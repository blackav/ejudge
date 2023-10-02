/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2016-2023 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "ejudge/telegram.h"
#include "ejudge/xml_utils.h"
#include "ejudge/random.h"
#include "ejudge/osdeps.h"
#include "ejudge/contests.h"
#include "ejudge/misctext.h"
#include "ejudge/base64.h"

#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"
#include "ejudge/logger.h"

#include "telegram_data.h"
#include "telegram_pbs.h"
#include "telegram_token.h"
#include "telegram_user.h"
#include "telegram_chat.h"
#include "telegram_chat_state.h"
#include "telegram_subscription.h"
#include "generic_conn.h"

#include "ejudge/cJSON.h"

#define CONNECT_TIMEOUT 30L

#if CONF_HAS_LIBCURL - 0 == 1
#include <curl/curl.h>
#endif

#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>

static struct common_plugin_data *
init_func(void);
static int
finish_func(struct common_plugin_data *data);
static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree);

static void
set_set_command_handler_func(
        void *data,
        tg_set_command_handler_t setter,
        void *setter_self);
static void
set_set_timer_handler_func(
        void *data,
        tg_set_timer_handler_t setter,
        void *setter_self);
static int
start_func(void *data);

static void
queue_packet_handler_telegram(int uid, int argc, char **argv, void *user);
static void
queue_packet_handler_telegram_token(int uid, int argc, char **argv, void *user);
static void
queue_packet_handler_telegram_reviewed(int uid, int argc, char **argv, void *user);
static void
queue_packet_handler_telegram_replied(int uid, int argc, char **argv, void *user);
static void
queue_packet_handler_telegram_cf(int uid, int argc, char **argv, void *user);
static void
queue_packet_handler_telegram_notify(int uid, int argc, char **argv, void *user);
static void
queue_packet_handler_telegram_reminder(int uid, int argc, char **argv, void *user);
static void
queue_packet_handler_telegram_registered(int uid, int argc, char **argv, void *user);

static void
queue_periodic_handler(void *user);

struct telegram_plugin_iface plugin_sn_telegram =
{
    { /* struct common_plugin_iface */
        { /* struct ejudge_plugin_iface */
            sizeof (struct telegram_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "sn",
            "telegram",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    TELEGRAM_PLUGIN_IFACE_VERSION,
    set_set_command_handler_func,
    set_set_timer_handler_func,
    start_func,
};

struct persistent_bot_state
{
    unsigned char *_id; // same as bot_id, actually
    long long update_id; // last processed update
};

struct bot_state
{
    unsigned char *bot_id;
    struct telegram_pbs *pbs;
};

struct queue_item
{
    void (*handler)(int uid, int argc, char **argv, void *user);
    int uid;
    int argc;
    char **argv;
};

enum { QUEUE_SIZE = 64 };

struct telegram_plugin_data
{
    struct
    {
        struct bot_state **v;
        int a, u;
    } bots;

    struct generic_conn *conn;

    int curl_verbose_flag;
    unsigned char *password_file;

    tg_set_command_handler_t set_command_handler;
    void *set_command_handler_self;

    tg_set_timer_handler_t set_timer_handler;
    void *set_timer_handler_self;

    pthread_t worker_thread;
    _Atomic _Bool worker_thread_finish_request;

    pthread_mutex_t q_m;
    pthread_cond_t  q_c;
    int q_first;
    int q_len;
    struct queue_item queue[QUEUE_SIZE];

    int enable_telegram_registration;
};

static void
put_to_queue(
        struct telegram_plugin_data *state,
        void (*handler)(int uid, int argc, char **argv, void *user),
        int uid,
        int argc,
        char **argv)
{
    pthread_mutex_lock(&state->q_m);
    if (state->q_len == QUEUE_SIZE) {
        err("telegram_plugin: request queue overflow, request dropped");
        goto done;
    }
    struct queue_item *item = &state->queue[(state->q_first + state->q_len++) % QUEUE_SIZE];
    memset(item, 0, sizeof(*item));
    item->handler = handler;
    item->uid = uid;
    item->argc = argc;
    item->argv = calloc(argc + 1, sizeof(item->argv[0]));
    for (int i = 0; i < argc; ++i) {
        item->argv[i] = strdup(argv[i]);
    }
    if (state->q_len == 1)
        pthread_cond_signal(&state->q_c);

done:
    pthread_mutex_unlock(&state->q_m);
}

static int
parse_passwd_file(
        struct telegram_plugin_data *state,
        const unsigned char *path)
{
  FILE *f = 0;
  const unsigned char *fname = __FUNCTION__;
  unsigned char buser[1024];
  unsigned char bpwd[1024];
  int len, c;

  if (!(f = fopen(path, "r"))) {
    err("%s: cannot open password file %s", fname, path);
    goto cleanup;
  }
  if (!fgets(buser, sizeof(buser), f)) {
    err("%s: cannot read the user line from %s", fname, path);
    goto cleanup;
  }
  if ((len = strlen(buser)) > sizeof(buser) - 24) {
    err("%s: user is too long in %s", fname, path);
    goto cleanup;
  }
  while (len > 0 && isspace(buser[--len]));
  buser[++len] = 0;

  if (!fgets(bpwd, sizeof(bpwd), f)) {
    err("%s: cannot read the password line from %s", fname, path);
    goto cleanup;
  }
  if ((len = strlen(bpwd)) > sizeof(bpwd) - 24) {
    err("%s: password is too long in %s", fname, path);
    goto cleanup;
  }
  while (len > 0 && isspace(bpwd[--len]));
  bpwd[++len] = 0;
  while ((c = getc(f)) && isspace(c));
  if (c != EOF) {
    err("%s: garbage in %s", fname, path);
    goto cleanup;
  }
  fclose(f); f = 0;
  state->conn->user = xstrdup(buser);
  state->conn->password = xstrdup(bpwd);

  // debug
  //fprintf(stderr, "login: %s\npassword: %s\n", state->user, state->password);
  return 0;

 cleanup:
  if (f) fclose(f);
  return -1;
}

static struct bot_state *
add_bot_id(struct telegram_plugin_data *state, const unsigned char *id)
{
    if (!id) return NULL;
    for (int i = 0; i < state->bots.u; ++i) {
        if (!strcmp(state->bots.v[i]->bot_id, id))
            return state->bots.v[i];
    }
    if (state->bots.u == state->bots.a) {
        if (!(state->bots.a *= 2)) state->bots.a = 16;
        XREALLOC(state->bots.v, state->bots.a);
    }
    struct bot_state *bs = NULL;
    XCALLOC(bs, 1);
    bs->bot_id = xstrdup(id);
    state->bots.v[state->bots.u++] = bs;
    return bs;
}

static struct common_plugin_data *
init_func(void)
{
    struct telegram_plugin_data *state = NULL;
    XCALLOC(state, 1);
    pthread_mutex_init(&state->q_m, NULL);
    pthread_cond_init(&state->q_c, NULL);
    return (struct common_plugin_data*) state;
}

static int
finish_func(struct common_plugin_data *data)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) data;

    state->conn->vt->free(state->conn);
    xfree(state->password_file);
    memset(state, 0, sizeof(*state));
    xfree(state);
    return 0;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) data;
    const struct xml_parse_spec *spec = ejudge_cfg_get_spec();

    if (tree->tag != spec->default_elem || strcmp(tree->name[0], "config")) {
        err("invalid plugin config");
        return -1;
    }

    unsigned char *storage = NULL;
    unsigned char *host = NULL;
    int port = 0;
    unsigned char *database = NULL;
    unsigned char *table_prefix = NULL;

    for (struct xml_tree *p = tree->first_down; p; p = p->right) {
        ASSERT(p->tag == spec->default_elem);
        if (!strcmp(p->name[0], "bots")) {
            for (struct xml_tree *q = p->first_down; q; q = q->right) {
                if (!strcmp(q->name[0], "bot")) {
                    unsigned char *bot_id = NULL;
                    if (xml_leaf_elem(q, &bot_id, 1, 0) < 0) return -1;
                    add_bot_id(state, bot_id);
                }
            }
        } else if (!strcmp(p->name[0], "storage")) {
            if (xml_leaf_elem(p, &storage, 1, 0) < 0) return -1;
        } else if (!strcmp(p->name[0], "host")) {
            if (xml_leaf_elem(p, &host, 1, 0) < 0) return -1;
        } else if (!strcmp(p->name[0], "port")) {
            if (xml_parse_int(NULL, "", p->line, p->column, p->text, &port) < 0) return -1;
            if (port < 0 || port > 65535) {
                xml_err_elem_invalid(p);
                return -1;
            }
        } else if (!strcmp(p->name[0], "database")) {
            if (xml_leaf_elem(p, &database, 1, 0) < 0) return -1;
        } else if (!strcmp(p->name[0], "table_prefix")) {
            if (xml_leaf_elem(p, &table_prefix, 1, 0) < 0) return -1;
        } else if (!strcmp(p->name[0], "password_file")) {
            if (xml_leaf_elem(p, &state->password_file, 1, 0) < 0) return -1;
        } else if (!strcmp(p->name[0], "curl_verbose")) {
            state->curl_verbose_flag = 1;
        }
    }

    state->enable_telegram_registration = config->enable_telegram_registration;

    struct generic_conn *conn = NULL;
    if (!storage || !*storage) storage = "mysql";
    if (!strcmp(storage, "mysql")) {
        conn = mysql_conn_create();
    } else if (!strcmp(storage, "mongo")) {
        conn = mongo_conn_create();
    } else {
        err("telegram: invalid storage '%s'", storage);
        return -1;
    }
    state->conn = conn;
    conn->host = host; host = NULL;
    conn->port = port;
    conn->database = database; database = NULL;
    conn->table_prefix = table_prefix; table_prefix = NULL;
    conn->ejudge_config = config;
    if (conn->vt->prepare && conn->vt->prepare(conn, config, NULL) < 0) {
        return -1;
    }

    if (state->password_file) {
        unsigned char ppath[PATH_MAX];
        ppath[0] = 0;
        if (os_IsAbsolutePath(state->password_file)) {
            snprintf(ppath, sizeof(ppath), "%s", state->password_file);
        }
#if defined EJUDGE_CONF_DIR
        if (!ppath[0]) {
            snprintf(ppath, sizeof(ppath), "%s/%s", EJUDGE_CONF_DIR,
                     state->password_file);
        }
#endif
        if (!ppath[0]) {
            snprintf(ppath, sizeof(ppath), "%s", state->password_file);
        }
        if (parse_passwd_file(state, ppath) < 0) return -1;
    }

    return 0;
}

static void
set_set_command_handler_func(
        void *data,
        tg_set_command_handler_t setter,
        void *setter_self)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) data;
    state->set_command_handler = setter;
    state->set_command_handler_self = setter_self;
}

static void
set_set_timer_handler_func(
        void *data,
        tg_set_timer_handler_t setter,
        void *setter_self)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) data;
    state->set_timer_handler = setter;
    state->set_timer_handler_self = setter_self;
}

static void *
thread_func(void *data)
{
    sigset_t ss;
    sigfillset(&ss);
    pthread_sigmask(SIG_BLOCK, &ss, NULL);

    struct telegram_plugin_data *state = (struct telegram_plugin_data*) data;
    while (!state->worker_thread_finish_request) {
        pthread_mutex_lock(&state->q_m);
        while (state->q_len == 0 && !state->worker_thread_finish_request) {
            pthread_cond_wait(&state->q_c, &state->q_m);
        }
        if (state->worker_thread_finish_request) {
            pthread_mutex_unlock(&state->q_m);
            break;
        }
        // this is local copy of the queue item
        struct queue_item item = state->queue[state->q_first];
        memset(&state->queue[state->q_first], 0, sizeof(item));
        state->q_first = (state->q_first + 1) % QUEUE_SIZE;
        --state->q_len;
        pthread_mutex_unlock(&state->q_m);

        item.handler(item.uid, item.argc, item.argv, state);

        for (int i = 0; i < item.argc; ++i) {
            free(item.argv[i]);
        }
        free(item.argv);
    }
    return NULL;
}

static int
start_func(void *data)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) data;

    state->set_command_handler(state->set_command_handler_self,
                               "telegram",
                               queue_packet_handler_telegram, state);
    state->set_command_handler(state->set_command_handler_self,
                               "telegram_token",
                               queue_packet_handler_telegram_token, state);
    state->set_command_handler(state->set_command_handler_self,
                               "telegram_reviewed",
                               queue_packet_handler_telegram_reviewed, state);
    state->set_command_handler(state->set_command_handler_self,
                               "telegram_replied",
                               queue_packet_handler_telegram_replied, state);
    state->set_command_handler(state->set_command_handler_self,
                               "telegram_cf",
                               queue_packet_handler_telegram_cf, state);
    state->set_command_handler(state->set_command_handler_self,
                               "telegram_notify",
                               queue_packet_handler_telegram_notify, state);
    state->set_command_handler(state->set_command_handler_self,
                               "telegram_reminder",
                               queue_packet_handler_telegram_reminder, state);
    state->set_command_handler(state->set_command_handler_self,
                               "telegram_registered",
                               queue_packet_handler_telegram_registered, state);
    state->set_timer_handler(state->set_timer_handler_self,
                             queue_periodic_handler, state);

    int r = pthread_create(&state->worker_thread, NULL, thread_func, state);
    if (r) {
        err("telegram: cannot create worker thread: %s", os_ErrorMsg());
        return -1;
    }

    return 0;
}

struct telegram_pbs *
get_persistent_bot_state(struct generic_conn *gc, struct bot_state *bs)
{
    if (bs->pbs) return bs->pbs;

    bs->pbs = gc->vt->pbs_fetch(gc, bs->bot_id);
    return bs->pbs;
}

static TeSendMessageResult *
send_message(
        struct telegram_plugin_data *state,
        struct bot_state *bs,
        struct telegram_chat *tc,
        const unsigned char *text,
        const unsigned char *parse_mode,
        const unsigned char *reply_markup)
{
    CURL *curl = NULL;
    char *url_s = NULL, *post_s = NULL, *resp_s = NULL;
    cJSON *root = NULL;
    TeSendMessageResult *result = NULL;

    curl = curl_easy_init();
    if (!curl) {
        err("cannot initialize curl");
        goto cleanup;
    }
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    {
        size_t url_z = 0;
        FILE *url_f = open_memstream(&url_s, &url_z);
        fprintf(url_f, "https://api.telegram.org/bot%s/%s", bs->bot_id, "sendMessage");
        fclose(url_f);
    }

    {
        size_t post_z = 0;
        FILE *post_f = open_memstream(&post_s, &post_z);
        fprintf(post_f, "chat_id=%lld", tc->_id);
        fprintf(post_f, "&text=");
        unsigned char *s = curl_easy_escape(curl, text, 0);
        fprintf(post_f, "%s", s);
        xfree(s);
        if (parse_mode && *parse_mode) {
            fprintf(post_f, "&parse_mode=");
            s = curl_easy_escape(curl, parse_mode, 0);
            fprintf(post_f, "%s", s);
            free(s);
        }
        if (reply_markup && *reply_markup) {
            fprintf(post_f, "&reply_markup=");
            s = curl_easy_escape(curl, reply_markup, 0);
            fprintf(post_f, "%s", s);
            free(s);
        }
        fclose(post_f);
    }

    //fprintf(stderr, ">%s<\n", post_s);

    {
        size_t resp_z = 0;
        FILE *resp_f = open_memstream(&resp_s, &resp_z);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT);
        curl_easy_setopt(curl, CURLOPT_AUTOREFERER, 1);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
        curl_easy_setopt(curl, CURLOPT_URL, url_s);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp_f);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (char*) post_s);
        curl_easy_setopt(curl, CURLOPT_POST, 1);
        if (state->curl_verbose_flag > 0) {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
        }
        CURLcode res = curl_easy_perform(curl);
        fclose(resp_f);
        if (res != CURLE_OK) {
            err("curl request failed");
            goto cleanup;
        }
    }

    fprintf(stderr, ">%s<\n", resp_s);

    root = cJSON_Parse(resp_s);
    if (!root) {
        err("JSON parsing failed");
        goto cleanup;
    } else {
        if (!(result = TeSendMessageResult_parse(root))) {
            err("TeSendMessageResult_parse failed");
            goto cleanup;
        }
    }

 cleanup:
    if (root) cJSON_Delete(root);
    xfree(resp_s);
    xfree(post_s);
    xfree(url_s);
    if (curl) {
        curl_easy_cleanup(curl);
    }
    return result;
}

/*
 * [0] - "telegram"
 * [1] - auth
 * [2] - chat_id
 * [3] - text
 * [4] - parse_mode
 */
static void
packet_handler_telegram(int uid, int argc, char **argv, void *user)
{
    CURL *curl = NULL;
    char *url_s = NULL, *post_s = NULL, *s = NULL, *resp_s = NULL;
    size_t url_z = 0, post_z = 0, resp_z = 0;
    FILE *url_f = NULL, *post_f = NULL, *resp_f = NULL;
    CURLcode res = 0;

    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;

    curl = curl_easy_init();
    if (!curl) {
        err("cannot initialize curl");
        goto cleanup;
    }

    add_bot_id(state, argv[1]);

    url_f = open_memstream(&url_s, &url_z);
    fprintf(url_f, "https://api.telegram.org/bot%s/%s", argv[1], "sendMessage");
    fclose(url_f); url_f = NULL;
    post_f = open_memstream(&post_s, &post_z);
    fprintf(post_f, "chat_id=");
    s = curl_easy_escape(curl, argv[2], 0);
    fprintf(stderr, "chat_id: %s\n", s);
    fprintf(post_f, "%s", s);
    free(s);
    fprintf(post_f, "&text=");
    s = curl_easy_escape(curl, argv[3], 0);
    fprintf(post_f, "%s", s);
    free(s);
    if (argc > 4 && argv[4] && argv[4][0]) {
        fprintf(post_f, "&parse_mode=");
        s = curl_easy_escape(curl, argv[4], 0);
        fprintf(post_f, "%s", s);
        free(s);
    }
    fclose(post_f); post_f = NULL;

    resp_f = open_memstream(&resp_s, &resp_z);

    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_AUTOREFERER, 1);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_URL, url_s);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp_f);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (char*) post_s);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    if (state->curl_verbose_flag > 0) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    }
    res = curl_easy_perform(curl);
    fclose(resp_f); resp_f = NULL;
    if (res != CURLE_OK) {
        err("curl request failed");
        goto cleanup;
    }
    fprintf(stderr, ">%s<\n", resp_s);
    free(resp_s); resp_s = NULL;

 cleanup:
    if (post_f) {
        fclose(post_f);
    }
    free(post_s);
    if (url_f) {
        fclose(url_f);
    }
    free(url_s);
    if (resp_f) {
        fclose(resp_f);
    }
    free(resp_s);
    if (curl) {
        curl_easy_cleanup(curl);
    }
}

static void
queue_packet_handler_telegram(int uid, int argc, char **argv, void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;
    put_to_queue(state, packet_handler_telegram, uid, argc, argv);
}

/*
  args[0] = "telegram_token";
  args[1] = cnts->telegram_bot_id;
  args[2] = locale_id_buf;
  args[3] = user_id_buf;
  args[4] = user_login;
  args[5] = user_name;
  args[6] = telegram_token;
  args[7] = contest_id_buf;
  args[8] = expiry_buf;
  args[9] = NULL;
 */
static void
packet_handler_telegram_token(int uid, int argc, char **argv, void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;
    struct telegram_token *token = NULL;
    struct telegram_token *other_token = NULL;

    if (argc != 9) {
        err("wrong number of arguments for telegram_token: %d", argc);
        goto cleanup;
    }

    err("expiry: %s", argv[8]);

    XCALLOC(token, 1);
    token->bot_id = xstrdup(argv[1]);
    sscanf(argv[2], "%d", &token->locale_id);
    if (token->locale_id < 0) token->locale_id = 0;
    sscanf(argv[3], "%d", &token->user_id);
    if (token->user_id < 0) token->user_id = 0;
    token->user_login = xstrdup(argv[4]);
    token->user_name = xstrdup(argv[5]);
    token->token = xstrdup(argv[6]);
    if (!*token->token) {
        err("telegram_token: empty_token");
        goto cleanup;
    }
    sscanf(argv[7], "%d", &token->contest_id);
    if (token->contest_id < 0) token->contest_id = 0;
    if (xml_parse_date(NULL, NULL, 0, 0, argv[8], &token->expiry_time) < 0 || token->expiry_time <= 0) {
        err("telegram_token: invalid expiry_time: %s", argv[8]);
        goto cleanup;
    }

    time_t current_time = time(NULL);
    state->conn->vt->token_remove_expired(state->conn, current_time);

    int res = state->conn->vt->token_fetch(state->conn, token->token, &other_token);
    if (res < 0) {
        err("telegram_token: get_token failed");
    } else if (res > 0) {
        err("duplicated token, removing all");
        state->conn->vt->token_remove(state->conn, token->token);
    } else {
        state->conn->vt->token_save(state->conn, token);
    }

cleanup:
    telegram_token_free(token);
    telegram_token_free(other_token);
}

static void
queue_packet_handler_telegram_token(int uid, int argc, char **argv, void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;
    put_to_queue(state, packet_handler_telegram_token, uid, argc, argv);
}

/*
  args[0] = "telegram_reviewed"
  args[1] = telegram_bot_id
  args[2] = contest_id
  args[3] = contest_name
  args[4] = user_id
  args[5] = user_login
  args[6] = user_name
  args[7] = run_id
  args[8] = new_status
  args[9] = NULL;
 */
static void
packet_handler_telegram_reviewed(int uid, int argc, char **argv, void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;
    struct telegram_subscription *sub = NULL;
    char *msg_s = NULL;
    struct TeSendMessageResult *send_result = NULL;
    struct bot_state *bs = NULL;
    struct telegram_chat *tc = NULL;

    if (argc != 9) {
        err("wrong number of arguments for telegram_reviewed: %d", argc);
        goto cleanup;
    }

    bs = add_bot_id(state, argv[1]);

    int contest_id, n;
    if (sscanf(argv[2], "%d%n", &contest_id, &n) != 1 || argv[2][n] || contest_id <= 0) {
        err("invalid contest_id: %s", argv[2]);
        goto cleanup;
    }
    int user_id;
    if (sscanf(argv[4], "%d%n", &user_id, &n) != 1 || argv[4][n] || user_id <= 0) {
        err("invalid user_id: %s", argv[4]);
        goto cleanup;
    }

    sub = state->conn->vt->subscription_fetch(state->conn, argv[1], user_id, contest_id);
    if (!sub) goto cleanup;
    if (!sub->review_flag) goto cleanup;
    if (!sub->chat_id) {
        err("chat_id is NULL for subscription");
        goto cleanup;
    }

    tc = state->conn->vt->chat_fetch(state->conn, sub->chat_id);
    if (!tc) {
        err("chat_id %lld is not registered", sub->chat_id);
    }

    {
        size_t msg_z = 0;
        FILE *msg_f = open_memstream(&msg_s, &msg_z);
        fprintf(msg_f, "Your run has been reviewed.\n");
        fprintf(msg_f, "    User: %s\n", argv[5]);
        fprintf(msg_f, "    Contest: %d (%s)\n", contest_id, argv[3]);
        fprintf(msg_f, "    Run Id: %s\n", argv[7]);
        fprintf(msg_f, "    Status: %s\n", argv[8]);
        fclose(msg_f);
    }

    send_result = send_message(state, bs, tc, msg_s, NULL, NULL);

cleanup:
    xfree(msg_s);
    telegram_subscription_free(sub);
    telegram_chat_free(tc);
    if (send_result) send_result->b.destroy(&send_result->b);
}

static void
queue_packet_handler_telegram_reviewed(int uid, int argc, char **argv, void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;
    put_to_queue(state, packet_handler_telegram_reviewed, uid, argc, argv);
}

/*
  args[0] = "telegram_replied"
  args[1] = telegram_bot_id
  args[2] = contest_id
  args[3] = contest_name
  args[4] = user_id
  args[5] = user_login
  args[6] = user_name
  args[7] = clar_id
  args[8] = reply
  args[9] = NULL
 */
static void
packet_handler_telegram_replied(int uid, int argc, char **argv, void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;
    struct telegram_subscription *sub = NULL;
    char *msg_s = NULL;
    struct TeSendMessageResult *send_result = NULL;
    struct bot_state *bs = NULL;
    struct telegram_chat *tc = NULL;

    if (argc != 9) {
        err("wrong number of arguments for telegram_reviewed: %d", argc);
        goto cleanup;
    }

    bs = add_bot_id(state, argv[1]);

    int contest_id, n;
    if (sscanf(argv[2], "%d%n", &contest_id, &n) != 1 || argv[2][n] || contest_id <= 0) {
        err("invalid contest_id: %s", argv[2]);
        goto cleanup;
    }
    int user_id;
    if (sscanf(argv[4], "%d%n", &user_id, &n) != 1 || argv[4][n] || user_id <= 0) {
        err("invalid user_id: %s", argv[4]);
        goto cleanup;
    }

    sub = state->conn->vt->subscription_fetch(state->conn, argv[1], user_id, contest_id);
    if (!sub) goto cleanup;
    if (!sub->reply_flag) goto cleanup;
    if (!sub->chat_id) {
        err("chat_id is NULL for subscription");
        goto cleanup;
    }

    tc = state->conn->vt->chat_fetch(state->conn, sub->chat_id);
    if (!tc) {
        err("chat_id %lld is not registered", sub->chat_id);
    }

    {
        size_t msg_z = 0;
        FILE *msg_f = open_memstream(&msg_s, &msg_z);
        fprintf(msg_f, "Your clarification request has been replied.\n");
        fprintf(msg_f, "    User: %s\n", argv[5]);
        fprintf(msg_f, "    Contest: %d (%s)\n", contest_id, argv[3]);
        fprintf(msg_f, "    Clar Id: %s\n", argv[7]);
        fprintf(msg_f, "%s\n", argv[8]);
        fclose(msg_f);
    }

    send_result = send_message(state, bs, tc, msg_s, NULL, NULL);

cleanup:
    xfree(msg_s);
    telegram_subscription_free(sub);
    telegram_chat_free(tc);
    if (send_result) send_result->b.destroy(&send_result->b);
}

static void
queue_packet_handler_telegram_replied(int uid, int argc, char **argv, void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;
    put_to_queue(state, packet_handler_telegram_replied, uid, argc, argv);
}

/*
  args[0] = "telegram_cf"
  args[1] = telegram_bot_id
  args[2] = telegram_chat_id
  args[3] = contest_id
  args[4] = contest_name
  args[5] = run_id
  args[6] = user_id
  args[7] = user_name
  args[8] = prob_name
  args[9] = NULL
 */
static void
packet_handler_telegram_cf(int uid, int argc, char **argv, void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;
    struct telegram_subscription *sub = NULL;
    char *msg_s = NULL;
    struct TeSendMessageResult *send_result = NULL;
    struct bot_state *bs = NULL;
    struct telegram_chat *tc = NULL;

    if (argc != 9) {
        err("wrong number of arguments for telegram_cf: %d", argc);
        goto cleanup;
    }

    bs = add_bot_id(state, argv[1]);

    int contest_id, n;
    if (sscanf(argv[3], "%d%n", &contest_id, &n) != 1 || argv[3][n] || contest_id <= 0) {
        err("invalid contest_id: %s", argv[3]);
        goto cleanup;
    }
    long long chat_id;
    if (sscanf(argv[2], "%lld%n", &chat_id, &n) != 1 || argv[2][n]) {
        err("invalid chat_id: %s", argv[2]);
        goto cleanup;
    }
    int user_id;
    if (sscanf(argv[6], "%d%n", &user_id, &n) != 1 || argv[6][n] || user_id <= 0) {
        err("invalid user_id: %s", argv[6]);
        goto cleanup;
    }

    tc = state->conn->vt->chat_fetch(state->conn, chat_id);
    if (!tc) {
        tc = telegram_chat_create();
        tc->_id = chat_id;
        state->conn->vt->chat_save(state->conn, tc);
    }

    {
        size_t msg_z = 0;
        FILE *msg_f = open_memstream(&msg_s, &msg_z);
        fprintf(msg_f, "Check failed.\n");
        fprintf(msg_f, "    Contest: %d (%s)\n", contest_id, argv[4]);
        fprintf(msg_f, "    Run Id: %s\n", argv[5]);
        fprintf(msg_f, "    User: %d (%s)\n", user_id, argv[7]);
        fprintf(msg_f, "    Problem: %s\n", argv[8]);
        fclose(msg_f);
    }

    send_result = send_message(state, bs, tc, msg_s, NULL, NULL);

cleanup:
    xfree(msg_s);
    telegram_subscription_free(sub);
    telegram_chat_free(tc);
    if (send_result) send_result->b.destroy(&send_result->b);
}

static void
queue_packet_handler_telegram_cf(int uid, int argc, char **argv, void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;
    put_to_queue(state, packet_handler_telegram_cf, uid, argc, argv);
}

/*
  args[0] = "telegram_notify"
  args[1] = telegram_bot_id
  args[2] = telegram_chat_id
  args[3] = contest_id
  args[4] = contest_name
  args[5] = run_id
  args[6] = user_id
  args[7] = user_name
  args[8] = prob_name
  args[9] = new_status
  args[10] = NULL
 */
static void
packet_handler_telegram_notify(int uid, int argc, char **argv, void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;
    struct telegram_subscription *sub = NULL;
    char *msg_s = NULL;
    struct TeSendMessageResult *send_result = NULL;
    struct bot_state *bs = NULL;
    struct telegram_chat *tc = NULL;

    if (argc != 10) {
        err("wrong number of arguments for telegram_notify: %d", argc);
        goto cleanup;
    }

    bs = add_bot_id(state, argv[1]);

    int contest_id, n;
    if (sscanf(argv[3], "%d%n", &contest_id, &n) != 1 || argv[3][n] || contest_id <= 0) {
        err("invalid contest_id: %s", argv[3]);
        goto cleanup;
    }
    long long chat_id;
    if (sscanf(argv[2], "%lld%n", &chat_id, &n) != 1 || argv[2][n]) {
        err("invalid chat_id: %s", argv[2]);
        goto cleanup;
    }
    int user_id;
    if (sscanf(argv[6], "%d%n", &user_id, &n) != 1 || argv[6][n] || user_id <= 0) {
        err("invalid user_id: %s", argv[6]);
        goto cleanup;
    }

    tc = state->conn->vt->chat_fetch(state->conn, chat_id);
    if (!tc) {
        tc = telegram_chat_create();
        tc->_id = chat_id;
        state->conn->vt->chat_save(state->conn, tc);
    }

    {
        size_t msg_z = 0;
        FILE *msg_f = open_memstream(&msg_s, &msg_z);
        fprintf(msg_f, "Submit notification.\n");
        fprintf(msg_f, "    Contest: %d (%s)\n", contest_id, argv[4]);
        fprintf(msg_f, "    Run Id: %s\n", argv[5]);
        fprintf(msg_f, "    User: %d (%s)\n", user_id, argv[7]);
        fprintf(msg_f, "    Problem: %s\n", argv[8]);
        fprintf(msg_f, "    Status: %s\n", argv[9]);
        fclose(msg_f);
    }

    send_result = send_message(state, bs, tc, msg_s, NULL, NULL);

cleanup:
    xfree(msg_s);
    telegram_subscription_free(sub);
    telegram_chat_free(tc);
    if (send_result) send_result->b.destroy(&send_result->b);
}

static void
queue_packet_handler_telegram_notify(int uid, int argc, char **argv, void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;
    put_to_queue(state, packet_handler_telegram_notify, uid, argc, argv);
}

/*
  args[0] = "telegram_reminder"
  args[1] = telegram_bot_id
  args[2] = telegram_admin_chat_id
  args[3] = contest_id
  args[4] = contest_name
  args[5] = pr_total
  args[6] = pr_too_old
  args[7] = unans_clars
  args[8] = NULL;
 */
static void
packet_handler_telegram_reminder(int uid, int argc, char **argv, void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;
    struct TeSendMessageResult *send_result = NULL;
    struct bot_state *bs = NULL;
    struct telegram_chat *tc = NULL;
    char *msg_s = NULL;

    bs = add_bot_id(state, argv[1]);

    int n;
    long long chat_id;
    if (sscanf(argv[2], "%lld%n", &chat_id, &n) != 1 || argv[2][n]) {
        err("invalid chat_id: %s", argv[2]);
        goto cleanup;
    }
    int contest_id;
    if (sscanf(argv[3], "%d%n", &contest_id, &n) != 1 || argv[3][n] || contest_id <= 0) {
        err("invalid contest_id: %s", argv[3]);
        goto cleanup;
    }
    int pr_total;
    if (sscanf(argv[5], "%d%n", &pr_total, &n) != 1 || argv[5][n] || pr_total < 0) {
        err("invalid pr_total: %s", argv[5]);
        goto cleanup;
    }
    int pr_too_old;
    if (sscanf(argv[6], "%d%n", &pr_too_old, &n) != 1 || argv[6][n] || pr_too_old < 0) {
        err("invalid pr_too_old: %s", argv[6]);
        goto cleanup;
    }
    int unans_clars = 0;
    if (sscanf(argv[7], "%d%n", &unans_clars, &n) != 1 || argv[7][n] || unans_clars < 0) {
        err("invalid unans_clars: %s", argv[7]);
        goto cleanup;
    }
    if (pr_total < 20 && pr_too_old == 0 && unans_clars == 0) goto cleanup;


    tc = state->conn->vt->chat_fetch(state->conn, chat_id);
    if (!tc) {
        tc = telegram_chat_create();
        tc->_id = chat_id;
        state->conn->vt->chat_save(state->conn, tc);
    }

    {
        size_t msg_z = 0;
        FILE *msg_f = open_memstream(&msg_s, &msg_z);
        fprintf(msg_f, "Reminder.\n");
        fprintf(msg_f, "    Contest: %d (%s)\n", contest_id, argv[4]);
        if (pr_total >= 20) {
            fprintf(msg_f, "    Pending Review runs: %d\n", pr_total);
        }
        if (pr_too_old > 0) {
            fprintf(msg_f, "    Pending Review older than 48h: %d\n", pr_too_old);
        }
        if (unans_clars > 0) {
            fprintf(msg_f, "    Unanswered clars older than 48h: %d\n", unans_clars);
        }
        fclose(msg_f);
    }

    send_result = send_message(state, bs, tc, msg_s, NULL, NULL);

cleanup:
    xfree(msg_s);
    telegram_chat_free(tc);
    if (send_result) send_result->b.destroy(&send_result->b);
}

static void
queue_packet_handler_telegram_reminder(int uid, int argc, char **argv, void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;
    put_to_queue(state, packet_handler_telegram_reminder, uid, argc, argv);
}

/*
  args[0] = "telegram_registered"
  args[1] = telegram_bot_id
  args[2] = telegram_chat_id
  args[3] = contest_id
  args[4] = contest_name
  args[5] = login_str
  args[6] = password_str
  args[7] = error_message
  args[8] = NULL;
 */
static void
packet_handler_telegram_registered(int uid, int argc, char **argv, void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;
    struct TeSendMessageResult *send_result = NULL;
    struct bot_state *bs = NULL;
    long long chat_id = 0;
    int contest_id = 0;
    struct telegram_chat *tc = NULL;
    char *msg_s = NULL;
    size_t msg_z = 0;
    FILE *msg_f = NULL;

    if (argc != 8) {
        err("wrong number of arguments for telegram_reviewed: %d", argc);
        goto cleanup;
    }

    bs = add_bot_id(state, argv[1]);

    {
        char *eptr = NULL;
        errno = 0;
        chat_id = strtoll(argv[2], &eptr, 10);
        if (errno || *eptr || eptr == argv[2]) {
            err("invalid chat id '%s'", argv[2]);
            goto cleanup;
        }
    }
    {
        char *eptr = NULL;
        errno = 0;
        long v = strtol(argv[3], &eptr, 10);
        if (errno || *eptr || eptr == argv[3] || v <= 0 || (int) v != v) {
            err("invalid contest_id '%s'", argv[3]);
            goto cleanup;
        }
        contest_id = v;
    }

    tc = state->conn->vt->chat_fetch(state->conn, chat_id);
    if (!tc) {
        err("chat_id %lld is not registered", chat_id);
        goto cleanup;
    }

    msg_f = open_memstream(&msg_s, &msg_z);

    if (argv[7][0]) {
        fprintf(msg_f, "%s", argv[7]);
    } else {
        fprintf(msg_f, "Registration successful.\n");
        fprintf(msg_f, "    Contest: %d (%s)\n", contest_id, argv[4]);
        fprintf(msg_f, "    Login: %s\n", argv[5]);
        fprintf(msg_f, "    Password: %s\n", argv[6]);
    }

    fclose(msg_f); msg_f = NULL;
    send_result = send_message(state, bs, tc, msg_s, NULL, NULL);
    free(msg_s); msg_s = NULL; msg_z = 0;

cleanup:;
    if (msg_f) fclose(msg_f);
    free(msg_s);
    telegram_chat_free(tc);
    if (send_result) send_result->b.destroy(&send_result->b);
}

static void
queue_packet_handler_telegram_registered(int uid, int argc, char **argv, void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;
    put_to_queue(state, packet_handler_telegram_registered, uid, argc, argv);
}

static unsigned char *
get_random_phrase(const unsigned char *filename)
{
    unsigned char path[PATH_MAX];
    FILE *f = NULL;
    unsigned char *retval = NULL;
    unsigned char **lines = NULL;
    size_t lines_a = 0;
    size_t lines_u = 0;
    unsigned char linebuf[1024];

    snprintf(path, sizeof(path), "%s/%s", EJUDGE_CONF_DIR, filename);
    if (!(f = fopen(path, "r"))) goto cleanup;
    lines_a = 16;
    XCALLOC(lines, lines_a);
    while (fgets(linebuf, sizeof(linebuf), f)) {
        size_t len = strlen(linebuf);
        while (len > 0 && isspace(linebuf[len - 1])) --len;
        linebuf[len] = 0;
        if (len > 0) {
            if (lines_u == lines_a) {
                XREALLOC(lines, (lines_a *= 2));
            }
            lines[lines_u++] = xstrdup(linebuf);
        }
    }
    if (lines_u > 0) {
        random_init();
        int ind = random_range(0, lines_u);
        retval = lines[ind]; lines[ind] = NULL;
    }

cleanup:
    if (lines) {
        for (size_t i = 0; i < lines_u; ++i) {
            xfree(lines[i]);
        }
        xfree(lines);
    }
    if (f) fclose(f);
    return retval;
}

static int
safe_strcmp(const unsigned char *s1, const unsigned char *s2)
{
    if (!s1 && !s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;
    return strcmp(s1, s2);
}

static unsigned char *
safe_strdup(const unsigned char *s)
{
    if (!s) return NULL;
    return xstrdup(s);
}

static int
need_update_user(const struct telegram_user *mu, const TeUser *teu)
{
    if (!mu && !teu) return 0;
    if (!mu) return 1;
    if (!teu) return 0;
    return safe_strcmp(mu->username, teu->username) != 0
        || safe_strcmp(mu->first_name, teu->first_name) != 0
        || safe_strcmp(mu->last_name, teu->last_name) != 0;
}

static int
need_update_chat(const struct telegram_chat *mc, const TeChat *tc)
{
    if (!mc && !tc) return 0;
    if (!mc) return 1;
    if (!tc) return 0;
    return safe_strcmp(mc->type, tc->type) != 0
        || safe_strcmp(mc->title, tc->title) != 0
        || safe_strcmp(mc->username, tc->username) != 0
        || safe_strcmp(mc->first_name, tc->first_name) != 0
        || safe_strcmp(mc->last_name, tc->last_name) != 0;
}

static unsigned char *
handle_get_password(
        struct telegram_plugin_data *state,
        TeMessage *tem)
{
    unsigned char *sgrp = NULL;
    unsigned char *sid = NULL;
    unsigned char *login = NULL;
    unsigned char *password = NULL;
    const unsigned char *errmsg = "Invalid input.";
    const unsigned char *te_user = "unknown";
    unsigned char te_user_buf[64];

    int len = strlen(tem->text);

    if (tem->from) {
        TeUser *teu = tem->from;
        te_user = teu->username;
        if (!te_user || !*te_user) {
            snprintf(te_user_buf, sizeof(te_user_buf), "[%lld]", teu->id);
            te_user = te_user_buf;
        }
    }

    sgrp = malloc(len + 1);
    sid = malloc(len + 1);
    if (sscanf(tem->text, "%s%s", sgrp, sid) != 2) {
        goto fail;
    }
    if (!*sgrp) goto fail;
    if (!*sid) goto fail;
    for (unsigned char *s = sgrp; *s; ++s) {
        if (!isdigit(*s)) goto fail;
    }
    for (unsigned char *s = sid; *s; ++s) {
        if (!isdigit(*s)) goto fail;
    }
    if (!state->conn->vt->password_get) {
        errmsg = "Operation not supported.";
        goto fail;
    }
    info("get_password: telegram user %s requested group %s and user %s", te_user, sgrp, sid);
    int res = state->conn->vt->password_get(state->conn, sgrp, sid, &login, &password);
    free(sgrp); sgrp = NULL;
    free(sid); sid = NULL;
    if (res < 0) {
        errmsg = "Database error.";
        goto fail;
    }
    if (!res) {
        errmsg = "Information not available.";
        goto fail;
    }
    char *s = NULL;
    asprintf(&s, "Login: %s\nPassword: %s\n", login, password);
    free(login); login = NULL;
    free(password); password = NULL;
    return s;

fail:;
    free(sgrp);
    free(sid);
    free(login);
    free(password);
    return strdup(errmsg);
}

static void
handle_register_0(
        struct telegram_plugin_data *state,
        struct bot_state *bs,
        struct telegram_pbs *pbs,
        TeMessage *tem,
        struct telegram_chat_state *tcs,
        struct telegram_chat *mc)
{
    struct TeSendMessageResult *send_result = NULL;
    const int *contest_ids = NULL;
    int contest_size = 0;
    char *rpl_s = NULL;
    size_t rpl_z = 0;
    FILE *rpl_f = NULL;
    struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
    time_t current_time = time(NULL);

    if (state->enable_telegram_registration <= 0) {
        send_result = send_message(state, bs, mc,
                                   "This option is not supported.", NULL, NULL);
        goto done;
    }

    rpl_f = open_memstream(&rpl_s, &rpl_z);
    fprintf(rpl_f, "{ \"one_time_keyboard\": true, \"keyboard\": [");

    contest_size = contests_get_list(&contest_ids);
    int reply_count = 0;
    for (int i = 0; i < contest_size; ++i) {
        const struct contest_desc *cnts = NULL;
        if (contests_get(contest_ids[i], &cnts) < 0 || !cnts) {
            continue;
        }
        if (cnts->enable_telegram_registration <= 0) {
            continue;
        }
        if (cnts->closed > 0) {
            continue;
        }
        if (cnts->reg_deadline > 0 && current_time >= cnts->reg_deadline) {
            continue;
        }

        if (reply_count > 0) {
            fprintf(rpl_f, ",");
        }
        ++reply_count;
        fprintf(rpl_f, "[\"%d - %s\"]", contest_ids[i],
                json_armor_buf(&ab, cnts->name));
    }
    fprintf(rpl_f, "]}");
    fclose(rpl_f); rpl_f = NULL;
    if (!reply_count) {
        send_result = send_message(state, bs, mc,
                                   "No contests available.", NULL, NULL);
        goto done;
    }
    send_result = send_message(state, bs, mc, "Select contest", NULL, rpl_s);
    tcs->command = xstrdup("/register");
    tcs->state = 1;

done:;
    html_armor_free(&ab);
    if (rpl_f) fclose(rpl_f);
    free(rpl_s);
    if (send_result) send_result->b.destroy(&send_result->b);
}

static void
handle_register_1(
        struct telegram_plugin_data *state,
        struct bot_state *bs,
        struct telegram_pbs *pbs,
        TeMessage *tem,
        struct telegram_chat_state *tcs,
        struct telegram_chat *mc)
{
    struct TeSendMessageResult *send_result = NULL;
    char *rpl_s = NULL;
    size_t rpl_z = 0;
    FILE *rpl_f = NULL;

    if (state->enable_telegram_registration <= 0) {
        send_result = send_message(state, bs, mc,
                                   "This option is not supported.", NULL, NULL);
        goto done;
    }

    int contest_id = 0;
    {
        char *eptr = NULL;
        errno = 0;
        long v = strtol(tem->text, &eptr, 10);
        if (errno || *eptr != ' ' || eptr == (char*) tem->text
            || v <= 0 || (int) v != v) {
            send_result = send_message(state, bs, mc,
                                       "Invalid value.", NULL, NULL);
            goto done;
        }
        contest_id = v;
    }

    const struct contest_desc *cnts = NULL;
    if (contests_get(contest_id, &cnts) < 0 || !cnts
        || cnts->enable_telegram_registration <= 0
        || cnts->closed > 0) {
        send_result = send_message(state, bs, mc,
                                   "Invalid contest.", NULL, NULL);
        goto done;
    }

    if (!cnts->register_url) {
        send_result = send_message(state, bs, mc,
                                   "Contest is not configured.", NULL, NULL);
        goto done;
    }

    unsigned char key_raw[16];
    random_bytes(key_raw, sizeof(key_raw));
    unsigned char key_str[32];
    int b64len = base64u_encode(key_raw, sizeof(key_raw), key_str);
    key_str[b64len] = 0;

    if (!state->conn->vt->registration_save) {
        send_result = send_message(state, bs, mc,
                                   "Operation not supported.", NULL, NULL);
        goto done;
    }

    int res = state->conn->vt->registration_save(state->conn, key_str,
                                                 mc->_id, contest_id);
    if (res < 0) {
        send_result = send_message(state, bs, mc,
                                   "Operation failed.", NULL, NULL);
        goto done;
    }

    rpl_f = open_memstream(&rpl_s, &rpl_z);
    fprintf(rpl_f, "Open the following link: %s?action=telegram-register&key=%s&contest_id=%d\nThis link expires in 5 minutes.",
            cnts->register_url, key_str, contest_id);
    fclose(rpl_f); rpl_f = NULL;

    send_result = send_message(state, bs, mc, rpl_s, NULL, NULL);

done:;
    if (rpl_f) fclose(rpl_f);
    free(rpl_s);
    if (send_result) send_result->b.destroy(&send_result->b);

    tcs->state = 0;
    xfree(tcs->command); tcs->command = NULL;
    xfree(tcs->token); tcs->token = NULL;
}

static int
handle_incoming_message(
        struct telegram_plugin_data *state,
        struct bot_state *bs,
        struct telegram_pbs *pbs,
        TeMessage *tem)
{
    struct telegram_user *mu = NULL; // mongo user
    struct telegram_chat *mc = NULL; // mongo chat
    struct TeSendMessageResult *send_result = NULL;
    struct telegram_chat_state *tcs = NULL;
    struct telegram_token *token = NULL;
    struct telegram_subscription *sub = NULL;
    int update_state = 0;

    if (!tem) return 0;

    if (tem->from) {
        TeUser *teu = tem->from;
        mu = state->conn->vt->user_fetch(state->conn, teu->id);
        if (need_update_user(mu, teu)) {
            info("updating user info for %lld", teu->id);
            telegram_user_free(mu);
            mu = telegram_user_create();
            mu->_id = teu->id;
            mu->username = safe_strdup(teu->username);
            mu->first_name = safe_strdup(teu->first_name);
            mu->last_name = safe_strdup(teu->last_name);
            state->conn->vt->user_save(state->conn, mu);
        }
    }
    if (tem->chat) {
        TeChat *tc = tem->chat;
        mc = state->conn->vt->chat_fetch(state->conn, tc->id);
        if (need_update_chat(mc, tc)) {
            info("updating chat info for %lld", tc->id);
            telegram_chat_free(mc);
            mc = telegram_chat_create();
            mc->_id = tc->id;
            mc->type = safe_strdup(tc->type);
            mc->title = safe_strdup(tc->title);
            mc->username = safe_strdup(tc->username);
            mc->first_name = safe_strdup(tc->first_name);
            mc->last_name = safe_strdup(tc->last_name);
            state->conn->vt->chat_save(state->conn, mc);
        }
    }

    if (!tem->chat || !tem->chat->type) goto cleanup;
    if (!mc) goto cleanup;
    if (strcmp(tem->chat->type, "private") != 0 && tem->text) {
        if (!strncmp(tem->text, "/chatid@", 8)) {
            char *reply_s = NULL;
            size_t reply_z = 0;
            FILE *reply_f = open_memstream(&reply_s, &reply_z);
            fprintf(reply_f, "This chat id is %lld\n", tem->chat->id);
            fclose(reply_f); reply_f = NULL;
            send_result = send_message(state, bs, mc, reply_s, NULL, NULL);
            free(reply_s);
            goto cleanup;
        } else if (tem->text[0] == '/' && strchr(tem->text, '@')) {
            char *reply_s = NULL;
            size_t reply_z = 0;
            FILE *reply_f = open_memstream(&reply_s, &reply_z);
            unsigned char *txt = get_random_phrase("phrases_1.txt");
            if (!txt) {
                txt = xstrdup("Let's use a private chat!");
            }
            fprintf(reply_f, "%s\n", txt);
            xfree(txt); txt = NULL;
            fclose(reply_f); reply_f = NULL;
            send_result = send_message(state, bs, mc, reply_s, NULL, NULL);
            free(reply_s);
            goto cleanup;
        } else {
            /*
            char *reply_s = NULL;
            size_t reply_z = 0;
            FILE *reply_f = open_memstream(&reply_s, &reply_z);
            fprintf(reply_f,
                    "Won't speak in public. Let's use a private chat.\n"
                    "This chat id is %lld\n", tem->chat->id);
            fclose(reply_f); reply_f = NULL;
            send_result = send_message(state, bs, mc, reply_s, NULL, NULL);
            free(reply_s);
            */
            goto cleanup;
        }
    }

    // only want private chats
    if (!tem->text) goto cleanup;

    // chat state machine is here
    tcs = state->conn->vt->chat_state_fetch(state->conn, mc->_id);
    if (!tcs) {
        tcs = telegram_chat_state_create();
        tcs->_id = mc->_id;
    }

    if (!tcs->state) {
        if (!strcmp(tem->text, "/subscribe")) {
            tcs->command = xstrdup(tem->text);
            tcs->state = 1;
            update_state = 1;
            send_result = send_message(state, bs, mc, "Enter Ejudge Telegram Token. You may obtain a token on Settings tab in the ejudge user interface.", NULL, NULL);
        } else if (!strcmp(tem->text, "/unsubscribe")) {
            tcs->command = xstrdup(tem->text);
            tcs->state = 1;
            update_state = 1;
            send_result = send_message(state, bs, mc, "Enter Ejudge Telegram Token. You may obtain a token on Settings tab in the ejudge user interface.", NULL, NULL);
        } else if (!strcmp(tem->text, "/cancel")) {
            send_result = send_message(state, bs, mc, "Operation canceled.", NULL, NULL);
            telegram_chat_state_reset(tcs);
            update_state = 1;
        } else if (!strcmp(tem->text, "/start")) {
            send_result = send_message(state, bs, mc, "Hi there! This is Eddie, your shipboard computer, and I'm feeling just great, guys, and I know I'm just going to get a bundle of kicks out of any program you care to run through me.", NULL, NULL);
            telegram_chat_state_reset(tcs);
            update_state = 1;
        } else if (!strcmp(tem->text, "/password")) {
            tcs->command = xstrdup(tem->text);
            tcs->state = 1;
            update_state = 1;
            send_result = send_message(state, bs, mc, "Enter the group number (for example, 201) and the student ID number (for example, 02220001), separated by spaces.", NULL, NULL);
        } else if (!strcmp(tem->text, "/chatid")) {
            char *reply_s = NULL;
            size_t reply_z = 0;
            FILE *reply_f = open_memstream(&reply_s, &reply_z);
            fprintf(reply_f, "This chat id is %lld\n", tem->chat->id);
            fclose(reply_f); reply_f = NULL;
            send_result = send_message(state, bs, mc, reply_s, NULL, NULL);
            free(reply_s);
            telegram_chat_state_reset(tcs);
            update_state = 1;
        } else if (!strcmp(tem->text, "/register")) {
            handle_register_0(state, bs, pbs, tem, tcs, mc);
            update_state = 1;
        } else if (!strcmp(tem->text, "/help")) {
            send_result = send_message(state, bs, mc,
                                       "List of commands:\n"
                                       "/subscribe - subscribe for event\n"
                                       "/unsubscribe - unsubscribe from event\n"
                                       "/cancel - cancel the current command\n"
                                       "/help - get this help\n",
                                       NULL, NULL);
        } else {
            send_result = send_message(state, bs, mc, "Sorry, cannot understand you! Type /help for help.", NULL, NULL);
        }
    } else if (tcs->state == 1) {
        if (!strcmp(tem->text, "/cancel")) {
            send_result = send_message(state, bs, mc, "Ok", NULL, NULL);
            telegram_chat_state_reset(tcs);
            update_state = 1;
        } else {
            if (!strcmp(tcs->command, "/password")) {
                unsigned char *reply = handle_get_password(state, tem);
                send_result =  send_message(state, bs, mc, reply, NULL, NULL);
                tcs->state = 0;
                xfree(tcs->command); tcs->command = NULL;
                xfree(tcs->token); tcs->token = NULL;
                xfree(reply);
                update_state = 1;
            } else if (!strcmp(tcs->command, "/register")) {
                handle_register_1(state, bs, pbs, tem, tcs, mc);
                update_state = 1;
            } else {
                int token_val, n;
                if (sscanf(tem->text, "%d%n", &token_val, &n) != 1 || tem->text[n] || token_val < 0 || token_val >= 1000000) {
                    send_result = send_message(state, bs, mc, "Token is invalid. Try again, or /cancel.", NULL, NULL);
                } else {
                    unsigned char buf[64];
                    snprintf(buf, sizeof(buf), "%d", token_val);
                    state->conn->vt->token_remove_expired(state->conn, 0);

                    int r = state->conn->vt->token_fetch(state->conn, buf, &token);
                    if (r < 0) {
                        send_result = send_message(state, bs, mc, "Internal error. Operation canceled.", NULL, NULL);
                        telegram_chat_state_reset(tcs);
                        update_state = 1;
                    } else if (!r || !token) {
                        send_result = send_message(state, bs, mc, "No such token. Try again, or /cancel.", NULL, NULL);
                    } else {
                        {
                            char *msg_s = NULL;
                            size_t msg_z = 0;
                            FILE *msg_f = open_memstream(&msg_s, &msg_z);
                            fprintf(msg_f, "Contest ID: %d", token->contest_id);
                            if (token->contest_name && *token->contest_name) {
                                fprintf(msg_f, " (%s)", token->contest_name);
                            }
                            fprintf(msg_f, "\n");
                            fprintf(msg_f, "User:");
                            if (token->user_login && *token->user_login) {
                                fprintf(msg_f, "%s", token->user_login);
                            } else {
                                fprintf(msg_f, "%d", token->user_id);
                            }
                            if (token->user_name && *token->user_name) {
                                fprintf(msg_f, " (%s)", token->user_name);
                            }
                            fprintf(msg_f, "\n");
                            fprintf(msg_f, "Please, select options. Press /done when done.\n");
                            fclose(msg_f);
                            send_result = send_message(state, bs, mc, msg_s, NULL, "{ \"keyboard\": [[{\"text\": \"review\"}, {\"text\": \"reply\"},{\"text\": \"/done\"}, {\"text\":\"/cancel\"}]]}");
                            free(msg_s);
                        }
                        if (send_result && send_result->ok) {
                            tcs->token = xstrdup(buf);
                            tcs->state = 2;
                            update_state = 1;
                        } else {
                            tcs->state = 0;
                            xfree(tcs->command); tcs->command = NULL;
                            xfree(tcs->token); tcs->token = NULL;
                            update_state = 1;
                        }
                    }
                }
            }
        }
    } else if (tcs->state == 2) {
        if (!strcmp(tem->text, "/cancel")) {
            send_result = send_message(state, bs, mc, "Operation canceled.", NULL, "{ \"hide_keyboard\": true}");
            telegram_chat_state_reset(tcs);
            update_state = 1;
        } else if (!strcmp(tem->text, "/done")) {
            int r = state->conn->vt->token_fetch(state->conn, tcs->token, &token);
            if (r < 0) {
                send_result = send_message(state, bs, mc, "Internal error. Operation canceled.", NULL, NULL);
            } else if (!r) {
                send_result = send_message(state, bs, mc, "Token expired. Operation failed.", NULL, NULL);
            } else {
                sub = state->conn->vt->subscription_fetch(state->conn, bs->bot_id, token->user_id, token->contest_id);
                if (!sub && !strcmp(tcs->command, "/unsubscribe")) {
                    send_result = send_message(state, bs, mc, "You have no subscriptions. Nothing to unsubscribe.", NULL, "{ \"hide_keyboard\": true}");
                } else {
                    if (!sub) sub = telegram_subscription_create(bs->bot_id, token->user_id, token->contest_id);
                    if (!strcmp(tcs->command, "/subscribe")) {
                        if (tcs->review_flag) sub->review_flag = 1;
                        if (tcs->reply_flag) sub->reply_flag = 1;
                    } else if (!strcmp(tcs->command, "/unsubscribe")) {
                        if (tcs->review_flag) sub->review_flag = 0;
                        if (tcs->reply_flag) sub->reply_flag = 0;
                    }
                    sub->chat_id = mc->_id;
                    {
                        char *msg_s = NULL;
                        size_t msg_z = 0;
                        FILE *msg_f = open_memstream(&msg_s, &msg_z);
                        fprintf(msg_f, "Current subscriptions:\n");
                        if (sub->review_flag) {
                            fprintf(msg_f, "    notify when my PENDING REVIEW run has been reviewed\n");
                        }
                        if (sub->reply_flag) {
                            fprintf(msg_f, "    notify when my message has been answered\n");
                        }
                        fclose(msg_f);
                        send_result = send_message(state, bs, mc, msg_s, NULL, "{ \"hide_keyboard\": true}");
                        free(msg_s);
                    }
                    state->conn->vt->subscription_save(state->conn, sub);
                }
                state->conn->vt->token_remove(state->conn, tcs->token);
            }
            telegram_chat_state_reset(tcs);
            update_state = 1;
        } else if (!strcmp(tem->text, "review")) {
            send_result = send_message(state, bs, mc, "Review Complete notification chosen", NULL, NULL);
            tcs->review_flag = 1;
            update_state = 1;
        } else if (!strcmp(tem->text, "reply")) {
            send_result = send_message(state, bs, mc, "Message Replied notification chosen", NULL, NULL);
            tcs->reply_flag = 1;
            update_state = 1;
        }
    }

    if (update_state) {
        state->conn->vt->chat_state_save(state->conn, tcs);
    }

cleanup:
    if (send_result) send_result->b.destroy(&send_result->b);
    telegram_subscription_free(sub);
    telegram_chat_state_free(tcs);
    telegram_chat_free(mc);
    telegram_user_free(mu);
    return 0;
}

static void
handle_reply(struct telegram_plugin_data *state,
             struct bot_state *bs,
             struct telegram_pbs *pbs,
             const unsigned char *reply)
{
    cJSON *root = NULL;
    TeGetUpdatesResult *updates = NULL;
    root = cJSON_Parse(reply);
    if (!root) {
        err("JSON parsing failed");
        goto cleanup;
    } else {
        if (!(updates = TeGetUpdatesResult_parse(root))) {
            err("TeGetUpdatesResult_parse failed");
            goto cleanup;
        }
        if (updates->ok) {
            int need_update = 0;
            for (int i = 0; i < updates->result.length; ++i) {
                const TeUpdate *tu = updates->result.v[i];
                info("{ update_id: %lld }", tu->update_id);
                if (handle_incoming_message(state, bs, pbs, tu->message))
                    need_update = 1;
                pbs->update_id = tu->update_id;
                need_update = 1;
                /*
                if (!pbs->update_id || tu->update_id > pbs->update_id) {
                    pbs->update_id = tu->update_id;
                    need_update = 1;
                }
                */
            }
            if (need_update) {
                state->conn->vt->pbs_save(state->conn, pbs);
            }
        }
    }

cleanup:
    TeGetUpdatesResult_destroy(&updates->b);
    if (root) {
        cJSON_Delete(root);
    }
}

static void
get_updates(struct telegram_plugin_data *state, struct bot_state *bs)
{
    CURL *curl = NULL;
    char *url_s = NULL, *resp_s = NULL;
    size_t url_z = 0, resp_z = 0;

    struct telegram_pbs *pbs = get_persistent_bot_state(state->conn, bs);
    if (!pbs) {
        err("cannot get persistent bot state for bot %s", bs->bot_id);
        return;
    }

    curl = curl_easy_init();
    if (!curl) {
        err("cannot initialize curl");
        goto cleanup;
    }

    {
        FILE *url_f = open_memstream(&url_s, &url_z);
        fprintf(url_f, "https://api.telegram.org/bot%s/%s", bs->bot_id, "getUpdates");
        if (pbs->update_id) {
            fprintf(url_f, "?offset=%lld", pbs->update_id + 1);
        }
        fclose(url_f);
    }

    //fprintf(stderr, "request: %s\n", url_s);

    {
        FILE *resp_f = open_memstream(&resp_s, &resp_z);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT);
        curl_easy_setopt(curl, CURLOPT_AUTOREFERER, 1);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
        curl_easy_setopt(curl, CURLOPT_URL, url_s);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp_f);
        if (state->curl_verbose_flag > 0) {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
        }
        CURLcode res = curl_easy_perform(curl);
        fclose(resp_f);
        if (res != CURLE_OK) {
            err("curl request failed");
            goto cleanup;
        }
    }

    xfree(url_s); url_s = NULL;

    //fprintf(stderr, "reply body: %s\n", resp_s);
    handle_reply(state, bs, pbs, resp_s);

cleanup:
    xfree(resp_s);
    xfree(url_s);
    if (curl) {
        curl_easy_cleanup(curl);
    }
}

static void
periodic_handler(int uid, int argc, char **argv, void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;

    for (int i = 0; i < state->bots.u; ++i) {
        get_updates(state, state->bots.v[i]);
    }
}

static void
queue_periodic_handler(void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;
    put_to_queue(state, periodic_handler, 0, 0, 0);
}
