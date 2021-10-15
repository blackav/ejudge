/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2021 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/auth_plugin.h"
#include "ejudge/xml_utils.h"
#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"
#include "ejudge/logger.h"
#include "ejudge/cJSON.h"
#include "ejudge/base64.h"
#include "ejudge/random.h"
#include "ejudge/misctext.h"
#include "ejudge/osdeps.h"
#include "../common-mysql/common_mysql.h"

#if CONF_HAS_LIBCURL - 0 == 1
#include <curl/curl.h>
#else
#error curl required
#endif

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <signal.h>
#include <pthread.h>

static struct common_plugin_data*
init_func(void);
static int
finish_func(struct common_plugin_data *data);
static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree);
static int
open_func(void *data);
static int
check_func(void *data);
static int
start_thread_func(void *data);
static void
set_set_command_handler_func(
        void *data,
        auth_set_command_handler_t setter,
        void *setter_self);
static void
set_send_job_handler_func(
        void *data,
        auth_send_job_handler_t handler,
        void *handler_self);
static unsigned char *
get_redirect_url_func(
        void *data,
        const unsigned char *cookie,
        const unsigned char *provider,
        int contest_id,
        const unsigned char *extra_data);
static unsigned char *
process_auth_callback_func(
        void *data,
        const unsigned char *state_id,
        const unsigned char *code);
static struct OAuthLoginResult
get_result_func(
        void *data,
        const unsigned char *job_id);

struct auth_plugin_iface plugin_auth_google =
{
    {
        {
            sizeof (struct auth_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "auth",
            "google",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    AUTH_PLUGIN_IFACE_VERSION,
    open_func,
    check_func,
    start_thread_func,
    set_set_command_handler_func,
    set_send_job_handler_func,
    get_redirect_url_func,
    process_auth_callback_func,
    get_result_func,
};

struct queue_item
{
    void (*handler)(int uid, int argc, char **argv, void *user);
    int uid;
    int argc;
    char **argv;
};

enum { QUEUE_SIZE = 64 };

struct auth_google_state
{
    // mysql access
    struct common_mysql_iface *mi;
    struct common_mysql_state *md;
    // curl for auth endpoint discovery
    CURL *curl;
    unsigned char *authorization_endpoint;
    unsigned char *token_endpoint;

    unsigned char *client_id;
    unsigned char *client_secret;
    unsigned char *redirect_uri;

    // background request thread
    pthread_t worker_thread;
    _Atomic _Bool worker_thread_finish_request;

    auth_set_command_handler_t set_command_handler_func;
    void *set_command_handler_data;

    auth_send_job_handler_t send_job_handler_func;
    void *send_job_handler_data;

    pthread_mutex_t q_m;
    pthread_cond_t  q_c;
    int q_first;
    int q_len;
    struct queue_item queue[QUEUE_SIZE];
};

struct oauth_stage1_internal
{
    unsigned char *state_id;
    unsigned char *provider;
    unsigned char *cookie;
    int contest_id;
    unsigned char *extra_data;
    time_t create_time;
    time_t expiry_time;
};

enum { OAUTH_STAGE1_ROW_WIDTH = 7 };

#define OAUTH_STAGE1_OFFSET(f) XOFFSET(struct oauth_stage1_internal, f)

static const struct common_mysql_parse_spec oauth_stage1_spec[OAUTH_STAGE1_ROW_WIDTH] =
{
    { 1, 's', "state_id", OAUTH_STAGE1_OFFSET(state_id), 0 },
    { 1, 's', "provider", OAUTH_STAGE1_OFFSET(provider), 0 },
    { 1, 's', "cookie", OAUTH_STAGE1_OFFSET(cookie), 0 },
    { 0, 'd', "contest_id", OAUTH_STAGE1_OFFSET(contest_id), 0 },
    { 1, 's', "extra_data", OAUTH_STAGE1_OFFSET(extra_data), 0 },
    { 0, 't', "create_time", OAUTH_STAGE1_OFFSET(create_time), 0 },
    { 0, 't', "expiry_time", OAUTH_STAGE1_OFFSET(expiry_time), 0 },
};

struct oauth_stage2_internal
{
    unsigned char *request_id;
    unsigned char *provider;
    int request_state;
    unsigned char *request_code;
    unsigned char *cookie;
    int contest_id;
    unsigned char *extra_data;
    time_t create_time;
    time_t update_time;
    unsigned char *response_email;
    unsigned char *response_name;
    unsigned char *access_token;
    unsigned char *id_token;
    unsigned char *error_message;
};

enum { OAUTH_STAGE2_ROW_WIDTH = 14 };

#define OAUTH_STAGE2_OFFSET(f) XOFFSET(struct oauth_stage2_internal, f)

static const struct common_mysql_parse_spec oauth_stage2_spec[OAUTH_STAGE2_ROW_WIDTH] =
{
    { 1, 's', "request_id", OAUTH_STAGE2_OFFSET(request_id), 0 },
    { 1, 's', "provider", OAUTH_STAGE2_OFFSET(provider), 0 },
    { 0, 'd', "request_state", OAUTH_STAGE2_OFFSET(request_state), 0 },
    { 1, 's', "request_code", OAUTH_STAGE2_OFFSET(request_code), 0 },
    { 1, 's', "cookie", OAUTH_STAGE2_OFFSET(cookie), 0 },
    { 0, 'd', "contest_id", OAUTH_STAGE2_OFFSET(contest_id), 0 },
    { 1, 's', "extra_data", OAUTH_STAGE2_OFFSET(extra_data), 0 },
    { 0, 't', "create_time", OAUTH_STAGE2_OFFSET(create_time), 0 },
    { 1, 't', "update_time", OAUTH_STAGE2_OFFSET(update_time), 0 },
    { 1, 's', "response_email", OAUTH_STAGE2_OFFSET(response_email), 0 },
    { 1, 's', "response_name", OAUTH_STAGE2_OFFSET(response_name), 0 },
    { 1, 's', "access_token", OAUTH_STAGE2_OFFSET(access_token), 0 },
    { 1, 's', "id_token", OAUTH_STAGE2_OFFSET(id_token), 0 },
    { 1, 's', "error_message", OAUTH_STAGE2_OFFSET(error_message), 0 },
};

static void
put_to_queue(
        struct auth_google_state *state,
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

static void *
thread_func(void *data)
{
    sigset_t ss;
    sigfillset(&ss);
    pthread_sigmask(SIG_BLOCK, &ss, NULL);

    struct auth_google_state *state = (struct auth_google_state*) data;
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

static struct common_plugin_data*
init_func(void)
{
    struct auth_google_state *state;

    XCALLOC(state, 1);

    state->curl = curl_easy_init();

    pthread_mutex_init(&state->q_m, NULL);
    pthread_cond_init(&state->q_c, NULL);

    return (struct common_plugin_data*) state;
}

static int
finish_func(struct common_plugin_data *data)
{
    return 0;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree)
{
    const struct xml_parse_spec *spec = ejudge_cfg_get_spec();

    // load common_mysql plugin
    const struct common_loaded_plugin *mplg;
    if (!(mplg = plugin_load_external(0, "common", "mysql", config))) {
        err("cannot load common_mysql plugin");
        return -1;
    }

    struct auth_google_state *state = (struct auth_google_state*) data;
    state->mi = (struct common_mysql_iface*) mplg->iface;
    state->md = (struct common_mysql_state*) mplg->data;

    // handle config section
    ASSERT(tree->tag == spec->default_elem);
    ASSERT(!strcmp(tree->name[0], "config"));

    for (struct xml_tree *p = tree->first_down; p; p = p->right) {
        ASSERT(p->tag == spec->default_elem);

        if (!strcmp(p->name[0], "client_id")) {
            if (xml_leaf_elem(p, &state->client_id, 1, 0) < 0) return -1;
        } else if (!strcmp(p->name[0], "client_secret")) {
            if (xml_leaf_elem(p, &state->client_secret, 1, 0) < 0) return -1;
        } else if (!strcmp(p->name[0], "redirect_uri")) {
            if (xml_leaf_elem(p, &state->redirect_uri, 1, 0) < 0) return -1;
        }
    }

    return 0;
}

static int
open_func(void *data)
{
  struct auth_google_state *state = (struct auth_google_state*) data;

  if (state->mi->connect(state->md) < 0)
    return -1;

  return 0;
}

static int
fetch_google_endpoints(struct auth_google_state *state)
{
    char *page_text = NULL;
    size_t page_size = 0;
    FILE *file = NULL;
    CURLcode res = 0;
    cJSON *root = NULL;

    curl_easy_setopt(state->curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(state->curl, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(state->curl, CURLOPT_URL, "https://accounts.google.com/.well-known/openid-configuration");
    file = open_memstream(&page_text, &page_size);
    curl_easy_setopt(state->curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(state->curl, CURLOPT_WRITEDATA, file);
    res = curl_easy_perform(state->curl);
    fclose(file); file = NULL;
    if (res != CURLE_OK) {
        err("Request failed: %s", curl_easy_strerror(res));
        goto fail;
    }
    root = cJSON_Parse(page_text);
    if (!root) {
        err("JSON parse failed");
        goto fail;
    }
    if (root->type != cJSON_Object) {
        err("invalid json, root document expected");
        goto fail;
    }
    cJSON *jauth = cJSON_GetObjectItem(root, "authorization_endpoint");
    if (!jauth || jauth->type != cJSON_String) {
        err("invalid json, invalid authorization_endpoint");
        goto fail;
    }
    state->authorization_endpoint = xstrdup(jauth->valuestring);

    cJSON *jtoken = cJSON_GetObjectItem(root, "token_endpoint");
    if (!jtoken || jtoken->type != cJSON_String) {
        err("invalid json, invalid token_endpoint");
        goto fail;
    }
    state->token_endpoint = xstrdup(jtoken->valuestring);

    return 0;

fail:
    if (root) cJSON_Delete(root);
    if (file) fclose(file);
    free(page_text);
    return -1;
}

static const char oauth_stage1_create_str[] =
"CREATE TABLE %soauth_stage1 ( \n"
"    state_id VARCHAR(64) NOT NULL PRIMARY KEY,\n"
"    provider VARCHAR(64) NOT NULL,\n"
"    cookie VARCHAR(64) NOT NULL,\n"
"    contest_id INT NOT NULL DEFAULT 0,\n"
"    extra_data VARCHAR(512) DEFAULT NULL,\n"
"    create_time DATETIME NOT NULL,\n"
"    expiry_time DATETIME NOT NULL\n"
") DEFAULT CHARSET=utf8 COLLATE=utf8_bin;";

static const char oauth_stage2_create_str[] =
"CREATE TABLE %soauth_stage2 ( \n"
"    request_id VARCHAR(64) NOT NULL PRIMARY KEY,\n"
"    provider VARCHAR(64) NOT NULL,\n"
"    request_state INT NOT NULL DEFAULT 0,\n"
"    request_code VARCHAR(256) NOT NULL,\n"
"    cookie VARCHAR(64) NOT NULL,\n"
"    contest_id INT NOT NULL DEFAULT 0,\n"
"    extra_data VARCHAR(512) DEFAULT NULL,\n"
"    create_time DATETIME NOT NULL,\n"
"    update_time DATETIME DEFAULT NULL,\n"
"    response_email VARCHAR(64) DEFAULT NULL,\n"
"    response_name VARCHAR(64) DEFAULT NULL,\n"
"    access_token VARCHAR(256) DEFAULT NULL,\n"
"    id_token VARCHAR(2048) DEFAULT NULL,\n"
"    error_message VARCHAR(256) DEFAULT NULL\n"
") DEFAULT CHARSET=utf8 COLLATE=utf8_bin;";

static int
do_check_database(struct auth_google_state *state)
{
    if (state->mi->simple_fquery(state->md, "SELECT config_val FROM %sconfig WHERE config_key = 'oauth_version' ;", state->md->table_prefix) < 0) {
        err("probably the database is not created. use --convert or --create");
        return -1;
    }
    if((state->md->field_count = mysql_field_count(state->md->conn)) != 1) {
        err("wrong database format: field_count == %d", state->md->field_count);
        return -1;
    }
    if (!(state->md->res = mysql_store_result(state->md->conn)))
        return state->mi->error(state->md);

    state->md->row_count = mysql_num_rows(state->md->res);
    if (!state->md->row_count) {
        int version = 1;
        if (state->mi->simple_fquery(state->md, oauth_stage1_create_str,
                                     state->md->table_prefix) < 0)
            return -1;
        if (state->mi->simple_fquery(state->md, oauth_stage2_create_str,
                                     state->md->table_prefix) < 0)
            return -1;
        if (state->mi->simple_fquery(state->md, "INSERT INTO %sconfig SET config_key='oauth_version', config_val='%d';",
                                     state->md->table_prefix, version) < 0)
            return -1;
    } else {
        if (state->md->row_count > 1) {
            err("wrong database format: row_count == %d", state->md->row_count);
            return -1;
        }
        int version = 0;
        if (state->mi->int_val(state->md, &version, 0) < 0) {
            return -1;
        }
        if (version != 1) {
            err("invalid version %d", version);
            return -1;
        }
    }
    state->mi->free_res(state->md);
    return 0;
}

static int
check_database(struct auth_google_state *state)
{
    int result = -1;
    time_t current_time = time(NULL);

    if (state->mi->simple_fquery(state->md, "INSERT INTO %sconfig SET config_key='oauth_update_lock', config_val='%ld';",
                                 state->md->table_prefix, (long) current_time) < 0) {
        // FIXME: check for DUPLICATE PKEY error
        // FIXME: sleep for some time and then reattempt
        // FIXME: fail after some attempts
        return 0;
    }

    result = do_check_database(state);

    state->mi->simple_fquery(state->md, "DELETE FROM %sconfig WHERE config_key = 'oauth_update_lock';", state->md->table_prefix);
    return result;
}

static int
check_func(void *data)
{
    struct auth_google_state *state = (struct auth_google_state*) data;

    if (!state->md->conn) return -1;

    check_database(state);

    fetch_google_endpoints(state);

    return 0;
}

static void
set_set_command_handler_func(
        void *data,
        auth_set_command_handler_t setter,
        void *setter_self)
{
    struct auth_google_state *state = (struct auth_google_state*) data;

    state->set_command_handler_func = setter;
    state->set_command_handler_data = setter_self;
}

static void
set_send_job_handler_func(
        void *data,
        auth_send_job_handler_t handler,
        void *handler_self)
{
    struct auth_google_state *state = (struct auth_google_state*) data;

    state->send_job_handler_func = handler;
    state->send_job_handler_data = handler_self;
}

static void
queue_packet_handler_auth_google(int uid, int argc, char **argv, void *user);

static int
start_thread_func(void *data)
{
    struct auth_google_state *state = (struct auth_google_state*) data;

    if (!state->set_command_handler_func) {
        return 0;
    }

    state->set_command_handler_func(state->set_command_handler_data,
                                    "auth_google",
                                    queue_packet_handler_auth_google,
                                    data);

    int r = pthread_create(&state->worker_thread, NULL, thread_func, state);
    if (r) {
        err("auth_google: cannot create worker thread: %s", os_ErrorMsg());
        return -1;
    }

    return 0;
}

static unsigned char *
get_redirect_url_func(
        void *data,
        const unsigned char *cookie,
        const unsigned char *provider,
        int contest_id,
        const unsigned char *extra_data)
{
    struct auth_google_state *state = (struct auth_google_state*) data;

    unsigned char rbuf[16];
    unsigned char ebuf[32];
    char *req_s = NULL;
    size_t req_z = 0;
    FILE *req_f = NULL;
    time_t create_time = time(NULL);
    time_t expiry_time = create_time + 60;
    char *url_s = NULL;
    size_t url_z = 0;
    FILE *url_f = NULL;
    struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

    random_init();
    random_bytes(rbuf, sizeof(rbuf));
    int len = base64u_encode(rbuf, sizeof(rbuf), ebuf);
    ebuf[len] = 0;

    req_f = open_memstream(&req_s, &req_z);
    fprintf(req_f, "INSERT INTO %soauth_stage1 VALUES (", state->md->table_prefix);
    fprintf(req_f, "'%s'", ebuf);
    state->mi->write_escaped_string(state->md, req_f, ",", provider);
    state->mi->write_escaped_string(state->md, req_f, ",", cookie);
    fprintf(req_f, ", %d", contest_id);
    state->mi->write_escaped_string(state->md, req_f, ",", extra_data);
    state->mi->write_timestamp(state->md, req_f, ",", create_time);
    state->mi->write_timestamp(state->md, req_f, ",", expiry_time);
    fprintf(req_f, ") ;");
    fclose(req_f); req_f = NULL;

    if (state->mi->simple_query(state->md, req_s, req_z) < 0) goto fail;
    free(req_s); req_s = NULL;

    url_f = open_memstream(&url_s, &url_z);
    fprintf(url_f, "%s?client_id=%s&response_type=code",
            state->authorization_endpoint,
            url_armor_buf(&ab, state->client_id));
    fprintf(url_f, "&redirect_uri=%s/S1", url_armor_buf(&ab, state->redirect_uri));
    fprintf(url_f, "&state=%s", ebuf);
    fprintf(url_f, "&scope=openid%%20profile%%20email");
    fclose(url_f); url_f = NULL;

    html_armor_free(&ab);
    return url_s;

fail:
    html_armor_free(&ab);
    free(req_s);
    return NULL;
}

static unsigned char *
process_auth_callback_func(
        void *data,
        const unsigned char *state_id,
        const unsigned char *code)
{
    struct auth_google_state *state = (struct auth_google_state*) data;

    char *req_s = NULL;
    size_t req_z = 0;
    FILE *req_f = NULL;
    struct oauth_stage1_internal oas1 = {};
    struct oauth_stage2_internal oas2 = {};
    unsigned char rbuf[16];
    unsigned char ebuf[32] = {};

    req_f = open_memstream(&req_s, &req_z);
    fprintf(req_f, "SELECT * FROM %soauth_stage1 WHERE state_id = ", state->md->table_prefix);
    state->mi->write_escaped_string(state->md, req_f, "", state_id);
    fprintf(req_f, ";");
    fclose(req_f); req_f = NULL;

    if (state->mi->query(state->md, req_s, req_z, OAUTH_STAGE1_ROW_WIDTH) < 0) goto fail;
    free(req_s); req_s = NULL; req_z = 0;

    if (state->md->row_count > 1) {
        err("auth_google: callback: row_count == %d", state->md->row_count);
        goto fail;
    }
    if (!state->md->row_count) {
        err("auth_google: callback: state_id '%s' does not exist", state_id);
        goto fail;
    }

    if (state->mi->next_row(state->md) < 0) goto fail;
    if (state->mi->parse_spec(state->md, state->md->field_count, state->md->row, state->md->lengths,
                              OAUTH_STAGE1_ROW_WIDTH, oauth_stage1_spec, &oas1) < 0)
        goto fail;
    state->mi->free_res(state->md);

    req_f = open_memstream(&req_s, &req_z);
    fprintf(req_f, "DELETE FROM %soauth_stage1 WHERE state_id = ", state->md->table_prefix);
    state->mi->write_escaped_string(state->md, req_f, "", state_id);
    fprintf(req_f, ";");
    fclose(req_f); req_f = NULL;
    if (state->mi->simple_query(state->md, req_s, req_z) , 0)
        goto fail;
    free(req_s); req_s = NULL; req_z = 0;

    random_init();
    random_bytes(rbuf, sizeof(rbuf));
    int len = base64u_encode(rbuf, sizeof(rbuf), ebuf);
    ebuf[len] = 0;

    oas2.request_id = ebuf;
    oas2.request_code = xstrdup(code);
    oas2.cookie = oas1.cookie; oas1.cookie = NULL;
    oas2.provider = oas1.provider; oas1.provider = NULL;
    oas2.contest_id = oas1.contest_id;
    oas2.extra_data = oas1.extra_data; oas1.extra_data = NULL;
    oas2.create_time = time(NULL);

    req_f = open_memstream(&req_s, &req_z);
    fprintf(req_f, "INSERT INTO %soauth_stage2 VALUES ( ", state->md->table_prefix);
    state->mi->unparse_spec(state->md, req_f, OAUTH_STAGE2_ROW_WIDTH, oauth_stage2_spec, &oas2);
    fprintf(req_f, ") ;");
    fclose(req_f); req_f = NULL;
    if (state->mi->simple_query(state->md, req_s, req_z) < 0) goto fail;
    free(req_s); req_s = NULL;

    if (state->send_job_handler_func) {
        unsigned char *args[] = { "auth_google", oas2.request_id, oas2.request_code, NULL };
        state->send_job_handler_func(state->send_job_handler_data, args);
    } else {
        err("send_job_handler_func is not installed");
        goto fail;
    }

    free(oas1.state_id);
    free(oas1.provider);
    free(oas1.cookie);
    free(oas1.extra_data);
    free(oas2.request_code);
    free(oas2.provider);
    free(oas2.cookie);
    free(oas2.extra_data);

    return xstrdup(oas2.request_id);

fail:
    free(oas1.state_id);
    free(oas1.provider);
    free(oas1.cookie);
    free(oas1.extra_data);
    free(oas2.request_code);
    free(oas2.provider);
    free(oas2.cookie);
    free(oas2.extra_data);
    state->mi->free_res(state->md);
    if (req_f) fclose(req_f);
    free(req_s);
    return NULL;
}

static struct OAuthLoginResult
get_result_func(
        void *data,
        const unsigned char *request_id)
{
    struct auth_google_state *state = (struct auth_google_state*) data;
    unsigned char *error_message = NULL;
    char *req_s = NULL;
    size_t req_z = 0;
    FILE *req_f = NULL;
    struct oauth_stage2_internal oas2 = {};
    struct OAuthLoginResult res = {};

    req_f = open_memstream(&req_s, &req_z);
    fprintf(req_f, "SELECT * FROM %soauth_stage2 WHERE request_id = ", state->md->table_prefix);
    state->mi->write_escaped_string(state->md, req_f, "", request_id);
    fprintf(req_f, ";");
    fclose(req_f); req_f = NULL;

    if (state->mi->query(state->md, req_s, req_z, OAUTH_STAGE2_ROW_WIDTH) < 0) {
        error_message = xstrdup("query failed");
        goto fail;
    }
    free(req_s); req_s = NULL; req_z = 0;
    if (state->md->row_count > 1) {
        err("auth_google: get_result: row_count == %d", state->md->row_count);
        error_message = xstrdup("non unique row");
        goto fail;
    }
    if (!state->md->row_count) {
        err("auth_google: get_result: request_id '%s' does not exist", request_id);
        error_message = xstrdup("nonexisting request");
        goto fail;
    }
    if (state->mi->next_row(state->md) < 0) goto fail;
    if (state->mi->parse_spec(state->md, state->md->field_count, state->md->row, state->md->lengths,
                              OAUTH_STAGE2_ROW_WIDTH, oauth_stage2_spec, &oas2) < 0)
        goto fail;
    state->mi->free_res(state->md);

    // FIXME: remove completed requests

    res.status = oas2.request_state;
    res.provider = oas2.provider; oas2.provider = NULL;
    res.cookie = oas2.cookie; oas2.cookie = NULL;
    res.extra_data = oas2.extra_data; oas2.extra_data = NULL;
    res.email = oas2.response_email; oas2.response_email = NULL;
    res.name = oas2.response_name; oas2.response_name = NULL;
    res.access_token = oas2.access_token; oas2.access_token = NULL;
    res.id_token = oas2.id_token; oas2.id_token = NULL;
    res.error_message = oas2.error_message; oas2.error_message = NULL;
    res.contest_id = oas2.contest_id;
    return res;

fail:
    free(oas2.request_id);
    free(oas2.provider);
    free(oas2.request_code);
    free(oas2.cookie);
    free(oas2.extra_data);
    free(oas2.response_email);
    free(oas2.response_name);
    free(oas2.access_token);
    free(oas2.id_token);
    free(oas2.error_message);
    state->mi->free_res(state->md);
    if (req_f) fclose(req_f);
    free(req_s);
    if (!error_message) error_message = xstrdup("unknown error");
    return (struct OAuthLoginResult) { .status = 2, .error_message = error_message };
}

/*
  args[0] = "auth_google"
  args[1] = request_id
  args[2] = request_code
  args[3] = NULL;
 */
static void
packet_handler_auth_google(int uid, int argc, char **argv, void *user)
{
    struct auth_google_state *state = (struct auth_google_state*) user;

    const unsigned char *request_id = argv[1];
    const unsigned char *request_code = argv[2];

    char *post_s = NULL;
    size_t post_z = 0;
    FILE *post_f = NULL;
    char *json_s = NULL;
    size_t json_z = 0;
    FILE *json_f = NULL;
    struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
    CURLcode res = 0;
    int request_status = 2;   // failed
    const char *error_message = "unknown error";
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    const unsigned char *response_email = NULL;
    const unsigned char *response_name = NULL;
    const unsigned char *access_token = NULL;
    const unsigned char *id_token = NULL;
    cJSON *root = NULL;
    cJSON *jwt = NULL;
    unsigned char *jwt_payload = NULL;

    post_f = open_memstream(&post_s, &post_z);
    fprintf(post_f, "grant_type=authorization_code");
    fprintf(post_f, "&code=%s", url_armor_buf(&ab, request_code));
    fprintf(post_f, "&client_id=%s", url_armor_buf(&ab, state->client_id));
    fprintf(post_f, "&client_secret=%s", url_armor_buf(&ab, state->client_secret));
    fprintf(post_f, "&redirect_uri=%s/S1", url_armor_buf(&ab, state->redirect_uri));
    fclose(post_f); post_f = NULL;

    json_f = open_memstream(&json_s, &json_z);
    curl_easy_setopt(state->curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(state->curl, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(state->curl, CURLOPT_URL, state->token_endpoint);
    curl_easy_setopt(state->curl, CURLOPT_POST, 1);
    curl_easy_setopt(state->curl, CURLOPT_POSTFIELDS, post_s);
    curl_easy_setopt(state->curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(state->curl, CURLOPT_WRITEDATA, json_f);
    res = curl_easy_perform(state->curl);
    fclose(json_f); json_f = NULL;
    free(post_s); post_s = NULL; post_z = 0;
    if (res != CURLE_OK) {
        err("Request failed: %s", curl_easy_strerror(res));
        error_message = "request failed";
        goto done;
    }

    //fprintf(stderr, ">>%s<<\n", json_s);

    if (!(root = cJSON_Parse(json_s))) {
        error_message = "google JSON parse failed";
        goto done;
    }
    free(json_s); json_s = NULL; json_z = 0;

    if (root->type != cJSON_Object) {
        error_message = "google root document expected";
        goto done;
    }

    cJSON *j = cJSON_GetObjectItem(root, "access_token");
    if (!j || j->type != cJSON_String) {
        error_message = "invalid google json: access_token";
        goto done;
    }
    access_token = j->valuestring;

    if (!(j = cJSON_GetObjectItem(root, "id_token")) || j->type != cJSON_String) {
        error_message = "invalid google json: id_token";
        goto done;
    }
    id_token = j->valuestring;

    // parse payload of JWT
    {
        char *p1 = strchr(id_token, '.');
        if (!p1) {
            error_message = "invalid google json: invalid JWT (1)";
            goto done;
        }
        char *p2 = strchr(p1 + 1, '.');
        if (!p2) {
            error_message = "invalid google json: invalid JWT (2)";
            goto done;
        }

        jwt_payload = xmalloc(strlen(id_token) + 1);
        int err = 0;
        int len = base64u_decode(p1 + 1, p2 - p1 - 1, jwt_payload, &err);
        if (err) {
            error_message = "invalid google json: base64u payload decode error";
            goto done;
        }
        jwt_payload[len] = 0;
    }

    if (!(jwt = cJSON_Parse(jwt_payload))) {
        error_message = "JWT payload parse failed";
        goto done;
    }
    if (jwt->type != cJSON_Object) {
        error_message = "JWT payload root document expected";
        goto done;
    }

    if (!(j = cJSON_GetObjectItem(jwt, "email")) || j->type != cJSON_String) {
        error_message = "JWT payload email expected";
        goto done;
    }
    response_email = j->valuestring;

    if ((j = cJSON_GetObjectItem(jwt, "name")) && j->type == cJSON_String) {
        response_name = j->valuestring;
    }

    // success
    request_status = 3;
    error_message = NULL;

done:

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "UPDATE %soauth_stage2 SET request_state = %d",
            state->md->table_prefix, request_status);
    if (error_message && *error_message) {
        fprintf(cmd_f, ", error_message = ");
        state->mi->write_escaped_string(state->md, cmd_f, "", error_message);
    }
    if (response_name && *response_name) {
        fprintf(cmd_f, ", response_name = ");
        state->mi->write_escaped_string(state->md, cmd_f, "", response_name);
    }
    if (response_email && *response_email) {
        fprintf(cmd_f, ", response_email = ");
        state->mi->write_escaped_string(state->md, cmd_f, "", response_email);
    }
    if (access_token && *access_token) {
        fprintf(cmd_f, ", access_token = ");
        state->mi->write_escaped_string(state->md, cmd_f, "", access_token);
    }
    if (id_token && *id_token) {
        fprintf(cmd_f, ", id_token = ");
        state->mi->write_escaped_string(state->md, cmd_f, "", id_token);
    }
    fprintf(cmd_f, ", update_time = NOW() WHERE request_id = ");
    state->mi->write_escaped_string(state->md, cmd_f, "", request_id);
    fprintf(cmd_f, " ;");
    fclose(cmd_f); cmd_f = NULL;
    state->mi->simple_query(state->md, cmd_s, cmd_z); // error is ignored
    free(cmd_s); cmd_s = NULL;

    free(jwt_payload);
    if (root) cJSON_Delete(root);
    html_armor_free(&ab);
    if (json_f) fclose(json_f);
    free(json_s);
    if (post_f) fclose(post_f);
    free(post_s);
    if (jwt) cJSON_Delete(jwt);
}

static void
queue_packet_handler_auth_google(int uid, int argc, char **argv, void *user)
{
    struct auth_google_state *state = (struct auth_google_state*) user;
    put_to_queue(state, packet_handler_auth_google, uid, argc, argv);
}
