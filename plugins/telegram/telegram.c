/* -*- mode: c -*- */

/* Copyright (C) 2016 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_jobs.h"
#include "ejudge/xml_utils.h"

#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"
#include "ejudge/bson_utils.h"

#include "telegram_data.h"
#include "telegram_pbs.h"
#include "telegram_token.h"

#include "ejudge/cJSON.h"

#if CONF_HAS_LIBCURL - 0 == 1
#include <curl/curl.h>
#endif

#include <mongo.h>

#include <string.h>
#include <errno.h>

#define MONGO_RETRY_TIMEOUT 60
#define TELEGRAM_BOTS_TABLE_NAME "telegram_bots"
#define TELEGRAM_TOKENS_TABLE_NAME "telegram_tokens"

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
packet_handler_telegram(int uid, int argc, char **argv, void *user);
static void
packet_handler_telegram_token(int uid, int argc, char **argv, void *user);

static void
periodic_handler(void *user);

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

struct telegram_plugin_data
{
    struct
    {
        struct bot_state **v;
        int a, u;
    } bots;

    // mongo connectivity
    unsigned char *database;
    unsigned char *host;
    unsigned char *table_prefix;
    unsigned char *user;
    unsigned char *password;
    int port;
    int show_queries;
    struct _mongo_sync_connection *conn;
    time_t last_check_time;
};

static void
add_bot_id(struct telegram_plugin_data *state, const unsigned char *id)
{
    if (!id) return;
    for (int i = 0; i < state->bots.u; ++i) {
        if (!strcmp(state->bots.v[i]->bot_id, id))
            return;
    }
    if (state->bots.u == state->bots.a) {
        if (!(state->bots.a *= 2)) state->bots.a = 16;
        XREALLOC(state->bots.v, state->bots.a);
    }
    struct bot_state *bs = NULL;
    XCALLOC(bs, 1);
    bs->bot_id = xstrdup(id);
    state->bots.v[state->bots.u++] = bs;
}

static struct common_plugin_data *
init_func(void)
{
    struct telegram_plugin_data *state = NULL;
    XCALLOC(state, 1);
    return (struct common_plugin_data*) state;
}

static int
finish_func(struct common_plugin_data *data)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) data;

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
        }
    }
  
    ej_jobs_add_handler("telegram", packet_handler_telegram, state);
    ej_jobs_add_handler("telegram_token", packet_handler_telegram_token, state);
    ej_jobs_add_periodic_handler(periodic_handler, state);
    return 0;
}

static struct _mongo_sync_connection *
get_mongo_connection(struct telegram_plugin_data *state)
{
    if (state->conn) return state->conn;

    time_t current_time = time(NULL);
    if (state->last_check_time > 0 && state->last_check_time + MONGO_RETRY_TIMEOUT > current_time) {
        return NULL;
    }

    if (!state->database) {
        if (!state->database) state->database = xstrdup("ejudge");
        if (!state->host) state->host = xstrdup("localhost");
        if (!state->table_prefix) state->table_prefix = xstrdup("");
        if (state->port <= 0) state->port = 27017;
        state->show_queries = 1;
    }
    state->last_check_time = current_time;

    state->conn = mongo_sync_connect(state->host, state->port, 0);
    if (!state->conn) {
        err("cannot connect to mongodb: %s", os_ErrorMsg());
        return NULL;
    }
    mongo_sync_conn_set_safe_mode(state->conn, 1);
    mongo_sync_conn_set_auto_reconnect(state->conn, 1);
    if (state->user && state->password) {
        if (!mongo_sync_cmd_authenticate(state->conn, state->database, state->user, state->password)) {
            err("mongodb authentification failed: %s", os_ErrorMsg());
            mongo_sync_disconnect(state->conn);
            state->conn = NULL;
            return NULL;
        }
    }
    return state->conn;
}

int
save_persistent_bot_state(struct telegram_plugin_data *state, const struct telegram_pbs *pbs)
{
    mongo_sync_connection *conn = get_mongo_connection(state);
    if (!conn) return -1;
    char ns[1024];
    int retval = -1;

    bson *s = bson_new();
    bson_append_string(s, "_id", pbs->_id, strlen(pbs->_id));
    bson_finish(s);

    bson *b = telegram_pbs_unparse_bson(pbs);
    snprintf(ns, sizeof(ns), "%s.%s%s", state->database, state->table_prefix, TELEGRAM_BOTS_TABLE_NAME);
    if (!mongo_sync_cmd_update(conn, ns, MONGO_WIRE_FLAG_UPDATE_UPSERT, s, b)) {
        err("save_persistent_bot_state: failed: %s", os_ErrorMsg());
        goto done;
    }
    retval = 0;

done:
    bson_free(s);
    bson_free(b);
    return retval;
}

struct telegram_pbs *
get_persistent_bot_state(struct telegram_plugin_data *state, struct bot_state *bs)
{
    if (bs->pbs) return bs->pbs;

    mongo_sync_connection *conn = get_mongo_connection(state);
    if (!conn) return NULL;

    mongo_packet *pkt = NULL;
    bson *query = NULL;
    mongo_sync_cursor *cursor = NULL;
    bson *result = NULL;
    char ns[1024];

    query = bson_new();
    bson_append_string(query, "_id", bs->bot_id, strlen(bs->bot_id));
    bson_finish(query);
    snprintf(ns, sizeof(ns), "%s.%s%s", state->database, state->table_prefix, TELEGRAM_BOTS_TABLE_NAME);
    pkt = mongo_sync_cmd_query(conn, ns, 0, 0, 1, query, NULL);
    if (!pkt && errno == ENOENT) {
        bson_free(query); query = NULL;
        bs->pbs = telegram_pbs_create(bs->bot_id);
        save_persistent_bot_state(state, bs->pbs);
        goto cleanup;
    }
    if (!pkt) {
        err("mongo query failed: %s", os_ErrorMsg());
        goto cleanup;
    }
    bson_free(query); query = NULL;
    cursor = mongo_sync_cursor_new(conn, ns, pkt);
    if (!cursor) {
        err("mongo query failed: cannot create cursor: %s", os_ErrorMsg());
        goto cleanup;
    }
    pkt = NULL;
    if (mongo_sync_cursor_next(cursor)) {
        result = mongo_sync_cursor_get_data(cursor);
        struct telegram_pbs *pbs = telegram_pbs_parse_bson(result);
        bs->pbs = pbs;
    } else {
        mongo_sync_cursor_free(cursor); cursor = NULL;
        bs->pbs = telegram_pbs_create(bs->bot_id);
        save_persistent_bot_state(state, bs->pbs);
    }

cleanup:
    if (result) bson_free(result);
    if (cursor) mongo_sync_cursor_free(cursor);
    if (pkt) mongo_wire_packet_free(pkt);
    if (query) bson_free(query);
    return bs->pbs;
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

    curl_easy_setopt(curl, CURLOPT_AUTOREFERER, 1);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_URL, url_s);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp_f);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (char*) post_s);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
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
remove_expired_tokens(struct telegram_plugin_data *state, time_t current_time)
{
    if (current_time <= 0) current_time = time(NULL);

    mongo_sync_connection *conn = get_mongo_connection(state);
    if (!conn) return;
    
    char ns[1024];
    snprintf(ns, sizeof(ns), "%s.%s%s", state->database, state->table_prefix, TELEGRAM_TOKENS_TABLE_NAME);

    bson *qq = bson_new();
    bson_append_utc_datetime(qq, "$lt", 1000LL * current_time);
    bson_finish(qq);
    bson *q = bson_new();
    bson_append_document(q, "expiry_time", qq); qq = NULL;
    bson_finish(q);

    mongo_sync_cmd_delete(conn, ns, 0, q);

    bson_free(q);
}

static void
remove_token(struct telegram_plugin_data *state, const unsigned char *token)
{
    mongo_sync_connection *conn = get_mongo_connection(state);
    if (!conn) return;
    
    char ns[1024];
    snprintf(ns, sizeof(ns), "%s.%s%s", state->database, state->table_prefix, TELEGRAM_TOKENS_TABLE_NAME);

    bson *q = bson_new();
    bson_append_string(q, "token", token, strlen(token));
    bson_finish(q);

    mongo_sync_cmd_delete(conn, ns, 0, q);

    bson_free(q);
}

static int
get_token(struct telegram_plugin_data *state, const unsigned char *token_str, struct telegram_token **p_token)
{
    int retval = -1;

    mongo_sync_connection *conn = get_mongo_connection(state);
    if (!conn) return -1;

    char ns[1024];
    snprintf(ns, sizeof(ns), "%s.%s%s", state->database, state->table_prefix, TELEGRAM_TOKENS_TABLE_NAME);

    bson *query = NULL;
    mongo_packet *pkt = NULL;
    mongo_sync_cursor *cursor = NULL;
    bson *result = NULL;

    query = bson_new();
    bson_append_string(query, "token", token_str, strlen(token_str));
    bson_finish(query);
    
    pkt = mongo_sync_cmd_query(conn, ns, 0, 0, 1, query, NULL);
    if (!pkt && errno == ENOENT) {
        retval = 0;
        goto cleanup;
    }
    if (!pkt) {
        err("mongo query failed: %s", os_ErrorMsg());
        goto cleanup;
    }
    bson_free(query); query = NULL;

    cursor = mongo_sync_cursor_new(conn, ns, pkt);
    if (!cursor) {
        err("mongo query failed: cannot create cursor: %s", os_ErrorMsg());
        goto cleanup;
    }
    pkt = NULL;
    if (mongo_sync_cursor_next(cursor)) {
        result = mongo_sync_cursor_get_data(cursor);
        if (result) {
            struct telegram_token *t = telegram_token_parse_bson(result);
            if (t) {
                *p_token = t;
                retval = 1;
            }
        } else {
            retval = 0;
        }
    } else {
        retval = 0;
    }

cleanup:
    if (result) bson_free(result);
    if (cursor) mongo_sync_cursor_free(cursor);
    if (pkt) mongo_wire_packet_free(pkt);
    if (query) bson_free(query);
    return retval;
}

static int
save_token(struct telegram_plugin_data *state, const struct telegram_token *token)
{
    mongo_sync_connection *conn = get_mongo_connection(state);
    if (!conn) return -1;
    char ns[1024];
    int retval = -1;

    snprintf(ns, sizeof(ns), "%s.%s%s", state->database, state->table_prefix, TELEGRAM_TOKENS_TABLE_NAME);
    bson *b = telegram_token_unparse_bson(token);
    bson *ind = NULL;

    if (!mongo_sync_cmd_insert(conn, ns, b, NULL)) {
        err("save_token: failed: %s", os_ErrorMsg());
        goto cleanup;
    }

    ind = bson_new();
    bson_append_int32(ind, "token", 1);
    bson_finish(ind);
    mongo_sync_cmd_index_create(conn, ns, ind, 0);
    
    retval = 0;
cleanup:
    if (ind) bson_free(ind);
    bson_free(b);
    return retval;
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
    remove_expired_tokens(state, current_time);

    int res = get_token(state, token->token, &other_token);
    if (res < 0) {
        err("telegram_token: get_token failed");
    } else if (res > 0) {
        err("duplicated token, removing all");
        remove_token(state, token->token);
    } else {
        save_token(state, token);
    }

cleanup:
    telegram_token_free(token);
    telegram_token_free(other_token);
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
                if (tu->message && tu->message->text) {
                    info("{ text: %s }", tu->message->text);
                }
                if (!pbs->update_id || tu->update_id > pbs->update_id) {
                    pbs->update_id = tu->update_id;
                    need_update = 1;
                }
            }
            if (need_update) {
                save_persistent_bot_state(state, pbs);
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

    struct telegram_pbs *pbs = get_persistent_bot_state(state, bs);
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

    fprintf(stderr, "request: %s\n", url_s);

    {
        FILE *resp_f = open_memstream(&resp_s, &resp_z);
        curl_easy_setopt(curl, CURLOPT_AUTOREFERER, 1);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
        curl_easy_setopt(curl, CURLOPT_URL, url_s);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp_f);
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
periodic_handler(void *user)
{
    struct telegram_plugin_data *state = (struct telegram_plugin_data*) user;

    for (int i = 0; i < state->bots.u; ++i) {
        get_updates(state, state->bots.v[i]);
    }
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
