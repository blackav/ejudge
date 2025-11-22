/* -*- mode: c -*- */

/* Copyright (C) 2025 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/agent_server.h"
#include "ejudge/agent_common.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/prepare.h"
#include "ejudge/dyntrie.h"
#include "ejudge/random.h"
#include "ejudge/cJSON.h"
#include "ejudge/fileutl.h"
#include "ejudge/osdeps.h"
#include "ejudge/xalloc.h"

#include <libwebsockets.h>
#include <uv.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#define DEFAULT_SERVER_PORT 8888
#define MAX_OUTPUT_FRAGMENT_SIZE 65000

typedef struct OutputFragment
{
    unsigned char *msg;
    size_t size;
    unsigned offset;
    int flags;
} OutputFragment;

typedef struct ConnectionState
{
    struct lws *wsi;                  // websocket connection descriptor

    unsigned char *queue_id;
    unsigned char *inst_id;
    unsigned char *param_mode;
    unsigned char *remote_addr;
    int serial;
    int mode;
    int established;

    // incoming message
    unsigned char *msg;
    size_t msg_a;
    size_t msg_u;
    cJSON *jmsg;

    cJSON *jreply;

    // outbound queue
    OutputFragment *out;
    size_t out_a;
    size_t out_u;
    size_t out_h;     // head element to send

    unsigned msg_serial;
    long long current_time_ms;

    SpoolQueue *spool_queue;
} ConnectionState;

static void
free_connection_state(ConnectionState *conn)
{
    if (!conn) return;
    free(conn->queue_id);
    free(conn->inst_id);
    free(conn->param_mode);
    free(conn->remote_addr);
    free(conn->msg);
    if (conn->jmsg) cJSON_Delete(conn->jmsg);
    if (conn->jreply) cJSON_Delete(conn->jreply);
    for (size_t i = conn->out_h; i < conn->out_u; ++i) {
        free(conn->out[i].msg);
    }
    free(conn->out);
}

struct AgentServerState;
struct QueryCallback;
typedef int (*QueryCallbackFunc)(
    const struct QueryCallback *cb,
    struct AgentServerState *ass,
    ConnectionState *conn,
    cJSON *req,
    cJSON *reply);

typedef struct QueryCallback
{
    unsigned char *query;
    void *extra;
    QueryCallbackFunc callback;
} QueryCallback;

typedef struct AgentServerState
{
    uv_loop_t *loop;
    void *loops[1]; // foreign loop pointer for libwebsockets
    struct lws_context *context;
    const struct ejudge_cfg *ejudge_config;
    int connect_serial;
    unsigned char *ejudge_xml_dir;

    struct QueryCallback *querys;
    int querya;
    int queryu;
    struct dyntrie_node *queryi;

    SpoolQueue *spools;
    size_t spool_u;
    size_t spool_a;

    ContestSpools css;
} AgentServerState;

static void
add_query_callback(
    AgentServerState *ass,
    const unsigned char *query,
    void *extra,
    QueryCallbackFunc callback)
{
    if (ass->querya == ass->queryu) {
        if (!(ass->querya *= 2)) ass->querya = 8;
        XREALLOC(ass->querys, ass->querya);
    }
    int index = ass->queryu++;
    struct QueryCallback *c = &ass->querys[index];
    c->query = xstrdup(query);
    c->extra = extra;
    c->callback = callback;
    dyntrie_insert(&ass->queryi, query, (void*) (intptr_t) (index + 1), 1, NULL);
}

static SpoolQueue *
get_spool_queue(
    AgentServerState *ass,
    unsigned char *queue_id,
    int mode)
{
    for (size_t i = 0; i < ass->spool_u; ++i) {
        if (!strcmp(ass->spools[i].queue_id, queue_id) && ass->spools[i].mode == mode) {
            return &ass->spools[i];
        }
    }

    if (ass->spool_u == ass->spool_a) {
        if (!(ass->spool_a *= 2)) ass->spool_a = 16;
        XREALLOC(ass->spools, ass->spool_a);
    }
    unsigned index = ass->spool_u++;
    SpoolQueue *q = &ass->spools[index];
    if (spool_queue_init(q, queue_id, mode, index) < 0) {
        --ass->spool_u;
        return NULL;
    }
    return q;
}

#define L_ERR(format, ...) fprintf(log_f, "%s:%d:" format "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define L_ERR_FAIL(format, ...) do { fprintf(log_f, "%s:%d:" format "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); goto fail; } while (0)
#define L_ERR_DONE(format, ...) do { fprintf(log_f, "%s:%d:" format "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); goto done; } while (0)

static const unsigned char *
get_param_value(const unsigned char *arg, const unsigned char *param)
{
    size_t len = strlen(param);
    if (!strncmp(arg, param, len)) {
        return arg + len;
    }
    return NULL;
}

static unsigned char *
read_token(
    AgentServerState *ass,
    ConnectionState *conn,
    const unsigned char *token_file)
{
    unsigned char full_path[PATH_MAX];
    if (os_IsAbsolutePath(token_file)) {
        if (snprintf(full_path, sizeof(full_path), "%s", token_file) >= (int) sizeof(full_path)) {
            lwsl_err("%d: %s: %s:%d: token path is too long", conn->serial, conn->remote_addr, __FUNCTION__, __LINE__);
            return NULL;
        }
    } else {
        if (snprintf(full_path, sizeof(full_path), "%s/%s", ass->ejudge_xml_dir, token_file) >= (int) sizeof(full_path)) {
            lwsl_err("%d: %s: %s:%d: token path is too long", conn->serial, conn->remote_addr, __FUNCTION__, __LINE__);
            return NULL;
        }
    }
    FILE *fin = fopen(full_path, "r");
    if (!fin) {
        lwsl_err("%d: %s: %s:%d: failed to open token file '%s': %s", conn->serial, conn->remote_addr, __FUNCTION__, __LINE__, full_path, strerror(errno));
        return NULL;
    }
    char *stxt = NULL;
    size_t ztxt = 0;
    FILE *ftxt = open_memstream(&stxt, &ztxt);
    int c;
    while ((c = getc_unlocked(fin)) != EOF) {
        putc_unlocked(c, ftxt);
    }
    fclose(ftxt); ftxt = NULL;
    fclose(fin); fin = NULL;
    while (ztxt > 0 && isspace((unsigned char) stxt[ztxt - 1])) --ztxt;
    stxt[ztxt] = 0;
    return stxt;
}

static bool
is_valid_id(const unsigned char *p)
{
    if (!*p) return 0;
    while (*p) {
        if ((*p >= '0' && *p <= '9') || (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z')
            || *p == '.' || *p == '-' || *p == '_') {
            ++p;
        } else {
            return false;
        }
    }
    return true;
}

static int
handle_filter_protocol_connection(
    struct lws *wsi,
    AgentServerState *ass,
    ConnectionState *conn)
{
    conn->serial = ++ass->connect_serial;

    unsigned char remote_addr_buf[128];
    remote_addr_buf[0] = 0;
    lws_get_peer_simple(wsi, remote_addr_buf, sizeof(remote_addr_buf));
    if (!remote_addr_buf[0]) {
        lwsl_err("%d: %s:%d: remote address is unknown\n", conn->serial, __FUNCTION__, __LINE__);
        return -1;
    }
    conn->remote_addr = strdup(remote_addr_buf);

    if (ass->ejudge_config && ass->ejudge_config->agent_server && ass->ejudge_config->agent_server->token_file) {
        unsigned char *token = read_token(ass, conn, ass->ejudge_config->agent_server->token_file);
        if (!token) {
            lwsl_err("%d: %s: %s:%d: failed to read token from config file, check!", conn->serial, conn->remote_addr, __FUNCTION__, __LINE__);
            return -1;
        }

        int tlen = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_AUTHORIZATION);
        if (tlen <= 0) {
            lwsl_err("%d: %s: %s:%d: no Authorization header", conn->serial, conn->remote_addr, __FUNCTION__, __LINE__);
            free(token);
            return -1;
        }
        char *authorization = malloc(tlen + 1);
        lws_hdr_copy(wsi, authorization, tlen + 1, WSI_TOKEN_HTTP_AUTHORIZATION);
        const static char bearer[] = "bearer ";
        if (strncasecmp(authorization, bearer, sizeof(bearer) - 1)) {
            lwsl_err("%d: %s: %s:%d: no Bearer", conn->serial, conn->remote_addr, __FUNCTION__, __LINE__);
            free(token);
            free(authorization);
            return -1;
        }
        tlen = strlen(authorization);
        while (tlen > 0 && isspace((unsigned char) authorization[tlen - 1])) --tlen;
        authorization[tlen] = 0;
        const char *t = authorization + sizeof(bearer) - 1;
        while (isspace((unsigned char) *t)) ++t;
        if (!*t) {
            lwsl_err("%d: %s: %s:%d: empty bearer token", conn->serial, conn->remote_addr, __FUNCTION__, __LINE__);
            free(token);
            free(authorization);
            return -1;
        }
        if (strcmp(t, token) != 0) {
            lwsl_err("%d: %s: %s:%d: token mismatch", conn->serial, conn->remote_addr, __FUNCTION__, __LINE__);
            free(token);
            free(authorization);
            return -1;
        }
        free(token);
        free(authorization);
    }

    int argidx = 0;
    while (1) {
        int len = lws_hdr_fragment_length(wsi, WSI_TOKEN_HTTP_URI_ARGS, argidx);
        if (len <= 0) break;
        unsigned char *buf = malloc(len + 1);
        lws_hdr_copy_fragment(wsi, buf, len + 1, WSI_TOKEN_HTTP_URI_ARGS, argidx);
        ++argidx;

        const unsigned char *s = get_param_value(buf, "queue_id=");
        if (s) {
            free(conn->queue_id);
            conn->queue_id = strdup(s);
        }
        if ((s = get_param_value(buf, "inst_id="))) {
            free(conn->inst_id);
            conn->inst_id = strdup(s);
        }
        if ((s = get_param_value(buf, "mode="))) {
            free(conn->param_mode);
            conn->param_mode = strdup(s);
        }
        free(buf);
    }

    if (!conn->queue_id) {
        lwsl_err("%d: %s: %s:%d: queue_id is not set\n", conn->serial, conn->remote_addr, __FUNCTION__, __LINE__);
        return -1;
    }
    if (!is_valid_id(conn->queue_id)) {
        lwsl_err("%d: %s: %s:%d: queue_id is invalid\n", conn->serial, conn->remote_addr, __FUNCTION__, __LINE__);
        return -1;
    }
    if (!conn->param_mode || !*conn->param_mode) {
        lwsl_err("%d: %s: %s:%d: mode is not set\n", conn->serial, conn->remote_addr, __FUNCTION__, __LINE__);
        return -1;
    }
    if (!strcmp(conn->param_mode, "compile")) {
        conn->mode = PREPARE_COMPILE;
    } else if (!strcmp(conn->param_mode, "run")) {
        conn->mode = PREPARE_RUN;
    } else {
        lwsl_err("%d: %s: %s:%d: invalid mode\n", conn->serial, conn->remote_addr, __FUNCTION__, __LINE__);
        return -1;
    }
    if (!conn->inst_id || !*conn->inst_id) {
        free(conn->inst_id);
        conn->inst_id = strdup(conn->remote_addr);
    }
    if (!is_valid_id(conn->inst_id)) {
        lwsl_err("%d: %s: %s:%d: inst_id is invalid\n", conn->serial, conn->remote_addr, __FUNCTION__, __LINE__);
        return -1;
    }

    SpoolQueue *sq = get_spool_queue(ass, conn->queue_id, conn->mode);
    if (!sq) {
        lwsl_err("%d: %s: %s: %s:%d: failed to create queue %s, mode %s\n", conn->serial, conn->remote_addr, conn->inst_id,
            __FUNCTION__, __LINE__,
            conn->queue_id, conn->param_mode);
        return -1;
    }

    conn->established = 1;
    conn->wsi = wsi;
    conn->spool_queue = sq;
    ++sq->refcount;
    lwsl_user("%d: %s: %s: connection checked, queue %s, mode %s\n", conn->serial, conn->remote_addr, conn->inst_id,
        conn->queue_id, conn->param_mode);

    return 0;
}

static void
conn_queue_data(
    ConnectionState *conn,
    const unsigned char *data,
    size_t size)
{
    int is_start = 1;
    while (size > 0) {
        size_t fragment = size;
        if (fragment > MAX_OUTPUT_FRAGMENT_SIZE) fragment = MAX_OUTPUT_FRAGMENT_SIZE;

        if (conn->out_h > 0 && conn->out_h == conn->out_u) {
            conn->out_h = 0;
            conn->out_u = 0;
        }
        if (conn->out_u == conn->out_a) {
            if (!(conn->out_a *= 2)) conn->out_a = 16;
            XREALLOC(conn->out, conn->out_a);
        }
        OutputFragment *f = &conn->out[conn->out_u++];
        memset(f, 0, sizeof(*f));
        f->flags = lws_write_ws_flags(LWS_WRITE_TEXT, is_start, size == fragment);
        f->offset = LWS_PRE;
        f->size = fragment;
        f->msg = xmalloc(LWS_PRE + fragment);
        memcpy(f->msg + f->offset, data, fragment);

        data += fragment;
        size -= fragment;
        is_start = 0;
    }
}

static int
ping_query_func(
    const struct QueryCallback *cb,
    struct AgentServerState *ass,
    ConnectionState *conn,
    cJSON *req,
    cJSON *reply)
{
    cJSON_AddStringToObject(reply, "q", "pong");
    return 1;
}

#define conn_err(conn,msg,...) lwsl_err("%d: %s: %s: %s:%d: " msg "\n", conn->serial, conn->remote_addr, conn->inst_id, __FUNCTION__, __LINE__, ##__VA_ARGS__)

static int
poll_func(
    const struct QueryCallback *cb,
    struct AgentServerState *ass,
    ConnectionState *conn,
    cJSON *query,
    cJSON *reply)
{
    unsigned char pkt_name[PATH_MAX];
    int random_mode = 0;
    int enable_file = 0;
    cJSON *jrm = cJSON_GetObjectItem(query, "random_mode");
    if (jrm && jrm->type == cJSON_True) {
        random_mode = 1;
    }
    cJSON *jef = cJSON_GetObjectItem(query, "enable_file");
    if (jef && jef->type == cJSON_True) {
        enable_file = 1;
    }

    while (1) {
        int r = scan_dir(conn->spool_queue->queue_dir, pkt_name, sizeof(pkt_name), random_mode);
        if (r < 0) {
            cJSON_AddStringToObject(reply, "message", "scan_dir failed");
            conn_err(conn, "scan_dir %s failed %s", conn->spool_queue->queue_dir, strerror(-r));
            return 0;
        }
        if (!r) {
            cJSON_AddStringToObject(reply, "q", "poll-result");
            return 1;
        }
        if (!enable_file) {
            cJSON_AddStringToObject(reply, "pkt-name", pkt_name);
            cJSON_AddStringToObject(reply, "q", "poll-result");
            return 1;
        }

        char *data = NULL;
        size_t size = 0;
        r = spool_queue_read_packet(conn->spool_queue, pkt_name, &data, &size);
        if (r < 0) {
            cJSON_AddStringToObject(reply, "message", "read_packet failed");
            return 0;
        }
        if (r > 0) {
            cJSON_AddStringToObject(reply, "pkt-name", pkt_name);
            cJSON_AddStringToObject(reply, "q", "file-result");
            cJSON_AddTrueToObject(reply, "found");
            agent_add_file_to_object(reply, data, size);
            free(data);
            return 1;
        }
    }
}

static int
get_packet_func(
    const struct QueryCallback *cb,
    struct AgentServerState *ass,
    ConnectionState *conn,
    cJSON *query,
    cJSON *reply)
{
    cJSON *jp = cJSON_GetObjectItem(query, "pkt_name");
    if (!jp || jp->type != cJSON_String) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        conn_err(conn, "missing pkt_name");
        return 0;
    }
    const unsigned char *pkt_name = jp->valuestring;
    char *pkt_ptr = NULL;
    size_t pkt_len = 0;
    int r = generic_read_file(&pkt_ptr, 0, &pkt_len, SAFE | REMOVE,
                              conn->spool_queue->queue_dir, pkt_name, "");
    if (!r) {
        // just file not found
        cJSON_AddStringToObject(reply, "q", "file-result");
        return 1;
    }
    if (r < 0 || !pkt_ptr) {
        cJSON_AddStringToObject(reply, "message", "failed to read file");
        return 0;
    }
    cJSON_AddStringToObject(reply, "q", "file-result");
    cJSON_AddTrueToObject(reply, "found");
    agent_add_file_to_object(reply, pkt_ptr, pkt_len);
    free(pkt_ptr);
    return 1;
}

static int
get_data_func(
    const struct QueryCallback *cb,
    struct AgentServerState *ass,
    ConnectionState *conn,
    cJSON *query,
    cJSON *reply)
{
    cJSON *jp = cJSON_GetObjectItem(query, "pkt_name");
    if (!jp || jp->type != cJSON_String) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        conn_err(conn, "missing pkt_name");
        return 0;
    }
    const unsigned char *pkt_name = jp->valuestring;
    const unsigned char *suffix = NULL;
    cJSON *js = cJSON_GetObjectItem(query, "suffix");
    if (js && js->type == cJSON_String) {
        suffix = js->valuestring;
    }
    char *pkt_ptr = NULL;
    size_t pkt_len = 0;
    int r = generic_read_file(&pkt_ptr, 0, &pkt_len, REMOVE,
                              conn->spool_queue->data_dir, pkt_name, suffix);
    if (!r) {
        // just file not found
        cJSON_AddStringToObject(reply, "q", "file-result");
        return 1;
    }
    if (r < 0 || !pkt_ptr) {
        cJSON_AddStringToObject(reply, "message", "failed to read file");
        return 0;
    }
    cJSON_AddStringToObject(reply, "q", "file-result");
    cJSON_AddTrueToObject(reply, "found");
    agent_add_file_to_object(reply, pkt_ptr, pkt_len);
    free(pkt_ptr);
    return 1;
}

static int
put_reply_func(
    const struct QueryCallback *cb,
    struct AgentServerState *ass,
    ConnectionState *conn,
    cJSON *query,
    cJSON *reply)
{
    char *data = NULL;
    size_t size = 0;
    int result = 0;

    if (agent_extract_file(conn->inst_id, query, &data, &size) < 0) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        return 0;
    }

    cJSON *jserver = cJSON_GetObjectItem(query, "server");
    if (!jserver || jserver->type != cJSON_String || !jserver->valuestring || !is_valid_id(jserver->valuestring)) {
        conn_err(conn, "invalid server");
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    const unsigned char *server = jserver->valuestring;

    cJSON *jcid = cJSON_GetObjectItem(query, "contest");
    if (!jcid || jcid->type != cJSON_Number || jcid->valuedouble <= 0) {
        conn_err(conn, "invalid contest");
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    int contest_id = jcid->valuedouble;

    cJSON *jrun = cJSON_GetObjectItem(query, "run_name");
    if (!jrun || jrun->type != cJSON_String || !jrun->valuestring || !is_valid_id(jrun->valuestring)) {
        conn_err(conn, "invalid run_name");
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    const unsigned char *run_name = jrun->valuestring;

    ContestSpool *ci = contest_spool_get(&ass->css, server, contest_id, conn->mode);
    if (!ci) {
        conn_err(conn, "directory creation failed");
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }
    if (generic_write_file(data, size, SAFE, ci->status_dir, run_name, 0) < 0) {
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }

    cJSON_AddStringToObject(reply, "q", "result");
    result = 1;

done:;
    free(data);
    return result;
}

static int
put_output_func(
    const struct QueryCallback *cb,
    struct AgentServerState *ass,
    ConnectionState *conn,
    cJSON *query,
    cJSON *reply)
{
    char *data = NULL;
    size_t size = 0;
    int result = 0;
    const unsigned char *suffix = NULL;

    if (agent_extract_file(conn->inst_id, query, &data, &size) < 0) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        return 0;
    }

    cJSON *jserver = cJSON_GetObjectItem(query, "server");
    if (!jserver || jserver->type != cJSON_String || !jserver->valuestring || !is_valid_id(jserver->valuestring)) {
        conn_err(conn, "invalid server");
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    const unsigned char *server = jserver->valuestring;

    cJSON *jcid = cJSON_GetObjectItem(query, "contest");
    if (!jcid || jcid->type != cJSON_Number || jcid->valuedouble <= 0) {
        conn_err(conn, "invalid contest");
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    int contest_id = jcid->valuedouble;

    cJSON *jrun = cJSON_GetObjectItem(query, "run_name");
    if (!jrun || jrun->type != cJSON_String || !jrun->valuestring || !is_valid_id(jrun->valuestring)) {
        conn_err(conn, "invalid run_name");
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    const unsigned char *run_name = jrun->valuestring;

    cJSON *jsuffix = cJSON_GetObjectItem(query, "suffix");
    if (jsuffix && jsuffix->type == cJSON_String) {
        suffix = jsuffix->valuestring;
    }

    ContestSpool *ci = contest_spool_get(&ass->css, server, contest_id, conn->mode);
    if (!ci) {
        conn_err(conn, "directory creation failed");
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }

    if (generic_write_file(data, size, 0, ci->report_dir, run_name, suffix) < 0) {
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }

    cJSON_AddStringToObject(reply, "q", "result");
    result = 1;

done:;
    free(data);
    return result;
}

static int
add_ignored_func(
    const struct QueryCallback *cb,
    struct AgentServerState *ass,
    ConnectionState *conn,
    cJSON *query,
    cJSON *reply)
{
    cJSON *jp = cJSON_GetObjectItem(query, "pkt_name");
    if (!jp || jp->type != cJSON_String || !is_valid_id(jp->valuestring)) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        cJSON_AddStringToObject(reply, "q", "result");
        conn_err(conn, "invalid pkt_name");
        return 0;
    }
    const unsigned char *pkt_name = jp->valuestring;

    scan_dir_add_ignored(conn->spool_queue->queue_dir, pkt_name);
    cJSON_AddStringToObject(reply, "q", "result");

    return 1;
}

static int
put_packet_func(
    const struct QueryCallback *cb,
    struct AgentServerState *ass,
    ConnectionState *conn,
    cJSON *query,
    cJSON *reply)
{
    int result = 0;
    char *data = NULL;
    size_t size = 0;

    cJSON *jp = cJSON_GetObjectItem(query, "pkt_name");
    if (!jp || jp->type != cJSON_String || !is_valid_id(jp->valuestring)) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        conn_err(conn, "invalid pkt_name");
        goto done;
    }
    const unsigned char *pkt_name = jp->valuestring;

    if (agent_extract_file(conn->inst_id, query, &data, &size) < 0) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    if (generic_write_file(data, size, SAFE, conn->spool_queue->queue_dir, pkt_name, "") < 0) {
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }
    result = 1;

done:;
    cJSON_AddStringToObject(reply, "q", "result");
    free(data);
    return result;
}

static int
put_heartbeat_func(
    const struct QueryCallback *cb,
    struct AgentServerState *ass,
    ConnectionState *conn,
    cJSON *query,
    cJSON *reply)
{
    int result = 0;
    char *data = NULL;
    size_t size = 0;
    unsigned char dir_path[PATH_MAX];
    __attribute__((unused)) int _;

    cJSON *jn = cJSON_GetObjectItem(query, "name");
    if (!jn || jn->type != cJSON_String) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        conn_err(conn, "invalid name");
        goto done;
    }
    const unsigned char *file_name = jn->valuestring;
    if (agent_extract_file(conn->inst_id, query, &data, &size) < 0) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }

    if (agent_save_to_spool(conn->inst_id, conn->spool_queue->heartbeat_dir, file_name, data, size) < 0) {
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }

    _ = snprintf(dir_path, sizeof(dir_path), "%s/%s@S", conn->spool_queue->heartbeat_packet_dir, file_name);
    if (access(dir_path, F_OK) >= 0) {
        cJSON_AddTrueToObject(reply, "stop_flag");
        unlink(dir_path);
    }
    _ = snprintf(dir_path, sizeof(dir_path), "%s/%s@D", conn->spool_queue->heartbeat_packet_dir, file_name);
    if (access(dir_path, F_OK) >= 0) {
        cJSON_AddTrueToObject(reply, "down_flag");
        unlink(dir_path);
    }
    _ = snprintf(dir_path, sizeof(dir_path), "%s/%s@R", conn->spool_queue->heartbeat_packet_dir, file_name);
    if (access(dir_path, F_OK) >= 0) {
        cJSON_AddTrueToObject(reply, "reboot_flag");
        unlink(dir_path);
    }

    result = 1;

done:;
    cJSON_AddStringToObject(reply, "q", "heartbeat-result");
    free(data);
    return result;
}

static int
delete_heartbeat_func(
    const struct QueryCallback *cb,
    struct AgentServerState *ass,
    ConnectionState *conn,
    cJSON *query,
    cJSON *reply)
{
    int result = 0;
    unsigned char path[PATH_MAX];
    __attribute__((unused)) int _;

    cJSON *jn = cJSON_GetObjectItem(query, "name");
    if (!jn || jn->type != cJSON_String || !is_valid_id(jn->valuestring)) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        conn_err(conn, "invalid name");
        goto done;
    }
    const unsigned char *file_name = jn->valuestring;

    _ = snprintf(path, sizeof(path), "%s/%s", conn->spool_queue->heartbeat_packet_dir, file_name);
    _ = unlink(path);
    result = 1;

done:;
    cJSON_AddStringToObject(reply, "q", "result");

    return result;
}

static int
put_archive_func(
    const struct QueryCallback *cb,
    struct AgentServerState *ass,
    ConnectionState *conn,
    cJSON *query,
    cJSON *reply)
{
    char *data = NULL;
    size_t size = 0;
    int result = 0;

    if (agent_extract_file(conn->inst_id, query, &data, &size) < 0) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }

    cJSON *jserver = cJSON_GetObjectItem(query, "server");
    if (!jserver || jserver->type != cJSON_String || !jserver->valuestring || !is_valid_id(jserver->valuestring)) {
        conn_err(conn, "invalid server");
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    const unsigned char *server = jserver->valuestring;

    cJSON *jcid = cJSON_GetObjectItem(query, "contest");
    if (!jcid || jcid->type != cJSON_Number || jcid->valuedouble <= 0) {
        conn_err(conn, "invalid contest");
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    int contest_id = jcid->valuedouble;

    cJSON *jrun = cJSON_GetObjectItem(query, "run_name");
    if (!jrun || jrun->type != cJSON_String || !jrun->valuestring) {
        conn_err(conn, "invalid run_name");
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }
    const unsigned char *run_name = jrun->valuestring;

    const unsigned char *suffix = NULL;
    cJSON *jsuffix = cJSON_GetObjectItem(query, "suffix");
    if (jsuffix && jsuffix->type == cJSON_String) {
        if (!is_valid_id(jsuffix->valuestring)) {
            conn_err(conn, "invalid suffix");
            cJSON_AddStringToObject(reply, "message", "invalid json");
            goto done;
        }
        suffix = jsuffix->valuestring;
    }

    ContestSpool *ci = contest_spool_get(&ass->css, server, contest_id, conn->mode);
    if (!ci) {
        conn_err(conn, "directory creation failed");
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }
    if (generic_write_file(data, size, 0, ci->output_dir, run_name, suffix) < 0) {
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }
    cJSON_AddStringToObject(reply, "q", "result");
    result = 1;

done:;
    free(data);
    return result;
}

static int
mirror_func(
    const struct QueryCallback *cb,
    struct AgentServerState *ass,
    ConnectionState *conn,
    cJSON *query,
    cJSON *reply)
{
    int result = 0;
    int fd = -1;
    unsigned char *pkt_ptr = MAP_FAILED;
    size_t pkt_size = 0;
    unsigned char perm_buf[64];

    cJSON *jpath = cJSON_GetObjectItem(query, "path");
    if (!jpath || jpath->type != cJSON_String) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        conn_err(conn, "missing path");
        goto done;
    }
    const unsigned char *path = jpath->valuestring;

    cJSON *jsize = cJSON_GetObjectItem(query, "size");
    int64_t size = -1;
    if (jsize) {
        if (!jsize || jsize->type != cJSON_Number) {
            cJSON_AddStringToObject(reply, "message", "invalid json");
            conn_err(conn, "invalid size");
            goto done;
        }
        size = jsize->valuedouble;
        if (size < 0) size = -1;
    }

    cJSON *jmtime = cJSON_GetObjectItem(query, "mtime");
    time_t mtime = 0;
    if (jmtime) {
        if (jmtime->type != cJSON_Number) {
            cJSON_AddStringToObject(reply, "message", "invalid json");
            conn_err(conn, "invalid mtime");
            goto done;
        }
        if ((mtime = jmtime->valuedouble) < 0) mtime = 0;
    }

    int mode = -1;
    cJSON *jmode = cJSON_GetObjectItem(query, "mode");
    if (jmode) {
        if (jmode->type != cJSON_String) {
            cJSON_AddStringToObject(reply, "message", "invalid json");
            conn_err(conn, "invalid mode");
            goto done;
        }
        // FIXME: check for errors
        mode = strtol(jmode->valuestring, NULL, 8);
        if (mode < 0 || mode > 07777) mode = -1;
    }

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK, 0);
    if (fd < 0) {
        cJSON_AddStringToObject(reply, "message", "cannot open file");
        conn_err(conn, "open '%s' failed: %s", path, strerror(errno));
        goto done;
    }
    struct stat stb;
    if (fstat(fd, &stb) < 0) {
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        conn_err(conn, "fstat '%s' failed: %s", path, strerror(errno));
        goto done;
    }
    if (!S_ISREG(stb.st_mode)) {
        cJSON_AddStringToObject(reply, "message", "not a regular file");
        conn_err(conn, "not regular '%s'", path);
        goto done;
    }
    if (stb.st_size > 1073741824) {
        cJSON_AddStringToObject(reply, "message", "file is too big");
        conn_err(conn, "too big '%s'", path);
        goto done;
    }

    if (size >= 0 && size == stb.st_size
        && mtime > 0 && mtime == stb.st_mtime
        && mode >= 0 && mode == (stb.st_mode & 07777)) {
        cJSON_AddStringToObject(reply, "q", "file-unchanged");
        cJSON_AddTrueToObject(reply, "found");
        result = 1;
        goto done;
    }

    snprintf(perm_buf, sizeof(perm_buf), "%04o", stb.st_mode & 07777);
    cJSON_AddStringToObject(reply, "mode", perm_buf);
    cJSON_AddNumberToObject(reply, "mtime", stb.st_mtime);
    cJSON_AddNumberToObject(reply, "uid", stb.st_uid);
    cJSON_AddNumberToObject(reply, "gid", stb.st_gid);
    if (stb.st_size <= 0) {
        agent_add_file_to_object(reply, NULL, 0);
        cJSON_AddStringToObject(reply, "q", "file-result");
        cJSON_AddTrueToObject(reply, "found");
        result = 1;
        goto done;
    }

    pkt_size = stb.st_size;
    pkt_ptr = mmap(NULL, pkt_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (pkt_ptr == MAP_FAILED) {
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        conn_err(conn, "mmap '%s' failed: %s", path, strerror(errno));
        goto done;
    }

    close(fd); fd = -1;
    cJSON_AddStringToObject(reply, "q", "file-result");
    cJSON_AddTrueToObject(reply, "found");
    agent_add_file_to_object(reply, pkt_ptr, pkt_size);
    result = 1;

done:;
    if (pkt_ptr != MAP_FAILED) munmap(pkt_ptr, pkt_size);
    if (fd >= 0) close(fd);
    return result;
}

static int
put_config_func(
    const struct QueryCallback *cb,
    struct AgentServerState *ass,
    ConnectionState *conn,
    cJSON *query,
    cJSON *reply)
{
    int result = 0;
    char *data = NULL;
    size_t size = 0;

    cJSON *jn = cJSON_GetObjectItem(query, "name");
    if (!jn || jn->type != cJSON_String || !is_valid_id(jn->valuestring)) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        conn_err(conn, "invalid name");
        goto done;
    }
    const unsigned char *file_name = jn->valuestring;

    if (agent_extract_file(conn->inst_id, query, &data, &size) < 0) {
        cJSON_AddStringToObject(reply, "message", "invalid json");
        goto done;
    }

    if (agent_save_to_spool(conn->inst_id, conn->spool_queue->config_dir, file_name, data, size) < 0) {
        cJSON_AddStringToObject(reply, "message", "filesystem error");
        goto done;
    }

    result = 1;

done:;
    cJSON_AddStringToObject(reply, "q", "config-result");
    free(data);
    return result;
}

static int
handle_incoming_json(
    struct lws *wsi,
    AgentServerState *ass,
    ConnectionState *conn,
    cJSON *req,
    cJSON *reply)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    conn->current_time_ms = tv.tv_sec * 1000LL + tv.tv_usec / 1000;

    cJSON_AddNumberToObject(reply, "tt", (double) conn->current_time_ms);
    cJSON_AddNumberToObject(reply, "ss", (double) ++conn->msg_serial);
    cJSON *jt = cJSON_GetObjectItem(req, "t");
    if (jt && jt->type == cJSON_Number) {
        cJSON_AddNumberToObject(reply, "t", jt->valuedouble);
    }
    cJSON *js = cJSON_GetObjectItem(req, "s");
    if (js && js->type == cJSON_Number) {
        cJSON_AddNumberToObject(reply, "s", js->valuedouble);
    }
    cJSON *jq = cJSON_GetObjectItem(req, "q");
    if (!jq || jq->type != cJSON_String) {
        cJSON_AddStringToObject(reply, "message", "Invalid query");
        lwsl_err("%d: %s: %s: invalid query: string expected\n", conn->serial, conn->remote_addr, conn->inst_id);
        return 0;
    }
    const unsigned char *query = jq->valuestring;

    cJSON_AddStringToObject(reply, "qq", query);
    void *vp = dyntrie_get(&ass->queryi, query);
    if (!vp) {
        cJSON_AddStringToObject(reply, "message", "Invalid query");
        lwsl_err("%d: %s: %s: invalid query: unhandled query\n", conn->serial, conn->remote_addr, conn->inst_id);
        return 0;
    }
    const struct QueryCallback *c = &ass->querys[((int)(intptr_t) vp) - 1];
    return c->callback(c, ass, conn, req, reply);
}

static int
handle_receive(
    struct lws *wsi,
    AgentServerState *ass,
    ConnectionState *conn,
    unsigned char *data,
    size_t len)
{
    if (lws_frame_is_binary(wsi)) {
        lwsl_err("%d: %s: %s: binary frame\n", conn->serial, conn->remote_addr, conn->inst_id);
        return -1;
    }

    if (lws_is_first_fragment(wsi) && conn->msg_u > 0) {
        lwsl_err("%d: %s: %s: first fragment flag set, but buffer not empty\n", conn->serial, conn->remote_addr, conn->inst_id);
        return -1;
    }

    size_t new_a = conn->msg_a;
    while (conn->msg_u + len + 1 > new_a) {
        if (!new_a) {
            new_a = 128;
        } else {
            new_a *= 2;
        }
    }
    if (new_a != conn->msg_a) {
        conn->msg = xrealloc(conn->msg, new_a);
        conn->msg_a = new_a;
    }
    memcpy(conn->msg + conn->msg_u, data, len);
    conn->msg_u += len;
    conn->msg[conn->msg_u] = 0;
    if (!lws_is_final_fragment(wsi)) {
        return 0;
    }

    conn->jmsg = cJSON_Parse(conn->msg);
    if (!conn->jmsg) {
        lwsl_user("%d: %s: %s: failed to parse JSON\n", conn->serial, conn->remote_addr, conn->inst_id);
        return -1;
    }

    conn->jreply = cJSON_CreateObject();
    int ok = handle_incoming_json(wsi, ass, conn, conn->jmsg, conn->jreply);
    cJSON_AddBoolToObject(conn->jreply, "ok", ok);
    unsigned char *jstr = cJSON_PrintUnformatted(conn->jreply);
    size_t jlen = strlen(jstr);
    conn_queue_data(conn, jstr, jlen);
    free(jstr);
    if (conn->out_h != conn->out_u) {
        lws_callback_on_writable(wsi);
    }

    conn->msg_u = 0;
    if (conn->jmsg) cJSON_Delete(conn->jmsg);
    conn->jmsg = NULL;
    if (conn->jreply) cJSON_Delete(conn->jreply);
    conn->jreply = NULL;
    return 0;
}

static int
callback_server(
        struct lws *wsi,
        enum lws_callback_reasons reason,
		void *user,
        void *in,
        size_t len)
{
    __attribute__((unused))
    struct lws_context *ctx = lws_get_context(wsi);
    ConnectionState *conn = (ConnectionState *) user;
    AgentServerState *ass = (AgentServerState*) lws_context_user(ctx);

    switch (reason) {
    case LWS_CALLBACK_PROTOCOL_INIT:
        break;
    case LWS_CALLBACK_PROTOCOL_DESTROY:
        break;
    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
        return handle_filter_protocol_connection(wsi, ass, conn);

    case LWS_CALLBACK_ESTABLISHED:
        lwsl_user("%d: %s: %s: connection established\n", conn->serial, conn->remote_addr, conn->inst_id);
        break;

    case LWS_CALLBACK_RECEIVE:
        return handle_receive(wsi, ass, conn, in, len);

    case LWS_CALLBACK_SERVER_WRITEABLE: {
        if (conn->out_h != conn->out_u) {
            OutputFragment *f = &conn->out[conn->out_h];
            lws_write(wsi, f->msg + f->offset, f->size, f->flags);
            memset(f, 0, sizeof(*f));
            if (++conn->out_h == conn->out_u) {
                conn->out_h = 0;
                conn->out_u = 0;
            }
        }
        if (conn->out_h != conn->out_u) {
            lws_callback_on_writable(wsi);
        }
        break;
    }

    case LWS_CALLBACK_CLOSED: {
        if (conn->established) {
            lwsl_user("%d: %s: %s: connection closed, queue %s, mode %s\n", conn->serial, conn->remote_addr, conn->inst_id,
                conn->queue_id, conn->param_mode);
        }
        if (conn->spool_queue) {
            --conn->spool_queue->refcount;
        }
        free_connection_state(conn);
        break;
    }
    default:
        break;
    }
    return 0;
}

static struct lws_protocols protocols[] =
{
    { 
        "server",
        callback_server,
        sizeof(ConnectionState),
        65536,
        0,
        NULL,
        0
    },
	LWS_PROTOCOL_LIST_TERM
};

/*
long long get_time_us()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000LL + tv.tv_usec;
}

void timer_callback(uv_timer_t *handle)
{
    struct application_info *app = handle->data;
    if (app->current_wsi) {
        lws_callback_on_writable(app->current_wsi);
    }
    printf("timer callback\n");
}
*/

int
agent_server_start(const AgentServerParams *params)
{
    int retval = -1;
    AgentServerState *ass = NULL;
    XCALLOC(ass, 1);
    FILE *log_f = stderr;
    const unsigned char *ejudge_xml_path = NULL;
    const struct ejudge_cfg *ejudge_config = NULL;

    random_init();

#if defined EJUDGE_XML_PATH
    if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */
    if (!ejudge_xml_path) L_ERR_DONE("ejudge.xml path is not specified");
    if (!(ejudge_config = ejudge_cfg_parse(ejudge_xml_path, 0)))
        L_ERR_DONE("failed to parse '%s'", ejudge_xml_path);
    if (!ejudge_config->agent_server) {
        L_ERR_DONE("ej-agent-server is not configured in '%s'", ejudge_xml_path);
    }
    if (ejudge_config->agent_server->enable <= 0) {
        L_ERR_DONE("ej-agent-server is not enabled in '%s'", ejudge_xml_path);
    }

    ass->ejudge_config = ejudge_config;
    ass->ejudge_xml_dir = os_DirName(ejudge_xml_path);
    ass->loop = uv_default_loop();
    ass->loops[0] = ass->loop;

    lws_set_log_level(LLL_WARN | LLL_ERR | LLL_USER, NULL);

    struct lws_context_creation_info info = {};
    if (ejudge_config->agent_server) {
        info.port = ejudge_config->agent_server->port;
    }
    if (!info.port) info.port = DEFAULT_SERVER_PORT;
    info.protocols = protocols;
    info.options = LWS_SERVER_OPTION_LIBUV | LWS_SERVER_OPTION_VALIDATE_UTF8 | LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;
    info.pt_serv_buf_size = 65536;
    info.foreign_loops = ass->loops;
    info.count_threads = 1;
    info.user = ass;

    ass->context = lws_create_context(&info);
    if (!ass->context) {
        L_ERR_DONE("failed to create libwebsockets context");
    }

    add_query_callback(ass, "ping", NULL, ping_query_func);
    add_query_callback(ass, "poll", NULL, poll_func);
    add_query_callback(ass, "get-packet", NULL, get_packet_func);
    add_query_callback(ass, "get-data", NULL, get_data_func);
    add_query_callback(ass, "put-reply", NULL, put_reply_func);
    add_query_callback(ass, "put-output", NULL, put_output_func);
    add_query_callback(ass, "add-ignored", NULL, add_ignored_func);
    add_query_callback(ass, "put-packet", NULL, put_packet_func);
    add_query_callback(ass, "put-heartbeat", NULL, put_heartbeat_func);
    add_query_callback(ass, "delete-heartbeat", NULL, delete_heartbeat_func);
    add_query_callback(ass, "put-archive", NULL, put_archive_func);
    add_query_callback(ass, "mirror", NULL, mirror_func);
    add_query_callback(ass, "put-config", NULL, put_config_func);

/*
    app_state_add_query_callback(&app, "set", NULL, set_query_func);
    app_state_add_query_callback(&app, "wait", NULL, wait_func);
    app_state_add_query_callback(&app, "cancel", NULL, cancel_func);
*/

    lwsl_user("server started");
    int r;
    while ((r = lws_service(ass->context, 0)) >= 0) {
    }

    retval = 0;

done:;
    if (ass->context) lws_context_destroy(ass->context);
    if (ass->loop) uv_loop_close(ass->loop);
    xfree(ass);
    return retval;
}
