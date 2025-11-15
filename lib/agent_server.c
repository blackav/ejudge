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
#include "ejudge/ejudge_cfg.h"
#include "ejudge/prepare.h"
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

#define DEFAULT_SERVER_PORT 8888

typedef struct ConnectionState
{
    unsigned char *queue_id;
    unsigned char *inst_id;
    unsigned char *param_mode;
    unsigned char *remote_addr;
    int serial;
    int mode;
    int established;
} ConnectionState;

static void
free_connection_state(ConnectionState *conn)
{
    if (!conn) return;
    free(conn->queue_id);
    free(conn->inst_id);
    free(conn->param_mode);
    free(conn->remote_addr);
}

typedef struct AgentServerState
{
    uv_loop_t *loop;
    void *loops[1]; // foreign loop pointer for libwebsockets
    struct lws_context *context;
    const struct ejudge_cfg *ejudge_config;
    int connect_serial;
    unsigned char *ejudge_xml_dir;
} AgentServerState;

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
            lwsl_err("%d: %s: token path is too long", conn->serial, conn->remote_addr);
            return NULL;
        }
    } else {
        if (snprintf(full_path, sizeof(full_path), "%s/%s", ass->ejudge_xml_dir, token_file) >= (int) sizeof(full_path)) {
            lwsl_err("%d: %s: token path is too long", conn->serial, conn->remote_addr);
            return NULL;
        }
    }
    FILE *fin = fopen(full_path, "r");
    if (!fin) {
        lwsl_err("%d: %s: failed to open token file '%s': %s", conn->serial, conn->remote_addr, full_path, strerror(errno));
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
    ConnectionState *conn
)
{
    conn->serial = ++ass->connect_serial;

    unsigned char remote_addr_buf[128];
    remote_addr_buf[0] = 0;
    lws_get_peer_simple(wsi, remote_addr_buf, sizeof(remote_addr_buf));
    if (!remote_addr_buf[0]) {
        lwsl_err("%d: remote address is unknown\n", conn->serial);
        return -1;
    }
    conn->remote_addr = strdup(remote_addr_buf);

    if (ass->ejudge_config && ass->ejudge_config->agent_server && ass->ejudge_config->agent_server->token_file) {
        unsigned char *token = read_token(ass, conn, ass->ejudge_config->agent_server->token_file);
        if (!token) {
            lwsl_err("%d: %s: failed to read token from config file, check!", conn->serial, conn->remote_addr);
            return -1;
        }

        int tlen = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_AUTHORIZATION);
        if (tlen <= 0) {
            lwsl_err("%d: %s: no Authorization header", conn->serial, conn->remote_addr);
            free(token);
            return -1;
        }
        char *authorization = malloc(tlen + 1);
        lws_hdr_copy(wsi, authorization, tlen + 1, WSI_TOKEN_HTTP_AUTHORIZATION);
        const static char bearer[] = "bearer ";
        if (strncasecmp(authorization, bearer, sizeof(bearer) - 1)) {
            lwsl_err("%d: %s: no Bearer", conn->serial, conn->remote_addr);
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
            lwsl_err("%d: %s: empty bearer token", conn->serial, conn->remote_addr);
            free(token);
            free(authorization);
            return -1;
        }
        if (strcmp(t, token) != 0) {
            lwsl_err("%d: %s: token mismatch", conn->serial, conn->remote_addr);
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
        lwsl_err("%d: %s: queue_id is not set\n", conn->serial, conn->remote_addr);
        return -1;
    }
    if (!is_valid_id(conn->queue_id)) {
        lwsl_err("%d: %s: queue_id is invalid\n", conn->serial, conn->remote_addr);
        return -1;
    }
    if (!conn->param_mode || !*conn->param_mode) {
        lwsl_err("%d: %s: mode is not set\n", conn->serial, conn->remote_addr);
        return -1;
    }
    if (!strcmp(conn->param_mode, "compile")) {
        conn->mode = PREPARE_COMPILE;
    } else if (!strcmp(conn->param_mode, "run")) {
        conn->mode = PREPARE_RUN;
    } else {
        lwsl_err("%d: %s: invalid mode\n", conn->serial, conn->remote_addr);
        return -1;
    }
    if (!conn->inst_id || !*conn->inst_id) {
        free(conn->inst_id);
        conn->inst_id = strdup(conn->remote_addr);
    }
    if (!is_valid_id(conn->inst_id)) {
        lwsl_err("%d: %s: inst_id is invalid\n", conn->serial, conn->remote_addr);
        return -1;
    }

    conn->established = 1;
    lwsl_user("%d: %s: %s: connection established, queue %s, mode %s\n", conn->serial, conn->remote_addr, conn->inst_id,
        conn->queue_id, conn->param_mode);

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

/*

    case LWS_CALLBACK_ESTABLISHED:
        printf("established\n");
        app->current_wsi = wsi;
        break;
    case LWS_CALLBACK_SERVER_WRITEABLE: {
        const char msg[] = "timer";
        char buf[LWS_PRE + sizeof(msg)];
        memcpy(&buf[LWS_PRE], msg, sizeof(msg));
        lws_write(wsi, (unsigned char *) &buf[LWS_PRE], sizeof(msg) - 1, LWS_WRITE_TEXT);
        break;
    }
    case LWS_CALLBACK_RECEIVE: {
        int is_first = lws_is_first_fragment(wsi);
        int is_final = lws_is_final_fragment(wsi);
        int is_binary = lws_frame_is_binary(wsi);
        printf("receive: %d %d %d %d\n", is_first, is_final, is_binary, (int) len);
        //lws_callback_on_writable(wsi);
        break;
    }
*/
    case LWS_CALLBACK_CLOSED: {
        if (conn->established) {
            lwsl_user("%d: %s: %s: connection closed, queue %s, mode %s\n", conn->serial, conn->remote_addr, conn->inst_id,
                conn->queue_id, conn->param_mode);
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
