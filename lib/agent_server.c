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
#include "ejudge/xalloc.h"

#include <libwebsockets.h>
#include <uv.h>

#define DEFAULT_SERVER_PORT 8888

typedef struct ConnectionState
{
} ConnectionState;

typedef struct AgentServerState
{
    uv_loop_t *loop;
    void *loops[1]; // foreign loop pointer for libwebsockets
    struct lws_context *context;
    const struct ejudge_cfg *ejudge_config;
} AgentServerState;

#define L_ERR(format, ...) fprintf(log_f, "%s:%d:" format "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define L_ERR_FAIL(format, ...) do { fprintf(log_f, "%s:%d:" format "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); goto fail; } while (0)
#define L_ERR_DONE(format, ...) do { fprintf(log_f, "%s:%d:" format "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); goto done; } while (0)

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
    __attribute__((unused))
    ConnectionState *conn = (ConnectionState *) user;
    __attribute__((unused))
    AgentServerState *ass = (AgentServerState*) lws_context_user(ctx);
/*

    switch (reason) {
    case LWS_CALLBACK_PROTOCOL_INIT:
        break;
    case LWS_CALLBACK_PROTOCOL_DESTROY:
        break;
    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION: {
        printf("Here!\n");
        int len = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_AUTHORIZATION);
        char *buf = malloc(len + 1);
        lws_hdr_copy(wsi, buf, len + 1, WSI_TOKEN_HTTP_AUTHORIZATION);
        printf("http host: %s!\n", buf);
        break;
    }
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
    case LWS_CALLBACK_CLOSED:
        printf("closed\n");
        app->current_wsi = NULL;
        break;
    default:
        break;
    }
*/
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
