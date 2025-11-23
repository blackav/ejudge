/* -*- mode: c; c-basic-offset: 4 -*- */

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
#include "ejudge/agent_client.h"
#include "ejudge/agent_common.h"
#include "ejudge/prepare.h"
#include "ejudge/misctext.h"
#include "ejudge/cJSON.h"
#include "ejudge/osdeps.h"
#include "ejudge/errlog.h"
#include "ejudge/xalloc.h"

#include <curl/curl.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>

struct AgentClientWs
{
    struct AgentClient b;

    CURL *curl;

    unsigned char *ejudge_xml_dir;
    unsigned char *inst_id;
    unsigned char *endpoint;
    unsigned char *queue_id;
    unsigned char *ip_address;
    unsigned char *token_file;

    int mode;
    int verbose_mode;
    int is_stopped;
    int serial;

    unsigned char *in_buf;
    size_t in_buf_a;
    size_t in_buf_u;
};

static struct AgentClient *
destroy_func(struct AgentClient *ac)
{
    struct AgentClientWs *acw = (struct AgentClientWs *) ac;
    if (!acw) return NULL;

    if (acw->curl) curl_easy_cleanup(acw->curl);
    free(acw->token_file);
    free(acw->ip_address);
    free(acw->queue_id);
    free(acw->endpoint);
    free(acw->inst_id);
    free(acw->ejudge_xml_dir);
    free(acw);
    return NULL;
}

static int
init_func(
        struct AgentClient *ac,
        const unsigned char *inst_id,
        const unsigned char *endpoint,
        const unsigned char *queue_id,
        int mode,
        int verbose_mode,
        const unsigned char *ip_address)
{
    struct AgentClientWs *acw = (struct AgentClientWs *) ac;

    acw->inst_id = xstrdup(inst_id);
    acw->endpoint = xstrdup(endpoint);
    if (queue_id) {
        acw->queue_id = xstrdup(queue_id);
    }
    if (ip_address) {
        acw->ip_address = xstrdup(ip_address);
    }
    acw->mode = mode;
    acw->verbose_mode = verbose_mode;

    const unsigned char *ejudge_xml_path = NULL;
#if defined EJUDGE_XML_PATH
    if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif
    if (!ejudge_xml_path) {
        err("%s:%d: ejudge.xml path is unspecified", __FUNCTION__, __LINE__);
        return -1;
    }
    acw->ejudge_xml_dir = os_DirName(ejudge_xml_path);

    return 0;
}

static unsigned char *
read_token(
    struct AgentClientWs *acw,
    const unsigned char *token_file)
{
    unsigned char full_path[PATH_MAX];
    if (os_IsAbsolutePath(token_file)) {
        if (snprintf(full_path, sizeof(full_path), "%s", token_file) >= (int) sizeof(full_path)) {
            err("%s:%d: token path is too long", __FUNCTION__, __LINE__);
            return NULL;
        }
    } else {
        if (snprintf(full_path, sizeof(full_path), "%s/%s", acw->ejudge_xml_dir, token_file) >= (int) sizeof(full_path)) {
            err("%s:%d: token path is too long", __FUNCTION__, __LINE__);
            return NULL;
        }
    }
    FILE *fin = fopen(full_path, "r");
    if (!fin) {
        err("%s:%d: failed to open token file '%s': %s", __FUNCTION__, __LINE__, full_path, strerror(errno));
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

static int
connect_func(struct AgentClient *ac)
{
    struct AgentClientWs *acw = (struct AgentClientWs *) ac;
    int retval = -1;
    struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
    char *urlt = NULL;
    size_t urlz = 0;
    FILE *urlf = NULL;
    struct curl_slist *headers = NULL;
    char *authorization = NULL;
    unsigned char *token = NULL;
    __attribute__((unused)) int _;

    CURLcode cc = curl_global_init(CURL_GLOBAL_ALL);
    if (cc != CURLE_OK) {
        err("%s:%d: curl_global_init failed: %s", __FUNCTION__, __LINE__, curl_easy_strerror(cc));
        goto done;
    }
    acw->curl = curl_easy_init();
    if (!acw->curl) {
        err("%s:%d: curl_easy_init failed", __FUNCTION__, __LINE__);
        goto done;
    }

    urlf = open_memstream(&urlt, &urlz);
    unsigned char sep = '?';
    fprintf(urlf, "%s", acw->endpoint);
    if (acw->inst_id) {
        fprintf(urlf, "%cinst_id=%s", sep, url_armor_buf(&ab, acw->inst_id));
        sep = '&';
    }
    if (acw->queue_id) {
        fprintf(urlf, "%cqueue_id=%s", sep, url_armor_buf(&ab, acw->queue_id));
        sep = '&';
    }
    if (acw->ip_address) {
        fprintf(urlf, "%cip_address=%s", sep, url_armor_buf(&ab, acw->ip_address));
        sep = '&';
    }
    if (acw->mode == PREPARE_COMPILE) {
        fprintf(urlf, "%cmode=compile", sep);
        sep = '&';
    } else if (acw->mode == PREPARE_RUN) {
        fprintf(urlf, "%cmode=run", sep);
        sep = '&';
    }
    if (acw->verbose_mode > 0) {
        fprintf(urlf, "%cverbose=%d", sep, acw->verbose_mode);
        sep = '&';
    }
    fclose(urlf); urlf = NULL;

    if (acw->token_file && acw->token_file[0]) {
        if (!(token = read_token(acw, acw->token_file))) {
            err("%s:%d: read_token failed", __FUNCTION__, __LINE__);
            goto done;
        }
        _ = asprintf(&authorization, "Authorization: Bearer %s", token);
        headers = curl_slist_append(headers, authorization);
    }

    curl_easy_setopt(acw->curl, CURLOPT_URL, urlf);
    if (headers) {
        curl_easy_setopt(acw->curl, CURLOPT_HTTPHEADER, headers);
    }
    curl_easy_setopt(acw->curl, CURLOPT_CONNECT_ONLY, 2L);
    cc = curl_easy_perform(acw->curl);
    if (cc != CURLE_OK) {
        err("%s:%d: curl_easy_perform failed: %s", __FUNCTION__, __LINE__, curl_easy_strerror(cc));
        goto done;
    }

    retval = 0;

done:;
    html_armor_free(&ab);
    if (urlf) fclose(urlf);
    free(urlt);
    if (headers) curl_slist_free_all(headers);
    free(authorization);
    free(token);
    return retval;
}

static void
close_func(struct AgentClient *ac)
{
    struct AgentClientWs *acw = (struct AgentClientWs *) ac;
    curl_easy_cleanup(acw->curl);
    acw->curl = NULL;
    acw->is_stopped = 1;
}

static int
is_closed_func(struct AgentClient *ac)
{
    struct AgentClientWs *acw = (struct AgentClientWs *) ac;
    return acw->is_stopped;
}

static cJSON *
create_request(
        struct AgentClientWs *acw,
        long long *p_time_ms,
        const unsigned char *query)
{
    cJSON *jq = cJSON_CreateObject();
    int serial = ++acw->serial;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    long long current_time_ms = tv.tv_sec * 1000LL + tv.tv_usec / 1000;
    if (p_time_ms) *p_time_ms = current_time_ms;

    cJSON_AddNumberToObject(jq, "t", (double) current_time_ms);
    cJSON_AddNumberToObject(jq, "s", (double) serial);
    cJSON_AddStringToObject(jq, "q", query);

    return jq;
}

static int
send_json(struct AgentClientWs *acw, cJSON *json)
{
    /*
 res = curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sockfd);
    if(!res && sockfd != CURL_SOCKET_BAD) {
      // operate on sockfd
    }
    */
    char *str = cJSON_PrintUnformatted(json);
    size_t len = strlen(str);
    if (acw->verbose_mode) {
        info("to agent: %s", str);
    }
    char *ptr = str;
    while (len) {
        size_t sent = 0;
        CURLcode res = curl_ws_send(acw->curl, ptr, len, &sent, 0, CURLWS_TEXT);
        if (res == CURLE_AGAIN) {
            // in real application: wait for socket here, e.g. using select()
            continue;
        }
        if (res != CURLE_OK) {
            err("%s:%d: curl_ws_send failed: %s", __FUNCTION__, __LINE__, curl_easy_strerror(res));
            free(str);
            return -1;
        }
        ptr += sent;
        len -= sent;
    }
    return 0;
}

static cJSON *
recv_json(struct AgentClientWs *acw)
{
    if (!acw->in_buf_a) {
        acw->in_buf_a = 4096;
        acw->in_buf = xmalloc(acw->in_buf_a);
    }
    acw->in_buf_u = 0;

    while (1) {
        size_t recv;
        const struct curl_ws_frame *meta;
        CURLcode res = curl_ws_recv(acw->curl, &acw->in_buf[acw->in_buf_u], acw->in_buf_a - acw->in_buf_u, &recv, &meta);
        if (res == CURLE_AGAIN) {
            // in real application: wait for socket here, e.g. using select()
            continue;
        }
        if (res != CURLE_OK) {
            err("%s:%d: websocket read error: %s", __FUNCTION__, __LINE__, curl_easy_strerror(res));
            return NULL;
        }
        if ((meta->flags & CURLWS_CLOSE)) {
            err("%s:%d: websocket connection close", __FUNCTION__, __LINE__);
            return NULL;
        }
        if ((meta->flags & (CURLWS_PING | CURLWS_PONG))) {
            continue;
        }
        if ((meta->flags & CURLWS_BINARY)) {
            err("%s:%d: binary frame received", __FUNCTION__, __LINE__);
            return NULL;
        }
        acw->in_buf_u += recv;
        if (meta->bytesleft > 0) {
            // preallocate for \0 terminator
            size_t exp_size = acw->in_buf_u + meta->bytesleft + 1;
            if (exp_size > acw->in_buf_a) {
                size_t a = acw->in_buf_a;
                while (exp_size > a) {
                    a *= 2;
                }
                XREALLOC(acw->in_buf, a);
                acw->in_buf_a = a;
            }
            continue;
        }
        if (!(meta->flags & CURLWS_CONT)) {
            // frame transfer completed
            break;
        }
    }
    if (acw->in_buf_u == acw->in_buf_a) {
        acw->in_buf_a *= 2;
        XREALLOC(acw->in_buf, acw->in_buf_a);
    }
    acw->in_buf[acw->in_buf_u] = 0;
    cJSON *j = cJSON_Parse(acw->in_buf);
    if (!j) {
        err("%s:%d: failed to parse JSON", __FUNCTION__, __LINE__);
    }
    return j;
}

static int
poll_queue_func(
        struct AgentClient *ac,
        unsigned char *pkt_name,
        size_t pkt_len,
        int random_mode,
        int enable_file,
        char **p_data,
        size_t *p_size)
{
    int result = -1;
    struct AgentClientWs *acw = (struct AgentClientWs *) ac;
    long long time_ms;
    cJSON *jr = NULL;

    cJSON *jq = create_request(acw, &time_ms, "poll");
    if (random_mode > 0) {
        cJSON_AddTrueToObject(jq, "random_mode");
    }
    if (enable_file > 0) {
        cJSON_AddTrueToObject(jq, "enable_file");
    }
    if (send_json(acw, jq) < 0) {
        err("%s:%d: send_json failed", __FUNCTION__, __LINE__);
        goto done;
    }
    cJSON_Delete(jq); jq = NULL;

    jr = recv_json(acw);
    if (!jr) {
        err("%s:%d: recv_json failed", __FUNCTION__, __LINE__);
        goto done;
    }
    cJSON *jj = cJSON_GetObjectItem(jr, "q");
    if (jj && jj->type == cJSON_String && !strcmp("poll-result", jj->valuestring)) {
        cJSON *jn = cJSON_GetObjectItem(jr, "pkt-name");
        if (!jn) {
            pkt_name[0] = 0;
            result = 1;
        } else if (jn->type == cJSON_String) {
            snprintf(pkt_name, pkt_len, "%s", jn->valuestring);
            result = 1;
        } else {
            err("%s:%d: pkt-name is invalid", __FUNCTION__, __LINE__);
        }
        goto done;
    }
    if (jj && jj->type == cJSON_String && !strcmp("file-result", jj->valuestring)) {
        cJSON *jn = cJSON_GetObjectItem(jr, "pkt-name");
        if (!jn) {
            pkt_name[0] = 0;
            result = 1;
        } else if (jn->type == cJSON_String) {
            snprintf(pkt_name, pkt_len, "%s", jn->valuestring);
            result = 1;
        }
        result = agent_extract_file_result(jr, p_data, p_size);
        if (result < 0) {
            err("%s:%d: json processing failed", __FUNCTION__, __LINE__);
        }
        goto done;
    }
    err("%s:%d: unexpected JSON result", __FUNCTION__, __LINE__);

done:;
    if (jq) cJSON_Delete(jq);
    if (jr) cJSON_Delete(jr);
    return result;
}

static int
set_token_file_func(
        struct AgentClient *ac,
        const unsigned char *token_file)
{
    struct AgentClientWs *acw = (struct AgentClientWs *) ac;
    acw->token_file = xstrdup(token_file);
    return 0;
}

static const struct AgentClientOps ops_ws =
{
    destroy_func,
    init_func,
    connect_func,
    close_func,
    is_closed_func,
    poll_queue_func,
    //get_packet_func,
    //get_data_func,
    //put_reply_func,
    //put_output_func,
    //put_output_2_func,
    //async_wait_init_func,
    //async_wait_complete_func,
    //add_ignored_func,
    //put_packet_func,
    //get_data_2_func,
    //put_heartbeat_func,
    //delete_heartbeat_func,
    //put_archive_2_func,
    //mirror_file_func,
    //put_config_func,
    .set_token_file = set_token_file_func,
};

struct AgentClient *
agent_client_ws_create(void)
{
    struct AgentClientWs *acw;

    XCALLOC(acw, 1);
    acw->b.ops = &ops_ws;

    return &acw->b;
}
