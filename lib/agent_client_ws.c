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
#include "ejudge/prepare.h"
#include "ejudge/misctext.h"
#include "ejudge/errlog.h"
#include "ejudge/xalloc.h"

#include <curl/curl.h>

#include <curl/easy.h>
#include <stdio.h>
#include <time.h>

struct AgentClientWs
{
    struct AgentClient b;

    CURL *curl;

    unsigned char *inst_id;
    unsigned char *endpoint;
    unsigned char *queue_id;
    unsigned char *ip_address;

    int mode;
    int verbose_mode;
};

static struct AgentClient *
destroy_func(struct AgentClient *ac)
{
    struct AgentClientWs *acw = (struct AgentClientWs *) ac;
    if (!acw) return NULL;

    if (acw->curl) curl_easy_cleanup(acw->curl);
    free(acw->ip_address);
    free(acw->queue_id);
    free(acw->endpoint);
    free(acw->inst_id);
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
    return 0;
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

    curl_easy_setopt(acw->curl, CURLOPT_URL, urlf);
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
    return retval;
}

static const struct AgentClientOps ops_ws =
{
    destroy_func,
    init_func,
    connect_func,
    //close_func,
    //is_closed_func,
    //poll_queue_func,
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
};

struct AgentClient *
agent_client_ws_create(void)
{
    struct AgentClientWs *acw;

    XCALLOC(acw, 1);
    acw->b.ops = &ops_ws;

    return &acw->b;
}
