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
#include "ejudge/agent_common.h"
#include "ejudge/prepare.h"
#include "ejudge/fileutl.h"
#include "ejudge/base64.h"
#include "ejudge/ej_lzma.h"
#include "ejudge/cJSON.h"
#include "ejudge/xalloc.h"

#include <zlib.h>
#include <string.h>

int
spool_queue_init(
    SpoolQueue *q,
    const unsigned char *queue_id,
    int mode,
    unsigned index)
{
    memset(q, 0, sizeof(*q));
    __attribute__((unused)) int _;
    char *s = NULL;

    q->queue_id = xstrdup(queue_id);
    q->mode = mode;
    q->index = index;

    if (q->mode == PREPARE_COMPILE) {
#if defined EJUDGE_COMPILE_SPOOL_DIR
        _ = asprintf(&s, "%s/%s", EJUDGE_COMPILE_SPOOL_DIR, q->queue_id);
        q->spool_dir = s; s = NULL;
        _ = asprintf(&s, "%s/queue", q->spool_dir);
        q->queue_dir = s; s = NULL;
        _ = asprintf(&s, "%s/dir", q->queue_dir);
        q->queue_packet_dir = s; s = NULL;
        _ = asprintf(&s, "%s/out", q->queue_dir);
        q->queue_out_dir = s; s = NULL;
        _ = asprintf(&s, "%s/src", q->spool_dir);
        q->data_dir = s; s = NULL;
        _ = asprintf(&s, "%s/heartbeat", q->spool_dir);
        q->heartbeat_dir = s; s = NULL;
        _ = asprintf(&s, "%s/dir", q->heartbeat_dir);
        q->heartbeat_packet_dir = s; s = NULL;
        _ = asprintf(&s, "%s/in", q->heartbeat_dir);
        q->heartbeat_in_dir = s; s = NULL;
        _ = asprintf(&s, "%s/config", q->spool_dir);
        q->config_dir = s; s = NULL;
        _ = asprintf(&s, "%s/dir", q->config_dir);
        q->config_packet_dir = s; s = NULL;
        _ = asprintf(&s, "%s/in", q->config_dir);
        q->config_in_dir = s; s = NULL;
#endif
    } else if (q->mode == PREPARE_RUN) {
#if defined EJUDGE_RUN_SPOOL_DIR
        _ = asprintf(&s, "%s/%s", EJUDGE_RUN_SPOOL_DIR, q->queue_id);
        q->spool_dir = s; s = NULL;
        _ = asprintf(&s, "%s/queue", q->spool_dir);
        q->queue_dir = s; s = NULL;
        _ = asprintf(&s, "%s/dir", q->queue_dir);
        q->queue_packet_dir = s; s = NULL;
        _ = asprintf(&s, "%s/out", q->queue_dir);
        q->queue_out_dir = s; s = NULL;
        _ = asprintf(&s, "%s/exe", q->spool_dir);
        q->data_dir = s; s = NULL;
        _ = asprintf(&s, "%s/heartbeat", q->spool_dir);
        q->heartbeat_dir = s; s = NULL;
        _ = asprintf(&s, "%s/dir", q->heartbeat_dir);
        q->heartbeat_packet_dir = s; s = NULL;
        _ = asprintf(&s, "%s/in", q->heartbeat_dir);
        q->heartbeat_in_dir = s; s = NULL;
#endif
    }

    // create directories
    if (q->spool_dir && q->spool_dir[0]) {
        if (make_dir(q->spool_dir, 0700) < 0) {
            goto fail;
        }
    }
    if (q->queue_dir && q->queue_dir[0]) {
        if (make_all_dir(q->queue_dir, 0700) < 0) {
            goto fail;
        }
    }
    if (q->data_dir && q->data_dir[0]) {
        if (make_dir(q->data_dir, 0700) < 0) {
            goto fail;
        }
    }
    if (q->heartbeat_dir && q->heartbeat_dir[0]) {
        if (make_all_dir(q->heartbeat_dir, 0700) < 0) {
            goto fail;
        }
    }
    if (q->config_dir && q->config_dir[0]) {
        if (make_all_dir(q->config_dir, 0700) < 0) {
            goto fail;
        }
    }

    return 0;

fail:;
    spool_queue_destroy(q);
    return -1;
}

void
spool_queue_destroy(SpoolQueue *q)
{
    if (!q) return;
    free(q->queue_id);
    free(q->spool_dir);
    free(q->queue_dir);
    free(q->queue_packet_dir);
    free(q->queue_out_dir);
    free(q->data_dir);
    free(q->heartbeat_dir);
    free(q->heartbeat_packet_dir);
    free(q->heartbeat_in_dir);
    free(q->config_dir);
    free(q->config_packet_dir);
    free(q->config_in_dir);
    memset(q, 0, sizeof(*q));
}

void
agent_add_file_to_object(cJSON *j, const char *data, size_t size)
{
    cJSON_AddNumberToObject(j, "size", (double) size);
    if (!size) {
        return;
    }
    // gzip mode
    if (size < 32) {
        cJSON_AddTrueToObject(j, "b64");
        char *ptr = malloc(size * 2 + 16);
        int n = base64u_encode(data, size, ptr);
        ptr[n] = 0;
        cJSON_AddStringToObject(j, "data", ptr);
        free(ptr);
    } else {
        z_stream zs = {};
        zs.next_in = (Bytef *) data;
        zs.avail_in = size;
        zs.total_in = size;

        if (deflateInit(&zs, 9) != Z_OK) {
            abort();
        }
        size_t bound = deflateBound(&zs, size);
        char *gz_buf = malloc(bound);
        zs.next_out = (Bytef*) gz_buf;
        zs.avail_out = bound;
        zs.total_out = 0;
        int r = deflate(&zs, Z_FINISH);
        if (r != Z_STREAM_END) {
            abort();
        }
        size_t gz_size = zs.total_out;
        if (deflateEnd(&zs) != Z_OK) {
            abort();
        }
        cJSON_AddTrueToObject(j, "gz");
        cJSON_AddNumberToObject(j, "gz_size", gz_size);
        char *b64_buf = malloc(gz_size * 2 + 16);
        int b64_size = base64u_encode(gz_buf, gz_size, b64_buf);
        b64_buf[b64_size] = 0;
        cJSON_AddTrueToObject(j, "b64");
        cJSON_AddStringToObject(j, "data", b64_buf);
        free(b64_buf);
        free(gz_buf);
    }

#if 0
    // lzma mode (unused)
    if (size < 160) {
        cJSON_AddTrueToObject(j, "b64");
        char *ptr = malloc(size * 2 + 16);
        int n = base64u_encode(data, size, ptr);
        ptr[n] = 0;
        cJSON_AddStringToObject(j, "data", ptr);
        free(ptr);
    } else {
        unsigned char *lzma_buf = NULL;
        size_t lzma_size = 0;
        if (ej_lzma_encode_buf(data, size, &lzma_buf, &lzma_size) < 0) {
            // fallback to uncompressed
            cJSON_AddTrueToObject(j, "b64");
            char *ptr = malloc(size * 2 + 16);
            int n = base64u_encode(data, size, ptr);
            ptr[n] = 0;
            cJSON_AddStringToObject(j, "data", ptr);
            free(ptr);
        } else {
            cJSON_AddTrueToObject(j, "lzma");
            cJSON_AddNumberToObject(j, "lzma_size", (double) lzma_size);
            char *b64_buf = malloc(lzma_size * 2 + 16);
            int b64_size = base64u_encode(lzma_buf, lzma_size, b64_buf);
            b64_buf[b64_size] = 0;
            cJSON_AddTrueToObject(j, "b64");
            cJSON_AddStringToObject(j, "data", b64_buf);
            free(b64_buf);
            free(lzma_buf);
        }
    }
#endif
}
