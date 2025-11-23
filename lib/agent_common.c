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
#include "ejudge/random.h"
#include "ejudge/errlog.h"
#include "ejudge/osdeps.h"
#include "ejudge/xalloc.h"

#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <zlib.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

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

int
spool_queue_read_packet(
        SpoolQueue *q,
        const unsigned char *pkt_name,
        char **p_data,
        size_t *p_size)
{
    unsigned char dir_path[PATH_MAX];
    unsigned char out_path[PATH_MAX];
    __attribute__((unused)) int r;
    int fd = -1;
    char *data = NULL;
    unsigned long long unique_prefix = random_u64();

    r = snprintf(dir_path, sizeof(dir_path), "%s/%s", q->queue_packet_dir, pkt_name);
    r = snprintf(out_path, sizeof(out_path), "%s/%llx%s", q->queue_out_dir, unique_prefix, pkt_name);

    r = rename(dir_path, out_path);
    if (r < 0 && errno == ENOENT) {
        return 0;
    }
    if (r < 0) {
        err("%s: %s:%d: rename %s->%s failed: %s", q->queue_id, __FUNCTION__, __LINE__, dir_path, out_path, os_ErrorMsg());
        out_path[0] = 0;
        goto fail;
    }
    struct stat stb;
    if (lstat(out_path, &stb) < 0) {
        err("%s: %s:%d: lstat %s failed: %s", q->queue_id, __FUNCTION__, __LINE__, out_path, os_ErrorMsg());
        goto fail;
    }
    if (!S_ISREG(stb.st_mode)) {
        err("%s: %s:%d: not regular file %s", q->queue_id, __FUNCTION__, __LINE__, out_path);
        goto fail;
    }
    if (stb.st_nlink != 1) {
        // two processes renamed the file simultaneously
        rename(out_path, dir_path);
        unlink(out_path);
        info("%s: rename created two hardlinks, rollback", q->queue_id);
        return 0;
    }
    if (stb.st_size <= 0) {
        char *data = malloc(1);
        data[0] = 0;
        *p_data = data;
        *p_size = 0;
        unlink(out_path);
        return 1;
    }

    data = malloc(stb.st_size + 1);
    data[stb.st_size] = 0;
    fd = open(out_path, O_RDONLY, 0);
    if (fd < 0) {
        err("%s: %s:%d: cannot open '%s': %s", q->queue_id, __FUNCTION__, __LINE__, out_path, os_ErrorMsg());
        goto fail;
    }
    char *ptr = data;
    size_t remain = stb.st_size;
    while (remain > 0) {
        ssize_t rr = read(fd, ptr, remain);
        if (rr < 0) {
            err("%s: %s:%d: read error on '%s': %s", q->queue_id, __FUNCTION__, __LINE__, out_path, os_ErrorMsg());
            goto fail;
        }
        if (!rr) {
            err("%s: %s:%d: unexpected EOF on '%s'", q->queue_id, __FUNCTION__, __LINE__, out_path);
            goto fail;
        }
        remain -= rr;
    }

    close(fd);
    unlink(out_path);
    *p_data = data;
    *p_size = stb.st_size;

    info("%s: read file '%s', %lld", q->queue_id, pkt_name, (long long) stb.st_size);

    return 1;

fail:;
    if (out_path[0]) unlink(out_path);
    if (fd >= 0) close(fd);
    free(data);
    return -1;
}

void
agent_add_file_to_object(
        cJSON *j,
        const char *data,
        size_t size)
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

int
agent_extract_file(
        const unsigned char *inst_id,
        cJSON *j,
        char **p_pkt_ptr,
        size_t *p_pkt_len)
{
    cJSON *jz = cJSON_GetObjectItem(j, "size");
    if (!jz || jz->type != cJSON_Number) {
        err("%s: %s:%d: invalid json: no size", inst_id, __FUNCTION__, __LINE__);
        return -1;
    }
    size_t size = (int) jz->valuedouble;
    if (size < 0 || size > 1000000000) {
        err("%s: %s:%d: invalid json: invalid size", inst_id, __FUNCTION__, __LINE__);
        return -1;
    }
    if (!size) {
        char *ptr = malloc(1);
        *ptr = 0;
        *p_pkt_ptr = ptr;
        *p_pkt_len = 0;
        return 1;
    }
    cJSON *jb64 = cJSON_GetObjectItem(j, "b64");
    if (!jb64 || jb64->type != cJSON_True) {
        err("%s: %s:%d: invalid json: no encoding", inst_id, __FUNCTION__, __LINE__);
        return -1;
    }
    cJSON *jd = cJSON_GetObjectItem(j, "data");
    if (!jd || jd->type != cJSON_String) {
        err("%s: %s:%d: invalid json: no data", inst_id, __FUNCTION__, __LINE__);
        return -1;
    }
    int len = strlen(jd->valuestring);
    cJSON *jgz = cJSON_GetObjectItem(j, "gz");
    cJSON *jlzma = cJSON_GetObjectItem(j, "lzma");
    if (jgz && jgz->type == cJSON_True) {
        cJSON *jgzz = cJSON_GetObjectItem(j, "gz_size");
        if (!jgzz || jgzz->type != cJSON_Number) {
            err("%s: %s:%d: invalid json: no gz_size", inst_id, __FUNCTION__, __LINE__);
            return -1;
        }
        size_t gz_size = (size_t) jgzz->valuedouble;
        char *gz_buf = malloc(len + 1);
        int b64err = 0;
        int n = base64u_decode(jd->valuestring, len, gz_buf, &b64err);
        if (n != gz_size) {
            err("%s: %s:%d: invalid json: size mismatch", inst_id, __FUNCTION__, __LINE__);
            free(gz_buf);
            return -1;
        }

        z_stream zs = {};
        if (inflateInit(&zs) != Z_OK) {
            err("%s: %s:%d: invalid json: libz failed", inst_id, __FUNCTION__, __LINE__);
            free(gz_buf);
            return -1;
        }
        zs.next_in = (Bytef *) gz_buf;
        zs.avail_in = gz_size;
        zs.total_in = gz_size;
        unsigned char *ptr = malloc(size + 1);
        zs.next_out = (Bytef *) ptr;
        zs.avail_out = size;
        zs.total_out = 0;
        if (inflate(&zs, Z_FINISH) != Z_STREAM_END) {
            err("%s: %s:%d: invalid json: libz inflate failed", inst_id, __FUNCTION__, __LINE__);
            free(gz_buf);
            free(ptr);
            inflateEnd(&zs);
            return -1;
        }
        if (inflateEnd(&zs) != Z_OK) {
            err("%s: %s:%d: invalid json: libz inflate failed", inst_id, __FUNCTION__, __LINE__);
            free(gz_buf);
            free(ptr);
            return -1;
        }
        ptr[size] = 0;
        free(gz_buf);
        *p_pkt_ptr = ptr;
        *p_pkt_len = size;
    } else if (jlzma && jlzma->type == cJSON_True) {
        cJSON *jlzmaz = cJSON_GetObjectItem(j, "lzma_size");
        if (!jlzmaz || jlzmaz->type != cJSON_Number) {
            err("%s: %s:%d: invalid json: no lzma_size", inst_id, __FUNCTION__, __LINE__);
            return -1;
        }
        size_t lzma_size = (size_t) jlzmaz->valuedouble;
        char *lzma_buf = malloc(len + 1);
        int b64err = 0;
        int n = base64u_decode(jd->valuestring, len, lzma_buf, &b64err);
        if (n != lzma_size) {
            err("%s: %s:%d: invalid json: size mismatch", inst_id, __FUNCTION__, __LINE__);
            free(lzma_buf);
            return -1;
        }
        unsigned char *ptr = NULL;
        size_t ptr_size = 0;
        if (ej_lzma_decode_buf(lzma_buf, lzma_size, size, &ptr, &ptr_size) < 0) {
            err("%s: %s:%d: invalid json: lzma decode error", inst_id, __FUNCTION__, __LINE__);
            free(lzma_buf);
            return -1;
        }
        free(lzma_buf);
        *p_pkt_ptr = ptr;
        *p_pkt_len = ptr_size;
    } else {
        char *ptr = malloc(len + 1);
        int b64err = 0;
        int n = base64u_decode(jd->valuestring, len, ptr, &b64err);
        if (n != size) {
            err("%s: %s:%d: invalid json: size mismatch", inst_id, __FUNCTION__, __LINE__);
            free(ptr);
            return -1;
        }
        ptr[size] = 0;
        *p_pkt_ptr = ptr;
        *p_pkt_len = size;
    }
    return 1;
}

int
agent_extract_file_result(
        cJSON *j,
        char **p_pkt_ptr,
        size_t *p_pkt_len)
{
    cJSON *jok = cJSON_GetObjectItem(j, "ok");
    if (!jok || jok->type != cJSON_True) {
        return -1;
    }
    cJSON *jq = cJSON_GetObjectItem(j, "q");
    if (!jq || jq->type != cJSON_String || strcmp("file-result", jq->valuestring) != 0) {
        err("%s:%d: invalid json", __FUNCTION__, __LINE__);
        return -1;
    }
    cJSON *jf = cJSON_GetObjectItem(j, "found");
    if (!jf || jf->type != cJSON_True) {
        return 0;
    }
    // TODO: call agent_extract_file?
    cJSON *jz = cJSON_GetObjectItem(j, "size");
    if (!jz || jz->type != cJSON_Number) {
        err("%s:%d: invalid json: no size", __FUNCTION__, __LINE__);
        return -1;
    }
    int size = (int) jz->valuedouble;
    if (size < 0 || size > 1000000000) {
        err("%s:%d: invalid json: invalid size", __FUNCTION__, __LINE__);
        return -1;
    }
    if (!size) {
        char *ptr = malloc(1);
        *ptr = 0;
        *p_pkt_ptr = ptr;
        *p_pkt_len = 0;
        return 1;
    }
    cJSON *jb64 = cJSON_GetObjectItem(j, "b64");
    if (!jb64 || jb64->type != cJSON_True) {
        err("%s:%d: invalid json: no encoding", __FUNCTION__, __LINE__);
        return -1;
    }
    cJSON *jd = cJSON_GetObjectItem(j, "data");
    if (!jd || jd->type != cJSON_String) {
        err("%s:%d: invalid json: no data", __FUNCTION__, __LINE__);
        return -1;
    }
    int len = strlen(jd->valuestring);
    cJSON *jgz = cJSON_GetObjectItem(j, "gz");
    cJSON *jlzma = cJSON_GetObjectItem(j, "lzma");

    if (jgz && jgz->type == cJSON_True) {
        cJSON *jgzz = cJSON_GetObjectItem(j, "gz_size");
        if (!jgzz || jgzz->type != cJSON_Number) {
            err("%s:%d: invalid json: no gz_size", __FUNCTION__, __LINE__);
            return -1;
        }
        size_t gz_size = (size_t) jgzz->valuedouble;
        char *gz_buf = malloc(len + 1);
        int b64err = 0;
        int n = base64u_decode(jd->valuestring, len, gz_buf, &b64err);
        if (n != gz_size) {
            err("%s:%d: invalid json: size mismatch", __FUNCTION__, __LINE__);
            free(gz_buf);
            return -1;
        }

        z_stream zs = {};
        if (inflateInit(&zs) != Z_OK) {
            err("%s:%d: invalid json: libz failed", __FUNCTION__, __LINE__);
            free(gz_buf);
            return -1;
        }
        zs.next_in = (Bytef *) gz_buf;
        zs.avail_in = gz_size;
        zs.total_in = gz_size;
        unsigned char *ptr = malloc(size + 1);
        zs.next_out = (Bytef *) ptr;
        zs.avail_out = size;
        zs.total_out = 0;
        if (inflate(&zs, Z_FINISH) != Z_STREAM_END) {
            err("%s:%d: invalid json: libz inflate failed", __FUNCTION__, __LINE__);
            free(gz_buf);
            free(ptr);
            inflateEnd(&zs);
            return -1;
        }
        if (inflateEnd(&zs) != Z_OK) {
            err("%s:%d: invalid json: libz inflate failed", __FUNCTION__, __LINE__);
            free(gz_buf);
            free(ptr);
            return -1;
        }
        ptr[size] = 0;
        free(gz_buf);
        *p_pkt_ptr = ptr;
        *p_pkt_len = size;
    } else if (jlzma && jlzma->type == cJSON_True) {
        cJSON *jlzmaz = cJSON_GetObjectItem(j, "lzma_size");
        if (!jlzmaz || jlzmaz->type != cJSON_Number) {
            err("%s:%d: invalid json: no lzma_size", __FUNCTION__, __LINE__);
            return -1;
        }
        size_t lzma_size = (size_t) jlzmaz->valuedouble;
        char *lzma_buf = malloc(len + 1);
        int b64err = 0;
        int n = base64u_decode(jd->valuestring, len, lzma_buf, &b64err);
        if (n != lzma_size) {
            err("%s:%d: invalid json: size mismatch", __FUNCTION__, __LINE__);
            free(lzma_buf);
            return -1;
        }
        unsigned char *ptr = NULL;
        size_t ptr_size = 0;
        if (ej_lzma_decode_buf(lzma_buf, lzma_size, size, &ptr, &ptr_size) < 0) {
            err("%s:%d: invalid json: lzma decode error", __FUNCTION__, __LINE__);
            free(lzma_buf);
            return -1;
        }
        free(lzma_buf);
        *p_pkt_ptr = ptr;
        *p_pkt_len = ptr_size;
    } else {
        char *ptr = malloc(len + 1);
        int b64err = 0;
        int n = base64u_decode(jd->valuestring, len, ptr, &b64err);
        if (n != size) {
            err("%s:%d: invalid json: size mismatch", __FUNCTION__, __LINE__);
            free(ptr);
            return -1;
        }
        ptr[size] = 0;
        *p_pkt_ptr = ptr;
        *p_pkt_len = size;
    }

    return 1;
}

ContestSpool *
contest_spool_get(
        ContestSpools *ss,
        const unsigned char *server,
        int contest_id,
        int mode)
{
    for (unsigned i = 0; i < ss->u; ++i) {
        ContestSpool *cs = &ss->v[i];
        if (!strcmp(cs->server, server) && cs->contest_id == contest_id && cs->mode == mode) {
            return cs;
        }
    }

    const unsigned char *root_dir = NULL;
    if (mode == PREPARE_COMPILE) {
#if defined EJUDGE_COMPILE_SPOOL_DIR
        root_dir = EJUDGE_COMPILE_SPOOL_DIR;
#endif
    } else if (mode == PREPARE_RUN) {
#if defined EJUDGE_RUN_SPOOL_DIR
        root_dir = EJUDGE_RUN_SPOOL_DIR;
#endif
    }

    __attribute__((unused)) int _;
    unsigned char server_dir[PATH_MAX];
    _ = snprintf(server_dir, sizeof(server_dir), "%s/%s", root_dir, server);
    unsigned char server_contest_dir[PATH_MAX];
    strcpy(server_contest_dir, server_dir);
    unsigned char status_dir[PATH_MAX];
    _ = snprintf(status_dir, sizeof(status_dir), "%s/status", server_contest_dir);
    unsigned char report_dir[PATH_MAX];
    _ = snprintf(report_dir, sizeof(report_dir), "%s/report", server_contest_dir);
    unsigned char output_dir[PATH_MAX];
    _ = snprintf(output_dir, sizeof(output_dir), "%s/output", server_contest_dir);

    if (ss->u == ss->a) {
        if (!(ss->a *= 2)) ss->a = 16;
        XREALLOC(ss->v, ss->a);
    }

    unsigned i = ss->u++;
    ContestSpool *cs = &ss->v[i];
    memset(cs, 0, sizeof(*cs));
    cs->serial = i;
    cs->mode = mode;
    cs->server = xstrdup(server);
    cs->contest_id = contest_id;
    cs->server_dir = xstrdup(server_dir);
    cs->server_contest_dir = xstrdup(server_contest_dir);
    cs->status_dir = xstrdup(status_dir);
    cs->report_dir = xstrdup(report_dir);
    cs->output_dir = xstrdup(output_dir);

    return cs;
}

int
agent_save_to_spool(
    const unsigned char *inst_id,
    const unsigned char *spool_dir,
    const unsigned char *file_name,
    const unsigned char *data,
    size_t size)
{
    __attribute__((unused)) int _;
    unsigned char in_path[PATH_MAX];
    unsigned char dir_path[PATH_MAX];
    int fd = -1;
    int retval = -1;
    unsigned char *mem = MAP_FAILED;

    _ = snprintf(in_path, sizeof(in_path), "%s/in/%s", spool_dir, file_name);
    fd = open(in_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        err("%s: %s:%d: put_heartbeat: open %s failed: %s", inst_id, __FUNCTION__, __LINE__, in_path, os_ErrorMsg());
        goto done;
    }
    if (ftruncate(fd, size) < 0) {
        err("%s: %s:%d: ftruncate failed: %s", inst_id, __FUNCTION__, __LINE__, os_ErrorMsg());
        goto done;
    }
    if (size > 0) {
        mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (mem == MAP_FAILED) {
            err("%s: %s:%d: mmap failed: %s", inst_id, __FUNCTION__, __LINE__, os_ErrorMsg());
            goto done;
        }
        memmove(mem, data, size);
        munmap(mem, size); mem = MAP_FAILED;
    }
    close(fd); fd = -1;

    _ = snprintf(dir_path, sizeof(dir_path), "%s/dir/%s", spool_dir, file_name);
    if (rename(in_path, dir_path) < 0) {
        err("%s: %s:%d: %s", inst_id, __FUNCTION__, __LINE__, os_ErrorMsg());
        goto done;
    }
    in_path[0] = 0;

    retval = 0;

done:;
    if (mem != MAP_FAILED) munmap(mem, size);
    if (fd >= 0) close(fd);
    if (in_path[0]) unlink(in_path);
    return retval;
}
