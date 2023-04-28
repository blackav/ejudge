/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/compile_heartbeat.h"
#include "ejudge/xalloc.h"
#include "ejudge/fileutl.h"
#include "ejudge/errlog.h"
#include "ejudge/xalloc.h"

#include "flatbuf-gen/compile_heartbeat_verifier.h"

#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>

struct compile_heartbeat_vector *
compile_heartbeat_vector_free(
        struct compile_heartbeat_vector *v,
        int free_v_flag)
{
    for (int i = 0; i < v->u; ++i) {
        struct compile_heartbeat_vector_item *item = v->v[i];
        xfree(item->queue);
        xfree(item->file);
        xfree(item->data);
        xfree(item);
    }
    xfree(v->v);

    if (free_v_flag) {
        xfree(v);
    }

    return NULL;
}

void
compile_heartbeat_scan(
        const unsigned char *queue,
        const unsigned char *heartbeat_dir,
        struct compile_heartbeat_vector *v)
{
    if (!heartbeat_dir) return;

    unsigned char dpath[PATH_MAX];
    snprintf(dpath, sizeof(dpath), "%s/dir", heartbeat_dir);

    DIR *d = opendir(dpath);
    if (!d) return;

    struct dirent *dd;
    while ((dd = readdir(d))) {
        if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, "..")) continue;
        int len = strlen(dd->d_name);
        if (len > 2 && dd->d_name[len - 2] == '@') continue;
        unsigned char path[PATH_MAX];
        __attribute__((unused)) int r;
        r = snprintf(path, sizeof(path), "%s/%s", dpath, dd->d_name);
        struct stat stb;
        if (stat(path, &stb) < 0) continue;
        if (!S_ISREG(stb.st_mode)) continue;
        size_t size = stb.st_size;
        unsigned char *data = NULL;
        if (fast_read_file_with_size(path, size, &data) < 0) {
            continue;
        }
        int ret = ej_compile_Heartbeat_verify_as_root(data, size);
        if (ret) {
            err("%s: invalid flatbuf: %s", __FUNCTION__,
                flatcc_verify_error_string(ret));
            continue;
        }
        if (v->u == v->a) {
            if (!(v->a *= 2)) v->a = 8;
            XREALLOC(v->v, v->a);
        }
        struct compile_heartbeat_vector_item *item;
        XCALLOC(item, 1);
        item->queue = xstrdup(queue);
        item->file = xstrdup(dd->d_name);
        item->data = data;
        item->size = size;
        v->v[v->u++] = item;
    }
    closedir(d);
}
