/* -*- c -*- */

/* Copyright (C) 2015-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_limits.h"
#include "ejudge/super_run_status.h"
#include "ejudge/agent_client.h"

#include "ejudge/xalloc.h"

#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

void
super_run_status_init(struct super_run_status *psrs)
{
    if (!psrs) return;

    memset(psrs, 0, sizeof (*psrs));
    psrs->signature[0] = 'S';
    psrs->signature[1] = '\r';
    psrs->signature[2] = 's';
    psrs->signature[3] = '\x1';
    psrs->endianness = 1;
    psrs->version = 1;
    psrs->size = sizeof(*psrs);
    psrs->strings_off = (unsigned short)(unsigned long)(&((struct super_run_status *) 0)->strings);
    psrs->str_lens = 1;
}

int
super_run_status_add_str(struct super_run_status *psrs, const unsigned char *str)
{
    if (!str) return 0;

    int len = strlen(str);
    if (psrs->strings_off + psrs->str_lens + len + 1 > sizeof(*psrs)) {
        str = "?";
        len = 1;
        if (psrs->str_lens + 2 > sizeof(*psrs))
            return 0;
    }

    int dst_off = psrs->str_lens;
    unsigned char *dst = ((unsigned char *) psrs) + psrs->strings_off + dst_off;
    memcpy(dst, str, len + 1);
    psrs->str_lens += len + 1;
    return dst_off;
}

#define CHECK_FAIL() do { return -__LINE__; } while (0)

int
super_run_status_check(const void *data, size_t size)
{
    if (!data) return -1;
    if (size != sizeof(struct super_run_status)) CHECK_FAIL();
    const struct super_run_status *psrs = (const struct super_run_status *) data;

    if (psrs->signature[0] != 'S' || psrs->signature[1] != '\r'
        || psrs->signature[2] != 's' || psrs->signature[3] != '\x1')
        CHECK_FAIL();
    if (psrs->endianness != 1) CHECK_FAIL();
    if (psrs->version != 1) CHECK_FAIL();
    if (psrs->size != sizeof(*psrs)) CHECK_FAIL();
    if (psrs->strings_off != (unsigned short)(unsigned long)(&((struct super_run_status *) 0)->strings))
        CHECK_FAIL();
    if (psrs->str_lens <= 1) CHECK_FAIL();
    if (psrs->strings_off + psrs->str_lens > sizeof(*psrs)) CHECK_FAIL();

    return 0;
}

void
super_run_status_save(
        struct AgentClient *agent,
        const unsigned char *heartbeat_dir,
        const unsigned char *file_name,
        const struct super_run_status *psrs,
        long long current_time_ms,
        long long *p_last_saved_time_ms,
        long long timeout_ms,
        unsigned char *p_stop_flag,
        unsigned char *p_down_flag,
        unsigned char *p_reboot_flag)
{
    unsigned char in_path[PATH_MAX];
    unsigned char dir_path[PATH_MAX];
    int fd = -1;

    if (p_last_saved_time_ms) {
        if (timeout_ms > 0 && *p_last_saved_time_ms > 0 && *p_last_saved_time_ms + timeout_ms > current_time_ms) {
            return;
        }
    }

    if (agent) {
        agent->ops->put_heartbeat(agent, file_name, psrs, sizeof(*psrs),
                                  p_last_saved_time_ms, p_stop_flag,
                                  p_down_flag,
                                  p_reboot_flag);
        return;
    }

    snprintf(in_path, sizeof(in_path), "%s/in/%s", heartbeat_dir, file_name);
    fd = open(in_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) return;

    const unsigned char *pp = (const unsigned char *) psrs;
    size_t zz = sizeof(*psrs);
    int w = 1;
    while (zz > 0 && (w = write(fd, pp, zz)) > 0) {
        pp += w;
        zz -= w;
    }
    if (w <= 0) {
        close(fd); fd = -1;
        unlink(in_path);
        return;
    }
    if (close(fd) < 0) {
        unlink(in_path);
        return;
    }
    fd = -1;

    snprintf(dir_path, sizeof(dir_path), "%s/dir/%s", heartbeat_dir, file_name);
    if (rename(in_path, dir_path) < 0) {
        unlink(in_path);
    }
    if (p_last_saved_time_ms) {
        *p_last_saved_time_ms = current_time_ms;
    }

    if (p_stop_flag) {
        *p_stop_flag = 0;
        snprintf(dir_path, sizeof(dir_path), "%s/dir/%s@S", heartbeat_dir, file_name);
        if (access(dir_path, F_OK) >= 0) {
            *p_stop_flag = 1;
            unlink(dir_path);
        }
    }
    if (p_down_flag) {
        *p_down_flag = 0;
        snprintf(dir_path, sizeof(dir_path), "%s/dir/%s@D", heartbeat_dir, file_name);
        if (access(dir_path, F_OK) >= 0) {
            *p_down_flag = 1;
            unlink(dir_path);
        }
    }
    if (p_reboot_flag) {
        *p_reboot_flag = 0;
        snprintf(dir_path, sizeof(dir_path), "%s/dir/%s@R", heartbeat_dir, file_name);
        if (access(dir_path, F_OK) >= 0) {
            *p_reboot_flag = 1;
            unlink(dir_path);
        }
    }
}

void
super_run_status_remove(
        struct AgentClient *agent,
        const unsigned char *heartbeat_dir,
        const unsigned char *file_name)
{
    if (agent) {
        agent->ops->delete_heartbeat(agent, file_name);
    } else {
        unsigned char dir_path[PATH_MAX];
        snprintf(dir_path, sizeof(dir_path), "%s/dir/%s", heartbeat_dir, file_name);
        unlink(dir_path);
    }
}

struct super_run_status_vector *
super_run_status_vector_free(
        struct super_run_status_vector *v,
        int free_v_flag)
{
    if (v) {
        for (int i = 0; i < v->u; ++i) {
            xfree(v->v[i]->file);
            xfree(v->v[i]->queue);
            xfree(v->v[i]);
        }
        xfree(v->v);
        memset(v, 0, sizeof(*v));
        if (free_v_flag) {
            xfree(v);
        }
    }
    return NULL;
}

void
super_run_status_vector_add(
        struct super_run_status_vector *v,
        const struct super_run_status *s,
        const unsigned char *queue,
        const unsigned char *file)
{
    if (v->u == v->a) {
        if (!(v->a *= 2)) v->a = 16;
        v->v = xrealloc(v->v, v->a * sizeof(v->v[0]));
    }
    struct super_run_status_vector_item *vi = NULL;
    XCALLOC(vi, 1);
    memcpy(&vi->status, s, sizeof(*s));
    if (file) {
        vi->file = xstrdup(file);
    }
    if (queue) {
        vi->queue = xstrdup(queue);
    }
    v->v[v->u++] = vi;
}

int
super_run_status_read(
        const unsigned char *path,
        struct super_run_status *ps)
{
    int fd = open(path, O_RDONLY, 0);
    if (fd < 0) return -1;
    unsigned char *pp = (unsigned char*) ps;
    size_t zz = sizeof(*ps);
    while (zz) {
        int r = read(fd, pp, zz);
        if (r < 0) {
            close(fd);
            return -1;
        }
        if (!r) {
            close(fd);
            return -1;
        }
        pp += r;
        zz -= r;
    }
    close(fd);
    return 0;
}

void
super_run_status_scan(
        const unsigned char *queue,
        const unsigned char *heartbeat_dir,
        struct super_run_status_vector *v)
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
        snprintf(path, sizeof(path), "%s/%s", dpath, dd->d_name);
        struct stat stb;
        if (stat(path, &stb) < 0) continue;
        if (!S_ISREG(stb.st_mode)) continue;
        if (stb.st_size != sizeof(struct super_run_status)) continue;
        struct super_run_status srs;
        if (super_run_status_read(path, &srs) < 0) continue;
        if (super_run_status_check(&srs, sizeof(srs)) < 0) continue;
        super_run_status_vector_add(v, &srs, queue, dd->d_name);
    }
    closedir(d);
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
