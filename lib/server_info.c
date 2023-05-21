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
#include "ejudge/server_info.h"
#include "ejudge/xalloc.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

struct process_info
{
    char state;
    int ppid;
    int pgrp;
    int session;
    int tty_nr;
    int tpgid;
    unsigned flags;
    unsigned long minflt;
    unsigned long cminflt;
    unsigned long majflt;
    unsigned long cmajflt;
    unsigned long utime;
    unsigned long stime;
    unsigned long cutime;
    unsigned long cstime;
    long priority;
    long nice;
    long num_threads;
    long itrealvalue;
    long long starttime;
    unsigned long vsize;
    long rss;
    unsigned long rsslim;
    unsigned long startcode;
    unsigned long endcode;
    unsigned long startstack;
    unsigned long kstkesp;
    unsigned long kstkeip;
    unsigned long signal;
    unsigned long blocked;
    unsigned long sigignore;
    unsigned long sigcatch;
    unsigned long wchan;
    unsigned long nswap;
    unsigned long cnswap;
    int exit_signal;
    int processor;
};

[[gnu::unused]]
static int
parse_proc_pid_stat(int pid, struct process_info *info)
{
    char path[PATH_MAX];
    FILE *f = NULL;
    char buf[8192];
    int blen;
    char *p = NULL;
    int r = 0;

    memset(info, 0, sizeof(*info));
    if (snprintf(path, sizeof(path), "/proc/%d/stat", pid) >= (int) sizeof(path)) abort();
    f = fopen(path, "r");
    if (!f) {
        goto fail;
    }
    if (!fgets(buf, sizeof(buf), f)) goto fail;
    blen = strlen(buf);
    if (blen + 1 == sizeof(buf)) goto fail;
    fclose(f); f = NULL;

    p = strrchr(buf, ')');
    if (!p) goto fail;
    ++p;

    r = sscanf(p, " %c%d%d%d%d%d%u%lu%lu%lu%lu%lu%lu%lu%lu%ld%ld%ld%ld%llu%lu%ld%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%d%d",
               &info->state,
               &info->ppid,
               &info->pgrp,
               &info->session,
               &info->tty_nr,
               &info->tpgid,
               &info->flags,
               &info->minflt,
               &info->cminflt,
               &info->majflt,
               &info->cmajflt,
               &info->utime,
               &info->stime,
               &info->cutime,
               &info->cstime,
               &info->priority,
               &info->nice,
               &info->num_threads,
               &info->itrealvalue,
               &info->starttime,
               &info->vsize,
               &info->rss,
               &info->rsslim,
               &info->startcode,
               &info->endcode,
               &info->startstack,
               &info->kstkesp,
               &info->kstkeip,
               &info->signal,
               &info->blocked,
               &info->sigignore,
               &info->sigcatch,
               &info->wchan,
               &info->nswap,
               &info->cnswap,
               &info->exit_signal,
               &info->processor);
    if (r != 37) goto fail;

    return 0;

fail:
    if (f) fclose(f);
    return -1;
}

struct process_status
{
    long long vm_size_kb;
    long long vm_rss_kb;
};

static int
parse_proc_pid_status(int pid, struct process_status *ps)
{
    char path[PATH_MAX];
    FILE *f = NULL;
    char buf[1024];

    if (snprintf(path, sizeof(path), "/proc/%d/status", pid) >= (int) sizeof(path)) {
        return -1;
    }
    f = fopen(path, "r");
    if (!f) {
        return -1;
    }
    while (fgets(buf, sizeof(buf), f)) {
        int len = strlen(buf);
        if (len >= (int) sizeof(buf) - 1) continue;
        while (len > 0 && isspace((unsigned char) buf[len - 1])) --len;
        buf[len] = 0;
        if (!strncmp(buf, "VmSize:", 7)) {
            ps->vm_size_kb = strtol(buf + 7, NULL, 10);
        } else if (!strncmp(buf, "VmRSS:", 6)) {
            ps->vm_rss_kb = strtol(buf + 6, NULL, 10);
        }
    }
    fclose(f);
    return 0;
}

struct server_info_process *
server_info_free_processes(struct server_info_process *p)
{
    if (p) {
        for (int i = 0; p[i].name; ++i) {
            xfree(p[i].name);
        }
        xfree(p);
    }
    return NULL;
}

const unsigned char * const tool_names[] =
{
    "ej-agent", "ej-compile", "ej-contests", "ej-jobs",
    "ej-super-run", "ej-super-server", "ej-users", NULL,
};

static int
read_file(const char *path, char **p_buf, size_t *p_size)
{
    int fd = -1;
    size_t size = 0;
    size_t reserved = 8;
    char *buf = malloc(reserved);
    char b[65536];
    if (!buf) {
        goto fail;
    }
    buf[0] = 0;
    if ((fd = open(path, O_RDONLY, 0)) < 0) {
        goto fail;
    }
    while (1) {
        ssize_t r = read(fd, b, sizeof(b));
        if (r < 0) {
            goto fail;
        }
        if (!r) {
            if (size == reserved) {
                char *newbuf = realloc(buf, reserved + 1);
                if (!newbuf) {
                    goto fail;
                }
                ++reserved;
            }
            buf[size] = 0;
            break;
        }
        if (size + r + 1 >= reserved) {
            size_t newr = reserved * 2;
            while (size + r + 1 >= newr) {
                newr *= 2;
            }
            char *newb = realloc(buf, newr);
            if (!newb) {
                goto fail;
            }
            reserved = newr;
            buf = newb;
        }
        memcpy(buf + size, b, r);
        size += r;
    }
    close(fd);
    *p_buf = buf;
    *p_size = size;
    return 0;

fail:;
    int ret = -errno;
    free(buf);
    if (fd >= 0) close(fd);
    return ret;
}

struct server_info_process *
server_info_get_processes(void)
{
    struct server_info_process *res = NULL;
    int tool_count = sizeof(tool_names) / sizeof(tool_names[0]);
    DIR *d = NULL;
    char *file_txt = NULL;
    size_t file_size = 0;
    long clock_ticks = sysconf(_SC_CLK_TCK);

    XCALLOC(res, tool_count);
    for (int i = 0; i < tool_count; ++i) {
        if (tool_names[i]) {
            res[i].name = xstrdup(tool_names[i]);
        }
    }

    d = opendir("/proc");

    struct dirent *dd;
    while ((dd = readdir(d))) {
        char *eptr = NULL;
        errno = 0;
        long v = strtol(dd->d_name, &eptr, 10);
        if (errno || *eptr || eptr == dd->d_name || v <= 0 || (int) v != v)
            continue;
        int pid = v;

        char path[PATH_MAX];
        __attribute__((unused)) int _;
        _ = snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

        free(file_txt);
        int r = read_file(path, &file_txt, &file_size);
        if (r < 0) {
            continue;
        }
        if (!file_size) {
            continue;
        }
        char *prc_name = strrchr(file_txt, '/');
        if (prc_name) {
            ++prc_name;
        } else {
            prc_name = file_txt;
        }

        for (int i = 0; res[i].name; ++i) {
            if (!strcmp(res[i].name, prc_name)) {
                ++res[i].count;

                struct process_info info = {};
                if (parse_proc_pid_stat(pid, &info) >= 0) {
                    long long cur_cpu_time = (long long) info.utime + (long long) info.stime;
                    res[i].cpu_time += (double) cur_cpu_time / clock_ticks;
                }

                struct process_status ps = {};
                if (parse_proc_pid_status(pid, &ps) >= 0) {
                    res[i].vm_size += ps.vm_size_kb;
                    res[i].vm_rss += ps.vm_rss_kb;
                }
            }
        }
    }
    closedir(d); d = NULL;
    free(file_txt);
    return res;
}
