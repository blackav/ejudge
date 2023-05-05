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
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

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

[[gnu::unused]]
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

struct server_info_process *
server_info_get_processes(void)
{
    struct server_info_process *res = NULL;
    int tool_count = sizeof(tool_names) / sizeof(tool_names[0]);
    DIR *d = NULL;

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

        /*

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        auto cnt = read_file(path);
        if (!cnt) continue;

        auto ind = cnt->find('\0');
        auto cmd = (ind == std::string::npos)?*cnt:cnt->substr(0, ind);
        if (cmd.empty()) continue;
        ind = cmd.rfind('/');
        if (ind != std::string::npos) cmd.erase(0, ind + 1);

        auto it = counters.find(cmd);
        if (it != counters.end()) {
            ++it->second;
            struct process_info info = {};
            if (parse_proc_pid_stat(pid, &info) >= 0) {
                long long cur_cpu_time = (long long) info.utime + (long long) info.stime;
                cpu_times[cmd] += (double) cur_cpu_time / clock_ticks;;
            }
            struct process_status ps = {};
            if (parse_proc_pid_status(pid, &ps) >= 0) {
                vm_sizes[cmd] += ps.vm_size_kb;
                vm_rss[cmd] += ps.vm_rss_kb;
            }
        }
     */
    }
    closedir(d); d = NULL;
    return res;

fail:;
    if (d) closedir(d);
    server_info_free_processes(res);
    return NULL;
}


/*
void scan_proc(void)
{
    DIR *d = opendir("/proc");
    struct dirent *dd;
    std::map<std::string, int> counters {
        { "ej-compile", 0 },
        { "ej-contests", 0 },
        { "ej-jobs", 0 },
        { "ej-super-run", 0 },
        { "ej-super-server", 0 },
        { "ej-users", 0 },
        { "ej-agent", 0 },
    };
    static std::map<std::string, std::string> metrics_names {
        { "ej-compile", "ej_compile" },
        { "ej-contests", "ej_contests" },
        { "ej-jobs", "ej_jobs" },
        { "ej-super-run", "ej_super_run" },
        { "ej-super-server", "ej_super_server" },
        { "ej-users", "ej_users" },
        { "ej-agent", "ej_agent" },
    };
    std::map<std::string, double> cpu_times;
    std::map<std::string, long long> vm_sizes;
    std::map<std::string, long long> vm_rss;

    while ((dd = readdir(d))) {
        char *eptr = NULL;
        errno = 0;
        long v = strtol(dd->d_name, &eptr, 10);
        if (errno || *eptr || eptr == dd->d_name || v <= 0 || (int) v != v)
            continue;
        int pid = v;

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        auto cnt = read_file(path);
        if (!cnt) continue;

        auto ind = cnt->find('\0');
        auto cmd = (ind == std::string::npos)?*cnt:cnt->substr(0, ind);
        if (cmd.empty()) continue;
        ind = cmd.rfind('/');
        if (ind != std::string::npos) cmd.erase(0, ind + 1);

        auto it = counters.find(cmd);
        if (it != counters.end()) {
            ++it->second;
            struct process_info info = {};
            if (parse_proc_pid_stat(pid, &info) >= 0) {
                long long cur_cpu_time = (long long) info.utime + (long long) info.stime;
                cpu_times[cmd] += (double) cur_cpu_time / clock_ticks;;
            }
            struct process_status ps = {};
            if (parse_proc_pid_status(pid, &ps) >= 0) {
                vm_sizes[cmd] += ps.vm_size_kb;
                vm_rss[cmd] += ps.vm_rss_kb;
            }
        }
    }

    for (const auto &p : counters) {
        pts("%s_total %d", metrics_names[p.first].c_str(), p.second);
    }
    for (const auto &p : cpu_times) {
        pts("%s_cpu_seconds %f", metrics_names[p.first].c_str(), p.second);
    }
    for (const auto &p : vm_sizes) {
        pts("%s_vm_size_kib %lld", metrics_names[p.first].c_str(), p.second);
    }
    for (const auto &p : vm_rss) {
        pts("%s_vm_rss_kib %lld", metrics_names[p.first].c_str(), p.second);
    }

    closedir(d);
}
 */
