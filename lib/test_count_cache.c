/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2022 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/test_count_cache.h"
#include "ejudge/dyntrie.h"
#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>

struct test_count_cache_dir
{
    unsigned char *path;
    long long last_check_us;
    struct timespec mtime;
    int test_count;
};

struct test_count_cache_state
{
    struct test_count_cache_dir **dirs;
    size_t dira, diru;
    struct dyntrie_node *trie;
};

static struct test_count_cache_dir *
test_count_cache_dir_new(const unsigned char *path)
{
    struct test_count_cache_dir *d = NULL;
    XCALLOC(d, 1);
    d->path = xstrdup(path);
    d->test_count = -1;
    return d;
}

struct test_count_cache_state *
test_count_cache_new(void)
{
    struct test_count_cache_state *s = NULL;

    XCALLOC(s, 1);
    s->diru = 1;
    s->dira = 16;
    XCALLOC(s->dirs, s->dira);
    return s;
}

struct test_count_cache_state *
test_count_cache_free(struct test_count_cache_state *s)
{
    if (s) {
        dyntrie_free(&s->trie, NULL, NULL);
        for (int i = 1; i < s->diru; ++i) {
            struct test_count_cache_dir *d = s->dirs[i];
            if (d) {
                free(d->path);
                free(d);
            }
        }
        free(s->dirs);
    }
    return NULL;
}

static struct test_count_cache_state *global_state = NULL;

static struct test_count_cache_state *
get_global_state(void)
{
    if (!global_state) {
        global_state = test_count_cache_new();
    }
    return global_state;
}

static void
scan_dir(struct test_count_cache_dir *dir, const unsigned char *pattern)
{
    if (!pattern || !*pattern) {
        err("scan_dir: pattern is empty");
        dir->test_count = -1;
        return;
    }

    int test_num = 0;
    while (1) {
        ++test_num;
        unsigned char name[PATH_MAX];
        unsigned char path[PATH_MAX];
        if (snprintf(name, sizeof(name), pattern, test_num) >= sizeof(name)) {
            err("scan_dir: name is too long for pattern '%s'", pattern);
            break;
        }
        if (snprintf(path, sizeof(path), "%s/%s", dir->path, name) >= sizeof(path)) {
            err("scan_dir: path is too long");
            break;
        }
        if (access(path, R_OK) < 0) {
            break;
        }
    }
    dir->test_count = test_num - 1;
}

static void
update_dir_info(
        struct test_count_cache_dir *dir,
        const unsigned char *pattern,
        long long us)
{
    dir->last_check_us = us;
    struct stat stb;
    if (stat(dir->path, &stb) < 0) {
        err("update_dir_info: '%s' failed: %s", dir->path, os_ErrorMsg());
        dir->test_count = -1;
        return;
    }
    if (!S_ISDIR(stb.st_mode)) {
        err("update_dir_info: '%s' is not a directory", dir->path);
        dir->test_count = -1;
        return;
    }
    if (stb.st_mtim.tv_sec != dir->mtime.tv_sec
        || stb.st_mtim.tv_nsec != dir->mtime.tv_nsec) {
        scan_dir(dir, pattern);
        dir->mtime = stb.st_mtim;
    }
}

int
test_count_cache_get(
        struct test_count_cache_state *state,
        const unsigned char *path,
        const unsigned char *pattern)
{
    if (!state) {
        state = get_global_state();
    }
    void *vidx = dyntrie_get(&state->trie, path);
    if (!vidx) {
        if (state->diru == state->dira) {
            if (!(state->dira *= 2)) state->dira = 16;
            XREALLOC(state->dirs, state->dira);
        }
        int idx = state->diru++;
        state->dirs[idx] = test_count_cache_dir_new(path);
        vidx = (void *) (intptr_t) idx;
        dyntrie_insert(&state->trie, path, vidx, 0, NULL);
    }
    int idx = (int)(intptr_t) vidx;
    struct test_count_cache_dir *dir = state->dirs[idx];

    struct timeval tv;
    gettimeofday(&tv, NULL);
    long long us = tv.tv_sec * 1000000LL + tv.tv_usec;

    if (!dir->last_check_us || dir->last_check_us + 5000000 < us) {
        dir->last_check_us = us;
        update_dir_info(dir, pattern, us);
    }

    return dir->test_count;
}
