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

#include <sys/types.h>
#include <sys/time.h>

struct test_count_cache_dir
{
    unsigned char *dir;
    long long last_check_us;
    struct timespec mtime;
};

struct test_count_cache_state
{
    struct test_count_cache_dir **dirs;
    size_t dira, diru;
    struct dyntrie_node *trie;
};

int
test_count_cache_get(
        struct test_count_cache_state *state,
        const unsigned char *path,
        const unsigned char *pattern)
{
    return -1;
}
