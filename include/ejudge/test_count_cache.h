/* -*- mode: c; c-basic-offset: 4 -*- */

#ifndef __TEST_COUNT_CACHE_H__
#define __TEST_COUNT_CACHE_H__

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

struct test_count_cache_state;

int
test_count_cache_get(
        struct test_count_cache_state *state,
        const unsigned char *path,
        const unsigned char *pattern);

#endif /* __TEST_COUNT_CACHE_H__ */
