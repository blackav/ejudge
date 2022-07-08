/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __TRIE_H__
#define __TRIE_H__

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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct trie_data;

struct trie_data *
trie_create(void);

struct trie_data *
trie_free(struct trie_data *td);

struct trie_data *
trie_compile(
        size_t count,
        unsigned char **strs);

struct trie_data *
trie_compile_f(
        unsigned char *(*index_func)(void *cntx, uint32_t index),
        void *cntx);

int
trie_check(
        const struct trie_data *td,
        const unsigned char *str);

void
trie_dump(
        struct trie_data *trie,
        FILE *fout);

struct trie_data *
trie_create_16(void);

struct trie_data *
trie_free_16(struct trie_data *td);

struct trie_data *
trie_compile_16(
        size_t count,
        unsigned char **strs);

struct trie_data *
trie_compile_f_16(
        unsigned char *(*index_func)(void *cntx, uint32_t index),
        void *cntx);

int
trie_check_16(
        const struct trie_data *td,
        const unsigned char *str);

void
trie_dump_16(
        struct trie_data *trie,
        FILE *fout);

void
trie_generate_c_16(
        struct trie_data *trie,
        const char *varname,
        FILE *fout);

#endif /* __TRIE_H__ */
