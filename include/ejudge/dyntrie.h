/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __DYNTRIE_H__
#define __DYNTRIE_H__

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

#include <stdlib.h>
#include <stdint.h>

struct dyntrie_node;

struct dyntrie_item
{
    union
    {
        unsigned char *ptr;
        unsigned char str[sizeof(unsigned char*)];
    } k;
    union
    {
        struct dyntrie_node *child;
        void *value;
    } t;
    uint32_t key_length;
    unsigned char is_leaf;
};

struct dyntrie_node
{
    struct dyntrie_item *children;
    uint32_t reserved;
    uint32_t size;
};

int
dyntrie_insert(
        struct dyntrie_node **root,
        const unsigned char *key,
        void *value,
        int allow_replace,
        void **old_value);

int
dyntrie_update(
        struct dyntrie_node **root,
        const unsigned char *key,
        void *value,
        void **old_value);

void *
dyntrie_get(
        struct dyntrie_node **root,
        const unsigned char *key);

int
dyntrie_remove(
        struct dyntrie_node **root,
        const unsigned char *key,
        void **old_value);

void
dyntrie_free(
        struct dyntrie_node **root,
        void (*value_free_func)(void *cntx, void *value),
        void *cntx);

int
dyntrie_equal(
        const struct dyntrie_node *root1,
        const struct dyntrie_node *root2);

#endif /* __DYNTRIE_H__ */
