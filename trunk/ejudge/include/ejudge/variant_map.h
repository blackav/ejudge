/* -*- c -*- */
/* $Id$ */
#ifndef __VARIANT_MAP_H__
#define __VARIANT_MAP_H__

/* Copyright (C) 2014 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdio.h>
#include <stdlib.h>

struct variant_map_item
{
    unsigned char *login;
    unsigned char *name;
    int user_id;
    int var_num;
    int *variants;

    // variant map version 2
    int real_variant;             /* one for all problems */
    int virtual_variant;          /* the displayed variant */
};

struct variant_map
{
    int *prob_map;
    int prob_map_size;
    int *prob_rev_map;
    int prob_rev_map_size;
    int var_prob_num;
    int vintage;

    size_t user_map_size;
    struct variant_map_item **user_map;

    size_t a, u;
    struct variant_map_item *v;

    unsigned char *header_txt;
    unsigned char *footer_txt;
};

struct serve_state;

void
variant_map_free(struct variant_map *p);
void
variant_map_unparse(
        FILE *f,
        const struct variant_map *vmap,
        int mode); // 0 - in super-serve, 1 - in contests
int
variant_map_save(
        FILE *log_f,
        const struct variant_map *vmap, 
        const unsigned char *path,
        int mode);
struct variant_map *
variant_map_parse(
        FILE *log_f,
        struct serve_state *state,
        const unsigned char *path);
int
variant_map_set_variant(
        struct variant_map *vmap,
        int user_id,
        const unsigned char *user_login,
        int prob_id,
        int variant);

#endif /* __VARIANT_MAP_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
