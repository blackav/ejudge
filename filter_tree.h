/* -*- c -*- */
/* $Id$ */

#ifndef __FILTER_TREE_H__
#define __FILTER_TREE_H__

/* Copyright (C) 2002 Alexander Chernov <cher@ispras.ru> */

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
#include <string.h>
#include <time.h>

/* valid tree types */
enum
  {
    FILTER_TYPE_INT = 1,
    FILTER_TYPE_STRING,
    FILTER_TYPE_BOOL,
    FILTER_TYPE_DATE,
    FILTER_TYPE_DUR,
    FILTER_TYPE_SIZE,
    FILTER_TYPE_RESULT,
    FILTER_TYPE_HASH,

    FILTER_TYPE_LAST
  };

struct filter_tree
{
  int kind;
  int type;
  union
  {
    struct filter_tree *t[2];
    int i;
    unsigned char *s;
    int b;
    time_t a;
    time_t u;
    size_t z;
    int r;
    unsigned long h[5];
  } v;
};
struct filter_tree_mem;

struct filter_tree_mem *filter_tree_new(void);
struct filter_tree_mem *filter_tree_delete(struct filter_tree_mem *);

struct filter_tree *filter_tree_new_node(struct filter_tree_mem *,
                                         int, int,
                                         struct filter_tree *,
                                         struct filter_tree *);
struct filter_tree *filter_tree_new_buf(struct filter_tree_mem *,
                                        unsigned char const *,
                                        size_t len);
struct filter_tree *filter_tree_new_string(struct filter_tree_mem *,
                                           unsigned char const *);
struct filter_tree *filter_tree_new_int(struct filter_tree_mem *,
                                        int);
struct filter_tree *filter_tree_new_bool(struct filter_tree_mem *,
                                         int);

void filter_tree_print(struct filter_tree *p, FILE *out,
                       unsigned char const *ind);

int filter_expr_lex(void);
void filter_expr_set_string(unsigned char const *str,
                            struct filter_tree_mem *mem);
int filter_expr_parse(void);
void filter_tree_stats(struct filter_tree_mem *mem, FILE *);
void filter_expr_init_parser(struct filter_tree_mem *mem);

unsigned char const *filter_tree_type_to_str(int type);

int filter_tree_int_str(unsigned char *, size_t, int);
int filter_tree_bool_str(unsigned char *, size_t, int);
int filter_tree_date_str(unsigned char *, size_t, time_t);
int filter_tree_dur_str(unsigned char *, size_t, time_t);
int filter_tree_size_str(unsigned char *, size_t, size_t);
int filter_tree_result_str(unsigned char *, size_t, int);
int filter_tree_hash_str(unsigned char *, size_t, unsigned long *);

#endif /* __FILTER_TREE_H__ */
