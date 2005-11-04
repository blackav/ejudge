/* -*- c -*- */
/* $Id$ */

#ifndef __FILTER_TREE_H__
#define __FILTER_TREE_H__

/* Copyright (C) 2002,2005 Alexander Chernov <cher@ispras.ru> */

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

#include "ej_types.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* valid tree types */
enum
  {
    FILTER_TYPE_INT = 1,
    FILTER_TYPE_STRING,
    FILTER_TYPE_BOOL,
    FILTER_TYPE_TIME,
    FILTER_TYPE_DUR,
    FILTER_TYPE_SIZE,
    FILTER_TYPE_RESULT,
    FILTER_TYPE_HASH,
    FILTER_TYPE_IP,

    FILTER_TYPE_LAST
  };

/* error codes */
enum
  {
    FILTER_ERR_OK = 0,
    FILTER_ERR_ERROR = 1,       /* unknown error */
    FILTER_ERR_INT_OVF,         /* integer overflow */
    FILTER_ERR_DIV0,            /* division by zero */
    FILTER_ERR_INT_CVT,         /* string->int conversion failed */
    FILTER_ERR_BOOL_CVT,        /* string->bool conversion failed */
    FILTER_ERR_DUR_CVT,         /* string->dur_t conversion failed */
    FILTER_ERR_TIME_CVT,        /* string->time_t conversion failed */
    FILTER_ERR_RESULT_CVT,      /* string->result_t conversion failed */
    FILTER_ERR_HASH_CVT,        /* string->hash_t conversion failed */
    FILTER_ERR_IP_CVT,          /* string->ip_t conversion failed */
    FILTER_ERR_RANGE,           /* int->result_t conversion failed */
    FILTER_ERR_INV_ARG,         /* invalid argument for operation */
    FILTER_ERR_INV_TYPES,       /* invalid argument types */

    FILTER_ERR_LAST
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
    ruint32_t h[5];
    ej_ip_t p;
  } v;
};
struct filter_tree_mem;

struct filter_tree_mem *filter_tree_new(void);
struct filter_tree_mem *filter_tree_delete(struct filter_tree_mem *);
void filter_tree_clear(struct filter_tree_mem *);

void *filter_tree_alloc(struct filter_tree_mem *, size_t);

struct filter_tree *filter_tree_new_node(struct filter_tree_mem *,
                                         int, int,
                                         struct filter_tree *,
                                         struct filter_tree *);
struct filter_tree *filter_tree_new_buf(struct filter_tree_mem *,
                                        unsigned char const *,
                                        size_t len);
struct filter_tree *filter_tree_new_string(struct filter_tree_mem *,
                                           unsigned char const *);
struct filter_tree *filter_tree_new_string2(struct filter_tree_mem *,
                                            unsigned char *);
struct filter_tree *filter_tree_new_int(struct filter_tree_mem *,
                                        int);
struct filter_tree *filter_tree_new_bool(struct filter_tree_mem *,
                                         int);
struct filter_tree *filter_tree_new_dur(struct filter_tree_mem *,
                                        time_t);
struct filter_tree *filter_tree_new_time(struct filter_tree_mem *,
                                         time_t);
struct filter_tree *filter_tree_new_size(struct filter_tree_mem *,
                                         size_t);
struct filter_tree *filter_tree_new_result(struct filter_tree_mem *,
                                           int);
struct filter_tree *filter_tree_new_hash(struct filter_tree_mem *,
                                         ruint32_t *);
struct filter_tree *filter_tree_new_ip(struct filter_tree_mem *,
                                       ej_ip_t);
struct filter_tree *filter_tree_dup(struct filter_tree_mem *,
                                    struct filter_tree*);

void filter_tree_print(struct filter_tree *p, FILE *out,
                       unsigned char const *ind);

int filter_expr_lex(void);
void filter_expr_set_string(unsigned char const *str,
                            struct filter_tree_mem *mem,
                            void (*errfunc)(unsigned char const *, ...));
int filter_expr_parse(void);
void filter_tree_stats(struct filter_tree_mem *mem, FILE *);
void filter_expr_init_parser(struct filter_tree_mem *mem,
                             void (*errfunc)(unsigned char const *, ...));

unsigned char const *filter_tree_type_to_str(int type);
unsigned char const *filter_tree_kind_to_str(int kind);

int filter_tree_int_str(unsigned char *, size_t, int);
int filter_tree_bool_str(unsigned char *, size_t, int);
int filter_tree_time_str(unsigned char *, size_t, time_t);
int filter_tree_dur_str(unsigned char *, size_t, time_t);
int filter_tree_size_str(unsigned char *, size_t, size_t);
int filter_tree_result_str(unsigned char *, size_t, int);
int filter_tree_hash_str(unsigned char *, size_t, ruint32_t *);
int filter_tree_ip_str(unsigned char *, size_t, ej_ip_t);

int filter_tree_is_value_node(struct filter_tree *p);

int filter_tree_eval_node(struct filter_tree_mem *,
                          int kind, struct filter_tree *res,
                          struct filter_tree *p1, struct filter_tree *p2);

unsigned char const *filter_strerror(int n);

extern int filter_expr_nerrs;
extern struct filter_tree *filter_expr_lval;

#endif /* __FILTER_TREE_H__ */
