/* -*- mode: C -*- */
/* $Id$ */

#ifndef __SEMA_FUNC_H__
#define __SEMA_FUNC_H__

/* Copyright (C) 2001-2014 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include "tree.h"
#include "sema_data.h"

int sema_typeinfo_to_index(typeinfo_t);
typeinfo_t sema_index_to_typeinfo(int);

void sema_analyze(tree_t tree);

ident_t     sema_get_ident(tree_t node, pos_t **);
semainfo_t *sema_get_sema_ptr(tree_t node);
typeinfo_t  sema_get_value_type(c_value_t *);
typeinfo_t  sema_get_expr_type(tree_t node);

int sema_get_expr_opcode(tree_t, pos_t **, char const **);

int sema_is_void_type(typeinfo_t t);
int sema_is_void_pointer(typeinfo_t t);
int sema_is_character_type(typeinfo_t t);
int sema_is_va_list_type(typeinfo_t);
int sema_is_void_array_type(typeinfo_t t);
int sema_is_nop_typecast(typeinfo_t, typeinfo_t);
int sema_is_varsize_type(typeinfo_t);

int sema_is_postfix_unop(tree_t, int *);

void  print_typeinfo(typeinfo_t, FILE *, char *, int);
char *sprint_typeinfo(typeinfo_t, char *, int, char *);
void  print_scope(struct sema_scope *, FILE *);

size_t sema_get_base_type_align(int);
size_t sema_get_type_align(typeinfo_t);
size_t sema_to_next_align(size_t, size_t);

#define SEMA_NO_SIZE ((unsigned long) -1)
unsigned long sema_get_type_size(typeinfo_t);

#endif /* __SEMA_FUNC_H__ */
