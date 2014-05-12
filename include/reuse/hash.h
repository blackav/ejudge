/* $Id$ */

#ifndef __REUSE_HASH_H__
#define __REUSE_HASH_H__

/* Copyright (C) 1996-2014 Alexander Chernov <cher@ejudge.ru> */
/* Created: Fri Nov  1 18:44:54 1996 by cher (Alexander Chernov) */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

typedef unsigned long ident_t;
typedef unsigned int hash_t;

void     ident_init(void);
void     ident_reinit(void);
void     ident_close(void);
void     ident_statistics(FILE *f);
void     ident_dump_table(FILE *f);
ident_t  ident_put(char const *, int);
char    *ident_get(ident_t);
char    *ident_dup(ident_t);
hash_t   ident_hash(char const *, int);

enum { ident_empty = 0 };

ident_t ident_read_from_file(FILE *);
ident_t ident_get_from_file(FILE *);

/* For AST tree writers */
//#define writeident_t(i)       fsWriteStr(ident_get(i),yyf);
//#define readident_t(i)        i = ident_read_from_file(yyf);
//#define putident_t(i)         fsPutStr(ident_get(i), yyf);
//#define getident_t(i)         i = ident_get_from_file(yyf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REUSE_HASH_H__ */
