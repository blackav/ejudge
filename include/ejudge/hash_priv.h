/* -*- mode:c -*- */
/* $Id$ */

#ifndef __REUSE_HASHP_H__
#define __REUSE_HASHP_H__

/* Copyright (C) 2002-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/hash.h"

#define INIT_SIZE   301         /* initial hash table size */
#define HASH_STEP   13          /* increment for secondary hash function */

/* hash table entry */
typedef struct hashentry_t
{
  hash_t     hash;     /* Full (not truncated code of the string) *
                        * 0 stands for empty slot */
  ident_t    ident;    /* Corresponding ident */
  short      len;      /* String length */
  char       *string;  /* Identifier string */
} hashentry_t;

typedef struct hashstate_t
{
  int          initialized;     /* whether the module is initialized */
  int          *map;       /* ident number to hash number map */
  int          total_idents; /* total number of idents */
  hashentry_t *table;           /* hash table */
  int          table_size;      /* Current hash table size */
  int          rehash_size; /* Size when we will rehash the table */

  int stat_rehash_num;          /* Number of rehashing */
  int stat_lookups_num;         /* Number of table lookups */
  int stat_success_num;       /* Number of successive lookups */
  int stat_cycles_num;          /* Search length for lookup */
} hashstate_t;

#endif /* __REUSE_HASHP_H__ */
