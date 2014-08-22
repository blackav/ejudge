/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "typedef.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <stdlib.h>
#include <string.h>

typedef struct s_myset
{
  unsigned int  *bits;
  size_t         size;
} myset_t;

struct t_scope
{
  myset_t types;
  myset_t regs;
};

static struct t_scope *scope_p = 0;
static size_t scope_a = 0;
static size_t scope_u = 0;

/* whether an ident ever been typedef'ed */
static myset_t t_set;

static void
myset_add(unsigned bit, myset_t *pset)
{
  if (bit >= pset->size) {
    size_t new_size = pset->size;
    unsigned *new_bits = 0;

    if (!new_size) new_size = 1024;
    while (bit >= new_size)
      new_size *= 2;
    new_bits = (unsigned*) xcalloc(new_size >> 3, 1);
    if (pset->bits > 0) memcpy(new_bits, pset->bits, pset->size >> 3);
    xfree(pset->bits);
    pset->size = new_size;
    pset->bits = new_bits;
  }
  pset->bits[bit >> 5] |= (0x80000000U) >> (bit & 31);
}

static inline int
myset_check(unsigned bit, myset_t *pset)
{
  if (bit >= pset->size) return 0;
  return (pset->bits[bit >> 5] << (bit & 31));
}

static void
myset_free(myset_t *pset)
{
  pset->size = 0;
  xfree(pset->bits);
  pset->bits = 0;
}

void
typedef_new_scope(void)
{
  if (scope_u >= scope_a) {
    if (!scope_a) scope_a = 64;
    scope_a *= 2;
    scope_p = (struct t_scope*) xrealloc(scope_p, sizeof(scope_p[0])*scope_a);
  }
  memset(&scope_p[scope_u], 0, sizeof(scope_p[0]));
  scope_u++;
}

void
typedef_drop_scope(void)
{
  ASSERT(scope_u > 0);
  scope_u--;
  myset_free(&scope_p[scope_u].types);
  myset_free(&scope_p[scope_u].regs);
}

void
typedef_register_typedef(ident_t id)
{
  ASSERT(scope_u > 0);

  myset_add(id, &t_set);
  myset_add(id, &scope_p[scope_u - 1].types);
}

void
typedef_register_regular(ident_t id)
{
  ASSERT(scope_u > 0);

  myset_add(id, &scope_p[scope_u - 1].regs);
}

int
typedef_is_typedef(ident_t id)
{
  int i;

  if (myset_check(id, &t_set) >= 0) return 0;
  for (i = scope_u - 1; i >= 0; i--) {
    if (myset_check(id, &scope_p[i].regs) < 0) return 0;
    if (myset_check(id, &scope_p[i].types) < 0) return 1;
  }
  return 0;
}

void
typedef_free(void)
{
  while (scope_u > 0) {
    typedef_drop_scope();
  }
  myset_free(&t_set);
  xfree(scope_p);
  scope_u = scope_a = 0;
  scope_p = 0;
}
