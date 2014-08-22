/* -*- mode: C -*- */
/* $Id$ */

#ifndef __BUILTIN_IDENTS_H__
#define __BUILTIN_IDENTS_H__

/* Copyright (C) 2003-2014 Alexander Chernov <cher@ejudge.ru > */

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

#include "ejudge/hash.h"

enum
{
  C_BUILTIN_NONE = 0,

  C_BUILTIN_FUNCTION,
  C_BUILTIN_ALLOCA,
  C_BUILTIN_RETVAL,
  C_BUILTIN_FUNC,

  C_BUILTIN_LAST
};

void builtin_initialize(void);
int builtin_lookup(ident_t id);
ident_t builtin_get_ident(int);

#endif /* __BUILTIN_IDENTS_H__ */
