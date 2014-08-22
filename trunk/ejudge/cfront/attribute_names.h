/* -*- mode: C -*- */
/* $Id$ */

#ifndef __ATTRIBUTE_NAMES_H__
#define __ATTRIBUTE_NAMES_H__

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
  C_ATTR_NONE = 0,
  C_ATTR_NORETURN,
  C_ATTR_PURE,
  C_ATTR_CONST,
  C_ATTR_NOTHROW,
  C_ATTR_STRING_PRE,
  C_ATTR_BUFFER_PRE,
  C_ATTR_MALLOC,
  C_ATTR_ALLOCA,
  C_ATTR_FORMAT,

  C_ATTR_LAST
};

int attribute_lookup(ident_t id);

#endif /* __ATTRIBUTE_NAMES_H__ */
