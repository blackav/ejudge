/* -*- mode: C -*- */

/* Copyright (C) 2003-2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "attribute_names.h"

#include "ejudge/hash.h"
#include "ejudge/xalloc.h"

#include <string.h>

static const unsigned char * attr_names[C_ATTR_LAST] =
{
  [C_ATTR_NORETURN] = "noreturn",
  [C_ATTR_PURE] = "pure",
  [C_ATTR_CONST] = "const",
  [C_ATTR_NOTHROW] = "nothrow",
  [C_ATTR_STRING_PRE] = "string_pre",
  [C_ATTR_BUFFER_PRE] = "buffer_pre",
  [C_ATTR_MALLOC] = "malloc",
  [C_ATTR_ALLOCA] = "alloca",
  [C_ATTR_FORMAT] = "format",
};
static ident_t attr_ids[C_ATTR_LAST];
static size_t id_attrs_size;
static int *id_attrs;
static int initialized = 0;

static void
initialize(void)
{
  int i;
  ident_t idmax = 0;

  initialized = 1;
  for (i = 0; i < C_ATTR_LAST; i++)
    if (attr_names[i]) {
      attr_ids[i] = ident_put(attr_names[i], strlen(attr_names[i]));
      if (attr_ids[i] > idmax) idmax = attr_ids[i];
    }
  id_attrs = xcalloc(idmax + 1, sizeof(id_attrs[0]));
  memset(id_attrs, -1, (idmax + 1) * sizeof(id_attrs[0]));
  for (i = 0; i < C_ATTR_LAST; i++)
    if (attr_names[i])
      id_attrs[attr_ids[i]] = i;
  id_attrs_size = idmax + 1;
}

int attribute_lookup(ident_t id)
{
  if (!initialized) initialize();
  if (id >= id_attrs_size) return -1;
  return id_attrs[id];
}

