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

#include "builtin_idents.h"

#include "ejudge/hash.h"
#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <string.h>

static const unsigned char * builtin_names[C_BUILTIN_LAST] =
{
  [C_BUILTIN_FUNCTION] = "__FUNCTION__",
  [C_BUILTIN_ALLOCA] = "__builtin_alloca",
  [C_BUILTIN_RETVAL] = "__builtin_retval",
  [C_BUILTIN_FUNC] = "__func__",
};
static ident_t builtin_ids[C_BUILTIN_LAST];
static size_t id_builtins_size;
static int *id_builtins;
static int initialized = 0;

static void
initialize(void)
{
  int i;
  ident_t idmax = 0;

  initialized = 1;
  for (i = 0; i < C_BUILTIN_LAST; i++)
    if (builtin_names[i]) {
      builtin_ids[i] = ident_put(builtin_names[i], strlen(builtin_names[i]));
      if (builtin_ids[i] > idmax) idmax = builtin_ids[i];
    }
  id_builtins = xcalloc(idmax + 1, sizeof(id_builtins[0]));
  memset(id_builtins, -1, (idmax + 1) * sizeof(id_builtins[0]));
  for (i = 0; i < C_BUILTIN_LAST; i++)
    if (builtin_names[i])
      id_builtins[builtin_ids[i]] = i;
  id_builtins_size = idmax + 1;
}

void
builtin_initialize(void)
{
  if (!initialized) initialize();
}

int
builtin_lookup(ident_t id)
{
  if (!initialized) initialize();
  if (id >= id_builtins_size) return -1;
  return id_builtins[id];
}

ident_t
builtin_get_ident(int n)
{
  ASSERT(n > C_BUILTIN_NONE && n < C_BUILTIN_LAST);
  return builtin_ids[n];
}
