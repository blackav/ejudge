/* -*- mode:c -*- */

/* Copyright (C) 2002-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/xalloc.h"

#include <string.h>

/**
 * NAME:    xexpand
 * PURPOSE: expand expandable array of strings
 * ARGS:    arr - pointer to expandable array structure
 */
void
xexpand(strarray_t *arr)
{
  if (arr->u < arr->a) return;

  if (!arr->a)
    {
      arr->a = 32;
      arr->v = (char**) xcalloc(arr->a, sizeof(char **));
      return;
    }

  arr->v = (char**) xrealloc(arr->v, arr->a * sizeof(char**) * 2);
  memset(arr->v + arr->a, 0, arr->a * sizeof(char**));
  arr->a *= 2;
}
