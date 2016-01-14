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
 * NAME:    xexpand2
 * PURPOSE: expand generic expandable array
 * ARGS:    arr    - pointer to expandable array structure
 *          elsize - size of an element of the array
 */
void
xexpand2(arr, elsize)
     genarray_t  *arr;
     size_t       elsize;
{
  if (!arr) return;

  if (elsize <= 0) elsize = sizeof(int);
  if (arr->u < arr->a) return;

  if (!arr->a)
    {
      arr->a = 32;
      arr->v = xcalloc(arr->a, elsize);
      return;
    }

  arr->v = (void*) xrealloc(arr->v, arr->a * elsize * 2);
  memset((char*) arr->v + arr->a * elsize, 0, arr->a * elsize);
  arr->a *= 2;
}
