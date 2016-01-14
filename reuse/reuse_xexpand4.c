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
 * NAME:    xexpand4
 * PURPOSE: unconditionally expand the array
 * ARGS:    arr     - array to expand
 *          elsize  - element size
 *          newsize - new size of the array
 */
void
xexpand4(arr, elsize, newsize)
     genarray_t *arr;
     size_t      elsize;
     int         newsize;
{
  int newsz;

  if (!arr) return;
  if (newsize <= arr->a) return;

  if (elsize <= 0) elsize = sizeof(int);
  newsz = arr->a;
  if (!newsz) newsz = 32;
  while (newsz < newsize)
    newsz *= 2;

  arr->v = (void*) xrealloc(arr->v, newsz * elsize);
  memset((char*) arr->v + arr->a * elsize, 0, (newsz - arr->a) * elsize);
  arr->a = newsz;
}
