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

void reuse_out_of_mem(void);

/**
 * NAME:    xmemdup
 * PURPOSE: returns a copy of the string in the heap
 * ARGS:    str  - string to copy (might not be \0 terminated)
 *          size - string length
 * RETURN:  copy of the string str with \0 terminator added
 */
char *
xmemdup(char const *str, size_t size)
{
  char *ptr;

  if (str == NULL) str = "";
  ptr = xmalloc (size + 1);
  if (ptr == NULL) reuse_out_of_mem();
  memcpy (ptr, str, size);
  ptr[size] = 0;
  return ptr;
}
