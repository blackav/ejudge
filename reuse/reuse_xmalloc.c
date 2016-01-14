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

void reuse_null_size(void);
void reuse_out_of_mem(void);

/**
 * NAME:    xmalloc
 * PURPOSE: wrapper over malloc function call
 * NOTE:    xmalloc never returns NULL
 */
void *
xmalloc(size_t size)
{
  void *ptr;

  if (size == 0) reuse_null_size();
  ptr = malloc(size);
  if (ptr == NULL) reuse_out_of_mem();
  return ptr;
}
