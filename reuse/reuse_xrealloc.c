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
 * NAME:    xrealloc
 * PURPOSE: wrapper over realloc function
 * NOTE:    if ptr == NULL,  realloc = malloc
 *          if size == NULL, realloc = free
 *          if ptr == NULL && size == NULL, ?
 */
void *
xrealloc(void *ptr, size_t size)
{
  if (ptr == NULL && size == 0) reuse_null_size();
  ptr = realloc(ptr,size);
  if (ptr == NULL) reuse_out_of_mem();
  return ptr;
}
