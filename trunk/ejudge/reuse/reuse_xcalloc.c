/* -*- mode:c -*- */
/* $Id$ */

/* Copyright (C) 2002-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "reuse/xalloc.h"

void reuse_null_size(void);
void reuse_out_of_mem(void);

/**
 * NAME:    xcalloc
 * PURPOSE: wrapper over calloc function
 * NOTE:    xcalloc never returns NULL
 */
void *
xcalloc(size_t nitems, size_t elsize)
{
  void *ptr;

  if (nitems == 0 || elsize == 0) reuse_null_size();
  ptr = calloc(nitems, elsize);
  if (ptr == NULL) reuse_out_of_mem();
  return ptr;
}

/*
 * Local variables:
 *  compile-command: "make"
 * End:
 */
