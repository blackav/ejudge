/* Copyright (C) 1996-2016 Alexander Chernov <cher@ejudge.ru> */
/* Created: Fri Nov  1 19:01:06 1996 by cher (Alexander Chernov) */

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

/**
 * FILE:    utils/xalloc.c
 * PURPOSE: safe memory allocation routines
 */

#include "ejudge/xalloc.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/**
 * NAME:    out_of_mem
 * PURPOSE: report out of virtual memory condition
 */
void
reuse_out_of_mem(void)
{
  fputs("Failed to allocate more memory!\n", stderr);
  abort();
}

/**
 * NAME:    null_size
 * PURPOSE: report 0 size allocation error
 */
void
reuse_null_size(void)
{
  fputs("Null size allocation requested!\n", stderr);
  abort();
}
