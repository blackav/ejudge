/* -*- mode:c -*- */
/* $Id$ */

/* Copyright (C) 2002-2011 Alexander Chernov <cher@ejudge.ru> */

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

#include "reuse_xalloc.h"

#include <string.h>

void reuse_out_of_mem(void);

/**
 * NAME:    xstrdup
 * PURPOSE: wrapper over strdup function
 * NOTE:    strdup(NULL) returns ""
 */
char *
xstrdup(char const*str)
{
  char *ptr;

  if (str == NULL) str = "";
  ptr = strdup(str);
  if (ptr == NULL) reuse_out_of_mem();
  return ptr;
}

/*
 * Local variables:
 *  compile-command: "make"
 * End:
 */
