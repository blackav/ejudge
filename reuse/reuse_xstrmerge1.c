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
 * NAME:    xstrmerge1
 * PURPOSE: concatenate two strings
 * ARGS:    str1 - string 1
 *          str2 - string 2
 * RETURN:  concatenation of two strings
 * NOTE:    str1 - freed after concatenation
 *          str2 - not freed
 */
  char *
xstrmerge1(char *str1, char const *str2)
{
  char *res;

  if (str1 == NULL && str2 == NULL)
    return NULL;

  if (str1 == NULL)
    return xstrdup(str2);

  if (str2 == NULL)
    return str1;

  res = (char*) xmalloc(strlen(str1) + strlen(str2) + 1);
  strcpy(res, str1);
  strcat(res, str2);
  xfree(str1);
  return res;
}
