/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2014 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "pos.h"

#include "ejudge/xalloc.h"

#include <string.h>

static int initialized = 0;

static strarray_t filenames;

static void
initialize(void)
{
  if (initialized) return;
  initialized = 1;
  xexpand(&filenames);
  filenames.v[0] = xstrdup("");
  filenames.u = 1;
}

static int
put_to_filenames(const unsigned char *str)
{
  int i;

  if (!str) return 0;
  for (i = 1; i < filenames.u; i++)
    if (!strcmp(filenames.v[i], str))
      break;
  if (i < filenames.u)
    return i;
  xexpand(&filenames);
  filenames.v[filenames.u] = xstrdup(str);
  return filenames.u++;
}

void
pos_set(pos_t *ppos, const unsigned char *filename, int line, int column)
{
  if (!initialized) initialize();
  memset(ppos, 0, sizeof(*ppos));
  ppos->file = put_to_filenames(filename);
  ppos->line = line;
  ppos->column = column;
}

unsigned char *
pos_get_file(const pos_t *ppos)
{
  if (!initialized) initialize();
  return filenames.v[ppos->file];
}

int
pos_is_valid_file(int i)
{
  if (!initialized) initialize();
  if (i < 0 || i >= filenames.u) return 0;
  return 1;
}

unsigned char *
pos_get_file_by_num(int i)
{
  if (!initialized) initialize();
  if (i < 0 || i >= filenames.u) return "";
  return filenames.v[i];
}
