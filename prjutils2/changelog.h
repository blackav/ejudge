/* $Id$ */

#ifndef __CHANGELOG__H__
#define __CHANGELOG__H__

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

#include <stdio.h>

typedef struct changelog_entry
{
  int   year, month, day, revision;
  char *file;
  char *author;
  char *text;
} changelog_entry_t;

typedef struct changelog
{
  int a, u;
  changelog_entry_t *v;

  int maxyear, maxmonth, maxday, maxrevision;
} changelog_t;

int changelog_read(char const *path, changelog_t *p_log, FILE *errlog);

#endif /* __CHANGELOG__H__ */
