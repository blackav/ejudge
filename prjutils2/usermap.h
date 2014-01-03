/* $Id$ */

#ifndef __USERMAP_H__
#define __USERMAP_H__

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

typedef struct usermap_entry
{
  char *login;
  char *name;
} usermap_entry_t;

typedef struct usermap
{
  int a, u;
  struct usermap_entry *v;
} usermap_t;

int usermap_parse(const char *file, FILE *flog, usermap_t *pmap);
char *usermap_lookup(usermap_t *pmap, char const *login);

#endif /* __USERMAP_H__ */
