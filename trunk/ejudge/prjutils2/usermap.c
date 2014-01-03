/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ispras.ru> */

/*
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 */

#include "usermap.h"
#include "xalloc.h"

#include <string.h>
#include <ctype.h>

int
usermap_parse(const char *file, FILE *flog, usermap_t *pmap)
{
  FILE *fin = 0;
  int lineno = 0, n, i;
  char bb[1024], login[sizeof(bb)], *name;
  size_t bblen;

  memset(pmap, 0, sizeof(*pmap));

  if (!(fin = fopen(file, "r"))) {
    fprintf(flog, "cannot open user map file `%s'\n", file);
    return -1;
  }
  while (fgets(bb, sizeof(bb), fin)) {
    lineno++;
    bblen = strlen(bb);
    if (bblen > sizeof(bb) - 2) {
      fprintf(flog, "%s: %d: input line is too long\n", file, lineno);
      return -1;
    }
    while (bblen > 0 && isspace(bb[bblen - 1])) bb[--bblen] = 0;
    if (sscanf(bb, "%s%n", login, &n) != 1) {
      fprintf(flog, "%s: %d: failed to parse login\n", file, lineno);
      return -1;
    }
    name = bb + n;
    while (*name && isspace(*name)) name++;

    for (i = 0; i < pmap->u; i++)
      if (!strcmp(pmap->v[i].login, login))
        break;
    if (i < pmap->u) {
      fprintf(flog, "%s: %d: duplicated login\n", file, lineno);
      return -1;
    }

    XEXPAND2(*pmap);
    pmap->v[pmap->u].login = xstrdup(login);
    pmap->v[pmap->u].name = xstrdup(name);
    pmap->u++;
  }
  if (ferror(fin)) {
    fprintf(flog, "input error on `%s'\n", file);
    return -1;
  }
  fclose(fin); fin = 0;
  return 0;
}

char *
usermap_lookup(usermap_t *pmap, char const *login)
{
  int i;

  for (i = 0; i < pmap->u; i++)
    if (!strcmp(pmap->v[i].login, login))
      return pmap->v[i].name;
  return 0;
}
