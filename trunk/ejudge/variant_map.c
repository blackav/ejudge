/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/variant_map.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void
variant_map_unparse(
        FILE *f,
        const struct variant_map *vmap,
        const unsigned char *header,
        const unsigned char *footer)
{
  int i, j;
  int hlen;

  // for header ignore the characters after the last '\n'
  if (header) {
    hlen = strlen(header);
    while (hlen > 0 && header[hlen - 1] != '\n') hlen--;
    fprintf(f, "%.*s", hlen, header);
  }

  fprintf(f, "<variant_map version=\"2\">\n");
  for (i = 0; i < vmap->u; i++) {
    fprintf(f, "%s", vmap->v[i].login);
    if (vmap->v[i].real_variant > 0) {
      fprintf(f, " variant %d", vmap->v[i].real_variant);
      if (vmap->v[i].virtual_variant > 0) {
        fprintf(f, " virtual %d", vmap->v[i].virtual_variant);
      }
    } else {
      for (j = 0; j < vmap->prob_rev_map_size; j++)
        fprintf(f, " %d", vmap->v[i].variants[j]);
    }
    fprintf(f, "\n");
  }
  fprintf(f, "</variant_map>\n");
  if (footer) fprintf(f, "%s", footer);
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
