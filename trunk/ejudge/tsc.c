/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "tsc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

ej_tsc_t cpu_frequency;
int
tsc_init(void)
{
  FILE *f = 0;
  unsigned char buf[1024];
  size_t len;
  int lineno = 0, n;
  unsigned char * path = "/proc/cpuinfo";
  long double cpuf;

  if (!(f = fopen(path, "r"))) {
    fprintf(stderr, "%s: cannot open: %s\n", path, strerror(errno));
    goto failure;
  }
  while (fgets(buf, sizeof(buf), f)) {
    lineno++;
    len = strlen(buf);
    if (len > sizeof(buf) - 2) {
      fprintf(stderr, "%s: %d: line is too long (%zu)\n", path, lineno, len);
      goto failure;
    }
    while (len > 0 && isspace(buf[len - 1])) buf[--len] = 0;
    if (strncmp(buf, "cpu MHz", 7)) continue;
    if (sscanf(buf, "cpu MHz : %Lf%n", &cpuf, &n) != 1 || buf[n]) {
      fprintf(stderr, "%s: %d: cannot parse `cpu MHz' line\n", path, lineno);
      goto failure;
    }
    cpu_frequency = (ej_tsc_t) (cpuf * 1000000.0L);
    //fprintf(stderr, "Detected CPU frequency is %lld\n", cpu_frequency);
    break;
  }
  fclose(f);
  return 0;

 failure:
  if (f) fclose(f);
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
