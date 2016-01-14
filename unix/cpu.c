/* -*- mode: c -*- */

/* Copyright (C) 2005-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/cpu.h"

#include "ejudge/xalloc.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

int
cpu_get_bogomips(void)
{
  FILE *f = 0;
  unsigned char buf[1024], *s;
  size_t buflen;
  int value = 0, n;
  double dv;

  if (!(f = fopen("/proc/cpuinfo", "r"))) goto failure;
  while (fgets(buf, sizeof(buf), f)) {
    buflen = strlen(buf);
    if (buflen > sizeof(buf) - 3) goto failure; // string is too long
    while (buflen > 0 && isspace(buf[buflen - 1])) buf[--buflen] = 0;
    if (strncasecmp(buf, "bogomips", 8)) continue;
    s = buf + 8;
    while (*s && isspace(*s)) s++;
    if (*s != ':') goto failure;
    s++;
    if (sscanf(s, "%lf%n", &dv, &n) != 1 || s[n]) goto failure;
    if (dv <= 0 || dv > 1e10) goto failure;
    value = (int) (dv + 0.5);
    break;
  }
  fclose(f);
  return value;

 failure:
  if (f) fclose(f);
  return -1;
}

void
cpu_get_performance_info(unsigned char **p_model, unsigned char **p_mhz)
{
  FILE *f = NULL;
  unsigned char buf[1024];
  unsigned char *model = NULL;
  unsigned char *mhz = NULL;

  if (p_model) *p_model = NULL;
  if (p_mhz) *p_mhz = NULL;

  if (!(f = fopen("/proc/cpuinfo", "r"))) goto failure;
  while (fgets(buf, sizeof(buf), f)) {
    int buflen = strlen(buf);
    if (buflen > sizeof(buf) - 3) goto failure; // string is too long
    while (buflen > 0 && isspace(buf[buflen - 1])) buf[--buflen] = 0;

    unsigned char *s = strchr(buf, ':');
    if (s && s[1] == ' ') s += 2;
    else if (s) ++s;

    if (!strncasecmp(buf, "model name", 10)) {
      if (model) xfree(model);
      model = xstrdup(s);
      if (mhz) break;
    } else if (!strncasecmp(buf, "cpu mhz", 7)) {
      if (mhz) xfree(mhz);
      mhz = xstrdup(s);
      if (model) break;
    }
  }
  fclose(f);

  if (p_model) *p_model = model;
  else xfree(model);
  if (p_mhz) *p_mhz = mhz;
  else xfree(mhz);
  return;

 failure:
  if (f) fclose(f);
}
