/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2007 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include "pathutl.h"

#include <reuse/osdeps.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#if defined __GNUC__ && defined __MINGW32__
#include <malloc.h>
#endif

char *
strmcpy(char *dst, char const *src, size_t maxsize)
{
  strncpy(dst, src, maxsize);
  dst[maxsize - 1] = 0;
  return dst;
}

char *
strmcat(char *dst, char const *src, size_t maxsize)
{
  char *sent = dst + maxsize - 1;
  char *p = dst;

  for (; *p; p++);
  for (; p < sent && *src; *p++ = *src++);
  *p = 0;
  return dst;
}

char *
pathcpy(char *dst, char const *src)
{
  return strmcpy(dst, src, PATH_MAX);
}

char *
pathcat(char *dst, char const *src)
{
  return strmcat(dst, src, PATH_MAX);
}

int
pathmake(char *dst, ...)
{
  va_list  args;
  char    *p;
  
  dst[0] = 0;
  va_start(args, dst);
  while ((p = va_arg(args, char*))) {
    if (p[0] == '/' && p[1] == 0) {
      strmcat(dst, PATH_SEP, PATH_MAX);
    } else {
      strmcat(dst, p, PATH_MAX);
    }
  }
  va_end(args);
  return strlen(dst);
}

int
pathmake2(char *dst, ...)
{
  va_list  args;
  char    *p;
  path_t   temp;

  if (os_IsAbsolutePath(dst)) return strlen(dst);
  
  temp[0] = 0;
  va_start(args, dst);
  while ((p = va_arg(args, char*))) {
    if (p[0] == '/' && p[1] == 0) {
      strmcat(temp, PATH_SEP, PATH_MAX);
    } else {
      strmcat(temp, p, PATH_MAX);
    }
  }
  va_end(args);
  pathcpy(dst, temp);
  return strlen(dst);
}

int
pathmake3(char *dst, ...)
{
  va_list  args;
  char    *p;
  path_t   temp;

  temp[0] = 0;
  va_start(args, dst);
  while ((p = va_arg(args, char*))) {
    if (p[0] == '/' && p[1] == 0) {
      strmcat(temp, PATH_SEP, PATH_MAX);
    } else {
      strmcat(temp, p, PATH_MAX);
    }
  }
  va_end(args);
  
  dst[0] = 0;
  if (!os_IsAbsolutePath(temp)) {
    os_rGetWorkingDir(dst, PATH_MAX, 1);
    pathcat(dst, PATH_SEP);
  }
  pathcat(dst, temp);
  return strlen(dst);
}

char *
chop(char *s)
{
  char *ps;
  size_t len;

  if (!s) return s;

  for (ps = s; *ps; ps++)
    if (*ps >= 1 && *ps < ' ') *ps = ' ';

  len = strlen(s);
  while (len > 0 && s[len - 1] == ' ') s[--len] = 0;

  return s;
}

void
path_add_dir(char *path, char const *dir)
{
  pathmake2(path, dir, "/", path, NULL);
}

void 
path_init(char *path, char const *dir, char const *def)
{
  if (!path[0]) pathcpy(path, def);
  path_add_dir(path, dir);
}

int
path_split(const unsigned char *path, unsigned char ***p_split)
{
  path_t p;
  unsigned char *s;
  int cnt;
  //unsigned char **split;

  snprintf(p, sizeof(p), "%s", path);
  os_normalize_path(p);

  // count the '/'
  for (s = p, cnt = 1; *s; s++)
    if (*s == '/') cnt++;
  abort();
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
