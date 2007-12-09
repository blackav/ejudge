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
#include <reuse/xalloc.h>

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
  unsigned char *s, *q;
  int cnt, i;
  unsigned char **split;

  snprintf(p, sizeof(p), "%s", path);
  os_normalize_path(p);

  // count the '/'
  for (s = p, cnt = 1; *s; s++)
    if (*s == '/') cnt++;
  XCALLOC(split, cnt + 1);
  s = p;
  i = 0;
  if (*s == '/') {
    split[i++] = xmemdup(s++, 1);
  }
  while (*s) {
    q = s;
    while (*q && *q != '/') q++;
    split[i++] = xmemdup(s, q - s);
    if (*q == '/') q++;
    s = q;
  }
  split[i] = 0;

  *p_split = split;
  return i;
}

unsigned char **
path_split_free(unsigned char **split)
{
  int i;

  if (!split) return 0;
  for (i = 0; split[i]; i++)
    xfree(split[i]);
  xfree(split);
  return 0;
}

void
path_normalize_split(unsigned char **split)
{
  int i, j;
  unsigned char *t;

  if (!split || !split[0] || strcmp(split[0], "/")) return;
  i = j = 1;
  while (split[i]) {
    if (!strcmp(split[i], "..")) {
      if (j > 1) j--;
      i++;
    } else if (!strcmp(split[i], ".")) {
      i++;
    } else {
      if (i == j) {
        i++; j++;
      } else {
        t = split[j]; split[j] = split[i]; split[i] = t;
        i++; j++;
      }
    }
  }
  if (i != j) {
    t = split[j]; split[j] = split[i]; split[i] = t;
  }
  for (; i > j; i--) {
    xfree(split[i]); split[i] = 0;
  }
}

void
path_normalize(unsigned char *path, size_t size)
{
  unsigned char **split = 0;
  int n, i, j, len;
  unsigned char *t;

  if (!os_IsAbsolutePath(path)) return;
  n = path_split(path, &split);
  i = j = 1;
  while (split[i]) {
    if (!strcmp(split[i], "..")) {
      if (j > 1) j--;
      i++;
    } else if (!strcmp(split[i], ".")) {
      i++;
    } else {
      if (i == j) {
        i++; j++;
      } else {
        t = split[j]; split[j] = split[i]; split[i] = t;
        i++; j++;
      }
    }
  }
  if (i != j) {
    t = split[j]; split[j] = split[i]; split[i] = t;
  }
  for (; i > j; i--) {
    xfree(split[i]); split[i] = 0;
  }
  for (len = 0, i = 1; split[i]; i++)
    len += strlen(split[i]) + 1;
  if (len >= size) goto cleanup;
  t = path;
  for (i = 1; split[i]; i++)
    t += sprintf(t, "/%s", split[i]);

 cleanup:
  for (i = 0; split[i]; i++)
    xfree(split[i]);
  xfree(split);
}

int
path_is_prefix(
        unsigned char **s_path,
        unsigned char **s_prefix)
{
  int i;

  if (!s_prefix || !s_path) return 0;
  for (i = 0; s_prefix[i]; i++) {
    if (!s_path[i]) return 0;
    if (strcmp(s_prefix[i], s_path[i])) return 0;
  }
  return 1;
}

static void
do_relative(
        unsigned char *out,
        size_t size,
        unsigned char **s_path,
        unsigned char **s_relto)
{
  int pfxlen, i, len;
  unsigned char *tmpbuf, *p;

  for (pfxlen = 0; s_path[pfxlen] && s_relto[pfxlen] && !strcmp(s_path[pfxlen], s_relto[pfxlen]); pfxlen++);

  // how many levels up
  for (i = pfxlen, len = 0; s_relto[i]; i++, len += 4);
  // levels down
  for (i = pfxlen; s_path[i]; i++)
    len += strlen(s_path[i]) + 2;

  p = tmpbuf = (unsigned char*) alloca(len + 1);
  *p = 0;
  for (i = pfxlen; s_relto[i]; i++) {
    if (p != tmpbuf) *p++ = '/';
    *p++ = '.';
    *p++ = '.';
    *p = 0;
  }
  for (i = pfxlen; s_path[i]; i++) {
    if (p != tmpbuf) *p++ = '/';
    p += sprintf(p, "%s", s_path[i]);
  }
  snprintf(out, size, "%s", tmpbuf);
}

void
path_make_relative(
        unsigned char *out,
        size_t size,
        const unsigned char *path,
        const unsigned char *relto,
        const unsigned char *prefix)
{
  path_t path1, relto1, prefix1;
  unsigned char **s_path = 0, **s_relto = 0, **s_prefix = 0;

  ASSERT(path);
  snprintf(path1, sizeof(path1), "%s", path);

  if (!relto || !prefix) goto do_nothing;
  snprintf(relto1, sizeof(relto1), "%s", relto);
  snprintf(prefix1, sizeof(prefix1), "%s", prefix);

  if (!os_IsAbsolutePath(path1) || !os_IsAbsolutePath(relto1)
      || !os_IsAbsolutePath(prefix1))
    goto do_nothing;
  path_split(path1, &s_path);
  path_normalize_split(s_path);
  path_split(relto1, &s_relto);
  path_normalize_split(s_relto);
  path_split(prefix1, &s_prefix);
  path_normalize_split(s_prefix);
  if (!path_is_prefix(s_path, s_prefix) || !path_is_prefix(s_relto, s_prefix))
    goto do_nothing;
  do_relative(out, size, s_path, s_relto);
  goto cleanup;

 do_nothing:
  snprintf(out, size, "%s", path1);

 cleanup:
  path_split_free(s_path);
  path_split_free(s_relto);
  path_split_free(s_prefix);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
