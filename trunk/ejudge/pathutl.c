/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2004 Alexander Chernov <cher@ispras.ru> */

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

static int
start_from_dot(char const *path)
{
  if (path[0] != '.') return 0;
  if (path[1] == '/') return 1;
  if (path[1] == PATH_SEP[0]) return 1;
  return 0;
}

int
pathmake2(char *dst, ...)
{
  va_list  args;
  char    *p;
  path_t   temp;

  if (os_IsAbsolutePath(dst)) return strlen(dst);
  if (start_from_dot(dst)) return strlen(dst);
  
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

int
pathmake4(char *dst, ...)
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

/* symbol verr exists :( */
void
vverr(char const *msg, va_list args)
{
  vwrite_log(0, LOG_ERR, msg, args);
}

void
err(char const *msg, ...)
{
  va_list args;

  va_start(args, msg);
  vwrite_log(0, LOG_ERR, msg, args);
  va_end(args);
}

/* we need this for proper localization */
void
do_err_r(char const *func, char const *txt, ...)
{
  va_list  args;
  char    *s = alloca(strlen(func) + strlen(txt) + 10);

  va_start(args, txt);
  sprintf(s, "%s: %s", func, txt);
  vverr(s, args);
  va_end(args);
}

void
info(char const *msg, ...)
{
  va_list args;

  va_start(args, msg);
  vwrite_log(0, LOG_INFO, msg, args);
  va_end(args);
}

void
path_add_dir(char *path, char const *dir)
{
  pathmake2(path, dir, "/", path, 0);
}

void 
path_init(char *path, char const *dir, char const *def)
{
  if (!path[0]) pathcpy(path, def);
  path_add_dir(path, dir);
}


/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
