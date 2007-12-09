/* -*- c -*- */
/* $Id$ */
#ifndef __PATHUTL_H__
#define __PATHUTL_H__

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

#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#ifdef unix
#define PATH_SEP     "/"
#define PATH_EOL     "\n"
#define PATH_EXE_SFX ""
#else
#define PATH_SEP     "\\"
#define PATH_EOL     "\r\n"
#define PATH_EXE_SFX ".exe"
#endif

typedef char path_t[PATH_MAX + 16];

extern char *strmcpy(char *, char const *, size_t);
extern char *strmcat(char *, char const *, size_t);
extern int   pathmake(char *, ...);
extern int   pathmake2(char *, ...);
extern int   pathmake3(char *, ...);

extern char *chop(char *);

#ifdef __GNUC__
extern inline char *
pathcpy(char *dst, char const *src)
{
  return strmcpy(dst, src, PATH_MAX);
}
extern inline char *
pathcat(char *dst, char const *src)
{
  return strmcat(dst, src, PATH_MAX);
}

extern inline void
path_add_dir(char *path, char const *dir)
{
  pathmake2(path, dir, "/", path, NULL);
}
extern inline void 
path_init(char *path, char const *dir, char const *def)
{
  if (!path[0]) pathcpy(path, def);
  path_add_dir(path, dir);
}
#else
char *pathcpy(char *dst, char const *src);
char *pathcat(char *dst, char const *src);

void path_add_dir(char *path, char const *dir);
void path_init(char *path, char const *dir, char const *def);
#endif /* __GNUC__ */

void path_normalize(unsigned char *path, size_t size);
void
path_make_relative(
        unsigned char *out,
        size_t size,
        const unsigned char *path,
        const unsigned char *relto,
        const unsigned char *prefix);

#endif /* __PATHUTL_H__ */
