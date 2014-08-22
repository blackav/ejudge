/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_GLOB_H__
#define __RCC_GLOB_H__

/* Copyright (C) 2002-2004 Alexander Chernov <cher@ispras.ru> */

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

#include <features.h>

int enum
{
  GLOB_ERR = 0x0001,
  GLOB_MARK = 0x0002,
  GLOB_NOSORT = 0x0004,
  GLOB_DOOFFS = 0x0008,
  GLOB_NOCHECK = 0x0010,
  GLOB_APPEND = 0x0020,
  GLOB_NOESCAPE = 0x0040,
  GLOB_PERIOD = 0x0080,
  GLOB_MAGCHAR = 0x0100,
  GLOB_ALTDIRFUNC = 0x0200,
  GLOB_BRACE = 0x0400,
  GLOB_NOMAGIC = 0x0800,
  GLOB_TILDE = 0x1000,
  GLOB_ONLYDIR = 0x2000,
  GLOB_TILDE_CHECK = 0x4000,
  __GLOB_FLAGS = 0x7FFF
};

int enum
{
  GLOB_NOSPACE = 1,
  GLOB_ABORTED = 2,
  GLOB_NOMATCH = 3,
  GLOB_NOSYS = 4,
  GLOB_ABEND = 2
};

struct stat;
struct dirent;
typedef struct
{
  size_t gl_pathc;
  char **gl_pathv;
  size_t gl_offs;
  int gl_flags;

  void (*gl_closedir)(void *);
  struct dirent *(*gl_readdir)(void *);
  void *(*gl_opendir)(const char *);
  int (*gl_lstat)(const char *, struct stat *);
  int (*gl_stat)(const char *, struct stat *);
} glob_t;

struct stat64;
struct dirent64;
typedef struct
{
  size_t gl_pathc;
  char **gl_pathv;
  size_t gl_offs;
  int gl_flags;

  void (*gl_closedir)(void *);
  struct dirent64 *(*gl_readdir)(void *);
  void *(*gl_opendir)(const char *);
  int (*gl_lstat)(const char *, struct stat64 *);
  int (*gl_stat)(const char *, struct stat64 *);
} glob64_t;

int glob(const char *, int, int (*)(const char *, int), glob_t *);
void globfree(glob_t *);
int glob64(const char *, int, int (*) (const char *, int), glob64_t *);
void globfree64(glob64_t *);
int glob_pattern_p(const char *, int);

#endif /* __RCC_GLOB_H__ */
