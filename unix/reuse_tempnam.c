/* -*- mode:c -*- */

/* Copyright (C) 2002-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static char *my_tempnam(char const *dir, char const *pfx);

/**
 * NAME:    os_tempnam
 * PURPOSE: wrapper over tempnam function
 * ARGS:    dir - temporary files directory
 *          pfx - file prefix
 * RETURN:  temporary file name allocated in the heap
 */
        char *
os_tempnam(char const *dir, char const *pfx)
{
#if defined __CYGWIN32__
        extern char *tempnam(char const *, char const *);
        char *r = tempnam(dir, pfx);

        return r?xstrdup(r):r;
#else
        //return tempnam(dir, pfx);
        return my_tempnam(dir, pfx);
#endif /* __CYGWIN32__ */
}

static char *
check_dir(char const *actdir)
{
  struct stat st;

  if (!actdir) return 0;
  if (stat(actdir, &st) >= 0
      && S_ISDIR(st.st_mode)
      && access(actdir, R_OK | W_OK | X_OK) >= 0) return (char*) actdir;
  return 0;
}

char const cvttab[] =
"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

static void
cvt(char *buf, int n, int val)
{
  int i;

  for (i = 0; i < n; i++) {
    *buf++ = cvttab[val % 62];
    val /= 62;
  }
  *buf = 0;
}

/* On linux glibc 2.2 use of tempnam causes linker warning! */
static char *
my_tempnam(char const *dir, char const *pfx)
{
  char *actdir = 0;
  char *actname = 0;
  char *actpfx = 0;
  struct stat st;
  int len, rnd;

  /* choose which directory to use */
  while (1) {
    if ((actdir = check_dir(getenv("TMPDIR")))) break;
    if ((actdir = check_dir(getenv("TEMPDIR")))) break;
    if ((actdir = check_dir(dir))) break;
#if defined P_tmpdir
    if ((actdir = check_dir(P_tmpdir))) break;
#endif /* P_tmpdir */
    if ((actdir = check_dir("/tmp"))) break;
    if ((actdir = check_dir("."))) break;
    return 0;                   /* FAILURE */
  }

  len = strlen(actdir);
  if (pfx) len += strlen(pfx);
  actpfx = (char*) alloca(len + 32);
  actname = (char*) alloca(len + 32);
  strcpy(actpfx, actdir);
  if (!*actpfx) strcpy(actpfx, ".");
  len = strlen(actpfx);
  if (actpfx[len - 1] != '/') strcat(actpfx, "/");
  if (pfx) strcat(actpfx, pfx);
  len = strlen(actpfx);

  while (1) {
    rnd = random();
    strcpy(actname, actpfx);
    cvt(actname + len, 6, rnd);
    if (stat(actname, &st) < 0) break;
  }

  //fprintf(stderr, "Temp name: %s\n", actname);
  return xstrdup(actname);
}
