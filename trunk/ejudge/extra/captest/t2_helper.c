/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2007-2008 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>

int main(int argc, char **argv)
{
  int p;
  char progname[PATH_MAX];

  snprintf(progname, sizeof(progname), "%s_2", argv[0]);

  p = fork();
  if (!p) _exit(0);
  if (p < 0 && errno != EPERM) {
    fprintf(stderr, "failed: unexpected fork() error: %s\n", strerror(errno));
    return 1;
  }
  if (p > 0) {
    fprintf(stderr, "failed: fork() succeeded\n");
    return 1;
  }
  execl(progname, progname, NULL);
  if (errno != EPERM) {
    fprintf(stderr, "failed: unexpected execl() error: %s\n", strerror(errno));
    return 1;
  }
  fprintf(stderr, "ok\n");
  return 0;
}
