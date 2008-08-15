/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2007,2008 Alexander Chernov <cher@ejudge.ru> */

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
#include <sys/ptrace.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/utsname.h>

#include "get_version.c"

void recur(int depth)
{
  char *arr;

  if (depth == 20) return;

  // this stuff is to avoid optimizations
  arr = malloc(2 * 1024 * 1024);
  arr[0] = '<';
  arr[1] = 0;
  fprintf(stderr, "%s", arr);
  recur(depth + 1);
  arr[0] = '>';
  arr[1] = 0;
  fprintf(stderr, "%s", arr);
}

static void do_son(void) __attribute__((noreturn));
void do_son(void)
{
  struct rlimit rl;
  int ptcmd = 0;

  if (linux_version >= 2006000) {
    ptcmd = 0x4280;
  } else if (linux_version >= 2004000) {
    ptcmd = 0x20;
  } else {
    fprintf(stderr, "failed: unsupported Linux kernel\n");
    _exit(111);
  }

  memset(&rl, 0, sizeof(rl));
  rl.rlim_cur = 32 * 1024 * 1024;
  rl.rlim_max = 32 * 1024 * 1024;
  if (setrlimit(RLIMIT_AS, &rl) < 0) {
    fprintf(stderr, "failed: setrlimit() error: %s\n", strerror(errno));
    _exit(111);
  }
  if (ptrace(ptcmd, 0, 0, 0) < 0) {
    fprintf(stderr, "failed: ptrace() error: %s\n", strerror(errno));
    _exit(111);
  }
  fprintf(stderr, "info: recursion: ");
  recur(0);
  fprintf(stderr, "\n");
  _exit(0);
}

int main(void)
{
  int p, s, d = 0;

  fprintf(stderr, "t4: checking memory limit error for heap\n");

  if ((linux_version = get_linux_version()) < 0)
    return 1;
  if (!linux_version) {
    fprintf(stderr, "failed: not Linux or unknown linux version\n");
    return 1;
  }
  fprintf(stderr, "t4: linux version %d\n", linux_version);

  if ((p = fork()) < 0) {
    fprintf(stderr, "failed: unexpected fork() error: %s\n", strerror(errno));
    return 1;
  }
  if (!p) do_son();
  wait(&s);
  if ((s & 0x10000)) {
    fprintf(stderr, "\ninfo: 0x10000 detected\n");
    s &= 0xffff;
    d = 1;
  }
  if (WIFEXITED(s) && WEXITSTATUS(s) == 111) {
    fprintf(stderr, "failed: child failed to setup limitations\n");
    return 1;
  }

  if (WIFEXITED(s)) {
    fprintf(stderr, "info: child exited: %d\n", WEXITSTATUS(s));
  } else if (WIFSIGNALED(s)) {
    fprintf(stderr, "info: child signaled: %d\n", WTERMSIG(s));
  }

  if (!d) {
    fprintf(stderr, "failed: memory limit error not detected\n");
    return 1;
  }
  fprintf(stderr, "ok\n");
  return 0;
}
