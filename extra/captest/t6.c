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

static void do_son(void) __attribute__((noreturn));
void do_son(void)
{
  struct rlimit rl;
  int rlname = 0;

  if (linux_version >= 2006025) {
    rlname = 19;
  } else if (linux_version >= 2006000) {
    rlname = 15;
  } else if (linux_version >= 2004000) {
    rlname = 11;
  } else {
    fprintf(stderr, "failed: unsupported Linux kernel\n");
    _exit(111);
  }

  memset(&rl, 0, sizeof(rl));
  rl.rlim_cur = 500;
  rl.rlim_max = 500;
  if (setrlimit(rlname, &rl) < 0) {
    fprintf(stderr, "failed: setrlimit() error: %s\n", strerror(errno));
    _exit(111);
  }
  while (1);
}

int main(void)
{
  int p, s, r;
  struct rusage rr;
  long long tms = 0;

  fprintf(stderr, "t6: checking millisecond time limits\n");

  if ((linux_version = get_linux_version()) < 0)
    return 1;
  if (!linux_version) {
    fprintf(stderr, "failed: not Linux or unknown linux version\n");
    return 1;
  }
  fprintf(stderr, "t6: linux version %d\n", linux_version);

  if ((p = fork()) < 0) {
    fprintf(stderr, "failed: unexpected fork() error: %s\n", strerror(errno));
    return 1;
  }
  if (!p) do_son();

  sleep(5);
  r = wait4(-1, &s, WNOHANG, &rr);
  if (!r) {
    fprintf(stderr, "failed: child did not terminate in 5 seconds\n");
    kill(p, SIGKILL);
    wait(0);
    return 1;
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

  tms = 0;
  tms += rr.ru_utime.tv_sec * 1000;
  tms += rr.ru_stime.tv_sec * 1000;
  tms += rr.ru_utime.tv_usec / 1000;
  tms += rr.ru_stime.tv_usec / 1000;
  fprintf(stderr, "info: child user+sys ms: %lld\n", tms);
  if (tms > 900) {
    fprintf(stderr, "failed: millisecond timelimit does not work\n");
    return 1;
  }

  fprintf(stderr, "ok\n");
  return 0;
}
