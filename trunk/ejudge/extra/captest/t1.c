/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2007 Alexander Chernov <cher@ejudge.ru> */

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
#include <sys/capability.h>
#include <sys/ptrace.h>

int main(void)
{
  cap_t old_caps, new_caps;
  int   setcaps[] = { CAP_SYS_OPERATIONS };
  int   p;

  fprintf(stderr, "t1: checking for disabled syscalls\n");

  if (ptrace(0x4281, 0, 0, 0) >= 0) {
    // new interface
    fprintf(stderr, "t1: new interface detected\n");
  } else {
    old_caps = cap_get_proc();
    new_caps = cap_dup(old_caps);
    cap_set_flag(new_caps, CAP_EFFECTIVE, 1, setcaps, CAP_CLEAR);
    cap_set_flag(new_caps, CAP_PERMITTED, 1, setcaps, CAP_CLEAR);
    cap_set_flag(new_caps, CAP_INHERITABLE, 1, setcaps, CAP_CLEAR);
    if (cap_set_proc(new_caps) < 0) {
      fprintf(stderr, "failed: cap_set_proc() failed\n");
      return 1;
    }
  }
  errno = 0;
  if ((p = fork()) < 0 && errno == EPERM) {
    fprintf(stderr, "ok\n");
    return 0;
  }
  if (p < 0) {
    fprintf(stderr, "failed: unexpected fork() error: %s\n", strerror(errno));
    return 1;
  }
  if (!p) _exit(1);
  fprintf(stderr, "failed: fork() succeeded\n");
  return 1;
}

