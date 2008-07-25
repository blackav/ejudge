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

#if defined HAVE_CONFIG_H && HAVE_CONFIG_H > 0
#include "../../config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <limits.h>

#if defined HAVE_CAP_SYS_OPERATIONS && HAVE_CAP_SYS_OPERATIONS > 0
#include <sys/capability.h>
#endif

int main(int argc, char **argv)
{
#if defined HAVE_CAP_SYS_OPERATIONS && HAVE_CAP_SYS_OPERATIONS > 0
  cap_t old_caps, new_caps;
  int   setcaps[] = { CAP_SYS_OPERATIONS };
#endif
  char progname[PATH_MAX];

  fprintf(stderr, "t2: checking for one-time exec\n");

  if (ptrace(0x4281, 0, 0, 0) >= 0) {
    // new interface
    fprintf(stderr, "t2: new interface detected\n");
  } else {
#if defined HAVE_CAP_SYS_OPERATIONS && HAVE_CAP_SYS_OPERATIONS > 0
    old_caps = cap_get_proc();
    new_caps = cap_dup(old_caps);
    cap_set_flag(new_caps, CAP_EFFECTIVE, 1, setcaps, CAP_CLEAR);
    cap_set_flag(new_caps, CAP_PERMITTED, 1, setcaps, CAP_CLEAR);
    cap_set_flag(new_caps, CAP_INHERITABLE, 1, setcaps, CAP_CLEAR);
    if (cap_set_proc(new_caps) < 0) {
      fprintf(stderr, "failed: cap_set_proc() failed\n");
      return 1;
    }
#endif
  }
  snprintf(progname, sizeof(progname), "%s_helper", argv[0]);
  errno = 0;
  execl(progname, progname, NULL);
  fprintf(stderr, "failed: execl failed: %s\n", strerror(errno));
  return 1;
}
