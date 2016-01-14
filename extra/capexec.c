/* -*- mode: c -*- */

/* Copyright (C) 2000-2016 Alexander Chernov <cher@ejudge.ru> */

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

/**
 * This small program just starts another program, which arguments
 * are given to it in the command line. Before execing it drops
 * CAP_SYS_OPERATIONS capability of the process, so the execed process
 * will be unable do perform almost all file operations except
 * read and write to the opened file descriptors.
 *
 * To compile this program successfully you need:
 *  1) CAP_SYS_OPERATIONS linux kernel patch, available from
 *    http://contest.cmc.msu.ru/download/linux-kernel.html
 *  2) libcap library, which you may download from
 *    http://contest.cmc.msu.ru/download/libcap.html
 */

#if defined HAVE_CONFIG_H && HAVE_CONFIG_H > 0
#include "../include/ejudge/config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#ifdef __linux__
#include <sys/ptrace.h>
#endif

#if defined HAVE_CAP_SYS_OPERATIONS && HAVE_CAP_SYS_OPERATIONS > 0
#include <sys/capability.h>
#endif

extern char **environ;

int main(int argc, char *argv[])
{
#ifdef __linux__
#if defined HAVE_CAP_SYS_OPERATIONS && HAVE_CAP_SYS_OPERATIONS > 0
  cap_t old_caps, new_caps;
  int   setcaps[] = { CAP_SYS_OPERATIONS };
#endif

  if (ptrace(0x4281, 0, 0, 0) >= 0) {
    // new secure exec interface
    /* if getppid works, CAP_SYS_OPERATIONS has no effect :-( */
    if (dup(0) >= 0) {
      fprintf(stderr,
              "capexec: CAP_SYS_OPERATIONS is not supported on this system\n");
      return 6;
    }

    execve(argv[1], argv + 1, environ);
    perror("capexec: execve");

    /* 6 exit code means that check is failed */
    return 6;
  }
  
#if defined HAVE_CAP_SYS_OPERATIONS && HAVE_CAP_SYS_OPERATIONS > 0
  old_caps = cap_get_proc();
  new_caps = cap_dup(old_caps);
  cap_set_flag(new_caps, CAP_EFFECTIVE, 1, setcaps, CAP_CLEAR);
  cap_set_flag(new_caps, CAP_PERMITTED, 1, setcaps, CAP_CLEAR);
  cap_set_flag(new_caps, CAP_INHERITABLE, 1, setcaps, CAP_CLEAR);
  cap_set_proc(new_caps);
#endif

  /* if getppid works, CAP_SYS_OPERATIONS has no effect :-( */
  if (dup(0) >= 0) {
    fprintf(stderr,
            "capexec: CAP_SYS_OPERATIONS is not supported on this system\n");
    return 6;
  }

  execve(argv[1], argv + 1, environ);
  perror("capexec: execve");
#endif

  /* 6 exit code means that check is failed */
  return 6;
}
