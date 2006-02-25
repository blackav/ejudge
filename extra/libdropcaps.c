/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2006 Alexander Chernov <cher@ispras.ru> */

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

static void init(void) __attribute__((constructor));

static void
init(void)
{
  cap_t old_caps, new_caps;
  int   setcaps[] = { CAP_SYS_OPERATIONS, CAP_SYS_ONE_EXEC };
  
  old_caps = cap_get_proc();
  new_caps = cap_dup(old_caps);
  cap_set_flag(new_caps, CAP_EFFECTIVE, 2, setcaps, CAP_CLEAR);
  cap_set_flag(new_caps, CAP_PERMITTED, 2, setcaps, CAP_CLEAR);
  cap_set_flag(new_caps, CAP_INHERITABLE, 2, setcaps, CAP_CLEAR);
  cap_set_proc(new_caps);

  /* if getppid works, CAP_SYS_OPERATIONS has no effect :-( */
  if (dup(0) >= 0) {
    fprintf(stderr,
            "capexec: CAP_SYS_OPERATIONS is not supported on this system\n");
    exit(6);
  }
}

/**
 * Local variables:
 *  compile-command: "gcc -Wl,--rpath,/usr/local/pkg/libcap-1.10/lib -D_GNU_SOURCE -s -O2 -Wall -I/usr/local/pkg/libcap-1.10/include -L/usr/local/pkg/libcap-1.10/lib capexec.c -o capexec -lcap"
 * End:
 */
