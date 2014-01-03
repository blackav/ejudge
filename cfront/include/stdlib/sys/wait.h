/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_SYS_WAIT_H__
#define __RCC_SYS_WAIT_H__

/* Copyright (C) 2002-2005 Alexander Chernov <cher@ispras.ru> */

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
#include <signal.h>
#include <sys/resource.h>

/* These flags are also in <stdlib.h> */
#ifndef WNOHANG
int enum
{
#defconst WNOHANG 1
#defconst WUNTRACED 2
#defconst __WALL 0x40000000
#defconst __WCLONE 0x80000000
};
#endif /* WNOHANG */

/* These macros are also in <sys/wait.h> */
#ifndef WEXITSTATUS
#define WEXITSTATUS(status)     (((status) & 0xff00) >> 8)
#define WTERMSIG(status)        ((status) & 0x7f)
#define WSTOPSIG(status)        WEXITSTATUS(status)
#define WIFEXITED(status)       (WTERMSIG(status) == 0)
#define WIFSIGNALED(status)     (!WIFSTOPPED(status) && !WIFEXITED(status))
#define WIFSTOPPED(status)      (((status) & 0xff) == 0x7f)
#define WCOREDUMP(status)       ((status) & WCOREFLAG)
#define WCOREFLAG               0x80
#define __WCOREFLAG             WCOREFLAG
#endif /* WEXITSTATUS */

pid_t wait(int *);
pid_t waitpid(pid_t, int *, int);

struct rusage;
pid_t wait3(int *, int, struct rusage *);
pid_t wait4(pid_t pid, int *, int, struct rusage *);

#endif /* __RCC_SYS_WAIT_H__ */
