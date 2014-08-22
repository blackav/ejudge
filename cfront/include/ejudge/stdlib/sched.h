/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_SCHED_H__
#define __RCC_SCHED_H__   1

/* Copyright (C) 2003,2004 Alexander Chernov <cher@ispras.ru> */

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
#include <sys/types.h>
#include <time.h>

int enum
{
  SCHED_OTHER = 0,
#define SCHED_OTHER SCHED_OTHER
  SCHED_FIFO = 1,
#define SCHED_FIFO SCHED_FIFO
  SCHED_RR = 2,
#define SCHED_RR SCHED_RR
};

int enum
{
  CSIGNAL = 0x000000ff,
#define CSIGNAL CSIGNAL
  CLONE_VM = 0x00000100,
#define CLONE_VM CLONE_VM
  CLONE_FS = 0x00000200,
#define CLONE_FS CLONE_FS
  CLONE_FILES = 0x00000400,
#define CLONE_FILES CLONE_FILES
  CLONE_SIGHAND = 0x00000800,
#define CLONE_SIGHAND CLONE_SIGHAND
  CLONE_PID = 0x00001000,
#define CLONE_PID CLONE_PID
  CLONE_PTRACE = 0x00002000,
#define CLONE_PTRACE CLONE_PTRACE
  CLONE_VFORK = 0x00004000,
#define CLONE_VFORK CLONE_VFORK
  CLONE_PARENT = 0x00008000,
#define CLONE_PARENT CLONE_PARENT
  CLONE_THREAD = 0x00010000,
#define CLONE_THREAD CLONE_THREAD
  CLONE_NEWNS = 0x00020000,
#define CLONE_NEWNS CLONE_NEWNS
  CLONE_SYSVSEM = 0x00040000,
#define CLONE_SYSVSEM CLONE_SYSVSEM
  CLONE_SETTLS = 0x00080000,
#define CLONE_SETTLS CLONE_SETTLS
  CLONE_PARENT_SETTID = 0x00100000,
#define CLONE_PARENT_SETTID CLONE_PARENT_SETTID
  CLONE_CHILD_CLEARTID = 0x00200000,
#define CLONE_CHILD_CLEARTID CLONE_CHILD_CLEARTID
  CLONE_DETACHED = 0x00400000,
#define CLONE_DETACHED CLONE_DETACHED
  CLONE_UNTRACED = 0x00800000,
#define CLONE_UNTRACED CLONE_UNTRACED
  CLONE_CHILD_SETTID = 0x01000000,
#define CLONE_CHILD_SETTID CLONE_CHILD_SETTID
};

struct sched_param
{
  int __sched_priority;
};

int clone(int (*fn)(void *arg), void *child_stack, int flags, void *arg);

struct __sched_param
{
  int __sched_priority;
};

#define sched_priority __sched_priority

int sched_setparam(pid_t pid, const struct sched_param *param);
int sched_getparam(pid_t pid, struct sched_param *param);
int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param);
int sched_getscheduler(pid_t pid);
int sched_yield(void);
int sched_get_priority_max(int algorithm);
int sched_get_priority_min(int algorithm);
int sched_rr_get_interval(pid_t pid, struct timespec *t);
int sched_setaffinity(pid_t pid, unsigned int len, unsigned long int *mask);
int sched_getaffinity(pid_t pid, unsigned int len, unsigned long int *mask);

#endif /* __RCC_SCHED_H__ */
