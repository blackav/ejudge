/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_SYS_RESOURCE_H__
#define __RCC_SYS_RESOURCE_H__

/* Copyright (C) 2002-2004 Alexander Chernov <cher@ispras.ru> */

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
#include <sys/time.h>

struct rlimit
{
  rlim_t rlim_cur;
  rlim_t rlim_max;
};
struct rlimit64
{
  rlim64_t rlim_cur;
  rlim64_t rlim_max;
};

struct rusage
{
  struct timeval ru_utime;
  struct timeval ru_stime;
  long int ru_maxrss;
  long int ru_ixrss;
  long int ru_idrss;
  long int ru_isrss;
  long int ru_minflt;
  long int ru_majflt;
  long int ru_nswap;
  long int ru_inblock;
  long int ru_oublock;
  long int ru_msgsnd;
  long int ru_msgrcv;
  long int ru_nsignals;
  long int ru_nvcsw;
  long int ru_nivcsw;
};

int enum __rlimit_resource
{
  RLIMIT_CPU = 0,
#define RLIMIT_CPU RLIMIT_CPU
  RLIMIT_FSIZE = 1,
#define RLIMIT_FSIZE RLIMIT_FSIZE
  RLIMIT_DATA = 2,
#define RLIMIT_DATA RLIMIT_DATA
  RLIMIT_STACK = 3,
#define RLIMIT_STACK RLIMIT_STACK
  RLIMIT_CORE = 4,
#define RLIMIT_CORE RLIMIT_CORE
  RLIMIT_RSS = 5,
#define RLIMIT_RSS RLIMIT_RSS
  RLIMIT_NOFILE = 7,
#define RLIMIT_NOFILE RLIMIT_NOFILE
  RLIMIT_OFILE = RLIMIT_NOFILE,
#define RLIMIT_OFILE RLIMIT_OFILE
  RLIMIT_AS = 9,
#define RLIMIT_AS RLIMIT_AS
  RLIMIT_NPROC = 6,
#define RLIMIT_NPROC RLIMIT_NPROC
  RLIMIT_MEMLOCK = 8,
#define RLIMIT_MEMLOCK RLIMIT_MEMLOCK
  RLIM_NLIMITS = 10
#define RLIM_NLIMITS RLIM_NLIMITS
};

unsigned long enum
{
#defconst RLIM_INFINITY 0xffffffffUL
};

unsigned long long enum
{
#defconst RLIM64_INFINITY 0xffffffffffffffffuLL
};

/* We can represent all limits.  */
#define RLIM_SAVED_MAX	RLIM_INFINITY
#define RLIM_SAVED_CUR	RLIM_INFINITY

int enum __rusage_who
{
  RUSAGE_SELF = 0,
  RUSAGE_CHILDREN = -1,
  RUSAGE_BOTH = -2
};

int enum __priority_which
{
  PRIO_PROCESS = 0,
  PRIO_PGRP = 1,
  PRIO_USER = 2
};

int getrlimit(enum __rlimit_resource, struct rlimit *);
int getrlimit64(enum __rlimit_resource, struct rlimit64 *);
int setrlimit(enum __rlimit_resource, const struct rlimit *);
int setrlimit64(enum __rlimit_resource, const struct rlimit64 *);

int getrusage(enum __rusage_who, struct rusage *);

int getpriority(enum __priority_which, int);
int setpriority(enum __priority_which, int, int);

#endif /* __RCC_SYS_RESOURCE_H__ */
