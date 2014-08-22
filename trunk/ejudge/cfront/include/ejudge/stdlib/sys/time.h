/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_SYS_TIME_H__
#define __RCC_SYS_TIME_H__

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
#include <sys/types.h>

#ifndef __RCC_TIMEVAL_DEFINED__
#define __RCC_TIMEVAL_DEFINED__
struct timeval
{
  time_t tv_sec;
  long   tv_usec;
};
#endif /* __RCC_TIMEVAL_DEFINED__ */

#ifndef __RCC_suseconds_t_defined
typedef long int suseconds_t;
#define __RCC__suseconds_t_defined
#endif

#ifndef RCC_TIMESPEC_DEFINED
#define RCC_TIMESPEC_DEFINED
struct timespec
{
  time_t tv_sec;
  long   tv_nsec;
};
#endif /* RCC_TIMESPEC_DEFINED */

int nanosleep(const struct timespec *, struct timespec *);

int gettimeofday(struct timeval *, void *);
int settimeofday(const struct timeval *, void *);
int adjtime(const struct timeval *delta, struct timeval *olddelta);

struct timezone
{
  int tz_minuteswest;
  int tz_dsttime;
};

typedef struct timezone * __timezone_ptr_t;

void TIMEVAL_TO_TIMESPEC(const struct timeval *, struct timespec *);
void TIMESPEC_TO_TIMEVAL(struct timeval *, const struct timespec *);

enum __itimer_which
{
  ITIMER_REAL = 0,
#define ITIMER_REAL ITIMER_REAL
  ITIMER_VIRTUAL = 1,
#define ITIMER_VIRTUAL ITIMER_VIRTUAL
  ITIMER_PROF = 2
#define ITIMER_PROF ITIMER_PROF
};

struct itimerval
{
  struct timeval it_interval;
  struct timeval it_value;
};

#if !defined __cplusplus
/* Use the nicer parameter type only in GNU mode and not for C++ since the
   strict C++ rules prevent the automatic promotion.  */
typedef enum __itimer_which __itimer_which_t;
#else
typedef int __itimer_which_t;
#endif

int getitimer(__itimer_which_t which, struct itimerval *value);
int setitimer(__itimer_which_t which, const struct itimerval *new,
              struct itimerval *old);

int utimes(const char *file, const struct timeval tvp[2]);
int lutimes(const char *file, const struct timeval tvp[2]);
int futimes(int fd, const struct timeval tvp[2]);

#define timerisset(tvp) ((tvp)->tv_sec || (tvp)->tv_usec)
#define timerclear(tvp) ((tvp)->tv_sec = (tvp)->tv_usec = 0)
#define timercmp(a, b, CMP)                                                   \
  (((a)->tv_sec == (b)->tv_sec) ?                                             \
   ((a)->tv_usec CMP (b)->tv_usec) :                                          \
   ((a)->tv_sec CMP (b)->tv_sec))
#define timeradd(a, b, result)                                                \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;                          \
    if ((result)->tv_usec >= 1000000)                                         \
      {                                                                       \
        ++(result)->tv_sec;                                                   \
        (result)->tv_usec -= 1000000;                                         \
      }                                                                       \
  } while (0)
#define timersub(a, b, result)                                                \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;                          \
    if ((result)->tv_usec < 0) {                                              \
      --(result)->tv_sec;                                                     \
      (result)->tv_usec += 1000000;                                           \
    }                                                                         \
  } while (0)

#endif /* __RCC_SYS_TIME_H__ */
