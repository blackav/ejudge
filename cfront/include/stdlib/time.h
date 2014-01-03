/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_TIME_H__
#define __RCC_TIME_H__  1

/* Copyright (C) 2003-2005 Alexander Chernov <cher@ispras.ru> */

/*
 * This library is free software; you can redistribute it and/or
 * it under the terms of the GNU Lesser General Public
 * as published by the Free Software Foundation; either
 * 2 of the License, or (at your option) any later version.
 *
 * library is distributed in the hope that it will be useful,
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <features.h>
#include <sys/types.h>

long enum { CLOCKS_PER_SEC = 1000000L };
#define CLOCKS_PER_SEC CLOCKS_PER_SEC

int enum {
#defconst CLOCK_REALTIME           0
#defconst CLOCK_PROCESS_CPUTIME_ID 2
#defconst CLOCK_THREAD_CPUTIME_ID  3
#defconst TIMER_ABSTIME            1
};

#define CLK_TCK CLOCKS_PER_SEC
typedef int clockid_t;
typedef int timer_t;

#ifndef RCC_TIMESPEC_DEFINED
#define RCC_TIMESPEC_DEFINED
struct timespec
{
    time_t tv_sec;
    long   tv_nsec;
};
#endif /* RCC_TIMESPEC_DEFINED */

struct tm
{
  int tm_sec;                   /* Seconds.     [0-60] (1 leap second) */
  int tm_min;                   /* Minutes.     [0-59] */
  int tm_hour;                  /* Hours.       [0-23] */
  int tm_mday;                  /* Day.         [1-31] */
  int tm_mon;                   /* Month.       [0-11] */
  int tm_year;                  /* Year - 1900.  */
  int tm_wday;                  /* Day of week. [0-6] */
  int tm_yday;                  /* Days in year.[0-365] */
  int tm_isdst;                 /* DST.         [-1/0/1]*/

  long int tm_gmtoff;           /* Seconds east of UTC.  */
  const char *tm_zone;          /* Timezone abbreviation.  */
  long int __tm_gmtoff;         /* Seconds east of UTC.  */
  const char *__tm_zone;        /* Timezone abbreviation.  */
};

struct itimerspec
{
  struct timespec it_interval;
  struct timespec it_value;
};

extern char *__tzname[2];
extern int __daylight;
extern long int __timezone;
extern char *tzname[2];
extern int daylight;
extern long int timezone;

void tzset(void);
clock_t clock(void);
time_t time(time_t *);
size_t strftime(char *, size_t, const char *, const struct tm *);

char *asctime(const struct tm *tm);
char *asctime_r(const struct tm *tm, char *buf);

char *ctime(const time_t *timep);
char *ctime_r(const time_t *timep, char *buf);

struct tm *gmtime(const time_t *timep);
struct tm *gmtime_r(const time_t *timep, struct tm *result);
struct tm *localtime(const time_t *timep);
struct tm *localtime_r(const time_t *timep, struct tm *result);

time_t mktime(struct tm *tm);

int nanosleep(const struct timespec *req_time, struct timespec *remaining);
int clock_getres(clockid_t clock_id, struct timespec *res);
int clock_gettime(clockid_t clock_id, struct timespec *tp);
int clock_settime(clockid_t clock_id, const struct timespec *tp);

int clock_nanosleep(clockid_t clock_id, int flags, const struct timespec *req,
                    struct timespec *rem);
int clock_getcpuclockid(pid_t pid, clockid_t *clock_id);

struct sigevent;

int timer_create(clockid_t clock_id, struct sigevent *evp, timer_t *timerid);
int timer_delete(timer_t timerid);
int timer_settime(timer_t timerid, int flags,
                  const struct itimerspec *value, struct itimerspec *ovalue);
int timer_gettime(timer_t timerid, struct itimerspec *value);
int timer_getoverrun(timer_t timerid);

extern int getdate_err;
struct tm *getdate(const char *string);
int getdate_r(const char *string, struct tm *resbufp);

#endif /* __RCC_TIME_H__  */
