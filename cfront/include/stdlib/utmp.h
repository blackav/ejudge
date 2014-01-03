/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_UTMP_H__
#define __RCC_UTMP_H__ 1

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
#include <paths.h>
#include <sys/types.h>
#include <sys/time.h>

int enum
{
  UT_LINESIZE = 32,
#define UT_LINESIZE UT_LINESIZE
  UT_NAMESIZE = 32,
#define UT_NAMESIZE UT_NAMESIZE
  UT_HOSTSIZE = 256,
#define UT_HOSTSIZE UT_HOSTSIZE
};

struct lastlog
{
  time_t ll_time;
  char ll_line[UT_LINESIZE];
  char ll_host[UT_HOSTSIZE];
};

struct exit_status
{
  short int e_termination;
  short int e_exit;
};

struct utmp
{
  short int ut_type;
  pid_t ut_pid;
  char ut_line[UT_LINESIZE];
  char ut_id[4];
  char ut_user[UT_NAMESIZE];
  char ut_host[UT_HOSTSIZE];
  struct exit_status ut_exit;
  long int ut_session;
  struct timeval ut_tv;
  int ut_addr_v6[4];
  char __unused[20];
};

#define ut_name         ut_user
#define ut_time         ut_tv.tv_sec
#define ut_xtime        ut_tv.tv_sec
#define ut_addr         ut_addr_v6[0]

#ifndef RUN_LVL
int enum
{
  EMPTY = 0,
#define EMPTY EMPTY
  RUN_LVL = 1,
#define RUN_LVL RUN_LVL
  BOOT_TIME = 2,
#define BOOT_TIME BOOT_TIME
  NEW_TIME = 3,
#define NEW_TIME NEW_TIME
  OLD_TIME = 4,
#define OLD_TIME OLD_TIME
  INIT_PROCESS = 5,
#define INIT_PROCESS INIT_PROCESS
  LOGIN_PROCESS = 6,
#define LOGIN_PROCESS LOGIN_PROCESS
  USER_PROCESS = 7,
#define USER_PROCESS USER_PROCESS
  DEAD_PROCESS = 8,
#define DEAD_PROCESS DEAD_PROCESS
  ACCOUNTING = 9,
#define ACCOUNTING ACCOUNTING
  UT_UNKNOWN = EMPTY,
#define UT_UNKNOWN UT_UNKNOWN
};
#endif /* RUN_LVL */

#define _HAVE_UT_TYPE   1
#define _HAVE_UT_PID    1
#define _HAVE_UT_ID     1
#define _HAVE_UT_TV     1
#define _HAVE_UT_HOST   1

#define UTMP_FILE     _PATH_UTMP
#define UTMP_FILENAME _PATH_UTMP
#define WTMP_FILE     _PATH_WTMP
#define WTMP_FILENAME _PATH_WTMP

int login_tty(int fd);
void login(const struct utmp *entry);
int logout(const char *ut_line);
void logwtmp(const char *ut_line, const char *ut_name, const char *ut_host);
void updwtmp(const char *wtmp_file, const struct utmp *utmp);
int utmpname(const char *file);
struct utmp *getutent(void);
void setutent(void);
void endutent(void);
struct utmp *getutid(const struct utmp *id);
struct utmp *getutline(const struct utmp *line);
struct utmp *pututline(const struct utmp *utmp_ptr);
int getutent_r(struct utmp *buffer, struct utmp **result);
int getutid_r(const struct utmp *id, struct utmp *buffer,struct utmp **result);
int getutline_r(const struct utmp *line,
                struct utmp *buffer, struct utmp **result);

#endif /* __RCC_UTMP_H__  */
