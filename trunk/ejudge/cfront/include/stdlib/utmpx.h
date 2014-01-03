/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `utmpx.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1997, 1998, 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef __RCC_UTMPX_H__
#define __RCC_UTMPX_H__ 1

#include <features.h>
#include <sys/time.h>
#include <sys/types.h>
#include <paths.h>

int enum
{
  __UT_LINESIZE = 32,
#define __UT_LINESIZE __UT_LINESIZE
  __UT_NAMESIZE = 32,
#define __UT_NAMESIZE __UT_NAMESIZE
  __UT_HOSTSIZE = 256,
#define __UT_HOSTSIZE __UT_HOSTSIZE
};

/* The structure describing the status of a terminated process.  This
   type is used in `struct utmpx' below.  */
struct __exit_status
{
  short int e_termination;
  short int e_exit;
};

/* The structure describing an entry in the user accounting database.  */
struct utmpx
{
  short int ut_type;
  pid_t ut_pid;
  char ut_line[__UT_LINESIZE];
  char ut_id[4];
  char ut_user[__UT_NAMESIZE];
  char ut_host[__UT_HOSTSIZE];
  struct __exit_status ut_exit;
  long int ut_session;
  struct timeval ut_tv;
  int32_t ut_addr_v6[4];
  char __unused[20];
};

/* Values for the `ut_type' field of a `struct utmpx'.  */
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

/* Compatibility names for the strings of the canonical file names.  */
#define _PATH_UTMPX  _PATH_UTMP 
#define _PATH_WTMPX  _PATH_WTMP 
# define UTMPX_FILE     _PATH_UTMPX
# define UTMPX_FILENAME _PATH_UTMPX
# define WTMPX_FILE     _PATH_WTMPX
# define WTMPX_FILENAME _PATH_WTMPX

/* For the getutmp{,x} functions we need the `struct utmp'.  */
struct utmp;

void setutxent(void);
void endutxent(void);
struct utmpx *getutxent(void);
struct utmpx *getutxid(const struct utmpx *id);
struct utmpx *getutxline(const struct utmpx *line);
struct utmpx *pututxline(const struct utmpx *utmpx);
int utmpxname(const char *file);
void updwtmpx(const char *wtmpx_file, const struct utmpx *utmpx);
void getutmp(const struct utmpx *utmpx, struct utmp *utmp);
void getutmpx(const struct utmp *utmp, struct utmpx *utmpx);

#endif /* __RCC_UTMPX_H__ */
