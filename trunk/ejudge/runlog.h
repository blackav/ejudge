/* -*- c -*- */
/* $Id$ */
#ifndef __RUNLOG_H__
#define __RUNLOG_H__

/* Copyright (C) 2000-2002 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <time.h>
#include <string.h>

#define RUN_MAX_IP_LEN 15

enum
{
  RUN_OK               = 0,
  RUN_COMPILE_ERR      = 1,
  RUN_RUN_TIME_ERR     = 2,
  RUN_TIME_LIMIT_ERR   = 3,
  RUN_PRESENTATION_ERR = 4,
  RUN_WRONG_ANSWER_ERR = 5,
  RUN_CHECK_FAILED     = 6,
  RUN_PARTIAL          = 7,
  RUN_ACCEPTED         = 8,
  RUN_IGNORED          = 9,
  RUN_MAX_STATUS       = 9,
  RUN_RUNNING          = 96,
  RUN_COMPILED         = 97,
  RUN_COMPILING        = 98,
  RUN_AVAILABLE        = 99,
  RUN_REJUDGE          = 99
};

enum { RUN_LOG_CREATE = 1 };

int run_open(const char *path, int flags);
int run_add_record(time_t         timestamp, 
                   size_t         size,
                   unsigned long  sha1[5],
                   unsigned long  ip,
                   int            locale_id,
                   int            team,
                   int            language,
                   int            problem);
int run_start_contest(time_t);
time_t run_get_start_time(void);
int run_change_status(int runid, int newstatus, int newtest, int newscore);
int run_get_status(int runid);
int run_get_param(int runid, int *ploc_id, int *plang, int *pprob, int *pstat);
int run_get_record(int, time_t *, size_t *, unsigned long *,
                   unsigned long *,
                   int *, int *, int *, int *, int *, int *, int *);

void run_get_times(time_t *, time_t *, time_t *, time_t *);
int  run_set_duration(time_t);

time_t run_get_stop_time(void);
int    run_stop_contest(time_t);
int    run_sched_contest(time_t);
int    run_get_total(void);

void run_get_team_usage(int, int *, size_t*);
int  run_get_attempts(int, int *);
char *run_status_str(int, char *, int);

int run_get_fog_period(time_t, int, int);
void run_reset(void);

unsigned char *run_unparse_ip(unsigned long ip);
unsigned long run_parse_ip(unsigned char const *buf);

int run_check_duplicate(int run_id);

#endif /* __RUNLOG_H__ */
