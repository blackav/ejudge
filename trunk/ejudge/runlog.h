/* -*- c -*- */
/* $Id$ */
#ifndef __RUNLOG_H__
#define __RUNLOG_H__

/* Copyright (C) 2000,2001 Alexander Chernov <cher@ispras.ru> */

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
  RUN_RUNNING          = 96,
  RUN_COMPILED         = 97,
  RUN_COMPILING        = 98,
  RUN_AVAILABLE        = 99,
  RUN_REJUDGE          = 99
};

enum { RUN_LOG_CREATE = 1 };

int run_open(char *path, int flags);
int run_add_record(unsigned long  timestamp, 
                   unsigned long  size,
                   char const    *ip,
                   int            team,
                   int            language,
                   int            problem);
int run_start_contest(unsigned long);
unsigned long run_get_start_time(void);
int run_change_status(int runid, int newstatus, int newtest);
int run_get_status(int runid);
int run_get_param(int runid, int *plang, int *pprob, int *pstat);
int run_get_record(int, unsigned long *, unsigned long *,
                   char *,
                   int *, int *, int *, int *, int *);

void run_get_times(unsigned long *, unsigned long *, unsigned long *,
                   unsigned long *);
int  run_set_duration(unsigned long);

unsigned long run_get_stop_time(void);
int           run_stop_contest(unsigned long);
int           run_sched_contest(unsigned long);
int           run_get_total(void);

void run_get_team_usage(int, int *, unsigned long*);
char *run_status_str(int, char *, int);

#endif /* __RUNLOG_H__ */
