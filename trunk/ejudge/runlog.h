/* -*- c -*- */
/* $Id$ */
#ifndef __RUNLOG_H__
#define __RUNLOG_H__

/* Copyright (C) 2000-2003 Alexander Chernov <cher@ispras.ru> */

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

#include <time.h>
#include <string.h>

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
  RUN_VIRTUAL_START    = 20,
  RUN_VIRTUAL_STOP     = 21,
  RUN_EMPTY            = 22,
  RUN_RUNNING          = 96,
  RUN_COMPILED         = 97,
  RUN_COMPILING        = 98,
  RUN_AVAILABLE        = 99,
  RUN_REJUDGE          = 99
};

enum { RUN_LOG_CREATE = 1, RUN_LOG_READONLY = 2 };

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
int run_get_param(int runid, int *pteam_id, int *ploc_id, int *plang, int *pprob, int *pstat);
int run_get_record(int, time_t *, size_t *, unsigned long *,
                   unsigned long *,
                   int *, int *, int *, int *, int *, int *, int *);

void run_get_times(time_t *, time_t *, time_t *, time_t *);
int  run_set_duration(time_t);

time_t run_get_stop_time(void);
int    run_stop_contest(time_t);
int    run_sched_contest(time_t);
int    run_get_total(void);

time_t run_get_duration(void);

void run_get_team_usage(int, int *, size_t*);
int  run_get_attempts(int, int *, int);
char *run_status_str(int, char *, int);

int run_get_fog_period(time_t, int, int);
void run_reset(void);

unsigned char *run_unparse_ip(unsigned long ip);
unsigned long run_parse_ip(unsigned char const *buf);

int run_check_duplicate(int run_id);

struct run_header
{
  int    version;
  time_t start_time;
  time_t sched_time;
  time_t duration;
  time_t stop_time;
  unsigned char pad[44];
};

enum
  {
    RUN_ENTRY_TIME   = 0x00000001,
    RUN_ENTRY_SIZE   = 0x00000002,
    RUN_ENTRY_IP     = 0x00000004,
    RUN_ENTRY_SHA1   = 0x00000008,
    RUN_ENTRY_USER   = 0x00000010,
    RUN_ENTRY_PROB   = 0x00000020,
    RUN_ENTRY_LANG   = 0x00000040,
    RUN_ENTRY_LOCALE = 0x00000080,
    RUN_ENTRY_STATUS = 0x00000100,
    RUN_ENTRY_TEST   = 0x00000200,
    RUN_ENTRY_SCORE  = 0x00000400,
  };

struct run_entry
{
  int            submission;
  time_t         timestamp;
  size_t         size;
  unsigned long  ip;
  unsigned long  sha1[5];
  int            team;
  int            problem;
  int            score;
  signed char    locale_id;
  unsigned char  language;
  unsigned char  status;
  signed char    test;
  unsigned char  pad[12];
};

void run_get_header(struct run_header *out);
void run_get_all_entries(struct run_entry *out);
int run_get_entry(int run_id, struct run_entry *out);
int run_set_entry(int run_id, unsigned int mask, struct run_entry const *in);

int run_build_virtual_table(void);
time_t run_get_virtual_start_time(int user_id);
time_t run_get_virtual_stop_time(int user_id, time_t cur_time);
int run_get_virtual_status(int user_id);
int run_virtual_start(int user_id, time_t, unsigned long);
int run_virtual_stop(int user_id, time_t, unsigned long);

int run_clear_entry(int run_id);
int run_squeeze_log(void);
void run_clear_variables(void);

#endif /* __RUNLOG_H__ */
