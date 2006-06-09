/* -*- c -*- */
/* $Id$ */
#ifndef __RUNLOG_H__
#define __RUNLOG_H__

/* Copyright (C) 2000-2005 Alexander Chernov <cher@ispras.ru> */

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

#include "ej_types.h"

#include <time.h>
#include <string.h>
#include <stdio.h>

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
  RUN_DISQUALIFIED     = 10,
  RUN_PENDING          = 11,
  RUN_MEM_LIMIT_ERR    = 12,
  RUN_SECURITY_ERR     = 13,    /* not used currently */
  RUN_MAX_STATUS       = 13,

  RUN_PSEUDO_FIRST     = 20,
  RUN_VIRTUAL_START    = 20,
  RUN_VIRTUAL_STOP     = 21,
  RUN_EMPTY            = 22,
  RUN_PSEUDO_LAST      = 22,

  RUN_TRANSIENT_FIRST  = 95,
  RUN_FULL_REJUDGE     = 95,    /* cannot appear in runlog */
  RUN_RUNNING          = 96,
  RUN_COMPILED         = 97,
  RUN_COMPILING        = 98,
  RUN_AVAILABLE        = 99,
  RUN_REJUDGE          = 99,
  RUN_TRANSIENT_LAST   = 99,
  RUN_LAST             = 99,
};

enum { RUN_LOG_CREATE = 1, RUN_LOG_READONLY = 2 };

int run_open(const char *path, int flags, time_t init_duration);
int run_add_record(time_t         timestamp,
                   int            nsec,
                   size_t         size,
                   ruint32_t      sha1[5],
                   ruint32_t      ip,
                   int            locale_id,
                   int            team,
                   int            problem,
                   int            language,
                   int            variant,
                   int            is_hidden);
int run_start_contest(time_t);
time_t run_get_start_time(void);
int run_change_status(int runid, int newstatus, int newtest, int newscore,
                      int judge_id);
int run_get_status(int runid);
void run_get_times(time_t *, time_t *, time_t *, time_t *);
int  run_set_duration(time_t);

time_t run_get_stop_time(void);
int    run_stop_contest(time_t);
int    run_sched_contest(time_t);
int    run_get_total(void);

time_t run_get_duration(void);

void run_get_team_usage(int, int *, size_t*);
int  run_get_attempts(int, int *, int *, int);
char *run_status_str(int, char *, int);

int run_get_fog_period(time_t, int, int);
int run_reset(time_t);
int runlog_flush(void);

unsigned char *run_unparse_ip(ej_ip_t ip);
ej_ip_t run_parse_ip(unsigned char const *buf);

int run_check_duplicate(int run_id);

struct run_header
{
  int    version;
  ej_time_t start_time;
  ej_time_t sched_time;
  ej_time_t duration;
  ej_time_t stop_time;
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
    RUN_ENTRY_IMPORTED = 0x00000800,
    RUN_ENTRY_VARIANT = 0x00001000,
    RUN_ENTRY_HIDDEN = 0x00002000,
    RUN_ENTRY_READONLY = 0x00004000,
    RUN_ENTRY_PAGES = 0x00008000,
    RUN_ENTRY_NSEC = 0x00010000,
    RUN_ENTRY_SCORE_ADJ = 0x00020000,
    RUN_ENTRY_ALL = 0x0003FFFF,
  };

struct run_entry
{
  rint32_t       submission;
  ej_time_t      timestamp;
  ej_size_t      size;
  ej_ip_t        ip;
  ruint32_t      sha1[5];
  rint32_t       team;
  rint32_t       problem;
  rint32_t       score;
  signed char    locale_id;
  unsigned char  language;
  unsigned char  status;
  signed char    test;
  unsigned char  is_imported;
  unsigned char  variant;
  unsigned char  is_hidden;
  unsigned char  is_readonly;
  unsigned char  pages;
  signed char    score_adj;     /* manual score adjustment */
  unsigned short judge_id;      /* judge required identifier */
  rint32_t       nsec;          /* nanosecond component of timestamp */
};

void run_get_header(struct run_header *out);
void run_get_all_entries(struct run_entry *out);
int run_get_entry(int run_id, struct run_entry *out);
int run_set_entry(int run_id, unsigned int mask, struct run_entry const *in);
int run_is_readonly(int run_id);
const struct run_entry *run_get_entries_ptr(void);

time_t run_get_virtual_start_time(int user_id);
time_t run_get_virtual_stop_time(int user_id, time_t cur_time);
int run_get_virtual_status(int user_id);
int run_virtual_start(int user_id, time_t, ej_ip_t, int);
int run_virtual_stop(int user_id, time_t, ej_ip_t, int);

int run_clear_entry(int run_id);
int run_squeeze_log(void);
void run_clear_variables(void);

int run_write_xml(FILE *f, int, time_t);
int unparse_runlog_xml(FILE *, const struct run_header*, size_t,
                       const struct run_entry*, int, time_t);
int parse_runlog_xml(const unsigned char *, struct run_header *,
                     size_t *, struct run_entry **);
void runlog_import_xml(FILE *flog, int flags, const unsigned char *in_xml);

int run_backup(const unsigned char *path);
int run_set_runlog(int total_entries, struct run_entry *entries);

int runlog_check(FILE *, struct run_header *, size_t, struct run_entry *);

int run_get_pages(int run_id);
int run_set_pages(int run_id, int pages);
int run_get_total_pages(int run_id);

int run_find(int first_run, int last_run,
             int team_id, int prob_id, int lang_id);
int run_undo_add_record(int run_id);
int run_is_failed_attempt(int status);
int run_is_valid_test_status(int status);
int run_is_team_report_available(int status);
int run_is_report_available(int status);

int run_status_to_str_short(unsigned char *buf, size_t size, int val);
int run_str_short_to_status(const unsigned char *str, int *pr);

#define RUN_TOO_MANY 100000
int run_get_prev_successes(int run_id);

#endif /* __RUNLOG_H__ */
