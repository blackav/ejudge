/* -*- c -*- */
/* $Id$ */
#ifndef __RUNLOG_H__
#define __RUNLOG_H__

/* Copyright (C) 2000-2008 Alexander Chernov <cher@ejudge.ru> */

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
#include "serve_state.h"

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

struct teamdb_state;
struct runlog_state;
typedef struct runlog_state *runlog_state_t;

runlog_state_t run_init(struct teamdb_state *);
runlog_state_t run_destroy(runlog_state_t);

int run_open(runlog_state_t state, const char *path, int flags,
             time_t init_duration, time_t init_finish_time);
int run_add_record(runlog_state_t state,
                   time_t         timestamp,
                   int            nsec,
                   size_t         size,
                   ruint32_t      sha1[5],
                   ruint32_t      ip,
                   int            ssl_flag,
                   int            locale_id,
                   int            team,
                   int            problem,
                   int            language,
                   int            variant,
                   int            is_hidden,
                   int            mime_type);
int run_start_contest(runlog_state_t, time_t);
time_t run_get_start_time(runlog_state_t);
int run_change_status(runlog_state_t state, int runid, int newstatus,
                      int newtest, int newscore, int judge_id);
int run_get_status(runlog_state_t state, int runid);
int run_is_imported(runlog_state_t state, int runid);
void run_get_times(runlog_state_t, time_t *, time_t *, time_t *, time_t *,
                   time_t *);
int  run_set_duration(runlog_state_t, time_t);

time_t run_get_stop_time(runlog_state_t);
int    run_stop_contest(runlog_state_t, time_t);
int    run_sched_contest(runlog_state_t, time_t);
int    run_get_total(runlog_state_t);

void run_get_saved_times(runlog_state_t, time_t *p_sd, time_t *p_sst, time_t*);
int run_save_times(runlog_state_t);

int run_set_finish_time(runlog_state_t state, time_t finish_time);
time_t run_get_finish_time(runlog_state_t state);

time_t run_get_duration(runlog_state_t);

void run_get_team_usage(runlog_state_t, int, int *, size_t*);
int  run_get_attempts(runlog_state_t, int, int *, int *, int);
int run_count_all_attempts(runlog_state_t state, int user_id, int prob_id);
char *run_status_str(int, char *, int, int, int);

int run_get_fog_period(runlog_state_t, time_t, int, int);
int run_reset(runlog_state_t, time_t, time_t);
int runlog_flush(runlog_state_t);

int run_check_duplicate(runlog_state_t, int run_id);
int run_find_duplicate(runlog_state_t state,
                       int user_id,
                       int prob_id,
                       int lang_id,
                       int variant,
                       size_t size,
                       ruint32_t sha1[]);
void run_get_accepted_set(runlog_state_t state, int user_id, int accepting_mode,
                          int max_prob, unsigned char *acc_set);

/* structure size is 128 bytes */
struct run_header
{
  unsigned char version;        /* current version is 2 */
  unsigned char _pad1[19];      /* skip fields of version 1 header */
  unsigned char byte_order;     /* 0 - little-endian, the only supported yet */
  unsigned char _pad2[11];      /* pad to the 32-byte boundary */
  ej_time64_t start_time;
  ej_time64_t sched_time;
  ej_time64_t duration;
  ej_time64_t stop_time;
  ej_time64_t finish_time;      /* when the contest expected to finish */
  ej_time64_t saved_duration;
  ej_time64_t saved_stop_time;
  ej_time64_t saved_finish_time;
  unsigned char _pad3[32];
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
    RUN_ENTRY_EXAMINABLE = 0x00040000,
    RUN_ENTRY_ALL = 0x0007FFFF,
  };

/* structure size is 128 bytes */
struct run_entry
{
  rint32_t       run_id;        /* 4 */
  ej_size_t      size;          /* 4 */
  ej_time64_t    time;          /* 8 */
  rint32_t       nsec;          /* 4 */
  rint32_t       user_id;       /* 4 */
  rint32_t       prob_id;       /* 4 */
  rint32_t       lang_id;       /* 4 */
  union
  {
    ej_ip_t        ip;
    unsigned char  ip6[16];
  }              a;             /* 16 */
  ruint32_t      sha1[5];       /* 20 */
  rint32_t       score;         /* 4 */
  rint32_t       test;          /* 4 */
  rint32_t       score_adj;     /* 4 */
  rint16_t       locale_id;     /* 2 */
  ruint16_t      judge_id;      /* 2 */
  unsigned char  status;        /* 1 */
  unsigned char  is_imported;   /* 1 */
  unsigned char  variant;       /* 1 */
  unsigned char  is_hidden;     /* 1 */
  unsigned char  is_readonly;   /* 1 */
  unsigned char  pages;         /* 1 */
  unsigned char  ipv6_flag;     /* 1 */
  unsigned char  ssl_flag;      /* 1 */
  rint16_t       mime_type;     /* 2 */
  unsigned char  is_examinable; /* 1 */
  unsigned char  _pad3[1];      /* 1 */
  int            examiners[3];  /* 12 */
  int            exam_score[3]; /* 12 */
  /* total is 120 bytes */
  unsigned char  _pad2[8];
};

struct run_file
{
  unsigned char *data;
  size_t size;
};
struct run_data
{
  struct run_file source;
  struct run_file audit;
};

void run_get_header(runlog_state_t, struct run_header *out);
void run_get_all_entries(runlog_state_t, struct run_entry *out);
int run_get_entry(runlog_state_t, int run_id, struct run_entry *out);
int run_get_virtual_start_entry(runlog_state_t, int user, struct run_entry *);
int run_set_entry(runlog_state_t, int run_id, unsigned int mask,
                  struct run_entry const *in);
int run_is_readonly(runlog_state_t, int run_id);
const struct run_entry *run_get_entries_ptr(runlog_state_t);

time_t run_get_virtual_start_time(runlog_state_t, int user_id);
time_t run_get_virtual_stop_time(runlog_state_t, int user_id, time_t cur_time);
int run_get_virtual_status(runlog_state_t, int user_id);
int run_virtual_start(runlog_state_t, int user_id, time_t, ej_ip_t, int, int);
int run_virtual_stop(runlog_state_t, int user_id, time_t, ej_ip_t, int, int);
int run_get_virtual_info(runlog_state_t state, int user_id,
                         struct run_entry *vs, struct run_entry *ve);

int run_clear_entry(runlog_state_t, int run_id);
int run_squeeze_log(runlog_state_t);
void run_clear_variables(runlog_state_t);
int run_has_transient_user_runs(runlog_state_t state, int user_id);

int run_forced_clear_entry(runlog_state_t, int run_id);
int run_forced_set_hidden(runlog_state_t state, int run_id);
int run_forced_set_judge_id(runlog_state_t state, int run_id, int judge_id);

struct run_xml_helpers
{
  void *user_data;
  int (*parse_login_func)(struct run_xml_helpers *self,
                          const unsigned char *str);
  int (*parse_prob_func)(struct run_xml_helpers *self,
                         const unsigned char *str);
  int (*parse_lang_func)(struct run_xml_helpers *self,
                         const unsigned char *str);
};

int run_write_xml(runlog_state_t, void *, const struct contest_desc *cnts,
                  FILE *f, int, int, time_t);
int unparse_runlog_xml(serve_state_t,
                       const struct contest_desc *cnts,
                       FILE *, const struct run_header*,
                       size_t, const struct run_entry*, int, int, time_t);
int parse_runlog_xml(const unsigned char *, struct run_header *,
                     size_t *, struct run_entry **, struct run_data **,
                     struct run_xml_helpers *);
void runlog_import_xml(serve_state_t, struct runlog_state *,
                       FILE *flog, int flags,
                       const unsigned char *in_xml);

int run_backup(runlog_state_t, const unsigned char *path);
int run_set_runlog(runlog_state_t, int total_entries,
                   struct run_entry *entries);

int runlog_check(FILE *, struct run_header *, size_t, struct run_entry *);

int run_get_pages(runlog_state_t, int run_id);
int run_set_pages(runlog_state_t, int run_id, int pages);
int run_get_total_pages(runlog_state_t, int run_id);

int run_find(runlog_state_t, int first_run, int last_run,
             int team_id, int prob_id, int lang_id);
int run_undo_add_record(runlog_state_t, int run_id);
int run_is_failed_attempt(int status);
int run_is_valid_test_status(int status);
int run_is_valid_status(int status);
int run_is_valid_user_status(int status);
int run_is_team_report_available(int status);
int run_is_report_available(int status);
int run_is_source_available(int status);

int run_status_to_str_short(unsigned char *buf, size_t size, int val);
int run_str_short_to_status(const unsigned char *str, int *pr);

#define RUN_TOO_MANY 100000
int run_get_prev_successes(runlog_state_t, int run_id);

int run_count_examinable_runs(runlog_state_t state, int prob_id,
                              int exam_num, int *p_assigned);

#endif /* __RUNLOG_H__ */
