/* -*- c -*- */
#ifndef __RUNLOG_H__
#define __RUNLOG_H__

/* Copyright (C) 2000-2024 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ej_types.h"
#include "ejudge/serve_state.h"
#include "ejudge/mixed_id.h"

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

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
  RUN_SECURITY_ERR     = 13,
  RUN_STYLE_ERR        = 14,
  RUN_WALL_TIME_LIMIT_ERR = 15,
  RUN_PENDING_REVIEW   = 16,
  RUN_REJECTED         = 17,
  RUN_SKIPPED          = 18,
  RUN_SYNC_ERR         = 19,
  OLD_RUN_MAX_STATUS   = 19, // obsoleted
  RUN_NORMAL_LAST      = 19, // may safely overlap pseudo statuses

  RUN_PSEUDO_FIRST     = 20,
  RUN_VIRTUAL_START    = 20,
  RUN_VIRTUAL_STOP     = 21,
  RUN_EMPTY            = 22,
  RUN_PSEUDO_LAST      = 22,

  RUN_SUMMONED         = 23, // summoned for oral defence
  RUN_LOW_LAST         = 23, // will be == RUN_NORMAL_LAST later

  RUN_TRANSIENT_FIRST  = 95,
  RUN_FULL_REJUDGE     = 95,    /* cannot appear in runlog */
  RUN_RUNNING          = 96,
  RUN_COMPILED         = 97,
  RUN_COMPILING        = 98,
  RUN_AVAILABLE        = 99,
  RUN_REJUDGE          = 99,
  RUN_TRANSIENT_LAST   = 99,

  RUN_STATUS_SIZE      = 100
};

/* bits for verdict bitset */
enum
{
  RUN_OK_BIT                  = 1,
  RUN_RUN_TIME_ERR_BIT        = 2,
  RUN_TIME_LIMIT_ERR_BIT      = 4,
  RUN_PRESENTATION_ERR_BIT    = 8,
  RUN_WRONG_ANSWER_ERR_BIT    = 0x10,
  RUN_CHECK_FAILED_BIT        = 0x20,
  RUN_MEM_LIMIT_ERR_BIT       = 0x40,
  RUN_SECURITY_ERR_BIT        = 0x80,
  RUN_WALL_TIME_LIMIT_ERR_BIT = 0x100,
  RUN_SKIPPED_BIT             = 0x200,
  RUN_SYNC_ERR_BIT            = 0x400,
};

enum { RUN_LOG_CREATE = 1, RUN_LOG_READONLY = 2, RUN_LOG_NOINDEX = 4, RUN_LOG_UUID_INDEX = 8 };

enum
{
  STORE_FLAGS_DEFAULT,
  STORE_FLAGS_UUID,      // each run is stored in the separate directory under its uuid
  STORE_FLAGS_UUID_BSON, // testing report is stored as BSON instead of XML
};

struct ejudge_cfg;
struct contest_desc;
struct section_global_data;
struct teamdb_state;
struct runlog_state;
typedef struct runlog_state *runlog_state_t;
struct metrics_contest_data;

runlog_state_t run_init(struct teamdb_state *);
runlog_state_t run_destroy(runlog_state_t);

int
run_open(
        runlog_state_t state,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        const unsigned char *plugin_name,
        struct metrics_contest_data *metrics,
        int flags,
        time_t init_duration,
        time_t init_sched_time,
        time_t init_finish_time);
int
run_add_record(
        runlog_state_t state,
        struct timeval *p_tv,    // filled as a result
        size_t         size,
        const ruint32_t sha1[5],
        ej_uuid_t     *puuid,    // filled as a result, if empty
        const ej_ip_t *pip,
        int            ssl_flag,
        int            locale_id,
        int            team,
        int            problem,
        int            language,
        int            eoln_type,
        int            variant,
        int            is_hidden,
        int            mime_type,
        const unsigned char *prob_uuid,
        int            store_flags,
        int            is_vcs,
        int            ext_user_kind,
        ej_mixed_id_t *ext_user,
        int            notify_driver,
        int            notify_kind,
        ej_mixed_id_t *notify_queue,
        struct run_entry *ure);
int run_start_contest(runlog_state_t, time_t);
time_t run_get_start_time(runlog_state_t);
int
run_change_status(
        runlog_state_t state,
        int runid,
        int newstatus,
        int newtest,
        int newpassedmode,
        int newscore,
        int judge_id,
        const ej_uuid_t *judge_uuid,
        unsigned int verdict_bits,
        int group_count,
        const int *group_scores,
        struct run_entry *ure);
int
run_change_status_3(
        runlog_state_t state,
        int runid,
        int newstatus,
        int newtest,
        int newpassedmode,
        int newscore,
        int is_marked,
        int has_user_score,
        int user_status,
        int user_tests_passed,
        int user_score,
        unsigned int verdict_bits,
        int group_count,
        const int *group_scores,
        struct run_entry *ure);
int
run_change_status_4(
        runlog_state_t state,
        int runid,
        int newstatus,
        struct run_entry *re);
int run_get_status(runlog_state_t state, int runid);
int run_is_imported(runlog_state_t state, int runid);
void run_get_times(runlog_state_t, int user_id, time_t *, time_t *, time_t *, time_t *,
                   time_t *);
int  run_set_duration(runlog_state_t, time_t);

time_t run_get_stop_time(runlog_state_t, int user_id, time_t current_time);
int    run_stop_contest(runlog_state_t, time_t);
int    run_sched_contest(runlog_state_t, time_t);

int    run_get_first(runlog_state_t);
int    run_get_total(runlog_state_t);

void run_get_saved_times(runlog_state_t, time_t *p_sd, time_t *p_sst, time_t*);
int run_save_times(runlog_state_t);

int run_set_finish_time(runlog_state_t state, time_t finish_time);
time_t run_get_finish_time(runlog_state_t state);

time_t run_get_duration(runlog_state_t, int user_id);

void run_get_team_usage(runlog_state_t, int, int *, size_t*);

int
run_get_attempts(
        runlog_state_t state,
        int runid,
        int *pattempts,
        int *pdisqattempts,
        int *pce_attempts,
        time_t *peffective_time,
        int skip_ce_flag,
        int ce_penalty,
        int group_merge_flag,
        int *p_group_count,
        int *p_group_scores);

int run_count_all_attempts(runlog_state_t state, int user_id, int prob_id);
int run_count_all_attempts_2(runlog_state_t state, int user_id, int prob_id, int ignored_set);
int run_count_all_attempts_3(runlog_state_t state, int user_id, int prob_id);

char *run_status_str(int, char *, int, int, int);
const unsigned char * run_status_short_str(int status);

int run_get_fog_period(runlog_state_t, time_t, int, int);
int run_reset(runlog_state_t, time_t, time_t, time_t);
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
void
run_get_ok_and_reject_count(
        runlog_state_t state,
        int user_id,
        int prob_id,
        int *p_ok_count,
        int *p_rejected_count);

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
    RE_SIZE          = 0x00000001,
    RE_IP            = 0x00000002,
    RE_SHA1          = 0x00000004,
    RE_USER_ID       = 0x00000008,
    RE_PROB_ID       = 0x00000010,
    RE_LANG_ID       = 0x00000020,
    RE_LOCALE_ID     = 0x00000040,
    RE_STATUS        = 0x00000080,
    RE_TEST          = 0x00000100,
    RE_SCORE         = 0x00000200,
    RE_IS_IMPORTED   = 0x00000400,
    RE_VARIANT       = 0x00000800,
    RE_IS_HIDDEN     = 0x00001000,
    RE_IS_READONLY   = 0x00002000,
    RE_PAGES         = 0x00004000,
    RE_SCORE_ADJ     = 0x00008000,
    RE_IS_CHECKED    = 0x00010000,
    RE_JUDGE_ID      = 0x00020000,
    RE_SSL_FLAG      = 0x00040000,
    RE_MIME_TYPE     = 0x00080000,
    RE_TOKEN_FLAGS   = 0x00100000,
    RE_TOKEN_COUNT   = 0x00200000,
    RE_IS_MARKED     = 0x00400000,
    RE_IS_SAVED      = 0x00800000,
    RE_SAVED_STATUS  = 0x01000000,
    RE_SAVED_SCORE   = 0x02000000,
    RE_SAVED_TEST    = 0x04000000,
    RE_RUN_UUID      = 0x08000000,
    RE_PASSED_MODE   = 0x10000000,
    RE_EOLN_TYPE     = 0x20000000,
    RE_STORE_FLAGS   = 0x40000000,
    RE_PROB_UUID     = 0x80000000,
    RE_JUDGE_UUID    = 0x100000000ULL,
    RE_IS_VCS        = 0x200000000ULL,
    RE_VERDICT_BITS  = 0x400000000ULL,
    RE_EXT_USER      = 0x800000000ULL,
    RE_NOTIFY        = 0x1000000000ULL,
    RE_GROUP_SCORES  = 0x2000000000ULL,
    RE_ALL           = 0x3FFFFFFFFFULL,
  };

struct run_entry
{
  rint32_t       run_id;        /* 4 */
  ej_size_t      size;          /* 4 */
  ej_time64_t    time;          /* 8 */
  rint32_t       nsec;          /* 4 */
  rint32_t       user_id;       /* 4 */
  rint32_t       prob_id;       /* 4 */
  rint32_t       lang_id;       /* 4 */
  unsigned int   ipv6_flag:1;
  unsigned int   sha256_flag:1;
  unsigned int   ssl_flag:1;
  unsigned int   judge_uuid_flag:1;
  unsigned int   is_imported:1;
  unsigned int   is_hidden:1;
  unsigned int   is_readonly:1;
  unsigned int   is_marked:1;
  unsigned int   is_saved:1;
  unsigned int   is_checked:1;
  unsigned int   is_vcs:1;
  unsigned int   _pad2:21;
  rint32_t       score;         /* 4 */
  unsigned char  status;        /* 1 */
  signed char    passed_mode;   /* 1 */
  unsigned char  store_flags;   /* 1 */
  unsigned char  variant;       /* 1 */
  rint16_t       test;          /* 2 */
  unsigned char  token_flags;   /* 1 */
  unsigned char  token_count;   /* 1 */
  union
  {
    ej_ip4_t       ip;
    unsigned char  ipv6[16];
  }              a;             /* 16 */
  union
  {
    ruint32_t      sha1[5];     /* 20 */
    unsigned char  sha256[32];  /* 32 */
  }              h;             /* 32 */
  ej_uuid_t      run_uuid;      /* 16 */
  union
  {
    ruint16_t      judge_id;    /* 2 */
    ej_uuid_t      judge_uuid;  /* 16 */
  }              j;
  ej_uuid_t      prob_uuid;     /* 16 */
  rint32_t       score_adj;     /* 4 */
  rint32_t       saved_score;   /* 4 */
  rint16_t       saved_test;    /* 2 */
  unsigned char  saved_status;  /* 1 */
  unsigned char  eoln_type;     /* 1 */
  rint16_t       locale_id;     /* 2 */
  rint16_t       mime_type;     /* 2 */
  int64_t        serial_id;     /* 8 */
  unsigned char  pages;         /* 1 */
  unsigned char  ext_user_kind; /* 1 */
  unsigned char  notify_driver; /* 1 */
  unsigned char  notify_kind;   /* 1 */
  ruint32_t      verdict_bits;  /* 4 */
  rint64_t       last_change_us;/* 8 */
  ruint32_t      group_scores;  /* 4 */
  char _pad1[4];
  ej_mixed_id_t  ext_user;      /* 16 */
  ej_mixed_id_t  notify_queue;  /* 16 */
  char _pad[32];
  /* total is 256 bytes */
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
int run_set_entry(
        runlog_state_t,
        int run_id,
        uint64_t mask,
        struct run_entry const *in,
        struct run_entry *ure);
int run_is_readonly(runlog_state_t, int run_id);
const struct run_entry *run_get_entries_ptr(runlog_state_t);

time_t run_get_virtual_start_time(runlog_state_t, int user_id);
time_t run_get_virtual_stop_time(runlog_state_t, int user_id, time_t cur_time);
int run_get_virtual_is_checked(runlog_state_t, int user_id);
int run_get_is_virtual(runlog_state_t, int user_id);
int run_virtual_start(runlog_state_t, int user_id, time_t, const ej_ip_t *, int, int);
int run_virtual_stop(runlog_state_t, int user_id, time_t, const ej_ip_t *, int, int);
int run_set_virtual_is_checked(runlog_state_t, int user_id, int is_checked, int last_change_user_id);

int run_clear_entry(runlog_state_t, int run_id);
int run_squeeze_log(runlog_state_t);
int run_has_transient_user_runs(runlog_state_t state, int user_id);
int run_clear_user_entries(runlog_state_t, int user_id);

int run_forced_clear_entry(runlog_state_t, int run_id);
int run_set_hidden(
        runlog_state_t state,
        int run_id,
        struct run_entry *ure);

int run_put_entry(runlog_state_t state, const struct run_entry *re);
int run_put_header(runlog_state_t state, const struct run_header *rh);

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
                       size_t,
                       size_t,
                       const struct run_entry*, int, int, time_t);
int parse_runlog_xml(const unsigned char *, struct run_header *,
                     size_t *, struct run_entry **, struct run_data **,
                     struct run_xml_helpers *);
void runlog_import_xml(serve_state_t, struct runlog_state *,
                       FILE *flog, int flags,
                       const unsigned char *in_xml);

int run_backup(runlog_state_t, const unsigned char *path);
int run_set_runlog(
        runlog_state_t,
        int first_entry,
        int total_entries,
        struct run_entry *entries);

int runlog_check(FILE *, const struct run_header *, size_t begin, size_t, const struct run_entry *);

int run_get_pages(runlog_state_t, int run_id);
int run_set_pages(
        runlog_state_t,
        int run_id,
        int pages,
        struct run_entry *ure);
int run_get_total_pages(runlog_state_t, int run_id);

const int *run_get_group_scores(runlog_state_t, uint32_t);

int run_find(
        runlog_state_t,
        int first_run,
        int last_run,
        int team_id,
        int prob_id,
        int lang_id,
        ej_uuid_t *p_run_uuid,
        int *p_store_flags);
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

void
run_get_all_statistics(
        runlog_state_t state,
        size_t size,
        int *counts,
        size_t *sizes);

int
run_fix_runlog_time(
        FILE *log_f,
        int run_f,
        int run_u,
        struct run_entry *runs,
        unsigned char *fix_mask);

int
run_get_max_user_id(runlog_state_t state);
int
run_get_total_users(runlog_state_t state);

void
run_entry_to_ipv6(const struct run_entry *p_re, ej_ip_t *p_ip);
void
ipv6_to_run_entry(const ej_ip_t *p_ip, struct run_entry *p_re);

// TO REMOVE
int __attribute__((deprecated))
obsolete_run_get_insert_position(runlog_state_t state, time_t t, int uid, int nsec);

int run_clear_index(runlog_state_t state, int run_id);

int run_get_user_last_run_id(runlog_state_t state, int user_id);
int run_get_user_first_run_id(runlog_state_t state, int user_id);
int run_get_user_next_run_id(runlog_state_t state, int run_id);
int run_get_user_prev_run_id(runlog_state_t state, int run_id);

int run_get_uuid_hash_state(runlog_state_t state);
int run_find_run_id_by_uuid(runlog_state_t state, const ej_uuid_t *puuid);

int run_count_tokens(runlog_state_t state, int user_id, int prob_id);

int
run_fetch_user_runs(
        runlog_state_t state,
        int low_run_id,
        int high_run_id,
        int user_id,
        int prob_id,
        int *p_count,
        struct run_entry **p_entries);

void
run_delete_user_run_header(
        runlog_state_t state,
        int user_id);

int
run_set_user_duration(
        runlog_state_t state,
        int user_id,
        int duration,
        int last_change_user_id);

int
run_set_user_stop_time(
        runlog_state_t state,
        int user_id,
        time_t stop_time,
        int last_change_user_id);

int run_is_virtual_legacy_mode(runlog_state_t state);

int
run_set_run_is_checked(
        runlog_state_t state,
        int run_id,
        int is_checked);

void
run_rebuild_user_run_index(runlog_state_t state, int user_id);

void
run_get_user_run_header_id_range(
        runlog_state_t state,
        int *p_low_user_id,
        int *p_high_user_id);

long long
run_get_last_update_time_us(runlog_state_t state);

struct user_run_header_info;

struct user_run_header_info *
run_try_user_run_header(
        runlog_state_t state,
        int user_id);

static inline _Bool __attribute__((always_inline)) run_is_normal_status(unsigned char status)
{
  return status <= RUN_LOW_LAST && (status < RUN_PSEUDO_FIRST || status > RUN_PSEUDO_LAST);
}
static inline _Bool __attribute__((always_inline)) run_is_normal_or_transient_status(unsigned char status)
{
  return (status <= RUN_LOW_LAST && (status < RUN_PSEUDO_FIRST || status > RUN_PSEUDO_LAST))
    || (status > RUN_TRANSIENT_FIRST && status <= RUN_TRANSIENT_LAST);
}
static inline _Bool __attribute__((always_inline)) run_is_invalid_status(unsigned char status)
{
  return status > RUN_TRANSIENT_LAST || (status > RUN_LOW_LAST && status <= RUN_TRANSIENT_FIRST);
}
static inline _Bool __attribute__((always_inline)) run_is_pseudo_status(unsigned char status)
{
  return status >= RUN_PSEUDO_FIRST && status <= RUN_PSEUDO_LAST;
}

void
group_scores_merge_1(
        int *p_group_count,
        int *p_group_scores,
        const int *p);

int
group_scores_calc(
        int group_count,
        const int *group_scores,
        int separate_user_score);

#endif /* __RUNLOG_H__ */
