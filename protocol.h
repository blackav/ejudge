/* -*- c -*- */
/* $Id$ */

#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

/* Copyright (C) 2002-2005 Alexander Chernov <cher@ispras.ru> */

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

#if !defined EJUDGE_SCORE_SYSTEM_DEFINED
#define EJUDGE_SCORE_SYSTEM_DEFINED
/* scoring systems */
enum { SCORE_ACM, SCORE_KIROV, SCORE_OLYMPIAD, SCORE_MOSCOW, SCORE_TOTAL };
#endif /* EJUDGE_SCORE_SYSTEM_DEFINED */

#define PROT_SERVE_STATUS_MAGIC_V1 (0xe739aa02)
struct prot_serve_status_v1
{
  unsigned int magic;
  time_t cur_time;
  time_t start_time;
  time_t sched_time;
  time_t duration;
  time_t stop_time;
  time_t freeze_time;
  int total_runs;
  int total_clars;
  int download_interval;
  unsigned char clars_disabled;
  unsigned char team_clars_disabled;
  unsigned char standings_frozen;
  unsigned char score_system;
  unsigned char clients_suspended;
  unsigned char testing_suspended;
  unsigned char is_virtual;
  unsigned char olympiad_judging_mode;
  unsigned char continuation_enabled;
};

#define PROT_SERVE_STATUS_MAGIC_V2 (0xe739aa03)
struct prot_serve_status_v2
{
  unsigned int magic;
  time_t cur_time;
  time_t start_time;
  time_t sched_time;
  time_t duration;
  time_t stop_time;
  time_t freeze_time;
  int total_runs;
  int total_clars;
  int download_interval;
  unsigned char clars_disabled;
  unsigned char team_clars_disabled;
  unsigned char standings_frozen;
  unsigned char score_system;
  unsigned char clients_suspended;
  unsigned char testing_suspended;
  unsigned char is_virtual;
  unsigned char olympiad_judging_mode;
  unsigned char continuation_enabled;
  unsigned char printing_enabled;
  unsigned char printing_suspended;
  unsigned char _pad[77];
};

#define PROT_SERVE_PACKET_MAGIC (0xe342)
struct prot_serve_packet
{
  unsigned short magic;
  short id;
};

// client->serve requests
enum
  {
    SRV_CMD_PASS_FD = 1,
    SRV_CMD_GET_ARCHIVE,
    SRV_CMD_SHOW_CLAR,
    SRV_CMD_SHOW_SOURCE,
    SRV_CMD_SHOW_REPORT,
    SRV_CMD_SUBMIT_RUN,
    SRV_CMD_SUBMIT_CLAR,
    SRV_CMD_TEAM_PAGE,
    SRV_CMD_MASTER_PAGE,
    SRV_CMD_PRIV_STANDINGS,
    SRV_CMD_VIEW_CLAR,
    SRV_CMD_VIEW_SOURCE,
    SRV_CMD_VIEW_REPORT,
    SRV_CMD_VIEW_USERS,
    SRV_CMD_PRIV_MSG,
    SRV_CMD_PRIV_REPLY,
    SRV_CMD_SUSPEND,
    SRV_CMD_RESUME,
    SRV_CMD_UPDATE_STAND,
    SRV_CMD_RESET,
    SRV_CMD_START,
    SRV_CMD_STOP,
    SRV_CMD_REJUDGE_ALL,
    SRV_CMD_REJUDGE_PROBLEM,
    SRV_CMD_SCHEDULE,
    SRV_CMD_DURATION,
    SRV_CMD_EDIT_RUN,
    SRV_CMD_VIRTUAL_START,
    SRV_CMD_VIRTUAL_STOP,
    SRV_CMD_VIRTUAL_STANDINGS,
    SRV_CMD_RESET_FILTER,
    SRV_CMD_CLEAR_RUN,
    SRV_CMD_SQUEEZE_RUNS,
    SRV_CMD_DUMP_RUNS,
    SRV_CMD_DUMP_STANDINGS,
    SRV_CMD_SET_JUDGING_MODE,
    SRV_CMD_CONTINUE,
    SRV_CMD_WRITE_XML_RUNS,
    SRV_CMD_IMPORT_XML_RUNS,
    SRV_CMD_QUIT,
    SRV_CMD_EXPORT_XML_RUNS,
    SRV_CMD_PRIV_SUBMIT_RUN,
    SRV_CMD_TEST_SUSPEND,
    SRV_CMD_TEST_RESUME,
    SRV_CMD_JUDGE_SUSPENDED,
    SRV_CMD_SET_ACCEPTING_MODE,
    SRV_CMD_PRIV_PRINT_RUN,
    SRV_CMD_PRINT_RUN,
    SRV_CMD_PRIV_DOWNLOAD_RUN,
    SRV_CMD_PRINT_SUSPEND,
    SRV_CMD_PRINT_RESUME,
    SRV_CMD_COMPARE_RUNS,
    SRV_CMD_UPLOAD_REPORT,
    SRV_CMD_REJUDGE_BY_MASK,
    SRV_CMD_NEW_RUN_FORM,
    SRV_CMD_NEW_RUN,
    SRV_CMD_VIEW_TEAM,
    SRV_CMD_SET_TEAM_STATUS,
    SRV_CMD_ISSUE_WARNING,
    SRV_CMD_SOFT_UPDATE_STAND,
    SRV_CMD_PRIV_DOWNLOAD_REPORT,
    SRV_CMD_PRIV_DOWNLOAD_TEAM_REPORT,
    SRV_CMD_DUMP_MASTER_RUNS,
    SRV_CMD_RESET_CLAR_FILTER,
    SRV_CMD_HAS_TRANSIENT_RUNS,
    SRV_CMD_GET_TEST_SUSPEND,
    SRV_CMD_VIEW_TEST_INPUT,
    SRV_CMD_VIEW_TEST_OUTPUT,
    SRV_CMD_VIEW_TEST_ANSWER,
    SRV_CMD_VIEW_TEST_ERROR,
    SRV_CMD_VIEW_TEST_CHECKER,
    SRV_CMD_VIEW_TEST_INFO,
    SRV_CMD_VIEW_AUDIT_LOG,
    SRV_CMD_DUMP_PROBLEMS,
    SRV_CMD_GET_CONTEST_TYPE,

    SRV_CMD_LAST
  };

// serve->client replies
enum
  {
    SRV_RPL_OK = 0,
    SRV_RPL_ARCHIVE_PATH = 1,
    SRV_RPL_DATA,

    SRV_RPL_LAST
  };

// serve error message codes
enum
  {
    SRV_ERR_NO_ERROR = 0,
    SRV_ERR_UNKNOWN_ERROR,
    SRV_ERR_BAD_SOCKET_NAME,
    SRV_ERR_SYSTEM_ERROR,
    SRV_ERR_CONNECT_FAILED,
    SRV_ERR_NOT_CONNECTED,
    SRV_ERR_PROTOCOL,
    SRV_ERR_EOF_FROM_SERVER,
    SRV_ERR_READ_FROM_SERVER,
    SRV_ERR_WRITE_TO_SERVER,
    SRV_ERR_NOT_SUPPORTED,
    SRV_ERR_ACCESS_DENIED,
    SRV_ERR_BAD_USER_ID,
    SRV_ERR_BAD_CONTEST_ID,
    SRV_ERR_CLARS_DISABLED,
    SRV_ERR_BAD_CLAR_ID,
    SRV_ERR_SOURCE_DISABLED,
    SRV_ERR_BAD_RUN_ID,
    SRV_ERR_BAD_PROB_ID,
    SRV_ERR_BAD_LANG_ID,
    SRV_ERR_REPORT_DISABLED,
    SRV_ERR_DOWNLOAD_DISABLED,
    SRV_ERR_DOWNLOAD_TOO_OFTEN,
    SRV_ERR_TRY_AGAIN,
    SRV_ERR_CONTEST_STARTED,
    SRV_ERR_CONTEST_NOT_STARTED,
    SRV_ERR_CONTEST_FINISHED,
    SRV_ERR_CONTEST_NOT_FINISHED,
    SRV_ERR_QUOTA_EXCEEDED,
    SRV_ERR_SUBJECT_TOO_LONG,
    SRV_ERR_DUPLICATED_RUN,
    SRV_ERR_NO_PERMS,
    SRV_ERR_BAD_DURATION,
    SRV_ERR_BAD_STATUS,
    SRV_ERR_ONLY_VIRTUAL,
    SRV_ERR_READONLY_RUN,
    SRV_ERR_PAGES_QUOTA,
    SRV_ERR_ALREADY_PRINTED,
    SRV_ERR_BAD_SESSION_ID,
    SRV_ERR_LANGUAGE_DISABLED,
    SRV_ERR_FILE_NOT_EXIST,
    SRV_ERR_FILTER_EXPR,
    SRV_ERR_TRANSIENT_RUNS,
    SRV_ERR_BAD_TEST_NUM,
    SRV_ERR_BAD_XML,
    SRV_ERR_REPORT_NOT_AVAILABLE,

    SRV_ERR_LAST
  };

struct prot_serve_pkt_get_archive
{
  struct prot_serve_packet b;

  int user_id;
  int contest_id;
  int locale_id;
};

struct prot_serve_pkt_list_runs
{
  struct prot_serve_packet b;

  int user_id;
  int contest_id;
  int locale_id;
  unsigned int flags;
  int form_start_len;
  unsigned char data[1];
};

struct prot_serve_pkt_show_item
{
  struct prot_serve_packet b;

  int user_id;
  int contest_id;
  int locale_id;
  int item_id;
};

struct prot_serve_pkt_submit_run
{
  struct prot_serve_packet b;

  int user_id;
  int contest_id;
  int locale_id;
  unsigned long ip;
  int prob_id;
  int lang_id;
  int variant;
  int run_len;
  unsigned char data[1];
};

struct prot_serve_pkt_submit_clar
{
  struct prot_serve_packet b;

  int user_id;
  int contest_id;
  int locale_id;
  unsigned long ip;
  int dest_user_id;
  int ref_clar_id;
  int dest_login_len;
  int subj_len;
  int text_len;
  unsigned char data[3];
};

struct prot_serve_pkt_team_page
{
  struct prot_serve_packet b;

  int locale_id;
  unsigned int flags;
  int self_url_len;
  int hidden_vars_len;
  int extra_args_len;
  unsigned char data[3];
};

#ifndef __MASTER_PAGE_ENUM_DEFINED__
#define __MASTER_PAGE_ENUM_DEFINED__
enum
{
  PRIV_LEVEL_USER = 0,
  PRIV_LEVEL_JUDGE,
  PRIV_LEVEL_ADMIN
};
#endif /* __MASTER_PAGE_ENUM_DEFINED__ */

struct prot_serve_pkt_master_page
{
  struct prot_serve_packet b;

  unsigned long long session_id;
  int user_id;
  int contest_id;
  int locale_id;
  unsigned long ip;
  int priv_level;
  int first_run;
  int last_run;
  int mode_clar;
  int first_clar;
  int last_clar;
  int self_url_len;
  int filter_expr_len;
  int hidden_vars_len;
  int extra_args_len;
  unsigned char data[4];
};

struct prot_serve_pkt_standings
{
  struct prot_serve_packet b;

  int user_id;
  int contest_id;
  int locale_id;
  int priv_level;
  int self_url_len;
  int hidden_vars_len;
  int extra_args_len;
  unsigned char data[3];
};

struct prot_serve_pkt_view
{
  struct prot_serve_packet b;

  int item;
  int item2;
  unsigned int flags;
  int self_url_len;
  int hidden_vars_len;
  int extra_args_len;
  unsigned char data[3];
};

struct prot_serve_pkt_simple
{
  struct prot_serve_packet b;

  union {
    time_t t;
    int i;
  } v;
};

enum
  {
    PROT_SERVE_RUN_UID_SET = 1,
    PROT_SERVE_RUN_LOGIN_SET = 2,
    PROT_SERVE_RUN_PROB_SET = 4,
    PROT_SERVE_RUN_LANG_SET = 8,
    PROT_SERVE_RUN_STATUS_SET = 16,
    PROT_SERVE_RUN_IMPORTED_SET = 32,
    PROT_SERVE_RUN_VARIANT_SET = 64,
    PROT_SERVE_RUN_HIDDEN_SET = 128,
    PROT_SERVE_RUN_TESTS_SET = 256,
    PROT_SERVE_RUN_SCORE_SET = 512,
    PROT_SERVE_RUN_READONLY_SET = 1024,
    PROT_SERVE_RUN_PAGES_SET = 2048,
    PROT_SERVE_RUN_SOURCE_SET = 4096,
    PROT_SERVE_RUN_SCORE_ADJ_SET = 8192,
  };

struct prot_serve_pkt_run_info
{
  struct prot_serve_packet b;

  int run_id;
  int mask;
  int user_id;
  int prob_id;
  int lang_id;
  int status;
  int is_imported;
  int variant;
  int is_hidden;
  int tests;
  int score;
  int score_adj;
  int is_readonly;
  int pages;
  unsigned long ip;
  int user_login_len;
  int run_src_len;
  unsigned char data[2];
};

struct prot_serve_pkt_archive_path
{
  struct prot_serve_packet b;

  int token;
  int path_len;
  unsigned char data[1];
};

struct prot_serve_pkt_upload_report
{
  struct prot_serve_packet b;

  int user_id;
  int contest_id;
  int run_id;
  unsigned int flags;
  int report_size;
  unsigned char data[1];
};

struct prot_serve_pkt_reset_filter
{
  struct prot_serve_packet b;

  unsigned long long session_id;
  int user_id;
  int contest_id;
};

struct prot_serve_pkt_rejudge_by_mask
{
  struct prot_serve_packet b;
  int mask_size;
  unsigned long mask[1];
};

struct prot_serve_pkt_user_info
{
  struct prot_serve_packet b;

  int user_id;
  int status;
  int txt_len;
  int cmt_len;
  unsigned char data[2];
};

struct prot_serve_pkt_data
{
  struct prot_serve_packet b;
  int data_len;
  unsigned char data[1];
};

unsigned char const *protocol_strerror(int n);
unsigned char const *protocol_priv_level_str(int n);

#endif /* __PROTOCOL_H__ */
