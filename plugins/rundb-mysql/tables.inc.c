/* -*- mode: c -*- */

/* Copyright (C) 2008-2022 Alexander Chernov <cher@ejudge.ru> */

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

static const char create_runs_query[] =
"CREATE TABLE %sruns( "
"        serial_id INT(18) NOT NULL PRIMARY KEY AUTO_INCREMENT, "
"        run_id INT UNSIGNED NOT NULL, "
"        contest_id INT UNSIGNED NOT NULL, "
"        size INT UNSIGNED NOT NULL DEFAULT 0, "
"        create_time DATETIME(6) NOT NULL, "
"        create_nsec INT UNSIGNED NOT NULL DEFAULT 0, "
"        user_id INT UNSIGNED NOT NULL, "
"        prob_id INT UNSIGNED NOT NULL DEFAULT 0, "
"        lang_id INT UNSIGNED NOT NULL DEFAULT 0, "
"        status INT NOT NULL DEFAULT 99, "
"        ssl_flag TINYINT NOT NULL DEFAULT 0, "
"        ip_version TINYINT NOT NULL DEFAULT 4, "
"        ip VARCHAR(64) DEFAULT NULL, "
"        hash VARCHAR (128) DEFAULT NULL, "
"        run_uuid CHAR(40) DEFAULT NULL, "
"        score INT NOT NULL DEFAULT -1, "
"        test_num INT NOT NULL DEFAULT -1, "
"        score_adj INT NOT NULL DEFAULT 0, "
"        locale_id INT NOT NULL DEFAULT 0, "
"        judge_id INT NOT NULL DEFAULT 0, "
"        variant INT NOT NULL DEFAULT 0, "
"        pages INT NOT NULL DEFAULT 0, "
"        is_imported TINYINT NOT NULL DEFAULT 0, "
"        is_hidden TINYINT NOT NULL DEFAULT 0, "
"        is_readonly TINYINT NOT NULL DEFAULT 0, "
"        mime_type VARCHAR(64) DEFAULT NULL, "
"        last_change_time DATETIME DEFAULT NULL, "
"        last_change_nsec INT UNSIGNED NOT NULL DEFAULT 0, "
"        is_marked TINYINT NOT NULL DEFAULT 0, "
"        is_saved TINYINT NOT NULL DEFAULT 0, "
"        saved_status INT NOT NULL DEFAULT 0, "
"        saved_score INT NOT NULL DEFAULT 0, "
"        saved_test INT NOT NULL DEFAULT 0, "
"        passed_mode TINYINT NOT NULL DEFAULT 0, "
"        eoln_type TINYINT NOT NULL DEFAULT 0, "
"        store_flags INT NOT NULL DEFAULT 0, "
"        token_flags INT NOT NULL DEFAULT 0, "
"        token_count INT NOT NULL DEFAULT 0, "
"        prob_uuid VARCHAR(40) DEFAULT NULL, "
"        is_checked TINYINT NOT NULL DEFAULT 0, "
"        judge_uuid VARCHAR(40) DEFAULT NULL, "
"        UNIQUE KEY runs_run_contest_id_idx(run_id, contest_id), "
"        KEY runs_contest_id_idx (contest_id) "
"        ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;";

struct run_entry_internal
{
  int serial_id;                /* 0 */
  int run_id;
  int contest_id;
  int size;
  struct timeval create_tv;
  //time_t create_time;
  int create_nsec;              /* 5 */
  int user_id;
  int prob_id;
  int lang_id;
  int status;
  int ssl_flag;                 /* 10 */
  int ip_version;
  ej_ip_t ip;
  unsigned char *hash;
  unsigned char *run_uuid;
  int score;                    /* 15 */
  int test_num;
  int score_adj;
  int locale_id;
  int judge_id;
  int variant;                  /* 20 */
  int pages;
  int is_imported;
  int is_hidden;
  int is_readonly;
  unsigned char *mime_type;     /* 25 */
  time_t last_change_time;
  int last_change_nsec;
  int is_marked;
  int is_saved;
  int saved_status;             /* 30 */
  int saved_score;
  int saved_test;
  int passed_mode;
  int eoln_type;
  int store_flags;              /* 35 */
  int token_flags;
  int token_count;
  unsigned char *prob_uuid;
  int is_checked;
  unsigned char *judge_uuid;    /* 40 */
};

enum { RUNS_ROW_WIDTH = 41 };

#define RUNS_OFFSET(f) XOFFSET(struct run_entry_internal, f)
static const struct common_mysql_parse_spec runs_spec[RUNS_ROW_WIDTH] =
{
  { 0, 'd', "serial_id", RUNS_OFFSET(serial_id), 0 },
  { 0, 'd', "run_id", RUNS_OFFSET(run_id), 0 },
  { 0, 'd', "contest_id", RUNS_OFFSET(contest_id), 0 },
  { 0, 'd', "size", RUNS_OFFSET(size), 0 },
  { 0, 'T', "create_time", RUNS_OFFSET(create_tv), 0 },
  { 0, 'd', "create_nsec", RUNS_OFFSET(create_nsec), 0 },
  { 0, 'd', "user_id", RUNS_OFFSET(user_id), 0, },
  { 0, 'd', "prob_id", RUNS_OFFSET(prob_id), 0, },
  { 0, 'd', "lang_id", RUNS_OFFSET(lang_id), 0, },
  { 0, 'd', "status", RUNS_OFFSET(status), 0, },
  { 0, 'b', "ssl_flag", RUNS_OFFSET(ssl_flag), 0 },
  { 0, 'd', "ip_version", RUNS_OFFSET(ip_version), 0 },
  { 0, 'I', "ip", RUNS_OFFSET(ip), 0, },
  { 1, 's', "hash", RUNS_OFFSET(hash), 0 },
  { 1, 's', "run_uuid", RUNS_OFFSET(run_uuid), 0 },
  { 0, 'd', "score", RUNS_OFFSET(score), 0 },
  { 0, 'd', "test_num", RUNS_OFFSET(test_num), 0 },
  { 0, 'd', "score_adj", RUNS_OFFSET(score_adj), 0 },
  { 0, 'd', "locale_id", RUNS_OFFSET(locale_id), 0 },
  { 0, 'd', "judge_id", RUNS_OFFSET(judge_id), 0 },
  { 0, 'd', "variant", RUNS_OFFSET(variant), 0 },
  { 0, 'd', "pages", RUNS_OFFSET(pages), 0 },
  { 0, 'b', "is_imported", RUNS_OFFSET(is_imported), 0 },
  { 0, 'b', "is_hidden", RUNS_OFFSET(is_hidden), 0 },
  { 0, 'b', "is_readonly", RUNS_OFFSET(is_readonly), 0 },
  { 1, 's', "mime_type", RUNS_OFFSET(mime_type), 0 },
  { 1, 't', "last_change_time", RUNS_OFFSET(last_change_time), 0 },
  { 0, 'd', "last_change_nsec", RUNS_OFFSET(last_change_nsec), 0 },
  { 0, 'b', "is_marked", RUNS_OFFSET(is_marked), 0 },
  { 0, 'b', "is_saved", RUNS_OFFSET(is_saved), 0 },
  { 0, 'd', "saved_status", RUNS_OFFSET(saved_status), 0 },
  { 0, 'd', "saved_score", RUNS_OFFSET(saved_score), 0 },
  { 0, 'd', "saved_test", RUNS_OFFSET(saved_test), 0 },
  { 0, 'd', "passed_mode", RUNS_OFFSET(passed_mode), 0 },
  { 0, 'd', "eoln_type", RUNS_OFFSET(eoln_type), 0 },
  { 0, 'd', "store_flags", RUNS_OFFSET(store_flags), 0 },
  { 0, 'd', "token_flags", RUNS_OFFSET(token_flags), 0 },
  { 0, 'd', "token_count", RUNS_OFFSET(token_count), 0 },
  { 1, 's', "prob_uuid", RUNS_OFFSET(prob_uuid), 0 },
  { 0, 'b', "is_checked", RUNS_OFFSET(is_checked), 0 },
  { 1, 's', "prob_uuid", RUNS_OFFSET(judge_uuid), 0 },
};

enum
{
  RH_START_TIME        = 0x00000001,
  RH_SCHED_TIME        = 0x00000002,
  RH_DURATION          = 0x00000004,
  RH_STOP_TIME         = 0x00000008,
  RH_FINISH_TIME       = 0x00000010,
  RH_SAVED_DURATION    = 0x00000020,
  RH_SAVED_STOP_TIME   = 0x00000040,
  RH_SAVED_FINISH_TIME = 0x00000080,
  RH_ALL               = 0x000000FF,
};

static const char create_runheaders_query[] =
"CREATE TABLE %srunheaders( "
"        contest_id INT UNSIGNED NOT NULL, "
"        start_time DATETIME DEFAULT NULL, "
"        sched_time DATETIME DEFAULT NULL, "
"        duration INT UNSIGNED, "
"        stop_time DATETIME DEFAULT NULL, "
"        finish_time DATETIME DEFAULT NULL, "
"        saved_duration INT UNSIGNED, "
"        saved_stop_time DATETIME DEFAULT NULL, "
"        saved_finish_time DATETIME DEFAULT NULL, "
"        last_change_time DATETIME DEFAULT NULL, "
"        last_change_nsec INT UNSIGNED NOT NULL, "
"        PRIMARY KEY (contest_id)"
"        );";

struct run_header_internal
{
  int contest_id;
  time_t start_time;
  time_t sched_time;
  int duration;
  time_t stop_time;
  time_t finish_time;
  int saved_duration;
  time_t saved_stop_time;
  time_t saved_finish_time;
  time_t last_change_time;
  int last_change_nsec;
};

enum { HEADERS_ROW_WIDTH = 11 };

#define HEADERS_OFFSET(f) XOFFSET(struct run_header_internal, f)
static const struct common_mysql_parse_spec headers_spec[RUNS_ROW_WIDTH] =
{
  { 0, 'd', "contest_id", HEADERS_OFFSET(contest_id), 0 },
  { 1, 't', "start_time", HEADERS_OFFSET(start_time), 0 },
  { 1, 't', "sched_time", HEADERS_OFFSET(sched_time), 0 },
  { 0, 'd', "duration", HEADERS_OFFSET(duration), 0 },
  { 1, 't', "stop_time", HEADERS_OFFSET(stop_time), 0 },
  { 1, 't', "finish_time", HEADERS_OFFSET(finish_time), 0 },
  { 0, 'd', "saved_duration", HEADERS_OFFSET(saved_duration), 0 },
  { 1, 't', "saved_stop_time", HEADERS_OFFSET(saved_stop_time), 0 },
  { 1, 't', "saved_finish_time", HEADERS_OFFSET(saved_finish_time), 0 },
  { 1, 't', "last_change_time", HEADERS_OFFSET(last_change_time), 0 },
  { 0, 'd', "last_change_nsec", HEADERS_OFFSET(last_change_nsec), 0 },
};

static const char create_userrunheaders_query[] =
"CREATE TABLE %suserrunheaders( "
"        user_id INT UNSIGNED NOT NULL, "
"        contest_id INT UNSIGNED NOT NULL, "
"        is_virtual TINYINT NOT NULL DEFAULT 0, "
"        is_checked TINYINT NOT NULL DEFAULT 0, "
"        start_time DATETIME DEFAULT NULL, "
"        duration INT UNSIGNED, "
"        stop_time DATETIME DEFAULT NULL, "
"        last_change_time DATETIME DEFAULT NULL, "
"        last_change_user_id INT UNSIGNED DEFAULT NULL, "
"        PRIMARY KEY (user_id, contest_id),"
"        KEY userrunheaders_contest_id_idx (contest_id), "
"        KEY userrunheaders_user_id_idx (user_id) "
"        ) DEFAULT CHARSET=utf8 COLLATE=utf8_bin;";

struct user_run_header_internal
{
  int user_id;
  int contest_id;
  int is_virtual;
  int is_checked;
  time_t start_time;
  int duration;
  time_t stop_time;
  time_t last_change_time;
  int last_change_user_id;
};

enum { USERRUNHEADERS_ROW_WIDTH = 9 };

#define USERRUNHEADERS_OFFSET(f) XOFFSET(struct user_run_header_internal, f)
static const struct common_mysql_parse_spec user_run_headers_spec[USERRUNHEADERS_ROW_WIDTH] =
{
  { 0, 'd', "user_id", USERRUNHEADERS_OFFSET(user_id), 0 },
  { 0, 'd', "contest_id", USERRUNHEADERS_OFFSET(contest_id), 0 },
  { 0, 'd', "is_virtual", USERRUNHEADERS_OFFSET(is_virtual), 0 },
  { 0, 'd', "is_checked", USERRUNHEADERS_OFFSET(is_checked), 0 },
  { 1, 't', "start_time", USERRUNHEADERS_OFFSET(start_time), 0 },
  { 1, 'd', "duration", USERRUNHEADERS_OFFSET(duration), 0 },
  { 1, 't', "stop_time", USERRUNHEADERS_OFFSET(stop_time), 0 },
  { 1, 't', "last_change_time", USERRUNHEADERS_OFFSET(last_change_time), 0 },
  { 1, 'd', "last_change_user_id", USERRUNHEADERS_OFFSET(last_change_user_id), 0 },
};

struct user_run_user_id_internal
{
  int min_user_id;
  int max_user_id;
};

enum { USERRUNUSERID_ROW_WIDTH = 2 };
#define USERRUNUSERID_OFFSET(f) XOFFSET(struct user_run_user_id_internal, f)
static const struct common_mysql_parse_spec user_run_user_id_spec[USERRUNUSERID_ROW_WIDTH] =
{
  { 1, 'd', "min_user_id", USERRUNUSERID_OFFSET(min_user_id), 0 },
  { 1, 'd', "max_user_id", USERRUNUSERID_OFFSET(max_user_id), 0 },
};
