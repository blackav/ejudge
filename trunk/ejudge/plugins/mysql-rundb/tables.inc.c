/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008-2014 Alexander Chernov <cher@ejudge.ru> */

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
"        run_id INT UNSIGNED NOT NULL, "
"        contest_id INT UNSIGNED NOT NULL, "
"        size INT UNSIGNED NOT NULL DEFAULT 0, "
"        create_time TIMESTAMP DEFAULT 0, "
"        create_nsec INT UNSIGNED NOT NULL DEFAULT 0, "
"        user_id INT UNSIGNED NOT NULL, "
"        prob_id INT UNSIGNED NOT NULL, "
"        lang_id INT UNSIGNED NOT NULL, "
"        status INT NOT NULL, "
"        ssl_flag TINYINT NOT NULL DEFAULT 0, "
"        ip_version TINYINT NOT NULL DEFAULT 4, "
"        ip VARCHAR(64) NOT NULL, "
"        hash VARCHAR (128), "
"        run_uuid CHAR(40), "
"        score INT NOT NULL, "
"        test_num INT NOT NULL, "
"        score_adj INT NOT NULL, "
"        locale_id INT NOT NULL, "
"        judge_id INT NOT NULL, "
"        variant INT NOT NULL, "
"        pages INT NOT NULL, "
"        is_imported TINYINT NOT NULL DEFAULT 0, "
"        is_hidden TINYINT NOT NULL DEFAULT 0, "
"        is_readonly TINYINT NOT NULL DEFAULT 0, "
"        is_examinable TINYINT NOT NULL DEFAULT 0, "
"        mime_type VARCHAR(64), "
"        examiners0 INT NOT NULL, "
"        examiners1 INT NOT NULL, "
"        examiners2 INT NOT NULL, "
"        exam_score0 INT NOT NULL, "
"        exam_score1 INT NOT NULL, "
"        exam_score2 INT NOT NULL, "
"        last_change_time TIMESTAMP DEFAULT 0, "
"        last_change_nsec INT UNSIGNED NOT NULL, "
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
"        PRIMARY KEY (run_id, contest_id)"
"        );";

struct run_entry_internal
{
  int run_id;                   /* 0 */
  int contest_id;
  int size;
  time_t create_time;
  int create_nsec;
  int user_id;                  /* 5 */
  int prob_id;
  int lang_id;
  int status;
  int ssl_flag;
  int ip_version;               /* 10 */
  ej_ip_t ip;
  unsigned char *hash;
  unsigned char *run_uuid;
  int score;
  int test_num;                 /* 15 */
  int score_adj;
  int locale_id;
  int judge_id;
  int variant;
  int pages;                    /* 20 */
  int is_imported;
  int is_hidden;
  int is_readonly;
  int is_examinable;
  unsigned char *mime_type;     /* 25 */
  int examiners0;
  int examiners1;
  int examiners2;
  int exam_score0;
  int exam_score1;              /* 30 */
  int exam_score2;
  time_t last_change_time;
  int last_change_nsec;
  int is_marked;
  int is_saved;                 /* 35 */
  int saved_status;
  int saved_score;
  int saved_test;
  int passed_mode;
  int eoln_type;                /* 40 */
  int store_flags;
  int token_flags;
  int token_count;
};

enum { RUNS_ROW_WIDTH = 44 };

#define RUNS_OFFSET(f) XOFFSET(struct run_entry_internal, f)
static const struct common_mysql_parse_spec runs_spec[RUNS_ROW_WIDTH] =
{
  { 0, 'd', "run_id", RUNS_OFFSET(run_id), 0 },
  { 0, 'd', "contest_id", RUNS_OFFSET(contest_id), 0 },
  { 0, 'd', "size", RUNS_OFFSET(size), 0 },
  { 0, 't', "create_time", RUNS_OFFSET(create_time), 0 },
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
  { 0, 'b', "is_examinable", RUNS_OFFSET(is_examinable), 0 },
  { 1, 's', "mime_type", RUNS_OFFSET(mime_type), 0 },
  { 0, 'd', "examiners0", RUNS_OFFSET(examiners0), 0 },
  { 0, 'd', "examiners1", RUNS_OFFSET(examiners1), 0 },
  { 0, 'd', "examiners2", RUNS_OFFSET(examiners2), 0 },
  { 0, 'd', "exam_score0", RUNS_OFFSET(exam_score0), 0 },
  { 0, 'd', "exam_score1", RUNS_OFFSET(exam_score1), 0 },
  { 0, 'd', "exam_score2", RUNS_OFFSET(exam_score2), 0 },
  { 0, 't', "last_change_time", RUNS_OFFSET(last_change_time), 0 },
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
"        start_time TIMESTAMP DEFAULT 0, "
"        sched_time TIMESTAMP DEFAULT 0, "
"        duration INT UNSIGNED, "
"        stop_time TIMESTAMP DEFAULT 0, "
"        finish_time TIMESTAMP DEFAULT 0, "
"        saved_duration INT UNSIGNED, "
"        saved_stop_time TIMESTAMP DEFAULT 0, "
"        saved_finish_time TIMESTAMP DEFAULT 0, "
"        last_change_time TIMESTAMP DEFAULT 0, "
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
  { 0, 't', "start_time", HEADERS_OFFSET(start_time), 0 },
  { 0, 't', "sched_time", HEADERS_OFFSET(sched_time), 0 },
  { 0, 'd', "duration", HEADERS_OFFSET(duration), 0 },
  { 0, 't', "stop_time", HEADERS_OFFSET(stop_time), 0 },
  { 0, 't', "finish_time", HEADERS_OFFSET(finish_time), 0 },
  { 0, 'd', "saved_duration", HEADERS_OFFSET(saved_duration), 0 },
  { 0, 't', "saved_stop_time", HEADERS_OFFSET(saved_stop_time), 0 },
  { 0, 't', "saved_finish_time", HEADERS_OFFSET(saved_finish_time), 0 },
  { 0, 't', "last_change_time", HEADERS_OFFSET(last_change_time), 0 },
  { 0, 'd', "last_change_nsec", HEADERS_OFFSET(last_change_nsec), 0 },
};
