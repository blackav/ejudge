/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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
"        create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
"        nsec INT UNSIGNED NOT NULL DEFAULT 0, "
"        user_id INT UNSIGNED NOT NULL, "
"        prob_id INT UNSIGNED NOT NULL, "
"        lang_id INT UNSIGNED NOT NULL, "
"        status INT NOT NULL, "
"        ssl_flag TINYINT NOT NULL DEFAULT 0, "
"        ip_version TINYINT NOT NULL DEFAULT 4, "
"        ip VARCHAR(64) NOT NULL, "
"        hash VARCHAR (128) NOT NULL, "
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
"        examiners1 INT NOT NULL, "
"        examiners2 INT NOT NULL, "
"        examiners3 INT NOT NULL, "
"        exam_score1 INT NOT NULL, "
"        exam_score2 INT NOT NULL, "
"        exam_score3 INT NOT NULL, "
"        PRIMARY KEY (run_id, contest_id)"
"        );";

static const char create_runheaders_query[] =
"CREATE TABLE %srunheaders( "
"        contest_id INT UNSIGNED NOT NULL, "
"        start_time TIMESTAMP, "
"        sched_time TIMESTAMP, "
"        duration INT UNSIGNED, "
"        stop_time TIMESTAMP, "
"        finish_time TIMESTAMP, "
"        saved_duration INT UNSIGNED, "
"        saved_stop_time TIMESTAMP, "
"        saved_finish_time TIMESTAMP, "
"        PRIMARY KEY (contest_id)"
"        );";
