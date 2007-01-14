/* -*- c -*- */
/* $Id$ */
#ifndef __PREPARE_DFLT_H__
#define __PREPARE_DFLT_H__

/* Copyright (C) 2005-2007 Alexander Chernov <cher@ejudge.ru> */

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

#define DFLT_G_SLEEP_TIME         1000
#define DFLT_G_SERVE_SLEEP_TIME   100
#define DFLT_G_MAX_RUN_SIZE       65536
#define DFLT_G_MAX_RUN_TOTAL      (2 * 1024 * 1024)
#define DFLT_G_MAX_RUN_NUM        200
#define DFLT_G_MAX_CLAR_SIZE      1024
#define DFLT_G_MAX_CLAR_TOTAL     (40 * 1024)
#define DFLT_G_MAX_CLAR_NUM       50
#define DFLT_G_BOARD_FOG_TIME     60
#define DFLT_G_BOARD_UNFOG_TIME   120
#define DFLT_G_CONTEST_TIME       300
#define DFLT_G_TESTS_TO_ACCEPT    1
#define DFLT_G_ROOT_DIR           "contest"
#define DFLT_G_CONF_DIR           "conf"
#define DFLT_G_VAR_DIR            "var"
#define DFLT_G_SCRIPT_DIR         "scripts"
#define DFLT_G_TEST_DIR           "../tests"
#define DFLT_G_CORR_DIR           "../tests"
#define DFLT_G_INFO_DIR           "../tests"
#define DFLT_G_INFO_SFX           ".inf"
#define DFLT_G_TGZ_DIR            "../tests"
#define DFLT_G_TGZ_SFX            ".tgz"
#define DFLT_G_CHECKER_DIR        "../checkers"
#define DFLT_G_STATEMENT_DIR      "../statements"
#define DFLT_G_RUN_LOG_FILE       "run.log"
#define DFLT_G_CLAR_LOG_FILE      "clar.log"
#define DFLT_G_ARCHIVE_DIR        "archive"
#define DFLT_G_CLAR_ARCHIVE_DIR   "clars"
#define DFLT_G_RUN_ARCHIVE_DIR    "runs"
#define DFLT_G_REPORT_ARCHIVE_DIR "reports"
#define DFLT_G_XML_REPORT_ARCHIVE_DIR "xmlreports"
#define DFLT_G_FULL_ARCHIVE_DIR   "output"
#define DFLT_G_AUDIT_LOG_DIR      "audit"
#define DFLT_G_TEAM_REPORT_ARCHIVE_DIR "teamreports"
#define DFLT_G_TEAM_EXTRA_DIR     "team_extra"
#define DFLT_G_PIPE_DIR           "pipe"
#define DFLT_G_TEAM_DIR           "team"
#define DFLT_G_TEAM_CMD_DIR       "cmd"
#define DFLT_G_TEAM_DATA_DIR      "data"
#define DFLT_G_JUDGE_DIR          "judge"
#define DFLT_G_JUDGE_CMD_DIR      "cmd"
#define DFLT_G_JUDGE_DATA_DIR     "data"
#define DFLT_G_STATUS_DIR         "status"
#define DFLT_G_WORK_DIR           "work"
#define DFLT_G_PRINT_WORK_DIR     "print"
#define DFLT_G_DIFF_WORK_DIR      "diff"
#define DFLT_G_A2PS_PATH          "/usr/bin/a2ps"
#define DFLT_G_LPR_PATH           "/usr/bin/lpr"
#define DFLT_G_DIFF_PATH          "/usr/bin/diff"
#define DFLT_G_COMPILE_DIR        "compile"
#define DFLT_G_COMPILE_QUEUE_DIR  "queue"
#define DFLT_G_COMPILE_SRC_DIR    "src"
#define DFLT_G_COMPILE_STATUS_DIR "status"
#define DFLT_G_COMPILE_REPORT_DIR "report"
#define DFLT_G_COMPILE_WORK_DIR   "compile"
#define DFLT_G_RUN_DIR            "run"
#define DFLT_G_RUN_QUEUE_DIR      "queue"
#define DFLT_G_RUN_EXE_DIR        "exe"
#define DFLT_G_RUN_STATUS_DIR     "status"
#define DFLT_G_RUN_REPORT_DIR     "report"
#define DFLT_G_RUN_TEAM_REPORT_DIR "teamreport"
#define DFLT_G_RUN_FULL_ARCHIVE_DIR "output"
#define DFLT_G_RUN_WORK_DIR       "runwork"
#define DFLT_G_RUN_CHECK_DIR      "runcheck"

#if defined EJUDGE_CHARSET
#define DFLT_G_CHARSET            EJUDGE_CHARSET
#else
#define DFLT_G_CHARSET            "iso8859-1"
#endif /* EJUDGE_CHARSET */

#define DFLT_G_STANDINGS_FILE_NAME "standings.html"
#define DFLT_G_MAX_FILE_LENGTH    65536
#define DFLT_G_MAX_LINE_LENGTH    4096
#define DFLT_G_MAX_CMD_LENGTH     256
#define DFLT_G_TEAM_DOWNLOAD_TIME 30
#define DFLT_G_SERVE_SOCKET       "serve"
#define DFLT_G_INACTIVITY_TIMEOUT 120
#define DFLT_G_CHECKER_REAL_TIME_LIMIT 30
#define DFLT_G_COMPILE_REAL_TIME_LIMIT 60
#define DFLT_G_USE_GZIP          1
#define DFLT_G_USE_DIR_HIERARCHY 1
#define DFLT_G_MIN_GZIP_SIZE     4096
#define DFLT_G_TEAM_PAGE_QUOTA   50
#define DFLT_G_TEAM_ENABLE_SRC_VIEW 0
#define DFLT_G_TEAM_ENABLE_REP_VIEW 0
#define DFLT_G_TEAM_ENABLE_CE_VIEW 0
#define DFLT_G_TEAM_SHOW_JUDGE_REPORT 0
#define DFLT_G_ALWAYS_SHOW_PROBLEMS 0
#define DFLT_G_DISABLE_USER_STANDINGS 0
#define DFLT_G_PROBLEM_NAVIGATION 0
#define DFLT_G_REPORT_ERROR_CODE 0
#define DFLT_G_DISABLE_CLARS 0
#define DFLT_G_DISABLE_TEAM_CLARS 0
#define DFLT_G_IGNORE_COMPILE_ERRORS 0
#define DFLT_G_DISABLE_FAILED_TEST_VIEW 0
#define DFLT_G_IGNORE_DUPLICATED_RUNS 1
#define DFLT_G_SHOW_DEADLINE 0
#define DFLT_G_ENABLE_PRINTING 0
#define DFLT_G_DISABLE_BANNER_PAGE 0
#define DFLT_G_PRUNE_EMPTY_USERS 0
#define DFLT_G_ENABLE_FULL_ARCHIVE 0
#define DFLT_G_PLOG_UPDATE_TIME 30
#define DFLT_G_STAND_SHOW_OK_TIME 0
#define DFLT_G_STAND_SHOW_WARN_NUMBER 0
#define DFLT_G_AUTOUPDATE_STANDINGS 1
#define DFLT_G_DISABLE_AUTO_TESTING 0
#define DFLT_G_DISABLE_TESTING 0
#define DFLT_G_SHOW_ASTR_TIME 0
#define DFLT_G_ENABLE_CONTINUE 1
#define DFLT_G_ENABLE_REPORT_UPLOAD 0
#define DFLT_G_ENABLE_RUNLOG_MERGE 0
#define DFLT_G_IGNORE_SUCCESS_TIME 0
#define DFLT_G_SECURE_RUN 0
#define DFLT_G_ENABLE_MEMORY_LIMIT_ERROR 0

#define DFLT_P_INPUT_FILE         "input"
#define DFLT_P_OUTPUT_FILE        "output"
#define DFLT_P_FULL_SCORE         50
#define DFLT_P_TEST_SCORE         1
#define DFLT_P_RUN_PENALTY        1
#define DFLT_P_ACM_RUN_PENALTY    20
#define DFLT_P_VARIABLE_FULL_SCORE 0
#define DFLT_P_HIDDEN             0
#define DFLT_P_BINARY_INPUT       0

#define DFLT_T_WORK_DIR           "work"
#define DFLT_T_TMP_DIR            "tmp"
#define DFLT_T_ERROR_FILE         "error"

#endif /* __PREPARE_DFLT_H__ */
