/* -*- c -*- */
/* $Id$ */

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

#include "prepare.h"

#include "fileutl.h"
#include "xalloc.h"
#include "logger.h"
#include "osdeps.h"

#include <stdio.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

#define MAX_LANGUAGE 31
#define MAX_PROBLEM  31
#define MAX_TESTER  100

struct generic_section_config *config;
struct section_global_data    *global;

struct section_language_data *langs[MAX_LANGUAGE + 1];
struct section_problem_data  *probs[MAX_PROBLEM + 1];
struct section_tester_data   *testers[MAX_TESTER + 1];

int max_lang;
int max_prob;
int max_tester;

#define GLOBAL_OFFSET(x)   XOFFSET(struct section_global_data, x)
#define GLOBAL_PARAM(x, t) { #x, t, GLOBAL_OFFSET(x) }
static struct config_parse_info section_global_params[] =
{
  GLOBAL_PARAM(sleep_time, "d"),
  GLOBAL_PARAM(serve_sleep_time, "d"),
  GLOBAL_PARAM(contest_time, "d"),
  GLOBAL_PARAM(max_run_size, "d"),
  GLOBAL_PARAM(max_run_total, "d"),
  GLOBAL_PARAM(max_run_num, "d"),
  GLOBAL_PARAM(max_clar_size, "d"),
  GLOBAL_PARAM(max_clar_total, "d"),
  GLOBAL_PARAM(max_clar_num, "d"),
  GLOBAL_PARAM(board_fog_time, "d"),
  GLOBAL_PARAM(board_unfog_time, "d"),
  GLOBAL_PARAM(team_enable_src_view, "d"),
  GLOBAL_PARAM(team_enable_rep_view, "d"),

  GLOBAL_PARAM(max_file_length, "d"),
  GLOBAL_PARAM(max_line_length, "d"),

  GLOBAL_PARAM(charset, "s"),

  GLOBAL_PARAM(name, "s"),
  GLOBAL_PARAM(root_dir, "s"),

  GLOBAL_PARAM(conf_dir, "s"),
  GLOBAL_PARAM(teamdb_file, "s"),
  GLOBAL_PARAM(passwd_file, "s"),
  GLOBAL_PARAM(script_dir, "s"),
  GLOBAL_PARAM(test_dir, "s"),
  GLOBAL_PARAM(corr_dir, "s"),
  GLOBAL_PARAM(checker_dir, "s"),
  GLOBAL_PARAM(test_sfx, "s"),
  GLOBAL_PARAM(corr_sfx, "s"),

  GLOBAL_PARAM(var_dir, "s"),

  //GLOBAL_PARAM(log_file, "s"),
  GLOBAL_PARAM(run_log_file, "s"),
  GLOBAL_PARAM(clar_log_file, "s"),
  GLOBAL_PARAM(archive_dir, "s"),
  GLOBAL_PARAM(clar_archive_dir, "s"),
  GLOBAL_PARAM(run_archive_dir, "s"),
  GLOBAL_PARAM(report_archive_dir, "s"),
  GLOBAL_PARAM(team_report_archive_dir, "s"),

  GLOBAL_PARAM(status_dir, "s"),
  GLOBAL_PARAM(work_dir, "s"),

  GLOBAL_PARAM(pipe_dir, "s"),
  GLOBAL_PARAM(team_dir, "s"),
  GLOBAL_PARAM(team_cmd_dir, "s"),
  GLOBAL_PARAM(team_data_dir, "s"),
  GLOBAL_PARAM(judge_dir, "s"),
  GLOBAL_PARAM(judge_cmd_dir, "s"),
  GLOBAL_PARAM(judge_data_dir, "s"),

  GLOBAL_PARAM(compile_dir, "s"),
  GLOBAL_PARAM(compile_src_dir, "s"),
  GLOBAL_PARAM(compile_status_dir, "s"),
  GLOBAL_PARAM(compile_report_dir, "s"),

  GLOBAL_PARAM(run_dir, "s"),
  GLOBAL_PARAM(run_exe_dir, "s"),
  GLOBAL_PARAM(run_status_dir, "s"),
  GLOBAL_PARAM(run_report_dir, "s"),
  GLOBAL_PARAM(run_team_report_dir, "s"),

  GLOBAL_PARAM(score_system, "s"),

  GLOBAL_PARAM(team_info_url, "s"),
  GLOBAL_PARAM(prob_info_url, "s"),

  { 0, 0, 0, 0 }
};

#define PROBLEM_OFFSET(x)   XOFFSET(struct section_problem_data, x)
#define PROBLEM_PARAM(x, t) { #x, t, PROBLEM_OFFSET(x) }
static struct config_parse_info section_problem_params[] =
{
  PROBLEM_PARAM(id, "d"),
  PROBLEM_PARAM(use_stdin, "d"),
  PROBLEM_PARAM(use_stdout, "d"),
  PROBLEM_PARAM(time_limit, "d"),
  PROBLEM_PARAM(team_enable_rep_view, "d"),
  PROBLEM_PARAM(full_score, "d"),
  PROBLEM_PARAM(test_score, "d"),
  PROBLEM_PARAM(run_penalty, "d"),

  PROBLEM_PARAM(short_name, "s"),
  PROBLEM_PARAM(long_name, "s"),
  PROBLEM_PARAM(test_dir, "s"),
  PROBLEM_PARAM(test_sfx, "s"),
  PROBLEM_PARAM(corr_dir, "s"),
  PROBLEM_PARAM(corr_sfx, "s"),
  PROBLEM_PARAM(input_file, "s"),
  PROBLEM_PARAM(output_file, "s"),
  PROBLEM_PARAM(test_score_list, "s"),

  { 0, 0, 0, 0 }
};

#define LANGUAGE_OFFSET(x)   XOFFSET(struct section_language_data, x)
#define LANGUAGE_PARAM(x, t) { #x, t, LANGUAGE_OFFSET(x) }
static struct config_parse_info section_language_params[] =
{
  LANGUAGE_PARAM(id, "d"),
  LANGUAGE_PARAM(short_name, "s"),
  LANGUAGE_PARAM(long_name, "s"),
  LANGUAGE_PARAM(key, "s"),
  LANGUAGE_PARAM(arch, "s"),
  LANGUAGE_PARAM(src_sfx, "s"),
  LANGUAGE_PARAM(exe_sfx, "s"),
  LANGUAGE_PARAM(cmd, "s"),

  LANGUAGE_PARAM(server_root_dir, "s"),
  LANGUAGE_PARAM(server_var_dir, "s"),
  LANGUAGE_PARAM(server_compile_dir, "s"),
  LANGUAGE_PARAM(server_src_dir, "s"),
  LANGUAGE_PARAM(compile_status_dir, "s"),
  LANGUAGE_PARAM(compile_report_dir, "s"),

  LANGUAGE_PARAM(src_dir, "s"),
  LANGUAGE_PARAM(work_dir, "s"),
  { 0, 0, 0, 0 }
};

#define TESTER_OFFSET(x) XOFFSET(struct section_tester_data, x)
#define TESTER_PARAM(x, t) { #x, t, TESTER_OFFSET(x) }
static struct config_parse_info section_tester_params[] =
{
  TESTER_PARAM(id, "d"),
  TESTER_PARAM(name, "s"),
  TESTER_PARAM(problem, "d"),
  TESTER_PARAM(problem_name, "s"),
  TESTER_PARAM(no_redirect, "d"),
  TESTER_PARAM(is_dos, "d"),
  TESTER_PARAM(arch, "s"),
  TESTER_PARAM(key, "s"),

  TESTER_PARAM(server_root_dir, "s"),
  TESTER_PARAM(server_var_dir, "s"),
  TESTER_PARAM(server_run_dir, "s"),
  TESTER_PARAM(server_exe_dir, "s"),
  TESTER_PARAM(run_status_dir, "s"),
  TESTER_PARAM(run_report_dir, "s"),
  TESTER_PARAM(run_team_report_dir, "s"),
  TESTER_PARAM(exe_dir, "s"),

  TESTER_PARAM(tester_dir, "s"),
  TESTER_PARAM(tmp_dir, "s"),
  TESTER_PARAM(work_dir, "s"),
  TESTER_PARAM(errorcode_file, "s"),
  TESTER_PARAM(error_file, "s"),

  TESTER_PARAM(prepare_cmd, "s"),
  TESTER_PARAM(check_cmd, "s"),
  TESTER_PARAM(start_cmd, "s"),

  { 0, 0, 0, 0 }
};

static int problem_counter;
static int language_counter;
static int tester_counter;

static struct config_section_info params[] =
{
  { "global", sizeof(struct section_global_data), section_global_params },
  { "problem", sizeof(struct section_problem_data), section_problem_params,
    &problem_counter },
  { "language",sizeof(struct section_language_data),section_language_params,
    &language_counter },
  { "tester", sizeof(struct section_tester_data), section_tester_params,
    &tester_counter },
  { NULL, 0, NULL }
};

int
find_tester(int problem, char const *arch)
{
  int i;

  for (i = 1; i <= max_tester; i++) {
    if (problem == testers[i]->problem
        && !strcmp(arch, testers[i]->arch))
      return i;
  }
  return 0;
}

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
#define DFLT_G_CONTEST_TIME       60
#define DFLT_G_ROOT_DIR           "contest"
#define DFLT_G_CONF_DIR           "conf"
#define DFLT_G_VAR_DIR            "var"
#define DFLT_G_TEAMDB_FILE        "teamdb"
#define DFLT_G_PASSWD_FILE        "passwd"
#define DFLT_G_SCRIPT_DIR         "scripts"
#define DFLT_G_TEST_DIR           "tests"
#define DFLT_G_CORR_DIR           "correct"
#define DFLT_G_CHECKER_DIR        "checkers"
#define DFLT_G_RUN_LOG_FILE       "run.log"
#define DFLT_G_CLAR_LOG_FILE      "clar.log"
#define DFLT_G_ARCHIVE_DIR        "archive"
#define DFLT_G_CLAR_ARCHIVE_DIR   "clars"
#define DFLT_G_RUN_ARCHIVE_DIR    "runs"
#define DFLT_G_REPORT_ARCHIVE_DIR "reports"
#define DFLT_G_TEAM_REPORT_ARCHIVE_DIR "teamreports"
#define DFLT_G_PIPE_DIR           "pipe"
#define DFLT_G_TEAM_DIR           "team"
#define DFLT_G_TEAM_CMD_DIR       "cmd"
#define DFLT_G_TEAM_DATA_DIR      "data"
#define DFLT_G_JUDGE_DIR          "judge"
#define DFLT_G_JUDGE_CMD_DIR      "cmd"
#define DFLT_G_JUDGE_DATA_DIR     "data"
#define DFLT_G_STATUS_DIR         "status"
#define DFLT_G_WORK_DIR           "work"
#define DFLT_G_COMPILE_DIR        "compile"
#define DFLT_G_COMPILE_SRC_DIR    "src"
#define DFLT_G_COMPILE_STATUS_DIR "status"
#define DFLT_G_COMPILE_REPORT_DIR "report"
#define DFLT_G_RUN_DIR            "run"
#define DFLT_G_RUN_EXE_DIR        "exe"
#define DFLT_G_RUN_STATUS_DIR     "status"
#define DFLT_G_RUN_REPORT_DIR     "report"
#define DFLT_G_RUN_TEAM_REPORT_DIR "teamreport"
#define DFLT_G_CHARSET            "iso8859-1"
#define DFLT_G_MAX_FILE_LENGTH    65535
#define DFLT_G_MAX_LINE_LENGTH    4096

#define DFLT_P_INPUT_FILE         "input"
#define DFLT_P_OUTPUT_FILE        "output"
#define DFLT_P_FULL_SCORE         25
#define DFLT_P_TEST_SCORE         1
#define DFLT_P_RUN_PENALTY        1

#define DFLT_T_WORK_DIR           "work"
#define DFLT_T_TMP_DIR            "tmp"
#define DFLT_T_ERROR_FILE         "error"

static void
set_initial_values(void)
{
}

static int
set_defaults(int mode)
{
  struct generic_section_config *p;

  int i, j;

  /* find global section */
  for (p = config; p; p = p->next)
    if (!p->name[0] || !strcmp(p->name, "global"))
      break;
  if (!p) {
    err(_("Global configuration settings not found"));
    return -1;
  }
  global = (struct section_global_data*) p;

  /* directory poll intervals */
  if (global->sleep_time < 0 || global->sleep_time > 10000) {
    err(_("Invalid global.sleep_time value"));
    return -1;
  }
  if (mode == PREPARE_SERVE) {
    if (global->serve_sleep_time < 0 || global->serve_sleep_time > 10000) {
      err(_("Invalid global.serve_sleep_time value"));
      return -1;
    }
  }
  if (!global->sleep_time && !global->serve_sleep_time) {
    info(_("global.sleep_time set to %d"), DFLT_G_SLEEP_TIME);
    global->sleep_time = DFLT_G_SLEEP_TIME;
    if (mode == PREPARE_SERVE) {
      info(_("global.serve_sleep_time set to %d"), DFLT_G_SERVE_SLEEP_TIME);
      global->serve_sleep_time = DFLT_G_SERVE_SLEEP_TIME;
    }
  } else if (!global->sleep_time) {
    info(_("global.sleep_time set to %d"), DFLT_G_SLEEP_TIME);
    global->sleep_time = DFLT_G_SLEEP_TIME;
  } else if (mode == PREPARE_SERVE && !global->serve_sleep_time) {
    info(_("global.serve_sleep_time set to global.sleep_time"));
    global->serve_sleep_time = global->sleep_time;
  }

#define GLOBAL_INIT_NUM_FIELD(f,v) do { if (!global->f) { info(_("global.%s set to %d"), #f, v); global->f = v; } } while (0)
  /* limits (serve) */
  if (mode == PREPARE_SERVE) {
    GLOBAL_INIT_NUM_FIELD(max_run_size, DFLT_G_MAX_RUN_SIZE);
    GLOBAL_INIT_NUM_FIELD(max_run_num, DFLT_G_MAX_RUN_NUM);
    GLOBAL_INIT_NUM_FIELD(max_run_total, DFLT_G_MAX_RUN_TOTAL);
    GLOBAL_INIT_NUM_FIELD(max_clar_size, DFLT_G_MAX_CLAR_SIZE);
    GLOBAL_INIT_NUM_FIELD(max_clar_num, DFLT_G_MAX_CLAR_NUM);
    GLOBAL_INIT_NUM_FIELD(max_clar_total, DFLT_G_MAX_CLAR_TOTAL);
  }

  /* timings */
  if (mode == PREPARE_SERVE) {
    if (!global->board_fog_time) {
      info(_("global.board_fog_time set to %d"), DFLT_G_BOARD_FOG_TIME);
      global->board_fog_time = DFLT_G_BOARD_FOG_TIME;
    }
    global->board_fog_time *= 60;
    if (!global->board_unfog_time) {
      info(_("global.board_unfog_time set to %d"), DFLT_G_BOARD_UNFOG_TIME);
      global->board_unfog_time = DFLT_G_BOARD_UNFOG_TIME;
    }
    global->board_unfog_time *= 60;
    if (global->contest_time < 0 || global->contest_time > 60 * 10) {
      err(_("bad value of global.contest_time: %d"), global->contest_time);
      return -1;
    }
    if (!global->contest_time) {
      info(_("global.contest_time set to %d"), DFLT_G_CONTEST_TIME);
      global->contest_time = DFLT_G_CONTEST_TIME;
    }
    global->contest_time *= 60;
  }

  /* root_dir, conf_dir, var_dir */
  if (!global->root_dir[0] && !global->var_dir[0] && !global->conf_dir[0]) {
    info(_("global.root_dir set to %s"), DFLT_G_ROOT_DIR);
    info(_("global.conf_dir set to %s"), DFLT_G_CONF_DIR);
    info(_("global.var_dir set to %s"), DFLT_G_VAR_DIR);
    pathcpy(global->root_dir, DFLT_G_ROOT_DIR);
    path_init(global->conf_dir, global->root_dir, DFLT_G_CONF_DIR);
    path_init(global->var_dir, global->root_dir, DFLT_G_VAR_DIR);
  } else if (global->root_dir[0]) {
    if (!global->conf_dir[0]) {
      info(_("global.conf_dir set to %s"), DFLT_G_CONF_DIR);
    }
    if (!global->var_dir[0]) {
      info(_("global.var_dir set to %s"), DFLT_G_VAR_DIR);
    }
    path_init(global->conf_dir, global->root_dir, DFLT_G_CONF_DIR);
    path_init(global->var_dir, global->root_dir, DFLT_G_VAR_DIR);
  } else if (!global->var_dir[0]) {
    err(_("global.var_dir must be set!"));
    return -1;
  } else if (!global->conf_dir[0]) {
    err(_("global.conf_dir must be set!"));
    return -1;
  }

  /* CONFIGURATION FILES DEFAULTS */
#define GLOBAL_INIT_FIELD(f,d,c) do { if (!global->f[0]) { info("global." #f " set to %s", d); pathcpy(global->f, d); } pathmake2(global->f,global->c, "/", global->f, NULL); } while (0)

  if (mode == PREPARE_SERVE) {
    GLOBAL_INIT_FIELD(teamdb_file, DFLT_G_TEAMDB_FILE, conf_dir);
    GLOBAL_INIT_FIELD(passwd_file, DFLT_G_PASSWD_FILE, conf_dir);
  }
  if (mode == PREPARE_COMPILE || mode == PREPARE_RUN) {
    GLOBAL_INIT_FIELD(script_dir, DFLT_G_SCRIPT_DIR, conf_dir);
  }
  if (mode == PREPARE_RUN) {
    GLOBAL_INIT_FIELD(test_dir, DFLT_G_TEST_DIR, conf_dir);
    GLOBAL_INIT_FIELD(corr_dir, DFLT_G_CORR_DIR, conf_dir);
    GLOBAL_INIT_FIELD(checker_dir, DFLT_G_CHECKER_DIR, conf_dir);
  }

  if (mode == PREPARE_SERVE) {
    GLOBAL_INIT_FIELD(run_log_file, DFLT_G_RUN_LOG_FILE, var_dir);
    GLOBAL_INIT_FIELD(clar_log_file, DFLT_G_CLAR_LOG_FILE, var_dir);
    GLOBAL_INIT_FIELD(archive_dir, DFLT_G_ARCHIVE_DIR, var_dir);
    GLOBAL_INIT_FIELD(clar_archive_dir, DFLT_G_CLAR_ARCHIVE_DIR, archive_dir);
    GLOBAL_INIT_FIELD(run_archive_dir, DFLT_G_RUN_ARCHIVE_DIR, archive_dir);
    GLOBAL_INIT_FIELD(report_archive_dir,DFLT_G_REPORT_ARCHIVE_DIR,archive_dir);
    GLOBAL_INIT_FIELD(team_report_archive_dir,DFLT_G_TEAM_REPORT_ARCHIVE_DIR,archive_dir);

    GLOBAL_INIT_FIELD(status_dir, DFLT_G_STATUS_DIR, var_dir);

    GLOBAL_INIT_FIELD(pipe_dir, DFLT_G_PIPE_DIR, var_dir);
    GLOBAL_INIT_FIELD(team_dir, DFLT_G_TEAM_DIR, var_dir);
    GLOBAL_INIT_FIELD(team_cmd_dir, DFLT_G_TEAM_CMD_DIR, team_dir);
    GLOBAL_INIT_FIELD(team_data_dir, DFLT_G_TEAM_DATA_DIR, team_dir);
    GLOBAL_INIT_FIELD(judge_dir, DFLT_G_JUDGE_DIR, var_dir);
    GLOBAL_INIT_FIELD(judge_cmd_dir, DFLT_G_JUDGE_CMD_DIR, judge_dir);
    GLOBAL_INIT_FIELD(judge_data_dir, DFLT_G_JUDGE_DATA_DIR, judge_dir);
  }

  if (mode == PREPARE_SERVE || mode == PREPARE_COMPILE) {
    GLOBAL_INIT_FIELD(compile_dir, DFLT_G_COMPILE_DIR, var_dir);
    GLOBAL_INIT_FIELD(compile_src_dir, DFLT_G_COMPILE_SRC_DIR, compile_dir);
    GLOBAL_INIT_FIELD(compile_status_dir,DFLT_G_COMPILE_STATUS_DIR,compile_dir);
    GLOBAL_INIT_FIELD(compile_report_dir,DFLT_G_COMPILE_REPORT_DIR,compile_dir);
  }

  if (mode == PREPARE_SERVE || mode == PREPARE_RUN) {
    GLOBAL_INIT_FIELD(run_dir, DFLT_G_RUN_DIR, var_dir);
    GLOBAL_INIT_FIELD(run_exe_dir, DFLT_G_RUN_EXE_DIR, run_dir);
    GLOBAL_INIT_FIELD(run_status_dir, DFLT_G_RUN_STATUS_DIR, run_dir);
    GLOBAL_INIT_FIELD(run_report_dir, DFLT_G_RUN_REPORT_DIR, run_dir);
    GLOBAL_INIT_FIELD(run_team_report_dir, DFLT_G_RUN_TEAM_REPORT_DIR,run_dir);
  }
  GLOBAL_INIT_FIELD(work_dir, DFLT_G_WORK_DIR, var_dir);

  /* score_system must be either "acm", either "kirov"
   * "acm" is the default
   */
  if (!global->score_system[0]) {
    global->score_system_val = SCORE_ACM;
  } else if (!strcmp(global->score_system, "acm")) {
    global->score_system_val = SCORE_ACM;
  } else if (!strcmp(global->score_system, "kirov")) {
    global->score_system_val = SCORE_KIROV;
  } else {
    /* FIXME: localize the string */
    err("Invalid scoring system: %s", global->score_system);
  }

  if (!global->charset[0]) {
    pathcpy(global->charset, DFLT_G_CHARSET);
    info(_("global.charset set to %s"), global->charset);
  }

  /* only run needs these parameters */
  if (mode == PREPARE_RUN) {
    if (!global->max_file_length) {
      global->max_file_length = DFLT_G_MAX_FILE_LENGTH;
      info(_("global.max_file_length set to %d"), global->max_file_length);
    }
    if (!global->max_line_length) {
      global->max_line_length = DFLT_G_MAX_LINE_LENGTH;
      info(_("global.max_line_length set to %d"), global->max_line_length);
    }
  }

  for (i = 1; i <= max_lang && mode != PREPARE_RUN; i++) {
    if (!langs[i]) continue;
    if (!langs[i]->short_name[0]) {
      info(_("language.%d.short_name set to \"lang%d\""), i, i);
      sprintf(langs[i]->short_name, "lang%d", i);
    }
    if (!langs[i]->long_name[0]) {
      info(_("language.%d.long_name set to \"Language %d\""), i, i);
      sprintf(langs[i]->long_name, "Language %d", i);
    }
    
    if (mode != PREPARE_COMPILE || !langs[i]->server_root_dir[0]) {
      //info("language.%d.server_root_dir set to %s", i, global->root_dir);
      pathcpy(langs[i]->server_root_dir, global->root_dir);
      pathcpy(langs[i]->server_var_dir, global->var_dir);
      pathcpy(langs[i]->server_compile_dir, global->compile_dir);
      pathcpy(langs[i]->server_src_dir, global->compile_src_dir);
      pathcpy(langs[i]->compile_status_dir, global->compile_status_dir);
      pathcpy(langs[i]->compile_report_dir, global->compile_report_dir);
    } else {
#define LANG_INIT_FIELD(f,d,c) do { if (!langs[i]->f[0]) { info(_("language.%d.%s set to %s"), i, #f, d); pathcpy(langs[i]->f, d); } path_add_dir(langs[i]->f, langs[i]->c); info(_("language.%d.%s is %s"), i, #f, langs[i]->f); } while(0)
      LANG_INIT_FIELD(server_var_dir, DFLT_G_VAR_DIR, server_root_dir);
      LANG_INIT_FIELD(server_compile_dir,DFLT_G_COMPILE_DIR,server_var_dir);
      LANG_INIT_FIELD(server_src_dir,DFLT_G_COMPILE_SRC_DIR,server_compile_dir);
      LANG_INIT_FIELD(compile_status_dir,DFLT_G_COMPILE_STATUS_DIR,server_compile_dir);
      LANG_INIT_FIELD(compile_report_dir,DFLT_G_COMPILE_REPORT_DIR,server_compile_dir);
    }
    LANG_INIT_FIELD(src_dir, langs[i]->short_name, server_src_dir);
    
    if (!langs[i]->src_sfx[0]) {
      err(_("language.%d.src_sfx must be set"), i);
      return -1;
    }

    if (mode == PREPARE_COMPILE) {
      if (!langs[i]->work_dir[0]) {
        info(_("language.%d.work_dir set to %s"), i, langs[i]->short_name);
        pathcpy(langs[i]->work_dir, langs[i]->short_name);
      }
      path_add_dir(langs[i]->work_dir, global->work_dir);
      info(_("language.%d.work_dir is %s"), i, langs[i]->work_dir);
      
      if (!langs[i]->cmd[0]) {
        err(_("language.%d.cmd must be set"), i);
        return -1;
      }
      pathmake4(langs[i]->cmd,global->script_dir, "/", langs[i]->cmd, NULL);
      info(_("language.%d.cmd is %s"), i, langs[i]->cmd);
    }
  }

  for (i = 1; i <= max_prob && mode != PREPARE_COMPILE; i++) {
    if (!probs[i]) continue;
    if (!probs[i]->short_name[0]) {
      info(_("problem.%d.short_name set to \"p%d\""), i, i);
      sprintf(probs[i]->short_name, "p%d", i);
    }
    if (!probs[i]->long_name[0]) {
      info(_("problem.%d.long_name set to \"Problem %d\""), i, i);
      sprintf(probs[i]->long_name, "Problem %d", i);
    }

    if (!probs[i]->team_enable_rep_view) {
      info(_("problem.%d.team_enable_rep_view inherited from global settings"),
           i);
      probs[i]->team_enable_rep_view = global->team_enable_rep_view;
    } else if (probs[i]->team_enable_rep_view == 2) {
      probs[i]->team_enable_rep_view = 0;
    }
    if (!probs[i]->full_score) {
      probs[i]->full_score = DFLT_P_FULL_SCORE;
      info(_("problem.%d.full_score set to %d"), i, DFLT_P_FULL_SCORE);
    }
    if (!probs[i]->test_score) {
      probs[i]->test_score = DFLT_P_TEST_SCORE;
      info(_("problem.%d.test_score set to %d"), i,  DFLT_P_TEST_SCORE);
    }
    if (!probs[i]->run_penalty) {
      probs[i]->run_penalty = DFLT_P_RUN_PENALTY;
      info(_("problem.%d.run_penalty set to %d"), i, DFLT_P_RUN_PENALTY);
    }
    
    if (mode == PREPARE_RUN) {
      if (!probs[i]->test_dir[0]) {
        info(_("problem.%d.test_dir set to %s"), i, probs[i]->short_name);
        pathcpy(probs[i]->test_dir, probs[i]->short_name);
      }
      path_add_dir(probs[i]->test_dir, global->test_dir);
      if (probs[i]->corr_dir[0]) {
        path_add_dir(probs[i]->corr_dir, global->corr_dir);
      }
      if (!probs[i]->input_file[0]) {
        info(_("problem.%d.input_file set to %s"), i, DFLT_P_INPUT_FILE);
        pathcpy(probs[i]->input_file, DFLT_P_INPUT_FILE);
      }
      if (!probs[i]->output_file[0]) {
        info(_("problem.%d.output_file set to %s"), i, DFLT_P_OUTPUT_FILE);
        pathcpy(probs[i]->output_file, DFLT_P_OUTPUT_FILE);
      }
    }
  }

#define TESTER_INIT_FIELD(f,d,c) do { if (!testers[i]->f[0]) { info(_("tester.%d.%s set to %s"), i, #f, d); pathcat(testers[i]->f, d); } path_add_dir(testers[i]->f, testers[i]->c); } while(0)
  if (mode == PREPARE_SERVE || mode == PREPARE_RUN) {
    for (i = 1; i <= max_tester; i++) {
      if (!testers[i]) continue;

      if (!testers[i]->name[0]) {
        sprintf(testers[i]->name, "tst_%s",
                probs[testers[i]->problem]->short_name);
        if (testers[i]->arch[0]) {
          sprintf(testers[i]->name + strlen(testers[i]->name),
                  "_%s", testers[i]->arch);
        }
        info(_("tester.%d.name set to \"%s\""), i, testers[i]->name);
      }
      if (mode == PREPARE_RUN) {
        if (!testers[i]->tester_dir[0]) {
          info(_("tester.%d.tester_dir set to \"%s\""), i, testers[i]->name);
          pathcpy(testers[i]->tester_dir, testers[i]->name);
        }
        path_add_dir(testers[i]->tester_dir, global->work_dir);
        TESTER_INIT_FIELD(tmp_dir, DFLT_T_TMP_DIR, tester_dir);
        TESTER_INIT_FIELD(work_dir, DFLT_T_WORK_DIR, tester_dir);
      }
      
      if (mode != PREPARE_RUN || !testers[i]->server_root_dir[0]) {
        //info("tester.%d.server_root_dir set to %s", i, global->root_dir);
        pathcpy(testers[i]->server_root_dir, global->root_dir);
        pathcpy(testers[i]->server_var_dir, global->var_dir);
        pathcpy(testers[i]->server_run_dir, global->run_dir);
        pathcpy(testers[i]->server_exe_dir, global->run_exe_dir);
        pathcpy(testers[i]->run_status_dir, global->run_status_dir);
        pathcpy(testers[i]->run_report_dir, global->run_report_dir);
        pathcpy(testers[i]->run_team_report_dir, global->run_team_report_dir);
      } else {
        TESTER_INIT_FIELD(server_var_dir, DFLT_G_VAR_DIR, server_root_dir);
        TESTER_INIT_FIELD(server_run_dir, DFLT_G_RUN_DIR, server_var_dir);
        TESTER_INIT_FIELD(server_exe_dir, DFLT_G_RUN_EXE_DIR, server_run_dir);
        TESTER_INIT_FIELD(run_status_dir,DFLT_G_RUN_STATUS_DIR,server_run_dir);
        TESTER_INIT_FIELD(run_report_dir,DFLT_G_RUN_REPORT_DIR,server_run_dir);
        TESTER_INIT_FIELD(run_team_report_dir,DFLT_G_RUN_TEAM_REPORT_DIR,server_run_dir);
      }

      TESTER_INIT_FIELD(exe_dir, testers[i]->name, server_exe_dir);

      if (mode == PREPARE_RUN) {
        if (!testers[i]->error_file[0]) {
          info(_("tester.%d.error_file set to %s"), i, DFLT_T_ERROR_FILE);
          pathcpy(testers[i]->error_file, DFLT_T_ERROR_FILE);
        }
        if (!testers[i]->check_cmd[0]) {
          err(_("tester.%d.check_cmd must be set"), i);
          return -1;
        }
        pathmake4(testers[i]->check_cmd, global->checker_dir, "/",
                  testers[i]->check_cmd, 0);
        if (testers[i]->start_cmd[0]) {
          pathmake4(testers[i]->start_cmd, global->script_dir, "/",
                    testers[i]->start_cmd, 0);
        }
      }
    }
  }

  if (mode == PREPARE_SERVE) {
    /* check language/checker pairs */
    for (i = 1; i <= max_lang; i++) {
      if (!langs[i]) continue;
      for (j = 1; j <= max_prob; j++) {
        if (!probs[j]) continue;
        if (!find_tester(j, langs[i]->arch)) {
          err(_("no tester for pair: %d, %s"), j, langs[i]->arch);
          return -1;
        }
      }
    }
  }

  return 0;
}

static int
collect_sections(int mode)
{
  struct generic_section_config *p;
  struct section_language_data  *l;
  struct section_problem_data   *q;
  struct section_tester_data    *t;
  int last_lang = 0, last_prob = 0, last_tester = 0;

  max_lang = max_prob = max_tester = 0;

  for (p = config; p; p = p->next) {
    if (!strcmp(p->name, "language") && mode != PREPARE_RUN) {
      l = (struct section_language_data*) p;
      if (!l->id) info(_("assigned language id = %d"), (l->id = last_lang + 1));
      if (l->id <= 0 || l->id > MAX_LANGUAGE) {
        err(_("language id %d is out of range"), l->id);
        return -1;
      }
      if (langs[l->id]) {
        err(_("duplicated language id %d"), l->id);
        return -1;
      }
      langs[l->id] = l;
      if (l->id > max_lang) max_lang = l->id;
      last_lang = l->id;
    } else if (!strcmp(p->name, "problem") && mode != PREPARE_COMPILE) {
      q = (struct section_problem_data*) p;
      if (!q->id) info(_("assigned problem id = %d"), (q->id = last_prob + 1));
      if (q->id <= 0 || q->id > MAX_PROBLEM) {
        err(_("problem id %d is out of range"), q->id);
        return -1;
      }
      if (probs[q->id]) {
        err(_("duplicated problem id %d"), q->id);
        return -1;
      }
      probs[q->id] = q;
      if (q->id > max_prob) max_prob = q->id;
      last_prob = q->id;
    } else if (!strcmp(p->name, "tester") && mode != PREPARE_COMPILE) {
      t = (struct section_tester_data *) p;
      if (!t->id) info(_("assigned tester id = %d"), (t->id = last_tester + 1));
      if (t->id <= 0 || t->id > MAX_TESTER) {
        err(_("tester id %d is out of range"), t->id);
        return -1;
      }
      if (testers[t->id]) {
        err(_("duplicated tester id %d"), t->id);
        return -1;
      }
      if (!t->problem && !t->problem_name[0]) {
        err(_("no problem specified for tester %d"), t->id);
        return -1;
      }
      if (t->problem && t->problem_name[0]) {
        err(_("only one of problem id and problem name must be specified"));
        return -1;
      }
      if (t->problem && !probs[t->problem]) {
        err(_("no problem %d for tester %d"), t->problem, t->id);
        return -1;
      }
      if (t->problem_name) {
        int j;

        for (j = 1; j <= max_prob; j++) {
          if (probs[j] && !strcmp(probs[j]->short_name, t->problem_name))
            break;
        }
        if (j > max_prob) {
          err(_("no problem %s for tester %d"), t->problem_name, t->id);
          return -1;
        }
        info(_("tester %d: problem '%s' has id %d"),
             t->id, t->problem_name, j);
        t->problem = j;
      }
      testers[t->id] = t;
      if (t->id > max_tester) max_tester = t->id;
      last_tester = t->id;
    }
  }
  return 0;
}

int
create_dirs(int mode)
{
  int i;

  if (mode == PREPARE_SERVE) {
    if (global->root_dir[0] && make_dir(global->root_dir, 0) < 0) return -1;
    if (make_dir(global->var_dir, 0) < 0) return -1;

    /* CGI scripts write to the followins dirs */
    if (make_dir(global->pipe_dir, 0777) < 0) return -1;
    if (make_dir(global->team_dir, 0) < 0) return -1;
    if (make_all_dir(global->team_cmd_dir, 0777) < 0) return -1;
    if (make_dir(global->team_data_dir, 0777) < 0) return -1;
    if (make_dir(global->judge_dir, 0) < 0) return -1;
    if (make_all_dir(global->judge_cmd_dir, 0777) < 0) return -1;
    if (make_dir(global->judge_data_dir, 0777) < 0) return -1;

    /* COMPILE writes its response here */
    if (make_dir(global->compile_dir, 0) < 0) return -1;
    if (make_dir(global->compile_src_dir, 0) < 0) return -1;
    if (make_all_dir(global->compile_status_dir, 0777) < 0) return -1;
    if (make_dir(global->compile_report_dir, 0777) < 0) return -1;

    /* RUN writes its response here */
    if (make_dir(global->run_dir, 0) < 0) return -1;
    if (make_dir(global->run_exe_dir, 0) < 0) return -1;
    if (make_all_dir(global->run_status_dir, 0777) < 0) return -1;
    if (make_dir(global->run_report_dir, 0777) < 0) return -1;
    if (global->team_enable_rep_view) {
      if (make_dir(global->run_team_report_dir, 0777) < 0) return -1;
    }

    /* SERVE's status directory */
    if (make_all_dir(global->status_dir, 0) < 0) return -1;

    /* working directory (if somebody needs it) */
    if (make_dir(global->work_dir, 0) < 0) return -1;

    /* SERVE's archive directories */
    if (make_dir(global->archive_dir, 0) < 0) return -1;
    if (make_dir(global->clar_archive_dir, 0) < 0) return -1;
    if (make_dir(global->run_archive_dir, 0) < 0) return -1;
    if (make_dir(global->report_archive_dir, 0) < 0) return -1;
    if (global->team_enable_rep_view) {
      if (make_dir(global->team_report_archive_dir, 0) < 0) return -1;
    }
  }

  for (i = 1; i <= max_lang; i++) {
    if (!langs[i]) continue;
    if (mode == PREPARE_SERVE) {
      /* COMPILE reads from here */
      if (make_all_dir(langs[i]->src_dir, 0777) < 0) return -1;
    }
    if (mode == PREPARE_COMPILE) {
      if (make_dir(langs[i]->work_dir, 0) < 0) return -1;
    }
  }

  for (i = 1; i <= max_tester; i++) {
    if (!testers[i]) continue;
    if (mode == PREPARE_SERVE) {
      /* RUN reads from here */
      if (make_all_dir(testers[i]->exe_dir, 0777) < 0) return -1;
    }
    if (mode == PREPARE_RUN) {
      if (make_dir(testers[i]->tester_dir, 0) < 0) return -1;
      if (make_dir(testers[i]->tmp_dir, 0) < 0) return -1;
      if (make_dir(testers[i]->work_dir, 0) < 0) return -1;
    }
  }

  write_log(0, LOG_INFO, _("all directories created"));
  return 0;
}

int
prepare(char const *config_file, int flags, int mode, char const *opts)
{
  /* set predefined values for certain variables */
  set_initial_values();

  if ((flags & PREPARE_USE_CPP)) {
    FILE   *f = 0;
    path_t  cmd;
    /* invoke a preprocessor. */
    /* FIXME: check for preprocessor invokation variants? */
    /* FIXME: use task_New, etc...? */
    pathcpy(cmd, "cpp ");
    pathcat(cmd, opts);
    pathcat(cmd, " ");
    pathcat(cmd, config_file);
    if (!(f = popen(cmd, "r"))) {
      err(_("popen(\"%s\") failed: %s"), cmd, os_ErrorMsg());
      return -1;
    }
    config = parse_param(NULL, f, params, (flags & PREPARE_QUIET));
    f = 0;
  } else {
    config = parse_param(config_file, 0, params, (flags & PREPARE_QUIET));
  }
  if (!config) return -1;
  write_log(0, LOG_INFO, _("Configuration file parsed ok"));
  if (collect_sections(mode) < 0) return -1;
  if (!max_lang && mode != PREPARE_RUN) {
    err(_("no languages specified"));
    return -1;
  }
  if (!max_prob && mode != PREPARE_COMPILE) {
    err(_("no problems specified"));
    return -1;
  }
  if (!max_tester && mode != PREPARE_COMPILE) {
    err(_("no testers specified"));
    return -1;
  }
  if (set_defaults(mode) < 0) return -1;
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
