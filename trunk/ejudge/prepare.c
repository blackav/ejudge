/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2002 Alexander Chernov <cher@ispras.ru> */

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
#include "sformat.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <stdio.h>
#include <string.h>

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

static struct section_problem_data  *abstr_probs[MAX_PROBLEM + 1];
static struct section_tester_data   *abstr_testers[MAX_TESTER + 1];

static int max_abstr_prob;
static int max_abstr_tester;

#define GLOBAL_OFFSET(x)   XOFFSET(struct section_global_data, x)
#define GLOBAL_PARAM(x, t) { #x, t, GLOBAL_OFFSET(x) }
static struct config_parse_info section_global_params[] =
{
  GLOBAL_PARAM(name, "s"),
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
  PROBLEM_PARAM(abstract, "d"),
  PROBLEM_PARAM(use_stdin, "d"),
  PROBLEM_PARAM(use_stdout, "d"),
  PROBLEM_PARAM(time_limit, "d"),
  PROBLEM_PARAM(real_time_limit, "d"),
  PROBLEM_PARAM(team_enable_rep_view, "d"),
  PROBLEM_PARAM(full_score, "d"),
  PROBLEM_PARAM(test_score, "d"),
  PROBLEM_PARAM(run_penalty, "d"),
  PROBLEM_PARAM(use_corr, "d"),

  PROBLEM_PARAM(super, "s"),
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

  TESTER_PARAM(abstract, "d"),
  TESTER_PARAM(super, "x"),

  TESTER_PARAM(no_core_dump, "d"),
  TESTER_PARAM(kill_signal, "s"),
  TESTER_PARAM(max_stack_size, "d"),
  TESTER_PARAM(max_data_size, "d"),
  TESTER_PARAM(max_vm_size, "d"),
  TESTER_PARAM(clear_env, "d"),

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

  TESTER_PARAM(start_env, "x"),

  { 0, 0, 0, 0 }
};

static int problem_counter;
static int language_counter;
static int tester_counter;

static void problem_init_func(struct generic_section_config *);
static void tester_init_func(struct generic_section_config *);

static struct config_section_info params[] =
{
  { "global", sizeof(struct section_global_data), section_global_params },
  { "problem", sizeof(struct section_problem_data), section_problem_params,
    &problem_counter, problem_init_func },
  { "language",sizeof(struct section_language_data),section_language_params,
    &language_counter },
  { "tester", sizeof(struct section_tester_data), section_tester_params,
    &tester_counter, tester_init_func },
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
problem_init_func(struct generic_section_config *gp)
{
  struct section_problem_data *p = (struct section_problem_data*) gp;

  p->use_stdin = -1;
  p->use_stdout = -1;
  p->team_enable_rep_view = -1;
  p->use_corr = -1;
  p->test_sfx[0] = 1;
  p->corr_sfx[0] = 1;
}

static void
tester_init_func(struct generic_section_config *gp)
{
  struct section_tester_data *p = (struct section_tester_data*) gp;

  p->is_dos = -1;
  p->no_redirect = -1;
  p->no_core_dump = -1;
  p->clear_env = -1;
}

static char*
tester_get_name(void const *vpt)
{
  struct section_tester_data *pt = (struct section_tester_data *) vpt;
  return pt->name;
}

struct inheritance_info
{
  unsigned long  offset;        /* offset of this field */
  char          *name;          /* name of this field */

  int (*isdef_func)(void *);    /* checks, whether field is defined */
  void (*copy_func)(void *d, void *s); /* copies s to d */
};

int
inherit_fields(struct inheritance_info *iinfo,
               void *obj, char *name, int stot, void **sups,
               char *(*get_name_func)(void const *))
{
  int   ii, j, defnum, defpos;
  void *objf, *sobjf;

  for (ii = 0; iinfo[ii].name; ii++) {
    objf = XPDEREF(void, obj, iinfo[ii].offset);
    /*
    fprintf(stderr, ">>objf: %#08lx,%lu,%#08lx\n",
            (unsigned long) obj, (unsigned long) iinfo[ii].offset,
            (unsigned long) objf);
    */
    if (iinfo[ii].isdef_func(objf)) continue;
    for (j = 0, defpos = -1, defnum = 0; j < stot; j++) {
      sobjf = XPDEREF(void, sups[j], iinfo[ii].offset);
      if (iinfo[ii].isdef_func(sobjf)) {
        defnum++;
        defpos = j;
      }
    }
    if (defnum > 1) {
      err(_("several supertesters define %s for %s"),
          iinfo[ii].name, name);
      return -1;
    }
    if (defnum == 0) continue;
    sobjf = XPDEREF(void, sups[defpos], iinfo[ii].offset);
    info(_("%s.%s inherited from %s"),
         name, iinfo[ii].name, get_name_func(sups[defpos]));
    iinfo[ii].copy_func(objf, sobjf);
  }

  return 0;
}

static int inh_isdef_int(void *vpint)
{
  int *pint = (int*) vpint;
  if (*pint != -1) return 1;
  return 0;
}
static int inh_isdef_int2(void *vpint)
{
  int *pint = (int*) vpint;
  if (*pint != 0) return 1;
  return 0;
}
static void inh_copy_int(void *dst, void *src)
{
  memcpy(dst, src, sizeof(int));
}

static int inh_isdef_path(void *vppath)
{
  char *pc = (char *) vppath;
  if (*pc) return 1;
  return 0;
}
static int inh_isdef_path2(void *vppath)
{
  char *pc = (char *) vppath;

  (void) &(inh_isdef_path2);
  if (*pc == 1) return 0;
  return 1;
}
static void inh_copy_path(void *dst, void *src)
{
  memcpy(dst, src, sizeof(path_t));
}

#define TESTER_INH(f,d,c) {TESTER_OFFSET(f),#f,inh_isdef_##d,inh_copy_##c }
static struct inheritance_info tester_inheritance_info[] =
{
  TESTER_INH(arch, path, path),
  TESTER_INH(key, path, path),
  TESTER_INH(tester_dir, path, path),
  TESTER_INH(tmp_dir, path, path),
  TESTER_INH(work_dir, path, path),
  TESTER_INH(server_root_dir, path, path),
  TESTER_INH(exe_dir, path, path),
  TESTER_INH(no_core_dump, int, int),
  TESTER_INH(clear_env, int, int),
  TESTER_INH(kill_signal, path, path),
  TESTER_INH(max_stack_size, int2, int),
  TESTER_INH(max_data_size, int2, int),
  TESTER_INH(max_vm_size, int2, int),
  TESTER_INH(is_dos, int, int),
  TESTER_INH(no_redirect, int, int),
  TESTER_INH(errorcode_file, path, path),
  TESTER_INH(error_file, path, path),
  TESTER_INH(check_cmd, path, path),
  TESTER_INH(start_cmd, path, path),
  TESTER_INH(prepare_cmd, path, path),

  { 0, 0, 0, 0 }
};

static int
process_abstract_tester(int i)
{
  struct section_tester_data *atp = abstr_testers[i], *katp;
  struct section_tester_data **sups;
  char ***envs;
  char *ish;
  char **nenv;
  int   stot, j, k;

  if (!atp->name[0]) {
    err(_("abstract tester must define tester name"));
    return -1;
  }
  ish = atp->name;
  if (atp->id) {
    err(_("abstract tester %s must not have id"), ish);
    return -1;
  }
  if (atp->problem || atp->problem_name[0]) {
    err(_("abstract tester %s cannot reference a problem"), ish);
    return -1;
  }

  // no inheritance
  if (!atp->super || !atp->super[0]) {
    atp->is_processed = 1;
    return 0;
  }

  // count the number of supertesters and create array of references
  for (stot = 0; atp->super[stot]; stot++);
  sups = (struct section_tester_data**) alloca(stot * sizeof(sups[0]));
  envs = (char***) alloca((stot + 1) * sizeof(envs[0]));
  memset(sups, 0, stot * sizeof(sups[0]));
  memset(envs, 0, stot * sizeof(envs[0]));
  envs[stot] = atp->start_env;

  for (j = 0; j < stot; j++) {
    katp = 0;
    for (k = 0; k < max_abstr_tester; k++) {
      katp = abstr_testers[k];
      if (!katp || !katp->name[0]) continue;
      if (!strcmp(atp->super[j], katp->name)) break;
    }
    if (k >= max_abstr_tester || !katp) {
      err(_("abstract tester %s not found"), atp->super[j]);
      return -1;
    }
    if (!katp->is_processed) {
      err(_("abstract tester %s must be defined before use"), atp->super[j]);
      return -1;
    }
    sups[j] = katp;
    envs[j] = katp->start_env;
  }

  for (j = 0; j < stot; j++)
    fprintf(stderr, ">>%s\n", sups[j]->name);

  if (inherit_fields(tester_inheritance_info,
                     atp, ish, stot, (void**) sups,
                     tester_get_name) < 0)
    return -1;

  // merge all the start_env fields
  nenv = sarray_merge_arr(stot + 1, envs);
  sarray_free(atp->start_env);
  atp->start_env = nenv;

  atp->is_processed = 1;
  return 0;
}

static int
set_defaults(int mode)
{
  struct generic_section_config *p;

  int i, j, si;
  char *ish;
  char *sish;

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

  for (i = 0; i < max_abstr_prob && mode != PREPARE_COMPILE; i++) {
    if (!abstr_probs[i]->short_name[0]) {
      err(_("abstract problem must define problem short name"));
      return -1;
    }
    ish = abstr_probs[i]->short_name;
    if (abstr_probs[i]->id) {
      err(_("abstract problem %s must not define problem id"), ish);
      return -1;
    }
    if (abstr_probs[i]->long_name[0]) {
      err(_("abstract problem %s must not define problem long name"), ish);
      return -1;
    }
    if (abstr_probs[i]->super[0]) {
      err(_("abstract problem %s cannot have a superproblem"), ish);
      return -1;
    }
  }

  for (i = 1; i <= max_prob && mode != PREPARE_COMPILE; i++) {
    if (!probs[i]) continue;
    si = -1;
    sish = 0;
    if (probs[i]->super[0]) {
      for (si = 0; si < max_abstr_prob; si++)
        if (!strcmp(abstr_probs[si]->short_name, probs[i]->super))
          break;
      if (si >= max_abstr_prob) {
        err(_("abstract problem `%s' is not defined"), probs[i]->super);
        return -1;
      }
      sish = abstr_probs[si]->short_name;
    }
    if (!probs[i]->short_name[0]) {
      err(_("problem %d short name must be set"), i);
      return -1;
    }
    ish = probs[i]->short_name;
    if (!probs[i]->long_name[0]) {
      info(_("problem.%s.long_name set to \"Problem %s\""), ish, ish);
      sprintf(probs[i]->long_name, "Problem %s", ish);
    }

    if (probs[i]->team_enable_rep_view == -1 && si != -1
        && abstr_probs[si]->team_enable_rep_view != -1) {
      probs[i]->team_enable_rep_view = abstr_probs[si]->team_enable_rep_view;
      info(_("problem.%s.team_enable_rep_view inherited from problem.%s (%d)"),
           ish, sish, probs[i]->team_enable_rep_view);
    }
    if (probs[i]->team_enable_rep_view == -1) {
      info(_("problem.%s.team_enable_rep_view inherited from global (%d)"),
           ish, global->team_enable_rep_view);
      probs[i]->team_enable_rep_view = global->team_enable_rep_view;
    } else if (probs[i]->team_enable_rep_view == -1) {
      probs[i]->team_enable_rep_view = 0;
    }

    if (!probs[i]->full_score && si != -1
        && abstr_probs[si]->full_score) {
      probs[i]->full_score = abstr_probs[si]->full_score;
      info(_("problem.%s.full_score inherited from problem.%s (%d)"),
           ish, sish, probs[i]->full_score);
    }
    if (!probs[i]->full_score) {
      probs[i]->full_score = DFLT_P_FULL_SCORE;
      info(_("problem.%s.full_score set to %d"), ish, DFLT_P_FULL_SCORE);
    }

    if (!probs[i]->test_score && si != -1
        && abstr_probs[si]->test_score) {
      probs[i]->test_score = abstr_probs[si]->test_score;
      info(_("problem.%s.test_score inherited from problem.%s (%d)"),
           ish, sish, probs[i]->test_score);
    }
    if (!probs[i]->test_score) {
      probs[i]->test_score = DFLT_P_TEST_SCORE;
      info(_("problem.%s.test_score set to %d"), ish,  DFLT_P_TEST_SCORE);
    }

    if (!probs[i]->run_penalty && si != -1
        && abstr_probs[si]->run_penalty) {
      probs[i]->run_penalty = abstr_probs[si]->run_penalty;
      info(_("problem.%s.run_penalty inherited from problem.%s (%d)"),
           ish, sish, probs[i]->run_penalty);
    }
    if (!probs[i]->run_penalty) {
      probs[i]->run_penalty = DFLT_P_RUN_PENALTY;
      info(_("problem.%s.run_penalty set to %d"), ish, DFLT_P_RUN_PENALTY);
    }
    
    if (probs[i]->use_stdin == -1 && si != -1
        && abstr_probs[si]->use_stdin != -1) {
      probs[i]->use_stdin = abstr_probs[si]->use_stdin;
      info(_("problem.%s.use_stdin inherited from problem.%s (%d)"),
           ish, sish, probs[i]->use_stdin);
    }
    if (probs[i]->use_stdin == -1) {
      probs[i]->use_stdin = 0;
      info(_("problem.%s.use_stdin set to %d"), ish, 0);
    }

    if (probs[i]->use_stdout == -1 && si != -1
        && abstr_probs[si]->use_stdout != -1) {
      probs[i]->use_stdout = abstr_probs[si]->use_stdout;
      info(_("problem.%s.use_stdout inherited from problem.%s (%d)"),
           ish, sish, probs[i]->use_stdout);
    }
    if (probs[i]->use_stdout == -1) {
      probs[i]->use_stdout = 0;
      info(_("problem.%s.use_stdout set to %d"), ish, 0);
    }

    if (!probs[i]->time_limit && si != -1 && abstr_probs[si]->time_limit) {
      probs[i]->time_limit = abstr_probs[si]->time_limit;
      info(_("problem.%s.time_limit inherited from problem.%s (%d)"),
           ish, sish, probs[i]->time_limit);
    }
    if (!probs[i]->real_time_limit && si != -1
        && abstr_probs[si]->real_time_limit) {
      probs[i]->real_time_limit = abstr_probs[si]->real_time_limit;
      info(_("problem.%s.real_time_limit inherited from problem.%s (%d)"),
           ish, sish, probs[i]->real_time_limit);
    }
    if (!probs[i]->test_score_list[0] && si != -1
        && abstr_probs[si]->test_score_list[0]) {
      strcpy(probs[i]->test_score_list, abstr_probs[si]->test_score_list);
      info(_("problem.%s.test_score_list inherited from problem.%s (`%s')"),
           ish, sish, probs[i]->test_score_list);
    }
    if (probs[i]->test_sfx[0] == 1 && si != -1 &&
        abstr_probs[si]->test_sfx[0] != 1) {
      strcpy(probs[i]->test_sfx, abstr_probs[si]->test_sfx);
      info(_("problem.%s.test_sfx inherited from problem.%s ('%s')"),
           ish, sish, probs[i]->test_sfx);
    }
    if (probs[i]->test_sfx[0] == 1 && global->test_sfx[0] != 1) {
      strcpy(probs[i]->test_sfx, global->test_sfx);
      info(_("problem.%s.test_sfx inherited from global ('%s')"),
           ish, probs[i]->test_sfx);
    }
    if (probs[i]->test_sfx[0] == 1) {
      probs[i]->test_sfx[0] = 0;
    }
    if (probs[i]->corr_sfx[0] == 1 && si != -1 &&
        abstr_probs[si]->corr_sfx[0] != 1) {
      strcpy(probs[i]->corr_sfx, abstr_probs[si]->corr_sfx);
      info(_("problem.%s.corr_sfx inherited from problem.%s ('%s')"),
           ish, sish, probs[i]->corr_sfx);
    }
    if (probs[i]->corr_sfx[0] == 1 && global->corr_sfx[0] != 1) {
      strcpy(probs[i]->corr_sfx, global->corr_sfx);
      info(_("problem.%s.corr_sfx inherited from global ('%s')"),
           ish, probs[i]->corr_sfx);
    }
    if (probs[i]->corr_sfx[0] == 1) {
      probs[i]->corr_sfx[0] = 0;
    }

    if (mode == PREPARE_RUN) {
      if (!probs[i]->test_dir[0] && si != -1
          && abstr_probs[si]->test_dir[0]) {
        sformat_message(probs[i]->test_dir, PATH_MAX,
                        abstr_probs[si]->test_dir,
                        NULL, probs[i], NULL, NULL, NULL);
        info(_("problem.%s.test_dir taken from problem.%s ('%s')"),
             ish, sish, probs[i]->test_dir);
      }
      if (!probs[i]->test_dir[0]) {
        info(_("problem.%s.test_dir set to %s"), ish, probs[i]->short_name);
        pathcpy(probs[i]->test_dir, probs[i]->short_name);
      }
      path_add_dir(probs[i]->test_dir, global->test_dir);
      info(_("problem.%s.test_dir is '%s'"), 
           ish, probs[i]->test_dir);

      if (!probs[i]->corr_dir[0] && si != -1
          && abstr_probs[si]->corr_dir[0]) {
        sformat_message(probs[i]->corr_dir, PATH_MAX,
                        abstr_probs[si]->corr_dir,
                        NULL, probs[i], NULL, NULL, NULL);
        info(_("problem.%s.corr_dir taken from problem.%s ('%s')"),
             ish, sish, probs[i]->corr_dir);
      }
      if (probs[i]->corr_dir[0]) {
        path_add_dir(probs[i]->corr_dir, global->corr_dir);
        info(_("problem.%s.corr_dir is '%s'"), ish, probs[i]->corr_dir);
      }

      if (!probs[i]->input_file[0] && si != -1
          && abstr_probs[si]->input_file[0]) {
        strcpy(probs[i]->input_file, abstr_probs[si]->input_file);
        info(_("problem.%s.input_file inherited from problem.%s ('%s')"),
             ish, sish, probs[i]->input_file);
      }
      if (!probs[i]->input_file[0]) {
        info(_("problem.%s.input_file set to %s"), ish, DFLT_P_INPUT_FILE);
        pathcpy(probs[i]->input_file, DFLT_P_INPUT_FILE);
      }
      if (!probs[i]->output_file[0] && si != -1
          && abstr_probs[si]->output_file[0]) {
        strcpy(probs[i]->output_file, abstr_probs[si]->output_file);
        info(_("problem.%s.output_file inherited from problem.%s ('%s')"),
             ish, sish, probs[i]->output_file);
      }
      if (!probs[i]->output_file[0]) {
        info(_("problem.%s.output_file set to %s"), ish, DFLT_P_OUTPUT_FILE);
        pathcpy(probs[i]->output_file, DFLT_P_OUTPUT_FILE);
      }

      if (probs[i]->use_corr == -1 && si != -1
          && abstr_probs[si]->use_corr != -1) {
        probs[i]->use_corr = abstr_probs[si]->use_corr;
        info(_("problem.%s.use_corr inherited from problem.%s (%d)"),
             ish, sish, probs[i]->use_corr);
      }
      if (probs[i]->use_corr == -1 && probs[i]->corr_dir[0]) {
        probs[i]->use_corr = 1;
      }
      if (probs[i]->use_corr == -1) {
        probs[i]->use_corr = 0;
      }
    }
  }

  if (mode == PREPARE_SERVE || mode == PREPARE_RUN) {
    for (i = 0; i < max_abstr_tester; i++) {
      if (process_abstract_tester(i) < 0) return -1;
    }
  }

#define TESTER_INIT_FIELD(f,d,c) do { if (!testers[i]->f[0]) { info(_("tester.%d.%s set to %s"), i, #f, d); pathcat(testers[i]->f, d); } path_add_dir(testers[i]->f, testers[i]->c); } while(0)
  if (mode == PREPARE_SERVE || mode == PREPARE_RUN) {
    for (i = 1; i <= max_tester; i++) {
      struct section_tester_data *tp = 0;
      struct section_tester_data *atp = 0;

      if (!testers[i]) continue;
      tp = testers[i];

      si = -1;
      sish = 0;
      if (tp->super && tp->super[0]) {
        if (tp->super[1]) {
          err(_("concrete tester may inherit only one abstract tester"));
          return -1;
        }
        for (si = 0; si < max_abstr_tester; si++) {
          atp = abstr_testers[si];
          if (!strcmp(atp->name, tp->super[0]))
            break;
        }
        if (si >= max_abstr_tester) {
          err(_("abstract tester %s not found"), tp->super[0]);
          return -1;
        }
        sish = atp->name;
      }

      /* copy arch and key */
      if (!tp->arch[0] && atp && atp->arch[0]) {
        strcpy(tp->arch, atp->arch);
        info(_("tester.%d.arch inherited from tester.%s ('%s')"),
             i, sish, tp->arch);
      }
      if (!tp->key[0] && atp && atp->key[0]) {
        strcpy(tp->key, atp->key);
        info(_("tester.%d.key inherited from tester.%s ('%s')"),
             i, sish, tp->key);
      }

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
        if (!tp->tester_dir[0] && atp && atp->tester_dir[0]) {
          sformat_message(tp->tester_dir, PATH_MAX, atp->tester_dir,
                          global, probs[tp->problem], NULL,
                          tp, NULL);
          info(_("tester.%d.tester_dir inherited from tester.%s ('%s')"),
               i, sish, tp->tester_dir);
        }
        if (!testers[i]->tester_dir[0]) {
          info(_("tester.%d.tester_dir set to \"%s\""), i, testers[i]->name);
          pathcpy(testers[i]->tester_dir, testers[i]->name);
        }
        path_add_dir(testers[i]->tester_dir, global->work_dir);
        if (!tp->tmp_dir[0] && atp && atp->tmp_dir[0]) {
          sformat_message(tp->tmp_dir, PATH_MAX, atp->tmp_dir,
                          global, probs[tp->problem], NULL,
                          tp, NULL);
          info(_("tester.%d.tmp_dir inherited from tester.%s ('%s')"),
               i, sish, tp->tmp_dir);
        }
        TESTER_INIT_FIELD(tmp_dir, DFLT_T_TMP_DIR, tester_dir);
        if (!tp->work_dir[0] && atp && atp->work_dir[0]) {
          sformat_message(tp->work_dir, PATH_MAX, atp->work_dir,
                          global, probs[tp->problem], NULL,
                          tp, NULL);
          info(_("tester.%d.work_dir inherited from tester.%s ('%s')"),
               i, sish, tp->work_dir);
        }
        TESTER_INIT_FIELD(work_dir, DFLT_T_WORK_DIR, tester_dir);
      }

      if (!tp->server_root_dir[0] && atp && atp->server_root_dir[0]) {
        strcpy(tp->server_root_dir, atp->server_root_dir);
        info(_("tester.%d.server_root_dir inherited from tester.%s ('%s')"),
             i, sish, tp->server_root_dir);
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

      if (!tp->exe_dir[0] && atp && atp->exe_dir[0]) {
          sformat_message(tp->exe_dir, PATH_MAX, atp->exe_dir,
                          global, probs[tp->problem], NULL,
                          tp, NULL);
          info(_("tester.%d.exe_dir inherited from tester.%s ('%s')"),
               i, sish, tp->exe_dir);        
      }
      TESTER_INIT_FIELD(exe_dir, testers[i]->name, server_exe_dir);

      if (tp->no_core_dump == -1 && atp && atp->no_core_dump != -1) {
        tp->no_core_dump = atp->no_core_dump;
        info(_("tester.%d.no_core_dump inherited from tester.%s (%d)"),
             i, sish, tp->no_core_dump);        
      }
      if (tp->no_core_dump == -1) {
        tp->no_core_dump = 0;
      }
      if (tp->clear_env == -1 && atp && atp->clear_env != -1) {
        tp->clear_env = atp->clear_env;
        info(_("tester.%d.clear_env inherited from tester.%s (%d)"),
             i, sish, tp->clear_env);
      }
      if (tp->clear_env == -1) {
        tp->clear_env = 0;
      }
      if (!tp->kill_signal[0] && atp && atp->kill_signal[0]) {
        strcpy(tp->kill_signal, atp->kill_signal);
        info(_("tester.%d.kill_signal inherited from tester.%s ('%s')"),
             i, sish, tp->kill_signal);
      }
      if (!tp->max_stack_size && atp && atp->max_stack_size) {
        tp->max_stack_size = atp->max_stack_size;
        info(_("tester.%d.max_stack_size inherited from tester.%s (%d)"),
             i, sish, tp->max_stack_size);        
      }
      if (!tp->max_data_size && atp && atp->max_data_size) {
        tp->max_data_size = atp->max_data_size;
        info(_("tester.%d.max_data_size inherited from tester.%s (%d)"),
             i, sish, tp->max_data_size);        
      }
      if (!tp->max_vm_size && atp && atp->max_vm_size) {
        tp->max_vm_size = atp->max_vm_size;
        info(_("tester.%d.max_vm_size inherited from tester.%s (%d)"),
             i, sish, tp->max_vm_size);        
      }

      if (tp->is_dos == -1 && atp && atp->is_dos != -1) {
        tp->is_dos = atp->is_dos;
        info(_("tester.%d.is_dos inherited from tester.%s (%d)"),
             i, sish, tp->is_dos);        
      }
      if (tp->is_dos == -1) {
        tp->is_dos = 0;
      }
      if (tp->no_redirect == -1 && atp && atp->no_redirect != -1) {
        tp->no_redirect = atp->no_redirect;
        info(_("tester.%d.no_redirect inherited from tester.%s (%d)"),
             i, sish, tp->no_redirect);        
      }
      if (tp->no_redirect == -1) {
        tp->no_redirect = 0;
      }
      if (!tp->errorcode_file[0] && atp && atp->errorcode_file) {
        sformat_message(tp->errorcode_file, PATH_MAX, atp->errorcode_file,
                        global, probs[tp->problem], NULL,
                        tp, NULL);
        info(_("tester.%d.errorcode_file inherited from tester.%s ('%s')"),
             i, sish, tp->errorcode_file);        
      }

      if (atp && atp->start_env) {
        tp->start_env = sarray_merge_pf(atp->start_env, tp->start_env);
      }

      if (mode == PREPARE_RUN) {
        if (!tp->error_file[0] && atp && atp->error_file[0]) {
          sformat_message(tp->error_file, PATH_MAX, atp->error_file,
                          global, probs[tp->problem], NULL,
                          tp, NULL);
          info(_("tester.%d.error_file inherited from tester.%s ('%s')"),
               i, sish, tp->error_file);        
        }
        if (!testers[i]->error_file[0]) {
          info(_("tester.%d.error_file set to %s"), i, DFLT_T_ERROR_FILE);
          pathcpy(testers[i]->error_file, DFLT_T_ERROR_FILE);
        }
        if (!tp->check_cmd[0] && atp && atp->check_cmd[0]) {
          sformat_message(tp->check_cmd, PATH_MAX, atp->check_cmd,
                          global, probs[tp->problem], NULL,
                          tp, NULL);
          info(_("tester.%d.check_cmd inherited from tester.%s ('%s')"),
               i, sish, tp->check_cmd);        
        }
        if (!testers[i]->check_cmd[0]) {
          err(_("tester.%d.check_cmd must be set"), i);
          return -1;
        }
        pathmake4(testers[i]->check_cmd, global->checker_dir, "/",
                  testers[i]->check_cmd, 0);
        if (!tp->start_cmd[0] && atp && atp->start_cmd[0]) {
          sformat_message(tp->start_cmd, PATH_MAX, atp->start_cmd,
                          global, probs[tp->problem], NULL,
                          tp, NULL);
          info(_("tester.%d.start_cmd inherited from tester.%s ('%s')"),
               i, sish, tp->start_cmd);        
        }
        if (testers[i]->start_cmd[0]) {
          pathmake4(testers[i]->start_cmd, global->script_dir, "/",
                    testers[i]->start_cmd, 0);
        }
        if (!tp->prepare_cmd[0] && atp && atp->prepare_cmd[0]) {
          sformat_message(tp->prepare_cmd, PATH_MAX, atp->prepare_cmd,
                          global, probs[tp->problem], NULL,
                          tp, NULL);
          info(_("tester.%d.prepare_cmd inherited from tester.%s ('%s')"),
               i, sish, tp->prepare_cmd);        
        }
        if (tp->prepare_cmd[0]) {
          pathmake4(tp->prepare_cmd, global->script_dir, "/",
                    tp->prepare_cmd, 0);
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
      if (q->abstract) {
        if (max_abstr_prob > MAX_PROBLEM) {
          err(_("too many abstract problems"));
          return -1;
        }
        abstr_probs[max_abstr_prob++] = q;
      } else {
        if (!q->id) info(_("assigned problem id = %d"), (q->id=last_prob + 1));
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
      }
    } else if (!strcmp(p->name, "tester") && mode != PREPARE_COMPILE) {
      t = (struct section_tester_data *) p;
      if (t->abstract) {
        if (max_abstr_tester > MAX_TESTER) {
          err(_("too many abstract tester"));
          return -1;
        }
        abstr_testers[max_abstr_tester++] = t;
      } else {
        if (!t->id)
          info(_("assigned tester id = %d"),(t->id = last_tester + 1));
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
    config = parse_param(NULL, f, params, 1);
    f = 0;
  } else {
    config = parse_param(config_file, 0, params, 1);
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

void print_global(FILE *o)
{
  int i;
  struct config_parse_info *pp;

  for (i = 0; section_global_params[i].name; i++) {
    pp = &section_global_params[i];
    if (!strcmp(pp->type, "s")) {
      char *pc = XPDEREF(char,global, pp->offset);
      fprintf(o, "%s = \"%s\"\n", pp->name, pc);
    } else if (!strcmp(pp->type, "d")) {
      int *pi = XPDEREF(int,global, pp->offset);
      fprintf(o, "%s = %d\n", pp->name, *pi);
    }
  }
  fprintf(o, "\n");
}

void print_problem(FILE *o, struct section_problem_data *p)
{
  int i;
  struct config_parse_info *pp;

  fprintf(o, "[problem]\n");
  for (i = 0;; i++) {
    pp = &section_problem_params[i];
    if (!pp->name) break;
    if (!strcmp(pp->type, "s")) {
      char *pc = XPDEREF(char,p, pp->offset);
      if (!strcmp(pp->name, "super")) fprintf(o, "; ");
      fprintf(o, "%s = \"%s\"\n", pp->name, pc);
    } else if (!strcmp(pp->type, "d")) {
      int *pi = XPDEREF(int,p, pp->offset);
      fprintf(o, "%s = %d\n", pp->name, *pi);
    }
  }
  fprintf(o, "\n");
}
void print_all_problems(FILE *o)
{
  int i;

  for (i = 0; i < max_abstr_prob; i++)
    print_problem(o, abstr_probs[i]);
  for (i = 1; i <= max_prob; i++) {
    if (!probs[i]) continue;
    print_problem(o, probs[i]);
  }
}

void print_language(FILE *o, struct section_language_data *l)
{
  int i;
  struct config_parse_info *pp;

  fprintf(o, "[language]\n");
  for (i = 0;; i++) {
    pp = &section_language_params[i];
    if (!pp->name) break;
    if (!strcmp(pp->type, "s")) {
      char *pc = XPDEREF(char,l, pp->offset);
      fprintf(o, "%s = \"%s\"\n", pp->name, pc);
    } else if (!strcmp(pp->type, "d")) {
      int *pi = XPDEREF(int,l, pp->offset);
      fprintf(o, "%s = %d\n", pp->name, *pi);
    }
  }
  fprintf(o, "\n");
}
void print_all_languages(FILE *o)
{
  int i;

  for (i = 1; i <= max_lang; i++) {
    if (!langs[i]) continue;
    print_language(o, langs[i]);
  }
}

void print_tester(FILE *o, struct section_tester_data *t)
{
  int i;

  fprintf(o, "[tester]\n");
  if (t->abstract) fprintf(o, "abstract\n");
  fprintf(o, "name = \"%s\"\n", t->name);
  fprintf(o, "id = %d\n", t->id);
  if (t->super) {
    for (i = 0; t->super[i]; i++)
      fprintf(o, "; super = \"%s\"\n", t->super[i]);
    /*
    for (;t->super[i] != (char*) 1; i++)
      fprintf(o, "super = (null)\n");
    fprintf(o, "super = (1)\n");
    */
  }
  fprintf(o, "problem = %d\n", t->problem);
  fprintf(o, "problem_name = \"%s\"\n", t->problem_name);
  fprintf(o, "is_dos = %d\n", t->is_dos);
  fprintf(o, "no_redirect = %d\n", t->no_redirect);
  fprintf(o, "arch = \"%s\"\n", t->arch);
  fprintf(o, "key = \"%s\"\n", t->key);
  fprintf(o, "no_core_dump = %d\n", t->no_core_dump);
  fprintf(o, "kill_signal = \"%s\"\n", t->kill_signal);
  fprintf(o, "max_stack_size = %d\n", t->max_stack_size);
  fprintf(o, "max_data_size = %d\n", t->max_data_size);
  fprintf(o, "max_vm_size = %d\n", t->max_vm_size);
  fprintf(o, "clear_env = %d\n", t->clear_env);
  fprintf(o, "server_root_dir = \"%s\"\n", t->server_root_dir);
  fprintf(o, "server_var_dir = \"%s\"\n", t->server_var_dir);
  fprintf(o, "server_run_dir = \"%s\"\n", t->server_run_dir);
  fprintf(o, "server_exe_dir = \"%s\"\n", t->server_exe_dir);
  fprintf(o, "run_status_dir = \"%s\"\n", t->run_status_dir);
  fprintf(o, "run_report_dir = \"%s\"\n", t->run_report_dir);
  fprintf(o, "run_team_report_dir = \"%s\"\n", t->run_team_report_dir);
  fprintf(o, "exe_dir = \"%s\"\n", t->exe_dir);
  fprintf(o, "tester_dir = \"%s\"\n", t->tester_dir);
  fprintf(o, "tmp_dir = \"%s\"\n", t->tmp_dir);
  fprintf(o, "work_dir = \"%s\"\n", t->work_dir);
  fprintf(o, "errorcode_file = \"%s\"\n", t->errorcode_file);
  fprintf(o, "error_file = \"%s\"\n", t->error_file);
  fprintf(o, "prepare_cmd = \"%s\"\n", t->prepare_cmd);
  fprintf(o, "start_cmd = \"%s\"\n", t->start_cmd);
  fprintf(o, "check_cmd = \"%s\"\n", t->check_cmd);

  if (t->start_env) {
    for (i = 0; t->start_env[i]; i++)
      fprintf(o, "start_env = \"%s\"\n", t->start_env[i]);
    /*
    for (;t->start_env[i] != (char*) 1; i++)
      fprintf(o, "start_env = (null)\n");
    fprintf(o, "start_env = (1)\n");
    */
  }
  fprintf(o, "\n");
}
void print_all_testers(FILE *o)
{
  int i;

  /*
  fprintf(stderr, "====%d, %d, %u\n", max_abstr_tester, max_tester,
          sizeof(struct section_tester_data));
  */

  for (i = 0; i < max_abstr_tester; i++)
    print_tester(o, abstr_testers[i]);
  for (i = 1; i <= max_tester; i++) {
    if (!testers[i]) continue;
    print_tester(o, testers[i]);
  }

  fflush(o);
}

void print_configuration(FILE *o)
{
  print_global(o);
  print_all_problems(o);
  print_all_languages(o);
  print_all_testers(o);
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
