/* -*- c -*- */
/* $Id$ */
#ifndef __PREPARE_H__
#define __PREPARE_H__

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

#include "pathutl.h"
#include "parsecfg.h"

#include <stdio.h>

enum { PREPARE_SERVE, PREPARE_COMPILE, PREPARE_RUN };
enum { PREPARE_QUIET = 1, PREPARE_USE_CPP = 2 };

/* scoring systems */
enum { SCORE_ACM, SCORE_KIROV };

struct section_global_data
{
  struct generic_section_config g;

  int    sleep_time;            /* interval between directory polls (millis) */
  int    serve_sleep_time;      /* poll interval for serve, if different */
  int    contest_time;          /* contest time (in seconds) */
  int    max_run_size;          /* max size of a run */
  int    max_run_total;         /* max total of all runs for each team */
  int    max_run_num;           /* max number of runs for each team */
  int    max_clar_size;         /* max size of a clar */
  int    max_clar_total;        /* max total of all clars for each team */
  int    max_clar_num;          /* max number of clars for each team */
  int    board_fog_time;        /* time before the end when the board
                                 * is not updated */
  int    board_unfog_time;      /* time after the end of the contest
                                 * when the board is again updated */

  int    team_enable_src_view;  /* teams are allowed to view sources? */
  int    team_enable_rep_view;  /* teams are allowed to view reports? */

  path_t charset;               /* html pages charset */

  path_t name;                  /* name of the contest */
  path_t root_dir;

  /* ====== CONFIGURATION FILES/DIRECTORIES SETUP ====== */
  path_t conf_dir;              /* configuration dir */

  path_t teamdb_file;           /* team account database */
  path_t passwd_file;           /* team password database */
  path_t script_dir;            /* default location of compile
                                 * and run scripts */
  path_t test_dir;              /* common prefix dir for tests */
  path_t corr_dir;              /* common prefix dir for correct answers */
  path_t checker_dir;           /* default location of checkers */
  path_t test_sfx;              /* default test files suffix */
  path_t corr_sfx;              /* default correct files suffix */

  /* ====== VARIABLE FILES/DIRECTORIES SETUP ====== */
  path_t var_dir;               /* variable files dir */

  /* --- server logging --- */
  //path_t log_file;              /* logger log file */
  path_t run_log_file;          /* run log file */
  path_t clar_log_file;         /* clar log file */
  path_t archive_dir;           /* common directory for archives */
  path_t clar_archive_dir;      /* clar archive directory */
  path_t run_archive_dir;       /* run archive directory */
  path_t report_archive_dir;    /* report archive directory */
  path_t team_report_archive_dir; /* team report archive directory */

  /* --- server status reporting --- */
  path_t status_dir;            /* server status directory */
  path_t work_dir;              /* subdir for working dirs */

  /* --- server <-> clients interaction --- */
  path_t pipe_dir;              /* server->client pipes directory */
  path_t team_dir;              /* team->server communication subdir */
  path_t team_cmd_dir;          /* team->server commands directory */
  path_t team_data_dir;         /* team->server data directory */
  path_t judge_dir;             /* judge->server comm. subdir */
  path_t judge_cmd_dir;         /* judge->server commands directory */
  path_t judge_data_dir;        /* judge->server data directory */

  /* --- server <-> compile interaction --- */
  path_t compile_dir;           /* common subdirectory */
  path_t compile_src_dir;       /* common prefix dir for serve->compile */
  path_t compile_status_dir;    /* compile->serve status dir */
  path_t compile_report_dir;    /* compile->serve report dir */

  /* --- serve <-> run interaction --- */
  path_t run_dir;               /* common subdirectory */
  path_t run_exe_dir;           /* common prefix dir for serve->run */
  path_t run_status_dir;        /* run->serve status dir */
  path_t run_report_dir;        /* run->serve report dir */
  path_t run_team_report_dir;   /* run->serve team report dir */

  /* scoring settings */
  path_t score_system;          /* scoring system */
  int    score_system_val;      /* internal int value */

  int    max_file_length;       /* maximal length of the file in reports */
  int    max_line_length;       /* maximal length of line in reports */

  path_t team_info_url;         /* the team info URL template */
  path_t prob_info_url;         /* the problem info URL template */
};

struct section_problem_data
{
  struct generic_section_config g;

  int    id;                    /* problem identifier */
  int    abstract;              /* is this abstract problem specification */
  int    use_stdin;             /* 1, if solution uses stdin for input */
  int    use_stdout;            /* 1, if solution uses stdout for output */
  int    real_time_limit;       /* maximum astronomical time for a problem */
  int    time_limit;            /* time limit in secs */
  int    team_enable_rep_view;  /* are teams allowed to view reports? */
  int    full_score;            /* score for complete solution */
  int    test_score;            /* score for one test */
  int    run_penalty;           /* penalty for one run */
  int    use_corr;              /* whether the correct answers defined */
  path_t super;                 /* superproblem's short_name */
  path_t short_name;            /* short problem name, eg A, B, ... */
  path_t long_name;             /* long problem name */
  path_t test_dir;              /* directory with tests */
  path_t test_sfx;              /* test files suffix */
  path_t corr_dir;              /* directory with correct answers */
  path_t corr_sfx;              /* correct files suffix */
  path_t input_file;            /* input file name */
  path_t output_file;           /* output file name */
  path_t test_score_list;       /* scores for individual tests */

  int     ntests;               /* number of tests found */
  int    *tscores;              /* internal scores array  */
};

struct section_language_data
{
  struct generic_section_config g;

  int    id;                    /* language id */
  path_t short_name;            /* language short name */
  path_t long_name;             /* language long name */
  path_t key;                   /* configuration key */
  path_t arch;                  /* language architecture */
  path_t src_sfx;               /* source file suffix */
  path_t exe_sfx;               /* executable file suffix */
  path_t cmd;                   /* compile command */

  path_t server_root_dir;       /* server root directory */
  path_t server_var_dir;        /* server variable directory */
  path_t server_compile_dir;    /* global.compile_dir override */
  path_t server_src_dir;        /* server src directory */
  path_t compile_status_dir;
  path_t compile_report_dir;
  path_t src_dir;               /* source subdirectory */

  path_t work_dir;              /* working directory */
};

struct section_tester_data
{
  struct generic_section_config g;

  int    id;
  path_t name;                  /* tester name */
  int    problem;               /* reference problem number */
  path_t problem_name;          /* reference problem name */

  int    is_dos;                /* do unix->dos conversion of tests? */
  int    no_redirect;           /* do not redirect standard streams */

  path_t arch;                  /* checker architecture */
  path_t key;                   /* configuration key */

  int    abstract;              /* is this tester abstract */
  char **super;                 /* names of the supertesters */
  int    is_processed;          /* whether this tester has been processed */

  int no_core_dump;             /* disable core dumps */
  path_t kill_signal;           /* the signal to kill processes */
  int max_stack_size;           /* max size of the stack */
  int max_data_size;            /* max size of the data */
  int max_vm_size;              /* max size of the virtual memory */
  int clear_env;                /* whether the environment is cleared */

  path_t server_root_dir;
  path_t server_var_dir;
  path_t server_run_dir;
  path_t server_exe_dir;
  path_t run_status_dir;
  path_t run_report_dir;
  path_t run_team_report_dir;
  path_t exe_dir;               /* incoming executable subdirectory */

  path_t tester_dir;            /* tester private subdirectory */
  path_t tmp_dir;               /* temporary directory (report, prepare) */
  path_t work_dir;              /* checking work directory */
  path_t errorcode_file;        /* file that contains completion status */
  path_t error_file;            /* stderr output of the checked program */

  path_t prepare_cmd;           /* helper to prepare the executable */
  path_t start_cmd;             /* helper to start testing */
  path_t check_cmd;             /* checker */

  char **start_env;             /* environment variables for start_cmd */
};

extern struct generic_section_config *config;
extern struct section_global_data    *global;

extern struct section_language_data *langs[];
extern struct section_problem_data  *probs[];
extern struct section_tester_data   *testers[];

extern int max_tester;
extern int max_lang;
extern int max_prob;

int prepare(char const *, int flags, int mode, char const *opts);
int create_dirs(int mode);

int find_tester(int, char const *);

void print_problem(FILE *, struct section_problem_data *);
void print_language(FILE *, struct section_language_data *);
void print_tester(FILE *, struct section_tester_data *);

void print_global(FILE *);
void print_all_problems(FILE *);
void print_all_languages(FILE *);
void print_all_testers(FILE *);

void print_configuration(FILE *);

#endif /* __PREPARE_H__ */
