/* -*- c -*- */
/* $Id$ */
#ifndef __PREPARE_H__
#define __PREPARE_H__

/* Copyright (C) 2000-2003 Alexander Chernov <cher@ispras.ru> */

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

#include "pathutl.h"
#include "contests.h"
#include "parsecfg.h"
#include "nls.h"

#include <stdio.h>

enum { PREPARE_SERVE, PREPARE_COMPILE, PREPARE_RUN };
enum { PREPARE_QUIET = 1, PREPARE_USE_CPP = 2 };

#if !defined EJUDGE_SCORE_SYSTEM_DEFINED
#define EJUDGE_SCORE_SYSTEM_DEFINED
/* scoring systems */
enum { SCORE_ACM, SCORE_KIROV, SCORE_OLYMPIAD };
#endif /* EJUDGE_SCORE_SYSTEM_DEFINED */

struct testset_info
{
  int total;                  /* total number of tests in set */
  unsigned char *nums;
  int testop;
  int scoreop;
  int score;
};

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
  int    autoupdate_standings;  /* update standings automatically? */
  int    inactivity_timeout;    /* timeout for slave case */

  int    fog_standings_updated; /* INTERNAL: updated at the moment of fog? */
  int    start_standings_updated; /* INTERNAL: updated at the start */
  int    unfog_standings_updated; /* INTERNAL: updated after the fog */

  int    team_enable_src_view;  /* teams are allowed to view sources? */
  int    team_enable_rep_view;  /* teams are allowed to view reports? */
  int    disable_clars;         /* clarification requests disabled */
  int    disable_team_clars;    /* team cannot compose a clarification */
  int    ignore_compile_errors; /* ignore CE result for score calculation */
  int    enable_continue;       /* enable contest continuation after stop */

  path_t name;                  /* name of the contest */
  path_t root_dir;
  path_t serve_socket;          /* serve's socket name */

  int    enable_l10n;           /* enable string translation? */
  path_t l10n_dir;              /* localization message catalog */
  path_t standings_locale;
  int    standings_locale_id;

  /* userlist-server support */
  int    contest_id;
  path_t socket_path;
  path_t contests_dir;

  /* charsets */
  path_t charset;               /* html pages charset */
  struct nls_table *charset_ptr; /* internal charset */
  path_t standings_charset;
  struct nls_table *standings_charset_ptr;

  /* ====== CONFIGURATION FILES/DIRECTORIES SETUP ====== */
  path_t conf_dir;              /* configuration dir */

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

  /* --- server <-> compile interaction --- */
  /* global parameters are used by compile utility, whereas 
   * language-local parameters are used by serve */
  path_t compile_dir;           /* common subdirectory */
  path_t compile_queue_dir;     /* directory for serve->compile packets */
  path_t compile_src_dir;       /* directory for source files */

  /* these are used by serve */  
  /* var/compile prefix is implicit and cannot be changed! */
  path_t compile_out_dir;       /* base directory for compile results */
  path_t compile_status_dir;    /* compile->serve status dir */
  path_t compile_report_dir;    /* compile->serve report dir */

  path_t compile_work_dir;

  /* --- serve <-> run interaction --- */
  path_t run_dir;               /* common subdirectory */
  path_t run_queue_dir;         /* common prefix dir for serve->run packets */
  path_t run_exe_dir;           /* serve->run executables */

  path_t run_out_dir;           /* base directory for run results */
  path_t run_status_dir;        /* run->serve status dir */
  path_t run_report_dir;        /* run->serve report dir */
  path_t run_team_report_dir;   /* run->serve team report dir */

  path_t run_work_dir;          /* private run's temporary directory */
  path_t run_check_dir;         /* working directory for checked programs */

  /* scoring settings */
  path_t score_system;          /* scoring system */
  int    score_system_val;      /* internal int value */
  int    tests_to_accept;       /* how many tests to accept a submit */
  int    virtual;               /* 1, if virtual contest */

  int    max_file_length;       /* maximal length of the file in reports */
  int    max_line_length;       /* maximal length of line in reports */

  path_t team_info_url;         /* the team info URL template */
  path_t prob_info_url;         /* the problem info URL template */
  path_t standings_file_name;   /* public standings file name */
  path_t stand_header_file;     /* file to use as standings header */
  path_t stand_footer_file;     /* file to use as standings footer */

  unsigned char *stand_header_txt; /* actual header text */
  unsigned char *stand_footer_txt; /* actual footer text */

  // standings2 information
  path_t stand2_file_name;      /* must be set to standings 2 be activated */
  path_t stand2_header_file;
  path_t stand2_footer_file;
  unsigned char *stand2_header_txt;
  unsigned char *stand2_footer_txt;

  // public log information
  path_t plog_file_name;
  path_t plog_header_file;
  path_t plog_footer_file;
  unsigned char *plog_header_txt;
  unsigned char *plog_footer_txt;
  int plog_update_time;

  // fun
  path_t sound_player;
  path_t accept_sound;
  path_t runtime_sound;
  path_t timelimit_sound;
  path_t presentation_sound;
  path_t wrong_sound;
  path_t internal_sound;
  path_t start_sound;

  int team_download_time;       /* how often team may download its solutions */

  int cr_serialization_key;     /* semaphore for compile/run serialization */
  int show_astr_time;
  int ignore_duplicated_runs;
  int report_error_code;
  int auto_short_problem_name;  /* automatically construct short name */

  // decorations
  path_t standings_team_color;
  path_t standings_virtual_team_color;
  path_t standings_real_team_color;
};

struct section_problem_data
{
  struct generic_section_config g;

  int    id;                    /* problem identifier */
  int    tester_id;
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
  int    tests_to_accept;       /* how many tests to accept a submit */
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

  char  **test_sets;            /* defined test sets */
  int ts_total;
  struct testset_info *ts_infos;
};

struct section_language_data
{
  struct generic_section_config g;

  int    id;                    /* language id */
  int    compile_id;            /* language id for compilation */
  int    disabled;              /* a participant cannot use this language */
  path_t short_name;            /* language short name */
  path_t long_name;             /* language long name */
  path_t key;                   /* configuration key */
  path_t arch;                  /* language architecture */
  path_t src_sfx;               /* source file suffix */
  path_t exe_sfx;               /* executable file suffix */
  path_t cmd;                   /* compile command */

  path_t compile_dir;           /* common subdirectory */
  path_t compile_queue_dir;     /* directory for serve->compile packets */
  path_t compile_src_dir;       /* directory for source files */
  path_t compile_out_dir;       /* base directory for compile results */
};

struct section_tester_data
{
  struct generic_section_config g;

  int    id;
  path_t name;                  /* tester name */
  int    problem;               /* reference problem number */
  path_t problem_name;          /* reference problem name */
  int    any;                   /* catch-all entry */

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
  int time_limit_adjustment;

  path_t run_dir;
  path_t run_queue_dir;
  path_t run_exe_dir;
  path_t run_out_dir;

  path_t check_dir;
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

/* userlist-server interaction */
extern struct contest_desc *cur_contest;

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

int prepare_tester_refinement(struct section_tester_data *, int, int);
int create_tester_dirs(struct section_tester_data *);

#endif /* __PREPARE_H__ */
