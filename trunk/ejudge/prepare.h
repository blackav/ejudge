/* -*- c -*- */
/* $Id$ */
#ifndef __PREPARE_H__
#define __PREPARE_H__

/* Copyright (C) 2000-2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "ej_types.h"
#include "pathutl.h"
#include "contests.h"
#include "parsecfg.h"
#include "serve_state.h"

#include <stdio.h>
#include <time.h>

enum { PREPARE_SERVE, PREPARE_COMPILE, PREPARE_RUN };
enum { PREPARE_QUIET = 1 };

/* rounding mode for seconds->minutes transformation */
enum { SEC_CEIL, SEC_FLOOR, SEC_ROUND };

/* problem types */
enum
{
  PROB_TYPE_STANDARD = 0,       /* standard problem */
  PROB_TYPE_OUTPUT_ONLY,        /* output-only problem */
  PROB_TYPE_SHORT_ANSWER,       /* output-only with short answer */
  PROB_TYPE_TEXT_ANSWER,        /* output-only with textarea input */
  PROB_TYPE_SELECT_ONE,         /* select one answer from the list */
  PROB_TYPE_SELECT_MANY,        /* select many answers from the list */

  PROB_TYPE_LAST,
};

struct testset_info
{
  int total;                  /* total number of tests in set */
  unsigned char *nums;
  int testop;
  int scoreop;
  int score;
};

struct penalty_info
{
  time_t deadline;
  int penalty;
};

struct variant_map;

struct pers_dead_info
{
  unsigned char *login;
  int user_id;
  time_t deadline;
  int penalty;
};

struct user_adjustment_info
{
  unsigned char *login;
  int id;
  int adjustment;
};
struct user_adjustment_map;

#define puc_t unsigned char

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
  int    disable_auto_testing;  /* do not test automatically */
  int    disable_testing;       /* do not test the submit at all */
  int    enable_runlog_merge;   /* enable runlog merging */
  int    secure_run;            /* run securely */
  int    enable_memory_limit_error; /* enable support for memory limit detection */

  puc_t  stand_ignore_after[256];
  time_t stand_ignore_after_d; /* ignore submits after this time in standings */

  puc_t  contest_finish_time[256];
  time_t contest_finish_time_d;

  int    fog_standings_updated; /* INTERNAL: updated at the moment of fog? */
  int    start_standings_updated; /* INTERNAL: updated at the start */
  int    unfog_standings_updated; /* INTERNAL: updated after the fog */

  int    team_enable_src_view;  /* teams are allowed to view sources? */
  int    team_enable_rep_view;  /* teams are allowed to view reports? */
  int    team_enable_ce_view;   /* teams are allowed to view compile errs? */
  int    team_show_judge_report;
  int    disable_clars;         /* clarification requests disabled */
  int    disable_team_clars;    /* team cannot compose a clarification */
  int    disable_submit_after_ok; /* disable submits of an already accepted problem */
  int    ignore_compile_errors; /* ignore CE result for score calculation */
  int    enable_continue;       /* enable contest continuation after stop */
  int    enable_report_upload;  /* enable manual upload of checking reports */
  int    priority_adjustment;   /* priority adjustment for the contest */
  int    ignore_success_time;   /* for ACM standings: do not count success time */
  int    disable_failed_test_view; /* do not show the failed test number */
  int    always_show_problems;  /* show "Problems" link before contest start */

  puc_t name[256];              /* name of the contest */
  path_t root_dir;
  path_t serve_socket;          /* serve's socket name */

  int    enable_l10n;           /* enable string translation? */
  path_t l10n_dir;              /* localization message catalog */
  puc_t  standings_locale[128];
  int    standings_locale_id;

  /* userlist-server support */
  int    contest_id;
  path_t socket_path;
  path_t contests_dir;

  /* charsets */
  puc_t charset[128];            /* html pages charset */
  //struct nls_table *charset_ptr; /* internal charset */
  //puc_t standings_charset[128];  /* charset for standings */
  //struct nls_table *standings_charset_ptr;

  /* ====== CONFIGURATION FILES/DIRECTORIES SETUP ====== */
  path_t conf_dir;              /* configuration dir */

  path_t script_dir;            /* default location of compile
                                 * and run scripts */
  path_t test_dir;              /* common prefix dir for tests */
  path_t corr_dir;              /* common prefix dir for correct answers */
  path_t info_dir;              /* common prefix dir for test infos */
  path_t tgz_dir;               /* common prefix dir for directory tests */
  path_t checker_dir;           /* default location of checkers */
  path_t statement_dir;         /* default location of inline prob. stat. */
  puc_t test_sfx[32];           /* default test files suffix */
  puc_t corr_sfx[32];           /* default correct files suffix */
  puc_t info_sfx[32];           /* default info files suffix */
  puc_t tgz_sfx[32];            /* default tar files suffix */
  path_t ejudge_checkers_dir;   /* path to the built-in checkers */
  path_t contest_start_cmd;     /* command to run when contest starts */

  puc_t test_pat[32];
  puc_t corr_pat[32];
  puc_t info_pat[32];
  puc_t tgz_pat[32];

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
  path_t xml_report_archive_dir;  /* new (XML-only) report archive directory */
  path_t full_archive_dir;      /* full output archive directory */
  path_t audit_log_dir;         /* directory for audit logs */
  path_t team_extra_dir;        /* team extra information directory */

  /* --- server status reporting --- */
  path_t status_dir;            /* server status directory */
  path_t work_dir;              /* subdir for working dirs */
  path_t print_work_dir;        /* subdir for printing */
  path_t diff_work_dir;         /* subdir for comparing */

  path_t a2ps_path;
  char **a2ps_args;
  path_t lpr_path;
  char **lpr_args;

  path_t diff_path;

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
  path_t run_full_archive_dir;  /* run->serve full output archive dir */

  path_t run_work_dir;          /* private run's temporary directory */
  path_t run_check_dir;         /* working directory for checked programs */

  path_t htdocs_dir;            /* httpd server html document root dir */

  /* scoring settings */
  puc_t score_system[32];       /* scoring system */
  int    score_system_val;      /* internal int value */
  int    tests_to_accept;       /* how many tests to accept a submit */
  int    is_virtual;            /* 1, if virtual contest */
  int    prune_empty_users;     /* 1, if do not show empty users in stands */
  puc_t  rounding_mode[32];     /* seconds rounding mode */
  int    rounding_mode_val;     /* internal int value */

  int    max_file_length;       /* maximal length of the file in reports */
  int    max_line_length;       /* maximal length of line in reports */
  int    max_cmd_length;        /* maximal length of command line in reports */

  path_t team_info_url;         /* the team info URL template */
  path_t prob_info_url;         /* the problem info URL template */
  puc_t standings_file_name[64]; /* public standings file name */
  path_t stand_header_file;     /* file to use as standings header */
  path_t stand_footer_file;     /* file to use as standings footer */
  path_t stand_symlink_dir;
  int    users_on_page;         /* number of users on page */
  puc_t stand_file_name_2[64];

  puc_t stand_extra_format[128];/* extra standings info */
  puc_t stand_extra_legend[64]; /* extra standings info legend */
  puc_t stand_extra_attr[128];  /* extra standings info attributes */
  puc_t stand_table_attr[128];  /* standings table attributes */
  puc_t stand_place_attr[128];  /* standings place column attributes */
  puc_t stand_team_attr[128];   /* standings team column attributes */
  puc_t stand_prob_attr[128];   /* standings problems column attributes */
  puc_t stand_solved_attr[128]; /* standings solved column attributes */
  puc_t stand_score_attr[128];  /* standings solved column attributes */
  puc_t stand_penalty_attr[128];/* standings penalty column attributes */
  puc_t stand_time_attr[128];   /* standings time attributes */
  puc_t stand_self_row_attr[128];/* self-row attributes */
  puc_t stand_r_row_attr[128];  /* standings real team row attributes */
  puc_t stand_v_row_attr[128];  /* standings virtual team row attributes */
  puc_t stand_u_row_attr[128];  /* standings unknown team row attributes */
  puc_t stand_success_attr[128];/* last success attributes */
  puc_t stand_fail_attr[128];   /* attributes for "Check failed" */
  puc_t stand_trans_attr[128];  /* attributes for transient cells */
  int stand_show_ok_time;       /* whether show time */
  int stand_show_att_num;       /* show number of attempts in Kirov standings */
  int stand_sort_by_solved;     /* sort by solved problems first in Kirov standings */
  char **stand_row_attr;
  puc_t stand_page_table_attr[128]; /* attribute for the page table */
  char **stand_page_row_attr;   /* attributes for the page table rows */
  char **stand_page_col_attr;   /* attributes for the page table columns */
  puc_t stand_page_cur_attr[128]; /* attribute for Page %d out of %d msg */

  unsigned char *stand_header_txt; /* actual header text */
  unsigned char *stand_footer_txt; /* actual footer text */

  // standings2 information
  puc_t stand2_file_name[64];   /* must be set to standings 2 be activated */
  path_t stand2_header_file;
  path_t stand2_footer_file;
  unsigned char *stand2_header_txt;
  unsigned char *stand2_footer_txt;
  path_t stand2_symlink_dir;

  // public log information
  puc_t plog_file_name[64];
  path_t plog_header_file;
  path_t plog_footer_file;
  unsigned char *plog_header_txt;
  unsigned char *plog_footer_txt;
  int plog_update_time;
  path_t plog_symlink_dir;

  int internal_xml_update_time;
  int external_xml_update_time;

  // fun
  int extended_sound;
  int disable_sound;
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
  int compile_real_time_limit;
  int checker_real_time_limit;
  int show_deadline;       /* show deadlines in problem name? */

  int use_gzip;                 /* allow gzip on large files (uses zlib) */
  int min_gzip_size;            /* minimal file size to gzip (4096) */
  int use_dir_hierarchy;        /* create subdirs to increase speed */
  int html_report;              /* whether generate master report in HTML */
  int xml_report;               /* whether generate master report in XML */
  int enable_full_archive;      /* enable storing the full output */
  int cpu_bogomips;             /* CPU speed (BogoMIPS) */
  int skip_full_testing;
  int skip_accept_testing;

  // variant support
  path_t variant_map_file;
  struct variant_map *variant_map;

  // printing support
  int enable_printing;
  int team_page_quota;

  // user priority adjustments
  char **user_priority_adjustments;
  struct user_adjustment_info *user_adjustment_info;
  struct user_adjustment_map *user_adjustment_map;

  // contestant status support
  int contestant_status_num;
  char **contestant_status_legend;
  char **contestant_status_row_attr;
  int stand_show_contestant_status;
  int stand_show_warn_number;
  puc_t stand_contestant_status_attr[128];
  puc_t stand_warn_number_attr[128];

  // internal use: text with unhandled variables
  unsigned char *unhandled_vars;
};

struct section_problem_data
{
  struct generic_section_config g;

  int    id;                    /* problem identifier */
  int    tester_id;
  int    abstract;              /* is this abstract problem specification */
  int    type_val;              /* the problem type */
  int    manual_checking;       /* 1, if this problem is checked manually */
  int    examinator_num;        /* number of independent examinations */
  int    check_presentation;    /* 1, if still check for PE */
  int    scoring_checker;       /* 1, if the checker calculates test score */
  int    use_stdin;             /* 1, if solution uses stdin for input */
  int    use_stdout;            /* 1, if solution uses stdout for output */
  int    binary_input;          /* input data for problem is binary */
  int    real_time_limit;       /* maximum astronomical time for a problem */
  int    time_limit;            /* time limit in secs */
  int    time_limit_millis;     /* time limit in milliseconds */
  int    team_enable_rep_view;  /* are teams allowed to view reports? */
  int    team_enable_ce_view;
  int    team_show_judge_report;
  int    full_score;            /* score for complete solution */
  int    variable_full_score;   /* is the full score is variable */
  int    test_score;            /* score for one test */
  int    run_penalty;           /* penalty for one run */
  int    acm_run_penalty;       /* penalty for one run for ACM contests */
  int    disqualified_penalty;  /* penalty for one disqualified run */
  int    use_corr;              /* whether the correct answers defined */
  int    use_info;              /* whether use the info files */
  int    use_tgz;               /* whether use tar test files */
  int    tests_to_accept;       /* how many tests to accept a submit */
  int    accept_partial;        /* whether accept partial solutions */
  int    checker_real_time_limit;
  int    disable_auto_testing;
  int    disable_testing;
  int    enable_compilation;
  int    skip_testing;          /* skip testing this problem */
  int    hidden;                /* hide the problem from standings */
  int    priority_adjustment;   /* priority adjustment for this problem */
  int    stand_hide_time;       /* do not show ok time */
  int    score_multiplier;      /* additional score multiplier */
  puc_t super[32];              /* superproblem's short_name */
  puc_t short_name[32];         /* short problem name, eg A, B, ... */
  puc_t long_name[128];         /* long problem name */
  path_t test_dir;              /* directory with tests */
  puc_t test_sfx[32];           /* test files suffix */
  path_t corr_dir;              /* directory with correct answers */
  puc_t corr_sfx[32];           /* correct files suffix */
  path_t info_dir;              /* directory with info files */
  puc_t info_sfx[32];           /* info files suffix */
  path_t tgz_dir;               /* directory with tar test archive */
  puc_t tgz_sfx[32];            /* tar test archive suffix */
  puc_t input_file[64];         /* input file name */
  puc_t output_file[64];        /* output file name */
  puc_t test_score_list[256];   /* scores for individual tests */
  puc_t score_tests[256];       /* number of tests for Moscow scoring */
  path_t standard_checker;      /* the name of the built-in checker */
  puc_t spelling[128];          /* spelling for speach generator */
  path_t statement_file;        /* file with inline problem statement */
  path_t alternatives_file;     /* file with alternatives for output-only */

  puc_t test_pat[32];
  puc_t corr_pat[32];
  puc_t info_pat[32];
  puc_t tgz_pat[32];
  puc_t type[64];               /* the problem type */

  int     ntests;               /* number of tests found */
  int    *tscores;              /* internal scores array  */
  int    *x_score_tests;        /* parsed `score_tests' */

  char  **test_sets;            /* defined test sets */
  int ts_total;
  struct testset_info *ts_infos;

  puc_t deadline[64];           /* deadline for sending this problem */
  time_t t_deadline;            /* in UNIX internal format */
  puc_t start_date[64];         /* the first date for sending this problem */
  time_t t_start_date;          /* in UNIX internal format */
  int variant_num;              /* number of variants for this problem */

  char **date_penalty;          /* penalty which depends on date */
  int dp_total;
  struct penalty_info *dp_infos;

  char **disable_language;
  char **enable_language;
  char **require;
  char **checker_env;           /* environment variables for checker */
  path_t check_cmd;
  char **lang_time_adj;         /* time limit adjustments depending on language */

  char **alternative;           /* alternatives for test-like problems */
  char **personal_deadline;     /* personal deadline extensions */
  int pd_total;
  struct pers_dead_info *pd_infos;

  puc_t score_bonus[256];       /* bonus for the Nth full solution of the problem */
  int   score_bonus_total;      /* parsed: number of entries in score_bonus */
  int   *score_bonus_val;       /* parsed: score_bonus values */

  /* these fields are for CGI editing of contest configuration files */
  size_t max_vm_size;
  size_t max_stack_size;
  unsigned char *unhandled_vars;
};

struct section_language_data
{
  struct generic_section_config g;

  int    id;                    /* language id */
  int    compile_id;            /* language id for compilation */
  int    disabled;              /* a participant cannot use this language */
  int    compile_real_time_limit;
  int    binary;                /* whether binary files are accepted */
  int    priority_adjustment;   /* priority adjustment for this language */
  puc_t short_name[32];         /* language short name */
  puc_t long_name[128];         /* language long name */
  puc_t key[32];                /* configuration key */
  puc_t arch[32];               /* language architecture */
  puc_t src_sfx[32];            /* source file suffix */
  puc_t exe_sfx[32];            /* executable file suffix */
  puc_t content_type[128];      /* Content-type: header for downloads */
  path_t cmd;                   /* compile command */

  int disable_auto_testing;     /* do not test this language automatically */
  int disable_testing;          /* do not test this language at all */

  path_t compile_dir;           /* common subdirectory */
  path_t compile_queue_dir;     /* directory for serve->compile packets */
  path_t compile_src_dir;       /* directory for source files */
  path_t compile_out_dir;       /* base directory for compile results */
  path_t compile_status_dir;    /* directory for compile->serve packets */
  path_t compile_report_dir;    /* directory for executables/error logs */
  char **compiler_env;          /* environment to pass to the compiler */

  // for internal use
  unsigned char *unhandled_vars;
};

struct section_tester_data
{
  struct generic_section_config g;

  int    id;
  puc_t name[32];               /* tester name */
  int    problem;               /* reference problem number */
  puc_t problem_name[32];       /* reference problem name */
  int    any;                   /* catch-all entry */

  int    is_dos;                /* do unix->dos conversion of tests? */
  int    no_redirect;           /* do not redirect standard streams */
  int    priority_adjustment;   /* priority adjustment for this tester */

  puc_t arch[32];               /* checker architecture */
  puc_t key[32];                /* configuration key */

  int    abstract;              /* is this tester abstract */
  char **super;                 /* names of the supertesters */
  int    is_processed;          /* whether this tester has been processed */
  int    skip_testing;

  int no_core_dump;             /* disable core dumps */
  int enable_memory_limit_error; /* enable memory limit detection */
  puc_t kill_signal[32];        /* the signal to kill processes */
  size_t max_stack_size;        /* max size of the stack */
  size_t max_data_size;         /* max size of the data */
  size_t max_vm_size;           /* max size of the virtual memory */
  int clear_env;                /* whether the environment is cleared */
  int time_limit_adjustment;

  path_t run_dir;
  path_t run_queue_dir;
  path_t run_exe_dir;
  path_t run_out_dir;
  path_t run_status_dir;        /* run->serve status dir */
  path_t run_report_dir;        /* run->serve report dir */
  path_t run_team_report_dir;   /* run->serve team report dir */
  path_t run_full_archive_dir;  /* run->serve full output archive dir */

  path_t check_dir;
  puc_t errorcode_file[64];     /* file that contains completion status */
  puc_t error_file[64];         /* stderr output of the checked program */

  path_t prepare_cmd;           /* helper to prepare the executable */
  path_t start_cmd;             /* helper to start testing */
  path_t check_cmd;             /* checker */

  char **start_env;             /* environment variables for start_cmd */
  char **checker_env;           /* environment variables for checker */

  int standard_checker_used;    /* internal: the standard checker is used */
};

#undef puc_t

int prepare(serve_state_t, char const *, int flags, int mode, char const *opts,
            int managed_flag);
int create_dirs(serve_state_t, int mode);
int prepare_serve_defaults(serve_state_t, const struct contest_desc **);

int find_tester(const serve_state_t, int, char const *);
int find_variant(const serve_state_t, int, int);
int find_user_priority_adjustment(const serve_state_t, int user_id);

void print_problem(FILE *, struct section_problem_data *);
void print_language(FILE *, struct section_language_data *);
void print_tester(FILE *, struct section_tester_data *);

void print_global(serve_state_t, FILE *);
void print_all_problems(serve_state_t, FILE *);
void print_all_languages(serve_state_t, FILE *);
void print_all_testers(serve_state_t, FILE *);

void print_configuration(serve_state_t, FILE *);

int prepare_tester_refinement(serve_state_t, struct section_tester_data *,
                              int, int);
int create_tester_dirs(struct section_tester_data *);

struct ejudge_cfg;
struct section_global_data *prepare_new_global_section(int contest_id, const unsigned char *root_dir, const struct ejudge_cfg *config);
struct generic_section_config * prepare_parse_config_file(const unsigned char *path,
                                                          int *p_cond_count);
void prepare_set_global_defaults(struct section_global_data *global);

void prepare_global_free_func(struct generic_section_config *gp);
void prepare_language_free_func(struct generic_section_config *gp);
void prepare_problem_free_func(struct generic_section_config *gp);
void prepare_tester_free_func(struct generic_section_config *gp);
struct generic_section_config *prepare_free_config(struct generic_section_config *cfg);

struct section_global_data *prepare_alloc_global(void);
struct section_language_data *prepare_alloc_language(void);
struct section_problem_data *prepare_alloc_problem(void);
struct section_tester_data *prepare_alloc_tester(void);

void prepare_problem_init_func(struct generic_section_config *gp);

// field identification enumeration
enum
{
  PREPARE_FIELD_ZERO,

  PREPARE_FIELD_PROB_TYPE,
  PREPARE_FIELD_PROB_SCORING_CHECKER,
  PREPARE_FIELD_PROB_MANUAL_CHECKING,
  PREPARE_FIELD_PROB_EXAMINATOR_NUM,
  PREPARE_FIELD_PROB_CHECK_PRESENTATION,
  PREPARE_FIELD_PROB_USE_STDIN,
  PREPARE_FIELD_PROB_USE_STDOUT,
  PREPARE_FIELD_PROB_BINARY_INPUT,
  PREPARE_FIELD_PROB_TIME_LIMIT,
  PREPARE_FIELD_PROB_TIME_LIMIT_MILLIS,
  PREPARE_FIELD_PROB_REAL_TIME_LIMIT,
  PREPARE_FIELD_PROB_TEAM_ENABLE_REP_VIEW,
  PREPARE_FIELD_PROB_TEAM_ENABLE_CE_VIEW,
  PREPARE_FIELD_PROB_TEAM_SHOW_JUDGE_REPORT,
  PREPARE_FIELD_PROB_DISABLE_TESTING,
  PREPARE_FIELD_PROB_DISABLE_AUTO_TESTING,
  PREPARE_FIELD_PROB_ENABLE_COMPILATION,
  PREPARE_FIELD_PROB_SKIP_TESTING,
  PREPARE_FIELD_PROB_FULL_SCORE,
  PREPARE_FIELD_PROB_TEST_SCORE,
  PREPARE_FIELD_PROB_RUN_PENALTY,
  PREPARE_FIELD_PROB_ACM_RUN_PENALTY,
  PREPARE_FIELD_PROB_DISQUALIFIED_PENALTY,
  PREPARE_FIELD_PROB_VARIABLE_FULL_SCORE,
  PREPARE_FIELD_PROB_TESTS_TO_ACCEPT,
  PREPARE_FIELD_PROB_ACCEPT_PARTIAL,
  PREPARE_FIELD_PROB_HIDDEN,
  PREPARE_FIELD_PROB_STAND_HIDE_TIME,
  PREPARE_FIELD_PROB_CHECKER_REAL_TIME_LIMIT,
  PREPARE_FIELD_PROB_MAX_VM_SIZE,
  PREPARE_FIELD_PROB_MAX_STACK_SIZE,
  PREPARE_FIELD_PROB_INPUT_FILE,
  PREPARE_FIELD_PROB_OUTPUT_FILE,
  PREPARE_FIELD_PROB_USE_CORR,
  PREPARE_FIELD_PROB_USE_INFO,
  PREPARE_FIELD_PROB_USE_TGZ,
  PREPARE_FIELD_PROB_TEST_DIR,
  PREPARE_FIELD_PROB_CORR_DIR,
  PREPARE_FIELD_PROB_INFO_DIR,
  PREPARE_FIELD_PROB_TGZ_DIR,
  PREPARE_FIELD_PROB_TEST_SFX,
  PREPARE_FIELD_PROB_CORR_SFX,
  PREPARE_FIELD_PROB_INFO_SFX,
  PREPARE_FIELD_PROB_TGZ_SFX,
  PREPARE_FIELD_PROB_TEST_PAT,
  PREPARE_FIELD_PROB_CORR_PAT,
  PREPARE_FIELD_PROB_INFO_PAT,
  PREPARE_FIELD_PROB_TGZ_PAT,
  PREPARE_FIELD_PROB_SCORE_BONUS,
  PREPARE_FIELD_PROB_CHECK_CMD,
  PREPARE_FIELD_PROB_SECURE_RUN,
  PREPARE_FIELD_PROB_STATEMENT_FILE,
  PREPARE_FIELD_PROB_ALTERNATIVES_FILE,
};

void prepare_copy_problem(struct section_problem_data *out,
                          const struct section_problem_data *in);

void prepare_set_prob_value(int field, struct section_problem_data *out,
                            const struct section_problem_data *abstr,
                            const struct section_global_data *global);

void prepare_unparse_global(FILE *f, struct section_global_data *global,
                            const unsigned char *compile_dir, int need_variant_map);
void prepare_unparse_unhandled_global(FILE *f,
                                      const struct section_global_data *global);
int prepare_check_forbidden_global(FILE *f, const struct section_global_data *global);

void prepare_unparse_lang(FILE *f, const struct section_language_data *lang,
                          const unsigned char *long_name,
                          const unsigned char *options);
void prepare_unparse_unhandled_lang(FILE *f,
                                    const struct section_language_data *lang);
int prepare_check_forbidden_lang(FILE *f, const struct section_language_data *lang);

void prepare_unparse_prob(FILE *f, const struct section_problem_data *prob,
                          const struct section_global_data *global,
                          int score_system_val);
void prepare_unparse_unhandled_prob(FILE *f, const struct section_problem_data *prob,
                                    const struct section_global_data *global);
int prepare_check_forbidden_prob(FILE *f, const struct section_problem_data *prob);

int prepare_unparse_testers(FILE *f,
                            int secure_run,
                            const struct section_global_data *global,
                            int max_lang,
                            struct section_language_data **langs,
                            int total_aprobs,
                            struct section_problem_data **aprobs,
                            int total_probs,
                            struct section_problem_data **probs,
                            int total_atesters,
                            struct section_tester_data **atesters,
                            const unsigned char *testing_work_dir);

void prepare_further_instructions(FILE *f,
                                  const unsigned char *root_dir,
                                  const unsigned char *conf_dir,
                                  const struct section_global_data *global,
                                  int aprob_a, struct section_problem_data **aprobs,
                                  int prob_a, struct section_problem_data **probs);

int prepare_unparse_is_supported_arch(const unsigned char *arch);
int prepare_unparse_is_supported_tester(const unsigned char *tester_name);

void prepare_set_abstr_problem_defaults(struct section_problem_data *prob,
                                        struct section_global_data *global);
void prepare_set_concr_problem_defaults(struct section_problem_data *prob,
                                        struct section_global_data *global);
struct variant_map;
void prepare_free_variant_map(struct variant_map *p);

void prepare_unparse_variants(FILE *f, const struct variant_map *vmap,
                              const unsigned char *header,
                              const unsigned char *footer);

int *prepare_parse_score_tests(const unsigned char *str, int score);
const unsigned char *prepare_unparse_problem_type(int val);

#endif /* __PREPARE_H__ */
