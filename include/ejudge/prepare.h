/* -*- c -*- */
#ifndef __PREPARE_H__
#define __PREPARE_H__

/* Copyright (C) 2000-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ej_types.h"
#include "ejudge/pathutl.h"
#include "ejudge/contests.h"
#include "ejudge/parsecfg.h"
#include "ejudge/serve_state.h"
#include "ejudge/problem_common.h"
#include "ejudge/problem_xml.h"

#include <stdio.h>
#include <time.h>

#ifndef META_ATTRIB
#if defined __RCC__
#undef __attribute__
#define META_ATTRIB(x) __attribute__(x)
#else
#define META_ATTRIB(x)
#endif /* __RCC__ */
#endif /* META_ATTRIB */

#ifdef __GCC__
#define GCC_ATTRIB(x) __attribute__(x)
#else
#define GCC_ATTRIB(x)
#endif

enum { PREPARE_SERVE, PREPARE_COMPILE, PREPARE_RUN };
enum { PREPARE_QUIET = 1 };

/* rounding mode for seconds->minutes transformation */
enum { SEC_CEIL, SEC_FLOOR, SEC_ROUND };

/* memory limit types */
enum
{
  MEMLIMIT_TYPE_DEFAULT = 0,
  MEMLIMIT_TYPE_DOS,
  MEMLIMIT_TYPE_JAVA,
  MEMLIMIT_TYPE_MONO,
  MEMLIMIT_TYPE_VALGRIND,
  MEMLIMIT_TYPE_DOTNET,

  MEMLIMIT_TYPE_LAST,
};

/* secure execution types */
enum
{
  SEXEC_TYPE_NONE = 0,
  SEXEC_TYPE_STATIC,
  SEXEC_TYPE_DLL,
  SEXEC_TYPE_JAVA,
  SEXEC_TYPE_DLL32,
  SEXEC_TYPE_MONO,
  SEXEC_TYPE_VALGRIND,
  SEXEC_TYPE_DOTNET,

  SEXEC_TYPE_LAST,
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
  time_t date;
  int penalty;
  int scale; // 1 - secs, 60 - mins, 3600 ...
  int decay;
};

struct group_date_info
{
  unsigned char *group_name;
  int group_ind;
  struct penalty_info p;
};

struct group_dates
{
  int count;
  struct group_date_info *info;
};

struct variant_map;

struct pers_dead_info
{
  unsigned char *login;
  int user_id;
  struct penalty_info p;
};

struct user_adjustment_info
{
  unsigned char *login;
  int id;
  int adjustment;
};
struct user_adjustment_map;

struct token_info
{
  int initial_count;  // initial token count
  int time_sign;      // sign (+/-) of the time term
  int time_increment; // periodic token increment
  int time_interval;  // period length (s)
  int open_sign;      // sign (+/-) of the open term
  int open_cost;      // token cost
  int open_flags;     // what opens by paying
};

struct dates_config;

struct virtual_end_info_s
{
  int source_mode;
  int report_mode;
  int visibility_mode;
  int score_mode;
  int checker_comment_mode;
};

/* sizeof(struct section_global_data) == 1208/1920 */
struct section_global_data
{
  struct generic_section_config g META_ATTRIB((meta_hidden));

  /** interval between directory polls (milliseconds) */
  int sleep_time;
  /** @deprecated poll interval for serve, if different */
  int serve_sleep_time;
  /** contest time (in seconds), 0 for unlimited contests */
  int contest_time;
  /** max size of a run in bytes */
  ejintsize_t max_run_size;
  /** max total size of all user's runs in bytes */
  ejintsize_t max_run_total;
  /** max number of runs for each user */
  int max_run_num;
  /** max size of a clar in bytes */
  ejintsize_t max_clar_size;
  /** max total size of all user's clars */
  ejintsize_t max_clar_total;
  /** max number of clars for each user */
  int max_clar_num;

  /** time before the end of the contest when the board stops updating (s) */
  int board_fog_time;
  /** time after the end of the contest when the board is updated again (s) */
  int board_unfog_time;
  /** update standings automatically? (1 by default) */
  ejintbool_t autoupdate_standings;
  /** use AC status for solutions that pass all tests */
  ejintbool_t use_ac_not_ok;
  /** timeout for unloading contest from memory */
  int inactivity_timeout;
  /** do not test automatically */
  ejintbool_t disable_auto_testing;
  /** do not test submits at all */
  ejintbool_t disable_testing;
  /** enable runlog merging (dangerous!) */
  ejintbool_t enable_runlog_merge;
  /** run securely (kernel patch is needed) */
  ejintbool_t secure_run;
  /** detect security violations (only with secure_run) */
  ejintbool_t detect_violations;
  /** enable support for memory limit detection */
  ejintbool_t enable_memory_limit_error;
  /** enable advanced problem layout */
  ejintbool_t advanced_layout;
  /** use UUID instead of run_id for runs */
  ejintbool_t uuid_run_store;
  /** compile all checkers, interactors, etc in 32-bit mode on 64-bit platforms */
  ejintbool_t enable_32bit_checkers;
  /** ignore BOM in submitted text files */
  ejintbool_t ignore_bom;
  /** disable loading of the user database */
  ejintbool_t disable_user_database;
  /** enable stack limit equal to memory limit */
  ejintbool_t enable_max_stack_size;
  /** number of retries in case of time limit errors */
  int time_limit_retry_count;
  /** score n best problems */
  int score_n_best_problems;
  /** require problem UUID */
  ejintbool_t require_problem_uuid;

  /** do not show submits after this time in the standings */
  time_t stand_ignore_after;

  /** the contest finish time (for unlimited contests) */
  time_t contest_finish_time;

  /** the appelation deadline */
  time_t appeal_deadline;

  /** INTERNAL: updated at the moment of fog? */
  int fog_standings_updated META_ATTRIB((meta_private));
  /** INTERNAL: updated at the start */
  int start_standings_updated META_ATTRIB((meta_private));
  /** INTERNAL: updated after the fog */
  int unfog_standings_updated META_ATTRIB((meta_private));

  /** participants are allowed to view sources? */
  ejintbool_t team_enable_src_view;
  /** participants are allowed to view reports? */
  ejintbool_t team_enable_rep_view;
  /** participants are allowed to view compile errors? */
  ejintbool_t team_enable_ce_view;
  /** the full testing protocol is available for participants */
  ejintbool_t team_show_judge_report;
  /** clarification requests are disabled completely */
  ejintbool_t disable_clars;
  /** participants are not allowed composing a clarification request */
  ejintbool_t disable_team_clars;
  /** disable submits of an already accepted problem */
  ejintbool_t disable_submit_after_ok;
  /** ignore compilation errors in score calculation */
  ejintbool_t ignore_compile_errors;
  /** enable contest continuation after stop */
  ejintbool_t enable_continue;
  /** enable manual upload of testing reports */
  ejintbool_t enable_report_upload;
  /** global priority adjustment for the contest */
  int priority_adjustment;
  /** for ACM standings: do not count success time */
  ejintbool_t ignore_success_time;
  /** do not show the failed test number to contestants */
  ejintbool_t disable_failed_test_view;
  /** show the "Problems" link before the contest start */
  ejintbool_t always_show_problems;
  /** disable the built-in contest standings */
  ejintbool_t disable_user_standings;
  /** do not show "language" column to contestants */
  ejintbool_t disable_language;
  /** extended tabbed problem navigation */
  ejintbool_t problem_navigation;
  /** the size of the problem tab */
  int problem_tab_size;
  /** display problem tabs vertically */
  ejintbool_t vertical_navigation;
  /** disable "virtual start" command for contestants */
  ejintbool_t disable_virtual_start;
  /** disable auto-judging after virtual olympiad is finished for a user */
  ejintbool_t disable_virtual_auto_judge;
  /** print user examination protocols automatically */
  ejintbool_t enable_auto_print_protocol;
  /** send clar reply notification to users */
  ejintbool_t notify_clar_reply;
  /** send status change notification to users */
  ejintbool_t notify_status_change;
  /** memoize the user results for use in filter expressions */
  ejintbool_t memoize_user_results;
  /** disable standings auto-refresh */
  ejintbool_t disable_auto_refresh;
  /** participants may select wanted EOLN type for tests */
  ejintbool_t enable_eoln_select;
  /** start virtual contest on first login */
  ejintbool_t start_on_first_login;
  /** enable restarting of virtual contest */
  ejintbool_t enable_virtual_restart;

  /** @deprecated the name of the contest */
  unsigned char *name;
  /** @deprecated the contest root directory */
  unsigned char *root_dir;
  /** @deprecated the contest socket path */
  unsigned char *serve_socket;

  /** enable message translation? */
  ejintbool_t enable_l10n;
  /** message translation catalog */
  unsigned char *l10n_dir;
  /** the language of the standings */
  unsigned char *standings_locale;
  /** parsed `standings_locale' */
  int standings_locale_id META_ATTRIB((meta_private));
  unsigned char *checker_locale;

  /** the contest number (mandatory) */
  int contest_id;
  /** the `userlist-server' socket path */
  unsigned char *socket_path;
  /** the contest XML directory */
  unsigned char *contests_dir;
  /** compiler configuration script dir */
  unsigned char *lang_config_dir;

  /** html charset */
  unsigned char *charset;
  /** charset for the standings */
  unsigned char *standings_charset;
  /** charset for the secondary standings */
  unsigned char *stand2_charset;
  /** charset for the submission log */
  unsigned char *plog_charset;

  /* ====== CONFIGURATION FILES/DIRECTORIES SETUP ====== */
  /** configuration dir */
  unsigned char *conf_dir;
  /** directory with problem files (for advanced_layout) */
  unsigned char *problems_dir;
  /** default location of the compile and run scripts */
  unsigned char *script_dir;
  /** directory with the tests */
  unsigned char *test_dir;
  /** directory with the correct answers */
  unsigned char *corr_dir;
  /** directory with the test info files */
  unsigned char *info_dir;
  /** directory with the working dir tgz archives */
  unsigned char *tgz_dir;
  /** directory with the checkers */
  unsigned char *checker_dir;
  /** directory with the problem statements */
  unsigned char *statement_dir;
  /** directory with the contest and problem plugins */
  unsigned char *plugin_dir;
  /** suffix of the test files */
  unsigned char *test_sfx;
  /** suffix of the files with correct answers */
  unsigned char *corr_sfx;
  /** suffix of the files with test info */
  unsigned char *info_sfx;
  /** suffix of the tgz archive files */
  unsigned char *tgz_sfx;
  /** suffix of the working directory master copy */
  unsigned char *tgzdir_sfx;
  /** path to the built-in checkers */
  unsigned char *ejudge_checkers_dir;
  /** command to run when the contest starts */
  unsigned char *contest_start_cmd;
  /** command to run when the contest stops */
  unsigned char *contest_stop_cmd;
  /** path to the HTML file with the contest description */
  unsigned char *description_file;
  /** path to the contest plugin */
  unsigned char *contest_plugin_file;

  /** user-visible behavior after the end of virtual contest for the user */
  unsigned char *virtual_end_options;
  struct virtual_end_info_s *virtual_end_info META_ATTRIB((meta_private));

  /** directory for non-default super-run directory */
  unsigned char *super_run_dir;

  /** printf pattern for the files with tests */
  unsigned char *test_pat;
  /** printf pattern for the files with correct answers */
  unsigned char *corr_pat;
  /** printf pattern for the files with test information */
  unsigned char *info_pat;
  /** printf pattern for the files with the working dir archive */
  unsigned char *tgz_pat;
  /** printf pattern for the files with the working directory master copy */
  unsigned char *tgzdir_pat;

  /** the clarification base storage plugin (file, mysql) */
  unsigned char *clardb_plugin;
  /** the run information base storage plugin (file, mysql) */
  unsigned char *rundb_plugin;
  /** the extra user information storage plugin (file, mongo) */
  unsigned char *xuser_plugin;
  /** the contest status plugin */
  unsigned char *status_plugin;
  /** the variant plugin */
  unsigned char *variant_plugin;

  /* ====== VARIABLE FILES/DIRECTORIES SETUP ====== */
  /** root directory with working files, run sources/reports, etc */
  unsigned char *var_dir;

  /* --- server logging --- */
  //path_t log_file;              /* logger log file */
  /** run database file (for file storage) */
  unsigned char *run_log_file;
  /** clarification database file (for file storage) */
  unsigned char *clar_log_file;
  /** root directory for archives */
  unsigned char *archive_dir;
  /** clar archive directory */
  unsigned char *clar_archive_dir;
  /** run source code archive directory */
  unsigned char *run_archive_dir;
  /** @deprecated report archive directory */
  unsigned char *report_archive_dir;
  /** @deprecated team report archive directory */
  unsigned char *team_report_archive_dir;
  /** XML report archive directory */
  unsigned char *xml_report_archive_dir;
  /** full output archive directory */
  unsigned char *full_archive_dir;
  /** directory for audit logs */
  unsigned char *audit_log_dir;
  /** directory for new UUID-based archives */
  unsigned char *uuid_archive_dir;
  /** team extra information directory */
  unsigned char *team_extra_dir;

  /* --- server status reporting --- */
  /** server status directory */
  unsigned char *legacy_status_dir;
  /** subdir for working dirs */
  unsigned char *work_dir;
  /** subdir for printing */
  unsigned char *print_work_dir;
  /** subdir for comparing */
  unsigned char *diff_work_dir;

  /** path to the `a2ps' program (default is /usr/bin/a2ps) */
  unsigned char *a2ps_path;
  /** arguments for the `a2ps' program */
  char **a2ps_args;
  /** path to the `lpr' program (default is /usr/bin/lpr) */
  unsigned char *lpr_path;
  /** arguments for the `lpr' program */
  char **lpr_args;

  /** path to the `diff' program */
  unsigned char *diff_path;

  /* --- server <-> compile interaction --- */
  /* global parameters are used by compile utility, whereas
   * language-local parameters are used by serve */
  /** the compile spool root dir */
  unsigned char *compile_dir;
  /** the compile packets spool directory */
  unsigned char *compile_queue_dir;
  /** the compile source files spool directory */
  unsigned char *compile_src_dir;

  /** additional compile directories */
  char **extra_compile_dirs;

  /* these are used by serve */
  /* var/compile prefix is implicit and cannot be changed! */
  /** base directory for compile results */
  unsigned char *compile_out_dir;
  /** compile->serve status dir */
  unsigned char *compile_status_dir;
  /** compile->serve report dir */
  unsigned char *compile_report_dir;

  /** working directory for compilation */
  unsigned char *compile_work_dir;

  /* --- serve <-> run interaction --- */
  /** the run spool root directory */
  unsigned char *run_dir;
  /** common prefix dir for serve->run packets */
  unsigned char *run_queue_dir;
  /** serve->run executables */
  unsigned char *run_exe_dir;

  /** base directory for run results */
  unsigned char *run_out_dir;
  /** run->serve status dir */
  unsigned char *run_status_dir;
  /** run->serve report dir */
  unsigned char *run_report_dir;
  /** run->serve team report dir */
  unsigned char *run_team_report_dir;
  /** run->serve full output archive dir */
  unsigned char *run_full_archive_dir;

  /** private run's temporary directory */
  unsigned char *run_work_dir;
  /** working directory for checked programs */
  unsigned char *run_check_dir;

  /** httpd server html document root dir */
  unsigned char *htdocs_dir;

  /** contest scoring system */
  int score_system;
  /** number of tests to accept a submit in olympiad contests */
  int tests_to_accept;
  /** 1, if virtual contest */
  ejintbool_t is_virtual;
  /** 1, if do not show empty users in stands */
  ejintbool_t prune_empty_users;
  /** seconds rounding mode */
  int rounding_mode;

  /** maximal length of the file in reports */
  ejintsize_t max_file_length;
  /** maximal length of line in reports */
  ejintsize_t max_line_length;
  /** maximal length of command line in reports */
  ejintsize_t max_cmd_length;

  /** URL template for the user information link in the standings */
  unsigned char *team_info_url;
  /** URL template for the problem link in the standings */
  unsigned char *prob_info_url;
  /** public standings file name */
  unsigned char *standings_file_name;
  /** standings header file */
  unsigned char *stand_header_file;
  /** standings footer file */
  unsigned char *stand_footer_file;
  /** directory where to install a symlink to the standings file */
  unsigned char *stand_symlink_dir;
  /** number of users on page */
  int    users_on_page;
  unsigned char *stand_file_name_2;

  /** enable fancy standings style */
  ejintbool_t stand_fancy_style;
  /** format for the extra column in the standings */
  unsigned char *stand_extra_format;
  /** legend for the extra column in the standings*/
  unsigned char *stand_extra_legend;
  /** HTML attribute for the extra column in the standings */
  unsigned char *stand_extra_attr;
  /** HTML attribute for the whole standings */
  unsigned char *stand_table_attr;
  /** HTML attribute for the `place' column in the standings */
  unsigned char *stand_place_attr;
  /** HTML attribute for the `user' column in the standings */
  unsigned char *stand_team_attr;
  /** HTML attribute for the problem columns in the standings */
  unsigned char *stand_prob_attr;
  /** HTML attribute for the `solved' column in the standings */
  unsigned char *stand_solved_attr;
  /** HTML attribute for the `score' column in the standings */
  unsigned char *stand_score_attr;
  /** HTML attribute for the `penalty' column in the standings */
  unsigned char *stand_penalty_attr;
  /** HTML attribute for time in problem cells */
  unsigned char *stand_time_attr;
  /** HTML attribute for rows corresponding to the current participant */
  unsigned char *stand_self_row_attr;
  /** HTML attribute for rows corresponding to the real participants */
  unsigned char *stand_r_row_attr;
  /** HTML attribute for rows corresponding to the virtual participants */
  unsigned char *stand_v_row_attr;
  /** HTML attribute for rows corresponding to the unknown participants */
  unsigned char *stand_u_row_attr;
  /** HTML attribute for "Last success" information */
  unsigned char *stand_success_attr;
  /** HTML attribute for cells with "Check failed" submits */
  unsigned char *stand_fail_attr;
  /** HTML attribute for cells with transient (being tested) submits */
  unsigned char *stand_trans_attr;
  /** HTML attribute for cells with disqualified submits */
  unsigned char *stand_disq_attr;
  /** show participant's login instead of name in the standings */
  ejintbool_t stand_use_login;
  /** show participant's avatar, if supported */
  ejintbool_t stand_show_avatar;
  /** show first solver of the problem */
  ejintbool_t stand_show_first_solver;
  /** show success time in the standings */
  ejintbool_t stand_show_ok_time;
  /** show number of attempts in Kirov standings */
  ejintbool_t stand_show_att_num;
  /** sort by the number of solved problems first in Kirov standings */
  ejintbool_t stand_sort_by_solved;
  /** HTML row attributes */
  char **stand_row_attr;
  /** HTML attribute for the page navigation table in multi-page standings */
  unsigned char *stand_page_table_attr;
  /** HTML attribute for the page navigation rows in multi-page standings */
  char **stand_page_row_attr;
  /** HTML attribute for the page navigation columns */
  char **stand_page_col_attr;
  /** HTML attribute for "Page %d out of %d" */
  unsigned char *stand_page_cur_attr;
  /** collate standings using user name rather then login */
  ejintbool_t stand_collate_name;
  /** calculate penalty for kirov & olympiad */
  ejintbool_t stand_enable_penalty;

  /** actual standings header text */
  unsigned char *stand_header_txt META_ATTRIB((meta_private));
  /** actual standings footer text */
  unsigned char *stand_footer_txt META_ATTRIB((meta_private));

  /** name of the generated file with the secondary standings */
  unsigned char *stand2_file_name;
  /** secondary standings header file */
  unsigned char *stand2_header_file;
  /** secondary standings footer file */
  unsigned char *stand2_footer_file;
  /** text of the secondary standings header */
  unsigned char *stand2_header_txt META_ATTRIB((meta_private));
  /** text of the secondary standings footer */
  unsigned char *stand2_footer_txt META_ATTRIB((meta_private));
  /** directory where to install a symlink to the secondary standings file */
  unsigned char *stand2_symlink_dir;

  /** name of the generated file with the public submission log */
  unsigned char *plog_file_name;
  /** public submission log header file */
  unsigned char *plog_header_file;
  /** public submission log footer file */
  unsigned char *plog_footer_file;
  /** text of the public submission log header */
  unsigned char *plog_header_txt META_ATTRIB((meta_private));
  /** text of the public submission log footer */
  unsigned char *plog_footer_txt META_ATTRIB((meta_private));
  /** public submission log update interval */
  int plog_update_time;
  /** directory where to install a symlink to the public log file */
  unsigned char *plog_symlink_dir;

  /** internal XML log update interval */
  int internal_xml_update_time;
  /** external XML log update interval */
  int external_xml_update_time;

  /** header file name for the user examination protocol */
  unsigned char *user_exam_protocol_header_file;
  /** footer file name for the user examination protocol */
  unsigned char *user_exam_protocol_footer_file;
  /** header text for the user examination protocol */
  unsigned char *user_exam_protocol_header_txt META_ATTRIB((meta_private));
  /** footer text for the user examination protocol */
  unsigned char *user_exam_protocol_footer_txt META_ATTRIB((meta_private));
  /** header file name for the problem examination protocol */
  unsigned char *prob_exam_protocol_header_file;
  /** footer file name for the problem examination protocol */
  unsigned char *prob_exam_protocol_footer_file;
  /** header text for the problem examination protocol */
  unsigned char *prob_exam_protocol_header_txt META_ATTRIB((meta_private));
  /** footer text for the problem examination protocol */
  unsigned char *prob_exam_protocol_footer_txt META_ATTRIB((meta_private));
  /** header file name for the full user examination protocol */
  unsigned char *full_exam_protocol_header_file;
  /** footer file name for the full user examination protocol */
  unsigned char *full_exam_protocol_footer_file;
  /** header text for the full user examination protocol */
  unsigned char *full_exam_protocol_header_txt META_ATTRIB((meta_private));
  /** footer text for the full user examination protocol */
  unsigned char *full_exam_protocol_footer_txt META_ATTRIB((meta_private));

  /** use festival for voice notifications */
  ejintbool_t extended_sound;
  /** disable sound notifications */
  ejintbool_t disable_sound;
  /** path to a sound file player */
  unsigned char *sound_player;
  /** sound to be played in case of success */
  unsigned char *accept_sound;
  /** sound to be played in case of run-time error */
  unsigned char *runtime_sound;
  /** sound to be played in case of time-limit exceeded error */
  unsigned char *timelimit_sound;
  /** sound to be played in case of presentation error */
  unsigned char *presentation_sound;
  /** sound to be played in case of wrong answer */
  unsigned char *wrong_sound;
  /** sound to be played in case of check failed condition */
  unsigned char *internal_sound;
  /** sound to be played upon start of the contest */
  unsigned char *start_sound;

  /** @deprecated participant's archive download interval */
  int team_download_time;

  /** serializing semaphore Id */
  int cr_serialization_key;
  /** use wall time in all reports */
  ejintbool_t show_astr_time;
  /** do not allow submitting identical runs */
  ejintbool_t ignore_duplicated_runs;
  /** enable reporting the program exit code to participants */
  ejintbool_t report_error_code;
  /** construct short problem names automatically */
  ejintbool_t auto_short_problem_name;
  /** timeout for compilers */
  int compile_real_time_limit;
  /** timeout for checkers */
  int checker_real_time_limit;
  /** show problem deadlines to participants? */
  ejintbool_t show_deadline;
  /** store separate scores for participants */
  ejintbool_t separate_user_score;
  /** show abbreviated SHA1 to users */
  ejintbool_t show_sha1;
  /** disclose judge identity in clar replies */
  ejintbool_t show_judge_identity;

  /** use gzip compression for large files */
  ejintbool_t use_gzip;
  /** minimal file size to be compressed (4096) */
  ejintsize_t min_gzip_size;
  /** store runs/reports/etc in a hierachical directory structure */
  ejintbool_t use_dir_hierarchy;
  /** @deprecated generate reports in HTML */
  ejintbool_t html_report;
  /** generate reports in XML */
  ejintbool_t xml_report;
  /** store the full output of the program being tested */
  ejintbool_t enable_full_archive;
  /** reference CPU speed (BogoMIPS) */
  int cpu_bogomips;
  ejintbool_t skip_full_testing;
  ejintbool_t skip_accept_testing;

  /** load problem uuid from history.txt file */
  ejintbool_t enable_problem_history;

  /** path to the file with variant assignment */
  unsigned char *variant_map_file;
  /** parsed variant map */
  //struct variant_map *variant_map META_ATTRIB((meta_private));

  /** enable printing of submission by participants */
  ejintbool_t enable_printing;
  /** disable banner page on printouts */
  ejintbool_t disable_banner_page;
  /** use participant login rather then name on printouts */
  ejintbool_t printout_uses_login;
  /** printing quota (in pages) */
  int team_page_quota;
  /** simplified printing by copying to the printing spool directory */
  ejintbool_t print_just_copy;

  /* common compilation virtual address space size limit */
  ej_size64_t compile_max_vm_size;
  /* common compilation stack size limit */
  ej_size64_t compile_max_stack_size;
  /* common file size limit */
  ej_size64_t compile_max_file_size;
  /* common compilation RSS limit */
  ej_size64_t compile_max_rss_size;

  /** per participant testing priority adjustment */
  char **user_priority_adjustments;
  struct user_adjustment_info *user_adjustment_info META_ATTRIB((meta_private));
  struct user_adjustment_map *user_adjustment_map META_ATTRIB((meta_private));

  /** number of different contestant statuses */
  int contestant_status_num;
  /** names of contestant statuses */
  char **contestant_status_legend;
  /** HTML attribute for standing rows for different contestant statuses */
  char **contestant_status_row_attr;
  /** show the contestant status column in the standings */
  ejintbool_t stand_show_contestant_status;
  /** show the warnings column in the standings */
  ejintbool_t stand_show_warn_number;
  /** HTML attribute for `contestant status' column of the standings */
  unsigned char *stand_contestant_status_attr;
  /** HTML attribute for `warnings' column of the standings */
  unsigned char *stand_warn_number_attr;

  /** the user groups to load */
  char **load_user_group;

  /** global tokens specification */
  unsigned char *tokens;

  struct token_info *token_info META_ATTRIB((meta_private));

  // set to 1 if there exist a tokenized problem
  int enable_tokens META_ATTRIB((meta_private));

  /** a separate dates configuration file */
  unsigned char *dates_config_file;

  struct dates_config *dates_config META_ATTRIB((meta_private));

  /** INTERNAL: text with unhandled variables */
  unsigned char *unhandled_vars;

  /** INTERNAL: no problem defined long_name */
  ejintbool_t disable_prob_long_name META_ATTRIB((meta_private));
  /** INTERNAL: all problems are output-only */
  ejintbool_t disable_passed_tests META_ATTRIB((meta_private));

  /** time between user submits */
  int time_between_submits;
  /** max size of a user input in bytes */
  ejintsize_t max_input_size;
  /** max number of submits for each user */
  int max_submit_num;
  /** max size of submits and data */
  ejintsize_t max_submit_total;
};

/* sizeof(struct section_problem_data) == 820/1280 */
struct section_problem_data
{
  struct generic_section_config g META_ATTRIB((meta_hidden));   // 32 bytes

  /** problem identifier */
  int id;
  int tester_id;
  /** problem type */
  int type;
  /** number of variants for this problem */
  int variant_num;
  /** score for successful solution */
  int full_score;
  /** score for successful user-visible solution (separate_user_score mode) */
  int full_user_score;
  /** min score after run penalty */
  int min_score_1;
  /** min score after all subtractions */
  int min_score_2;

  // offset == 64
  /** base abstract problem */
  unsigned char super[32];
  /** short name of the problem */
  unsigned char short_name[32];

  // offset == 128
  /** is this an abstract problem specification */
  ejbyteflag_t abstract;
  /** 1, if this problem is checked manually */
  ejbyteflag_t manual_checking;
  /** 1, if still check for PE */
  ejbyteflag_t check_presentation;
  /** 1, if the checker calculates test score */
  ejbyteflag_t scoring_checker;
  /** 1, if the scoring checker also produces a token */
  ejbyteflag_t enable_checker_token;
  /** 1, if the valuer works in parallel with testing */
  ejbyteflag_t interactive_valuer;
  /** 1, if PEs are converted to WAs */
  ejbyteflag_t disable_pe;
  /** 1, if WTLs are converted to TLs */
  ejbyteflag_t disable_wtl;
  /** 1, if WTLs are treated as CFs */
  ejbyteflag_t wtl_is_cf;

  /** 1, if solution uses stdin for input */
  ejbyteflag_t use_stdin;
  /** 1, if solution uses stdout for output */
  ejbyteflag_t use_stdout;
  /** 1, if combined stdin/files input is enabled */
  ejbyteflag_t combined_stdin;
  /** 1, if combined stdout/files output is enabled */
  ejbyteflag_t combined_stdout;
  /** input data for problem is binary */
  ejbyteflag_t binary_input;
  /** submit is binary */
  ejbyteflag_t binary;
  /** do not treat non-zero exit code as run-time error */
  ejbyteflag_t ignore_exit_code;
  /** for KIROV contests: handle problem in the olympiad mode*/
  ejbyteflag_t olympiad_mode;

  /** for KIROV contests: score the latest submit */
  ejbyteflag_t score_latest;
  /** for KIROV contests: score the latest submit or the best unmarked */
  ejbyteflag_t score_latest_or_unmarked;
  /** for KIROV contests: score the latest marked submit */
  ejbyteflag_t score_latest_marked;
  /** for KIROV contests: score only the tokenized submits (with tokens spent on them) */
  ejbyteflag_t score_tokenized;
  /** use AC instead of OK for successful submits */
  ejbyteflag_t use_ac_not_ok;
  /** mark previous AC for this problems as IG */
  ejbyteflag_t ignore_prev_ac;
  /** enable report viewing for contestants */
  ejbyteflag_t team_enable_rep_view;
  /** enable compilation error messages viewing for contestants */
  ejbyteflag_t team_enable_ce_view;

  /** show the full testing report to contestants */
  ejbyteflag_t team_show_judge_report;
  /** always show checker comments */
  ejbyteflag_t show_checker_comment;
  /** do not count compilation errors as failed runs */
  ejbyteflag_t ignore_compile_errors;
  /** allow changing the score for successful solutions */
  ejbyteflag_t variable_full_score;
  /** ignore penalty for this problem in overall penalty calculation */
  ejbyteflag_t ignore_penalty;
  /** pass a file with the correct answer to the checker */
  ejbyteflag_t use_corr;
  /** pass a file with test information to the checker */
  ejbyteflag_t use_info;
  /** use a working directory from the tgz archive */
  ejbyteflag_t use_tgz;


  /** accept solutions that do not pass all accepting tests */
  ejbyteflag_t accept_partial;
  /** participants cannot submit this problem */
  ejbyteflag_t disable_user_submit;
  /** no problem tab for this problem in problem_navigation mode */
  ejbyteflag_t disable_tab;
  /** do show problem statement after problem expiration */
  ejbyteflag_t unrestricted_statement;
  /** for compatibility with old configs */
  ejbyteflag_t restricted_statement;
  /** enable submit for rejected problems even after deadline */
  ejbyteflag_t enable_submit_after_reject;
  /** hide input/output file names from problem submit page */
  ejbyteflag_t hide_file_names;
  /** hide information about real time limit */
  ejbyteflag_t hide_real_time_limit;

  /** enable tokens for this problem */
  ejbyteflag_t enable_tokens;
  /** enable tokens only for user AC status */
  ejbyteflag_t tokens_for_user_ac;
  /** disable submission after this problem is solved */
  ejbyteflag_t disable_submit_after_ok;
  /** do not test this problem automatically */
  ejbyteflag_t disable_auto_testing;
  /** disable any testing of this problem */
  ejbyteflag_t disable_testing;
  /** check that submission compiles successfully */
  ejbyteflag_t enable_compilation;
  /** skip testing this problem */
  ejbyteflag_t skip_testing;
  /** hide the problem from standings */
  ejbyteflag_t hidden;

  /** do not show accept time in standings */
  ejbyteflag_t stand_hide_time;
  /** automatically advance to the next problem in navigation mode */
  ejbyteflag_t advance_to_next;
  /** disable any control characters except \r, \n in the source code */
  ejbyteflag_t disable_ctrl_chars;
  /** enable text area form for output-only problems */
  ejbyteflag_t enable_text_form;
  /** ignore the score in total score calculation */
  ejbyteflag_t stand_ignore_score;
  /** show the column after the `total' column */
  ejbyteflag_t stand_last_column;
  /** disable security restrictions for this problem */
  ejbyteflag_t disable_security;
  /** enable suid helpers for this problem */
  ejbyteflag_t enable_suid_run;
  /** enable container for this problem */
  ejbyteflag_t enable_container;
  /** adjust testing priority depending on the testing queue state */
  ejbyteflag_t enable_dynamic_priority;

  /** if the valuer also sets the marked flag */
  ejbyteflag_t valuer_sets_marked;
  /** ignore unmarked submits in scoring */
  ejbyteflag_t ignore_unmarked;
  /** consider any output to stderr as presentation error */
  ejbyteflag_t disable_stderr;
  /** use process groups */
  ejbyteflag_t enable_process_group;
  /** kill all processes belonging to 'ejexec' user */
  ejbyteflag_t enable_kill_all;
  /** hide variant number from user */
  ejbyteflag_t hide_variant;
  /** enable testlib-compatibility mode */
  ejbyteflag_t enable_testlib_mode;
  /** autoassign variants? */
  ejbyteflag_t autoassign_variants;
  /** require any of the specified problem, not all */
  ejbyteflag_t require_any;
  /** pass extended info to checker, valuer, interactor */
  ejbyteflag_t enable_extended_info;
  /** stop testing after the first failed test (like ACM) */
  ejbyteflag_t stop_on_first_fail;
  /** create a controlling socket pair for interactor */
  ejbyteflag_t enable_control_socket;

  /** enable headers/footers specific for each test */
  ejbyteflag_t enable_multi_header;
  /** use lang short name in multi headers */
  ejbyteflag_t use_lang_multi_header;

  /** send a notification to judges upon submit */
  ejbyteflag_t notify_on_submit;

  ejbyteflag_t enable_user_input;

  ejbyteflag_t enable_vcs;

  // padding to 8-byte boundary
  //unsigned char _pad1[1];

  /** number of independent examinations */
  int examinator_num;
  /** maximum astronomical time for a problem (seconds) */
  int real_time_limit;
  /** time limit in seconds */
  int time_limit;
  /** time limit in milliseconds */
  int time_limit_millis;
  /** score for one test */
  int test_score;
  /** penalty for one run for KIROV contests*/
  int run_penalty;
  /** penalty for one run for ACM contests */
  int acm_run_penalty;
  /** penalty for one disqualified run */
  int disqualified_penalty;
  /** penalty for a compilation error */
  int compile_error_penalty;
  /** number of tests to accept solutions in olympiad contests */
  int tests_to_accept;
  /** minimal number of tests to accept solutions in olympiad contests */
  int min_tests_to_accept;
  /** real time limit for checkers */
  int checker_real_time_limit;
  /** time limit for checkers */
  int checker_time_limit_ms;
  /** priority adjustment for this problem */
  int priority_adjustment;
  /** additional score multiplier for this problem */
  int score_multiplier;
  /** number of previous runs to show */
  int prev_runs_to_show;
  /** limit for the number of submits for this problem for a user */
  int max_user_run_count;
  /** long name of the problem */
  unsigned char *long_name;
  /** name for the standings column */
  unsigned char *stand_name;
  /** column to collate this problem */
  unsigned char *stand_column;
  /** group name of the problem */
  unsigned char *group_name;
  /** internal problem name */
  unsigned char *internal_name;
  /** problem UUID */
  unsigned char *uuid;
  /** problem directory (relative to problems or absolute) */
  unsigned char *problem_dir;
  /** directory with tests */
  unsigned char *test_dir;
  /** test files suffix */
  unsigned char *test_sfx;
  /** directory with correct answers */
  unsigned char *corr_dir;
  /** correct files suffix */
  unsigned char *corr_sfx;
  /** directory with info files */
  unsigned char *info_dir;
  /** info files suffix */
  unsigned char *info_sfx;
  /** directory with tar test archive */
  unsigned char *tgz_dir;
  /** tar test archive suffix */
  unsigned char *tgz_sfx;
  /** working directory master copy suffix */
  unsigned char *tgzdir_sfx;
  /** input file name */
  unsigned char *input_file;
  /** output file name */
  unsigned char *output_file;
  /** scores for individual tests */
  unsigned char *test_score_list;
  /** token specification */
  unsigned char *tokens;
  /** process umask */
  unsigned char *umask;
  /** success status (generalization of use_ac_not_ok) */
  unsigned char *ok_status;
  /** header pattern for multi-header mode */
  unsigned char *header_pat;
  /** footer pattern for multi-header mode */
  unsigned char *footer_pat;
  /** compiler environment pattern for multi-header mode */
  unsigned char *compiler_env_pat;
  /** options for container */
  unsigned char *container_options;

  struct token_info *token_info META_ATTRIB((meta_private));

  /** number of tests for Moscow scoring */
  unsigned char *score_tests;
  /** name of the built-in checker */
  unsigned char *standard_checker;
  /** spelling for the festival speach generator */
  unsigned char *spelling;
  /** file with HTML problem statement */
  unsigned char *statement_file;
  /** file with alternatives for select-one or select-many problem */
  unsigned char *alternatives_file;
  /** file with the custom problem plugin */
  unsigned char *plugin_file;
  /** XML file with the problem information */
  unsigned char *xml_file;
  /** HTML attributes for standings column */
  unsigned char *stand_attr;
  /** file to insert into the beginning of the source file */
  unsigned char *source_header;
  /** file to insert at the end of source file */
  unsigned char *source_footer;
  /** time-limit for the interactor */
  int interactor_time_limit;
  /** real time limit for the interactor */
  int interactor_real_time_limit;
  /** custom compilation command (if enable_custom language enabled) */
  unsigned char *custom_compile_cmd;
  /** custom language name (if enable_custom language enabled) */
  unsigned char *custom_lang_name;

  /** printf pattern for the test files */
  unsigned char *test_pat;
  /** printf pattern for the correct answer files */
  unsigned char *corr_pat;
  /** printf pattern for the test information files */
  unsigned char *info_pat;
  /** printf pattern for the tgz archive pattern */
  unsigned char *tgz_pat;
  /** printf pattern for the working directory master copy */
  unsigned char *tgzdir_pat;

  /** number of tests found */
  int ntests META_ATTRIB((meta_private));
  /** internal scores array  */
  int *tscores META_ATTRIB((meta_private));
  /** parsed `score_tests' */
  int *x_score_tests META_ATTRIB((meta_private));

  /** defined test sets */
  char **test_sets;
  int ts_total META_ATTRIB((meta_private));
  struct testset_info *ts_infos META_ATTRIB((meta_private));

  /** test normalization type */
  unsigned char *normalization;
  int normalization_val META_ATTRIB((meta_private));

  /** deadline for sending this problem */
  time_t deadline;
  /** time for opening this problem for submission */
  time_t start_date;

  /** penalty which depends on date */
  char **date_penalty;
  int dp_total META_ATTRIB((meta_private));
  struct penalty_info *dp_infos META_ATTRIB((meta_private));

  /** group-specific start date for this problem */
  char **group_start_date;
  /** group-specific deadline for this problem */
  char **group_deadline;

  struct group_dates gsd META_ATTRIB((meta_private));
  struct group_dates gdl META_ATTRIB((meta_private));

  char **disable_language;
  char **enable_language;
  char **require;
  char **provide_ok;
  char **allow_ip;
  /** environment variables for compilation */
  ejenvlist_t lang_compiler_env;
  /** container options for compilation */
  ejenvlist_t lang_compiler_container_options;
  /** environment variables for the problem checker */
  ejenvlist_t checker_env;
  /** environment variables for the problem valuer */
  ejenvlist_t valuer_env;
  /** environment variables for the problem interactor */
  ejenvlist_t interactor_env;
  /** environment variables for the style checker */
  ejenvlist_t style_checker_env;
  /** environment variables for the test checker */
  ejenvlist_t test_checker_env;
  /** environment variables for the init-style interactor */
  ejenvlist_t init_env;
  /** environment variables for the program itself */
  ejenvlist_t start_env;
  /** checker program */
  unsigned char *check_cmd;
  /** valuer program */
  unsigned char *valuer_cmd;
  /** interactor program */
  unsigned char *interactor_cmd;
  /** style checker program */
  unsigned char *style_checker_cmd;
  /** test checker program */
  unsigned char *test_checker_cmd;
  /** start/stop init-style interactor */
  unsigned char *init_cmd;
  /** proxy to start the program being tested */
  unsigned char *start_cmd;
  /** solution source file */
  unsigned char *solution_src;
  /** solution command */
  unsigned char *solution_cmd;
  /** post pull preparation script */
  unsigned char *post_pull_cmd;
  /** vcs mode compile script */
  unsigned char *vcs_compile_cmd;
  /** time limit adjustments depending on language */
  char **lang_time_adj;
  /** time limit milliseconds adjustments depending on language (priority over lang_time_adj) */
  char **lang_time_adj_millis;
  /** tester specially for this problem */
  unsigned char *super_run_dir;
  /** language-specific memory limit */
  char **lang_max_vm_size;
  char **lang_max_stack_size;
  char **lang_max_rss_size;

  /** environment variables for the statement */
  ejenvlist_t statement_env;

  /** alternatives for test-like problems */
  char **alternative;
  /** personal deadline extensions */
  char **personal_deadline;
  int pd_total META_ATTRIB((meta_private));
  struct pers_dead_info *pd_infos META_ATTRIB((meta_private));

  /** bonus for the Nth full solution of the problem */
  unsigned char *score_bonus;
  /** parsed: number of entries in score_bonus */
  int score_bonus_total META_ATTRIB((meta_private));
  /** parsed: score_bonus values */
  int *score_bonus_val META_ATTRIB((meta_private));

  /** number of tests, open for unprivileged users */
  unsigned char *open_tests;
  int open_tests_count META_ATTRIB((meta_private));
  int *open_tests_val META_ATTRIB((meta_private));

  /** test visibility in the final final mode */
  unsigned char *final_open_tests;
  int final_open_tests_count META_ATTRIB((meta_private));
  int *final_open_tests_val META_ATTRIB((meta_private));

  /** test visibility purchasable by tokens */
  unsigned char *token_open_tests;
  int token_open_tests_count META_ATTRIB((meta_private));
  int *token_open_tests_val META_ATTRIB((meta_private));

  /** max virtual size limit  */
  ej_size64_t max_vm_size;
  /** max size of the data (NOT USED) */
  ej_size64_t max_data_size;
  /** max stack size limit */
  ej_size64_t max_stack_size;
  /** max resident set size limit  */
  ej_size64_t max_rss_size;
  /** max allowed size of the core file */
  ej_size64_t max_core_size;
  /** max file size */
  ej_size64_t max_file_size;
  /** max virtual size limit for checkers */
  ej_size64_t checker_max_vm_size;
  /** max stack size limit for checkers */
  ej_size64_t checker_max_stack_size;
  /** max RSS limit for checkers */
  ej_size64_t checker_max_rss_size;
  /** max number of opened files per process */
  int max_open_file_count;
  /** max number of processes per user */
  int max_process_count;

  /** external id (for external application binding) */
  unsigned char *extid;

  /** these fields are for CGI editing of contest configuration files */
  unsigned char *unhandled_vars;

  /** external score view */
  char **score_view;
  int *score_view_score META_ATTRIB((meta_private));
  char **score_view_text;

  /** full path to xml_file */
  unsigned char *xml_file_path META_ATTRIB((meta_private));
  unsigned char **var_xml_file_paths META_ATTRIB((meta_private));

  /* parsed XML specs */
  union
  {
    problem_xml_t p;            /* for single problems */
    problem_xml_t *a;           /* for variant problems */
  } xml META_ATTRIB((meta_hidden));
};

/* sizeof(struct section_language_data) == 312/400 */
struct section_language_data
{
  struct generic_section_config g META_ATTRIB((meta_hidden));

  /** language id */
  int id;
  /** language id for compilation */
  int compile_id;
  /** participant cannot use this language */
  ejintbool_t disabled;
  int compile_real_time_limit;
  /** whether binary files are accepted */
  ejintbool_t binary;
  /** priority adjustment for this language */
  int priority_adjustment;
  /** language is insecure */
  ejintbool_t insecure;
  /** disable security restrictions for this language */
  ejintbool_t disable_security;
  /** enable suid helpers for this problem */
  ejintbool_t enable_suid_run;
  /** perform unix->dos conversion */
  ejintbool_t is_dos;
  /** language short name */
  unsigned char short_name[32];
  /** language long name */
  unsigned char *long_name;
  /** configuration key */
  unsigned char *key;
  /** language architecture */
  unsigned char *arch;
  /** source file suffix */
  unsigned char src_sfx[32];
  /** executable file suffix */
  unsigned char exe_sfx[32];
  /** Content-type: header for downloads */
  unsigned char *content_type;
  /** compile command */
  unsigned char *cmd;
  /** style checker */
  unsigned char *style_checker_cmd;
  /** environment to pass to the style checker */
  ejenvlist_t style_checker_env;

  /** external id (for external application binding) */
  unsigned char *extid;

  /** directory for non-default super-run directory */
  unsigned char *super_run_dir;

  /** do not test this language automatically */
  ejintbool_t disable_auto_testing;
  /** do not test this language at all */
  ejintbool_t disable_testing;
  /** enable custom compilation script */
  ejintbool_t enable_custom;

  /** max virtual size limit  */
  ej_size64_t max_vm_size;
  /** max stack size limit */
  ej_size64_t max_stack_size;
  /** max file size limit */
  ej_size64_t max_file_size;
  /** max RSS limit  */
  ej_size64_t max_rss_size;
  /** stack size limit for compiled programs, overrides the problem settings */
  ej_size64_t run_max_stack_size;
  /** virtual memory size limit for compiled programs, overrides the problem settings */
  ej_size64_t run_max_vm_size;
  /** max resident set size limit for compiled programs, overrides the problem settings */
  ej_size64_t run_max_rss_size;

  /** index of the compile directory in the list of compile servers */
  int compile_dir_index;
  /** common subdirectory */
  unsigned char *compile_dir;
  /** directory for serve->compile packets */
  unsigned char *compile_queue_dir;
  /** directory for source files */
  unsigned char *compile_src_dir;
  /** base directory for compile results */
  unsigned char *compile_out_dir;
  /** directory for compile->serve packets */
  unsigned char *compile_status_dir;
  /** directory for executables/error logs */
  unsigned char *compile_report_dir;
  /** environment to pass to the compiler */
  ejenvlist_t compiler_env;
  /** ID of compilation server */
  unsigned char *compile_server_id;
  /** suffix to use for multi-header setup */
  unsigned char *multi_header_suffix;
  /** additional container options -- appended to the problem container_options */
  unsigned char *container_options;

  unsigned char *unhandled_vars;
  /** disabled by configuration script */
  int disabled_by_config META_ATTRIB((meta_private));
};

/* sizeof(struct section_tester_data) == 292/400 */
struct section_tester_data
{
  struct generic_section_config g META_ATTRIB((meta_hidden));

  int id;
  /** tester name */
  unsigned char name[32];
  /** reference problem number */
  int problem;
  /** reference problem name */
  unsigned char problem_name[32];
  /** catch-all entry */
  ejintbool_t any;

  /** do unix->dos conversion of tests? */
  ejintbool_t is_dos;
  /** do not redirect standard streams */
  ejintbool_t no_redirect;
  /** priority adjustment for this tester */
  int priority_adjustment;
  /** ignore the stderr stream */
  ejintbool_t ignore_stderr;

  /** checker architecture */
  unsigned char arch[32];
  /** configuration key */
  unsigned char *key;
  /** type of memory limit handling */
  unsigned char *memory_limit_type;
  /** type of secure execution handling */
  unsigned char *secure_exec_type;

  /** is this tester abstract */
  ejintbool_t abstract;
  /** names of the supertesters */
  char **super;
  /** whether this tester has been processed */
  ejintbool_t is_processed META_ATTRIB((meta_private));
  ejintbool_t skip_testing;

  /** disable core dumps */
  ejintbool_t no_core_dump;
  /** enable memory limit detection */
  ejintbool_t enable_memory_limit_error;
  /** the signal to kill processes */
  unsigned char *kill_signal;
  /** max size of the stack */
  size_t max_stack_size;
  /** max size of the data */
  size_t max_data_size;
  /** max size of the virtual memory */
  size_t max_vm_size;
  /** max size of the resident set */
  size_t max_rss_size;
  /** whether the environment is cleared */
  ejintbool_t clear_env;
  int time_limit_adjustment;
  /** have priority over `time_limit_adjustment' */
  int time_limit_adj_millis;

  unsigned char *run_dir;
  unsigned char *run_queue_dir;
  unsigned char *run_exe_dir;
  unsigned char *run_out_dir;
  /** run->serve status dir */
  unsigned char *run_status_dir;
  /** run->serve report dir */
  unsigned char *run_report_dir;
  /** run->serve team report dir */
  unsigned char *run_team_report_dir;
  /** run->serve full output archive dir */
  unsigned char *run_full_archive_dir;

  unsigned char *check_dir;
  /** file that contains completion status */
  unsigned char *errorcode_file;
  /** stderr output of the checked program */
  unsigned char *error_file;

  /** helper to prepare the executable */
  unsigned char *prepare_cmd;
  /** helper to start testing */
  unsigned char *start_cmd;
  /** nwrun spool directory */
  unsigned char *nwrun_spool_dir;

  /** environment variables for start_cmd */
  ejenvlist_t start_env;

  /** internal: parsed memory_limit_type */
  int memory_limit_type_val META_ATTRIB((meta_private));
  /** internal: parsed secure_exec_type */
  int secure_exec_type_val META_ATTRIB((meta_private));
};

int
prepare(
        const struct contest_desc *cnts,
        serve_state_t,
        char const *,
        int flags,
        int mode,
        char const *opts,
        int managed_flag,
        const unsigned char **,
        const unsigned char **);
int create_dirs(
        const struct contest_desc *cnts,
        serve_state_t, int mode);
int
prepare_serve_defaults(
        const struct contest_desc *cnts,
        serve_state_t,
        const struct contest_desc **);

int find_tester(const serve_state_t, int, char const *);
int find_variant(const serve_state_t, int, int, int *);
int find_user_variant(const serve_state_t, int, int *);
int find_user_priority_adjustment(const serve_state_t, int user_id);

int prepare_tester_refinement(serve_state_t, struct section_tester_data *,
                              int, int);
int create_tester_dirs(struct section_tester_data *);

struct ejudge_cfg;
struct section_global_data *prepare_new_global_section(int contest_id, const unsigned char *root_dir, const struct ejudge_cfg *config);
struct generic_section_config * prepare_parse_config_file(const unsigned char *path,
                                                          int *p_cond_count);
void prepare_set_global_defaults(struct section_global_data *global);

struct generic_section_config *prepare_free_config(struct generic_section_config *cfg);

struct section_global_data *
prepare_global_free(struct section_global_data *global);
struct section_language_data *
prepare_language_free(struct section_language_data *lang);
struct section_problem_data *
prepare_problem_free(struct section_problem_data *prob);
struct section_tester_data *
prepare_tester_free(struct section_tester_data *tester);

struct section_global_data *prepare_alloc_global(void);
struct section_language_data *prepare_alloc_language(void);
struct section_problem_data *prepare_alloc_problem(void);
struct section_tester_data *prepare_alloc_tester(void);

void prepare_problem_init_func(struct generic_section_config *gp);

struct section_problem_data *
prepare_copy_problem(const struct section_problem_data *in);

void prepare_set_prob_value(int field, struct section_problem_data *out,
                            const struct section_problem_data *abstr,
                            const struct section_global_data *global);
void
prepare_set_all_prob_values(
        struct section_problem_data *out,
        const struct section_problem_data *abstr,
        const struct section_global_data *global);

void
prepare_unparse_global(
        FILE *f,
        const struct contest_desc *cnts,
        struct section_global_data *global,
        const unsigned char *compile_dir,
        int need_variant_map);
void prepare_unparse_unhandled_global(FILE *f,
                                      const struct section_global_data *global);
int prepare_check_forbidden_global(FILE *f, const struct section_global_data *global);

void
prepare_unparse_lang(
        FILE *f,
        const struct section_language_data *lang,
        const unsigned char *long_name,
        const unsigned char *options,
        const unsigned char *libs);
void prepare_unparse_unhandled_lang(FILE *f,
                                    const struct section_language_data *lang);
int prepare_check_forbidden_lang(FILE *f, const struct section_language_data *lang);

void
prepare_unparse_prob(
        FILE *f,
        const struct section_problem_data *prob,
        const struct section_problem_data *aprob,
        const struct section_global_data *global,
        int score_system_val);
void prepare_unparse_unhandled_prob(FILE *f, const struct section_problem_data *prob,
                                    const struct section_global_data *global);
int prepare_check_forbidden_prob(FILE *f, const struct section_problem_data *prob);
void
prepare_unparse_actual_prob(
        FILE *f,
        const struct section_problem_data *prob,
        const struct section_global_data *global,
        int show_paths);

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
                            const unsigned char *testing_work_dir,
                            const unsigned char *contests_home_dir);

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

int *prepare_parse_score_tests(const unsigned char *str, int score);
const unsigned char *prepare_unparse_problem_type(int val);
int prepare_parse_memory_limit_type(const unsigned char *str);
int prepare_parse_secure_exec_type(const unsigned char *str);
int
prepare_parse_score_system(const unsigned char *str);
int
prepare_insert_variant_num(
        unsigned char *buf,
        size_t size,
        const unsigned char *file,
        int variant);

struct token_info *
prepare_parse_tokens(FILE *log_f, const unsigned char *tokens);

struct ejudge_cfg;
extern struct ejudge_cfg *ejudge_config;

int
lang_config_configure(
	FILE *log_f,
	const unsigned char *config_dir,
        int max_lang,
        struct section_language_data **langs);

const unsigned char*
get_advanced_layout_path(
        unsigned char *buf,
        size_t bufsize,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        const unsigned char *entry,
        int variant);

int
prepare_parse_open_tests(
        FILE *flog,
        const unsigned char *str,
        int **p_vals,
        int *p_count);

int
cntsprob_get_test_visibility(
        const struct section_problem_data *prob,
        int num,
        int final_mode,
        int token_flags);

int
prepare_parse_test_score_list(
        FILE *log_f,
        const unsigned char *test_score_list,
        int **pscores,
        int *pcount);

int
prepare_parse_testsets(
        char **set_in,
        int *p_total,
        struct testset_info **p_info);
void
prepare_free_testsets(int t, struct testset_info *p);

void
prepare_copy_dates(
        struct section_problem_data *prob,
        struct dates_config *dcfg);

unsigned char *
prepare_varsubst(
        serve_state_t state,
        unsigned char *in_str,
        int free_flag,
        const struct section_problem_data *prob,
        const struct section_language_data *lang,
        const struct section_tester_data *tester);

char **
prepare_sarray_varsubst(
        serve_state_t state,
        const struct section_problem_data *prob,
        const struct section_language_data *lang,
        const struct section_tester_data *tester,
        char **a1);

#endif /* __PREPARE_H__ */
