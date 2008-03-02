/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005-2008 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"
#include "version.h"

#include "super_html.h"
#include "super-serve.h"
#include "misctext.h"
#include "mischtml.h"
#include "prepare.h"
#include "ejudge_cfg.h"
#include "super_proto.h"
#include "fileutl.h"
#include "prepare_dflt.h"
#include "xml_utils.h"
#include "ej_process.h"
#include "cpu.h"
#include "userlist_clnt.h"
#include "userlist_proto.h"
#include "userlist.h"
#include "prepare_serve.h"
#include "errlog.h"
#include "random.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/wait.h>
#include <errno.h>

#if defined EJUDGE_CHARSET
#define INTERNAL_CHARSET EJUDGE_CHARSET
#else
#define INTERNAL_CHARSET "utf-8"
#endif

static const unsigned char head_row_attr[] =
  " bgcolor=\"#a0a0a0\"";
static const unsigned char prob_row_attr[] =
  " bgcolor=\"#b0b0b0\"";
static const unsigned char * const form_row_attrs[]=
{
  " bgcolor=\"#d0d0d0\"",
  " bgcolor=\"#e0e0e0\"",
};

static void
html_submit_button(FILE *f,
                   int action,
                   const unsigned char *label)
{
  fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\"/>",
          action, label);
}

static void
html_select(FILE *f, int value, const unsigned char *param_name,
            const unsigned char * const *options)
{
  int i;

  fprintf(f, "<select name=\"%s\">", param_name);
  for (i = 0; options[i]; i++)
    fprintf(f, "<option value=\"%d\"%s>%s</option>",
            i, (i == value) ? " selected=\"1\"" : "", options[i]);
  fprintf(f, "</select>\n");
}

static void
html_boolean_select(FILE *f,
                    int value,
                    const unsigned char *param_name,
                    const unsigned char *false_txt,
                    const unsigned char *true_txt)
{
  if (!false_txt) false_txt = "No";
  if (!true_txt) true_txt = "Yes";

  fprintf(f, "<select name=\"%s\"><option value=\"0\"%s>%s</option><option value=\"1\"%s>%s</option></select>",
          param_name,
          value?"":" selected=\"1\"", false_txt,
          value?" selected=\"1\"":"", true_txt);
}

static void
html_boolean_3_select(FILE *f,
                      int value,
                      const unsigned char *param_name,
                      const unsigned char *unknown_txt,
                      const unsigned char *false_txt,
                      const unsigned char *true_txt)
{
  const unsigned char *sel[3] = { "", "", "" };

  if (!unknown_txt) unknown_txt = "Unknown";
  if (!false_txt) false_txt = "No";
  if (!true_txt) true_txt = "Yes";

  if (value != 0 && value != 1) value = -1;
  sel[value + 1] = " selected=\"1\"";

  fprintf(f, "<select name=\"%s\"><option value=\"-1\"%s>%s</option><option value=\"0\"%s>%s</option><option value=\"1\"%s>%s</option></select>",
          param_name,
          sel[0], unknown_txt, sel[1], false_txt, sel[2], true_txt);
}

static void
html_edit_text_form(FILE *f,
                    int size,
                    int maxlength,
                    const unsigned char *param_name,
                    const unsigned char *value)
{
  unsigned char *s, *p = "";

  if (!size) size = 48;
  if (!maxlength) maxlength = 1024;
  if (!value || !value[0]) p = "<i>(Not set)</i>";
  s = html_armor_string_dup(value);

  fprintf(f, "<input type=\"text\" name=\"%s\" value=\"%s\" size=\"%d\" maxlength=\"%d\"/>%s", param_name, s, size, maxlength, p);
  xfree(s);
}

static void
html_edit_text_form_1(FILE *f,
                      int size,
                      int maxlength,
                      const unsigned char *param_name,
                      const unsigned char *value)
{
  unsigned char *s, *p = "";

  if (!size) size = 48;
  if (!maxlength) maxlength = 1024;
  if (value && value[0] == 1) {
    p = "<i>(Not set)</i>";
    s = xstrdup("");
  } else {
    if (!value || !value[0]) p = "<i>(Empty)</i>";
    s = html_armor_string_dup(value);
  }

  fprintf(f, "<input type=\"text\" name=\"%s\" value=\"%s\" size=\"%d\" maxlength=\"%d\"/>%s", param_name, s, size, maxlength, p);
  xfree(s);
}

static void
html_hidden_var(FILE *f, const unsigned char *name, const unsigned char *value)
{
  fprintf(f, "<input type=\"hidden\" name=\"%s\" value=\"%s\"/>", name, value);
}

static void
print_string_editing_row(FILE *f,
                         const unsigned char *title,
                         const unsigned char *value,
                         int change_action,
                         int clear_action,
                         int edit_action,
                         ej_cookie_t session_id,
                         const unsigned char *row_attr,
                         const unsigned char *self_url,
                         const unsigned char *extra_args,
                         const unsigned char *hidden_vars)
{
  unsigned char hbuf[1024];

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>%s</td><td>", row_attr, title);
  html_edit_text_form(f, 0, 0, "param", value);
  fprintf(f, "</td><td>");
  html_submit_button(f, change_action, "Change");
  if (clear_action > 0) {
    html_submit_button(f, clear_action, "Clear");
  }
  if (edit_action > 0 && value && *value)
    fprintf(f, "%sEdit file</a>",
            html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                          "action=%d", edit_action));
  fprintf(f, "</td></tr></form>\n");
}

static void
print_string_editing_row_2(FILE *f,
                           const unsigned char *title,
                           const unsigned char *value,
                           int change_action,
                           int clear_action,
                           const unsigned char *extra_msg,
                           ej_cookie_t session_id,
                           const unsigned char *row_attr,
                           const unsigned char *self_url,
                           const unsigned char *extra_args,
                           const unsigned char *hidden_vars)
{
  if (!extra_msg) extra_msg = "";
  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>%s</td><td>", row_attr, title);
  html_edit_text_form(f, 0, 0, "param", value);
  fprintf(f, "%s</td><td>", extra_msg);
  html_submit_button(f, change_action, "Change");
  if (clear_action > 0) {
    html_submit_button(f, clear_action, "Clear");
  }
  fprintf(f, "</td></tr></form>\n");
}

static void
print_string_editing_row_3(FILE *f,
                           const unsigned char *title,
                           const unsigned char *value,
                           int change_action,
                           int clear_action,
                           const unsigned char *extra_msg,
                           ej_cookie_t session_id,
                           const unsigned char *row_attr,
                           const unsigned char *self_url,
                           const unsigned char *extra_args,
                           const unsigned char *hidden_vars)
{
  if (!extra_msg) extra_msg = "";
  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>%s</td><td>", row_attr, title);
  html_edit_text_form_1(f, 0, 0, "param", value);
  fprintf(f, "%s</td><td>", extra_msg);
  html_submit_button(f, change_action, "Change");
  if (clear_action > 0) {
    html_submit_button(f, clear_action, "Clear");
  }
  fprintf(f, "</td></tr></form>\n");
}

static void
print_int_editing_row(FILE *f,
                      const unsigned char *title,
                      int value,
                      const unsigned char *extra_text,
                      int change_action,
                      ej_cookie_t session_id,
                      const unsigned char *row_attr,
                      const unsigned char *self_url,
                      const unsigned char *extra_args,
                      const unsigned char *hidden_vars)
{
  unsigned char vbuf[1024];

  if (!extra_text) extra_text = "";
  snprintf(vbuf, sizeof(vbuf), "%d", value);
  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>%s</td><td>", row_attr, title);
  html_edit_text_form(f, 0, 0, "param", vbuf);
  fprintf(f, "%s</td><td>", extra_text);
  html_submit_button(f, change_action, "Change");
  fprintf(f, "</td></tr></form>\n");
}

static void
print_boolean_select_row(FILE *f,
                         const unsigned char *title,
                         int value,
                         int change_action,
                         ej_cookie_t session_id,
                         const unsigned char *row_attr,
                         const unsigned char *self_url,
                         const unsigned char *extra_args,
                         const unsigned char *hidden_vars)

{
  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>%s</td><td>", row_attr, title);
  html_boolean_select(f, value, "param", 0, 0);
  fprintf(f, "</td><td>");
  html_submit_button(f, change_action, "Change");
  fprintf(f, "</td></tr></form>\n");
}

#define SIZE_G (1024 * 1024 * 1024)
#define SIZE_M (1024 * 1024)
#define SIZE_K (1024)

static unsigned char*
num_to_size(unsigned char *buf, size_t buf_size, int num)
{
  if (!num) snprintf(buf, buf_size, "0");
  else if (!(num % SIZE_G)) snprintf(buf, buf_size, "%uG", num / SIZE_G);
  else if (!(num % SIZE_M)) snprintf(buf, buf_size, "%uM", num / SIZE_M);
  else if (!(num % SIZE_K)) snprintf(buf, buf_size, "%uK", num / SIZE_K);
  else snprintf(buf, buf_size, "%u", num);
  return buf;
}
static unsigned char*
size_t_to_size(unsigned char *buf, size_t buf_size, size_t num)
{
  if (!num) snprintf(buf, buf_size, "0");
  else if (!(num % SIZE_G)) snprintf(buf, buf_size, "%zuG", num / SIZE_G);
  else if (!(num % SIZE_M)) snprintf(buf, buf_size, "%zuM", num / SIZE_M);
  else if (!(num % SIZE_K)) snprintf(buf, buf_size, "%zuK", num / SIZE_K);
  else snprintf(buf, buf_size, "%zu", num);
  return buf;
}

/*
Basic settings:
  GLOBAL_PARAM(contest_time, "d"),
  GLOBAL_PARAM(board_fog_time, "d"),
  GLOBAL_PARAM(board_unfog_time, "d"),
  GLOBAL_PARAM(score_system, "s"),
  GLOBAL_PARAM(virtual, "d"),
  Use compile server?
  GLOBAL_PARAM(standings_locale, "s"),

Participant's capabilities
  GLOBAL_PARAM(team_enable_src_view, "d"),
  GLOBAL_PARAM(team_enable_rep_view, "d"),
  GLOBAL_PARAM(team_enable_ce_view, "d"),
  GLOBAL_PARAM(team_show_judge_report, "d"),
  GLOBAL_PARAM(ignore_compile_errors, "d"),
  GLOBAL_PARAM(disable_clars, "d"),
  GLOBAL_PARAM(disable_team_clars, "d"),
  GLOBAL_PARAM(disable_submit_after_ok, "d"),
  GLOBAL_PARAM(ignore_compile_errors, "d"),
  GLOBAL_PARAM(enable_printing, "d"),
  GLOBAL_PARAM(disable_banner_page, "d"),
  GLOBAL_PARAM(ignore_duplicated_runs, "d"),
  GLOBAL_PARAM(report_error_code, "d"),
  GLOBAL_PARAM(show_deadline, "d"),
  GLOBAL_PARAM(prune_empty_users, "d"),
  GLOBAL_PARAM(enable_full_archive, "d"),

Contest files and directories:
  GLOBAL_PARAM(script_dir, "s"),
  GLOBAL_PARAM(test_dir, "s"),
  GLOBAL_PARAM(corr_dir, "s"),
  GLOBAL_PARAM(info_dir, "s"),
  GLOBAL_PARAM(tgz_dir, "s"),
  GLOBAL_PARAM(checker_dir, "s"),
  GLOBAL_PARAM(statement_dir, "s"),
  GLOBAL_PARAM(plugin_dir, "s"),
  GLOBAL_PARAM(description_file, "s"),
  GLOBAL_PARAM(contest_start_cmd, "s"),

Participant's quotas:
  GLOBAL_PARAM(max_run_size, "d"),
  GLOBAL_PARAM(max_run_total, "d"),
  GLOBAL_PARAM(max_run_num, "d"),
  GLOBAL_PARAM(max_clar_size, "d"),
  GLOBAL_PARAM(max_clar_total, "d"),
  GLOBAL_PARAM(max_clar_num, "d"),
  GLOBAL_PARAM(team_page_quota, "d"),

Standings files and URLs:
  GLOBAL_PARAM(team_info_url, "s"),
  GLOBAL_PARAM(prob_info_url, "s"),
  GLOBAL_PARAM(standings_file_name, "s"),
  GLOBAL_PARAM(users_on_page, "d"),
  GLOBAL_PARAM(stand_header_file, "s"),
  GLOBAL_PARAM(stand_footer_file, "s"),
  GLOBAL_PARAM(stand_symlink_dir, "s"),
  GLOBAL_PARAM(stand2_file_name, "s"),
  GLOBAL_PARAM(stand2_header_file, "s"),
  GLOBAL_PARAM(stand2_footer_file, "s"),
  GLOBAL_PARAM(stand2_symlink_dir, "s"),
  GLOBAL_PARAM(plog_file_name, "s"),
  GLOBAL_PARAM(plog_header_file, "s"),
  GLOBAL_PARAM(plog_footer_file, "s"),
  GLOBAL_PARAM(plog_update_time, "d"),
  GLOBAL_PARAM(plog_symlink_dir, "s"),

Standings table attributes:
  GLOBAL_PARAM(stand_fancy_style, "d"),
  GLOBAL_PARAM(stand_extra_format, "s"),
  GLOBAL_PARAM(stand_extra_legend, "s"),
  GLOBAL_PARAM(stand_extra_attr, "s"),
  GLOBAL_PARAM(stand_table_attr, "s"),
  GLOBAL_PARAM(stand_place_attr, "s"),
  GLOBAL_PARAM(stand_team_attr, "s"),
  GLOBAL_PARAM(stand_prob_attr, "s"),
  GLOBAL_PARAM(stand_solved_attr, "s"),
  GLOBAL_PARAM(stand_score_attr, "s"),
  GLOBAL_PARAM(stand_penalty_attr, "s"),
  GLOBAL_PARAM(stand_time_attr, "s"),
  GLOBAL_PARAM(stand_self_row_attr, "s"),
  GLOBAL_PARAM(stand_v_row_attr, "s"),
  GLOBAL_PARAM(stand_r_row_attr, "s"),
  GLOBAL_PARAM(stand_u_row_attr, "s"),
  GLOBAL_PARAM(stand_success_attr, "s"),
  GLOBAL_PARAM(stand_fail_attr, "s"),
  GLOBAL_PARAM(stand_trans_attr, "s"),
  GLOBAL_PARAM(stand_disq_attr, "s"),
  GLOBAL_PARAM(stand_use_login, "d"),
  GLOBAL_PARAM(stand_show_ok_time, "d"),
  GLOBAL_PARAM(stand_show_att_num, "d"),
  GLOBAL_PARAM(stand_sort_by_solved, "d"),
  GLOBAL_PARAM(ignore_success_time, "d"),
  GLOBAL_PARAM(stand_collate_name, "d"),
  GLOBAL_PARAM(stand_enable_penalty, "d"),

Advanced settings:
  GLOBAL_PARAM(sleep_time, "d"),
  GLOBAL_PARAM(serve_sleep_time, "d"),
  GLOBAL_PARAM(autoupdate_standings, "d"),
  GLOBAL_PARAM(charset, "s"),
  GLOBAL_PARAM(rounding_mode, "s"),
  GLOBAL_PARAM(max_file_length, "d"),
  GLOBAL_PARAM(max_line_length, "d"),
  GLOBAL_PARAM(inactivity_timeout, "d"),
  GLOBAL_PARAM(disable_auto_testing, "d"),
  GLOBAL_PARAM(disable_testing, "d"),
  GLOBAL_PARAM(team_download_time, "d"),
  GLOBAL_PARAM(cr_serialization_key, "d"),
  GLOBAL_PARAM(show_astr_time, "d"),
  GLOBAL_PARAM(enable_continue, "d"),
  GLOBAL_PARAM(enable_report_upload, "d"),
  GLOBAL_PARAM(enable_runlog_merge, "d"),
  GLOBAL_PARAM(cpu_bogomips, "d"),

Not settable (atleast for now):
  GLOBAL_PARAM(a2ps_path, "s"),
  GLOBAL_PARAM(a2ps_args, "x"),
  GLOBAL_PARAM(lpr_path, "s"),
  GLOBAL_PARAM(lpr_args, "x"),
  GLOBAL_PARAM(diff_path, "s"),
  GLOBAL_PARAM(compile_dir, "s"),
  GLOBAL_PARAM(compile_work_dir, "s"),
  GLOBAL_PARAM(run_dir, "s"),
  GLOBAL_PARAM(run_work_dir, "s"),
  GLOBAL_PARAM(run_check_dir, "s"),
  GLOBAL_PARAM(htdocs_dir, "s"),
  GLOBAL_PARAM(enable_l10n, "d"),
  GLOBAL_PARAM(l10n_dir, "s"),
  GLOBAL_PARAM(use_gzip, "d"),
  GLOBAL_PARAM(min_gzip_size, "d"),
  GLOBAL_PARAM(use_dir_hierarchy, "d"),
  GLOBAL_PARAM(variant_map_file, "s"),
  GLOBAL_PARAM(priority_adjustment, "d"),
  GLOBAL_PARAM(user_priority_adjustments, "x"),
  GLOBAL_PARAM(contestant_status_num, "d"),
  GLOBAL_PARAM(contestant_status_legend, "x"),
  GLOBAL_PARAM(contestant_status_row_attr, "x"),
  GLOBAL_PARAM(stand_show_contestant_status, "d"),
  GLOBAL_PARAM(stand_contestant_status_attr, "s"),
*/

int
super_html_edit_global_parameters(FILE *f,
                                  int priv_level,
                                  int user_id,
                                  const unsigned char *login,
                                  ej_cookie_t session_id,
                                  ej_ip_t ip_address,
                                  struct ejudge_cfg *config,
                                  struct sid_state *sstate,
                                  const unsigned char *self_url,
                                  const unsigned char *hidden_vars,
                                  const unsigned char *extra_args)
{
  struct section_global_data *global = sstate->global;
  unsigned char hbuf[1024];
  int param;
  unsigned char *s, *xstr;
  int row = 1;

  static const unsigned char * const contest_types[] =
  {
    "ACM",
    "Kirov",
    "Olympiad",
    "Moscow",
    "Virtual ACM",
    "Virtual Olympiad",
    0,
  };
  static const unsigned char * const standings_languages[] =
  {
    "English",
    "Russian",
    0,
  };

  static const unsigned char * const rounding_modes[] =
  {
    "Truncating up (ceil)",
    "Truncating down (floor)",
    "Rounding",
    0,
  };

  if (sstate->serve_parse_errors) {
    unsigned char *s = html_armor_string_dup(sstate->serve_parse_errors);
    super_html_contest_page_menu(f, session_id, sstate, 2, self_url, hidden_vars,
                                 extra_args);
    fprintf(f, "<h2><tt>serve.cfg</tt> cannot be edited</h2>\n");
    fprintf(f, "<font color=\"red\"><pre>%s</pre></font>\n", s);
    xfree(s);
    return 0;
  }

  if (!global) {
    fprintf(f, "<h2>No current global settings!</h2>\n");
    super_html_contest_page_menu(f, session_id, sstate, 2, self_url, hidden_vars,
                                 extra_args);
    return 0;
  }

  super_html_contest_page_menu(f, session_id, sstate, 2, self_url, hidden_vars,
                               extra_args);

  fprintf(f, "<table border=\"0\">\n");

  //GLOBAL_PARAM(contest_time, "d"),
  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Contest time (HH:MM):</td>", form_row_attrs[row ^= 1]);
  if (!global->contest_time) {
    fprintf(f, "<td><input type=\"text\" name=\"param\" value=\"0\" size=\"8\"/><i>(Unlimited)</i></td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_DURATION, "Change");
  } else {
    fprintf(f, "<td><input type=\"text\" name=\"param\" value=\"%d:%02d\" size=\"8\"/></td><td>", global->contest_time / 60, global->contest_time % 60);
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_DURATION, "Change");
    html_submit_button(f, SSERV_CMD_GLOB_UNLIMITED_DURATION, "Set unlimited");
  }
  fprintf(f, "</td></tr></form>\n");

  if (!global->contest_time) {
    //GLOBAL_PARAM(contest_finish_time, "s"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Contest end time:</td><td>",
            form_row_attrs[row ^= 1]);
    html_date_select(f, global->contest_finish_time_d);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_CONTEST_FINISH_TIME, "Change");
    html_submit_button(f, SSERV_CMD_GLOB_CLEAR_CONTEST_FINISH_TIME, "Clear");
    fprintf(f, "</td></tr></form>\n");
  }

  //GLOBAL_PARAM(score_system, "s"),
  //GLOBAL_PARAM(virtual, "d"),
  ASSERT(global->score_system_val >= SCORE_ACM && global->score_system_val < SCORE_TOTAL);
  if (global->is_virtual) {
    ASSERT(global->score_system_val == SCORE_ACM || global->score_system_val == SCORE_OLYMPIAD);
  }
  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Scoring system:</td><td>", form_row_attrs[row ^= 1]);
  param = global->score_system_val;
  if (global->is_virtual) {
    if (global->score_system_val == SCORE_ACM) param = SCORE_TOTAL;
    else param = SCORE_TOTAL + 1;
  }
  html_select(f, param, "param", contest_types);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_GLOB_CHANGE_TYPE, "Change");
  fprintf(f, "</td></tr></form>\n");

  //GLOBAL_PARAM(board_fog_time, "d"),
  //GLOBAL_PARAM(board_unfog_time, "d"),
  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Standings freeze time (HH:MM) before finish:</td>"
          , form_row_attrs[row ^= 1]);
  if (!global->board_fog_time) {
    fprintf(f, "<td><input type=\"text\" name=\"param\" value=\"0\" size=\"8\"/><i>(No freeze)</i></td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_FOG_TIME, "Change");
  } else {
    fprintf(f, "<td><input type=\"text\" name=\"param\" value=\"%d:%02d\" size=\"8\"/></td><td>", global->board_fog_time / 60, global->board_fog_time % 60);
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_FOG_TIME, "Change");
    html_submit_button(f, SSERV_CMD_GLOB_DISABLE_FOG, "Disable");
  }
  fprintf(f, "</td></tr></form>\n");
  if (global->board_fog_time) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Standings unfreeze time (HH:MM) after finish:</td>",
            form_row_attrs[row ^= 1]);
    fprintf(f, "<td><input type=\"text\" name=\"param\" value=\"%d:%02d\" size=\"8\"/></td><td>", global->board_unfog_time / 60, global->board_unfog_time % 60);
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_UNFOG_TIME, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  //use standard compilation server?
  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Use the default compilation server:</td><td>",
          form_row_attrs[row ^= 1]);
  html_boolean_select(f, !sstate->disable_compilation_server, "param", 0, 0);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_GLOB_CHANGE_USE_COMPILATION_SERVER, "Change");
  fprintf(f, "</td></tr></form>\n");

  //GLOBAL_PARAM(secure_run, "d"),
  print_boolean_select_row(f, "Run programs securely:",
                           global->secure_run,
                           SSERV_CMD_GLOB_CHANGE_SECURE_RUN,
                           session_id, form_row_attrs[row ^= 1],
                           self_url, extra_args, hidden_vars);

  //GLOBAL_PARAM(enable_memory_limit_error, "d"),
  print_boolean_select_row(f, "Enable support for MemoryLimit error:",
                           global->enable_memory_limit_error,
                           SSERV_CMD_GLOB_CHANGE_ENABLE_MEMORY_LIMIT_ERROR,
                           session_id, form_row_attrs[row ^= 1],
                           self_url, extra_args, hidden_vars);

  //GLOBAL_PARAM(detect_violations, "d"),
  print_boolean_select_row(f, "Detect security violations:",
                           global->detect_violations,
                           SSERV_CMD_GLOB_CHANGE_DETECT_VIOLATIONS,
                           session_id, form_row_attrs[row ^= 1],
                           self_url, extra_args, hidden_vars);

  //GLOBAL_PARAM(standings_locale, "s"),
  if (!strcmp(global->standings_locale, "ru_RU.KOI8-R")
      || !strcmp(global->standings_locale, "ru")) {
    param = 1;
  } else {
    param = 0;
  }
  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Standings language:</td><td>",
          form_row_attrs[row ^= 1]);
  html_select(f, param, "param", standings_languages);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_GLOB_CHANGE_STAND_LOCALE, "Change");
  fprintf(f, "</td></tr></form>\n");

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Contestant's capabilities</b>", head_row_attr);
  row = 1;
  if (sstate->show_global_1) {
    html_submit_button(f, SSERV_CMD_GLOB_HIDE_1, "Hide");
  } else {
    html_submit_button(f, SSERV_CMD_GLOB_SHOW_1, "Show");
  }
  fprintf(f, "</td></tr></form>");

  if (sstate->show_global_1) {
    //GLOBAL_PARAM(team_enable_src_view, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Contestant may view submitted source code:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->team_enable_src_view, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_SRC_VIEW, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(disable_failed_test_view, "d"),
    if (global->score_system_val == SCORE_ACM
        || global->score_system_val == SCORE_MOSCOW) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<tr%s><td>Participants cannot view failed test number:</td><td>", form_row_attrs[row ^= 1]);
      html_boolean_select(f, global->disable_failed_test_view, "param", 0, 0);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_DISABLE_FAILED_TEST_VIEW, "Change");
      fprintf(f, "</td></tr></form>\n");
    }

    //GLOBAL_PARAM(team_enable_rep_view, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Contestant may view testing protocol:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->team_enable_rep_view, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_REP_VIEW, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(team_enable_ce_view, "d"),
    if (!global->team_enable_rep_view) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<tr%s><td>Contestant may view compilation errors:</td><td>",
              form_row_attrs[row ^= 1]);
      html_boolean_select(f, global->team_enable_ce_view, "param", 0, 0);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_CE_VIEW, "Change");
      fprintf(f, "</td></tr></form>\n");
    }

    //GLOBAL_PARAM(team_show_judge_report, "d"),
    if (global->team_enable_rep_view) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<tr%s><td>Contestant may view FULL (judge's) testing protocol:</td><td>", form_row_attrs[row ^= 1]);
      html_boolean_select(f, global->team_show_judge_report, "param", 0, 0);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_JUDGE_REPORT, "Change");
      fprintf(f, "</td></tr></form>\n");
    }

    //GLOBAL_PARAM(report_error_code, "d"),
    if (global->team_enable_rep_view && !global->team_show_judge_report) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<tr%s><td>Process exit code is shown in testing report:</td><td>", form_row_attrs[row ^= 1]);
      html_boolean_select(f, global->report_error_code, "param", 0, 0);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_REPORT_ERROR_CODE, "Change");
      fprintf(f, "</td></tr></form>\n");
    }
    
    //GLOBAL_PARAM(disable_clars, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Clarification requests are disabled completely:</td><td>", form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->disable_clars, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_DISABLE_CLARS, "Change");
    fprintf(f, "</td></tr></form>\n");
    
    //GLOBAL_PARAM(disable_team_clars, "d"),
    if (!global->disable_clars) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<tr%s><td>Contestant cannot write clarification request:</td><td>", form_row_attrs[row ^= 1]);
      html_boolean_select(f, global->disable_team_clars, "param", 0, 0);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_DISABLE_TEAM_CLARS, "Change");
      fprintf(f, "</td></tr></form>\n");
    }

    //GLOBAL_PARAM(disable_submit_after_ok, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Disable submit of already solved problems:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->disable_submit_after_ok, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_DISABLE_SUBMIT_AFTER_OK, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(ignore_compile_errors, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Compilation errors are not counted as failed runs:</td><td>", form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->ignore_compile_errors, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_IGNORE_COMPILE_ERRORS, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(ignore_duplicated_runs, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Identical submits of one contestant are ignored:</td><td>", form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->ignore_duplicated_runs, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_IGNORE_DUPICATED_RUNS, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(show_deadline, "d"),
    if (!global->contest_time) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<tr%s><td>Show submit deadline in problem selection menu:</td><td>", form_row_attrs[row ^= 1]);
      html_boolean_select(f, global->show_deadline, "param", 0, 0);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_SHOW_DEADLINE, "Change");
      fprintf(f, "</td></tr></form>\n");
    }
    
    //GLOBAL_PARAM(enable_printing, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Contestant may print his submit:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->enable_printing, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_ENABLE_PRINTING, "Change");
    fprintf(f, "</td></tr></form>\n");

    if (global->enable_printing > 0) {
      //GLOBAL_PARAM(disable_banner_page, "d"),
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<tr%s><td>Disable separate banner page:</td><td>",
              form_row_attrs[row ^= 1]);
      html_boolean_select(f, global->disable_banner_page, "param", 0, 0);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_DISABLE_BANNER_PAGE, "Change");
      fprintf(f, "</td></tr></form>\n");
    }

    //GLOBAL_PARAM(prune_empty_users, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Do not show contestants, which did not make any submit, in standings:</td><td>", form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->prune_empty_users, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_PRUNE_EMPTY_USERS, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(enable_full_archive, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Store full contestant's program output in the archive:</td><td>", form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->enable_full_archive, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_ENABLE_FULL_ARCHIVE, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(always_show_problems, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Contestant may view Problems link before start:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->always_show_problems, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_ALWAYS_SHOW_PROBLEMS, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(disable_user_standings, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Disable build-in standings in new-client:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->disable_user_standings, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_DISABLE_USER_STANDINGS, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(disable_language, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Disable language column in new-client:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->disable_language, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_DISABLE_LANGUAGE, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(problem_navigation, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Advanced problem navigation:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->problem_navigation, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_PROBLEM_NAVIGATION, "Change");
    fprintf(f, "</td></tr></form>\n");

    if (global->problem_navigation) {
      //GLOBAL_PARAM(vertical_navigation, "d"),
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<tr%s><td>Place problem navigation vertically:</td><td>",
              form_row_attrs[row ^= 1]);
      html_boolean_select(f, global->vertical_navigation, "param", 0, 0);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_VERTICAL_NAVIGATION,"Change");
      fprintf(f, "</td></tr></form>\n");
    }

    if (global->is_virtual) {
      //GLOBAL_PARAM(disable_virtual_start, "d"),
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<tr%s><td>Disable user Virtual start button:</td><td>",
              form_row_attrs[row ^= 1]);
      html_boolean_select(f, global->disable_virtual_start, "param", 0, 0);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_DISABLE_VIRTUAL_START, "Change");
      fprintf(f, "</td></tr></form>\n");
    }

    //GLOBAL_PARAM(disable_virtual_auto_judge, "d"),
    if (global->score_system_val == SCORE_OLYMPIAD) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<tr%s><td>Disable auto-judging after virtual olympiad:</td><td>",
              form_row_attrs[row ^= 1]);
      html_boolean_select(f, global->disable_virtual_auto_judge, "param", 0, 0);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_DISABLE_VIRTUAL_AUTO_JUDGE, "Change");
      fprintf(f, "</td></tr></form>\n");
    }

    //GLOBAL_PARAM(enable_auto_print_protocol, "d"),
    if (global->score_system_val == SCORE_OLYMPIAD) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<tr%s><td>Enable automatic protocol printing:</td><td>",
              form_row_attrs[row ^= 1]);
      html_boolean_select(f, global->enable_auto_print_protocol, "param", 0, 0);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_ENABLE_AUTO_PRINT_PROTOCOL, "Change");
      fprintf(f, "</td></tr></form>\n");
    }
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Files and directories</b>", head_row_attr);
  row = 1;
  if (sstate->show_global_2) {
    html_submit_button(f, SSERV_CMD_GLOB_HIDE_2, "Hide");
  } else {
    html_submit_button(f, SSERV_CMD_GLOB_SHOW_2, "Show");
  }
  fprintf(f, "</td></tr></form>");

  if (sstate->show_global_2) {
    //GLOBAL_PARAM(test_dir, "s"),
    print_string_editing_row(f, "Directory for tests (relative to contest configuration dir):", global->test_dir,
                             SSERV_CMD_GLOB_CHANGE_TEST_DIR,
                             SSERV_CMD_GLOB_CLEAR_TEST_DIR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(corr_dir, "s"),
    print_string_editing_row(f, "Directory for correct answers (relative to contest configuration dir):", global->corr_dir,
                             SSERV_CMD_GLOB_CHANGE_CORR_DIR,
                             SSERV_CMD_GLOB_CLEAR_CORR_DIR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(info_dir, "s"),
    print_string_editing_row(f, "Directory for test info files (relative to contest configuration dir):", global->info_dir,
                             SSERV_CMD_GLOB_CHANGE_INFO_DIR,
                             SSERV_CMD_GLOB_CLEAR_INFO_DIR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(tgz_dir, "s"),
    print_string_editing_row(f, "Directory for test tgz files (relative to contest configuration dir):", global->tgz_dir,
                             SSERV_CMD_GLOB_CHANGE_TGZ_DIR,
                             SSERV_CMD_GLOB_CLEAR_TGZ_DIR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(checker_dir, "s"),
    print_string_editing_row(f, "Directory for checkers (relative to contest configuration dir):", global->checker_dir,
                             SSERV_CMD_GLOB_CHANGE_CHECKER_DIR,
                             SSERV_CMD_GLOB_CLEAR_CHECKER_DIR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(statement_dir, "s"),
    print_string_editing_row(f, "Directory for problem statements (relative to contest configuration dir):", global->statement_dir,
                             SSERV_CMD_GLOB_CHANGE_STATEMENT_DIR,
                             SSERV_CMD_GLOB_CLEAR_STATEMENT_DIR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(plugin_dir, "s"),
    print_string_editing_row(f, "Directory for problem plugins (relative to contest configuration dir):", global->plugin_dir,
                             SSERV_CMD_GLOB_CHANGE_PLUGIN_DIR,
                             SSERV_CMD_GLOB_CLEAR_PLUGIN_DIR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(contest_start_cmd, "s"),
    print_string_editing_row(f, "Contest start script:", global->contest_start_cmd,
                             SSERV_CMD_GLOB_CHANGE_CONTEST_START_CMD,
                             SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD,
                             SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(description_file, "s"),
    print_string_editing_row(f, "Contest description file:",
                             global->description_file,
                             SSERV_CMD_GLOB_CHANGE_DESCRIPTION_FILE,
                             SSERV_CMD_GLOB_CLEAR_DESCRIPTION_FILE,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Contestant's quotas</b>", head_row_attr);
  row = 1;
  if (sstate->show_global_3) {
    html_submit_button(f, SSERV_CMD_GLOB_HIDE_3, "Hide");
  } else {
    html_submit_button(f, SSERV_CMD_GLOB_SHOW_3, "Show");
  }
  fprintf(f, "</td></tr></form>");

  if (sstate->show_global_3) {
    //GLOBAL_PARAM(max_run_size, "d"),
    print_string_editing_row(f, "Maximum size of one submitted program:",
                             num_to_size(hbuf, sizeof(hbuf), global->max_run_size),
                             SSERV_CMD_GLOB_CHANGE_MAX_RUN_SIZE,
                             0,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(max_run_total, "d"),
    print_string_editing_row(f, "Maximum total size of all submitted programs:",
                             num_to_size(hbuf, sizeof(hbuf), global->max_run_total),
                             SSERV_CMD_GLOB_CHANGE_MAX_RUN_TOTAL,
                             0,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(max_run_num, "d"),
    snprintf(hbuf, sizeof(hbuf), "%d", global->max_run_num);
    print_string_editing_row(f, "Maximum number of submits:",
                             hbuf,
                             SSERV_CMD_GLOB_CHANGE_MAX_RUN_NUM,
                             0,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    if (!global->disable_clars && !global->disable_team_clars) {
      //GLOBAL_PARAM(max_clar_size, "d"),
      print_string_editing_row(f, "Maximum size of one clarification request:",
                               num_to_size(hbuf, sizeof(hbuf), global->max_clar_size),
                               SSERV_CMD_GLOB_CHANGE_MAX_CLAR_SIZE,
                               0,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);

      //GLOBAL_PARAM(max_clar_total, "d"),
      print_string_editing_row(f, "Maximum total size of all clarification requests:",
                               num_to_size(hbuf, sizeof(hbuf), global->max_clar_total),
                               SSERV_CMD_GLOB_CHANGE_MAX_CLAR_TOTAL,
                               0,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);

      //GLOBAL_PARAM(max_clar_num, "d"),
      snprintf(hbuf, sizeof(hbuf), "%d", global->max_clar_num);
      print_string_editing_row(f, "Maximum number of clarification requests:",
                               hbuf,
                               SSERV_CMD_GLOB_CHANGE_MAX_CLAR_NUM,
                               0,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);
    }

    if (global->enable_printing) {
      //GLOBAL_PARAM(team_page_quota, "d"),
      snprintf(hbuf, sizeof(hbuf), "%d", global->team_page_quota);
      print_string_editing_row(f, "Maximum number of printed pages:",
                               hbuf,
                               SSERV_CMD_GLOB_CHANGE_TEAM_PAGE_QUOTA,
                               0,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);
    }
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Standings files and URLs:</b>", head_row_attr);
  row = 1;
  if (sstate->show_global_4) {
    html_submit_button(f, SSERV_CMD_GLOB_HIDE_4, "Hide");
  } else {
    html_submit_button(f, SSERV_CMD_GLOB_SHOW_4, "Show");
  }
  fprintf(f, "</td></tr></form>");

  if (sstate->show_global_4) {
    //GLOBAL_PARAM(team_info_url, "s"),
    print_string_editing_row(f, "URL to view detailed contestant information:",
                             global->team_info_url,
                             SSERV_CMD_GLOB_CHANGE_TEAM_INFO_URL,
                             SSERV_CMD_GLOB_CLEAR_TEAM_INFO_URL,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(prob_info_url, "s"),
    print_string_editing_row(f, "URL to view problem statement:",
                             global->prob_info_url,
                             SSERV_CMD_GLOB_CHANGE_PROB_INFO_URL,
                             SSERV_CMD_GLOB_CLEAR_PROB_INFO_URL,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(standings_file_name, "s"),
    print_string_editing_row(f, "Name of the current standings file:",
                             global->standings_file_name,
                             SSERV_CMD_GLOB_CHANGE_STAND_FILE_NAME,
                             SSERV_CMD_GLOB_CLEAR_STAND_FILE_NAME,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(users_on_page, "d"),
    hbuf[0] = 0;
    if (global->users_on_page > 0)
      snprintf(hbuf, sizeof(hbuf), "%d", global->users_on_page);
    print_string_editing_row(f, "Number of users on standings page:",
                             hbuf,
                             SSERV_CMD_GLOB_CHANGE_USERS_ON_PAGE,
                             0,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(stand_header_file, "s"),
    print_string_editing_row(f, "HTML header file for the standings:",
                             global->stand_header_file,
                             SSERV_CMD_GLOB_CHANGE_STAND_HEADER_FILE,
                             SSERV_CMD_GLOB_CLEAR_STAND_HEADER_FILE,
                             SSERV_CMD_GLOB_EDIT_STAND_HEADER_FILE,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(stand_footer_file, "s"),
    print_string_editing_row(f, "HTML footer file for the standings:",
                             global->stand_footer_file,
                             SSERV_CMD_GLOB_CHANGE_STAND_FOOTER_FILE,
                             SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_FILE,
                             SSERV_CMD_GLOB_EDIT_STAND_FOOTER_FILE,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(stand_symlink_dir, "s"),
    print_string_editing_row(f, "Directory to make standings symlink (rel. to DocumentRoot):",
                             global->stand_symlink_dir,
                             SSERV_CMD_GLOB_CHANGE_STAND_SYMLINK_DIR,
                             SSERV_CMD_GLOB_CLEAR_STAND_SYMLINK_DIR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(stand_ignore_after, "s"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Ignore submissions after:</td><td>",
            form_row_attrs[row ^= 1]);
    html_date_select(f, global->stand_ignore_after_d);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_STAND_IGNORE_AFTER, "Change");
    html_submit_button(f, SSERV_CMD_GLOB_CLEAR_STAND_IGNORE_AFTER, "Clear");
    fprintf(f, "</td></tr></form>\n");

    // whether supplementary standings are enabled?
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Enable supplementary standings table:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, sstate->enable_stand2, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_ENABLE_STAND2, "Change");
    fprintf(f, "</td></tr></form>\n");

    if (sstate->enable_stand2) {
      //GLOBAL_PARAM(stand2_file_name, "s"),
      print_string_editing_row(f, "Name of the supplementary standings file:",
                               global->stand2_file_name,
                               SSERV_CMD_GLOB_CHANGE_STAND2_FILE_NAME,
                               SSERV_CMD_GLOB_CLEAR_STAND2_FILE_NAME,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);

    //GLOBAL_PARAM(stand2_header_file, "s"),
    print_string_editing_row(f, "HTML header file for the supplementary standings:",
                             global->stand2_header_file,
                             SSERV_CMD_GLOB_CHANGE_STAND2_HEADER_FILE,
                             SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_FILE,
                             SSERV_CMD_GLOB_EDIT_STAND2_HEADER_FILE,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(stand2_footer_file, "s"),
    print_string_editing_row(f, "HTML footer file for the supplementary standings:",
                             global->stand2_footer_file,
                             SSERV_CMD_GLOB_CHANGE_STAND2_FOOTER_FILE,
                             SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_FILE,
                             SSERV_CMD_GLOB_EDIT_STAND2_FOOTER_FILE,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(stand2_symlink_dir, "s"),
    print_string_editing_row(f, "Directory to make suppl. standings symlink (rel. to DocumentRoot):",
                             global->stand2_symlink_dir,
                             SSERV_CMD_GLOB_CHANGE_STAND2_SYMLINK_DIR,
                             SSERV_CMD_GLOB_CLEAR_STAND2_SYMLINK_DIR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    }

    // whether public submission log is enabled?
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Enable public submission log:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, sstate->enable_plog, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_ENABLE_PLOG, "Change");
    fprintf(f, "</td></tr></form>\n");

    if (sstate->enable_plog) {
      //GLOBAL_PARAM(plog_file_name, "s"),
      print_string_editing_row(f, "Name of the public submission log file:",
                               global->plog_file_name,
                               SSERV_CMD_GLOB_CHANGE_PLOG_FILE_NAME,
                               SSERV_CMD_GLOB_CLEAR_PLOG_FILE_NAME,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);

      //GLOBAL_PARAM(plog_header_file, "s"),
      print_string_editing_row(f, "HTML header file for the public submission log:",
                               global->plog_header_file,
                               SSERV_CMD_GLOB_CHANGE_PLOG_HEADER_FILE,
                               SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_FILE,
                               SSERV_CMD_GLOB_EDIT_PLOG_HEADER_FILE,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);

      //GLOBAL_PARAM(plog_footer_file, "s"),
      print_string_editing_row(f, "HTML footer file for the public submission log:",
                               global->plog_footer_file,
                               SSERV_CMD_GLOB_CHANGE_PLOG_FOOTER_FILE,
                               SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_FILE,
                               SSERV_CMD_GLOB_EDIT_PLOG_FOOTER_FILE,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);

      //GLOBAL_PARAM(plog_symlink_dir, "s"),
      print_string_editing_row(f, "Directory to make symlink to public submission log (rel. to DocumentRoot):",
                               global->plog_symlink_dir,
                               SSERV_CMD_GLOB_CHANGE_PLOG_SYMLINK_DIR,
                               SSERV_CMD_GLOB_CLEAR_PLOG_SYMLINK_DIR,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);

      //GLOBAL_PARAM(plog_update_time, "d"),
      snprintf(hbuf, sizeof(hbuf), "%d", global->plog_update_time);
      print_string_editing_row(f, "Public submission log update interval (sec):",
                               hbuf,
                               SSERV_CMD_GLOB_CHANGE_PLOG_UPDATE_TIME,
                               0,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);
    }

    //GLOBAL_PARAM(external_xml_update_time, "d"),
    snprintf(hbuf, sizeof(hbuf), "%d", global->external_xml_update_time);
    print_string_editing_row(f, "External XML log update interval (sec):",
                             hbuf,
                             SSERV_CMD_GLOB_CHANGE_EXTERNAL_XML_UPDATE_TIME,
                             0,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(internal_xml_update_time, "d"),
    snprintf(hbuf, sizeof(hbuf), "%d", global->internal_xml_update_time);
    print_string_editing_row(f, "Internal XML log update interval (sec):",
                             hbuf,
                             SSERV_CMD_GLOB_CHANGE_INTERNAL_XML_UPDATE_TIME,
                             0,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Standings table attributes</b>", head_row_attr);
  row = 1;
  if (sstate->show_global_5) {
    html_submit_button(f, SSERV_CMD_GLOB_HIDE_5, "Hide");
  } else {
    html_submit_button(f, SSERV_CMD_GLOB_SHOW_5, "Show");
  }
  fprintf(f, "</td></tr></form>");

  if (sstate->show_global_5) {
    //GLOBAL_PARAM(stand_fancy_style, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Use fancy decorations:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->stand_fancy_style, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_STAND_FANCY_STYLE, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(stand_success_attr, "s"),
    print_string_editing_row(f, "HTML attributes for \"Last success\" note:",
                             global->stand_success_attr,
                             SSERV_CMD_GLOB_CHANGE_STAND_SUCCESS_ATTR,
                             SSERV_CMD_GLOB_CLEAR_STAND_SUCCESS_ATTR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(stand_table_attr, "s"),
    print_string_editing_row(f, "HTML attributes for standings table:",
                             global->stand_table_attr,
                             SSERV_CMD_GLOB_CHANGE_STAND_TABLE_ATTR,
                             SSERV_CMD_GLOB_CLEAR_STAND_TABLE_ATTR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(stand_row_attr, "x"),
    if (!global->stand_row_attr || !global->stand_row_attr[0]) {
      xstr = xstrdup("");
    } else {
      xstr = sarray_unparse_2(global->stand_row_attr);
    }
    print_string_editing_row(f, "Standings row attributes:", xstr,
                             SSERV_CMD_GLOB_CHANGE_STAND_ROW_ATTR,
                             SSERV_CMD_GLOB_CLEAR_STAND_ROW_ATTR,
                             0,
                             session_id, form_row_attrs[row ^= 1],
                             self_url, extra_args, hidden_vars);
    xfree(xstr);

    //GLOBAL_PARAM(stand_place_attr, "s"),
    print_string_editing_row(f, "HTML attributes for the \"Place\" column:",
                             global->stand_place_attr,
                             SSERV_CMD_GLOB_CHANGE_STAND_PLACE_ATTR,
                             SSERV_CMD_GLOB_CLEAR_STAND_PLACE_ATTR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(stand_team_attr, "s"),
    print_string_editing_row(f, "HTML attributes for the \"Team name\" column:",
                             global->stand_team_attr,
                             SSERV_CMD_GLOB_CHANGE_STAND_TEAM_ATTR,
                             SSERV_CMD_GLOB_CLEAR_STAND_TEAM_ATTR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(stand_prob_attr, "s"),
    print_string_editing_row(f, "HTML attributes for the \"Problems\" columns:",
                             global->stand_prob_attr,
                             SSERV_CMD_GLOB_CHANGE_STAND_PROB_ATTR,
                             SSERV_CMD_GLOB_CLEAR_STAND_PROB_ATTR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(stand_solved_attr, "s"),
    print_string_editing_row(f, "HTML attributes for the \"Solved\" column:",
                             global->stand_solved_attr,
                             SSERV_CMD_GLOB_CHANGE_STAND_SOLVED_ATTR,
                             SSERV_CMD_GLOB_CLEAR_STAND_SOLVED_ATTR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    if (global->score_system_val == SCORE_KIROV
        || global->score_system_val == SCORE_OLYMPIAD) {
      //GLOBAL_PARAM(stand_score_attr, "s"),
      print_string_editing_row(f, "HTML attributes for the \"Score\" column:",
                               global->stand_score_attr,
                               SSERV_CMD_GLOB_CHANGE_STAND_SCORE_ATTR,
                               SSERV_CMD_GLOB_CLEAR_STAND_SCORE_ATTR,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);
    }

    if (global->score_system_val == SCORE_ACM
        || global->score_system_val == SCORE_MOSCOW) {
      //GLOBAL_PARAM(stand_penalty_attr, "s"),
      print_string_editing_row(f, "HTML attributes for the \"Penalty\" column:",
                               global->stand_penalty_attr,
                               SSERV_CMD_GLOB_CHANGE_STAND_PENALTY_ATTR,
                               SSERV_CMD_GLOB_CLEAR_STAND_PENALTY_ATTR,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);
    }

    //GLOBAL_PARAM(stand_use_login, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Use login instead of name:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->stand_use_login, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_STAND_USE_LOGIN, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(stand_show_ok_time, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Show success time in standings:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->stand_show_ok_time, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_STAND_SHOW_OK_TIME, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(stand_show_att_num, "d"),
    if (global->score_system_val == SCORE_KIROV
        || global->score_system_val == SCORE_OLYMPIAD) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<tr%s><td>Show number of attempts in standings:</td><td>",
              form_row_attrs[row ^= 1]);
      html_boolean_select(f, global->stand_show_att_num, "param", 0, 0);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_STAND_SHOW_ATT_NUM, "Change");
      fprintf(f, "</td></tr></form>\n");
    }

    //GLOBAL_PARAM(stand_sort_by_solved, "d"),
    if (global->score_system_val == SCORE_KIROV
        || global->score_system_val == SCORE_OLYMPIAD) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<tr%s><td>Sort participants by the solved problems first:</td><td>", form_row_attrs[row ^= 1]);
      html_boolean_select(f, global->stand_sort_by_solved, "param", 0, 0);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_STAND_SORT_BY_SOLVED, "Change");
      fprintf(f, "</td></tr></form>\n");
    }

    //GLOBAL_PARAM(stand_collate_name, "d"),
    if (global->score_system_val == SCORE_KIROV
        || global->score_system_val == SCORE_OLYMPIAD) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<tr%s><td>Collate standings on user name:</td><td>",
              form_row_attrs[row ^= 1]);
      html_boolean_select(f, global->stand_collate_name, "param", 0, 0);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_STAND_COLLATE_NAME, "Change");
      fprintf(f, "</td></tr></form>\n");
    }

    //GLOBAL_PARAM(stand_enable_penalty, "d"),
    if (global->score_system_val == SCORE_KIROV
        || global->score_system_val == SCORE_OLYMPIAD) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<tr%s><td>Enable time penalties:</td><td>",
              form_row_attrs[row ^= 1]);
      html_boolean_select(f, global->stand_enable_penalty, "param", 0, 0);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_STAND_ENABLE_PENALTY, "Change");
      fprintf(f, "</td></tr></form>\n");
    }

    //GLOBAL_PARAM(ignore_success_time, "d"),
    if (global->score_system_val == SCORE_ACM
        || global->score_system_val == SCORE_MOSCOW) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<tr%s><td>Ignore success time in penalty calculation:</td><td>", form_row_attrs[row ^= 1]);
      html_boolean_select(f, global->ignore_success_time, "param", 0, 0);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_IGNORE_SUCCESS_TIME, "Change");
      fprintf(f, "</td></tr></form>\n");
    }

    if (global->stand_show_ok_time) {
      //GLOBAL_PARAM(stand_time_attr, "s"),
      print_string_editing_row(f, "HTML attributes for the success time:",
                               global->stand_time_attr,
                               SSERV_CMD_GLOB_CHANGE_STAND_TIME_ATTR,
                               SSERV_CMD_GLOB_CLEAR_STAND_TIME_ATTR,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);
    }

    //GLOBAL_PARAM(stand_fail_attr, "s"),
    print_string_editing_row(f, "HTML attributes for \"Check failed\" cells:",
                             global->stand_fail_attr,
                             SSERV_CMD_GLOB_CHANGE_STAND_FAIL_ATTR,
                             SSERV_CMD_GLOB_CLEAR_STAND_FAIL_ATTR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(stand_trans_attr, "s"),
    print_string_editing_row(f, "HTML attributes for transient cells:",
                             global->stand_trans_attr,
                             SSERV_CMD_GLOB_CHANGE_STAND_TRANS_ATTR,
                             SSERV_CMD_GLOB_CLEAR_STAND_TRANS_ATTR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(stand_disq_attr, "s"),
    print_string_editing_row(f, "HTML attributes for \"Disqualified\" cells:",
                             global->stand_disq_attr,
                             SSERV_CMD_GLOB_CHANGE_STAND_DISQ_ATTR,
                             SSERV_CMD_GLOB_CLEAR_STAND_DISQ_ATTR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    if (global->is_virtual) {
      //GLOBAL_PARAM(stand_self_row_attr, "s"),
      print_string_editing_row(f, "HTML attributes for the participant's table row:",
                               global->stand_self_row_attr,
                               SSERV_CMD_GLOB_CHANGE_STAND_SELF_ROW_ATTR,
                               SSERV_CMD_GLOB_CLEAR_STAND_SELF_ROW_ATTR,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);

      //GLOBAL_PARAM(stand_v_row_attr, "s"),
      print_string_editing_row(f, "HTML attributes for the virtual participant's rows:",
                               global->stand_v_row_attr,
                               SSERV_CMD_GLOB_CHANGE_STAND_V_ROW_ATTR,
                               SSERV_CMD_GLOB_CLEAR_STAND_V_ROW_ATTR,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);

      //GLOBAL_PARAM(stand_r_row_attr, "s"),
      print_string_editing_row(f, "HTML attributes for the real participant's rows:",
                               global->stand_r_row_attr,
                               SSERV_CMD_GLOB_CHANGE_STAND_R_ROW_ATTR,
                               SSERV_CMD_GLOB_CLEAR_STAND_R_ROW_ATTR,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);

      //GLOBAL_PARAM(stand_u_row_attr, "s"),
      print_string_editing_row(f, "HTML attributes for the unknown participant's rows:",
                               global->stand_u_row_attr,
                               SSERV_CMD_GLOB_CHANGE_STAND_U_ROW_ATTR,
                               SSERV_CMD_GLOB_CLEAR_STAND_U_ROW_ATTR,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);
    }
    
    //enable "Extra" column
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Show \"Extra information\" column:</td><td>", form_row_attrs[row ^= 1]);
    html_boolean_select(f, sstate->enable_extra_col, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_ENABLE_EXTRA_COL, "Change");
    fprintf(f, "</td></tr></form>\n");

    if (sstate->enable_extra_col) {
      //GLOBAL_PARAM(stand_extra_format, "s"),
      print_string_editing_row(f, "Format string for \"Extra information\" column:",
                               global->stand_extra_format,
                               SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_FORMAT,
                               SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_FORMAT,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);

      //GLOBAL_PARAM(stand_extra_legend, "s"),
      print_string_editing_row(f, "Column title for \"Extra information\" column:",
                               global->stand_extra_legend,
                               SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_LEGEND,
                               SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_LEGEND,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);

      //GLOBAL_PARAM(stand_extra_attr, "s"),
      print_string_editing_row(f, "HTML attributes for \"Extra information\" column:",
                               global->stand_extra_attr,
                               SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_ATTR,
                               SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_ATTR,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);
    }

    //GLOBAL_PARAM(stand_show_warn_number, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Show \"Warnings\" column:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->stand_show_warn_number, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_STAND_SHOW_WARN_NUMBER, "Change");
    fprintf(f, "</td></tr></form>\n");

    if (global->stand_show_warn_number) {
      //GLOBAL_PARAM(stand_warn_number_attr, "s"),
      print_string_editing_row(f, "HTML attributes for the \"Warnings\" column:",
                               global->stand_warn_number_attr,
                               SSERV_CMD_GLOB_CHANGE_STAND_WARN_NUMBER_ATTR,
                               SSERV_CMD_GLOB_CLEAR_STAND_WARN_NUMBER_ATTR,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);
    }

    if (global->users_on_page > 0) {
      //GLOBAL_PARAM(stand_page_table_attr, "s"),
      print_string_editing_row(f, "HTML attributes for page table:",
                               global->stand_page_table_attr,
                               SSERV_CMD_GLOB_CHANGE_STAND_PAGE_TABLE_ATTR,
                               SSERV_CMD_GLOB_CLEAR_STAND_PAGE_TABLE_ATTR,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);

      //GLOBAL_PARAM(stand_page_cur_attr, "s"),
      print_string_editing_row(f, "HTML attributes for current page message:",
                               global->stand_page_cur_attr,
                               SSERV_CMD_GLOB_CHANGE_STAND_PAGE_CUR_ATTR,
                               SSERV_CMD_GLOB_CLEAR_STAND_PAGE_CUR_ATTR,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);

      //GLOBAL_PARAM(stand_page_row_attr, "x"),
      if (!global->stand_page_row_attr || !global->stand_page_row_attr[0]) {
        xstr = xstrdup("");
      } else {
        xstr = sarray_unparse_2(global->stand_page_row_attr);
      }
      print_string_editing_row(f, "Page table row attributes:", xstr,
                               SSERV_CMD_GLOB_CHANGE_STAND_PAGE_ROW_ATTR,
                               SSERV_CMD_GLOB_CLEAR_STAND_PAGE_ROW_ATTR,
                               0,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, hidden_vars);
      xfree(xstr);

      //GLOBAL_PARAM(stand_page_col_attr, "x"),
      if (!global->stand_page_col_attr || !global->stand_page_col_attr[0]) {
        xstr = xstrdup("");
      } else {
        xstr = sarray_unparse_2(global->stand_page_col_attr);
      }
      print_string_editing_row(f, "Page table column attributes:", xstr,
                               SSERV_CMD_GLOB_CHANGE_STAND_PAGE_COL_ATTR,
                               SSERV_CMD_GLOB_CLEAR_STAND_PAGE_COL_ATTR,
                               0,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, hidden_vars);
      xfree(xstr);
    }
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Advanced settings</b>", head_row_attr);
  row = 1;
  if (sstate->show_global_6) {
    html_submit_button(f, SSERV_CMD_GLOB_HIDE_6, "Hide");
  } else {
    html_submit_button(f, SSERV_CMD_GLOB_SHOW_6, "Show");
  }
  fprintf(f, "</td></tr></form>");

  if (sstate->show_global_6) {
    //GLOBAL_PARAM(appeal_deadline, "s"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Appeal deadline:</td><td>",
            form_row_attrs[row ^= 1]);
    html_date_select(f, global->appeal_deadline_d);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_APPEAL_DEADLINE, "Change");
    html_submit_button(f, SSERV_CMD_GLOB_CLEAR_APPEAL_DEADLINE, "Clear");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(sleep_time, "d"),
    snprintf(hbuf, sizeof(hbuf), "%d", global->sleep_time);
    print_string_editing_row(f, "`compile', `run' sleep time (ms):",
                             hbuf,
                             SSERV_CMD_GLOB_CHANGE_SLEEP_TIME,
                             0,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(serve_sleep_time, "d"),
    snprintf(hbuf, sizeof(hbuf), "%d", global->serve_sleep_time);
    print_string_editing_row(f, "`serve' sleep time (ms):",
                             hbuf,
                             SSERV_CMD_GLOB_CHANGE_SERVE_SLEEP_TIME,
                             0,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(autoupdate_standings, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Update standings automatically (except freeze time):</td><td>", form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->autoupdate_standings, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_AUTOUPDATE_STANDINGS, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(rounding_mode, "s"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Seconds to minutes rounding mode:</td><td>",
            form_row_attrs[row ^= 1]);
    html_select(f, global->rounding_mode_val, "param", rounding_modes);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_ROUNDING_MODE, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(max_file_length, "d"),
    print_string_editing_row(f, "Maximal file size to be included into testing protocol:",
                             num_to_size(hbuf, sizeof(hbuf), global->max_file_length),
                             SSERV_CMD_GLOB_CHANGE_MAX_FILE_LENGTH,
                             0,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(max_line_length, "d"),
    print_string_editing_row(f, "Maximal line length to be included into testing protocol:",
                             num_to_size(hbuf, sizeof(hbuf), global->max_line_length),
                             SSERV_CMD_GLOB_CHANGE_MAX_LINE_LENGTH,
                             0,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(inactivity_timeout, "d"),
    snprintf(hbuf, sizeof(hbuf), "%d", global->inactivity_timeout);
    print_string_editing_row(f, "Inactivity timeout for `serve' and `run' (sec)",
                             hbuf,
                             SSERV_CMD_GLOB_CHANGE_INACTIVITY_TIMEOUT,
                             0,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(disable_testing, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Disable any testing of submissions:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->disable_testing, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_DISABLE_TESTING, "Change");
    fprintf(f, "</td></tr></form>\n");

    if (!global->disable_testing) {
      //GLOBAL_PARAM(disable_auto_testing, "d"),
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<tr%s><td>Disable automatic testing of submissions:</td><td>", form_row_attrs[row ^= 1]);
      html_boolean_select(f, global->disable_auto_testing, "param", 0, 0);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_DISABLE_AUTO_TESTING, "Change");
      fprintf(f, "</td></tr></form>\n");
    }

    //GLOBAL_PARAM(cr_serialization_key, "d"),
    snprintf(hbuf, sizeof(hbuf), "%d", global->cr_serialization_key);
    print_string_editing_row(f, "Serialization semaphore for `compile' and `run'",
                             hbuf,
                             SSERV_CMD_GLOB_CHANGE_CR_SERIALIZATION_KEY,
                             0,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(show_astr_time, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Show astronomic time instead of relative time:</td><td>", form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->show_astr_time, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_SHOW_ASTR_TIME, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(enable_continue, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Enable contest continuation:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->enable_continue, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_ENABLE_CONTINUE, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(enable_report_upload, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Enable testing protocol upload:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->enable_report_upload, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_ENABLE_REPORT_UPLOAD, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(enable_runlog_merge, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Enable run database importing and merging:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->enable_runlog_merge, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_ENABLE_RUNLOG_MERGE, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(enable_l10n, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Enable message translation:</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, global->enable_l10n, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_ENABLE_L10N, "Change");
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(charset, "s"),
    print_string_editing_row(f, "Character set:",
                             global->charset,
                             SSERV_CMD_GLOB_CHANGE_CHARSET,
                             SSERV_CMD_GLOB_CLEAR_CHARSET,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    //GLOBAL_PARAM(team_download_time, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Team archive download interval (HH:MM:SS):</td>",
            form_row_attrs[row ^= 1]);
    if (!global->team_download_time) {
      fprintf(f, "<td><input type=\"text\" name=\"param\" value=\"0\" size=\"8\"/><i>(Disabled)</i></td><td>");
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_TEAM_DOWNLOAD_TIME, "Change");
    } else {
      fprintf(f, "<td><input type=\"text\" name=\"param\" value=\"%d:%02d:%02d\" size=\"8\"/></td><td>",
              global->team_download_time / 3600,
              (global->team_download_time / 60) % 60,
              global->team_download_time % 60);
      html_submit_button(f, SSERV_CMD_GLOB_CHANGE_TEAM_DOWNLOAD_TIME, "Change");
      html_submit_button(f, SSERV_CMD_GLOB_DISABLE_TEAM_DOWNLOAD_TIME, "Disable");
    }
    fprintf(f, "</td></tr></form>\n");

    //GLOBAL_PARAM(cpu_bogomips, "d"),
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>CPU speed (BogoMIPS):</td>",
            form_row_attrs[row ^= 1]);
    if (global->cpu_bogomips <= 0) {
      fprintf(f, "<td><input type=\"text\" name=\"param\" value=\"0\" size=\"8\"/><i>(Unknown)</i></td><td>");
    } else {
      fprintf(f, "<td><input type=\"text\" name=\"param\" value=\"%d\" size=\"8\"/></td><td>", global->cpu_bogomips);
    }
    html_submit_button(f, SSERV_CMD_GLOB_CHANGE_CPU_BOGOMIPS, "Change");
    html_submit_button(f, SSERV_CMD_GLOB_DETECT_CPU_BOGOMIPS, "Detect");
    fprintf(f, "</td></tr></form>\n");
  }

  if (global->unhandled_vars) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Uneditable parameters</b>", head_row_attr);
    row = 1;
    if (sstate->show_global_7) {
      html_submit_button(f, SSERV_CMD_GLOB_HIDE_7, "Hide");
    } else {
      html_submit_button(f, SSERV_CMD_GLOB_SHOW_7, "Show");
    }
    fprintf(f, "</td></tr></form>\n");
    if (sstate->show_global_7) {
      s = html_armor_string_dup(global->unhandled_vars);
      fprintf(f, "<tr%s><td colspan=\"3\"><pre>%s</pre></td></tr>\n", form_row_attrs[row ^= 1], s);
      xfree(s);
    }
  }

  fprintf(f, "</table>\n");

  super_html_contest_footer_menu(f, session_id, sstate,
                                 self_url, hidden_vars, extra_args);

  return 0;
}

#define GLOB_SET_STRING(f) p_str = global->f; str_size = sizeof(global->f); goto handle_string
#define GLOB_CLEAR_STRING(f) global->f[0] = 0; return 0

int
super_html_global_param(struct sid_state *sstate, int cmd,
                        const struct ejudge_cfg *config,
                        int param1, const unsigned char *param2,
                        int param3, int param4)
{
  struct section_global_data *global = sstate->global;
  int hh, mm, n, val, default_val;
  unsigned char *s;
  int *p_int;
  unsigned char *p_str;
  size_t str_size;
  unsigned char **pp_str;
  char **tmp_env = 0;

  if (!global) return -SSERV_ERR_CONTEST_NOT_EDITED;

  switch (cmd) {
  case SSERV_CMD_GLOB_CHANGE_DURATION:
    if (sscanf(param2, "%d:%d%n", &hh, &mm, &n) == 2 && !param2[n]) {
      if (hh < 0 || hh >= 1000000) return -SSERV_ERR_INVALID_PARAMETER;
      if (mm < 0 || mm >= 60) return -SSERV_ERR_INVALID_PARAMETER;
      global->contest_time = hh * 60 + mm;
      return 0;
    }
    if (sscanf(param2, "%d%n", &mm, &n) != 1 || param2[n] ||
        mm < 0 || mm >= 1000000)
      return -SSERV_ERR_INVALID_PARAMETER;
    global->contest_time = mm;
    if (global->contest_time > global->board_fog_time)
      global->board_fog_time = global->contest_time;
    if (!global->contest_time) global->board_unfog_time = 0;
    return 0;

  case SSERV_CMD_GLOB_UNLIMITED_DURATION:
    global->contest_time = 0;
    global->board_fog_time = 0;
    global->board_unfog_time = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_TYPE:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n]
        || val < 0 || val > SCORE_TOTAL + 2)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (val < SCORE_TOTAL) {
      global->score_system_val = val;
      global->is_virtual = 0;
    } else {
      if (val == SCORE_TOTAL) global->score_system_val = SCORE_ACM;
      else global->score_system_val = SCORE_OLYMPIAD;
      global->is_virtual = 1;
    }
    return 0;

  case SSERV_CMD_GLOB_CHANGE_FOG_TIME:
    if (sscanf(param2, "%d:%d%n", &hh, &mm, &n) == 2 && !param2[n]) {
      if (hh < 0 || hh >= 1000000) return -SSERV_ERR_INVALID_PARAMETER;
      if (mm < 0 || mm >= 60) return -SSERV_ERR_INVALID_PARAMETER;
      mm = hh * 60 + mm;
    } else if (sscanf(param2, "%d%n", &mm, &n) != 1 || param2[n] ||
               mm < 0 || mm >= 1000000) {
      return -SSERV_ERR_INVALID_PARAMETER;
    }
    if (mm > global->contest_time) mm = global->contest_time;
    global->board_fog_time = mm;
    if (!global->board_fog_time) global->board_unfog_time = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_UNFOG_TIME:
    if (sscanf(param2, "%d:%d%n", &hh, &mm, &n) == 2 && !param2[n]) {
      if (hh < 0 || hh >= 1000000) return -SSERV_ERR_INVALID_PARAMETER;
      if (mm < 0 || mm >= 60) return -SSERV_ERR_INVALID_PARAMETER;
      mm = hh * 60 + mm;
    } else if (sscanf(param2, "%d%n", &mm, &n) != 1 || param2[n] ||
               mm < 0 || mm >= 1000000) {
      return -SSERV_ERR_INVALID_PARAMETER;
    }
    if (!global->contest_time) mm = 0;
    if (!global->board_fog_time) mm = 0;
    global->board_unfog_time = mm;
    return 0;

  case SSERV_CMD_GLOB_DISABLE_FOG:
    global->board_fog_time = 0;
    global->board_unfog_time = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_STAND_LOCALE:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n]
        || val < 0 || val > 1) return -SSERV_ERR_INVALID_PARAMETER;
    switch (val) {
    case 0: s = "en"; break;
    case 1: s = "ru"; break;
    default:
      abort();
    }
    snprintf(global->standings_locale, sizeof(global->standings_locale), "%s", s);
    return 0;

  case SSERV_CMD_GLOB_CHANGE_SRC_VIEW:
    p_int = &global->team_enable_src_view;

  handle_boolean:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n] || val < 0 || val > 1)
      return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_REP_VIEW:
    p_int = &global->team_enable_rep_view;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_CE_VIEW:
    p_int = &global->team_enable_ce_view;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_JUDGE_REPORT:
    p_int = &global->team_show_judge_report;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_CLARS:
    p_int = &global->disable_clars;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_TEAM_CLARS:
    p_int = &global->disable_team_clars;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_SUBMIT_AFTER_OK:
    p_int = &global->disable_submit_after_ok;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_IGNORE_COMPILE_ERRORS:
    p_int = &global->ignore_compile_errors;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_FAILED_TEST_VIEW:
    p_int = &global->disable_failed_test_view;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_IGNORE_DUPICATED_RUNS:
    p_int = &global->ignore_duplicated_runs;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_REPORT_ERROR_CODE:
    p_int = &global->report_error_code;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_SHOW_DEADLINE:
    p_int = &global->show_deadline;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_PRINTING:
    p_int = &global->enable_printing;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_BANNER_PAGE:
    p_int = &global->disable_banner_page;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_PRUNE_EMPTY_USERS:
    p_int = &global->prune_empty_users;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_FULL_ARCHIVE:
    p_int = &global->enable_full_archive;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ALWAYS_SHOW_PROBLEMS:
    p_int = &global->always_show_problems;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_USER_STANDINGS:
    p_int = &global->disable_user_standings;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_LANGUAGE:
    p_int = &global->disable_language;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_PROBLEM_NAVIGATION:
    p_int = &global->problem_navigation;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_VERTICAL_NAVIGATION:
    p_int = &global->vertical_navigation;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_VIRTUAL_START:
    p_int = &global->disable_virtual_start;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_VIRTUAL_AUTO_JUDGE:
    p_int = &global->disable_virtual_auto_judge;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_AUTO_PRINT_PROTOCOL:
    p_int = &global->enable_auto_print_protocol;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_TEST_DIR:
    GLOB_SET_STRING(test_dir);

  handle_string:
    snprintf(p_str, str_size, "%s", param2);
    return 0;
    
  case SSERV_CMD_GLOB_CLEAR_TEST_DIR:
    GLOB_CLEAR_STRING(test_dir);

  case SSERV_CMD_GLOB_CHANGE_CORR_DIR:
    GLOB_SET_STRING(corr_dir);

  case SSERV_CMD_GLOB_CLEAR_CORR_DIR:
    GLOB_CLEAR_STRING(corr_dir);

  case SSERV_CMD_GLOB_CHANGE_INFO_DIR:
    GLOB_SET_STRING(info_dir);

  case SSERV_CMD_GLOB_CLEAR_INFO_DIR: 
    GLOB_CLEAR_STRING(info_dir);

  case SSERV_CMD_GLOB_CHANGE_TGZ_DIR:
    GLOB_SET_STRING(tgz_dir);

  case SSERV_CMD_GLOB_CLEAR_TGZ_DIR: 
    GLOB_CLEAR_STRING(tgz_dir);

  case SSERV_CMD_GLOB_CHANGE_CHECKER_DIR:
    GLOB_SET_STRING(checker_dir);

  case SSERV_CMD_GLOB_CLEAR_CHECKER_DIR:
    GLOB_CLEAR_STRING(checker_dir);

  case SSERV_CMD_GLOB_CHANGE_STATEMENT_DIR:
    GLOB_SET_STRING(statement_dir);

  case SSERV_CMD_GLOB_CLEAR_STATEMENT_DIR:
    GLOB_CLEAR_STRING(statement_dir);

  case SSERV_CMD_GLOB_CHANGE_PLUGIN_DIR:
    GLOB_SET_STRING(plugin_dir);

  case SSERV_CMD_GLOB_CLEAR_PLUGIN_DIR:
    GLOB_CLEAR_STRING(plugin_dir);

  case SSERV_CMD_GLOB_CHANGE_DESCRIPTION_FILE:
    GLOB_SET_STRING(description_file);

  case SSERV_CMD_GLOB_CLEAR_DESCRIPTION_FILE:
    GLOB_CLEAR_STRING(description_file);

  case SSERV_CMD_GLOB_CHANGE_CONTEST_START_CMD:
    GLOB_SET_STRING(contest_start_cmd);

  case SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD:
    GLOB_CLEAR_STRING(contest_start_cmd);

  case SSERV_CMD_GLOB_CHANGE_MAX_RUN_SIZE:
    p_int = &global->max_run_size;
    goto handle_size;

  handle_size:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || val < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (param2[n] == 'k' || param2[n] == 'K') {
      val *= SIZE_K;
      n++;
    } else if (param2[n] == 'm' || param2[n] == 'M') {
      val *= SIZE_M;
      n++;
    }
    if (param2[n]) return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_MAX_RUN_TOTAL:
    p_int = &global->max_run_total;
    goto handle_size;

  case SSERV_CMD_GLOB_CHANGE_MAX_RUN_NUM:
    p_int = &global->max_run_num;

  handle_int:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n] || val < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_MAX_CLAR_SIZE:
    p_int = &global->max_clar_size;
    goto handle_size;

  case SSERV_CMD_GLOB_CHANGE_MAX_CLAR_TOTAL:
    p_int = &global->max_clar_total;
    goto handle_size;

  case SSERV_CMD_GLOB_CHANGE_MAX_CLAR_NUM:
    p_int = &global->max_clar_num;
    goto handle_int;

  case SSERV_CMD_GLOB_CHANGE_TEAM_PAGE_QUOTA:
    p_int = &global->team_page_quota;
    goto handle_int;

  case SSERV_CMD_GLOB_CHANGE_TEAM_INFO_URL:
    GLOB_SET_STRING(team_info_url);

  case SSERV_CMD_GLOB_CLEAR_TEAM_INFO_URL:
    GLOB_CLEAR_STRING(team_info_url);

  case SSERV_CMD_GLOB_CHANGE_PROB_INFO_URL:
    GLOB_SET_STRING(prob_info_url);

  case SSERV_CMD_GLOB_CLEAR_PROB_INFO_URL:
    GLOB_CLEAR_STRING(prob_info_url);

  case SSERV_CMD_GLOB_CHANGE_STAND_FILE_NAME:
    GLOB_SET_STRING(standings_file_name);

  case SSERV_CMD_GLOB_CLEAR_STAND_FILE_NAME:
    GLOB_CLEAR_STRING(standings_file_name);

  case SSERV_CMD_GLOB_CHANGE_USERS_ON_PAGE:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n])
      return -SSERV_ERR_INVALID_PARAMETER;
    if (val <= 0) val = 0;
    global->users_on_page = val;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_STAND_HEADER_FILE:
    GLOB_SET_STRING(stand_header_file);

  case SSERV_CMD_GLOB_CLEAR_STAND_HEADER_FILE:
    GLOB_CLEAR_STRING(stand_header_file);

  case SSERV_CMD_GLOB_CHANGE_STAND_FOOTER_FILE:
    GLOB_SET_STRING(stand_footer_file);

  case SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_FILE:
    GLOB_CLEAR_STRING(stand_footer_file);

  case SSERV_CMD_GLOB_CHANGE_STAND_SYMLINK_DIR:
    GLOB_SET_STRING(stand_symlink_dir);

  case SSERV_CMD_GLOB_CLEAR_STAND_SYMLINK_DIR:
    GLOB_CLEAR_STRING(stand_symlink_dir);

  case SSERV_CMD_GLOB_CHANGE_STAND_IGNORE_AFTER:
    if (xml_parse_date("", 0, 0, param2, &global->stand_ignore_after_d) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    return 0;

  case SSERV_CMD_GLOB_CLEAR_STAND_IGNORE_AFTER:
    global->stand_ignore_after_d = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_APPEAL_DEADLINE:
    if (xml_parse_date("", 0, 0, param2, &global->appeal_deadline_d) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    snprintf(global->appeal_deadline, sizeof(global->appeal_deadline),
             "%s", xml_unparse_date(global->appeal_deadline_d));
    return 0;

  case SSERV_CMD_GLOB_CLEAR_APPEAL_DEADLINE:
    global->appeal_deadline_d = 0;
    global->appeal_deadline[0] = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_CONTEST_FINISH_TIME:
    if (xml_parse_date("", 0, 0, param2, &global->contest_finish_time_d) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    return 0;

  case SSERV_CMD_GLOB_CLEAR_CONTEST_FINISH_TIME:
    global->contest_finish_time_d = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_STAND2:
    p_int = &sstate->enable_stand2;
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n] || val < 0 || val > 1)
      return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    if (val && !global->stand2_file_name[0])
      strcpy(global->stand2_file_name, "standings2.html");
    return 0;

  case SSERV_CMD_GLOB_CHANGE_STAND2_FILE_NAME:
    GLOB_SET_STRING(stand2_file_name);

  case SSERV_CMD_GLOB_CLEAR_STAND2_FILE_NAME:
    GLOB_CLEAR_STRING(stand2_file_name);

  case SSERV_CMD_GLOB_CHANGE_STAND2_HEADER_FILE:
    GLOB_SET_STRING(stand2_header_file);

  case SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_FILE:
    GLOB_CLEAR_STRING(stand2_header_file);

  case SSERV_CMD_GLOB_CHANGE_STAND2_FOOTER_FILE:
    GLOB_SET_STRING(stand2_footer_file);

  case SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_FILE:
    GLOB_CLEAR_STRING(stand2_footer_file);

  case SSERV_CMD_GLOB_CHANGE_STAND2_SYMLINK_DIR:
    GLOB_SET_STRING(stand2_symlink_dir);

  case SSERV_CMD_GLOB_CLEAR_STAND2_SYMLINK_DIR:
    GLOB_CLEAR_STRING(stand2_symlink_dir);

  case SSERV_CMD_GLOB_CHANGE_ENABLE_PLOG:
    p_int = &sstate->enable_plog;
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n] || val < 0 || val > 1)
      return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    if (val && !global->plog_file_name[0])
      strcpy(global->plog_file_name, "plog.html");
    return 0;

  case SSERV_CMD_GLOB_CHANGE_PLOG_FILE_NAME:
    GLOB_SET_STRING(plog_file_name);

  case SSERV_CMD_GLOB_CLEAR_PLOG_FILE_NAME:
    GLOB_CLEAR_STRING(plog_file_name);

  case SSERV_CMD_GLOB_CHANGE_PLOG_HEADER_FILE:
    GLOB_SET_STRING(plog_header_file);

  case SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_FILE:
    GLOB_CLEAR_STRING(plog_header_file);

  case SSERV_CMD_GLOB_CHANGE_PLOG_FOOTER_FILE:
    GLOB_SET_STRING(plog_footer_file);

  case SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_FILE:
    GLOB_CLEAR_STRING(plog_footer_file);

  case SSERV_CMD_GLOB_CHANGE_PLOG_SYMLINK_DIR:
    GLOB_SET_STRING(plog_symlink_dir);

  case SSERV_CMD_GLOB_CLEAR_PLOG_SYMLINK_DIR:
    GLOB_CLEAR_STRING(plog_symlink_dir);

  case SSERV_CMD_GLOB_CHANGE_PLOG_UPDATE_TIME:
    p_int = &global->plog_update_time;
    goto handle_int;

  case SSERV_CMD_GLOB_CHANGE_EXTERNAL_XML_UPDATE_TIME:
    p_int = &global->external_xml_update_time;
    goto handle_int;
  case SSERV_CMD_GLOB_CHANGE_INTERNAL_XML_UPDATE_TIME:
    p_int = &global->internal_xml_update_time;
    goto handle_int;

  case SSERV_CMD_GLOB_CHANGE_STAND_FANCY_STYLE:
    p_int = &global->stand_fancy_style;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_STAND_TABLE_ATTR:
    GLOB_SET_STRING(stand_table_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_TABLE_ATTR:
    GLOB_CLEAR_STRING(stand_table_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_PLACE_ATTR:
    GLOB_SET_STRING(stand_place_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_PLACE_ATTR:
    GLOB_CLEAR_STRING(stand_place_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_TEAM_ATTR:
    GLOB_SET_STRING(stand_team_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_TEAM_ATTR:
    GLOB_CLEAR_STRING(stand_team_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_PROB_ATTR:
    GLOB_SET_STRING(stand_prob_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_PROB_ATTR:
    GLOB_CLEAR_STRING(stand_prob_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_SOLVED_ATTR:
    GLOB_SET_STRING(stand_solved_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_SOLVED_ATTR:
    GLOB_CLEAR_STRING(stand_solved_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_SCORE_ATTR:
    GLOB_SET_STRING(stand_score_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_SCORE_ATTR:
    GLOB_CLEAR_STRING(stand_score_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_PENALTY_ATTR:
    GLOB_SET_STRING(stand_penalty_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_PENALTY_ATTR:
    GLOB_CLEAR_STRING(stand_penalty_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_USE_LOGIN:
    p_int = &global->stand_use_login;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_STAND_SHOW_OK_TIME:
    p_int = &global->stand_show_ok_time;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_STAND_SHOW_ATT_NUM:
    p_int = &global->stand_show_att_num;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_STAND_SORT_BY_SOLVED:
    p_int = &global->stand_sort_by_solved;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_IGNORE_SUCCESS_TIME:
    p_int = &global->ignore_success_time;
    goto handle_boolean;    

  case SSERV_CMD_GLOB_CHANGE_STAND_COLLATE_NAME:
    p_int = &global->stand_collate_name;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_STAND_ENABLE_PENALTY:
    p_int = &global->stand_enable_penalty;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_STAND_TIME_ATTR:
    GLOB_SET_STRING(stand_time_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_TIME_ATTR:
    GLOB_CLEAR_STRING(stand_time_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_SUCCESS_ATTR:
    GLOB_SET_STRING(stand_success_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_SUCCESS_ATTR:
    GLOB_CLEAR_STRING(stand_success_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_FAIL_ATTR:
    GLOB_SET_STRING(stand_fail_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_FAIL_ATTR:
    GLOB_CLEAR_STRING(stand_fail_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_TRANS_ATTR:
    GLOB_SET_STRING(stand_trans_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_TRANS_ATTR:
    GLOB_CLEAR_STRING(stand_trans_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_DISQ_ATTR:
    GLOB_SET_STRING(stand_disq_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_DISQ_ATTR:
    GLOB_CLEAR_STRING(stand_disq_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_SELF_ROW_ATTR:
    GLOB_SET_STRING(stand_self_row_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_SELF_ROW_ATTR:
    GLOB_CLEAR_STRING(stand_self_row_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_V_ROW_ATTR:
    GLOB_SET_STRING(stand_v_row_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_V_ROW_ATTR:
    GLOB_CLEAR_STRING(stand_v_row_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_R_ROW_ATTR:
    GLOB_SET_STRING(stand_r_row_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_R_ROW_ATTR:
    GLOB_CLEAR_STRING(stand_r_row_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_U_ROW_ATTR:
    GLOB_SET_STRING(stand_u_row_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_U_ROW_ATTR:
    GLOB_CLEAR_STRING(stand_u_row_attr);

  case SSERV_CMD_GLOB_CHANGE_ENABLE_EXTRA_COL:
    p_int = &sstate->enable_extra_col;
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n] || val < 0 || val > 1)
      return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    if (val && !global->stand_extra_format[0]) {
      strcpy(global->stand_extra_format, "%Mc");
      strcpy(global->stand_extra_legend, "City");
    }
    return 0;

  case SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_FORMAT:
    GLOB_SET_STRING(stand_extra_format);

  case SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_FORMAT:
    GLOB_CLEAR_STRING(stand_extra_format);

  case SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_LEGEND:
    GLOB_SET_STRING(stand_extra_legend);

  case SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_LEGEND:
    GLOB_CLEAR_STRING(stand_extra_legend);

  case SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_ATTR:
    GLOB_SET_STRING(stand_extra_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_ATTR:
    GLOB_CLEAR_STRING(stand_extra_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_SHOW_WARN_NUMBER:
    p_int = &global->stand_show_warn_number;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_STAND_WARN_NUMBER_ATTR:
    GLOB_SET_STRING(stand_warn_number_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_WARN_NUMBER_ATTR:
    GLOB_CLEAR_STRING(stand_warn_number_attr);

  case SSERV_CMD_GLOB_CHANGE_SLEEP_TIME:
    p_int = &global->sleep_time; default_val = 1000;

  handle_int_def:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n] || val < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (!val) val = default_val;
    *p_int = val;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_SERVE_SLEEP_TIME:
    p_int = &global->serve_sleep_time; default_val = 500;
    goto handle_int_def;

  case SSERV_CMD_GLOB_CHANGE_AUTOUPDATE_STANDINGS:
    p_int = &global->autoupdate_standings;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ROUNDING_MODE:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n]
        || val < 0 || val > 2) return -SSERV_ERR_INVALID_PARAMETER;
    global->rounding_mode_val = val;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_MAX_FILE_LENGTH:
    p_int = &global->max_file_length;
    goto handle_size;

  case SSERV_CMD_GLOB_CHANGE_MAX_LINE_LENGTH:
    p_int = &global->max_line_length;
    goto handle_size;

  case SSERV_CMD_GLOB_CHANGE_INACTIVITY_TIMEOUT:
    p_int = &global->inactivity_timeout; default_val = 120;
    goto handle_int_def;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_AUTO_TESTING:
    p_int = &global->disable_auto_testing;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_TESTING:
    p_int = &global->disable_testing;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_CR_SERIALIZATION_KEY:
    p_int = &global->cr_serialization_key; default_val = config->serialization_key;
    goto handle_int_def;

  case SSERV_CMD_GLOB_CHANGE_SHOW_ASTR_TIME:
    p_int = &global->show_astr_time;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_CONTINUE:
    p_int = &global->enable_continue;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_REPORT_UPLOAD:
    p_int = &global->enable_report_upload;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_RUNLOG_MERGE:
    p_int = &global->enable_runlog_merge;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_USE_COMPILATION_SERVER:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n] || val < 0 || val > 1)
      return -SSERV_ERR_INVALID_PARAMETER;
    sstate->disable_compilation_server = !val;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_SECURE_RUN:
    p_int = &global->secure_run;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DETECT_VIOLATIONS:
    p_int = &global->detect_violations;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_MEMORY_LIMIT_ERROR:
    p_int = &global->enable_memory_limit_error;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_L10N:
    p_int = &global->enable_l10n;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_CHARSET:
    GLOB_SET_STRING(charset);

  case SSERV_CMD_GLOB_CLEAR_CHARSET:
    GLOB_CLEAR_STRING(charset);

  case SSERV_CMD_GLOB_CHANGE_TEAM_DOWNLOAD_TIME:
    p_int = &global->team_download_time;
    goto handle_int;

  case SSERV_CMD_GLOB_DISABLE_TEAM_DOWNLOAD_TIME:
    global->team_download_time = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_CPU_BOGOMIPS:
    p_int = &global->cpu_bogomips;
    goto handle_int;

  case SSERV_CMD_GLOB_DETECT_CPU_BOGOMIPS:
    global->cpu_bogomips = cpu_get_bogomips();
    return 0;

  case SSERV_CMD_GLOB_SAVE_CONTEST_START_CMD:
    pp_str = &sstate->contest_start_cmd_text;

  handle_string_3:
    xfree(*pp_str);
    *pp_str = dos2unix_str(param2);
    return 0;

  case SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD_TEXT:
    pp_str = &sstate->contest_start_cmd_text;

  clear_string_2:
    xfree(*pp_str);
    *pp_str = 0;
    return 0;

  case SSERV_CMD_GLOB_SAVE_STAND_HEADER:
    pp_str = &sstate->stand_header_text;
    goto handle_string_3;

  case SSERV_CMD_GLOB_CLEAR_STAND_HEADER_TEXT:
    pp_str = &sstate->stand_header_text;
    goto clear_string_2;

  case SSERV_CMD_GLOB_SAVE_STAND_FOOTER:
    pp_str = &sstate->stand_footer_text;
    goto handle_string_3;

  case SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_TEXT:
    pp_str = &sstate->stand_footer_text;
    goto clear_string_2;

  case SSERV_CMD_GLOB_SAVE_STAND2_HEADER:
    pp_str = &sstate->stand2_header_text;
    goto handle_string_3;

  case SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_TEXT:
    pp_str = &sstate->stand2_header_text;
    goto clear_string_2;

  case SSERV_CMD_GLOB_SAVE_STAND2_FOOTER:
    pp_str = &sstate->stand2_footer_text;
    goto handle_string_3;

  case SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_TEXT:
    pp_str = &sstate->stand2_footer_text;
    goto clear_string_2;

  case SSERV_CMD_GLOB_SAVE_PLOG_HEADER:
    pp_str = &sstate->plog_header_text;
    goto handle_string_3;

  case SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_TEXT:
    pp_str = &sstate->plog_header_text;
    goto clear_string_2;

  case SSERV_CMD_GLOB_SAVE_PLOG_FOOTER:
    pp_str = &sstate->plog_footer_text;
    goto handle_string_3;

  case SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_TEXT:
    pp_str = &sstate->plog_footer_text;
    goto clear_string_2;

  case SSERV_CMD_GLOB_CHANGE_STAND_ROW_ATTR:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(global->stand_row_attr);
    global->stand_row_attr = tmp_env;
    return 0;

  case SSERV_CMD_GLOB_CLEAR_STAND_ROW_ATTR:
    sarray_free(global->stand_row_attr);
    global->stand_row_attr = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_STAND_PAGE_TABLE_ATTR:
    GLOB_SET_STRING(stand_page_table_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_PAGE_TABLE_ATTR:
    GLOB_CLEAR_STRING(stand_page_table_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_PAGE_CUR_ATTR:
    GLOB_SET_STRING(stand_page_cur_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_PAGE_CUR_ATTR:
    GLOB_CLEAR_STRING(stand_page_cur_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_PAGE_ROW_ATTR:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(global->stand_page_row_attr);
    global->stand_page_row_attr = tmp_env;
    return 0;

  case SSERV_CMD_GLOB_CLEAR_STAND_PAGE_ROW_ATTR:
    sarray_free(global->stand_page_row_attr);
    global->stand_page_row_attr = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_STAND_PAGE_COL_ATTR:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(global->stand_page_col_attr);
    global->stand_page_col_attr = tmp_env;
    return 0;

  case SSERV_CMD_GLOB_CLEAR_STAND_PAGE_COL_ATTR:
    sarray_free(global->stand_page_col_attr);
    global->stand_page_col_attr = 0;
    return 0;

  default:
    abort();
  }
  return 0;
}

static int
load_cs_languages(const struct ejudge_cfg *config,
                  struct sid_state *sstate,
                  int check_version_flag)
{
  path_t cs_conf_dir;
  struct generic_section_config *cfg = 0, *p;
  struct section_language_data *lp;
  int max_lang = -1;
  int cur_lang = 1;
  path_t cmdline;
  path_t cmdpath;
  path_t script_dir;

  sstate->cs_langs_loaded = 1;

  if (!sstate->compile_home_dir) {
    sstate->compile_home_dir = xstrdup(config->compile_home_dir);
  }
  snprintf(cs_conf_dir, sizeof(cs_conf_dir), "%s/conf/compile.cfg",
           sstate->compile_home_dir);
  if (!(cfg = prepare_parse_config_file(cs_conf_dir, 0))) return -1;
  sstate->cs_cfg = cfg;

  for (p = cfg; p; p = p->next) {
    if (strcmp(p->name, "language") != 0) continue;
    lp = (typeof(lp)) p;
    if (lp->id < 0) {
      fprintf(stderr, "%s: language identifier is negative\n", cs_conf_dir);
      goto failed;
    }
    if (!lp->id) lp->id = cur_lang++;
    if (lp->id > max_lang) max_lang = lp->id;
  }

  if (max_lang <= 0) {
    fprintf(stderr, "%s: no languages defined\n", cs_conf_dir);
    goto failed;
  }

  sstate->cs_lang_total = max_lang + 1;
  XCALLOC(sstate->cs_langs, sstate->cs_lang_total);
  XCALLOC(sstate->cs_loc_map, sstate->cs_lang_total);
  XCALLOC(sstate->cs_lang_names, sstate->cs_lang_total);

  for (p = cfg; p; p = p->next) {
    if (strcmp(p->name, "language") != 0) continue;
    lp = (typeof(lp)) p;
    if (sstate->cs_langs[lp->id]) {
      fprintf(stderr, "%s: duplicated language id %d\n", cs_conf_dir, lp->id);
      goto failed;
    }
    sstate->cs_langs[lp->id] = lp;
  }

  script_dir[0] = 0;
  if (config->script_dir) {
    snprintf(script_dir, sizeof(script_dir), "%s", config->script_dir);
  }
#if defined EJUDGE_SCRIPT_DIR
  if (!*script_dir) {
    snprintf(script_dir, sizeof(script_dir), "%s", EJUDGE_SCRIPT_DIR);
  }
#endif

  if (*script_dir) {
    // detect actual language versions
    for (cur_lang = 1; cur_lang < sstate->cs_lang_total; cur_lang++) {
      if (!(lp = sstate->cs_langs[cur_lang])) continue;
      snprintf(cmdpath, sizeof(cmdpath), "%s/lang/%s-version", script_dir,
               lp->cmd);
      /*
      if (!check_version_flag && sstate->?) {
        snprintf(cmdline, sizeof(cmdline), "\"%s/%s-version\"",
                 script_dir, lp->cmd);
      } else {
      */
      snprintf(cmdline, sizeof(cmdline), "\"%s/lang/%s-version\" -f",
               script_dir, lp->cmd);
        //}
      if (access(cmdpath, X_OK) >= 0) {
        sstate->cs_lang_names[cur_lang] = read_process_output(cmdline, 0, 0, 0);
        //fprintf(stderr, ">>%s<<\n", sstate->cs_lang_names[cur_lang]);
      }
    }
  }

  return 0;

 failed:
  return -1;
}

int
super_html_edit_languages(FILE *f,
                          int priv_level,
                          int user_id,
                          const unsigned char *login,
                          ej_cookie_t session_id,
                          ej_ip_t ip_address,
                          const struct ejudge_cfg *config,
                          struct sid_state *sstate,
                          const unsigned char *self_url,
                          const unsigned char *hidden_vars,
                          const unsigned char *extra_args)
{
  int i;
  unsigned char *s;
  struct section_language_data *lang = 0, *cs_lang;
  unsigned char buf[1024], buf2[1024];
  unsigned char *cmt, *lang_name, *td_attr;
  path_t lang_hidden_vars;
  int row = 1;

  if (sstate->serve_parse_errors) {
    s = html_armor_string_dup(sstate->serve_parse_errors);
    super_html_contest_page_menu(f, session_id, sstate, 3, self_url, hidden_vars,
                                 extra_args);
    fprintf(f, "<h2><tt>serve.cfg</tt> cannot be edited</h2>\n");
    fprintf(f, "<font color=\"red\"><pre>%s</pre></font>\n", s);
    xfree(s);
    return 0;
  }

  if (sstate->disable_compilation_server) {
    fprintf(f, "<h2>Compilation without compilation server not yet supported!</h2>\n");
    super_html_contest_page_menu(f, session_id, sstate, 3, self_url, hidden_vars,
                                 extra_args);
    return 0;
  }

  if (!sstate->cs_langs_loaded) {
    load_cs_languages(config, sstate, 1);
  }

  if (!sstate->cs_langs) {
    fprintf(f, "<h2>No compile server available!</h2>\n");
    super_html_contest_page_menu(f, session_id, sstate, 3, self_url, hidden_vars,
                                 extra_args);
    return 0;
  }

  super_html_contest_page_menu(f, session_id, sstate, 3, self_url, hidden_vars,
                               extra_args);

  fprintf(f, "<table border=\"0\">\n");

  for (i = 1; i < sstate->cs_lang_total; i++) {
    if (!(cs_lang = sstate->cs_langs[i])) continue;
    lang = 0;
    if (sstate->cs_loc_map[i] > 0) lang = sstate->langs[sstate->cs_loc_map[i]];
    if (lang && lang->long_name[0]) {
      lang_name = lang->long_name;
      if (!sstate->cs_lang_names[i]) {
        cmt = " <font color=\"magenta\">(No version script!)</font>";
      } else if (!*sstate->cs_lang_names[i]) {
        cmt = " <font color=\"red\">(Version script failed!)</font>";
      } else {
        snprintf(buf2, sizeof(buf2), " (%s)", sstate->cs_lang_names[i]);
        cmt = buf2;
      }
    } else if (!sstate->cs_lang_names[i]) {
      cmt = " <font color=\"magenta\">(No version script!)</font>";
      lang_name = cs_lang->long_name;
    } else if (!*sstate->cs_lang_names[i]) {
      cmt = " <font color=\"red\">(Version script failed!)</font>";
      lang_name = cs_lang->long_name;
    } else {
      cmt = "";
      lang_name = sstate->cs_lang_names[i];
    }
    td_attr = "";
    if (lang) {
      td_attr = " bgcolor=\"#ddffdd\"";
    }
    html_start_form(f, 1, self_url, hidden_vars);
    snprintf(buf, sizeof(buf), "%d", i);
    html_hidden_var(f, "lang_id", buf);
    s = html_armor_string_dup(lang_name);
    fprintf(f, "<tr><td colspan = \"2\"%s><b>%s</b>%s</td><td>",td_attr,s,cmt);
    xfree(s);
    if (lang) {
      if (!sstate->lang_flags[lang->id]) {
        html_submit_button(f, SSERV_CMD_LANG_SHOW_DETAILS, "View details");
      } else {
        html_submit_button(f, SSERV_CMD_LANG_HIDE_DETAILS, "Hide details");
      }
      if (!sstate->loc_cs_map[lang->id]) {
        html_submit_button(f, SSERV_CMD_LANG_DEACTIVATE, "Deactivate");
      }
    } else {
      html_submit_button(f, SSERV_CMD_LANG_ACTIVATE, "Activate");
    }
    fprintf(f, "</td></tr></form>\n");
    row = 1;

    if (!lang || !sstate->lang_flags[lang->id]) continue;
    ASSERT(lang->compile_id == i);

    //LANGUAGE_PARAM(id, "d"),
    fprintf(f, "<tr%s><td>Language ID:</td><td>%d</td><td>&nbsp;</td></tr>\n",
            form_row_attrs[row ^= 1],
            lang->id);
    //LANGUAGE_PARAM(compile_id, "d"),
    fprintf(f, "<tr%s><td>Compilation server ID:</td><td>%d</td><td>&nbsp;</td></tr>\n",
            form_row_attrs[row ^= 1],
            lang->compile_id);
    //LANGUAGE_PARAM(short_name, "s"),
    s = html_armor_string_dup(lang->short_name);
    fprintf(f, "<tr%s><td>Language short name:</td><td>%s</td><td>&nbsp;</td></tr>\n",
            form_row_attrs[row ^= 1],
            s);
    xfree(s);
    //LANGUAGE_PARAM(arch, "s"),
    s = html_armor_string_dup(lang->arch);
    fprintf(f, "<tr%s><td>Language architecture:</td><td>%s%s</td><td>&nbsp;</td></tr>\n",
            form_row_attrs[row ^= 1],
            s, *s?"":"<i>(Default)</i>");
    xfree(s);
    //LANGUAGE_PARAM(src_sfx, "s"),
    s = html_armor_string_dup(lang->src_sfx);
    fprintf(f, "<tr%s><td>Suffix of the source files:</td><td>%s</td><td>&nbsp;</td></tr>\n",
            form_row_attrs[row ^= 1],
            s);
    xfree(s);
    //LANGUAGE_PARAM(exe_sfx, "s"),
    s = html_armor_string_dup(lang->exe_sfx);
    fprintf(f, "<tr%s><td>Suffix of the executable files:</td><td>%s%s</td><td>&nbsp;</td></tr>\n",
            form_row_attrs[row ^= 1],
            s, *s?"":"<i>(Empty)</i>");
    xfree(s);

    snprintf(lang_hidden_vars, sizeof(lang_hidden_vars),
             "%s<input type=\"hidden\" name=\"lang_id\" value=\"%d\"/>",
             hidden_vars, lang->compile_id);

    //LANGUAGE_PARAM(long_name, "s"),
    print_string_editing_row(f, "Language long name:", lang->long_name,
                             SSERV_CMD_LANG_CHANGE_LONG_NAME,
                             SSERV_CMD_LANG_CLEAR_LONG_NAME,
                             0,
                             session_id, 
                             form_row_attrs[row ^= 1],
                             self_url, extra_args, lang_hidden_vars);

    //LANGUAGE_PARAM(disabled, "d"),
    print_boolean_select_row(f, "Disable this language for participants",
                             lang->disabled,
                             SSERV_CMD_LANG_CHANGE_DISABLED,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url, extra_args, lang_hidden_vars);

    //LANGUAGE_PARAM(disable_testing, "d"),
    print_boolean_select_row(f, "Disable any testing of submissions",
                             lang->disable_testing,
                             SSERV_CMD_LANG_CHANGE_DISABLE_TESTING,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url, extra_args, lang_hidden_vars);

    if (!lang->disable_testing) {
      //LANGUAGE_PARAM(disable_auto_testing, "d"),
      print_boolean_select_row(f, "Disable automatic testing of submissions",
                               lang->disable_auto_testing,
                               SSERV_CMD_LANG_CHANGE_DISABLE_AUTO_TESTING,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url, extra_args, lang_hidden_vars);
    }

    //LANGUAGE_PARAM(binary, "d"),
    print_boolean_select_row(f, "Language source files are binary",
                             lang->binary,
                             SSERV_CMD_LANG_CHANGE_BINARY,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url, extra_args, lang_hidden_vars);

    if (lang->binary) {
      //LANGUAGE_PARAM(content_type, "s"),
      print_string_editing_row(f, "Content type for files:", lang->content_type,
                               SSERV_CMD_LANG_CHANGE_CONTENT_TYPE,
                               SSERV_CMD_LANG_CLEAR_CONTENT_TYPE,
                               0,
                               session_id, 
                               form_row_attrs[row ^= 1],
                               self_url, extra_args, lang_hidden_vars);
    }

    // additional compilation options
    buf[0] = 0;
    if (sstate->lang_opts[lang->id])
      snprintf(buf, sizeof(buf), "%s", sstate->lang_opts[lang->id]);
    print_string_editing_row(f, "Additional compilation options:", buf,
                             SSERV_CMD_LANG_CHANGE_OPTS,
                             SSERV_CMD_LANG_CLEAR_OPTS,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url, extra_args, lang_hidden_vars);

/*
  FIXME: LANGUAGE_PARAM(compiler_env, "x"),
 */

    if (lang->unhandled_vars) {
      s = html_armor_string_dup(lang->unhandled_vars);
      fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Uneditable parameters</td></tr>\n<tr><td colspan=\"3\"><pre>%s</pre></td></tr>\n",
              form_row_attrs[row ^= 1],
              s);
      xfree(s);
    }
  }

  fprintf(f, "</table>\n");

  // update compiler versions
  fprintf(f, "<table><tr><td>");
  html_start_form(f, 1, self_url, hidden_vars);
  html_submit_button(f, SSERV_CMD_LANG_UPDATE_VERSIONS, "Update versions");
  fprintf(f, "</form></td></tr></table>\n");

  super_html_contest_footer_menu(f, session_id, sstate,
                                 self_url, hidden_vars, extra_args);


  return 0;
}

int
super_html_lang_cmd(struct sid_state *sstate, int cmd,
                    int lang_id, const unsigned char *param2,
                    int param3, int param4)
{
  struct section_language_data *pl_old, *pl_new;
  int val, n, max_id, i;
  int *p_int;

  if (!sstate->cs_langs) {
    return -SSERV_ERR_CONTEST_NOT_EDITED;
  }
  if (lang_id <= 0 || lang_id >= sstate->cs_lang_total
      || !sstate->cs_langs[lang_id]) {
    return -SSERV_ERR_INVALID_PARAMETER;
  }

  pl_old = sstate->cs_langs[lang_id];
  pl_new = 0;
  if (sstate->cs_loc_map[lang_id] > 0)
    pl_new = sstate->langs[sstate->cs_loc_map[lang_id]];

  switch (cmd) {
  case SSERV_CMD_LANG_SHOW_DETAILS:
    if (!pl_new) return 0;
    sstate->lang_flags[pl_new->id] = 1;
    break;

  case SSERV_CMD_LANG_HIDE_DETAILS:
    if (!pl_new) return 0;
    sstate->lang_flags[pl_new->id] = 0;
    break;

  case SSERV_CMD_LANG_DEACTIVATE:
    if (!pl_new) return 0;
    if (sstate->loc_cs_map[pl_new->id]) return 0;
    sstate->langs[pl_new->id] = 0;
    xfree(sstate->lang_opts[pl_new->id]);
    sstate->lang_opts[pl_new->id] = 0;
    sstate->lang_flags[pl_new->id] = 0;
    sstate->cs_loc_map[lang_id] = 0;
    break;

  case SSERV_CMD_LANG_ACTIVATE:
    if (pl_new) return 0;

    pl_new = prepare_alloc_language();
    sstate->cfg = param_merge(&pl_new->g, sstate->cfg);

    // find appropriate language ID
    max_id = 0;
    for (i = 1; i < sstate->lang_a; i++)
      if (sstate->langs[i] && sstate->loc_cs_map[i]
          && i > max_id)
        max_id = i;
    if (pl_old->id > max_id) {
      pl_new->id = pl_old->id;
      pl_new->compile_id = pl_old->id;
    } else {
      while (1) {
        max_id++;
        for (i = 1; i < sstate->lang_a; i++)
          if (sstate->langs[i] && sstate->langs[i]->id == max_id)
            break;
        if (i < sstate->lang_a) continue;
        for (i = 1; i < sstate->cs_lang_total; i++)
          if (sstate->cs_langs[i] && sstate->cs_langs[i]->id == max_id)
            break;
        if (i == sstate->cs_lang_total)
          break;
      }
      pl_new->id = max_id;
      pl_new->compile_id = pl_old->id;
    }

    if (pl_new->id >= sstate->lang_a) {
      int new_lang_a = sstate->lang_a;
      // langs, loc_cs_map, lang_opts, lang_flags
      struct section_language_data **new_langs;
      int *new_loc_cs_map;
      unsigned char **new_lang_opts;
      int *new_lang_flags;

      if (!new_lang_a) new_lang_a = 4;
      while (pl_new->id >= new_lang_a) new_lang_a *= 2;
      XCALLOC(new_langs, new_lang_a);
      XCALLOC(new_loc_cs_map, new_lang_a);
      XCALLOC(new_lang_opts, new_lang_a);
      XCALLOC(new_lang_flags, new_lang_a);
      if (sstate->lang_a > 0) {
        XMEMMOVE(new_langs, sstate->langs, sstate->lang_a);
        XMEMMOVE(new_loc_cs_map, sstate->loc_cs_map, sstate->lang_a);
        XMEMMOVE(new_lang_opts, sstate->lang_opts, sstate->lang_a);
        XMEMMOVE(new_lang_flags, sstate->lang_flags, sstate->lang_a);
      }
      xfree(sstate->langs);
      xfree(sstate->loc_cs_map);
      xfree(sstate->lang_opts);
      xfree(sstate->lang_flags);
      sstate->lang_a = new_lang_a;
      sstate->langs = new_langs;
      sstate->loc_cs_map = new_loc_cs_map;
      sstate->lang_opts = new_lang_opts;
      sstate->lang_flags = new_lang_flags;
    }

    sstate->langs[pl_new->id] = pl_new;
    sstate->lang_opts[pl_new->id] = 0;
    sstate->lang_flags[pl_new->id] = 0;
    sstate->cs_loc_map[pl_new->compile_id] = pl_new->id;

    strcpy(pl_new->short_name, pl_old->short_name);
    if (sstate->cs_lang_names[lang_id] && *sstate->cs_lang_names[lang_id]) {
      snprintf(pl_new->long_name, sizeof(pl_new->long_name),
               "%s", sstate->cs_lang_names[lang_id]);
    } else {
      snprintf(pl_new->long_name, sizeof(pl_new->long_name),
               "%s", pl_old->long_name);
    }
    strcpy(pl_new->arch, pl_old->arch);
    strcpy(pl_new->src_sfx, pl_old->src_sfx);
    strcpy(pl_new->exe_sfx, pl_old->exe_sfx);
    pl_new->binary = pl_old->binary;
    strcpy(pl_new->content_type, pl_old->content_type);
    break;

  case SSERV_CMD_LANG_CHANGE_DISABLED:
    if (!pl_new) return 0;
    p_int = &pl_new->disabled;

  handle_boolean:
    if (!param2 || sscanf(param2, "%d%n", &val, &n) != 1 || param2[n]
        || val < 0 || val > 1) return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    break;
    
  case SSERV_CMD_LANG_CHANGE_LONG_NAME:
    if (!pl_new) return 0;
    snprintf(pl_new->long_name, sizeof(pl_new->long_name), "%s", param2);
    break;

  case SSERV_CMD_LANG_CHANGE_CONTENT_TYPE:
    if (!pl_new) return 0;
    snprintf(pl_new->content_type, sizeof(pl_new->content_type), "%s", param2);
    break;

  case SSERV_CMD_LANG_CLEAR_LONG_NAME:
    if (!pl_new) return 0;
    pl_new->long_name[0] = 0;
    break;

  case SSERV_CMD_LANG_CLEAR_CONTENT_TYPE:
    if (!pl_new) return 0;
    pl_new->content_type[0] = 0;
    break;

  case SSERV_CMD_LANG_CHANGE_DISABLE_AUTO_TESTING:
    if (!pl_new) return 0;
    p_int = &pl_new->disable_auto_testing;
    goto handle_boolean;

  case SSERV_CMD_LANG_CHANGE_DISABLE_TESTING:
    if (!pl_new) return 0;
    p_int = &pl_new->disable_testing;
    goto handle_boolean;

  case SSERV_CMD_LANG_CHANGE_BINARY:
    if (!pl_new) return 0;
    p_int = &pl_new->binary;
    goto handle_boolean;

  case SSERV_CMD_LANG_CHANGE_OPTS:
    if (!pl_new) return 0;
    xfree(sstate->lang_opts[lang_id]);
    sstate->lang_opts[lang_id] = xstrdup(param2);
    break;

  case SSERV_CMD_LANG_CLEAR_OPTS:
    if (!pl_new) return 0;
    xfree(sstate->lang_opts[lang_id]);
    sstate->lang_opts[lang_id] = 0;
    break;

  default:
    abort();
  }

  return 0;
}

int
super_html_update_versions(struct sid_state *sstate)
{
  int i, j;

  if (!sstate->cs_langs) {
    return -SSERV_ERR_CONTEST_NOT_EDITED;
  }

  for (i = 1; i < sstate->lang_a; i++) {
    if (!sstate->langs[i]) continue;
    j = 0;
    if (sstate->loc_cs_map) {
      j = sstate->loc_cs_map[i];
      if (j <= 0 || j >= sstate->cs_lang_total || !sstate->cs_langs[j])
        j = 0;
    }
    if (j > 0) {
      snprintf(sstate->langs[i]->long_name,sizeof(sstate->langs[i]->long_name),
               "%s", sstate->cs_lang_names[j]);
    }
  }
  return 0;
}

static void
print_boolean_3_select_row(FILE *f,
                           const unsigned char *title,
                           int value,
                           int change_action,
                           const unsigned char *undef_str,
                           ej_cookie_t session_id,
                           const unsigned char *row_attr,
                           const unsigned char *self_url,
                           const unsigned char *extra_args,
                           const unsigned char *hidden_vars)

{
  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>%s</td><td>", row_attr, title);
  if (undef_str) {
    html_boolean_3_select(f, value, "param", undef_str, 0, 0);
  } else {
    html_boolean_select(f, value, "param", 0, 0);
  }
  fprintf(f, "</td><td>");
  html_submit_button(f, change_action, "Change");
  fprintf(f, "</td></tr></form>\n");
}

struct std_checker_info
{
  unsigned char *name;
  unsigned char *desc;
};
static struct std_checker_info std_checkers[] =
{
  { "", "" },
  { "cmp_file", "compare two files (trailing whitespace ignored)" },
  { "cmp_file_nospace", "compare two files (duplicated whitespace ignored)" },
  { "cmp_bytes", "compare two files byte by byte" },
  { "cmp_int", "compare two ints (32 bit)" },
  { "cmp_int_seq", "compare two sequences of ints (32 bit)" },
  { "cmp_long_long", "compare two long longs (64 bit)" },
  { "cmp_long_long_seq", "compare two sequences of long longs (64 bit)" },
  { "cmp_unsigned_int", "compare two unsigned ints (32 bit)" },
  { "cmp_unsigned_int_seq", "compare two sequences of unsigned ints (32 bit)" },
  { "cmp_unsigned_long_long", "compare two unsigned long longs (64 bit)" },
  { "cmp_unsigned_long_long_seq", "compare two sequences of unsigned long longs (64 bit)" },
  { "cmp_huge_int", "compare two arbitrarily long ints" },
  { "cmp_double", "compare two doubles (EPS env. var is required)" },
  { "cmp_double_seq", "compare two sequences of doubles (EPS is required)" },
  { "cmp_long_double", "compare two long doubles (EPS is required)" },
  { "cmp_long_double_seq", "compare two sequences of long doubles (EPS is required)" },
  { "cmp_sexpr", "compare two S-expressions" },
  { "cmp_yesno", "compare YES/NO answers" },
  { 0, 0 },
};
static void
print_std_checker_row(FILE *f,
                      struct section_problem_data *prob,
                      struct sid_state *sstate,
                      ej_cookie_t session_id,
                      const unsigned char *row_attr,
                      const unsigned char *self_url,
                      const unsigned char *extra_args,
                      const unsigned char *hidden_vars)
{
  int was_match = 0;
  int i;
  unsigned char *s;

  if (prob->abstract) return;
  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>%s</td><td>", row_attr, "Standard checker:");
  fprintf(f, "<select name=\"param\">");
  for (i = 0; std_checkers[i].name; i++) {
    s = "";
    if (!strcmp(prob->standard_checker, std_checkers[i].name)) {
      s = " selected=\"1\"";
      was_match = 1;
    }
    fprintf(f, "<option value=\"%s\"%s>%s</option>",
            std_checkers[i].name, s, std_checkers[i].desc);
  }
  if (!was_match) {
    s = html_armor_string_dup(prob->standard_checker);
    fprintf(f, "<option value=\"%s\" selected=\"1\">Unknown - %s</option>", s, s);
    xfree(s);
  }
  fprintf(f, "</select></td><td>");
  html_submit_button(f, SSERV_CMD_PROB_CHANGE_STANDARD_CHECKER, "Change");
  fprintf(f, "</td></tr></form>\n");
}

/*
  PROBLEM_PARAM(tester_id, "d"),
  PROBLEM_PARAM(use_tgz, "d"),
  PROBLEM_PARAM(priority_adjustment, "d"),
  PROBLEM_PARAM(spelling, "s"),
  PROBLEM_PARAM(score_multiplier, "d"),

  PROBLEM_PARAM(tgz_dir, "s"),
  PROBLEM_PARAM(tgz_sfx, "s"),
  PROBLEM_PARAM(test_sets, "x"),
  PROBLEM_PARAM(score_view, "x"),
  PROBLEM_PARAM(deadline, "s"),
  PROBLEM_PARAM(start_date, "s"),
  PROBLEM_PARAM(variant_num, "d"),
  PROBLEM_PARAM(date_penalty, "x"),
  PROBLEM_PARAM(disable_language, "x"),
  PROBLEM_PARAM(enable_language, "x"),
  PROBLEM_PARAM(require, "x"),
  *PROBLEM_PARAM(checker_env, "x"),
  PROBLEM_PARAM(tgz_pat, "s"),
  PROBLEM_PARAM(personal_deadline, "x"),
  *PROBLEM_PARAM(score_bonus, "s"),

  TESTER_PARAM(id, "d"),
  TESTER_PARAM(name, "s"),
  TESTER_PARAM(problem, "d"),
  TESTER_PARAM(problem_name, "s"),
  TESTER_PARAM(no_redirect, "d"),
  TESTER_PARAM(is_dos, "d"),
  TESTER_PARAM(arch, "s"),
  TESTER_PARAM(key, "s"),
  TESTER_PARAM(any, "d"),
  TESTER_PARAM(priority_adjustment, "d"),

  TESTER_PARAM(abstract, "d"),
  TESTER_PARAM(super, "x"),

  TESTER_PARAM(no_core_dump, "d"),
  TESTER_PARAM(enable_memory_limit_error, "d"),
  TESTER_PARAM(kill_signal, "s"),
  TESTER_PARAM(max_data_size, "d"),
  TESTER_PARAM(clear_env, "d"),
  TESTER_PARAM(time_limit_adjustment, "d"),
  TESTER_PARAM(time_limit_adj_millis, "d"),

  TESTER_PARAM(run_dir, "s"),
  TESTER_PARAM(check_dir, "s"),
  TESTER_PARAM(errorcode_file, "s"),
  TESTER_PARAM(error_file, "s"),

  TESTER_PARAM(prepare_cmd, "s"),
  *TESTER_PARAM(check_cmd, "s"),
  TESTER_PARAM(start_cmd, "s"),

  TESTER_PARAM(start_env, "x"),
  TESTER_PARAM(checker_env, "x"),
*/

static void
super_html_print_problem(FILE *f,
                         int num,
                         int is_abstract,
                         struct sid_state *sstate,
                         ej_cookie_t session_id,
                         const unsigned char *self_url,
                         const unsigned char *hidden_vars,
                         const unsigned char *extra_args)
{
  unsigned char name_buf[1024];
  int i, sel_num;
  struct section_problem_data *prob, *sup_prob = 0;
  unsigned char *s, *ss, *checker_env;
  unsigned char prob_hidden_vars[4096];
  unsigned char *extra_msg = 0;
  struct section_problem_data tmp_prob;
  unsigned char msg_buf[1024];
  int flags, show_adv = 0, show_details = 0;;
  unsigned char num_buf[1024];
  struct section_global_data *global = sstate->global;
  time_t tmp_date;
  unsigned char hbuf[1024];
  int row = 1, problem_type_flag = 0;

  if (is_abstract) {
    prob = sstate->aprobs[num];
    flags = sstate->aprob_flags[num];
  } else {
    prob = sstate->probs[num];
    flags = sstate->prob_flags[num];
  }
  ASSERT(prob);
  if ((flags & SID_STATE_SHOW_HIDDEN)) show_details = 1;
  if ((flags & SID_STATE_SHOW_CLOSED)) show_adv = 1;

  snprintf(prob_hidden_vars, sizeof(prob_hidden_vars),
           "%s<input type=\"hidden\" name=\"prob_id\" value=\"%d\"/>",
           hidden_vars, is_abstract?-num:num);
  prepare_copy_problem(&tmp_prob, prob);

  html_start_form(f, 1, self_url, prob_hidden_vars);
  if (is_abstract) {
    snprintf(name_buf, sizeof(name_buf), "%s", prob->short_name);
  } else {
    if (!prob->short_name[0]) {
      snprintf(name_buf, sizeof(name_buf), "Problem %d", prob->id);
    } else {
      if (!prob->long_name[0]) {
        snprintf(name_buf, sizeof(name_buf), "%s", prob->short_name);
      } else {
        snprintf(name_buf, sizeof(name_buf), "%s: %s", prob->short_name,
                 prob->long_name);
      }
    }
  }
  s = html_armor_string_dup(name_buf);
  fprintf(f, "<tr%s><td colspan=\"2\" align=\"center\">%s</td><td>",
          prob_row_attr, s);
  xfree(s);
  if (!show_details) {
    html_submit_button(f, SSERV_CMD_PROB_SHOW_DETAILS, "Show details");
  } else {
    html_submit_button(f, SSERV_CMD_PROB_HIDE_DETAILS, "Hide details");
    if (!show_adv) {
      html_submit_button(f, SSERV_CMD_PROB_SHOW_ADVANCED, "Show advanced");
    } else {
      html_submit_button(f, SSERV_CMD_PROB_HIDE_ADVANCED, "Hide advanced");
    }
  }
  html_submit_button(f, SSERV_CMD_PROB_DELETE, "Delete!");
  fprintf(f, "</td></tr></form>\n");

  if (!show_details) return;

  if (!prob->abstract) {
    fprintf(f, "<tr%s><td>Problem ID:</td><td>%d</td><td>&nbsp;</td></tr>\n",
            form_row_attrs[row ^= 1],
            prob->id);
    print_string_editing_row(f, "Problem short name:", prob->short_name,
                             SSERV_CMD_PROB_CHANGE_SHORT_NAME,
                             SSERV_CMD_PROB_CLEAR_SHORT_NAME,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url, extra_args, prob_hidden_vars);
    print_string_editing_row(f, "Problem long name:", prob->long_name,
                             SSERV_CMD_PROB_CHANGE_LONG_NAME,
                             SSERV_CMD_PROB_CLEAR_LONG_NAME,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url, extra_args, prob_hidden_vars);

    //PROBLEM_PARAM(super, "s"),
    sel_num = 0;
    if (*prob->super) {
      for (i = 0; i < sstate->aprob_u; i++)
        if (!strcmp(prob->super, sstate->aprobs[i]->short_name)) {
          sup_prob = sstate->aprobs[i];
          break;
        }
      sel_num = i + 1;
      if (sel_num > sstate->aprob_u) sel_num = 0;
    }
    html_start_form(f, 1, self_url, prob_hidden_vars);
    fprintf(f, "<tr%s><td>Base abstract problem:</td><td>",
            form_row_attrs[row ^= 1]);
    fprintf(f, "<select name=\"param\">"
            "<option value=\"0\"></option>");
    for (i = 0; i < sstate->aprob_u; i++) {
      s = html_armor_string_dup(sstate->aprobs[i]->short_name);
      fprintf(f, "<option value=\"%d\"%s>%s</option>",
              i + 1, (i + 1 == sel_num)?" selected=\"1\"":"", s);
      xfree(s);
    }
    fprintf(f, "</select></td><td>");
    html_submit_button(f, SSERV_CMD_PROB_CHANGE_SUPER, "Change");
    fprintf(f, "</td></tr></form>\n");
  } else {
    s = html_armor_string_dup(prob->short_name);
    fprintf(f, "<tr%s><td>Problem Name:</td><td>%s</td><td>&nbsp;</td></tr>\n",
            form_row_attrs[row ^= 1], s);
    xfree(s);
  }

  //PROBLEM_PARAM(type, "s")
  if (prob->type_val < -1 || prob->type_val >= PROB_TYPE_LAST)
    prob->type_val = -1;
  extra_msg = 0;
  problem_type_flag = prob->type_val;
  if (!prob->abstract) {
    prepare_set_prob_value(PREPARE_FIELD_PROB_TYPE,
                           &tmp_prob, sup_prob, sstate->global);
    snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
             problem_unparse_type(tmp_prob.type_val));
    extra_msg = msg_buf;
    problem_type_flag = tmp_prob.type_val;
  } else {
    if (prob->type_val < 0) prob->type_val = 0;
  }
  if (problem_type_flag < 0) problem_type_flag = 0;
  html_start_form(f, 1, self_url, prob_hidden_vars);
  fprintf(f, "<tr%s><td>%s</td><td>", form_row_attrs[row ^= 1],
          "Problem type:");
  fprintf(f, "<select name=\"param\">");
  if (!prob->abstract) {
    s = "";
    if (prob->type_val < 0) s = " selected=\"1\"";
    fprintf(f, "<option value=\"-1\"%s>Default</option>\n", s);
  }
  for (i = 0; i < PROB_TYPE_LAST; i++) {
    s = "";
    if (prob->type_val == i) s = " selected=\"1\"";
    fprintf(f, "<option value=\"%d\"%s>%s</option>\n",
            i, s, problem_unparse_type(i));
  }
  fprintf(f, "</select></td><td>");
  html_submit_button(f, SSERV_CMD_PROB_CHANGE_TYPE, "Change");
  fprintf(f, "</td></tr></form>\n");

  //PROBLEM_PARAM(manual_checking, "d")
  if ((prob->abstract && prob->type_val)
      || (!prob->abstract && tmp_prob.type_val > 0)) {
    extra_msg = 0;
    if (!prob->abstract) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_MANUAL_CHECKING,
                             &tmp_prob, sup_prob, sstate->global);
      snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
               tmp_prob.manual_checking?"Yes":"No");
      extra_msg = msg_buf;
    }
    print_boolean_3_select_row(f, "Problem is checked manually",
                               prob->manual_checking,
                               SSERV_CMD_PROB_CHANGE_MANUAL_CHECKING,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
  }

  //PROBLEM_PARAM(examinator_num, "d")
  if ((prob->abstract && prob->type_val)
      || (!prob->abstract && tmp_prob.type_val > 0)) {
    extra_msg = "";

    if (!prob->abstract) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_EXAMINATOR_NUM,
                             &tmp_prob, sup_prob, sstate->global);
      snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - %d)</i>",
               tmp_prob.examinator_num);
      extra_msg = msg_buf;
    } else {
      if (prob->examinator_num < 0) prob->examinator_num = 0;
    }
    html_start_form(f, 1, self_url, prob_hidden_vars);
    fprintf(f, "<tr%s><td>%s</td><td>", form_row_attrs[row ^= 1],
            "Number of examinators:");
    fprintf(f, "<select name=\"param\">");
    s = "";
    if (prob->examinator_num == 0) s = " selected=\"1\"";
    ss = "Default";
    if (prob->abstract) ss = "0";
    fprintf(f, "<option value=\"0\"%s>%s</option>", s, ss);
    for (i = 1; i <= 3; i++) {
      s = "";
      if (i == prob->examinator_num) s = " selected=\"1\"";
      fprintf(f, "<option value=\"%d\"%s>%d</option>", i, s, i);
    }
    fprintf(f, "</select>%s</td><td>", extra_msg);
    html_submit_button(f, SSERV_CMD_PROB_CHANGE_EXAMINATOR_NUM, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  //PROBLEM_PARAM(check_presentation, "d")
  if ((prob->abstract && prob->type_val > 0 && prob->manual_checking > 0)
      || (!prob->abstract && tmp_prob.type_val > 0 && tmp_prob.manual_checking > 0)) {
    extra_msg = 0;
    if (!prob->abstract) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_CHECK_PRESENTATION,
                             &tmp_prob, sup_prob, sstate->global);
      snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
               tmp_prob.check_presentation?"Yes":"No");
      extra_msg = msg_buf;
    }
    print_boolean_3_select_row(f, "Check output presentation anyway?",
                               prob->check_presentation,
                               SSERV_CMD_PROB_CHANGE_CHECK_PRESENTATION,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
  }

  //PROBLEM_PARAM(use_stdin, "d"),
  extra_msg = 0;
  if (!prob->abstract) {
    prepare_set_prob_value(PREPARE_FIELD_PROB_USE_STDIN,
                           &tmp_prob, sup_prob, sstate->global);
    snprintf(msg_buf, sizeof(msg_buf), "Default (%s)", tmp_prob.use_stdin?"Yes":"No");
    extra_msg = msg_buf;
  }
  if (!problem_type_flag) {
    print_boolean_3_select_row(f, "Use standard input", prob->use_stdin,
                               SSERV_CMD_PROB_CHANGE_USE_STDIN,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
  }

  //PROBLEM_PARAM(input_file, "s"),
  extra_msg = 0;
  if (prob->abstract && !prob->use_stdin) extra_msg = "";
  if (!prob->abstract && !tmp_prob.use_stdin) {
    extra_msg = "";
    prepare_set_prob_value(PREPARE_FIELD_PROB_INPUT_FILE,
                           &tmp_prob, sup_prob, sstate->global);
    if (!prob->input_file[0]) {
      s = html_armor_string_dup(tmp_prob.input_file);
      snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - \"%s\")</i>", s);
      xfree(s);
      extra_msg = msg_buf;
    }
  }
  if (!problem_type_flag && extra_msg) {
    print_string_editing_row_2(f, "Input file name:", prob->input_file,
                               SSERV_CMD_PROB_CHANGE_INPUT_FILE,
                               SSERV_CMD_PROB_CLEAR_INPUT_FILE,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
                               
  }

  //PROBLEM_PARAM(use_stdout, "d"),
  extra_msg = 0;
  if (!prob->abstract) {
    prepare_set_prob_value(PREPARE_FIELD_PROB_USE_STDOUT,
                           &tmp_prob, sup_prob, sstate->global);
    snprintf(msg_buf, sizeof(msg_buf), "Default (%s)", tmp_prob.use_stdout?"Yes":"No");
    extra_msg = msg_buf;
  }
  if (!problem_type_flag) {
    print_boolean_3_select_row(f, "Use standard output", prob->use_stdout,
                               SSERV_CMD_PROB_CHANGE_USE_STDOUT,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
  }

  //PROBLEM_PARAM(output_file, "s"),
  extra_msg = 0;
  if (prob->abstract && !prob->use_stdout) extra_msg = "";
  if (!prob->abstract && !tmp_prob.use_stdout) {
    extra_msg = "";
    prepare_set_prob_value(PREPARE_FIELD_PROB_OUTPUT_FILE,
                           &tmp_prob, sup_prob, sstate->global);
    if (!prob->output_file[0]) {
      s = html_armor_string_dup(tmp_prob.output_file);
      snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - \"%s\")</i>", s);
      xfree(s);
      extra_msg = msg_buf;
    }
  }
  if (!problem_type_flag && extra_msg) {
    print_string_editing_row_2(f, "Output file name:", prob->output_file,
                               SSERV_CMD_PROB_CHANGE_OUTPUT_FILE,
                               SSERV_CMD_PROB_CLEAR_OUTPUT_FILE,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
                               
  }

  if (show_adv) {
    //PROBLEM_PARAM(binary_input, "d"),
    extra_msg = 0;
    if (!prob->abstract) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_BINARY_INPUT,
                             &tmp_prob, sup_prob, sstate->global);
      snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
               tmp_prob.binary_input?"Yes":"No");
      extra_msg = msg_buf;
    }
    print_boolean_3_select_row(f, "Input data is binary", prob->binary_input,
                               SSERV_CMD_PROB_CHANGE_BINARY_INPUT,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
  }

  //PROBLEM_PARAM(statement_file, "s"),
  extra_msg = 0;
  if (prob->abstract && !prob->statement_file[0])extra_msg="<i>(Undefined)</i>";
  if (!prob->abstract) {
    prepare_set_prob_value(PREPARE_FIELD_PROB_STATEMENT_FILE,
                           &tmp_prob, sup_prob, sstate->global);
    s = html_armor_string_dup(tmp_prob.statement_file);
    if (!prob->statement_file[0])
      snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - \"%s\")</i>", s);
    else
      snprintf(msg_buf, sizeof(msg_buf), "<i>(\"%s\")</i>", s);
    xfree(s);
    extra_msg = msg_buf;
  }
  print_string_editing_row_2(f, "File with problem statement:",
                             prob->statement_file,
                             SSERV_CMD_PROB_CHANGE_STATEMENT_FILE,
                             SSERV_CMD_PROB_CLEAR_STATEMENT_FILE,
                             extra_msg,
                             session_id, form_row_attrs[row ^= 1],
                             self_url, extra_args, prob_hidden_vars);

  //PROBLEM_PARAM(alternatives_file, "s"),
  if (prob->abstract) i = prob->type_val;
  else i = tmp_prob.type_val;
  if (i == PROB_TYPE_SELECT_MANY || i == PROB_TYPE_SELECT_ONE) {
    extra_msg = 0;
    if (prob->abstract && !prob->alternatives_file[0])
      extra_msg="<i>(Undefined)</i>";
    if (!prob->abstract) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_ALTERNATIVES_FILE,
                             &tmp_prob, sup_prob, sstate->global);
      s = html_armor_string_dup(tmp_prob.alternatives_file);
      if (!prob->alternatives_file[0])
        snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - \"%s\")</i>", s);
      else
        snprintf(msg_buf, sizeof(msg_buf), "<i>(\"%s\")</i>", s);
      xfree(s);
      extra_msg = msg_buf;
    }
    print_string_editing_row_2(f, "File with answer alternatives:",
                               prob->alternatives_file,
                               SSERV_CMD_PROB_CHANGE_ALTERNATIVES_FILE,
                               SSERV_CMD_PROB_CLEAR_ALTERNATIVES_FILE,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
  }

  //PROBLEM_PARAM(plugin_file, "s"),
  extra_msg = 0;
  if (prob->abstract && !prob->plugin_file[0])extra_msg="<i>(Undefined)</i>";
  if (!prob->abstract) {
    prepare_set_prob_value(PREPARE_FIELD_PROB_PLUGIN_FILE,
                           &tmp_prob, sup_prob, sstate->global);
    s = html_armor_string_dup(tmp_prob.plugin_file);
    if (!prob->plugin_file[0])
      snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - \"%s\")</i>", s);
    else
      snprintf(msg_buf, sizeof(msg_buf), "<i>(\"%s\")</i>", s);
    xfree(s);
    extra_msg = msg_buf;
  }
  print_string_editing_row_2(f, "Problem handling plugin file:",
                             prob->plugin_file,
                             SSERV_CMD_PROB_CHANGE_PLUGIN_FILE,
                             SSERV_CMD_PROB_CLEAR_PLUGIN_FILE,
                             extra_msg,
                             session_id, form_row_attrs[row ^= 1],
                             self_url, extra_args, prob_hidden_vars);

  //PROBLEM_PARAM(test_dir, "s"),
  extra_msg = 0;
  if (prob->abstract && !prob->test_dir[0]) extra_msg = "<i>(Undefined)</i>";
  if (!prob->abstract) {
    prepare_set_prob_value(PREPARE_FIELD_PROB_TEST_DIR,
                           &tmp_prob, sup_prob, sstate->global);
    s = html_armor_string_dup(tmp_prob.test_dir);
    if (!prob->test_dir[0])
      snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - \"%s\")</i>", s);
    else
      snprintf(msg_buf, sizeof(msg_buf), "<i>(\"%s\")</i>", s);
    xfree(s);
    extra_msg = msg_buf;
  }
  print_string_editing_row_2(f, "Directory with tests:", prob->test_dir,
                             SSERV_CMD_PROB_CHANGE_TEST_DIR,
                             SSERV_CMD_PROB_CLEAR_TEST_DIR,
                             extra_msg,
                             session_id, form_row_attrs[row ^= 1],
                             self_url, extra_args, prob_hidden_vars);

  if (!prob->abstract) {
    prepare_set_prob_value(PREPARE_FIELD_PROB_TEST_SFX,
                           &tmp_prob, sup_prob, sstate->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_TEST_PAT,
                           &tmp_prob, sup_prob, sstate->global);
  }

  //PROBLEM_PARAM(test_sfx, "s"),
  extra_msg = 0;
  if (prob->abstract && (!prob->test_pat[0] || prob->test_pat[0] == 1)) extra_msg = "";
  if (!prob->abstract && !tmp_prob.test_pat[0]) {
    s = html_armor_string_dup(tmp_prob.test_sfx);
    if (prob->test_sfx[0] == 1)
      snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - \"%s\")</i>", s);
    else
      snprintf(msg_buf, sizeof(msg_buf), "<i>(\"%s\")</i>", s);
    xfree(s);
    extra_msg = msg_buf;
  }
  if (extra_msg)
    print_string_editing_row_3(f, "Suffix of test files:", prob->test_sfx,
                               SSERV_CMD_PROB_CHANGE_TEST_SFX,
                               SSERV_CMD_PROB_CLEAR_TEST_SFX,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);

  //PROBLEM_PARAM(test_pat, "s"),
  extra_msg = 0;
  if (show_adv && prob->abstract) extra_msg = "";
  if (!prob->abstract && (show_adv || tmp_prob.test_pat[0])) {
    extra_msg = "";
    s = html_armor_string_dup(tmp_prob.test_pat);
    if (prob->test_pat[0] == 1)
      snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - \"%s\")</i>", s);
    else
      snprintf(msg_buf, sizeof(msg_buf), "<i>(\"%s\")</i>", s);
    xfree(s);
    extra_msg = msg_buf;
  }
  if (extra_msg)
    print_string_editing_row_3(f,
                               "Pattern for test file names (overrides test_suffix):",
                               prob->test_pat,
                               SSERV_CMD_PROB_CHANGE_TEST_PAT,
                               SSERV_CMD_PROB_CLEAR_TEST_PAT,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);

  //PROBLEM_PARAM(use_corr, "d"),
  extra_msg = 0;
  if (!prob->abstract) {
    prepare_set_prob_value(PREPARE_FIELD_PROB_USE_CORR,
                           &tmp_prob, sup_prob, sstate->global);
    snprintf(msg_buf, sizeof(msg_buf), "Default (%s)", tmp_prob.use_corr?"Yes":"No");
    extra_msg = msg_buf;
  }
  print_boolean_3_select_row(f, "Use \"correct answer\" files for check:",
                             prob->use_corr,
                             SSERV_CMD_PROB_CHANGE_USE_CORR,
                             extra_msg,
                             session_id, form_row_attrs[row ^= 1],
                             self_url, extra_args, prob_hidden_vars);

  //PROBLEM_PARAM(corr_dir, "s"),
  extra_msg = 0;
  if (prob->abstract && prob->use_corr == 1) {
    extra_msg = "";
    if (prob->abstract && !prob->corr_dir[0]) extra_msg = "<i>(Undefined)</i>";
  }
  if (!prob->abstract && tmp_prob.use_corr) {
    prepare_set_prob_value(PREPARE_FIELD_PROB_CORR_DIR,
                           &tmp_prob, sup_prob, sstate->global);
    s = html_armor_string_dup(tmp_prob.corr_dir);
    if (!prob->corr_dir[0])
      snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - \"%s\")</i>", s);
    else
      snprintf(msg_buf, sizeof(msg_buf), "<i>(\"%s\")</i>", s);
    xfree(s);
    extra_msg = msg_buf;
  }
  if (extra_msg) {
    print_string_editing_row_2(f, "Directory with \"correct answer\" files:",
                               prob->corr_dir,
                               SSERV_CMD_PROB_CHANGE_CORR_DIR,
                               SSERV_CMD_PROB_CLEAR_CORR_DIR,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
  }

  if (!prob->abstract) {
    prepare_set_prob_value(PREPARE_FIELD_PROB_CORR_SFX,
                           &tmp_prob, sup_prob, sstate->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_CORR_PAT,
                           &tmp_prob, sup_prob, sstate->global);
  }

  //PROBLEM_PARAM(corr_sfx, "s"),
  extra_msg = 0;
  if (prob->abstract && prob->use_corr == 1
      && (!prob->corr_pat[0] || prob->corr_pat[0] == 1)) extra_msg = "";
  if (!prob->abstract && tmp_prob.use_corr && !tmp_prob.corr_pat[0]) {
    s = html_armor_string_dup(tmp_prob.corr_sfx);
    if (prob->corr_sfx[0] == 1)
      snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - \"%s\")</i>", s);
    else
      snprintf(msg_buf, sizeof(msg_buf), "<i>(\"%s\")</i>", s);
    xfree(s);
    extra_msg = msg_buf;
  }
  if (extra_msg)
    print_string_editing_row_3(f, "Suffix of \"correct answer\" files:", prob->corr_sfx,
                               SSERV_CMD_PROB_CHANGE_CORR_SFX,
                               SSERV_CMD_PROB_CLEAR_CORR_SFX,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);

  //PROBLEM_PARAM(corr_pat, "s"),
  extra_msg = 0;
  if (show_adv && prob->abstract && prob->use_corr == 1) extra_msg = "";
  if (!prob->abstract && tmp_prob.use_corr
      && (show_adv || tmp_prob.corr_pat[0])) {
    extra_msg = "";
    s = html_armor_string_dup(tmp_prob.corr_pat);
    if (prob->corr_pat[0] == 1)
      snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - \"%s\")</i>", s);
    else
      snprintf(msg_buf, sizeof(msg_buf), "<i>(\"%s\")</i>", s);
    xfree(s);
    extra_msg = msg_buf;
  }
  if (extra_msg)
    print_string_editing_row_3(f,
                               "Pattern for \"correct answer\" file names (overrides corr_suffix):",
                               prob->corr_pat,
                               SSERV_CMD_PROB_CHANGE_CORR_PAT,
                               SSERV_CMD_PROB_CLEAR_CORR_PAT,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);

  //PROBLEM_PARAM(use_info, "d"),
  extra_msg = 0;
  if (!prob->abstract) {
    prepare_set_prob_value(PREPARE_FIELD_PROB_USE_INFO,
                           &tmp_prob, sup_prob, sstate->global);
    snprintf(msg_buf, sizeof(msg_buf), "Default (%s)", tmp_prob.use_info?"Yes":"No");
    extra_msg = msg_buf;
  }
  print_boolean_3_select_row(f, "Use test info files for check:",
                             prob->use_info,
                             SSERV_CMD_PROB_CHANGE_USE_INFO,
                             extra_msg,
                             session_id, form_row_attrs[row ^= 1],
                             self_url, extra_args, prob_hidden_vars);

  //PROBLEM_PARAM(info_dir, "s"),
  extra_msg = 0;
  if (prob->abstract && prob->use_info == 1) {
    extra_msg = "";
    if (prob->abstract && !prob->info_dir[0]) extra_msg = "<i>(Undefined)</i>";
  }
  if (!prob->abstract && tmp_prob.use_info) {
    prepare_set_prob_value(PREPARE_FIELD_PROB_INFO_DIR,
                           &tmp_prob, sup_prob, sstate->global);
    s = html_armor_string_dup(tmp_prob.info_dir);
    if (!prob->info_dir[0])
      snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - \"%s\")</i>", s);
    else
      snprintf(msg_buf, sizeof(msg_buf), "<i>(\"%s\")</i>", s);
    xfree(s);
    extra_msg = msg_buf;
  }
  if (extra_msg) {
    print_string_editing_row_2(f, "Directory with test info files:",
                               prob->info_dir,
                               SSERV_CMD_PROB_CHANGE_INFO_DIR,
                               SSERV_CMD_PROB_CLEAR_INFO_DIR,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
  }

  if (!prob->abstract) {
    prepare_set_prob_value(PREPARE_FIELD_PROB_INFO_SFX,
                           &tmp_prob, sup_prob, sstate->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_INFO_PAT,
                           &tmp_prob, sup_prob, sstate->global);
  }

  //PROBLEM_PARAM(info_sfx, "s"),
  extra_msg = 0;
  if (prob->abstract && prob->use_info == 1
      && (!prob->info_pat[0] || prob->info_pat[0] == 1)) extra_msg = "";
  if (!prob->abstract && tmp_prob.use_info && !tmp_prob.info_pat[0]) {
    s = html_armor_string_dup(tmp_prob.info_sfx);
    if (prob->info_sfx[0] == 1)
      snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - \"%s\")</i>", s);
    else
      snprintf(msg_buf, sizeof(msg_buf), "<i>(\"%s\")</i>", s);
    xfree(s);
    extra_msg = msg_buf;
  }
  if (extra_msg)
    print_string_editing_row_3(f, "Suffix of test info:", prob->info_sfx,
                               SSERV_CMD_PROB_CHANGE_INFO_SFX,
                               SSERV_CMD_PROB_CLEAR_INFO_SFX,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);

  //PROBLEM_PARAM(info_pat, "s"),
  extra_msg = 0;
  if (show_adv && prob->abstract && prob->use_info == 1) extra_msg = "";
  if (!prob->abstract && tmp_prob.use_info
      && (show_adv || tmp_prob.info_pat[0])) {
    extra_msg = "";
    s = html_armor_string_dup(tmp_prob.info_pat);
    if (prob->info_pat[0] == 1)
      snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - \"%s\")</i>", s);
    else
      snprintf(msg_buf, sizeof(msg_buf), "<i>(\"%s\")</i>", s);
    xfree(s);
    extra_msg = msg_buf;
  }
  if (extra_msg)
    print_string_editing_row_3(f,
                               "Pattern for test info file names (overrides info_suffix):",
                               prob->info_pat,
                               SSERV_CMD_PROB_CHANGE_INFO_PAT,
                               SSERV_CMD_PROB_CLEAR_INFO_PAT,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);

  //PROBLEM_PARAM(time_limit, "d"),
  extra_msg = "";
  if (prob->abstract) {
    if (prob->time_limit == -1) extra_msg = "<i>(Undefined)</i>";
    else if (!prob->time_limit) extra_msg = "<i>(Unlimited)</i>";
  } else {
    if (prob->time_limit == -1) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_TIME_LIMIT,
                             &tmp_prob, sup_prob, sstate->global);
      if (!tmp_prob.time_limit)
        snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - Unlimited)</i>");
      else
        snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - %d)</i>",
                 tmp_prob.time_limit);
      extra_msg = msg_buf;
    } else if (!prob->time_limit) extra_msg = "<i>(Unlimited)</i>";
  }
  if (!problem_type_flag) {
    print_int_editing_row(f, "Processor time limit (sec):",
                          prob->time_limit, extra_msg,
                          SSERV_CMD_PROB_CHANGE_TIME_LIMIT,
                          session_id, form_row_attrs[row ^= 1],
                          self_url, extra_args, prob_hidden_vars);
  }

  //PROBLEM_PARAM(time_limit_millis, "d"),
  extra_msg = "";
  if (prob->abstract) {
    if (prob->time_limit_millis == -1) extra_msg = "<i>(Undefined)</i>";
    else if (!prob->time_limit_millis) extra_msg = "<i>(Unlimited)</i>";
  } else {
    if (prob->time_limit_millis == -1) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_TIME_LIMIT_MILLIS,
                             &tmp_prob, sup_prob, sstate->global);
      if (!tmp_prob.time_limit_millis)
        snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - Unlimited)</i>");
      else
        snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - %d)</i>",
                 tmp_prob.time_limit_millis);
      extra_msg = msg_buf;
    } else if (!prob->time_limit_millis) extra_msg = "<i>(Unlimited)</i>";
  }
  if (!problem_type_flag) {
    print_int_editing_row(f, "Processor time limit (ms, ovverides prev. limit):",
                          prob->time_limit_millis, extra_msg,
                          SSERV_CMD_PROB_CHANGE_TIME_LIMIT_MILLIS,
                          session_id, form_row_attrs[row ^= 1],
                          self_url, extra_args, prob_hidden_vars);
  }

  //PROBLEM_PARAM(real_time_limit, "d"),
  extra_msg = "";
  if (prob->abstract) {
    if (prob->real_time_limit == -1) extra_msg = "<i>(Undefined)</i>";
    else if (!prob->real_time_limit) extra_msg = "<i>(Unlimited)</i>";
  } else {
    if (prob->real_time_limit == -1) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_REAL_TIME_LIMIT,
                             &tmp_prob, sup_prob, sstate->global);
      if (!tmp_prob.real_time_limit)
        snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - Unlimited)</i>");
      else
        snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - %d)</i>",
                 tmp_prob.real_time_limit);
      extra_msg = msg_buf;
    } else if (!prob->real_time_limit) extra_msg = "<i>(Unlimited)</i>";
  }
  if (!problem_type_flag) {
    print_int_editing_row(f, "Real time limit (sec):",
                          prob->real_time_limit, extra_msg,
                          SSERV_CMD_PROB_CHANGE_REAL_TIME_LIMIT,
                          session_id, form_row_attrs[row ^= 1],
                          self_url, extra_args, prob_hidden_vars);
  }

  //PROBLEM_PARAM(max_vm_size, "d"),
  extra_msg = "";
  if (prob->abstract) {
    /*
    if (prob->max_vm_size == -1L) extra_msg = "<i>(Undefined)</i>";
    else if (!prob->max_vm_size) extra_msg = "<i>(OS Limit)</i>";
    */
    if (prob->max_vm_size == -1L || !prob->max_vm_size)
      extra_msg = "<i>(OS Limit)</i>";
  } else {
    if (prob->max_vm_size == -1L) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_MAX_VM_SIZE,
                             &tmp_prob, sup_prob, sstate->global);
      if (tmp_prob.max_vm_size == -1L || !tmp_prob.max_vm_size)
        snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - OS Limit)</i>");
      else
        snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - %s)</i>",
                 size_t_to_size(num_buf, sizeof(num_buf), tmp_prob.max_vm_size));
      extra_msg = msg_buf;
    } else if (!prob->max_vm_size) extra_msg = "<i>(OS Limit)</i>";
  }
  if (prob->max_vm_size == -1L) {
    snprintf(num_buf, sizeof(num_buf), "-1");
  } else {
    size_t_to_size(num_buf, sizeof(num_buf), tmp_prob.max_vm_size);
  }
  if (!problem_type_flag) {
    html_start_form(f, 1, self_url, prob_hidden_vars);
    fprintf(f, "<tr%s><td>%s</td><td>", form_row_attrs[row ^= 1],
            "Maximum virtual memory size:");
    html_edit_text_form(f, 0, 0, "param", num_buf);
    fprintf(f, "%s</td><td>", extra_msg);
    html_submit_button(f, SSERV_CMD_PROB_CHANGE_MAX_VM_SIZE, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  if (!problem_type_flag && show_adv) {
    //PROBLEM_PARAM(max_stack_size, "d"),
    extra_msg = "";
    if (prob->abstract) {
      /*
      if (prob->max_stack_size == -1L) extra_msg = "<i>(Undefined)</i>";
      else if (!prob->max_stack_size) extra_msg = "<i>(OS Limit)</i>";
      */
      if (prob->max_stack_size == -1L || !prob->max_stack_size)
        extra_msg = "<i>(OS Limit)</i>";
    } else {
      if (prob->max_stack_size == -1L) {
        prepare_set_prob_value(PREPARE_FIELD_PROB_MAX_STACK_SIZE,
                               &tmp_prob, sup_prob, sstate->global);
        if (tmp_prob.max_stack_size == -1L || !tmp_prob.max_stack_size)
          snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - OS Limit)</i>");
        else
          snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - %s)</i>",
                   num_to_size(num_buf, sizeof(num_buf), tmp_prob.max_stack_size));
        extra_msg = msg_buf;
      } else if (!prob->max_stack_size) extra_msg = "<i>(OS Limit)</i>";
    }
    if (prob->max_stack_size == -1L) {
      snprintf(num_buf, sizeof(num_buf), "-1");
    } else {
      num_to_size(num_buf, sizeof(num_buf), tmp_prob.max_stack_size);
    }
    html_start_form(f, 1, self_url, prob_hidden_vars);
    fprintf(f, "<tr%s><td>%s</td><td>",
            form_row_attrs[row ^= 1], "Maximum stack size:");
    html_edit_text_form(f, 0, 0, "param", num_buf);
    fprintf(f, "%s</td><td>", extra_msg);
    html_submit_button(f, SSERV_CMD_PROB_CHANGE_MAX_STACK_SIZE, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  //PROBLEM_PARAM(checker_real_time_limit, "d"),
  if (show_adv) {
    extra_msg = "";
    if (prob->abstract) {
      if (prob->checker_real_time_limit == -1) extra_msg = "<i>(Undefined)</i>";
      else if (!prob->checker_real_time_limit) extra_msg = "<i>(Unlimited)</i>";
    } else {
      if (prob->checker_real_time_limit == -1) {
        prepare_set_prob_value(PREPARE_FIELD_PROB_CHECKER_REAL_TIME_LIMIT,
                               &tmp_prob, sup_prob, sstate->global);
        if (!tmp_prob.checker_real_time_limit)
          snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - Unlimited)</i>");
        else
          snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - %d)</i>",
                   tmp_prob.checker_real_time_limit);
        extra_msg = msg_buf;
      } else if (!prob->checker_real_time_limit) extra_msg = "<i>(Unlimited)</i>";
    }
    print_int_editing_row(f, "Real time limit for checker (sec):",
                          prob->checker_real_time_limit, extra_msg,
                          SSERV_CMD_PROB_CHANGE_CHECKER_REAL_TIME_LIMIT,
                          session_id, form_row_attrs[row ^= 1],
                          self_url, extra_args, prob_hidden_vars);
  }

  if (show_adv) {
    //PROBLEM_PARAM(team_enable_rep_view, "d"),
    extra_msg = "Undefined";
    tmp_prob.team_enable_rep_view = prob->team_enable_rep_view;
    if (!prob->abstract) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_TEAM_ENABLE_REP_VIEW,
                             &tmp_prob, sup_prob, sstate->global);
      snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
               tmp_prob.team_enable_rep_view?"Yes":"No");
      extra_msg = msg_buf;
    }
    print_boolean_3_select_row(f, "Contestant may view testing protocol:",
                               prob->team_enable_rep_view,
                               SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_REP_VIEW,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);

    if (tmp_prob.team_enable_rep_view != 1) {
      //PROBLEM_PARAM(team_enable_ce_view, "d"),
      extra_msg = "Undefined";
      if (!prob->abstract) {
        prepare_set_prob_value(PREPARE_FIELD_PROB_TEAM_ENABLE_CE_VIEW,
                               &tmp_prob, sup_prob, sstate->global);
        snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
                 tmp_prob.team_enable_ce_view?"Yes":"No");
        extra_msg = msg_buf;
      }
      print_boolean_3_select_row(f, "Contestant may view compilation errors:",
                                 prob->team_enable_ce_view,
                                 SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_CE_VIEW,
                                 extra_msg,
                                 session_id, form_row_attrs[row ^= 1],
                                 self_url, extra_args, prob_hidden_vars);
    }

    if (tmp_prob.team_enable_rep_view != 0) {
      //PROBLEM_PARAM(team_show_judge_report, "d"),
      extra_msg = "Undefined";
      if (!prob->abstract) {
        prepare_set_prob_value(PREPARE_FIELD_PROB_TEAM_SHOW_JUDGE_REPORT,
                               &tmp_prob, sup_prob, sstate->global);
        snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
                 tmp_prob.team_show_judge_report?"Yes":"No");
        extra_msg = msg_buf;
      }
      print_boolean_3_select_row(f,"Contestant may view FULL (judge's) testing protocol:",
                                 prob->team_show_judge_report,
                                 SSERV_CMD_PROB_CHANGE_TEAM_SHOW_JUDGE_REPORT,
                                 extra_msg,
                                 session_id, form_row_attrs[row ^= 1],
                                 self_url, extra_args, prob_hidden_vars);
    }

    //PROBLEM_PARAM(ignore_compile_errors, "d"),
    extra_msg = "Undefined";
    tmp_prob.ignore_compile_errors = prob->ignore_compile_errors;
    if (!prob->abstract) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_IGNORE_COMPILE_ERRORS,
                             &tmp_prob, sup_prob, sstate->global);
      snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
               tmp_prob.ignore_compile_errors?"Yes":"No");
      extra_msg = msg_buf;
    }
    print_boolean_3_select_row(f, "Ignore compilation errors:",
                               prob->ignore_compile_errors,
                               SSERV_CMD_PROB_CHANGE_IGNORE_COMPILE_ERRORS,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);

    //PROBLEM_PARAM(disable_user_submit, "d"),
    extra_msg = "Undefined";
    tmp_prob.disable_user_submit = prob->disable_user_submit;
    if (!prob->abstract) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_DISABLE_USER_SUBMIT,
                             &tmp_prob, sup_prob, sstate->global);
      snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
               tmp_prob.disable_user_submit?"Yes":"No");
      extra_msg = msg_buf;
    }
    print_boolean_3_select_row(f, "Disable user submissions:",
                               prob->disable_user_submit,
                               SSERV_CMD_PROB_CHANGE_DISABLE_USER_SUBMIT,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);

    if (global && global->problem_navigation > 0) {
      //PROBLEM_PARAM(disable_tab, "d"),
      extra_msg = "Undefined";
      tmp_prob.disable_tab = prob->disable_tab;
      if (!prob->abstract) {
        prepare_set_prob_value(PREPARE_FIELD_PROB_DISABLE_TAB,
                               &tmp_prob, sup_prob, sstate->global);
        snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
                 tmp_prob.disable_tab?"Yes":"No");
        extra_msg = msg_buf;
      }
      print_boolean_3_select_row(f, "Disable problem tab:",
                                 prob->disable_tab,
                                 SSERV_CMD_PROB_CHANGE_DISABLE_TAB,
                                 extra_msg,
                                 session_id, form_row_attrs[row ^= 1],
                                 self_url, extra_args, prob_hidden_vars);
    }

    //PROBLEM_PARAM(restricted_statement, "d"),
    extra_msg = "Undefined";
    tmp_prob.restricted_statement = prob->restricted_statement;
    if (!prob->abstract) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_RESTRICTED_STATEMENT,
                             &tmp_prob, sup_prob, sstate->global);
      snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
               tmp_prob.restricted_statement?"Yes":"No");
      extra_msg = msg_buf;
    }
    print_boolean_3_select_row(f, "Restricted problem statement:",
                               prob->restricted_statement,
                               SSERV_CMD_PROB_CHANGE_RESTRICTED_STATEMENT,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);

    //PROBLEM_PARAM(disable_submit_after_ok, "d"),
    extra_msg = "Undefined";
    tmp_prob.disable_submit_after_ok = prob->disable_submit_after_ok;
    if (!prob->abstract) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_DISABLE_SUBMIT_AFTER_OK,
                             &tmp_prob, sup_prob, sstate->global);
      snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
               tmp_prob.disable_submit_after_ok?"Yes":"No");
      extra_msg = msg_buf;
    }
    print_boolean_3_select_row(f, "Disable submissions after OK:",
                               prob->disable_submit_after_ok,
                               SSERV_CMD_PROB_CHANGE_DISABLE_SUBMIT_AFTER_OK,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);

    //PROBLEM_PARAM(disable_testing, "d"),
    extra_msg = "Undefined";
    tmp_prob.disable_testing = prob->disable_testing;
    if (!prob->abstract) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_DISABLE_TESTING,
                             &tmp_prob, sup_prob, sstate->global);
      snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
               tmp_prob.disable_testing?"Yes":"No");
      extra_msg = msg_buf;
    }
    print_boolean_3_select_row(f, "Disable any testing of submissions:",
                               prob->disable_testing,
                               SSERV_CMD_PROB_CHANGE_DISABLE_TESTING,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);

    if (tmp_prob.disable_testing != 1) {
      //PROBLEM_PARAM(disable_auto_testing, "d"),
      extra_msg = "Undefined";
      tmp_prob.disable_auto_testing = prob->disable_auto_testing;
      if (!prob->abstract) {
        prepare_set_prob_value(PREPARE_FIELD_PROB_DISABLE_AUTO_TESTING,
                               &tmp_prob, sup_prob, sstate->global);
        snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
                 tmp_prob.disable_auto_testing?"Yes":"No");
        extra_msg = msg_buf;
      }
      print_boolean_3_select_row(f, "Disable automatic testing of submissions:",
                                 prob->disable_auto_testing,
                                 SSERV_CMD_PROB_CHANGE_DISABLE_AUTO_TESTING,
                                 extra_msg,
                                 session_id, form_row_attrs[row ^= 1],
                                 self_url, extra_args, prob_hidden_vars);
    }

    if (!problem_type_flag && tmp_prob.disable_testing == 1) {
      //PROBLEM_PARAM(enable_compilation, "d"),
      extra_msg = "Undefined";
      tmp_prob.enable_compilation = prob->enable_compilation;
      if (!prob->abstract) {
        prepare_set_prob_value(PREPARE_FIELD_PROB_ENABLE_COMPILATION,
                               &tmp_prob, sup_prob, sstate->global);
        snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
                 tmp_prob.enable_compilation?"Yes":"No");
        extra_msg = msg_buf;
      }
      print_boolean_3_select_row(f, "Still compile runs to mark as ACCEPTED:",
                                 prob->enable_compilation,
                                 SSERV_CMD_PROB_CHANGE_ENABLE_COMPILATION,
                                 extra_msg,
                                 session_id, form_row_attrs[row ^= 1],
                                 self_url, extra_args, prob_hidden_vars);
    }
  } /* show_adv */

  if (show_adv) {
    //PROBLEM_PARAM(ignore_exit_code, "d"),
    extra_msg = 0;
    if (!prob->abstract) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_IGNORE_EXIT_CODE,
                             &tmp_prob, sup_prob, sstate->global);
      snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
               tmp_prob.ignore_exit_code?"Yes":"No");
      extra_msg = msg_buf;
    }
    print_boolean_3_select_row(f, "Ignore exit code?", prob->ignore_exit_code,
                               SSERV_CMD_PROB_CHANGE_IGNORE_EXIT_CODE,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
  }

  if (sstate->global && sstate->global->score_system_val == SCORE_KIROV
      && show_adv) {
    //PROBLEM_PARAM(olympiad_mode, "d"),
    extra_msg = 0;
    if (!prob->abstract) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_OLYMPIAD_MODE,
                             &tmp_prob, sup_prob, sstate->global);
      snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
               tmp_prob.olympiad_mode?"Yes":"No");
      extra_msg = msg_buf;
    }
    print_boolean_3_select_row(f, "Use Olympiad mode?", prob->olympiad_mode,
                               SSERV_CMD_PROB_CHANGE_OLYMPIAD_MODE,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
  }

  if (sstate->global && sstate->global->score_system_val == SCORE_KIROV
      && show_adv) {
    //PROBLEM_PARAM(score_latest, "d"),
    extra_msg = 0;
    if (!prob->abstract) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_SCORE_LATEST,
                             &tmp_prob, sup_prob, sstate->global);
      snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
               tmp_prob.score_latest?"Yes":"No");
      extra_msg = msg_buf;
    }
    print_boolean_3_select_row(f, "Score the latest submit?", prob->score_latest,
                               SSERV_CMD_PROB_CHANGE_SCORE_LATEST,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
  }

  if (sstate->global && sstate->global->score_system_val != SCORE_ACM) {
    //PROBLEM_PARAM(full_score, "d"),
    extra_msg = "";
    if (prob->full_score == -1) {
      if (prob->abstract) {
        extra_msg = "<i>(Undefined)</i>";
      } else {
        prepare_set_prob_value(PREPARE_FIELD_PROB_FULL_SCORE,
                               &tmp_prob, sup_prob, sstate->global);
        snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - %d)</i>",
                 tmp_prob.full_score);
        extra_msg = msg_buf;
      }
    }
    print_int_editing_row(f, "Score for full solution:",
                          prob->full_score, extra_msg,
                          SSERV_CMD_PROB_CHANGE_FULL_SCORE,
                          session_id, form_row_attrs[row ^= 1],
                          self_url, extra_args, prob_hidden_vars);
  }

  if (sstate->global &&
      (sstate->global->score_system_val == SCORE_KIROV
       || sstate->global->score_system_val == SCORE_OLYMPIAD)) {
    if (show_adv) {
      //PROBLEM_PARAM(variable_full_score, "d"),
      extra_msg = "Undefined";
      if (!prob->abstract) {
        prepare_set_prob_value(PREPARE_FIELD_PROB_VARIABLE_FULL_SCORE,
                               &tmp_prob, sup_prob, sstate->global);
        snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
                 tmp_prob.variable_full_score?"Yes":"No");
        extra_msg = msg_buf;
      }
      print_boolean_3_select_row(f, "Allow variable score for full solution:",
                                 prob->variable_full_score,
                                 SSERV_CMD_PROB_CHANGE_VARIABLE_FULL_SCORE,
                                 extra_msg,
                                 session_id, form_row_attrs[row ^= 1],
                                 self_url, extra_args, prob_hidden_vars);
    }

    //PROBLEM_PARAM(test_score, "d"),
    extra_msg = "";
    if (prob->test_score == -1) {
      if (prob->abstract) {
        extra_msg = "<i>(Undefined)</i>";
      } else {
        prepare_set_prob_value(PREPARE_FIELD_PROB_TEST_SCORE,
                               &tmp_prob, sup_prob, sstate->global);
        snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - %d)</i>",
                 tmp_prob.test_score);
        extra_msg = msg_buf;
      }
    }
    print_int_editing_row(f, "Default score for 1 passed test:",
                          prob->test_score, extra_msg,
                          SSERV_CMD_PROB_CHANGE_TEST_SCORE,
                          session_id, form_row_attrs[row ^= 1],
                          self_url, extra_args, prob_hidden_vars);

    if (sstate->global->score_system_val == SCORE_KIROV) {
      //PROBLEM_PARAM(run_penalty, "d"),
      extra_msg = "";
      if (prob->run_penalty == -1) {
        if (prob->abstract) {
          extra_msg = "<i>(Undefined)</i>";
        } else {
          prepare_set_prob_value(PREPARE_FIELD_PROB_RUN_PENALTY,
                                 &tmp_prob, sup_prob, sstate->global);
          snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - %d)</i>",
                   tmp_prob.run_penalty);
          extra_msg = msg_buf;
        }
      }
      print_int_editing_row(f, "Penalty for a submission:",
                            prob->run_penalty, extra_msg,
                            SSERV_CMD_PROB_CHANGE_RUN_PENALTY,
                            session_id, form_row_attrs[row ^= 1],
                            self_url, extra_args, prob_hidden_vars);
    }

    //PROBLEM_PARAM(disqualified_penalty, "d"),
    extra_msg = "";
    if (prob->disqualified_penalty == -1) {
      if (prob->abstract) {
        extra_msg = "<i>(Undefined)</i>";
      } else {
        prepare_set_prob_value(PREPARE_FIELD_PROB_DISQUALIFIED_PENALTY,
                               &tmp_prob, sup_prob, sstate->global);
        snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - %d)</i>",
                 tmp_prob.disqualified_penalty);
        extra_msg = msg_buf;
      }
    }
    print_int_editing_row(f, "Penalty for a disqualified submission:",
                          prob->disqualified_penalty, extra_msg,
                          SSERV_CMD_PROB_CHANGE_DISQUALIFIED_PENALTY,
                          session_id, form_row_attrs[row ^= 1],
                          self_url, extra_args, prob_hidden_vars);

    //PROBLEM_PARAM(test_score_list, "s"),
    print_string_editing_row(f, "Test scores for tests:", prob->test_score_list,
                             SSERV_CMD_PROB_CHANGE_TEST_SCORE_LIST,
                             SSERV_CMD_PROB_CLEAR_TEST_SCORE_LIST,
                             0,
                             session_id, form_row_attrs[row ^= 1],
                             self_url, extra_args, prob_hidden_vars);
  }

  if ((sstate->global->score_system_val == SCORE_ACM
       || sstate->global->score_system_val == SCORE_MOSCOW)
      && show_adv) {
    //PROBLEM_PARAM(acm_run_penalty, "d"),
    extra_msg = "";
    if (prob->acm_run_penalty == -1) {
      if (prob->abstract) {
        extra_msg = "<i>(Undefined)</i>";
      } else {
        prepare_set_prob_value(PREPARE_FIELD_PROB_ACM_RUN_PENALTY,
                               &tmp_prob, sup_prob, sstate->global);
        snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - %d)</i>",
                 tmp_prob.acm_run_penalty);
        extra_msg = msg_buf;
      }
    }
    print_int_editing_row(f, "Penalty for a submission (minutes):",
                          prob->acm_run_penalty, extra_msg,
                          SSERV_CMD_PROB_CHANGE_ACM_RUN_PENALTY,
                          session_id, form_row_attrs[row ^= 1],
                          self_url, extra_args, prob_hidden_vars);
  }

  if (sstate->global && sstate->global->score_system_val == SCORE_MOSCOW) {
    //PROBLEM_PARAM(score_tests, "s"),
    print_string_editing_row(f, "Tests for problem scores:", prob->score_tests,
                             SSERV_CMD_PROB_CHANGE_SCORE_TESTS,
                             SSERV_CMD_PROB_CLEAR_SCORE_TESTS,
                             0,
                             session_id, form_row_attrs[row ^= 1],
                             self_url, extra_args, prob_hidden_vars);
  }

  if (sstate->global
      && (sstate->global->score_system_val == SCORE_KIROV
          || sstate->global->score_system_val == SCORE_OLYMPIAD)
      && !prob->abstract
      && show_adv) {
    if (!prob->test_sets || !prob->test_sets[0]) {
      extra_msg = "(not set)";
      checker_env = xstrdup("");
    } else {
      extra_msg = "";
      checker_env = sarray_unparse_2(prob->test_sets);
    }
    print_string_editing_row_3(f, "Specially scored test sets:", checker_env,
                               SSERV_CMD_PROB_CHANGE_TEST_SETS,
                               SSERV_CMD_PROB_CLEAR_TEST_SETS,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
    xfree(checker_env);
  }

  //PROBLEM_PARAM(score_bonus, "s"),
  extra_msg = 0;
  if (global && global->score_system_val == SCORE_KIROV) {
    if (prob->abstract && (show_adv || prob->score_bonus[0])) extra_msg = "";
    if (!prob->abstract) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_SCORE_BONUS,
                             &tmp_prob, sup_prob, sstate->global);
      if (show_adv || tmp_prob.score_bonus[0]) {
        s = html_armor_string_dup(tmp_prob.score_bonus);
        snprintf(msg_buf, sizeof(msg_buf), "<i>(%s\"%s\")</i>",
                 prob->score_bonus[0]?"Default - ":"", s);
        xfree(s);
        extra_msg = msg_buf;
      }
    }
  }
  if (extra_msg)
    print_string_editing_row_3(f, "Additional score bonus:", prob->score_bonus,
                               SSERV_CMD_PROB_CHANGE_SCORE_BONUS,
                               SSERV_CMD_PROB_CLEAR_SCORE_BONUS,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);

  if (sstate->global && sstate->global->score_system_val == SCORE_OLYMPIAD) {
    //PROBLEM_PARAM(tests_to_accept, "d"),
    extra_msg = "";
    if (prob->tests_to_accept == -1) {
      if (prob->abstract) {
        extra_msg = "<i>(Undefined)</i>";
      } else {
        prepare_set_prob_value(PREPARE_FIELD_PROB_TESTS_TO_ACCEPT,
                               &tmp_prob, sup_prob, sstate->global);
        snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - %d)</i>",
                 tmp_prob.tests_to_accept);
        extra_msg = msg_buf;
      }
    }
    if (!problem_type_flag) {
      print_int_editing_row(f, "Number of accept tests:",
                            prob->tests_to_accept, extra_msg,
                            SSERV_CMD_PROB_CHANGE_TESTS_TO_ACCEPT,
                            session_id, form_row_attrs[row ^= 1],
                            self_url, extra_args, prob_hidden_vars);
    }

    if (show_adv) {
      //PROBLEM_PARAM(accept_partial, "d"),
      extra_msg = "Undefined";
      if (!prob->abstract) {
        prepare_set_prob_value(PREPARE_FIELD_PROB_ACCEPT_PARTIAL,
                               &tmp_prob, sup_prob, sstate->global);
        snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
                 tmp_prob.accept_partial?"Yes":"No");
        extra_msg = msg_buf;
      }
      if (!problem_type_flag) {
        print_boolean_3_select_row(f, "Accept for testing solutions that do not pass all accept tests:",
                                   prob->accept_partial,
                                   SSERV_CMD_PROB_CHANGE_ACCEPT_PARTIAL,
                                   extra_msg,
                                   session_id, form_row_attrs[row ^= 1],
                                   self_url, extra_args, prob_hidden_vars);
      }

      //PROBLEM_PARAM(min_tests_to_accept, "d"),
      extra_msg = "";
      if (prob->min_tests_to_accept < 0) {
        if (prob->abstract) {
          extra_msg = "<i>(Undefined)</i>";
        } else {
          prepare_set_prob_value(PREPARE_FIELD_PROB_MIN_TESTS_TO_ACCEPT,
                                 &tmp_prob, sup_prob, sstate->global);
          if (tmp_prob.min_tests_to_accept < 0)
            tmp_prob.min_tests_to_accept = tmp_prob.tests_to_accept;
          snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - %d)</i>",
                   tmp_prob.min_tests_to_accept);
          extra_msg = msg_buf;
        }
      }
      if (!problem_type_flag) {
        print_int_editing_row(f, "Min. Number of accept tests:",
                              prob->min_tests_to_accept, extra_msg,
                              SSERV_CMD_PROB_CHANGE_MIN_TESTS_TO_ACCEPT,
                              session_id, form_row_attrs[row ^= 1],
                              self_url, extra_args, prob_hidden_vars);
      }
    }
  }

  if (show_adv) {
    //PROBLEM_PARAM(hidden, "d"),
      extra_msg = "Undefined";
      if (!prob->abstract) {
        prepare_set_prob_value(PREPARE_FIELD_PROB_HIDDEN,
                               &tmp_prob, sup_prob, sstate->global);
        snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
                 tmp_prob.hidden?"Yes":"No");
        extra_msg = msg_buf;
      }
      print_boolean_3_select_row(f, "Do not show this problem in standings:",
                                 prob->hidden,
                                 SSERV_CMD_PROB_CHANGE_HIDDEN,
                                 extra_msg,
                                 session_id, form_row_attrs[row ^= 1],
                                 self_url, extra_args, prob_hidden_vars);
  }

  if (!prob->abstract && show_adv && sstate->global
      && sstate->global->stand_show_ok_time) {
    //PROBLEM_PARAM(stand_hide_time, "d"),
    print_boolean_select_row(f, "Do not show accept time for this problem",
                             prob->stand_hide_time,
                             SSERV_CMD_PROB_CHANGE_STAND_HIDE_TIME,
                             session_id, form_row_attrs[row ^= 1],
                             self_url, extra_args, prob_hidden_vars);

  }

  if (show_adv && sstate->global && sstate->global->problem_navigation) {
    //PROBLEM_PARAM(advance_to_next, "d"),
      extra_msg = "Undefined";
      if (!prob->abstract) {
        prepare_set_prob_value(PREPARE_FIELD_PROB_ADVANCE_TO_NEXT,
                               &tmp_prob, sup_prob, sstate->global);
        snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
                 tmp_prob.advance_to_next?"Yes":"No");
        extra_msg = msg_buf;
      }
      print_boolean_3_select_row(f,"Automatically advance to the next problem:",
                                 prob->advance_to_next,
                                 SSERV_CMD_PROB_CHANGE_ADVANCE_TO_NEXT,
                                 extra_msg,
                                 session_id, form_row_attrs[row ^= 1],
                                 self_url, extra_args, prob_hidden_vars);
  }

  if (show_adv && sstate->global && sstate->global->problem_navigation
      && prob->type_val == PROB_TYPE_OUTPUT_ONLY) {
    //PROBLEM_PARAM(enable_text_form, "d"),
      extra_msg = "Undefined";
      if (!prob->abstract) {
        prepare_set_prob_value(PREPARE_FIELD_PROB_ENABLE_TEXT_FORM,
                               &tmp_prob, sup_prob, sstate->global);
        snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
                 tmp_prob.enable_text_form?"Yes":"No");
        extra_msg = msg_buf;
      }
      print_boolean_3_select_row(f,"Enable text input form anyway:",
                                 prob->enable_text_form,
                                 SSERV_CMD_PROB_CHANGE_ENABLE_TEXT_FORM,
                                 extra_msg,
                                 session_id, form_row_attrs[row ^= 1],
                                 self_url, extra_args, prob_hidden_vars);
  }

  if (show_adv) {
    //PROBLEM_PARAM(stand_attr, "s"),
    extra_msg = 0;
    if (prob->abstract && !prob->use_stdout) extra_msg = "";
    if (!prob->abstract && !tmp_prob.use_stdout) {
      extra_msg = "";
      prepare_set_prob_value(PREPARE_FIELD_PROB_STAND_ATTR,
                             &tmp_prob, sup_prob, sstate->global);
      if (!prob->stand_attr[0]) {
        s = html_armor_string_dup(tmp_prob.stand_attr);
        snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - \"%s\")</i>", s);
        xfree(s);
        extra_msg = msg_buf;
      }
    }
    if (!problem_type_flag && extra_msg) {
      print_string_editing_row_2(f, "Standings attributes:", prob->stand_attr,
                                 SSERV_CMD_PROB_CHANGE_STAND_ATTR,
                                 SSERV_CMD_PROB_CLEAR_STAND_ATTR,
                                 extra_msg,
                                 session_id, form_row_attrs[row ^= 1],
                                 self_url, extra_args, prob_hidden_vars);
    }
  }

  //PROBLEM_PARAM(standard_checker, "s"),
  print_std_checker_row(f, prob, sstate, session_id, form_row_attrs[row ^= 1],
                        self_url, extra_args, prob_hidden_vars);

  //PROBLEM_PARAM(check_cmd, "s"),
  extra_msg = 0;
  if (prob->abstract) extra_msg = "";
  if (!prob->abstract && !prob->standard_checker[0]) {
    extra_msg = "";
    prepare_set_prob_value(PREPARE_FIELD_PROB_CHECK_CMD,
                           &tmp_prob, sup_prob, sstate->global);
    s = html_armor_string_dup(tmp_prob.check_cmd);
    snprintf(msg_buf, sizeof(msg_buf), "<i>(%s\"%s\")</i>",
             prob->check_cmd[0]?"Default - ":"", s);
    xfree(s);
    extra_msg = msg_buf;
  }
  if (extra_msg)
    print_string_editing_row_3(f, "Checker name:", prob->check_cmd,
                               SSERV_CMD_PROB_CHANGE_CHECK_CMD,
                               SSERV_CMD_PROB_CLEAR_CHECK_CMD,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);

  //PROBLEM_PARAM(checker_env, "x"),
  if (!prob->abstract) {
    if (!prob->checker_env || !prob->checker_env[0]) {
      extra_msg = "(not set)";
      checker_env = xstrdup("");
    } else {
      extra_msg = "";
      checker_env = sarray_unparse(prob->checker_env);
    }
    print_string_editing_row_3(f, "Checker environment:", checker_env,
                               SSERV_CMD_PROB_CHANGE_CHECKER_ENV,
                               SSERV_CMD_PROB_CLEAR_CHECKER_ENV,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
    xfree(checker_env);
  }

  //PROBLEM_PARAM(scoring_checker, "d")
  if (show_adv) {
    extra_msg = 0;
    if (!prob->abstract) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_SCORING_CHECKER,
                             &tmp_prob, sup_prob, sstate->global);
      snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
               tmp_prob.scoring_checker?"Yes":"No");
      extra_msg = msg_buf;
    }
    print_boolean_3_select_row(f, "Checker calculates score",
                               prob->scoring_checker,
                               SSERV_CMD_PROB_CHANGE_SCORING_CHECKER,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
  }

  //PROBLEM_PARAM(valuer_cmd, "s"),
  extra_msg = 0;
  if (show_adv) {
    if (prob->abstract) extra_msg = "";
    if (!prob->abstract && !prob->standard_checker[0]) {
      extra_msg = "";
      prepare_set_prob_value(PREPARE_FIELD_PROB_VALUER_CMD,
                             &tmp_prob, sup_prob, sstate->global);
      s = html_armor_string_dup(tmp_prob.valuer_cmd);
      snprintf(msg_buf, sizeof(msg_buf), "<i>(%s\"%s\")</i>",
               prob->valuer_cmd[0]?"Default - ":"", s);
      xfree(s);
      extra_msg = msg_buf;
    }
  }
  if (extra_msg)
    print_string_editing_row_3(f, "Score valuer name:", prob->valuer_cmd,
                               SSERV_CMD_PROB_CHANGE_VALUER_CMD,
                               SSERV_CMD_PROB_CLEAR_VALUER_CMD,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);

  //PROBLEM_PARAM(valuer_env, "x"),
  if (!prob->abstract) {
    if (!prob->valuer_env || !prob->valuer_env[0]) {
      extra_msg = "(not set)";
      checker_env = xstrdup("");
    } else {
      extra_msg = "";
      checker_env = sarray_unparse(prob->valuer_env);
    }
    print_string_editing_row_3(f, "Valuer environment:", checker_env,
                               SSERV_CMD_PROB_CHANGE_VALUER_ENV,
                               SSERV_CMD_PROB_CLEAR_VALUER_ENV,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
    xfree(checker_env);
  }

  // PROBLEM_PARAM(score_view, "x")
  if (!prob->abstract && show_adv) {
    if (!prob->score_view || !prob->score_view[0]) {
      extra_msg = "(not set)";
      checker_env = xstrdup("");
    } else {
      extra_msg = "";
      checker_env = sarray_unparse_2(prob->score_view);
    }
    print_string_editing_row_3(f, "Special view for scores:", checker_env,
                               SSERV_CMD_PROB_CHANGE_SCORE_VIEW,
                               SSERV_CMD_PROB_CLEAR_SCORE_VIEW,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
    xfree(checker_env);
  }

  if (show_adv && sstate->global) {
    //PROBLEM_PARAM(stand_ignore_score, "d"),
      extra_msg = "Undefined";
      if (!prob->abstract) {
        prepare_set_prob_value(PREPARE_FIELD_PROB_STAND_IGNORE_SCORE,
                               &tmp_prob, sup_prob, sstate->global);
        snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
                 tmp_prob.stand_ignore_score?"Yes":"No");
        extra_msg = msg_buf;
      }
      print_boolean_3_select_row(f,"Ignore problem score in standings:",
                                 prob->stand_ignore_score,
                                 SSERV_CMD_PROB_CHANGE_STAND_IGNORE_SCORE,
                                 extra_msg,
                                 session_id, form_row_attrs[row ^= 1],
                                 self_url, extra_args, prob_hidden_vars);
  }

  if (show_adv && sstate->global) {
    //PROBLEM_PARAM(stand_last_column, "d"),
      extra_msg = "Undefined";
      if (!prob->abstract) {
        prepare_set_prob_value(PREPARE_FIELD_PROB_STAND_LAST_COLUMN,
                               &tmp_prob, sup_prob, sstate->global);
        snprintf(msg_buf, sizeof(msg_buf), "Default (%s)",
                 tmp_prob.stand_last_column?"Yes":"No");
        extra_msg = msg_buf;
      }
      print_boolean_3_select_row(f,"Show the problem after all results:",
                                 prob->stand_last_column,
                                 SSERV_CMD_PROB_CHANGE_STAND_LAST_COLUMN,
                                 extra_msg,
                                 session_id, form_row_attrs[row ^= 1],
                                 self_url, extra_args, prob_hidden_vars);
  }

  //PROBLEM_PARAM(lang_time_adj, "x"),
  if (!prob->abstract && !problem_type_flag && show_adv) {
    if (!prob->lang_time_adj || !prob->lang_time_adj[0]) {
      extra_msg = "(not set)";
      checker_env = xstrdup("");
    } else {
      extra_msg = "";
      checker_env = sarray_unparse(prob->lang_time_adj);
    }
    print_string_editing_row_3(f, "Language-based time-limit adjustment:", checker_env,
                               SSERV_CMD_PROB_CHANGE_LANG_TIME_ADJ,
                               SSERV_CMD_PROB_CLEAR_LANG_TIME_ADJ,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
    xfree(checker_env);
  }

  //PROBLEM_PARAM(lang_time_adj_millis, "x"),
  if (!prob->abstract && !problem_type_flag && show_adv) {
    if (!prob->lang_time_adj_millis || !prob->lang_time_adj_millis[0]) {
      extra_msg = "(not set)";
      checker_env = xstrdup("");
    } else {
      extra_msg = "";
      checker_env = sarray_unparse(prob->lang_time_adj_millis);
    }
    print_string_editing_row_3(f, "Language-based time-limit adjustment (ms):",
                               checker_env,
                               SSERV_CMD_PROB_CHANGE_LANG_TIME_ADJ_MILLIS,
                               SSERV_CMD_PROB_CLEAR_LANG_TIME_ADJ_MILLIS,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
    xfree(checker_env);
  }

  //PROBLEM_PARAM(disable_language, "x"),
  if (!prob->abstract && show_adv) {
    if (!prob->disable_language || !prob->disable_language[0]) {
      extra_msg = "(not set)";
      checker_env = xstrdup("");
    } else {
      extra_msg = "";
      checker_env = sarray_unparse_2(prob->disable_language);
    }
    print_string_editing_row_3(f, "Disabled languages:", checker_env,
                               SSERV_CMD_PROB_CHANGE_DISABLE_LANGUAGE,
                               SSERV_CMD_PROB_CLEAR_DISABLE_LANGUAGE,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
    xfree(checker_env);
  }

  //PROBLEM_PARAM(enable_language, "x"),
  if (!prob->abstract && show_adv) {
    if (!prob->enable_language || !prob->enable_language[0]) {
      extra_msg = "(not set)";
      checker_env = xstrdup("");
    } else {
      extra_msg = "";
      checker_env = sarray_unparse_2(prob->enable_language);
    }
    print_string_editing_row_3(f, "Enabled languages:", checker_env,
                               SSERV_CMD_PROB_CHANGE_ENABLE_LANGUAGE,
                               SSERV_CMD_PROB_CLEAR_ENABLE_LANGUAGE,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
    xfree(checker_env);
  }

  //PROBLEM_PARAM(require, "x"),
  if (!prob->abstract && show_adv) {
    if (!prob->require || !prob->require[0]) {
      extra_msg = "(not set)";
      checker_env = xstrdup("");
    } else {
      extra_msg = "";
      checker_env = sarray_unparse_2(prob->require);
    }
    print_string_editing_row_3(f, "Required problems:", checker_env,
                               SSERV_CMD_PROB_CHANGE_REQUIRE,
                               SSERV_CMD_PROB_CLEAR_REQUIRE,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
    xfree(checker_env);
  }

  //PROBLEM_PARAM(variant_num, "d"),
  if (!prob->abstract && show_adv) {
    extra_msg = "";
    if (prob->variant_num <= 0) {
      prob->variant_num = 0;
      extra_msg = "<i>(No variants)</i>";
    }

    snprintf(num_buf, sizeof(num_buf), "%d", prob->variant_num);
    html_start_form(f, 1, self_url, prob_hidden_vars);
    fprintf(f, "<tr%s><td>%s</td><td>", form_row_attrs[row ^= 1],
            "Number of variants:");
    html_edit_text_form(f, 0, 0, "param", num_buf);
    fprintf(f, "%s</td><td>", extra_msg);
    html_submit_button(f, SSERV_CMD_PROB_CHANGE_VARIANT_NUM, "Change");
    if (prob->variant_num > 0) {
      fprintf(f, "%sEdit variants</a>",
              html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                            "action=%d", SSERV_CMD_PROB_EDIT_VARIANTS));
    }
    fprintf(f, "</td></tr></form>\n");
  }

  //PROBLEM_PARAM(start_date, "s"),
  if (!prob->abstract && show_adv && !global->contest_time) {
    html_start_form(f, 1, self_url, prob_hidden_vars);
    if (!prob->start_date[0] || xml_parse_date(0,0,0,prob->start_date,&tmp_date) < 0)
      tmp_date = 0;
    fprintf(f, "<tr%s><td>Accept start date:</td><td>",
            form_row_attrs[row ^= 1]);
    html_date_select(f, tmp_date);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_PROB_CHANGE_START_DATE, "Change");
    html_submit_button(f, SSERV_CMD_PROB_CLEAR_START_DATE, "Clear");
    fprintf(f, "</td></tr></form>\n");
  }
  //PROBLEM_PARAM(deadline, "s"),
  if (!prob->abstract && show_adv && !global->contest_time) {
    html_start_form(f, 1, self_url, prob_hidden_vars);
    if (!prob->deadline[0] || xml_parse_date(0, 0, 0, prob->deadline, &tmp_date) < 0)
      tmp_date = 0;
    fprintf(f, "<tr%s><td>Accept deadline:</td><td>", form_row_attrs[row ^= 1]);
    html_date_select(f, tmp_date);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_PROB_CHANGE_DEADLINE, "Change");
    html_submit_button(f, SSERV_CMD_PROB_CLEAR_DEADLINE, "Clear");
    fprintf(f, "</td></tr></form>\n");
  }

  if (show_adv) {
    //PROBLEM_PARAM(source_header, "s"),
    extra_msg = "";
    prepare_set_prob_value(PREPARE_FIELD_PROB_SOURCE_HEADER,
                           &tmp_prob, sup_prob, sstate->global);
    if (!prob->source_header[0]) {
      s = html_armor_string_dup(tmp_prob.source_header);
      snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - \"%s\")</i>", s);
      xfree(s);
      extra_msg = msg_buf;
    }
    print_string_editing_row_2(f, "Source header file:", prob->source_header,
                               SSERV_CMD_PROB_CHANGE_SOURCE_HEADER,
                               SSERV_CMD_PROB_CLEAR_SOURCE_HEADER,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);

    //PROBLEM_PARAM(source_footer, "s"),
    extra_msg = "";
    prepare_set_prob_value(PREPARE_FIELD_PROB_SOURCE_FOOTER,
                           &tmp_prob, sup_prob, sstate->global);
    if (!prob->source_footer[0]) {
      s = html_armor_string_dup(tmp_prob.source_footer);
      snprintf(msg_buf, sizeof(msg_buf), "<i>(Default - \"%s\")</i>", s);
      xfree(s);
      extra_msg = msg_buf;
    }
    print_string_editing_row_2(f, "Source footer file:", prob->source_footer,
                               SSERV_CMD_PROB_CHANGE_SOURCE_FOOTER,
                               SSERV_CMD_PROB_CLEAR_SOURCE_FOOTER,
                               extra_msg,
                               session_id, form_row_attrs[row ^= 1],
                               self_url, extra_args, prob_hidden_vars);
  }

  if (prob->unhandled_vars) {
    s = html_armor_string_dup(prob->unhandled_vars);
    fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Uneditable parameters</td></tr>\n<tr><td colspan=\"3\"><pre>%s</pre></td></tr>\n",
            form_row_attrs[row ^= 1], s);
    xfree(s);
  }
}

int
super_html_edit_problems(FILE *f,
                         int priv_level,
                         int user_id,
                         const unsigned char *login,
                         ej_cookie_t session_id,
                         ej_ip_t ip_address,
                         const struct ejudge_cfg *config,
                         struct sid_state *sstate,
                         const unsigned char *self_url,
                         const unsigned char *hidden_vars,
                         const unsigned char *extra_args)
{
  int i;

  if (sstate->serve_parse_errors) {
    unsigned char *s = html_armor_string_dup(sstate->serve_parse_errors);
    super_html_contest_page_menu(f, session_id, sstate, 4, self_url, hidden_vars,
                                 extra_args);
    fprintf(f, "<h2><tt>serve.cfg</tt> cannot be edited</h2>\n");
    fprintf(f, "<font color=\"red\"><pre>%s</pre></font>\n", s);
    xfree(s);
    return 0;
  }

  super_html_contest_page_menu(f, session_id, sstate, 4, self_url,
                               hidden_vars, extra_args);

  fprintf(f, "<table border=\"0\">\n");
  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Abstract problems</b></td></tr>\n", head_row_attr);

  for (i = 0; i < sstate->aprob_u; i++) {
    super_html_print_problem(f, i, 1, sstate, session_id, self_url,
                             hidden_vars, extra_args);
  }

  // add new abstract problem
  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Add new abstract problem</b></td></tr>\n", prob_row_attr);
  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Name:</td><td>", form_row_attrs[0]);
  html_edit_text_form(f, 0, 0, "prob_name", "");
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_PROB_ADD_ABSTRACT, "Add");
  fprintf(f, "</td></tr></form>\n");


  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Concrete problems</b></td></tr>\n", head_row_attr);

  for (i = 1; i < sstate->prob_a; i++) {
    if (!sstate->probs[i]) continue;
    super_html_print_problem(f, i, 0, sstate, session_id, self_url,
                             hidden_vars, extra_args);
  }

  // add new concrete problem
  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Add new problem</b></td></tr>\n", prob_row_attr);
  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Id (optional):</td><td>", form_row_attrs[0]);
  html_edit_text_form(f, 0, 0, "prob_id", "");
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_PROB_ADD, "Add");
  fprintf(f, "</td></tr></form>\n");

  fprintf(f, "</table>\n");

  super_html_contest_footer_menu(f, session_id, sstate,
                                 self_url, hidden_vars, extra_args);


  return 0;
}

int
super_html_prob_cmd(struct sid_state *sstate, int cmd,
                    int prob_id, const unsigned char *param2,
                    int param3, int param4)
{
  int i;
  struct section_problem_data *prob;
  int new_val_1, new_val_2;

  switch (cmd) {
  case SSERV_CMD_PROB_ADD:
    if (prob_id < 0 || prob_id > 999999)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (!prob_id) {
      for (i = 1; i < sstate->prob_a; i++)
        if (!sstate->probs[i])
          break;
      prob_id = i;
    }

    if (prob_id >= sstate->prob_a) {
      int new_prob_a = sstate->prob_a;
      struct section_problem_data **new_probs;
      int *new_flags;

      if (!new_prob_a) new_prob_a = 16;
      while (prob_id >= new_prob_a) new_prob_a *= 2;
      XCALLOC(new_probs, new_prob_a);
      XCALLOC(new_flags, new_prob_a);
      if (sstate->prob_a) {
        XMEMMOVE(new_probs, sstate->probs, sstate->prob_a);
        XMEMMOVE(new_flags, sstate->prob_flags, sstate->prob_a);
      }
      xfree(sstate->probs);
      xfree(sstate->prob_flags);
      sstate->probs = new_probs;
      sstate->prob_flags = new_flags;
      sstate->prob_a = new_prob_a;
    }
 
    if (sstate->probs[prob_id])
      return -SSERV_ERR_DUPLICATED_PROBLEM;

    prob = prepare_alloc_problem();
    prepare_problem_init_func(&prob->g);
    sstate->cfg = param_merge(&prob->g, sstate->cfg);
    sstate->probs[prob_id] = prob;
    prob->id = prob_id;
    sstate->prob_flags[prob_id] = 0;
    snprintf(prob->short_name, sizeof(prob->short_name), "%c", '@' + prob->id);
    if (sstate->aprob_u == 1)
      snprintf(prob->super, sizeof(prob->super), "%s", sstate->aprobs[0]->short_name);
    prob->variant_num = 0;
    return 0;

  case SSERV_CMD_PROB_ADD_ABSTRACT:
    if (!param2 || !*param2) return -SSERV_ERR_INVALID_PARAMETER;
    if (check_str(param2, login_accept_chars) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    for (i = 0; i < sstate->aprob_u; i++)
      if (!strcmp(sstate->aprobs[i]->short_name, param2))
        break;
    if (i < sstate->aprob_u)
      return -SSERV_ERR_DUPLICATED_PROBLEM;
    if (i == sstate->aprob_a) {
      if (!sstate->aprob_a) sstate->aprob_a = 4;
      sstate->aprob_a *= 2;
      XREALLOC(sstate->aprobs, sstate->aprob_a);
      XREALLOC(sstate->aprob_flags, sstate->aprob_a);
    }
    prob = prepare_alloc_problem();
    prepare_problem_init_func(&prob->g);
    sstate->cfg = param_merge(&prob->g, sstate->cfg);
    sstate->aprobs[i] = prob;
    sstate->aprob_flags[i] = 0;
    sstate->aprob_u++;
    snprintf(prob->short_name, sizeof(prob->short_name), "%s", param2);
    prob->abstract = 1;
    prob->type_val = 0;
    prob->manual_checking = 0;
    prob->examinator_num = 0;
    prob->check_presentation = 0;
    prob->scoring_checker = 0;
    prob->use_stdin = 1;
    prob->use_stdout = 1;
    prob->binary_input = DFLT_P_BINARY_INPUT;
    prob->ignore_exit_code = 0;
    prob->olympiad_mode = 0;
    prob->score_latest = 0;
    prob->time_limit = 5;
    prob->time_limit_millis = 0;
    prob->real_time_limit = 30;
    snprintf(prob->test_dir, sizeof(prob->test_sfx), "%s", "%Ps");
    snprintf(prob->test_sfx, sizeof(prob->test_sfx), "%s", ".dat");
    prob->use_corr = 1;
    snprintf(prob->corr_dir, sizeof(prob->corr_dir), "%s", "%Ps");
    snprintf(prob->corr_sfx, sizeof(prob->corr_sfx), "%s", ".ans");
    prob->use_info = 0;
    snprintf(prob->info_dir, sizeof(prob->info_dir), "%s", "%Ps");
    snprintf(prob->info_sfx, sizeof(prob->info_sfx), "%s", ".inf");
    prob->use_tgz = 0;
    snprintf(prob->tgz_dir, sizeof(prob->tgz_dir), "%s", "%Ps");
    snprintf(prob->tgz_sfx, sizeof(prob->tgz_sfx), "%s", ".tgz");
    snprintf(prob->check_cmd, sizeof(prob->check_cmd), "%s", "check_%Ps");
    prob->max_vm_size = 64 * SIZE_M;
    prob->variant_num = 0;
    return 0;

  case SSERV_CMD_PROB_SHOW_DETAILS:
    new_val_1 = SID_STATE_SHOW_HIDDEN;
    new_val_2 = 0;
    goto do_handle_details_flag;
  case SSERV_CMD_PROB_HIDE_DETAILS:
    new_val_1 = 0;
    new_val_2 = SID_STATE_SHOW_HIDDEN;
    goto do_handle_details_flag;
  case SSERV_CMD_PROB_SHOW_ADVANCED:
    new_val_1 = SID_STATE_SHOW_CLOSED;
    new_val_2 = 0;
    goto do_handle_details_flag;
  case SSERV_CMD_PROB_HIDE_ADVANCED:
    new_val_1 = 0;
    new_val_2 = SID_STATE_SHOW_CLOSED;
    goto do_handle_details_flag;
  do_handle_details_flag:;
    if (prob_id <= 0) {
      prob_id = -prob_id;
      if (prob_id >= sstate->aprob_u)
        return -SSERV_ERR_INVALID_PARAMETER;
      sstate->aprob_flags[prob_id] |= new_val_1;
      sstate->aprob_flags[prob_id] &= ~new_val_2;
    } else {
      if (prob_id >= sstate->prob_a || !sstate->probs[prob_id])
        return -SSERV_ERR_INVALID_PARAMETER;
      sstate->prob_flags[prob_id] |= new_val_1;
      sstate->prob_flags[prob_id] &= ~new_val_2;
    }
    return 0;

  default:
    abort();
  }
}

#define PROB_ASSIGN_STRING(f) snprintf(prob->f, sizeof(prob->f), "%s", param2)
#define PROB_CLEAR_STRING(f) prob->f[0] = 0

static int
num_suffix(const unsigned char *str)
{
  if (!str[0]) return 1;
  if (str[1]) return 0; 
  if (str[0] == 'k' || str[0] == 'K') return 1024;
  if (str[0] == 'm' || str[0] == 'M') return 1024 * 1024;
  if (str[0] == 'g' || str[0] == 'G') return 1024 * 1024 * 1024;
  return 0;
}

int
super_html_prob_param(struct sid_state *sstate, int cmd,
                      int prob_id, const unsigned char *param2,
                      int param3, int param4)
{
  struct section_problem_data *prob;
  int i, n, val, mult;
  int *p_int;
  time_t tmp_date;
  unsigned char *p_str;
  size_t str_size;
  char **tmp_env = 0;
  size_t *p_size, zval;

  if (prob_id > 0) {
    if (prob_id >= sstate->prob_a || !sstate->probs[prob_id])
      return -SSERV_ERR_INVALID_PARAMETER;
    prob = sstate->probs[prob_id];
  } else {
    prob_id = -prob_id;
    if (prob_id >= sstate->aprob_u || !sstate->aprobs[prob_id])
      return -SSERV_ERR_INVALID_PARAMETER;
    prob = sstate->aprobs[prob_id];
  }

  switch (cmd) {
  case SSERV_CMD_PROB_DELETE:
    if (prob->abstract && prob->short_name[0]) {
      for (i = 1; i < sstate->prob_a; i++)
        if (sstate->probs[i]
            && !strcmp(sstate->probs[i]->short_name, prob->short_name))
          break;
      if (i < sstate->prob_a) return -SSERV_ERR_PROBLEM_IS_USED;
      for (i = prob_id + 1; i < sstate->aprob_u; i++) {
        sstate->aprobs[i - 1] = sstate->aprobs[i];
        sstate->aprob_flags[i - 1] = sstate->aprob_flags[i];
      }
      sstate->aprob_u--;
      sstate->aprobs[sstate->aprob_u] = 0;
      sstate->aprob_flags[sstate->aprob_u] = 0;
    } else {
      sstate->probs[prob_id] = 0;
      sstate->prob_flags[prob_id] = 0;
    }
    return 0;
  case SSERV_CMD_PROB_CHANGE_SHORT_NAME:
    if (!param2 || !*param2 || check_str(param2, login_accept_chars) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (prob->abstract) {
      for (i = 0; i < sstate->aprob_u; i++)
        if (i != prob_id && !strcmp(sstate->aprobs[i]->short_name, param2))
          break;
      if (i < sstate->aprob_u)
        return -SSERV_ERR_DUPLICATED_PROBLEM;
    }
    PROB_ASSIGN_STRING(short_name);
    return 0;

  case SSERV_CMD_PROB_CLEAR_SHORT_NAME:
    if (prob->abstract) return -SSERV_ERR_INVALID_PARAMETER;
    PROB_CLEAR_STRING(short_name);
    return 0;

  case SSERV_CMD_PROB_CHANGE_LONG_NAME:
    PROB_ASSIGN_STRING(long_name);
    return 0;

  case SSERV_CMD_PROB_CLEAR_LONG_NAME:
    PROB_CLEAR_STRING(long_name);
    return 0;

  case SSERV_CMD_PROB_CHANGE_SUPER:
    if (prob->abstract) return -SSERV_ERR_INVALID_PARAMETER;
    if (!param2 || sscanf(param2, "%d%n", &val, &n) != 1 || param2[n])
      return -SSERV_ERR_INVALID_PARAMETER;
    if (val < 0 || val > sstate->aprob_u)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (!val) {
      prob->super[0] = 0;
    } else {
      val--;
      if (!sstate->aprobs[val]) return -SSERV_ERR_INVALID_PARAMETER;
      snprintf(prob->super, sizeof(prob->super), "%s", sstate->aprobs[val]->short_name);
    }
    return 0;

  case SSERV_CMD_PROB_CHANGE_TYPE:
    if (!param2 || sscanf(param2, "%d%n", &val, &n) != 1 || param2[n])
      return -SSERV_ERR_INVALID_PARAMETER;
    if (val < -1 || val >= PROB_TYPE_LAST)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (prob->abstract && val < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    prob->type_val = val;
    return 0;

  case SSERV_CMD_PROB_CHANGE_SCORING_CHECKER:
    p_int = &prob->scoring_checker;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_MANUAL_CHECKING:
    p_int = &prob->manual_checking;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_EXAMINATOR_NUM:
    if (!param2 || sscanf(param2, "%d%n", &val, &n) != 1 || param2[n]
        || val < 0 || val > 3)
      return -SSERV_ERR_INVALID_PARAMETER;
    prob->examinator_num = val;
    return 0;

  case SSERV_CMD_PROB_CHANGE_CHECK_PRESENTATION:
    p_int = &prob->check_presentation;
    goto handle_boolean_1;
    
  case SSERV_CMD_PROB_CHANGE_USE_STDIN:
    p_int = &prob->use_stdin;

  handle_boolean_1:
    if (!param2 || sscanf(param2, "%d%n", &val, &n) != 1 || param2[n])
      return -SSERV_ERR_INVALID_PARAMETER;
    if (prob->abstract) {
      if (val < 0 || val > 1) return -SSERV_ERR_INVALID_PARAMETER;
    } else {
      if (val < -1 || val > 1) return -SSERV_ERR_INVALID_PARAMETER;
    }
    *p_int = val;
    return 0;

  case SSERV_CMD_PROB_CHANGE_USE_STDOUT:
    p_int = &prob->use_stdout;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_BINARY_INPUT:
    p_int = &prob->binary_input;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_IGNORE_EXIT_CODE:
    p_int = &prob->ignore_exit_code;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_OLYMPIAD_MODE:
    p_int = &prob->olympiad_mode;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_SCORE_LATEST:
    p_int = &prob->score_latest;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_TIME_LIMIT:
    p_int = &prob->time_limit;

  handle_int_1:
    if (!param2 || sscanf(param2, "%d%n", &val, &n) != 1 || param2[n])
      return -SSERV_ERR_INVALID_PARAMETER;
    if (val < -1) return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    return 0;

  case SSERV_CMD_PROB_CHANGE_TIME_LIMIT_MILLIS:
    p_int = &prob->time_limit_millis;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_REAL_TIME_LIMIT:
    p_int = &prob->real_time_limit;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_REP_VIEW:
    p_int = &prob->team_enable_rep_view;

  handle_boolean_2:
    if (!param2 || sscanf(param2, "%d%n", &val, &n) != 1 || param2[n])
      return -SSERV_ERR_INVALID_PARAMETER;
    if (val < -1 || val > 1) return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    return 0;

  case SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_CE_VIEW:
    p_int = &prob->team_enable_ce_view;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_TEAM_SHOW_JUDGE_REPORT:
    p_int = &prob->team_show_judge_report;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_IGNORE_COMPILE_ERRORS:
    p_int = &prob->ignore_compile_errors;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_DISABLE_USER_SUBMIT:
    p_int = &prob->disable_user_submit;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_DISABLE_TAB:
    p_int = &prob->disable_tab;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_RESTRICTED_STATEMENT:
    p_int = &prob->restricted_statement;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_DISABLE_SUBMIT_AFTER_OK:
    p_int = &prob->disable_submit_after_ok;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_DISABLE_TESTING:
    p_int = &prob->disable_testing;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_DISABLE_AUTO_TESTING:
    p_int = &prob->disable_auto_testing;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_ENABLE_COMPILATION:
    p_int = &prob->enable_compilation;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_FULL_SCORE:
    p_int = &prob->full_score;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_TEST_SCORE:
    p_int = &prob->test_score;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_RUN_PENALTY:
    p_int = &prob->run_penalty;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_ACM_RUN_PENALTY:
    p_int = &prob->acm_run_penalty;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_DISQUALIFIED_PENALTY:
    p_int = &prob->disqualified_penalty;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_VARIABLE_FULL_SCORE:
    p_int = &prob->variable_full_score;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_TEST_SCORE_LIST:
    // FIXME: check for correctness
    PROB_ASSIGN_STRING(test_score_list);
    return 0;

  case SSERV_CMD_PROB_CLEAR_TEST_SCORE_LIST:
    PROB_CLEAR_STRING(test_score_list);
    return 0;

  case SSERV_CMD_PROB_CHANGE_SCORE_TESTS:
    // FIXME: check for correctness
    PROB_ASSIGN_STRING(score_tests);
    return 0;

  case SSERV_CMD_PROB_CLEAR_SCORE_TESTS:
    PROB_CLEAR_STRING(score_tests);
    return 0;

  case SSERV_CMD_PROB_CHANGE_TESTS_TO_ACCEPT:
    p_int = &prob->tests_to_accept;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_ACCEPT_PARTIAL:
    p_int = &prob->accept_partial;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_MIN_TESTS_TO_ACCEPT:
    p_int = &prob->min_tests_to_accept;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_HIDDEN:
    p_int = &prob->hidden;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_STAND_HIDE_TIME:
    p_int = &prob->stand_hide_time;

    if (!param2 || sscanf(param2, "%d%n", &val, &n) != 1 || param2[n])
      return -SSERV_ERR_INVALID_PARAMETER;
    if (val < 0 || val > 1) return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    return 0;

  case SSERV_CMD_PROB_CHANGE_ADVANCE_TO_NEXT:
    p_int = &prob->advance_to_next;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_ENABLE_TEXT_FORM:
    p_int = &prob->enable_text_form;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_STAND_IGNORE_SCORE:
    p_int = &prob->stand_ignore_score;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_STAND_LAST_COLUMN:
    p_int = &prob->stand_last_column;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_CHECKER_REAL_TIME_LIMIT:
    p_int = &prob->checker_real_time_limit;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_MAX_VM_SIZE:
    p_size = &prob->max_vm_size;

  handle_size_t:
    if (!param2) return -SSERV_ERR_INVALID_PARAMETER;
    if (sscanf(param2, "%d%n", &val, &n) == 1 && !param2[n] && val == -1) {
      *p_size = -1L;
      return 0;
    }
    if (sscanf(param2, "%zu%n", &zval, &n) != 1)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (!(mult = num_suffix(param2 + n))) return -SSERV_ERR_INVALID_PARAMETER;
    // FIXME: check for overflow
    zval *= mult;
    *p_size = zval;
    return 0;

  case SSERV_CMD_PROB_CHANGE_MAX_STACK_SIZE:
    p_size = &prob->max_stack_size;
    goto handle_size_t;

  case SSERV_CMD_PROB_CHANGE_INPUT_FILE:
    PROB_ASSIGN_STRING(input_file);
    return 0;

  case SSERV_CMD_PROB_CLEAR_INPUT_FILE:
    PROB_CLEAR_STRING(input_file);
    return 0;

  case SSERV_CMD_PROB_CHANGE_OUTPUT_FILE:
    PROB_ASSIGN_STRING(output_file);
    return 0;

  case SSERV_CMD_PROB_CLEAR_OUTPUT_FILE:
    PROB_CLEAR_STRING(output_file);
    return 0;

  case SSERV_CMD_PROB_CHANGE_USE_CORR:
    p_int = &prob->use_corr;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_USE_INFO:
    p_int = &prob->use_info;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_TEST_DIR:
    PROB_ASSIGN_STRING(test_dir);
    return 0;

  case SSERV_CMD_PROB_CLEAR_TEST_DIR:
    PROB_CLEAR_STRING(test_dir);
    return 0;

  case SSERV_CMD_PROB_CHANGE_CORR_DIR:
    PROB_ASSIGN_STRING(corr_dir);
    return 0;

  case SSERV_CMD_PROB_CLEAR_CORR_DIR:
    PROB_CLEAR_STRING(corr_dir);
    return 0;

  case SSERV_CMD_PROB_CHANGE_INFO_DIR:
    PROB_ASSIGN_STRING(info_dir);
    return 0;

  case SSERV_CMD_PROB_CLEAR_INFO_DIR:
    PROB_CLEAR_STRING(info_dir);
    return 0;

  case SSERV_CMD_PROB_CHANGE_TEST_SFX:
    PROB_ASSIGN_STRING(test_sfx);
    return 0;

  case SSERV_CMD_PROB_CLEAR_TEST_SFX:
    prob->test_sfx[0] = 1;
    prob->test_sfx[1] = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_TEST_PAT:
    PROB_ASSIGN_STRING(test_pat);
    return 0;

  case SSERV_CMD_PROB_CLEAR_TEST_PAT:
    prob->test_pat[0] = 1;
    prob->test_pat[1] = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_CORR_SFX:
    PROB_ASSIGN_STRING(corr_sfx);
    return 0;

  case SSERV_CMD_PROB_CLEAR_CORR_SFX:
    prob->corr_sfx[0] = 1;
    prob->corr_sfx[1] = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_CORR_PAT:
    PROB_ASSIGN_STRING(corr_pat);
    return 0;

  case SSERV_CMD_PROB_CLEAR_CORR_PAT:
    prob->corr_pat[0] = 1;
    prob->corr_pat[1] = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_INFO_SFX:
    PROB_ASSIGN_STRING(info_sfx);
    return 0;

  case SSERV_CMD_PROB_CLEAR_INFO_SFX:
    prob->info_sfx[0] = 1;
    prob->info_sfx[1] = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_INFO_PAT:
    PROB_ASSIGN_STRING(info_pat);
    return 0;

  case SSERV_CMD_PROB_CLEAR_INFO_PAT:
    prob->info_pat[0] = 1;
    prob->info_pat[1] = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_STANDARD_CHECKER:
    if (!param2 || !*param2) {
      PROB_CLEAR_STRING(standard_checker);
    } else if (check_str(param2, login_accept_chars) < 0) {
      return -SSERV_ERR_INVALID_PARAMETER;
    } else {
      PROB_ASSIGN_STRING(standard_checker);
    }
    return 0;

  case SSERV_CMD_PROB_CHANGE_SCORE_BONUS:
    // FIXME: check string for correctness
    PROB_ASSIGN_STRING(score_bonus);
    return 0;

  case SSERV_CMD_PROB_CLEAR_SCORE_BONUS:
    PROB_CLEAR_STRING(score_bonus);
    return 0;

  case SSERV_CMD_PROB_CHANGE_CHECK_CMD:
    PROB_ASSIGN_STRING(check_cmd);
    return 0;

  case SSERV_CMD_PROB_CLEAR_CHECK_CMD:
    PROB_CLEAR_STRING(check_cmd);
    return 0;

  case SSERV_CMD_PROB_CHANGE_CHECKER_ENV:
    if (sarray_parse(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->checker_env);
    prob->checker_env = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_CHECKER_ENV:
    sarray_free(prob->checker_env);
    prob->checker_env = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_VALUER_CMD:
    PROB_ASSIGN_STRING(valuer_cmd);
    return 0;

  case SSERV_CMD_PROB_CLEAR_VALUER_CMD:
    PROB_CLEAR_STRING(valuer_cmd);
    return 0;

  case SSERV_CMD_PROB_CHANGE_VALUER_ENV:
    if (sarray_parse(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->valuer_env);
    prob->valuer_env = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_VALUER_ENV:
    sarray_free(prob->valuer_env);
    prob->valuer_env = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_LANG_TIME_ADJ:
    if (sarray_parse(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->lang_time_adj);
    prob->lang_time_adj = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_LANG_TIME_ADJ:
    sarray_free(prob->lang_time_adj);
    prob->lang_time_adj = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_LANG_TIME_ADJ_MILLIS:
    if (sarray_parse(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->lang_time_adj_millis);
    prob->lang_time_adj_millis = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_LANG_TIME_ADJ_MILLIS:
    sarray_free(prob->lang_time_adj_millis);
    prob->lang_time_adj_millis = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_DISABLE_LANGUAGE:
    if (sarray_parse(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->disable_language);
    prob->disable_language = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_DISABLE_LANGUAGE:
    sarray_free(prob->disable_language);
    prob->disable_language = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_ENABLE_LANGUAGE:
    if (sarray_parse(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->enable_language);
    prob->enable_language = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_ENABLE_LANGUAGE:
    sarray_free(prob->enable_language);
    prob->enable_language = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_REQUIRE:
    if (sarray_parse(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->require);
    prob->require = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_REQUIRE:
    sarray_free(prob->require);
    prob->require = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_TEST_SETS:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->test_sets);
    prob->test_sets = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_TEST_SETS:
    sarray_free(prob->test_sets);
    prob->test_sets = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_SCORE_VIEW:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->score_view);
    prob->score_view = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_SCORE_VIEW:
    sarray_free(prob->score_view);
    prob->score_view = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_START_DATE:
    p_str = prob->start_date; str_size = sizeof(prob->start_date);
  handle_date:;
    if (xml_parse_date(0, 0, 0, param2, &tmp_date) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    snprintf(p_str, str_size, "%s", xml_unparse_date(tmp_date));
    return 0;

  case SSERV_CMD_PROB_CLEAR_START_DATE:
    PROB_CLEAR_STRING(start_date);
    return 0;

  case SSERV_CMD_PROB_CHANGE_DEADLINE:
    p_str = prob->deadline; str_size = sizeof(prob->deadline);
    goto handle_date;

  case SSERV_CMD_PROB_CLEAR_DEADLINE:
    PROB_CLEAR_STRING(deadline);
    return 0;

  case SSERV_CMD_PROB_CHANGE_VARIANT_NUM:
    p_int = &prob->variant_num;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_STATEMENT_FILE:
    PROB_ASSIGN_STRING(statement_file);
    return 0;

  case SSERV_CMD_PROB_CLEAR_STATEMENT_FILE:
    PROB_CLEAR_STRING(statement_file);
    return 0;

  case SSERV_CMD_PROB_CHANGE_ALTERNATIVES_FILE:
    PROB_ASSIGN_STRING(alternatives_file);
    return 0;

  case SSERV_CMD_PROB_CLEAR_ALTERNATIVES_FILE:
    PROB_CLEAR_STRING(alternatives_file);
    return 0;

  case SSERV_CMD_PROB_CHANGE_PLUGIN_FILE:
    PROB_ASSIGN_STRING(plugin_file);
    return 0;

  case SSERV_CMD_PROB_CLEAR_PLUGIN_FILE:
    PROB_CLEAR_STRING(plugin_file);
    return 0;

  case SSERV_CMD_PROB_CHANGE_STAND_ATTR:
    PROB_ASSIGN_STRING(stand_attr);
    return 0;

  case SSERV_CMD_PROB_CLEAR_STAND_ATTR:
    PROB_CLEAR_STRING(stand_attr);
    return 0;

  case SSERV_CMD_PROB_CHANGE_SOURCE_HEADER:
    PROB_ASSIGN_STRING(source_header);
    return 0;

  case SSERV_CMD_PROB_CLEAR_SOURCE_HEADER:
    PROB_CLEAR_STRING(source_header);
    return 0;

  case SSERV_CMD_PROB_CHANGE_SOURCE_FOOTER:
    PROB_ASSIGN_STRING(source_footer);
    return 0;

  case SSERV_CMD_PROB_CLEAR_SOURCE_FOOTER:
    PROB_CLEAR_STRING(source_footer);
    return 0;

  default:
    abort();
  }
}

static void
unparse_serve_cfg(FILE *f,
                  const struct ejudge_cfg *config,
                  const struct sid_state *sstate)
{
  struct section_global_data *global = sstate->global;
  struct contest_desc *cnts = sstate->edited_cnts;
  int i, active_langs, need_variant_map = 0;

  if (!global) return;
  if (sstate->serve_parse_errors) return;

  if (cnts) {
    global->contest_id = cnts->id;
    if (cnts->root_dir)
      snprintf(global->root_dir, sizeof(global->root_dir), "%s", cnts->root_dir);
    if (cnts->conf_dir)
      snprintf(global->conf_dir, sizeof(global->conf_dir), "%s", cnts->conf_dir);
  }
  if (sstate->enable_stand2 && !global->stand2_file_name[0]) {
    strcpy(global->stand2_file_name, "standings2.html");
  }
  if (!sstate->enable_stand2) global->stand2_file_name[0] = 0;
  if (sstate->enable_plog && !global->plog_file_name[0]) {
    strcpy(global->plog_file_name, "plog.html");
  }
  if (!sstate->enable_plog) global->plog_file_name[0] = 0;
  if (sstate->enable_extra_col && !global->stand_extra_format[0]) {
    strcpy(global->stand_extra_format, "%Mc");
  }
  if (!sstate->enable_extra_col) global->stand_extra_format[0] = 0;

  for (i = 1; i < sstate->prob_a; i++)
    if (sstate->probs[i] && sstate->probs[i]->variant_num > 0)
      need_variant_map = 1;

  prepare_unparse_global(f, global, sstate->compile_home_dir, need_variant_map);

  if (sstate->lang_a > 0) {
    for (i = 1, active_langs = 0; i < sstate->lang_a; i++) {
      if (!sstate->langs[i]) continue;
      prepare_unparse_lang(f, sstate->langs[i], 0, sstate->lang_opts[i]);
      active_langs++;
    }
  }

  for (i = 0; i < sstate->aprob_u; i++)
    prepare_unparse_prob(f, sstate->aprobs[i], global, global->score_system_val);

  for (i = 0; i < sstate->prob_a; i++) {
    if (!sstate->probs[i]) continue;
    prepare_unparse_prob(f, sstate->probs[i], global, global->score_system_val);
  }

  prepare_unparse_testers(f, global->secure_run,
                          sstate->global,
                          sstate->lang_a,
                          sstate->langs,
                          sstate->aprob_u,
                          sstate->aprobs,
                          sstate->prob_a,
                          sstate->probs,
                          sstate->atester_total,
                          sstate->atesters,
                          config->testing_work_dir,
                          config->contests_home_dir);
}

int
super_html_serve_unparse_and_save(
        const unsigned char *path,
        const unsigned char *tmp_path,
        const struct sid_state *sstate,
        const struct ejudge_cfg *config,
        const unsigned char *charset,
        const unsigned char *header,
        const unsigned char *footer,
        const unsigned char *audit)
{
  char *new_text = 0;
  size_t new_size = 0;
  char *old_text = 0;
  size_t old_size = 0;
  FILE *f;

  if (sstate->serve_parse_errors || !sstate->global) return 0;

  if (!charset || !*charset) charset = INTERNAL_CHARSET;
  if (!header) header = "";
  if (!footer) footer = "";
  f = open_memstream(&new_text, &new_size);
  fprintf(f, "# -*- coding: %s -*-\n", charset);
  fputs(header, f);
  unparse_serve_cfg(f, config, sstate);
  fputs(footer, f);
  fclose(f); f = 0;

  if (generic_read_file(&old_text, 0, &old_size, 0, 0, path, 0) >= 0
      && new_size == old_size && memcmp(new_text, old_text, new_size) == 0) {
    info("serve_unparse_and_save: %s not changed", path);
    xfree(old_text);
    xfree(new_text);
    unlink(tmp_path);
    return 0;
  }
  xfree(old_text); old_text = 0; old_size = 0;

  if (!(f = fopen(tmp_path, "w"))) {
    xfree(new_text);
    return -1;
  }
  fwrite(new_text, 1, new_size, f);
  xfree(new_text); new_text = 0; new_size = 0;
  fputs(audit, f);
  if (ferror(f) || fclose(f) < 0) {
    fclose(f);
    unlink(tmp_path);
    return -1;
  }

  return 1;
}

int
super_html_view_new_serve_cfg(FILE *f,
                              int priv_level,
                              int user_id,
                              const unsigned char *login,
                              ej_cookie_t session_id,
                              ej_ip_t ip_address,
                              const struct ejudge_cfg *config,
                              struct sid_state *sstate,
                              const unsigned char *self_url,
                              const unsigned char *hidden_vars,
                              const unsigned char *extra_args)
{
  char *out_text = 0;
  size_t out_size = 0;
  FILE *tmpf = 0;
  unsigned char *s;

  tmpf = open_memstream(&out_text, &out_size);
  unparse_serve_cfg(tmpf, config, sstate);
  fclose(tmpf); tmpf = 0;
  s = html_armor_string_dup(out_text);
  fprintf(f, "<pre>%s</pre>\n", s);
  xfree(s); s = 0;
  xfree(out_text); out_text = 0; out_size = 0;
  return 0;
}

int
super_html_get_serve_header_and_footer(const unsigned char *path,
                                       unsigned char **p_header,
                                       unsigned char **p_footer)
{
  struct stat sb;
  char *text = 0;
  size_t size = 0;
  int at_beg = 1;
  unsigned char *s, *after_start = 0, *before_end = 0, *tstart, *p = 0;
  unsigned char *header = 0, *footer = 0;

  if (stat(path, &sb) < 0) return -SSERV_ERR_FILE_NOT_EXIST;
  if (generic_read_file(&text, 0, &size, 0, 0, path, 0) < 0)
    return -SSERV_ERR_FILE_READ_ERROR;

  tstart = (unsigned char *) text;
  if (!strncmp(tstart, "# -*- ", 6)) {
    while (*tstart && *tstart != '\n') tstart++;
    if (*tstart == '\n') tstart++;
  }

  s = tstart;
  while (s - tstart < size) {
    if (at_beg) {
      if (*s == '#' || *s == ';') {
        // comment line
        if (after_start && !before_end) before_end = s;
      } else {
        // regular line
        if (!after_start) after_start = s;
        else before_end = 0;
      }
    }
    at_beg = 0;
    if (*s == '\r' && s[1] == '\n') {
      s += 2;
      at_beg = 1;
    } else if (*s == '\n') {
      s++;
      at_beg = 1;
    } else if (*s == '\r') {
      s++;
      at_beg = 1;
    } else {
      s++;
    }
  }

  if (!before_end) {
    footer = xstrdup("");
  } else {
    footer = p = xmalloc(size + 1 - (before_end - tstart));
    at_beg = 1;
    s = before_end;
    while (s - tstart < size) {
      if (at_beg && (*s == '#' || *s == ';')) *s = '#';
      at_beg = 0;
      if (*s == '\r' && s[1] == '\n') {
        *p++ = '\n';
        s += 2;
        at_beg = 1;
      } else if (*s == '\n') {
        *p++ = *s++;
        at_beg = 1;
      } else if (*s == '\r') {
        *p++ = '\n';
        s++;
        at_beg = 1;
      } else {
        *p++ = *s++;
      }
    }
    *p = 0;
  }

  if (!after_start) after_start = tstart + size;
  header = p = xmalloc(after_start - tstart + 1);
  at_beg = 1;
  s = tstart;
  while (s != after_start) {
    if (at_beg && (*s == '#' || *s == ';')) *s = '#';
    at_beg = 0;
    if (*s == '\r' && s[1] == '\n') {
      *p++ = '\n';
      s += 2;
      at_beg = 1;
    } else if (*s == '\n') {
      *p++ = *s++;
      at_beg = 1;
    } else if (*s == '\r') {
      *p++ = '\n';
      s++;
      at_beg = 1;
    } else {
      *p++ = *s++;
    }
  }
  *p = 0;

  if (p_header) *p_header = header;
  if (p_footer) *p_footer = footer;

  xfree(text);
  return 0;
}

static unsigned char *
do_load_file(const unsigned char *conf_path, const unsigned char *file)
{
  unsigned char full_path[PATH_MAX];
  char *buf = 0;
  size_t buf_size = 0;

  if (!file || !*file) return 0;

  if (!os_IsAbsolutePath(file)) {
    snprintf(full_path, sizeof(full_path), "%s/%s", conf_path, file);
  } else {
    snprintf(full_path, sizeof(full_path), "%s", file);
  }

  if (generic_read_file(&buf, 0, &buf_size, 0, 0, full_path, 0) < 0) return 0;
  return buf;
}

static const unsigned char compile_dir_suffix[] = "/var/compile";

int
super_html_read_serve(FILE *flog,
                      const unsigned char *path,
                      const struct ejudge_cfg *config,
                      const struct contest_desc *cnts,
                      struct sid_state *sstate)
{
  struct stat sb;
  int cond_count = 0, total, i, cur_id, j, arch, k;
  struct generic_section_config *pg;
  struct section_global_data *global;
  struct section_problem_data *prob, *aprob;
  struct section_tester_data *tst, *atst;
  struct section_language_data *lang;
  size_t vm_size, st_size;
  size_t *mem_lims, *st_lims;
  int *mem_cnt, *st_cnt;
  //int mem_u, st_u, max_i;
  path_t check_cmd = { 0 };
  FILE *fuh;
  char *fuh_text = 0;
  size_t fuh_size = 0;
  path_t cs_spool_dir;
  path_t conf_dir;
  path_t tmppath;
  unsigned char *prob_no_any = 0;
  size_t cs_spool_dir_len = 0;

  if (!cnts) {
    fprintf(flog, "No contest XML description\n");
    return -1;
  }
  if (!cnts->conf_dir || !*cnts->conf_dir) {
    snprintf(conf_dir, sizeof(conf_dir), "%s/%s", cnts->root_dir, "conf");
  } else if (!os_IsAbsolutePath(cnts->conf_dir)) {
    snprintf(conf_dir, sizeof(conf_dir), "%s/%s", cnts->root_dir, cnts->conf_dir);
  } else {
    snprintf(conf_dir, sizeof(conf_dir), "%s", cnts->conf_dir);
  }

  if (stat(path, &sb) < 0) {
    // file do not exist
    return 0;
  }
  if (!S_ISREG(sb.st_mode)) {
    fprintf(flog, "File `%s' not a regular file\n", path);
    return -1;
  }
  if (access(path, R_OK) < 0) {
    fprintf(flog, "File `%s' is not readable\n", path);
    return -1;
  }

  // FIXME: redirect output?
  if (!(sstate->cfg = prepare_parse_config_file(path, &cond_count))) {
    fprintf(flog, "Parsing of `%s' failed\n", path);
    return -1;
  }
  if (cond_count > 0) {
    fprintf(flog, "The configuration file uses conditional compilation directives\n");
    return -1;
  }

  // find global section
  for (pg = sstate->cfg; pg; pg = pg->next)
    if (!pg->name[0] || !strcmp(pg->name, "global"))
      break;
  if (!pg) {
    fprintf(flog, "The global section is not defined\n");
    return -1;
  }
  global = sstate->global = (struct section_global_data *) pg;

  // set up the default value of the root_dir
  if (!global->root_dir[0]) {
    snprintf(global->root_dir, sizeof(global->root_dir), "%06d",
             global->contest_id);
  }
  if (!os_IsAbsolutePath(global->root_dir) && config
      && config->contests_home_dir
      && os_IsAbsolutePath(config->contests_home_dir)) {
    snprintf(tmppath, sizeof(tmppath), "%s/%s", config->contests_home_dir,
             global->root_dir);
    snprintf(global->root_dir, sizeof(global->root_dir), "%s", tmppath);
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!os_IsAbsolutePath(global->root_dir)) {
    snprintf(tmppath, sizeof(tmppath), "%s/%s", EJUDGE_CONTESTS_HOME_DIR,
             global->root_dir);
    snprintf(global->root_dir, sizeof(global->root_dir), "%s", tmppath);
  }
#endif
  if (!os_IsAbsolutePath(global->root_dir)) {
    err("global.root_dir must be absolute directory!");
    return -1;
  }

  // check variables that we don't want to be ever set
  if (prepare_check_forbidden_global(flog, global) < 0) return -1;

  // contest_id, conf_dir, root_dir must match
  if (global->contest_id != cnts->id) {
    fprintf(flog, "contest_id does not match\n");
    return -1;
  }
  if (strcmp(global->root_dir, cnts->root_dir)) {
    fprintf(flog, "root_dir does not match\n");
    return -1;
  }
  /*
  if ((!cnts->conf_dir && global->conf_dir)
      || (cnts->conf_dir && strcmp(cnts->conf_dir, global->conf_dir))) {
    fprintf(flog, "conf_dir does not match\n");
    return -1;
  } 
  */

  // compile server must be used
  if (!global->compile_dir[0]) {
    fprintf(flog, "compilation server is not used\n");
    return -1;
  }
  if (!os_IsAbsolutePath(global->compile_dir)) {
    snprintf(tmppath, sizeof(tmppath), "%s/var/%s", global->root_dir,
             global->compile_dir);
    path_normalize(tmppath, sizeof(tmppath));
    snprintf(global->compile_dir, sizeof(global->compile_dir), "%s", tmppath);
  }
  if (!config->compile_home_dir) {
    fprintf(flog, "compile server home dir is not set\n");
    return -1;
  }
  // cut off "/var/compile" suffix from the compile dir
  snprintf(cs_spool_dir, sizeof(cs_spool_dir), "%s", global->compile_dir);
  cs_spool_dir_len = strlen(cs_spool_dir);
  if (cs_spool_dir_len < sizeof(compile_dir_suffix)
      || strcmp(cs_spool_dir+cs_spool_dir_len-sizeof(compile_dir_suffix)+1,
                compile_dir_suffix) != 0) {
    fprintf(flog, "invalid `compile_dir' %s\n", cs_spool_dir);
    return -1;
  }
  cs_spool_dir[cs_spool_dir_len-sizeof(compile_dir_suffix)+1] = 0;
  sstate->compile_home_dir = xstrdup(cs_spool_dir);
  //fprintf(stderr, "compile_home_dir>>%s<<\n", sstate->compile_home_dir);
  /*
  snprintf(cs_spool_dir, sizeof(cs_spool_dir), "%s/var/compile",
           config->compile_home_dir);
  if (strcmp(cs_spool_dir, global->compile_dir)) {
    fprintf(flog, "non-default compilation server is used\n");
    return -1;
  }
  */

  if (global->stand_ignore_after[0]
      && xml_parse_date("", 0, 0, global->stand_ignore_after,
                        &global->stand_ignore_after_d) < 0)
    return -1;

  if (global->contest_finish_time[0]
      && xml_parse_date("", 0, 0, global->contest_finish_time,
                        &global->contest_finish_time_d) < 0)
    return -1;

  prepare_set_global_defaults(global);
  if (global->stand2_file_name[0]) sstate->enable_stand2 = 1;
  if (global->plog_file_name[0]) sstate->enable_plog = 1;
  if (global->stand_extra_format[0]) sstate->enable_extra_col = 1;

  fuh = open_memstream(&fuh_text, &fuh_size);
  prepare_unparse_unhandled_global(fuh, global);
  fclose(fuh);
  if (fuh_text && *fuh_text) {
    global->unhandled_vars = fuh_text;
  } else {
    xfree(fuh_text);
  }
  fuh_text = 0; fuh_size = 0;

  // collect languages
  total = 0; cur_id = 0;
  for (pg = sstate->cfg; pg; pg = pg->next) {
    if (strcmp(pg->name, "language") != 0) continue;
    lang = (struct section_language_data*) pg;
    if (!lang->id) lang->id = cur_id + 1;
    cur_id = lang->id;
    if (lang->id <= 0 || lang->id > 999999) {
      fprintf(flog, "Invalid language ID\n");
      return -1;
    }
    if (lang->id >= total) total = lang->id + 1;
  }

  sstate->lang_a = 0;
  sstate->langs = 0;
  sstate->loc_cs_map = 0;
  sstate->lang_opts = 0;
  sstate->lang_flags = 0;
  if (total > 0) {
    sstate->lang_a = 4;
    while (total > sstate->lang_a) sstate->lang_a *= 2;
    XCALLOC(sstate->langs, sstate->lang_a);
    XCALLOC(sstate->loc_cs_map, sstate->lang_a);
    XCALLOC(sstate->lang_opts, sstate->lang_a);
    XCALLOC(sstate->lang_flags, sstate->lang_a);
    for (pg = sstate->cfg; pg; pg = pg->next) {
      if (strcmp(pg->name, "language") != 0) continue;
      lang = (struct section_language_data*) pg;
      if (sstate->langs[lang->id]) {
        fprintf(flog, "Duplicated language ID %d\n", lang->id);
        return -1;
      }
      sstate->langs[lang->id] = lang;
    }
  }

  // load the compilation server state and establish correspondence
  if (load_cs_languages(config, sstate, 0) < 0) {
    fprintf(flog, "Failed to load compilation server configuration\n");
    return -1;
  }

  for (i = 1; i < sstate->lang_a; i++) {
    if (!(lang = sstate->langs[i])) continue;
    if (!lang->compile_id) lang->compile_id = lang->id;

    if (prepare_check_forbidden_lang(flog, lang) < 0)
      return -1;

    if (lang->compile_id <= 0 || lang->compile_id >= sstate->cs_lang_total
        || !sstate->cs_langs[lang->compile_id]) {
      fprintf(flog, "Invalid compile_id\n");
      return -1;
    }
    sstate->loc_cs_map[lang->id] = lang->compile_id;
    sstate->cs_loc_map[lang->compile_id] = lang->id;

    fuh = open_memstream(&fuh_text, &fuh_size);
    prepare_unparse_unhandled_lang(fuh, lang);
    fclose(fuh);
    if (fuh_text && *fuh_text) {
      lang->unhandled_vars = fuh_text;
    } else {
      xfree(fuh_text);
    }
    fuh_text = 0; fuh_size = 0;

    if (lang->compiler_env) {
      for (j = 0; lang->compiler_env[j]; j++) {
        if (!strncmp(lang->compiler_env[j], "EJUDGE_FLAGS=", 13)) {
          sstate->lang_opts[lang->id] = xstrmerge1(sstate->lang_opts[lang->id],
                                                   lang->compiler_env[j] + 13);
        }
      }
      for (--j; j >= 0; --j) {
        if (!strncmp(lang->compiler_env[j], "EJUDGE_FLAGS=", 13)) {
          xfree(lang->compiler_env[j]); lang->compiler_env[j] = 0;
          for (k = j + 1; lang->compiler_env[k]; k++) {
            lang->compiler_env[k - 1] = lang->compiler_env[k];
          }
          lang->compiler_env[k - 1] = lang->compiler_env[k];
        }        
      }
    }
  }

  // collect abstract problems
  for (pg = sstate->cfg, total = 0; pg; pg = pg->next) {
    if (!strcmp(pg->name, "problem")
        && (prob = (struct section_problem_data*) pg)->abstract)
      total++;
  }

  sstate->aprob_a = 0;
  sstate->aprob_u = 0;
  sstate->aprobs = 0;
  sstate->aprob_flags = 0;
  if (total) {
    sstate->aprob_a = 4;
    while (total > sstate->aprob_a) sstate->aprob_a *= 2;
    XCALLOC(sstate->aprobs, sstate->aprob_a);
    XCALLOC(sstate->aprob_flags, sstate->aprob_a);
    for (pg = sstate->cfg, i = 0; pg; pg = pg->next) {
      if (strcmp(pg->name, "problem") != 0) continue;
      prob = (struct section_problem_data*) pg;
      if (!prob->abstract) continue;
      sstate->aprobs[i++] = prob;
      if (!prob->short_name[0]) {
        fprintf(flog, "Abstract problem must have `short_name' field set\n");
        return -1;
      }
      if (prob->super[0]) {
        fprintf(flog, "Abstract problem must not have a superproblem\n");
        return -1;
      }

      if (prepare_check_forbidden_prob(flog, prob) < 0)
        return -1;

      prepare_set_abstr_problem_defaults(prob, global);

      fuh = open_memstream(&fuh_text, &fuh_size);
      prepare_unparse_unhandled_prob(fuh, prob, global);
      fclose(fuh);
      if (fuh_text && *fuh_text) {
        prob->unhandled_vars = fuh_text;
      } else {
        xfree(fuh_text);
      }
      fuh_text = 0; fuh_size = 0;
    }
    ASSERT(i == total);
    sstate->aprob_u = total;
  }

  // collect concrete problems
  total = 0; cur_id = 0;
  for (pg = sstate->cfg; pg; pg = pg->next) {
    if (strcmp(pg->name, "problem") != 0) continue;
    prob = (struct section_problem_data*) pg;
    if (prob->abstract) continue;
    if (!prob->id) prob->id = cur_id + 1;
    cur_id = prob->id;
    if (prob->id <= 0 || prob->id > 999999) {
      fprintf(flog, "Invalid problem ID\n");
      return -1;
    }
    if (prob->id >= total) total = prob->id + 1;
  }

  sstate->probs = 0;
  sstate->prob_a = 0;
  sstate->prob_flags = 0;
  if (total > 0) {
    sstate->prob_a = 4;
    while (total > sstate->prob_a) sstate->prob_a *= 2;
    XCALLOC(sstate->probs, sstate->prob_a);
    XCALLOC(sstate->prob_flags, sstate->prob_a);
    XALLOCAZ(prob_no_any, sstate->prob_a);
    for (pg = sstate->cfg; pg; pg = pg->next) {
      if (strcmp(pg->name, "problem") != 0) continue;
      prob = (struct section_problem_data*) pg;
      if (prob->abstract) continue;
      if (sstate->probs[prob->id]) {
        fprintf(flog, "Duplicated problem id %d\n", prob->id);
        return -1;
      }
      sstate->probs[prob->id] = prob;
      if (prob->super[0]) {
        for (i = 0; i < sstate->aprob_u; i++)
          if (!strcmp(prob->super, sstate->aprobs[i]->short_name))
            break;
        if (i == sstate->aprob_u) {
          fprintf(flog, "Abstract problem `%s' not found\n", prob->super);
          return -1;
        }
      }
      if (prepare_check_forbidden_prob(flog, prob) < 0)
        return -1;

      prepare_set_concr_problem_defaults(prob, global);

      fuh = open_memstream(&fuh_text, &fuh_size);
      prepare_unparse_unhandled_prob(fuh, prob, global);
      fclose(fuh);
      if (fuh_text && *fuh_text) {
        prob->unhandled_vars = fuh_text;
      } else {
        xfree(fuh_text);
      }
      fuh_text = 0; fuh_size = 0;
    }
  }

  // collect abstract testers
  total = 0;
  for (pg = sstate->cfg; pg; pg = pg->next) {
    if (strcmp(pg->name, "tester")) continue;
    tst = (struct section_tester_data*) pg;
    if (!tst->abstract) continue;
    // check, that we know such abstract tester
    if ((arch = prepare_unparse_is_supported_tester(tst->name)) < 0) {
      fprintf(flog, "Unsupported abstract tester `%s'\n", tst->name);
      return -1;
    }
    if ((i = prepare_unparse_is_supported_arch(tst->arch)) < 0) {
      fprintf(flog, "Unsupported tester architecture `%s'\n", tst->arch);
      return -1;
    }
    if (i != arch) {
      fprintf(flog, "Abstract tester name does not match tester arch\n");
      return -1;
    }
    if (tst->id) {
      fprintf(flog, "Abstract tester must not define tester ID\n");
      return -1;
    }
    if (tst->problem_name[0]) {
      fprintf(flog, "Abstract tester must not define problem name\n");
      return -1;
    }
    if (tst->problem) {
      fprintf(flog, "Abstract tester must not define problem ID\n");
      return -1;
    }
    total++;
  }

  if (!total) {
    fprintf(flog, "No abstract testers defined\n");
    return -1;
  }

  sstate->atester_total = total;
  XCALLOC(sstate->atesters, sstate->atester_total);
  for (pg = sstate->cfg, i = 0; pg; pg = pg->next) {
    if (strcmp(pg->name, "tester")) continue;
    tst = (struct section_tester_data*) pg;
    if (!tst->abstract) continue;
    sstate->atesters[i++] = tst;
    // FIXME: check for unhandled fields
  }

  // collect concrete testers, attempting to recover vm limit, stack limit
  // and checker name
  total = 0; cur_id = 0;
  for (pg = sstate->cfg; pg; pg = pg->next) {
    if (strcmp(pg->name, "tester") != 0) continue;
    tst = (struct section_tester_data*) pg;
    if (tst->abstract) continue;
    if (!tst->id) tst->id = cur_id + 1;
    cur_id = tst->id;
    if (tst->id <= 0 || tst->id > 999999) {
      fprintf(flog, "Invalid tester ID\n");
      return -1;
    }
    if (tst->id >= total) total = tst->id + 1;
  }

  sstate->tester_total = total;
  XCALLOC(sstate->testers, sstate->tester_total);
  for (pg = sstate->cfg; pg; pg = pg->next) {
    if (strcmp(pg->name, "tester") != 0) continue;
    tst = (struct section_tester_data*) pg;
    if (tst->abstract) continue;
    if (sstate->testers[tst->id]) {
      fprintf(flog, "Duplicated tester ID %d\n", tst->id);
      return -1;
    }
    sstate->testers[tst->id] = tst;
    if (tst->super && tst->super[0] && tst->super[1]) {
      fprintf(flog, "Tester %d has several supertesters\n", tst->id);
      return -1;
    }
    atst = 0;
    if (tst->super) {
      for (i = 0; i < sstate->atester_total; i++)
        if (!strcmp(sstate->atesters[i]->name, tst->super[0]))
          break;
      if (i == sstate->atester_total) {
        fprintf(flog, "Abstract tester `%s' not found\n", tst->super[0]);
        return -1;
      }
      atst = sstate->atesters[i];
    }
    if (tst->any) {
      continue;
    }
    prob = 0;
    if (tst->problem && tst->problem_name[0]) {
      fprintf(flog, "Both problem and problem_name fields cannot be set\n");
      return -1;
    } else if (tst->problem) {
      if (tst->problem <= 0 || tst->problem >= sstate->prob_a
          || !sstate->probs[tst->problem]) {
        fprintf(flog, "problem %d is invalid\n", tst->problem);
        return -1;
      }
      prob = sstate->probs[tst->problem];
    } else if (tst->problem_name[0]) {
      for (i = 1; i < sstate->prob_a; i++)
        if (sstate->probs[i]
            && !strcmp(sstate->probs[i]->short_name, tst->problem_name))
          break;
      if (i == sstate->prob_a) {
        fprintf(flog, "Problem `%s' does not exist\n", tst->problem_name);
        return -1;
      }
      prob = sstate->probs[i];
    } else {
      fprintf(flog, "Neither problem not problem_name are set\n");
      return -1;
    }
    prob_no_any[prob->id] = 1;

    vm_size = tst->max_vm_size;
    if (vm_size == -1L && atst) vm_size = atst->max_vm_size;
    st_size = tst->max_stack_size;
    if (st_size == -1L && atst) st_size = atst->max_stack_size;
    if (vm_size != -1L) {
      if (prob->max_vm_size == -1L) prob->max_vm_size = vm_size;
      if (prob->max_vm_size != vm_size) {
        fprintf(flog, "Conflicting max_vm_size specifications for problem `%s'\n",
                prob->short_name);
        return -1;
      }
    }
    if (st_size != -1L) {
      if (prob->max_stack_size == -1L) prob->max_stack_size = st_size;
      if (prob->max_stack_size != st_size) {
        fprintf(flog, "Conflicting max_stack_size specifications for problem `%s'\n",
                prob->short_name);
        return -1;
      }
    }
  }

  for (i = 0; i < sstate->tester_total; i++) {
    if (!(tst = sstate->testers[i])) continue;

    atst = 0;
    if (tst->super) {
      for (j = 0; j < sstate->atester_total; j++)
        if (!strcmp(sstate->atesters[j]->name, tst->super[0]))
          break;
      if (j == sstate->atester_total) {
        fprintf(flog, "Abstract tester `%s' not found\n", tst->super[0]);
        return -1;
      }
      atst = sstate->atesters[j];
    }

    if (!tst->any) continue;

    for (j = 0; j < sstate->prob_a; j++) {
      if (!(prob = sstate->probs[j])) continue;
      if (prob_no_any[j]) continue;

      vm_size = tst->max_vm_size;
      if (vm_size == -1L && atst) vm_size = atst->max_vm_size;
      st_size = tst->max_stack_size;
      if (st_size == -1L && atst) st_size = atst->max_stack_size;
      if (vm_size != -1L) {
        if (prob->max_vm_size == -1L) prob->max_vm_size = vm_size;
        if (prob->max_vm_size != vm_size) {
          fprintf(flog, "Conflicting max_vm_size specifications for problem `%s'\n",
                  prob->short_name);
          return -1;
        }
      }
      if (st_size != -1L) {
        if (prob->max_stack_size == -1L) prob->max_stack_size = st_size;
        if (prob->max_stack_size != st_size) {
          fprintf(flog, "Conflicting max_stack_size specifications for problem `%s'\n",
                  prob->short_name);
          return -1;
        }
      }
    }
  }

  XALLOCA(mem_lims, sstate->prob_a);
  XALLOCA(st_lims, sstate->prob_a);
  XALLOCA(mem_cnt, sstate->prob_a);
  XALLOCA(st_cnt, sstate->prob_a);

  // propagate most used memory limit to superproblem
  /*
  for (i = 0; i < sstate->aprob_u; i++) {
    aprob = sstate->aprobs[i];
    mem_u = 0;
    st_u = 0;
    XMEMZERO(mem_cnt, sstate->prob_a);
    XMEMZERO(st_cnt, sstate->prob_a);
    for (j = 1; j < sstate->prob_a; j++) {
      if (!(prob = sstate->probs[j]) || !prob->super[0]
          || strcmp(prob->super, aprob->short_name)) continue;
      if (prob->max_vm_size != -1L) {
        for (k = 0; k < mem_u; k++)
          if (mem_lims[k] == prob->max_vm_size)
            break;
        if (k == mem_u) mem_u++;
        mem_lims[k] = prob->max_vm_size;
        mem_cnt[k]++;
      }
      if (prob->max_stack_size != -1L) {
        for (k = 0; k < st_u; k++)
          if (st_lims[k] == prob->max_stack_size)
            break;
        if (k == st_u) st_u++;
        st_lims[k] = prob->max_stack_size;
        st_cnt[k]++;
      }
    }
    if (mem_u > 0) {
      max_i = 0;
      for (i = 1; i < mem_u; i++)
        if (mem_cnt[i] > mem_cnt[max_i])
          max_i = i; 
      aprob->max_vm_size = mem_lims[max_i];
      for (j = 1; j < sstate->prob_a; j++) {
        if (!(prob = sstate->probs[j]) || !prob->super[0]
            || strcmp(prob->super, aprob->short_name)) continue;
        if (prob->max_vm_size == -1L) {
          prob->max_vm_size = 0;
        } else if (prob->max_vm_size == aprob->max_vm_size) {
          prob->max_vm_size = -1L;
        }
      }
    }
    if (st_u > 0) {
      max_i = 0;
      for (i = 1; i < st_u; i++)
        if (st_cnt[i] > st_cnt[max_i])
          max_i = i; 
      aprob->max_stack_size = st_lims[max_i];
      for (j = 1; j < sstate->prob_a; j++) {
        if (!(prob = sstate->probs[j]) || !prob->super[0]
            || strcmp(prob->super, aprob->short_name)) continue;
        if (prob->max_stack_size == -1L) {
          prob->max_stack_size = 0;
        } else if (prob->max_stack_size == aprob->max_stack_size) {
          prob->max_stack_size = -1L;
        }
      }
    }
  }
  */

  // very simple rule for check_cmd extraction:
  // check_cmd for all abstract checkers must be the same
  for (i = 0; i < sstate->atester_total; i++) {
    if (!check_cmd[0])
      snprintf(check_cmd, sizeof(check_cmd), "%s", sstate->atesters[i]->check_cmd);
    if (strcmp(check_cmd, sstate->atesters[i]->check_cmd)) {
      fprintf(flog, "conflicting check_cmd for abstract testers\n");
      return -1;
    }
  }

  // assign this check_cmd to all abstract problems without check_cmd
  for (i = 0; i < sstate->aprob_u; i++)
    if (!(aprob = sstate->aprobs[i])->check_cmd[0])
      snprintf(aprob->check_cmd, sizeof(aprob->check_cmd), "%s", check_cmd);

  sstate->contest_start_cmd_text = do_load_file(conf_dir, global->contest_start_cmd);
  sstate->stand_header_text = do_load_file(conf_dir, global->stand_header_file);
  sstate->stand_footer_text = do_load_file(conf_dir, global->stand_footer_file);
  sstate->stand2_header_text = do_load_file(conf_dir, global->stand2_header_file);
  sstate->stand2_footer_text = do_load_file(conf_dir, global->stand2_footer_file);
  sstate->plog_header_text = do_load_file(conf_dir, global->plog_header_file);
  sstate->plog_footer_text = do_load_file(conf_dir, global->plog_footer_file);

  return 0;
}

static unsigned char *
strsubst(const unsigned char *str, const unsigned char *from,
         const unsigned char *to)
{
  unsigned char *p, *q;
  size_t from_len = strlen(from);
  size_t to_len = strlen(to);
  size_t str_len = strlen(str);

  if (!(p = strstr(str, from))) return 0;

  q = xmalloc(str_len - from_len + to_len + 1);
  memcpy(q, str, p - str);
  memcpy(q + (p - str), to, to_len);
  strcpy(q + (p - str) + to_len, p + from_len);
  return q;
}

static void
subst_param(unsigned char **p_param,
            int n,
            unsigned char s_from[][32], unsigned char s_to[][32])
{
  int i;
  unsigned char *t;
  unsigned char *param = *p_param;

  if (!param) return;
  for (i = 0; i < n; i++) {
    if (!(t = strsubst(param, s_from[i], s_to[i]))) continue;
    xfree(param);
    *p_param = t;
    return;
  }
}

void
super_html_fix_serve(struct sid_state *sstate,
                     int orig_id, int contest_id)
{
  unsigned char substs_from[6][32];
  unsigned char substs_to[6][32];
  struct section_global_data *global = sstate->global;
  unsigned char *s;

  if (!global) return;

  snprintf(substs_from[0], sizeof(substs_from[0]), "%06d", orig_id);
  snprintf(substs_from[1], sizeof(substs_from[0]), "%05d", orig_id);
  snprintf(substs_from[2], sizeof(substs_from[0]), "%04d", orig_id);
  snprintf(substs_from[3], sizeof(substs_from[0]), "%03d", orig_id);
  snprintf(substs_from[4], sizeof(substs_from[0]), "%02d", orig_id);
  snprintf(substs_from[5], sizeof(substs_from[0]), "%d", orig_id);
  snprintf(substs_to[0], sizeof(substs_to[0]), "%06d", contest_id);
  snprintf(substs_to[1], sizeof(substs_to[0]), "%05d", contest_id);
  snprintf(substs_to[2], sizeof(substs_to[0]), "%04d", contest_id);
  snprintf(substs_to[3], sizeof(substs_to[0]), "%03d", contest_id);
  snprintf(substs_to[4], sizeof(substs_to[0]), "%02d", contest_id);
  snprintf(substs_to[5], sizeof(substs_to[0]), "%d", contest_id);

  s = xstrdup(global->standings_file_name);
  subst_param(&s, 6, substs_from, substs_to);
  snprintf(global->standings_file_name, sizeof(global->standings_file_name),
           "%s", s);
  xfree(s);

  if (global->stand2_file_name[0]) {
    s = xstrdup(global->stand2_file_name);
    subst_param(&s, 6, substs_from, substs_to);
    snprintf(global->stand2_file_name, sizeof(global->stand2_file_name),
             "%s", s);
    xfree(s);
  }

  if (global->plog_file_name[0]) {
    s = xstrdup(global->plog_file_name);
    subst_param(&s, 6, substs_from, substs_to);
    snprintf(global->plog_file_name, sizeof(global->plog_file_name),
             "%s", s);
    xfree(s);
  }

  global->stand_ignore_after_d = 0;
}

static void
mkpath(unsigned char *out, const unsigned char *d, const unsigned char *n,
       const unsigned char *i)
{
  if (!n || !*n) {
    snprintf(out, sizeof(path_t), "%s/%s", d, i);
  } else if (!os_IsAbsolutePath(n)) {
    snprintf(out, sizeof(path_t), "%s/%s", d, n);
  } else {
    snprintf(out, sizeof(path_t), "%s", n);
  }
}

static int
check_test_file(FILE *flog, int n, const unsigned char *path, const unsigned char *pat,
                const unsigned char *sfx, int q_flag, int bin_flag)
{
  path_t name;
  path_t name2;
  path_t full;
  path_t full2;
  struct stat stbuf;
  DIR *d;
  struct dirent *dd;
  char *test_txt = 0;
  size_t test_len = 0;
  unsigned char *d2u_txt = 0, *out_txt = 0;
  int changed = 0;

  if (pat && *pat) {
    snprintf(name, sizeof(name), pat, n);
  } else {
    snprintf(name, sizeof(name), "%03d%s", n, sfx);
  }

  snprintf(full, sizeof(full), "%s/%s", path, name);
  if (stat(full, &stbuf) < 0) {
    // try case-insensitive search
    name2[0] = 0;
    if (!(d = opendir(path))) {
      fprintf(flog, "Error: cannot open directory %s\n", path);
      return -1;
    }
    while ((dd = readdir(d))) {
      if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, ".."))
        continue;
      if (!strcasecmp(name, dd->d_name)) {
        snprintf(name2, sizeof(name2), dd->d_name);
        break;
      }
    }
    closedir(d);
    if (!name2[0]) {
      if (!q_flag)
        fprintf(flog, "Error: file %s not found even case insensetively\n", name);
      return 0;
    }
    snprintf(full2, sizeof(full2), "%s/%s", path, name2);
    fprintf(flog, "Info: found %s using case-insensetive search\n", name2);
    if (stat(full2, &stbuf) < 0) {
      fprintf(flog, "Error: file %s is not found. Strange!\n", full2);
      return -1;
    }
    if (!S_ISREG(stbuf.st_mode)) {
      fprintf(flog, "Error: file %s is not regular\n", full2);
      return -1;
    }
    if (rename(full2, full) < 0) {
      fprintf(flog, "Error: rename %s -> %s failed: %s\n", full2, full,
              os_ErrorMsg());
      return -1;
    }
    fprintf(flog, "Info: file renamed: %s -> %s\n", full2, full);
  } else {
    if (!S_ISREG(stbuf.st_mode)) {
      fprintf(flog, "Error: file %s is not regular\n", full);
      return -1;
    }
  }

  if (!bin_flag) {
    if (generic_read_file(&test_txt, 0, &test_len, 0, 0, full, 0) < 0) {
      fprintf(flog, "Error: failed to read %s\n", full);
      return -1;
    }
    if (test_len != strlen(test_txt)) {
      fprintf(flog, "Error: file %s contains zero bytes\n", full);
      xfree(test_txt);
      return -1;
    }
    d2u_txt = dos2unix_str(test_txt);
    if (strcmp(d2u_txt, test_txt)) {
      changed = 1;
      fprintf(flog, "Info: file %s converted from DOS to UNIX format\n", full);
    }
    xfree(test_txt); test_txt = 0;
    test_len = strlen(d2u_txt);
    if (test_len > 0 && d2u_txt[test_len - 1] != '\n') {
      changed = 1;
      out_txt = xmalloc(test_len + 2);
      strcpy(out_txt, d2u_txt);
      out_txt[test_len] = '\n';
      out_txt[test_len + 1] = 0;
      xfree(d2u_txt); d2u_txt = 0;
      fprintf(flog, "Info: file %s: final newline appended\n", full);
      test_len++;
    } else {
      out_txt = d2u_txt; d2u_txt = 0;
    }
  }

  if (changed) {
    if (generic_write_file(out_txt, test_len, KEEP_ON_FAIL, 0, full, 0) < 0) {
      fprintf(flog, "Error: write of %s failed\n", full);
      xfree(out_txt);
      return -1;
    }
    fprintf(flog, "Info: file %s successfully written\n", full);
  }

  xfree(out_txt);
  return 1;
}

static int
invoke_compile_process(FILE *flog, const unsigned char *cur_dir,
                       const unsigned char *cmd)
{
  int pfd[2];
  int pid;
  unsigned char inbuf[1024];
  int rsz, status;
  const unsigned char *coredumped = "";

  fprintf(flog, "Starting compilation: %s\n", cmd);

  if (pipe(pfd) < 0) {
    fprintf(flog, "pipe() failed: %s\n", os_ErrorMsg());
    return -1;
  }

  if ((pid = fork()) < 0) {
    fprintf(flog, "fork() failed: %s\n", os_ErrorMsg());
    return -1;
  }
  if (!pid) {
    // child
    if (cur_dir) {
      if (chdir(cur_dir) < 0)
        _exit(100);
    }
    close(pfd[0]);
    if (pfd[1] != 1) dup2(pfd[1], 1);
    if (pfd[1] != 2) dup2(pfd[1], 2);
    if (pfd[1] != 1 && pfd[1] != 2) close(pfd[1]);
    execl("/bin/sh", "/bin/sh", "-c", cmd, NULL);
    _exit(100);
  }

  // parent
  close(pfd[1]);
  while ((rsz = read(pfd[0], inbuf, sizeof(inbuf))) > 0) {
    fwrite(inbuf, 1, rsz, flog);
  }
  if (rsz < 0) {
    fprintf(flog, "read() failed: %s\n", os_ErrorMsg());
    close(pfd[0]);
    return -1;
  }
  close(pfd[0]);
  fprintf(flog, "\n");

  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) {
      fprintf(flog, "waitpid() failed: %s\n", os_ErrorMsg());
      return -1;
    }
  }

  if (WIFEXITED(status)) {
    if (!WEXITSTATUS(status))
      fprintf(flog, "process is completed successfully\n");
    else
      fprintf(flog, "process exited with code %d\n", WEXITSTATUS(status));
  } else if (WIFSIGNALED(status)) {
    if (WCOREDUMP(status)) coredumped = " (core dumped)";
    fprintf(flog, "process is terminated by signal %d %s%s\n",
            WTERMSIG(status), os_GetSignalString(WTERMSIG(status)), coredumped);
  } else {
    fprintf(flog, "waitpid() returned unexpected status\n");
    return -1;
  }
  return 0;
}

enum
{
  CHECKER_LANG_FIRST,
  CHECKER_LANG_PAS = CHECKER_LANG_FIRST,
  CHECKER_LANG_DPR,
  CHECKER_LANG_C,
  CHECKER_LANG_CPP,

  CHECKER_LANG_LAST,
};
static const unsigned char * const supported_suffixes[] =
{
  ".pas",
  ".dpr",
  ".c",
  ".cpp",
  0,
};

static unsigned char *fpc_path = 0;
static unsigned char *dcc_path = 0;
static unsigned char *gcc_path = 0;
static unsigned char *gpp_path = 0;

static unsigned char *
get_compiler_path(const unsigned char *short_name, unsigned char *old_path)
{
  unsigned char *s = 0;
  path_t cmd;

  if (old_path) return old_path;

  snprintf(cmd, sizeof(cmd), "%s/lang/%s-version -p",
           EJUDGE_SCRIPT_DIR, short_name);
  if (!(s = read_process_output(cmd, 0, 0, 0))) s = xstrdup("");
  return s;
} 

static int
recompile_checker(FILE *f, const unsigned char *checker_path)
{
  struct stat stbuf1, stbuf2;
  path_t checker_src;
  path_t checker_obj;
  int need_recompile = 0, retcode = 0;
  path_t cmd;
  path_t check_dir;
  path_t filename;
  path_t filename2;
  int lang_ind, i;

  lang_ind = -1;
  for (i = CHECKER_LANG_FIRST; i < CHECKER_LANG_LAST; i++) {
    snprintf(checker_src, sizeof(checker_src), "%s%s", checker_path,
             supported_suffixes[i]);
    if (stat(checker_src, &stbuf2) < 0) continue;
    if (!S_ISREG(stbuf2.st_mode)) {
      fprintf(f, "Error: checker source %s is not a regular file\n", checker_src);
      return -1;
    }
    if (lang_ind >= 0) {
      fprintf(f, "Error: several source files (%s, %s) are found for a checker\n",
              supported_suffixes[lang_ind], supported_suffixes[i]);
      return -1;
    }
    lang_ind = i;
  }
  if (lang_ind < 0) {
    if (stat(checker_path, &stbuf1) < 0) {
      fprintf(f, "Error: checker %s does not exist and cannot be compiled\n",
              checker_path);
      return -1;
    }
    if (!S_ISREG(stbuf1.st_mode)) {
      fprintf(f, "Error: checker %s is not a regular file\n", checker_path);
      return -1;
    }
    if (access(checker_path, X_OK) < 0) {
      fprintf(f, "Error: checker %s is not executable\n", checker_path);
      return -1;
    }
    fprintf(f, "Warning: no source file or unsupported language for checker %s\n", checker_path);
    return 0;
  }

  snprintf(checker_src, sizeof(checker_src), "%s%s", checker_path,
           supported_suffixes[lang_ind]);
  // FIXME: make configurable object file suffix
  snprintf(checker_obj, sizeof(checker_obj), "%s.o", checker_path);
  if (stat(checker_path, &stbuf1) < 0) {
    fprintf(f, "Warning: checker %s does not exist\n", checker_path);
    if (stat(checker_src, &stbuf2) < 0) {
      fprintf(f, "Error: checker source %s is missing\n", checker_src);
      return -1;
    }
    need_recompile = 1;
  } else {
    if (stat(checker_src, &stbuf2) >= 0 && stbuf2.st_mtime > stbuf1.st_mtime) {
      fprintf(f, "Info: checker source %s is newer, than %s\n", checker_src,
              checker_path);
      need_recompile = 1;
    }
  }
  if (!need_recompile) return 0;

  os_rDirName(checker_path, check_dir, sizeof(check_dir));
  os_rGetBasename(checker_path, filename, sizeof(filename));
  snprintf(filename2, sizeof(filename2), "%s%s", filename,
           supported_suffixes[lang_ind]);

  switch (lang_ind) {
  case CHECKER_LANG_PAS:
    fpc_path = get_compiler_path("fpc", fpc_path);
    if (!*fpc_path) {
      fprintf(f, "Error: Free Pascal support is not configured\n");
      return -1;
    }
    snprintf(cmd, sizeof(cmd), "%s -Fu%s/share/ejudge/testlib/fpc %s",
             fpc_path, EJUDGE_PREFIX_DIR, filename2);
    break;
  case CHECKER_LANG_DPR:
    dcc_path = get_compiler_path("dcc", dcc_path);
    if (!*dcc_path) {
      fprintf(f, "Error: Delphi (Kylix) support is not configured\n");
      return -1;
    }
    snprintf(cmd, sizeof(cmd), "%s -U%s/share/ejudge/testlib/delphi %s",
             dcc_path, EJUDGE_PREFIX_DIR, filename2);
    break;
  case CHECKER_LANG_C:
    gcc_path = get_compiler_path("gcc", gcc_path);
    if (!*gcc_path) {
      fprintf(f, "Error: GNU C support is not configured\n");
      return -1;
    }
    snprintf(cmd, sizeof(cmd), "%s -std=gnu99 -O2 -Wall -I%s/include/ejudge -L%s/lib -Wl,--rpath,%s/lib %s -o %s -lchecker -lm", gcc_path, EJUDGE_PREFIX_DIR, EJUDGE_PREFIX_DIR, EJUDGE_PREFIX_DIR, filename2, filename);
    break;
  case CHECKER_LANG_CPP:
    gpp_path = get_compiler_path("g++", gpp_path);
    if (!*gpp_path) {
      fprintf(f, "Error: GNU C++ support is not configured\n");
      return -1;
    }
    snprintf(cmd, sizeof(cmd), "%s -O2 -Wall -I%s/include/ejudge -L%s/lib -Wl,--rpath,%s/lib %s -o %s -lchecker -lm", gpp_path, EJUDGE_PREFIX_DIR, EJUDGE_PREFIX_DIR, EJUDGE_PREFIX_DIR, filename2, filename);
    break;

  default:
    abort();
  }

  // remove old executable and object file
  unlink(checker_obj);
  unlink(checker_path);

  fprintf(f, "Info: using command line %s\n", cmd);
  if ((retcode = invoke_compile_process(f, check_dir, cmd)) < 0) {
    fprintf(f, "Error: failed to start the compiler\n");
    return -1;
  } else if (retcode > 0) {
    fprintf(f, "Error: compiler exit code %d\n", retcode);
    return -1;
  } if (stat(checker_path, &stbuf1)) {
    fprintf(f, "Error: checker is not created by the compiler\n");
    return -1;
  } else {
    fprintf(f, "Info: checker %s is recompiled\n", filename);
  }
  return 0;
}

static int
check_test_score(FILE *flog, int ntests, int test_score, int full_score,
                 const unsigned char *test_score_list)
{
  int *scores;
  int i, sum;
  int index, score, n, tn = 1, was_indices = 0;
  const unsigned char *s;

  ASSERT(ntests >= 0);

  if (test_score < 0) {
    fprintf(flog, "Error: test_score is negative\n");
    return -1;
  }

  XALLOCA(scores, ntests + 1);
  for (i = 0; i <= ntests; i++)
    scores[i] = test_score;

  if (test_score_list && *test_score_list) {
    s = test_score_list;

    while (1) {
      while (*s > 0 && *s <= ' ') s++;
      if (!*s) break;

      if (*s == '[') {
        if (sscanf(s, "[ %d ] %d%n", &index, &score, &n) != 2) {
          fprintf(flog, "Error: invalid test_score_list specification \"%s\"\n",
                  test_score_list);
          return -1;
        }
        if (index < 1 || index > ntests) {
          fprintf(flog, "Error: test index %d is out of range\n", index);
          return -1;
        }
        if (score < 0) {
          fprintf(flog, "Error: score %d is invalid\n", score);
          return -1;
        }
        tn = index;
        was_indices = 1;
      } else {
        if (sscanf(s, "%d%n", &score, &n) != 1) {
          fprintf(flog, "Error: invalid test_score_list specification \"%s\"\n",
                  test_score_list);
          return -1;
        }
        if (score < 0) {
          fprintf(flog, "Error: score %d is invalid\n", score);
          return -1;
        }
        if (tn > ntests) {
          fprintf(flog, "Error: too many scores specified\n");
          return -1;
        }
      }
      scores[tn++] = score;
      s += n;
    }

    if (!was_indices && tn <= ntests) {
      fprintf(flog, "Info: test_score_list defines only %d tests\n", tn - 1);
    }
  }

  for (i = 1, sum = 0; i <= ntests; i++)
    sum += scores[i];

  if (sum > full_score) {
    fprintf(flog, "Error: summ of all test scores (%d) is greater than full_score (%d)\n", sum, full_score);
    return -1;
  } else if (sum < full_score) {
    fprintf(flog, "Warning: summ of all test scores (%d) is less than full_score (%d)\n", sum, full_score);
  }

  return 0;
}

int
super_html_check_tests(FILE *f,
                       int priv_level,
                       int user_id,
                       const unsigned char *login,
                       ej_cookie_t session_id,
                       ej_ip_t ip_address,
                       struct ejudge_cfg *config,
                       struct sid_state *sstate,
                       const unsigned char *self_url,
                       const unsigned char *hidden_vars,
                       const unsigned char *extra_args)
{
  unsigned char *s;
  path_t conf_path;
  path_t g_test_path;
  path_t g_corr_path;
  path_t g_info_path;
  path_t g_tgz_path;
  path_t g_checker_path;
  path_t test_path, corr_path, info_path, checker_path;
  path_t v_test_path, v_corr_path, v_info_path, v_checker_path;
  struct contest_desc *cnts;
  struct section_global_data *global;
  struct section_problem_data *prob, *abstr;
  struct section_problem_data tmp_prob;
  int i, j, k, variant;
  char *flog_txt = 0;
  size_t flog_len = 0;
  FILE *flog = 0;
  struct stat stbuf;
  int total_tests = 0, v_total_tests = 0;
  unsigned char hbuf[1024];

  if (sstate->serve_parse_errors) {
    fprintf(f, "<h2>The tests cannot be checked</h2>\n");
    s = html_armor_string_dup(sstate->serve_parse_errors);
    fprintf(f, "<p><pre><font color=\"red\">%s</font></pre></p>\n", s);
    xfree(s);
    return 0;
  }

  if (!sstate->edited_cnts || !sstate->global) {
    fprintf(f, "<h2>The tests cannot be checked: No contest</h2>\n");
    return 0;
  }

  flog = open_memstream(&flog_txt, &flog_len);

  cnts = sstate->edited_cnts;
  global = sstate->global;

  mkpath(conf_path, cnts->root_dir, cnts->conf_dir, DFLT_G_CONF_DIR);
  mkpath(g_test_path, conf_path, global->test_dir, DFLT_G_TEST_DIR);
  mkpath(g_corr_path, conf_path, global->corr_dir, DFLT_G_CORR_DIR);
  mkpath(g_info_path, conf_path, global->info_dir, DFLT_G_INFO_DIR);
  mkpath(g_tgz_path, conf_path, global->tgz_dir, DFLT_G_TGZ_DIR);
  mkpath(g_checker_path, conf_path, global->checker_dir, DFLT_G_CHECKER_DIR);

  for (i = 1; i < sstate->prob_a; i++) {
    if (!(prob = sstate->probs[i])) continue;

    fprintf(flog, "*** Checking problem %s ***\n", prob->short_name);
    if (prob->disable_testing > 0) {
      fprintf(flog, "Testing is disabled, skipping\n");
      continue;
    }

    abstr = 0;
    if (prob->super[0]) {
      for (j = 0; j < sstate->aprob_u; j++)
        if (!strcmp(prob->super, sstate->aprobs[j]->short_name))
          break;
      if (j < sstate->aprob_u)
        abstr = sstate->aprobs[j];
      if (!abstr) {
        fprintf(flog, "Error: no abstract checker for problem `%s'\n",
                prob->short_name);
        goto check_failed;
      }
    }

    prepare_copy_problem(&tmp_prob, prob);
    prepare_set_prob_value(PREPARE_FIELD_PROB_TYPE, &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_XML_FILE,&tmp_prob,abstr, global);

    if (tmp_prob.type_val == PROB_TYPE_SELECT_ONE && tmp_prob.xml_file[0]) {
      fprintf(flog, "Select-one XML-specified problem, skipping\n");
      continue;
    }

    prepare_set_prob_value(PREPARE_FIELD_PROB_SCORING_CHECKER, &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_MANUAL_CHECKING, &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_EXAMINATOR_NUM, &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_CHECK_PRESENTATION, &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_BINARY_INPUT, &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_IGNORE_EXIT_CODE, &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_VALUER_CMD, &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_TEST_DIR, &tmp_prob, abstr, 0);
    prepare_set_prob_value(PREPARE_FIELD_PROB_USE_CORR, &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_TEST_SFX, &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_TEST_PAT, &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_TEST_SCORE, &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_FULL_SCORE, &tmp_prob, abstr, global);
    mkpath(test_path, g_test_path, tmp_prob.test_dir, "");
    if (tmp_prob.use_corr) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_CORR_DIR, &tmp_prob, abstr, 0);
      prepare_set_prob_value(PREPARE_FIELD_PROB_CORR_SFX, &tmp_prob, abstr, global);
      prepare_set_prob_value(PREPARE_FIELD_PROB_CORR_PAT, &tmp_prob, abstr, global);
      mkpath(corr_path, g_corr_path, tmp_prob.corr_dir, "");
    }
    prepare_set_prob_value(PREPARE_FIELD_PROB_USE_INFO, &tmp_prob, abstr, global);
    if (tmp_prob.use_info) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_INFO_DIR, &tmp_prob, abstr, 0);
      prepare_set_prob_value(PREPARE_FIELD_PROB_INFO_SFX, &tmp_prob, abstr, global);
      prepare_set_prob_value(PREPARE_FIELD_PROB_INFO_PAT, &tmp_prob, abstr, global);
      mkpath(info_path, g_info_path, tmp_prob.info_dir, "");
    }
    checker_path[0] = 0;
    if (!tmp_prob.standard_checker[0]) {
      prepare_set_prob_value(PREPARE_FIELD_PROB_CHECK_CMD, &tmp_prob, abstr, 0);
      mkpath(checker_path, g_checker_path, tmp_prob.check_cmd, "");
    }

    // check tests
    if (prob->variant_num <= 0) {
      if (stat(test_path, &stbuf) < 0) {
        fprintf(flog, "Error: test directory %s does not exist\n", test_path);
        goto check_failed;
      }
      if (!S_ISDIR(stbuf.st_mode)) {
        fprintf(flog, "Error: test directory %s is not a directory\n", test_path);
        goto check_failed;
      }
      if (tmp_prob.use_corr) {
        if (stat(corr_path, &stbuf) < 0) {
          fprintf(flog, "Error: test directory %s does not exist\n", corr_path);
          goto check_failed;
        }
        if (!S_ISDIR(stbuf.st_mode)) {
          fprintf(flog, "Error: test directory %s is not a directory\n", corr_path);
          goto check_failed;
        }
      }
      if (tmp_prob.use_info) {
        if (stat(info_path, &stbuf) < 0) {
          fprintf(flog, "Error: test directory %s does not exist\n", info_path);
          goto check_failed;
        }
        if (!S_ISDIR(stbuf.st_mode)) {
          fprintf(flog, "Error: test directory %s is not a directory\n", info_path);
          goto check_failed;
        }
      }

      total_tests = 1;
      while (1) {
        k = check_test_file(flog, total_tests, test_path, tmp_prob.test_pat, tmp_prob.test_sfx, 1, tmp_prob.binary_input);
        if (k < 0) goto check_failed;
        if (!k) break;
        total_tests++;
      }
      total_tests--;
      if (!total_tests) {
        fprintf(flog, "Error: no tests defined for the problem\n");
        goto check_failed;
      }
      if (tmp_prob.type_val > 0 && total_tests != 1) {
        fprintf(flog, "Error: output-only problem must have only one test\n");
        goto check_failed;
      }
      fprintf(flog, "Info: assuming, that there are %d tests for this problem\n",
              total_tests);
      
      for (j = 1; j <= total_tests; j++) {
        if (tmp_prob.use_corr
            && check_test_file(flog, j, corr_path, tmp_prob.corr_pat,
                               tmp_prob.corr_sfx, 0, tmp_prob.binary_input) <= 0)
          goto check_failed;
        if (tmp_prob.use_info
            && check_test_file(flog, j, info_path, tmp_prob.info_pat,
                               tmp_prob.info_sfx, 0, 0) <= 0)
          goto check_failed;
      }
      if (tmp_prob.use_corr
          && check_test_file(flog, j, corr_path, tmp_prob.corr_pat,
                             tmp_prob.corr_sfx, 1, tmp_prob.binary_input) != 0) {
        fprintf(flog, "Error: there is answer file for test %d, but no data file\n",
                j);
        goto check_failed;
      }
      if (tmp_prob.use_info
          && check_test_file(flog, j, info_path, tmp_prob.info_pat,
                             tmp_prob.info_sfx, 1, 0) != 0) {
        fprintf(flog, "Error: there is test info file for test %d, but no data file\n",
                j);
        goto check_failed;
      }
    } else {
      for (variant = 1; variant <= prob->variant_num; variant++) {
        snprintf(v_test_path, sizeof(v_test_path), "%s-%d", test_path, variant);
        if (stat(v_test_path, &stbuf) < 0) {
          fprintf(flog, "Error: test directory %s does not exist\n", v_test_path);
          goto check_failed;
        }
        if (!S_ISDIR(stbuf.st_mode)) {
          fprintf(flog, "Error: test directory %s is not a directory\n", v_test_path);
          goto check_failed;
        }
        if (tmp_prob.use_corr) {
          snprintf(v_corr_path, sizeof(v_corr_path), "%s-%d", corr_path, variant);
          if (stat(v_corr_path, &stbuf) < 0) {
            fprintf(flog, "Error: test directory %s does not exist\n", v_corr_path);
            goto check_failed;
          }
          if (!S_ISDIR(stbuf.st_mode)) {
            fprintf(flog, "Error: test directory %s is not a directory\n", v_corr_path);
            goto check_failed;
          }
        }
        if (tmp_prob.use_info) {
          snprintf(v_info_path, sizeof(v_info_path), "%s-%d", info_path, variant);
          if (stat(v_info_path, &stbuf) < 0) {
            fprintf(flog, "Error: test directory %s does not exist\n", v_info_path);
            goto check_failed;
          }
          if (!S_ISDIR(stbuf.st_mode)) {
            fprintf(flog, "Error: test directory %s is not a directory\n", v_info_path);
            goto check_failed;
          }
        }

        total_tests = 1;
        while (1) {
          k = check_test_file(flog, total_tests, v_test_path, tmp_prob.test_pat, tmp_prob.test_sfx, 1, tmp_prob.binary_input);
          if (k < 0) goto check_failed;
          if (!k) break;
          total_tests++;
        }
        total_tests--;
        if (!total_tests) {
          fprintf(flog, "Error: no tests defined for the problem\n");
          goto check_failed;
        }
        if (tmp_prob.type_val > 0 && total_tests != 1) {
          fprintf(flog, "Error: output-only problem must have only one test\n");
          goto check_failed;
        }
        if (variant == 1) {
          fprintf(flog, "Info: assuming, that there are %d tests for this problem\n",
                  total_tests);
          v_total_tests = total_tests;
        } else {
          if (v_total_tests != total_tests) {
            fprintf(flog, "Error: variant 1 defines %d tests, but variant %d defines %d tests\n", v_total_tests, variant, total_tests);
            goto check_failed;
          }
        }
      
        for (j = 1; j <= total_tests; j++) {
          if (tmp_prob.use_corr
              && check_test_file(flog, j, v_corr_path, tmp_prob.corr_pat,
                                 tmp_prob.corr_sfx, 0, tmp_prob.binary_input) <= 0)
            goto check_failed;
          if (tmp_prob.use_info
              && check_test_file(flog, j, v_info_path, tmp_prob.info_pat,
                                 tmp_prob.info_sfx, 0, 0) <= 0)
            goto check_failed;
        }
        if (tmp_prob.use_corr
            && check_test_file(flog, j, v_corr_path, tmp_prob.corr_pat,
                               tmp_prob.corr_sfx, 1, tmp_prob.binary_input) != 0) {
          fprintf(flog, "Error: there is answer file for test %d, but no data file, variant %d\n",
                  j, variant);
          goto check_failed;
        }
        if (tmp_prob.use_info
            && check_test_file(flog, j, v_info_path, tmp_prob.info_pat,
                               tmp_prob.info_sfx, 1, 0) != 0) {
          fprintf(flog, "Error: there is test info file for test %d, but no data file, variant %d\n",
                  j, variant);
          goto check_failed;
        }
      }
    }

    if (!tmp_prob.standard_checker[0]) {
      if (prob->variant_num <= 0) {
        if (recompile_checker(flog, checker_path) < 0) goto check_failed;
      } else {
        for (variant = 1; variant <= prob->variant_num; variant++) {
          snprintf(v_checker_path, sizeof(v_checker_path), "%s-%d",
                   checker_path, variant);
          if (recompile_checker(flog, v_checker_path) < 0) goto check_failed;
        }
      }
    }

    if (global->score_system_val != SCORE_ACM
        && global->score_system_val != SCORE_MOSCOW) {
      if (check_test_score(flog, total_tests, tmp_prob.test_score,
                           tmp_prob.full_score, tmp_prob.test_score_list) < 0)
        goto check_failed;
    }
  }

  fclose(flog);
  s = html_armor_string_dup(flog_txt);
  fprintf(f, "<h2>Contest is set up OK</h2>\n");
  fprintf(f, "<p><pre><font>%s</font></pre></p>\n", s);
  xfree(s);
  xfree(flog_txt);

  fprintf(f, "<table border=\"0\"><tr>");
  fprintf(f, "<td>%sTo the top</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url,extra_args,0));
  fprintf(f, "<td>%sBack</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                        "contest_id=%d&action=%d", cnts->id,
                        SSERV_CMD_CONTEST_PAGE));
  fprintf(f, "</tr></table>\n");

  return 0;

 check_failed:
  fclose(flog);

  s = html_armor_string_dup(flog_txt);
  fprintf(f, "<h2>Contest settings contain error:</h2>\n");
  fprintf(f, "<p><pre><font color=\"red\">%s</font></pre></p>\n", s);
  xfree(s);
  xfree(flog_txt);
  return 0;
}

static int
vmap_sort_func(const void *v1, const void *v2)
{
  const struct variant_map_item *p1 = (typeof(p1)) v1;
  const struct variant_map_item *p2 = (typeof(p2)) v2;

  if (p1->user_id > 0 && p2->user_id > 0) {
    if (p1->user_id < p2->user_id) return -1;
    if (p1->user_id > p2->user_id) return 1;
    return 0;
  }
  if (p1->user_id > 0) return -1;
  if (p2->user_id > 0) return 1;
  return strcmp(p1->login, p2->login);
}

int
super_html_update_variant_map(FILE *flog, int contest_id,
                              struct userlist_clnt *server_conn,
                              struct contest_desc *cnts,
                              struct section_global_data *global,
                              int total_probs,
                              struct section_problem_data **probs,
                              unsigned char **p_header_txt,
                              unsigned char **p_footer_txt)
{
  int r;
  unsigned char *xml_text = 0;
  struct userlist_list *users = 0;
  path_t conf_dir;
  path_t variant_file;
  struct stat stbuf;
  int var_prob_num, i, n, j, uid;
  struct variant_map *vmap = 0;
  int *tvec = 0, *new_map, *new_rev_map;
  struct userlist_user *user;
  unsigned char header_buf[1024];

  if (!cnts->root_dir && !cnts->root_dir[0]) {
    fprintf(flog, "update_variant_map: contest root_dir is not set");
    goto failed;
  }
  if (!os_IsAbsolutePath(cnts->root_dir)) {
    fprintf(flog, "update_variant_map: contest root_dir is not absolute");
    goto failed;
  }

  if (!global->variant_map) {
    if (!cnts->conf_dir || !cnts->conf_dir[0]) {
      snprintf(conf_dir, sizeof(conf_dir), "%s/conf", cnts->root_dir);
    } else if (!os_IsAbsolutePath(cnts->conf_dir)) {
      snprintf(conf_dir, sizeof(conf_dir), "%s/%s", cnts->root_dir, cnts->conf_dir);
    } else {
      snprintf(conf_dir, sizeof(conf_dir), "%s", cnts->conf_dir);
    }

    if (!global->variant_map_file[0]) {
      snprintf(global->variant_map_file, sizeof(global->variant_map_file),
               "variant.map");
    }

    if (!os_IsAbsolutePath(global->variant_map_file)) {
      snprintf(variant_file, sizeof(variant_file), "%s/%s", conf_dir,
               global->variant_map_file);
    } else {
      snprintf(variant_file, sizeof(variant_file), "%s", global->variant_map_file);
    }

    if (stat(variant_file, &stbuf) < 0) {
      XCALLOC(global->variant_map, 1);
      if (p_header_txt) {
        snprintf(header_buf, sizeof(header_buf),
                 "<?xml version=\"1.0\" encoding=\"%s\" ?>\n"
                 "<!-- $%s$ -->\n",
                 INTERNAL_CHARSET, "Id");
        *p_header_txt = xstrdup(header_buf);
      }
    } else {
      if (!S_ISREG(stbuf.st_mode)) {
        fprintf(flog, "update_variant_map: variant map file %s is not regular file\n",
                variant_file);
        goto failed;
      }

      if (!(global->variant_map = prepare_parse_variant_map(flog, 0, variant_file, p_header_txt, p_footer_txt)))
        goto failed;
    }
  }

  if (!(vmap = global->variant_map)) {
    fprintf(flog, "update_variant_map: variant map is not set");
    goto failed;
  }

  // remap problems, if necessary
  for (var_prob_num = 0, i = 1; i < total_probs; i++)
    if (probs[i] && probs[i]->variant_num > 0)
      var_prob_num++;

  if (!var_prob_num) {
    fprintf(flog, "update_variant_map: no variant problems");
    goto failed;
  }

  if (vmap->prob_map) {
    ASSERT(vmap->prob_map_size > 0);
    ASSERT(vmap->prob_rev_map_size > 0);
    ASSERT(vmap->prob_rev_map);
    // update forward and reverse mappings
    XCALLOC(new_map, total_probs);
    memset(new_map, -1, sizeof(new_map[0]) * total_probs);
    XCALLOC(new_rev_map, var_prob_num);
    for (i = 1, j = 0; i < total_probs; i++)
      if (probs[i] && probs[i]->variant_num > 0) {
        new_map[i] = j;
        new_rev_map[j] = i;
        j++;
      }
    for (i = 0; i < vmap->u; i++) {
      XCALLOC(tvec, var_prob_num);
      ASSERT(vmap->v[i].var_num == vmap->prob_rev_map_size);
      for (j = 0; j < vmap->prob_rev_map_size; j++) {
        n = vmap->prob_rev_map[j];
        if (n > 0 && n < total_probs && probs[n] && probs[n]->variant_num > 0)
          tvec[new_map[n]] = vmap->v[i].variants[j];
      }
      xfree(vmap->v[i].variants);
      vmap->v[i].var_num = var_prob_num;
      vmap->v[i].variants = tvec;
    }
    xfree(vmap->prob_map);
    xfree(vmap->prob_rev_map);
    vmap->prob_map = new_map;
    vmap->prob_map_size = total_probs;
    vmap->prob_rev_map = new_rev_map;
    vmap->prob_rev_map_size = var_prob_num;
  } else if (vmap->var_prob_num > 0) {
    // reallocate new array for each entry
    for (i = 0; i < vmap->u; i++) {
      if (vmap->v[i].var_num != var_prob_num) {
        XCALLOC(tvec, var_prob_num);
        if (vmap->v[i].var_num > 0) {
          n = vmap->v[i].var_num;
          if (n > var_prob_num) n = var_prob_num;
          memcpy(tvec, vmap->v[i].variants, n * sizeof(tvec[0]));
          xfree(vmap->v[i].variants);
        }
        vmap->v[i].var_num = var_prob_num;
        vmap->v[i].variants = tvec;
      }
    }
    // create forward and reverse mappings
    vmap->prob_map_size = total_probs;
    XCALLOC(vmap->prob_map, total_probs);
    memset(vmap->prob_map, -1, sizeof(vmap->prob_map[0]) * total_probs);
    vmap->prob_rev_map_size = var_prob_num;
    XCALLOC(vmap->prob_rev_map, var_prob_num);
    for (i = 1, j = 0; i < total_probs; i++)
      if (probs[i] && probs[i]->variant_num > 0) {
        vmap->prob_map[i] = j;
        vmap->prob_rev_map[j] = i;
        j++;
      }
  } else {
    // allocate new array
    for (i = 0; i < vmap->u; i++) {
      vmap->v[i].var_num = var_prob_num;
      XCALLOC(vmap->v[i].variants, var_prob_num);
    }
    // create forward and reverse mappings
    vmap->prob_map_size = total_probs;
    XCALLOC(vmap->prob_map, total_probs);
    memset(vmap->prob_map, -1, sizeof(vmap->prob_map[0]) * total_probs);
    vmap->prob_rev_map_size = var_prob_num;
    XCALLOC(vmap->prob_rev_map, var_prob_num);
    for (i = 1, j = 0; i < total_probs; i++)
      if (probs[i] && probs[i]->variant_num > 0) {
        vmap->prob_map[i] = j;
        vmap->prob_rev_map[j] = i;
        j++;
      }
  }

  if ((r = userlist_clnt_list_all_users(server_conn, ULS_LIST_ALL_USERS,
                                        contest_id, &xml_text)) < 0) {
    fprintf(flog, "update_variant_map: cannot get list of participants\n");
    goto failed;
  }
  if (!(users = userlist_parse_str(xml_text))) {
    fprintf(flog, "update_variant_map: parsing of XML file failed\n");
    goto failed;
  }
  xfree(xml_text); xml_text = 0;

  // find registered users, which are not in the variant map
  for (uid = 1; uid < users->user_map_size; uid++) {
    if (!(user = users->user_map[uid])) continue;
    if (!user->login || !user->login[0]) continue;
    for (i = 0; i < vmap->u; i++)
      if (!strcmp(user->login, vmap->v[i].login))
        break;
    if (i < vmap->u) {
      vmap->v[i].user_id = uid;
      if (vmap->v[i].name && user->i.name) {
        if (strcmp(vmap->v[i].name, user->i.name)) {
          xfree(vmap->v[i].name);
          vmap->v[i].name = xstrdup(user->i.name);
        }
      } else if (user->i.name) {
        vmap->v[i].name = xstrdup(user->i.name);
      } else {
        xfree(vmap->v[i].name);
        vmap->v[i].name = 0;
      }
      continue;
    }
    if (vmap->u >= vmap->a) {
      if (!vmap->a) vmap->a = 32;
      vmap->a *= 2;
      vmap->v = (typeof(vmap->v)) xrealloc(vmap->v,
                                           vmap->a * sizeof(vmap->v[0]));
    }
    memset(&vmap->v[vmap->u], 0, sizeof(vmap->v[vmap->u]));
    vmap->v[vmap->u].login = xstrdup(user->login);
    vmap->v[vmap->u].user_id = uid;
    vmap->v[vmap->u].var_num = vmap->prob_rev_map_size;
    vmap->v[vmap->u].name = 0;
    if (user->i.name) vmap->v[vmap->u].name = xstrdup(user->i.name);
    XCALLOC(vmap->v[vmap->u].variants, vmap->prob_rev_map_size);
    vmap->u++;
  }
  userlist_free(&users->b); users = 0;

  // sort the entries by the user_id
  qsort(vmap->v, vmap->u, sizeof(vmap->v[0]), vmap_sort_func);

  return 0;

 failed:
  xfree(xml_text);
  if (users) userlist_free(&users->b);
  return -1;
}

#define ARMOR(s)  html_armor_buf(&ab, s)
int
super_html_edit_variants(FILE *f, int cmd, int priv_level, int user_id,
                         const unsigned char *login,
                         ej_cookie_t session_id,
                         ej_ip_t ip_address,
                         int ssl_flag,
                         struct userlist_clnt *userlist_conn,
                         const struct ejudge_cfg *config,
                         struct sid_state *sstate,
                         const unsigned char *self_url,
                         const unsigned char *hidden_vars,
                         const unsigned char *extra_args)
{
  const unsigned char *s = 0;
  struct section_global_data *global = 0;
  struct contest_desc *cnts = 0;
  int var_prob_num = 0, i, j, k;
  char *log_txt = 0;
  size_t log_len = 0;
  FILE *log_file = 0;
  struct variant_map *vmap = 0;
  struct section_problem_data *prob = 0;
  unsigned char buf[32];
  int row = 1;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (sstate->serve_parse_errors) {
    super_html_contest_page_menu(f, session_id, sstate, -1, self_url,
                                 hidden_vars, extra_args);
    fprintf(f, "<h2><tt>serve.cfg</tt> cannot be edited</h2>\n");
    fprintf(f, "<font color=\"red\"><pre>%s</pre></font>\n",
            ARMOR(sstate->serve_parse_errors));
    goto cleanup;
  }

  if (!sstate->global || !sstate->edited_cnts) {
    super_html_contest_page_menu(f, session_id, sstate, -1, self_url,
                                 hidden_vars, extra_args);
    fprintf(f, "<h3>No contest is edited</h2>\n");
    goto cleanup;
  }

  cnts = sstate->edited_cnts;
  global = sstate->global;

  if (sstate->probs) {
    for (i = 1; i < sstate->prob_a; i++)
      if (sstate->probs[i] && sstate->probs[i]->variant_num > 0)
        var_prob_num++;
  }

  if (!var_prob_num) {
    super_html_contest_page_menu(f, session_id, sstate, -1, self_url,
                                 hidden_vars, extra_args);
    fprintf(f, "<h3>Contest does not have variant problems</h2>\n");
    prepare_free_variant_map(global->variant_map);
    global->variant_map = 0;
    goto cleanup;
  }

  log_file = open_memstream(&log_txt, &log_len);
  if (cmd == SSERV_CMD_PROB_EDIT_VARIANTS_2) {
    if (!(vmap = global->variant_map) || vmap->prob_map_size != sstate->prob_a
        || vmap->prob_rev_map_size <= 0) {
      fclose(log_file);
      xfree(log_txt);
      super_html_contest_page_menu(f, session_id, sstate, -1, self_url,
                                   hidden_vars, extra_args);
      fprintf(f, "<h2>variant map is obsolete</h2>\n");
      goto cleanup;
    }
  } else {
    if (super_html_update_variant_map(log_file, cnts->id, userlist_conn,
                                      cnts, global,
                                      sstate->prob_a, sstate->probs,
                                      &sstate->var_header_text,
                                      &sstate->var_footer_text) < 0){
      fclose(log_file); log_file = 0;

      super_html_contest_page_menu(f, session_id, sstate, -1, self_url,
                                   hidden_vars, extra_args);
      fprintf(f, "<h2>variant map cannot be edited</h2>\n");
      fprintf(f, "<font color=\"red\"><pre>%s</pre></font>\n", ARMOR(log_txt));
      xfree(log_txt);
      goto cleanup;
    }
  }

  super_html_contest_page_menu(f, session_id, sstate, -1, self_url, hidden_vars,
                               extra_args);

  fclose(log_file); log_file = 0;

  fprintf(f, "<h2>Variant map</h2>\n");

  while (log_len > 0 && isspace(log_txt[log_len - 1])) log_txt[--log_len] = 0;
  if (log_txt && *log_txt) {
    fprintf(f, "Variant map parsing messages:\n<pre>%s</pre>\n",
            ARMOR(log_txt));
  }

  xfree(log_txt); log_txt = 0;
  vmap = global->variant_map;

  fprintf(f, "<table border=\"0\">\n");
  fprintf(f, "<tr%s><th>User Id</th><th>User Login</th><th>User Name</th>",
          head_row_attr);
  for (j = 0; j < vmap->prob_rev_map_size; j++) {
    prob = sstate->probs[vmap->prob_rev_map[j]];
    fprintf(f, "<th>%s</th>", ARMOR(prob->short_name));
  }
  fprintf(f, "<th>Action</th></tr>\n");

  for (i = 0; i < vmap->u; i++) {
    snprintf(buf, sizeof(buf), "%d", i);
    html_start_form(f, 1, self_url, hidden_vars);
    html_hidden_var(f, "row", buf);
    if (vmap->v[i].user_id > 0)
      snprintf(buf, sizeof(buf), "%d", vmap->v[i].user_id);
    else
      snprintf(buf, sizeof(buf), "&nbsp;");
    if (vmap->v[i].login)
      s = ARMOR(vmap->v[i].login);
    else
      s = "&nbsp;";
    fprintf(f, "<tr%s><td>%s</td><td>%s</td>", form_row_attrs[row ^= 1],
            buf, s);
    if (vmap->v[i].name)
      s = ARMOR(vmap->v[i].name);
    else
      s = "&nbsp;";
    fprintf(f, "<td>%s</td>", s);

    for (j = 0; j < vmap->prob_rev_map_size; j++) {
      prob = sstate->probs[vmap->prob_rev_map[j]];
      fprintf(f, "<td><select name=\"param_%d\">"
              "<option value=\"0\"%s>N/A</option>",
              j, !vmap->v[i].variants[j]?" selected=\"1\"" : "");
      for (k = 1; k <= prob->variant_num; k++)
        fprintf(f, "<option value=\"%d\"%s>%d</option>",
                k, vmap->v[i].variants[j] == k?" selected=\"1\"" : "", k);
      fprintf(f, "</select></td>");
    }
    fprintf(f, "<td>");
    html_submit_button(f, SSERV_CMD_PROB_CHANGE_VARIANTS, "Change");
    html_submit_button(f, SSERV_CMD_PROB_DELETE_VARIANTS, "Delete row");
    fprintf(f, "</td></tr></form>\n");
  }
  fprintf(f, "</table>\n");

  // clear variant, generate random variants
  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<table border=\"0\">");
  fprintf(f, "<tr><td>%s</td><td>", "Problem");
  fprintf(f, "<select name=\"prob_id\">");
  fprintf(f, "<option value=\"\"></option>");
  for (j = 0; j < vmap->prob_rev_map_size; j++) {
    prob = sstate->probs[vmap->prob_rev_map[j]];
    fprintf(f, "<option value=\"%d\">%s - %s</option>",
            prob->id, prob->short_name, ARMOR(prob->long_name));
  }
  fprintf(f, "</select></td><td>");
  html_submit_button(f, SSERV_CMD_PROB_CLEAR_VARIANTS, "Clear variants");
  html_submit_button(f, SSERV_CMD_PROB_RANDOM_VARIANTS, "Random variants");
  fprintf(f, "</table></form>\n");

  super_html_contest_footer_menu(f, session_id, sstate,
                                 self_url, hidden_vars, extra_args);

 cleanup:
  html_armor_free(&ab);
  return 0;
}

int
super_html_variant_param(struct sid_state *sstate, int cmd,
                         int map_i, const unsigned char *param2,
                         int param3, int param4)
{
  struct variant_map *vmap = 0;
  const unsigned char *s;
  int n, total, i;
  int *vars = 0;
  struct section_problem_data *prob = 0;

  if (!sstate || !sstate->global) return -SSERV_ERR_INVALID_PARAMETER;
  if (!(vmap = sstate->global->variant_map)) return -SSERV_ERR_INVALID_PARAMETER;
  if (map_i < 0 || map_i >= vmap->u) return -SSERV_ERR_INVALID_PARAMETER;
  if (!sstate->prob_a || !sstate->probs) return -SSERV_ERR_INVALID_PARAMETER;

  s = param2;
  if (sscanf(s, "%d%n", &total, &n) != 1) return -SSERV_ERR_INVALID_PARAMETER;
  s += n;
  if (total < 0 || total != vmap->prob_rev_map_size)
    return -SSERV_ERR_INVALID_PARAMETER;
  XALLOCAZ(vars, total);
  for (i = 0; i < total; i++) {
    if (sscanf(s, "%d%n", &vars[i], &n) != 1) return -SSERV_ERR_INVALID_PARAMETER;
    s += n;
    if (vars[i] < 0 || vmap->prob_rev_map[i] <= 0
        || vmap->prob_rev_map[i] >= sstate->prob_a
        || !(prob = sstate->probs[vmap->prob_rev_map[i]]))
      return -SSERV_ERR_INVALID_PARAMETER;
    if (prob->variant_num <= 0 || vars[i] > prob->variant_num)
      return -SSERV_ERR_INVALID_PARAMETER;
  }

  switch (cmd) {
  case SSERV_CMD_PROB_DELETE_VARIANTS:
    if (vmap->v[map_i].user_id > 0) {
      for (i = 0; i < total; i++)
        vmap->v[map_i].variants[i] = 0;
    } else {
      xfree(vmap->v[map_i].variants);
      xfree(vmap->v[map_i].login);
      xfree(vmap->v[map_i].name);
      if (map_i < vmap->u - 1)
        memmove(&vmap->v[map_i], &vmap->v[map_i + 1],
                (vmap->u - map_i - 1) * sizeof(vmap->v[0]));
      vmap->u--;
    }
  case SSERV_CMD_PROB_CHANGE_VARIANTS:
    for (i = 0; i < total; i++)
      vmap->v[map_i].variants[i] = vars[i];
    break;
  default:
    abort();
  }

  return 0;
}

int
super_html_variant_prob_op(struct sid_state *sstate, int cmd, int prob_id)
{
  struct variant_map *vmap = 0;
  struct section_problem_data *prob = 0;
  int j, i;

  if (!sstate || !sstate->global) return -SSERV_ERR_INVALID_PARAMETER;
  if (!(vmap = sstate->global->variant_map)) return-SSERV_ERR_INVALID_PARAMETER;
  if (!sstate->prob_a || !sstate->probs) return -SSERV_ERR_INVALID_PARAMETER;
  if (prob_id <= 0 || prob_id >= sstate->prob_a)
    return -SSERV_ERR_INVALID_PARAMETER;
  if (!(prob = sstate->probs[prob_id])) return -SSERV_ERR_INVALID_PARAMETER;
  if (prob->variant_num <= 0) return -SSERV_ERR_INVALID_PARAMETER;
  j = vmap->prob_map[prob_id];
  if (j < 0 || j >= vmap->prob_map_size) return -SSERV_ERR_INVALID_PARAMETER;

  switch (cmd) {
  case SSERV_CMD_PROB_CLEAR_VARIANTS:
    for (i = 0; i < vmap->u; i++)
      vmap->v[i].variants[j] = 0;
    break;
  case SSERV_CMD_PROB_RANDOM_VARIANTS:
    for (i = 0; i < vmap->u; i++) {
      if (prob->variant_num == 1) {
        vmap->v[i].variants[j] = 1;
        continue;
      }
      vmap->v[i].variants[j] = 1 + (int) ((random_u16() / 65536.0) * prob->variant_num);
    }
    break;
  default:
    return -SSERV_ERR_INVALID_PARAMETER;
  }

  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
