/* -*- c -*- */
#ifndef __HTML_H__
#define __HTML_H__

/* Copyright (C) 2000-2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/opcaps.h"
#include "ejudge/ej_types.h"
#include "ejudge/serve_state.h"

#include <stdio.h>
#include <time.h>

void
write_standings(
        const serve_state_t,
        const struct contest_desc *,
        char const *,
        char const *,
        int,
        char const *,
        char const *,
        int,
        int,
        int,
        int user_mode);
void
write_public_log(
        const serve_state_t,
        const struct contest_desc *,
        char const *,
        char const *,
        char const *,
        char const *,
        int,
        int user_mode);

void write_standings_header(const serve_state_t state,
                            const struct contest_desc * cnts,
                            FILE *f,
                            int client_flag,
                            int user_id,
                            unsigned char const * header_str,
                            unsigned char const * user_name);

struct user_filter_info;

void
do_write_kirov_standings(
        const serve_state_t,
        const struct contest_desc *cnts,
        FILE *f,
        const unsigned char *stand_dir,
        int client_flag,
        int only_table_flag,
        int user_id,
        const unsigned char *header_str,
        unsigned char const *footer_str,
        int raw_flag,
        int accepting_mode,
        int force_fancy_style,
        time_t cur_time,
        int charset_id,
        struct user_filter_info *u,
        int user_mode);

void
do_write_standings(
        const serve_state_t,
        const struct contest_desc *cnts,
        FILE *f,
        int client_flag,
        int only_table_flag,
        int user_id,
        const unsigned char *header_str,
        unsigned char const *footer_str,
        int raw_flag,
        const unsigned char *user_name,
        int force_fancy_style,
        time_t cur_time,
        struct user_filter_info *u);

void
do_write_moscow_standings(
        const serve_state_t,
        const struct contest_desc *cnts,
        FILE *f,
        const unsigned char *stand_dir,
        int client_flag, int only_table_flag,
        int user_id,
        const unsigned char *header_str,
        const unsigned char *footer_str,
        int raw_flag,
        const unsigned char *user_name,
        int force_fancy_style,
        time_t cur_time,
        int charset_id,
        struct user_filter_info *u);

void html_reset_filter(serve_state_t, int user_id, ej_cookie_t session_id);
void html_reset_clar_filter(serve_state_t, int user_id, ej_cookie_t session_id);

void write_runs_dump(const serve_state_t, FILE *f, const unsigned char *,
                     unsigned char const *charset);
struct run_entry;
struct section_problem_data;
struct penalty_info;

int
calc_kirov_score(
        unsigned char *outbuf,
        size_t outsize,
        time_t start_time,
        int separate_user_score,
        int user_mode,
        int token_flags,
        const struct run_entry *pe,
        const struct section_problem_data *pr,
        int attempts,
        int disq_attempts,
        int prev_successes,
        int *p_date_penalty,
        int format);
void
write_html_run_status(
        const serve_state_t,
        FILE *f,
        time_t start_time,
        const struct run_entry *pe,
        int user_mode,
        int priv_level,
        int attempts,
        int disq_attempts,
        int prev_successes,
        const unsigned char *td_class,
        int disable_failed,
        int enable_js_status_menu,
        int run_fields);

int
write_xml_tests_report(
        FILE *f,
        int user_mode,
        unsigned char const *txt,
        ej_cookie_t sid,
        unsigned char const *self_url,
        unsigned char const *extra_args,
        const unsigned char *class1,
        const unsigned char *class2);

void
generate_daily_statistics(
        const struct contest_desc *cnts,
        const serve_state_t, FILE *f,
        time_t from_time,
        time_t to_time,
        int utf8_mode);

void
write_change_status_dialog(const serve_state_t state,
                           FILE *f, unsigned char const *var_name,
                           int disable_rejudge_flag,
                           const unsigned char *td_class,
                           int cur_value, int is_readonly);

void
write_text_run_status(
        const serve_state_t state,
        FILE *f,
        time_t start_time,
        struct run_entry *pe,
        int user_mode,
        int priv_level,
        int attempts,
        int disq_attempts,
        int prev_successes);

unsigned char*
score_view_display(
        unsigned char *buf,
        size_t size,
        const struct section_problem_data *prob,
        int score);
void
score_view_display_f(
        FILE *out_f,
        const struct section_problem_data *prob,
        int score);

/* run field selection flags */
enum
{
  RUN_VIEW_RUN_ID,
  RUN_VIEW_SIZE,
  RUN_VIEW_TIME,
  RUN_VIEW_ABS_TIME,
  RUN_VIEW_REL_TIME,
  RUN_VIEW_NSEC,
  RUN_VIEW_USER_ID,
  RUN_VIEW_USER_LOGIN,
  RUN_VIEW_USER_NAME,
  RUN_VIEW_PROB_ID,
  RUN_VIEW_PROB_NAME,
  RUN_VIEW_LANG_ID,
  RUN_VIEW_LANG_NAME,
  RUN_VIEW_IP,
  RUN_VIEW_SHA1,
  RUN_VIEW_SCORE,
  RUN_VIEW_TEST,
  RUN_VIEW_SCORE_ADJ,
  RUN_VIEW_STATUS,
  RUN_VIEW_VARIANT,
  RUN_VIEW_MIME_TYPE,
  RUN_VIEW_SAVED_SCORE,
  RUN_VIEW_SAVED_TEST,
  RUN_VIEW_SAVED_STATUS,
  RUN_VIEW_RUN_UUID,
  RUN_VIEW_EOLN_TYPE,
  RUN_VIEW_STORE_FLAGS,
  RUN_VIEW_TOKENS,

  RUN_VIEW_LAST,

  RUN_VIEW_DEFAULT = (1 << RUN_VIEW_RUN_ID)
  | (1 << RUN_VIEW_TIME)
  //| (1 << RUN_VIEW_SIZE)
  //| (1 << RUN_VIEW_IP)
  //| (1 << RUN_VIEW_USER_ID)
  | (1 << RUN_VIEW_USER_NAME)
  | (1 << RUN_VIEW_PROB_NAME)
  | (1 << RUN_VIEW_LANG_NAME)
  | (1 << RUN_VIEW_STATUS)
  | (1 << RUN_VIEW_TEST)
  | (1 << RUN_VIEW_SCORE)
};

struct testing_report_file_content;
struct html_armor_buffer;
void
html_print_testing_report_file_content(
        FILE *out_f,
        struct html_armor_buffer *pab,
        struct testing_report_file_content *fc,
        int type);

#endif /* __HTML_H__ */
