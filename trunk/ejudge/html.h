/* -*- c -*- */
/* $Id$ */
#ifndef __HTML_H__
#define __HTML_H__

/* Copyright (C) 2000-2008 Alexander Chernov <cher@ejudge.ru> */

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

#include "opcaps.h"
#include "ej_types.h"
#include "serve_state.h"

#include <stdio.h>
#include <time.h>

void write_standings(const serve_state_t,
                     const struct contest_desc *,
                     char const *, char const *,
                     int, char const *, char const *, int, int, int);
void write_public_log(const serve_state_t,
                      const struct contest_desc *,
                      char const *, char const *,
                      char const *, char const *, int);

void new_write_user_runs(const serve_state_t, FILE *f, int uid,
                         unsigned int show_flags,
                         int prob_id,
                         int action_view_source,
                         int action_view_report,
                         int action_print_run,
                         ej_cookie_t sid,
                         unsigned char const *self_url,
                         unsigned char const *hidden_vars,
                         unsigned char const *extra_args,
                         const unsigned char *table_class);

void new_write_user_clars(const serve_state_t,
                          FILE *f, int uid, unsigned int show_flags,
                          int action, ej_cookie_t sid,
                          unsigned char const *self_url,
                          unsigned char const *hidden_vars,
                          unsigned char const *extra_args,
                          const unsigned char *table_class);

int new_write_user_clar(const serve_state_t, const struct contest_desc *,
                        FILE *, int, int, int);
int new_write_user_source_view(const serve_state_t, FILE *, int, int, int);
int write_user_run_status(const serve_state_t, FILE *, int, int, int, int);
int new_write_user_report_view(const serve_state_t, FILE *f, int uid, int rid,
                               int accepting_mode,
                               const int *action_vec,
                               ej_cookie_t sid,
                               const unsigned char *self_url,
                               const unsigned char *hidden_vars,
                               const unsigned char *extra_args);

void write_team_page(const serve_state_t,
                     const struct contest_desc *cnts,
                     FILE *f, int user_id,
                     ej_cookie_t sid,
                     int all_runs, int all_clars,
                     unsigned char const *self_url,
                     unsigned char const *hidden_vars,
                     unsigned char const *extra_args,
                     time_t server_start,
                     time_t server_end,
                     int accepting_mode);

void write_master_page(serve_state_t, FILE *f,
                       int user_id, int priv_level,
                       ej_cookie_t sid,
                       int first_run, int last_run,
                       int mode_clar, int first_clar, int last_clar,
                       unsigned char const *self_url,
                       unsigned char const *filter_expr,
                       unsigned char const *hidden_vars,
                       unsigned char const *extra_args,
                       const opcap_t *pcaps);

void write_priv_standings(const serve_state_t,
                          const struct contest_desc *cnts,
                          FILE *f,
                          ej_cookie_t sid,
                          unsigned char const *self_url,
                          unsigned char const *hidden_vars,
                          unsigned char const *extra_args,
                          int accepting_mode);

struct user_filter_info;
int write_priv_all_runs(const serve_state_t, FILE *f,
                        int user_id, struct user_filter_info *u,
                        int priv_level, ej_cookie_t sid,
                        int first_run, int last_run,
                        unsigned char const *self_url,
                        unsigned char const *filter_expr,
                        unsigned char const *hidden_vars,
                        unsigned char const *extra_args);

void write_standings_header(const serve_state_t state,
                            const struct contest_desc * cnts,
                            FILE *f,
                            int client_flag,
                            int user_id,
                            unsigned char const * header_str,
                            unsigned char const * user_name);

void do_write_kirov_standings(const serve_state_t,
                              const struct contest_desc *cnts,
                              FILE *f,
                              const unsigned char *stand_dir,
                              int client_flag, int only_table_flag,
                              const unsigned char *header_str,
                              unsigned char const *footer_str,
                              int raw_flag,
                              int accepting_mode,
                              int force_fancy_style,
                              time_t cur_time,
                              int charset_id);

void do_write_standings(const serve_state_t,
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
                        time_t cur_time);

void do_write_moscow_standings(const serve_state_t,
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
                               int charset_id);

int write_priv_source(const serve_state_t, FILE *f, int user_id, int priv_level,
                      ej_cookie_t sid,
                      unsigned char const *self_url,
                      unsigned char const *hidden_vars,
                      unsigned char const *extra_args,
                      int run_id, const opcap_t *);
int write_new_run_form(const serve_state_t, FILE *f,
                       int user_id, int priv_level,
                       ej_cookie_t sid,
                       unsigned char const *self_url,
                       unsigned char const *hidden_vars,
                       unsigned char const *extra_args,
                       int run_id, const opcap_t *);
int write_priv_report(const serve_state_t, FILE *f, int user_id, int priv_level,
                      ej_cookie_t sid,
                      int team_report_flag,
                      unsigned char const *self_url,
                      unsigned char const *hidden_vars,
                      unsigned char const *extra_args,
                      int run_id, const opcap_t *);

int write_priv_clar(const serve_state_t, FILE *f, int user_id, int priv_level,
                    ej_cookie_t sid,
                    unsigned char const *self_url,
                    unsigned char const *hidden_vars,
                    unsigned char const *extra_args,
                    int clar_id, const opcap_t *);

int write_priv_users(const serve_state_t, FILE *f, int user_id, int priv_level,
                     ej_cookie_t sid,
                     unsigned char const *self_url,
                     unsigned char const *hidden_vars,
                     unsigned char const *extra_args,
                     const opcap_t *);

int write_priv_user(const serve_state_t, FILE *f, int user_id, int priv_level,
                    ej_cookie_t sid,
                    unsigned char const *self_url,
                    unsigned char const *hidden_vars,
                    unsigned char const *extra_args,
                    int view_user_id,
                    const opcap_t *);

int write_virtual_standings(const serve_state_t,
                            const struct contest_desc *cnts,
                            FILE *f, int user_id, int force_fancy_style);

void html_reset_filter(serve_state_t, int user_id, ej_cookie_t session_id);
void html_reset_clar_filter(serve_state_t, int user_id, ej_cookie_t session_id);

void write_runs_dump(const serve_state_t, FILE *f, const unsigned char *,
                     unsigned char const *charset);
void write_raw_standings(const serve_state_t,
                         const struct contest_desc *cnts,
                         FILE *f,
                         unsigned char const *charset);
int write_raw_source(const serve_state_t, FILE *f,
                     const unsigned char *, int run_id);
int write_raw_report(const serve_state_t, FILE *f,
                     const unsigned char *self_url, int run_id,
                     int team_report_flag);

struct run_entry;
struct section_problem_data;

int calc_kirov_score(unsigned char *outbuf, size_t outsize,
                     const struct run_entry *pe,
                     const struct section_problem_data *pr,
                     int attempts,
                     int disq_attempts,
                     int prev_successes,
                     int *p_date_penalty,
                     int format);
void write_html_run_status(const serve_state_t, FILE *f,
                           const struct run_entry *pe,
                           int priv_level, int attempts,
                           int disq_attempts, int prev_successes,
                           const unsigned char *td_class);

int write_tests(const serve_state_t, FILE *f, int cmd, int run_id,
                int test_num);

int write_xml_testing_report(FILE *f, unsigned char const *txt,
                             ej_cookie_t sid,
                             unsigned char const *self_url,
                             unsigned char const *extra_args,
                             const int *actions_vector,
                             const unsigned char *class1,
                             const unsigned char *class2);
int write_xml_team_testing_report(serve_state_t, FILE *f,
                                  int output_only,
                                  const unsigned char *txt,
                                  const unsigned char *table_class);

int write_audit_log(const serve_state_t, FILE *f, int run_id);

void generate_daily_statistics(const serve_state_t, FILE *f,
                               time_t from_time, time_t to_time, int utf8_mode);

void
html_write_user_problems_summary(const serve_state_t state,
                                 FILE *f, int user_id,
                                 unsigned char *solved_flag,
                                 unsigned char *accepted_flag,
                                 int no_output_flag,
                                 int accepting_mode,
                                 const unsigned char *table_class);
void
write_change_status_dialog(const serve_state_t state,
                           FILE *f, unsigned char const *var_name,
                           int disable_rejudge_flag,
                           const unsigned char *td_class);

int
write_xml_team_accepting_report(FILE *f, const unsigned char *txt,
                                int rid, const struct run_entry *re,
                                const struct section_problem_data *prob,
                                const int *action_vec,
                                ej_cookie_t sid,
                                int exam_mode,
                                const unsigned char *self_url,
                                const unsigned char *extra_args,
                                const unsigned char *table_class);

void
write_text_run_status(const serve_state_t state, FILE *f, struct run_entry *pe,
                      int priv_level, int attempts, int disq_attempts,
                      int prev_successes);

unsigned char*
score_view_display(
        unsigned char *buf,
        size_t size,
        const struct section_problem_data *prob,
        int score);

#endif /* __HTML_H__ */
