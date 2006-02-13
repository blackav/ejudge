/* -*- c -*- */
/* $Id$ */
#ifndef __HTML_H__
#define __HTML_H__

/* Copyright (C) 2000-2006 Alexander Chernov <cher@ispras.ru> */

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

#include <stdio.h>
#include <time.h>

void write_standings(char const *, char const *,int,char const *,char const *,int);
void write_public_log(char const *, char const *, char const *, char const *);

void new_write_user_runs(FILE *f, int uid, int printing_suspended,
                         int accepting_mode,
                         unsigned int show_flags,
                         ej_cookie_t sid,
                         unsigned char const *self_url,
                         unsigned char const *hidden_vars,
                         unsigned char const *extra_args);

void new_write_user_clars(FILE *f, int uid, unsigned int show_flags,
                          ej_cookie_t sid,
                          unsigned char const *self_url,
                          unsigned char const *hidden_vars,
                          unsigned char const *extra_args);

int new_write_user_clar(FILE *, int, int);
int new_write_user_source_view(FILE *, int, int);
int new_write_user_report_view(FILE *f, int uid, int rid,
                               int accepting_mode,
                               ej_cookie_t sid,
                               const unsigned char *self_url,
                               const unsigned char *hidden_vars,
                               const unsigned char *extra_args);

void write_team_page(FILE *f, int user_id,
                     int printing_suspended,
                     ej_cookie_t sid,
                     int all_runs, int all_clars,
                     unsigned char const *self_url,
                     unsigned char const *hidden_vars,
                     unsigned char const *extra_args,
                     time_t server_start,
                     time_t server_end,
                     int accepting_mode);

void write_master_page(FILE *f,
                       int user_id, int priv_level,
                       ej_cookie_t sid,
                       int first_run, int last_run,
                       int mode_clar, int first_clar, int last_clar,
                       int accepting_mode,
                       unsigned char const *self_url,
                       unsigned char const *filter_expr,
                       unsigned char const *hidden_vars,
                       unsigned char const *extra_args,
                       const opcap_t *pcaps);

void write_priv_standings(FILE *f,
                          ej_cookie_t sid,
                          unsigned char const *self_url,
                          unsigned char const *hidden_vars,
                          unsigned char const *extra_args,
                          int accepting_mode);

struct user_filter_info;
int write_priv_all_runs(FILE *f, int user_id, struct user_filter_info *u,
                        int priv_level, ej_cookie_t sid,
                        int first_run, int last_run,
                        int accepting_mode,
                        unsigned char const *self_url,
                        unsigned char const *filter_expr,
                        unsigned char const *hidden_vars,
                        unsigned char const *extra_args);

void write_standings_header(FILE *f,
                            int client_flag,
                            int user_id,
                            unsigned char const * header_str,
                            unsigned char const * user_name);

void do_write_kirov_standings(FILE *f,
                              const unsigned char *stand_dir,
                              int client_flag,
                              const unsigned char *header_str,
                              unsigned char const *footer_str,
                              int raw_flag,
                              int accepting_mode);

void do_write_standings(FILE *f,
                        int client_flag,
                        int user_id,
                        const unsigned char *header_str,
                        unsigned char const *footer_str,
                        int raw_flag,
                        const unsigned char *user_name);

void do_write_moscow_standings(FILE *f,
                               const unsigned char *stand_dir,
                               int client_flag,
                               int user_id,
                               const unsigned char *header_str,
                               const unsigned char *footer_str,
                               int raw_flag,
                               const unsigned char *user_name);

int write_priv_source(FILE *f, int user_id, int priv_level,
                      ej_cookie_t sid,
                      int accepting_mode,
                      unsigned char const *self_url,
                      unsigned char const *hidden_vars,
                      unsigned char const *extra_args,
                      int run_id, const opcap_t *);
int write_new_run_form(FILE *f, int user_id, int priv_level,
                       ej_cookie_t sid,
                       unsigned char const *self_url,
                       unsigned char const *hidden_vars,
                       unsigned char const *extra_args,
                       int run_id, const opcap_t *);
int write_priv_report(FILE *f, int user_id, int priv_level,
                      ej_cookie_t sid,
                      int team_report_flag,
                      unsigned char const *self_url,
                      unsigned char const *hidden_vars,
                      unsigned char const *extra_args,
                      int run_id, const opcap_t *);

int write_priv_clar(FILE *f, int user_id, int priv_level,
                    ej_cookie_t sid,
                    unsigned char const *self_url,
                    unsigned char const *hidden_vars,
                    unsigned char const *extra_args,
                    int clar_id, const opcap_t *);

int write_priv_users(FILE *f, int user_id, int priv_level,
                     ej_cookie_t sid,
                     unsigned char const *self_url,
                     unsigned char const *hidden_vars,
                     unsigned char const *extra_args,
                     const opcap_t *);

int write_priv_user(FILE *f, int user_id, int priv_level,
                    ej_cookie_t sid,
                    unsigned char const *self_url,
                    unsigned char const *hidden_vars,
                    unsigned char const *extra_args,
                    int view_user_id,
                    const opcap_t *);

int write_virtual_standings(FILE *f, int user_id);

void html_reset_filter(int user_id, ej_cookie_t session_id);
void html_reset_clar_filter(int user_id, ej_cookie_t session_id);

void write_runs_dump(FILE *f, const unsigned char *,
                     unsigned char const *charset);
void write_raw_standings(FILE *f, unsigned char const *charset);
int write_raw_source(FILE *f, const unsigned char *, int run_id);
int write_raw_report(FILE *f, const unsigned char *self_url, int run_id,
                     int team_report_flag);

struct run_entry;
struct section_problem_data;

int calc_kirov_score(unsigned char *outbuf, size_t outsize,
                     struct run_entry *pe,
                     struct section_problem_data *pr,
                     int attempts,
                     int disq_attempts,
                     int prev_successes,
                     int *p_date_penalty);
void write_html_run_status(FILE *f, struct run_entry *pe,
                           int priv_level, int attempts,
                           int disq_attempts, int prev_successes);

int write_tests(FILE *f, int cmd, int run_id, int test_num);

int write_xml_testing_report(FILE *f, unsigned char const *txt,
                             ej_cookie_t sid,
                             unsigned char const *self_url,
                             unsigned char const *extra_args);
int write_xml_team_testing_report(FILE *f, const unsigned char *txt);

int write_audit_log(FILE *f, int run_id);

void generate_daily_statistics(FILE *f, time_t from_time, time_t to_time);

#endif /* __HTML_H__ */
