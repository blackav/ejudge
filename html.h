/* -*- c -*- */
/* $Id$ */
#ifndef __HTML_H__
#define __HTML_H__

/* Copyright (C) 2000-2004 Alexander Chernov <cher@ispras.ru> */

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

#include <stdio.h>
#include <time.h>

void write_standings(char const *, char const *, char const *, char const *);
void write_public_log(char const *, char const *, char const *, char const *);

void new_write_user_runs(FILE *f, int uid, int printing_suspended,
                         unsigned int show_flags,
                         int sid_mode, unsigned long long sid,
                         unsigned char const *self_url,
                         unsigned char const *hidden_vars,
                         unsigned char const *extra_args);

void new_write_user_clars(FILE *f, int uid, unsigned int show_flags,
                          int sid_mode, unsigned long long sid,
                          unsigned char const *self_url,
                          unsigned char const *hidden_vars,
                          unsigned char const *extra_args);

int new_write_user_clar(FILE *, int, int);
int new_write_user_source_view(FILE *, int, int);
int new_write_user_report_view(FILE *, int, int);

void write_team_page(FILE *f, int user_id,
                     int printing_suspended,
                     int sid_mode, unsigned long long sid,
                     int all_runs, int all_clars,
                     unsigned char const *self_url,
                     unsigned char const *hidden_vars,
                     unsigned char const *extra_args,
                     time_t server_start,
                     time_t server_end);

void write_master_page(FILE *f,
                       int user_id, int priv_level,
                       int sid_mode, unsigned long long sid,
                       int first_run, int last_run,
                       int first_clar, int last_clar,
                       unsigned char const *self_url,
                       unsigned char const *filter_expr,
                       unsigned char const *hidden_vars,
                       unsigned char const *extra_args,
                       const opcap_t *pcaps);

void write_priv_standings(FILE *f,
                          int sid_mode,
                          unsigned long long sid,
                          unsigned char const *self_url,
                          unsigned char const *hidden_vars,
                          unsigned char const *extra_args);

void write_standings_header(FILE *f,
                            int client_flag,
                            int user_id,
                            unsigned char const * header_str,
                            unsigned char const * user_name);

void do_write_kirov_standings(FILE *, int, unsigned char const *, int);
void do_write_standings(FILE *, int, int, unsigned char const *, int);

int write_priv_source(FILE *f, int user_id, int priv_level,
                      int sid_mode, unsigned long long sid,
                      unsigned char const *self_url,
                      unsigned char const *hidden_vars,
                      unsigned char const *extra_args,
                      int run_id, const opcap_t *);
int write_priv_report(FILE *f, int user_id, int priv_level,
                      int sid_mode, unsigned long long sid,
                      int team_report_flag,
                      unsigned char const *self_url,
                      unsigned char const *hidden_vars,
                      unsigned char const *extra_args,
                      int run_id, const opcap_t *);

int write_priv_clar(FILE *f, int user_id, int priv_level,
                    int sid_mode, unsigned long long sid,
                    unsigned char const *self_url,
                    unsigned char const *hidden_vars,
                    unsigned char const *extra_args,
                    int clar_id, const opcap_t *);

int write_priv_users(FILE *f, int user_id, int priv_level,
                     int sid_mode, unsigned long long sid,
                     unsigned char const *self_url,
                     unsigned char const *hidden_vars,
                     unsigned char const *extra_args,
                     const opcap_t *);

void html_start_form(FILE *f, int mode,
                     int sid_mode, unsigned long long sid,
                     unsigned char const *self_url,
                     unsigned char const *hidden_vars,
                     unsigned char const *extra_args);
unsigned char *html_hyperref(unsigned char *buf, int size,
                             int sid_mode, unsigned long long sid,
                             unsigned char const *self_url,
                             unsigned char const *format,
                             unsigned char const *extra_args, ...);

int write_virtual_standings(FILE *f, int user_id);

void html_reset_filter(int user_id, unsigned long long session_id);

void write_runs_dump(FILE *f, unsigned char const *charset);
void write_raw_standings(FILE *f, unsigned char const *charset);
int write_raw_source(FILE *f, int run_id);

#endif /* __HTML_H__ */
