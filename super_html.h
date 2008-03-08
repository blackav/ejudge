/* -*- c -*- */
/* $Id$ */
#ifndef __SUPER_HTML_H__
#define __SUPER_HTML_H__

/* Copyright (C) 2004-2008 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdio.h>

struct ejudge_cfg;
struct sid_state;

int super_html_main_page(FILE *f,
                         int priv_level,
                         int user_id,
                         const unsigned char *login,
                         ej_cookie_t session_id,
                         ej_ip_t ip_address,
                         int ssl,
                         unsigned int flags,
                         struct ejudge_cfg *config,
                         struct sid_state *sstate,
                         const unsigned char *self_url,
                         const unsigned char *hidden_vars,
                         const unsigned char *extra_args);

int super_html_contest_page(FILE *f,
                            int priv_level,
                            int user_id,
                            int contest_id,
                            const unsigned char *login,
                            ej_cookie_t session_id,
                            ej_ip_t ip_address,
                            int ssl,
                            struct ejudge_cfg *config,
                            const unsigned char *self_url,
                            const unsigned char *hidden_vars,
                            const unsigned char *extra_args);

int super_html_serve_probe_run(FILE *f,
                               int priv_level,
                               int user_id,
                               int contest_id,
                               const unsigned char *login,
                               ej_cookie_t session_id,
                               ej_ip_t ip_address,
                               int ssl,
                               struct ejudge_cfg *config,
                               const unsigned char *self_url,
                               const unsigned char *hidden_vars,
                               const unsigned char *extra_args);

int super_html_log_page(FILE *f,
                        int cmd,
                        int priv_level,
                        int user_id,
                        int contest_id,
                        const unsigned char *login,
                        ej_cookie_t session_id,
                        ej_ip_t ip_address,
                        int ssl,
                        struct ejudge_cfg *config,
                        const unsigned char *self_url,
                        const unsigned char *hidden_vars,
                        const unsigned char *extra_args);

int super_html_edit_contest_page(FILE *f,
                                 int priv_level,
                                 int user_id,
                                 const unsigned char *login,
                                 ej_cookie_t session_id,
                                 ej_ip_t ip_address,
                                 struct ejudge_cfg *config,
                                 struct sid_state *sstate,
                                 const unsigned char *self_url,
                                 const unsigned char *hidden_vars,
                                 const unsigned char *extra_args);

int super_html_edit_access_rules(FILE *f,
                                 int priv_level,
                                 int user_id,
                                 const unsigned char *login,
                                 ej_cookie_t session_id,
                                 ej_ip_t ip_address,
                                 struct ejudge_cfg *config,
                                 struct sid_state *sstate,
                                 int cmd,
                                 const unsigned char *self_url,
                                 const unsigned char *hidden_vars,
                                 const unsigned char *extra_args);

int super_html_edit_permission(FILE *f,
                               int priv_level,
                               int user_id,
                               const unsigned char *login,
                               ej_cookie_t session_id,
                               ej_ip_t ip_address,
                               struct ejudge_cfg *config,
                               struct sid_state *sstate,
                               int num,
                               const unsigned char *self_url,
                               const unsigned char *hidden_vars,
                               const unsigned char *extra_args);

int super_html_edit_form_fields(FILE *f,
                                int priv_level,
                                int user_id,
                                const unsigned char *login,
                                ej_cookie_t session_id,
                                ej_ip_t ip_address,
                                struct ejudge_cfg *config,
                                struct sid_state *sstate,
                                int cmd,
                                const unsigned char *self_url,
                                const unsigned char *hidden_vars,
                                const unsigned char *extra_args);

int super_html_edit_template_file(FILE *f,
                                  int priv_level,
                                  int user_id,
                                  const unsigned char *login,
                                  ej_cookie_t session_id,
                                  ej_ip_t ip_address,
                                  struct ejudge_cfg *config,
                                  struct sid_state *sstate,
                                  int cmd,
                                  const unsigned char *self_url,
                                  const unsigned char *hidden_vars,
                                  const unsigned char *extra_args);

int super_html_create_contest(FILE *f,
                              int priv_level,
                              int user_id,
                              const unsigned char *login,
                              ej_cookie_t session_id,
                              ej_ip_t ip_address,
                              struct ejudge_cfg *config,
                              struct sid_state *sstate,
                              const unsigned char *self_url,
                              const unsigned char *hidden_vars,
                              const unsigned char *extra_args);

int super_html_create_contest_2(FILE *f,
                                int priv_level,
                                int user_id,
                                const unsigned char *login,
                                const unsigned char *ss_login,
                                ej_cookie_t session_id,
                                ej_ip_t ip_address,
                                struct ejudge_cfg *config,
                                struct sid_state *sstate,
                                int num_mode,
                                int templ_mode,
                                int contest_id,
                                int templ_id,
                                const unsigned char *self_url,
                                const unsigned char *hidden_vars,
                                const unsigned char *extra_args);

struct userlist_clnt;
int super_html_commit_contest(FILE *f,
                              int priv_level,
                              int user_id,
                              const unsigned char *login,
                              ej_cookie_t session_id,
                              ej_ip_t ip_address,
                              struct ejudge_cfg *config,
                              struct userlist_clnt *us_conn,
                              struct sid_state *sstate,
                              int cmd,
                              const unsigned char *self_url,
                              const unsigned char *hidden_vars,
                              const unsigned char *extra_args);

int super_html_edit_global_parameters(FILE *f,
                                      int priv_level,
                                      int user_id,
                                      const unsigned char *login,
                                      ej_cookie_t session_id,
                                      ej_ip_t ip_address,
                                      struct ejudge_cfg *config,
                                      struct sid_state *sstate,
                                      const unsigned char *self_url,
                                      const unsigned char *hidden_vars,
                                      const unsigned char *extra_args);

int super_html_edit_languages(FILE *f,
                              int priv_level,
                              int user_id,
                              const unsigned char *login,
                              ej_cookie_t session_id,
                              ej_ip_t ip_address,
                              const struct ejudge_cfg *config,
                              struct sid_state *sstate,
                              const unsigned char *self_url,
                              const unsigned char *hidden_vars,
                              const unsigned char *extra_args);

int super_html_edit_problems(FILE *f,
                             int priv_level,
                             int user_id,
                             const unsigned char *login,
                             ej_cookie_t session_id,
                             ej_ip_t ip_address,
                             const struct ejudge_cfg *config,
                             struct sid_state *sstate,
                             const unsigned char *self_url,
                             const unsigned char *hidden_vars,
                             const unsigned char *extra_args);

int super_html_view_new_serve_cfg(FILE *f,
                                  int priv_level,
                                  int user_id,
                                  const unsigned char *login,
                                  ej_cookie_t session_id,
                                  ej_ip_t ip_address,
                                  const struct ejudge_cfg *config,
                                  struct sid_state *sstate,
                                  const unsigned char *self_url,
                                  const unsigned char *hidden_vars,
                                  const unsigned char *extra_args);

void super_html_contest_page_menu(FILE *f, 
                                  ej_cookie_t session_id,
                                  struct sid_state *sstate,
                                  int cur_page,
                                  const unsigned char *self_url,
                                  const unsigned char *hidden_vars,
                                  const unsigned char *extra_args);

void super_html_contest_footer_menu(FILE *f, 
                                    ej_cookie_t session_id,
                                    struct sid_state *sstate,
                                    const unsigned char *self_url,
                                    const unsigned char *hidden_vars,
                                    const unsigned char *extra_args);

struct contest_desc;
struct sid_state;

int super_html_open_contest(struct contest_desc *cnts, int user_id,
                            const unsigned char *user_login, ej_ip_t ip);
int super_html_close_contest(struct contest_desc *cnts, int user_id,
                             const unsigned char *user_login, ej_ip_t ip);

int super_html_make_invisible_contest(struct contest_desc *cnts,
                                      int user_id,
                                      const unsigned char *user_login,
                                      ej_ip_t ip);
int super_html_make_visible_contest(struct contest_desc *cnts,
                                    int user_id,
                                    const unsigned char *user_login,
                                    ej_ip_t ip);

int super_html_serve_managed_contest(struct contest_desc *cnts, int user_id,
                                     const unsigned char *user_login,
                                     ej_ip_t ip);
int super_html_serve_unmanaged_contest(struct contest_desc *cnts, int user_id,
                                       const unsigned char *user_login,
                                       ej_ip_t ip);

int super_html_run_managed_contest(struct contest_desc *cnts, int user_id,
                                   const unsigned char *user_login,
                                   ej_ip_t ip);
int super_html_run_unmanaged_contest(struct contest_desc *cnts, int user_id,
                                     const unsigned char *user_login,
                                     ej_ip_t ip);

struct contest_desc *contest_tmpl_new(int contest_id,
                                      const unsigned char *login,
                                      const unsigned char *self_url,
                                      const unsigned char *ss_login,
                                      const struct ejudge_cfg *ejudge_config);
struct contest_desc *contest_tmpl_clone(struct sid_state *sstate,
                                        int contest_id, int orig_id,
                                        const unsigned char *login,
                                        const unsigned char *ss_login);

int super_html_clear_variable(struct sid_state *sstate, int cmd);

int super_html_set_contest_var(struct sid_state *sstate, int cmd,
                               int param1, const unsigned char *param2,
                               int param3, int param4, int param5);

int super_html_lang_cmd(struct sid_state *sstate, int cmd,
                        int param1, const unsigned char *param2,
                        int param3, int param4);

int super_html_prob_cmd(struct sid_state *sstate, int cmd,
                        int param1, const unsigned char *param2,
                        int param3, int param4);

int super_html_prob_param(struct sid_state *sstate, int cmd,
                          int param1, const unsigned char *param2,
                          int param3, int param4);

int super_html_global_param(struct sid_state *sstate, int cmd,
                            const struct ejudge_cfg *config,
                            int param1, const unsigned char *param2,
                            int param3, int param4);

int super_html_report_error(FILE *f,
                            ej_cookie_t session_id,
                            const unsigned char *self_url,
                            const unsigned char *extra_args,
                            const char *format, ...);

int super_html_get_serve_header_and_footer(const unsigned char *path,
                                           unsigned char **p_header,
                                           unsigned char **p_footer);
int super_html_serve_unparse_and_save(const unsigned char *path,
                                      const unsigned char *tmp_path,
                                      const struct sid_state *sstate,
                                      const struct ejudge_cfg *config,
                                      const unsigned char *charset,
                                      const unsigned char *header,
                                      const unsigned char *footer,
                                      const unsigned char *audit);

int super_html_read_serve(FILE *flog,
                          const unsigned char *path,
                          const struct ejudge_cfg *config,
                          const struct contest_desc *cnts,
                          struct sid_state *sstate);
void super_html_load_serve_cfg(const struct contest_desc *cnts,
                               const struct ejudge_cfg *config,
                               struct sid_state *sstate);
void super_html_fix_serve(struct sid_state *sstate,
                          int orig_id, int contest_id);

int super_html_check_tests(FILE *f,
                           int priv_level,
                           int user_id,
                           const unsigned char *login,
                           ej_cookie_t session_id,
                           ej_ip_t ip_address,
                           struct ejudge_cfg *config,
                           struct sid_state *sstate,
                           const unsigned char *self_url,
                           const unsigned char *hidden_vars,
                           const unsigned char *extra_args);

int super_html_update_versions(struct sid_state *sstate);

int super_html_edit_variants(FILE *f, int cmd, int priv_level, int user_id,
                             const unsigned char *login,
                             ej_cookie_t session_id,
                             ej_ip_t ip_address,
                             int ssl_flag,
                             struct userlist_clnt *userlist_conn,
                             const struct ejudge_cfg *config,
                             struct sid_state *sstate,
                             const unsigned char *self_url,
                             const unsigned char *hidden_vars,
                             const unsigned char *extra_args);

int super_html_variant_param(struct sid_state *sstate, int cmd,
                             int param1, const unsigned char *param2,
                             int param3, int param4);
int super_html_variant_prob_op(struct sid_state *sstate, int cmd, int prob_id);

struct section_problem_data;
struct section_global_data;
int
super_html_update_variant_map(FILE *flog, int contest_id,
                              struct userlist_clnt *server_conn,
                              struct contest_desc *cnts,
                              struct section_global_data *global,
                              int total_probs,
                              struct section_problem_data **probs,
                              unsigned char **p_header_txt,
                              unsigned char **p_footer_txt);

struct super_http_request_info;
void
super_html_http_request(
        char **p_out_t,
        size_t *p_out_z,
        struct super_http_request_info *hr);

#endif /* __SUPER_HTML_H__ */
