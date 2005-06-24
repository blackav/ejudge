/* -*- c -*- */
/* $Id$ */
#ifndef __SUPER_HTML_H__
#define __SUPER_HTML_H__

/* Copyright (C) 2004,2005 Alexander Chernov <cher@ispras.ru> */

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

#include <stdio.h>

struct userlist_cfg;
struct sid_state;

int super_html_main_page(FILE *f,
                         int priv_level,
                         int user_id,
                         const unsigned char *login,
                         unsigned long long session_id,
                         unsigned long ip_address,
                         unsigned int flags,
                         struct userlist_cfg *config,
                         struct sid_state *sstate,
                         const unsigned char *self_url,
                         const unsigned char *hidden_vars,
                         const unsigned char *extra_args);

int super_html_contest_page(FILE *f,
                            int priv_level,
                            int user_id,
                            int contest_id,
                            const unsigned char *login,
                            unsigned long long session_id,
                            unsigned long ip_address,
                            struct userlist_cfg *config,
                            const unsigned char *self_url,
                            const unsigned char *hidden_vars,
                            const unsigned char *extra_args);

int super_html_log_page(FILE *f,
                        int cmd,
                        int priv_level,
                        int user_id,
                        int contest_id,
                        const unsigned char *login,
                        unsigned long long session_id,
                        unsigned long ip_address,
                        struct userlist_cfg *config,
                        const unsigned char *self_url,
                        const unsigned char *hidden_vars,
                        const unsigned char *extra_args);

int super_html_edit_contest_page(FILE *f,
                                 int priv_level,
                                 int user_id,
                                 const unsigned char *login,
                                 unsigned long long session_id,
                                 unsigned long ip_address,
                                 struct userlist_cfg *config,
                                 struct sid_state *sstate,
                                 const unsigned char *self_url,
                                 const unsigned char *hidden_vars,
                                 const unsigned char *extra_args);

int super_html_edit_access_rules(FILE *f,
                                 int priv_level,
                                 int user_id,
                                 const unsigned char *login,
                                 unsigned long long session_id,
                                 unsigned long ip_address,
                                 struct userlist_cfg *config,
                                 struct sid_state *sstate,
                                 int cmd,
                                 const unsigned char *self_url,
                                 const unsigned char *hidden_vars,
                                 const unsigned char *extra_args);

int super_html_edit_permission(FILE *f,
                               int priv_level,
                               int user_id,
                               const unsigned char *login,
                               unsigned long long session_id,
                               unsigned long ip_address,
                               struct userlist_cfg *config,
                               struct sid_state *sstate,
                               int num,
                               const unsigned char *self_url,
                               const unsigned char *hidden_vars,
                               const unsigned char *extra_args);

int super_html_edit_form_fields(FILE *f,
                                int priv_level,
                                int user_id,
                                const unsigned char *login,
                                unsigned long long session_id,
                                unsigned long ip_address,
                                struct userlist_cfg *config,
                                struct sid_state *sstate,
                                int cmd,
                                const unsigned char *self_url,
                                const unsigned char *hidden_vars,
                                const unsigned char *extra_args);

int super_html_edit_template_file(FILE *f,
                                  int priv_level,
                                  int user_id,
                                  const unsigned char *login,
                                  unsigned long long session_id,
                                  unsigned long ip_address,
                                  struct userlist_cfg *config,
                                  struct sid_state *sstate,
                                  int cmd,
                                  const unsigned char *self_url,
                                  const unsigned char *hidden_vars,
                                  const unsigned char *extra_args);

int super_html_create_contest(FILE *f,
                              int priv_level,
                              int user_id,
                              const unsigned char *login,
                              unsigned long long session_id,
                              unsigned long ip_address,
                              struct userlist_cfg *config,
                              struct sid_state *sstate,
                              const unsigned char *self_url,
                              const unsigned char *hidden_vars,
                              const unsigned char *extra_args);

int super_html_create_contest_2(FILE *f,
                                int priv_level,
                                int user_id,
                                const unsigned char *login,
                                unsigned long long session_id,
                                unsigned long ip_address,
                                struct userlist_cfg *config,
                                struct sid_state *sstate,
                                int num_mode,
                                int templ_mode,
                                int contest_id,
                                int templ_id,
                                const unsigned char *self_url,
                                const unsigned char *hidden_vars,
                                const unsigned char *extra_args);

int super_html_commit_contest(FILE *f,
                              int priv_level,
                              int user_id,
                              const unsigned char *login,
                              unsigned long long session_id,
                              unsigned int ip_address,
                              struct userlist_cfg *config,
                              struct sid_state *sstate,
                              int cmd,
                              const unsigned char *self_url,
                              const unsigned char *hidden_vars,
                              const unsigned char *extra_args);

struct contest_desc;
struct sid_state;

int super_html_open_contest(struct contest_desc *cnts, int user_id,
                            const unsigned char *user_login);
int super_html_close_contest(struct contest_desc *cnts, int user_id,
                             const unsigned char *user_login);

int super_html_make_invisible_contest(struct contest_desc *cnts, int user_id,
                                      const unsigned char *user_login);
int super_html_make_visible_contest(struct contest_desc *cnts, int user_id,
                                    const unsigned char *user_login);

int super_html_serve_managed_contest(struct contest_desc *cnts, int user_id,
                                     const unsigned char *user_login);
int super_html_serve_unmanaged_contest(struct contest_desc *cnts, int user_id,
                                       const unsigned char *user_login);

int super_html_run_managed_contest(struct contest_desc *cnts, int user_id,
                                   const unsigned char *user_login);
int super_html_run_unmanaged_contest(struct contest_desc *cnts, int user_id,
                                     const unsigned char *user_login);

struct contest_desc *contest_tmpl_new(int contest_id,
                                      const unsigned char *login,
                                      const unsigned char *self_url,
                                      const struct userlist_cfg *ejudge_config);
struct contest_desc *contest_tmpl_clone(struct sid_state *sstate,
                                        int contest_id, int orig_id,
                                        const unsigned char *login);

int super_html_clear_variable(struct sid_state *sstate, int cmd);

int super_html_set_contest_var(struct sid_state *sstate, int cmd,
                               int param1, const unsigned char *param2,
                               int param3, int param4);

int super_html_report_error(FILE *f,
                            unsigned long long session_id,
                            const unsigned char *self_url,
                            const unsigned char *extra_args,
                            const char *format, ...);

#endif /* __SUPER_HTML_H__ */
