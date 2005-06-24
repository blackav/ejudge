/* -*- c -*- */
/* $Id$ */
#ifndef __SUPER_SERVE_H__
#define __SUPER_SERVE_H__

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

#include <time.h>

struct contest_extra
{
  int id;
  unsigned char serve_used;
  unsigned char run_used;
  unsigned char dnotify_flag;
  unsigned char serve_suspended;
  unsigned char run_suspended;

  int serve_pid;
  int run_pid;
  int socket_fd;
  int run_dir_fd;
  int serve_uid;
  int serve_gid;
  int run_uid;
  int run_gid;

  unsigned char *root_dir;
  unsigned char *conf_file;
  unsigned char *var_dir;

  unsigned char *socket_path;
  unsigned char *log_file;
  unsigned char *run_queue_dir;
  unsigned char *run_log_file;
  unsigned char *messages;

  time_t serve_last_start;
  time_t serve_suspend_end;
  time_t run_last_start;
  time_t run_suspend_end;
};

struct contest_extra *get_contest_extra(int num);
struct contest_extra *get_existing_contest_extra(int num);

enum
{
  SID_STATE_SHOW_HIDDEN = 1,
  SID_STATE_SHOW_CLOSED = 2,
  SID_STATE_SHOW_UNMNG = 4,
};

struct contest_desc;
struct sid_state
{
  struct sid_state *next;
  struct sid_state *prev;
  unsigned long long sid;
  time_t init_time;
  unsigned long flags;
  struct contest_desc *edited_cnts;
  int advanced_view;
  int show_html_attrs;
  int show_html_headers;
  int show_paths;
  int show_access_rules;
  int show_permissions;
  int show_form_fields;

  unsigned char *users_header_text;
  unsigned char *users_footer_text;
  unsigned char *register_header_text;
  unsigned char *register_footer_text;
  unsigned char *team_header_text;
  unsigned char *team_footer_text;
  unsigned char *register_email_text;
};

#endif /* __SUPER_SERVE_H__ */
