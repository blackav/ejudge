/* -*- c -*- */
/* $Id$ */
#ifndef __SUPER_SERVE_H__
#define __SUPER_SERVE_H__

/* Copyright (C) 2004 Alexander Chernov <cher@ispras.ru> */

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
  int uid;
  int gid;
  unsigned char *socket_path;
  unsigned char *root_dir;
  unsigned char *conf_file;
  unsigned char *log_file;
  unsigned char *run_queue_dir;
  unsigned char *run_log_file;

  time_t serve_last_start;
  time_t serve_suspend_end;
  time_t run_last_start;
  time_t run_suspend_end;
};

extern int contest_num;
extern struct contest_extra *contest_extra;
struct contest_extra *get_contest_extra(int num);

#endif /* __SUPER_SERVE_H__ */
