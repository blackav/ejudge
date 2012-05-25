/* -*- c -*- */
/* $Id$ */

#ifndef __RUNLOG_STATE_H__
#define __RUNLOG_STATE_H__

/* Copyright (C) 2008-2012 Alexander Chernov <cher@ejudge.ru> */

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

#define RUNLOG_MAX_SIZE    (2 * 1024 * 1024)

enum
  {
    V_REAL_USER = 1,
    V_VIRTUAL_USER = 2,
    V_LAST = 2,
  };

struct user_entry
{
  int status;                   /* virtual or real user */
  int start_time;
  int stop_time;
};

struct user_flags_info_s
{
  int nuser;
  int *flags;
};

struct rldb_plugin_iface;
struct rldb_plugin_data;
struct rldb_plugin_cnts;

#if !defined RUNS_ACCESS
#define RUNS_ACCESS const
#endif /* RUNS_ACCESS */

struct runlog_state
{
  RUNS_ACCESS struct run_header  head;
  RUNS_ACCESS struct run_entry  *runs;
  RUNS_ACCESS int                run_u;
  RUNS_ACCESS int                run_a;
  teamdb_state_t     teamdb_state;
  int ut_size;
  struct user_entry **ut_table;
  struct user_flags_info_s user_flags;

  int max_user_id;
  int user_count;

  // the managing plugin information
  struct rldb_plugin_iface *iface;
  struct rldb_plugin_data *data;
  struct rldb_plugin_cnts *cnts;
};

#endif /* __RUNLOG_STATE_H__ */
