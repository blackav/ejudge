/* -*- c -*- */
/* $Id$ */
#ifndef __TEAMDB_PRIV_H__
#define __TEAMDB_PRIV_H__

/* Copyright (C) 2010-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/userlist_proto.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>

/* non-saved local extra information about teams */
struct teamdb_extra
{
  time_t last_archive_time;
};

/* update hooks */
struct update_hook
{
  struct update_hook *next;
  void (*func)(void *);
  void *user_ptr;
};

struct old_db_state
{
  unsigned char *server_path;
  time_t server_last_open_time;
  struct userlist_clnt *server_conn;
  struct userlist_table *server_users;
  struct userlist_table local_users;
  int shm_id;
  key_t shm_key;
};

struct teamdb_state
{
  int contest_id;
  int nref;
  int disabled;

  struct teamdb_db_callbacks *callbacks;
  int need_update;
  int pseudo_vintage;

  struct old_db_state old;

  struct userlist_list *users;
  int total_participants;
  struct userlist_user **participants;
  struct userlist_contest **u_contests;

  int extra_out_of_sync;
  int extra_num;
  struct teamdb_extra **extra_info;

  struct update_hook *first_update_hook;
};

#endif /* __TEAMDB_PRIV_H__ */
