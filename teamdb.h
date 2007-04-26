/* -*- c -*- */
/* $Id$ */
#ifndef __TEAMDB_H__
#define __TEAMDB_H__

/* Copyright (C) 2000-2007 Alexander Chernov <cher@ejudge.ru> */

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

#include <time.h>

/* various team flags */
enum
{
  TEAM_BANNED       = 1,
  TEAM_INVISIBLE    = 2,
  TEAM_LOCKED       = 4,
  TEAM_INCOMPLETE   = 8,
  TEAM_DISQUALIFIED = 16,
};

struct teamdb_state;
typedef struct teamdb_state *teamdb_state_t;

struct teamdb_db_callbacks
{
  void *user_data;
  int (*list_all_users)(void *, int, unsigned char **);
};

teamdb_state_t teamdb_init(void);
teamdb_state_t teamdb_destroy(teamdb_state_t);

int teamdb_open_client(teamdb_state_t state,
                       unsigned char const *socket_path, int contest_id);
int teamdb_set_callbacks(teamdb_state_t state,
                         const struct teamdb_db_callbacks *callbacks,
                         int contest_id);
int teamdb_refresh(teamdb_state_t);
void teamdb_set_update_flag(teamdb_state_t state);

int teamdb_lookup(teamdb_state_t, int);
int teamdb_lookup_login(teamdb_state_t, char const *);

char *teamdb_get_login(teamdb_state_t, int);
char *teamdb_get_name(teamdb_state_t, int);
const unsigned char *teamdb_get_name_2(teamdb_state_t, int);
int   teamdb_get_max_team_id(teamdb_state_t);
int   teamdb_get_flags(teamdb_state_t, int);
int   teamdb_get_total_teams(teamdb_state_t);
int   teamdb_get_vintage(teamdb_state_t);

/* this is export data structure */
enum {
  TEAMDB_LOGIN_LEN = 64,
  TEAMDB_NAME_LEN = 64,
};

struct userlist_user;
struct teamdb_export
{
  int id;
  int flags;
  unsigned char login[TEAMDB_LOGIN_LEN];
  unsigned char name[TEAMDB_NAME_LEN];
  struct userlist_user *user;
};

int teamdb_export_team(teamdb_state_t, int id, struct teamdb_export *);

time_t teamdb_get_archive_time(teamdb_state_t, int uid);
int    teamdb_set_archive_time(teamdb_state_t, int uid, time_t time);

int teamdb_get_uid_by_pid(teamdb_state_t,
                          int system_uid,
                          int system_gid,
                          int system_pid,
                          int *p_uid,
                          int *p_priv_level,
                          ej_cookie_t *p_cookie,
                          ej_ip_t *p_ip,
                          int *p_ssl);

void teamdb_register_update_hook(teamdb_state_t, void (*)(void *), void *);
void teamdb_unregister_update_hook(teamdb_state_t, void (*)(void *));
int teamdb_get_user_status_map(teamdb_state_t, int *p_size, int **p_map);

#endif /* __TEAMDB_H__ */
