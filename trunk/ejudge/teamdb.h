/* -*- c -*- */
/* $Id$ */
#ifndef __TEAMDB_H__
#define __TEAMDB_H__

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

#include "ej_types.h"

#include <time.h>

/* various team flags */
enum { TEAM_BANNED = 1, TEAM_INVISIBLE = 2, TEAM_LOCKED = 4 };

int teamdb_open_client(unsigned char const *socket_path, int contest_id);
int teamdb_refresh(void);

int teamdb_lookup(int);
int teamdb_lookup_login(char const *);

char *teamdb_get_login(int);
char *teamdb_get_name(int);
int   teamdb_get_max_team_id(void);
int   teamdb_get_flags(int);
int   teamdb_get_total_teams(void);
int   teamdb_get_vintage(void);

int teamdb_dump_database(int fd);

int teamdb_toggle_flags(int user_id, int contest_id, unsigned int flags);

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

int teamdb_export_team(int id, struct teamdb_export *);

time_t teamdb_get_archive_time(int uid);
int    teamdb_set_archive_time(int uid, time_t time);

int teamdb_get_uid_by_pid(int system_uid,
                          int system_gid,
                          int system_pid,
                          int contest_id,
                          int *p_uid,
                          int *p_priv_level,
                          ej_cookie_t *p_cookie,
                          ej_ip_t *p_ip,
                          int *p_ssl);

void teamdb_register_update_hook(void (*)(void *), void *);
void teamdb_unregister_update_hook(void (*)(void *));
int teamdb_get_user_status_map(int *p_size, int **p_map);

#endif /* __TEAMDB_H__ */
