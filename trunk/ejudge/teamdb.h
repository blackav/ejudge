/* -*- c -*- */
/* $Id$ */
#ifndef __TEAMDB_H__
#define __TEAMDB_H__

/* Copyright (C) 2000,2001 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <time.h>

#define TEAMDB_MAX_SCRAMBLED_PASSWD_SIZE 48

/* various team flags */
enum { TEAM_BANNED = 1, TEAM_INVISIBLE = 2 };

int teamdb_open_client(unsigned char const *socket_path, int contest_id);
void teamdb_refresh(void);

int teamdb_lookup(int);
int teamdb_lookup_login(char const *);

char *teamdb_get_login(int);
char *teamdb_get_name(int);
int   teamdb_get_max_team_id(void);
int   teamdb_get_flags(int);
int   teamdb_get_total_teams(void);

int teamdb_regenerate_passwords(int fd);

int   teamdb_toggle_ban(int);
int   teamdb_toggle_vis(int);

/* this is export data structure */
enum {
  TEAMDB_LOGIN_LEN = 64,
  TEAMDB_NAME_LEN = 64,
};

struct teamdb_export
{
  int id;
  int flags;
  char login[TEAMDB_LOGIN_LEN];
  char name[TEAMDB_NAME_LEN];
};

int teamdb_export_team(int id, struct teamdb_export *);

time_t teamdb_get_archive_time(int uid);
int    teamdb_set_archive_time(int uid, time_t time);

int teamdb_get_uid_by_pid(int, int, int, int *, int *,unsigned long long *,
                          unsigned long *);

#endif /* __TEAMDB_H__ */
