/* -*- c -*- */
/* $Id$ */
#ifndef __TEAMDB_H__
#define __TEAMDB_H__

/* Copyright (C) 2000 Alexander Chernov <cher@ispras.ru> */

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

#define TEAMDB_MAX_SCRAMBLED_PASSWD_SIZE 48

/* various team flags */
enum { TEAM_BANNED = 1, TEAM_INVISIBLE = 2 };

int teamdb_open(char const *, char const *, int);
int teamdb_write_passwd(char const *);

int teamdb_lookup(int);
int teamdb_lookup_login(char const *);

char *teamdb_get_login(int);
char *teamdb_get_name(int);
int   teamdb_scramble_passwd(char const *, char *);
int   teamdb_check_scrambled_passwd(int, char const *);
int   teamdb_set_scrambled_passwd(int, char const *);
int   teamdb_check_passwd(int, char const *);
int   teamdb_get_max_team_id(void);
int   teamdb_get_flags(int);

#endif /* __TEAMDB_H__ */
