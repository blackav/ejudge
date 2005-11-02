/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2005 Alexander Chernov <cher@ispras.ru> */

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

#include "teamdb.h"

#include "pathutl.h"
#include "base64.h"
#include "userlist_clnt.h"
#include "userlist_proto.h"
#include "userlist.h"

#include <reuse/osdeps.h>
#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <signal.h>

/* userlist-server connection */
static unsigned char *server_path = 0;
static time_t server_last_open_time = 0;
static struct userlist_clnt *server_conn = 0;
static struct userlist_table *server_users = 0;
static struct userlist_table local_users;
static struct userlist_list *users;
static int total_participants;
static struct userlist_user **participants;
static struct userlist_contest **u_contests;
static int shm_id = -1;
static key_t shm_key;
static int contest_id;

/* non-saved local extra information about teams */
struct teamdb_extra
{
  time_t last_archive_time;
};
static int extra_out_of_sync;
static int extra_num;
static struct teamdb_extra **extra_info;

/* update hooks */
struct update_hook
{
  struct update_hook *next;
  void (*func)(void *);
  void *user_ptr;
};
static struct update_hook *first_update_hook = 0;

void
teamdb_register_update_hook(void (*func)(void *), void *user_ptr)
{
  struct update_hook **pp = &first_update_hook;

  while (*pp && (*pp)->func != func) pp = &(*pp)->next;
  if (!*pp) {
    XCALLOC(*pp, 1);
  }
  (*pp)->func = func;
  (*pp)->user_ptr = user_ptr;
}
void
teamdb_unregister_update_hook(void (*func)(void *))
{
  struct update_hook **pp = &first_update_hook, *p;

  while (*pp && (*pp)->func != func) pp = &(*pp)->next;
  if (*pp) {
    p = *pp;
    *pp = p->next;
    xfree(p);
  }
}
static void
call_update_hooks(void)
{
  struct update_hook *p;

  for (p = first_update_hook; p; p = p->next) {
    (*p->func)(p->user_ptr);
  }
}

static int
open_connection(void)
{
  int r;
  time_t cur_time;

  if (server_conn) return 0;
  cur_time = time(0);
  if (cur_time - server_last_open_time <= 1) return -1;
  server_last_open_time = cur_time;
  if (!(server_conn = userlist_clnt_open(server_path))) {
    err("teamdb_open_client: connect to server failed");
    return -1;
  }
  if ((r = userlist_clnt_admin_process(server_conn, 0, 0, 0)) < 0) {
    err("teamdb_open_client: cannot became an admin process: %s",
        userlist_strerror(-r));
    return -1;
  }
  if ((r = userlist_clnt_map_contest(server_conn, contest_id,
                                     0, &shm_key)) < 0) {
    err("teamdb_open_client: cannot map contest: %s", userlist_strerror(-r));
    return -1;
  }
  if ((shm_id = shmget(shm_key, 0, 0)) < 0) {
    err("teamdb_open_client: cannot obtain a shared memory: %s",
        os_ErrorMsg());
    return -1;
  }
  if ((long) (server_users = shmat(shm_id, 0, SHM_RDONLY)) == -1) {
    err("teamdb_open_client: cannot attach shared memory: %s",
        os_ErrorMsg());
    return -1;
  }
  return 0;
}

static void
close_connection(void)
{
  if (server_conn) {
    userlist_clnt_close(server_conn);
    server_conn = 0;
  }
  if (server_users) {
    shmdt(server_users);
    server_users = 0;
  }
  if (shm_id >= 0) {
    shmctl(shm_id, IPC_RMID, 0);
    shm_id = -1;
  }
  if (shm_key > 0) {
    shm_key = 0;
  }
}

int
teamdb_refresh(void)
{
  int i, r, j;
  unsigned char *xml_text;
  struct userlist_list *new_users;
  unsigned long prev_vintage;
  struct userlist_user *uu;
  struct userlist_contest *uc;

  if (open_connection() < 0) return -1;

  if (server_users && server_users->vintage != 0xffffffff
      && local_users.vintage && local_users.vintage != 0xffffffff
      && server_users->vintage == local_users.vintage) return 0;

  prev_vintage = local_users.vintage;

  /* this should be an atomic copy */
  local_users.vintage = server_users->vintage;

  /* There is a possibility, that vintage will be incremented
   * in this time window. However, this may only cause harmless
   * userlist reload.
   */

  r = userlist_clnt_list_all_users(server_conn, ULS_LIST_STANDINGS_USERS,
                                   contest_id, &xml_text);
  if (r < 0) {
    /* Don't try hard. Just proceed with the current copy. */
    local_users.vintage = prev_vintage;
    err("teamdb_refresh: cannot load userlist: %s", userlist_strerror(-r));
    close_connection();
    return -1;
  }
  new_users = userlist_parse_str(xml_text);
  if (!new_users) {
    local_users.vintage = prev_vintage;
    err("teamdb_refresh: XML parse error");
    close_connection();
    return -1;
  }

  //fprintf(stderr, ">>%s\n", xml_text);

  userlist_free((struct xml_tree*) users);
  users = new_users;
  xfree(participants);
  participants = 0;
  xfree(u_contests);
  u_contests = 0;
  total_participants = 0;

  if (users->user_map_size <= 0) {
    info("teamdb_refresh: no users in updated contest");
    call_update_hooks();
    return 1;
  }

  for (i = 1; i < users->user_map_size; i++)
    if (users->user_map[i]) total_participants++;
  if (!total_participants) {
    info("teamdb_refresh: no users in updated contest");
    call_update_hooks();
    return 1;
  }

  XCALLOC(participants, total_participants);
  XCALLOC(u_contests, users->user_map_size);

  for (i = 1, j = 0; i < users->user_map_size; i++) {
    if (!(uu = users->user_map[i])) continue;
    if (!uu->contests) continue;

    for (uc = (struct userlist_contest*) uu->contests->first_down;
         uc; uc = (struct userlist_contest*) uc->b.right) {
      if (uc->id == contest_id) break;
    }
    if (!uc) continue;

    participants[j++] = users->user_map[i];
    u_contests[i] = uc;
  }
  ASSERT(j <= total_participants);
  if (j < total_participants) {
    err("teamdb_refresh: registered %d, passed %d", j, total_participants);
  }

  info("teamdb_refresh: updated: %d users, %d max user, XML size = %zu",
       total_participants, users->user_map_size - 1, strlen(xml_text));
  extra_out_of_sync = 1;
  call_update_hooks();
  return 1;
}

int
teamdb_get_vintage(void)
{
  if (teamdb_refresh() < 0) return 0;
  return local_users.vintage;
}

int
teamdb_open_client(unsigned char const *socket_path, int id)
{
  contest_id = id;
  server_path = xstrdup(socket_path);
  if (open_connection() < 0) return -1;
  if (teamdb_refresh() < 0) return -1;
  return 0;
}

inline int
teamdb_lookup_client(int teamno)
{
  if (!users || teamno <= 0 || teamno >= users->user_map_size
      || !users->user_map[teamno]) return 0;
  return 1;
}

int
teamdb_lookup(int teamno)
{
  if (teamdb_refresh() < 0) return 0;
  return teamdb_lookup_client(teamno);
}

int
teamdb_lookup_login(char const *login)
{
  int i;

  if (teamdb_refresh() < 0) return -1;
  if (!participants) return -1;
  for (i = 0; i < total_participants; i++) {
    ASSERT(participants[i]);
    ASSERT(participants[i]->login);
    if (!strcmp(participants[i]->login, login))
      return participants[i]->id;
  }
  return -1;
}

char *
teamdb_get_login(int teamid)
{
  unsigned char *login = 0;
  if (teamdb_refresh() < 0) return 0;
  if (!teamdb_lookup_client(teamid)) {
    err("teamdb_get_login: bad id: %d", teamid);
    return 0;
  }
  login = users->user_map[teamid]->login;
  ASSERT(login);
  return login;
}

char *
teamdb_get_name(int teamid)
{
  unsigned char *name = 0;

  if (teamdb_refresh() < 0) return 0;
  if (!teamdb_lookup_client(teamid)) {
    err("teamdb_get_login: bad id: %d", teamid);
    return 0;
  }
  name = users->user_map[teamid]->name;
  if (!name) name = "";
  return name;
}

int
teamdb_get_flags(int id)
{
  int new_flags = 0, old_flags = 0;

  if (teamdb_refresh() < 0) return TEAM_BANNED;
  if (!teamdb_lookup_client(id)) {
    err("teamdb_get_flags: bad team id %d", id);
    return TEAM_BANNED;
  }
  ASSERT(u_contests[id]);
  old_flags = u_contests[id]->flags;
  if ((old_flags & USERLIST_UC_INVISIBLE)) {
    new_flags |= TEAM_INVISIBLE;
  }
  if ((old_flags & USERLIST_UC_BANNED)) {
    new_flags |= TEAM_BANNED;
  }
  if ((old_flags & USERLIST_UC_LOCKED)) {
    new_flags |= TEAM_LOCKED;
  }
  return new_flags;
}

int
teamdb_get_max_team_id(void)
{
  if (teamdb_refresh() < 0) return 0;
  return users->user_map_size - 1;
}

int
teamdb_get_total_teams(void)
{
  if (teamdb_refresh() < 0) return 0;
  return total_participants;
}

int
teamdb_toggle_flags(int user_id, int contest_id, unsigned int flags)
{
  int r;

  if (open_connection() < 0) return -1;
  if (!teamdb_lookup_client(user_id)) {
    err("teamdb_export_team: bad id: %d", user_id);
    return -1;
  }
  r = userlist_clnt_change_registration(server_conn, user_id, contest_id,
                                        -1, 3, flags);
  if (r < 0) return -1;
  // force userdb reload
  local_users.vintage = 0;
  return r;
}

int
teamdb_export_team(int tid, struct teamdb_export *pdata)
{
  struct userlist_user *uu;
  unsigned char *u_login, *u_name;
  int u_flags;

  if (teamdb_refresh() < 0) return -1;
  if (!teamdb_lookup_client(tid)) {
    err("teamdb_export_team: bad id: %d", tid);
    return -1;
  }
  ASSERT(u_contests[tid]);
  uu = users->user_map[tid];
  u_login = uu->login;
  if (!u_login) u_login = "";
  u_name = uu->name;
  if (!u_name) u_name = "";
  u_flags = u_contests[tid]->flags;

  XMEMZERO(pdata, 1);
  pdata->id = tid;
  if ((u_flags & USERLIST_UC_INVISIBLE))
    pdata->flags |= TEAM_INVISIBLE;
  if ((u_flags & USERLIST_UC_BANNED))
    pdata->flags |= TEAM_BANNED;
  if ((u_flags & USERLIST_UC_LOCKED))
    pdata->flags |= TEAM_LOCKED;
  strncpy(pdata->login, u_login, TEAMDB_LOGIN_LEN - 1);
  strncpy(pdata->name, u_name, TEAMDB_NAME_LEN - 1);
  pdata->user = uu;
  return 0;
}

int
teamdb_dump_database(int fd)
{
  int r;

  if (open_connection() < 0) {
    close(fd);
    return -1;
  }
  r = userlist_clnt_dump_database(server_conn, ULS_DUMP_DATABASE, contest_id, fd, 1);
  if (r < 0) {
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

static void
syncronize_team_extra(void)
{
  struct teamdb_extra **old_extra = 0;
  int old_extra_num = 0, max_idx = 0, i;

  if (!extra_out_of_sync && extra_info) return;
  old_extra = extra_info;
  old_extra_num = extra_num;
  if (users && users->user_map_size > 0) {
    extra_num = users->user_map_size;
    extra_info = xcalloc(extra_num, sizeof(extra_info[0]));
  } else {
    extra_info = 0;
    extra_num = 0;
  }
  max_idx = extra_num;
  if (old_extra_num < max_idx) max_idx = old_extra_num;
  for (i = 0; i < max_idx; i++) {
    if (users->user_map[i]) {
      extra_info[i] = old_extra[i];
      old_extra[i] = 0;
    }
  }
  for (i = 0; i < old_extra_num; i++)
    xfree(old_extra[i]);
  xfree(old_extra);
  extra_out_of_sync = 0;
}

time_t
teamdb_get_archive_time(int uid)
{
  if (teamdb_refresh() < 0) return (time_t) -1;
  if (!teamdb_lookup_client(uid)) return (time_t) -1;
  syncronize_team_extra();
  if (!extra_info[uid]) {
    XCALLOC(extra_info[uid], 1);
  }
  return extra_info[uid]->last_archive_time;
}
int
teamdb_set_archive_time(int uid, time_t time)
{
  if (teamdb_refresh() < 0) return -1;
  if (!teamdb_lookup_client(uid)) return -1;
  syncronize_team_extra();
  if (!extra_info[uid]) {
    XCALLOC(extra_info[uid], 1);
  }
  extra_info[uid]->last_archive_time = time;
  return 0;
}

int
teamdb_get_uid_by_pid(int system_uid, int system_gid, int system_pid,
                      int *p_uid, int *p_priv_level,
                      unsigned long long *p_cookie,
                      unsigned long *p_ip, int *p_ssl)
{
  int r;

  if (open_connection() < 0) return -1;
  r = userlist_clnt_get_uid_by_pid(server_conn, system_uid, system_gid,
                                   system_pid, p_uid,
                                   p_priv_level, p_cookie, p_ip, p_ssl);
  if (r < 0) return -1;
  return r;
}

int
teamdb_get_user_status_map(int *p_size, int **p_map)
{
  int map_size = 0, i;
  int *map = 0;
  struct userlist_contest *uc;
  int old_flags, new_flags;

  if (teamdb_refresh() < 0) return -1;

  if (users->user_map_size <= 0) {
    *p_size = 0;
    *p_map = 0;
    return 0;
  }

  map_size = users->user_map_size;
  XCALLOC(map, map_size);

  for (i = 1; i < users->user_map_size; i++) {
    if (!(uc = u_contests[i])) {
      map[i] = -1;
      continue;
    }
    old_flags = uc->flags;
    new_flags = 0;
    if ((old_flags & USERLIST_UC_INVISIBLE)) {
      new_flags |= TEAM_INVISIBLE;
    }
    if ((old_flags & USERLIST_UC_BANNED)) {
      new_flags |= TEAM_BANNED;
    }
    if ((old_flags & USERLIST_UC_LOCKED)) {
      new_flags |= TEAM_LOCKED;
    }
    map[i] = new_flags;
  }

  *p_size = map_size;
  *p_map = map;
  return 1;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */

