/* -*- c -*- */

/* Copyright (C) 2000-2017 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/teamdb.h"
#include "ejudge/teamdb_priv.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/base64.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/userlist_proto.h"
#include "ejudge/userlist.h"
#include "ejudge/xml_utils.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"
#include "ejudge/userlist_bin.h"

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
#include <sys/time.h>

teamdb_state_t
teamdb_init(int contest_id)
{
  teamdb_state_t state;

  XCALLOC(state, 1);
  state->contest_id = contest_id;
  state->old.shm_id = -1;
  return state;
}

void teamdb_disable(teamdb_state_t state, int disable_flag)
{
  if (state && disable_flag > 0) {
    state->disabled = 1;
  }
}

void
teamdb_register_update_hook(teamdb_state_t state, void (*func)(void *),
                            void *user_ptr)
{
  struct update_hook **pp = &state->first_update_hook;

  while (*pp && (*pp)->func != func) pp = &(*pp)->next;
  if (!*pp) {
    XCALLOC(*pp, 1);
  }
  (*pp)->func = func;
  (*pp)->user_ptr = user_ptr;
}
void
teamdb_unregister_update_hook(teamdb_state_t state, void (*func)(void *))
{
  struct update_hook **pp = &state->first_update_hook, *p;

  while (*pp && (*pp)->func != func) pp = &(*pp)->next;
  if (*pp) {
    p = *pp;
    *pp = p->next;
    xfree(p);
  }
}
static void
call_update_hooks(teamdb_state_t state)
{
  struct update_hook *p;

  for (p = state->first_update_hook; p; p = p->next) {
    (*p->func)(p->user_ptr);
  }
}

static int
open_connection(struct old_db_state *old_db, int contest_id)
{
  int r;
  time_t cur_time;
  int *p_int = 0;

  if (old_db->server_conn) return 0;
  cur_time = time(0);
  if (cur_time - old_db->server_last_open_time <= 1) return -1;
  old_db->server_last_open_time = cur_time;
  if (!(old_db->server_conn = userlist_clnt_open(old_db->server_path))) {
    err("teamdb_open_client: connect to server failed");
    return -1;
  }
  if ((r = userlist_clnt_admin_process(old_db->server_conn, 0, 0, 0)) < 0) {
    err("teamdb_open_client: cannot became an admin process: %s",
        userlist_strerror(-r));
    return -1;
  }
  p_int = (int*) &old_db->shm_key;
  if ((r = userlist_clnt_map_contest(old_db->server_conn, contest_id,
                                     0, p_int)) < 0) {
    err("teamdb_open_client: cannot map contest: %s", userlist_strerror(-r));
    return -1;
  }
  if ((old_db->shm_id = shmget(old_db->shm_key, 0, 0)) < 0) {
    err("teamdb_open_client: cannot obtain a shared memory: %s",
        os_ErrorMsg());
    return -1;
  }
  if ((long)(old_db->server_users = shmat(old_db->shm_id, 0, SHM_RDONLY))==-1) {
    err("teamdb_open_client: cannot attach shared memory: %s",
        os_ErrorMsg());
    return -1;
  }
  return 0;
}

static void
close_connection(struct old_db_state *old_db)
{
  if (old_db->server_conn) {
    userlist_clnt_close(old_db->server_conn);
    old_db->server_conn = 0;
  }
  if (old_db->server_users) {
    shmdt(old_db->server_users);
    old_db->server_users = 0;
  }
  if (old_db->shm_id >= 0) {
    shmctl(old_db->shm_id, IPC_RMID, 0);
    old_db->shm_id = -1;
  }
  if (old_db->shm_key > 0) {
    old_db->shm_key = 0;
  }
}

int
teamdb_refresh(teamdb_state_t state)
{
  int i, r, j;
  struct userlist_list *new_users;
  unsigned long prev_vintage;
  struct userlist_user *uu;
  struct userlist_contest *uc;
  size_t data_size = 0;
  const struct contest_desc *cnts = 0;
  int user_contest_id = state->contest_id;
  UserlistBinaryHeader *new_header = NULL;

  struct timeval tv1, tv2;

  if (state->disabled) return 0;
  if (state->callbacks) {
    if (state->users && !state->need_update) return 0;
  }

  gettimeofday(&tv1, NULL);

  if (state->contest_id > 0) contests_get(state->contest_id, &cnts);
  if (cnts && cnts->user_contest_num) user_contest_id = cnts->user_contest_num;

  if (state->callbacks) {
    r = state->callbacks->list_all_users(state->callbacks->user_data,
                                         user_contest_id, NULL, &new_header);
    if (r < 0) {
      err("teamdb_refresh: cannot load userlist: %s", userlist_strerror(-r));
      return -1;
    }
    data_size = new_header->pkt_size;
    new_users = (struct userlist_list*) userlist_bin_get_root(new_header);
    state->need_update = 0;
    state->pseudo_vintage++;
  } else {
    unsigned char *xml_text = NULL;
    if (open_connection(&state->old, user_contest_id) < 0) return -1;

    if (state->old.server_users
        && state->old.server_users->vintage != 0xffffffff
        && state->old.local_users.vintage
        && state->old.local_users.vintage != 0xffffffff
        && state->old.server_users->vintage == state->old.local_users.vintage)
      return 0;

    prev_vintage = state->old.local_users.vintage;

    /* this should be an atomic copy */
    state->old.local_users.vintage = state->old.server_users->vintage;

    /* There is a possibility, that vintage will be incremented
     * in this time window. However, this may only cause harmless
     * userlist reload.
     */

    r = userlist_clnt_list_all_users(state->old.server_conn,
                                     ULS_LIST_STANDINGS_USERS,
                                     user_contest_id, &xml_text);
    if (r < 0) {
      /* Don't try hard. Just proceed with the current copy. */
      state->old.local_users.vintage = prev_vintage;
      err("teamdb_refresh: cannot load userlist: %s", userlist_strerror(-r));
      close_connection(&state->old);
      return -1;
    }
    data_size = strlen(xml_text);
    new_users = userlist_parse_str(xml_text);
    xfree(xml_text); xml_text = 0;
    if (!new_users) {
      state->old.local_users.vintage = prev_vintage;
      err("teamdb_refresh: XML parse error");
      close_connection(&state->old);
      return -1;
    }
  }

  if (!state->header) {
    if (state->users) {
      userlist_free((struct xml_tree*) state->users);
    }
  }
  if (state->header) {
    xfree(state->header);
  }
  state->header = new_header;
  state->users = new_users;
  xfree(state->participants);
  state->participants = 0;
  xfree(state->u_contests);
  state->u_contests = 0;
  state->total_participants = 0;

  if (state->users->user_map_size <= 0) {
    info("teamdb_refresh: no users in updated contest");
    call_update_hooks(state);
    return 1;
  }

  for (i = 1; i < state->users->user_map_size; i++)
    if (state->users->user_map[i]) state->total_participants++;
  if (!state->total_participants) {
    info("teamdb_refresh: no users in updated contest");
    call_update_hooks(state);
    return 1;
  }

  XCALLOC(state->participants, state->total_participants);
  XCALLOC(state->u_contests, state->users->user_map_size);

  for (i = 1, j = 0; i < state->users->user_map_size; i++) {
    if (!(uu = state->users->user_map[i])) continue;
    if (!uu->contests) continue;

    for (uc = (struct userlist_contest*) uu->contests->first_down;
         uc; uc = (struct userlist_contest*) uc->b.right) {
      if (uc->id == user_contest_id) break;
    }
    if (!uc) continue;

    state->participants[j++] = state->users->user_map[i];
    state->u_contests[i] = uc;
  }
  ASSERT(j <= state->total_participants);
  if (j < state->total_participants) {
    err("teamdb_refresh: registered %d, passed %d", j,
        state->total_participants);
  }

  gettimeofday(&tv2, NULL);

  unsigned long long t1 = (unsigned long long) tv1.tv_sec * 1000000UL + tv1.tv_usec;
  unsigned long long t2 = (unsigned long long) tv2.tv_sec * 1000000UL + tv2.tv_usec;

  info("teamdb_refresh: updated: %d users, %d max user, XML size = %zu, time = %llu",
       state->total_participants, state->users->user_map_size - 1, data_size, (t2 - t1));
  state->extra_out_of_sync = 1;
  call_update_hooks(state);
  return 1;
}

void
teamdb_set_update_flag(teamdb_state_t state)
{
  state->need_update = 1;
}

int
teamdb_get_vintage(teamdb_state_t state)
{
  if (teamdb_refresh(state) < 0) return 0;
  if (state->callbacks) return state->pseudo_vintage;
  return state->old.local_users.vintage;
}

int
teamdb_set_callbacks(teamdb_state_t state,
                     const struct teamdb_db_callbacks *callbacks,
                     int contest_id)
{
  xfree(state->callbacks);
  XCALLOC(state->callbacks, 1);
  memcpy(state->callbacks, callbacks, sizeof(*callbacks));
  state->contest_id = contest_id;
  return 0;
}

int
teamdb_open_client(teamdb_state_t state, unsigned char const *socket_path,
                   int id)
{
  state->contest_id = id;
  state->old.server_path = xstrdup(socket_path);
  state->callbacks = 0;
  if (state->disabled) return 0;
  if (open_connection(&state->old, state->contest_id) < 0) return -1;
  if (teamdb_refresh(state) < 0) return -1;
  return 0;
}

/*inline*/ int
teamdb_lookup_client(teamdb_state_t state, int teamno)
{
  if (state->disabled) {
    if (teamno <= 0) return 0;
    return 1;
  }
  if (!state->users || teamno <= 0 || teamno >= state->users->user_map_size
      || !state->users->user_map[teamno]) return 0;
  return 1;
}

int
teamdb_lookup(teamdb_state_t state, int teamno)
{
  if (teamdb_refresh(state) < 0) return 0;
  return teamdb_lookup_client(state, teamno);
}

int
teamdb_lookup_login(teamdb_state_t state, char const *login)
{
  int i;

  if (state->disabled) return -1;

  if (teamdb_refresh(state) < 0) return -1;
  if (!state->participants) return -1;
  for (i = 0; i < state->total_participants; i++) {
    ASSERT(state->participants[i]);
    ASSERT(state->participants[i]->login);
    if (!strcmp(state->participants[i]->login, login))
      return state->participants[i]->id;
  }
  return -1;
}

int
teamdb_lookup_name(teamdb_state_t state, char const *name)
{
  int i;
  const unsigned char *v;
  const struct userlist_user *u = 0;

  if (state->disabled) return -1;

  if (teamdb_refresh(state) < 0) return -1;
  if (!state->participants) return -1;
  for (i = 0; i < state->total_participants; i++) {
    u = state->participants[i];
    ASSERT(u);
    v = 0;
    if (u->cnts0) v = u->cnts0->name;
    if (!v || !*v) v = state->participants[i]->login;
    ASSERT(v);
    if (!strcmp(v, name))
      return state->participants[i]->id;
  }
  return -1;
}

int
teamdb_lookup_cypher(teamdb_state_t state, char const *cypher)
{
  int i;
  const struct userlist_user *u;
  const struct userlist_user_info *ui;

  if (state->disabled) return -1;

  if (teamdb_refresh(state) < 0) return -1;
  if (!state->participants) return -1;
  for (i = 0; i < state->total_participants; i++) {
    if (!(u = state->participants[i])) continue;
    if (!(ui = u->cnts0)) continue;
    if (ui->exam_cypher && !strcmp(ui->exam_cypher, cypher))
      return u->id;
  }
  return -1;
}

char *
teamdb_get_login(teamdb_state_t state, int teamid)
{
  unsigned char *login = 0;

  if (state->disabled) {
    static unsigned char login_buf[64];
    snprintf(login_buf, sizeof(login_buf), "User #%d", teamid);
    return login_buf;
  }

  if (teamdb_refresh(state) < 0) return 0;
  if (!teamdb_lookup_client(state, teamid)) {
    err("teamdb_get_login: bad id: %d", teamid);
    return 0;
  }
  login = state->users->user_map[teamid]->login;
  ASSERT(login);
  return login;
}

char *
teamdb_get_login_2(teamdb_state_t state, int teamid)
{
  unsigned char *login = 0;

  if (state->disabled) {
    static unsigned char login_buf[64];
    snprintf(login_buf, sizeof(login_buf), "User #%d", teamid);
    return login_buf;
  }

  if (teamdb_refresh(state) < 0) return 0;
  if (!teamdb_lookup_client(state, teamid)) {
    err("teamdb_get_login_2: bad id: %d", teamid);
    static unsigned char login_buf[64];
    snprintf(login_buf, sizeof(login_buf), "User #%d", teamid);
    return login_buf;
  }
  login = state->users->user_map[teamid]->login;
  ASSERT(login);
  return login;
}

char *
teamdb_get_name(teamdb_state_t state, int teamid)
{
  unsigned char *name = 0;
  const struct userlist_user_info *ui = 0;
  static unsigned char login_buf[64];

  if (state->disabled) {
    snprintf(login_buf, sizeof(login_buf), "User #%d", teamid);
    return login_buf;
  }

  if (teamdb_refresh(state) < 0) return 0;
  if (!teamdb_lookup_client(state, teamid)) {
    err("teamdb_get_name: bad id: %d", teamid);
    snprintf(login_buf, sizeof(login_buf), "User #%d", teamid);
    return login_buf;
  }
  ui = state->users->user_map[teamid]->cnts0;
  if (ui) name = ui->name;
  if (!name) name = "";
  return name;
}

const unsigned char *
teamdb_get_name_2(teamdb_state_t state, int teamid)
{
  unsigned char *name = 0;
  const struct userlist_user_info *ui = 0;
  static unsigned char login_buf[64];

  if (state->disabled) {
    snprintf(login_buf, sizeof(login_buf), "User #%d", teamid);
    return login_buf;
  }

  if (teamdb_refresh(state) < 0) return 0;
  if (!teamdb_lookup_client(state, teamid)) {
    err("teamdb_get_name_2: bad id: %d", teamid);
    snprintf(login_buf, sizeof(login_buf), "User #%d", teamid);
    return login_buf;
  }
  ui = state->users->user_map[teamid]->cnts0;
  if (ui) name = ui->name;
  if (!name || !*name) name = state->users->user_map[teamid]->login;
  return name;
}

const unsigned char *
teamdb_get_cypher(teamdb_state_t state, int user_id)
{
  const struct userlist_user_info *ui = 0;

  if (state->disabled) {
    static unsigned char login_buf[64];
    snprintf(login_buf, sizeof(login_buf), "User #%d", user_id);
    return login_buf;
  }

  if (teamdb_refresh(state) < 0) return 0;
  if (!teamdb_lookup_client(state, user_id)) {
    err("teamdb_get_cypher: bad id: %d", user_id);
    return 0;
  }
  if (!(ui = state->users->user_map[user_id]->cnts0)) return 0;
  return ui->exam_cypher;
}

static int
teamdb_convert_flags(int old_flags)
{
  int new_flags = 0;

  if ((old_flags & USERLIST_UC_INVISIBLE)) {
    new_flags |= TEAM_INVISIBLE;
  }
  if ((old_flags & USERLIST_UC_BANNED)) {
    new_flags |= TEAM_BANNED;
  }
  if ((old_flags & USERLIST_UC_LOCKED)) {
    new_flags |= TEAM_LOCKED;
  }
  if ((old_flags & USERLIST_UC_INCOMPLETE)) {
    new_flags |= TEAM_INCOMPLETE;
  }
  if ((old_flags & USERLIST_UC_DISQUALIFIED)) {
    new_flags |= TEAM_DISQUALIFIED;
  }
  if ((old_flags & USERLIST_UC_PRIVILEGED)) {
    new_flags |= TEAM_PRIVILEGED;
  }
  if ((old_flags & USERLIST_UC_REG_READONLY)) {
    new_flags |= TEAM_REG_READONLY;
  }

  return new_flags;
}

int
teamdb_get_flags(teamdb_state_t state, int id)
{
  if (state->disabled) return 0;

  if (teamdb_refresh(state) < 0) return TEAM_BANNED;
  if (!teamdb_lookup_client(state, id)) {
    err("teamdb_get_flags: bad team id %d (contest_id %d)", id,
        state->contest_id);
    return TEAM_BANNED;
  }
  ASSERT(state->u_contests[id]);
  return teamdb_convert_flags(state->u_contests[id]->flags);
}

int
teamdb_get_status(teamdb_state_t state, int id)
{
  if (state->disabled) return 0;

  if (teamdb_refresh(state) < 0) return -1;
  if (!teamdb_lookup_client(state, id)) {
    err("teamdb_get_status: bad team id %d (contest_id %d)", id, state->contest_id);
    return -1;
  }
  ASSERT(state->u_contests[id]);
  return state->u_contests[id]->status;
}

const struct userlist_user *
teamdb_get_userlist(teamdb_state_t state, int user_id)
{
  if (state->disabled) return 0;

  if (teamdb_refresh(state) < 0) return 0;
  if (!teamdb_lookup_client(state, user_id)) {
    err("teamdb_get_userlist: bad id: %d", user_id);
    return 0;
  }
  return state->users->user_map[user_id];
}

int
teamdb_get_max_team_id(teamdb_state_t state)
{
  if (state->disabled) return 0;

  if (teamdb_refresh(state) < 0) return 0;
  return state->users->user_map_size - 1;
}

int
teamdb_get_total_teams(teamdb_state_t state)
{
  if (state->disabled) return 0;

  if (teamdb_refresh(state) < 0) return 0;
  return state->total_participants;
}

int
teamdb_export_team(teamdb_state_t state, int tid, struct teamdb_export *pdata)
{
  struct userlist_user *uu;
  unsigned char *u_login, *u_name = 0;
  int u_flags;

  if (state->disabled) {
    XMEMZERO(pdata, 1);
    pdata->id = tid;
    snprintf(pdata->login, sizeof(pdata->login), "User #%d", tid);
    snprintf(pdata->name, sizeof(pdata->name), "User #%d", tid);
    return 0;
  }

  if (teamdb_refresh(state) < 0) return -1;
  if (!teamdb_lookup_client(state, tid)) {
    err("teamdb_export_team: bad id: %d", tid);
    return -1;
  }
  ASSERT(state->u_contests[tid]);
  uu = state->users->user_map[tid];
  u_login = uu->login;
  if (!u_login) u_login = "";
  if (uu->cnts0) u_name = uu->cnts0->name;
  if (!u_name) u_name = "";
  u_flags = state->u_contests[tid]->flags;

  XMEMZERO(pdata, 1);
  pdata->id = tid;
  if ((u_flags & USERLIST_UC_INVISIBLE))
    pdata->flags |= TEAM_INVISIBLE;
  if ((u_flags & USERLIST_UC_BANNED))
    pdata->flags |= TEAM_BANNED;
  if ((u_flags & USERLIST_UC_LOCKED))
    pdata->flags |= TEAM_LOCKED;
  if ((u_flags & USERLIST_UC_INCOMPLETE))
    pdata->flags |= TEAM_INCOMPLETE;
  if ((u_flags & USERLIST_UC_DISQUALIFIED))
    pdata->flags |= TEAM_DISQUALIFIED;
  if ((u_flags & USERLIST_UC_PRIVILEGED))
    pdata->flags |= TEAM_PRIVILEGED;
  if ((u_flags & USERLIST_UC_REG_READONLY))
    pdata->flags |= TEAM_REG_READONLY;
  strncpy(pdata->login, u_login, TEAMDB_LOGIN_LEN - 1);
  strncpy(pdata->name, u_name, TEAMDB_NAME_LEN - 1);
  pdata->user = uu;
  return 0;
}

static void
syncronize_team_extra(teamdb_state_t state)
{
  struct teamdb_extra **old_extra = 0;
  int old_extra_num = 0, max_idx = 0, i;

  if (!state->extra_out_of_sync && state->extra_info) return;
  old_extra = state->extra_info;
  old_extra_num = state->extra_num;
  if (state->users && state->users->user_map_size > 0) {
    state->extra_num = state->users->user_map_size;
    state->extra_info = xcalloc(state->extra_num, sizeof(state->extra_info[0]));
  } else {
    state->extra_info = 0;
    state->extra_num = 0;
  }
  max_idx = state->extra_num;
  if (old_extra_num < max_idx) max_idx = old_extra_num;
  for (i = 0; i < max_idx; i++) {
    if (state->users->user_map[i]) {
      state->extra_info[i] = old_extra[i];
      old_extra[i] = 0;
    }
  }
  for (i = 0; i < old_extra_num; i++)
    xfree(old_extra[i]);
  xfree(old_extra);
  state->extra_out_of_sync = 0;
}

time_t
teamdb_get_archive_time(teamdb_state_t state, int uid)
{
  if (teamdb_refresh(state) < 0) return (time_t) -1;
  if (!teamdb_lookup_client(state, uid)) return (time_t) -1;
  syncronize_team_extra(state);
  if (!state->extra_info[uid]) {
    XCALLOC(state->extra_info[uid], 1);
  }
  return state->extra_info[uid]->last_archive_time;
}
int
teamdb_set_archive_time(teamdb_state_t state, int uid, time_t time)
{
  if (teamdb_refresh(state) < 0) return -1;
  if (!teamdb_lookup_client(state, uid)) return -1;
  syncronize_team_extra(state);
  if (!state->extra_info[uid]) {
    XCALLOC(state->extra_info[uid], 1);
  }
  state->extra_info[uid]->last_archive_time = time;
  return 0;
}

int
teamdb_get_uid_by_pid(
        teamdb_state_t state,
        int system_uid,
        int system_gid,
        int system_pid,
        int *p_uid,
        int *p_priv_level,
        ej_cookie_t *p_cookie,
        ej_ip_t *p_ip,
        int *p_ssl)
{
  int r;

  if (state->callbacks) {
    err("teamdb_get_uid_by_pid: function cannot be called in callback mode");
    abort();
  }
  if (open_connection(&state->old, state->contest_id) < 0) return -1;
  r = userlist_clnt_get_uid_by_pid(state->old.server_conn, system_uid,
                                   system_gid, system_pid, state->contest_id,
                                   p_uid, p_priv_level,
                                   p_cookie,
                                   NULL /* FIXME: client_key */,
                                   p_ip, p_ssl);
  if (r < 0) return -1;
  return r;
}

int
teamdb_get_user_status_map(teamdb_state_t state, int *p_size, int **p_map)
{
  int map_size = 0, i;
  int *map = 0;
  struct userlist_contest *uc;
  int old_flags, new_flags;

  if (state->disabled) {
    *p_size = 0;
    *p_map = 0;
    return 0;
  }

  if (teamdb_refresh(state) < 0) return -1;

  if (state->users->user_map_size <= 0) {
    *p_size = 0;
    *p_map = 0;
    return 0;
  }

  map_size = state->users->user_map_size;
  XCALLOC(map, map_size);

  for (i = 1; i < state->users->user_map_size; i++) {
    if (!(uc = state->u_contests[i])) {
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
    if ((old_flags & USERLIST_UC_INCOMPLETE)) {
      new_flags |= TEAM_INCOMPLETE;
    }
    if ((old_flags & USERLIST_UC_DISQUALIFIED)) {
      new_flags |= TEAM_DISQUALIFIED;
    }
    if ((old_flags & USERLIST_UC_PRIVILEGED)) {
      new_flags |= TEAM_PRIVILEGED;
    }
    if ((old_flags & USERLIST_UC_REG_READONLY)) {
      new_flags |= TEAM_REG_READONLY;
    }
    map[i] = new_flags;
  }

  *p_size = map_size;
  *p_map = map;
  return 1;
}

teamdb_state_t
teamdb_destroy(teamdb_state_t state)
{
  int i;
  struct update_hook *p, *q;

  if (!state) return 0;

  if (!state->callbacks) {
    close_connection(&state->old);
    xfree(state->old.server_path);
  }
  xfree(state->callbacks);

  if (!state->header) {
    if (state->users) {
      userlist_free((struct xml_tree*) state->users);
    }
  } else {
    xfree(state->header);
  }
  xfree(state->participants);
  xfree(state->u_contests);
  for (i = 0; i < state->extra_num; i++)
    xfree(state->extra_info[i]);
  xfree(state->extra_info);
  for (p = state->first_update_hook; p; p = q) {
    q = p->next;
    xfree(p);
  }

  memset(state, 0, sizeof(*state));
  xfree(state);
  return 0;
}
