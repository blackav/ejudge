/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2002 Alexander Chernov <cher@ispras.ru> */

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

/*
 * team file
 *   teamlogin:teamid:flags:name
 * passwd file
 *   teamid:flags:passwd
 */

#include "teamdb.h"

#include "pathutl.h"
#include "base64.h"
#include "userlist_clnt.h"
#include "userlist_proto.h"

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

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

/* userlist-server connection */
static unsigned char *server_path = 0;
static struct userlist_clnt *server_conn = 0;
static int sem_id = -1;
static int shm_id = -1;
static struct userlist_table *server_users;
static struct userlist_table *cached_users;
static int cached_size;
static struct userlist_user_short **cached_map;
static key_t sem_key, shm_key;
static int contest_id;

/* non-saved local extra information about teams */
struct teamdb_extra
{
  time_t last_archive_time;
};
static int extra_out_of_sync;
static int extra_num;
static struct teamdb_extra **extra_info;

static int interrupted_flag;
static sighandler_t prev_handler[32];

static void handler(int signo)
{
  interrupted_flag = 1;
  if (signo != SIGINT && signo != SIGTERM) return;
  if (prev_handler[signo]
      && prev_handler[signo] != SIG_DFL
      && prev_handler[signo] != SIG_IGN) {
    (*prev_handler[signo])(signo);
  }
}

static int
restore_connection(void)
{
  int retcode = 1;
  int first_time = 1;
  int r;

  info("userlist-server is disconnected. Trying to restore connection.");

  userlist_clnt_close(server_conn);
  server_conn = 0;
  xfree(cached_users); cached_users = 0;
  xfree(cached_map); cached_map = 0;
  cached_size = 0;
  shmdt(server_users);
  // just in case...
  semctl(sem_id, 0, IPC_RMID);
  shmctl(shm_id, IPC_RMID, 0);
  sem_id = shm_id = -1;

  prev_handler[SIGINT] = signal(SIGINT, handler);
  prev_handler[SIGTERM] = signal(SIGTERM, handler);

  while (1) {
    if (!first_time) sleep(1);
    first_time = 0;

    if (interrupted_flag) {
      retcode = 0;
      break;
    }

    server_conn = userlist_clnt_open(server_path);
    if (!server_conn) {
      err("teamdb_open_client: connect to server failed");
      continue;
    }
    if ((r = userlist_clnt_admin_process(server_conn)) < 0) {
      if (r == ULS_ERR_NO_CONNECT || r == ULS_ERR_DISCONNECT) continue;
      err("teamdb_open_client: cannot became an admin process: %s",
          userlist_strerror(-r));
      retcode = -1;
      break;
    }
    if ((r = userlist_clnt_map_contest(server_conn, contest_id,
                                       &sem_key, &shm_key)) < 0) {
      if (r == ULS_ERR_NO_CONNECT || r == ULS_ERR_DISCONNECT) continue;
      err("teamdb_open_client: cannot map contest: %s", userlist_strerror(-r));
      retcode = -1;
      break;
    }
    if ((sem_id = semget(sem_key, 1, 0)) < 0) {
      err("teamdb_open_client: cannot obtain a semafore: %s", os_ErrorMsg());
      retcode = -1;
      break;
    }
    if ((shm_id = shmget(shm_key, 0, 0)) < 0) {
      err("teamdb_open_client: cannot obtain a shared memory: %s",
          os_ErrorMsg());
      retcode = -1;
      break;
    }
    if ((int) (server_users = shmat(shm_id, 0, SHM_RDONLY)) == -1) {
      err("teamdb_open_client: cannot attach shared memory: %s",
          os_ErrorMsg());
      retcode = -1;
      break;
    }
    // success!
    break;
  }

  signal(SIGINT, prev_handler[SIGINT]);
  signal(SIGTERM, prev_handler[SIGTERM]);
  return retcode;
}

static int
lock_userlist_table(void)
{
  struct sembuf lock;
  int r;

 restart_lock:
  lock.sem_num = 0;
  lock.sem_op = -1;
  lock.sem_flg = SEM_UNDO;      /* in case of crash */
  while (1) {
    if (!semop(sem_id, &lock, 1)) break;
    if (errno == EIDRM || errno == EINVAL) {
      r = restore_connection();
      if (r > 0) goto restart_lock;
      return -1;
    }
    if (errno != EINTR) {
      err("semop failed: %s", os_ErrorMsg());
      return -1;
    }
    info("semop restarted after signal");
  }
  return 0;
}
static void
unlock_userlist_table(void)
{
  struct sembuf unlock;

  unlock.sem_num = 0;
  unlock.sem_op = 1;
  unlock.sem_flg = SEM_UNDO;
  if (semop(sem_id, &unlock, 1) < 0) {
    err("semop failed: %s", os_ErrorMsg());
  }
}
void
teamdb_refresh(void)
{
  int m;
  int i;

  if (!server_conn) return;
  if (cached_users && cached_users->vintage == server_users->vintage) return;
  if (!cached_users) {
    cached_users = xcalloc(1, sizeof(*cached_users));
  }
  if (lock_userlist_table() < 0) {
    xfree(cached_users);
    cached_users = 0;
    return;
  }
  if (!cached_users) {
    cached_users = xcalloc(1, sizeof(*cached_users));
  }
  memcpy(cached_users, server_users, sizeof(*server_users));
  unlock_userlist_table();

  xfree(cached_map);
  cached_map = 0;
  m = -1;
  for (i = 0; i < cached_users->total; i++) {
    if (cached_users->users[i].user_id > m) m = cached_users->users[i].user_id;
  }
  if (m <= 0) {
    cached_size = 0;
  } else {
    cached_size = m + 1;
    cached_map = xcalloc(cached_size, sizeof(cached_map[0]));
    for (i = 0; i < cached_users->total; i++) {
      cached_map[cached_users->users[i].user_id] = &cached_users->users[i];
    }
  }

  info("refresh_userlist_table: updated from server, %d users (size = %d)", cached_users->total, cached_size);
  extra_out_of_sync = 1;
}

int
teamdb_open_client(unsigned char const *socket_path, int id)
{
  int r;

  contest_id = id;
  server_path = xstrdup(socket_path);
  server_conn = userlist_clnt_open(socket_path);
  if (!server_conn) {
    err("teamdb_open_client: connect to server failed");
    return -1;
  }
  if ((r = userlist_clnt_admin_process(server_conn)) < 0) {
    err("teamdb_open_client: cannot became an admin process: %s",
        userlist_strerror(-r));
    return -1;
  }
  if ((r = userlist_clnt_map_contest(server_conn, contest_id,
                                     &sem_key, &shm_key)) < 0) {
    err("teamdb_open_client: cannot map contest: %s", userlist_strerror(-r));
    return -1;
  }
  if ((sem_id = semget(sem_key, 1, 0)) < 0) {
    err("teamdb_open_client: cannot obtain a semafore: %s", os_ErrorMsg());
    return -1;
  }
  if ((shm_id = shmget(shm_key, 0, 0)) < 0) {
    err("teamdb_open_client: cannot obtain a shared memory: %s",
        os_ErrorMsg());
    return -1;
  }
  if ((int) (server_users = shmat(shm_id, 0, SHM_RDONLY)) == -1) {
    err("teamdb_open_client: cannot attach shared memory: %s",
        os_ErrorMsg());
    return -1;
  }

  teamdb_refresh();
  return 0;
}

inline int
teamdb_lookup_client(int teamno)
{
  if (teamno <= 0 || teamno >= cached_size
      || !cached_map || !cached_map[teamno]) return 0;
  return 1;
}

int
teamdb_lookup(int teamno)
{
  ASSERT(server_conn);
  if (teamno <= 0 || teamno >= cached_size
      || !cached_map || !cached_map[teamno]) return 0;
  return 1;
}

int
teamdb_lookup_login(char const *login)
{
  ASSERT(server_conn);
  err("teamdb_lookup_login: operation not implemented in client mode");
  return 0;
}

char *
teamdb_get_login(int teamid)
{
  ASSERT(server_conn);
  if (!teamdb_lookup_client(teamid)) {
    err("teamdb_get_login: bad id: %d", teamid);
    return 0;
  }
  if (!cached_users || !cached_map) return "";
  return cached_users->pool + cached_map[teamid]->login_idx;
}

char *
teamdb_get_name(int teamid)
{
  ASSERT(server_conn);
  if (!teamdb_lookup_client(teamid)) {
    err("teamdb_get_login: bad id: %d", teamid);
    return 0;
  }
  if (!cached_users || !cached_map) return "";
  return cached_users->pool + cached_map[teamid]->name_idx;
}

int
teamdb_scramble_passwd(char const *passwd, char *scramble)
{
  ASSERT(server_conn);
  err("teamdb_scramble_passwd: operation not implemented in client mode");
  return 0;
}

int
teamdb_check_scrambled_passwd(int id, char const *scrambled)
{
  ASSERT(server_conn);
  err("teamdb_check_scrambled_passwd: not implemented in client mode");
  return 0;
}

int
teamdb_check_passwd(int id, char const *passwd)
{
  ASSERT(server_conn);
  err("teamdb_check_passwd: operation not implemented in client mode");
  return 0;
}

int
teamdb_set_scrambled_passwd(int id, char const *scrambled)
{
  ASSERT(server_conn);
  err("teamdb_set_scrambled_passwd: operation not implemented in client mode");
  return 0;
}

int
teamdb_get_plain_password(int id, char *buf, int size)
{
  ASSERT(server_conn);
  err("teamdb_get_plain_password: operation not implemented in client mode");
  return -1;
}

int
teamdb_get_flags(int id)
{
  int new_flags = 0;

  ASSERT(server_conn);
  if (!teamdb_lookup_client(id)) {
    err("teamdb_get_flags: bad team id %d", id);
    return 0;
  }
  if (!cached_map) return 0;
  if ((cached_map[id]->flags & USERLIST_UC_INVISIBLE)) {
    new_flags |= TEAM_INVISIBLE;
  }
  if ((cached_map[id]->flags & USERLIST_UC_BANNED)) {
    new_flags |= TEAM_BANNED;
  }
  return new_flags;
}

int
teamdb_write_passwd(char const *path)
{
  ASSERT(server_conn);
  err("teamdb_write_passwd: operation not implemented in client mode");
  return 0;
}

int
teamdb_write_teamdb(char const *path)
{
  ASSERT(server_conn);
  err("teamdb_write_teamdb: operation not implemented in client mode");
  return 0;
}

int
teamdb_get_max_team_id(void)
{
  ASSERT(server_conn);
  return cached_size - 1;
}

int
teamdb_get_total_teams(void)
{
  ASSERT(server_conn);
  return cached_users->total;
}

int
teamdb_is_valid_login(char const *str)
{
  ASSERT(server_conn);
  err("teamdb_is_valid_login: not implemented in client mode");
  return 0;
}

int
teamdb_is_valid_name(char const *str)
{
  ASSERT(server_conn);
  err("teamdb_is_valid_name: not implemented in client mode");
  return 0;
}

int
teamdb_change_login(int tid, char const *login)
{
  ASSERT(server_conn);
  err("teamdb_change_login: not implemented in client mode");
  return -1;
}

int
teamdb_change_name(int tid, char const *name)
{
  ASSERT(server_conn);
  err("teamdb_change_name: not implemented in client mode");
  return -1;
}

int
teamdb_toggle_vis(int tid)
{
  ASSERT(server_conn);
  err("teamdb_toggle_vis: not implemented in client mode");
  return -1;
}

int
teamdb_toggle_ban(int tid)
{
  ASSERT(server_conn);
  err("teamdb_toggle_ban: not implemented in client mode");
  return -1;
}

int
teamdb_add_team(int tid,
                char const *login,
                char const *name,
                char const *passwd,
                int vis,
                int ban,
                char **msg)
{
  ASSERT(server_conn);

  err("teamdb_add_team: not implemented in client mode");
  *msg = "Not implemented in client mode";
  return -1;
}

void
teamdb_transaction(void)
{
  ASSERT(server_conn);
  info("teamdb_transaction called");
}

void
teamdb_commit(void)
{
  ASSERT(server_conn);
  info("teamdb_commit called");
}

void
teamdb_rollback(void)
{
  ASSERT(server_conn);
  info("teamdb_rollback called");
}

int
teamdb_export_team(int tid, struct teamdb_export *pdata)
{
  ASSERT(server_conn);

  if (!teamdb_lookup_client(tid)) {
    err("teamdb_export_team: bad id: %d", tid);
    return -1;
  }

  XMEMZERO(pdata, 1);
  pdata->id = tid;
  if (!cached_map || !cached_users) return 0;
  if ((cached_map[tid]->flags & USERLIST_UC_INVISIBLE))
    pdata->flags |= TEAM_INVISIBLE;
  if ((cached_map[tid]->flags & USERLIST_UC_BANNED))
    pdata->flags |= TEAM_BANNED;
  strncpy(pdata->login, cached_users->pool + cached_map[tid]->login_idx,
          TEAMDB_LOGIN_LEN - 1);
  strncpy(pdata->name, cached_users->pool + cached_map[tid]->name_idx,
          TEAMDB_NAME_LEN - 1);
  return 0;
}

int
teamdb_regenerate_passwords(unsigned char const *path)
{
  int fd, r;

  ASSERT(server_conn);
  if ((fd = open(path, O_WRONLY)) < 0) {
    err("teamdb_regenerate_passwords: cannot open %s: %s",
        path, os_ErrorMsg());
    return -1;
  }
 restart_server_request:
  r = userlist_clnt_generate_team_passwd(server_conn, contest_id, fd);
  if (r == ULS_ERR_NO_CONNECT || r == ULS_ERR_DISCONNECT) {
    r = restore_connection();
    if (r < 0) {
      err("teamdb_regenerate_passwords: cannot restore connection");
      close(fd);
      return -1;
    }
    if (!r) {
      err("teamdb_regenerate_passwords: user interrupt");
      close(fd);
      return -1;
    }
    goto restart_server_request;
  }
  if (r < 0) {
    err("teamdb_regenerate_passwords: failed: %s", userlist_strerror(-r));
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
  if (cached_size > 0) {
    extra_info = xcalloc(cached_size, sizeof(extra_info[0]));
    extra_num = cached_size;
  } else {
    extra_info = 0;
    extra_num = 0;
  }
  max_idx = extra_num;
  if (old_extra_num < max_idx) max_idx = old_extra_num;
  for (i = 0; i < max_idx; i++) {
    if (cached_map[i]) {
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
  ASSERT(server_conn);
  if (!teamdb_lookup_client(uid)) return (time_t) -1;
  if (!cached_users || !cached_map) return (time_t) -1;
  syncronize_team_extra();
  if (!extra_info[uid]) {
    XCALLOC(extra_info[uid], 1);
  }
  return extra_info[uid]->last_archive_time;
}
int
teamdb_set_archive_time(int uid, time_t time)
{
  ASSERT(server_conn);
  if (!teamdb_lookup_client(uid)) return -1;
  if (!cached_users || !cached_map) return -1;
  syncronize_team_extra();
  if (!extra_info[uid]) {
    XCALLOC(extra_info[uid], 1);
  }
  extra_info[uid]->last_archive_time = time;
  return 0;
}

int
teamdb_get_uid_by_pid(int system_uid, int system_gid, int system_pid,
                      int *p_uid, unsigned long long *p_cookie)
{
  int r;

 restart_operation:
  r = userlist_clnt_get_uid_by_pid(server_conn, system_uid, system_gid,
                                   system_pid, p_uid, p_cookie);
  if (r == ULS_ERR_NO_CONNECT || r == ULS_ERR_DISCONNECT) {
    r = restore_connection();
    if (r <= 0) return -1;
    goto restart_operation;
  }
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */

