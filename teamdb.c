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

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

#define LOGIN_FIELD_LEN  64
#define NAME_FIELD_LEN   64
#define PASSWD_FIELD_LEN 128

#define MAX_PASSWD_LEN 16
#define MAX_TEAM_ID    1023

struct teaminfo
{
  int  id;
  int  flags;
  char login[LOGIN_FIELD_LEN];
  char name[NAME_FIELD_LEN];
  char passwd[PASSWD_FIELD_LEN];
};

#define MAX_UNDO_STACK 8
struct teaminfo undo_stack[MAX_UNDO_STACK];
int undo_sp = -1;
static void save_undo(int tid);

struct fieldinfo
{
  char *name;
  int   maxlen;
  char *ptr;
};

static struct teaminfo *teams[MAX_TEAM_ID + 1];
static int teams_total;
//static int serial = 1;

static char login_b[LOGIN_FIELD_LEN];
static char name_b[NAME_FIELD_LEN];
static char passwd_b[PASSWD_FIELD_LEN];
static char flags_b[32];
static char id_b[32];

static char linebuf[1024];

static struct fieldinfo team_fieldinfo [] =
{
  { "team_login", LOGIN_FIELD_LEN, login_b },
  { "team_id",    32,              id_b },
  { "team_flags", 32,              flags_b },
  { "team_name",  NAME_FIELD_LEN,  name_b },
  { 0, 0 }
};
static struct fieldinfo passwd_fieldinfo [] =
{
  { "passwd_id",     32,               id_b },
  { "passwd_flags",  32,               flags_b },
  { "passwd_passwd", PASSWD_FIELD_LEN, passwd_b },
  { 0, 0 }
};

/* userlist-server connection */
static struct userlist_clnt *server_conn = 0;
static int sem_id = -1;
static int shm_id = -1;
static struct userlist_table *server_users;
static struct userlist_table *cached_users;
static int cached_size;
static struct userlist_user_short **cached_map;
static key_t sem_key, shm_key;
static int contest_id;

static void
lock_userlist_table(void)
{
  struct sembuf lock;

  lock.sem_num = 0;
  lock.sem_op = -1;
  lock.sem_flg = SEM_UNDO;      /* in case of crash */
  while (1) {
    if (!semop(sem_id, &lock, 1)) break;
    if (errno != EINTR) {
      err("semop failed: %s", os_ErrorMsg());
      exit(1);                  /* FIXME: exit gracefully */
    }
    info("semop restarted after signal");
  }
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
    exit(1);                  /* FIXME: exit gracefully */
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
  lock_userlist_table();
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
}

static int
verify_passwd(char const *passwd)
{
  char buf[256];
  int  plen, errf = 0;

  plen = base64_decode(passwd, strlen(passwd), buf, &errf);
  if (errf > 0) return -1;
  return 0;
}

static int
read_fields(char const *s, const struct fieldinfo *fi)
{
  int i, j;
  char const *p = s;

  for (i = 0; fi[i].maxlen && *p; i++) {
    j = 0;
    memset(fi[i].ptr, 0, fi[i].maxlen);
    while (*p != 0 && *p != ':' && *p != '\n') {
      if (j >= fi[i].maxlen - 1) {
        err("read_fields: field %s is too long", fi[i].name);
        return -1;
      }
      fi[i].ptr[j++] = *p++;
    }
    if (*p == ':' || *p == '\n') p++;
  }
  if (fi[i].maxlen != 0) {
    err("read_fields: too few fields read: %d", i);
    return -1;
  }
  return i;
}

static int
parse_teamdb_flags(char const *flags)
{
  /* FIXME: complete it! */
  return 0;
}
static int
parse_passwd_flags(char const *flags)
{
  int val = 0;
  for(; *flags; flags++) {
    if (*flags == 'b') val |= TEAM_BANNED;
    if (*flags == 'i') val |= TEAM_INVISIBLE;
  }
  return val;
}
static char *
unparse_passwd_flags(int flags)
{
  static char buf[32];
  buf[0] = 0;
  if ((flags & TEAM_BANNED)) strcat(buf, "b");
  if ((flags & TEAM_INVISIBLE)) strcat(buf, "i");
  return buf;
}

int
teamdb_open(char const *team, char const *passwd, int rel_flag)
{
  FILE *f = 0;
  int   id, n;

  if (server_conn) {
    err("teamdb_open: already opened in client mode");
    return -1;
  }

  memset(teams, 0, sizeof(teams));
  teams_total = 0;
  /* read team information file */
  info("teamdb_open: opening %s", team);
  if (!(f = fopen(team, "r"))) {
    err("teamdb_open: cannot open %s: %s", team, os_ErrorMsg());
    goto cleanup;
  }
  while (fgets(linebuf, sizeof(linebuf), f)) {
    if (strlen(linebuf) == sizeof(linebuf) - 1
        && linebuf[sizeof(linebuf) - 2] != '\n') {
      err("teamdb_open: line is too long: %d", strlen(linebuf));
      goto cleanup;
    }
    if (linebuf[0] == '#') continue;
    if (read_fields(linebuf, team_fieldinfo) < 0) goto cleanup;

    if (sscanf(id_b, "%d%n", &id, &n) != 1 || id_b[n] || id <= 0
        || id > MAX_TEAM_ID) {
      err("teamdb_open: invalid team id: %s", id_b);
      goto cleanup;
    }
    if (teams[id]) {
      err("teamid %d already used", id);
      goto cleanup;
    }
    if (!login_b[0]) {
      err("login is empty for team %d", id);
      goto cleanup;
    }
    if (!name_b[0]) {
      strncpy(name_b, login_b, NAME_FIELD_LEN);
      name_b[NAME_FIELD_LEN - 1] = 0;
    }
    teams[id] = (struct teaminfo*) xcalloc(sizeof(struct teaminfo), 1);
    teams[id]->id = id;
    teams[id]->flags |= parse_teamdb_flags(flags_b);
    strcpy(teams[id]->login, login_b);
    strcpy(teams[id]->name, name_b);
    teams_total++;
  }
  if (ferror(f)) {
    err("teamdb_open: read error: %s", os_ErrorMsg());
    goto cleanup;
  }
  fclose(f);

  /* read team passwd file */
  info("teamdb_open: opening %s", passwd);
  if (!(f = fopen(passwd, "r"))) {
    err("teamdb_open: cannot open %s: %s", team, os_ErrorMsg());
    goto relaxed_cleanup;
  }
  while (fgets(linebuf, sizeof(linebuf), f)) {
    if (strlen(linebuf) == sizeof(linebuf) - 1
        && linebuf[sizeof(linebuf) - 2] != '\n') {
      err("teamdb_open: line is too long: %d", strlen(linebuf));
      goto cleanup;
    }
    if (linebuf[0] == '#') continue;
    if (read_fields(linebuf, passwd_fieldinfo) < 0) goto cleanup;
    if (sscanf(id_b, "%d%n", &id, &n) != 1 || id_b[n] || id <= 0
        || id > MAX_TEAM_ID) {
      err("teamdb_open: invalid team id: %s", id_b);
      if (rel_flag) continue;
      goto cleanup;
    }
    if (!teams[id]) {
      err("teamid %d not defined", id);
      if (rel_flag) continue;
      goto cleanup;
    }
    teams[id]->flags |= parse_passwd_flags(flags_b);
    if (verify_passwd(passwd_b) < 0) {
      err("team %d: invalid password: %s", id, passwd_b);
      if (rel_flag) continue;
      goto cleanup;
    }
    if (!passwd_b[0]) {
      if (rel_flag) continue;
      err("team %d: empty password", id);
      goto cleanup;
    }
    strcpy(teams[id]->passwd, passwd_b);
  }
  if (ferror(f)) {
    err("teamdb_open: read error: %d, %s",
              errno, strerror(errno));
    goto cleanup;
  }
  fclose(f);

  for (n = 1; n <= MAX_TEAM_ID; n++) {
    if (!teams[n]) continue;
    //fprintf(stderr, "%s:%d:%s:%s\n",
    //        teams[n]->login, teams[n]->id,
    //        teams[n]->name, teams[n]->passwd);
    if (!teams[n]->passwd[0]) {
      if (rel_flag) continue;
      err("team %d: passwd not set", n);
      goto cleanup;
    }
  }

  return 0;

 relaxed_cleanup:
  if (f) fclose(f);
  return 0;

 cleanup:
  if (f) fclose(f);
  return -1;
}

int
teamdb_open_client(unsigned char const *socket_path, int id)
{
  int r;

  if (teams_total > 0) {
    err("teamdb_open_client: already opened in files mode");
    return -1;
  }
  contest_id = id;
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

int
teamdb_lookup(int teamno)
{
  if (server_conn) {
    if (teamno <= 0 || teamno >= cached_size || !cached_map[teamno]) return 0;
    return 1;
  }

  if (teamno <= 0) return 0;
  if (teamno > MAX_TEAM_ID) return 0;
  if (!teams[teamno]) return 0;
  return 1;
}

int
teamdb_lookup_login(char const *login)
{
  int id;

  if (server_conn) {
    err("teamdb_lookup_login: operation not implemented in client mode");
    return 0;
  }

  for (id = 1; id <= MAX_TEAM_ID; id++) {
    if (!teams[id]) continue;
    if (!strcmp(teams[id]->login, login))
      return id;
  }
  return 0;
}

char *
teamdb_get_login(int teamid)
{
  if (!teamdb_lookup(teamid)) {
    err("teamdb_get_login: bad id: %d", teamid);
    return 0;
  }
  if (server_conn) {
    return cached_users->pool + cached_map[teamid]->login_idx;
  }
  return teams[teamid]->login;
}

char *
teamdb_get_name(int teamid)
{
  if (!teamdb_lookup(teamid)) {
    err("teamdb_get_login: bad id: %d", teamid);
    return 0;
  }
  if (server_conn) {
    return cached_users->pool + cached_map[teamid]->name_idx;
  }
  return teams[teamid]->name;
}

int
teamdb_scramble_passwd(char const *passwd, char *scramble)
{
  int ssz;

  if (server_conn) {
    err("teamdb_scramble_passwd: operation not implemented in client mode");
    return 0;
  }

  ssz = base64_encode(passwd, strlen(passwd), scramble);
  scramble[ssz] = 0;
  return strlen(scramble);
}

int
teamdb_check_scrambled_passwd(int id, char const *scrambled)
{
  if (server_conn) {
    err("teamdb_check_scrambled_passwd: operation not implemented in client mode");
    return 0;
  }

  if (!teamdb_lookup(id)) {
    err("teamdb_get_login: bad id: %d", id);
    return 0;
  }
  if (!strcmp(scrambled, teams[id]->passwd)) return 1;
  return 0;
}

int
teamdb_check_passwd(int id, char const *passwd)
{
  char buf[TEAMDB_MAX_SCRAMBLED_PASSWD_SIZE];

  if (server_conn) {
    err("teamdb_check_passwd: operation not implemented in client mode");
    return 0;
  }

  if (teamdb_scramble_passwd(passwd, buf) <= 0) return 0;
  return teamdb_check_scrambled_passwd(id, buf);
}

int
teamdb_set_scrambled_passwd(int id, char const *scrambled)
{
  if (server_conn) {
    err("teamdb_set_scrambled_passwd: operation not implemented in client mode");
    return 0;
  }

  if (!teamdb_lookup(id)) {
    err("teamdb_get_login: bad id: %d", id);
    return 0;
  }
  if (strlen(scrambled) >= PASSWD_FIELD_LEN) {
    err("teamdb_set_scrambled_passwd: passwd too long: %d",
        strlen(scrambled));
    return 0;
  }
  save_undo(id);
  strcpy(teams[id]->passwd, scrambled);
  return 1;
}

int
teamdb_get_plain_password(int id, char *buf, int size)
{
  int errcode = 0, outlen, inlen;
  char *outbuf;

  if (server_conn) {
    err("teamdb_get_plain_password: operation not implemented in client mode");
    return -1;
  }

  if (!teamdb_lookup(id)) {
    err("teamdb_get_plain_password: bad id: %d", id);
    return -1;
  }
  inlen = strlen(teams[id]->passwd);
  outbuf = (char*) alloca(inlen * 2 + 10);
  outlen = base64_decode(teams[id]->passwd, inlen, outbuf, &errcode);
  if (errcode) {
    err("teamdb_get_plain_password: invalid password for %d", id);
    return -1;
  }
  if (outlen + 1 > size) {
    err("teamdb_get_plain_password: output buffer too short");
    return -1;
  }
  memset(buf, 0, size);
  memcpy(buf, outbuf, outlen);
  return 0;
}

int
teamdb_get_flags(int id)
{
  if (server_conn) {
    int new_flags = 0;
    if (!teamdb_lookup(id)) {
      err("teamdb_get_flags: bad team id %d", id);
      return 0;
    }
    if ((cached_map[id]->flags & USERLIST_UC_INVISIBLE)) {
      new_flags |= TEAM_INVISIBLE;
    }
    return new_flags;
  }

  return teams[id]->flags;
}

int
teamdb_write_passwd(char const *path)
{
  char    tname[32];
  path_t  tpath; 
  path_t  dir;
  FILE   *f = 0;
  int     id;

  if (server_conn) {
    err("teamdb_write_passwd: operation not implemented in client mode");
    return 0;
  }

  os_rDirName(path, dir, PATH_MAX);
  sprintf(tname, "%lu%d", time(0), getpid());
  pathmake(tpath, dir, "/", tname, NULL);

  info("write_passwd: opening %s", tpath);
  if (!(f = fopen(tpath, "w"))) {
    err("fopen failed: %s", os_ErrorMsg());
    goto cleanup;
  }
  for (id = 1; id <= MAX_TEAM_ID; id++) {
    if (!teams[id]) continue;
    fprintf(f, "%d:%s:%s\n", id,
            unparse_passwd_flags(teams[id]->flags),
            teams[id]->passwd);
    if (ferror(f)) {
      err("fprintf failed: %s", os_ErrorMsg());
    }
  }
  if (fclose(f) < 0) {
    err("fclose failed: %s", os_ErrorMsg());
    goto cleanup;
  }
  f = 0;

  info("renaming: %s -> %s", tpath, path);
  if (rename(tpath, path) < 0) {
    err("rename failed: %s", os_ErrorMsg());
    goto cleanup;
  }

  info("write_passwd: success");
  return 0;

 cleanup:
  if (f) fclose(f);
  return -1;
}

int
teamdb_write_teamdb(char const *path)
{
  char    tname[32];
  path_t  tpath; 
  path_t  dir;
  FILE   *f = 0;
  int     id;

  if (server_conn) {
    err("teamdb_write_teamdb: operation not implemented in client mode");
    return 0;
  }

  os_rDirName(path, dir, PATH_MAX);
  sprintf(tname, "%lu%d", time(0), getpid());
  pathmake(tpath, dir, "/", tname, NULL);

  info("write_teamdb: opening %s", tpath);
  if (!(f = fopen(tpath, "w"))) {
    err("fopen failed: %s", os_ErrorMsg());
    goto cleanup;
  }
  for (id = 1; id <= MAX_TEAM_ID; id++) {
    if (!teams[id]) continue;
    fprintf(f, "%s:%d::%s\n",
            teams[id]->login,
            id,
            teams[id]->name);
    if (ferror(f)) {
      err("fprintf failed: %s", os_ErrorMsg());
    }
  }
  if (fclose(f) < 0) {
    err("fclose failed: %s", os_ErrorMsg());
    goto cleanup;
  }
  f = 0;

  info("renaming: %s -> %s", tpath, path);
  if (rename(tpath, path) < 0) {
    err("rename failed: %s", os_ErrorMsg());
    goto cleanup;
  }

  info("write_teamdb: success");
  return 0;

 cleanup:
  if (f) fclose(f);
  return -1;
}

int
teamdb_get_max_team_id(void)
{
  if (server_conn) {
    return cached_size - 1;
  }
  return MAX_TEAM_ID;
}

int
teamdb_get_total_teams(void)
{
  int tot = 0, i;

  if (server_conn) {
    return cached_users->total;
  }

  for (i = 1; i <= MAX_TEAM_ID; i++)
    if (teams[i]) tot++;

  return tot;
}

static char const valid_login_chars[256] =
{
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,'-','.',0,
  '0','1','2','3','4','5','6','7','8','9',0,0,0,'=',0,0,
  '@','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O',
  'P','Q','R','S','T','U','V','W','X','Y','Z',0,0,0,0,'_',
  0,'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o',
  'p','q','r','s','t','u','v','w','x','y','z',0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};
int
teamdb_is_valid_login(char const *str)
{
  unsigned char const *s = (unsigned char const*) str;

  if (server_conn) {
    err("teamdb_is_valid_login: not implemented in client mode");
    return 0;
  }
  for (s = str; *s; s++) {
    if (!valid_login_chars[*s]) return 0;
  }
  return 1;
}

static char const valid_name_chars[256] =
{
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  ' ','!',0,'#','$','%','&',0,'(',')','*','+',',','-','.','/',
  '0','1','2','3','4','5','6','7','8','9',0,0,'<','=','>','?',
  '@','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O',
  'P','Q','R','S','T','U','V','W','X','Y','Z','[',0,']','^','_',
  '`','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o',
  'p','q','r','s','t','u','v','w','x','y','z','{','|','}','~',0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  ' ','¡','¢','£','¤','¥','¦','§','¨','©','ª','«','¬','­','®','¯',
  '°','±','²','³','´','µ','¶','·','¸','¹','º','»','¼','½','¾','¿',
  'À','Á','Â','Ã','Ä','Å','Æ','Ç','È','É','Ê','Ë','Ì','Í','Î','Ï',
  'Ð','Ñ','Ò','Ó','Ô','Õ','Ö','×','Ø','Ù','Ú','Û','Ü','Ý','Þ','ß',
  'à','á','â','ã','ä','å','æ','ç','è','é','ê','ë','ì','í','î','ï',
  'ð','ñ','ò','ó','ô','õ','ö','÷','ø','ù','ú','û','ü','ý','þ','ÿ'
};
int
teamdb_is_valid_name(char const *str)
{
  unsigned char const *s = (unsigned char const*) str;

  if (server_conn) {
    err("teamdb_is_valid_name: not implemented in client mode");
    return 0;
  }
  for (s = str; *s; s++) {
    if (!valid_name_chars[*s]) return 0;
  }
  return 1;
}

int
teamdb_change_login(int tid, char const *login)
{
  if (server_conn) {
    err("teamdb_change_login: not implemented in client mode");
    return -1;
  }
  if (!teamdb_lookup(tid)) {
    err("teamdb_change_login: bad id: %d", tid);
    return -1;
  }
  if (!teamdb_is_valid_login(login)) {
    err("teamdb_change_login: invalid login");
    return -1;
  }
  if (strlen(login) >= LOGIN_FIELD_LEN) {
    err("teamdb_change_login: login is too long");
    return -1;
  }
  save_undo(tid);
  strcpy(teams[tid]->login, login);
  return 0;
}

int
teamdb_change_name(int tid, char const *name)
{
  if (server_conn) {
    err("teamdb_change_name: not implemented in client mode");
    return -1;
  }
  if (!teamdb_lookup(tid)) {
    err("teamdb_change_name: bad id: %d", tid);
    return -1;
  }
  if (!teamdb_is_valid_name(name)) {
    err("teamdb_change_name: invalid name");
    return -1;
  }
  if (strlen(name) >= NAME_FIELD_LEN) {
    err("teamdb_change_name: name is too long");
    return -1;
  }
  save_undo(tid);
  strcpy(teams[tid]->name, name);
  return 0;
}

int
teamdb_toggle_vis(int tid)
{
  if (server_conn) {
    // FIXME: this operation has sense!
    err("teamdb_toggle_vis: not implemented in client mode");
    return -1;
  }
  if (!teamdb_lookup(tid)) {
    err("teamdb_toggle_vis: bad id: %d", tid);
    return -1;
  }
  save_undo(tid);
  teams[tid]->flags ^= TEAM_INVISIBLE;
  return 0;
}

int
teamdb_toggle_ban(int tid)
{
  if (server_conn) {
    // FIXME: this operation has sense!
    err("teamdb_toggle_ban: not implemented in client mode");
    return -1;
  }
  if (!teamdb_lookup(tid)) {
    err("teamdb_toggle_ban: bad id: %d", tid);
    return -1;
  }
  save_undo(tid);
  teams[tid]->flags ^= TEAM_BANNED;
  return 0;
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
  char *scramble;

  if (server_conn) {
    err("teamdb_add_team: not implemented in client mode");
    *msg = "Not implemented in client mode";
    return -1;
  }

  *msg = 0;
  if (!tid) {
    for (tid = 1; tid <= MAX_TEAM_ID && teams[tid]; tid++);
    if (tid > MAX_TEAM_ID) {
      *msg = "Team capacity exhausted";
      return -1;
    }
  }
  if (tid <= 0 || tid > MAX_TEAM_ID) {
    *msg = "Invalid team id";
    return -1;
  }
  if (teams[tid]) {
    *msg = "Team with the given team id already exists";
    return -1;
  }
  if (!*login) {
    *msg = "Team login is empty";
    return -1;
  }
  if (strlen(login) >= LOGIN_FIELD_LEN) {
    *msg = "Team login is too long";
    return -1;
  }
  if (!teamdb_is_valid_login(login)) {
    *msg = "Team login is invalid";
    return -1;
  }
  if (!*name) {
    *msg = "Team name is empty";
    return -1;
  }
  if (strlen(name) >= NAME_FIELD_LEN) {
    *msg = "Team name is too long";
    return -1;
  }
  if (!teamdb_is_valid_name(name)) {
    *msg = "Team name is invalid";
    return -1;
  }
  if (!*passwd) {
    *msg = "Team password is empty";
    return -1;
  }
  if (strlen(passwd) > MAX_PASSWD_LEN) {
    *msg = "Password is too long";
    return -1;
  }
  scramble = alloca(strlen(passwd) * 2 + 16);
  teamdb_scramble_passwd(passwd, scramble);
  save_undo(tid);
  XCALLOC(teams[tid], 1);
  teams[tid]->id = tid;
  teams[tid]->flags = 0;
  if (!vis) teams[tid]->flags |= TEAM_INVISIBLE;
  if (ban)  teams[tid]->flags |= TEAM_BANNED;
  strcpy(teams[tid]->login, login);
  strcpy(teams[tid]->name, name);
  strcpy(teams[tid]->passwd, scramble);
  return 0;
}

static void
save_undo(int tid)
{
  if (undo_sp < 0) return;
  if (!teams[tid]) {
    undo_stack[undo_sp].id = tid;
    undo_stack[undo_sp].flags = -1;
  } else {
    ASSERT(teams[tid]->id == tid);
    memcpy(&undo_stack[undo_sp], teams[tid], sizeof(undo_stack[0]));
  }
  undo_sp++;
}

void
teamdb_transaction(void)
{
  if (server_conn) {
    err("teamdb_transaction: not implemented in client mode");
    return;
  }
  undo_sp = 0;
}

void
teamdb_commit(void)
{
  if (server_conn) {
    err("teamdb_commit: not implemented in client mode");
    return;
  }
  undo_sp = -1;
}

void
teamdb_rollback(void)
{
  int id;

  if (server_conn) {
    err("teamdb_rollback: not implemented in client mode");
    return;
  }

  while (undo_sp > 0) {
    undo_sp--;
    id = undo_stack[undo_sp].id;
    if (undo_stack[undo_sp].flags == -1) {
      xfree(teams[id]); teams[id] = 0;
    } else {
      if (!teams[id]) {
        XCALLOC(teams[id], 1);
      }
      memcpy(teams[id], &undo_stack[undo_sp], sizeof(undo_stack[0]));
    }
  }
}

int
teamdb_export_team(int tid, struct teamdb_export *pdata)
{
  if (server_conn) {
    err("teamdb_export_team: not implemented in client mode");
    return -1;
  }

  if (!teamdb_lookup(tid)) {
    err("teamdb_export_team: bad id: %d", tid);
    return -1;
  }

  XMEMZERO(pdata, 1);
  pdata->id = teams[tid]->id;
  pdata->flags = teams[tid]->flags;
  strncpy(pdata->login, teams[tid]->login, TEAMDB_LOGIN_LEN);
  pdata->login[TEAMDB_LOGIN_LEN - 1] = 0;
  strncpy(pdata->name, teams[tid]->name, TEAMDB_NAME_LEN);
  pdata->name[TEAMDB_NAME_LEN - 1] = 0;
  strncpy(pdata->scrambled, teams[tid]->passwd, TEAMDB_SCRAMBLED_LEN);
  pdata->scrambled[TEAMDB_SCRAMBLED_LEN - 1] = 0;
  teamdb_get_plain_password(tid, pdata->passwd, TEAMDB_PASSWD_LEN);

  return 0;
}

int
teamdb_regenerate_passwords(unsigned char const *path)
{
  int fd, r;

  if (!server_conn) {
    err("teamdb_regenerate_passwords: not supported in files mode");
    return -1;
  }
  if ((fd = open(path, O_WRONLY)) < 0) {
    err("teamdb_regenerate_passwords: cannot open %s: %s",
        path, os_ErrorMsg());
    return -1;
  }
  r = userlist_clnt_generate_team_passwd(server_conn, contest_id, fd);
  if (r < 0) {
    err("teamdb_regenerate_passwords: failed: %s", userlist_strerror(-r));
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */

