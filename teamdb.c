/* -*- c -*- */
/* $Id$ */

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

/*
 * team file
 *   teamlogin:teamid:flags:name:...
 * passwd file
 *   teamid:flags:passwd
 */

#include "teamdb.h"

#include "pathutl.h"
#include "osdeps.h"
#include "logger.h"
#include "xalloc.h"
#include "base64.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>

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
        err(_("read_fields: field %s is too long"), fi[i].name);
        return -1;
      }
      fi[i].ptr[j++] = *p++;
    }
    if (*p == ':' || *p == '\n') p++;
  }
  if (fi[i].maxlen != 0) {
    err(_("read_fields: too few fields read: %d"), i);
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

  memset(teams, 0, sizeof(teams));
  teams_total = 0;
  /* read team information file */
  info(_("teamdb_open: opening %s"), team);
  if (!(f = fopen(team, "r"))) {
    err(_("teamdb_open: cannot open %s: %s"), team, os_ErrorMsg());
    goto cleanup;
  }
  while (fgets(linebuf, sizeof(linebuf), f)) {
    if (strlen(linebuf) == sizeof(linebuf) - 1
        && linebuf[sizeof(linebuf) - 2] != '\n') {
      err(_("teamdb_open: line is too long: %d"), strlen(linebuf));
      goto cleanup;
    }
    if (linebuf[0] == '#') continue;
    if (read_fields(linebuf, team_fieldinfo) < 0) goto cleanup;

    if (sscanf(id_b, "%d%n", &id, &n) != 1 || id_b[n] || id <= 0
        || id > MAX_TEAM_ID) {
      err(_("teamdb_open: invalid team id: %s"), id_b);
      goto cleanup;
    }
    if (teams[id]) {
      err(_("teamid %d already used"), id);
      goto cleanup;
    }
    if (!login_b[0]) {
      err(_("login is empty for team %d"), id);
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
    err(_("teamdb_open: read error: %s"), os_ErrorMsg());
    goto cleanup;
  }
  fclose(f);

  /* read team passwd file */
  info(_("teamdb_open: opening %s"), passwd);
  if (!(f = fopen(passwd, "r"))) {
    err(_("teamdb_open: cannot open %s: %s"), team, os_ErrorMsg());
    goto relaxed_cleanup;
  }
  while (fgets(linebuf, sizeof(linebuf), f)) {
    if (strlen(linebuf) == sizeof(linebuf) - 1
        && linebuf[sizeof(linebuf) - 2] != '\n') {
      err(_("teamdb_open: line is too long: %d"), strlen(linebuf));
      goto cleanup;
    }
    if (linebuf[0] == '#') continue;
    if (read_fields(linebuf, passwd_fieldinfo) < 0) goto cleanup;
    if (sscanf(id_b, "%d%n", &id, &n) != 1 || id_b[n] || id <= 0
        || id > MAX_TEAM_ID) {
      err(_("teamdb_open: invalid team id: %s"), id_b);
      if (rel_flag) continue;
      goto cleanup;
    }
    if (!teams[id]) {
      err(_("teamid %d not defined"), id);
      if (rel_flag) continue;
      goto cleanup;
    }
    teams[id]->flags |= parse_passwd_flags(flags_b);
    if (verify_passwd(passwd_b) < 0) {
      err(_("team %d: invalid password: %s"), id, passwd_b);
      if (rel_flag) continue;
      goto cleanup;
    }
    if (!passwd_b[0]) {
      if (rel_flag) continue;
      err(_("team %d: empty password"), id);
      goto cleanup;
    }
    strcpy(teams[id]->passwd, passwd_b);
  }
  if (ferror(f)) {
    err(_("teamdb_open: read error: %d, %s"),
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
      err(_("team %d: passwd not set"), n);
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
teamdb_lookup(int teamno)
{
  if (teamno <= 0) return 0;
  if (teamno > MAX_TEAM_ID) return 0;
  if (!teams[teamno]) return 0;
  return 1;
}

int
teamdb_lookup_login(char const *login)
{
  int id;

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
    err(_("teamdb_get_login: bad id: %d"), teamid);
    return 0;
  }
  return teams[teamid]->login;
}

char *
teamdb_get_name(int teamid)
{
  if (!teamdb_lookup(teamid)) {
    err(_("teamdb_get_login: bad id: %d"), teamid);
    return 0;
  }
  return teams[teamid]->name;
}

int
teamdb_scramble_passwd(char const *passwd, char *scramble)
{
  int ssz;

  ssz = base64_encode(passwd, strlen(passwd), scramble);
  scramble[ssz] = 0;
  return strlen(scramble);
}

int
teamdb_check_scrambled_passwd(int id, char const *scrambled)
{
  if (!teamdb_lookup(id)) {
    err(_("teamdb_get_login: bad id: %d"), id);
    return 0;
  }
  if (!strcmp(scrambled, teams[id]->passwd)) return 1;
  return 0;
}

int
teamdb_check_passwd(int id, char const *passwd)
{
  char buf[TEAMDB_MAX_SCRAMBLED_PASSWD_SIZE];

  if (teamdb_scramble_passwd(passwd, buf) <= 0) return 0;
  return teamdb_check_scrambled_passwd(id, buf);
}

int
teamdb_set_scrambled_passwd(int id, char const *scrambled)
{
  if (!teamdb_lookup(id)) {
    err(_("teamdb_get_login: bad id: %d"), id);
    return 0;
  }
  if (strlen(scrambled) >= PASSWD_FIELD_LEN) {
    err(_("teamdb_set_scrambled_passwd: passwd too long: %d"),
        strlen(scrambled));
    return 0;
  }
  strcpy(teams[id]->passwd, scrambled);
  return 1;
}

int
teamdb_get_flags(int id)
{
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

  os_rDirName(path, dir, PATH_MAX);
  sprintf(tname, "%lu%d", time(0), getpid());
  pathmake(tpath, dir, "/", tname, NULL);

  info(_("write_passwd: opening %s"), tpath);
  if (!(f = fopen(tpath, "w"))) {
    err(_("fopen failed: %s"), os_ErrorMsg());
    goto cleanup;
  }
  for (id = 1; id <= MAX_TEAM_ID; id++) {
    if (!teams[id]) continue;
    fprintf(f, "%d:%s:%s\n", id,
            unparse_passwd_flags(teams[id]->flags),
            teams[id]->passwd);
    if (ferror(f)) {
      err(_("fprintf failed: %s"), os_ErrorMsg());
    }
  }
  if (fclose(f) < 0) {
    err(_("fclose failed: %s"), os_ErrorMsg());
    goto cleanup;
  }
  f = 0;

  info(_("renaming: %s -> %s"), tpath, path);
  if (rename(tpath, path) < 0) {
    err(_("rename failed: %s"), os_ErrorMsg());
    goto cleanup;
  }

  info(_("write_passwd: success"));
  return 0;

 cleanup:
  if (f) fclose(f);
  return -1;
}

int
teamdb_get_max_team_id(void)
{
  return MAX_TEAM_ID;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */

