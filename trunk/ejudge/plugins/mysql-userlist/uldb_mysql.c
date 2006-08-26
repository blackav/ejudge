/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ispras.ru> */

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

#include "config.h"
#include "settings.h"
#include "ej_limits.h"
#include "errlog.h"
#include "uldb_plugin.h"
#include "xml_utils.h"
#include "expat_iface.h"
#include "ejudge_cfg.h"
#include "pathutl.h"
#include "userlist.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <mysql.h>

#include <string.h>
#include <stdarg.h>
#include <ctype.h>

static void *init_func(const struct ejudge_cfg *);
static int parse_func(const struct ejudge_cfg *,struct xml_tree *, void *);
static int open_func(void *data);
static int close_func(void *data);
static int check_func(void *data);
static int create_func(void *data);
static int insert_func(void *data, const struct userlist_user *user);
static int get_full_func(void *data, int user_id,
                         const struct userlist_user **user);

/* plugin entry point */
struct uldb_plugin_iface plugin_uldb_mysql =
{
  {
    sizeof (struct uldb_plugin_iface),
    EJUDGE_PLUGIN_IFACE_VERSION,
    "userdb",
    "uldb_mysql",
  },
  ULDB_PLUGIN_IFACE_VERSION,

  init_func,
  parse_func,
  open_func,
  close_func,
  check_func,
  create_func,
  insert_func,
  get_full_func,
};

struct uldb_mysql_state
{
  // configuration settings
  int port;

  unsigned char *user;
  unsigned char *password;
  unsigned char *database;
  unsigned char *host;
  unsigned char *socket;
  unsigned char *table_prefix;
  unsigned char *schema_path;

  MYSQL *conn;
  MYSQL_RES *res;
  MYSQL_ROW row;
  unsigned long *lengths;
  int row_count;
  int field_count;
};

static void*
init_func(const struct ejudge_cfg *config)
{
  struct uldb_mysql_state *state;

  XCALLOC(state, 1);
  return (void*) state;
}

static int
parse_func(const struct ejudge_cfg *config, struct xml_tree *tree, void *data)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct xml_tree *p;

  ASSERT(tree->tag == xml_err_spec->default_elem);
  ASSERT(!strcmp(tree->name[0], "config"));

  if (xml_empty_text(tree) < 0) return -1;
  if (tree->first) return xml_err_attrs(tree);

  for (p = tree->first_down; p; p = p->right) {
    ASSERT(p->tag == xml_err_spec->default_elem);
    if (!strcmp(p->name[0], "user")) {
      if (xml_leaf_elem(p, &state->user, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "password")) {
      if (xml_leaf_elem(p, &state->password, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "database")) {
      if (xml_leaf_elem(p, &state->database, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "host")) {
      if (xml_leaf_elem(p, &state->host, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "socket")) {
      if (xml_leaf_elem(p, &state->socket, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "table_prefix")) {
      if (xml_leaf_elem(p, &state->table_prefix, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "schema_path")) {
      if (xml_leaf_elem(p, &state->schema_path, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "port")) {
      if (p->first) return xml_err_attrs(p);
      if (p->first_down) return xml_err_nested_elems(p);
      if (state->port > 0) return xml_err_elem_redefined(p);
      if (xml_parse_int(xml_err_path, p->line, p->column, p->text,
                        &state->port) < 0) return -1;
    } else {
      return xml_err_elem_not_allowed(p);
    }
  }

  if (!state->user) return xml_err_elem_undefined_s(tree, "user");
  if (!state->password) return xml_err_elem_undefined_s(tree, "password");
  if (!state->database) return xml_err_elem_undefined_s(tree, "database");
  if (!state->table_prefix) state->table_prefix = xstrdup("");

  return 0;
}

static int
open_func(void *data)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  // already opened?
  if (state->conn) return 0;

  if (!(state->conn = mysql_init(0))) {
    err("mysql_init failed");
    return -1;
  }

  if (!mysql_real_connect(state->conn,
                          state->host, state->user, state->password,
                          state->database, state->port, state->socket, 0)) {
    err("database error: %s", mysql_error(state->conn));
    return -1;
  }

  return 0;
}

static int
check_func(void *data)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char cmdbuf[512];
  int cmdlen, version, n;

  if (!state->conn) return -1;

  // check, that database is created
  cmdlen = snprintf(cmdbuf, sizeof(cmdbuf),
                    "SELECT config_val FROM %sconfig WHERE config_key = 'version'",
                    state->table_prefix);
  fprintf(stderr, ">%s\n", cmdbuf);
  if (mysql_real_query(state->conn, cmdbuf, cmdlen)) {
    err("database error: %s", mysql_error(state->conn));
    err("probably the database is not created. use --convert or --create");
    return 0;
  }

  if((state->field_count = mysql_field_count(state->conn)) != 1) {
    err("wrong database format: field_count == %d", state->field_count);
    return -1;
  }
  if (!(state->res = mysql_store_result(state->conn))) {
    err("database error: %s", mysql_error(state->conn));
    return -1;
  }
  if (!(state->row_count = mysql_num_rows(state->res))) {
    err("database has no key 'version'. recreate the database");
    return -1;
  }
  if (state->row_count > 1) {
    err("wrong database format: row_count == %d", state->row_count);
    return -1;
  }

  if (!(state->row = mysql_fetch_row(state->res))) {
    err("wrong database format: no data");
    return -1;
  }
  state->lengths = mysql_fetch_lengths(state->res);
  if (strlen(state->row[0]) != state->lengths[0]) {
    err("wrong database format: version is binary data");
    return -1;
  }
  if (sscanf(state->row[0], "%d%n", &version, &n) != 1 || state->row[0][n]
      || version <= 0) {
    err("invalid 'version' key value");
    return -1;
  }
  // current version is 1, so cannot handle future version
  if (version > 1) {
    err("cannot handle database version %d", version);
    return -1;
  }

  // the current version is OK, no upgrade necessary

  return 1;
}

static int
create_func(void *data)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  path_t schema_path;
  FILE *fin = 0, *fstr = 0;
  char *cmdstr = 0;
  size_t cmdlen = 0;
  int c;
  char *buf = 0;
  size_t bufsize, buflen;

  if (!state->conn) return -1;

  if (state->schema_path) {
    snprintf(schema_path, sizeof(schema_path),
             "%s/mysql-create.sql", state->schema_path);
  } else {
    snprintf(schema_path, sizeof(schema_path),
             "%s/share/ejudge/mysql-create.sql", EJUDGE_PREFIX_DIR);
  }

  if (!(fin = fopen(schema_path, "r"))) {
    err("cannot open database schema file: %s", os_ErrorMsg());
    return -1;
  }

  while (1) {
    // skip whitespaces
    while ((c = getc(fin)) != EOF && isspace(c));
    if (c == EOF) break;

    // read up to ';' converting nonprintable into spaces
    if (!(fstr = open_memstream(&cmdstr, &cmdlen))) {
      err("open_memstream failed: %s", os_ErrorMsg());
      goto fail;
    }
    while (c != EOF && c != ';') {
      if (c >= 0 && c < ' ') c = ' ';
      putc(c, fstr);
      c = getc(fin);
    }
    fclose(fstr); fstr = 0;
    while (cmdlen > 0 && isspace(cmdstr[cmdlen - 1])) cmdstr[--cmdlen] = 0;
    if (!cmdlen) {
      err("empty command");
      goto fail;
    }
    bufsize = cmdlen * 2 + strlen(state->table_prefix) * 2 + 1;
    buf = (unsigned char*) xmalloc(bufsize);
    buflen = snprintf(buf, bufsize, cmdstr, state->table_prefix);

    fprintf(stderr, ">>%s\n", buf);

    if (mysql_real_query(state->conn, buf, buflen)) {
      err("database error: %s", mysql_error(state->conn));
      goto fail;
    }

    xfree(buf); buf = 0; bufsize = buflen = 0;
    xfree(cmdstr); cmdstr = 0; cmdlen = 0;

    if (c == EOF) break;
  }

  return 0;

 fail:
  if (fin) fclose(fin);
  if (fstr) fclose(fstr);
  xfree(cmdstr);
  xfree(buf);
  return -1;
}

static void
write_escaped_string(FILE *f, struct uldb_mysql_state *state,
                     const unsigned char *pfx,
                     const unsigned char *str)
{
  size_t len1, len2;
  unsigned char *str2;

  if (!str) {
    fprintf(f, "%sNULL", pfx);
    return;
  }

  len1 = strlen(str);
  len2 = 2 * len1 + 1;
  str2 = (unsigned char*) alloca(len2);
  mysql_real_escape_string(state->conn, str2, str, len1);
  fprintf(f, "%s'%s'", pfx, str2);
}

static void
write_timestamp(FILE *f, struct uldb_mysql_state *state,
                const unsigned char *pfx, time_t time)
{
  struct tm *ptm;

  if (time <= 0) {
    fprintf(f, "%sDEFAULT", pfx);
    return;
  }

  ptm = localtime(&time);
  fprintf(f, "%s'%04d-%02d-%02d %02d:%02d:%02d'",
          pfx, ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
          ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
}

static int
insert_member_info(struct uldb_mysql_state *state,
                   int user_id, int contest_id, int role,
                   const struct userlist_member *memb)
{
  char *cmdstr = 0;
  size_t cmdlen = 0;
  FILE *fcmd;

  if (!(fcmd = open_memstream(&cmdstr, &cmdlen))) {
    err("open_memstream failed: %s", os_ErrorMsg());
    goto fail;
  }

  fprintf(fcmd, "INSERT INTO %sparticipants VALUES ( ", state->table_prefix);
  if (memb->serial <= 0) {
    fprintf(fcmd, "DEFAULT");
  } else {
    fprintf(fcmd, "%d", memb->serial);
  }
  fprintf(fcmd, ", %d", memb->copied_from);
  fprintf(fcmd, ", %d, %d, %d", user_id, contest_id, role);
  write_timestamp(fcmd, state, ", ", memb->create_time);
  write_timestamp(fcmd, state, ", ", memb->last_change_time);
  write_escaped_string(fcmd, state, ", ", memb->firstname);
  write_escaped_string(fcmd, state, ", ", memb->firstname_en);
  write_escaped_string(fcmd, state, ", ", memb->middlename);
  write_escaped_string(fcmd, state, ", ", memb->middlename_en);
  write_escaped_string(fcmd, state, ", ", memb->surname);
  write_escaped_string(fcmd, state, ", ", memb->surname_en);
  fprintf(fcmd, ", %d", memb->status);
  fprintf(fcmd, ", %d", memb->grade);
  write_escaped_string(fcmd, state, ", ", memb->group);
  write_escaped_string(fcmd, state, ", ", memb->group_en);
  write_escaped_string(fcmd, state, ", ", memb->occupation);
  write_escaped_string(fcmd, state, ", ", memb->occupation_en);
  write_escaped_string(fcmd, state, ", ", memb->email);
  write_escaped_string(fcmd, state, ", ", memb->homepage);
  write_escaped_string(fcmd, state, ", ", memb->phone);
  write_escaped_string(fcmd, state, ", ", memb->inst);
  write_escaped_string(fcmd, state, ", ", memb->inst_en);
  write_escaped_string(fcmd, state, ", ", memb->instshort);
  write_escaped_string(fcmd, state, ", ", memb->instshort_en);
  write_escaped_string(fcmd, state, ", ", memb->fac);
  write_escaped_string(fcmd, state, ", ", memb->fac_en);
  write_escaped_string(fcmd, state, ", ", memb->facshort);
  write_escaped_string(fcmd, state, ", ", memb->facshort_en);
  fprintf(fcmd, " )");
  fclose(fcmd); fcmd = 0;

  fprintf(stderr, ">>%s\n", cmdstr);

  if (mysql_real_query(state->conn, cmdstr, cmdlen)) {
    err("database error: %s", mysql_error(state->conn));
    goto fail;
  }

  xfree(cmdstr); cmdstr = 0; cmdlen = 0;
  return 0;

 fail:
  if (fcmd) fclose(fcmd);
  xfree(cmdstr);
  return -1;
}

static int
insert_contest_info(struct uldb_mysql_state *state, 
                    int user_id, int contest_id, int force_fill,
                    const struct userlist_user_info *info)
{
  char *cmdstr = 0;
  size_t cmdlen = 0;
  FILE *fcmd;
  int role, i;
  struct userlist_members *membs;
  struct userlist_member *mm;

  if (!info->filled && !force_fill) return 0;

  if (!(fcmd = open_memstream(&cmdstr, &cmdlen))) {
    err("open_memstream failed: %s", os_ErrorMsg());
    goto fail;
  }

  fprintf(fcmd, "INSERT INTO %susers VALUES ( ", state->table_prefix);
  fprintf(fcmd, "%d, %d", user_id, contest_id);

  fprintf(fcmd, ", %d", info->cnts_read_only);
  write_escaped_string(fcmd, state, ", ", info->name);
  // pwdmethod: 0 - plain, 1 - base64 (not used), 2 - sha1
  // team_passwd
  if (info->team_passwd) {
    fprintf(fcmd, ", %d", info->team_passwd_method);
    write_escaped_string(fcmd, state, ", ", info->team_passwd);
    write_timestamp(fcmd, state, ", ", info->last_pwdchange_time);
  } else {
    fprintf(fcmd, ", 0, NULL, 0");
  }
  write_timestamp(fcmd, state, ", ", info->create_time);
  write_timestamp(fcmd, state, ", ", info->last_change_time);
  write_escaped_string(fcmd, state, ", ", info->inst);
  write_escaped_string(fcmd, state, ", ", info->inst_en);
  write_escaped_string(fcmd, state, ", ", info->instshort);
  write_escaped_string(fcmd, state, ", ", info->instshort_en);
  write_escaped_string(fcmd, state, ", ", info->fac);
  write_escaped_string(fcmd, state, ", ", info->fac_en);
  write_escaped_string(fcmd, state, ", ", info->facshort);
  write_escaped_string(fcmd, state, ", ", info->facshort_en);
  write_escaped_string(fcmd, state, ", ", info->homepage);
  write_escaped_string(fcmd, state, ", ", info->phone);
  write_escaped_string(fcmd, state, ", ", info->city);
  write_escaped_string(fcmd, state, ", ", info->city_en);
  write_escaped_string(fcmd, state, ", ", info->country);
  write_escaped_string(fcmd, state, ", ", info->country_en);
  write_escaped_string(fcmd, state, ", ", info->location);
  write_escaped_string(fcmd, state, ", ", info->spelling);
  write_escaped_string(fcmd, state, ", ", info->printer_name);
  write_escaped_string(fcmd, state, ", ", info->languages);
  fprintf(fcmd, " )");
  fclose(fcmd); fcmd = 0;

  fprintf(stderr, ">>%s\n", cmdstr);

  if (mysql_real_query(state->conn, cmdstr, cmdlen)) {
    err("database error: %s", mysql_error(state->conn));
    goto fail;
  }

  xfree(cmdstr); cmdstr = 0; cmdlen = 0;

  for (role = 0; role < USERLIST_MB_LAST; role++) {
    if (!(membs = info->members[role])) continue;
    for (i = 0; i < membs->total; i++) {
      if (!(mm = membs->members[i])) continue;
      if (insert_member_info(state, user_id, contest_id, role, mm) < 0)
        goto fail;
    }
  }

  return 0;

 fail:
  if (fcmd) fclose(fcmd);
  xfree(cmdstr);
  return -1;
}

static int
insert_contest(struct uldb_mysql_state *state, int user_id, 
               struct userlist_contest *c)
{
  char *cmdstr = 0;
  size_t cmdlen = 0;
  FILE *fcmd;

  if (!(fcmd = open_memstream(&cmdstr, &cmdlen))) {
    err("open_memstream failed: %s", os_ErrorMsg());
    goto fail;
  }

  fprintf(fcmd, "INSERT INTO %scntsregs VALUES ( ", state->table_prefix);
  fprintf(fcmd, "%d, %d, %d", user_id, c->id, c->status);
  fprintf(fcmd, ", %d", !!(c->flags & USERLIST_UC_BANNED));
  fprintf(fcmd, ", %d", !!(c->flags & USERLIST_UC_INVISIBLE));
  fprintf(fcmd, ", %d", !!(c->flags & USERLIST_UC_LOCKED));
  write_timestamp(fcmd, state, ", ", c->date);
  fprintf(fcmd, ", 0");         /* changetime not available */
  fprintf(fcmd, " )");
  fclose(fcmd); fcmd = 0;

  fprintf(stderr, ">>%s\n", cmdstr);

  if (mysql_real_query(state->conn, cmdstr, cmdlen)) {
    err("database error: %s", mysql_error(state->conn));
    goto fail;
  }

  xfree(cmdstr); cmdstr = 0; cmdlen = 0;
  return 0;

 fail:
  if (fcmd) fclose(fcmd);
  xfree(cmdstr);
  return -1;
}

static int
insert_cookie(struct uldb_mysql_state *state, int user_id, 
              struct userlist_cookie *c)
{
  char *cmdstr = 0;
  size_t cmdlen = 0;
  FILE *fcmd;

  if (!(fcmd = open_memstream(&cmdstr, &cmdlen))) {
    err("open_memstream failed: %s", os_ErrorMsg());
    goto fail;
  }

  fprintf(fcmd, "INSERT INTO %scookies VALUES ( ", state->table_prefix);
  fprintf(fcmd, "%lld, %d, %d, 4, %d, %d", c->cookie, user_id, c->priv_level,
          c->locale_id, c->contest_id);
  fprintf(fcmd, ", '%s'", xml_unparse_ip(c->ip));
  fprintf(fcmd, ", %d", c->ssl);
  write_timestamp(fcmd, state, ", ", c->expire);
  fprintf(fcmd, " )");
  fclose(fcmd); fcmd = 0;

  fprintf(stderr, ">>%s\n", cmdstr);

  if (mysql_real_query(state->conn, cmdstr, cmdlen)) {
    err("database error: %s", mysql_error(state->conn));
    goto fail;
  }

  xfree(cmdstr); cmdstr = 0; cmdlen = 0;
  return 0;

 fail:
  if (fcmd) fclose(fcmd);
  xfree(cmdstr);
  return -1;
}

static int
insert_func(void *data, const struct userlist_user *user)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmdstr = 0;
  size_t cmdlen = 0;
  FILE *fcmd;
  int contest_id;
  struct userlist_cntsinfo *cntsinfo;
  struct xml_tree *p;

  if (!(fcmd = open_memstream(&cmdstr, &cmdlen))) {
    err("open_memstream failed: %s", os_ErrorMsg());
    goto fail;
  }

  fprintf(fcmd, "INSERT INTO %slogins VALUES ( ", state->table_prefix);

  // id
  fprintf(fcmd, "%d", user->id);
  // login
  if (!user->login || !*user->login) {
    err("login is empty");
    goto fail;
  }
  write_escaped_string(fcmd, state, ", ", user->login);
  // email
  write_escaped_string(fcmd, state, ", ", user->email);
  // pwdmethod: 0 - plain, 1 - base64 (not used), 2 - sha1
  // register_passwd
  if (user->passwd) {
    fprintf(fcmd, ", %d", user->passwd_method);
    write_escaped_string(fcmd, state, ", ", user->passwd);
  } else {
    fprintf(fcmd, ", 0, NULL");
  }
  fprintf(fcmd, ", %d", user->is_privileged);
  fprintf(fcmd, ", %d", user->is_invisible);
  fprintf(fcmd, ", %d", user->is_banned);
  fprintf(fcmd, ", %d", user->is_locked);
  fprintf(fcmd, ", %d", user->read_only);
  fprintf(fcmd, ", %d", user->never_clean);
  fprintf(fcmd, ", %d", user->simple_registration);
  write_timestamp(fcmd, state, ", ", user->registration_time);
  write_timestamp(fcmd, state, ", ", user->last_login_time);
  write_timestamp(fcmd, state, ", ", user->last_pwdchange_time);
  write_timestamp(fcmd, state, ", ", user->last_change_time);

  /* unhandled fields
  time_t last_minor_change_time;
  time_t last_access_time;
  */

  fprintf(fcmd, " )");
  fclose(fcmd); fcmd = 0;

  fprintf(stderr, ">>%s\n", cmdstr);

  if (mysql_real_query(state->conn, cmdstr, cmdlen)) {
    err("database error: %s", mysql_error(state->conn));
    goto fail;
  }

  xfree(cmdstr); cmdstr = 0; cmdlen = 0;

  if (insert_contest_info(state, user->id, 0, user->i.filled, &user->i) < 0)
    goto fail;

  for (contest_id = 1; contest_id < user->cntsinfo_a; contest_id++) {
    if (!(cntsinfo = user->cntsinfo[contest_id])) continue;
    if (insert_contest_info(state, user->id, contest_id, 1, &cntsinfo->i) < 0)
      goto fail;
  }

  if (user->cookies) {
    for (p = user->cookies->first_down; p; p = p->right) {
      if (insert_cookie(state, user->id, (struct userlist_cookie*) p) < 0)
        goto fail;
    }
  }

  if (user->contests) {
    for (p = user->contests->first_down; p; p = p->right) {
      if (insert_contest(state, user->id, (struct userlist_contest*) p) < 0)
        goto fail;
    }
  }

  return 0;

 fail:
  if (fcmd) fclose(fcmd);
  xfree(cmdstr);
  return -1;
}

struct mysql_parse_spec
{
  unsigned char null_allowed;
  unsigned char format;
  const unsigned char *name;
  size_t offset;
  int (*handle_func)();
};

static int
handle_parse_spec(struct uldb_mysql_state *state,
                  int spec_num,
                  const struct mysql_parse_spec *specs,
                  void *data, ...)
{
  int i, x, n, d_year, d_mon, d_day, d_hour, d_min, d_sec;
  va_list args;
  int *p_int;
  unsigned char **p_str;
  struct tm tt;
  time_t t;
  time_t *p_time;

  if (state->field_count != spec_num) {
    err("wrong field_count (%d instead of %d). invalid table format?",
        state->field_count, spec_num);
    return -1;
  }

  // check non-null and binary data
  for (i = 0; i < spec_num; i++) {
    if (!specs[i].null_allowed && !state->row[i]) {
      err("column %d (%s) cannot be NULL", i, specs[i].name);
      return -1;
    }
    if (state->row[i] && strlen(state->row[i]) != state->lengths[i]) {
      err("column %d (%s) cannot be binary", i, specs[i].name);
      return -1;
    }
  }

  // parse data
  va_start(args, data);
  for (i = 0; i < spec_num; i++) {
    switch (specs[i].format) {
    case 0: break;
    case 'd':
      if (sscanf(state->row[i], "%d%n", &x, &n) != 1 || state->row[i][n])
        goto invalid_format;
      p_int = XPDEREF(int, data, specs[i].offset);
      *p_int = x;
      break;
    case 'D':
      if (sscanf(state->row[i], "%d%n", &x, &n) != 1 || state->row[i][n])
        goto invalid_format;
      p_int = va_arg(args, int*);
      *p_int = x;
      break;
    case 'b':
      if (sscanf(state->row[i], "%d%n", &x, &n) != 1 || state->row[i][n])
        goto invalid_format;
      if (x != 0 && x != 1) goto invalid_format;
      p_int = XPDEREF(int, data, specs[i].offset);
      *p_int = x;
      break;
    case 's':
      if (state->row[i]) {
        p_str = XPDEREF(unsigned char *, data, specs[i].offset);
        *p_str = xstrdup(state->row[i]);
      }
      break;
    case 't':
      if (!state->row[i]) break;
      // special handling for '0' case
      if (sscanf(state->row[i], "%d%n", &x, &n) == 1 && !state->row[i][n])
        break;
      // 'YYYY-MM-DD hh:mm:ss'
      if (sscanf(state->row[i], "%d-%d-%d %d:%d:%d%n",
                 &d_year, &d_mon, &d_day, &d_hour, &d_min, &d_sec, &n) != 6
          || state->row[i][n])
        goto invalid_format;
      memset(&tt, 0, sizeof(tt));
      tt.tm_year = d_year - 1900;
      tt.tm_mon = d_mon - 1;
      tt.tm_mday = d_day;
      tt.tm_hour = d_hour;
      tt.tm_min = d_min;
      tt.tm_sec = d_sec;
      tt.tm_isdst = -1;
      if ((t = mktime(&tt)) == (time_t) -1) goto invalid_format;
      p_time = XPDEREF(time_t, data, specs[i].offset);
      *p_time = t;
      break;

    default:
      err("unhandled format %d", specs[i].format);
      abort();

    invalid_format:
      err("column %d (%s) format is invalid", i, specs[i].name);
      break;
    }
  }
  va_end(args);
  return 0;
}

/* logins - > struct userlist_user specification */
#define USER_OFFSET(f) XOFFSET(struct userlist_user, f)
static struct mysql_parse_spec logins_spec[16] =
{
  { 0, 'd', "id", USER_OFFSET(id) },
  { 0, 's', "login", USER_OFFSET(login) },
  { 1, 's', "email", USER_OFFSET(email) },
  { 0, 'D', "pwdmethod", 0 },
  { 0, 0, "password", 0 },
  { 0, 'b', "privileged", USER_OFFSET(is_privileged) },
  { 0, 'b', "invisible", USER_OFFSET(is_invisible) },
  { 0, 'b', "banned", USER_OFFSET(is_banned) },
  { 0, 'b', "locked", USER_OFFSET(is_locked) },
  { 0, 'b', "readonly", USER_OFFSET(read_only) },
  { 0, 'b', "neverclean", USER_OFFSET(never_clean) },
  { 0, 'b', "simplereg", USER_OFFSET(simple_registration) },
  { 0, 't', "regtime", USER_OFFSET(registration_time) },
  { 0, 't', "logintime", USER_OFFSET(last_login_time) },
  { 0, 't', "pwdtime", USER_OFFSET(last_pwdchange_time) },
  { 0, 't', "changetime", USER_OFFSET(last_change_time) },
};

static int
get_full_func(void *data, int user_id, const struct userlist_user **p_user)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char cmdstr[512];
  int cmdlen;
  struct userlist_user *u = 0;
  int passwd_method;

  // fetch main user info
  cmdlen = snprintf(cmdstr, sizeof(cmdstr),
                    "SELECT * FROM %slogins WHERE id = %d",
                    state->table_prefix, user_id);

  if (mysql_real_query(state->conn, cmdstr, cmdlen)) {
    err("database error: %s", mysql_error(state->conn));
    goto fail;
  }

  if((state->field_count = mysql_field_count(state->conn)) != 16) {
    err("wrong database format: field_count == %d, must be 16",
        state->field_count);
    goto fail;
  }
  if (!(state->res = mysql_store_result(state->conn))) {
    err("database error: %s", mysql_error(state->conn));
    goto fail;
  }
  if (!(state->row_count = mysql_num_rows(state->res))) {
    // no such user
    if (p_user) *p_user = 0;
    return 0;
  }
  if (state->row_count > 1) {
    err("wrong database format: row_count == %d", state->row_count);
    return -1;
  }
  if (!(state->row = mysql_fetch_row(state->res))) {
    err("wrong database format: no data");
    return -1;
  }
  state->lengths = mysql_fetch_lengths(state->res);

  if (!p_user) {
    return 1;
  }

  u = (struct userlist_user*) userlist_node_alloc(USERLIST_T_USER);
  u->b.tag = USERLIST_T_USER;

  if (handle_parse_spec(state, 16, logins_spec, u, &passwd_method) < 0)
    goto invalid_format;

  // post-parse checks
  if (u->id <= 0) goto invalid_format;
  if (!u->login) goto invalid_format;
  if (state->row[4]) {
    u->passwd_method = passwd_method;
    u->passwd = xstrdup(state->row[4]);
  }

  return 0;

 invalid_format:
  err("invalid table data");
  goto fail;

 fail:
  userlist_free(&u->b);
  return -1;
}

static int
close_func(void *data)
{
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make -C ../.."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "MYSQL")
 * End:
 */
