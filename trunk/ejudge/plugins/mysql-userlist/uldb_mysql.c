/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2008 Alexander Chernov <cher@ejudge.ru> */

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
#include "ej_limits.h"
#include "errlog.h"
#include "uldb_plugin.h"
#include "xml_utils.h"
#include "expat_iface.h"
#include "ejudge_cfg.h"
#include "pathutl.h"
#include "userlist.h"
#include "list_ops.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <mysql.h>

#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>

static void *init_func(const struct ejudge_cfg *);
static int parse_func(void *, const struct ejudge_cfg *,struct xml_tree *);
static int open_func(void *data);
static int close_func(void *data);
static int check_func(void *data);
static int create_func(void *data);
static int insert_func(void *data, const struct userlist_user *user, int *p_member_serial);
static int get_full_func(void *data, int user_id,
                         const struct userlist_user **user);
static int_iterator_t get_user_id_iterator_func(void *data);
static int get_user_by_login_func(void *data, const unsigned char *login);
static void sync_func(void *);
static void forced_sync_func(void *);
static unsigned char *get_login_func(void *data, int user_id);
static int new_user_func(void *data, const unsigned char *login,
                         const unsigned char *email,
                         const unsigned char *passwd,
                         int simple_reg_flag);
static int remove_user_func(void *data, int user_id);
static int get_cookie_func(void *data,
                           ej_cookie_t value,
                           const struct userlist_cookie **p_cookie);
static int new_cookie_func(void *, int user_id,
                           ej_ip_t ip, int ssl_flag,
                           ej_cookie_t cookie, time_t,
                           int contest_id,
                           int locale_id,
                           int priv_level,
                           int role, int recovery, int team_login,
                           const struct userlist_cookie **);
static int remove_cookie_func(void *data,
                              const struct userlist_cookie *c);
static int remove_user_cookies_func(void *data, int user_id);
static int remove_expired_cookies_func(void *data, time_t cur_time);
static ptr_iterator_t get_user_contest_iterator_func(void *data, int user_id);
static int remove_expired_users_func(void *data, time_t min_reg_time);
static int get_user_info_1_func(void *data, int user_id,
                                const struct userlist_user **p_user);
static int get_user_info_2_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_u,
        const struct userlist_user_info **p_ui);

/* plugin entry point */
struct uldb_plugin_iface plugin_uldb_mysql =
{
  {
    sizeof (struct uldb_plugin_iface),
    EJUDGE_PLUGIN_IFACE_VERSION,
    "uldb",
    "mysql",
  },
  ULDB_PLUGIN_IFACE_VERSION,

  // initialize the plugin
  init_func,
  // parse the configuration settings
  parse_func,
  // open the database
  open_func,
  // close the database flushing all the data, if necessary
  close_func,
  // check the database, probably upgrading it to the current version
  check_func,
  // create a new database
  create_func,
  // insert a whole user record; used only during the database conversion
  insert_func,
  // get the whole user record; used only during the database conversion
  get_full_func,
  // get the user_id iterator
  get_user_id_iterator_func,
  // get the user_id by login
  get_user_by_login_func,
  // mark the database for syncing, if necessary
  sync_func,
  // force syncing
  forced_sync_func,
  // get login by the user_id, login allocated on heap
  get_login_func,
  // create a new user
  new_user_func,
  // remove a user
  remove_user_func,
  // find a cookie
  get_cookie_func,
  // create a new cookie
  new_cookie_func,
  // remove a cookie
  remove_cookie_func,
  // remove all user's cookies
  remove_user_cookies_func,
  // remove expired cookies
  remove_expired_cookies_func,
  // get an iterator over the user's contests
  get_user_contest_iterator_func,
  // remove expired users
  remove_expired_users_func,
  // get the login user info
  get_user_info_1_func,
  // get the login user info
  get_user_info_2_func,

  /*
  // set the login time
  int (*touch_login_time)(void *, int, int, time_t);
  // get the login, basic contest-specific user info, and registration
  int (*get_user_info_3)(void *, int, int, const struct userlist_user **, const struct userlist_user_info **, const struct userlist_contest **);
  // change the contest_id for the cookie
  int (*set_cookie_contest)(void *, const struct userlist_cookie *, int);
  // change the locale of the cookie
  int (*set_cookie_locale)(void *, const struct userlist_cookie *, int);
  // change the privilege level of the cookie
  int (*set_cookie_priv_level)(void *, const struct userlist_cookie *, int);
  // get the login, basic contest-specific user info, and registration
  // merged into one structure for further retrieval by unparse
  int (*get_user_info_4)(void *, int, int, const struct userlist_user **);
  // get the all the information about a user for privileged
  // get user information
  int (*get_user_info_5)(void *, int, int, const struct userlist_user **);
  // get an iterator for extracting brief user info (general or contest)
  // iterator iterates over all users
  ptr_iterator_t (*get_brief_list_iterator)(void *, int);
  // get an iterator for standings XML userlist
  ptr_iterator_t (*get_standings_list_iterator)(void *, int);
  // check, that user exists (0 - yes, -1 - no)
  int (*check_user)(void *, int);
  // set the registration password
  int (*set_reg_passwd)(void *, int, int, const unsigned char *, time_t);
  // set the team password
  int (*set_team_passwd)(void *, int, int, int, const unsigned char *, time_t, int *);
  // register a user for contest
  int (*register_contest)(void *, int, int, int, time_t, const struct userlist_contest**);
  // remove a particular member from a user
  int (*remove_member)(void *, int, int, int, time_t, int *);
  // check if the user is read-only
  int (*is_read_only)(void *, int, int);
  // get the user iterator for HTML user info requests
  // userlist_user, userlist_user_info, userlist_member, userlist_contest
  // fields are filled up
  ptr_iterator_t (*get_info_list_iterator)(void *, int, unsigned int);
  // clear the team password
  int (*clear_team_passwd)(void *, int, int, int *);
  // remove a contest registration
  int (*remove_registration)(void *, int, int);
  // set the registration status
  int (*set_reg_status)(void *, int, int, int);
  // set the registration flags
  int (*set_reg_flags)(void *, int, int, int, unsigned int);
  // remove user contest-specific info
  int (*remove_user_contest_info)(void *, int, int);
  // clear the main user info field
  int (*clear_user_field)(void *, int, int, time_t);
  // clear the user_info field
  int (*clear_user_info_field)(void *, int, int, int, time_t, int *);
  // clear the member field
  int (*clear_user_member_field)(void *, int, int, int, int, time_t, int *);
  // set the main user info field
  int (*set_user_field)(void *, int, int, const unsigned char *, time_t);
  // set the user contest-specific info field
  int (*set_user_info_field)(void *, int, int, int, const unsigned char *, time_t, int *);
  // set the user member field
  int (*set_user_member_field)(void *, int, int, int, int, const unsigned char *, time_t, int *);
  // create new member
  int (*new_member)(void *, int, int, int, time_t, int *);
  // maintenance operations
  int (*maintenance)(void *, time_t);
  // change the role of the existing member
  int (*change_member_role)(void *, int, int, int, int, time_t, int *);
  // set the user fields by its XML
  int (*set_user_xml)(void *, int, int, struct userlist_user *,
                      time_t, int *);
  // copy contest-specific user info to another contest
  int (*copy_user_info)(void *, int, int, int, time_t,
                        const struct contest_desc *);
  int (*check_user_reg_data)(void *, int, int);
  // move a particular member to a different role
  int (*move_member)(void *, int, int, int, int, time_t, int *);
  // change the team_login flag of the cookie
  int (*set_cookie_team_login)(void *, const struct userlist_cookie *, int);
  // get the login, basic contest-specific user info, registration
  // and member information
  int (*get_user_info_6)(void *, int, int, const struct userlist_user **, const struct userlist_user_info **, const struct userlist_contest **, const struct userlist_members **);
  // get the login, basic contest-specific user info, and member info
  int (*get_user_info_7)(void *, int, int, const struct userlist_user **, const struct userlist_user_info **, const struct userlist_members **);
  // get the member serial number
  int (*get_member_serial)(void *);
  */
};

// the size of the cookies pool, must be power of 2
enum { COOKIES_POOL_SIZE = 1024 };
enum { COOKIES_MAX_HASH_SIZE = 600 };

// the size of the cntsregs pool
enum { CNTSREGS_POOL_SIZE = 1024 };

// the size of the users pool
enum { USERS_POOL_SIZE = 1024 };

// the size of the user info pool
enum { USER_INFO_POOL_SIZE = 1024 };

// the size of the member pool
enum { MEMBERS_POOL_SIZE = 1024 };

struct cookies_cache
{
  struct userlist_cookie *hash[COOKIES_POOL_SIZE];
  struct xml_tree *first, *last;
  int count;
};

struct cntsregs_container;
struct cntsregs_user;

struct cntsregs_cache
{
  int size, count;
  struct cntsregs_user *user_map;
  struct cntsregs_container *first, *last;
};

struct users_cache
{
  int size, count;
  struct xml_tree *first, *last;
  struct userlist_user **user_map;
};

struct user_info_container;
struct user_info_user;

struct user_info_cache
{
  int size, count;
  struct user_info_user *user_map;
  struct user_info_container *first, *last;
};

struct members_container;
struct members_user;

struct members_cache
{
  int size;                     /* size of the user map */
  int count;                    /* the total count of entries in cache */
  struct members_user *user_map;
  struct members_container *first, *last;
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
  unsigned char *charset;
  unsigned char *collation;

  MYSQL *conn;
  MYSQL_RES *res;
  MYSQL_ROW row;
  unsigned long *lengths;
  int row_count;
  int field_count;

  // cookies cache
  struct cookies_cache cookies;

  // cntsregs cache
  struct cntsregs_cache cntsregs;

  // users cache
  struct users_cache users;

  // user_info cache
  struct user_info_cache user_infos;

  // members cache
  struct members_cache members;
};

struct user_id_iterator
{
  struct int_iterator b;

  struct uldb_mysql_state *state;
  int *ids;
  int id_num;
  int cur_i;
};
struct user_contest_iterator
{
  struct ptr_iterator b;

  struct uldb_mysql_state *state;
  int user_id;
  int *ids;
  int id_num;
  int cur_i;
};

#include "protos.inc.c"

static int
db_error(struct uldb_mysql_state *state)
{
  err("database error: %s", mysql_error(state->conn));
  return -1;
}
#define db_error_fail(s) do { db_error(s); goto fail; } while (0)

static void
db_wrong_field_count(struct uldb_mysql_state *state, int cnt)
{
  err("wrong database format: field_count == %d, must be %d",
      state->field_count, cnt);
}
#define db_wrong_field_count_fail(s, c) do { db_wrong_field_count(s, c); goto fail; } while (0)

/*
static void
db_wrong_row_count(struct uldb_mysql_state *state, int cnt)
{
  err("wrong database format: row_count == %d, must be %d",
      state->row_count, cnt);
}
#define db_wrong_row_count_fail(s, c) do { db_wrong_row_count(s, c); goto fail; } while (0)
*/

static void
db_no_data(void)
{
  err("database error: no data");
}
#define db_no_data_fail() do { db_no_data(); goto fail; } while (0)

static void
db_inv_value(void)
{
  err("database error: invalid value");
}
#define db_inv_value_fail() do { db_inv_value(); goto fail; } while (0)

static int
parse_int(const unsigned char *str, int *p_val)
{
  char *eptr;
  int val;

  if (!str) return -1;
  errno = 0;
  val = strtol(str, &eptr, 10);
  if (*eptr || errno) return -1;
  *p_val = val;
  return 0;
}

static void*
init_func(const struct ejudge_cfg *config)
{
  struct uldb_mysql_state *state;

  XCALLOC(state, 1);
  return (void*) state;
}

static const unsigned char *charset_mappings[][2] =
{
  { "utf-8", "utf8" },
  { "koi8-r", "koi8r" },

  { 0, 0 },
};

static int
parse_func(void *data, const struct ejudge_cfg *config, struct xml_tree *tree)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct xml_tree *p;
  int i;
  const unsigned char *cs = 0;

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
    } else if (!strcmp(p->name[0], "charset")) {
      if (xml_leaf_elem(p, &state->charset, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "collation")) {
      if (xml_leaf_elem(p, &state->collation, 1, 0) < 0) return -1;
    } else {
      return xml_err_elem_not_allowed(p);
    }
  }

  if (!state->user) return xml_err_elem_undefined_s(tree, "user");
  if (!state->password) return xml_err_elem_undefined_s(tree, "password");
  if (!state->database) return xml_err_elem_undefined_s(tree, "database");
  if (!state->table_prefix) state->table_prefix = xstrdup("");
  if (!state->charset) {
    if (config) cs = config->charset;
#if defined EJUDGE_CHARSET
    if (!cs) cs = EJUDGE_CHARSET;
#endif /* EJUDGE_CHARSET */
    // remap charset, since mysql has different charset names
    if (cs) {
      for (i = 0; charset_mappings[i][0]; i++) {
        if (!strcasecmp(charset_mappings[i][0], cs))
          state->charset = xstrdup(charset_mappings[i][1]);
      }
    }
  }

  return 0;
}

static int
open_func(void *data)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char cmdbuf[1024];
  int cmdlen;

  // already opened?
  if (state->conn) return 0;

  if (!(state->conn = mysql_init(0))) {
    err("mysql_init failed");
    return -1;
  }

  if (!mysql_real_connect(state->conn,
                          state->host, state->user, state->password,
                          state->database, state->port, state->socket, 0))
    return db_error(state);

  if (state->charset) {
    cmdlen = snprintf(cmdbuf, sizeof(cmdbuf), "SET NAMES '%s' ;\n",
                      state->charset);
    fprintf(stderr, ">%s\n", cmdbuf);
    if (mysql_real_query(state->conn, cmdbuf, cmdlen))
      return db_error(state);
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
    db_error(state);
    err("probably the database is not created. use --convert or --create");
    return 0;
  }

  if((state->field_count = mysql_field_count(state->conn)) != 1) {
    err("wrong database format: field_count == %d", state->field_count);
    return -1;
  }
  if (!(state->res = mysql_store_result(state->conn)))
    return db_error(state);

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
  unsigned char cmdbuf[1024];

  if (!state->conn) return -1;

  if (state->charset) {
    if (state->collation) {
      cmdlen = snprintf(cmdbuf, sizeof(cmdbuf), "ALTER DATABASE %s DEFAULT CHARACTER SET '%s' DEFAULT COLLATE '%s' ;\n", state->database, state->charset, state->collation);
    } else {
      cmdlen = snprintf(cmdbuf, sizeof(cmdbuf), "ALTER DATABASE %s DEFAULT CHARACTER SET '%s' ;\n", state->database, state->charset);
    }
    if (mysql_real_query(state->conn, cmdbuf, cmdlen))
      db_error_fail(state);
  }

  if (state->schema_path) {
    snprintf(schema_path, sizeof(schema_path),
             "%s/mysql-create.sql", state->schema_path);
  } else {
    snprintf(schema_path, sizeof(schema_path),
             "%s/share/ejudge/mysql-create.sql", EJUDGE_PREFIX_DIR);
  }

  if (!(fin = fopen(schema_path, "r"))) {
    err("cannot open database schema file: %s, %s", schema_path, os_ErrorMsg());
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

    if (mysql_real_query(state->conn, buf, buflen))
      db_error_fail(state);

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
insert_member_info(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id,
        const struct userlist_member *memb,
        int *p_serial)
{
  char *cmdstr = 0;
  size_t cmdlen = 0;
  FILE *fcmd;
  struct userlist_member newm;

  if (p_serial) {
    memcpy(&newm, memb, sizeof(newm));
    newm.serial = (*p_serial)++;
  }

  if (!(fcmd = open_memstream(&cmdstr, &cmdlen))) {
    err("open_memstream failed: %s", os_ErrorMsg());
    goto fail;
  }

  fprintf(fcmd, "INSERT INTO %smembers VALUES ( ", state->table_prefix);
  if (p_serial) {
    unparse_member(state, fcmd, user_id, contest_id, &newm);
  } else {
    unparse_member(state, fcmd, user_id, contest_id, memb);
  }
  fprintf(fcmd, " )");
  fclose(fcmd); fcmd = 0;

  fprintf(stderr, ">>%s\n", cmdstr);

  if (mysql_real_query(state->conn, cmdstr, cmdlen))
    db_error_fail(state);

  xfree(cmdstr); cmdstr = 0; cmdlen = 0;
  return 0;

 fail:
  if (fcmd) fclose(fcmd);
  xfree(cmdstr);
  return -1;
}

static int
insert_contest_info(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id,
        const struct userlist_user_info *info,
        int *p_serial)
{
  char *cmdstr = 0;
  size_t cmdlen = 0;
  FILE *fcmd;
  int i;

  if (!(fcmd = open_memstream(&cmdstr, &cmdlen))) {
    err("open_memstream failed: %s", os_ErrorMsg());
    goto fail;
  }

  fprintf(fcmd, "INSERT INTO %susers VALUES ( ", state->table_prefix);
  unparse_user_info(state, fcmd, user_id, contest_id, info);
  fprintf(fcmd, " )");
  fclose(fcmd); fcmd = 0;

  fprintf(stderr, ">>%s\n", cmdstr);

  if (mysql_real_query(state->conn, cmdstr, cmdlen))
    db_error_fail(state);

  xfree(cmdstr); cmdstr = 0; cmdlen = 0;

  if (!info->members) return 0;
  for (i = 0; i < info->members->u; i++)
    if (insert_member_info(state, user_id, contest_id,
                           info->members->m[i], p_serial) < 0)
      goto fail;

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
  unparse_cntsreg(state, fcmd, user_id, c);
  fprintf(fcmd, " )");
  fclose(fcmd); fcmd = 0;

  fprintf(stderr, ">>%s\n", cmdstr);

  if (mysql_real_query(state->conn, cmdstr, cmdlen))
    db_error_fail(state);

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
  unparse_cookie(state, fcmd, c);
  fprintf(fcmd, " )");
  fclose(fcmd); fcmd = 0;

  fprintf(stderr, ">>%s\n", cmdstr);

  if (mysql_real_query(state->conn, cmdstr, cmdlen))
    db_error_fail(state);

  xfree(cmdstr); cmdstr = 0; cmdlen = 0;
  return 0;

 fail:
  if (fcmd) fclose(fcmd);
  xfree(cmdstr);
  return -1;
}

static int
insert_func(void *data, const struct userlist_user *user, int *p_member_serial)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmdbuf = 0;
  size_t cmdlen = 0;
  FILE *fcmd;
  int contest_id;
  struct userlist_cntsinfo *cntsinfo;
  struct xml_tree *p;
  unsigned char *contest_set = 0;
  int max_contest_id;
  struct userlist_contest *uc;

  if (!(fcmd = open_memstream(&cmdbuf, &cmdlen))) {
    err("open_memstream failed: %s", os_ErrorMsg());
    goto fail;
  }

  fprintf(fcmd, "INSERT INTO %slogins VALUES ( ", state->table_prefix);
  unparse_login(state, fcmd, user);
  fprintf(fcmd, " );");
  fclose(fcmd); fcmd = 0;

  fprintf(stderr, ">>%s\n", cmdbuf);

  if (mysql_real_query(state->conn, cmdbuf, cmdlen))
    db_error_fail(state);

  xfree(cmdbuf); cmdbuf = 0; cmdlen = 0;

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

  if (!user->i.filled) {
    for (contest_id = 1; contest_id < user->cntsinfo_a; contest_id++) {
      if (!(cntsinfo = user->cntsinfo[contest_id])) continue;
      if (insert_contest_info(state, user->id, contest_id, &cntsinfo->i, 0) < 0)
        goto fail;
    }
    return 0;
  }

  // insert the existing contest info
  if (insert_contest_info(state, user->id, 0, &user->i, 0) < 0)
    goto fail;

  for (contest_id = 1; contest_id < user->cntsinfo_a; contest_id++) {
    if (!(cntsinfo = user->cntsinfo[contest_id])) continue;
    if (insert_contest_info(state, user->id, contest_id, &cntsinfo->i, 0) < 0)
      goto fail;
  }

  // collect the contests for which the user is registered
  max_contest_id = 0;
  if (user->contests) {
    for (p = user->contests->first_down; p; p = p->right) {
      uc = (struct userlist_contest*) p;
      if (uc->id > max_contest_id) max_contest_id = uc->id;
    }
  }
  if (!max_contest_id) return 0;

  XALLOCAZ(contest_set, max_contest_id + 1);
  for (p = user->contests->first_down; p; p = p->right) {
    uc = (struct userlist_contest*) p;
    if (uc->id > 0 && uc->id <= max_contest_id)
      contest_set[uc->id] = 1;
  }
  
  for (contest_id = 1;
       contest_id < user->cntsinfo_a && contest_id <= max_contest_id;
       contest_id++) {
    if (!(cntsinfo = user->cntsinfo[contest_id])) continue;
    contest_set[contest_id] = 0;
  }

  // now in contest_set we've got the contests need cloning
  for (contest_id = 1; contest_id <= max_contest_id; contest_id++) {
    if (!contest_set[contest_id]) continue;
    if (insert_contest_info(state, user->id, contest_id, &user->i,
                            p_member_serial) < 0)
      goto fail;
  }

  return 0;

 fail:
  if (fcmd) fclose(fcmd);
  xfree(cmdbuf);
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
  char *eptr;
  unsigned long long uq;
  unsigned long long *p_uq;
  ej_ip_t *p_ip;

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
    case 'q':
      errno = 0;
      eptr = 0;
      uq = strtoull(state->row[i], &eptr, 10);
      if (errno || *eptr) goto invalid_format;
      p_uq = XPDEREF(unsigned long long, data, specs[i].offset);
      *p_uq = uq;
      break;
      
    case 'd':
    case 'e':
      errno = 0;
      eptr = 0;
      x = strtol(state->row[i], &eptr, 10);
      if (errno || *eptr) goto invalid_format;
      p_int = XPDEREF(int, data, specs[i].offset);
      *p_int = x;
      break;
    case 'D':
      errno = 0;
      eptr = 0;
      x = strtol(state->row[i], &eptr, 10);
      if (errno || *eptr) goto invalid_format;
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
    case 'B':
      if (sscanf(state->row[i], "%d%n", &x, &n) != 1 || state->row[i][n])
        goto invalid_format;
      if (x != 0 && x != 1) goto invalid_format;
      p_int = va_arg(args, int*);
      *p_int = x;
      break;
    case 's':
      p_str = XPDEREF(unsigned char *, data, specs[i].offset);
      if (state->row[i]) {
        *p_str = xstrdup(state->row[i]);
      } else {
        *p_str = 0;
      }
      break;
    case 'S':
      p_str = va_arg(args, unsigned char **);
      if (state->row[i]) {
        *p_str = xstrdup(state->row[i]);
      } else {
        *p_str = 0;
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
      if (t < 0) t = 0;
      p_time = XPDEREF(time_t, data, specs[i].offset);
      *p_time = t;
      break;
    case 'i':
      p_ip = XPDEREF(ej_ip_t, data, specs[i].offset);
      if (xml_parse_ip(0, 0, 0, state->row[i], p_ip) < 0) goto invalid_format;
      break;

    default:
      err("unhandled format %d", specs[i].format);
      abort();

    invalid_format:
      err("column %d (%s) format is invalid", i, specs[i].name);
      va_end(args);
      return -1;
    }
  }
  va_end(args);
  return 0;
}

static void
handle_unparse_spec(
        struct uldb_mysql_state *state,
        FILE *fout,
        int spec_num,
        const struct mysql_parse_spec *specs,
        const void *data,
        ...)
{
  int i, val;
  va_list args;
  const unsigned char *sep = "";
  const unsigned char *str;
  unsigned char **p_str;
  const time_t *p_time;
  const int *p_int;
  const unsigned long long *p_uq;
  unsigned long long uq;
  ej_ip_t *p_ip;

  va_start(args, data);
  for (i = 0; i < spec_num; ++i) {
    switch (specs[i].format) {
    case 0: break;
    case 'q':
      p_uq = XPDEREF(unsigned long long, data, specs[i].offset);
      uq = *p_uq;
      fprintf(fout, "%s%llu", sep, uq);
      break;

    case 'e':
      p_int = XPDEREF(int, data, specs[i].offset);
      val = *p_int;
      if (val == -1) {
        fprintf(fout, "%sDEFAULT", sep);
      } else {
        fprintf(fout, "%s%d", sep, val);
      }
      break;

    case 'd':
      p_int = XPDEREF(int, data, specs[i].offset);
      val = *p_int;
      fprintf(fout, "%s%d", sep, val);
      break;

    case 'D':
      val = va_arg(args, int);
      fprintf(fout, "%s%d", sep, val);
      break;

    case 'b':
      p_int = XPDEREF(int, data, specs[i].offset);
      val = *p_int;
      if (val) val = 1;
      fprintf(fout, "%s%d", sep, val);
      break;

    case 'B':
      val = va_arg(args, int);
      if (val) val = 1;
      fprintf(fout, "%s%d", sep, val);
      break;

    case 's':
      p_str = XPDEREF(unsigned char *, data, specs[i].offset);
      write_escaped_string(fout, state, sep, *p_str);
      break;

    case 'S':
      str = va_arg(args, const unsigned char *);
      write_escaped_string(fout, state, sep, str);
      break;

    case 't':
      p_time = XPDEREF(time_t, data, specs[i].offset);
      write_timestamp(fout, state, sep, *p_time);
      break;

    case 'i':
      p_ip = XPDEREF(ej_ip_t, data, specs[i].offset);
      fprintf(fout, "%s%s", sep, xml_unparse_ip(*p_ip));
      break;

    default:
      err("unhandled format %d", specs[i].format);
      abort();
    }
    sep = ", ";
  }
  va_end(args);
}

#include "tables.inc.c"

#include "cookies.inc.c"
#include "cntsregs.inc.c"
#include "logins.inc.c"
#include "user_infos.inc.c"
#include "members.inc.c"

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
                    "SELECT * FROM %slogins WHERE user_id = %d",
                    state->table_prefix, user_id);

  if (mysql_real_query(state->conn, cmdstr, cmdlen))
    db_error_fail(state);

  if((state->field_count = mysql_field_count(state->conn)) != 16) {
    err("wrong database format: field_count == %d, must be 16",
        state->field_count);
    goto fail;
  }
  if (!(state->res = mysql_store_result(state->conn)))
    db_error_fail(state);
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

  if (parse_login(state, u) < 0) goto invalid_format;

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

static int
user_id_iterator_has_next(int_iterator_t data)
{
  struct user_id_iterator *iter = (struct user_id_iterator*) data;
  return iter->cur_i < iter->id_num;
}
static int
user_id_iterator_get(int_iterator_t data)
{
  struct user_id_iterator *iter = (struct user_id_iterator*) data;
  if (iter->cur_i < iter->id_num) return iter->ids[iter->cur_i];
  return -1;
}
static void
user_id_iterator_next(int_iterator_t data)
{
  struct user_id_iterator *iter = (struct user_id_iterator*) data;
  if (iter->cur_i < iter->id_num) iter->cur_i++;
}
static void
user_id_iterator_destroy(int_iterator_t data)
{
  struct user_id_iterator *iter = (struct user_id_iterator*) data;

  xfree(iter->ids);
  xfree(iter);
}

static struct int_iterator user_id_iterator_funcs =
{
  user_id_iterator_has_next,
  user_id_iterator_get,
  user_id_iterator_next,
  user_id_iterator_destroy,
};

static int_iterator_t
get_user_id_iterator_func(void *data)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct user_id_iterator *iter;
  unsigned char cmd[1024];
  int cmdlen, i, val;

  XCALLOC(iter, 1);
  iter->b = user_id_iterator_funcs;

  cmdlen = snprintf(cmd, sizeof(cmd),
                    "SELECT user_id FROM %slogins WHERE 1 ;",
                    state->table_prefix);
  if (mysql_real_query(state->conn, cmd, cmdlen))
    db_error_fail(state);

  if((state->field_count = mysql_field_count(state->conn)) != 1)
    db_wrong_field_count_fail(state, 1);
  if (!(state->res = mysql_store_result(state->conn)))
    db_error_fail(state);
  state->row_count = mysql_num_rows(state->res);
  iter->id_num = state->row_count;

  if (iter->id_num > 0) {
    XCALLOC(iter->ids, iter->id_num);
    for (i = 0; i < iter->id_num; i++) {
      if (!(state->row = mysql_fetch_row(state->res)))
        db_no_data_fail();
      state->lengths = mysql_fetch_lengths(state->res);
      if (!state->lengths[0])
        db_inv_value_fail();
      if (parse_int(state->row[0], &val) < 0 || val <= 0)
        db_inv_value_fail();
      iter->ids[i] = val;
    }
  }
  return (int_iterator_t) iter;

 fail:
  xfree(iter->ids);
  xfree(iter);
  return 0;
}

static int
one_row_request(
        struct uldb_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen,
        int colnum)
{
  if (mysql_real_query(state->conn, cmd, cmdlen))
    db_error_fail(state);
  if((state->field_count = mysql_field_count(state->conn)) != colnum)
    db_wrong_field_count_fail(state, colnum);
  if (!(state->res = mysql_store_result(state->conn)))
    db_error_fail(state);
  if ((state->row_count = mysql_num_rows(state->res)) != 1)
    goto fail;
    //db_wrong_row_count_fail(state, 1);
  if (!(state->row = mysql_fetch_row(state->res)))
    db_no_data_fail();
  state->lengths = mysql_fetch_lengths(state->res);
  return 0;

 fail:
  return -1;
}

static int
get_user_by_login_func(void *data, const unsigned char *login)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  size_t login_len;
  unsigned char *esc_str, *cmd;
  int cmdlen, val;

  login_len = strlen(login);
  esc_str = (unsigned char*) alloca(login_len * 2 + 1);
  cmdlen = login_len * 2 + 512;
  cmd = (unsigned char*) alloca(cmdlen);
  mysql_real_escape_string(state->conn, esc_str, login, login_len);
  cmdlen = snprintf(cmd, cmdlen,
                    "SELECT user_id FROM %slogins WHERE login = '%s' ; ",
                    state->table_prefix, esc_str);
  if (one_row_request(state, cmd, cmdlen, 1) < 0) goto fail;
  if (!state->lengths[0])
    db_inv_value_fail();
  if (parse_int(state->row[0], &val) < 0 || val <= 0)
    db_inv_value_fail();
  return val;

 fail:
  return -1;
}

static void
sync_func(void *data)
{
}

static void
forced_sync_func(void *data)
{
}

static unsigned char *
get_login_func(void *data, int user_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  int cmdlen;
  unsigned char cmd[1024];

  cmdlen = snprintf(cmd, sizeof(cmd),
                    "SELECT login FROM %slogins WHERE user_id = %d ; ",
                    state->table_prefix, user_id);
  if (one_row_request(state, cmd, cmdlen, 1) < 0) goto fail;
  if (!(state->row = mysql_fetch_row(state->res)))
    db_inv_value_fail();
  return xstrdup(state->row[0]);

 fail:
  return 0;
}

static int
new_user_func(
        void *data,
        const unsigned char *login,
        const unsigned char *email,
        const unsigned char *passwd,
        int simple_reg_flag)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char *login_arm, *email_arm = "NULL", *passwd_arm = "NULL", *cmd;
  size_t login_len, email_len = 0, passwd_len = 0, cmdlen;
  int val;

  if (!login || !*login) return -1;
  login_len = strlen(login);
  login_arm = (unsigned char *) alloca(login_len * 2 + 1);
  mysql_real_escape_string(state->conn, login_arm, login, login_len);

  if (email) {
    email_len = strlen(email);
    email_arm = (unsigned char*) alloca(email_len * 2 + 1);
    mysql_real_escape_string(state->conn, email_arm, email, email_len);
  }

  if (passwd) {
    passwd_len = strlen(passwd);
    passwd_arm = (unsigned char*) alloca(passwd_len * 2 + 1);
    mysql_real_escape_string(state->conn, passwd_arm, passwd, passwd_len);
  }

  simple_reg_flag = !!simple_reg_flag;

  cmdlen = 512 + login_len + email_len + passwd_len;
  cmd = (unsigned char*) alloca(cmdlen);
  cmdlen = snprintf(cmd, cmdlen, "INSERT into %slogins VALUES ( DEFAULT, '%s', '%s', 0, '%s', 0, 0, 0, 0, 0, 0, %d, DEFAULT, NULL, NULL, NULL ) ;", state->table_prefix, login_arm, email_arm, passwd_arm, simple_reg_flag);
  if (mysql_real_query(state->conn, cmd, cmdlen))
    db_error_fail(state);
  cmdlen = 512 + login_len + email_len + passwd_len;
  cmdlen = snprintf(cmd, cmdlen, "SELECT user_id FROM %slogins WHERE login = '%s' ;", state->table_prefix, login_arm);
  if (one_row_request(state, cmd, cmdlen, 1) < 0) goto fail;
  if (!state->lengths[0])
    db_inv_value_fail();
  if (parse_int(state->row[0], &val) < 0 || val <= 0)
    db_inv_value_fail();
  return val;

 fail:
  return -1;
}

static int
remove_user_func(void *data, int user_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char cmd[1024];
  int cmdlen;

  cmdlen = sizeof(cmd);
  cmdlen = snprintf(cmd, cmdlen, "DELETE FROM %scookies WHERE user_id = %d; DELETE FROM %scntsregs WHERE user_id = %d; DELETE FROM %smembers WHERE user_id = %d; DELETE FROM %susers WHERE user_id = %d; DELETE FROM %slogins WHERE user_id = %d;", state->table_prefix, user_id, state->table_prefix, user_id, state->table_prefix, user_id, state->table_prefix, user_id, state->table_prefix, user_id);
  mysql_real_query(state->conn, cmd, cmdlen);
  return 0;
}

static int
get_cookie_func(
        void *data,
        ej_cookie_t value,
        const struct userlist_cookie **p_cookie)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct userlist_cookie *c;

  if (fetch_cookie(state, value, &c) <= 0) return -1;
  if (p_cookie) *p_cookie = c;
  return 0;
}

static int
new_cookie_func(
        void *data,
        int user_id,
        ej_ip_t ip,
        int ssl_flag,
        ej_cookie_t cookie,
        time_t expire,
        int contest_id,
        int locale_id,
        int priv_level,
        int role,
        int recovery,
        int team_login,
        const struct userlist_cookie **p_cookie)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  FILE *fcmd = 0;
  char *ftxt = 0;
  size_t flen = 0;
  unsigned char cmd[1024];
  int cmdlen;
  struct userlist_cookie *c;

  fcmd = open_memstream(&ftxt, &flen);
  fprintf(fcmd, "INSERT INTO %scookies VALUES ( ", state->table_prefix);
  fprintf(fcmd, "%llu, %d, %d, %d, %d, %d, %d, %d, %d",
          cookie, user_id, contest_id,
          priv_level, role, 4 /*c->ipversion*/, locale_id,
          recovery, team_login);
  fprintf(fcmd, ", '%s'", xml_unparse_ip(ip));
  fprintf(fcmd, ", %d", ssl_flag);
  write_timestamp(fcmd, state, ", ", expire);
  fprintf(fcmd, " )");
  fclose(fcmd); fcmd = 0;
  if (mysql_real_query(state->conn, ftxt, flen))
    db_error_fail(state);
  cmdlen = sizeof(cmd);
  cmdlen = snprintf(cmd, cmdlen, "SELECT * FROM %scookies WHERE cookie = %llu ;",
                    state->table_prefix, cookie);
  if (one_row_request(state, cmd, cmdlen, COOKIE_WIDTH) < 0) goto fail;
  c = allocate_cookie_on_pool(state, cookie);
  if (parse_cookie(state, c) < 0) goto fail;
  if (p_cookie) *p_cookie = c;
  return 0;

 fail:
  if (fcmd) fclose(fcmd);
  xfree(ftxt);
  return -1;
}

static int
remove_cookie_func(
        void *data,
        const struct userlist_cookie *c)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char cmd[1024];
  int cmdlen;

  if (!c) return 0;

  cmdlen = sizeof(cmd);
  cmdlen = snprintf(cmd, cmdlen, "DELETE FROM %scookies WHERE cookie = %llu;", state->table_prefix, c->cookie);
  mysql_real_query(state->conn, cmd, cmdlen);
  return 0;
}

static int
remove_user_cookies_func(
        void *data,
        int user_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char cmd[1024];
  int cmdlen;

  cmdlen = sizeof(cmd);
  cmdlen = snprintf(cmd, cmdlen, "DELETE FROM %scookies WHERE user_id = %d;", state->table_prefix, user_id);
  mysql_real_query(state->conn, cmd, cmdlen);
  return 0;
}

static int
remove_expired_cookies_func(
        void *data,
        time_t cur_time)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  FILE *fcmd = 0;
  char *tcmd = 0;
  size_t lcmd = 0;

  if (cur_time <= 0) cur_time = time(0);

  fcmd = open_memstream(&tcmd, &lcmd);
  fprintf(fcmd, "DELETE FROM %scookies WHERE expire >= ",
          state->table_prefix);
  write_timestamp(fcmd, state, "", cur_time);
  fclose(fcmd); fcmd = 0;
  mysql_real_query(state->conn, tcmd, lcmd);
  xfree(tcmd);
  return 0;
}

static int
user_contest_iterator_has_next_func(ptr_iterator_t data)
{
  struct user_contest_iterator *iter = (struct user_contest_iterator *) data;
  return iter->cur_i < iter->id_num;
}
static const void *
user_contest_iterator_get_func(ptr_iterator_t data)
{
  struct user_contest_iterator *iter = (struct user_contest_iterator *) data;
  struct uldb_mysql_state *state = iter->state;
  unsigned char cmd[1024];
  int cmdlen = sizeof(cmd);
  struct userlist_contest *c = 0;

  if (iter->cur_i >= iter->id_num) return 0;
  cmdlen = snprintf(cmd, cmdlen, "SELECT * FROM %scntsregs WHERE user_id = %d AND contest_id = %d ;", state->table_prefix, iter->user_id, iter->ids[iter->cur_i]);
  if (one_row_request(state, cmd, cmdlen, COOKIE_WIDTH) < 0) return 0;
  c = allocate_cntsreg_on_pool(state, iter->user_id, iter->ids[iter->cur_i]);
  if (!c) return 0;
  if (parse_cntsreg(state, c) < 0) return 0;
  return (void*) c;
}
static void
user_contest_iterator_next_func(ptr_iterator_t data)
{
  struct user_contest_iterator *iter = (struct user_contest_iterator *) data;
  if (iter->cur_i < iter->id_num) iter->cur_i++;
}
static void
user_contest_iterator_destroy_func(ptr_iterator_t data)
{
  struct user_contest_iterator *iter = (struct user_contest_iterator *) data;
  xfree(iter->ids);
  xfree(iter);
}
static struct ptr_iterator user_contest_iterator_funcs =
{
  user_contest_iterator_has_next_func,
  user_contest_iterator_get_func,
  user_contest_iterator_next_func,
  user_contest_iterator_destroy_func,
};

static ptr_iterator_t
get_user_contest_iterator_func(
        void *data,
        int user_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct user_contest_iterator *iter = 0;
  int cmdlen, i, val;
  unsigned char cmd[1024];

  XCALLOC(iter, 1);
  iter->b = user_contest_iterator_funcs;
  iter->state = state;
  iter->user_id = user_id;

  cmdlen = sizeof(cmd);
  cmdlen = snprintf(cmd, cmdlen,
                    "SELECT contest_id FROM %scntsregs WHERE user_id = %d ;",
                    state->table_prefix, user_id);
  if (mysql_real_query(state->conn, cmd, cmdlen))
    db_error_fail(state);

  if((state->field_count = mysql_field_count(state->conn)) != 1)
    db_wrong_field_count_fail(state, 1);
  if (!(state->res = mysql_store_result(state->conn)))
    db_error_fail(state);
  state->row_count = mysql_num_rows(state->res);
  iter->id_num = state->row_count;

  if (iter->id_num > 0) {
    XCALLOC(iter->ids, iter->id_num);
    for (i = 0; i < iter->id_num; i++) {
      if (!(state->row = mysql_fetch_row(state->res)))
        db_no_data_fail();
      state->lengths = mysql_fetch_lengths(state->res);
      if (!state->lengths[0])
        db_inv_value_fail();
      if (parse_int(state->row[0], &val) < 0 || val <= 0)
        db_inv_value_fail();
      iter->ids[i] = val;
    }
  }
  return (ptr_iterator_t) iter;

 fail:
  xfree(iter->ids);
  xfree(iter);
  return 0;
}

static int
remove_expired_users_func(
        void *data,
        time_t min_reg_time)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *q_txt = 0;
  size_t q_len = 0;
  FILE *q_f = 0;
  int *ids = 0, i, val, count;

  if (min_reg_time <= 0) min_reg_time = time(0) - 24 * 60 * 60;

  q_f = open_memstream(&q_txt, &q_len);
  fprintf(q_f, "SELECT user_id FROM %slogins WHERE regtime < ", 
          state->table_prefix);
  write_timestamp(q_f, state, "", min_reg_time);
  fprintf(q_f, " AND (logintime = NULL OR logintime = 0) ;");
  fclose(q_f); q_f = 0;

  if (mysql_real_query(state->conn, q_txt, q_len))
    db_error_fail(state);

  if((state->field_count = mysql_field_count(state->conn)) != 1)
    db_wrong_field_count_fail(state, 1);
  if (!(state->res = mysql_store_result(state->conn)))
    db_error_fail(state);
  count = state->row_count = mysql_num_rows(state->res);
  if (!count) return 0;

  // save the result set into the temp array
  XCALLOC(ids, count);
  for (i = 0; i < count; i++) {
    if (!(state->row = mysql_fetch_row(state->res)))
      db_no_data_fail();
    state->lengths = mysql_fetch_lengths(state->res);
    if (!state->lengths[0])
      db_inv_value_fail();
    if (parse_int(state->row[0], &val) < 0 || val <= 0)
      db_inv_value_fail();
    ids[i] = val;
  }

  for (i = 0; i < count; i++) {
    remove_user_func(data, ids[i]);
  }

  return 0;

 fail:
  if (q_f) fclose(q_f);
  xfree(q_txt);
  xfree(ids);
  return -1;
}

static int
get_user_info_1_func(
        void *data,
        int user_id,
        const struct userlist_user **p_user)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char cmd[1024];
  int cmdlen = sizeof(cmd);
  struct userlist_user *u = 0;

  if (user_id <= 0) goto fail;

  cmdlen = snprintf(cmd, cmdlen, "SELECT * FROM %slogins WHERE user_id = %d ;",
                    state->table_prefix, user_id);
  if (one_row_request(state, cmd, cmdlen, LOGIN_WIDTH) < 0) return 0;
  if (!(u = allocate_login_on_pool(state, user_id))) return 0;
  if (parse_login(state, u) < 0) return 0;
  if (p_user) *p_user = u;
  return 1;

 fail:
  // free resources
  if (p_user) *p_user = 0;
  return -1;
}

static int
get_user_info_2_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_u,
        const struct userlist_user_info **p_ui)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct userlist_user_info *ii;

  ii = allocate_user_info_on_pool(state, user_id, contest_id);

  // lookup table for the specified user_id
  // lookup table for the specified user_id, contest_id
  // if not exist, insert a record

  abort();
}

/*
 * Local variables:
 *  compile-command: "make -C ../.."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "MYSQL")
 * End:
 */
