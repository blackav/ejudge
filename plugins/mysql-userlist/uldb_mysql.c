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
static int insert_func(void *data, const struct userlist_user *user);
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
  */
};

// the number of columns in `cookies' table
enum { COOKIES_WIDTH = 12 };
// the number of columns in `cntsregs' table
enum { CNTSREGS_WIDTH = 10 };
// the number of columns in `logins' table
enum { LOGINS_WIDTH = 16 };
// the number of columns in `users' table
enum { USER_INFO_WIDTH = 44 };

// the size of the cookies pool, must be power of 2
enum { COOKIES_POOL_SIZE = 1024 };
enum { COOKIES_MAX_HASH_SIZE = 600 };

// the size of the cntsregs pool
enum { CNTSREGS_POOL_SIZE = 1024 };

// the size of the users pool
enum { USERS_POOL_SIZE = 1024 };

// the size of the user info pool
enum { USER_INFO_POOL_SIZE = 1024 };

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
  int map_size, count;
  struct xml_tree *first, *last;
  struct userlist_user **map;
};

struct user_info_container;
struct user_info_user;

struct user_info_cache
{
  int size, count;
  struct user_info_user *user_map;
  struct user_info_container *first, *last;
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

  // cookies caching
  struct userlist_cookie *cookie_hash[COOKIES_POOL_SIZE];
  struct xml_tree *cookie_first, *cookie_last;
  int cookie_count;

  // cntsregs caching
  struct cntsregs_cache cntsregs;

  // users caching
  struct users_cache users;

  // user_info caching
  struct user_info_cache user_infos;
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

static int
parse_ullong(const unsigned char *str, unsigned long long *p_val)
{
  char *eptr;
  unsigned long long val;

  if (!str) return -1;
  errno = 0;
  val = strtoull(str, &eptr, 10);
  if (*eptr || errno) return -1;
  *p_val = val;
  return 0;
}

static int
parse_datetime(const unsigned char *str, time_t *p_val)
{
  int year, month, day, hour, min, sec, n;
  time_t t;
  struct tm tt;

  memset(&tt, 0, sizeof(tt));
  tt.tm_isdst = -1;
  if (!str) return -1;

  if (sscanf(str, "%d/%d/%d %d:%d:%d%n", &year, &month, &day, &hour,
             &min, &sec, &n) == 6 && !str[n]) return -1;
  if (year < 1900 || year > 2100 || month < 1 || month > 12
      || day < 1 || day > 31 || hour < 0 || hour >= 24
      || min < 0 || min >= 60 || sec < 0 || sec >= 60) return -1;
  tt.tm_sec = sec;
  tt.tm_min = min;
  tt.tm_hour = hour;
  tt.tm_mday = day;
  tt.tm_mon = month - 1;
  tt.tm_year = year - 1900;
  if ((t = mktime(&tt)) == (time_t) -1) return -1;
  if (p_val) *p_val = t;
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
  //fprintf(fcmd, ", %d", memb->copied_from);
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
  fprintf(fcmd, ", %d", memb->gender);
  fprintf(fcmd, ", %d", memb->grade);
  write_escaped_string(fcmd, state, ", ", memb->group);
  write_escaped_string(fcmd, state, ", ", memb->group_en);
  write_escaped_string(fcmd, state, ", ", memb->occupation);
  write_escaped_string(fcmd, state, ", ", memb->occupation_en);
  write_escaped_string(fcmd, state, ", ", memb->discipline);
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
  write_timestamp(fcmd, state, ", ", memb->birth_date);
  write_timestamp(fcmd, state, ", ", memb->entry_date);
  write_timestamp(fcmd, state, ", ", memb->graduation_date);
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
insert_contest_info(struct uldb_mysql_state *state, 
                    int user_id, int contest_id, int force_fill,
                    const struct userlist_user_info *info)
{
  char *cmdstr = 0;
  size_t cmdlen = 0;
  FILE *fcmd;
  int role, i, role_cnt;
  struct userlist_member *mm;

  if (!info->filled && !force_fill) return 0;

  if (!(fcmd = open_memstream(&cmdstr, &cmdlen))) {
    err("open_memstream failed: %s", os_ErrorMsg());
    goto fail;
  }

  fprintf(fcmd, "INSERT INTO %susers VALUES ( ", state->table_prefix);
  fprintf(fcmd, "%d, %d", user_id, contest_id);

  fprintf(fcmd, ", %d", info->cnts_read_only);
  if (info->instnum >= 0) {
    fprintf(fcmd, ", %d", info->instnum);
  } else {
    fprintf(fcmd, ", NULL");
  }
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
  write_escaped_string(fcmd, state, ", ", info->region);
  write_escaped_string(fcmd, state, ", ", info->area);
  write_escaped_string(fcmd, state, ", ", info->zip);
  write_escaped_string(fcmd, state, ", ", info->street);
  write_escaped_string(fcmd, state, ", ", info->country);
  write_escaped_string(fcmd, state, ", ", info->country_en);
  write_escaped_string(fcmd, state, ", ", info->location);
  write_escaped_string(fcmd, state, ", ", info->spelling);
  write_escaped_string(fcmd, state, ", ", info->printer_name);
  write_escaped_string(fcmd, state, ", ", info->languages);
  write_escaped_string(fcmd, state, ", ", info->exam_id);
  write_escaped_string(fcmd, state, ", ", info->exam_cypher);
  write_escaped_string(fcmd, state, ", ", info->field0);
  write_escaped_string(fcmd, state, ", ", info->field1);
  write_escaped_string(fcmd, state, ", ", info->field2);
  write_escaped_string(fcmd, state, ", ", info->field3);
  write_escaped_string(fcmd, state, ", ", info->field4);
  write_escaped_string(fcmd, state, ", ", info->field5);
  write_escaped_string(fcmd, state, ", ", info->field6);
  write_escaped_string(fcmd, state, ", ", info->field7);
  write_escaped_string(fcmd, state, ", ", info->field8);
  write_escaped_string(fcmd, state, ", ", info->field9);
  fprintf(fcmd, " )");
  fclose(fcmd); fcmd = 0;

  fprintf(stderr, ">>%s\n", cmdstr);

  if (mysql_real_query(state->conn, cmdstr, cmdlen))
    db_error_fail(state);

  xfree(cmdstr); cmdstr = 0; cmdlen = 0;

  for (role = 0; role < USERLIST_MB_LAST; role++) {
    if ((role_cnt = userlist_members_count(info->new_members, role)) <= 0)
      continue;
    for (i = 0; i < role_cnt; i++) {
      if (!(mm = (struct userlist_member*) userlist_members_get_nth(info->new_members, role, i)))
        continue;
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
  fprintf(fcmd, ", %d", !!(c->flags & USERLIST_UC_INCOMPLETE));
  fprintf(fcmd, ", %d", !!(c->flags & USERLIST_UC_DISQUALIFIED));
  write_timestamp(fcmd, state, ", ", c->date);
  fprintf(fcmd, ", 0");         /* changetime not available */
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
  fprintf(fcmd, "%llu, %d, %d, %d, %d, %d, %d, %d, %d",
          c->cookie, user_id, c->contest_id,
          c->priv_level, c->role, 4 /*c->ipversion*/, c->locale_id,
          c->recovery, c->team_login);
  fprintf(fcmd, ", '%s'", xml_unparse_ip(c->ip));
  fprintf(fcmd, ", %d", c->ssl);
  write_timestamp(fcmd, state, ", ", c->expire);
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

  if (mysql_real_query(state->conn, cmdstr, cmdlen))
    db_error_fail(state);

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
  char *eptr;

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
      p_time = XPDEREF(time_t, data, specs[i].offset);
      *p_time = t;
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
  cmdlen = snprintf(cmd, cmdlen, "DELETE FROM %scookies WHERE user_id = %d; DELETE FROM %scntsregs WHERE user_id = %d; DELETE FROM %sparticipants WHERE user_id = %d; DELETE FROM %susers WHERE user_id = %d; DELETE FROM %slogins WHERE user_id = %d;", state->table_prefix, user_id, state->table_prefix, user_id, state->table_prefix, user_id, state->table_prefix, user_id, state->table_prefix, user_id);
  mysql_real_query(state->conn, cmd, cmdlen);
  return 0;
}

static struct userlist_cookie *
allocate_cookie_on_pool(
        struct uldb_mysql_state *state,
        unsigned long long val)
{
  int i, j, h;
  struct userlist_cookie *c, **v;

  h = val & (COOKIES_POOL_SIZE - 1);
  while ((c = state->cookie_hash[h]) && c->cookie != val)
    h = (h + 1) & (COOKIES_POOL_SIZE - 1);
  if ((c = state->cookie_hash[h]) && c->cookie == val) {
    userlist_elem_free_data(&c->b);
    c->cookie = val;
    // move the cookie c to the front
    if (&c->b != state->cookie_first) {
      c->b.left->right = c->b.right->left;
      if (&c->b == state->cookie_last)
        state->cookie_last = c->b.left;
      else
        c->b.right->left = c->b.left->right;
      c->b.right = state->cookie_first;
      c->b.left = 0;
      state->cookie_first->left = &c->b;
      state->cookie_first = &c->b;
    }
    return c;
  }

  if (state->cookie_count > COOKIES_MAX_HASH_SIZE) {
    // remove the least used cookie
    c = (struct userlist_cookie*) state->cookie_last;
    h = c->cookie & (COOKIES_POOL_SIZE - 1);
    i = 0;
    while (state->cookie_hash[h]) {
      h = (h + 1) & (COOKIES_POOL_SIZE - 1);
      i++;
    }
    XALLOCAZ(v, i + 1);
    j = 0;
    h = c->cookie & (COOKIES_POOL_SIZE - 1);
    while (state->cookie_hash[h]) {
      if (state->cookie_hash[h] != c) {
        v[j++] = state->cookie_hash[h];
      }
      state->cookie_hash[h] = 0;
      h = (h + 1) & (COOKIES_POOL_SIZE - 1);
    }
    // rehash the collected pointers
    for (i = 0; i < j; i++) {
      h = v[i]->cookie & (COOKIES_POOL_SIZE - 1);
      while (state->cookie_hash[h])
        h = (h + 1) & (COOKIES_POOL_SIZE - 1);
      state->cookie_hash[h] = v[i];
    }
    // remove c from the tail of the list
    c->b.left->right = 0;
    state->cookie_last = c->b.left;
    userlist_elem_free_data(&c->b);
    state->cookie_count--;
    xfree(c);
  }

  // allocate new entry
  c = (struct userlist_cookie*) userlist_node_alloc(USERLIST_T_COOKIES);
  c->cookie = val;
  state->cookie_count++;
  if (state->cookie_first)
    state->cookie_first->left = &c->b;
  else
    state->cookie_last = &c->b;
  c->b.right = state->cookie_first;
  state->cookie_first = &c->b;
  h = val & (COOKIES_POOL_SIZE - 1);
  while (state->cookie_hash[h])
    h = (h + 1) & (COOKIES_POOL_SIZE - 1);
  state->cookie_hash[h] = c;
  return c;
}

  /*
[0]       (cookie BIGINT UNSIGNED NOT NULL PRIMARY KEY,
[1]       user_id INT NOT NULL,
[2]       contest_id INT UNSIGNED NOT NULL,
[3]       priv_level TINYINT NOT NULL DEFAULT 0,
[4]       role_id TINYINT NOT NULL DEFAULT 0,
[5]       ip_version TINYINT NOT NULL DEFAULT 4,
[6]       locale_id TINYINT NOT NULL DEFAULT 0,
[7]       recovery TINYINT NOT NULL DEFAULT 0,
[8]       team_login TINYINT NOT NULL DEFAULT 0,
[9]       ip VARCHAR(64) NOT NULL,
[10]      ssl_flag TINYINT NOT NULL DEFAULT 0,
[11]      expire DATETIME NOT NULL)
   */
static int
parse_cookie_row(struct uldb_mysql_state *state,
                 struct userlist_cookie *c)
{
  // [0]  cookie
  if (!state->lengths[0] || parse_ullong(state->row[0], &c->cookie) < 0
      || !c->cookie)
    db_inv_value_fail();
  // [1]  user_id
  if (!state->lengths[1] || parse_int(state->row[1], &c->user_id) < 0
      || c->user_id <= 0)
    db_inv_value_fail();
  // [2]  contest_id
  if (!state->lengths[2] || parse_int(state->row[2], &c->contest_id) < 0
      || c->contest_id <= 0)
    db_inv_value_fail();
  // [3]  priv_level
  if (!state->lengths[3] || parse_int(state->row[3], &c->priv_level) < 0
      || c->priv_level < 0 || c->priv_level > PRIV_LEVEL_ADMIN)
    db_inv_value_fail();
  // [4]  role_id
  if (!state->lengths[4] || parse_int(state->row[4], &c->role) < 0
      || c->role < 0)
    db_inv_value_fail();
  // [5]  ip_version (ignored for now)
  // [6]  locale_id
  if (!state->lengths[6] || parse_int(state->row[6], &c->locale_id) < 0)
    db_inv_value_fail();
  if (c->locale_id < 0) c->locale_id = 0;
  // [7]  recovery
  if (!state->lengths[7] || parse_int(state->row[7], &c->recovery) < 0
      || c->recovery < 0 || c->recovery > 1)
    db_inv_value_fail();
  // [8]  team_login
  if (!state->lengths[8] || parse_int(state->row[8], &c->team_login) < 0
      || c->team_login < 0 || c->team_login > 1)
    db_inv_value_fail();
  // [9]  ip
  if (!state->lengths[9] || xml_parse_ip(0, 0, 0, state->row[9], &c->ip) < 0)
    db_inv_value_fail();
  // [10] ssl_flag
  if (!state->lengths[10] || parse_int(state->row[10], &c->ssl) < 0
      || c->ssl < 0 || c->ssl > 1)
    db_inv_value_fail();
  // [11] expire
  if (!state->lengths[11] || parse_datetime(state->row[11], &c->expire) < 0)
    db_inv_value_fail();

  return 0;

 fail:
  return -1;
}

static int
get_cookie_func(
        void *data,
        ej_cookie_t value,
        const struct userlist_cookie **p_cookie)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char cmd[1024];
  int cmdlen;
  struct userlist_cookie *c;

  cmdlen = sizeof(cmd);
  cmdlen = snprintf(cmd, cmdlen, "SELECT * FROM %scookies WHERE cookie = %llu ;",
                    state->table_prefix, value);
  if (one_row_request(state, cmd, cmdlen, COOKIES_WIDTH) < 0) goto fail;
  c = allocate_cookie_on_pool(state, value);
  if (parse_cookie_row(state, c) < 0) goto fail;
  if (p_cookie) *p_cookie = c;
  return 0;

 fail:
  return -1;
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
  if (one_row_request(state, cmd, cmdlen, COOKIES_WIDTH) < 0) goto fail;
  c = allocate_cookie_on_pool(state, cookie);
  if (parse_cookie_row(state, c) < 0) goto fail;
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

/*
[0]    (user_id INT UNSIGNED NOT NULL,
[1]    contest_id INT UNSIGNED NOT NULL,
[2]    status TINYINT NOT NULL DEFAULT 0,
[3]    banned TINYINT NOT NULL DEFAULT 0,
[4]    invisible TINYINT NOT NULL DEFAULT 0,
[5]    locked TINYINT NOT NULL DEFAULT 0,
[6]    incomplete TINYINT NOT NULL DEFAULT 0,
[7]    disqualified TINYINT NOT NULL DEFAULT 0,
[8]    createtime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
[9]    changetime TIMESTAMP DEFAULT 0,
       );
*/
#define CONTEST_OFFSET(f) XOFFSET(struct userlist_contest, f)
static struct mysql_parse_spec cntsregs_spec[CNTSREGS_WIDTH] =
{
  { 0, 'D', "user_id", 0 },
  { 0, 'd', "contest_id", CONTEST_OFFSET(id) },
  { 0, 'd', "status", CONTEST_OFFSET(status) },
  { 0, 'B', "banned", 0 },
  { 0, 'B', "invisible", 0 },
  { 0, 'B', "locked", 0 },
  { 0, 'B', "incomplete", 0 },
  { 0, 'B', "disqualified", 0 },
  { 0, 't', "date", CONTEST_OFFSET(date) },
  { 1, 0, "cntsregs", 0 },
};

static int
parse_cntsregs_row(
        struct uldb_mysql_state *state,
        struct userlist_contest *c)
{
  int user_id = 0, is_banned = 0, is_invisible = 0, is_locked = 0;
  int is_incomplete = 0, is_disqualified = 0;
  int flags = 0;

  if (handle_parse_spec(state, CNTSREGS_WIDTH, cntsregs_spec, c,
                        &user_id, &is_banned, &is_invisible,
                        &is_locked, &is_incomplete, &is_disqualified) < 0)
    goto fail;
  if (user_id <= 0 || c->id <= 0
      || c->status < 0 || c->status >= USERLIST_REG_LAST
      || c->date < 0)
    db_inv_value_fail();
  if (is_banned) flags |= USERLIST_UC_BANNED;
  if (is_invisible) flags |= USERLIST_UC_INVISIBLE;
  if (is_locked) flags |= USERLIST_UC_LOCKED;
  if (is_incomplete) flags |= USERLIST_UC_INCOMPLETE;
  if (is_disqualified) flags |= USERLIST_UC_DISQUALIFIED;
  c->flags = flags;

 fail:
  return -1;
}

struct cntsregs_container
{
  struct xml_tree b;
  int user_id;
  int contest_id;
  struct userlist_contest *c;
  struct cntsregs_container *next, *prev;
  struct cntsregs_container *next_user, *prev_user;
};
struct cntsregs_user
{
  struct cntsregs_container *first_user, *last_user;
  int min_id, max_id;           // [min_id, max_id)
};

static struct userlist_contest *
allocate_cntsregs_on_pool(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id)
{
  struct cntsregs_cache *cc = &state->cntsregs;
  struct cntsregs_user *cu;
  struct cntsregs_container *co;
  struct userlist_contest *c;
  int new_size = 0;
  struct cntsregs_user *new_ptr = 0;

  if (user_id <= 0 || contest_id <= 0) return 0;
  if (user_id < cc->size && cc->user_map && (cu = &cc->user_map[user_id])
      && contest_id >= cu->min_id && contest_id < cu->max_id) {
    for (co = cu->first_user; co; co = co->next_user)
      if (co->contest_id == contest_id)
        break;
    if (co) {
      c = co->c;
      userlist_elem_free_data(&c->b);
      c->id = contest_id;
      // move to the front of the united list
      if (co != cc->first) {
        if (co->next) co->next->prev = co->prev;
        else cc->last = co->prev;
        co->prev->next = co->next;
        co->next = cc->first;
        co->next->prev = co;
        cc->first = co;
      }
      // move to the front of the user list
      if (co != cu->first_user) {
        if (co->next_user) co->next_user->prev_user = co->prev_user;
        else cu->last_user = co->prev_user;
        co->prev_user->next_user = co->prev_user;
        co->next_user = cu->first_user;
        co->next_user->prev_user = co;
        cu->first_user = co;
      }
      return c;
    }
  }

  if (cc->count >= CNTSREGS_POOL_SIZE) {
    // detach the least user entry
    co = cc->last;
    cu = &cc->user_map[co->user_id];
    if (cu->first_user == co) {
      memset(cu, 0, sizeof(*cu));
    } else {
      ASSERT(cu->last_user == co);
      co->prev_user->next_user = 0;
      cu->last_user = co->prev_user;
    }
    co->prev->next = 0;
    cc->last = co->prev;
    c = co->c;
    userlist_elem_free_data(&c->b);
    xfree(c);
    memset(co, 0, sizeof(*co));
    xfree(co);
    cc->count--;
    cu->min_id = cu->max_id = 0;
    for (co = cu->first_user; co; co = co->next_user) {
      if (co->user_id < cu->min_id) cu->min_id = co->user_id;
      if (co->user_id >= cu->max_id) cu->max_id = co->user_id + 1;
    }
  }

  // allocate new entry
  c = (struct userlist_contest*) userlist_node_alloc(USERLIST_T_CONTEST);
  XCALLOC(co, 1);
  co->user_id = user_id;
  co->contest_id = contest_id;
  co->c = c;
  cc->count++;
  if (!cc->first) {
    cc->first = cc->last = co;
  } else {
    co->prev = cc->last;
    co->prev->next = co;
    cc->last = co;
  }
  if (cc->size <= user_id) {
    if (!(new_size = cc->size)) new_size = 128;
    while (new_size <= user_id) new_size *= 2;
    XCALLOC(new_ptr, new_size);
    if (cc->size)
      memcpy(new_ptr, cc->user_map, cc->size * sizeof(cc->user_map[0]));
    xfree(cc->user_map);
    cc->user_map = new_ptr;
    cc->size = new_size;
  }
  cu = &cc->user_map[user_id];
  if (!cu->first_user) {
    cu->first_user = cu->last_user = co;
    cu->min_id = user_id;
    cu->max_id = user_id + 1;
  } else {
    co->prev_user = cu->last_user;
    co->prev_user->next_user = co;
    cu->last_user = co;
    if (user_id < cu->min_id) cu->min_id = user_id;
    if (user_id >= cu->max_id) cu->max_id = user_id + 1;
  }
  return c;
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
  if (one_row_request(state, cmd, cmdlen, COOKIES_WIDTH) < 0) return 0;
  c = allocate_cntsregs_on_pool(state, iter->user_id, iter->ids[iter->cur_i]);
  if (!c) return 0;
  if (parse_cntsregs_row(state, c) < 0) return 0;
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

static struct userlist_user *
allocate_users_on_pool(
        struct uldb_mysql_state *state,
        int user_id)
{
  struct users_cache *uc = &state->users;
  struct userlist_user *u;

  if (user_id <= 0) return 0;
  // user_id is ridiculously big?
  if (user_id >= 1000000000) return 0;

  if (user_id < uc->map_size && (u = uc->map[user_id])) {
    userlist_elem_free_data(&u->b);
    u->id = user_id;
    u->b.tag = USERLIST_T_USER;
    if (&u->b == uc->first) return u;
    // detach u
    u->b.left->right = u->b.right;
    if (&u->b == uc->last)
      uc->last = u->b.left;
    else
      u->b.right->left = u->b.left;
    u->b.left = u->b.right = 0;
    // reattach u to the first element
    u->b.right = uc->first;
    uc->first->left = &u->b;
    uc->first = &u->b;
    return u;
  }

  if (uc->count == USERS_POOL_SIZE) {
    // free the least used element
    u = (struct userlist_user*) uc->last;
    uc->map[u->id] = 0;
    u->b.left->right = 0;
    uc->last = u->b.left;
    u->b.left = u->b.right = 0;
    userlist_elem_free_data(&u->b);
    memset(u, 0, sizeof(*u));
    xfree(u);
    uc->count--;
  }

  u = (struct userlist_user*) userlist_node_alloc(USERLIST_T_USER);
  u->id = user_id;
  if (!uc->first) {
    uc->first = uc->last = &u->b;
  } else {
    u->b.right = uc->first;
    uc->first->left = &u->b;
    uc->first = &u->b;
  }
  if (user_id >= uc->map_size) {
    int new_map_size = uc->map_size;
    struct userlist_user **new_map;

    if (!new_map_size) new_map_size = 1024;
    while (user_id >= new_map_size) new_map_size *= 2;
    XCALLOC(new_map, new_map_size);
    if (uc->map_size > 0)
      memcpy(new_map, uc->map, uc->map_size * sizeof(uc->map[0]));
    xfree(uc->map);
    uc->map_size = new_map_size;
    uc->map = new_map;
  }
  uc->map[user_id] = u;
  uc->count++;
  return u;
}

/*
[0]   (user_id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
[1]    login VARCHAR(64) NOT NULL UNIQUE KEY COLLATE utf8_bin,
[2]    email VARCHAR(128),
[3]    pwdmethod TINYINT NOT NULL DEFAULT 0,
[4]    password VARCHAR(64),
[5]    privileged TINYINT NOT NULL DEFAULT 0,
[6]    invisible TINYINT NOT NULL DEFAULT 0,
[7]    banned TINYINT NOT NULL DEFAULT 0,
[8]    locked TINYINT NOT NULL DEFAULT 0,
[9]    readonly TINYINT NOT NULL DEFAULT 0,
[10]   neverclean TINYINT NOT NULL DEFAULT 0,
[11]   simplereg TINYINT NOT NULL DEFAULT 0,
[12]   regtime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
[13]   logintime TIMESTAMP DEFAULT NULL,
[14]   pwdtime TIMESTAMP DEFAULT NULL,
[15]   changetime TIMESTAMP DEFAULT NULL
       );
*/
#define LOGINS_OFFSET(f) XOFFSET(struct userlist_user, f)
static struct mysql_parse_spec logins2_spec[LOGINS_WIDTH] =
{
  { 0, 'd', "user_id", LOGINS_OFFSET(id) },
  { 0, 's', "login", LOGINS_OFFSET(login) },
  { 1, 's', "email", LOGINS_OFFSET(email) },
  { 0, 'd', "pwdmethod", LOGINS_OFFSET(passwd_method) },
  { 1, 's', "password", LOGINS_OFFSET(passwd) },
  { 0, 'b', "privileged", LOGINS_OFFSET(is_privileged) },
  { 0, 'b', "invisible", LOGINS_OFFSET(is_invisible) },
  { 0, 'b', "banned", LOGINS_OFFSET(is_banned) },
  { 0, 'b', "locked", LOGINS_OFFSET(is_locked) },
  { 0, 'b', "readonly", LOGINS_OFFSET(read_only) },
  { 0, 'b', "neverclean", LOGINS_OFFSET(never_clean) },
  { 0, 'b', "simplereg", LOGINS_OFFSET(simple_registration) },
  { 1, 't', "regtime", LOGINS_OFFSET(registration_time) },
  { 1, 't', "logintime", LOGINS_OFFSET(last_login_time) },
  { 1, 't', "pwdtime", LOGINS_OFFSET(last_pwdchange_time) },
  { 1, 't', "changetime", LOGINS_OFFSET(last_change_time) },
};

static int
parse_users_row(
        struct uldb_mysql_state *state,
        struct userlist_user *u)
{
  if (handle_parse_spec(state, LOGINS_WIDTH, logins2_spec, u) < 0)
    goto fail;
  if (u->id <= 0) goto fail;
  if (u->passwd_method < USERLIST_PWD_PLAIN
      || u->passwd_method > USERLIST_PWD_SHA1)
    goto fail;
  if (u->registration_time < 0) u->registration_time = 0;
  if (u->last_login_time < 0) u->last_login_time = 0;
  if (u->last_pwdchange_time < 0) u->last_pwdchange_time = 0;
  if (u->last_change_time < 0) u->last_change_time = 0;
  return 0;

    fail:
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
  if (one_row_request(state, cmd, cmdlen, LOGINS_WIDTH) < 0) return 0;
  if (!(u = allocate_users_on_pool(state, user_id))) return 0;
  if (parse_users_row(state, u) < 0) return 0;
  if (p_user) *p_user = u;
  return 1;

 fail:
  if (p_user) *p_user = 0;
  return -1;
}

/*
struct user_info_cache
{
  int size, count;
  struct user_info_user *user_map;
  struct user_info_container *first, *last;
};
*/
struct user_info_container
{
  struct xml_tree b;
  int user_id;
  int contest_id;
  struct userlist_cntsinfo *ui;
  struct user_info_container *next, *prev;
  struct user_info_container *next_user, *prev_user;
};
struct user_info_user
{
  struct user_info_container *first_user, *last_user;
  int min_id, max_id;           // [min_id, max_id) - contest_id
};

static struct userlist_user_info *
allocate_user_info_on_pool(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id)
{
  struct user_info_cache *ic = &state->user_infos;
  struct user_info_user *uiu;
  struct user_info_container *pp = 0, *qq = 0;

  if (user_id >= ic->size) {
    int new_size = ic->size;
    struct user_info_user *new_map = 0;

    if (!new_size) new_size = 128;
    while (user_id >= new_size) new_size *= 2;

    XCALLOC(new_map, new_size);
    if (ic->size > 0) {
      memcpy(new_map, ic->user_map, ic->size * sizeof(new_map[0]));
    }
    xfree(ic->user_map);
    ic->user_map = new_map;
    ic->size = new_size;
  }
  uiu = &ic->user_map[user_id];

  if (contest_id >= uiu->min_id && contest_id < uiu->max_id) {
    for (pp = uiu->first_user; pp; pp = pp->next_user)
      if (pp->contest_id == contest_id)
        break;
  }
  if (pp) {
    userlist_elem_free_data(&pp->ui->b);
    pp->ui->b.tag = USERLIST_T_CNTSINFO;
    // move the element to the head of list
    if (pp != ic->first) {
      if (pp->next) {
        pp->next->prev = pp->prev;
      } else {
        ic->last = pp->prev;
      }
      pp->prev->next = pp->next;
      pp->prev = 0;
      pp->next = ic->first;
      ic->first = pp;
    }
    // also move the element to the head of the user list
    if (pp != uiu->first_user) {
      if (pp->next_user) {
        pp->next_user->prev_user = pp->prev_user;
      } else {
        uiu->last_user = pp->prev_user;
      }
      pp->prev_user->next_user = pp->next_user;
      pp->prev_user = 0;
      pp->next_user = uiu->first_user;
      uiu->first_user= pp;
    }
    return &pp->ui->i;
  }

  if (ic->count == USER_INFO_POOL_SIZE) {
    // remove the least used entry from the list
    pp = ic->last;
    ic->last = pp->prev;
    ic->last->next = 0;
    pp->prev = 0;
    // also remove the entry from user list
    ASSERT(pp->user_id > 0 && pp->user_id < ic->size);
    uiu = &ic->user_map[pp->user_id];
    ASSERT(uiu);
    if (pp == uiu->first_user) {
      uiu->first_user = pp->next_user;
    } else {
      pp->prev_user->next_user = pp->next_user;
    }
    if (pp == uiu->last_user) {
      uiu->last_user = pp->prev_user;
    } else {
      pp->next_user->prev_user = pp->prev_user;
    }
    pp->prev_user = 0;
    pp->next_user = 0;
    userlist_free(&pp->ui->b);
    pp->ui = 0;
    xfree(pp);
    ic->count--;
    // recalculate [min_id, max_id)
    if (pp->contest_id == uiu->min_id || pp->contest_id + 1 == uiu->max_id) {
      uiu->min_id = uiu->max_id = 0;
      if (uiu->first_user) {
        uiu->min_id = uiu->first_user->contest_id;
        uiu->max_id = uiu->first_user->contest_id + 1;
      }
      for (qq = uiu->first_user; qq; qq = qq->next_user) {
        if (qq->contest_id < uiu->min_id) uiu->min_id = qq->contest_id;
        if (qq->contest_id >= uiu->max_id) uiu->max_id = qq->contest_id + 1;
      }
    }
  }

  XCALLOC(pp, 1);
  pp->ui = (struct userlist_cntsinfo*) userlist_node_alloc(USERLIST_T_CNTSINFO);
  pp->ui->b.tag = USERLIST_T_CNTSINFO;
  pp->user_id = user_id;
  pp->contest_id = contest_id;

  pp->next = ic->first;
  if (ic->first) {
    pp->next->prev = pp;
  } else {
    ic->last = pp;
  }
  ic->first = pp;

  if (!uiu->first_user) {
    ASSERT(!uiu->last_user);
    uiu->first_user = uiu->last_user = pp;
    uiu->min_id = pp->contest_id;
    uiu->max_id = pp->contest_id + 1;
  } else {
    ASSERT(uiu->last_user);
    pp->next_user = uiu->first_user;
    pp->next_user->prev_user = pp;
    uiu->first_user = pp;
    if (pp->contest_id < uiu->min_id) uiu->min_id = pp->contest_id;
    if (pp->contest_id >= uiu->max_id) uiu->max_id = pp->contest_id + 1;
  }

  return &pp->ui->i;
}

/*
[0]	user_id INT UNSIGNED NOT NULL,
[1]	contest_id INT UNSIGNED NOT NULL,
[2]	cnts_read_only TINYINT NOT NULL DEFAULT 0,
[3]	instnum INT,
[4]	username VARCHAR(512),
[5]	pwdmethod TINYINT NOT NULL DEFAULT 0,
[6]	password VARCHAR(64),
[7]	pwdtime TIMESTAMP DEFAULT 0,
[8]	createtime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
[9]	changetime TIMESTAMP DEFAULT 0,
[10]	inst VARCHAR(512),
[11]	inst_en VARCHAR (512),
[12]	instshort VARCHAR (512),
[13]	instshort_en VARCHAR (512),
[14]	fac VARCHAR(512),
[15]	fac_en VARCHAR (512),
[16]	facshort VARCHAR (512),
[17]	facshort_en VARCHAR (512),
[18]	homepage VARCHAR (512),
[19]	phone VARCHAR (512),
[20]	city VARCHAR (512),
[21]	city_en VARCHAR (512),
[22]	region VARCHAR (512),
[23]	area VARCHAR (512),
[24]	zip VARCHAR (512),
[25]	street VARCHAR (512),
[26]	country VARCHAR (512),
[27]	country_en VARCHAR (512),
[28]	location VARCHAR (512),
[29]	spelling VARCHAR (512),
[30]	printer VARCHAR (512),
[31]	languages VARCHAR (512),
[32]	exam_id VARCHAR (512),
[33]	exam_cypher VARCHAR (512),
[34]	field0 VARCHAR(512),
[35]	field1 VARCHAR(512),
[36]	field2 VARCHAR(512),
[37]	field3 VARCHAR(512),
[38]	field4 VARCHAR(512),
[39]	field5 VARCHAR(512),
[40]	field6 VARCHAR(512),
[41]	field7 VARCHAR(512),
[42]	field8 VARCHAR(512),
[43]	field9 VARCHAR(512),
*/

 /*
#define USER_INFO_OFFSET(f) XOFFSET(struct userlist_user_info, f)
static struct mysql_parse_spec user_info_spec[USER_INFO_WIDTH] =
{
  { 0, 'D', "user_id", 0 },     // read into the variable, not structure
  { 0, 'D', "contest_id", 0 },  // the same
  { 0, 'b', "cnts_read_only", USER_INFO_OFFSET(cnts_read_only) },
  { 1, 's', "name", USER_INFO_OFFSET(name) },
  { 0, 'D', "team_passwd_method", 0 }, // read into the variable
  { 1, 'S', "team_passwd", 0 },        // read into the variable
  { 1, 's', "inst", USER_INFO_OFFSET(inst) },
  { 1, 's', "inst_en", USER_INFO_OFFSET(inst_en) },
  { 1, 's', "instshort", USER_INFO_OFFSET(instshort) },
  { 1, 's', "instshort_en", USER_INFO_OFFSET(instshort_en) },
  { 1, 's', "fac", USER_INFO_OFFSET(fac) },
  { 1, 's', "fac_en", USER_INFO_OFFSET(fac_en) },
  { 1, 's', "facshort", USER_INFO_OFFSET(facshort) },
  { 1, 's', "facshort_en", USER_INFO_OFFSET(facshort_en) },
  { 1, 's', "homepage", USER_INFO_OFFSET(homepage) },
  { 1, 's', "city", USER_INFO_OFFSET(city) },
  { 1, 's', "city_en", USER_INFO_OFFSET(city_en) },
  { 1, 's', "country", USER_INFO_OFFSET(country) },
  { 1, 's', "country_en", USER_INFO_OFFSET(country_en) },
  { 1, 's', "region", USER_INFO_OFFSET(region) },
  { 1, 's', "area", USER_INFO_OFFSET(area) },
  { 1, 's', "zip", USER_INFO_OFFSET(zip) },
  { 1, 's', "street", USER_INFO_OFFSET(street) },
  { 1, 's', "location", USER_INFO_OFFSET(location) },
  { 1, 's', "spelling", USER_INFO_OFFSET(spelling) },
  { 1, 's', "printer_name", USER_INFO_OFFSET(printer_name) },
  { 1, 's', "exam_id", USER_INFO_OFFSET(exam_id) },
  { 1, 's', "exam_cypher", USER_INFO_OFFSET(exam_cypher) },
  { 1, 's', "languages", USER_INFO_OFFSET(languages) },
  { 1, 's', "phone", USER_INFO_OFFSET(phone) },
  { 1, 's', "field0", USER_INFO_OFFSET(field0) },
  { 1, 's', "field1", USER_INFO_OFFSET(field1) },
  { 1, 's', "field2", USER_INFO_OFFSET(field2) },
  { 1, 's', "field3", USER_INFO_OFFSET(field3) },
  { 1, 's', "field4", USER_INFO_OFFSET(field4) },
  { 1, 's', "field5", USER_INFO_OFFSET(field5) },
  { 1, 's', "field6", USER_INFO_OFFSET(field6) },
  { 1, 's', "field7", USER_INFO_OFFSET(field7) },
  { 1, 's', "field8", USER_INFO_OFFSET(field8) },
  { 1, 's', "field9", USER_INFO_OFFSET(field9) },
};
 */

 /*
struct userlist_user_info
{
  int cnts_read_only;
  int filled;

  unsigned char *name;
  int instnum;

  // team password
  int team_passwd_method;
  unsigned char *team_passwd;

  unsigned char *inst;
  unsigned char *inst_en;
  unsigned char *instshort;
  unsigned char *instshort_en;
  unsigned char *fac;
  unsigned char *fac_en;
  unsigned char *facshort;
  unsigned char *facshort_en;
  unsigned char *homepage;
  unsigned char *city;
  unsigned char *city_en;
  unsigned char *country;
  unsigned char *country_en;
  unsigned char *region;
  unsigned char *area;
  unsigned char *zip;
  unsigned char *street;
  unsigned char *location;
  unsigned char *spelling;
  unsigned char *printer_name;
  unsigned char *exam_id;
  unsigned char *exam_cypher;
  unsigned char *languages;
  unsigned char *phone;
  unsigned char *field0;
  unsigned char *field1;
  unsigned char *field2;
  unsigned char *field3;
  unsigned char *field4;
  unsigned char *field5;
  unsigned char *field6;
  unsigned char *field7;
  unsigned char *field8;
  unsigned char *field9;
  struct userlist_members *members[USERLIST_MB_LAST];

  time_t create_time;
  time_t last_login_time;
  time_t last_change_time;
  time_t last_access_time;
  time_t last_pwdchange_time;
};
  */

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
