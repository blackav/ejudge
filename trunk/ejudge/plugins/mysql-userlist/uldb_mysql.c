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
#include "misctext.h"
#include "random.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <mysql.h>

#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>

#include "methods.inc.c"

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
  NULL,                         /* not implemented yet */
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
  // set the login time
  touch_login_time_func,
  // get the login, basic contest-specific user info, and registration
  get_user_info_3_func,
  // change the contest_id for the cookie
  set_cookie_contest_func,
  // change the locale of the cookie
  set_cookie_locale_func,
  // change the privilege level of the cookie
  set_cookie_priv_level_func,
  // get the login, basic contest-specific user info, and registration
  // merged into one structure for further retrieval by unparse
  get_user_info_4_func,
  // get the all the information about a user for privileged
  // get user information
  get_user_info_5_func,
  // get an iterator for extracting brief user info (general or contest)
  // iterator iterates over all users
  get_brief_list_iterator_func,
  // get an iterator for standings XML userlist
  get_standings_list_iterator_func,
  // check, that user exists (0 - yes, -1 - no)
  check_user_func,
  // set the registration password
  set_reg_passwd_func,
  // set the team password
  set_team_passwd_func,
  // register a user for contest
  register_contest_func,
  // remove a particular member from a user
  remove_member_func,
  // check if the user is read-only
  is_read_only_func,
  // get the user iterator for HTML user info requests
  // userlist_user, userlist_user_info, userlist_member, userlist_contest
  // fields are filled up
  get_info_list_iterator_func,
  // clear the team password
  clear_team_passwd_func,
  // remove a contest registration
  remove_registration_func,
  // set the registration status
  set_reg_status_func,
  // set the registration flags
  set_reg_flags_func,
  // remove user contest-specific info
  remove_user_contest_info_func,
  // clear the main user info field
  clear_user_field_func,
  // clear the user_info field
  clear_user_info_field_func,
  // clear the member field
  clear_user_member_field_func,
  // set the main user info field
  set_user_field_func,
  // set the user contest-specific info field
  set_user_info_field_func,
  // set the user member field
  set_user_member_field_func,
  // create new member
  new_member_func,
  // maintenance operations
  maintenance_func,
  // set the user fields by its XML
  // currently not used, UNIMPLEMENTED
  set_user_xml_func,
  // copy contest-specific user info to another contest
  copy_user_info_func,
  // check the user registration information
  check_user_reg_data_func,
  // move a particular member to a different role
  move_member_func,
  // change the team_login flag of the cookie
  set_cookie_team_login_func,
  // get the login, basic contest-specific user info, registration
  // and member information
  get_user_info_6_func,
  // get the login, basic contest-specific user info, and member info
  get_user_info_7_func,
  // get the member serial number
  get_member_serial_func,
  // set the member serial number
  set_member_serial_func,
  // unlock the complete user information structure
  unlock_user_func,
  // get the user contest registration info
  get_contest_reg_func,
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

struct cookies_container;

struct cookies_cache
{
  struct cookies_container *hash[COOKIES_POOL_SIZE];
  struct cookies_container *first, *last;
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
  int show_queries;
  int cache_queries;

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

  // for user lock debugging
  int locked_user_id;
  const unsigned char *locked_func;

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

struct saved_row
{
  int field_count;
  unsigned long *lengths;
  char **row;
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

static void
my_free_res(struct uldb_mysql_state *state)
{
  if (state->res) mysql_free_result(state->res);
  state->res = 0;
}

static int
my_simple_query(
        struct uldb_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen)
{
  if (state->show_queries) {
    fprintf(stderr, "mysql: %s\n", cmd);
  }
  if (mysql_real_query(state->conn, cmd, cmdlen)) db_error_fail(state);
  return 0;

 fail:
  return -1;
}

static int
my_simple_fquery(
        struct uldb_mysql_state *state,
        const char *format,
        ...)
  __attribute__((format(printf, 2, 3)));
static int
my_simple_fquery(
        struct uldb_mysql_state *state,
        const char *format,
        ...)
{
  unsigned char cmdbuf[1024];
  size_t cmdlen;
  va_list args;

  va_start(args, format);
  vsnprintf(cmdbuf, sizeof(cmdbuf), format, args);
  va_end(args);
  cmdlen = strlen(cmdbuf);
  return my_simple_query(state, cmdbuf, cmdlen);
}

static int
my_query(
        struct uldb_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen,
        int colnum)
{
  if (state->show_queries) {
    fprintf(stderr, "mysql: %s\n", cmd);
  }
  if (mysql_real_query(state->conn, cmd, cmdlen)) db_error_fail(state);
  if((state->field_count = mysql_field_count(state->conn)) != colnum)
    db_wrong_field_count_fail(state, colnum);
  if (!(state->res = mysql_store_result(state->conn))) db_error_fail(state);
  if ((state->row_count = mysql_num_rows(state->res)) < 0) goto fail;
  return state->row_count;

 fail:
  my_free_res(state);
  return -1;
}

static int
my_query_one_row(
        struct uldb_mysql_state *state,
        const unsigned char *cmd,
        int cmdlen,
        int colnum)
{
  int i;

  if (state->show_queries) {
    fprintf(stderr, "mysql: %s\n", cmd);
  }
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
  // extra check...
  for (i = 0; i < state->field_count; i++)
    if (state->row[i] && strlen(state->row[i]) != state->lengths[i])
      db_inv_value_fail();
  return 0;

 fail:
  my_free_res(state);
  return -1;
}

static int
my_row(struct uldb_mysql_state *state)
{
  int i;

  if (!(state->row = mysql_fetch_row(state->res)))
    db_no_data_fail();
  state->lengths = mysql_fetch_lengths(state->res);

  // extra check...
  for (i = 0; i < state->field_count; i++)
    if (state->row[i] && strlen(state->row[i]) != state->lengths[i])
      db_inv_value_fail();
  return 0;

 fail:
  my_free_res(state);
  return -1;
}

static int
my_int_val(struct uldb_mysql_state *state, int *p_int, int min_val)
{
  if (my_row(state) < 0) goto fail;
  if (!state->lengths[0]) db_inv_value_fail();
  if (parse_int(state->row[0], p_int) < 0 || *p_int < min_val)
    db_inv_value_fail();
  return 0;

 fail:
  my_free_res(state);
  return -1;
}

static void
userlist_attach_user_info(
        struct userlist_user *u,
        struct userlist_user_info *ui)
{
  if (!u || !ui) return;

  if (ui->contest_id <= 0) {
    u->cnts0 = ui;
  } else {
    userlist_expand_cntsinfo(u, ui->contest_id);
    u->cntsinfo[ui->contest_id] = ui;
  }
}

static void
userlist_attach_cntsreg(
        struct userlist_user *u,
        struct userlist_contest *c)
{
  if (!u || !c) return;

  if (!u->contests) {
    u->contests = userlist_node_alloc(USERLIST_T_CONTESTS);
    xml_link_node_last(&u->b, u->contests);
  }
  xml_link_node_last(u->contests, &c->b);
}

static void
userlist_attach_cookie(
        struct userlist_user *u,
        struct userlist_cookie *c)
{
  if (!u || !c) return;

  if (!u->cookies) {
    u->cookies = userlist_node_alloc(USERLIST_T_COOKIES);
    xml_link_node_last(&u->b, u->cookies);
  }
  xml_link_node_last(u->cookies, &c->b);
}

static void*
init_func(const struct ejudge_cfg *config)
{
  struct uldb_mysql_state *state;

  XCALLOC(state, 1);
  state->show_queries = 1;
  state->cache_queries = 1;
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
  struct xml_attr *a;
  int i;
  const unsigned char *cs = 0;

  ASSERT(tree->tag == xml_err_spec->default_elem);
  ASSERT(!strcmp(tree->name[0], "config"));

  if (xml_empty_text(tree) < 0) return -1;

  for (a = tree->first; a; a = a->next) {
    ASSERT(a->tag == xml_err_spec->default_attr);
    if (!strcmp(a->name[0], "show_queries")) {
      if (xml_attr_bool(a, &state->show_queries) < 0) return -1;
    } else if (!strcmp(a->name[0], "cache_queries")) {
      if (xml_attr_bool(a, &state->cache_queries) < 0) return -1;
    } else {
      return xml_err_attr_not_allowed(p, a);
    }
  }

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
    if (my_simple_fquery(state, "SET NAMES '%s' ;\n", state->charset) < 0)
      return -1;
  }

  return 0;
}

static int
check_func(void *data)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  int version, n;

  if (!state->conn) return -1;

  // check, that database is created
  if (my_simple_fquery(state, "SELECT config_val FROM %sconfig WHERE config_key = 'version' ;", state->table_prefix) < 0) {
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
  my_free_res(state);
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
      snprintf(cmdbuf, sizeof(cmdbuf), "ALTER DATABASE %s DEFAULT CHARACTER SET '%s' DEFAULT COLLATE '%s' ;\n", state->database, state->charset, state->collation);
    } else {
      snprintf(cmdbuf, sizeof(cmdbuf), "ALTER DATABASE %s DEFAULT CHARACTER SET '%s' ;\n", state->database, state->charset);
    }
    cmdlen = strlen(cmdbuf);
    if (my_simple_query(state, cmdbuf, cmdlen) < 0) goto fail;
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
    snprintf(buf, bufsize, cmdstr, state->table_prefix);
    buflen = strlen(buf);
    if (my_simple_query(state, buf, buflen) < 0) goto fail;

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

  if (!pfx) pfx = "";
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

  if (!pfx) pfx = "";
  if (time <= 0) {
    fprintf(f, "%sDEFAULT", pfx);
    return;
  }

  ptm = localtime(&time);
  fprintf(f, "%s'%04d-%02d-%02d %02d:%02d:%02d'",
          pfx, ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
          ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
}

static void
write_date(
        FILE *f,
        struct uldb_mysql_state *state,
        const unsigned char *pfx,
        time_t time)
{
  struct tm *ptm;

  if (!pfx) pfx = "";
  if (time <= 0) {
    fprintf(f, "%sDEFAULT", pfx);
    return;
  }

  ptm = localtime(&time);
  fprintf(f, "%s'%04d-%02d-%02d'",
          pfx, ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday);
}

static int
insert_member_info(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id,
        const struct userlist_member *memb,
        int *p_serial)
{
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  struct userlist_member newm;

  if (p_serial) {
    memcpy(&newm, memb, sizeof(newm));
    newm.serial = (*p_serial)++;
  }

  if (!(cmd_f = open_memstream(&cmd_t, &cmd_z))) {
    err("open_memstream failed: %s", os_ErrorMsg());
    goto fail;
  }

  fprintf(cmd_f, "INSERT INTO %smembers VALUES ( ", state->table_prefix);
  if (p_serial) {
    unparse_member(state, cmd_f, user_id, contest_id, &newm);
  } else {
    unparse_member(state, cmd_f, user_id, contest_id, memb);
  }
  fprintf(cmd_f, " ) ;");
  fclose(cmd_f); cmd_f = 0;

  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;

  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
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
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  int i;

  if (!(cmd_f = open_memstream(&cmd_t, &cmd_z))) {
    err("open_memstream failed: %s", os_ErrorMsg());
    goto fail;
  }

  fprintf(cmd_f, "INSERT INTO %susers VALUES ( ", state->table_prefix);
  unparse_user_info(state, cmd_f, user_id, info);
  fprintf(cmd_f, " ) ;");
  fclose(cmd_f); cmd_f = 0;

  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;

  xfree(cmd_t); cmd_t = 0; cmd_z = 0;

  if (!info->members) return 0;
  for (i = 0; i < info->members->u; i++)
    if (insert_member_info(state, user_id, contest_id,
                           info->members->m[i], p_serial) < 0)
      goto fail;

  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
insert_contest(struct uldb_mysql_state *state, int user_id, 
               struct userlist_contest *c)
{
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  if (!(cmd_f = open_memstream(&cmd_t, &cmd_z))) {
    err("open_memstream failed: %s", os_ErrorMsg());
    goto fail;
  }

  fprintf(cmd_f, "INSERT INTO %scntsregs VALUES ( ", state->table_prefix);
  unparse_cntsreg(state, cmd_f, user_id, c);
  fprintf(cmd_f, " ) ;");
  fclose(cmd_f); cmd_f = 0;

  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;

  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
insert_cookie(struct uldb_mysql_state *state, int user_id, 
              struct userlist_cookie *c)
{
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  if (!(cmd_f = open_memstream(&cmd_t, &cmd_z))) {
    err("open_memstream failed: %s", os_ErrorMsg());
    goto fail;
  }

  fprintf(cmd_f, "INSERT INTO %scookies VALUES ( ", state->table_prefix);
  unparse_cookie(state, cmd_f, c);
  fprintf(cmd_f, " ) ;");
  fclose(cmd_f); cmd_f = 0;

  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;

  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
insert_func(void *data, const struct userlist_user *user, int *p_member_serial)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  int contest_id;
  struct userlist_user_info *cntsinfo;
  struct xml_tree *p;
  unsigned char *contest_set = 0;
  int max_contest_id;
  struct userlist_contest *uc;

  if (!(cmd_f = open_memstream(&cmd_t, &cmd_z))) {
    err("open_memstream failed: %s", os_ErrorMsg());
    goto fail;
  }

  fprintf(cmd_f, "INSERT INTO %slogins VALUES ( ", state->table_prefix);
  unparse_login(state, cmd_f, user);
  fprintf(cmd_f, " );");
  fclose(cmd_f); cmd_f = 0;

  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;

  xfree(cmd_t); cmd_t = 0; cmd_z = 0;

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

  if (!user->cnts0) {
    for (contest_id = 1; contest_id < user->cntsinfo_a; contest_id++) {
      if (!(cntsinfo = user->cntsinfo[contest_id])) continue;
      if (insert_contest_info(state, user->id, contest_id, cntsinfo, 0) < 0)
        goto fail;
    }
    return 0;
  }

  // insert the existing contest info
  if (insert_contest_info(state, user->id, 0, user->cnts0, 0) < 0)
    goto fail;

  for (contest_id = 1; contest_id < user->cntsinfo_a; contest_id++) {
    if (!(cntsinfo = user->cntsinfo[contest_id])) continue;
    if (insert_contest_info(state, user->id, contest_id, cntsinfo, 0) < 0)
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
    if (insert_contest_info(state, user->id, contest_id, user->cnts0,
                            p_member_serial) < 0)
      goto fail;
  }

  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
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
handle_parse_spec(
        int field_count,
        char **row,
        unsigned long *lengths,
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

  if (field_count != spec_num) {
    err("wrong field_count (%d instead of %d). invalid table format?",
        field_count, spec_num);
    return -1;
  }

  // check non-null and binary data
  for (i = 0; i < spec_num; i++) {
    if (!specs[i].null_allowed && !row[i]) {
      err("column %d (%s) cannot be NULL", i, specs[i].name);
      return -1;
    }
    if (row[i] && strlen(row[i]) != lengths[i]) {
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
      uq = strtoull(row[i], &eptr, 16);
      if (errno || *eptr) goto invalid_format;
      p_uq = XPDEREF(unsigned long long, data, specs[i].offset);
      *p_uq = uq;
      break;
      
    case 'd':
    case 'e':
      errno = 0;
      eptr = 0;
      x = strtol(row[i], &eptr, 10);
      if (errno || *eptr) goto invalid_format;
      p_int = XPDEREF(int, data, specs[i].offset);
      *p_int = x;
      break;
    case 'D':
      errno = 0;
      eptr = 0;
      x = strtol(row[i], &eptr, 10);
      if (errno || *eptr) goto invalid_format;
      p_int = va_arg(args, int*);
      *p_int = x;
      break;
    case 'b':
      if (sscanf(row[i], "%d%n", &x, &n) != 1 || row[i][n])
        goto invalid_format;
      if (x != 0 && x != 1) goto invalid_format;
      p_int = XPDEREF(int, data, specs[i].offset);
      *p_int = x;
      break;
    case 'B':
      if (sscanf(row[i], "%d%n", &x, &n) != 1 || row[i][n])
        goto invalid_format;
      if (x != 0 && x != 1) goto invalid_format;
      p_int = va_arg(args, int*);
      *p_int = x;
      break;
    case 's':
      p_str = XPDEREF(unsigned char *, data, specs[i].offset);
      if (row[i]) {
        *p_str = xstrdup(row[i]);
      } else {
        *p_str = 0;
      }
      break;
    case 'S':
      p_str = va_arg(args, unsigned char **);
      if (row[i]) {
        *p_str = xstrdup(row[i]);
      } else {
        *p_str = 0;
      }
      break;
    case 't':
      if (!row[i]) {
        p_time = XPDEREF(time_t, data, specs[i].offset);
        *p_time = 0;
        break;
      }
      // special handling for '0' case
      if (sscanf(row[i], "%d%n", &x, &n) == 1 && !row[i][n]
          && !x) {
        p_time = XPDEREF(time_t, data, specs[i].offset);
        *p_time = 0;
        break;
      }
      // 'YYYY-MM-DD hh:mm:ss'
      if (sscanf(row[i], "%d-%d-%d %d:%d:%d%n",
                 &d_year, &d_mon, &d_day, &d_hour, &d_min, &d_sec, &n) != 6
          || row[i][n])
        goto invalid_format;
      if (!d_year && !d_mon && !d_day && !d_hour && !d_min && !d_sec) {
        p_time = XPDEREF(time_t, data, specs[i].offset);
        *p_time = 0;
        break;
      }
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
    case 'a':
      if (!row[i]) {
        p_time = XPDEREF(time_t, data, specs[i].offset);
        *p_time = 0;
        break;
      }
      // special handling for '0' case
      if (sscanf(row[i], "%d%n", &x, &n) == 1 && !row[i][n]
          && !x) {
        p_time = XPDEREF(time_t, data, specs[i].offset);
        *p_time = 0;
        break;
      }
      // 'YYYY-MM-DD hh:mm:ss'
      if (sscanf(row[i], "%d-%d-%d%n", &d_year, &d_mon, &d_day, &n) != 3
          || row[i][n])
        goto invalid_format;
      if (!d_year && !d_mon && !d_day) {
        p_time = XPDEREF(time_t, data, specs[i].offset);
        *p_time = 0;
        break;
      }
      memset(&tt, 0, sizeof(tt));
      tt.tm_year = d_year - 1900;
      tt.tm_mon = d_mon - 1;
      tt.tm_mday = d_day;
      tt.tm_hour = 12;
      tt.tm_isdst = -1;
      if ((t = mktime(&tt)) == (time_t) -1) goto invalid_format;
      if (t < 0) t = 0;
      p_time = XPDEREF(time_t, data, specs[i].offset);
      *p_time = t;
      break;
    case 'i':
      p_ip = XPDEREF(ej_ip_t, data, specs[i].offset);
      if (xml_parse_ip(0, 0, 0, row[i], p_ip) < 0) goto invalid_format;
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
      fprintf(fout, "%s'%016llx'", sep, uq);
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

    case 'a':
      p_time = XPDEREF(time_t, data, specs[i].offset);
      write_date(fout, state, sep, *p_time);
      break;

    case 'i':
      p_ip = XPDEREF(ej_ip_t, data, specs[i].offset);
      fprintf(fout, "%s'%s'", sep, xml_unparse_ip(*p_ip));
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
  unsigned char cmdbuf[1024];
  int cmdlen, i;

  XCALLOC(iter, 1);
  iter->b = user_id_iterator_funcs;

  snprintf(cmdbuf, sizeof(cmdbuf), "SELECT user_id FROM %slogins WHERE 1 ;",
           state->table_prefix);
  cmdlen = strlen(cmdbuf);
  if (my_query(state, cmdbuf, cmdlen, 1) < 0) goto fail;
  iter->id_num = state->row_count;

  if (iter->id_num > 0) {
    XCALLOC(iter->ids, iter->id_num);
    for (i = 0; i < iter->id_num; i++) {
      if (my_int_val(state, &iter->ids[i], 1) < 0) goto fail;
    }
  }
  my_free_res(state);
  return (int_iterator_t) iter;

 fail:
  my_free_res(state);
  xfree(iter->ids);
  xfree(iter);
  return 0;
}

static int
get_user_by_login_func(void *data, const unsigned char *login)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  int val;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "SELECT user_id FROM %slogins WHERE login = ",
          state->table_prefix);
  write_escaped_string(cmd_f, state, 0, login);
  fprintf(cmd_f, " ;");
  fclose(cmd_f); cmd_f = 0;
  if (my_query_one_row(state, cmd_t, cmd_z, 1) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0;
  if (!state->lengths[0])
    db_inv_value_fail();
  if (parse_int(state->row[0], &val) < 0 || val <= 0)
    db_inv_value_fail();
  my_free_res(state);
  return val;

 fail:
  my_free_res(state);
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
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
  unsigned char cmdbuf[1024];
  struct userlist_user *u = 0;
  int r;
  unsigned char *res = 0;

  if (state->cache_queries) {
    r = fetch_login(state, user_id, &u);
    if (r < 0) return 0;
    if (r > 0 && u) return xstrdup(u->login);
  }

  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT login FROM %slogins WHERE user_id = %d ; ",
           state->table_prefix, user_id);
  cmdlen = strlen(cmdbuf);
  if (my_query_one_row(state, cmdbuf, cmdlen, 1) < 0) goto fail;
  res = xstrdup(state->row[0]);
  my_free_res(state);
  return res;

 fail:
  my_free_res(state);
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
  int val;
  struct userlist_user user;
  FILE *cmd_f = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;

  if (!login || !*login) return -1;

  memset(&user, 0, sizeof(user));

  user.id = -1;
  user.login = (char*) login;
  user.email = (char*) email;
  user.passwd = (char*) passwd;
  user.simple_registration = !!simple_reg_flag;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "INSERT into %slogins VALUES ( ", state->table_prefix);
  unparse_login(state, cmd_f, &user);
  fprintf(cmd_f, " );");
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "SELECT user_id FROM %slogins WHERE login = ",
          state->table_prefix);
  write_escaped_string(cmd_f, state, 0, login);
  fclose(cmd_f); cmd_f = 0;
  if (my_query_one_row(state, cmd_t, cmd_z, 1) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  if (!state->lengths[0])
    db_inv_value_fail();
  if (parse_int(state->row[0], &val) < 0 || val <= 0)
    db_inv_value_fail();
  my_free_res(state);
  return val;

 fail:
  my_free_res(state);
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
remove_user_func(void *data, int user_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  my_simple_fquery(state, "DELETE FROM %scookies WHERE user_id = %d;",
                   state->table_prefix, user_id);
  my_simple_fquery(state, "DELETE FROM %scntsregs WHERE user_id = %d;",
                   state->table_prefix, user_id);
  my_simple_fquery(state, "DELETE FROM %susers WHERE user_id = %d; ",
                   state->table_prefix, user_id);
  my_simple_fquery(state, "DELETE FROM %slogins WHERE user_id = %d;",
                   state->table_prefix, user_id);
  remove_login_from_pool(state, user_id);
  remove_cookie_from_pool_by_uid(state, user_id);
  remove_cntsreg_from_pool_by_uid(state, user_id);
  remove_member_from_pool_by_uid(state, user_id);
  remove_user_info_from_pool_by_uid(state, user_id);
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

  if (state->cache_queries && (c = get_cookie_from_pool(state, value))) {
    *p_cookie = c;
    return 0;
  }

  if (fetch_cookie(state, value, &c) <= 0) return -1;
  if (p_cookie) *p_cookie = c;
  return 0;
}

static int
is_unique_cookie(
        struct uldb_mysql_state *state,
        unsigned long long value)
{
  unsigned char cmdbuf[1024];
  size_t cmdlen;

  if (!value) return 0;
  snprintf(cmdbuf, sizeof(cmdbuf), "SELECT user_id FROM %scookies WHERE cookie = '%016llx' ;", state->table_prefix, value);
  cmdlen = strlen(cmdbuf);
  if (my_query(state, cmdbuf, cmdlen, 1) < 0) return -1;
  if (state->row_count < 0) {
    my_free_res(state);
    return -1;
  }
  if (state->row_count > 0) {
    my_free_res(state);
    return 0;
  }
  my_free_res(state);
  return 1;
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
  FILE *cmd_f = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  struct userlist_cookie *c;
  struct userlist_cookie newc;
  int r;

  if (cookie) {
    if (is_unique_cookie(state, cookie) <= 0) return -1;
  } else {
    do {
      cookie = random_u64();
    } while (!(r = is_unique_cookie(state, cookie)));
    if (r < 0) return -1;
  }
  if (!expire) expire = time(0) + 24 * 60 * 60;

  ASSERT(cookie != 0);
  memset(&newc, 0, sizeof(newc));
  newc.user_id = user_id;
  newc.ip = ip;
  newc.ssl = ssl_flag;
  newc.cookie = cookie;
  newc.expire = expire;
  newc.contest_id = contest_id;
  newc.locale_id = locale_id;
  newc.priv_level = priv_level;
  newc.role = role;
  newc.recovery = recovery;
  newc.team_login = team_login;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %scookies VALUES ( ", state->table_prefix);
  unparse_cookie(state, cmd_f, &newc);
  fprintf(cmd_f, " ) ;");
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0;
  if (fetch_cookie(state, cookie, &c) < 0) goto fail;
  if (p_cookie) *p_cookie = c;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
remove_cookie_func(
        void *data,
        const struct userlist_cookie *c)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned long long val;

  if (!c) return 0;

  val = c->cookie;
  if (my_simple_fquery(state, "DELETE FROM %scookies WHERE cookie = '%016llx';", state->table_prefix, c->cookie) < 0) return -1;
  remove_cookie_from_pool(state, val);
  return 0;
}

static int
remove_user_cookies_func(
        void *data,
        int user_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  if (my_simple_fquery(state, "DELETE FROM %scookies WHERE user_id = %d;",
                       state->table_prefix, user_id) < 0)
    return -1;
  remove_cookie_from_pool_by_uid(state, user_id);
  return 0;
}

static int
remove_expired_cookies_func(
        void *data,
        time_t cur_time)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  FILE *cmd_f = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;

  if (cur_time <= 0) cur_time = time(0);

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "DELETE FROM %scookies WHERE expire < ", state->table_prefix);
  write_timestamp(cmd_f, state, "", cur_time);
  fprintf(cmd_f, " ;");
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t);
  remove_cookie_from_pool_by_expire(state, cur_time);
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
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
  unsigned char cmdbuf[1024];
  int cmdlen;
  struct userlist_contest *c = 0;

  if (iter->cur_i >= iter->id_num) return 0;

  if (state->cache_queries
      && (c=get_cntsreg_from_pool(state,iter->user_id,iter->ids[iter->cur_i]))){
    return (void*) c;
  }

  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT * FROM %scntsregs WHERE user_id = %d AND contest_id = %d ;",
           state->table_prefix, iter->user_id, iter->ids[iter->cur_i]);
  cmdlen = strlen(cmdbuf);
  if (my_query_one_row(state, cmdbuf, cmdlen, COOKIE_WIDTH) < 0) return 0;
  c = allocate_cntsreg_on_pool(state, iter->user_id, iter->ids[iter->cur_i]);
  if (!c) goto fail;
  if (parse_cntsreg(state->field_count,state->row,state->lengths, c) < 0)
    goto fail;
  my_free_res(state);
  return (void*) c;

 fail:
  my_free_res(state);
  return 0;
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
  int cmdlen, i;
  unsigned char cmdbuf[1024];

  XCALLOC(iter, 1);
  iter->b = user_contest_iterator_funcs;
  iter->state = state;
  iter->user_id = user_id;

  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT contest_id FROM %scntsregs WHERE user_id = %d ;",
           state->table_prefix, user_id);
  cmdlen = strlen(cmdbuf);
  if (my_query(state, cmdbuf, cmdlen, 1) < 0) goto fail;
  iter->id_num = state->row_count;

  if (iter->id_num > 0) {
    XCALLOC(iter->ids, iter->id_num);
    for (i = 0; i < iter->id_num; i++) {
      if (my_int_val(state, &iter->ids[i], 1) < 0) goto fail;
    }
  }
  my_free_res(state);
  return (ptr_iterator_t) iter;

 fail:
  my_free_res(state);
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
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  int *ids = 0, i, count;

  if (min_reg_time <= 0) min_reg_time = time(0) - 24 * 60 * 60;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "SELECT user_id FROM %slogins WHERE regtime < ", 
          state->table_prefix);
  write_timestamp(cmd_f, state, "", min_reg_time);
  fprintf(cmd_f, " AND (logintime = NULL OR logintime = 0) ;");
  fclose(cmd_f); cmd_f = 0;

  if (my_query(state, cmd_t, cmd_z, 1) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0;
  count = state->row_count;
  if (!count) {
    my_free_res(state);
    return 0;
  }

  // save the result set into the temp array
  XCALLOC(ids, count);
  for (i = 0; i < count; i++) {
    if (my_int_val(state, &ids[i], 1) < 0) goto fail;
  }
  my_free_res(state);

  for (i = 0; i < count; i++) {
    remove_user_func(data, ids[i]);
  }

  xfree(ids);
  return 0;

 fail:
  my_free_res(state);
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
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
  struct userlist_user *u = 0;

  ASSERT(user_id > 0);

  if (p_user) *p_user = 0;
  if (fetch_login(state, user_id, &u) < 0) goto fail;
  if (p_user) *p_user = u;
  return 1;

 fail:
  remove_login_from_pool(state, user_id);
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
  struct userlist_user *u = 0;
  struct userlist_user_info *ui = 0;

  ASSERT(user_id > 0);
  ASSERT(contest_id >= 0);

  if (fetch_login(state, user_id, &u) < 0) return -1;
  if (fetch_user_info(state, user_id, contest_id, &ui) < 0) return -1;
  if (p_u) *p_u = u;
  if (p_ui) *p_ui = ui;
  return 0;
}

static int
touch_login_time_func(
        void *data,
        int user_id,
        int contest_id,
        time_t cur_time)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  struct userlist_user_info *ui = 0;

  if (cur_time <= 0) cur_time = time(0);

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %slogins SET logintime = ", state->table_prefix);
  write_timestamp(cmd_f, state, 0, cur_time);
  fprintf(cmd_f, " WHERE user_id = %d ;", user_id);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  remove_login_from_pool(state, user_id);

  if (contest_id > 0) {
    fetch_or_create_user_info(state, user_id, contest_id, &ui);
    cmd_f = open_memstream(&cmd_t, &cmd_z);
    fprintf(cmd_f, "UPDATE %susers SET logintime = ", state->table_prefix);
    write_timestamp(cmd_f, state, 0, cur_time);
    fprintf(cmd_f, " WHERE user_id = %d AND contest_id = %d ;",
            user_id, contest_id);
    fclose(cmd_f); cmd_f = 0;
    if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
    xfree(cmd_t); cmd_t = 0; cmd_z = 0;
    remove_user_info_from_pool(state, user_id, contest_id);
  }

  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
get_user_info_3_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_user,
        const struct userlist_user_info **p_info,
        const struct userlist_contest **p_contest)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct userlist_user *u = 0;
  struct userlist_user_info *ui = 0;
  struct userlist_contest *cc = 0;

  if (fetch_login(state, user_id, &u) < 0) return -1;
  if (fetch_user_info(state, user_id, contest_id, &ui) < 0) return -1;
  if (fetch_cntsreg(state, user_id, contest_id, &cc) < 0) return -1;
  if (p_user) *p_user = u;
  if (p_info) *p_info = ui;
  if (p_contest) *p_contest = cc;
  return 0;
}

static int
set_cookie_contest_func(
        void *data,
        const struct userlist_cookie *c,
        int contest_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  if (my_simple_fquery(state, "UPDATE %scookies SET contest_id = %d WHERE cookie = '%016llx' ;", state->table_prefix, contest_id, c->cookie) < 0) return -1;
  remove_cookie_from_pool(state, c->cookie);
  return 0;
}

static int
set_cookie_locale_func(
        void *data,
        const struct userlist_cookie *c,
        int locale_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  if (my_simple_fquery(state, "UPDATE %scookies SET locale_id = %d WHERE cookie = '%016llx' ;", state->table_prefix, locale_id, c->cookie) < 0) return -1;
  remove_cookie_from_pool(state, c->cookie);
  return 0;
}

static int
set_cookie_priv_level_func(
        void *data,
        const struct userlist_cookie *c,
        int priv_level)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  if (my_simple_fquery(state, "UPDATE %scookies SET priv_level = %d WHERE cookie = '%016llx' ;", state->table_prefix, priv_level, c->cookie) < 0)
    return -1;
  remove_cookie_from_pool(state, c->cookie);
  return 0;
}

static int
get_user_info_4_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_user)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct userlist_user *u = 0;
  struct userlist_user_info *ui = 0;
  struct userlist_members *mm = 0;
  struct userlist_contest *uc = 0;

  if (fetch_login(state, user_id, &u) < 0 || !u) return -1;
  if (fetch_member(state, user_id, contest_id, &mm) < 0) return -1;
  if (mm) {
    if (fetch_or_create_user_info(state, user_id, contest_id, &ui) < 0)
      return -1;
  } else {
    if (fetch_user_info(state, user_id, contest_id, &ui) < 0)
      return -1;
  }
  if (fetch_cntsreg(state, user_id, contest_id, &uc) < 0) return -1;
  userlist_attach_user_info(u, ui);
  if (ui) ui->members = mm;
  if (u->contests) {
    u->contests->first_down = u->contests->last_down = 0;
  }
  if (state->locked_user_id > 0) {
    err("user %d was not properly unlocked after %s",
        state->locked_user_id, state->locked_func);
  }
  state->locked_user_id = user_id;
  state->locked_func = "get_user_info_4_func";
  userlist_attach_cntsreg(u, uc);
  if (p_user) *p_user = u;
  return 0;
}

static int
get_user_info_5_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_user)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct userlist_user *u = 0;
  struct userlist_user_info *ui = 0;
  struct userlist_members *mm = 0;
  struct userlist_contest *uc = 0;
  struct userlist_cookie *cc = 0;
  unsigned char cmdbuf[1024];
  size_t cmdlen;
  int cookie_count = 0, reg_count = 0;
  unsigned long long *cookies = 0;
  int *cntsregs = 0;
  int i;
  char *eptr;

  ASSERT(user_id > 0);
  ASSERT(contest_id >= 0);
  if (fetch_login(state, user_id, &u) < 0 || !u) return -1;
  if (fetch_member(state, user_id, contest_id, &mm) < 0) return -1;
  if (mm) {
    if (fetch_or_create_user_info(state, user_id, contest_id, &ui) < 0)
      return -1;
  } else {
    if (fetch_user_info(state, user_id, contest_id, &ui) < 0)
      return -1;
  }
  userlist_attach_user_info(u, ui);
  if (ui) ui->members = mm;

  snprintf(cmdbuf, sizeof(cmdbuf), "SELECT cookie FROM %scookies WHERE user_id = %d ;", state->table_prefix, user_id);
  cmdlen = strlen(cmdbuf);
  if (my_query(state, cmdbuf, cmdlen, 1) < 0) return -1;
  if (state->row_count > 0) {
    cookie_count = state->row_count;
    XALLOCAZ(cookies, cookie_count);
    for (i = 0; i < cookie_count; i++) {
      if (my_row(state) < 0) goto fail;
      if (!state->row[0]) goto fail;
      errno = 0; eptr = 0;
      cookies[i] = strtoull(state->row[0], &eptr, 16);
      if (errno || *eptr) goto fail;
    }
  }
  my_free_res(state);

  snprintf(cmdbuf, sizeof(cmdbuf), "SELECT contest_id FROM %scntsregs WHERE user_id = %d ;", state->table_prefix, user_id);
  cmdlen = strlen(cmdbuf);
  if (my_query(state, cmdbuf, cmdlen, 1) < 0) goto fail;;
  if (state->row_count > 0) {
    reg_count = state->row_count;
    XALLOCAZ(cntsregs, reg_count);
    for (i = 0; i < reg_count; i++) {
      if (my_int_val(state, &cntsregs[i], 0) < 0) goto fail;
    }
  }
  my_free_res(state);

  if (u->cookies) {
    u->cookies->first_down = u->cookies->last_down = 0;
  }
  for (i = 0; i < cookie_count; i++) {
    if (fetch_cookie(state, cookies[i], &cc) < 0) goto fail;
    userlist_attach_cookie(u, cc);
  }

  if (u->contests) {
    u->contests->first_down = u->contests->last_down = 0;
  }
  for (i = 0; i < reg_count; i++) {
    if (fetch_cntsreg(state, user_id, cntsregs[i], &uc) < 0) goto fail;
    userlist_attach_cntsreg(u, uc);
  }

  if (p_user) *p_user = u;
  if (state->locked_user_id > 0) {
    err("user %d was not properly unlocked after %s",
        state->locked_user_id, state->locked_func);
  }
  state->locked_user_id = user_id;
  state->locked_func = "get_user_info_5_func";
  return 0;

 fail:
  my_free_res(state);
  if (u) unlock_user_func(state, u);
  return -1;
}

static void
free_saved_row(struct saved_row *r)
{
  int i;

  if (!r) return;
  for (i = 0; i < r->field_count; i++) {
    xfree(r->row[i]);
    r->row[i] = 0;
  }
  xfree(r->lengths);
  xfree(r->row);
  memset(r, 0, sizeof(*r));
}

static void
copy_saved_row(struct uldb_mysql_state *state, struct saved_row *r)
{
  int i;

  r->field_count = state->field_count;
  if (r->field_count <= 0) return;
  XCALLOC(r->lengths, r->field_count);
  XCALLOC(r->row, r->field_count);
  memcpy(r->lengths, state->lengths, sizeof(r->lengths[0]) * r->field_count);
  for (i = 0; i < r->field_count; i++) {
    if (!state->row[i])
      r->row[i] = 0;
    else
      r->row[i] = xstrdup(state->row[i]);
  }
}

struct user_list_noreg_row
{
  int user_id;
  struct saved_row login_row;
  struct saved_row user_info_row;
};

struct user_list_row
{
  int user_id;
  struct saved_row login_row;
  struct saved_row user_info_row;
  struct saved_row cntsreg_row;
};

struct brief_list_iterator
{
  struct ptr_iterator b;
  struct uldb_mysql_state *state;
  int contest_id;
  int cur_ind;
  int total_ids;
  struct user_list_noreg_row *noreg_rows;
  struct user_list_row *full_rows;
};

static int
brief_list_iterator_has_next_func(ptr_iterator_t data)
{
  struct brief_list_iterator *iter = (struct brief_list_iterator *) data;

  if (!iter) return 0;
  return (iter->cur_ind < iter->total_ids);
}
static const void*
brief_list_iterator_get_func(ptr_iterator_t data)
{
  struct brief_list_iterator *iter = (struct brief_list_iterator *) data;
  struct uldb_mysql_state *state = iter->state;
  int user_id;
  struct userlist_user *u = 0;
  struct userlist_user_info *ui = 0;
  struct userlist_contest *uc = 0;
  struct saved_row *rr;

  if (!iter) return 0;
  if (iter->cur_ind >= iter->total_ids) return 0;

  if (iter->noreg_rows) {
    ASSERT(!iter->contest_id);
    user_id = iter->noreg_rows[iter->cur_ind].user_id;
    if (!(u = get_login_from_pool(state, user_id))) {
      u = allocate_login_on_pool(state, user_id);
      rr = &iter->noreg_rows[iter->cur_ind].login_row;
      if (u && parse_login(rr->field_count, rr->row, rr->lengths, u) < 0) {
        remove_login_from_pool(state, user_id);
        u = 0;
      }
    }
    if (!(ui = get_user_info_from_pool(state, user_id, iter->contest_id))) {
      rr = &iter->noreg_rows[iter->cur_ind].user_info_row;
      if (rr->field_count == USER_INFO_WIDTH) {
        ui = allocate_user_info_on_pool(state, user_id, iter->contest_id);
        if (ui && parse_user_info(rr->field_count,rr->row,rr->lengths,ui) < 0) {
          remove_user_info_from_pool(state, user_id, iter->contest_id);
          ui = 0;
        }
      }
    }
    userlist_attach_user_info(u, ui);
    if (state->locked_user_id > 0) {
      err("user %d was not properly unlocked after %s",
          state->locked_user_id, state->locked_func);
    }
    state->locked_user_id = user_id;
    state->locked_func = __FUNCTION__;
    return u;
  }

  if (iter->full_rows) {
    user_id = iter->full_rows[iter->cur_ind].user_id;
    if (!(u = get_login_from_pool(state, user_id))) {
      u = allocate_login_on_pool(state, user_id);
      rr = &iter->full_rows[iter->cur_ind].login_row;
      if (u && parse_login(rr->field_count, rr->row, rr->lengths, u) < 0) {
        remove_login_from_pool(state, user_id);
        u = 0;
      }
    }
    if (!(ui = get_user_info_from_pool(state, user_id, iter->contest_id))) {
      rr = &iter->full_rows[iter->cur_ind].user_info_row;
      if (rr->field_count == USER_INFO_WIDTH) {
        ui = allocate_user_info_on_pool(state, user_id, iter->contest_id);
        if (ui && parse_user_info(rr->field_count,rr->row,rr->lengths,ui) < 0) {
          remove_user_info_from_pool(state, user_id, iter->contest_id);
          ui = 0;
        }
      }
    }
    if (!(uc = get_cntsreg_from_pool(state, user_id, iter->contest_id))) {
      rr = &iter->full_rows[iter->cur_ind].cntsreg_row;
      if (rr->field_count == CNTSREG_WIDTH) {
        uc = allocate_cntsreg_on_pool(state, user_id, iter->contest_id);
        if (uc && parse_cntsreg(rr->field_count,rr->row,rr->lengths,uc) < 0) {
          remove_cntsreg_from_pool(state, user_id, iter->contest_id);
          uc = 0;
        }
      }
    }
    userlist_attach_user_info(u, ui);
    if (u->contests) {
      u->contests->first_down = u->contests->last_down = 0;
    }
    userlist_attach_cntsreg(u, uc);
    if (state->locked_user_id > 0) {
      err("user %d was not properly unlocked after %s",
          state->locked_user_id, state->locked_func);
    }
    state->locked_user_id = user_id;
    state->locked_func = __FUNCTION__;
    return u;
  }

  return 0;
}
static void
brief_list_iterator_next_func(ptr_iterator_t data)
{
  struct brief_list_iterator *iter = (struct brief_list_iterator *) data;
  if (iter->cur_ind < iter->total_ids) iter->cur_ind++;
}
static void
brief_list_iterator_destroy_func(ptr_iterator_t data)
{
  struct brief_list_iterator *iter = (struct brief_list_iterator *) data;
  int i;

  if (!iter) return;
  if (iter->noreg_rows) {
    for (i = 0; i < iter->total_ids; i++) {
      free_saved_row(&iter->noreg_rows[i].login_row);
      free_saved_row(&iter->noreg_rows[i].user_info_row);
    }
    xfree(iter->noreg_rows);
  }
  if (iter->full_rows) {
    for (i = 0; i < iter->total_ids; i++) {
      free_saved_row(&iter->full_rows[i].login_row);
      free_saved_row(&iter->full_rows[i].user_info_row);
      free_saved_row(&iter->full_rows[i].cntsreg_row);
    }
    xfree(iter->full_rows);
  }
  xfree(iter);
}

static struct ptr_iterator brief_list_iterator_funcs =
{
  brief_list_iterator_has_next_func,
  brief_list_iterator_get_func,
  brief_list_iterator_next_func,
  brief_list_iterator_destroy_func,
};

static ptr_iterator_t
get_brief_list_iterator_func(
        void *data,
        int contest_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct brief_list_iterator *iter = 0;
  int i, val, j;
  unsigned char cmdbuf[1024];
  size_t cmdlen;

  XCALLOC(iter, 1);
  iter->b = brief_list_iterator_funcs;
  iter->state = state;
  iter->contest_id = contest_id;
  iter->cur_ind = 0;

  if (!contest_id) {
    snprintf(cmdbuf, sizeof(cmdbuf),
             "SELECT * FROM %slogins WHERE 1 ORDER BY user_id ;",
             state->table_prefix);
    cmdlen = strlen(cmdbuf);
    if (my_query(state, cmdbuf, cmdlen, LOGIN_WIDTH) < 0) goto fail;
    iter->total_ids = state->row_count;
    if (!iter->total_ids) {
      my_free_res(state);
      return (ptr_iterator_t) iter;
    }

    XCALLOC(iter->noreg_rows, iter->total_ids);
    for (i = 0; i < iter->total_ids; i++) {
      if (!(state->row = mysql_fetch_row(state->res)))
        db_no_data_fail();
      state->lengths = mysql_fetch_lengths(state->res);
      if (!state->lengths[0])
        db_inv_value_fail();
      if (parse_int(state->row[0], &val) < 0 || val <= 0)
        db_inv_value_fail();
      iter->noreg_rows[i].user_id = val;
      copy_saved_row(state, &iter->noreg_rows[i].login_row);
    }

    my_free_res(state);
    snprintf(cmdbuf, sizeof(cmdbuf),
             "SELECT * FROM %susers WHERE contest_id = 0 ORDER BY user_id ;",
             state->table_prefix);
    cmdlen = strlen(cmdbuf);
    if (my_query(state, cmdbuf, cmdlen, USER_INFO_WIDTH) < 0) goto fail;
    j = 0;
    for (i = 0; i < state->row_count; i++) {
      if (!(state->row = mysql_fetch_row(state->res)))
        db_no_data_fail();
      state->lengths = mysql_fetch_lengths(state->res);
      if (!state->lengths[0])
        db_inv_value_fail();
      if (parse_int(state->row[0], &val) < 0 || val <= 0)
        db_inv_value_fail();
      while (j < iter->total_ids && iter->noreg_rows[j].user_id < val) j++;
      if (j < iter->total_ids && iter->noreg_rows[j].user_id == val) {
        copy_saved_row(state, &iter->noreg_rows[j].user_info_row);
      }
    }

    my_free_res(state);
    return (ptr_iterator_t) iter;
  }

  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT %slogins.* FROM %slogins, %scntsregs WHERE %slogins.user_id = %scntsregs.user_id AND %scntsregs.contest_id = %d ORDER BY %slogins.user_id ;",
           state->table_prefix, state->table_prefix, state->table_prefix,
           state->table_prefix, state->table_prefix, state->table_prefix,
           contest_id, state->table_prefix);
  cmdlen = strlen(cmdbuf);
  if (my_query(state, cmdbuf, cmdlen, LOGIN_WIDTH) < 0) goto fail;
  iter->total_ids = state->row_count;
  if (!iter->total_ids) {
    my_free_res(state);
    return (ptr_iterator_t) iter;
  }
  XCALLOC(iter->full_rows, iter->total_ids);
  for (i = 0; i < iter->total_ids; i++) {
    if (!(state->row = mysql_fetch_row(state->res)))
      db_no_data_fail();
    state->lengths = mysql_fetch_lengths(state->res);
    if (!state->lengths[0])
      db_inv_value_fail();
    if (parse_int(state->row[0], &val) < 0 || val <= 0)
      db_inv_value_fail();
    iter->full_rows[i].user_id = val;
    copy_saved_row(state, &iter->full_rows[i].login_row);
  }
  my_free_res(state);

  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT * FROM %susers WHERE contest_id = %d ORDER BY user_id ;",
           state->table_prefix, contest_id);
  cmdlen = strlen(cmdbuf);
  if (my_query(state, cmdbuf, cmdlen, USER_INFO_WIDTH) < 0) goto fail;
  j = 0;
  for (i = 0; i < state->row_count; i++) {
    if (!(state->row = mysql_fetch_row(state->res)))
      db_no_data_fail();
    state->lengths = mysql_fetch_lengths(state->res);
    if (!state->lengths[0])
      db_inv_value_fail();
    if (parse_int(state->row[0], &val) < 0 || val <= 0)
      db_inv_value_fail();
    while (j < iter->total_ids && iter->full_rows[j].user_id < val) j++;
    if (j < iter->total_ids && iter->full_rows[j].user_id == val) {
      copy_saved_row(state, &iter->full_rows[j].user_info_row);
    }
  }
  my_free_res(state);

  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT * FROM %scntsregs WHERE contest_id = %d ORDER BY user_id ;",
           state->table_prefix, contest_id);
  cmdlen = strlen(cmdbuf);
  if (my_query(state, cmdbuf, cmdlen, CNTSREG_WIDTH) < 0) goto fail;
  j = 0;
  for (i = 0; i < state->row_count; i++) {
    if (!(state->row = mysql_fetch_row(state->res)))
      db_no_data_fail();
    state->lengths = mysql_fetch_lengths(state->res);
    if (!state->lengths[0])
      db_inv_value_fail();
    if (parse_int(state->row[0], &val) < 0 || val <= 0)
      db_inv_value_fail();
    while (j < iter->total_ids && iter->full_rows[j].user_id < val) j++;
    if (j < iter->total_ids && iter->full_rows[j].user_id == val) {
      copy_saved_row(state, &iter->full_rows[j].cntsreg_row);
    }
  }
  my_free_res(state);

  return (ptr_iterator_t) iter;

 fail:
  my_free_res(state);
  brief_list_iterator_destroy_func((ptr_iterator_t) iter);
  return 0;
}

static struct userlist_members *
collect_members(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id,
        struct saved_row *beg,
        struct saved_row *end)
{
  struct userlist_members *mm = 0;
  struct userlist_member *m = 0;

  if (beg >= end) return 0;

  if (!(mm = allocate_member_on_pool(state, user_id, contest_id)))
    return 0;
  userlist_members_reserve(mm, end - beg);
  for (; beg < end; beg++) {
    m = (struct userlist_member*) userlist_node_alloc(USERLIST_T_MEMBER);
    xml_link_node_last(&mm->b, &m->b);
    mm->m[mm->u++] = m;
    if (parse_member(beg->field_count, beg->row, beg->lengths, m) < 0)
      goto fail;
  }
  return mm;

 fail:
  remove_member_from_pool(state, user_id, contest_id);
  return 0;
}

struct standings_list_iterator
{
  struct ptr_iterator b;
  struct uldb_mysql_state *state;
  int contest_id;
  int cur_ind;
  int total_ids;
  struct user_list_row *full_rows;
  int total_membs;
  struct saved_row *memb_rows;
  int *memb_ids;
  int cur_memb;
};

static int
standings_list_iterator_has_next_func(ptr_iterator_t data)
{
  struct standings_list_iterator *iter = (struct standings_list_iterator *)data;
  return (iter->cur_ind < iter->total_ids);
}
static const void*
standings_list_iterator_get_func(ptr_iterator_t data)
{
  struct standings_list_iterator *iter = (struct standings_list_iterator *)data;
  struct uldb_mysql_state *state = iter->state;
  int user_id, i;
  struct userlist_user *u = 0;
  struct userlist_user_info *ui = 0;
  struct userlist_contest *uc = 0;
  struct userlist_members *mm = 0;
  struct saved_row *rr;

  if (iter->cur_ind >= iter->total_ids) return 0;
  if (!iter->full_rows) return 0;

  user_id = iter->full_rows[iter->cur_ind].user_id;
  if (!(u = get_login_from_pool(state, user_id))) {
    u = allocate_login_on_pool(state, user_id);
    rr = &iter->full_rows[iter->cur_ind].login_row;
    if (u && parse_login(rr->field_count, rr->row, rr->lengths, u) < 0) {
      remove_login_from_pool(state, user_id);
      u = 0;
    }
  }
  if (!(ui = get_user_info_from_pool(state, user_id, iter->contest_id))) {
    rr = &iter->full_rows[iter->cur_ind].user_info_row;
    if (rr->field_count == USER_INFO_WIDTH) {
      ui = allocate_user_info_on_pool(state, user_id, iter->contest_id);
      if (ui && parse_user_info(rr->field_count,rr->row,rr->lengths,ui) < 0){
        remove_user_info_from_pool(state, user_id, iter->contest_id);
        ui = 0;
      }
    }
  }
  if (!(uc = get_cntsreg_from_pool(state, user_id, iter->contest_id))) {
    rr = &iter->full_rows[iter->cur_ind].cntsreg_row;
    if (rr->field_count == CNTSREG_WIDTH) {
      uc = allocate_cntsreg_on_pool(state, user_id, iter->contest_id);
      if (uc && parse_cntsreg(rr->field_count,rr->row,rr->lengths,uc) < 0) {
        remove_cntsreg_from_pool(state, user_id, iter->contest_id);
        uc = 0;
      }
    }
  }
  while (iter->cur_memb < iter->total_membs
         && iter->memb_ids[iter->cur_memb] < user_id)
    iter->cur_memb++;
  if (iter->cur_memb < iter->total_membs
      && iter->memb_ids[iter->cur_memb] == user_id) {
    for (i = iter->cur_memb;
         i < iter->total_membs && iter->memb_ids[i] == user_id;
         i++);
    mm = collect_members(state, user_id, iter->contest_id,
                         iter->memb_rows + iter->cur_memb,
                         iter->memb_rows + i);
    iter->cur_memb = i;
    if (mm && !ui && fetch_or_create_user_info(state,user_id,iter->contest_id,&ui)<0)
      return 0;
  }

  if (ui) ui->members = mm;
  userlist_attach_user_info(u, ui);
  if (u->contests) {
    u->contests->first_down = u->contests->last_down = 0;
  }
  userlist_attach_cntsreg(u, uc);
  if (state->locked_user_id > 0) {
    err("user %d was not properly unlocked after %s",
        state->locked_user_id, state->locked_func);
  }
  state->locked_user_id = user_id;
  state->locked_func = __FUNCTION__;
  return u;
}
static void
standings_list_iterator_next_func(ptr_iterator_t data)
{
  struct standings_list_iterator *iter = (struct standings_list_iterator *)data;
  if (iter->cur_ind < iter->total_ids) iter->cur_ind++;
}
static void
standings_list_iterator_destroy_func(ptr_iterator_t data)
{
  struct standings_list_iterator *iter =(struct standings_list_iterator *)data;
  int i;

  if (!iter) return;
  if (iter->full_rows) {
    for (i = 0; i < iter->total_ids; i++) {
      free_saved_row(&iter->full_rows[i].login_row);
      free_saved_row(&iter->full_rows[i].user_info_row);
      free_saved_row(&iter->full_rows[i].cntsreg_row);
    }
    xfree(iter->full_rows);
  }
  if (iter->memb_rows) {
    for (i = 0; i < iter->total_membs; i++)
      free_saved_row(&iter->memb_rows[i]);
  }
  xfree(iter->memb_rows);
  xfree(iter->memb_ids);
  xfree(iter);
}

static struct ptr_iterator standings_list_iterator_funcs =
{
  standings_list_iterator_has_next_func,
  standings_list_iterator_get_func,
  standings_list_iterator_next_func,
  standings_list_iterator_destroy_func,
};

static ptr_iterator_t
get_standings_list_iterator_func(
        void *data,
        int contest_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct standings_list_iterator *iter = 0;
  int i, j, val;
  unsigned char cmdbuf[1024];
  size_t cmdlen;

  ASSERT(contest_id > 0);

  XCALLOC(iter, 1);
  iter->b = standings_list_iterator_funcs;
  iter->state = state;
  iter->contest_id = contest_id;
  iter->cur_ind = 0;
  iter->cur_memb = 0;

  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT %slogins.* FROM %slogins, %scntsregs WHERE %slogins.user_id = %scntsregs.user_id AND %scntsregs.contest_id = %d ORDER BY %slogins.user_id ;",
           state->table_prefix, state->table_prefix, state->table_prefix,
           state->table_prefix, state->table_prefix, state->table_prefix,
           contest_id, state->table_prefix);
  cmdlen = strlen(cmdbuf);
  if (my_query(state, cmdbuf, cmdlen, LOGIN_WIDTH) < 0) goto fail;
  iter->total_ids = state->row_count;
  if (!iter->total_ids) {
    my_free_res(state);
    return (ptr_iterator_t) iter;
  }
  XCALLOC(iter->full_rows, iter->total_ids);
  for (i = 0; i < iter->total_ids; i++) {
    if (!(state->row = mysql_fetch_row(state->res)))
      db_no_data_fail();
    state->lengths = mysql_fetch_lengths(state->res);
    if (!state->lengths[0])
      db_inv_value_fail();
    if (parse_int(state->row[0], &val) < 0 || val <= 0)
      db_inv_value_fail();
    iter->full_rows[i].user_id = val;
    copy_saved_row(state, &iter->full_rows[i].login_row);
  }
  my_free_res(state);

  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT * FROM %susers WHERE contest_id = %d ORDER BY user_id ;",
           state->table_prefix, contest_id);
  cmdlen = strlen(cmdbuf);
  if (my_query(state, cmdbuf, cmdlen, USER_INFO_WIDTH) < 0) goto fail;
  j = 0;
  for (i = 0; i < state->row_count; i++) {
    if (!(state->row = mysql_fetch_row(state->res)))
      db_no_data_fail();
    state->lengths = mysql_fetch_lengths(state->res);
    if (!state->lengths[0])
      db_inv_value_fail();
    if (parse_int(state->row[0], &val) < 0 || val <= 0)
      db_inv_value_fail();
    while (j < iter->total_ids && iter->full_rows[j].user_id < val) j++;
    if (j < iter->total_ids && iter->full_rows[j].user_id == val) {
      copy_saved_row(state, &iter->full_rows[j].user_info_row);
    }
  }
  my_free_res(state);

  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT * FROM %scntsregs WHERE contest_id = %d ORDER BY user_id ;",
           state->table_prefix, contest_id);
  cmdlen = strlen(cmdbuf);
  if (my_query(state, cmdbuf, cmdlen, CNTSREG_WIDTH) < 0) goto fail;
  j = 0;
  for (i = 0; i < state->row_count; i++) {
    if (!(state->row = mysql_fetch_row(state->res)))
      db_no_data_fail();
    state->lengths = mysql_fetch_lengths(state->res);
    if (!state->lengths[0])
      db_inv_value_fail();
    if (parse_int(state->row[0], &val) < 0 || val <= 0)
      db_inv_value_fail();
    while (j < iter->total_ids && iter->full_rows[j].user_id < val) j++;
    if (j < iter->total_ids && iter->full_rows[j].user_id == val) {
      copy_saved_row(state, &iter->full_rows[j].cntsreg_row);
    }
  }
  my_free_res(state);

  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT * FROM %smembers WHERE contest_id = %d ORDER BY user_id ;",
           state->table_prefix, contest_id);
  cmdlen = strlen(cmdbuf);
  if (my_query(state, cmdbuf, cmdlen, MEMBER_WIDTH) < 0) goto fail;
  iter->total_membs = state->row_count;
  if (iter->total_membs > 0) {
    XCALLOC(iter->memb_rows, iter->total_membs);
    XCALLOC(iter->memb_ids, iter->total_membs);
    for (i = 0; i < iter->total_membs; i++) {
      if (my_row(state) < 0) goto fail;
      if (parse_int(state->row[1], &val) < 0 || val <= 0)
        db_inv_value_fail();
      iter->memb_ids[i] = val;
      copy_saved_row(state, &iter->memb_rows[i]);
    }
  }
  my_free_res(state);

  return (ptr_iterator_t) iter;

 fail:
  my_free_res(state);
  standings_list_iterator_destroy_func((ptr_iterator_t) iter);
  return 0;
}

static int
check_user_func(
        void *data,
        int user_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char cmdbuf[1024];
  int cmdlen;
  struct userlist_user *u = 0;

  if (state->cache_queries && (u = get_login_from_pool(state, user_id)))
    return 0;

  snprintf(cmdbuf, sizeof(cmdbuf), "SELECT user_id FROM %slogins WHERE user_id = %d ;", state->table_prefix, user_id);
  cmdlen = strlen(cmdbuf);
  if (my_query(state, cmdbuf, cmdlen, 1) < 0) {
    my_free_res(state);
    return -1;
  }
  if (state->row_count <= 0) {
    my_free_res(state);
    return -1;
  }
  my_free_res(state);
  return 0;
}

static int
set_reg_passwd_func(
        void *data,
        int user_id,
        int method,
        const unsigned char *password,
        time_t cur_time)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  if (cur_time <= 0) cur_time = time(0);

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %slogins SET pwdmethod = %d, password = ",
          state->table_prefix, method);
  write_escaped_string(cmd_f, state, 0, password);
  fprintf(cmd_f, ", pwdtime = ");
  write_timestamp(cmd_f, state, 0, cur_time);
  fprintf(cmd_f, " WHERE user_id = %d ;", user_id);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  remove_login_from_pool(state, user_id);
  return 0;

 fail:
  remove_login_from_pool(state, user_id);
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
set_team_passwd_func(
        void *data,
        int user_id,
        int contest_id,
        int method,
        const unsigned char *password,
        time_t cur_time,
        int *p_cloned_flag)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  if (cur_time <= 0) cur_time = time(0);

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %susers SET pwdmethod = %d, password = ",
          state->table_prefix, method);
  write_escaped_string(cmd_f, state, 0, password);
  fprintf(cmd_f, ", pwdtime = ");
  write_timestamp(cmd_f, state, 0, cur_time);
  fprintf(cmd_f, " WHERE user_id = %d AND contest_id = %d;",
          user_id, contest_id);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  remove_user_info_from_pool(state, user_id, contest_id);
  if (p_cloned_flag) *p_cloned_flag = 0;
  return 0;

 fail:
  remove_user_info_from_pool(state, user_id, contest_id);
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
register_contest_func(
        void *data,
        int user_id,
        int contest_id,
        int status,
        time_t cur_time,
        const struct userlist_contest **p_c)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  struct userlist_contest new_uc;
  struct userlist_contest *c = 0;
  int r;

  if (user_id <= 0 || contest_id <= 0) return -1;
  if (cur_time <= 0) cur_time = time(0);

  if ((r = fetch_cntsreg(state, user_id, contest_id, &c)) < 0) goto fail;
  if (r > 0) return 0;

  memset(&new_uc, 0, sizeof(new_uc));
  new_uc.id = contest_id;
  new_uc.status = status;
  new_uc.create_time = cur_time;
  new_uc.last_change_time = cur_time;
  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %scntsregs VALUES (", state->table_prefix);
  unparse_cntsreg(state, cmd_f, user_id, &new_uc);
  fprintf(cmd_f, " );");
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0;

  if (fetch_cntsreg(state, user_id, contest_id, &c) < 0) goto fail;
  if (p_c) *p_c = c;
  return 1;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
remove_member_func(
        void *data,
        int user_id,
        int contest_id,
        int serial,
        time_t cur_time,
        int *p_cloned_flag)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  if (my_simple_fquery(state, "DELETE FROM %smembers WHERE user_id = %d AND contest_id = %d AND serial = %d ;", state->table_prefix, user_id, contest_id, serial) < 0) return -1;
  remove_member_from_pool(state, user_id, contest_id);
  if (p_cloned_flag) *p_cloned_flag = 0;
  return 0;
}

static int
is_read_only_func(
        void *data,
        int user_id,
        int contest_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct userlist_user *u = 0;
  struct userlist_user_info *ui = 0;

  if (fetch_login(state, user_id, &u) < 0) return -1;
  if (u->read_only) return 1;
  if (fetch_user_info(state, user_id, contest_id, &ui) < 0) return -1;
  if (ui->cnts_read_only) return 1;
  return 0;
}

struct info_list_iterator
{
  struct ptr_iterator b;
  struct uldb_mysql_state *state;
  int contest_id;
  int cur_ind;
  int total_ids;
  struct user_list_row *full_rows;
  int total_membs;
  struct saved_row *memb_rows;
  int *memb_ids;
  int cur_memb;
};

static int
info_list_iterator_has_next_func(ptr_iterator_t data)
{
  struct info_list_iterator *iter = (struct info_list_iterator *) data;
  return (iter->cur_ind < iter->total_ids);
}
static const void*
info_list_iterator_get_func(ptr_iterator_t data)
{
  struct info_list_iterator *iter = (struct info_list_iterator *) data;
  struct uldb_mysql_state *state = iter->state;
  int user_id, i;
  struct userlist_user *u = 0;
  struct userlist_user_info *ui = 0;
  struct userlist_contest *uc = 0;
  struct userlist_members *mm = 0;
  struct saved_row *rr;

  if (iter->cur_ind >= iter->total_ids) return 0;
  if (!iter->full_rows) return 0;

  user_id = iter->full_rows[iter->cur_ind].user_id;
  if (!(u = get_login_from_pool(state, user_id))) {
    u = allocate_login_on_pool(state, user_id);
    rr = &iter->full_rows[iter->cur_ind].login_row;
    if (u && parse_login(rr->field_count, rr->row, rr->lengths, u) < 0) {
      remove_login_from_pool(state, user_id);
      u = 0;
    }
  }
  if (!(ui = get_user_info_from_pool(state, user_id, iter->contest_id))) {
    rr = &iter->full_rows[iter->cur_ind].user_info_row;
    if (rr->field_count == USER_INFO_WIDTH) {
      ui = allocate_user_info_on_pool(state, user_id, iter->contest_id);
      if (ui && parse_user_info(rr->field_count,rr->row,rr->lengths,ui) < 0){
        remove_user_info_from_pool(state, user_id, iter->contest_id);
        ui = 0;
      }
    }
  }
  if (!(uc = get_cntsreg_from_pool(state, user_id, iter->contest_id))) {
    rr = &iter->full_rows[iter->cur_ind].cntsreg_row;
    if (rr->field_count == CNTSREG_WIDTH) {
      uc = allocate_cntsreg_on_pool(state, user_id, iter->contest_id);
      if (uc && parse_cntsreg(rr->field_count,rr->row,rr->lengths,uc) < 0) {
        remove_cntsreg_from_pool(state, user_id, iter->contest_id);
        uc = 0;
      }
    }
  }
  while (iter->cur_memb < iter->total_membs
         && iter->memb_ids[iter->cur_memb] < user_id)
    iter->cur_memb++;
  if (iter->cur_memb < iter->total_membs
      && iter->memb_ids[iter->cur_memb] == user_id) {
    for (i = iter->cur_memb;
         i < iter->total_membs && iter->memb_ids[i] == user_id;
         i++);
    mm = collect_members(state, user_id, iter->contest_id,
                         iter->memb_rows + iter->cur_memb,
                         iter->memb_rows + i);
    iter->cur_memb = i;
    if (mm && !ui && fetch_or_create_user_info(state,user_id,iter->contest_id,&ui)<0)
      return 0;
  }

  if (ui) ui->members = mm;
  userlist_attach_user_info(u, ui);
  if (u->contests) {
    u->contests->first_down = u->contests->last_down = 0;
  }
  userlist_attach_cntsreg(u, uc);
  if (state->locked_user_id > 0) {
    err("user %d was not properly unlocked after %s",
        state->locked_user_id, state->locked_func);
  }
  state->locked_user_id = user_id;
  state->locked_func = __FUNCTION__;
  return u;
}
static void
info_list_iterator_next_func(ptr_iterator_t data)
{
  struct info_list_iterator *iter = (struct info_list_iterator *) data;
  if (iter->cur_ind < iter->total_ids) iter->cur_ind++;
}
static void
info_list_iterator_destroy_func(ptr_iterator_t data)
{
  struct info_list_iterator *iter = (struct info_list_iterator *) data;
  int i;

  if (!iter) return;
  if (iter->full_rows) {
    for (i = 0; i < iter->total_ids; i++) {
      free_saved_row(&iter->full_rows[i].login_row);
      free_saved_row(&iter->full_rows[i].user_info_row);
      free_saved_row(&iter->full_rows[i].cntsreg_row);
    }
    xfree(iter->full_rows);
  }
  if (iter->memb_rows) {
    for (i = 0; i < iter->total_membs; i++)
      free_saved_row(&iter->memb_rows[i]);
  }
  xfree(iter->memb_rows);
  xfree(iter->memb_ids);
  xfree(iter);
}

static struct ptr_iterator info_list_iterator_funcs =
{
  info_list_iterator_has_next_func,
  info_list_iterator_get_func,
  info_list_iterator_next_func,
  info_list_iterator_destroy_func,
};

static ptr_iterator_t
get_info_list_iterator_func(
        void *data,
        int contest_id,
        unsigned flag_mask)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct info_list_iterator *iter = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  int i, val, j;
  unsigned char cmdbuf[1024];
  size_t cmdlen;

  ASSERT(contest_id > 0);
  flag_mask &= USERLIST_UC_ALL;

  XCALLOC(iter, 1);
  iter->b = info_list_iterator_funcs;
  iter->state = state;
  iter->contest_id = contest_id;
  iter->cur_ind = 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "SELECT %slogins.* FROM %slogins, %scntsregs AS R WHERE %slogins.user_id = R.user_id AND R.contest_id = %d ", state->table_prefix, state->table_prefix, state->table_prefix, state->table_prefix, contest_id);
  if (!flag_mask) {
    fprintf(cmd_f, " AND R.banned = 0 AND R.invisible = 0 AND R.locked = 0 AND R.incomplete = 0 AND R.disqualified = 0 ");
  } else if (flag_mask != USERLIST_UC_ALL) {
    fprintf(cmd_f, " AND ((R.banned = 0 AND R.invisible = 0 AND R.locked = 0 AND R.incomplete = 0 AND R.disqualified = 0) ");
    if ((flag_mask & USERLIST_UC_BANNED))
      fprintf(cmd_f, " OR R.banned = 1 ");
    if ((flag_mask & USERLIST_UC_INVISIBLE))
      fprintf(cmd_f, " OR R.invisible = 1 ");
    if ((flag_mask & USERLIST_UC_LOCKED))
      fprintf(cmd_f, " OR R.locked = 1 ");
    if ((flag_mask & USERLIST_UC_INCOMPLETE))
      fprintf(cmd_f, " OR R.incomplete = 1 ");
    if ((flag_mask & USERLIST_UC_DISQUALIFIED))
      fprintf(cmd_f, " OR R.disqualified = 1 ");
    fprintf(cmd_f, ") ");
  }
  fprintf(cmd_f, "ORDER BY %slogins.user_id ; ", state->table_prefix);
  fclose(cmd_f); cmd_f = 0;
  if (my_query(state, cmd_t, cmd_z, LOGIN_WIDTH) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  iter->total_ids = state->row_count;
  if (!iter->total_ids) {
    my_free_res(state);
    return (ptr_iterator_t) iter;
  }
  XCALLOC(iter->full_rows, iter->total_ids);
  for (i = 0; i < iter->total_ids; i++) {
    if (!(state->row = mysql_fetch_row(state->res)))
      db_no_data_fail();
    state->lengths = mysql_fetch_lengths(state->res);
    if (!state->lengths[0])
      db_inv_value_fail();
    if (parse_int(state->row[0], &val) < 0 || val <= 0)
      db_inv_value_fail();
    iter->full_rows[i].user_id = val;
    copy_saved_row(state, &iter->full_rows[i].login_row);
  }
  my_free_res(state);

  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT * FROM %susers WHERE contest_id = %d ORDER BY user_id ;",
           state->table_prefix, contest_id);
  cmdlen = strlen(cmdbuf);
  if (my_query(state, cmdbuf, cmdlen, USER_INFO_WIDTH) < 0) goto fail;
  j = 0;
  for (i = 0; i < state->row_count; i++) {
    if (!(state->row = mysql_fetch_row(state->res)))
      db_no_data_fail();
    state->lengths = mysql_fetch_lengths(state->res);
    if (!state->lengths[0])
      db_inv_value_fail();
    if (parse_int(state->row[0], &val) < 0 || val <= 0)
      db_inv_value_fail();
    while (j < iter->total_ids && iter->full_rows[j].user_id < val) j++;
    if (j < iter->total_ids && iter->full_rows[j].user_id == val) {
      copy_saved_row(state, &iter->full_rows[j].user_info_row);
    }
  }
  my_free_res(state);

  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT * FROM %scntsregs WHERE contest_id = %d ORDER BY user_id ;",
           state->table_prefix, contest_id);
  cmdlen = strlen(cmdbuf);
  if (my_query(state, cmdbuf, cmdlen, CNTSREG_WIDTH) < 0) goto fail;
  j = 0;
  for (i = 0; i < state->row_count; i++) {
    if (!(state->row = mysql_fetch_row(state->res)))
      db_no_data_fail();
    state->lengths = mysql_fetch_lengths(state->res);
    if (!state->lengths[0])
      db_inv_value_fail();
    if (parse_int(state->row[0], &val) < 0 || val <= 0)
      db_inv_value_fail();
    while (j < iter->total_ids && iter->full_rows[j].user_id < val) j++;
    if (j < iter->total_ids && iter->full_rows[j].user_id == val) {
      copy_saved_row(state, &iter->full_rows[j].cntsreg_row);
    }
  }
  my_free_res(state);

  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT * FROM %smembers WHERE contest_id = %d ORDER BY user_id ;",
           state->table_prefix, contest_id);
  cmdlen = strlen(cmdbuf);
  if (my_query(state, cmdbuf, cmdlen, MEMBER_WIDTH) < 0) goto fail;
  iter->total_membs = state->row_count;
  if (iter->total_membs > 0) {
    XCALLOC(iter->memb_rows, iter->total_membs);
    XCALLOC(iter->memb_ids, iter->total_membs);
    for (i = 0; i < iter->total_membs; i++) {
      if (my_row(state) < 0) goto fail;
      if (parse_int(state->row[1], &val) < 0 || val <= 0)
        db_inv_value_fail();
      iter->memb_ids[i] = val;
      copy_saved_row(state, &iter->memb_rows[i]);
    }
  }
  my_free_res(state);

  return (ptr_iterator_t) iter;

 fail:
  my_free_res(state);
  info_list_iterator_destroy_func((ptr_iterator_t) iter);
  return 0;
}

static int
clear_team_passwd_func(
        void *data,
        int user_id,
        int contest_id,
        int *p_cloned_flag)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  if (my_simple_fquery(state, "UPDATE %susers SET password = NULL, pwdmethod = 0 WHERE user_id = %d AND contest_id = %d ;", state->table_prefix, user_id, contest_id) < 0) return -1;
  if (p_cloned_flag) *p_cloned_flag = 0;
  remove_user_info_from_pool(state, user_id, contest_id);
  return 0;
}

static int
remove_registration_func(
        void *data,
        int user_id,
        int contest_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  if (my_simple_fquery(state, "DELETE FROM %scntsregs WHERE user_id = %d AND contest_id = %d ;", state->table_prefix, user_id, contest_id) < 0)
    return -1;
  remove_cntsreg_from_pool(state, user_id, contest_id);
  return 0;
}

static int
set_reg_status_func(
        void *data,
        int user_id,
        int contest_id,
        int status)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  ASSERT(user_id > 0);
  ASSERT(contest_id > 0);
  ASSERT(status >= 0 && status < USERLIST_REG_LAST);

  if (my_simple_fquery(state, "UPDATE %scntsregs SET status = %d WHERE user_id = %d AND contest_id = %d ;", state->table_prefix, status, user_id, contest_id) < 0)
    return -1;
  remove_cntsreg_from_pool(state, user_id, contest_id);
  return 0;
}

static int
set_reg_flags_func(
        void *data,
        int user_id,
        int contest_id,
        int cmd,
        unsigned int value)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  const unsigned char *sep = " ";

  ASSERT(user_id > 0);
  ASSERT(contest_id > 0);
  ASSERT(cmd >= 0 && cmd <= 3);
  value &= USERLIST_UC_ALL;

  if (!cmd || !value) return 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %scntsregs SET ", state->table_prefix);
  switch (cmd) {
  case 1:                       /* set */
    if ((value & USERLIST_UC_INVISIBLE)) {
      fprintf(cmd_f, "%sinvisible = 1", sep);
      sep = ", ";
    }
    if ((value & USERLIST_UC_BANNED)) {
      fprintf(cmd_f, "%sbanned = 1", sep);
      sep = ", ";
    }
    if ((value & USERLIST_UC_LOCKED)) {
      fprintf(cmd_f, "%slocked = 1", sep);
      sep = ", ";
    }
    if ((value & USERLIST_UC_INCOMPLETE)) {
      fprintf(cmd_f, "%sincomplete = 1", sep);
      sep = ", ";
    }
    if ((value & USERLIST_UC_DISQUALIFIED)) {
      fprintf(cmd_f, "%sdisqualified = 1", sep);
      sep = ", ";
    }
    break;
  case 2:                       /* clear */
    if ((value & USERLIST_UC_INVISIBLE)) {
      fprintf(cmd_f, "%sinvisible = 0", sep);
      sep = ", ";
    }
    if ((value & USERLIST_UC_BANNED)) {
      fprintf(cmd_f, "%sbanned = 0", sep);
      sep = ", ";
    }
    if ((value & USERLIST_UC_LOCKED)) {
      fprintf(cmd_f, "%slocked = 0", sep);
      sep = ", ";
    }
    if ((value & USERLIST_UC_INCOMPLETE)) {
      fprintf(cmd_f, "%sincomplete = 0", sep);
      sep = ", ";
    }
    if ((value & USERLIST_UC_DISQUALIFIED)) {
      fprintf(cmd_f, "%sdisqualified = 0", sep);
      sep = ", ";
    }
    break;
  case 3:                       /* flip */
    if ((value & USERLIST_UC_INVISIBLE)) {
      fprintf(cmd_f, "%sinvisible = 1 - invisible", sep);
      sep = ", ";
    }
    if ((value & USERLIST_UC_BANNED)) {
      fprintf(cmd_f, "%sbanned = 1 - banned", sep);
      sep = ", ";
    }
    if ((value & USERLIST_UC_LOCKED)) {
      fprintf(cmd_f, "%slocked = 1 - locked", sep);
      sep = ", ";
    }
    if ((value & USERLIST_UC_INCOMPLETE)) {
      fprintf(cmd_f, "%sincomplete = 1 - incomplete", sep);
      sep = ", ";
    }
    if ((value & USERLIST_UC_DISQUALIFIED)) {
      fprintf(cmd_f, "%sdisqualified = 1 - disqualified", sep);
      sep = ", ";
    }
    break;
  default:
    abort();
  }
  fprintf(cmd_f, " WHERE user_id = %d AND contest_id = %d ;",
          user_id, contest_id);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  remove_cntsreg_from_pool(state, user_id, contest_id);
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
remove_user_contest_info_func(
        void *data,
        int user_id,
        int contest_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  ASSERT(user_id > 0);
  ASSERT(contest_id >= 0);

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "DELETE FROM %susers WHERE user_id = %d AND contest_id = %d ;",
          state->table_prefix, user_id, contest_id);
  fprintf(cmd_f, "DELETE FROM %smembers WHERE user_id = %d AND contest_id = %d ;",
          state->table_prefix, user_id, contest_id);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  remove_user_info_from_pool(state, user_id, contest_id);
  remove_member_from_pool(state, user_id, contest_id);
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

#include "fields.inc.c"

static int
clear_user_field_func(
        void *data,
        int user_id,
        int field_id,
        time_t cur_time)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  const unsigned char *sep = ", ";
  const unsigned char *tsvarname = "changetime";

  ASSERT(user_id > 0);
  ASSERT(field_id >= USERLIST_NN_FIRST && field_id < USERLIST_NN_LAST);

  if (!fields[field_id].sql_name) return -1;

  if (cur_time <= 0) cur_time = time(0);

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %slogins SET ", state->table_prefix);
  switch (fields[field_id].field_type) {
  case USERLIST_NN_IS_PRIVILEGED:
    fprintf(cmd_f, "%s = 0", fields[field_id].sql_name);
    break;
  case USERLIST_NN_SHOW_LOGIN:
    sep = "";
    break;
  case USERLIST_NN_LOGIN:
    goto fail;
  case USERLIST_NN_EMAIL:
    fprintf(cmd_f, "%s = NULL", fields[field_id].sql_name);
    break;
  case USERLIST_NN_PASSWD:
    fprintf(cmd_f, "password = NULL, pwdmethod = 0");
    break;
  case USERLIST_NN_REGISTRATION_TIME:
    fprintf(cmd_f, "%s = 0", fields[field_id].sql_name);
    break;
  case USERLIST_NN_LAST_CHANGE_TIME:
    sep = "";
    break;
  case USERLIST_NN_LAST_PWDCHANGE_TIME:
    sep = "";
    tsvarname = "pwdtime";
    break;
  default:
    abort();
  }
  fprintf(cmd_f, "%s%s = ", sep, tsvarname);
  write_timestamp(cmd_f, state, 0, cur_time);
  fprintf(cmd_f, " WHERE user_id = %d ;", user_id);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  remove_login_from_pool(state, user_id);
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
clear_user_info_field_func(
        void *data,
        int user_id,
        int contest_id,
        int field_id,
        time_t cur_time,
        int *p_cloned_flag)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  const unsigned char *sep = ", ";
  const unsigned char *tsvarname = "changetime";

  ASSERT(user_id > 0);
  ASSERT(contest_id >= 0);
  ASSERT(field_id >= USERLIST_NC_FIRST && field_id < USERLIST_NC_LAST);
  if (!fields[field_id].sql_name) return -1;
  if (cur_time <= 0) cur_time = time(0);

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %susers SET ", state->table_prefix);
  switch (fields[field_id].field_type) {
  case USERLIST_NC_CNTS_READ_ONLY:
    fprintf(cmd_f, "%s = 0", fields[field_id].sql_name);
    break;
  case USERLIST_NC_NAME:
    fprintf(cmd_f, "%s = NULL", fields[field_id].sql_name);
    break;
  case USERLIST_NC_TEAM_PASSWD:
    fprintf(cmd_f, "password = NULL, pwdmethod = 0");
    break;
  case USERLIST_NC_INSTNUM:
    fprintf(cmd_f, "%s = -1", fields[field_id].sql_name);
    break;
  case USERLIST_NC_INST:
    fprintf(cmd_f, "%s = NULL", fields[field_id].sql_name);
    break;
  case USERLIST_NC_CREATE_TIME:
    fprintf(cmd_f, "%s = 0", fields[field_id].sql_name);
    break;
  case USERLIST_NC_LAST_CHANGE_TIME:
    sep = "";
    break;
  case USERLIST_NC_LAST_PWDCHANGE_TIME:
    sep = "";
    tsvarname = "pwdtime";
    break;
  default:
    abort();
  }
  fprintf(cmd_f, "%s%s = ", sep, tsvarname);
  write_timestamp(cmd_f, state, 0, cur_time);
  fprintf(cmd_f, " WHERE user_id = %d AND contest_id = %d;",
          user_id, contest_id);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  remove_user_info_from_pool(state, user_id, contest_id);
  if (p_cloned_flag) *p_cloned_flag = 0;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
clear_user_member_field_func(
        void *data,
        int user_id,
        int contest_id,
        int serial,
        int field_id,
        time_t cur_time,
        int *p_cloned_flag)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  const unsigned char *sep = ", ";

  ASSERT(user_id > 0);
  ASSERT(contest_id >= 0);
  ASSERT(serial > 0);
  ASSERT(field_id >= USERLIST_NM_FIRST && field_id < USERLIST_NM_LAST);
  if (!fields[field_id].sql_name) return -1;
  if (cur_time <= 0) cur_time = time(0);

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %smembers SET ", state->table_prefix);
  switch (fields[field_id].field_type) {
  case USERLIST_NM_STATUS:
    fprintf(cmd_f, "%s = 0", fields[field_id].sql_name);
    break;
  case USERLIST_NM_GENDER:
    fprintf(cmd_f, "%s = 0", fields[field_id].sql_name);
    break;
  case USERLIST_NM_GRADE:
    fprintf(cmd_f, "%s = 0", fields[field_id].sql_name);
    break;
  case USERLIST_NM_FIRSTNAME:
    fprintf(cmd_f, "%s = NULL", fields[field_id].sql_name);
    break;
  case USERLIST_NM_CREATE_TIME:
    fprintf(cmd_f, "%s = 0", fields[field_id].sql_name);
    break;
  case USERLIST_NM_LAST_CHANGE_TIME:
    sep = "";
    break;
  case USERLIST_NM_BIRTH_DATE:
    fprintf(cmd_f, "%s = 0", fields[field_id].sql_name);
    break;
  default:
    abort();
  }
  fprintf(cmd_f, "%s%s = ", sep, "changetime");
  write_timestamp(cmd_f, state, 0, cur_time);
  fprintf(cmd_f, " WHERE serial = %d ;", serial);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  remove_member_from_pool(state, user_id, contest_id);
  if (p_cloned_flag) *p_cloned_flag = 0;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
set_user_field_func(
        void *data,
        int user_id,
        int field_id,
        const unsigned char *value,
        time_t cur_time)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  const unsigned char *sep = ", ";
  const unsigned char *tsvarname = "changetime";
  struct userlist_user arena;
  void *p_field;
  int v_int;
  time_t v_time;

  ASSERT(user_id > 0);
  ASSERT(field_id >= USERLIST_NN_FIRST && field_id < USERLIST_NN_LAST);
  if (!fields[field_id].sql_name) return -1;
  if (cur_time <= 0) cur_time = time(0);
  memset(&arena, 0, sizeof(arena));
  arena.b.tag = USERLIST_T_USER;
  if (!(p_field = userlist_get_user_field_ptr(&arena, field_id))) goto fail;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %slogins SET ", state->table_prefix);
  switch (fields[field_id].field_type) {
  case USERLIST_NN_IS_PRIVILEGED:
    if (userlist_set_user_field_str(&arena, field_id, value) < 0) goto fail;
    v_int = *(int*) p_field;
    fprintf(cmd_f, "%s = %d", fields[field_id].sql_name, v_int);
    break;
  case USERLIST_NN_SHOW_LOGIN:
    sep = "";
    break;
  case USERLIST_NN_LOGIN:
    if (!value) goto fail;
    if ((v_int = get_user_by_login_func(data, value)) > 0
        && v_int != user_id)
      goto fail;
    fprintf(cmd_f, "%s = ", fields[field_id].sql_name);
    write_escaped_string(cmd_f, state, 0, value);
    break;
  case USERLIST_NN_EMAIL:
    fprintf(cmd_f, "%s = ", fields[field_id].sql_name);
    write_escaped_string(cmd_f, state, 0, value);
    break;
  case USERLIST_NN_PASSWD:
    write_escaped_string(cmd_f, state, "password = ", value);
    fprintf(cmd_f, ", pwdmethod = 0");
    tsvarname = "pwdtime";
    break;
  case USERLIST_NN_REGISTRATION_TIME:
    if (userlist_set_user_field_str(&arena, field_id, value) < 0) goto fail;
    v_time = *(time_t*) p_field;
    fprintf(cmd_f, "%s = ", fields[field_id].sql_name);
    write_timestamp(cmd_f, state, 0, v_time);
    break;
  case USERLIST_NN_LAST_CHANGE_TIME:
    sep = "";
    break;
  case USERLIST_NN_LAST_PWDCHANGE_TIME:
    sep = "";
    tsvarname = "pwdtime";
    break;
  default:
    abort();
  }
  fprintf(cmd_f, "%s%s = ", sep, tsvarname);
  write_timestamp(cmd_f, state, 0, cur_time);
  fprintf(cmd_f, " WHERE user_id = %d ;", user_id);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  remove_login_from_pool(state, user_id);
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
set_user_info_field_func(
        void *data,
        int user_id,
        int contest_id,
        int field_id,
        const unsigned char *value,
        time_t cur_time,
        int *p_cloned_flag)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  const unsigned char *sep = ", ";
  const unsigned char *tsvarname = "changetime";
  struct userlist_user_info arena;
  struct userlist_user_info *ui = 0;
  void *p_field;
  int v_int;
  time_t v_time;

  ASSERT(user_id > 0);
  ASSERT(contest_id >= 0);
  ASSERT(field_id >= USERLIST_NC_FIRST && field_id < USERLIST_NC_LAST);
  if (!fields[field_id].sql_name) return -1;
  if (cur_time <= 0) cur_time = time(0);

  if (fetch_or_create_user_info(state, user_id, contest_id, &ui) < 0)
    goto fail;

  memset(&arena, 0, sizeof(arena));
  arena.b.tag = USERLIST_T_CNTSINFO;
  if (!(p_field = userlist_get_user_info_field_ptr(&arena, field_id)))
    goto fail;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %susers SET ", state->table_prefix);
  switch (fields[field_id].field_type) {
  case USERLIST_NC_CNTS_READ_ONLY:
    if (userlist_set_user_info_field_str(&arena, field_id, value) < 0)
      goto fail;
    v_int = *(int*) p_field;
    fprintf(cmd_f, "%s = %d", fields[field_id].sql_name, v_int);
    break;
  case USERLIST_NC_NAME:
    fprintf(cmd_f, "%s = ", fields[field_id].sql_name);
    write_escaped_string(cmd_f, state, 0, value);
    break;
  case USERLIST_NC_TEAM_PASSWD:
    write_escaped_string(cmd_f, state, "password = ", value);
    fprintf(cmd_f, ", pwdmethod = 0");
    tsvarname = "pwdtime";
    break;
  case USERLIST_NC_INSTNUM:
    if (userlist_set_user_info_field_str(&arena, field_id, value) < 0)
      goto fail;
    v_int = *(int*) p_field;
    fprintf(cmd_f, "%s = %d", fields[field_id].sql_name, v_int);
    break;
  case USERLIST_NC_INST:
    fprintf(cmd_f, "%s = ", fields[field_id].sql_name);
    write_escaped_string(cmd_f, state, 0, value);
    break;
  case USERLIST_NC_CREATE_TIME:
    if (userlist_set_user_info_field_str(&arena, field_id, value) < 0)
      goto fail;
    v_time = *(time_t*) p_field;
    fprintf(cmd_f, "%s = ", fields[field_id].sql_name);
    write_timestamp(cmd_f, state, 0, v_time);
    break;
  case USERLIST_NC_LAST_CHANGE_TIME:
    sep = "";
    break;
  case USERLIST_NC_LAST_PWDCHANGE_TIME:
    sep = "";
    tsvarname = "pwdtime";
    break;
  default:
    abort();
  }
  fprintf(cmd_f, "%s%s = ", sep, tsvarname);
  write_timestamp(cmd_f, state, 0, cur_time);
  fprintf(cmd_f, " WHERE user_id = %d AND contest_id = %d;",
          user_id, contest_id);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  remove_user_info_from_pool(state, user_id, contest_id);
  if (p_cloned_flag) *p_cloned_flag = 0;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
set_user_member_field_func(
        void *data,
        int user_id,
        int contest_id,
        int serial,
        int field_id,
        const unsigned char *value,
        time_t cur_time,
        int *p_cloned_flag)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  const unsigned char *sep = ", ";
  struct userlist_member arena;
  struct userlist_user_info *ui = 0;
  void *p_field;
  int v_int;
  time_t v_time;

  ASSERT(user_id > 0);
  ASSERT(contest_id >= 0);
  ASSERT(serial > 0);
  ASSERT(field_id >= USERLIST_NM_FIRST && field_id < USERLIST_NM_LAST);
  if (!fields[field_id].sql_name) return -1;
  if (cur_time <= 0) cur_time = time(0);

  if (fetch_or_create_user_info(state, user_id, contest_id, &ui) < 0)
    goto fail;

  memset(&arena, 0, sizeof(arena));
  arena.b.tag = USERLIST_T_CNTSINFO;
  if (!(p_field = userlist_get_member_field_ptr(&arena, field_id)))
    goto fail;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %smembers SET ", state->table_prefix);
  switch (fields[field_id].field_type) {
  case USERLIST_NM_STATUS:
  case USERLIST_NM_GENDER:
  case USERLIST_NM_GRADE:
    if (userlist_set_member_field_str(&arena, field_id, value) < 0)
      goto fail;
    v_int = *(int*) p_field;
    fprintf(cmd_f, "%s = %d", fields[field_id].sql_name, v_int);
    break;
  case USERLIST_NM_FIRSTNAME:
    fprintf(cmd_f, "%s = ", fields[field_id].sql_name);
    write_escaped_string(cmd_f, state, 0, value);
    break;
  case USERLIST_NM_CREATE_TIME:
    if (userlist_set_member_field_str(&arena, field_id, value) < 0)
      goto fail;
    v_time = *(time_t*) p_field;
    fprintf(cmd_f, "%s = ", fields[field_id].sql_name);
    write_timestamp(cmd_f, state, 0, v_time);
    break;
  case USERLIST_NM_LAST_CHANGE_TIME:
    sep = "";
    break;
  case USERLIST_NM_BIRTH_DATE:
    if (userlist_set_member_field_str(&arena, field_id, value) < 0)
      goto fail;
    v_time = *(time_t*) p_field;
    fprintf(cmd_f, "%s = ", fields[field_id].sql_name);
    write_date(cmd_f, state, 0, v_time);
    break;
  default:
    abort();
  }
  fprintf(cmd_f, "%s%s = ", sep, "changetime");
  write_timestamp(cmd_f, state, 0, cur_time);
  fprintf(cmd_f, " WHERE serial = %d ;", serial);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  remove_member_from_pool(state, user_id, contest_id);
  if (p_cloned_flag) *p_cloned_flag = 0;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
new_member_func(
        void *data,
        int user_id,
        int contest_id,
        int role,
        time_t cur_time,
        int *p_cloned_flag)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char cmdbuf[1024];
  size_t cmdlen;
  int current_member = 0;
  struct userlist_member arena;

  ASSERT(user_id > 0);
  ASSERT(contest_id >= 0);
  ASSERT(role >= 0 && role < USERLIST_MB_LAST);
  if (cur_time <= 0) cur_time = time(0);
  memset(&arena, 0, sizeof(arena));

  snprintf(cmdbuf, sizeof(cmdbuf), "SELECT config_val FROM %sconfig WHERE config_key = 'current_member' ;", state->table_prefix);
  cmdlen = strlen(cmdbuf);
  if (my_query_one_row(state, cmdbuf, cmdlen, 1) < 0) goto fail;
  if (!state->row[0]) goto fail;
  if (parse_int(state->row[0], &current_member) < 0) goto fail;
  if (current_member < 1) goto fail;
  arena.team_role = role;
  arena.serial = current_member;
  arena.grade = -1;
  arena.create_time = cur_time;
  arena.last_change_time = cur_time;
  if (insert_member_info(state, user_id, contest_id, &arena, 0) < 0) goto fail;
  current_member++;
  my_free_res(state);
  if (my_simple_fquery(state, "UPDATE %sconfig SET config_val = '%d' WHERE config_key = 'current_member' ;", state->table_prefix, current_member) < 0) goto fail;
  remove_member_from_pool(state, user_id, contest_id);
  return current_member;
  
 fail:
  return -1;
}

static int
maintenance_func(
        void *data,
        time_t cur_time)
{
  return 0;
}

static int
set_user_xml_func(
        void *data,
        int user_id,
        int contest_id,
        struct userlist_user *new_u,
        time_t cur_time,
        int *p_cloned_flag)
{
  fprintf(stderr, "uldb_mysql: set_user_xml: unimplemented\n");
  abort();
}

static const int copy_user_general_fields[] =
{
  USERLIST_NC_INST,
  USERLIST_NC_INST_EN,
  USERLIST_NC_INSTSHORT,
  USERLIST_NC_INSTSHORT_EN,
  USERLIST_NC_FAC,
  USERLIST_NC_FAC_EN,
  USERLIST_NC_FACSHORT,
  USERLIST_NC_FACSHORT_EN,
  USERLIST_NC_HOMEPAGE,
  USERLIST_NC_CITY,
  USERLIST_NC_CITY_EN,
  USERLIST_NC_COUNTRY,
  USERLIST_NC_COUNTRY_EN,
  USERLIST_NC_REGION,
  USERLIST_NC_AREA,
  USERLIST_NC_ZIP,
  USERLIST_NC_STREET,
  USERLIST_NC_LANGUAGES,
  USERLIST_NC_PHONE,
  USERLIST_NC_FIELD0,
  USERLIST_NC_FIELD1,
  USERLIST_NC_FIELD2,
  USERLIST_NC_FIELD3,
  USERLIST_NC_FIELD4,
  USERLIST_NC_FIELD5,
  USERLIST_NC_FIELD6,
  USERLIST_NC_FIELD7,
  USERLIST_NC_FIELD8,
  USERLIST_NC_FIELD9,

  0
};
static const int copy_user_member_fields[] =
{
  USERLIST_NM_FIRSTNAME,
  USERLIST_NM_FIRSTNAME_EN,
  USERLIST_NM_MIDDLENAME,
  USERLIST_NM_MIDDLENAME_EN,
  USERLIST_NM_SURNAME,
  USERLIST_NM_SURNAME_EN,
  USERLIST_NM_GROUP,
  USERLIST_NM_GROUP_EN,
  USERLIST_NM_EMAIL,
  USERLIST_NM_HOMEPAGE,
  USERLIST_NM_OCCUPATION,
  USERLIST_NM_OCCUPATION_EN,
  USERLIST_NM_DISCIPLINE,
  USERLIST_NM_INST,
  USERLIST_NM_INST_EN,
  USERLIST_NM_INSTSHORT,
  USERLIST_NM_INSTSHORT_EN,
  USERLIST_NM_FAC,
  USERLIST_NM_FAC_EN,
  USERLIST_NM_FACSHORT,
  USERLIST_NM_FACSHORT_EN,
  USERLIST_NM_PHONE,

  0
};
static int
copy_user_info_func(
        void *data,
        int user_id,
        int from_cnts,
        int to_cnts,
        int copy_passwd_flag,
        time_t cur_time,
        const struct contest_desc *cnts)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char cmdbuf[1024];
  size_t cmdlen;
  struct userlist_user_info *ui = 0;
  struct userlist_members *mm = 0;
  struct userlist_member *m;
  struct userlist_user_info u_arena;
  struct userlist_member m_arena;
  int i, j, k, cur_memb;
  unsigned char **p_str_to, **p_str_from;
  int m_max[USERLIST_MB_LAST];
  int m_cur[USERLIST_MB_LAST];
  const struct contest_member *cm;
  int current_member = 0;

  ASSERT(user_id > 0);
  ASSERT(from_cnts >= 0);
  ASSERT(to_cnts >= 0);
  if (cur_time <= 0) cur_time = time(0);
  if (from_cnts == to_cnts) return 0;

  if (my_simple_fquery(state, "DELETE FROM %susers WHERE user_id = %d AND contest_id = %d ;", state->table_prefix, user_id, to_cnts) < 0) goto fail;
  if (my_simple_fquery(state, "DELETE FROM %smembers WHERE user_id = %d AND contest_id = %d ;", state->table_prefix, user_id, to_cnts) < 0) goto fail;

  if (fetch_user_info(state, user_id, from_cnts, &ui) < 0) goto fail;
  if (fetch_member(state, user_id, from_cnts, &mm) < 0) goto fail;

  memset(&u_arena, 0, sizeof(u_arena));
  u_arena.contest_id = to_cnts;
  u_arena.instnum = -1;
  if (ui) {
    if (!cnts || cnts->fields[CONTEST_F_INSTNUM]) {
      u_arena.instnum = ui->instnum;
    }
    if ((!cnts || !cnts->disable_name) && ui->name && *ui->name) {
      u_arena.name = ui->name;
    }
    if ((!cnts || !cnts->disable_team_password)) {
      u_arena.team_passwd_method = ui->team_passwd_method;
      u_arena.team_passwd = ui->team_passwd;
    }
    for (i = 0; copy_user_general_fields[i]; i++) {
      j = copy_user_general_fields[i];
      k = userlist_map_userlist_to_contest_field(j);
      p_str_to = (unsigned char**)userlist_get_user_info_field_ptr(&u_arena,j);
      if (cnts && !cnts->fields[k]) continue;
      p_str_from = (unsigned char**) userlist_get_user_info_field_ptr(ui, j);
      *p_str_to = *p_str_from;
    }
    u_arena.spelling = ui->spelling;
  }
  u_arena.create_time = cur_time;
  u_arena.last_change_time = cur_time;
  if (insert_contest_info(state, user_id, to_cnts, &u_arena, NULL) < 0)
    goto fail;
  memset(&u_arena, 0, sizeof(u_arena));

  if (mm) {
    memset(m_max, 0, sizeof(m_max));
    memset(m_cur, 0, sizeof(m_cur));

    for (i = 0; i < mm->u; i++) {
      m = mm->m[i];
      ASSERT(m);
      ASSERT(m->team_role >= 0 && m->team_role < USERLIST_MB_LAST);
      m_max[m->team_role]++;
    }

    if (cnts) {
      for (i = 0; i < USERLIST_MB_LAST; i++)
        if (!cnts->members[i]) {
          m_max[i] = 0;
        } else if (cnts->members[i]->max_count > m_max[i]) {
          m_max[i] = cnts->members[i]->max_count;
        }
    }

    for (cur_memb = 0; cur_memb < mm->u; cur_memb++) {
      m = mm->m[cur_memb];
      if (m_cur[m->team_role] >= m_max[m->team_role]) continue;
      m_cur[m->team_role]++;
      cm = 0;
      if (cnts) {
        cm = cnts->members[cur_memb];
        ASSERT(cm);
      }

      if (current_member <= 0) {
        snprintf(cmdbuf, sizeof(cmdbuf), "SELECT config_val FROM %sconfig WHERE config_key = 'current_member' ;", state->table_prefix);
        cmdlen = strlen(cmdbuf);
        if (my_query_one_row(state, cmdbuf, cmdlen, 1) < 0) goto fail;
        if (my_int_val(state, &current_member, 1) < 0) goto fail;
      }
      my_free_res(state);

      memset(&m_arena, 0, sizeof(m_arena));
      m_arena.serial = current_member++;
      m_arena.team_role = m->team_role;
      if (!cm || cm->fields[CONTEST_MF_STATUS])
        m_arena.status = m->status;
      if (!cm || cm->fields[CONTEST_MF_GENDER])
        m_arena.gender = m->gender;
      if (!cm || cm->fields[CONTEST_MF_GRADE])
        m_arena.grade = m->grade;
      for (i = 0; copy_user_member_fields[i]; i++) {
        j = copy_user_member_fields[i];
        k = userlist_member_map_userlist_to_contest_field(j);
        p_str_to=(unsigned char**)userlist_get_member_field_ptr(&m_arena,j);
        if (cm && !cm->fields[k]) continue;
        p_str_from = (unsigned char**) userlist_get_member_field_ptr(m, j);
        *p_str_to = *p_str_from;
      }
      if (!cm || cm->fields[CONTEST_MF_BIRTH_DATE])
        m_arena.birth_date = m->birth_date;
      if (!cm || cm->fields[CONTEST_MF_ENTRY_DATE])
        m_arena.entry_date = m->entry_date;
      if (!cm || cm->fields[CONTEST_MF_GRADUATION_DATE])
        m_arena.graduation_date = m->graduation_date;
      m_arena.create_time = cur_time;
      m_arena.last_change_time = cur_time;
      if (insert_member_info(state, user_id, to_cnts, &m_arena, 0) < 0)
        goto fail;
      memset(&m_arena, 0, sizeof(m_arena));
    }
  }

  if (current_member > 0) {
    if (my_simple_fquery(state, "UPDATE %sconfig SET config_val = '%d' WHERE config_key = 'current_member' ;", state->table_prefix, current_member) < 0) goto fail;
  }

  remove_user_info_from_pool(state, user_id, to_cnts);
  remove_member_from_pool(state, user_id, to_cnts);
  return 0;

 fail:
  return -1;
}

static int
check_user_reg_data_func(
        void *data,
        int user_id,
        int contest_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct userlist_user *u = 0;
  struct userlist_user_info *ui = 0;
  struct userlist_members *mm = 0;
  struct userlist_contest *c = 0;
  const struct contest_desc *cnts = 0;
  int memb_errs[CONTEST_LAST_MEMBER + 1];
  int nerr, val = 0;

  if (contests_get(contest_id, &cnts) < 0 || !cnts) return -1;
  if (fetch_login(state, user_id, &u) < 0) return -1;
  if (fetch_user_info(state, user_id, contest_id, &ui) < 0) return -1;
  if (fetch_member(state, user_id, contest_id, &mm) < 0) return -1;
  if (fetch_cntsreg(state, user_id, contest_id, &c) < 0) return -1;

  if (!c || (c->status!=USERLIST_REG_OK && c->status != USERLIST_REG_PENDING))
    return -1;

  nerr = userlist_count_info_errors(cnts, u, ui, mm, memb_errs);
  if (ui && ui->name && *ui->name && check_str(ui->name, name_accept_chars))
    nerr++;

  if (!nerr && (c->flags & USERLIST_UC_INCOMPLETE)) {
    val = 0;
  } else if (nerr > 0 && !(c->flags & USERLIST_UC_INCOMPLETE)
             && (!ui || !ui->cnts_read_only)) {
    val = 1;
  } else {
    return 0;
  }

  if (my_simple_fquery(state, "UPDATE %scntsregs SET incomplete = %d WHERE user_id = %d AND contest_id = %d ;", state->table_prefix, val, user_id, contest_id) < 0) return -1;
  remove_cntsreg_from_pool(state, user_id, contest_id);
  return 1;
}

static int
move_member_func(
        void *data,
        int user_id,
        int contest_id,
        int serial,
        int new_role,
        time_t cur_time,
        int *p_cloned_flag)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  ASSERT(user_id > 0);
  ASSERT(contest_id >= 0);
  ASSERT(serial > 0);
  ASSERT(new_role >= 0 && new_role < USERLIST_MB_LAST);
  if (cur_time <= 0) cur_time = time(0);

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %smembers SET role_id = %d, changetime = ",
          state->table_prefix, new_role);
  write_timestamp(cmd_f, state, 0, cur_time);
  fprintf(cmd_f, " WHERE serial = %d ; ", serial);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  my_free_res(state);
  remove_member_from_pool(state, user_id, contest_id);
  if (p_cloned_flag) *p_cloned_flag = 0;
  return 0;

 fail:
  my_free_res(state);
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
set_cookie_team_login_func(
        void *data,
        const struct userlist_cookie *c,
        int team_login)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  if (state->cache_queries && c->team_login == team_login) return 0;

  ASSERT(team_login >= 0 && team_login <= 1);
  if (my_simple_fquery(state, "UPDATE %scookies SET team_login = %d WHERE cookie = '%016llx' ;", state->table_prefix, team_login, c->cookie) < 0) return -1;
  remove_cookie_from_pool(state, c->cookie);
  return 0;
}

static int
get_user_info_6_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_user,
        const struct userlist_user_info **p_info,
        const struct userlist_contest **p_contest,
        const struct userlist_members **p_members)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct userlist_user *u = 0;
  struct userlist_user_info *ui = 0;
  struct userlist_contest *c = 0;
  struct userlist_members *mm = 0;

  if (fetch_login(state, user_id, &u) < 0) return -1;
  if (fetch_user_info(state, user_id, contest_id, &ui) < 0) return -1;
  if (fetch_cntsreg(state, user_id, contest_id, &c) < 0) return -1;
  if (fetch_member(state, user_id, contest_id, &mm) < 0) return -1;

  if (p_user) *p_user = u;
  if (p_info) *p_info = ui;
  if (p_contest) *p_contest = c;
  if (p_members) *p_members = mm;

  if (state->locked_user_id > 0) {
    err("user %d was not properly unlocked after %s",
        state->locked_user_id, state->locked_func);
  }
  state->locked_user_id = user_id;
  state->locked_func = __FUNCTION__;
  return 0;
}

static int
get_user_info_7_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_user,
        const struct userlist_user_info **p_info,
        const struct userlist_members **p_members)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct userlist_user *u = 0;
  struct userlist_user_info *ui = 0;
  struct userlist_members *mm = 0;

  if (fetch_login(state, user_id, &u) < 0) return -1;
  if (fetch_user_info(state, user_id, contest_id, &ui) < 0) return -1;
  if (fetch_member(state, user_id, contest_id, &mm) < 0) return -1;

  if (p_user) *p_user = u;
  if (p_info) *p_info = ui;
  if (p_members) *p_members = mm;

  if (state->locked_user_id > 0) {
    err("user %d was not properly unlocked after %s",
        state->locked_user_id, state->locked_func);
  }
  state->locked_user_id = user_id;
  state->locked_func = __FUNCTION__;
  return 0;
}

static int
get_member_serial_func(void *data)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  size_t cmdlen;
  unsigned char cmdbuf[1024];
  int current_member = -1;

  snprintf(cmdbuf, sizeof(cmdbuf), "SELECT config_val FROM %sconfig WHERE config_key = 'current_member' ;", state->table_prefix);
  cmdlen = strlen(cmdbuf);
  if (my_query_one_row(state, cmdbuf, cmdlen, 1) < 0) goto fail;
  if (my_int_val(state, &current_member, 1) < 0) goto fail;
  my_free_res(state);
  return current_member;

 fail:
  my_free_res(state);
  return -1;
}

static int
set_member_serial_func(void *data, int new_serial)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  if (my_simple_fquery(state, "UPDATE %sconfig SET config_val = '%d' WHERE config_key = 'current_member' ;", state->table_prefix, new_serial) < 0) return -1;
  return 0;
}

static void
unlock_user_func(
        void *data,
        const struct userlist_user *c_u)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  int i;
  struct userlist_user *u = (struct userlist_user*) c_u;
  struct xml_tree *p, *q;
  struct userlist_user_info *ui = 0;

  if (!c_u) return;

  // detach all existing user_infos
  for (i = 0; i < u->cntsinfo_a; i++) {
    if (!(ui = u->cntsinfo[i])) continue;
    ui->members = 0;
    u->cntsinfo[i] = 0;
  }
  xfree(u->cntsinfo);
  u->cntsinfo = 0;
  u->cntsinfo_a = 0;
  u->cnts0 = 0;

  // detach all existing cntsregs
  if (u->contests) {
    for (p = u->contests->first_down; p; p = q) {
      q = p->right;
      p->left = p->right = 0;
    }
    u->contests->first_down = 0;
    u->contests->last_down = 0;
    xml_unlink_node(u->contests);
    userlist_free(u->contests);
    u->contests = 0;
  }

  // detach the cookies
  if (u->cookies) {
    for (p = u->cookies->first_down; p; p = q) {
      q = p->right;
      p->left = p->right = 0;
    }
    u->cookies->first_down = 0;
    u->cookies->last_down = 0;
    xml_unlink_node(u->cookies);
    userlist_free(u->cookies);
    u->cookies = 0;
  }
  state->locked_user_id = 0;
  state->locked_func = 0;
}

static const struct userlist_contest *
get_contest_reg_func(
        void *data,
        int user_id,
        int contest_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct userlist_contest *uc = 0;

  if (fetch_cntsreg(state, user_id, contest_id, &uc) < 0) return 0;
  return uc;
}

/*
 * Local variables:
 *  compile-command: "make -C ../.."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "MYSQL")
 * End:
 */
