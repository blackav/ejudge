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
static int
touch_login_time_func(
        void *data,
        int user_id,
        int contest_id,
        time_t cur_time);
static int
get_user_info_3_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_user,
        const struct userlist_user_info **p_info,
        const struct userlist_contest **p_contest);
static int
set_cookie_contest_func(
        void *data,
        const struct userlist_cookie *c,
        int contest_id);
static int
set_cookie_locale_func(
        void *data,
        const struct userlist_cookie *c,
        int locale_id);
static int
set_cookie_priv_level_func(
        void *data,
        const struct userlist_cookie *c,
        int priv_level);
static int
get_user_info_4_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_user);
static int
get_user_info_5_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_user);
static ptr_iterator_t
get_brief_list_iterator_func(
        void *data,
        int contest_id);
static ptr_iterator_t
get_standings_list_iterator_func(
        void *data,
        int contest_id);
static int
check_user_func(
        void *data,
        int user_id);
static int
set_reg_passwd_func(
        void *data,
        int user_id,
        int method,
        const unsigned char *password,
        time_t cur_time);
static int
set_team_passwd_func(
        void *data,
        int user_id,
        int contest_id,
        int method,
        const unsigned char *password,
        time_t cur_time,
        int *p_cloned_flag);
static int
register_contest_func(
        void *data,
        int user_id,
        int contest_id,
        int status,
        time_t cur_time,
        const struct userlist_contest **p_c);
static int
remove_member_func(
        void *data,
        int user_id,
        int contest_id,
        int serial,
        time_t cur_time,
        int *p_cloned_flag);
static int
is_read_only_func(
        void *data,
        int user_id,
        int contest_id);
static ptr_iterator_t
get_info_list_iterator_func(
        void *data,
        int contest_id,
        unsigned flag_mask);
static int
clear_team_passwd_func(
        void *data,
        int user_id,
        int contest_id,
        int *p_cloned_flag);
static int
remove_registration_func(
        void *data,
        int user_id,
        int contest_id);
static int
set_reg_status_func(
        void *data,
        int user_id,
        int contest_id,
        int status);
static int
set_reg_flags_func(
        void *data,
        int user_id,
        int contest_id,
        int cmd,
        unsigned int value);
static int
remove_user_contest_info_func(
        void *data,
        int user_id,
        int contest_id);
static int
clear_user_field_func(
        void *data,
        int user_id,
        int field_id,
        time_t cur_time);
static int
clear_user_field_func(
        void *data,
        int user_id,
        int field_id,
        time_t cur_time);

static void
unlock_user_func(
        void *data,
        const struct userlist_user *c_u)
  __attribute__((unused));

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

  /*
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
  // set the member serial number
  int (*set_member_serial)(void *, int);
  // unlock the complete user information structure
  void (*unlock_user)(void *, const struct userlist_user *);
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
  int nocache;

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
  if (!u->contests) {
    u->contests = userlist_node_alloc(USERLIST_T_CONTESTS);
  }
  xml_link_node_last(u->contests, &c->b);
}

static void
userlist_attach_cookie(struct userlist_user *u, struct userlist_cookie *c)
  __attribute__((unused));
static void
userlist_attach_cookie(
        struct userlist_user *u,
        struct userlist_cookie *c)
{
  if (!u->cookies) {
    u->cookies = userlist_node_alloc(USERLIST_T_COOKIES);
  }
  xml_link_node_last(u->cookies, &c->b);
}

static void*
init_func(const struct ejudge_cfg *config)
{
  struct uldb_mysql_state *state;

  XCALLOC(state, 1);
  state->show_queries = 1;
  state->nocache = 1;
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
    if (my_simple_query(state, cmdbuf, cmdlen) < 0) return -1;
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
  if (my_simple_query(state, cmdbuf, cmdlen) < 0) {
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
    buflen = snprintf(buf, bufsize, cmdstr, state->table_prefix);
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

  if (pfx) pfx = "";
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
  fprintf(cmd_f, " )");
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
  unparse_user_info(state, cmd_f, user_id, contest_id, info);
  fprintf(cmd_f, " )");
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
  fprintf(cmd_f, " )");
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
  fprintf(cmd_f, " )");
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
  unsigned char cmd[1024];
  int cmdlen, i;

  XCALLOC(iter, 1);
  iter->b = user_id_iterator_funcs;

  cmdlen = snprintf(cmd, sizeof(cmd),
                    "SELECT user_id FROM %slogins WHERE 1 ;",
                    state->table_prefix);
  if (my_query(state, cmd, cmdlen, 1) < 0) goto fail;
  iter->id_num = state->row_count;

  if (iter->id_num > 0) {
    XCALLOC(iter->ids, iter->id_num);
    for (i = 0; i < iter->id_num; i++) {
      if (my_int_val(state, &iter->ids[i], 1) < 0) goto fail;
    }
  }
  return (int_iterator_t) iter;

 fail:
  xfree(iter->ids);
  xfree(iter);
  return 0;
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
  if (my_query_one_row(state, cmd, cmdlen, 1) < 0) goto fail;
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
  if (my_query_one_row(state, cmd, cmdlen, 1) < 0) goto fail;
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
  fprintf(cmd_f, "SELECT user_id FROM %slogins WHERE login = '",
          state->table_prefix);
  write_escaped_string(cmd_f, state, 0, login);
  fclose(cmd_f); cmd_f = 0;
  if (my_query_one_row(state, cmd_t, cmd_z, 1) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  if (!state->lengths[0])
    db_inv_value_fail();
  if (parse_int(state->row[0], &val) < 0 || val <= 0)
    db_inv_value_fail();
  
  return val;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
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
  if (my_simple_query(state, cmd, cmdlen) < 0) return -1;
  // FIXME: update local cache
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
  FILE *cmd_f = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  struct userlist_cookie *c;
  struct userlist_cookie newc;

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
  unsigned char cmd[1024];
  int cmdlen;

  if (!c) return 0;

  cmdlen = sizeof(cmd);
  cmdlen = snprintf(cmd, cmdlen, "DELETE FROM %scookies WHERE cookie = %llu;", state->table_prefix, c->cookie);
  if (my_simple_query(state, cmd, cmdlen) < 0) return -1;
  // FIXME: update local cache
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
  if (my_simple_query(state, cmd, cmdlen) < 0) return -1;
  // FIXME: update local cache
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
  fprintf(cmd_f, "DELETE FROM %scookies WHERE expire >= ",
          state->table_prefix);
  write_timestamp(cmd_f, state, "", cur_time);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t);
  // FIXME: update local cache
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
  unsigned char cmd[1024];
  int cmdlen = sizeof(cmd);
  struct userlist_contest *c = 0;

  if (iter->cur_i >= iter->id_num) return 0;
  cmdlen = snprintf(cmd, cmdlen, "SELECT * FROM %scntsregs WHERE user_id = %d AND contest_id = %d ;", state->table_prefix, iter->user_id, iter->ids[iter->cur_i]);
  if (my_query_one_row(state, cmd, cmdlen, COOKIE_WIDTH) < 0) return 0;
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
  int cmdlen, i;
  unsigned char cmd[1024];

  XCALLOC(iter, 1);
  iter->b = user_contest_iterator_funcs;
  iter->state = state;
  iter->user_id = user_id;

  cmdlen = sizeof(cmd);
  cmdlen = snprintf(cmd, cmdlen,
                    "SELECT contest_id FROM %scntsregs WHERE user_id = %d ;",
                    state->table_prefix, user_id);
  if (my_query(state, cmd, cmdlen, 1) < 0) goto fail;
  iter->id_num = state->row_count;

  if (iter->id_num > 0) {
    XCALLOC(iter->ids, iter->id_num);
    for (i = 0; i < iter->id_num; i++) {
      if (my_int_val(state, &iter->ids[i], 1) < 0) goto fail;
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
  count = state->row_count;
  if (!count) return 0;

  // save the result set into the temp array
  XCALLOC(ids, count);
  for (i = 0; i < count; i++) {
    if (my_int_val(state, &ids[i], 1) < 0) goto fail;
  }

  for (i = 0; i < count; i++) {
    remove_user_func(data, ids[i]);
  }

  xfree(ids);
  return 0;

 fail:
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

  if (user_id <= 0) goto fail;

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

  if (fetch_login(state, user_id, &u) < 0) return -1;
  if (fetch_user_info(state, user_id, contest_id, &ui) < 0) return -1;
  *p_u = u;
  *p_ui = ui;
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

  if (cur_time <= 0) cur_time = time(0);

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %susers SET logintime = ", state->table_prefix);
  write_timestamp(cmd_f, state, 0, cur_time);
  fprintf(cmd_f, " WHERE user_id = %d AND contest_id = %d ;",
          user_id, contest_id);
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
  *p_user = u;
  *p_info = ui;
  *p_contest = cc;
  return 0;
}

static int
set_cookie_contest_func(
        void *data,
        const struct userlist_cookie *c,
        int contest_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %scookies SET contest_id = %d WHERE cookie = %llu ;",
          state->table_prefix, contest_id, c->cookie);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  if (cmd_t) xfree(cmd_t);
  return -1;
}

static int
set_cookie_locale_func(
        void *data,
        const struct userlist_cookie *c,
        int locale_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %scookies SET locale_id = %d WHERE cookie = %llu ;",
          state->table_prefix, locale_id, c->cookie);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  if (cmd_t) xfree(cmd_t);
  return -1;
}

static int
set_cookie_priv_level_func(
        void *data,
        const struct userlist_cookie *c,
        int priv_level)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %scookies SET priv_level = %d WHERE cookie = %llu ;",
          state->table_prefix, priv_level, c->cookie);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  if (cmd_t) xfree(cmd_t);
  return -1;
}

static int
get_user_info_4_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_user)
{
  //struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  abort();
}

static int
get_user_info_5_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_user)
{
  //struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  abort();
}

struct brief_list_iterator
{
  struct ptr_iterator b;
  struct uldb_mysql_state *state;
  int contest_id;
  int cur_ind;
  int *user_ids;
  int total_ids;
};

static int
brief_list_iterator_has_next_func(ptr_iterator_t data)
{
  struct brief_list_iterator *iter = (struct brief_list_iterator *) data;
  return (iter->cur_ind < iter->total_ids);
}
static const void*
brief_list_iterator_get_func(ptr_iterator_t data)
{
  struct brief_list_iterator *iter = (struct brief_list_iterator *) data;
  struct uldb_mysql_state *state = iter->state;
  int user_id, contest_id;
  struct userlist_user *u = 0;
  struct userlist_user_info *ui = 0;
  struct userlist_contest *uc = 0;

  if (iter->cur_ind >= iter->total_ids) return 0;

  user_id = iter->user_ids[iter->cur_ind];
  contest_id = iter->contest_id;
  if (fetch_login(state, user_id, &u) < 0) return 0;
  if (fetch_user_info(state, user_id, contest_id, &ui) < 0) return 0;
  if (fetch_cntsreg(state, user_id, contest_id, &uc) < 0) return 0;

  userlist_attach_user_info(u, ui);
  userlist_attach_cntsreg(u, uc);

  return u;
}
static void
brief_list_iterator_next_func(ptr_iterator_t data)
{
  struct brief_list_iterator *iter = (struct brief_list_iterator *) data;
  if (iter->cur_ind < iter->total_ids) iter++;
}
static void
brief_list_iterator_destroy_func(ptr_iterator_t data)
{
  struct brief_list_iterator *iter = (struct brief_list_iterator *) data;
  xfree(iter->user_ids);
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
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  int i, val;

  XCALLOC(iter, 1);
  iter->b = brief_list_iterator_funcs;
  iter->state = state;
  iter->contest_id = contest_id;
  iter->cur_ind = 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  if (contest_id <= 0) {
    fprintf(cmd_f, "SELECT user_id FROM %slogins WHERE 1 ORDER BY user_id ;",
            state->table_prefix);
  } else {
    fprintf(cmd_f, "SELECT user_id FROM %scntsregs WHERE contest_id = %d ORDER BY user_id ;", state->table_prefix, contest_id);
  }
  fclose(cmd_f); cmd_f = 0;

  if((state->field_count = mysql_field_count(state->conn)) != 1)
    db_wrong_field_count_fail(state, 1);
  if (!(state->res = mysql_store_result(state->conn)))
    db_error_fail(state);
  state->row_count = mysql_num_rows(state->res);
  iter->total_ids = state->row_count;

  if (iter->total_ids > 0) {
    XCALLOC(iter->user_ids, iter->total_ids);
    for (i = 0; i < iter->total_ids; i++) {
      if (!(state->row = mysql_fetch_row(state->res)))
        db_no_data_fail();
      state->lengths = mysql_fetch_lengths(state->res);
      if (!state->lengths[0])
        db_inv_value_fail();
      if (parse_int(state->row[0], &val) < 0 || val <= 0)
        db_inv_value_fail();
      iter->user_ids[i] = val;
    }
  }
  
  return (ptr_iterator_t) iter;

 fail:
  if (iter) xfree(iter->user_ids);
  xfree(iter);
  return 0;
}

struct standings_list_iterator
{
  struct ptr_iterator b;
  struct uldb_mysql_state *state;
  int contest_id;
  int cur_ind;
  int *user_ids;
  int total_ids;
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
  int user_id, contest_id;
  struct userlist_user *u = 0;
  struct userlist_user_info *ui = 0;
  struct userlist_contest *uc = 0;
  struct userlist_members *mm = 0;

  if (iter->cur_ind >= iter->total_ids) return 0;

  user_id = iter->user_ids[iter->cur_ind];
  contest_id = iter->contest_id;
  if (fetch_login(state, user_id, &u) < 0) return 0;
  if (fetch_user_info(state, user_id, contest_id, &ui) < 0) return 0;
  if (fetch_cntsreg(state, user_id, contest_id, &uc) < 0) return 0;
  if (fetch_member(state, user_id, contest_id, &mm) < 0) return 0;

  if (ui) ui->members = mm;
  userlist_attach_user_info(u, ui);
  userlist_attach_cntsreg(u, uc);

  return u;
}
static void
standings_list_iterator_next_func(ptr_iterator_t data)
{
  struct standings_list_iterator *iter = (struct standings_list_iterator *)data;
  if (iter->cur_ind < iter->total_ids) iter++;
}
static void
standings_list_iterator_destroy_func(ptr_iterator_t data)
{
  struct standings_list_iterator *iter = (struct standings_list_iterator *)data;
  xfree(iter->user_ids);
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
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  int i, val;

  if (contest_id <= 0) return 0;

  XCALLOC(iter, 1);
  iter->b = standings_list_iterator_funcs;
  iter->state = state;
  iter->contest_id = contest_id;
  iter->cur_ind = 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  if (contest_id <= 0) {
    fprintf(cmd_f, "SELECT user_id FROM %slogins WHERE 1 ORDER BY user_id ;",
            state->table_prefix);
  } else {
    fprintf(cmd_f, "SELECT user_id FROM %scntsregs WHERE contest_id = %d ORDER BY user_id ;", state->table_prefix, contest_id);
  }
  fclose(cmd_f); cmd_f = 0;

  if((state->field_count = mysql_field_count(state->conn)) != 1)
    db_wrong_field_count_fail(state, 1);
  if (!(state->res = mysql_store_result(state->conn)))
    db_error_fail(state);
  state->row_count = mysql_num_rows(state->res);
  iter->total_ids = state->row_count;

  if (iter->total_ids > 0) {
    XCALLOC(iter->user_ids, iter->total_ids);
    for (i = 0; i < iter->total_ids; i++) {
      if (!(state->row = mysql_fetch_row(state->res)))
        db_no_data_fail();
      state->lengths = mysql_fetch_lengths(state->res);
      if (!state->lengths[0])
        db_inv_value_fail();
      if (parse_int(state->row[0], &val) < 0 || val <= 0)
        db_inv_value_fail();
      iter->user_ids[i] = val;
    }
  }
  
  return (ptr_iterator_t) iter;

 fail:
  if (iter) xfree(iter->user_ids);
  xfree(iter);
  return 0;
}

static int
check_user_func(
        void *data,
        int user_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char cmdbuf[1024];
  int cmdlen = sizeof(cmdbuf);

  cmdlen = snprintf(cmdbuf, cmdlen, "SELECT user_id FROM %slogins WHERE user_id = %d ;", state->table_prefix, user_id);
  if (my_query(state, cmdbuf, cmdlen, 1) < 0) return -1;
  if (state->row_count <= 0) return -1;
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
  return 0;

 fail:
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
  if (p_cloned_flag) *p_cloned_flag = 0;
  return 0;

 fail:
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
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "DELETE FROM %smembers WHERE user_id = %d AND contest_id = %d AND serial = %d ;", state->table_prefix, user_id, contest_id, serial);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  remove_member_from_pool(state, user_id, contest_id);
  if (p_cloned_flag) *p_cloned_flag = 0;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
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
  int *user_ids;
  int total_ids;
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
  int user_id, contest_id;
  struct userlist_user *u = 0;
  struct userlist_user_info *ui = 0;
  struct userlist_contest *uc = 0;
  struct userlist_members *mm = 0;

  if (iter->cur_ind >= iter->total_ids) return 0;

  user_id = iter->user_ids[iter->cur_ind];
  contest_id = iter->contest_id;
  if (fetch_login(state, user_id, &u) < 0) return 0;
  if (fetch_user_info(state, user_id, contest_id, &ui) < 0) return 0;
  if (fetch_cntsreg(state, user_id, contest_id, &uc) < 0) return 0;
  if (fetch_member(state, user_id, contest_id, &mm) < 0) return 0;

  userlist_attach_user_info(u, ui);
  userlist_attach_cntsreg(u, uc);
  if (ui) ui->members = mm;

  return u;
}
static void
info_list_iterator_next_func(ptr_iterator_t data)
{
  struct info_list_iterator *iter = (struct info_list_iterator *) data;
  if (iter->cur_ind < iter->total_ids) iter++;
}
static void
info_list_iterator_destroy_func(ptr_iterator_t data)
{
  struct info_list_iterator *iter = (struct info_list_iterator *) data;
  xfree(iter->user_ids);
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
  int i, val;

  ASSERT(contest_id > 0);
  flag_mask &= USERLIST_UC_ALL;

  XCALLOC(iter, 1);
  iter->b = info_list_iterator_funcs;
  iter->state = state;
  iter->contest_id = contest_id;
  iter->cur_ind = 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "SELECT user_id FROM %scntsregs WHERE contest_id = %d ", state->table_prefix, contest_id);
  if (!flag_mask) {
    fprintf(cmd_f, " AND banned = 0 AND invisible = 0 AND locked = 0 AND incomplete = 0 AND disqualified = 0 ");
  } else if (flag_mask != USERLIST_UC_ALL) {
    fprintf(cmd_f, " AND ((banned = 0 AND invisible = 0 AND locked = 0 AND incomplete = 0 AND disqualified = 0) ");
    if ((flag_mask & USERLIST_UC_BANNED))
      fprintf(cmd_f, " OR banned = 1 ");
    if ((flag_mask & USERLIST_UC_INVISIBLE))
      fprintf(cmd_f, " OR invisible = 1 ");
    if ((flag_mask & USERLIST_UC_LOCKED))
      fprintf(cmd_f, " OR locked = 1 ");
    if ((flag_mask & USERLIST_UC_INCOMPLETE))
      fprintf(cmd_f, " OR incomplete = 1 ");
    if ((flag_mask & USERLIST_UC_DISQUALIFIED))
      fprintf(cmd_f, " OR disqualified = 1 ");
    fprintf(cmd_f, ") ");
  }
  fprintf(cmd_f, " ORDER BY user_id ;");
  fclose(cmd_f); cmd_f = 0;

  if((state->field_count = mysql_field_count(state->conn)) != 1)
    db_wrong_field_count_fail(state, 1);
  if (!(state->res = mysql_store_result(state->conn)))
    db_error_fail(state);
  state->row_count = mysql_num_rows(state->res);
  iter->total_ids = state->row_count;

  if (iter->total_ids > 0) {
    XCALLOC(iter->user_ids, iter->total_ids);
    for (i = 0; i < iter->total_ids; i++) {
      if (!(state->row = mysql_fetch_row(state->res)))
        db_no_data_fail();
      state->lengths = mysql_fetch_lengths(state->res);
      if (!state->lengths[0])
        db_inv_value_fail();
      if (parse_int(state->row[0], &val) < 0 || val <= 0)
        db_inv_value_fail();
      iter->user_ids[i] = val;
    }
  }
  
  return (ptr_iterator_t) iter;

 fail:
  if (iter) xfree(iter->user_ids);
  xfree(iter);
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
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %susers SET password = NULL, pwdmethod = 0 WHERE user_id = %d AND contest_id = %d ;", state->table_prefix, user_id, contest_id);
  fclose(cmd_f); cmd_f = 0;
  if (my_simple_query(state, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  if (p_cloned_flag) *p_cloned_flag = 0;
  remove_user_info_from_pool(state, user_id, contest_id);
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
remove_registration_func(
        void *data,
        int user_id,
        int contest_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "DELETE FROM %scntsregs WHERE user_id = %d AND contest_id = %d ;", state->table_prefix, user_id, contest_id);
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
set_reg_status_func(
        void *data,
        int user_id,
        int contest_id,
        int status)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  ASSERT(user_id > 0);
  ASSERT(contest_id > 0);
  ASSERT(status >= 0 && status < USERLIST_REG_LAST);

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %scntsregs SET status = %d WHERE user_id = %d AND contest_id = %d ;", state->table_prefix, status, user_id, contest_id);
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
  switch (field_id) {
  case USERLIST_NN_IS_PRIVILEGED:
    fprintf(cmd_f, "%s = 0", fields[field_id].sql_name);
    break;
  case USERLIST_NN_SHOW_LOGIN:
    fclose(cmd_f);
    xfree(cmd_t);
    return 0;
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

static void
unlock_user_func(
        void *data,
        const struct userlist_user *c_u)
{
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
    userlist_free(u->cookies);
    u->cookies = 0;
  }
}

/*
 * Local variables:
 *  compile-command: "make -C ../.."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "MYSQL")
 * End:
 */
