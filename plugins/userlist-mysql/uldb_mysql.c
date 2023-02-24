/* -*- mode: c -*- */

/* Copyright (C) 2006-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/ej_limits.h"
#include "ejudge/errlog.h"
#include "ejudge/uldb_plugin.h"
#include "ejudge/xml_utils.h"
#include "ejudge/expat_iface.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/pathutl.h"
#include "ejudge/userlist.h"
#include "ejudge/list_ops.h"
#include "ejudge/misctext.h"
#include "ejudge/random.h"
#include "../common-mysql/common_mysql.h"
#include "ejudge/compat.h"
#include "ejudge/base64.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <mysql.h>

#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>

#include "methods.inc.c"

#define GROUPS_TABLE_NAME "ejgroups"

/* plugin entry point */
struct uldb_plugin_iface plugin_uldb_mysql =
{
  {
    {
      sizeof (struct uldb_plugin_iface),
      EJUDGE_PLUGIN_IFACE_VERSION,
      "uldb",
      "mysql",
    },
    COMMON_PLUGIN_IFACE_VERSION,
    // initialize the plugin
    init_func,
    // clean-up the plugin
    finish_func,
    // parse the configuration settings
    prepare_func,
  },
  ULDB_PLUGIN_IFACE_VERSION,

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
  // drop the cache
  drop_cache_func,
  // disable caching
  disable_cache_func,
  // enable caching
  enable_cache_func,
  // try new login
  try_new_login_func,
  // set the simple_registration flag
  set_simple_reg_func,
  // get the group iterator
  get_group_iterator_func,
  // get the group by the group name
  get_group_by_name_func,
  // pick up a new group name by a template
  try_new_group_name_func,
  // create a new group
  create_group_func,
  // remove a group
  remove_group_func,
  // edit a group field
  edit_group_field_func,
  // clear a group field
  clear_group_field_func,
  // get the group by the group id
  get_group_func,
  // get the group users iterator
  get_group_user_iterator_func,
  // get the group groupmember iterator
  get_group_member_iterator_func,
  // create a group member
  create_group_member_func,
  // remove a group member
  remove_group_member_func,
  // get a user iterator
  get_brief_list_iterator_2_func,
  // get the total count of the users
  get_user_count_func,
  // get a group iterator
  get_group_iterator_2_func,
  // get the total count of the groups
  get_group_count_func,
  // get the previous user
  get_prev_user_id_func,
  // get the next user
  get_next_user_id_func,
  // create a cookie (128 bit)
  new_cookie_2_func,
  // get any cookie with the given client key
  get_client_key_func,
  // create a new API key
  new_api_key_func,
  get_api_key_func,
  get_api_key_secret_func,
  get_api_keys_count_func,
  get_api_keys_for_user_func,
  remove_api_key_func,
};

// the size of the cookies pool, must be power of 2
enum { COOKIES_POOL_SIZE = 4096 };
enum { COOKIES_MAX_HASH_SIZE = 2500 };

// the size of the cntsregs pool
enum { CNTSREGS_POOL_SIZE = 1024 };

// the size of the users pool
enum { USERS_POOL_SIZE = 1024 };

// the size of the user info pool
enum { USER_INFO_POOL_SIZE = 1024 };

// the size of the member pool
enum { MEMBERS_POOL_SIZE = 1024 };

// the size of the usergroups pool
enum { GROUPS_POOL_SIZE = 1024 };

// the size of the apikey pool
enum { API_KEY_POOL_SIZE = 1024 };

// the maintenance interval
enum { MAINT_INTERVAL = 10 * 60 };

struct cookies_container;

struct cookies_cache
{
  struct cookies_container *hash[COOKIES_POOL_SIZE];
  struct cookies_container *client_key_hash[COOKIES_POOL_SIZE];
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

struct groups_cache
{
  int size;                     /* the size of the group map */
  int count;                    /* the total count of entries in the cache */
  struct userlist_group **group_map;
  struct xml_tree *first, *last;
};

struct api_key_cache_entry
{
  struct userlist_api_key api_key;
  int prev_entry;
  int next_entry;
};

struct api_key_cache
{
  struct api_key_cache_entry *entries;
  int *token_index;
  int *secret_index;

  int size;
  int token_index_count;
  int secret_index_count;
  int first_entry;
  int last_entry;
  int first_free;
  int last_free;
};

struct uldb_mysql_state
{
  int cache_queries;

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

  // groups cache
  struct groups_cache groups;

  // api key cache
  struct api_key_cache api_keys;

  time_t last_maint_time;
  time_t maint_interval;

  int total_unused_ids;
  int cur_unused_id;
  int *unused_ids;

  // mysql access
  struct common_mysql_iface *mi;
  struct common_mysql_state *md;
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

static void
userlist_attach_user_info(
        struct userlist_user *u,
        struct userlist_user_info *ui)
{
  if (!u || !ui) return;

  if (ui->contest_id <= 0) {
    u->cnts0 = ui;
  } else {
    userlist_insert_user_info(u, ui->contest_id, ui);
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

static int
finish_func(struct common_plugin_data *data)
{
  return 0;
}

static struct common_plugin_data*
init_func(void)
{
  struct uldb_mysql_state *state;

  XCALLOC(state, 1);
  state->cache_queries = 1;
  state->maint_interval = MAINT_INTERVAL;
  return (struct common_plugin_data*) state;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct xml_attr *a;
  const struct common_loaded_plugin *mplg;

  // load common_mysql plugin
  if (!(mplg = plugin_load_external(0, "common", "mysql", config))) {
    err("cannot load common_mysql plugin");
    return -1;
  }
  state->mi = (struct common_mysql_iface*) mplg->iface;
  state->md = (struct common_mysql_state*) mplg->data;

  ASSERT(tree->tag == xml_err_spec->default_elem);
  ASSERT(!strcmp(tree->name[0], "config"));

  if (xml_empty_text(tree) < 0) return -1;

  for (a = tree->first; a; a = a->next) {
    ASSERT(a->tag == xml_err_spec->default_attr);
    if (!strcmp(a->name[0], "cache_queries")) {
      if (xml_attr_bool(a, &state->cache_queries) < 0) return -1;
    } else {
      return xml_err_attr_not_allowed(tree, a);
    }
  }

  return 0;
}

static int
open_func(void *data)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  if (state->mi->connect(state->md) < 0)
    return -1;

  return 0;
}

static int
check_func(void *data)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  int version, n;

  if (!state->md->conn) return -1;

  // check, that database is created
  unsigned char qbuf[1024];
  int qlen = snprintf(qbuf, sizeof(qbuf), "SELECT config_val FROM %sconfig WHERE config_key = 'version' ;", state->md->table_prefix);
  if (state->mi->simple_query_bin(state->md, qbuf, qlen) < 0) {
    err("probably the database is not created. use --convert or --create");
    return 0;
  }

  if((state->md->field_count = mysql_field_count(state->md->conn)) != 1) {
    err("wrong database format: field_count == %d", state->md->field_count);
    return -1;
  }
  if (!(state->md->res = mysql_store_result(state->md->conn)))
    return state->mi->error(state->md);

  if (!(state->md->row_count = mysql_num_rows(state->md->res))) {
    err("database has no key 'version'. recreate the database");
    return -1;
  }
  if (state->md->row_count > 1) {
    err("wrong database format: row_count == %d", state->md->row_count);
    return -1;
  }

  if (!(state->md->row = mysql_fetch_row(state->md->res))) {
    err("wrong database format: no data");
    return -1;
  }
  state->md->lengths = mysql_fetch_lengths(state->md->res);
  if (strlen(state->md->row[0]) != state->md->lengths[0]) {
    err("wrong database format: version is binary data");
    return -1;
  }
  if (sscanf(state->md->row[0], "%d%n", &version, &n) != 1
      || state->md->row[0][n] || version <= 0) {
    err("invalid 'version' key value");
    return -1;
  }
  // current version is 11, so cannot handle future version
  if (version == 1) {
    if (state->mi->simple_fquery(state->md, "CREATE TABLE %sgroups(group_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, group_name VARCHAR(128) NOT NULL UNIQUE KEY, description VARCHAR(512) DEFAULT NULL, created_by INT NOT NULL, create_time DATETIME NOT NULL, last_change_time DATETIME DEFAULT NULL, FOREIGN KEY (created_by) REFERENCES %slogins(user_id));", state->md->table_prefix, state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "CREATE TABLE %sgroupmembers(group_id INT NOT NULL, user_id INT NOT NULL, rights VARCHAR(512) DEFAULT NULL, PRIMARY KEY (group_id, user_id), FOREIGN KEY g(group_id) REFERENCES %sgroups(group_id), FOREIGN KEY u(user_id) REFERENCES %slogins(user_id));", state->md->table_prefix, state->md->table_prefix, state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "UPDATE %sconfig SET config_val = '2' WHERE config_key = 'version' ;", state->md->table_prefix) < 0)
      return -1;
    version = 2;
  }
  if (version == 2) {
    // extend cookie size to VARCHAR(64)
    if (state->mi->simple_fquery(state->md, "ALTER TABLE %scookies MODIFY cookie VARCHAR(64) NOT NULL;", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "UPDATE %sconfig SET config_val = '3' WHERE config_key = 'version' ;", state->md->table_prefix) < 0)
      return -1;
    version = 3;
  }
  if (version == 3) {
    if (state->mi->simple_fquery(state->md, "ALTER TABLE %scntsregs ADD privileged TINYINT NOT NULL DEFAULT 0 AFTER disqualified, ADD reg_readonly TINYINT NOT NULL DEFAULT 0 AFTER privileged;", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "UPDATE %sconfig SET config_val = '4' WHERE config_key = 'version' ;", state->md->table_prefix) < 0)
      return -1;
    version = 4;
  }
  if (version == 4) {
    if (state->mi->simple_fquery(state->md, "ALTER TABLE %susers ADD avatar_store VARCHAR(512) DEFAULT NULL AFTER field9, ADD avatar_id VARCHAR(512) DEFAULT NULL AFTER avatar_store ;", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "UPDATE %sconfig SET config_val = '5' WHERE config_key = 'version' ;", state->md->table_prefix) < 0)
      return -1;
    version = 5;
  }
  if (version == 5) {
    if (state->mi->simple_fquery(state->md, "ALTER TABLE %susers ADD avatar_suffix VARCHAR(32) DEFAULT NULL AFTER avatar_id ;", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "UPDATE %sconfig SET config_val = '6' WHERE config_key = 'version' ;", state->md->table_prefix) < 0)
      return -1;
    version = 6;
  }
  if (version == 6) {
    if (state->mi->simple_fquery(state->md, "ALTER TABLE %scntsregs ADD INDEX cntsregs_user_id_idx (user_id), ADD INDEX cntsregs_contest_id_idx (contest_id);", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "ALTER TABLE %susers    ADD INDEX users_user_id_idx (user_id), ADD INDEX users_contest_id_idx (contest_id);", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "ALTER TABLE %smembers  ADD INDEX members_user_id_idx (user_id), ADD INDEX members_contest_id_idx (contest_id);", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "ALTER TABLE %sgroupmembers ADD INDEX groupmembers_group_id_idx (group_id), ADD INDEX groupmembers_user_id_idx (user_id);", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "UPDATE %sconfig SET config_val = '7' WHERE config_key = 'version' ;", state->md->table_prefix) < 0)
      return -1;
    version = 7;
  }
  if (version == 7) {
    if (state->mi->simple_fquery(state->md, "ALTER TABLE %scookies ADD is_ws TINYINT NOT NULL DEFAULT 0 AFTER expire ;", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "UPDATE %sconfig SET config_val = '8' WHERE config_key = 'version' ;", state->md->table_prefix) < 0)
      return -1;
    version = 8;
  }
  if (version == 8) {
    if (state->mi->simple_fquery(state->md, "ALTER TABLE %sconfig ENGINE=InnoDB ;", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "ALTER TABLE %slogins ENGINE=InnoDB ;", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "ALTER TABLE %scookies ENGINE=InnoDB ;", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "ALTER TABLE %scntsregs ENGINE=InnoDB ;", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "ALTER TABLE %susers ENGINE=InnoDB ;", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "ALTER TABLE %smembers ENGINE=InnoDB ;", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "ALTER TABLE %sgroups ENGINE=InnoDB ;", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "ALTER TABLE %sgroupmembers ENGINE=InnoDB ;", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "UPDATE %sconfig SET config_val = '9' WHERE config_key = 'version' ;", state->md->table_prefix) < 0)
      return -1;
    version = 9;
  }
  if (version == 9) {
    if (state->mi->simple_fquery(state->md, "CREATE TABLE %sapikeys(token VARCHAR(64) NOT NULL PRIMARY KEY, secret VARCHAR(64) NOT NULL UNIQUE KEY, user_id INT UNSIGNED NOT NULL, contest_id INT UNSIGNED NOT NULL, create_time DATETIME NOT NULL, expiry_time DATETIME DEFAULT NULL, payload VARCHAR(1024) DEFAULT NULL, origin VARCHAR(128) DEFAULT NULL, all_contests TINYINT NOT NULL DEFAULT 0, role_id TINYINT NOT NULL DEFAULT 0, FOREIGN KEY apikeys_user_id_fk(user_id) REFERENCES logins(user_id)) ENGINE=InnoDB;", state->md->table_prefix) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "UPDATE %sconfig SET config_val = '10' WHERE config_key = 'version' ;", state->md->table_prefix) < 0)
      return -1;
    version = 10;
  }
  if (version == 10) {
    if (state->mi->simple_fquery(state->md, "RENAME TABLE %sgroups TO %s%s ;", state->md->table_prefix, state->md->table_prefix, GROUPS_TABLE_NAME) < 0)
      return -1;
    if (state->mi->simple_fquery(state->md, "UPDATE %sconfig SET config_val = '11' WHERE config_key = 'version' ;", state->md->table_prefix) < 0)
      return -1;
    version = 11;
  }
  while (version >= 0) {
    switch (version) {
    case 1 ... 10:
      // see above
      break;

    case 11:
      if (state->mi->simple_fquery(state->md,
                                   "ALTER TABLE %slogins"
                                   " MODIFY logintime DATETIME DEFAULT NULL,"
                                   " MODIFY pwdtime DATETIME DEFAULT NULL,"
                                   " MODIFY changetime DATETIME DEFAULT NULL;",
                                   state->md->table_prefix) < 0)
        return -1;
      break;

    case 12:
      if (state->mi->simple_fquery(state->md,
                                   "ALTER TABLE %scntsregs"
                                   " MODIFY changetime DATETIME DEFAULT NULL;",
                                   state->md->table_prefix) < 0)
        return -1;
      break;

    case 13:
      if (state->mi->simple_fquery(state->md,
                                   "ALTER TABLE %susers"
                                   " MODIFY pwdtime DATETIME DEFAULT NULL,"
                                   " MODIFY changetime DATETIME DEFAULT NULL,"
                                   " MODIFY logintime DATETIME DEFAULT NULL;",
                                   state->md->table_prefix) < 0)
        return -1;
      break;

    case 14:
      if (state->mi->simple_fquery(state->md,
                                   "ALTER TABLE %smembers"
                                   " MODIFY changetime DATETIME DEFAULT NULL;",
                                   state->md->table_prefix) < 0)
        return -1;
      break;

    case 15:
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %scookies ADD is_job TINYINT NOT NULL DEFAULT 0 AFTER is_ws ;", state->md->table_prefix) < 0)
        return -1;
      break;
    case 16:
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %sconfig DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", state->md->table_prefix) < 0)
        return -1;
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %slogins DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", state->md->table_prefix) < 0)
        return -1;
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %scookies DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", state->md->table_prefix) < 0)
        return -1;
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %scntsregs DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", state->md->table_prefix) < 0)
        return -1;
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %susers DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", state->md->table_prefix) < 0)
        return -1;
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %smembers DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", state->md->table_prefix) < 0)
        return -1;
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %sejgroups DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", state->md->table_prefix) < 0)
        return -1;
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %sgroupmembers DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", state->md->table_prefix) < 0)
        return -1;
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %sapikeys DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", state->md->table_prefix) < 0)
        return -1;
      break;
    case 17:
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %sconfig MODIFY COLUMN config_key VARCHAR(64) NOT NULL, MODIFY COLUMN config_val VARCHAR(64) ;", state->md->table_prefix) < 0)
        return -1;
      break;
    case 18:
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %slogins MODIFY COLUMN login VARCHAR(64) NOT NULL, MODIFY COLUMN email VARCHAR(128), MODIFY COLUMN password VARCHAR(128) ;", state->md->table_prefix) < 0)
        return -1;
      break;
    case 19:
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %scookies MODIFY COLUMN cookie VARCHAR(64) NOT NULL, MODIFY COLUMN ip VARCHAR(64) NOT NULL ;", state->md->table_prefix) < 0)
        return -1;
      break;
    case 20:
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %susers MODIFY COLUMN username VARCHAR(512) DEFAULT NULL, MODIFY COLUMN password VARCHAR(128) DEFAULT NULL, MODIFY COLUMN inst VARCHAR(512) DEFAULT NULL, MODIFY COLUMN inst_en VARCHAR (512) DEFAULT NULL, MODIFY COLUMN instshort VARCHAR (512) DEFAULT NULL, MODIFY COLUMN instshort_en VARCHAR (512) DEFAULT NULL, MODIFY COLUMN fac VARCHAR(512) DEFAULT NULL, MODIFY COLUMN fac_en VARCHAR (512) DEFAULT NULL, MODIFY COLUMN facshort VARCHAR (512) DEFAULT NULL, MODIFY COLUMN facshort_en VARCHAR (512) DEFAULT NULL, MODIFY COLUMN homepage VARCHAR (512) DEFAULT NULL, MODIFY COLUMN phone VARCHAR (512) DEFAULT NULL, MODIFY COLUMN city VARCHAR (256) DEFAULT NULL, MODIFY COLUMN city_en VARCHAR (256) DEFAULT NULL, MODIFY COLUMN region VARCHAR (512) DEFAULT NULL, MODIFY COLUMN area VARCHAR (512) DEFAULT NULL, MODIFY COLUMN zip VARCHAR (256) DEFAULT NULL, MODIFY COLUMN street VARCHAR (512) DEFAULT NULL, MODIFY COLUMN country VARCHAR (256) DEFAULT NULL, MODIFY COLUMN country_en VARCHAR (256) DEFAULT NULL, MODIFY COLUMN location VARCHAR (256) DEFAULT NULL, MODIFY COLUMN spelling VARCHAR (512) DEFAULT NULL, MODIFY COLUMN printer VARCHAR (256) DEFAULT NULL, MODIFY COLUMN languages VARCHAR (512) DEFAULT NULL, MODIFY COLUMN exam_id VARCHAR (256) DEFAULT NULL, MODIFY COLUMN exam_cypher VARCHAR (256) DEFAULT NULL, MODIFY COLUMN field0 VARCHAR(256) DEFAULT NULL, MODIFY COLUMN field1 VARCHAR(256) DEFAULT NULL, MODIFY COLUMN field2 VARCHAR(256) DEFAULT NULL, MODIFY COLUMN field3 VARCHAR(256) DEFAULT NULL, MODIFY COLUMN field4 VARCHAR(256) DEFAULT NULL, MODIFY COLUMN field5 VARCHAR(256) DEFAULT NULL, MODIFY COLUMN field6 VARCHAR(256) DEFAULT NULL, MODIFY COLUMN field7 VARCHAR(256) DEFAULT NULL, MODIFY COLUMN field8 VARCHAR(256) DEFAULT NULL, MODIFY COLUMN field9 VARCHAR(256) DEFAULT NULL, MODIFY COLUMN avatar_store VARCHAR(256) DEFAULT NULL, MODIFY COLUMN avatar_id VARCHAR(256) DEFAULT NULL, MODIFY COLUMN avatar_suffix VARCHAR(32) DEFAULT NULL ;", state->md->table_prefix) < 0)
        return -1;
      break;
    case 21:
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %smembers MODIFY COLUMN firstname VARCHAR(512) DEFAULT NULL, MODIFY COLUMN firstname_en VARCHAR(512) DEFAULT NULL, MODIFY COLUMN middlename VARCHAR(512) DEFAULT NULL, MODIFY COLUMN middlename_en VARCHAR(512) DEFAULT NULL, MODIFY COLUMN surname VARCHAR(512) DEFAULT NULL, MODIFY COLUMN surname_en VARCHAR(512) DEFAULT NULL, MODIFY COLUMN grp VARCHAR(512) DEFAULT NULL, MODIFY COLUMN grp_en VARCHAR(512) DEFAULT NULL, MODIFY COLUMN occupation VARCHAR(512) DEFAULT NULL, MODIFY COLUMN occupation_en VARCHAR(512) DEFAULT NULL, MODIFY COLUMN discipline VARCHAR(512) DEFAULT NULL, MODIFY COLUMN email VARCHAR(512) DEFAULT NULL, MODIFY COLUMN homepage VARCHAR(512) DEFAULT NULL, MODIFY COLUMN phone VARCHAR(512) DEFAULT NULL, MODIFY COLUMN inst VARCHAR(512) DEFAULT NULL, MODIFY COLUMN inst_en VARCHAR(512) DEFAULT NULL, MODIFY COLUMN instshort VARCHAR(512) DEFAULT NULL, MODIFY COLUMN instshort_en VARCHAR(512) DEFAULT NULL, MODIFY COLUMN fac VARCHAR(512) DEFAULT NULL, MODIFY COLUMN fac_en VARCHAR(512) DEFAULT NULL, MODIFY COLUMN facshort VARCHAR(512) DEFAULT NULL, MODIFY COLUMN facshort_en VARCHAR(512) DEFAULT NULL ;", state->md->table_prefix) < 0)
        return -1;
      break;
    case 22:
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %sejgroups MODIFY COLUMN group_name VARCHAR(128) NOT NULL UNIQUE KEY, MODIFY COLUMN description VARCHAR(512) DEFAULT NULL ;", state->md->table_prefix) < 0)
        return -1;
      break;
    case 23:
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %sgroupmembers MODIFY COLUMN rights VARCHAR(512) DEFAULT NULL ;", state->md->table_prefix) < 0)
        return -1;
      break;
    case 24:
      if (state->mi->simple_fquery(state->md, "ALTER TABLE %sapikeys MODIFY COLUMN token VARCHAR(64) NOT NULL, MODIFY COLUMN secret VARCHAR(64) NOT NULL UNIQUE KEY, MODIFY COLUMN payload VARCHAR(1024) DEFAULT NULL, MODIFY COLUMN origin VARCHAR(128) DEFAULT NULL ;", state->md->table_prefix) < 0)
        return -1;
      break;
    default:
      version = -1;
      break;
    }
    if (version >= 0) {
      ++version;
      if (state->mi->simple_fquery(state->md, "UPDATE %sconfig SET config_val = '%d' WHERE config_key = 'version' ;", state->md->table_prefix, version) < 0)
      return -1;
    }
  }

  // the current version is OK, no upgrade necessary
  state->mi->free_res(state->md);
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

  if (!state->md->conn) return -1;

  if (state->md->charset) {
    if (state->md->collation) {
      snprintf(cmdbuf, sizeof(cmdbuf), "ALTER DATABASE %s DEFAULT CHARACTER SET '%s' DEFAULT COLLATE '%s' ;\n", state->md->database, state->md->charset, state->md->collation);
    } else {
      snprintf(cmdbuf, sizeof(cmdbuf), "ALTER DATABASE %s DEFAULT CHARACTER SET '%s' ;\n", state->md->database, state->md->charset);
    }
    cmdlen = strlen(cmdbuf);
    if (state->mi->simple_query(state->md, cmdbuf, cmdlen) < 0) goto fail;
  }

  if (state->md->schema_path) {
    snprintf(schema_path, sizeof(schema_path),
             "%s/create-userdb.sql", state->md->schema_path);
  } else {
    snprintf(schema_path, sizeof(schema_path),
             "%s/share/ejudge/mysql/create-userdb.sql",EJUDGE_PREFIX_DIR);
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
    close_memstream(fstr); fstr = 0;
    while (cmdlen > 0 && isspace(cmdstr[cmdlen - 1])) cmdstr[--cmdlen] = 0;
    if (!cmdlen) {
      err("empty command");
      goto fail;
    }
    bufsize = cmdlen * 2 + strlen(state->md->table_prefix) * 2 + 1;
    buf = (unsigned char*) xmalloc(bufsize);
    snprintf(buf, bufsize, cmdstr, state->md->table_prefix);
    buflen = strlen(buf);
    if (state->mi->simple_query(state->md, buf, buflen) < 0) goto fail;

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

  fprintf(cmd_f, "INSERT INTO %smembers VALUES ( ", state->md->table_prefix);
  if (p_serial) {
    unparse_member(state, cmd_f, user_id, contest_id, &newm);
  } else {
    unparse_member(state, cmd_f, user_id, contest_id, memb);
  }
  fprintf(cmd_f, " ) ;");
  close_memstream(cmd_f); cmd_f = 0;

  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;

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

  fprintf(cmd_f, "INSERT INTO %susers VALUES ( ", state->md->table_prefix);
  if (contest_id >= 0 && info->contest_id != contest_id) {
    struct userlist_user_info u_arena;
    memcpy(&u_arena, info, sizeof(u_arena));
    u_arena.contest_id = contest_id;
    unparse_user_info(state, cmd_f, user_id, &u_arena);
  } else {
    unparse_user_info(state, cmd_f, user_id, info);
  }
  fprintf(cmd_f, " ) ;");
  close_memstream(cmd_f); cmd_f = 0;

  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;

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

  fprintf(cmd_f, "INSERT INTO %scntsregs VALUES ( ", state->md->table_prefix);
  unparse_cntsreg(state, cmd_f, user_id, c);
  fprintf(cmd_f, " ) ;");
  close_memstream(cmd_f); cmd_f = 0;

  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;

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

  fprintf(cmd_f, "INSERT INTO %scookies VALUES ( ", state->md->table_prefix);
  unparse_cookie(state, cmd_f, c);
  fprintf(cmd_f, " ) ;");
  close_memstream(cmd_f); cmd_f = 0;

  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;

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

  fprintf(cmd_f, "INSERT INTO %slogins VALUES ( ", state->md->table_prefix);
  unparse_login(state, cmd_f, user);
  fprintf(cmd_f, " );");
  close_memstream(cmd_f); cmd_f = 0;

  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;

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
    for (int i = 0; i < user->cis_a; ++i) {
      struct userlist_user_info *ui = user->cis[i];
      if (insert_contest_info(state, user->id, ui->contest_id, ui, 0) < 0)
        goto fail;
    }
    return 0;
  }

  // insert the existing contest info
  if (insert_contest_info(state, user->id, 0, user->cnts0, 0) < 0)
    goto fail;

  for (int i = 0; i < user->cis_a; ++i) {
    struct userlist_user_info *ui = user->cis[i];
    if (insert_contest_info(state, user->id, ui->contest_id, ui, 0) < 0)
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

  for (int i = 0; i < user->cis_a; ++i) {
    cntsinfo = user->cis[i];
    if (cntsinfo->contest_id > 0 && cntsinfo->contest_id <= max_contest_id)
      contest_set[cntsinfo->contest_id] = 0;
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

#include "tables.inc.c"

#include "cookies.inc.c"
#include "cntsregs.inc.c"
#include "logins.inc.c"
#include "user_infos.inc.c"
#include "members.inc.c"
#include "groups.inc.c"
#include "groupmembers.inc.c"
#include "api_keys.inc.c"

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
  int i;

  XCALLOC(iter, 1);
  iter->b = user_id_iterator_funcs;

  if (state->mi->fquery(state->md, 1, "SELECT user_id FROM %slogins WHERE 1 ;",
                state->md->table_prefix) < 0)
    goto fail;
  iter->id_num = state->md->row_count;

  if (iter->id_num > 0) {
    XCALLOC(iter->ids, iter->id_num);
    for (i = 0; i < iter->id_num; i++) {
      if (state->mi->int_val(state->md, &iter->ids[i], 1) < 0) goto fail;
    }
  }
  state->mi->free_res(state->md);
  return (int_iterator_t) iter;

 fail:
  state->mi->free_res(state->md);
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
          state->md->table_prefix);
  state->mi->write_escaped_string(state->md, cmd_f, 0, login);
  fprintf(cmd_f, " ;");
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->query_one_row(state->md, cmd_t, cmd_z, 1) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0;
  if (!state->md->lengths[0])
    db_error_inv_value_fail(state->md, "value");
  if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
    db_error_inv_value_fail(state->md, "value");
  state->mi->free_res(state->md);
  return val;

 fail:
  state->mi->free_res(state->md);
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
           state->md->table_prefix, user_id);
  cmdlen = strlen(cmdbuf);
  if (state->mi->query_one_row(state->md, cmdbuf, cmdlen, 1) < 0) goto fail;
  res = xstrdup(state->md->row[0]);
  state->mi->free_res(state->md);
  return res;

 fail:
  state->mi->free_res(state->md);
  return 0;
}

static int
new_user_func(
        void *data,
        const unsigned char *login,
        const unsigned char *email,
        int passwd_method,
        const unsigned char *passwd,
        int is_privileged,
        int is_invisible,
        int is_banned,
        int is_locked,
        int show_login,
        int show_email,
        int read_only,
        int never_clean,
        int simple_registration)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  int val, inserted_flag = 0;
  struct userlist_user user;
  FILE *cmd_f = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;

  if (!login || !*login) return -1;

  if (state->total_unused_ids > 0
      && state->cur_unused_id < state->total_unused_ids) {
    memset(&user, 0, sizeof(user));
    user.id = state->unused_ids[state->cur_unused_id++];
    user.login = (char*) login;
    user.email = (char*) email;
    user.passwd = (char*) passwd;
    user.passwd_method = passwd_method;
    user.is_privileged = !!is_privileged;
    user.is_invisible = !!is_invisible;
    user.is_banned = !!is_banned;
    user.is_locked = !!is_locked;
    user.show_login = !!show_login;
    user.show_email = !!show_email;
    user.read_only = !!read_only;
    user.never_clean = !!never_clean;
    user.simple_registration = !!simple_registration;

    cmd_f = open_memstream(&cmd_t, &cmd_z);
    fprintf(cmd_f, "INSERT into %slogins VALUES ( ", state->md->table_prefix);
    unparse_login(state, cmd_f, &user);
    fprintf(cmd_f, " );");
    close_memstream(cmd_f); cmd_f = 0;
    if (state->mi->simple_query(state->md, cmd_t, cmd_z) >= 0) {
      xfree(cmd_t); cmd_t = 0; cmd_z = 0;
      inserted_flag = 1;
    }
  }

  if (!inserted_flag) {
    memset(&user, 0, sizeof(user));
    user.id = -1;
    user.login = (char*) login;
    user.email = (char*) email;
    user.passwd = (char*) passwd;
    user.passwd_method = passwd_method;
    user.is_privileged = !!is_privileged;
    user.is_invisible = !!is_invisible;
    user.is_banned = !!is_banned;
    user.is_locked = !!is_locked;
    user.show_login = !!show_login;
    user.show_email = !!show_email;
    user.read_only = !!read_only;
    user.never_clean = !!never_clean;
    user.simple_registration = !!simple_registration;

    cmd_f = open_memstream(&cmd_t, &cmd_z);
    fprintf(cmd_f, "INSERT into %slogins VALUES ( ", state->md->table_prefix);
    unparse_login(state, cmd_f, &user);
    fprintf(cmd_f, " );");
    close_memstream(cmd_f); cmd_f = 0;
    if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
    xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  }

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "SELECT user_id FROM %slogins WHERE login = ",
          state->md->table_prefix);
  state->mi->write_escaped_string(state->md, cmd_f, 0, login);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->query_one_row(state->md, cmd_t, cmd_z, 1) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  if (!state->md->lengths[0])
    db_error_inv_value_fail(state->md, "value");
  if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
    db_error_inv_value_fail(state->md, "value");
  state->mi->free_res(state->md);
  return val;

 fail:
  state->mi->free_res(state->md);
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
remove_user_func(void *data, int user_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  state->mi->simple_fquery(state->md, "DELETE FROM %scookies WHERE user_id = %d;",
                   state->md->table_prefix, user_id);
  state->mi->simple_fquery(state->md, "DELETE FROM %scntsregs WHERE user_id = %d;",
                   state->md->table_prefix, user_id);
  state->mi->simple_fquery(state->md, "DELETE FROM %susers WHERE user_id = %d; ",
                   state->md->table_prefix, user_id);
  state->mi->simple_fquery(state->md, "DELETE FROM %slogins WHERE user_id = %d;",
                   state->md->table_prefix, user_id);
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
        ej_cookie_t client_key,
        const struct userlist_cookie **p_cookie)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct userlist_cookie *c;

  if (state->cache_queries && (c = get_cookie_from_pool(state, value))) {
    if (c->client_key != client_key) {
      if (p_cookie) *p_cookie = NULL;
      return -1;
    }
    if (p_cookie) *p_cookie = c;
    return 0;
  }

  if (fetch_cookie(state, value, client_key, &c) <= 0) {
    if (p_cookie) *p_cookie = NULL;
    return -1;
  }
  if (p_cookie) *p_cookie = c;
  return 0;
}

static int
is_unique_cookie(
        struct uldb_mysql_state *state,
        unsigned long long value)
{
  if (!value) return 0;
  if (state->mi->fquery(state->md, 1,
                "SELECT user_id FROM %scookies WHERE cookie LIKE('%016llx%%') ;",
                state->md->table_prefix, value) < 0)
    return -1;
  if (state->md->row_count < 0) {
    state->mi->free_res(state->md);
    return -1;
  }
  if (state->md->row_count > 0) {
    state->mi->free_res(state->md);
    return 0;
  }
  state->mi->free_res(state->md);
  return 1;
}

static int
new_cookie_func(
        void *data,
        int user_id,
        const ej_ip_t *pip,
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
  newc.ip = *pip;
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
  fprintf(cmd_f, "INSERT INTO %scookies VALUES ( ", state->md->table_prefix);
  unparse_cookie(state, cmd_f, &newc);
  fprintf(cmd_f, " ) ;");
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0;
  if (fetch_cookie(state, cookie, 0, &c) < 0) goto fail;
  if (p_cookie) *p_cookie = c;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
new_cookie_2_func(
        void *data,
        int user_id,
        const ej_ip_t *pip,
        int ssl_flag,
        ej_cookie_t cookie,
        ej_cookie_t client_key,
        time_t expire,
        int contest_id,
        int locale_id,
        int priv_level,
        int role,
        int recovery,
        int team_login,
        int is_ws,
        int is_job,
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
  if (!client_key) {
    client_key = random_u64();
  }
  if (!expire) expire = time(0) + 24 * 60 * 60;

  ASSERT(cookie != 0);
  memset(&newc, 0, sizeof(newc));
  newc.user_id = user_id;
  newc.ip = *pip;
  newc.ssl = ssl_flag;
  newc.cookie = cookie;
  newc.client_key = client_key;
  newc.expire = expire;
  newc.contest_id = contest_id;
  newc.locale_id = locale_id;
  newc.priv_level = priv_level;
  newc.role = role;
  newc.recovery = recovery;
  newc.team_login = team_login;
  newc.is_ws = is_ws;
  newc.is_job = is_job;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %scookies VALUES ( ", state->md->table_prefix);
  unparse_cookie(state, cmd_f, &newc);
  fprintf(cmd_f, " ) ;");
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0;
  if (fetch_cookie(state, cookie, client_key, &c) < 0) goto fail;
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
  unsigned char buf[64];

  if (!c) return 0;

  if (state->mi->simple_fquery(state->md, "DELETE FROM %scookies WHERE cookie = '%s';", state->md->table_prefix,
                               xml_unparse_full_cookie(buf, sizeof(buf), &c->cookie, &c->client_key)) < 0) return -1;
  remove_cookie_from_pool(state, c->cookie);
  return 0;
}

static int
remove_user_cookies_func(
        void *data,
        int user_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  if (state->mi->simple_fquery(state->md, "DELETE FROM %scookies WHERE user_id = %d;",
                       state->md->table_prefix, user_id) < 0)
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
  fprintf(cmd_f, "DELETE FROM %scookies WHERE expire < ", state->md->table_prefix);
  state->mi->write_timestamp(state->md, cmd_f, "", cur_time);
  fprintf(cmd_f, " ;");
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
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
           state->md->table_prefix, iter->user_id, iter->ids[iter->cur_i]);
  cmdlen = strlen(cmdbuf);
  if (state->mi->query_one_row(state->md, cmdbuf, cmdlen, CNTSREG_WIDTH) < 0) return 0;
  c = allocate_cntsreg_on_pool(state, iter->user_id, iter->ids[iter->cur_i]);
  if (!c) goto fail;
  if (parse_cntsreg(state, state->md->field_count,state->md->row,state->md->lengths, c) < 0)
    goto fail;
  state->mi->free_res(state->md);
  return (void*) c;

 fail:
  state->mi->free_res(state->md);
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
  int i;

  XCALLOC(iter, 1);
  iter->b = user_contest_iterator_funcs;
  iter->state = state;
  iter->user_id = user_id;

  if (state->mi->fquery(state->md, 1,
                "SELECT contest_id FROM %scntsregs WHERE user_id = %d ;",
                state->md->table_prefix, user_id) < 0)
    goto fail;
  iter->id_num = state->md->row_count;

  if (iter->id_num > 0) {
    XCALLOC(iter->ids, iter->id_num);
    for (i = 0; i < iter->id_num; i++) {
      if (state->mi->int_val(state->md, &iter->ids[i], 1) < 0) goto fail;
    }
  }
  state->mi->free_res(state->md);
  return (ptr_iterator_t) iter;

 fail:
  state->mi->free_res(state->md);
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
          state->md->table_prefix);
  state->mi->write_timestamp(state->md, cmd_f, "", min_reg_time);
  fprintf(cmd_f, " AND (logintime = NULL OR logintime = 0) ;");
  close_memstream(cmd_f); cmd_f = 0;

  if (state->mi->query(state->md, cmd_t, cmd_z, 1) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0;
  count = state->md->row_count;
  if (!count) {
    state->mi->free_res(state->md);
    return 0;
  }

  // save the result set into the temp array
  XCALLOC(ids, count);
  for (i = 0; i < count; i++) {
    if (state->mi->int_val(state->md, &ids[i], 1) < 0) goto fail;
  }
  state->mi->free_res(state->md);

  for (i = 0; i < count; i++) {
    remove_user_func(data, ids[i]);
  }

  xfree(ids);
  return 0;

 fail:
  state->mi->free_res(state->md);
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
  fprintf(cmd_f, "UPDATE %slogins SET logintime = ", state->md->table_prefix);
  state->mi->write_timestamp(state->md, cmd_f, 0, cur_time);
  fprintf(cmd_f, " WHERE user_id = %d ;", user_id);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  remove_login_from_pool(state, user_id);

  if (contest_id > 0) {
    fetch_or_create_user_info(state, user_id, contest_id, &ui);
    cmd_f = open_memstream(&cmd_t, &cmd_z);
    fprintf(cmd_f, "UPDATE %susers SET logintime = ", state->md->table_prefix);
    state->mi->write_timestamp(state->md, cmd_f, 0, cur_time);
    fprintf(cmd_f, " WHERE user_id = %d AND contest_id = %d ;",
            user_id, contest_id);
    close_memstream(cmd_f); cmd_f = 0;
    if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
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
  unsigned char buf[64];

  if (state->mi->simple_fquery(state->md, "UPDATE %scookies SET contest_id = %d WHERE cookie = '%s' ;",
                               state->md->table_prefix, contest_id,
                               xml_unparse_full_cookie(buf, sizeof(buf), &c->cookie, &c->client_key)) < 0) return -1;
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
  unsigned char buf[64];

  if (state->mi->simple_fquery(state->md, "UPDATE %scookies SET locale_id = %d WHERE cookie = '%s' ;",
                               state->md->table_prefix, locale_id,
                               xml_unparse_full_cookie(buf, sizeof(buf), &c->cookie, &c->client_key)) < 0) return -1;
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
  unsigned char buf[64];

  if (state->mi->simple_fquery(state->md, "UPDATE %scookies SET priv_level = %d WHERE cookie = '%s' ;",
                               state->md->table_prefix, priv_level,
                               xml_unparse_full_cookie(buf, sizeof(buf), &c->cookie, &c->client_key)) < 0)
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
  state->locked_func = __FUNCTION__;
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
  int cookie_count = 0, reg_count = 0;
  unsigned long long *cookies = 0;
  ej_cookie_t *client_keys = NULL;
  int *cntsregs = 0;
  int i;

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

  if (state->mi->fquery(state->md, 1,
                "SELECT cookie FROM %scookies WHERE user_id = %d ;",
                state->md->table_prefix, user_id) < 0)
    return -1;
  if (state->md->row_count > 0) {
    cookie_count = state->md->row_count;
    XALLOCAZ(cookies, cookie_count);
    XALLOCAZ(client_keys, cookie_count);
    for (i = 0; i < cookie_count; i++) {
      if (state->mi->next_row(state->md) < 0) goto fail;
      if (!state->md->row[0]) goto fail;
      if (xml_parse_full_cookie(state->md->row[0], &cookies[i], &client_keys[i]) < 0)
        goto fail;
    }
  }
  state->mi->free_res(state->md);

  if (state->mi->fquery(state->md, 1,
                "SELECT contest_id FROM %scntsregs WHERE user_id = %d ;",
                state->md->table_prefix, user_id) < 0)
    goto fail;
  if (state->md->row_count > 0) {
    reg_count = state->md->row_count;
    XALLOCAZ(cntsregs, reg_count);
    for (i = 0; i < reg_count; i++) {
      if (state->mi->int_val(state->md, &cntsregs[i], 0) < 0) goto fail;
    }
  }
  state->mi->free_res(state->md);

  if (u->cookies) {
    u->cookies->first_down = u->cookies->last_down = 0;
  }
  for (i = 0; i < cookie_count; i++) {
    // FIXME: this is wrong...
    if (fetch_cookie(state, cookies[i], client_keys[i], &cc) < 0) goto fail;
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
  state->locked_func = __FUNCTION__;
  return 0;

 fail:
  state->mi->free_res(state->md);
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

  r->field_count = state->md->field_count;
  if (r->field_count <= 0) return;
  XCALLOC(r->lengths, r->field_count);
  XCALLOC(r->row, r->field_count);
  memcpy(r->lengths, state->md->lengths, sizeof(r->lengths[0]) * r->field_count);
  for (i = 0; i < r->field_count; i++) {
    if (!state->md->row[i])
      r->row[i] = 0;
    else
      r->row[i] = xstrdup(state->md->row[i]);
  }
}

static void
copy_saved_row_2(struct uldb_mysql_state *state, struct saved_row *r, int offset, int count)
{
  int i;

  ASSERT(offset >= 0);
  ASSERT(count > 0);
  ASSERT(offset + count <= state->md->field_count);
  r->field_count = count;
  XCALLOC(r->lengths, r->field_count);
  XCALLOC(r->row, r->field_count);
  memcpy(r->lengths, state->md->lengths + offset, sizeof(r->lengths[0]) * count);
  for (i = 0; i < r->field_count; ++i) {
    if (!state->md->row[i + offset]) {
      r->row[i] = 0;
    } else {
      r->row[i] = xstrdup(state->md->row[i + offset]);
    }
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
      if (u && parse_login(state, rr->field_count, rr->row, rr->lengths, u) < 0) {
        remove_login_from_pool(state, user_id);
        u = 0;
      }
    }
    if (!(ui = get_user_info_from_pool(state, user_id, iter->contest_id))) {
      rr = &iter->noreg_rows[iter->cur_ind].user_info_row;
      if (rr->field_count == USER_INFO_WIDTH && rr->row[0] != NULL) {
        ui = allocate_user_info_on_pool(state, user_id, iter->contest_id);
        if (ui && parse_user_info(state, rr->field_count,rr->row,rr->lengths,ui) < 0) {
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
      if (u && parse_login(state, rr->field_count, rr->row, rr->lengths, u) < 0) {
        remove_login_from_pool(state, user_id);
        u = 0;
      }
    }
    if (!(ui = get_user_info_from_pool(state, user_id, iter->contest_id))) {
      rr = &iter->full_rows[iter->cur_ind].user_info_row;
      if (rr->field_count == USER_INFO_WIDTH && rr->row[0] != NULL) {
        ui = allocate_user_info_on_pool(state, user_id, iter->contest_id);
        if (ui && parse_user_info(state, rr->field_count,rr->row,rr->lengths,ui) < 0) {
          remove_user_info_from_pool(state, user_id, iter->contest_id);
          ui = 0;
        }
      }
    }
    if (!(uc = get_cntsreg_from_pool(state, user_id, iter->contest_id))) {
      rr = &iter->full_rows[iter->cur_ind].cntsreg_row;
      if (rr->field_count == CNTSREG_WIDTH) {
        uc = allocate_cntsreg_on_pool(state, user_id, iter->contest_id);
        if (uc && parse_cntsreg(state, rr->field_count,rr->row,rr->lengths,uc) < 0) {
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

  XCALLOC(iter, 1);
  iter->b = brief_list_iterator_funcs;
  iter->state = state;
  iter->contest_id = contest_id;
  iter->cur_ind = 0;

  if (!contest_id) {
    if (state->mi->fquery(state->md, LOGIN_WIDTH,
                  "SELECT * FROM %slogins WHERE 1 ORDER BY user_id ;",
                  state->md->table_prefix) < 0)
      goto fail;
    iter->total_ids = state->md->row_count;
    if (!iter->total_ids) {
      state->mi->free_res(state->md);
      return (ptr_iterator_t) iter;
    }

    XCALLOC(iter->noreg_rows, iter->total_ids);
    for (i = 0; i < iter->total_ids; i++) {
      if (!(state->md->row = mysql_fetch_row(state->md->res)))
        db_error_no_data_fail(state->md);
      state->md->lengths = mysql_fetch_lengths(state->md->res);
      if (!state->md->lengths[0])
        db_error_inv_value_fail(state->md, "value");
      if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
        db_error_inv_value_fail(state->md, "value");
      iter->noreg_rows[i].user_id = val;
      copy_saved_row(state, &iter->noreg_rows[i].login_row);
    }

    state->mi->free_res(state->md);
    if (state->mi->fquery(state->md, USER_INFO_WIDTH,
                  "SELECT * FROM %susers WHERE contest_id = 0 ORDER BY user_id ;",
                  state->md->table_prefix) < 0)
      goto fail;
    j = 0;
    for (i = 0; i < state->md->row_count; i++) {
      if (!(state->md->row = mysql_fetch_row(state->md->res)))
        db_error_no_data_fail(state->md);
      state->md->lengths = mysql_fetch_lengths(state->md->res);
      if (!state->md->lengths[0])
        db_error_inv_value_fail(state->md, "value");
      if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
        db_error_inv_value_fail(state->md, "value");
      while (j < iter->total_ids && iter->noreg_rows[j].user_id < val) j++;
      if (j < iter->total_ids && iter->noreg_rows[j].user_id == val) {
        copy_saved_row(state, &iter->noreg_rows[j].user_info_row);
      }
    }

    state->mi->free_res(state->md);
    return (ptr_iterator_t) iter;
  }

  if (state->mi->fquery(state->md, LOGIN_WIDTH,
                "SELECT %slogins.* FROM %slogins, %scntsregs WHERE %slogins.user_id = %scntsregs.user_id AND %scntsregs.contest_id = %d ORDER BY %slogins.user_id ;",
                state->md->table_prefix, state->md->table_prefix, state->md->table_prefix,
                state->md->table_prefix, state->md->table_prefix, state->md->table_prefix,
                contest_id, state->md->table_prefix) < 0)
    goto fail;

  iter->total_ids = state->md->row_count;
  if (!iter->total_ids) {
    state->mi->free_res(state->md);
    return (ptr_iterator_t) iter;
  }
  XCALLOC(iter->full_rows, iter->total_ids);
  for (i = 0; i < iter->total_ids; i++) {
    if (!(state->md->row = mysql_fetch_row(state->md->res)))
      db_error_no_data_fail(state->md);
    state->md->lengths = mysql_fetch_lengths(state->md->res);
    if (!state->md->lengths[0])
      db_error_inv_value_fail(state->md, "value");
    if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
      db_error_inv_value_fail(state->md, "value");
    iter->full_rows[i].user_id = val;
    copy_saved_row(state, &iter->full_rows[i].login_row);
  }
  state->mi->free_res(state->md);

  if (state->mi->fquery(state->md, USER_INFO_WIDTH,
                "SELECT * FROM %susers WHERE contest_id = %d ORDER BY user_id ;",
                state->md->table_prefix, contest_id) < 0)
    goto fail;
  j = 0;
  for (i = 0; i < state->md->row_count; i++) {
    if (!(state->md->row = mysql_fetch_row(state->md->res)))
      db_error_no_data_fail(state->md);
    state->md->lengths = mysql_fetch_lengths(state->md->res);
    if (!state->md->lengths[0])
      db_error_inv_value_fail(state->md, "value");
    if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
      db_error_inv_value_fail(state->md, "value");
    while (j < iter->total_ids && iter->full_rows[j].user_id < val) j++;
    if (j < iter->total_ids && iter->full_rows[j].user_id == val) {
      copy_saved_row(state, &iter->full_rows[j].user_info_row);
    }
  }
  state->mi->free_res(state->md);

  if (state->mi->fquery(state->md, CNTSREG_WIDTH,
                "SELECT * FROM %scntsregs WHERE contest_id = %d ORDER BY user_id ;",
                state->md->table_prefix, contest_id) < 0)
    goto fail;
  j = 0;
  for (i = 0; i < state->md->row_count; i++) {
    if (!(state->md->row = mysql_fetch_row(state->md->res)))
      db_error_no_data_fail(state->md);
    state->md->lengths = mysql_fetch_lengths(state->md->res);
    if (!state->md->lengths[0])
      db_error_inv_value_fail(state->md, "value");
    if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
      db_error_inv_value_fail(state->md, "value");
    while (j < iter->total_ids && iter->full_rows[j].user_id < val) j++;
    if (j < iter->total_ids && iter->full_rows[j].user_id == val) {
      copy_saved_row(state, &iter->full_rows[j].cntsreg_row);
    }
  }
  state->mi->free_res(state->md);

  return (ptr_iterator_t) iter;

 fail:
  state->mi->free_res(state->md);
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
    if (parse_member(state, beg->field_count, beg->row, beg->lengths, m) < 0)
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
    if (u && parse_login(state, rr->field_count, rr->row, rr->lengths, u) < 0) {
      remove_login_from_pool(state, user_id);
      u = 0;
    }
  }
  if (!(ui = get_user_info_from_pool(state, user_id, iter->contest_id))) {
    rr = &iter->full_rows[iter->cur_ind].user_info_row;
    if (rr->field_count == USER_INFO_WIDTH) {
      ui = allocate_user_info_on_pool(state, user_id, iter->contest_id);
      if (ui && parse_user_info(state, rr->field_count,rr->row,rr->lengths,ui) < 0){
        remove_user_info_from_pool(state, user_id, iter->contest_id);
        ui = 0;
      }
    }
  }
  if (!(uc = get_cntsreg_from_pool(state, user_id, iter->contest_id))) {
    rr = &iter->full_rows[iter->cur_ind].cntsreg_row;
    if (rr->field_count == CNTSREG_WIDTH) {
      uc = allocate_cntsreg_on_pool(state, user_id, iter->contest_id);
      if (uc && parse_cntsreg(state, rr->field_count,rr->row,rr->lengths,uc) < 0) {
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

  ASSERT(contest_id > 0);

  XCALLOC(iter, 1);
  iter->b = standings_list_iterator_funcs;
  iter->state = state;
  iter->contest_id = contest_id;
  iter->cur_ind = 0;
  iter->cur_memb = 0;

  if (state->mi->fquery(state->md, LOGIN_WIDTH,
                "SELECT %slogins.* FROM %slogins, %scntsregs WHERE %slogins.user_id = %scntsregs.user_id AND %scntsregs.contest_id = %d ORDER BY %slogins.user_id ;",
                state->md->table_prefix, state->md->table_prefix, state->md->table_prefix,
                state->md->table_prefix, state->md->table_prefix, state->md->table_prefix,
                contest_id, state->md->table_prefix) < 0)
    goto fail;
  iter->total_ids = state->md->row_count;
  if (!iter->total_ids) {
    state->mi->free_res(state->md);
    return (ptr_iterator_t) iter;
  }
  XCALLOC(iter->full_rows, iter->total_ids);
  for (i = 0; i < iter->total_ids; i++) {
    if (!(state->md->row = mysql_fetch_row(state->md->res)))
      db_error_no_data_fail(state->md);
    state->md->lengths = mysql_fetch_lengths(state->md->res);
    if (!state->md->lengths[0])
      db_error_inv_value_fail(state->md, "value");
    if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
      db_error_inv_value_fail(state->md, "value");
    iter->full_rows[i].user_id = val;
    copy_saved_row(state, &iter->full_rows[i].login_row);
  }
  state->mi->free_res(state->md);

  if (state->mi->fquery(state->md, USER_INFO_WIDTH,
                "SELECT * FROM %susers WHERE contest_id = %d ORDER BY user_id ;",
                state->md->table_prefix, contest_id) < 0)
    goto fail;
  j = 0;
  for (i = 0; i < state->md->row_count; i++) {
    if (!(state->md->row = mysql_fetch_row(state->md->res)))
      db_error_no_data_fail(state->md);
    state->md->lengths = mysql_fetch_lengths(state->md->res);
    if (!state->md->lengths[0])
      db_error_inv_value_fail(state->md, "value");
    if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
      db_error_inv_value_fail(state->md, "value");
    while (j < iter->total_ids && iter->full_rows[j].user_id < val) j++;
    if (j < iter->total_ids && iter->full_rows[j].user_id == val) {
      copy_saved_row(state, &iter->full_rows[j].user_info_row);
    }
  }
  state->mi->free_res(state->md);

  if (state->mi->fquery(state->md, CNTSREG_WIDTH,
                "SELECT * FROM %scntsregs WHERE contest_id = %d ORDER BY user_id ;",
                state->md->table_prefix, contest_id) < 0)
    goto fail;
  j = 0;
  for (i = 0; i < state->md->row_count; i++) {
    if (!(state->md->row = mysql_fetch_row(state->md->res)))
      db_error_no_data_fail(state->md);
    state->md->lengths = mysql_fetch_lengths(state->md->res);
    if (!state->md->lengths[0])
      db_error_inv_value_fail(state->md, "value");
    if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
      db_error_inv_value_fail(state->md, "value");
    while (j < iter->total_ids && iter->full_rows[j].user_id < val) j++;
    if (j < iter->total_ids && iter->full_rows[j].user_id == val) {
      copy_saved_row(state, &iter->full_rows[j].cntsreg_row);
    }
  }
  state->mi->free_res(state->md);

  if (state->mi->fquery(state->md, MEMBER_WIDTH,
                "SELECT * FROM %smembers WHERE contest_id = %d ORDER BY user_id ;",
                state->md->table_prefix, contest_id) < 0)
    goto fail;
  iter->total_membs = state->md->row_count;
  if (iter->total_membs > 0) {
    XCALLOC(iter->memb_rows, iter->total_membs);
    XCALLOC(iter->memb_ids, iter->total_membs);
    for (i = 0; i < iter->total_membs; i++) {
      if (state->mi->next_row(state->md) < 0) goto fail;
      if (state->mi->parse_int(state->md, state->md->row[1], &val) < 0 || val <= 0)
        db_error_inv_value_fail(state->md, "value");
      iter->memb_ids[i] = val;
      copy_saved_row(state, &iter->memb_rows[i]);
    }
  }
  state->mi->free_res(state->md);

  return (ptr_iterator_t) iter;

 fail:
  state->mi->free_res(state->md);
  standings_list_iterator_destroy_func((ptr_iterator_t) iter);
  return 0;
}

static int
check_user_func(
        void *data,
        int user_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct userlist_user *u = 0;

  if (state->cache_queries && (u = get_login_from_pool(state, user_id)))
    return 0;

  if (state->mi->fquery(state->md, 1, "SELECT user_id FROM %slogins WHERE user_id = %d ;", state->md->table_prefix, user_id) < 0) {
    state->mi->free_res(state->md);
    return -1;
  }
  if (state->md->row_count <= 0) {
    state->mi->free_res(state->md);
    return -1;
  }
  state->mi->free_res(state->md);
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
          state->md->table_prefix, method);
  state->mi->write_escaped_string(state->md, cmd_f, 0, password);
  fprintf(cmd_f, ", pwdtime = ");
  state->mi->write_timestamp(state->md, cmd_f, 0, cur_time);
  fprintf(cmd_f, " WHERE user_id = %d ;", user_id);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
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
  struct userlist_user_info *ui = 0;

  if (cur_time <= 0) cur_time = time(0);

  if (fetch_or_create_user_info(state, user_id, contest_id, &ui) < 0)
    goto fail;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %susers SET pwdmethod = %d, password = ",
          state->md->table_prefix, method);
  state->mi->write_escaped_string(state->md, cmd_f, 0, password);
  fprintf(cmd_f, ", pwdtime = ");
  state->mi->write_timestamp(state->md, cmd_f, 0, cur_time);
  fprintf(cmd_f, " WHERE user_id = %d AND contest_id = %d;",
          user_id, contest_id);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
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
        int flags,
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
  new_uc.flags = flags;
  new_uc.create_time = cur_time;
  new_uc.last_change_time = cur_time;
  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %scntsregs VALUES (", state->md->table_prefix);
  unparse_cntsreg(state, cmd_f, user_id, &new_uc);
  fprintf(cmd_f, " );");
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
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

  if (state->mi->simple_fquery(state->md, "DELETE FROM %smembers WHERE user_id = %d AND contest_id = %d AND serial = %d ;", state->md->table_prefix, user_id, contest_id, serial) < 0) return -1;
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
    if (u && parse_login(state, rr->field_count, rr->row, rr->lengths, u) < 0) {
      remove_login_from_pool(state, user_id);
      u = 0;
    }
  }
  if (!(ui = get_user_info_from_pool(state, user_id, iter->contest_id))) {
    rr = &iter->full_rows[iter->cur_ind].user_info_row;
    if (rr->field_count == USER_INFO_WIDTH) {
      ui = allocate_user_info_on_pool(state, user_id, iter->contest_id);
      if (ui && parse_user_info(state, rr->field_count,rr->row,rr->lengths,ui) < 0){
        remove_user_info_from_pool(state, user_id, iter->contest_id);
        ui = 0;
      }
    }
  }
  if (!(uc = get_cntsreg_from_pool(state, user_id, iter->contest_id))) {
    rr = &iter->full_rows[iter->cur_ind].cntsreg_row;
    if (rr->field_count == CNTSREG_WIDTH) {
      uc = allocate_cntsreg_on_pool(state, user_id, iter->contest_id);
      if (uc && parse_cntsreg(state, rr->field_count,rr->row,rr->lengths,uc) < 0) {
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
    if (mm && !ui
        && fetch_or_create_user_info(state,user_id,iter->contest_id,&ui)<0)
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

  ASSERT(contest_id > 0);
  flag_mask &= USERLIST_UC_ALL;

  XCALLOC(iter, 1);
  iter->b = info_list_iterator_funcs;
  iter->state = state;
  iter->contest_id = contest_id;
  iter->cur_ind = 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "SELECT %slogins.* FROM %slogins, %scntsregs AS R WHERE %slogins.user_id = R.user_id AND R.contest_id = %d ", state->md->table_prefix, state->md->table_prefix, state->md->table_prefix, state->md->table_prefix, contest_id);
  if (!flag_mask) {
    fprintf(cmd_f, " AND R.banned = 0 AND R.invisible = 0 AND R.locked = 0 AND R.incomplete = 0 AND R.disqualified = 0 AND R.privileged = 0 AND R.reg_readonly = 0 ");
  } else if (flag_mask != USERLIST_UC_ALL) {
    fprintf(cmd_f, " AND ((R.banned = 0 AND R.invisible = 0 AND R.locked = 0 AND R.incomplete = 0 AND R.disqualified = 0 AND R.privileged = 0 AND R.reg_readonly = 0) ");
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
    if ((flag_mask & USERLIST_UC_PRIVILEGED))
      fprintf(cmd_f, " OR R.privileged = 1 ");
    if ((flag_mask & USERLIST_UC_REG_READONLY))
      fprintf(cmd_f, " OR R.reg_readonly = 1 ");
    fprintf(cmd_f, ") ");
  }
  fprintf(cmd_f, "ORDER BY %slogins.user_id ; ", state->md->table_prefix);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->query(state->md, cmd_t, cmd_z, LOGIN_WIDTH) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  iter->total_ids = state->md->row_count;
  if (!iter->total_ids) {
    state->mi->free_res(state->md);
    return (ptr_iterator_t) iter;
  }
  XCALLOC(iter->full_rows, iter->total_ids);
  for (i = 0; i < iter->total_ids; i++) {
    if (!(state->md->row = mysql_fetch_row(state->md->res)))
      db_error_no_data_fail(state->md);
    state->md->lengths = mysql_fetch_lengths(state->md->res);
    if (!state->md->lengths[0])
      db_error_inv_value_fail(state->md, "value");
    if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
      db_error_inv_value_fail(state->md, "value");
    iter->full_rows[i].user_id = val;
    copy_saved_row(state, &iter->full_rows[i].login_row);
  }
  state->mi->free_res(state->md);

  if (state->mi->fquery(state->md, USER_INFO_WIDTH,
                "SELECT * FROM %susers WHERE contest_id = %d ORDER BY user_id ;",
                state->md->table_prefix, contest_id) < 0)
    goto fail;
  j = 0;
  for (i = 0; i < state->md->row_count; i++) {
    if (!(state->md->row = mysql_fetch_row(state->md->res)))
      db_error_no_data_fail(state->md);
    state->md->lengths = mysql_fetch_lengths(state->md->res);
    if (!state->md->lengths[0])
      db_error_inv_value_fail(state->md, "value");
    if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
      db_error_inv_value_fail(state->md, "value");
    while (j < iter->total_ids && iter->full_rows[j].user_id < val) j++;
    if (j < iter->total_ids && iter->full_rows[j].user_id == val) {
      copy_saved_row(state, &iter->full_rows[j].user_info_row);
    }
  }
  state->mi->free_res(state->md);

  if (state->mi->fquery(state->md, CNTSREG_WIDTH,
                "SELECT * FROM %scntsregs WHERE contest_id = %d ORDER BY user_id ;",
                state->md->table_prefix, contest_id) < 0)
    goto fail;
  j = 0;
  for (i = 0; i < state->md->row_count; i++) {
    if (!(state->md->row = mysql_fetch_row(state->md->res)))
      db_error_no_data_fail(state->md);
    state->md->lengths = mysql_fetch_lengths(state->md->res);
    if (!state->md->lengths[0])
      db_error_inv_value_fail(state->md, "value");
    if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
      db_error_inv_value_fail(state->md, "value");
    while (j < iter->total_ids && iter->full_rows[j].user_id < val) j++;
    if (j < iter->total_ids && iter->full_rows[j].user_id == val) {
      copy_saved_row(state, &iter->full_rows[j].cntsreg_row);
    }
  }
  state->mi->free_res(state->md);

  if (state->mi->fquery(state->md, MEMBER_WIDTH,
                "SELECT * FROM %smembers WHERE contest_id = %d ORDER BY user_id ;",
                state->md->table_prefix, contest_id) < 0)
    goto fail;
  iter->total_membs = state->md->row_count;
  if (iter->total_membs > 0) {
    XCALLOC(iter->memb_rows, iter->total_membs);
    XCALLOC(iter->memb_ids, iter->total_membs);
    for (i = 0; i < iter->total_membs; i++) {
      if (state->mi->next_row(state->md) < 0) goto fail;
      if (state->mi->parse_int(state->md, state->md->row[1], &val) < 0 || val <= 0)
        db_error_inv_value_fail(state->md, "value");
      iter->memb_ids[i] = val;
      copy_saved_row(state, &iter->memb_rows[i]);
    }
  }
  state->mi->free_res(state->md);

  return (ptr_iterator_t) iter;

 fail:
  state->mi->free_res(state->md);
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

  if (state->mi->simple_fquery(state->md, "UPDATE %susers SET password = NULL, pwdmethod = 0 WHERE user_id = %d AND contest_id = %d ;", state->md->table_prefix, user_id, contest_id) < 0) return -1;
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

  if (state->mi->simple_fquery(state->md, "DELETE FROM %scntsregs WHERE user_id = %d AND contest_id = %d ;", state->md->table_prefix, user_id, contest_id) < 0)
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

  if (state->mi->simple_fquery(state->md, "UPDATE %scntsregs SET status = %d WHERE user_id = %d AND contest_id = %d ;", state->md->table_prefix, status, user_id, contest_id) < 0)
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
  ASSERT(cmd >= 0 && cmd <= 4);
  value &= USERLIST_UC_ALL;

  if (!cmd) return 0;
  if (cmd != 4 && !value) return 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %scntsregs SET ", state->md->table_prefix);
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
    if ((value & USERLIST_UC_PRIVILEGED)) {
      fprintf(cmd_f, "%sprivileged = 1", sep);
      sep = ", ";
    }
    if ((value & USERLIST_UC_REG_READONLY)) {
      fprintf(cmd_f, "%sreg_readonly = 1", sep);
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
    if ((value & USERLIST_UC_PRIVILEGED)) {
      fprintf(cmd_f, "%sprivileged = 0", sep);
      sep = ", ";
    }
    if ((value & USERLIST_UC_REG_READONLY)) {
      fprintf(cmd_f, "%sreg_readonly = 0", sep);
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
    if ((value & USERLIST_UC_PRIVILEGED)) {
      fprintf(cmd_f, "%sprivileged = 1 - privileged", sep);
      sep = ", ";
    }
    if ((value & USERLIST_UC_REG_READONLY)) {
      fprintf(cmd_f, "%sreg_readonly = 1 - reg_readonly", sep);
      sep = ", ";
    }
    break;
  case 4:                       /* copy */
    fprintf(cmd_f, "%sinvisible = %d", sep, !!(value & USERLIST_UC_INVISIBLE));
    sep = ", ";
    fprintf(cmd_f, "%sbanned = %d", sep, !!(value & USERLIST_UC_BANNED));
    sep = ", ";
    fprintf(cmd_f, "%slocked = %d", sep, !!(value & USERLIST_UC_LOCKED));
    sep = ", ";
    fprintf(cmd_f, "%sincomplete = %d", sep, !!(value & USERLIST_UC_INCOMPLETE));
    sep = ", ";
    fprintf(cmd_f, "%sdisqualified = %d", sep, !!(value & USERLIST_UC_DISQUALIFIED));
    sep = ", ";
    fprintf(cmd_f, "%sprivileged = %d", sep, !!(value & USERLIST_UC_PRIVILEGED));
    sep = ", ";
    fprintf(cmd_f, "%sreg_readonly = %d", sep, !!(value & USERLIST_UC_REG_READONLY));
    sep = ", ";
    break;
  default:
    abort();
  }
  fprintf(cmd_f, " WHERE user_id = %d AND contest_id = %d ;",
          user_id, contest_id);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
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
          state->md->table_prefix, user_id, contest_id);
  fprintf(cmd_f, "DELETE FROM %smembers WHERE user_id = %d AND contest_id = %d ;",
          state->md->table_prefix, user_id, contest_id);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
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
  fprintf(cmd_f, "UPDATE %slogins SET ", state->md->table_prefix);
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
  state->mi->write_timestamp(state->md, cmd_f, 0, cur_time);
  fprintf(cmd_f, " WHERE user_id = %d ;", user_id);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
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
  fprintf(cmd_f, "UPDATE %susers SET ", state->md->table_prefix);
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
  state->mi->write_timestamp(state->md, cmd_f, 0, cur_time);
  fprintf(cmd_f, " WHERE user_id = %d AND contest_id = %d;",
          user_id, contest_id);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
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
  fprintf(cmd_f, "UPDATE %smembers SET ", state->md->table_prefix);
  switch (fields[field_id].field_type) {
  case USERLIST_NM_STATUS:
    fprintf(cmd_f, "%s = 0", fields[field_id].sql_name);
    break;
  case USERLIST_NM_GENDER:
    fprintf(cmd_f, "%s = 0", fields[field_id].sql_name);
    break;
  case USERLIST_NM_GRADE:
    fprintf(cmd_f, "%s = -1", fields[field_id].sql_name);
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
  state->mi->write_timestamp(state->md, cmd_f, 0, cur_time);
  fprintf(cmd_f, " WHERE serial = %d ;", serial);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
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
  fprintf(cmd_f, "UPDATE %slogins SET ", state->md->table_prefix);
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
    state->mi->write_escaped_string(state->md, cmd_f, 0, value);
    break;
  case USERLIST_NN_EMAIL:
    fprintf(cmd_f, "%s = ", fields[field_id].sql_name);
    state->mi->write_escaped_string(state->md, cmd_f, 0, value);
    break;
  case USERLIST_NN_PASSWD:
    state->mi->write_escaped_string(state->md, cmd_f, "password = ", value);
    fprintf(cmd_f, ", pwdmethod = 0");
    tsvarname = "pwdtime";
    break;
  case USERLIST_NN_REGISTRATION_TIME:
    if (userlist_set_user_field_str(&arena, field_id, value) < 0) goto fail;
    v_time = *(time_t*) p_field;
    fprintf(cmd_f, "%s = ", fields[field_id].sql_name);
    state->mi->write_timestamp(state->md, cmd_f, 0, v_time);
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
  state->mi->write_timestamp(state->md, cmd_f, 0, cur_time);
  fprintf(cmd_f, " WHERE user_id = %d ;", user_id);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
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
  fprintf(cmd_f, "UPDATE %susers SET ", state->md->table_prefix);
  switch (fields[field_id].field_type) {
  case USERLIST_NC_CNTS_READ_ONLY:
    if (userlist_set_user_info_field_str(&arena, field_id, value) < 0)
      goto fail;
    v_int = *(int*) p_field;
    fprintf(cmd_f, "%s = %d", fields[field_id].sql_name, v_int);
    break;
  case USERLIST_NC_NAME:
    fprintf(cmd_f, "%s = ", fields[field_id].sql_name);
    state->mi->write_escaped_string(state->md, cmd_f, 0, value);
    break;
  case USERLIST_NC_TEAM_PASSWD:
    state->mi->write_escaped_string(state->md, cmd_f, "password = ", value);
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
    state->mi->write_escaped_string(state->md, cmd_f, 0, value);
    break;
  case USERLIST_NC_CREATE_TIME:
    if (userlist_set_user_info_field_str(&arena, field_id, value) < 0)
      goto fail;
    v_time = *(time_t*) p_field;
    fprintf(cmd_f, "%s = ", fields[field_id].sql_name);
    state->mi->write_timestamp(state->md, cmd_f, 0, v_time);
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
  state->mi->write_timestamp(state->md, cmd_f, 0, cur_time);
  fprintf(cmd_f, " WHERE user_id = %d AND contest_id = %d;",
          user_id, contest_id);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
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
  fprintf(cmd_f, "UPDATE %smembers SET ", state->md->table_prefix);
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
    state->mi->write_escaped_string(state->md, cmd_f, 0, value);
    break;
  case USERLIST_NM_CREATE_TIME:
    if (userlist_set_member_field_str(&arena, field_id, value) < 0)
      goto fail;
    v_time = *(time_t*) p_field;
    fprintf(cmd_f, "%s = ", fields[field_id].sql_name);
    state->mi->write_timestamp(state->md, cmd_f, 0, v_time);
    break;
  case USERLIST_NM_LAST_CHANGE_TIME:
    sep = "";
    break;
  case USERLIST_NM_BIRTH_DATE:
    if (userlist_set_member_field_str(&arena, field_id, value) < 0)
      goto fail;
    v_time = *(time_t*) p_field;
    fprintf(cmd_f, "%s = ", fields[field_id].sql_name);
    state->mi->write_date(state->md, cmd_f, 0, v_time);
    break;
  default:
    abort();
  }
  fprintf(cmd_f, "%s%s = ", sep, "changetime");
  state->mi->write_timestamp(state->md, cmd_f, 0, cur_time);
  fprintf(cmd_f, " WHERE serial = %d ;", serial);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
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
  int current_member = -1;
  struct userlist_member arena;

  ASSERT(user_id > 0);
  ASSERT(contest_id >= 0);
  ASSERT(role >= 0 && role < USERLIST_MB_LAST);
  if (cur_time <= 0) cur_time = time(0);
  memset(&arena, 0, sizeof(arena));

  arena.team_role = role;
  arena.serial = -1;
  arena.grade = -1;
  arena.create_time = cur_time;
  arena.last_change_time = cur_time;
  if (insert_member_info(state, user_id, contest_id, &arena, 0) < 0) goto fail;
  if (!(state->md->res = mysql_store_result(state->md->conn))
      && !mysql_field_count(state->md->conn)
      && mysql_insert_id(state->md->conn)) {
    current_member = mysql_insert_id(state->md->conn);
  }
  info("new member serial = %d", current_member);
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
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  int total_uids = 0;
  int *uids = 0;
  int i, j, k;

  if (cur_time <= 0) cur_time = time(0);
  if (cur_time <= state->last_maint_time + state->maint_interval) return 0;

  if (state->total_unused_ids > 0
      && state->cur_unused_id < state->total_unused_ids)
    return 0;

  state->last_maint_time = cur_time;

  xfree(state->unused_ids); state->unused_ids = 0;
  state->total_unused_ids = 0;
  state->cur_unused_id = 0;

  if (state->mi->fquery(state->md, 1, "SELECT user_id FROM %slogins WHERE 1 ORDER BY user_id ;", state->md->table_prefix) < 0)
    goto fail;
  if (state->md->row_count <= 0) return 0;

  state->total_unused_ids = 0;
  total_uids = state->md->row_count;
  XCALLOC(uids, total_uids + 1);
  uids[0] = 0;
  for (i = 1; i <= total_uids; i++) {
    if (state->mi->int_val(state->md, &uids[i], 1) < 0)
      goto fail;
    ASSERT(uids[i] > uids[i - 1]);
    state->total_unused_ids += (uids[i] - uids[i - 1] - 1);
  }
  state->mi->free_res(state->md);

  if (!state->total_unused_ids) goto done;
  XCALLOC(state->unused_ids, state->total_unused_ids);
  for (i = 1, k = 0; i <= total_uids; i++) {
    for (j = uids[i - 1] + 1; j < uids[i]; j++)
      state->unused_ids[k++] = j;
  }
  ASSERT(k == state->total_unused_ids);
  info("%d unused user_ids detected", state->total_unused_ids);

 done:
  xfree(uids);
  state->mi->free_res(state->md);
  return 0;

 fail:
  xfree(uids);
  return -1;
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

  ASSERT(user_id > 0);
  ASSERT(from_cnts >= 0);
  ASSERT(to_cnts >= 0);
  if (cur_time <= 0) cur_time = time(0);
  if (from_cnts == to_cnts) return 0;

  if (state->mi->simple_fquery(state->md, "DELETE FROM %susers WHERE user_id = %d AND contest_id = %d ;", state->md->table_prefix, user_id, to_cnts) < 0) goto fail;
  if (state->mi->simple_fquery(state->md, "DELETE FROM %smembers WHERE user_id = %d AND contest_id = %d ;", state->md->table_prefix, user_id, to_cnts) < 0) goto fail;

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
    if (cnts && cnts->enable_avatar > 0) {
      u_arena.avatar_store = ui->avatar_store;
      u_arena.avatar_id = ui->avatar_id;
      u_arena.avatar_suffix = ui->avatar_suffix;
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
      cm = 0;
      if (cnts) {
        cm = cnts->members[cur_memb];
        if (!cm) continue;
      }
      m_cur[m->team_role]++;

      memset(&m_arena, 0, sizeof(m_arena));
      m_arena.serial = -1;
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

  if ((c->flags & USERLIST_UC_PRIVILEGED)) {
    if ((c->flags & USERLIST_UC_INCOMPLETE)) {
      val = 0;
    } else {
      return 0;
    }
  } else {
    if (!nerr && (c->flags & USERLIST_UC_INCOMPLETE)) {
      val = 0;
    } else if (nerr > 0 && !(c->flags & USERLIST_UC_INCOMPLETE)
               && (!ui || !ui->cnts_read_only)) {
      val = 1;
    } else {
      return 0;
    }
  }

  if (state->mi->simple_fquery(state->md, "UPDATE %scntsregs SET incomplete = %d WHERE user_id = %d AND contest_id = %d ;", state->md->table_prefix, val, user_id, contest_id) < 0) return -1;
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
          state->md->table_prefix, new_role);
  state->mi->write_timestamp(state->md, cmd_f, 0, cur_time);
  fprintf(cmd_f, " WHERE serial = %d ; ", serial);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  state->mi->free_res(state->md);
  remove_member_from_pool(state, user_id, contest_id);
  if (p_cloned_flag) *p_cloned_flag = 0;
  return 0;

 fail:
  state->mi->free_res(state->md);
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
  unsigned char buf[64];

  if (state->cache_queries && c->team_login == team_login) return 0;

  ASSERT(team_login >= 0 && team_login <= 1);
  if (state->mi->simple_fquery(state->md, "UPDATE %scookies SET team_login = %d WHERE cookie = '%s' ;",
                               state->md->table_prefix, team_login,
                               xml_unparse_full_cookie(buf, sizeof(buf), &c->cookie, &c->client_key)) < 0) return -1;
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

  return 0;
}

static int
get_member_serial_func(void *data)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  size_t cmdlen;
  unsigned char cmdbuf[1024];
  int current_member = -1;

  snprintf(cmdbuf, sizeof(cmdbuf), "SELECT MAX(serial) FROM %smembers WHERE 1 ;", state->md->table_prefix);
  cmdlen = strlen(cmdbuf);
  if (state->mi->query_one_row(state->md, cmdbuf, cmdlen, 1) < 0) goto fail;
  if (!state->md->lengths[0])
    db_error_inv_value_fail(state->md, "value");
  if (state->mi->parse_int(state->md, state->md->row[0], &current_member) < 0 || current_member <= 0)
    db_error_inv_value_fail(state->md, "value");
  state->mi->free_res(state->md);
  return current_member;

 fail:
  state->mi->free_res(state->md);
  return -1;
}

static int
set_member_serial_func(void *data, int new_serial)
{
  //struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  return -1;
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

  if (!c_u) return;

  // detach all existing user_infos
  for (i = 0; i < u->cis_a; ++i) {
    u->cis[i] = NULL;
  }
  xfree(u->cis);
  u->cis = NULL;
  u->cis_a = 0;
  u->cnts0 = NULL;

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

static void
drop_cache_func(void *data)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  drop_login_cache(state);
  drop_user_info_cache(state);
  drop_members_cache(state);
  drop_cookie_cache(state);
  drop_cntsreg_cache(state);
  info("MySQL query cache is dropped");
}

static void
disable_cache_func(void *data)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  drop_cache_func(data);
  state->cache_queries = 0;
  info("MySQL query caching is disabled");
}

static void
enable_cache_func(void *data)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  state->cache_queries = 1;
  info("MySQL query caching is enabled");
}

static void
convert_to_pattern(unsigned char *out, const unsigned char *in)
{
  unsigned char *pout = out;
  const unsigned char *pin = in;
  while (*pin) {
    if (*pin != '%') {
      *pout++ = *pin++;
      continue;
    }
    *pout++ = *pin++;
    while (*pin && *pin != 'd' && *pin != 'u' && *pin != 'x' && *pin != 'X'
           && *pin != 'o')
      pin++;
    if (*pin) pin++;
  }
  *pout = 0;
}

static int
try_new_login_func(
        void *data,
        unsigned char *buf,
        size_t bufsize,
        const char *format,
        int serial,
        int serial_step)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  size_t flen;
  unsigned char *patt;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  int total_logins = 0, i;
  unsigned char **logins = 0;

  ASSERT(serial >= 0);

  flen = strlen(format);
  patt = (unsigned char *) alloca(flen + 10);
  convert_to_pattern(patt, format);
  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "SELECT login FROM %slogins WHERE login LIKE(",
          state->md->table_prefix);
  state->mi->write_escaped_string(state->md, cmd_f, 0, patt);
  fprintf(cmd_f, ") ;");
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->query(state->md, cmd_t, cmd_z, 1) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  if (state->md->row_count <= 0) {
    snprintf(buf, bufsize, format, serial);
    state->mi->free_res(state->md);
    return serial;
  }
  total_logins = state->md->row_count;
  XCALLOC(logins, total_logins);
  for (i = 0; i < total_logins; i++) {
    if (state->mi->next_row(state->md) < 0) goto fail;
    logins[i] = xstrdup(state->md->row[0]);
  }
  state->mi->free_res(state->md);

  serial -= serial_step;
  do {
    serial += serial_step;
    snprintf(buf, bufsize, format, serial);
    for (i = 0; i < total_logins; i++)
      if (!strcmp(buf, logins[i]))
        break;
  } while (i < total_logins);

  for (i = 0; i < total_logins; i++)
    xfree(logins[i]);
  xfree(logins);
  return serial;

 fail:
  if (logins) {
    for (i = 0; i < total_logins; i++)
      xfree(logins[i]);
  }
  xfree(logins);
  state->mi->free_res(state->md);
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
set_simple_reg_func(
        void *data,
        int user_id,
        int value,
        time_t cur_time)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  if (cur_time <= 0) cur_time = time(0);
  value = !!value;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %slogins SET simplereg = %d, changetime = ",
          state->md->table_prefix, value);
  state->mi->write_timestamp(state->md, cmd_f, 0, cur_time);
  fprintf(cmd_f, " WHERE user_id = %d ;", user_id);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  remove_login_from_pool(state, user_id);
  return 0;

 fail:
  remove_login_from_pool(state, user_id);
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

struct group_iterator
{
  struct ptr_iterator b;

  int group_count;
  int cur_group;
  struct userlist_group **groups;
};

static int
group_iterator_has_next_func(ptr_iterator_t data)
{
  struct group_iterator *iter = (struct group_iterator*) data;
  if (!iter || iter->cur_group >= iter->group_count) return 0;
  return 1;
}

static const void *
group_iterator_get_func(ptr_iterator_t data)
{
  struct group_iterator *iter = (struct group_iterator*) data;

  if (!iter || iter->cur_group >= iter->group_count) return 0;
  return iter->groups[iter->cur_group];
}

static void
group_iterator_next_func(ptr_iterator_t data)
{
  struct group_iterator *iter = (struct group_iterator*) data;

  if (!iter || iter->cur_group >= iter->group_count) return;
  ++iter->cur_group;
}

static void
group_iterator_destroy_func(ptr_iterator_t data)
{
  struct group_iterator *iter = (struct group_iterator*) data;
  int i;

  if (!data) return;
  if (iter->group_count > 0) {
    for (i = 0; i < iter->group_count; ++i) {
      userlist_free((struct xml_tree*) iter->groups[i]);
    }
  }
  xfree(iter->groups);
  memset(iter, 0, sizeof(*iter));
  xfree(iter);
}

static struct ptr_iterator group_iterator_funcs =
{
  group_iterator_has_next_func,
  group_iterator_get_func,
  group_iterator_next_func,
  group_iterator_destroy_func,
};

static ptr_iterator_t
get_group_iterator_func(void *data)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  struct group_iterator *iter = 0;
  int i;

  XCALLOC(iter, 1);
  iter->b = group_iterator_funcs;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "SELECT * FROM %s%s WHERE 1 ORDER BY group_id ;",
          state->md->table_prefix, GROUPS_TABLE_NAME);
  fclose(cmd_f); cmd_f = 0;
  if (state->mi->query(state->md, cmd_t, cmd_z, USERGROUP_WIDTH) < 0)
    goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  iter->group_count = state->md->row_count;
  if (iter->group_count <= 0) {
    state->mi->free_res(state->md);
    return (ptr_iterator_t) iter;
  }
  XCALLOC(iter->groups, iter->group_count);
  for (i = 0; i < iter->group_count; ++i) {
    if (!(state->md->row = mysql_fetch_row(state->md->res)))
      db_error_no_data_fail(state->md);
    state->md->lengths = mysql_fetch_lengths(state->md->res);
    iter->groups[i] = (struct userlist_group*) userlist_node_alloc(USERLIST_T_USERGROUP);
    if (parse_group(state, state->md->field_count, state->md->row,
                    state->md->lengths, iter->groups[i]) < 0) goto fail;
  }

  state->mi->free_res(state->md);
  return (ptr_iterator_t) iter;

fail:
  state->mi->free_res(state->md);
  group_iterator_destroy_func((ptr_iterator_t) iter);
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return 0;
}

static const struct userlist_group*
get_group_by_name_func(
        void *data,
        const unsigned char *group_name)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct xml_tree *p;
  struct userlist_group *grp = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  if (!state) return 0;
  if (!group_name) return 0;
  for (p = state->groups.first; p; p = p->right) {
    ASSERT(p->tag == USERLIST_T_USERGROUP);
    grp = (struct userlist_group*) p;
    if (!strcmp(grp->group_name, group_name)) {
      MOVE_TO_FRONT(p, state->groups.first, state->groups.last, left, right);
      return grp;
    }
  }

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "SELECT * FROM %s%s WHERE group_name = ",
          state->md->table_prefix, GROUPS_TABLE_NAME);
  state->mi->write_escaped_string(state->md, cmd_f, 0, group_name);
  fprintf(cmd_f, " ;");
  fclose(cmd_f); cmd_f = 0;
  if (state->mi->query_one_row(state->md, cmd_t, cmd_z, USERGROUP_WIDTH) < 0)
    goto fail;
  xfree(cmd_t); cmd_t = 0;

  grp = (struct userlist_group*) userlist_node_alloc(USERLIST_T_USERGROUP);
  if (parse_group(state, state->md->field_count, state->md->row,
                  state->md->lengths, grp) < 0) goto fail;

  if (state->groups.count >= GROUPS_POOL_SIZE) {
    group_cache_remove(state, (struct userlist_group*) state->groups.last);
  }
  group_cache_add(state, grp);
  state->mi->free_res(state->md);

  return grp;

fail:
  state->mi->free_res(state->md);
  userlist_free((struct xml_tree*) grp);
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return 0;
}

static int
try_new_group_name_func(
        void *data,
        unsigned char *buf,
        size_t bufsize,
        const char *format,
        int serial,
        int step)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  int fmt_len = strlen(format);
  unsigned char *sql_patt = (unsigned char*) malloc(fmt_len + 10);
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  int group_name_count = 0, i;
  unsigned char **group_names = 0;

  convert_to_pattern(sql_patt, format);
  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "SELECT group_name FROM %s%s WHERE group_name LIKE(",
          state->md->table_prefix, GROUPS_TABLE_NAME);
  state->mi->write_escaped_string(state->md, cmd_f, 0, sql_patt);
  fprintf(cmd_f, ") ;");
  close_memstream(cmd_f); cmd_f = 0;
  xfree(sql_patt); sql_patt = 0;
  if (state->mi->query(state->md, cmd_t, cmd_z, 1) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  if (state->md->row_count <= 0) {
    snprintf(buf, bufsize, format, serial);
    state->mi->free_res(state->md);
    return serial;
  }

  group_name_count = state->md->row_count;
  XCALLOC(group_names, group_name_count);
  for (i = 0; i < group_name_count; ++i) {
    if (state->mi->next_row(state->md) < 0) goto fail;
    group_names[i] = xstrdup(state->md->row[0]);
  }
  state->mi->free_res(state->md);

  serial -= step;
  do {
    serial += step;
    snprintf(buf, bufsize, format, serial);
    for (i = 0; i < group_name_count; i++)
      if (!strcmp(buf, group_names[i]))
        break;
  } while (i < group_name_count);

  if (group_names) {
    for (i = 0; i < group_name_count; ++i)
      xfree(group_names[i]);
    xfree(group_names);
    group_names = 0;
  }
  return serial;

fail:
  if (group_names) {
    for (i = 0; i < group_name_count; ++i)
      xfree(group_names[i]);
    xfree(group_names);
  }
  state->mi->free_res(state->md);
  xfree(sql_patt);
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
create_group_func(
        void *data,
        const unsigned char *group_name,
        int created_by)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  int group_id = 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %s%s(group_name, created_by, create_time) VALUES(", state->md->table_prefix, GROUPS_TABLE_NAME);
  state->mi->write_escaped_string(state->md, cmd_f, 0, group_name);
  fprintf(cmd_f, ", %d, NOW()) ;", created_by);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  group_id = mysql_insert_id(state->md->conn);
  if (group_id <= 0) goto fail;
  state->mi->free_res(state->md);
  return group_id;

fail:
  state->mi->free_res(state->md);
  xfree(cmd_t);
  return -1;
}

static int
remove_group_func(
        void *data,
        int group_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  state->mi->simple_fquery(state->md,
                           "DELETE FROM %sgroupmembers WHERE group_id = %d;",
                           state->md->table_prefix, group_id);
  state->mi->free_res(state->md);
  state->mi->simple_fquery(state->md,
                           "DELETE FROM %s%s WHERE group_id = %d;",
                           state->md->table_prefix, GROUPS_TABLE_NAME, group_id);
  state->mi->free_res(state->md);
  group_cache_drop(state);
  return 0;
}

static int
edit_group_field_func(
        void *data,
        int group_id,
        int field,
        const unsigned char *value)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct userlist_group *grp = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  if (group_id <= 0) return -1;
  if (field != USERLIST_GRP_DESCRIPTION && field != USERLIST_GRP_GROUP_NAME)
    return -1;

  if ((grp = group_cache_try_get(state, group_id))) {
    switch (field) {
    case USERLIST_GRP_GROUP_NAME:
      if (!value || !*value) return -1;
      if (!strcmp(grp->group_name, value))
        return 0;
      break;
    case USERLIST_GRP_DESCRIPTION:
      if (!grp->description && !value) return 0;
      if (grp->description && value && !strcmp(grp->description, value))
        return 0;
      break;
    default:
      abort();
    }
  }

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %s%s SET ", state->md->table_prefix, GROUPS_TABLE_NAME);
  switch (field) {
  case USERLIST_GRP_GROUP_NAME:
    fprintf(cmd_f, " group_name = ");
    break;
  case USERLIST_GRP_DESCRIPTION:
    fprintf(cmd_f, " description = ");
    break;
  default:
    abort();
  }
  if (!value) {
    fprintf(cmd_f, " NULL ");
  } else {
    state->mi->write_escaped_string(state->md, cmd_f, 0, value);
  }
  fprintf(cmd_f, ", last_change_time = NOW() WHERE group_id = %d ;", group_id);
  fclose(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  group_cache_remove_by_id(state, group_id);
  return 0;

fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
clear_group_field_func(
        void *data,
        int group_id,
        int field)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct userlist_group *grp = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  if (group_id <= 0) return -1;
  if (field != USERLIST_GRP_DESCRIPTION) return -1;

  if ((grp = group_cache_try_get(state, group_id))) {
    switch (field) {
    case USERLIST_GRP_DESCRIPTION:
      if (!grp->description) return 0;
      break;
    default:
      abort();
    }
  }

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %s%s SET ", state->md->table_prefix, GROUPS_TABLE_NAME);
  switch (field) {
  case USERLIST_GRP_DESCRIPTION:
    fprintf(cmd_f, " description = NULL ");
    break;
  default:
    abort();
  }
  fprintf(cmd_f, ", last_change_time = NOW() WHERE group_id = %d ;", group_id);
  fclose(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  group_cache_remove_by_id(state, group_id);
  return 0;

fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static const struct userlist_group*
get_group_func(
        void *data,
        int group_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct userlist_group *grp = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  if (!state) return 0;
  if (group_id <= 0) return 0;
  if ((grp = group_cache_try_get(state, group_id))) {
    MOVE_TO_FRONT(&grp->b,state->groups.first,state->groups.last,left,right);
    return grp;
  }

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "SELECT * FROM %s%s WHERE group_id = %d ;",
          state->md->table_prefix, GROUPS_TABLE_NAME, group_id);
  fclose(cmd_f); cmd_f = 0;
  if (state->mi->query_one_row(state->md, cmd_t, cmd_z, USERGROUP_WIDTH) < 0)
    goto fail;
  xfree(cmd_t); cmd_t = 0;

  grp = (struct userlist_group*) userlist_node_alloc(USERLIST_T_USERGROUP);
  if (parse_group(state, state->md->field_count, state->md->row,
                  state->md->lengths, grp) < 0) goto fail;

  if (state->groups.count >= GROUPS_POOL_SIZE) {
    group_cache_remove(state, (struct userlist_group*) state->groups.last);
  }
  group_cache_add(state, grp);
  state->mi->free_res(state->md);

  return grp;

fail:
  state->mi->free_res(state->md);
  userlist_free((struct xml_tree*) grp);
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return 0;
}

struct group_user_iterator
{
  struct ptr_iterator b;

  int user_count;
  int cur_user;
  struct userlist_user **users;
};

static int
group_user_iterator_has_next_func(ptr_iterator_t data)
{
  struct group_user_iterator *iter = (struct group_user_iterator*) data;

  if (!iter || iter->cur_user >= iter->user_count) return 0;
  return 1;
}

static const void *
group_user_iterator_get_func(ptr_iterator_t data)
{
  struct group_user_iterator *iter = (struct group_user_iterator*) data;

  if (!iter || iter->cur_user >= iter->user_count) return 0;
  return iter->users[iter->cur_user];
}

static void
group_user_iterator_next_func(ptr_iterator_t data)
{
  struct group_user_iterator *iter = (struct group_user_iterator*) data;

  if (!iter || iter->cur_user >= iter->user_count) return;
  ++iter->cur_user;
}

static void
group_user_iterator_destroy_func(ptr_iterator_t data)
{
  struct group_user_iterator *iter = (struct group_user_iterator*) data;
  int i;

  if (!data) return;
  if (iter->user_count > 0) {
    for (i = 0; i < iter->user_count; ++i) {
      userlist_free((struct xml_tree*) iter->users[i]);
    }
  }
  xfree(iter->users);
  memset(iter, 0, sizeof(*iter));
  xfree(iter);
}

static struct ptr_iterator group_user_iterator_funcs =
{
  group_user_iterator_has_next_func,
  group_user_iterator_get_func,
  group_user_iterator_next_func,
  group_user_iterator_destroy_func,
};

static ptr_iterator_t
get_group_user_iterator_func(void *data, int group_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct group_user_iterator *iter = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  int i;

  XCALLOC(iter, 1);
  iter->b = group_user_iterator_funcs;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f,
          "SELECT %slogins.* FROM %sgroupmembers, %slogins WHERE %slogins.user_id = %sgroupmembers.user_id AND %sgroupmembers.group_id = %d ORDER BY user_id;",
          state->md->table_prefix,
          state->md->table_prefix, state->md->table_prefix,
          state->md->table_prefix, state->md->table_prefix,
          state->md->table_prefix, group_id);
  fclose(cmd_f); cmd_f = 0;
  if (state->mi->query(state->md, cmd_t, cmd_z, LOGIN_WIDTH) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  iter->user_count = state->md->row_count;
  if (iter->user_count <= 0) {
    state->mi->free_res(state->md);
    return (ptr_iterator_t) iter;
  }
  XCALLOC(iter->users, iter->user_count);
  for (i = 0; i < iter->user_count; ++i) {
    if (!(state->md->row = mysql_fetch_row(state->md->res)))
      db_error_no_data_fail(state->md);
    state->md->lengths = mysql_fetch_lengths(state->md->res);
    iter->users[i] = (struct userlist_user*) userlist_node_alloc(USERLIST_T_USER);
    if (parse_login(state, state->md->field_count, state->md->row,
                    state->md->lengths, iter->users[i]) < 0)
      goto fail;
  }
  state->mi->free_res(state->md);

  return (ptr_iterator_t) iter;

fail:
  state->mi->free_res(state->md);
  group_user_iterator_destroy_func((ptr_iterator_t) iter);
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return 0;
}

struct group_member_iterator
{
  struct ptr_iterator b;

  int member_count;
  int cur_member;
  struct userlist_groupmember **members;
};

static int
group_member_iterator_has_next_func(ptr_iterator_t data)
{
  struct group_member_iterator *iter = (struct group_member_iterator*) data;

  if (!iter || iter->cur_member >= iter->member_count) return 0;
  return 1;
}

static const void *
group_member_iterator_get_func(ptr_iterator_t data)
{
  struct group_member_iterator *iter = (struct group_member_iterator*) data;

  if (!iter || iter->cur_member >= iter->member_count) return 0;
  return iter->members[iter->cur_member];
}

static void
group_member_iterator_next_func(ptr_iterator_t data)
{
  struct group_member_iterator *iter = (struct group_member_iterator*) data;

  if (!iter || iter->cur_member >= iter->member_count) return;
  ++iter->cur_member;
}

static void
group_member_iterator_destroy_func(ptr_iterator_t data)
{
  struct group_member_iterator *iter = (struct group_member_iterator*) data;
  int i;

  if (!data) return;
  if (iter->member_count > 0) {
    for (i = 0; i < iter->member_count; ++i) {
      userlist_free((struct xml_tree*) iter->members[i]);
    }
  }
  xfree(iter->members);
  memset(iter, 0, sizeof(*iter));
  xfree(iter);
}

static struct ptr_iterator group_member_iterator_funcs =
{
  group_member_iterator_has_next_func,
  group_member_iterator_get_func,
  group_member_iterator_next_func,
  group_member_iterator_destroy_func,
};

static ptr_iterator_t
get_group_member_iterator_func(void *data, int group_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct group_member_iterator *iter = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  int i;

  if (group_id <= 0) return 0;

  XCALLOC(iter, 1);
  iter->b = group_member_iterator_funcs;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f,
          "SELECT * FROM %sgroupmembers WHERE group_id = %d ORDER BY user_id;",
          state->md->table_prefix, group_id);
  fclose(cmd_f); cmd_f = 0;
  if (state->mi->query(state->md, cmd_t, cmd_z, USERGROUPMEMBER_WIDTH) < 0)
    goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;

  iter->member_count = state->md->row_count;
  if (iter->member_count <= 0) {
    state->mi->free_res(state->md);
    return (ptr_iterator_t) iter;
  }
  XCALLOC(iter->members, iter->member_count);
  for (i = 0; i < iter->member_count; ++i) {
    if (!(state->md->row = mysql_fetch_row(state->md->res)))
      db_error_no_data_fail(state->md);
    state->md->lengths = mysql_fetch_lengths(state->md->res);
    iter->members[i] = (struct userlist_groupmember*) userlist_node_alloc(USERLIST_T_USERGROUPMEMBER);
    if (parse_groupmember(state, state->md->field_count, state->md->row,
                          state->md->lengths, iter->members[i]) < 0) goto fail;
  }
  state->mi->free_res(state->md);

  return (ptr_iterator_t) iter;

fail:
  state->mi->free_res(state->md);
  group_member_iterator_destroy_func((ptr_iterator_t) iter);
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return 0;
}

static int
create_group_member_func(void *data, int group_id, int user_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  if (group_id <= 0 || user_id <= 0) return -1;

  return state->mi->simple_fquery(state->md, "INSERT INTO %sgroupmembers(group_id, user_id) VALUES(%d, %d) ;", state->md->table_prefix, group_id, user_id);
}

static int
remove_group_member_func(void *data, int group_id, int user_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  if (group_id <= 0 || user_id <= 0) return -1;

  state->mi->simple_fquery(state->md, "DELETE FROM %sgroupmembers WHERE group_id = %d AND user_id = %d ;",
                           state->md->table_prefix, group_id, user_id);
  return 0;
}

static int
emit_filter_int(
        struct uldb_mysql_state *state,
        FILE *out_f,
        int filter_op,
        const unsigned char *filter)
{
  if (!filter) return -1;
  int len = strlen(filter);
  while (len > 0 && isspace(filter[len - 1])) --len;
  if (!len) return -1; // empty string
  errno = 0;
  char *eptr = NULL;
  int value = strtol(filter, &eptr, 10);
  if (errno) return -1;
  if (filter + len != (const unsigned char *) eptr) return -1;

  switch (filter_op) {
  case USER_FILTER_OP_EQ: // "eq": 'equal'
    fprintf(out_f, " = ");
    break;
  case USER_FILTER_OP_NE: // "ne": 'not equal'
    fprintf(out_f, " != ");
    break;
  case USER_FILTER_OP_LT: // "lt": 'less'
    fprintf(out_f, " < ");
    break;
  case USER_FILTER_OP_LE: // "le": 'less or equal'
    fprintf(out_f, " <= ");
    break;
  case USER_FILTER_OP_GT: // "gt": 'greater'
    fprintf(out_f, " > ");
    break;
  case USER_FILTER_OP_GE: // "ge": 'greater or equal'
    fprintf(out_f, " >= ");
    break;
  default:
    return -1;
  }
  fprintf(out_f, " %d ", value);
  return 0;
}
static int
emit_filter_string(
        struct uldb_mysql_state *state,
        FILE *out_f,
        int filter_op,
        const unsigned char *filter)
{
  switch (filter_op) {
  case USER_FILTER_OP_EQ: // "eq": 'equal'
    if (!filter) {
      fprintf(out_f, " IS NULL ");
    } else {
      state->mi->write_escaped_string(state->md, out_f, " = ", filter);
    }
    return 0;
  case USER_FILTER_OP_NE: // "ne": 'not equal'
    if (!filter) {
      fprintf(out_f, " IS NOT NULL ");
    } else {
      state->mi->write_escaped_string(state->md, out_f, " != ", filter);
    }
    return 0;
  case USER_FILTER_OP_LT: // "lt": 'less'
    if (!filter) return -1;
    state->mi->write_escaped_string(state->md, out_f, " < ", filter);
    return 0;
  case USER_FILTER_OP_LE: // "le": 'less or equal'
    if (!filter) return -1;
    state->mi->write_escaped_string(state->md, out_f, " <= ", filter);
    return 0;
  case USER_FILTER_OP_GT: // "gt": 'greater'
    if (!filter) return -1;
    state->mi->write_escaped_string(state->md, out_f, " > ", filter);
    return 0;
  case USER_FILTER_OP_GE: // "ge": 'greater or equal'
    if (!filter) return -1;
    state->mi->write_escaped_string(state->md, out_f, " >= ", filter);
    return 0;
  case USER_FILTER_OP_BW: // "bw": 'begins with'
    if (!filter) return -1;
    fprintf(out_f, " LIKE '");
    state->mi->escape_string(state->md, out_f, filter);
    fprintf(out_f, "%%' ");
    return 0;
  case USER_FILTER_OP_BN: // "bn": 'does not begin with'
    if (!filter) return -1;
    fprintf(out_f, " NOT LIKE '");
    state->mi->escape_string(state->md, out_f, filter);
    fprintf(out_f, "%%' ");
    return 0;
  case USER_FILTER_OP_EW: // "ew": 'ends with'
    if (!filter) return -1;
    fprintf(out_f, " LIKE '%%");
    state->mi->escape_string(state->md, out_f, filter);
    fprintf(out_f, "' ");
    return 0;
  case USER_FILTER_OP_EN: // "en": 'does not end with'
    if (!filter) return -1;
    fprintf(out_f, " NOT LIKE '%%");
    state->mi->escape_string(state->md, out_f, filter);
    fprintf(out_f, "' ");
    return 0;
  case USER_FILTER_OP_CN: // "cn": 'contains'
    if (!filter) return -1;
    fprintf(out_f, " LIKE '%%");
    state->mi->escape_string(state->md, out_f, filter);
    fprintf(out_f, "%%' ");
    return 0;
  case USER_FILTER_OP_NC: // "nc": 'does not contain'
    if (!filter) return -1;
    fprintf(out_f, " NOT LIKE '%%");
    state->mi->escape_string(state->md, out_f, filter);
    fprintf(out_f, "%%' ");
    return 0;
  default:
    return -1;
  }
}

static int
emit_filter(
        struct uldb_mysql_state *state,
        FILE *out_f,
        int filter_field,
        int filter_op,
        const unsigned char *filter)
{
  switch (filter_field) {
  case USERLIST_NN_ID:
    fprintf(out_f, " l.user_id ");
    return emit_filter_int(state, out_f, filter_op, filter);
  case USERLIST_NN_LOGIN:
    fprintf(out_f, " l.login ");
    return emit_filter_string(state, out_f, filter_op, filter);
  case USERLIST_NN_EMAIL:
    fprintf(out_f, " l.email ");
    return emit_filter_string(state, out_f, filter_op, filter);
  case USERLIST_NC_NAME:
    fprintf(out_f, " u.username ");
    return emit_filter_string(state, out_f, filter_op, filter);
  default:
    return -1;
  }
}

static unsigned char *
emit_query(
        struct uldb_mysql_state *state,
        int contest_id,
        int group_id,
        const unsigned char *filter,
        int count,
        int page,
        int sort_field,
        int sort_order,
        int filter_field,
        int filter_op,
        int count_mode)
{
  char *q_s = NULL;
  size_t q_z = 0;
  FILE *q_f = open_memstream(&q_s, &q_z);
  fprintf(q_f, "SELECT ");
  if (count_mode > 0) {
    fprintf(q_f, " COUNT(l.user_id) ");
  } else if (contest_id > 0) {
    fprintf(q_f, " l.*, u.*, r.* ");
  } else {
    fprintf(q_f, " l.*, u.* ");
  }
  if (contest_id > 0 && group_id > 0) {
    fprintf(q_f,
            " FROM (%slogins AS l LEFT JOIN %susers AS u ON l.user_id = u.user_id AND u.contest_id = %d)"
            ", %scntsregs AS r"
            ", %sgroupmembers AS m"
            " WHERE l.user_id = r.user_id AND r.contest_id = %d AND l.user_id = m.user_id AND m.group_id = %d",
            state->md->table_prefix, state->md->table_prefix, contest_id,
            state->md->table_prefix,
            state->md->table_prefix,
            contest_id, group_id);
  } else if (contest_id > 0) {
    fprintf(q_f,
            " FROM (%slogins AS l LEFT JOIN %susers AS u ON l.user_id = u.user_id AND u.contest_id = %d)"
            ", %scntsregs AS r"
            " WHERE l.user_id = r.user_id AND r.contest_id = %d ",
            state->md->table_prefix, state->md->table_prefix, contest_id,
            state->md->table_prefix,
            contest_id);
  } else if (group_id > 0) {
    fprintf(q_f,
            " FROM (%slogins AS l LEFT JOIN %susers AS u ON l.user_id = u.user_id AND u.contest_id = 0)"
            ", %sgroupmembers AS m"
            " WHERE l.user_id = m.user_id AND m.group_id = %d",
            state->md->table_prefix, state->md->table_prefix,
            state->md->table_prefix,
            group_id);
  } else {
    fprintf(q_f,
            " FROM (%slogins AS l LEFT JOIN %susers AS u ON l.user_id = u.user_id AND u.contest_id = 0) "
            " WHERE 1 ",
            state->md->table_prefix, state->md->table_prefix);
  }

  char *sq_s = NULL;
  size_t sq_z = 0;
  FILE *sq_f = open_memstream(&sq_s, &sq_z);
  int res = emit_filter(state, sq_f, filter_field, filter_op, filter);
  fclose(sq_f); sq_f = NULL;
  if (res >= 0) {
    fprintf(q_f, " AND ( %s ) ", sq_s);
  }
  xfree(sq_s); sq_s = NULL; sq_z = 0;

  fprintf(q_f, " ORDER BY ");
  switch (sort_field) {
  case USERLIST_NN_LOGIN:
    fprintf(q_f, " l.login ");
    break;
  case USERLIST_NN_EMAIL:
    fprintf(q_f, " l.email ");
    break;
  case USERLIST_NC_NAME:
    fprintf(q_f, " u.username ");
    break;
  case USERLIST_NN_ID:
  default:
    fprintf(q_f, " l.user_id ");
    break;
  }
  if (sort_order == 2) {
    fprintf(q_f, " DESC ");
  }

  if (count_mode <= 0) {
    if (count <= 0) count = 15;
    if (page < 0) page = 0;
    fprintf(q_f, " LIMIT %d, %d;", page * count, count);
  }

  fclose(q_f); q_f = NULL;
  return q_s;
}

static ptr_iterator_t
new_get_brief_list_iterator_2_func(
        void *data,
        int contest_id,
        int group_id,
        const unsigned char *filter,
        int offset,
        int count,
        int page,
        int sort_field,
        int sort_order,
        int filter_field,
        int filter_op)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct brief_list_iterator *iter = 0;
  int i, val;

  unsigned char *query = emit_query(state, contest_id, group_id, filter,
                                    count, page, sort_field, sort_order,
                                    filter_field, filter_op, 0);
  int width = LOGIN_WIDTH + USER_INFO_WIDTH;
  if (contest_id > 0) {
    width += CNTSREG_WIDTH;
  }

  XCALLOC(iter, 1);
  iter->b = brief_list_iterator_funcs;
  iter->state = state;
  iter->contest_id = contest_id;
  iter->cur_ind = 0;

  if (state->mi->query(state->md, query, strlen(query), width) < 0) {
    goto fail;
  }
  xfree(query); query = NULL;

  iter->total_ids = state->md->row_count;
  if (!iter->total_ids) {
    state->mi->free_res(state->md);
    return (ptr_iterator_t) iter;
  }

  if (contest_id > 0) {
    XCALLOC(iter->full_rows, iter->total_ids);
    for (i = 0; i < iter->total_ids; ++i) {
      if (!(state->md->row = mysql_fetch_row(state->md->res)))
        db_error_no_data_fail(state->md);
      state->md->lengths = mysql_fetch_lengths(state->md->res);
      copy_saved_row_2(state, &iter->full_rows[i].login_row, 0, LOGIN_WIDTH);
      copy_saved_row_2(state, &iter->full_rows[i].user_info_row, LOGIN_WIDTH, USER_INFO_WIDTH);
      copy_saved_row_2(state, &iter->full_rows[i].cntsreg_row, LOGIN_WIDTH + USER_INFO_WIDTH, CNTSREG_WIDTH);

      if (!state->md->lengths[0])
        db_error_inv_value_fail(state->md, "value");
      if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
        db_error_inv_value_fail(state->md, "value");
      iter->full_rows[i].user_id = val;
    }
  } else {
    XCALLOC(iter->noreg_rows, iter->total_ids);
    for (i = 0; i < iter->total_ids; ++i) {
      if (!(state->md->row = mysql_fetch_row(state->md->res)))
        db_error_no_data_fail(state->md);
      state->md->lengths = mysql_fetch_lengths(state->md->res);
      copy_saved_row_2(state, &iter->noreg_rows[i].login_row, 0, LOGIN_WIDTH);
      copy_saved_row_2(state, &iter->noreg_rows[i].user_info_row, LOGIN_WIDTH, USER_INFO_WIDTH);

      if (!state->md->lengths[0])
        db_error_inv_value_fail(state->md, "value");
      if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
        db_error_inv_value_fail(state->md, "value");
      iter->noreg_rows[i].user_id = val;
    }
  }

  state->mi->free_res(state->md);
  xfree(query); query = NULL;
  return (ptr_iterator_t) iter;

fail:
  xfree(query);
  state->mi->free_res(state->md);
  brief_list_iterator_destroy_func((ptr_iterator_t) iter);
  return NULL;
}

static ptr_iterator_t
get_brief_list_iterator_2_func(
        void *data,
        int contest_id,
        int group_id,
        const unsigned char *filter,
        int offset,
        int count,
        int page,
        int sort_field,
        int sort_order,
        int filter_field,
        int filter_op)
{
  if (page >= 0) {
    return new_get_brief_list_iterator_2_func(data, contest_id, group_id, filter, offset, count, page, sort_field, sort_order,
                                              filter_field, filter_op);
  }

  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct brief_list_iterator *iter = 0;
  int i, val, j;
  FILE *uid_f = NULL;
  char *uid_t = NULL;
  size_t uid_z = 0;

  if (offset < 0) offset = 0;
  if (count < 0) count = 0;
  if (offset + count < 0) count = 0;

  XCALLOC(iter, 1);
  iter->b = brief_list_iterator_funcs;
  iter->state = state;
  iter->contest_id = contest_id;
  iter->cur_ind = 0;

  if (contest_id <= 0 && group_id > 0) {
    if (state->mi->fquery(state->md, LOGIN_WIDTH,
                  "SELECT l.* FROM %slogins AS l, %sgroupmembers AS m WHERE l.user_id = m.user_id AND m.group_id = %d ORDER BY l.user_id LIMIT %d, %d;",
                          state->md->table_prefix,
                          state->md->table_prefix,
                          group_id, offset, count) < 0)
      goto fail;
    iter->total_ids = state->md->row_count;
    if (!iter->total_ids) {
      state->mi->free_res(state->md);
      return (ptr_iterator_t) iter;
    }

    uid_f = open_memstream(&uid_t, &uid_z);
    XCALLOC(iter->noreg_rows, iter->total_ids);
    for (i = 0; i < iter->total_ids; i++) {
      if (!(state->md->row = mysql_fetch_row(state->md->res)))
        db_error_no_data_fail(state->md);
      state->md->lengths = mysql_fetch_lengths(state->md->res);
      if (!state->md->lengths[0])
        db_error_inv_value_fail(state->md, "value");
      if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
        db_error_inv_value_fail(state->md, "value");
      iter->noreg_rows[i].user_id = val;
      copy_saved_row(state, &iter->noreg_rows[i].login_row);
      if (i > 0) fprintf(uid_f, ", ");
      fprintf(uid_f, "%d", val);
    }
    fclose(uid_f); uid_f = NULL;

    if (!uid_t && !*uid_t) {
      xfree(uid_t); uid_t = 0;
      state->mi->free_res(state->md);
      return (ptr_iterator_t) iter;
    }

    state->mi->free_res(state->md);
    if (state->mi->fquery(state->md, USER_INFO_WIDTH,
                  "SELECT * FROM %susers WHERE contest_id = 0 AND user_id IN (%s) ORDER BY user_id;",
                          state->md->table_prefix, uid_t) < 0)
      goto fail;
    xfree(uid_t); uid_t = 0; uid_z = 0;
    j = 0;
    for (i = 0; i < state->md->row_count; i++) {
      if (!(state->md->row = mysql_fetch_row(state->md->res)))
        db_error_no_data_fail(state->md);
      state->md->lengths = mysql_fetch_lengths(state->md->res);
      if (!state->md->lengths[0])
        db_error_inv_value_fail(state->md, "value");
      if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
        db_error_inv_value_fail(state->md, "value");
      while (j < iter->total_ids && iter->noreg_rows[j].user_id < val) j++;
      if (j < iter->total_ids && iter->noreg_rows[j].user_id == val) {
        copy_saved_row(state, &iter->noreg_rows[j].user_info_row);
      }
    }

    state->mi->free_res(state->md);
    return (ptr_iterator_t) iter;
  }

  if (!contest_id) {
    if (state->mi->fquery(state->md, LOGIN_WIDTH,
                  "SELECT * FROM %slogins WHERE 1 ORDER BY user_id LIMIT %d, %d;",
                          state->md->table_prefix, offset, count) < 0)
      goto fail;
    iter->total_ids = state->md->row_count;
    if (!iter->total_ids) {
      state->mi->free_res(state->md);
      return (ptr_iterator_t) iter;
    }

    uid_f = open_memstream(&uid_t, &uid_z);
    XCALLOC(iter->noreg_rows, iter->total_ids);
    for (i = 0; i < iter->total_ids; i++) {
      if (!(state->md->row = mysql_fetch_row(state->md->res)))
        db_error_no_data_fail(state->md);
      state->md->lengths = mysql_fetch_lengths(state->md->res);
      if (!state->md->lengths[0])
        db_error_inv_value_fail(state->md, "value");
      if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
        db_error_inv_value_fail(state->md, "value");
      iter->noreg_rows[i].user_id = val;
      copy_saved_row(state, &iter->noreg_rows[i].login_row);
      if (i > 0) fprintf(uid_f, ", ");
      fprintf(uid_f, "%d", val);
    }
    fclose(uid_f); uid_f = NULL;

    if (!uid_t && !*uid_t) {
      state->mi->free_res(state->md);
      return (ptr_iterator_t) iter;
    }

    state->mi->free_res(state->md);
    if (state->mi->fquery(state->md, USER_INFO_WIDTH,
                  "SELECT * FROM %susers WHERE contest_id = 0 AND user_id IN (%s) ORDER BY user_id ;",
                          state->md->table_prefix, uid_t) < 0)
      goto fail;
    xfree(uid_t); uid_t = 0; uid_z = 0;
    j = 0;
    for (i = 0; i < state->md->row_count; i++) {
      if (!(state->md->row = mysql_fetch_row(state->md->res)))
        db_error_no_data_fail(state->md);
      state->md->lengths = mysql_fetch_lengths(state->md->res);
      if (!state->md->lengths[0])
        db_error_inv_value_fail(state->md, "value");
      if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
        db_error_inv_value_fail(state->md, "value");
      while (j < iter->total_ids && iter->noreg_rows[j].user_id < val) j++;
      if (j < iter->total_ids && iter->noreg_rows[j].user_id == val) {
        copy_saved_row(state, &iter->noreg_rows[j].user_info_row);
      }
    }

    state->mi->free_res(state->md);
    return (ptr_iterator_t) iter;
  }

  if (state->mi->fquery(state->md, LOGIN_WIDTH,
                        "SELECT %slogins.* FROM %slogins, %scntsregs WHERE %slogins.user_id = %scntsregs.user_id AND %scntsregs.contest_id = %d ORDER BY %slogins.user_id LIMIT %d, %d;",
                        state->md->table_prefix, state->md->table_prefix, state->md->table_prefix,
                        state->md->table_prefix, state->md->table_prefix, state->md->table_prefix,
                        contest_id, state->md->table_prefix, offset, count) < 0)
    goto fail;

  iter->total_ids = state->md->row_count;
  if (!iter->total_ids) {
    state->mi->free_res(state->md);
    return (ptr_iterator_t) iter;
  }

  uid_f = open_memstream(&uid_t, &uid_z);
  XCALLOC(iter->full_rows, iter->total_ids);
  for (i = 0; i < iter->total_ids; i++) {
    if (!(state->md->row = mysql_fetch_row(state->md->res)))
      db_error_no_data_fail(state->md);
    state->md->lengths = mysql_fetch_lengths(state->md->res);
    if (!state->md->lengths[0])
      db_error_inv_value_fail(state->md, "value");
    if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
      db_error_inv_value_fail(state->md, "value");
    iter->full_rows[i].user_id = val;
    copy_saved_row(state, &iter->full_rows[i].login_row);
    if (i > 0) fprintf(uid_f, ", ");
    fprintf(uid_f, "%d", val);
  }
  fclose(uid_f); uid_f = NULL;
  state->mi->free_res(state->md);

  if (!uid_t && !*uid_t) {
    state->mi->free_res(state->md);
    return (ptr_iterator_t) iter;
  }

  if (state->mi->fquery(state->md, USER_INFO_WIDTH,
                "SELECT * FROM %susers WHERE contest_id = %d AND user_id IN (%s) ORDER BY user_id ;",
                        state->md->table_prefix, contest_id, uid_t) < 0)
    goto fail;
  j = 0;
  for (i = 0; i < state->md->row_count; i++) {
    if (!(state->md->row = mysql_fetch_row(state->md->res)))
      db_error_no_data_fail(state->md);
    state->md->lengths = mysql_fetch_lengths(state->md->res);
    if (!state->md->lengths[0])
      db_error_inv_value_fail(state->md, "value");
    if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
      db_error_inv_value_fail(state->md, "value");
    while (j < iter->total_ids && iter->full_rows[j].user_id < val) j++;
    if (j < iter->total_ids && iter->full_rows[j].user_id == val) {
      copy_saved_row(state, &iter->full_rows[j].user_info_row);
    }
  }
  state->mi->free_res(state->md);

  if (state->mi->fquery(state->md, CNTSREG_WIDTH,
                        "SELECT * FROM %scntsregs WHERE contest_id = %d AND user_id IN (%s) ORDER BY user_id ;",
                        state->md->table_prefix, contest_id, uid_t) < 0)
    goto fail;
  xfree(uid_t); uid_t = 0; uid_z = 0;
  j = 0;
  for (i = 0; i < state->md->row_count; i++) {
    if (!(state->md->row = mysql_fetch_row(state->md->res)))
      db_error_no_data_fail(state->md);
    state->md->lengths = mysql_fetch_lengths(state->md->res);
    if (!state->md->lengths[0])
      db_error_inv_value_fail(state->md, "value");
    if (state->mi->parse_int(state->md, state->md->row[0], &val) < 0 || val <= 0)
      db_error_inv_value_fail(state->md, "value");
    while (j < iter->total_ids && iter->full_rows[j].user_id < val) j++;
    if (j < iter->total_ids && iter->full_rows[j].user_id == val) {
      copy_saved_row(state, &iter->full_rows[j].cntsreg_row);
    }
  }
  state->mi->free_res(state->md);

  return (ptr_iterator_t) iter;

 fail:
  if (uid_f) {
    fclose(uid_f);
    uid_f = 0;
  }
  xfree(uid_t); uid_t = 0;
  state->mi->free_res(state->md);
  brief_list_iterator_destroy_func((ptr_iterator_t) iter);
  return 0;
}

static int
new_get_user_count_func(
        void *data,
        int contest_id,
        int group_id,
        const unsigned char *filter,
        int filter_field,
        int filter_op,
        int new_mode,
        long long *p_count)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char *query = emit_query(state, contest_id, group_id, filter,
                                    0, 0, -1, 0,
                                    filter_field, filter_op, 1);
  int query_len = strlen(query);
  int count = 0;
  if (state->mi->query_one_row(state->md, query, query_len, 1) < 0) goto fail;
  if (!state->md->lengths[0])
    db_error_inv_value_fail(state->md, "value");
  if (state->mi->parse_int(state->md, state->md->row[0], &count) < 0 || count <= 0)
    db_error_inv_value_fail(state->md, "value");
  state->mi->free_res(state->md);
  if (p_count) *p_count = count;
  xfree(query); query = NULL;
  return 0;

fail:
  xfree(query);
  state->mi->free_res(state->md);
  return 0;
}

static int
get_user_count_func(
        void *data,
        int contest_id,
        int group_id,
        const unsigned char *filter,
        int filter_field,
        int filter_op,
        int new_mode,
        long long *p_count)
{
  if (new_mode) {
    return new_get_user_count_func(data, contest_id, group_id, filter, filter_field, filter_op, new_mode, p_count);
  }
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char cmdbuf[1024];
  int cmdlen, count = 0;

  if (contest_id > 0 && group_id > 0) {
    // FIXME:
    abort();
  } else if (contest_id > 0) {
    snprintf(cmdbuf, sizeof(cmdbuf), "SELECT COUNT(%slogins.user_id) FROM %slogins, %scntsregs WHERE %slogins.user_id = %scntsregs.user_id AND %scntsregs.contest_id = %d;",
             state->md->table_prefix, state->md->table_prefix,
             state->md->table_prefix, state->md->table_prefix,
             state->md->table_prefix, state->md->table_prefix, contest_id);
  } else if (group_id > 0) {
  } else {
    snprintf(cmdbuf, sizeof(cmdbuf), "SELECT COUNT(user_id) FROM %slogins WHERE 1 ;", state->md->table_prefix);
  }

  cmdlen = strlen(cmdbuf);
  if (state->mi->query_one_row(state->md, cmdbuf, cmdlen, 1) < 0) goto fail;
  if (!state->md->lengths[0])
    db_error_inv_value_fail(state->md, "value");
  if (state->mi->parse_int(state->md, state->md->row[0], &count) < 0 || count <= 0)
    db_error_inv_value_fail(state->md, "value");
  state->mi->free_res(state->md);
  if (p_count) *p_count = count;
  return 0;

fail:
  state->mi->free_res(state->md);
  return 0;
}

static ptr_iterator_t
get_group_iterator_2_func(
        void *data,
        const unsigned char *filter,
        int offset,
        int count)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  struct group_iterator *iter = 0;
  int i;

  if (offset < 0) offset = 0;
  if (count < 0) count = 0;

  XCALLOC(iter, 1);
  iter->b = group_iterator_funcs;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "SELECT * FROM %s%s WHERE 1 ORDER BY group_id LIMIT %d, %d;",
          state->md->table_prefix, GROUPS_TABLE_NAME, offset, count);
  fclose(cmd_f); cmd_f = 0;
  if (state->mi->query(state->md, cmd_t, cmd_z, USERGROUP_WIDTH) < 0)
    goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  iter->group_count = state->md->row_count;
  if (iter->group_count <= 0) {
    state->mi->free_res(state->md);
    return (ptr_iterator_t) iter;
  }
  XCALLOC(iter->groups, iter->group_count);
  for (i = 0; i < iter->group_count; ++i) {
    if (!(state->md->row = mysql_fetch_row(state->md->res)))
      db_error_no_data_fail(state->md);
    state->md->lengths = mysql_fetch_lengths(state->md->res);
    iter->groups[i] = (struct userlist_group*) userlist_node_alloc(USERLIST_T_USERGROUP);
    if (parse_group(state, state->md->field_count, state->md->row,
                    state->md->lengths, iter->groups[i]) < 0) goto fail;
  }

  state->mi->free_res(state->md);
  return (ptr_iterator_t) iter;

fail:
  state->mi->free_res(state->md);
  group_iterator_destroy_func((ptr_iterator_t) iter);
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return 0;
}

static int
get_group_count_func(
        void *data,
        const unsigned char *filter,
        long long *p_count)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char cmdbuf[1024];
  int cmdlen, count = 0;

  snprintf(cmdbuf, sizeof(cmdbuf), "SELECT COUNT(group_id) FROM %s%s WHERE 1 ;", state->md->table_prefix, GROUPS_TABLE_NAME);

  cmdlen = strlen(cmdbuf);
  if (state->mi->query_one_row(state->md, cmdbuf, cmdlen, 1) < 0) goto fail;
  if (!state->md->lengths[0])
    db_error_inv_value_fail(state->md, "value");
  if (state->mi->parse_int(state->md, state->md->row[0], &count) < 0 || count <= 0)
    db_error_inv_value_fail(state->md, "value");
  state->mi->free_res(state->md);
  if (p_count) *p_count = count;
  return 0;

fail:
  state->mi->free_res(state->md);
  return 0;
}

static int
get_prev_user_id_func(
        void *data,
        int contest_id,
        int group_id,
        int user_id,
        const unsigned char *filter,
        int *p_user_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char cmdbuf[1024];
  int cmdlen;

  if (contest_id > 0 && group_id > 0) group_id = 0; // FIXME
  if (group_id > 0) group_id = 0;                   /* FIXME */
  if (p_user_id) *p_user_id = 0;

  if (contest_id > 0 && group_id > 0) {
    abort();
  } else if (contest_id > 0) {
    snprintf(cmdbuf, sizeof(cmdbuf), "SELECT %slogins.user_id FROM %slogins, %scntsregs WHERE %slogins.user_id = %scntsregs.user_id AND %scntsregs.contest_id = %d AND %slogins.user_id < %d ORDER BY %slogins.user_id DESC LIMIT 0, 1;",
             state->md->table_prefix, state->md->table_prefix,
             state->md->table_prefix, state->md->table_prefix,
             state->md->table_prefix, state->md->table_prefix, contest_id,
             state->md->table_prefix, user_id,
             state->md->table_prefix);
  } else if (group_id > 0) {
    abort();
  } else {
    snprintf(cmdbuf, sizeof(cmdbuf), "SELECT user_id FROM %slogins WHERE user_id < %d ORDER BY user_id DESC LIMIT 0, 1;",
             state->md->table_prefix, user_id);
  }
  cmdlen = strlen(cmdbuf);
  if (state->mi->query(state->md, cmdbuf, cmdlen, 1) < 0) goto fail;
  if (state->md->row_count != 1) goto fail;
  if (!(state->md->row = mysql_fetch_row(state->md->res))) goto fail;
  state->md->lengths = mysql_fetch_lengths(state->md->res);
  if (!state->md->lengths[0]) goto fail;
  if (state->mi->parse_int(state->md, state->md->row[0], &user_id) < 0 || user_id <= 0) goto fail;
  if (p_user_id) *p_user_id = user_id;

fail:
  state->mi->free_res(state->md);
  return 0;
}

static int
get_next_user_id_func(
        void *data,
        int contest_id,
        int group_id,
        int user_id,
        const unsigned char *filter,
        int *p_user_id)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  unsigned char cmdbuf[1024];
  int cmdlen;

  if (contest_id > 0 && group_id > 0) group_id = 0; // FIXME
  if (group_id > 0) group_id = 0;                   /* FIXME */
  if (p_user_id) *p_user_id = 0;

  if (contest_id > 0 && group_id > 0) {
    abort();
  } else if (contest_id > 0) {
    snprintf(cmdbuf, sizeof(cmdbuf), "SELECT %slogins.user_id FROM %slogins, %scntsregs WHERE %slogins.user_id = %scntsregs.user_id AND %scntsregs.contest_id = %d AND %slogins.user_id > %d ORDER BY %slogins.user_id LIMIT 0, 1;",
             state->md->table_prefix, state->md->table_prefix,
             state->md->table_prefix, state->md->table_prefix,
             state->md->table_prefix, state->md->table_prefix, contest_id,
             state->md->table_prefix, user_id,
             state->md->table_prefix);
  } else if (group_id > 0) {
    abort();
  } else {
    snprintf(cmdbuf, sizeof(cmdbuf), "SELECT user_id FROM %slogins WHERE user_id > %d ORDER BY user_id DESC LIMIT 0, 1;",
             state->md->table_prefix, user_id);
  }
  cmdlen = strlen(cmdbuf);
  if (state->mi->query(state->md, cmdbuf, cmdlen, 1) < 0) goto fail;
  if (state->md->row_count != 1) goto fail;
  if (!(state->md->row = mysql_fetch_row(state->md->res))) goto fail;
  state->md->lengths = mysql_fetch_lengths(state->md->res);
  if (!state->md->lengths[0]) goto fail;
  if (state->mi->parse_int(state->md, state->md->row[0], &user_id) < 0 || user_id <= 0) goto fail;
  if (p_user_id) *p_user_id = user_id;

fail:
  state->mi->free_res(state->md);
  return 0;
}

static int
get_client_key_func(
        void *data,
        ej_cookie_t client_key,
        const struct userlist_cookie **p_cookie)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct userlist_cookie *c;

  if (state->cache_queries && (c = get_client_key_from_pool(state, client_key))) {
    *p_cookie = c;
    return 0;
  }

  if (fetch_client_key(state, client_key, &c) <= 0) return -1;
  if (p_cookie) *p_cookie = c;
  return 0;
}

static const char zero_token[32] = {};

static int
new_api_key_func(
        void *data,
        struct userlist_api_key *in_api_key,
        const struct userlist_api_key **p_api_key)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  if (in_api_key->create_time <= 0) {
    in_api_key->create_time = time(NULL);
  }

  // disallow zero key
  if (!memcmp(in_api_key->token, zero_token, 32)) {
    return -1;
  }
  if (!memcmp(in_api_key->secret, zero_token, 32)) {
    return -1;
  }

  if (state->cache_queries) {
    int index = api_key_cache_index_find(state, in_api_key->token);
    if (index > 0) return -1;
    if (api_key_cache_secret_find(state, in_api_key->secret) > 0) return -1;
  }

  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  if (!(cmd_f = open_memstream(&cmd_t, &cmd_z))) {
    err("open_memstream failed: %s", os_ErrorMsg());
    goto fail;
  }

  fprintf(cmd_f, "INSERT INTO %sapikeys VALUES (", state->md->table_prefix);
  char token_buf[64];
  int token_len = base64u_encode(in_api_key->token, 32, token_buf);
  token_buf[token_len] = 0;
  fprintf(cmd_f, "'%s'", token_buf);
  token_len = base64u_encode(in_api_key->secret, 32, token_buf);
  token_buf[token_len] = 0;
  fprintf(cmd_f, ",'%s'", token_buf);
  fprintf(cmd_f, ",%d", in_api_key->user_id);
  fprintf(cmd_f, ",%d", in_api_key->contest_id);
  state->mi->write_timestamp(state->md, cmd_f, ",", in_api_key->create_time);
  state->mi->write_timestamp(state->md, cmd_f, ",", in_api_key->expiry_time);
  state->mi->write_escaped_string(state->md, cmd_f, ",", in_api_key->payload);
  state->mi->write_escaped_string(state->md, cmd_f, ",", in_api_key->origin);
  fprintf(cmd_f, ",%d", in_api_key->all_contests);
  fprintf(cmd_f, ",%d", in_api_key->role);
  fprintf(cmd_f, " ) ;");
  close_memstream(cmd_f); cmd_f = 0;

  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;

  xfree(cmd_t); cmd_t = 0; cmd_z = 0;

  return get_api_key_func(data, in_api_key->token, p_api_key);

fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
get_api_key_func(
        void *data,
        const char *token,
        const struct userlist_api_key **p_api_key)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = open_memstream(&cmd_t, &cmd_z);
  char token_buf[64];
  int token_len = base64u_encode(token, 32, token_buf);
  struct userlist_api_key tmp_apk;

  int cache_index = api_key_cache_index_find(state, token);
  if (cache_index > 0) {
    if (cache_index != state->api_keys.first_entry) {
      api_key_cache_unlink(state, cache_index);
      api_key_cache_link(state, cache_index, state->api_keys.first_entry);
    }
    *p_api_key = &state->api_keys.entries[cache_index].api_key;
    return 1;
  }

  memset(&tmp_apk, 0, sizeof(tmp_apk));
  token_buf[token_len] = 0;
  fprintf(cmd_f, "SELECT * FROM %sapikeys WHERE token = '%s' ;", state->md->table_prefix, token_buf);
  fclose(cmd_f); cmd_f = NULL;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = NULL;
  state->md->field_count = mysql_field_count(state->md->conn);
  if (state->md->field_count != APIKEY_WIDTH)
    db_error_field_count_fail(state->md, APIKEY_WIDTH);
  if (!(state->md->res = mysql_store_result(state->md->conn)))
    db_error_fail(state->md);
  state->md->row_count = mysql_num_rows(state->md->res);
  if (state->md->row_count < 0) db_error_fail(state->md);
  if (!state->md->row_count) {
    state->mi->free_res(state->md);
    return 0;
  }
  if (state->md->row_count > 1) goto fail;
  if (!(state->md->row = mysql_fetch_row(state->md->res)))
    db_error_no_data_fail(state->md);
  state->md->lengths = mysql_fetch_lengths(state->md->res);
  if (api_key_parse(state, &tmp_apk) < 0) goto fail;

  if (state->api_keys.token_index_count >= API_KEY_POOL_SIZE - 1) {
    int last_index = state->api_keys.last_entry;
    api_key_cache_index_remove(state, last_index);
    api_key_cache_secret_remove(state, last_index);
    api_key_cache_unlink(state, last_index);
    api_key_cache_free(state, last_index);
  }

  int new_index = api_key_cache_allocate(state);
  struct api_key_cache_entry *e = &state->api_keys.entries[new_index];
  e->api_key = tmp_apk;
  memset(&tmp_apk, 0, sizeof(tmp_apk));
  api_key_cache_link(state, new_index, state->api_keys.first_entry);
  api_key_cache_index_insert(state, new_index);
  api_key_cache_secret_insert(state, new_index);
  *p_api_key = &e->api_key;

  state->mi->free_res(state->md);
  return 1;

fail:
  xfree(cmd_t);
  state->mi->free_res(state->md);
  return -1;
}

static int
get_api_key_secret_func(
        void *data,
        const char *secret,
        const struct userlist_api_key **p_api_key)
{
  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = open_memstream(&cmd_t, &cmd_z);
  char token_buf[64];
  int token_len = base64u_encode(secret, 32, token_buf);
  struct userlist_api_key tmp_apk;

  int cache_index = api_key_cache_secret_find(state, secret);
  if (cache_index > 0) {
    if (cache_index != state->api_keys.first_entry) {
      api_key_cache_unlink(state, cache_index);
      api_key_cache_link(state, cache_index, state->api_keys.first_entry);
    }
    *p_api_key = &state->api_keys.entries[cache_index].api_key;
    return 1;
  }

  memset(&tmp_apk, 0, sizeof(tmp_apk));
  token_buf[token_len] = 0;
  fprintf(cmd_f, "SELECT * FROM %sapikeys WHERE secret = '%s' ;", state->md->table_prefix, token_buf);
  fclose(cmd_f); cmd_f = NULL;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = NULL;
  state->md->field_count = mysql_field_count(state->md->conn);
  if (state->md->field_count != APIKEY_WIDTH)
    db_error_field_count_fail(state->md, APIKEY_WIDTH);
  if (!(state->md->res = mysql_store_result(state->md->conn)))
    db_error_fail(state->md);
  state->md->row_count = mysql_num_rows(state->md->res);
  if (state->md->row_count < 0) db_error_fail(state->md);
  if (!state->md->row_count) {
    state->mi->free_res(state->md);
    return 0;
  }
  if (state->md->row_count > 1) goto fail;
  if (!(state->md->row = mysql_fetch_row(state->md->res)))
    db_error_no_data_fail(state->md);
  state->md->lengths = mysql_fetch_lengths(state->md->res);
  if (api_key_parse(state, &tmp_apk) < 0) goto fail;

  if (state->api_keys.secret_index_count >= API_KEY_POOL_SIZE - 1) {
    int last_index = state->api_keys.last_entry;
    api_key_cache_index_remove(state, last_index);
    api_key_cache_secret_remove(state, last_index);
    api_key_cache_unlink(state, last_index);
    api_key_cache_free(state, last_index);
  }

  int new_index = api_key_cache_allocate(state);
  struct api_key_cache_entry *e = &state->api_keys.entries[new_index];
  e->api_key = tmp_apk;
  memset(&tmp_apk, 0, sizeof(tmp_apk));
  api_key_cache_link(state, new_index, state->api_keys.first_entry);
  api_key_cache_index_insert(state, new_index);
  api_key_cache_secret_insert(state, new_index);
  *p_api_key = &e->api_key;

  state->mi->free_res(state->md);
  return 1;

fail:
  xfree(cmd_t);
  state->mi->free_res(state->md);
  return -1;
}

static int
get_api_keys_count_func(
        void *data,
        int user_id)
{
  ASSERT(user_id > 0);

  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "SELECT COUNT(*) FROM %sapikeys WHERE user_id = %d ;", state->md->table_prefix, user_id);
  fclose(cmd_f); cmd_f = NULL;
  if (state->mi->query_one_row(state->md, cmd_t, cmd_z, 1) < 0) goto fail;
  xfree(cmd_t); cmd_t = NULL;
  int count = 0;
  if (!state->md->lengths[0])
    db_error_inv_value_fail(state->md, "value");
  if (state->mi->parse_int(state->md, state->md->row[0], &count) < 0 || count < 0)
    db_error_inv_value_fail(state->md, "value");
  state->mi->free_res(state->md);
  return count;

fail:
  xfree(cmd_t);
  state->mi->free_res(state->md);
  return -1;
}

static int
get_api_keys_for_user_func(
        void *data,
        int user_id,
        const struct userlist_api_key ***p_api_keys)
{
  ASSERT(user_id > 0);

  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;
  struct userlist_api_key *tmp_apks = NULL;
  const struct userlist_api_key **api_keys = NULL;
  int tmp_apks_size = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "SELECT * FROM %sapikeys WHERE user_id = %d ORDER BY create_time ;", state->md->table_prefix, user_id);
  fclose(cmd_f); cmd_f = NULL;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = NULL;
  state->md->field_count = mysql_field_count(state->md->conn);
  if (state->md->field_count != APIKEY_WIDTH)
    db_error_field_count_fail(state->md, APIKEY_WIDTH);
  if (!(state->md->res = mysql_store_result(state->md->conn)))
    db_error_fail(state->md);
  state->md->row_count = mysql_num_rows(state->md->res);
  if (state->md->row_count < 0) db_error_fail(state->md);
  if (!state->md->row_count) {
    state->mi->free_res(state->md);
    *p_api_keys = NULL;
    return 0;
  }

  tmp_apks_size = state->md->row_count;
  tmp_apks = xcalloc(state->md->row_count, sizeof(tmp_apks[0]));
  for (int i = 0; i < state->md->row_count; ++i) {
    if (!(state->md->row = mysql_fetch_row(state->md->res)))
      db_error_no_data_fail(state->md);
    state->md->lengths = mysql_fetch_lengths(state->md->res);
    if (api_key_parse(state, &tmp_apks[i]) < 0) goto fail;
  }

  int new_count = 0;
  for (int i = 0; i < tmp_apks_size; ++i) {
    new_count += (api_key_cache_index_find(state, tmp_apks[i].token) <= 0);
  }
  if (tmp_apks_size > state->api_keys.size - 1) {
    while (tmp_apks_size > state->api_keys.size - 1) {
      api_key_extend(state);
    }
  }

  api_keys = xcalloc(tmp_apks_size, sizeof(api_keys[0]));
  int api_keys_last = 0;
  // rearrange the existing items
  for (int i = 0; i < tmp_apks_size; ++i) {
    int cache_index = api_key_cache_index_find(state, tmp_apks[i].token);
    if (cache_index <= 0) continue;
    if (cache_index != state->api_keys.first_entry) {
      api_key_cache_unlink(state, cache_index);
      api_key_cache_link(state, cache_index, state->api_keys.first_entry);
    }
    struct api_key_cache_entry *e = &state->api_keys.entries[cache_index];
    ASSERT(e->api_key.user_id == user_id);
    struct userlist_api_key *tmp_e = &tmp_apks[i];
    e->api_key.contest_id = tmp_e->contest_id;
    e->api_key.create_time = tmp_e->create_time;
    e->api_key.expiry_time = tmp_e->expiry_time;
    e->api_key.all_contests = tmp_e->all_contests;
    e->api_key.role = tmp_e->role;
    xfree(e->api_key.payload); e->api_key.payload = tmp_e->payload;
    xfree(e->api_key.origin); e->api_key.origin = tmp_e->origin;
    memset(tmp_e, 0, sizeof(*tmp_e));
    api_keys[api_keys_last++] = &e->api_key;
  }

  // add the new items
  for (int i = 0; i < tmp_apks_size; ++i) {
    struct userlist_api_key *tmp_e = &tmp_apks[i];
    if (tmp_e->user_id <= 0) continue;

    // new item
    if (state->api_keys.token_index_count == state->api_keys.size - 1) {
      int last_index = state->api_keys.last_entry;
      api_key_cache_index_remove(state, last_index);
      api_key_cache_secret_remove(state, last_index);
      api_key_cache_unlink(state, last_index);
      api_key_cache_free(state, last_index);
    }
    int new_index = api_key_cache_allocate(state);
    struct api_key_cache_entry *e = &state->api_keys.entries[new_index];
    e->api_key = *tmp_e;
    memset(tmp_e, 0, sizeof(*tmp_e));
    api_key_cache_link(state, new_index, state->api_keys.first_entry);
    api_key_cache_index_insert(state, new_index);
    api_key_cache_secret_insert(state, new_index);
    api_keys[api_keys_last++] = &e->api_key;
  }

  xfree(tmp_apks); tmp_apks = NULL;
  *p_api_keys = api_keys; api_keys = NULL;
  state->mi->free_res(state->md);
  return tmp_apks_size;

fail:
  for (int i = 0; i < tmp_apks_size; ++i) {
    xfree(tmp_apks[i].payload);
    xfree(tmp_apks[i].origin);
  }
  xfree(tmp_apks);
  xfree(api_keys);
  xfree(cmd_t);
  state->mi->free_res(state->md);
  return -1;
}

static int
remove_api_key_func(
        void *data,
        int user_id,
        const char *token)
{
  ASSERT(user_id > 0);

  struct uldb_mysql_state *state = (struct uldb_mysql_state*) data;

  char token_buf[64];
  int token_len = base64u_encode(token, 32, token_buf);
  token_buf[token_len] = 0;
  state->mi->simple_fquery(state->md, "DELETE FROM %sapikeys WHERE user_id = %d AND token = '%s' ;",
                           state->md->table_prefix, user_id, token_buf);

  int cache_index = api_key_cache_index_find(state, token);
  if (cache_index > 0) {
    api_key_cache_index_remove(state, cache_index);
    api_key_cache_secret_remove(state, cache_index);
    api_key_cache_unlink(state, cache_index);
    api_key_cache_free(state, cache_index);
  }

  return 0;
}
