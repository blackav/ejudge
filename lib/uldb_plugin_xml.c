/* -*- mode: c -*- */

/* Copyright (C) 2006-2022 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/uldb_plugin.h"
#include "ejudge/errlog.h"
#include "ejudge/pathutl.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/userlist.h"
#include "ejudge/random.h"
#include "ejudge/misctext.h"
#include "ejudge/ej_limits.h"
#include "ejudge/compat.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"
#include "ejudge/xml_utils.h"

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <zlib.h>

// default interval to flush changes, in seconds
#define DEFAULT_FLUSH_INTERVAL 600
#define DEFAULT_BACKUP_INTERVAL (24*60*60)

static struct common_plugin_data *init_func(void);
static int finish_func(struct common_plugin_data *);
static int prepare_func(
        struct common_plugin_data *,
        const struct ejudge_cfg *,
        struct xml_tree *);
static int open_func(void *);
static int close_func(void *);
static int check_func(void *);
static int create_func(void *);
static int get_user_full_func(void *, int, const struct userlist_user **);
static int_iterator_t get_user_id_iterator_func(void *);
static int get_user_by_login_func(void *, const unsigned char *);
static void sync_func(void *);
static void forced_sync_func(void *);
static unsigned char *get_login_func(void *, int);
static int new_user_func(void *, const unsigned char *login,
                         const unsigned char *email,
                         int passwd_method,
                         const unsigned char *reg_passwd,
                         int is_privileged,
                         int is_invisible,
                         int is_banned,
                         int is_locked,
                         int show_login,
                         int show_email,
                         int read_only,
                         int never_clean,
                         int simple_registration);
static int remove_user_func(void *, int);
static int get_cookie_func(void *, ej_cookie_t, ej_cookie_t,
                           const struct userlist_cookie **);
static int new_cookie_func(void *, int, const ej_ip_t *,
                           int, ej_cookie_t, time_t,
                           int, int, int, int, int, int,
                           const struct userlist_cookie **);
static int remove_cookie_func(void *data, const struct userlist_cookie *c);
static int remove_user_cookies_func(void *, int);
static int remove_expired_cookies_func(void *, time_t);
static ptr_iterator_t get_user_contest_iterator_func(void *, int);
static int remove_expired_users_func(void *, time_t);
static int get_user_info_1_func(void *, int, const struct userlist_user **);
static int get_user_info_2_func(void *, int, int,
                                const struct userlist_user **,
                                const struct userlist_user_info **);
static int touch_login_time_func(void *, int, int, time_t);
static int get_user_info_3_func(void *, int, int,
                                const struct userlist_user **,
                                const struct userlist_user_info **,
                                const struct userlist_contest **);
static int set_cookie_contest_func(void *, const struct userlist_cookie *, int);
static int set_cookie_locale_func(void *, const struct userlist_cookie *, int);
static int set_cookie_priv_level_func(void *, const struct userlist_cookie *, int);
static int set_cookie_team_login_func(void *, const struct userlist_cookie *, int);
static int get_user_info_4_func(void *, int, int,
                                const struct userlist_user **);
static int get_user_info_5_func(void *, int, int,
                                const struct userlist_user **);
static ptr_iterator_t get_brief_list_iterator_func(void *, int);
static ptr_iterator_t get_standings_list_iterator_func(void *, int);
static int check_user_func(void *, int);
static int set_reg_passwd_func(void *, int, int, const unsigned char *, time_t);
static int set_team_passwd_func(void *, int, int, int, const unsigned char *, time_t, int *);
static int register_contest_func(void *, int, int, int, int, time_t, const struct userlist_contest **);
static int remove_member_func(void *, int, int, int, time_t, int *);
static int is_read_only_func(void *, int, int);
static ptr_iterator_t get_info_list_iterator_func(void *, int, unsigned int);
static int clear_team_passwd_func(void *, int, int, int *);
static int remove_registration_func(void *, int, int);
static int set_reg_status_func(void *, int, int, int);
static int set_reg_flags_func(void *, int, int, int, unsigned int);
static int remove_user_contest_info_func(void *, int, int);
static int clear_user_field_func(void *, int, int, time_t);
static int clear_user_info_field_func(void *, int, int, int, time_t, int *);
static int clear_user_member_field_func(void *, int, int, int, int, time_t, int *);
static int set_user_field_func(void *, int, int, const unsigned char *, time_t);
static int set_user_info_field_func(void *, int, int, int, const unsigned char *, time_t, int *);
static int set_user_member_field_func(void *, int, int, int, int, const unsigned char *, time_t, int *);
static int new_member_func(void *, int, int, int, time_t, int *);
static int maintenance_func(void *, time_t);
static int set_user_xml_func(void *, int, int, struct userlist_user *,
                             time_t, int *);
static int copy_user_info_func(void *, int, int, int, int, time_t,
                               const struct contest_desc *);
static int check_user_reg_data_func(void *, int, int);
static int move_member_func(void *, int, int, int, int, time_t, int *);
static int get_user_info_6_func(void *, int, int,
                                const struct userlist_user **,
                                const struct userlist_user_info **,
                                const struct userlist_contest **,
                                const struct userlist_members **);
static int get_user_info_7_func(void *, int, int,
                                const struct userlist_user **,
                                const struct userlist_user_info **,
                                const struct userlist_members **);
static int get_member_serial_func(void *);
static int set_member_serial_func(void *, int);
static void unlock_user_func(void *data, const struct userlist_user *u) {}
static const struct userlist_contest *get_contest_reg_func(void *, int, int);
static int set_simple_reg_func(void *, int, int, time_t);
static ptr_iterator_t get_group_iterator_func(void *);
static const struct userlist_group*
get_group_by_name_func(
        void *data,
        const unsigned char *group_name);
static int
try_new_group_name_func(
        void *data,
        unsigned char *buf,
        size_t bufsize,
        const char *format,
        int serial,
        int step);
static int
create_group_func(
        void *data,
        const unsigned char *group_name,
        int created_by);
static int
remove_group_func(
        void *data,
        int group_id);
static int
edit_group_field_func(
        void *data,
        int group_id,
        int field,
        const unsigned char *value);
static int
clear_group_field_func(
        void *data,
        int group_id,
        int field);
static const struct userlist_group*
get_group_func(
        void *data,
        int group_id);
static ptr_iterator_t
get_group_user_iterator_func(void *data, int group_id);
static ptr_iterator_t
get_group_member_iterator_func(void *data, int group_id);
static int
create_group_member_func(void *data, int group_id, int user_id);
static int
remove_group_member_func(void *data, int group_id, int user_id);
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
        int filter_op);
static int
get_user_count_func(
        void *data,
        int contest_id,
        int group_id,
        const unsigned char *filter,
        int filter_field,
        int filter_op,
        int new_mode,
        long long *p_count);
static ptr_iterator_t
get_group_iterator_2_func(
        void *data,
        const unsigned char *filter,
        int offset,
        int count);
static int
get_group_count_func(
        void *data,
        const unsigned char *filter,
        long long *p_count);
static int
get_prev_user_id_func(
        void *data,
        int contest_id,
        int group_id,
        int user_id,
        const unsigned char *filter,
        int *p_user_id);
static int
get_next_user_id_func(
        void *data,
        int contest_id,
        int group_id,
        int user_id,
        const unsigned char *filter,
        int *p_user_id);
static int
new_cookie_2_func(
        void *,
        int,
        const ej_ip_t *,
        int,
        ej_cookie_t,
        ej_cookie_t,
        time_t,
        int,
        int,
        int,
        int,
        int,
        int,
        int,
        int,
        const struct userlist_cookie **);
static int
get_client_key_func(
        void *data,
        ej_cookie_t client_key,
        const struct userlist_cookie **p_c);

struct uldb_plugin_iface uldb_plugin_xml =
{
  {
    {
      sizeof (struct uldb_plugin_iface),
      EJUDGE_PLUGIN_IFACE_VERSION,
      "uldb",
      "xml",
    },
    COMMON_PLUGIN_IFACE_VERSION,
    init_func,
    finish_func,
    prepare_func,
  },
  ULDB_PLUGIN_IFACE_VERSION,

  open_func,
  close_func,
  check_func,
  create_func,
  NULL,                         /* insert */
  get_user_full_func,
  get_user_id_iterator_func,
  get_user_by_login_func,
  sync_func,
  forced_sync_func,
  get_login_func,
  new_user_func,
  remove_user_func,
  get_cookie_func,
  new_cookie_func,
  remove_cookie_func,
  remove_user_cookies_func,
  remove_expired_cookies_func,
  get_user_contest_iterator_func,
  remove_expired_users_func,
  get_user_info_1_func,
  get_user_info_2_func,
  touch_login_time_func,
  get_user_info_3_func,
  set_cookie_contest_func,
  set_cookie_locale_func,
  set_cookie_priv_level_func,
  get_user_info_4_func,
  get_user_info_5_func,
  get_brief_list_iterator_func,
  get_standings_list_iterator_func,
  check_user_func,
  set_reg_passwd_func,
  set_team_passwd_func,
  register_contest_func,
  remove_member_func,
  is_read_only_func,
  get_info_list_iterator_func,
  clear_team_passwd_func,
  remove_registration_func,
  set_reg_status_func,
  set_reg_flags_func,
  remove_user_contest_info_func,
  clear_user_field_func,
  clear_user_info_field_func,
  clear_user_member_field_func,
  set_user_field_func,
  set_user_info_field_func,
  set_user_member_field_func,
  new_member_func,
  maintenance_func,
  set_user_xml_func,
  copy_user_info_func,
  check_user_reg_data_func,
  move_member_func,
  set_cookie_team_login_func,
  get_user_info_6_func,
  get_user_info_7_func,
  get_member_serial_func,
  set_member_serial_func,
  unlock_user_func,
  get_contest_reg_func,
  // drop the cache
  0,
  // disable caching
  0,
  // enable caching
  0,
  // pick up a new login
  0,
  // set the simple_registration flag
  set_simple_reg_func,
  get_group_iterator_func,
  get_group_by_name_func,
  try_new_group_name_func,
  create_group_func,
  remove_group_func,
  edit_group_field_func,
  clear_group_field_func,
  get_group_func,
  get_group_user_iterator_func,
  get_group_member_iterator_func,
  create_group_member_func,
  remove_group_member_func,
  get_brief_list_iterator_2_func,
  get_user_count_func,
  get_group_iterator_2_func,
  get_group_count_func,
  get_prev_user_id_func,
  get_next_user_id_func,
  new_cookie_2_func,
  get_client_key_func,
};

struct uldb_xml_state
{
  unsigned char *db_path;

  int dirty;
  time_t last_flush_time;
  int flush_interval;
  time_t last_backup_time;
  int backup_interval;
  struct userlist_list *userlist;
};

struct user_id_iterator
{
  struct int_iterator b;

  struct uldb_xml_state *state;
  int cur_id;
};

struct user_contest_iterator
{
  struct ptr_iterator b;
  struct uldb_xml_state *state;
  struct xml_tree *cur_ptr;
};

struct brief_list_iterator
{
  struct ptr_iterator b;
  struct uldb_xml_state *state;
  int contest_id;
  int user_id;
};

struct standings_list_iterator
{
  struct ptr_iterator b;
  struct uldb_xml_state *state;
  int contest_id;
  int user_id;
};

struct info_list_iterator
{
  struct ptr_iterator b;
  struct uldb_xml_state *state;
  int contest_id;
  unsigned int flag_mask;
  int user_id;
};

struct brief_list_2_iterator
{
  struct ptr_iterator b;
  struct uldb_xml_state *state;
  int contest_id;
  int group_id;
  unsigned char *filter;
  int offset;
  int count;
  int user_id;
};

static struct userlist_user_info *
userlist_clone_user_info(
        struct userlist_user *u,
        int contest_id,
        int *p_serial,
        time_t current_time,
        int *p_cloned_flag);
static struct userlist_member *
userlist_clone_member(
        struct userlist_member *src,
        int *p_serial,
        time_t current_time);

static struct common_plugin_data *
init_func(void)
{
  struct uldb_xml_state *state;

  XCALLOC(state, 1);
  return (struct common_plugin_data*) state;
}

static int
finish_func(struct common_plugin_data *data)
{
  return 0;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *ej_cfg,
        struct xml_tree *t)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;

  if (!ej_cfg->db_path) {
    err("database path is not specified");
    return -1;
  }
  state->db_path = xstrdup(ej_cfg->db_path);

  return 0;
}

static int
open_func(void *data)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  path_t db_dir;
  struct stat stb;

  // check, that the directory is writable
  os_rDirName(state->db_path, db_dir, sizeof(db_dir));
  if (stat(db_dir, &stb) < 0) {
    err("%s does not exist", db_dir);
    return -1;
  }
  if (!S_ISDIR(stb.st_mode)) {
    err("%s is not a directory", db_dir);
    return -1;
  }
  if (access(db_dir, W_OK | R_OK | X_OK) < 0) {
    err("%s is not accessible", db_dir);
    return -1;
  }

  return 0;
}

static int
check_func(void *data)
{
  struct stat stb;

  struct uldb_xml_state *state = (struct uldb_xml_state*) data;

  if (stat(state->db_path, &stb) < 0) {
    err("%s does not exist. Use --convert or --create", state->db_path);
    return 0;
  }

  if (!S_ISREG(stb.st_mode)) {
    err("%s is not a regular file", state->db_path);
    return -1;
  }
  if (access(state->db_path, R_OK | W_OK) < 0) {
    err("%s is not accessible", state->db_path);
    return -1;
  }

  // load the XML
  if (!(state->userlist = userlist_parse(state->db_path)))
    return -1;

  state->flush_interval = DEFAULT_FLUSH_INTERVAL;
  state->last_flush_time = time(0);
  state->dirty = 0;

  if (userlist_build_login_hash(state->userlist) < 0)
    return -1;
  if (userlist_build_cookie_hash(state->userlist) < 0)
    return -1;

  return 1;
}

static int
create_func(void *data)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;

  state->userlist = userlist_new();
  state->flush_interval = 0;
  state->last_flush_time = 0;
  state->dirty = 1;

  return 1;
}

static void
flush_database(struct uldb_xml_state *state)
{
  path_t basedir, tempname;
  FILE *f = 0;
  int fd = -1;

  if (!state->dirty) return;

  os_rDirName(state->db_path, basedir, sizeof(basedir));
  snprintf(tempname, sizeof(tempname), "%s/%u", basedir, random_u32());

  if ((fd = open(tempname, O_CREAT | O_WRONLY | O_TRUNC, 0600)) < 0) {
    err("bdflush: fopen for `%s' failed: %s", tempname, os_ErrorMsg());
    goto failed;
  }
  if (!(f = fdopen(fd, "w"))) {
    err("bdflush: fdopen for `%s' failed: %s", tempname, os_ErrorMsg());
    goto failed;
  }
  fd = -1;

  userlist_unparse(state->userlist, f);
  if (ferror(f)) {
    err("bdflush: write failed: %s", os_ErrorMsg());
    goto failed;
  }
  if (fclose(f) < 0) {
    err("bdflush: fclose() failed: %s", os_ErrorMsg());
    f = NULL;
    goto failed;
  }
  f = 0;

  if (rename(tempname, state->db_path) < 0) {
    err("bdflush: rename() failed: %s", os_ErrorMsg());
    goto failed;
  }

  state->last_flush_time = time(0);
  state->flush_interval = DEFAULT_FLUSH_INTERVAL;
  state->dirty = 0;
  return;

 failed:
  if (f) fclose(f);
  if (fd >= 0) close(fd);
  unlink(tempname);
  state->last_flush_time = time(0);
  state->flush_interval = 10; // retry in 10 secs
}

static int
close_func(void *data)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;

  // ensure success on saving
  while (state->dirty) {
    flush_database(state);
    if (!state->dirty) break;
    sleep(10);
  }

  return 0;
}

static int
get_user_full_func(void *data, int user_id,
                   const struct userlist_user **p_user)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;

  if (user_id <= 0 || user_id >= ul->user_map_size || !ul->user_map[user_id]) {
    if (p_user) *p_user = 0;
    return 0;
  }
  if (p_user) *p_user = ul->user_map[user_id];
  return 1;
}

static int
user_id_iterator_has_next(int_iterator_t data)
{
  struct user_id_iterator *iter = (struct user_id_iterator*) data;
  struct userlist_list *ul = iter->state->userlist;

  while (iter->cur_id < ul->user_map_size && !ul->user_map[iter->cur_id])
    iter->cur_id++;
  return (iter->cur_id < ul->user_map_size);
}
static int
user_id_iterator_get(int_iterator_t data)
{
  struct user_id_iterator *iter = (struct user_id_iterator*) data;
  struct userlist_list *ul = iter->state->userlist;

  while (iter->cur_id < ul->user_map_size && !ul->user_map[iter->cur_id])
    iter->cur_id++;
  ASSERT(iter->cur_id < ul->user_map_size);
  return iter->cur_id;
}
static void
user_id_iterator_next(int_iterator_t data)
{
  struct user_id_iterator *iter = (struct user_id_iterator*) data;
  struct userlist_list *ul = iter->state->userlist;

  iter->cur_id++;
  while (iter->cur_id < ul->user_map_size && !ul->user_map[iter->cur_id])
    iter->cur_id++;
}
static void
user_id_iterator_destroy(int_iterator_t data)
{
  struct user_id_iterator *iter = (struct user_id_iterator*) data;

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
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct user_id_iterator *iter;

  XCALLOC(iter, 1);
  iter->b = user_id_iterator_funcs;
  iter->state = state;
  iter->cur_id = 0;

  return (int_iterator_t) iter;
}

static int
get_user_by_login_func(void *data, const unsigned char *login)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  userlist_login_hash_t m_hash;
  int i;
  struct userlist_user *tmpu;

  if (ul->login_hash_table) {
    m_hash = userlist_login_hash(login);
    i = m_hash % ul->login_hash_size;
    while ((tmpu = ul->login_hash_table[i])
           && (tmpu->login_hash != m_hash || strcmp(tmpu->login, login))) {
      i = (i + ul->login_hash_step) % ul->login_hash_size;
    }
    if (!tmpu) return -1;
    return tmpu->id;
  } else {
    for (i = 1; i < ul->user_map_size; i++) {
      if (!ul->user_map[i]) continue;
      if (!ul->user_map[i]->login) continue;
      if (!strcmp(ul->user_map[i]->login, login))
        return i;
    }
    return -1;
  }
}

static void
sync_func(void *data)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;

  state->flush_interval = 0;
}

static void
forced_sync_func(void *data)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;

  state->dirty = 1;
  state->flush_interval = 0;
}

static unsigned char *
get_login_func(void *data, int user_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;

  if (user_id <= 0 || user_id >= ul->user_map_size) return 0;
  if (!ul->user_map[user_id]) return 0;
  return xstrdup(ul->user_map[user_id]->login);
}

static int
new_user_func(
        void *data,
        const unsigned char *login,
        const unsigned char *email,
        int passwd_method,
        const unsigned char *reg_passwd,
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
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u, **new_map, *tmpu;
  int i;
  size_t new_size;

  if (login && *login) {
    if (get_user_by_login_func(data, login) >= 0) {
      err("login %s already exist", login);
      return -1;
    }
  } else {
    // FIXME: create a new unique login
    abort();
  }

  u = (struct userlist_user*) userlist_node_alloc(USERLIST_T_USER);
  xml_link_node_last(&ul->b, &u->b);

  for (i = 1; i < ul->user_map_size && ul->user_map[i]; i++);
  if (i >= ul->user_map_size) {
    new_size = ul->user_map_size * 2;
    new_map = (struct userlist_user**) xcalloc(new_size, sizeof(new_map[0]));
    memcpy(new_map, ul->user_map, ul->user_map_size * sizeof(new_map[0]));
    xfree(ul->user_map);
    ul->user_map = new_map;
    ul->user_map_size = new_size;
  }
  ul->user_map[i] = u;
  u->id = i;

  u->login = xstrdup(login);
  if (email) u->email = xstrdup(email);
  u->login_hash = userlist_login_hash(login);
  u->is_privileged = is_privileged;
  u->is_invisible = is_invisible;
  u->is_banned = is_banned;
  u->is_locked = is_locked;
  u->show_login = show_login;
  u->show_email = show_email;
  u->read_only = read_only;
  u->never_clean = never_clean;
  u->simple_registration = simple_registration;

  if (reg_passwd) {
    u->passwd = xstrdup(reg_passwd);
    u->passwd_method = passwd_method;
  }

  if (ul->login_hash_table) {
    if (ul->login_cur_fill >= ul->login_thresh) {
      if (userlist_build_login_hash(ul) < 0) {
        // FIXME: release the hash table and try to live without it?
        abort();
      }
    }
    i = u->login_hash % ul->login_hash_size;
    while ((tmpu = ul->login_hash_table[i])) {
      /*
      if (tmpu->login_hash == login_hash && !strcmp(tmpu->login, login)) {
        // FIXME: handle gracefully?
        SWERR(("Adding non-unique login???"));
      }
      */
      i = (i + ul->login_hash_step) % ul->login_hash_size;
    }
    ul->login_hash_table[i] = u;
    ul->login_cur_fill++;
  }

  u->registration_time = time(0);
  state->dirty = 1;
  state->flush_interval /= 2;

  return u->id;
}

static int
remove_user_func(void *data, int user_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct xml_tree *p;
  struct userlist_cookie *c;

  if (user_id <= 0 || user_id >= ul->user_map_size) return -1;
  if (!(u = ul->user_map[user_id])) return -1;
  if (u->cookies) {
    for (p = u->cookies->first_down; p; p = p->right) {
      c = (struct userlist_cookie*) p;
      userlist_cookie_hash_del(ul, c);
    }
  }
  userlist_remove_user(ul, u);
  state->dirty = 1;
  return 0;
}

static int
get_cookie_func(
        void *data,
        ej_cookie_t value,
        ej_cookie_t client_key,
        const struct userlist_cookie **p_cookie)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_cookie *c = 0;
  int i, user_id;
  struct userlist_user *u;
  struct xml_tree *t;

  ASSERT(value);

  if (!ul->cookie_hash_table) {
    for (user_id = 1; user_id < ul->user_map_size; user_id++) {
      if (!(u = ul->user_map[user_id])) continue;
      if (!u->cookies) continue;
      for (t = u->cookies->first_down; t; t = t->right) {
        c = (struct userlist_cookie*) t;
        if (c->cookie == value) break;
      }
      if (t) break;
    }
  } else {
    i = value % ul->cookie_hash_size;
    while ((c = ul->cookie_hash_table[i]) && c->cookie != value) {
      i = (i + ul->cookie_hash_step) % ul->cookie_hash_size;
    }
  }

  if (c && client_key && c->client_key != client_key) {
    c = NULL;
  }

  if (c) {
    if (p_cookie) *p_cookie = c;
    return 0;
  } else {
    if (p_cookie) *p_cookie = 0;
    return -1;
  }
}

static int
new_cookie_func(
        void *data,
        int user_id,
        const ej_ip_t *pip,
        int ssl_flag,
        ej_cookie_t value,
        time_t expire,
        int contest_id,
        int locale_id,
        int priv_level,
        int role,
        int recovery,
        int team_login,
        const struct userlist_cookie **p_cookie)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct userlist_cookie *c;
  struct xml_tree *cs;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id]))
    return -1;

  if (value) {
    // check that the value is unique
    if (get_cookie_func(data, value, 0LL, 0) >= 0) return -1;
  } else {
    // generate a random unique value
    while (1) {
      if (!(value = random_u64())) continue;
      if (get_cookie_func(data, value, 0LL, 0) < 0) break;
    }
  }

  if (!expire) expire = time(0) + 24 * 60 * 60;

  if (!(cs = u->cookies)) {
    u->cookies = cs = userlist_node_alloc(USERLIST_T_COOKIES);
    xml_link_node_last(&u->b, cs);
  }

  c = (struct userlist_cookie*) userlist_node_alloc(USERLIST_T_COOKIE);
  c->user_id = user_id;
  c->ip = *pip;
  c->ssl = ssl_flag;
  c->cookie = value;
  c->expire = expire;
  c->contest_id = contest_id;
  c->locale_id = locale_id;
  c->priv_level = priv_level;
  c->role = role;
  c->recovery = recovery;
  c->team_login = team_login;
  xml_link_node_last(cs, &c->b);
  userlist_cookie_hash_add(ul, c);

  if (p_cookie) *p_cookie = c;

  state->dirty = 1;
  return 0;
}

static int
new_cookie_2_func(
        void *data,
        int user_id,
        const ej_ip_t *pip,
        int ssl_flag,
        ej_cookie_t value,
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
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct userlist_cookie *c;
  struct xml_tree *cs;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id]))
    return -1;

  if (value) {
    // check that the value is unique
    if (get_cookie_func(data, value, 0LL, 0) >= 0) return -1;
  } else {
    // generate a random unique value
    while (1) {
      if (!(value = random_u64())) continue;
      if (get_cookie_func(data, value, 0LL, 0) < 0) break;
    }
  }

  if (!client_key) {
    client_key = random_u64();
    // FIXME: check for uniqueness
  }

  if (!expire) expire = time(0) + 24 * 60 * 60;

  if (!(cs = u->cookies)) {
    u->cookies = cs = userlist_node_alloc(USERLIST_T_COOKIES);
    xml_link_node_last(&u->b, cs);
  }

  c = (struct userlist_cookie*) userlist_node_alloc(USERLIST_T_COOKIE);
  c->user_id = user_id;
  c->ip = *pip;
  c->ssl = ssl_flag;
  c->cookie = value;
  c->client_key = client_key;
  c->expire = expire;
  c->contest_id = contest_id;
  c->locale_id = locale_id;
  c->priv_level = priv_level;
  c->role = role;
  c->recovery = recovery;
  c->team_login = team_login;
  c->is_ws = is_ws;
  c->is_job = is_job;
  xml_link_node_last(cs, &c->b);
  userlist_cookie_hash_add(ul, c);

  if (p_cookie) *p_cookie = c;

  state->dirty = 1;
  return 0;
}

static int
remove_cookie_func(void *data, const struct userlist_cookie *cookie)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct xml_tree *p = (struct xml_tree*) cookie;

  if (cookie->user_id <= 0 || cookie->user_id >= ul->user_map_size
      || !(u = ul->user_map[cookie->user_id])) {
    return -1;
  }

  userlist_cookie_hash_del(ul, cookie);
  xml_unlink_node(p);
  userlist_free(p);
  if (!u->cookies->first_down) {
    xml_unlink_node(u->cookies);
    userlist_free(u->cookies);
    u->cookies = 0;
  }
  return 0;
}

static int
remove_user_cookies_func(void *data, int user_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct xml_tree *p;
  struct userlist_cookie *c;
  int count = 0;

  if (user_id <= 0 || user_id >= ul->user_map_size) return -1;
  if (!(u = ul->user_map[user_id])) return -1;
  if (!u->cookies) return 0;

  for (p = u->cookies->first_down; p; p = p->right) {
    c = (struct userlist_cookie*) p;
    userlist_cookie_hash_del(ul, c);
    count++;
  }

  xml_unlink_node(u->cookies);
  userlist_free(u->cookies);
  u->cookies = 0;
  return count;
}

static int
remove_expired_cookies_func(void *data, time_t cur_time)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct xml_tree *p, *q;
  struct userlist_cookie *c;
  int count = 0, user_id;

  if (cur_time <= 0) cur_time = time(0);

  for (user_id = 1; user_id < ul->user_map_size; user_id++) {
    if (!(u = ul->user_map[user_id])) continue;
    if (!u->cookies) continue;

    for (p = u->cookies->first_down; p; p = q) {
      q = p->right;
      c = (struct userlist_cookie*) p;
      if (c->expire >= cur_time) continue;
      /*
          if (!daemon_mode) {
            info("cookies: removing cookie %d,%s,%s,%llx",
                 user->id, user->login, unparse_ip(rmcookie->ip),
                 rmcookie->cookie);
          }

       */
      remove_cookie_func(data, c);
      count++;
    }
  }
  return count;
}

static int
user_contest_iterator_has_next_func(ptr_iterator_t data)
{
  struct user_contest_iterator *iter = (struct user_contest_iterator *) data;
  return (iter->cur_ptr != NULL);
}
static const void *
user_contest_iterator_get_func(ptr_iterator_t data)
{
  struct user_contest_iterator *iter = (struct user_contest_iterator *) data;
  return (const void *) iter->cur_ptr;
}
static void
user_contest_iterator_next_func(ptr_iterator_t data)
{
  struct user_contest_iterator *iter = (struct user_contest_iterator *) data;
  if (iter->cur_ptr) iter->cur_ptr = iter->cur_ptr->right;
}
static void
user_contest_iterator_destroy_func(ptr_iterator_t data)
{
  xfree(data);
}

static struct ptr_iterator user_contest_iterator_funcs =
{
  user_contest_iterator_has_next_func,
  user_contest_iterator_get_func,
  user_contest_iterator_next_func,
  user_contest_iterator_destroy_func,
};

static ptr_iterator_t
get_user_contest_iterator_func(void *data, int user_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct user_contest_iterator *iter;

  if (user_id <= 0 || user_id >= ul->user_map_size) return 0;
  if (!(u = ul->user_map[user_id])) return 0;

  XCALLOC(iter, 1);
  iter->b = user_contest_iterator_funcs;
  iter->state = state;
  if (u->contests) iter->cur_ptr = u->contests->first_down;
  return (ptr_iterator_t) iter;
}

static int
remove_expired_users_func(void *data, time_t min_reg_time)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  int user_id;

  if (min_reg_time <= 0) min_reg_time = time(0) - 24 * 60 * 60;

  for (user_id = 1; user_id < ul->user_map_size; user_id++) {
    if (!(u = ul->user_map[user_id])) continue;
    if (u->last_login_time <= 0 && u->registration_time < min_reg_time) {
      // FIXME: assume, that such users have no
      // active contest registrations and are not in the system map...
      remove_user_func(data, u->id);
    }
  }

  return 0;
}

static int
get_user_info_1_func(void *data, int user_id,
                     const struct userlist_user **p_user)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;

  if (user_id <= 0 || user_id >= ul->user_map_size || !ul->user_map[user_id]) {
    if (p_user) *p_user = 0;
    return -1;
  }
  if (p_user) *p_user = ul->user_map[user_id];
  return 0;
}

static int
get_user_info_2_func(void *data, int user_id, int contest_id,
                     const struct userlist_user **p_user,
                     const struct userlist_user_info **p_info)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;

  if (user_id <= 0 || user_id >= ul->user_map_size || !ul->user_map[user_id]) {
    if (p_user) *p_user = 0;
    return -1;
  }
  if (p_user) *p_user = ul->user_map[user_id];
  if (p_info) *p_info = userlist_get_user_info(ul->user_map[user_id], contest_id);
  return 0;
}

static int
touch_login_time_func(void *data, int user_id, int contest_id, time_t cur_time)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct userlist_user_info *ui;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);
  u->last_login_time = cur_time;
  if (contest_id > 0) {
    ui = userlist_clone_user_info(u, contest_id, &ul->member_serial, cur_time,
                                  0);
    if (ui) ui->last_login_time = cur_time;
  }
  state->dirty = 1;
  return 0;
}

static int
get_user_info_3_func(void *data, int user_id, int contest_id,
                     const struct userlist_user **p_user,
                     const struct userlist_user_info **p_info,
                     const struct userlist_contest **p_contest)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct xml_tree *t;
  struct userlist_contest *c;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    if (p_user) *p_user = 0;
    if (p_info) *p_info = 0;
    if (p_contest) *p_contest = 0;
    return -1;
  }
  if (p_user) *p_user = u;
  if (p_info) *p_info = userlist_get_user_info(u, contest_id);
  if (p_contest) *p_contest = 0;
  if (u->contests && contest_id > 0) {
    for (t = u->contests->first_down; t; t = t->right) {
      c = (struct userlist_contest*) t;
      if (c->id == contest_id) {
        if (p_contest) *p_contest = c;
        break;
      }
    }
  }
  return 0;
}

static int
set_cookie_contest_func(void *data,
                        const struct userlist_cookie *c,
                        int contest_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_cookie *cc = (struct userlist_cookie*) c;

  if (cc->contest_id != contest_id) {
    cc->contest_id = contest_id;
    state->dirty = 1;
  }
  return 0;
}

static int
set_cookie_locale_func(void *data,
                       const struct userlist_cookie *c,
                       int locale_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_cookie *cc = (struct userlist_cookie*) c;

  if (cc->locale_id != locale_id) {
    cc->locale_id = locale_id;
    state->dirty = 1;
  }
  return 0;
}

static int
set_cookie_priv_level_func(void *data,
                           const struct userlist_cookie *c,
                           int priv_level)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_cookie *cc = (struct userlist_cookie*) c;

  if (cc->priv_level != priv_level) {
    cc->priv_level = priv_level;
    state->dirty = 1;
  }
  return 0;
}

static int
set_cookie_team_login_func(
        void *data,
        const struct userlist_cookie *c,
        int team_login)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_cookie *cc = (struct userlist_cookie*) c;

  if (cc->team_login != team_login) {
    cc->team_login = team_login;
    state->dirty = 1;
  }
  return 0;
}

static int
get_user_info_4_func(void *data, int user_id, int contest_id,
                     const struct userlist_user **p_user)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    if (p_user) *p_user = 0;
    return -1;
  }
  if (p_user) *p_user = u;
  return 0;
}

static int
get_user_info_5_func(void *data, int user_id, int contest_id,
                     const struct userlist_user **p_user)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    if (p_user) *p_user = 0;
    return -1;
  }
  if (p_user) *p_user = u;
  return 0;
}

static void
brief_list_do_skip(struct brief_list_iterator *iter,
                   const struct userlist_list *ul)
{
  const struct userlist_user *u;
  const struct xml_tree *t;
  const struct userlist_contest *c;

  for (;; iter->user_id++) {
    if (iter->user_id >= ul->user_map_size) return;
    if (!(u = ul->user_map[iter->user_id])) continue;
    // no contest specified, any user is ok
    if (iter->contest_id <= 0) return;
    // no registrations at all
    if (!u->contests) continue;
    for (t = u->contests->first_down; t; t = t->right) {
      c = (const struct userlist_contest*) t;
      // found a registration
      if (c->id == iter->contest_id) return;
    }
  }
}

static int
brief_list_iterator_has_next_func(ptr_iterator_t data)
{
  struct brief_list_iterator *iter = (struct brief_list_iterator*) data;
  struct userlist_list *ul = iter->state->userlist;

  brief_list_do_skip(iter, ul);
  return (iter->user_id < ul->user_map_size);
}
static const void *
brief_list_iterator_get_func(ptr_iterator_t data)
{
  struct brief_list_iterator *iter = (struct brief_list_iterator*) data;
  struct userlist_list *ul = iter->state->userlist;

  brief_list_do_skip(iter, ul);
  if (iter->user_id >= ul->user_map_size) return 0;
  return (const void *) ul->user_map[iter->user_id];
}
static void
brief_list_iterator_next_func(ptr_iterator_t data)
{
  struct brief_list_iterator *iter = (struct brief_list_iterator*) data;
  struct userlist_list *ul = iter->state->userlist;

  if (iter->user_id < ul->user_map_size) iter->user_id++;
  brief_list_do_skip(iter, ul);
}
static void
brief_list_iterator_destroy_func(ptr_iterator_t data)
{
  xfree(data);
}

static struct ptr_iterator brief_list_iterator_funcs =
{
  brief_list_iterator_has_next_func,
  brief_list_iterator_get_func,
  brief_list_iterator_next_func,
  brief_list_iterator_destroy_func,
};

static ptr_iterator_t
get_brief_list_iterator_func(void *data, int contest_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct brief_list_iterator *iter;

  XCALLOC(iter, 1);
  iter->b = brief_list_iterator_funcs;
  iter->state = state;
  iter->contest_id = contest_id;
  iter->user_id = 0;
  return (ptr_iterator_t) iter;
}

static void
standings_list_do_skip(struct standings_list_iterator *iter,
                       const struct userlist_list *ul)
{
  const struct userlist_user *u;
  const struct xml_tree *t;
  const struct userlist_contest *c;

  for (;; iter->user_id++) {
    if (iter->user_id >= ul->user_map_size) return;
    if (!(u = ul->user_map[iter->user_id])) continue;
    // no registrations at all
    if (!u->contests) continue;
    for (t = u->contests->first_down; t; t = t->right) {
      c = (const struct userlist_contest*) t;
      // found a registration
      if (c->id == iter->contest_id) break;
    }
    if (!t) continue;
    if (c->status != USERLIST_REG_OK) continue;
    return;
  }
}

static int
standings_list_iterator_has_next_func(ptr_iterator_t data)
{
  struct standings_list_iterator *iter = (struct standings_list_iterator*) data;
  struct userlist_list *ul = iter->state->userlist;

  standings_list_do_skip(iter, ul);
  return (iter->user_id < ul->user_map_size);
}
static const void *
standings_list_iterator_get_func(ptr_iterator_t data)
{
  struct standings_list_iterator *iter = (struct standings_list_iterator*) data;
  struct userlist_list *ul = iter->state->userlist;

  standings_list_do_skip(iter, ul);
  if (iter->user_id >= ul->user_map_size) return 0;
  return (const void *) ul->user_map[iter->user_id];
}
static void
standings_list_iterator_next_func(ptr_iterator_t data)
{
  struct standings_list_iterator *iter = (struct standings_list_iterator*) data;
  struct userlist_list *ul = iter->state->userlist;

  if (iter->user_id < ul->user_map_size) iter->user_id++;
  standings_list_do_skip(iter, ul);
}
static void
standings_list_iterator_destroy_func(ptr_iterator_t data)
{
  xfree(data);
}

static struct ptr_iterator standings_list_iterator_funcs =
{
  standings_list_iterator_has_next_func,
  standings_list_iterator_get_func,
  standings_list_iterator_next_func,
  standings_list_iterator_destroy_func,
};

static ptr_iterator_t
get_standings_list_iterator_func(void *data, int contest_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct standings_list_iterator *iter;

  XCALLOC(iter, 1);
  iter->b = standings_list_iterator_funcs;
  iter->state = state;
  iter->contest_id = contest_id;
  iter->user_id = 0;
  return (ptr_iterator_t) iter;
}

static int
check_user_func(void *data, int user_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;

  if (user_id <= 0 || user_id >= ul->user_map_size || !ul->user_map[user_id])
    return -1;
  return 0;
}

static int
set_reg_passwd_func(void *data, int user_id,
                    int method,
                    const unsigned char *password,
                    time_t cur_time)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }

  xfree(u->passwd);
  u->passwd = xstrdup(password);
  u->passwd_method = method;
  if (cur_time <= 0) cur_time = time(0);
  u->last_pwdchange_time = cur_time;
  state->dirty = 1;
  state->flush_interval /= 2;
  return 0;
}

static int
set_team_passwd_func(void *data, int user_id, int contest_id,
                     int method,
                     const unsigned char *password,
                     time_t cur_time,
                     int *p_cloned_flag)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct userlist_user_info *ui;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  if (contest_id > 0) {
    ui = userlist_clone_user_info(u, contest_id, &ul->member_serial, cur_time,
                                  p_cloned_flag);
  } else {
    ui = userlist_get_cnts0(u);
  }

  xfree(ui->team_passwd);
  ui->team_passwd = xstrdup(password);
  ui->team_passwd_method = method;
  ui->last_pwdchange_time = cur_time;
  state->dirty = 1;
  state->flush_interval /= 2;
  return 0;
}

static int
register_contest_func(void *data,
                      int user_id,
                      int contest_id,
                      int status,
                      int flags,
                      time_t cur_time,
                      const struct userlist_contest **p_c)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct xml_tree *t;
  struct userlist_contest *c;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  if (!u->contests) {
    u->contests = userlist_node_alloc(USERLIST_T_CONTESTS);
    xml_link_node_last(&u->b, u->contests);
  }
  for (t = u->contests->first_down; t; t = t->right) {
    c = (struct userlist_contest*) t;
    if (c->id == contest_id) {
      if (p_c) *p_c = c;
      return 0;
    }
  }

  c = (struct userlist_contest*) userlist_node_alloc(USERLIST_T_CONTEST);
  xml_link_node_last(u->contests, &c->b);
  c->id = contest_id;
  c->status = status;
  c->flags = flags;
  c->create_time = cur_time;

  state->dirty = 1;
  state->flush_interval /= 2;
  if (p_c) *p_c = c;

  return 1;
}

static int
remove_member_func(void *data, int user_id, int contest_id,
                   int serial, time_t cur_time, int *p_cloned_flag)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct userlist_user_info *ui;
  struct userlist_member *m;
  int i, num = -1;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  if (contest_id > 0) {
    ui = userlist_clone_user_info(u, contest_id, &ul->member_serial, cur_time,
                                  p_cloned_flag);
  } else {
    ui = userlist_get_cnts0(u);
  }

  /*
    as a result of cloning a new member may be created.
    its serial is storied in copied_from field.
   */

  // find a member by serial
  if (!ui->members) return -1;
  for (num = 0; num < ui->members->u; num++) {
    if (!(m = ui->members->m[num])) continue;
    if (m->serial == serial || m->copied_from == serial) break;
  }
  if (num >= ui->members->u) return -1;

  /*
  if (role < 0 || role >= USERLIST_MB_LAST) return -1;
  if (!(mm = ui->members[role])) return -1;
  if (num < 0 || num >= mm->total) return -1;
  m = mm->members[num];
  if (m->serial != serial && m->copied_from != serial) return -1;
  */

  xml_unlink_node(&m->b);
  userlist_free(&m->b);
  for (i = num + 1; i < ui->members->u; ++i)
    ui->members->m[i - 1] = ui->members->m[i];
  if (--ui->members->u) {
    xml_unlink_node(&ui->members->b);
    ui->members = 0;
  }
  /*
  for (i = num + 1; i < mm->total; i++)
    mm->members[i - 1] = mm->members[i];
  mm->total--;
  if (!mm->total) {
    xml_unlink_node(&mm->b);
    ui->members[role] = 0;
    userlist_free(&mm->b);
  }
  */

  // clean copied_from
  /*
  for (role = 0; role < USERLIST_MB_LAST; role++) {
    if (!(mm = ui->members[role])) continue;
    for (num = 0; num < mm->total; num++) {
      m = mm->members[num];
      m->copied_from = 0;
    }
  }
  */

  ui->last_change_time = cur_time;
  state->dirty = 1;
  state->flush_interval /= 2;
  return 0;
}

static int
is_read_only_func(void *data, int user_id, int contest_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  const struct userlist_user_info *ui;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (u->read_only) return 1;
  ui = userlist_get_user_info(u, contest_id);
  if (ui && ui->cnts_read_only) return 1;
  return 0;
}

static void
info_list_do_skip(struct info_list_iterator *iter,
                  const struct userlist_list *ul)
{
  const struct userlist_user *u;
  const struct xml_tree *t;
  const struct userlist_contest *c;

  for (;; iter->user_id++) {
    if (iter->user_id >= ul->user_map_size) return;
    if (!(u = ul->user_map[iter->user_id])) continue;
    // no registrations at all
    if (!u->contests) continue;
    for (t = u->contests->first_down; t; t = t->right) {
      c = (const struct userlist_contest*) t;
      // found a registration
      if (c->id == iter->contest_id) break;
    }
    if (!t) continue;
    if (c->flags && !(c->flags & iter->flag_mask)) continue;
    return;
  }
}

static int
info_list_iterator_has_next_func(ptr_iterator_t data)
{
  struct info_list_iterator *iter = (struct info_list_iterator*) data;
  struct userlist_list *ul = iter->state->userlist;

  info_list_do_skip(iter, ul);
  return (iter->user_id < ul->user_map_size);
}
static const void *
info_list_iterator_get_func(ptr_iterator_t data)
{
  struct info_list_iterator *iter = (struct info_list_iterator*) data;
  struct userlist_list *ul = iter->state->userlist;

  info_list_do_skip(iter, ul);
  if (iter->user_id >= ul->user_map_size) return 0;
  return (const void *) ul->user_map[iter->user_id];
}
static void
info_list_iterator_next_func(ptr_iterator_t data)
{
  struct info_list_iterator *iter = (struct info_list_iterator*) data;
  struct userlist_list *ul = iter->state->userlist;

  if (iter->user_id < ul->user_map_size) iter->user_id++;
  info_list_do_skip(iter, ul);
}
static void
info_list_iterator_destroy_func(ptr_iterator_t data)
{
  xfree(data);
}

static struct ptr_iterator info_list_iterator_funcs =
{
  info_list_iterator_has_next_func,
  info_list_iterator_get_func,
  info_list_iterator_next_func,
  info_list_iterator_destroy_func,
};

static ptr_iterator_t
get_info_list_iterator_func(void *data, int contest_id, unsigned int flag_mask)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct info_list_iterator *iter;

  XCALLOC(iter, 1);
  iter->b = info_list_iterator_funcs;
  iter->state = state;
  iter->contest_id = contest_id;
  iter->flag_mask = flag_mask;
  iter->user_id = 0;
  return (ptr_iterator_t) iter;
}

static int
clear_team_passwd_func(void *data, int user_id, int contest_id,
                       int *p_cloned_flag)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct userlist_user_info *ui;
  time_t cur_time = time(0);

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }

  if (contest_id > 0) {
    ui = userlist_clone_user_info(u, contest_id, &ul->member_serial, cur_time,
                                  p_cloned_flag);
  } else {
    ui = userlist_get_cnts0(u);
  }

  xfree(ui->team_passwd); ui->team_passwd = 0;
  ui->team_passwd_method = 0;
  state->dirty = 1;
  state->flush_interval /= 2;
  return 0;
}

static int
remove_registration_func(void *data, int user_id, int contest_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct xml_tree *t;
  struct userlist_contest *c;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }

  if (!u->contests) return -1;
  for (t = u->contests->first_down; t; t = t->right) {
    c = (struct userlist_contest*) t;
    if (c->id == contest_id) break;
  }
  if (!t) return -1;

  xml_unlink_node(t);
  userlist_free(t);

  state->dirty = 1;
  state->flush_interval /= 2;
  return 0;
}

static int
set_reg_status_func(void *data, int user_id, int contest_id, int status)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct userlist_contest *c;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }

  if (!(c=(struct userlist_contest*) userlist_get_user_contest(u, contest_id)))
    return -1;

  if (status == c->status) return 0;
  c->status = status;
  state->dirty = 1;
  state->flush_interval /= 2;
  return 1;
}

static int
set_reg_flags_func(void *data, int user_id, int contest_id, int cmd,
                  unsigned int value)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct userlist_contest *c;
  unsigned int new_value;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }

  if (!(c=(struct userlist_contest*) userlist_get_user_contest(u, contest_id)))
    return -1;

  new_value = c->flags;
  switch (cmd) {
  case 1: new_value |= value; break;
  case 2: new_value &= ~value; break;
  case 3: new_value ^= value; break;
  case 4: new_value = value; break;
  }
  if (new_value == c->flags) return 0;

  c->flags = new_value;
  state->dirty = 1;
  state->flush_interval /= 2;
  return 1;
}

static int
remove_user_contest_info_func(void *data, int user_id, int contest_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct userlist_user_info *uc;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }

  if ((uc = userlist_remove_user_info(u, contest_id))) {
    xml_unlink_node(&uc->b);
    userlist_free(&uc->b);
  }

  state->dirty = 1;
  state->flush_interval /= 2;
  return 1;
}

static int
clear_user_field_func(void *data, int user_id, int field_id, time_t cur_time)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  int r;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  if (userlist_is_empty_user_field(u, field_id)) return 0;

  if ((r = userlist_delete_user_field(u, field_id)) == 1) {
    if (field_id == USERLIST_NN_PASSWD) u->last_pwdchange_time = cur_time;
    else u->last_change_time = cur_time;
    state->dirty = 1;
    state->flush_interval /= 2;
  }
  return r;
}

static int
clear_user_info_field_func(void *data, int user_id, int contest_id,
                           int field_id, time_t cur_time, int *p_cloned_flag)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct userlist_user_info *ui;
  int r;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  ui = userlist_get_user_info_nc(u, contest_id);
  if (!ui) return 0;
  if (userlist_is_empty_user_info_field(ui, field_id)) return 0;

  if (contest_id > 0) {
    if (!(userlist_clone_user_info(u, contest_id, &ul->member_serial,
                                   cur_time, p_cloned_flag)))
      return -1;
    ui = userlist_get_user_info_nc(u, contest_id);
  }

  if ((r = userlist_delete_user_info_field(ui, field_id)) == 1) {
    if (field_id == USERLIST_NC_TEAM_PASSWD) ui->last_pwdchange_time = cur_time;
    else ui->last_change_time = cur_time;
    state->dirty = 1;
    state->flush_interval /= 2;
  }
  return r;
}

static int
clear_user_member_field_func(void *data, int user_id, int contest_id,
                             int serial, int field_id, time_t cur_time,
                             int *p_cloned_flag)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct userlist_user_info *ui;
  struct userlist_member *m;
  int r;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  if (!(ui = userlist_get_user_info_nc(u, contest_id))) return 0;
  if (!(m = userlist_get_member_nc(ui->members, serial, 0, 0))) return 0;
  if (userlist_is_empty_member_field(m, field_id)) return 0;

  if (contest_id > 0) {
    if (!(userlist_clone_user_info(u, contest_id, &ul->member_serial,
                                   cur_time, p_cloned_flag)))
      return -1;
    ui = userlist_get_user_info_nc(u, contest_id);
    m = userlist_get_member_nc(ui->members, serial, 0, 0);
  }

  if ((r = userlist_delete_member_field(m, field_id)) == 1) {
    m->last_change_time = cur_time;
    state->dirty = 1;
    state->flush_interval /= 2;
  }
  return r;
}

static int
set_user_field_func(void *data,
                    int user_id,
                    int field_id,
                    const unsigned char *value,
                    time_t cur_time)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  int r, id2;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  if ((r = userlist_is_equal_user_field(u, field_id, value)) != 0) return r;
  switch (field_id) {
  case USERLIST_NN_ID:
    return -1;
  case USERLIST_NN_LOGIN:
    if ((id2 = get_user_by_login_func(data, value)) > 0 && user_id != id2)
      return -1;
    break;
  case USERLIST_NN_IS_PRIVILEGED:
    if (u->is_privileged) return -1;
    break;
  }

  if ((r = userlist_set_user_field_str(u, field_id, value)) > 0) {
    if (field_id == USERLIST_NN_LOGIN) userlist_build_login_hash(ul);
    if (field_id == USERLIST_NN_PASSWD) u->last_pwdchange_time = cur_time;
    else u->last_change_time = cur_time;
    state->dirty = 1;
    state->flush_interval /= 2;
  }
  return r;
}

static int
set_user_info_field_func(void *data,
                         int user_id,
                         int contest_id,
                         int field_id,
                         const unsigned char *value,
                         time_t cur_time,
                         int *p_cloned_flag)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct userlist_user_info *ui;
  int r;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  if (!contest_id) ui = userlist_get_cnts0(u);
  else ui = userlist_get_user_info_nc(u, contest_id);
  if (ui && userlist_is_equal_user_info_field(ui, field_id, value)) return 0;

  if (contest_id > 0) {
    if (!(userlist_clone_user_info(u, contest_id, &ul->member_serial,
                                   cur_time, p_cloned_flag)))
      return -1;
    ui = userlist_get_user_info_nc(u, contest_id);
  }

  if ((r = userlist_set_user_info_field_str(ui, field_id, value)) == 1) {
    if (field_id == USERLIST_NC_TEAM_PASSWD) ui->last_pwdchange_time = cur_time;
    else ui->last_change_time = cur_time;
    state->dirty = 1;
    state->flush_interval /= 2;
  }
  return r;
}

static int
set_user_member_field_func(void *data,
                           int user_id,
                           int contest_id,
                           int serial,
                           int field_id,
                           const unsigned char *value,
                           time_t cur_time,
                           int *p_cloned_flag)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct userlist_user_info *ui;
  struct userlist_member *m;
  int r;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  if (!contest_id) ui = userlist_get_cnts0(u);
  if (!(ui = userlist_get_user_info_nc(u, contest_id))) return -1;
  if (!(m = userlist_get_member_nc(ui->members, serial, 0, 0))) return -1;
  if (userlist_is_equal_member_field(m, field_id, value)) return 0;

  if (contest_id > 0) {
    if (!(userlist_clone_user_info(u, contest_id, &ul->member_serial,
                                   cur_time, p_cloned_flag)))
      return -1;
    ui = userlist_get_user_info_nc(u, contest_id);
    m = userlist_get_member_nc(ui->members, serial, 0, 0);
  }

  if ((r = userlist_set_member_field_str(m, field_id, value)) == 1) {
    m->last_change_time = cur_time;
    state->dirty = 1;
    state->flush_interval /= 2;
  }
  return r;
}

static int
new_member_func(void *data, int user_id, int contest_id, int role,
                time_t cur_time, int *p_cloned_flag)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct userlist_user_info *ci;
  struct userlist_user_info *ui;
  struct userlist_member *m;
  struct userlist_members *mm;
  struct xml_tree *link_node;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);
  ASSERT(role >= 0 && role < CONTEST_LAST_MEMBER);

  if (contest_id > 0) {
    ci = userlist_clone_user_info(u, contest_id, &ul->member_serial, cur_time,
                                  p_cloned_flag);
    if (!ci) return -1;
    link_node = &ci->b;
  } else {
    ui = userlist_get_cnts0(u);
    link_node = &u->b;
  }
  ui = userlist_get_user_info_nc(u, contest_id);
  ASSERT(ui);

  /*
  if (!ui->members[role]) {
    mm = (struct userlist_members*) userlist_node_alloc(USERLIST_T_CONTESTANTS + role);
    mm->team_role = role;
    xml_link_node_last(link_node, &mm->b);
    ui->members[role] = mm;
  }
  mm = ui->members[role];
  */
  if (!ui->members) {
    mm = (struct userlist_members*) userlist_node_alloc(USERLIST_T_MEMBERS);
    xml_link_node_last(link_node, &mm->b);
    ui->members = mm;
  }
  mm = ui->members;

  m = (struct userlist_member*) userlist_node_alloc(USERLIST_T_MEMBER);
  m->team_role = role;
  m->serial = ul->member_serial++;
  m->create_time = m->last_change_time = cur_time;
  m->grade = -1;
  xml_link_node_last(&mm->b, &m->b);

  if (mm->u >= mm->a) {
    if (!mm->a) mm->a = 2;
    mm->a *= 2;
    XREALLOC(mm->m, mm->a);
  }
  mm->m[mm->u++] = m;

  state->dirty = 1;
  state->flush_interval /= 2;
  return m->serial;
}

static void
do_backup(struct uldb_xml_state *state, time_t cur_time)
{
  struct tm *ptm = 0;
  unsigned char *buf = 0;
  FILE *f = 0;
  int fd = -1;
  char *xml_buf = 0;
  size_t xml_len = 0;
  gzFile gz_dst = 0;
  unsigned char const *failed_function = 0;

  if (!(f = open_memstream(&xml_buf, &xml_len))) {
    failed_function = "open_memstream";
    goto cleanup;
  }
  userlist_unparse(state->userlist, f);
  if (ferror(f)) {
    failed_function = "userlist_unparse";
    goto cleanup;
  }
  close_memstream(f); f = 0;

  buf = alloca(strlen(state->db_path) + 64);
  if (!buf) {
    failed_function = "alloca";
    goto cleanup;
  }
  ptm = localtime(&cur_time);
  sprintf(buf, "%s.%d%02d%02d.gz",
          state->db_path, ptm->tm_year + 1900,
          ptm->tm_mon + 1, ptm->tm_mday);

  /*
  if (!daemon_mode)
    info("backup: starting backup to %s", buf);
  */
  if ((fd = open(buf, O_CREAT | O_TRUNC | O_WRONLY, 0600)) < 0) {
    failed_function = "open";
    goto cleanup;
  }
  if (!(gz_dst = gzdopen(fd, "wb9"))) {
    failed_function = "gzdopen";
    goto cleanup;
  }
  fd = -1;
  if (!gzwrite(gz_dst, xml_buf, xml_len)) {
    failed_function = "gzwrite";
    goto cleanup;
  }
  if (gzclose(gz_dst) != Z_OK) {
    failed_function = "gzclose";
    goto cleanup;
  }

  xfree(xml_buf);
  info("backup: complete to %s", buf);
  state->last_backup_time = cur_time;
  state->backup_interval = DEFAULT_BACKUP_INTERVAL;
  return;

 cleanup:
  if (failed_function) err("backup: %s failed", failed_function);
  if (f) fclose(f);
  if (fd >= 0) close(fd);
  if (gz_dst) gzclose(gz_dst);
  if (buf) unlink(buf);
  if (xml_buf) xfree(xml_buf);
  // delay for 30 sec
  state->backup_interval += 30;
}

static int
maintenance_func(void *data, time_t cur_time)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;

  if (cur_time <= 0) cur_time = time(0);

  if (cur_time > state->last_backup_time + state->backup_interval) {
    do_backup(state, cur_time);
  }

  if (cur_time > state->last_flush_time + state->flush_interval) {
    flush_database(state);
  }
  return 0;
}

static int
count_members(const struct userlist_user_info *ui)
{
  if (!ui) return 0;
  if (!ui->members) return 0;
  return ui->members->u;
}

static int
needs_update(unsigned char const *old, unsigned char const *new)
{
  if (!new) return 0;
  if (!old) return 1;
  if (strcmp(old, new) == 0) return 0;
  return 1;
}
static int
needs_name_update(unsigned char const *old, unsigned char const *new)
{
  if (!new || !*new) return 0;
  if (!old || !*old) return 1;
  if (strcmp(old, new) == 0) return 0;
  return 1;
}

static int
set_user_xml_func(void *data,
                  int user_id,
                  int contest_id,
                  struct userlist_user *new_u,
                  time_t cur_time,
                  int *p_cloned_flag)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct userlist_user_info *ui;
  int nrole, nnum, orole, onum;
  struct userlist_member *nm, *om, *oom;
  struct userlist_member **handled_members;
  int handled_members_count, handled_members_size;
  int new_serial, i;
  struct userlist_user_info *new_ui;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  if (!new_u->login || strcmp(u->login, new_u->login) != 0) return -1;
  if (u->email) {
    if (!new_u->email || strcmp(u->email, new_u->email) != 0) return -1;
  }

  if (contest_id > 0) {
    if (!userlist_clone_user_info(u, contest_id, &ul->member_serial, cur_time,
                                  p_cloned_flag))
      return -1;
  } else {
    userlist_get_cnts0(u);
  }
  if (!(ui = userlist_get_user_info_nc(u, contest_id))) return -1;

  // set fields from new_u->i to ui
  // update the user's fields
  new_ui = new_u->cnts0;
  if (!new_ui) {
    state->dirty = 1;
    state->flush_interval /= 2;
    return 1;
  }

  if (needs_name_update(ui->name, new_ui->name)) {
    xfree(ui->name);
    ui->name = xstrdup(new_ui->name);
  }
  if (needs_update(ui->homepage, new_ui->homepage)) {
    xfree(ui->homepage);
    ui->homepage = xstrdup(new_ui->homepage);
  }
  if (needs_update(ui->phone, new_ui->phone)) {
    xfree(ui->phone);
    ui->phone = xstrdup(new_ui->phone);
  }
  if (needs_update(ui->inst, new_ui->inst)) {
    xfree(ui->inst);
    ui->inst = xstrdup(new_ui->inst);
  }
  if (needs_update(ui->inst_en, new_ui->inst_en)) {
    xfree(ui->inst_en);
    ui->inst_en = xstrdup(new_ui->inst_en);
  }
  if (needs_update(ui->instshort, new_ui->instshort)) {
    xfree(ui->instshort);
    ui->instshort = xstrdup(new_ui->instshort);
  }
  if (needs_update(ui->instshort_en, new_ui->instshort_en)) {
    xfree(ui->instshort_en);
    ui->instshort_en = xstrdup(new_ui->instshort_en);
  }
  if (needs_update(ui->fac, new_ui->fac)) {
    xfree(ui->fac);
    ui->fac = xstrdup(new_ui->fac);
  }
  if (needs_update(ui->fac_en, new_ui->fac_en)) {
    xfree(ui->fac_en);
    ui->fac_en = xstrdup(new_ui->fac_en);
  }
  if (needs_update(ui->facshort, new_ui->facshort)) {
    xfree(ui->facshort);
    ui->facshort = xstrdup(new_ui->facshort);
  }
  if (needs_update(ui->facshort_en, new_ui->facshort_en)) {
    xfree(ui->facshort_en);
    ui->facshort_en = xstrdup(new_ui->facshort_en);
  }
  if (needs_update(ui->city, new_ui->city)) {
    xfree(ui->city);
    ui->city = xstrdup(new_ui->city);
  }
  if (needs_update(ui->city_en, new_ui->city_en)) {
    xfree(ui->city_en);
    ui->city_en = xstrdup(new_ui->city_en);
  }
  if (needs_update(ui->country, new_ui->country)) {
    xfree(ui->country);
    ui->country = xstrdup(new_ui->country);
  }
  if (needs_update(ui->country_en, new_ui->country_en)) {
    xfree(ui->country_en);
    ui->country_en = xstrdup(new_ui->country_en);
  }
  if (needs_update(ui->region, new_ui->region)) {
    xfree(ui->region);
    ui->region = xstrdup(new_ui->region);
  }
  if (needs_update(ui->area, new_ui->area)) {
    xfree(ui->area);
    ui->area = xstrdup(new_ui->area);
  }
  if (needs_update(ui->languages, new_ui->languages)) {
    xfree(ui->languages);
    ui->languages = xstrdup(new_ui->languages);
  }

  /* change members */
  handled_members_size = count_members(ui) + count_members(new_ui) + 8;
  XALLOCAZ(handled_members, handled_members_size);
  handled_members_count = 0;

  // create new members and move the existing ones
  for (nrole = 0; nrole < CONTEST_LAST_MEMBER; nrole++) {
    if (!new_ui->members || new_ui->members->u <= 0) continue;
    for (nnum = 0; nnum < new_ui->members->u; nnum++) {
      if (!(nm = new_ui->members->m[nnum])) continue;
      if (nm->team_role != nrole) continue;
      if (nm->serial <= 0) {
        // create new member
        new_serial = new_member_func(data, user_id, contest_id, nrole,
                                     cur_time, 0);
        if (new_serial <= 0) return -1;
        nm->serial = new_serial;
      }
      om = userlist_get_member_nc(ui->members, nm->serial, &orole, &onum);
      if (!om) {
        err("set_user_xml: %d, %d: member %d not found",
            user_id, contest_id, nm->serial);
        return -1;
      }
      for (i = 0; i < handled_members_count; i++)
        if (handled_members[i] == om)
          break;
      if (i < handled_members_count) {
        err("set_user_xml: %d, %d member %d used more than once",
            user_id, contest_id, om->serial);
        return -1;
      }
      if (orole != nrole) {
        if (move_member_func(data, user_id, contest_id, om->serial,
                             nrole, cur_time, 0) < 0) return -1;
        oom = userlist_get_member_nc(ui->members, nm->serial, &orole, &onum);
        ASSERT(oom == om);
        ASSERT(orole == nrole);
        (void) oom;
      }
      handled_members[handled_members_count++] = om;
    }
  }

  // check the members for removal
  while (1) {
    for (orole = 0; orole < CONTEST_LAST_MEMBER; orole++) {
      if (!(ui->members)) continue;
      for (onum = 0; onum < ui->members->u; onum++) {
        if (!(om = ui->members->m[onum])) continue;
        if (om->team_role != orole) continue;
        ASSERT(om->serial > 0);
        for (i = 0; i < handled_members_count; i++)
          if (handled_members[i] == om)
            break;
        if (i >= handled_members_count) break;
      }
      if (onum < ui->members->u) break;
    }
    if (orole >= CONTEST_LAST_MEMBER) break;
    // remove `om'
    ASSERT(om);
    if (remove_member_func(data, user_id, contest_id, om->serial,
                           cur_time, 0) < 0) {
      err("set_user_xml: %d, %d: remove_member_func failed",
          user_id, contest_id);
      return -1;
    }
  }

  for (nrole = 0, i = 0; nrole < CONTEST_LAST_MEMBER; nrole++) {
    if (!new_ui->members) continue;
    for (nnum = 0; nnum < new_ui->members->u; nnum++) {
      if (!(nm = new_ui->members->m[nnum])) continue;
      if (nm->team_role != nrole) continue;
      ASSERT(nm->serial > 0);
      ASSERT(i < handled_members_count);
      om = handled_members[i++];
      ASSERT(om);
      ASSERT(nm->serial == om->serial || nm->serial == om->copied_from);

      if (nm->status && om->status != nm->status) {
        om->status = nm->status;
      }
      if (nm->grade >= 0 && om->grade != nm->grade) {
        om->grade = nm->grade;
      }
      if (needs_update(om->firstname, nm->firstname)) {
        xfree(om->firstname);
        om->firstname = xstrdup(nm->firstname);
      }
      if (needs_update(om->firstname_en, nm->firstname_en)) {
        xfree(om->firstname_en);
        om->firstname_en = xstrdup(nm->firstname_en);
      }
      if (needs_update(om->middlename, nm->middlename)) {
        xfree(om->middlename);
        om->middlename = xstrdup(nm->middlename);
      }
      if (needs_update(om->middlename_en, nm->middlename_en)) {
        xfree(om->middlename_en);
        om->middlename_en = xstrdup(nm->middlename_en);
      }
      if (needs_update(om->surname, nm->surname)) {
        xfree(om->surname);
        om->surname = xstrdup(nm->surname);
      }
      if (needs_update(om->surname_en, nm->surname_en)) {
        xfree(om->surname_en);
        om->surname_en = xstrdup(nm->surname_en);
      }
      if (needs_update(om->group, nm->group)) {
        xfree(om->group);
        om->group = xstrdup(nm->group);
      }
      if (needs_update(om->group_en, nm->group_en)) {
        xfree(om->group_en);
        om->group_en = xstrdup(nm->group_en);
      }
      if (needs_update(om->email, nm->email)) {
        xfree(om->email);
        om->email = xstrdup(nm->email);
      }
      if (needs_update(om->homepage, nm->homepage)) {
        xfree(om->homepage);
        om->homepage = xstrdup(nm->homepage);
      }
      if (needs_update(om->phone, nm->phone)) {
        xfree(om->phone);
        om->phone = xstrdup(nm->phone);
      }
      if (needs_update(om->inst, nm->inst)) {
        xfree(om->inst);
        om->inst = xstrdup(nm->inst);
      }
      if (needs_update(om->inst_en, nm->inst_en)) {
        xfree(om->inst_en);
        om->inst_en = xstrdup(nm->inst_en);
      }
      if (needs_update(om->instshort, nm->instshort)) {
        xfree(om->instshort);
        om->instshort = xstrdup(nm->instshort);
      }
      if (needs_update(om->instshort_en, nm->instshort_en)) {
        xfree(om->instshort_en);
        om->instshort_en = xstrdup(nm->instshort_en);
      }
      if (needs_update(om->fac, nm->fac)) {
        xfree(om->fac);
        om->fac = xstrdup(nm->fac);
      }
      if (needs_update(om->fac_en, nm->fac_en)) {
        xfree(om->fac_en);
        om->fac_en = xstrdup(nm->fac_en);
      }
      if (needs_update(om->facshort, nm->facshort)) {
        xfree(om->facshort);
        om->facshort = xstrdup(nm->facshort);
      }
      if (needs_update(om->facshort_en, nm->facshort_en)) {
        xfree(om->facshort_en);
        om->facshort_en = xstrdup(nm->facshort_en);
      }
      if (needs_update(om->occupation, nm->occupation)) {
        xfree(om->occupation);
        om->occupation = xstrdup(nm->occupation);
      }
      if (needs_update(om->occupation_en, nm->occupation_en)) {
        xfree(om->occupation_en);
        om->occupation_en = xstrdup(nm->occupation_en);
      }
      if (needs_update(om->discipline, nm->discipline)) {
        xfree(om->discipline);
        om->discipline = xstrdup(nm->discipline);
      }
      if (nm->birth_date && nm->birth_date != om->birth_date)
        om->birth_date = nm->birth_date;
      if (nm->entry_date && nm->entry_date != om->entry_date)
        om->entry_date = nm->entry_date;
      if (nm->graduation_date && nm->graduation_date != om->graduation_date)
        om->graduation_date = nm->graduation_date;
    }
  }

  // FIXME: properly set the change flag?
  state->dirty = 1;
  state->flush_interval /= 2;
  return 1;
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
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  const struct userlist_user_info *ui_from = 0;
  struct userlist_user_info *ui_to;
  int i, j, k, r;
  unsigned char **p_str_from, **p_str_to;
  struct userlist_members *mm = 0;
  struct userlist_member *m = 0, *om = 0;
  struct userlist_user_info *ci;
  int role_max[USERLIST_MB_LAST];
  int role_cur[USERLIST_MB_LAST];
  int members_total;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);
  if (from_cnts == to_cnts) return 0;

  // the source information
  if (!(ui_from = userlist_get_user_info(u, from_cnts)))
    return -1;

  // the destination
  if (!to_cnts) userlist_get_cnts0(u);
  if (!(ci = userlist_clone_user_info(u, to_cnts, &ul->member_serial,
                                      cur_time, 0)))
    return -1;
  if (!(ui_to = userlist_get_user_info_nc(u, to_cnts))) return -1;

  xfree(ui_to->name);
  ui_to->name = xstrdup(ui_from->name);
  if (copy_passwd_flag && ui_from->team_passwd) {
    xfree(ui_to->team_passwd);
    ui_to->team_passwd = xstrdup(ui_from->team_passwd);
    ui_to->team_passwd_method = ui_from->team_passwd_method;
  }
  ui_to->instnum = ui_from->instnum;

  for (i = 0; copy_user_general_fields[i] > 0; i++) {
    j = copy_user_general_fields[i];
    k = userlist_map_userlist_to_contest_field(j);
    p_str_to = (unsigned char**) userlist_get_user_info_field_ptr(ui_to, j);
    xfree(*p_str_to); *p_str_to = 0;
    if (cnts && !cnts->fields[k]) continue;
    p_str_from = (unsigned char**) userlist_get_user_info_field_ptr(ui_from,j);
    if (!*p_str_from) continue;
    *p_str_to = xstrdup(*p_str_from);
  }

  if (cnts && cnts->enable_avatar > 0) {
    xstrdup3(&ui_to->avatar_store, ui_from->avatar_store);
    xstrdup3(&ui_to->avatar_id, ui_from->avatar_id);
    xstrdup3(&ui_to->avatar_suffix, ui_from->avatar_suffix);
  }

  /* clear `printer_name' and `location' */
  xfree(ui_to->printer_name); ui_to->printer_name = 0;
  xfree(ui_to->exam_id); ui_to->exam_id = 0;
  xfree(ui_to->exam_cypher); ui_to->exam_cypher = 0;
  xfree(ui_to->location); ui_to->location = 0;
  /* copy spelling field */
  xfree(ui_to->spelling); ui_to->spelling = 0;
  if (ui_from->spelling) ui_to->spelling = xstrdup(ui_from->spelling);

  /*
    free the existing member info
   */
  if (ui_to->members) {
    for (i = 0; i < ui_to->members->u; i++) {
      if (!(m = ui_to->members->m[i])) continue;
      xml_unlink_node(&m->b);
      userlist_free(&m->b);
      ui_to->members->m[i] = 0;
    }
    xml_unlink_node(&ui_to->members->b);
    userlist_free(&ui_to->members->b);
    ui_to->members = 0;
  }

  /*
    copy the member info
   */
  memset(role_max, 0, sizeof(role_max));
  memset(role_cur, 0, sizeof(role_cur));
  if (ui_from->members) {
    for (i = 0; i < ui_from->members->u; i++) {
      if (!(m = ui_from->members->m[i])) continue;
      ASSERT(m->team_role >= 0 && m->team_role < USERLIST_MB_LAST);
      role_max[m->team_role]++;
    }
  }
  if (cnts) {
    for (i = 0; i < USERLIST_MB_LAST; i++) {
      if (!cnts->members[i]) {
        role_max[i] = 0;
      } else if (cnts->members[i]->max_count < role_max[i]) {
        role_max[i] = cnts->members[i]->max_count;
      }
    }
  }
  for (i = 0, members_total = 0; i < USERLIST_MB_LAST; i++)
    members_total += role_max[i];

  if (members_total > 0) {
    mm = (struct userlist_members*)userlist_node_alloc(USERLIST_T_MEMBERS);
    xml_link_node_last(&ci->b, &mm->b);
    ui_to->members = mm;
    j = 4;
    while (j < members_total) j *= 2;
    mm->a = j;
    XCALLOC(mm->m, j);
  }

  if (ui_from->members) {
    for (i = 0; i < ui_from->members->u; i++) {
      if (!(om = ui_from->members->m[i])) continue;
      r = om->team_role;
      if (r < 0 || r >= USERLIST_MB_LAST || role_cur[r] >= role_max[r])
        continue;

      mm->m[mm->u] = userlist_clone_member(ui_from->members->m[i], &ul->member_serial, cur_time);
      xml_link_node_last(&mm->b, &mm->m[mm->u]->b);
      mm->u++;
    }
  }

  ui_to->last_change_time = cur_time;
  state->dirty = 1;
  state->flush_interval /= 2;
  return 0;
}

static int
check_user_reg_data_func(void *data, int user_id, int contest_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  const struct userlist_user *u = 0;
  const struct userlist_user_info *ui = 0;
  const struct userlist_contest *c = 0;
  struct userlist_contest *cm = 0;
  const struct contest_desc *cnts = 0;
  int memb_errs[CONTEST_LAST_MEMBER + 1];
  int nerr;
  const struct userlist_members *mm = 0;

  if (contests_get(contest_id, &cnts) < 0 || !cnts)
    return -1;

  if (get_user_info_3_func(data, user_id, contest_id, &u, &ui, &c) < 0)
    return -1;
  if (ui) mm = ui->members;

  if (!c || (c->status != USERLIST_REG_OK && c->status != USERLIST_REG_PENDING))
    return -1;

  nerr = userlist_count_info_errors(cnts, u, ui, mm, memb_errs);
  if (ui && ui->name && *ui->name && check_str(ui->name, name_accept_chars))
    nerr++;

  if ((c->flags & USERLIST_UC_PRIVILEGED)) {
    if ((c->flags & USERLIST_UC_INCOMPLETE)) {
      cm = (struct userlist_contest*) c;
      cm->flags &= ~USERLIST_UC_INCOMPLETE;
      state->dirty = 1;
      state->flush_interval /= 2;
      return 1;
    }
  } else {
    if (!nerr && (c->flags & USERLIST_UC_INCOMPLETE)) {
      cm = (struct userlist_contest*) c;
      cm->flags &= ~USERLIST_UC_INCOMPLETE;
      state->dirty = 1;
      state->flush_interval /= 2;
      return 1;
    } else if (nerr > 0 && !(c->flags & USERLIST_UC_INCOMPLETE)
               && (!ui || !ui->cnts_read_only)) {
      cm = (struct userlist_contest*) c;
      cm->flags |= USERLIST_UC_INCOMPLETE;
      state->dirty = 1;
      state->flush_interval /= 2;
      return 1;
    }
  }
  return 0;
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
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct userlist_user_info *ui;
  struct userlist_members *mm;
  struct userlist_member *m;
  int role = 0, num = -1;
  struct xml_tree *link_node = 0;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  if (contest_id > 0) {
    ui = userlist_clone_user_info(u, contest_id, &ul->member_serial, cur_time,
                                  p_cloned_flag);
    link_node = &ui->b;
  } else {
    ui = userlist_get_cnts0(u);
    link_node = &ui->b;
  }

  (void) link_node;
  /*
    as a result of cloning a new member may be created.
    its serial is storied in copied_from field.
   */

  // find a member by serial
  if (!(mm = ui->members)) return -1;
  for (num = 0; num < mm->u; num++) {
    if (!(m = mm->m[num])) continue;
    role = m->team_role;
    if (m->serial == serial || m->copied_from == serial) break;
  }
  if (num >= mm->u) return -1;

  if (role == new_role) return 0;
  if (new_role < 0 || new_role >= CONTEST_LAST_MEMBER) return -1;
  m->team_role = new_role;

  ui->last_change_time = cur_time;
  state->dirty = 1;
  state->flush_interval /= 2;
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
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct xml_tree *t;
  struct userlist_contest *c;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    if (p_user) *p_user = 0;
    if (p_info) *p_info = 0;
    if (p_contest) *p_contest = 0;
    if (p_members) *p_members = 0;
    return -1;
  }
  if (p_user) *p_user = u;
  if (p_info) *p_info = userlist_get_user_info(u, contest_id);
  if (p_members) {
    *p_members = 0;
    if (*p_info) *p_members = (*p_info)->members;
  }
  if (p_contest) *p_contest = 0;
  if (u->contests && contest_id > 0) {
    for (t = u->contests->first_down; t; t = t->right) {
      c = (struct userlist_contest*) t;
      if (c->id == contest_id) {
        if (p_contest) *p_contest = c;
        break;
      }
    }
  }
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
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;

  if (user_id <= 0 || user_id >= ul->user_map_size || !ul->user_map[user_id]) {
    if (p_user) *p_user = 0;
    if (p_info) *p_info = 0;
    if (p_members) *p_members = 0;
    return -1;
  }
  if (p_user) *p_user = ul->user_map[user_id];
  if (p_info) *p_info = userlist_get_user_info(ul->user_map[user_id], contest_id);
  if (p_members) {
    *p_members = 0;
    if (*p_info) *p_members = (*p_info)->members;
  }
  return 0;
}

/*
 * if the source string is NULL, also NULL is returned, as opposed
 * to the `xstrdup', which returns "" in case of NULL.
 */
static unsigned char *
copy_field(const unsigned char *s)
{
  if (!s) return 0;
  return xstrdup(s);
}

static struct userlist_member *
userlist_clone_member(
        struct userlist_member *src,
        int *p_serial,
        time_t current_time)
{
  struct userlist_member *dst;

  if (!src) return 0;
  ASSERT(src->b.tag == USERLIST_T_MEMBER);

  dst = (struct userlist_member*) userlist_node_alloc(USERLIST_T_MEMBER);

  dst->serial = (*p_serial)++;
  dst->team_role = src->team_role;
  dst->copied_from = src->serial;
  dst->status = src->status;
  dst->gender = src->gender;
  dst->grade = src->grade;

  dst->firstname = copy_field(src->firstname);
  dst->firstname_en = copy_field(src->firstname_en);
  dst->middlename = copy_field(src->middlename);
  dst->middlename_en = copy_field(src->middlename_en);
  dst->surname = copy_field(src->surname);
  dst->surname_en = copy_field(src->surname_en);
  dst->group = copy_field(src->group);
  dst->group_en = copy_field(src->group_en);
  dst->email = copy_field(src->email);
  dst->homepage = copy_field(src->homepage);
  dst->phone = copy_field(src->phone);
  dst->occupation = copy_field(src->occupation);
  dst->occupation_en = copy_field(src->occupation_en);
  dst->discipline = copy_field(src->discipline);
  dst->inst = copy_field(src->inst);
  dst->inst_en = copy_field(src->inst_en);
  dst->instshort = copy_field(src->instshort);
  dst->instshort_en = copy_field(src->instshort_en);
  dst->fac = copy_field(src->fac);
  dst->fac_en = copy_field(src->fac_en);
  dst->facshort = copy_field(src->facshort);
  dst->facshort_en = copy_field(src->facshort_en);

  dst->birth_date = src->birth_date;
  dst->entry_date = src->entry_date;
  dst->graduation_date = src->graduation_date;

  dst->create_time = current_time;
  dst->last_change_time = current_time;
  dst->last_access_time = 0;
  src->last_access_time = current_time;

  return dst;
}

static struct userlist_user_info *
userlist_clone_user_info(
        struct userlist_user *u,
        int contest_id,
        int *p_serial,
        time_t current_time,
        int *p_cloned_flag)
{
  struct xml_tree *p;
  struct userlist_user_info *ci;
  struct userlist_members *mm = 0;
  int i, j, r;
  const struct contest_desc *cnts = 0;
  int role_max[USERLIST_MB_LAST];
  int role_cur[USERLIST_MB_LAST];
  int members_total = 0;
  struct userlist_member *om;
  struct userlist_user_info *ui = 0;

  if (p_cloned_flag) *p_cloned_flag = 0;
  if (contest_id <= 0 || contest_id > EJ_MAX_CONTEST_ID) return 0;
  if (!u) return 0;

  if ((ui = userlist_get_user_info_nc(u, contest_id)))
    return ui;

  // ok, needs clone
  // 1. find <cntsinfos> element in the list of childs
  for (p = u->b.first_down; p && p->tag != USERLIST_T_CNTSINFOS; p = p->right);
  if (!p) {
    // <cntsinfos> not found, create a new one
    p = userlist_node_alloc(USERLIST_T_CNTSINFOS);
    xml_link_node_last(&u->b, p);
  }

  ci = (struct userlist_user_info*) userlist_node_alloc(USERLIST_T_CNTSINFO);
  xml_link_node_last(p, &ci->b);
  ci->contest_id = contest_id;
  ci->instnum = -1;
  if (!(ui = u->cnts0)) {
    userlist_insert_user_info(u, contest_id, ci);
    if (p_cloned_flag) *p_cloned_flag = 1;
    return ci;
  }

  // NOTE: should we reset the cnts_read_only flag?
  ci->cnts_read_only = ui->cnts_read_only;
  ci->instnum = ui->instnum;

  ci->name = copy_field(ui->name);
  ci->inst = copy_field(ui->inst);
  ci->inst_en = copy_field(ui->inst_en);
  ci->instshort = copy_field(ui->instshort);
  ci->instshort_en = copy_field(ui->instshort_en);
  ci->fac = copy_field(ui->fac);
  ci->fac_en = copy_field(ui->fac_en);
  ci->facshort = copy_field(ui->facshort);
  ci->facshort_en = copy_field(ui->facshort_en);
  ci->homepage = copy_field(ui->homepage);
  ci->city = copy_field(ui->city);
  ci->city_en = copy_field(ui->city_en);
  ci->country = copy_field(ui->country);
  ci->country_en = copy_field(ui->country_en);
  ci->region = copy_field(ui->region);
  ci->area = copy_field(ui->area);
  ci->location = copy_field(ui->location);
  ci->spelling = copy_field(ui->spelling);
  ci->printer_name = copy_field(ui->printer_name);
  ci->exam_id = copy_field(ui->exam_id);
  ci->exam_cypher = copy_field(ui->exam_cypher);
  ci->languages = copy_field(ui->languages);
  ci->phone = copy_field(ui->phone);

  ci->create_time = current_time;
  ci->last_change_time = ui->last_change_time;
  ci->last_access_time = 0;
  ci->last_pwdchange_time = ui->last_pwdchange_time;
  ui->last_access_time = current_time;

  if (ui->team_passwd) {
    ci->team_passwd = xstrdup(ui->team_passwd);
    ci->team_passwd_method = ui->team_passwd_method;
  }

  if (contests_get(contest_id, &cnts) < 0) cnts = 0;
  memset(role_max, 0, sizeof(role_max));
  memset(role_cur, 0, sizeof(role_cur));

  if (ui->members) {
    for (i = 0; i < ui->members->u; i++) {
      if (!(om = ui->members->m[i])) continue;
      ASSERT(om->team_role >= 0 && om->team_role < USERLIST_MB_LAST);
      role_max[om->team_role]++;
    }
  }
  if (cnts) {
    for (i = 0; i < USERLIST_MB_LAST; i++) {
      if (!cnts->members[i]) {
        role_max[i] = 0;
      } else if (cnts->members[i]->max_count < role_max[i]) {
        role_max[i] = cnts->members[i]->max_count;
      }
    }
  }
  for (i = 0, members_total = 0; i < USERLIST_MB_LAST; i++)
    members_total += role_max[i];

  if (members_total > 0) {
    mm = (struct userlist_members*)userlist_node_alloc(USERLIST_T_MEMBERS);
    xml_link_node_last(&ci->b, &mm->b);
    ci->members = mm;
    j = 4;
    while (j < members_total) j *= 2;
    mm->a = j;
    XCALLOC(mm->m, j);
  }

  if (ui->members) {
    for (i = 0; i < ui->members->u; i++) {
      if (!(om = ui->members->m[i])) continue;
      r = om->team_role;
      if (r < 0 || r >= USERLIST_MB_LAST || role_cur[r] >= role_max[r])
        continue;

      mm->m[mm->u] = userlist_clone_member(ui->members->m[i], p_serial, current_time);
      xml_link_node_last(&mm->b, &mm->m[mm->u]->b);
      mm->u++;
    }
  }

  userlist_insert_user_info(u, contest_id, ci);

  if (p_cloned_flag) *p_cloned_flag = 1;
  return ci;
}

static int
get_member_serial_func(void *data)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  return ul->member_serial;
}

static int
set_member_serial_func(void *data, int new_serial)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  if (ul->member_serial > new_serial) return -1;
  if (ul->member_serial == new_serial) return 0;
  ul->member_serial = new_serial;
  state->dirty = 1;
  return 1;
}

static const struct userlist_contest *
get_contest_reg_func(
        void *data,
        int user_id,
        int contest_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct xml_tree *p;
  struct userlist_contest *uc;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id]))
    return 0;
  if (contest_id <= 0) return 0;
  if (!u->contests) return 0;
  for (p = u->contests->first_down; p; p = p->right) {
    uc = (struct userlist_contest*) p;
    if (uc->id == contest_id) return uc;
  }
  return 0;
}

static int
set_simple_reg_func(
        void *data,
        int user_id,
        int value,
        time_t cur_time)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }

  value = !!value;
  u->simple_registration = value;
  if (cur_time <= 0) cur_time = time(0);
  u->last_change_time = cur_time;
  state->dirty = 1;
  state->flush_interval /= 2;
  return 0;
}

struct group_iterator
{
  struct ptr_iterator b;

  struct uldb_xml_state *state;
  int group_id;
};

static int
group_iterator_has_next_func(ptr_iterator_t data)
{
  struct group_iterator *iter = (struct group_iterator *) data;
  struct userlist_list *ul;

  if (!iter->state || !(ul = iter->state->userlist)) return 0;
  if (ul->group_map_size <= 0) return 0;
  if (iter->group_id >= ul->group_map_size) return 0;
  return iter->group_id < ul->group_map_size;
}
static const void *
group_iterator_get_func(ptr_iterator_t data)
{
  struct group_iterator *iter = (struct group_iterator *) data;
  struct userlist_list *ul;

  if (!iter->state || !(ul = iter->state->userlist)) return 0;
  if (ul->group_map_size <= 0) return 0;
  if (iter->group_id >= ul->group_map_size) return 0;
  return ul->group_map[iter->group_id];
}
static void
group_iterator_next_func(ptr_iterator_t data)
{
  struct group_iterator *iter = (struct group_iterator *) data;
  struct userlist_list *ul;

  if (!iter->state || !(ul = iter->state->userlist)) return;
  if (ul->group_map_size <= 0) return;
  if (iter->group_id >= ul->group_map_size) return;
  ++iter->group_id;
  while (iter->group_id < ul->group_map_size
         && !ul->group_map[iter->group_id]) {
    ++iter->group_id;
  }
}
static void
group_iterator_destroy_func(ptr_iterator_t data)
{
  xfree(data);
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
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct group_iterator *iter = 0;
  const struct userlist_list *ul = state->userlist;

  XCALLOC(iter, 1);
  iter->b = group_iterator_funcs;
  iter->state = state;
  iter->group_id = 0;

  while (iter->group_id < ul->group_map_size
         && !ul->group_map[iter->group_id]) {
    ++iter->group_id;
  }

  return (ptr_iterator_t) iter;
}

static const struct userlist_group*
get_group_by_name_func(
        void *data,
        const unsigned char *group_name)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  const struct userlist_list *ul = state->userlist;
  const struct userlist_group *grp;
  int i;

  if (!ul || ul->group_map_size <= 0) return 0;
  /* FIXME: use hash */
  for (i = 1; i < ul->group_map_size; ++i) {
    if ((grp = ul->group_map[i]) && grp->group_name
        && !strcmp(group_name, grp->group_name))
      return grp;
  }

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
  serial -= step;
  do {
    serial += step;
    snprintf(buf, bufsize, format, serial);
  } while (get_group_by_name_func(data, buf));
  return serial;
}

static int
create_group_func(
        void *data,
        const unsigned char *group_name,
        int created_by)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_group *grp;
  int i, group_id, new_size;
  struct userlist_group **new_map;

  if (!group_name || !*group_name) return -1;
  for (i = 1; i < ul->group_map_size; ++i) {
    if ((grp = ul->group_map[i]) && grp->group_name
        && !strcmp(group_name, grp->group_name))
      return -1;
  }

  for (group_id = 1; group_id < ul->group_map_size; ++group_id) {
    if (!ul->group_map[group_id])
      break;
  }

  if (group_id >= ul->group_map_size) {
    new_size = 16;
    if (ul->group_map_size > new_size) new_size = ul->group_map_size;
    while (group_id >= new_size)
      new_size *= 2;

    XCALLOC(new_map, new_size);
    for (i = 1; i < ul->group_map_size; ++i) {
      new_map[i] = ul->group_map[i];
    }
    xfree(ul->group_map);
    ul->group_map = new_map;
    ul->group_map_size = new_size;
  }

  if (!ul->groups_node) {
    ul->groups_node = userlist_node_alloc(USERLIST_T_USERGROUPS);
    xml_link_node_last(&ul->b, ul->groups_node);
  }

  grp = (struct userlist_group*) userlist_node_alloc(USERLIST_T_USERGROUP);
  xml_link_node_last(&ul->b, &grp->b);
  grp->group_id = group_id;
  grp->group_name = xstrdup(group_name);
  ul->group_map[group_id] = grp;

  state->dirty = 1;
  state->flush_interval /= 2;

  return group_id;
}

static int
remove_group_func(
        void *data,
        int group_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_group *grp;

  if (ul->group_map_size <= 0 || !ul->group_map) return -1;
  if (group_id <= 0 || group_id >= ul->group_map_size) return -1;
  if (!(grp = ul->group_map[group_id])) return -1;
  xml_unlink_node(&grp->b);
  userlist_free(&grp->b);
  ul->group_map[group_id] = 0;

  state->dirty = 1;
  state->flush_interval /= 2;

  return 0;
}

static int
edit_group_field_func(
        void *data,
        int group_id,
        int field,
        const unsigned char *value)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_group *grp;
  void *vptr;
  int i;

  if (ul->group_map_size <= 0 || !ul->group_map) return -1;
  if (group_id <= 0 || group_id >= ul->group_map_size) return -1;
  if (!(grp = ul->group_map[group_id])) return -1;
  if (field <= 0 || field >= USERLIST_GRP_LAST) return -1;

  vptr = userlist_group_get_ptr_nc(grp, field);
  switch (field) {
  case USERLIST_GRP_GROUP_NAME:
    {
      unsigned char **sptr = (unsigned char**) vptr;

      if (!value || !*value) return -1;
      for (i = 1; i < ul->group_map_size; ++i) {
        if (i != group_id && ul->group_map[i] && ul->group_map[i]->group_name
            && !strcmp(value, ul->group_map[i]->group_name)) {
          return -1;
        }
      }

      xfree(*sptr); *sptr = 0;
      *sptr = xstrdup(value);
    }
    break;
  case USERLIST_GRP_DESCRIPTION:
    {
      unsigned char **sptr = (unsigned char**) vptr;

      if (!value) {
        if (!*sptr) return 0;
        xfree(*sptr); *sptr = 0;
        return 0;
      }
      if (*sptr && !strcmp(*sptr, value)) {
        return 0;
      }
      xfree(*sptr); *sptr = 0;
      *sptr = xstrdup(value);
      return 0;
    }
    break;
  default:
    return -1;
  }

  state->dirty = 1;
  state->flush_interval /= 2;

  return 0;
}

static int
clear_group_field_func(
        void *data,
        int group_id,
        int field)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_group *grp;
  void *vptr;

  if (ul->group_map_size <= 0 || !ul->group_map) return -1;
  if (group_id <= 0 || group_id >= ul->group_map_size) return -1;
  if (!(grp = ul->group_map[group_id])) return -1;
  if (field != USERLIST_GRP_DESCRIPTION) return -1;

  vptr = userlist_group_get_ptr_nc(grp, field);
  switch (field) {
  case USERLIST_GRP_DESCRIPTION:
    {
      unsigned char **sptr = (unsigned char**) vptr;
      if (!*sptr) return 0;
      xfree(*sptr); *sptr = 0;
    }
    break;
  default:
    return -1;
  }

  state->dirty = 1;
  state->flush_interval /= 2;

  return 0;
}

static const struct userlist_group*
get_group_func(
        void *data,
        int group_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  const struct userlist_list *ul = state->userlist;

  if (!ul || ul->group_map_size <= 0) return 0;
  if (group_id <= 0 || group_id >= ul->group_map_size) return 0;
  return ul->group_map[group_id];
}

struct group_user_iterator
{
  struct ptr_iterator b;

  struct uldb_xml_state *state;
  int group_id;
  struct userlist_groupmember *cur_member;
};

static int
group_user_iterator_has_next_func(ptr_iterator_t data)
{
  struct group_user_iterator *iter = (struct group_user_iterator *) data;

  return iter->cur_member != 0;
}
static const void *
group_user_iterator_get_func(ptr_iterator_t data)
{
  struct group_user_iterator *iter = (struct group_user_iterator *) data;
  struct userlist_list *ul;

  if (!iter || !iter->state || !(ul = iter->state->userlist)) return 0;
  if (!iter->cur_member) return 0;
  if (iter->cur_member->user_id <= 0) return 0;
  if (iter->cur_member->user_id >= ul->user_map_size) return 0;
  return ul->user_map[iter->cur_member->user_id];
}
static void
group_user_iterator_next_func(ptr_iterator_t data)
{
  struct group_user_iterator *iter = (struct group_user_iterator *) data;

  if (iter->cur_member) {
    iter->cur_member = (struct userlist_groupmember*) iter->cur_member->user_next;
  }
}
static void
group_user_iterator_destroy_func(ptr_iterator_t data)
{
  xfree(data);
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
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct group_user_iterator *iter = 0;
  const struct userlist_list *ul = state->userlist;

  if (!ul || group_id <= 0 || group_id >= ul->group_map_size)
    return 0;
  if (!ul->group_map[group_id])
    return 0;

  XCALLOC(iter, 1);
  iter->b = group_user_iterator_funcs;
  iter->state = state;
  iter->group_id = group_id;
  iter->cur_member = (struct userlist_groupmember*) ul->group_map[group_id]->user_first;

  return (ptr_iterator_t) iter;
}

struct group_member_iterator
{
  struct ptr_iterator b;

  struct uldb_xml_state *state;
  int group_id;
  struct userlist_groupmember *cur_member;
};

static int
group_member_iterator_has_next_func(ptr_iterator_t data)
{
  struct group_member_iterator *iter = (struct group_member_iterator *) data;

  return iter->cur_member != 0;
}
static const void *
group_member_iterator_get_func(ptr_iterator_t data)
{
  struct group_member_iterator *iter = (struct group_member_iterator *) data;
  struct userlist_list *ul;

  if (!iter || !iter->state || !(ul = iter->state->userlist)) return 0;
  if (!iter->cur_member) return 0;
  return iter->cur_member;
}
static void
group_member_iterator_next_func(ptr_iterator_t data)
{
  struct group_member_iterator *iter = (struct group_member_iterator *) data;

  if (iter->cur_member) {
    iter->cur_member = (struct userlist_groupmember*) iter->cur_member->user_next;
  }
}
static void
group_member_iterator_destroy_func(ptr_iterator_t data)
{
  xfree(data);
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
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct group_member_iterator *iter = 0;
  const struct userlist_list *ul = state->userlist;

  if (!ul || group_id <= 0 || group_id >= ul->group_map_size)
    return 0;
  if (!ul->group_map[group_id])
    return 0;

  XCALLOC(iter, 1);
  iter->b = group_member_iterator_funcs;
  iter->state = state;
  iter->group_id = group_id;
  iter->cur_member = (struct userlist_groupmember*) ul->group_map[group_id]->user_first;

  return (ptr_iterator_t) iter;
}

static int
create_group_member_func(void *data, int group_id, int user_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_group *grp;
  struct userlist_user *u;
  struct xml_tree *t;
  struct userlist_groupmember *gm = 0;
  struct userlist_groupmember *gm2, *gm3;

  if (ul->group_map_size <= 0 || !ul->group_map) return -1;
  if (group_id <= 0 || group_id >= ul->group_map_size) return -1;
  if (!(grp = ul->group_map[group_id])) return -1;
  if (ul->user_map_size <= 0 || !ul->user_map) return -1;
  if (user_id <= 0 || user_id >= ul->user_map_size) return -1;
  if (!(u = ul->user_map[user_id])) return -1;

  for (t = grp->user_first; t; t = gm->user_next) {
    ASSERT(t->tag == USERLIST_T_USERGROUPMEMBER);
    gm = (struct userlist_groupmember*) t;
    if (gm->group_id == group_id && gm->user_id == user_id) return 0;
  }

  if (!ul->groupmembers_node) {
    t = userlist_node_alloc(USERLIST_T_USERGROUPMEMBERS);
    xml_link_node_last(&ul->b, t);
    ul->groupmembers_node = t;
  }

  gm = (struct userlist_groupmember*) userlist_node_alloc(USERLIST_T_USERGROUPMEMBER);
  xml_link_node_last(ul->groupmembers_node, &gm->b);
  gm->user_id = user_id;
  gm->group_id = group_id;

  for (gm2 = (struct userlist_groupmember*) grp->user_first;
       gm2 && gm2->user_id < user_id;
       gm2 = (struct userlist_groupmember*) gm2->user_next) {
  }
  if (!grp->user_first) {
    grp->user_first = &gm->b;
    grp->user_last = &gm->b;
  } else if (!gm2) {
    gm3 = (struct userlist_groupmember*) grp->user_last;
    gm->user_prev = &gm3->b;
    gm3->user_next = &gm->b;
    grp->user_last = &gm->b;
  } else if (&gm2->b == grp->user_first) {
    ASSERT(gm2->user_id > user_id);
    gm->user_next = &gm2->b;
    gm2->user_prev = &gm->b;
    grp->user_first = &gm->b;
  } else {
    ASSERT(gm2->user_id > user_id);
    gm3 = (struct userlist_groupmember*) gm2->user_prev;
    gm->user_prev = &gm3->b;
    gm->user_next = &gm2->b;
    gm3->user_next = &gm->b;
    gm2->user_prev = &gm->b;
  }

  for (gm2 = (struct userlist_groupmember*) u->group_first;
       gm2 && gm2->group_id < group_id;
       gm2 = (struct userlist_groupmember*) gm2->group_next) {
  }
  if (!u->group_first) {
    u->group_first = &gm->b;
    u->group_last = &gm->b;
  } else if (!gm2) {
    gm3 = (struct userlist_groupmember*) u->group_last;
    gm->group_prev = &gm3->b;
    gm3->group_next = &gm->b;
    u->group_last = &gm->b;
  } else if (&gm2->b == u->group_first) {
    ASSERT(gm2->group_id > group_id);
    gm->group_next = &gm2->b;
    gm2->group_prev = &gm->b;
    u->group_first = &gm->b;
  } else {
    ASSERT(gm2->group_id > group_id);
    gm3 = (struct userlist_groupmember*) gm2->group_prev;
    gm->group_prev = &gm3->b;
    gm->group_next = &gm2->b;
    gm3->group_next = &gm->b;
    gm2->group_prev = &gm->b;
  }

  state->dirty = 1;
  state->flush_interval /= 2;

  return 0;
}

static int
remove_group_member_func(void *data, int group_id, int user_id)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_group *grp;
  struct userlist_user *u;
  struct xml_tree *t;
  struct userlist_groupmember *gm = 0;
  struct userlist_groupmember *gm2, *gm3;

  if (ul->group_map_size <= 0 || !ul->group_map) return -1;
  if (group_id <= 0 || group_id >= ul->group_map_size) return -1;
  if (!(grp = ul->group_map[group_id])) return -1;
  if (ul->user_map_size <= 0 || !ul->user_map) return -1;
  if (user_id <= 0 || user_id >= ul->user_map_size) return -1;
  if (!(u = ul->user_map[user_id])) return -1;

  for (gm = (struct userlist_groupmember*) grp->user_first;
       gm && gm->user_id != user_id;
       gm = (struct userlist_groupmember*) gm->user_next) {
    ASSERT(gm->b.tag == USERLIST_T_USERGROUPMEMBER);
  }

  for (gm2 = (struct userlist_groupmember *) u->group_first;
       gm2 && gm2->group_id != group_id;
       gm2 = (struct userlist_groupmember*) gm2->group_next) {
    ASSERT(gm->b.tag == USERLIST_T_USERGROUPMEMBER);
  }

  if (!gm && !gm2) {
    // no such member
    return 0;
  }
  ASSERT(gm == gm2);

  /* remove from the list of group users */
  gm3 = (struct userlist_groupmember*) gm->user_prev;
  if (gm3) {
    gm3->user_next = gm->user_next;
  } else {
    grp->user_first = gm->user_next;
  }
  gm2 = (struct userlist_groupmember*) gm->user_next;
  if (gm2) {
    gm2->user_prev = gm->user_prev;
  } else {
    grp->user_last = gm->user_prev;
  }
  gm->user_prev = 0;
  gm->user_next = 0;

  /* remove from the list of user groups */
  gm3 = (struct userlist_groupmember*) gm->group_prev;
  if (gm3) {
    gm3->group_next = gm->group_next;
  } else {
    u->group_first = gm->group_next;
  }
  gm2 = (struct userlist_groupmember*) gm->group_next;
  if (gm2) {
    gm2->group_prev = gm->group_prev;
  } else {
    u->group_last = gm->group_prev;
  }
  gm->group_prev = 0;
  gm->group_next = 0;

  xml_unlink_node(&gm->b);
  userlist_free(&gm->b);

  t = ul->groupmembers_node;
  if (!t->first_down) {
    ul->groupmembers_node = 0;
    xml_unlink_node(t);
    userlist_free(t);
  }

  state->dirty = 1;
  state->flush_interval /= 2;

  return 0;
}

static const struct userlist_groupmember *
find_user_group(const struct userlist_user *u, int group_id)
{
  if (!u) return NULL;
  if (!u->group_first) return NULL;

  const struct userlist_groupmember *gm;
  for (gm = (const struct userlist_groupmember*) u->group_first;
       gm && gm->group_id < group_id;
       gm = (const struct userlist_groupmember*) gm->group_next) {
  }
  if (gm && gm->group_id == group_id) return gm;
  return NULL;
}

static const struct userlist_contest *
find_user_contest(const struct userlist_user *u, int contest_id)
{
  if (!u) return NULL;
  if (!u->contests) return NULL;

  const struct xml_tree *t;
  for (t = u->contests->first_down; t; t = t->right) {
    const struct userlist_contest *c = (const struct userlist_contest*) t;
    if (c->id == contest_id) return c;
  }
  return NULL;
}

static int
match_string(const unsigned char *value, int filter_op, const unsigned char *pattern)
{
  if (!value) value = "";
  if (!pattern) pattern = "";
  int vlen = strlen(value);
  int plen = strlen(pattern);

  switch (filter_op) {
  case USER_FILTER_OP_EQ: // "eq": 'equal'
    return strcmp(value, pattern) == 0;
  case USER_FILTER_OP_NE: // "ne": 'not equal'
    return strcmp(value, pattern) != 0;
  case USER_FILTER_OP_LT: // "lt": 'less'
    return strcmp(value, pattern) < 0;
  case USER_FILTER_OP_LE: // "le": 'less or equal'
    return strcmp(value, pattern) <= 0;
  case USER_FILTER_OP_GT: // "gt": 'greater'
    return strcmp(value, pattern) > 0;
  case USER_FILTER_OP_GE: // "ge": 'greater or equal'
    return strcmp(value, pattern) >= 0;
  case USER_FILTER_OP_BW: // "bw": 'begins with'
    return vlen >= plen && !strncmp(value, pattern, plen);
  case USER_FILTER_OP_BN: // "bn": 'does not begin with'
    return vlen < plen || strncmp(value, pattern, plen) != 0;
  case USER_FILTER_OP_IN: // "in": 'is in'
    return 0;
  case USER_FILTER_OP_NI: // "ni": 'is not in'
    return 0;
  case USER_FILTER_OP_EW: // "ew": 'ends with'
    return vlen >= plen && !strcmp(value + vlen - plen, pattern);
  case USER_FILTER_OP_EN: // "en": 'does not end with'
    return vlen < plen || strcmp(value + vlen - plen, pattern) != 0;
  case USER_FILTER_OP_CN: // "cn": 'contains'
    return strstr(value, pattern) != NULL;
  case USER_FILTER_OP_NC: // "nc": 'does not contain'
    return strstr(value, pattern) == NULL;
  default:
    return 0;
  }
  return 0;
}

static int
match_int(int value, int filter_op, int pattern)
{
  switch (filter_op) {
  case USER_FILTER_OP_EQ: // "eq": 'equal'
    return value == pattern;
  case USER_FILTER_OP_NE: // "ne": 'not equal'
    return value != pattern;
  case USER_FILTER_OP_LT: // "lt": 'less'
    return value < pattern;
  case USER_FILTER_OP_LE: // "le": 'less or equal'
    return value <= pattern;
  case USER_FILTER_OP_GT: // "gt": 'greater'
    return value > pattern;
  case USER_FILTER_OP_GE: // "ge": 'greater or equal'
    return value >= pattern;
  case USER_FILTER_OP_BW: // "bw": 'begins with'
    return 0;
  case USER_FILTER_OP_BN: // "bn": 'does not begin with'
    return 0;
  case USER_FILTER_OP_IN: // "in": 'is in'
    return 0;
  case USER_FILTER_OP_NI: // "ni": 'is not in'
    return 0;
  case USER_FILTER_OP_EW: // "ew": 'ends with'
    return 0;
  case USER_FILTER_OP_EN: // "en": 'does not end with'
    return 0;
  case USER_FILTER_OP_CN: // "cn": 'contains'
    return 0;
  case USER_FILTER_OP_NC: // "nc": 'does not contain'
    return 0;
  default:
    return 0;
  }
  return 0;
}

static int
does_user_match(
        const struct userlist_user *u,
        int contest_id,
        int group_id,
        int filter_field,
        int filter_op,
        const void *vvalue)
{
  if (!u) return 0;
  if (contest_id > 0 && !find_user_contest(u, contest_id)) return 0;
  if (group_id > 0 && !find_user_group(u, group_id)) return 0;
  if (filter_field < 0) return 1;

  switch (filter_field) {
  case USERLIST_NN_ID:
    return match_int(u->id, filter_op, *(const int*) vvalue);
  case USERLIST_NN_LOGIN:
    return match_string(u->login, filter_op, (const unsigned char*) vvalue);
  case USERLIST_NN_EMAIL:
    return match_string(u->email, filter_op, (const unsigned char *) vvalue);
  case USERLIST_NC_NAME:
    {
      const struct userlist_user_info *ui = NULL;
      if (contest_id <= 0) {
        ui = u->cnts0;
      } else {
        ui = userlist_get_user_info(u, contest_id);
      }
      if (!ui) return 0;
      return match_string(ui->name, filter_op, (const unsigned char *) vvalue);
    }
  default:
    return 0;
  }

  return 0;
}

struct userlist_sorting_context
{
  const struct userlist_list *userlist;
  int contest_id;
};

/*
static int
sort_func_user_id_asc(const void *v1, const void *v2, void *vc)
{
  const struct userlist_sorting_context *cntx = (const struct userlist_sorting_context *) vc;
  int idx1 = *(const int*) v1;
  int idx2 = *(const int*) v2;
  const struct userlist_user *u1 = NULL;
  const struct userlist_user *u2 = NULL;
  if (idx1 > 0 && idx1 < cntx->userlist->user_map_size) u1 = cntx->userlist->user_map[idx1];
  if (idx2 > 0 && idx2 < cntx->userlist->user_map_size) u2 = cntx->userlist->user_map[idx2];
  int id1 = 0;
  int id2 = 0;
  if (u1) id1 = u1->id;
  if (u2) id2 = u2->id;
  if (id1 < id2) return -1;
  if (id1 > id2) return 1;
  return 0;
}
*/
static int
sort_func_user_id_dsc(const void *v1, const void *v2, void *vc)
{
  const struct userlist_sorting_context *cntx = (const struct userlist_sorting_context *) vc;
  int idx1 = *(const int*) v1;
  int idx2 = *(const int*) v2;
  const struct userlist_user *u1 = NULL;
  const struct userlist_user *u2 = NULL;
  if (idx1 > 0 && idx1 < cntx->userlist->user_map_size) u1 = cntx->userlist->user_map[idx1];
  if (idx2 > 0 && idx2 < cntx->userlist->user_map_size) u2 = cntx->userlist->user_map[idx2];
  int id1 = 0;
  int id2 = 0;
  if (u1) id1 = u1->id;
  if (u2) id2 = u2->id;
  if (id1 > id2) return -1;
  if (id1 < id2) return 1;
  return 0;
}
static int
sort_func_login_asc(const void *v1, const void *v2, void *vc)
{
  const struct userlist_sorting_context *cntx = (const struct userlist_sorting_context *) vc;
  int idx1 = *(const int*) v1;
  int idx2 = *(const int*) v2;
  const struct userlist_user *u1 = NULL;
  const struct userlist_user *u2 = NULL;
  if (idx1 > 0 && idx1 < cntx->userlist->user_map_size) u1 = cntx->userlist->user_map[idx1];
  if (idx2 > 0 && idx2 < cntx->userlist->user_map_size) u2 = cntx->userlist->user_map[idx2];
  const unsigned char *str1 = NULL;
  const unsigned char *str2 = NULL;
  if (u1) str1 = u1->login;
  if (!str1) str1 = "";
  if (u2) str2 = u2->login;
  if (!str2) str2 = "";
  return strcmp(str1, str2);
}
static int
sort_func_login_dsc(const void *v1, const void *v2, void *vc)
{
  const struct userlist_sorting_context *cntx = (const struct userlist_sorting_context *) vc;
  int idx1 = *(const int*) v1;
  int idx2 = *(const int*) v2;
  const struct userlist_user *u1 = NULL;
  const struct userlist_user *u2 = NULL;
  if (idx1 > 0 && idx1 < cntx->userlist->user_map_size) u1 = cntx->userlist->user_map[idx1];
  if (idx2 > 0 && idx2 < cntx->userlist->user_map_size) u2 = cntx->userlist->user_map[idx2];
  const unsigned char *str1 = NULL;
  const unsigned char *str2 = NULL;
  if (u1) str1 = u1->login;
  if (!str1) str1 = "";
  if (u2) str2 = u2->login;
  if (!str2) str2 = "";
  return strcmp(str2, str1);
}
static int
sort_func_email_asc(const void *v1, const void *v2, void *vc)
{
  const struct userlist_sorting_context *cntx = (const struct userlist_sorting_context *) vc;
  int idx1 = *(const int*) v1;
  int idx2 = *(const int*) v2;
  const struct userlist_user *u1 = NULL;
  const struct userlist_user *u2 = NULL;
  if (idx1 > 0 && idx1 < cntx->userlist->user_map_size) u1 = cntx->userlist->user_map[idx1];
  if (idx2 > 0 && idx2 < cntx->userlist->user_map_size) u2 = cntx->userlist->user_map[idx2];
  const unsigned char *str1 = NULL;
  const unsigned char *str2 = NULL;
  if (u1) str1 = u1->email;
  if (!str1) str1 = "";
  if (u2) str2 = u2->email;
  if (!str2) str2 = "";
  return strcmp(str1, str2);
}
static int
sort_func_email_dsc(const void *v1, const void *v2, void *vc)
{
  const struct userlist_sorting_context *cntx = (const struct userlist_sorting_context *) vc;
  int idx1 = *(const int*) v1;
  int idx2 = *(const int*) v2;
  const struct userlist_user *u1 = NULL;
  const struct userlist_user *u2 = NULL;
  if (idx1 > 0 && idx1 < cntx->userlist->user_map_size) u1 = cntx->userlist->user_map[idx1];
  if (idx2 > 0 && idx2 < cntx->userlist->user_map_size) u2 = cntx->userlist->user_map[idx2];
  const unsigned char *str1 = NULL;
  const unsigned char *str2 = NULL;
  if (u1) str1 = u1->email;
  if (!str1) str1 = "";
  if (u2) str2 = u2->email;
  if (!str2) str2 = "";
  return strcmp(str2, str1);
}
static int
sort_func_name_asc(const void *v1, const void *v2, void *vc)
{
  const struct userlist_sorting_context *cntx = (const struct userlist_sorting_context *) vc;
  int idx1 = *(const int*) v1;
  int idx2 = *(const int*) v2;
  const struct userlist_user *u1 = NULL;
  const struct userlist_user *u2 = NULL;
  if (idx1 > 0 && idx1 < cntx->userlist->user_map_size) u1 = cntx->userlist->user_map[idx1];
  if (idx2 > 0 && idx2 < cntx->userlist->user_map_size) u2 = cntx->userlist->user_map[idx2];
  const struct userlist_user_info *ui1 = NULL;
  const struct userlist_user_info *ui2 = NULL;
  if (u1) ui1 = userlist_get_user_info(u1, cntx->contest_id);
  if (u2) ui2 = userlist_get_user_info(u2, cntx->contest_id);
  const unsigned char *str1 = NULL;
  const unsigned char *str2 = NULL;
  if (ui1) str1 = ui1->name;
  if (!str1) str1 = "";
  if (ui2) str2 = ui2->name;
  if (!str2) str2 = "";
  return strcmp(str1, str2);
}
static int
sort_func_name_dsc(const void *v1, const void *v2, void *vc)
{
  const struct userlist_sorting_context *cntx = (const struct userlist_sorting_context *) vc;
  int idx1 = *(const int*) v1;
  int idx2 = *(const int*) v2;
  const struct userlist_user *u1 = NULL;
  const struct userlist_user *u2 = NULL;
  if (idx1 > 0 && idx1 < cntx->userlist->user_map_size) u1 = cntx->userlist->user_map[idx1];
  if (idx2 > 0 && idx2 < cntx->userlist->user_map_size) u2 = cntx->userlist->user_map[idx2];
  const struct userlist_user_info *ui1 = NULL;
  const struct userlist_user_info *ui2 = NULL;
  if (u1) ui1 = userlist_get_user_info(u1, cntx->contest_id);
  if (u2) ui2 = userlist_get_user_info(u2, cntx->contest_id);
  const unsigned char *str1 = NULL;
  const unsigned char *str2 = NULL;
  if (ui1) str1 = ui1->name;
  if (!str1) str1 = "";
  if (ui2) str2 = ui2->name;
  if (!str2) str2 = "";
  return strcmp(str1, str2);
}

struct brief_list_3_iterator
{
  struct ptr_iterator b;
  struct uldb_xml_state *state;
  int *user_ids;
  int total;
  int count;
  int index;
};

static int
brief_list_3_iterator_has_next_func(ptr_iterator_t data)
{
  struct brief_list_3_iterator *iter = (struct brief_list_3_iterator*) data;
  return iter->index < iter->count;
}
static const void *
brief_list_3_iterator_get_func(ptr_iterator_t data)
{
  struct brief_list_3_iterator *iter = (struct brief_list_3_iterator*) data;
  struct userlist_list *ul = iter->state->userlist;
  if (iter->index >= iter->count) return NULL;
  int user_id = iter->user_ids[iter->index];
  if (user_id > 0 && user_id < ul->user_map_size)
    return (const void *) ul->user_map[user_id];
  return NULL;
}
static void
brief_list_3_iterator_next_func(ptr_iterator_t data)
{
  struct brief_list_3_iterator *iter = (struct brief_list_3_iterator*) data;
  if (iter->index < iter->count) ++iter->index;
}
static void
brief_list_3_iterator_destroy_func(ptr_iterator_t data)
{
  struct brief_list_3_iterator *iter = (struct brief_list_3_iterator*) data;
  xfree(iter->user_ids);
  xfree(iter);
}
static long long
brief_list_3_iterator_get_total_func(ptr_iterator_t data)
{
  struct brief_list_3_iterator *iter = (struct brief_list_3_iterator*) data;
  return iter->total;
}

static struct ptr_iterator brief_list_3_iterator_funcs =
{
  brief_list_3_iterator_has_next_func,
  brief_list_3_iterator_get_func,
  brief_list_3_iterator_next_func,
  brief_list_3_iterator_destroy_func,
  brief_list_3_iterator_get_total_func,
};

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
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;

  int *user_ids = 0;
  int user_ids_a = 16;
  int user_ids_u = 0;
  XCALLOC(user_ids, user_ids_a);

  const void *filter_data = filter;
  int int_key = 0;
  if (filter_field == USERLIST_NN_ID) {
    if (xml_parse_int(NULL, NULL, 0, 0, filter, &int_key) >= 0) {
      filter_data = &int_key;
    } else {
      filter_op = 0;
    }
  }

  for (int user_id = 1; user_id < state->userlist->user_map_size; ++user_id) {
    if (does_user_match(state->userlist->user_map[user_id], contest_id, group_id, filter_field, filter_op, filter_data)) {
      if (user_ids_u >= user_ids_a) {
        if (!(user_ids_a *= 2)) user_ids_a = 32;
        XREALLOC(user_ids, user_ids_a);
      }
      user_ids[user_ids_u++] = user_id;
    }
  }

  // sort data according to sort_field/sort_order
  int (*sort_func)(const void *, const void *, void *) = NULL;
  switch (sort_field) {
  case USERLIST_NN_ID:
    if (sort_order == 1) {
      //sort_func = sort_func_user_id_asc;
    } else if (sort_order == 2) {
      sort_func = sort_func_user_id_dsc;
    }
    break;
  case USERLIST_NN_LOGIN:
    if (sort_order == 1) {
      sort_func = sort_func_login_asc;
    } else if (sort_order == 2) {
      sort_func = sort_func_login_dsc;
    }
    break;
  case USERLIST_NN_EMAIL:
    if (sort_order == 1) {
      sort_func = sort_func_email_asc;
    } else if (sort_order == 2) {
      sort_func = sort_func_email_dsc;
    }
    break;
  case USERLIST_NC_NAME:
    if (sort_order == 1) {
      sort_func = sort_func_name_asc;
    } else if (sort_order == 2) {
      sort_func = sort_func_name_dsc;
    }
    break;
  }

  if (sort_func) {
    qsort_r(user_ids, user_ids_u, sizeof(user_ids[0]), sort_func,
            (struct userlist_sorting_context[]){{ state->userlist, contest_id }});
  }

  // extract the requested window
  // page is numbered from 0
  if (count <= 0) count = 15; // default page size
  if (page < 0) page = 0;
  if (page * count >= user_ids_u) page = user_ids_u / count;
  int page_size = count;
  if ((page + 1) * count > user_ids_u) count = user_ids_u - page * count;

  struct brief_list_3_iterator *iter = NULL;
  XCALLOC(iter, 1);
  iter->b = brief_list_3_iterator_funcs;
  iter->state = state;
  iter->total = user_ids_u;
  iter->count = count;
  if (count > 0) {
    XCALLOC(iter->user_ids, count);
    memcpy(iter->user_ids, user_ids + page * page_size, count * sizeof(user_ids[0]));
  }
  xfree(user_ids); user_ids = NULL;
  return (ptr_iterator_t) iter;
}

static void
brief_list_2_do_skip(
        struct brief_list_2_iterator *iter,
        const struct userlist_list *ul)
{
  const struct userlist_user *u;
  const struct xml_tree *t;
  const struct userlist_contest *c;

  for (;; ++iter->user_id) {
    if (iter->user_id >= ul->user_map_size) return;
    if (!(u = ul->user_map[iter->user_id])) continue;
    if (iter->contest_id > 0 && iter->group_id > 0) {
      if (!find_user_group(u, iter->group_id)) continue;
      if (!u->contests) continue;
      for (t = u->contests->first_down; t; t = t->right) {
        c = (const struct userlist_contest*) t;
        if (c->id == iter->contest_id) {
          if (iter->offset <= 0) return;
          --iter->offset;
          break;
        }
      }
    } else if (iter->group_id > 0) {
      if (!find_user_group(u, iter->group_id)) continue;
      if (iter->offset <= 0) return;
      --iter->offset;
    } else if (iter->contest_id > 0) {
      if (!u->contests) continue;
      for (t = u->contests->first_down; t; t = t->right) {
        c = (const struct userlist_contest*) t;
        if (c->id == iter->contest_id) {
          if (iter->offset <= 0) return;
          --iter->offset;
          break;
        }
      }
    } else {
      if (iter->offset <= 0) return;
      --iter->offset;
      continue;
    }
  }
}

static int
brief_list_2_iterator_has_next_func(ptr_iterator_t data)
{
  struct brief_list_2_iterator *iter = (struct brief_list_2_iterator*) data;
  struct userlist_list *ul = iter->state->userlist;

  if (iter->count <= 0) return 0;
  brief_list_2_do_skip(iter, ul);
  return (iter->user_id < ul->user_map_size);
}
static const void *
brief_list_2_iterator_get_func(ptr_iterator_t data)
{
  struct brief_list_2_iterator *iter = (struct brief_list_2_iterator*) data;
  struct userlist_list *ul = iter->state->userlist;

  if (iter->count <= 0) return 0;
  brief_list_2_do_skip(iter, ul);
  if (iter->user_id >= ul->user_map_size) return 0;
  return (const void *) ul->user_map[iter->user_id];
}
static void
brief_list_2_iterator_next_func(ptr_iterator_t data)
{
  struct brief_list_2_iterator *iter = (struct brief_list_2_iterator*) data;
  struct userlist_list *ul = iter->state->userlist;

  if (iter->count <= 0) return;
  if (iter->user_id < ul->user_map_size) iter->user_id++;
  --iter->count;
  brief_list_2_do_skip(iter, ul);
}

static void
brief_list_2_iterator_destroy_func(ptr_iterator_t data)
{
  struct brief_list_2_iterator *iter = (struct brief_list_2_iterator*) data;
  xfree(iter->filter);
  xfree(iter);
}

static struct ptr_iterator brief_list_2_iterator_funcs =
{
  brief_list_2_iterator_has_next_func,
  brief_list_2_iterator_get_func,
  brief_list_2_iterator_next_func,
  brief_list_2_iterator_destroy_func,
};

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

  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct brief_list_2_iterator *iter;

  if (offset < 0) offset = 0;
  if (count < 0) count = 0;
  if (offset + count < 0) count = 0;

  XCALLOC(iter, 1);
  iter->b = brief_list_2_iterator_funcs;
  iter->state = state;
  iter->contest_id = contest_id;
  iter->group_id = group_id;
  if (filter) iter->filter = xstrdup(filter);
  iter->offset = offset;
  iter->count = count;
  iter->user_id = 0;
  return (ptr_iterator_t) iter;
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
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  int i;
  long long count = 0;

  for (i = 0; i < state->userlist->user_map_size; ++i) {
    if (state->userlist->user_map[i]) {
      ++count;
    }
  }

  if (p_count) *p_count = count;
  return 0;
}

struct group_iterator_2
{
  struct ptr_iterator b;

  struct uldb_xml_state *state;
  unsigned char *filter;
  int offset;
  int count;

  int group_id;
};

static int
group_iterator_2_has_next_func(ptr_iterator_t data)
{
  struct group_iterator_2 *iter = (struct group_iterator_2 *) data;
  struct userlist_list *ul;

  if (!iter->state || !(ul = iter->state->userlist)) return 0;
  if (ul->group_map_size <= 0 || iter->count <= 0) return 0;
  return iter->group_id < ul->group_map_size;
}
static const void *
group_iterator_2_get_func(ptr_iterator_t data)
{
  struct group_iterator_2 *iter = (struct group_iterator_2 *) data;
  struct userlist_list *ul;

  if (!iter->state || !(ul = iter->state->userlist)) return 0;
  if (ul->group_map_size <= 0 || iter->count <= 0) return 0;
  if (iter->group_id >= ul->group_map_size) return NULL;
  return ul->group_map[iter->group_id];
}
static void
group_iterator_2_next_func(ptr_iterator_t data)
{
  struct group_iterator_2 *iter = (struct group_iterator_2 *) data;
  struct userlist_list *ul;

  if (!iter->state || !(ul = iter->state->userlist)) return;
  if (ul->group_map_size <= 0 || iter->count <= 0) return;
  if (iter->group_id >= ul->group_map_size) return;
  --iter->count; ++iter->group_id;
  while (iter->group_id < ul->group_map_size && !ul->group_map[iter->group_id]) {
    ++iter->group_id;
  }
}
static void
group_iterator_2_destroy_func(ptr_iterator_t data)
{
  struct group_iterator_2 *iter = (struct group_iterator_2 *) data;
  xfree(iter->filter);
  xfree(iter);
}

static struct ptr_iterator group_iterator_2_funcs =
{
  group_iterator_2_has_next_func,
  group_iterator_2_get_func,
  group_iterator_2_next_func,
  group_iterator_2_destroy_func,
};

static ptr_iterator_t
get_group_iterator_2_func(
        void *data,
        const unsigned char *filter,
        int offset,
        int count)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct group_iterator_2 *iter = 0;
  const struct userlist_list *ul = state->userlist;

  if (offset < 0) offset = 0;
  if (count < 0) count = 0;

  XCALLOC(iter, 1);
  iter->b = group_iterator_2_funcs;
  iter->state = state;
  iter->filter = xstrdup(filter);
  iter->offset = offset;
  iter->count = count;
  iter->group_id = 0;

  if (ul->group_map_size > 0 || iter->count > 0) {
    while (iter->group_id < ul->group_map_size && !ul->group_map[iter->group_id]) {
      ++iter->group_id;
    }
    while (iter->offset > 0 && iter->group_id < ul->group_map_size && ul->group_map[iter->group_id]) {
      --iter->offset;
      ++iter->group_id;
      while (iter->group_id < ul->group_map_size && !ul->group_map[iter->group_id]) {
        ++iter->group_id;
      }
    }
  }

  return (ptr_iterator_t) iter;
}

static int
get_group_count_func(
        void *data,
        const unsigned char *filter,
        long long *p_count)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  int i;
  long long count = 0;

  for (i = 0; i < state->userlist->group_map_size; ++i) {
    if (state->userlist->group_map[i]) {
      ++count;
    }
  }

  if (p_count) *p_count = count;
  return 0;
}

static int
check_user_match(const struct userlist_user *u, int contest_id, int group_id, const unsigned char *filter)
{
  const struct xml_tree *t;
  const struct userlist_contest *c;
  const struct userlist_groupmember *m;

  if (!u) return 0;
  if (contest_id > 0) {
    if (!u->contests) return 0;
    for (t = u->contests->first_down; t; t = t->right) {
      c = (const struct userlist_contest*) t;
      if (c->id == contest_id) {
        break;
      }
    }
    if (!t) return 0;
  }
  if (group_id > 0) {
    if (!u->group_first) return 0;
    for (t = u->group_first; t; t = m->group_next) {
      m = (const struct userlist_groupmember*) t;
      if (m->group_id == group_id) break;
    }
    if (!t) return 0;
  }

  return 1;
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
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;

  if (user_id > ul->user_map_size) user_id = ul->user_map_size;
  for (--user_id;
       user_id > 0 && !check_user_match(ul->user_map[user_id], contest_id, group_id, filter);
       --user_id) {
  }

  if (p_user_id) *p_user_id = user_id;
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
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;

  if (user_id < 0) user_id = 0;
  for (++user_id;
       user_id < ul->user_map_size && !check_user_match(ul->user_map[user_id], contest_id, group_id, filter);
       ++user_id) {
  }
  if (user_id >= ul->user_map_size) user_id = 0;

  if (p_user_id) *p_user_id = user_id;
  return 0;
}

static int
get_client_key_func(
        void *data,
        ej_cookie_t client_key,
        const struct userlist_cookie **p_cookie)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  const struct userlist_cookie *c = 0;

  if (!ul->client_key_hash_table) return -1;
  int i = client_key % ul->client_key_hash_size;
  while ((c = ul->client_key_hash_table[i]) && c->client_key != client_key) {
    i = (i + ul->client_key_hash_step) % ul->client_key_hash_size;
  }

  if (c) {
    if (p_cookie) *p_cookie = c;
    return 0;
  } else {
    if (p_cookie) *p_cookie = 0;
    return -1;
  }
}
