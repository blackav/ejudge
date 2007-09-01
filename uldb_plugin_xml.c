/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "uldb_plugin.h"
#include "errlog.h"
#include "pathutl.h"
#include "ejudge_cfg.h"
#include "userlist.h"
#include "random.h"
#include "misctext.h"

#include <reuse/xalloc.h>
#include <reuse/osdeps.h>
#include <reuse/logger.h>

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <zlib.h>

// default interval to flush changes, in seconds
#define DEFAULT_FLUSH_INTERVAL 600
#define DEFAULT_BACKUP_INTERVAL (24*60*60)

static void *init_func(const struct ejudge_cfg *);
static int parse_func(void *, const struct ejudge_cfg *,struct xml_tree *);
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
                         const unsigned char *reg_passwd,
                         int simple_reg_flag);
static int remove_user_func(void *, int);
static int get_cookie_func(void *, ej_cookie_t,
                           const struct userlist_cookie **);
static int new_cookie_func(void *, int, ej_ip_t, int, ej_cookie_t, time_t,
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
static int get_user_info_4_func(void *, int, int,
                                const struct userlist_user **);
static int get_user_info_5_func(void *, int, int,
                                const struct userlist_user **);
static ptr_iterator_t get_brief_list_iterator_func(void *, int);
static ptr_iterator_t get_standings_list_iterator_func(void *, int);
static int check_user_func(void *, int);
static int set_reg_passwd_func(void *, int, int, const unsigned char *, time_t);
static int set_team_passwd_func(void *, int, int, int, const unsigned char *, time_t, int *);
static int register_contest_func(void *, int, int, int, time_t, const struct userlist_contest **);
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
static int change_member_role_func(void *, int, int, int, int, time_t, int *);
static int set_user_xml_func(void *, int, int, struct userlist_user *,
                             time_t, int *);
static int copy_user_info_func(void *, int, int, int, time_t,
                               const struct contest_desc *);
static int check_user_reg_data_func(void *, int, int);
static int move_member_func(void *, int, int, int, int, time_t, int *);

struct uldb_plugin_iface uldb_plugin_xml =
{
  {
    sizeof (struct uldb_plugin_iface),
    EJUDGE_PLUGIN_IFACE_VERSION,
    "userdb",
    "uldb_xml",
  },

  ULDB_PLUGIN_IFACE_VERSION,

  init_func,
  parse_func,
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
  change_member_role_func,
  set_user_xml_func,
  copy_user_info_func,
  check_user_reg_data_func,
  move_member_func,
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

static void *
init_func(const struct ejudge_cfg *ej_cfg)
{
  struct uldb_xml_state *state;

  XCALLOC(state, 1);
  return (void*) state;
}

static int
parse_func(void *data, const struct ejudge_cfg *ej_cfg,struct xml_tree *t)
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
new_user_func(void *data,
              const unsigned char *login,
              const unsigned char *email,
              const unsigned char *reg_passwd,
              int simple_reg_flag)
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
  u->simple_registration = simple_reg_flag;
  u->i.name = xstrdup("");

  if (reg_passwd) {
    u->passwd = xstrdup(reg_passwd);
    u->passwd_method = USERLIST_PWD_PLAIN;
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
get_cookie_func(void *data,
                ej_cookie_t value,
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

  if (c) {
    if (p_cookie) *p_cookie = c;
    return 0;
  } else {
    if (p_cookie) *p_cookie = 0;
    return -1;
  }
}

static int
new_cookie_func(void *data,
                int user_id,
                ej_ip_t ip, int ssl_flag,
                ej_cookie_t value, time_t expire,
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
    if (get_cookie_func(data, value, 0) >= 0) return -1;
  } else {
    // generate a random unique value
    while (1) {
      if (!(value = random_u64())) continue;
      if (get_cookie_func(data, value, 0) < 0) break;
    }
  }

  if (!expire) expire = time(0) + 24 * 60 * 60;

  if (!(cs = u->cookies)) {
    u->cookies = cs = userlist_node_alloc(USERLIST_T_COOKIES);
    xml_link_node_last(&u->b, cs);
  }

  c = (struct userlist_cookie*) userlist_node_alloc(USERLIST_T_COOKIE);
  c->user_id = user_id;
  c->ip = ip;
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
  struct userlist_cntsinfo *ci;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);
  u->last_login_time = cur_time;
  if (contest_id > 0) {
    ci = userlist_clone_user_info(u, contest_id, &ul->member_serial, cur_time,
                                  0);
    if (ci) ci->i.last_login_time = cur_time;
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
  struct userlist_cntsinfo *ci;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  if (contest_id > 0) {
    ci = userlist_clone_user_info(u, contest_id, &ul->member_serial, cur_time,
                                  p_cloned_flag);
    ui = &ci->i;
  } else {
    ui = &u->i;
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
  c->date = cur_time;

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
  struct userlist_cntsinfo *ci;
  struct userlist_members *mm;
  struct userlist_member *m;
  int i, role, num = -1;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  if (contest_id > 0) {
    ci = userlist_clone_user_info(u, contest_id, &ul->member_serial, cur_time,
                                  p_cloned_flag);
    ui = &ci->i;
  } else {
    ui = &u->i;
  }

  /*
    as a result of cloning a new member may be created.
    its serial is storied in copied_from field.
   */

  // find a member by serial
  for (role = 0; role < USERLIST_MB_LAST; role++) {
    if (!(mm = ui->members[role])) continue;
    for (num = 0; num < mm->total; num++) {
      m = mm->members[num];
      if (m->serial == serial || m->copied_from == serial) break;
    }
    if (num < mm->total) break;
  }
  if (role == USERLIST_MB_LAST) return -1;

  if (role < 0 || role >= USERLIST_MB_LAST) return -1;
  if (!(mm = ui->members[role])) return -1;
  if (num < 0 || num >= mm->total) return -1;
  m = mm->members[num];
  if (m->serial != serial && m->copied_from != serial) return -1;

  xml_unlink_node(&m->b);
  userlist_free(&m->b);
  for (i = num + 1; i < mm->total; i++)
    mm->members[i - 1] = mm->members[i];
  mm->total--;
  if (!mm->total) {
    xml_unlink_node(&mm->b);
    ui->members[role] = 0;
    userlist_free(&mm->b);
  }

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
  if (ui->cnts_read_only) return 1;
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
  struct userlist_cntsinfo *ci;
  time_t cur_time = time(0);

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }

  if (contest_id > 0) {
    ci = userlist_clone_user_info(u, contest_id, &ul->member_serial, cur_time,
                                  p_cloned_flag);
    ui = &ci->i;
  } else {
    ui = &u->i;
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
  struct userlist_cntsinfo *uc;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }

  // no contest info
  if (contest_id <= 0 || contest_id >= u->cntsinfo_a
      || !(uc = u->cntsinfo[contest_id])) return 0;

  xml_unlink_node(&uc->b);
  userlist_free(&uc->b);
  u->cntsinfo[contest_id] = 0;

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
  struct userlist_cntsinfo *ci;
  struct userlist_user_info *ui;
  int r;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  ui = userlist_get_user_info_nc(u, contest_id);
  if (userlist_is_empty_user_info_field(ui, field_id)) return 0;

  if (contest_id > 0) {
    if (!(ci = userlist_clone_user_info(u, contest_id, &ul->member_serial,
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
  struct userlist_cntsinfo *ci;
  struct userlist_user_info *ui;
  struct userlist_member *m;
  int r;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  ui = userlist_get_user_info_nc(u, contest_id);
  if (!(m = userlist_get_member_nc(ui, serial, 0, 0))) return -1;
  if (userlist_is_empty_member_field(m, field_id)) return 0;

  if (contest_id > 0) {
    if (!(ci = userlist_clone_user_info(u, contest_id, &ul->member_serial,
                                        cur_time, p_cloned_flag)))
      return -1;
    ui = userlist_get_user_info_nc(u, contest_id);
    m = userlist_get_member_nc(ui, serial, 0, 0);
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
  struct userlist_cntsinfo *ci;
  int r;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  if (!(ui = userlist_get_user_info_nc(u, contest_id))) return -1;
  if (userlist_is_equal_user_info_field(ui, field_id, value)) return 0;

  if (contest_id > 0) {
    if (!(ci = userlist_clone_user_info(u, contest_id, &ul->member_serial,
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
  struct userlist_cntsinfo *ci;
  struct userlist_user_info *ui;
  struct userlist_member *m;
  int r;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  ui = userlist_get_user_info_nc(u, contest_id);
  if (!(m = userlist_get_member_nc(ui, serial, 0, 0))) return -1;
  if (userlist_is_equal_member_field(m, field_id, value)) return 0;

  if (contest_id > 0) {
    if (!(ci = userlist_clone_user_info(u, contest_id, &ul->member_serial,
                                        cur_time, p_cloned_flag)))
      return -1;
    ui = userlist_get_user_info_nc(u, contest_id);
    m = userlist_get_member_nc(ui, serial, 0, 0);
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
  struct userlist_cntsinfo *ci;
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
    link_node = &u->b;
  }
  ui = userlist_get_user_info_nc(u, contest_id);

  if (!ui->members[role]) {
    mm = (struct userlist_members*) userlist_node_alloc(USERLIST_T_CONTESTANTS + role);
    mm->role = role;
    xml_link_node_last(link_node, &mm->b);
    ui->members[role] = mm;
  }
  mm = ui->members[role];

  m = (struct userlist_member*) userlist_node_alloc(USERLIST_T_MEMBER);
  m->serial = ul->member_serial++;
  m->create_time = m->last_change_time = cur_time;
  xml_link_node_last(&mm->b, &m->b);

  if (mm->total >= mm->allocd) {
    if (!mm->allocd) mm->allocd = 2;
    mm->allocd *= 2;
    XREALLOC(mm->members, mm->allocd);
  }
  mm->members[mm->total++] = m;

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
  if (fclose(f) < 0) {
    failed_function = "fclose";
    goto cleanup;
  }
  f = 0;

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
change_member_role_func(void *data, int user_id, int contest_id, int serial,
                        int new_role, time_t cur_time, int *p_cloned_flag)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  struct userlist_cntsinfo *ci;
  struct userlist_user_info *ui;
  struct userlist_member *m;
  struct userlist_members *mm, *old_mm;
  struct xml_tree *link_node;
  int old_role = 0, old_num = 0, i;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);
  ASSERT(new_role >= 0 && new_role < CONTEST_LAST_MEMBER);

  if (!(ui = userlist_get_user_info_nc(u, contest_id))) return -1;
  if (!(m = userlist_get_member_nc(ui, serial, &old_role, &old_num)))
    return -1;
  if (old_role == new_role) return 0;

  if (contest_id > 0) {
    ci = userlist_clone_user_info(u, contest_id, &ul->member_serial, cur_time,
                                  p_cloned_flag);
    if (!ci) return -1;
    link_node = &ci->b;
  } else {
    link_node = &u->b;
  }
  ui = userlist_get_user_info_nc(u, contest_id);

  if (!ui->members[new_role]) {
    mm = (struct userlist_members*) userlist_node_alloc(USERLIST_T_CONTESTANTS + new_role);
    mm->role = new_role;
    xml_link_node_last(link_node, &mm->b);
    ui->members[new_role] = mm;
  }
  mm = ui->members[new_role];

  // remove member from the old location
  old_mm = ui->members[old_role];
  ASSERT(old_mm);
  m = userlist_get_member_nc(ui, serial, 0, 0);
  ASSERT(m);
  ASSERT(m->b.up == &old_mm->b);
  ASSERT(old_num < old_mm->total && old_mm->members[old_num] == m);
  xml_unlink_node(&m->b);
  for (i = old_num + 1; i < old_mm->total; i++)
    old_mm->members[i - 1] = old_mm->members[i];
  old_mm->total--;
  old_mm->members[old_mm->total] = 0;

  // insert member to the new location
  if (mm->total >= mm->allocd) {
    if (!mm->allocd) mm->allocd = 2;
    mm->allocd *= 2;
    XREALLOC(mm->members, mm->allocd);
  }
  mm->members[mm->total++] = m;

  state->dirty = 1;
  state->flush_interval /= 2;
  return 1;
}

static int
count_members(const struct userlist_user_info *ui)
{
  int count = 0, role;
  struct userlist_members *mm;

  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (!(mm = ui->members[role])) continue;
    count += mm->total;
  }
  return count;
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
  struct userlist_cntsinfo *ci;
  struct userlist_user_info *ui;
  int nrole, nnum, orole, onum;
  struct userlist_members *nmm, *omm;
  struct userlist_member *nm, *om, *oom;
  struct userlist_member **handled_members;
  int handled_members_count, handled_members_size;
  int new_serial, i;

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
    ci = userlist_clone_user_info(u, contest_id, &ul->member_serial, cur_time,
                                  p_cloned_flag);
    if (!ci) return -1;
  }
  if (!(ui = userlist_get_user_info_nc(u, contest_id))) return -1;

  // set fields from new_u->i to ui
  // update the user's fields
  if (needs_name_update(ui->name, new_u->i.name)) {
    xfree(ui->name);
    ui->name = xstrdup(new_u->i.name);
  }
  if (needs_update(ui->homepage, new_u->i.homepage)) {
    xfree(ui->homepage);
    ui->homepage = xstrdup(new_u->i.homepage);
  }
  if (needs_update(ui->phone, new_u->i.phone)) {
    xfree(ui->phone);
    ui->phone = xstrdup(new_u->i.phone);
  }
  if (needs_update(ui->inst, new_u->i.inst)) {
    xfree(ui->inst);
    ui->inst = xstrdup(new_u->i.inst);
  }
  if (needs_update(ui->inst_en, new_u->i.inst_en)) {
    xfree(ui->inst_en);
    ui->inst_en = xstrdup(new_u->i.inst_en);
  }
  if (needs_update(ui->instshort, new_u->i.instshort)) {
    xfree(ui->instshort);
    ui->instshort = xstrdup(new_u->i.instshort);
  }
  if (needs_update(ui->instshort_en, new_u->i.instshort_en)) {
    xfree(ui->instshort_en);
    ui->instshort_en = xstrdup(new_u->i.instshort_en);
  }
  if (needs_update(ui->fac, new_u->i.fac)) {
    xfree(ui->fac);
    ui->fac = xstrdup(new_u->i.fac);
  }
  if (needs_update(ui->fac_en, new_u->i.fac_en)) {
    xfree(ui->fac_en);
    ui->fac_en = xstrdup(new_u->i.fac_en);
  }
  if (needs_update(ui->facshort, new_u->i.facshort)) {
    xfree(ui->facshort);
    ui->facshort = xstrdup(new_u->i.facshort);
  }
  if (needs_update(ui->facshort_en, new_u->i.facshort_en)) {
    xfree(ui->facshort_en);
    ui->facshort_en = xstrdup(new_u->i.facshort_en);
  }
  if (needs_update(ui->city, new_u->i.city)) {
    xfree(ui->city);
    ui->city = xstrdup(new_u->i.city);
  }
  if (needs_update(ui->city_en, new_u->i.city_en)) {
    xfree(ui->city_en);
    ui->city_en = xstrdup(new_u->i.city_en);
  }
  if (needs_update(ui->country, new_u->i.country)) {
    xfree(ui->country);
    ui->country = xstrdup(new_u->i.country);
  }
  if (needs_update(ui->country_en, new_u->i.country_en)) {
    xfree(ui->country_en);
    ui->country_en = xstrdup(new_u->i.country_en);
  }
  if (needs_update(ui->region, new_u->i.region)) {
    xfree(ui->region);
    ui->region = xstrdup(new_u->i.region);
  }
  if (needs_update(ui->languages, new_u->i.languages)) {
    xfree(ui->languages);
    ui->languages = xstrdup(new_u->i.languages);
  }

  /* change members */
  handled_members_size = count_members(ui) + count_members(&new_u->i) + 8;
  XALLOCAZ(handled_members, handled_members_size);
  handled_members_count = 0;

  // create new members and move the existing ones
  for (nrole = 0; nrole < CONTEST_LAST_MEMBER; nrole++) {
    if (!(nmm = new_u->i.members[nrole])) continue;
    for (nnum = 0; nnum < nmm->total; nnum++) {
      nm = nmm->members[nnum];
      ASSERT(nm);
      if (nm->serial <= 0) {
        // create new member
        new_serial = new_member_func(data, user_id, contest_id, nrole,
                                     cur_time, 0);
        if (new_serial <= 0) return -1;
        nm->serial = new_serial;
      }
      om = userlist_get_member_nc(ui, nm->serial, &orole, &onum);
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
        if (change_member_role_func(data, user_id, contest_id, om->serial,
                                    nrole, cur_time, 0) < 0) return -1;
        oom = userlist_get_member_nc(ui, nm->serial, &orole, &onum);
        ASSERT(oom == om);
        ASSERT(orole == nrole);
      }
      handled_members[handled_members_count++] = om;
    }
  }

  // check the members for removal
  while (1) {
    for (orole = 0; orole < CONTEST_LAST_MEMBER; orole++) {
      if (!(omm = ui->members[orole])) continue;
      for (onum = 0; onum < omm->total; onum++) {
        om = omm->members[onum];
        ASSERT(om);
        ASSERT(om->serial > 0);
        for (i = 0; i < handled_members_count; i++)
          if (handled_members[i] == om)
            break;
        if (i >= handled_members_count) break;
      }
      if (onum < omm->total) break;
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
    if (!(nmm = new_u->i.members[nrole])) continue;
    for (nnum = 0; nnum < nmm->total; nnum++) {
      nm = nmm->members[nnum];
      ASSERT(nm);
      ASSERT(nm->serial > 0);
      ASSERT(i < handled_members_count);
      om = handled_members[i++];
      ASSERT(om);
      ASSERT(nm->serial == om->serial || nm->serial == om->copied_from);

      if (nm->status && om->status != nm->status) {
        om->status = nm->status;
      }
      if (nm->grade && om->grade != nm->grade) {
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
  USERLIST_NC_ZIP,
  USERLIST_NC_STREET,
  USERLIST_NC_LANGUAGES,
  USERLIST_NC_PHONE,

  0
};

static int
copy_user_info_func(void *data, int user_id,
                    int from_cnts, int to_cnts,
                    time_t cur_time, const struct contest_desc *cnts)
{
  struct uldb_xml_state *state = (struct uldb_xml_state*) data;
  struct userlist_list *ul = state->userlist;
  struct userlist_user *u;
  const struct userlist_user_info *ui_from = 0;
  struct userlist_user_info *ui_to;
  int i, j, k;
  unsigned char **p_str_from, **p_str_to;
  struct userlist_members *mm;
  struct userlist_member *m;
  struct userlist_cntsinfo *ci;

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
  if (!(ci = userlist_clone_user_info(u, to_cnts, &ul->member_serial,
                                      cur_time, 0)))
    return -1;
  if (!(ui_to = userlist_get_user_info_nc(u, to_cnts))) return -1;

  xfree(ui_to->name);
  ui_to->name = xstrdup(ui_from->name);
  if (ui_from->team_passwd) {
    xfree(ui_to->team_passwd);
    ui_to->team_passwd = xstrdup(ui_from->team_passwd);
    ui_to->team_passwd_method = ui_from->team_passwd_method;
  }

  for (i = 0; copy_user_general_fields[i] > 0; i++) {
    j = copy_user_general_fields[i];
    k = userlist_map_userlist_to_contest_field(j);
    p_str_to = (unsigned char**) userlist_get_user_info_field_ptr(ui_to, j);
    xfree(*p_str_to); *p_str_to = 0;
    if (cnts && !cnts->fields[k]) continue;
    p_str_from = (unsigned char**) userlist_get_user_info_field_ptr(ui_to, j);
    if (!*p_str_from) continue;
    *p_str_to = xstrdup(*p_str_from);
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
  for (i = 0; i < USERLIST_MB_LAST; i++) {
    if (!(mm = ui_to->members[i])) continue;
    for (j = 0; j < mm->total; j++) {
      if (!(m = mm->members[j])) continue;
      xml_unlink_node(&m->b);
      userlist_free(&m->b);
      mm->members[j] = 0;
    }
    xml_unlink_node(&mm->b);
    userlist_free(&mm->b);
    ui_to->members[i] = 0;
  }

  /*
    copy the member info
   */
  for (i = 0; i < USERLIST_MB_LAST; i++) {
    if (cnts && (!cnts->members[i] || !cnts->members[i]->max_count)) continue;
    if (!ui_from->members[i] || !ui_from->members[i]->total) continue;
    k = ui_from->members[i]->total;
    if (cnts && k > cnts->members[i]->max_count)
      k = cnts->members[i]->max_count;
    mm = (struct userlist_members*) userlist_node_alloc(USERLIST_T_CONTESTANTS + i);
    ui_to->members[i] = mm;
    xml_link_node_last(&ci->b, &mm->b);
    mm->role = ui_from->members[i]->role;
    mm->total = ui_from->members[i]->total;
    j = 4;
    while (j < mm->total) j *= 2;
    mm->allocd = j;
    XCALLOC(mm->members, j);

    for (j = 0; j < k; j++) {
      if (!ui_from->members[i]->members[j]) continue;
      mm->members[j] = userlist_clone_member(ui_from->members[i]->members[j],
                                             &ul->member_serial, cur_time);
      xml_link_node_last(&mm->b, &mm->members[i]->b);
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

  if (contests_get(contest_id, &cnts) < 0 || !cnts)
    return -1;

  if (get_user_info_3_func(data, user_id, contest_id, &u, &ui, &c) < 0)
    return -1;

  if (!c || (c->status != USERLIST_REG_OK && c->status != USERLIST_REG_PENDING))
    return -1;

  nerr = userlist_count_info_errors(cnts, u, ui, memb_errs);
  if (ui->name && *ui->name && check_str(ui->name, name_accept_chars))
    nerr++;

  if (!nerr && (c->flags & USERLIST_UC_INCOMPLETE)) {
    cm = (struct userlist_contest*) c;
    cm->flags &= ~USERLIST_UC_INCOMPLETE;
    state->dirty = 1;
    state->flush_interval /= 2;
    return 1;
  } else if (nerr > 0 && !(c->flags & USERLIST_UC_INCOMPLETE)
             && !ui->cnts_read_only) {
    cm = (struct userlist_contest*) c;
    cm->flags |= USERLIST_UC_INCOMPLETE;
    state->dirty = 1;
    state->flush_interval /= 2;
    return 1;
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
  struct userlist_cntsinfo *ci;
  struct userlist_members *mm;
  struct userlist_member *m;
  int i, role, num = -1;
  struct xml_tree *link_node = 0;

  if (user_id <= 0 || user_id >= ul->user_map_size
      || !(u = ul->user_map[user_id])) {
    return -1;
  }
  if (cur_time <= 0) cur_time = time(0);

  if (contest_id > 0) {
    ci = userlist_clone_user_info(u, contest_id, &ul->member_serial, cur_time,
                                  p_cloned_flag);
    ui = &ci->i;
    link_node = &ci->b;
  } else {
    ui = &u->i;
    link_node = &u->b;
  }

  /*
    as a result of cloning a new member may be created.
    its serial is storied in copied_from field.
   */

  // find a member by serial
  for (role = 0; role < USERLIST_MB_LAST; role++) {
    if (!(mm = ui->members[role])) continue;
    for (num = 0; num < mm->total; num++) {
      m = mm->members[num];
      if (m->serial == serial || m->copied_from == serial) break;
    }
    if (num < mm->total) break;
  }
  if (role == USERLIST_MB_LAST) return -1;

  if (role < 0 || role >= USERLIST_MB_LAST) return -1;
  if (!(mm = ui->members[role])) return -1;
  if (num < 0 || num >= mm->total) return -1;
  m = mm->members[num];
  if (m->serial != serial && m->copied_from != serial) return -1;
  if (role == new_role) return 0;
  if (new_role < 0 || new_role >= CONTEST_LAST_MEMBER) return -1;

  xml_unlink_node(&m->b);
  for (i = num + 1; i < mm->total; i++)
    mm->members[i - 1] = mm->members[i];
  mm->total--;
  if (!mm->total) {
    xml_unlink_node(&mm->b);
    ui->members[role] = 0;
    userlist_free(&mm->b);
  }

  if (!ui->members[new_role]) {
    mm = (struct userlist_members*) userlist_node_alloc(USERLIST_T_CONTESTANTS + new_role);
    mm->role = new_role;
    xml_link_node_last(link_node, &mm->b);
    ui->members[new_role] = mm;
  }
  mm = ui->members[new_role];
  xml_link_node_last(&mm->b, &m->b);

  if (mm->total >= mm->allocd) {
    if (!mm->allocd) mm->allocd = 2;
    mm->allocd *= 2;
    XREALLOC(mm->members, mm->allocd);
  }
  mm->members[mm->total++] = m;

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

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
