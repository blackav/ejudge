/* -*- mode: c -*- */

/* Copyright (C) 2008-2016 Alexander Chernov <cher@ejudge.ru> */

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

static void
do_remove_login_from_pool(
        struct users_cache *uc,
        struct userlist_user *u)
{
  struct xml_tree *u_xml = (struct xml_tree*) u;

  if (!u) return;
  ASSERT(u->id > 0 && u->id < uc->size);

  uc->user_map[u->id] = 0;
  UNLINK_FROM_LIST(u_xml, uc->first, uc->last, left, right);
  // don't even try to free nested cntsregs and cookies
  if (u->contests) {
    u->contests->first_down = u->contests->last_down = 0;
  }
  if (u->cookies) {
    u->cookies->first_down = u->cookies->last_down = 0;
  }
  userlist_free(u_xml);
  uc->count--;
}

static struct userlist_user *
get_login_from_pool(
        struct uldb_mysql_state *state,
        int user_id)
{
  struct users_cache *uc = &state->users;
  struct userlist_user *u;
  struct xml_tree *u_xml;

  if (user_id <= 0 || user_id >= uc->size) return 0;
  if (!(u = uc->user_map[user_id])) return 0;
  u_xml = (struct xml_tree*) u;
  MOVE_TO_FRONT(u_xml, uc->first, uc->last, left, right);
  return u;
}

static struct userlist_user *
allocate_login_on_pool(
        struct uldb_mysql_state *state,
        int user_id)
{
  struct users_cache *uc = &state->users;
  struct userlist_user *u;
  struct xml_tree *u_xml, *l, *r;

  if (user_id <= 0) return 0;
  if (user_id > EJ_MAX_USER_ID) return 0;

  if (user_id >= uc->size) {
    int new_size = uc->size;
    struct userlist_user **new_map;

    if (!new_size) new_size = 1024;
    while (user_id >= new_size) new_size *= 2;
    XCALLOC(new_map, new_size);
    if (uc->size > 0)
      memcpy(new_map, uc->user_map, uc->size * sizeof(uc->user_map[0]));
    xfree(uc->user_map);
    uc->size = new_size;
    uc->user_map = new_map;
  }

  if ((u = uc->user_map[user_id])) {
    // don't even try to free nested cntsregs and cookies
    if (u->contests) {
      u->contests->first_down = u->contests->last_down = 0;
    }
    if (u->cookies) {
      u->cookies->first_down = u->cookies->last_down = 0;
    }
    u_xml = (struct xml_tree*) u;
    l = u_xml->left;
    r = u_xml->right;
    userlist_elem_free_data(u_xml);
    u->id = user_id;
    u_xml->left = l;
    u_xml->right = r;

    MOVE_TO_FRONT(u_xml, uc->first, uc->last, left, right);
    return u;
  }

  if (uc->count == USERS_POOL_SIZE) {
    do_remove_login_from_pool(uc, (struct userlist_user*) uc->last);
  }

  u = (struct userlist_user*) userlist_node_alloc(USERLIST_T_USER);
  u->id = user_id;
  u_xml = (struct xml_tree*) u;
  LINK_FIRST(u_xml, uc->first, uc->last, left, right);
  uc->user_map[user_id] = u;
  uc->count++;
  return u;
}

static void
remove_login_from_pool(
        struct uldb_mysql_state *state,
        int user_id)
{
  struct users_cache *uc = &state->users;

  if (user_id <= 0 || user_id >= uc->size) return;
  do_remove_login_from_pool(uc, uc->user_map[user_id]);
}

static int
parse_login(
        struct uldb_mysql_state *state,
        int field_count,
        char **row,
        unsigned long *lengths,
        struct userlist_user *u)
{
  if (state->mi->parse_spec(state->md, field_count,row,lengths,LOGIN_WIDTH,login_spec,u) < 0)
    goto fail;
  if (u->id <= 0) goto fail;
  if (u->passwd_method < USERLIST_PWD_PLAIN
      || u->passwd_method > USERLIST_PWD_LAST)
    goto fail;
  if (!u->login || !*u->login) goto fail;
  return 0;

 fail:
  return -1;
}

static void
unparse_login(
        struct uldb_mysql_state *state,
        FILE *fout,
        const struct userlist_user *u)
{
  state->mi->unparse_spec(state->md, fout, LOGIN_WIDTH, login_spec, u);
}

static int
fetch_login(
        struct uldb_mysql_state *state,
        int user_id,
        struct userlist_user **p_user)
{
  unsigned char cmdbuf[1024];
  int cmdlen;
  struct userlist_user *u = 0;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;

  *p_user = 0;
  if (user_id <= 0) goto fail;

  if (state->cache_queries && (u = get_login_from_pool(state, user_id))) {
    *p_user = u;
    return 1;
  }

  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT * FROM %slogins WHERE user_id = %d ;",
           md->table_prefix, user_id);
  cmdlen = strlen(cmdbuf);
  if (mi->simple_query(md, cmdbuf, cmdlen) < 0) goto fail;
  md->field_count = mysql_field_count(md->conn);
  if (md->field_count != LOGIN_WIDTH)
    db_error_field_count_fail(md, LOGIN_WIDTH);
  if (!(md->res = mysql_store_result(md->conn)))
    db_error_fail(md);
  md->row_count = mysql_num_rows(md->res);
  if (md->row_count < 0) db_error_fail(md);
  if (!md->row_count) {
    mi->free_res(md);
    return 0;
  }
  if (md->row_count > 1) goto fail;
  if (!(md->row = mysql_fetch_row(md->res)))
    db_error_no_data_fail(md);
  md->lengths = mysql_fetch_lengths(md->res);
  if (!(u = allocate_login_on_pool(state, user_id))) goto fail;
  if (parse_login(state, md->field_count, md->row, md->lengths, u) < 0)
    goto fail;
  mi->free_res(md);
  *p_user = u;
  return 1;

 fail:
  mi->free_res(md);
  remove_login_from_pool(state, user_id);
  return -1;
}

static void
drop_login_cache(struct uldb_mysql_state *state)
{
  int i;

  for (i = 1; i < state->users.size; i++)
    do_remove_login_from_pool(&state->users, state->users.user_map[i]);
}
