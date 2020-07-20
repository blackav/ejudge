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

#define FAIL(s, ...) do { snprintf(errbuf, sizeof(errbuf), s, ## __VA_ARGS__); goto fail; } while (0)

struct user_info_container
{
  struct xml_tree b;
  int user_id;
  int contest_id;
  struct userlist_user_info *ui;
  struct user_info_container *next, *prev;
  struct user_info_container *next_user, *prev_user;
};
struct user_info_user
{
  struct user_info_container *first_user, *last_user;
  int min_id, max_id;           // [min_id, max_id) - contest_id
};

static void
do_remove_user_info_from_pool(
        struct user_info_cache *ic,
        struct user_info_container *pp)
{
  struct user_info_user *uiu;
  struct user_info_container *qq = 0;

  if (!pp) return;
  ASSERT(pp->user_id > 0 && pp->user_id < ic->size);
  uiu = &ic->user_map[pp->user_id];

  UNLINK_FROM_LIST(pp, uiu->first_user, uiu->last_user, prev_user, next_user);
  UNLINK_FROM_LIST(pp, ic->first, ic->last, prev, next);
  CALCULATE_RANGE(uiu->min_id, uiu->max_id, uiu->first_user, contest_id, next_user, qq);
  userlist_free(&pp->ui->b);
  pp->ui = 0;
  xfree(pp);
  ic->count--;
}

static struct userlist_user_info *
get_user_info_from_pool(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id)
{
  struct user_info_cache *ic = &state->user_infos;
  struct user_info_user *uiu;
  struct user_info_container *pp = 0;

  ASSERT(user_id > 0);
  ASSERT(contest_id >= 0);

  if (user_id >= ic->size) return 0;
  uiu = &ic->user_map[user_id];

  if (contest_id < uiu->min_id || contest_id >= uiu->max_id) return 0;
  for (pp = uiu->first_user; pp; pp = pp->next_user)
    if (pp->contest_id == contest_id)
      break;
  if (!pp) return 0;
  MOVE_TO_FRONT(pp, ic->first, ic->last, prev, next);
  MOVE_TO_FRONT(pp, uiu->first_user, uiu->last_user, prev_user, next_user);
  return pp->ui;
}

static struct userlist_user_info *
allocate_user_info_on_pool(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id)
{
  struct user_info_cache *ic = &state->user_infos;
  struct user_info_user *uiu;
  struct user_info_container *pp = 0;

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

    MOVE_TO_FRONT(pp, ic->first, ic->last, prev, next);
    MOVE_TO_FRONT(pp, uiu->first_user, uiu->last_user, prev_user, next_user);
    return pp->ui;
  }

  if (ic->count == USER_INFO_POOL_SIZE) {
    do_remove_user_info_from_pool(ic, ic->last);
  }

  XCALLOC(pp, 1);
  pp->ui = (struct userlist_user_info*)userlist_node_alloc(USERLIST_T_CNTSINFO);
  pp->ui->b.tag = USERLIST_T_CNTSINFO;
  pp->user_id = user_id;
  pp->contest_id = contest_id;
  ic->count++;
  UPDATE_RANGE(uiu->min_id, uiu->max_id, uiu->first_user, contest_id);
  LINK_FIRST(pp, ic->first, ic->last, prev, next);
  LINK_FIRST(pp, uiu->first_user, uiu->last_user, prev_user, next_user);
  return pp->ui;
}

static void
remove_user_info_from_pool(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id)
{
  struct user_info_cache *ic = &state->user_infos;
  struct user_info_user *uiu;
  struct user_info_container *pp = 0;

  if (user_id <= 0 || user_id >= ic->size) return;
  uiu = &ic->user_map[user_id];
  if (!uiu) return;
  if (contest_id < uiu->min_id || contest_id >= uiu->max_id) return;
  for (pp = uiu->first_user; pp; pp = pp->next_user)
    if (pp->contest_id == contest_id)
      break;
  do_remove_user_info_from_pool(ic, pp);
}

static void
remove_user_info_from_pool_by_uid(
        struct uldb_mysql_state *state,
        int user_id)
{
  struct user_info_cache *ic = &state->user_infos;
  struct user_info_container *pp = 0, *qq;

  if (user_id <= 0 || user_id >= ic->size) return;
  for (pp = ic->user_map[user_id].first_user; pp; pp = qq) {
    qq = pp->next_user;
    do_remove_user_info_from_pool(ic, pp);
  }
}

static int
parse_user_info(
        struct uldb_mysql_state *state,
        int field_count,
        char **row,
        unsigned long *lengths,
        struct userlist_user_info *ui)
{
  int user_id = 0;
  char errbuf[1024];

  if (state->mi->parse_spec(state->md, field_count, row, lengths,
                            USER_INFO_WIDTH, user_info_spec, ui,
                            &user_id) < 0) {
    goto fail;
  }
  if (user_id <= 0) FAIL("user_id <= 0");
  if (ui->contest_id < 0) FAIL("contest_id < 0");
  if (ui->instnum < -1) FAIL("instnum < -1");
  if (ui->team_passwd_method < 0 || ui->team_passwd_method >= USERLIST_PWD_LAST)
    FAIL("pwdmethod is out of range");
  return 0;

 fail:
  return -1;
}

static void
unparse_user_info(
        struct uldb_mysql_state *state,
        FILE *fout,
        int user_id,
        const struct userlist_user_info *ui)
{
  state->mi->unparse_spec(state->md, fout, USER_INFO_WIDTH, user_info_spec, ui,
                          user_id);
}

static int
fetch_user_info(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id,
        struct userlist_user_info **p_ui)
{
  unsigned char cmdbuf[1024];
  int cmdlen;
  struct userlist_user_info *ui = 0;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;

  ASSERT(user_id > 0);
  ASSERT(contest_id >= 0);

  if (p_ui) *p_ui = 0;
  if (state->cache_queries
      && (ui = get_user_info_from_pool(state, user_id, contest_id))) {
    if (p_ui) *p_ui = ui;
    return 1;
  }

  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT * FROM %susers WHERE user_id = %d AND contest_id = %d ;",
           md->table_prefix, user_id, contest_id);
  cmdlen = strlen(cmdbuf);
  if (mi->simple_query(md, cmdbuf, cmdlen) < 0) goto fail;
  if ((md->field_count = mysql_field_count(md->conn)) != USER_INFO_WIDTH)
    db_error_field_count_fail(md, USER_INFO_WIDTH);
  if (!(md->res = mysql_store_result(md->conn)))
    db_error_fail(md);
  md->row_count = mysql_num_rows(md->res);
  if (md->row_count < 0) goto fail;
  if (!md->row_count) {
    mi->free_res(md);
    if (p_ui) *p_ui = 0;
    return 0;
  }
  if (md->row_count > 1) {
    err("fetch_user_info: too many rows in result");
    goto fail;
  }

  ui = allocate_user_info_on_pool(state, user_id, contest_id);
  if (!(md->row = mysql_fetch_row(md->res)))
    db_error_no_data_fail(md);
  md->lengths = mysql_fetch_lengths(md->res);
  if (parse_user_info(state, md->field_count, md->row, md->lengths, ui) < 0)
    goto fail;

  mi->free_res(md);
  if (p_ui) *p_ui = ui;
  return 1;

 fail:
  mi->free_res(md);
  remove_user_info_from_pool(state, user_id, contest_id);
  return -1;
}

static int
fetch_or_create_user_info(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id,
        struct userlist_user_info **p_ui)
{
  struct userlist_user_info *ui = 0;
  struct userlist_user_info arena;
  time_t cur_time;
  FILE *cmd_f = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;

  if (fetch_user_info(state, user_id, contest_id, &ui) < 0) goto fail;
  if (ui) {
    if (p_ui) *p_ui = ui;
    return 1;
  }

  cur_time = time(0);
  memset(&arena, 0, sizeof(arena));
  arena.contest_id = contest_id;
  arena.instnum = -1;
  arena.create_time = cur_time;
  arena.last_change_time = cur_time;
  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %susers VALUES ( ", md->table_prefix);
  unparse_user_info(state, cmd_f, user_id, &arena);
  fprintf(cmd_f, " ) ;");
  close_memstream(cmd_f); cmd_f = 0;
  if (mi->simple_query(md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  if (fetch_user_info(state, user_id, contest_id, &ui) < 0) goto fail;
  ASSERT(ui);
  if (p_ui) *p_ui = ui;
  return 1;

 fail:
  remove_user_info_from_pool(state, user_id, contest_id);
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

#undef FAIL

static void
drop_user_info_cache(struct uldb_mysql_state *state)
{
  struct user_info_container *p, *q;

  for (p = state->user_infos.first; p; p = q) {
    q = p->next;
    do_remove_user_info_from_pool(&state->user_infos, p);
  }
}
