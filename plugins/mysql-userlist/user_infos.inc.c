/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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
  struct userlist_cntsinfo *ui;
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
    // FIXME: preserve the old value???
    // or introduce 'nocache' option???
    userlist_elem_free_data(&pp->ui->b);

    MOVE_TO_FRONT(pp, ic->first, ic->last, prev, next);
    MOVE_TO_FRONT(pp, uiu->first_user, uiu->last_user, prev_user, next_user);
    return &pp->ui->i;
  }

  if (ic->count == USER_INFO_POOL_SIZE) {
    do_remove_user_info_from_pool(ic, ic->last);
  }

  XCALLOC(pp, 1);
  pp->ui = (struct userlist_cntsinfo*) userlist_node_alloc(USERLIST_T_CNTSINFO);
  pp->ui->b.tag = USERLIST_T_CNTSINFO;
  pp->user_id = user_id;
  pp->contest_id = contest_id;
  ic->count++;
  UPDATE_RANGE(uiu->min_id, uiu->max_id, uiu->first_user, contest_id);
  LINK_FIRST(pp, ic->first, ic->last, prev, next);
  LINK_FIRST(pp, uiu->first_user, uiu->last_user, prev_user, next_user);
  return &pp->ui->i;
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

static int
parse_user_info(struct uldb_mysql_state *state, struct userlist_user_info *ui)
{
  int user_id = 0, contest_id = -1;
  char errbuf[1024];

  if (handle_parse_spec(state, USER_INFO_WIDTH, user_info_spec, ui,
                        &user_id, &contest_id) < 0)
    goto fail;
  if (user_id <= 0) FAIL("user_id <= 0");
  if (contest_id < 0) FAIL("contest_id < 0");
  if (ui->instnum < 0) FAIL("instnum < 0");
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
        int contest_id,
        const struct userlist_user_info *ui)
{
  handle_unparse_spec(state, fout, USER_INFO_WIDTH, user_info_spec, ui,
                      user_id, contest_id);
}

static int
fetch_user_info(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id,
        struct userlist_user_info **p_ui)
{
  unsigned char cmdbuf[1024];
  int cmdlen = sizeof(cmdbuf);
  struct userlist_user_info *ui = 0;

  cmdlen = snprintf(cmdbuf, cmdlen, "SELECT * FROM %susers WHERE user_id = %d AND contest_id = %d", state->table_prefix, user_id, contest_id);
  if (mysql_real_query(state->conn, cmdbuf, cmdlen))
    db_error_fail(state);
  if ((state->field_count = mysql_field_count(state->conn)) != USER_INFO_WIDTH)
    db_wrong_field_count_fail(state, USER_INFO_WIDTH);
  if (!(state->res = mysql_store_result(state->conn)))
    db_error_fail(state);
  state->row_count = mysql_num_rows(state->res);
  if (state->row_count < 0) goto fail;
  if (!state->row_count) {
    *p_ui = 0;
    return 0;
  }
  if (state->row_count > 1) {
    err("fetch_user_info: too many rows in result");
    goto fail;
  }

  ui = allocate_user_info_on_pool(state, user_id, contest_id);
  if (!(state->row = mysql_fetch_row(state->res)))
    db_no_data_fail();
  state->lengths = mysql_fetch_lengths(state->res);
  if (parse_user_info(state, ui) < 0) goto fail;

  *p_ui = ui;
  return 1;

 fail:
  remove_user_info_from_pool(state, user_id, contest_id);
  return -1;
}

#undef FAIL

/*
 * Local variables:
 *  compile-command: "make -C ../.."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "MYSQL")
 * End:
 */
