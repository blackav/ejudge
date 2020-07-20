/* -*- mode: c -*- */

/* Copyright (C) 2008-2017 Alexander Chernov <cher@ejudge.ru> */

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

static void
do_remove_cntsreg_from_pool(
        struct cntsregs_cache *cache,
        struct cntsregs_container *cc)
{
  struct cntsregs_user *usr;
  struct cntsregs_container *qq;

  if (!cc) return;
  if (cc->user_id <= 0 || cc->user_id >= cache->size) return;
  usr = &cache->user_map[cc->user_id];

  UNLINK_FROM_LIST(cc, cache->first, cache->last, prev, next);
  UNLINK_FROM_LIST(cc, usr->first_user, usr->last_user, prev_user, next_user);
  CALCULATE_RANGE(usr->min_id, usr->max_id, usr->first_user, contest_id, next_user, qq);
  userlist_free(&cc->c->b);
  cc->c = 0;
  xfree(cc);
  cache->count--;
}

static struct userlist_contest *
get_cntsreg_from_pool(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id)
{
  struct cntsregs_cache *cc = &state->cntsregs;
  struct cntsregs_user *cu;
  struct cntsregs_container *co;

  ASSERT(user_id > 0);
  ASSERT(contest_id >= 0);

  if (!contest_id) return 0;
  if (user_id >= cc->size) return 0;
  cu = &cc->user_map[user_id];

  if (contest_id < cu->min_id || contest_id >= cu->max_id) return 0;
  for (co = cu->first_user; co; co = co->next_user)
    if (co->contest_id == contest_id)
      break;
  if (!co) return 0;
  MOVE_TO_FRONT(co, cc->first, cc->last, prev, next);
  MOVE_TO_FRONT(co, cu->first_user, cu->last_user, prev_user, next_user);
  return co->c;
}

static struct userlist_contest *
allocate_cntsreg_on_pool(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id)
{
  struct cntsregs_cache *cc = &state->cntsregs;
  struct cntsregs_user *cu;
  struct cntsregs_container *co;
  struct userlist_contest *c;

  ASSERT(user_id > 0);
  ASSERT(contest_id >= 0);

  if (user_id >= cc->size) {
    int new_size = cc->size;
    struct cntsregs_user *new_map = 0;

    if (!new_size) new_size = 128;
    while (new_size <= user_id) new_size *= 2;
    XCALLOC(new_map, new_size);
    if (cc->size > 0)
      memcpy(new_map, cc->user_map, sizeof(new_map[0]) * cc->size);
    cc->size = new_size;
    xfree(cc->user_map);
    cc->user_map = new_map;
  }
  cu = &cc->user_map[user_id];

  co = 0;
  if (contest_id >= cu->min_id && contest_id < cu->max_id) {
    for (co = cu->first_user; co; co = co->next_user)
      if (co->contest_id == contest_id)
        break;
  }

  if (co) {
    userlist_elem_free_data(&co->c->b);
    co->c->id = contest_id;

    MOVE_TO_FRONT(co, cc->first, cc->last, prev, next);
    MOVE_TO_FRONT(co, cu->first_user, cu->last_user, prev_user, next_user);
    return co->c;
  }

  if (cc->count >= CNTSREGS_POOL_SIZE) {
    do_remove_cntsreg_from_pool(cc, cc->last);
  }

  // allocate new entry
  c = (struct userlist_contest*) userlist_node_alloc(USERLIST_T_CONTEST);
  XCALLOC(co, 1);
  co->user_id = user_id;
  co->contest_id = contest_id;
  co->c = c;
  cc->count++;
  cu = &cc->user_map[user_id];
  UPDATE_RANGE(cu->min_id, cu->max_id, cu->first_user, contest_id);
  LINK_FIRST(co, cc->first, cc->last, prev, next);
  LINK_FIRST(co, cu->first_user, cu->last_user, prev_user, next_user);
  return c;
}

static void
remove_cntsreg_from_pool(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id)
{
  struct cntsregs_cache *cc = &state->cntsregs;
  struct cntsregs_user *cu;
  struct cntsregs_container *co;

  if (user_id <= 0 || contest_id <= 0) return;
  if (user_id >= cc->size) return;
  cu = &cc->user_map[user_id];
  if (contest_id < cu->min_id || contest_id >= cu->max_id) return;
  for (co = cu->first_user; co; co = co->next_user)
    if (co->contest_id == contest_id)
      break;
  do_remove_cntsreg_from_pool(cc, co);
}

static void
remove_cntsreg_from_pool_by_uid(
        struct uldb_mysql_state *state,
        int user_id)
{
  struct cntsregs_cache *cc = &state->cntsregs;
  struct cntsregs_user *cu;
  struct cntsregs_container *co, *cq;

  if (user_id <= 0 || user_id >= cc->size) return;
  cu = &cc->user_map[user_id];
  for (co = cu->first_user; co; co = cq) {
    cq = co->next_user;
    do_remove_cntsreg_from_pool(cc, co);
  }
}

static int
parse_cntsreg(
        struct uldb_mysql_state *state,
        int field_count,
        char **row,
        unsigned long *lengths,
        struct userlist_contest *c)
{
  int user_id = 0, is_banned = 0, is_invisible = 0, is_locked = 0;
  int is_incomplete = 0, is_disqualified = 0;
  int is_privileged = 0, is_reg_readonly = 0;
  int flags = 0;

  if (state->mi->parse_spec(state->md, field_count, row, lengths,
                        CNTSREG_WIDTH, cntsreg_spec, c,
                        &user_id, &is_banned, &is_invisible,
                            &is_locked, &is_incomplete, &is_disqualified, &is_privileged, &is_reg_readonly) < 0)
    goto fail;
  if (user_id <= 0 || c->id <= 0
      || c->status < 0 || c->status >= USERLIST_REG_LAST)
    db_error_inv_value_fail(state->md, "status");
  if (is_banned) flags |= USERLIST_UC_BANNED;
  if (is_invisible) flags |= USERLIST_UC_INVISIBLE;
  if (is_locked) flags |= USERLIST_UC_LOCKED;
  if (is_incomplete) flags |= USERLIST_UC_INCOMPLETE;
  if (is_disqualified) flags |= USERLIST_UC_DISQUALIFIED;
  if (is_privileged) flags |= USERLIST_UC_PRIVILEGED;
  if (is_reg_readonly) flags |= USERLIST_UC_REG_READONLY;
  c->flags = flags;
  return 0;

 fail:
  return -1;
}

static void
unparse_cntsreg(
        struct uldb_mysql_state *state,
        FILE *fout,
        int user_id,
        const struct userlist_contest *c)
{
  int is_banned = 0, is_invisible = 0, is_locked = 0;
  int is_incomplete = 0, is_disqualified = 0;
  int is_privileged = 0, is_reg_readonly = 0;

  if ((c->flags & USERLIST_UC_BANNED)) is_banned = 1;
  if ((c->flags & USERLIST_UC_INVISIBLE)) is_invisible = 1;
  if ((c->flags & USERLIST_UC_LOCKED)) is_locked = 1;
  if ((c->flags & USERLIST_UC_INCOMPLETE)) is_incomplete = 1;
  if ((c->flags & USERLIST_UC_DISQUALIFIED)) is_disqualified = 1;
  is_privileged = ((c->flags & USERLIST_UC_PRIVILEGED) != 0);
  is_reg_readonly = ((c->flags & USERLIST_UC_REG_READONLY) != 0);
  state->mi->unparse_spec(state->md, fout, CNTSREG_WIDTH, cntsreg_spec, c,
                          user_id, is_banned, is_invisible,
                          is_locked, is_incomplete, is_disqualified,
                          is_privileged, is_reg_readonly);
}

static int
fetch_cntsreg(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id,
        struct userlist_contest **p_c)
{
  unsigned char cmdbuf[1024];
  int cmdlen;
  struct userlist_contest *c = 0;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;

  *p_c = 0;
  if (!contest_id) return 0;
  if (state->cache_queries
      && (c = get_cntsreg_from_pool(state, user_id, contest_id))) {
    *p_c = c;
    return 1;
  }

  snprintf(cmdbuf, sizeof(cmdbuf), "SELECT * FROM %scntsregs WHERE user_id = %d AND contest_id = %d ;", md->table_prefix, user_id, contest_id);
  cmdlen = strlen(cmdbuf);
  if (mi->simple_query(md, cmdbuf, cmdlen) < 0) goto fail;
  md->field_count = mysql_field_count(md->conn);
  if (md->field_count != CNTSREG_WIDTH)
    db_error_field_count_fail(md, CNTSREG_WIDTH);
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
  if (!(c = allocate_cntsreg_on_pool(state, user_id, contest_id))) goto fail;
  if (parse_cntsreg(state, md->field_count,md->row,md->lengths, c) < 0)
    goto fail;
  mi->free_res(md);
  *p_c = c;
  return 1;

 fail:
  mi->free_res(md);
  remove_cntsreg_from_pool(state, user_id, contest_id);
  return -1;
}

static void
drop_cntsreg_cache(struct uldb_mysql_state *state)
{
  struct cntsregs_container *p, *q;

  for (p = state->cntsregs.first; p; p = q) {
    q = p->next;
    do_remove_cntsreg_from_pool(&state->cntsregs, p);
  }
}
