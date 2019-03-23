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

struct members_container
{
  struct xml_tree b;
  int user_id;
  int contest_id;
  struct userlist_members *mm;
  struct members_container *prev, *next;
  // sublist of containers with the same user_id
  struct members_container *prev_user, *next_user;
};
struct members_user
{
  struct members_container *first_user, *last_user;
  int min_id, max_id;           // [min_id, max_id) for contest
};

static void
do_remove_member_from_pool(
        struct members_cache *cache,
        struct members_container *pp)
{
  struct members_user *usr;
  struct members_container *qq;

  if (!pp) return;
  ASSERT(pp->user_id > 0 && pp->user_id < cache->size);
  usr = &cache->user_map[pp->user_id];

  UNLINK_FROM_LIST(pp, cache->first, cache->last, prev, next);
  UNLINK_FROM_LIST(pp, usr->first_user, usr->last_user, prev_user, next_user);
  CALCULATE_RANGE(usr->min_id, usr->max_id, usr->first_user, contest_id, next_user, qq);
  userlist_free(&pp->mm->b);
  pp->mm = 0;
  xfree(pp);
  cache->count--;
}

static struct userlist_members *
get_member_from_pool(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id)
{
  struct members_cache *cache = &state->members;
  struct members_user *usr;
  struct members_container *pp;

  ASSERT(user_id > 0);
  ASSERT(contest_id >= 0);

  if (user_id >= cache->size) return 0;
  usr = &cache->user_map[user_id];

  if (contest_id < usr->min_id || contest_id >= usr->max_id) return 0;
  for (pp = usr->first_user; pp; pp = pp->next_user) {
    if (pp->contest_id == contest_id)
      break;
  }
  if (!pp) return 0;
  MOVE_TO_FRONT(pp, cache->first, cache->last, prev, next);
  MOVE_TO_FRONT(pp, usr->first_user, usr->last_user, prev_user, next_user);
  return pp->mm;
}

static struct userlist_members *
allocate_member_on_pool(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id)
{
  struct members_cache *cache = &state->members;
  struct members_user *usr;
  struct members_container *pp;

  ASSERT(user_id > 0);
  ASSERT(contest_id >= 0);

  if (user_id >= cache->size) {
    // extend the cache index
    int new_size = cache->size;
    struct members_user *new_map = 0;

    if (!new_size) new_size = 128;
    while (new_size <= user_id) new_size *= 2;
    XCALLOC(new_map, new_size);
    if (cache->size > 0)
      memcpy(new_map, cache->user_map, sizeof(new_map[0]) * cache->size);
    cache->size = new_size;
    xfree(cache->user_map);
    cache->user_map = new_map;
  }
  usr = &cache->user_map[user_id];

  pp = 0;
  if (contest_id >= usr->min_id && contest_id < usr->max_id) {
    for (pp = usr->first_user; pp; pp = pp->next_user) {
      ASSERT(pp->user_id == user_id);
      if (pp->contest_id == contest_id)
        break;
    }
  }

  // found in cache
  if (pp) {
    userlist_free(&pp->mm->b);
    pp->mm = (struct userlist_members*) userlist_node_alloc(USERLIST_T_MEMBERS);

    MOVE_TO_FRONT(pp, cache->first, cache->last, prev, next);
    MOVE_TO_FRONT(pp, usr->first_user, usr->last_user, prev_user, next_user);
    return pp->mm;
  }

  if (cache->count == MEMBERS_POOL_SIZE) {
    do_remove_member_from_pool(cache, pp);
  }

  XCALLOC(pp, 1);
  pp->mm = (struct userlist_members*) userlist_node_alloc(USERLIST_T_MEMBERS);
  pp->user_id = user_id;
  pp->contest_id = contest_id;
  cache->count++;
  UPDATE_RANGE(usr->min_id, usr->max_id, usr->first_user, contest_id);
  LINK_FIRST(pp, cache->first, cache->last, prev, next);
  LINK_FIRST(pp, usr->first_user, usr->last_user, prev_user, next_user);
  return pp->mm;
}

static void
remove_member_from_pool(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id)
{
  struct members_cache *cache = &state->members;
  struct members_user *usr;
  struct members_container *pp;

  ASSERT(user_id > 0);
  ASSERT(contest_id >= 0);

  if (user_id >= cache->size) return;
  usr = &cache->user_map[user_id];
  if (!usr) return;             /* this never happens */
  if (contest_id < usr->min_id || contest_id >= usr->max_id) return;
  for (pp = usr->first_user; pp; pp = pp->next_user)
    if (pp->contest_id == contest_id) break;
  do_remove_member_from_pool(cache, pp);
}

static void
remove_member_from_pool_by_uid(
        struct uldb_mysql_state *state,
        int user_id)
{
  struct members_cache *cache = &state->members;
  struct members_container *pp, *qq;

  ASSERT(user_id > 0);

  if (user_id >= cache->size) return;
  for (pp = cache->user_map[user_id].first_user; pp; pp = qq) {
    qq = pp->next_user;
    do_remove_member_from_pool(cache, pp);
  }
}

static int
parse_member(
        struct uldb_mysql_state *state,
        int field_count,
        char **row,
        unsigned long *lengths,
        struct userlist_member *m)
{
  int user_id = 0, contest_id = -1;
  char errbuf[1024];

  if (state->mi->parse_spec(state->md, field_count, row, lengths,
                            MEMBER_WIDTH, member_spec,
                            m, &user_id, &contest_id) < 0)
    return -1;
  if (m->serial <= 0) FAIL("serial <= 0");
  if (user_id <= 0) FAIL("user_id <= 0");
  if (contest_id < 0) FAIL("contest_id <= 0");
  if (m->team_role<USERLIST_MB_CONTESTANT || m->team_role>=USERLIST_MB_LAST)
    FAIL("team_role out of range");
  if (m->status < 0 || m->status >= USERLIST_ST_LAST)
    FAIL("status is out of range");
  if (m->gender < 0 || m->gender >= USERLIST_SX_LAST)
    FAIL("gender is out of range");
  if (m->grade < -1 || m->grade > EJ_MAX_GRADE)
    FAIL("grade is out of range");
  return 0;

 fail:
  fprintf(stderr, "parse_member: %s\n", errbuf);
  return -1;
}

static int
fetch_member(
        struct uldb_mysql_state *state,
        int user_id,
        int contest_id,
        struct userlist_members **p_mm)
{
  unsigned char cmdbuf[1024];
  int cmdlen;
  struct userlist_members *mm = 0;
  struct userlist_member *m;
  int i;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;

  if (p_mm) *p_mm = 0;
  if (state->cache_queries
      && (mm = get_member_from_pool(state, user_id, contest_id))) {
    if (p_mm) *p_mm = mm;
    return 1;
  }

  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT * FROM %smembers WHERE user_id = %d AND contest_id = %d ;",
           md->table_prefix, user_id, contest_id);
  cmdlen = strlen(cmdbuf);
  if (mi->simple_query(md, cmdbuf, cmdlen) < 0) goto fail;
  if ((md->field_count = mysql_field_count(md->conn)) != MEMBER_WIDTH)
    db_error_field_count_fail(md, MEMBER_WIDTH);
  if (!(md->res = mysql_store_result(md->conn)))
    db_error_fail(md);
  md->row_count = mysql_num_rows(md->res);
  if (md->row_count <= 0) {
    mi->free_res(md);
    if (p_mm) *p_mm = 0;
    return 0;
  }

  mm = allocate_member_on_pool(state, user_id, contest_id);
  userlist_members_reserve(mm, md->row_count);
  for (i = 0; i < md->row_count; i++) {
    if (!(md->row = mysql_fetch_row(md->res)))
      db_error_no_data_fail(md);
    md->lengths = mysql_fetch_lengths(md->res);
    m = (struct userlist_member*) userlist_node_alloc(USERLIST_T_MEMBER);
    xml_link_node_last(&mm->b, &m->b);
    mm->m[mm->u++] = m;
    if (parse_member(state, md->field_count, md->row, md->lengths, m) < 0)
      goto fail;
  }
  mi->free_res(md);
  if (p_mm) *p_mm = mm;
  return 1;

 fail:
  mi->free_res(md);
  remove_member_from_pool(state, user_id, contest_id);
  return -1;
}

static void
unparse_member(
        struct uldb_mysql_state *state,
        FILE *fout,
        int user_id,
        int contest_id,
        const struct userlist_member *m)
{
  state->mi->unparse_spec(state->md, fout, MEMBER_WIDTH, member_spec, m,
                          user_id, contest_id);
}

#undef FAIL

static void
drop_members_cache(struct uldb_mysql_state *state)
{
  struct members_container *p, *q;

  for (p = state->members.first; p; p = q) {
    q = p->next;
    do_remove_member_from_pool(&state->members, p);
  }
}
