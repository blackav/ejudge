/* -*- mode: c -*- */

/* Copyright (C) 2010-2016 Alexander Chernov <cher@ejudge.ru> */

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

static int
parse_group(
        struct uldb_mysql_state *state,
        int field_count,
        char **row,
        unsigned long *lengths,
        struct userlist_group *grp)
{
  char errbuf[1024];

  if (state->mi->parse_spec(state->md, field_count, row, lengths,
                            USERGROUP_WIDTH, usergroup_spec, grp) < 0)
    return -1;
  if (grp->group_id <= 0) FAIL("group_id <= 0");
  if (!grp->group_name) FAIL("group_name == 0");
  return 0;

 fail:
  fprintf(stderr, "parse_member: %s\n", errbuf);
  return -1;
}

static void
unparse_group(
        struct uldb_mysql_state *state,
        FILE *fout,
        const struct userlist_group *grp)
  __attribute__((unused));
static void
unparse_group(
        struct uldb_mysql_state *state,
        FILE *fout,
        const struct userlist_group *grp)
{
  state->mi->unparse_spec(state->md,fout,USERGROUP_WIDTH,usergroup_spec,grp);
}

static void
group_cache_drop(struct uldb_mysql_state *state)
{
  struct xml_tree *p, *q;

  for (p = state->groups.first; p; p = q) {
    q = p->right;
    p->left = p->right = 0;
    userlist_free(p);
  }
  xfree(state->groups.group_map);
  memset(&state->groups, 0, sizeof(state->groups));
}

static void
group_cache_remove(struct uldb_mysql_state *state, struct userlist_group *grp)
{
  if (!grp) return;

  if (grp->group_id > 0 && grp->group_id < state->groups.size
      && state->groups.group_map[grp->group_id] == grp) {
    state->groups.group_map[grp->group_id] = 0;
    state->groups.count--;
  }
  UNLINK_FROM_LIST(&grp->b,state->groups.first,state->groups.last,left,right);

  userlist_free(&grp->b);
  memset(grp, 0, sizeof(*grp));
}

static void
group_cache_remove_by_id(struct uldb_mysql_state *state, int group_id)
{
  struct userlist_group *grp;

  if (group_id <= 0 || group_id >= state->groups.size) return;
  if (!(grp = state->groups.group_map[group_id])) return;

  state->groups.group_map[grp->group_id] = 0;
  state->groups.count--;
  UNLINK_FROM_LIST(&grp->b,state->groups.first,state->groups.last,left,right);
  userlist_free(&grp->b);
  memset(grp, 0, sizeof(*grp));
}

static void
group_cache_add(struct uldb_mysql_state *state, struct userlist_group *grp)
{
  int new_size = 0;
  struct userlist_group **new_map = 0;

  if (!grp) return;
  ASSERT(grp->group_id > 0);
  if (grp->group_id < state->groups.size
      && state->groups.group_map[grp->group_id] == grp)
    return;
  if (grp->group_id < state->groups.size
      && state->groups.group_map[grp->group_id]) {
    // cache descync?
    group_cache_drop(state);
  }

  if (grp->group_id >= state->groups.size) {
    if (!(new_size = state->groups.size)) new_size = 32;
    while (new_size <= grp->group_id) {
      new_size *= 2;
    }
    XCALLOC(new_map, new_size);
    if (state->groups.size > 0) {
      memcpy(new_map, state->groups.group_map,
             state->groups.size * sizeof(new_map[0]));
    }
    xfree(state->groups.group_map);
    state->groups.size = new_size;
    state->groups.group_map = new_map;
  }

  state->groups.group_map[grp->group_id] = grp;
  LINK_FIRST(&grp->b, state->groups.first, state->groups.last, left, right);
  state->groups.count++;
}

static struct userlist_group *
group_cache_try_get(struct uldb_mysql_state *state, int group_id)
{
  if (group_id <= 0 || group_id >= state->groups.size) return 0;
  return state->groups.group_map[group_id];
}

#undef FAIL
