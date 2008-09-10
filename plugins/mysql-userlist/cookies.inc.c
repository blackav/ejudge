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

struct cookies_container
{
  struct cookies_container *prev, *next;
  struct userlist_cookie *cookie;
  unsigned long long value;
};

static void
do_remove_cookie_from_pool(
        struct cookies_cache *cache,
        struct cookies_container *cntr)
{
  struct cookies_container **v;
  int i, j, h;

  if (!cache || !cntr) return;

  h = cntr->value & (COOKIES_POOL_SIZE - 1);
  i = 0;
  while (cache->hash[h]) {
    h = (h + 1) & (COOKIES_POOL_SIZE - 1);
    i++;
  }
  XALLOCAZ(v, i + 1);
  j = 0;
  h = cntr->value & (COOKIES_POOL_SIZE - 1);
  while (cache->hash[h]) {
    if (cache->hash[h] != cntr) {
      v[j++] = cache->hash[h];
    }
    cache->hash[h] = 0;
    h = (h + 1) & (COOKIES_POOL_SIZE - 1);
  }
  // rehash the collected pointers
  for (i = 0; i < j; i++) {
    h = v[i]->value & (COOKIES_POOL_SIZE - 1);
    while (cache->hash[h])
      h = (h + 1) & (COOKIES_POOL_SIZE - 1);
    cache->hash[h] = v[i];
  }
  // remove c from the tail of the list
  UNLINK_FROM_LIST(cntr, cache->first, cache->last, prev, next);
  userlist_free(&cntr->cookie->b); cntr->cookie = 0;
  xfree(cntr);
  cache->count--;
}

static struct userlist_cookie *
allocate_cookie_on_pool(
        struct uldb_mysql_state *state,
        unsigned long long val)
{
  int h;
  struct cookies_container *cntr;
  struct userlist_cookie *c;
  struct cookies_cache *cache = &state->cookies;

  h = val & (COOKIES_POOL_SIZE - 1);
  while ((cntr = cache->hash[h]) && cntr->value != val)
    h = (h + 1) & (COOKIES_POOL_SIZE - 1);
  if ((cntr = cache->hash[h]) && cntr->value == val) {
    if (state->nocache) {
      c = cntr->cookie;
      ASSERT(c);
      userlist_elem_free_data(&c->b);
      c->cookie = val;
    }

    MOVE_TO_FRONT(cntr, cache->first, cache->last, prev, next);
    return c;
  }

  if (cache->count > COOKIES_MAX_HASH_SIZE) {
    do_remove_cookie_from_pool(cache, cache->last);
  }

  // allocate new entry
  XCALLOC(cntr, 1);
  c = (struct userlist_cookie*)userlist_node_alloc(USERLIST_T_COOKIE);
  cntr->cookie = c;
  c->cookie = val;
  cntr->value = val;
  cache->count++;
  LINK_FIRST(cntr, cache->first, cache->last, prev, next);
  h = val & (COOKIES_POOL_SIZE - 1);
  while (cache->hash[h])
    h = (h + 1) & (COOKIES_POOL_SIZE - 1);
  cache->hash[h] = cntr;
  return c;
}

static void
remove_cookie_from_pool(
        struct uldb_mysql_state *state,
        unsigned long long val)
{
  int h;
  struct cookies_container *cntr;
  struct cookies_cache *cache = &state->cookies;

  if (!state || !val) return;

  h = val & (COOKIES_POOL_SIZE - 1);
  while ((cntr = cache->hash[h]) && cntr->value != val)
    h = (h + 1) & (COOKIES_POOL_SIZE - 1);
  if (!(cntr = cache->hash[h])) return;
  if (cntr->value != val) return;
  do_remove_cookie_from_pool(cache, cntr);
}

static int
parse_cookie(
        struct uldb_mysql_state *state,
        struct userlist_cookie *c)
{
  int ip_version = 0;

  if (handle_parse_spec(state, COOKIE_WIDTH, cookie_spec, c, &ip_version) < 0)
    goto fail;
  if (!c->cookie) db_inv_value_fail();
  if (c->user_id <= 0) db_inv_value_fail();
  if (c->contest_id < 0) db_inv_value_fail();
  if (c->priv_level < 0 || c->priv_level > PRIV_LEVEL_ADMIN)
    db_inv_value_fail();
  if (c->role < 0) db_inv_value_fail();
  if (ip_version != 4) db_inv_value_fail();
  if (c->locale_id < 0) c->locale_id = 0;
  return 0;

 fail:
  return -1;
}

static int
fetch_cookie(
        struct uldb_mysql_state *state,
        ej_cookie_t val,
        struct userlist_cookie **p_c)
{
  unsigned char cmdbuf[1024];
  int cmdlen = sizeof(cmdbuf);
  struct userlist_cookie *c = 0;

  if (p_c) *p_c = 0;
  cmdlen = snprintf(cmdbuf, cmdlen,
                    "SELECT * FROM %scookies WHERE cookie = %llu ;",
                    state->table_prefix, val);
  if (my_simple_query(state, cmdbuf, cmdlen) < 0) goto fail;
  state->field_count = mysql_field_count(state->conn);
  if (state->field_count != COOKIE_WIDTH)
    db_wrong_field_count_fail(state, COOKIE_WIDTH);
  if (!(state->res = mysql_store_result(state->conn)))
    db_error_fail(state);
  state->row_count = mysql_num_rows(state->res);
  if (state->row_count < 0) db_error_fail(state);
  if (!state->row_count) return 0;
  if (state->row_count > 0) goto fail;
  if (!(state->row = mysql_fetch_row(state->res)))
    db_no_data_fail();
  state->lengths = mysql_fetch_lengths(state->res);
  if (!(c = allocate_cookie_on_pool(state, val))) goto fail;
  if (parse_cookie(state, c) < 0) goto fail;
  if (p_c) *p_c = c;
  return 1;

 fail:
  remove_cookie_from_pool(state, val);
  return -1;
}

static void
unparse_cookie(
        struct uldb_mysql_state *state,
        FILE *fout,
        const struct userlist_cookie *c)
{
  handle_unparse_spec(state, fout, COOKIE_WIDTH, cookie_spec, c, 4);
}

/*
 * Local variables:
 *  compile-command: "make -C ../.."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "MYSQL")
 * End:
 */
