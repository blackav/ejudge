/* -*- mode: c -*- */

/* Copyright (C) 2008-2022 Alexander Chernov <cher@ejudge.ru> */

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
};

static void
do_remove_cookie_from_pool(
        struct cookies_cache *cache,
        struct cookies_container *cntr)
{
  struct cookies_container **v;
  int i, j, h;

  if (!cache || !cntr) return;
  struct userlist_cookie *cookie = cntr->cookie;

  h = cookie->cookie & (COOKIES_POOL_SIZE - 1);
  i = 0;
  while (cache->hash[h]) {
    h = (h + 1) & (COOKIES_POOL_SIZE - 1);
    i++;
  }
  XALLOCAZ(v, i + 1);
  j = 0;
  h = cookie->cookie & (COOKIES_POOL_SIZE - 1);
  while (cache->hash[h]) {
    if (cache->hash[h] != cntr) {
      v[j++] = cache->hash[h];
    }
    cache->hash[h] = 0;
    h = (h + 1) & (COOKIES_POOL_SIZE - 1);
  }
  ASSERT(j + 1 == i);
  // rehash the collected pointers
  for (i = 0; i < j; i++) {
    h = v[i]->cookie->cookie & (COOKIES_POOL_SIZE - 1);
    while (cache->hash[h])
      h = (h + 1) & (COOKIES_POOL_SIZE - 1);
    cache->hash[h] = v[i];
  }

  if (cookie->client_key != 0) {
    h = cookie->client_key & (COOKIES_POOL_SIZE - 1);
    i = 0;
    while (cache->client_key_hash[h]) {
      h = (h + 1) & (COOKIES_POOL_SIZE - 1);
      ++i;
    }
    XALLOCAZ(v, i + 1);
    j = 0;
    h = cookie->client_key & (COOKIES_POOL_SIZE - 1);
    while (cache->client_key_hash[h]) {
      if (cache->client_key_hash[h] != cntr) {
        v[j++] = cache->client_key_hash[h];
      }
      cache->client_key_hash[h] = NULL;
      h = (h + 1) & (COOKIES_POOL_SIZE - 1);
    }
    for (i = 0; i < j; ++i) {
      h = v[i]->cookie->client_key & (COOKIES_POOL_SIZE - 1);
      while (cache->client_key_hash[h])
        h = (h + 1) & (COOKIES_POOL_SIZE - 1);
      cache->client_key_hash[h] = v[i];
    }
  }


  // remove c from the list
  UNLINK_FROM_LIST(cntr, cache->first, cache->last, prev, next);
  userlist_free(&cntr->cookie->b); cntr->cookie = 0;
  xfree(cntr);
  cache->count--;
}

static struct userlist_cookie *
get_cookie_from_pool(
        struct uldb_mysql_state *state,
        unsigned long long val)
{
  int h;
  struct cookies_container *cntr;
  struct cookies_cache *cache = &state->cookies;

  h = val & (COOKIES_POOL_SIZE - 1);
  while ((cntr = cache->hash[h]) && cntr->cookie && cntr->cookie->cookie != val)
    h = (h + 1) & (COOKIES_POOL_SIZE - 1);
  if ((cntr = cache->hash[h]) && cntr->cookie && cntr->cookie->cookie == val) {
    MOVE_TO_FRONT(cntr, cache->first, cache->last, prev, next);
    return cntr->cookie;
  }
  return 0;
}

static struct userlist_cookie *
get_client_key_from_pool(
        struct uldb_mysql_state *state,
        unsigned long long client_key)
{
  int h;
  struct cookies_container *cntr;
  struct cookies_cache *cache = &state->cookies;

  h = client_key & (COOKIES_POOL_SIZE - 1);
  while ((cntr = cache->client_key_hash[h]) && cntr->cookie && cntr->cookie->client_key != client_key)
    h = (h + 1) & (COOKIES_POOL_SIZE - 1);
  if ((cntr = cache->client_key_hash[h]) && cntr->cookie && cntr->cookie->client_key == client_key) {
    MOVE_TO_FRONT(cntr, cache->first, cache->last, prev, next);
    return cntr->cookie;
  }
  return 0;
}

static struct userlist_cookie *
allocate_cookie_on_pool(
        struct uldb_mysql_state *state,
        const struct userlist_cookie *in_c)
{
  int h;
  struct cookies_container *cntr;
  struct userlist_cookie *c;
  struct cookies_cache *cache = &state->cookies;

  h = in_c->cookie & (COOKIES_POOL_SIZE - 1);
  while ((cntr = cache->hash[h]) && cntr->cookie && cntr->cookie->cookie != in_c->cookie)
    h = (h + 1) & (COOKIES_POOL_SIZE - 1);
  if ((cntr = cache->hash[h]) && cntr->cookie && cntr->cookie->cookie == in_c->cookie) {
    c = cntr->cookie;
    ASSERT(c);
    userlist_elem_free_data(&c->b);

    memcpy(&c->ip, &in_c->ip, sizeof(c->ip));
    c->cookie = in_c->cookie;
    c->client_key = in_c->client_key;
    c->expire = in_c->expire;
    c->user_id = in_c->user_id;
    c->ssl = in_c->ssl;
    c->contest_id = in_c->contest_id;
    c->locale_id = in_c->locale_id;
    c->priv_level = in_c->priv_level;
    c->role = in_c->role;
    c->recovery = in_c->recovery;
    c->team_login = in_c->team_login;
    c->is_ws = in_c->is_ws;
    c->is_job = in_c->is_job;

    MOVE_TO_FRONT(cntr, cache->first, cache->last, prev, next);
    return c;
  }

  if (cache->count > COOKIES_MAX_HASH_SIZE) {
    do_remove_cookie_from_pool(cache, cache->last);
  }

  // allocate new entry
  XCALLOC(cntr, 1);
  c = (struct userlist_cookie*)userlist_node_alloc(USERLIST_T_COOKIE);
  memcpy(&c->ip, &in_c->ip, sizeof(c->ip));
  c->cookie = in_c->cookie;
  c->client_key = in_c->client_key;
  c->expire = in_c->expire;
  c->user_id = in_c->user_id;
  c->ssl = in_c->ssl;
  c->contest_id = in_c->contest_id;
  c->locale_id = in_c->locale_id;
  c->priv_level = in_c->priv_level;
  c->role = in_c->role;
  c->recovery = in_c->recovery;
  c->team_login = in_c->team_login;
  c->is_ws = in_c->is_ws;
  c->is_job = in_c->is_job;

  cntr->cookie = c;
  cache->count++;
  LINK_FIRST(cntr, cache->first, cache->last, prev, next);
  h = in_c->cookie & (COOKIES_POOL_SIZE - 1);
  while (cache->hash[h])
    h = (h + 1) & (COOKIES_POOL_SIZE - 1);
  cache->hash[h] = cntr;
  if (c->client_key) {
    h = c->client_key & (COOKIES_POOL_SIZE - 1);
    while (cache->client_key_hash[h])
      h = (h + 1) & (COOKIES_POOL_SIZE - 1);
    cache->client_key_hash[h] = cntr;
  }
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
  while ((cntr = cache->hash[h]) && cntr->cookie && cntr->cookie->cookie != val)
    h = (h + 1) & (COOKIES_POOL_SIZE - 1);
  if (!(cntr = cache->hash[h])) return;
  if (!cntr->cookie) return;
  if (cntr->cookie->cookie != val) return;
  do_remove_cookie_from_pool(cache, cntr);
}

static void
remove_cookie_from_pool_by_uid(
        struct uldb_mysql_state *state,
        int user_id)
{
  struct cookies_container *p, *q;
  for (p = state->cookies.first; p; p = q) {
    q = p->next;
    if (p->cookie && p->cookie->user_id == user_id)
      do_remove_cookie_from_pool(&state->cookies, p);
  }
}

static void
remove_cookie_from_pool_by_expire(
        struct uldb_mysql_state *state,
        time_t expire)
{
  struct cookies_container *p, *q;
  for (p = state->cookies.first; p; p = q) {
    q = p->next;
    if (p->cookie && p->cookie->expire < expire)
      do_remove_cookie_from_pool(&state->cookies, p);
  }
}

static int
parse_cookie(
        struct uldb_mysql_state *state,
        struct userlist_cookie *c)
{
  int ip_version = 0;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;

  if (mi->parse_spec(md, md->field_count, md->row,
                            md->lengths, COOKIE_WIDTH, cookie_spec, c,
                            &ip_version) < 0)
    goto fail;
  if (!c->cookie) db_error_inv_value_fail(md, "cookie");
  if (c->user_id <= 0) db_error_inv_value_fail(md, "user_id");
  if (c->contest_id < 0) db_error_inv_value_fail(md, "contest_id");
  if (c->priv_level < 0 || c->priv_level > PRIV_LEVEL_ADMIN)
    db_error_inv_value_fail(md, "priv_level");
  if (c->role < 0) db_error_inv_value_fail(md, "role");
  if (ip_version != 4) db_error_inv_value_fail(md, "ip_version");
  if (c->locale_id < 0) c->locale_id = 0;
  return 0;

 fail:
  return -1;
}

static int
fetch_cookie(
        struct uldb_mysql_state *state,
        ej_cookie_t val,
        ej_cookie_t client_key,
        struct userlist_cookie **p_c)
{
  unsigned char cookie_buf[64];
  unsigned char cmdbuf[1024];
  int cmdlen;
  struct userlist_cookie *c = 0;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  struct userlist_cookie tmp_c;

  memset(&tmp_c, 0, sizeof(tmp_c));
  if (p_c) *p_c = 0;
  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT * FROM %scookies WHERE cookie = '%s' ;",
           md->table_prefix,
           xml_unparse_full_cookie(cookie_buf, sizeof(cookie_buf),
                                   &val, &client_key));
  cmdlen = strlen(cmdbuf);
  if (mi->simple_query(md, cmdbuf, cmdlen) < 0) goto fail;
  md->field_count = mysql_field_count(md->conn);
  if (md->field_count != COOKIE_WIDTH)
    db_error_field_count_fail(md, COOKIE_WIDTH);
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
  if (parse_cookie(state, &tmp_c) < 0) goto fail;
  if (!(c = allocate_cookie_on_pool(state, &tmp_c))) goto fail;
  mi->free_res(md);
  if (p_c) *p_c = c;
  return 1;

 fail:
  mi->free_res(md);
  return -1;
}

static void
unparse_cookie(
        struct uldb_mysql_state *state,
        FILE *fout,
        const struct userlist_cookie *c)
{
  state->mi->unparse_spec(state->md, fout, COOKIE_WIDTH, cookie_spec, c, 4);
}

static void
drop_cookie_cache(struct uldb_mysql_state *state)
{
  struct cookies_container *p, *q;

  for (p = state->cookies.first; p; p = q) {
    q = p->next;
    do_remove_cookie_from_pool(&state->cookies, p);
  }
}

static int
fetch_client_key(
        struct uldb_mysql_state *state,
        ej_cookie_t client_key,
        struct userlist_cookie **p_c)
{
  unsigned char cmdbuf[1024];
  int cmdlen;
  struct userlist_cookie *c = 0;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  struct userlist_cookie tmp_c;

  memset(&tmp_c, 0, sizeof(tmp_c));
  if (p_c) *p_c = 0;
  snprintf(cmdbuf, sizeof(cmdbuf),
           "SELECT * FROM %scookies WHERE cookie LIKE('%%-%016llx') ;",
           md->table_prefix,
           client_key);
  cmdlen = strlen(cmdbuf);
  if (mi->simple_query(md, cmdbuf, cmdlen) < 0) goto fail;
  md->field_count = mysql_field_count(md->conn);
  if (md->field_count != COOKIE_WIDTH)
    db_error_field_count_fail(md, COOKIE_WIDTH);
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
  if (parse_cookie(state, &tmp_c) < 0) goto fail;
  if (!(c = allocate_cookie_on_pool(state, &tmp_c))) goto fail;
  mi->free_res(md);
  if (p_c) *p_c = c;
  return 1;

 fail:
  mi->free_res(md);
  return -1;
}
