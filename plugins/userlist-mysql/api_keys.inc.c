/* -*- mode: c -*- */

/* Copyright (C) 2020 Alexander Chernov <cher@ejudge.ru> */

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

static inline int
apikey_cmp(const char *p1, const char *p2)
{
  const unsigned int *k1 = (const unsigned int*) p1;
  const unsigned int *k2 = (const unsigned int*) p2;

  if (k1[0] < k2[0]) return -1;
  if (k1[0] > k2[0]) return 1;
  if (k1[1] < k2[1]) return -1;
  if (k1[1] > k2[1]) return 1;
  if (k1[2] < k2[2]) return -1;
  if (k1[2] > k2[2]) return 1;
  if (k1[3] < k2[3]) return -1;
  if (k1[3] > k2[3]) return 1;
  if (k1[4] < k2[4]) return -1;
  if (k1[4] > k2[4]) return 1;
  if (k1[5] < k2[5]) return -1;
  if (k1[5] > k2[5]) return 1;
  if (k1[6] < k2[6]) return -1;
  if (k1[6] > k2[6]) return 1;
  if (k1[7] < k2[7]) return -1;
  if (k1[7] > k2[7]) return 1;
  return 0;
}

static void
api_key_extend(struct uldb_mysql_state *state)
{
  struct api_key_cache *apk = &state->api_keys;

  if (!apk->size) {
    apk->size = API_KEY_POOL_SIZE;
    apk->token_index = calloc(apk->size, sizeof(apk->token_index[0]));
    apk->secret_index = calloc(apk->size, sizeof(apk->secret_index[0]));
    apk->entries = calloc(apk->size, sizeof(apk->entries[0]));
    // entry [0] is unused
    for (int i = 1; i < apk->size; ++i) {
      struct api_key_cache_entry *e = &apk->entries[i];
      if (i < apk->size - 1) {
        e->next_entry = i + 1;
      }
      if (i > 1) {
        e->prev_entry = i - 1;
      }
    }
    apk->first_free = 1;
    apk->last_free = apk->size - 1;
  } else {
    int new_size = apk->size * 2;
    apk->token_index = realloc(apk->token_index, new_size * sizeof(apk->token_index[0]));
    apk->secret_index = realloc(apk->secret_index, new_size * sizeof(apk->secret_index[0]));
    apk->entries = realloc(apk->entries, new_size * sizeof(apk->entries[0]));
    memset(apk->entries + apk->size, 0, (new_size - apk->size) * sizeof(apk->entries[0]));
    for (int i = apk->size; i < new_size; ++i) {
      struct api_key_cache_entry *e = &apk->entries[i];
      e->prev_entry = apk->last_free;
      if (e->prev_entry) {
        struct api_key_cache_entry *pe = &apk->entries[apk->last_free];
        pe->next_entry = i;
      } else {
        apk->first_free = i;
      }
      apk->last_free = i;
    }
    apk->size = new_size;
  }
}

static int
api_key_cache_index_find(struct uldb_mysql_state *state, const char *token)
{
  struct api_key_cache *apk = &state->api_keys;
  int low = 0, high = apk->token_index_count, mid = 0;
  while (low < high) {
    mid = (low + high) / 2;
    int r = apikey_cmp(apk->entries[apk->token_index[mid]].api_key.token, token);
    if (!r) {
      return apk->token_index[mid];
    } else if (r < 0) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }
  return 0;
}

static __attribute__((unused)) int
api_key_cache_secret_find(struct uldb_mysql_state *state, const char *secret)
{
  struct api_key_cache *apk = &state->api_keys;
  int low = 0, high = apk->secret_index_count, mid = 0;
  while (low < high) {
    mid = (low + high) / 2;
    int r = apikey_cmp(apk->entries[apk->secret_index[mid]].api_key.secret, secret);
    if (!r) {
      return apk->secret_index[mid];
    } else if (r < 0) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }
  return 0;
}

static int
api_key_cache_index_insert(struct uldb_mysql_state *state, int index)
{
  struct api_key_cache *apk = &state->api_keys;
  struct api_key_cache_entry *e = &apk->entries[index];
  int low = 0, high = apk->token_index_count, mid = 0;
  while (low < high) {
    mid = (low + high) / 2;
    int r = apikey_cmp(apk->entries[apk->token_index[mid]].api_key.token, e->api_key.token);
    if (!r) {
      return 0;
    } else if (r < 0) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }
  memmove(&apk->token_index[low + 1], &apk->token_index[low], (apk->token_index_count - low) * sizeof(apk->token_index[0]));
  apk->token_index[low] = index;
  ++apk->token_index_count;
  return 1;
}

static __attribute__((unused)) int
api_key_cache_secret_insert(struct uldb_mysql_state *state, int index)
{
  struct api_key_cache *apk = &state->api_keys;
  struct api_key_cache_entry *e = &apk->entries[index];
  int low = 0, high = apk->secret_index_count, mid = 0;
  while (low < high) {
    mid = (low + high) / 2;
    int r = apikey_cmp(apk->entries[apk->secret_index[mid]].api_key.secret, e->api_key.secret);
    if (!r) {
      return 0;
    } else if (r < 0) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }
  memmove(&apk->secret_index[low + 1], &apk->secret_index[low], (apk->secret_index_count - low) * sizeof(apk->secret_index[0]));
  apk->secret_index[low] = index;
  ++apk->secret_index_count;
  return 1;
}

static int
api_key_cache_index_remove(struct uldb_mysql_state *state, int index)
{
  struct api_key_cache *apk = &state->api_keys;
  struct api_key_cache_entry *e = &apk->entries[index];
  int low = 0, high = apk->token_index_count, mid = 0;
  while (low < high) {
    mid = (low + high) / 2;
    int r = apikey_cmp(apk->entries[apk->token_index[mid]].api_key.token, e->api_key.token);
    if (!r) {
      memmove(&apk->token_index[mid], &apk->token_index[mid + 1], (apk->token_index_count - mid - 1) * sizeof(apk->token_index[0]));
      --apk->token_index_count;
      return 1;
    } else if (r < 0) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }
  return 0;
}

static __attribute__((unused)) int
api_key_cache_secret_remove(struct uldb_mysql_state *state, int index)
{
  struct api_key_cache *apk = &state->api_keys;
  struct api_key_cache_entry *e = &apk->entries[index];
  int low = 0, high = apk->secret_index_count, mid = 0;
  while (low < high) {
    mid = (low + high) / 2;
    int r = apikey_cmp(apk->entries[apk->secret_index[mid]].api_key.secret, e->api_key.secret);
    if (!r) {
      memmove(&apk->secret_index[mid], &apk->secret_index[mid + 1], (apk->secret_index_count - mid - 1) * sizeof(apk->secret_index[0]));
      --apk->secret_index_count;
      return 1;
    } else if (r < 0) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }
  return 0;
}

static void
api_key_cache_unlink(struct uldb_mysql_state *state, int index)
{
  struct api_key_cache *apk = &state->api_keys;
  struct api_key_cache_entry *e = &apk->entries[index];

  if (e->prev_entry) {
    struct api_key_cache_entry *pe = &apk->entries[e->prev_entry];
    pe->next_entry = e->next_entry;
  } else {
    apk->first_entry = e->next_entry;
  }
  if (e->next_entry) {
    struct api_key_cache_entry *ne = &apk->entries[e->next_entry];
    ne->prev_entry = e->prev_entry;
  } else {
    apk->last_entry = e->prev_entry;
  }
  e->next_entry = 0;
  e->prev_entry = 0;
}

static void
api_key_cache_free(struct uldb_mysql_state *state, int index)
{
  struct api_key_cache *apk = &state->api_keys;
  struct api_key_cache_entry *e = &apk->entries[index];

  xfree(e->api_key.payload);
  xfree(e->api_key.origin);
  memset(e, 0, sizeof(*e));
  e->prev_entry = apk->last_free;
  if (apk->last_free) {
    struct api_key_cache_entry *pe = &apk->entries[apk->last_free];
    pe->next_entry = index;
  } else {
    apk->first_free = index;
  }
  apk->last_free = index;
}

static void
api_key_cache_link(struct uldb_mysql_state *state, int index, int where)
{
  struct api_key_cache *apk = &state->api_keys;
  struct api_key_cache_entry *e = &apk->entries[index];

  if (!where) {
    // to the front of the list
    e->next_entry = apk->first_entry;
    if (e->next_entry) {
      struct api_key_cache_entry *ne = &apk->entries[e->next_entry];
      ne->prev_entry = index;
    } else {
      apk->last_entry = index;
    }
    apk->first_entry = index;
  } else {
    struct api_key_cache_entry *we = &apk->entries[where];
    e->next_entry = where;
    if (we->prev_entry) {
      struct api_key_cache_entry *pe = &apk->entries[we->prev_entry];
      pe->next_entry = index;
    } else {
      apk->first_entry = index;
    }
    e->prev_entry = we->prev_entry;
    we->prev_entry = index;
  }
}

static int
api_key_cache_allocate(struct uldb_mysql_state *state)
{
  struct api_key_cache *apk = &state->api_keys;

  if (!apk->last_free) {
    api_key_extend(state);
  }
  assert(apk->last_free);

  int index = apk->first_free;
  struct api_key_cache_entry *e = &apk->entries[index];
  if (e->next_entry) {
    struct api_key_cache_entry *ne = &apk->entries[e->next_entry];
    ne->prev_entry = 0;
  } else {
    apk->last_free = 0;
  }
  apk->first_free = e->next_entry;

  e->prev_entry = 0;
  e->next_entry = 0;

  return index;
}

static int
api_key_parse(
        struct uldb_mysql_state *state,
        struct userlist_api_key *apk)
{
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;

  if (mi->parse_spec(md, md->field_count, md->row,
                     md->lengths, APIKEY_WIDTH, apikey_spec, apk) < 0)
    goto fail;

  return 0;

 fail:
  return -1;
}
