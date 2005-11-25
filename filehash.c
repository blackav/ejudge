/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005 Alexander Chernov <cher@ispras.ru> */

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

#include "ej_types.h"

#include "filehash.h"
#include "timestamp.h"
#include "sha.h"
#include "pathutl.h"
#include "errlog.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <string.h>
#include <stdio.h>

#define SHA1_SIZE 20

struct hash_entry
{
  unsigned long path_hash;
  unsigned char *path;
  unsigned char sha1_hash[SHA1_SIZE];
  file_stamp_t stamp;
  unsigned tick;
};

#define HASH_SIZE 4099
#define HASH_STEP 23
#define HASH_CAP  2048

static struct hash_entry *hash_table[HASH_SIZE];
static int hash_use = 0;
static unsigned cur_tick = 1;

/* this is a copy of `userlist_login_hash' */
static const unsigned char id_hash_map[256] =
{
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,64,62,65,
   0, 1, 2, 3, 4, 5, 6, 7, 8, 9,65,65,65,65,65,65,
  65,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,
  25,26,27,28,29,30,31,32,33,34,35,65,65,65,65,63,
  65,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,
  51,52,53,54,55,56,57,58,59,60,61,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
};

static unsigned long
get_hash(const unsigned char *p)
{
  unsigned long hash = 0;

  for (; *p; p++)
    hash = hash * 66 + id_hash_map[*p];
  return hash;
}

static struct hash_entry *
free_hash_item(struct hash_entry *p)
{
  if (!p) return 0;
  xfree(p->path);
  file_stamp_free(p->stamp);
  xfree(p);
  return 0;
}

static void
add_hash_item(struct hash_entry *p)
{
  int idx = p->path_hash % HASH_SIZE;

  while (hash_table[idx]) {
    idx = (idx + HASH_STEP) % HASH_SIZE;
  }
  hash_table[idx] = p;
}

static struct hash_entry *
remove_hash_item(int idx)
{
  int cnt = 0, i, j = 0;
  struct hash_entry *retval;
  struct hash_entry **saved_entries = 0;

  // count the items after this one
  ASSERT(hash_table[idx]);
  retval = hash_table[idx];
  i = (idx + HASH_STEP) % HASH_SIZE;
  while (hash_table[i]) {
    cnt++;
    i = (i + HASH_STEP) % HASH_SIZE;
  }
  if (!cnt) {
    hash_table[idx] = 0;
    return retval;
  }

  XALLOCAZ(saved_entries, cnt);
  i = idx;
  hash_table[i] = 0;
  i = (i + HASH_STEP) % HASH_SIZE;
  while (hash_table[i]) {
    saved_entries[j++] = hash_table[i];
    hash_table[i] = 0;
    i = (i + HASH_STEP) % HASH_SIZE;
  }
  ASSERT(j == cnt);

  for (j = 0; j < cnt; j++)
    add_hash_item(saved_entries[j]);
  return retval;
}

int
filehash_get(const unsigned char *path, unsigned char *val)
{
  unsigned long p_hash;
  unsigned int idx, i, min_i;
  struct hash_entry *p, *q;
  FILE *f = 0;
  unsigned min_tick;

  ASSERT(path);
  p_hash = get_hash(path);

  idx = p_hash % HASH_SIZE;
  while (hash_table[idx] && hash_table[idx]->path_hash == p_hash
         && strcmp(hash_table[idx]->path, path) != 0) {
    idx = (idx + HASH_STEP) % HASH_SIZE;
  }
  if (hash_table[idx] && hash_table[idx]->path_hash == p_hash) {
    // hit!
    if (!file_stamp_is_updated(path, hash_table[idx]->stamp)) {
      info("entry <%s> is in hash table and is not changed", path);
      memcpy(val, hash_table[idx]->sha1_hash, SHA1_SIZE);
      hash_table[idx]->tick = cur_tick++;
      return 0;
    }
    // update the hash code, maybe removing an item
    info("entry <%s> is in hash table and is CHANGED!", path);
    hash_table[idx]->stamp = file_stamp_update(path, hash_table[idx]->stamp);
    if (!hash_table[idx]->stamp || !(f = fopen(path, "rb"))
        || sha_stream(f, hash_table[idx]->sha1_hash)) {
      // file no longer exists or I/O error
      if (f) fclose(f);
      p = remove_hash_item(idx);
      free_hash_item(p);
      hash_use--;
      return -1;
    }
    // recalculate the hash
    fclose(f);
    memcpy(val, hash_table[idx]->sha1_hash, SHA1_SIZE);
    hash_table[idx]->tick = cur_tick++;
    return 0;
  }

  // no entry in the hash table
  XCALLOC(p, 1);
  if (!(p->stamp = file_stamp_get(path))
      || !(f = fopen(path, "rb"))
      || sha_stream(f, p->sha1_hash)) {
    if (f) fclose(f);
    free_hash_item(p);
    return -1;
  }
  fclose(f);
  p->path_hash = p_hash;
  p->path = xstrdup(path);
  p->tick = cur_tick++;
  memcpy(val, p->sha1_hash, SHA1_SIZE);
  if (hash_use < HASH_CAP) {
    info("entry <%s> is not in the hash table - adding", path);
    add_hash_item(p);
    hash_use++;
    return 0;
  }

  // find the least recently used entry and remove it
  info("entry <%s> is not in the hash table - REPLACING", path);
  min_i = -1;
  min_tick = cur_tick;
  for (i = 0; i < HASH_SIZE; i++)
    if (hash_table[i] && hash_table[i]->tick < min_tick) {
      min_i = i;
      min_tick = hash_table[i]->tick;
    }
  ASSERT(min_i >= 0);
  q = remove_hash_item(min_i);
  free_hash_item(q);
  add_hash_item(p);
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
