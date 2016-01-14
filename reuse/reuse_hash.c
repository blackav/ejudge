/* Copyright (C) 1996-2016 Alexander Chernov <cher@ejudge.ru> */
/* Created: Fri Nov  1 18:46:25 1996 by cher (Alexander Chernov) */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

/**
 * FILE:    utils/hash.c
 * PURPOSE: identifier hash table support
 */

#include "ejudge/xalloc.h"
#include "ejudge/hash_priv.h"

#include <assert.h>
#include <string.h>

/* state of the module */
hashstate_t ident_state;

/**
 * NAME:    ident_init
 * PURPOSE: initialize the module
 */
void
ident_init(void)
{
  ident_state.initialized = 1;
  ident_state.table = (hashentry_t*) xcalloc(INIT_SIZE, sizeof(hashentry_t));
  ident_state.map = (int*) xcalloc(INIT_SIZE, sizeof(int));
  ident_state.table_size = INIT_SIZE;
  ident_state.rehash_size = (ident_state.table_size * 7) / 10;
  ident_state.total_idents = 1;
  ident_state.map[0] = 0;

  ident_state.table[0].hash = 1;
  ident_state.table[0].string = xstrdup("");
  ident_state.table[0].len = 0;
  ident_state.table[0].ident = 0;
  /* ident_empty = 0; */
}

/**
 * NAME:    ident_do_put
 * PURPOSE: put entry into the hash table
 * ARGS:    hash  - hash code
 *          str   - identifier string to put
 *          ident - assigned identifier number
 *          len   - identifier string length
 * RETURN:  index in the hash table
 */
static int
ident_do_put(hash_t hash, char *str, ident_t ident, int len)
{
  hash_t index = hash % ident_state.table_size;

  while (ident_state.table[index].hash != 0)
    index = (index + HASH_STEP) % ident_state.table_size;

  ident_state.table[index].hash = hash;
  ident_state.table[index].string = str;
  ident_state.table[index].ident = ident;
  ident_state.table[index].len = len;
  return index;
}

/**
 * NAME:    ident_rehash
 * PURPOSE: increase the size and rehash the hash table
 */
  static void
ident_rehash(void)
{
  int         *old_map;
  hashentry_t *old_table;
  int         cntr;

  /* Backup old pointers */
  old_map = ident_state.map;
  old_table = ident_state.table;

  /* Allocate new space */
  ident_state.table_size *= 2;
  ident_state.rehash_size *= 2;
  ident_state.map = (int*) xcalloc(ident_state.table_size, sizeof(int));
  ident_state.table = (hashentry_t*) xcalloc(ident_state.table_size, sizeof(hashentry_t));

  /* Put empty identifier */
  ident_state.map[0] = 0;
  ident_state.table[0].hash = 1;
  ident_state.table[0].string = old_table[0].string;
  ident_state.table[0].ident = 0;
  ident_state.table[0].len = 0;

  /* Rehash the whole table */
  for (cntr = 1; cntr < ident_state.total_idents; cntr++)
    {
      ident_state.stat_cycles_num++;
      ident_state.map[cntr] = ident_do_put(old_table[old_map[cntr]].hash,
                                           old_table[old_map[cntr]].string,
                                           cntr,
                                           old_table[old_map[cntr]].len);
    }

  /* Drop old tables */
  free(old_table);
  free(old_map);

  ident_state.stat_rehash_num++;
}

/**
 * NAME:    ident_hash
 * PURPOSE: calculate the hash function for the string
 * ARGS:    str - string to calculate the hash
 *          len - string length
 * RETURN:  calculated hash function
 */
  hash_t
ident_hash(char const *str, int len)
{
  hash_t hash = 1;
  hash_t multip = 1;

  for (str += len - 1;len;len--,str--,multip *= 26)
    {
      hash += ((hash_t) *str)*multip;
    }
  return hash;
}

/**
 * NAME:    ident_put
 * PURPOSE: add string to the hash table
 * ARGS:    str - string to add
 *          len - string length
 * RETURN:  identifier number of the added string
 * NOTE:    str might be not \0 terminated
 */
ident_t
ident_put(char const *str, int len)
{
  hash_t hash;
  hash_t index;
  char   *str_dup;

  if (!ident_state.initialized) ident_init();

  assert(len >= 0);
  ident_state.stat_lookups_num++;

  if (len == 0)
    {
      ident_state.stat_success_num++;
      return ident_empty;
    }

  hash = ident_hash(str, len);
  index = hash % ident_state.table_size;
  ident_state.stat_cycles_num++;
  while (ident_state.table[index].hash != 0)
    {
      if (ident_state.table[index].hash == hash
          && ident_state.table[index].len == len)
        {
          if (!strncmp(str, ident_state.table[index].string, len))
            {
              ident_state.stat_success_num++;
              return ident_state.table[index].ident;
            }
        }
      index = (index + HASH_STEP) % ident_state.table_size;
      ident_state.stat_cycles_num++;
    }
  
  /* make the duplicate of the string */
  str_dup = (char*) xmalloc(len + 1);
  memcpy(str_dup, str, len);
  str_dup[len] = 0;

  /* Not found in the table */
  if (ident_state.total_idents >= ident_state.rehash_size)
    {
      ident_rehash();
      /* The old calculated index is invalid, so we should make new one */
      ident_state.map[ident_state.total_idents] = ident_do_put(hash, str_dup, ident_state.total_idents, len);
    }
  else
    {
      /* Use already calculated slot */
      ident_state.map[ident_state.total_idents] = index;
      ident_state.table[index].hash = hash;
      ident_state.table[index].string = str_dup;
      ident_state.table[index].ident = ident_state.total_idents;
      ident_state.table[index].len = len;
    }
  return ident_state.total_idents++;
}

/**
 * NAME:    ident_get
 * PURPOSE: get string by the identifier number
 * ARGS:    id - identifier number
 * RETURN:  string in the hash table (MUST NOT BE ALTERED)
 */
char *
ident_get(ident_t id)
{
  if (!ident_state.initialized) ident_init();

  assert(/*id >= 0 && */id < (ident_t) ident_state.total_idents);
  return ident_state.table[ident_state.map[id]].string;
}
