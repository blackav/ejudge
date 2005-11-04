/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2004,2005 Alexander Chernov <cher@ispras.ru> */

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

#include "ej_limits.h"
#include "team_extra.h"
#include "prepare.h"
#include "prepare_vars.h"
#include "pathutl.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_USER_ID_32DIGITS 4
#define BPE (CHAR_BIT * sizeof(((struct team_extra*)0)->clar_map[0]))

static size_t team_map_size = 0;
static struct team_extra **team_map;

static const unsigned char b32_digits[]=
"0123456789ABCDEFGHIJKLMNOPQRSTUV";
static void
b32_number(unsigned num, size_t size, unsigned char buf[])
{
  int i;

  ASSERT(size > 1);

  memset(buf, '0', size - 1);
  buf[size - 1] = 0;
  i = size - 2;
  while (num > 0 && i >= 0) {
    buf[i] = b32_digits[num & 0x1f];
    i--;
    num >>= 5;
  }
  ASSERT(!num);
}

static int
make_read_path(unsigned char *path, size_t size, int user_id)
{
  unsigned char b32[16];

  ASSERT(user_id > 0 && user_id <= EJ_MAX_USER_ID);
  b32_number(user_id, MAX_USER_ID_32DIGITS + 1, b32);
  return snprintf(path, size, "%s/%c/%c/%c/%06d.xml",
                  global->team_extra_dir, b32[0], b32[1], b32[2], user_id);
}

static int
make_write_path(unsigned char *path, size_t size, int user_id)
{
  unsigned char b32[16];
  unsigned char *mpath = 0, *p;
  struct stat sb;
  int i;

  ASSERT(user_id > 0 && user_id <= EJ_MAX_USER_ID);
  b32_number(user_id, MAX_USER_ID_32DIGITS + 1, b32);

  mpath = alloca(strlen(global->team_extra_dir) + 32);
  strcpy(mpath, global->team_extra_dir);
  p = mpath + strlen(mpath);
  for (i = 0; i < MAX_USER_ID_32DIGITS - 1; i++) {
    *p++ = '/';
    *p++ = b32[i];
    *p = 0;
    if (mkdir(mpath, 0700) < 0) {
      if (errno != EEXIST) {
        err("team_extra: %s: mkdir failed: %s", mpath, os_ErrorMsg());
        return -1;
      }
      if (lstat(mpath, &sb) < 0) {
        err("team_extra: %s: lstat failed: %s", mpath, os_ErrorMsg());
        return -1;
      }
      if (!S_ISDIR(sb.st_mode)) {
        err("team_extra: %s: is not a directory", mpath);
        return -1;
      }
    }
  }

  return snprintf(path, size, "%s/%c/%c/%c/%06d.xml",
                  global->team_extra_dir, b32[0], b32[1], b32[2], user_id);
}

static void
extend_team_map(int user_id)
{
  size_t new_size = team_map_size;
  struct team_extra **new_map = 0;

  if (!new_size) new_size = 32;
  while (new_size <= user_id) new_size *= 2;
  XCALLOC(new_map, new_size);
  if (team_map_size > 0) {
    memcpy(new_map, team_map, team_map_size * sizeof(new_map[0]));
    xfree(team_map);
  }
  team_map = new_map;
  team_map_size = new_size;
}

static struct team_extra *
get_entry(int user_id)
{
  struct team_extra *te = team_map[user_id];
  path_t rpath;
  struct stat sb;

  if (te) return te;

  make_read_path(rpath, sizeof(rpath), user_id);
  if (lstat(rpath, &sb) < 0) {
    XCALLOC(te, 1);
    te->user_id = user_id;
    team_map[user_id] = te;
    return te;
  }
  if (!S_ISREG(sb.st_mode)) {
    err("team_extra: %s: not a regular file", rpath);
    team_map[user_id] = (struct team_extra*) -1;
    return (struct team_extra*) -1;
  }
  if (team_extra_parse_xml(rpath, &te) < 0) {
    team_map[user_id] = (struct team_extra*) -1;
    return (struct team_extra*) -1;
  }
  if (te->user_id != user_id) {
    err("team_extra: %s: user_id mismatch: %d, %d",
        rpath, te->user_id, user_id);
    team_map[user_id] = (struct team_extra*) -1;
    return (struct team_extra*) -1;
  }
  team_map[user_id] = te;
  return te;
}

struct team_extra*
team_extra_get_entry(int user_id)
{
  struct team_extra *tmpval;

  ASSERT(user_id > 0 && user_id <= EJ_MAX_USER_ID);
  if (user_id >= team_map_size) extend_team_map(user_id);

  tmpval = get_entry(user_id);
  if (tmpval == (struct team_extra*) -1) tmpval = 0;
  return tmpval;
}

static void
extend_clar_map(struct team_extra *te, int clar_id)
{
  int new_size = te->clar_map_size;
  int new_alloc;
  unsigned long *new_map = 0;

  if (!new_size) new_size = 128;
  while (new_size <= clar_id) new_size *= 2;
  new_alloc = new_size / BPE;
  XCALLOC(new_map, new_alloc);
  if (te->clar_map_size > 0) {
    memcpy(new_map, te->clar_map, sizeof(new_map[0]) * te->clar_map_alloc);
    xfree(te->clar_map);
  }
  te->clar_map_size = new_size;
  te->clar_map_alloc = new_alloc;
  te->clar_map = new_map;
}

int
team_extra_get_clar_status(int user_id, int clar_id)
{
  struct team_extra *te;

  ASSERT(user_id > 0 && user_id <= EJ_MAX_USER_ID);
  ASSERT(clar_id >= 0 && clar_id <= EJ_MAX_CLAR_ID);

  if (user_id >= team_map_size) extend_team_map(user_id);
  te = get_entry(user_id);
  if (te == (struct team_extra*) -1) return -1;
  ASSERT(te->user_id == user_id);

  if (clar_id >= te->clar_map_size) return 0;
  if ((te->clar_map[clar_id / BPE] & (1UL << clar_id % BPE)))
    return 1;
  return 0;
}

int
team_extra_set_clar_status(int user_id, int clar_id)
{
  struct team_extra *te;

  ASSERT(user_id > 0 && user_id <= EJ_MAX_USER_ID);
  ASSERT(clar_id >= 0 && clar_id <= EJ_MAX_CLAR_ID);

  if (user_id >= team_map_size) extend_team_map(user_id);
  te = get_entry(user_id);
  if (te == (struct team_extra*) -1) return -1;
  ASSERT(te->user_id == user_id);
  if (clar_id >= te->clar_map_size) extend_clar_map(te, clar_id);
  if ((te->clar_map[clar_id / BPE] & (1UL << clar_id % BPE)))
    return 1;
  te->clar_map[clar_id / BPE] |= (1UL << clar_id % BPE);
  te->is_dirty = 1;
  return 0;
}

void
team_extra_flush(void)
{
  int i;
  path_t wpath;
  FILE *f;

  for (i = 1; i < team_map_size; i++) {
    if (!team_map[i]) continue;
    if (team_map[i] == (struct team_extra*) -1) continue;
    ASSERT(team_map[i]->user_id == i);
    if (!team_map[i]->is_dirty) continue;
    if (make_write_path(wpath, sizeof(wpath), i) < 0) continue;
    if (!(f = fopen(wpath, "w"))) {
      unlink(wpath);
      continue;
    }
    team_extra_unparse_xml(f, team_map[i]);
    fclose(f);
    team_map[i]->is_dirty = 0;
  }
}

int
team_extra_append_warning(int user_id,
                          int issuer_id, ej_ip_t issuer_ip,
                          time_t issue_date,
                          const unsigned char *txt,
                          const unsigned char *cmt)
{
  struct team_extra *te;
  struct team_warning *cur_warn;

  ASSERT(user_id > 0 && user_id <= EJ_MAX_USER_ID);

  if (user_id >= team_map_size) extend_team_map(user_id);
  te = get_entry(user_id);
  if (te == (struct team_extra*) -1) return -1;
  ASSERT(te->user_id == user_id);

  if (te->warn_u == te->warn_a) {
    te->warn_a *= 2;
    if (!te->warn_a) te->warn_a = 8;
    XREALLOC(te->warns, te->warn_a);
  }
  XCALLOC(cur_warn, 1);
  te->warns[te->warn_u++] = cur_warn;

  cur_warn->date = issue_date;
  cur_warn->issuer_id = issuer_id;
  cur_warn->issuer_ip = issuer_ip;
  cur_warn->text = xstrdup(txt);
  cur_warn->comment = xstrdup(cmt);

  te->is_dirty = 1;
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
