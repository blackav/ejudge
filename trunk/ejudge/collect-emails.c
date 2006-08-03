/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004-2006 Alexander Chernov <cher@unicorn.cmc.msu.ru> */

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

#include "config.h"

#include "version.h"
#include "ejudge_cfg.h"
#include "userlist.h"

#include <reuse/xalloc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int iset_a = 0;
static unsigned char *iset = 0;
static unsigned char *cfg_path = 0;
static unsigned char *progname = 0;

static struct ejudge_cfg  *config;
static struct userlist_list *userlist;

static void
do_add_to_set(int n, int *pa, unsigned char **ps)
{
  assert(n >= 0 && n <= 100000);

  if (n >= *pa) {
    int new_a = *pa;
    unsigned char *new_s = 0;

    if (!new_a) new_a = 128;
    while (n >= new_a) new_a *= 2;
    new_s = xcalloc(new_a, 1);
    if (*pa > 0) {
      memcpy(new_s, *ps, *pa);
    }
    *ps = new_s;
    *pa = new_a;
  }
  (*ps)[n] = 1;
}

static void
add_to_set(const unsigned char *str, int *pa, unsigned char **ps)
{
  int v, n;

  if (sscanf(str, "%d%n", &v, &n) != 1 || str[n]) {
    fprintf(stderr, "%s: contest number expected\n", progname);
    exit(1);
  }
  if (v <= 0 || v > 100000) {
    fprintf(stderr, "%s: invalid contest number %d\n", progname, v);
    exit(1);
  }
  do_add_to_set(v, pa, ps);
}

int
main(int argc, char *argv[])
{
  int i = 1;
  struct userlist_user *u = 0;
  struct userlist_contest *c = 0;

  progname = argv[0];

  while (i < argc) {
    if (!strcmp(argv[i], "-i")) {
      if (i + 1 >= argc) {
        fprintf(stderr, "%s: argument expected for -i\n", argv[0]);
        return 1;
      }
      add_to_set(argv[i + 1], &iset_a, &iset);
      i += 2;
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "%s: unknown option `%s'\n", argv[0], argv[i]);
      return 1;
    } else {
      break;
    }
  }

  if (i < argc) {
    cfg_path = argv[i];
    i++;
  }
  if (i < argc) {
    fprintf(stderr, "%s: extra parameters\n", argv[0]);
    return 1;
  }

#if defined EJUDGE_XML_PATH
  if (!cfg_path) cfg_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */

  fprintf(stderr, "collect-emails %s, compiled %s\n",
          compile_version, compile_date);
  config = ejudge_cfg_parse(cfg_path);
  if (!config) return 1;

  userlist = userlist_parse(config->db_path);
  if (!userlist) return 1;

  for (i = 1; i < userlist->user_map_size; i++) {
    if (!(u = userlist->user_map[i])) continue;
    if (!strchr(u->email, '@')) continue;
    if (!u->contests) continue;
    c = (struct userlist_contest*) u->contests->first_down;
    while (c) {
      if (c->id > 0 && c->id < iset_a && iset[c->id]) break;
      c = (struct userlist_contest*) c->b.right;
    }
    if (c) {
      printf("%s\n", u->email);
    }
  }

  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
