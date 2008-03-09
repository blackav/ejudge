/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004-2008 Alexander Chernov <cher@ejudge.ru> */

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
#include <stdarg.h>

static int iset_a = 0;
static unsigned char *iset = 0;
static unsigned char *cfg_path = 0;
static unsigned char *progname = 0;
static unsigned char *keyword = 0;

static struct ejudge_cfg  *config;
static struct userlist_list *userlist;

static void fatal(const char *format, ...)
  __attribute__((noreturn, format(printf, 1, 2)));
static void
fatal(const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: %s\n", progname, buf);
  exit(1);
}

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

  if (sscanf(str, "%d%n", &v, &n) != 1 || str[n])
    fatal("contest number expected");
  if (v <= 0 || v > 100000)
    fatal("invalid contest number %d", v);
  do_add_to_set(v, pa, ps);
}

static void
process_keywords(void)
{
  int contest_size, i, r;
  unsigned char *contests;
  const struct contest_desc *cnts = 0;

  contest_size = contests_get_list(&contests);
  if (contest_size <= 0 || !contests)
    fatal("no contests");

  for (i = 1; i < contest_size; i++) {
    if (!contests[i]) continue;
    cnts = 0;
    if ((r = contests_get(i, &cnts)) < 0 || !cnts) {
      fatal("cannot load contest %d: %s", i, contests_strerror(-r));
    }
    if (cnts->keywords && strcasestr(cnts->keywords, keyword)) {
      fprintf(stderr, "contest %d matches\n", i);
      do_add_to_set(i, &iset_a, &iset);
    }
  }
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
      if (i + 1 >= argc) fatal("argument expected for -i");
      add_to_set(argv[i + 1], &iset_a, &iset);
      i += 2;
    } else if (!strcmp(argv[i], "-k")) {
      if (i + 1 >= argc) fatal("argument expected for -k");
      keyword = argv[i + 1];
      i += 2;
    } else if (argv[i][0] == '-') {
      fatal("unknown option `%s'", argv[i]);
    } else {
      break;
    }
  }

  if (i < argc) {
    cfg_path = argv[i];
    i++;
  }
  if (i < argc) fatal("extra parameters");

#if defined EJUDGE_XML_PATH
  if (!cfg_path) cfg_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */

  fprintf(stderr, "collect-emails %s, compiled %s\n",
          compile_version, compile_date);
  config = ejudge_cfg_parse(cfg_path);
  if (!config) return 1;

  if (keyword) {
    if (!config->contests_dir) fatal("<contests_dir> tag is not set!");
    if (contests_set_directory(config->contests_dir) < 0)
      fatal("contests directory is invalid");
    process_keywords();
  }

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

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
