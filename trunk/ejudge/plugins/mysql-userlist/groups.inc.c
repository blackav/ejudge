/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2010 Alexander Chernov <cher@ejudge.ru> */

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
{
  state->mi->unparse_spec(state->md,fout,USERGROUP_WIDTH,usergroup_spec,grp);
}

#undef FAIL

/*
 * Local variables:
 *  compile-command: "make -C ../.."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "MYSQL")
 * End:
 */
