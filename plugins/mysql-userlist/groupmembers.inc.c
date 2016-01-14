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
parse_groupmember(
        struct uldb_mysql_state *state,
        int field_count,
        char **row,
        unsigned long *lengths,
        struct userlist_groupmember *gm)
{
  if (state->mi->parse_spec(state->md, field_count, row, lengths,
                            USERGROUPMEMBER_WIDTH, usergroupmember_spec, gm)<0)
    return -1;
  return 0;
}

#undef FAIL
