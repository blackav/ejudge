/* -*- c -*- */

#ifndef __TEAM_EXTRA_H__
#define __TEAM_EXTRA_H__

/* Copyright (C) 2004-2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ej_types.h"

#include <stdio.h>
#include <time.h>

struct team_warning
{
  time_t date;                  /* the date of issue */
  int issuer_id;                /* the issuer id */
  ej_ip_t issuer_ip;            /* the ip of the issuer */
  unsigned char *text;          /* the text of the warning (reported to user)*/
  unsigned char *comment;       /* the comment for other judges */
};

struct team_extra
{
  // primary key
  ej_uuid_t uuid;

  int is_dirty;
  int user_id;
  int contest_id;

  int clar_map_size;
  int clar_map_alloc;
  unsigned long *clar_map;

  /* the sorted vector of viewed clar uuids */
  int clar_uuids_size;
  int clar_uuids_alloc;
  ej_uuid_t *clar_uuids;

  // disqualification reason
  unsigned char *disq_comment;

  // warnings
  int warn_u, warn_a;
  struct team_warning **warns;

  // status
  int status;

  // run table fields
  int run_fields;
};

struct team_extra *team_extra_free(struct team_extra *te);
void team_extra_extend_clar_map(struct team_extra *te, int clar_id);

int
team_extra_find_clar_uuid(
        struct team_extra *te,
        const ej_uuid_t *puuid);
/* returns: -1 error, 0 - already exists, 1 - added */
int
team_extra_add_clar_uuid(
        struct team_extra *te,
        const ej_uuid_t *puuid);

int team_extra_parse_xml(const unsigned char *path, struct team_extra **pte);
int team_extra_unparse_xml(FILE *f, const struct team_extra *te);

struct xuser_cnts_state;
struct ejudge_cfg;
struct contest_desc;
struct section_global_data;

struct xuser_cnts_state *
team_extra_open(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        const unsigned char *plugin_name,
        int flags);

#endif /* __TEAM_EXTRA_H__ */

/*
 * Local variables:
 *  compile-command: "make"
 * End:
 */
