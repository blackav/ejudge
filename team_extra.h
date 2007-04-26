/* -*- c -*- */
/* $Id$ */

#ifndef __TEAM_EXTRA_H__
#define __TEAM_EXTRA_H__

/* Copyright (C) 2004-2007 Alexander Chernov <cher@ejudge.ru> */

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
  int is_dirty;
  int user_id;
  int clar_map_size;
  int clar_map_alloc;
  unsigned long *clar_map;

  // disqualification reason
  unsigned char *disq_comment;

  // warnings
  int warn_u, warn_a;
  struct team_warning **warns;

  // status
  int status;
};

struct team_extra_state;
typedef struct team_extra_state *team_extra_state_t;

team_extra_state_t team_extra_init(void);
team_extra_state_t team_extra_destroy(team_extra_state_t);
int team_extra_set_dir(team_extra_state_t, const unsigned char *);
int team_extra_parse_xml(const unsigned char *path, struct team_extra **pte);
int team_extra_unparse_xml(FILE *f, struct team_extra *te);

void team_extra_flush(team_extra_state_t state);

int team_extra_get_clar_status(team_extra_state_t state,
                               int user_id, int clar_id);
int team_extra_set_clar_status(team_extra_state_t, int user_id, int clar_id);

const struct team_extra* team_extra_get_entry(team_extra_state_t state,
                                              int user_id);

int team_extra_append_warning(team_extra_state_t state,
                              int user_id,
                              int issuer_id,
                              ej_ip_t issuer_ip,
                              time_t issue_date,
                              const unsigned char *txt,
                              const unsigned char *cmt);

int team_extra_set_status(team_extra_state_t state, int user_id, int status);
int team_extra_set_disq_comment(team_extra_state_t state, int user_id,
                                const unsigned char *disq_comment);

#endif /* __TEAM_EXTRA_H__ */

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "DIR")
 * End:
 */
