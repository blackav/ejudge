/* -*- c -*- */
/* $Id$ */

#ifndef __TEAM_EXTRA_H__
#define __TEAM_EXTRA_H__

/* Copyright (C) 2004 Alexander Chernov <cher@ispras.ru> */

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

#include <stdio.h>

struct team_extra
{
  int is_dirty;
  int user_id;
  int clar_map_size;
  int clar_map_alloc;
  unsigned long *clar_map;
};

int team_extra_parse_xml(const unsigned char *path, struct team_extra **pte);
int team_extra_unparse_xml(FILE *f, struct team_extra *te);

void team_extra_flush(void);

int team_extra_get_clar_status(int user_id, int clar_id);
int team_extra_set_clar_status(int user_id, int clar_id);

#endif /* __TEAM_EXTRA_H__ */

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "DIR")
 * End:
 */
