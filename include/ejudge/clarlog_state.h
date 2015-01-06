/* -*- c -*- */

#ifndef __CLARLOG_STATE_H__
#define __CLARLOG_STATE_H__

/* Copyright (C) 2008-2015 Alexander Chernov <cher@ejudge.ru> */

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

struct cldb_plugin_iface;
struct cldb_plugin_data;
struct cldb_plugin_cnts;

/* new version of the clarification log */
struct clar_array
{
  int                   a, u;
  struct clar_entry_v2 *v;
};

struct clarlog_state
{
  struct clar_array clars;

  size_t allocd;
  unsigned char **subjects;
  int *charset_codes;

  // the managing plugin information
  struct cldb_plugin_iface *iface;
  struct cldb_plugin_data *data;
  struct cldb_plugin_cnts *cnts;
};

#endif /* __CLARLOG_STATE_H__ */
