/* -*- c -*- */
/* $Id$ */

#ifndef __CLDB_PLUGIN_H__
#define __CLDB_PLUGIN_H__

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge_plugin.h"
#include "ej_types.h"
#include "iterators.h"
#include "ejudge_cfg.h"

struct contest_desc;
struct section_global_data;

/* version of the plugin interface structure */
#define CLDB_PLUGIN_IFACE_VERSION 1

struct clarlog_state;
struct cldb_plugin_data;
struct cldb_plugin_cnts;

struct cldb_plugin_iface
{
  struct ejudge_plugin_iface b;
  int cldb_version;

  // initialize the plugin
  struct cldb_plugin_data *(*init)(const struct ejudge_cfg*);
  // close the database flushing all the data, if necessary
  int (*finish)(struct cldb_plugin_data *);
  // parse the plugin arguments
  int (*prepare)(struct cldb_plugin_data *, const struct ejudge_cfg *,
                 const struct xml_tree*);
  // open a contest
  struct cldb_plugin_cnts *(*open)(struct cldb_plugin_data *,
                                   struct clarlog_state *,
                                   const struct ejudge_cfg *,
                                   const struct contest_desc *,
                                   const struct section_global_data *,
                                   int flags);
  // close a contest
  struct cldb_plugin_cnts *(*close)(struct cldb_plugin_cnts *);
  // create a new clarlog erasing the old contents
  int (*create_new)(struct cldb_plugin_cnts *);
  // add a new entry
  int (*add_entry)(struct cldb_plugin_cnts *, int);
  // update entry flags
  int (*set_flags)(struct cldb_plugin_cnts *, int);
  // update entry charset
  int (*set_charset)(struct cldb_plugin_cnts *, int);
};

/* default plugin: compiled into new-server */
extern struct cldb_plugin_iface cldb_plugin_file;

#endif /* __CLDB_PLUGIN_H__ */
