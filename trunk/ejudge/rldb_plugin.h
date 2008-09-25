/* -*- c -*- */
/* $Id$ */

#ifndef __RLDB_PLUGIN_H__
#define __RLDB_PLUGIN_H__

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

/* version of the plugin interface structure */
#define RLDB_PLUGIN_IFACE_VERSION 1

struct rldb_plugin_data;
struct rldb_plugin_cnts;

struct rldb_plugin_iface
{
  struct ejudge_plugin_iface b;
  int rldb_version;

  // initialize the plugin
  struct rldb_plugin_data *(*init)(const struct ejudge_cfg*);
  // close the database flushing all the data, if necessary
  int (*finish)(struct rldb_plugin_data *);
  // open a contest
  struct rldb_plugin_cnts *(*open)(struct rldb_plugin_data *, int);
  // close a contest
  struct rldb_plugin_cnts *(*close)(struct rldb_plugin_cnts *);
};

/* default plugin: compiled into new-server */
extern struct rldb_plugin_iface rldb_plugin_file;

#endif /* __RLDB_PLUGIN_H__ */
