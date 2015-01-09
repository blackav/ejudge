/* -*- c -*- */

#ifndef __CLDB_PLUGIN_H__
#define __CLDB_PLUGIN_H__

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

#include "ejudge/ejudge_plugin.h"
#include "ejudge/common_plugin.h"
#include "ejudge/ej_types.h"
#include "ejudge/iterators.h"
#include "ejudge/ejudge_cfg.h"

struct contest_desc;
struct section_global_data;

/* version of the plugin interface structure */
#define CLDB_PLUGIN_IFACE_VERSION 1

struct clarlog_state;
struct cldb_plugin_data;
struct cldb_plugin_cnts;
struct clar_entry_v2;
struct full_clar_entry;

struct cldb_plugin_iface
{
  struct common_plugin_iface b;
  int cldb_version;

  /*
  // initialize the plugin
  struct cldb_plugin_data *(*init)(void);
  // close the database flushing all the data, if necessary
  int (*finish)(struct cldb_plugin_data *);
  // parse the plugin arguments
  int (*prepare)(struct cldb_plugin_data *, struct ejudge_cfg *,
                 struct xml_tree*);
  */
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
  int (*reset)(struct cldb_plugin_cnts *);
  // add a new entry
  int (*add_entry)(struct cldb_plugin_cnts *, int);
  // update entry flags
  int (*set_flags)(struct cldb_plugin_cnts *, int);
  // update entry charset
  int (*set_charset)(struct cldb_plugin_cnts *, int);
  // get the message text as is
  int (*get_raw_text)(struct cldb_plugin_cnts *, int, unsigned char **,size_t*);
  // add the message text
  int (*add_text)(struct cldb_plugin_cnts *, int, const ej_uuid_t *, const unsigned char *,size_t);
  // modify the message text
  int (*modify_text)(struct cldb_plugin_cnts *, int clar_id, const unsigned char *text, size_t size);
  // modify the message record
  int (*modify_record)(struct cldb_plugin_cnts *, int clar_id, int mask, const struct clar_entry_v2 *pe);
  // fetch the messages related to the specified run UUID
  int (*fetch_run_messages)(
        struct cldb_plugin_cnts *,
        const ej_uuid_t *p_run_uuid,
        struct full_clar_entry **pfce);
};

/* default plugin: compiled into new-server */
extern struct cldb_plugin_iface cldb_plugin_file;

#endif /* __CLDB_PLUGIN_H__ */
