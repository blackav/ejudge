/* -*- c -*- */
/* $Id$ */

#ifndef __NSDB_PLUGIN_H__
#define __NSDB_PLUGIN_H__

/* Copyright (C) 2006-2007 Alexander Chernov <cher@ejudge.ru> */

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

struct ejudge_cfg;
struct xml_tree;

/* version of the plugin interface structure */
#define NSDB_PLUGIN_IFACE_VERSION 1

struct nsdb_plugin_iface
{
  struct ejudge_plugin_iface b;
  int nsdb_version;

  // initialize the plugin
  void *(*init)(const struct ejudge_cfg *);
  // parse the configuration settings
  int (*parse)(void *, const struct ejudge_cfg *, struct xml_tree *);
  // open (initialize) the connection
  int (*open)(void *);
  // close the connection
  int (*close)(void *);
  // check the data and probably upgrade it
  int (*check)(void *);
  // initialize the data
  int (*create)(void *);

  // check whether the user may login using the given role
  int (*check_role)(void *, int, int, int);
  // get the priv_table contest user id iterator
  int_iterator_t (*get_contest_user_id_iterator)(void *, int);
  // get the role_mask by the iterator
  int (*get_priv_role_mask_by_iter)(void *, int_iterator_t, unsigned int *);
  // add the specified role to the user
  int (*add_role)(void *, int, int, int);
  // remove the specified role from the user
  int (*del_role)(void *, int, int, int);
  // remove the user completely
  int (*priv_remove_user)(void *, int, int);

  // assign an examiner for a problem
  int (*assign_examiner)(void *, int, int, int);
  // assign the chief examiner for a problem
  int (*assign_chief_examiner)(void *, int, int, int, int);
  // remove an examiner or the chief examiner from a problem
  int (*remove_examiner)(void *, int, int, int);
  // get an examiner's role for the contest/problem pair
  int (*get_examiner_role)(void *, int, int, int);
  // find the chief examiner
  int (*find_chief_examiner)(void *, int, int);
  // get the examiners iterator
  int_iterator_t (*get_examiner_user_id_iterator)(void *, int, int);
  // count the examiners
  int (*get_examiner_count)(void *, int, int);
};

/* default plugin: compiled into new-server */
extern struct nsdb_plugin_iface nsdb_plugin_files;

#endif /* __NSDB_PLUGIN_H__ */
