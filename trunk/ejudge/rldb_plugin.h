/* -*- c -*- */
/* $Id$ */

#ifndef __RLDB_PLUGIN_H__
#define __RLDB_PLUGIN_H__

/* Copyright (C) 2008-2014 Alexander Chernov <cher@ejudge.ru> */

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

struct ejudge_cfg;
struct contest_desc;
struct section_global_data;
struct runlog_state;
struct run_header;
struct run_entry;

/* version of the plugin interface structure */
#define RLDB_PLUGIN_IFACE_VERSION 1

struct rldb_plugin_data;
struct rldb_plugin_cnts;

struct rldb_plugin_iface
{
  struct common_plugin_iface b;
  int rldb_version;

  /*
  // initialize the plugin
  struct rldb_plugin_data *(*init)(void);
  // close the database flushing all the data, if necessary
  int (*finish)(struct rldb_plugin_data *);
  // parse the plugin arguments
  int (*prepare)(struct rldb_plugin_data *, struct ejudge_cfg *,
                 struct xml_tree*);
  */
  // open a contest
  struct rldb_plugin_cnts *(*open)(struct rldb_plugin_data *,
                                   struct runlog_state *,
                                   const struct ejudge_cfg *,
                                   const struct contest_desc *,
                                   const struct section_global_data *,
                                   int flags,
                                   time_t,
                                   time_t,
                                   time_t);
  // close a contest
  struct rldb_plugin_cnts *(*close)(struct rldb_plugin_cnts *);
  // clear the data
  int (*reset)(struct rldb_plugin_cnts *, time_t, time_t, time_t);
  // set the entire runlog
  int (*set_runlog)(struct rldb_plugin_cnts *cdata, int total_entries,
                    struct run_entry *entries);
  // backup the runlog
  int (*backup)(struct rldb_plugin_cnts *cdata);
  // flush the whole runlog
  int (*flush)(struct rldb_plugin_cnts *cdata);
  // get the position to insert a new run
  int (*get_insert_run_id)(struct rldb_plugin_cnts *,
                           time_t t, int uid, int nsec);
  // write a new run to the database
  int (*add_entry)(struct rldb_plugin_cnts *, int i,
                   const struct run_entry *, int);
  // undo the last append
  int (*undo_add_entry)(struct rldb_plugin_cnts *, int run_id);
  // change the status
  int (*change_status)(struct rldb_plugin_cnts *,
                       int run_id,
                       int new_status,
                       int new_test,
                       int new_passed_mode,
                       int new_score,
                       int judge_id);
  // start the contest
  int (*start)(struct rldb_plugin_cnts *, time_t);
  // stop the contest
  int (*stop)(struct rldb_plugin_cnts *, time_t);
  // set the duration
  int (*set_duration)(struct rldb_plugin_cnts *, int);
  // set the scheduled start time
  int (*schedule)(struct rldb_plugin_cnts *, time_t);
  // set the finish time
  int (*set_finish_time)(struct rldb_plugin_cnts *, time_t);
  // save the contest times
  int (*save_times)(struct rldb_plugin_cnts *);
  // set the status
  int (*set_status)(struct rldb_plugin_cnts *,
                    int run_id,
                    int new_status);
  // clear the entry
  int (*clear_entry)(struct rldb_plugin_cnts *, int run_id);
  // set the hidden flag value
  int (*set_hidden)(struct rldb_plugin_cnts *,
                    int run_id,
                    int new_hidden);
  // set the judge_id value
  int (*set_judge_id)(struct rldb_plugin_cnts *,
                      int run_id,
                      int new_judge_id);
  // set the pages value
  int (*set_pages)(struct rldb_plugin_cnts *,
                   int run_id,
                   int new_pages);
  // set the entry
  int (*set_entry)(struct rldb_plugin_cnts *,
                   int run_id,
                   const struct run_entry *in,
                   int flags);
  // remove the EMPTY records
  int (*squeeze)(struct rldb_plugin_cnts *);
  // insert the whole record
  int (*put_entry)(struct rldb_plugin_cnts *, const struct run_entry *);
  // insert the whole header
  int (*put_header)(struct rldb_plugin_cnts *, const struct run_header *);
  // change the status (extended version)
  int (*change_status_2)(struct rldb_plugin_cnts *,
                         int run_id,
                         int new_status,
                         int new_test,
                         int new_passed_mode,
                         int new_score,
                         int judge_id,
                         int is_marked);
  // check the runlog (may fix broken items)
  int (*check)(struct rldb_plugin_cnts *, FILE *log_f);
  // change the status (includes user status)
  int (*change_status_3)(struct rldb_plugin_cnts *,
                         int run_id,
                         int new_status,
                         int new_test,
                         int new_passed_mode,
                         int new_score,
                         int judge_id,
                         int is_marked,
                         int has_user_score,
                         int user_status,
                         int user_tests_passed,
                         int user_score);
  // change the status (brief version)
  int (*change_status_4)(struct rldb_plugin_cnts *,
                         int run_id,
                         int new_status);
};

/* default plugin: compiled into new-server */
extern struct rldb_plugin_iface rldb_plugin_file;

#endif /* __RLDB_PLUGIN_H__ */
