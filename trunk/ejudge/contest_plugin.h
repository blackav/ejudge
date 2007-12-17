/* -*- c -*- */
/* $Id$ */

#ifndef __CONTEST_PLUGIN_H__
#define __CONTEST_PLUGIN_H__

/* Copyright (C) 2007 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdio.h>

struct ejudge_cfg;
struct xml_tree;

/* version of the plugin interface structure */
#define CONTEST_PLUGIN_IFACE_VERSION 1

struct http_request_info;
struct contest_desc;
struct contest_extra;
struct serve_state;

struct contest_plugin_iface
{
  struct ejudge_plugin_iface b;
  int contest_plugin_version;

  void *(*init)(void);
  void (*finalize)(void *);

  int (*generate_tex_user_report)(
        void *handle,           /* the plugin handle */
        FILE *log_f,            /* the logging stream */
        FILE *fout,             /* the output stream */
        const unsigned char *out_path, /* the output file path */
        const struct contest_desc *cnts,
        const struct serve_state *cs,
        int user_id,
        int locale_id);
  int (*generate_tex_full_user_report)(
        void *handle,
        FILE *log_f,
        FILE *fout,
        const unsigned char *out_path,
        const struct contest_desc *cnts,
        const struct serve_state *cs,
        int user_id,
        int locale_id,
        int use_cypher);
  int (*generate_tex_problem_report)(
        void *handle,
        FILE *log_f,
        FILE *fout,
        const unsigned char *out_path,
        const struct contest_desc *cnts,
        const struct serve_state *cs,
        int prob_id,
        int locale_id,
        int use_exam_cypher);

  int (*print_user_reports)(
        void *handle,
        FILE *log_f,
        const struct contest_desc *cnts,
        const struct serve_state *cs,
        int nuser,
        int *user_ids,
        int locale_id,
        int use_user_printer,
        int full_report,
        int use_cypher);

  int (*generate_html_user_problems_summary)(
        void *handle,
        FILE *log_f,
        FILE *fout,
        const struct contest_desc *cnts,
        const struct serve_state *cs,
        int user_id,
        int accepting_mode,
        const unsigned char *table_class,
        unsigned char *solved_flag,   /* whether the problem was OK */
        unsigned char *accepted_flag, /* whether the problem was accepted */
        unsigned char *pending_flag,  /* whether there are pending runs */
        unsigned char *trans_flag,    /* whether there are transient runs */
        int *best_run,                /* the number of the best run */
        int *attempts,                /* the number of previous attempts */
        int *disqualified,            /* the number of prev. disq. attempts */
        int *best_score,              /* the best score for the problem */
        int *prev_successes);         /* the number of prev. successes */

  int (*generate_html_user_runs)(
        void *handle,
        FILE *log_f,
        FILE *fout,
        const struct contest_desc *cnts,
        const struct serve_state *cs,
        const struct http_request_info *phr,
        int user_id,
        int prob_id,
        int all_runs_flag,
        const unsigned char *table_class);

};

#endif /* __CONTEST_PLUGIN_H__ */
