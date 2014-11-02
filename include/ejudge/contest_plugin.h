/* -*- c -*- */
/* $Id$ */

#ifndef __CONTEST_PLUGIN_H__
#define __CONTEST_PLUGIN_H__

/* Copyright (C) 2007-2014 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_types.h"
#include "ejudge/iterators.h"

#include <stdio.h>

struct ejudge_cfg;
struct xml_tree;

/* version of the plugin interface structure */
#define CONTEST_PLUGIN_IFACE_VERSION 2

struct http_request_info;
struct contest_desc;
struct contest_extra;
struct serve_state;
struct UserProblemInfo;

struct contest_plugin_iface
{
  struct ejudge_plugin_iface b;
  int contest_plugin_version;

  const size_t *sizes_array;
  size_t sizes_array_size;

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
        struct UserProblemInfo *pinfo);/* user problem info */

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

  int (*generate_html_standings)(
        void *handle,           /* the plugin own data */
        FILE *log_f,            /* the logging stream */
        FILE *fout,             /* the output stream (MAY BE NULL) */
        const struct contest_desc *cnts,
        const struct serve_state *cs,
        const struct http_request_info *phr,
        time_t cur_time,        /* the current time */
        const unsigned char *stand_dir, /* the output path */
        const unsigned char *header_str,
        const unsigned char *footer_str,
        int user_id,            /* the user which standings */
        const unsigned char *user_name,
        int priv_mode,          /* privileged standings */
        int client_flag,        /* generate for client (omit headers) */
        int only_table_flag,    /* omit table indices */
        int raw_flag,           /* CSV standings */
        int xml_flag,           /* XML standings */
        int accepting_mode,     /* generate for accepting mode */
        int force_fancy_style); /* use fancy table style */

};

#endif /* __CONTEST_PLUGIN_H__ */
