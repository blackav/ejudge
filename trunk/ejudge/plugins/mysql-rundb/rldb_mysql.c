/* -*- mode: c -*- */
/* $Id$ */

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

#include "config.h"
#include "ej_limits.h"
#include "rldb_plugin.h"
#include "runlog.h"
#include "teamdb.h"
#include "../mysql-common/common_mysql.h"

#define RUNS_ACCESS 
#include "runlog_state.h"

#include "errlog.h"
#include "xml_utils.h"
#include "contests.h"
#include "prepare.h"
#include "mime_type.h"
#include "misctext.h"
#include "compat.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <mysql.h>

#include <stdarg.h>
#include <errno.h>
#include <sys/time.h>

struct rldb_mysql_state
{
  int nref;

  // mysql access
  struct common_mysql_iface *mi;
  struct common_mysql_state *md;
};

struct rldb_mysql_cnts
{
  struct rldb_mysql_state *plugin_state;
  struct runlog_state *rl_state;
  int contest_id;
};

#include "methods.inc.c"

/* plugin entry point */
struct rldb_plugin_iface plugin_rldb_mysql =
{
  {
    {
      sizeof (struct rldb_plugin_iface),
      EJUDGE_PLUGIN_IFACE_VERSION,
      "rldb",
      "mysql",
    },
    COMMON_PLUGIN_IFACE_VERSION,
    init_func,
    finish_func,
    prepare_func,
  },
  RLDB_PLUGIN_IFACE_VERSION,

  open_func,
  close_func,
  reset_func,
  set_runlog_func,
  backup_func,
  flush_func,
  get_insert_run_id,
  add_entry_func,
  undo_add_entry_func,
  change_status_func,
  start_func,
  stop_func,
  set_duration_func,
  schedule_func,
  set_finish_time_func,
  save_times_func,
  set_status_func,
  clear_entry_func,
  set_hidden_func,
  set_judge_id_func,
  set_pages_func,
  set_entry_func,
  squeeze_func,
  put_entry_func,
  put_header_func,
};

static struct common_plugin_data *
init_func(void)
{
  struct rldb_mysql_state *state = 0;
  XCALLOC(state, 1);
  return (struct common_plugin_data*) state;
}

static int
finish_func(struct common_plugin_data *data)
{
  struct rldb_mysql_state *state = (struct rldb_mysql_state*) data;

  if (state->nref > 0) {
    err("rldb_mysql::finish: reference counter > 0");
    return -1;
  }

  memset(state, 0, sizeof(*state));
  xfree(state);
  return 0;
}

static int
prepare_func(
        struct common_plugin_data *data,
        struct ejudge_cfg *config,
        struct xml_tree *tree)
{
  struct rldb_mysql_state *state = (struct rldb_mysql_state*) data;
  const struct common_loaded_plugin *mplg;

  // load common_mysql plugin
  if (!(mplg = plugin_load_external(0, "common", "mysql", config))) {
    err("cannot load common_mysql plugin");
    return -1;
  }
  state->mi = (struct common_mysql_iface*) mplg->iface;
  state->md = (struct common_mysql_state*) mplg->data;

  return 0;
}

#include "tables.inc.c"

static int
do_create(struct rldb_mysql_state *state)
{
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;

  mi->free_res(md);
  if (mi->simple_fquery(md, create_runheaders_query, md->table_prefix) < 0)
    db_error_fail(md);
  if (mi->simple_fquery(md, create_runs_query, md->table_prefix) < 0)
    db_error_fail(md);
  if (mi->simple_fquery(md,
                        "INSERT INTO %sconfig VALUES ('run_version', '1') ;",
                        md->table_prefix) < 0)
    db_error_fail(md);
  return 0;

 fail:
  return -1;
}

static int
do_open(struct rldb_mysql_state *state)
{
  int run_version = 0;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;

  if (mi->connect(md) < 0) return -1;

  if (mi->fquery(md, 1, "SELECT config_val FROM %sconfig WHERE config_key = 'run_version' ;", md->table_prefix) < 0) {
    err("probably the database is not created, please, create it");
    return -1;
  }
  if (md->row_count > 1) {
    err("run_version key is not unique");
    return -1;
  }
  if (!md->row_count) return do_create(state);
  if (mi->next_row(state->md) < 0) db_error_fail(md);
  if (!md->row[0] || mi->parse_int(md, md->row[0], &run_version) < 0)
    db_error_inv_value_fail(md, "config_val");
  mi->free_res(md);
  if (run_version != 1) {
    err("run_version == %d is not supported", run_version);
    goto fail;
  }
  return 0;

 fail:
  mi->free_res(md);
  return -1;
}

static int
load_header(
        struct rldb_mysql_cnts *cs,
        int flags,
        time_t init_duration,
        time_t init_sched_time,
        time_t init_finish_time)
{
  struct rldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  struct runlog_state *rls = cs->rl_state;
  struct run_header_internal rh;
  struct timeval curtime;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  memset(&rh, 0, sizeof(rh));
  if (mi->fquery(md, HEADERS_ROW_WIDTH,
                 "SELECT * FROM %srunheaders WHERE contest_id = %d ; ",
                 md->table_prefix, cs->contest_id) < 0)
    goto fail;
  if (md->row_count > 1) {
    err("rldb_mysql: load_header: row_count == %d", md->row_count);
    goto fail;
  }
  if (!md->row_count) {
    mi->free_res(md);
    gettimeofday(&curtime, 0);
    rh.contest_id = cs->contest_id;
    rh.duration = init_duration;
    rh.sched_time = init_sched_time;
    rh.finish_time = init_finish_time;
    rh.last_change_time = curtime.tv_sec;
    rh.last_change_nsec = curtime.tv_usec * 1000;

    cmd_f = open_memstream(&cmd_t, &cmd_z);
    fprintf(cmd_f, "INSERT INTO %srunheaders VALUES ( ", md->table_prefix);
    mi->unparse_spec(md, cmd_f, HEADERS_ROW_WIDTH, headers_spec, &rh);
    fprintf(cmd_f, " ) ;");
    close_memstream(cmd_f); cmd_f = 0;
    if (mi->simple_query(md, cmd_t, cmd_z) < 0) goto fail;
    xfree(cmd_t); cmd_t = 0;

    memset(&rls->head, 0, sizeof(rls->head));
    rls->head.version = 2;
    rls->head.byte_order = 0;
    rls->head.duration = init_duration;
    rls->head.sched_time = init_sched_time;
    rls->head.finish_time = init_finish_time;
    return 0;
  }

  if (mi->next_row(md) < 0) goto fail;
  if (mi->parse_spec(md, md->field_count, md->row, md->lengths,
                     HEADERS_ROW_WIDTH, headers_spec, &rh) < 0)
    goto fail;
  mi->free_res(md);

  memset(&rls->head, 0, sizeof(rls->head));
  rls->head.version = 2;
  rls->head.byte_order = 0;
  rls->head.start_time = rh.start_time;
  rls->head.sched_time = rh.sched_time;
  rls->head.duration = rh.duration;
  rls->head.stop_time = rh.stop_time;
  rls->head.finish_time = rh.finish_time;
  rls->head.saved_duration = rh.saved_duration;
  rls->head.saved_stop_time = rh.saved_stop_time;
  rls->head.saved_finish_time = rh.saved_finish_time;
  return 1;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  mi->free_res(md);
  return -1;
}

static void
expand_runs(struct runlog_state *rls, int run_id)
{
  int new_a, i;
  struct run_entry *new_v;

  if (run_id < rls->run_u) return;
  if (run_id < rls->run_a) {
    rls->run_u = run_id + 1;
    return;
  }

  if (!(new_a = rls->run_a)) new_a = 128;
  while (run_id >= new_a) new_a *= 2;
  XCALLOC(new_v, new_a);
  for (i = 0; i < new_a; ++i) {
    new_v[i].run_id = i;
    new_v[i].status = RUN_EMPTY;
  }
  if (rls->run_u) memcpy(new_v, rls->runs, rls->run_u * sizeof(new_v[0]));
  xfree(rls->runs);
  rls->runs = new_v;
  rls->run_a = new_a;
  rls->run_u = run_id + 1;
}

static int
parse_sha1(const unsigned char *str, ruint32_t *psha1)
{
  const unsigned char *s = str;
  unsigned char buf[3];
  int i, v;
  unsigned char *eptr;
  unsigned char *optr = (unsigned char*) psha1;
  char *tmpeptr = 0;

  if (!str || strlen(str) != 40) return -1;
  for (i = 0; i < 20; i++) {
    buf[0] = *s++;
    buf[1] = *s++;
    buf[2] = 0;
    v = strtol(buf, &tmpeptr, 16);
    eptr = tmpeptr;
    if (v < 0 || v > 255 || *eptr) return -1;
    *optr++ = v;
  }
  return 0;
}

static int
load_runs(struct rldb_mysql_cnts *cs)
{
  struct rldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  struct runlog_state *rls = cs->rl_state;
  struct run_entry_internal ri;
  struct run_entry *re;
  int i, mime_type;
  ruint32_t sha1[5];

  memset(&ri, 0, sizeof(ri));
  if (mi->fquery(md, RUNS_ROW_WIDTH,
                 "SELECT * FROM %sruns WHERE contest_id=%d ORDER BY run_id ;",
                 md->table_prefix, cs->contest_id) < 0)
    goto fail;
  if (!md->row_count) {
    mi->free_res(md);
    return 0;
  }
  for (i = 0; i < md->row_count; i++) {
    if (mi->next_row(md) < 0) goto fail;
    memset(&ri, 0, sizeof(ri));
    memset(sha1, 0, sizeof(sha1));
    mime_type = 0;
    if (mi->parse_spec(md, md->field_count, md->row, md->lengths,
                       RUNS_ROW_WIDTH, runs_spec, &ri) < 0)
      goto fail;
    if (ri.run_id < 0) db_error_inv_value_fail(md, "run_id");
    if (ri.size < 0) db_error_inv_value_fail(md, "size");
    /* FIXME: check ordering on create_time/create_nsec */
    if (ri.create_nsec < 0 || ri.create_nsec > NSEC_MAX)
      db_error_inv_value_fail(md, "create_nsec");
    if (!run_is_valid_status(ri.status))
      db_error_inv_value_fail(md, "status");
    if (ri.status == RUN_EMPTY) {
      xfree(ri.hash); ri.hash = 0;
      xfree(ri.mime_type); ri.mime_type = 0;
      continue;
    }
    if (ri.user_id <= 0) db_error_inv_value_fail(md, "user_id");
    if (ri.prob_id < 0) db_error_inv_value_fail(md, "prob_id");
    if (ri.lang_id < 0) db_error_inv_value_fail(md, "lang_id");
    if (ri.hash && parse_sha1(ri.hash, sha1) < 0)
      db_error_inv_value_fail(md, "hash");
    if (ri.ip_version != 4) db_error_inv_value_fail(md, "ip_version");
    if (ri.mime_type && (mime_type = mime_type_parse(ri.mime_type)) < 0)
      db_error_inv_value_fail(md, "mime_type");
    xfree(ri.hash); ri.hash = 0;
    xfree(ri.mime_type); ri.mime_type = 0;

    expand_runs(rls, ri.run_id);
    re = &rls->runs[ri.run_id];

    re->run_id = ri.run_id;
    re->size = ri.size;
    re->time = ri.create_time;
    re->nsec = ri.create_nsec;
    re->user_id = ri.user_id;
    re->prob_id = ri.prob_id;
    re->lang_id = ri.lang_id;
    re->a.ip = ri.ip;
    re->ipv6_flag = 0;
    memcpy(re->sha1, sha1, sizeof(re->sha1));
    re->score = ri.score;
    re->test = ri.test_num;
    re->score_adj = ri.score_adj;
    re->locale_id = ri.locale_id;
    re->judge_id = ri.judge_id;
    re->status = ri.status;
    re->is_imported = ri.is_imported;
    re->variant = ri.variant;
    re->is_hidden = ri.is_hidden;
    re->is_readonly = ri.is_readonly;
    re->pages = ri.pages;
    re->ssl_flag = ri.ssl_flag;
    re->mime_type = mime_type;
    re->is_examinable = ri.is_examinable;
    re->examiners[0] = ri.examiners0;
    re->examiners[1] = ri.examiners1;
    re->examiners[2] = ri.examiners2;
    re->exam_score[0] = ri.exam_score0;
    re->exam_score[1] = ri.exam_score1;
    re->exam_score[2] = ri.exam_score2;
  }
  return 1;

 fail:
  xfree(ri.hash);
  xfree(ri.mime_type);
  mi->free_res(md);
  return -1;
}

static struct rldb_plugin_cnts *
open_func(
        struct rldb_plugin_data *data,
        struct runlog_state *rl_state,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags,
        time_t init_duration,
        time_t init_sched_time,
        time_t init_finish_time)
{
  struct rldb_mysql_state *state = (struct rldb_mysql_state*) data;
  struct rldb_mysql_cnts *cs = 0;
  int r;

  ASSERT(state);
  XCALLOC(cs, 1);
  cs->plugin_state = state;
  state->nref++;
  cs->rl_state = rl_state;
  if (cnts) cs->contest_id = cnts->id;
  if (!cs->contest_id && global) cs->contest_id = global->contest_id;
  if (!cs->contest_id) {
    err("undefined contest_id");
    goto fail;
  }

  if (do_open(state) < 0) goto fail;
  if ((r = load_header(cs, flags, init_duration, init_sched_time,
                       init_finish_time)) < 0)
    goto fail;
  if (!r) return (struct rldb_plugin_cnts*) cs;
  if (load_runs(cs) < 0) goto fail;
  state->mi->free_res(state->md);
  return (struct rldb_plugin_cnts*) cs;

 fail:
  state->mi->free_res(state->md);
  close_func((struct rldb_plugin_cnts*) cs);
  return 0;
}

static struct rldb_plugin_cnts *
close_func(struct rldb_plugin_cnts *cdata)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  if (!cs) return 0;
  rls = cs->rl_state;
  if (rls) {
    xfree(rls->runs); rls->runs = 0;
    rls->run_a = rls->run_u = 0;
  }
  if (cs->plugin_state) cs->plugin_state->nref--;
  memset(cs, 0, sizeof(*cs));
  xfree(cs);
  return 0;
}

static int
reset_func(
        struct rldb_plugin_cnts *cdata,
        time_t init_duration,
        time_t init_sched_time,
        time_t init_finish_time)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts*) cdata;
  struct rldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  struct runlog_state *rls = cs->rl_state;
  struct run_header_internal rh;
  int i;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  struct timeval curtime;

  rls->run_u = 0;
  if (rls->run_a > 0) {
    memset(rls->runs, 0, sizeof(rls->runs[0]) * rls->run_a);
    for (i = 0; i < rls->run_a; ++i)
      rls->runs[i].status = RUN_EMPTY;
  }

  memset(&rls->head, 0, sizeof(rls->head));
  rls->head.version = 2;
  rls->head.duration = init_duration;
  rls->head.sched_time = init_sched_time;
  rls->head.finish_time = init_finish_time;

  mi->simple_fquery(md, "DELETE FROM %sruns WHERE contest_id = %d ;",
                    md->table_prefix, cs->contest_id);
  mi->simple_fquery(md, "DELETE FROM %srunheaders WHERE contest_id = %d ;",
                    md->table_prefix, cs->contest_id);

  memset(&rh, 0, sizeof(rh));
  gettimeofday(&curtime, 0);
  rh.contest_id = cs->contest_id;
  rh.duration = init_duration;
  rh.sched_time = init_sched_time;
  rh.finish_time = init_finish_time;
  rh.last_change_time = curtime.tv_sec;
  rh.last_change_nsec = curtime.tv_usec * 1000;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %srunheaders VALUES ( ", md->table_prefix);
  mi->unparse_spec(md, cmd_f, HEADERS_ROW_WIDTH, headers_spec, &rh);
  fprintf(cmd_f, " ) ;");
  close_memstream(cmd_f); cmd_f = 0;
  mi->simple_query(md, cmd_t, cmd_z);
  xfree(cmd_t); cmd_t = 0;

  return 0;
}

static int
set_runlog_func(
        struct rldb_plugin_cnts *cdata,
        int total_entries,
        struct run_entry *entries)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;
  int i;

  // only work for empty runlog
  if (rls->run_u > 0) {
    err("rldb_mysql: set_runlog: runlog is not empty");
    return -1;
  }

  // FIXME: handle errors
  for (i = 0; i < total_entries; ++i) {
    put_entry_func(cdata, &entries[i]);
  }

  return 0;
}

static int
backup_func(struct rldb_plugin_cnts *cdata)
{
  return 0;
}

static int
flush_func(struct rldb_plugin_cnts *cdata)
{
  return 0;
}

static int
compare_runs(
        const struct run_entry *re,
        time_t create_time,
        int create_nsec,
        int user_id)
{
  if (re->time < create_time) return -1;
  if (re->time > create_time) return 1;
  if (re->nsec < create_nsec) return -1;
  if (re->nsec > create_nsec) return 1;
  if (re->user_id < user_id) return -1;
  if (re->user_id > user_id) return 1;
  return 0;
}

static int
find_insert_point(
        struct runlog_state *rls,
        time_t create_time,
        int create_nsec,
        int user_id)
{
  int run_id;
  int r, f, l, m1, m2;

  if (!rls->run_u) {
    expand_runs(rls, 0);
    return 0;
  }

  run_id = rls->run_u - 1;
  while (run_id >= 0 && rls->runs[run_id].status == RUN_EMPTY)
    run_id--;
  if (run_id < 0) return 0;

  if (rls->runs[run_id].time < create_time) {
    run_id++;
    expand_runs(rls, run_id);
    return run_id;
  }
  if (rls->runs[run_id].time == create_time
      && rls->runs[run_id].nsec < create_nsec) {
    run_id++;
    expand_runs(rls, run_id);
    return run_id;
  }

  // ok, use slow function and so on
  r = compare_runs(&rls->runs[run_id], create_time, create_nsec, user_id);
  if (r < 0) {
    run_id++;
    expand_runs(rls, run_id);
    return run_id;
  }
  if (!r) goto duplicate_insert;

  // bsearch
  f = 0;
  while (rls->runs[f].status == RUN_EMPTY && f < rls->run_u) f++;
  ASSERT(f < rls->run_u);
  l = run_id + 1;
  while (f < l) {
    m1 = (f + l) / 2;
    if (rls->runs[m1].status != RUN_EMPTY) {
      if (!(r = compare_runs(&rls->runs[m1],create_time,create_nsec,user_id)))
        goto duplicate_insert;
      if (r < 0) {
        f = m1 + 1;
        while (f < l && rls->runs[f].status == RUN_EMPTY) f++;
        continue;
      }
      l = m1;
      while (f < l && rls->runs[l - 1].status == RUN_EMPTY) l--;
      continue;
    }
    m2 = m1;
    while (m1 >= f && rls->runs[m1].status == RUN_EMPTY) m1--;
    ASSERT(m1 >= f);
    while (m2 < l && rls->runs[m2].status == RUN_EMPTY) m2++;
    ASSERT(m2 < l);
    if (!(r = compare_runs(&rls->runs[m1],create_time,create_nsec,user_id)))
      goto duplicate_insert;
    if (r > 0) {
      l = m1;
      while (f < l && rls->runs[l - 1].status == RUN_EMPTY) l--;
      continue;
    }
    if (!(r = compare_runs(&rls->runs[m2],create_time,create_nsec,user_id)))
      goto duplicate_insert;
    if (r < 0) {
      f = m2 + 1;
      while (f < l && rls->runs[f].status == RUN_EMPTY) f++;
      continue;
    }
    // insert somewhere inbetween [m1,m2]
    run_id = m1 + 1;
    return run_id;
  }
  ASSERT(f == l);
  expand_runs(rls, rls->run_u);
  return f;

 duplicate_insert:
  err("find_insert_point: duplicate insert?");
  return -1;
}

static int
get_insert_run_id(
        struct rldb_plugin_cnts *cdata,
        time_t create_time,
        int user_id,
        int create_nsec)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct rldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  struct runlog_state *rls = cs->rl_state;
  struct run_entry_internal ri;
  struct run_entry *re;
  struct timeval curtime;
  int run_id, i;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  if ((run_id = find_insert_point(rls, create_time, create_nsec, user_id)) < 0)
    goto fail;
  ASSERT(run_id < rls->run_u);

  if (rls->runs[run_id].status != RUN_EMPTY) {
    // move [run_id, run_u - 1) one forward
    memmove(&rls->runs[run_id + 1], &rls->runs[run_id],
            (rls->run_u - run_id - 1) * sizeof(rls->runs[0]));
    for (i = run_id + 1; i < rls->run_u; ++i)
      rls->runs[i].run_id = i;
    // FIXME: does it work???
    if (mi->simple_fquery(md, "UPDATE %sruns SET run_id = run_id + 1 WHERE contest_id = %d AND run_id >= %d ;", md->table_prefix, cs->contest_id, run_id) < 0)
      goto fail;
  }
  re = &rls->runs[run_id];
  memset(re, 0, sizeof(*re));
  re->run_id = run_id;
  re->time = create_time;
  re->nsec = create_nsec;
  re->user_id = user_id;
  re->status = RUN_EMPTY;

  memset(&ri, 0, sizeof(ri));
  gettimeofday(&curtime, 0);
  ri.run_id = run_id;
  ri.contest_id = cs->contest_id;
  ri.create_time = create_time;
  ri.create_nsec = create_nsec;
  ri.status = RUN_EMPTY;
  ri.user_id = user_id;
  ri.last_change_time = curtime.tv_sec;
  ri.last_change_nsec = curtime.tv_usec * 1000;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %sruns VALUES ( ", md->table_prefix);
  mi->unparse_spec(md, cmd_f, RUNS_ROW_WIDTH, runs_spec, &ri);
  fprintf(cmd_f, " ) ;");
  close_memstream(cmd_f); cmd_f = 0;
  if (mi->simple_query(md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0;
  return run_id;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static void
generate_update_entry_clause(
        struct rldb_mysql_state *state,
        FILE *f,
        const struct run_entry *re,
        int flags)
{
  struct timeval curtime;
  const unsigned char *sep = "";
  const unsigned char *comma = ", ";

  if ((flags & RE_SIZE)) {
    fprintf(f, "%ssize = %d", sep, re->size);
    sep = comma;
  }
  if ((flags & RE_USER_ID)) {
    fprintf(f, "%suser_id = %d", sep, re->user_id);
    sep = comma;
  }
  if ((flags & RE_PROB_ID)) {
    fprintf(f, "%sprob_id = %d", sep, re->prob_id);
    sep = comma;
  }
  if ((flags & RE_LANG_ID)) {
    fprintf(f, "%slang_id = %d", sep, re->lang_id);
    sep = comma;
  }
  if ((flags & RE_STATUS)) {
    fprintf(f, "%sstatus = %d", sep, re->status);
    sep = comma;
  }
  if ((flags & RE_SSL_FLAG)) {
    fprintf(f, "%sssl_flag = %d", sep, re->ssl_flag);
    sep = comma;
  }
  if ((flags & RE_IP)) {
    fprintf(f, "%sip_version = 4", sep);
    sep = comma;
    fprintf(f, "%sip = '%s'", sep, xml_unparse_ip(re->a.ip));
  }
  if ((flags & RE_SHA1)) {
    if (!re->sha1[0] && !re->sha1[1] && !re->sha1[2]
        && !re->sha1[3] && !re->sha1[4]) {
      fprintf(f, "%shash = NULL", sep);
    } else {
      fprintf(f, "%shash = '%s'", sep, unparse_sha1(re->sha1));
    }
    sep =comma;
  }
  if ((flags & RE_SCORE)) {
    fprintf(f, "%sscore = %d", sep, re->score);
    sep = comma;
  }
  if ((flags & RE_TEST)) {
    fprintf(f, "%stest_num = %d", sep, re->test);
    sep = comma;
  }
  if ((flags & RE_SCORE_ADJ)) {
    fprintf(f, "%sscore_adj = %d", sep, re->score_adj);
    sep = comma;
  }
  if ((flags & RE_LOCALE_ID)) {
    fprintf(f, "%slocale_id = %d", sep, re->locale_id);
    sep = comma;
  }
  if ((flags & RE_JUDGE_ID)) {
    fprintf(f, "%sjudge_id = %d", sep, re->judge_id);
    sep = comma;
  }
  if ((flags & RE_VARIANT)) {
    fprintf(f, "%svariant = %d", sep, re->variant);
    sep = comma;
  }
  if ((flags & RE_PAGES)) {
    fprintf(f, "%spages = %d", sep, re->pages);
    sep = comma;
  }
  if ((flags & RE_IS_IMPORTED)) {
    fprintf(f, "%sis_imported = %d", sep, re->is_imported);
    sep = comma;
  }
  if ((flags & RE_IS_HIDDEN)) {
    fprintf(f, "%sis_hidden = %d", sep, re->is_hidden);
    sep = comma;
  }
  if ((flags & RE_IS_READONLY)) {
    fprintf(f, "%sis_readonly = %d", sep, re->is_readonly);
    sep = comma;
  }
  if ((flags & RE_IS_EXAMINABLE)) {
    fprintf(f, "%sis_examinable = %d", sep, re->is_examinable);
    sep = comma;
  }
  if ((flags & RE_MIME_TYPE)) {
    if (re->mime_type > 0) {
      fprintf(f, "%smime_type = '%s'", sep, mime_type_get_type(re->mime_type));
    } else {
      fprintf(f, "%smime_type = NULL", sep);
    }
    sep = comma;
  }
  if ((flags & RE_EXAMINERS)) {
    fprintf(f, "%sexaminers0 = %d", sep, re->examiners[0]);
    sep = comma;
    fprintf(f, "%sexaminers1 = %d", sep, re->examiners[1]);
    fprintf(f, "%sexaminers2 = %d", sep, re->examiners[2]);
  }
  if ((flags & RE_EXAM_SCORE)) {
    fprintf(f, "%sexam_score0 = %d", sep, re->exam_score[0]);
    sep = comma;
    fprintf(f, "%sexam_score1 = %d", sep, re->exam_score[1]);
    fprintf(f, "%sexam_score2 = %d", sep, re->exam_score[2]);
  }

  gettimeofday(&curtime, 0);
  fprintf(f, "%slast_change_time = ", sep);
  state->mi->write_timestamp(state->md, f, 0, curtime.tv_sec);
  sep = comma;
  fprintf(f, "%slast_change_nsec = %ld", sep, curtime.tv_usec * 1000);
}

static void
update_entry(
        struct run_entry *dst,
        const struct run_entry *src,
        int flags)
{
  if ((flags & RE_SIZE)) {
    dst->size = src->size;
  }
  if ((flags & RE_USER_ID)) {
    dst->user_id = src->user_id;
  }
  if ((flags & RE_PROB_ID)) {
    dst->prob_id = src->prob_id;
  }
  if ((flags & RE_LANG_ID)) {
    dst->lang_id = src->lang_id;
  }
  if ((flags & RE_IP)) {
    dst->a = src->a;
    dst->ipv6_flag = src->ipv6_flag;
  }
  if ((flags & RE_SHA1)) {
    memcpy(dst->sha1, src->sha1, sizeof(dst->sha1));
  }
  if ((flags & RE_SCORE)) {
    dst->score = src->score;
  }
  if ((flags & RE_TEST)) {
    dst->test = src->test;
  }
  if ((flags & RE_SCORE_ADJ)) {
    dst->score_adj = src->score_adj;
  }
  if ((flags & RE_LOCALE_ID)) {
    dst->locale_id = src->locale_id;
  }
  if ((flags & RE_JUDGE_ID)) {
    dst->judge_id = src->judge_id;
  }
  if ((flags & RE_STATUS)) {
    dst->status = src->status;
  }
  if ((flags & RE_IS_IMPORTED)) {
    dst->is_imported = src->is_imported;
  }
  if ((flags & RE_VARIANT)) {
    dst->variant = src->variant;
  }
  if ((flags & RE_IS_HIDDEN)) {
    dst->is_hidden = src->is_hidden;
  }
  if ((flags & RE_IS_READONLY)) {
    dst->is_readonly = src->is_readonly;
  }
  if ((flags & RE_PAGES)) {
    dst->pages = src->pages;
  }
  if ((flags & RE_SSL_FLAG)) {
    dst->ssl_flag = src->ssl_flag;
  }
  if ((flags & RE_MIME_TYPE)) {
    dst->mime_type = src->mime_type;
  }
  if ((flags & RE_IS_EXAMINABLE)) {
    dst->is_examinable = src->is_examinable;
  }
  if ((flags & RE_EXAMINERS)) {
    memcpy(dst->examiners, src->examiners, sizeof(dst->examiners));
  }
  if ((flags & RE_EXAM_SCORE)) {
    memcpy(dst->exam_score, src->exam_score, sizeof(dst->exam_score));
  }
}

static int
do_update_entry(
        struct rldb_mysql_cnts *cs,
        int run_id,
        const struct run_entry *re,
        int flags)
{
  struct rldb_mysql_state *state = cs->plugin_state;
  struct runlog_state *rls = cs->rl_state;
  struct run_entry *de;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  ASSERT(run_id >= 0 && run_id < rls->run_u);
  de = &rls->runs[run_id];

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %sruns SET ", state->md->table_prefix);
  generate_update_entry_clause(state, cmd_f, re, flags);
  fprintf(cmd_f, " WHERE contest_id = %d AND run_id = %d ;",
          cs->contest_id, run_id);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  update_entry(de, re, flags);
  return run_id;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
add_entry_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        const struct run_entry *re,
        int flags)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct runlog_state *rls = cs->rl_state;
  struct run_entry *de;

  ASSERT(run_id >= 0 && run_id < rls->run_u);
  de = &rls->runs[run_id];

  ASSERT(de->run_id == run_id);
  ASSERT(de->status == RUN_EMPTY);
  ASSERT(de->time > 0);

  return do_update_entry(cs, run_id, re, flags);
}

static int
undo_add_entry_func(
        struct rldb_plugin_cnts *cdata,
        int run_id)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct rldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  struct runlog_state *rls = cs->rl_state;
  struct run_entry *re;

  ASSERT(run_id >= 0 && run_id < rls->run_u);
  re = &rls->runs[run_id];

  if (mi->simple_fquery(md, "DELETE FROM %sruns WHERE run_id = %d AND contest_id = %d ;", md->table_prefix, run_id, cs->contest_id) < 0)
    return -1;

  memset(re, 0, sizeof(*re));
  re->status = RUN_EMPTY;
  re->run_id = run_id;
  if (run_id == rls->run_u - 1) rls->run_u--;
  return 0;
}

static int
change_status_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_status,
        int new_test,
        int new_score,
        int new_judge_id)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct run_entry te;

  memset(&te, 0, sizeof(te));
  te.status = new_status;
  te.test = new_test;
  te.score = new_score;
  te.judge_id = new_judge_id;

  return do_update_entry(cs, run_id, &te,
                         RE_STATUS | RE_TEST | RE_SCORE | RE_JUDGE_ID);
}

static void
generate_update_header_clause(
        struct rldb_mysql_state *state,
        FILE *f,
        const struct run_header *rh,
        int flags)
{
  struct timeval curtime;
  const unsigned char *sep = "";
  const unsigned char *comma = ", ";

  if ((flags & RH_START_TIME)) {
    fprintf(f, "%sstart_time = ", sep);
    state->mi->write_timestamp(state->md, f, 0, rh->start_time);
    sep = comma;
  }
  if ((flags & RH_SCHED_TIME)) {
    fprintf(f, "%ssched_time = ", sep);
    state->mi->write_timestamp(state->md, f, 0, rh->sched_time);
    sep = comma;
  }
  if ((flags & RH_DURATION)) {
    fprintf(f, "%sduration = %lld", sep, rh->duration);
    sep = comma;
  }
  if ((flags & RH_STOP_TIME)) {
    fprintf(f, "%sstop_time = ", sep);
    state->mi->write_timestamp(state->md, f, 0, rh->stop_time);
    sep = comma;
  }
  if ((flags & RH_FINISH_TIME)) {
    fprintf(f, "%sfinish_time = ", sep);
    state->mi->write_timestamp(state->md, f, 0, rh->finish_time);
    sep = comma;
  }
  if ((flags & RH_SAVED_DURATION)) {
    fprintf(f, "%ssaved_duration = %lld", sep, rh->saved_duration);
    sep = comma;
  }
  if ((flags & RH_SAVED_STOP_TIME)) {
    fprintf(f, "%ssaved_stop_time = ", sep);
    state->mi->write_timestamp(state->md, f, 0, rh->saved_stop_time);
    sep = comma;
  }
  if ((flags & RH_SAVED_FINISH_TIME)) {
    fprintf(f, "%ssaved_finish_time = ", sep);
    state->mi->write_timestamp(state->md, f, 0, rh->saved_finish_time);
    sep = comma;
  }

  gettimeofday(&curtime, 0);
  fprintf(f, "%slast_change_time = ", sep);
  state->mi->write_timestamp(state->md, f, 0, curtime.tv_sec);
  sep = comma;
  fprintf(f, "%slast_change_nsec = %ld", sep, curtime.tv_usec * 1000);
}

static void
update_header(
        struct run_header *dst,
        const struct run_header *src,
        int flags)
{
  if ((flags & RH_START_TIME)) {
    dst->start_time = src->start_time;
  }
  if ((flags & RH_SCHED_TIME)) {
    dst->sched_time = src->sched_time;
  }
  if ((flags & RH_DURATION)) {
    dst->duration = src->duration;
  }
  if ((flags & RH_STOP_TIME)) {
    dst->stop_time = src->stop_time;
  }
  if ((flags & RH_FINISH_TIME)) {
    dst->finish_time = src->finish_time;
  }
  if ((flags & RH_SAVED_DURATION)) {
    dst->saved_duration = src->saved_duration;
  }
  if ((flags & RH_SAVED_STOP_TIME)) {
    dst->saved_stop_time = src->saved_stop_time;
  }
  if ((flags & RH_SAVED_FINISH_TIME)) {
    dst->saved_finish_time = src->saved_finish_time;
  }
}

static int
do_update_header(
        struct rldb_mysql_cnts *cs,
        const struct run_header *rh,
        int flags)
{
  struct rldb_mysql_state *state = cs->plugin_state;
  struct runlog_state *rls = cs->rl_state;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %srunheaders SET ", state->md->table_prefix);
  generate_update_header_clause(state, cmd_f, rh, flags);
  fprintf(cmd_f, " WHERE contest_id = %d ;", cs->contest_id);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  update_header(&rls->head, rh, flags);
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
start_func(
        struct rldb_plugin_cnts *cdata,
        time_t start_time)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct run_header rh;

  memset(&rh, 0, sizeof(rh));
  rh.start_time = start_time;
  return do_update_header(cs, &rh, RH_START_TIME);
}

static int
stop_func(
        struct rldb_plugin_cnts *cdata,
        time_t stop_time)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct run_header rh;

  memset(&rh, 0, sizeof(rh));
  rh.stop_time = stop_time;
  return do_update_header(cs, &rh, RH_STOP_TIME);
}

static int
set_duration_func(
        struct rldb_plugin_cnts *cdata,
        int duration)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct run_header rh;

  memset(&rh, 0, sizeof(rh));
  rh.duration = duration;
  return do_update_header(cs, &rh, RH_DURATION);
}

static int
schedule_func(
        struct rldb_plugin_cnts *cdata,
        time_t sched_time)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct run_header rh;

  memset(&rh, 0, sizeof(rh));
  rh.sched_time = sched_time;
  return do_update_header(cs, &rh, RH_SCHED_TIME);
}

static int
set_finish_time_func(
        struct rldb_plugin_cnts *cdata,
        time_t finish_time)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct run_header rh;

  memset(&rh, 0, sizeof(rh));
  rh.finish_time = finish_time;
  return do_update_header(cs, &rh, RH_FINISH_TIME);
}

static int
save_times_func(struct rldb_plugin_cnts *cdata)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct runlog_state *rls = cs->rl_state;
  struct run_header rh;

  memset(&rh, 0, sizeof(rh));
  rh.saved_duration = rls->head.duration;
  rh.saved_stop_time = rls->head.stop_time;
  rh.saved_finish_time = rls->head.finish_time;
  return do_update_header(cs, &rh, RH_SAVED_DURATION | RH_SAVED_STOP_TIME | RH_SAVED_FINISH_TIME);
}

static int
set_status_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_status)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct run_entry te;

  memset(&te, 0, sizeof(te));
  te.status = new_status;

  return do_update_entry(cs, run_id, &te, RE_STATUS);
}

static int
clear_entry_func(
        struct rldb_plugin_cnts *cdata,
        int run_id)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct rldb_mysql_state *state = cs->plugin_state;
  struct runlog_state *rls = cs->rl_state;
  struct run_entry *re;

  ASSERT(run_id >= 0 && run_id < rls->run_u);
  re = &rls->runs[run_id];

  if (state->mi->simple_fquery(state->md, "DELETE FROM %sruns WHERE run_id = %d AND contest_id = %d ;", state->md->table_prefix, run_id, cs->contest_id) < 0)
    return -1;

  memset(re, 0, sizeof(*re));
  re->status = RUN_EMPTY;
  re->run_id = run_id;
  if (run_id == rls->run_u - 1) rls->run_u--;
  return 0;
}

static int
set_hidden_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_hidden)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct run_entry te;

  ASSERT(new_hidden >= 0 && new_hidden <= 1);

  memset(&te, 0, sizeof(te));
  te.is_hidden = new_hidden;

  return do_update_entry(cs, run_id, &te, RE_IS_HIDDEN);
}

static int
set_judge_id_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_judge_id)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct run_entry te;

  memset(&te, 0, sizeof(te));
  te.judge_id = new_judge_id;

  return do_update_entry(cs, run_id, &te, RE_JUDGE_ID);
}

static int
set_pages_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_pages)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct run_entry te;

  memset(&te, 0, sizeof(te));
  te.pages = new_pages;

  return do_update_entry(cs, run_id, &te, RE_PAGES);
}

static int
set_entry_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        const struct run_entry *in,
        int flags)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct runlog_state *rls = cs->rl_state;

  ASSERT(run_id >= 0 && run_id < rls->run_u);
  ASSERT(rls->runs[run_id].status != RUN_EMPTY);

  (void) rls;
  return do_update_entry(cs, run_id, in, flags);
}

static int
squeeze_func(struct rldb_plugin_cnts *cdata)
{
  err("rldb_mysql: squeeze_func: not implemented");
  return -1;
}

static int
put_entry_func(
        struct rldb_plugin_cnts *cdata,
        const struct run_entry *re)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct rldb_mysql_state *state = cs->plugin_state;
  struct runlog_state *rls = cs->rl_state;
  struct run_entry_internal ri;
  struct timeval curtime;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  ASSERT(re);
  ASSERT(re->run_id >= 0);

  expand_runs(rls, re->run_id);
  if (rls->runs[re->run_id].status != RUN_EMPTY) return -1;
  if (re->status == RUN_EMPTY) return -1;

  // FIXME: check, that time is valid

  memset(&ri, 0, sizeof(ri));
  gettimeofday(&curtime, 0);

  ri.run_id = re->run_id;
  ri.contest_id = cs->contest_id;
  ri.size = re->size;
  ri.create_time = re->time;
  ri.create_nsec = re->nsec;
  ri.user_id = re->user_id;
  ri.prob_id = re->prob_id;
  ri.lang_id = re->lang_id;
  ri.status = re->status;
  ri.ip = re->a.ip;
  ri.ip_version = 4;
  ri.ssl_flag = re->ssl_flag;
  if (re->sha1[0] || re->sha1[1] || re->sha1[2] || re->sha1[3]
      || re->sha1[4]) {
    ri.hash = unparse_sha1(re->sha1);
  }
  ri.score = re->score;
  ri.test_num = re->test;
  ri.score_adj = re->score_adj;
  ri.locale_id = re->locale_id;
  ri.judge_id = re->judge_id;
  ri.variant = re->variant;
  ri.pages = re->pages;
  ri.is_imported = re->is_imported;
  ri.is_hidden = re->is_hidden;
  ri.is_readonly = re->is_readonly;
  ri.is_examinable = re->is_examinable;
  if (re->mime_type) {
    ri.mime_type = (unsigned char*) mime_type_get_type(re->mime_type);
  }
  ri.examiners0 = re->examiners[0];
  ri.examiners1 = re->examiners[1];
  ri.examiners2 = re->examiners[2];
  ri.exam_score0 = re->exam_score[0];
  ri.exam_score1 = re->exam_score[1];
  ri.exam_score2 = re->exam_score[2];
  ri.last_change_time = curtime.tv_sec;
  ri.last_change_nsec = curtime.tv_usec * 1000;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %sruns VALUES ( ", state->md->table_prefix);
  state->mi->unparse_spec(state->md, cmd_f, RUNS_ROW_WIDTH, runs_spec, &ri);
  fprintf(cmd_f, " ) ;");
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0;

  memcpy(&rls->runs[re->run_id], re, sizeof(rls->runs[0]));

  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
put_header_func(
        struct rldb_plugin_cnts *cdata,
        const struct run_header *rh)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;

  return do_update_header(cs, rh, RH_ALL);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "MYSQL")
 * End:
 */
