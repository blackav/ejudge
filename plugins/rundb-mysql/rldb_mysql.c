/* -*- mode: c -*- */

/* Copyright (C) 2008-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/ej_limits.h"
#include "ejudge/rldb_plugin.h"
#include "ejudge/runlog.h"
#include "ejudge/teamdb.h"
#include "../common-mysql/common_mysql.h"

#define RUNS_ACCESS
#include "ejudge/runlog_state.h"

#include "ejudge/errlog.h"
#include "ejudge/xml_utils.h"
#include "ejudge/contests.h"
#include "ejudge/prepare.h"
#include "ejudge/mime_type.h"
#include "ejudge/misctext.h"
#include "ejudge/compat.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/metrics_contest.h"
#include "ejudge/mixed_id.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <mysql.h>

#include <stdarg.h>
#include <errno.h>
#include <sys/time.h>

#if CONF_HAS_LIBUUID - 0 != 0
#include <uuid/uuid.h>
#endif

struct rldb_mysql_state
{
  int nref;

  // mysql access
  struct common_mysql_iface *mi;
  struct common_mysql_state *md;

  int window;

  long long last_serial_id;
};

struct rldb_mysql_cnts
{
  struct rldb_mysql_state *plugin_state;
  struct runlog_state *rl_state;
  int contest_id;
  struct metrics_contest_data *metrics;
  int next_run_id_set;
  int next_run_id;
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
  get_insert_run_id_func,
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
  NULL, // set_judge_id - deprecated
  set_pages_func,
  set_entry_func,
  squeeze_func,
  put_entry_func,
  put_header_func,
  NULL, // change_status_2 - deprecated
  check_func,
  change_status_3_func,
  change_status_4_func,
  NULL,
  NULL, // add_entry_2_func - deprecated
  user_run_header_set_start_time_func,
  user_run_header_set_stop_time_func,
  user_run_header_set_duration_func,
  user_run_header_set_is_checked_func,
  user_run_header_delete_func,
  append_run_func,
  run_set_is_checked_func,
};

static long long
get_current_time_us(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * 1000000LL + tv.tv_usec;
}

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
        const struct ejudge_cfg *config,
        struct xml_tree *tree)
{
  struct rldb_mysql_state *state = (struct rldb_mysql_state*) data;
  const struct common_loaded_plugin *mplg;
  const struct xml_parse_spec *spec = ejudge_cfg_get_spec();
  (void) spec;

  // load common_mysql plugin
  if (!(mplg = plugin_load_external(0, "common", "mysql", config))) {
    err("cannot load common_mysql plugin");
    return -1;
  }
  state->mi = (struct common_mysql_iface*) mplg->iface;
  state->md = (struct common_mysql_state*) mplg->data;

  for (struct xml_tree *p = tree->first_down; p; p = p->right) {
    ASSERT(p->tag == spec->default_elem);
    if (!strcmp(p->name[0], "window")) {
      if (p->first) return xml_err_attrs(p);
      if (p->first_down) return xml_err_nested_elems(p);
      if (state->window > 0) return xml_err_elem_redefined(p);
      if (xml_parse_int(NULL, "", p->line, p->column, p->text, &state->window) < 0) return -1;
    } else {
      return xml_err_elem_not_allowed(p);
    }
  }

  return 0;
}

#include "tables.inc.c"

#define RUN_DB_VERSION 27

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
  if (mi->simple_fquery(md, create_userrunheaders_query, md->table_prefix) < 0)
    db_error_fail(md);
  if (mi->simple_fquery(md,
                        "INSERT INTO %sconfig VALUES ('run_version', '%d') ;",
                        md->table_prefix, RUN_DB_VERSION) < 0)
    db_error_fail(md);
  return 0;

 fail:
  return -1;
}

static long long
next_serial_id(struct rldb_mysql_state *state)
{
  if (state->last_serial_id > 0) {
    return ++state->last_serial_id;
  }

  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;

  int r = mi->fquery(md, 1, "SELECT MAX(serial_id) FROM %sruns ;", md->table_prefix);
  if (r < 0) {
    err("request failed");
    goto reset_counter;
  }
  if (md->row_count > 1) {
    err("too many rows");
    goto reset_counter;
  }
  if (md->row_count < 1) {
    err("too few rows");
    goto reset_counter;
  }
  if (mi->next_row(md) < 0) {
    err("database error");
    goto reset_counter;
  }
  if (!md->row[0]) {
    goto reset_counter;
  }
  int len = strlen(md->row[0]);
  if (len != md->lengths[0]) {
    err("binary data");
    mi->free_res(md);
    goto reset_counter;
  }
  const char *s = md->row[0];
  char *eptr = NULL;
  errno = 0;
  long long value = strtoll(s, &eptr, 10);
  if (errno || *eptr || s == eptr || value < 0) {
    err("invalid data");
    mi->free_res(md);
    goto reset_counter;
  }

  state->last_serial_id = value + 1;
  return state->last_serial_id;

reset_counter:;
  state->last_serial_id = 1;
  return state->last_serial_id;
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

  if (run_version < 1) {
    err("run_version == %d is not supported", run_version);
    goto fail;
  }

  while (run_version >= 0) {
    switch (run_version) {
    case 1:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN is_marked TINYINT NOT NULL DEFAULT 0 AFTER last_change_nsec",
                            md->table_prefix) < 0)
        return -1;
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN is_saved TINYINT NOT NULL DEFAULT 0 AFTER is_marked",
                            md->table_prefix) < 0)
        return -1;
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN saved_status INT NOT NULL DEFAULT 0 AFTER is_saved",
                            md->table_prefix) < 0)
        return -1;
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN saved_score INT NOT NULL DEFAULT 0 AFTER saved_status",
                            md->table_prefix) < 0)
        return -1;
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN saved_test INT NOT NULL DEFAULT 0 AFTER saved_score",
                            md->table_prefix) < 0)
        return -1;
      break;
    case 2:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN run_uuid CHAR(40) DEFAULT NULL AFTER hash", md->table_prefix) < 0)
        return -1;
      break;
    case 3:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN passed_mode TINYINT NOT NULL DEFAULT 0 AFTER saved_test", md->table_prefix) < 0)
        return -1;
      break;
    case 4:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN eoln_type TINYINT NOT NULL DEFAULT 0 AFTER passed_mode", md->table_prefix) < 0)
        return -1;
      break;
    case 5:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN store_flags TINYINT NOT NULL DEFAULT 0 AFTER eoln_type", md->table_prefix) < 0)
        return -1;
      break;
    case 6:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN token_flags TINYINT NOT NULL DEFAULT 0 AFTER store_flags", md->table_prefix) < 0)
        return -1;
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN token_count TINYINT NOT NULL DEFAULT 0 AFTER token_flags", md->table_prefix) < 0)
        return -1;
      break;
    case 7:
      if (mi->simple_fquery(md, "ALTER TABLE %srunheaders ADD COLUMN next_run_id INT NOT NULL DEFAULT 0 AFTER last_change_nsec", md->table_prefix) < 0)
        return -1;
      break;
    case 8:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD INDEX runs_contest_id_idx (contest_id);", md->table_prefix) < 0)
        return -1;
      break;
    case 9:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN prob_uuid VARCHAR(40) DEFAULT NULL AFTER token_count", md->table_prefix) < 0)
        return -1;
      break;
    case 10:
      if (mi->simple_fquery(md, create_userrunheaders_query, md->table_prefix) < 0)
        return -1;
      // ignore errors
      mi->simple_fquery(md, "ALTER TABLE %suserrunheaders ADD INDEX userrunheaders_contest_id_idx (contest_id);", md->table_prefix);
      mi->simple_fquery(md, "ALTER TABLE %suserrunheaders ADD INDEX userrunheaders_user_id_idx (user_id);", md->table_prefix);
      // ignore error
      mi->simple_fquery(md, "ALTER TABLE %sruns ADD INDEX runs_user_id_idx (user_id) ;", md->table_prefix);
      break;
    case 11:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin ;", md->table_prefix) < 0)
        return -1;
      mi->simple_fquery(md, "ALTER TABLE %sruns DROP PRIMARY KEY ;", md->table_prefix);
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD UNIQUE KEY runs_run_contest_id_idx(run_id, contest_id) ;", md->table_prefix) < 0)
        return -1;
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN serial_id INT(18) NOT NULL PRIMARY KEY AUTO_INCREMENT FIRST ;", md->table_prefix) < 0)
        return -1;
      break;
    case 12:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns MODIFY create_time DATETIME(6) NOT NULL ;", md->table_prefix) < 0)
        return -1;
      break;
    case 13:
      if (mi->simple_fquery(md,
                            "ALTER TABLE %sruns"
                            " MODIFY prob_id INT UNSIGNED NOT NULL DEFAULT 0,"
                            " MODIFY lang_id INT UNSIGNED NOT NULL DEFAULT 0,"
                            " MODIFY status INT NOT NULL DEFAULT 99,"
                            " MODIFY ip VARCHAR(64) DEFAULT NULL,"
                            " MODIFY hash VARCHAR (128) DEFAULT NULL,"
                            " MODIFY run_uuid CHAR(40) DEFAULT NULL,"
                            " MODIFY score INT NOT NULL DEFAULT -1,"
                            " MODIFY test_num INT NOT NULL DEFAULT -1,"
                            " MODIFY score_adj INT NOT NULL DEFAULT 0,"
                            " MODIFY locale_id INT NOT NULL DEFAULT 0,"
                            " MODIFY judge_id INT NOT NULL DEFAULT 0,"
                            " MODIFY variant INT NOT NULL DEFAULT 0,"
                            " MODIFY pages INT NOT NULL DEFAULT 0,"
                            " MODIFY mime_type VARCHAR(64) DEFAULT NULL,"
                            " MODIFY examiners0 INT NOT NULL DEFAULT 0,"
                            " MODIFY examiners1 INT NOT NULL DEFAULT 0,"
                            " MODIFY examiners2 INT NOT NULL DEFAULT 0,"
                            " MODIFY exam_score0 INT NOT NULL DEFAULT 0,"
                            " MODIFY exam_score1 INT NOT NULL DEFAULT 0,"
                            " MODIFY exam_score2 INT NOT NULL DEFAULT 0,"
                            " MODIFY last_change_time DATETIME DEFAULT NULL,"
                            " MODIFY last_change_nsec INT UNSIGNED NOT NULL DEFAULT 0"
                            ";", md->table_prefix) < 0)
        return -1;
      break;
    case 14:
      if (mi->simple_fquery(md, "ALTER TABLE %srunheaders DROP COLUMN next_run_id ;", md->table_prefix) < 0)
        return -1;
      break;
    case 15:
      if (mi->simple_fquery(md, "ALTER TABLE %srunheaders "
                            " MODIFY start_time DATETIME DEFAULT NULL, "
                            " MODIFY sched_time DATETIME DEFAULT NULL, "
                            " MODIFY stop_time DATETIME DEFAULT NULL, "
                            " MODIFY finish_time DATETIME DEFAULT NULL, "
                            " MODIFY saved_stop_time DATETIME DEFAULT NULL, "
                            " MODIFY saved_finish_time DATETIME DEFAULT NULL, "
                            " MODIFY last_change_time DATETIME DEFAULT NULL "
                            " ;", md->table_prefix) < 0)
        return -1;
      break;
    case 16:
      if (mi->simple_fquery(md,
                            "ALTER TABLE %sruns"
                            " DROP COLUMN is_examinable,"
                            " DROP COLUMN examiners0,"
                            " DROP COLUMN examiners1,"
                            " DROP COLUMN examiners2,"
                            " DROP COLUMN exam_score0,"
                            " DROP COLUMN exam_score1,"
                            " DROP COLUMN exam_score2"
                            ";", md->table_prefix) < 0)
        return -1;
      break;
    case 17:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN is_checked TINYINT NOT NULL DEFAULT 0 AFTER prob_uuid", md->table_prefix) < 0)
        return -1;
      break;
    case 18:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN judge_uuid VARCHAR(40) DEFAULT NULL AFTER is_checked", md->table_prefix) < 0)
        return -1;
      break;
    case 19:
      if (mi->simple_fquery(md, "ALTER TABLE %srunheaders ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin ;", md->table_prefix) < 0)
        return -1;
      break;
    case 20:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN is_vcs TINYINT NOT NULL DEFAULT 0 AFTER judge_uuid", md->table_prefix) < 0)
        return -1;
      break;
    case 21:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns MODIFY COLUMN serial_id INT(18) NOT NULL ;", md->table_prefix) < 0)
        return -1;
      if (mi->simple_fquery(md, "ALTER TABLE %sruns DROP PRIMARY KEY ;", md->table_prefix) < 0)
        return -1;
      if (mi->simple_fquery(md, "ALTER TABLE %sruns MODIFY COLUMN serial_id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT ;", md->table_prefix) < 0)
        return -1;
      break;
    case 22:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", md->table_prefix) < 0)
        return -1;
      if (mi->simple_fquery(md, "ALTER TABLE %srunheaders DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", md->table_prefix) < 0)
        return -1;
      if (mi->simple_fquery(md, "ALTER TABLE %suserrunheaders ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", md->table_prefix) < 0)
        return -1;
      break;
    case 23:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns MODIFY COLUMN ip VARCHAR(64) DEFAULT NULL, MODIFY COLUMN hash VARCHAR (128) DEFAULT NULL, MODIFY COLUMN run_uuid CHAR(40) DEFAULT NULL, MODIFY COLUMN mime_type VARCHAR(64) DEFAULT NULL, MODIFY COLUMN prob_uuid VARCHAR(40) DEFAULT NULL, MODIFY COLUMN judge_uuid VARCHAR(40) DEFAULT NULL ;", md->table_prefix) < 0)
        return -1;
      break;
    case 24:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN verdict_bits INT NOT NULL DEFAULT 0 AFTER is_vcs", md->table_prefix) < 0)
        return -1;
      break;
    case 25:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN ext_user_kind TINYINT NOT NULL DEFAULT 0 AFTER verdict_bits, ADD COLUMN ext_user VARCHAR(40) DEFAULT NULL AFTER ext_user_kind", md->table_prefix) < 0)
        return -1;
      break;
    case 26:
      if (mi->simple_fquery(md, "ALTER TABLE %sruns ADD COLUMN notify_driver TINYINT NOT NULL DEFAULT 0 AFTER ext_user, ADD COLUMN notify_kind TINYINT NOT NULL DEFAULT 0 AFTER notify_driver, ADD COLUMN notify_queue VARCHAR(40) DEFAULT NULL AFTER notify_kind", md->table_prefix) < 0)
        return -1;
      break;
    case RUN_DB_VERSION:
      run_version = -1;
      break;
    default:
      // FIXME: report an error?
      run_version = -1;
      break;
    }
  if (run_version >= 0) {
    ++run_version;
    if (mi->simple_fquery(md, "UPDATE %sconfig SET config_val = '%d' WHERE config_key = 'run_version' ;", md->table_prefix, run_version) < 0)
      return -1;
  }
  }

  return 0;

 fail:
  mi->free_res(md);
  return -1;
}

static int
next_run_id(struct rldb_mysql_cnts *cs)
{
  if (cs->next_run_id_set) {
    return cs->next_run_id++;
  }

  struct rldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;

  int r = mi->fquery(md, 1, "SELECT MAX(run_id) FROM %s runs WHERE contest_id = %d;", md->table_prefix, cs->contest_id);
  if (r < 0) {
    err("request failed");
    goto reset_counter;
  }
  if (md->row_count > 1) {
    err("too many rows");
    goto reset_counter;
  }
  if (md->row_count < 1) {
    err("too few rows");
    goto reset_counter;
  }
  if (mi->next_row(md) < 0) {
    err("database error");
    goto reset_counter;
  }
  if (!md->row[0]) {
    goto reset_counter;
  }
  int len = strlen(md->row[0]);
  if (len != md->lengths[0]) {
    err("binary data");
    mi->free_res(md);
    goto reset_counter;
  }

  const char *s = md->row[0];
  char *eptr = NULL;
  errno = 0;
  long value = strtol(s, &eptr, 10);
  if (errno || *eptr || s == eptr || value < 0 || (int) value != value) {
    err("invalid data");
    mi->free_res(md);
    goto reset_counter;
  }

  cs->next_run_id = value + 1;
  cs->next_run_id_set = 1;
  return cs->next_run_id++;

reset_counter:;
  cs->next_run_id = 1;
  cs->next_run_id_set = 1;
  return 0;
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

static int
load_user_header(
        struct rldb_mysql_cnts *cs)
{
  struct rldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  struct runlog_state *rls = cs->rl_state;

  int min_user_id = 0, max_user_id = 0;

  if (mi->fquery(md, 2,
                 "SELECT MIN(user_id), MAX(user_id) FROM %suserrunheaders WHERE contest_id = %d ;", md->table_prefix, cs->contest_id) < 0) {
    goto fail;
  }
  if (md->row_count == 1) {
    if (mi->next_row(md) < 0) goto fail;
    struct user_run_user_id_internal ri = {};
    if (mi->parse_spec(md, md->field_count, md->row, md->lengths,
                       USERRUNUSERID_ROW_WIDTH, user_run_user_id_spec, &ri) < 0)
      goto fail;
    if (ri.min_user_id > 0) min_user_id = ri.min_user_id;
    if (ri.max_user_id > 0) max_user_id = ri.max_user_id;
  }
  mi->free_res(md);

  if (mi->fquery(md, 2,
                 "SELECT MIN(user_id), MAX(user_id) FROM %sruns WHERE contest_id = %d ;", md->table_prefix, cs->contest_id) < 0) {
    goto fail;
  }
  if (md->row_count == 1) {
    if (mi->next_row(md) < 0) goto fail;
    struct user_run_user_id_internal ri = {};
    if (mi->parse_spec(md, md->field_count, md->row, md->lengths,
                       USERRUNUSERID_ROW_WIDTH, user_run_user_id_spec, &ri) < 0)
      goto fail;
    if (ri.min_user_id > 0) {
      if (min_user_id <= 0 || ri.min_user_id < min_user_id) {
        min_user_id = ri.min_user_id;
      }
    }
    if (ri.max_user_id > 0 && ri.max_user_id > max_user_id) {
      max_user_id = ri.max_user_id;
    }
  }
  mi->free_res(md);

  // if user_id range is available, preallocate map
  if (min_user_id > 0 && max_user_id > 0 && min_user_id <= max_user_id) {
    int count = max_user_id - min_user_id + 1;
    int size = 32;
    while (size < count) {
      size *= 2;
    }
    if (count < size) {
      min_user_id -= (size - count) / 2;
      if (min_user_id < 1) min_user_id = 1;
    }
    rls->urh.low_user_id = min_user_id;
    rls->urh.high_user_id = min_user_id + size;
    XCALLOC(rls->urh.umap, size);
  }

  if (mi->fquery(md, USERRUNHEADERS_ROW_WIDTH,
                 "SELECT * FROM %suserrunheaders WHERE contest_id = %d ORDER BY user_id ;",
                 md->table_prefix, cs->contest_id) < 0) {
    goto fail;
  }
  if (md->row_count <= 0) {
    return 0;
  }

  // preallocate entries
  if (md->row_count > 0) {
    int reserved = 32;
    while (reserved <= md->row_count) {
      reserved *= 2;
    }
    rls->urh.reserved = reserved;
    XCALLOC(rls->urh.infos, reserved);
    rls->urh.size = 1;
  }

  for (int i = 0; i < md->row_count; ++i) {
    struct user_run_header_internal urhi = {};
    if (mi->next_row(md) < 0) goto fail;
    if (mi->parse_spec(md, md->field_count, md->row, md->lengths,
                       USERRUNHEADERS_ROW_WIDTH, user_run_headers_spec, &urhi) < 0)
      goto fail;

    if (urhi.user_id > 0) {
      if (urhi.user_id < rls->urh.low_user_id || urhi.user_id >= rls->urh.high_user_id) {
        run_extend_user_run_header_map(rls, urhi.user_id);
      }
      int offset = urhi.user_id - rls->urh.low_user_id;
      if (!rls->urh.umap[offset]) {
        if (rls->urh.size == rls->urh.reserved) {
          if (!rls->urh.reserved) {
            rls->urh.reserved = 32;
            XCALLOC(rls->urh.infos, rls->urh.reserved);
            rls->urh.size = 1;
          } else {
            rls->urh.reserved *= 2;
            XREALLOC(rls->urh.infos, rls->urh.reserved);
          }
        }
        int index = rls->urh.size++;
        rls->urh.umap[offset] = index;
        struct user_run_header_info *p = &rls->urh.infos[index];
        p->user_id = urhi.user_id;
        p->duration = urhi.duration;
        p->is_virtual = urhi.is_virtual;
        p->is_checked = urhi.is_checked;
        p->has_db_record = 1;
        p->last_change_user_id = urhi.last_change_user_id;
        p->start_time = urhi.start_time;
        p->stop_time = urhi.stop_time;
        p->last_change_time = urhi.last_change_time;
      }
    }
  }

  mi->free_res(md);
  return 1;

fail:
  mi->free_res(md);
  return -1;
}

static void
expand_runs(struct runlog_state *rls, int run_id)
{
  int new_a, i;
  struct run_entry *new_v;

  ASSERT(run_id >= rls->run_f);

  if (run_id < rls->run_u) return;
  if (run_id - rls->run_f < rls->run_a) {
    rls->run_u = run_id + 1;
    return;
  }

  if (!(new_a = rls->run_a)) new_a = 128;
  while (run_id - rls->run_f >= new_a) new_a *= 2;
  XCALLOC(new_v, new_a);
  for (i = 0; i < new_a; ++i) {
    // this is physicall access, must add to get run id
    new_v[i].run_id = i + rls->run_f;
    new_v[i].status = RUN_EMPTY;
  }
  if (rls->run_u - rls->run_f > 0) memcpy(new_v, rls->runs, (rls->run_u - rls->run_f) * sizeof(new_v[0]));
  xfree(rls->runs);
  rls->runs = new_v;
  rls->run_a = new_a;
  rls->run_u = run_id + 1;
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
  ej_uuid_t run_uuid;
  ej_uuid_t prob_uuid;
  ej_uuid_t judge_uuid;
  ej_mixed_id_t ext_user;
  ej_mixed_id_t notify_queue;

  memset(&ri, 0, sizeof(ri));
  if (state->window > 0) {
    if (mi->fquery(md, RUNS_ROW_WIDTH,
                   "(SELECT * FROM %sruns WHERE contest_id=%d ORDER BY run_id DESC LIMIT %d) ORDER BY run_id;",
                   md->table_prefix, cs->contest_id, state->window) < 0)
      goto fail;
  } else {
    if (mi->fquery(md, RUNS_ROW_WIDTH,
                   "SELECT * FROM %sruns WHERE contest_id=%d ORDER BY run_id ;",
                   md->table_prefix, cs->contest_id) < 0)
      goto fail;
  }
  if (!md->row_count) {
    mi->free_res(md);
    return 0;
  }

  // as the result is sorted by run_id, the first table row determines the id_offset (run_f) for the runs table
  int run_f = -1;

  for (i = 0; i < md->row_count; i++) {
    memset(&ri, 0, sizeof(ri));
    memset(sha1, 0, sizeof(sha1));
    memset(&run_uuid, 0, sizeof(run_uuid));
    memset(&prob_uuid, 0, sizeof(prob_uuid));
    memset(&judge_uuid, 0, sizeof(judge_uuid));
    if (mi->next_row(md) < 0) goto fail;
    mime_type = 0;
    if (mi->parse_spec(md, md->field_count, md->row, md->lengths,
                       RUNS_ROW_WIDTH, runs_spec, &ri) < 0)
      goto fail;
    if (ri.run_id < 0) db_error_inv_value_fail(md, "run_id");
    if (run_f < 0) {
      run_f = ri.run_id;
      rls->run_f = run_f; // FIXME: check!
    }
    if (ri.run_id < run_f) continue;
    if (ri.size < 0) db_error_inv_value_fail(md, "size");
    /* FIXME: check ordering on create_time/create_nsec */
    if (ri.create_nsec < 0 || ri.create_nsec > NSEC_MAX)
      db_error_inv_value_fail(md, "create_nsec");
    if (!run_is_valid_status(ri.status))
      db_error_inv_value_fail(md, "status");
    if (ri.status == RUN_EMPTY) {
      xfree(ri.hash); ri.hash = 0;
      xfree(ri.mime_type); ri.mime_type = 0;
      xfree(ri.run_uuid); ri.run_uuid = 0;
      xfree(ri.prob_uuid); ri.prob_uuid = NULL;
      xfree(ri.judge_uuid); ri.judge_uuid = NULL;
      xfree(ri.ext_user); ri.ext_user = NULL;
      xfree(ri.notify_queue); ri.notify_queue = NULL;

      expand_runs(rls, ri.run_id);
      re = &rls->runs[ri.run_id - rls->run_f];
      memset(re, 0, sizeof(*re));

      re->run_id = ri.run_id;
      /*
      re->time = ri.create_time;
      re->nsec = ri.create_nsec;
      */
      re->time = ri.create_tv.tv_sec;
      re->nsec = ri.create_nsec;
      if (re->nsec <= 0) re->nsec = ri.create_tv.tv_usec * 1000;
      re->status = ri.status;
      re->last_change_us = ri.last_change_time * 1000000LL + ri.last_change_nsec / 1000;
      continue;
    }
    if (ri.user_id <= 0) db_error_inv_value_fail(md, "user_id");
    if (ri.prob_id < 0) db_error_inv_value_fail(md, "prob_id");
    if (ri.lang_id < 0) db_error_inv_value_fail(md, "lang_id");
    if (ri.hash && parse_sha1(sha1, ri.hash) < 0)
      db_error_inv_value_fail(md, "hash");
    if (ri.run_uuid) {
#if CONF_HAS_LIBUUID - 0 != 0
      uuid_parse(ri.run_uuid, (void*) &run_uuid);
#endif
    }
    if (ri.prob_uuid) {
      uuid_parse(ri.prob_uuid, (void*) &prob_uuid);
    }
    if (ri.judge_uuid) {
      uuid_parse(ri.judge_uuid, (void*) &judge_uuid);
    }
    //if (ri.ip_version != 4) db_error_inv_value_fail(md, "ip_version");
    if (ri.mime_type && (mime_type = mime_type_parse(ri.mime_type)) < 0)
      db_error_inv_value_fail(md, "mime_type");
    if (ri.ext_user_kind > 0 && ri.ext_user_kind < MIXED_ID_LAST) {
      if (mixed_id_unmarshall(&ext_user, ri.ext_user_kind, ri.ext_user) < 0) {
        // silently ignore parse error
        ri.ext_user_kind = 0;
        memset(&ext_user, 0, sizeof(ext_user));
      }
    } else {
      ri.ext_user_kind = 0;
      memset(&ext_user, 0, sizeof(ext_user));
    }
    if (ri.notify_driver > 0
        && ri.notify_kind > 0 && ri.notify_kind < MIXED_ID_LAST) {
      if (mixed_id_unmarshall(&notify_queue, ri.notify_kind, ri.notify_queue) < 0) {
        ri.notify_driver = 0;
        ri.notify_kind = 0;
        memset(&notify_queue, 0, sizeof(notify_queue));
      }
    } else {
      ri.notify_driver = 0;
      ri.notify_kind = 0;
      memset(&notify_queue, 0, sizeof(notify_queue));
    }
    xfree(ri.hash); ri.hash = 0;
    xfree(ri.mime_type); ri.mime_type = 0;
    xfree(ri.run_uuid); ri.run_uuid = 0;
    xfree(ri.prob_uuid); ri.prob_uuid = NULL;
    xfree(ri.judge_uuid); ri.judge_uuid = NULL;
    xfree(ri.ext_user); ri.ext_user = NULL;
    xfree(ri.notify_queue); ri.notify_queue = NULL;

    expand_runs(rls, ri.run_id);
    re = &rls->runs[ri.run_id - rls->run_f];

    re->run_id = ri.run_id;
    re->serial_id = ri.serial_id;
    re->size = ri.size;
    /*
    re->time = ri.create_time;
    re->nsec = ri.create_nsec;
    */
    re->time = ri.create_tv.tv_sec;
    re->nsec = ri.create_nsec;
    if (re->nsec <= 0) re->nsec = ri.create_tv.tv_usec * 1000;
    re->user_id = ri.user_id;
    re->prob_id = ri.prob_id;
    re->lang_id = ri.lang_id;
    ipv6_to_run_entry(&ri.ip, re);
    memcpy(re->h.sha1, sha1, sizeof(re->h.sha1));
    memcpy(&re->run_uuid, &run_uuid, sizeof(re->run_uuid));
    re->prob_uuid = prob_uuid;
    if (ej_uuid_is_nonempty(judge_uuid)) {
      re->judge_uuid_flag = 1;
      re->j.judge_uuid = judge_uuid;
    } else if (ri.judge_id > 0) {
      re->j.judge_id = ri.judge_id;
    }
    re->score = ri.score;
    re->test = ri.test_num;
    re->score_adj = ri.score_adj;
    re->locale_id = ri.locale_id;
    re->status = ri.status;
    re->is_imported = ri.is_imported;
    re->variant = ri.variant;
    re->is_hidden = ri.is_hidden;
    re->is_readonly = ri.is_readonly;
    re->pages = ri.pages;
    re->ssl_flag = ri.ssl_flag;
    re->mime_type = mime_type;
    re->is_marked = ri.is_marked;
    re->is_saved = ri.is_saved;
    re->saved_status = ri.saved_status;
    re->saved_score = ri.saved_score;
    re->saved_test = ri.saved_test;
    re->passed_mode = ri.passed_mode;
    re->eoln_type = ri.eoln_type;
    re->store_flags = ri.store_flags;
    re->token_flags = ri.token_flags;
    re->token_count = ri.token_count;
    re->is_checked = ri.is_checked;
    re->is_vcs = ri.is_vcs;
    re->verdict_bits = ri.verdict_bits;
    re->last_change_us = ri.last_change_time * 1000000LL + ri.last_change_nsec / 1000;
    re->ext_user_kind = ri.ext_user_kind;
    re->ext_user = ext_user;
    re->notify_driver = ri.notify_driver;
    re->notify_kind = ri.notify_kind;
    re->notify_queue = notify_queue;
  }
  return 1;

 fail:
  xfree(ri.hash);
  xfree(ri.mime_type);
  xfree(ri.run_uuid);
  xfree(ri.prob_uuid);
  xfree(ri.judge_uuid);
  xfree(ri.ext_user);
  xfree(ri.notify_queue);
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
        struct metrics_contest_data *metrics,
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
  cs->metrics = metrics;
  if (cnts) cs->contest_id = cnts->id;
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
  if (load_user_header(cs) < 0) goto fail;
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
  if (!cs) return 0;
  struct runlog_state *rls = cs->rl_state;

  rls = cs->rl_state;
  if (rls) {
    xfree(rls->runs); rls->runs = 0;
    rls->run_a = rls->run_u = 0;
    rls->run_f = 0;
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
  rls->run_f = 0;
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
  xfree(rls->urh.umap);
  xfree(rls->urh.infos);
  rls->urh.low_user_id = 0;
  rls->urh.high_user_id = 0;
  rls->urh.umap = NULL;
  rls->urh.size = 0;
  rls->urh.reserved = 0;
  rls->urh.infos = NULL;

  mi->simple_fquery(md, "DELETE FROM %sruns WHERE contest_id = %d ;",
                    md->table_prefix, cs->contest_id);
  mi->simple_fquery(md, "DELETE FROM %srunheaders WHERE contest_id = %d ;",
                    md->table_prefix, cs->contest_id);
  mi->simple_fquery(md, "DELETE FROM %suserrunheaders WHERE contest_id = %d ;",
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
        int id_offset,
        int total_entries,
        struct run_entry *entries)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts*) cdata;
  struct rldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  struct runlog_state *rls = cs->rl_state;
  int i;

  // FIXME: support id_offset > 0
  ASSERT(id_offset == 0);

  mi->simple_fquery(md, "DELETE FROM %sruns WHERE contest_id = %d ;",
                    md->table_prefix, cs->contest_id);

  rls->run_u = 0;
  if (rls->run_a > 0) {
    memset(rls->runs, 0, sizeof(rls->runs[0]) * rls->run_a);
    for (i = 0; i < rls->run_a; ++i)
      rls->runs[i].status = RUN_EMPTY;
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
  while (run_id >= rls->run_f && rls->runs[run_id - rls->run_f].status == RUN_EMPTY)
    run_id--;
  if (run_id < rls->run_f) return rls->run_f;

  if (rls->runs[run_id - rls->run_f].time < create_time) {
    // preserve RUN_EMPTY runs anyway
    run_id = rls->run_u;
    //run_id++;
    expand_runs(rls, run_id);
    return run_id;
  }
  if (rls->runs[run_id - rls->run_f].time == create_time
      && rls->runs[run_id - rls->run_f].nsec < create_nsec) {
    run_id = rls->run_u;
    //run_id++;
    expand_runs(rls, run_id);
    return run_id;
  }

  // ok, use slow function and so on
  r = compare_runs(&rls->runs[run_id - rls->run_f], create_time, create_nsec, user_id);
  if (r < 0) {
    run_id++;
    expand_runs(rls, run_id);
    return run_id;
  }
  if (!r) goto duplicate_insert;

  // bsearch
  f = 0;
  while (rls->runs[f].status == RUN_EMPTY) ++f;
  ASSERT(f < rls->run_u - rls->run_f);
  l = run_id + 1 - rls->run_f;
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
    run_id = m1 + 1 + rls->run_f;
    return run_id;
  }
  ASSERT(f == l);
  expand_runs(rls, rls->run_u);
  return f + rls->run_f;

 duplicate_insert:
  err("find_insert_point: duplicate insert?");
  return -1;
}

static int
get_insert_run_id_func(
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

  if (rls->runs[run_id - rls->run_f].status != RUN_EMPTY) {
    // move [run_id, run_u - 1) one forward
    memmove(&rls->runs[run_id + 1 - rls->run_f], &rls->runs[run_id - rls->run_f],
            (rls->run_u - run_id - 1) * sizeof(rls->runs[0]));
    for (i = run_id + 1; i < rls->run_u; ++i)
      rls->runs[i - rls->run_f].run_id = i;
    if (mi->simple_fquery(md, "UPDATE %sruns SET run_id = run_id + 1 WHERE contest_id = %d AND run_id >= %d ORDER BY run_id DESC;", md->table_prefix, cs->contest_id, run_id) < 0)
      goto fail;
  }
  re = &rls->runs[run_id - rls->run_f];
  memset(re, 0, sizeof(*re));
  re->run_id = run_id;
  re->time = create_time;
  re->nsec = create_nsec;
  //re->user_id = user_id;
  re->status = RUN_EMPTY;

  memset(&ri, 0, sizeof(ri));
  gettimeofday(&curtime, 0);
  ri.run_id = run_id;
  ri.contest_id = cs->contest_id;
  /*
  ri.create_time = create_time;
  ri.create_nsec = create_nsec;
  */
  ri.create_tv.tv_sec = create_time;
  ri.create_tv.tv_usec = (create_nsec + 500) / 1000;
  ri.create_nsec = create_nsec;
  ri.status = RUN_EMPTY;
  //ri.user_id = user_id;
  ri.last_change_time = curtime.tv_sec;
  ri.last_change_nsec = curtime.tv_usec * 1000;

  re->last_change_us = curtime.tv_sec * 1000000LL + curtime.tv_usec;

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

static const unsigned char *
to_uuid_str(unsigned char *buf, size_t size, const ej_uuid_t *p_uuid)
{
  if (!p_uuid->v[0] && !p_uuid->v[1] && !p_uuid->v[2] && !p_uuid->v[3]) {
    snprintf(buf, size, "NULL");
  } else {
    char uuid_buf[40];
    uuid_unparse((void*) p_uuid, uuid_buf);
    snprintf(buf, size, "'%s'", uuid_buf);
  }
  return buf;
}

static void
generate_update_entry_clause(
        struct rldb_mysql_state *state,
        FILE *f,
        const struct run_entry *re,
        uint64_t mask,
        const struct timeval *curtime)
{
  const unsigned char *sep = "";
  const unsigned char *comma = ", ";
  unsigned char uuid_buf[128];

  if ((mask & RE_SIZE)) {
    fprintf(f, "%ssize = %d", sep, re->size);
    sep = comma;
  }
  if ((mask & RE_USER_ID)) {
    fprintf(f, "%suser_id = %d", sep, re->user_id);
    sep = comma;
  }
  if ((mask & RE_PROB_ID)) {
    fprintf(f, "%sprob_id = %d", sep, re->prob_id);
    sep = comma;
  }
  if ((mask & RE_LANG_ID)) {
    fprintf(f, "%slang_id = %d", sep, re->lang_id);
    sep = comma;
  }
  if ((mask & RE_STATUS)) {
    fprintf(f, "%sstatus = %d", sep, re->status);
    sep = comma;
  }
  if ((mask & RE_SSL_FLAG)) {
    fprintf(f, "%sssl_flag = %d", sep, re->ssl_flag);
    sep = comma;
  }
  if ((mask & RE_IP)) {
    int ip_version = 4;
    if (re->ipv6_flag) ip_version = 6;
    fprintf(f, "%sip_version = %d", sep, ip_version);
    sep = comma;
    ej_ip_t ipv6;
    run_entry_to_ipv6(re, &ipv6);
    fprintf(f, "%sip = '%s'", sep, xml_unparse_ipv6(&ipv6));
  }
  if ((mask & RE_SHA1)) {
    if (!re->h.sha1[0] && !re->h.sha1[1] && !re->h.sha1[2]
        && !re->h.sha1[3] && !re->h.sha1[4]) {
      fprintf(f, "%shash = NULL", sep);
    } else {
      fprintf(f, "%shash = '%s'", sep, unparse_sha1(re->h.sha1));
    }
    sep = comma;
  }
  if ((mask & RE_RUN_UUID)) {
    fprintf(f, "%srun_uuid = %s", sep,
            to_uuid_str(uuid_buf, sizeof(uuid_buf), &re->run_uuid));
    sep = comma;
  }
  if ((mask & RE_SCORE)) {
    fprintf(f, "%sscore = %d", sep, re->score);
    sep = comma;
  }
  if ((mask & RE_TEST)) {
    fprintf(f, "%stest_num = %d", sep, re->test);
    sep = comma;
  }
  if ((mask & RE_SCORE_ADJ)) {
    fprintf(f, "%sscore_adj = %d", sep, re->score_adj);
    sep = comma;
  }
  if ((mask & RE_LOCALE_ID)) {
    fprintf(f, "%slocale_id = %d", sep, re->locale_id);
    sep = comma;
  }
  if ((mask & RE_JUDGE_UUID)) {
    fprintf(f, "%sjudge_id = 0", sep);
    sep = comma;
    fprintf(f, "%sjudge_uuid = %s", sep,
            to_uuid_str(uuid_buf, sizeof(uuid_buf), &re->j.judge_uuid));
  } else if ((mask & RE_JUDGE_ID)) {
    fprintf(f, "%sjudge_id = %d", sep, re->j.judge_id);
    sep = comma;
    fprintf(f, "%sjudge_uuid = NULL", sep);
  }
  if ((mask & RE_VARIANT)) {
    fprintf(f, "%svariant = %d", sep, re->variant);
    sep = comma;
  }
  if ((mask & RE_PAGES)) {
    fprintf(f, "%spages = %d", sep, re->pages);
    sep = comma;
  }
  if ((mask & RE_IS_IMPORTED)) {
    fprintf(f, "%sis_imported = %d", sep, re->is_imported);
    sep = comma;
  }
  if ((mask & RE_IS_HIDDEN)) {
    fprintf(f, "%sis_hidden = %d", sep, re->is_hidden);
    sep = comma;
  }
  if ((mask & RE_IS_READONLY)) {
    fprintf(f, "%sis_readonly = %d", sep, re->is_readonly);
    sep = comma;
  }
  if ((mask & RE_MIME_TYPE)) {
    if (re->mime_type > 0) {
      fprintf(f, "%smime_type = '%s'", sep, mime_type_get_type(re->mime_type));
    } else {
      fprintf(f, "%smime_type = NULL", sep);
    }
    sep = comma;
  }
  if ((mask & RE_IS_MARKED)) {
    fprintf(f, "%sis_marked = %d", sep, re->is_marked);
    sep = comma;
  }
  if ((mask & RE_IS_SAVED)) {
    fprintf(f, "%sis_saved = %d", sep, re->is_saved);
    sep = comma;
  }
  if ((mask & RE_SAVED_STATUS)) {
    fprintf(f, "%ssaved_status = %d", sep, re->saved_status);
    sep = comma;
  }
  if ((mask & RE_SAVED_SCORE)) {
    fprintf(f, "%ssaved_score = %d", sep, re->saved_score);
    sep = comma;
  }
  if ((mask & RE_SAVED_TEST)) {
    fprintf(f, "%ssaved_test = %d", sep, re->saved_test);
    sep = comma;
  }
  if ((mask & RE_PASSED_MODE)) {
    fprintf(f, "%spassed_mode = %d", sep, !!re->passed_mode);
    sep = comma;
  }
  if ((mask & RE_EOLN_TYPE)) {
    fprintf(f, "%seoln_type = %d", sep, re->eoln_type);
    sep = comma;
  }
  if ((mask & RE_STORE_FLAGS)) {
    fprintf(f, "%sstore_flags = %d", sep, re->store_flags);
    sep = comma;
  }
  if ((mask & RE_TOKEN_FLAGS)) {
    fprintf(f, "%stoken_flags = %d", sep, re->token_flags);
    sep = comma;
  }
  if ((mask & RE_TOKEN_COUNT)) {
    fprintf(f, "%stoken_count = %d", sep, re->token_count);
    sep = comma;
  }
  if ((mask & RE_PROB_UUID)) {
    fprintf(f, "%prob_uuid = %s", sep,
            to_uuid_str(uuid_buf, sizeof(uuid_buf), &re->prob_uuid));
    sep = comma;
    /*
     */
  }
  if ((mask & RE_IS_CHECKED)) {
    fprintf(f, "%sis_checked = %d", sep, re->is_checked);
    sep = comma;
  }
  if ((mask & RE_IS_VCS)) {
    fprintf(f, "%sis_vcs = %d", sep, re->is_vcs);
    sep = comma;
  }
  if ((mask & RE_VERDICT_BITS)) {
    fprintf(f, "%sverdict_bits = %u", sep, re->verdict_bits);
    sep = comma;
  }
  if ((mask & RE_EXT_USER)) {
    if (!re->ext_user_kind) {
      fprintf(f, "%sext_user_kind = 0%sext_user = NULL", sep, comma);
      sep = comma;
    } else if (re->ext_user_kind > 0 && re->ext_user_kind < MIXED_ID_LAST) {
      fprintf(f, "%sext_user_kind = %d", sep, re->ext_user_kind);
      sep = comma;
      fprintf(f, "%sext_user = \"%s\"", sep,
              mixed_id_marshall(uuid_buf, re->ext_user_kind, &re->ext_user));
      sep = comma;
    }
  }
  if ((mask & RE_NOTIFY)) {
    if (re->notify_driver > 0
        && re->notify_kind > 0 && re->notify_kind < MIXED_ID_LAST) {
      fprintf(f, "%snotify_driver=%d,notify_kind=%d,notify_queue=\"%s\"",
              sep, re->notify_driver, re->notify_kind,
              mixed_id_marshall(uuid_buf, re->notify_kind, &re->notify_queue));
      sep = comma;
    } else {
      fprintf(f, "%snotify_driver=0,notify_kind=0,notify_queue=NULL",
              sep);
      sep = comma;
    }
  }

  fprintf(f, "%slast_change_time = ", sep);
  state->mi->write_timestamp(state->md, f, 0, curtime->tv_sec);
  sep = comma;
  fprintf(f, "%slast_change_nsec = %ld", sep, curtime->tv_usec * 1000);
}

static void
update_entry(
        struct run_entry *dst,
        const struct run_entry *src,
        uint64_t mask)
{
  if ((mask & RE_SIZE)) {
    dst->size = src->size;
  }
  if ((mask & RE_USER_ID)) {
    dst->user_id = src->user_id;
  }
  if ((mask & RE_PROB_ID)) {
    dst->prob_id = src->prob_id;
  }
  if ((mask & RE_LANG_ID)) {
    dst->lang_id = src->lang_id;
  }
  if ((mask & RE_IP)) {
    dst->a = src->a;
    dst->ipv6_flag = src->ipv6_flag;
  }
  if ((mask & RE_SHA1)) {
    memcpy(dst->h.sha1, src->h.sha1, sizeof(dst->h.sha1));
  }
  if ((mask & RE_RUN_UUID)) {
    memcpy(&dst->run_uuid, &src->run_uuid, sizeof(dst->run_uuid));
  }
  if ((mask & RE_SCORE)) {
    dst->score = src->score;
  }
  if ((mask & RE_TEST)) {
    dst->test = src->test;
  }
  if ((mask & RE_SCORE_ADJ)) {
    dst->score_adj = src->score_adj;
  }
  if ((mask & RE_LOCALE_ID)) {
    dst->locale_id = src->locale_id;
  }
  if ((mask & RE_JUDGE_UUID)) {
    dst->judge_uuid_flag = 1;
    dst->j.judge_uuid = src->j.judge_uuid;
  } else if ((mask & RE_JUDGE_ID)) {
    dst->judge_uuid_flag = 0;
    memset(&dst->j, 0, sizeof(dst->j));
    dst->j.judge_id = src->j.judge_id;
  }
  if ((mask & RE_STATUS)) {
    dst->status = src->status;
  }
  if ((mask & RE_IS_IMPORTED)) {
    dst->is_imported = src->is_imported;
  }
  if ((mask & RE_VARIANT)) {
    dst->variant = src->variant;
  }
  if ((mask & RE_IS_HIDDEN)) {
    dst->is_hidden = src->is_hidden;
  }
  if ((mask & RE_IS_READONLY)) {
    dst->is_readonly = src->is_readonly;
  }
  if ((mask & RE_PAGES)) {
    dst->pages = src->pages;
  }
  if ((mask & RE_SSL_FLAG)) {
    dst->ssl_flag = src->ssl_flag;
  }
  if ((mask & RE_MIME_TYPE)) {
    dst->mime_type = src->mime_type;
  }
  if ((mask & RE_IS_MARKED)) {
    dst->is_marked = src->is_marked;
  }
  if ((mask & RE_IS_SAVED)) {
    dst->is_saved = src->is_saved;
  }
  if ((mask & RE_SAVED_STATUS)) {
    dst->saved_status = src->saved_status;
  }
  if ((mask & RE_SAVED_SCORE)) {
    dst->saved_score = src->saved_score;
  }
  if ((mask & RE_SAVED_TEST)) {
    dst->saved_test = src->saved_test;
  }
  if ((mask & RE_PASSED_MODE)) {
    dst->passed_mode = src->passed_mode;
  }
  if ((mask & RE_EOLN_TYPE)) {
    dst->eoln_type = src->eoln_type;
  }
  if ((mask & RE_STORE_FLAGS)) {
    dst->store_flags = src->store_flags;
  }
  if ((mask & RE_TOKEN_FLAGS)) {
    dst->token_flags = src->token_flags;
  }
  if ((mask & RE_TOKEN_COUNT)) {
    dst->token_count = src->token_count;
  }
  if ((mask & RE_IS_CHECKED)) {
    dst->is_checked = src->is_checked;
  }
  if ((mask & RE_IS_VCS)) {
    dst->is_vcs = src->is_vcs;
  }
  if ((mask & RE_VERDICT_BITS)) {
    dst->verdict_bits = src->verdict_bits;
  }
  if ((mask & RE_EXT_USER)) {
    dst->ext_user_kind = src->ext_user_kind;
    dst->ext_user = src->ext_user;
  }
  if ((mask & RE_NOTIFY)) {
    dst->notify_driver = src->notify_driver;
    dst->notify_kind = src->notify_kind;
    dst->notify_queue = src->notify_queue;
  }
}

static int
do_update_entry(
        struct rldb_mysql_cnts *cs,
        int run_id,
        const struct run_entry *re,
        uint64_t mask,
        struct run_entry *ure)
{
  struct rldb_mysql_state *state = cs->plugin_state;
  struct runlog_state *rls = cs->rl_state;
  struct run_entry *de;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;
  struct timeval curtime;

  ASSERT(run_id >= rls->run_f && run_id < rls->run_u);
  de = &rls->runs[run_id - rls->run_f];

  gettimeofday(&curtime, NULL);

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %sruns SET ", state->md->table_prefix);
  generate_update_entry_clause(state, cmd_f, re, mask, &curtime);
  fprintf(cmd_f, " WHERE contest_id = %d AND run_id = %d ;",
          cs->contest_id, run_id);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  update_entry(de, re, mask);
  de->last_change_us = curtime.tv_sec * 1000000LL + curtime.tv_usec;
  if (ure) {
    *ure = *de;
  }
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
        uint64_t mask,
        struct run_entry *ure)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct runlog_state *rls = cs->rl_state;
  struct run_entry *de;

  ASSERT(run_id >= rls->run_f && run_id < rls->run_u);
  de = &rls->runs[run_id - rls->run_f];

  ASSERT(de->run_id == run_id);
  ASSERT(de->status == RUN_EMPTY);
  ASSERT(de->time > 0);
  (void) de;

  return do_update_entry(cs, run_id, re, mask, ure);
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

  ASSERT(run_id >= rls->run_f && run_id < rls->run_u);
  re = &rls->runs[run_id - rls->run_f];

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
        int new_passed_mode,
        int new_score,
        int new_judge_id,
        const ej_uuid_t *judge_uuid,
        unsigned int verdict_bits,
        struct run_entry *ure)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct run_entry te;
  uint64_t mask = RE_STATUS | RE_TEST | RE_SCORE | RE_PASSED_MODE | RE_VERDICT_BITS;

  memset(&te, 0, sizeof(te));
  te.status = new_status;
  te.test = new_test;
  te.passed_mode = !!new_passed_mode;
  te.score = new_score;
  if (judge_uuid && ej_uuid_is_nonempty(*judge_uuid)) {
    te.judge_uuid_flag = 1;
    te.j.judge_uuid = *judge_uuid;
    mask |= RE_JUDGE_UUID;
  } else {
    te.j.judge_id = new_judge_id;
    mask |= RE_JUDGE_ID;
  }
  te.verdict_bits = verdict_bits;

  return do_update_entry(cs, run_id, &te, mask, ure);
}

static void
generate_update_header_clause(
        struct rldb_mysql_state *state,
        FILE *f,
        const struct run_header *rh,
        uint64_t mask)
{
  struct timeval curtime;
  const unsigned char *sep = "";
  const unsigned char *comma = ", ";

  if ((mask & RH_START_TIME)) {
    fprintf(f, "%sstart_time = ", sep);
    state->mi->write_timestamp(state->md, f, 0, rh->start_time);
    sep = comma;
  }
  if ((mask & RH_SCHED_TIME)) {
    fprintf(f, "%ssched_time = ", sep);
    state->mi->write_timestamp(state->md, f, 0, rh->sched_time);
    sep = comma;
  }
  if ((mask & RH_DURATION)) {
    fprintf(f, "%sduration = %lld", sep, rh->duration);
    sep = comma;
  }
  if ((mask & RH_STOP_TIME)) {
    fprintf(f, "%sstop_time = ", sep);
    state->mi->write_timestamp(state->md, f, 0, rh->stop_time);
    sep = comma;
  }
  if ((mask & RH_FINISH_TIME)) {
    fprintf(f, "%sfinish_time = ", sep);
    state->mi->write_timestamp(state->md, f, 0, rh->finish_time);
    sep = comma;
  }
  if ((mask & RH_SAVED_DURATION)) {
    fprintf(f, "%ssaved_duration = %lld", sep, rh->saved_duration);
    sep = comma;
  }
  if ((mask & RH_SAVED_STOP_TIME)) {
    fprintf(f, "%ssaved_stop_time = ", sep);
    state->mi->write_timestamp(state->md, f, 0, rh->saved_stop_time);
    sep = comma;
  }
  if ((mask & RH_SAVED_FINISH_TIME)) {
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
        uint64_t mask)
{
  if ((mask & RH_START_TIME)) {
    dst->start_time = src->start_time;
  }
  if ((mask & RH_SCHED_TIME)) {
    dst->sched_time = src->sched_time;
  }
  if ((mask & RH_DURATION)) {
    dst->duration = src->duration;
  }
  if ((mask & RH_STOP_TIME)) {
    dst->stop_time = src->stop_time;
  }
  if ((mask & RH_FINISH_TIME)) {
    dst->finish_time = src->finish_time;
  }
  if ((mask & RH_SAVED_DURATION)) {
    dst->saved_duration = src->saved_duration;
  }
  if ((mask & RH_SAVED_STOP_TIME)) {
    dst->saved_stop_time = src->saved_stop_time;
  }
  if ((mask & RH_SAVED_FINISH_TIME)) {
    dst->saved_finish_time = src->saved_finish_time;
  }
}

static int
do_update_header(
        struct rldb_mysql_cnts *cs,
        const struct run_header *rh,
        int mask)
{
  struct rldb_mysql_state *state = cs->plugin_state;
  struct runlog_state *rls = cs->rl_state;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %srunheaders SET ", state->md->table_prefix);
  generate_update_header_clause(state, cmd_f, rh, mask);
  fprintf(cmd_f, " WHERE contest_id = %d ;", cs->contest_id);
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0; cmd_z = 0;
  update_header(&rls->head, rh, mask);
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

  return do_update_entry(cs, run_id, &te, RE_STATUS, NULL);
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

  ASSERT(run_id >= rls->run_f && run_id < rls->run_u);
  re = &rls->runs[run_id - rls->run_f];

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
        int new_hidden,
        struct run_entry *ure)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct run_entry te;

  ASSERT(new_hidden >= 0 && new_hidden <= 1);

  memset(&te, 0, sizeof(te));
  te.is_hidden = new_hidden;

  return do_update_entry(cs, run_id, &te, RE_IS_HIDDEN, ure);
}

static int
set_pages_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_pages,
        struct run_entry *ure)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct run_entry te;

  memset(&te, 0, sizeof(te));
  te.pages = new_pages;

  return do_update_entry(cs, run_id, &te, RE_PAGES, ure);
}

static int
set_entry_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        const struct run_entry *in,
        uint64_t mask,
        struct run_entry *ure)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct runlog_state *rls = cs->rl_state;

  ASSERT(run_id >= rls->run_f && run_id < rls->run_u);
  ASSERT(rls->runs[run_id - rls->run_f].status != RUN_EMPTY);

  (void) rls;
  return do_update_entry(cs, run_id, in, mask, ure);
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
  char uuid_buf[40];
  char ext_user_buf[64];
  char notify_queue_buf[64];

  ASSERT(re);
  ASSERT(re->run_id >= 0);

  expand_runs(rls, re->run_id);
  if (rls->runs[re->run_id - rls->run_f].status != RUN_EMPTY) return -1;
  if (re->status == RUN_EMPTY) return -1;

  // FIXME: check, that time is valid

  memset(&ri, 0, sizeof(ri));
  gettimeofday(&curtime, 0);

  ri.run_id = re->run_id;
  ri.contest_id = cs->contest_id;
  ri.size = re->size;
  /*
  ri.create_time = re->time;
  */
  ri.create_tv.tv_sec = re->time;
  ri.create_tv.tv_usec = (re->nsec + 500) / 1000;
  ri.create_nsec = re->nsec;
  ri.user_id = re->user_id;
  ri.prob_id = re->prob_id;
  ri.lang_id = re->lang_id;
  ri.status = re->status;
  ri.ip_version = 4;
  if (re->ipv6_flag) ri.ip_version = 6;
  run_entry_to_ipv6(re, &ri.ip);
  ri.ssl_flag = re->ssl_flag;
  if (re->h.sha1[0] || re->h.sha1[1] || re->h.sha1[2] || re->h.sha1[3]
      || re->h.sha1[4]) {
    ri.hash = unparse_sha1(re->h.sha1);
  }
#if CONF_HAS_LIBUUID
  {
    if (re->run_uuid.v[0] || re->run_uuid.v[1] || re->run_uuid.v[2] || re->run_uuid.v[3]) {
      uuid_unparse((void*) &re->run_uuid, uuid_buf);
      ri.run_uuid = uuid_buf;
    }
  }
#endif
  ri.score = re->score;
  ri.test_num = re->test;
  ri.score_adj = re->score_adj;
  ri.locale_id = re->locale_id;
  ri.judge_id = re->j.judge_id;
  ri.variant = re->variant;
  ri.pages = re->pages;
  ri.is_imported = re->is_imported;
  ri.is_hidden = re->is_hidden;
  ri.is_readonly = re->is_readonly;
  if (re->mime_type) {
    ri.mime_type = (unsigned char*) mime_type_get_type(re->mime_type);
  }
  ri.last_change_time = curtime.tv_sec;
  ri.last_change_nsec = curtime.tv_usec * 1000;
  ri.is_marked = re->is_marked;
  ri.is_saved = re->is_saved;
  ri.saved_status = re->saved_status;
  ri.saved_score = re->saved_score;
  ri.saved_test = re->saved_test;
  ri.passed_mode = re->passed_mode;
  ri.eoln_type = re->eoln_type;
  ri.store_flags = re->store_flags;
  ri.token_flags = re->token_flags;
  ri.token_count = re->token_count;
  ri.is_checked = re->is_checked;
  ri.is_vcs = re->is_vcs;
  ri.verdict_bits = re->verdict_bits;
  if (re->ext_user_kind > 0 && re->ext_user_kind < MIXED_ID_LAST) {
    ri.ext_user_kind = re->ext_user_kind;
    ri.ext_user = mixed_id_marshall(ext_user_buf, re->ext_user_kind, &re->ext_user);
  } else {
    ri.ext_user_kind = 0;
    ri.ext_user = NULL;
  }
  if (re->notify_driver > 0
      && re->notify_kind > 0 && re->notify_kind < MIXED_ID_LAST) {
    ri.notify_driver = re->notify_driver;
    ri.notify_kind = re->notify_kind;
    ri.notify_queue = mixed_id_marshall(notify_queue_buf, re->notify_kind, &re->notify_queue);
  } else {
    ri.notify_driver = 0;
    ri.notify_kind = 0;
    ri.notify_queue = NULL;
  }

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %sruns VALUES ( ", state->md->table_prefix);
  state->mi->unparse_spec(state->md, cmd_f, RUNS_ROW_WIDTH, runs_spec, &ri);
  fprintf(cmd_f, " ) ;");
  close_memstream(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0;

  struct run_entry *dst = &rls->runs[re->run_id - rls->run_f];
  memcpy(dst, re, sizeof(*dst));
  dst->last_change_us = curtime.tv_sec * 1000000LL + curtime.tv_usec;

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

static int
check_func(
        struct rldb_plugin_cnts *cdata,
        FILE *log_f)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct runlog_state *rls = cs->rl_state;
  int retval = run_fix_runlog_time(log_f, rls->run_f, rls->run_u, rls->runs, NULL);
  if (retval < 0) {
    return retval;
  }

  // FIXME: save the updated runs
  return 0;
}

static int
change_status_3_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_status,
        int new_test,
        int new_passed_mode,
        int new_score,
        int new_is_marked,
        int has_user_score,
        int user_status,
        int user_tests_passed,
        int user_score,
        unsigned int verdict_bits,
        struct run_entry *ure)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct run_entry te;

  memset(&te, 0, sizeof(te));
  te.status = new_status;
  te.test = new_test;
  te.passed_mode = !!new_passed_mode;
  te.score = new_score;
  te.j.judge_id = 0;
  te.is_marked = new_is_marked;
  te.is_saved = has_user_score;
  te.saved_status = user_status;
  te.saved_test = user_tests_passed;
  te.saved_score = user_score;
  te.verdict_bits = verdict_bits;

  return do_update_entry(cs, run_id, &te,
                         RE_STATUS | RE_TEST | RE_SCORE | RE_JUDGE_ID
                         | RE_IS_MARKED | RE_IS_SAVED | RE_SAVED_STATUS
                         | RE_SAVED_TEST | RE_SAVED_SCORE | RE_PASSED_MODE
                         | RE_VERDICT_BITS, ure);
}

static int
change_status_4_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_status,
        struct run_entry *ure)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct run_entry te;

  memset(&te, 0, sizeof(te));
  te.status = new_status;
  // te.test = 0;
  te.score = -1;
  te.j.judge_id = 0;
  te.is_marked = 0;
  te.is_saved = 0;
  te.saved_status = 0;
  // te.saved_test = 0;
  te.saved_score = 0;
  te.passed_mode = 1;

  return do_update_entry(cs, run_id, &te,
                         RE_STATUS /* | RE_TEST */ | RE_SCORE | RE_JUDGE_ID
                         | RE_IS_MARKED | RE_IS_SAVED | RE_SAVED_STATUS
                         /* | RE_SAVED_TEST */ | RE_SAVED_SCORE
                         | RE_PASSED_MODE, ure);
}

static int
user_run_header_delete_func(
        struct rldb_plugin_cnts *cdata,
        int user_id)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts*) cdata;
  struct rldb_mysql_state *state = cs->plugin_state;
  struct runlog_state *rls = cs->rl_state;
  char *cmd_s = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  cmd_f = open_memstream(&cmd_s, &cmd_z);
  fprintf(cmd_f, "DELETE FROM %suserrunheaders WHERE user_id = %d and contest_id = %d ;", state->md->table_prefix, user_id, cs->contest_id);
  fclose(cmd_f); cmd_f = NULL;
  if (state->mi->simple_query(state->md, cmd_s, cmd_z) < 0) {
    free(cmd_s);
    return -1;
  }
  free(cmd_s); cmd_s = NULL;
  if (user_id >= rls->urh.low_user_id && user_id < rls->urh.high_user_id) {
    int index = rls->urh.umap[user_id - rls->urh.low_user_id];
    rls->urh.umap[user_id - rls->urh.low_user_id] = 0;
    if (index > 0) {
      memset(&rls->urh.infos[index], 0, sizeof(rls->urh.infos[index]));
    }
  }
  // FIXME: the user_run_header_info entry for user_id in vector infos is just lost...
  return 0;
}

static int
user_run_header_set_start_time_func(
        struct rldb_plugin_cnts *cdata,
        int user_id,
        time_t start_time,
        int is_virtual,
        int last_change_user_id)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts*) cdata;
  struct rldb_mysql_state *state = cs->plugin_state;
  struct runlog_state *rls = cs->rl_state;
  char *cmd_s = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  cmd_f = open_memstream(&cmd_s, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %suserrunheaders SET start_time = ", state->md->table_prefix);
  state->mi->write_timestamp(state->md, cmd_f, 0, start_time);
  fprintf(cmd_f, ", is_virtual = %d", is_virtual);
  fprintf(cmd_f, ", user_id = %d", user_id);
  fprintf(cmd_f, ", contest_id = %d", cs->contest_id);
  fprintf(cmd_f, ", last_change_user_id = %d", last_change_user_id);
  fprintf(cmd_f, ", last_change_time = NOW()");
  fprintf(cmd_f, " ON DUPLICATE KEY UPDATE start_time = ");
  state->mi->write_timestamp(state->md, cmd_f, 0, start_time);
  fprintf(cmd_f, ", is_virtual = %d", is_virtual);
  fprintf(cmd_f, ", last_change_user_id = %d", last_change_user_id);
  fprintf(cmd_f, ", last_change_time = NOW() ;");
  fclose(cmd_f); cmd_f = NULL;

  if (state->mi->simple_query(state->md, cmd_s, cmd_z) < 0) {
    free(cmd_s);
    return -1;
  }
  free(cmd_s); cmd_s = NULL;

  struct user_run_header_info *urhi = run_get_user_run_header(rls, user_id, NULL);
  if (urhi) {
    urhi->user_id = user_id;
    urhi->is_virtual = is_virtual;
    urhi->has_db_record = 1;
    urhi->last_change_user_id = last_change_user_id;
    urhi->start_time = start_time;
    urhi->last_change_time = time(NULL);
  }

  return 0;
}

static int
user_run_header_set_stop_time_func(
        struct rldb_plugin_cnts *cdata,
        int user_id,
        time_t stop_time,
        int last_change_user_id)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts*) cdata;
  struct rldb_mysql_state *state = cs->plugin_state;
  struct runlog_state *rls = cs->rl_state;
  char *cmd_s = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  cmd_f = open_memstream(&cmd_s, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %suserrunheaders SET stop_time = ", state->md->table_prefix);
  state->mi->write_timestamp(state->md, cmd_f, 0, stop_time);
  fprintf(cmd_f, ", user_id = %d", user_id);
  fprintf(cmd_f, ", contest_id = %d", cs->contest_id);
  fprintf(cmd_f, ", last_change_user_id = %d", last_change_user_id);
  fprintf(cmd_f, ", last_change_time = NOW()");
  fprintf(cmd_f, " ON DUPLICATE KEY UPDATE stop_time = ");
  state->mi->write_timestamp(state->md, cmd_f, 0, stop_time);
  fprintf(cmd_f, ", last_change_user_id = %d", last_change_user_id);
  fprintf(cmd_f, ", last_change_time = NOW() ;");
  fclose(cmd_f); cmd_f = NULL;

  if (state->mi->simple_query(state->md, cmd_s, cmd_z) < 0) {
    free(cmd_s);
    return -1;
  }
  free(cmd_s); cmd_s = NULL;

  struct user_run_header_info *urhi = run_get_user_run_header(rls, user_id, NULL);
  if (urhi) {
    urhi->user_id = user_id;
    urhi->has_db_record = 1;
    urhi->last_change_user_id = last_change_user_id;
    urhi->stop_time = stop_time;
    urhi->last_change_time = time(NULL);
  }

  return 0;
}

static int
user_run_header_set_duration_func(
        struct rldb_plugin_cnts *cdata,
        int user_id,
        int duration,
        int last_change_user_id)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts*) cdata;
  struct rldb_mysql_state *state = cs->plugin_state;
  struct runlog_state *rls = cs->rl_state;
  char *cmd_s = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  cmd_f = open_memstream(&cmd_s, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %suserrunheaders SET duration = %d", state->md->table_prefix, duration);
  fprintf(cmd_f, ", user_id = %d", user_id);
  fprintf(cmd_f, ", contest_id = %d", cs->contest_id);
  fprintf(cmd_f, ", last_change_user_id = %d", last_change_user_id);
  fprintf(cmd_f, ", last_change_time = NOW()");
  fprintf(cmd_f, " ON DUPLICATE KEY UPDATE duration = %d", duration);
  fprintf(cmd_f, ", last_change_user_id = %d", last_change_user_id);
  fprintf(cmd_f, ", last_change_time = NOW() ;");
  fclose(cmd_f); cmd_f = NULL;

  if (state->mi->simple_query(state->md, cmd_s, cmd_z) < 0) {
    free(cmd_s);
    return -1;
  }
  free(cmd_s); cmd_s = NULL;

  struct user_run_header_info *urhi = run_get_user_run_header(rls, user_id, NULL);
  if (urhi) {
    urhi->user_id = user_id;
    urhi->has_db_record = 1;
    urhi->last_change_user_id = last_change_user_id;
    urhi->duration = duration;
    urhi->last_change_time = time(NULL);
  }

  return 0;
}

static int
user_run_header_set_is_checked_func(
        struct rldb_plugin_cnts *cdata,
        int user_id,
        int is_checked,
        int last_change_user_id)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts*) cdata;
  struct rldb_mysql_state *state = cs->plugin_state;
  struct runlog_state *rls = cs->rl_state;
  char *cmd_s = 0;
  size_t cmd_z = 0;
  FILE *cmd_f = 0;

  cmd_f = open_memstream(&cmd_s, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %suserrunheaders SET is_checked = %d", state->md->table_prefix, is_checked);
  fprintf(cmd_f, ", user_id = %d", user_id);
  fprintf(cmd_f, ", contest_id = %d", cs->contest_id);
  fprintf(cmd_f, ", last_change_user_id = %d", last_change_user_id);
  fprintf(cmd_f, ", last_change_time = NOW()");
  fprintf(cmd_f, " ON DUPLICATE KEY UPDATE is_checked = %d", is_checked);
  fprintf(cmd_f, ", last_change_user_id = %d", last_change_user_id);
  fprintf(cmd_f, ", last_change_time = NOW() ;");
  fclose(cmd_f); cmd_f = NULL;

  if (state->mi->simple_query(state->md, cmd_s, cmd_z) < 0) {
    free(cmd_s);
    return -1;
  }
  free(cmd_s); cmd_s = NULL;

  struct user_run_header_info *urhi = run_get_user_run_header(rls, user_id, NULL);
  if (urhi) {
    urhi->user_id = user_id;
    urhi->is_checked = is_checked;
    urhi->has_db_record = 1;
    urhi->last_change_user_id = last_change_user_id;
    urhi->last_change_time = time(NULL);
  }

  return 0;
}

struct run_id_create_time_internal
{
  int run_id;
  struct timeval create_time;
};

enum { RUNIDCREATETIME_WIDTH = 2 };
#define RUNIDCREATETIME_OFFSET(f) XOFFSET(struct run_id_create_time_internal, f)
static __attribute__((unused)) const struct common_mysql_parse_spec run_id_create_time_spec[RUNIDCREATETIME_WIDTH] =
{
  { 1, 'd', "run_id", RUNIDCREATETIME_OFFSET(run_id), 0 },
  { 1, 'T', "create_time", RUNIDCREATETIME_OFFSET(create_time), 0 },
};

static int
append_run_func(
        struct rldb_plugin_cnts *cdata,
        const struct run_entry *in_re,
        uint64_t mask,
        struct timeval *p_tv,
        int64_t *p_serial_id,
        ej_uuid_t *p_uuid,
        struct run_entry *ure)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct rldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  struct runlog_state *rls = cs->rl_state;
  struct run_entry *new_re;
  char *cmd_s = NULL;
  size_t cmd_z = 0;
  FILE *cmd_f = NULL;
  ej_uuid_t tmp_uuid = {};
  unsigned char uuid_buf[64];
  long long serial_id = -1;
  int run_id = 0;
  struct timeval current_time_tv;

  gettimeofday(&current_time_tv, NULL);
  long long request_start_time = current_time_tv.tv_sec * 1000000LL + current_time_tv.tv_usec;

  mask &= ~((uint64_t) RE_RUN_UUID);

  if (!p_uuid) p_uuid = &tmp_uuid;
  if (!ej_uuid_is_nonempty(*p_uuid)) ej_uuid_generate(p_uuid);

  serial_id = next_serial_id(state);
  run_id = next_run_id(cs);

  /*
  if (mi->simple_fquery(md, "START TRANSACTION;") < 0)
    db_error_fail(md);
  */

  /*
  if (mi->fquery(md, 1, "SELECT IFNULL(MAX(run_id),-1)+1 FROM %sruns WHERE contest_id = %d;", md->table_prefix, cs->contest_id) < 0) {
    mi->simple_fquery(md, "ROLLBACK;");
    db_error_fail(md);
  }
  if (md->row_count != 1) {
    err("invalid row_count: %d", md->row_count);
    mi->simple_fquery(md, "ROLLBACK;");
    db_error_fail(md);
  }
  if (mi->next_row(state->md) < 0) {
    mi->simple_fquery(md, "ROLLBACK;");
    db_error_fail(md);
  }
  if (!md->row[0] || mi->parse_int(md, md->row[0], &run_id) < 0) {
    err("invalid run_id");
    mi->simple_fquery(md, "ROLLBACK;");
    db_error_fail(md);
  }
  mi->free_res(md);
  */

  cmd_f = open_memstream(&cmd_s, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %sruns(serial_id,run_id,contest_id,create_time,create_nsec,run_uuid,last_change_time,last_change_nsec",
          md->table_prefix);
  if ((mask & RE_SIZE)) {
    fputs(",size", cmd_f);
  }
  if ((mask & RE_IP)) {
    fputs(",ip_version", cmd_f);
    fputs(",ip", cmd_f);
  }
  if ((mask & RE_SHA1)) {
    fputs(",hash", cmd_f);
  }
  if ((mask & RE_USER_ID)) {
    fputs(",user_id", cmd_f);
  }
  if ((mask & RE_PROB_ID)) {
    fputs(",prob_id", cmd_f);
  }
  if ((mask & RE_LANG_ID)) {
    fputs(",lang_id", cmd_f);
  }
  if ((mask & RE_LOCALE_ID)) {
    fputs(",locale_id", cmd_f);
  }
  if ((mask & RE_STATUS)) {
    fputs(",status", cmd_f);
  }
  if ((mask & RE_TEST)) {
    fputs(",test_num", cmd_f);
  }
  if ((mask & RE_SCORE)) {
    fputs(",score", cmd_f);
  }
  if ((mask & RE_IS_IMPORTED)) {
    fputs(",is_imported", cmd_f);
  }
  if ((mask & RE_VARIANT)) {
    fputs(",variant", cmd_f);
  }
  if ((mask & RE_IS_HIDDEN)) {
    fputs(",is_hidden", cmd_f);
  }
  if ((mask & RE_IS_READONLY)) {
    fputs(",is_readonly", cmd_f);
  }
  if ((mask & RE_PAGES)) {
    fputs(",pages", cmd_f);
  }
  if ((mask & RE_SCORE_ADJ)) {
    fputs(",score_adj", cmd_f);
  }
  if ((mask & RE_JUDGE_UUID)) {
    fputs(",judge_uuid", cmd_f);
  } else if ((mask & RE_JUDGE_ID)) {
    fputs(",judge_id", cmd_f);
  }
  if ((mask & RE_SSL_FLAG)) {
    fputs(",ssl_flag", cmd_f);
  }
  if ((mask & RE_MIME_TYPE)) {
    fputs(",mime_type", cmd_f);
  }
  if ((mask & RE_TOKEN_FLAGS)) {
    fputs(",token_flags", cmd_f);
  }
  if ((mask & RE_TOKEN_COUNT)) {
    fputs(",token_count", cmd_f);
  }
  if ((mask & RE_IS_MARKED)) {
    fputs(",is_marked", cmd_f);
  }
  if ((mask & RE_IS_SAVED)) {
    fputs(",is_saved", cmd_f);
  }
  if ((mask & RE_SAVED_STATUS)) {
    fputs(",saved_status", cmd_f);
  }
  if ((mask & RE_SAVED_SCORE)) {
    fputs(",saved_score", cmd_f);
  }
  if ((mask & RE_SAVED_TEST)) {
    fputs(",saved_test", cmd_f);
  }
  if ((mask & RE_RUN_UUID)) {
    fputs(",run_uuid", cmd_f);
  }
  if ((mask & RE_PASSED_MODE)) {
    fputs(",passed_mode", cmd_f);
  }
  if ((mask & RE_EOLN_TYPE)) {
    fputs(",eoln_type", cmd_f);
  }
  if ((mask & RE_STORE_FLAGS)) {
    fputs(",store_flags", cmd_f);
  }
  if ((mask & RE_PROB_UUID)) {
    fputs(",prob_uuid", cmd_f);
  }
  if ((mask & RE_IS_CHECKED)) {
    fputs(",is_checked", cmd_f);
  }
  if ((mask & RE_IS_VCS)) {
    fputs(",is_vcs", cmd_f);
  }
  if ((mask & RE_VERDICT_BITS)) {
    fputs(",verdict_bits", cmd_f);
  }
  if ((mask & RE_EXT_USER)) {
    fputs(",ext_user_kind,ext_user", cmd_f);
  }
  if ((mask & RE_NOTIFY)) {
    fputs(",notify_driver,notify_kind,notify_queue", cmd_f);
  }
  fprintf(cmd_f, ") VALUES (%lld, %d, %d, NOW(6), MICROSECOND(NOW(6)) * 1000, '%s', NOW(), MICROSECOND(NOW(6)) * 1000",
          serial_id,
          run_id,
          cs->contest_id,
          ej_uuid_unparse_r(uuid_buf, sizeof(uuid_buf), p_uuid, ""));
  if ((mask & RE_SIZE)) {
    fprintf(cmd_f, ",%u", (unsigned) in_re->size);
  }
  if ((mask & RE_IP)) {
    int ip_version = 4;
    if (in_re->ipv6_flag) ip_version = 6;
    fprintf(cmd_f, ",%d", ip_version);
    ej_ip_t ipv6;
    run_entry_to_ipv6(in_re, &ipv6);
    fprintf(cmd_f, ",'%s'", xml_unparse_ipv6(&ipv6));
  }
  if ((mask & RE_SHA1)) {
    if (!in_re->h.sha1[0] && !in_re->h.sha1[1] && !in_re->h.sha1[2]
        && !in_re->h.sha1[3] && !in_re->h.sha1[4]) {
      fprintf(cmd_f, ",NULL");
    } else {
      fprintf(cmd_f, ",'%s'", unparse_sha1(in_re->h.sha1));
    }
  }
  if ((mask & RE_USER_ID)) {
    fprintf(cmd_f, ",%d", in_re->user_id);
  }
  if ((mask & RE_PROB_ID)) {
    fprintf(cmd_f, ",%d", in_re->prob_id);
  }
  if ((mask & RE_LANG_ID)) {
    fprintf(cmd_f, ",%d", in_re->lang_id);
  }
  if ((mask & RE_LOCALE_ID)) {
    fprintf(cmd_f, ",%d", in_re->locale_id);
  }
  if ((mask & RE_STATUS)) {
    fprintf(cmd_f, ",%d", in_re->status);
  }
  if ((mask & RE_TEST)) {
    fprintf(cmd_f, ",%d", in_re->test);
  }
  if ((mask & RE_SCORE)) {
    fprintf(cmd_f, ",%d", in_re->score);
  }
  if ((mask & RE_IS_IMPORTED)) {
    fprintf(cmd_f, ",%d", !!in_re->is_imported);
  }
  if ((mask & RE_VARIANT)) {
    fprintf(cmd_f, ",%d", in_re->variant);
  }
  if ((mask & RE_IS_HIDDEN)) {
    fprintf(cmd_f, ",%d", !!in_re->is_hidden);
  }
  if ((mask & RE_IS_READONLY)) {
    fprintf(cmd_f, ",%d", !!in_re->is_readonly);
  }
  if ((mask & RE_PAGES)) {
    fprintf(cmd_f, ",%d", in_re->pages);
  }
  if ((mask & RE_SCORE_ADJ)) {
    fprintf(cmd_f, ",%d", in_re->score_adj);
  }
  if ((mask & RE_JUDGE_UUID)) {
    fprintf(cmd_f, ",%s", to_uuid_str(uuid_buf, sizeof(uuid_buf), &in_re->j.judge_uuid));
  } else if ((mask & RE_JUDGE_ID)) {
    fprintf(cmd_f, ",%d", in_re->j.judge_id);
  }
  if ((mask & RE_SSL_FLAG)) {
    fprintf(cmd_f, ",%d", !!in_re->ssl_flag);
  }
  if ((mask & RE_MIME_TYPE)) {
    if (in_re->mime_type > 0) {
      fprintf(cmd_f, ",'%s'", mime_type_get_type(in_re->mime_type));
    } else {
      fprintf(cmd_f, ",NULL");
    }
  }
  if ((mask & RE_TOKEN_FLAGS)) {
    fprintf(cmd_f, ",%d", in_re->token_flags);
  }
  if ((mask & RE_TOKEN_COUNT)) {
    fprintf(cmd_f, ",%d", in_re->token_count);
  }
  if ((mask & RE_IS_MARKED)) {
    fprintf(cmd_f, ",%d", !!in_re->is_marked);
  }
  if ((mask & RE_IS_SAVED)) {
    fprintf(cmd_f, ",%d", !!in_re->is_saved);
  }
  if ((mask & RE_SAVED_STATUS)) {
    fprintf(cmd_f, ",%d", in_re->saved_status);
  }
  if ((mask & RE_SAVED_SCORE)) {
    fprintf(cmd_f, ",%d", in_re->saved_score);
  }
  if ((mask & RE_SAVED_TEST)) {
    fprintf(cmd_f, ",%d", in_re->saved_test);
  }
  if ((mask & RE_RUN_UUID)) {
    fprintf(cmd_f, ",'%s'",
            ej_uuid_unparse_r(uuid_buf, sizeof(uuid_buf), &in_re->run_uuid, ""));
  }
  if ((mask & RE_PASSED_MODE)) {
    fprintf(cmd_f, ",%d", in_re->passed_mode);
  }
  if ((mask & RE_EOLN_TYPE)) {
    fprintf(cmd_f, ",%d", in_re->eoln_type);
  }
  if ((mask & RE_STORE_FLAGS)) {
    fprintf(cmd_f, ",%d", in_re->store_flags);
  }
  if ((mask & RE_PROB_UUID)) {
    fprintf(cmd_f, ",'%s'",
            ej_uuid_unparse_r(uuid_buf, sizeof(uuid_buf), &in_re->prob_uuid, ""));
  }
  if ((mask & RE_IS_CHECKED)) {
    fprintf(cmd_f, ",%d", !!in_re->is_checked);
  }
  if ((mask & RE_IS_VCS)) {
    fprintf(cmd_f, ",%d", !!in_re->is_vcs);
  }
  if ((mask & RE_VERDICT_BITS)) {
    fprintf(cmd_f, ",%u", in_re->verdict_bits);
  }
  if ((mask & RE_EXT_USER)) {
    int ext_user_kind = in_re->ext_user_kind;
    if (ext_user_kind < 0 || ext_user_kind >= MIXED_ID_LAST) {
      ext_user_kind = 0;
    }
    if (!ext_user_kind) {
      fprintf(cmd_f, ",0,NULL");
    } else {
      fprintf(cmd_f, ",%d,\"%s\"", ext_user_kind,
              mixed_id_marshall(uuid_buf, ext_user_kind,
                                &in_re->ext_user));
    }
  }
  if ((mask & RE_NOTIFY)) {
    if (in_re->notify_driver > 0
        && in_re->notify_kind > 0 && in_re->notify_kind < MIXED_ID_LAST) {
      fprintf(cmd_f, ",%d,%d,\"%s\"",
              in_re->notify_driver, in_re->notify_kind,
              mixed_id_marshall(uuid_buf, in_re->notify_kind,
                                &in_re->notify_queue));
    } else {
      fprintf(cmd_f, ",0,0,NULL");
    }
  }
  fprintf(cmd_f, ") ;");
  fclose(cmd_f); cmd_f = NULL;
  if (mi->simple_query(md, cmd_s, cmd_z) < 0) {
    //mi->simple_fquery(md, "ROLLBACK;");
    goto fail;
  }
  free(cmd_s); cmd_s = NULL; cmd_z = 0;
  //mi->simple_fquery(md, "COMMIT;");

  /*
  if (mi->fquery(md, 1, "SELECT LAST_INSERT_ID();") < 0) {
    goto fail;
  }
  if (md->row_count <= 0) {
    goto fail;
  }
  if (mi->next_row(md) < 0) {
    goto fail;
  }
  if (mi->parse_int64(md, 0, &serial_id) < 0 || serial_id <= 0) {
    goto fail;
  }
  mi->free_res(md);
  */

  /*
  cmd_f = open_memstream(&cmd_s, &cmd_z);
  fprintf(cmd_f, "SELECT run_id, create_time FROM %sruns WHERE serial_id = %lld; ", md->table_prefix, serial_id);
  fclose(cmd_f); cmd_f = NULL;

  if (mi->query_one_row(md, cmd_s, cmd_z, RUNIDCREATETIME_WIDTH) < 0) {
    goto fail;
  }
  free(cmd_s); cmd_s = NULL; cmd_z = 0;
  struct run_id_create_time_internal ri = {};
  if (mi->parse_spec(md, md->field_count, md->row, md->lengths,
                     RUNIDCREATETIME_WIDTH, run_id_create_time_spec, &ri) < 0) {
    goto fail;
  }
  mi->free_res(md);
  */

  expand_runs(rls, run_id);
  new_re = &rls->runs[run_id - rls->run_f];
  memset(new_re, 0, sizeof(*new_re));
  new_re->run_id = run_id;
  new_re->time = current_time_tv.tv_sec;
  new_re->nsec = current_time_tv.tv_usec * 1000;
  new_re->last_change_us = current_time_tv.tv_sec * 1000000LL + current_time_tv.tv_usec;
  new_re->run_uuid = *p_uuid;
  new_re->serial_id = serial_id;
  if ((mask & RE_SIZE)) {
    new_re->size = in_re->size;
  }
  if ((mask & RE_IP)) {
    new_re->ipv6_flag = in_re->ipv6_flag;
    new_re->a = in_re->a;
  }
  if ((mask & RE_SHA1)) {
    memcpy(new_re->h.sha1, in_re->h.sha1, sizeof(new_re->h.sha1));
  }
  if ((mask & RE_USER_ID)) {
    new_re->user_id = in_re->user_id;
  }
  if ((mask & RE_PROB_ID)) {
    new_re->prob_id = in_re->prob_id;
  }
  if ((mask & RE_LANG_ID)) {
    new_re->lang_id = in_re->lang_id;
  }
  if ((mask & RE_LOCALE_ID)) {
    new_re->locale_id = in_re->locale_id;
  }
  if ((mask & RE_STATUS)) {
    new_re->status = in_re->status;
  }
  if ((mask & RE_TEST)) {
    new_re->test = in_re->test;
  }
  if ((mask & RE_SCORE)) {
    new_re->score = in_re->score;
  }
  if ((mask & RE_IS_IMPORTED)) {
    new_re->is_imported = in_re->is_imported;
  }
  if ((mask & RE_VARIANT)) {
    new_re->variant = in_re->variant;
  }
  if ((mask & RE_IS_HIDDEN)) {
    new_re->is_hidden = in_re->is_hidden;
  }
  if ((mask & RE_IS_READONLY)) {
    new_re->is_readonly = in_re->is_readonly;
  }
  if ((mask & RE_PAGES)) {
    new_re->pages = in_re->pages;
  }
  if ((mask & RE_SCORE_ADJ)) {
    new_re->score_adj = in_re->score_adj;
  }
  if ((mask & RE_JUDGE_UUID)) {
    new_re->judge_uuid_flag = 1;
    new_re->j.judge_uuid = in_re->j.judge_uuid;
  } else if ((mask & RE_JUDGE_ID)) {
    new_re->judge_uuid_flag = 0;
    memset(&new_re->j, 0, sizeof(new_re->j));
    new_re->j.judge_id = in_re->j.judge_id;
  }
  if ((mask & RE_SSL_FLAG)) {
    new_re->ssl_flag = in_re->ssl_flag;
  }
  if ((mask & RE_MIME_TYPE)) {
    new_re->mime_type = in_re->mime_type;
  }
  if ((mask & RE_TOKEN_FLAGS)) {
    new_re->token_flags = in_re->token_flags;
  }
  if ((mask & RE_TOKEN_COUNT)) {
    new_re->token_count = in_re->token_count;
  }
  if ((mask & RE_IS_MARKED)) {
    new_re->is_marked = in_re->is_marked;
  }
  if ((mask & RE_IS_SAVED)) {
    new_re->is_saved = in_re->is_saved;
  }
  if ((mask & RE_SAVED_STATUS)) {
    new_re->saved_status = in_re->saved_status;
  }
  if ((mask & RE_SAVED_SCORE)) {
    new_re->saved_score = in_re->saved_score;
  }
  if ((mask & RE_SAVED_TEST)) {
    new_re->saved_test = in_re->saved_test;
  }
  if ((mask & RE_RUN_UUID)) {
    new_re->run_uuid = in_re->run_uuid;
  }
  if ((mask & RE_PASSED_MODE)) {
    new_re->passed_mode = in_re->passed_mode;
  }
  if ((mask & RE_EOLN_TYPE)) {
    new_re->eoln_type = in_re->eoln_type;
  }
  if ((mask & RE_STORE_FLAGS)) {
    new_re->store_flags = in_re->store_flags;
  }
  if ((mask & RE_PROB_UUID)) {
    //{ 1, 's', "prob_uuid", RUNS_OFFSET(prob_uuid), 0 },
  }
  if ((mask & RE_IS_CHECKED)) {
    new_re->is_checked = in_re->is_checked;
  }
  if ((mask & RE_IS_VCS)) {
    new_re->is_vcs = in_re->is_vcs;
  }
  if ((mask & RE_VERDICT_BITS)) {
    new_re->verdict_bits = in_re->verdict_bits;
  }
  if ((mask & RE_EXT_USER)) {
    new_re->ext_user_kind = in_re->ext_user_kind;
    new_re->ext_user = in_re->ext_user;
  }
  if ((mask & RE_NOTIFY)) {
    new_re->notify_driver = in_re->notify_driver;
    new_re->notify_kind = in_re->notify_kind;
    new_re->notify_queue = in_re->notify_queue;
  }

  if (p_tv) *p_tv = current_time_tv;
  if (p_serial_id) *p_serial_id = serial_id;
  if (ure) {
    *ure = *new_re;
  }

  if (cs->metrics) {
    long long request_end_time = get_current_time_us();
    cs->metrics->append_run_us += (request_end_time - request_start_time);
    ++cs->metrics->append_run_count;
  }

  return run_id;

fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_s);
  return -1;
}

static int
run_set_is_checked_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int is_checked)
{
  struct rldb_mysql_cnts *cs = (struct rldb_mysql_cnts *) cdata;
  struct run_entry te;

  memset(&te, 0, sizeof(te));
  te.is_checked = !!is_checked;

  return do_update_entry(cs, run_id, &te, RE_IS_CHECKED, NULL);
}
