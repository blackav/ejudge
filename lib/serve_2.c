/* -*- mode: c -*- */

/* Copyright (C) 2006-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/serve_state.h"
#include "ejudge/runlog.h"
#include "ejudge/prepare.h"
#include "ejudge/l10n.h"
#include "ejudge/html.h"
#include "ejudge/errlog.h"
#include "ejudge/protocol.h"
#include "ejudge/clarlog.h"
#include "ejudge/fileutl.h"
#include "ejudge/teamdb.h"
#include "ejudge/contests.h"
#include "ejudge/job_packet.h"
#include "ejudge/archive_paths.h"
#include "ejudge/xml_utils.h"
#include "ejudge/compile_packet.h"
#include "ejudge/run_packet.h"
#include "ejudge/curtime.h"
#include "ejudge/userlist.h"
#include "ejudge/sformat.h"
#include "ejudge/misctext.h"
#include "ejudge/charsets.h"
#include "ejudge/compat.h"
#include "ejudge/varsubst.h"
#include "ejudge/mime_type.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/super_run_packet.h"
#include "ejudge/prepare_dflt.h"
#include "ejudge/testing_report_xml.h"
#include "ejudge/server_framework.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/team_extra.h"
#include "ejudge/packet_name.h"
#include "ejudge/xuser_plugin.h"
#include "ejudge/random.h"
#include "ejudge/statusdb.h"
#include "ejudge/test_count_cache.h"
#include "ejudge/submit_plugin.h"
#include "ejudge/storage_plugin.h"
#include "ejudge/metrics_contest.h"
#include "ejudge/notify_plugin.h"
#include "ejudge/cJSON.h"
#include "ejudge/json_serializers.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"
#include "ejudge/exec.h"

#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif
#define __(x) x

#define ARMOR(s)  html_armor_buf(&ab, s)

void
serve_update_standings_file(
        struct contest_extra *extra,
        serve_state_t state,
        const struct contest_desc *cnts,
        int force_flag)
{
  struct section_global_data *global = state->global;
  //time_t start_time, stop_time, duration;
  //int p = 0;
  int charset_id = 0;

  //run_get_times(state->runlog_state, &start_time, 0, &duration, &stop_time, 0);

  if (global->autoupdate_standings <= 0 && force_flag <= 0) return;
  /*
  while (1) {
    if (global->is_virtual) break;
    if (force_flag) break;
    if (!global->autoupdate_standings) return;
    if (!duration) break;
    if (!global->board_fog_time) break;

    ASSERT(state->current_time >= start_time);
    ASSERT(global->board_fog_time >= 0);
    ASSERT(global->board_unfog_time >= 0);

    p = run_get_fog_period(state->runlog_state, state->current_time,
                           global->board_fog_time, global->board_unfog_time);
    if (p == 1) return;
    break;
  }

  if (!global->is_virtual) {
    p = run_get_fog_period(state->runlog_state, state->current_time,
                           global->board_fog_time, global->board_unfog_time);
  }
  */
  unsigned char status_dir[PATH_MAX];
  unsigned char *status_dir_ptr = status_dir;
#if defined EJUDGE_CONTESTS_STATUS_DIR
  if (snprintf(status_dir, sizeof(status_dir), "%s/%06d", EJUDGE_CONTESTS_STATUS_DIR, cnts->id) >= sizeof(status_dir)) {
    // FIXME
    abort();
  }
#else
  status_dir_ptr = global->legacy_status_dir;
#endif

  charset_id = charset_get_id(global->standings_charset);
  l10n_setlocale(global->standings_locale_id);
  write_standings(extra,
                  state,
                  cnts,
                  status_dir_ptr,
                  global->standings_file_name,
                  global->stand_file_name_2,
                  global->users_on_page,
                  global->stand_header_txt,
                  global->stand_footer_txt,
                  state->accepting_mode,
                  0 /* force_fancy_style */,
                  charset_id,
                  1 /* user_mode */);
  if (global->stand2_file_name && global->stand2_file_name[0]) {
    charset_id = charset_get_id(global->stand2_charset);
    write_standings(extra,
                    state,
                    cnts,
                    status_dir_ptr,
                    global->stand2_file_name,
                    NULL /* name2 */,
                    0 /* users_on_page */,
                    global->stand2_header_txt,
                    global->stand2_footer_txt,
                    state->accepting_mode,
                    0 /* force_fancy_style */,
                    charset_id,
                    1 /* user_mode */);
  }
  l10n_resetlocale();
  /*
  if (global->is_virtual) return;
  switch (p) {
  case 0:
    global->start_standings_updated = 1;
    break;
  case 1:
    global->fog_standings_updated = 1;
    break;
  case 2:
    global->unfog_standings_updated = 1;
    break;
  }
  */
}

void
serve_update_public_log_file(
        struct contest_extra *extra,
        serve_state_t state,
        const struct contest_desc *cnts)
{
  struct section_global_data *global = state->global;
  //time_t start_time, stop_time, duration;
  //int p;
  int charset_id = 0;

  if (!global->plog_update_time) return;
  if (state->current_time < state->last_update_public_log + global->plog_update_time) return;

  /*
  run_get_times(state->runlog_state, &start_time, 0, &duration, &stop_time, 0);

  while (1) {
    if (!duration) break;
    if (!global->board_fog_time) break;

    ASSERT(state->current_time >= start_time);
    ASSERT(global->board_fog_time >= 0);
    ASSERT(global->board_unfog_time >= 0);

    p = run_get_fog_period(state->runlog_state, state->current_time,
                           global->board_fog_time, global->board_unfog_time);
    if (p == 1) return;
    break;
  }
  */

  unsigned char status_dir[PATH_MAX];
  unsigned char *status_dir_ptr = status_dir;
#if defined EJUDGE_CONTESTS_STATUS_DIR
  if (snprintf(status_dir, sizeof(status_dir), "%s/%06d", EJUDGE_CONTESTS_STATUS_DIR, cnts->id) >= sizeof(status_dir)) {
    // FIXME
    abort();
  }
#else
  status_dir_ptr = global->legacy_status_dir;
#endif

  charset_id = charset_get_id(global->plog_charset);
  l10n_setlocale(global->standings_locale_id);
  write_public_log(extra, state, cnts, status_dir_ptr,
                   global->plog_file_name,
                   global->plog_header_txt,
                   global->plog_footer_txt,
                   charset_id, 1 /* user_mode */);
  state->last_update_public_log = state->current_time;
  l10n_resetlocale();
}

static void
do_update_xml_log(serve_state_t state, const struct contest_desc *cnts,
                  char const *name, int external_mode)
{
  struct run_header rhead;
  int rbegin;
  int rtotal;
  const struct run_entry *rentries;
  path_t path1;
  path_t path2;
  FILE *fout;

  run_get_header(state->runlog_state, &rhead);
  rbegin = run_get_first(state->runlog_state);
  rtotal = run_get_total(state->runlog_state);
  rentries = run_get_entries_ptr(state->runlog_state);

  unsigned char status_dir[PATH_MAX];
  unsigned char *status_dir_ptr = status_dir;
#if defined EJUDGE_CONTESTS_STATUS_DIR
  if (snprintf(status_dir, sizeof(status_dir), "%s/%06d", EJUDGE_CONTESTS_STATUS_DIR, cnts->id) >= sizeof(status_dir)) {
    // FIXME
    abort();
  }
#else
  status_dir_ptr = state->global->legacy_status_dir;
#endif

  snprintf(path1, sizeof(path1), "%s/in/%s.tmp", status_dir_ptr, name);
  snprintf(path2, sizeof(path2), "%s/dir/%s", status_dir_ptr, name);

  if (!(fout = fopen(path1, "w"))) {
    err("update_xml_log: cannot open %s", path1);
    return;
  }
  unparse_runlog_xml(state, cnts, fout, &rhead, rbegin, rtotal, rentries,
                     external_mode, 0, state->current_time);
  if (ferror(fout)) {
    err("update_xml_log: write error");
    fclose(fout);
    unlink(path1);
    return;
  }
  if (fclose(fout) < 0) {
    err("update_xml_log: write error");
    unlink(path1);
    return;
  }
  if (rename(path1, path2) < 0) {
    err("update_xml_log: rename %s -> %s failed", path1, path2);
    unlink(path1);
    return;
  }
}

void
serve_update_external_xml_log(serve_state_t state,
                              const struct contest_desc *cnts)
{
  if (!state->global->external_xml_update_time) return;
  if (state->current_time < state->last_update_external_xml_log + state->global->external_xml_update_time) return;

  long long runlog_last_update_time_us = run_get_last_update_time_us(state->runlog_state);
  if (!state->last_update_external_xml_log_us && !runlog_last_update_time_us) {
    // not updated yet

    struct timeval tv;
    gettimeofday(&tv, NULL);
    long long current_time_us = tv.tv_sec * 1000000LL + tv.tv_usec;
    state->last_update_external_xml_log_us = current_time_us;
  } else if (state->last_update_external_xml_log_us >= runlog_last_update_time_us) {
    return;
  } else {
    state->last_update_external_xml_log_us = runlog_last_update_time_us;
  }

  state->last_update_external_xml_log = state->current_time;
  do_update_xml_log(state, cnts, "external.xml", 1);
}

void
serve_update_internal_xml_log(serve_state_t state,
                              const struct contest_desc *cnts)
{
  if (!state->global->internal_xml_update_time) return;
  if (state->current_time < state->last_update_internal_xml_log + state->global->internal_xml_update_time) return;

  long long runlog_last_update_time_us = run_get_last_update_time_us(state->runlog_state);
  if (!state->last_update_internal_xml_log_us && !runlog_last_update_time_us) {
    // not updated yet

    struct timeval tv;
    gettimeofday(&tv, NULL);
    long long current_time_us = tv.tv_sec * 1000000LL + tv.tv_usec;
    state->last_update_internal_xml_log_us = current_time_us;
  } else if (state->last_update_internal_xml_log_us >= runlog_last_update_time_us) {
    return;
  } else {
    state->last_update_internal_xml_log_us = runlog_last_update_time_us;
  }

  state->last_update_internal_xml_log = state->current_time;
  do_update_xml_log(state, cnts, "internal.xml", 0);
}

int
serve_update_status_file(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t state,
        int force_flag)
{
  if (!force_flag && state->current_time <= state->last_update_status_file) return 0;

  const struct section_global_data *global = state->global;

  struct prot_serve_status status = {};
  time_t t1, t2, t3, t4, t5;
  int p;

  status.cur_time = state->current_time;
  run_get_times(state->runlog_state, 0, &t1, &t2, &t3, &t4, &t5);
  if (t1 > 0 && t5 > 0 && t5 <= t1) {
    t5 = 0;
  }
  status.start_time = t1;
  status.sched_time = t2;
  status.duration = t3;
  status.stop_time = t4;
  status.total_runs = run_get_total(state->runlog_state);
  status.total_clars = clar_get_total(state->clarlog_state);
  status.clars_disabled = global->disable_clars;
  status.team_clars_disabled = global->disable_team_clars;
  status.score_system = global->score_system;
  status.clients_suspended = state->clients_suspended;
  status.testing_suspended = state->testing_suspended;
  status.download_interval = global->team_download_time / 60;
  status.is_virtual = global->is_virtual;
  status.continuation_enabled = global->enable_continue;
  status.printing_enabled = global->enable_printing;
  status.printing_suspended = state->printing_suspended;
  status.always_show_problems = global->always_show_problems;
  status.accepting_mode = state->accepting_mode;
  status.testing_finished = state->testing_finished;

  status.upsolving_mode = state->upsolving_mode;
  status.upsolving_freeze_standings = state->upsolving_freeze_standings;
  status.upsolving_view_source = state->upsolving_view_source;
  status.upsolving_view_protocol = state->upsolving_view_protocol;
  status.upsolving_full_protocol = state->upsolving_full_protocol;
  status.upsolving_disable_clars = state->upsolving_disable_clars;
  status.online_view_source = state->online_view_source;
  status.online_view_report = state->online_view_report;
  status.online_view_judge_score = state->online_view_judge_score;
  status.online_final_visibility = state->online_final_visibility;
  status.online_valuer_judge_comments = state->online_valuer_judge_comments;
  status.disable_virtual_start = state->disable_virtual_start;

  if (status.start_time && status.duration && global->board_fog_time > 0
      && !status.is_virtual) {
    status.freeze_time = status.start_time + status.duration - global->board_fog_time;
    if (status.freeze_time < status.start_time) {
      status.freeze_time = status.start_time;
    }
  }
  status.finish_time = t5;
  //if (status.duration) status.continuation_enabled = 0;

  if (!global->is_virtual) {
    p = run_get_fog_period(state->runlog_state, state->current_time,
                           global->board_fog_time, global->board_unfog_time);
    if (p == 1 && global->autoupdate_standings) {
      status.standings_frozen = 1;
    }
  }

  status.stat_reported_before = state->stat_reported_before;
  status.stat_report_time = state->stat_report_time;

  status.max_online_time = state->max_online_time;
  status.max_online_count = state->max_online_count;
  status.last_daily_reminder = state->last_daily_reminder;

  memcpy(status.prob_prio, state->prob_prio, sizeof(status.prob_prio));

  statusdb_save(state->statusdb_state, config, cnts, state->global, 0, &status);
  state->last_update_status_file = state->current_time;
  return 1;
}

void
serve_load_status_file(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t state)
{
  struct prot_serve_status status = {};

  int ret = statusdb_load(state->statusdb_state, config, cnts, state->global, 0, &status);
  if (ret <= 0) {
    if (state->global->score_system == SCORE_OLYMPIAD)
      state->accepting_mode = 1;
    return;
  }

  
  state->clients_suspended = status.clients_suspended;
  //info("load_status_file: clients_suspended = %d", state->clients_suspended);
  state->testing_suspended = status.testing_suspended;
  //info("load_status_file: testing_suspended = %d", state->testing_suspended);
  state->accepting_mode = status.accepting_mode;
  if (state->global->score_system == SCORE_OLYMPIAD
      && state->global->is_virtual) {
    state->accepting_mode = 1;
  }
  if (state->global->score_system != SCORE_OLYMPIAD) {
    state->accepting_mode = 0;
  }
  //info("load_status_file: accepting_mode = %d", state->accepting_mode);
  state->printing_suspended = status.printing_suspended;
  //info("load_status_file: printing_suspended = %d", state->printing_suspended);
  state->stat_reported_before = status.stat_reported_before;
  state->stat_report_time = status.stat_report_time;

  state->upsolving_mode = status.upsolving_mode;
  //info("load_status_file: upsolving_mode = %d", state->upsolving_mode);
  state->upsolving_freeze_standings = status.upsolving_freeze_standings;
  state->upsolving_view_source = status.upsolving_view_source;
  state->upsolving_view_protocol = status.upsolving_view_protocol;
  state->upsolving_full_protocol = status.upsolving_full_protocol;
  state->upsolving_disable_clars = status.upsolving_disable_clars;
  state->testing_finished = status.testing_finished;
  state->online_view_source = status.online_view_source;
  state->online_view_report = status.online_view_report;
  state->online_view_judge_score = status.online_view_judge_score;
  state->online_final_visibility = status.online_final_visibility;
  state->online_valuer_judge_comments = status.online_valuer_judge_comments;
  state->disable_virtual_start = status.disable_virtual_start;

  state->max_online_time = status.max_online_time;
  state->max_online_count = status.max_online_count;
  state->last_daily_reminder = status.last_daily_reminder;

  memcpy(state->prob_prio, status.prob_prio, sizeof(state->prob_prio));
}

void
serve_remove_status_file(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t state)
{
  if (!state || !state->global) return;
  if (!state->statusdb_state) return;

  statusdb_remove(state->statusdb_state, config, cnts, state->global);
}

int
serve_check_user_quota(serve_state_t state, int user_id, size_t size)
{
  int num;
  size_t total;

  if (size > state->global->max_run_size) return -1;
  run_get_team_usage(state->runlog_state, user_id, &num, &total);
  if (num >= state->global->max_run_num
      || total + size > state->global->max_run_total)
    return -1;
  return 0;
}

int
serve_check_clar_quota(serve_state_t state, int user_id, size_t size)
{
  int num;
  size_t total;

  if (size > state->global->max_clar_size) return -1;
  clar_get_user_usage(state->clarlog_state, user_id, &num, &total);
  if (num >= state->global->max_clar_num
      || total + size > state->global->max_clar_total)
    return -1;
  return 0;
}

int
serve_check_cnts_caps(serve_state_t state,
                      const struct contest_desc *cnts,
                      int user_id, int bit)
{
  opcap_t caps;
  unsigned char const *login = 0;

  login = teamdb_get_login(state->teamdb_state, user_id);
  if (!login || !*login) return 0;

  if (opcaps_find(&cnts->capabilities, login, &caps) < 0) return 0;
  if (opcaps_check(caps, bit) < 0) return 0;
  return 1;
}

int
serve_get_cnts_caps(serve_state_t state,
                    const struct contest_desc *cnts,
                    int user_id, opcap_t *out_caps)
{
  opcap_t caps;
  unsigned char const *login = 0;

  login = teamdb_get_login(state->teamdb_state, user_id);
  if (!login || !*login) return -1;

  if (opcaps_find(&cnts->capabilities, login, &caps) < 0) return -1;
  if (out_caps) *out_caps = caps;
  return 0;
}

static struct compile_queue_item *
lookup_compile_queue_item(
        const serve_state_t state,
        const unsigned char *queue_id)
{
  if (!queue_id) queue_id = "";
  for (int i = 0; i < state->compile_queues_u; ++i) {
    if (!strcmp(state->compile_queues[i].id, queue_id))
      return &state->compile_queues[i];
  }
  return NULL;
}

static int
do_build_compile_queue_dirs(
        serve_state_t cs,
        const unsigned char *id,
        const unsigned char *queue_dir,
        const unsigned char *src_dir,
        const unsigned char *heartbeat_dir)
{
  int i;

  for (i = 0; i < cs->compile_queues_u; ++i) {
    if (!strcmp(cs->compile_queues[i].queue_dir, queue_dir)) {
      return i;
    }
  }

  if (cs->compile_queues_u == cs->compile_queues_a) {
    if (!(cs->compile_queues_a *= 2)) cs->compile_queues_a = 8;
    XREALLOC(cs->compile_queues, cs->compile_queues_a);
  }

  struct compile_queue_item *item = &cs->compile_queues[cs->compile_queues_u++];
  memset(item, 0, sizeof(*item));

  item->id = xstrdup(id);
  item->queue_dir = xstrdup(queue_dir);
  item->src_dir = xstrdup(src_dir);
  if (heartbeat_dir) {
    item->heartbeat_dir = xstrdup(heartbeat_dir);
  }

  return i;
}

static int
do_build_compile_dirs(serve_state_t state,
                      const unsigned char *status_dir,
                      const unsigned char *report_dir)
{
  int i;

  if (!status_dir || !*status_dir || !report_dir || !*report_dir) abort();

  for (i = 0; i < state->compile_dirs_u; i++)
    if (!strcmp(state->compile_dirs[i].status_dir, status_dir))
      break;
  if (i < state->compile_dirs_u) return i;

  if (state->compile_dirs_u == state->compile_dirs_a) {
    if (!state->compile_dirs_a) state->compile_dirs_a = 8;
    state->compile_dirs_a *= 2;
    XREALLOC(state->compile_dirs, state->compile_dirs_a);
  }

  state->compile_dirs[state->compile_dirs_u].status_dir = xstrdup(status_dir);
  state->compile_dirs[state->compile_dirs_u].report_dir = xstrdup(report_dir);
  return state->compile_dirs_u++;
}

void
serve_build_compile_dirs(
        const struct ejudge_cfg *config,
        serve_state_t state)
{
  int i;
  const __attribute__((unused)) struct section_global_data *global = state->global;

  for (i = 1; i <= state->max_lang; i++) {
    const struct section_language_data *lang = state->langs[i];
    if (!lang) continue;

    const unsigned char *compile_status_dir = NULL;
    const unsigned char *compile_report_dir = NULL;

#if defined EJUDGE_COMPILE_SPOOL_DIR
    __attribute__((unused)) const unsigned char *compile_spool_dir = EJUDGE_COMPILE_SPOOL_DIR;
    __attribute__((unused)) const unsigned char *compile_server_id = NULL;
    /*
    if (lang && lang->compile_server_id && lang->compile_server_id[0]) {
      compile_server_id = lang->compile_server_id;
    } else {
      compile_server_id = config->contest_server_id;
    }
    */
    // result directories always use server contest_server_id
    compile_server_id = config->contest_server_id;

    __attribute__((unused)) unsigned char compile_report_buf[PATH_MAX];
    __attribute__((unused)) unsigned char compile_status_buf[PATH_MAX];

    if (lang && lang->compile_dir_index > 0) {
      compile_status_dir = lang->compile_status_dir;
      compile_report_dir = lang->compile_report_dir;
    } else if (lang && lang->compile_dir && lang->compile_dir[0] && global && global->compile_dir && strcmp(lang->compile_dir, global->compile_dir) != 0) {
      compile_status_dir = lang->compile_status_dir;
      compile_report_dir = lang->compile_report_dir;
    } else {
      // do not add watch dirs, because the global compile result directories are used
      /*
      snprintf(compile_status_buf, sizeof(compile_status_buf), "%s/%s/%06d/status", compile_spool_dir, compile_server_id, state->contest_id);
      compile_status_dir = compile_status_buf;
      snprintf(compile_report_buf, sizeof(compile_report_buf), "%s/%s/%06d/report", compile_spool_dir, compile_server_id, state->contest_id);
      compile_report_dir = compile_report_buf;
      */
    }
#else
    compile_status_dir = lang->compile_status_dir;
    compile_report_dir = lang->compile_report_dir;
#endif
    if (compile_status_dir) {
      do_build_compile_dirs(state, compile_status_dir, compile_report_dir);
    }
  }

  // build queue dirs
  for (i = 1; i <= state->max_lang; i++) {
    const struct section_language_data *lang = state->langs[i];
    if (!lang) continue;

    const unsigned char *id = "";
    const unsigned char *src_dir = NULL;
    const unsigned char *queue_dir = NULL;
    const unsigned char *heartbeat_dir = NULL;

    unsigned char src_buf[PATH_MAX];
    unsigned char queue_buf[PATH_MAX];
    unsigned char heartbeat_buf[PATH_MAX];
    __attribute__((unused)) int r;

#if defined EJUDGE_COMPILE_SPOOL_DIR
    if (lang && lang->compile_server_id && lang->compile_server_id[0]) {
      id = lang->compile_server_id;
    } else if (global->compile_server_id && global->compile_server_id[0]) {
      id = global->compile_server_id;
    } else {
      id = config->contest_server_id;
    }

    if (lang->compile_dir_index > 0) {
      src_dir = lang->compile_src_dir;
      queue_dir = lang->compile_queue_dir;
      r = snprintf(heartbeat_buf, sizeof(heartbeat_buf), "%s/../heartbeat", queue_dir);
      heartbeat_dir = heartbeat_buf;
    } else if (lang->compile_dir && lang->compile_dir[0] && global && global->compile_dir && strcmp(lang->compile_dir, global->compile_dir) != 0) {
      src_dir = lang->compile_src_dir;
      queue_dir = lang->compile_queue_dir;
      r = snprintf(heartbeat_buf, sizeof(heartbeat_buf), "%s/../heartbeat", queue_dir);
      heartbeat_dir = heartbeat_buf;
    } else {
      const unsigned char *spool_dir = EJUDGE_COMPILE_SPOOL_DIR;
      r = snprintf(src_buf, sizeof(src_buf), "%s/%s/src", spool_dir, id);
      src_dir = src_buf;
      r = snprintf(queue_buf, sizeof(queue_buf), "%s/%s/queue", spool_dir, id);
      queue_dir = queue_buf;
      r = snprintf(heartbeat_buf, sizeof(heartbeat_buf), "%s/%s/heartbeat", spool_dir, id);
      heartbeat_dir = heartbeat_buf;
    }
#else
    src_dir = global->compile_src_dir;
    if (lang->compile_src_dir && lang->compile_src_dir[0]) {
      src_dir = lang->compile_src_dir;
    }
    queue_dir = global->compile_queue_dir;
    if (lang->compile_queue_dir && lang->compile_queue_dir[0]) {
      queue_dir = lang->compile_queue_dir;
    }
    heartbeat_dir = NULL; // disabled
#endif
    do_build_compile_queue_dirs(state, id, queue_dir, src_dir, heartbeat_dir);
  }
}

static __attribute__((unused)) int
do_build_run_dirs(
        serve_state_t state,
        const unsigned char *id,
        const unsigned char *status_dir,
        const unsigned char *report_dir,
        const unsigned char *team_report_dir,
        const unsigned char *full_report_dir)
{
  int i;

  if (!status_dir || !*status_dir) abort();

  for (i = 0; i < state->run_dirs_u; i++)
    if (!strcmp(state->run_dirs[i].status_dir, status_dir))
      break;
  if (i < state->run_dirs_u) return i;

  if (state->run_dirs_u == state->run_dirs_a) {
    if (!state->run_dirs_a) state->run_dirs_a = 8;
    state->run_dirs_a *= 2;
    XREALLOC(state->run_dirs, state->run_dirs_a);
  }

  struct run_dir_item *cur = &state->run_dirs[state->run_dirs_u];
  memset(cur, 0, sizeof(*cur));

  cur->id = xstrdup(id);
  cur->status_dir = xstrdup(status_dir);
  cur->report_dir = xstrdup(report_dir);
  cur->team_report_dir = xstrdup(team_report_dir);
  cur->full_report_dir = xstrdup(full_report_dir);
  return state->run_dirs_u++;
}

static int
do_build_queue_dirs(
        serve_state_t state,
        const unsigned char *id,
        const unsigned char *queue_dir,
        const unsigned char *exe_dir,
        const unsigned char *heartbeat_dir)
{
  int i;

  for (i = 0; i < state->run_queues_u; ++i) {
    if (!strcmp(state->run_queues[i].queue_dir, queue_dir)) {
      return i;
    }
  }

  if (state->run_queues_u == state->run_queues_a) {
    if (!state->run_queues_a) state->run_queues_a = 8;
    state->run_queues_a *= 2;
    XREALLOC(state->run_queues, state->run_queues_a);
  }

  struct run_queue_item *cur = &state->run_queues[state->run_queues_u];
  memset(cur, 0, sizeof(*cur));

  cur->id = xstrdup(id);
  cur->queue_dir = xstrdup(queue_dir);
  cur->exe_dir = xstrdup(exe_dir);
  if (heartbeat_dir) {
    cur->heartbeat_dir = xstrdup(heartbeat_dir);
  }

  return state->run_queues_u++;
}

#if defined EJUDGE_RUN_SPOOL_DIR
static void
build_run_dir(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        const unsigned char *contest_server_id,
        const unsigned char *run_server_id,
        const unsigned char *queue_name)
{
  unsigned char d1[PATH_MAX];
  snprintf(d1, sizeof(d1), "%s/%s", EJUDGE_RUN_SPOOL_DIR, run_server_id);

  unsigned char queue_dir[PATH_MAX];
  unsigned char exe_dir[PATH_MAX];
  unsigned char heartbeat_dir[PATH_MAX];
  snprintf(queue_dir, sizeof(queue_dir), "%s/queue", d1);
  snprintf(exe_dir, sizeof(exe_dir), "%s/exe", d1);
  snprintf(heartbeat_dir, sizeof(heartbeat_dir), "%s/heartbeat", d1);
  do_build_queue_dirs(state, run_server_id, queue_dir, exe_dir, heartbeat_dir);

  // do not create contest specific dirs, using the globals instead
  return;
    /*
  unsigned char d2[PATH_MAX];
  snprintf(d2, sizeof(d2), "%s/%s/%06d", EJUDGE_RUN_SPOOL_DIR, contest_server_id, cnts->id);

  unsigned char status_dir[PATH_MAX];
  unsigned char report_dir[PATH_MAX];
  unsigned char team_report_dir[PATH_MAX];
  unsigned char full_report_dir[PATH_MAX];
  snprintf(status_dir, sizeof(status_dir), "%s/status", d2);
  snprintf(report_dir, sizeof(report_dir), "%s/report", d2);
  snprintf(full_report_dir, sizeof(full_report_dir), "%s/output", d2);
  snprintf(team_report_dir, sizeof(team_report_dir), "%s/teamreports", d2);
  do_build_run_dirs(state, "", status_dir, report_dir, team_report_dir, full_report_dir);
    */
}
#endif

void
serve_build_run_dirs(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts)
{
  const struct section_global_data *global = state->global;
  int i;
#if !defined EJUDGE_RUN_SPOOL_DIR
  unsigned char status_dir[PATH_MAX];
  unsigned char report_dir[PATH_MAX];
  unsigned char team_report_dir[PATH_MAX];
  unsigned char full_report_dir[PATH_MAX];
  unsigned char queue_dir[PATH_MAX];
  unsigned char exe_dir[PATH_MAX];
  unsigned char heartbeat_dir[PATH_MAX];
#endif

  if (cnts && cnts->run_managed) {
#if defined EJUDGE_RUN_SPOOL_DIR
    build_run_dir(config, state, cnts, config->contest_server_id, config->contest_server_id, "");
#else
    snprintf(queue_dir, sizeof(queue_dir), "%s/super-run/var/queue", EJUDGE_CONTESTS_HOME_DIR);
    snprintf(exe_dir, sizeof(exe_dir), "%s/super-run/var/exe", EJUDGE_CONTESTS_HOME_DIR);
    snprintf(heartbeat_dir, sizeof(heartbeat_dir), "%s/super-run/var/heartbeat", EJUDGE_CONTESTS_HOME_DIR);
    do_build_queue_dirs(state, "", queue_dir, exe_dir, heartbeat_dir);
#endif
  }

  if (global->super_run_dir && global->super_run_dir[0]) {
#if defined EJUDGE_RUN_SPOOL_DIR
    build_run_dir(config, state, cnts, config->contest_server_id, global->super_run_dir, global->super_run_dir);
#else
    snprintf(status_dir, sizeof(status_dir),
             "%s/var/%06d/status", global->super_run_dir, cnts->id);
    snprintf(report_dir, sizeof(report_dir),
             "%s/var/%06d/report", global->super_run_dir, cnts->id);
    snprintf(full_report_dir, sizeof(full_report_dir),
             "%s/var/%06d/output", global->super_run_dir, cnts->id);
    snprintf(team_report_dir, sizeof(team_report_dir),
             "%s/var/%06d/teamreports", global->super_run_dir, cnts->id);
    do_build_run_dirs(state, "", status_dir, report_dir, team_report_dir, full_report_dir);

    snprintf(queue_dir, sizeof(queue_dir), "%s/var/queue", global->super_run_dir);
    snprintf(exe_dir, sizeof(exe_dir), "%s/var/exe", global->super_run_dir);
    snprintf(heartbeat_dir, sizeof(heartbeat_dir), "%s/var/heartbeat", global->super_run_dir);
    do_build_queue_dirs(state, global->super_run_dir, queue_dir, exe_dir, heartbeat_dir);
#endif
  }

  for (i = 1; i <= state->max_lang; ++i) {
    struct section_language_data *lang = state->langs[i];
    if (lang && lang->super_run_dir && lang->super_run_dir[0]) {
#if defined EJUDGE_RUN_SPOOL_DIR
      build_run_dir(config, state, cnts, config->contest_server_id, lang->super_run_dir, lang->super_run_dir);
#else
      snprintf(status_dir, sizeof(status_dir),
               "%s/var/%06d/status", lang->super_run_dir, cnts->id);
      snprintf(report_dir, sizeof(report_dir),
               "%s/var/%06d/report", lang->super_run_dir, cnts->id);
      snprintf(full_report_dir, sizeof(full_report_dir),
               "%s/var/%06d/output", lang->super_run_dir, cnts->id);
      snprintf(team_report_dir, sizeof(team_report_dir),
               "%s/var/%06d/teamreports", lang->super_run_dir, cnts->id);
      do_build_run_dirs(state, lang->super_run_dir, status_dir, report_dir, team_report_dir, full_report_dir);

      snprintf(queue_dir, sizeof(queue_dir), "%s/var/queue", lang->super_run_dir);
      snprintf(exe_dir, sizeof(exe_dir), "%s/var/exe", lang->super_run_dir);
      snprintf(heartbeat_dir, sizeof(heartbeat_dir), "%s/var/heartbeat", lang->super_run_dir);
      do_build_queue_dirs(state, lang->super_run_dir, queue_dir, exe_dir, heartbeat_dir);
#endif
    }
  }

  for (i = 1; i <= state->max_prob; ++i) {
    struct section_problem_data *prob = state->probs[i];
    if (prob && prob->super_run_dir && prob->super_run_dir[0]) {
#if defined EJUDGE_RUN_SPOOL_DIR
      build_run_dir(config, state, cnts, config->contest_server_id, prob->super_run_dir, prob->super_run_dir);
#else
      snprintf(status_dir, sizeof(status_dir),
               "%s/var/%06d/status", prob->super_run_dir, cnts->id);
      snprintf(report_dir, sizeof(report_dir),
               "%s/var/%06d/report", prob->super_run_dir, cnts->id);
      snprintf(full_report_dir, sizeof(full_report_dir),
               "%s/var/%06d/output", prob->super_run_dir, cnts->id);
      snprintf(team_report_dir, sizeof(team_report_dir),
               "%s/var/%06d/teamreports", prob->super_run_dir, cnts->id);
      do_build_run_dirs(state, prob->super_run_dir, status_dir, report_dir, team_report_dir, full_report_dir);

      snprintf(queue_dir, sizeof(queue_dir), "%s/var/queue", prob->super_run_dir);
      snprintf(exe_dir, sizeof(exe_dir), "%s/var/exe", prob->super_run_dir);
      snprintf(heartbeat_dir, sizeof(heartbeat_dir), "%s/var/heartbeat", prob->super_run_dir);
      do_build_queue_dirs(state, prob->super_run_dir, queue_dir, exe_dir, heartbeat_dir);
#endif
    }
  }

#if !defined EJUDGE_RUN_SPOOL_DIR
  for (i = 1; i <= state->max_tester; i++) {
    if (!state->testers[i]) continue;
    //if (state->testers[i]->any) continue;
    do_build_run_dirs(state, state->testers[i]->name,
                      state->testers[i]->run_status_dir,
                      state->testers[i]->run_report_dir,
                      state->testers[i]->run_team_report_dir,
                      state->testers[i]->run_full_archive_dir);

    do_build_queue_dirs(state, state->testers[i]->name,
                        state->testers[i]->run_queue_dir,
                        state->testers[i]->run_exe_dir, NULL);
  }

  if (state->max_tester <= 0) {
    // provide default dirs for run results and run queue
    do_build_run_dirs(state, "default",
                      global->run_status_dir,
                      global->run_report_dir,
                      global->run_team_report_dir,
                      global->run_full_archive_dir);
    do_build_queue_dirs(state, "default",
                        global->run_queue_dir,
                        global->run_exe_dir,
                        NULL);
  }
#endif
}

int
serve_create_symlinks(
        const struct contest_desc *cnts,
        serve_state_t state)
{
  const struct section_global_data *global = state->global;
  unsigned char src_path[PATH_MAX];
  unsigned char dst_path[PATH_MAX];
  path_t stand_file;
  int npages, pgn;
  int total_users = 0;

  unsigned char status_dir[PATH_MAX];
  unsigned char *status_dir_ptr = status_dir;
#if defined EJUDGE_CONTESTS_STATUS_DIR
  if (snprintf(status_dir, sizeof(status_dir), "%s/%06d", EJUDGE_CONTESTS_STATUS_DIR, cnts->id) >= sizeof(status_dir)) {
    // FIXME
    abort();
  }
#else
  status_dir_ptr = global->legacy_status_dir;
#endif

  if (global->stand_symlink_dir && global->stand_symlink_dir[0]
      && global->htdocs_dir && global->htdocs_dir[0]) {
    if (global->users_on_page > 0) {
      // FIXME: check, that standings_file_name depends on page number
      if (global->disable_user_database > 0) {
        total_users = run_get_total_users(state->runlog_state);
      } else {
        total_users = teamdb_get_total_teams(state->teamdb_state);
      }
      npages = (total_users + global->users_on_page - 1)
        / global->users_on_page;
      for (pgn = 0; pgn < npages; pgn++) {
        if (!pgn) {
          snprintf(stand_file, sizeof(stand_file),
                   global->standings_file_name, pgn + 1);
        } else {
          snprintf(stand_file, sizeof(stand_file),
                   global->stand_file_name_2, pgn + 1);
        }
        snprintf(src_path, sizeof(src_path), "%s/dir/%s",
                 status_dir_ptr, stand_file);
        snprintf(dst_path, sizeof(dst_path), "%s/%s/%s",
                 global->htdocs_dir, global->stand_symlink_dir,
                 stand_file);
        os_normalize_path(dst_path);
        if (unlink(dst_path) < 0 && errno != ENOENT) {
          err("unlink %s failed: %s", dst_path, os_ErrorMsg());
          //return -1;
        }
        if (symlink(src_path, dst_path) < 0) {
          err("symlink %s->%s failed: %s", dst_path, src_path, os_ErrorMsg());
          //return -1;
        }
      }
    } else {
      snprintf(src_path, sizeof(src_path), "%s/dir/%s",
               status_dir_ptr, global->standings_file_name);
      snprintf(dst_path, sizeof(dst_path), "%s/%s/%s",
               global->htdocs_dir, global->stand_symlink_dir,
               global->standings_file_name);
      os_normalize_path(dst_path);
      if (unlink(dst_path) < 0 && errno != ENOENT) {
        err("unlink %s failed: %s", dst_path, os_ErrorMsg());
        //return -1;
      }
      if (symlink(src_path, dst_path) < 0) {
        err("symlink %s->%s failed: %s", dst_path, src_path, os_ErrorMsg());
        //return -1;
      }
    }
  }
  if (global->stand2_symlink_dir && global->stand2_symlink_dir[0]
      && global->htdocs_dir && global->htdocs_dir[0]
      && global->stand2_file_name && global->stand2_file_name[0]) {
    snprintf(src_path, sizeof(src_path), "%s/dir/%s",
             status_dir_ptr, global->stand2_file_name);
    snprintf(dst_path, sizeof(dst_path), "%s/%s/%s",
             global->htdocs_dir, global->stand2_symlink_dir,
             global->stand2_file_name);
    os_normalize_path(dst_path);
    if (unlink(dst_path) < 0 && errno != ENOENT) {
      err("unlink %s failed: %s", dst_path, os_ErrorMsg());
      //return -1;
    }
    if (symlink(src_path, dst_path) < 0) {
      err("symlink %s->%s failed: %s", dst_path, src_path, os_ErrorMsg());
      //return -1;
    }
  }
  if (global->plog_symlink_dir && global->plog_symlink_dir[0]
      && global->htdocs_dir && global->htdocs_dir[0]
      && global->plog_file_name && global->plog_file_name[0]
      && global->plog_update_time > 0) {
    snprintf(src_path, sizeof(src_path), "%s/dir/%s",
             status_dir_ptr, global->plog_file_name);
    snprintf(dst_path, sizeof(dst_path), "%s/%s/%s",
             global->htdocs_dir, global->plog_symlink_dir,
             global->plog_file_name);
    os_normalize_path(dst_path);
    if (unlink(dst_path) < 0 && errno != ENOENT) {
      err("unlink %s failed: %s", dst_path, os_ErrorMsg());
      //return -1;
    }
    if (symlink(src_path, dst_path) < 0) {
      err("symlink %s->%s failed: %s", dst_path, src_path, os_ErrorMsg());
      //return -1;
    }
  }
  return 0;
}

const unsigned char *
serve_get_email_sender(const struct ejudge_cfg *config, const struct contest_desc *cnts)
{
  int sysuid;
  struct passwd *ppwd;

  if (cnts && cnts->register_email) return cnts->register_email;
  if (config && config->register_email) return config->register_email;
  sysuid = getuid();
  ppwd = getpwuid(sysuid);
  return ppwd->pw_name;
}

void
serve_check_telegram_reminder(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts)
{
  if (cnts->enable_reminders <= 0) return;

  // if current time hour >= 10 and time from the last reminder > 24h, try hard
  struct tm *ptm = localtime(&state->current_time);
  if (ptm->tm_hour >= 10 && (state->last_daily_reminder <= 0 || state->last_daily_reminder + 24 * 60 * 60 <= state->current_time)) {
  } else {
    return;
  }

  if (!cnts->telegram_admin_chat_id || !cnts->telegram_admin_chat_id[0])
    return;

  const unsigned char *telegram_bot_id = cnts->telegram_bot_id;
  if (telegram_bot_id && !*telegram_bot_id) telegram_bot_id = NULL;
  if (!telegram_bot_id) telegram_bot_id = ejudge_cfg_get_telegram_bot_id(config, NULL);
  if (!telegram_bot_id) return;

  struct telegram_reminder_data trdata;
  collect_telegram_reminder(cnts, state, &trdata);
  if (trdata.pr_total >= 20 || trdata.pr_too_old > 0 || trdata.unans_clars > 0) {
    const unsigned char *args[10];
    char contest_id_buf[32];
    char pr_total_buf[32];
    char pr_too_old_buf[32];
    char unans_clar_buf[32];

    args[0] = "telegram_reminder";
    args[1] = telegram_bot_id;
    args[2] = cnts->telegram_admin_chat_id;
    snprintf(contest_id_buf, sizeof(contest_id_buf), "%d", cnts->id);
    args[3] = contest_id_buf;
    args[4] = cnts->name;
    snprintf(pr_total_buf, sizeof(pr_total_buf), "%d", trdata.pr_total);
    args[5] = pr_total_buf;
    snprintf(pr_too_old_buf, sizeof(pr_too_old_buf), "%d", trdata.pr_too_old);
    args[6] = pr_too_old_buf;
    snprintf(unans_clar_buf, sizeof(unans_clar_buf), "%d", trdata.unans_clars);
    args[7] = unans_clar_buf;
    args[8] = NULL;
    send_job_packet(config, (unsigned char**) args);
  }

  struct tm stm;
  memset(&stm, 0, sizeof(stm));
  stm.tm_year = ptm->tm_year;
  stm.tm_mon = ptm->tm_mon;
  stm.tm_mday = ptm->tm_mday;
  stm.tm_hour = 10;
  stm.tm_min = 0;
  stm.tm_sec = 0;
  stm.tm_isdst = -1;
  time_t st = mktime(&stm);

  state->last_daily_reminder = st;
}

static void
generate_statistics_email(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        time_t from_time,
        time_t to_time,
        int utf8_mode)
{
  unsigned char esubj[1024];
  struct tm *ptm;
  char *etxt = 0, *ftxt = 0;
  size_t elen = 0, flen = 0;
  FILE *eout = 0, *fout = 0;
  const unsigned char *mail_args[7];
  const unsigned char *originator;
  struct tm tm1;

  ptm = localtime(&from_time);
  snprintf(esubj, sizeof(esubj),
           "Daily statistics for %04d-%02d-%02d, contest %d",
           ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
           cnts->id);

  eout = open_memstream(&etxt, &elen);
  generate_daily_statistics(cnts, state, eout, from_time, to_time, utf8_mode);
  close_memstream(eout); eout = 0;
  if (!etxt || !*etxt) {
    xfree(etxt);
    return;
  }

  localtime_r(&from_time, &tm1);

  fout = open_memstream(&ftxt, &flen);
  fprintf(fout,
          "Hello,\n"
          "\n"
          "This is daily report for contest %d (%s)\n"
          "Report day: %04d-%02d-%02d\n\n"
          "%s\n\n"
          "-\n"
          "Regards,\n"
          "the ejudge contest management system\n",
          cnts->id, cnts->name,
          tm1.tm_year + 1900, tm1.tm_mon + 1, tm1.tm_mday,
          etxt);
  close_memstream(fout); fout = 0;

  originator = serve_get_email_sender(config, cnts);
  mail_args[0] = "mail";
  mail_args[1] = "";
  mail_args[2] = esubj;
  mail_args[3] = originator;
  mail_args[4] = cnts->daily_stat_email;
  mail_args[5] = ftxt;
  mail_args[6] = 0;
  send_job_packet(config, (unsigned char **) mail_args);
  xfree(ftxt); ftxt = 0;
  xfree(etxt); etxt = 0;
}

void
serve_check_stat_generation(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        int force_flag,
        int utf8_mode)
{
  struct tm *ptm;
  time_t thisday, nextday;

  if (!cnts) return;
  if (!force_flag && state->stat_last_check_time > 0
      && state->stat_last_check_time + 600 > state->current_time)
    return;
  state->stat_last_check_time = state->current_time;
  if (!cnts->daily_stat_email) return;

  if (!state->stat_reported_before) {
    // set the time to the beginning of this day
    ptm = localtime(&state->current_time);
    ptm->tm_hour = 0;
    ptm->tm_min = 0;
    ptm->tm_sec = 0;
    ptm->tm_isdst = -1;
    if ((thisday = mktime(ptm)) == (time_t) -1) {
      err("check_stat_generation: mktime() failed");
      thisday = 0;
    }
    state->stat_reported_before = thisday;
  }
  if (!state->stat_report_time) {
    // set the time to the beginning of the next day
    ptm = localtime(&state->current_time);
    ptm->tm_hour = 0;
    ptm->tm_min = 0;
    ptm->tm_sec = 0;
    ptm->tm_isdst = -1;
    ptm->tm_mday++;             // pretty valid. see man mktime
    if ((nextday = mktime(ptm)) == (time_t) -1) {
      err("check_stat_generation: mktime() failed");
      nextday = 0;
    }
    state->stat_report_time = nextday;
  }

  if (state->current_time < state->stat_report_time) return;

  // set the stat_report_time to the beginning of today
  ptm = localtime(&state->current_time);
  ptm->tm_hour = 0;
  ptm->tm_min = 0;
  ptm->tm_sec = 0;
  ptm->tm_isdst = -1;
  if ((thisday = mktime(ptm)) != (time_t) -1)
    state->stat_report_time = thisday;

  // generate report for each day from stat_reported_before to stat_report_time
  thisday = state->stat_reported_before;
  while (thisday < state->stat_report_time) {
    ptm = localtime(&thisday);
    ptm->tm_hour = 0;
    ptm->tm_min = 0;
    ptm->tm_sec = 0;
    ptm->tm_isdst = -1;
    ptm->tm_mday++;
    if ((nextday = mktime(ptm)) == (time_t) -1) {
      err("check_stat_generation: mktime() failed");
      state->stat_reported_before = 0;
      state->stat_report_time = 0;
      return;
    }
    generate_statistics_email(config, state, cnts, thisday, nextday, utf8_mode);
    thisday = nextday;
  }

  ptm = localtime(&thisday);
  ptm->tm_hour = 0;
  ptm->tm_min = 0;
  ptm->tm_sec = 0;
  ptm->tm_isdst = -1;
  ptm->tm_mday++;
  if ((nextday = mktime(ptm)) == (time_t) -1) {
    err("check_stat_generation: mktime() failed");
    state->stat_reported_before = 0;
    state->stat_report_time = 0;
    return;
  }
  state->stat_reported_before = thisday;
  state->stat_report_time = nextday;
}

void
serve_move_files_to_insert_run(serve_state_t state, int run_id)
{
  int total = run_get_total(state->runlog_state);
  int i, s;
  const struct section_global_data *global = state->global;
  struct run_entry re;

  ASSERT(run_id >= 0 && run_id < total);
  // the last run
  if (run_id == total - 1) return;
  for (i = total - 2; i >= run_id; i--) {
    if (run_get_entry(state->runlog_state, i, &re) < 0) continue;
    if (re.store_flags == STORE_FLAGS_UUID) continue;

    info("rename: %d -> %d", i, i + 1);
    archive_remove(state, global->run_archive_dir, i + 1, 0);
    archive_remove(state, global->xml_report_archive_dir, i + 1, 0);
    archive_remove(state, global->report_archive_dir, i + 1, 0);
    archive_remove(state, global->team_report_archive_dir, i + 1, 0);
    archive_remove(state, global->full_archive_dir, i + 1, 0);
    archive_remove(state, global->audit_log_dir, i + 1, 0);

    archive_rename(state, global->audit_log_dir, 0, i, 0, i + 1, 0, 0);
    serve_audit_log(state, i + 1, &re, 0, 0, 0,
                    "rename", "ok", -1,
                    "From-run-id: %d\n"
                    "To-run-id: %d\n", i, i + 1);

    s = run_get_status(state->runlog_state, i + 1);
    run_clear_index(state->runlog_state, i + 1);
    archive_rename(state, global->run_archive_dir, 0, i, 0, i + 1, 0, 0);
    if (s >= RUN_PSEUDO_FIRST && s <= RUN_PSEUDO_LAST) continue;
    if (s == RUN_IGNORED || s == RUN_DISQUALIFIED || s ==RUN_PENDING) continue;
    if (run_is_imported(state->runlog_state, i + 1)) continue;
    archive_rename(state, global->xml_report_archive_dir, 0, i, 0, i + 1, 0, 0);
    archive_rename(state, global->report_archive_dir, 0, i, 0, i + 1, 0, 0);
    archive_rename(state, global->team_report_archive_dir, 0,i,0,i + 1,0,0);
    archive_rename(state, global->full_archive_dir, 0, i, 0, i + 1, 0, ZIP);
  }
}

void
serve_audit_log(
        serve_state_t state,
        int run_id,
        const struct run_entry *re,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        const unsigned char *command,
        const unsigned char *status,
        int run_status,
        const char *format,
        ...)
{
  unsigned char buf[16384];
  unsigned char tbuf[128];
  va_list args;
  struct tm *ltm;
  path_t audit_path;
  FILE *f;
  unsigned char *login;
  size_t buf_len;
  unsigned char status_buf[64];
  int flags;
  struct run_entry local_re;

  buf[0] = 0;
  if (format && *format) {
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
  }
  buf_len = strlen(buf);
  while (buf_len > 0 && isspace(buf[buf_len - 1])) buf[--buf_len] = 0;

  if (re == NULL) {
    if (run_get_entry(state->runlog_state, run_id, &local_re) >= 0)
      re = &local_re;
  }

  ltm = localtime(&state->current_time);
  snprintf(tbuf, sizeof(tbuf), "%04d-%02d-%02d %02d:%02d:%02d",
           ltm->tm_year + 1900, ltm->tm_mon + 1, ltm->tm_mday,
           ltm->tm_hour, ltm->tm_min, ltm->tm_sec);

  if (re && (re->store_flags == STORE_FLAGS_UUID || re->store_flags == STORE_FLAGS_UUID_BSON)) {
    flags = uuid_archive_prepare_write_path(state, audit_path, sizeof(audit_path),
                                            &re->run_uuid, 0, DFLT_R_UUID_AUDIT, 0, 1);
  } else {
    flags = archive_prepare_write_path(state, audit_path, sizeof(audit_path),
                                       state->global->audit_log_dir, run_id, 0,
                                       NULL, 0, 1);
  }
  if (flags < 0) return;
  if (!(f = fopen(audit_path, "a"))) return;

  fprintf(f, "Date: %s\n", tbuf);
  if (!user_id) {
    fprintf(f, "From: SYSTEM\n");
  } else if (user_id < 0) {
    fprintf(f, "From: invalid user %d\n", user_id);
  } else if (!(login = teamdb_get_login(state->teamdb_state, user_id))){
    fprintf(f, "From: user %d (login unknown)\n", user_id);
  } else {
    fprintf(f, "From: %s (uid %d)\n", login, user_id);
  }
  if (ip) {
    fprintf(f, "Ip: %s%s\n", xml_unparse_ipv6(ip), ssl_flag?"/SSL":"");
  }
  if (command && *command) {
    fprintf(f, "Command: %s\n", command);
  }
  if (status && *status) {
    fprintf(f, "Status: %s\n", status);
  }
  if (run_id >= 0) {
    fprintf(f, "Run-id: %d\n", run_id);
  }
  if (run_status >= 0) {
    run_status_to_str_short(status_buf, sizeof(status_buf), run_status);
    fprintf(f, "Run-status: %s\n", status_buf);
  }

  if (buf[0]) {
    fprintf(f, "%s\n\n", buf);
  } else {
    fprintf(f, "\n");
  }

  fclose(f);
}

static char **
filter_lang_environ(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct section_problem_data *prob,
        const struct section_language_data *lang,
        const struct section_tester_data *tester,
        char **environ)
{
  int count = 0, i, llen, j = 0;
  char **env = NULL;
  llen = strlen(lang->short_name);
  for (i = 0; environ[i]; ++i) {
    if (environ[i][0] == '*' && environ[i][1] == '=') {
      ++count;
    } else if (strlen(environ[i]) > llen && !strncmp(lang->short_name, environ[i], llen) && environ[i][llen] == '=') {
      ++count;
    }
  }
  XCALLOC(env, count + 1);
  for (i = 0; environ[i]; ++i) {
    if (environ[i][0] == '*' && environ[i][1] == '=') {
      env[j++] = prepare_varsubst(state, environ[i] + 2, 0, prob, lang, tester);
    } else if (strlen(environ[i]) > llen && !strncmp(lang->short_name, environ[i], llen) && environ[i][llen] == '=') {
      env[j++] = prepare_varsubst(state, environ[i] + llen + 1, 0, prob, lang, tester);
    }
  }
  return env;
}

int
serve_compile_request(
        const struct ejudge_cfg *config,
        serve_state_t state,
        unsigned char const *str,
        int len,
        int contest_id,
        int run_id,
        int64_t submit_id,
        int user_id,
        int variant,
        int locale_id,
        int output_only,
        unsigned char const *sfx,
        int style_check_only,
        int accepting_mode,
        int priority_adjustment,
        int notify_flag,
        const struct section_problem_data *prob,
        const struct section_language_data *lang,
        int no_db_flag,
        const ej_uuid_t *puuid,
        const ej_uuid_t *p_judge_uuid,
        int store_flags,
        int rejudge_flag,
        int vcs_mode,
        int not_ok_is_cf,
        const struct userlist_user *user,
        struct run_entry *ure)
{
  struct compile_run_extra rx;
  struct compile_request_packet cp;
  void *pkt_buf = 0;
  size_t pkt_len = 0;
  unsigned char pkt_name[64];
  int arch_flags;
  path_t run_arch;
  const struct section_global_data *global = state->global;
  path_t tmp_path, tmp_path_2;
  char *src_header_text = 0, *src_footer_text = 0, *src_text = 0;
  size_t src_header_size = 0, src_footer_size = 0, src_size = 0;
  unsigned char *src_out_text = 0;
  size_t src_out_size = 0;
  int prio = 0;
  char **sc_env_mem = 0;
  char **comp_env_mem = NULL;
  char **comp_env_mem_2 = NULL;
  char **compiler_env_copy = NULL;
  char **compiler_container_options = NULL;
  const unsigned char *compile_src_dir = 0;
  const unsigned char *compile_queue_dir = 0;
  int errcode = -SERVE_ERR_GENERIC;
  struct sformat_extra_data sformat_extra;
  __attribute__((unused)) unsigned char compile_src_buf[PATH_MAX];
  __attribute__((unused)) unsigned char compile_queue_buf[PATH_MAX];
  ej_uuid_t judge_uuid;
  const unsigned char *style_checker_cmd = NULL;
  char **style_checker_env = NULL;
  char **compiler_env = NULL;
  int lang_id = 0;
  unsigned char *custom_compile_cmd = NULL;
  unsigned char *extra_src_dir = NULL;

  if (prob) {
    style_checker_cmd = prob->style_checker_cmd;
    style_checker_env = prob->style_checker_env;
  }
  if (lang) {
    compiler_env = lang->compiler_env;
    lang_id = lang->compile_id;
  }

  memset(&sformat_extra, 0, sizeof(sformat_extra));
  if (!p_judge_uuid || ej_uuid_is_empty(*p_judge_uuid)) {
    ej_uuid_generate(&judge_uuid);
    p_judge_uuid = &judge_uuid;
  }

  // perform substitutions
  compiler_env_copy = prepare_sarray_varsubst(state, prob, lang, NULL, compiler_env);
  compiler_env = compiler_env_copy;

  if (prob->variant_num <= 0 && variant > 0) {
    goto failed;
  }
  if (prob->variant_num > 0) {
    if (variant <= 0) variant = find_variant(state, user_id, prob->id, 0);
    if (variant <= 0) {
      goto failed;
    }
  }

  sformat_extra.locale_id = locale_id;
  sformat_extra.variant = variant;

  if (prob->source_header) {
    sformat_message(tmp_path, sizeof(tmp_path), 0, prob->source_header,
                    global, prob, lang, 0, 0, 0, 0, &sformat_extra);
    if (os_IsAbsolutePath(tmp_path)) {
      snprintf(tmp_path_2, sizeof(tmp_path_2), "%s", tmp_path);
    } else if (global->advanced_layout > 0) {
      get_advanced_layout_path(tmp_path_2, sizeof(tmp_path_2),
                               global, prob, tmp_path, variant);
    } else {
      snprintf(tmp_path_2, sizeof(tmp_path_2), "%s/%s",
               global->statement_dir, tmp_path);
    }
    if (generic_read_file(&src_header_text, 0, &src_header_size, 0, 0,
                          tmp_path_2, "") < 0) {
      errcode = -SERVE_ERR_SRC_HEADER;
      goto failed;
    }
  }
  if (prob->source_footer) {
    sformat_message(tmp_path, sizeof(tmp_path), 0, prob->source_footer,
                    global, prob, lang, 0, 0, 0, 0, &sformat_extra);
    if (os_IsAbsolutePath(tmp_path)) {
      snprintf(tmp_path_2, sizeof(tmp_path_2), "%s", tmp_path);
    } else if (global->advanced_layout > 0) {
      get_advanced_layout_path(tmp_path_2, sizeof(tmp_path_2),
                               global, prob, tmp_path, variant);
    } else {
      snprintf(tmp_path_2, sizeof(tmp_path_2), "%s/%s",
               global->statement_dir, tmp_path);
    }
    if (generic_read_file(&src_footer_text, 0, &src_footer_size, 0, 0,
                          tmp_path_2, "") < 0) {
      errcode = -SERVE_ERR_SRC_FOOTER;
      goto failed;
    }
  }

  if (accepting_mode == -1) accepting_mode = state->accepting_mode;

  if (!state->compile_request_id) state->compile_request_id++;

  if ((!style_checker_cmd || !style_checker_cmd[0]) && lang && lang->style_checker_cmd) {
    style_checker_cmd = lang->style_checker_cmd;
  }

  if (style_checker_cmd && style_checker_cmd[0]) {
    sformat_message(tmp_path, sizeof(tmp_path), 0, style_checker_cmd,
                    global, prob, lang, 0, 0, 0, 0, 0);
    config_var_substitute_buf(tmp_path, sizeof(tmp_path));
    if (os_IsAbsolutePath(tmp_path)) {
      style_checker_cmd = tmp_path;
    } else if (global->advanced_layout > 0) {
      get_advanced_layout_path(tmp_path_2, sizeof(tmp_path_2),
                               global, prob, tmp_path, variant);
      style_checker_cmd = tmp_path_2;
    } else {
      snprintf(tmp_path_2, sizeof(tmp_path_2), "%s/%s",
               global->checker_dir, tmp_path);
      style_checker_cmd = tmp_path_2;
    }
  }

  if (prob && prob->lang_compiler_env && lang) {
    comp_env_mem_2 = filter_lang_environ(config, state, prob, lang, NULL, prob->lang_compiler_env);
  }
  if (prob && lang && prob->lang_compiler_container_options) {
    compiler_container_options = filter_lang_environ(config, state, prob, lang, NULL, prob->lang_compiler_container_options);
  }

  if (compiler_env && compiler_env[0] && comp_env_mem_2 && comp_env_mem_2[0]) {
    comp_env_mem = sarray_merge_pp(compiler_env, comp_env_mem_2);
    compiler_env = comp_env_mem;
  } else if (comp_env_mem_2 && comp_env_mem_2[0]) {
    compiler_env = comp_env_mem_2;
  }

  if (style_checker_env && style_checker_env[0] && lang
      && lang->style_checker_env && lang->style_checker_env[0]) {
    sc_env_mem = sarray_merge_pp(lang->style_checker_env, style_checker_env);
    style_checker_env = sc_env_mem;
  } else if (lang && lang->style_checker_env && lang->style_checker_env[0]) {
    style_checker_env = lang->style_checker_env;
  }

  memset(&cp, 0, sizeof(cp));
  cp.judge_id = state->compile_request_id++;
  cp.judge_uuid = *p_judge_uuid;
  cp.contest_id = contest_id;
  cp.run_id = run_id;
  cp.submit_id = submit_id;
  cp.lang_id = lang_id;
  cp.locale_id = locale_id;
  cp.output_only = output_only;
  get_current_time(&cp.ts1, &cp.ts1_us);
  cp.run_block_len = sizeof(rx);
  cp.run_block = &rx;
  cp.env_num = -1;
  cp.env_vars = (unsigned char**) compiler_env;
  if (compiler_container_options) {
    cp.container_options = compiler_container_options[0];
  }
  cp.style_check_only = !!style_check_only;
  cp.max_vm_size = ~(ej_size64_t) 0;
  cp.max_stack_size = ~(ej_size64_t) 0;
  cp.max_file_size = ~(ej_size64_t) 0;
  cp.use_uuid = 1;
  if (puuid && (puuid->v[0] || puuid->v[1] || puuid->v[2] || puuid->v[3])) {
    cp.uuid = *puuid;
  }
  if (lang) {
    if (lang->max_vm_size > 0) {
      cp.max_vm_size = lang->max_vm_size;
    } else if (global->compile_max_vm_size > 0) {
      cp.max_vm_size = global->compile_max_vm_size;
    }
    if (lang->max_stack_size > 0) {
      cp.max_stack_size = lang->max_stack_size;
    } else if (global->compile_max_stack_size > 0) {
      cp.max_stack_size = global->compile_max_stack_size;
    }
    if (lang->max_file_size > 0) {
      cp.max_file_size = lang->max_file_size;
    } else if (global->compile_max_file_size > 0) {
      cp.max_file_size = global->compile_max_file_size;
    }
    if (lang->max_rss_size > 0) {
      cp.max_rss_size = lang->max_rss_size;
    } else if (global->compile_max_rss_size > 0) {
      cp.max_rss_size = global->compile_max_rss_size;
    }
  }
  if (style_checker_cmd && style_checker_cmd[0]) {
    cp.style_checker = (unsigned char*) style_checker_cmd;
  }
  cp.src_sfx = (unsigned char*) sfx;
  cp.sc_env_num = -1;
  cp.sc_env_vars = (unsigned char**) style_checker_env;
  cp.contest_server_id = config->contest_server_id;

  if (prob->enable_multi_header > 0) {
    unsigned char test_dir[PATH_MAX];
    test_dir[0] = 0;
    if (global->advanced_layout > 0) {
      get_advanced_layout_path(test_dir, sizeof(test_dir), global, prob, DFLT_P_TEST_DIR, variant);
    } else if (variant > 0) {
      snprintf(test_dir, sizeof(test_dir), "%s-%d", prob->test_dir, variant);
    } else {
      snprintf(test_dir, sizeof(test_dir), "%s", prob->test_dir);
    }

    cp.multi_header = 1;
    cp.lang_header = (prob->use_lang_multi_header > 0);
    cp.header_pat = prob->header_pat;
    cp.footer_pat = prob->footer_pat;
    cp.header_dir = test_dir;
    cp.compiler_env_pat = prob->compiler_env_pat;
  }
  if (cp.lang_header) {
    if (lang->multi_header_suffix && lang->multi_header_suffix[0]) {
      cp.lang_short_name = lang->multi_header_suffix;
    } else if (/*lang->short_name &&*/ lang->short_name[0]) {
      cp.lang_short_name = (unsigned char*) lang->short_name;
    }
  }

  if (user) {
    cp.user_id = user->id;
    cp.user_login = user->login;
    if (user->cnts0) {
      cp.exam_cypher = user->cnts0->exam_cypher;
    }
  }

  if (lang && lang->enable_custom > 0 && prob && prob->custom_compile_cmd
      && prob->custom_compile_cmd[0]) {
    custom_compile_cmd = prepare_varsubst(state, prob->custom_compile_cmd, 0, prob, lang, NULL);
    /*
    sformat_message(tmp_path, sizeof(tmp_path), 0, style_checker_cmd,
                    global, prob, lang, 0, 0, 0, 0, 0);
     */
    custom_compile_cmd = config_var_substitute_heap(custom_compile_cmd);
    if (os_IsAbsolutePath(custom_compile_cmd)) {
      // nothing
    } else if (global->advanced_layout > 0) {
      unsigned char tmp[PATH_MAX];
      get_advanced_layout_path(tmp, sizeof(tmp),
                               global, prob, custom_compile_cmd, variant);
      free(custom_compile_cmd);
      custom_compile_cmd = xstrdup(tmp);
    } else {
      char *tmp = NULL;
      __attribute__((unused)) int _;
      _ = asprintf(&tmp, "%s/%s", global->checker_dir, custom_compile_cmd);
      free(custom_compile_cmd);
      custom_compile_cmd = tmp;
    }
    cp.compile_cmd = custom_compile_cmd;
  }

  if (prob && prob->extra_src_dir && prob->extra_src_dir[0]) {
    extra_src_dir = prepare_varsubst(state, prob->extra_src_dir, 0, prob, lang, NULL);
    extra_src_dir = config_var_substitute_heap(extra_src_dir);
    if (os_IsAbsolutePath(extra_src_dir)) {
      // nothing
    } else if (global->advanced_layout > 0) {
      unsigned char tmp[PATH_MAX];
      get_advanced_layout_path(tmp, sizeof(tmp),
                               global, prob, extra_src_dir, variant);
      free(extra_src_dir);
      extra_src_dir = xstrdup(tmp);
    } else {
      char *tmp = NULL;
      __attribute__((unused)) int _;
      _ = asprintf(&tmp, "%s/%s", global->checker_dir, extra_src_dir);
      free(extra_src_dir);
      extra_src_dir = tmp;
    }
    cp.extra_src_dir = extra_src_dir;
  }

  cp.vcs_mode = vcs_mode;
  if (vcs_mode > 0 && prob && prob->vcs_compile_cmd && prob->vcs_compile_cmd[0]) {
    cp.vcs_compile_cmd = prob->vcs_compile_cmd;
  }
  cp.not_ok_is_cf = not_ok_is_cf;
  if (global->preserve_line_numbers > 0 || (lang && lang->preserve_line_numbers > 0)) {
    cp.preserve_numbers = 1;
  }
  cp.enable_remote_cache = (global->enable_remote_cache > 0);

  memset(&rx, 0, sizeof(rx));
  rx.accepting_mode = accepting_mode;
  rx.priority_adjustment = priority_adjustment;
  rx.notify_flag = notify_flag;
  if (lang) {
    rx.is_dos = lang->is_dos;
  }
  rx.rejudge_flag = rejudge_flag;
  rx.not_ok_is_cf = not_ok_is_cf;

  if (compile_request_packet_write(&cp, &pkt_len, &pkt_buf) < 0) {
    // FIXME: need reasonable recovery?
    errcode = -SERVE_ERR_COMPILE_PACKET_WRITE;
    goto failed;
  }

  prio = global->priority_adjustment;
  if (lang) prio += lang->priority_adjustment;
  if (prob) prio += prob->priority_adjustment;
  prio += find_user_priority_adjustment(state, user_id);
  prio += priority_adjustment;
  if (prob && prob->id < EJ_SERVE_STATE_TOTAL_PROBS)
    prio += state->prob_prio[prob->id];

#if defined EJUDGE_COMPILE_SPOOL_DIR
  {
    const unsigned char *compile_spool_dir = EJUDGE_COMPILE_SPOOL_DIR;
    const unsigned char *compile_server_id = NULL;
    if (lang && lang->compile_server_id && lang->compile_server_id[0]) {
      compile_server_id = lang->compile_server_id;
    } else if (global->compile_server_id && global->compile_server_id[0]) {
      compile_server_id = global->compile_server_id;
    } else {
      compile_server_id = config->contest_server_id;
    }

    if (lang && lang->compile_dir_index > 0) {
      compile_src_dir = lang->compile_src_dir;
      compile_queue_dir = lang->compile_queue_dir;
    } else if (lang && lang->compile_dir && lang->compile_dir[0] && global && global->compile_dir && strcmp(lang->compile_dir, global->compile_dir) != 0) {
      compile_src_dir = lang->compile_src_dir;
      compile_queue_dir = lang->compile_queue_dir;
    } else {
      snprintf(compile_src_buf, sizeof(compile_src_buf), "%s/%s/src", compile_spool_dir, compile_server_id);
      compile_src_dir = compile_src_buf;
      snprintf(compile_queue_buf, sizeof(compile_queue_buf), "%s/%s/queue", compile_spool_dir, compile_server_id);
      compile_queue_dir = compile_queue_buf;
    }
  }
#else
  compile_src_dir = global->compile_src_dir;
  if (lang && lang->compile_src_dir && lang->compile_src_dir[0]) {
    compile_src_dir = lang->compile_src_dir;
  }
  compile_queue_dir = global->compile_queue_dir;
  if (lang && lang->compile_queue_dir && lang->compile_queue_dir[0]) {
    compile_queue_dir = lang->compile_queue_dir;
  }
#endif

  if (!sfx) sfx = "";
  serve_packet_name(contest_id, run_id, prio, p_judge_uuid, pkt_name, sizeof(pkt_name));

  if (src_header_size > 0 || src_footer_size > 0) {
    if (len < 0) {
      if (store_flags == STORE_FLAGS_UUID || store_flags == STORE_FLAGS_UUID_BSON) {
        arch_flags = uuid_archive_make_read_path(state, run_arch, sizeof(run_arch),
                                                 puuid, DFLT_R_UUID_SOURCE, 0);
      } else {
        arch_flags = archive_make_read_path(state, run_arch, sizeof(run_arch),
                                            global->run_archive_dir, run_id,0,0);
      }
      if (arch_flags < 0) {
        errcode = -SERVE_ERR_SOURCE_READ;
        goto failed;
      }
      if (generic_read_file(&src_text, 0, &src_size, arch_flags, 0,
                            run_arch, "") < 0) {
        errcode = -SERVE_ERR_SOURCE_READ;
        goto failed;
      }
      str = src_text;
      len = src_size;
    }
    src_out_size = src_header_size + len + src_footer_size;
    src_out_text = (unsigned char*) xmalloc(src_out_size + 1);
    if (src_header_size > 0)
      memcpy(src_out_text, src_header_text, src_header_size);
    if (len > 0)
      memcpy(src_out_text + src_header_size, str, len);
    if (src_footer_size > 0)
      memcpy(src_out_text + src_header_size + len, src_footer_text,
             src_footer_size);
    if (generic_write_file(src_out_text, src_out_size, 0,
                           compile_src_dir, pkt_name, sfx) < 0) {
      errcode = -SERVE_ERR_SOURCE_WRITE;
      goto failed;
    }
  } else if (len < 0) {
    // copy from archive
    if (store_flags == STORE_FLAGS_UUID || store_flags == STORE_FLAGS_UUID_BSON) {
      arch_flags = uuid_archive_make_read_path(state, run_arch, sizeof(run_arch),
                                               puuid, DFLT_R_UUID_SOURCE, 0);
    } else {
      arch_flags = archive_make_read_path(state, run_arch, sizeof(run_arch),
                                          global->run_archive_dir, run_id, 0,0);
    }
    if (arch_flags < 0) {
      errcode = -SERVE_ERR_SOURCE_READ;
      goto failed;
    }
    if (generic_copy_file(arch_flags, 0, run_arch, "",
                          0, compile_src_dir, pkt_name, sfx) < 0) {
      errcode = -SERVE_ERR_SOURCE_WRITE;
      goto failed;
    }
  } else {
    // write from memory
    if (generic_write_file(str, len, 0,
                           compile_src_dir, pkt_name, sfx) < 0) {
      errcode = -SERVE_ERR_SOURCE_WRITE;
      goto failed;
    }
  }

  if (generic_write_file(pkt_buf, pkt_len, SAFE,
                         compile_queue_dir, pkt_name, "") < 0) {
    errcode = -SERVE_ERR_COMPILE_PACKET_WRITE;
    goto failed;
  }

  if (!no_db_flag) {
    if (run_change_status(state->runlog_state, run_id, RUN_COMPILING, 0, 1, -1,
                          cp.judge_id, &cp.judge_uuid, 0, ure) < 0) {
      errcode = -SERVE_ERR_DB;
      goto failed;
    }
    serve_notify_run_update(config, state, ure);
  }

  sarray_free(comp_env_mem_2);
  sarray_free(comp_env_mem);
  sarray_free(compiler_container_options);
  sarray_free(sc_env_mem);
  sarray_free(compiler_env_copy);
  xfree(pkt_buf);
  xfree(src_header_text);
  xfree(src_footer_text);
  xfree(src_text);
  xfree(src_out_text);
  xfree(custom_compile_cmd);
  xfree(extra_src_dir);
  return 0;

 failed:
  sarray_free(comp_env_mem_2);
  sarray_free(comp_env_mem);
  sarray_free(compiler_container_options);
  sarray_free(sc_env_mem);
  sarray_free(compiler_env_copy);
  xfree(pkt_buf);
  xfree(src_header_text);
  xfree(src_footer_text);
  xfree(src_text);
  xfree(src_out_text);
  xfree(custom_compile_cmd);
  xfree(extra_src_dir);
  return errcode;
}

static const unsigned char *
unparse_scoring_system(unsigned char *buf, size_t size, int val);

static int
find_lang_specific_value(
        char **values,
        const struct section_language_data *lang,
        int default_value)
{
  if (!values || !values[0] || !lang /*|| !lang->short_name*/ || !lang->short_name[0]) return default_value;

  size_t lsn = strlen(lang->short_name);
  size_t vl;
  int adj, n;
  unsigned char *sn;
  for (int i = 0; (sn = values[i]); i++) {
    vl = strlen(sn);
    if (vl > lsn + 1
        && !strncmp(sn, lang->short_name, lsn)
        && sn[lsn] == '='
        && sscanf(sn + lsn + 1, "%d%n", &adj, &n) == 1
        && !sn[lsn + 1 + n]) {
      return adj;
    }
  }
  return default_value;
}

static int
find_lang_specific_size(
        char **values,
        const struct section_language_data *lang,
        ej_size64_t *p_size)
{
  if (!values || !values[0] || !lang) return 0;
  if (lang->short_name[0] <= ' ') return 0;

  int lsn = strlen(lang->short_name);
  const unsigned char *sn;
  for (int i = 0; (sn = values[i]); ++i) {
    int vl = strlen(sn);
    if (vl > lsn + 1 && !strncmp(sn, lang->short_name, lsn) && sn[lsn] == '=') {
      return size_str_to_size64_t(sn + lsn + 1, p_size) >= 0;
    }
  }

  return 0;
}

int
serve_run_request(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        FILE *errf,
        const unsigned char *run_text,
        size_t run_size,
        int contest_id,
        int run_id,
        int64_t submit_id,
        int user_id,
        int prob_id,
        int lang_id,
        int variant,
        int priority_adjustment,
        int judge_id,
        const ej_uuid_t *judge_uuid,
        int accepting_mode,
        int notify_flag,
        int mime_type,
        int eoln_type,
        int locale_id,
        const unsigned char *compile_report_dir,
        const struct compile_reply_packet *comp_pkt,
        int no_db_flag,
        ej_uuid_t *puuid,
        int rejudge_flag,
        int zip_mode,
        int store_flags,
        int not_ok_is_cf,
        const unsigned char *inp_text,
        size_t inp_size,
        struct run_entry *ure,
        const unsigned char *src_text,
        size_t src_size)
{
  int cn;
  struct section_global_data *global = state->global;
  struct section_problem_data *prob;
  struct section_language_data *lang = 0;
  const struct section_tester_data *tester = NULL;
  unsigned char *arch = 0, *exe_sfx = "";
  const unsigned char *user_name;
  int prio;
  unsigned char pkt_base[64];
  unsigned char exe_out_name[256];
  unsigned char exe_in_name[256];
  struct teamdb_export te;
  struct userlist_user_info *ui = 0;

  path_t run_exe_dir;
  path_t run_queue_dir;

  struct super_run_in_packet *srp = NULL;
  unsigned char buf[1024];
  unsigned char pathbuf[PATH_MAX];
  int secure_run = 0;
  int suid_run = 0;
  int current_time = 0;
  int current_time_us = 0;
  int time_limit_adj = 0;
  int time_limit_adj_millis = 0;
  struct section_tester_data *refined_tester = NULL;
  FILE *srp_f = NULL;
  char *srp_t = NULL;
  size_t srp_z = 0;
  ej_size64_t lang_specific_size = 0;
  ej_uuid_t local_judge_uuid;
  unsigned char src_name[64];

  get_current_time(&current_time, &current_time_us);

  if (prob_id <= 0 || prob_id > state->max_prob
      || !(prob = state->probs[prob_id])) {
    fprintf(errf, "invalid problem %d", prob_id);
    goto fail;
  }
  if (lang_id > 0) {
    if (lang_id > state->max_lang || !(lang = state->langs[lang_id])) {
      fprintf(errf, "invalid language %d", lang_id);
      goto fail;
    }
  }
  if (no_db_flag) {
    user_name = "";
  } else {
    if (!(user_name = teamdb_get_name(state->teamdb_state, user_id))) {
      fprintf(errf, "invalid user %d", user_id);
      goto fail;
    }
    if (!*user_name) {
      user_name = teamdb_get_login(state->teamdb_state, user_id);
    }
  }

  if (lang) arch = lang->arch;
  if (lang) exe_sfx = lang->exe_sfx;

  if (prob->type == PROB_TYPE_TESTS) {
    switch (mime_type) {
    case MIME_TYPE_APPL_GZIP:
      exe_sfx = ".tar.gz";
      break;
    case MIME_TYPE_APPL_BZIP2:
      exe_sfx = ".tar.bz2";
      break;
    case MIME_TYPE_APPL_COMPRESS:
      exe_sfx = ".tar.Z";
      break;
    case MIME_TYPE_APPL_TAR:
      exe_sfx = ".tar";
      break;
    case MIME_TYPE_APPL_ZIP:
      exe_sfx = ".zip";
      break;
    }
  }

  cn = find_tester(state, prob_id, arch);
  if (cn >= 1 && cn <= state->max_tester) tester = state->testers[cn];
  /*
  if (cn < 1 || cn > state->max_tester || !state->testers[cn]) {
    fprintf(errf, "no appropriate checker for <%s>, <%s>\n",
            prob->short_name, arch);
    goto fail;
  }
  */

  if (cnts && cnts->run_managed) {
    // FIXME: resolve conflict when both prob->super_run_dir and lang->super_run_dir are set
#if defined EJUDGE_RUN_SPOOL_DIR
    {
      const unsigned char *run_server_id = NULL;
      if (prob->super_run_dir && prob->super_run_dir[0]) {
        run_server_id = prob->super_run_dir;
      } else if (lang && lang->super_run_dir && lang->super_run_dir[0]) {
        run_server_id = lang->super_run_dir;
      } else if (global->super_run_dir && global->super_run_dir[0]) {
        run_server_id = global->super_run_dir;
      } else {
        run_server_id = config->contest_server_id;
      }
      snprintf(run_exe_dir, sizeof(run_exe_dir), "%s/%s/exe", EJUDGE_RUN_SPOOL_DIR, run_server_id);
      snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/%s/queue", EJUDGE_RUN_SPOOL_DIR, run_server_id);
    }
#else
    if (prob->super_run_dir && prob->super_run_dir[0]) {
      snprintf(run_exe_dir, sizeof(run_exe_dir), "%s/var/exe", prob->super_run_dir);
      snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/var/queue", prob->super_run_dir);
    } else if (lang && lang->super_run_dir && lang->super_run_dir[0]) {
      snprintf(run_exe_dir, sizeof(run_exe_dir), "%s/var/exe", lang->super_run_dir);
      snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/var/queue", lang->super_run_dir);
    } else if (global->super_run_dir && global->super_run_dir[0]) {
      snprintf(run_exe_dir, sizeof(run_exe_dir), "%s/var/exe", global->super_run_dir);
      snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/var/queue", global->super_run_dir);
    } else {
      snprintf(run_exe_dir, sizeof(run_exe_dir), "%s/super-run/var/exe", EJUDGE_CONTESTS_HOME_DIR);
      snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/super-run/var/queue", EJUDGE_CONTESTS_HOME_DIR);
    }
#endif
  } else if (tester && tester->run_dir && tester->run_dir[0]) {
    snprintf(run_exe_dir, sizeof(run_exe_dir), "%s/exe", tester->run_dir);
    snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/queue", tester->run_dir);
  } else {
    snprintf(run_exe_dir, sizeof(run_exe_dir), "%s/exe", global->run_dir);
    snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/queue", global->run_dir);
  }

  if (prob->variant_num <= 0 && variant > 0) {
    fprintf(errf, "variant is not allowed for this problem\n");
    goto fail;
  }
  if (prob->variant_num > 0) {
    if (variant <= 0) variant = find_variant(state, user_id, prob_id, 0);
    if (variant <= 0) {
      fprintf(errf, "no appropriate variant for <%s>, <%s>\n",
              user_name, prob->short_name);
      goto fail;
    }
  }

  /* calculate a priority */
  prio = global->priority_adjustment;
  if (lang) prio += lang->priority_adjustment;
  prio += prob->priority_adjustment;
  prio += find_user_priority_adjustment(state, user_id);
  if (tester) prio += tester->priority_adjustment;
  prio += priority_adjustment;
  if (prob_id < EJ_SERVE_STATE_TOTAL_PROBS)
    prio += state->prob_prio[prob_id];

  if (judge_id < 0) {
    if (!state->compile_request_id) state->compile_request_id++;
    judge_id = state->compile_request_id++;
  }
  if (!judge_uuid) {
    ej_uuid_generate(&local_judge_uuid);
    judge_uuid = &local_judge_uuid;
  }
  if (accepting_mode < 0) {
    if (global->score_system == SCORE_OLYMPIAD && global->is_virtual > 0) {
      accepting_mode = 1;
    } else {
      accepting_mode = state->accepting_mode;
    }
  }

  secure_run = global->secure_run;
  if (secure_run && prob->disable_security) secure_run = 0;
  if (secure_run && lang && lang->disable_security) secure_run = 0;

  if (!secure_run) {
    if (prob->enable_suid_run > 0) suid_run = 1;
    if (lang && lang->enable_suid_run > 0) suid_run = 1;
  }

  /* generate a packet name */
  serve_packet_name(contest_id, run_id, prio, judge_uuid, pkt_base, sizeof(pkt_base));
  snprintf(exe_out_name, sizeof(exe_out_name), "%s%s", pkt_base, exe_sfx);

  if (!run_text) {
    if (comp_pkt && comp_pkt->use_uuid > 0) {
      if (ej_uuid_is_nonempty(comp_pkt->judge_uuid)) {
        snprintf(exe_in_name, sizeof(exe_in_name), "%s%s",
                 ej_uuid_unparse(&comp_pkt->judge_uuid, NULL), exe_sfx);
      } else {
        snprintf(exe_in_name, sizeof(exe_in_name), "%s%s",
                 ej_uuid_unparse(&comp_pkt->uuid, NULL), exe_sfx);
      }
    } else {
      snprintf(exe_in_name, sizeof(exe_in_name), "%06d%s", run_id, exe_sfx);
    }
    if (generic_copy_file(REMOVE, compile_report_dir, exe_in_name, "",
                          0, run_exe_dir,exe_out_name, "") < 0) {
      fprintf(errf, "copying failed");
      goto fail;
    }
  } else {
    if (generic_write_file(run_text, run_size, 0,
                           run_exe_dir, exe_out_name, "") < 0) {
      fprintf(errf, "writing failed");
      goto fail;
    }
  }

  if (submit_id > 0) {
    if (generic_write_file(inp_text, inp_size, 0,
                           run_exe_dir, pkt_base, ".input") < 0) {
      fprintf(errf, "writing failed");
      goto fail;
    }
  }

  if (!arch) {
    arch = "";
  }

  time_limit_adj_millis = find_lang_specific_value(prob->lang_time_adj_millis, lang, 0);
  time_limit_adj = find_lang_specific_value(prob->lang_time_adj, lang, 0);

  ui = 0;
  if (!no_db_flag) {
    if (teamdb_export_team(state->teamdb_state, user_id, &te) >= 0 && te.user) {
      ui = te.user->cnts0;
    }
  }

  // new run packet creation
  srp = super_run_in_packet_alloc();
  struct super_run_in_global_packet *srgp = srp->global;

  srgp->contest_id = contest_id;
  srgp->judge_id = judge_id;
  srgp->judge_uuid = xstrdup(ej_uuid_unparse(judge_uuid, NULL));
  srgp->run_id = run_id;
  srgp->submit_id = submit_id;
  srgp->variant = variant;
  srgp->user_id = user_id;
  srgp->accepting_mode = accepting_mode;
  srgp->separate_user_score = global->separate_user_score;
  srgp->mime_type = mime_type;
  srgp->score_system = xstrdup(unparse_scoring_system(buf, sizeof(buf), global->score_system));
  srgp->is_virtual = global->is_virtual;
  srgp->notify_flag = notify_flag;
  srgp->advanced_layout = global->advanced_layout;
  srgp->enable_full_archive = global->enable_full_archive;
  srgp->secure_run = secure_run;
  srgp->suid_run = suid_run;
  srgp->enable_container = prob->enable_container;
  if (config->force_container) srgp->enable_container = 1;
  srgp->enable_memory_limit_error = global->enable_memory_limit_error;
  srgp->detect_violations = global->detect_violations;
  srgp->time_limit_retry_count = global->time_limit_retry_count;
  srgp->enable_max_stack_size = global->enable_max_stack_size;
  srgp->priority = prio;
  srgp->arch = xstrdup(arch);
  if (puuid && (puuid->v[0] || puuid->v[1] || puuid->v[2] || puuid->v[3])) {
    srgp->run_uuid = xstrdup(ej_uuid_unparse(puuid, NULL));
  }
  if (comp_pkt) {
    srgp->ts1 = comp_pkt->ts1;
    srgp->ts1_us = comp_pkt->ts1_us;
    srgp->ts2 = comp_pkt->ts2;
    srgp->ts2_us = comp_pkt->ts2_us;
    srgp->ts3 = comp_pkt->ts3;
    srgp->ts3_us = comp_pkt->ts3_us;
  } else {
    srgp->ts1 = current_time;
    srgp->ts1_us = current_time_us;
    srgp->ts2 = current_time;
    srgp->ts2_us = current_time_us;
    srgp->ts3 = current_time;
    srgp->ts3_us = current_time_us;
  }
  srgp->ts4 = current_time;
  srgp->ts4_us = current_time_us;
  srgp->is_dos = 0;
  if (eoln_type == EOLN_CRLF) srgp->is_dos = 1;
  if (lang) {
    srgp->lang_short_name = xstrdup(lang->short_name);
    if (lang->key && lang->key[0]) {
      srgp->lang_key = xstrdup(lang->key);
    }
    if (eoln_type <= 0) srgp->is_dos = lang->is_dos;
  }
  if (!no_db_flag) {
    if (/*te.login &&*/ te.login[0]) {
      srgp->user_login = xstrdup(te.login);
    }
    if (ui && ui->name && ui->name[0]) {
      srgp->user_name = xstrdup(ui->name);
    }
  }
  srgp->max_file_length = global->max_file_length;
  srgp->max_line_length = global->max_line_length;
  srgp->max_cmd_length = global->max_cmd_length;
  if (time_limit_adj_millis > 0) {
    srgp->lang_time_limit_adj_ms = time_limit_adj_millis;
  } else if (time_limit_adj > 0) {
    srgp->lang_time_limit_adj_ms = time_limit_adj * 1000;
  }
  if (exe_sfx) {
    srgp->exe_sfx = xstrdup(exe_sfx);
  }
  if (srgp->judge_uuid && srgp->judge_uuid[0]) {
    srgp->reply_packet_name = xstrdup(srgp->judge_uuid);
  } else if (srgp->run_uuid) {
    srgp->reply_packet_name = xstrdup(srgp->run_uuid);
  } else {
    snprintf(buf, sizeof(buf), "%06d", run_id);
    srgp->reply_packet_name = xstrdup(buf);
  }

#if !defined EJUDGE_RUN_SPOOL_DIR
  if (global->super_run_dir && global->super_run_dir[0]) {
    snprintf(pathbuf, sizeof(pathbuf), "var/%06d/report", contest_id);
    srgp->reply_report_dir = xstrdup(pathbuf);
    snprintf(pathbuf, sizeof(pathbuf), "var/%06d/status", contest_id);
    srgp->reply_spool_dir = xstrdup(pathbuf);
    if (srgp->enable_full_archive > 0) {
      snprintf(pathbuf, sizeof(pathbuf), "var/%06d/output", contest_id);
      srgp->reply_full_archive_dir = xstrdup(pathbuf);
    }
  } else {
    snprintf(pathbuf, sizeof(pathbuf), "%s/%06d/report", global->run_dir, contest_id);
    srgp->reply_report_dir = xstrdup(pathbuf);
    snprintf(pathbuf, sizeof(pathbuf), "%s/%06d/status", global->run_dir, contest_id);
    srgp->reply_spool_dir = xstrdup(pathbuf);
    if (srgp->enable_full_archive > 0) {
      snprintf(pathbuf, sizeof(pathbuf), "%s/%06d/output", global->run_dir, contest_id);
      srgp->reply_full_archive_dir = xstrdup(pathbuf);
    }
  }
#endif
  if (global->checker_locale && global->checker_locale[0]) {
    if (!strcasecmp(global->checker_locale, "user") && locale_id > 0) {
      char buf[64];
      snprintf(buf, sizeof(buf), "%d", locale_id);
      srgp->checker_locale = xstrdup(buf);
    } else {
      srgp->checker_locale = xstrdup(global->checker_locale);
    }
  }
  srgp->rejudge_flag = rejudge_flag;
  srgp->zip_mode = zip_mode;
  srgp->contest_server_id = xstrdup(config->contest_server_id);
  if (submit_id > 0) {
    srgp->bson_available = testing_report_bson_available();
  } else {
    srgp->bson_available = (store_flags == STORE_FLAGS_UUID_BSON);
  }
  if (lang && lang->container_options) {
    srgp->lang_container_options = xstrdup(lang->container_options);
  }
  srgp->not_ok_is_cf = not_ok_is_cf;
  if (comp_pkt) {
    srgp->prepended_size = comp_pkt->prepended_size;
    srgp->cached_on_remote = comp_pkt->cached_on_remote;
  }
  if (lang && lang->clean_up_cmd) {
    srgp->clean_up_cmd = xstrdup(lang->clean_up_cmd);
  }
  if (lang && lang->run_env_file) {
    srgp->run_env_file = xstrdup(lang->run_env_file);
  }
  if (lang && lang->clean_up_env_file) {
    srgp->clean_up_env_file = xstrdup(lang->clean_up_env_file);
  }

  if (prob && prob->enable_src_for_testing > 0 && lang && src_size > 0) {
    srgp->src_sfx = xstrdup(lang->src_sfx);
    random_init();
    snprintf(src_name, sizeof(src_name), "%llx", random_u64());
    if (generic_write_file(src_text, src_size, 0,
                           run_exe_dir, src_name, lang->src_sfx) < 0) {
      fprintf(errf, "failed to save the source file");
      goto fail;
    }
    srgp->src_file = xstrdup(src_name);
  }

  struct super_run_in_problem_packet *srpp = srp->problem;
  srpp->type = xstrdup(problem_unparse_type(prob->type));
  srpp->id = prob->tester_id;
  srpp->check_presentation = prob->check_presentation;
  srpp->scoring_checker = prob->scoring_checker;
  srpp->enable_checker_token = prob->enable_checker_token;
  srpp->interactive_valuer = prob->interactive_valuer;
  srpp->disable_pe = prob->disable_pe;
  srpp->disable_wtl = prob->disable_wtl;
  srpp->wtl_is_cf = prob->wtl_is_cf;
  srpp->use_stdin = prob->use_stdin;
  srpp->use_stdout = prob->use_stdout;
  srpp->combined_stdin = prob->combined_stdin;
  srpp->combined_stdout = prob->combined_stdout;
  srpp->ignore_exit_code = prob->ignore_exit_code;
  srpp->ignore_term_signal = prob->ignore_term_signal;
  srpp->binary_input = prob->binary_input;
  srpp->binary_output = prob->binary_input;
  srpp->real_time_limit_ms = prob->real_time_limit * 1000;
  if (prob->time_limit_millis > 0) {
    srpp->time_limit_ms = prob->time_limit_millis;
  } else if (prob->time_limit > 0) {
    srpp->time_limit_ms = prob->time_limit * 1000;
  }
  srpp->use_ac_not_ok = prob->use_ac_not_ok;
  srpp->full_score = prob->full_score;
  srpp->full_user_score = prob->full_user_score;
  srpp->variable_full_score = prob->variable_full_score;
  srpp->test_score = prob->test_score;
  srpp->use_corr = prob->use_corr;
  srpp->use_info = prob->use_info;
  srpp->use_tgz = prob->use_tgz;
  srpp->tests_to_accept = prob->tests_to_accept;
  srpp->accept_partial = prob->accept_partial;
  srpp->min_tests_to_accept = prob->min_tests_to_accept;
  srpp->checker_real_time_limit_ms = prob->checker_real_time_limit * 1000;
  srpp->checker_time_limit_ms = prob->checker_time_limit_ms;
  srpp->checker_max_vm_size = prob->checker_max_vm_size;
  srpp->checker_max_stack_size = prob->checker_max_stack_size;
  srpp->checker_max_rss_size = prob->checker_max_rss_size;
  srpp->short_name = xstrdup(prob->short_name);
  srpp->long_name = xstrdup2(prob->long_name);
  srpp->internal_name = xstrdup2(prob->internal_name);
  srpp->uuid = xstrdup2(prob->uuid);
  srpp->open_tests = xstrdup2(prob->open_tests);
  srpp->container_options = xstrdup2(prob->container_options);
  if (submit_id > 0) {
    char *inp_name = NULL;
    __attribute__((unused)) int _;
    _ = asprintf(&inp_name, "%s.input", pkt_base);
    srpp->user_input_file = inp_name;
  }

  if (srgp->advanced_layout > 0) {
    get_advanced_layout_path(pathbuf, sizeof(pathbuf), global, prob, NULL, variant);
    srpp->problem_dir = xstrdup(pathbuf);
  }

  if (srgp->advanced_layout > 0) {
    get_advanced_layout_path(pathbuf, sizeof(pathbuf), global, prob, DFLT_P_TEST_DIR, variant);
    srpp->test_dir = xstrdup(pathbuf);
  } else if (variant > 0) {
    snprintf(pathbuf, sizeof(pathbuf), "%s-%d", prob->test_dir, variant);
    srpp->test_dir = xstrdup(pathbuf);
  } else {
    srpp->test_dir = xstrdup(prob->test_dir);
  }
  if (prob->use_corr > 0) {
    if (srgp->advanced_layout > 0) {
      get_advanced_layout_path(pathbuf, sizeof(pathbuf), global, prob, DFLT_P_CORR_DIR, variant);
      srpp->corr_dir = xstrdup(pathbuf);
    } else if (variant > 0) {
      snprintf(pathbuf, sizeof(pathbuf), "%s-%d", prob->corr_dir, variant);
      srpp->corr_dir = xstrdup(pathbuf);
    } else {
      srpp->corr_dir = xstrdup(prob->corr_dir);
    }
  }
  if (prob->use_info > 0) {
    if (srgp->advanced_layout > 0) {
      get_advanced_layout_path(pathbuf, sizeof(pathbuf), global, prob, DFLT_P_INFO_DIR, variant);
      srpp->info_dir = xstrdup(pathbuf);
    } else if (variant > 0) {
      snprintf(pathbuf, sizeof(pathbuf), "%s-%d", prob->info_dir, variant);
      srpp->info_dir = xstrdup(pathbuf);
    } else {
      srpp->info_dir = xstrdup(prob->info_dir);
    }
  }
  if (prob->use_tgz > 0) {
    if (srgp->advanced_layout > 0) {
      get_advanced_layout_path(pathbuf, sizeof(pathbuf), global, prob, DFLT_P_TGZ_DIR, variant);
      srpp->tgz_dir = xstrdup(pathbuf);
    } else if (variant > 0) {
      snprintf(pathbuf, sizeof(pathbuf), "%s-%d", prob->tgz_dir, variant);
      srpp->tgz_dir = xstrdup(pathbuf);
    } else {
      srpp->tgz_dir = xstrdup(prob->tgz_dir);
    }
  }

  srpp->input_file = xstrdup2(prob->input_file);
  srpp->output_file = xstrdup2(prob->output_file);
  srpp->test_score_list = xstrdup2(prob->test_score_list);
  srpp->score_tests = xstrdup2(prob->score_tests);
  srpp->standard_checker = xstrdup2(prob->standard_checker);
  srpp->valuer_sets_marked = prob->valuer_sets_marked;
  if (prob->interactor_time_limit > 0) {
    srpp->interactor_time_limit_ms = prob->interactor_time_limit * 1000;
  }
  if (prob->interactor_real_time_limit > 0) {
    srpp->interactor_real_time_limit_ms = prob->interactor_real_time_limit * 1000;
  }
  srpp->disable_stderr = prob->disable_stderr;
  if (prob->test_pat) {
    srpp->test_pat = xstrdup(prob->test_pat);
  } else if (prob->test_sfx) {
    usprintf(&srpp->test_pat, "%%03d%s", prob->test_sfx);
  } else {
    srpp->test_pat = xstrdup("%03d.dat");
  }
  if (prob->use_corr > 0) {
    if (prob->corr_pat) {
      srpp->corr_pat = xstrdup(prob->corr_pat);
    } else if (prob->corr_sfx) {
      usprintf(&srpp->corr_pat, "%%03d%s", prob->corr_sfx);
    } else {
      srpp->corr_pat = xstrdup("%03d.ans");
    }
  }
  if (prob->use_info > 0) {
    if (prob->info_pat) {
      srpp->info_pat = xstrdup(prob->info_pat);
    } else if (prob->info_sfx) {
      usprintf(&srpp->info_pat, "%%03d%s", prob->info_sfx);
    } else {
      srpp->info_pat = xstrdup("%03d.inf");
    }
  }
  if (prob->use_tgz > 0) {
    if (prob->tgz_pat) {
      srpp->tgz_pat = xstrdup(prob->tgz_pat);
    } else if (prob->tgz_sfx) {
      usprintf(&srpp->tgz_pat, "%%03d%s", prob->tgz_sfx);
    } else {
      srpp->tgz_pat = xstrdup("%03d.tgz");
    }
    if (prob->tgzdir_pat) {
      srpp->tgzdir_pat = xstrdup2(prob->tgzdir_pat);
    } else if (prob->tgzdir_sfx) {
      usprintf(&srpp->tgzdir_pat, "%%03d%s", prob->tgzdir_sfx);
    } else {
      srpp->tgzdir_pat = xstrdup("%03d.dir");
    }
  }
  srpp->test_sets = sarray_copy(prob->test_sets);
  srpp->checker_env = sarray_copy(prob->checker_env);
  srpp->valuer_env = sarray_copy(prob->valuer_env);
  srpp->interactor_env = sarray_copy(prob->interactor_env);
  srpp->test_checker_env = sarray_copy(prob->test_checker_env);
  srpp->test_generator_env = sarray_copy(prob->test_generator_env);
  srpp->init_env = sarray_copy(prob->init_env);
  srpp->start_env = sarray_copy(prob->start_env);
  if (prob->check_cmd && prob->check_cmd[0]) {
    if (os_IsAbsolutePath(prob->check_cmd)) {
      srpp->check_cmd = xstrdup(prob->check_cmd);
    } else {
      if (srgp->advanced_layout > 0) {
        get_advanced_layout_path(pathbuf, sizeof(pathbuf), global, prob, prob->check_cmd, variant);
        srpp->check_cmd = xstrdup(pathbuf);
      } else if (variant > 0) {
        snprintf(pathbuf, sizeof(pathbuf), "%s/%s-%d", global->checker_dir, prob->check_cmd, variant);
        srpp->check_cmd = xstrdup(pathbuf);
      } else {
        snprintf(pathbuf, sizeof(pathbuf), "%s/%s", global->checker_dir, prob->check_cmd);
        srpp->check_cmd = xstrdup(pathbuf);
      }
    }
  }
  if (prob->valuer_cmd && prob->valuer_cmd[0]) {
    if (srgp->advanced_layout > 0) {
      get_advanced_layout_path(pathbuf, sizeof(pathbuf), global, prob, prob->valuer_cmd, variant);
      srpp->valuer_cmd = xstrdup(pathbuf);
    } else if (variant > 0) {
      snprintf(pathbuf, sizeof(pathbuf), "%s-%d", prob->valuer_cmd, variant);
      srpp->valuer_cmd = xstrdup(pathbuf);
    } else {
      srpp->valuer_cmd = xstrdup(prob->valuer_cmd);
    }
  }
  if (prob->interactor_cmd && prob->interactor_cmd[0]) {
    if (srgp->advanced_layout > 0) {
      get_advanced_layout_path(pathbuf, sizeof(pathbuf), global, prob, prob->interactor_cmd, variant);
      srpp->interactor_cmd = xstrdup(pathbuf);
    } else if (variant > 0) {
      snprintf(pathbuf, sizeof(pathbuf), "%s-%d", prob->interactor_cmd, variant);
      srpp->interactor_cmd = xstrdup(pathbuf);
    } else {
      srpp->interactor_cmd = xstrdup(prob->interactor_cmd);
    }
  }
  if (prob->test_checker_cmd && prob->test_checker_cmd[0]) {
    if (srgp->advanced_layout > 0) {
      get_advanced_layout_path(pathbuf, sizeof(pathbuf), global, prob, prob->test_checker_cmd, variant);
      srpp->test_checker_cmd = xstrdup(pathbuf);
    } else if (variant > 0) {
      snprintf(pathbuf, sizeof(pathbuf), "%s-%d", prob->test_checker_cmd, variant);
      srpp->test_checker_cmd = xstrdup(pathbuf);
    } else {
      srpp->test_checker_cmd = xstrdup(prob->test_checker_cmd);
    }
  }
  if (prob->test_generator_cmd && prob->test_generator_cmd[0]) {
    if (global->advanced_layout > 0) {
      get_advanced_layout_path(pathbuf, sizeof(pathbuf), global, prob, prob->test_generator_cmd, variant);
      srpp->test_generator_cmd = xstrdup(pathbuf);
    } else {
      if (os_IsAbsolutePath(prob->test_generator_cmd) && variant > 0) {
        snprintf(pathbuf, sizeof(pathbuf), "%s-%d",
                 prob->test_generator_cmd, variant);
        srpp->test_generator_cmd = xstrdup(pathbuf);
      } else if (os_IsAbsolutePath(prob->test_generator_cmd)) {
        srpp->test_generator_cmd = xstrdup(prob->test_generator_cmd);
      } else if (variant > 0) {
        snprintf(pathbuf, sizeof(pathbuf), "%s/%s-%d",
                 global->checker_dir, prob->test_generator_cmd, variant);
        srpp->test_generator_cmd = xstrdup(pathbuf);
      } else {
        snprintf(pathbuf, sizeof(pathbuf), "%s/%s",
                 global->checker_dir, prob->test_generator_cmd);
        srpp->test_generator_cmd = xstrdup(pathbuf);
      }
    }
  }
  if (prob->init_cmd && prob->init_cmd[0]) {
    if (srgp->advanced_layout > 0) {
      get_advanced_layout_path(pathbuf, sizeof(pathbuf), global, prob, prob->init_cmd, variant);
      srpp->init_cmd = xstrdup(pathbuf);
    } else if (variant > 0) {
      snprintf(pathbuf, sizeof(pathbuf), "%s-%d", prob->init_cmd, variant);
      srpp->init_cmd = xstrdup(pathbuf);
    } else {
      srpp->init_cmd = xstrdup(prob->init_cmd);
    }
  }
  if (prob->start_cmd && prob->start_cmd[0]) {
    if (srgp->advanced_layout > 0) {
      get_advanced_layout_path(pathbuf, sizeof(pathbuf), global, prob, prob->start_cmd, variant);
      srpp->start_cmd = xstrdup(pathbuf);
    } else if (variant > 0) {
      snprintf(pathbuf, sizeof(pathbuf), "%s-%d", prob->start_cmd, variant);
      srpp->start_cmd = xstrdup(pathbuf);
    } else {
      srpp->start_cmd = xstrdup(prob->start_cmd);
    }
  }
  if (prob->solution_cmd && prob->solution_cmd[0]) {
    if (srgp->advanced_layout > 0) {
      get_advanced_layout_path(pathbuf, sizeof(pathbuf), global, prob, prob->solution_cmd, variant);
      srpp->solution_cmd = xstrdup(pathbuf);
    } else if (variant > 0) {
      snprintf(pathbuf, sizeof(pathbuf), "%s-%d", prob->solution_cmd, variant);
      srpp->solution_cmd = xstrdup(pathbuf);
    } else {
      srpp->solution_cmd = xstrdup(prob->solution_cmd);
    }
  }
  srpp->max_vm_size = prob->max_vm_size;
  srpp->max_data_size = prob->max_data_size;
  srpp->max_stack_size = prob->max_stack_size;
  srpp->max_rss_size = prob->max_rss_size;
  srpp->max_core_size = prob->max_core_size;
  srpp->max_file_size = prob->max_file_size;
  srpp->max_open_file_count = prob->max_open_file_count;
  srpp->max_process_count = prob->max_process_count;
  srpp->enable_process_group = prob->enable_process_group;
  srpp->enable_kill_all = prob->enable_kill_all;
  srgp->testlib_mode = prob->enable_testlib_mode;
  srpp->enable_extended_info = prob->enable_extended_info;
  srpp->stop_on_first_fail = prob->stop_on_first_fail;
  srpp->enable_control_socket = prob->enable_control_socket;
  srpp->copy_exe_to_tgzdir = prob->copy_exe_to_tgzdir;
  if (prob->umask && prob->umask[0]) {
    srpp->umask = xstrdup(prob->umask);
  }
  srpp->test_count = test_count_cache_get(NULL, srpp->test_dir, srpp->test_pat);

  if (find_lang_specific_size(prob->lang_max_vm_size, lang, &lang_specific_size) > 0) {
    srpp->max_vm_size = lang_specific_size;
  }
  if (find_lang_specific_size(prob->lang_max_stack_size, lang, &lang_specific_size) > 0) {
    srpp->max_stack_size = lang_specific_size;
  }
  if (find_lang_specific_size(prob->lang_max_rss_size, lang, &lang_specific_size) > 0) {
    srpp->max_rss_size = lang_specific_size;
  }
  if (lang && lang->run_max_stack_size > 0) {
    srpp->max_stack_size = lang->run_max_stack_size;
  }
  if (lang && lang->run_max_vm_size > 0) {
    srpp->max_vm_size = lang->run_max_vm_size;
  }
  if (lang && lang->run_max_rss_size > 0) {
    srpp->max_rss_size = lang->run_max_rss_size;
  }
  srpp->checker_extra_files = sarray_copy(prob->checker_extra_files);
  if (lang && lang->enable_ejudge_env > 0) {
    srgp->enable_ejudge_env = lang->enable_ejudge_env;
  }
  if (prob->disable_vm_size_limit > 0) {
    srpp->disable_vm_size_limit = 1;
  }

  if (tester) {
    struct super_run_in_tester_packet *srtp = srp->tester;

    if (tester->any) {
      refined_tester = prepare_alloc_tester();
      prepare_tester_refinement(state, refined_tester, cn, prob->id);
      tester = refined_tester;
    }

    srtp->name = xstrdup(tester->name);
    srtp->is_dos = tester->is_dos;
    srtp->no_redirect = tester->no_redirect;
    srtp->priority_adjustment = tester->priority_adjustment;
    srtp->arch = xstrdup(tester->arch);
    srtp->key = xstrdup2(tester->key);
    srtp->memory_limit_type = xstrdup2(tester->memory_limit_type);
    srtp->secure_exec_type = xstrdup2(tester->secure_exec_type);
    srtp->no_core_dump = tester->no_core_dump;
    srtp->enable_memory_limit_error = tester->enable_memory_limit_error;
    srtp->kill_signal = xstrdup2(tester->kill_signal);
    srtp->clear_env = tester->clear_env;
    srtp->enable_ejudge_env = tester->enable_ejudge_env;
    if (tester->time_limit_adj_millis > 0) {
      srtp->time_limit_adjustment_ms = tester->time_limit_adj_millis;
    } else if (tester->time_limit_adjustment > 0) {
      srtp->time_limit_adjustment_ms = tester->time_limit_adjustment;
    }
    srtp->errorcode_file = xstrdup2(tester->errorcode_file);
    srtp->error_file = xstrdup2(tester->error_file);
    srtp->prepare_cmd = xstrdup2(tester->prepare_cmd);
    srtp->start_cmd = xstrdup2(tester->start_cmd);
    srtp->start_env = sarray_copy(tester->start_env);
  } else {
    super_run_in_packet_free_tester(srp);
  }

  super_run_in_packet_set_default(srp);

  srp_f = open_memstream(&srp_t, &srp_z);
  super_run_in_packet_unparse_cfg(srp_f, srp);
  fclose(srp_f); srp_f = NULL;

  if (generic_write_file(srp_t, srp_z, SAFE, run_queue_dir, pkt_base, "") < 0) {
    fprintf(errf, "failed to write run packet\n");
    goto fail;
  }
  xfree(srp_t); srp_t = NULL;

  /* update status */
  if (!no_db_flag) {
    if (run_change_status(state->runlog_state, run_id, RUN_RUNNING, 0, 1, -1,
                          judge_id, judge_uuid, 0, ure) < 0) {
      goto fail;
    }
    serve_notify_run_update(config, state, ure);
  }

  prepare_tester_free(refined_tester);
  super_run_in_packet_free(srp);
  return 0;

fail:
  if (srp_f) fclose(srp_f);
  xfree(srp_t);
  prepare_tester_free(refined_tester);
  super_run_in_packet_free(srp);
  return -1;
}

void
serve_send_clar_notify_telegram(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        int user_id,
        const unsigned char *user_name,
        const unsigned char *subject,
        const unsigned char *text)
{
  const unsigned char *args[10];
  char *text_s = NULL;
  size_t text_z = 0;
  FILE *text_f = NULL;

  if (!cnts->telegram_admin_chat_id || !cnts->telegram_admin_chat_id[0])
    return;

  const unsigned char *telegram_bot_id = cnts->telegram_bot_id;
  if (telegram_bot_id && !*telegram_bot_id) telegram_bot_id = NULL;
  if (!telegram_bot_id) telegram_bot_id = ejudge_cfg_get_telegram_bot_id(config, NULL);
  if (!telegram_bot_id) return;

  text_f = open_memstream(&text_s, &text_z);
  fprintf(text_f, "New clar\n"
          "Contest: %d (%s)\n"
          "User: %d (%s)\n"
          "Subject: %s\n"
          "%s\n",
          cnts->id, cnts->name, user_id, user_name, subject, text);
  fclose(text_f); text_f = NULL;

  args[0] = "telegram";
  args[1] = telegram_bot_id;
  args[2] = cnts->telegram_admin_chat_id;
  args[3] = text_s;
  args[4] = NULL;
  send_job_packet(config, (unsigned char**) args);

  free(text_s); text_s = NULL;
}

void
serve_send_telegram_token(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        int locale_id,
        int user_id,
        const unsigned char *user_login,
        const unsigned char *user_name,
        const unsigned char *telegram_token,
        time_t expiry_time)
{
  const unsigned char *args[10];
  char user_id_buf[64];
  char contest_id_buf[64];
  char locale_id_buf[64];
  char expiry_buf[64];

  const unsigned char *telegram_bot_id = cnts->telegram_bot_id;
  if (telegram_bot_id && !*telegram_bot_id) telegram_bot_id = NULL;
  if (!telegram_bot_id) telegram_bot_id = ejudge_cfg_get_telegram_bot_id(config, NULL);
  if (!telegram_bot_id) return;

  if (!user_login) return;
  if (!user_name) user_name = user_login;
  if (!telegram_token) return;

  snprintf(user_id_buf, sizeof(user_id_buf), "%d", user_id);
  snprintf(contest_id_buf, sizeof(contest_id_buf), "%d", cnts->id);
  if (expiry_time <= 0) expiry_time = time(NULL) + 300;
  snprintf(expiry_buf, sizeof(expiry_buf), "%s", xml_unparse_date(expiry_time));
  snprintf(locale_id_buf, sizeof(locale_id_buf), "%d", locale_id);

  args[0] = "telegram_token";
  args[1] = telegram_bot_id;
  args[2] = locale_id_buf;
  args[3] = user_id_buf;
  args[4] = user_login;
  args[5] = user_name;
  args[6] = telegram_token;
  args[7] = contest_id_buf;
  args[8] = expiry_buf;
  args[9] = NULL;
  send_job_packet(config, (unsigned char**) args);
}

void
serve_send_clar_notify_email(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        int user_id,
        const unsigned char *user_name,
        const unsigned char *subject,
        const unsigned char *text)
{
  unsigned char esubj[1024];
  FILE *fmsg = 0;
  char *ftxt = 0;
  size_t flen = 0;
  const unsigned char *originator = 0;
  const unsigned char *mail_args[7];

  if (!state || !cnts || !cnts->clar_notify_email) return;

  snprintf(esubj, sizeof(esubj), "New clar request in contest %d", cnts->id);
  originator = serve_get_email_sender(config, cnts);
  fmsg = open_memstream(&ftxt, &flen);
  fprintf(fmsg, "Hello,\n\nNew clarification request is received\n"
          "Contest: %d (%s)\n"
          "User: %d (%s)\n"
          "Subject: %s\n\n"
          "%s\n\n-\n"
          "Regards,\n"
          "the ejudge contest management system\n",
          cnts->id, cnts->name, user_id, user_name, subject, text);
  close_memstream(fmsg); fmsg = 0;
  mail_args[0] = "mail";
  mail_args[1] = "";
  mail_args[2] = esubj;
  mail_args[3] = originator;
  mail_args[4] = cnts->clar_notify_email;
  mail_args[5] = ftxt;
  mail_args[6] = 0;
  send_job_packet(config, (unsigned char**) mail_args);
  xfree(ftxt); ftxt = 0;
}

void
serve_telegram_notify_on_submit(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const serve_state_t cs,
        int run_id,
        const struct run_entry *re,
        int new_status)
{
  if (!cnts) return;
  if (!cnts->telegram_admin_chat_id || !*cnts->telegram_admin_chat_id) return;

  const unsigned char *telegram_bot_id = cnts->telegram_bot_id;
  if (telegram_bot_id && !*telegram_bot_id) telegram_bot_id = NULL;
  if (!telegram_bot_id) telegram_bot_id = ejudge_cfg_get_telegram_bot_id(config, NULL);
  if (!telegram_bot_id) return;

  const unsigned char *args[11];
  unsigned char buf1[64];
  unsigned char buf2[64];
  unsigned char buf3[64];
  unsigned char buf4[64];
  const unsigned char *name = "";
  const unsigned char *probname = "";

  args[0] = "telegram_notify";
  args[1] = telegram_bot_id;
  args[2] = cnts->telegram_admin_chat_id;
  snprintf(buf1, sizeof(buf1), "%d", cnts->id);
  args[3] = buf1;
  args[4] = cnts->name;
  if (!args[4]) args[4] = "";
  snprintf(buf2, sizeof(buf2), "%d", run_id);
  args[5] = buf2;
  buf3[0] = 0;
  if (re) {
    snprintf(buf3, sizeof(buf3), "%d", re->user_id);
  }
  args[6] = buf3;
  if (re) {
    name = teamdb_get_name_2(cs->teamdb_state, re->user_id);
    if (!name) name = "";
  }
  args[7] = name;
  if (re && re->prob_id > 0 && re->prob_id <= cs->max_prob && cs->probs[re->prob_id]) {
    probname = cs->probs[re->prob_id]->short_name;
  }
  args[8] = probname;
  args[9] = run_status_str(new_status, buf4, sizeof(buf4), 0, 0);
  args[10] = NULL;
  send_job_packet(config, (unsigned char **) args);
}

void
serve_telegram_check_failed(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const serve_state_t cs,
        int run_id,
        const struct run_entry *re)
{
  if (!cnts) return;
  if (!cnts->telegram_admin_chat_id || !*cnts->telegram_admin_chat_id) return;

  const unsigned char *telegram_bot_id = cnts->telegram_bot_id;
  if (telegram_bot_id && !*telegram_bot_id) telegram_bot_id = NULL;
  if (!telegram_bot_id) telegram_bot_id = ejudge_cfg_get_telegram_bot_id(config, NULL);
  if (!telegram_bot_id) return;

  const unsigned char *args[10];
  unsigned char buf1[64];
  unsigned char buf2[64];
  unsigned char buf3[64];
  const unsigned char *name = "";
  const unsigned char *probname = "";

  args[0] = "telegram_cf";
  args[1] = telegram_bot_id;
  args[2] = cnts->telegram_admin_chat_id;
  snprintf(buf1, sizeof(buf1), "%d", cnts->id);
  args[3] = buf1;
  args[4] = cnts->name;
  if (!args[4]) args[4] = "";
  snprintf(buf2, sizeof(buf2), "%d", run_id);
  args[5] = buf2;
  buf3[0] = 0;
  if (re) {
    snprintf(buf3, sizeof(buf3), "%d", re->user_id);
  }
  args[6] = buf3;
  if (re) {
    name = teamdb_get_name_2(cs->teamdb_state, re->user_id);
    if (!name) name = "";
  }
  args[7] = name;
  if (re && re->prob_id > 0 && re->prob_id <= cs->max_prob && cs->probs[re->prob_id]) {
    probname = cs->probs[re->prob_id]->short_name;
  }
  args[8] = probname;
  args[9] = NULL;
  send_job_packet(config, (unsigned char **) args);
}

void
serve_send_check_failed_email(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        int run_id)
{
  unsigned char esubj[1024];
  const unsigned char *originator = 0;
  FILE *fmsg = 0;
  char *ftxt = 0;
  size_t flen = 0;
  const unsigned char *mail_args[7];

  if (!cnts->cf_notify_email) return;

  snprintf(esubj, sizeof(esubj), "Check failed in contest %d", cnts->id);
  originator = serve_get_email_sender(config, cnts);

  fmsg = open_memstream(&ftxt, &flen);
  fprintf(fmsg, "Hello,\n\nRun evaluation got \"Check failed\"!\n"
          "Contest: %d (%s)\n"
          "Run Id: %d\n\n-\n"
          "Regards,\n"
          "the ejudge contest management system\n",
          cnts->id, cnts->name, run_id);
  close_memstream(fmsg); fmsg = 0;
  mail_args[0] = "mail";
  mail_args[1] = "";
  mail_args[2] = esubj;
  mail_args[3] = originator;
  mail_args[4] = cnts->cf_notify_email;
  mail_args[5] = ftxt;
  mail_args[6] = 0;
  send_job_packet(config, (unsigned char **) mail_args);
  xfree(ftxt); ftxt = 0;
}

void
serve_send_email_to_user(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const serve_state_t cs,
        int user_id,
        const unsigned char *subject,
        const unsigned char *text)
{
  const struct userlist_user *u = 0;
  const unsigned char *originator = 0;
  const unsigned char *mail_args[7];

  if (!(u = teamdb_get_userlist(cs->teamdb_state, user_id))) return;
  if (!is_valid_email_address(u->email)) return;

  originator = serve_get_email_sender(config, cnts);

  mail_args[0] = "mail";
  mail_args[1] = "";
  mail_args[2] = subject;
  mail_args[3] = originator;
  mail_args[4] = u->email;
  mail_args[5] = text;
  mail_args[6] = 0;
  send_job_packet(config, (unsigned char**) mail_args);
}

void
serve_telegram_user_run_reviewed(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const serve_state_t cs,
        int user_id,
        int run_id,
        int new_status)
{
  const unsigned char *telegram_bot_id = cnts->telegram_bot_id;
  if (telegram_bot_id && !*telegram_bot_id) telegram_bot_id = NULL;
  if (!telegram_bot_id) telegram_bot_id = ejudge_cfg_get_telegram_bot_id(config, NULL);
  if (!telegram_bot_id) return;

  const unsigned char *args[10];
  unsigned char buf1[64];
  unsigned char buf2[64];
  unsigned char buf3[64];
  unsigned char buf4[128];

  args[0] = "telegram_reviewed";
  args[1] = telegram_bot_id;
  snprintf(buf1, sizeof(buf1), "%d", cnts->id);
  args[2] = buf1;
  args[3] = cnts->name;
  if (!args[3]) args[3] = "";
  snprintf(buf2, sizeof(buf2), "%d", user_id);
  args[4] = buf2;
  args[5] = teamdb_get_login(cs->teamdb_state, user_id);
  args[6] = teamdb_get_name_2(cs->teamdb_state, user_id);
  snprintf(buf3, sizeof(buf3), "%d", run_id);
  args[7] = buf3;
  if (new_status < 0) {
    args[8] = "unchanged";
  } else {
    args[8] = run_status_str(new_status, buf4, sizeof(buf4), 0, 0);
  }
  args[9] = NULL;
  send_job_packet(config, (unsigned char **) args);
}

void
serve_telegram_user_clar_replied(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const serve_state_t cs,
        int user_id,
        int clar_id,
        const unsigned char *reply)
{
  const unsigned char *telegram_bot_id = cnts->telegram_bot_id;
  if (telegram_bot_id && !*telegram_bot_id) telegram_bot_id = NULL;
  if (!telegram_bot_id) telegram_bot_id = ejudge_cfg_get_telegram_bot_id(config, NULL);
  if (!telegram_bot_id) return;

  const unsigned char *args[10];
  unsigned char buf1[64];
  unsigned char buf2[64];
  unsigned char buf3[64];

  args[0] = "telegram_replied";
  args[1] = telegram_bot_id;
  snprintf(buf1, sizeof(buf1), "%d", cnts->id);
  args[2] = buf1;
  args[3] = cnts->name;
  if (!args[3]) args[3] = "";
  snprintf(buf2, sizeof(buf2), "%d", user_id);
  args[4] = buf2;
  args[5] = teamdb_get_login(cs->teamdb_state, user_id);
  args[6] = teamdb_get_name_2(cs->teamdb_state, user_id);
  snprintf(buf3, sizeof(buf3), "%d", clar_id);
  args[7] = buf3;
  args[8] = reply;
  args[9] = NULL;
  send_job_packet(config, (unsigned char **) args);
}

void
serve_telegram_registered(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        long long chat_id,
        const char *login_str,
        const char *password_str,
        const char *error_message)
{
  const unsigned char *telegram_bot_id = cnts->telegram_bot_id;
  if (telegram_bot_id && !*telegram_bot_id) telegram_bot_id = NULL;
  if (!telegram_bot_id) telegram_bot_id = ejudge_cfg_get_telegram_bot_id(config, NULL);
  if (!telegram_bot_id) return;

  const unsigned char *args[10];
  unsigned char buf1[64];
  unsigned char buf2[64];

  args[0] = "telegram_registered";
  args[1] = telegram_bot_id;
  snprintf(buf2, sizeof(buf2), "%lld", chat_id);
  args[2] = buf2;
  snprintf(buf1, sizeof(buf1), "%d", cnts->id);
  args[3] = buf1;
  args[4] = cnts->name;
  if (!login_str) login_str = "";
  args[5] = login_str;
  if (!password_str) password_str = "";
  args[6] = password_str;
  if (!error_message) error_message = "";
  args[7] = error_message;
  args[8] = NULL;
  send_job_packet(config, (unsigned char **) args);
}

void
serve_notify_user_run_status_change(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const serve_state_t cs,
        int user_id,
        int run_id,
        int new_status)
{
  unsigned char nsubj[1024];
  FILE *msg_f = 0;
  char *msg_t = 0;
  size_t msg_z = 0;

  // FIXME: do not send a notification if the user is online?

  if (cnts->default_locale_num > 0)
    l10n_setlocale(cnts->default_locale_num);
  snprintf(nsubj, sizeof(nsubj),
           _("Status of your submit %d is changed in contest %d"),
           run_id, cnts->id);
  msg_f = open_memstream(&msg_t, &msg_z);
  fprintf(msg_f, _("Status of your submit is changed\n"));
  fprintf(msg_f, _("Contest: %d (%s)\n"), cnts->id, cnts->name);
  fprintf(msg_f, "Run Id: %d\n", run_id);
  fprintf(msg_f, _("New status: %s\n"),
          run_status_str(new_status, 0, 0, 0, 0));
  if (cnts->team_url) {
    fprintf(msg_f, "URL: %s?contest_id=%d&login=%s\n", cnts->team_url,
            cnts->id, teamdb_get_login(cs->teamdb_state, user_id));
  }
  fprintf(msg_f, "\n-\nRegards,\nthe ejudge contest management system (www.ejudge.ru)\n");
  close_memstream(msg_f); msg_f = 0;
  if (cnts->default_locale_num > 0) {
    l10n_setlocale(cnts->default_locale_num);
  }
  serve_send_email_to_user(config, cnts, cs, user_id, nsubj, msg_t);
  xfree(msg_t); msg_t = 0; msg_z = 0;
}

static void
notify_submit_update(
        const struct ejudge_cfg *config,
        struct submit_entry *se,
        testing_report_xml_t tr)
{
  if (!se->notify_driver) return;

  struct notify_plugin_data *np = notify_plugin_get(config, se->notify_driver);
  if (!np) {
    err("notify_submit_update: failed to get notify_plugin %d",
        se->notify_driver);
    return;
  }
  if (se->notify_kind < 0 || se->notify_kind >= MIXED_ID_LAST) {
    err("notify_submit_update: invalid se.notify_kind %d", se->notify_kind);
    return;
  }
  if (!se->notify_kind) return;

  unsigned char buf[64];
  mixed_id_marshall(buf, se->notify_kind, &se->notify_queue);

  cJSON *jr = cJSON_CreateObject();

  struct timeval tv;
  gettimeofday(&tv, NULL);
  long long server_time_us = tv.tv_sec * 1000000LL + tv.tv_usec;

  cJSON_AddNumberToObject(jr, "server_time_us", (double) server_time_us);
  cJSON_AddStringToObject(jr, "type", "submit");
  cJSON_AddItemToObject(jr, "submit", json_serialize_submit(se, tr));
  char *jrstr = cJSON_PrintUnformatted(jr);
  cJSON_Delete(jr);

  if (np->vt->notify(np, buf, jrstr) < 0) {
    err("notify_submit_update: notify failed");
  }
  free(jrstr);
}

void
serve_notify_run_update(
        const struct ejudge_cfg *config,
        serve_state_t cs,
        const struct run_entry *re)
{
  if (!re) return;
  if (!re->notify_driver) return;

  struct notify_plugin_data *np = notify_plugin_get(config, re->notify_driver);
  if (!np) {
    err("notify_run_update: failed to get notify_plugin %d",
        re->notify_driver);
    return;
  }
  if (re->notify_kind < 0 || re->notify_kind >= MIXED_ID_LAST) {
    err("notify_run_update: invalid se.notify_kind %d", re->notify_kind);
    return;
  }
  if (!re->notify_kind) return;

  unsigned char buf[64];
  mixed_id_marshall(buf, re->notify_kind, &re->notify_queue);

  cJSON *jr = cJSON_CreateObject();

  struct timeval tv;
  gettimeofday(&tv, NULL);
  long long server_time_us = tv.tv_sec * 1000000LL + tv.tv_usec;

  cJSON_AddNumberToObject(jr, "server_time_us", (double) server_time_us);
  cJSON_AddStringToObject(jr, "type", "run");
  cJSON_AddItemToObject(jr, "run", json_serialize_run(cs, re));
  char *jrstr = cJSON_PrintUnformatted(jr);
  cJSON_Delete(jr);

  if (np->vt->notify(np, buf, jrstr) < 0) {
    err("notify_submit_update: notify failed");
  }
  free(jrstr);
}

static void
read_compile_packet_input(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        serve_state_t cs,
        const struct contest_desc *cnts,
        const unsigned char *compile_report_dir,
        const unsigned char *pname,
        const struct compile_reply_packet *comp_pkt)
{
  struct submit_entry se = {};
  int r;
  char *txt_text = NULL;
  size_t txt_size = 0;
  testing_report_xml_t tr = NULL;
  int mime_type = 0;
  struct storage_entry rep_se = {};
  char *run_text = NULL;
  size_t run_size = 0;
  struct storage_entry inp_se = {};
  struct storage_entry src_se = {};

  info("read_compile_packet_input: submit_id %lld", (long long) comp_pkt->submit_id);

  if (ej_uuid_is_empty(comp_pkt->judge_uuid)) {
    err("read_compile_packet_input: judge_uuid is empty");
    goto done;
  }

  if (!cs->storage_state) {
    cs->storage_state = storage_plugin_get(extra, cnts, ejudge_config, NULL);
    if (!cs->storage_state) {
      err("read_compile_packet_input: storage plugin not available");
      goto done;
    }
  }
  if (!cs->submit_state) {
    cs->submit_state = submit_plugin_open(ejudge_config, cnts, cs, NULL, 0);
    if (!cs->submit_state) {
      err("read_compile_packet_input: submit plugin not available");
      goto done;
    }
  }

  r = cs->submit_state->vt->fetch(cs->submit_state, comp_pkt->submit_id, &se);
  if (r < 0) {
    err("read_compile_packet_input: fetch failed");
    goto done;
  }
  if (!r) {
    err("read_compile_packet_input: submit %lld not found", (long long) comp_pkt->submit_id);
    goto done;
  }

  if (se.contest_id != cnts->id) {
    err("read_compile_packet_input: contest_id mismatch: read %d", se.contest_id);
    goto done;
  }
  if (se.status != RUN_COMPILING) {
    err("read_compile_packet_input: submit_entry status not COMPILING");
    goto done;
  }
  if (memcmp(&se.judge_uuid, &comp_pkt->judge_uuid, 16) != 0) {
    unsigned char buf1[64], buf2[64];
    err("read_compile_packet_input: judge_uuid mismatch: submit_entry: %s, compile_packet: %s",
        ej_uuid_unparse_r(buf1, sizeof(buf1), &se.judge_uuid, NULL),
        ej_uuid_unparse_r(buf2, sizeof(buf2), &comp_pkt->judge_uuid, NULL));
    goto done;
  }
  if (comp_pkt->status != RUN_OK
      && comp_pkt->status != RUN_COMPILE_ERR
      && comp_pkt->status != RUN_STYLE_ERR
      && comp_pkt->status != RUN_CHECK_FAILED) {
    err("read_compile_packet_input: invalid compile packet status %d", comp_pkt->status);
    goto done;
  }

  // account compile time
  if (metrics.data) {
    long long ts2 = comp_pkt->ts2 * 1000LL + comp_pkt->ts2_us / 1000;
    long long ts3 = comp_pkt->ts3 * 1000LL + comp_pkt->ts3_us / 1000;
    if (ts3 > ts2) {
      metrics.data->total_compile_time_ms += (ts3 - ts2);
    }
  }

  if (comp_pkt->status == RUN_COMPILE_ERR
      || comp_pkt->status == RUN_STYLE_ERR
      || comp_pkt->status == RUN_CHECK_FAILED) {
    r = generic_read_file(&txt_text, 0, &txt_size, REMOVE, compile_report_dir, pname, ".txt");
    if (r < 0) {
      err("read_compile_packet_input: failed to read compiler output");
      txt_text = xstrdup("");
      txt_size = 0;
    }
    if (!txt_text) {
      txt_text = xstrdup("");
      txt_size = 0;
    }
    tr = testing_report_alloc(se.contest_id, 0, 0, &se.judge_uuid);
    tr->scoring_system = 0;
    tr->submit_id = se.serial_id;
    tr->status = comp_pkt->status;
    tr->compiler_output = txt_text;
    txt_text = NULL; txt_size = 0;
    utf8_fix_string(tr->compiler_output, NULL);
    tr->compile_error = 1;
    if (testing_report_bson_available()) {
      testing_report_to_mem_bson(&txt_text, &txt_size, tr);
      mime_type = MIME_TYPE_BSON;
    } else {
      testing_report_to_str(&txt_text, &txt_size, 1, tr);
    }

    r = cs->storage_state->vt->insert(cs->storage_state, 0, mime_type, txt_size, txt_text, &rep_se);
    if (r < 0) {
      err("read_compile_packet_input: failed to store the report");
      goto done;
    }

    cs->submit_state->vt->change_status(cs->submit_state,
                                        se.serial_id,
                                        SUBMIT_FIELD_STATUS | SUBMIT_FIELD_PROTOCOL_ID | SUBMIT_FIELD_JUDGE_UUID,
                                        comp_pkt->status,
                                        rep_se.serial_id,
                                        NULL,
                                        &se);
    notify_submit_update(config, &se, tr);
    goto done;
  }

  // compiled successfully
  r = generic_read_file(&txt_text, 0, &txt_size, REMOVE, compile_report_dir, pname, ".txt");
  if (r < 0) {
  }
  if (txt_text && !*txt_text) {
    free(txt_text); txt_text = NULL;
    txt_size = 0;
  }

  // do not store empty compiler output
  unsigned flags = SUBMIT_FIELD_STATUS;
  if (txt_size > 0) {
    tr = testing_report_alloc(se.contest_id, 0, 0, &se.judge_uuid);
    tr->scoring_system = 0;
    tr->submit_id = se.serial_id;
    tr->status = RUN_COMPILED;
    tr->compiler_output = txt_text;
    txt_text = NULL; txt_size = 0;
    utf8_fix_string(tr->compiler_output, NULL);
    tr->compile_error = 1;
    if (testing_report_bson_available()) {
      testing_report_to_mem_bson(&txt_text, &txt_size, tr);
      mime_type = MIME_TYPE_BSON;
    } else {
      testing_report_to_str(&txt_text, &txt_size, 1, tr);
    }

    r = cs->storage_state->vt->insert(cs->storage_state, 0, mime_type, txt_size, txt_text, &rep_se);
    if (r < 0) {
      err("read_compile_packet_input: failed to store the report");
      goto done;
    }
    flags |= SUBMIT_FIELD_PROTOCOL_ID;
    se.protocol_id = rep_se.serial_id;
  }
  r = cs->submit_state->vt->change_status(cs->submit_state,
                                          se.serial_id,
                                          flags,
                                          RUN_COMPILED,
                                          se.protocol_id,
                                          NULL, NULL);
  if (r < 0) {
    err("read_compile_packet_input: failed to change status");
    goto done;
  }

  const unsigned char *exe_sfx = "";
  const struct section_language_data *lang = NULL;
  if (se.lang_id >= 0 && se.lang_id <= cs->max_lang) {
    lang = cs->langs[se.lang_id];
  }
  if (lang) {
    exe_sfx = lang->exe_sfx;
  }

  r = generic_read_file(&run_text, 0, &run_size, REMOVE, compile_report_dir, pname, exe_sfx);
  if (r < 0) {
    err("read_compile_packet_input: failed to read executable");
    goto done;
  }

  r = cs->storage_state->vt->get_by_serial_id(cs->storage_state,
                                              se.input_id,
                                              &inp_se);
  if (r < 0) {
    err("read_compile_packet_input: failed to read input data");
    goto done;
  }

  const struct section_problem_data *prob = NULL;
  if (se.prob_id > 0 && se.prob_id <= cs->max_prob) {
    prob = cs->probs[se.prob_id];
  }
  if (prob && prob->enable_src_for_testing > 0) {
    r = cs->storage_state->vt->get_by_serial_id(cs->storage_state,
                                                se.source_id,
                                                &src_se);
    if (r < 0) {
      err("read_compile_packet_input: failed to read source code");
      goto done;
    }
  }

  r = serve_run_request(config, cs, cnts, stderr,
                        run_text, run_size, se.contest_id,
                        0 /* run_id */, se.serial_id,
                        se.user_id, se.prob_id, se.lang_id, se.variant,
                        0 /* priority_adjustment */,
                        0 /* judge_id */,
                        &se.judge_uuid,
                        0 /* accepting_mode */,
                        0 /* notify_flag */,
                        0 /* mime_type */,
                        se.eoln_type,
                        se.locale_id,
                        compile_report_dir,
                        comp_pkt,
                        1 /* no_db_flag */,
                        NULL /* puuid */,
                        0 /* rejudge_flag */,
                        0 /* zip_mode */,
                        0 /* store_flags */,
                        0 /* not_ok_is_cf */,
                        inp_se.content,
                        inp_se.size,
                        NULL,
                        src_se.content,
                        src_se.size);
  if (r < 0) {
    err("read_compile_packet_input: failed to send to testing");
    goto done;
  }

  r = cs->submit_state->vt->change_status(cs->submit_state,
                                          se.serial_id,
                                          SUBMIT_FIELD_STATUS,
                                          RUN_RUNNING,
                                          0,
                                          NULL, &se);
  notify_submit_update(config, &se, tr);

done:;
  testing_report_free(tr);
  free(txt_text);
  free(run_text);
  free(inp_se.content);
  free(src_se.content);
}

int
serve_read_compile_packet(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        const unsigned char *compile_status_dir,
        const unsigned char *compile_report_dir,
        const unsigned char *pname,
        struct compile_reply_packet *comp_pkt /* ownership transferred */)
{
  unsigned char rep_path[PATH_MAX];
  int  r, rep_flags = 0;
  struct run_entry re;
  const struct section_global_data *global = state->global;
  char *comp_pkt_buf = 0;       /* need char* for generic_read_file */
  size_t comp_pkt_size = 0;
  long report_size = 0;
  unsigned char errmsg[1024] = { 0 };
  //unsigned char *team_name = 0;
  struct compile_run_extra *comp_extra = 0;
  struct section_problem_data *prob = 0;
  struct section_language_data *lang = 0;
  int arch_flags;
  path_t run_arch_path;
  char *run_text = 0, *txt_text = 0;
  size_t run_size = 0, txt_size = 0;
  path_t pkt_name;
  path_t txt_report_path;
  path_t txt_packet_path;
  size_t min_txt_size = 1;
  testing_report_xml_t testing_report = NULL;
  char *src_text = NULL;
  size_t src_size = 0;
  unsigned char src_path[PATH_MAX];

  if (!comp_pkt) {
    if ((r = generic_read_file(&comp_pkt_buf, 0, &comp_pkt_size, SAFE | REMOVE,
                               compile_status_dir, pname, "")) <= 0)
      return r;

    if (compile_reply_packet_read(comp_pkt_size, comp_pkt_buf, &comp_pkt) < 0) {
      /* failed to parse a compile packet */
      /* we can't do any reasonable recovery, just drop the packet */
      goto non_fatal_error;
    }
  }

  if (comp_pkt->contest_id != cnts->id) {
    err("read_compile_packet: mismatched contest_id %d", comp_pkt->contest_id);
    goto non_fatal_error;
  }
  if (comp_pkt->submit_id > 0) {
    read_compile_packet_input(extra,
                              config,
                              state,
                              cnts,
                              compile_report_dir,
                              pname,
                              comp_pkt);
    goto non_fatal_error;
  }
  int new_run_id = -1;
  if (run_get_uuid_hash_state(state->runlog_state) >= 0 && comp_pkt->use_uuid > 0) {
    new_run_id = run_find_run_id_by_uuid(state->runlog_state, &comp_pkt->uuid);
    if (new_run_id < 0) {
      err("read_compile_packet: non-existing UUID %s (packet run_id %d)", ej_uuid_unparse(&comp_pkt->uuid, NULL), comp_pkt->run_id);
      goto non_fatal_error;
    }
    if (new_run_id != comp_pkt->run_id) {
      info("read_compile_packet: run_id changed: old: %d, current: %d", comp_pkt->run_id, new_run_id);
      comp_pkt->run_id = new_run_id;
    }
  }

  if (run_get_entry(state->runlog_state, comp_pkt->run_id, &re) < 0) {
    err("read_compile_packet: invalid run_id %d", comp_pkt->run_id);
    goto non_fatal_error;
  }
  if (new_run_id >= 0) {
    if (memcmp(&re.run_uuid, &comp_pkt->uuid, sizeof(re.run_uuid)) != 0) {
      err("read_compile_packet: UUID mismatch for run_id %d", comp_pkt->run_id);
      goto non_fatal_error;
    }
  }
  if (re.judge_uuid_flag) {
    if (memcmp(&comp_pkt->judge_uuid, &re.j.judge_uuid, sizeof(re.j.judge_uuid)) != 0) {
      unsigned char b1[64];
      unsigned char b2[64];
      err("read_compile_packet: judge_uuid mismatch: %s, %s",
          ej_uuid_unparse_r(b1, sizeof(b1), &comp_pkt->judge_uuid, NULL),
          ej_uuid_unparse_r(b2, sizeof(b2), &re.j.judge_uuid, NULL));
      goto non_fatal_error;
    }
  } else {
    if (comp_pkt->judge_id != re.j.judge_id) {
      err("read_compile_packet: judge_id mismatch: %d, %d", comp_pkt->judge_id,
          re.j.judge_id);
      goto non_fatal_error;
    }
  }
  if (re.status != RUN_COMPILING) {
    err("read_compile_packet: run %d is not compiling", comp_pkt->run_id);
    goto non_fatal_error;
  }

  // account compile time
  if (metrics.data) {
    long long ts2 = comp_pkt->ts2 * 1000LL + comp_pkt->ts2_us / 1000;
    long long ts3 = comp_pkt->ts3 * 1000LL + comp_pkt->ts3_us / 1000;
    if (ts3 > ts2) {
      metrics.data->total_compile_time_ms += (ts3 - ts2);
    }
  }

  if (re.prob_id >= 1 && re.prob_id <= state->max_prob) {
    prob = state->probs[re.prob_id];
  }

  comp_extra = (typeof(comp_extra)) comp_pkt->run_block;
  if (!comp_extra || comp_pkt->run_block_len != sizeof(*comp_extra)
      || comp_extra->accepting_mode < 0 || comp_extra->accepting_mode > 1) {
    snprintf(errmsg, sizeof(errmsg), "invalid run block\n");
    goto report_check_failed;
  }

  snprintf(pkt_name, sizeof(pkt_name), "%06d", comp_pkt->run_id);

  if ((comp_pkt->status == RUN_CHECK_FAILED || comp_pkt->status == RUN_COMPILE_ERR || comp_pkt->status == RUN_STYLE_ERR)) {
    if (generic_read_file(&txt_text, 0, &txt_size, REMOVE, compile_report_dir, pname, ".txt") < 0) {
      snprintf(errmsg, sizeof(errmsg), "generic_read_file: %s/%s.txt failed\n", compile_report_dir, pname);
      goto report_check_failed;
    }
    if (re.judge_uuid_flag) {
      testing_report = testing_report_alloc(comp_pkt->contest_id, comp_pkt->run_id, 0, &re.j.judge_uuid);
    } else {
      testing_report = testing_report_alloc(comp_pkt->contest_id, comp_pkt->run_id, re.j.judge_id, NULL);
    }
    testing_report->status = comp_pkt->status;
    testing_report->compiler_output = xstrdup(txt_text);
    utf8_fix_string(testing_report->compiler_output, NULL);
    testing_report->scoring_system = global->score_system;
    testing_report->compile_error = 1;
    memcpy(&testing_report->uuid, &re.run_uuid, sizeof(testing_report->uuid));

    if (re.store_flags == STORE_FLAGS_UUID_BSON) {
      xfree(txt_text); txt_text = NULL; txt_size = 0;
      testing_report_to_mem_bson(&txt_text, &txt_size, testing_report);
      rep_flags = uuid_archive_make_write_path(state, rep_path, sizeof(rep_path),
                                               &re.run_uuid, txt_size, DFLT_R_UUID_BSON_REPORT, -1);
    } else {
      xfree(txt_text); txt_text = NULL; txt_size = 0;
      testing_report_to_str(&txt_text, &txt_size, 1, testing_report);

      if (re.store_flags == STORE_FLAGS_UUID) {
        rep_flags = uuid_archive_make_write_path(state, rep_path, sizeof(rep_path),
                                                 &re.run_uuid, txt_size, DFLT_R_UUID_XML_REPORT, 0);
      } else {
        rep_flags = archive_make_write_path(state, rep_path, sizeof(rep_path),
                                            global->xml_report_archive_dir, comp_pkt->run_id, txt_size, 0, 0);
      }
    }

    if (rep_flags < 0) {
      snprintf(errmsg, sizeof(errmsg),
               "archive_make_write_path: %s, %d, %ld failed\n",
               global->xml_report_archive_dir, comp_pkt->run_id,
               (long) txt_size);
      goto report_check_failed;
    }

    if (re.store_flags == STORE_FLAGS_UUID_BSON) {
      if (uuid_archive_dir_prepare(state, &re.run_uuid, DFLT_R_UUID_BSON_REPORT, 0) < 0) {
        snprintf(errmsg, sizeof(errmsg), "uuid_archive_dir_prepare: failed\n");
        goto report_check_failed;
      }
    } else if (re.store_flags == STORE_FLAGS_UUID) {
      if (uuid_archive_dir_prepare(state, &re.run_uuid, DFLT_R_UUID_XML_REPORT, 0) < 0) {
        snprintf(errmsg, sizeof(errmsg), "uuid_archive_dir_prepare: failed\n");
        goto report_check_failed;
      }
    } else {
      if (archive_dir_prepare(state, global->xml_report_archive_dir, comp_pkt->run_id, 0, 0) < 0) {
        snprintf(errmsg, sizeof(errmsg), "archive_dir_prepare: failed\n");
        goto report_check_failed;
      }
    }

    if (generic_write_file(txt_text, txt_size, rep_flags, 0, rep_path, 0) < 0) {
      snprintf(errmsg, sizeof(errmsg),
               "generic_write_file failed: %s, %ld\n",
               rep_path, (long) rep_flags);
      goto report_check_failed;
    }

    if (comp_pkt->status == RUN_CHECK_FAILED) {
      if (run_change_status_4(state->runlog_state, comp_pkt->run_id,
                              RUN_CHECK_FAILED, &re) < 0)
        goto non_fatal_error;
      serve_notify_run_update(config, state, &re);
      serve_send_check_failed_email(config, cnts, comp_pkt->run_id);
      serve_telegram_check_failed(config, cnts, state, comp_pkt->run_id, &re);
      goto success;
    }

    if (comp_pkt->status == RUN_COMPILE_ERR || comp_pkt->status == RUN_STYLE_ERR) {
      if (run_change_status_4(state->runlog_state, comp_pkt->run_id,
                              comp_pkt->status, &re) < 0)
        goto non_fatal_error;
      serve_notify_run_update(config, state, &re);

      serve_update_standings_file(extra, state, cnts, 0);
      if (global->notify_status_change > 0 && !re.is_hidden && comp_extra->notify_flag) {
        serve_notify_user_run_status_change(config, cnts, state, re.user_id,
                                            comp_pkt->run_id, comp_pkt->status);
      }
      if (prob && prob->notify_on_submit > 0) {
        serve_telegram_notify_on_submit(config, cnts, state, comp_pkt->run_id, &re, comp_pkt->status);
      }
      goto success;
    }

    abort();
  }

  if (1 /*re.store_flags == STORE_FLAGS_UUID || re.store_flags == STORE_FLAGS_UUID_BSON */) {
    snprintf(txt_packet_path, sizeof(txt_packet_path), "%s/%s.txt", compile_report_dir, pname);
    generic_read_file(&txt_text, 0, &txt_size, REMOVE, NULL, txt_packet_path, NULL);

    if (re.judge_uuid_flag) {
      testing_report = testing_report_alloc(comp_pkt->contest_id, comp_pkt->run_id, 0, &re.j.judge_uuid);
    } else {
      testing_report = testing_report_alloc(comp_pkt->contest_id, comp_pkt->run_id, re.j.judge_id, NULL);
    }
    testing_report->status = RUN_RUNNING;
    if (txt_text) {
      testing_report->compiler_output = xstrdup(txt_text);
      utf8_fix_string(testing_report->compiler_output, NULL);
    }
    testing_report->scoring_system = global->score_system;
    testing_report->compile_error = 1;
    memcpy(&testing_report->uuid, &re.run_uuid, sizeof(testing_report->uuid));

    if (re.store_flags == STORE_FLAGS_UUID_BSON) {
      xfree(txt_text); txt_text = NULL; txt_size = 0;
      testing_report_to_mem_bson(&txt_text, &txt_size, testing_report);
      rep_flags = uuid_archive_make_write_path(state, rep_path, sizeof(rep_path),
                                               &re.run_uuid, txt_size, DFLT_R_UUID_BSON_REPORT, -1);
    } else {
      xfree(txt_text); txt_text = NULL; txt_size = 0;
      testing_report_to_str(&txt_text, &txt_size, 1, testing_report);

      if (re.store_flags == STORE_FLAGS_UUID) {
        rep_flags = uuid_archive_make_write_path(state, rep_path, sizeof(rep_path),
                                                 &re.run_uuid, txt_size, DFLT_R_UUID_XML_REPORT, 0);
      } else {
        rep_flags = archive_make_write_path(state, rep_path, sizeof(rep_path),
                                            global->xml_report_archive_dir, comp_pkt->run_id, txt_size, 0, 0);
      }
    }
    ASSERT(rep_flags >= 0);
    if (re.store_flags == STORE_FLAGS_UUID_BSON) {
      if (uuid_archive_dir_prepare(state, &re.run_uuid, DFLT_R_UUID_BSON_REPORT, 0) < 0) {
        snprintf(errmsg, sizeof(errmsg), "uuid_archive_dir_prepare: failed\n");
        goto report_check_failed;
      }
    } else if (re.store_flags == STORE_FLAGS_UUID) {
      if (uuid_archive_dir_prepare(state, &re.run_uuid, DFLT_R_UUID_XML_REPORT, 0) < 0) {
        snprintf(errmsg, sizeof(errmsg), "uuid_archive_dir_prepare: failed\n");
        goto report_check_failed;
      }
    } else {
      if (archive_dir_prepare(state, global->xml_report_archive_dir, comp_pkt->run_id, 0, 0) < 0) {
        snprintf(errmsg, sizeof(errmsg), "archive_dir_prepare: failed\n");
        goto report_check_failed;
      }
    }
    if (generic_write_file(txt_text, txt_size, rep_flags, 0, rep_path, 0) < 0) {
      snprintf(errmsg, sizeof(errmsg), "generic_write_file failed: %s, %ld\n", rep_path, (long) rep_flags);
      goto report_check_failed;
    }
    goto prepare_run_request;
  }

  // looks like we never should get here
  if (re.store_flags == STORE_FLAGS_UUID_BSON) {
    err("read_compile_packet: unsupported mode: STORE_FLAGS_UUID_BSON not supported here");
    goto report_check_failed;
  }

  if (comp_pkt->status == RUN_CHECK_FAILED
      || comp_pkt->status == RUN_COMPILE_ERR
      || comp_pkt->status == RUN_STYLE_ERR) {
    if ((report_size = generic_file_size(compile_report_dir, pname, ".txt")) < 0) {
      err("read_compile_packet: cannot get report file size");
      snprintf(errmsg, sizeof(errmsg), "cannot get size of %s/%s.txt\n", compile_report_dir, pname);
      goto report_check_failed;
    }

    if (re.store_flags == STORE_FLAGS_UUID) {
      rep_flags = uuid_archive_make_write_path(state, rep_path, sizeof(rep_path),
                                               &re.run_uuid, report_size, DFLT_R_UUID_XML_REPORT, 0);
    } else {
      rep_flags = archive_make_write_path(state, rep_path, sizeof(rep_path),
                                          global->xml_report_archive_dir,
                                          comp_pkt->run_id, report_size, 0, 0);
    }
    if (rep_flags < 0) {
      snprintf(errmsg, sizeof(errmsg),
               "archive_make_write_path: %s, %d, %ld failed\n",
               global->xml_report_archive_dir, comp_pkt->run_id,
               report_size);
      goto report_check_failed;
    }
  }

  if ((prob && prob->style_checker_cmd && prob->style_checker_cmd[0])
      || (lang && lang->style_checker_cmd && lang->style_checker_cmd[0])) {
    min_txt_size = 0;
  }
  snprintf(txt_packet_path, sizeof(txt_packet_path), "%s/%s.txt", compile_report_dir, pname);
  if (generic_read_file(&txt_text, 0, &txt_size, REMOVE, NULL, txt_packet_path, NULL) >= 0
      && txt_size >= min_txt_size) {
    if (re.store_flags == STORE_FLAGS_UUID) {
      arch_flags = uuid_archive_make_write_path(state, txt_report_path, sizeof(txt_report_path),
                                                &re.run_uuid, txt_size, DFLT_R_UUID_REPORT, 0);
    } else {
      arch_flags = archive_make_write_path(state, txt_report_path, sizeof(txt_report_path),
                                           global->report_archive_dir, comp_pkt->run_id, txt_size, 0, 0);
    }
    if (arch_flags >= 0) {
      generic_write_file(txt_text, txt_size, arch_flags, 0, txt_report_path, 0);
    }
  }

  if (comp_pkt->status == RUN_CHECK_FAILED) {
    /* if status change fails, we cannot do reasonable recovery */
    if (run_change_status_4(state->runlog_state, comp_pkt->run_id,
                            RUN_CHECK_FAILED, &re) < 0)
      goto non_fatal_error;
    serve_notify_run_update(config, state, &re);
    if (re.store_flags == STORE_FLAGS_UUID) {
      if (uuid_archive_dir_prepare(state, &re.run_uuid, DFLT_R_UUID_XML_REPORT, 0) < 0)
        goto non_fatal_error;
    } else {
      if (archive_dir_prepare(state, global->xml_report_archive_dir, comp_pkt->run_id, 0, 0) < 0)
        goto non_fatal_error;
    }
    if (generic_copy_file(REMOVE, compile_report_dir, pname, ".txt", rep_flags, 0, rep_path, "") < 0) {
      snprintf(errmsg, sizeof(errmsg),
               "generic_copy_file: %s/%s.txt, %d, %s failed\n",
               compile_report_dir, pname, rep_flags, rep_path);
      goto report_check_failed;
    }
    serve_send_check_failed_email(config, cnts, comp_pkt->run_id);
    serve_telegram_check_failed(config, cnts, state, comp_pkt->run_id, &re);
    goto success;
  }

  if (comp_pkt->status == RUN_COMPILE_ERR || comp_pkt->status == RUN_STYLE_ERR) {
    /* if status change fails, we cannot do reasonable recovery */
    if (run_change_status_4(state->runlog_state, comp_pkt->run_id,
                            comp_pkt->status, &re) < 0)
      goto non_fatal_error;
    serve_notify_run_update(config, state, &re);

    if (re.store_flags == STORE_FLAGS_UUID) {
      if (uuid_archive_dir_prepare(state, &re.run_uuid, DFLT_R_UUID_XML_REPORT, 0) < 0) {
        snprintf(errmsg, sizeof(errmsg), "archive_dir_prepare: %s, %d failed\n",
                 global->uuid_archive_dir, comp_pkt->run_id);
        goto report_check_failed;
      }
    } else {
      if (archive_dir_prepare(state, global->xml_report_archive_dir,
                              comp_pkt->run_id, 0, 0) < 0) {
        snprintf(errmsg, sizeof(errmsg), "archive_dir_prepare: %s, %d failed\n",
                 global->xml_report_archive_dir, comp_pkt->run_id);
        goto report_check_failed;
      }
    }
    if (generic_copy_file(REMOVE, compile_report_dir, pname, ".txt", rep_flags, 0, rep_path, "") < 0) {
      snprintf(errmsg, sizeof(errmsg), "generic_copy_file: %s/%s.txt, %d, %s failed\n",
               compile_report_dir, pname, rep_flags, rep_path);
      goto report_check_failed;
    }
    serve_update_standings_file(extra, state, cnts, 0);
    if (global->notify_status_change > 0 && !re.is_hidden
        && comp_extra->notify_flag) {
      serve_notify_user_run_status_change(config, cnts, state, re.user_id,
                                          comp_pkt->run_id, comp_pkt->status);
    }
    if (prob && prob->notify_on_submit > 0) {
      serve_telegram_notify_on_submit(config, cnts, state, comp_pkt->run_id, &re, comp_pkt->status);
    }
    goto success;
  }

prepare_run_request:

  /* check run parameters */
  if (re.prob_id < 1 || re.prob_id > state->max_prob
      || !(prob = state->probs[re.prob_id])) {
    snprintf(errmsg, sizeof(errmsg), "invalid problem %d\n", re.prob_id);
    goto report_check_failed;
  }
  if (re.lang_id > 1 && re.lang_id <= state->max_lang) {
    lang = state->langs[re.lang_id];
  }
  /*
  if (re.lang_id < 1 || re.lang_id > state->max_lang
      || !(lang = state->langs[re.lang_id])) {
    snprintf(errmsg, sizeof(errmsg), "invalid language %d\n", re.lang_id);
    goto report_check_failed;
  }
  */
  /*
  if (!(team_name = teamdb_get_name(state->teamdb_state, re.user_id))) {
    snprintf(errmsg, sizeof(errmsg), "invalid team %d\n", re.user_id);
    goto report_check_failed;
  }
  */
  if (prob->disable_testing && prob->enable_compilation > 0) {
    if (run_change_status_4(state->runlog_state, comp_pkt->run_id,
                            RUN_ACCEPTED, &re) < 0)
      goto non_fatal_error;
    serve_notify_run_update(config, state, &re);
    if (global->notify_status_change > 0 && !re.is_hidden
        && comp_extra->notify_flag) {
      serve_notify_user_run_status_change(config, cnts, state, re.user_id,
                                          comp_pkt->run_id, RUN_ACCEPTED);
    }
    if (prob && prob->notify_on_submit > 0) {
      serve_telegram_notify_on_submit(config, cnts, state, comp_pkt->run_id, &re, comp_pkt->status);
    }
    goto success;
  }

  /*
  if (run_change_status(state->runlog_state, comp_pkt->run_id, RUN_COMPILED,
                        0, 1, -1, comp_pkt->judge_id) < 0)
    goto non_fatal_error;
  */

  /*
   * so far compilation is successful, and now we prepare a run packet
   */

  if (prob && prob->type > 0 && prob->style_checker_cmd && prob->style_checker_cmd[0]) {
    arch_flags = serve_make_source_read_path(state, run_arch_path, sizeof(run_arch_path), &re);
    if (arch_flags < 0) goto report_check_failed;
    if (generic_read_file(&run_text, 0, &run_size, arch_flags,
                          0, run_arch_path, 0) < 0)
      goto report_check_failed;
  }

  if (prob && prob->enable_src_for_testing > 0) {
    int af = 0;
    int sf = re.store_flags;
    if (sf == STORE_FLAGS_UUID || sf == STORE_FLAGS_UUID_BSON) {
      af = uuid_archive_make_read_path(state, src_path, sizeof(src_path),
                                       &re.run_uuid, DFLT_R_UUID_SOURCE, 0);
    } else {
      af = archive_make_read_path(state, src_path, sizeof(src_path),
                                  global->run_archive_dir, comp_pkt->run_id,
                                  0, 0);
    }
    if (af < 0) {
      snprintf(errmsg, sizeof(errmsg), "failed to read source code\n");
      goto report_check_failed;
    }
    if (generic_read_file(&src_text, 0, &src_size, af, 0, src_path, "") < 0) {
      snprintf(errmsg, sizeof(errmsg), "failed to read source code\n");
      goto report_check_failed;
    }
  }

  if (serve_run_request(config, state, cnts, stderr, run_text, run_size,
                        cnts->id, comp_pkt->run_id,
                        0 /* submit_id */,
                        re.user_id, re.prob_id, re.lang_id, re.variant,
                        comp_extra->priority_adjustment,
                        comp_pkt->judge_id, &comp_pkt->judge_uuid,
                        comp_extra->accepting_mode,
                        comp_extra->notify_flag, re.mime_type, re.eoln_type,
                        re.locale_id, compile_report_dir, comp_pkt, 0, &re.run_uuid,
                        comp_extra->rejudge_flag, comp_pkt->zip_mode, re.store_flags,
                        comp_extra->not_ok_is_cf,
                        NULL, 0,
                        &re,
                        src_text,
                        src_size) < 0) {
    snprintf(errmsg, sizeof(errmsg), "failed to write run packet\n");
    goto report_check_failed;
  }
  xfree(run_text); run_text = 0; run_size = 0;

 success:
  xfree(comp_pkt_buf);
  xfree(txt_text);
  compile_reply_packet_free(comp_pkt);
  testing_report_free(testing_report);
  // remove stale reports
  if (snprintf(txt_report_path, sizeof(txt_report_path), "%s/%s.txt", compile_report_dir, pname) < sizeof(txt_report_path)) {
    unlink(txt_report_path);
  }
  if (snprintf(txt_report_path, sizeof(txt_report_path), "%s/%s", compile_report_dir, pname) < sizeof(txt_report_path)) {
    unlink(txt_report_path);
  }
  return 1;

 report_check_failed:
  xfree(run_text); run_text = 0; run_size = 0;
  serve_send_check_failed_email(config, cnts, comp_pkt->run_id);
  serve_telegram_check_failed(config, cnts, state, comp_pkt->run_id, &re);

  /* this is error recover, so if error happens again, we cannot do anything */
  if (run_change_status_4(state->runlog_state, comp_pkt->run_id,
                          RUN_CHECK_FAILED, &re) < 0)
    goto non_fatal_error;
  serve_notify_run_update(config, state, &re);
  report_size = strlen(errmsg);

  if (re.store_flags == STORE_FLAGS_UUID_BSON) {
    if (re.judge_uuid_flag) {
      testing_report = testing_report_alloc(comp_pkt->contest_id, comp_pkt->run_id, 0, &re.j.judge_uuid);
    } else {
      testing_report = testing_report_alloc(comp_pkt->contest_id, comp_pkt->run_id, re.j.judge_id, NULL);
    }
    testing_report->status = RUN_CHECK_FAILED;
    if (txt_text) {
      testing_report->compiler_output = xstrdup(errmsg);
      utf8_fix_string(testing_report->compiler_output, NULL);
    }
    testing_report->scoring_system = global->score_system;
    testing_report->compile_error = 1;
    memcpy(&testing_report->uuid, &re.run_uuid, sizeof(testing_report->uuid));
    xfree(txt_text); txt_text = NULL; txt_size = 0;
    testing_report_to_mem_bson(&txt_text, &txt_size, testing_report);
    rep_flags = uuid_archive_prepare_write_path(state, rep_path, sizeof(rep_path),
                                                &re.run_uuid, txt_size, DFLT_R_UUID_BSON_REPORT, -1, 0);
  } else {
    if (re.store_flags == STORE_FLAGS_UUID) {
      rep_flags = uuid_archive_prepare_write_path(state, rep_path, sizeof(rep_path),
                                                  &re.run_uuid, report_size, DFLT_R_UUID_XML_REPORT, 0, 0);
    } else {
      rep_flags = archive_prepare_write_path(state, rep_path, sizeof(rep_path),
                                             global->xml_report_archive_dir, comp_pkt->run_id,
                                             report_size, NULL, 0, 0);
    }
  }
  if (rep_flags < 0)
    goto non_fatal_error;

  /* error code is ignored */
  generic_write_file(errmsg, report_size, rep_flags, 0, rep_path, 0);
  /* goto non_fatal_error; */

 non_fatal_error:
  xfree(comp_pkt_buf);
  xfree(txt_text);
  xfree(src_text);
  compile_reply_packet_free(comp_pkt);
  testing_report_free(testing_report);
  // remove stale reports
  if (snprintf(txt_report_path, sizeof(txt_report_path), "%s/%s.txt", compile_report_dir, pname) < sizeof(txt_report_path)) {
    unlink(txt_report_path);
  }
  if (snprintf(txt_report_path, sizeof(txt_report_path), "%s/%s", compile_report_dir, pname) < sizeof(txt_report_path)) {
    unlink(txt_report_path);
  }
  return 0;
}

int
serve_is_valid_status(serve_state_t state, int status, int mode)
{
  if (state->global->score_system == SCORE_OLYMPIAD) {
    switch (status) {
    case RUN_OK:
    case RUN_PARTIAL:
    case RUN_RUN_TIME_ERR:
    case RUN_TIME_LIMIT_ERR:
    case RUN_WALL_TIME_LIMIT_ERR:
    case RUN_PRESENTATION_ERR:
    case RUN_WRONG_ANSWER_ERR:
    case RUN_ACCEPTED:
    case RUN_PENDING_REVIEW:
    case RUN_SUMMONED:
    case RUN_CHECK_FAILED:
    case RUN_MEM_LIMIT_ERR:
    case RUN_SECURITY_ERR:
    case RUN_SYNC_ERR:
      return 1;
    case RUN_COMPILE_ERR:
    case RUN_STYLE_ERR:
    case RUN_REJECTED:
    case RUN_FULL_REJUDGE:
    case RUN_REJUDGE:
    case RUN_IGNORED:
    case RUN_DISQUALIFIED:
    case RUN_PENDING:
      if (mode != 1) return 0;
      return 1;
    default:
      return 0;
    }
  } else if (state->global->score_system == SCORE_KIROV) {
    switch (status) {
    case RUN_OK:
    case RUN_PARTIAL:
    case RUN_CHECK_FAILED:
    case RUN_ACCEPTED:
    case RUN_PENDING_REVIEW:
    case RUN_SUMMONED:
    case RUN_PRESENTATION_ERR:
      return 1;
    case RUN_COMPILE_ERR:
    case RUN_STYLE_ERR:
    case RUN_REJECTED:
    case RUN_REJUDGE:
    case RUN_IGNORED:
    case RUN_DISQUALIFIED:
    case RUN_PENDING:
      if (mode != 1) return 0;
      return 1;
    default:
      return 0;
    }
  } else {
    switch (status) {
    case RUN_OK:
    case RUN_ACCEPTED:
    case RUN_PENDING_REVIEW:
    case RUN_SUMMONED:
    case RUN_RUN_TIME_ERR:
    case RUN_TIME_LIMIT_ERR:
    case RUN_WALL_TIME_LIMIT_ERR:
    case RUN_PRESENTATION_ERR:
    case RUN_WRONG_ANSWER_ERR:
    case RUN_CHECK_FAILED:
    case RUN_MEM_LIMIT_ERR:
    case RUN_SECURITY_ERR:
    case RUN_SYNC_ERR:
      return 1;
    case RUN_COMPILE_ERR:
    case RUN_STYLE_ERR:
    case RUN_REJECTED:
    case RUN_REJUDGE:
    case RUN_IGNORED:
    case RUN_DISQUALIFIED:
    case RUN_PENDING:
      if (mode != 1) return 0;
      return 1;
    default:
      return 0;
    }
  }
}

static unsigned char *
time_to_str(unsigned char *buf, size_t size, int secs, int usecs)
{
  struct tm *ltm;
  time_t tt = secs;

  if (secs <= 0) {
    snprintf(buf, size, "N/A");
    return buf;
  }
  ltm = localtime(&tt);
  snprintf(buf, size, "%04d-%02d-%02d %02d:%02d:%02d.%06d",
           ltm->tm_year + 1900, ltm->tm_mon + 1, ltm->tm_mday,
           ltm->tm_hour, ltm->tm_min, ltm->tm_sec, usecs);
  return buf;
}

static unsigned char *
dur_to_str(unsigned char *buf, size_t size, int sec1, int usec1,
           int sec2, int usec2)
{
  long long d;

  if (sec1 <= 0 || sec2 <= 0) {
    snprintf(buf, size, "N/A");
    return buf;
  }
  if ((d = sec2 * 1000000LL + usec2 - (sec1 * 1000000LL + usec1)) < 0) {
    snprintf(buf, size, "t1 > t2");
    return buf;
  }
  d = (d + 500) / 1000;
  snprintf(buf, size, "%lld.%03lld", d / 1000, d % 1000);
  return buf;
}

#define BAD_PACKET() do { bad_packet_line = __LINE__; goto bad_packet_error; } while (0)

static void
read_run_packet_input(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        serve_state_t cs,
        const struct contest_desc *cnts,
        const unsigned char *run_status_dir,
        const unsigned char *run_report_dir,
        const unsigned char *run_full_archive_dir,
        const unsigned char *pname,
        const struct run_reply_packet *reply_pkt)
{
  int r;
  struct submit_entry se = {};
  struct storage_entry cp_se = {};
  char *rep_data = NULL;
  size_t rep_size = 0;
  testing_report_xml_t cp_tr = NULL;
  testing_report_xml_t tr = NULL;
  int mime_type = 0;
  struct storage_entry tr_se = {};

  info("read_run_packet_input: submit_id %lld", (long long) reply_pkt->submit_id);

  if (!cs->storage_state) {
    cs->storage_state = storage_plugin_get(extra, cnts, ejudge_config, NULL);
    if (!cs->storage_state) {
      err("read_run_packet_input: storage plugin not available");
      goto done;
    }
  }
  if (!cs->submit_state) {
    cs->submit_state = submit_plugin_open(ejudge_config, cnts, cs, NULL, 0);
    if (!cs->submit_state) {
      err("read_run_packet_input: submit plugin not available");
      goto done;
    }
  }

  if (ej_uuid_is_empty(reply_pkt->judge_uuid)) {
    err("read_run_packet_input: judge_uuid is empty");
    goto done;
  }

  r = cs->submit_state->vt->fetch(cs->submit_state, reply_pkt->submit_id, &se);
  if (r < 0) {
    err("read_run_packet_input: fetch failed");
    goto done;
  }
  if (!r) {
    err("read_run_packet_input: submit %lld not found", (long long) reply_pkt->submit_id);
    goto done;
  }

  if (se.contest_id != cnts->id) {
    err("read_run_packet_input: contest_id mismatch: read %d", se.contest_id);
    goto done;
  }

  // account the testing time
  if (metrics.data) {
    long long ts5 = reply_pkt->ts5 * 1000LL + reply_pkt->ts5_us / 1000;
    long long ts6 = reply_pkt->ts6 * 1000LL + reply_pkt->ts6_us / 1000;
    if (ts6 > ts5) {
      metrics.data->total_testing_time_ms += (ts6 - ts5);
    }
  }

  if (se.status != RUN_RUNNING) {
    err("read_compile_packet_input: submit_entry status not RUNNING");
    goto done;
  }
  if (memcmp(&se.judge_uuid, &reply_pkt->judge_uuid, 16) != 0) {
    unsigned char buf1[64], buf2[64];
    err("read_run_packet_input: judge_uuid mismatch: submit_entry: %s, run_packet: %s",
        ej_uuid_unparse_r(buf1, sizeof(buf1), &se.judge_uuid, NULL),
        ej_uuid_unparse_r(buf2, sizeof(buf2), &reply_pkt->judge_uuid, NULL));
    goto done;
  }

  if (generic_read_file(&rep_data, 0, &rep_size, REMOVE, run_report_dir, pname, NULL) < 0) {
    err("read_run_packet_input: failed to read testing report");
    goto done;
  }

  if (se.protocol_id > 0) {
    // merge compilation and testing protocol
    r = cs->storage_state->vt->get_by_serial_id(cs->storage_state,
                                                se.protocol_id,
                                                &cp_se);
    if (r < 0) {
      err("read_run_packet_input: failed to read compilation protocol");
      goto done;
    }
    if (cp_se.mime_type == MIME_TYPE_BSON) {
      cp_tr = testing_report_parse_bson_data(cp_se.content, cp_se.size);
    } else if (!cp_se.mime_type) {
      size_t len = strlen(cp_se.content);
      if (len != cp_se.size) {
        err("read_run_packet_input: invalid length of compilation XML report");
        goto done;
      }
      cp_tr = testing_report_parse_xml(cp_se.content);
    } else {
      err("read_run_packet_input: invalid mime type of compilation protocol");
      goto done;
    }
    if (!cp_tr) {
      err("read_run_packet_input: failed to parse compilation report");
      goto done;
    }
    if (reply_pkt->bson_flag) {
      tr = testing_report_parse_bson_data(rep_data, rep_size);
    } else {
      size_t len = strlen(rep_data);
      if (len != rep_size) {
        err("read_run_packet_input: invalid length of testing report");
        goto done;
      }
      tr = testing_report_parse_xml(rep_data);
    }
    if (!tr) {
      err("read_run_packet_input: failed to parse testing report");
      goto done;
    }
    if (cp_tr->compiler_output && *cp_tr->compiler_output) {
      tr->compiler_output = xstrdup(cp_tr->compiler_output);
    }
    free(rep_data); rep_data = NULL; rep_size = 0;
    if (testing_report_bson_available()) {
      testing_report_to_mem_bson(&rep_data, &rep_size, tr);
      mime_type = MIME_TYPE_BSON;
    } else {
      testing_report_to_str(&rep_data, &rep_size, 1, tr);
    }
  } else {
    if (reply_pkt->bson_flag) {
      mime_type = MIME_TYPE_BSON;
    }
    // parse protocol for notification
    if (se.notify_driver > 0) {
      if (reply_pkt->bson_flag) {
        tr = testing_report_parse_bson_data(rep_data, rep_size);
      } else {
        size_t len = strlen(rep_data);
        if (len != rep_size) {
          err("read_run_packet_input: invalid length of testing report");
          goto done;
        }
        tr = testing_report_parse_xml(rep_data);
      }
      if (!tr) {
        err("read_run_packet_input: failed to parse testing report");
        goto done;
      }
    }
  }

  r = cs->storage_state->vt->insert(cs->storage_state, 0, mime_type, rep_size, rep_data, &tr_se);
  if (r < 0) {
    err("read_run_packet_input: failed to store the report");
    goto done;
  }

  cs->submit_state->vt->change_status(cs->submit_state,
                                      se.serial_id,
                                      SUBMIT_FIELD_STATUS | SUBMIT_FIELD_PROTOCOL_ID | SUBMIT_FIELD_JUDGE_UUID,
                                      reply_pkt->status,
                                      tr_se.serial_id,
                                      NULL, &se);
  notify_submit_update(config, &se, tr);

done:;
  free(rep_data);
  free(cp_se.content);
  testing_report_free(cp_tr);
  testing_report_free(tr);
}

int
serve_read_run_packet(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        const unsigned char *run_status_dir,
        const unsigned char *run_report_dir,
        const unsigned char *run_full_archive_dir,
        const unsigned char *pname,
        struct run_reply_packet *reply_pkt /* ownership transferred */)
{
  const struct section_global_data *global = state->global;
  path_t rep_path, full_path, cur_rep_path;
  int r, rep_flags, full_flags, i, cur_rep_flag;
  struct run_entry re, pe;
  char *reply_buf = 0;          /* need char* for generic_read_file */
  size_t reply_buf_size = 0;
  char *audit_text = 0;
  size_t audit_text_size = 0;
  FILE *f = 0;
  int ts8, ts8_us;
  unsigned char time_buf[64];
  int ignore_prev_ac = 0;
  int bad_packet_line = 0;
  const unsigned char *full_suffix = "";
  char *cur_rep_text = NULL;
  size_t cur_rep_len = 0;
  testing_report_xml_t cur_tr = NULL;
  unsigned char *compiler_output = NULL;
  char *new_rep_text = NULL;
  size_t new_rep_len = 0;
  testing_report_xml_t new_tr = NULL;

  get_current_time(&ts8, &ts8_us);

  if (!reply_pkt) {
    if ((r = generic_read_file(&reply_buf, 0, &reply_buf_size, SAFE | REMOVE,
                               run_status_dir, pname, "")) <= 0)
      return r;

    if (run_reply_packet_read(reply_buf_size, reply_buf, &reply_pkt) < 0)
      goto failed;
    xfree(reply_buf), reply_buf = 0;
  }

  if (reply_pkt->contest_id != cnts->id) {
    err("read_run_packet: contest_id mismatch: %d in packet",
        reply_pkt->contest_id);
    goto failed;
  }

  if (reply_pkt->submit_id > 0) {
    read_run_packet_input(extra,
                          config,
                          state,
                          cnts,
                          run_status_dir,
                          run_report_dir,
                          run_full_archive_dir,
                          pname,
                          reply_pkt);
    run_reply_packet_free(reply_pkt);
    return 1;
  }

  int new_run_id = -1;
  if (run_get_uuid_hash_state(state->runlog_state) >= 0
      && (reply_pkt->uuid.v[0] || reply_pkt->uuid.v[1] || reply_pkt->uuid.v[2] || reply_pkt->uuid.v[3])) {
    new_run_id = run_find_run_id_by_uuid(state->runlog_state, &reply_pkt->uuid);
    if (new_run_id < 0) {
      err("read_run_packet: non-existing UUID %s (packet run_id %d)", ej_uuid_unparse(&reply_pkt->uuid, NULL), reply_pkt->run_id);
      goto failed;
    }
    if (new_run_id != reply_pkt->run_id) {
      info("read_run_packet: run_id changed: old: %d, current: %d", reply_pkt->run_id, new_run_id);
      reply_pkt->run_id = new_run_id;
    }
  }

  if (run_get_entry(state->runlog_state, reply_pkt->run_id, &re) < 0) {
    err("read_run_packet: invalid run_id: %d", reply_pkt->run_id);
    goto failed;
  }
  if (new_run_id >= 0) {
    if (memcmp(&re.run_uuid, &reply_pkt->uuid, sizeof(re.run_uuid)) != 0) {
      err("read_run_packet: UUID mismatch for run_id %d", reply_pkt->run_id);
      goto failed;
    }
  }

  // account the testing time
  if (metrics.data) {
    long long ts5 = reply_pkt->ts5 * 1000LL + reply_pkt->ts5_us / 1000;
    long long ts6 = reply_pkt->ts6 * 1000LL + reply_pkt->ts6_us / 1000;
    if (ts6 > ts5) {
      metrics.data->total_testing_time_ms += (ts6 - ts5);
    }
  }

  if (re.status != RUN_RUNNING) {
    err("read_run_packet: run %d status is not RUNNING", reply_pkt->run_id);
    goto failed;
  }
  if (re.judge_uuid_flag) {
    if (memcmp(&reply_pkt->judge_uuid, &re.j.judge_uuid, sizeof(re.j.judge_uuid)) != 0) {
      unsigned char b1[64];
      unsigned char b2[64];
      err("read_run_packet: judge_uuid mismatch: %s, %s",
          ej_uuid_unparse_r(b1, sizeof(b1), &reply_pkt->judge_uuid, NULL),
          ej_uuid_unparse_r(b2, sizeof(b2), &re.j.judge_uuid, NULL));
      goto failed;
    }
  } else {
    if (re.j.judge_id != reply_pkt->judge_id) {
      err("read_run_packet: judge_id mismatch: packet: %d, db: %d",
          reply_pkt->judge_id, re.j.judge_id);
      goto failed;
    }
  }

  if (!serve_is_valid_status(state, reply_pkt->status, 2))
    BAD_PACKET();

  const struct section_problem_data *prob = NULL;
  if (re.prob_id >= 1 && re.prob_id <= state->max_prob)
    prob = state->probs[re.prob_id];
  if (!prob) BAD_PACKET();

  if (global->score_system == SCORE_OLYMPIAD) {
  } else if (global->score_system == SCORE_KIROV) {
    /*
    if (status != RUN_PARTIAL && status != RUN_OK
        && status != RUN_CHECK_FAILED) goto bad_packet_error;
    */
    if (reply_pkt->score < 0
        || reply_pkt->score > prob->full_score)
      BAD_PACKET();
    /*
    for (n = 0; n < serve_state.probs[re.prob_id]->dp_total; n++)
      if (re.timestamp < serve_state.probs[re.prob_id]->dp_infos[n].deadline)
        break;
    if (n < serve_state.probs[re.prob_id]->dp_total) {
      score += serve_state.probs[re.prob_id]->dp_infos[n].penalty;
      if (score > serve_state.probs[re.prob_id]->full_score)
        score = serve_state.probs[re.prob_id]->full_score;
      if (score < 0) score = 0;
    }
    */
  } else if (global->score_system == SCORE_MOSCOW) {
    if (reply_pkt->score < 0
        || reply_pkt->score > prob->full_score)
      BAD_PACKET();
  } else {
    reply_pkt->score = -1;
  }

  if (global->score_system == SCORE_OLYMPIAD
      && reply_pkt->status == RUN_ACCEPTED
      && prob->ignore_prev_ac > 0) {
    ignore_prev_ac = 1;
  } else if (prob->ok_status && *prob->ok_status && reply_pkt->status == RUN_OK) {
    int status = 0;
    if (run_str_short_to_status(prob->ok_status, &status) >= 0) {
      reply_pkt->status = status;
      if (prob->ignore_prev_ac > 0) ignore_prev_ac = 1;
    }
  } else if (prob->use_ac_not_ok > 0 && reply_pkt->status == RUN_OK) {
    reply_pkt->status = RUN_PENDING_REVIEW;
    if (prob->ignore_prev_ac > 0) ignore_prev_ac = 1;
  } else if (reply_pkt->has_user_score > 0 && reply_pkt->user_status == RUN_ACCEPTED && prob->ignore_prev_ac > 0) {
    ignore_prev_ac = 1;
  }
  if (reply_pkt->status == RUN_CHECK_FAILED) {
    serve_send_check_failed_email(config, cnts, reply_pkt->run_id);
    serve_telegram_check_failed(config, cnts, state, reply_pkt->run_id, &re);
  }
  if (reply_pkt->marked_flag < 0) reply_pkt->marked_flag = 0;
  if (reply_pkt->status == RUN_CHECK_FAILED) {
    if (run_change_status_4(state->runlog_state, reply_pkt->run_id,
                            reply_pkt->status, &re) < 0)
      goto failed;
    serve_notify_run_update(config, state, &re);
  } else {
    int has_user_score = 0;
    int user_status = 0;
    int user_tests_passed = 0;
    int user_score = 0;
    if (global->separate_user_score > 0 && reply_pkt->has_user_score) {
      has_user_score = 1;
      user_status = reply_pkt->user_status;
      user_tests_passed = reply_pkt->user_tests_passed;
      user_score = reply_pkt->user_score;
    }
    if (run_change_status_3(state->runlog_state, reply_pkt->run_id,
                            reply_pkt->status, reply_pkt->tests_passed, 1,
                            reply_pkt->score, reply_pkt->marked_flag,
                            has_user_score, user_status, user_tests_passed,
                            user_score, reply_pkt->verdict_bits, &re) < 0)
      goto failed;
    serve_notify_run_update(config, state, &re);
  }
  serve_update_standings_file(extra, state, cnts, 0);
  if (global->notify_status_change > 0 && !re.is_hidden
      && reply_pkt->notify_flag) {
    serve_notify_user_run_status_change(config, cnts, state, re.user_id,
                                        reply_pkt->run_id, reply_pkt->status);
  }
  if (prob && prob->notify_on_submit > 0) {
    serve_telegram_notify_on_submit(config, cnts, state, reply_pkt->run_id, &re, reply_pkt->status);
  }

  // read the new testing report
  if (generic_read_file(&new_rep_text, 0, &new_rep_len, REMOVE, run_report_dir, pname, NULL) < 0) {
    goto failed;
  }

  // try to read the existing testing report
  cur_rep_flag = serve_make_xml_report_read_path(state, cur_rep_path, sizeof(cur_rep_path), &re);
  if (cur_rep_flag >= 0) {
    if (re.store_flags == STORE_FLAGS_UUID_BSON) {
      cur_tr = testing_report_parse_bson_file(cur_rep_path);
      if (cur_tr && cur_tr->compiler_output) {
        compiler_output = cur_tr->compiler_output; cur_tr->compiler_output = NULL;
        testing_report_free(cur_tr); cur_tr = NULL;
      }
    } else {
      if (generic_read_file(&cur_rep_text, 0, &cur_rep_len, cur_rep_flag, 0, cur_rep_path, 0) >= 0) {
        const unsigned char *cur_start_ptr = NULL;
        int cur_content_type = get_content_type(cur_rep_text, &cur_start_ptr);
        if (cur_content_type == CONTENT_TYPE_XML && cur_start_ptr) {
          cur_tr = testing_report_parse_xml(cur_start_ptr);
          if (cur_tr && cur_tr->compiler_output) {
            compiler_output = cur_tr->compiler_output; cur_tr->compiler_output = NULL;
          }
          testing_report_free(cur_tr); cur_tr = NULL;
        }
        xfree(cur_rep_text); cur_rep_text = NULL;
      }
    }
  }

  // try to merge the testing reports
  if (compiler_output) {
    if (re.store_flags == STORE_FLAGS_UUID_BSON) {
      if ((new_tr = testing_report_parse_bson_data(new_rep_text, new_rep_len))) {
        if (new_tr && !new_tr->compiler_output) {
          new_tr->compiler_output = compiler_output; compiler_output = NULL;
          xfree(new_rep_text); new_rep_text = NULL; new_rep_len = 0;
          testing_report_to_mem_bson(&new_rep_text, &new_rep_len, new_tr);
        }
        testing_report_free(new_tr); new_tr = NULL;
        xfree(compiler_output); compiler_output = NULL;
      }
    } else {
      const unsigned char *new_start_ptr = NULL;
      int new_content_type = get_content_type(new_rep_text, &new_start_ptr);
      if (new_content_type == CONTENT_TYPE_XML && new_start_ptr) {
        new_tr = testing_report_parse_xml(new_start_ptr);
        if (new_tr && !new_tr->compiler_output) {
          new_tr->compiler_output = compiler_output; compiler_output = NULL;
          xfree(new_rep_text); new_rep_text = NULL; new_rep_len = 0;
          testing_report_to_str(&new_rep_text, &new_rep_len, 1, new_tr);
        }
        testing_report_free(new_tr); new_tr = NULL;
        xfree(compiler_output); compiler_output = NULL;
      }
    }
  }

  if (re.store_flags == STORE_FLAGS_UUID_BSON) {
    rep_flags = uuid_archive_prepare_write_path(state, rep_path, sizeof(rep_path),
                                                &re.run_uuid, new_rep_len, DFLT_R_UUID_BSON_REPORT, -1, 0);
  } else if (re.store_flags == STORE_FLAGS_UUID) {
    rep_flags = uuid_archive_prepare_write_path(state, rep_path, sizeof(rep_path),
                                                &re.run_uuid, new_rep_len, DFLT_R_UUID_XML_REPORT, 0, 0);
  } else {
    rep_flags = archive_prepare_write_path(state, rep_path, sizeof(rep_path),
                                           global->xml_report_archive_dir, reply_pkt->run_id,
                                           new_rep_len, NULL, 0, 0);
  }
  if (rep_flags < 0)
    goto failed;

  // save the new testing report
  if (generic_write_file(new_rep_text, new_rep_len, rep_flags, 0, rep_path, 0) < 0) {
    goto failed;
  }

  if (global->enable_full_archive) {
    full_flags = -1;
    if (generic_file_size(run_full_archive_dir, pname, ".zip") >= 0) {
      full_flags = ZIP;
      full_suffix = ".zip";
    }
    if (re.store_flags == STORE_FLAGS_UUID || re.store_flags == STORE_FLAGS_UUID_BSON) {
      full_flags = uuid_archive_prepare_write_path(state, full_path, sizeof(full_path),
                                                   &re.run_uuid, 0, DFLT_R_UUID_FULL_ARCHIVE, full_flags, 0);
    } else {
      full_flags = archive_prepare_write_path(state, full_path, sizeof(full_path),
                                              global->full_archive_dir,
                                              reply_pkt->run_id, 0, NULL, full_flags, 0);
    }
    if (full_flags < 0)
      goto failed;
    if (generic_copy_file(REMOVE, run_full_archive_dir, pname, full_suffix,
                          full_flags, 0, full_path, "") < 0)
      goto failed;
  }

  /* add auditing information */
  if (!(f = open_memstream(&audit_text, &audit_text_size))) return 1;
  fprintf(f, "  Profiling information:\n");
  fprintf(f, "  Request start time:                %s\n",
          time_to_str(time_buf, sizeof(time_buf),
                      reply_pkt->ts1, reply_pkt->ts1_us));
  fprintf(f, "  Request completion time:           %s\n",
          time_to_str(time_buf, sizeof(time_buf),
                      ts8, ts8_us));
  fprintf(f, "  Total testing duration:            %s\n",
          dur_to_str(time_buf, sizeof(time_buf),
                     reply_pkt->ts1, reply_pkt->ts1_us,
                     ts8, ts8_us));
  fprintf(f, "  Waiting in compile queue duration: %s\n",
          dur_to_str(time_buf, sizeof(time_buf),
                     reply_pkt->ts1, reply_pkt->ts1_us,
                     reply_pkt->ts2, reply_pkt->ts2_us));
  fprintf(f, "  Compilation duration:              %s\n",
          dur_to_str(time_buf, sizeof(time_buf),
                     reply_pkt->ts2, reply_pkt->ts2_us,
                     reply_pkt->ts3, reply_pkt->ts3_us));
  fprintf(f, "  Waiting in serve queue duration:   %s\n",
          dur_to_str(time_buf, sizeof(time_buf),
                     reply_pkt->ts3, reply_pkt->ts3_us,
                     reply_pkt->ts4, reply_pkt->ts4_us));
  fprintf(f, "  Waiting in run queue duration:     %s\n",
          dur_to_str(time_buf, sizeof(time_buf),
                     reply_pkt->ts4, reply_pkt->ts4_us,
                     reply_pkt->ts5, reply_pkt->ts5_us));
  fprintf(f, "  Testing duration:                  %s\n",
          dur_to_str(time_buf, sizeof(time_buf),
                     reply_pkt->ts5, reply_pkt->ts5_us,
                     reply_pkt->ts6, reply_pkt->ts6_us));
  fprintf(f, "  Post-processing duration:          %s\n",
          dur_to_str(time_buf, sizeof(time_buf),
                     reply_pkt->ts6, reply_pkt->ts6_us,
                     reply_pkt->ts7, reply_pkt->ts7_us));
  fprintf(f, "  Waiting in serve queue duration:   %s\n",
          dur_to_str(time_buf, sizeof(time_buf),
                     reply_pkt->ts7, reply_pkt->ts7_us,
                     ts8, ts8_us));
  fprintf(f, "\n");
  close_memstream(f); f = 0;
  serve_audit_log(state, reply_pkt->run_id, &re, 0, 0, 0,
                  NULL, "testing completed", reply_pkt->status, "%s", audit_text);
  xfree(audit_text); audit_text = 0;

  if (ignore_prev_ac) {
    for (i = reply_pkt->run_id - 1; i >= 0; --i) {
      if (run_get_entry(state->runlog_state, i, &pe) < 0) continue;
      if ((pe.status == RUN_ACCEPTED || pe.status == RUN_PENDING_REVIEW)
          && pe.prob_id == re.prob_id && pe.user_id == re.user_id) {
        run_change_status_3(state->runlog_state, i, RUN_IGNORED, 0, 1, 0, 0, 0, 0, 0, 0, 0, &re);
        serve_notify_run_update(config, state, &re);
      } else if (pe.is_saved && (pe.saved_status == RUN_ACCEPTED || pe.saved_status == RUN_PENDING_REVIEW)
          && pe.prob_id == re.prob_id && pe.user_id == re.user_id) {
        run_change_status_3(state->runlog_state, i, RUN_IGNORED, 0, 1, 0, 0, 0, 0, 0, 0, 0, &re);
        serve_notify_run_update(config, state, &re);
      }
    }
  }

  run_reply_packet_free(reply_pkt);
  testing_report_free(cur_tr);
  testing_report_free(new_tr);
  xfree(cur_rep_text);
  xfree(compiler_output);
  xfree(new_rep_text);

  return 1;

 bad_packet_error:
  err("bad_packet: %s, %d", __FILE__, bad_packet_line);

 failed:
  xfree(reply_buf);
  run_reply_packet_free(reply_pkt);
  testing_report_free(cur_tr);
  testing_report_free(new_tr);
  xfree(cur_rep_text);
  xfree(compiler_output);
  xfree(new_rep_text);
  return 0;
}

static const char * const scoring_system_strs[] =
{
  [SCORE_ACM] = "ACM",
  [SCORE_KIROV] = "KIROV",
  [SCORE_OLYMPIAD] = "OLYMPIAD",
  [SCORE_MOSCOW] = "MOSCOW",
};
static const unsigned char *
unparse_scoring_system(unsigned char *buf, size_t size, int val)
{
  if (val >= SCORE_ACM && val < SCORE_TOTAL) return scoring_system_strs[val];
  snprintf(buf, size, "scoring_%d", val);
  return buf;
}

void
serve_judge_built_in_problem(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        int run_id,
        int judge_id,
        const ej_uuid_t *judge_uuid,
        int variant,
        int accepting_mode,
        struct run_entry *re,
        const struct section_problem_data *prob,
        problem_xml_t px,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag)
{
  const struct section_global_data *global = state->global;
  int arch_flags, n, status, rep_flags, glob_status;
  path_t run_arch_path, rep_path;
  char *run_text = 0, *eptr = 0;
  size_t run_size = 0;
  unsigned char msgbuf[1024] = { 0 }, buf1[128], buf2[128];
  char *xml_buf = 0;
  size_t xml_len = 0;
  FILE *f = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int passed_tests = 0, score = 0, failed_test = 1;

  arch_flags = serve_make_source_read_path(state, run_arch_path, sizeof(run_arch_path), re);
  if (arch_flags < 0) {
    snprintf(msgbuf, sizeof(msgbuf), "User answer file does not exist.");
    status = RUN_CHECK_FAILED;
    goto done;
  }
  if (generic_read_file(&run_text, 0, &run_size, arch_flags,
                        0, run_arch_path, 0) < 0) {
    snprintf(msgbuf, sizeof(msgbuf), "User answer file read error.");
    status = RUN_CHECK_FAILED;
    goto done;
  }
  if (strlen(run_text) != run_size) {
    snprintf(msgbuf, sizeof(msgbuf), "User answer file is binary.");
    status = RUN_PRESENTATION_ERR;
    goto done;
  }
  while (run_size > 0 && isspace(run_text[run_size - 1])) run_size--;
  run_text[run_size] = 0;

  errno = 0;
  n = strtol(run_text, &eptr, 10);
  if (*eptr || errno) {
    snprintf(msgbuf, sizeof(msgbuf), "Number expected in user answer file.");
    status = RUN_PRESENTATION_ERR;
    goto done;
  }
  if (n <= 0 || n > px->ans_num) {
    snprintf(msgbuf, sizeof(msgbuf), "Number is out of range.");
    status = RUN_PRESENTATION_ERR;
    goto done;
  }
  if (n != px->correct_answer) {
    snprintf(msgbuf, sizeof(msgbuf), "Wrong answer.");
    status = RUN_WRONG_ANSWER_ERR;
    goto done;
  }

  passed_tests = 1;
  failed_test = 0;
  score = prob->full_score;
  status = RUN_OK;

 done:
  glob_status = status;
  if (global->score_system == SCORE_OLYMPIAD
      || global->score_system == SCORE_KIROV) {
    if (glob_status != RUN_OK && glob_status != RUN_CHECK_FAILED)
      glob_status = RUN_PARTIAL;
  }
  f = open_memstream(&xml_buf, &xml_len);
  fprintf(f, "Content-type: text/xml\n\n");
  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\"?>\n", EJUDGE_CHARSET);
  run_status_to_str_short(buf1, sizeof(buf1), glob_status);
  fprintf(f, "<testing-report run-id=\"%d\" judge-id=\"%d\" status=\"%s\" scoring=\"%s\" archive-available=\"no\" run-tests=\"1\" correct-available=\"no\" info-available=\"no\"",
          run_id, judge_id, buf1,
          unparse_scoring_system(buf2, sizeof(buf2), global->score_system));
  if (variant > 0) {
    fprintf(f, " variant=\"%d\"", variant);
  }
  if (global->score_system == SCORE_OLYMPIAD) {
    fprintf(f, " accepting-mode=\"%s\"", accepting_mode?"yes":"no");
  }
  if (global->score_system == SCORE_OLYMPIAD && accepting_mode
      && status != RUN_ACCEPTED) {
    fprintf(f, " failed-test=\"1\"");
  } else if (global->score_system == SCORE_ACM && status != RUN_OK) {
    fprintf(f, " failed-test=\"1\"");
  } else if (global->score_system == SCORE_OLYMPIAD && !accepting_mode) {
    fprintf(f, " tests-passed=\"%d\" score=\"%d\" max-score=\"%d\"",
            passed_tests, score, prob->full_score);
  } else if (global->score_system == SCORE_KIROV) {
    fprintf(f, " tests-passed=\"%d\" score=\"%d\" max-score=\"%d\"",
            passed_tests, score, prob->full_score);
  } else if (global->score_system == SCORE_MOSCOW) {
    if (status != RUN_OK) {
      fprintf(f, " failed-test=\"1\"");
    }
    fprintf(f, " score=\"%d\" max-score=\"%d\"", score, prob->full_score);
  }
  fprintf(f, " >\n");

  run_status_to_str_short(buf1, sizeof(buf1), status);
  fprintf(f, "  <tests>\n");
  fprintf(f, "    <test num=\"1\" status=\"%s\"", buf1);
  fprintf(f, " exit-code=\"0\"");
  fprintf(f, " time=\"0\"");
  fprintf(f, " real-time=\"0\"");
  if (global->score_system == SCORE_OLYMPIAD && !accepting_mode) {
    fprintf(f, " nominal-score=\"%d\" score=\"%d\"", prob->full_score, score);
  } else if (global->score_system == SCORE_KIROV) {
    fprintf(f, " nominal-score=\"%d\" score=\"%d\"", prob->full_score, score);
  }
  if (msgbuf[0]) {
    fprintf(f, " checker-comment=\"%s\"", ARMOR(msgbuf));
  }
  fprintf(f, " >\n");

  /*
    if (tests[i].input_size >= 0 && !req_pkt->full_archive) {
      fprintf(f, "      <input>");
      html_print_by_line(f, tests[i].input, tests[i].input_size);
      fprintf(f, "</input>\n");
    }
  */

  fprintf(f, "      <output>%s\n\n</output>\n", ARMOR(run_text));
  fprintf(f, "      <correct>%d\n\n</correct>\n", px->correct_answer);
  fprintf(f, "      <checker>%s\n\n</checker>\n", ARMOR(msgbuf));
  fprintf(f, "    </test>\n");
  fprintf(f, "  </tests>\n");
  fprintf(f, "</testing-report>\n");
  close_memstream(f); f = 0;

  serve_audit_log(state, run_id, NULL, user_id, ip, ssl_flag,
                  "submit", "ok", status, NULL);

  if (status == RUN_CHECK_FAILED) {
    serve_send_check_failed_email(config, cnts, run_id);
    serve_telegram_check_failed(config, cnts, state, run_id, re);
  }

  /* FIXME: handle database update error */
  (void) failed_test;
  run_change_status_3(state->runlog_state, run_id, glob_status, passed_tests, 1,
                      score, 0, 0, 0, 0, 0, 0, re);
  serve_notify_run_update(config, state, re);
  serve_update_standings_file(extra, state, cnts, 0);
  /*
  if (global->notify_status_change > 0 && !re.is_hidden
      && comp_extra->notify_flag) {
    serve_notify_user_run_status_change(cnts, state, re.user_id,
                                        run_id, glob_status);
  }
  */

  // FIXME: handle errors
  run_get_entry(state->runlog_state, run_id, re);

  if (re->store_flags == STORE_FLAGS_UUID_BSON) {
    // FIXME: this sucks, FIX report generation (above) to create internal structure instead of text
    const unsigned char *start_ptr = NULL;
    int content_type = get_content_type(xml_buf, &start_ptr);
    if (content_type == CONTENT_TYPE_XML && start_ptr) {
      testing_report_xml_t tr = testing_report_parse_xml(start_ptr);
      if (tr) {
        free(xml_buf); xml_buf = NULL; xml_len = 0;
        testing_report_to_mem_bson(&xml_buf, &xml_len, tr);
        testing_report_free(tr);
        rep_flags = uuid_archive_prepare_write_path(state, rep_path, sizeof(rep_path),
                                                    &re->run_uuid, xml_len, DFLT_R_UUID_BSON_REPORT, -1, 0);
        generic_write_file(xml_buf, xml_len, rep_flags, 0, rep_path, "");
      }
    }
  } else {
    if (re->store_flags == STORE_FLAGS_UUID) {
      rep_flags = uuid_archive_prepare_write_path(state, rep_path, sizeof(rep_path),
                                                  &re->run_uuid, xml_len, DFLT_R_UUID_XML_REPORT, 0, 0);
    } else {
      rep_flags = archive_prepare_write_path(state, rep_path, sizeof(rep_path),
                                             global->xml_report_archive_dir, run_id,
                                             xml_len, NULL, 0, 0);
    }
    generic_write_file(xml_buf, xml_len, rep_flags, 0, rep_path, "");
  }

  xfree(xml_buf); xml_buf = 0;
  html_armor_free(&ab);
}

void
serve_report_check_failed(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t state,
        int run_id,
        const unsigned char *error_text)
{
  const struct section_global_data *global = state->global;
  testing_report_xml_t tr = testing_report_alloc(cnts->id, run_id, 0, NULL);
  size_t tr_z = 0;
  char *tr_t = NULL;
  unsigned char tr_p[PATH_MAX];
  int flags = 0;
  struct run_entry re;

  run_get_entry(state->runlog_state, run_id, &re);

  serve_audit_log(state, run_id, &re, 0, 0, 0,
                  NULL, "check failed", -1,
                  "  %s\n\n", error_text);

  tr->status = RUN_CHECK_FAILED;
  tr->scoring_system = global->score_system;
  tr->marked_flag = 0;
  tr->user_status = -1;
  tr->errors = xstrdup(error_text);

  if (re.store_flags == STORE_FLAGS_UUID_BSON) {
    testing_report_to_mem_bson(&tr_t, &tr_z, tr);
    tr = testing_report_free(tr);
    flags = uuid_archive_prepare_write_path(state, tr_p, sizeof(tr_p),
                                            &re.run_uuid, tr_z, DFLT_R_UUID_BSON_REPORT, -1, 0);
  } else {
    testing_report_to_str(&tr_t, &tr_z, 1/*utf8_mode*/, tr);
    tr = testing_report_free(tr);

    if (re.store_flags == STORE_FLAGS_UUID) {
      flags = uuid_archive_prepare_write_path(state, tr_p, sizeof(tr_p),
                                              &re.run_uuid, tr_z, DFLT_R_UUID_XML_REPORT, 0, 0);
    } else {
      flags = archive_prepare_write_path(state, tr_p, sizeof(tr_p), global->xml_report_archive_dir, run_id,
                                         tr_z, NULL, 0, 0);
    }
  }
  if (flags < 0) {
    err("archive_make_write_path: %s, %d, %ld failed\n", global->xml_report_archive_dir, run_id, (long) tr_z);
  } else {
    generic_write_file(tr_t, tr_z, flags, NULL, tr_p, NULL);
  }
  xfree(tr_t); tr_t = NULL;

  if (run_change_status_4(state->runlog_state, run_id,
                          RUN_CHECK_FAILED, &re) < 0) {
    err("run_change_status_4: %d, RUN_CHECK_FAILED failed\n", run_id);
  }
  serve_notify_run_update(config, state, &re);
}

void
serve_rejudge_run(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t state,
        int run_id,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int force_full_rejudge,
        int priority_adjustment)
{
  const struct section_global_data *global = state->global;
  struct run_entry re;
  int accepting_mode = -1, arch_flags = 0, r;
  path_t run_arch_path;
  char *run_text = 0;
  size_t run_size = 0;
  const struct section_problem_data *prob = 0;
  const struct section_language_data *lang = 0;
  problem_xml_t px = 0;
  int variant = 0;

  if (run_get_entry(state->runlog_state, run_id, &re) < 0) return;
  if (re.is_imported) return;
  if (re.is_readonly) return;

  const struct userlist_user *user = NULL;
  if (re.user_id > 0) {
    user = teamdb_get_userlist(state->teamdb_state, re.user_id);
  }

  serve_audit_log(state, run_id, &re, user_id, ip, ssl_flag,
                  "rejudge", "ok", RUN_COMPILING, NULL);

  if (re.prob_id <= 0 || re.prob_id > state->max_prob
      || !(prob = state->probs[re.prob_id])) {
    err("rejudge_run: bad problem: %d", re.prob_id);
    return;
  }
  if (prob->manual_checking > 0
      || (prob->disable_testing > 0 && prob->enable_compilation <= 0)) return;
  if (prob->type > 0) {
    if (force_full_rejudge && global->score_system == SCORE_OLYMPIAD) {
      accepting_mode = 0;
    }

    if (prob->variant_num > 0) {
      if (variant <= 0)
        variant = re.variant;
      if (variant <= 0)
        variant = find_variant(state, re.user_id, re.prob_id, 0);
      if (variant <= 0 || variant > prob->variant_num) {
        err("rejudge_run: invalid variant for run %d", run_id);
        return;
      }
      if (prob->xml.a) px = prob->xml.a[variant - 1];
    } else {
      px = prob->xml.p;
    }

    if (prob->type == PROB_TYPE_SELECT_ONE && px && px->ans_num > 0) {
      serve_judge_built_in_problem(extra, config, state, cnts, run_id,
                                   1 /* judge_id*/,
                                   NULL, /* judge_uuid */
                                   variant, accepting_mode, &re, prob,
                                   px, user_id, ip, ssl_flag);
      return;
    }

    if (prob->style_checker_cmd && prob->style_checker_cmd[0]) {
      r = serve_compile_request(config, state, 0 /* str*/, -1 /* len*/, cnts->id,
                                run_id, 0 /* submit_id */, re.user_id,
                                re.variant,
                                0 /* locale_id */, 1 /* output_only*/,
                                mime_type_get_suffix(re.mime_type),
                                1 /* style_check_only */,
                                0 /* accepting_mode */,
                                priority_adjustment,
                                1 /* notify flag */,
                                prob, NULL /* lang */,
                                0 /* no_db_flag */, &re.run_uuid,
                                NULL /* judge_uuid */,
                                re.store_flags,
                                1 /* rejudge_flag */,
                                re.is_vcs /* vcs_mode */,
                                0 /* not_ok_is_cf */,
                                user,
                                NULL);
      if (r < 0) {
        serve_report_check_failed(config, cnts, state, run_id, serve_err_str(r));
        err("rejudge_run: serve_compile_request failed: %s", serve_err_str(r));
        return;
      }
      return;
    }

    arch_flags = serve_make_source_read_path(state, run_arch_path, sizeof(run_arch_path), &re);
    if (arch_flags < 0) return;
    if (generic_read_file(&run_text, 0, &run_size, arch_flags,
                          0, run_arch_path, 0) < 0)
      return;

    serve_run_request(config, state, cnts, stderr, run_text, run_size,
                      cnts->id, run_id,
                      0 /* submit_id */,
                      re.user_id, re.prob_id, re.lang_id,
                      re.variant, priority_adjustment,
                      -1,       /* judge_id */
                      NULL,     /* judge_uuid */
                      accepting_mode, 1, re.mime_type, re.eoln_type,
                      re.locale_id, 0, 0, 0, &re.run_uuid,
                      1 /* rejudge_flag */, 0 /* zip_mode */, re.store_flags,
                      0 /* not_ok_is_cf */,
                      NULL, 0,
                      &re,
                      NULL /* src_text */,
                      0 /* src_size */);
    xfree(run_text);
    return;
  }

  if (re.lang_id <= 0 || re.lang_id > state->max_lang
      || !(lang = state->langs[re.lang_id])) {
    err("rejudge_run: bad language: %d", re.lang_id);
    return;
  }

  if (force_full_rejudge && global->score_system == SCORE_OLYMPIAD) {
    accepting_mode = 0;
  }

  r = serve_compile_request(config, state, 0, -1, cnts->id, run_id, 0 /* submit_id */, re.user_id,
                            re.variant, re.locale_id,
                            (prob->type > 0),
                            lang->src_sfx,
                            0,
                            accepting_mode, priority_adjustment, 1, prob, lang, 0,
                            &re.run_uuid,
                            NULL /* judge_uuid */,
                            re.store_flags,
                            1 /* rejudge_flag */,
                            re.is_vcs /* vcs_mode */,
                            0 /* not_ok_is_cf */,
                            user,
                            NULL);
  if (r < 0) {
    serve_report_check_failed(config, cnts, state, run_id, serve_err_str(r));
    err("rejudge_run: serve_compile_request failed: %s", serve_err_str(r));
    return;
  }
}

void
serve_invoke_start_script(serve_state_t state)
{
  tpTask tsk = 0;
  const unsigned char *contest_start_cmd = state->global->contest_start_cmd;

  if (!contest_start_cmd || !contest_start_cmd[0]) return;
  if (!(tsk = task_New())) return;
  task_AddArg(tsk, contest_start_cmd);
  task_SetPathAsArg0(tsk);
  if (task_Start(tsk) < 0) {
    task_Delete(tsk);
    return;
  }
  task_Wait(tsk);
  task_Delete(tsk);
}

void
serve_invoke_stop_script(serve_state_t state)
{
  tpTask tsk = 0;

  if (!state->global->contest_stop_cmd) return;
  if (!state->global->contest_stop_cmd[0]) return;
  if (!(tsk = task_New())) return;
  task_AddArg(tsk, state->global->contest_stop_cmd);
  task_SetPathAsArg0(tsk);
  if (task_Start(tsk) < 0) {
    task_Delete(tsk);
    return;
  }
  task_Wait(tsk);
  task_Delete(tsk);
}

static unsigned char olympiad_rejudgeable_runs[RUN_STATUS_SIZE] =
{
  [RUN_OK]               = 1,
  [RUN_COMPILE_ERR]      = 0,
  [RUN_RUN_TIME_ERR]     = 0,
  [RUN_TIME_LIMIT_ERR]   = 0,
  [RUN_WALL_TIME_LIMIT_ERR] = 0,
  [RUN_PRESENTATION_ERR] = 0,
  [RUN_WRONG_ANSWER_ERR] = 0,
  [RUN_CHECK_FAILED]     = 0,
  [RUN_PARTIAL]          = 1,
  [RUN_ACCEPTED]         = 1,
  [RUN_PENDING_REVIEW]   = 1,
  [RUN_SUMMONED]         = 1,
  [RUN_IGNORED]          = 0,
  [RUN_DISQUALIFIED]     = 0,
  [RUN_PENDING]          = 0,
  [RUN_MEM_LIMIT_ERR]    = 0,
  [RUN_SECURITY_ERR]     = 0,
  [RUN_SYNC_ERR]         = 0,
  [RUN_STYLE_ERR]        = 0,
  [RUN_REJECTED]         = 0,
  [RUN_VIRTUAL_START]    = 0,
  [RUN_VIRTUAL_STOP]     = 0,
  [RUN_EMPTY]            = 0,
  [RUN_RUNNING]          = 1,
  [RUN_COMPILED]         = 1,
  [RUN_COMPILING]        = 1,
  [RUN_AVAILABLE]        = 1,
};

static unsigned char olympiad_output_only_rejudgeable_runs[RUN_STATUS_SIZE] =
{
  [RUN_OK]               = 1,
  [RUN_COMPILE_ERR]      = 0,
  [RUN_RUN_TIME_ERR]     = 0,
  [RUN_TIME_LIMIT_ERR]   = 0,
  [RUN_WALL_TIME_LIMIT_ERR] = 0,
  [RUN_PRESENTATION_ERR] = 0,
  [RUN_WRONG_ANSWER_ERR] = 1,
  [RUN_CHECK_FAILED]     = 0,
  [RUN_PARTIAL]          = 1,
  [RUN_ACCEPTED]         = 1,
  [RUN_PENDING_REVIEW]   = 1,
  [RUN_SUMMONED]         = 1,
  [RUN_IGNORED]          = 0,
  [RUN_DISQUALIFIED]     = 0,
  [RUN_PENDING]          = 0,
  [RUN_MEM_LIMIT_ERR]    = 0,
  [RUN_SECURITY_ERR]     = 0,
  [RUN_SYNC_ERR]         = 0,
  [RUN_STYLE_ERR]        = 0,
  [RUN_REJECTED]         = 0,
  [RUN_VIRTUAL_START]    = 0,
  [RUN_VIRTUAL_STOP]     = 0,
  [RUN_EMPTY]            = 0,
  [RUN_RUNNING]          = 1,
  [RUN_COMPILED]         = 1,
  [RUN_COMPILING]        = 1,
  [RUN_AVAILABLE]        = 1,
};

static unsigned char generally_rejudgable_runs[RUN_STATUS_SIZE] =
{
  [RUN_OK]               = 1,
  [RUN_COMPILE_ERR]      = 1,
  [RUN_RUN_TIME_ERR]     = 1,
  [RUN_TIME_LIMIT_ERR]   = 1,
  [RUN_WALL_TIME_LIMIT_ERR] = 1,
  [RUN_PRESENTATION_ERR] = 1,
  [RUN_WRONG_ANSWER_ERR] = 1,
  [RUN_CHECK_FAILED]     = 1,
  [RUN_PARTIAL]          = 1,
  [RUN_ACCEPTED]         = 1,
  [RUN_PENDING_REVIEW]   = 1,
  [RUN_SUMMONED]         = 1,
  [RUN_IGNORED]          = 1,
  [RUN_DISQUALIFIED]     = 1,
  [RUN_PENDING]          = 1,
  [RUN_MEM_LIMIT_ERR]    = 1,
  [RUN_SECURITY_ERR]     = 1,
  [RUN_SYNC_ERR]         = 1,
  [RUN_STYLE_ERR]        = 1,
  [RUN_REJECTED]         = 1,
  [RUN_VIRTUAL_START]    = 0,
  [RUN_VIRTUAL_STOP]     = 0,
  [RUN_EMPTY]            = 0,
  [RUN_RUNNING]          = 1,
  [RUN_COMPILED]         = 1,
  [RUN_COMPILING]        = 1,
  [RUN_AVAILABLE]        = 1,
};

static int
is_generally_rejudgable(const serve_state_t state,
                        const struct run_entry *pe,
                        int total_users)
{
  const struct section_problem_data *prob = 0;
  const struct section_language_data *lang = 0;

  if (((unsigned) pe->status) >= RUN_STATUS_SIZE) return 0;
  if (!generally_rejudgable_runs[pe->status]) return 0;
  if (pe->is_imported) return 0;
  if (pe->is_readonly) return 0;
  if (pe->user_id <= 0 || pe->user_id >= total_users) return 0;
  if (pe->prob_id <= 0 || pe->prob_id > state->max_prob
      || !(prob = state->probs[pe->prob_id])) return 0;
  if (prob->disable_testing) return 0;
  if (prob->type == PROB_TYPE_STANDARD) {
    if (pe->lang_id <= 0 || pe->lang_id > state->max_lang
        || !(lang = state->langs[pe->lang_id])) return 0;
    if (lang->disable_testing) return 0;
  }
  if (prob->manual_checking) return 0;

  return 1;
}

#define BITS_PER_LONG (8*sizeof(unsigned long))

struct rejudge_by_mask_job
{
  struct server_framework_job b;

  struct contest_extra *extra;
  const struct ejudge_cfg *config;
  const struct contest_desc *cnts;
  serve_state_t state;
  int user_id;
  ej_ip_t ip;
  int ssl_flag;
  int mask_size;
  unsigned long *mask;
  int force_flag;
  int priority_adjustment;

  int cur_id;
};

static void
rejudge_by_mask_destroy_func(struct server_framework_job *j)
{
  struct rejudge_by_mask_job* job = (struct rejudge_by_mask_job*) j;

  xfree(job->mask);
  xfree(job);
}

static int
rejudge_by_mask_run_func(
        struct server_framework_job *j,
        int *p_count,
        int max_count)
{
  struct rejudge_by_mask_job* job = (struct rejudge_by_mask_job*) j;

  int total_runs = run_get_total(job->state->runlog_state);
  if (total_runs > job->mask_size * BITS_PER_LONG) {
    total_runs = job->mask_size * BITS_PER_LONG;
  }

  struct run_entry re;
  for (; job->cur_id < total_runs && *p_count < max_count; ++job->cur_id, ++(*p_count)) {
    if (run_get_entry(job->state->runlog_state, job->cur_id, &re) >= 0
        && is_generally_rejudgable(job->state, &re, INT_MAX)
        && (job->mask[job->cur_id / BITS_PER_LONG] & (1L << (job->cur_id % BITS_PER_LONG)))) {
      serve_rejudge_run(job->extra, job->config, job->cnts, job->state, job->cur_id,
                        job->user_id, &job->ip, job->ssl_flag,
                        job->force_flag, job->priority_adjustment);
    }
  }

  return *p_count >= total_runs;
}

static unsigned char *
rejudge_by_mask_get_status_func(
        struct server_framework_job *j)
{
  struct rejudge_by_mask_job *job = (struct rejudge_by_mask_job*) j;

  int total_runs = run_get_total(job->state->runlog_state);
  if (total_runs <= 0 || job->cur_id < 0) {
    return xstrdup("done");
  }
  unsigned char buf[1024];
  snprintf(buf, sizeof(buf), "%lld%% done",
           job->cur_id * 100LL / total_runs);
  return xstrdup(buf);
}

static const struct server_framework_job_funcs rejudge_by_mask_funcs __attribute__((unused)) =
{
  rejudge_by_mask_destroy_func,
  rejudge_by_mask_run_func,
  rejudge_by_mask_get_status_func,
};

static struct server_framework_job *
create_rejudge_by_mask_job(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t state,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int mask_size,
        unsigned long *mask,
        int force_flag,
        int priority_adjustment)
{
  struct rejudge_by_mask_job *job = NULL;

  XCALLOC(job, 1);
  job->extra = extra;
  job->config = config;
  job->cnts = cnts;
  job->state = state;
  job->user_id = user_id;
  job->ip = *ip;
  job->ssl_flag = ssl_flag;
  job->mask_size = mask_size;
  if (mask_size > 0) {
    XCALLOC(job->mask, mask_size);
    memcpy(job->mask, mask, mask_size * sizeof(job->mask[0]));
  }
  job->force_flag = force_flag;
  job->priority_adjustment = priority_adjustment;

  return (struct server_framework_job*) job;
}

/* Since we're provided the exact set of runs to rejudge, we ignore
 * "latest" condition in OLYMPIAD contests, or DISQUALIFIED or IGNORED
 * runs
 */
struct server_framework_job *
serve_rejudge_by_mask(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t state,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int mask_size,
        unsigned long *mask,
        int force_flag,
        int priority_adjustment,
        int create_job_flag)
{
  int total_runs, r;
  struct run_entry re;

  ASSERT(mask_size > 0);

  struct server_framework_job *job = NULL;
  if (create_job_flag) {
    job = create_rejudge_by_mask_job(extra, config, cnts, state, user_id, ip,
                                     ssl_flag, mask_size, mask,
                                     force_flag, priority_adjustment);
    if (job) return job;
  }

  total_runs = run_get_total(state->runlog_state);
  if (total_runs > mask_size * BITS_PER_LONG) {
    total_runs = mask_size * BITS_PER_LONG;
  }

  /*
  if (state->global->score_system == SCORE_OLYMPIAD
      && !state->accepting_mode) {
    // rejudge only "ACCEPTED", "OK", "PARTIAL SOLUTION" runs,
    // considering only the last run for the given problem and
    // the given participant
    total_ids = teamdb_get_max_team_id(state->teamdb_state) + 1;
    total_probs = state->max_prob + 1;
    size = total_ids * total_probs;

    if (total_ids <= 0 || total_probs <= 0) return;
    flag = (unsigned char *) alloca(size);
    memset(flag, 0, size);
    for (r = total_runs - 1; r >= 0; r--) {
      if (run_get_entry(state->runlog_state, r, &re) < 0) continue;
      if (!run_is_source_available(re.status)) continue;
      if (re.is_imported) continue;
      if (re.is_readonly) continue;

      if (re.status != RUN_OK && re.status != RUN_PARTIAL
          && re.status != RUN_ACCEPTED) continue;
      if (re.user_id <= 0 || re.user_id >= total_ids) continue;
      if (re.prob_id <= 0 || re.prob_id >= total_probs) continue;
      if (re.lang_id <= 0 || re.lang_id > state->max_lang) continue;
      if (!state->probs[re.prob_id]
          || state->probs[re.prob_id]->disable_testing) continue;
      if (!state->langs[re.lang_id]
          || state->langs[re.lang_id]->disable_testing) continue;
      if (!(mask[r / BITS_PER_LONG] & (1L << (r % BITS_PER_LONG)))) continue;
      idx = re.user_id * total_probs + re.prob_id;
      if (flag[idx]) continue;
      flag[idx] = 1;
      serve_rejudge_run(state, r, user_id, ip, ssl_flag, 0, 0);
    }
    return;
  }
  */

  for (r = 0; r < total_runs; r++) {
    if (run_get_entry(state->runlog_state, r, &re) >= 0
        && is_generally_rejudgable(state, &re, INT_MAX)
        && (mask[r / BITS_PER_LONG] & (1L << (r % BITS_PER_LONG)))) {
      serve_rejudge_run(extra, config, cnts, state, r, user_id, ip, ssl_flag,
                        force_flag, priority_adjustment);
    }
  }

  return NULL;
}

struct rejudge_problem_job
{
  struct server_framework_job b;

  struct contest_extra *extra;
  const struct ejudge_cfg *config;
  const struct contest_desc *cnts;
  serve_state_t state;
  int user_id;
  ej_ip_t ip;
  int ssl_flag;
  int prob_id;
  int priority_adjustment;

  int cur_id;
};

static void
rejudge_problem_destroy_func(
        struct server_framework_job *j)
{
  struct rejudge_problem_job *job = (struct rejudge_problem_job*) j;

  xfree(job);
}

static int
rejudge_problem_run_func(
        struct server_framework_job *j,
        int *p_count,
        int max_count)
{
  struct rejudge_problem_job *job = (struct rejudge_problem_job*) j;
  struct run_entry re;

  int total_runs = run_get_total(job->state->runlog_state);

  for (; job->cur_id < total_runs && *p_count < max_count; ++job->cur_id, ++(*p_count)) {
    if (run_get_entry(job->state->runlog_state, job->cur_id, &re) >= 0
        && is_generally_rejudgable(job->state, &re, INT_MAX)
        && re.status != RUN_IGNORED && re.status != RUN_DISQUALIFIED
        && re.prob_id == job->prob_id) {
      serve_rejudge_run(job->extra, job->config, job->cnts, job->state, job->cur_id,
                        job->user_id, &job->ip, job->ssl_flag, 0,
                        job->priority_adjustment);
    }
  }

  return *p_count >= max_count;
}

static unsigned char *
rejudge_problem_get_status_func(
        struct server_framework_job *j)
{
  struct rejudge_problem_job *job = (struct rejudge_problem_job*) j;

  int total_runs = run_get_total(job->state->runlog_state);
  if (total_runs <= 0 || job->cur_id < 0) {
    return xstrdup("done");
  }
  unsigned char buf[1024];
  snprintf(buf, sizeof(buf), "%lld%% done",
           job->cur_id * 100LL / total_runs);
  return xstrdup(buf);
}

static const struct server_framework_job_funcs rejudge_problem_funcs __attribute__((unused)) =
{
  rejudge_problem_destroy_func,
  rejudge_problem_run_func,
  rejudge_problem_get_status_func,
};

static struct server_framework_job *
create_rejudge_problem_job(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t state,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int prob_id,
        int priority_adjustment)
{
  struct rejudge_problem_job *job = NULL;

  XCALLOC(job, 1);
  job->extra = extra;
  job->config = config;
  job->cnts = cnts;
  job->state = state;
  job->user_id = user_id;
  job->ip = *ip;
  job->ssl_flag = ssl_flag;
  job->prob_id = prob_id;
  job->priority_adjustment = priority_adjustment;

  return (struct server_framework_job*) job;
}

struct server_framework_job *
serve_rejudge_problem(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t state,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int prob_id,
        int priority_adjustment,
        int create_job_flag)
{
  int total_runs, r;
  struct run_entry re;
  int total_ids;
  unsigned char *flag;

  if (prob_id <= 0 || prob_id > state->max_prob || !state->probs[prob_id]
      || state->probs[prob_id]->disable_testing) return NULL;

  struct server_framework_job *job = NULL;
  if (create_job_flag) {
    job = create_rejudge_problem_job(extra, config, cnts, state, user_id, ip,
                                     ssl_flag, prob_id,
                                     priority_adjustment);
    if (job) return job;
  }

  total_runs = run_get_total(state->runlog_state);

  if (state->global->score_system == SCORE_OLYMPIAD
      && !state->accepting_mode) {
    // rejudge only "ACCEPTED", "OK", "PARTIAL SOLUTION" runs,
    // considering only the last run for the given participant
    if (state->global->disable_user_database > 0) {
      total_ids = run_get_max_user_id(state->runlog_state) + 1;
    } else {
      total_ids = teamdb_get_max_team_id(state->teamdb_state) + 1;
    }

    if (total_ids <= 0) return NULL;
    flag = (unsigned char *) alloca(total_ids);
    memset(flag, 0, total_ids);
    for (r = total_runs - 1; r >= 0; r--) {
      if (run_get_entry(state->runlog_state, r, &re) < 0) continue;
      if (!is_generally_rejudgable(state, &re, total_ids)) continue;
      if (state->probs[re.prob_id]->type != PROB_TYPE_STANDARD) {
        if (!olympiad_output_only_rejudgeable_runs[re.status]) continue;
      } else {
        if (!olympiad_rejudgeable_runs[re.status]) continue;
      }
      if (re.prob_id != prob_id) continue;
      if (flag[re.user_id]) continue;
      flag[re.user_id] = 1;
      serve_rejudge_run(extra, config, cnts, state, r, user_id, ip, ssl_flag, 0,
                        priority_adjustment);
    }
    return NULL;
  }

  for (r = 0; r < total_runs; r++) {
    if (run_get_entry(state->runlog_state, r, &re) >= 0
        && is_generally_rejudgable(state, &re, INT_MAX)
        && re.status != RUN_IGNORED && re.status != RUN_DISQUALIFIED
        && re.prob_id == prob_id) {
      serve_rejudge_run(extra, config, cnts, state, r, user_id, ip, ssl_flag, 0,
                        priority_adjustment);
    }
  }
  return NULL;
}

struct judge_suspended_job
{
  struct server_framework_job b;

  struct contest_extra *extra;
  const struct ejudge_cfg *config;
  const struct contest_desc *cnts;
  serve_state_t state;
  int user_id;
  ej_ip_t ip;
  int ssl_flag;
  int priority_adjustment;

  int total_runs;
  int cur_run;
};

static void
judge_suspended_destroy_func(
        struct server_framework_job *job)
{
  xfree(job->title);
  xfree(job);
}

static int
judge_suspended_run_func(
        struct server_framework_job *job,
        int *p_count,
        int max_count)
{
  struct judge_suspended_job *sj = (struct judge_suspended_job *) job;
  struct run_entry re;

  sj->total_runs = run_get_total(sj->state->runlog_state);
  for (; sj->cur_run < sj->total_runs && *p_count < max_count; ++sj->cur_run, ++(*p_count)) {
    if (run_get_entry(sj->state->runlog_state, sj->cur_run, &re) >= 0 && re.status == RUN_PENDING) {
      serve_rejudge_run(sj->extra, sj->config, sj->cnts, sj->state,
                        sj->cur_run, sj->user_id, &sj->ip, sj->ssl_flag, 0,
                        sj->priority_adjustment);
    }
  }

  return (sj->cur_run >= sj->total_runs);
}

static unsigned char *
judge_suspended_get_status_func(
        struct server_framework_job *job)
{
  struct judge_suspended_job *sj = (struct judge_suspended_job*) job;

  sj->total_runs = run_get_total(sj->state->runlog_state);
  if (sj->total_runs <= 0 || sj->cur_run < 0) {
    return xstrdup("done");
  }

  unsigned char buf[1024];
  snprintf(buf, sizeof(buf), "%lld%% done", sj->cur_run * 100LL / sj->total_runs);
  return xstrdup(buf);
}

static const struct server_framework_job_funcs judge_suspended_funcs =
{
  judge_suspended_destroy_func,
  judge_suspended_run_func,
  judge_suspended_get_status_func,
};

struct server_framework_job *
create_judge_suspended_job(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t state,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int priority_adjustment)
{
  struct judge_suspended_job *sj = NULL;

  XCALLOC(sj, 1);

  sj->b.vt = &judge_suspended_funcs;
  sj->b.contest_id = cnts->id;
  sj->b.title = xstrdup("Judge PENDING initialization");
  sj->extra = extra;
  sj->config = config;
  sj->cnts = cnts;
  sj->state = state;
  sj->user_id = user_id;
  sj->ip = *ip;
  sj->ssl_flag = ssl_flag;
  sj->priority_adjustment = priority_adjustment;
  sj->total_runs = run_get_total(state->runlog_state);

  return (struct server_framework_job *) sj;
}

struct server_framework_job *
serve_judge_suspended(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t state,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int priority_adjustment,
        int create_job_flag)
{
  int total_runs, r;
  struct run_entry re;

  struct server_framework_job *job = NULL;
  if (create_job_flag) {
    job = create_judge_suspended_job(extra, config, cnts, state, user_id, ip,
                                     ssl_flag, priority_adjustment);
    if (job) return job;
  }

  total_runs = run_get_total(state->runlog_state);

  if (state->global->score_system == SCORE_OLYMPIAD
      && !state->accepting_mode)
    return NULL;

  for (r = 0; r < total_runs; r++) {
    if (run_get_entry(state->runlog_state, r, &re) >= 0
        && is_generally_rejudgable(state, &re, INT_MAX)
        && re.status == RUN_PENDING) {
      serve_rejudge_run(extra, config, cnts, state, r, user_id, ip, ssl_flag, 0,
                        priority_adjustment);
    }
  }
  return NULL;
}

struct rejudge_all_job
{
  struct server_framework_job b;

  // passed parameters
  struct contest_extra *extra;
  const struct ejudge_cfg *config;
  const struct contest_desc *cnts;
  serve_state_t state;
  int user_id;
  ej_ip_t ip;
  int ssl_flag;
  int priority_adjustment;

  int total_runs;
  int cur_run;
};

static void
rejudge_all_destroy_func(
        struct server_framework_job *job)
{
  xfree(job->title);
  xfree(job);
}

static int
rejudge_all_run_func(
        struct server_framework_job *job,
        int *p_count,
        int max_count)
{
  struct rejudge_all_job *rj = (struct rejudge_all_job*) job;
  struct run_entry re;

  rj->total_runs = run_get_total(rj->state->runlog_state);
  for (; rj->cur_run < rj->total_runs && *p_count < max_count; ++rj->cur_run, ++(*p_count)) {
    if (run_get_entry(rj->state->runlog_state, rj->cur_run, &re) >= 0
        && is_generally_rejudgable(rj->state, &re, INT_MAX)
        && re.status != RUN_IGNORED && re.status != RUN_DISQUALIFIED) {
      serve_rejudge_run(rj->extra, rj->config, rj->cnts, rj->state,
                        rj->cur_run, rj->user_id, &rj->ip, rj->ssl_flag, 0,
                        rj->priority_adjustment);
    }
  }

  return (rj->cur_run >= rj->total_runs);
}

static unsigned char *
rejudge_all_get_status(
        struct server_framework_job *job)
{
  struct rejudge_all_job *rj = (struct rejudge_all_job*) job;

  rj->total_runs = run_get_total(rj->state->runlog_state);
  if (rj->total_runs <= 0 || rj->cur_run < 0) {
    return xstrdup("done");
  }
  unsigned char buf[1024];
  snprintf(buf, sizeof(buf), "%lld%% done",
           rj->cur_run * 100LL / rj->total_runs);
  return xstrdup(buf);
}

static const struct server_framework_job_funcs rejudge_all_funcs =
{
  rejudge_all_destroy_func,
  rejudge_all_run_func,
  rejudge_all_get_status,
};

static struct server_framework_job *
create_rejudge_all_job(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t state,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int priority_adjustment)
{
  struct rejudge_all_job *rj = NULL;

  if (state->global->score_system == SCORE_OLYMPIAD && !state->accepting_mode) {
    return NULL;
  }

  XCALLOC(rj, 1);

  rj->b.vt = &rejudge_all_funcs;
  rj->b.contest_id = cnts->id;
  rj->b.title = xstrdup("Full rejudge initialization");
  rj->extra = extra;
  rj->config = config;
  rj->cnts = cnts;
  rj->state = state;
  rj->user_id = user_id;
  rj->ip = *ip;
  rj->ssl_flag = ssl_flag;
  rj->priority_adjustment = priority_adjustment;
  rj->total_runs = run_get_total(state->runlog_state);

  return (struct server_framework_job *) rj;
}

struct server_framework_job *
serve_rejudge_all(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t state,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int priority_adjustment,
        int create_job_flag)
{
  int total_runs, r, size, idx, total_ids, total_probs;
  struct run_entry re;
  unsigned char *flag;

  struct server_framework_job *job = NULL;
  if (create_job_flag) {
    job = create_rejudge_all_job(extra, config, cnts, state, user_id, ip,
                                 ssl_flag, priority_adjustment);
    if (job) return job;
  }

  total_runs = run_get_total(state->runlog_state);

  if (state->global->score_system == SCORE_OLYMPIAD
      && !state->accepting_mode) {
    // rejudge only "ACCEPTED", "OK", "PARTIAL SOLUTION" runs,
    // considering only the last run for the given problem and
    // the given participant
    if (state->global->disable_user_database > 0) {
      total_ids = run_get_max_user_id(state->runlog_state) + 1;
    } else {
      total_ids = teamdb_get_max_team_id(state->teamdb_state) + 1;
    }
    total_probs = state->max_prob + 1;
    size = total_ids * total_probs;

    if (total_ids <= 0 || total_probs <= 0) return NULL;
    flag = (unsigned char *) alloca(size);
    memset(flag, 0, size);
    for (r = total_runs - 1; r >= 0; r--) {
      if (run_get_entry(state->runlog_state, r, &re) < 0) continue;
      if (!is_generally_rejudgable(state, &re, total_ids)) continue;
      if (state->probs[re.prob_id]->type != PROB_TYPE_STANDARD) {
        if (!olympiad_output_only_rejudgeable_runs[re.status]) continue;
      } else {
        if (!olympiad_rejudgeable_runs[re.status]) continue;
      }
      idx = re.user_id * total_probs + re.prob_id;
      if (flag[idx]) continue;
      flag[idx] = 1;
      serve_rejudge_run(extra, config, cnts, state, r, user_id, ip, ssl_flag, 0,
                        priority_adjustment);
    }
    return NULL;
  }

  for (r = 0; r < total_runs; r++) {
    if (run_get_entry(state->runlog_state, r, &re) >= 0
        && is_generally_rejudgable(state, &re, INT_MAX)
        && re.status != RUN_IGNORED && re.status != RUN_DISQUALIFIED) {
      serve_rejudge_run(extra, config, cnts, state, r, user_id, ip, ssl_flag, 0,
                        priority_adjustment);
    }
  }
  return NULL;
}

void
serve_reset_contest(const struct contest_desc *cnts, serve_state_t state)
{
  struct section_global_data *global = state->global;
  time_t contest_finish_time = 0;

  if (global->contest_finish_time > 0) {
    contest_finish_time = global->contest_finish_time;
  }
  if (contest_finish_time > 0 && contest_finish_time <= state->current_time) {
    contest_finish_time = 0;
  }
  run_reset(state->runlog_state, global->contest_time,
            cnts->sched_time, contest_finish_time);
  run_set_duration(state->runlog_state,
                   global->contest_time);
  clar_reset(state->clarlog_state);

  /* clear all submissions and clarifications */
  if (global->xml_report_archive_dir && global->xml_report_archive_dir[0])
    clear_directory(global->xml_report_archive_dir);
  if (global->report_archive_dir && global->report_archive_dir[0])
    clear_directory(global->report_archive_dir);
  if (global->run_archive_dir && global->run_archive_dir[0])
    clear_directory(global->run_archive_dir);
  if (global->team_report_archive_dir && global->team_report_archive_dir[0])
    clear_directory(global->team_report_archive_dir);
  if (global->full_archive_dir && global->full_archive_dir[0])
    clear_directory(global->full_archive_dir);
  if (global->audit_log_dir && global->audit_log_dir[0])
    clear_directory(global->audit_log_dir);
  if (global->team_extra_dir && global->team_extra_dir[0])
    clear_directory(global->team_extra_dir);
  if (global->uuid_archive_dir && global->uuid_archive_dir[0])
    clear_directory(global->uuid_archive_dir);

  unsigned char status_dir[PATH_MAX];
  unsigned char *status_dir_ptr = status_dir;
#if defined EJUDGE_CONTESTS_STATUS_DIR
  if (snprintf(status_dir, sizeof(status_dir), "%s/%06d", EJUDGE_CONTESTS_STATUS_DIR, cnts->id) >= sizeof(status_dir)) {
    // FIXME
    abort();
  }
#else
  status_dir_ptr = global->legacy_status_dir;
#endif

  unsigned char path[PATH_MAX];
  snprintf(path, sizeof(path), "%s/dir", status_dir_ptr);
  clear_directory(path);
}

void
serve_squeeze_runs(serve_state_t state)
{
  const struct section_global_data *global = state->global;
  int i, j, tot;

  // sorry...
  return;

  tot = run_get_total(state->runlog_state);
  for (i = 0, j = 0; i < tot; i++) {
    if (run_get_status(state->runlog_state, i) == RUN_EMPTY) continue;
    if (i != j) {
      archive_rename(state, global->run_archive_dir, 0, i, 0, j, 0, 0);
      archive_rename(state, global->xml_report_archive_dir, 0, i, 0, j, 0, 1);
      archive_rename(state, global->report_archive_dir, 0, i, 0, j, 0, 1);
      archive_rename(state, global->team_report_archive_dir, 0, i, 0, j, 0, 0);
      if (global->enable_full_archive) {
        archive_rename(state, global->full_archive_dir, 0, i, 0, j, 0, ZIP);
      }
      archive_rename(state, global->audit_log_dir, 0, i, 0, j, 0, 1);
    }
    j++;
  }
  for (; j < tot; j++) {
    archive_remove(state, global->run_archive_dir, j, 0);
    archive_remove(state, global->xml_report_archive_dir, j, 0);
    archive_remove(state, global->report_archive_dir, j, 0);
    archive_remove(state, global->team_report_archive_dir, j, 0);
    archive_remove(state, global->full_archive_dir, j, 0);
    archive_remove(state, global->audit_log_dir, j, 0);
  }
  run_squeeze_log(state->runlog_state);

  /* FIXME: add an audit record for each renumbered run */
}

int
serve_count_transient_runs(serve_state_t state)
{
  int total_runs, r, counter = 0;
  struct run_entry re;

  total_runs = run_get_total(state->runlog_state);
  for (r = 0; r < total_runs; r++) {
    if (run_get_entry(state->runlog_state, r, &re) < 0) continue;
    if (re.status >= RUN_TRANSIENT_FIRST && re.status <= RUN_TRANSIENT_LAST)
      counter++;
  }
  return counter;
}

#if 0
static int
check_file(const serve_state_t cs, const unsigned char *base_dir, int serial)
{
  path_t pp;

  return archive_make_read_path(cs, pp, sizeof(pp), base_dir, serial, 0, 1);
}
#endif

int
serve_collect_virtual_stop_events(serve_state_t cs)
{
  //const struct section_global_data *global = cs->global;
  struct run_header head;
  const struct run_entry *runs, *pe;
  int begin_runs, total_runs, i;
  time_t *user_time = 0, *new_time, *pt;
  int user_time_size = 0, new_size;
  int need_reload = 0;
  struct run_entry upd_re;

  if (!cs->global->is_virtual) return 0;

  run_get_header(cs->runlog_state, &head);
  if (!head.duration) return 0;
  begin_runs = run_get_first(cs->runlog_state);
  total_runs = run_get_total(cs->runlog_state);
  runs = run_get_entries_ptr(cs->runlog_state);

  user_time_size = 128;
  XCALLOC(user_time, user_time_size);

#if 0
  for (i = begin_runs; i < total_runs; i++) {
    if (!run_is_valid_status(runs[i].status)) continue;
    if (runs[i].status >= RUN_PSEUDO_FIRST
        && runs[i].status <= RUN_PSEUDO_LAST) continue;
    if (runs[i].is_imported) continue;

    check_file(cs, global->run_archive_dir, i);
    if (runs[i].status >= RUN_TRANSIENT_FIRST) continue;
    if (runs[i].status == RUN_IGNORED || runs[i].status == RUN_DISQUALIFIED || runs[i].status ==RUN_PENDING) continue;
    if (check_file(cs, global->xml_report_archive_dir, i) < 0) {
      check_file(cs, global->report_archive_dir, i);
      if (global->team_enable_rep_view)
        check_file(cs, global->team_report_archive_dir, i);
    }
    if (global->enable_full_archive)
      check_file(cs, global->full_archive_dir, i);
    //check_file(cs, global->audit_log_dir, i);
  }
#endif

  for (i = begin_runs; i < total_runs; i++) {
    pe = &runs[i];
    if (!run_is_valid_status(pe->status)) continue;
    if (pe->status == RUN_EMPTY) continue;
    if (pe->user_id <= 0 || pe->user_id >= 100000) continue;
    if (pe->user_id >= user_time_size) {
      new_size = user_time_size;
      while (pe->user_id >= new_size) new_size *= 2;
      XCALLOC(new_time, new_size);
      memcpy(new_time, user_time, user_time_size * sizeof(user_time[0]));
      xfree(user_time);
      user_time = new_time;
      user_time_size = new_size;
    }
    pt = &user_time[pe->user_id];
    if (pe->status == RUN_VIRTUAL_START) {
      if (*pt == -2) {
        err("run %d: virtual start after non-virtual runs, cleared!", i);
        run_forced_clear_entry(cs->runlog_state, i);
        need_reload = 1;
      } else if (*pt == -1) {
        err("run %d: virtual start after virtual stop, cleared!", i);
        run_forced_clear_entry(cs->runlog_state, i);
        need_reload = 1;
      } else if (*pt > 0) {
        err("run %d: virtual start after virtual start, cleared!", i);
        run_forced_clear_entry(cs->runlog_state, i);
        need_reload = 1;
      } else {
        *pt = pe->time;
      }
    } else if (pe->status == RUN_VIRTUAL_STOP) {
      if (*pt == -2) {
        err("run %d: virtual stop after non-virtual runs, cleared!", i);
        run_forced_clear_entry(cs->runlog_state, i);
        need_reload = 1;
      } else if (*pt == -1) {
        err("run %d: virtual stop after virtual stop, cleared!", i);
        run_forced_clear_entry(cs->runlog_state, i);
        need_reload = 1;
      } else if (!*pt) {
        err("run %d: virtual stop without virtual start, cleared!", i);
        run_forced_clear_entry(cs->runlog_state, i);
        need_reload = 1;
      } else if (pe->time > *pt + head.duration) {
        err("run %d: virtual stop time overrun, cleared!", i);
        run_forced_clear_entry(cs->runlog_state, i);
        need_reload = 1;
      } else {
        *pt = -1;
      }
    } else {
      if (*pt == -2) {
        // another non-virtual run
      } else if (*pt == -1) {
        // run after virtual stop
        if (!pe->is_hidden) {
          err("run %d: run after virtual stop, made hidden!", i);
          run_set_hidden(cs->runlog_state, i, &upd_re);
          need_reload = 1;
        }
      } else if (!*pt) {
        // first run
        *pt = -2;
      } else if (pe->time > *pt + head.duration) {
        // virtual run overrun
        if (!pe->is_hidden) {
          err("run %d: virtual time run overrun, made hidden!", i);
          run_set_hidden(cs->runlog_state, i, &upd_re);
          need_reload = 1;
        }
      } else {
        // regular virtual run
      }
    }
  }

  if (need_reload) {
    xfree(user_time); user_time = 0;
    return 1;
  }

  for (i = 1; i < user_time_size; i++)
    if (user_time[i] > 0) {
      serve_event_add(cs, user_time[i] + head.duration,
                      SERVE_EVENT_VIRTUAL_STOP, i, 0);
    }

  xfree(user_time); user_time = 0;
  return 0;
}

static void
handle_virtual_stop_event(
        const struct contest_desc *cnts,
        serve_state_t cs,
        struct serve_event_queue *p)
{
  int trans_runs = -1, nsec = -1, run_id;
  struct timeval precise_time;

  /* FIXME: if we're trying to add backlogged virtual stop while
   * having transient runs, we do some kind of busy wait
   * by not removing the pending virtual stop event from the
   * event queue...
   */

  if (p->time < cs->current_time) {
    if (trans_runs < 0) trans_runs = serve_count_transient_runs(cs);
    if (trans_runs > 0) return;
    info("inserting backlogged virtual stop event at time %ld", p->time);
    nsec = -1;
  } else {
    // p->time == cs->current_time
    gettimeofday(&precise_time, 0);
    if (precise_time.tv_sec != cs->current_time) {
      // oops...
      info("inserting virtual stop event 1 second past");
      nsec = -1;
    } else {
      info("inserting virtual stop event");
      nsec = precise_time.tv_usec * 1000;
    }
  }

  if (nsec < 0) {
    random_init();
    nsec = random_u32() % 1000000000;
  }

  /*
  if (p->time + 15 * 60 < cs->current_time) {
    // too old virtual stop, skip it
    info("virtual stop event is too old, skip it for now...");
    serve_event_remove(cs, p);
    return;
  }

  run_id = run_get_insert_position(cs->runlog_state, p->user_id, p->time, nsec);
  if (run_id + 500 < run_get_total(cs->runlog_state)) {
    info("virtual stop event would be inserted at position %d, that is too far away", run_id);
    serve_event_remove(cs, p);
    return;
  }
  */

  run_id = run_virtual_stop(cs->runlog_state, p->user_id, p->time,
                            0 /* IP */, 0, nsec);
  if (run_id < 0) {
    err("insert failed, removing event!");
    serve_event_remove(cs, p);
    return;
  }
  info("inserted virtual stop as run %d", run_id);
  if (run_is_virtual_legacy_mode(cs->runlog_state)) {
    serve_move_files_to_insert_run(cs, run_id);
  }
  if (cs->global->score_system == SCORE_OLYMPIAD
      && cs->global->is_virtual && cs->global->disable_virtual_auto_judge<= 0) {
    serve_event_add(cs, p->time + 1, SERVE_EVENT_JUDGE_OLYMPIAD, p->user_id, 0);
  }
  if (p->handler) (*p->handler)(cnts, cs, p);
  serve_event_remove(cs, p);
}

static void
handle_judge_olympiad_event(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t cs,
        struct serve_event_queue *p)
{
  if (cs->global->score_system != SCORE_OLYMPIAD
      || !cs->global->is_virtual) goto done;
  if (run_get_virtual_is_checked(cs->runlog_state, p->user_id)) return;
  serve_judge_virtual_olympiad(extra, config, cnts, cs, p->user_id, 0,
                               DFLT_G_REJUDGE_PRIORITY_ADJUSTMENT);
  if (p->handler) (*p->handler)(cnts, cs, p);

 done:
  serve_event_remove(cs, p);
  return;
}

void
serve_handle_events(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t cs)
{
  struct serve_event_queue *p, *q;

  if (!cs->event_first) return;

  for (p = cs->event_first; p; p = q) {
    q = p->next;
    if (p->time > cs->current_time) break;
    switch (p->type) {
    case SERVE_EVENT_VIRTUAL_STOP:
      handle_virtual_stop_event(cnts, cs, p);
      break;
    case SERVE_EVENT_JUDGE_OLYMPIAD:
      handle_judge_olympiad_event(extra, config, cnts, cs, p);
      break;
    default:
      abort();
    }
  }
}

void
serve_judge_virtual_olympiad(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t cs,
        int user_id,
        int run_id,
        int priority_adjustment)
{
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob;
  struct run_entry re;
  int *latest_runs, s, i;

  if (global->score_system != SCORE_OLYMPIAD || !global->is_virtual) return;
  if (user_id <= 0) return;
  if (run_get_virtual_is_checked(cs->runlog_state, user_id)) return;

  // Fully rejudge latest submits
  run_id = run_get_total(cs->runlog_state) - 1;
  if (run_id < 0) return;
  if (cs->max_prob <= 0) return;

  XALLOCA(latest_runs, cs->max_prob + 1);
  memset(latest_runs, -1, (cs->max_prob + 1) * sizeof(latest_runs[0]));
  run_id--;
  for (;run_id >= 0; run_id--) {
    if (run_get_entry(cs->runlog_state, run_id, &re) < 0) return;
    if (!run_is_valid_status((s = re.status))) continue;
    if (s == RUN_EMPTY) continue;
    if (re.user_id != user_id) continue;
    if (s == RUN_VIRTUAL_START) break;
    prob = 0;
    if (re.prob_id > 0 && re.prob_id <= cs->max_prob)
      prob = cs->probs[re.prob_id];
    if (!prob) continue;
    if (prob->disable_testing || prob->disable_auto_testing) continue;
    if (s != RUN_OK && s != RUN_PARTIAL && s != RUN_ACCEPTED && s != RUN_PENDING_REVIEW && s != RUN_SUMMONED
        && (s != RUN_WRONG_ANSWER_ERR || prob->type == PROB_TYPE_STANDARD))
        continue;
    if (latest_runs[re.prob_id] < 0) latest_runs[re.prob_id] = run_id;
  }
  if (run_id < 0) return;

  for (i = 1; i <= cs->max_prob; i++) {
    if (latest_runs[i] >= 0)
      serve_rejudge_run(extra, config, cnts, cs, latest_runs[i], user_id, 0, 0, 1,
                        priority_adjustment);
  }
  run_set_virtual_is_checked(cs->runlog_state, user_id, 1, 0);
}

void
serve_clear_by_mask(serve_state_t state,
                    int user_id, const ej_ip_t *ip, int ssl_flag,
                    int mask_size, unsigned long *mask)
{
  int total_runs, r;
  const struct section_global_data *global = state->global;
  struct run_entry re;

  ASSERT(mask_size > 0);

  total_runs = run_get_total(state->runlog_state);
  if (total_runs > mask_size * BITS_PER_LONG) {
    total_runs = mask_size * BITS_PER_LONG;
  }

  for (r = total_runs - 1; r >= 0; r--) {
    if ((mask[r / BITS_PER_LONG] & (1L << (r % BITS_PER_LONG)))
        && !run_is_readonly(state->runlog_state, r)) {
      if (run_get_entry(state->runlog_state, r, &re) >= 0
          && re.status != RUN_EMPTY
          && run_clear_entry(state->runlog_state, r) >= 0) {
        if (re.store_flags == STORE_FLAGS_UUID || re.store_flags == STORE_FLAGS_UUID_BSON) {
          uuid_archive_remove(state, &re.run_uuid, 0);
        } else {
          archive_remove(state, global->run_archive_dir, r, 0);
          archive_remove(state, global->xml_report_archive_dir, r, 0);
          archive_remove(state, global->report_archive_dir, r, 0);
          archive_remove(state, global->team_report_archive_dir, r, 0);
          archive_remove(state, global->full_archive_dir, r, 0);
        }
        //archive_remove(state, global->audit_log_dir, r, 0);

        serve_audit_log(state, r, &re, user_id, ip, ssl_flag,
                        "clear-run", "ok", -1, NULL);
      }
    }
  }
}

void
serve_ignore_by_mask(
        const struct ejudge_cfg *config,
        serve_state_t state,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int mask_size,
        unsigned long *mask,
        int new_status)
{
  int total_runs, r;
  struct run_entry re;
  const unsigned char *cmd = 0;
  const struct section_global_data *global = state->global;

  ASSERT(mask_size > 0);

  switch (new_status) {
  case RUN_IGNORED:
    cmd = "ignore";
    break;
  case RUN_DISQUALIFIED:
    cmd = "disqualify";
    break;
  default:
    abort();
  }

  total_runs = run_get_total(state->runlog_state);
  if (total_runs > mask_size * BITS_PER_LONG) {
    total_runs = mask_size * BITS_PER_LONG;
  }

  for (r = total_runs - 1; r >= 0; r--) {
    if (!(mask[r / BITS_PER_LONG] & (1L << (r % BITS_PER_LONG)))
        || run_is_readonly(state->runlog_state, r))
      continue;
    if (run_get_entry(state->runlog_state, r, &re) < 0) continue;
    if (!run_is_valid_status(re.status)) continue;
    // do not change EMPTY, VIRTUAL_START, VIRTUAL_STOP runs
    if (!run_is_normal_or_transient_status(re.status)) continue;
    if (re.status == new_status) continue;

    re.status = new_status;
    if (run_set_entry(state->runlog_state, r, RE_STATUS, &re, &re) >= 0) {
      if (re.store_flags == STORE_FLAGS_UUID || re.store_flags == STORE_FLAGS_UUID_BSON) {
        uuid_archive_remove(state, &re.run_uuid, 1);
      } else {
        archive_remove(state, global->xml_report_archive_dir, r, 0);
        archive_remove(state, global->report_archive_dir, r, 0);
        archive_remove(state, global->team_report_archive_dir, r, 0);
        archive_remove(state, global->full_archive_dir, r, 0);
      }
      serve_audit_log(state, r, &re, user_id, ip, ssl_flag,
                      cmd, "ok", new_status, NULL);
      serve_notify_run_update(config, state, &re);
    }
  }
}

void
serve_mark_by_mask(
        const struct ejudge_cfg *config,
        serve_state_t state,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int mask_size,
        unsigned long *mask,
        int mark_value)
{
  int total_runs, r;
  struct run_entry re;
  const unsigned char *audit_cmd = NULL;

  ASSERT(mask_size > 0);
  mark_value = !!mark_value;

  if (mark_value) {
    audit_cmd = "set-marked";
  } else {
    audit_cmd = "set-unmarked";
  }

  total_runs = run_get_total(state->runlog_state);
  if (total_runs > mask_size * BITS_PER_LONG) {
    total_runs = mask_size * BITS_PER_LONG;
  }

  for (r = total_runs - 1; r >= 0; r--) {
    if (!(mask[r / BITS_PER_LONG] & (1L << (r % BITS_PER_LONG)))
        || run_is_readonly(state->runlog_state, r))
      continue;
    if (run_get_entry(state->runlog_state, r, &re) < 0) continue;
    if (!run_is_normal_status(re.status)) continue;
    if (!run_is_valid_status(re.status)) continue;
    if (re.is_marked == mark_value) continue;

    re.is_marked = mark_value;
    run_set_entry(state->runlog_state, r, RE_IS_MARKED, &re, &re);
    serve_notify_run_update(config, state, &re);

    serve_audit_log(state, r, &re, user_id, ip, ssl_flag,
                    audit_cmd, "ok", -1, NULL);
  }
}

void
serve_tokenize_by_mask(
        serve_state_t state,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int mask_size,
        unsigned long *mask,
        int token_count,
        int token_flags)
{
  int total_runs, r;
  struct run_entry re;

  ASSERT(mask_size > 0);

  total_runs = run_get_total(state->runlog_state);
  if (total_runs > mask_size * BITS_PER_LONG) {
    total_runs = mask_size * BITS_PER_LONG;
  }

  for (r = total_runs - 1; r >= 0; r--) {
    if (!(mask[r / BITS_PER_LONG] & (1L << (r % BITS_PER_LONG)))
        || run_is_readonly(state->runlog_state, r))
      continue;
    if (run_get_entry(state->runlog_state, r, &re) < 0) continue;
    if (!run_is_normal_status(re.status)) continue;
    if (!run_is_valid_status(re.status)) continue;

    if (re.token_count != token_count || re.token_flags != token_flags) {
      re.token_count = token_count;
      re.token_flags = token_flags;
      run_set_entry(state->runlog_state, r, RE_TOKEN_COUNT | RE_TOKEN_FLAGS,
                    &re, &re);
      //FIXME:2notify
      //serve_notify_run_update(config, state, &re);
    }

    serve_audit_log(state, r, &re, user_id, ip, ssl_flag,
                    "change-token", "ok", -1, NULL);
  }
}

static int
testing_queue_unlock_entry(
        const unsigned char *run_queue_dir,
        const unsigned char *out_path,
        const unsigned char *packet_name);

static struct super_run_in_packet *
testing_queue_lock_entry(
        int contest_id,
        const unsigned char *user_login,
        const unsigned char *run_queue_dir,
        const unsigned char *packet_name,
        unsigned char *out_name,
        size_t out_size,
        unsigned char *out_path,
        size_t out_path_size)
{
  path_t dir_path;
  struct stat sb;
  char *pkt_buf = 0;
  size_t pkt_size = 0;
  struct super_run_in_packet *srp = NULL;

  snprintf(out_name, out_size, "%s_%d_%s",
           os_NodeName(), getpid(), packet_name);
  snprintf(dir_path, sizeof(dir_path), "%s/dir/%s",
           run_queue_dir, packet_name);
  snprintf(out_path, out_path_size, "%s/out/%s",
           run_queue_dir, out_name);

  if (rename(dir_path, out_path) < 0) {
    err("testing_queue_lock_entry: rename for %s failed: %s",
        packet_name, os_ErrorMsg());
    return NULL;
  }
  if (stat(out_path, &sb) < 0) {
    err("testing_queue_lock_entry: stat for %s failed: %s",
        packet_name, os_ErrorMsg());
    return NULL;
  }
  if (!S_ISREG(sb.st_mode)) {
    err("testing_queue_lock_entry: invalid file type of %s", out_path);
    return NULL;
  }
  if (sb.st_nlink != 1) {
    err("testing_queue_lock_entry: file %s has been linked several times",
        out_path);
    unlink(out_path);
    return NULL;
  }

  if (generic_read_file(&pkt_buf, 0, &pkt_size, 0, 0, out_path, 0) < 0) {
    // no attempt to recover...
    return NULL;
  }

  if (!(srp = super_run_in_packet_parse_cfg_str(packet_name, pkt_buf, pkt_size))) {
    xfree(pkt_buf); pkt_buf = 0;
    return NULL;
  }

  xfree(pkt_buf); pkt_buf = 0;
  pkt_size = 0;

  if (!srp->global || srp->global->contest_id != contest_id) {
    // do allow locking if the user has CONTROL_CONTEST capability on that contest
    const struct contest_desc *cnts = NULL;
    opcap_t caps = 0;
    if (srp->global && user_login
        && contests_get(srp->global->contest_id, &cnts) >= 0
        && cnts
        && opcaps_find(&cnts->capabilities, user_login, &caps) >= 0
        && opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0) {
      return srp;
    }
    srp = super_run_in_packet_free(srp);
    testing_queue_unlock_entry(run_queue_dir, out_path, packet_name);
    return NULL;
  }

  return srp;
}

static int
testing_queue_unlock_entry(
        const unsigned char *run_queue_dir,
        const unsigned char *out_path,
        const unsigned char *packet_name)
{
  path_t dir_path;

  snprintf(dir_path, sizeof(dir_path), "%s/dir/%s",
           run_queue_dir, packet_name);
  if (rename(out_path, dir_path) < 0) {
    err("testing_queue_unlock_entry: rename %s -> %s failed: %s",
        out_path, dir_path, os_ErrorMsg());
    return -1;
  }

  return 0;
}

static int
get_priority_value(int priority_code)
{
  int priority = 0;
  if (priority_code >= '0' && priority_code <= '9') {
    priority = -16 + (priority_code - '0');
  } else if (priority_code >= 'A' && priority_code <= 'V') {
    priority = -6 + (priority_code - 'A');
  }
  return priority;
}

static int
get_priority_code(int priority)
{
  priority += 16;
  if (priority < 0) priority = 0;
  if (priority > 31) priority = 31;
  if (priority < 10) return '0' + priority;
  return 'A' - 10 + priority;
}

static struct run_queue_item *
lookup_run_queue_item(
        const serve_state_t state,
        const unsigned char *queue_id)
{
  if (!queue_id) queue_id = "";
  for (int i = 0; i < state->run_queues_u; ++i) {
    if (!strcmp(state->run_queues[i].id, queue_id))
      return &state->run_queues[i];
  }
  return NULL;
}

int
serve_testing_queue_delete(
        const struct contest_desc *cnts,
        const serve_state_t state,
        const unsigned char *queue_id,
        const unsigned char *packet_name,
        const unsigned char *user_login)
{
  path_t out_path;
  path_t out_name;
  path_t exe_path;
  struct run_entry re;
  struct super_run_in_packet *srp = NULL;
  const unsigned char *exe_sfx = NULL;

  const struct run_queue_item *rqi = lookup_run_queue_item(state, queue_id);
  if (!rqi) return -1;

  if (!(srp = testing_queue_lock_entry(cnts->id, user_login, rqi->queue_dir, packet_name,
                                       out_name, sizeof(out_name),
                                       out_path, sizeof(out_path))))
    return -1;

  if (!srp->global) {
    srp = super_run_in_packet_free(srp);
    return -1;
  }

  exe_sfx = srp->global->exe_sfx;
  if (!exe_sfx) exe_sfx = "";

  snprintf(exe_path, sizeof(exe_path), "%s/%s%s", rqi->exe_dir, packet_name, exe_sfx);
  unlink(out_path);
  unlink(exe_path);

  if (run_get_entry(state->runlog_state, srp->global->run_id, &re) >= 0
      && re.status == RUN_RUNNING) {
    if (re.judge_uuid_flag) {
      ej_uuid_t judge_uuid = {};
      if (srp->global->judge_uuid
          && srp->global->judge_uuid[0]
          && ej_uuid_parse(srp->global->judge_uuid, &judge_uuid) >= 0
          && !memcmp(&re.j.judge_uuid, &judge_uuid, sizeof(re.j.judge_uuid))) {
        run_change_status_4(state->runlog_state, srp->global->run_id,
                            RUN_PENDING, &re);
        //FIXME:2notify
        //serve_notify_run_update(config, state, &re);
      }
    } else {
      if (re.j.judge_id == srp->global->judge_id) {
        run_change_status_4(state->runlog_state, srp->global->run_id,
                            RUN_PENDING, &re);
        //FIXME:2notify
        //serve_notify_run_update(config, state, &re);
      }
    }
  }

  srp = super_run_in_packet_free(srp);
  return 0;
}

int
serve_testing_queue_change_priority(
        const struct contest_desc *cnts,
        const serve_state_t state,
        const unsigned char *queue_id,
        const unsigned char *packet_name,
        int adjustment,
        const unsigned char *user_login)
{
  path_t out_path;
  path_t out_name;
  path_t new_packet_name;
  path_t exe_path;
  path_t new_exe_path;
  struct super_run_in_packet *srp = NULL;
  const unsigned char *exe_sfx = NULL;

  const struct run_queue_item *rqi = lookup_run_queue_item(state, queue_id);
  if (!rqi) return -1;

  if (!(srp = testing_queue_lock_entry(cnts->id, user_login, rqi->queue_dir, packet_name,
                                       out_name, sizeof(out_name),
                                       out_path, sizeof(out_path)))) {
    goto fail;
  }
  if (!srp->global) goto fail;

  exe_sfx = srp->global->exe_sfx;
  if (!exe_sfx) exe_sfx = "";

  snprintf(new_packet_name, sizeof(new_packet_name), "%s", packet_name);
  new_packet_name[0] = get_priority_code(get_priority_value(new_packet_name[0]) + adjustment);
  if (!strcmp(packet_name, new_packet_name)) {
    // already hit min or max priority
    testing_queue_unlock_entry(rqi->queue_dir, out_path, packet_name);
    srp = super_run_in_packet_free(srp);
    return 0;
  }

  snprintf(exe_path, sizeof(exe_path), "%s/%s%s", rqi->exe_dir, packet_name, exe_sfx);
  snprintf(new_exe_path, sizeof(new_exe_path), "%s/%s%s", rqi->exe_dir, new_packet_name, exe_sfx);
  if (rename(exe_path, new_exe_path) < 0) {
    err("serve_testing_queue_up: rename %s -> %s failed: %s",
        exe_path, new_exe_path, os_ErrorMsg());
    testing_queue_unlock_entry(rqi->queue_dir, out_path, packet_name);
    goto fail;
  }

  testing_queue_unlock_entry(rqi->queue_dir, out_path, new_packet_name);

  srp = super_run_in_packet_free(srp);
  return 0;

fail:
  srp = super_run_in_packet_free(srp);
  return -1;
}

struct run_packet_item
{
  unsigned char *queue_id;
  unsigned char *packet_name;
};

struct run_packet_vector
{
  struct run_packet_item *v;
  int u, a;
};

static void
run_packet_push_back(
        struct run_packet_vector *pv,
        const unsigned char *queue_id,
        const unsigned char *packet_name)
{
  if (pv->u == pv->a) {
    if (!(pv->a *= 2)) pv->a = 16;
    XREALLOC(pv->v, pv->a);
  }

  struct run_packet_item *pp = &pv->v[pv->u++];
  memset(pp, 0, sizeof(*pp));
  pp->queue_id = xstrdup(queue_id);
  pp->packet_name = xstrdup(packet_name);
}

static void
run_packet_free(struct run_packet_vector *pv)
{
  for (int i = 0; i < pv->u; ++i) {
    xfree(pv->v[i].queue_id);
    xfree(pv->v[i].packet_name);
  }
  xfree(pv->v);
  memset(pv, 0, sizeof(*pv));
}

static void
collect_run_packets(const struct contest_desc *cnts, const serve_state_t state, struct run_packet_vector *pv)
{
  path_t dir_path;
  DIR *d = 0;
  struct dirent *dd;

  for (int i = 0; i < state->run_queues_u; ++i) {
    snprintf(dir_path, sizeof(dir_path), "%s/dir", state->run_queues[i].queue_dir);
    if ((d = opendir(dir_path))) {
      while ((dd = readdir(d))) {
        if (!strcmp(dd->d_name, ".") && !strcmp(dd->d_name, "..")) continue;
        run_packet_push_back(pv, state->run_queues[i].id, dd->d_name);
      }
      closedir(d); d = NULL;
    }
  }
}

int
serve_testing_queue_delete_all(
        const struct contest_desc *cnts,
        const serve_state_t state,
        const unsigned char *user_login)
{
  struct run_packet_vector vec;
  int i;

  memset(&vec, 0, sizeof(vec));
  collect_run_packets(cnts, state, &vec);
  for (i = 0; i < vec.u; ++i) {
    serve_testing_queue_delete(cnts, state, vec.v[i].queue_id, vec.v[i].packet_name, user_login);
  }

  run_packet_free(&vec);
  return 0;
}

int
serve_testing_queue_change_priority_all(
        const struct contest_desc *cnts,
        const serve_state_t state,
        int adjustment,
        const unsigned char *user_login)
{
  struct run_packet_vector vec;
  int i;

  memset(&vec, 0, sizeof(vec));
  collect_run_packets(cnts, state, &vec);
  for (i = 0; i < vec.u; ++i) {
    serve_testing_queue_change_priority(cnts, state, vec.v[i].queue_id, vec.v[i].packet_name, adjustment, user_login);
  }

  run_packet_free(&vec);
  return 0;
}

/**
 * returns 0, if 'start_date' has not yet come, 1 otherwise
 */
int
serve_is_problem_started(
        const serve_state_t state,
        int user_id,
        const struct section_problem_data *prob)
{
  int i, user_ind, group_ind;
  const unsigned int *bm;

  if (prob->start_date <= 0 && !prob->gsd.count) {
    return 1;
  } else if (prob->start_date > 0 && !prob->gsd.count) {
    return (state->current_time >= prob->start_date);
  } else {
    user_ind = -1;
    if (user_id > 0 && user_id < state->group_member_map_size) {
      user_ind = state->group_member_map[user_id];
    }
    if (user_ind >= 0) {
      bm = state->group_members[user_ind].group_bitmap;
      for (i = 0; i < prob->gsd.count; ++i) {
        if ((group_ind = prob->gsd.info[i].group_ind) < 0) break;
        if ((bm[group_ind >> 5] & (1U << (group_ind & 0x1f))))
          break;
      }
    } else {
      for (i = 0; i < prob->gsd.count; ++i) {
        if (prob->gsd.info[i].group_ind < 0) break;
      }
    }
    if (i < prob->gsd.count) {
      return (state->current_time >= prob->gsd.info[i].p.date);
    }
    if (prob->start_date <= 0) return 1;
    return (state->current_time >= prob->start_date);
  }

  return 1;
}

int
serve_is_problem_started_2(
        const serve_state_t state,
        int user_id,
        int prob_id)
{
  const struct section_problem_data *prob;

  if (prob_id <= 0 || prob_id > state->max_prob) return 0;
  if (!(prob = state->probs[prob_id])) return 0;
  return serve_is_problem_started(state, user_id, prob);
}

/**
 * returns 0, if 'deadline' has not yet come, 1 otherwise
 */
int
serve_is_problem_deadlined(
        const serve_state_t state,
        int user_id,
        const unsigned char *user_login,
        const struct section_problem_data *prob,
        time_t *p_deadline)
{
  int i, user_ind, group_ind;
  const unsigned int *bm;
  struct pers_dead_info *pdinfo;

  if (p_deadline) *p_deadline = 0;

  /* personal deadlines */
  if (prob->pd_total > 0) {
    for (i = 0, pdinfo = prob->pd_infos; i < prob->pd_total; i++, pdinfo++) {
      if (!strcmp(user_login, pdinfo->login) && pdinfo->p.date > 0) {
        if (p_deadline) *p_deadline = pdinfo->p.date;
        return (state->current_time >= pdinfo->p.date);
      }
    }
  }

  /* group deadlines */
  if (prob->gdl.count > 0) {
    user_ind = -1;
    if (user_id > 0 && user_id < state->group_member_map_size) {
      user_ind = state->group_member_map[user_id];
    }
    if (user_ind >= 0) {
      bm = state->group_members[user_ind].group_bitmap;
      for (i = 0; i < prob->gdl.count; ++i) {
        if ((group_ind = prob->gdl.info[i].group_ind) < 0) break;
        if ((bm[group_ind >> 5] & (1U << (group_ind & 0x1f))))
          break;
      }
    } else {
      for (i = 0; i < prob->gdl.count; ++i) {
        if (prob->gdl.info[i].group_ind < 0) break;
      }
    }
    if (i < prob->gdl.count) {
      if (p_deadline) *p_deadline = prob->gdl.info[i].p.date;
      return (state->current_time >= prob->gdl.info[i].p.date);
    }
  }

  if (prob->deadline > 0) {
      if (p_deadline) *p_deadline = prob->deadline;
      return (state->current_time >= prob->deadline);
  }

  return 0;
}

int
serve_is_problem_deadlined_2(
        const serve_state_t state,
        int user_id,
        const unsigned char *user_login,
        int prob_id,
        time_t *p_deadline)
{
  const struct section_problem_data *prob;

  if (prob_id <= 0 || prob_id > state->max_prob) return 0;
  if (!(prob = state->probs[prob_id])) return 0;

  return serve_is_problem_deadlined(state, user_id, user_login, prob,
                                    p_deadline);
}

static const unsigned char * const
serve_err_str_map[] =
{
  [SERVE_ERR_GENERIC] = "unidentified error",
  [SERVE_ERR_SRC_HEADER] = "failed to read source header file",
  [SERVE_ERR_SRC_FOOTER] = "failed to read source footer file",
  [SERVE_ERR_COMPILE_PACKET_WRITE] = "failed to write compile packet",
  [SERVE_ERR_SOURCE_READ] = "failed to read source file",
  [SERVE_ERR_SOURCE_WRITE] = "failed to write source file",
  [SERVE_ERR_DB] = "database error",
};

const unsigned char *
serve_err_str(int serve_err)
{
  const unsigned char *str = NULL;
  if (!serve_err) return "no error!";
  if (serve_err < 0) serve_err = -serve_err;
  if (serve_err >= sizeof(serve_err_str_map) / sizeof(serve_err_str_map[0]))
    return "unknown error!";
  str = serve_err_str_map[serve_err];
  if (!str) str = "unknown error!";
  return str;
}

int
serve_make_source_read_path(
        const serve_state_t state,
        unsigned char *path,
        size_t size,
        const struct run_entry *re)
{
  int ret;
  if (re->store_flags == STORE_FLAGS_UUID || re->store_flags == STORE_FLAGS_UUID_BSON) {
    ret = uuid_archive_make_read_path(state, path, size,
                                      &re->run_uuid, DFLT_R_UUID_SOURCE, 1);
  } else {
    ret = archive_make_read_path(state, path, size, state->global->run_archive_dir,
                                 re->run_id, NULL, 1);
  }
  return ret;
}

int
serve_make_xml_report_read_path(
        const serve_state_t state,
        unsigned char *path,
        size_t size,
        const struct run_entry *re)
{
  int ret;
  if (re->store_flags == STORE_FLAGS_UUID_BSON) {
    ret = uuid_archive_make_read_path(state, path, size,
                                      &re->run_uuid, DFLT_R_UUID_BSON_REPORT, -1);
  } else if (re->store_flags == STORE_FLAGS_UUID) {
    ret = uuid_archive_make_read_path(state, path, size,
                                      &re->run_uuid, DFLT_R_UUID_XML_REPORT, 1);
  } else {
    ret = archive_make_read_path(state, path, size, state->global->xml_report_archive_dir,
                                 re->run_id, NULL, 1);
  }
  return ret;
}

int
serve_make_report_read_path(
        const serve_state_t state,
        unsigned char *path,
        size_t size,
        const struct run_entry *re)
{
  int ret;
  if (re->store_flags == STORE_FLAGS_UUID || re->store_flags == STORE_FLAGS_UUID_BSON) {
    ret = uuid_archive_make_read_path(state, path, size,
                                      &re->run_uuid, DFLT_R_UUID_REPORT, 1);
  } else {
    ret = archive_make_read_path(state, path, size, state->global->report_archive_dir,
                                 re->run_id, NULL, 1);
  }
  return ret;
}

int
serve_make_team_report_read_path(
        const serve_state_t state,
        unsigned char *path,
        size_t size,
        const struct run_entry *re)
{
  return archive_make_read_path(state, path, size, state->global->team_report_archive_dir, re->run_id, NULL, 1);
}

int
serve_make_full_report_read_path(
        const serve_state_t state,
        unsigned char *path,
        size_t size,
        const struct run_entry *re)
{
  int ret;
  if (re->store_flags == STORE_FLAGS_UUID || re->store_flags == STORE_FLAGS_UUID_BSON) {
    ret = uuid_archive_make_read_path(state, path, size,
                                      &re->run_uuid, DFLT_R_UUID_FULL_ARCHIVE, ZIP);
  } else {
    ret = archive_make_read_path(state, path, size, state->global->full_archive_dir,
                                 re->run_id, NULL, ZIP);
  }
  return ret;
}

int
serve_make_audit_read_path(
        const serve_state_t state,
        unsigned char *path,
        size_t size,
        const struct run_entry *re)
{
  int ret;
  if (re->store_flags == STORE_FLAGS_UUID || re->store_flags == STORE_FLAGS_UUID_BSON) {
    ret = uuid_archive_make_read_path(state, path, size,
                                      &re->run_uuid, DFLT_R_UUID_AUDIT, 0);
  } else {
    ret = archive_make_read_path(state, path, size, state->global->audit_log_dir,
                                 re->run_id, NULL, 0);
  }
  return ret;
}

int
serve_count_unread_clars(
        const serve_state_t state,
        int user_id,
        time_t start_time)
{
  int i, total = 0;
  struct clar_entry_v2 clar;

  for (i = clar_get_total(state->clarlog_state) - 1; i >= 0; i--) {
    if (clar_get_record(state->clarlog_state, i, &clar) < 0)
      continue;
    if (clar.id < 0) continue;
    if (clar.to > 0 && clar.to != user_id) continue;
    if (!clar.to && clar.from > 0) continue;
    if (start_time <= 0 && clar.hide_flag) continue;
    if (clar.from != user_id) {
      total++;
    }
  }
  if (state->xuser_state) {
    total -= state->xuser_state->vt->count_read_clars(state->xuser_state, user_id);
  }
  if (total < 0) total = 0;
  return total;
}

static unsigned char *
get_compiler_option(
        const struct ejudge_cfg *config,
        const serve_state_t state,
        const struct section_language_data *lang)
{
  if (!lang) return NULL;

  const unsigned char *flags = NULL;
  const unsigned char *libs = NULL;

  if (lang->compiler_env) {
    for (int i = 0; lang->compiler_env[i]; ++i) {
      if (!strncmp(lang->compiler_env[i], "EJUDGE_FLAGS=", 13)) {
        flags = lang->compiler_env[i] + 13;
      } else if (!strncmp(lang->compiler_env[i], "EJUDGE_LIBS=", 12)) {
        libs = lang->compiler_env[i] + 12;
      }
    }
  }

  const unsigned char *mandatory = "";
  if (!strcmp(lang->short_name, "clang-32")) {
    mandatory = "-m32";
  } else if (!strcmp(lang->short_name, "clang++-32")) {
    mandatory = "-m32";
  } else if (!strcmp(lang->short_name, "dcc")) {
    mandatory = "-Q";
  } else if (!strcmp(lang->short_name, "fbc")) {
    mandatory = "-lang qb";
  } else if (!strcmp(lang->short_name, "fpc")) {
    mandatory = "-XS";
  } else if (!strcmp(lang->short_name, "gcc")) {
    mandatory = "";
  } else if (!strcmp(lang->short_name, "gcc-32")) {
    mandatory = "-m32";
  } else if (!strcmp(lang->short_name, "g++")) {
    mandatory = "";
  } else if (!strcmp(lang->short_name, "g++-32")) {
    mandatory = "-m32";
  } else if (!strcmp(lang->short_name, "g77")) {
    mandatory = "-static";
  } else if (!strcmp(lang->short_name, "gfortran")) {
    mandatory = "";
  } else if (!strcmp(lang->short_name, "gccgo")) {
    mandatory = "-g";
  } else if (!strcmp(lang->short_name, "gcj")) {
    mandatory = "--main=Main Main.java";
  } else if (!strcmp(lang->short_name, "gpc")) {
    mandatory = "-static";
  } else if (!strcmp(lang->short_name, "gprolog")) {
    mandatory = "--min-size";
  } else if (!strcmp(lang->short_name, "nasm-x86")) {
    mandatory = "-DUNIX -f elf";
  }

  if (!flags) {
    flags = ejudge_cfg_get_compiler_option(config, lang->short_name);
  }

  if (!flags) {
    if (!strcmp(lang->short_name, "clang")) {
      flags = "-Wall -O2";
    } else if (!strcmp(lang->short_name, "clang-32")) {
      flags = "-Wall -O2";
    } else if (!strcmp(lang->short_name, "clang++")) {
      flags = "-Wall -O2";
    } else if (!strcmp(lang->short_name, "clang++-32")) {
      flags = "-Wall -O2";
    } else if (!strcmp(lang->short_name, "gcc")) {
      flags = "-Wall -O2";
    } else if (!strcmp(lang->short_name, "gcc-32")) {
      flags = "-Wall -O2";
    } else if (!strcmp(lang->short_name, "gcc-vg")) {
      flags = "-g -O2";
    } else if (!strcmp(lang->short_name, "g++")) {
      flags = "-Wall -O2";
    } else if (!strcmp(lang->short_name, "g++-32")) {
      flags = "-Wall -O2";
    } else if (!strcmp(lang->short_name, "g++-vg")) {
      flags = "-g -O2";
    } else if (!strcmp(lang->short_name, "g77")) {
      flags = "-O2";
    } else if (!strcmp(lang->short_name, "gfortran")) {
      flags = "-O2";
    } else if (!strcmp(lang->short_name, "gccgo")) {
      flags = "-O2";
    } else if (!strcmp(lang->short_name, "gcj")) {
      flags = "-Wall -O2";
    } else if (!strcmp(lang->short_name, "gpc")) {
      flags = "-O2";
    } else if (!strcmp(lang->short_name, "mcs")) {
      flags = "-optimize+";
    } else if (!strcmp(lang->short_name, "nasm-x86")) {
      flags = "-Werror";
    }
  }

  if (!libs) {
    if (!strcmp(lang->short_name, "clang")) {
      libs = "-lm";
    } else if (!strcmp(lang->short_name, "clang-32")) {
      libs = "-lm";
    } else if (!strcmp(lang->short_name, "clang++")) {
      libs = "-lm";
    } else if (!strcmp(lang->short_name, "clang++-32")) {
      libs = "-lm";
    } else if (!strcmp(lang->short_name, "gcc")) {
      libs = "-lm";
    } else if (!strcmp(lang->short_name, "gcc-32")) {
      libs = "-lm";
    } else if (!strcmp(lang->short_name, "gcc-vg")) {
      libs = "-lm";
    } else if (!strcmp(lang->short_name, "g++")) {
      libs = "-lm";
    } else if (!strcmp(lang->short_name, "g++-32")) {
      libs = "-lm";
    } else if (!strcmp(lang->short_name, "g++-vg")) {
      libs = "-lm";
    }
  }

  if (!mandatory) mandatory = "";
  if (!flags) flags = "";
  if (!libs) libs = "";

  const unsigned char *spc = "";
  unsigned char *out = xmalloc(strlen(mandatory) + strlen(flags) + strlen(libs) + 3);
  *out = 0;
  if (*mandatory) {
    strcat(out, mandatory);
    spc = " ";
  }
  if (*flags) {
    strcat(out, spc);
    strcat(out, flags);
    spc = " ";
  }
  if (*libs) {
    strcat(out, spc);
    strcat(out, libs);
  }
  return out;
}

static void
fill_compiler_options(
        const struct ejudge_cfg *config,
        const serve_state_t state)
{
  if (state->compiler_options) return;
  if (state->max_lang <= 0) return;
  XCALLOC(state->compiler_options, state->max_lang + 1);

  for (int lang_id = 1; lang_id <= state->max_lang; ++lang_id) {
    const struct section_language_data *lang = state->langs[lang_id];
    state->compiler_options[lang_id] = get_compiler_option(config, state, lang);
  }
}

const unsigned char *
serve_get_compiler_options(
        const struct ejudge_cfg *config,
        const serve_state_t state,
        int lang_id)
{
  const unsigned char *s = 0;

  if (lang_id <= 0 || lang_id > state->max_lang) return "";

  if (!state->compiler_options) {
    fill_compiler_options(config, state);
  }

  s = state->compiler_options[lang_id];
  if (!s) s = "";
  return s;
}

void
serve_invoker_delete(
        const serve_state_t state,
        const unsigned char *queue,
        const unsigned char *file)
{
  unsigned char file2[PATH_MAX];
  unsigned char path[PATH_MAX];

  const struct run_queue_item *rqi = lookup_run_queue_item(state, queue);
  if (!rqi) return;
  if (!rqi->heartbeat_dir || !*rqi->heartbeat_dir) return;

  snprintf(file2, sizeof(file2), "%s", file);
  for (int i = 0; file2[i]; ++i) {
    if (file2[i] <= ' ' || file2[i] >= 0x7f || file2[i] == '/') {
      file2[i] = '_';
    }
  }

  snprintf(path, sizeof(path), "%s/dir/%s", rqi->heartbeat_dir, file2);
  unlink(path);
  snprintf(path, sizeof(path), "%s/dir/%s@D", rqi->heartbeat_dir, file2);
  unlink(path);
  snprintf(path, sizeof(path), "%s/dir/%s@S", rqi->heartbeat_dir, file2);
  unlink(path);
}

void
serve_invoker_stop(
        const serve_state_t state,
        const unsigned char *queue,
        const unsigned char *file)
{
  unsigned char file2[PATH_MAX];
  unsigned char path[PATH_MAX];

  const struct run_queue_item *rqi = lookup_run_queue_item(state, queue);
  if (!rqi) return;
  if (!rqi->heartbeat_dir || !*rqi->heartbeat_dir) return;

  snprintf(file2, sizeof(file2), "%s", file);
  for (int i = 0; file2[i]; ++i) {
    if (file2[i] <= ' ' || file2[i] >= 0x7f || file2[i] == '/') {
      file2[i] = '_';
    }
  }

  snprintf(path, sizeof(path), "%s/dir/%s@S", rqi->heartbeat_dir, file2);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  close(fd);
}

void
serve_invoker_down(
        const serve_state_t state,
        const unsigned char *queue,
        const unsigned char *file)
{
  unsigned char file2[PATH_MAX];
  unsigned char path[PATH_MAX];

  const struct run_queue_item *rqi = lookup_run_queue_item(state, queue);
  if (!rqi) return;
  if (!rqi->heartbeat_dir || !*rqi->heartbeat_dir) return;

  snprintf(file2, sizeof(file2), "%s", file);
  for (int i = 0; file2[i]; ++i) {
    if (file2[i] <= ' ' || file2[i] >= 0x7f || file2[i] == '/') {
      file2[i] = '_';
    }
  }

  snprintf(path, sizeof(path), "%s/dir/%s@D", rqi->heartbeat_dir, file2);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  close(fd);
}

void
serve_invoker_reboot(
        const serve_state_t state,
        const unsigned char *queue,
        const unsigned char *file)
{
  unsigned char file2[PATH_MAX];
  unsigned char path[PATH_MAX];

  const struct run_queue_item *rqi = lookup_run_queue_item(state, queue);
  if (!rqi) return;
  if (!rqi->heartbeat_dir || !*rqi->heartbeat_dir) return;

  snprintf(file2, sizeof(file2), "%s", file);
  for (int i = 0; file2[i]; ++i) {
    if (file2[i] <= ' ' || file2[i] >= 0x7f || file2[i] == '/') {
      file2[i] = '_';
    }
  }

  snprintf(path, sizeof(path), "%s/dir/%s@R", rqi->heartbeat_dir, file2);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  close(fd);
}

void
serve_compiler_op(
        const serve_state_t state,
        const unsigned char *queue,
        const unsigned char *file,
        const unsigned char *op)
{
  unsigned char file2[PATH_MAX];
  unsigned char path[PATH_MAX];

  const struct compile_queue_item *cqi = lookup_compile_queue_item(state, queue);
  if (!cqi) return;
  if (!cqi->heartbeat_dir || !*cqi->heartbeat_dir) return;
  if (!op || !*op) return;

  snprintf(file2, sizeof(file2), "%s", file);
  for (int i = 0; file2[i]; ++i) {
    if (file2[i] <= ' ' || file2[i] >= 0x7f || file2[i] == '/') {
      file2[i] = '_';
    }
  }

  if (!strcmp(op, "delete")) {
    info("DELETE for queue %s and compiler %s", queue, file);
    snprintf(path, sizeof(path), "%s/dir/%s", cqi->heartbeat_dir, file2);
    unlink(path);
    snprintf(path, sizeof(path), "%s/dir/%s@D", cqi->heartbeat_dir, file2);
    unlink(path);
    snprintf(path, sizeof(path), "%s/dir/%s@S", cqi->heartbeat_dir, file2);
    unlink(path);
  } else if (!strcmp(op, "stop")) {
    info("STOP for queue %s and compiler %s", queue, file);
    snprintf(path, sizeof(path), "%s/dir/%s@S", cqi->heartbeat_dir, file2);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0666);
    close(fd);
  } else if (!strcmp(op, "down")) {
    info("DOWN for queue %s and compiler %s", queue, file);
    snprintf(path, sizeof(path), "%s/dir/%s@D", cqi->heartbeat_dir, file2);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0666);
    close(fd);
  } else if (!strcmp(op, "reboot")) {
    info("REBOOT for queue %s and compiler %s", queue, file);
    snprintf(path, sizeof(path), "%s/dir/%s@R", cqi->heartbeat_dir, file2);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0666);
    close(fd);
  }
}

int
serve_get_compile_reply_contest_id(const unsigned char *path)
{
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK, 0);
  if (fd < 0 && errno == ENOENT) {
    return 0;
  }
  if (fd < 0) {
    err("serve_get_compile_reply_contest_id: failed to open '%s': %s", path, os_ErrorMsg());
    return -1;
  }
  struct stat stb;
  if (fstat(fd, &stb)) {
    abort();
  }
  if (!S_ISREG(stb.st_mode)) {
    err("serve_get_compile_reply_contest_id: not regular file '%s'", path);
    close(fd);
    return -1;
  }
  if (stb.st_size <= 0) {
    err("serve_get_compile_reply_contest_id: empty file '%s'", path);
    close(fd);
    return -1;
  }
  if (stb.st_size > 1024 * 128) {
    err("serve_get_compile_reply_contest_id: file '%s' too big: %lld", path, (long long) stb.st_size);
    close(fd);
    return -1;
  }
  void *pkt_ptr = mmap(NULL, stb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (pkt_ptr == MAP_FAILED) {
    err("serve_get_compile_reply_contest_id: file '%s' map failed: %s", path, os_ErrorMsg());
    close(fd);
    return -1;
  }
  close(fd); fd = -1;

  int r = compile_reply_packet_get_contest_id(stb.st_size, pkt_ptr);
  munmap(pkt_ptr, stb.st_size);

  return r;
}
