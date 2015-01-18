/* -*- mode: c -*- */

/* Copyright (C) 2006-2015 Alexander Chernov <cher@ejudge.ru> */

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

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif
#define __(x) x

#define ARMOR(s)  html_armor_buf(&ab, s)

void
serve_update_standings_file(serve_state_t state,
                            const struct contest_desc *cnts,
                            int force_flag)
{
  struct section_global_data *global = state->global;
  time_t start_time, stop_time, duration;
  int p = 0, charset_id = 0;

  run_get_times(state->runlog_state, &start_time, 0, &duration, &stop_time, 0);

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
  charset_id = charset_get_id(global->standings_charset);
  l10n_setlocale(global->standings_locale_id);
  write_standings(state, cnts, global->status_dir,
                  global->standings_file_name,
                  global->users_on_page,
                  global->stand_header_txt,
                  global->stand_footer_txt,
                  state->accepting_mode, 0, charset_id, 1 /* user_mode */);
  if (global->stand2_file_name[0]) {
    charset_id = charset_get_id(global->stand2_charset);
    write_standings(state, cnts, global->status_dir,
                    global->stand2_file_name, 0,
                    global->stand2_header_txt,
                    global->stand2_footer_txt,
                    state->accepting_mode, 0, charset_id, 1 /* user_mode */);
  }
  l10n_resetlocale();
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
}

void
serve_update_public_log_file(serve_state_t state,
                             const struct contest_desc *cnts)
{
  struct section_global_data *global = state->global;
  time_t start_time, stop_time, duration;
  int p, charset_id = 0;

  if (!global->plog_update_time) return;
  if (state->current_time < state->last_update_public_log + global->plog_update_time) return;

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

  charset_id = charset_get_id(global->plog_charset);
  l10n_setlocale(global->standings_locale_id);
  write_public_log(state, cnts, global->status_dir,
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
  int rtotal;
  const struct run_entry *rentries;
  path_t path1;
  path_t path2;
  FILE *fout;

  run_get_header(state->runlog_state, &rhead);
  rtotal = run_get_total(state->runlog_state);
  rentries = run_get_entries_ptr(state->runlog_state);

  snprintf(path1, sizeof(path1), "%s/in/%s.tmp",state->global->status_dir,name);
  snprintf(path2, sizeof(path2), "%s/dir/%s", state->global->status_dir, name);

  if (!(fout = fopen(path1, "w"))) {
    err("update_xml_log: cannot open %s", path1);
    return;
  }
  unparse_runlog_xml(state, cnts, fout, &rhead, rtotal, rentries,
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
  state->last_update_external_xml_log = state->current_time;
  do_update_xml_log(state, cnts, "external.xml", 1);
}

void
serve_update_internal_xml_log(serve_state_t state,
                              const struct contest_desc *cnts)
{
  if (!state->global->internal_xml_update_time) return;
  if (state->current_time < state->last_update_internal_xml_log + state->global->internal_xml_update_time) return;
  state->last_update_internal_xml_log = state->current_time;
  do_update_xml_log(state, cnts, "internal.xml", 0);
}

int
serve_update_status_file(serve_state_t state, int force_flag)
{
  const struct section_global_data *global = state->global;
  struct prot_serve_status_v2 status;
  time_t t1, t2, t3, t4, t5;
  int p;

  if (!force_flag && state->current_time <= state->last_update_status_file) return 0;

  memset(&status, 0, sizeof(status));
  status.magic = PROT_SERVE_STATUS_MAGIC_V2;

  status.cur_time = state->current_time;
  run_get_times(state->runlog_state, &t1, &t2, &t3, &t4, &t5);
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

  memcpy(status.prob_prio, state->prob_prio, sizeof(status.prob_prio));

  generic_write_file((char*) &status, sizeof(status), SAFE,
                     global->status_dir, "status", "");
  state->last_update_status_file = state->current_time;
  return 1;
}

void
serve_load_status_file(serve_state_t state)
{
  struct section_global_data *global = state->global;
  struct prot_serve_status_v2 status;
  size_t stat_len = 0;
  char *ptr = 0;

  if (generic_read_file(&ptr, 0, &stat_len, 0, global->status_dir,
                        "dir/status", "") < 0) {
    if (global->score_system == SCORE_OLYMPIAD)
      state->accepting_mode = 1;
    return;
  }
  if (stat_len != sizeof(status)) {
    info("load_status_file: length %zu does not match %zu",
         stat_len, sizeof(status));
    xfree(ptr);
    if (global->score_system == SCORE_OLYMPIAD)
      state->accepting_mode = 1;
    return;
  }
  memcpy(&status, ptr, sizeof(status));
  xfree(ptr);
  if (status.magic != PROT_SERVE_STATUS_MAGIC_V2) {
    info("load_status_file: bad magic value");
    if (global->score_system == SCORE_OLYMPIAD)
      state->accepting_mode = 1;
    return;
  }

  state->clients_suspended = status.clients_suspended;
  info("load_status_file: clients_suspended = %d", state->clients_suspended);
  state->testing_suspended = status.testing_suspended;
  info("load_status_file: testing_suspended = %d", state->testing_suspended);
  state->accepting_mode = status.accepting_mode;
  if (global->score_system == SCORE_OLYMPIAD
      && global->is_virtual) {
    state->accepting_mode = 1;
  }
  if (global->score_system != SCORE_OLYMPIAD) {
    state->accepting_mode = 0;
  }
  info("load_status_file: accepting_mode = %d", state->accepting_mode);
  state->printing_suspended = status.printing_suspended;
  info("load_status_file: printing_suspended = %d", state->printing_suspended);
  state->stat_reported_before = status.stat_reported_before;
  state->stat_report_time = status.stat_report_time;

  state->upsolving_mode = status.upsolving_mode;
  info("load_status_file: upsolving_mode = %d", state->upsolving_mode);
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

  state->max_online_time = status.max_online_time;
  state->max_online_count = status.max_online_count;

  memcpy(state->prob_prio, status.prob_prio, sizeof(state->prob_prio));
}

void
serve_remove_status_file(serve_state_t state)
{
  if (!state || !state->global) return;
  relaxed_remove(state->global->status_dir, "dir/status");
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
serve_build_compile_dirs(serve_state_t state)
{
  int i;

  for (i = 1; i <= state->max_lang; i++) {
    if (!state->langs[i]) continue;
    do_build_compile_dirs(state,
                          state->langs[i]->compile_status_dir,
                          state->langs[i]->compile_report_dir);
  }
}

static int
do_build_run_dirs(serve_state_t state,
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

  state->run_dirs[state->run_dirs_u].status_dir = xstrdup(status_dir);
  state->run_dirs[state->run_dirs_u].report_dir = xstrdup(report_dir);
  state->run_dirs[state->run_dirs_u].team_report_dir = xstrdup(team_report_dir);
  state->run_dirs[state->run_dirs_u].full_report_dir = xstrdup(full_report_dir);
  return state->run_dirs_u++;
}

void
serve_build_run_dirs(serve_state_t state, int contest_id)
{
  const struct section_global_data *global = state->global;
  int i;

  if (global->super_run_dir && global->super_run_dir[0]) {
    unsigned char status_dir[PATH_MAX];
    unsigned char report_dir[PATH_MAX];
    unsigned char team_report_dir[PATH_MAX];
    unsigned char full_report_dir[PATH_MAX];

    snprintf(status_dir, sizeof(status_dir),
             "%s/var/%06d/status", global->super_run_dir, contest_id);
    snprintf(report_dir, sizeof(report_dir),
             "%s/var/%06d/report", global->super_run_dir, contest_id);
    snprintf(full_report_dir, sizeof(full_report_dir),
             "%s/var/%06d/output", global->super_run_dir, contest_id);
    snprintf(team_report_dir, sizeof(team_report_dir),
             "%s/var/%06d/teamreports", global->super_run_dir, contest_id);
    do_build_run_dirs(state, status_dir, report_dir, team_report_dir, full_report_dir);

    for (i = 1; i <= state->max_lang; ++i) {
      struct section_language_data *lang = state->langs[i];
      if (lang && lang->super_run_dir && lang->super_run_dir[0]) {
        snprintf(status_dir, sizeof(status_dir),
                 "%s/var/%06d/status", lang->super_run_dir, contest_id);
        snprintf(report_dir, sizeof(report_dir),
                 "%s/var/%06d/report", lang->super_run_dir, contest_id);
        snprintf(full_report_dir, sizeof(full_report_dir),
                 "%s/var/%06d/output", lang->super_run_dir, contest_id);
        snprintf(team_report_dir, sizeof(team_report_dir),
                 "%s/var/%06d/teamreports", lang->super_run_dir, contest_id);
        do_build_run_dirs(state, status_dir, report_dir, team_report_dir, full_report_dir);
      }
    }

    for (i = 1; i <= state->max_prob; ++i) {
      struct section_problem_data *prob = state->probs[i];
      if (prob && prob->super_run_dir && prob->super_run_dir[0]) {
        snprintf(status_dir, sizeof(status_dir),
                 "%s/var/%06d/status", prob->super_run_dir, contest_id);
        snprintf(report_dir, sizeof(report_dir),
                 "%s/var/%06d/report", prob->super_run_dir, contest_id);
        snprintf(full_report_dir, sizeof(full_report_dir),
                 "%s/var/%06d/output", prob->super_run_dir, contest_id);
        snprintf(team_report_dir, sizeof(team_report_dir),
                 "%s/var/%06d/teamreports", prob->super_run_dir, contest_id);
        do_build_run_dirs(state, status_dir, report_dir, team_report_dir, full_report_dir);
      }
    }
  } else {
    for (i = 1; i <= state->max_tester; i++) {
      if (!state->testers[i]) continue;
      //if (state->testers[i]->any) continue;
      do_build_run_dirs(state, state->testers[i]->run_status_dir,
                        state->testers[i]->run_report_dir,
                        state->testers[i]->run_team_report_dir,
                        state->testers[i]->run_full_archive_dir);
    }
  }
}

int
serve_create_symlinks(serve_state_t state)
{
  const struct section_global_data *global = state->global;  
  unsigned char src_path[PATH_MAX];
  unsigned char dst_path[PATH_MAX];
  path_t stand_file;
  int npages, pgn;
  int total_users = 0;

  if (global->stand_symlink_dir[0] && global->htdocs_dir[0]) {
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
                 global->status_dir, stand_file);
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
               global->status_dir, global->standings_file_name);
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
  if (global->stand2_symlink_dir[0] && global->htdocs_dir[0]
      && global->stand2_file_name[0]) {
    snprintf(src_path, sizeof(src_path), "%s/dir/%s",
             global->status_dir, global->stand2_file_name);
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
  if (global->plog_symlink_dir[0] && global->htdocs_dir[0]
      && global->plog_file_name[0]
      && global->plog_update_time > 0) {
    snprintf(src_path, sizeof(src_path), "%s/dir/%s",
             global->status_dir, global->plog_file_name);
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
           "Daily statistics for %04d/%02d/%02d, contest %d",
           ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
           state->global->contest_id);

  eout = open_memstream(&etxt, &elen);
  generate_daily_statistics(state, eout, from_time, to_time, utf8_mode);
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
          "Report day: %04d/%02d/%02d\n\n"
          "%s\n\n"
          "-\n"
          "Regards,\n"
          "the ejudge contest management system\n",
          state->global->contest_id, cnts->name,
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
  send_job_packet(NULL, (unsigned char **) mail_args, 0);
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
    if (re.store_flags == 1) continue;

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
  snprintf(tbuf, sizeof(tbuf), "%04d/%02d/%02d %02d:%02d:%02d",
           ltm->tm_year + 1900, ltm->tm_mon + 1, ltm->tm_mday,
           ltm->tm_hour, ltm->tm_min, ltm->tm_sec);

  if (re && re->store_flags == 1) {
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
filter_lang_environ(const unsigned char *lang_short_name, char **environ)
{
  int count = 0, i, llen, j = 0;
  char **env = NULL;
  llen = strlen(lang_short_name);
  for (i = 0; environ[i]; ++i) {
    if (strlen(environ[i]) > llen && !strncmp(lang_short_name, environ[i], llen) && environ[i][llen] == '=') {
      ++count;
    }
  }
  XCALLOC(env, count + 1);
  for (i = 0; environ[i]; ++i) {
    if (strlen(environ[i]) > llen && !strncmp(lang_short_name, environ[i], llen) && environ[i][llen] == '=') {
      env[j++] = xstrdup(environ[i] + llen + 1);
    }
  }
  return env;
}

int
serve_compile_request(
        serve_state_t state,
        unsigned char const *str,
        int len,
        int contest_id,
        int run_id,
        int user_id,
        int lang_id,
        int variant,
        int locale_id,
        int output_only,
        unsigned char const *sfx,
        char **compiler_env,
        int style_check_only,
        const unsigned char *style_checker_cmd,
        char **style_checker_env,
        int accepting_mode,
        int priority_adjustment,
        int notify_flag,
        const struct section_problem_data *prob,
        const struct section_language_data *lang,
        int no_db_flag,
        const ej_uuid_t *puuid,
        int store_flags,
        int rejudge_flag)
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
  const unsigned char *compile_src_dir = 0;
  const unsigned char *compile_queue_dir = 0;
  int errcode = -SERVE_ERR_GENERIC;

  if (prob->variant_num <= 0 && variant > 0) {
    goto failed;
  }
  if (prob->variant_num > 0) {
    if (variant <= 0) variant = find_variant(state, user_id, prob->id, 0);
    if (variant <= 0) {
      goto failed;
    }
  }

  if (prob->source_header[0]) {
    sformat_message(tmp_path, sizeof(tmp_path), 0, prob->source_header,
                    global, prob, lang, 0, 0, 0, 0, 0);
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
  if (prob->source_footer[0]) {
    sformat_message(tmp_path, sizeof(tmp_path), 0, prob->source_footer,
                    global, prob, lang, 0, 0, 0, 0, 0);
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

  if ((!style_checker_cmd || !style_checker_cmd[0]) && lang) {
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
    comp_env_mem_2 = filter_lang_environ(lang->short_name, prob->lang_compiler_env);
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
  cp.contest_id = contest_id;
  cp.run_id = run_id;
  cp.lang_id = lang_id;
  cp.locale_id = locale_id;
  cp.output_only = output_only;
  get_current_time(&cp.ts1, &cp.ts1_us);
  cp.run_block_len = sizeof(rx);
  cp.run_block = &rx;
  cp.env_num = -1;
  cp.env_vars = (unsigned char**) compiler_env;
  cp.style_check_only = !!style_check_only;
  cp.max_vm_size = -1L;
  cp.max_stack_size = -1L;
  cp.max_file_size = -1L;
  if (puuid && (puuid->v[0] || puuid->v[1] || puuid->v[2] || puuid->v[3])) {
    cp.use_uuid = 1;
    cp.uuid = *puuid;
  }
  if (lang) {
    if (((ssize_t) lang->max_vm_size) > 0) {
      cp.max_vm_size = lang->max_vm_size;
    } else if (((ssize_t) global->compile_max_vm_size) > 0) {
      cp.max_vm_size = global->compile_max_vm_size;
    }
    if (((ssize_t) lang->max_stack_size) > 0) {
      cp.max_stack_size = lang->max_stack_size;
    } else if (((ssize_t) global->compile_max_stack_size) > 0) {
      cp.max_stack_size = global->compile_max_stack_size;
    }
    if (((ssize_t) lang->max_file_size) > 0) {
      cp.max_file_size = lang->max_file_size;
    } else if (((ssize_t) global->compile_max_file_size) > 0) {
      cp.max_file_size = global->compile_max_file_size;
    }
  }
  if (style_checker_cmd && style_checker_cmd[0]) {
    cp.style_checker = (unsigned char*) style_checker_cmd;
  }
  cp.src_sfx = (unsigned char*) sfx;
  cp.sc_env_num = -1;
  cp.sc_env_vars = (unsigned char**) style_checker_env;

  memset(&rx, 0, sizeof(rx));
  rx.accepting_mode = accepting_mode;
  rx.priority_adjustment = priority_adjustment;
  rx.notify_flag = notify_flag;
  if (lang) {
    rx.is_dos = lang->is_dos;
  }
  rx.rejudge_flag = rejudge_flag;

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

  compile_src_dir = global->compile_src_dir;
  if (lang && lang->compile_src_dir && lang->compile_src_dir[0]) {
    compile_src_dir = lang->compile_src_dir;
  }
  compile_queue_dir = global->compile_queue_dir;
  if (lang && lang->compile_queue_dir && lang->compile_queue_dir[0]) {
    compile_queue_dir = lang->compile_queue_dir;
  }

  if (!sfx) sfx = "";
  serve_packet_name(contest_id, run_id, prio, pkt_name, sizeof(pkt_name));

  if (src_header_size > 0 || src_footer_size > 0) {
    if (len < 0) {
      if (store_flags == 1) {
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
    if (store_flags == 1) {
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
                          cp.judge_id) < 0) {
      errcode = -SERVE_ERR_DB;
      goto failed;
    }
  }

  sarray_free(comp_env_mem_2);
  sarray_free(comp_env_mem);
  sarray_free(sc_env_mem);
  xfree(pkt_buf);
  xfree(src_header_text);
  xfree(src_footer_text);
  xfree(src_text);
  xfree(src_out_text);
  return 0;

 failed:
  sarray_free(comp_env_mem_2);
  sarray_free(comp_env_mem);
  sarray_free(sc_env_mem);
  xfree(pkt_buf);
  xfree(src_header_text);
  xfree(src_footer_text);
  xfree(src_text);
  xfree(src_out_text);
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
  if (!values || !values[0] || !lang || !lang->short_name || !lang->short_name[0]) return default_value;

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
        size_t *p_size)
{
  if (!values || !values[0] || !lang) return 0;
  if (lang->short_name[0] <= ' ') return 0;

  int lsn = strlen(lang->short_name);
  const unsigned char *sn;
  for (int i = 0; (sn = values[i]); ++i) {
    int vl = strlen(sn);
    if (vl > lsn + 1 && !strncmp(sn, lang->short_name, lsn) && sn[lsn] == '=') {
      return size_str_to_size_t(sn + lsn + 1, p_size) >= 0;
    }
  }

  return 0;
}

int
serve_run_request(
        serve_state_t state,
        const struct contest_desc *cnts,
        FILE *errf,
        const unsigned char *run_text,
        size_t run_size,
        int contest_id,
        int run_id,
        int user_id,
        int prob_id,
        int lang_id,
        int variant,
        int priority_adjustment,
        int judge_id,
        int accepting_mode,
        int notify_flag,
        int mime_type,
        int eoln_type,
        int locale_id,
        const unsigned char *compile_report_dir,
        const struct compile_reply_packet *comp_pkt,
        int no_db_flag,
        ej_uuid_t *puuid,
        int rejudge_flag)
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
  int current_time = 0;
  int current_time_us = 0;
  int time_limit_adj = 0;
  int time_limit_adj_millis = 0;
  struct section_tester_data *refined_tester = NULL;
  const unsigned char *s;
  FILE *srp_f = NULL;
  char *srp_t = NULL;
  size_t srp_z = 0;
  size_t lang_specific_size;

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

  /* generate a packet name */
  serve_packet_name(contest_id, run_id, prio, pkt_base, sizeof(pkt_base));
  snprintf(exe_out_name, sizeof(exe_out_name), "%s%s", pkt_base, exe_sfx);

  if (!run_text) {
    if (comp_pkt && comp_pkt->use_uuid > 0
        && comp_pkt->uuid.v[0] && comp_pkt->uuid.v[1]
        && comp_pkt->uuid.v[2] && comp_pkt->uuid.v[3]) {
      snprintf(exe_in_name, sizeof(exe_in_name), "%s%s",
               ej_uuid_unparse(&comp_pkt->uuid, NULL), exe_sfx);
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

  if (!arch) {
    arch = "";
  }

  time_limit_adj_millis = find_lang_specific_value(prob->lang_time_adj_millis, lang, 0);
  time_limit_adj = find_lang_specific_value(prob->lang_time_adj, lang, 0);

  if (!no_db_flag) {
    teamdb_export_team(state->teamdb_state, user_id, &te);
    ui = 0;
    if (te.user) ui = te.user->cnts0;
  }

  // new run packet creation
  srp = super_run_in_packet_alloc();
  struct super_run_in_global_packet *srgp = srp->global;

  srgp->contest_id = contest_id;
  srgp->judge_id = judge_id;
  srgp->run_id = run_id;
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
    if (te.login && te.login[0]) {
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
  if (srgp->run_uuid) {
    srgp->reply_packet_name = xstrdup(srgp->run_uuid);
  } else {
    snprintf(buf, sizeof(buf), "%06d", run_id);
    srgp->reply_packet_name = xstrdup(buf);
  }

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

  struct super_run_in_problem_packet *srpp = srp->problem;
  srpp->type = xstrdup(problem_unparse_type(prob->type));
  srpp->id = prob->tester_id;
  srpp->check_presentation = prob->check_presentation;
  srpp->scoring_checker = prob->scoring_checker;
  srpp->interactive_valuer = prob->interactive_valuer;
  srpp->disable_pe = prob->disable_pe;
  srpp->disable_wtl = prob->disable_wtl;
  srpp->use_stdin = prob->use_stdin;
  srpp->use_stdout = prob->use_stdout;
  srpp->combined_stdin = prob->combined_stdin;
  srpp->combined_stdout = prob->combined_stdout;
  srpp->ignore_exit_code = prob->ignore_exit_code;
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
  srpp->short_name = xstrdup(prob->short_name);
  srpp->long_name = xstrdup(prob->long_name);
  srpp->internal_name = xstrdup2(prob->internal_name);
  srpp->open_tests = xstrdup2(prob->open_tests);

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

  srpp->input_file = xstrdup(prob->input_file);
  srpp->output_file = xstrdup(prob->output_file);
  srpp->test_score_list = xstrdup2(prob->test_score_list);
  srpp->score_tests = xstrdup2(prob->score_tests);
  srpp->standard_checker = xstrdup2(prob->standard_checker);
  srpp->valuer_sets_marked = prob->valuer_sets_marked;
  if (prob->interactor_time_limit > 0) {
    srpp->interactor_time_limit_ms = prob->interactor_time_limit * 1000;
  }
  srpp->disable_stderr = prob->disable_stderr;
  if (prob->test_pat && prob->test_pat[0]) {
    srpp->test_pat = xstrdup(prob->test_pat);
  } else {
    snprintf(buf, sizeof(buf), "%%03d%s", prob->test_sfx);
    srpp->test_pat = xstrdup(buf);
  }
  if (prob->corr_pat && prob->corr_pat[0]) {
    srpp->corr_pat = xstrdup(prob->corr_pat);
  } else {
    snprintf(buf, sizeof(buf), "%%03d%s", prob->corr_sfx);
    srpp->corr_pat = xstrdup(buf);
  }
  if (prob->info_pat && prob->info_pat[0]) {
    srpp->info_pat = xstrdup(prob->info_pat);
  } else {
    snprintf(buf, sizeof(buf), "%%03d%s", prob->info_sfx);
    srpp->info_pat = xstrdup(buf);
  }
  if (prob->tgz_pat && prob->tgz_pat[0]) {
    srpp->tgz_pat = xstrdup(prob->tgz_pat);
  } else {
    snprintf(buf, sizeof(buf), "%%03d%s", prob->tgz_sfx);
    srpp->tgz_pat = xstrdup(buf);
  }
  if (prob->tgzdir_pat && prob->tgzdir_pat[0]) {
    srpp->tgzdir_pat = xstrdup(prob->tgzdir_pat);
  } else {
    snprintf(buf, sizeof(buf), "%%03d%s", prob->tgzdir_sfx);
    srpp->tgzdir_pat = xstrdup(buf);
  }
  srpp->test_sets = sarray_copy(prob->test_sets);
  srpp->checker_env = sarray_copy(prob->checker_env);
  srpp->valuer_env = sarray_copy(prob->valuer_env);
  srpp->interactor_env = sarray_copy(prob->interactor_env);
  srpp->test_checker_env = sarray_copy(prob->test_checker_env);
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
  srpp->max_core_size = prob->max_core_size;
  srpp->max_file_size = prob->max_file_size;
  srpp->max_open_file_count = prob->max_open_file_count;
  srpp->max_process_count = prob->max_process_count;
  srpp->enable_process_group = prob->enable_process_group;
  if (prob->umask && prob->umask[0]) {
    srpp->umask = xstrdup(prob->umask);
  }

  if (find_lang_specific_size(prob->lang_max_vm_size, lang,
                              &lang_specific_size) > 0) {
    srpp->max_vm_size = lang_specific_size;
  }
  if (find_lang_specific_size(prob->lang_max_stack_size, lang,
                              &lang_specific_size) > 0) {
    srpp->max_stack_size = lang_specific_size;
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
    s = tester->memory_limit_type;
    if (s && s[0] && s[0] != 1) {
      srtp->memory_limit_type = xstrdup(s);
    }
    s = tester->secure_exec_type;
    if (s && s[0] && s[0] != 1) {
      srtp->secure_exec_type = xstrdup(s);
    }
    srtp->no_core_dump = tester->no_core_dump;
    srtp->enable_memory_limit_error = tester->enable_memory_limit_error;
    srtp->kill_signal = xstrdup(tester->kill_signal);
    srtp->clear_env = tester->clear_env;
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
    if (run_change_status(state->runlog_state, run_id, RUN_RUNNING, 0, 1, -1, judge_id) < 0) {
      goto fail;
    }
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
  send_job_packet(NULL, (unsigned char**) mail_args, 0);
  xfree(ftxt); ftxt = 0;
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
  send_job_packet(NULL, (unsigned char **) mail_args, 0);
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
  send_job_packet(NULL, (unsigned char**) mail_args, 0);
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

int
serve_read_compile_packet(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        const unsigned char *compile_status_dir,
        const unsigned char *compile_report_dir,
        const unsigned char *pname)
{
  unsigned char rep_path[PATH_MAX];
  int  r, rep_flags = 0;
  struct run_entry re;
  const struct section_global_data *global = state->global;
  char *comp_pkt_buf = 0;       /* need char* for generic_read_file */
  size_t comp_pkt_size = 0;
  struct compile_reply_packet *comp_pkt = 0;
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

  if ((r = generic_read_file(&comp_pkt_buf, 0, &comp_pkt_size, SAFE | REMOVE,
                             compile_status_dir, pname, "")) <= 0)
    return r;

  if (compile_reply_packet_read(comp_pkt_size, comp_pkt_buf, &comp_pkt) < 0) {
    /* failed to parse a compile packet */
    /* we can't do any reasonable recovery, just drop the packet */
    goto non_fatal_error;
  }
  if (comp_pkt->contest_id != cnts->id) {
    err("read_compile_packet: mismatched contest_id %d", comp_pkt->contest_id);
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
  if (comp_pkt->judge_id != re.judge_id) {
    err("read_compile_packet: judge_id mismatch: %d, %d", comp_pkt->judge_id,
        re.judge_id);
    goto non_fatal_error;
  }
  if (re.status != RUN_COMPILING) {
    err("read_compile_packet: run %d is not compiling", comp_pkt->run_id);
    goto non_fatal_error;
  }

  comp_extra = (typeof(comp_extra)) comp_pkt->run_block;
  if (!comp_extra || comp_pkt->run_block_len != sizeof(*comp_extra)
      || comp_extra->accepting_mode < 0 || comp_extra->accepting_mode > 1) {
    snprintf(errmsg, sizeof(errmsg), "invalid run block\n");
    goto report_check_failed;
  }

  snprintf(pkt_name, sizeof(pkt_name), "%06d", comp_pkt->run_id);

  if ((comp_pkt->status == RUN_CHECK_FAILED || comp_pkt->status == RUN_COMPILE_ERR || comp_pkt->status == RUN_STYLE_ERR)) {
    if (generic_read_file(&txt_text, 0, &txt_size, REMOVE, compile_report_dir, pname, NULL) < 0) {
      snprintf(errmsg, sizeof(errmsg),
               "generic_read_file: %s, %s failed\n", compile_report_dir, pname);
      goto report_check_failed;
    }
    testing_report = testing_report_alloc(comp_pkt->contest_id, comp_pkt->run_id, re.judge_id);
    testing_report->status = comp_pkt->status;
    testing_report->compiler_output = xstrdup(txt_text);
    testing_report->scoring_system = global->score_system;
    testing_report->compile_error = 1;
    memcpy(&testing_report->uuid, &re.run_uuid, sizeof(testing_report->uuid));

    xfree(txt_text); txt_text = NULL; txt_size = 0;
    testing_report_to_str(&txt_text, &txt_size, 1, global->max_file_length, global->max_line_length, testing_report);

    if (re.store_flags == 1) {
      rep_flags = uuid_archive_make_write_path(state, rep_path, sizeof(rep_path),
                                               &re.run_uuid, txt_size, DFLT_R_UUID_XML_REPORT, 0);
    } else {
      rep_flags = archive_make_write_path(state, rep_path, sizeof(rep_path),
                                          global->xml_report_archive_dir, comp_pkt->run_id, txt_size, 0, 0);
    }
    if (rep_flags < 0) {
      snprintf(errmsg, sizeof(errmsg),
               "archive_make_write_path: %s, %d, %ld failed\n",
               global->xml_report_archive_dir, comp_pkt->run_id,
               (long) txt_size);
      goto report_check_failed;
    }

    if (re.store_flags == 1) {
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
      if (run_change_status_4(state->runlog_state, comp_pkt->run_id, RUN_CHECK_FAILED) < 0)
        goto non_fatal_error;
      serve_send_check_failed_email(config, cnts, comp_pkt->run_id);
      goto success;
    }

    if (comp_pkt->status == RUN_COMPILE_ERR || comp_pkt->status == RUN_STYLE_ERR) {
      if (run_change_status_4(state->runlog_state, comp_pkt->run_id, comp_pkt->status) < 0)
        goto non_fatal_error;

      serve_update_standings_file(state, cnts, 0);
      if (global->notify_status_change > 0 && !re.is_hidden && comp_extra->notify_flag) {
        serve_notify_user_run_status_change(config, cnts, state, re.user_id,
                                            comp_pkt->run_id, comp_pkt->status);
      }
      goto success;
    }

    abort();
  }

  if (1 /*re.store_flags == 1*/) {
    snprintf(txt_packet_path, sizeof(txt_packet_path), "%s/%s.txt", compile_report_dir, pname);
    generic_read_file(&txt_text, 0, &txt_size, REMOVE, NULL, txt_packet_path, NULL);

    testing_report = testing_report_alloc(comp_pkt->contest_id, comp_pkt->run_id, re.judge_id);
    testing_report->status = RUN_RUNNING;
    if (txt_text) {
      testing_report->compiler_output = xstrdup(txt_text);
    }
    testing_report->scoring_system = global->score_system;
    testing_report->compile_error = 1;
    memcpy(&testing_report->uuid, &re.run_uuid, sizeof(testing_report->uuid));

    xfree(txt_text); txt_text = NULL; txt_size = 0;
    testing_report_to_str(&txt_text, &txt_size, 1, global->max_file_length, global->max_line_length, testing_report);

    if (re.store_flags == 1) {
      rep_flags = uuid_archive_make_write_path(state, rep_path, sizeof(rep_path),
                                               &re.run_uuid, txt_size, DFLT_R_UUID_XML_REPORT, 0);
    } else {
      rep_flags = archive_make_write_path(state, rep_path, sizeof(rep_path),
                                          global->xml_report_archive_dir, comp_pkt->run_id, txt_size, 0, 0);
    }
    ASSERT(rep_flags >= 0);
    if (re.store_flags == 1) {
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

  if (comp_pkt->status == RUN_CHECK_FAILED
      || comp_pkt->status == RUN_COMPILE_ERR
      || comp_pkt->status == RUN_STYLE_ERR) {
    if ((report_size = generic_file_size(compile_report_dir, pname, "")) < 0) {
      err("read_compile_packet: cannot get report file size");
      snprintf(errmsg, sizeof(errmsg), "cannot get size of %s/%s\n",
               compile_report_dir, pname);
      goto report_check_failed;
    }

    if (re.store_flags == 1) {
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
    if (re.store_flags == 1) {
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
                            RUN_CHECK_FAILED) < 0)
      goto non_fatal_error;
    if (re.store_flags == 1) {
      if (uuid_archive_dir_prepare(state, &re.run_uuid, DFLT_R_UUID_XML_REPORT, 0) < 0)
        goto non_fatal_error;
    } else {
      if (archive_dir_prepare(state, global->xml_report_archive_dir,
                              comp_pkt->run_id, 0, 0) < 0)
        goto non_fatal_error;
    }
    if (generic_copy_file(REMOVE, compile_report_dir, pname, "",
                          rep_flags, 0, rep_path, "") < 0) {
      snprintf(errmsg, sizeof(errmsg),
               "generic_copy_file: %s, %s, %d, %s failed\n",
               compile_report_dir, pname, rep_flags, rep_path);
      goto report_check_failed;
    }
    serve_send_check_failed_email(config, cnts, comp_pkt->run_id);
    goto success;
  }

  if (comp_pkt->status == RUN_COMPILE_ERR
      || comp_pkt->status == RUN_STYLE_ERR) {
    /* if status change fails, we cannot do reasonable recovery */
    if (run_change_status_4(state->runlog_state, comp_pkt->run_id,
                            comp_pkt->status) < 0)
      goto non_fatal_error;

    if (re.store_flags == 1) {
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
    if (generic_copy_file(REMOVE, compile_report_dir, pname, "",
                          rep_flags, 0, rep_path, "") < 0) {
      snprintf(errmsg, sizeof(errmsg), "generic_copy_file: %s, %s, %d, %s failed\n",
               compile_report_dir, pname, rep_flags, rep_path);
      goto report_check_failed;
    }
    serve_update_standings_file(state, cnts, 0);
    if (global->notify_status_change > 0 && !re.is_hidden
        && comp_extra->notify_flag) {
      serve_notify_user_run_status_change(config, cnts, state, re.user_id,
                                          comp_pkt->run_id, comp_pkt->status);
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
                            RUN_ACCEPTED) < 0)
      goto non_fatal_error;
    if (global->notify_status_change > 0 && !re.is_hidden
        && comp_extra->notify_flag) {
      serve_notify_user_run_status_change(config, cnts, state, re.user_id,
                                          comp_pkt->run_id, RUN_ACCEPTED);
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

  if (serve_run_request(state, cnts, stderr, run_text, run_size,
                        global->contest_id, comp_pkt->run_id,
                        re.user_id, re.prob_id, re.lang_id, re.variant,
                        comp_extra->priority_adjustment,
                        comp_pkt->judge_id, comp_extra->accepting_mode,
                        comp_extra->notify_flag, re.mime_type, re.eoln_type,
                        re.locale_id, compile_report_dir, comp_pkt, 0, &re.run_uuid,
                        comp_extra->rejudge_flag) < 0) {
    snprintf(errmsg, sizeof(errmsg), "failed to write run packet\n");
    goto report_check_failed;
  }
  xfree(run_text); run_text = 0; run_size = 0;

 success:
  xfree(comp_pkt_buf);
  xfree(txt_text);
  compile_reply_packet_free(comp_pkt);
  testing_report_free(testing_report);
  return 1;

 report_check_failed:
  xfree(run_text); run_text = 0; run_size = 0;
  serve_send_check_failed_email(config, cnts, comp_pkt->run_id);

  /* this is error recover, so if error happens again, we cannot do anything */
  if (run_change_status_4(state->runlog_state, comp_pkt->run_id,
                          RUN_CHECK_FAILED) < 0)
    goto non_fatal_error;
  report_size = strlen(errmsg);
  if (re.store_flags == 1) {
    rep_flags = uuid_archive_prepare_write_path(state, rep_path, sizeof(rep_path),
                                                &re.run_uuid, report_size, DFLT_R_UUID_XML_REPORT, 0, 0);
  } else {
    rep_flags = archive_prepare_write_path(state, rep_path, sizeof(rep_path),
                                           global->xml_report_archive_dir, comp_pkt->run_id,
                                           report_size, NULL, 0, 0);
  }
  if (rep_flags < 0)
    goto non_fatal_error;

  /* error code is ignored */
  generic_write_file(errmsg, report_size, rep_flags, 0, rep_path, 0);
  /* goto non_fatal_error; */

 non_fatal_error:
  xfree(comp_pkt_buf);
  xfree(txt_text);
  compile_reply_packet_free(comp_pkt);
  testing_report_free(testing_report);
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
    case RUN_CHECK_FAILED:
    case RUN_MEM_LIMIT_ERR:
    case RUN_SECURITY_ERR:
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
    case RUN_RUN_TIME_ERR:
    case RUN_TIME_LIMIT_ERR:
    case RUN_WALL_TIME_LIMIT_ERR:
    case RUN_PRESENTATION_ERR:
    case RUN_WRONG_ANSWER_ERR:
    case RUN_CHECK_FAILED:
    case RUN_MEM_LIMIT_ERR:
    case RUN_SECURITY_ERR:
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
  snprintf(buf, size, "%04d/%02d/%02d %02d:%02d:%02d.%06d",
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

int
serve_read_run_packet(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        const unsigned char *run_status_dir,
        const unsigned char *run_report_dir,
        const unsigned char *run_full_archive_dir,
        const unsigned char *pname)
{
  const struct section_global_data *global = state->global;
  path_t rep_path, full_path, cur_rep_path;
  int r, rep_flags, full_flags, i, cur_rep_flag;
  struct run_entry re, pe;
  char *reply_buf = 0;          /* need char* for generic_read_file */
  size_t reply_buf_size = 0;
  struct run_reply_packet *reply_pkt = 0;
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
  if ((r = generic_read_file(&reply_buf, 0, &reply_buf_size, SAFE | REMOVE,
                             run_status_dir, pname, "")) <= 0)
    return r;

  if (run_reply_packet_read(reply_buf_size, reply_buf, &reply_pkt) < 0)
    goto failed;
  xfree(reply_buf), reply_buf = 0;

  if (reply_pkt->contest_id != cnts->id) {
    err("read_run_packet: contest_id mismatch: %d in packet",
        reply_pkt->contest_id);
    goto failed;
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

  if (re.status != RUN_RUNNING) {
    err("read_run_packet: run %d status is not RUNNING", reply_pkt->run_id);
    goto failed;
  }
  if (re.judge_id != reply_pkt->judge_id) {
    err("read_run_packet: judge_id mismatch: packet: %d, db: %d",
        reply_pkt->judge_id, re.judge_id);
    goto failed;
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
  } else if (prob->use_ac_not_ok > 0 && reply_pkt->status == RUN_OK) {
    reply_pkt->status = RUN_PENDING_REVIEW;
    if (prob->ignore_prev_ac > 0) ignore_prev_ac = 1;
  }
  if (reply_pkt->status == RUN_CHECK_FAILED)
    serve_send_check_failed_email(config, cnts, reply_pkt->run_id);
  if (reply_pkt->marked_flag < 0) reply_pkt->marked_flag = 0;
  if (reply_pkt->status == RUN_CHECK_FAILED) {
    if (run_change_status_4(state->runlog_state, reply_pkt->run_id,
                            reply_pkt->status) < 0)
      goto failed;
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
                            reply_pkt->score, 0, reply_pkt->marked_flag,
                            has_user_score, user_status, user_tests_passed,
                            user_score) < 0)
      goto failed;
  }
  serve_update_standings_file(state, cnts, 0);
  if (global->notify_status_change > 0 && !re.is_hidden
      && reply_pkt->notify_flag) {
    serve_notify_user_run_status_change(config, cnts, state, re.user_id,
                                        reply_pkt->run_id, reply_pkt->status);
  }

  // read the new testing report
  if (generic_read_file(&new_rep_text, 0, &new_rep_len, REMOVE, run_report_dir, pname, NULL) < 0) {
    goto failed;
  }

  // try to read the existing testing report
  cur_rep_flag = serve_make_xml_report_read_path(state, cur_rep_path, sizeof(cur_rep_path), &re);
  if (cur_rep_flag >= 0) {
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

  // try to merge the testing reports
  if (compiler_output) {
    const unsigned char *new_start_ptr = NULL;
    int new_content_type = get_content_type(new_rep_text, &new_start_ptr);
    if (new_content_type == CONTENT_TYPE_XML && new_start_ptr) {
      new_tr = testing_report_parse_xml(new_start_ptr);
      if (new_tr && !new_tr->compiler_output) {
        new_tr->compiler_output = compiler_output; compiler_output = NULL;
        xfree(new_rep_text); new_rep_text = NULL; new_rep_len = 0;
        testing_report_to_str(&new_rep_text, &new_rep_len, 1, global->max_file_length, global->max_line_length, new_tr);
      }
      testing_report_free(new_tr); new_tr = NULL;
      xfree(compiler_output); compiler_output = NULL;
    }
  }

  if (re.store_flags == 1) {
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
    if (re.store_flags == 1) {
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
        run_change_status_3(state->runlog_state, i, RUN_IGNORED, 0, 1, 0, 0, 0, 0, 0, 0, 0);
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
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        int run_id,
        int judge_id,
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

  if (status == RUN_CHECK_FAILED)
    serve_send_check_failed_email(config, cnts, run_id);

  /* FIXME: handle database update error */
  (void) failed_test;
  run_change_status_3(state->runlog_state, run_id, glob_status, passed_tests, 1,
                      score, 0, 0, 0, 0, 0, 0);
  serve_update_standings_file(state, cnts, 0);
  /*
  if (global->notify_status_change > 0 && !re.is_hidden
      && comp_extra->notify_flag) {
    serve_notify_user_run_status_change(cnts, state, re.user_id,
                                        run_id, glob_status);
  }
  */

  // FIXME: handle errors
  run_get_entry(state->runlog_state, run_id, re);
  if (re->store_flags == 1) {
    rep_flags = uuid_archive_prepare_write_path(state, rep_path, sizeof(rep_path),
                                                &re->run_uuid, xml_len, DFLT_R_UUID_XML_REPORT, 0, 0);
  } else {
    rep_flags = archive_prepare_write_path(state, rep_path, sizeof(rep_path),
                                           global->xml_report_archive_dir, run_id,
                                           xml_len, NULL, 0, 0);
  }
  generic_write_file(xml_buf, xml_len, rep_flags, 0, rep_path, "");

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
  testing_report_xml_t tr = testing_report_alloc(cnts->id, run_id, 0);
  size_t tr_z = 0;
  char *tr_t = NULL;
  unsigned char tr_p[PATH_MAX];
  int flags = 0;
  struct run_entry re;

  run_get_entry(state->runlog_state, run_id, &re);

  tr->status = RUN_CHECK_FAILED;
  tr->scoring_system = global->score_system;
  tr->marked_flag = 0;
  tr->user_status = -1;
  tr->errors = xstrdup(error_text);

  testing_report_to_str(&tr_t, &tr_z, 1/*utf8_mode*/, global->max_file_length, global->max_line_length, tr);
  tr = testing_report_free(tr);

  serve_audit_log(state, run_id, &re, 0, 0, 0,
                  NULL, "check failed", -1,
                  "  %s\n\n", error_text);

  if (re.store_flags) {
    flags = uuid_archive_prepare_write_path(state, tr_p, sizeof(tr_p),
                                            &re.run_uuid, tr_z, DFLT_R_UUID_XML_REPORT, 0, 0);
  } else {
    flags = archive_prepare_write_path(state, tr_p, sizeof(tr_p), global->xml_report_archive_dir, run_id,
                                       tr_z, NULL, 0, 0);
  }
  if (flags < 0) {
    err("archive_make_write_path: %s, %d, %ld failed\n", global->xml_report_archive_dir, run_id, (long) tr_z);
  } else {
    generic_write_file(tr_t, tr_z, flags, NULL, tr_p, NULL);
  }
  xfree(tr_t); tr_t = NULL;

  if (run_change_status_4(state->runlog_state, run_id, RUN_CHECK_FAILED) < 0) {
    err("run_change_status_4: %d, RUN_CHECK_FAILED failed\n", run_id);
  }
}

void
serve_rejudge_run(
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

  serve_audit_log(state, run_id, &re, user_id, ip, ssl_flag,
                  "rejudge", "ok", RUN_COMPILING, NULL);
 
  if (re.prob_id <= 0 || re.prob_id > state->max_prob
      || !(prob = state->probs[re.prob_id])) {
    err("rejudge_run: bad problem: %d", re.prob_id);
    return;
  }
  if (prob->manual_checking > 0 || prob->disable_testing > 0) return;
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
      serve_judge_built_in_problem(config, state, cnts, run_id, 1 /* judge_id*/,
                                   variant, accepting_mode, &re, prob,
                                   px, user_id, ip, ssl_flag);
      return;
    }

    if (prob->style_checker_cmd && prob->style_checker_cmd[0]) {
      r = serve_compile_request(state, 0 /* str*/, -1 /* len*/, global->contest_id,
                                run_id, re.user_id, 0 /* lang_id */, re.variant,
                                0 /* locale_id */, 1 /* output_only*/,
                                mime_type_get_suffix(re.mime_type),
                                NULL /* compiler_env */,
                                1 /* style_check_only */,
                                prob->style_checker_cmd,
                                prob->style_checker_env,
                                0 /* accepting_mode */,
                                priority_adjustment,
                                1 /* notify flag */,
                                prob, NULL /* lang */,
                                0 /* no_db_flag */, &re.run_uuid, re.store_flags,
                                1 /* rejudge_flag */);
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

    serve_run_request(state, cnts, stderr, run_text, run_size,
                      global->contest_id, run_id,
                      re.user_id, re.prob_id, re.lang_id,
                      re.variant, priority_adjustment,
                      -1, accepting_mode, 1, re.mime_type, re.eoln_type,
                      re.locale_id, 0, 0, 0, &re.run_uuid,
                      1 /* rejudge_flag */);
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

  r = serve_compile_request(state, 0, -1, global->contest_id, run_id, re.user_id,
                            lang->compile_id, re.variant, re.locale_id,
                            (prob->type > 0),
                            lang->src_sfx,
                            lang->compiler_env,
                            0, prob->style_checker_cmd,
                            prob->style_checker_env,
                            accepting_mode, priority_adjustment, 1, prob, lang, 0,
                            &re.run_uuid, re.store_flags,
                            1 /* rejudge_flag */);
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

  if (!state->global->contest_start_cmd[0]) return;
  if (!(tsk = task_New())) return;
  task_AddArg(tsk, state->global->contest_start_cmd);
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

static unsigned char olympiad_rejudgeable_runs[RUN_LAST + 1] =
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
  [RUN_IGNORED]          = 0,
  [RUN_DISQUALIFIED]     = 0,
  [RUN_PENDING]          = 0,
  [RUN_MEM_LIMIT_ERR]    = 0,
  [RUN_SECURITY_ERR]     = 0,
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

static unsigned char olympiad_output_only_rejudgeable_runs[RUN_LAST + 1] =
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
  [RUN_IGNORED]          = 0,
  [RUN_DISQUALIFIED]     = 0,
  [RUN_PENDING]          = 0,
  [RUN_MEM_LIMIT_ERR]    = 0,
  [RUN_SECURITY_ERR]     = 0,
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

static unsigned char generally_rejudgable_runs[RUN_LAST + 1] =
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
  [RUN_IGNORED]          = 1,
  [RUN_DISQUALIFIED]     = 1,
  [RUN_PENDING]          = 1,
  [RUN_MEM_LIMIT_ERR]    = 1,
  [RUN_SECURITY_ERR]     = 1,
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

  if (pe->status > RUN_LAST) return 0;
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
      serve_rejudge_run(job->config, job->cnts, job->state, job->cur_id,
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
    job = create_rejudge_by_mask_job(config, cnts, state, user_id, ip,
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
      serve_rejudge_run(config, cnts, state, r, user_id, ip, ssl_flag,
                        force_flag, priority_adjustment);
    }
  }

  return NULL;
}

struct rejudge_problem_job
{
  struct server_framework_job b;

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
      serve_rejudge_run(job->config, job->cnts, job->state, job->cur_id,
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
    job = create_rejudge_problem_job(config, cnts, state, user_id, ip,
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
      serve_rejudge_run(config, cnts, state, r, user_id, ip, ssl_flag, 0,
                        priority_adjustment);
    }
    return NULL;
  }

  for (r = 0; r < total_runs; r++) {
    if (run_get_entry(state->runlog_state, r, &re) >= 0
        && is_generally_rejudgable(state, &re, INT_MAX)
        && re.status != RUN_IGNORED && re.status != RUN_DISQUALIFIED
        && re.prob_id == prob_id) {
      serve_rejudge_run(config, cnts, state, r, user_id, ip, ssl_flag, 0,
                        priority_adjustment);
    }
  }
  return NULL;
}

struct judge_suspended_job
{
  struct server_framework_job b;

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
      serve_rejudge_run(sj->config, sj->cnts, sj->state,
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
    job = create_judge_suspended_job(config, cnts, state, user_id, ip,
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
      serve_rejudge_run(config, cnts, state, r, user_id, ip, ssl_flag, 0,
                        priority_adjustment);
    }
  }
  return NULL;
}

struct rejudge_all_job
{
  struct server_framework_job b;

  // passed parameters
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
      serve_rejudge_run(rj->config, rj->cnts, rj->state,
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
    job = create_rejudge_all_job(config, cnts, state, user_id, ip,
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
      serve_rejudge_run(config, cnts, state, r, user_id, ip, ssl_flag, 0,
                        priority_adjustment);
    }
    return NULL;
  }

  for (r = 0; r < total_runs; r++) {
    if (run_get_entry(state->runlog_state, r, &re) >= 0
        && is_generally_rejudgable(state, &re, INT_MAX)
        && re.status != RUN_IGNORED && re.status != RUN_DISQUALIFIED) {
      serve_rejudge_run(config, cnts, state, r, user_id, ip, ssl_flag, 0,
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
  if (global->xml_report_archive_dir[0])
    clear_directory(global->xml_report_archive_dir);
  if (global->report_archive_dir[0])
    clear_directory(global->report_archive_dir);
  if (global->run_archive_dir[0])
    clear_directory(global->run_archive_dir);
  if (global->team_report_archive_dir[0])
    clear_directory(global->team_report_archive_dir);
  if (global->full_archive_dir[0])
    clear_directory(global->full_archive_dir);
  if (global->audit_log_dir[0])
    clear_directory(global->audit_log_dir);
  if (global->team_extra_dir[0])
    clear_directory(global->team_extra_dir);
  if (global->uuid_archive_dir[0])
    clear_directory(global->uuid_archive_dir);

  unsigned char path[PATH_MAX];
  snprintf(path, sizeof(path), "%s/dir", global->status_dir);
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
  int total_runs, i;
  time_t *user_time = 0, *new_time, *pt;
  int user_time_size = 0, new_size;
  int need_reload = 0;

  if (!cs->global->is_virtual) return 0;

  run_get_header(cs->runlog_state, &head);
  if (!head.duration) return 0;
  total_runs = run_get_total(cs->runlog_state);
  runs = run_get_entries_ptr(cs->runlog_state);

  user_time_size = 128;
  XCALLOC(user_time, user_time_size);

#if 0
  for (i = 0; i < total_runs; i++) {
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

  for (i = 0; i < total_runs; i++) {
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
          run_set_hidden(cs->runlog_state, i);
          need_reload = 1;
        }
      } else if (!*pt) {
        // first run
        *pt = -2;
      } else if (pe->time > *pt + head.duration) {
        // virtual run overrun
        if (!pe->is_hidden) {
          err("run %d: virtual time run overrun, made hidden!", i);
          run_set_hidden(cs->runlog_state, i);
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
  serve_move_files_to_insert_run(cs, run_id);
  if (cs->global->score_system == SCORE_OLYMPIAD
      && cs->global->is_virtual && cs->global->disable_virtual_auto_judge<= 0) {
    serve_event_add(cs, p->time + 1, SERVE_EVENT_JUDGE_OLYMPIAD, p->user_id, 0);
  }
  if (p->handler) (*p->handler)(cnts, cs, p);
  serve_event_remove(cs, p);
}

static void
handle_judge_olympiad_event(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t cs,
        struct serve_event_queue *p)
{
  int count;
  struct run_entry rs, re;

  if (cs->global->score_system != SCORE_OLYMPIAD
      || !cs->global->is_virtual) goto done;
  count = run_get_virtual_info(cs->runlog_state, p->user_id, &rs, &re);
  if (count < 0) {
    err("virtual user %d cannot be judged", p->user_id);
    goto done;
  }
  // cannot do judging before all transint runs are done
  if (count > 0) return;
  if (rs.status != RUN_VIRTUAL_START || rs.user_id != p->user_id)
    goto done;
  if (re.status != RUN_VIRTUAL_STOP || re.user_id != p->user_id)
    goto done;
  // already judged somehow
  if (rs.judge_id > 0) goto done;
  serve_judge_virtual_olympiad(config, cnts, cs, p->user_id, re.run_id,
                               DFLT_G_REJUDGE_PRIORITY_ADJUSTMENT);
  if (p->handler) (*p->handler)(cnts, cs, p);

 done:
  serve_event_remove(cs, p);
  return;
}

void
serve_handle_events(
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
      handle_judge_olympiad_event(config, cnts, cs, p);
      break;
    default:
      abort();
    }
  }
}

void
serve_judge_virtual_olympiad(
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
  int vstart_id;

  if (global->score_system != SCORE_OLYMPIAD || !global->is_virtual) return;
  if (user_id <= 0) return;
  if (run_get_virtual_start_entry(cs->runlog_state, user_id, &re) < 0) return;
  if (re.judge_id > 0) return;
  if (run_id < 0) return;
  vstart_id = re.run_id;

  // Fully rejudge latest submits
  if (run_get_entry(cs->runlog_state, run_id, &re) < 0) return;
  if (re.status != RUN_VIRTUAL_STOP) return;
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
    if (s != RUN_OK && s != RUN_PARTIAL && s != RUN_ACCEPTED && s != RUN_PENDING_REVIEW
        && (s != RUN_WRONG_ANSWER_ERR || prob->type == PROB_TYPE_STANDARD))
        continue;
    if (latest_runs[re.prob_id] < 0) latest_runs[re.prob_id] = run_id;
  }
  if (run_id < 0) return;

  for (i = 1; i <= cs->max_prob; i++) {
    if (latest_runs[i] >= 0)
      serve_rejudge_run(config, cnts, cs, latest_runs[i], user_id, 0, 0, 1,
                        priority_adjustment);
  }
  run_set_judge_id(cs->runlog_state, vstart_id, 1);
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
      if (run_get_entry(state->runlog_state, r, &re) >= 0 && run_clear_entry(state->runlog_state, r) >= 0) {
        if (re.store_flags == 1) {
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
serve_ignore_by_mask(serve_state_t state,
                     int user_id, const ej_ip_t *ip, int ssl_flag,
                     int mask_size, unsigned long *mask,
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
    if (re.status > RUN_MAX_STATUS && re.status < RUN_TRANSIENT_FIRST)
      continue;
    if (re.status == new_status) continue;

    re.status = new_status;
    if (run_set_entry(state->runlog_state, r, RE_STATUS, &re) >= 0) {
      if (re.store_flags == 1) {
        uuid_archive_remove(state, &re.run_uuid, 1);
      } else {
        archive_remove(state, global->xml_report_archive_dir, r, 0);
        archive_remove(state, global->report_archive_dir, r, 0);
        archive_remove(state, global->team_report_archive_dir, r, 0);
        archive_remove(state, global->full_archive_dir, r, 0);
      }
      serve_audit_log(state, r, &re, user_id, ip, ssl_flag,
                      cmd, "ok", new_status, NULL);
    }
  }
}

void
serve_mark_by_mask(
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
    if (!run_is_valid_status(re.status)) continue;
    if (re.status > RUN_MAX_STATUS) continue;
    if (re.is_marked == mark_value) continue;

    re.is_marked = mark_value;
    run_set_entry(state->runlog_state, r, RE_IS_MARKED, &re);

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
    if (!run_is_valid_status(re.status)) continue;
    if (re.status > RUN_MAX_STATUS) continue;

    if (re.token_count != token_count || re.token_flags != token_flags) {
      re.token_count = token_count;
      re.token_flags = token_flags;
      run_set_entry(state->runlog_state, r, RE_TOKEN_COUNT | RE_TOKEN_FLAGS, &re);
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
  return 'A' + priority;
}

int
serve_testing_queue_delete(
        const struct contest_desc *cnts,
        const serve_state_t state,
        const unsigned char *packet_name,
        const unsigned char *user_login)
{
  const struct section_global_data *global = state->global;
  path_t out_path;
  path_t out_name;
  path_t exe_path;
  struct run_entry re;
  struct super_run_in_packet *srp = NULL;
  const unsigned char *exe_sfx = NULL;
  unsigned char run_queue_dir[PATH_MAX];
  unsigned char run_exe_dir[PATH_MAX];

  if (cnts && cnts->run_managed) {
    if (global && global->super_run_dir && global->super_run_dir[0]) {
      snprintf(run_exe_dir, sizeof(run_exe_dir), "%s/var/exe", global->super_run_dir);
      snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/var/queue", global->super_run_dir);
    } else {
      snprintf(run_exe_dir, sizeof(run_exe_dir), "%s/super-run/var/exe", EJUDGE_CONTESTS_HOME_DIR);
      snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/super-run/var/queue", EJUDGE_CONTESTS_HOME_DIR);
    }
  } else {
    snprintf(run_exe_dir, sizeof(run_exe_dir), "%s/exe", global->run_dir);
    snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/queue", global->run_dir);
  }

  if (!(srp = testing_queue_lock_entry(cnts->id, user_login, run_queue_dir, packet_name,
                                       out_name, sizeof(out_name),
                                       out_path, sizeof(out_path))))
    return -1;

  if (!srp->global) {
    srp = super_run_in_packet_free(srp);
    return -1;
  }

  exe_sfx = srp->global->exe_sfx;
  if (!exe_sfx) exe_sfx = "";

  snprintf(exe_path, sizeof(exe_path), "%s/%s%s", run_exe_dir, packet_name, exe_sfx);
  unlink(out_path);
  unlink(exe_path);

  if (run_get_entry(state->runlog_state, srp->global->run_id, &re) >= 0
      && re.status == RUN_RUNNING
      && re.judge_id == srp->global->judge_id) {
    run_change_status_4(state->runlog_state, srp->global->run_id, RUN_PENDING);
  }

  srp = super_run_in_packet_free(srp);
  return 0;
}

int
serve_testing_queue_change_priority(
        const struct contest_desc *cnts,
        const serve_state_t state,
        const unsigned char *packet_name,
        int adjustment,
        const unsigned char *user_login)
{
  const struct section_global_data *global = state->global;
  path_t out_path;
  path_t out_name;
  path_t new_packet_name;
  path_t exe_path;
  path_t new_exe_path;
  struct super_run_in_packet *srp = NULL;
  const unsigned char *exe_sfx = NULL;
  unsigned char run_queue_dir[PATH_MAX];
  unsigned char run_exe_dir[PATH_MAX];

  if (cnts && cnts->run_managed) {
    if (global && global->super_run_dir && global->super_run_dir[0]) {
      snprintf(run_exe_dir, sizeof(run_exe_dir), "%s/var/exe", global->super_run_dir);
      snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/var/queue", global->super_run_dir);
    } else {
      snprintf(run_exe_dir, sizeof(run_exe_dir), "%s/super-run/var/exe", EJUDGE_CONTESTS_HOME_DIR);
      snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/super-run/var/queue", EJUDGE_CONTESTS_HOME_DIR);
    }
  } else {
    snprintf(run_exe_dir, sizeof(run_exe_dir), "%s/exe", global->run_dir);
    snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/queue", global->run_dir);
  }

  if (!(srp = testing_queue_lock_entry(cnts->id, user_login, run_queue_dir, packet_name,
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
    testing_queue_unlock_entry(run_queue_dir, out_path, packet_name);
    srp = super_run_in_packet_free(srp);
    return 0;
  }

  snprintf(exe_path, sizeof(exe_path), "%s/%s%s", run_exe_dir, packet_name, exe_sfx);
  snprintf(new_exe_path, sizeof(new_exe_path), "%s/%s%s", run_exe_dir, new_packet_name, exe_sfx);
  if (rename(exe_path, new_exe_path) < 0) {
    err("serve_testing_queue_up: rename %s -> %s failed: %s",
        exe_path, new_exe_path, os_ErrorMsg());
    testing_queue_unlock_entry(run_queue_dir, out_path, packet_name);
    goto fail;
  }

  testing_queue_unlock_entry(run_queue_dir, out_path, new_packet_name);

  srp = super_run_in_packet_free(srp);
  return 0;

fail:
  srp = super_run_in_packet_free(srp);
  return -1;
}

static void
collect_run_packets(const struct contest_desc *cnts, const serve_state_t state, strarray_t *vec)
{
  const struct section_global_data *global = state->global;
  path_t dir_path;
  DIR *d = 0;
  struct dirent *dd;
  unsigned char run_queue_dir[PATH_MAX];

  if (cnts && cnts->run_managed) {
    if (global && global->super_run_dir && global->super_run_dir[0]) {
      snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/var/queue", global->super_run_dir);
    } else {
      snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/super-run/var/queue", EJUDGE_CONTESTS_HOME_DIR);
    }
  } else {
    snprintf(run_queue_dir, sizeof(run_queue_dir), "%s/queue", global->run_dir);
  }

  memset(vec, 0, sizeof(*vec));
  snprintf(dir_path, sizeof(dir_path), "%s/dir", run_queue_dir);
  if (!(d = opendir(dir_path))) return;

  while ((dd = readdir(d))) {
    if (!strcmp(dd->d_name, ".") && !strcmp(dd->d_name, "..")) continue;
    xexpand(vec);
    vec->v[vec->u++] = xstrdup(dd->d_name);
  }

  closedir(d); d = 0;
}

int
serve_testing_queue_delete_all(
        const struct contest_desc *cnts,
        const serve_state_t state,
        const unsigned char *user_login)
{
  strarray_t vec;
  int i;

  collect_run_packets(cnts, state, &vec);
  for (i = 0; i < vec.u; ++i) {
    serve_testing_queue_delete(cnts, state, vec.v[i], user_login);
  }

  xstrarrayfree(&vec);
  return 0;
}

int
serve_testing_queue_change_priority_all(
        const struct contest_desc *cnts,
        const serve_state_t state,
        int adjustment,
        const unsigned char *user_login)
{
  strarray_t vec;
  int i;

  collect_run_packets(cnts, state, &vec);
  for (i = 0; i < vec.u; ++i) {
    serve_testing_queue_change_priority(cnts, state, vec.v[i], adjustment, user_login);
  }

  xstrarrayfree(&vec);
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
  if (re->store_flags == 1) {
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
  if (re->store_flags == 1) {
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
  if (re->store_flags == 1) {
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
  if (re->store_flags == 1) {
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
  if (re->store_flags == 1) {
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
    if (clar.from != user_id
        && !team_extra_get_clar_status(state->team_extra_state, user_id, i))
      total++;
  }
  return total;
}
