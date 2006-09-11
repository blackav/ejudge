/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "serve_state.h"
#include "runlog.h"
#include "prepare.h"
#include "l10n.h"
#include "html.h"
#include "errlog.h"
#include "protocol.h"
#include "clarlog.h"
#include "fileutl.h"
#include "teamdb.h"
#include "contests.h"
#include "job_packet.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <pwd.h>

void
serve_update_standings_file(serve_state_t state, int force_flag)
{
  time_t start_time, stop_time, duration;
  int p = 0;
  int accepting_mode = 0;

  run_get_times(state->runlog_state, &start_time, 0, &duration,
                &stop_time);

  while (1) {
    if (state->global->virtual) break;
    if (force_flag) break;
    if (!state->global->autoupdate_standings) return;
    if (!duration) break;
    if (!state->global->board_fog_time) break;

    ASSERT(state->current_time >= start_time);
    ASSERT(state->global->board_fog_time >= 0);
    ASSERT(state->global->board_unfog_time >= 0);
    
    p = run_get_fog_period(state->runlog_state, state->current_time,
                           state->global->board_fog_time,
                           state->global->board_unfog_time);
    if (p == 1) return;
    break;
  }

  if (!state->global->virtual) {
    p = run_get_fog_period(state->runlog_state, state->current_time,
                           state->global->board_fog_time,
                           state->global->board_unfog_time);
  }
  l10n_setlocale(state->global->standings_locale_id);
  if (state->global->score_system_val == SCORE_OLYMPIAD
      && !state->olympiad_judging_mode)
    accepting_mode = 1;
  write_standings(state, state->global->status_dir,
                  state->global->standings_file_name,
                  state->global->users_on_page,
                  state->global->stand_header_txt,
                  state->global->stand_footer_txt,
                  accepting_mode);
  if (state->global->stand2_file_name[0]) {
    write_standings(state, state->global->status_dir,
                    state->global->stand2_file_name, 0,
                    state->global->stand2_header_txt,
                    state->global->stand2_footer_txt,
                    accepting_mode);
  }
  l10n_setlocale(0);
  if (state->global->virtual) return;
  switch (p) {
  case 0:
    state->global->start_standings_updated = 1;
    break;
  case 1:
    state->global->fog_standings_updated = 1;
    break;
  case 2:
    state->global->unfog_standings_updated = 1;
    break;
  }
}

void
serve_update_public_log_file(serve_state_t state)
{
  time_t start_time, stop_time, duration;
  int p;

  if (!state->global->plog_update_time) return;
  if (state->current_time < state->last_update_public_log + state->global->plog_update_time) return;

  run_get_times(state->runlog_state, &start_time, 0, &duration, &stop_time);

  while (1) {
    if (!duration) break;
    if (!state->global->board_fog_time) break;

    ASSERT(state->current_time >= start_time);
    ASSERT(state->global->board_fog_time >= 0);
    ASSERT(state->global->board_unfog_time >= 0);
    
    p = run_get_fog_period(state->runlog_state, state->current_time,
                           state->global->board_fog_time,
                           state->global->board_unfog_time);
    if (p == 1) return;
    break;
  }

  l10n_setlocale(state->global->standings_locale_id);
  write_public_log(state, state->global->status_dir,
                   state->global->plog_file_name,
                   state->global->plog_header_txt,
                   state->global->plog_footer_txt);
  state->last_update_public_log = state->current_time;
  l10n_setlocale(0);
}

static void
do_update_xml_log(serve_state_t state, char const *name, int external_mode)
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
  unparse_runlog_xml(state, fout, &rhead, rtotal, rentries,
                     external_mode, state->current_time);
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
serve_update_external_xml_log(serve_state_t state)
{
  if (!state->global->external_xml_update_time) return;
  if (state->current_time < state->last_update_external_xml_log + state->global->external_xml_update_time) return;
  state->last_update_external_xml_log = state->current_time;
  do_update_xml_log(state, "external.xml", 1);
}

void
serve_update_internal_xml_log(serve_state_t state)
{
  if (!state->global->internal_xml_update_time) return;
  if (state->current_time < state->last_update_internal_xml_log + state->global->internal_xml_update_time) return;
  state->last_update_internal_xml_log = state->current_time;
  do_update_xml_log(state, "internal.xml", 0);
}

int
serve_update_status_file(serve_state_t state, int force_flag)
{
  struct prot_serve_status_v2 status;
  time_t t1, t2, t3, t4;
  int p;

  if (!force_flag && state->current_time <= state->last_update_status_file) return 0;

  memset(&status, 0, sizeof(status));
  status.magic = PROT_SERVE_STATUS_MAGIC_V2;

  status.cur_time = state->current_time;
  run_get_times(state->runlog_state, &t1, &t2, &t3, &t4);
  status.start_time = t1;
  status.sched_time = t2;
  status.duration = t3;
  status.stop_time = t4;
  status.total_runs = run_get_total(state->runlog_state);
  status.total_clars = clar_get_total(state->clarlog_state);
  status.clars_disabled = state->global->disable_clars;
  status.team_clars_disabled = state->global->disable_team_clars;
  status.score_system = state->global->score_system_val;
  status.clients_suspended = state->clients_suspended;
  status.testing_suspended = state->testing_suspended;
  status.download_interval = state->global->team_download_time / 60;
  status.is_virtual = state->global->virtual;
  status.olympiad_judging_mode = state->olympiad_judging_mode;
  status.continuation_enabled = state->global->enable_continue;
  status.printing_enabled = state->global->enable_printing;
  status.printing_suspended = state->printing_suspended;
  status.always_show_problems = state->global->always_show_problems;
  if (status.start_time && status.duration && state->global->board_fog_time > 0
      && !status.is_virtual) {
    status.freeze_time = status.start_time + status.duration - state->global->board_fog_time;
    if (status.freeze_time < status.start_time) {
      status.freeze_time = status.start_time;
    }
  }
  if (!status.duration && state->global->contest_finish_time_d)
    status.finish_time = state->global->contest_finish_time_d;
  //if (status.duration) status.continuation_enabled = 0;

  if (!state->global->virtual) {
    p = run_get_fog_period(state->runlog_state, state->current_time,
                           state->global->board_fog_time, state->global->board_unfog_time);
    if (p == 1 && state->global->autoupdate_standings) {
      status.standings_frozen = 1;
    }
  }

  status.stat_reported_before = state->stat_reported_before;
  status.stat_report_time = state->stat_report_time;

  generic_write_file((char*) &status, sizeof(status), SAFE,
                     state->global->status_dir, "status", "");
  state->last_update_status_file = state->current_time;
  return 1;
}

void
serve_load_status_file(serve_state_t state)
{
  struct prot_serve_status_v2 status;
  size_t stat_len = 0;
  char *ptr = 0;

  if (generic_read_file(&ptr, 0, &stat_len, 0, state->global->status_dir,
                        "dir/status", "") < 0) return;
  if (stat_len != sizeof(status)) {
    info("load_status_file: length %zu does not match %zu",
         stat_len, sizeof(status));
    xfree(ptr);
    return;
  }
  memcpy(&status, ptr, sizeof(status));
  xfree(ptr);
  if (status.magic != PROT_SERVE_STATUS_MAGIC_V2) {
    info("load_status_file: bad magic value");
    return;
  }

  state->clients_suspended = status.clients_suspended;
  info("load_status_file: clients_suspended = %d", state->clients_suspended);
  state->testing_suspended = status.testing_suspended;
  info("load_status_file: testing_suspended = %d", state->testing_suspended);
  state->olympiad_judging_mode = status.olympiad_judging_mode;
  info("load_status_file: state->olympiad_judging_mode = %d", state->olympiad_judging_mode);
  state->printing_suspended = status.printing_suspended;
  info("load_status_file: printing_suspended = %d", state->printing_suspended);
  state->stat_reported_before = status.stat_reported_before;
  state->stat_report_time = status.stat_report_time;
}

int
serve_check_user_quota(serve_state_t state, int user_id, size_t size)
{
  int num;
  size_t total;

  if (size > state->global->max_run_size) return -1;
  run_get_team_usage(state->runlog_state, user_id, &num, &total);
  if (num > state->global->max_run_num
      || total + size > state->global->max_run_total)
    return -1;
  return 0;
}

int
serve_check_clar_qouta(serve_state_t state, int user_id, size_t size)
{
  int num;
  size_t total;

  if (size > state->global->max_clar_size) return -1;
  clar_get_team_usage(state->clarlog_state, user_id, &num, &total);
  if (num > state->global->max_clar_num
      || total + size > state->global->max_clar_total)
    return -1;
  return 0;
}

int
serve_check_cnts_caps(serve_state_t state, int user_id, int bit)
{
  const struct contest_desc *cnts = 0;
  opcap_t caps;
  int errcode = 0;
  unsigned char const *login = 0;

  if ((errcode = contests_get(state->global->contest_id, &cnts)) < 0) {
    err("contests_get(%d): %s", state->global->contest_id,
        contests_strerror(-errcode));
    return 0;
  }
  login = teamdb_get_login(state->teamdb_state, user_id);
  if (!login || !*login) return 0;

  if (opcaps_find(&cnts->capabilities, login, &caps) < 0) return 0;
  if (opcaps_check(caps, bit) < 0) return 0;
  return 1;
}

int
serve_get_cnts_caps(serve_state_t state, int user_id, opcap_t *out_caps)
{
  const struct contest_desc *cnts = 0;
  opcap_t caps;
  int errcode = 0;
  unsigned char const *login = 0;

  if ((errcode = contests_get(state->global->contest_id, &cnts)) < 0) {
    err("contests_get(%d): %s", state->global->contest_id,
        contests_strerror(-errcode));
    return -1;
  }
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
serve_build_run_dirs(serve_state_t state)
{
  int i;

  for (i = 1; i <= state->max_tester; i++) {
    if (!state->testers[i]) continue;
    do_build_run_dirs(state, state->testers[i]->run_status_dir,
                      state->testers[i]->run_report_dir,
                      state->testers[i]->run_team_report_dir,
                      state->testers[i]->run_full_archive_dir);
  }
}

int
serve_create_symlinks(serve_state_t state)
{
  unsigned char src_path[PATH_MAX];
  unsigned char dst_path[PATH_MAX];
  path_t stand_file;
  int npages, pgn;

  if (state->global->stand_symlink_dir[0] && state->global->htdocs_dir[0]) {
    if (state->global->users_on_page > 0) {
      // FIXME: check, that standings_file_name depends on page number
      npages = (teamdb_get_total_teams(state->teamdb_state)
                + state->global->users_on_page - 1)
        / state->global->users_on_page;
      for (pgn = 0; pgn < npages; pgn++) {
        if (!pgn) {
          snprintf(stand_file, sizeof(stand_file),
                   state->global->standings_file_name, pgn + 1);
        } else {
          snprintf(stand_file, sizeof(stand_file),
                   state->global->stand_file_name_2, pgn + 1);
        }
        snprintf(src_path, sizeof(src_path), "%s/dir/%s",
                 state->global->status_dir, stand_file);
        snprintf(dst_path, sizeof(dst_path), "%s/%s/%s",
                 state->global->htdocs_dir, state->global->stand_symlink_dir,
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
               state->global->status_dir, state->global->standings_file_name);
      snprintf(dst_path, sizeof(dst_path), "%s/%s/%s",
               state->global->htdocs_dir, state->global->stand_symlink_dir,
               state->global->standings_file_name);
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
  if (state->global->stand2_symlink_dir[0] && state->global->htdocs_dir[0]
      && state->global->stand2_file_name[0]) {
    snprintf(src_path, sizeof(src_path), "%s/dir/%s",
             state->global->status_dir, state->global->stand2_file_name);
    snprintf(dst_path, sizeof(dst_path), "%s/%s/%s",
             state->global->htdocs_dir, state->global->stand2_symlink_dir,
             state->global->stand2_file_name);
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
  if (state->global->plog_symlink_dir[0] && state->global->htdocs_dir[0]
      && state->global->plog_file_name[0]
      && state->global->plog_update_time > 0) {
    snprintf(src_path, sizeof(src_path), "%s/dir/%s",
             state->global->status_dir, state->global->plog_file_name);
    snprintf(dst_path, sizeof(dst_path), "%s/%s/%s",
             state->global->htdocs_dir, state->global->plog_symlink_dir,
             state->global->plog_file_name);
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
serve_get_email_sender(const struct contest_desc *cnts)
{
  int sysuid;
  struct passwd *ppwd;

  if (cnts && cnts->register_email) return cnts->register_email;
  sysuid = getuid();
  ppwd = getpwuid(sysuid);
  return ppwd->pw_name;
}

static void
generate_statistics_email(serve_state_t state, time_t from_time, time_t to_time)
{
  unsigned char esubj[1024];
  struct tm *ptm;
  char *etxt = 0, *ftxt = 0;
  size_t elen = 0, flen = 0;
  FILE *eout = 0, *fout = 0;
  const struct contest_desc *cnts = 0;
  const unsigned char *mail_args[7];
  const unsigned char *originator;
  struct tm tm1;

  if (contests_get(state->global->contest_id, &cnts) < 0 || !cnts) return;

  ptm = localtime(&from_time);
  snprintf(esubj, sizeof(esubj),
           "Daily statistics for %04d/%02d/%02d, contest %d",
           ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
           state->global->contest_id);

  eout = open_memstream(&etxt, &elen);
  generate_daily_statistics(state, eout, from_time, to_time);
  fclose(eout); eout = 0;
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
  fclose(fout); fout = 0;

  originator = serve_get_email_sender(cnts);
  mail_args[0] = "mail";
  mail_args[1] = "";
  mail_args[2] = esubj;
  mail_args[3] = originator;
  mail_args[4] = cnts->daily_stat_email;
  mail_args[5] = ftxt;
  mail_args[6] = 0;
  send_job_packet(NULL, (unsigned char **) mail_args);
  xfree(ftxt); ftxt = 0;
  xfree(etxt); etxt = 0;
}

void
serve_check_stat_generation(serve_state_t state, int force_flag)
{
  const struct contest_desc *cnts = 0;
  struct tm *ptm;
  time_t thisday, nextday;

  if (!force_flag && state->stat_last_check_time > 0
      && state->stat_last_check_time + 600 > state->current_time)
    return;
  state->stat_last_check_time = state->current_time;
  if (contests_get(state->global->contest_id, &cnts) < 0 || !cnts) return;
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
    generate_statistics_email(state, thisday, nextday);
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

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
