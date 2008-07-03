/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2008 Alexander Chernov <cher@ejudge.ru> */

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
#include "ej_types.h"
#include "ej_limits.h"

#include "new-server.h"
#include "new_server_proto.h"
#include "contests.h"
#include "userlist.h"
#include "userlist_proto.h"
#include "userlist_clnt.h"
#include "runlog.h"
#include "html.h"
#include "prepare.h"
#include "archive_paths.h"
#include "fileutl.h"
#include "teamdb.h"
#include "misctext.h"
#include "clarlog.h"
#include "mime_type.h"
#include "sha.h"
#include "filter_tree.h"
#include "filter_eval.h"
#include "xml_utils.h"
#include "charsets.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

static int
parse_int(const char *str, int *p_val)
{
  int v;
  char *eptr = 0;

  errno = 0;
  v = strtol(str, &eptr, 10);
  if (errno || *eptr) return -1;
  *p_val = v;
  return 0;
}

static int
cmd_login(
        FILE *fout,
        struct http_request_info *phr)
{
  int retval = 0, r;
  const struct contest_desc *cnts = 0;
  const unsigned char *login = 0, *password = 0, *role_str = 0;
  opcap_t caps;

  // login, password, role, contest_id
  if (ns_cgi_param(phr, "login", &login) <= 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (ns_cgi_param(phr, "password", &password) <= 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (phr->contest_id <= 0 || contests_get(phr->contest_id, &cnts) || !cnts)
    FAIL(NEW_SRV_ERR_INV_CONTEST_ID);
  if (!cnts->new_managed)
    FAIL(NEW_SRV_ERR_INV_CONTEST_ID);
  if (ns_cgi_param(phr, "role", &role_str) <= 0)
    FAIL(NEW_SRV_ERR_INV_ROLE);
  if (parse_int(role_str, &phr->role) < 0
      || phr->role < 0 || phr->role >= USER_ROLE_LAST)
    FAIL(NEW_SRV_ERR_INV_ROLE);
  phr->login = xstrdup(login);

  switch (phr->role) {
  case USER_ROLE_CONTESTANT:
    if (cnts->closed || cnts->client_disable_team) 
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    if (!contests_check_team_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    break;
  case USER_ROLE_OBSERVER:
  case USER_ROLE_EXAMINER:
  case USER_ROLE_CHIEF_EXAMINER:
  case USER_ROLE_COORDINATOR:
  case USER_ROLE_JUDGE:
    if (!contests_check_judge_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    break;
  case USER_ROLE_ADMIN:
    if (!contests_check_master_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    break;
  default:
    abort();
  }

  if (ns_open_ul_connection(phr->fw_state) < 0)
    FAIL(NEW_SRV_ERR_USERLIST_SERVER_DOWN);

  if (phr->role == USER_ROLE_CONTESTANT) {
    r = userlist_clnt_login(ul_conn, ULS_TEAM_CHECK_USER,
                            phr->ip, phr->ssl_flag, phr->contest_id,
                            phr->locale_id, login, password,
                            &phr->user_id, &phr->session_id,
                            &phr->name);
  } else {
    r = userlist_clnt_priv_login(ul_conn, ULS_PRIV_CHECK_USER,
                                 phr->ip, phr->ssl_flag, phr->contest_id,
                                 phr->locale_id, phr->role, login,
                                 password, &phr->user_id, &phr->session_id,
                                 0, &phr->name);
  }

  if (r < 0) {
    switch (-r) {
    case ULS_ERR_INVALID_LOGIN:
    case ULS_ERR_INVALID_PASSWORD:
    case ULS_ERR_BAD_CONTEST_ID:
    case ULS_ERR_IP_NOT_ALLOWED:
    case ULS_ERR_NO_PERMS:
    case ULS_ERR_NOT_REGISTERED:
    case ULS_ERR_CANNOT_PARTICIPATE:
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    case ULS_ERR_DISCONNECT:
      FAIL(NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    default:
      FAIL(NEW_SRV_ERR_INTERNAL);
    }
  }

  // analyze permissions
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
        || opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  } else if (phr->role == USER_ROLE_JUDGE) {
    // as for the judge program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
        || opcaps_check(caps, OPCAP_JUDGE_LOGIN) < 0)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  } else if (phr->role != USER_ROLE_CONTESTANT) {
    // user privileges checked locally
    if (nsdb_check_role(phr->user_id, phr->contest_id, phr->role) < 0)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }

  ns_get_session(phr->session_id, 0);
  fprintf(fout, "%016llx\n", phr->session_id);

 cleanup:
  return retval;
}

static int
cmd_logout(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  if (ns_open_ul_connection(phr->fw_state) < 0)
    return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
  userlist_clnt_delete_cookie(ul_conn, phr->user_id, phr->contest_id,
                              phr->session_id);
  ns_remove_session(phr->session_id);
  return 0;
}

static int
cmd_dump_runs(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;

  if (phr->role < USER_ROLE_JUDGE
      || opcaps_check(phr->caps, OPCAP_DUMP_RUNS) < 0)
    return -NEW_SRV_ERR_PERMISSION_DENIED;

  switch (phr->action) {
  case NEW_SRV_ACTION_EXPORT_XML_RUNS:
    if (run_write_xml(cs->runlog_state, cs, cnts, fout, 1, 0,
                      cs->current_time) < 0)
      return -NEW_SRV_ERR_TRY_AGAIN;
    break;

  case NEW_SRV_ACTION_WRITE_XML_RUNS:
    if (run_write_xml(cs->runlog_state, cs, cnts, fout, 0, 0,
                      cs->current_time) < 0)
      return -NEW_SRV_ERR_TRY_AGAIN;
    break;

  case NEW_SRV_ACTION_WRITE_XML_RUNS_WITH_SRC:
    if (run_write_xml(cs->runlog_state, cs, cnts, fout, 0, 1,
                      cs->current_time) < 0)
      return -NEW_SRV_ERR_TRY_AGAIN;
    break;

  case NEW_SRV_ACTION_VIEW_RUNS_DUMP:
    write_runs_dump(cs, fout, 0, 0);
    break;
  default:
    abort();
  }

  return 0;
}
           
static int
cmd_dump_problems(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  int i;
  const struct section_problem_data *prob;

  for (i = 0; i <= cs->max_prob; i++) {
    if (!(prob = cs->probs[i])) continue;
    fprintf(fout, "%d;%s;%s\n", prob->id, prob->short_name, prob->long_name);
  }
  return 0;
}

static int
do_schedule(
        struct http_request_info *phr,
        serve_state_t cs,
        const struct contest_desc *cnts)
{
  const unsigned char *s = 0;
  int hour = 0, min = 0, sec = 0, year = 0, mon = 0, day = 0, n;
  struct tm loc2;
  struct tm *ploc;
  time_t sloc, start_time, stop_time;

  if (ns_cgi_param(phr, "sched_time", &s) <= 0)
    return -NEW_SRV_ERR_INV_TIME_SPEC;
  if (sscanf(s, "%d/%d/%d %d:%d:%d%n",
             &year, &mon, &day, &hour, &min, &sec, &n) == 6 && !s[n]) {
    memset(&loc2, 0, sizeof(loc2));
    loc2.tm_isdst = -1;
    loc2.tm_year = year - 1900;
    loc2.tm_mon = mon - 1;
    loc2.tm_mday = day;
    loc2.tm_hour = hour;
    loc2.tm_min = min;
    loc2.tm_sec = sec;
    ploc = &loc2;
  } else if (sscanf(s, "%d:%d%n", &hour, &min, &n) == 2 && !s[n]) {
    ploc = localtime(&cs->current_time);
    ploc->tm_hour = hour;
    ploc->tm_min = min;
    ploc->tm_sec = 0;
  } else if (sscanf(s, "%d%n", &hour, &n) == 1 && !s[n]) {
    ploc = localtime(&cs->current_time);
    ploc->tm_hour = hour;
    ploc->tm_min = 0;
    ploc->tm_sec = 0;
  } else {
    return -NEW_SRV_ERR_INV_TIME_SPEC;
  }

  if ((sloc = mktime(ploc)) == (time_t) -1) {
    return -NEW_SRV_ERR_INV_TIME_SPEC;
  }

  run_get_times(cs->runlog_state, &start_time, 0, 0, &stop_time, 0);

  if (stop_time > 0) return -NEW_SRV_ERR_CONTEST_ALREADY_FINISHED;
  if (start_time > 0) return -NEW_SRV_ERR_CONTEST_ALREADY_STARTED;
  run_sched_contest(cs->runlog_state, sloc);
  serve_update_standings_file(cs, cnts, 0);
  serve_update_status_file(cs, 1);
  return 0;
}

static int
cmd_operation(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  time_t start_time = 0, duration = 0, stop_time = 0;

  if (phr->role != USER_ROLE_ADMIN
      || opcaps_check(phr->caps, OPCAP_CONTROL_CONTEST))
    return -NEW_SRV_ERR_PERMISSION_DENIED;

  switch (phr->action) {
  case NEW_SRV_ACTION_SOFT_UPDATE_STANDINGS:
    serve_update_standings_file(cs, cnts, 0);
    break;

  case NEW_SRV_ACTION_TEST_SUSPEND:
    cs->testing_suspended = 1;
    serve_update_status_file(cs, 1);
    break;
  case NEW_SRV_ACTION_TEST_RESUME:
    cs->testing_suspended = 0;
    serve_update_status_file(cs, 1);
    break;
  case NEW_SRV_ACTION_REJUDGE_SUSPENDED_2:
    serve_judge_suspended(cnts, cs, phr->user_id, phr->ip, phr->ssl_flag);
    break;
  case NEW_SRV_ACTION_HAS_TRANSIENT_RUNS:
    if (serve_count_transient_runs(cs) > 0)
      return -NEW_SRV_ERR_TRANSIENT_RUNS;
    break;
  case NEW_SRV_ACTION_RELOAD_SERVER:
    extra->last_access_time = 0;
    serve_send_run_quit(cs);
    break;
  case NEW_SRV_ACTION_START_CONTEST:
    run_get_times(cs->runlog_state, &start_time, 0, &duration, &stop_time, 0);
    if (stop_time > 0) return -NEW_SRV_ERR_CONTEST_ALREADY_FINISHED;
    if (start_time > 0) return -NEW_SRV_ERR_CONTEST_ALREADY_STARTED;
    run_start_contest(cs->runlog_state, cs->current_time);
    serve_update_status_file(cs, 1);
    serve_invoke_start_script(cs);
    serve_update_standings_file(cs, cnts, 0);
    break;
  case NEW_SRV_ACTION_STOP_CONTEST:
    run_get_times(cs->runlog_state, &start_time, 0, &duration, &stop_time, 0);
    if (stop_time > 0) return -NEW_SRV_ERR_CONTEST_ALREADY_FINISHED;
    if (start_time <= 0) return -NEW_SRV_ERR_CONTEST_NOT_STARTED;
    run_stop_contest(cs->runlog_state, cs->current_time);
    serve_update_status_file(cs, 1);
    break;
  case NEW_SRV_ACTION_CONTINUE_CONTEST:
    run_get_times(cs->runlog_state, &start_time, 0, &duration, &stop_time, 0);
    if (!global->enable_continue) return -NEW_SRV_ERR_CANNOT_CONTINUE_CONTEST;
    if (start_time <= 0) return -NEW_SRV_ERR_CONTEST_NOT_STARTED;
    if (stop_time <= 0) return -NEW_SRV_ERR_CONTEST_NOT_FINISHED;
    if (duration > 0 && cs->current_time >= start_time + duration)
      return -NEW_SRV_ERR_INSUFFICIENT_DURATION;
    run_set_finish_time(cs->runlog_state, 0);
    run_stop_contest(cs->runlog_state, 0);
    serve_update_status_file(cs, 1);
    break;
  case NEW_SRV_ACTION_SUSPEND:
    cs->clients_suspended = 1;
    serve_update_status_file(cs, 1);
    break;
  case NEW_SRV_ACTION_RESUME:
    cs->clients_suspended = 0;
    serve_update_status_file(cs, 1);
    break;
  case NEW_SRV_ACTION_PRINT_SUSPEND:
    if (!global->enable_printing) break;
    cs->printing_suspended = 1;
    serve_update_status_file(cs, 1);
    break;
  case NEW_SRV_ACTION_PRINT_RESUME:
    if (!global->enable_printing) break;
    cs->printing_suspended = 1;
    serve_update_status_file(cs, 1);
    break;
  case NEW_SRV_ACTION_SET_JUDGING_MODE:
    if (global->score_system_val != SCORE_OLYMPIAD) break;
    cs->accepting_mode = 0;
    serve_update_status_file(cs, 1);
    break;
  case NEW_SRV_ACTION_SET_ACCEPTING_MODE:
    if (global->score_system_val != SCORE_OLYMPIAD) break;
    cs->accepting_mode = 1;
    serve_update_status_file(cs, 1);
    break;
  case NEW_SRV_ACTION_SET_TESTING_FINISHED_FLAG:
    if (global->score_system_val != SCORE_OLYMPIAD) break;
    if ((!global->is_virtual && cs->accepting_mode)
        ||(global->is_virtual && global->disable_virtual_auto_judge <= 0))
      break;
    cs->testing_finished = 1;
    serve_update_status_file(cs, 1);
    break;
  case NEW_SRV_ACTION_CLEAR_TESTING_FINISHED_FLAG:
    if (global->score_system_val != SCORE_OLYMPIAD) break;
    cs->testing_finished = 0;
    serve_update_status_file(cs, 1);
    break;
  case NEW_SRV_ACTION_REJUDGE_ALL_2:
    serve_rejudge_all(cnts, cs, phr->user_id, phr->ip, phr->ssl_flag);
    break;
  case NEW_SRV_ACTION_SCHEDULE:
    return do_schedule(phr, cs, cnts);

  default:
    abort();
  }

  return 0;
}

static int
cmd_operation_2(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0;
  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const unsigned char *s = 0;
  static const unsigned char * const contest_types[SCORE_TOTAL] =
  {
    [SCORE_ACM] = "acm",
    [SCORE_KIROV] = "kirov",
    [SCORE_OLYMPIAD] = "olympiad",
    [SCORE_MOSCOW] = "moscow",
  };
  static const unsigned char * const virtual_contest_types[SCORE_TOTAL] =
  {
    [SCORE_ACM] = "acm-virtual",
    [SCORE_KIROV] = 0,
    [SCORE_OLYMPIAD] = "olympiad-virtual",
    [SCORE_MOSCOW] = 0,
  };

  switch (phr->action) {
  case NEW_SRV_ACTION_GET_CONTEST_NAME:
    fprintf(fout, "%s", cnts->name);
    break;
  case NEW_SRV_ACTION_GET_CONTEST_TYPE:
    if (global->score_system_val < 0
        || global->score_system_val >= SCORE_TOTAL)
      FAIL(NEW_SRV_ERR_INV_CONTEST_ID);
    if (global->is_virtual) s = virtual_contest_types[global->score_system_val];
    else s = contest_types[global->score_system_val];
    if (!s) FAIL(NEW_SRV_ERR_INV_CONTEST_ID);
    fprintf(fout, "%s", s);
    break;
  default:
    abort();
  }

 cleanup:
  return retval;
}

static int
cmd_run_operation(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = 0;
  int run_id = -1, src_flags, retval = 0;
  const unsigned char *s = 0;
  struct run_entry re;
  path_t src_path;
  char *src_text = 0;
  size_t src_len = 0;

  if (ns_cgi_param(phr, "run_id", &s) <= 0)
    FAIL(NEW_SRV_ERR_INV_RUN_ID);
  if (parse_int(s, &run_id) < 0 || run_id < 0)
    FAIL(NEW_SRV_ERR_INV_RUN_ID);
  if (run_get_entry(cs->runlog_state, run_id, &re) < 0)
    FAIL(NEW_SRV_ERR_INV_RUN_ID);

  switch (phr->role) {
  case USER_ROLE_CONTESTANT:
    if (!run_is_valid_user_status(re.status))
      FAIL(NEW_SRV_ERR_INV_RUN_ID);
    if (phr->user_id != re.user_id)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    switch (phr->action) {
    case NEW_SRV_ACTION_DUMP_RUN_STATUS:
      break;
    case NEW_SRV_ACTION_DUMP_SOURCE:
      if (re.prob_id <= 0 || re.prob_id > cs->max_prob
          || !(prob = cs->probs[re.prob_id]))
        FAIL(NEW_SRV_ERR_INV_PROB_ID);
      if (global->team_enable_src_view <= 0)
        FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
      break;
    case NEW_SRV_ACTION_DUMP_REPORT:
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    }
    break;

    // not implemented yet
  case USER_ROLE_OBSERVER:
  case USER_ROLE_EXAMINER:
  case USER_ROLE_CHIEF_EXAMINER:
  case USER_ROLE_COORDINATOR:
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  case USER_ROLE_JUDGE:
  case USER_ROLE_ADMIN:
    if (!run_is_valid_status(re.status))
      FAIL(NEW_SRV_ERR_INV_RUN_ID);
    switch (phr->action) {
    case NEW_SRV_ACTION_DUMP_RUN_STATUS:
      break;
    case NEW_SRV_ACTION_DUMP_SOURCE:
      if (opcaps_check(phr->caps, OPCAP_VIEW_SOURCE) < 0)
        FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
      break;
    case NEW_SRV_ACTION_DUMP_REPORT:
      if (opcaps_check(phr->caps, OPCAP_VIEW_REPORT) < 0)
        FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
      break;
    }
    break;
  default:
    abort();
  }

  if (re.status > RUN_LAST)
    FAIL(NEW_SRV_ERR_INV_RUN_ID);
  if (re.status > RUN_PSEUDO_LAST && re.status < RUN_TRANSIENT_FIRST)
    FAIL(NEW_SRV_ERR_INV_RUN_ID);
  if (re.status > RUN_MAX_STATUS && re.status < RUN_PSEUDO_FIRST)
    FAIL(NEW_SRV_ERR_INV_RUN_ID);

  switch (phr->action) {
  case NEW_SRV_ACTION_DUMP_RUN_STATUS:
    retval = ns_write_user_run_status(cs, fout, run_id);
    break;
  case NEW_SRV_ACTION_DUMP_SOURCE:
    src_flags = archive_make_read_path(cs, src_path, sizeof(src_path),
                                       global->run_archive_dir, run_id,
                                       0, 1);
    if (src_flags < 0) FAIL(NEW_SRV_ERR_SOURCE_NONEXISTANT);
    if (generic_read_file(&src_text, 0, &src_len, src_flags,0,src_path, "") < 0)
      FAIL(NEW_SRV_ERR_DISK_READ_ERROR);
    if (fwrite(src_text, 1, src_len, fout) != src_len)
      FAIL(NEW_SRV_ERR_WRITE_ERROR);
    break;
  case NEW_SRV_ACTION_DUMP_REPORT:
    if (!run_is_report_available(re.status))
      FAIL(NEW_SRV_ERR_REPORT_UNAVAILABLE);
    src_flags = archive_make_read_path(cs, src_path, sizeof(src_path),
                                       global->xml_report_archive_dir,
                                       run_id, 0, 1);
    if (src_flags < 0) {
      src_flags = archive_make_read_path(cs, src_path, sizeof(src_path),
                                         global->report_archive_dir,
                                         run_id, 0, 1);
    }
    if (src_flags < 0)
      FAIL(NEW_SRV_ERR_REPORT_NONEXISTANT);
    if (generic_read_file(&src_text, 0, &src_len, src_flags,0,src_path, "") < 0)
      FAIL(NEW_SRV_ERR_DISK_READ_ERROR);
    if (fwrite(src_text, 1, src_len, fout) != src_len)
      FAIL(NEW_SRV_ERR_WRITE_ERROR);
    break;
  default:
    abort();
  }

 cleanup:
  xfree(src_text);
  return retval;
}

static int
cmd_clar_operation(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  int retval = 0;
  const unsigned char *s = 0;
  int clar_id = -1;
  struct clar_entry_v1 ce;
  path_t msg_path;
  char *msg_txt = 0;
  const unsigned char *recoded_txt = 0;
  size_t msg_len = 0, recoded_len = 0;
  int charset_id;
  struct html_armor_buffer rb = HTML_ARMOR_INITIALIZER;

  if (ns_cgi_param(phr, "clar_id", &s) <= 0)
    FAIL(NEW_SRV_ERR_INV_CLAR_ID);
  if (parse_int(s, &clar_id) < 0 || clar_id < 0)
    FAIL(NEW_SRV_ERR_INV_CLAR_ID);
  if (clar_get_record_new(cs->clarlog_state, clar_id, &ce) < 0)
    FAIL(NEW_SRV_ERR_INV_CLAR_ID);

  /* permission check */
  switch (phr->role) {
  case USER_ROLE_CONTESTANT:
    if (global->disable_clars)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    if (ce.from != phr->user_id && ce.to != phr->user_id
        && (ce.from > 0 || ce.to > 0))
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    break;

  case USER_ROLE_OBSERVER:
  case USER_ROLE_EXAMINER:
  case USER_ROLE_CHIEF_EXAMINER:
  case USER_ROLE_COORDINATOR:
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  case USER_ROLE_JUDGE:
  case USER_ROLE_ADMIN:
    switch (phr->action) {
    case NEW_SRV_ACTION_DUMP_CLAR:
      if (opcaps_check(phr->caps, OPCAP_VIEW_CLAR) < 0)
        FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
      break;
    default:
      abort();
    }
    break;
  default:
    abort();
  }

  switch (phr->action) {
  case NEW_SRV_ACTION_DUMP_CLAR:
    snprintf(msg_path, sizeof(msg_path), "%06d", clar_id);
    if (generic_read_file(&msg_txt, 0, &msg_len, 0,
                          global->clar_archive_dir, msg_path, "") < 0)
      FAIL(NEW_SRV_ERR_DISK_READ_ERROR);
    charset_id = clar_get_charset_id(cs->clarlog_state, clar_id);
    recoded_txt = charset_recode(charset_id, &rb, msg_txt);
    recoded_len = strlen(recoded_txt);
    if (fwrite(recoded_txt, 1, recoded_len, fout) != msg_len)
      FAIL(NEW_SRV_ERR_WRITE_ERROR);
    break;
  }

 cleanup:
  html_armor_free(&rb);
  xfree(msg_txt);
  return retval;
}

static int
cmd_submit_run(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = 0;
  const struct section_language_data *lang = 0;
  int variant = -1;
  int retval = 0;
  int lang_id = 0;
  int i, r, n, j;
  const unsigned char *s = 0;
  const unsigned char *run_text = 0;
  size_t run_size = 0;
  char *run_text_2 = 0;
  size_t run_size_2 = 0;
  FILE *ans_f = 0;
  unsigned char ans_map[65536];
  time_t start_time = 0, stop_time = 0, user_deadline = 0;
  const unsigned char *login = 0;
  char **lang_list;
  int mime_type = 0;
  const unsigned char *mime_type_str = 0;
  ruint32_t shaval[5];
  unsigned char *acc_probs = 0;
  int run_id = 0;
  struct timeval precise_time;
  int arch_flags = 0, hidden_flag = 0;
  path_t run_path;

  // initial permission check
  switch (phr->role) {
  case USER_ROLE_CONTESTANT:
    break;
    
  case USER_ROLE_OBSERVER:
  case USER_ROLE_EXAMINER:
  case USER_ROLE_CHIEF_EXAMINER:
  case USER_ROLE_COORDINATOR:
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  case USER_ROLE_JUDGE:
  case USER_ROLE_ADMIN:
    hidden_flag = 1;
    if (opcaps_check(phr->caps, OPCAP_SUBMIT_RUN) < 0)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    break;
  default:
      abort();
  }

  if (ns_cgi_param(phr, "prob", &s) <= 0)
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  for (i = 1; i <= cs->max_prob; i++)
    if (cs->probs[i] && !strcmp(s, cs->probs[i]->short_name))
      break;
  if (i > cs->max_prob)
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  prob = cs->probs[i];

  /* check variant */
  switch (phr->role) {
  case USER_ROLE_CONTESTANT:
    if (ns_cgi_param(phr, "variant", &s) != 0)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    if (prob->variant_num > 0) {
      if ((variant = find_variant(cs, phr->user_id, prob->id, 0)) <= 0)
        FAIL(NEW_SRV_ERR_VARIANT_UNASSIGNED);
    }
    variant = 0;
    break;
    
  case USER_ROLE_JUDGE:
  case USER_ROLE_ADMIN:
    if (prob->variant_num <= 0) {
      if (ns_cgi_param(phr, "variant", &s) != 0)
        FAIL(NEW_SRV_ERR_INV_VARIANT);
      variant = 0;
    } else {
      if ((r = ns_cgi_param(phr, "variant", &s)) < 0)
        FAIL(NEW_SRV_ERR_INV_VARIANT);
      if (!r) {
        if ((variant = find_variant(cs, phr->user_id, prob->id, 0)) <= 0)
          FAIL(NEW_SRV_ERR_VARIANT_UNASSIGNED);
      } else {
        if (parse_int(s, &variant) < 0 || variant < 0
            || variant > prob->variant_num)
          FAIL(NEW_SRV_ERR_INV_VARIANT);
        if (!variant && (variant=find_variant(cs, phr->user_id, prob->id, 0)) <= 0)
          FAIL(NEW_SRV_ERR_VARIANT_UNASSIGNED);
      }
    }
    break;
  default:
      abort();
  }

  /* parse language */
  if (prob->type_val == PROB_TYPE_STANDARD) {
    if (ns_cgi_param(phr, "lang", &s) <= 0)
      FAIL(NEW_SRV_ERR_INV_LANG_ID);
    for (i = 1; i <= cs->max_lang; i++)
      if (cs->langs[i] && !strcmp(s, cs->langs[i]->short_name))
        break;
    if (i > cs->max_lang)
      FAIL(NEW_SRV_ERR_INV_LANG_ID);
    lang_id = i;
    lang = cs->langs[i];
  }

  /* get the source */
  if (!ns_cgi_param_bin(phr, "file", &run_text, &run_size))
    FAIL(NEW_SRV_ERR_SOURCE_NONEXISTANT);
  if (!run_size)
    FAIL(NEW_SRV_ERR_SUBMIT_EMPTY);
  // check for binaryness
  switch (prob->type_val) {
  case PROB_TYPE_STANDARD:
    if (!lang->binary && strlen(run_text) != run_size) 
      FAIL(NEW_SRV_ERR_BINARY_FILE);
    break;
  case PROB_TYPE_OUTPUT_ONLY:
    if (!prob->binary_input && strlen(run_text) != run_size) 
      FAIL(NEW_SRV_ERR_BINARY_FILE);
    break;
  case PROB_TYPE_TEXT_ANSWER:
  case PROB_TYPE_SHORT_ANSWER:
  case PROB_TYPE_SELECT_ONE:
  case PROB_TYPE_SELECT_MANY:
    if (strlen(run_text) != run_size) 
      FAIL(NEW_SRV_ERR_BINARY_FILE);
    break;
  case PROB_TYPE_CUSTOM:
    break;
  }

  /* process special kind of answers */
  switch (prob->type_val) {
  case PROB_TYPE_SELECT_ONE:
    run_text_2 = xstrdup(run_text);
    while (run_size > 0 && isspace(run_text_2[run_size - 1])) run_size--;
    run_text_2[run_size] = 0;
    if (parse_int(run_text, &i) < 0 || i < 0 || i > 65535)
      FAIL(NEW_SRV_ERR_INV_ANSWER);
    xfree(run_text_2); run_text_2 = 0;
    ans_f = open_memstream(&run_text_2, &run_size_2);
    fprintf(ans_f, "%d\n", i);
    fclose(ans_f); ans_f = 0;
    run_text = run_text_2;
    run_size = run_size_2;
    break;
  case PROB_TYPE_SELECT_MANY:
    run_text_2 = xstrdup(run_text);
    while (run_size > 0 && isspace(run_text_2[run_size - 1])) run_size--;
    run_text_2[run_size] = 0;
    memset(ans_map, 0, sizeof(ans_map));
    s = run_text_2;
    while (*s) {
      if (sscanf(s, "%d%n", &i, &n) != 1 || i < 0 || i > 65535)
        FAIL(NEW_SRV_ERR_INV_ANSWER);
      ans_map[i] = 1;
      s += n;
    }
    xfree(run_text_2); run_text_2 = 0;
    ans_f = open_memstream(&run_text_2, &run_size_2);
    for (i = 0, n = 0; i < 65536; i++)
      if (ans_map[i]) {
        if (n > 0) putc_unlocked(' ', ans_f);
        fprintf(ans_f, "%d", i);
        n++;
      }
    if (n > 0) putc_unlocked('\n', ans_f);
    fclose(ans_f); ans_f = 0;
    run_text = run_text_2;
    run_size = run_size_2;
    break;
  }

  if (phr->role == USER_ROLE_CONTESTANT) {
    if (global->is_virtual) {
      start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
      stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                            cs->current_time);
    } else {
      start_time = run_get_start_time(cs->runlog_state);
      stop_time = run_get_stop_time(cs->runlog_state);
    }
    if (cs->clients_suspended)
      FAIL(NEW_SRV_ERR_CLIENTS_SUSPENDED);
    if (!start_time)
      FAIL(NEW_SRV_ERR_CONTEST_NOT_STARTED);
    if (stop_time)
      FAIL(NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
    if (serve_check_user_quota(cs, phr->user_id, run_size) < 0)
      FAIL(NEW_SRV_ERR_RUN_QUOTA_EXCEEDED);
    if (prob->t_start_date >= 0 && cs->current_time < prob->t_start_date)
      FAIL(NEW_SRV_ERR_PROB_UNAVAILABLE);
    if (prob->pd_total > 0) {
      login = teamdb_get_login(cs->teamdb_state, phr->user_id);
      for (i = 0; i < prob->pd_total; i++) {
        if (!strcmp(login, prob->pd_infos[i].login)) {
          user_deadline = prob->pd_infos[i].deadline;
          break;
        }
      }
    }
    // common problem deadline
    if (user_deadline <= 0) user_deadline = prob->t_deadline;
    if (user_deadline > 0 && cs->current_time >= user_deadline)
      FAIL(NEW_SRV_ERR_PROB_DEADLINE_EXPIRED);
  }

  /* check for disabled languages */
  if (lang_id > 0) {
    if (lang->disabled)
      FAIL(NEW_SRV_ERR_LANG_DISABLED);

    if (prob->enable_language) {
      lang_list = prob->enable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], lang->short_name))
          break;
      if (!lang_list[i])
        FAIL(NEW_SRV_ERR_LANG_NOT_AVAIL_FOR_PROBLEM);
    } else if (prob->disable_language) {
      lang_list = prob->disable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], lang->short_name))
          break;
      if (lang_list[i])
        FAIL(NEW_SRV_ERR_LANG_DISABLED_FOR_PROBLEM);
    }
  } else {
    // guess the content-type and check it against the list
    if ((mime_type = mime_type_guess(cs->global->diff_work_dir,
                                     run_text, run_size)) < 0)
      FAIL(NEW_SRV_ERR_CANNOT_DETECT_CONTENT_TYPE);
    mime_type_str = mime_type_get_type(mime_type);
    if (prob->enable_language) {
      lang_list = prob->enable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], mime_type_str))
          break;
      if (!lang_list[i])
        FAIL(NEW_SRV_ERR_CONTENT_TYPE_NOT_AVAILABLE);
    } else if (prob->disable_language) {
      lang_list = prob->disable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], mime_type_str))
          break;
      if (lang_list[i])
        FAIL(NEW_SRV_ERR_CONTENT_TYPE_DISABLED);
    }
  }

  sha_buffer(run_text, run_size, shaval);

  if (phr->role == USER_ROLE_CONTESTANT) {
    if ((run_id = run_find_duplicate(cs->runlog_state, phr->user_id, prob->id,
                                     lang_id, variant, run_size,
                                     shaval)) >= 0)
      FAIL(NEW_SRV_ERR_DUPLICATE_SUBMIT);

    if (prob->disable_submit_after_ok
        && global->score_system_val != SCORE_OLYMPIAD && !cs->accepting_mode) {
      XALLOCAZ(acc_probs, cs->max_prob + 1);
      run_get_accepted_set(cs->runlog_state, phr->user_id,
                           cs->accepting_mode, cs->max_prob, acc_probs);
      if (acc_probs[prob->id])
        FAIL(NEW_SRV_ERR_PROB_ALREADY_SOLVED);
    }

    if (prob->require) {
      if (!acc_probs) {
        XALLOCAZ(acc_probs, cs->max_prob + 1);
        run_get_accepted_set(cs->runlog_state, phr->user_id,
                             cs->accepting_mode, cs->max_prob, acc_probs);
      }
      for (i = 0; prob->require[i]; i++) {
        for (j = 1; j <= cs->max_prob; j++)
          if (cs->probs[j] && !strcmp(cs->probs[j]->short_name,
                                      prob->require[i]))
            break;
        if (j > cs->max_prob || !acc_probs[j]) break;
      }
      if (prob->require[i])
        FAIL(NEW_SRV_ERR_NOT_ALL_REQ_SOLVED);
    }
  }

  gettimeofday(&precise_time, 0);

  run_id = run_add_record(cs->runlog_state, 
                          precise_time.tv_sec, precise_time.tv_usec * 1000,
                          run_size, shaval,
                          phr->ip, phr->ssl_flag,
                          phr->locale_id, phr->user_id,
                          prob->id, lang_id, variant, hidden_flag, mime_type);
  if (run_id < 0)
    FAIL(NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
  serve_move_files_to_insert_run(cs, run_id);
                          
  arch_flags = archive_make_write_path(cs, run_path, sizeof(run_path),
                                       global->run_archive_dir, run_id,
                                       run_size, 0);
  if (arch_flags < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    FAIL(NEW_SRV_ERR_DISK_WRITE_ERROR);
  }
  if (archive_dir_prepare(cs, global->run_archive_dir, run_id, 0, 0) < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    FAIL(NEW_SRV_ERR_DISK_WRITE_ERROR);
  }
  if (generic_write_file(run_text, run_size, arch_flags, 0, run_path, "") < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    FAIL(NEW_SRV_ERR_DISK_WRITE_ERROR);
  }

  if (prob->type_val == PROB_TYPE_STANDARD) {
    if (prob->disable_auto_testing > 0
        || (prob->disable_testing > 0 && prob->enable_compilation <= 0)
        || lang->disable_auto_testing || lang->disable_testing) {
      run_change_status(cs->runlog_state, run_id, RUN_PENDING, 0, -1, 0);
      serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                      "Command: submit\n"
                      "Status: pending\n"
                      "Run-id: %d\n"
                      "  Testing disabled for this problem or language\n",
                      run_id);
    } else {
      if (serve_compile_request(cs, run_text, run_size, run_id,
                                lang->compile_id, phr->locale_id, 0,
                                lang->src_sfx,
                                lang->compiler_env, -1, 0, prob, lang) < 0)
        FAIL(NEW_SRV_ERR_DISK_WRITE_ERROR);
      serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                      "Command: submit\n"
                      "Status: ok\n"
                      "Run-id: %d\n", run_id);
    }
  } else if (prob->manual_checking > 0) {
    // manually tested outputs
    if (prob->check_presentation <= 0) {
      run_change_status(cs->runlog_state, run_id, RUN_ACCEPTED, 0, -1, 0);
      serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                      "Command: submit\n"
                      "Status: accepted for testing\n"
                      "Run-id: %d\n"
                      "  This problem is checked manually.\n",
                      run_id);
    } else {
      if (serve_run_request(cs, stderr, run_text, run_size, run_id,
                            phr->user_id, prob->id, 0, variant, 0, -1, -1,
                            0, 0) < 0)
        FAIL(NEW_SRV_ERR_DISK_WRITE_ERROR);

      serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                      "Command: submit\n"
                      "Status: ok\n"
                      "Run-id: %d\n", run_id);
    }
  } else {
    if (prob->disable_auto_testing > 0
        || (prob->disable_testing > 0 && prob->enable_compilation <= 0)) {
      run_change_status(cs->runlog_state, run_id, RUN_PENDING, 0, -1, 0);
      serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                      "Command: submit\n"
                      "Status: pending\n"
                      "Run-id: %d\n"
                      "  Testing disabled for this problem\n",
                      run_id);
    } else {
      if (serve_run_request(cs, stderr, run_text, run_size, run_id,
                            phr->user_id, prob->id, 0, variant, 0, -1, -1,
                            0, 0) < 0)
        FAIL(NEW_SRV_ERR_DISK_WRITE_ERROR);

      serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                      "Command: submit\n"
                      "Status: ok\n"
                      "Run-id: %d\n", run_id);
    }
  }
  fprintf(fout, "%d\n", run_id);

 cleanup:
  if (ans_f) fclose(ans_f);
  xfree(run_text_2);
  return retval;
}

static int
cmd_import_xml_runs(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0, r;
  const serve_state_t cs = extra->serve_state;
  const unsigned char *s = 0, *p;

  if (phr->role != USER_ROLE_ADMIN
      || opcaps_check(phr->caps, OPCAP_IMPORT_XML_RUNS) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (phr->action == NEW_SRV_ACTION_FULL_UPLOAD_RUNLOG_XML
      && opcaps_check(phr->caps, OPCAP_CONTROL_CONTEST) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (cs->global->enable_runlog_merge <= 0)
    FAIL(NEW_SRV_ERR_NOT_SUPPORTED);

  if (!(r = ns_cgi_param(phr, "file", &s)))
    FAIL(NEW_SRV_ERR_FILE_UNSPECIFIED);
  else if (r < 0)
    FAIL(NEW_SRV_ERR_BINARY_FILE);
  for (p = s; *p && isspace(*p); p++);
  if (!*p) FAIL(NEW_SRV_ERR_FILE_EMPTY);
  if (serve_count_transient_runs(cs) > 0) {
    if (phr->action == NEW_SRV_ACTION_UPLOAD_RUNLOG_XML_2)
      return -NEW_SRV_ERR_TRANSIENT_RUNS;
    if (cs->pending_xml_import)
      return -NEW_SRV_ERR_PENDING_IMPORT_EXISTS;
    cs->saved_testing_suspended = cs->testing_suspended;
    cs->testing_suspended = 1;
    serve_update_status_file(cs, 1);
    phr->client_state->contest_id = cnts->id;
    phr->client_state->destroy_callback = ns_client_destroy_callback;
    cs->client_id = phr->id;
    cs->pending_xml_import = xstrdup(s);
    cs->destroy_callback = ns_contest_unload_callback;
    phr->no_reply = 1;
  } else {
    runlog_import_xml(cs, cs->runlog_state, fout, 1, s);
  }

 cleanup:
  return retval;
}

static void
parse_error_func(void *data, unsigned char const *format, ...)
{
  va_list args;
  unsigned char buf[1024];
  int l;
  struct serve_state *state = (struct serve_state*) data;

  va_start(args, format);
  l = vsnprintf(buf, sizeof(buf) - 24, format, args);
  va_end(args);
  strcpy(buf + l, "\n");
  state->cur_user->error_msgs = xstrmerge1(state->cur_user->error_msgs, buf);
  filter_expr_nerrs++;
}

static const unsigned char has_failed_test_num[RUN_LAST + 1] =
{
  [RUN_RUN_TIME_ERR]     = 1,
  [RUN_TIME_LIMIT_ERR]   = 1,
  [RUN_PRESENTATION_ERR] = 1,
  [RUN_WRONG_ANSWER_ERR] = 1,
  [RUN_CHECK_FAILED]     = 1,
  [RUN_MEM_LIMIT_ERR]    = 1,
  [RUN_SECURITY_ERR]     = 1,
};
static const unsigned char has_passed_tests[RUN_LAST + 1] =
{
  [RUN_OK]               = 1,
  [RUN_PARTIAL]          = 1,
  [RUN_ACCEPTED]         = 1,
};
static const unsigned char has_olympiad_score[RUN_LAST + 1] =
{
  [RUN_OK]               = 1,
  [RUN_PARTIAL]          = 1,
};
static const unsigned char has_kirov_score[RUN_LAST + 1] =
{
  [RUN_OK]               = 1,
  [RUN_COMPILE_ERR]      = 1,
  [RUN_PARTIAL]          = 1,
  [RUN_ACCEPTED]         = 1,
};

// field codes
enum
{
  F_RUN_ID,                     /* 0 */
  F_IS_HIDDEN,                  /* 1 */
  F_IS_IMPORTED,                /* 2 */
  F_TIME,                       /* 3 */
  F_NSEC,                       /* 4 */
  F_DURATION,                   /* 5 */
  F_SIZE,                       /* 6 */
  F_IS_IPV6,                    /* 7 */
  F_IP,                         /* 8 */
  F_IS_SSL,                     /* 9 */
  F_USER_ID,                    /* 10 */
  F_USER_LOGIN,                 /* 11 */
  F_IS_USER_BANNED,             /* 12 */
  F_IS_USER_INVISIBLE,          /* 13 */
  F_IS_USER_LOCKED,             /* 14 */
  F_IS_USER_INCOMPLETE,         /* 15 */
  F_IS_USER_DISQUALIFIED,       /* 16 */
  F_PROB_ID,                    /* 17 */
  F_PROB_SHORT_NAME,            /* 18 */
  F_VARIANT,                    /* 19 */
  F_VARIANT_DB,                 /* 20 */
  F_LANG_ID,                    /* 21 */
  F_LANG_SHORT_NAME,            /* 22 */
  F_MIME_TYPE,                  /* 23 */
  F_SOURCE_SUFFIX,              /* 24 */
  F_STATUS_SHORT,               /* 25 */
  F_FAILED_TEST,                /* 26 */
  F_PASSED_TESTS,               /* 27 */
  F_TOTAL_SCORE,                /* 28 */
  F_BASE_SCORE,                 /* 29 */
  F_PREV_ATTEMPTS,              /* 30 */
  F_ATTEMPT_PENALTY,            /* 31 */
  F_PREV_DISQUAL,               /* 32 */
  F_DISQUAL_PENALTY,            /* 33 */
  F_TIME_PENALTY,               /* 34 */
  F_PREV_SUCCESSES,             /* 35 */
  F_SUCCESS_BONUS,              /* 36 */
  F_SCORE_ADJUSTMENT,           /* 37 */
  F_IS_AFTER_OK,                /* 38 */
  F_IS_LATEST,                  /* 39 */
  F_SHA1,                       /* 40 */
  F_LOCALE_ID,                  /* 41 */
  F_IS_READONLY,                /* 42 */
  F_PAGES,                      /* 43 */
  F_JUDGE_ID,                   /* 44 */

  F_TOTAL_FIELDS,               /* 45 */
};

static void
write_csv_record(
        FILE *fout,
        int nfield,
        const unsigned char **fields)
{
  int i;

  for (i = 0; i < nfield; i++) {
    if (i > 0) putc(';', fout);
    if (fields[i]) fputs(fields[i], fout);
  }
  putc('\n', fout);
}

static int
do_dump_master_runs(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int first_run, int last_run,
        unsigned char const *filter_expr)
{
  struct user_filter_info *u = 0;
  struct filter_env env;
  int i, r;
  int *match_idx = 0;
  int match_tot = 0;
  int transient_tot = 0;
  int *list_idx = 0;
  int list_tot = 0;
  unsigned char statstr[64];
  int rid, attempts, disq_attempts, prev_successes;
  time_t run_time, start_time;
  const struct run_entry *pe;
  unsigned char dur_str[128];
  int duration, dur_sec, dur_min, dur_hour, user_flags, variant;
  int score, score_bonus, orig_score, date_penalty;
  const unsigned char *user_login;
  unsigned char variant_buf[128], db_variant_buf[128];
  unsigned char failed_test_buf[128], passed_tests_buf[128], score_buf[128];
  unsigned char prev_successes_buf[128], score_bonus_buf[128];
  unsigned char attempts_buf[128], attempts_penalty_buf[128];
  unsigned char disq_attempts_buf[128], disq_attempts_penalty_buf[128];
  unsigned char date_penalty_buf[128], score_adj_buf[128];
  unsigned char run_id_buf[128], run_date_buf[128], nsec_buf[128];
  unsigned char user_id_buf[128], ip_buf[128], prob_id_buf[128];
  unsigned char lang_id_buf[128], judge_id_buf[128], pages_buf[128];
  unsigned char locale_id_buf[128], sha1_buf[256], base_score_buf[128];
  const unsigned char *csv_rec[F_TOTAL_FIELDS];

  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = 0;
  const struct section_language_data *lang = 0;

  filter_expr_nerrs = 0;
  u = user_filter_info_allocate(cs, phr->user_id, phr->session_id);
  if (u->prev_filter_expr) xfree(u->prev_filter_expr);
  if (u->tree_mem) filter_tree_delete(u->tree_mem);
  if (u->error_msgs) xfree(u->error_msgs);
  u->error_msgs = 0;
  u->prev_filter_expr = 0;
  u->prev_tree = 0;
  u->tree_mem = 0;
  u->prev_filter_expr = xstrdup(filter_expr);
  u->tree_mem = filter_tree_new();
  if (filter_expr && *filter_expr) {
    filter_expr_set_string(filter_expr, u->tree_mem, parse_error_func, cs);
    filter_expr_init_parser(u->tree_mem, parse_error_func, cs);
    i = filter_expr_parse();
    if (i + filter_expr_nerrs == 0 && filter_expr_lval &&
        filter_expr_lval->type == FILTER_TYPE_BOOL) {
      // parsing successful
      u->prev_tree = filter_expr_lval;
      xfree(u->error_msgs); u->error_msgs = 0;
    } else {
      // parsing failed
      u->tree_mem = filter_tree_delete(u->tree_mem);
      u->prev_tree = 0;
      u->tree_mem = 0;
      return -NEW_SRV_ERR_INV_FILTER_EXPR;
    }
  }

  memset(&env, 0, sizeof(env));
  env.teamdb_state = cs->teamdb_state;
  env.serve_state = cs;
  env.mem = filter_tree_new();
  env.maxlang = cs->max_lang;
  env.langs = (const struct section_language_data * const *) cs->langs;
  env.maxprob = cs->max_prob;
  env.probs = (const struct section_problem_data * const *) cs->probs;
  env.rtotal = run_get_total(cs->runlog_state);
  run_get_header(cs->runlog_state, &env.rhead);
  env.cur_time = time(0);
  env.rentries = run_get_entries_ptr(cs->runlog_state);

  match_idx = alloca((env.rtotal + 1) * sizeof(match_idx[0]));
  memset(match_idx, 0, (env.rtotal + 1) * sizeof(match_idx[0]));
  match_tot = 0;
  transient_tot = 0;

  for (i = 0; i < env.rtotal; i++) {
    if (env.rentries[i].status >= RUN_TRANSIENT_FIRST
        && env.rentries[i].status <= RUN_TRANSIENT_LAST)
      transient_tot++;
    env.rid = i;
    if (u->prev_tree) {
      r = filter_tree_bool_eval(&env, u->prev_tree);
      if (r < 0) {
        parse_error_func(cs, "run %d: %s", i, filter_strerror(-r));
        continue;
      }
      if (!r) continue;
    }
    match_idx[match_tot++] = i;
  }
  env.mem = filter_tree_delete(env.mem);
  if (u->error_msgs) {
    return -NEW_SRV_ERR_INV_FILTER_EXPR;
  }

  list_idx = alloca((env.rtotal + 1) * sizeof(list_idx[0]));
  memset(list_idx, 0, (env.rtotal + 1) * sizeof(list_idx[0]));
  list_tot = 0;

  if (!first_run) first_run = u->prev_first_run;
  if (!last_run) last_run = u->prev_last_run;
  u->prev_first_run = first_run;
  u->prev_last_run = last_run;

  if (!first_run && !last_run) {
    // last 20 in the reverse order
    first_run = -1;
    last_run = -20;
  } else if (!first_run) {
    // from the last in the reverse order
    first_run = -1;
  } else if (!last_run) {
    // 20 in the reverse order
    last_run = first_run - 20 + 1;
    if (first_run > 0 && last_run <= 0) {
      last_run = 1;
    }
  }
  if (first_run > 0) first_run--;
  if (last_run > 0) last_run--;
  if (first_run >= match_tot) first_run = match_tot;
  if (first_run < 0) {
    first_run = match_tot + first_run;
    if (first_run < 0) first_run = 0;
  }
  if (last_run >= match_tot) last_run = match_tot;
  if (last_run < 0) {
    last_run = match_tot + last_run;
    if (last_run < 0) last_run = 0;
  }
  if (first_run <= last_run) {
    for (i = first_run; i <= last_run && i < match_tot; i++)
      list_idx[list_tot++] = match_idx[i];
  } else {
    for (i = first_run; i >= last_run; i--)
      list_idx[list_tot++] = match_idx[i];
  }

  for (i = 0; i < list_tot; i++) {
    memset(csv_rec, 0, sizeof(csv_rec));

    rid = list_idx[i];
    ASSERT(rid >= 0 && rid < env.rtotal);
    pe = &env.rentries[rid];
    snprintf(run_id_buf, sizeof(run_id_buf), "%d", rid);
    csv_rec[F_RUN_ID] = run_id_buf;
    if (!run_is_valid_status(pe->status)) {
      snprintf(statstr, sizeof(statstr), "%d", pe->status);
      csv_rec[F_STATUS_SHORT] = statstr;
      write_csv_record(fout, F_TOTAL_FIELDS, csv_rec);
      continue;
    }

    run_status_to_str_short(statstr, sizeof(statstr), pe->status);
    csv_rec[F_STATUS_SHORT] = statstr;

    if (pe->status == RUN_EMPTY) {
      write_csv_record(fout, F_TOTAL_FIELDS, csv_rec);
      continue;
    }

    snprintf(run_date_buf, sizeof(run_date_buf), "%s",
             xml_unparse_date(pe->time));
    csv_rec[F_TIME] = run_date_buf;
    snprintf(nsec_buf, sizeof(nsec_buf), "%d", pe->nsec);
    csv_rec[F_NSEC] = nsec_buf;
    run_time = pe->time;
    if (global->is_virtual) {
      start_time = run_get_virtual_start_time(cs->runlog_state, pe->user_id);
    } else {
      start_time = env.rhead.start_time;
    }
    if (run_time < start_time) {
      dur_str[0] = 0;
    } else {
      duration = run_time - start_time;
      dur_sec = duration % 60; duration /= 60;
      dur_min = duration % 60; duration /= 60;
      dur_hour = duration % 24; duration /= 24;
      if (duration > 0) {
        snprintf(dur_str, sizeof(dur_str), "%d %02d:%02d:%02d",
                 duration, dur_hour, dur_min, dur_sec);
      } else {
        snprintf(dur_str, sizeof(dur_str), "%02d:%02d:%02d",
                 dur_hour, dur_min, dur_sec);
      }
    }
    csv_rec[F_DURATION] = dur_str;

    snprintf(user_id_buf, sizeof(user_id_buf), "%d", pe->user_id);
    csv_rec[F_USER_ID] = user_id_buf;
    if ((user_login = teamdb_get_login(cs->teamdb_state, pe->user_id))) {
      user_flags = teamdb_get_flags(cs->teamdb_state, pe->user_id);
      if ((user_flags & TEAM_BANNED)) csv_rec[F_IS_USER_BANNED] = "1";
      if ((user_flags & TEAM_INVISIBLE)) csv_rec[F_IS_USER_INVISIBLE] = "1";
      if ((user_flags & TEAM_LOCKED)) csv_rec[F_IS_USER_LOCKED] = "1";
      if ((user_flags & TEAM_INCOMPLETE)) csv_rec[F_IS_USER_INCOMPLETE] = "1";
      if ((user_flags & TEAM_DISQUALIFIED)) csv_rec[F_IS_USER_DISQUALIFIED]="1";
    } else {
      user_login = "";
    }
    csv_rec[F_USER_LOGIN] = user_login;

    snprintf(ip_buf, sizeof(ip_buf), "%s", xml_unparse_ip(pe->a.ip));
    csv_rec[F_IP] = ip_buf;
    if (pe->ipv6_flag) csv_rec[F_IS_IPV6] = "1";
    if (pe->ssl_flag) csv_rec[F_IS_SSL] = "1";

    if (pe->status == RUN_VIRTUAL_START || pe->status == RUN_VIRTUAL_STOP) {
      write_csv_record(fout, F_TOTAL_FIELDS, csv_rec);
      continue;
    }

    if (pe->is_hidden) csv_rec[F_IS_HIDDEN] = "1";
    if (pe->is_imported) csv_rec[F_IS_IMPORTED] = "1";
    if (pe->is_readonly) csv_rec[F_IS_READONLY] = "1";
    snprintf(sha1_buf, sizeof(sha1_buf), "%s", unparse_sha1(pe->sha1));
    csv_rec[F_SHA1] = sha1_buf;
    if (pe->locale_id >= 0) {
      snprintf(locale_id_buf, sizeof(locale_id_buf), "%d", pe->locale_id);
      csv_rec[F_LOCALE_ID] = locale_id_buf;
    }
    if (pe->pages > 0) {
      snprintf(pages_buf, sizeof(pages_buf), "%d", pe->pages);
      csv_rec[F_PAGES] = pages_buf;
    }
    if (pe->judge_id > 0) {
      snprintf(judge_id_buf, sizeof(judge_id_buf), "%d", pe->judge_id);
      csv_rec[F_JUDGE_ID] = judge_id_buf;
    }

    snprintf(prob_id_buf, sizeof(prob_id_buf), "%d", pe->prob_id);
    csv_rec[F_PROB_ID] = prob_id_buf;

    if (pe->prob_id > 0 && pe->prob_id <= cs->max_prob
        && (prob = cs->probs[pe->prob_id])) {
      csv_rec[F_PROB_SHORT_NAME] = prob->short_name;
      if (prob->variant_num > 0) {
        snprintf(db_variant_buf, sizeof(db_variant_buf), "%d", pe->variant);
        variant = find_variant(cs, pe->user_id, pe->prob_id, 0);
        if (variant < 0) variant = 0;
        snprintf(variant_buf, sizeof(variant_buf), "%d", variant);
        csv_rec[F_VARIANT] = variant_buf;
        csv_rec[F_VARIANT_DB] = db_variant_buf;
      }
    }

    snprintf(lang_id_buf, sizeof(lang_id_buf), "%d", pe->lang_id);
    csv_rec[F_LANG_ID] = lang_id_buf;

    if (pe->lang_id > 0 && pe->lang_id <= cs->max_lang
        && (lang = cs->langs[pe->lang_id])) {
      csv_rec[F_LANG_SHORT_NAME] = lang->short_name;
      csv_rec[F_SOURCE_SUFFIX] = lang->src_sfx;
    } else if (!pe->lang_id) {
      csv_rec[F_MIME_TYPE] = mime_type_get_type(pe->mime_type);
      csv_rec[F_SOURCE_SUFFIX] = mime_type_get_suffix(pe->mime_type);
    }

    if (global->score_system_val == SCORE_ACM) {
      if (has_failed_test_num[pe->status]) {
        snprintf(failed_test_buf, sizeof(failed_test_buf), "%d", pe->test);
        csv_rec[F_FAILED_TEST] = failed_test_buf;
      }
      write_csv_record(fout, F_TOTAL_FIELDS, csv_rec);
      continue;
    } else if (global->score_system_val == SCORE_MOSCOW) {
      if (has_failed_test_num[pe->status]) {
        snprintf(failed_test_buf, sizeof(failed_test_buf), "%d", pe->test);
        csv_rec[F_FAILED_TEST] = failed_test_buf;
      }
      snprintf(score_buf, sizeof(score_buf), "%d", pe->score);
      csv_rec[F_TOTAL_SCORE] = score_buf;
      csv_rec[F_BASE_SCORE] = score_buf;
      write_csv_record(fout, F_TOTAL_FIELDS, csv_rec);
      continue;
    } else if (global->score_system_val == SCORE_OLYMPIAD) {
      if (has_failed_test_num[pe->status]) {
        snprintf(failed_test_buf, sizeof(failed_test_buf), "%d", pe->test);
        csv_rec[F_FAILED_TEST] = failed_test_buf;
      }
      if (has_passed_tests[pe->status]) {
        snprintf(passed_tests_buf, sizeof(passed_tests_buf), "%d", pe->test);
        csv_rec[F_PASSED_TESTS] = passed_tests_buf;
      }
      if (has_olympiad_score[pe->status]) {
        snprintf(score_buf, sizeof(score_buf), "%d", pe->score);
        csv_rec[F_TOTAL_SCORE] = score_buf;
        csv_rec[F_BASE_SCORE] = score_buf;
      }
      write_csv_record(fout, F_TOTAL_FIELDS, csv_rec);
      continue;
    } else if (global->score_system_val == SCORE_KIROV) {
      if (!has_kirov_score[pe->status]) {
        write_csv_record(fout, F_TOTAL_FIELDS, csv_rec);
        continue;
      }

      snprintf(passed_tests_buf, sizeof(passed_tests_buf), "%d", pe->test - 1);
      csv_rec[F_PASSED_TESTS] = passed_tests_buf;

      prev_successes = RUN_TOO_MANY;
      score_bonus = 0;
      if (pe->status == RUN_OK && !pe->is_hidden
          && prob && prob->score_bonus_total > 0) {
        if ((prev_successes = run_get_prev_successes(cs->runlog_state, rid))<0)
          prev_successes = RUN_TOO_MANY;
        if (prev_successes != RUN_TOO_MANY) {
          snprintf(prev_successes_buf, sizeof(prev_successes_buf),
                   "%d", prev_successes);
          csv_rec[F_PREV_SUCCESSES] = prev_successes_buf;
        }
        if (prev_successes >= 0 && prev_successes < prob->score_bonus_total)
          score_bonus = prob->score_bonus_val[prev_successes];
        snprintf(score_bonus_buf, sizeof(score_bonus_buf), "%d", score_bonus);
        csv_rec[F_SUCCESS_BONUS] = score_bonus_buf;
      }

      attempts = 0; disq_attempts = 0;
      if (global->score_system_val == SCORE_KIROV && !pe->is_hidden) {
        run_get_attempts(cs->runlog_state, rid, &attempts, &disq_attempts,
                         global->ignore_compile_errors);
      }

      orig_score = pe->score;
      if (pe->status == RUN_OK && !prob->variable_full_score)
        orig_score = prob->full_score;
      snprintf(base_score_buf, sizeof(base_score_buf), "%d", orig_score);
      csv_rec[F_BASE_SCORE] = base_score_buf;
      score = calc_kirov_score(0, 0, pe, prob, attempts, disq_attempts,
                               prev_successes, &date_penalty, 0);
      snprintf(score_buf, sizeof(score_buf), "%d", score);
      csv_rec[F_TOTAL_SCORE] = score_buf;
      if (attempts > 0) {
        snprintf(attempts_buf, sizeof(attempts_buf), "%d", attempts);
        csv_rec[F_PREV_ATTEMPTS] = attempts_buf;
      }
      if (attempts * prob->run_penalty != 0) {
        snprintf(attempts_penalty_buf, sizeof(attempts_penalty_buf),
                 "%d", attempts * prob->run_penalty);
        csv_rec[F_ATTEMPT_PENALTY] = attempts_penalty_buf;
      }
      if (disq_attempts > 0) {
        snprintf(disq_attempts_buf, sizeof(disq_attempts_buf),
                 "%d", disq_attempts);
        csv_rec[F_PREV_DISQUAL] = disq_attempts_buf;
      }
      if (disq_attempts * prob->disqualified_penalty != 0) {
        snprintf(disq_attempts_penalty_buf, sizeof(disq_attempts_penalty_buf),
                 "%d", disq_attempts * prob->disqualified_penalty);
        csv_rec[F_DISQUAL_PENALTY] = disq_attempts_penalty_buf;
      }
      if (date_penalty != 0) {
        snprintf(date_penalty_buf, sizeof(date_penalty_buf),
                 "%d", date_penalty);
        csv_rec[F_TIME_PENALTY] = date_penalty_buf;
      }
      if (pe->score_adj != 0) {
        snprintf(score_adj_buf, sizeof(score_adj_buf), "%d", pe->score_adj);
        csv_rec[F_SCORE_ADJUSTMENT] = score_adj_buf;
      }
      write_csv_record(fout, F_TOTAL_FIELDS, csv_rec);
      continue;
    } else {
      abort();
    }
  }
  return 0;
}

static int
cmd_dump_master_runs(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0, first_run = 0, last_run = 0, r;
  const unsigned char *filter_expr = 0, *s = 0;

  if (phr->role != USER_ROLE_ADMIN && phr->role != USER_ROLE_JUDGE)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (ns_cgi_param(phr, "filter_expr", &filter_expr) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  if (!filter_expr) filter_expr = "";
  if ((r = ns_cgi_param(phr, "first_run", &s)) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  if (r > 0 && *s) {
    if (parse_int(s, &first_run) < 0)
      FAIL(NEW_SRV_ERR_INV_PARAM);
    if (first_run >= 0) first_run++;
  }
  if ((r = ns_cgi_param(phr, "last_run", &s)) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  if (r > 0 && *s) {
    if (parse_int(s, &last_run) < 0)
      FAIL(NEW_SRV_ERR_INV_PARAM);
    if (last_run >= 0) last_run++;
  }

  retval = do_dump_master_runs(fout, phr, cnts, extra,
                               first_run, last_run, filter_expr);

 cleanup:
  return retval;
}

typedef int (*cmd_handler_t)(FILE *, struct http_request_info *,
                             const struct contest_desc *,
                             struct contest_extra *);

static cmd_handler_t cmd_actions_table[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_WRITE_XML_RUNS] = cmd_dump_runs,
  [NEW_SRV_ACTION_EXPORT_XML_RUNS] = cmd_dump_runs,
  [NEW_SRV_ACTION_VIEW_RUNS_DUMP] = cmd_dump_runs,
  [NEW_SRV_ACTION_LOGOUT] = cmd_logout,
  [NEW_SRV_ACTION_DUMP_PROBLEMS] = cmd_dump_problems,
  [NEW_SRV_ACTION_SOFT_UPDATE_STANDINGS] = cmd_operation,
  [NEW_SRV_ACTION_TEST_SUSPEND] = cmd_operation,
  [NEW_SRV_ACTION_TEST_RESUME] = cmd_operation,
  [NEW_SRV_ACTION_REJUDGE_SUSPENDED_2] = cmd_operation,
  [NEW_SRV_ACTION_HAS_TRANSIENT_RUNS] = cmd_operation,
  [NEW_SRV_ACTION_DUMP_RUN_STATUS] = cmd_run_operation,
  [NEW_SRV_ACTION_DUMP_SOURCE] = cmd_run_operation,
  [NEW_SRV_ACTION_DUMP_CLAR] = cmd_clar_operation,
  [NEW_SRV_ACTION_GET_CONTEST_NAME] = cmd_operation_2,
  [NEW_SRV_ACTION_GET_CONTEST_TYPE] = cmd_operation_2,
  [NEW_SRV_ACTION_SUBMIT_RUN] = cmd_submit_run,
  [NEW_SRV_ACTION_UPLOAD_RUNLOG_XML_2] = cmd_import_xml_runs,
  [NEW_SRV_ACTION_DUMP_MASTER_RUNS] = cmd_dump_master_runs,
  [NEW_SRV_ACTION_DUMP_REPORT] = cmd_run_operation,
  [NEW_SRV_ACTION_FULL_UPLOAD_RUNLOG_XML] = cmd_import_xml_runs,
  [NEW_SRV_ACTION_RELOAD_SERVER] = cmd_operation,
  [NEW_SRV_ACTION_START_CONTEST] = cmd_operation,
  [NEW_SRV_ACTION_STOP_CONTEST] = cmd_operation,
  [NEW_SRV_ACTION_CONTINUE_CONTEST] = cmd_operation,
  [NEW_SRV_ACTION_SUSPEND] = cmd_operation,
  [NEW_SRV_ACTION_RESUME] = cmd_operation,
  [NEW_SRV_ACTION_PRINT_SUSPEND] = cmd_operation,
  [NEW_SRV_ACTION_PRINT_RESUME] = cmd_operation,
  [NEW_SRV_ACTION_SET_JUDGING_MODE] = cmd_operation,
  [NEW_SRV_ACTION_SET_ACCEPTING_MODE] = cmd_operation,
  [NEW_SRV_ACTION_SET_TESTING_FINISHED_FLAG] = cmd_operation,
  [NEW_SRV_ACTION_CLEAR_TESTING_FINISHED_FLAG] = cmd_operation,
  [NEW_SRV_ACTION_REJUDGE_ALL_2] = cmd_operation,
  [NEW_SRV_ACTION_SCHEDULE] = cmd_operation,
};

int
new_server_cmd_handler(FILE *fout, struct http_request_info *phr)
{
  int r = 0;
  const struct contest_desc *cnts = 0;
  opcap_t caps = 0;
  struct teamdb_db_callbacks callbacks;
  struct contest_extra *extra = 0;

  if (phr->action == NEW_SRV_ACTION_LOGIN)
    return cmd_login(fout, phr);

  if (ns_open_ul_connection(phr->fw_state) < 0)
    return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;

  if ((r = userlist_clnt_get_cookie(ul_conn, ULS_PRIV_GET_COOKIE,
                                    phr->ip, phr->ssl_flag,
                                    phr->session_id,
                                    &phr->user_id, &phr->contest_id,
                                    &phr->locale_id, 0, &phr->role, 0, 0, 0,
                                    &phr->login, &phr->name)) < 0) {
    switch (-r) {
    case ULS_ERR_NO_COOKIE:
      return -NEW_SRV_ERR_PERMISSION_DENIED;
    case ULS_ERR_DISCONNECT:
      return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
    default:
      return -NEW_SRV_ERR_INTERNAL;
    }
  }

  if (phr->contest_id < 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts)
    return -NEW_SRV_ERR_INV_CONTEST_ID;
  if (!cnts->new_managed)
    return -NEW_SRV_ERR_INV_CONTEST_ID;
  extra = ns_get_contest_extra(phr->contest_id);
  ASSERT(extra);

  if (phr->role < 0 || phr->role >= USER_ROLE_LAST)
    return -NEW_SRV_ERR_INV_ROLE;

  // analyze IP limitations
  if (phr->role == USER_ROLE_ADMIN) {
    if (!contests_check_master_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      return -NEW_SRV_ERR_PERMISSION_DENIED;
  } else if (phr->role == USER_ROLE_CONTESTANT) {
    if (!contests_check_team_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      return -NEW_SRV_ERR_PERMISSION_DENIED;
  } else {
    if (!contests_check_judge_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      return -NEW_SRV_ERR_PERMISSION_DENIED;
  }

  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
        || opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0)
      return -NEW_SRV_ERR_PERMISSION_DENIED;
  } else if (phr->role == USER_ROLE_JUDGE) {
    // as for the judge program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
        || opcaps_check(caps, OPCAP_JUDGE_LOGIN) < 0)
      return -NEW_SRV_ERR_PERMISSION_DENIED;
  } else if (phr->role == USER_ROLE_CONTESTANT) {
    if (cnts->closed || cnts->client_disable_team)
      return -NEW_SRV_ERR_PERMISSION_DENIED;
  } else {
    // user privileges checked locally
    if (nsdb_check_role(phr->user_id, phr->contest_id, phr->role) < 0)
      return -NEW_SRV_ERR_PERMISSION_DENIED;
  }

  if (phr->name && *phr->name) {
    phr->name_arm = html_armor_string_dup(phr->name);
  } else {
    phr->name_arm = html_armor_string_dup(phr->login);
  }
  if (extra->contest_arm) xfree(extra->contest_arm);
  if (phr->locale_id == 0 && cnts->name_en) {
    extra->contest_arm = html_armor_string_dup(cnts->name_en);
  } else {
    extra->contest_arm = html_armor_string_dup(cnts->name);
  }

  phr->caps = 0;
  if ((phr->role == USER_ROLE_ADMIN || phr->role == USER_ROLE_JUDGE)
      && opcaps_find(&cnts->capabilities, phr->login, &caps) >= 0) {
    phr->caps = caps;
  }

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.user_data = (void*) phr->fw_state;
  callbacks.list_all_users = ns_list_all_users_callback;

  // invoke the contest
  if (serve_state_load_contest(phr->contest_id,
                               ul_conn,
                               &callbacks,
                               &extra->serve_state, 0) < 0) {
    return -NEW_SRV_ERR_INV_CONTEST_ID;
  }

  if (phr->role == USER_ROLE_CONTESTANT) {
    if (!teamdb_lookup(extra->serve_state->teamdb_state, phr->user_id))
      return -NEW_SRV_ERR_PERMISSION_DENIED;
    r = teamdb_get_flags(extra->serve_state->teamdb_state, phr->user_id);
    if (r & (TEAM_BANNED | TEAM_LOCKED))
      return -NEW_SRV_ERR_PERMISSION_DENIED;
  }

  extra->serve_state->current_time = time(0);
  ns_check_contest_events(extra->serve_state, cnts);
  phr->allow_empty_output = 1;

  if (phr->action > 0 && phr->action < NEW_SRV_ACTION_LAST
      && cmd_actions_table[phr->action]) {
    return (*cmd_actions_table[phr->action])(fout, phr, cnts, extra);
  } else {
    return -NEW_SRV_ERR_INV_ACTION;
  }
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
