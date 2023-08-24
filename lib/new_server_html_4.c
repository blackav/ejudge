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
#include "ejudge/ej_types.h"
#include "ejudge/ej_limits.h"
#include "ejudge/new-server.h"
#include "ejudge/new_server_proto.h"
#include "ejudge/contests.h"
#include "ejudge/userlist.h"
#include "ejudge/userlist_proto.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/runlog.h"
#include "ejudge/html.h"
#include "ejudge/prepare.h"
#include "ejudge/archive_paths.h"
#include "ejudge/fileutl.h"
#include "ejudge/teamdb.h"
#include "ejudge/misctext.h"
#include "ejudge/clarlog.h"
#include "ejudge/mime_type.h"
#include "ejudge/sha.h"
#include "ejudge/filter_tree.h"
#include "ejudge/filter_eval.h"
#include "ejudge/xml_utils.h"
#include "ejudge/charsets.h"
#include "ejudge/compat.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/errlog.h"
#include "ejudge/prepare_dflt.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/testing_report_xml.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <pwd.h>

#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

static int
parse_int(const char *str, int *p_val)
{
  int v;
  char *eptr = 0;

  if (!str) return -1;
  while (isspace(*str)) ++str;
  if (!*str) return -1;

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
  if (hr_cgi_param(phr, "login", &login) <= 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (hr_cgi_param(phr, "password", &password) <= 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (phr->contest_id <= 0 || contests_get(phr->contest_id, &cnts) || !cnts)
    FAIL(NEW_SRV_ERR_INV_CONTEST_ID);
  if (!cnts->managed)
    FAIL(NEW_SRV_ERR_INV_CONTEST_ID);
  if (hr_cgi_param(phr, "role", &role_str) <= 0)
    FAIL(NEW_SRV_ERR_INV_ROLE);
  if (parse_int(role_str, &phr->role) < 0
      || phr->role < 0 || phr->role >= USER_ROLE_LAST)
    FAIL(NEW_SRV_ERR_INV_ROLE);
  phr->login = xstrdup(login);

  switch (phr->role) {
  case USER_ROLE_CONTESTANT:
    if (cnts->closed)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    if (!contests_check_team_ip(phr->contest_id, &phr->ip, phr->ssl_flag))
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    break;
  case USER_ROLE_OBSERVER:
  case USER_ROLE_EXAMINER:
  case USER_ROLE_CHIEF_EXAMINER:
  case USER_ROLE_COORDINATOR:
  case USER_ROLE_JUDGE:
    if (!contests_check_judge_ip(phr->contest_id, &phr->ip, phr->ssl_flag))
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    break;
  case USER_ROLE_ADMIN:
    if (!contests_check_master_ip(phr->contest_id, &phr->ip, phr->ssl_flag))
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    break;
  default:
    abort();
  }

  if (ns_open_ul_connection(phr->fw_state) < 0)
    FAIL(NEW_SRV_ERR_USERLIST_SERVER_DOWN);

  if (phr->role == USER_ROLE_CONTESTANT) {
    r = userlist_clnt_login(ul_conn, ULS_TEAM_CHECK_USER,
                            &phr->ip,
                            0, /* cookie */
                            phr->client_key,
                            0, /* expire */
                            phr->ssl_flag, phr->contest_id,
                            phr->locale_id,
                            0, /* pwd_special */
                            0, /* is_ws */
                            0, /* is_job */
                            login, password,
                            &phr->user_id,
                            &phr->session_id,
                            &phr->client_key,
                            &phr->name,
                            NULL /* expire */,
                            &phr->priv_level,
                            &phr->reg_status,
                            &phr->reg_flags);
  } else {
    r = userlist_clnt_priv_login(ul_conn, ULS_PRIV_CHECK_USER,
                                 &phr->ip, phr->client_key,
                                 phr->ssl_flag, phr->contest_id,
                                 phr->locale_id, phr->role, login,
                                 password, &phr->user_id,
                                 &phr->session_id,
                                 &phr->client_key,
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

  if (phr->client_key) {
    fprintf(fout, "%016llx-%016llx\n", phr->session_id, phr->client_key);
  } else {
    fprintf(fout, "%016llx\n", phr->session_id);
  }

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
                              phr->session_id,
                              phr->client_key);
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
    const unsigned char *long_name = prob->long_name;
    if (!long_name) long_name = "";
    fprintf(fout, "%d;%s;%s\n", prob->id, prob->short_name, long_name);
  }
  return 0;
}

static int
cmd_dump_languages(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  int i;
  const struct section_language_data *lang;

  for (i = 0; i <= cs->max_lang; i++) {
    if (!(lang = cs->langs[i])) continue;
    fprintf(fout, "%d;%s;%s;%s;%s\n", lang->id, lang->short_name, lang->long_name, lang->src_sfx, lang->exe_sfx);
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
  time_t sloc = 0, start_time, stop_time;

  if (hr_cgi_param(phr, "sched_time", &s) <= 0)
    return -NEW_SRV_ERR_INV_TIME_SPEC;
  if (xml_parse_date(NULL, 0, 0, 0, s, &sloc) < 0 || sloc < 0)
    return -NEW_SRV_ERR_INV_TIME_SPEC;

  if (sloc > 0) {
    run_get_times(cs->runlog_state, 0, &start_time, 0, 0, &stop_time, 0);
    if (stop_time > 0) return -NEW_SRV_ERR_CONTEST_ALREADY_FINISHED;
    if (start_time > 0) return -NEW_SRV_ERR_CONTEST_ALREADY_STARTED;
  }
  run_sched_contest(cs->runlog_state, sloc);
  serve_update_standings_file(phr->extra, cs, cnts, 0);
  serve_update_status_file(ejudge_config, cnts, cs, 1);
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
    serve_update_standings_file(extra, cs, cnts, 0);
    break;

  case NEW_SRV_ACTION_TEST_SUSPEND:
    cs->testing_suspended = 1;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;
  case NEW_SRV_ACTION_TEST_RESUME:
    cs->testing_suspended = 0;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;
  case NEW_SRV_ACTION_REJUDGE_SUSPENDED_2:
    serve_judge_suspended(extra, ejudge_config, cnts, cs, phr->user_id, &phr->ip, phr->ssl_flag, DFLT_G_REJUDGE_PRIORITY_ADJUSTMENT, 0);
    break;
  case NEW_SRV_ACTION_HAS_TRANSIENT_RUNS:
    if (serve_count_transient_runs(cs) > 0)
      return -NEW_SRV_ERR_TRANSIENT_RUNS;
    break;
  case NEW_SRV_ACTION_RELOAD_SERVER:
    extra->last_access_time = 0;
    break;
  case NEW_SRV_ACTION_RELOAD_SERVER_ALL:
    ns_reload_server_all();
    break;
  case NEW_SRV_ACTION_START_CONTEST:
    run_get_times(cs->runlog_state, 0, &start_time, 0, &duration, &stop_time, 0);
    if (stop_time > 0) return -NEW_SRV_ERR_CONTEST_ALREADY_FINISHED;
    if (start_time > 0) return -NEW_SRV_ERR_CONTEST_ALREADY_STARTED;
    run_start_contest(cs->runlog_state, cs->current_time);
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    serve_invoke_start_script(cs);
    serve_update_standings_file(extra, cs, cnts, 0);
    break;
  case NEW_SRV_ACTION_STOP_CONTEST:
    run_get_times(cs->runlog_state, 0, &start_time, 0, &duration, &stop_time, 0);
    if (stop_time > 0) return -NEW_SRV_ERR_CONTEST_ALREADY_FINISHED;
    if (start_time <= 0) return -NEW_SRV_ERR_CONTEST_NOT_STARTED;
    run_stop_contest(cs->runlog_state, cs->current_time);
    serve_invoke_stop_script(cs);
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;
  case NEW_SRV_ACTION_CONTINUE_CONTEST:
    run_get_times(cs->runlog_state, 0, &start_time, 0, &duration, &stop_time, 0);
    if (!global->enable_continue) return -NEW_SRV_ERR_CANNOT_CONTINUE_CONTEST;
    if (start_time <= 0) return -NEW_SRV_ERR_CONTEST_NOT_STARTED;
    if (stop_time <= 0) return -NEW_SRV_ERR_CONTEST_NOT_FINISHED;
    if (duration > 0 && cs->current_time >= start_time + duration)
      return -NEW_SRV_ERR_INSUFFICIENT_DURATION;
    run_set_finish_time(cs->runlog_state, 0);
    run_stop_contest(cs->runlog_state, 0);
    serve_invoke_stop_script(cs);
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;
  case NEW_SRV_ACTION_SUSPEND:
    cs->clients_suspended = 1;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;
  case NEW_SRV_ACTION_RESUME:
    cs->clients_suspended = 0;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;
  case NEW_SRV_ACTION_PRINT_SUSPEND:
    if (!global->enable_printing) break;
    cs->printing_suspended = 1;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;
  case NEW_SRV_ACTION_PRINT_RESUME:
    if (!global->enable_printing) break;
    cs->printing_suspended = 1;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;
  case NEW_SRV_ACTION_SET_JUDGING_MODE:
    if (global->score_system != SCORE_OLYMPIAD) break;
    cs->accepting_mode = 0;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;
  case NEW_SRV_ACTION_SET_ACCEPTING_MODE:
    if (global->score_system != SCORE_OLYMPIAD) break;
    cs->accepting_mode = 1;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;
  case NEW_SRV_ACTION_SET_TESTING_FINISHED_FLAG:
    if (global->score_system != SCORE_OLYMPIAD) break;
    if ((!global->is_virtual && cs->accepting_mode)
        ||(global->is_virtual && global->disable_virtual_auto_judge <= 0))
      break;
    cs->testing_finished = 1;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;
  case NEW_SRV_ACTION_CLEAR_TESTING_FINISHED_FLAG:
    if (global->score_system != SCORE_OLYMPIAD) break;
    cs->testing_finished = 0;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;
  case NEW_SRV_ACTION_REJUDGE_ALL_2:
    nsf_add_job(phr->fw_state, serve_rejudge_all(extra, ejudge_config, cnts, cs, phr->user_id, &phr->ip, phr->ssl_flag, DFLT_G_REJUDGE_PRIORITY_ADJUSTMENT, 1));
    break;
  case NEW_SRV_ACTION_SCHEDULE:
    return do_schedule(phr, cs, cnts);

  default:
    abort();
  }

  return 0;
}

static int
get_contest_type(FILE *fout, const struct section_global_data *global)
{
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
    [SCORE_KIROV] = "kirov-virtual",
    [SCORE_OLYMPIAD] = "olympiad-virtual",
    [SCORE_MOSCOW] = 0,
  };

  if (global->score_system < 0 || global->score_system >= SCORE_TOTAL) return -1;
  if (global->is_virtual) s = virtual_contest_types[global->score_system];
  else s = contest_types[global->score_system];
  if (!s) return -1;
  fprintf(fout, "%s", s);
  return 0;
}

static int
get_contest_status(
        FILE *fout,
        const serve_state_t cs,
        time_t start_time,
        time_t stop_time,
        time_t duration)
{
  if (start_time > 0) {
    if (stop_time > 0) {
      if (duration == 0 || start_time + duration > cs->current_time) {
        fprintf(fout, "paused");
      } else {
        fprintf(fout, "over");
      }
    } else {
      fprintf(fout, "running");
    }
  } else {
    fprintf(fout, "not started");
  }
  return 0;
}

static int
get_positive_time(FILE *fout, time_t t)
{
  if (t > 0) {
    fprintf(fout, "%s", xml_unparse_date(t));
  } else {
    fprintf(fout, "%d", 0);
  }
  return 0;
}

static int
get_contest_duration(FILE *fout, int duration)
{
  fprintf(fout, "%d", duration);
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
  time_t start_time = 0, duration = 0, stop_time = 0, sched = 0;

  run_get_times(cs->runlog_state, 0, &start_time, &sched, &duration, &stop_time, 0);
  switch (phr->action) {
  case NEW_SRV_ACTION_GET_CONTEST_NAME:
    fprintf(fout, "%s", cnts->name);
    break;
  case NEW_SRV_ACTION_GET_CONTEST_TYPE:
    if (get_contest_type(fout, global) < 0) FAIL(NEW_SRV_ERR_INV_CONTEST_ID);
    break;
  case NEW_SRV_ACTION_GET_CONTEST_STATUS:
    get_contest_status(fout, cs, start_time, stop_time, duration);
    break;
  case NEW_SRV_ACTION_GET_CONTEST_SCHED:
    get_positive_time(fout, sched);
    break;
  case NEW_SRV_ACTION_GET_CONTEST_DURATION:
    get_contest_duration(fout, duration);
    break;
  case NEW_SRV_ACTION_GET_CONTEST_DESCRIPTION:
    /*
    {
    'name' : '<name>',
    'type' : '<type>',
    'status' : '<status>',
    'start' : '<start time>',
    'duration' : '<duration in seconds>',
    'stop' : '<stop time>',
    'sched' : '<schedule time>'
    }
    */
    fprintf(fout, "{ 'name' : '%s', 'type' : '", cnts->name);
    if (get_contest_type(fout, global) < 0) FAIL(NEW_SRV_ERR_INV_CONTEST_ID);
    fprintf(fout, "', 'status' : '");
    get_contest_status(fout, cs, start_time, stop_time, duration);
    fprintf(fout, "', 'start' : '");
    get_positive_time(fout, start_time);
    fprintf(fout, "', 'duration' : '");
    get_contest_duration(fout, duration);
    fprintf(fout, "', 'stop' : '");
    get_positive_time(fout, stop_time);
    fprintf(fout, "', 'sched' : '");
    get_positive_time(fout, sched);
    fprintf(fout, "' }");
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

  if (hr_cgi_param(phr, "run_id", &s) <= 0)
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

  if (run_is_invalid_status(re.status))
    FAIL(NEW_SRV_ERR_INV_RUN_ID);

  switch (phr->action) {
  case NEW_SRV_ACTION_DUMP_RUN_STATUS:
    retval = ns_write_user_run_status(cs, fout, run_id);
    break;
  case NEW_SRV_ACTION_DUMP_SOURCE:
    src_flags = serve_make_source_read_path(cs, src_path, sizeof(src_path), &re);
    if (src_flags < 0) FAIL(NEW_SRV_ERR_SOURCE_NONEXISTANT);
    if (generic_read_file(&src_text, 0, &src_len, src_flags,0,src_path, "") < 0)
      FAIL(NEW_SRV_ERR_DISK_READ_ERROR);
    if (fwrite(src_text, 1, src_len, fout) != src_len)
      FAIL(NEW_SRV_ERR_WRITE_ERROR);
    break;
  case NEW_SRV_ACTION_DUMP_REPORT:
    if (!run_is_report_available(re.status))
      FAIL(NEW_SRV_ERR_REPORT_UNAVAILABLE);
    if (re.store_flags == STORE_FLAGS_UUID_BSON) {
      // FIXME: support it
    } else {
      src_flags = serve_make_xml_report_read_path(cs, src_path, sizeof(src_path), &re);
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
    }
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
  struct clar_entry_v2 ce;
  unsigned char *msg_txt = 0;
  size_t msg_len = 0;

  if (hr_cgi_param(phr, "clar_id", &s) <= 0)
    FAIL(NEW_SRV_ERR_INV_CLAR_ID);
  if (parse_int(s, &clar_id) < 0 || clar_id < 0)
    FAIL(NEW_SRV_ERR_INV_CLAR_ID);
  if (clar_get_record(cs->clarlog_state, clar_id, &ce) < 0)
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
    if (clar_get_text(cs->clarlog_state, clar_id, &msg_txt, &msg_len) < 0)
      FAIL(NEW_SRV_ERR_DISK_READ_ERROR);
    if (fwrite(msg_txt, 1, msg_len, fout) != msg_len)
      FAIL(NEW_SRV_ERR_WRITE_ERROR);
    xfree(msg_txt); msg_txt = 0;
    break;
  }

 cleanup:
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
  time_t start_time = 0, stop_time = 0;
  char **lang_list;
  int mime_type = 0;
  const unsigned char *mime_type_str = 0;
  ruint32_t shaval[5];
  unsigned char *acc_probs = 0;
  int run_id = 0;
  struct timeval precise_time;
  int arch_flags = 0, hidden_flag = 0;
  path_t run_path;
  unsigned char *utf8_str = NULL;
  int utf8_len = 0;
  int eoln_type = 0;
  struct run_entry new_run;

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

  if (hr_cgi_param(phr, "prob", &s) <= 0)
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  if (s && *s == '#') {
    if (parse_int(s + 1, &i) < 0 || i <= 0 || i > cs->max_prob || !(prob = cs->probs[i]))
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
  } else {
    for (i = 1; i <= cs->max_prob; i++)
      if (cs->probs[i] && !strcmp(s, cs->probs[i]->short_name))
        break;
    if (i > cs->max_prob)
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
    prob = cs->probs[i];
  }

  /* check variant */
  switch (phr->role) {
  case USER_ROLE_CONTESTANT:
    if (prob->disable_user_submit > 0) {
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    }
    if (hr_cgi_param(phr, "variant", &s) != 0)
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
      if (hr_cgi_param(phr, "variant", &s) != 0)
        FAIL(NEW_SRV_ERR_INV_VARIANT);
      variant = 0;
    } else {
      if ((r = hr_cgi_param(phr, "variant", &s)) < 0)
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
  if (prob->type == PROB_TYPE_STANDARD) {
    if (hr_cgi_param(phr, "lang", &s) <= 0)
      FAIL(NEW_SRV_ERR_INV_LANG_ID);
    for (i = 1; i <= cs->max_lang; i++)
      if (cs->langs[i] && !strcmp(s, cs->langs[i]->short_name))
        break;
    if (i > cs->max_lang)
      FAIL(NEW_SRV_ERR_INV_LANG_ID);
    lang_id = i;
    lang = cs->langs[i];

    if (cs->global->enable_eoln_select > 0) {
      hr_cgi_param_int_opt(phr, "eoln_type", &eoln_type, 0);
      if (eoln_type < 0 || eoln_type > EOLN_CRLF) eoln_type = 0;
    }
  }

  if (prob->type == PROB_TYPE_STANDARD && prob->custom_compile_cmd && prob->custom_compile_cmd[0]) {
    // only enable_custom language is allowed
    if (!lang || lang->enable_custom <= 0) {
      fprintf(phr->log_f, "custom language is expected\n");
      FAIL(NEW_SRV_ERR_INV_LANG_ID);
    }
  } else if (prob->type == PROB_TYPE_STANDARD) {
    // enable_custom language is disabled
    if (lang && lang->enable_custom > 0) {
      fprintf(phr->log_f, "custom language is not allowed\n");
      FAIL(NEW_SRV_ERR_INV_LANG_ID);
    }
  }

  /* get the source */
  if (!hr_cgi_param_bin(phr, "file", &run_text, &run_size))
    FAIL(NEW_SRV_ERR_SOURCE_NONEXISTANT);
  if (!run_size)
    FAIL(NEW_SRV_ERR_SUBMIT_EMPTY);
  // check for binaryness
  switch (prob->type) {
  case PROB_TYPE_STANDARD:
    if (!lang->binary && strlen(run_text) != run_size) {
      // guess utf-16/ucs-2
      if (((int) run_size) < 0
          || (utf8_len = ucs2_to_utf8(&utf8_str, run_text, run_size)) < 0) {
        FAIL(NEW_SRV_ERR_BINARY_FILE);
      }
      run_text = utf8_str;
      run_size = (size_t) utf8_len;
    }
    break;
  case PROB_TYPE_OUTPUT_ONLY:
  case PROB_TYPE_TESTS:
    if (!prob->binary_input && !prob->binary && strlen(run_text) != run_size)
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

  if (global->ignore_bom > 0 && !prob->binary && (!lang || !lang->binary)) {
    if (run_text && run_size >= 3 && run_text[0] == 0xef
        && run_text[1] == 0xbb && run_text[2] == 0xbf) {
      run_text += 3; run_size -= 3;
    }
  }

  /* process special kind of answers */
  switch (prob->type) {
  case PROB_TYPE_SELECT_ONE:
    run_text_2 = xstrdup(run_text);
    while (run_size > 0 && isspace(run_text_2[run_size - 1])) run_size--;
    run_text_2[run_size] = 0;
    if (parse_int(run_text, &i) < 0 || i < 0 || i > 65535)
      FAIL(NEW_SRV_ERR_INV_ANSWER);
    xfree(run_text_2); run_text_2 = 0;
    ans_f = open_memstream(&run_text_2, &run_size_2);
    fprintf(ans_f, "%d\n", i);
    close_memstream(ans_f); ans_f = 0;
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
    close_memstream(ans_f); ans_f = 0;
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
      stop_time = run_get_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
    }
    if (cs->clients_suspended)
      FAIL(NEW_SRV_ERR_CLIENTS_SUSPENDED);
    if (!start_time)
      FAIL(NEW_SRV_ERR_CONTEST_NOT_STARTED);
    if (stop_time)
      FAIL(NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
    if (serve_check_user_quota(cs, phr->user_id, run_size) < 0)
      FAIL(NEW_SRV_ERR_RUN_QUOTA_EXCEEDED);
    if (!serve_is_problem_started(cs, phr->user_id, prob))
      FAIL(NEW_SRV_ERR_PROB_UNAVAILABLE);
    if (serve_is_problem_deadlined(cs, phr->user_id, phr->login, prob, 0)) {
      FAIL(NEW_SRV_ERR_PROB_DEADLINE_EXPIRED);
    }
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
    if (global->ignore_duplicated_runs > 0
        && (run_id = run_find_duplicate(cs->runlog_state, phr->user_id,
                                        prob->id, lang_id, variant, run_size,
                                        shaval)) >= 0)
      FAIL(NEW_SRV_ERR_DUPLICATE_SUBMIT);

    if (prob->disable_submit_after_ok
        && global->score_system != SCORE_OLYMPIAD && !cs->accepting_mode) {
      XALLOCAZ(acc_probs, cs->max_prob + 1);
      ns_get_accepted_set(cs, phr->user_id, acc_probs);
      if (acc_probs[prob->id])
        FAIL(NEW_SRV_ERR_PROB_ALREADY_SOLVED);
    }

    if (prob->require) {
      if (!acc_probs) {
        XALLOCAZ(acc_probs, cs->max_prob + 1);
        ns_get_accepted_set(cs, phr->user_id, acc_probs);
      }
      if (prob->require_any > 0) {
        for (i = 0; prob->require[i]; i++) {
          for (j = 1; j <= cs->max_prob; j++)
            if (cs->probs[j] && !strcmp(cs->probs[j]->short_name,
                                        prob->require[i]))
              break;
          if (j <= cs->max_prob && acc_probs[j]) break;
        }
        if (!prob->require[i])
          FAIL(NEW_SRV_ERR_NOT_ALL_REQ_SOLVED);
      } else {
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
  }
  if (ns_load_problem_uuid(phr->log_f, global, prob, variant) < 0) {
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  }

  ej_uuid_t run_uuid = {};
  int store_flags = 0;
  if (global->uuid_run_store > 0 && run_get_uuid_hash_state(cs->runlog_state) >= 0) {
    store_flags = STORE_FLAGS_UUID;
    if (testing_report_bson_available()) store_flags = STORE_FLAGS_UUID_BSON;
  }
  run_id = run_add_record(cs->runlog_state,
                          &precise_time,
                          run_size, shaval, &run_uuid,
                          &phr->ip, phr->ssl_flag,
                          phr->locale_id, phr->user_id,
                          prob->id, lang_id, eoln_type,
                          variant, hidden_flag, mime_type,
                          prob->uuid,
                          store_flags,
                          0 /* is_vcs */,
                          0 /* ext_user_kind */,
                          NULL /* ext_user */,
                          0 /* notify_driver */,
                          0 /* notify_kind */,
                          NULL /* notify_queue */,
                          &new_run);
  if (run_id < 0)
    FAIL(NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
  serve_move_files_to_insert_run(cs, run_id);

  if (store_flags == STORE_FLAGS_UUID || store_flags == STORE_FLAGS_UUID_BSON) {
    arch_flags = uuid_archive_prepare_write_path(cs, run_path, sizeof(run_path),
                                                 &run_uuid, run_size, DFLT_R_UUID_SOURCE, 0, 0);
  } else {
    arch_flags = archive_prepare_write_path(cs, run_path, sizeof(run_path),
                                            global->run_archive_dir, run_id,
                                            run_size, NULL, 0, 0);
  }
  if (arch_flags < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    FAIL(NEW_SRV_ERR_DISK_WRITE_ERROR);
  }

  if (generic_write_file(run_text, run_size, arch_flags, 0, run_path, "") < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    FAIL(NEW_SRV_ERR_DISK_WRITE_ERROR);
  }

  const struct userlist_user *user = teamdb_get_userlist(cs->teamdb_state, phr->user_id);

  if (prob->type == PROB_TYPE_STANDARD) {
    if (prob->disable_auto_testing > 0
        || (prob->disable_testing > 0 && prob->enable_compilation <= 0)
        || lang->disable_auto_testing || lang->disable_testing) {
      serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                        "submit", "ok", RUN_PENDING,
                        "  Testing disabled for this problem or language");
      run_change_status_4(cs->runlog_state, run_id, RUN_PENDING, &new_run);
      serve_notify_run_update(phr->config, cs, &new_run);
    } else {
      serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                        "submit", "ok", RUN_COMPILING, NULL);
      if ((r = serve_compile_request(phr->config, cs, run_text, run_size, cnts->id,
                                     run_id, 0 /* submit_id */, phr->user_id,
                                     variant,
                                     phr->locale_id, 0,
                                     lang->src_sfx,
                                     0,
                                     -1, 0, 0, prob, lang, 0, &run_uuid,
                                     NULL /* judge_uuid */,
                                     store_flags,
                                     0 /* rejudge_flag */,
                                     phr->is_job,
                                     0 /* not_ok_is_cf */,
                                     user,
                                     &new_run)) < 0) {
        serve_report_check_failed(ejudge_config, cnts, cs, run_id, serve_err_str(r));
      }
    }
  } else if (prob->manual_checking > 0) {
    // manually tested outputs
    if (prob->check_presentation <= 0) {
      serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                        "submit", "ok", RUN_ACCEPTED,
                        "  This problem is checked manually");
      run_change_status_4(cs->runlog_state, run_id, RUN_ACCEPTED, &new_run);
      serve_notify_run_update(phr->config, cs, &new_run);
    } else {
      serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                        "submit", "ok", RUN_COMPILING, NULL);
      if (prob->style_checker_cmd && prob->style_checker_cmd[0]) {
        if ((r = serve_compile_request(phr->config, cs, run_text, run_size, cnts->id,
                                       run_id, 0 /* submit_id */, phr->user_id,
                                       variant,
                                       0 /* locale_id */, 1 /* output_only*/,
                                       mime_type_get_suffix(mime_type),
                                       1 /* style_check_only */,
                                       0 /* accepting_mode */,
                                       0 /* priority_adjustment */,
                                       0 /* notify flag */,
                                       prob, NULL /* lang */,
                                       0 /* no_db_flag */, &run_uuid,
                                       NULL /* judge_uuid */,
                                       store_flags,
                                       0 /* rejudge_flag */,
                                       phr->is_job,
                                       0 /* not_ok_is_cf */,
                                       user,
                                       &new_run)) < 0) {
          serve_report_check_failed(ejudge_config, cnts, cs, run_id, serve_err_str(r));
        }
      } else {
        if (serve_run_request(phr->config, cs, cnts, stderr, run_text, run_size,
                              cnts->id, run_id,
                              0 /* submit_id */,
                              phr->user_id, prob->id, 0, variant, 0,
                              -1, /* judge_id */
                              NULL, /* judge_uuid */
                              -1, 0,
                              mime_type, 0, phr->locale_id, 0, 0, 0, &run_uuid,
                              0 /* rejudge_flag */, 0 /* zip_mode */,
                              store_flags,
                              0 /* not_ok_is_cf */,
                              NULL, 0,
                              &new_run,
                              NULL /* src_text */,
                              0 /* src_size */) < 0)
          FAIL(NEW_SRV_ERR_DISK_WRITE_ERROR);
      }
    }
  } else {
    if (prob->disable_auto_testing > 0
        || (prob->disable_testing > 0 && prob->enable_compilation <= 0)) {
      serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                        "submit", "ok", RUN_PENDING,
                        "  Testing disabled for this problem");
      run_change_status_4(cs->runlog_state, run_id, RUN_PENDING, &new_run);
      serve_notify_run_update(phr->config, cs, &new_run);
    } else {
      problem_xml_t px = NULL;
      if (prob->variant_num > 0 && prob->xml.a && variant > 0) {
        px = prob->xml.a[variant -  1];
      } else if (prob->variant_num <= 0) {
        px = prob->xml.p;
      }
      if (px && px->ans_num > 0) {
        struct run_entry re;
        run_get_entry(cs->runlog_state, run_id, &re);
        serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                        "submit", "ok", RUN_RUNNING, NULL);
        serve_judge_built_in_problem(extra, ejudge_config, cs, cnts, run_id,
                                     1 /* judge_id */,
                                     NULL, /* judge_uuid */
                                     variant, cs->accepting_mode, &re,
                                     prob, px, phr->user_id, &phr->ip,
                                     phr->ssl_flag);
      } else if (prob->style_checker_cmd && prob->style_checker_cmd[0]) {
        serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                        "submit", "ok", RUN_COMPILING, NULL);
        if ((r = serve_compile_request(phr->config, cs, run_text, run_size, cnts->id,
                                       run_id, 0 /* submit_id */, phr->user_id,
                                       variant,
                                       0 /* locale_id */, 1 /* output_only*/,
                                       mime_type_get_suffix(mime_type),
                                       1 /* style_check_only */,
                                       0 /* accepting_mode */,
                                       0 /* priority_adjustment */,
                                       0 /* notify flag */,
                                       prob, NULL /* lang */,
                                       0 /* no_db_flag */, &run_uuid,
                                       NULL /* judge_uuid */,
                                       store_flags,
                                       0 /* rejudge_flag */,
                                       phr->is_job,
                                       0 /* not_ok_is_cf */,
                                       user,
                                       &new_run)) < 0) {
          serve_report_check_failed(ejudge_config, cnts, cs, run_id, serve_err_str(r));
        }
      } else {
        serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                        "submit", "ok", RUN_RUNNING, NULL);
        if (serve_run_request(phr->config, cs, cnts, stderr, run_text, run_size,
                              cnts->id, run_id,
                              0 /* submit_id */,
                              phr->user_id, prob->id, 0, variant, 0,
                              -1, /* judge_id */
                              NULL, /* judge_uuid */
                              -1, 0,
                              mime_type, 0, phr->locale_id, 0, 0, 0, &run_uuid,
                              0 /* rejudge_flag */, 0 /* zip_mode */,
                              store_flags,
                              0 /* not_ok_is_cf */,
                              NULL, 0,
                              &new_run,
                              NULL /* src_text */,
                              0 /* src_size */) < 0)
          FAIL(NEW_SRV_ERR_DISK_WRITE_ERROR);
      }
    }
  }
  fprintf(fout, "%d\n", run_id);

 cleanup:
  if (ans_f) fclose(ans_f);
  xfree(run_text_2);
  xfree(utf8_str);
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

  if (!(r = hr_cgi_param(phr, "file", &s)))
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
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    phr->client_state->ops->set_destroy_callback(phr->client_state, cnts->id, ns_client_destroy_callback);
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

static const unsigned char has_failed_test_num[RUN_STATUS_SIZE] =
{
  [RUN_RUN_TIME_ERR]     = 1,
  [RUN_TIME_LIMIT_ERR]   = 1,
  [RUN_PRESENTATION_ERR] = 1,
  [RUN_WRONG_ANSWER_ERR] = 1,
  [RUN_CHECK_FAILED]     = 1,
  [RUN_MEM_LIMIT_ERR]    = 1,
  [RUN_SECURITY_ERR]     = 1,
  [RUN_SYNC_ERR]         = 1,
  [RUN_WALL_TIME_LIMIT_ERR] = 1,
};
static const unsigned char has_passed_tests[RUN_STATUS_SIZE] =
{
  [RUN_OK]               = 1,
  [RUN_PARTIAL]          = 1,
  [RUN_ACCEPTED]         = 1,
};
static const unsigned char has_olympiad_score[RUN_STATUS_SIZE] =
{
  [RUN_OK]               = 1,
  [RUN_PARTIAL]          = 1,
};
static const unsigned char has_kirov_score[RUN_STATUS_SIZE] =
{
  [RUN_OK]               = 1,
  [RUN_COMPILE_ERR]      = 1,
  [RUN_PARTIAL]          = 1,
  [RUN_ACCEPTED]         = 1,
  [RUN_STYLE_ERR]        = 1,
  [RUN_REJECTED]         = 1,
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
        int first_run_set,
        int first_run,
        int last_run_set,
        int last_run,
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
  int rid, attempts, disq_attempts, ce_attempts, prev_successes;
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
  time_t effective_time;
  time_t *p_eff_time;

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
  env.rbegin = run_get_first(cs->runlog_state);
  env.rtotal = run_get_total(cs->runlog_state);
  run_get_header(cs->runlog_state, &env.rhead);
  struct timeval tv;
  gettimeofday(&tv, NULL);
  env.cur_time = tv.tv_sec;
  env.cur_time_us = tv.tv_sec * 1000000LL + tv.tv_usec;
  env.rentries = run_get_entries_ptr(cs->runlog_state);

  XCALLOC(match_idx, (env.rtotal + 1));
  match_tot = 0;
  transient_tot = 0;

  for (i = env.rbegin; i < env.rtotal; i++) {
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

  XCALLOC(list_idx, (env.rtotal + 1));
  list_tot = 0;

  if (!first_run_set) {
    first_run_set = u->prev_first_run_set;
    first_run = u->prev_first_run;
  }
  if (!last_run_set) {
    last_run_set = u->prev_last_run_set;
    last_run = u->prev_last_run;
  }
  u->prev_first_run_set = first_run_set;
  u->prev_first_run = first_run;
  u->prev_last_run_set = last_run_set;
  u->prev_last_run = last_run;

  if (!first_run_set && !last_run_set) {
    // last 20 in the reverse order
    first_run = -1;
    last_run = -20;
  } else if (!first_run_set) {
    // from the last in the reverse order
    first_run = -1;
  } else if (!last_run_set) {
    // 20 in the reverse order
    last_run = first_run - 20 + 1;
    if (first_run >= 0 && last_run < 0) last_run = 0;
  }

  if (first_run >= match_tot) {
    first_run = match_tot - 1;
    if (first_run < 0) first_run = 0;
  }
  if (first_run < 0) {
    first_run = match_tot + first_run;
    if (first_run < 0) first_run = 0;
  }
  if (last_run >= match_tot) {
    last_run = match_tot - 1;
    if (last_run < 0) last_run = 0;
  }
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
    ASSERT(rid >= env.rbegin && rid < env.rtotal);
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
    snprintf(sha1_buf, sizeof(sha1_buf), "%s", unparse_sha1(pe->h.sha1));
    csv_rec[F_SHA1] = sha1_buf;
    if (pe->locale_id >= 0) {
      snprintf(locale_id_buf, sizeof(locale_id_buf), "%d", pe->locale_id);
      csv_rec[F_LOCALE_ID] = locale_id_buf;
    }
    if (pe->pages > 0) {
      snprintf(pages_buf, sizeof(pages_buf), "%d", pe->pages);
      csv_rec[F_PAGES] = pages_buf;
    }
    if (pe->j.judge_id > 0) {
      snprintf(judge_id_buf, sizeof(judge_id_buf), "%d", pe->j.judge_id);
      csv_rec[F_JUDGE_ID] = judge_id_buf;
    }

    snprintf(prob_id_buf, sizeof(prob_id_buf), "%d", pe->prob_id);
    csv_rec[F_PROB_ID] = prob_id_buf;

    prob = NULL;
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

    if (global->score_system == SCORE_ACM) {
      if (has_failed_test_num[pe->status]) {
        snprintf(failed_test_buf, sizeof(failed_test_buf), "%d", pe->test);
        if (pe->passed_mode > 0) {
          csv_rec[F_PASSED_TESTS] = failed_test_buf;
        } else {
          csv_rec[F_FAILED_TEST] = failed_test_buf;
        }
      }
      write_csv_record(fout, F_TOTAL_FIELDS, csv_rec);
      continue;
    } else if (global->score_system == SCORE_MOSCOW) {
      if (has_failed_test_num[pe->status]) {
        snprintf(failed_test_buf, sizeof(failed_test_buf), "%d", pe->test);
        if (pe->passed_mode > 0) {
          csv_rec[F_PASSED_TESTS] = failed_test_buf;
        } else {
          csv_rec[F_FAILED_TEST] = failed_test_buf;
        }
      }
      snprintf(score_buf, sizeof(score_buf), "%d", pe->score);
      csv_rec[F_TOTAL_SCORE] = score_buf;
      csv_rec[F_BASE_SCORE] = score_buf;
      write_csv_record(fout, F_TOTAL_FIELDS, csv_rec);
      continue;
    } else if (global->score_system == SCORE_OLYMPIAD) {
      if (pe->passed_mode > 0 && pe->test >= 0) {
        snprintf(passed_tests_buf, sizeof(passed_tests_buf), "%d", pe->test);
        csv_rec[F_PASSED_TESTS] = passed_tests_buf;
      } else {
        if (has_failed_test_num[pe->status]) {
          snprintf(failed_test_buf, sizeof(failed_test_buf), "%d", pe->test);
          csv_rec[F_FAILED_TEST] = failed_test_buf;
        }
        if (has_passed_tests[pe->status]) {
          snprintf(passed_tests_buf, sizeof(passed_tests_buf), "%d", pe->test);
          csv_rec[F_PASSED_TESTS] = passed_tests_buf;
        }
      }
      if (has_olympiad_score[pe->status]) {
        snprintf(score_buf, sizeof(score_buf), "%d", pe->score);
        csv_rec[F_TOTAL_SCORE] = score_buf;
        csv_rec[F_BASE_SCORE] = score_buf;
      }
      write_csv_record(fout, F_TOTAL_FIELDS, csv_rec);
      continue;
    } else if (global->score_system == SCORE_KIROV) {
      if (!has_kirov_score[pe->status]) {
        write_csv_record(fout, F_TOTAL_FIELDS, csv_rec);
        continue;
      }

      if (pe->passed_mode > 0) {
        snprintf(passed_tests_buf, sizeof(passed_tests_buf), "%d", pe->test);
      } else {
        snprintf(passed_tests_buf, sizeof(passed_tests_buf), "%d", pe->test - 1);
      }
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

      attempts = 0; disq_attempts = 0; ce_attempts = 0;
      effective_time = 0; p_eff_time = NULL;
      if (prob->enable_submit_after_reject > 0) p_eff_time = &effective_time;
      if (global->score_system == SCORE_KIROV && !pe->is_hidden) {
        run_get_attempts(cs->runlog_state, rid, &attempts, &disq_attempts, &ce_attempts,
                         p_eff_time,
                         prob->ignore_compile_errors, prob->compile_error_penalty);
      }

      orig_score = pe->score;
      if (pe->status == RUN_OK && !prob->variable_full_score)
        orig_score = prob->full_score;
      snprintf(base_score_buf, sizeof(base_score_buf), "%d", orig_score);
      csv_rec[F_BASE_SCORE] = base_score_buf;
      score = calc_kirov_score(0, 0, start_time, 0, 0, 0, pe, prob, attempts, disq_attempts, ce_attempts,
                               prev_successes, &date_penalty, 0, effective_time);
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

  free(list_idx);
  free(match_idx);
  return 0;
}

static int
cmd_dump_master_runs(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0, first_run_set = 0, first_run = 0, last_run_set = 0, last_run = 0;
  const unsigned char *filter_expr = 0;

  if (phr->role != USER_ROLE_ADMIN && phr->role != USER_ROLE_JUDGE)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (hr_cgi_param(phr, "filter_expr", &filter_expr) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  if (!filter_expr) filter_expr = "";

  if (hr_cgi_param_int_opt_2(phr, "first_run", &first_run, &first_run_set) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);

  if (hr_cgi_param_int_opt_2(phr, "last_run", &last_run, &last_run_set) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);

  retval = do_dump_master_runs(fout, phr, cnts, extra,
                               first_run_set, first_run, last_run_set, last_run, filter_expr);

 cleanup:
  return retval;
}

static int
cmd_force_start_virtual(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  int retval = 0;
  int user_id_2 = 0;
  int run_id;
  struct timeval tt;

  if (phr->role != USER_ROLE_ADMIN
      || opcaps_check(phr->caps, OPCAP_CONTROL_CONTEST) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (!global->is_virtual)
    FAIL(NEW_SRV_ERR_NOT_VIRTUAL);
  if (hr_cgi_param_int(phr, "user_id_2", &user_id_2) < 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);
  if (!teamdb_lookup(cs->teamdb_state, user_id_2))
    FAIL(NEW_SRV_ERR_INV_USER_ID);

  gettimeofday(&tt, 0);
  run_id = run_virtual_start(cs->runlog_state, user_id_2,
                             tt.tv_sec, 0, 0, tt.tv_usec * 1000);
  if (run_id < 0) FAIL(NEW_SRV_ERR_VIRTUAL_START_FAILED);
  if (run_is_virtual_legacy_mode(cs->runlog_state)) {
    serve_move_files_to_insert_run(cs, run_id);
  }

 cleanup:
  return retval;
}

static int
cmd_reload_server_2(
        FILE *fout,
        struct http_request_info *phr)
{
  int retval = -NEW_SRV_ERR_NOT_SUPPORTED, r;
  const struct contest_desc *cnts = NULL;
  struct contest_extra *extra = NULL;
  const unsigned char *login = NULL;
  const unsigned char *password = NULL;
  const unsigned char *ejudge_login = NULL;
  opcap_t caps = 0LL;

  phr->allow_empty_output = 1;

  if (phr->contest_id < 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts)
    return -NEW_SRV_ERR_INV_CONTEST_ID;
  if (!cnts->managed)
    return -NEW_SRV_ERR_INV_CONTEST_ID;
  extra = ns_try_contest_extra(phr->contest_id);

  //fprintf(fout, "contest_id: %d\n", phr->contest_id);

  if (!extra) return 0;
  if (!extra->serve_state) return 0;

  if (hr_cgi_param(phr, "login", &login) <= 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (hr_cgi_param(phr, "password", &password) <= 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (!strcmp(login, "__unix__") && !strcmp(password, "__unix__")) {
    if (!phr->client_state) FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    /*
    fprintf(fout,
            "peer_pid: %d\n"
            "peer_uid: %d\n"
            "peer_gid: %d\n",
            phr->client_state->peer_pid,
            phr->client_state->peer_uid,
            phr->client_state->peer_gid);
    */

    int peer_uid = phr->client_state->ops->get_peer_uid(phr->client_state);
    if (peer_uid <= 0) FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

    struct passwd *pwd = getpwuid(peer_uid);
    if (!pwd || !pwd->pw_name) FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    //fprintf(fout, "system login: %s\n", pwd->pw_name);
    if (!ejudge_config) FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    ejudge_login = ejudge_cfg_user_map_find(ejudge_config, pwd->pw_name);
    if (!ejudge_login) {
      fprintf(stderr, "no system user %s is mapped in <user_map> in ejudge.xml\n", pwd->pw_name);
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    }
    //fprintf(fout, "ejudge login: %s\n", ejudge_login);
  } else {
    if (ns_open_ul_connection(phr->fw_state) < 0)
      FAIL(NEW_SRV_ERR_USERLIST_SERVER_DOWN);

    r = userlist_clnt_priv_login(ul_conn, ULS_PRIV_CHECK_PASSWORD,
                                 &phr->ip, phr->client_key,
                                 phr->ssl_flag, 0,
                                 0, 0, login,
                                 password, &phr->user_id,
                                 &phr->session_id,
                                 &phr->client_key,
                                 0, &phr->name);
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
    ejudge_login = login;
    //fprintf(fout, "user_id: %d\nname: %s\n", phr->user_id, phr->name);
  }

  if (ejudge_cfg_opcaps_find(ejudge_config, ejudge_login, &caps) < 0) {
    if (opcaps_find(&cnts->capabilities, ejudge_login, &caps) < 0) {
      fprintf(stderr, "unload_contest_2: %s: ejudge.xml->no caps, contest.xml->no caps\n", ejudge_login);
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    }
    if (opcaps_check(caps, OPCAP_UNLOAD_CONTEST) < 0) {
      fprintf(stderr, "unload_contest_2: %s: ejudge.xml->no caps, contest.xml->no cap\n", ejudge_login);
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    }
  } else if (opcaps_check(caps, OPCAP_UNLOAD_CONTEST) < 0) {
    if (opcaps_find(&cnts->capabilities, ejudge_login, &caps) < 0) {
      fprintf(stderr, "unload_contest_2: %s: ejudge.xml->no cap, contest.xml->no caps\n", ejudge_login);
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    }
    if (opcaps_check(caps, OPCAP_UNLOAD_CONTEST) < 0) {
      fprintf(stderr, "unload_contest_2: %s: ejudge.xml->no cap, contest.xml->no cap\n", ejudge_login);
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    }
  }

  info("unload_contest_2: %s: %d: contest unload", ejudge_login, phr->contest_id);
  if (extra) {
    extra->last_access_time = 0;
  }
  retval = 0;

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
  [NEW_SRV_ACTION_DUMP_LANGUAGES] = cmd_dump_languages,
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
  [NEW_SRV_ACTION_GET_CONTEST_STATUS] = cmd_operation_2,
  [NEW_SRV_ACTION_GET_CONTEST_SCHED] = cmd_operation_2,
  [NEW_SRV_ACTION_GET_CONTEST_DURATION] = cmd_operation_2,
  [NEW_SRV_ACTION_GET_CONTEST_DESCRIPTION] = cmd_operation_2,
  [NEW_SRV_ACTION_SUBMIT_RUN] = cmd_submit_run,
  [NEW_SRV_ACTION_UPLOAD_RUNLOG_XML_2] = cmd_import_xml_runs,
  [NEW_SRV_ACTION_DUMP_MASTER_RUNS] = cmd_dump_master_runs,
  [NEW_SRV_ACTION_DUMP_REPORT] = cmd_run_operation,
  [NEW_SRV_ACTION_FULL_UPLOAD_RUNLOG_XML] = cmd_import_xml_runs,
  [NEW_SRV_ACTION_RELOAD_SERVER] = cmd_operation,
  [NEW_SRV_ACTION_RELOAD_SERVER_ALL] = cmd_operation,
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
  [NEW_SRV_ACTION_FORCE_START_VIRTUAL] = cmd_force_start_virtual,
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

  if (phr->action == NEW_SRV_ACTION_RELOAD_SERVER_2)
    return cmd_reload_server_2(fout, phr);

  if (ns_open_ul_connection(phr->fw_state) < 0)
    return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;

  if ((r = userlist_clnt_get_cookie(ul_conn, ULS_FETCH_COOKIE,
                                    &phr->ip, phr->ssl_flag,
                                    phr->session_id,
                                    phr->client_key,
                                    &phr->user_id, &phr->contest_id,
                                    &phr->locale_id, 0, &phr->role, 0, 0, 0,
                                    NULL /* p_passwd_method */,
                                    NULL /* p_is_ws */,
                                    NULL /* p_is_job */,
                                    NULL /* p_expire */,
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
  if (!cnts->managed)
    return -NEW_SRV_ERR_INV_CONTEST_ID;
  extra = ns_get_contest_extra(cnts, phr->config);
  ASSERT(extra);

  if (phr->role < 0 || phr->role >= USER_ROLE_LAST)
    return -NEW_SRV_ERR_INV_ROLE;

  // analyze IP limitations
  if (phr->role == USER_ROLE_ADMIN) {
    if (!contests_check_master_ip(phr->contest_id, &phr->ip, phr->ssl_flag))
      return -NEW_SRV_ERR_PERMISSION_DENIED;
  } else if (phr->role == USER_ROLE_CONTESTANT) {
    if (!contests_check_team_ip(phr->contest_id, &phr->ip, phr->ssl_flag))
      return -NEW_SRV_ERR_PERMISSION_DENIED;
  } else {
    if (!contests_check_judge_ip(phr->contest_id, &phr->ip, phr->ssl_flag))
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
    if (cnts->closed)
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
  if (serve_state_load_contest(extra, ejudge_config, phr->contest_id,
                               ul_conn,
                               &callbacks,
                               0, 0,
                               ns_load_problem_plugin) < 0) {
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
  ns_check_contest_events(extra, extra->serve_state, cnts);
  phr->allow_empty_output = 1;

  if (phr->action > 0 && phr->action < NEW_SRV_ACTION_LAST
      && cmd_actions_table[phr->action]) {
    return (*cmd_actions_table[phr->action])(fout, phr, cnts, extra);
  } else {
    return -NEW_SRV_ERR_INV_ACTION;
  }
}
