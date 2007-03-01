/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2007 Alexander Chernov <cher@ejudge.ru> */

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
#include "settings.h"
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
    r = userlist_clnt_team_login(ul_conn, ULS_TEAM_CHECK_USER,
                                 phr->ip, phr->ssl_flag, phr->contest_id,
                                 phr->locale_id, login, password,
                                 &phr->user_id, &phr->session_id,
                                 0, &phr->name);
  } else {
    r = userlist_clnt_priv_login(ul_conn, ULS_PRIV_CHECK_USER,
                                 phr->ip, phr->ssl_flag, phr->contest_id,
                                 phr->locale_id, 0, phr->role, login,
                                 password, &phr->user_id, &phr->session_id,
                                 0, 0, &phr->name);
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
cmd_operation(
	FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;

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
    serve_judge_suspended(cs, phr->user_id, phr->ip, phr->ssl_flag);
    break;
  case NEW_SRV_ACTION_HAS_TRANSIENT_RUNS:
    if (serve_count_transient_runs(cs) > 0)
      return -NEW_SRV_ERR_TRANSIENT_RUNS;
    break;
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
  size_t msg_len = 0;

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
    if (fwrite(msg_txt, 1, msg_len, fout) != msg_len)
      FAIL(NEW_SRV_ERR_WRITE_ERROR);
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
      if ((variant = find_variant(cs, phr->user_id, prob->id)) <= 0)
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
        if ((variant = find_variant(cs, phr->user_id, prob->id)) <= 0)
          FAIL(NEW_SRV_ERR_VARIANT_UNASSIGNED);
      } else {
        if (parse_int(s, &variant) < 0 || variant < 0
            || variant > prob->variant_num)
          FAIL(NEW_SRV_ERR_INV_VARIANT);
        if (!variant && (variant=find_variant(cs, phr->user_id, prob->id)) <= 0)
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
                                lang->compiler_env, -1, 0) < 0)
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
};

/* Run information structure:
 * [0]  run_id
 * [1]  "H", if hidden
 * [2]  "I", if imported
 * [3]  time
 * [4]  nsec
 * [5]  duration
 * [6]  size
 * [7]  1, if IPv6, 0, if IPv4
 * [8]  IP
 * [9]  ssl_flag
 * [10] user_id
 * [11] user_login
 * [12] "I", if user invisible
 * [13] "B", if user banned
 * [14] "L", if user locked
 * [15] prob_id
 * [16] prob_short_name
 * [17] variant_actual
 * [18] variant_db
 * [19] lang_id
 * [20] lang_short_name
 * [21] mime_type
 * [22] source_suffix
 * [23] status_short
 * [24] failed test
 * [25] passed tests
 * [26] total_score
 * [27] orig_score
 * [28] prev_attempts
 * [29] attempt_penalty
 * [30] prev_disqualified
 * [31] disq_penalty
 * [32] time_penalty
 * [33] prev_successes
 * [34] prev_success_bonus
 * [35] score_adjustment
 * [36] is_after_ok
 * [37] is_latest
 * [38] sha1
 * [39] locale_id
 * [40] is_readonly
 * [41] pages
 * [42] judge_id
 */

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
  const unsigned char *run_date = 0;
  unsigned char dur_str[128];
  int duration, dur_sec, dur_min, dur_hour, user_flags, variant;
  int score, score_bonus, orig_score, date_penalty;
  const unsigned char *user_login, *user_invisible_flag;
  const unsigned char *user_banned_flag, *user_locked_flag;
  const unsigned char *run_hidden_flag, *run_imported_flag;
  const unsigned char *prob_short_name;
  const unsigned char *lang_short_name, *source_suffix, *mime_type_str;
  unsigned char variant_buf[128], db_variant_buf[128];
  unsigned char failed_test_buf[128], passed_tests_buf[128], score_buf[128];
  unsigned char prev_successes_buf[128], score_bonus_buf[128];
  unsigned char attempts_buf[128], attempts_penalty_buf[128];
  unsigned char disq_attempts_buf[128], disq_attempts_penalty_buf[128];
  unsigned char date_penalty_buf[128], score_adj_buf[128];

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

  // table header
  fputs("run_id"
        ";is_hidden"
        ";is_imported"
        ";time"
        ";nsec"
        ";duration"
        ";size"
        ";is_ipv6"
        ";IP"
        ";ssl_flag"
        ";user_id"
        ";user_login"
        ";is_user_invisible"
        ";is_user_banned"
        ";is_user_locked"
        ";prob_id"
        ";prob_short_name"
        ";variant_actual"
        ";variant_db"
        ";lang_id"
        ";lang_short_name"
        ";mime_type"
        ";source_suffix"
        ";status_short"
        ";failed_test"
        ";passed_tests"
        ";total_score"
        ";orig_score"
        ";prev_attempts"
        ";attempt_penalty"
        ";prev_disqualified"
        ";disq_penalty"
        ";time_penalty"
        ";prev_successes"
        ";success_bonus"
        ";score_adjustment"
        ";is_after_ok"
        ";is_latest"
        ";sha1"
        ";locale_id"
        ";is_readonly"
        ";pages"
        ";judge_id"
        "\n", fout);

  for (i = 0; i < list_tot; i++) {
    rid = list_idx[i];
    ASSERT(rid >= 0 && rid < env.rtotal);
    pe = &env.rentries[rid];

    run_status_to_str_short(statstr, sizeof(statstr), pe->status);

    if (!run_is_valid_status(pe->status)) {
      fprintf(fout, "%d;;;;;;;;;;;;;;;;;;;;;;;%d;;;;;;;;;;;;;;;;;;;\n",
              rid, pe->status);
      continue;
    }
    if (pe->status == RUN_EMPTY) {
      fprintf(fout, "%d;;;;;;;;;;;;;;;;;;;;;;;%s;;;;;;;;;;;;;;;;;;;\n",
              rid, statstr);
      continue;
    }

    run_date = xml_unparse_date(pe->time);
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

    if ((user_login = teamdb_get_login(cs->teamdb_state, pe->user_id))) {
      user_flags = teamdb_get_flags(cs->teamdb_state, pe->user_id);
      user_invisible_flag = "";
      user_banned_flag = "";
      user_locked_flag = "";
      if ((user_flags & TEAM_INVISIBLE)) user_invisible_flag = "I";
      if ((user_flags & TEAM_BANNED)) user_banned_flag = "B";
      if ((user_flags & TEAM_LOCKED)) user_banned_flag = "L";
    } else {
      user_login = "";
      user_invisible_flag = "";
      user_banned_flag = "";
      user_locked_flag = "";
    }

    if (pe->status == RUN_VIRTUAL_START || pe->status == RUN_VIRTUAL_STOP) {
      fprintf(fout, "%d;;"
              ";%s;%09d;%s;"
              ";%d;%s;%d"
              ";%d;%s;%s;%s;%s;;;;;;;;"
              ";%s;;;;;;;;;;;;;;;;;;;\n",
              rid, run_date, pe->nsec, dur_str,
              pe->ipv6_flag, xml_unparse_ip(pe->a.ip), pe->ssl_flag,
              pe->user_id, user_login, user_invisible_flag, user_banned_flag,
              user_locked_flag, statstr);
      continue;
    }

    run_hidden_flag = "";
    if (pe->is_hidden) run_hidden_flag = "H";
    run_imported_flag = "";
    if (pe->is_imported) run_imported_flag = "I";

    if (pe->prob_id > 0 && pe->prob_id <= cs->max_prob
        && (prob = cs->probs[pe->prob_id])) {
      if (prob->variant_num > 0) {
        snprintf(db_variant_buf, sizeof(db_variant_buf), "%d", pe->variant);
        variant = find_variant(cs, pe->user_id, pe->prob_id);
        if (variant < 0) variant = 0;
        snprintf(variant_buf, sizeof(variant_buf), "%d", variant);
      } else {
        variant_buf[0] = 0;
        db_variant_buf[0] = 0;
      }
    } else {
      prob_short_name = "";
      variant_buf[0] = 0;
      db_variant_buf[0] = 0;
    }

    if (pe->lang_id > 0 && pe->lang_id <= cs->max_lang
        && (lang = cs->langs[pe->lang_id])) {
      lang_short_name = lang->short_name;
      source_suffix = lang->src_sfx;
      mime_type_str = "";
    } else if (!pe->lang_id) {
      lang_short_name = "";
      mime_type_str = mime_type_get_type(pe->mime_type);
      source_suffix = mime_type_get_suffix(pe->mime_type);
    } else {
      lang_short_name = "";
      mime_type_str = "";
      source_suffix = "";
    }

    if (global->score_system_val == SCORE_ACM) {
      failed_test_buf[0] = 0;
      if (has_failed_test_num[pe->status])
        snprintf(failed_test_buf, sizeof(failed_test_buf), "%d", pe->test);
      fprintf(fout,
              "%d;%s;%s"
              ";%s;%09d;%s;%u"
              ";%d;%s;%d"
              ";%d;%s;%s;%s;%s"
              ";%d;%s;%s;%s"
              ";%d;%s;%s;%s"
              ";%s;%s;;;;;;;;;;;"
              ";"               /* is_after_ok */
              ";"               /* is_latest */
              ";%s;%d;%d;%d;%d\n",
              rid, run_hidden_flag, run_imported_flag,
              run_date, pe->nsec, dur_str, pe->size,
              pe->ipv6_flag, xml_unparse_ip(pe->a.ip), pe->ssl_flag,
              pe->user_id, user_login,
              user_invisible_flag, user_banned_flag, user_locked_flag,
              pe->prob_id, prob_short_name, variant_buf, db_variant_buf,
              pe->lang_id, lang_short_name, mime_type_str, source_suffix,
              statstr, failed_test_buf,
              unparse_sha1(pe->sha1), pe->locale_id, pe->is_readonly,
              pe->pages, pe->judge_id);
    } else if (global->score_system_val == SCORE_MOSCOW) {
      failed_test_buf[0] = 0;
      if (has_failed_test_num[pe->status])
        snprintf(failed_test_buf, sizeof(failed_test_buf), "%d", pe->test);
      fprintf(fout,
              "%d;%s;%s"
              ";%s;%09d;%s;%u"
              ";%d;%s;%d"
              ";%d;%s;%s;%s;%s"
              ";%d;%s;%s;%s"
              ";%d;%s;%s;%s"
              ";%s;%s;;%d;%d;;;;;;;;"
              ";"               /* is_after_ok */
              ";"               /* is_latest */
              ";%s;%d;%d;%d;%d\n",
              rid, run_hidden_flag, run_imported_flag,
              run_date, pe->nsec, dur_str, pe->size,
              pe->ipv6_flag, xml_unparse_ip(pe->a.ip), pe->ssl_flag,
              pe->user_id, user_login,
              user_invisible_flag, user_banned_flag, user_locked_flag,
              pe->prob_id, prob_short_name, variant_buf, db_variant_buf,
              pe->lang_id, lang_short_name, mime_type_str, source_suffix,
              statstr, failed_test_buf, pe->score, pe->score,
              unparse_sha1(pe->sha1), pe->locale_id, pe->is_readonly,
              pe->pages, pe->judge_id);
    } else if (global->score_system_val == SCORE_OLYMPIAD) {
      failed_test_buf[0] = 0;
      if (has_failed_test_num[pe->status])
        snprintf(failed_test_buf, sizeof(failed_test_buf), "%d", pe->test);
      passed_tests_buf[0] = 0;
      if (has_passed_tests[pe->status]) {
        snprintf(passed_tests_buf, sizeof(passed_tests_buf), "%d", pe->test);
      }
      score_buf[0] = 0;
      if (has_olympiad_score[pe->status]) {
        snprintf(score_buf, sizeof(score_buf), "%d", pe->score);
      }
      fprintf(fout,
              "%d;%s;%s"
              ";%s;%09d;%s;%u"
              ";%d;%s;%d"
              ";%d;%s;%s;%s;%s"
              ";%d;%s;%s;%s"
              ";%d;%s;%s;%s"
              ";%s;%s;%s"
              ";%s;%s;;;;;;;;"
              ";"               /* is_after_ok */
              ";"               /* is_latest */
              ";%s;%d;%d;%d;%d\n",
              rid, run_hidden_flag, run_imported_flag,
              run_date, pe->nsec, dur_str, pe->size,
              pe->ipv6_flag, xml_unparse_ip(pe->a.ip), pe->ssl_flag,
              pe->user_id, user_login,
              user_invisible_flag, user_banned_flag, user_locked_flag,
              pe->prob_id, prob_short_name, variant_buf, db_variant_buf,
              pe->lang_id, lang_short_name, mime_type_str, source_suffix,
              statstr, failed_test_buf, passed_tests_buf, score_buf, score_buf,
              unparse_sha1(pe->sha1), pe->locale_id, pe->is_readonly,
              pe->pages, pe->judge_id);
    } else if (global->score_system_val == SCORE_KIROV) {
      if (!has_kirov_score[pe->status]) {
        fprintf(fout,
                "%d;%s;%s"
                ";%s;%09d;%s;%u"
                ";%d;%s;%d"
                ";%d;%s;%s;%s;%s"
                ";%d;%s;%s;%s"
                ";%d;%s;%s;%s"
                ";%s;;;;;;;;;;;;"
                ";"               /* is_after_ok */
                ";"               /* is_latest */
                ";%s;%d;%d;%d;%d\n",
                rid, run_hidden_flag, run_imported_flag,
                run_date, pe->nsec, dur_str, pe->size,
                pe->ipv6_flag, xml_unparse_ip(pe->a.ip), pe->ssl_flag,
                pe->user_id, user_login,
                user_invisible_flag, user_banned_flag, user_locked_flag,
                pe->prob_id, prob_short_name, variant_buf, db_variant_buf,
                pe->lang_id, lang_short_name, mime_type_str, source_suffix,
                statstr,
                unparse_sha1(pe->sha1), pe->locale_id, pe->is_readonly,
                pe->pages, pe->judge_id);
        continue;
      }

      prev_successes = RUN_TOO_MANY;
      score_bonus = 0;
      prev_successes_buf[0] = 0;
      score_bonus_buf[0] = 0;
      if (pe->status == RUN_OK && !pe->is_hidden
          && prob && prob->score_bonus_total > 0) {
        if ((prev_successes = run_get_prev_successes(cs->runlog_state, rid))<0)
          prev_successes = RUN_TOO_MANY;
        if (prev_successes != RUN_TOO_MANY) {
          snprintf(prev_successes_buf, sizeof(prev_successes_buf),
                   "%d", prev_successes);
        }
        if (prev_successes >= 0 && prev_successes < prob->score_bonus_total)
          score_bonus = prob->score_bonus_val[prev_successes];
        snprintf(score_bonus_buf, sizeof(score_bonus_buf), "%d", score_bonus);
      }

      attempts = 0; disq_attempts = 0;
      if (global->score_system_val == SCORE_KIROV && !pe->is_hidden) {
        run_get_attempts(cs->runlog_state, rid, &attempts, &disq_attempts,
                         global->ignore_compile_errors);
      }

      orig_score = pe->score;
      if (pe->status == RUN_OK && !prob->variable_full_score)
        orig_score = prob->full_score;
      score = calc_kirov_score(0, 0, pe, prob, attempts, disq_attempts,
                               prev_successes, &date_penalty, 0);
      attempts_buf[0] = 0;
      if (attempts > 0)
        snprintf(attempts_buf, sizeof(attempts_buf), "%d", attempts);
      attempts_penalty_buf[0] = 0;
      if (attempts * prob->run_penalty != 0)
        snprintf(attempts_penalty_buf, sizeof(attempts_penalty_buf),
                 "%d", attempts * prob->run_penalty);
      disq_attempts_buf[0] = 0;
      if (disq_attempts > 0)
        snprintf(disq_attempts_buf, sizeof(disq_attempts_buf),
                 "%d", disq_attempts);
      disq_attempts_penalty_buf[0] = 0;
      if (disq_attempts * prob->disqualified_penalty != 0)
        snprintf(disq_attempts_penalty_buf, sizeof(disq_attempts_penalty_buf),
                 "%d", disq_attempts * prob->disqualified_penalty);
      date_penalty_buf[0] = 0;
      if (date_penalty != 0)
        snprintf(date_penalty_buf, sizeof(date_penalty_buf),
                 "%d", date_penalty);
      score_adj_buf[0] = 0;
      if (pe->score_adj != 0)
        snprintf(score_adj_buf, sizeof(score_adj_buf), "%d", pe->score_adj);
      fprintf(fout,
              "%d;%s;%s"
              ";%s;%09d;%s;%u"
              ";%d;%s;%d"
              ";%d;%s;%s;%s;%s"
              ";%d;%s;%s;%s"
              ";%d;%s;%s;%s"
              ";%s;;%d;%d;%d"
              ";%s;%s"
              ";%s;%s"
              ";%s"
              ";%s;%s"
              ";%s"
              ";"               /* is_after_ok */
              ";"               /* is_latest */
              ";%s;%d;%d;%d;%d\n",
              rid, run_hidden_flag, run_imported_flag,
              run_date, pe->nsec, dur_str, pe->size,
              pe->ipv6_flag, xml_unparse_ip(pe->a.ip), pe->ssl_flag,
              pe->user_id, user_login,
              user_invisible_flag, user_banned_flag, user_locked_flag,
              pe->prob_id, prob_short_name, variant_buf, db_variant_buf,
              pe->lang_id, lang_short_name, mime_type_str, source_suffix,
              statstr, pe->test, score, orig_score,
              attempts_buf, attempts_penalty_buf,
              disq_attempts_buf, disq_attempts_penalty_buf,
              date_penalty_buf,
              prev_successes_buf, score_bonus_buf,
              score_adj_buf,
              unparse_sha1(pe->sha1), pe->locale_id, pe->is_readonly,
              pe->pages, pe->judge_id);
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
                                    &phr->locale_id, 0, &phr->role,
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
