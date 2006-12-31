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
    r = userlist_clnt_team_login(ul_conn, ULS_CHECK_USER,
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
    if (run_write_xml(cs->runlog_state, cs, cnts, fout, 1,
                      cs->current_time) < 0)
      return -NEW_SRV_ERR_TRY_AGAIN;
    break;

  case NEW_SRV_ACTION_WRITE_XML_RUNS:
    if (run_write_xml(cs->runlog_state, cs, cnts, fout, 0,
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
  if (generic_read_file(&src_text, 0, &src_len, src_flags, 0, src_path, "") < 0)
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
