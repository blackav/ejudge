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

/*
 * Command reimplementation status:
    SRV_CMD_GET_ARCHIVE,                OK
    SRV_CMD_SHOW_CLAR,                  OK
    SRV_CMD_SHOW_SOURCE,                OK
    SRV_CMD_SHOW_REPORT,                OK
    SRV_CMD_SUBMIT_RUN,                 OK
    SRV_CMD_SUBMIT_CLAR,                OK
    SRV_CMD_TEAM_PAGE,                  OK
    SRV_CMD_MASTER_PAGE,                OK
    SRV_CMD_PRIV_STANDINGS,             OK
    SRV_CMD_VIEW_CLAR,                  OK
    SRV_CMD_VIEW_SOURCE,                OK
    SRV_CMD_VIEW_REPORT,                OK
    SRV_CMD_VIEW_USERS,                 OK
    SRV_CMD_PRIV_MSG,                   OK
    SRV_CMD_PRIV_REPLY,                 OK
    SRV_CMD_SUSPEND,                    OK
    SRV_CMD_RESUME,                     OK
    SRV_CMD_UPDATE_STAND,               OK
    SRV_CMD_RESET,                      OK
    SRV_CMD_START,                      OK
    SRV_CMD_STOP,                       OK
    SRV_CMD_REJUDGE_ALL,                OK
    SRV_CMD_REJUDGE_PROBLEM,            OK
    SRV_CMD_SCHEDULE,                   OK
    SRV_CMD_DURATION,                   OK
    SRV_CMD_EDIT_RUN,                   OK
    SRV_CMD_VIRTUAL_START,              OK
    SRV_CMD_VIRTUAL_STOP,               OK
    SRV_CMD_VIRTUAL_STANDINGS,          OK
    SRV_CMD_RESET_FILTER,               OK
    SRV_CMD_CLEAR_RUN,                  OK
    SRV_CMD_SQUEEZE_RUNS,               OK
    SRV_CMD_DUMP_RUNS,                  OK
    SRV_CMD_DUMP_STANDINGS,
    SRV_CMD_SET_JUDGING_MODE,           OK
    SRV_CMD_CONTINUE,                   OK
    SRV_CMD_WRITE_XML_RUNS,             OK
    SRV_CMD_IMPORT_XML_RUNS,            OK
    SRV_CMD_QUIT,                       OK
    SRV_CMD_EXPORT_XML_RUNS,            OK
    SRV_CMD_PRIV_SUBMIT_RUN,            OK
    SRV_CMD_TEST_SUSPEND,               OK
    SRV_CMD_TEST_RESUME,                OK
    SRV_CMD_JUDGE_SUSPENDED,            OK
    SRV_CMD_SET_ACCEPTING_MODE,         OK
    SRV_CMD_PRIV_PRINT_RUN,             OK
    SRV_CMD_PRINT_RUN,                  OK
    SRV_CMD_PRIV_DOWNLOAD_RUN,          OK
    SRV_CMD_PRINT_SUSPEND,              OK
    SRV_CMD_PRINT_RESUME,               OK
    SRV_CMD_COMPARE_RUNS,               OK
    SRV_CMD_UPLOAD_REPORT,
    SRV_CMD_REJUDGE_BY_MASK,            OK
    SRV_CMD_NEW_RUN_FORM,               OK
    SRV_CMD_NEW_RUN,                    OK
    SRV_CMD_VIEW_TEAM,                  OK
    SRV_CMD_SET_TEAM_STATUS,            OK
    SRV_CMD_ISSUE_WARNING,              OK
    SRV_CMD_SOFT_UPDATE_STAND,          OK
    SRV_CMD_PRIV_DOWNLOAD_REPORT,       OK
    SRV_CMD_PRIV_DOWNLOAD_TEAM_REPORT,
    SRV_CMD_DUMP_MASTER_RUNS,           OK
    SRV_CMD_RESET_CLAR_FILTER,          OK
    SRV_CMD_HAS_TRANSIENT_RUNS,         OK
    SRV_CMD_GET_TEST_SUSPEND,
    SRV_CMD_VIEW_TEST_INPUT,            OK
    SRV_CMD_VIEW_TEST_OUTPUT,           OK
    SRV_CMD_VIEW_TEST_ANSWER,           OK
    SRV_CMD_VIEW_TEST_ERROR,            OK
    SRV_CMD_VIEW_TEST_CHECKER,          OK
    SRV_CMD_VIEW_TEST_INFO,             OK
    SRV_CMD_VIEW_AUDIT_LOG,             OK
    SRV_CMD_DUMP_PROBLEMS,              OK
    SRV_CMD_GET_CONTEST_TYPE,           OK
    SRV_CMD_SUBMIT_RUN_2,               OK
    SRV_CMD_FULL_REJUDGE_BY_MASK,       OK
    SRV_CMD_DUMP_SOURCE,                OK
    SRV_CMD_DUMP_CLAR,                  OK
    SRV_CMD_RUN_STATUS,                 OK
    SRV_CMD_DUMP_SOURCE_2,              OK
*/

#include "config.h"
#include "ej_types.h"
#include "ej_limits.h"

#include "new-server.h"
#include "new_server_proto.h"
#include "pathutl.h"
#include "xml_utils.h"
#include "misctext.h"
#include "copyright.h"
#include "userlist_clnt.h"
#include "ejudge_cfg.h"
#include "errlog.h"
#include "userlist_proto.h"
#include "contests.h"
#include "nsdb_plugin.h"
#include "l10n.h"
#include "fileutl.h"
#include "userlist.h"
#include "mischtml.h"
#include "serve_state.h"
#include "teamdb.h"
#include "prepare.h"
#include "runlog.h"
#include "html.h"
#include "watched_file.h"
#include "mime_type.h"
#include "sha.h"
#include "archive_paths.h"
#include "curtime.h"
#include "clarlog.h"
#include "team_extra.h"
#include "diff.h"
#include "protocol.h"
#include "printing.h"
#include "sformat.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif
#define __(x) x

#if !defined CONF_STYLE_PREFIX
#define CONF_STYLE_PREFIX "/ejudge/"
#endif

#define ARMOR(s)  html_armor_buf(&ab, s)
#define URLARMOR(s)  url_armor_buf(&ab, s)
#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

enum { CONTEST_EXPIRE_TIME = 300 };
static struct contest_extra **extras = 0;
static size_t extra_a = 0;

static void unprivileged_page_login(FILE *fout,
                                    struct http_request_info *phr,
                                    int orig_locale_id);
static void
unpriv_page_header(FILE *fout,
                   struct http_request_info *phr,
                   const struct contest_desc *cnts,
                   struct contest_extra *extra,
                   time_t start_time, time_t stop_time);
static void
do_xml_user_state(FILE *fout, const serve_state_t cs, int user_id);
static int
get_register_url(
        unsigned char *buf,
        size_t size,
        const struct contest_desc *cnts,
        const unsigned char *self_url);

struct contest_extra *
ns_get_contest_extra(int contest_id)
{
  size_t new_extra_a = 0;
  struct contest_extra **new_extras = 0, *p;

  ASSERT(contest_id > 0 && contest_id <= EJ_MAX_CONTEST_ID);

  if (contest_id >= extra_a) {
    if (!(new_extra_a = extra_a)) new_extra_a = 8;
    while (contest_id >= new_extra_a) new_extra_a *= 2;
    XCALLOC(new_extras, new_extra_a);
    if (extra_a > 0) memcpy(new_extras, extras, extra_a * sizeof(extras[0]));
    xfree(extras);
    extra_a = new_extra_a;
    extras = new_extras;
  }
  if (!(p = extras[contest_id])) {
    XCALLOC(p, 1);
    extras[contest_id] = p;
  }
  p->last_access_time = time(0);
  return p;
}

static struct contest_extra *
try_contest_extra(int contest_id)
{
  if (contest_id <= 0 || contest_id > EJ_MAX_CONTEST_ID) return 0;
  if (contest_id >= extra_a) return 0;
  return extras[contest_id];
}

void
ns_contest_unload_callback(serve_state_t cs)
{
  struct client_state *p;

  if (cs->client_id < 0 || !cs->pending_xml_import
      || !(p = ns_get_client_by_id(cs->client_id)))
    return;

  p->contest_id = 0;
  p->destroy_callback = 0;
  nsf_close_client_fds(p);
  ns_send_reply(p, -NEW_SRV_ERR_CONTEST_UNLOADED);
}

void
ns_client_destroy_callback(struct client_state *p)
{
  struct contest_extra *extra;
  const struct contest_desc *cnts = 0;
  serve_state_t cs;

  if (p->contest_id <= 0) return;
  if (contests_get(p->contest_id, &cnts) < 0) return;
  if (!(extra = try_contest_extra(p->contest_id))) return;
  if (!(cs = extra->serve_state)) return;
  if (!cs->pending_xml_import || cs->client_id < 0) return;
  if (cs->saved_testing_suspended != cs->testing_suspended) {
    cs->testing_suspended = cs->saved_testing_suspended;
    serve_update_status_file(cs, 1);
    if (!cs->testing_suspended)
      serve_judge_suspended(cnts, cs, 0, 0, 0);
  }
  xfree(cs->pending_xml_import); cs->pending_xml_import = 0;
  cs->client_id = -1;
  cs->destroy_callback = 0;
}

void
ns_unload_contest(int contest_id)
{
  struct contest_extra *extra;
  const struct contest_desc *cnts = 0;
  int i;

  if (contest_id <= 0 || contest_id >= extra_a) return;
  if (!(extra = extras[contest_id])) return;

  contests_get(contest_id, &cnts);

  if (extra->serve_state) {
    serve_check_stat_generation(extra->serve_state, cnts, 1);
    serve_update_status_file(extra->serve_state, 1);
    team_extra_flush(extra->serve_state->team_extra_state);
    extra->serve_state = serve_state_destroy(extra->serve_state, cnts, ul_conn);
  }

  xfree(extra->contest_arm);
  watched_file_clear(&extra->header);
  watched_file_clear(&extra->menu_1);
  watched_file_clear(&extra->menu_2);
  watched_file_clear(&extra->separator);
  watched_file_clear(&extra->footer);
  watched_file_clear(&extra->priv_header);
  watched_file_clear(&extra->priv_footer);
  watched_file_clear(&extra->copyright);
  watched_file_clear(&extra->welcome);

  for (i = 0; i < USER_ROLE_LAST; i++) {
    xfree(extra->user_access[i].v);
  }
  xfree(extra->user_access_idx.v);

  memset(extra, 0, sizeof(*extra));
  xfree(extra);
  extras[contest_id] = 0;

  info("contest %d is unloaded", contest_id);
}

void
ns_unload_contests(void)
{
  int i;

  for (i = 1; i < extra_a; i++)
    if (extras[i])
      ns_unload_contest(i);
}

void
ns_unload_expired_contests(time_t cur_time)
{
  int i;

  if (cur_time <= 0) cur_time = time(0);

  for (i = 1; i < extra_a; i++)
    if (extras[i]
        && extras[i]->last_access_time + CONTEST_EXPIRE_TIME < cur_time
        && (!extras[i]->serve_state
            || !extras[i]->serve_state->pending_xml_import))
      ns_unload_contest(i);
}

static void
handle_pending_xml_import(const struct contest_desc *cnts, serve_state_t cs)
{
  struct client_state *p;
  FILE *fout = 0;
  char *out_text = 0;
  size_t out_size = 0;

  if (cs->client_id < 0 || !(p = ns_get_client_by_id(cs->client_id))) {
    if (cs->saved_testing_suspended != cs->testing_suspended) {
      cs->testing_suspended = cs->saved_testing_suspended;
      serve_update_status_file(cs, 1);
      if (!cs->testing_suspended)
        serve_judge_suspended(cnts, cs, 0, 0, 0);
    }
    xfree(cs->pending_xml_import); cs->pending_xml_import = 0;
    cs->client_id = -1; cs->destroy_callback = 0;
    return;
  }

  fout = open_memstream(&out_text, &out_size);
  runlog_import_xml(cs, cs->runlog_state, fout, 1, cs->pending_xml_import);
  fclose(fout); fout = 0;
  if (out_size > 0) {
    ns_new_autoclose(p, out_text, out_size);
    out_text = 0;
  } else {
    nsf_close_client_fds(p);
    xfree(out_text); out_text = 0;
  }
  ns_send_reply(p, NEW_SRV_RPL_OK);

  if (cs->saved_testing_suspended != cs->testing_suspended) {
    cs->testing_suspended = cs->saved_testing_suspended;
    serve_update_status_file(cs, 1);
    if (!cs->testing_suspended)
      serve_judge_suspended(cnts, cs, 0, 0, 0);
  }
  xfree(cs->pending_xml_import); cs->pending_xml_import = 0;
  cs->client_id = -1; cs->destroy_callback = 0;
  p->contest_id = 0;
  p->destroy_callback = 0;
}

void
ns_loop_callback(struct server_framework_state *state)
{
  time_t cur_time = time(0);
  struct contest_extra *e;
  serve_state_t cs;
  const struct contest_desc *cnts;
  int contest_id, i, r;
  path_t packetname;

  for (contest_id = 1; contest_id < extra_a; contest_id++) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) continue;
    if (!(e = extras[contest_id])) continue;
    if (!(cs = e->serve_state)) continue;

    e->serve_state->current_time = cur_time;
    ns_check_contest_events(e->serve_state, cnts);

    serve_update_public_log_file(e->serve_state, cnts);
    serve_update_external_xml_log(e->serve_state, cnts);
    serve_update_internal_xml_log(e->serve_state, cnts);

    for (i = 0; i < cs->compile_dirs_u; i++) {
      if ((r = scan_dir(cs->compile_dirs[i].status_dir,
                        packetname, sizeof(packetname))) <= 0)
        continue;
      serve_read_compile_packet(cs, cnts,
                                cs->compile_dirs[i].status_dir,
                                cs->compile_dirs[i].report_dir,
                                packetname);
    }

    for (i = 0; i < cs->run_dirs_u; i++) {
      if ((r = scan_dir(cs->run_dirs[i].status_dir,
                        packetname, sizeof(packetname))) <= 0)
        continue;
      serve_read_run_packet(cs, cnts,
                            cs->run_dirs[i].status_dir,
                            cs->run_dirs[i].report_dir,
                            cs->run_dirs[i].full_report_dir,
                            packetname);
    }

    if (cs->pending_xml_import && !serve_count_transient_runs(cs))
      handle_pending_xml_import(cnts, cs);
  }

  ns_unload_expired_contests(cur_time);
}

void
ns_post_select_callback(struct server_framework_state *state)
{
  time_t cur_time = time(0);
  struct contest_extra *e;
  serve_state_t cs;
  const struct contest_desc *cnts;
  int contest_id;

  for (contest_id = 1; contest_id < extra_a; contest_id++) {
    if (contests_get(contest_id, &cnts) < 0 || !cnts) continue;
    if (!(e = extras[contest_id])) continue;
    if (!(cs = e->serve_state)) continue;

    e->serve_state->current_time = cur_time;
    ns_check_contest_events(e->serve_state, cnts);
  }
}

static const unsigned char*
ns_getenv(const struct http_request_info *phr, const unsigned char *var)
{
  int i;
  size_t var_len;

  if (!var) return 0;
  var_len = strlen(var);
  for (i = 0; i < phr->env_num; i++)
    if (!strncmp(phr->envs[i], var, var_len) && phr->envs[i][var_len] == '=')
      break;
  if (i < phr->env_num)
    return phr->envs[i] + var_len + 1;
  return 0;
}

int
ns_cgi_param(const struct http_request_info *phr, const unsigned char *param,
             const unsigned char **p_value)
{
  int i;

  if (!param) return -1;
  for (i = 0; i < phr->param_num; i++)
    if (!strcmp(phr->param_names[i], param))
      break;
  if (i >= phr->param_num) return 0;
  if (strlen(phr->params[i]) != phr->param_sizes[i]) return -1;
  *p_value = phr->params[i];
  return 1;
}

int
ns_cgi_param_bin(const struct http_request_info *phr,
                 const unsigned char *param,
                 const unsigned char **p_value,
                 size_t *p_size)
{
  int i;

  if (!param) return -1;
  for (i = 0; i < phr->param_num; i++)
    if (!strcmp(phr->param_names[i], param))
      break;
  if (i >= phr->param_num) return 0;
  *p_value = phr->params[i];
  *p_size = phr->param_sizes[i];
  return 1;
}

static const unsigned char *
ns_cgi_nname(const struct http_request_info *phr,
             const unsigned char *prefix, size_t pflen)
{
  int i;

  if (!prefix || !pflen) return 0;
  for (i = 0; i < phr->param_num; i++)
    if (!strncmp(phr->param_names[i], prefix, pflen))
      return phr->param_names[i];
  return 0;
}

int
ns_cgi_param_int(
        struct http_request_info *phr,
        const unsigned char *name,
        int *p_val)
{
  const unsigned char *s = 0;
  char *eptr = 0;
  int x;

  if (ns_cgi_param(phr, name, &s) <= 0) return -1;
  errno = 0;
  x = strtol(s, &eptr, 10);
  if (errno || *eptr) return -1;
  if (p_val) *p_val = x;
  return 0;
}

int
ns_cgi_param_int_opt(
        struct http_request_info *phr,
        const unsigned char *name,
        int *p_val,
        int default_value)
{
  const unsigned char *s = 0, *p;
  char *eptr = 0;
  int x;

  if (!(x = ns_cgi_param(phr, name, &s))) {
    if (p_val) *p_val = default_value;
    return 0;
  } else if (x < 0) return -1;
  p = s;
  while (*p && isspace(*p)) p++;
  if (!*p) {
    if (p_val) *p_val = default_value;
    return 0;
  }
  errno = 0;
  x = strtol(s, &eptr, 10);
  if (errno || *eptr) return -1;
  if (p_val) *p_val = x;
  return 0;
}
static void
close_ul_connection(struct server_framework_state *state)
{
  if (!ul_conn) return;

  nsf_remove_watch(state, userlist_clnt_get_fd(ul_conn));
  ul_conn = userlist_clnt_close(ul_conn);
}

static void
ul_conn_callback(struct server_framework_state *state,
                 struct server_framework_watch *pw,
                 int events)
{
  int r, contest_id = 0;
  struct contest_extra *e;

  info("userlist-server fd ready");
  while (1) {
    r = userlist_clnt_read_notification(ul_conn, &contest_id);
    if (r == ULS_ERR_UNEXPECTED_EOF) {
      info("userlist-server disconnect");
      close_ul_connection(state);
      break;
    } else if (r < 0) {
      err("userlist-server error: %s", userlist_strerror(-r));
      close_ul_connection(state);
      break;
    } else {
      e = try_contest_extra(contest_id);
      if (!e) {
        err("userlist-server notification: %d - no such contest", contest_id);
        break;
      } else {
        info("userlist-server notification: %d", contest_id);
        if (e->serve_state && e->serve_state->teamdb_state)
          teamdb_set_update_flag(e->serve_state->teamdb_state);
        if (userlist_clnt_bytes_available(ul_conn) <= 0) break;
      }
    }
    info("userlist-server fd has more data");
  }
}

static void
ul_notification_callback(void *user_data, int contest_id)
{
  struct contest_extra *e;

  e = try_contest_extra(contest_id);
  if (!e) {
    err("userlist-server notification: %d - no such contest", contest_id);
  } else {
    info("userlist-server notification: %d", contest_id);
    if (e->serve_state && e->serve_state->teamdb_state)
      teamdb_set_update_flag(e->serve_state->teamdb_state);
  }
}

int
ns_open_ul_connection(struct server_framework_state *state)
{
  struct server_framework_watch w;
  int r, contest_id;
  struct contest_extra *e;

  if (ul_conn) return 0;

  if (!(ul_conn = userlist_clnt_open(config->socket_path))) {
    err("ns_open_ul_connection: connect to server failed");
    return -1;
  }

  memset(&w, 0, sizeof(w));
  w.fd = userlist_clnt_get_fd(ul_conn);
  w.mode = NSF_READ;
  w.callback = ul_conn_callback;
  nsf_add_watch(state, &w);

  xfree(ul_login); ul_login = 0;
  if ((r = userlist_clnt_admin_process(ul_conn, &ul_uid, &ul_login, 0)) < 0) {
    err("open_connection: cannot became an admin process: %s",
        userlist_strerror(-r));
    close_ul_connection(state);
    return -1;
  }

  userlist_clnt_set_notification_callback(ul_conn, ul_notification_callback, 0);

  // add notifications for all the active contests
  for (contest_id = 1; contest_id < extra_a; contest_id++) {
    if (!(e = extras[contest_id]) || !e->serve_state) continue;
    if ((r = userlist_clnt_notify(ul_conn, ULS_ADD_NOTIFY, contest_id)) < 0) {
      err("open_connection: cannot add notification: %s",
          userlist_strerror(-r));
      close_ul_connection(state);
      return -1;
    }
  }

  info("running as %s (%d)", ul_login, ul_uid);
  return 0;
}

static void
load_problem_plugin(serve_state_t cs, int prob_id)
{
  struct section_problem_data *prob = 0;
  struct problem_extra_info *extra;
  struct problem_plugin_iface *iface;
  unsigned char plugin_name[1024];
  int len, i;

  if (prob_id <= 0 || prob_id > cs->max_prob) return;
  if (!(prob = cs->probs[prob_id])) return;
  extra = &cs->prob_extras[prob_id];

  if (!prob->plugin_file[0]) return;
  if (extra->plugin || extra->plugin_error) return;

  snprintf(plugin_name, sizeof(plugin_name), "problem_%s", prob->short_name);
  len = strlen(plugin_name);
  for (i = 0; i < len; i++)
    if (plugin_name[i] == '-')
      plugin_name[i] = '_';

  iface = (struct problem_plugin_iface*) plugin_load(prob->plugin_file,
                                                     "problem",
                                                     plugin_name);
  if (!iface) {
    extra->plugin_error = 1;
    return;
  }

  extra->plugin = iface;
  extra->plugin_data = (*extra->plugin->init)();
  info("loaded plugin %s", plugin_name);
}

int
ns_list_all_users_callback(
        void *user_data,
        int contest_id,
        unsigned char **p_xml)
{
  struct server_framework_state *state = (struct server_framework_state *) user_data;
  if (ns_open_ul_connection(state) < 0) return -1;

  if (userlist_clnt_list_all_users(ul_conn, ULS_LIST_STANDINGS_USERS,
                                   contest_id, p_xml) < 0) return -1;
  return 0;
}

static const unsigned char *role_strs[] =
  {
    __("Contestant"),
    __("Observer"),
    __("Examiner"),
    __("Chief examiner"),
    __("Coordinator"),
    __("Judge"),
    __("Administrator"),
    0,
  };
const unsigned char *
ns_unparse_role(int role)
{
  static unsigned char buf[32];
  if (role < 0 || role >= USER_ROLE_LAST) {
    snprintf(buf, sizeof(buf), "role_%d", role);
    return buf;
  }
  return gettext(role_strs[role]);
}

static void
html_role_select(FILE *fout, int role, int allow_admin,
                 const unsigned char *var_name)
{
  int i;
  const unsigned char *ss;
  int last_role = USER_ROLE_ADMIN;

  if (!var_name) var_name = "role";
  if (!allow_admin) last_role = USER_ROLE_COORDINATOR;
  if (role <= 0 || role > last_role) role = USER_ROLE_OBSERVER;
  fprintf(fout, "<select name=\"%s\">", var_name);
  for (i = 1; i <= last_role; i++) {
    ss = "";
    if (i == role) ss = " selected=\"1\"";
    fprintf(fout, "<option value=\"%d\"%s>%s</option>",
            i, ss, gettext(role_strs[i]));
  }
  fprintf(fout, "</select>\n");
}

unsigned char *
ns_url(unsigned char *buf, size_t size,
       const struct http_request_info *phr,
       int action, const char *format, ...)
{
  unsigned char fbuf[1024];
  unsigned char abuf[64];
  const unsigned char *sep = "";
  va_list args;

  fbuf[0] = 0;
  if (format && *format) {
    va_start(args, format);
    vsnprintf(fbuf, sizeof(fbuf), format, args);
    va_end(args);
  }
  if (fbuf[0]) sep = "&amp;";

  abuf[0] = 0;
  if (action > 0) snprintf(abuf, sizeof(abuf), "&amp;action=%d", action);

  snprintf(buf, size, "%s?SID=%016llx%s%s%s", phr->self_url,
           phr->session_id, abuf, sep, fbuf);
  return buf;
}

unsigned char *
ns_url_unescaped(
        unsigned char *buf,
        size_t size,
        const struct http_request_info *phr,
        int action,
        const char *format,
        ...)
{
  unsigned char fbuf[1024];
  unsigned char abuf[64];
  const unsigned char *sep = "";
  va_list args;

  fbuf[0] = 0;
  if (format && *format) {
    va_start(args, format);
    vsnprintf(fbuf, sizeof(fbuf), format, args);
    va_end(args);
  }
  if (fbuf[0]) sep = "&";

  abuf[0] = 0;
  if (action > 0) snprintf(abuf, sizeof(abuf), "&action=%d", action);

  snprintf(buf, size, "%s?SID=%016llx%s%s%s", phr->self_url,
           phr->session_id, abuf, sep, fbuf);
  return buf;
}

unsigned char *
ns_aref(unsigned char *buf, size_t size,
        const struct http_request_info *phr,
        int action, const char *format, ...)
{
  unsigned char fbuf[1024];
  unsigned char abuf[64];
  const unsigned char *sep = "";
  va_list args;

  fbuf[0] = 0;
  if (format && *format) {
    va_start(args, format);
    vsnprintf(fbuf, sizeof(fbuf), format, args);
    va_end(args);
  }
  if (fbuf[0]) sep = "&amp;";

  abuf[0] = 0;
  if (action > 0) snprintf(abuf, sizeof(abuf), "&amp;action=%d", action);

  snprintf(buf, size, "<a href=\"%s?SID=%016llx%s%s%s\">", phr->self_url,
           phr->session_id, abuf, sep, fbuf);
  return buf;
}

unsigned char *
ns_aref_2(unsigned char *buf, size_t size,
          const struct http_request_info *phr,
          const unsigned char *style,
          int action, const char *format, ...)
{
  unsigned char fbuf[1024];
  unsigned char abuf[64];
  unsigned char stbuf[128];
  const unsigned char *sep = "";
  va_list args;

  fbuf[0] = 0;
  if (format && *format) {
    va_start(args, format);
    vsnprintf(fbuf, sizeof(fbuf), format, args);
    va_end(args);
  }
  if (fbuf[0]) sep = "&amp;";

  abuf[0] = 0;
  if (action > 0) snprintf(abuf, sizeof(abuf), "&amp;action=%d", action);

  stbuf[0] = 0;
  if (style && *style) {
    snprintf(stbuf, sizeof(stbuf), " class=\"%s\"", style);
  }

  snprintf(buf, size, "<a href=\"%s?SID=%016llx%s%s%s\"%s>", phr->self_url,
           phr->session_id, abuf, sep, fbuf, stbuf);
  return buf;
}

#define BUTTON(a) ns_submit_button(bb, sizeof(bb), 0, a, 0)

unsigned char *
ns_submit_button(unsigned char *buf, size_t size,
                 const unsigned char *var_name, int action,
                 const unsigned char *label)
{
  unsigned char name_buf[64];
  const unsigned char *name_ptr;

  if (!var_name) var_name = "action";
  if (!label && action > 0 && action < NEW_SRV_ACTION_LAST)
    label = gettext(ns_submit_button_labels[action]);
  if (!label) label = "Submit";
  name_ptr = var_name;
  if (action > 0) {
    // IE bug mode :(
    snprintf(name_buf, sizeof(name_buf), "%s_%d", var_name, action);
    name_ptr = name_buf;
  }
  snprintf(buf, size,
           "<input type=\"submit\" name=\"%s\" value=\"%s\"/>",
           name_ptr, label);
  return buf;
}

void
ns_refresh_page(FILE *fout, struct http_request_info *phr, int new_action,
                const unsigned char *extra)
{
  unsigned char url[1024];

  if (extra && *extra) {
    ns_url_unescaped(url, sizeof(url), phr, new_action, "%s", extra);
  } else {
    ns_url_unescaped(url, sizeof(url), phr, new_action, 0);
  }

  fprintf(fout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\nLocation: %s\n\n", EJUDGE_CHARSET, url);
}

void
ns_refresh_page_2(FILE *fout, const unsigned char *url)
{
  fprintf(fout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\nLocation: %s\n\n", EJUDGE_CHARSET, url);
}

void
ns_check_contest_events(serve_state_t cs, const struct contest_desc *cnts)
{
  const struct section_global_data *global = cs->global;
  time_t start_time, stop_time, sched_time, duration, finish_time;

  run_get_times(cs->runlog_state, &start_time, &sched_time,
                &duration, &stop_time, &finish_time);

  if (!global->is_virtual) {
    if (start_time > 0 && stop_time <= 0 && duration <= 0 && finish_time > 0
        && cs->current_time >= finish_time) {
      /* the contest is over: contest_finish_time is expired! */
      info("CONTEST IS OVER");
      run_stop_contest(cs->runlog_state, finish_time);
    } else if (start_time > 0 && stop_time <= 0 && duration > 0
               && cs->current_time >= start_time + duration){
      /* the contest is over: duration is expired! */
      info("CONTEST IS OVER");
      run_stop_contest(cs->runlog_state, start_time + duration);
    } else if (sched_time > 0 && start_time <= 0
               && cs->current_time >= sched_time) {
      /* it's time to start! */
      info("CONTEST IS STARTED");
      run_start_contest(cs->runlog_state, sched_time);
      serve_invoke_start_script(cs);
      serve_update_standings_file(cs, cnts, 0);
    }
  }

  if (cs->event_first) serve_handle_events(cnts, cs);
}

static void
privileged_page_login_page(FILE *fout, struct http_request_info *phr)
{
  const unsigned char *s;
  int r, n;
  unsigned char bbuf[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  l10n_setlocale(phr->locale_id);
  ns_header(fout, ns_fancy_priv_header, 0, 0, 0, 0, phr->locale_id, "Login page");
  html_start_form(fout, 1, phr->self_url, "");
  fprintf(fout, "<table>\n");
  fprintf(fout, "<tr><td>%s:</td><td><input type=\"text\" size=\"32\" name=\"login\"", _("Login"));
  if (ns_cgi_param(phr, "login", &s) > 0) {
    fprintf(fout, " value=\"%s\"", ARMOR(s));
  }
  fprintf(fout, "/></td></tr>\n");
  fprintf(fout, "<tr><td>%s:</td><td><input type=\"password\" size=\"32\" name=\"password\"", _("Password"));
  if (ns_cgi_param(phr, "password", &s) > 0) {
    fprintf(fout, " value=\"%s\"", ARMOR(s));
  }
  fprintf(fout, "/></td></tr>\n");
  fprintf(fout, "<tr><td>%s:</td><td><input type=\"text\" size=\"32\" name=\"contest_id\"", _("Contest"));
  if (phr->contest_id > 0) {
    fprintf(fout, " value=\"%d\"", phr->contest_id);
  }
  fprintf(fout, "/></td></tr>\n");
  if (!phr->role) {
    phr->role = USER_ROLE_OBSERVER;
    if (ns_cgi_param(phr, "role", &s) > 0) {
      if (sscanf(s, "%d%n", &r, &n) == 1 && !s[n]
          && r >= USER_ROLE_CONTESTANT && r < USER_ROLE_LAST)
        phr->role = r;
    }
  }
  fprintf(fout, "<tr><td>%s:</td><td>", _("Role"));
  html_role_select(fout, phr->role, 1, 0);
  fprintf(fout, "</td></tr>\n");
  fprintf(fout, "<tr><td>%s:</td><td>", _("Language"));
  l10n_html_locale_select(fout, phr->locale_id);
  fprintf(fout, "</td></tr>\n");
  fprintf(fout, "<tr><td>&nbsp;</td><td>%s</td></tr>\n",
          ns_submit_button(bbuf, sizeof(bbuf), "submit", 0, _("Submit")));
  fprintf(fout, "</table></form>\n");
  ns_footer(fout, 0, 0, phr->locale_id);
  l10n_setlocale(0);
  html_armor_free(&ab);
}

static void
html_error_status_page(FILE *fout,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra,
                       const unsigned char *log_txt,
                       int back_action,
                       const char *format,
                       ...)
  __attribute__((format(printf,7,8)));
static void
html_error_status_page(FILE *fout,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra,
                       const unsigned char *log_txt,
                       int back_action,
                       const char *format,
                       ...)
{
  unsigned char url[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char urlextra[1024];
  va_list args;

  urlextra[0] = 0;
  if (format && *format) {
    va_start(args, format);
    vsnprintf(urlextra, sizeof(urlextra), format, args);
    va_end(args);
  }

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            _("Operation completed with errors"));
  if (extra->separator_txt && *extra->separator_txt) {
    fprintf(fout, "%s%s", ns_fancy_empty_status, extra->separator_txt);
  }
  fprintf(fout, "<font color=\"red\"><pre>%s</pre></font>\n", ARMOR(log_txt));
  fprintf(fout, "<hr>%s%s</a>\n",
          ns_aref(url, sizeof(url), phr, back_action, "%s", urlextra),
          _("Back"));
  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);
  html_armor_free(&ab);
}
                       
static void
privileged_page_cookie_login(FILE *fout,
                             struct http_request_info *phr)
{
  const struct contest_desc *cnts = 0;
  opcap_t caps;
  int r, n;
  const unsigned char *s = 0;

  if (phr->contest_id<=0 || contests_get(phr->contest_id, &cnts)<0 || !cnts)
    return ns_html_err_inv_param(fout, phr, 1, "invalid contest_id");
  if (!cnts->new_managed)
    return ns_html_err_inv_param(fout, phr, 1, "contest is not managed");
  if (!phr->role) {
    phr->role = USER_ROLE_OBSERVER;
    if (ns_cgi_param(phr, "role", &s) > 0) {
      if (sscanf(s, "%d%n", &r, &n) == 1 && !s[n]
          && r >= USER_ROLE_CONTESTANT && r < USER_ROLE_LAST)
        phr->role = r;
    }
  }
  if (phr->role <= USER_ROLE_CONTESTANT || phr->role >= USER_ROLE_LAST)
      return ns_html_err_no_perm(fout, phr, 1, "invalid role");
  if (!phr->session_id)
      return ns_html_err_no_perm(fout, phr, 1, "SID is undefined");    

  // analyze IP limitations
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (!contests_check_master_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      return ns_html_err_no_perm(fout, phr, 1, "%s://%s is not allowed for MASTER for contest %d", ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  } else {
    // as for judge program
    if (!contests_check_judge_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      return ns_html_err_no_perm(fout, phr, 1, "%s://%s is not allowed for JUDGE for contest %d", ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  }

  if (ns_open_ul_connection(phr->fw_state) < 0)
    return ns_html_err_ul_server_down(fout, phr, 1, 0);

  xfree(phr->login); phr->login = 0;
  xfree(phr->name); phr->name = 0;
  if ((r = userlist_clnt_priv_cookie_login(ul_conn, ULS_PRIV_COOKIE_LOGIN,
                                           phr->ip, phr->ssl_flag,
                                           phr->contest_id, phr->session_id,
                                           phr->locale_id,
                                           phr->role, &phr->user_id,
                                           &phr->session_id, &phr->login,
                                           &phr->name)) < 0) {
    switch (-r) {
    case ULS_ERR_BAD_CONTEST_ID:
    case ULS_ERR_IP_NOT_ALLOWED:
    case ULS_ERR_NO_PERMS:
    case ULS_ERR_NOT_REGISTERED:
    case ULS_ERR_CANNOT_PARTICIPATE:
      return ns_html_err_no_perm(fout, phr, 1, "priv_login failed: %s",
                                 userlist_strerror(-r));
    case ULS_ERR_DISCONNECT:
      return ns_html_err_ul_server_down(fout, phr, 1, 0);
    default:
      return ns_html_err_internal_error(fout, phr, 1,
                                        "priv_login failed: %s",
                                        userlist_strerror(-r));
    }
  }

  // analyze permissions
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
        || opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0)
      return ns_html_err_no_perm(fout, phr, 1, "user %s does not have MASTER_LOGIN bit for contest %d", phr->login, phr->contest_id);
  } else if (phr->role == USER_ROLE_JUDGE) {
    // as for the judge program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
        || opcaps_check(caps, OPCAP_JUDGE_LOGIN) < 0)
      return ns_html_err_no_perm(fout, phr, 1, "user %s does not have JUDGE_LOGIN bit for contest %d", phr->login, phr->contest_id);
  } else {
    // user privileges checked locally
    if (nsdb_check_role(phr->user_id, phr->contest_id, phr->role) < 0)
      return ns_html_err_no_perm(fout, phr, 1, "user %s has no permission to login as role %d for contest %d", phr->login, phr->role, phr->contest_id);
  }

  ns_get_session(phr->session_id, 0);
  ns_refresh_page(fout, phr, NEW_SRV_ACTION_MAIN_PAGE, 0);
}

static void
privileged_page_login(FILE *fout,
                      struct http_request_info *phr)
{
  const unsigned char *login, *password, *s;
  int r, n;
  const struct contest_desc *cnts = 0;
  opcap_t caps;

  if ((r = ns_cgi_param(phr, "login", &login)) < 0)
    return ns_html_err_inv_param(fout, phr, 1, "cannot parse login");
  if (!r || phr->action == NEW_SRV_ACTION_LOGIN_PAGE)
    return privileged_page_login_page(fout, phr);

  phr->login = xstrdup(login);
  if ((r = ns_cgi_param(phr, "password", &password)) <= 0)
    return ns_html_err_inv_param(fout, phr, 1, "cannot parse password");
  if (phr->contest_id<=0 || contests_get(phr->contest_id, &cnts)<0 || !cnts)
    return ns_html_err_inv_param(fout, phr, 1, "invalid contest_id");
  if (!cnts->new_managed)
    return ns_html_err_inv_param(fout, phr, 1, "contest is not managed");

  if (!phr->role) {
    phr->role = USER_ROLE_OBSERVER;
    if (ns_cgi_param(phr, "role", &s) > 0) {
      if (sscanf(s, "%d%n", &r, &n) == 1 && !s[n]
          && r >= USER_ROLE_CONTESTANT && r < USER_ROLE_LAST)
        phr->role = r;
    }
  }
  if (phr->role == USER_ROLE_CONTESTANT)
    return unprivileged_page_login(fout, phr, phr->locale_id);

  // analyze IP limitations
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (!contests_check_master_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      return ns_html_err_no_perm(fout, phr, 1, "%s://%s is not allowed for MASTER for contest %d", ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  } else {
    // as for judge program
    if (!contests_check_judge_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      return ns_html_err_no_perm(fout, phr, 1, "%s://%s is not allowed for JUDGE for contest %d", ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  }

  if (ns_open_ul_connection(phr->fw_state) < 0)
    return ns_html_err_ul_server_down(fout, phr, 1, 0);
  if ((r = userlist_clnt_priv_login(ul_conn, ULS_PRIV_CHECK_USER,
                                    phr->ip, phr->ssl_flag, phr->contest_id,
                                    phr->locale_id, phr->role, login,
                                    password, &phr->user_id, &phr->session_id,
                                    0, &phr->name)) < 0) {
    switch (-r) {
    case ULS_ERR_INVALID_LOGIN:
    case ULS_ERR_INVALID_PASSWORD:
    case ULS_ERR_BAD_CONTEST_ID:
    case ULS_ERR_IP_NOT_ALLOWED:
    case ULS_ERR_NO_PERMS:
    case ULS_ERR_NOT_REGISTERED:
    case ULS_ERR_CANNOT_PARTICIPATE:
      return ns_html_err_no_perm(fout, phr, 1, "priv_login failed: %s",
                                 userlist_strerror(-r));
    case ULS_ERR_DISCONNECT:
      return ns_html_err_ul_server_down(fout, phr, 1, 0);
    default:
      return ns_html_err_internal_error(fout, phr, 1,
                                        "priv_login failed: %s",
                                        userlist_strerror(-r));
    }
  }

  // analyze permissions
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
        || opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0)
      return ns_html_err_no_perm(fout, phr, 1, "user %s does not have MASTER_LOGIN bit for contest %d", phr->login, phr->contest_id);
  } else if (phr->role == USER_ROLE_JUDGE) {
    // as for the judge program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
        || opcaps_check(caps, OPCAP_JUDGE_LOGIN) < 0)
      return ns_html_err_no_perm(fout, phr, 1, "user %s does not have JUDGE_LOGIN bit for contest %d", phr->login, phr->contest_id);
  } else {
    // user privileges checked locally
    if (nsdb_check_role(phr->user_id, phr->contest_id, phr->role) < 0)
      return ns_html_err_no_perm(fout, phr, 1, "user %s has no permission to login as role %d for contest %d", phr->login, phr->role, phr->contest_id);
  }

  ns_get_session(phr->session_id, 0);
  ns_refresh_page(fout, phr, NEW_SRV_ACTION_MAIN_PAGE, 0);
}

static void
priv_parse_user_id_range(
        struct http_request_info *phr,
        int *p_first_id,
        int *p_last_id)
{
  int first = 0, last = -1, x, y;

  if (ns_cgi_param_int_opt(phr, "first_user_id", &x, 0) < 0) goto done;
  if (ns_cgi_param_int_opt(phr, "last_user_id", &y, -1) < 0) goto done;
  if (x <= 0 || y <= 0 || x > y || y - x > 10000) goto done;

  first = x;
  last = y;

 done:
  if (p_first_id) *p_first_id = first;
  if (p_last_id) *p_last_id = last;
}

static int
priv_registration_operation(FILE *fout,
                            FILE *log_f,
                            struct http_request_info *phr,
                            const struct contest_desc *cnts,
                            struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  int i, x, n, new_status, cmd, flag;
  intarray_t uset;
  const unsigned char *s;
  int retcode = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char *disq_comment = 0;
  int first_user_id = 0, last_user_id  = -1;

  // extract the selected set of users
  memset(&uset, 0, sizeof(uset));
  for (i = 0; i < phr->param_num; i++) {
    if (strncmp(phr->param_names[i], "user_", 5) != 0) continue;
    if (sscanf((s = phr->param_names[i] + 5), "%d%n", &x, &n) != 1
        || s[n] || x <= 0) {
      ns_html_err_inv_param(fout, phr, 1, "invalid parameter name %s",
                            ARMOR(phr->param_names[i]));
      retcode = -1;
      goto cleanup;
    }
    XEXPAND2(uset);
    uset.v[uset.u++] = x;
  }

  priv_parse_user_id_range(phr, &first_user_id, &last_user_id);
  if (first_user_id > 0) {
    for (i = first_user_id; i <= last_user_id; i++) {
      XEXPAND2(uset);
      uset.v[uset.u++] = i;
    }
  }

  if (phr->action == NEW_SRV_ACTION_USERS_SET_DISQUALIFIED) {
    if (ns_cgi_param(phr, "disq_comment", &s) < 0) {
      ns_html_err_inv_param(fout, phr, 1, "invalid parameter disq_comment");
      retcode = -1;
      goto cleanup;
    }
    disq_comment = text_area_process_string(s, 0, 0);
  }

  // FIXME: probably we need to sort user_ids and remove duplicates

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    ns_html_err_ul_server_down(fout, phr, 1, 0);
    retcode = -1;
    goto cleanup;
  }

  for (i = 0; i < uset.u; i++) {
    switch (phr->action) {
    case NEW_SRV_ACTION_USERS_REMOVE_REGISTRATIONS:
      n = userlist_clnt_change_registration(ul_conn, uset.v[i],
                                            phr->contest_id, -2, 0, 0);
      if (n < 0) {
        ns_error(log_f, NEW_SRV_ERR_USER_REMOVAL_FAILED,
                 uset.v[i], phr->contest_id, userlist_strerror(-n));
      }
      break;
    case NEW_SRV_ACTION_USERS_SET_PENDING:
    case NEW_SRV_ACTION_USERS_SET_OK:
    case NEW_SRV_ACTION_USERS_SET_REJECTED:
      switch (phr->action) {
      case NEW_SRV_ACTION_USERS_SET_PENDING: 
        new_status = USERLIST_REG_PENDING;
        break;
      case NEW_SRV_ACTION_USERS_SET_OK:
        new_status = USERLIST_REG_OK;
        break;
      case NEW_SRV_ACTION_USERS_SET_REJECTED:
        new_status = USERLIST_REG_REJECTED;
        break;
      default:
        abort();
      }
      n = userlist_clnt_change_registration(ul_conn, uset.v[i],
                                            phr->contest_id, new_status, 0, 0);
      if (n < 0) {
        ns_error(log_f, NEW_SRV_ERR_USER_STATUS_CHANGE_FAILED,
                 uset.v[i], phr->contest_id, userlist_strerror(-n));
      }
      break;

    case NEW_SRV_ACTION_USERS_SET_INVISIBLE:
    case NEW_SRV_ACTION_USERS_CLEAR_INVISIBLE:
    case NEW_SRV_ACTION_USERS_SET_BANNED:
    case NEW_SRV_ACTION_USERS_CLEAR_BANNED:
    case NEW_SRV_ACTION_USERS_SET_LOCKED:
    case NEW_SRV_ACTION_USERS_CLEAR_LOCKED:
    case NEW_SRV_ACTION_USERS_SET_INCOMPLETE:
    case NEW_SRV_ACTION_USERS_CLEAR_INCOMPLETE:
    case NEW_SRV_ACTION_USERS_SET_DISQUALIFIED:
    case NEW_SRV_ACTION_USERS_CLEAR_DISQUALIFIED:
      switch (phr->action) {
      case NEW_SRV_ACTION_USERS_SET_INVISIBLE:
        cmd = 1;
        flag = USERLIST_UC_INVISIBLE;
        break;
      case NEW_SRV_ACTION_USERS_CLEAR_INVISIBLE:
        cmd = 2;
        flag = USERLIST_UC_INVISIBLE;
        break;
      case NEW_SRV_ACTION_USERS_SET_BANNED:
        cmd = 1;
        flag = USERLIST_UC_BANNED;
        break;
      case NEW_SRV_ACTION_USERS_CLEAR_BANNED:
        cmd = 2;
        flag = USERLIST_UC_BANNED;
        break;
      case NEW_SRV_ACTION_USERS_SET_LOCKED:
        cmd = 1;
        flag = USERLIST_UC_LOCKED;
        break;
      case NEW_SRV_ACTION_USERS_CLEAR_LOCKED:
        cmd = 2;
        flag = USERLIST_UC_LOCKED;
        break;
      case NEW_SRV_ACTION_USERS_SET_INCOMPLETE:
        cmd = 1;
        flag = USERLIST_UC_INCOMPLETE;
        break;
      case NEW_SRV_ACTION_USERS_CLEAR_INCOMPLETE:
        cmd = 2;
        flag = USERLIST_UC_INCOMPLETE;
        break;
      case NEW_SRV_ACTION_USERS_SET_DISQUALIFIED:
        cmd = 1;
        flag = USERLIST_UC_DISQUALIFIED;
        team_extra_set_disq_comment(cs->team_extra_state, uset.v[i],
                                    disq_comment);
        break;
      case NEW_SRV_ACTION_USERS_CLEAR_DISQUALIFIED:
        cmd = 2;
        flag = USERLIST_UC_DISQUALIFIED;
        break;
      default:
        abort();
      }
      n = userlist_clnt_change_registration(ul_conn, uset.v[i],
                                            phr->contest_id, -1, cmd,
                                            flag);
      if (n < 0) {
        ns_error(log_f, NEW_SRV_ERR_USER_FLAGS_CHANGE_FAILED,
                 uset.v[i], phr->contest_id, userlist_strerror(-n));
      }
      break;

    default:
      ns_html_err_inv_param(fout, phr, 1, "invalid action %d", phr->action);
      retcode = -1;
      goto cleanup;
    }
  }

  if (phr->action == NEW_SRV_ACTION_USERS_SET_DISQUALIFIED) {
    team_extra_flush(cs->team_extra_state);
  }

 cleanup:
  xfree(disq_comment);
  xfree(uset.v);
  html_armor_free(&ab);
  return retcode;
}

static int
priv_add_user_by_user_id(FILE *fout,
                         FILE *log_f,
                         struct http_request_info *phr,
                         const struct contest_desc *cnts,
                         struct contest_extra *extra)
{
  const unsigned char *s;
  int x, n, r;
  int retval = 0;

  if ((r = ns_cgi_param(phr, "add_user_id", &s)) < 0 || !s
      || sscanf(s, "%d%n", &x, &n) != 1 || s[n] || x <= 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    ns_html_err_ul_server_down(fout, phr, 1, 0);
    retval = -1;
    goto cleanup;
  }
  
  r = userlist_clnt_register_contest(ul_conn, ULS_PRIV_REGISTER_CONTEST,
                                     x, phr->contest_id, phr->ip,
                                     phr->ssl_flag);
  if (r < 0) {
    ns_error(log_f, NEW_SRV_ERR_REGISTRATION_FAILED, userlist_strerror(-r));
    goto cleanup;
  }

 cleanup:
  return retval;
}

static int
priv_add_user_by_login(FILE *fout,
                       FILE *log_f,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra)
{
  const unsigned char *s;
  int r, user_id;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int retval = 0;

  if ((r = ns_cgi_param(phr, "add_login", &s)) < 0 || !s) {
    ns_error(log_f, NEW_SRV_ERR_INV_USER_LOGIN);
    goto cleanup;
  }
  if (ns_open_ul_connection(phr->fw_state) < 0) {
    ns_html_err_ul_server_down(fout, phr, 1, 0);
    retval = -1;
    goto cleanup;
  }
  if ((r = userlist_clnt_lookup_user(ul_conn, s, 0, &user_id, 0)) < 0) {
    ns_error(log_f, NEW_SRV_ERR_USER_LOGIN_NONEXISTANT, ARMOR(s));
    goto cleanup;
  }
  if ((r = userlist_clnt_register_contest(ul_conn, ULS_PRIV_REGISTER_CONTEST,
                                          user_id, phr->contest_id,
                                          phr->ip, phr->ssl_flag)) < 0) {
    ns_error(log_f, NEW_SRV_ERR_REGISTRATION_FAILED, userlist_strerror(-r));
    goto cleanup;
  }

 cleanup:
  html_armor_free(&ab);
  return retval;
}

static int
priv_priv_user_operation(FILE *fout,
                         FILE *log_f,
                         struct http_request_info *phr,
                         const struct contest_desc *cnts,
                         struct contest_extra *extra)
{
  int i, x, n, role = 0;
  intarray_t uset;
  const unsigned char *s;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int retval = 0;
  int first_user_id = 0, last_user_id = -1;

  // extract the selected set of users
  memset(&uset, 0, sizeof(uset));
  for (i = 0; i < phr->param_num; i++) {
    if (strncmp(phr->param_names[i], "user_", 5) != 0) continue;
    if (sscanf((s = phr->param_names[i] + 5), "%d%n", &x, &n) != 1
        || s[n] || x <= 0) {
      ns_html_err_inv_param(fout, phr, 1, "invalid parameter name %s",
                            ARMOR(phr->param_names[i]));
      retval = -1;
      goto cleanup;
    }
    XEXPAND2(uset);
    uset.v[uset.u++] = x;
  }

  priv_parse_user_id_range(phr, &first_user_id, &last_user_id);
  if (first_user_id > 0) {
    for (i = first_user_id; i <= last_user_id; i++) {
      XEXPAND2(uset);
      uset.v[uset.u++] = i;
    }
  }

  // FIXME: probably we need to sort user_ids and remove duplicates

  switch (phr->action) {
  case NEW_SRV_ACTION_PRIV_USERS_ADD_OBSERVER:
  case NEW_SRV_ACTION_PRIV_USERS_DEL_OBSERVER:
    role = USER_ROLE_OBSERVER;
    break;
  case NEW_SRV_ACTION_PRIV_USERS_ADD_EXAMINER:
  case NEW_SRV_ACTION_PRIV_USERS_DEL_EXAMINER:
    role = USER_ROLE_EXAMINER;
    break;
  case NEW_SRV_ACTION_PRIV_USERS_ADD_CHIEF_EXAMINER:
  case NEW_SRV_ACTION_PRIV_USERS_DEL_CHIEF_EXAMINER:
    role = USER_ROLE_CHIEF_EXAMINER;
    break;
  case NEW_SRV_ACTION_PRIV_USERS_ADD_COORDINATOR:
  case NEW_SRV_ACTION_PRIV_USERS_DEL_COORDINATOR:
    role = USER_ROLE_COORDINATOR;
    break;
  }

  for (i = 0; i < uset.u; i++) {
    switch (phr->action) {
    case NEW_SRV_ACTION_PRIV_USERS_REMOVE:
      if (nsdb_priv_remove_user(uset.v[i], phr->contest_id) < 0) {
        ns_error(log_f, NEW_SRV_ERR_PRIV_USER_REMOVAL_FAILED,
                 uset.v[i], phr->contest_id);
      }
      break;

    case NEW_SRV_ACTION_PRIV_USERS_ADD_OBSERVER:
    case NEW_SRV_ACTION_PRIV_USERS_ADD_EXAMINER:
    case NEW_SRV_ACTION_PRIV_USERS_ADD_CHIEF_EXAMINER:
    case NEW_SRV_ACTION_PRIV_USERS_ADD_COORDINATOR:
      if (nsdb_add_role(uset.v[i], phr->contest_id, role) < 0) {
        ns_error(log_f, NEW_SRV_ERR_PRIV_USER_ROLE_ADD_FAILED,
                 role, uset.v[i], phr->contest_id);
      }
      break;

    case NEW_SRV_ACTION_PRIV_USERS_DEL_OBSERVER:
    case NEW_SRV_ACTION_PRIV_USERS_DEL_EXAMINER:
    case NEW_SRV_ACTION_PRIV_USERS_DEL_CHIEF_EXAMINER:
    case NEW_SRV_ACTION_PRIV_USERS_DEL_COORDINATOR:
      if (nsdb_del_role(uset.v[i], phr->contest_id, role) < 0) {
        ns_error(log_f, NEW_SRV_ERR_PRIV_USER_ROLE_DEL_FAILED,
                 role, uset.v[i], phr->contest_id);
      }
      break;

    default:
      ns_html_err_inv_param(fout, phr, 1, "invalid action %d", phr->action);
      retval = -1;
      goto cleanup;
    }
  }

 cleanup:
  xfree(uset.v);
  html_armor_free(&ab);
  return retval;
}

static int
priv_add_priv_user_by_user_id(FILE *fout,
                              FILE *log_f,
                              struct http_request_info *phr,
                              const struct contest_desc *cnts,
                              struct contest_extra *extra)
{
  const unsigned char *s;
  int user_id, n, r, add_role;

  if ((r = ns_cgi_param(phr, "add_user_id", &s)) < 0 || !s
      || sscanf(s, "%d%n", &user_id, &n) != 1 || s[n] || user_id <= 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_USER_ID);
    goto cleanup;
  }
  if ((r = ns_cgi_param(phr, "add_role_2", &s)) < 0 || !s
      || sscanf(s, "%d%n", &add_role, &n) != 1 || s[n]
      || add_role < USER_ROLE_OBSERVER || add_role > USER_ROLE_COORDINATOR) {
    ns_error(log_f, NEW_SRV_ERR_INV_USER_ROLE);
    goto cleanup;
  }

  if (nsdb_add_role(user_id, phr->contest_id, add_role) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PRIV_USER_ROLE_ADD_FAILED,
             add_role, user_id, phr->contest_id);
    goto cleanup;
  }

 cleanup:
  return 0;
}

static int
priv_add_priv_user_by_login(FILE *fout,
                            FILE *log_f,
                            struct http_request_info *phr,
                            const struct contest_desc *cnts,
                            struct contest_extra *extra)
{
  const unsigned char *s, *login;
  int r, user_id, add_role, n;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int retval = 0;

  if ((r = ns_cgi_param(phr, "add_login", &login)) < 0 || !s) {
    ns_error(log_f, NEW_SRV_ERR_INV_USER_LOGIN);
    goto cleanup;
  }
  if ((r = ns_cgi_param(phr, "add_role_1", &s)) < 0 || !s
      || sscanf(s, "%d%n", &add_role, &n) != 1 || s[n]
      || add_role < USER_ROLE_OBSERVER || add_role > USER_ROLE_COORDINATOR) {
    ns_error(log_f, NEW_SRV_ERR_INV_USER_ROLE);
    goto cleanup;
  }
  if (ns_open_ul_connection(phr->fw_state) < 0) {
    ns_html_err_ul_server_down(fout, phr, 1, 0);
    retval = -1;
    goto cleanup;
  }
  if ((r = userlist_clnt_lookup_user(ul_conn, login, 0, &user_id, 0)) < 0) {
    ns_error(log_f, NEW_SRV_ERR_USER_LOGIN_NONEXISTANT, ARMOR(s));
    goto cleanup;
  }
  if (nsdb_add_role(user_id, phr->contest_id, add_role) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PRIV_USER_ROLE_ADD_FAILED,
                    add_role, user_id, phr->contest_id);
    goto cleanup;
  }

 cleanup:
  html_armor_free(&ab);
  return retval;
}

static int
priv_user_operation(FILE *fout,
                    FILE *log_f,
                    struct http_request_info *phr,
                    const struct contest_desc *cnts,
                    struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const unsigned char *s;
  int retval = 0, user_id, n, new_status;
  const struct team_extra *t_extra = 0;

  if (ns_cgi_param(phr, "user_id", &s) <= 0
      || sscanf(s, "%d%n", &user_id, &n) != 1 || s[n]
      || user_id <= 0 || !teamdb_lookup(cs->teamdb_state, user_id))
    FAIL(NEW_SRV_ERR_INV_USER_ID);

  switch (phr->action) {
  case NEW_SRV_ACTION_USER_CHANGE_STATUS:
    if (ns_cgi_param(phr, "status", &s) <= 0
        || sscanf(s, "%d%n", &new_status, &n) != 1 || s[n]
        || new_status < 0 || new_status >= cs->global->contestant_status_num)
      FAIL(NEW_SRV_ERR_INV_STATUS);
    if (opcaps_check(phr->caps, OPCAP_EDIT_REG) < 0)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    if (!(t_extra = team_extra_get_entry(cs->team_extra_state, user_id)))
      FAIL(NEW_SRV_ERR_DISK_READ_ERROR);
    if (t_extra->status == new_status) goto cleanup;
    team_extra_set_status(cs->team_extra_state, user_id, new_status);
    team_extra_flush(cs->team_extra_state);
    break;
  }

 cleanup:
  return retval;
}

static int
priv_user_issue_warning(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int retval = 0;
  const unsigned char *s;
  int user_id, n;
  unsigned char *warn_txt = 0, *cmt_txt = 0;
  size_t warn_len = 0, cmt_len = 0;

  if (opcaps_check(phr->caps, OPCAP_EDIT_REG) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  /* user_id, warn_text, warn_comment */
  if (ns_cgi_param(phr, "user_id", &s) <= 0
      || sscanf(s, "%d%n", &user_id, &n) != 1 || s[n]
      || teamdb_lookup(cs->teamdb_state, user_id) <= 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);
  if ((n = ns_cgi_param(phr, "warn_text", &s)) < 0)
    FAIL(NEW_SRV_ERR_INV_WARN_TEXT);
  if (!n) FAIL(NEW_SRV_ERR_WARN_TEXT_EMPTY);
  warn_len = strlen(warn_txt = dos2unix_str(s));
  while (warn_len > 0 && isspace(warn_txt[warn_len - 1])) warn_len--;
  warn_txt[warn_len] = 0;
  if (!warn_len) FAIL(NEW_SRV_ERR_WARN_TEXT_EMPTY);
  if ((n = ns_cgi_param(phr, "warn_comment", &s)) < 0)
    FAIL(NEW_SRV_ERR_INV_WARN_CMT);
  if (!n) {
    cmt_len = strlen(cmt_txt = xstrdup(""));
  } else {
    cmt_len = strlen(cmt_txt = dos2unix_str(s));
    while (cmt_len > 0 && isspace(cmt_txt[cmt_len - 1])) cmt_len--;
    cmt_txt[cmt_len] = 0;
  }

  team_extra_append_warning(cs->team_extra_state, user_id, phr->user_id,
                            phr->ip, cs->current_time, warn_txt, cmt_txt);
  team_extra_flush(cs->team_extra_state);

 cleanup:
  xfree(warn_txt);
  xfree(cmt_txt);
  return retval;
}

static int
priv_user_toggle_flags(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0, flag, user_id, n;

  if (phr->role < USER_ROLE_JUDGE)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (opcaps_check(phr->caps, OPCAP_EDIT_REG) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (ns_cgi_param_int(phr, "user_id", &user_id) < 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);

  switch (phr->action) {
  case NEW_SRV_ACTION_TOGGLE_VISIBILITY:
    flag = USERLIST_UC_INVISIBLE;
    break;
  case NEW_SRV_ACTION_TOGGLE_BAN:
    flag = USERLIST_UC_BANNED;
    break;
  case NEW_SRV_ACTION_TOGGLE_LOCK:
    flag = USERLIST_UC_LOCKED;
    break;
  case NEW_SRV_ACTION_TOGGLE_INCOMPLETENESS:
    flag = USERLIST_UC_INCOMPLETE;
    break;
  default:
    abort();
  }

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    ns_html_err_ul_server_down(fout, phr, 1, 0);
    retval = -1;
    goto cleanup;
  }
  n = userlist_clnt_change_registration(ul_conn, user_id, phr->contest_id,
                                        -1, 3, flag);
  if (n < 0) {
    ns_error(log_f, NEW_SRV_ERR_USER_FLAGS_CHANGE_FAILED,
             user_id, phr->contest_id, userlist_strerror(-n));
    retval = -1;
    goto cleanup;
  }

  snprintf(phr->next_extra, sizeof(phr->next_extra), "user_id=%d", user_id);
  retval = NEW_SRV_ACTION_VIEW_USER_INFO;

 cleanup:
  return retval;
}

static int
priv_force_start_virtual(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const unsigned char *s;
  int retval = 0, i, n, x;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  intarray_t uset;
  struct timeval tt;
  long nsec;
  int run_id;
  int first_user_id = 0, last_user_id = -1;

  if (phr->role < USER_ROLE_JUDGE)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (opcaps_check(phr->caps, OPCAP_EDIT_REG) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (!global->is_virtual)
    FAIL(NEW_SRV_ERR_NOT_VIRTUAL);

  memset(&uset, 0, sizeof(uset));
  for (i = 0; i < phr->param_num; i++) {
    if (strncmp(phr->param_names[i], "user_", 5) != 0) continue;
    if (sscanf((s = phr->param_names[i] + 5), "%d%n", &x, &n) != 1
        || s[n] || x <= 0) {
      ns_html_err_inv_param(fout, phr, 1, "invalid parameter name %s",
                            ARMOR(phr->param_names[i]));
      retval = -1;
      goto cleanup;
    }
    if (teamdb_lookup(cs->teamdb_state, x) <= 0)
      FAIL(NEW_SRV_ERR_INV_USER_ID);

    XEXPAND2(uset);
    uset.v[uset.u++] = x;
  }

  priv_parse_user_id_range(phr, &first_user_id, &last_user_id);
  if (first_user_id > 0) {
    for (i = first_user_id; i <= last_user_id; i++) {
      XEXPAND2(uset);
      uset.v[uset.u++] = i;
    }
  }

  gettimeofday(&tt, 0);
  nsec = tt.tv_usec * 1000;
  // FIXME: it's a bit risky, need to check the database...
  if (nsec + uset.u >= 1000000000) nsec = 999999998 - uset.u;

  for (i = 0; i < uset.u; i++, nsec++) {
    run_id = run_virtual_start(cs->runlog_state, uset.v[i], tt.tv_sec,0,0,nsec);
    if (run_id >= 0) serve_move_files_to_insert_run(cs, run_id);
  }

 cleanup:
  xfree(uset.v);
  html_armor_free(&ab);
  return retval;
}

static int
priv_user_disqualify(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int retval = 0;
  const unsigned char *s;
  int user_id, n;
  unsigned char *warn_txt = 0;

  if (opcaps_check(phr->caps, OPCAP_EDIT_REG) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  /* user_id, disq_comment */
  if (ns_cgi_param(phr, "user_id", &s) <= 0
      || sscanf(s, "%d%n", &user_id, &n) != 1 || s[n]
      || teamdb_lookup(cs->teamdb_state, user_id) <= 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);
  if ((n = ns_cgi_param(phr, "disq_comment", &s)) < 0)
    FAIL(NEW_SRV_ERR_INV_WARN_TEXT);
  warn_txt = text_area_process_string(s, 0, 0);

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    ns_html_err_ul_server_down(fout, phr, 1, 0);
    retval = -1;
    goto cleanup;
  }
  n = userlist_clnt_change_registration(ul_conn, user_id,
                                        phr->contest_id, -1, 1,
                                        USERLIST_UC_DISQUALIFIED);
  if (n < 0) {
    ns_error(log_f, NEW_SRV_ERR_USER_FLAGS_CHANGE_FAILED,
             user_id, phr->contest_id, userlist_strerror(-n));
    retval = -1;
    goto cleanup;
  }

  team_extra_set_disq_comment(cs->team_extra_state, user_id, warn_txt);
  team_extra_flush(cs->team_extra_state);

 cleanup:
  xfree(warn_txt);
  return retval;
}

static void
do_schedule(FILE *log_f,
            struct http_request_info *phr,
            serve_state_t cs,
            const struct contest_desc *cnts)
{
  const unsigned char *s = 0;
  int hour = 0, min = 0, sec = 0, year = 0, mon = 0, day = 0, n;
  struct tm loc2;
  struct tm *ploc;
  time_t sloc, start_time, stop_time;

  if (ns_cgi_param(phr, "sched_time", &s) <= 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_TIME_SPEC);
    return;
  }
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
    ns_error(log_f, NEW_SRV_ERR_INV_TIME_SPEC);
    return;
  }

  if ((sloc = mktime(ploc)) == (time_t) -1) {
    ns_error(log_f, NEW_SRV_ERR_INV_TIME_SPEC);
    return;
  }

  run_get_times(cs->runlog_state, &start_time, 0, 0, &stop_time, 0);

  if (stop_time > 0) {
    ns_error(log_f, NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
    return;
  }
  if (start_time > 0) {
    ns_error(log_f, NEW_SRV_ERR_CONTEST_ALREADY_STARTED);
    return;
  }
  run_sched_contest(cs->runlog_state, sloc);
  serve_update_standings_file(cs, cnts, 0);
  serve_update_status_file(cs, 1);
}

static void
do_change_duration(FILE *log_f,
                   struct http_request_info *phr,
                   serve_state_t cs,
                   const struct contest_desc *cnts)
{
  const unsigned char *s = 0;
  int dh = 0, dm = 0, n, d;
  time_t start_time, stop_time;

  if (ns_cgi_param(phr, "dur", &s) <= 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_DUR_SPEC);
    return;
  }
  if (sscanf(s, "%d:%d%n", &dh, &dm, &n) == 2 && !s[n]) {
  } else if (sscanf(s, "%d%n", &dh, &n) == 1 && !s[n]) {
    dm = 0;
  } else {
    ns_error(log_f, NEW_SRV_ERR_INV_DUR_SPEC);
    return;
  }
  d = dh * 60 + dm;
  if (d < 0 || d > 1000000) {
    ns_error(log_f, NEW_SRV_ERR_INV_DUR_SPEC);
    return;
  }
  d *= 60;

  run_get_times(cs->runlog_state, &start_time, 0, 0, &stop_time, 0);

  if (stop_time > 0 && !cs->global->enable_continue) {
    ns_error(log_f, NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
    return;
  }
  if (d > 0 && start_time && start_time + d < cs->current_time) {
    ns_error(log_f, NEW_SRV_ERR_DUR_TOO_SMALL);
    return;
  }

  run_set_duration(cs->runlog_state, d);
  serve_update_standings_file(cs, cnts, 0);
  serve_update_status_file(cs, 1);
  return;
}

static int
priv_contest_operation(FILE *fout,
                       FILE *log_f,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  opcap_t caps;
  time_t start_time, stop_time, duration;

  if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
      || opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  run_get_times(cs->runlog_state, &start_time, 0, &duration, &stop_time, 0);

  switch (phr->action) {
  case NEW_SRV_ACTION_START_CONTEST:
    if (stop_time > 0) {
      ns_error(log_f, NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
      goto cleanup;
    }
    if (start_time > 0) {
      ns_error(log_f, NEW_SRV_ERR_CONTEST_ALREADY_STARTED);
      goto cleanup;
    }
    run_start_contest(cs->runlog_state, cs->current_time);
    serve_update_status_file(cs, 1);
    serve_invoke_start_script(cs);
    serve_update_standings_file(cs, cnts, 0);
    break;

  case NEW_SRV_ACTION_STOP_CONTEST:
    if (stop_time > 0) {
      ns_error(log_f, NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
      goto cleanup;
    }
    if (start_time <= 0) {
      ns_error(log_f, NEW_SRV_ERR_CONTEST_NOT_STARTED);
      goto cleanup;
    }
    run_stop_contest(cs->runlog_state, cs->current_time);
    serve_update_status_file(cs, 1);
    break;

  case NEW_SRV_ACTION_CONTINUE_CONTEST:
    if (!global->enable_continue) {
      ns_error(log_f, NEW_SRV_ERR_CANNOT_CONTINUE_CONTEST);
      goto cleanup;
    }
    if (start_time <= 0) {
      ns_error(log_f, NEW_SRV_ERR_CONTEST_NOT_STARTED);
      goto cleanup;
    }
    if (stop_time <= 0) {
      ns_error(log_f, NEW_SRV_ERR_CONTEST_NOT_FINISHED);
      goto cleanup;
    }
    if (duration > 0 && cs->current_time >= start_time + duration) {
      ns_error(log_f, NEW_SRV_ERR_INSUFFICIENT_DURATION);
      goto cleanup;
    }
    run_set_finish_time(cs->runlog_state, 0);
    run_stop_contest(cs->runlog_state, 0);
    serve_update_status_file(cs, 1);
    break;

  case NEW_SRV_ACTION_SCHEDULE:
    do_schedule(log_f, phr, cs, cnts);
    break;

  case NEW_SRV_ACTION_CHANGE_DURATION:
    do_change_duration(log_f, phr, cs, cnts);
    break;

  case NEW_SRV_ACTION_SUSPEND:
    cs->clients_suspended = 1;
    serve_update_status_file(cs, 1);
    break;

  case NEW_SRV_ACTION_RESUME:
    cs->clients_suspended = 0;
    serve_update_status_file(cs, 1);
    break;

  case NEW_SRV_ACTION_TEST_SUSPEND:
    cs->testing_suspended = 1;
    serve_update_status_file(cs, 1);
    break;

  case NEW_SRV_ACTION_TEST_RESUME:
    cs->testing_suspended = 0;
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

  case NEW_SRV_ACTION_RELOAD_SERVER:
    extra->last_access_time = 0;
    serve_send_run_quit(cs);
    break;

  case NEW_SRV_ACTION_UPDATE_STANDINGS_2:
    serve_update_standings_file(cs, cnts, 1);
    break;

  case NEW_SRV_ACTION_RESET_2:
    serve_reset_contest(cs);
    extra->last_access_time = 0;
    serve_send_run_quit(cs);
    break;

  case NEW_SRV_ACTION_SQUEEZE_RUNS:
    serve_squeeze_runs(cs);
    break;
  }

 cleanup:
  return 0;
}

static int
priv_password_operation(FILE *fout,
                        FILE *log_f,
                        struct http_request_info *phr,
                        const struct contest_desc *cnts,
                        struct contest_extra *extra)
{
  int retval = 0, r = 0;

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    ns_html_err_ul_server_down(fout, phr, 0, 0);
    FAIL(1);
  }

  switch (phr->action) {
  case NEW_SRV_ACTION_GENERATE_PASSWORDS_2:
    if (opcaps_check(phr->caps, OPCAP_EDIT_USER) < 0
        && opcaps_check(phr->dbcaps, OPCAP_EDIT_USER) < 0)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    if (cnts->disable_team_password) FAIL(NEW_SRV_ERR_TEAM_PWD_DISABLED);
    r = userlist_clnt_cnts_passwd_op(ul_conn,
                                     ULS_GENERATE_TEAM_PASSWORDS_2,
                                     cnts->id);
    break;
  case NEW_SRV_ACTION_GENERATE_REG_PASSWORDS_2:
    if (opcaps_check(phr->dbcaps, OPCAP_EDIT_USER) < 0)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    r = userlist_clnt_cnts_passwd_op(ul_conn,
                                     ULS_GENERATE_PASSWORDS_2,
                                     cnts->id);
    break;
  case NEW_SRV_ACTION_CLEAR_PASSWORDS_2:
    if (opcaps_check(phr->caps, OPCAP_EDIT_USER) < 0
        && opcaps_check(phr->dbcaps, OPCAP_EDIT_USER) < 0)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    if (cnts->disable_team_password) FAIL(NEW_SRV_ERR_TEAM_PWD_DISABLED);
    r = userlist_clnt_cnts_passwd_op(ul_conn,
                                     ULS_CLEAR_TEAM_PASSWORDS,
                                     cnts->id);
    break;
  }
  if (r < 0) {
    ns_error(log_f, NEW_SRV_ERR_PWD_UPDATE_FAILED, userlist_strerror(-r));
    goto cleanup;
  }

 cleanup:
  return retval;
}

static int
priv_change_language(FILE *fout,
                     FILE *log_f,
                     struct http_request_info *phr,
                     const struct contest_desc *cnts,
                     struct contest_extra *extra)
{
  const unsigned char *s;
  int r, n;
  int new_locale_id;

  if ((r = ns_cgi_param(phr, "locale_id", &s)) < 0) goto invalid_param;
  if (r > 0) {
    if (sscanf(s, "%d%n", &new_locale_id, &n) != 1 || s[n] || new_locale_id < 0)
      goto invalid_param;
  }

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    ns_html_err_ul_server_down(fout, phr, 0, 0);
    return -1;
  }
  if ((r = userlist_clnt_set_cookie(ul_conn, ULS_SET_COOKIE_LOCALE,
                                    phr->session_id,
                                    new_locale_id)) < 0) {
    ns_error(log_f, NEW_SRV_ERR_SESSION_UPDATE_FAILED, userlist_strerror(-r));
  }
  return 0;

 invalid_param:
  ns_error(log_f, NEW_SRV_ERR_INV_LOCALE_ID);
  return 0;
}

static void
priv_change_password(FILE *fout,
                     struct http_request_info *phr,
                     const struct contest_desc *cnts,
                     struct contest_extra *extra)
{
  const unsigned char *p0 = 0, *p1 = 0, *p2 = 0;
  char *log_txt = 0;
  size_t log_len = 0;
  FILE *log_f = 0;
  int cmd, r;
  unsigned char url[1024];
  unsigned char login_buf[256];

  if (ns_cgi_param(phr, "oldpasswd", &p0) <= 0)
    return ns_html_err_inv_param(fout, phr, 1, "cannot parse oldpasswd");
  if (ns_cgi_param(phr, "newpasswd1", &p1) <= 0)
    return ns_html_err_inv_param(fout, phr, 1, "cannot parse newpasswd1");
  if (ns_cgi_param(phr, "newpasswd2", &p2) <= 0)
    return ns_html_err_inv_param(fout, phr, 1, "cannot parse newpasswd2");

  log_f = open_memstream(&log_txt, &log_len);

  if (strlen(p0) >= 256) {
    ns_error(log_f, NEW_SRV_ERR_OLD_PWD_TOO_LONG);
    goto done;
  }
  if (strcmp(p1, p2)) {
    ns_error(log_f, NEW_SRV_ERR_NEW_PWD_MISMATCH);
    goto done;
  }
  if (strlen(p1) >= 256) {
    ns_error(log_f, NEW_SRV_ERR_NEW_PWD_TOO_LONG);
    goto done;
  }

  cmd = ULS_PRIV_SET_REG_PASSWD;

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    ns_html_err_ul_server_down(fout, phr, 1, 0);
    goto cleanup;
  }
  r = userlist_clnt_set_passwd(ul_conn, cmd, phr->user_id, phr->contest_id,
                               p0, p1);
  if (r < 0) {
    ns_error(log_f, NEW_SRV_ERR_PWD_UPDATE_FAILED, userlist_strerror(-r));
    goto done;
  }

 done:;
  fclose(log_f); log_f = 0;
  if (!log_txt || !*log_txt) {
    url_armor_string(login_buf, sizeof(login_buf), phr->login);
    snprintf(url, sizeof(url),
             "%s?contest_id=%d&role=%d&login=%s&locale_id=%d&action=%d",
             phr->self_url, phr->contest_id, phr->role,
             login_buf, phr->locale_id,
             NEW_SRV_ACTION_LOGIN_PAGE);
    ns_refresh_page_2(fout, url);
  } else {
    html_error_status_page(fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_MAIN_PAGE, 0);
  }

 cleanup:;
  if (log_f) fclose(log_f);
  xfree(log_txt);
}

static int
priv_reset_filter(FILE *fout,
                  FILE *log_f,
                  struct http_request_info *phr,
                  const struct contest_desc *cnts,
                  struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;

  switch (phr->action) {
  case NEW_SRV_ACTION_RESET_FILTER:
    html_reset_filter(cs, phr->user_id, phr->session_id);
    break;

  case NEW_SRV_ACTION_RESET_CLAR_FILTER:
    html_reset_clar_filter(cs, phr->user_id, phr->session_id);
    break;
  }
  return 0;
}

static int
priv_submit_run(FILE *fout,
                FILE *log_f,
                struct http_request_info *phr,
                const struct contest_desc *cnts,
                struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = 0;
  const struct section_language_data *lang = 0;
  const unsigned char *s;
  int prob_id = 0, variant = 0, lang_id = 0, n, max_ans, ans, i, mime_type = 0;
  const unsigned char *errmsg = 0;
  const unsigned char *run_text;
  size_t run_size, ans_size;
  unsigned char *ans_map = 0, *ans_buf = 0, *ans_tmp = 0;
  char **lang_list = 0;
  const unsigned char *mime_type_str = 0;
  int run_id, arch_flags, retval = 0;
  ruint32_t shaval[5];
  struct timeval precise_time;
  path_t run_path;
  struct problem_plugin_iface *plg = 0;

  if (ns_cgi_param(phr, "problem", &s) <= 0) {
    errmsg = "problem is not set or binary";
    goto invalid_param;
  }
  if (sscanf(s, "%d_%d%n", &prob_id, &variant, &n) == 2 && !s[n]) {
    if (prob_id <= 0 || prob_id > cs->max_prob
        || !(prob = cs->probs[prob_id])) {
      errmsg = "invalid prob_id";
      goto invalid_param;
    }
    if (prob->variant_num <= 0 || variant <= 0 || variant > prob->variant_num) {
      errmsg = "invalid variant";
      goto invalid_param;
    }
  } else if (sscanf(s, "%d%n", &prob_id, &n) == 1 && !s[n]) {
    if (prob_id <= 0 || prob_id > cs->max_prob
        || !(prob = cs->probs[prob_id])) {
      errmsg = "invalid prob_id";
      goto invalid_param;
    }
    if (prob->variant_num > 0) {
      errmsg = "invalid variant";
      goto invalid_param;
    }
  } else {
    errmsg = "cannot parse problem";
    goto invalid_param;
  }

  if (prob->type_val == PROB_TYPE_STANDARD) {
    if (ns_cgi_param(phr, "lang_id", &s) <= 0) {
      errmsg = "lang_id is not set or binary";
      goto invalid_param;
    }
    if (sscanf(s, "%d%n", &lang_id, &n) != 1 || s[n]) {
      errmsg = "cannot parse lang_id";
      goto invalid_param;
    }
    if (lang_id <= 0 || lang_id > cs->max_lang || !(lang = cs->langs[lang_id])){
      errmsg = "lang_id is invalid";
      goto invalid_param;
    }
  }

  /* get the submission text */
  switch (prob->type_val) {
  case PROB_TYPE_STANDARD:      // "file"
  case PROB_TYPE_OUTPUT_ONLY:
  case PROB_TYPE_TEXT_ANSWER:
  case PROB_TYPE_SHORT_ANSWER:
  case PROB_TYPE_SELECT_ONE:
    if (!ns_cgi_param_bin(phr, "file", &run_text, &run_size)) {
      errmsg = "\"file\" parameter is not set";
      goto invalid_param;
    }
    break;
  case PROB_TYPE_SELECT_MANY:   // "ans_*"
    for (i = 0, max_ans = -1, ans_size = 0; i < phr->param_num; i++)
      if (!strncmp(phr->param_names[i], "ans_", 4)) {
        if (sscanf(phr->param_names[i] + 4, "%d%n", &ans, &n) != 1
            || phr->param_names[i][4 + n]) {
          errmsg = "\"ans_*\" parameter is invalid";
          goto invalid_param;
        }
        if (ans < 0 || ans > 65535) {
          errmsg = "\"ans_*\" parameter is out of range";
          goto invalid_param;
        }
        if (ans > max_ans) max_ans = ans;
        ans_size += 7;
      }
    if (max_ans < 0) {
      run_text = "";
      run_size = 0;
      break;
    }
    XALLOCAZ(ans_map, max_ans + 1);
    for (i = 0; i < phr->param_num; i++)
      if (!strncmp(phr->param_names[i], "ans_", 4)) {
        sscanf(phr->param_names[i] + 4, "%d", &ans);
        ans_map[ans] = 1;
      }
    XALLOCA(ans_buf, ans_size);
    run_text = ans_buf;
    for (i = 0, run_size = 0; i <= max_ans; i++)
      if (ans_map[i]) {
        if (run_size > 0) ans_buf[run_size++] = ' ';
        run_size += sprintf(ans_buf + run_size, "%d", i);
      }
    ans_buf[run_size++] = '\n';
    ans_buf[run_size] = 0;
    break;
  case PROB_TYPE_CUSTOM:   // use problem plugin
    load_problem_plugin(cs, prob_id);
    if (!(plg = cs->prob_extras[prob_id].plugin) || !plg->parse_form) {
      errmsg = "problem plugin is not available";
      goto invalid_param;
    }
    ans_tmp = (*plg->parse_form)(cs->prob_extras[prob_id].plugin_data,
                                 log_f, phr, cnts, extra);
    if (!ans_tmp) goto cleanup;
    run_size = strlen(ans_tmp);
    ans_buf = (unsigned char*) alloca(run_size + 1);
    strcpy(ans_buf, ans_tmp);
    run_text = ans_buf;
    xfree(ans_tmp);
    break;
  default:
    abort();
  }

  switch (prob->type_val) {
  case PROB_TYPE_STANDARD:
    if (!lang->binary && strlen(run_text) != run_size) goto binary_submission;
    break;

  case PROB_TYPE_OUTPUT_ONLY:
    if (!prob->binary_input && strlen(run_text) != run_size)
      goto binary_submission;
    break;

  case PROB_TYPE_TEXT_ANSWER:
  case PROB_TYPE_SHORT_ANSWER:
  case PROB_TYPE_SELECT_ONE:
    if (strlen(run_text) != run_size) goto binary_submission;
    break;

  case PROB_TYPE_SELECT_MANY:
  case PROB_TYPE_CUSTOM:
    break;

  binary_submission:
    errmsg = "binary submission";
    goto invalid_param;
  }

  /* check for disabled languages */
  if (lang_id > 0) {
    if (lang->disabled) {
      ns_error(log_f, NEW_SRV_ERR_LANG_DISABLED);
      goto cleanup;
    }

    if (prob->enable_language) {
      lang_list = prob->enable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], lang->short_name))
          break;
      if (!lang_list[i]) {
        ns_error(log_f, NEW_SRV_ERR_LANG_NOT_AVAIL_FOR_PROBLEM);
        goto cleanup;
      }
    } else if (prob->disable_language) {
      lang_list = prob->disable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], lang->short_name))
          break;
      if (lang_list[i]) {
        ns_error(log_f, NEW_SRV_ERR_LANG_DISABLED_FOR_PROBLEM);
        goto cleanup;
      }
    }
  } else {
    // guess the content-type and check it against the list
    if ((mime_type = mime_type_guess(global->diff_work_dir,
                                     run_text, run_size)) < 0) {
      ns_error(log_f, NEW_SRV_ERR_CANNOT_DETECT_CONTENT_TYPE);
      goto cleanup;
    }
    mime_type_str = mime_type_get_type(mime_type);
    if (prob->enable_language) {
      lang_list = prob->enable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], mime_type_str))
          break;
      if (!lang_list[i]) {
        ns_error(log_f, NEW_SRV_ERR_CONTENT_TYPE_NOT_AVAILABLE, mime_type_str);
        goto cleanup;
      }
    } else if (prob->disable_language) {
      lang_list = prob->disable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], mime_type_str))
          break;
      if (lang_list[i]) {
        ns_error(log_f, NEW_SRV_ERR_CONTENT_TYPE_DISABLED, mime_type_str);
        goto cleanup;
      }
    }
  }

  // OK, so all checks are done, now we add this submit to the database
  sha_buffer(run_text, run_size, shaval);
  gettimeofday(&precise_time, 0);

  run_id = run_add_record(cs->runlog_state, 
                          precise_time.tv_sec, precise_time.tv_usec * 1000,
                          run_size, shaval,
                          phr->ip, phr->ssl_flag,
                          phr->locale_id, phr->user_id,
                          prob_id, lang_id, variant, 1, mime_type);
  if (run_id < 0) {
    ns_error(log_f, NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
    goto cleanup;
  }
  serve_move_files_to_insert_run(cs, run_id);
                          
  arch_flags = archive_make_write_path(cs, run_path, sizeof(run_path),
                                       global->run_archive_dir, run_id,
                                       run_size, 0);
  if (arch_flags < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto cleanup;
  }
  if (archive_dir_prepare(cs, global->run_archive_dir, run_id, 0, 0) < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto cleanup;
  }
  if (generic_write_file(run_text, run_size, arch_flags, 0, run_path, "") < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto cleanup;
  }

  if (prob->type_val == PROB_TYPE_STANDARD) {
    // automatically tested programs
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
                                lang->compiler_env, -1, 0, prob, lang) < 0) {
        ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
        goto cleanup;
      }
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
      if (serve_run_request(cs, log_f, run_text, run_size, run_id,
                            phr->user_id, prob_id, 0, variant, 0, -1, -1,
                            0, 0) < 0) {
        ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
        goto cleanup;
      }
      serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                      "Command: submit\n"
                      "Status: ok\n"
                      "Run-id: %d\n", run_id);
    }
  } else {
    // automatically tested outputs
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
      /* FIXME: check for XML problem */
      if (serve_run_request(cs, log_f, run_text, run_size, run_id,
                            phr->user_id, prob_id, 0, variant, 0, -1, -1,
                            0, 0) < 0) {
        ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
        goto cleanup;
      }
      serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                      "Command: submit\n"
                      "Status: ok\n"
                      "Run-id: %d\n", run_id);
    }
  }

 cleanup:
  return retval;

 invalid_param:
  ns_html_err_inv_param(fout, phr, 0, errmsg);
  return -1;
}

static int
priv_submit_clar(FILE *fout,
                 FILE *log_f,
                 struct http_request_info *phr,
                 const struct contest_desc *cnts,
                 struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  int n, user_id = -1, hide_flag = 0, clar_id;
  const unsigned char *s;
  struct html_armor_buffer ab;
  const unsigned char *errmsg;
  const unsigned char *subject = 0, *text = 0;
  size_t subj_len, text_len, text3_len;
  unsigned char *subj2, *text2, *text3;
  path_t clar_file;
  struct timeval precise_time;

  html_armor_init(&ab);

  // msg_dest_id, msg_dest_login, msg_subj, msg_hide_flag, msg_text
  if ((n = ns_cgi_param(phr, "msg_dest_id", &s)) < 0) {
    errmsg = "msg_dest_id is binary";
    goto invalid_param;
  }
  if (n > 0 && *s) {
    if (sscanf(s, "%d%n", &user_id, &n) != 1 || s[n]) {
      errmsg = "msg_dest_id is invalid";
      goto invalid_param;
    }
    if (user_id && !teamdb_lookup(cs->teamdb_state, user_id)) {
      ns_error(log_f, NEW_SRV_ERR_USER_ID_NONEXISTANT, user_id);
      goto cleanup;
    }
  }
  if ((n = ns_cgi_param(phr, "msg_dest_login", &s)) < 0) {
    errmsg = "msg_dest_login is binary";
    goto invalid_param;
  }
  if (n > 0 && *s) {
    if (!strcasecmp(s, "all")) {
      if (user_id > 0) {
        ns_error(log_f, NEW_SRV_ERR_CONFLICTING_USER_ID_LOGIN,
                 user_id, ARMOR(s));
        goto cleanup;
      }
      user_id = 0;
    } else {
      if ((n = teamdb_lookup_login(cs->teamdb_state, s)) <= 0) {
        ns_error(log_f, NEW_SRV_ERR_USER_LOGIN_NONEXISTANT, ARMOR(s));
        goto cleanup;
      }
      if (user_id >= 0 && user_id != n) {
        ns_error(log_f, NEW_SRV_ERR_CONFLICTING_USER_ID_LOGIN,
                 user_id, ARMOR(s));
        goto cleanup;
      }
      user_id = n;
    }
  }
  if ((n = ns_cgi_param(phr, "msg_subj", &subject)) < 0) {
    errmsg = "msg_subj is binary";
    goto invalid_param;
  }
  if (!subject) subject = "";
  if ((n = ns_cgi_param(phr, "msg_text", &text)) < 0) {
    errmsg = "msg_text is binary";
    goto invalid_param;
  }
  if (!text) text = "";
  if ((n = ns_cgi_param(phr, "msg_hide_flag", &s)) < 0) {
    errmsg = "msg_hide_flag is binary";
    goto invalid_param;
  }
  if (n > 0) {
    if (sscanf(s, "%d%n", &hide_flag, &n) != 1 || s[n]
        || hide_flag < 0 || hide_flag > 1) {
      errmsg = "msg_hide_flag is invalid";
      goto invalid_param;
    }
  }

  subj_len = strlen(subject);
  if (subj_len > 1024) {
    ns_error(log_f, NEW_SRV_ERR_SUBJECT_TOO_LONG, subj_len);
    goto cleanup;
  }
  subj2 = alloca(subj_len + 1);
  memcpy(subj2, subject, subj_len + 1);
  while (subj_len > 0 && isspace(subj2[subj_len - 1])) subj2[--subj_len] = 0;
  if (!subj_len) {
    ns_error(log_f, NEW_SRV_ERR_SUBJECT_EMPTY);
    goto cleanup;
  }

  text_len = strlen(text);
  if (text_len > 128 * 1024 * 1024) {
    ns_error(log_f, NEW_SRV_ERR_MESSAGE_TOO_LONG, subj_len);
    goto cleanup;
  }
  text2 = alloca(text_len + 1);
  memcpy(text2, text, text_len + 1);
  while (text_len > 0 && isspace(text2[text_len - 1])) text2[--text_len] = 0;
  if (!text_len) {
    ns_error(log_f, NEW_SRV_ERR_MESSAGE_EMPTY);
    goto cleanup;
  }

  text3 = alloca(subj_len + text_len + 32);
  text3_len = sprintf(text3, "Subject: %s\n\n%s\n", subj2, text2);

  gettimeofday(&precise_time, 0);
  if ((clar_id = clar_add_record_new(cs->clarlog_state,
                                     precise_time.tv_sec,
                                     precise_time.tv_usec * 1000,
                                     text3_len,
                                     phr->ip, phr->ssl_flag,
                                     0, user_id, 0, phr->user_id,
                                     hide_flag, phr->locale_id, 0, 0,
                                     utf8_mode, subj2)) < 0) {
    ns_error(log_f, NEW_SRV_ERR_CLARLOG_UPDATE_FAILED);
    goto cleanup;
  }

  sprintf(clar_file, "%06d", clar_id);
  if (generic_write_file(text3, text3_len, 0,
                         global->clar_archive_dir, clar_file, "") < 0) {
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto cleanup;
  }

  /*
  serve_send_clar_notify_email(cs, cnts, phr->user_id, phr->name, subj3, text2);
  */

 cleanup:
  html_armor_free(&ab);
  return 0;

 invalid_param:
  ns_html_err_inv_param(fout, phr, 0, errmsg);
  return -1;
}

static int
priv_clar_reply(FILE *fout,
                FILE *log_f,
                struct http_request_info *phr,
                const struct contest_desc *cnts,
                struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const unsigned char *errmsg;
  const unsigned char *s, *reply_txt;
  int in_reply_to, n, clar_id, from_id;
  struct clar_entry_v1 clar;
  unsigned char *reply_txt_2;
  size_t reply_len;
  path_t orig_clar_name, clar_name;
  char *orig_txt = 0;
  size_t orig_txt_len = 0;
  unsigned char *new_subj, *quoted, *msg;
  size_t new_subj_len, quoted_len, msg_len;
  struct timeval precise_time;

  // reply, in_reply_to
  if (ns_cgi_param(phr, "in_reply_to", &s) <= 0
      || sscanf(s, "%d%n", &in_reply_to, &n) != 1 || s[n]
      || in_reply_to < 0 || in_reply_to >= clar_get_total(cs->clarlog_state)) {
    errmsg = "in_reply_to parameter is invalid";
    goto invalid_param;
  }

  switch (phr->action) {
  case NEW_SRV_ACTION_CLAR_REPLY:
  case NEW_SRV_ACTION_CLAR_REPLY_ALL:
    if (ns_cgi_param(phr, "reply", &reply_txt) <= 0) {
      errmsg = "reply parameter is invalid";
      goto invalid_param;
    }
  }

  if (opcaps_check(phr->caps, OPCAP_REPLY_MESSAGE) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  if (clar_get_record_new(cs->clarlog_state, in_reply_to, &clar) < 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_CLAR_ID);
    goto cleanup;
  }

  if (!clar.from) {
    ns_error(log_f, NEW_SRV_ERR_CANNOT_REPLY_TO_JUDGE);
    goto cleanup;
  }

  l10n_setlocale(clar.locale_id);
  switch (phr->action) {
  case NEW_SRV_ACTION_CLAR_REPLY_READ_PROBLEM:
    reply_txt = _("Read the problem.");
    break;
  case NEW_SRV_ACTION_CLAR_REPLY_NO_COMMENTS:
    reply_txt = _("No comments.");
    break;
  case NEW_SRV_ACTION_CLAR_REPLY_YES:
    reply_txt = _("Yes.");
    break;
  case NEW_SRV_ACTION_CLAR_REPLY_NO:
    reply_txt = _("No.");
    break;
  }
  l10n_setlocale(0);

  reply_len = strlen(reply_txt);
  if (reply_len > 128 * 1024 * 1024) {
    ns_error(log_f, NEW_SRV_ERR_MESSAGE_TOO_LONG, reply_len);
    goto cleanup;
  }
  reply_txt_2 = (unsigned char*) alloca(reply_len + 1);
  memcpy(reply_txt_2, reply_txt, reply_len + 1);
  while (reply_len > 0 && isspace(reply_txt_2[reply_len - 1])) reply_len--;
  reply_txt_2[reply_len] = 0;
  if (!reply_len) {
    ns_error(log_f, NEW_SRV_ERR_MESSAGE_EMPTY);
    goto cleanup;
  }

  snprintf(orig_clar_name, sizeof(orig_clar_name), "%06d", in_reply_to);
  if (generic_read_file(&orig_txt, 0, &orig_txt_len, 0,
                        global->clar_archive_dir, orig_clar_name, "") < 0) {
    ns_error(log_f, NEW_SRV_ERR_DISK_READ_ERROR);
    goto cleanup;
  }

  l10n_setlocale(clar.locale_id);
  new_subj = alloca(orig_txt_len + 64);
  new_subj_len = message_reply_subj(orig_txt, new_subj);
  l10n_setlocale(0);

  quoted_len = message_quoted_size(orig_txt);
  quoted = alloca(quoted_len + 16);
  message_quote(orig_txt, quoted);

  msg = alloca(reply_len + quoted_len + new_subj_len + 64);
  msg_len = sprintf(msg, "%s%s\n%s\n", new_subj, quoted, reply_txt_2);

  from_id = clar.from;
  if (phr->action == NEW_SRV_ACTION_CLAR_REPLY_ALL) from_id = 0;

  gettimeofday(&precise_time, 0);
  clar_id = clar_add_record_new(cs->clarlog_state,
                                precise_time.tv_sec,
                                precise_time.tv_usec * 1000,
                                msg_len,
                                phr->ip, phr->ssl_flag,
                                0, from_id, 0, phr->user_id, 0,
                                clar.locale_id, in_reply_to + 1, 0,
                                utf8_mode, clar.subj);

  if (clar_id < 0) {
    ns_error(log_f, NEW_SRV_ERR_CLARLOG_UPDATE_FAILED);
    goto cleanup;
  }

  snprintf(clar_name, sizeof(clar_name), "%06d", clar_id);
  if (generic_write_file(msg, msg_len, 0, global->clar_archive_dir,
                         clar_name, "") < 0) {
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto cleanup;
  }

  clar_update_flags(cs->clarlog_state, in_reply_to, 2);

 cleanup:
  xfree(orig_txt);
  return 0;

 invalid_param:
  ns_html_err_inv_param(fout, phr, 0, errmsg);
  return -1;
}

static int
parse_run_id(FILE *fout, struct http_request_info *phr,
             const struct contest_desc *cnts,
             struct contest_extra *extra, int *p_run_id, struct run_entry *pe)
{
  const serve_state_t cs = extra->serve_state;
  int n, run_id;
  const unsigned char *s = 0, *errmsg = 0;
  unsigned char msgbuf[1024];
  
  if (!(n = ns_cgi_param(phr, "run_id", &s))) {
    errmsg = ns_strerror_r(msgbuf, sizeof(msgbuf),
                           NEW_SRV_ERR_RUN_ID_UNDEFINED);
    goto failure;
  }
  if (n < 0 || sscanf(s, "%d%n", &run_id, &n) != 1 || s[n]) {
    errmsg = ns_strerror_r(msgbuf, sizeof(msgbuf), NEW_SRV_ERR_INV_RUN_ID);
    goto failure;
  }
  if (run_id < 0 || run_id >= run_get_total(cs->runlog_state)) {
    errmsg = ns_strerror_r(msgbuf, sizeof(msgbuf),
                           NEW_SRV_ERR_INV_RUN_ID, run_id);
    goto failure;
  }

  if (p_run_id) *p_run_id = run_id;
  if (pe && run_get_entry(cs->runlog_state, run_id, pe) < 0) {
    errmsg = ns_strerror_r(msgbuf, sizeof(msgbuf),
                           NEW_SRV_ERR_RUNLOG_READ_FAILED, run_id);
    goto failure;
  }

  return 0;

 failure:
  html_error_status_page(fout, phr, cnts, extra, errmsg,
                         ns_priv_prev_state[phr->action], 0);
  return -1;
}

static int
priv_print_run_cmd(FILE *fout, FILE *log_f,
                   struct http_request_info *phr,
                   const struct contest_desc *cnts,
                   struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int retval = 0, run_id = -1;

  if (parse_run_id(fout, phr, cnts, extra, &run_id, 0) < 0) {
    retval = -1;
    goto cleanup;
  }
  if (opcaps_check(phr->caps, OPCAP_PRINT_RUN) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (priv_print_run(cs, run_id, phr->user_id) < 0)
    FAIL(NEW_SRV_ERR_PRINTING_FAILED);

 cleanup:
  return retval;
}

static int
priv_clear_run(FILE *fout, FILE *log_f,
               struct http_request_info *phr,
               const struct contest_desc *cnts,
               struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  int retval = 0, run_id = -1;

  if (parse_run_id(fout, phr, cnts, extra, &run_id, 0) < 0) {
    retval = -1;
    goto cleanup;
  }
  if (opcaps_check(phr->caps, OPCAP_CONTROL_CONTEST) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (run_is_readonly(cs->runlog_state, run_id))
    FAIL(NEW_SRV_ERR_RUN_READ_ONLY);
  if (run_clear_entry(cs->runlog_state, run_id) < 0)
    FAIL(NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);

  archive_remove(cs, global->run_archive_dir, run_id, 0);
  archive_remove(cs, global->xml_report_archive_dir, run_id, 0);
  archive_remove(cs, global->report_archive_dir, run_id, 0);
  if (global->team_enable_rep_view) {
    archive_remove(cs, global->team_report_archive_dir, run_id, 0);
  }
  if (global->enable_full_archive) {
    archive_remove(cs, global->full_archive_dir, run_id, 0);
  }
  archive_remove(cs, global->audit_log_dir, run_id, 0);

 cleanup:
  return retval;
}

/*
 * what we gonna handle here
 * NEW_SRV_ACTION_CHANGE_RUN_USER_ID
 * NEW_SRV_ACTION_CHANGE_RUN_USER_LOGIN
 * NEW_SRV_ACTION_CHANGE_RUN_PROB_ID
 * NEW_SRV_ACTION_CHANGE_RUN_VARIANT
 * NEW_SRV_ACTION_CHANGE_RUN_LANG_ID
 * NEW_SRV_ACTION_CHANGE_RUN_IS_IMPORTED
 * NEW_SRV_ACTION_CHANGE_RUN_IS_HIDDEN
 * NEW_SRV_ACTION_CHANGE_RUN_IS_EXAMINABLE
 * NEW_SRV_ACTION_CHANGE_RUN_IS_READONLY
 * NEW_SRV_ACTION_CHANGE_RUN_TEST
 * NEW_SRV_ACTION_CHANGE_RUN_SCORE
 * NEW_SRV_ACTION_CHANGE_RUN_SCORE_ADJ
 * NEW_SRV_ACTION_CHANGE_RUN_PAGES
 */
static int
priv_edit_run(FILE *fout, FILE *log_f,
              struct http_request_info *phr,
              const struct contest_desc *cnts,
              struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = 0;
  int retval = 0, run_id = -1, n;
  struct run_entry re, ne;
  const unsigned char *s, *param_str = 0;
  int param_int = 0, param_bool = 0;
  int ne_mask = 0;

  if (parse_run_id(fout, phr, cnts, extra, &run_id, &re) < 0) return -1;
  if (ns_cgi_param(phr, "param", &s) <= 0) {
    ns_html_err_inv_param(fout, phr, 1, "param is not set");
    return -1;
  }
  snprintf(phr->next_extra, sizeof(phr->next_extra), "run_id=%d", run_id);

  if (opcaps_check(phr->caps, OPCAP_EDIT_RUN) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  switch (phr->action) {
  case NEW_SRV_ACTION_CHANGE_RUN_USER_LOGIN:
    param_str = s;
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_USER_ID:
  case NEW_SRV_ACTION_CHANGE_RUN_PROB_ID:
  case NEW_SRV_ACTION_CHANGE_RUN_VARIANT:
  case NEW_SRV_ACTION_CHANGE_RUN_LANG_ID:
  case NEW_SRV_ACTION_CHANGE_RUN_TEST:
  case NEW_SRV_ACTION_CHANGE_RUN_SCORE:
  case NEW_SRV_ACTION_CHANGE_RUN_SCORE_ADJ:
  case NEW_SRV_ACTION_CHANGE_RUN_PAGES:
    if (sscanf(s, "%d%n", &param_int, &n) != 1 || s[n]) {
      ns_html_err_inv_param(fout, phr, 1, "invalid integer param");
      return -1;
    }
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_IS_IMPORTED:
  case NEW_SRV_ACTION_CHANGE_RUN_IS_HIDDEN:
  case NEW_SRV_ACTION_CHANGE_RUN_IS_EXAMINABLE:
  case NEW_SRV_ACTION_CHANGE_RUN_IS_READONLY:
    if (sscanf(s, "%d%n", &param_bool, &n) != 1 || s[n]
        || param_bool < 0 || param_bool > 1) {
      ns_html_err_inv_param(fout, phr, 1, "invalid boolean param");
      return -1;
    }
    break;
  default:
    ns_error(log_f, NEW_SRV_ERR_UNHANDLED_ACTION, phr->action);
    goto cleanup;
  }

  if (re.is_readonly && phr->action != NEW_SRV_ACTION_CHANGE_RUN_IS_READONLY)
    FAIL(NEW_SRV_ERR_RUN_READ_ONLY);

  memset(&ne, 0, sizeof(ne));
  switch (phr->action) {
  case NEW_SRV_ACTION_CHANGE_RUN_USER_LOGIN:
    if ((ne.user_id = teamdb_lookup_login(cs->teamdb_state, param_str)) <= 0)
      FAIL(NEW_SRV_ERR_INV_USER_LOGIN);
    ne_mask = RUN_ENTRY_USER;
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_USER_ID:
    if (teamdb_lookup(cs->teamdb_state, param_int) <= 0)
      FAIL(NEW_SRV_ERR_INV_USER_ID);
    ne.user_id = param_int;
    ne_mask = RUN_ENTRY_USER;
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_PROB_ID:
    if (param_int <= 0 || param_int > cs->max_prob || !cs->probs[param_int])
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
    ne.prob_id = param_int;
    ne_mask = RUN_ENTRY_PROB;
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_VARIANT:
    if (re.prob_id <= 0 || re.prob_id > cs->max_prob
        || !(prob = cs->probs[re.prob_id]))
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
    if (prob->variant_num <= 0) {
      if (param_int)
        FAIL(NEW_SRV_ERR_INV_VARIANT);
    } else {
      if (param_int < 0 || param_int > prob->variant_num)
        FAIL(NEW_SRV_ERR_INV_VARIANT);
      if (!param_int && find_variant(cs, re.user_id, re.prob_id, 0) <= 0)
        FAIL(NEW_SRV_ERR_VARIANT_UNASSIGNED);
    }
    ne.variant = param_int;
    ne_mask = RUN_ENTRY_VARIANT;
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_LANG_ID:
    if (param_int <= 0 || param_int > cs->max_lang || !cs->langs[param_int])
      FAIL(NEW_SRV_ERR_INV_LANG_ID);
    ne.lang_id = param_int;
    ne_mask = RUN_ENTRY_LANG;
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_TEST:
    if (param_int < -1 || param_int >= 100000)
      FAIL(NEW_SRV_ERR_INV_TEST);
    if (global->score_system_val == SCORE_KIROV
        || global->score_system_val == SCORE_OLYMPIAD)
      param_int++;
    ne.test = param_int;
    ne_mask = RUN_ENTRY_TEST;
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_SCORE:
    /*
    if (global->score_system_val == SCORE_ACM
        || (global->score_system_val == SCORE_OLYMPIAD && cs->accepting_mode))
      FAIL(NEW_SRV_ERR_INV_PARAM);
    */
    if (re.prob_id <= 0 || re.prob_id > cs->max_prob
        || !(prob = cs->probs[re.prob_id]))
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
    if (param_int < 0 || param_int > prob->full_score)
      FAIL(NEW_SRV_ERR_INV_SCORE);
    ne.score = param_int;
    ne_mask = RUN_ENTRY_SCORE;
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_SCORE_ADJ:
    if (global->score_system_val != SCORE_KIROV
        && (global->score_system_val != SCORE_OLYMPIAD || cs->accepting_mode))
      FAIL(NEW_SRV_ERR_INV_PARAM);
    if (param_int <= -100000 || param_int >= 100000)
      FAIL(NEW_SRV_ERR_INV_SCORE_ADJ);
    ne.score_adj = param_int;
    ne_mask = RUN_ENTRY_SCORE_ADJ;
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_PAGES:
    if (param_int < 0 || param_int >= 100000)
      FAIL(NEW_SRV_ERR_INV_PAGES);
    ne.pages = param_int;
    ne_mask = RUN_ENTRY_PAGES;
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_IS_IMPORTED:
    ne.is_imported = param_bool;
    ne_mask = RUN_ENTRY_IMPORTED;
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_IS_HIDDEN:
    ne.is_hidden = param_bool;
    ne_mask = RUN_ENTRY_HIDDEN;
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_IS_EXAMINABLE:
    ne.is_examinable = param_bool;
    ne_mask = RUN_ENTRY_EXAMINABLE;
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_IS_READONLY:
    ne.is_readonly = param_bool;
    ne_mask = RUN_ENTRY_READONLY;
    break;
  }

  if (!ne_mask) goto cleanup;

  if (run_set_entry(cs->runlog_state, run_id, ne_mask, &ne) < 0)
    FAIL(NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);

 cleanup:
  return retval;
}

/*
 * NEW_SRV_ACTION_CHANGE_RUN_STATUS:
 */
static int
priv_change_status(FILE *fout,
                   FILE *log_f,
                   struct http_request_info *phr,
                   const struct contest_desc *cnts,
                   struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const unsigned char *errmsg = 0, *s;
  int run_id, n, status, flags;
  struct run_entry new_run;

  // run_id, status
  if (parse_run_id(fout, phr, cnts, extra, &run_id, 0) < 0) goto failure;
  snprintf(phr->next_extra, sizeof(phr->next_extra), "run_id=%d", run_id);
  if (ns_cgi_param(phr, "status", &s) <= 0
      || sscanf(s, "%d%n", &status, &n) != 1 || s[n]
      || status < 0 || status > RUN_LAST) {
    errmsg = "invalid status";
    goto invalid_param;
  }
  if (opcaps_check(phr->caps, OPCAP_EDIT_RUN) < 0
      && ((status != RUN_REJUDGE && status != RUN_FULL_REJUDGE)
          || opcaps_check(phr->caps, OPCAP_REJUDGE_RUN))) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }
  if (status == RUN_REJUDGE || status == RUN_FULL_REJUDGE) {
    serve_rejudge_run(cnts, cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                      (status == RUN_FULL_REJUDGE), 0);
    goto cleanup;
  }
  if (!serve_is_valid_status(cs, status, 1)) {
    ns_error(log_f, NEW_SRV_ERR_INV_STATUS);
    goto cleanup;
  }
  memset(&new_run, 0, sizeof(new_run));
  new_run.status = status;
  flags = RUN_ENTRY_STATUS;
  if (run_set_entry(cs->runlog_state, run_id, flags, &new_run) < 0) {
    ns_error(log_f, NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
    goto cleanup;
  }

 cleanup:
  return 0;

 invalid_param:
  ns_html_err_inv_param(fout, phr, 0, errmsg);
 failure:
  return -1;
}

static int
parse_run_mask(struct http_request_info *phr,
               const unsigned char **p_size_str,
               const unsigned char **p_mask_str,
               size_t *p_size,
               unsigned long **p_mask)
{
  const unsigned char *size_str = 0;
  const unsigned char *mask_str = 0;
  size_t size = 0, mask_len;
  unsigned long *mask = 0;
  int n, i;
  unsigned char *s;

  if (p_size_str) *p_size_str = 0;
  if (p_mask_str) *p_mask_str = 0;
  if (p_size) *p_size = 0;
  if (p_mask) *p_mask = 0;

  if (ns_cgi_param(phr, "run_mask_size", &size_str) <= 0) {
    err("parse_run_mask: `run_mask_size' is not defined or binary");
    goto invalid_param;
  }
  if (sscanf(size_str, "%zu%n", &size, &n) != 1
      || size_str[n] || size > 100000) {
    err("parse_run_mask: `run_mask_size' value is invalid");
    goto invalid_param;
  }
  if (!size) {
    if (p_size_str) *p_size_str = "0";
    if (p_mask_str) *p_mask_str = "";
    return 0;
  }

  if (ns_cgi_param(phr, "run_mask", &mask_str) <= 0) {
    err("parse_run_mask: `run_mask' is not defined or binary");
    goto invalid_param;
  }

  XCALLOC(mask, size);
  mask_len = strlen(mask_str);
  s = (unsigned char*) alloca(mask_len + 1);
  memcpy(s, mask_str, mask_len + 1);
  while (mask_len > 0 && isspace(s[mask_len - 1])) mask_len--;
  s[mask_len] = 0;
  for (i = 0; i < size; i++) {
    if (sscanf(s, "%lx%n", &mask[i], &n) != 1) {
      err("parse_run_mask: cannot parse mask[%d]", i);
      goto invalid_param;
    }
    s += n;
  }
  if (*s) {
    err("parse_run_mask: garbage at end");
    goto invalid_param;
  }

  if (p_size_str) *p_size_str = size_str;
  if (p_mask_str) *p_mask_str = mask_str;
  if (p_size) *p_size = size;
  if (p_mask) {
    *p_mask = mask;
    mask = 0;
  }
  xfree(mask);
  return 1;

 invalid_param:
  xfree(mask);
  return -1;
}

static int
priv_clear_displayed(FILE *fout,
                     FILE *log_f,
                     struct http_request_info *phr,
                     const struct contest_desc *cnts,
                     struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  unsigned long *mask = 0;
  size_t mask_size;
  int retval = 0;

  if (parse_run_mask(phr, 0, 0, &mask_size, &mask) < 0) goto invalid_param;
  if (!mask_size) FAIL(NEW_SRV_ERR_NO_RUNS_TO_REJUDGE);
  if (opcaps_check(phr->caps, OPCAP_EDIT_RUN) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  switch (phr->action) {
  case NEW_SRV_ACTION_CLEAR_DISPLAYED_2:
    serve_clear_by_mask(cs, phr->user_id, phr->ip, phr->ssl_flag,
                        mask_size, mask);
    break;
  case NEW_SRV_ACTION_IGNORE_DISPLAYED_2:
    serve_ignore_by_mask(cs, phr->user_id, phr->ip, phr->ssl_flag,
                         mask_size, mask, RUN_IGNORED);
    break;
  case NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_2:
    serve_ignore_by_mask(cs, phr->user_id, phr->ip, phr->ssl_flag,
                         mask_size, mask, RUN_DISQUALIFIED);
    break;
  default:
    abort();
  }

 cleanup:
  xfree(mask);
  return retval;

 invalid_param:
  ns_html_err_inv_param(fout, phr, 0, 0);
  xfree(mask);
  return -1;
}

static int
priv_rejudge_displayed(FILE *fout,
                       FILE *log_f,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  unsigned long *mask = 0;
  size_t mask_size;
  int force_full = 0;
  int prio_adj = 0;
  int retval = 0;

  if (parse_run_mask(phr, 0, 0, &mask_size, &mask) < 0) goto invalid_param;
  if (!mask_size) FAIL(NEW_SRV_ERR_NO_RUNS_TO_REJUDGE);
  if (opcaps_check(phr->caps, OPCAP_REJUDGE_RUN) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (global->score_system_val == SCORE_OLYMPIAD
      && cs->accepting_mode
      && phr->action == NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_2) {
    force_full = 1;
    prio_adj = 10;
  }

  serve_rejudge_by_mask(cnts, cs, phr->user_id, phr->ip, phr->ssl_flag,
                        mask_size, mask, force_full, prio_adj);

 cleanup:
  xfree(mask);
  return retval;

 invalid_param:
  ns_html_err_inv_param(fout, phr, 0, 0);
  xfree(mask);
  return -1;
}

static int
priv_rejudge_problem(FILE *fout,
                     FILE *log_f,
                     struct http_request_info *phr,
                     const struct contest_desc *cnts,
                     struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_problem_data *prob = 0;
  const unsigned char *s;
  int prob_id, n;

  if (ns_cgi_param(phr, "prob_id", &s) <= 0
      || sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n]
      || prob_id <= 0 || prob_id > cs->max_prob
      || !(prob = cs->probs[prob_id])
      || prob->disable_testing)
    goto invalid_param;
  if (opcaps_check(phr->caps, OPCAP_REJUDGE_RUN) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  serve_rejudge_problem(cnts,cs,phr->user_id, phr->ip, phr->ssl_flag, prob_id);

 cleanup:
  return 0;

 invalid_param:
  ns_html_err_inv_param(fout, phr, 0, 0);
  return -1;
}

static int
priv_rejudge_all(FILE *fout,
                 FILE *log_f,
                 struct http_request_info *phr,
                 const struct contest_desc *cnts,
                 struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;

  if (opcaps_check(phr->caps, OPCAP_REJUDGE_RUN) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  switch (phr->action) {
  case NEW_SRV_ACTION_REJUDGE_SUSPENDED_2:
    serve_judge_suspended(cnts, cs, phr->user_id, phr->ip, phr->ssl_flag);
    break;
  case NEW_SRV_ACTION_REJUDGE_ALL_2:
    serve_rejudge_all(cnts, cs, phr->user_id, phr->ip, phr->ssl_flag);
    break;
  default:
    abort();
  }

 cleanup:
  return 0;
}

static int
priv_new_run(FILE *fout,
             FILE *log_f,
             struct http_request_info *phr,
             const struct contest_desc *cnts,
             struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = 0;
  const struct section_language_data *lang = 0;
  int retval = 0;
  const unsigned char *s = 0;
  int user_id = 0, n, x, i;
  int prob_id = 0, variant = 0, lang_id = 0;
  int is_imported = 0, is_hidden = 0, is_readonly = 0, status = 0;
  int tests = 0, score = 0, mime_type = 0;
  const unsigned char *run_text = 0;
  size_t run_size = 0;
  char **lang_list = 0;
  ruint32_t shaval[5];
  const unsigned char *mime_type_str = 0;
  struct timeval precise_time;
  int arch_flags = 0, run_id;
  path_t run_path;
  struct run_entry re;
  int re_flags = 0;

  memset(&re, 0, sizeof(re));

  // run_user_id, run_user_login, prob_id, variant, language,
  // is_imported, is_hidden, is_readonly, status,
  // tests, score, file
  if (ns_cgi_param(phr, "run_user_id", &s) > 0
      && sscanf(s, "%d%n", &x, &n) == 1 && !s[n]
      && teamdb_lookup(cs->teamdb_state, x))
    user_id = x;
  x = 0;
  if (ns_cgi_param(phr, "run_user_login", &s) > 0 && *s)
    x = teamdb_lookup_login(cs->teamdb_state, s);
  if (user_id <= 0 && x <= 0)
    FAIL(NEW_SRV_ERR_UNDEFINED_USER_ID_LOGIN);
  if (user_id > 0 && x > 0 && user_id != x)
    FAIL(NEW_SRV_ERR_CONFLICTING_USER_ID_LOGIN);
  if (user_id <= 0) user_id = x;

  if (ns_cgi_param(phr, "prob_id", &s) <= 0
      || sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n]
      || prob_id <= 0 || prob_id > cs->max_prob
      || !(prob = cs->probs[prob_id]))
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  if (ns_cgi_param(phr, "variant", &s) > 0 && *s) {
    if (sscanf(s, "%d%n", &variant, &n) != 1 || s[n]
        || prob->variant_num <= 0 || variant < 0
        || variant > prob->variant_num)
      FAIL(NEW_SRV_ERR_INV_VARIANT);
  }

  // check language, content-type, binariness and other stuff
  if (prob->type_val == PROB_TYPE_STANDARD) {
    if (ns_cgi_param(phr, "language", &s) <= 0
        || sscanf(s, "%d%n", &lang_id, &n) != 1 || s[n]
        || lang_id <= 0 || lang_id > cs->max_lang
        || !(lang = cs->langs[lang_id]))
      FAIL(NEW_SRV_ERR_INV_LANG_ID);
  }
  switch (prob->type_val) {
  case PROB_TYPE_STANDARD:      // "file"
  case PROB_TYPE_OUTPUT_ONLY:
  case PROB_TYPE_TEXT_ANSWER:
  case PROB_TYPE_SHORT_ANSWER:
    if (!ns_cgi_param_bin(phr, "file", &run_text, &run_size)) {
      run_text = "";
      run_size = 0;
    }
    break;
  default:
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  }

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
    if (strlen(run_text) != run_size)
      FAIL(NEW_SRV_ERR_BINARY_FILE);
    break;

  case PROB_TYPE_SELECT_MANY:
  case PROB_TYPE_CUSTOM:
    break;
  }

  if (lang) {
    if (lang->disabled) FAIL(NEW_SRV_ERR_LANG_DISABLED);

    if (prob->enable_language) {
      lang_list = prob->enable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], lang->short_name))
          break;
      if (!lang_list[i]) FAIL(NEW_SRV_ERR_LANG_NOT_AVAIL_FOR_PROBLEM);
    } else if (prob->disable_language) {
      lang_list = prob->disable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], lang->short_name))
          break;
      if (lang_list[i]) FAIL(NEW_SRV_ERR_LANG_DISABLED_FOR_PROBLEM);
    }
  } else {
    // guess the content-type and check it against the list
    if ((mime_type = mime_type_guess(global->diff_work_dir,
                                     run_text, run_size)) < 0)
      FAIL(NEW_SRV_ERR_CANNOT_DETECT_CONTENT_TYPE);
    mime_type_str = mime_type_get_type(mime_type);
    if (prob->enable_language) {
      lang_list = prob->enable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], mime_type_str))
          break;
      if (!lang_list[i]) {
        ns_error(log_f, NEW_SRV_ERR_CONTENT_TYPE_NOT_AVAILABLE, mime_type_str);
        goto cleanup;
      }
    } else if (prob->disable_language) {
      lang_list = prob->disable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], mime_type_str))
          break;
      if (lang_list[i]) {
        ns_error(log_f, NEW_SRV_ERR_CONTENT_TYPE_DISABLED, mime_type_str);
        goto cleanup;
      }
    }
  }
  sha_buffer(run_text, run_size, shaval);

  if (ns_cgi_param(phr, "is_imported", &s) > 0 && *s) {
    if (sscanf(s, "%d%n", &is_imported, &n) != 1 || s[n]
        || is_imported < 0 || is_imported > 1)
      FAIL(NEW_SRV_ERR_INV_PARAM);
    re.is_imported = is_imported;
    re_flags |= RUN_ENTRY_IMPORTED;
  }
  if (ns_cgi_param(phr, "is_hidden", &s) > 0 && *s) {
    if (sscanf(s, "%d%n", &is_hidden, &n) != 1 || s[n]
        || is_hidden < 0 || is_hidden > 1)
      FAIL(NEW_SRV_ERR_INV_PARAM);
  }
  if (ns_cgi_param(phr, "is_readonly", &s) > 0 && *s) {
    if (sscanf(s, "%d%n", &is_readonly, &n) != 1 || s[n]
        || is_readonly < 0 || is_readonly > 1)
      FAIL(NEW_SRV_ERR_INV_PARAM);
    re.is_readonly = is_readonly;
    re_flags |= RUN_ENTRY_READONLY;
  }
  if (ns_cgi_param(phr, "status", &s) > 0 && *s) {
    if (sscanf(s, "%d%n", &status, &n) != 1 || s[n]
        || status < 0 || status > RUN_MAX_STATUS
        || !serve_is_valid_status(cs, status, 1))
      FAIL(NEW_SRV_ERR_INV_STATUS);
    re.status = status;
    re_flags |= RUN_ENTRY_STATUS;
  }
  if (ns_cgi_param(phr, "tests", &s) > 0 && *s) {
    if (sscanf(s, "%d%n", &tests, &n) != 1 || s[n]
        || tests < -1 || tests > 100000)
      FAIL(NEW_SRV_ERR_INV_TEST);
    re.test = tests;
    re_flags |= RUN_ENTRY_TEST;
  }
  if (ns_cgi_param(phr, "score", &s) > 0 && *s) {
    if (sscanf(s, "%d%n", &score, &n) != 1 || s[n]
        || score < 0 || score > 100000)
      FAIL(NEW_SRV_ERR_INV_PARAM);
    re.score = score;
    re_flags |= RUN_ENTRY_SCORE;
  }

  if (!lang) lang_id = 0;
  gettimeofday(&precise_time, 0);

  run_id = run_add_record(cs->runlog_state, 
                          precise_time.tv_sec, precise_time.tv_usec * 1000,
                          run_size, shaval,
                          phr->ip, phr->ssl_flag, phr->locale_id,
                          user_id, prob_id, lang_id, variant,
                          is_hidden, mime_type);
  if (run_id < 0) FAIL(NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
  serve_move_files_to_insert_run(cs, run_id);
  arch_flags = archive_make_write_path(cs, run_path, sizeof(run_path),
                                       global->run_archive_dir, run_id,
                                       run_size, 0);
  if (arch_flags < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto cleanup;
  }
  if (archive_dir_prepare(cs, global->run_archive_dir, run_id, 0, 0) < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto cleanup;
  }
  if (generic_write_file(run_text, run_size, arch_flags, 0, run_path, "") < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto cleanup;
  }
  run_set_entry(cs->runlog_state, run_id, re_flags, &re);

  serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                  "Command: new_run\n"
                  "Status: pending\n"
                  "Run-id: %d\n",
                  run_id);

 cleanup:
  return retval;
}

static const unsigned char * const form_row_attrs[]=
{
  " bgcolor=\"#d0d0d0\"",
  " bgcolor=\"#e0e0e0\"",
};

static const unsigned char * const confirmation_headers[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_REJUDGE_DISPLAYED_1] = __("Rejudge displayed runs"),
  [NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_1] = __("Fully rejudge displayed runs"),
  [NEW_SRV_ACTION_REJUDGE_PROBLEM_1] = __("Rejudge problem"),
  [NEW_SRV_ACTION_REJUDGE_SUSPENDED_1] = __("Judge suspended runs"),
  [NEW_SRV_ACTION_REJUDGE_ALL_1] = __("Rejudge all runs"),
  [NEW_SRV_ACTION_UPDATE_STANDINGS_1] = __("Update the public standings"),
  [NEW_SRV_ACTION_RESET_1] = __("Reset the contest"),
  [NEW_SRV_ACTION_GENERATE_PASSWORDS_1] = __("Generate random contest passwords"),
  [NEW_SRV_ACTION_GENERATE_REG_PASSWORDS_1] = __("Generate random registration passwords"),
  [NEW_SRV_ACTION_CLEAR_PASSWORDS_1] = __("Clear contest passwords"),
  [NEW_SRV_ACTION_CLEAR_DISPLAYED_1] = __("Clear displayed runs"),
  [NEW_SRV_ACTION_IGNORE_DISPLAYED_1] = __("Ignore displayed runs"),
  [NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_1] = __("Disqualify displayed runs"),
};

static const int confirm_next_action[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_REJUDGE_DISPLAYED_1] = NEW_SRV_ACTION_REJUDGE_DISPLAYED_2,
  [NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_1] = NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_2,
  [NEW_SRV_ACTION_REJUDGE_PROBLEM_1] = NEW_SRV_ACTION_REJUDGE_PROBLEM_2,
  [NEW_SRV_ACTION_REJUDGE_SUSPENDED_1] = NEW_SRV_ACTION_REJUDGE_SUSPENDED_2,
  [NEW_SRV_ACTION_REJUDGE_ALL_1] = NEW_SRV_ACTION_REJUDGE_ALL_2,
  [NEW_SRV_ACTION_UPDATE_STANDINGS_1] = NEW_SRV_ACTION_UPDATE_STANDINGS_2,
  [NEW_SRV_ACTION_RESET_1] = NEW_SRV_ACTION_RESET_2,
  [NEW_SRV_ACTION_GENERATE_PASSWORDS_1] = NEW_SRV_ACTION_GENERATE_PASSWORDS_2,
  [NEW_SRV_ACTION_GENERATE_REG_PASSWORDS_1] = NEW_SRV_ACTION_GENERATE_REG_PASSWORDS_2,
  [NEW_SRV_ACTION_CLEAR_PASSWORDS_1] = NEW_SRV_ACTION_CLEAR_PASSWORDS_2,
  [NEW_SRV_ACTION_CLEAR_DISPLAYED_1] = NEW_SRV_ACTION_CLEAR_DISPLAYED_2,
  [NEW_SRV_ACTION_IGNORE_DISPLAYED_1] = NEW_SRV_ACTION_IGNORE_DISPLAYED_2,
  [NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_1]=NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_2,
};

static const unsigned char * const confirmation_message[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_REJUDGE_DISPLAYED_1] = __("Rejudge runs"),
  [NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_1] = __("Fully rejudge runs"),
  [NEW_SRV_ACTION_CLEAR_DISPLAYED_1] = __("Clear runs"),
  [NEW_SRV_ACTION_IGNORE_DISPLAYED_1] = __("Ignore runs"),
  [NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_1] = __("Disqualify runs"),
};

static int
priv_confirmation_page(FILE *fout,
                       FILE *log_f,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_problem_data *prob = 0;
  unsigned char bb[1024];
  const unsigned char *errmsg = 0;
  const unsigned char *run_mask_size_str = 0;
  const unsigned char *run_mask_str = 0;
  int n, i, prob_id = 0;
  size_t run_mask_size = 0;
  unsigned long *run_mask = 0, m;
  const unsigned char *s;
  int disable_ok = 0, runs_count = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  switch (phr->action) {
  case NEW_SRV_ACTION_REJUDGE_DISPLAYED_1:
  case NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_1:
  case NEW_SRV_ACTION_CLEAR_DISPLAYED_1:
  case NEW_SRV_ACTION_IGNORE_DISPLAYED_1:
  case NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_1:
    // run_mask_size, run_mask
    errmsg = "cannot parse run mask";
    if (parse_run_mask(phr, &run_mask_size_str, &run_mask_str,
                       &run_mask_size, &run_mask) < 0)
      goto invalid_param;
    break;
  case NEW_SRV_ACTION_REJUDGE_PROBLEM_1:
    if (ns_cgi_param(phr, "prob_id", &s) <= 0
        || sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n]
        || prob_id <= 0 || prob_id > cs->max_prob
        || !(prob = cs->probs[prob_id])
        || prob->disable_testing)
      goto invalid_param;
    break;
  }

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s &quot;%s&quot;",
            ns_unparse_role(phr->role), phr->name_arm, phr->contest_id,
            extra->contest_arm, _("Confirm action"),
            gettext(confirmation_headers[phr->action]));

  switch (phr->action) {
  case NEW_SRV_ACTION_REJUDGE_DISPLAYED_1:
  case NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_1:
  case NEW_SRV_ACTION_CLEAR_DISPLAYED_1:
  case NEW_SRV_ACTION_IGNORE_DISPLAYED_1:
  case NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_1:
    fprintf(fout, "<p>%s ", gettext(confirmation_message[phr->action]));
    s = "";
    for (n = 0; n < 8 * sizeof(run_mask[0]) * run_mask_size; n++) {
      i = n / (8 * sizeof(run_mask[0]));
      m = 1L << (n % (8 * sizeof(run_mask[0])));
      if ((run_mask[i] & m)) {
        fprintf(fout, "%s%d", s, n);
        s = ", ";
        runs_count++;
      }
    }
    if (!runs_count) {
      fprintf(fout, "<i>no runs!</i></p>\n");
      disable_ok = 1;
    } else {
      fprintf(fout, " (<b>%d total</b>)?</p>\n", runs_count);
    }
    break;
  case NEW_SRV_ACTION_REJUDGE_PROBLEM_1:
    fprintf(fout, "<p>%s %s(%s)?</p>\n", _("Rejudge problem"),
            prob->short_name, ARMOR(prob->long_name));
    break;
  }

  fprintf(fout, "<table border=\"0\"><tr><td>");
  html_start_form(fout, 0, phr->self_url, phr->hidden_vars);
  fprintf(fout, "%s", ns_submit_button(bb, sizeof(bb), "nop", 0,
                                              "Cancel"));
  fprintf(fout, "</form></td><td>");
  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);

  switch (phr->action) {
  case NEW_SRV_ACTION_REJUDGE_DISPLAYED_1:
  case NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_1:
  case NEW_SRV_ACTION_CLEAR_DISPLAYED_1:
  case NEW_SRV_ACTION_IGNORE_DISPLAYED_1:
  case NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_1:
    html_hidden(fout, "run_mask_size", "%s", run_mask_size_str);
    html_hidden(fout, "run_mask", "%s", run_mask_str);
    break;
  case NEW_SRV_ACTION_REJUDGE_PROBLEM_1:
    html_hidden(fout, "prob_id", "%d", prob_id);
    break;
  }

  if (!disable_ok) {
    fprintf(fout, "%s", BUTTON(confirm_next_action[phr->action]));
  }
  fprintf(fout, "</form></td></tr></table>\n");

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);
  html_armor_free(&ab);
  xfree(run_mask);
  return 0;

 invalid_param:
  ns_html_err_inv_param(fout, phr, 0, errmsg);
  html_armor_free(&ab);
  xfree(run_mask);
  return -1;
}

static int
priv_view_user_dump(FILE *fout,
                    FILE *log_f,
                    struct http_request_info *phr,
                    const struct contest_desc *cnts,
                    struct contest_extra *extra)
{
  int retval = 0, r;
  unsigned char *db_text = 0;

  if (opcaps_check(phr->caps, OPCAP_DUMP_USERS) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    ns_html_err_ul_server_down(fout, phr, 1, 0);
    return -1;
  }
  if ((r = userlist_clnt_get_database(ul_conn, ULS_GET_DATABASE,
                                      phr->contest_id, &db_text)) < 0) {
    switch (-r) {
    case ULS_ERR_INVALID_LOGIN:
    case ULS_ERR_INVALID_PASSWORD:
    case ULS_ERR_BAD_CONTEST_ID:
    case ULS_ERR_IP_NOT_ALLOWED:
    case ULS_ERR_NO_PERMS:
    case ULS_ERR_NOT_REGISTERED:
    case ULS_ERR_CANNOT_PARTICIPATE:
      ns_html_err_no_perm(fout, phr, 1, "operation failed: %s",
                          userlist_strerror(-r));
      return -1;
    case ULS_ERR_DISCONNECT:
      ns_html_err_ul_server_down(fout, phr, 1, 0);
      return -1;
    default:
      ns_html_err_internal_error(fout, phr, 1, "operation failed: %s",
                                 userlist_strerror(-r));
      return -1;
    }
  }

  fprintf(fout, "Content-type: text/plain\n\n%s\n", db_text);
  xfree(db_text);

 cleanup:
  return retval;
}

static int
priv_view_runs_dump(FILE *fout,
                    FILE *log_f,
                    struct http_request_info *phr,
                    const struct contest_desc *cnts,
                    struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  int retval = 0;

  if (phr->role < USER_ROLE_JUDGE
      || opcaps_check(phr->caps, OPCAP_DUMP_RUNS) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  switch (phr->action) {
  case NEW_SRV_ACTION_VIEW_RUNS_DUMP:
    write_runs_dump(cs, fout, phr->self_url, global->charset);
    break;

  case NEW_SRV_ACTION_EXPORT_XML_RUNS:
    fprintf(fout, "Content-type: text/plain; charset=%s\n\n", EJUDGE_CHARSET);
    if (run_write_xml(cs->runlog_state, cs, cnts, fout, 1, 0,
                      cs->current_time) < 0)
      FAIL(NEW_SRV_ERR_TRY_AGAIN);
    break;

  case NEW_SRV_ACTION_WRITE_XML_RUNS:
    fprintf(fout, "Content-type: text/plain; charset=%s\n\n", EJUDGE_CHARSET);
    if (run_write_xml(cs->runlog_state, cs, cnts, fout, 0, 0,
                      cs->current_time) < 0)
      FAIL(NEW_SRV_ERR_TRY_AGAIN);
    break;

  case NEW_SRV_ACTION_WRITE_XML_RUNS_WITH_SRC:
    fprintf(fout, "Content-type: text/plain; charset=%s\n\n", EJUDGE_CHARSET);
    if (run_write_xml(cs->runlog_state, cs, cnts, fout, 0, 1,
                      cs->current_time) < 0)
      FAIL(NEW_SRV_ERR_TRY_AGAIN);
    break;

  default:
    abort();
  }

 cleanup:
  return retval;
}

static int
priv_view_audit_log(FILE *fout,
                    FILE *log_f,
                    struct http_request_info *phr,
                    const struct contest_desc *cnts,
                    struct contest_extra *extra)
{
  int run_id;
  int retval = 0;

  if (parse_run_id(fout, phr, cnts, extra, &run_id, 0) < 0) FAIL(1);

  if (opcaps_check(phr->caps, OPCAP_CONTROL_CONTEST) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  ns_write_audit_log(extra->serve_state, fout, log_f, phr, cnts, extra,
                     run_id);

 cleanup:
  return retval;
}

static int
priv_diff_page(FILE *fout,
               FILE *log_f,
               struct http_request_info *phr,
               const struct contest_desc *cnts,
               struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  const unsigned char *s;
  int run_id1, run_id2, n, total_runs;
  int retval = 0;

  total_runs = run_get_total(cs->runlog_state);
  if (parse_run_id(fout, phr, cnts, extra, &run_id1, 0) < 0) goto failure;
  if (!(n = ns_cgi_param(phr, "run_id2", &s)) || (n > 0 && !*s))
    FAIL(NEW_SRV_ERR_RUN_TO_COMPARE_UNSPECIFIED);
  if (n < 0 || sscanf(s, "%d%n", &run_id2, &n) != 1 || s[n]
      || run_id2 < 0 || run_id2 >= total_runs)
    FAIL(NEW_SRV_ERR_INV_RUN_TO_COMPARE);
  if (opcaps_check(phr->caps, OPCAP_VIEW_SOURCE) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (compare_runs(cs, fout, run_id1, run_id2) < 0)
    FAIL(NEW_SRV_ERR_RUN_COMPARE_FAILED);

 cleanup:
  return retval;

 failure:
  return -1;
}

static int
priv_user_detail_page(FILE *fout,
                      FILE *log_f,
                      struct http_request_info *phr,
                      const struct contest_desc *cnts,
                      struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int retval = 0;
  int user_id, n;
  const unsigned char *s = 0;

  if (ns_cgi_param(phr, "user_id", &s) <= 0
      || sscanf(s, "%d%n", &user_id, &n) != 1 || s[n]
      || !teamdb_lookup(cs->teamdb_state, user_id))
    FAIL(NEW_SRV_ERR_INV_USER_ID);

  if (opcaps_check(phr->caps, OPCAP_GET_USER) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s %d", ns_unparse_role(phr->role),
            phr->name_arm, phr->contest_id, extra->contest_arm,
            _("Details for user "), user_id);
  ns_user_info_page(fout, log_f, phr, cnts, extra, user_id);
  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  return retval;
}

static int
priv_new_run_form_page(FILE *fout,
                       FILE *log_f,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra)
{
  int retval = 0;

  if (opcaps_check(phr->caps, OPCAP_SUBMIT_RUN) < 0
      || opcaps_check(phr->caps, OPCAP_EDIT_RUN))
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm, _("Add new run"));
  ns_new_run_form(fout, log_f, phr, cnts, extra);
  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  return retval;
}

static int
priv_examiners_page(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0;

  /*
  if (opcaps_check(phr->caps, OPCAP_SUBMIT_RUN) < 0
      || opcaps_check(phr->caps, OPCAP_EDIT_RUN))
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  */

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm, _("Add new run"));
  ns_examiners_page(fout, log_f, phr, cnts, extra);
  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

  //cleanup:
  return retval;
}

static int
priv_assign_chief_examiner(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  int retval = 0;
  int prob_id = 0;
  int user_id = 0;

  if (phr->role != USER_ROLE_ADMIN && phr->role != USER_ROLE_COORDINATOR)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (ns_cgi_param_int(phr, "prob_id", &prob_id) < 0
      || prob_id <= 0 || prob_id > cs->max_prob || !cs->probs[prob_id]
      || cs->probs[prob_id]->manual_checking <= 0)
    FAIL(NEW_SRV_ERR_INV_PROB_ID);

  if (ns_cgi_param_int(phr, "chief_user_id", &user_id) < 0 || user_id < 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);
  if (!user_id) {
    user_id = nsdb_find_chief_examiner(phr->contest_id, prob_id);
    if (user_id > 0) {
      nsdb_remove_examiner(user_id, phr->contest_id, prob_id);
    }
    retval = NEW_SRV_ACTION_EXAMINERS_PAGE;
    goto cleanup;
  }
  if (nsdb_check_role(user_id, phr->contest_id, USER_ROLE_CHIEF_EXAMINER) < 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);
  nsdb_assign_chief_examiner(user_id, phr->contest_id, prob_id);
  retval = NEW_SRV_ACTION_EXAMINERS_PAGE;

 cleanup:
  return retval;
}

static int
priv_assign_examiner(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  int retval = 0;
  int prob_id = 0;
  int user_id = 0;

  if (phr->role != USER_ROLE_ADMIN && phr->role != USER_ROLE_COORDINATOR)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (ns_cgi_param_int(phr, "prob_id", &prob_id) < 0
      || prob_id <= 0 || prob_id > cs->max_prob || !cs->probs[prob_id]
      || cs->probs[prob_id]->manual_checking <= 0)
    FAIL(NEW_SRV_ERR_INV_PROB_ID);

  if (ns_cgi_param_int(phr, "exam_add_user_id", &user_id) < 0 || user_id < 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);
  if (!user_id) {
    retval = NEW_SRV_ACTION_EXAMINERS_PAGE;
    goto cleanup;
  }
  if (nsdb_check_role(user_id, phr->contest_id, USER_ROLE_EXAMINER) < 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);
  nsdb_assign_examiner(user_id, phr->contest_id, prob_id);
  retval = NEW_SRV_ACTION_EXAMINERS_PAGE;

 cleanup:
  return retval;
}

static int
priv_unassign_examiner(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  int retval = 0;
  int prob_id = 0;
  int user_id = 0;

  if (phr->role != USER_ROLE_ADMIN && phr->role != USER_ROLE_COORDINATOR)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (ns_cgi_param_int(phr, "prob_id", &prob_id) < 0
      || prob_id <= 0 || prob_id > cs->max_prob || !cs->probs[prob_id]
      || cs->probs[prob_id]->manual_checking <= 0)
    FAIL(NEW_SRV_ERR_INV_PROB_ID);

  if (ns_cgi_param_int(phr, "exam_del_user_id", &user_id) < 0 || user_id < 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);
  if (!user_id) {
    retval = NEW_SRV_ACTION_EXAMINERS_PAGE;
    goto cleanup;
  }
  /*
  if (nsdb_check_role(user_id, phr->contest_id, USER_ROLE_EXAMINER) < 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);
  */
  nsdb_remove_examiner(user_id, phr->contest_id, prob_id);
  retval = NEW_SRV_ACTION_EXAMINERS_PAGE;

 cleanup:
  return retval;
}

static void
priv_view_users_page(FILE *fout,
                     struct http_request_info *phr,
                     const struct contest_desc *cnts,
                     struct contest_extra *extra)
{
  int r;
  unsigned char *xml_text = 0;
  struct userlist_list *users = 0;
  const struct userlist_user *u = 0;
  const struct userlist_contest *uc = 0;
  int uid;
  int row = 1, serial = 1;
  char url[1024];
  unsigned char bb[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int details_allowed = 0;
  unsigned char cl[128];
  unsigned char b1[1024], b2[1024];
  int new_contest_id = cnts->id;
  const struct section_global_data *global = extra->serve_state->global;

  if (cnts->user_contest_num > 0) new_contest_id = cnts->user_contest_num;
  if (ns_open_ul_connection(phr->fw_state) < 0)
    return ns_html_err_ul_server_down(fout, phr, 1, 0);
  if ((r = userlist_clnt_list_all_users(ul_conn, ULS_LIST_ALL_USERS,
                                        phr->contest_id, &xml_text)) < 0)
    return ns_html_err_internal_error(fout, phr, 1,
                                      "list_all_users failed: %s",
                                      userlist_strerror(-r));
  users = userlist_parse_str(xml_text);
  xfree(xml_text); xml_text = 0;
  if (!users)
    return ns_html_err_internal_error(fout, phr, 1, "XML parsing failed");

  if (opcaps_check(phr->caps, OPCAP_GET_USER) >= 0) details_allowed = 1;

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm, _("Users page"));

  fprintf(fout, "<h2>Registered users</h2>");

  snprintf(cl, sizeof(cl), " class=\"b1\"");

  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
  fprintf(fout, "<table%s><tr><th%s>NN</th><th%s>Id</th><th%s>Login</th><th%s>Name</th><th%s>Status</th><th%s>Flags</th><th%s>Reg. date</th><th%s>Login date</th><th%s>Select</th></tr>\n", cl, cl, cl, cl, cl, cl, cl, cl, cl, cl);
  for (uid = 1; uid < users->user_map_size; uid++) {
    if (!(u = users->user_map[uid])) continue;
    if (!(uc = userlist_get_user_contest(u, new_contest_id))) continue;

    fprintf(fout, "<tr%s>", form_row_attrs[row ^= 1]);
    fprintf(fout, "<td%s>%d</td>", cl, serial++);

    snprintf(b1, sizeof(b1), "uid == %d", uid);
    url_armor_string(b2, sizeof(b2), b1);
    fprintf(fout, "<td%s>%s%d</a></td>", cl,
            ns_aref(bb, sizeof(bb), phr,
                    NEW_SRV_ACTION_MAIN_PAGE, "filter_expr=%s", b2),
            uid);

    if (details_allowed) {
      fprintf(fout, "<td%s>%s%s</a></td>", cl,
              ns_aref(bb, sizeof(bb), phr,
                      NEW_SRV_ACTION_VIEW_USER_INFO, "user_id=%d", uid),
              ARMOR(u->login));
    } else {
      fprintf(fout, "<td%s>%s</td>", cl, ARMOR(u->login));
    }
    if (u->i.name && *u->i.name) {
      fprintf(fout, "<td%s>%s</td>", cl, ARMOR(u->i.name));
    } else {
      fprintf(fout, "<td%s>&nbsp;</td>", cl);
    }
    fprintf(fout, "<td%s>%s</td>", cl, userlist_unparse_reg_status(uc->status));
    if ((uc->flags & USERLIST_UC_ALL)) {
      r = 0;
      fprintf(fout, "<td%s>", cl);
      if ((uc->flags & USERLIST_UC_BANNED))
        fprintf(fout, "%s%s", r++?",":"", "banned");
      if ((uc->flags & USERLIST_UC_INVISIBLE))
        fprintf(fout, "%s%s", r++?",":"", "invisible");
      if ((uc->flags & USERLIST_UC_LOCKED))
        fprintf(fout, "%s%s", r++?",":"", "locked");
      if ((uc->flags & USERLIST_UC_INCOMPLETE))
        fprintf(fout, "%s%s", r++?",":"", "incomplete");
      if ((uc->flags & USERLIST_UC_DISQUALIFIED))
        fprintf(fout, "%s%s", r++?",":"", "disqualified");
      fprintf(fout, "</td>");
    } else {
      fprintf(fout, "<td%s>&nbsp;</td>", cl);
    }
    if (uc->date > 0) {
      fprintf(fout, "<td%s>%s</td>", cl, xml_unparse_date(uc->date));
    } else {
      fprintf(fout, "<td%s>&nbsp;</td>", cl);
    }
    if (u->i.last_login_time > 0) {
      fprintf(fout, "<td%s>%s</td>", cl,
              xml_unparse_date(u->i.last_login_time));
    } else {
      fprintf(fout, "<td%s>&nbsp;</td>", cl);
    }
    fprintf(fout, "<td%s><input type=\"checkbox\" name=\"user_%d\"/></td>",
            cl, uid);
    fprintf(fout, "</tr>\n");
  }
  fprintf(fout, "</table>\n");

  fprintf(fout, "<h2>Users range</h2>\n");

  fprintf(fout, "<table>\n");
  fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
          _("First User_Id"),
          html_input_text(bb, sizeof(bb), "first_user_id", 16, 0));
  fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
          _("Last User_Id (incl.)"),
          html_input_text(bb, sizeof(bb), "last_user_id", 16, 0));
  fprintf(fout, "</table>\n");

  fprintf(fout, "<h2>Available actions</h2>\n");

  fprintf(fout, "<table>\n");
  fprintf(fout, "<tr><td>%s%s</a></td><td>%s</td></tr>\n",
          ns_aref(url, sizeof(url), phr, 0, 0),
          _("Back"), _("Return to the main page"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_USERS_REMOVE_REGISTRATIONS),
          _("Remove the selected users from the list"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_USERS_SET_PENDING),
          _("Set the registration status of the selected users to PENDING"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_USERS_SET_OK),
          _("Set the registration status of the selected users to OK"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_USERS_SET_REJECTED), 
          _("Set the registration status of the selected users to REJECTED"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_USERS_SET_INVISIBLE),
          _("Set the INVISIBLE flag for the selected users"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_USERS_CLEAR_INVISIBLE),
          _("Clear the INVISIBLE flag for the selected users"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_USERS_SET_BANNED),
          _("Set the BANNED flag for the selected users"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_USERS_CLEAR_BANNED),
          _("Clear the BANNED flag for the selected users"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_USERS_SET_LOCKED),
          _("Set the LOCKED flag for the selected users"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_USERS_CLEAR_LOCKED),
          _("Clear the LOCKED flag for the selected users"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_USERS_SET_INCOMPLETE),
          _("Set the INCOMPLETE flag for the selected users"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_USERS_CLEAR_INCOMPLETE),
          _("Clear the INCOMPLETE flag for the selected users"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_USERS_CLEAR_DISQUALIFIED),
          _("Clear the DISQUALIFIED flag for the selected users"));
  if (global->is_virtual) {
    fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
            BUTTON(NEW_SRV_ACTION_FORCE_START_VIRTUAL),
            _("Force virtual contest start for the selected users"));
  }

  if (global->user_exam_protocol_header_txt)
    fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
            BUTTON(NEW_SRV_ACTION_PRINT_SELECTED_USER_PROTOCOL),
            _("Print the user examination protocols for the selected users"));
  if (global->full_exam_protocol_header_txt)
    fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
            BUTTON(NEW_SRV_ACTION_PRINT_SELECTED_USER_FULL_PROTOCOL),
            _("Print the user full examination protocols for the selected users"));
  if (global->full_exam_protocol_header_txt)
    fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
            BUTTON(NEW_SRV_ACTION_PRINT_SELECTED_UFC_PROTOCOL),
            _("Print the user full cyphered examination protocols for the selected users"));
  fprintf(fout, "</table>\n");

  fprintf(fout, "<h2>%s</h3>\n", _("Disqualify selected users"));
  fprintf(fout, "<p>%s:<br>\n",
          _("Disqualification explanation"));
  fprintf(fout, "<p><textarea name=\"disq_comment\" rows=\"5\" cols=\"60\">");
  fprintf(fout, "</textarea></p>\n");

  fprintf(fout, "<table class=\"b0\"><tr>");
  fprintf(fout, "<td class=\"b0\">%s</td>",
          BUTTON(NEW_SRV_ACTION_USERS_SET_DISQUALIFIED));
  fprintf(fout, "</tr></table>\n");

  fprintf(fout, "<h2>%s</h2>\n", _("Add new user"));
  fprintf(fout, "<table>\n");
  fprintf(fout, "<tr><td><input type=\"text\" size=\"32\" name=\"add_login\"/></td><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_USERS_ADD_BY_LOGIN),
          _("Add a new user specifying his/her login"));
  fprintf(fout, "<tr><td><input type=\"text\" size=\"32\" name=\"add_user_id\"/></td><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_USERS_ADD_BY_USER_ID),
          _("Add a new user specifying his/her User Id"));
  fprintf(fout, "</table>\n");

  fprintf(fout, "</form>\n");

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

  if (users) userlist_free(&users->b);
  html_armor_free(&ab);
}

struct priv_user_info
{
  int user_id;
  unsigned char *login;
  unsigned char *name;
  unsigned int role_mask;
};
static int
priv_user_info_sort_func(const void *v1, const void *v2)
{
  const struct priv_user_info *p1 = *(const struct priv_user_info**) v1;
  const struct priv_user_info *p2 = *(const struct priv_user_info**) v2;

  if (v1 == v2) return 0;
  ASSERT(p1 != p2);
  if (p1->user_id < p2->user_id) return -1;
  if (p1->user_id > p2->user_id) return 1;
  abort();
}

static void
priv_view_priv_users_page(FILE *fout,
                          struct http_request_info *phr,
                          const struct contest_desc *cnts,
                          struct contest_extra *extra)
{
  struct ptrarray_t
  {
    int a, u;
    struct priv_user_info **v;
  };
  struct ptrarray_t users;
  struct opcap_list_item *op;
  int user_id, i;
  unsigned char *name = 0, *login = 0;
  struct priv_user_info *pp;
  int_iterator_t iter;
  unsigned int role_mask;
  int row = 1, cnt, r;
  unsigned char url[1024];
  unsigned char bb[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char cl[128];

  XMEMZERO(&users, 1);

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    ns_html_err_ul_server_down(fout, phr, 1, 0);
    goto cleanup;
  }

  // collect all information about allowed MASTER and JUDGE logins
  for (op = cnts->capabilities.first; op;
       op = (struct opcap_list_item*) op->b.right) {
    role_mask = 0;
    if (opcaps_check(op->caps, OPCAP_MASTER_LOGIN) >= 0) {
      role_mask |= (1 << USER_ROLE_ADMIN);
    }
    if (opcaps_check(op->caps, OPCAP_JUDGE_LOGIN) >= 0) {
      role_mask |= (1 << USER_ROLE_JUDGE);
    }
    if (!role_mask) continue;
    if (userlist_clnt_lookup_user(ul_conn, op->login, 0, &user_id, &name) < 0)
      continue;
    for (i = 0; i < users.u; i++)
      if (users.v[i]->user_id == user_id)
        break;
    if (i < users.u) {
      xfree(name);
      continue;
    }
    XEXPAND2(users);
    XCALLOC(users.v[users.u], 1);
    pp = users.v[users.u++];
    pp->user_id = user_id;
    pp->login = xstrdup(op->login);
    pp->name = name;
    pp->role_mask |= role_mask;
  }

  // collect information about other roles
  for (iter = nsdb_get_contest_user_id_iterator(phr->contest_id);
       iter->has_next(iter);
       iter->next(iter)) {
    user_id = iter->get(iter);
    if (nsdb_get_priv_role_mask_by_iter(iter, &role_mask) < 0) continue;
    if (userlist_clnt_lookup_user_id(ul_conn, user_id, phr->contest_id,
                                     &login, &name) < 0)
      continue;
    for (i = 0; i < users.u; i++)
      if (users.v[i]->user_id == user_id)
        break;
    if (i < users.u) {
      xfree(login);
      xfree(name);
      users.v[i]->role_mask |= role_mask;
      continue;
    }
    XEXPAND2(users);
    XCALLOC(users.v[users.u], 1);
    pp = users.v[users.u++];
    pp->user_id = user_id;
    pp->login = login;
    pp->name = name;
    pp->role_mask |= role_mask;
  }
  iter->destroy(iter); iter = 0;

  qsort(users.v, users.u, sizeof(users.v[0]), priv_user_info_sort_func);

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm, _("Privileged users page"));

  snprintf(cl, sizeof(cl), " class=\"b1\"");

  fprintf(fout, "<h2>Privileged users</h2>");

  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
  fprintf(fout, "<table%s><tr><th%s>NN</th><th%s>Id</th><th%s>Login</th><th%s>Name</th><th%s>Roles</th><th%s>Select</th></tr>\n", cl, cl, cl, cl, cl, cl, cl);
  for (i = 0; i < users.u; i++) {
    fprintf(fout, "<tr%s><td%s>%d</td>", form_row_attrs[row ^= 1], cl, i + 1);
    fprintf(fout, "<td%s>%d</td>", cl, users.v[i]->user_id);
    fprintf(fout, "<td%s>%s</td>", cl, ARMOR(users.v[i]->login));
    fprintf(fout, "<td%s>%s</td>", cl, ARMOR(users.v[i]->name));
    if ((role_mask = users.v[i]->role_mask)) {
      fprintf(fout, "<td%s>", cl);
      for (cnt = 0, r = USER_ROLE_OBSERVER; r <= USER_ROLE_ADMIN; r++)
        if ((role_mask & (1 << r)))
          fprintf(fout, "%s%s", cnt++?",":"", ns_unparse_role(r));
      fprintf(fout, "</td>");
    } else {
      fprintf(fout, "<td%s>&nbsp;</td>", cl);
    }
    fprintf(fout, "<td%s><input type=\"checkbox\" name=\"user_%d\"/></td>",
            cl, users.v[i]->user_id);
    fprintf(fout, "</tr>\n");
  }
  fprintf(fout, "</table>\n");

  fprintf(fout, "<h2>Available actions</h2>\n");

  fprintf(fout, "<table>\n");
  fprintf(fout, "<tr><td>%s%s</a></td><td>%s</td></tr>\n",
          ns_aref(url, sizeof(url), phr, 0, 0),
          _("Back"), _("Return to the main page"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_PRIV_USERS_REMOVE),
          _("Remove the selected users from the list (ADMINISTRATORs cannot be removed)"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_PRIV_USERS_ADD_OBSERVER),
          _("Add the OBSERVER role to the selected users"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_PRIV_USERS_DEL_OBSERVER),
          _("Remove the OBSERVER role from the selected users"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_PRIV_USERS_ADD_EXAMINER),
          _("Add the EXAMINER role to the selected users"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_PRIV_USERS_DEL_EXAMINER),
          _("Remove the EXAMINER role from the selected users"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_PRIV_USERS_ADD_CHIEF_EXAMINER),
          _("Add the CHIEF EXAMINER role to the selected users"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_PRIV_USERS_DEL_CHIEF_EXAMINER),
          _("Remove the CHIEF EXAMINER role from the selected users"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_PRIV_USERS_ADD_COORDINATOR),
          _("Add the COORDINATOR role to the selected users"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_PRIV_USERS_DEL_COORDINATOR),
          _("Remove the COORDINATOR role from the selected users"));
  fprintf(fout, "</table>\n");

  fprintf(fout, "<h2>%s</h2>\n", _("Add new user"));
  fprintf(fout, "<table>\n");
  fprintf(fout, "<tr><td><input type=\"text\" size=\"32\" name=\"add_login\"/></td><td>");
  html_role_select(fout, USER_ROLE_OBSERVER, 0, "add_role_1");
  fprintf(fout, "</td><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_PRIV_USERS_ADD_BY_LOGIN),
          _("Add a new user specifying his/her login"));
  fprintf(fout, "<tr><td><input type=\"text\" size=\"32\" name=\"add_user_id\"/></td><td>");
  html_role_select(fout, USER_ROLE_OBSERVER, 0, "add_role_2");
  fprintf(fout, "</td><td>%s</td><td>%s</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_PRIV_USERS_ADD_BY_USER_ID),
          _("Add a new user specifying his/her User Id"));
  fprintf(fout, "</table>\n");

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  for (i = 0; i < users.u; i++) {
    if (users.v[i]) {
      xfree(users.v[i]->login);
      xfree(users.v[i]->name);
    }
    xfree(users.v[i]);
  }
  xfree(users.v);
  if (iter) iter->destroy(iter);
  html_armor_free(&ab);
}

static int
priv_view_report(FILE *fout,
                 FILE *log_f,
                 struct http_request_info *phr,
                 const struct contest_desc *cnts,
                 struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int run_id;
  int user_mode = 0;

  if (parse_run_id(fout, phr, cnts, extra, &run_id, 0) < 0) goto failure;

  if (opcaps_check(phr->caps, OPCAP_VIEW_REPORT) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }
  if (phr->action == NEW_SRV_ACTION_VIEW_USER_REPORT) user_mode = 1;

  ns_write_priv_report(cs, fout, log_f, phr, cnts, extra, user_mode, run_id);

 cleanup:
  return 0;

 failure:
  return -1;
}

static int
priv_view_source(FILE *fout,
                 FILE *log_f,
                 struct http_request_info *phr,
                 const struct contest_desc *cnts,
                 struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int run_id;

  if (parse_run_id(fout, phr, cnts, extra, &run_id, 0) < 0) goto failure;

  if (opcaps_check(phr->caps, OPCAP_VIEW_SOURCE) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  ns_write_priv_source(cs, fout, log_f, phr, cnts, extra, run_id);

 cleanup:
  return 0;

 failure:
  return -1;
}

static int
priv_download_source(FILE *fout,
                     FILE *log_f,
                     struct http_request_info *phr,
                     const struct contest_desc *cnts,
                     struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  int run_id, n, src_flags, no_disp = 0, x;
  const unsigned char *s;
  const struct section_problem_data *prob = 0;
  const struct section_language_data *lang = 0;
  struct run_entry re;
  path_t src_path;
  char *run_text = 0;
  size_t run_size = 0;
  int retval = 0;

  if (parse_run_id(fout, phr, cnts, extra, &run_id, &re) < 0) goto failure;
  if (ns_cgi_param(phr, "no_disp", &s) > 0
      && sscanf(s, "%d%n", &x, &n) == 1 && !s[n]
      && x >= 0 && x <= 1)
    no_disp = x;

  if (opcaps_check(phr->caps, OPCAP_VIEW_SOURCE) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (re.prob_id <= 0 || re.prob_id > cs->max_prob ||
      !(prob = cs->probs[re.prob_id]))
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  if (re.status > RUN_LAST
      || (re.status > RUN_MAX_STATUS && re.status < RUN_TRANSIENT_FIRST))
    FAIL(NEW_SRV_ERR_SOURCE_UNAVAILABLE);

  if ((src_flags = archive_make_read_path(cs, src_path, sizeof(src_path),
                                          global->run_archive_dir,
                                          run_id, 0, 1)) < 0)
    FAIL(NEW_SRV_ERR_SOURCE_NONEXISTANT);
  if (generic_read_file(&run_text, 0, &run_size, src_flags, 0, src_path, 0)<0)
    FAIL(NEW_SRV_ERR_DISK_READ_ERROR);

  if (prob->type_val > 0) {
    fprintf(fout, "Content-type: %s\n", mime_type_get_type(re.mime_type));
    if (!no_disp) {
      fprintf(fout, "Content-Disposition: attachment; filename=\"%06d%s\"\n",
              run_id, mime_type_get_suffix(re.mime_type));
    }
    putc_unlocked('\n', fout);
  } else {
    if(re.lang_id <= 0 || re.lang_id > cs->max_lang ||
       !(lang = cs->langs[re.lang_id]))
      FAIL(NEW_SRV_ERR_INV_LANG_ID);

    if (lang->content_type) {
      fprintf(fout, "Content-type: %s\n", lang->content_type);
    } else if (lang->binary) {
      fprintf(fout, "Content-type: application/octet-stream\n\n");
    } else {
      fprintf(fout, "Content-type: text/plain\n");
    }
    if (!no_disp) {
      fprintf(fout, "Content-Disposition: attachment; filename=\"%06d%s\"\n\n",
              run_id, lang->src_sfx);
    }
  }
  fwrite(run_text, 1, run_size, fout);

 cleanup:
  xfree(run_text);
  return retval;

 failure:
  xfree(run_text);
  return -1;
}

static int
priv_view_clar(FILE *fout,
               FILE *log_f,
               struct http_request_info *phr,
               const struct contest_desc *cnts,
               struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int clar_id, n;
  const unsigned char *s;

  if (ns_cgi_param(phr, "clar_id", &s) <= 0
      || sscanf(s, "%d%n", &clar_id, &n) != 1 || s[n]
      || clar_id < 0 || clar_id >= clar_get_total(cs->clarlog_state)) {
    ns_html_err_inv_param(fout, phr, 1, "cannot parse clar_id");
    return -1;
  }

  if (opcaps_check(phr->caps, OPCAP_VIEW_CLAR) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s %d", ns_unparse_role(phr->role),
            phr->name_arm, phr->contest_id, extra->contest_arm,
            _("Viewing clar"), clar_id);

  ns_write_priv_clar(cs, fout, log_f, phr, cnts, extra, clar_id);

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  return 0;
}

static int
priv_standings(FILE *fout,
               FILE *log_f,
               struct http_request_info *phr,
               const struct contest_desc *cnts,
               struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;

  if (phr->role < USER_ROLE_JUDGE) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }
  if (opcaps_check(phr->caps, OPCAP_VIEW_STANDINGS) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm, _("Current standings"));
  ns_write_priv_standings(cs, cnts, fout, cs->accepting_mode);
  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);
  
 cleanup:
  return 0;
}

static int
priv_view_test(FILE *fout,
               FILE *log_f,
               struct http_request_info *phr,
               const struct contest_desc *cnts,
               struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  int run_id, test_num, n, retval = 0;
  const unsigned char *s = 0;

  // run_id, test_num
  if (parse_run_id(fout, phr, cnts, extra, &run_id, 0) < 0) goto failure;
  if (ns_cgi_param(phr, "test_num", &s) <= 0
      || sscanf(s, "%d%n", &test_num, &n) != 1 || s[n]) {
    ns_html_err_inv_param(fout, phr, 1, "cannot parse test_num");
    return -1;
  }

  if (opcaps_check(phr->caps, OPCAP_VIEW_REPORT) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (test_num <= 0) FAIL(NEW_SRV_ERR_INV_TEST);

  ns_write_tests(cs, fout, log_f, phr->action, run_id, test_num);

 cleanup:
  return retval;

 failure:
  return -1;
}

static int
priv_upload_runlog_csv_1(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0;
  unsigned char bb[1024];

  if (opcaps_check(phr->caps, OPCAP_IMPORT_XML_RUNS) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);  

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm, "Add new runs in CSV format");
  html_start_form(fout, 2, phr->self_url, phr->hidden_vars);

  fprintf(fout, "<table>");
  fprintf(fout, "<tr><td>%s</td><td><input type=\"checkbox\" name=\"results_only\"/></td></tr>\n", _("Import results for existing runs"));
  fprintf(fout, "<tr><td>%s</td><td><input type=\"file\" name=\"file\"/></td></tr>\n",
          _("File"));
  fprintf(fout, "<tr><td>&nbsp;</td><td>%s</td></tr></table>\n",
          BUTTON(NEW_SRV_ACTION_UPLOAD_RUNLOG_CSV_2));

  fprintf(fout, "</form>\n");
  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  return retval;
}

static int
priv_upload_runlog_csv_2(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  int retval = 0, r;
  unsigned char bb[1024];
  const unsigned char *s = 0, *p, *ro_flag = 0;
  char *log_text = 0;
  size_t log_size = 0;
  FILE *ff = 0;
  unsigned char *ss = 0;

  if (opcaps_check(phr->caps, OPCAP_IMPORT_XML_RUNS) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);  

  if (!(r = ns_cgi_param(phr, "file", &s)))
    FAIL(NEW_SRV_ERR_FILE_UNSPECIFIED);
  else if (r < 0)
    FAIL(NEW_SRV_ERR_BINARY_FILE);

  for (p = s; *p && isspace(*p); p++);
  if (!*p) FAIL(NEW_SRV_ERR_FILE_EMPTY);

  ff = open_memstream(&log_text, &log_size);
  if (ns_cgi_param(phr, "results_only", &ro_flag) > 0) {
    r = ns_upload_csv_results(phr, cs, ff, s);
  } else {
    r = ns_upload_csv_runs(phr, cs, ff, s);
  }
  fclose(ff); ff = 0;

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm, _("Adding new runs"));

  fprintf(fout, "<h2>%s</h2>\n",
          (r >= 0)?_("Operation succeeded"):_("Operation failed"));

  fprintf(fout, "<table>");
  fprintf(fout, "<tr><td>%s%s</a></td></tr></table>",
          ns_aref(bb, sizeof(bb), phr, NEW_SRV_ACTION_MAIN_PAGE, 0),
          _("Main page"));

  ss = html_armor_string_dup(log_text);
  fprintf(fout, "<hr/><pre>");
  if (r < 0) fprintf(fout, "<font color=\"red\">");
  fprintf(fout, "%s", ss);
  if (r < 0) fprintf(fout, "</font>");
  fprintf(fout, "</pre>\n");
  xfree(ss); ss = 0;
  xfree(log_text); log_text = 0;

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  if (ff) fclose(ff);
  xfree(log_text);
  xfree(ss);
  return retval;
}

static int
priv_upload_runlog_xml_1(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0;
  unsigned char bb[1024];

  if (opcaps_check(phr->caps, OPCAP_IMPORT_XML_RUNS) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);  

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm, "Merge XML runlog");
  html_start_form(fout, 2, phr->self_url, phr->hidden_vars);

  fprintf(fout, "<table><tr><td>%s</td><td><input type=\"file\" name=\"file\"/></td></tr>\n", _("File"));
  fprintf(fout, "<tr><td>&nbsp;</td><td>%s</td></tr></table>\n",
          BUTTON(NEW_SRV_ACTION_UPLOAD_RUNLOG_XML_2));

  fprintf(fout, "</form>\n");
  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  return retval;
}

static int
priv_upload_runlog_xml_2(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  int retval = 0, r;
  unsigned char bb[1024];
  const unsigned char *s = 0, *p;
  char *log_text = 0;
  size_t log_size = 0;
  FILE *ff = 0;
  unsigned char *ss = 0;

  if (phr->role < USER_ROLE_ADMIN
      || opcaps_check(phr->caps, OPCAP_IMPORT_XML_RUNS) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (cs->global->enable_runlog_merge <= 0)
    FAIL(NEW_SRV_ERR_NOT_SUPPORTED);

  if (!(r = ns_cgi_param(phr, "file", &s)))
    FAIL(NEW_SRV_ERR_FILE_UNSPECIFIED);
  else if (r < 0)
    FAIL(NEW_SRV_ERR_BINARY_FILE);

  for (p = s; *p && isspace(*p); p++);
  if (!*p) FAIL(NEW_SRV_ERR_FILE_EMPTY);

  ff = open_memstream(&log_text, &log_size);
  runlog_import_xml(cs, cs->runlog_state, ff, 1, s);
  fclose(ff); ff = 0;

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm, _("Merging runs"));

  fprintf(fout, "<h2>%s</h2>\n", _("Operation completed"));

  fprintf(fout, "<table>");
  fprintf(fout, "<tr><td>%s%s</a></td></tr></table>",
          ns_aref(bb, sizeof(bb), phr, NEW_SRV_ACTION_MAIN_PAGE, 0),
          _("Main page"));

  ss = html_armor_string_dup(log_text);
  fprintf(fout, "<hr/><pre>");
  fprintf(fout, "%s", ss);
  fprintf(fout, "</pre>\n");
  xfree(ss); ss = 0;
  xfree(log_text); log_text = 0;

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  if (ff) fclose(ff);
  xfree(log_text);
  xfree(ss);
  return retval;
}

static int
priv_download_runs_confirmation(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  //const serve_state_t cs = extra->serve_state;
  int retval = 0;
  unsigned char bb[1024];
  unsigned long *mask = 0, mval;
  size_t mask_size = 0;
  const unsigned char *mask_size_str = 0;
  const unsigned char *mask_str = 0;
  size_t mask_count = 0;
  int i, j;

  if (opcaps_check(phr->caps, OPCAP_DUMP_RUNS) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);  

  if (parse_run_mask(phr, &mask_size_str, &mask_str, &mask_size, &mask) < 0)
    goto invalid_param;

  for (i = 0; i < mask_size; i++) {
    mval = mask[i];
    for (j = 0; j < 8 * sizeof(mask[0]); j++, mval >>= 1)
      if ((mval & 1)) mask_count++;
  }

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm, "Download runs configuration");

  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
  html_hidden(fout, "run_mask_size", "%s", mask_size_str);
  html_hidden(fout, "run_mask", "%s", mask_str);
  fprintf(fout, "<h2>%s</h2>\n", _("Run selection"));
  fprintf(fout, "<table>");
  fprintf(fout, "<tr><td><input type=\"radio\" name=\"run_selection\" value=\"0\" checked=\"yes\"/></td><td>%s</td></tr>\n", _("Download all runs"));
  fprintf(fout, "<tr><td><input type=\"radio\" name=\"run_selection\" value=\"1\"/></td><td>%s (%zu)</td></tr>\n", _("Download selected runs"), mask_count);
  fprintf(fout, "<tr><td><input type=\"radio\" name=\"run_selection\" value=\"2\"/></td><td>%s</td></tr>\n", _("Download OK runs"));
  fprintf(fout, "</table>\n");

  fprintf(fout, "<h2>%s</h2>\n", _("File name pattern"));
  fprintf(fout, "<table>");
  fprintf(fout, "<tr><td><input type=\"checkbox\" name=\"file_pattern_run\" checked=\"yes\"/></td><td>%s</td></tr>\n", _("Use run number"));
  fprintf(fout, "<tr><td><input type=\"checkbox\" name=\"file_pattern_uid\"/></td><td>%s</td></tr>\n", _("Use user Id"));
  fprintf(fout, "<tr><td><input type=\"checkbox\" name=\"file_pattern_login\"/></td><td>%s</td></tr>\n", _("Use user Login"));
  fprintf(fout, "<tr><td><input type=\"checkbox\" name=\"file_pattern_name\"/></td><td>%s</td></tr>\n", _("Use user Name"));
  fprintf(fout, "<tr><td><input type=\"checkbox\" name=\"file_pattern_prob\"/></td><td>%s</td></tr>\n", _("Use problem short name"));
  fprintf(fout, "<tr><td><input type=\"checkbox\" name=\"file_pattern_lang\"/></td><td>%s</td></tr>\n", _("Use programming language short name"));
  fprintf(fout, "<tr><td><input type=\"checkbox\" name=\"file_pattern_suffix\" checked=\"yes\"/></td><td>%s</td></tr>\n", _("Use source language or content type suffix"));
  fprintf(fout, "</table>\n");

  fprintf(fout, "<h2>%s</h2>\n", _("Directory structure"));
  fprintf(fout, "<table>");
  fprintf(fout, "<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"0\" checked=\"yes\"/></td><td>%s</td></tr>\n", _("No directory structure"));
  fprintf(fout, "<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"1\"/></td><td>%s</td></tr>\n", _("/&lt;Problem&gt;/&lt;File&gt;"));
  fprintf(fout, "<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"2\"/></td><td>%s</td></tr>\n", _("/&lt;User_Id&gt;/&lt;File&gt;"));
  fprintf(fout, "<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"3\"/></td><td>%s</td></tr>\n", _("/&lt;User_Login&gt;/&lt;File&gt;"));
  fprintf(fout, "<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"8\"/></td><td>%s</td></tr>\n", _("/&lt;User_Name&gt;/&lt;File&gt;"));
  fprintf(fout, "<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"4\"/></td><td>%s</td></tr>\n", _("/&lt;Problem&gt;/&lt;User_Id&gt;/&lt;File&gt;"));
  fprintf(fout, "<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"5\"/></td><td>%s</td></tr>\n", _("/&lt;Problem&gt;/&lt;User_Login&gt;/&lt;File&gt;"));
  fprintf(fout, "<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"9\"/></td><td>%s</td></tr>\n", _("/&lt;Problem&gt;/&lt;User_Name&gt;/&lt;File&gt;"));
  fprintf(fout, "<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"6\"/></td><td>%s</td></tr>\n", _("/&lt;User_Id&gt;/&lt;Problem&gt;/&lt;File&gt;"));
  fprintf(fout, "<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"7\"/></td><td>%s</td></tr>\n", _("/&lt;User_Login&gt;/&lt;Problem&gt;/&lt;File&gt;"));
  fprintf(fout, "<tr><td><input type=\"radio\" name=\"dir_struct\" value=\"10\"/></td><td>%s</td></tr>\n", _("/&lt;User_Name&gt;/&lt;Problem&gt;/&lt;File&gt;"));
  fprintf(fout, "</table>\n");

  fprintf(fout, "<h2>%s</h2>\n", _("Download runs"));
  fprintf(fout, "<table>");
  fprintf(fout, "<tr><td>%s</td></tr>",
          BUTTON(NEW_SRV_ACTION_DOWNLOAD_ARCHIVE_2));
  fprintf(fout, "<tr><td>%s%s</a></td></tr></table>",
          ns_aref(bb, sizeof(bb), phr, NEW_SRV_ACTION_MAIN_PAGE, 0),
          _("Main page"));
  fprintf(fout, "</form>\n");

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  return retval;

 invalid_param:
  ns_html_err_inv_param(fout, phr, 0, 0);
  xfree(mask);
  return -1;
}

static int
priv_download_runs(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  int retval = 0;
  unsigned long *mask = 0;
  size_t mask_size = 0;
  int x;
  int dir_struct = 0;
  int run_selection = 0;
  int file_name_mask = 0;
  const unsigned char *s;
  char *ss = 0;

  if (opcaps_check(phr->caps, OPCAP_DUMP_RUNS) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  // run_selection
  // dir_struct
  // file_pattern_run
  // file_pattern_uid
  // file_pattern_login
  // file_pattern_name
  // file_pattern_prob
  // file_pattern_lang
  // file_pattern_suffix
  if (ns_cgi_param(phr, "run_selection", &s) <= 0)
    FAIL(NEW_SRV_ERR_INV_RUN_SELECTION);
  errno = 0;
  x = strtol(s, &ss, 10);
  if (errno || *ss || x < 0 || x > 2) FAIL(NEW_SRV_ERR_INV_RUN_SELECTION);
  run_selection = x;

  if (ns_cgi_param(phr, "dir_struct", &s) <= 0)
    FAIL(NEW_SRV_ERR_INV_DIR_STRUCT);
  errno = 0;
  x = strtol(s, &ss, 10);
  if (errno || *ss || x < 0 || x > 10) FAIL(NEW_SRV_ERR_INV_DIR_STRUCT);
  dir_struct = x;

  if (ns_cgi_param(phr, "file_pattern_run", &s) > 0)
    file_name_mask |= NS_FILE_PATTERN_RUN;
  if (ns_cgi_param(phr, "file_pattern_uid", &s) > 0)
    file_name_mask |= NS_FILE_PATTERN_UID;
  if (ns_cgi_param(phr, "file_pattern_login", &s) > 0)
    file_name_mask |= NS_FILE_PATTERN_LOGIN;
  if (ns_cgi_param(phr, "file_pattern_name", &s) > 0)
    file_name_mask |= NS_FILE_PATTERN_NAME;
  if (ns_cgi_param(phr, "file_pattern_prob", &s) > 0)
    file_name_mask |= NS_FILE_PATTERN_PROB;
  if (ns_cgi_param(phr, "file_pattern_lang", &s) > 0)
    file_name_mask |= NS_FILE_PATTERN_LANG;
  if (ns_cgi_param(phr, "file_pattern_suffix", &s) > 0)
    file_name_mask |= NS_FILE_PATTERN_SUFFIX;
  if (!file_name_mask) file_name_mask = NS_FILE_PATTERN_RUN;

  if (parse_run_mask(phr, 0, 0, &mask_size, &mask) < 0)
    goto invalid_param;

  ns_download_runs(cs, fout, log_f, run_selection, dir_struct, file_name_mask,
                   mask_size, mask);

 cleanup:
  return retval;

 invalid_param:
  ns_html_err_inv_param(fout, phr, 0, 0);
  xfree(mask);
  return -1;
}

static int
priv_upsolving_configuration_1(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  int retval = 0;
  unsigned char bb[1024];
  const unsigned char *freeze_standings = 0;
  const unsigned char *view_source = 0;
  const unsigned char *view_protocol = 0;
  const unsigned char *full_proto = 0;
  const unsigned char *disable_clars = 0;

  if (opcaps_check(phr->caps, OPCAP_CONTROL_CONTEST) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);  

  if (cs->upsolving_mode) {
    ns_cgi_param(phr, "freeze_standings", &freeze_standings);
    ns_cgi_param(phr, "view_source", &view_source);
    ns_cgi_param(phr, "view_protocol", &view_protocol);
    ns_cgi_param(phr, "full_protocol", &full_proto);
    ns_cgi_param(phr, "disable_clars", &disable_clars);
  } else {
    freeze_standings = "1";
    view_source = "1";
    view_protocol = "1";
    full_proto = 0;
    disable_clars = "1";
  }

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm, "Upsolving configuration");

  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
  fprintf(fout, "<table>");
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          html_checkbox(bb, sizeof(bb), "freeze_standings",
                        freeze_standings?1:0),
          _("Freeze contest standings"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          html_checkbox(bb, sizeof(bb), "view_source",
                        view_source?1:0),
          _("Allow viewing source code"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          html_checkbox(bb, sizeof(bb), "view_protocol",
                        view_protocol?1:0),
          _("Allow viewing run report"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          html_checkbox(bb, sizeof(bb), "full_protocol",
                        full_proto?1:0),
          _("Allow viewing full protocol"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          html_checkbox(bb, sizeof(bb), "disable_clars",
                        disable_clars?1:0),
          _("Disable clarifications"));
  fprintf(fout, "</table>\n");

  fprintf(fout, "<table><tr>");
  fprintf(fout, "<td>%s</td>",
          BUTTON(NEW_SRV_ACTION_UPSOLVING_CONFIG_2));
  fprintf(fout, "<td>%s</td>",
          BUTTON(NEW_SRV_ACTION_UPSOLVING_CONFIG_3));
  fprintf(fout, "<td>%s</td>",
          BUTTON(NEW_SRV_ACTION_UPSOLVING_CONFIG_4));
  fprintf(fout, "</tr></table>\n");

  fprintf(fout, "</form>\n");

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  return retval;
}

static int
priv_upsolving_operation(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  int retval = 0;
  const unsigned char *freeze_standings = 0;
  const unsigned char *view_source = 0;
  const unsigned char *view_protocol = 0;
  const unsigned char *full_proto = 0;
  const unsigned char *disable_clars = 0;
  time_t duration = 0, saved_stop_time = 0, stop_time = 0;

  if (opcaps_check(phr->caps, OPCAP_CONTROL_CONTEST) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  /* check that the contest is stopped */
  run_get_saved_times(cs->runlog_state, &duration, &saved_stop_time);
  stop_time = run_get_stop_time(cs->runlog_state);
  if (stop_time <= 0 && saved_stop_time <= 0) return 0;

  ns_cgi_param(phr, "freeze_standings", &freeze_standings);
  ns_cgi_param(phr, "view_source", &view_source);
  ns_cgi_param(phr, "view_protocol", &view_protocol);
  ns_cgi_param(phr, "full_protocol", &full_proto);
  ns_cgi_param(phr, "disable_clars", &disable_clars);

  switch (phr->action) {
  case NEW_SRV_ACTION_UPSOLVING_CONFIG_2: // back to main page
    break;
  case NEW_SRV_ACTION_UPSOLVING_CONFIG_3: // stop upsolving
    if (!cs->upsolving_mode) break;
    run_stop_contest(cs->runlog_state, cs->current_time);
    cs->upsolving_mode = 0;
    cs->freeze_standings = 0;
    cs->view_source = 0;
    cs->view_protocol = 0;
    cs->full_protocol = 0;
    cs->disable_clars = 0;
    serve_update_status_file(cs, 1);
    extra->last_access_time = 0;          // force reload
    break;
  case NEW_SRV_ACTION_UPSOLVING_CONFIG_4: // start upsolving
    run_save_times(cs->runlog_state);
    run_set_duration(cs->runlog_state, 0);
    run_stop_contest(cs->runlog_state, 0);
    cs->upsolving_mode = 1;
    cs->freeze_standings = 0;
    cs->view_source = 0;
    cs->view_protocol = 0;
    cs->full_protocol = 0;
    cs->disable_clars = 0;
    if (freeze_standings && *freeze_standings) cs->freeze_standings = 1;
    if (view_source && *view_source) cs->view_source = 1;
    if (view_protocol && *view_protocol) cs->view_protocol = 1;
    if (full_proto && *full_proto) cs->full_protocol = 1;
    if (disable_clars && *disable_clars) cs->disable_clars = 1;
    serve_update_status_file(cs, 1);
    extra->last_access_time = 0;          // force reload
    break;
  default:
    abort();
  }

 cleanup:
  return retval;
}

static int
priv_assign_cyphers_1(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0;
  unsigned char bb[1024];

  if (opcaps_check(phr->caps, OPCAP_CONTROL_CONTEST) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);  

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm, "Assign cyphers");
  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
  fprintf(fout, "<table>\n");

  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          html_input_text(bb, sizeof(bb), "prefix", 16, 0),
          _("Cypher prefix"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          html_input_text(bb, sizeof(bb), "min_num", 16, 0),
          _("Minimal random number"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          html_input_text(bb, sizeof(bb), "max_num", 16, 0),
          _("Maximal random number"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          html_input_text(bb, sizeof(bb), "seed", 16, 0),
          _("Random seed"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          html_input_text(bb, sizeof(bb), "mult", 16, 0),
          _("Mult parameter"));
  fprintf(fout, "<tr><td>%s</td><td>%s</td></tr>\n",
          html_input_text(bb, sizeof(bb), "shift", 16, 0),
          _("Shift parameter"));
  fprintf(fout, "<tr><td>%s</td><td>&nbsp;</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_ASSIGN_CYPHERS_2));

  fprintf(fout, "</table>\n");
  fprintf(fout, "</form>\n");
  fprintf(fout, "<p>The following formula is applied: mult * X + shift.</p>\n");
  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  return retval;
}

static int
priv_assign_cyphers_2(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  //const struct section_global_data *global = cs->global;
  int retval = 0;
  const unsigned char *prefix = 0;
  int min_num = 0, max_num = 0, seed = 0, total_users = 0, user_count, user_id;
  int max_user_id, i, j, r;
  int mult = 1, shift = 0;
  int *user_ids = 0, *rand_map = 0, *user_cyphers = 0;
  char *msg_txt = 0;
  size_t msg_len = 0;
  FILE *msg_f = 0;
  unsigned char **user_logins = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char *csv_reply = 0;

  if (phr->role < USER_ROLE_ADMIN)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (opcaps_check(phr->caps, OPCAP_EDIT_REG) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (ns_cgi_param(phr, "prefix", &prefix) <= 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  if (ns_cgi_param_int(phr, "min_num", &min_num) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  if (ns_cgi_param_int(phr, "max_num", &max_num) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  if (ns_cgi_param_int(phr, "seed", &seed) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  if (ns_cgi_param_int_opt(phr, "mult", &mult, 1) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  if (ns_cgi_param_int_opt(phr, "shift", &shift, 1) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  if (min_num < 0 || max_num < 0 || min_num > max_num || seed < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);

  total_users = teamdb_get_total_teams(cs->teamdb_state);
  if (total_users >= max_num - min_num)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  XCALLOC(user_ids, total_users + 2);
  XCALLOC(user_cyphers, total_users + 2);
  XCALLOC(user_logins, total_users + 2);
  max_user_id = teamdb_get_max_team_id(cs->teamdb_state);
  for (user_id = 1, user_count = 0;
       user_id <= max_user_id && user_count <= total_users; user_id++) {
    if (teamdb_lookup(cs->teamdb_state, user_id) <= 0) continue;
    if (teamdb_get_flags(cs->teamdb_state, user_id) != 0) continue;
    user_logins[user_count] = xstrdup(teamdb_get_login(cs->teamdb_state, user_id));
    user_ids[user_count++] = user_id;
  }

  if (!seed) {
    struct timeval tv;
    gettimeofday(&tv, 0);
    seed = (tv.tv_sec ^ tv.tv_usec) & INT_MAX;
    if (!seed) seed = tv.tv_sec;
  }
  srand(seed);
  XCALLOC(rand_map, max_num - min_num + 1);

  for (i = 0; i < user_count; i++) {
    do {
      j = min_num + (int)((rand() / (RAND_MAX + 1.0)) * (max_num - min_num + 1));
    } while (rand_map[j - min_num]);
    rand_map[j - min_num] = user_ids[i];
    user_cyphers[i] = j;
  }

  if (!prefix) prefix = "";
  msg_f = open_memstream(&msg_txt, &msg_len);
  fprintf(msg_f, "Login;Exam_Cypher\n");
  for (i = 0; i < user_count; i++) {
    fprintf(msg_f, "%s;%s%d\n", user_logins[i], prefix,
            mult * user_cyphers[i] + shift);
  }
  fclose(msg_f); msg_f = 0;


  if (ns_open_ul_connection(phr->fw_state) < 0)
    FAIL(NEW_SRV_ERR_TRY_AGAIN);
  r = userlist_clnt_import_csv_users(ul_conn, ULS_IMPORT_CSV_USERS,
                                     phr->contest_id, ';', 0, msg_txt,
                                     &csv_reply);
  if (r < 0) FAIL(NEW_SRV_ERR_INTERNAL);

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role),
            phr->name_arm, phr->contest_id, extra->contest_arm,
            _("Assigned cyphers"));

  fprintf(fout, "<table class=\"b1\">\n");
  fprintf(fout, "<tr><td class=\"b1\">NN</td><td class=\"b1\">%s</td><td class=\"b1\">%s</td><td class=\"b1\">%s</td></tr>\n",
          _("User Id"), _("Login"), _("Cypher"));
  for (i = 0; i < user_count; i++) {
    fprintf(fout, "<tr><td class=\"b1\">%d</td><td class=\"b1\">%d</td><td class=\"b1\">%s</td>",
            i + 1, user_ids[i], ARMOR(user_logins[i]));
    fprintf(fout, "<td class=\"b1\">%s%d</td></tr>\n",
            ARMOR(prefix), mult * user_cyphers[i] + shift);
  }
  fprintf(fout, "</table>\n");

  if (csv_reply && *csv_reply) {
    fprintf(fout, "<h2>Operation status</h2>\n");
    fprintf(fout, "<pre>%s</pre>\n", ARMOR(csv_reply));
  }

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  xfree(csv_reply);
  if (user_logins) {
    for (i = 0; i < total_users + 2; i++)
      xfree(user_logins[i]);
    xfree(user_logins);
  }
  xfree(msg_txt);
  if (msg_f) fclose(msg_f);
  xfree(rand_map);
  xfree(user_cyphers);
  xfree(user_ids);
  html_armor_free(&ab);
  return retval;
}

static int
priv_view_passwords(FILE *fout,
                    FILE *log_f,
                    struct http_request_info *phr,
                    const struct contest_desc *cnts,
                    struct contest_extra *extra)
{
  int retval = 0;
  const unsigned char *s = 0;

  /*
  if (opcaps_check(phr->caps, OPCAP_GENERATE_TEAM_PASSWORDS) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  */
  if (phr->action == NEW_SRV_ACTION_VIEW_CNTS_PWDS
      && cnts->disable_team_password)
    FAIL(NEW_SRV_ERR_TEAM_PWD_DISABLED);

  l10n_setlocale(phr->locale_id);
  if (phr->action == NEW_SRV_ACTION_VIEW_CNTS_PWDS) {
    s = _("Contest passwords");
  } else {
    s = _("Registration passwords");
  }
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role),
            phr->name_arm, phr->contest_id, extra->contest_arm, s);

  ns_write_passwords(fout, log_f, phr, cnts, extra);

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  return retval;
}

static int
priv_view_online_users(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0;

  if (phr->role < USER_ROLE_JUDGE) FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role),
            phr->name_arm, phr->contest_id, extra->contest_arm,
            _("Online users"));
  ns_write_online_users(fout, log_f, phr, cnts, extra);
  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  return retval;
}

static int
priv_view_exam_info(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0;

  if (phr->role < USER_ROLE_JUDGE) FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role),
            phr->name_arm, phr->contest_id, extra->contest_arm,
            _("Examination information"));
  ns_write_exam_info(fout, log_f, phr, cnts, extra);
  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  return retval;
}

static int
priv_print_user_exam_protocol(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  int retval = 0, user_id, r;
  char *log_text = 0;
  size_t log_size = 0;
  FILE *ff = 0;
  unsigned char bb[1024];
  unsigned char *ss = 0;
  int locale_id = 0;
  int use_user_printer = 0;
  int full_report = 0;
  int use_cypher = 0;

  if (opcaps_check(phr->caps, OPCAP_PRINT_RUN) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (ns_cgi_param_int(phr, "user_id", &user_id) < 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);
  if (!teamdb_lookup(cs->teamdb_state, user_id))
    FAIL(NEW_SRV_ERR_INV_USER_ID);

  if (phr->action == NEW_SRV_ACTION_PRINT_UFC_PROTOCOL) {
    full_report = 1;
    use_cypher = 1;
  } else if (phr->action == NEW_SRV_ACTION_PRINT_USER_FULL_PROTOCOL) {
    full_report = 1;
  } else {
    use_user_printer = 1;
  }

  if (cnts->default_locale_val > 0) locale_id = cnts->default_locale_val;
  if (locale_id > 0) l10n_setlocale(locale_id);
  ff = open_memstream(&log_text, &log_size);
  r = ns_print_user_exam_protocol(cnts, cs, ff, user_id, locale_id,
                                  use_user_printer, full_report, use_cypher);
  fclose(ff); ff = 0;
  if (locale_id > 0) l10n_setlocale(0);

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm, _("Printing user protocol"));

  fprintf(fout, "<h2>%s</h2>\n",
          (r >= 0)?_("Operation succeeded"):_("Operation failed"));

  fprintf(fout, "<table>");
  fprintf(fout, "<tr><td>%s%s</a></td></tr></table>",
          ns_aref(bb, sizeof(bb), phr, NEW_SRV_ACTION_MAIN_PAGE, 0),
          _("Main page"));

  ss = html_armor_string_dup(log_text);
  fprintf(fout, "<hr/><pre>");
  if (r < 0) fprintf(fout, "<font color=\"red\">");
  fprintf(fout, "%s", ss);
  if (r < 0) fprintf(fout, "</font>");
  fprintf(fout, "</pre>\n");
  xfree(ss); ss = 0;
  xfree(log_text); log_text = 0;

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  if (ff) fclose(ff);
  xfree(ss);
  xfree(log_text);
  return retval;
}

static int
priv_print_users_exam_protocol(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  int retval = 0, r;
  char *log_text = 0;
  size_t log_size = 0;
  FILE *ff = 0;
  unsigned char bb[1024];
  unsigned char *ss = 0;
  int locale_id = 0, i, x, n;
  intarray_t uset;
  const unsigned char *s;
  int use_user_printer = 0;
  int full_report = 0;
  int use_cypher = 0;
  int first_user_id = 0, last_user_id = -1;

  if (opcaps_check(phr->caps, OPCAP_PRINT_RUN) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  memset(&uset, 0, sizeof(uset));
  for (i = 0; i < phr->param_num; i++) {
    if (strncmp(phr->param_names[i], "user_", 5) != 0) continue;
    if (sscanf((s = phr->param_names[i] + 5), "%d%n", &x, &n) != 1
        || s[n] || x <= 0)
      FAIL(NEW_SRV_ERR_INV_USER_ID);
    if (teamdb_lookup(cs->teamdb_state, x) <= 0)
      FAIL(NEW_SRV_ERR_INV_USER_ID);

    XEXPAND2(uset);
    uset.v[uset.u++] = x;
  }

  priv_parse_user_id_range(phr, &first_user_id, &last_user_id);
  if (first_user_id > 0) {
    for (i = first_user_id; i <= last_user_id; i++) {
      XEXPAND2(uset);
      uset.v[uset.u++] = i;
    }
  }

  if (phr->action == NEW_SRV_ACTION_PRINT_SELECTED_UFC_PROTOCOL) {
    full_report = 1;
    use_cypher = 1;
  } else if (phr->action == NEW_SRV_ACTION_PRINT_SELECTED_USER_FULL_PROTOCOL) {
    full_report = 1;
  } else {
    use_user_printer = 1;
  }

  if (cnts->default_locale_val > 0) locale_id = cnts->default_locale_val;
  if (locale_id > 0) l10n_setlocale(locale_id);
  ff = open_memstream(&log_text, &log_size);
  if (cs->contest_plugin && cs->contest_plugin->print_user_reports) {
    r = (*cs->contest_plugin->print_user_reports)
      (cs->contest_plugin_data, ff, cnts, cs, uset.u, uset.v, locale_id,
       use_user_printer, full_report, use_cypher);
  } else {
    r = ns_print_user_exam_protocols(cnts, cs, ff, uset.u, uset.v, locale_id,
                                     use_user_printer, full_report, use_cypher);
  }
  fclose(ff); ff = 0;
  if (locale_id > 0) l10n_setlocale(0);

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm, _("Printing user protocol"));

  fprintf(fout, "<h2>%s</h2>\n",
          (r >= 0)?_("Operation succeeded"):_("Operation failed"));

  fprintf(fout, "<table>");
  fprintf(fout, "<tr><td>%s%s</a></td></tr></table>",
          ns_aref(bb, sizeof(bb), phr, NEW_SRV_ACTION_MAIN_PAGE, 0),
          _("Main page"));

  ss = html_armor_string_dup(log_text);
  fprintf(fout, "<hr/><pre>");
  if (r < 0) fprintf(fout, "<font color=\"red\">");
  fprintf(fout, "%s", ss);
  if (r < 0) fprintf(fout, "</font>");
  fprintf(fout, "</pre>\n");
  xfree(ss); ss = 0;
  xfree(log_text); log_text = 0;

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  if (ff) fclose(ff);
  xfree(uset.v);
  xfree(ss);
  xfree(log_text);
  return retval;
}

static int
priv_print_problem_exam_protocol(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  int retval = 0, r;
  char *log_text = 0;
  size_t log_size = 0;
  FILE *ff = 0;
  unsigned char bb[1024];
  unsigned char *ss = 0;
  int locale_id = 0;
  int prob_id;

  if (opcaps_check(phr->caps, OPCAP_PRINT_RUN) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (ns_cgi_param_int(phr, "prob_id", &prob_id) < 0)
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  if (prob_id <= 0 || prob_id > cs->max_prob || !cs->probs[prob_id])
    FAIL(NEW_SRV_ERR_INV_PROB_ID);

  if (cnts->default_locale_val > 0) locale_id = cnts->default_locale_val;
  if (locale_id > 0) l10n_setlocale(locale_id);
  ff = open_memstream(&log_text, &log_size);
  r = ns_print_prob_exam_protocol(cnts, cs, ff, prob_id, locale_id, 1);
  fclose(ff); ff = 0;
  if (locale_id > 0) l10n_setlocale(0);

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm,_("Printing problem protocol"));

  fprintf(fout, "<h2>%s</h2>\n",
          (r >= 0)?_("Operation succeeded"):_("Operation failed"));

  fprintf(fout, "<table>");
  fprintf(fout, "<tr><td>%s%s</a></td></tr></table>",
          ns_aref(bb, sizeof(bb), phr, NEW_SRV_ACTION_MAIN_PAGE, 0),
          _("Main page"));

  ss = html_armor_string_dup(log_text);
  fprintf(fout, "<hr/><pre>");
  if (r < 0) fprintf(fout, "<font color=\"red\">");
  fprintf(fout, "%s", ss);
  if (r < 0) fprintf(fout, "</font>");
  fprintf(fout, "</pre>\n");
  xfree(ss); ss = 0;
  xfree(log_text); log_text = 0;

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  if (ff) fclose(ff);
  xfree(ss);
  xfree(log_text);
  return retval;
}

static void
unpriv_print_status(FILE *fout,
                    struct http_request_info *phr,
                    const struct contest_desc *cnts,
                    struct contest_extra *extra,
                    time_t start_time, time_t stop_time, time_t duration,
                    time_t sched_time,
                    time_t fog_start_time)
{
  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const unsigned char *s = 0;
  unsigned char duration_buf[128];
  unsigned char bb[1024];
  time_t tmpt;

  if (!cnts->exam_mode) {
    fprintf(fout, "<%s>%s</%s>\n",
            cnts->team_head_style, _("Server status"),
            cnts->team_head_style);
    if (stop_time > 0) {
      if (duration > 0 && global->board_fog_time > 0
          && global->board_unfog_time > 0
          && cs->current_time < stop_time + global->board_unfog_time
          && !cs->standings_updated) {
        if (cnts->exam_mode) {
          s = _("The exam is over (standings are frozen)");
        } else {
          s = _("The contest is over (standings are frozen)");
        }
      } else if (cnts->exam_mode) {
        s = _("The exam is over");
      } else {
        s = _("The contest is over");
      }
    } else if (start_time > 0) {
      if (fog_start_time > 0 && cs->current_time >= fog_start_time) {
        if (cnts->exam_mode) {
          s = _("The exam is in progress (standings are frozen)");
        } else {
          s = _("The contest is in progress (standings are frozen)");
        }
      } else {
        if (cnts->exam_mode) {
          s = _("The exam is in progress");
        } else {
          s = _("The contest is in progress");
        }
      }
    } else {
      if (cnts->exam_mode) {
        s = _("The exam is not started");
      } else {
        s = _("The contest is not started");
      }
    }
    fprintf(fout, "<p><b>%s</b></p>\n", s);

    if (cs->upsolving_mode) {
      fprintf(fout, "<p><b>%s</b></p>\n", _("Upsolving mode"));
    }

    if (start_time > 0) {
      if (global->score_system_val == SCORE_OLYMPIAD && !global->is_virtual) {
        if (cs->accepting_mode)
          s = _("Participants' solutions are being accepted");
        else if (!cs->testing_finished)
          s = _("Participants' solutions are being judged");
        else
          s = _("Participants' solutions are judged");
        fprintf(fout, "<p><b>%s</b></p>\n", s);
      }
    }

    if (cs->clients_suspended) {
      fprintf(fout, "<p><b>%s</b></p>\n",
              _("Participants' requests are suspended"));
    }

    if (start_time > 0) {
      if (cs->testing_suspended) {
        fprintf(fout, "<p><b>%s</b></p>\n",
                _("Testing of participants' submits is suspended"));
      }
      if (cs->printing_suspended) {
        fprintf(fout, "<p><b>%s</b></p>\n",
                _("Print requests are suspended"));
      }
    }

    fprintf(fout, "<table class=\"b0\">");
    fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">%s</td></tr>\n",
            _("Server time"), ctime(&cs->current_time));
    if (start_time > 0) {
      if (cnts->exam_mode) {
        s = _("Exam start time");
      } else {
        s = _("Contest start time");
      }
      fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">%s</td></tr>\n",
              s, ctime(&start_time));
    }
    if (!global->is_virtual && start_time <= 0 && sched_time > 0) {
      fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">%s</td></tr>\n",
              _("Planned start time"), ctime(&sched_time));
    }
    if (stop_time <= 0 && (duration > 0 || global->contest_finish_time_d <= 0)) {
      if (duration > 0) {
        duration_str(0, duration, 0, duration_buf, 0);
      } else {
        snprintf(duration_buf, sizeof(duration_buf), "%s", _("Unlimited"));
      }
      fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">%s</td></tr>\n",
              _("Duration"), duration_buf);
    }
    if (start_time > 0 && stop_time <= 0 && duration > 0) {
      tmpt = start_time + duration;
      fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">%s</td></tr>\n",
              _("Scheduled end time"), ctime(&tmpt));
    } else if (start_time > 0 && stop_time <= 0 && duration <= 0
               && global->contest_finish_time_d > 0) {
      fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">%s</td></tr>\n",
              _("Scheduled end time"), ctime(&global->contest_finish_time_d));
    } else if (stop_time) {
      fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">%s</td></tr>\n",
              _("End time"), ctime(&stop_time));
    }

    if (start_time > 0 && stop_time <= 0 && fog_start_time > 0) {
      fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">%s</td></tr>\n",
              _("Standings freeze time"), ctime(&fog_start_time));
    } else if (stop_time > 0 && duration > 0 && global->board_fog_time > 0
               && global->board_unfog_time > 0 && !cs->standings_updated
               && cs->current_time < stop_time + global->board_unfog_time) {
      tmpt = stop_time + global->board_unfog_time;
      fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">%s</td></tr>\n",
              _("Standings unfreeze time"), ctime(&tmpt));
    }

    if (start_time > 0 && stop_time <= 0 && duration > 0) {
      duration_str(0, cs->current_time, start_time, duration_buf, 0);
      fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">%s</td></tr>\n",
              _("Elapsed time"), duration_buf);
      duration_str(0, start_time + duration - cs->current_time, 0,
                   duration_buf, 0);
      fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">%s</td></tr>\n",
              _("Remaining time"), duration_buf);
    }
    fprintf(fout, "</table>\n");
  }

  if (global->description_file[0]) {
    watched_file_update(&cs->description, global->description_file,
                        cs->current_time);
    if (cs->description.text) {
      fprintf(fout, "%s", cs->description.text);
    }
  }

  if (!cnts->exam_mode) {
    fprintf(fout, "<p><b>%s: %d</b></p>\n",
            _("On-line users in this contest"), phr->online_users);
    if (cs->max_online_count > 0) {
      fprintf(fout, "<p><b>%s: %d, %s</b></p>\n",
              _("Max number of users was"), cs->max_online_count,
              xml_unparse_date(cs->max_online_time));
    }
  }

  if (!cnts->exam_mode && global->is_virtual && start_time <= 0) {
    if (global->disable_virtual_start <= 0) {
      html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
      if (cnts->exam_mode) {
        fprintf(fout, "<p>%s</p></form>",
                ns_submit_button(bb, sizeof(bb), 0,
                                 NEW_SRV_ACTION_VIRTUAL_START,
                                 _("Start exam")));
      } else {
        fprintf(fout, "<p>%s</p></form>",
                BUTTON(NEW_SRV_ACTION_VIRTUAL_START));
      }
    }
  } else if (!cnts->exam_mode && global->is_virtual && stop_time <= 0) {
    html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
    if (cnts->exam_mode) {
      fprintf(fout, "<p>%s</p></form>",
              ns_submit_button(bb, sizeof(bb), 0, NEW_SRV_ACTION_VIRTUAL_STOP,
                               _("Stop exam")));
    } else {
      fprintf(fout, "<p>%s</p></form>",
              BUTTON(NEW_SRV_ACTION_VIRTUAL_STOP));
    }
  }
}

typedef int (*action_handler2_t)(FILE *fout,
                                 FILE *log_f,
                                 struct http_request_info *phr,
                                 const struct contest_desc *cnts,
                                 struct contest_extra *extra);

static action_handler2_t priv_actions_table_2[NEW_SRV_ACTION_LAST] =
{
#if 0
  [NEW_SRV_ACTION_VIEW_USERS] = priv_view_users_page,
  [NEW_SRV_ACTION_PRIV_USERS_VIEW] = priv_view_priv_users_page,
#endif
  /* for priv_generic_operation */
  [NEW_SRV_ACTION_USERS_REMOVE_REGISTRATIONS] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_SET_PENDING] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_SET_OK] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_SET_REJECTED] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_SET_INVISIBLE] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_CLEAR_INVISIBLE] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_SET_BANNED] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_CLEAR_BANNED] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_SET_LOCKED] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_CLEAR_LOCKED] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_SET_INCOMPLETE] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_CLEAR_INCOMPLETE] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_SET_DISQUALIFIED] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_CLEAR_DISQUALIFIED] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_ADD_BY_LOGIN] = priv_add_user_by_login,
  [NEW_SRV_ACTION_USERS_ADD_BY_USER_ID] = priv_add_user_by_user_id,
  [NEW_SRV_ACTION_PRIV_USERS_REMOVE] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_OBSERVER] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_DEL_OBSERVER] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_EXAMINER] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_DEL_EXAMINER] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_CHIEF_EXAMINER] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_DEL_CHIEF_EXAMINER] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_COORDINATOR] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_DEL_COORDINATOR] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_BY_USER_ID] = priv_add_priv_user_by_user_id,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_BY_LOGIN] = priv_add_priv_user_by_login,
  [NEW_SRV_ACTION_START_CONTEST] = priv_contest_operation,
  [NEW_SRV_ACTION_STOP_CONTEST] = priv_contest_operation,
  [NEW_SRV_ACTION_CONTINUE_CONTEST] = priv_contest_operation,
  [NEW_SRV_ACTION_SCHEDULE] = priv_contest_operation,
  [NEW_SRV_ACTION_CHANGE_DURATION] = priv_contest_operation,
  [NEW_SRV_ACTION_SUSPEND] = priv_contest_operation,
  [NEW_SRV_ACTION_RESUME] = priv_contest_operation,
  [NEW_SRV_ACTION_TEST_SUSPEND] = priv_contest_operation,
  [NEW_SRV_ACTION_TEST_RESUME] = priv_contest_operation,
  [NEW_SRV_ACTION_PRINT_SUSPEND] = priv_contest_operation,
  [NEW_SRV_ACTION_PRINT_RESUME] = priv_contest_operation,
  [NEW_SRV_ACTION_SET_JUDGING_MODE] = priv_contest_operation,
  [NEW_SRV_ACTION_SET_ACCEPTING_MODE] = priv_contest_operation,
  [NEW_SRV_ACTION_SET_TESTING_FINISHED_FLAG] = priv_contest_operation,
  [NEW_SRV_ACTION_CLEAR_TESTING_FINISHED_FLAG] = priv_contest_operation,
  [NEW_SRV_ACTION_SQUEEZE_RUNS] = priv_contest_operation,
  [NEW_SRV_ACTION_RESET_FILTER] = priv_reset_filter,
  [NEW_SRV_ACTION_RESET_CLAR_FILTER] = priv_reset_filter,
  [NEW_SRV_ACTION_CHANGE_LANGUAGE] = priv_change_language,
  [NEW_SRV_ACTION_SUBMIT_RUN] = priv_submit_run,
  [NEW_SRV_ACTION_PRIV_SUBMIT_CLAR] = priv_submit_clar,
  [NEW_SRV_ACTION_CLAR_REPLY] = priv_clar_reply,
  [NEW_SRV_ACTION_CLAR_REPLY_ALL] = priv_clar_reply,
  [NEW_SRV_ACTION_CLAR_REPLY_READ_PROBLEM] = priv_clar_reply,
  [NEW_SRV_ACTION_CLAR_REPLY_NO_COMMENTS] = priv_clar_reply,
  [NEW_SRV_ACTION_CLAR_REPLY_YES] = priv_clar_reply,
  [NEW_SRV_ACTION_CLAR_REPLY_NO] = priv_clar_reply,
  [NEW_SRV_ACTION_RELOAD_SERVER] = priv_contest_operation,
  [NEW_SRV_ACTION_CHANGE_STATUS] = priv_change_status,
  [NEW_SRV_ACTION_CHANGE_RUN_STATUS] = priv_change_status,
  [NEW_SRV_ACTION_REJUDGE_DISPLAYED_2] = priv_rejudge_displayed,
  [NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_2] = priv_rejudge_displayed,
  [NEW_SRV_ACTION_REJUDGE_PROBLEM_2] = priv_rejudge_problem,
  [NEW_SRV_ACTION_REJUDGE_SUSPENDED_2] = priv_rejudge_all,
  [NEW_SRV_ACTION_REJUDGE_ALL_2] = priv_rejudge_all,
  [NEW_SRV_ACTION_UPDATE_STANDINGS_2] = priv_contest_operation,
  [NEW_SRV_ACTION_RESET_2] = priv_contest_operation,
  [NEW_SRV_ACTION_GENERATE_PASSWORDS_2] = priv_password_operation,
  [NEW_SRV_ACTION_GENERATE_REG_PASSWORDS_2] = priv_password_operation,
  [NEW_SRV_ACTION_CLEAR_PASSWORDS_2] = priv_password_operation,
  [NEW_SRV_ACTION_USER_CHANGE_STATUS] = priv_user_operation,
  [NEW_SRV_ACTION_NEW_RUN] = priv_new_run,
  [NEW_SRV_ACTION_CHANGE_RUN_USER_ID] = priv_edit_run,
  [NEW_SRV_ACTION_CHANGE_RUN_USER_LOGIN] = priv_edit_run,
  [NEW_SRV_ACTION_CHANGE_RUN_PROB_ID] = priv_edit_run,
  [NEW_SRV_ACTION_CHANGE_RUN_VARIANT] = priv_edit_run,
  [NEW_SRV_ACTION_CHANGE_RUN_LANG_ID] = priv_edit_run,
  [NEW_SRV_ACTION_CHANGE_RUN_IS_IMPORTED] = priv_edit_run,
  [NEW_SRV_ACTION_CHANGE_RUN_IS_HIDDEN] = priv_edit_run,
  [NEW_SRV_ACTION_CHANGE_RUN_IS_EXAMINABLE] = priv_edit_run,
  [NEW_SRV_ACTION_CHANGE_RUN_IS_READONLY] = priv_edit_run,
  [NEW_SRV_ACTION_CHANGE_RUN_TEST] = priv_edit_run,
  [NEW_SRV_ACTION_CHANGE_RUN_SCORE] = priv_edit_run,
  [NEW_SRV_ACTION_CHANGE_RUN_SCORE_ADJ] = priv_edit_run,
  [NEW_SRV_ACTION_CHANGE_RUN_PAGES] = priv_edit_run,
  [NEW_SRV_ACTION_CLEAR_RUN] = priv_clear_run,
  [NEW_SRV_ACTION_PRINT_RUN] = priv_print_run_cmd,
  [NEW_SRV_ACTION_ISSUE_WARNING] = priv_user_issue_warning,
  [NEW_SRV_ACTION_SET_DISQUALIFICATION] = priv_user_disqualify,
  [NEW_SRV_ACTION_CLEAR_DISPLAYED_2] = priv_clear_displayed,
  [NEW_SRV_ACTION_IGNORE_DISPLAYED_2] = priv_clear_displayed,
  [NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_2] = priv_clear_displayed,
  [NEW_SRV_ACTION_UPSOLVING_CONFIG_2] = priv_upsolving_operation,
  [NEW_SRV_ACTION_UPSOLVING_CONFIG_3] = priv_upsolving_operation,
  [NEW_SRV_ACTION_UPSOLVING_CONFIG_4] = priv_upsolving_operation,
  [NEW_SRV_ACTION_ASSIGN_CHIEF_EXAMINER] = priv_assign_chief_examiner,
  [NEW_SRV_ACTION_ASSIGN_EXAMINER] = priv_assign_examiner,
  [NEW_SRV_ACTION_UNASSIGN_EXAMINER] = priv_unassign_examiner,
  [NEW_SRV_ACTION_TOGGLE_VISIBILITY] = priv_user_toggle_flags,
  [NEW_SRV_ACTION_TOGGLE_BAN] = priv_user_toggle_flags,
  [NEW_SRV_ACTION_TOGGLE_LOCK] = priv_user_toggle_flags,
  [NEW_SRV_ACTION_TOGGLE_INCOMPLETENESS] = priv_user_toggle_flags,
  [NEW_SRV_ACTION_FORCE_START_VIRTUAL] = priv_force_start_virtual,
  [NEW_SRV_ACTION_ASSIGN_CYPHERS_2] = priv_assign_cyphers_2,

  /* for priv_generic_page */
  [NEW_SRV_ACTION_VIEW_REPORT] = priv_view_report,
  [NEW_SRV_ACTION_VIEW_SOURCE] = priv_view_source,
  [NEW_SRV_ACTION_PRIV_DOWNLOAD_RUN] = priv_download_source,
  [NEW_SRV_ACTION_STANDINGS] = priv_standings,
  [NEW_SRV_ACTION_VIEW_CLAR] = priv_view_clar,
  [NEW_SRV_ACTION_REJUDGE_DISPLAYED_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_REJUDGE_PROBLEM_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_REJUDGE_SUSPENDED_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_REJUDGE_ALL_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_COMPARE_RUNS] = priv_diff_page,
  [NEW_SRV_ACTION_VIEW_TEST_INPUT] = priv_view_test,
  [NEW_SRV_ACTION_VIEW_TEST_ANSWER] = priv_view_test,
  [NEW_SRV_ACTION_VIEW_TEST_INFO] = priv_view_test,
  [NEW_SRV_ACTION_VIEW_TEST_OUTPUT] = priv_view_test,
  [NEW_SRV_ACTION_VIEW_TEST_ERROR] = priv_view_test,
  [NEW_SRV_ACTION_VIEW_TEST_CHECKER] = priv_view_test,
  [NEW_SRV_ACTION_VIEW_AUDIT_LOG] = priv_view_audit_log,
  [NEW_SRV_ACTION_UPDATE_STANDINGS_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_RESET_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_GENERATE_PASSWORDS_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_GENERATE_REG_PASSWORDS_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_CLEAR_PASSWORDS_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_VIEW_CNTS_PWDS] = priv_view_passwords,
  [NEW_SRV_ACTION_VIEW_REG_PWDS] = priv_view_passwords,
  [NEW_SRV_ACTION_VIEW_USER_INFO] = priv_user_detail_page,
  [NEW_SRV_ACTION_NEW_RUN_FORM] = priv_new_run_form_page,
  [NEW_SRV_ACTION_VIEW_USER_DUMP] = priv_view_user_dump,
  [NEW_SRV_ACTION_VIEW_USER_REPORT] = priv_view_report,
  [NEW_SRV_ACTION_DOWNLOAD_ARCHIVE_1] = priv_download_runs_confirmation,
  [NEW_SRV_ACTION_DOWNLOAD_ARCHIVE_2] = priv_download_runs,
  [NEW_SRV_ACTION_UPLOAD_RUNLOG_CSV_1] = priv_upload_runlog_csv_1,
  [NEW_SRV_ACTION_UPLOAD_RUNLOG_CSV_2] = priv_upload_runlog_csv_2,
  [NEW_SRV_ACTION_VIEW_RUNS_DUMP] = priv_view_runs_dump,
  [NEW_SRV_ACTION_EXPORT_XML_RUNS] = priv_view_runs_dump,
  [NEW_SRV_ACTION_WRITE_XML_RUNS] = priv_view_runs_dump,
  [NEW_SRV_ACTION_WRITE_XML_RUNS_WITH_SRC] = priv_view_runs_dump,
  [NEW_SRV_ACTION_UPLOAD_RUNLOG_XML_1] = priv_upload_runlog_xml_1,
  [NEW_SRV_ACTION_UPLOAD_RUNLOG_XML_2] = priv_upload_runlog_xml_2,
  [NEW_SRV_ACTION_CLEAR_DISPLAYED_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_IGNORE_DISPLAYED_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_UPSOLVING_CONFIG_1] = priv_upsolving_configuration_1,
  [NEW_SRV_ACTION_EXAMINERS_PAGE] = priv_examiners_page,
  [NEW_SRV_ACTION_VIEW_ONLINE_USERS] = priv_view_online_users,
  [NEW_SRV_ACTION_PRINT_USER_PROTOCOL] = priv_print_user_exam_protocol,
  [NEW_SRV_ACTION_PRINT_USER_FULL_PROTOCOL] = priv_print_user_exam_protocol,
  [NEW_SRV_ACTION_PRINT_UFC_PROTOCOL] = priv_print_user_exam_protocol,
  [NEW_SRV_ACTION_PRINT_SELECTED_USER_PROTOCOL] =priv_print_users_exam_protocol,
  [NEW_SRV_ACTION_PRINT_SELECTED_USER_FULL_PROTOCOL] =priv_print_users_exam_protocol,
  [NEW_SRV_ACTION_PRINT_SELECTED_UFC_PROTOCOL] =priv_print_users_exam_protocol,
  [NEW_SRV_ACTION_PRINT_PROBLEM_PROTOCOL] = priv_print_problem_exam_protocol,
  [NEW_SRV_ACTION_ASSIGN_CYPHERS_1] = priv_assign_cyphers_1,
  [NEW_SRV_ACTION_VIEW_EXAM_INFO] = priv_view_exam_info,
};

static void
priv_generic_operation(FILE *fout,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra)
{
  FILE *log_f = 0;
  char *log_txt = 0;
  size_t log_len = 0;
  int r, rr;

  log_f = open_memstream(&log_txt, &log_len);

  r = priv_actions_table_2[phr->action](fout, log_f, phr, cnts, extra);
  if (r == -1) {
    fclose(log_f);
    xfree(log_txt);
    return;
  }
  if (r < 0) {
    ns_error(log_f, r);
    r = 0;
  }
  rr = r;
  if (!r) r = ns_priv_next_state[phr->action];
  if (!rr) rr = ns_priv_prev_state[phr->action];

  fclose(log_f);
  if (!log_txt || !*log_txt) {
    /*
    if (r == NEW_SRV_ACTION_VIEW_SOURCE) {
      if (phr->next_run_id < 0) r = 0;
      else snprintf(next_extra, sizeof(next_extra), "run_id=%d",
                    phr->next_run_id);
    }
    */
    ns_refresh_page(fout, phr, r, phr->next_extra);
  } else {
    html_error_status_page(fout, phr, cnts, extra, log_txt, rr, 0);
  }
  xfree(log_txt);
}

static void
priv_generic_page(FILE *fout,
                  struct http_request_info *phr,
                  const struct contest_desc *cnts,
                  struct contest_extra *extra)
{
  FILE *log_f = 0;
  char *log_txt = 0;
  size_t log_len = 0;
  int r;

  log_f = open_memstream(&log_txt, &log_len);

  r = priv_actions_table_2[phr->action](fout, log_f, phr, cnts, extra);
  if (r == -1) {
    fclose(log_f);
    xfree(log_txt);
    return;
  }
  if (r < 0) {
    ns_error(log_f, r);
    r = 0;
  }
  if (!r) r = ns_priv_prev_state[phr->action];

  fclose(log_f);
  if (log_txt && *log_txt) {
    html_error_status_page(fout, phr, cnts, extra, log_txt, r, 0);
  }
  xfree(log_txt);
}

static void
priv_logout(FILE *fout,
            struct http_request_info *phr,
            const struct contest_desc *cnts,
            struct contest_extra *extra)
{
  //unsigned char locale_buf[64];
  unsigned char urlbuf[1024];

  if (ns_open_ul_connection(phr->fw_state) < 0)
    return ns_html_err_ul_server_down(fout, phr, 0, 0);
  userlist_clnt_delete_cookie(ul_conn, phr->user_id, phr->contest_id,
                              phr->session_id);
  ns_remove_session(phr->session_id);
  snprintf(urlbuf, sizeof(urlbuf),
           "%s?contest_id=%d&locale_id=%d&role=%d",
           phr->self_url, phr->contest_id, phr->locale_id, phr->role);
  ns_refresh_page_2(fout, urlbuf);
}


static void
write_alternatives_file(FILE *fout, int is_radio, const unsigned char *txt,
                        int last_answer, int prob_id, int next_prob_id,
                        int enable_js, const unsigned char *class_name)
{
  const unsigned char *s, *p;
  unsigned char *txt2;
  size_t txt_len, t_len;
  int line_max_count = 0, line_count = 0, i;
  unsigned char **lines = 0;
  unsigned char *t;
  unsigned char *cl = "";
  unsigned char jsbuf[1024];

  if (!txt) return;

  if (class_name && *class_name) {
    cl = (unsigned char *) alloca(strlen(class_name) + 32);
    sprintf(cl, " class=\"%s\"", class_name);
  }

  // normalize the file
  txt_len = strlen(txt);
  txt2 = (unsigned char*) alloca(txt_len + 2);
  memcpy(txt2, txt, txt_len + 1);
  while (txt_len > 0 && isspace(txt2[txt_len - 1])) txt_len--;
  if (!txt_len) return;
  txt2[txt_len++] = '\n';
  txt2[txt_len] = 0;

  // count number of lines
  for (s = txt2; *s; s++)
    if (*s == '\n') line_max_count++;

  lines = (unsigned char**) alloca((line_max_count + 1) * sizeof(lines[0]));
  memset(lines, 0, (line_max_count + 1) * sizeof(lines[0]));

  s = txt2;
  while (*s) {
    while (*s != '\n' && isspace(*s)) s++;
    if (*s == '#') while (*s != '\n') s++;
    if (*s == '\n') {
      s++;
      continue;
    }
    p = s;
    while (*s != '\n') s++;
    t_len = s - p;
    t = (unsigned char*) alloca(t_len + 1);
    memcpy(t, p, t_len);
    while (t_len > 0 && isspace(t[t_len - 1])) t_len--;
    t[t_len] = 0;
    lines[line_count++] = t;
  }

  for (i = 0; i < line_count; i++) {
    if (is_radio) {
      jsbuf[0] = 0;
      if (prob_id > 0 && enable_js) {
        snprintf(jsbuf, sizeof(jsbuf), " onclick=\"submitAnswer(%d,%d,%d)\"",
                 prob_id, i + 1, next_prob_id);
      }
      s = "";
      if (last_answer == i + 1) s = " checked=\"1\"";
      fprintf(fout, "<tr><td%s>%d</td><td%s><input type=\"radio\" name=\"file\" value=\"%d\"%s%s/></td><td%s>%s</td></tr>\n", cl, i + 1, cl, i + 1, s, jsbuf, cl, lines[i]);
    } else {
      fprintf(fout, "<tr><td%s>%d</td><td%s><input type=\"checkbox\" name=\"ans_%d\"/></td><td%s>%s</td></tr>\n", cl, i + 1, cl, i + 1, cl, lines[i]);
    }
  }
}

static void
priv_main_page(FILE *fout,
               struct http_request_info *phr,
               const struct contest_desc *cnts,
               struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  time_t start_time, sched_time, duration, stop_time, fog_start_time = 0, tmpt;
  time_t finish_time;
  unsigned char hbuf[1024];
  unsigned char duration_buf[128];
  const unsigned char *s;
  unsigned char bb[1024];
  int action;
  long long tdiff;
  int filter_first_run = 0, filter_last_run = 0, filter_first_clar = 0;
  int filter_last_clar = 0, filter_mode_clar = 0;
  const unsigned char *filter_expr = 0;
  int i, x, y, n, variant = 0, need_examiners = 0, online_users = 0;
  const struct section_problem_data *prob = 0;
  path_t variant_stmt_file;
  struct watched_file *pw = 0;
  const unsigned char *pw_path;
  const unsigned char *alternatives;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int skip_start_form = 0;
  struct last_access_info *pa;

  if (ns_cgi_param(phr, "filter_expr", &s) > 0) filter_expr = s;
  if (ns_cgi_param(phr, "filter_first_run", &s) > 0
      && sscanf(s, "%d%n", &x, &n) == 1 && !s[n]) {
    filter_first_run = x;
    if (filter_first_run >= 0) filter_first_run++;
  }
  if (ns_cgi_param(phr, "filter_last_run", &s) > 0
      && sscanf(s, "%d%n", &x, &n) == 1 && !s[n]) {
    filter_last_run = x;
    if (filter_last_run >= 0) filter_last_run++;
  }
  if (ns_cgi_param(phr, "filter_first_clar", &s) > 0
      && sscanf(s, "%d%n", &x, &n) == 1 && !s[n]) {
    filter_first_clar = x;
    if (filter_first_clar >= 0) filter_first_clar++;
  }
  if (ns_cgi_param(phr, "filter_last_clar", &s) > 0
      && sscanf(s, "%d%n", &x, &n) == 1 && !s[n]) {
    filter_last_clar = x;
    if (filter_last_clar >= 0) filter_last_clar--;
  }
  if (ns_cgi_param(phr, "filter_mode_clar", &s) > 0
      && sscanf(s, "%d%n", &x, &n) == 1 && !s[n] && x >= 1 && x <= 2)
    filter_mode_clar = x;
  if (ns_cgi_param(phr, "problem", &s) > 0) {
    if (sscanf(s, "%d_%d%n", &x, &y, &n) == 2 && !s[n]
        && x > 0 && x <= cs->max_prob && cs->probs[x]
        && cs->probs[x]->variant_num > 0 && y > 0
        && y <= cs->probs[x]->variant_num) {
      prob = cs->probs[x];
      variant = y;
    } else if (sscanf(s, "%d%n", &x, &n) == 1 && !s[n]
               && x > 0 && x <= cs->max_prob && cs->probs[x]
               && cs->probs[x]->variant_num <= 0) {
      prob = cs->probs[x];
    }
  }

  run_get_times(cs->runlog_state, &start_time, &sched_time, &duration,
                &stop_time, &finish_time);
  if (duration > 0 && start_time && !stop_time && global->board_fog_time > 0)
    fog_start_time = start_time + duration - global->board_fog_time;
  if (fog_start_time < 0) fog_start_time = 0;

  for (i = 1; i <= cs->max_prob; i++)
    if (cs->probs[i] && cs->probs[i]->manual_checking)
      need_examiners = 1;

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role),
            phr->name_arm, phr->contest_id, extra->contest_arm, _("Main page"));
  fprintf(fout, "<ul>\n");
  fprintf(fout, "<li>%s%s</a></li>\n",
          ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_VIEW_USERS, 0),
          _("View regular users"));
  fprintf(fout, "<li>%s%s</a></li>\n",
          ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_PRIV_USERS_VIEW, 0),
          _("View privileged users"));
  fprintf(fout, "<li>%s%s</a></li>\n",
          ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_VIEW_ONLINE_USERS, 0),
          _("View who is currently online"));
  fprintf(fout, "<li>%s%s</a></li>\n",
          ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_VIEW_EXAM_INFO, 0),
          _("View examination information"));
  if (need_examiners)
    fprintf(fout, "<li>%s%s</a></li>\n",
            ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_EXAMINERS_PAGE, 0),
            _("Examiners assignments"));
  fprintf(fout, "<li>%s%s</a></li>\n",
          ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_STANDINGS, 0),
          _("View standings"));
  fprintf(fout, "<li>%s%s</a></li>\n",
          ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_VIEW_REG_PWDS, 0),
          _("View registration passwords"));
  if (!cnts->disable_team_password) {
    fprintf(fout, "<li>%s%s</a></li>\n",
            ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_VIEW_CNTS_PWDS, 0),
            _("View contest passwords"));
  }
  if (phr->role >= USER_ROLE_JUDGE
      && opcaps_check(phr->caps, OPCAP_DUMP_USERS) >= 0) {
    fprintf(fout, "<li>%s%s</a></li>\n",
            ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_VIEW_USER_DUMP, 0),
            _("Dump users in CSV format"));
  }
  if (phr->role >= USER_ROLE_JUDGE
      && opcaps_check(phr->caps, OPCAP_DUMP_RUNS) >= 0) {
    fprintf(fout, "<li>%s%s</a></li>\n",
            ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_VIEW_RUNS_DUMP, 0),
            _("Dump runs in CSV format"));
    fprintf(fout, "<li>%s%s</a></li>\n",
            ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_EXPORT_XML_RUNS, 0),
            _("Export runs in XML external format"));
    fprintf(fout, "<li>%s%s</a></li>\n",
            ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_WRITE_XML_RUNS, 0),
            _("Write runs in XML internal format"));
    fprintf(fout, "<li>%s%s</a></li>\n",
            ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_WRITE_XML_RUNS_WITH_SRC, 0),
            _("Write runs in XML internal format with source"));
  }
  fprintf(fout, "<li>%s%s</a></li>\n",
          ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_ASSIGN_CYPHERS_1, 0),
          _("Assign random cyphers"));
  if (cnts->problems_url) {
    fprintf(fout, "<li><a href=\"%s\" target=_blank>%s</a>\n",
            cnts->problems_url, _("Problems"));
  }
  fprintf(fout, "<li>%s%s</a></li>\n",
          ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_LOGOUT, 0),
          _("Logout"));

  fprintf(fout, "</ul>\n");

  /* if role == ADMIN and capability CONTROL_CONTEST */

  fprintf(fout, "<hr><a name=\"status\"></a><%s>%s</%s>\n",
          /*cnts->priv_head_style*/ "h2", _("Server status"),
          /*cnts->priv_head_style*/ "h2");
  if (stop_time > 0 && !global->is_virtual) {
    if (duration > 0 && global->board_fog_time > 0
        && global->board_unfog_time > 0
        && cs->current_time < stop_time + global->board_unfog_time
        && !cs->standings_updated) {
      s = _("The contest is over (standings are frozen)");
    } else {
      s = _("The contest is over");
    }
  } else if (start_time > 0) {
    if (fog_start_time > 0 && cs->current_time >= fog_start_time)
      s = _("The contest is in progress (standings are frozen)");
    else
      s = _("The contest is in progress");
  } else {
    s = _("The contest is not started");
  }
  fprintf(fout, "<p><big><b>%s</b></big></p>\n", s);

  if (global->score_system_val == SCORE_OLYMPIAD && !global->is_virtual) {
    if (cs->accepting_mode)
      s = _("Participants' solutions are being accepted");
    else if (!cs->testing_finished)
      s = _("Participants' solutions are being judged");
    else
      s = _("Participants' solutions are judged");
    fprintf(fout, "<p><big><b>%s</b></big></p>\n", s);
  }

  if (cs->upsolving_mode) {
    fprintf(fout, "<p><big><b>%s</b></big></p>\n", _("Upsolving mode"));
  }

  if (cs->clients_suspended) {
    fprintf(fout, "<p><big><b>%s</b></big></p>\n",
            _("Participants' requests are suspended"));
  }

  if (cs->testing_suspended) {
    fprintf(fout, "<p><big><b>%s</b></big></p>\n",
            _("Testing of participants' submits is suspended"));
  }
  if (cs->printing_suspended) {
    fprintf(fout, "<p><big><b>%s</b></big></p>\n",
            _("Print requests are suspended"));
  }

  // count online users
  online_users = 0;
  for (i = 0; i < extra->user_access[USER_ROLE_CONTESTANT].u; i++) {
    pa = &extra->user_access[USER_ROLE_CONTESTANT].v[i];
    if (pa->time + 65 >= cs->current_time) online_users++;
  }
  fprintf(fout, "<p><big><b>%s: %d</b></big></p>\n",
          _("On-line users in this contest"), online_users);
  if (cs->max_online_count > 0) {
    fprintf(fout, "<p><big><b>%s: %d, %s</b></big></p>\n",
            _("Max number of users was"), cs->max_online_count,
            xml_unparse_date(cs->max_online_time));
  }

  if (phr->role == USER_ROLE_ADMIN
      && opcaps_check(phr->caps, OPCAP_CONTROL_CONTEST) >= 0) {
    html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
    fprintf(fout, "<table border=\"0\">");

    fprintf(fout,
            "<tr><td>%s:</td><td>%s</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n",
            _("Server time"), ctime(&cs->current_time));

    if (start_time <= 0) {
      fprintf(fout, "<tr><td colspan=\"2\"><b>%s</b></td><td>&nbsp;</td><td>%s</td></tr>\n",
              _("Contest is not started"),
              BUTTON(NEW_SRV_ACTION_START_CONTEST));
    } else {
      fprintf(fout, "<tr><td>%s:</td><td>%s</td><td>&nbsp;</td>",
              _("Contest start time"), ctime(&start_time));
      if (stop_time <= 0) {
        fprintf(fout, "<td>%s</td></tr>\n",
                BUTTON(NEW_SRV_ACTION_STOP_CONTEST));
      } else if (global->enable_continue
                 && (!duration || stop_time < start_time + duration)) {
        fprintf(fout, "<td>%s</td></tr>\n",
                BUTTON(NEW_SRV_ACTION_CONTINUE_CONTEST));
      }
    }

    if (!global->is_virtual && start_time <= 0) {
      fprintf(fout, "<tr><td>%s:</td><td>%s</td>"
              "<td><input type=\"text\" name=\"sched_time\" size=\"16\"/></td>"
              "<td>%s</td></tr>\n",
              _("Planned start time"),
              sched_time <= 0?_("Not set"):ctime(&sched_time),
              BUTTON(NEW_SRV_ACTION_SCHEDULE));
    }

    if (finish_time <= 0) {
      if (duration > 0) {
        duration_str(0, duration, 0, duration_buf, 0);
      } else {
        snprintf(duration_buf, sizeof(duration_buf), "%s", _("Unlimited"));
      }

      fprintf(fout, "<tr><td>%s:</td><td>%s</td>",_("Duration"), duration_buf);
      if ((stop_time <= 0 || global->enable_continue) && !global->is_virtual) {
        fprintf(fout, "<td><input type=\"text\" name=\"dur\" size=\"16\"/></td>"
                "<td>%s</td></tr>\n",
                BUTTON(NEW_SRV_ACTION_CHANGE_DURATION));
      } else {
        fprintf(fout, "<td>&nbsp;</td><td>&nbsp;</td></tr>\n");
      }
    }

    if (!global->is_virtual) {
      if (start_time > 0 && stop_time <= 0 && duration > 0) {
        tmpt = start_time + duration;
        fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("Scheduled end time"), ctime(&tmpt));
      } else if (start_time > 0 && stop_time <= 0 && duration <= 0
                 && finish_time > 0) {
        fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("Scheduled end time"), ctime(&finish_time));
      } else if (stop_time) {
        fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("End time"), ctime(&stop_time));
      }

      if (start_time > 0 && stop_time <= 0 && fog_start_time > 0) {
        fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("Standings freeze time"), ctime(&fog_start_time));
      } else if (stop_time > 0 && duration > 0 && global->board_fog_time > 0
                 && global->board_unfog_time > 0 && !cs->standings_updated
                 && cs->current_time < stop_time + global->board_unfog_time) {
        tmpt = stop_time + global->board_unfog_time;
        fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("Standings unfreeze time"), ctime(&tmpt));
      }

      if (start_time > 0 && stop_time <= 0 && duration > 0) {
        duration_str(0, cs->current_time, start_time, duration_buf, 0);
        fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("Elapsed time"), duration_buf);
        duration_str(0, start_time + duration - cs->current_time, 0,
                     duration_buf, 0);
        fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("Remaining time"), duration_buf);
      }
    }
    fprintf(fout, "</table></form>\n");

    fprintf(fout, "<hr>\n");

    html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
    fprintf(fout, "%s\n",  BUTTON(NEW_SRV_ACTION_UPDATE_STANDINGS_1));
    fprintf(fout, "%s\n", BUTTON(NEW_SRV_ACTION_RESET_1));
    action = NEW_SRV_ACTION_SUSPEND;
    if (cs->clients_suspended) action = NEW_SRV_ACTION_RESUME;
    fprintf(fout, "%s\n", BUTTON(action));
    action = NEW_SRV_ACTION_TEST_SUSPEND;
    if (cs->testing_suspended) action = NEW_SRV_ACTION_TEST_RESUME;
    fprintf(fout, "%s\n", BUTTON(action));
    if (global->enable_printing) {
      action = NEW_SRV_ACTION_PRINT_SUSPEND;
      if (cs->printing_suspended) action = NEW_SRV_ACTION_PRINT_RESUME;
      fprintf(fout, "%s\n", BUTTON(action));
    }
    if (global->score_system_val == SCORE_OLYMPIAD && !global->is_virtual) {
      action = NEW_SRV_ACTION_SET_JUDGING_MODE;
      if (!cs->accepting_mode) action = NEW_SRV_ACTION_SET_ACCEPTING_MODE;
      fprintf(fout, "%s\n", BUTTON(action));
    }
    if (global->score_system_val == SCORE_OLYMPIAD
        && ((!global->is_virtual && !cs->accepting_mode)
            || (global->is_virtual && global->disable_virtual_auto_judge >0))) {
      action = NEW_SRV_ACTION_SET_TESTING_FINISHED_FLAG;
      if (cs->testing_finished)
        action = NEW_SRV_ACTION_CLEAR_TESTING_FINISHED_FLAG;
      fprintf(fout, "%s\n", BUTTON(action));
    }
    if (!cnts->disable_team_password) {
      fprintf(fout, "%s\n", BUTTON(NEW_SRV_ACTION_GENERATE_PASSWORDS_1));
      fprintf(fout, "%s\n", BUTTON(NEW_SRV_ACTION_CLEAR_PASSWORDS_1));
    }
    fprintf(fout, "%s\n", BUTTON(NEW_SRV_ACTION_GENERATE_REG_PASSWORDS_1));
    fprintf(fout, "%s\n", BUTTON(NEW_SRV_ACTION_UPSOLVING_CONFIG_1));
    fprintf(fout, "%s\n", BUTTON(NEW_SRV_ACTION_RELOAD_SERVER));
    fprintf(fout, "</form>\n");
  } else {
    // judge mode
    fprintf(fout, "<table border=\"0\">");

    fprintf(fout,
            "<tr><td>%s:</td><td>%s</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n",
            _("Server time"), ctime(&cs->current_time));

    if (start_time <= 0) {
      fprintf(fout, "<tr><td colspan=\"2\"><b>%s</b></td></tr>\n",
              _("Contest is not started"));
    } else {
      fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
              _("Contest start time"), ctime(&start_time));
    }

    if (!global->is_virtual && start_time <= 0) {
      fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
              _("Planned start time"),
              sched_time <= 0?_("Not set"):ctime(&sched_time));
    }

    if (finish_time <= 0) {
      if (duration > 0) {
        duration_str(0, duration, 0, duration_buf, 0);
      } else {
        snprintf(duration_buf, sizeof(duration_buf), "%s", _("Unlimited"));
      }

      fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
              _("Duration"), duration_buf);
    }

    if (!global->is_virtual) {
      if (start_time > 0 && stop_time <= 0 && duration > 0) {
        tmpt = start_time + duration;
        fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("Scheduled end time"), ctime(&tmpt));
      } else if (start_time > 0 && stop_time <= 0 && duration <= 0
                 && finish_time > 0) {
        fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("Scheduled end time"), ctime(&finish_time));
      } else if (stop_time) {
        fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("End time"), ctime(&stop_time));
      }

      if (start_time > 0 && stop_time <= 0 && fog_start_time > 0) {
        fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("Standings freeze time"), ctime(&fog_start_time));
      } else if (stop_time > 0 && duration > 0 && global->board_fog_time > 0
                 && global->board_unfog_time > 0 && !cs->standings_updated
                 && cs->current_time < stop_time + global->board_unfog_time) {
        tmpt = stop_time + global->board_unfog_time;
        fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("Standings unfreeze time"), ctime(&tmpt));
      }

      if (start_time > 0 && stop_time <= 0 && duration > 0) {
        duration_str(0, cs->current_time, start_time, duration_buf, 0);
        fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("Elapsed time"), duration_buf);
        duration_str(0, start_time + duration - cs->current_time, 0,
                     duration_buf, 0);
        fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("Remaining time"), duration_buf);
      }
    }
    fprintf(fout, "</table>\n");
  }

  ns_write_priv_all_runs(fout, phr, cnts, extra,
                         filter_first_run, filter_last_run,
                         filter_expr);

  if (opcaps_check(phr->caps, OPCAP_SUBMIT_RUN) >= 0) {
    if (!prob) {
      // no problem is selected yet
      fprintf(fout, "<hr><a name=\"submit\"></a><%s>%s</%s>\n",
              /*cnts->priv_head_style*/ "h2",
              _("View the problem statement and send a submission"),
              /*cnts->priv_head_style*/ "h2");
      html_start_form(fout, 0, phr->self_url, phr->hidden_vars);
      fprintf(fout, "<table>\n");
      fprintf(fout, "<tr><td>%s:</td><td><select name=\"problem\">",
              _("Problem"));
      for (x = 1; x <= cs->max_prob; x++) {
        if (!(prob = cs->probs[x])) continue;
        if (prob->variant_num <= 0) {
          fprintf(fout, "<option value=\"%d\">%s - %s</option>",
                  x, prob->short_name, ARMOR(prob->long_name));
        } else {
          for (y = 1; y <= prob->variant_num; y++) {
            fprintf(fout, "<option value=\"%d_%d\">%s - %s, %s %d</option>",
                    x, y, prob->short_name,  ARMOR(prob->long_name),
                    _("Variant"), y);
          }
        }
      }
      fprintf(fout, "</select></td><td>%s</td></tr></table></form>\n",
              ns_submit_button(bb, sizeof(bb), 0, NEW_SRV_ACTION_MAIN_PAGE,
                               _("Select problem")));
      prob = 0;
    } else {
      // a problem is already selected
      // prob and variant have correct values
      if (variant > 0) {
        fprintf(fout, "<hr><a name=\"submit\"></a><%s>%s %s-%s (%s %d)</%s>\n",
                /*cnts->team_head_style*/ "h2", _("Submit a solution for"),
                prob->short_name, ARMOR(prob->long_name), _("Variant"), variant,
                /*cnts->team_head_style*/ "h2");
      } else {
        fprintf(fout, "<hr><a name=\"submit\"></a><%s>%s %s-%s</%s>\n",
                /*cnts->team_head_style*/ "h2", _("Submit a solution for"),
                prob->short_name,  ARMOR(prob->long_name),
                /*cnts->team_head_style*/ "h2");
      }

      /* FIXME: handle problem XML */

      /* put problem statement */
      if (prob->statement_file[0]) {
        if (variant > 0) {
          prepare_insert_variant_num(variant_stmt_file,
                                     sizeof(variant_stmt_file),
                                     prob->statement_file, variant);
          pw = &cs->prob_extras[prob->id].v_stmts[variant];
          pw_path = variant_stmt_file;
        } else {
          pw = &cs->prob_extras[prob->id].stmt;
          pw_path = prob->statement_file;
        }
        watched_file_update(pw, pw_path, cs->current_time);
        if (!pw->text) {
          fprintf(fout, "<big><font color=\"red\"><p>%s</p></font></big>\n",
                  _("The problem statement is not available"));
        } else {
          if (prob->type_val == PROB_TYPE_CUSTOM) {
            html_start_form(fout, 2, phr->self_url, phr->hidden_vars);
            skip_start_form = 1;
          }
          fprintf(fout, "%s", pw->text);
        }
      }
      alternatives = 0;
      if ((prob->type_val == PROB_TYPE_SELECT_ONE
           || prob->type_val == PROB_TYPE_SELECT_MANY)
          && prob->alternatives_file[0]) {
        if (variant > 0) {
          prepare_insert_variant_num(variant_stmt_file,
                                     sizeof(variant_stmt_file),
                                     prob->alternatives_file, variant);
          pw = &cs->prob_extras[prob->id].v_alts[variant];
          pw_path = variant_stmt_file;
        } else {
          pw = &cs->prob_extras[prob->id].alt;
          pw_path = prob->alternatives_file;
        }
        watched_file_update(pw, pw_path, cs->current_time);
        alternatives = pw->text;
      }

      if (!skip_start_form) {
        html_start_form(fout, 2, phr->self_url, phr->hidden_vars);
      }
      if (variant <= 0) {
        html_hidden(fout, "problem", "%d", prob->id);
      } else {
        html_hidden(fout, "problem", "%d_%d", prob->id, variant);
      }
      fprintf(fout, "<table>\n");
      if (!prob->type_val) {
        fprintf(fout, "<tr><td>%s:</td><td>", _("Language"));
        fprintf(fout, "<select name=\"lang_id\"><option value=\"\">\n");
        for (i = 1; i <= cs->max_lang; i++) {
          if (!cs->langs[i]) continue;
          fprintf(fout, "<option value=\"%d\">%s - %s</option>\n",
                  i, cs->langs[i]->short_name, ARMOR(cs->langs[i]->long_name));
        }
        fprintf(fout, "</select></td></tr>\n");
      }

      switch (prob->type_val) {
      case PROB_TYPE_STANDARD:
      case PROB_TYPE_OUTPUT_ONLY:
        fprintf(fout, "<tr><td>%s</td><td><input type=\"file\" name=\"file\"/></td></tr>\n", _("File"));
        break;
      case PROB_TYPE_SHORT_ANSWER:
        fprintf(fout, "<tr><td>%s</td><td><input type=\"text\" name=\"file\"/></td></tr>\n", _("Answer"));
        break;
      case PROB_TYPE_TEXT_ANSWER:
        fprintf(fout, "<tr><td colspan=\"2\"><textarea name=\"file\" rows=\"20\" cols=\"60\"></textarea></td></tr>\n");
        break;
      case PROB_TYPE_SELECT_ONE:
        /* FIXME: handle problem XML */
        if (alternatives) {
          write_alternatives_file(fout, 1, alternatives, -1, 0, 0, 0, "b0");
        } else if (prob->alternative) {
          for (i = 0; prob->alternative[i]; i++) {
            fprintf(fout, "<tr><td>%d</td><td><input type=\"radio\" name=\"file\" value=\"%d\"/></td><td>%s</td></tr>\n", i + 1, i + 1, prob->alternative[i]);
          }
        }
        break;
      case PROB_TYPE_SELECT_MANY:
        if (alternatives) {
          write_alternatives_file(fout, 0, alternatives, -1, 0, 0, 0, "b0");
        } else if (prob->alternative) {
          for (i = 0; prob->alternative[i]; i++) {
            fprintf(fout, "<tr><td>%d</td><td><input type=\"checkbox\" name=\"ans_%d\"/></td><td>%s</td></tr>\n", i + 1, i + 1, prob->alternative[i]);
          }
        }
        break;
      case PROB_TYPE_CUSTOM:    /* form is a part of problem statement */
        break;
      }
      fprintf(fout, "<tr><td>%s</td><td>%s</td></tr></table></form>\n",
              _("Send!"), BUTTON(NEW_SRV_ACTION_SUBMIT_RUN));
     
      fprintf(fout, "<hr><a name=\"submit\"></a><%s>%s</%s>\n",
              /*cnts->team_head_style*/ "h2", _("Select another problem"),
              /*cnts->team_head_style*/ "h2");

      html_start_form(fout, 0, phr->self_url, phr->hidden_vars);
      fprintf(fout, "<table>\n");
      fprintf(fout, "<tr><td>%s:</td><td><select name=\"problem\">",
              _("Problem"));
      for (x = 1; x <= cs->max_prob; x++) {
        if (!(prob = cs->probs[x])) continue;
        if (prob->variant_num <= 0) {
          fprintf(fout, "<option value=\"%d\">%s - %s</option>",
                  x, prob->short_name, ARMOR(prob->long_name));
        } else {
          for (y = 1; y <= prob->variant_num; y++) {
            fprintf(fout, "<option value=\"%d_%d\">%s - %s, %s %d</option>",
                    x, y, prob->short_name, ARMOR(prob->long_name),
                    _("Variant"), y);
          }
        }
      }
      fprintf(fout, "</select></td><td>%s</td></tr></table></form>\n",
              ns_submit_button(bb, sizeof(bb), 0, NEW_SRV_ACTION_MAIN_PAGE,
                               _("Select problem")));
      prob = 0;
    }
  }

  ns_write_all_clars(fout, phr, cnts, extra, filter_mode_clar,
                     filter_first_clar, filter_last_clar);

  fprintf(fout, "<hr><h2>%s</h2>", _("Compose a message to all participants"));
  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
  fprintf(fout, "<table>\n"
          "<tr>"
          "<td>%s:</td>"
          "<td><input type=\"text\" size=\"16\" name=\"msg_dest_id\"/></td>"
          "</tr>\n"
          "<tr>"
          "<td>%s:</td>"
          "<td><input type=\"text\" size=\"32\" name=\"msg_dest_login\"/></td>"
          "</tr>\n"
          "<tr>"
          "<td>%s:</td>"
          "<td><input type=\"text\" size=\"64\" name=\"msg_subj\"/></td>"
          "</tr>\n",
          _("To user id"),
          _("To user login"),
          _("Subject"));
  if (start_time <= 0) {
    fprintf(fout, "<tr><td>%s</td><td><select name=\"msg_hide_flag\"><option value=\"0\">NO</option><option value=\"1\">YES</option></select></td></tr>\n",
            _("Do not show before the contest starts?"));
  }
  fprintf(fout, "</table>\n"
          "<p><textarea name=\"msg_text\" rows=\"20\" cols=\"60\">"
          "</textarea></p>"
          "<p>%s\n</form>\n",
          BUTTON(NEW_SRV_ACTION_PRIV_SUBMIT_CLAR));

  /* change the password */
  fprintf(fout, "<hr><a name=\"chgpasswd\"></a>\n<%s>%s</%s>\n",
          /*cnts->priv_head_style*/ "h2",
          _("Change password"),
          /*cnts->team_head_style*/ "h2");
  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);

  fprintf(fout, "<table>\n"
          "<tr><td>%s:</td><td><input type=\"password\" name=\"oldpasswd\" size=\"16\"/></td></tr>\n"
          "<tr><td>%s:</td><td><input type=\"password\" name=\"newpasswd1\" size=\"16\"/></td></tr>\n"
          "<tr><td>%s:</td><td><input type=\"password\" name=\"newpasswd2\" size=\"16\"/></td></tr>\n"
          "<tr><td colspan=\"2\">%s</td></tr>\n"
          "</table></form>",
          _("Old password"),
          _("New password"), _("Retype new password"),
          BUTTON(NEW_SRV_ACTION_CHANGE_PASSWORD));

#if CONF_HAS_LIBINTL - 0 == 1
  if (cs->global->enable_l10n) {
    fprintf(fout, "<hr><a name=\"chglanguage\"></a><%s>%s</%s>\n",
            cnts->team_head_style, _("Change language"),
            cnts->team_head_style);
    html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
    fprintf(fout, "<table><tr><td>%s</td><td>", _("Change language"));
    l10n_html_locale_select(fout, phr->locale_id);
    fprintf(fout, "</td><td>%s</td></tr></table></form>\n",
            BUTTON(NEW_SRV_ACTION_CHANGE_LANGUAGE));
  }
#endif /* CONF_HAS_LIBINTL */

  if (1 /*cs->global->show_generation_time*/) {
  gettimeofday(&phr->timestamp2, 0);
  tdiff = ((long long) phr->timestamp2.tv_sec) * 1000000;
  tdiff += phr->timestamp2.tv_usec;
  tdiff -= ((long long) phr->timestamp1.tv_sec) * 1000000;
  tdiff -= phr->timestamp1.tv_usec;
  fprintf(fout, "<div class=\"dotted\"><p%s>%s: %lld %s</p></div>",
          cnts->team_par_style,
          _("Page generation time"), tdiff / 1000,
          _("msec"));
  }

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);
  html_armor_free(&ab);
}

typedef void (*action_handler_t)(FILE *fout,
                                 struct http_request_info *phr,
                                 const struct contest_desc *cnts,
                                 struct contest_extra *extra);

static action_handler_t actions_table[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_VIEW_USERS] = priv_view_users_page,
  [NEW_SRV_ACTION_USERS_REMOVE_REGISTRATIONS] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_SET_PENDING] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_SET_OK] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_SET_REJECTED] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_SET_INVISIBLE] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_CLEAR_INVISIBLE] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_SET_BANNED] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_CLEAR_BANNED] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_SET_LOCKED] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_CLEAR_LOCKED] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_SET_INCOMPLETE] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_CLEAR_INCOMPLETE] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_SET_DISQUALIFIED] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_CLEAR_DISQUALIFIED] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_ADD_BY_LOGIN] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_ADD_BY_USER_ID] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_USERS_VIEW] = priv_view_priv_users_page,
  [NEW_SRV_ACTION_PRIV_USERS_REMOVE] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_OBSERVER] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_USERS_DEL_OBSERVER] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_EXAMINER] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_USERS_DEL_EXAMINER] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_CHIEF_EXAMINER] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_USERS_DEL_CHIEF_EXAMINER] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_COORDINATOR] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_USERS_DEL_COORDINATOR] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_BY_LOGIN] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_BY_USER_ID] = priv_generic_operation,
  [NEW_SRV_ACTION_START_CONTEST] = priv_generic_operation,
  [NEW_SRV_ACTION_STOP_CONTEST] = priv_generic_operation,
  [NEW_SRV_ACTION_CONTINUE_CONTEST] = priv_generic_operation,
  [NEW_SRV_ACTION_SCHEDULE] = priv_generic_operation,
  [NEW_SRV_ACTION_CHANGE_DURATION] = priv_generic_operation,
  [NEW_SRV_ACTION_SUSPEND] = priv_generic_operation,
  [NEW_SRV_ACTION_RESUME] = priv_generic_operation,
  [NEW_SRV_ACTION_TEST_SUSPEND] = priv_generic_operation,
  [NEW_SRV_ACTION_TEST_RESUME] = priv_generic_operation,
  [NEW_SRV_ACTION_PRINT_SUSPEND] = priv_generic_operation,
  [NEW_SRV_ACTION_PRINT_RESUME] = priv_generic_operation,
  [NEW_SRV_ACTION_SET_JUDGING_MODE] = priv_generic_operation,
  [NEW_SRV_ACTION_SET_ACCEPTING_MODE] = priv_generic_operation,
  [NEW_SRV_ACTION_SET_TESTING_FINISHED_FLAG] = priv_generic_operation,
  [NEW_SRV_ACTION_CLEAR_TESTING_FINISHED_FLAG] = priv_generic_operation,
  [NEW_SRV_ACTION_SQUEEZE_RUNS] = priv_generic_operation,
  [NEW_SRV_ACTION_RESET_FILTER] = priv_generic_operation,
  [NEW_SRV_ACTION_RESET_CLAR_FILTER] = priv_generic_operation,
  [NEW_SRV_ACTION_VIEW_SOURCE] = priv_generic_page,
  [NEW_SRV_ACTION_VIEW_REPORT] = priv_generic_page,
  [NEW_SRV_ACTION_PRIV_DOWNLOAD_RUN] = priv_generic_page,
  [NEW_SRV_ACTION_STANDINGS] = priv_generic_page,
  [NEW_SRV_ACTION_CHANGE_LANGUAGE] = priv_generic_operation,
  [NEW_SRV_ACTION_SUBMIT_RUN] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_SUBMIT_CLAR] = priv_generic_operation,
  [NEW_SRV_ACTION_CLAR_REPLY] = priv_generic_operation,
  [NEW_SRV_ACTION_CLAR_REPLY_ALL] = priv_generic_operation,
  [NEW_SRV_ACTION_CLAR_REPLY_READ_PROBLEM] = priv_generic_operation,
  [NEW_SRV_ACTION_CLAR_REPLY_NO_COMMENTS] = priv_generic_operation,
  [NEW_SRV_ACTION_CLAR_REPLY_YES] = priv_generic_operation,
  [NEW_SRV_ACTION_CLAR_REPLY_NO] = priv_generic_operation,
  [NEW_SRV_ACTION_VIEW_CLAR] = priv_generic_page,
  [NEW_SRV_ACTION_RELOAD_SERVER] = priv_generic_operation,
  [NEW_SRV_ACTION_CHANGE_STATUS] = priv_generic_operation,
  [NEW_SRV_ACTION_CHANGE_RUN_STATUS] = priv_generic_operation,
  [NEW_SRV_ACTION_REJUDGE_DISPLAYED_1] = priv_generic_page,
  [NEW_SRV_ACTION_REJUDGE_DISPLAYED_2] = priv_generic_operation,
  [NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_1] = priv_generic_page,
  [NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_2] = priv_generic_operation,
  [NEW_SRV_ACTION_REJUDGE_PROBLEM_1] = priv_generic_page,
  [NEW_SRV_ACTION_REJUDGE_PROBLEM_2] = priv_generic_operation,
  [NEW_SRV_ACTION_REJUDGE_SUSPENDED_1] = priv_generic_page,
  [NEW_SRV_ACTION_REJUDGE_SUSPENDED_2] = priv_generic_operation,
  [NEW_SRV_ACTION_REJUDGE_ALL_1] = priv_generic_page,
  [NEW_SRV_ACTION_REJUDGE_ALL_2] = priv_generic_operation,
  [NEW_SRV_ACTION_COMPARE_RUNS] = priv_generic_page,
  [NEW_SRV_ACTION_VIEW_TEST_INPUT] = priv_generic_page,
  [NEW_SRV_ACTION_VIEW_TEST_ANSWER] = priv_generic_page,
  [NEW_SRV_ACTION_VIEW_TEST_INFO] = priv_generic_page,
  [NEW_SRV_ACTION_VIEW_TEST_OUTPUT] = priv_generic_page,
  [NEW_SRV_ACTION_VIEW_TEST_ERROR] = priv_generic_page,
  [NEW_SRV_ACTION_VIEW_TEST_CHECKER] = priv_generic_page,
  [NEW_SRV_ACTION_VIEW_AUDIT_LOG] = priv_generic_page,
  [NEW_SRV_ACTION_UPDATE_STANDINGS_2] = priv_generic_operation,
  [NEW_SRV_ACTION_UPDATE_STANDINGS_1] = priv_generic_page,
  [NEW_SRV_ACTION_RESET_2] = priv_generic_operation,
  [NEW_SRV_ACTION_RESET_1] = priv_generic_page,
  [NEW_SRV_ACTION_GENERATE_PASSWORDS_1] = priv_generic_page,
  [NEW_SRV_ACTION_GENERATE_PASSWORDS_2] = priv_generic_operation,
  [NEW_SRV_ACTION_GENERATE_REG_PASSWORDS_1] = priv_generic_page,
  [NEW_SRV_ACTION_GENERATE_REG_PASSWORDS_2] = priv_generic_operation,
  [NEW_SRV_ACTION_CLEAR_PASSWORDS_1] = priv_generic_page,
  [NEW_SRV_ACTION_CLEAR_PASSWORDS_2] = priv_generic_operation,
  [NEW_SRV_ACTION_VIEW_CNTS_PWDS] = priv_generic_page,
  [NEW_SRV_ACTION_VIEW_REG_PWDS] = priv_generic_page,
  [NEW_SRV_ACTION_VIEW_USER_INFO] = priv_generic_page,
  [NEW_SRV_ACTION_NEW_RUN_FORM] = priv_generic_page,
  [NEW_SRV_ACTION_VIEW_USER_DUMP] = priv_generic_page,
  [NEW_SRV_ACTION_USER_CHANGE_STATUS] = priv_generic_operation,
  [NEW_SRV_ACTION_NEW_RUN] = priv_generic_operation,
  [NEW_SRV_ACTION_CHANGE_RUN_USER_ID] = priv_generic_operation,
  [NEW_SRV_ACTION_CHANGE_RUN_USER_LOGIN] = priv_generic_operation,
  [NEW_SRV_ACTION_CHANGE_RUN_PROB_ID] = priv_generic_operation,
  [NEW_SRV_ACTION_CHANGE_RUN_VARIANT] = priv_generic_operation,
  [NEW_SRV_ACTION_CHANGE_RUN_LANG_ID] = priv_generic_operation,
  [NEW_SRV_ACTION_CHANGE_RUN_IS_IMPORTED] = priv_generic_operation,
  [NEW_SRV_ACTION_CHANGE_RUN_IS_HIDDEN] = priv_generic_operation,
  [NEW_SRV_ACTION_CHANGE_RUN_IS_EXAMINABLE] = priv_generic_operation,
  [NEW_SRV_ACTION_CHANGE_RUN_IS_READONLY] = priv_generic_operation,
  [NEW_SRV_ACTION_CHANGE_RUN_TEST] = priv_generic_operation,
  [NEW_SRV_ACTION_CHANGE_RUN_SCORE] = priv_generic_operation,
  [NEW_SRV_ACTION_CHANGE_RUN_SCORE_ADJ] = priv_generic_operation,
  [NEW_SRV_ACTION_CHANGE_RUN_PAGES] = priv_generic_operation,
  [NEW_SRV_ACTION_CLEAR_RUN] = priv_generic_operation,
  [NEW_SRV_ACTION_PRINT_RUN] = priv_generic_operation,
  [NEW_SRV_ACTION_ISSUE_WARNING] = priv_generic_operation,
  [NEW_SRV_ACTION_SET_DISQUALIFICATION] = priv_generic_operation,
  [NEW_SRV_ACTION_LOGOUT] = priv_logout,
  [NEW_SRV_ACTION_CHANGE_PASSWORD] = priv_change_password,
  [NEW_SRV_ACTION_VIEW_USER_REPORT] = priv_generic_page,
  [NEW_SRV_ACTION_DOWNLOAD_ARCHIVE_1] = priv_generic_page,
  [NEW_SRV_ACTION_DOWNLOAD_ARCHIVE_2] = priv_generic_page,
  [NEW_SRV_ACTION_UPLOAD_RUNLOG_CSV_1] = priv_generic_page,
  [NEW_SRV_ACTION_UPLOAD_RUNLOG_CSV_2] = priv_generic_page,
  [NEW_SRV_ACTION_VIEW_RUNS_DUMP] = priv_generic_page,
  [NEW_SRV_ACTION_EXPORT_XML_RUNS] = priv_generic_page,
  [NEW_SRV_ACTION_WRITE_XML_RUNS] = priv_generic_page,
  [NEW_SRV_ACTION_WRITE_XML_RUNS_WITH_SRC] = priv_generic_page,
  [NEW_SRV_ACTION_UPLOAD_RUNLOG_XML_1] = priv_generic_page,
  [NEW_SRV_ACTION_UPLOAD_RUNLOG_XML_2] = priv_generic_page,
  [NEW_SRV_ACTION_CLEAR_DISPLAYED_1] = priv_generic_page,
  [NEW_SRV_ACTION_CLEAR_DISPLAYED_2] = priv_generic_operation,
  [NEW_SRV_ACTION_IGNORE_DISPLAYED_1] = priv_generic_page,
  [NEW_SRV_ACTION_IGNORE_DISPLAYED_2] = priv_generic_operation,
  [NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_1] = priv_generic_page,
  [NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_2] = priv_generic_operation,
  [NEW_SRV_ACTION_UPSOLVING_CONFIG_1] = priv_generic_page,
  [NEW_SRV_ACTION_UPSOLVING_CONFIG_2] = priv_generic_operation,
  [NEW_SRV_ACTION_UPSOLVING_CONFIG_3] = priv_generic_operation,
  [NEW_SRV_ACTION_UPSOLVING_CONFIG_4] = priv_generic_operation,
  [NEW_SRV_ACTION_EXAMINERS_PAGE] = priv_generic_page,
  [NEW_SRV_ACTION_ASSIGN_CHIEF_EXAMINER] = priv_generic_operation,
  [NEW_SRV_ACTION_ASSIGN_EXAMINER] = priv_generic_operation,
  [NEW_SRV_ACTION_UNASSIGN_EXAMINER] = priv_generic_operation,
  [NEW_SRV_ACTION_TOGGLE_VISIBILITY] = priv_generic_operation,
  [NEW_SRV_ACTION_TOGGLE_BAN] = priv_generic_operation,
  [NEW_SRV_ACTION_TOGGLE_LOCK] = priv_generic_operation,
  [NEW_SRV_ACTION_TOGGLE_INCOMPLETENESS] = priv_generic_operation,
  [NEW_SRV_ACTION_VIEW_ONLINE_USERS] = priv_generic_page,
  [NEW_SRV_ACTION_PRINT_USER_PROTOCOL] = priv_generic_page,
  [NEW_SRV_ACTION_PRINT_USER_FULL_PROTOCOL] = priv_generic_page,
  [NEW_SRV_ACTION_PRINT_UFC_PROTOCOL] = priv_generic_page,
  [NEW_SRV_ACTION_FORCE_START_VIRTUAL] = priv_generic_operation,
  [NEW_SRV_ACTION_PRINT_SELECTED_USER_PROTOCOL] = priv_generic_page,
  [NEW_SRV_ACTION_PRINT_SELECTED_USER_FULL_PROTOCOL] = priv_generic_page,
  [NEW_SRV_ACTION_PRINT_SELECTED_UFC_PROTOCOL] = priv_generic_page,
  [NEW_SRV_ACTION_PRINT_PROBLEM_PROTOCOL] = priv_generic_page,
  [NEW_SRV_ACTION_ASSIGN_CYPHERS_1] = priv_generic_page,
  [NEW_SRV_ACTION_ASSIGN_CYPHERS_2] = priv_generic_page,
  [NEW_SRV_ACTION_VIEW_EXAM_INFO] = priv_generic_page,
};

static void
privileged_entry_point(
        FILE *fout,
        struct http_request_info *phr)
{
  int r;
  opcap_t caps;
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  time_t cur_time = time(0);
  unsigned char hid_buf[1024];
  struct teamdb_db_callbacks callbacks;

  if (phr->action == NEW_SRV_ACTION_COOKIE_LOGIN)
    return privileged_page_cookie_login(fout, phr);

  if (!phr->session_id || phr->action == NEW_SRV_ACTION_LOGIN_PAGE)
    return privileged_page_login(fout, phr);

  // validate cookie
  if (ns_open_ul_connection(phr->fw_state) < 0)
    return ns_html_err_ul_server_down(fout, phr, 1, 0);
  if ((r = userlist_clnt_get_cookie(ul_conn, ULS_PRIV_GET_COOKIE,
                                    phr->ip, phr->ssl_flag,
                                    phr->session_id,
                                    &phr->user_id, &phr->contest_id,
                                    &phr->locale_id, 0, &phr->role, 0, 0, 0,
                                    &phr->login, &phr->name)) < 0) {
    switch (-r) {
    case ULS_ERR_NO_COOKIE:
      return ns_html_err_inv_session(fout, phr, 1,
                                     "priv_login failed: %s",
                                     userlist_strerror(-r));
    case ULS_ERR_DISCONNECT:
      return ns_html_err_ul_server_down(fout, phr, 1, 0);
    default:
      return ns_html_err_internal_error(fout, phr, 1, "priv_login failed: %s",
                                        userlist_strerror(-r));
    }
  }

  if (phr->contest_id < 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts)
    return ns_html_err_no_perm(fout, phr, 1, "invalid contest_id %d",
                               phr->contest_id);
  if (!cnts->new_managed)
    return ns_html_err_inv_param(fout, phr, 1, "contest is not managed");
  extra = ns_get_contest_extra(phr->contest_id);
  ASSERT(extra);

  // analyze IP limitations
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (!contests_check_master_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      return ns_html_err_no_perm(fout, phr, 1, "%s://%s is not allowed for MASTER for contest %d", ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  } else {
    // as for judge program
    if (!contests_check_judge_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      return ns_html_err_no_perm(fout, phr, 1, "%s://%s is not allowed for MASTER for contest %d", ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  }

  // analyze permissions
  if (phr->role <= 0 || phr->role >= USER_ROLE_LAST)
    return ns_html_err_no_perm(fout, phr, 1, "invalid role %d", phr->role);
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
        || opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0)
      return ns_html_err_no_perm(fout, phr, 1, "user %s does not have MASTER_LOGIN bit for contest %d", phr->login, phr->contest_id);
  } else if (phr->role == USER_ROLE_JUDGE) {
    // as for the judge program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
        || opcaps_check(caps, OPCAP_JUDGE_LOGIN) < 0)
      return ns_html_err_no_perm(fout, phr, 1, "user %s does not have JUDGE_LOGIN bit for contest %d", phr->login, phr->contest_id);
  } else {
    // user privileges checked locally
    if (nsdb_check_role(phr->user_id, phr->contest_id, phr->role) < 0)
      return ns_html_err_no_perm(fout, phr, 1, "user %s has no permission to login as role %d for contest %d", phr->login, phr->role, phr->contest_id);
  }

  watched_file_update(&extra->priv_header, cnts->priv_header_file, cur_time);
  watched_file_update(&extra->priv_footer, cnts->priv_footer_file, cur_time);
  extra->header_txt = extra->priv_header.text;
  extra->footer_txt = extra->priv_footer.text;
  if (!extra->header_txt || !extra->footer_txt) {
    extra->header_txt = ns_fancy_priv_header;
    extra->footer_txt = ns_fancy_priv_footer;
    extra->separator_txt = ns_fancy_priv_separator;
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

  snprintf(hid_buf, sizeof(hid_buf),
           "<input type=\"hidden\" name=\"SID\" value=\"%016llx\"/>",
           phr->session_id);
  phr->hidden_vars = hid_buf;
  phr->session_extra = ns_get_session(phr->session_id, cur_time);
  phr->caps = 0;
  if (opcaps_find(&cnts->capabilities, phr->login, &caps) >= 0) {
    phr->caps = caps;
  }
  phr->dbcaps = 0;
  if (opcaps_find(&config->capabilities, phr->login, &caps) >= 0) {
    phr->dbcaps = caps;
  }

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.user_data = (void*) phr->fw_state;
  callbacks.list_all_users = ns_list_all_users_callback;

  // invoke the contest
  if (serve_state_load_contest(phr->contest_id,
                               ul_conn,
                               &callbacks,
                               &extra->serve_state, 0) < 0) {
    return ns_html_err_cnts_unavailable(fout, phr, 0, 0);
  }

  extra->serve_state->current_time = time(0);
  ns_check_contest_events(extra->serve_state, cnts);
  
  if (phr->action > 0 && phr->action < NEW_SRV_ACTION_LAST
      && actions_table[phr->action]) {
    actions_table[phr->action](fout, phr, cnts, extra);
  } else {
    if (phr->action < 0 || phr->action >= NEW_SRV_ACTION_LAST)
      phr->action = 0;
    priv_main_page(fout, phr, cnts, extra);
  }
}

static void
unpriv_load_html_style(struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra **p_extra,
                       time_t *p_cur_time)
{
  struct contest_extra *extra = 0;
  time_t cur_time = 0;
#if defined CONF_ENABLE_AJAX && CONF_ENABLE_AJAX
  unsigned char bb[8196];
  char *state_xml_txt = 0;
  size_t state_xml_len = 0;
  FILE *state_xml_f = 0;
#endif

  extra = ns_get_contest_extra(phr->contest_id);
  ASSERT(extra);

  cur_time = time(0);
  watched_file_update(&extra->header, cnts->team_header_file, cur_time);
  watched_file_update(&extra->menu_1, cnts->team_menu_1_file, cur_time);
  watched_file_update(&extra->menu_2, cnts->team_menu_2_file, cur_time);
  watched_file_update(&extra->separator, cnts->team_separator_file, cur_time);
  watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
  watched_file_update(&extra->copyright, cnts->copyright_file, cur_time);
  extra->header_txt = extra->header.text;
  extra->footer_txt = extra->footer.text;
  extra->separator_txt = extra->separator.text;
  extra->copyright_txt = extra->copyright.text;
  if (!extra->header_txt || !extra->footer_txt || !extra->separator_txt) {
    extra->header_txt = ns_fancy_header;
    extra->separator_txt = ns_fancy_separator;
    if (extra->copyright_txt) extra->footer_txt = ns_fancy_footer_2;
    else extra->footer_txt = ns_fancy_footer;
  }

  if (extra->contest_arm) xfree(extra->contest_arm);
  if (phr->locale_id == 0 && cnts->name_en) {
    extra->contest_arm = html_armor_string_dup(cnts->name_en);
  } else {
    extra->contest_arm = html_armor_string_dup(cnts->name);
  }

  if (p_extra) *p_extra = extra;
  if (p_cur_time) *p_cur_time = cur_time;

  // js part
#if defined CONF_ENABLE_AJAX && CONF_ENABLE_AJAX
  if (extra->serve_state && phr->user_id > 0) {
    state_xml_f = open_memstream(&state_xml_txt, &state_xml_len);
    do_xml_user_state(state_xml_f, extra->serve_state, phr->user_id);
    fclose(state_xml_f); state_xml_f = 0;
  } else {
    state_xml_txt = xstrdup("");
  }

  snprintf(bb, sizeof(bb),
           "<script type=\"text/javascript\" src=\"" CONF_STYLE_PREFIX "dojo.js\"></script>\n"
           "<script type=\"text/javascript\" src=\"" CONF_STYLE_PREFIX "actions.js\"></script>\n"
           "<script type=\"text/javascript\" src=\"" CONF_STYLE_PREFIX "unpriv.js\"></script>\n"
           "<script type=\"text/javascript\">\n"
           "  var SID=\"%016llx\";\n"
           "  var self_url=\"%s\";\n"
           "  dojo.require(\"dojo.event.*\");\n"
           "  dojo.require(\"dojo.io.*\");\n"
           "  dojo.require(\"dojo.xml.Parse\");\n"
           "  var xmlStateStr = \"%s\";\n"
           "</script>\n", phr->session_id, phr->self_url,
           state_xml_txt);
  xfree(state_xml_txt); state_xml_txt = 0;
  phr->script_part = xstrdup(bb);
  snprintf(bb, sizeof(bb), " onload=\"startClock()\"");
  phr->body_attr = xstrdup(bb);
#endif
}

static int
unpriv_parse_run_id(FILE *fout, struct http_request_info *phr,
                    const struct contest_desc *cnts,
                    struct contest_extra *extra, int *p_run_id,
                    struct run_entry *pe)
{
  const serve_state_t cs = extra->serve_state;
  int n, run_id;
  const unsigned char *s = 0, *errmsg = 0;
  unsigned char msgbuf[1024];
  
  if (!(n = ns_cgi_param(phr, "run_id", &s))) {
    errmsg = ns_strerror_r(msgbuf, sizeof(msgbuf),
                           NEW_SRV_ERR_RUN_ID_UNDEFINED);
    goto failure;
  }
  if (n < 0 || sscanf(s, "%d%n", &run_id, &n) != 1 || s[n]) {
    errmsg = ns_strerror_r(msgbuf, sizeof(msgbuf), NEW_SRV_ERR_INV_RUN_ID);
    goto failure;
  }
  if (run_id < 0 || run_id >= run_get_total(cs->runlog_state)) {
    errmsg = ns_strerror_r(msgbuf, sizeof(msgbuf), NEW_SRV_ERR_INV_RUN_ID);
    errmsg = msgbuf;
    goto failure;
  }

  if (p_run_id) *p_run_id = run_id;
  if (pe && run_get_entry(cs->runlog_state, run_id, pe) < 0) {
    errmsg = ns_strerror_r(msgbuf, sizeof(msgbuf),
                           NEW_SRV_ERR_RUNLOG_READ_FAILED, run_id);
    goto failure;
  }

  return 0;

 failure:
  html_error_status_page(fout, phr, cnts, extra, errmsg,
                         ns_unpriv_prev_state[phr->action], 0);
  return -1;
}

/* FIXME: this should be moved to `new-register' part */
static void
unpriv_page_forgot_password_1(FILE *fout, struct http_request_info *phr,
                              int orig_locale_id)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  time_t cur_time = 0;
  unsigned char bb[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (phr->contest_id <= 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest_id is invalid");
  if (orig_locale_id < 0 && cnts->default_locale_val >= 0)
    phr->locale_id = cnts->default_locale_val;
  if (!contests_check_team_ip(phr->contest_id, phr->ip, phr->ssl_flag))
    return ns_html_err_service_not_available(fout, phr, 0, "%s://%s is not allowed for USER for contest %d", ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  if (cnts->closed)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d is closed", cnts->id);
  if (!cnts->new_managed)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d is not managed",
                                             cnts->id);
  if (cnts->client_disable_team)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d user is disabled",
                                             cnts->id);
  if (!cnts->enable_forgot_password
      || (cnts->simple_registration && !cnts->send_passwd_email))
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d password recovery disabled",
                                             cnts->id);

  unpriv_load_html_style(phr, cnts, &extra, &cur_time);

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            _("Lost password recovery [%s]"), extra->contest_arm);

  // change language button
  fprintf(fout, "<div class=\"user_actions\"><table class=\"menu\"><tr>\n");
  html_start_form(fout, 1, phr->self_url, "");
  html_hidden(fout, "contest_id", "%d", phr->contest_id);
  html_hidden(fout, "action", "%d", NEW_SRV_ACTION_FORGOT_PASSWORD_1);
  if (cnts->disable_locale_change) 
    html_hidden(fout, "locale_id", "%d", phr->locale_id);

  if (!cnts->disable_locale_change) {
    fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s: ",
            _("language"));
    l10n_html_locale_select(fout, phr->locale_id);
    fprintf(fout, "</div></td>\n");
  }

  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s</div></td>\n", ns_submit_button(bb, sizeof(bb), "submit", 0, _("Change Language")));

  fprintf(fout, "</tr></table></div>\n"
          "<div class=\"white_empty_block\">&nbsp;</div>\n"
          "<div class=\"contest_actions\"><table class=\"menu\"><tr>\n");

  fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td></tr></table></div>\n");

  //fprintf(fout, "<div class=\"l13\">\n");
  if (extra->separator_txt && *extra->separator_txt)
    fprintf(fout, "%s", extra->separator_txt);

  fprintf(fout, _("<p class=\"fixed_width\">Password recovery requires several steps. Now, please, specify the <b>login</b> and the <b>e-mail</b>, which was specified when the login was created.</p>\n<p class=\"fixed_width\">Note, that automatic password recovery is not possible for invisible, banned, locked, or privileged users!</p>\n"));

  html_start_form(fout, 1, phr->self_url, "");
  html_hidden(fout, "contest_id", "%d", phr->contest_id);
  fprintf(fout, "<table><tr><td class=\"menu\">%s:</td><td class=\"menu\">%s</td></tr>\n",
          _("Login"), html_input_text(bb, sizeof(bb), "login", 16, 0));
  fprintf(fout, "<tr><td class=\"menu\">%s:</td><td class=\"menu\">%s</td></tr>\n",
          _("E-mail"), html_input_text(bb, sizeof(bb), "email", 16, 0));
  fprintf(fout, "<tr><td class=\"menu\">&nbsp;</td><td class=\"menu\">%s</td></tr></table></form>\n",
          BUTTON(NEW_SRV_ACTION_FORGOT_PASSWORD_2));


  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);
  html_armor_free(&ab);
}

/* FIXME: this should be moved to `new-register' part */
static void
unpriv_page_forgot_password_2(FILE *fout, struct http_request_info *phr,
                              int orig_locale_id)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  time_t cur_time;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *login = 0, *email = 0;
  int r;
  FILE *log_f = 0;
  char *log_txt = 0;
  size_t log_len = 0;

  if (phr->contest_id <= 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts)
    return ns_html_err_service_not_available(fout, phr, 0, "contest_id is invalid");
  if (orig_locale_id < 0 && cnts->default_locale_val >= 0)
    phr->locale_id = cnts->default_locale_val;
  if (!contests_check_team_ip(phr->contest_id, phr->ip, phr->ssl_flag))
    return ns_html_err_service_not_available(fout, phr, 0, "%s://%s is not allowed for USER for contest %d", ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  if (cnts->closed)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d is closed", cnts->id);
  if (!cnts->new_managed)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d is not managed",
                                             cnts->id);
  if (cnts->client_disable_team)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d user is disabled",
                                             cnts->id);
  if (!cnts->enable_forgot_password
      || (cnts->simple_registration && !cnts->send_passwd_email))
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d password recovery disabled",
                                             cnts->id);

  if (ns_cgi_param(phr, "login", &login) <= 0) {
    return ns_html_err_inv_param(fout, phr, 0, "login is not specified");
  }
  if (ns_cgi_param(phr, "email", &email) <= 0) {
    return ns_html_err_inv_param(fout, phr, 0, "email is not specified");
  }

  unpriv_load_html_style(phr, cnts, &extra, &cur_time);

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    ns_html_err_ul_server_down(fout, phr, 0, 0);
    goto cleanup;
  }
  r = userlist_clnt_register_new(ul_conn, ULS_RECOVER_PASSWORD_1,
                                 phr->ip, phr->ssl_flag,
                                 phr->contest_id,
                                 phr->locale_id,
                                 NEW_SRV_ACTION_FORGOT_PASSWORD_3,
                                 login, email, phr->self_url);

  if (r < 0) {
    log_f = open_memstream(&log_txt, &log_len);

    if (r == -ULS_ERR_EMAIL_FAILED) {
      fprintf(log_f, "%s",
              _("The server was unable to send a registration e-mail\n"
                "to the specified address. This is probably due\n"
                "to heavy server load rather than to an invalid\n"
                "e-mail address. You should try to register later.\n"));
    } else {
      fprintf(log_f, gettext(userlist_strerror(-r)));
    }

    fclose(log_f); log_f = 0;

    l10n_setlocale(phr->locale_id);
    ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
                     _("Password recovery error"));
    fprintf(fout, "%s", ns_fancy_empty_status);
    if (extra->separator_txt && *extra->separator_txt)
      fprintf(fout, "%s", extra->separator_txt);
    fprintf(fout, "<p>Password recovery is not possible because of the following error.</p>\n");
    //fprintf(fout, "%s", extra->separator_txt);
    fprintf(fout, "<font color=\"red\"><pre>%s</pre></font>\n", ARMOR(log_txt));
    ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
    l10n_setlocale(0);
    goto cleanup;
  }

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            _("Password recovery, stage 1 [%s, %s]"),
            ARMOR(login), extra->contest_arm);
  fprintf(fout, "%s", ns_fancy_empty_status);
  if (extra->separator_txt && *extra->separator_txt)
    fprintf(fout, "%s", extra->separator_txt);

  fprintf(fout, _("<p class=\"fixed_width\">First stage of password recovery is successful. You should receive an e-mail message with further instructions. <b>Note,</b> that you should confirm password recovery in 24 hours, or operation will be cancelled.</p>"));

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  if (log_f) fclose(log_f);
  xfree(log_txt);
  html_armor_free(&ab);
}

/* FIXME: this should be moved to `new-register' part */
static void
unpriv_page_forgot_password_3(FILE *fout, struct http_request_info *phr,
                              int orig_locale_id)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  time_t cur_time = 0;
  int user_id = 0;
  unsigned char *login = 0, *name = 0, *passwd = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int r;
  FILE *log_f = 0;
  char *log_txt = 0;
  size_t log_len = 0;
  unsigned char bb[1024];
  const unsigned char *s = 0;

  if (phr->contest_id <= 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts)
    return ns_html_err_service_not_available(fout, phr, 0, "contest_id is invalid");
  if (orig_locale_id < 0 || cnts->default_locale_val >= 0)
    phr->locale_id = cnts->default_locale_val;
  if (!contests_check_team_ip(phr->contest_id, phr->ip, phr->ssl_flag))
    return ns_html_err_service_not_available(fout, phr, 0, "%s://%s is not allowed for USER for contest %d", ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  if (cnts->closed)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d is closed", cnts->id);
  if (!cnts->new_managed)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d is not managed",
                                             cnts->id);
  if (cnts->client_disable_team)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d user is disabled",
                                             cnts->id);
  if (!cnts->enable_forgot_password
      || (cnts->simple_registration && !cnts->send_passwd_email))
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d password recovery disabled",
                                             cnts->id);

  unpriv_load_html_style(phr, cnts, &extra, &cur_time);

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    ns_html_err_ul_server_down(fout, phr, 0, 0);
    goto cleanup;
  }
  r = userlist_clnt_recover_passwd_2(ul_conn, ULS_RECOVER_PASSWORD_2,
                                     phr->ip, phr->ssl_flag,
                                     phr->contest_id, phr->session_id,
                                     &user_id, &login, &name, &passwd);

  if (r < 0) {
    log_f = open_memstream(&log_txt, &log_len);

    if (r == -ULS_ERR_EMAIL_FAILED) {
      fprintf(log_f, "%s",
              _("The server was unable to send a registration e-mail\n"
                "to the specified address. This is probably due\n"
                "to heavy server load rather than to an invalid\n"
                "e-mail address. You should try to register later.\n"));
    } else {
      fprintf(log_f, gettext(userlist_strerror(-r)));
    }

    fclose(log_f); log_f = 0;

    l10n_setlocale(phr->locale_id);
    ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
              _("Password recovery error"));
    fprintf(fout, "%s", ns_fancy_empty_status);
    if (extra->separator_txt && *extra->separator_txt)
      fprintf(fout, "%s", extra->separator_txt);
    fprintf(fout, "<p>Password recovery is not possible because of the following error.</p>\n");
    //fprintf(fout, "%s", extra->separator_txt);
    fprintf(fout, "<font color=\"red\"><pre>%s</pre></font>\n", ARMOR(log_txt));
    ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
    l10n_setlocale(0);
    goto cleanup;
  }

  s = name;
  if (!s || !*s) s = login;

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            _("Password recovery completed [%s, %s]"),
            ARMOR(s), extra->contest_arm);
  fprintf(fout, "%s", ns_fancy_empty_status);
  if (extra->separator_txt && *extra->separator_txt)
    fprintf(fout, "%s", extra->separator_txt);

  fprintf(fout, _("<p>New password is generated.</p>"));
  fprintf(fout, "<table><tr><td class=\"menu\">%s</td><td class=\"menu\"><tt>%s</tt></td></tr>\n",
          _("Login"), ARMOR(login));
  fprintf(fout, "<tr><td class=\"menu\">%s</td><td class=\"menu\"><tt>%s</tt></td></tr></table>\n", _("Password"), ARMOR(passwd));

  html_start_form(fout, 1, phr->self_url, "");
  html_hidden(fout, "contest_id", "%d", phr->contest_id);
  html_hidden(fout, "role", "%d", 0);
  html_hidden(fout, "locale_id", "%d", phr->locale_id);
  fprintf(fout, "<table><tr><td class=\"menu\">%s:</td><td class=\"menu\">%s</td></tr>\n",
          _("Login"), html_input_text(bb, sizeof(bb), "login", 16, "%s", ARMOR(login)));
  fprintf(fout, "<tr><td class=\"menu\">%s:</td><td class=\"menu\"><input type=\"password\" size=\"16\" name=\"password\" value=\"%s\"/></td></tr>\n",
          _("Password"), ARMOR(passwd));
  fprintf(fout, "<tr><td class=\"menu\">&nbsp;</td><td class=\"menu\">%s</td></tr></table></form>\n",
          ns_submit_button(bb, sizeof(bb), "submit", 0, _("Submit")));
  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 cleanup:
  xfree(login);
  xfree(name);
  xfree(passwd);
  if (log_f) fclose(log_f);
  xfree(log_txt);
  html_armor_free(&ab);
}

void
unprivileged_page_login_page(FILE *fout, struct http_request_info *phr,
                             int orig_locale_id)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  time_t cur_time;
  const unsigned char *s, *ss;
  unsigned char bb[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int vis_flag = 0;

  if (phr->contest_id <= 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts)
    return ns_html_err_service_not_available(fout, phr, 0, "contest_id is invalid");
  if (orig_locale_id < 0 && cnts->default_locale_val >= 0)
    phr->locale_id = cnts->default_locale_val;
  if (!contests_check_team_ip(phr->contest_id, phr->ip, phr->ssl_flag))
    return ns_html_err_service_not_available(fout, phr, 0, "%s://%s is not allowed for USER for contest %d", ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  if (cnts->closed)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d is closed", cnts->id);
  if (!cnts->new_managed)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d is not managed",
                                             cnts->id);
  if (cnts->client_disable_team)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d user is disabled",
                                             cnts->id);

  extra = ns_get_contest_extra(phr->contest_id);
  ASSERT(extra);

  cur_time = time(0);
  watched_file_update(&extra->header, cnts->team_header_file, cur_time);
  watched_file_update(&extra->menu_1, cnts->team_menu_1_file, cur_time);
  watched_file_update(&extra->menu_2, cnts->team_menu_2_file, cur_time);
  watched_file_update(&extra->separator, cnts->team_separator_file, cur_time);
  watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
  watched_file_update(&extra->copyright, cnts->copyright_file, cur_time);
  extra->header_txt = extra->header.text;
  extra->menu_1_txt = extra->menu_1.text;
  extra->menu_2_txt = extra->menu_2.text;
  extra->footer_txt = extra->footer.text;
  extra->separator_txt = extra->separator.text;
  extra->copyright_txt = extra->copyright.text;
  if (!extra->header_txt || !extra->footer_txt || !extra->separator_txt) {
    extra->header_txt = ns_fancy_header;
    if (extra->copyright_txt) extra->footer_txt = ns_fancy_footer_2;
    else extra->footer_txt = ns_fancy_footer;
    extra->separator_txt = ns_fancy_separator;
  }

  if (extra->contest_arm) xfree(extra->contest_arm);
  if (phr->locale_id == 0 && cnts->name_en) {
    extra->contest_arm = html_armor_string_dup(cnts->name_en);
  } else {
    extra->contest_arm = html_armor_string_dup(cnts->name);
  }

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            _("User login [%s]"), extra->contest_arm);


  html_start_form(fout, 1, phr->self_url, "");
  fprintf(fout, "<div class=\"user_actions\">");
  html_hidden(fout, "contest_id", "%d", phr->contest_id);
  html_hidden(fout, "role", "%s", "0");
  if (cnts->disable_locale_change)
    html_hidden(fout, "locale_id", "%d", phr->locale_id);
  fprintf(fout, "<table class=\"menu\"><tr>\n");

  ss = 0;
  if (ns_cgi_param(phr, "login", &s) > 0) ss = ARMOR(s);
  if (!ss) ss = "";
  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s: %s</div></td>\n", _("login"), html_input_text(bb, sizeof(bb), "login", 8, "%s", ss));

  ss = 0;
  if (ns_cgi_param(phr, "password", &s) > 0) ss = ARMOR(s);
  if (!ss) ss = "";
  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s: <input type=\"password\" size=\"8\" name=\"password\" value=\"%s\"/></div></td>\n", _("password"), ss);

  if (!cnts->disable_locale_change) {
    fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s: ",
            _("language"));
    l10n_html_locale_select(fout, phr->locale_id);
    fprintf(fout, "</div></td>\n");
  }

  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s</div></td>\n", ns_submit_button(bb, sizeof(bb), "submit", 0, _("Log in")));

  fprintf(fout, "</tr></table>");
  fprintf(fout, "</div></form>\n"
          "<div class=\"white_empty_block\">&nbsp;</div>\n"
          "<div class=\"contest_actions\"><table class=\"menu\"><tr>\n");

  if (cnts && cnts->assign_logins && cnts->force_registration
      && cnts->register_url
      && (cnts->reg_deadline <= 0 || cur_time < cnts->reg_deadline)) {
    fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">");
    if (cnts->assign_logins) {
      fprintf(fout,
              "<a class=\"menu\" href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d\">%s</a>",
              cnts->register_url, phr->contest_id, phr->locale_id,
              NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE,
              _("Registration"));
    } else {
      fprintf(fout,
              "<a class=\"menu\" href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=2\">%s</a>",
              cnts->register_url, phr->contest_id, phr->locale_id,
              _("Registration"));
    }
    fprintf(fout, "</div></td>\n");
    vis_flag++;
  } else if (cnts && cnts->register_url
             && (cnts->reg_deadline <= 0 || cur_time < cnts->reg_deadline)) {
    fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">");
    fprintf(fout,
            "<a class=\"menu\" href=\"%s?contest_id=%d&amp;locale_id=%d\">%s</a>",
            cnts->register_url, phr->contest_id, phr->locale_id,
            _("Registration"));
    fprintf(fout, "</div></td>\n");
    vis_flag++;
  }

  if (cnts && cnts->enable_forgot_password && cnts->disable_team_password) {
    fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\"><a class=\"menu\" href=\"%s?contest_id=%d&amp;locale_id=%d&amp;action=%d\">%s</a></div></td>", phr->self_url, phr->contest_id, phr->locale_id, NEW_SRV_ACTION_FORGOT_PASSWORD_1, _("Forgot password?"));
    vis_flag++;
  }

  if (!vis_flag) {
    fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td>");
  }

  /*
  fprintf(fout, "<div class=\"search_actions\"><a href=\"\">%s</a>&nbsp;&nbsp;<a href=\"\">%s</a></div>", _("Registration"), _("Forgot the password?"));
  */

  fprintf(fout, "</tr></table></div>\n");
  if (extra->separator_txt && *extra->separator_txt)
    fprintf(fout, "%s", extra->separator_txt);

  watched_file_update(&extra->welcome, cnts->welcome_file, cur_time);
  if (extra->welcome.text && extra->welcome.text[0])
    fprintf(fout, "%s", extra->welcome.text);

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);
  html_armor_free(&ab);
}

static void
unprivileged_page_login(FILE *fout, struct http_request_info *phr,
                        int orig_locale_id)
{
  const unsigned char *login = 0;
  const unsigned char *password = 0;
  int r;
  const struct contest_desc *cnts = 0;

  if ((r = ns_cgi_param(phr, "login", &login)) < 0)
    return ns_html_err_inv_param(fout, phr, 0, "cannot parse login");
  if (!r || phr->action == NEW_SRV_ACTION_LOGIN_PAGE)
    return unprivileged_page_login_page(fout, phr, orig_locale_id);

  if (phr->contest_id<=0 || contests_get(phr->contest_id, &cnts)<0 || !cnts)
    return ns_html_err_inv_param(fout, phr, 0, "invalid contest_id");
  if (orig_locale_id < 0 && cnts->default_locale_val >= 0)
    phr->locale_id = cnts->default_locale_val;

  phr->login = xstrdup(login);
  if ((r = ns_cgi_param(phr, "password", &password)) <= 0)
    return ns_html_err_inv_param(fout, phr, 0, "cannot parse password");
  if (!contests_check_team_ip(phr->contest_id, phr->ip, phr->ssl_flag))
    return ns_html_err_no_perm(fout, phr, 0, "%s://%s is not allowed for USER for contest %d", ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  if (cnts->closed)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d is closed", cnts->id);
  if (!cnts->new_managed)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d is not managed",
                                             cnts->id);
  if (cnts->client_disable_team)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d user is disabled",
                                             cnts->id);

  if (ns_open_ul_connection(phr->fw_state) < 0)
    return ns_html_err_ul_server_down(fout, phr, 0, 0);

  if ((r = userlist_clnt_login(ul_conn, ULS_TEAM_CHECK_USER,
                               phr->ip, phr->ssl_flag, phr->contest_id,
                               phr->locale_id, login, password,
                               &phr->user_id, &phr->session_id,
                               &phr->name)) < 0) {
    switch (-r) {
    case ULS_ERR_INVALID_LOGIN:
    case ULS_ERR_INVALID_PASSWORD:
    case ULS_ERR_BAD_CONTEST_ID:
    case ULS_ERR_IP_NOT_ALLOWED:
    case ULS_ERR_NO_PERMS:
    case ULS_ERR_NOT_REGISTERED:
    case ULS_ERR_CANNOT_PARTICIPATE:
      return ns_html_err_no_perm(fout, phr, 0, "user_login failed: %s",
                                 userlist_strerror(-r));
    case ULS_ERR_DISCONNECT:
      return ns_html_err_ul_server_down(fout, phr, 0, 0);
    case ULS_ERR_INCOMPLETE_REG:
      return ns_html_err_registration_incomplete(fout, phr);
    default:
      return ns_html_err_internal_error(fout, phr, 0, "user_login failed: %s",
                                        userlist_strerror(-r));
    }
  }

  ns_get_session(phr->session_id, 0);
  ns_refresh_page(fout, phr, NEW_SRV_ACTION_MAIN_PAGE, 0);
}

static void
unpriv_change_language(FILE *fout,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra)
{
  const unsigned char *s;
  int r, n;
  char *log_txt = 0;
  size_t log_len = 0;
  FILE *log_f = 0;
  int new_locale_id;

  if ((r = ns_cgi_param(phr, "locale_id", &s)) < 0)
    return ns_html_err_inv_param(fout, phr, 0, "cannot parse locale_id");
  if (r > 0) {
    if (sscanf(s, "%d%n", &new_locale_id, &n) != 1 || s[n] || new_locale_id < 0)
      return ns_html_err_inv_param(fout, phr, 0, "cannot parse locale_id");
  }

  log_f = open_memstream(&log_txt, &log_len);

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    ns_html_err_ul_server_down(fout, phr, 0, 0);
    goto cleanup;
  }
  if ((r = userlist_clnt_set_cookie(ul_conn, ULS_SET_COOKIE_LOCALE,
                                    phr->session_id,
                                    new_locale_id)) < 0) {
    fprintf(log_f, "set_cookie failed: %s", userlist_strerror(-r));
  }

  //done:
  fclose(log_f); log_f = 0;
  if (!log_txt || !*log_txt) {
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_MAIN_PAGE, 0);
  } else {
    html_error_status_page(fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_MAIN_PAGE, 0);
  }

 cleanup:
  if (log_f) fclose(log_f);
  xfree(log_txt);
}

static void
unpriv_change_password(FILE *fout,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra)
{
  const unsigned char *p0 = 0, *p1 = 0, *p2 = 0;
  char *log_txt = 0;
  size_t log_len = 0;
  FILE *log_f = 0;
  int cmd, r;
  unsigned char url[1024];
  unsigned char login_buf[256];

  if (ns_cgi_param(phr, "oldpasswd", &p0) <= 0)
    return ns_html_err_inv_param(fout, phr, 0, "cannot parse oldpasswd");
  if (ns_cgi_param(phr, "newpasswd1", &p1) <= 0)
    return ns_html_err_inv_param(fout, phr, 0, "cannot parse newpasswd1");
  if (ns_cgi_param(phr, "newpasswd2", &p2) <= 0)
    return ns_html_err_inv_param(fout, phr, 0, "cannot parse newpasswd2");

  log_f = open_memstream(&log_txt, &log_len);

  if (strlen(p0) >= 256) {
    ns_error(log_f, NEW_SRV_ERR_OLD_PWD_TOO_LONG);
    goto done;
  }
  if (strcmp(p1, p2)) {
    ns_error(log_f, NEW_SRV_ERR_NEW_PWD_MISMATCH);
    goto done;
  }
  if (strlen(p1) >= 256) {
    ns_error(log_f, NEW_SRV_ERR_NEW_PWD_TOO_LONG);
    goto done;
  }

  cmd = ULS_PRIV_SET_TEAM_PASSWD;
  if (cnts->disable_team_password) cmd = ULS_PRIV_SET_REG_PASSWD;

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    ns_html_err_ul_server_down(fout, phr, 0, 0);
    goto cleanup;
  }
  r = userlist_clnt_set_passwd(ul_conn, cmd, phr->user_id, phr->contest_id,
                               p0, p1);
  if (r < 0) {
    ns_error(log_f, NEW_SRV_ERR_PWD_UPDATE_FAILED, userlist_strerror(-r));
    goto done;
  }

 done:;
  fclose(log_f); log_f = 0;
  if (!log_txt || !*log_txt) {
    url_armor_string(login_buf, sizeof(login_buf), phr->login);
    snprintf(url, sizeof(url),
             "%s?contest_id=%d&login=%s&locale_id=%d&action=%d",
             phr->self_url, phr->contest_id, login_buf, phr->locale_id,
             NEW_SRV_ACTION_LOGIN_PAGE);
    ns_refresh_page_2(fout, url);
  } else {
    html_error_status_page(fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_MAIN_PAGE, 0);
  }

 cleanup:;
  if (log_f) fclose(log_f);
  xfree(log_txt);
}

static void
unpriv_print_run(FILE *fout,
                 struct http_request_info *phr,
                 const struct contest_desc *cnts,
                 struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  char *log_txt = 0;
  size_t log_len = 0;
  FILE *log_f = 0;
  int run_id, n;
  struct run_entry re;

  if (unpriv_parse_run_id(fout, phr, cnts, extra, &run_id, &re) < 0)
    goto cleanup;

  log_f = open_memstream(&log_txt, &log_len);

  if (!cs->global->enable_printing || cs->printing_suspended) {
    ns_error(log_f, NEW_SRV_ERR_PRINTING_DISABLED);
    goto done;
  }

  if (re.status > RUN_LAST
      || (re.status > RUN_MAX_STATUS && re.status < RUN_TRANSIENT_FIRST)
      || re.user_id != phr->user_id) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto done;
  }

  if (re.pages > 0) {
    ns_error(log_f, NEW_SRV_ERR_ALREADY_PRINTED);
    goto done;
  }

  if ((n = team_print_run(cs, run_id, phr->user_id)) < 0) {
    switch (-n) {
    case SRV_ERR_PAGES_QUOTA:
      ns_error(log_f, NEW_SRV_ERR_ALREADY_PRINTED, cs->global->team_page_quota);
      goto done;
    default:
      ns_error(log_f, NEW_SRV_ERR_PRINTING_FAILED, -n, protocol_strerror(-n));
      goto done;
    }
  }

  serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                  "Command: print\n"
                  "Status: ok\n"
                  "  %d pages printed\n", n);

 done:
  fclose(log_f); log_f = 0;
  if (!log_txt || !*log_txt) {
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_MAIN_PAGE, 0);
  } else {
    html_error_status_page(fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_MAIN_PAGE, 0);
  }

 cleanup:;
  if (log_f) fclose(log_f);
  xfree(log_txt);
}

static void
unpriv_submit_run(FILE *fout,
                  struct http_request_info *phr,
                  const struct contest_desc *cnts,
                  struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = 0, *prob2;
  const struct section_language_data *lang = 0;
  char *log_txt = 0;
  size_t log_len = 0;
  FILE *log_f = 0;
  int prob_id, n, lang_id = 0, i, ans, max_ans, j;
  const unsigned char *s, *run_text = 0, *text_form_text = 0;
  size_t run_size = 0, ans_size, text_form_size = 0;
  unsigned char *ans_buf, *ans_map, *ans_tmp;
  time_t start_time, stop_time, user_deadline = 0;
  const unsigned char *login, *mime_type_str = 0;
  char **lang_list;
  int mime_type = 0;
  ruint32_t shaval[5];
  int variant = 0, run_id, arch_flags = 0;
  unsigned char *acc_probs = 0;
  struct timeval precise_time;
  path_t run_path;
  unsigned char bb[1024];
  unsigned char *tmp_run = 0;
  char *tmp_ptr = 0;
  int ans_val = 0, accept_immediately = 0;
  struct problem_plugin_iface *plg = 0;
  problem_xml_t px = 0;
  struct run_entry re;
  int skip_mime_type_test = 0;

  l10n_setlocale(phr->locale_id);
  log_f = open_memstream(&log_txt, &log_len);

  if (ns_cgi_param(phr, "prob_id", &s) <= 0
      || sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n]
      || prob_id <= 0 || prob_id > cs->max_prob
      || !(prob = cs->probs[prob_id])) {
    ns_error(log_f, NEW_SRV_ERR_INV_PROB_ID);
    goto done;
  }

  // "STANDARD" problems need programming language identifier
  if (prob->type_val == PROB_TYPE_STANDARD) {
    if (ns_cgi_param(phr, "lang_id", &s) <= 0
        || sscanf(s, "%d%n", &lang_id, &n) != 1 || s[n]
        || lang_id <= 0 || lang_id > cs->max_lang
        || !(lang = cs->langs[lang_id])) {
      ns_error(log_f, NEW_SRV_ERR_INV_LANG_ID);
      goto done;
    }
  }

  switch (prob->type_val) {
  case PROB_TYPE_STANDARD:      // "file"
    if (!ns_cgi_param_bin(phr, "file", &run_text, &run_size)) {
      ns_error(log_f, NEW_SRV_ERR_FILE_UNSPECIFIED);
      goto done;
    }
    break;
  case PROB_TYPE_OUTPUT_ONLY:
    if (prob->enable_text_form > 0) {
      int r1 = ns_cgi_param_bin(phr, "file", &run_text, &run_size);
      int r2 =ns_cgi_param_bin(phr,"text_form",&text_form_text,&text_form_size);
      if (!r1 && !r2) {
        ns_error(log_f, NEW_SRV_ERR_FILE_UNSPECIFIED);
        goto done;
      }
    } else {
      if (!ns_cgi_param_bin(phr, "file", &run_text, &run_size)) {
        ns_error(log_f, NEW_SRV_ERR_FILE_UNSPECIFIED);
        goto done;
      }
    }
    break;
  case PROB_TYPE_TEXT_ANSWER:
  case PROB_TYPE_SHORT_ANSWER:
  case PROB_TYPE_SELECT_ONE:
    if (!ns_cgi_param_bin(phr, "file", &run_text, &run_size)) {
      ns_error(log_f, NEW_SRV_ERR_ANSWER_UNSPECIFIED);
      goto done;
    }
    break;
  case PROB_TYPE_SELECT_MANY:   // "ans_*"
    for (i = 0, max_ans = -1, ans_size = 0; i < phr->param_num; i++)
      if (!strncmp(phr->param_names[i], "ans_", 4)) {
        if (sscanf(phr->param_names[i] + 4, "%d%n", &ans, &n) != 1
            || phr->param_names[i][4 + n]
            || ans < 0 || ans > 65535) {
          ns_error(log_f, NEW_SRV_ERR_INV_ANSWER);
          goto done;
        }
        if (ans > max_ans) max_ans = ans;
        ans_size += 7;
      }
    if (max_ans < 0) {
      run_text = "";
      run_size = 0;
      break;
    }
    XALLOCAZ(ans_map, max_ans + 1);
    for (i = 0; i < phr->param_num; i++)
      if (!strncmp(phr->param_names[i], "ans_", 4)) {
        sscanf(phr->param_names[i] + 4, "%d", &ans);
        ans_map[ans] = 1;
      }
    XALLOCA(ans_buf, ans_size);
    run_text = ans_buf;
    for (i = 0, run_size = 0; i <= max_ans; i++)
      if (ans_map[i]) {
        if (run_size > 0) ans_buf[run_size++] = ' ';
        run_size += sprintf(ans_buf + run_size, "%d", i);
      }
    ans_buf[run_size++] = '\n';
    ans_buf[run_size] = 0;
    break;
  case PROB_TYPE_CUSTOM:
    // invoke problem plugin
    load_problem_plugin(cs, prob_id);
    if (!(plg = cs->prob_extras[prob_id].plugin) || !plg->parse_form) {
      ns_error(log_f, NEW_SRV_ERR_PLUGIN_NOT_AVAIL);
      goto done;
    }
    ans_tmp = (*plg->parse_form)(cs->prob_extras[prob_id].plugin_data,
                                 log_f, phr, cnts, extra);
    if (!ans_tmp) goto done;
    run_size = strlen(ans_tmp);
    ans_buf = (unsigned char*) alloca(run_size + 1);
    strcpy(ans_buf, ans_tmp);
    run_text = ans_buf;
    xfree(ans_tmp);
    break;
  default:
    abort();
  }

  switch (prob->type_val) {
  case PROB_TYPE_STANDARD:
    if (!lang->binary && strlen(run_text) != run_size) {
      ns_error(log_f, NEW_SRV_ERR_BINARY_FILE);
      goto done;
    }
    if (!run_size) {
      ns_error(log_f, NEW_SRV_ERR_SUBMIT_EMPTY);
      goto done;
    }
    break;

  case PROB_TYPE_OUTPUT_ONLY:
    if (!prob->binary_input && strlen(run_text) != run_size) {
      ns_error(log_f, NEW_SRV_ERR_BINARY_FILE);
      goto done;
    }
    if (prob->enable_text_form > 0 && text_form_text
        && strlen(text_form_text) != text_form_size) {
      ns_error(log_f, NEW_SRV_ERR_BINARY_FILE);
      goto done;
    }
    if (prob->enable_text_form > 0) {
      if (!run_size && !text_form_size) {
        ns_error(log_f, NEW_SRV_ERR_SUBMIT_EMPTY);
        goto done;
      }
      if (!run_size) {
        run_text = text_form_text;
        run_size = text_form_size;
        skip_mime_type_test = 1;
      } else {
        text_form_text = 0;
        text_form_size = 0;
      }
    }
    break;

  case PROB_TYPE_TEXT_ANSWER:
  case PROB_TYPE_SHORT_ANSWER:
  case PROB_TYPE_SELECT_ONE:
    if (strlen(run_text) != run_size) {
      ns_error(log_f, NEW_SRV_ERR_BINARY_FILE);
      goto done;
    }
    if (!run_size) {
      ns_error(log_f, NEW_SRV_ERR_SUBMIT_EMPTY);
      goto done;
    }
    break;

  case PROB_TYPE_SELECT_MANY:
    if (strlen(run_text) != run_size) {
      ns_error(log_f, NEW_SRV_ERR_BINARY_FILE);
      goto done;
    }
    break;

  case PROB_TYPE_CUSTOM:
    break;
  }

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state);
  }

  if (cs->clients_suspended) {
    ns_error(log_f, NEW_SRV_ERR_CLIENTS_SUSPENDED);
    goto done;
  }
  if (!start_time) {
    ns_error(log_f, NEW_SRV_ERR_CONTEST_NOT_STARTED);
    goto done;
  }
  if (stop_time) {
    ns_error(log_f, NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
    goto done;
  }
  if (serve_check_user_quota(cs, phr->user_id, run_size) < 0) {
    ns_error(log_f, NEW_SRV_ERR_RUN_QUOTA_EXCEEDED);
    goto done;
  }
  // problem submit start time
  if (prob->t_start_date >= 0 && cs->current_time < prob->t_start_date) {
    ns_error(log_f, NEW_SRV_ERR_PROB_UNAVAILABLE);
    goto done;
  }
  // personal deadline
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
  if (user_deadline > 0 && cs->current_time >= user_deadline) {
    ns_error(log_f, NEW_SRV_ERR_PROB_DEADLINE_EXPIRED);
    goto done;
  }
  /* check for disabled languages */
  if (lang_id > 0) {
    if (lang->disabled) {
      ns_error(log_f, NEW_SRV_ERR_LANG_DISABLED);
      goto done;
    }

    if (prob->enable_language) {
      lang_list = prob->enable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], lang->short_name))
          break;
      if (!lang_list[i]) {
        ns_error(log_f, NEW_SRV_ERR_LANG_NOT_AVAIL_FOR_PROBLEM);
        goto done;
      }
    } else if (prob->disable_language) {
      lang_list = prob->disable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], lang->short_name))
          break;
      if (lang_list[i]) {
        ns_error(log_f, NEW_SRV_ERR_LANG_DISABLED_FOR_PROBLEM);
        goto done;
      }
    }
  } else if (skip_mime_type_test) {
    mime_type = 0;
    mime_type_str = mime_type_get_type(mime_type);
  } else {
    // guess the content-type and check it against the list
    if ((mime_type = mime_type_guess(cs->global->diff_work_dir,
                                     run_text, run_size)) < 0) {
      ns_error(log_f, NEW_SRV_ERR_CANNOT_DETECT_CONTENT_TYPE);
      goto done;
    }
    mime_type_str = mime_type_get_type(mime_type);
    if (prob->enable_language) {
      lang_list = prob->enable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], mime_type_str))
          break;
      if (!lang_list[i]) {
        ns_error(log_f, NEW_SRV_ERR_CONTENT_TYPE_NOT_AVAILABLE, mime_type_str);
        goto done;
      }
    } else if (prob->disable_language) {
      lang_list = prob->disable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], mime_type_str))
          break;
      if (lang_list[i]) {
        ns_error(log_f, NEW_SRV_ERR_CONTENT_TYPE_DISABLED, mime_type_str);
        goto done;
      }
    }
  }

  if (prob->variant_num > 0) {
    if ((variant = find_variant(cs, phr->user_id, prob_id, 0)) <= 0) {
      ns_error(log_f, NEW_SRV_ERR_VARIANT_UNASSIGNED);
      goto done;
    }
  }

  sha_buffer(run_text, run_size, shaval);
  if (global->ignore_duplicated_runs != 0) {
    if ((run_id = run_find_duplicate(cs->runlog_state, phr->user_id, prob_id,
                                     lang_id, variant, run_size, shaval)) >= 0){
      ns_error(log_f, NEW_SRV_ERR_DUPLICATE_SUBMIT, run_id);
      goto done;
    }
  }

  if (prob->disable_submit_after_ok
      && global->score_system_val != SCORE_OLYMPIAD && !cs->accepting_mode) {
    XALLOCAZ(acc_probs, cs->max_prob + 1);
    run_get_accepted_set(cs->runlog_state, phr->user_id,
                         cs->accepting_mode, cs->max_prob, acc_probs);
    if (acc_probs[prob_id]) {
      ns_error(log_f, NEW_SRV_ERR_PROB_ALREADY_SOLVED);
      goto done;
    }
  }

  if (prob->require) {
    if (!acc_probs) {
      XALLOCAZ(acc_probs, cs->max_prob + 1);
      run_get_accepted_set(cs->runlog_state, phr->user_id,
                           cs->accepting_mode, cs->max_prob, acc_probs);
    }
    for (i = 0; prob->require[i]; i++) {
      for (j = 1; j <= cs->max_prob; j++)
        if (cs->probs[j] && !strcmp(cs->probs[j]->short_name, prob->require[i]))
          break;
      if (j > cs->max_prob || !acc_probs[j]) break;
    }
    if (prob->require[i]) {
      ns_error(log_f, NEW_SRV_ERR_NOT_ALL_REQ_SOLVED);
      goto done;
    }
  }

  if (prob->type_val == PROB_TYPE_SELECT_ONE) {
    // check that answer is valid
    tmp_run = (unsigned char*) alloca(run_size + 1);
    memcpy(tmp_run, run_text, run_size);
    tmp_run[run_size] = 0;
    while (run_size > 0 && isspace(tmp_run[run_size - 1])) run_size--;
    tmp_run[run_size] = 0;
    errno = 0;
    ans_val = strtol(tmp_run, &tmp_ptr, 10);
    if (errno || *tmp_ptr || tmp_run + run_size != (unsigned char*) tmp_ptr
        || ans_val < 0) {
      ns_error(log_f, NEW_SRV_ERR_INV_ANSWER);
      goto done;
    }

    // add this run and if we're in olympiad accepting mode mark
    // as accepted
    if (global->score_system_val == SCORE_OLYMPIAD && cs->accepting_mode)
      accept_immediately = 1;
  }

  // OK, so all checks are done, now we add this submit to the database
  gettimeofday(&precise_time, 0);

  run_id = run_add_record(cs->runlog_state, 
                          precise_time.tv_sec, precise_time.tv_usec * 1000,
                          run_size, shaval,
                          phr->ip, phr->ssl_flag,
                          phr->locale_id, phr->user_id,
                          prob_id, lang_id, 0, 0, mime_type);
  if (run_id < 0) {
    ns_error(log_f, NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
    goto done;
  }
  serve_move_files_to_insert_run(cs, run_id);
                          
  arch_flags = archive_make_write_path(cs, run_path, sizeof(run_path),
                                       global->run_archive_dir, run_id,
                                       run_size, 0);
  if (arch_flags < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto done;
  }
  if (archive_dir_prepare(cs, global->run_archive_dir, run_id, 0, 0) < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto done;
  }
  if (generic_write_file(run_text, run_size, arch_flags, 0, run_path, "") < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto done;
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
                                lang->compiler_env, -1, 0, prob, lang) < 0) {
        ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
        goto done;
      }
      serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                      "Command: submit\n"
                      "Status: ok\n"
                      "Run-id: %d\n", run_id);
    }
  } else if (prob->manual_checking > 0 && !accept_immediately) {
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
      if (serve_run_request(cs, log_f, run_text, run_size, run_id,
                            phr->user_id, prob_id, 0, variant, 0, -1, -1,
                            0, 0) < 0) {
        ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
        goto done;
      }

      serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                      "Command: submit\n"
                      "Status: ok\n"
                      "Run-id: %d\n", run_id);
    }
  } else {
    if (accept_immediately) {
      run_change_status(cs->runlog_state, run_id, RUN_ACCEPTED, 0, -1, 0);
      serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                      "Command: submit\n"
                      "Status: accepted\n"
                      "Run-id: %d\n", run_id);
    } else if (prob->disable_auto_testing > 0
        || (prob->disable_testing > 0 && prob->enable_compilation <= 0)) {
      run_change_status(cs->runlog_state, run_id, RUN_PENDING, 0, -1, 0);
      serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                      "Command: submit\n"
                      "Status: pending\n"
                      "Run-id: %d\n"
                      "  Testing disabled for this problem\n",
                      run_id);
    } else {
      if (prob->variant_num > 0 && prob->xml.a) {
        px = prob->xml.a[variant -  1];
      } else {
        px = prob->xml.p;
      }
      if (px && px->ans_num > 0) {
        run_get_entry(cs->runlog_state, run_id, &re);
        serve_judge_built_in_problem(cs, cnts, run_id, 1 /* judge_id */,
                                     variant, cs->accepting_mode, &re,
                                     prob, px, phr->user_id, phr->ip,
                                     phr->ssl_flag);
        goto done;
      }

      if (serve_run_request(cs, log_f, run_text, run_size, run_id,
                            phr->user_id, prob_id, 0, variant, 0, -1, -1,
                            0, 0) < 0) {
        ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
        goto done;
      }

      serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                      "Command: submit\n"
                      "Status: ok\n"
                      "Run-id: %d\n", run_id);
    }
  }

 done:;
  l10n_setlocale(0);
  fclose(log_f); log_f = 0;
  if (!log_txt || !*log_txt) {
    i = 0;
    if (global->problem_navigation) {
      i = prob->id;
      if (prob->advance_to_next > 0) {
        for (i++; i <= cs->max_prob; i++) {
          if (!(prob2 = cs->probs[i])) continue;
          if (prob2->t_start_date > 0 && prob2->t_start_date > cs->current_time)
            continue;
          // FIXME: standard applicability checks
          break;
        }
        if (i > cs->max_prob) i = 0;
      }
    }
    if (i > 0) {
      snprintf(bb, sizeof(bb), "prob_id=%d", i);
      ns_refresh_page(fout, phr, NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT, bb);
    }  else {
      ns_refresh_page(fout, phr, NEW_SRV_ACTION_VIEW_SUBMISSIONS, 0);
    }
  } else {
    unpriv_load_html_style(phr, cnts, 0, 0);
    html_error_status_page(fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT,
                           "prob_id=%d", prob_id);
  }

  //cleanup:;
  if (log_f) fclose(log_f);
  xfree(log_txt);
}

static void
unpriv_submit_clar(FILE *fout,
                   struct http_request_info *phr,
                   const struct contest_desc *cnts,
                   struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = 0;
  const unsigned char *s, *subject = 0, *text = 0;
  int prob_id = 0, n;
  time_t start_time, stop_time;
  FILE *log_f = 0;
  char *log_txt = 0;
  size_t log_len = 0;
  size_t subj_len, text_len, subj3_len, text3_len;
  unsigned char *subj2, *text2, *subj3, *text3;
  struct timeval precise_time;
  int clar_id;
  unsigned char clar_file[32];

  // parameters: prob_id, subject, text,  

  if ((n = ns_cgi_param(phr, "prob_id", &s)) < 0)
    return ns_html_err_inv_param(fout, phr, 0, "prob_id is binary");
  if (n > 0 && *s) {
    if (sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n])
      return ns_html_err_inv_param(fout, phr, 0, "cannot parse prob_id");
    if (prob_id <= 0 || prob_id > cs->max_prob || !(prob = cs->probs[prob_id]))
      return ns_html_err_inv_param(fout, phr, 0, "prob_id is invalid");
  }
  if (ns_cgi_param(phr, "subject", &subject) < 0)
    return ns_html_err_inv_param(fout, phr, 0, "subject is binary");
  if (ns_cgi_param(phr, "text", &text) <= 0)
    return ns_html_err_inv_param(fout, phr, 0,
                                 "text is not set or binary");

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state);
  }

  log_f = open_memstream(&log_txt, &log_len);

  if (cs->clients_suspended) {
    ns_error(log_f, NEW_SRV_ERR_CLIENTS_SUSPENDED);
    goto done;
  }
  if (global->disable_team_clars) {
    ns_error(log_f, NEW_SRV_ERR_CLARS_DISABLED);
    goto done;
  }
  if (!start_time) {
    ns_error(log_f, NEW_SRV_ERR_CONTEST_NOT_STARTED);
    goto done;
  }
  if (stop_time) {
    ns_error(log_f, NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
    goto done;
  }

  if (!subject) subject = "";
  subj_len = strlen(subject);
  if (subj_len > 128 * 1024 * 1024) {
    ns_error(log_f, NEW_SRV_ERR_SUBJECT_TOO_LONG, subj_len);
    goto done;
  }
  subj2 = alloca(subj_len + 1);
  strcpy(subj2, subject);
  while (subj_len > 0 && isspace(subj2[subj_len - 1])) subj2[--subj_len] = 0;
  if (!subj_len) {
    subj2 = "(no subject)";
    subj_len = strlen(subj2);
  }

  if (!text) text = "";
  text_len = strlen(text);
  if (text_len > 128 * 1024 * 1024) {
    ns_error(log_f, NEW_SRV_ERR_MESSAGE_TOO_LONG, text_len);
    goto done;
  }
  text2 = alloca(text_len + 1);
  strcpy(text2, text);
  while (text_len > 0 && isspace(text2[text_len - 1])) text2[--text_len] = 0;
  if (!text_len) {
    ns_error(log_f, NEW_SRV_ERR_MESSAGE_EMPTY);
    goto done;
  }

  if (prob) {
    subj3 = alloca(strlen(prob->short_name) + subj_len + 10);
    subj3_len = sprintf(subj3, "%s: %s", prob->short_name, subj2);
  } else {
    subj3 = subj2;
    subj3_len = subj_len;
  }

  text3 = alloca(subj3_len + text_len + 32);
  text3_len = sprintf(text3, "Subject: %s\n\n%s\n", subj3, text2);

  if (serve_check_clar_quota(cs, phr->user_id, text3_len) < 0) {
    ns_error(log_f, NEW_SRV_ERR_CLAR_QUOTA_EXCEEDED);
    goto done;
  }

  gettimeofday(&precise_time, 0);
  if ((clar_id = clar_add_record_new(cs->clarlog_state,
                                     precise_time.tv_sec,
                                     precise_time.tv_usec * 1000,
                                     text3_len,
                                     phr->ip, phr->ssl_flag,
                                     phr->user_id, 0, 0, 0, 0,
                                     phr->locale_id, 0, 0,
                                     utf8_mode, subj3)) < 0) {
    ns_error(log_f, NEW_SRV_ERR_CLARLOG_UPDATE_FAILED);
    goto done;
  }

  sprintf(clar_file, "%06d", clar_id);
  if (generic_write_file(text3, text3_len, 0,
                         global->clar_archive_dir, clar_file, "") < 0) {
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto done;
  }

  serve_send_clar_notify_email(cs, cnts, phr->user_id, phr->name, subj3, text2);

 done:;
  fclose(log_f); log_f = 0;
  if (!log_txt || !*log_txt) {
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_VIEW_CLARS, 0);
  } else {
    html_error_status_page(fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_VIEW_CLAR_SUBMIT, 0);
  }

  //cleanup:;
  if (log_f) fclose(log_f);
  xfree(log_txt);
}

static void
unpriv_submit_appeal(FILE *fout,
                     struct http_request_info *phr,
                     const struct contest_desc *cnts,
                     struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = 0;
  const unsigned char *s, *text = 0;
  int prob_id = 0, n;
  time_t start_time, stop_time;
  FILE *log_f = 0;
  char *log_txt = 0;
  size_t log_len = 0;
  size_t text_len, subj3_len, text3_len;
  unsigned char *text2, *subj3, *text3;
  struct timeval precise_time;
  int clar_id, test;
  unsigned char clar_file[32];

  // parameters: prob_id, subject, text,  

  if ((n = ns_cgi_param(phr, "prob_id", &s)) < 0)
    return ns_html_err_inv_param(fout, phr, 0, "prob_id is binary");
  if (n > 0 && *s) {
    if (sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n])
      return ns_html_err_inv_param(fout, phr, 0, "cannot parse prob_id");
    if (prob_id <= 0 || prob_id > cs->max_prob || !(prob = cs->probs[prob_id]))
      return ns_html_err_inv_param(fout, phr, 0, "prob_id is invalid");
  }
  if ((n = ns_cgi_param(phr, "test", &s)) < 0)
    return ns_html_err_inv_param(fout, phr, 0, "test is binary");
  if (ns_cgi_param(phr, "text", &text) <= 0)
    return ns_html_err_inv_param(fout, phr, 0,
                                 "text is not set or binary");

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state);
  }

  log_f = open_memstream(&log_txt, &log_len);

  if (cs->clients_suspended) {
    ns_error(log_f, NEW_SRV_ERR_CLIENTS_SUSPENDED);
    goto done;
  }
  if (global->disable_team_clars) {
    ns_error(log_f, NEW_SRV_ERR_CLARS_DISABLED);
    goto done;
  }
  if (!start_time) {
    ns_error(log_f, NEW_SRV_ERR_CONTEST_NOT_STARTED);
    goto done;
  }
  if (!stop_time) {
    ns_error(log_f, NEW_SRV_ERR_CONTEST_NOT_FINISHED);
    goto done;
  }
  if (global->appeal_deadline_d <= 0) {
    ns_error(log_f, NEW_SRV_ERR_APPEALS_DISABLED);
    goto done;
  }
  if (cs->current_time >= global->appeal_deadline_d) {
    ns_error(log_f, NEW_SRV_ERR_APPEALS_FINISHED);
    goto done;
  }
  if (ns_cgi_param(phr, "test", &s) <= 0
      || sscanf(s, "%d%n", &test, &n) != 1 || s[n]
      || test <= 0 || test > 100000) {
    ns_error(log_f, NEW_SRV_ERR_INV_TEST);
    goto done;
  }
  if (!prob) {
    ns_error(log_f, NEW_SRV_ERR_INV_PROB_ID);
    goto done;
  }

  if (!text) text = "";
  text_len = strlen(text);
  if (text_len > 128 * 1024 * 1024) {
    ns_error(log_f, NEW_SRV_ERR_MESSAGE_TOO_LONG, text_len);
    goto done;
  }
  text2 = alloca(text_len + 1);
  strcpy(text2, text);
  while (text_len > 0 && isspace(text2[text_len - 1])) text2[--text_len] = 0;
  if (!text_len) {
    ns_error(log_f, NEW_SRV_ERR_MESSAGE_EMPTY);
    goto done;
  }

  subj3 = alloca(strlen(prob->short_name) + 128);
  subj3_len = sprintf(subj3, "Appeal: %s, %d", prob->short_name, test);

  text3 = alloca(subj3_len + text_len + 32);
  text3_len = sprintf(text3, "Subject: %s\n\n%s\n", subj3, text2);

  if (serve_check_clar_quota(cs, phr->user_id, text3_len) < 0) {
    ns_error(log_f, NEW_SRV_ERR_CLAR_QUOTA_EXCEEDED);
    goto done;
  }

  gettimeofday(&precise_time, 0);
  if ((clar_id = clar_add_record_new(cs->clarlog_state,
                                     precise_time.tv_sec,
                                     precise_time.tv_usec * 1000,
                                     text3_len,
                                     phr->ip, phr->ssl_flag,
                                     phr->user_id, 0, 0, 0, 0,
                                     phr->locale_id, 0, 1,
                                     utf8_mode, subj3)) < 0) {
    ns_error(log_f, NEW_SRV_ERR_CLARLOG_UPDATE_FAILED);
    goto done;
  }

  sprintf(clar_file, "%06d", clar_id);
  if (generic_write_file(text3, text3_len, 0,
                         global->clar_archive_dir, clar_file, "") < 0) {
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto done;
  }

  serve_send_clar_notify_email(cs, cnts, phr->user_id, phr->name, subj3, text2);

 done:;
  fclose(log_f); log_f = 0;
  if (!log_txt || !*log_txt) {
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_VIEW_CLARS, 0);
  } else {
    html_error_status_page(fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_VIEW_CLAR_SUBMIT, 0);
  }

  //cleanup:;
  if (log_f) fclose(log_f);
  xfree(log_txt);
}

static void
virtual_stop_callback(
        const struct contest_desc *cnts,
        struct serve_state *cs,
        struct serve_event_queue *p)
{
  const struct section_global_data *global = cs->global;

  char *tmps = 0;
  size_t tmpz = 0;
  FILE *tmpf = 0;
  int locale_id = 0;

  if (global->enable_auto_print_protocol <= 0) return;

  // Note, that all printing errors are ignored... 
  if (cnts->default_locale_val > 0) locale_id = cnts->default_locale_val;
  if (locale_id > 0) l10n_setlocale(locale_id);
  tmpf = open_memstream(&tmps, &tmpz);
  ns_print_user_exam_protocol(cnts, cs, tmpf, p->user_id, locale_id, 1, 0, 0);
  fclose(tmpf); tmpf = 0;
  xfree(tmps); tmps = 0; tmpz = 0;
  if (locale_id > 0) l10n_setlocale(0);
}

static void
unpriv_command(FILE *fout,
               struct http_request_info *phr,
               const struct contest_desc *cnts,
               struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob;
  char *log_txt = 0;
  size_t log_size = 0;
  FILE *log_f = 0;
  time_t start_time, stop_time;
  struct timeval precise_time;
  int run_id, i;
  unsigned char bb[1024];

  l10n_setlocale(phr->locale_id);
  log_f = open_memstream(&log_txt, &log_size);

  switch (phr->action) {
  case NEW_SRV_ACTION_VIRTUAL_START:
  case NEW_SRV_ACTION_VIRTUAL_STOP:
    if (global->is_virtual <= 0) {
      ns_error(log_f, NEW_SRV_ERR_NOT_VIRTUAL);
      goto done;
    }
    if (run_get_start_time(cs->runlog_state) <= 0) {
      ns_error(log_f, NEW_SRV_ERR_VIRTUAL_NOT_STARTED);
      goto done;
    }
    break;
  default:
    ns_error(log_f, NEW_SRV_ERR_UNHANDLED_ACTION, phr->action);
    goto done;
  }

  switch (phr->action) {
  case NEW_SRV_ACTION_VIRTUAL_START:
    if (global->disable_virtual_start) {
      ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
      goto done;
    }
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    if (start_time > 0) {
      ns_error(log_f, NEW_SRV_ERR_CONTEST_ALREADY_STARTED);
      goto done;
    }
    gettimeofday(&precise_time, 0);
    run_id = run_virtual_start(cs->runlog_state, phr->user_id,
                               precise_time.tv_sec, phr->ip, phr->ssl_flag,
                               precise_time.tv_usec * 1000);
    if (run_id < 0) {
      ns_error(log_f, NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
      goto done;
    }
    serve_move_files_to_insert_run(cs, run_id);
    serve_event_add(cs,
                    precise_time.tv_sec + run_get_duration(cs->runlog_state),
                    SERVE_EVENT_VIRTUAL_STOP, phr->user_id,
                    virtual_stop_callback);
    break;
  case NEW_SRV_ACTION_VIRTUAL_STOP:
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    if (start_time <= 0) {
      ns_error(log_f, NEW_SRV_ERR_CONTEST_NOT_STARTED);
      goto done;
    }
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
    if (stop_time > 0) {
      ns_error(log_f, NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
      goto done;
    }
    gettimeofday(&precise_time, 0);
    run_id = run_virtual_stop(cs->runlog_state, phr->user_id,
                              precise_time.tv_sec, phr->ip, phr->ssl_flag,
                              precise_time.tv_usec * 1000);
    if (run_id < 0) {
      ns_error(log_f, NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
      goto done;
    }
    serve_move_files_to_insert_run(cs, run_id);
    if (global->score_system_val == SCORE_OLYMPIAD && global->is_virtual > 0) {
      serve_event_remove_matching(cs, 0, 0, phr->user_id);
      if (global->disable_virtual_auto_judge <= 0) {
        serve_event_add(cs, precise_time.tv_sec + 1,
                        SERVE_EVENT_JUDGE_OLYMPIAD, phr->user_id, 0);
      }
    }

    if (global->enable_auto_print_protocol > 0) {
      char *tmps = 0;
      size_t tmpz = 0;
      FILE *tmpf = 0;
      int locale_id = 0;

      /* Note, that all printing errors are ignored... */
      if (cnts->default_locale_val > 0) locale_id = cnts->default_locale_val;
      if (locale_id > 0) l10n_setlocale(locale_id);
      tmpf = open_memstream(&tmps, &tmpz);
      ns_print_user_exam_protocol(cnts, cs, tmpf, phr->user_id, locale_id, 1,
                                  0, 0);
      fclose(tmpf); tmpf = 0;
      xfree(tmps); tmps = 0; tmpz = 0;
      if (locale_id > 0) l10n_setlocale(0);
    }

    break;
  }

 done:;
  l10n_setlocale(0);
  fclose(log_f); log_f = 0;
  if (!log_txt || !*log_txt) {
    i = 0;
    if (phr->action == NEW_SRV_ACTION_VIRTUAL_START
        && global->problem_navigation) {
      for (i = 1; i <= cs->max_prob; i++) {
        if (!(prob = cs->probs[i])) continue;
        if (prob->t_start_date > 0 && prob->t_start_date > cs->current_time)
          continue;
        // FIXME: standard applicability checks
        break;
      }
      if (i > cs->max_prob) i = 0;
    }
    if (i > 0) {
      snprintf(bb, sizeof(bb), "prob_id=%d", i);
      ns_refresh_page(fout, phr, NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT, bb);
    } else if (phr->action == NEW_SRV_ACTION_VIRTUAL_STOP) {
      ns_refresh_page(fout, phr, NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY, 0);
    } else {
      ns_refresh_page(fout, phr, NEW_SRV_ACTION_MAIN_PAGE, 0);
    }
  } else {
    unpriv_load_html_style(phr, cnts, 0, 0);
    html_error_status_page(fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_MAIN_PAGE, 0);
  }

  //cleanup:;
  if (log_f) fclose(log_f);
  xfree(log_txt);
}

static void
unpriv_view_source(FILE *fout,
                   struct http_request_info *phr,
                   const struct contest_desc *cnts,
                   struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  int run_id, src_flags;
  char *log_txt = 0;
  size_t log_len = 0;
  FILE *log_f = 0;
  struct run_entry re;
  const struct section_language_data *lang = 0;
  const struct section_problem_data *prob = 0;
  char *run_text = 0;
  size_t run_size = 0;
  path_t src_path;

  if (unpriv_parse_run_id(fout, phr, cnts, extra, &run_id, &re) < 0)
    goto cleanup;

  log_f = open_memstream(&log_txt, &log_len);

  if (cs->clients_suspended) {
    ns_error(log_f, NEW_SRV_ERR_CLIENTS_SUSPENDED);
    goto done;
  }
  if (!global->team_enable_src_view) {
    ns_error(log_f, NEW_SRV_ERR_SOURCE_VIEW_DISABLED);
    goto done;
  }
  if (re.user_id != phr->user_id) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto done;
  }
  if (re.prob_id <= 0 || re.prob_id > cs->max_prob ||
      !(prob = cs->probs[re.prob_id])) {
    ns_error(log_f, NEW_SRV_ERR_INV_PROB_ID);
    goto done;
  }
  if (re.status > RUN_LAST
      || (re.status > RUN_MAX_STATUS && re.status < RUN_TRANSIENT_FIRST)) {
    ns_error(log_f, NEW_SRV_ERR_SOURCE_UNAVAILABLE);
    goto done;
  }

  if ((src_flags = archive_make_read_path(cs, src_path, sizeof(src_path),
                                          global->run_archive_dir,
                                          run_id, 0, 1)) < 0) {
    ns_error(log_f, NEW_SRV_ERR_SOURCE_NONEXISTANT);
    goto done;
  }
  if (generic_read_file(&run_text, 0, &run_size, src_flags, 0, src_path, 0)<0) {
    ns_error(log_f, NEW_SRV_ERR_DISK_READ_ERROR);
    goto done;
  }

  if (prob->type_val > 0) {
    fprintf(fout, "Content-type: %s\n", mime_type_get_type(re.mime_type));
    /*
    fprintf(fout, "Content-Disposition: attachment; filename=\"%06d%s\"\n",
            run_id, mime_type_get_suffix(re.mime_type));
    */
    putc_unlocked('\n', fout);
  } else {
    if(re.lang_id <= 0 || re.lang_id > cs->max_lang ||
       !(lang = cs->langs[re.lang_id])) {
      ns_error(log_f, NEW_SRV_ERR_INV_LANG_ID);
      goto done;
    }

    if (lang->content_type) {
      fprintf(fout, "Content-type: %s\n", lang->content_type);
      fprintf(fout, "Content-Disposition: attachment; filename=\"%06d%s\"\n\n",
              run_id, lang->src_sfx);
    } else if (lang->binary) {
      fprintf(fout, "Content-type: application/octet-stream\n\n");
      fprintf(fout, "Content-Disposition: attachment; filename=\"%06d%s\"\n\n",
              run_id, lang->src_sfx);
    } else {
      fprintf(fout, "Content-type: text/plain\n");
    }
  }
  fwrite(run_text, 1, run_size, fout);

 done:;
  fclose(log_f); log_f = 0;
  if (log_txt && *log_txt) {
    html_error_status_page(fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_MAIN_PAGE, 0);
  }

 cleanup:
  if (log_f) fclose(log_f);
  xfree(log_txt);
  xfree(run_text);
}

static void
unpriv_view_test(FILE *fout,
                 struct http_request_info *phr,
                 const struct contest_desc *cnts,
                 struct contest_extra *extra)
{


  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  int run_id, test_num, n;
  const unsigned char *s = 0;
  struct run_entry re;
  FILE *log_f = 0;
  char *log_txt = 0;
  size_t log_len = 0;

  // run_id, test_num
  if (unpriv_parse_run_id(fout, phr, cnts, extra, &run_id, &re) < 0)
    goto cleanup;
  if (ns_cgi_param(phr, "test_num", &s) <= 0
      || sscanf(s, "%d%n", &test_num, &n) != 1 || s[n] || test_num <= 0) {
    ns_html_err_inv_param(fout, phr, 0, "cannot parse test_num");
    goto cleanup;
  }

  log_f = open_memstream(&log_txt, &log_len);

  if (cs->clients_suspended) {
    ns_error(log_f, NEW_SRV_ERR_CLIENTS_SUSPENDED);
    goto done;
  }
  if (global->team_enable_rep_view <= 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto done;
  }
  if (global->team_show_judge_report <= 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto done;
  }
  if (re.user_id != phr->user_id) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto done;
  }
  switch (re.status) {
  case RUN_OK:
  case RUN_RUN_TIME_ERR:
  case RUN_TIME_LIMIT_ERR:
  case RUN_PRESENTATION_ERR:
  case RUN_WRONG_ANSWER_ERR:
  case RUN_PARTIAL:
  case RUN_ACCEPTED:
  case RUN_MEM_LIMIT_ERR:
  case RUN_SECURITY_ERR:
    break;
  default:
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto done;
  }    

  ns_write_tests(cs, fout, log_f, phr->action, run_id, test_num);

 done:;
  fclose(log_f); log_f = 0;
  if (log_txt && *log_txt) {
    html_error_status_page(fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_MAIN_PAGE, 0);
  }

 cleanup:
  if (log_f) fclose(log_f);
  xfree(log_txt);
}

static void
unpriv_view_report(FILE *fout,
                   struct http_request_info *phr,
                   const struct contest_desc *cnts,
                   struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob;
  int run_id, flags, content_type;
  const unsigned char *rep_start = 0, *arch_dir;
  FILE *log_f = 0;
  char *log_txt = 0, *rep_text = 0;
  size_t log_len = 0, rep_size = 0, html_len;
  struct run_entry re;
  path_t rep_path;
  unsigned char *html_report;
  time_t start_time, stop_time;
  int accepting_mode = 0;

  static const int new_actions_vector[] =
  {
    NEW_SRV_ACTION_VIEW_TEST_INPUT,
    NEW_SRV_ACTION_VIEW_TEST_OUTPUT,
    NEW_SRV_ACTION_VIEW_TEST_ANSWER,
    NEW_SRV_ACTION_VIEW_TEST_ERROR,
    NEW_SRV_ACTION_VIEW_TEST_CHECKER,
    NEW_SRV_ACTION_VIEW_TEST_INFO,
  };

  start_time = run_get_start_time(cs->runlog_state);
  stop_time = run_get_stop_time(cs->runlog_state);
  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
    if (global->score_system_val == SCORE_OLYMPIAD) {
      if (global->disable_virtual_auto_judge <= 0 && stop_time <= 0)
        accepting_mode = 1;
      else if (global->disable_virtual_auto_judge > 0
               && cs->testing_finished <= 0)
        accepting_mode = 1;
    }
  } else {
    accepting_mode = cs->accepting_mode;
  }

  if (unpriv_parse_run_id(fout, phr, cnts, extra, &run_id, &re) < 0)
    goto cleanup;

  log_f = open_memstream(&log_txt, &log_len);

  if (cs->clients_suspended) {
    ns_error(log_f, NEW_SRV_ERR_CLIENTS_SUSPENDED);
    goto done;
  }

  if (re.user_id != phr->user_id) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto done;
  }
  if (re.prob_id <= 0 || re.prob_id > cs->max_prob ||
      !(prob = cs->probs[re.prob_id])) {
    ns_error(log_f, NEW_SRV_ERR_INV_PROB_ID);
    goto done;
  }
  // check viewable statuses
  switch (re.status) {
  case RUN_OK:
  case RUN_COMPILE_ERR:
  case RUN_RUN_TIME_ERR:
  case RUN_TIME_LIMIT_ERR:
  case RUN_PRESENTATION_ERR:
  case RUN_WRONG_ANSWER_ERR:
  case RUN_PARTIAL:
  case RUN_ACCEPTED:
  case RUN_MEM_LIMIT_ERR:
  case RUN_SECURITY_ERR:
    // these statuses have viewable reports
    break;
  default:
    ns_error(log_f, NEW_SRV_ERR_REPORT_UNAVAILABLE);
    goto done;
  }

  if (accepting_mode && prob->type_val != PROB_TYPE_STANDARD) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto done;
  }

  if (!prob->team_enable_rep_view
      && (!prob->team_enable_ce_view || re.status != RUN_COMPILE_ERR)) {
    ns_error(log_f, NEW_SRV_ERR_REPORT_VIEW_DISABLED);
    goto done;
  }

  flags = archive_make_read_path(cs, rep_path, sizeof(rep_path),
                                 global->xml_report_archive_dir, run_id, 0, 1);
  if (flags >= 0) {
    if (generic_read_file(&rep_text, 0, &rep_size, flags, 0, rep_path, 0) < 0) {
      ns_error(log_f, NEW_SRV_ERR_DISK_READ_ERROR);
      goto done;
    }
    content_type = get_content_type(rep_text, &rep_start);
    if (content_type != CONTENT_TYPE_XML && re.status != RUN_COMPILE_ERR) {
      ns_error(log_f, NEW_SRV_ERR_REPORT_UNAVAILABLE);
      goto done;
    }
  } else {
    if (prob->team_enable_ce_view && re.status == RUN_COMPILE_ERR)
      arch_dir = global->report_archive_dir;
    else if (prob->team_show_judge_report)
      arch_dir = global->report_archive_dir;
    else
      arch_dir = global->team_report_archive_dir;

    if ((flags = archive_make_read_path(cs, rep_path, sizeof(rep_path),
                                        arch_dir, run_id, 0, 1)) < 0) {
      ns_error(log_f, NEW_SRV_ERR_REPORT_NONEXISTANT);
      goto done;
    }
    if (generic_read_file(&rep_text,0,&rep_size,flags,0,rep_path, 0) < 0) {
      ns_error(log_f, NEW_SRV_ERR_DISK_READ_ERROR);
      goto done;
    }
    content_type = get_content_type(rep_text, &rep_start);
  }

  unpriv_load_html_style(phr, cnts, 0, 0);
  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, phr->script_part, phr->body_attr,
            phr->locale_id,
            "%s [%s]: %s %d",
            phr->name_arm, extra->contest_arm, _("Report for run"),
            run_id);
  unpriv_page_header(fout, phr, cnts, extra, start_time, stop_time);

  switch (content_type) {
  case CONTENT_TYPE_TEXT:
    html_len = html_armored_memlen(rep_text, rep_size);
    if (html_len > 2 * 1024 * 1024) {
      html_report = xmalloc(html_len + 16);
      html_armor_text(rep_text, rep_size, html_report);
      html_report[html_len] = 0;
      fprintf(fout, "<pre>%s</pre>", html_report);
      xfree(html_report);
    } else {
      html_report = alloca(html_len + 16);
      html_armor_text(rep_text, rep_size, html_report);
      html_report[html_len] = 0;
      fprintf(fout, "<pre>%s</pre>", html_report);
    }
    break;
  case CONTENT_TYPE_HTML:
    fprintf(fout, "%s", rep_start);
    break;
  case CONTENT_TYPE_XML:
    if (global->score_system_val == SCORE_OLYMPIAD && accepting_mode) {
      write_xml_team_accepting_report(fout, rep_start, run_id, &re, prob,
                                      new_actions_vector,
                                      phr->session_id, cnts->exam_mode,
                                      phr->self_url, "", "b1");
    } else if (prob->team_show_judge_report) {
      write_xml_testing_report(fout, rep_start, phr->session_id,
                               phr->self_url, "", new_actions_vector,"b1","b0");
    } else {
      write_xml_team_testing_report(cs, fout,
                                    prob->type_val != PROB_TYPE_STANDARD,
                                    rep_start, "b1");
    }
    break;
  default:
    abort();
  }

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 done:;
  fclose(log_f); log_f = 0;
  if (log_txt && *log_txt) {
    html_error_status_page(fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_MAIN_PAGE, 0);
  }

 cleanup:
  if (log_f) fclose(log_f);
  xfree(log_txt);
  xfree(rep_text);
}

static void
unpriv_view_clar(FILE *fout,
                 struct http_request_info *phr,
                 const struct contest_desc *cnts,
                 struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  int n, clar_id, show_astr_time;
  const unsigned char *s;
  FILE *log_f = 0;
  char *log_txt = 0;
  size_t log_len = 0, clar_size = 0, html_subj_len, html_text_len;
  struct clar_entry_v1 ce;
  time_t start_time, clar_time, stop_time;
  unsigned char clar_file_name[128];
  char *clar_text = 0;
  unsigned char *html_subj, *html_text;
  unsigned char dur_str[64];

  if ((n = ns_cgi_param(phr, "clar_id", &s)) <= 0)
    return ns_html_err_inv_param(fout, phr, 0, "clar_id is binary or not set");
  if (sscanf(s, "%d%n", &clar_id, &n) != 1 || s[n])
    return ns_html_err_inv_param(fout, phr, 0, "cannot parse clar_id");

  log_f = open_memstream(&log_txt, &log_len);

  if (cs->clients_suspended) {
    ns_error(log_f, NEW_SRV_ERR_CLIENTS_SUSPENDED);
    goto done;
  }
  if (global->disable_clars) {
    ns_error(log_f, NEW_SRV_ERR_CLARS_DISABLED);
    goto done;
  }
  if (clar_id < 0 || clar_id >= clar_get_total(cs->clarlog_state)
      || clar_get_record_new(cs->clarlog_state, clar_id, &ce) < 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_CLAR_ID);
    goto done;
  }

  show_astr_time = global->show_astr_time;
  if (global->is_virtual) show_astr_time = 1;
  start_time = run_get_start_time(cs->runlog_state);
  stop_time = run_get_stop_time(cs->runlog_state);
  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
  }

  if ((ce.from > 0 && ce.from != phr->user_id)
      || (ce.to > 0 && ce.to != phr->user_id)
      || (start_time <= 0 && ce.hide_flag)) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto done;
  }

  if (ce.from != phr->user_id) {
    team_extra_set_clar_status(cs->team_extra_state, phr->user_id, clar_id);
  }

  sprintf(clar_file_name, "%06d", clar_id);
  if (generic_read_file(&clar_text, 0, &clar_size, 0,
                        global->clar_archive_dir, clar_file_name, "") < 0) {
    ns_error(log_f, NEW_SRV_ERR_DISK_READ_ERROR);
    goto done;
  }

  html_subj_len = html_armored_strlen(ce.subj);
  html_subj = alloca(html_subj_len + 1);
  html_armor_string(ce.subj, html_subj);
  html_text_len = html_armored_strlen(clar_text);
  html_text = alloca(html_text_len + 1);
  html_armor_string(clar_text, html_text);

  clar_time = ce.time;
  if (start_time < 0) start_time = 0;
  if (!start_time) clar_time = start_time;
  if (clar_time < start_time) clar_time = start_time;
  duration_str(show_astr_time, clar_time, start_time, dur_str, 0);

  unpriv_load_html_style(phr, cnts, 0, 0);
  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, phr->script_part, phr->body_attr,
            phr->locale_id,
            "%s [%s]: %s %d",
            phr->name_arm, extra->contest_arm, _("Clarification"),
            clar_id);
  unpriv_page_header(fout, phr, cnts, extra, start_time, stop_time);

  fprintf(fout, "<%s>%s #%d</%s>\n", cnts->team_head_style,
          _("Message"), clar_id, cnts->team_head_style);
  fprintf(fout, "<table class=\"b0\">\n");
  fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">%d</td></tr>\n", _("Number"), clar_id);
  fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">%s</td></tr>\n", _("Time"), dur_str);
  fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">%u</td></tr>\n", _("Size"), ce.size);
  fprintf(fout, "<tr><td class=\"b0\">%s:</td>", _("Sender"));
  if (!ce.from) {
    fprintf(fout, "<td class=\"b0\"><b>%s</b></td>", _("judges"));
  } else {
    fprintf(fout, "<td class=\"b0\">%s</td>", teamdb_get_name(cs->teamdb_state, ce.from));
  }
  fprintf(fout, "</tr>\n<tr><td class=\"b0\">%s:</td>", _("To"));
  if (!ce.to && !ce.from) {
    fprintf(fout, "<td class=\"b0\"><b>%s</b></td>", _("all"));
  } else if (!ce.to) {
    fprintf(fout, "<td class=\"b0\"><b>%s</b></td>", _("judges"));
  } else {
    fprintf(fout, "<td class=\"b0\">%s</td>", teamdb_get_name(cs->teamdb_state, ce.to));
  }
  fprintf(fout, "</tr>\n");
  fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">%s</td></tr>", _("Subject"), html_subj);
  fprintf(fout, "</table>\n");
  fprintf(fout, "<hr><pre>");
  fprintf(fout, "%s", html_text);
  fprintf(fout, "</pre><hr>");

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);

 done:;
  fclose(log_f); log_f = 0;
  if (log_txt && *log_txt) {
    html_error_status_page(fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_MAIN_PAGE, 0);
  }

  if (log_f) fclose(log_f);
  xfree(log_txt);
  xfree(clar_text);
}

static void
unpriv_view_standings(FILE *fout,
                      struct http_request_info *phr,
                      const struct contest_desc *cnts,
                      struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  time_t start_time, stop_time, cur_time, fog_start_time = 0, fog_stop_time = 0;
  time_t sched_time = 0, duration = 0;
  long long tdiff;
  unsigned char comment[1024] = { 0 };
  unsigned char dur_buf[128];

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state);
  }
  run_get_times(cs->runlog_state, 0, &sched_time, &duration, 0, 0);
  if (duration > 0 && start_time > 0 && global->board_fog_time > 0)
    fog_start_time = start_time + duration - global->board_fog_time;
  if (fog_start_time < 0) fog_start_time = 0;
  if (fog_start_time > 0 && stop_time > 0) {
    if (global->board_unfog_time > 0)
      fog_stop_time = stop_time + global->board_unfog_time;
    else
      fog_stop_time = stop_time;
  }
  /* FIXME: if a virtual contest is over, display the final
   * standings at the current time! */

  unpriv_load_html_style(phr, cnts, 0, 0);
  l10n_setlocale(phr->locale_id);
  if (start_time <= 0) {
    ns_header(fout, extra->header_txt, 0, 0, phr->script_part, phr->body_attr,
              phr->locale_id,
              "%s [%s]: %s",
              phr->name_arm, extra->contest_arm, _("Standings [not started]"));
    unpriv_page_header(fout, phr, cnts, extra, start_time, stop_time);
    goto done;
  }

  cur_time = cs->current_time;
  if (cur_time < start_time) cur_time = start_time;
  if (duration <= 0) {
    if (stop_time > 0 && cur_time >= stop_time)
      snprintf(comment, sizeof(comment), _(" [over]"));
    else if (global->stand_ignore_after_d > 0
             && cur_time >= global->stand_ignore_after_d) {
      cur_time = global->stand_ignore_after_d;
      snprintf(comment, sizeof(comment), " [%s, frozen]",
               xml_unparse_date(cur_time));
    } else
      snprintf(comment, sizeof(comment), " [%s]", xml_unparse_date(cur_time));
  } else {
    if (stop_time > 0 && cur_time >= stop_time) {
      if (fog_stop_time > 0 && cur_time < fog_stop_time) {
        cur_time = fog_start_time;
        snprintf(comment, sizeof(comment), _(" [over, frozen]"));
      }
      else
        snprintf(comment, sizeof(comment), _(" [over]"));
    } else {
      if (fog_start_time > 0 && cur_time >= fog_start_time) {
        cur_time = fog_start_time;
        snprintf(comment, sizeof(comment), _(" [%s, frozen]"),
                 duration_str(global->show_astr_time, cur_time, start_time,
                              dur_buf, sizeof(dur_buf)));
      } else
        snprintf(comment, sizeof(comment), " [%s]",
                 duration_str(global->show_astr_time, cur_time, start_time,
                              dur_buf, sizeof(dur_buf)));
    }
  }

  ns_header(fout, extra->header_txt, 0, 0, phr->script_part, phr->body_attr,
            phr->locale_id,
            "%s [%s]: %s%s",
            phr->name_arm, extra->contest_arm, _("Standings"), comment);

  unpriv_page_header(fout, phr, cnts, extra, start_time, stop_time);
  fprintf(fout, "<%s>%s%s</%s>\n",
          cnts->team_head_style, _("Standings"), comment,
          cnts->team_head_style);

  if (global->is_virtual) {
    do_write_standings(cs, cnts, fout, 1, 1, phr->user_id, 0, 0, 0, 0, 1,
                       cur_time);
  } else if (global->score_system_val == SCORE_ACM) {
    do_write_standings(cs, cnts, fout, 1, 1, phr->user_id, 0, 0, 0, 0, 1,
                       cur_time);
  } else if (global->score_system_val == SCORE_OLYMPIAD && cs->accepting_mode) {
    fprintf(fout, _("<p>Information is not available.</p>"));
  } else if (global->score_system_val == SCORE_OLYMPIAD) {
    //fprintf(fout, _("<p>Information is not available.</p>"));
    do_write_kirov_standings(cs, cnts, fout, 0, 1, 1, 0, 0, 0, 0, 1, cur_time);
  } else if (global->score_system_val == SCORE_KIROV) {
    do_write_kirov_standings(cs, cnts, fout, 0, 1, 1, 0, 0, 0, 0, 1, cur_time);
  } else if (global->score_system_val == SCORE_MOSCOW) {
    do_write_moscow_standings(cs, cnts, fout, 0, 1, 1, phr->user_id,
                              0, 0, 0, 0, 1, cur_time);
  }

 done:
  if (1 /*cs->global->show_generation_time*/) {
  gettimeofday(&phr->timestamp2, 0);
  tdiff = ((long long) phr->timestamp2.tv_sec) * 1000000;
  tdiff += phr->timestamp2.tv_usec;
  tdiff -= ((long long) phr->timestamp1.tv_sec) * 1000000;
  tdiff -= phr->timestamp1.tv_usec;
  fprintf(fout, "<div class=\"dotted\"><p%s>%s: %lld %s</p></div>",
          cnts->team_par_style,
          _("Page generation time"), tdiff / 1000,
          _("msec"));
  }

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);
}

static int
is_problem_deadlined(serve_state_t cs,
                     int problem_id,
                     const unsigned char *user_login,
                     time_t *p_deadline)
{
  time_t user_deadline = 0;
  int pdi;
  struct pers_dead_info *pdinfo;

  if (problem_id <= 0 || problem_id > cs->max_prob) return 1;
  if (!cs->probs[problem_id]) return 1;

  user_deadline = 0;
  for (pdi = 0, pdinfo = cs->probs[problem_id]->pd_infos;
       pdi < cs->probs[problem_id]->pd_total;
       pdi++, pdinfo++) {
    if (!strcmp(user_login, pdinfo->login)) {
      user_deadline = pdinfo->deadline;
      break;
    }
  }
  if (!user_deadline) user_deadline = cs->probs[problem_id]->t_deadline;
  if (p_deadline) *p_deadline = user_deadline;

  if (!user_deadline) return 0;
  return (cs->current_time >= user_deadline);
}

static void
html_problem_selection(serve_state_t cs,
                       FILE *fout,
                       struct http_request_info *phr,
                       const unsigned char *solved_flag,
                       const unsigned char *accepted_flag,
                       const unsigned char *var_name,
                       int light_mode,
                       time_t start_time)
{
  int i, pdi, dpi, j, k;
  time_t user_deadline = 0;
  int user_penalty = 0, variant = 0;
  struct pers_dead_info *pdinfo;
  unsigned char deadline_str[64];
  unsigned char penalty_str[64];
  unsigned char problem_str[128];
  const unsigned char *problem_ptr = 0;
  const struct section_problem_data *prob;

  if (!var_name) var_name = "prob_id";

  fprintf(fout, "<select name=\"%s\"><option value=\"\"></option>\n", var_name);

  for (i = 1; i <= cs->max_prob; i++) {
    if (!(prob = cs->probs[i])) continue;
    if (!light_mode && prob->disable_submit_after_ok>0 && solved_flag[i])
      continue;
    if (prob->t_start_date > 0 && cs->current_time < prob->t_start_date)
      continue;
    if (start_time <= 0) continue;
    //if (prob->disable_user_submit) continue;

    penalty_str[0] = 0;
    deadline_str[0] = 0;
    if (!light_mode) {
      // try to find personal rules
      user_deadline = 0;
      user_penalty = 0;
      for (pdi = 0, pdinfo = prob->pd_infos;
           pdi < prob->pd_total;
           pdi++, pdinfo++) {
        if (!strcmp(phr->login, pdinfo->login)) {
          user_deadline = pdinfo->deadline;
          break;
        }
      }
      // if no user-specific deadline, try the problem deadline
      if (!user_deadline) user_deadline = prob->t_deadline;
      // if deadline is over, go to the next problem
      if (user_deadline && cs->current_time >= user_deadline) continue;

      // check `require' variable
      if (prob->require) {
        for (j = 0; prob->require[j]; j++) {
          for (k = 1; k <= cs->max_prob; k++) {
            if (cs->probs[k]
                && !strcmp(cs->probs[k]->short_name, prob->require[j]))
              break;
          }
          // no such problem :(
          if (k > cs->max_prob) break;
          // this problem is not yet accepted or solved
          if (!solved_flag[k] && !accepted_flag[k]) break;
        }
        if (prob->require[j]) continue;
      }

      // find date penalty
      for (dpi = 0; dpi < prob->dp_total; dpi++)
        if (cs->current_time < prob->dp_infos[dpi].deadline)
          break;
      if (dpi < prob->dp_total)
        user_penalty = prob->dp_infos[dpi].penalty;

      if (user_deadline > 0 && cs->global->show_deadline)
        snprintf(deadline_str, sizeof(deadline_str),
                 " (%s)", xml_unparse_date(user_deadline));
      if (user_penalty && cs->global->show_deadline)
        snprintf(penalty_str, sizeof(penalty_str), " [%d]", user_penalty);
    }

    if (prob->variant_num > 0) {
      if ((variant = find_variant(cs, phr->user_id, i, 0)) <= 0) continue;
      snprintf(problem_str, sizeof(problem_str),
               "%s-%d", prob->short_name, variant);
      problem_ptr = problem_str;
    } else {
      problem_ptr = prob->short_name;
    }

    fprintf(fout, "<option value=\"%d\">%s - %s%s%s</option>\n",
            i, problem_ptr, prob->long_name, penalty_str,
            deadline_str);
  }

  fprintf(fout, "</select>");
}

// for "Statements" section
static void
html_problem_selection_2(serve_state_t cs,
                         FILE *fout,
                         struct http_request_info *phr,
                         const unsigned char *var_name,
                         time_t start_time)
{
  int i, pdi, dpi;
  time_t user_deadline = 0;
  int variant = 0;
  struct pers_dead_info *pdinfo;
  unsigned char deadline_str[64];
  unsigned char problem_str[128];
  const unsigned char *problem_ptr = 0;
  const struct section_problem_data *prob;

  if (!var_name) var_name = "prob_id";

  fprintf(fout, "<select name=\"%s\"><option value=\"\"></option>\n", var_name);
  fprintf(fout, "<option value=\"-1\">%s</option>\n", _("View all"));

  for (i = 1; i <= cs->max_prob; i++) {
    if (!(prob = cs->probs[i])) continue;
    if (prob->t_start_date > 0 && cs->current_time < prob->t_start_date)
      continue;
    if (start_time <= 0) continue;

    deadline_str[0] = 0;
    user_deadline = 0;
    for (pdi = 0, pdinfo = prob->pd_infos;
         pdi < prob->pd_total;
         pdi++, pdinfo++) {
      if (!strcmp(phr->login, pdinfo->login)) {
        user_deadline = pdinfo->deadline;
        break;
      }
    }
    // if no user-specific deadline, try the problem deadline
    if (!user_deadline) user_deadline = prob->t_deadline;
    // if deadline is over, go to the next problem
    if (user_deadline && cs->current_time >= user_deadline) continue;

    // find date penalty
    for (dpi = 0; dpi < prob->dp_total; dpi++)
      if (cs->current_time < prob->dp_infos[dpi].deadline)
        break;

    if (user_deadline > 0 && cs->global->show_deadline)
      snprintf(deadline_str, sizeof(deadline_str),
               " (%s)", xml_unparse_date(user_deadline));

    if (prob->variant_num > 0) {
      if ((variant = find_variant(cs, phr->user_id, i, 0)) <= 0) continue;
      snprintf(problem_str, sizeof(problem_str),
               "%s-%d", prob->short_name, variant);
      problem_ptr = problem_str;
    } else {
      problem_ptr = prob->short_name;
    }

    fprintf(fout, "<option value=\"%d\">%s - %s%s</option>\n",
            i, problem_ptr, prob->long_name, deadline_str);
  }

  fprintf(fout, "</select>");
}

static unsigned char *
brief_time(unsigned char *buf, size_t size, time_t time)
{
  struct tm *ptm = localtime(&time);
  snprintf(buf, size, "%02d:%02d:%02d",
           ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
  return buf;
}

static void
unpriv_page_header(FILE *fout,
                   struct http_request_info *phr,
                   const struct contest_desc *cnts,
                   struct contest_extra *extra,
                   time_t start_time, time_t stop_time)
{
  static int top_action_list[] =
  {
    NEW_SRV_ACTION_VIEW_SETTINGS,
    NEW_SRV_ACTION_REG_DATA_EDIT,
    NEW_SRV_ACTION_LOGOUT,

    -1,
  };

  static const unsigned char *top_action_names[] =
  {
    __("Settings"),
    __("Registration data"),
    __("Logout"),
  };

  static int action_list[] =
  {
    NEW_SRV_ACTION_MAIN_PAGE,
    NEW_SRV_ACTION_VIEW_STARTSTOP,
    NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY,
    NEW_SRV_ACTION_VIEW_PROBLEM_STATEMENTS,
    NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT,
    NEW_SRV_ACTION_VIEW_SUBMISSIONS,
    NEW_SRV_ACTION_STANDINGS,
    NEW_SRV_ACTION_VIEW_CLAR_SUBMIT,
    NEW_SRV_ACTION_VIEW_CLARS,

    -1,
  };

  static const unsigned char *action_names[] =
  {
    __("Info"),
    0,
    __("Summary"),
    __("Statements"),
    __("Submit"),
    __("Submissions"),
    __("Standings"),
    __("Submit clar"),
    __("Clars"),
    __("Settings"),
    __("Logout"),
  };

  int i, prob_id, has_prob_stmt = 0;
  serve_state_t cs = extra->serve_state;
  const unsigned char *forced_url = 0;
  const unsigned char *target = 0;
  const unsigned char *forced_text = 0;
  const struct section_global_data *global = cs->global;
  int unread_clars = 0;
  const unsigned char *status_style = "", *s;
  unsigned char time_buf[64];
  time_t duration = 0, sched_time = 0, fog_start_time = 0;
  int shown_items = 0;
  const unsigned char *template_ptr;
  unsigned char stand_url_buf[1024];
  struct teamdb_export tdb;
  struct sformat_extra_data fe;

  template_ptr = extra->menu_2_txt;
  if (!template_ptr || !*template_ptr)
    template_ptr = ns_fancy_unpriv_content_header;

  if (!phr->action) phr->action = NEW_SRV_ACTION_MAIN_PAGE;

  while (*template_ptr) {
    if (*template_ptr != '%') {
      putc(*template_ptr, fout);
      template_ptr++;
      continue;
    }
    template_ptr++;
    if (!*template_ptr) {
      putc('%', fout);
      break;
    } else if (*template_ptr == '%') {
      putc('%', fout);
      template_ptr++;
      continue;
    }

    switch (*template_ptr++) {
    case '1':
      for (i = 0; top_action_list[i] != -1; i++) {
        // phew ;)
        if (cnts->exam_mode) continue;
        if (phr->action == top_action_list[i]) {
          fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">%s</div></td>", gettext(top_action_names[i]));
          shown_items++;
        } else if (top_action_list[i] == NEW_SRV_ACTION_REG_DATA_EDIT) {
          if (!cnts->allow_reg_data_edit) continue;
          if (!contests_check_register_ip_2(cnts, phr->ip, phr->ssl_flag))
            continue;
          if (cnts->reg_deadline > 0 && cs->current_time >= cnts->reg_deadline)
            continue;
          get_register_url(stand_url_buf, sizeof(stand_url_buf), cnts,
                           phr->self_url);
          fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\"><a class=\"menu\" href=\"%s?SID=%016llx\">%s</a></div></td>",
                  stand_url_buf, phr->session_id,
                  gettext(top_action_names[i]));
          shown_items++;
        } else if (top_action_list[i] == NEW_SRV_ACTION_LOGOUT) {
          forced_text = 0;
          if (cnts->exam_mode) forced_text = _("Finish session");
          if (!forced_text) forced_text = gettext(top_action_names[i]);
          fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\"><a class=\"menu\" href=\"%s?SID=%016llx&amp;action=%d\">%s [%s]</a></div></td>",
                  phr->self_url, phr->session_id, top_action_list[i],
                  forced_text, phr->login);
          shown_items++;
        } else {
          fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\"><a class=\"menu\" href=\"%s?SID=%016llx&amp;action=%d\">%s</a></div></td>",
                  phr->self_url, phr->session_id, top_action_list[i],
                  gettext(top_action_names[i]));
          shown_items++;
        }
      }
      if (!shown_items)
        fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td>");
      break;
    case '2':
      for (i = 0; action_list[i] != -1; i++) {
        forced_url = 0;
        forced_text = 0;
        target = "";
        // conditions when the corresponding menu item is shown
        switch (action_list[i]) {
        case NEW_SRV_ACTION_MAIN_PAGE:
          if (cnts->exam_mode) forced_text = _("Instructions");
          break;
        case NEW_SRV_ACTION_VIEW_STARTSTOP:
          if (!global->is_virtual) continue;
          if (start_time <= 0) {
            if (global->disable_virtual_start > 0) continue;
            if (cnts->exam_mode) forced_text = _("Start exam");
            else forced_text = _("Start virtual contest");
          } else if (stop_time <= 0) {
            if (cnts->exam_mode) forced_text = _("Stop exam");
            else forced_text = _("Stop virtual contest");
          } else {
            continue;
          }
          break;
        case NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY:
          if (start_time <= 0) continue;
          if (cnts->exam_mode && stop_time <= 0) continue;
          break;      
        case NEW_SRV_ACTION_VIEW_PROBLEM_STATEMENTS:
          if (start_time <= 0) continue;
          if (stop_time > 0 && !cnts->problems_url) continue;
          for (prob_id = 1; prob_id <= cs->max_prob; prob_id++)
            if (cs->probs[prob_id] && cs->probs[prob_id]->statement_file[0])
              break;
          if (prob_id <= cs->max_prob)
            has_prob_stmt = 1;
          if (!has_prob_stmt && !cnts->problems_url) continue;
          if (cnts->problems_url && (stop_time > 0 || !has_prob_stmt)) {
            forced_url = cnts->problems_url;
            target = " target=\"_blank\"";
          }
          if (global->problem_navigation) continue;
          break;
        case NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT:
          if (start_time <= 0 || stop_time > 0) continue;
          if (global->problem_navigation > 0) continue;
          break;
        case NEW_SRV_ACTION_VIEW_SUBMISSIONS:
          if (start_time <= 0) continue;
          if (cnts->exam_mode && stop_time <= 0) continue;
          break;
        case NEW_SRV_ACTION_STANDINGS:
          if (start_time <= 0) continue;
          if (global->disable_user_standings > 0) continue;
          //if (global->score_system_val == SCORE_OLYMPIAD) continue;
          if (cnts->standings_url) {
            memset(&tdb, 0, sizeof(tdb));
            teamdb_export_team(cs->teamdb_state, phr->user_id, &tdb);
            memset(&fe, 0, sizeof(fe));
            fe.locale_id = phr->locale_id;
            sformat_message(stand_url_buf, sizeof(stand_url_buf),
                            cnts->standings_url, global, 0, 0, 0, &tdb,
                            tdb.user, cnts, &fe);
            forced_url = stand_url_buf;
            target = " target=\"_blank\"";
          }
          if (cnts->personal) forced_text = _("User standings");
          break;
        case NEW_SRV_ACTION_VIEW_CLAR_SUBMIT:
          if (global->disable_team_clars) continue;
          if (global->disable_clars) continue;
          if (start_time <= 0) continue;
          if (stop_time > 0
              && (global->appeal_deadline_d <= 0
                  || cs->current_time >= global->appeal_deadline_d))
            continue;
          break;
        case NEW_SRV_ACTION_VIEW_CLARS:
          if (global->disable_clars) continue;
          break;
        case NEW_SRV_ACTION_VIEW_SETTINGS:
          break;
        }
        if (!forced_text) forced_text = gettext(action_names[i]);
        if (phr->action == action_list[i]) {
          fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">%s</div></td>", forced_text);
        } else if (forced_url) {
          fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\"><a class=\"menu\" href=\"%s\"%s>%s</a></div></td>",
                  forced_url, target, forced_text);
        } else {
          fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\"><a class=\"menu\" href=\"%s?SID=%016llx&amp;action=%d\">%s</a></div></td>",
                  phr->self_url, phr->session_id, action_list[i], forced_text);
        }
      }
      break;

    case '3':
      if (extra->separator_txt && *extra->separator_txt) {
        fprintf(fout, "%s", extra->separator_txt);
      }
      break;

    case '4':
      run_get_times(cs->runlog_state, 0, &sched_time, &duration, 0, 0);
      if (duration > 0 && start_time && !stop_time
          && global->board_fog_time > 0)
        fog_start_time = start_time + duration - global->board_fog_time;
      if (fog_start_time < 0) fog_start_time = 0;
      if (!cs->global->disable_clars || !cs->global->disable_team_clars)
        unread_clars = serve_count_unread_clars(cs, phr->user_id, start_time);
      if (cs->clients_suspended) {
        status_style = "server_status_off";
      } else if (unread_clars > 0) {
        status_style = "server_status_alarm";
      } else {
        status_style = "server_status_on";
      }
      fprintf(fout, "<div class=\"%s\">\n", status_style);
      fprintf(fout, "<div id=\"currentTime\">%s</div>",
              brief_time(time_buf, sizeof(time_buf), cs->current_time));
      if (unread_clars > 0) {
        fprintf(fout, _(" / <b>%d unread message(s)</b>"),
                unread_clars);
      }

      if (stop_time > 0) {
        if (duration > 0 && global->board_fog_time > 0
            && global->board_unfog_time > 0
            && cs->current_time < stop_time + global->board_unfog_time
            && !cs->standings_updated) {
          s = _("OVER (frozen)");
        } else {
          s = _("OVER");
        }
      } else if (start_time > 0) {
        if (fog_start_time > 0 && cs->current_time >= fog_start_time) {
          if (cnts->exam_mode)
            s = _("EXAM IS RUNNING (frozen)");
          else
            s = _("RUNNING (frozen)");
        } else {
          if (cnts->exam_mode)
            s = _("EXAM IS RUNNING");
          else
            s = _("RUNNING");
        }
      } else {
        s = _("NOT STARTED");
      }
      fprintf(fout, " / <b>%s</b>", s);

      if (start_time > 0) {
        if (global->score_system_val == SCORE_OLYMPIAD && !global->is_virtual) {
          if (cs->accepting_mode)
            s = _("accepting");
          else if (!cs->testing_finished)
            s = _("judging");
          else
            s = _("judged");
          fprintf(fout, " / <b>%s</b>", s);
        }
      }

      if (cs->upsolving_mode) {
        fprintf(fout, " / <b>%s</b>", _("UPSOLVING"));
      }

      if (cs->clients_suspended) {
        fprintf(fout, " / <b><font color=\"red\">%s</font></b>",
                _("clients suspended"));
      }

      if (start_time > 0) {
        if (cs->testing_suspended) {
          fprintf(fout, " / <b><font color=\"red\">%s</font></b>",
                  _("testing suspended"));
        }
        if (cs->printing_suspended) {
          fprintf(fout, " / <b><font color=\"red\">%s</font></b>",
                  _("printing suspended"));
        }
      }

      if (!global->is_virtual && start_time <= 0 && sched_time > 0) {
        fprintf(fout, " / %s: %s",
                _("Start at"),
                brief_time(time_buf, sizeof(time_buf), sched_time));
      }

      if (start_time > 0 && stop_time <= 0 && duration > 0) {
        duration_str(0, start_time + duration - cs->current_time, 0,
                     time_buf, 0);
        fprintf(fout, " / %s: <div id=\"remainingTime\">%s</div>",
                _("Remaining"), time_buf);
      }

      fprintf(fout, "</div>\n");
      break;

    default:
      break;
    }
  }
}

static int
get_last_language(serve_state_t cs, int user_id)
{
  int total_runs = run_get_total(cs->runlog_state), run_id;
  struct run_entry re;

  for (run_id = total_runs - 1; run_id >= 0; run_id--) {
    if (run_get_entry(cs->runlog_state, run_id, &re) < 0) continue;
    if (!run_is_source_available(re.status)) continue;
    if (re.user_id != user_id) continue;
    if (re.lang_id <= 0 || re.lang_id > cs->max_lang || !cs->langs[re.lang_id])
      continue;
    return re.lang_id;
  }
  return 0;
}

static unsigned char *
get_last_source(serve_state_t cs, int user_id, int prob_id)
{
  const struct section_global_data *global = cs->global;
  int total_runs = run_get_total(cs->runlog_state), run_id;
  struct run_entry re;
  int src_flag = 0;
  path_t src_path;
  char *src_txt = 0;
  size_t src_len = 0;
  unsigned char *s;

  for (run_id = total_runs - 1; run_id >= 0; run_id--) {
    if (run_get_entry(cs->runlog_state, run_id, &re) < 0) continue;
    if (!run_is_source_available(re.status)) continue;
    if (re.user_id != user_id || re.prob_id != prob_id) continue;
    break;
  }
  if (run_id < 0) return 0;

  if ((src_flag = archive_make_read_path(cs, src_path, sizeof(src_path),
                                         global->run_archive_dir,
                                         run_id, 0, 1)) < 0)
    return 0;
  if (generic_read_file(&src_txt, 0, &src_len, src_flag, 0, src_path, 0) < 0)
    return 0;

  s = src_txt;
  while (src_len > 0 && isspace(s[src_len])) src_len--;
  s[src_len] = 0;

  return s;
}

static int
get_last_answer_select_one(serve_state_t cs, int user_id, int prob_id)
{
  unsigned char *s = get_last_source(cs, user_id, prob_id);
  int val;
  char *eptr = 0;

  if (!s || !*s) return -1;
  errno = 0;
  val = strtol(s, &eptr, 10);
  if (*eptr || errno || val <= 0) val = -1;
  xfree(s);
  return val;
}

static int
is_judged_virtual_olympiad(serve_state_t cs, int user_id)
{
  struct run_entry vs, ve;

  if (run_get_virtual_info(cs->runlog_state, user_id, &vs, &ve) < 0) return 0;
  return (vs.judge_id > 0);
}

// problem status flags
enum
{
  PROB_STATUS_VIEWABLE = 1,
  PROB_STATUS_SUBMITTABLE = 2,
  PROB_STATUS_TABABLE = 4,

  PROB_STATUS_GOOD = PROB_STATUS_VIEWABLE | PROB_STATUS_SUBMITTABLE,
};

/*
  *PROBLEM_PARAM(disable_user_submit, "d"),
  *PROBLEM_PARAM(disable_tab, "d"),
  *PROBLEM_PARAM(restricted_statement, "d"),
  *PROBLEM_PARAM(disable_submit_after_ok, "d"),
  *PROBLEM_PARAM(deadline, "s"),
  *PROBLEM_PARAM(start_date, "s"),
  *PROBLEM_PARAM(require, "x"),
  *PROBLEM_PARAM(personal_deadline, "x"),
*/

static void
get_problem_status(serve_state_t cs, int user_id,
                   const unsigned char *user_login,
                   int accepting_mode,
                   time_t start_time,
                   time_t stop_time,
                   const unsigned char *solved_flag,
                   const unsigned char *accepted_flag,
                   unsigned char *pstat)
{
  const struct section_problem_data *prob;
  int prob_id, pdi, is_deadlined, k, j;
  time_t user_deadline;
  const struct pers_dead_info *pdinfo;

  // nothing before contest start
  if (start_time <= 0) return;

  for (prob_id = 1; prob_id <= cs->max_prob; prob_id++) {
    if (!(prob = cs->probs[prob_id])) continue;

    // the problem is completely disabled before its start_date
    if (prob->t_start_date > 0 && prob->t_start_date > cs->current_time)
      continue;

    // the problem is completely disabled before requirements are met
    // check requirements
    if (prob->require) {
      for (j = 0; prob->require[j]; j++) {
        for (k = 1; k <= cs->max_prob; k++) {
          if (cs->probs[k]
              && !strcmp(cs->probs[k]->short_name, prob->require[j]))
            break;
        }
        // no such problem :(
        if (k > cs->max_prob) break;
        // this problem is not yet accepted or solved
        if (!solved_flag[k] && !accepted_flag[k]) break;
      }
      // if the requirements are not met, skip this problem
      if (prob->require[j]) continue;
    }

    // check problem deadline
    is_deadlined = 0;
    if (stop_time > 0 && cs->current_time >= stop_time) {
      is_deadlined = 1;
    } else {
      user_deadline = 0;
      for (pdi = 0, pdinfo = prob->pd_infos; pdi < prob->pd_total;
           pdi++, pdinfo++) {
        if (!strcmp(user_login, pdinfo->login)) {
          user_deadline = pdinfo->deadline;
          break;
        }
      }
      if (user_deadline <= 0) user_deadline = prob->t_deadline;
      if (user_deadline > 0 && cs->current_time >= user_deadline)
        is_deadlined = 1;
    }

    if (prob->restricted_statement <= 0 || !is_deadlined)
      pstat[prob_id] |= PROB_STATUS_VIEWABLE;

    if (!is_deadlined && prob->disable_user_submit <= 0
        && (prob->disable_submit_after_ok <= 0 || !solved_flag[prob_id]))
      pstat[prob_id] |= PROB_STATUS_SUBMITTABLE;

    if (prob->disable_tab <= 0)
      pstat[prob_id] |= PROB_STATUS_TABABLE;
  }
}

static void
unpriv_unparse_statement(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        const struct section_problem_data *prob,
        problem_xml_t px,
        const unsigned char *bb)
{
  struct problem_stmt *pp = 0;
  struct xml_tree *p, *q;
  unsigned char b1[1024];
  unsigned char b2[1024];
  unsigned char b3[1024];
  unsigned char b4[1024];
  unsigned char b5[1024];
  unsigned char b6[1024];
  const unsigned char *vars[7] = { "self", "prob", "get", "getfile", "input_file", "output_file", 0 };
  const unsigned char *vals[7] = { b1, b2, b3, b4, b5, b6, 0 };

  snprintf(b1, sizeof(b1), "%s?SID=%016llx", phr->self_url, phr->session_id);
  snprintf(b2, sizeof(b2), "&prob_id=%d", prob->id);
  snprintf(b3, sizeof(b3), "&action=%d", NEW_SRV_ACTION_GET_FILE);
  snprintf(b4, sizeof(b4), "%s%s%s&file", b1, b2, b3);
  snprintf(b5, sizeof(b5), "%s", prob->input_file);
  snprintf(b6, sizeof(b6), "%s", prob->output_file);

  if (bb && *bb && !cnts->exam_mode) fprintf(fout, "%s", bb);

  pp = problem_xml_find_statement(px, 0);
  if (pp->title) {
    fprintf(fout, "<h3>");
    problem_xml_unparse_node(fout, pp->title, vars, vals);
    fprintf(fout, "</h3>");
  }
  
  if (pp->desc) {
    problem_xml_unparse_node(fout, pp->desc, vars, vals);
  }

  if (pp->input_format) {
    fprintf(fout, "<h3>%s</h3>", _("Input format"));
    problem_xml_unparse_node(fout, pp->input_format, vars, vals);
  }
  if (pp->output_format) {
    fprintf(fout, "<h3>%s</h3>", _("Output format"));
    problem_xml_unparse_node(fout, pp->output_format, vars, vals);
  }

  if (px->examples) {
    fprintf(fout, "<h3>%s</h3>", _("Examples"));
    fprintf(fout, "<table class=\"b1\">");
    fprintf(fout, "<tr><td class=\"b1\" align=\"center\"><b>");
    if (prob->use_stdin) {
      fprintf(fout, "%s", _("Input"));
    } else {
      fprintf(fout, "%s <tt>%s</tt>", _("Input in"), prob->input_file);
    }
    fprintf(fout, "</b></td><td class=\"b1\" align=\"center\"><b>");
    if (prob->use_stdout) {
      fprintf(fout, "%s", _("Output"));
    } else {
      fprintf(fout, "%s <tt>%s</tt>", _("Output in"), prob->output_file);
    }
    fprintf(fout, "</b></td></tr>");
    for (p = px->examples->first_down; p; p = p->right) {
      if (p->tag != PROB_T_EXAMPLE) continue;
      fprintf(fout, "<tr><td class=\"b1\" valign=\"top\"><pre>");
      for (q = p->first_down; q && q->tag != PROB_T_INPUT; q = q->right);
      if (q && q->tag == PROB_T_INPUT) problem_xml_unparse_node(fout, q, 0, 0);
      fprintf(fout, "</pre></td><td class=\"b1\" valign=\"top\"><pre>");
      for (q = p->first_down; q && q->tag != PROB_T_OUTPUT; q = q->right);
      if (q && q->tag == PROB_T_OUTPUT) problem_xml_unparse_node(fout, q, 0, 0);
      fprintf(fout, "</pre></td></tr>");
    }
    fprintf(fout, "</table>");
  }

  if (pp->notes) {
    fprintf(fout, "<h3>%s</h3>", _("Notes"));
    problem_xml_unparse_node(fout, pp->notes, vars, vals);
  }

  if (prob->type_val == PROB_TYPE_SELECT_ONE) {
    fprintf(fout, "<h3>%s</h3>", _("Choose an answer"));
  } else {
    fprintf(fout, "<h3>%s</h3>", _("Submit a solution"));
  }
}

static void
unpriv_unparse_answers(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        const struct section_problem_data *prob,
        problem_xml_t px,
        const unsigned char *lang,
        int is_radio,
        int last_answer,
        int next_prob_id,
        int enable_js,
        const unsigned char *class_name)
{
  unsigned char *cl = "";
  unsigned char jsbuf[128];
  int l, i;
  const unsigned char *s;

  if (class_name && *class_name) {
    cl = (unsigned char *) alloca(strlen(class_name) + 32);
    sprintf(cl, " class=\"%s\"", class_name);
  }

  l = problem_xml_find_language(lang, px->tr_num, px->tr_names);
  for (i = 0; i < px->ans_num; i++) {
    if (is_radio) {
      jsbuf[0] = 0;
      if (prob->id > 0 && enable_js) {
        snprintf(jsbuf, sizeof(jsbuf), " onclick=\"submitAnswer(%d,%d,%d)\"",
                 prob->id, i + 1, next_prob_id);
      }
      s = "";
      if (last_answer == i + 1) s = " checked=\"1\"";
      fprintf(fout, "<tr><td%s>%d)</td><td%s><input type=\"radio\" name=\"file\" value=\"%d\"%s%s/></td><td%s>", cl, i + 1, cl, i + 1, s, jsbuf, cl);
      problem_xml_unparse_node(fout, px->answers[i][l], 0, 0);
      fprintf(fout, "</td></tr>\n");
    } else {
      fprintf(fout, "<tr><td%s>%d)</td><td%s><input type=\"checkbox\" name=\"ans_%d\"/></td><td%s>", cl, i + 1, cl, i + 1, cl);
      problem_xml_unparse_node(fout, px->answers[i][l], 0, 0);
      fprintf(fout, "</td></tr>\n");
    }
  }
}

static const unsigned char *main_page_headers[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_MAIN_PAGE] = __("Contest status"),
  [NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY] = __("Problem summary"),
  [NEW_SRV_ACTION_VIEW_PROBLEM_STATEMENTS] = __("Statements"),
  [NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT] = __("Submit a solution"),
  [NEW_SRV_ACTION_VIEW_SUBMISSIONS] = __("Submissions"),
  [NEW_SRV_ACTION_VIEW_CLAR_SUBMIT] = __("Send a message"),
  [NEW_SRV_ACTION_VIEW_CLARS] = __("Messages"),
  [NEW_SRV_ACTION_VIEW_SETTINGS] = __("Settings"),
};

static void
unpriv_main_page(FILE *fout,
                 struct http_request_info *phr,
                 const struct contest_desc *cnts,
                 struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  struct section_global_data *global = cs->global;
  //long long tdiff;
  time_t start_time, stop_time, duration, sched_time, fog_start_time = 0;
  const unsigned char *s;
  int all_runs = 0, all_clars = 0;
  unsigned char *solved_flag = 0;
  unsigned char *accepted_flag = 0;
  unsigned char *pending_flag = 0;
  unsigned char *trans_flag = 0;
  unsigned char *prob_status = 0;
  int *best_run = 0;
  int *attempts = 0;
  int *disqualified = 0;
  int *best_score = 0;
  int *prev_successes = 0;
  int *all_attempts = 0;
  int n, v, prob_id = 0, i, j, variant = 0;
  char **lang_list;
  path_t variant_stmt_file;
  struct watched_file *pw = 0;
  const unsigned char *pw_path;
  const struct section_problem_data *prob = 0, *prob2;
  unsigned char bb[1024];
  const unsigned char *alternatives = 0, *header = 0;
  int lang_count = 0, lang_id = 0;
  int first_prob_id, last_prob_id;
  int accepting_mode = 0;
  const unsigned char *hh = 0;
  const unsigned char *cc = 0;
  int last_answer = -1, last_lang_id, skip_start_form = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char *last_source = 0;
  unsigned char dbuf[1024];
  unsigned char wbuf[1024];
  int upper_tab_id = 0, next_prob_id;
  problem_xml_t px;
  unsigned char prev_group_name[256] = { 0 };

  if (ns_cgi_param(phr, "all_runs", &s) > 0
      && sscanf(s, "%d%n", &v, &n) == 1 && !s[n] && v >= 0 && v <= 1) {
    phr->session_extra->user_view_all_runs = v;
  }
  all_runs = phr->session_extra->user_view_all_runs;
  if (ns_cgi_param(phr, "all_clars", &s) > 0
      && sscanf(s, "%d%n", &v, &n) == 1 && !s[n] && v >= 0 && v <= 1) {
    phr->session_extra->user_view_all_clars = v;
  }
  all_clars = phr->session_extra->user_view_all_clars;
  if (ns_cgi_param(phr, "prob_id", &s) > 0
      && sscanf(s, "%d%n", &v, &n) == 1 && !s[n] && v >= -1)
    prob_id = v;
  
  XALLOCAZ(solved_flag, cs->max_prob + 1);
  XALLOCAZ(accepted_flag, cs->max_prob + 1);
  XALLOCAZ(pending_flag, cs->max_prob + 1);
  XALLOCAZ(trans_flag, cs->max_prob + 1);
  XALLOCA(best_run, cs->max_prob + 1);
  memset(best_run, -1, (cs->max_prob + 1) * sizeof(best_run[0]));
  XALLOCAZ(attempts, cs->max_prob + 1);
  XALLOCAZ(disqualified, cs->max_prob + 1);
  XALLOCAZ(best_score, cs->max_prob + 1);
  XALLOCAZ(prev_successes, cs->max_prob + 1);
  XALLOCAZ(all_attempts, cs->max_prob + 1);
  XALLOCAZ(prob_status, cs->max_prob + 1);

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
    if (stop_time <= 0) accepting_mode = 1;
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state);
    accepting_mode = cs->accepting_mode;
  }
  run_get_times(cs->runlog_state, 0, &sched_time, &duration, 0, 0);
  if (duration > 0 && start_time && !stop_time && global->board_fog_time > 0)
    fog_start_time = start_time + duration - global->board_fog_time;
  if (fog_start_time < 0) fog_start_time = 0;

  hh = main_page_headers[phr->action];
  if (phr->action == NEW_SRV_ACTION_MAIN_PAGE && cnts->exam_mode) {
    hh = __("Exam status");
  }
  l10n_setlocale(phr->locale_id);
  header = gettext(hh);
  if (!header) header = _("Main page");
  unpriv_load_html_style(phr, cnts, 0, 0);
  ns_header(fout, extra->header_txt, 0, 0, phr->script_part, phr->body_attr,
            phr->locale_id,
            "%s [%s]: %s",
            phr->name_arm, extra->contest_arm, header);

  unpriv_page_header(fout, phr, cnts, extra, start_time, stop_time);

  ns_get_user_problems_summary(cs, phr->user_id, accepting_mode,
                               solved_flag, accepted_flag, pending_flag,
                               trans_flag,
                               best_run, attempts, disqualified,
                               best_score, prev_successes, all_attempts);
  get_problem_status(cs, phr->user_id, phr->login, accepting_mode,
                     start_time, stop_time,
                     solved_flag, accepted_flag, prob_status);

  if (global->problem_navigation > 0 && start_time > 0 && stop_time <= 0) {
    if (prob_id > cs->max_prob) prob_id = 0;
    if (prob_id > 0 && !(prob = cs->probs[prob_id])) prob_id = 0;
    if (prob_id > 0 && !(prob_status[prob_id] & PROB_STATUS_GOOD))
      prob_id = 0;
    if (prob_id > 0 && prob->variant_num > 0
        && (variant = find_variant(cs, phr->user_id, prob_id, 0)) <= 0)
      prob_id = 0;

    fprintf(fout, "<br/>\n");
    fprintf(fout, "<table class=\"probNav\">\n");
    upper_tab_id = prob_id;
    if (global->vertical_navigation <= 0) {
      fprintf(fout, "<tr id=\"probNavTopList\">\n");
      for (i = 1, j = 0; i <= cs->max_prob; i++) {
        if (!(prob = cs->probs[i])) continue;
        if (!(prob_status[i] & PROB_STATUS_TABABLE)) continue;

        if (j > 0) {
          fprintf(fout, "<td class=\"probNavSpaceTop\">&nbsp;</td>");
          j++;
        }
        hh = "probNavHidden";
        if (i == prob_id) {
          cc = "probCurrent";
        } else if (prob->disable_user_submit > 0) {
          cc = "probDisabled";
        } else if (!all_attempts[i]) {
          cc = "probEmpty";
        } else if (pending_flag[i] || trans_flag[i]) {
          cc = "probTrans";
        } else if (accepted_flag[i] || solved_flag[i]) {
          cc = "probOk";
        } else {
          cc = "probBad";
        }
        if (i == prob_id) hh = "probNavActiveTop";
        wbuf[0] = 0;
        if (global->problem_tab_size > 0)
          snprintf(wbuf, sizeof(wbuf), " width=\"%dpx\"",
                   global->problem_tab_size);
        fprintf(fout, "<td class=\"%s\" onclick=\"displayProblemSubmitForm(%d)\"%s><div class=\"%s\">", hh, i, wbuf, cc);
      //fprintf(fout, "<td class=\"%s\" style=\"background-color: %s\">", hh, cc);
      /*
      if (accepting_mode && accepted_flag[i]) {
        fprintf(fout, "<s>");
      }
      */
        fprintf(fout, "%s%s</a>",
                ns_aref_2(bb, sizeof(bb), phr, "tab",
                          NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT,
                          "prob_id=%d", i), prob->short_name);
      /*
      if (accepting_mode && accepted_flag[i]) {
        fprintf(fout, "</s>");
      }
      */
        fprintf(fout, "</div></td>\n");
        j++;
      }
      fprintf(fout, "</tr>");
      fprintf(fout, "<tr><td colspan=\"%d\" id=\"probNavTaskArea\" valign=\"top\"><div id=\"probNavTaskArea\">\n", j);
    } else {
      fprintf(fout, "<tr><td class=\"b0\" id=\"probNavTaskArea\" valign=\"top\"><div id=\"probNavTaskArea\">\n");
    }
  }

  if (phr->action == NEW_SRV_ACTION_MAIN_PAGE) {
    unpriv_print_status(fout, phr, cnts, extra,
                        start_time, stop_time, duration, sched_time,
                        fog_start_time);
  }

  if (phr->action == NEW_SRV_ACTION_VIEW_STARTSTOP) {
    if (global->is_virtual && start_time <= 0) {
      if (global->disable_virtual_start <= 0) {
        html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
        if (cnts->exam_mode) {
          fprintf(fout, "<p>%s</p></form>",
                  ns_submit_button(bb, sizeof(bb), 0,
                                   NEW_SRV_ACTION_VIRTUAL_START,
                                   _("Start exam")));
        } else {
          fprintf(fout, "<p>%s</p></form>",
                  BUTTON(NEW_SRV_ACTION_VIRTUAL_START));
        }
      }
    } else if (global->is_virtual && stop_time <= 0) {
      if (cnts->exam_mode) {
        fprintf(fout, "<h2>%s</h2>\n", _("Finish the exam"));
        fprintf(fout, "<p>%s</p>\n",
                _("Press \"Stop exam\" button to finish the exam. Your answers will be checked shortly after that."));
      }

      html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
      if (cnts->exam_mode) {
        fprintf(fout, "<p>%s</p></form>",
                ns_submit_button(bb, sizeof(bb), 0, NEW_SRV_ACTION_VIRTUAL_STOP,
                                 _("Stop exam")));
      } else {
        fprintf(fout, "<p>%s</p></form>",
                BUTTON(NEW_SRV_ACTION_VIRTUAL_STOP));
      }
    }
  }

  if (start_time && phr->action == NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY) {
    if (cnts->exam_mode && global->score_system_val == SCORE_OLYMPIAD
        && global->is_virtual && stop_time > 0
        && global->disable_virtual_auto_judge > 0
        && !cs->testing_finished) {
      char *ff_txt = 0, *fl_txt = 0;
      size_t ff_len = 0, fl_len = 0;
      FILE *ff = open_memstream(&ff_txt, &ff_len);
      FILE *fl = open_memstream(&fl_txt, &fl_len);
      int rr = ns_olympiad_final_user_report(ff, fl, cnts, cs,
                                             phr->user_id, phr->locale_id);
      if (rr < 0) {
        fprintf(fout, "<%s>%s</%s>\n<p>%s %d</p>",
                cnts->team_head_style,
                _("Problem status summary"),
                cnts->team_head_style, _("Error"), -rr);
        fclose(fl); fl = 0; xfree(fl_txt); fl_txt = 0; fl_len = 0;
        fclose(ff); ff = 0; xfree(ff_txt); ff_txt = 0; ff_len = 0;
      } else {
        fclose(fl); fl = 0;
        if (fl_txt && *fl_txt) {
          fprintf(fout,
                  "<%s>%s</%s>\n<pre><font color=\"red\">%s</font></pre>\n",
                  cnts->team_head_style,
                  _("Problem status summary"),
                  cnts->team_head_style, ARMOR(fl_txt));
          xfree(fl_txt); fl_txt = 0; fl_len = 0;
          fclose(ff); ff = 0; xfree(ff_txt); ff_txt = 0; ff_len = 0;
        } else {
          fclose(ff); ff = 0; 
          fprintf(fout,
                  "<%s>%s</%s>\n%s\n",
                  cnts->team_head_style,
                  _("Problem status summary"),
                  cnts->team_head_style, ff_txt);
          xfree(fl_txt); fl_txt = 0; fl_len = 0;
          xfree(ff_txt); ff_txt = 0; ff_len = 0;
        }
      }
    } else if (cnts->exam_mode && global->score_system_val == SCORE_OLYMPIAD
               && global->is_virtual && stop_time > 0
               && (run_has_transient_user_runs(cs->runlog_state, phr->user_id)
                   || (global->disable_virtual_auto_judge <= 0
                       && !is_judged_virtual_olympiad(cs, phr->user_id)))) {
      fprintf(fout, "<%s>%s</%s>\n",
              cnts->team_head_style,
              _("Testing is in progress..."),
              cnts->team_head_style);
    } else {
      fprintf(fout, "<%s>%s</%s>\n",
              cnts->team_head_style,
              _("Problem status summary"),
              cnts->team_head_style);
      if (global->score_system_val == SCORE_OLYMPIAD
          && global->is_virtual
          && cs->testing_finished)
        accepting_mode = 0;
      if (cs->contest_plugin
          && cs->contest_plugin->generate_html_user_problems_summary) {
        // FIXME: return code and logging stream is not used now
        char *us_text = 0;
        size_t us_size = 0;
        FILE *us_file = open_memstream(&us_text, &us_size);
        (*cs->contest_plugin->generate_html_user_problems_summary)(cs->contest_plugin_data, us_file, fout, cnts, cs, phr->user_id, accepting_mode, "b1", solved_flag, accepted_flag, pending_flag, trans_flag, best_run, attempts, disqualified, best_score, prev_successes);
        fclose(us_file); us_file = 0;
        xfree(us_text); us_text = 0;
      } else {
        ns_write_user_problems_summary(cnts, cs, fout, phr->user_id,
                                       accepting_mode, "b1",
                                       solved_flag, accepted_flag, pending_flag,
                                       trans_flag, best_run, attempts,
                                       disqualified, best_score,
                                       prev_successes);
      }
    }
  }

  if (phr->action == NEW_SRV_ACTION_VIEW_PROBLEM_STATEMENTS
      && start_time > 0) {
    if (cnts->problems_url) {
      fprintf(fout, "<p><a href=\"%s\">%s</a></p>\n",
              cnts->problems_url, _("Problem statements"));
    }
    // if prob_id == -1, show all available problem statements
    if (prob_id == -1) {
      first_prob_id = 1;
      last_prob_id = cs->max_prob;
    } else {
      first_prob_id = prob_id;
      last_prob_id = prob_id;
    }
    for (prob_id = first_prob_id; prob_id <= last_prob_id; prob_id++) {
      variant = 0;
      if (prob_id <= 0 || prob_id > cs->max_prob) continue;
      if (!(prob = cs->probs[prob_id])) continue;
      if (is_problem_deadlined(cs, prob_id, phr->login, 0)) continue;
      if (prob->t_start_date > 0 && cs->current_time < prob->t_start_date)
        continue;
      if (prob->variant_num > 0
          && (variant = find_variant(cs, phr->user_id, prob_id, 0)) <= 0)
        continue;
      if (!prob->statement_file[0]) continue;
      if (variant > 0) {
        prepare_insert_variant_num(variant_stmt_file, sizeof(variant_stmt_file),
                                   prob->statement_file, variant);
        pw = &cs->prob_extras[prob_id].v_stmts[variant];
        pw_path = variant_stmt_file;
      } else {
        pw = &cs->prob_extras[prob_id].stmt;
        pw_path = prob->statement_file;
      }
      watched_file_update(pw, pw_path, cs->current_time);
      if (!pw->text) continue;

      fprintf(fout, "%s", pw->text);
    }

    fprintf(fout, "<%s>%s</%s>\n",
            cnts->team_head_style, _("Select another problem"),
            cnts->team_head_style);
    html_start_form(fout, 0, phr->self_url, phr->hidden_vars);
    fprintf(fout, "<table class=\"b0\">\n");
    fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">", _("Problem"));

    html_problem_selection_2(cs, fout, phr, 0, start_time);

    fprintf(fout, "</td><td class=\"b0\">%s</td></tr></table></form>\n",
            ns_submit_button(bb, sizeof(bb), 0,
                             NEW_SRV_ACTION_VIEW_PROBLEM_STATEMENTS,
                             _("Select problem")));
  }

  if (phr->action == NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT
      && !cs->clients_suspended) {
    if (prob_id > cs->max_prob) prob_id = 0;
    if (prob_id > 0 && !(prob = cs->probs[prob_id])) prob_id = 0;
    if (prob_id > 0 && is_problem_deadlined(cs, prob_id, phr->login, 0))
      prob_id = 0;
    if (prob_id > 0 && prob->t_start_date > 0
        && cs->current_time < prob->t_start_date)
      prob_id = 0;
    //if (prob_id > 0 && prob->disable_user_submit > 0) prob_id = 0;
    if (prob_id > 0 && prob->variant_num > 0
        && (variant = find_variant(cs, phr->user_id, prob_id, 0)) <= 0)
      prob_id = 0;

    if (start_time > 0 && stop_time <= 0 && !prob_id) {
      fprintf(fout, "<%s>%s</%s>\n",
              cnts->team_head_style,
              _("View the problem statement and send a submission"),
              cnts->team_head_style);
      html_start_form(fout, 0, phr->self_url, phr->hidden_vars);
      fprintf(fout, "<table class=\"b0\">\n");
      fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">", _("Problem"));

      html_problem_selection(cs, fout, phr, solved_flag, accepted_flag, 0, 0,
                             start_time);

      fprintf(fout, "</td><td class=\"b0\">%s</td></tr></table></form>\n",
              ns_submit_button(bb, sizeof(bb), 0, NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT,
                               _("Select problem")));
    } else if (start_time > 0 && stop_time <= 0 && prob_id > 0) {
      prob = cs->probs[prob_id];

      dbuf[0] = 0;
      if ((prob_status[prob_id] & PROB_STATUS_SUBMITTABLE)
          && prob->t_deadline > 0) {
        snprintf(dbuf, sizeof(dbuf), "<h3>%s: %s</h3>",
                 _("Problem deadline"), xml_unparse_date(prob->t_deadline));
      }

      bb[0] = 0;
      if (variant > 0) {
        snprintf(bb, sizeof(bb), "<%s>%s %s-%s (%s %d)</%s>%s\n",
                 cnts->team_head_style,
                 (prob_status[prob_id] & PROB_STATUS_SUBMITTABLE)?_("Submit a solution for"):_("Problem"),
                 prob->short_name, prob->long_name, _("Variant"), variant,
                 cnts->team_head_style, dbuf);
      } else {
        if (cnts->exam_mode) {
          /*
          if (prob->disable_user_submit > 0) {
            snprintf(bb, sizeof(bb), "<%s>%s</%s>\n",
                     cnts->team_head_style,
                     prob->long_name, cnts->team_head_style);
          } else {
            snprintf(bb, sizeof(bb), "<%s>%s %s</%s>\n",
                     cnts->team_head_style, _("Submit a solution for"),
                     prob->long_name, cnts->team_head_style);
          }
          */
          snprintf(bb, sizeof(bb), "<%s>%s %s</%s>%s\n",
                   cnts->team_head_style, _("Problem"),
                   prob->long_name, cnts->team_head_style, dbuf);
        } else {
          if (1 /*!(prob_status[prob_id] & PROB_STATUS_SUBMITTABLE)*/) {
            if (prob->long_name[0]) {
              snprintf(bb, sizeof(bb), "<%s>%s %s-%s</%s>%s\n",
                       cnts->team_head_style, _("Problem"),
                       prob->short_name, prob->long_name, cnts->team_head_style,
                       dbuf);
            } else {
              snprintf(bb, sizeof(bb), "<%s>%s %s</%s>%s\n",
                       cnts->team_head_style, _("Problem"),
                       prob->short_name, cnts->team_head_style, dbuf);
            }
          } else {
            if (prob->long_name[0]) {
              snprintf(bb, sizeof(bb), "<%s>%s %s-%s</%s>%s\n",
                       cnts->team_head_style, _("Submit a solution for"),
                       prob->short_name, prob->long_name, cnts->team_head_style,
                       dbuf);
            } else {
              snprintf(bb, sizeof(bb), "<%s>%s %s</%s>%s\n",
                       cnts->team_head_style, _("Submit a solution for"),
                       prob->short_name, cnts->team_head_style, dbuf);
            }
          }
        }
      }

      px = 0;
      if (variant > 0 && prob->xml.a && prob->xml.a[variant - 1]) {
        px = prob->xml.a[variant - 1];
      } else if (variant <= 0 && prob->xml.p) {
        px = prob->xml.p;
      }

      /* put problem statement */
      if (px && px->stmts) {
        unpriv_unparse_statement(fout, phr, cnts, extra, prob, px, bb);
      } else if (prob->statement_file[0]
          && (prob_status[prob_id] & PROB_STATUS_VIEWABLE)) {
        if (variant > 0) {
          prepare_insert_variant_num(variant_stmt_file,
                                     sizeof(variant_stmt_file),
                                     prob->statement_file, variant);
          pw = &cs->prob_extras[prob_id].v_stmts[variant];
          pw_path = variant_stmt_file;
        } else {
          pw = &cs->prob_extras[prob_id].stmt;
          pw_path = prob->statement_file;
        }
        watched_file_update(pw, pw_path, cs->current_time);
        if (!pw->text) {
          fprintf(fout, "%s<big><font color=\"red\"><p>%s</p></font></big>\n",
                  bb, _("The problem statement is not available"));
        } else {
          if (cnts->exam_mode) bb[0] = 0;
          fprintf(fout, "%s", bb);
          if ((prob_status[prob_id] & PROB_STATUS_SUBMITTABLE)
              && prob->type_val == PROB_TYPE_CUSTOM) {
            html_start_form(fout, 2, phr->self_url, phr->hidden_vars);
            skip_start_form = 1;
          }
          fprintf(fout, "%s", pw->text);
        }
      } else {
        fprintf(fout, "%s", bb);
      }

      if ((prob_status[prob_id] & PROB_STATUS_SUBMITTABLE)) {
        alternatives = 0;
        if ((prob->type_val == PROB_TYPE_SELECT_ONE
             || prob->type_val == PROB_TYPE_SELECT_MANY)
            && prob->alternatives_file[0]) {
          if (variant > 0) {
            prepare_insert_variant_num(variant_stmt_file,
                                       sizeof(variant_stmt_file),
                                       prob->alternatives_file, variant);
            pw = &cs->prob_extras[prob->id].v_alts[variant];
            pw_path = variant_stmt_file;
          } else {
            pw = &cs->prob_extras[prob->id].alt;
            pw_path = prob->alternatives_file;
          }
          watched_file_update(pw, pw_path, cs->current_time);
          alternatives = pw->text;
        }

        if (!skip_start_form) {
          html_start_form(fout, 2, phr->self_url, phr->hidden_vars);
        }
        fprintf(fout, "<input type=\"hidden\" name=\"prob_id\" value=\"%d\"/>\n",
                prob_id);
        fprintf(fout, "<table class=\"b0\">\n");
        if (!prob->type_val) {
          for (i = 1; i <= cs->max_lang; i++) {
            if (!cs->langs[i] || cs->langs[i]->disabled) continue;
            if ((lang_list = prob->enable_language)) {
              for (j = 0; lang_list[j]; j++)
                if (!strcmp(lang_list[j], cs->langs[i]->short_name))
                  break;
              if (!lang_list[j]) continue;
            } else if ((lang_list = prob->disable_language)) {
              for (j = 0; lang_list[j]; j++)
                if (!strcmp(lang_list[j], cs->langs[i]->short_name))
                  break;
              if (lang_list[j]) continue;
            }
            lang_count++;
            lang_id = i;
          }

          if (lang_count == 1) {
            html_hidden(fout, "lang_id", "%d", lang_id);
            fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">%s - %s</td></tr>\n",
                    _("Language"),
                    cs->langs[lang_id]->short_name,
                    cs->langs[lang_id]->long_name);
          } else {
            last_lang_id = get_last_language(cs, phr->user_id);
            fprintf(fout, "<tr><td class=\"b0\">%s:</td><td class=\"b0\">", _("Language"));
            fprintf(fout, "<select name=\"lang_id\"><option value=\"\">\n");
            for (i = 1; i <= cs->max_lang; i++) {
              if (!cs->langs[i] || cs->langs[i]->disabled) continue;
              if ((lang_list = prob->enable_language)) {
                for (j = 0; lang_list[j]; j++)
                  if (!strcmp(lang_list[j], cs->langs[i]->short_name))
                    break;
                if (!lang_list[j]) continue;
              } else if ((lang_list = prob->disable_language)) {
                for (j = 0; lang_list[j]; j++)
                  if (!strcmp(lang_list[j], cs->langs[i]->short_name))
                    break;
                if (lang_list[j]) continue;
              }
              cc = "";
              if (last_lang_id == i) cc = " selected=\"selected\"";
              fprintf(fout, "<option value=\"%d\"%s>%s - %s</option>\n",
                      i, cc, cs->langs[i]->short_name, cs->langs[i]->long_name);
            }
            fprintf(fout, "</select></td></tr>\n");
          }
        }
        switch (prob->type_val) {
        case PROB_TYPE_STANDARD:
          fprintf(fout, "<tr><td class=\"b0\">%s</td><td class=\"b0\"><input type=\"file\" name=\"file\"/></td></tr>\n", _("File"));
          break;
        case PROB_TYPE_OUTPUT_ONLY:
          if (prob->enable_text_form > 0) {
            fprintf(fout, "<tr><td colspan=\"2\" class=\"b0\"><textarea name=\"text_form\" rows=\"20\" cols=\"60\"></textarea></td></tr>\n");
          }
          fprintf(fout, "<tr><td class=\"b0\">%s</td><td class=\"b0\"><input type=\"file\" name=\"file\"/></td></tr>\n", _("File"));
          break;
        case PROB_TYPE_SHORT_ANSWER:
          last_source = 0;
          if (cnts->exam_mode) {
            last_source = get_last_source(cs, phr->user_id, prob->id);
          }
          if (last_source) {
            fprintf(fout, "<tr><td class=\"b0\">%s</td><td class=\"b0\"><input type=\"text\" name=\"file\" value=\"%s\"/></td></tr>\n", _("Answer"), ARMOR(last_source));
          } else {
            fprintf(fout, "<tr><td class=\"b0\">%s</td><td class=\"b0\"><input type=\"text\" name=\"file\"/></td></tr>\n", _("Answer"));
          }
        xfree(last_source); last_source = 0;
          break;
        case PROB_TYPE_TEXT_ANSWER:
          fprintf(fout, "<tr><td colspan=\"2\" class=\"b0\"><textarea name=\"file\" rows=\"20\" cols=\"60\"></textarea></td></tr>\n");
          break;
        case PROB_TYPE_SELECT_ONE:
          last_answer = -1;
          if (cnts->exam_mode) {
            last_answer = get_last_answer_select_one(cs, phr->user_id,
                                                     prob->id);
          }

          if (px) {
            next_prob_id = prob->id;
            if (cnts->exam_mode) {
              if (prob->advance_to_next > 0) {
                next_prob_id++;
                for (; next_prob_id <= cs->max_prob; next_prob_id++) {
                  if (!(prob2 = cs->probs[next_prob_id])) continue;
                  if (prob2->t_start_date > 0
                      && prob2->t_start_date > cs->current_time) continue;
                  break;
                }
                if (next_prob_id > cs->max_prob) next_prob_id = prob->id;
              }
              unpriv_unparse_answers(fout, phr, cnts, extra, prob,
                                     px, 0 /* lang */, 1 /* is_radio */,
                                     last_answer, next_prob_id,
                                     1 /* js_flag */, "b0");
            } else {
              unpriv_unparse_answers(fout, phr, cnts, extra, prob,
                                     px, 0 /* lang */, 1 /* is_radio */,
                                     last_answer, next_prob_id,
                                     0 /* js_flag */, "b0");
            }
          } else if (alternatives) {
            if (cnts->exam_mode) {
              next_prob_id = prob->id;
              if (prob->advance_to_next > 0) {
                next_prob_id++;
                for (; next_prob_id <= cs->max_prob; next_prob_id++) {
                  if (!(prob2 = cs->probs[next_prob_id])) continue;
                  if (prob2->t_start_date > 0
                      && prob2->t_start_date > cs->current_time) continue;
                  break;
                }
                if (next_prob_id > cs->max_prob) next_prob_id = prob->id;
              }
              write_alternatives_file(fout, 1, alternatives, last_answer,
                                      prob->id, next_prob_id, 1, "b0");
            } else {
              write_alternatives_file(fout, 1, alternatives, last_answer,
                                      0, 0, 0, "b0");
            }
          } else if (prob->alternative) {
            for (i = 0; prob->alternative[i]; i++) {
              cc = "";
              if (i + 1 == last_answer) cc = " checked=\"1\"";
              fprintf(fout, "<tr><td class=\"b0\">%d</td><td class=\"b0\"><input type=\"radio\" name=\"file\" value=\"%d\"%s/></td><td>%s</td></tr>\n", i + 1, i + 1, cc, prob->alternative[i]);
            }
          }
          break;
        case PROB_TYPE_SELECT_MANY:
          if (alternatives) {
            write_alternatives_file(fout, 0, alternatives, -1, 0, 0, 0, "b0");
          } else if (prob->alternative) {
            for (i = 0; prob->alternative[i]; i++) {
              fprintf(fout, "<tr><td class=\"b0\">%d</td><td class=\"b0\"><input type=\"checkbox\" name=\"ans_%d\"/></td><td>%s</td></tr>\n", i + 1, i + 1, prob->alternative[i]);
            }
          }
          break;
        case PROB_TYPE_CUSTOM:
          break;
        }
        if (cnts->exam_mode) {
          if (prob->type_val != PROB_TYPE_SELECT_ONE) {
            cc = "";
            if (prob && (prob->type_val == PROB_TYPE_SELECT_MANY || prob->type_val == PROB_TYPE_SELECT_ONE)) cc = "<td class=\"b0\">&nbsp;</td>";
            fprintf(fout, "<tr>%s<td class=\"b0\">&nbsp;</td><td class=\"b0\">%s</td></tr></table></form>\n", cc,
                    ns_submit_button(bb, sizeof(bb), 0,
                                     NEW_SRV_ACTION_SUBMIT_RUN,
                                     _("Submit solution!")));
          } else {
            fprintf(fout, "</tr></table></form>\n");
          }
        } else {
          fprintf(fout, "<tr><td class=\"b0\">%s</td><td class=\"b0\">%s</td></tr></table></form>\n",
                  _("Send!"),
                  BUTTON(NEW_SRV_ACTION_SUBMIT_RUN));
        }
      } /* prob->disable_user_submit <= 0 */

      if (global->problem_navigation
          && !prob->disable_user_submit
          && prob->type_val != PROB_TYPE_SELECT_ONE
          && all_attempts[prob->id]) {
        if (all_attempts[prob->id] <= 15) {
          fprintf(fout, "<%s>%s</%s>\n",
                  cnts->team_head_style,
                  _("Previous submissions of this problem"),
                  cnts->team_head_style);
        } else {
          fprintf(fout, "<%s>%s (%s)</%s>\n",
                  cnts->team_head_style,
                  _("Previous submissions of this problem"),
                  /*all_runs?_("all"):*/_("last 15"),
                  cnts->team_head_style);
        }
        if (cs->contest_plugin && cs->contest_plugin->generate_html_user_runs){
          // FIXME: logged output is also ignored
          // FIXME: return code is ignored for now
          char *ur_text = 0;
          size_t ur_size = 0;
          FILE *ur_file = open_memstream(&ur_text, &ur_size);
          (*cs->contest_plugin->generate_html_user_runs)(cs->contest_plugin_data, ur_file, fout, cnts, cs, phr, phr->user_id, prob_id, all_runs, "b1");
          fclose(ur_file); ur_file = 0;
          xfree(ur_text); ur_text = 0;
        } else if (global->score_system_val == SCORE_OLYMPIAD) {
          ns_write_olympiads_user_runs(phr, fout, cnts, extra, all_runs,
                                       prob_id, "b1");
        } else {
          new_write_user_runs(cs, fout, phr->user_id, all_runs, prob->id,
                              NEW_SRV_ACTION_VIEW_SOURCE,
                              NEW_SRV_ACTION_VIEW_REPORT,
                              NEW_SRV_ACTION_PRINT_RUN,
                              phr->session_id, phr->self_url,
                              phr->hidden_vars, "", "b1");
        }
      }

      if (!cnts->exam_mode) {
        if (global->problem_navigation <= 0) {
          fprintf(fout, "<%s>%s</%s>\n",
                  cnts->team_head_style, _("Select another problem"),
                  cnts->team_head_style);
        } else {
          /*
          fprintf(fout, "<%s>%s</%s>\n",
                  cnts->team_head_style, _("Problem navigation"),
                  cnts->team_head_style);
          */
        }
        html_start_form(fout, 0, phr->self_url, phr->hidden_vars);
        fprintf(fout, "<table class=\"b0\">\n");
        fprintf(fout, "<tr>");

        if (global->problem_navigation > 0) {
          for (i = prob_id - 1; i > 0; i--) {
            if (!(prob_status[i] & PROB_STATUS_GOOD)) continue;
            break;
          }
          if (i > 0) {
            fprintf(fout, "<td class=\"b0\">%s%s</a></td>",
                    ns_aref(bb, sizeof(bb), phr,
                            NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT,
                            "prob_id=%d", i), _("Previous problem"));
          }
        }

        if (global->problem_navigation <= 0) {
          fprintf(fout, "<td class=\"b0\">%s:</td><td class=\"b0\">", _("Problem"));
          html_problem_selection(cs, fout, phr, solved_flag, accepted_flag, 0,
                                 0, start_time);
          fprintf(fout, "</td><td class=\"b0\">%s</td>",
                  ns_submit_button(bb, sizeof(bb), 0,
                                   NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT,
                                   _("Select problem")));
        }

        if (global->problem_navigation > 0) {
          for (i = prob_id + 1; i <= cs->max_prob; i++) {
            if (!(prob_status[i] & PROB_STATUS_GOOD)) continue;
            break;
          }
          if (i <= cs->max_prob) {
            fprintf(fout, "<td class=\"b0\">%s%s</a></td>",
                    ns_aref(bb, sizeof(bb), phr,
                            NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT,
                            "prob_id=%d", i), _("Next problem"));
          }
        }

      fprintf(fout, "</tr></table></form>\n");
      }
    }
  }

  if (phr->action == NEW_SRV_ACTION_VIEW_SUBMISSIONS && start_time > 0) {
    fprintf(fout, "<%s>%s (%s)</%s>\n",
            cnts->team_head_style,
            _("Sent submissions"),
            all_runs?_("all"):_("last 15"),
            cnts->team_head_style);
    if (global->score_system_val == SCORE_OLYMPIAD) {
      ns_write_olympiads_user_runs(phr, fout, cnts, extra, all_runs,
                                   0, "b1");
    } else {
      new_write_user_runs(cs, fout, phr->user_id, all_runs, 0,
                          NEW_SRV_ACTION_VIEW_SOURCE,
                          NEW_SRV_ACTION_VIEW_REPORT,
                          NEW_SRV_ACTION_PRINT_RUN,
                          phr->session_id, phr->self_url,
                          phr->hidden_vars, "", "b1");
    }
    if (all_runs) s = _("View last 15");
    else s = _("View all");
    fprintf(fout, "<p><a href=\"%s?SID=%016llx&amp;all_runs=%d&amp;action=%d\">%s</a></p>\n", phr->self_url, phr->session_id, !all_runs, NEW_SRV_ACTION_VIEW_SUBMISSIONS, s);
  }


  if (phr->action == NEW_SRV_ACTION_VIEW_CLAR_SUBMIT
      && !cs->clients_suspended) {
    if (!global->disable_clars && !global->disable_team_clars
        && start_time > 0 && stop_time <= 0) {
      fprintf(fout, "<%s>%s</%s>\n",
              cnts->team_head_style, _("Send a message to judges"),
              cnts->team_head_style);
      html_start_form(fout, 2, phr->self_url, phr->hidden_vars);
      fprintf(fout, "<table class=\"b0\"><tr><td class=\"b0\">%s:</td><td class=\"b0\">", _("Problem"));
      html_problem_selection(cs, fout, phr, solved_flag, accepted_flag, 0, 1,
                             start_time);
      fprintf(fout, "</td></tr>\n<tr><td class=\"b0\">%s:</td>"
              "<td class=\"b0\"><input type=\"text\" name=\"subject\"/></td></tr>\n"
              "<tr><td colspan=\"2\" class=\"b0\"><textarea name=\"text\" rows=\"20\" cols=\"60\"></textarea></td></tr>\n"
              "<tr><td colspan=\"2\" class=\"b0\">%s</td></tr>\n"
              "</table></form>\n",
              _("Subject"), BUTTON(NEW_SRV_ACTION_SUBMIT_CLAR));
    }
    if (!global->disable_clars && !global->disable_team_clars
        && start_time > 0 && stop_time > 0
        && global->appeal_deadline_d > 0
        && cs->current_time < global->appeal_deadline_d) {
      fprintf(fout, "<%s>%s</%s>\n",
              cnts->team_head_style, _("Send an appeal"),
              cnts->team_head_style);
      html_start_form(fout, 2, phr->self_url, phr->hidden_vars);
      fprintf(fout, "<table class=\"b0\"><tr><td class=\"b0\">%s:</td><td class=\"b0\">", _("Problem"));
      html_problem_selection(cs, fout, phr, solved_flag, accepted_flag, 0, 1,
                             start_time);
      fprintf(fout, "</td></tr>\n<tr><td class=\"b0\">%s:</td>"
              "<td class=\"b0\"><input type=\"text\" name=\"test\"/></td></tr>\n"
              "<tr><td colspan=\"2\" class=\"b0\"><textarea name=\"text\" rows=\"20\" cols=\"60\"></textarea></td></tr>\n"
              "<tr><td colspan=\"2\" class=\"b0\">%s</td></tr>\n"
              "</table></form>\n",
              _("Test number"), BUTTON(NEW_SRV_ACTION_SUBMIT_APPEAL));
    }
  }

  if (phr->action == NEW_SRV_ACTION_VIEW_CLARS && !global->disable_clars) {
    fprintf(fout, "<%s>%s (%s)</%s>\n",
            cnts->team_head_style, _("Messages"),
            all_clars?_("all"):_("last 15"), cnts->team_head_style);

    new_write_user_clars(cs, fout, phr->user_id, all_clars,
                         NEW_SRV_ACTION_VIEW_CLAR,
                         phr->session_id,
                         phr->self_url, phr->hidden_vars, "", "b1");

    if (all_clars) s = _("View last 15");
    else s = _("View all");
    fprintf(fout, "<p><a href=\"%s?SID=%016llx&amp;all_clars=%d&amp;action=%d\">%s</a></p>\n", phr->self_url, phr->session_id, !all_clars, NEW_SRV_ACTION_VIEW_CLARS, s);
  }

  if (phr->action == NEW_SRV_ACTION_VIEW_SETTINGS) {
    /* change the password */
    if (!cs->clients_suspended) {
      fprintf(fout, "<%s>%s</%s>\n",
              cnts->team_head_style,
              _("Change password"),
              cnts->team_head_style);
      html_start_form(fout, 1, phr->self_url, phr->hidden_vars);

      fprintf(fout, "<table class=\"b0\">\n"
              "<tr><td class=\"b0\">%s:</td><td class=\"b0\"><input type=\"password\" name=\"oldpasswd\" size=\"16\"/></td></tr>\n"
              "<tr><td class=\"b0\">%s:</td><td class=\"b0\"><input type=\"password\" name=\"newpasswd1\" size=\"16\"/></td></tr>\n"
              "<tr><td class=\"b0\">%s:</td><td class=\"b0\"><input type=\"password\" name=\"newpasswd2\" size=\"16\"/></td></tr>\n"
              "<tr><td class=\"b0\" colspan=\"2\"><input type=\"submit\" name=\"action_%d\" value=\"%s\"/></td></tr>\n"
              "</table></form>",
              _("Old password"),
              _("New password"), _("Retype new password"),
              NEW_SRV_ACTION_CHANGE_PASSWORD, _("Change!"));
    }

#if CONF_HAS_LIBINTL - 0 == 1
    if (global->enable_l10n && !cs->clients_suspended
        && !cnts->disable_locale_change) {
      fprintf(fout, "<%s>%s</%s>\n",
              cnts->team_head_style, _("Change language"),
              cnts->team_head_style);
      html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
      fprintf(fout, "<table class=\"b0\"><tr><td class=\"b0\">%s</td><td class=\"b0\">", _("Change language"));
      l10n_html_locale_select(fout, phr->locale_id);
      fprintf(fout, "</td><td class=\"b0\"><input type=\"submit\" name=\"action_%d\" value=\"%s\"/></td></tr></table></form>\n",
              NEW_SRV_ACTION_CHANGE_LANGUAGE, _("Change"));
    }
#endif /* CONF_HAS_LIBINTL */
  }

  /* new problem navigation */
  if (global->problem_navigation > 0 && global->vertical_navigation > 0
      && start_time > 0 && stop_time <= 0) {
    fprintf(fout, "</div></td><td class=\"b0\" id=\"probNavRightList\" valign=\"top\">\n");
    prev_group_name[0] = 0;

    for (i = 1, j = 0; i <= cs->max_prob; i++) {
      if (!(prob = cs->probs[i])) continue;
      if (!(prob_status[i] & PROB_STATUS_TABABLE)) continue;

      if (prob->group_name[0] && strcmp(prob->group_name, prev_group_name)) {
        fprintf(fout, "<div class=\"%s\">", "probDisabled");
        fprintf(fout, "%s", prob->group_name);
        fprintf(fout, "</div>\n");
        snprintf(prev_group_name, sizeof(prev_group_name),
                 "%s", prob->group_name);
      }

      if (i == prob_id) {
        cc = "probCurrent";
      } else if (prob->disable_user_submit > 0) {
        cc = "probDisabled";
      } else if (!all_attempts[i]) {
        cc = "probEmpty";
      } else if (pending_flag[i] || trans_flag[i]) {
        cc = "probTrans";
      } else if (accepted_flag[i] || solved_flag[i]) {
        cc = "probOk";
      } else {
        cc = "probBad";
      }
      fprintf(fout, "<div class=\"%s\">", cc);
      /*
      if (accepting_mode && accepted_flag[i]) {
        fprintf(fout, "<s>");
      }
      */
      fprintf(fout, "%s%s</a>",
              ns_aref_2(bb, sizeof(bb), phr, "tab",
                        NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT,
                        "prob_id=%d", i), prob->short_name);
      /*
      if (accepting_mode && accepted_flag[i]) {
        fprintf(fout, "</s>");
      }
      */
      fprintf(fout, "</div>\n");
      j++;
    }
    fprintf(fout, "</td></tr></table>\n");
  } else if (global->problem_navigation > 0
             && start_time > 0 && stop_time <= 0) {
    fprintf(fout, "</div></td></tr>\n");
    fprintf(fout, "<tr id=\"probNavBottomList\">\n");
    for (i = 1, j = 0; i <= cs->max_prob; i++) {
      if (!(prob = cs->probs[i])) continue;
      if (!(prob_status[i] & PROB_STATUS_TABABLE)) continue;

      if (j > 0) {
        fprintf(fout, "<td class=\"probNavSpaceBottom\">&nbsp;</td>");
        j++;
      }
      hh = "probNavHidden";
      if (upper_tab_id == i) hh = "probNavActiveBottom";
      if (i == upper_tab_id) {
        cc = "probCurrent";
      } else if (prob->disable_user_submit > 0) {
        cc = "probDisabled";
      } else if (!all_attempts[i]) {
        cc = "probEmpty";
      } else if (pending_flag[i] || trans_flag[i]) {
        cc = "probTrans";
      } else if (accepted_flag[i] || solved_flag[i]) {
        cc = "probOk";
      } else {
        cc = "probBad";
      }
      wbuf[0] = 0;
      if (global->problem_tab_size > 0)
        snprintf(wbuf, sizeof(wbuf), " width=\"%dpx\"",
                 global->problem_tab_size);
      fprintf(fout, "<td class=\"%s\" onclick=\"displayProblemSubmitForm(%d)\"%s><div class=\"%s\">", hh, i, wbuf, cc);
      /*
      if (accepting_mode && accepted_flag[i]) {
        fprintf(fout, "<s>");
      }
      */
      fprintf(fout, "%s%s</a>",
              ns_aref_2(bb, sizeof(bb), phr, "tab",
                        NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT,
                        "prob_id=%d", i), prob->short_name);
      /*
      if (accepting_mode && accepted_flag[i]) {
        fprintf(fout, "</s>");
      }
      */
      fprintf(fout, "</div></td>\n");
      j++;
    }
    fprintf(fout, "</tr></table>\n");
  }

#if 0
  if (!cnts->exam_mode /*&& global->show_generation_time*/) {
    gettimeofday(&phr->timestamp2, 0);
    tdiff = ((long long) phr->timestamp2.tv_sec) * 1000000;
    tdiff += phr->timestamp2.tv_usec;
    tdiff -= ((long long) phr->timestamp1.tv_sec) * 1000000;
    tdiff -= phr->timestamp1.tv_usec;
    fprintf(fout, "<div class=\"dotted\"><p class=\"dotted\">%s: %lld %s</p></div>",
            _("Page generation time"), tdiff / 1000,
            _("msec"));
  }
#endif

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_setlocale(0);
  html_armor_free(&ab);
}

static void
unpriv_logout(FILE *fout,
              struct http_request_info *phr,
              const struct contest_desc *cnts,
              struct contest_extra *extra)
{
  //unsigned char locale_buf[64];
  unsigned char urlbuf[1024];

  if (ns_open_ul_connection(phr->fw_state) < 0)
    return ns_html_err_ul_server_down(fout, phr, 0, 0);
  userlist_clnt_delete_cookie(ul_conn, phr->user_id, phr->contest_id,
                              phr->session_id);
  ns_remove_session(phr->session_id);
  snprintf(urlbuf, sizeof(urlbuf),
           "%s?contest_id=%d&locale_id=%d",
           phr->self_url, phr->contest_id, phr->locale_id);
  ns_refresh_page_2(fout, urlbuf);
}

static void
do_xml_user_state(FILE *fout, const serve_state_t cs, int user_id)
{
  const struct section_global_data *global = cs->global;
  struct tm *ptm;
  time_t start_time = 0, stop_time = 0, duration = 0, remaining;

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, user_id,
                                          cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state);
  }
  duration = run_get_duration(cs->runlog_state);

  ptm = localtime(&cs->current_time);
  fprintf(fout, "<t>"
          "<h>%02d</h>"
          "<m>%02d</m>"
          "<s>%02d</s>"
          "<d>%02d</d>"
          "<o>%02d</o>"
          "<y>%d</y>",
          ptm->tm_hour, ptm->tm_min, ptm->tm_sec,
          ptm->tm_mday, ptm->tm_mon + 1, ptm->tm_year + 1900);
  if (start_time > 0 && stop_time <= 0 && duration > 0) {
    remaining = start_time + duration - cs->current_time;
    if (remaining < 0) remaining = 0;
    fprintf(fout, "<r>%ld</r>", remaining);
  }
  if (run_has_transient_user_runs(cs->runlog_state, user_id) ||
      (global->score_system_val == SCORE_OLYMPIAD
       && global->is_virtual
       && stop_time > 0
       && global->disable_virtual_auto_judge <= 0
       && !is_judged_virtual_olympiad(cs, user_id))) {
    fprintf(fout, "<x>1</x>");
  }
  fprintf(fout, "</t>");
}

static void
unpriv_xml_user_state(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;

  fprintf(fout, "Content-type: text/xml\n"
          "Cache-Control: no-cache\n\n");
  fprintf(fout, "<?xml version=\"1.0\" encoding=\"%s\"?>", EJUDGE_CHARSET);
  do_xml_user_state(fout, cs, phr->user_id);
}

static void
unpriv_xml_update_answer(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = 0;
  int retval = 0;
  const unsigned char *s;
  int prob_id = 0, n, ans, i, variant = 0, j, run_id;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *run_text = 0, *login = 0;
  unsigned char *tmp_txt = 0;
  size_t run_size = 0, tmp_size = 0;
  char *eptr;
  time_t start_time, stop_time, user_deadline = 0;
  ruint32_t shaval[5];
  unsigned char *acc_probs = 0;
  struct timeval precise_time;
  int new_flag = 0, arch_flags = 0;
  path_t run_path;
  struct run_entry nv;

  if (global->score_system_val != SCORE_OLYMPIAD
      || !cs->accepting_mode) FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (ns_cgi_param(phr, "prob_id", &s) <= 0
      || sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n]
      || prob_id <= 0 || prob_id > cs->max_prob
      || !(prob = cs->probs[prob_id]))
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  if (prob->type_val != PROB_TYPE_SELECT_ONE)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (!ns_cgi_param_bin(phr, "file", &run_text, &run_size))
    FAIL(NEW_SRV_ERR_ANSWER_UNSPECIFIED);
  if (strlen(run_text) != run_size)
    FAIL(NEW_SRV_ERR_BINARY_FILE);
  if (!run_size)
    FAIL(NEW_SRV_ERR_SUBMIT_EMPTY);

  tmp_txt = alloca(run_size + 1);
  memcpy(tmp_txt, run_text, run_size);
  tmp_txt[run_size] = 0;
  tmp_size = run_size;
  while (tmp_size > 0 && isspace(tmp_txt[tmp_size])) tmp_size--;
  tmp_txt[tmp_size] = 0;
  if (!tmp_size) FAIL(NEW_SRV_ERR_SUBMIT_EMPTY);
  errno = 0;
  ans = strtol(tmp_txt, &eptr, 10);
  if (errno || *eptr || ans < 0) FAIL(NEW_SRV_ERR_INV_ANSWER);

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state);
  }

  if (cs->clients_suspended) FAIL(NEW_SRV_ERR_CLIENTS_SUSPENDED);
  if (!start_time) FAIL(NEW_SRV_ERR_CONTEST_NOT_STARTED);
  if (stop_time) FAIL(NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
  if (serve_check_user_quota(cs, phr->user_id, run_size) < 0)
    FAIL(NEW_SRV_ERR_RUN_QUOTA_EXCEEDED);
  // problem submit start time
  if (prob->t_start_date >= 0 && cs->current_time < prob->t_start_date)
    FAIL(NEW_SRV_ERR_PROB_UNAVAILABLE);
  // personal deadline
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

  if (prob->variant_num > 0) {
    if ((variant = find_variant(cs, phr->user_id, prob_id, 0)) <= 0)
      FAIL(NEW_SRV_ERR_VARIANT_UNASSIGNED);
  }

  sha_buffer(run_text, run_size, shaval);

  if (prob->require) {
    if (!acc_probs) {
      XALLOCAZ(acc_probs, cs->max_prob + 1);
      run_get_accepted_set(cs->runlog_state, phr->user_id,
                           cs->accepting_mode, cs->max_prob, acc_probs);
    }
    for (i = 0; prob->require[i]; i++) {
      for (j = 1; j <= cs->max_prob; j++)
        if (cs->probs[j] && !strcmp(cs->probs[j]->short_name, prob->require[i]))
          break;
      if (j > cs->max_prob || !acc_probs[j]) break;
    }
    if (prob->require[i]) FAIL(NEW_SRV_ERR_NOT_ALL_REQ_SOLVED);
  }

  run_id = run_find(cs->runlog_state, -1, 0, phr->user_id, prob->id, 0);
  if (run_id < 0) {
    gettimeofday(&precise_time, 0);
    run_id = run_add_record(cs->runlog_state, 
                            precise_time.tv_sec, precise_time.tv_usec * 1000,
                            run_size, shaval,
                            phr->ip, phr->ssl_flag,
                            phr->locale_id, phr->user_id,
                            prob_id, 0, 0, 0, 0);
    if (run_id < 0) FAIL(NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
    serve_move_files_to_insert_run(cs, run_id);
    new_flag = 1;
  }

  arch_flags = archive_make_write_path(cs, run_path, sizeof(run_path),
                                       global->run_archive_dir, run_id,
                                       run_size, 0);
  if (arch_flags < 0) {
    if (new_flag) run_undo_add_record(cs->runlog_state, run_id);
    FAIL(NEW_SRV_ERR_DISK_WRITE_ERROR);
  }
  if (archive_dir_prepare(cs, global->run_archive_dir, run_id, 0, 0) < 0) {
    if (new_flag) run_undo_add_record(cs->runlog_state, run_id);
    FAIL(NEW_SRV_ERR_DISK_WRITE_ERROR);
  }
  if (generic_write_file(run_text, run_size, arch_flags, 0, run_path, "") < 0) {
    if (new_flag) run_undo_add_record(cs->runlog_state, run_id);
    FAIL(NEW_SRV_ERR_DISK_WRITE_ERROR);
  }

  memset(&nv, 0, sizeof(nv));
  nv.size = run_size;
  memcpy(nv.sha1, shaval, sizeof(nv.sha1));
  nv.status = RUN_ACCEPTED;
  nv.test = 0;
  nv.score = -1;
  run_set_entry(cs->runlog_state, run_id,
                RUN_ENTRY_SIZE | RUN_ENTRY_SHA1 | RUN_ENTRY_STATUS
                | RUN_ENTRY_TEST | RUN_ENTRY_SCORE,
                &nv);

  serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                  "Command: submit\n"
                  "Status: accepted\n"
                  "Run-id: %d\n", run_id);


 cleanup:
  fprintf(fout, "Content-type: text/xml\n"
          "Cache-Control: no-cache\n\n");
  fprintf(fout, "<?xml version=\"1.0\" encoding=\"%s\"?>", EJUDGE_CHARSET);
  if (!retval) {
    fprintf(fout, "<r><s>%d</s></r>", retval);
  } else {
    l10n_setlocale(phr->locale_id);
    fprintf(fout, "<r><s>%d</s><t>%s</t></r>", -retval,
            ARMOR(ns_strerror_2(retval)));
    l10n_setlocale(0);
  }

  html_armor_free(&ab);
}

static void
unpriv_get_file(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = 0;
  int retval = 0, prob_id, n, variant = 0, i, mime_type = 0;
  const unsigned char *s = 0;
  const unsigned char *login = 0;
  time_t user_deadline = 0, start_time, stop_time;
  path_t fpath, sfx;
  char *file_bytes = 0;
  size_t file_size = 0;
  const unsigned char *content_type = 0;

  if (ns_cgi_param(phr, "prob_id", &s) <= 0
      || sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n]
      || prob_id <= 0 || prob_id > cs->max_prob
      || !(prob = cs->probs[prob_id]))
    FAIL(NEW_SRV_ERR_INV_PROB_ID);

  // check, that this problem may be viewed
  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state);
  }

  if (cs->clients_suspended) FAIL(NEW_SRV_ERR_CLIENTS_SUSPENDED);
  if (start_time <= 0) FAIL(NEW_SRV_ERR_CONTEST_NOT_STARTED);
  if (stop_time > 0 && cs->current_time >= stop_time
      && prob->restricted_statement > 0)
    FAIL(NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
  if (prob->t_start_date > 0 && prob->t_start_date > cs->current_time)
    FAIL(NEW_SRV_ERR_PROB_UNAVAILABLE);
      
  // personal deadline
  if (prob->pd_total > 0) {
    login = teamdb_get_login(cs->teamdb_state, phr->user_id);
    for (i = 0; i < prob->pd_total; i++) {
      if (!strcmp(login, prob->pd_infos[i].login)) {
        user_deadline = prob->pd_infos[i].deadline;
        break;
      }
    }
  }
  if (user_deadline <= 0) user_deadline = prob->t_deadline;
  if (user_deadline > 0 && cs->current_time >= user_deadline
      && prob->restricted_statement > 0)
    FAIL(NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);

  // FIXME: check requisites
  /*
    // the problem is completely disabled before requirements are met
    // check requirements
    if (prob->require) {
      for (j = 0; prob->require[j]; j++) {
        for (k = 1; k <= cs->max_prob; k++) {
          if (cs->probs[k]
              && !strcmp(cs->probs[k]->short_name, prob->require[j]))
            break;
        }
        // no such problem :(
        if (k > cs->max_prob) break;
        // this problem is not yet accepted or solved
        if (!solved_flag[k] && !accepted_flag[k]) break;
      }
      // if the requirements are not met, skip this problem
      if (prob->require[j]) continue;
    }
   */

  if (prob->variant_num > 0
      && (variant = find_variant(cs, phr->user_id, prob_id, 0)) <= 0)
      FAIL(NEW_SRV_ERR_VARIANT_UNASSIGNED);

  if (ns_cgi_param(phr, "file", &s) <= 0 || strchr(s, '/'))
    FAIL(NEW_SRV_ERR_INV_FILE_NAME);

  os_rGetSuffix(s, sfx, sizeof(sfx));
  if (variant > 0) {
    snprintf(fpath, sizeof(fpath), "%s/%s-%d/%s",
             global->statement_dir, prob->short_name, variant, s);
  } else {
    snprintf(fpath, sizeof(fpath), "%s/%s/%s",
             global->statement_dir, prob->short_name, s);
  }
  mime_type = mime_type_parse_suffix(sfx);
  content_type = mime_type_get_type(mime_type);

  if (generic_read_file(&file_bytes, 0, &file_size, 0, 0, fpath, "") < 0)
    FAIL(NEW_SRV_ERR_INV_FILE_NAME);

  fprintf(fout, "Content-type: %s\n\n", content_type);
  fwrite(file_bytes, 1, file_size, fout);

 cleanup:
  if (retval) {
    snprintf(fpath, sizeof(fpath), "Error %d", -retval);
    html_error_status_page(fout, phr, cnts, extra, fpath,
                           NEW_SRV_ACTION_MAIN_PAGE, 0);
  }
  xfree(file_bytes);
}

static void
anon_select_contest_page(FILE *fout, struct http_request_info *phr)
  __attribute__((unused));
static void
anon_select_contest_page(FILE *fout, struct http_request_info *phr)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char *cntslist = 0;
  int cntsnum = 0;
  const unsigned char *cl;
  const struct contest_desc *cnts;
  time_t curtime = time(0);
  int row = 0, i, orig_locale_id;
  const unsigned char *s;
  const unsigned char *login = 0;
  unsigned char bb[1024];

  ns_cgi_param(phr, "login", &login);

  // defaulting to English as we have no contest chosen
  orig_locale_id = phr->locale_id;
  if (phr->locale_id < 0) phr->locale_id = 0;

  // even don't know about the contest specific settings
  l10n_setlocale(phr->locale_id);
  ns_header(fout, ns_fancy_header, 0, 0, 0, 0, phr->locale_id,
            _("Contest selection"));

  html_start_form(fout, 1, phr->self_url, "");
  fprintf(fout, "<div class=\"user_actions\"><table class=\"menu\"><tr>\n");
  html_hidden(fout, "action", "%d", NEW_SRV_ACTION_CHANGE_LANGUAGE);
  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s: ",
          _("language"));
  l10n_html_locale_select(fout, phr->locale_id);
  fprintf(fout, "</div></td>\n");
  fprintf(fout, "<td class=\"menu\"><div class=\"user_action_item\">%s</div></td>\n", ns_submit_button(bb, sizeof(bb), "submit", 0, _("Change Language")));
  fprintf(fout, "</tr></table></div></form>\n");

  fprintf(fout,
          "<div class=\"white_empty_block\">&nbsp;</div>\n"
          "<div class=\"contest_actions\"><table class=\"menu\"><tr>\n");

  fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td></tr></table></div>\n");

  fprintf(fout, "%s", ns_fancy_separator);

  fprintf(fout, "<h2>%s</h2>\n", _("Select one of available contests"));

  cntsnum = contests_get_list(&cntslist);
  cl = " class=\"b1\"";
  fprintf(fout, "<table%s><tr>"
          "<td%s>N</td><td%s>%s</td></tr>\n",
          cl, cl, cl, _("Contest name"));
  for (i = 1; i < cntsnum; i++) {
    cnts = 0;
    if (contests_get(i, &cnts) < 0 || !cnts) continue;
    if (cnts->closed) continue;
    if (!contests_check_register_ip_2(cnts, phr->ip, phr->ssl_flag)) continue;
    if (cnts->reg_deadline > 0 && curtime >= cnts->reg_deadline) continue;

    fprintf(fout, "<tr%s><td%s>%d</td>", form_row_attrs[(row++) & 1], cl, i);
    fprintf(fout, "<td%s><a href=\"%s?contest_id=%d", cl, phr->self_url, i);

    if (orig_locale_id >= 0 && cnts->default_locale_val >= 0
        && orig_locale_id != cnts->default_locale_val) {
      fprintf(fout, "&amp;locale_id=%d", phr->locale_id);
    }

    if (login && *login) fprintf(fout, "&amp;login=%s", URLARMOR(login));
    s = 0;
    if (phr->locale_id == 0 && cnts->name_en) s = cnts->name_en;
    if (!s) s = cnts->name;
    fprintf(fout, "\">%s</a></td>", ARMOR(s));
    fprintf(fout, "</tr>\n");
  }
  fprintf(fout, "</table>\n");

  ns_footer(fout, ns_fancy_footer, 0, phr->locale_id);
  l10n_setlocale(0);

  html_armor_free(&ab);
  xfree(cntslist);
}

static action_handler_t user_actions_table[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_CHANGE_LANGUAGE] = unpriv_change_language,
  [NEW_SRV_ACTION_CHANGE_PASSWORD] = unpriv_change_password,
  [NEW_SRV_ACTION_SUBMIT_RUN] = unpriv_submit_run,
  [NEW_SRV_ACTION_SUBMIT_CLAR] = unpriv_submit_clar,
  [NEW_SRV_ACTION_LOGOUT] = unpriv_logout,
  [NEW_SRV_ACTION_VIEW_SOURCE] = unpriv_view_source,
  [NEW_SRV_ACTION_VIEW_REPORT] = unpriv_view_report,
  [NEW_SRV_ACTION_VIEW_CLAR] = unpriv_view_clar,
  [NEW_SRV_ACTION_PRINT_RUN] = unpriv_print_run,
  [NEW_SRV_ACTION_VIEW_TEST_INPUT] = unpriv_view_test,
  [NEW_SRV_ACTION_VIEW_TEST_ANSWER] = unpriv_view_test,
  [NEW_SRV_ACTION_VIEW_TEST_INFO] = unpriv_view_test,
  [NEW_SRV_ACTION_VIEW_TEST_OUTPUT] = unpriv_view_test,
  [NEW_SRV_ACTION_VIEW_TEST_ERROR] = unpriv_view_test,
  [NEW_SRV_ACTION_VIEW_TEST_CHECKER] = unpriv_view_test,
  [NEW_SRV_ACTION_SUBMIT_APPEAL] = unpriv_submit_appeal,
  [NEW_SRV_ACTION_STANDINGS] = unpriv_view_standings,
  [NEW_SRV_ACTION_VIRTUAL_START] = unpriv_command,
  [NEW_SRV_ACTION_VIRTUAL_STOP] = unpriv_command,
  [NEW_SRV_ACTION_XML_USER_STATE] = unpriv_xml_user_state,
  [NEW_SRV_ACTION_UPDATE_ANSWER] = unpriv_xml_update_answer,
  [NEW_SRV_ACTION_GET_FILE] = unpriv_get_file,
};

static void
unprivileged_entry_point(
        FILE *fout,
        struct http_request_info *phr,
        int orig_locale_id)
{
  int r, i;
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  time_t cur_time = time(0);
  unsigned char hid_buf[1024];
  struct teamdb_db_callbacks callbacks;
  struct last_access_info *pp;
  int online_users = 0;
  serve_state_t cs = 0;

  if (phr->action == NEW_SRV_ACTION_FORGOT_PASSWORD_1)
    return unpriv_page_forgot_password_1(fout, phr, orig_locale_id);
  if (phr->action == NEW_SRV_ACTION_FORGOT_PASSWORD_2)
    return unpriv_page_forgot_password_2(fout, phr, orig_locale_id);
  if (phr->action == NEW_SRV_ACTION_FORGOT_PASSWORD_3)
    return unpriv_page_forgot_password_3(fout, phr, orig_locale_id);

  if ((phr->contest_id < 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts)
      && !phr->session_id){
    //return anon_select_contest_page(fout, phr);
  }

  if (!phr->session_id || phr->action == NEW_SRV_ACTION_LOGIN_PAGE)
    return unprivileged_page_login(fout, phr, orig_locale_id);

  // validate cookie
  if (ns_open_ul_connection(phr->fw_state) < 0)
    return ns_html_err_ul_server_down(fout, phr, 0, 0);
  if ((r = userlist_clnt_get_cookie(ul_conn, ULS_TEAM_GET_COOKIE,
                                    phr->ip, phr->ssl_flag,
                                    phr->session_id,
                                    &phr->user_id, &phr->contest_id,
                                    &phr->locale_id, 0, &phr->role, 0, 0, 0,
                                    &phr->login, &phr->name)) < 0) {
    if (r < 0 && orig_locale_id < 0 && cnts && cnts->default_locale_val >= 0) {
      phr->locale_id = cnts->default_locale_val;
    }
    switch (-r) {
    case ULS_ERR_NO_COOKIE:
    case ULS_ERR_CANNOT_PARTICIPATE:
    case ULS_ERR_NOT_REGISTERED:
      return ns_html_err_inv_session(fout, phr, 0,
                                     "get_cookie failed: %s",
                                     userlist_strerror(-r));
    case ULS_ERR_INCOMPLETE_REG:
      return ns_html_err_registration_incomplete(fout, phr);
    case ULS_ERR_DISCONNECT:
      return ns_html_err_ul_server_down(fout, phr, 0, 0);
    default:
      return ns_html_err_internal_error(fout, phr, 0, "get_cookie failed: %s",
                                        userlist_strerror(-r));
    }
  }

  if (phr->contest_id < 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts){
    //return anon_select_contest_page(fout, phr);
    return ns_html_err_no_perm(fout, phr, 1, "invalid contest_id %d",
                               phr->contest_id);
  }
  extra = ns_get_contest_extra(phr->contest_id);
  ASSERT(extra);

  if (!contests_check_team_ip(phr->contest_id, phr->ip, phr->ssl_flag))
    return ns_html_err_no_perm(fout, phr, 0, "%s://%s is not allowed for USER for contest %d", ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  if (cnts->closed)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d is closed", cnts->id);
  if (!cnts->new_managed)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d is not managed",
                                             cnts->id);
  if (cnts->client_disable_team)
    return ns_html_err_service_not_available(fout, phr, 0,
                                             "contest %d user is disabled",
                                             cnts->id);

  watched_file_update(&extra->header, cnts->team_header_file, cur_time);
  watched_file_update(&extra->menu_1, cnts->team_menu_1_file, cur_time);
  watched_file_update(&extra->menu_2, cnts->team_menu_2_file, cur_time);
  watched_file_update(&extra->separator, cnts->team_separator_file, cur_time);
  watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
  watched_file_update(&extra->copyright, cnts->copyright_file, cur_time);
  extra->header_txt = extra->header.text;
  extra->menu_1_txt = extra->menu_1.text;
  extra->menu_2_txt = extra->menu_2.text;
  extra->separator_txt = extra->separator.text;
  extra->footer_txt = extra->footer.text;
  extra->copyright_txt = extra->copyright.text;
  //if (!extra->header_txt) extra->header_txt = ns_fancy_header;
  //if (!extra->footer_txt) extra->footer_txt = ns_fancy_footer;

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

  snprintf(hid_buf, sizeof(hid_buf),
           "<input type=\"hidden\" name=\"SID\" value=\"%016llx\"/>",
           phr->session_id);
  phr->hidden_vars = hid_buf;
  phr->session_extra = ns_get_session(phr->session_id, cur_time);

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.user_data = (void*) phr->fw_state;
  callbacks.list_all_users = ns_list_all_users_callback;

  // invoke the contest
  if (serve_state_load_contest(phr->contest_id,
                               ul_conn,
                               &callbacks,
                               &extra->serve_state, 0) < 0) {
    return ns_html_err_cnts_unavailable(fout, phr, 0, 0);
  }

  cs = extra->serve_state;
  cs->current_time = time(0);
  ns_check_contest_events(cs, cnts);

  // check the user map
  if (phr->user_id >= extra->user_access_idx.a) {
    int new_size = extra->user_access_idx.a;
    if (!new_size) new_size = 128;
    while (phr->user_id >= new_size) new_size *= 2;
    short *new_idx = (short*) xmalloc(new_size * sizeof(new_idx[0]));
    memset(new_idx, -1, new_size * sizeof(new_idx[0]));
    if (extra->user_access_idx.a > 0) {
      memcpy(new_idx, extra->user_access_idx.v,
             extra->user_access_idx.a * sizeof(new_idx[0]));
    }
    xfree(extra->user_access_idx.v);
    extra->user_access_idx.a = new_size;
    extra->user_access_idx.v = new_idx;
  }
  if (extra->user_access_idx.v[phr->user_id] < 0
      && extra->user_access[USER_ROLE_CONTESTANT].u < 32000) {
    struct last_access_array *p = &extra->user_access[USER_ROLE_CONTESTANT];
    if (p->u == p->a) {
      if (!p->a) p->a = 64;
      p->a *= 2;
      XREALLOC(p->v, p->a);
    }
    extra->user_access_idx.v[phr->user_id] = p->u;
    memset(&p->v[p->u], 0, sizeof(p->v[0]));
    p->v[p->u].user_id = phr->user_id;
    p->u++;
  }
  if ((i = extra->user_access_idx.v[phr->user_id]) >= 0) {
    struct last_access_info *pp=&extra->user_access[USER_ROLE_CONTESTANT].v[i];
    pp->ip = phr->ip;
    pp->ssl = phr->ssl_flag;
    pp->time = cs->current_time;
  }

  // count number of users online
  online_users = 0;
  for (i = 0; i < extra->user_access[USER_ROLE_CONTESTANT].u; i++) {
    pp = &extra->user_access[USER_ROLE_CONTESTANT].v[i];
    if (pp->time + 65 >= cs->current_time) online_users++;
  }
  if (online_users > cs->max_online_count) {
    cs->max_online_count = online_users;
    cs->max_online_time = cs->current_time;
    serve_update_status_file(cs, 1);
  }
  phr->online_users = online_users;

  if ((teamdb_get_flags(cs->teamdb_state, phr->user_id) & TEAM_DISQUALIFIED))
    return ns_html_err_disqualified(fout, phr, cnts, extra);

  if (phr->action > 0 && phr->action < NEW_SRV_ACTION_LAST
      && user_actions_table[phr->action]) {
    user_actions_table[phr->action](fout, phr, cnts, extra);
  } else {
    if (phr->action < 0 || phr->action >= NEW_SRV_ACTION_LAST)
      phr->action = 0;
    unpriv_main_page(fout, phr, cnts, extra);
  }
}

static int
get_register_url(
        unsigned char *buf,
        size_t size,
        const struct contest_desc *cnts,
        const unsigned char *self_url)
{
  int i, len;

  if (cnts->register_url)
    return snprintf(buf, size, "%s", cnts->register_url);

  if (!self_url) return snprintf(buf, size, "%s", "/new-register");
  len = strlen(self_url);
  for (i = len - 1; i >= 0 && self_url[i] != '/'; i--);
  if (i < 0) return snprintf(buf, size, "%s", "/new-register");
#if defined CGI_PROG_SUFFIX
  return snprintf(buf, size, "%.*s/new-register%s", i, self_url,
                  CGI_PROG_SUFFIX);
#else
  return snprintf(buf, size, "%.*s/new-register", i, self_url);
#endif
}

void
ns_handle_http_request(struct server_framework_state *state,
                       struct client_state *p,
                       FILE *fout,
                       struct http_request_info *phr)
{
  const unsigned char *script_filename = 0;
  path_t last_name;
  const unsigned char *http_host;
  const unsigned char *script_name;
  const unsigned char *protocol = "http";
  const unsigned char *remote_addr;
  const unsigned char *s;
  path_t self_url;
  int r, n, orig_locale_id = -1;

  // make a self-referencing URL
  if (ns_getenv(phr, "SSL_PROTOCOL") || ns_getenv(phr, "HTTPS")) {
    phr->ssl_flag = 1;
    protocol = "https";
  }
  if (!(http_host = ns_getenv(phr, "HTTP_HOST"))) http_host = "localhost";
  if (!(script_name = ns_getenv(phr, "SCRIPT_NAME")))
    script_name = "/cgi-bin/new-client";
  snprintf(self_url, sizeof(self_url), "%s://%s%s", protocol,
           http_host, script_name);
  phr->self_url = self_url;

  // parse the client IP address
  if (!(remote_addr = ns_getenv(phr, "REMOTE_ADDR")))
    return ns_html_err_inv_param(fout, phr, 0, "REMOTE_ADDR does not exist");
  if (!strcmp(remote_addr, "::1")) remote_addr = "127.0.0.1";
  if (xml_parse_ip(0, 0, 0, remote_addr, &phr->ip) < 0)
    return ns_html_err_inv_param(fout, phr, 0, "cannot parse REMOTE_ADDR");

  // parse the contest_id
  if ((r = ns_cgi_param(phr, "contest_id", &s)) < 0)
    return ns_html_err_inv_param(fout, phr, 0, "cannot parse contest_id");
  if (r > 0) {
    if (sscanf(s, "%d%n", &phr->contest_id, &n) != 1
        || s[n] || phr->contest_id <= 0)
      return ns_html_err_inv_param(fout, phr, 0, "cannot parse contest_id");
  }

  // parse the session_id
  if ((r = ns_cgi_param(phr, "SID", &s)) < 0)
    return ns_html_err_inv_param(fout, phr, 0, "cannot parse SID");
  if (r > 0) {
    if (sscanf(s, "%llx%n", &phr->session_id, &n) != 1
        || s[n] || !phr->session_id)
      return ns_html_err_inv_param(fout, phr, 0, "cannot parse SID");
  }

  // parse the locale_id
  if ((r = ns_cgi_param(phr, "locale_id", &s)) < 0)
    return ns_html_err_inv_param(fout, phr, 0, "cannot parse locale_id");
  if (r > 0) {
    if (sscanf(s, "%d%n", &phr->locale_id, &n) != 1 || s[n]
        || phr->locale_id < 0)
      return ns_html_err_inv_param(fout, phr, 0, "cannot parse locale_id");
    orig_locale_id = phr->locale_id;
  }

  // parse the action
  if ((s = ns_cgi_nname(phr, "action_", 7))) {
    if (sscanf(s, "action_%d%n", &phr->action, &n) != 1 || s[n]
        || phr->action <= 0)
      return ns_html_err_inv_param(fout, phr, 0, "cannot parse action");
  } else if ((r = ns_cgi_param(phr, "action", &s)) < 0) {
    return ns_html_err_inv_param(fout, phr, 0, "cannot parse action");
  } else if (r > 0) {
    if (sscanf(s, "%d%n", &phr->action, &n) != 1 || s[n]
        || phr->action <= 0)
      return ns_html_err_inv_param(fout, phr, 0, "cannot parse action");
  }

  // check how we've been called
  script_filename = ns_getenv(phr, "SCRIPT_FILENAME");
  if (!script_filename && phr->arg_num > 0) script_filename = phr->args[0];
  if (!script_filename)
    return ns_html_err_inv_param(fout, phr, 0, "cannot get script filename");

  os_rGetLastname(script_filename, last_name, sizeof(last_name));

#if defined CGI_PROG_SUFFIX
  {
    static const unsigned char cgi_prog_suffix_str[] = CGI_PROG_SUFFIX;
    if (sizeof(cgi_prog_suffix_str) > 1) {
      int ll;
      if ((ll = strlen(last_name)) >= sizeof(cgi_prog_suffix_str)
          && !strcmp(last_name + ll - (sizeof(cgi_prog_suffix_str) - 1),
                     cgi_prog_suffix_str)) {
        last_name[ll - (sizeof(cgi_prog_suffix_str) - 1)] = 0;
      }
    }
  }
#endif /* CGI_PROG_SUFFIX */

  if (!strcmp(last_name, "priv-client"))
    privileged_entry_point(fout, phr);
  else if (!strcmp(last_name, "new-master")) {
    phr->role = USER_ROLE_ADMIN;
    privileged_entry_point(fout, phr);
  } else if (!strcmp(last_name, "new-judge")) {
    phr->role = USER_ROLE_JUDGE;
    privileged_entry_point(fout, phr);
  } else if (!strcmp(last_name, "new-register")) {
    // FIXME: temporary hack
    phr->locale_id = orig_locale_id;
    ns_register_pages(fout, phr);
  } else if (!strcmp(last_name, "new-server-cmd")) {
    phr->protocol_reply = new_server_cmd_handler(fout, phr);
  } else
    unprivileged_entry_point(fout, phr, orig_locale_id);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
