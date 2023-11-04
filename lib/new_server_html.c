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
#include "ejudge/pathutl.h"
#include "ejudge/xml_utils.h"
#include "ejudge/misctext.h"
#include "ejudge/copyright.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/errlog.h"
#include "ejudge/userlist_proto.h"
#include "ejudge/contests.h"
#include "ejudge/nsdb_plugin.h"
#include "ejudge/l10n.h"
#include "ejudge/fileutl.h"
#include "ejudge/userlist.h"
#include "ejudge/mischtml.h"
#include "ejudge/serve_state.h"
#include "ejudge/teamdb.h"
#include "ejudge/prepare.h"
#include "ejudge/runlog.h"
#include "ejudge/html.h"
#include "ejudge/watched_file.h"
#include "ejudge/mime_type.h"
#include "ejudge/sha.h"
#include "ejudge/archive_paths.h"
#include "ejudge/curtime.h"
#include "ejudge/clarlog.h"
#include "ejudge/team_extra.h"
#include "ejudge/diff.h"
#include "ejudge/protocol.h"
#include "ejudge/printing.h"
#include "ejudge/sformat.h"
#include "ejudge/charsets.h"
#include "ejudge/compat.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/prepare_dflt.h"
#include "ejudge/new_server_match.h"
#include "ejudge/external_action.h"
#include "ejudge/new_server_pi.h"
#include "ejudge/xuser_plugin.h"
#include "ejudge/blowfish.h"
#include "ejudge/base64.h"
#include "ejudge/random.h"
#include "ejudge/avatar_plugin.h"
#include "ejudge/content_plugin.h"
#include "ejudge/imagemagick.h"
#include "ejudge/base32.h"
#include "ejudge/userlist_bin.h"
#include "ejudge/testing_report_xml.h"
#include "ejudge/cJSON.h"
#include "ejudge/filter_tree.h"
#include "ejudge/filter_eval.h"
#include "ejudge/storage_plugin.h"
#include "ejudge/submit_plugin.h"
#include "ejudge/userprob_plugin.h"
#include "ejudge/job_packet.h"
#include "ejudge/sha256utils.h"
#include "ejudge/metrics_contest.h"
#include "ejudge/session_cache.h"
#include "ejudge/tsc.h"
#include "ejudge/compile_packet.h"
#include "ejudge/run_packet.h"
#include "ejudge/notify_plugin.h"
#include "ejudge/json_serializers.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>

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

#define ARMOR(s)  html_armor_buf(&ab, (s))
#define URLARMOR(s)  url_armor_buf(&ab, s)
#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)
#define JARMOR(s) (json_armor_buf(&ab, (s)))

#pragma GCC diagnostic ignored "-Wformat-security"

typedef struct ContestExternalActionVector
{
  int a; // allocated
  int u; // size
  ContestExternalActions *v;
} ContestExternalActionVector;

enum { CONTEST_EXPIRE_TIME = 300 };
static struct contest_extra **extras = 0;
static size_t extra_a = 0, extra_u = 0;

extern const unsigned char * const ns_symbolic_action_table[];

static ContestExternalActionVector cnts_ext_actions;

struct id_cache main_id_cache;
static time_t expired_contest_last_check_time = 0;

static void
error_page(
        FILE *out_f,
        struct http_request_info *phr,
        int priv_mode,
        int error_code);

static void unprivileged_page_login(FILE *fout,
                                    struct http_request_info *phr);
void
unpriv_page_header(FILE *fout,
                   struct http_request_info *phr,
                   const struct contest_desc *cnts,
                   struct contest_extra *extra,
                   time_t start_time, time_t stop_time);
void
do_json_user_state(FILE *fout, const serve_state_t cs, int user_id,
                   int need_reload_check);
const unsigned char *
ns_get_register_url(
        unsigned char *buf,
        size_t size,
        const struct contest_desc *cnts,
        const struct http_request_info *phr);

static int
parse_user_list(
        struct http_request_info *phr,
        serve_state_t cs,
        intarray_t *uset,
        int skip_user_check);

void
ns_invalidate_session(
        unsigned long long session_id,
        unsigned long long client_key)
{

  struct new_session_info del_item;

  if (nsc_remove(&main_id_cache.s, session_id, client_key, &del_item)) {
    xfree(del_item.login);
    xfree(del_item.name);
  }
}

static void
init_contest_external_action(ContestExternalActions *pact, int contest_id)
{
  memset(pact, 0, sizeof(*pact));
  pact->nref = 1;
  pact->contest_id = contest_id;
  pact->actions_size = NEW_SRV_ACTION_LAST;
  pact->errors_size = NEW_SRV_ERR_LAST;
  pact->ints_size = NEW_SRV_INT_LAST;
  XCALLOC(pact->priv_actions, pact->actions_size);
  XCALLOC(pact->unpriv_actions, pact->actions_size);
  XCALLOC(pact->reg_actions, pact->actions_size);
  XCALLOC(pact->priv_errors, pact->errors_size);
  XCALLOC(pact->unpriv_errors, pact->errors_size);
  XCALLOC(pact->reg_errors, pact->errors_size);
  XCALLOC(pact->int_actions, pact->ints_size);
}

ContestExternalActions *
ns_get_contest_external_actions(int contest_id, time_t current_time)
{
  if (contest_id <= 0) return NULL;
  if (cnts_ext_actions.a <= 0) {
    cnts_ext_actions.a = 16;
    XCALLOC(cnts_ext_actions.v, cnts_ext_actions.a);
  }
  if (cnts_ext_actions.u <= 0) {
    cnts_ext_actions.u = 1;
    init_contest_external_action(&cnts_ext_actions.v[0], contest_id);
    return &cnts_ext_actions.v[0];
  }
  if (contest_id > cnts_ext_actions.v[cnts_ext_actions.u - 1].contest_id) {
    if (cnts_ext_actions.u == cnts_ext_actions.a) {
      XREALLOC(cnts_ext_actions.v, cnts_ext_actions.a *= 2);
    }
    int i = cnts_ext_actions.u++;
    init_contest_external_action(&cnts_ext_actions.v[i], contest_id);
    return &cnts_ext_actions.v[i];
  }
  if (contest_id < cnts_ext_actions.v[0].contest_id) {
    if (cnts_ext_actions.u == cnts_ext_actions.a) {
      XREALLOC(cnts_ext_actions.v, cnts_ext_actions.a *= 2);
    }
    memmove(&cnts_ext_actions.v[1], &cnts_ext_actions.v[0], cnts_ext_actions.u * sizeof(cnts_ext_actions.v[0]));
    ++cnts_ext_actions.u;
    int i = 0;
    init_contest_external_action(&cnts_ext_actions.v[i], contest_id);
    return &cnts_ext_actions.v[i];
  }
  int l = 0, h = cnts_ext_actions.u;
  while (l < h) {
    int i = (l + h) / 2;
    if (cnts_ext_actions.v[i].contest_id == contest_id) {
      return &cnts_ext_actions.v[i];
    }
    if (cnts_ext_actions.v[i].contest_id < contest_id) {
      l = i + 1;
    } else {
      h = i;
    }
  }
  ASSERT(h < cnts_ext_actions.u);
  ASSERT(contest_id < cnts_ext_actions.v[h].contest_id);
  ASSERT(contest_id > cnts_ext_actions.v[h - 1].contest_id);
  if (cnts_ext_actions.u == cnts_ext_actions.a) {
    XREALLOC(cnts_ext_actions.v, cnts_ext_actions.a *= 2);
  }
  memmove(&cnts_ext_actions.v[h + 1], &cnts_ext_actions.v[h], (cnts_ext_actions.u - h) * sizeof(cnts_ext_actions.v[0]));
  ++cnts_ext_actions.u;
  init_contest_external_action(&cnts_ext_actions.v[h], contest_id);
  return &cnts_ext_actions.v[h];
}

ContestExternalActions *
ns_try_contest_external_actions(int contest_id)
{
  if (contest_id <= 0) return NULL;
  if (cnts_ext_actions.u <= 0) return NULL;
  if (contest_id > cnts_ext_actions.v[cnts_ext_actions.u - 1].contest_id) return NULL;
  if (contest_id < cnts_ext_actions.v[0].contest_id) return NULL;

  int l = 0, h = cnts_ext_actions.u;
  while (l < h) {
    int i = (l + h) / 2;
    if (cnts_ext_actions.v[i].contest_id == contest_id) {
      return &cnts_ext_actions.v[i];
    }
    if (cnts_ext_actions.v[i].contest_id < contest_id) {
      l = i + 1;
    } else {
      h = i;
    }
  }

  return NULL;
}

struct contest_extra *
ns_get_contest_extra(
        const struct contest_desc *cnts,
        const struct ejudge_cfg *config)
{
  struct contest_extra *p;
  size_t i, j, k;

  if (!cnts) return NULL;
  int contest_id = cnts->id;
  ASSERT(contest_id > 0 && contest_id <= EJ_MAX_CONTEST_ID);

  if (!extra_u) {
    if (!extra_a) {
      extra_a = 16;
      XCALLOC(extras, extra_a);
    }
    XCALLOC(p, 1);
    extras[extra_u++] = p;
    p->contest_id = contest_id;
    p->last_access_time = time(0);
    if (cnts->enable_local_pages > 0 && !p->cnts_actions) {
      p->cnts_actions = ns_get_contest_external_actions(contest_id, p->last_access_time);
    }
    return p;
  }

  if (contest_id > extras[extra_u - 1]->contest_id) {
    if (extra_u == extra_a) {
      extra_a *= 2;
      XREALLOC(extras, extra_a);
    }
    XCALLOC(p, 1);
    extras[extra_u++] = p;
    p->contest_id = contest_id;
    p->last_access_time = time(0);
    if (cnts->enable_local_pages > 0 && !p->cnts_actions) {
      p->cnts_actions = ns_get_contest_external_actions(contest_id, p->last_access_time);
    }
    return p;
  }

  i = 0; j = extra_u;
  while (i < j) {
    k = (i + j) / 2;
    if ((p = extras[k])->contest_id == contest_id) {
      p->last_access_time = time(0);
      if (cnts->enable_local_pages > 0 && !p->cnts_actions) {
        p->cnts_actions = ns_get_contest_external_actions(contest_id, p->last_access_time);
      }
      return p;
    }
    if (p->contest_id < contest_id) {
      i = k + 1;
    } else {
      j = k;
    }
  }
  ASSERT(j < extra_u);
  ASSERT(extras[j]->contest_id > contest_id);
  if (!j) {
    if (extra_u == extra_a) {
      extra_a *= 2;
      XREALLOC(extras, extra_a);
    }
    memmove(&extras[j + 1], &extras[j], extra_u * sizeof(extras[0]));
    extra_u++;
    XCALLOC(p, 1);
    extras[j] = p;
    p->contest_id = contest_id;
    p->last_access_time = time(0);
    if (cnts->enable_local_pages > 0 && !p->cnts_actions) {
      p->cnts_actions = ns_get_contest_external_actions(contest_id, p->last_access_time);
    }
    if (config && config->max_loaded_contests > 0) {
      // count loaded contests and the oldest contest
      int loaded_count = 0;
      int oldest_idx = -1;
      for (int idx = 0; idx < extra_u; ++idx) {
        if (extras[idx]->serve_state) {
          ++loaded_count;
          if (oldest_idx < 0 || extras[oldest_idx]->last_access_time > extras[idx]->last_access_time) {
            oldest_idx = idx;
          }
        }
      }
      if (loaded_count >= config->max_loaded_contests && oldest_idx >= 0) {
        extras[oldest_idx]->last_access_time = 0;
        expired_contest_last_check_time = 0;
      }
    }
    return p;
  }
  // FIXME: eliminate code clone
  ASSERT(i > 0);
  ASSERT(extras[i - 1]->contest_id < contest_id);
  if (extra_u == extra_a) {
    extra_a *= 2;
    XREALLOC(extras, extra_a);
  }
  memmove(&extras[j + 1], &extras[j], (extra_u - j) * sizeof(extras[0]));
  extra_u++;
  XCALLOC(p, 1);
  extras[j] = p;
  p->contest_id = contest_id;
  p->last_access_time = time(0);
  if (cnts->enable_local_pages > 0 && !p->cnts_actions) {
    p->cnts_actions = ns_get_contest_external_actions(contest_id, p->last_access_time);
  }
  if (config && config->max_loaded_contests > 0) {
    // count loaded contests and the oldest contest
    int loaded_count = 0;
    int oldest_idx = -1;
    for (int idx = 0; idx < extra_u; ++idx) {
      if (extras[idx]->serve_state) {
        ++loaded_count;
        if (oldest_idx < 0 || extras[oldest_idx]->last_access_time > extras[idx]->last_access_time) {
          oldest_idx = idx;
        }
      }
    }
    if (loaded_count >= config->max_loaded_contests && oldest_idx >= 0) {
      extras[oldest_idx]->last_access_time = 0;
      expired_contest_last_check_time = 0;
    }
  }
  return p;
}

struct contest_extra *
ns_try_contest_extra(int contest_id)
{
  struct contest_extra *p;
  size_t i, j, k;

  if (contest_id <= 0 || contest_id > EJ_MAX_CONTEST_ID) return 0;
  if (!extra_u) return 0;
  if (contest_id < extras[0]->contest_id) return 0;
  if (contest_id > extras[extra_u - 1]->contest_id) return 0;
  i = 0; j = extra_u;
  while (i < j) {
    k = (i + j) / 2;
    if ((p = extras[k])->contest_id == contest_id) {
      return p;
    }
    if (p->contest_id < contest_id) {
      i = k + 1;
    } else {
      j = k;
    }
  }
  return 0;
}

void
ns_for_each_contest_extra(void (*callback)(struct contest_extra *, void *ptr), void *ptr)
{
  for (int i = 0; i < extra_u; ++i) {
    if (extras[i]) {
      callback(extras[i], ptr);
    }
  }
}

void
ns_contest_unload_callback(serve_state_t cs)
{
  if (cs->client_id < 0 || !cs->pending_xml_import
      || !ns_is_valid_client_id(cs->client_id))
    return;

  ns_client_state_clear_contest_id(cs->client_id);
  ns_close_client_fds(cs->client_id);
  ns_send_reply_2(cs->client_id, -NEW_SRV_ERR_CONTEST_UNLOADED);
}

void
ns_client_destroy_callback(struct client_state *p)
{
  struct contest_extra *extra;
  const struct contest_desc *cnts = 0;
  serve_state_t cs;

  int cnts_id = p->ops->get_contest_id(p);
  if (cnts_id <= 0) return;
  if (contests_get(cnts_id, &cnts) < 0) return;
  if (!(extra = ns_try_contest_extra(cnts_id))) return;
  if (!(cs = extra->serve_state)) return;
  if (!cs->pending_xml_import || cs->client_id < 0) return;
  if (cs->saved_testing_suspended != cs->testing_suspended) {
    cs->testing_suspended = cs->saved_testing_suspended;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    if (!cs->testing_suspended)
      serve_judge_suspended(extra, ejudge_config, cnts, cs, 0, 0, 0,
                            DFLT_G_REJUDGE_PRIORITY_ADJUSTMENT, 0);
  }
  xfree(cs->pending_xml_import); cs->pending_xml_import = 0;
  cs->client_id = -1;
  cs->destroy_callback = 0;
}

static void
do_unload_contest(int idx)
{
  struct contest_extra *extra;
  const struct contest_desc *cnts = 0;
  int i, contest_id;

  ASSERT(idx >= 0 && idx < extra_u);
  extra = extras[idx];
  contest_id = extra->contest_id;

  contests_get(contest_id, &cnts);

  if (extra->serve_state) {
    serve_check_stat_generation(ejudge_config, extra->serve_state, cnts, 1, utf8_mode);
    serve_update_status_file(ejudge_config, cnts, extra->serve_state, 1);
    if (extra->serve_state->xuser_state) {
      extra->serve_state->xuser_state->vt->flush(extra->serve_state->xuser_state);
    }
    extra->serve_state = serve_state_destroy(extra, ejudge_config, extra->serve_state, cnts, ul_conn);
  }

  xfree(extra->contest_arm);
  watched_file_clear(&extra->copyright);
  watched_file_clear(&extra->welcome);
  watched_file_clear(&extra->reg_welcome);

  for (i = 0; i < USER_ROLE_LAST; i++) {
    xfree(extra->user_access[i].v);
  }
  xfree(extra->user_access_idx.v);

  avatar_plugin_destroy(extra->main_avatar_plugin);
  content_plugin_destroy(extra->main_content_plugin);

  memset(extra, 0, sizeof(*extra));
  xfree(extra);
  extras[idx] = 0;
}

void
ns_unload_contest(int contest_id)
{
  struct contest_extra *extra = 0;
  int i, j, k = 0;

  if (contest_id <= 0 || contest_id > EJ_MAX_CONTEST_ID) return;
  if (!extra_u) return;
  if (contest_id < extras[0]->contest_id) return;
  if (contest_id > extras[extra_u - 1]->contest_id) return;
  i = 0; j = extra_u;
  while (i < j) {
    k = (i + j) / 2;
    if ((extra = extras[k])->contest_id == contest_id) {
      break;
    }
    if (extra->contest_id < contest_id) {
      i = k + 1;
    } else {
      j = k;
    }
  }
  if (i >= j) return;

  do_unload_contest(k);
  if (k < extra_u - 1)
    memmove(&extras[k], &extras[k + 1], (extra_u-k-1)*sizeof(extras[0]));
  extra_u--;
  extras[extra_u] = 0;

  info("contest %d is unloaded", contest_id);
}

void
ns_unload_contests(void)
{
  int i;

  // we must keep `extras` array valid at all times
  for (i = extra_u - 1; i >= 0; --i) {
    do_unload_contest(i);
    extra_u = i;
  }
  extra_u = 0;
}

enum { EXPIRED_CONTEST_CHECK_INTERVAL = 60 };

void
ns_unload_expired_contests(time_t cur_time)
{
  int i;

  if (cur_time <= 0) cur_time = time(0);

  if (expired_contest_last_check_time + EXPIRED_CONTEST_CHECK_INTERVAL >= cur_time) {
    return;
  }
  expired_contest_last_check_time = cur_time;

  // we must keep `extras` array valid at all times
  for (i = 0; i < extra_u; ) {
    if (extras[i]
        && extras[i]->last_access_time + CONTEST_EXPIRE_TIME < cur_time
        && (!extras[i]->serve_state
            || !extras[i]->serve_state->pending_xml_import)) {
      do_unload_contest(i);
      if (i < extra_u - 1) {
        memmove(&extras[i], &extras[i+1], (extra_u-i-1)*sizeof(extras[0]));
      }
      --extra_u;
    } else {
      ++i;
    }
  }
}

static void
handle_pending_xml_import(
        struct contest_extra *extra,
        const struct contest_desc *cnts,
        serve_state_t cs)
{
  FILE *fout = 0;
  char *out_text = 0;
  size_t out_size = 0;

  if (cs->client_id < 0 || !ns_is_valid_client_id(cs->client_id)) {
    if (cs->saved_testing_suspended != cs->testing_suspended) {
      cs->testing_suspended = cs->saved_testing_suspended;
      serve_update_status_file(ejudge_config, cnts, cs, 1);
      if (!cs->testing_suspended)
        serve_judge_suspended(extra, ejudge_config, cnts, cs, 0, 0, 0,
                              DFLT_G_REJUDGE_PRIORITY_ADJUSTMENT, 0);
    }
    xfree(cs->pending_xml_import); cs->pending_xml_import = 0;
    cs->client_id = -1; cs->destroy_callback = 0;
    return;
  }

  fout = open_memstream(&out_text, &out_size);
  runlog_import_xml(cs, cs->runlog_state, fout, 1, cs->pending_xml_import);
  close_memstream(fout); fout = 0;
  if (out_size > 0) {
    ns_new_autoclose_2(cs->client_id, out_text, out_size);
    out_text = 0;
  } else {
    ns_close_client_fds(cs->client_id);
    xfree(out_text); out_text = 0;
  }
  ns_send_reply_2(cs->client_id, NEW_SRV_RPL_OK);

  if (cs->saved_testing_suspended != cs->testing_suspended) {
    cs->testing_suspended = cs->saved_testing_suspended;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    if (!cs->testing_suspended)
      serve_judge_suspended(extra, ejudge_config, cnts, cs, 0, 0, 0,
                            DFLT_G_REJUDGE_PRIORITY_ADJUSTMENT, 0);
  }
  xfree(cs->pending_xml_import); cs->pending_xml_import = 0;
  cs->client_id = -1; cs->destroy_callback = 0;
  ns_client_state_clear_contest_id(cs->client_id);
}

enum { SESSION_CHECK_INTERVAL = 3600 };

static void
ns_check_session_cache(time_t cur_time)
{
  if (cur_time <= 0) cur_time = time(NULL);

  if (main_id_cache.last_check_time + SESSION_CHECK_INTERVAL >= cur_time) {
    return;
  }
  main_id_cache.last_check_time = cur_time;

  nsc_remove_expired(&main_id_cache.s, cur_time);
  tc_remove_expired(&main_id_cache.t, cur_time);
}

enum { MAX_WORK_BATCH = 10 };

int
ns_loop_callback(struct server_framework_state *state)
{
  time_t cur_time = time(0);
  struct contest_extra *e;
  serve_state_t cs;
  const struct contest_desc *cnts;
  int contest_id, i, eind;
  strarray_t files;
  int count = 0;
  struct server_framework_job *job = nsf_get_first_job(state);

  memset(&files, 0, sizeof(files));

  if (job) {
    if (job->contest_id > 0) {
      e = ns_try_contest_extra(job->contest_id);
      e->last_access_time = cur_time;
    }
    if (job->vt->run(job, &count, MAX_WORK_BATCH)) {
      nsf_remove_job(state, job);
    }
  }

  for (eind = 0; eind < extra_u; eind++) {
    e = extras[eind];
    ASSERT(e);
    contest_id = e->contest_id;
    if (!(cs = e->serve_state)) continue;
    if (contests_get(contest_id, &cnts) < 0 || !cnts) continue;

    e->serve_state->current_time = cur_time;
    ns_check_contest_events(e, e->serve_state, cnts);

    serve_update_public_log_file(e, e->serve_state, cnts);
    serve_update_external_xml_log(e->serve_state, cnts);
    serve_update_internal_xml_log(e->serve_state, cnts);

    for (i = 0; i < cs->compile_dirs_u; i++) {
      if (get_file_list(cs->compile_dirs[i].status_dir, &files) < 0)
        continue;
      if (files.u <= 0) continue;
      for (int j = 0; j < files.u && count < MAX_WORK_BATCH; ++j) {
        ++count;
        serve_read_compile_packet(e, ejudge_config, cs, cnts,
                                  cs->compile_dirs[i].status_dir,
                                  cs->compile_dirs[i].report_dir,
                                  files.v[j], NULL);
      }
      e->last_access_time = cur_time;
      xstrarrayfree(&files);
    }

    for (i = 0; i < cs->run_dirs_u; i++) {
      if (get_file_list(cs->run_dirs[i].status_dir, &files) < 0
          || files.u <= 0)
        continue;
      for (int j = 0; j < files.u && count < MAX_WORK_BATCH; ++j) {
        ++count;
        serve_read_run_packet(e, ejudge_config, cs, cnts,
                              cs->run_dirs[i].status_dir,
                              cs->run_dirs[i].report_dir,
                              cs->run_dirs[i].full_report_dir,
                              files.v[j], NULL);
      }
      e->last_access_time = cur_time;
      xstrarrayfree(&files);
    }

    if (cs->pending_xml_import && !serve_count_transient_runs(cs))
      handle_pending_xml_import(e, cnts, cs);

    /*
    if (cs->clarlog_state && clar_get_total(cs->clarlog_state) != clar_fetch_total(cs->clarlog_state))
      e->last_access_time = 0;
      */
  }

  ns_unload_expired_contests(cur_time);
  ns_check_session_cache(cur_time);
  xstrarrayfree(&files);
  return count < MAX_WORK_BATCH;
}

void
ns_post_select_callback(struct server_framework_state *state)
{
  time_t cur_time = time(0);
  struct contest_extra *e;
  serve_state_t cs;
  const struct contest_desc *cnts;
  int contest_id, eind;

  for (eind = 0; eind < extra_u; eind++) {
    e = extras[eind];
    ASSERT(e);
    contest_id = e->contest_id;
    if (!(cs = e->serve_state)) continue;
    if (contests_get(contest_id, &cnts) < 0 || !cnts) continue;

    e->serve_state->current_time = cur_time;
    ns_check_contest_events(e, e->serve_state, cnts);
  }
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
      e = ns_try_contest_extra(contest_id);
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

  e = ns_try_contest_extra(contest_id);
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
  int r, contest_id, eind;
  struct contest_extra *e;

  if (ul_conn) return 0;

  if (!(ul_conn = userlist_clnt_open(ejudge_config->socket_path))) {
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
  for (eind = 0; eind < extra_u; eind++) {
    e = extras[eind];
    ASSERT(e);
    contest_id = e->contest_id;
    if (!e->serve_state) continue;
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

void
ns_load_problem_plugin(
        serve_state_t cs,
        struct problem_extra_info *extra,
        const struct section_problem_data *prob)
{
  const unsigned char *f = __FUNCTION__;
  unsigned char plugin_path[PATH_MAX];
  if (cs->global->advanced_layout > 0) {
    get_advanced_layout_path(plugin_path, sizeof(plugin_path), cs->global,
                             prob, prob->plugin_file, -1);
  } else {
    snprintf(plugin_path, sizeof(plugin_path), "%s", prob->plugin_file);
  }

  unsigned char plugin_name[1024];
  if (prob->plugin_entry_name && prob->plugin_entry_name[0]) {
    snprintf(plugin_name, sizeof(plugin_name), "%s", prob->plugin_entry_name);
  } else {
    snprintf(plugin_name, sizeof(plugin_name), "problem_%s", prob->short_name);
    int len = strlen(plugin_name);
    for (int i = 0; i < len; i++)
      if (plugin_name[i] == '-')
        plugin_name[i] = '_';
  }

  struct problem_plugin_iface *iface = NULL;
  iface = (struct problem_plugin_iface*) plugin_load_2(plugin_path,
                                                       "problem",
                                                       plugin_name);
  if (!iface) {
    err("%s: failed to load plugin '%s'", f, plugin_name);
    return;
  }

  if (iface->problem_version != PROBLEM_PLUGIN_IFACE_VERSION) {
    err("%s: plugin version mismatch", f);
    return;
  }

  const size_t *sza = NULL;
  if (!(sza = iface->sizes_array)) {
    err("%s: plugin sizes array is NULL", f);
    return;
  }
  if (iface->sizes_array_size != serve_struct_sizes_array_size) {
    err("%s: plugin sizes array size mismatch: %zu instead of %zu",
        f, iface->sizes_array_size, serve_struct_sizes_array_size);
    return;
  }
  for (int i = 0; i < serve_struct_sizes_array_num; ++i) {
    if (sza[i] && sza[i] != serve_struct_sizes_array[i]) {
      err("%s: plugin sizes array element %d mismatch: %zu instead of %zu",
          f, i, sza[i], serve_struct_sizes_array[i]);
      return;
    }
  }

  extra->plugin = iface;
  extra->plugin_data = (*extra->plugin->init)();
  info("loaded plugin %s", plugin_name);
}

static void
load_problem_plugin(serve_state_t cs, int prob_id)
{
  struct section_problem_data *prob = 0;
  struct problem_extra_info *extra;
  struct problem_plugin_iface *iface;
  unsigned char plugin_name[1024];
  int len, i;
  const unsigned char *f = __FUNCTION__;
  const size_t *sza;
  path_t plugin_path;

  if (prob_id <= 0 || prob_id > cs->max_prob) return;
  if (!(prob = cs->probs[prob_id])) return;
  extra = &cs->prob_extras[prob_id];

  if (!prob->plugin_file || !prob->plugin_file[0]) return;
  if (extra->plugin || extra->plugin_error) return;

  if (cs->global->advanced_layout > 0) {
    get_advanced_layout_path(plugin_path, sizeof(plugin_path), cs->global,
                             prob, prob->plugin_file, -1);
  } else {
    snprintf(plugin_path, sizeof(plugin_path), "%s", prob->plugin_file);
  }

  snprintf(plugin_name, sizeof(plugin_name), "problem_%s", prob->short_name);
  len = strlen(plugin_name);
  for (i = 0; i < len; i++)
    if (plugin_name[i] == '-')
      plugin_name[i] = '_';

  iface = (struct problem_plugin_iface*) plugin_load(plugin_path,
                                                     "problem",
                                                     plugin_name);
  if (!iface) {
    extra->plugin_error = 1;
    return;
  }

  if (iface->problem_version != PROBLEM_PLUGIN_IFACE_VERSION) {
    err("%s: plugin version mismatch", f);
    return;
  }
  if (!(sza = iface->sizes_array)) {
    err("%s: plugin sizes array is NULL", f);
    return;
  }
  if (iface->sizes_array_size != serve_struct_sizes_array_size) {
    err("%s: plugin sizes array size mismatch: %zu instead of %zu",
        f, iface->sizes_array_size, serve_struct_sizes_array_size);
    return;
  }
  for (i = 0; i < serve_struct_sizes_array_num; ++i) {
    if (sza[i] && sza[i] != serve_struct_sizes_array[i]) {
      err("%s: plugin sizes array element %d mismatch: %zu instead of %zu",
          f, i, sza[i], serve_struct_sizes_array[i]);
      return;
    }
  }

  extra->plugin = iface;
  extra->plugin_data = (*extra->plugin->init)();
  info("loaded plugin %s", plugin_name);
}

int
ns_list_all_users_callback(
        void *user_data,
        int contest_id,
        unsigned char **p_xml,
        UserlistBinaryHeader **p_header)
{
  struct server_framework_state *state = (struct server_framework_state *) user_data;
  unsigned char *xml = NULL;
  UserlistBinaryHeader *header = NULL;
  unsigned char *data = NULL;

  if (ns_open_ul_connection(state) < 0) goto fail;

  if (p_xml) {
    if (userlist_clnt_list_all_users(ul_conn, ULS_LIST_STANDINGS_USERS,
                                     contest_id, &xml) < 0)
      goto fail;
  }

  if (p_header) {
    int r = userlist_clnt_bin_data(ul_conn, ULS_LIST_STANDINGS_USERS_2, contest_id, &data);
    if (r < 0) goto fail;
    if (r == ULS_BIN_DATA) {
      header = (UserlistBinaryHeader*) data;
      data = NULL;
      if (!userlist_bin_unmarshall(header)) {
        goto fail;
      }
    } else {
      xfree(data); data = NULL;
    }
  }
  if (p_xml) {
    *p_xml = xml;
  } else {
    xfree(xml);
  }
  if (p_header) {
    *p_header = header;
  } else {
    xfree(header);
  }

  return 0;

fail:
  xfree(xml);
  xfree(data);
  xfree(header);
  return -1;
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

void
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
ns_url(
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

  if (phr->rest_mode > 0) {
    if (fbuf[0]) sep = "?";
    if (action < 0 || action >= NEW_SRV_ACTION_LAST) action = 0;
    snprintf(buf, size, "%s/%s/S%016llx%s%s", phr->self_url,
             ns_symbolic_action_table[action],
             phr->session_id, sep, fbuf);
  } else {
    abuf[0] = 0;
    if (fbuf[0]) sep = "&amp;";
    if (action > 0) snprintf(abuf, sizeof(abuf), "&amp;action=%d", action);

    snprintf(buf, size, "%s?SID=%016llx%s%s%s", phr->self_url,
             phr->session_id, abuf, sep, fbuf);
  }
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

  if (phr->rest_mode > 0) {
    if (action < 0 || action >= NEW_SRV_ACTION_LAST) action = 0;
    if (fbuf[0]) sep = "?";
    snprintf(buf, size, "%s/%s/S%016llx%s%s", phr->self_url,
             ns_symbolic_action_table[action],
             phr->session_id, sep, fbuf);
  } else {
    abuf[0] = 0;
    if (fbuf[0]) sep = "&";
    if (action > 0) snprintf(abuf, sizeof(abuf), "&action=%d", action);

    snprintf(buf, size, "%s?SID=%016llx%s%s%s", phr->self_url,
             phr->session_id, abuf, sep, fbuf);
  }
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

  if (phr->rest_mode > 0) {
    if (action < 0 || action >= NEW_SRV_ACTION_LAST) action = 0;
    if (fbuf[0]) sep = "?";
    snprintf(buf, size, "<a href=\"%s/%s/S%016llx%s%s\">", phr->self_url,
             ns_symbolic_action_table[action],
             phr->session_id, sep, fbuf);
  } else {
    abuf[0] = 0;
    if (fbuf[0]) sep = "&amp;";
    if (action > 0) snprintf(abuf, sizeof(abuf), "&amp;action=%d", action);

    snprintf(buf, size, "<a href=\"%s?SID=%016llx%s%s%s\">", phr->self_url,
             phr->session_id, abuf, sep, fbuf);
  }
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

  stbuf[0] = 0;
  if (style && *style) {
    snprintf(stbuf, sizeof(stbuf), " class=\"%s\"", style);
  }

  if (phr->rest_mode > 0) {
    if (action < 0 || action >= NEW_SRV_ACTION_LAST) action = 0;
    if (fbuf[0]) sep = "?";
    snprintf(buf, size, "<a href=\"%s/%s/S%016llx%s%s\"%s>", phr->self_url,
             ns_symbolic_action_table[action],
             phr->session_id, sep, fbuf, stbuf);
  } else {
    abuf[0] = 0;
    if (fbuf[0]) sep = "&amp;";
    if (action > 0) snprintf(abuf, sizeof(abuf), "&amp;action=%d", action);

    snprintf(buf, size, "<a href=\"%s?SID=%016llx%s%s%s\"%s>", phr->self_url,
             phr->session_id, abuf, sep, fbuf, stbuf);
  }
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

unsigned char *
ns_submit_button_2(
        unsigned char *buf,
        size_t size,
        const unsigned char *class_name,
        const unsigned char *var_name,
        int action,
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
           "<input type=\"submit\" class=\"%s\" name=\"%s\" value=\"%s\"/>",
           class_name, name_ptr, label);
  return buf;
}

void
ns_refresh_page(
        FILE *fout,
        struct http_request_info *phr,
        int new_action,
        const unsigned char *extra)
{
  unsigned char url[1024];

  if (extra && *extra) {
    ns_url_unescaped(url, sizeof(url), phr, new_action, "%s", extra);
  } else {
    ns_url_unescaped(url, sizeof(url), phr, new_action, 0);
  }

  if (phr->client_key) {
    fprintf(fout, "Set-Cookie: EJSID=%016llx; Path=/; SameSite=Lax\n", phr->client_key);
  }
  fprintf(fout, "Location: %s\n\n", url);
}

void
ns_refresh_page_2(
        FILE *fout,
        ej_cookie_t client_key,
        const unsigned char *url)
{
  if (client_key) {
    fprintf(fout, "Set-Cookie: EJSID=%016llx; Path=/; SameSite=Lax\n", client_key);
  }
  fprintf(fout, "Location: %s\n\n", url);
}

void
ns_check_contest_events(
        struct contest_extra *extra,
        serve_state_t cs,
        const struct contest_desc *cnts)
{
  const struct section_global_data *global = cs->global;
  time_t start_time, stop_time, sched_time, duration, finish_time;

  // check once per 10m
  if (cs->last_periodic_check <= 0 || cs->current_time >= cs->last_periodic_check + 600) {
    cs->last_periodic_check = cs->current_time;

    serve_check_telegram_reminder(ejudge_config, cs, cnts);
  }

  run_get_times(cs->runlog_state, 0, &start_time, &sched_time,
                &duration, &stop_time, &finish_time);

  if (start_time > 0 && finish_time > 0 && finish_time < start_time) {
    // this is not right, ignore this situation
    finish_time = 0;
  }

  if (!global->is_virtual) {
    if (start_time > 0 && stop_time <= 0 && duration <= 0 && finish_time > 0
        && cs->current_time >= finish_time) {
      /* the contest is over: contest_finish_time is expired! */
      info("CONTEST IS OVER");
      run_stop_contest(cs->runlog_state, finish_time);
      serve_invoke_stop_script(cs);
    } else if (start_time > 0 && stop_time <= 0 && duration > 0
               && cs->current_time >= start_time + duration){
      /* the contest is over: duration is expired! */
      info("CONTEST IS OVER");
      run_stop_contest(cs->runlog_state, start_time + duration);
      serve_invoke_stop_script(cs);
    } else if (sched_time > 0 && start_time <= 0
               && cs->current_time >= sched_time) {
      /* it's time to start! */
      info("CONTEST IS STARTED");
      run_start_contest(cs->runlog_state, sched_time);
      serve_invoke_start_script(cs);
      serve_update_standings_file(extra, cs, cnts, 0);
    }
  }

  if (cs->event_first) serve_handle_events(extra, ejudge_config, cnts, cs);
}

static int
priv_external_action(FILE *out_f, struct http_request_info *phr);

static void
privileged_page_login_page(FILE *fout, struct http_request_info *phr)
{
  phr->action = NEW_SRV_ACTION_LOGIN_PAGE;
  priv_external_action(fout, phr);
}

static void
privileged_page_cookie_login(FILE *fout,
                             struct http_request_info *phr)
{
  const struct contest_desc *cnts = 0;
  opcap_t caps;
  int r, n;
  const unsigned char *s = 0;

  if (phr->contest_id<=0 || contests_get(phr->contest_id, &cnts)<0 || !cnts) {
    fprintf(phr->log_f, "invalid contest_id: %d", phr->contest_id);
    return error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
  }
  if (!cnts->managed) {
    fprintf(phr->log_f, "contest is not managed");
    return error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
  }
  if (!phr->role) {
    phr->role = USER_ROLE_OBSERVER;
    if (hr_cgi_param(phr, "role", &s) > 0) {
      if (sscanf(s, "%d%n", &r, &n) == 1 && !s[n]
          && r >= USER_ROLE_CONTESTANT && r < USER_ROLE_LAST)
        phr->role = r;
    }
  }
  if (phr->role <= USER_ROLE_CONTESTANT || phr->role >= USER_ROLE_LAST) {
    fprintf(phr->log_f, "invalid role: %d", phr->role);
    return error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
  }
  if (!phr->session_id) {
    fprintf(phr->log_f, "SID is undefined");
    return error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
  }

  // analyze IP limitations
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (!contests_check_master_ip(phr->contest_id, &phr->ip, phr->ssl_flag)) {
      fprintf(phr->log_f, "%s://%s is not allowed for MASTER for contest %d", ns_ssl_flag_str[phr->ssl_flag],
              xml_unparse_ipv6(&phr->ip), phr->contest_id);
      return error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
    }
  } else {
    // as for judge program
    if (!contests_check_judge_ip(phr->contest_id, &phr->ip, phr->ssl_flag)) {
      fprintf(phr->log_f, "%s://%s is not allowed for JUDGE for contest %d", ns_ssl_flag_str[phr->ssl_flag],
              xml_unparse_ipv6(&phr->ip), phr->contest_id);
      return error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
    }
  }

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    return error_page(fout, phr, 1, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
  }

  xfree(phr->login); phr->login = 0;
  xfree(phr->name); phr->name = 0;
  if ((r = userlist_clnt_priv_cookie_login(ul_conn, ULS_PRIV_COOKIE_LOGIN,
                                           &phr->ip, phr->ssl_flag,
                                           phr->contest_id, phr->session_id, phr->client_key,
                                           phr->locale_id,
                                           phr->role, &phr->user_id,
                                           &phr->session_id, &phr->client_key,
                                           &phr->login,
                                           &phr->name)) < 0) {
    switch (-r) {
    case ULS_ERR_BAD_CONTEST_ID:
    case ULS_ERR_IP_NOT_ALLOWED:
    case ULS_ERR_NO_PERMS:
    case ULS_ERR_NOT_REGISTERED:
    case ULS_ERR_CANNOT_PARTICIPATE:
    case ULS_ERR_NO_COOKIE:
      fprintf(phr->log_f, "priv_login failed: %s", userlist_strerror(-r));
      return error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
    case ULS_ERR_DISCONNECT:
      return error_page(fout, phr, 1, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    default:
      fprintf(phr->log_f, "priv_login failed: %s", userlist_strerror(-r));
      return error_page(fout, phr, 1, NEW_SRV_ERR_INTERNAL);
    }
  }

  // analyze permissions
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0 || opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0) {
      fprintf(phr->log_f, "user %s does not have MASTER_LOGIN bit for contest %d", phr->login, phr->contest_id);
      return error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
    }
  } else if (phr->role == USER_ROLE_JUDGE) {
    // as for the judge program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0 || opcaps_check(caps, OPCAP_JUDGE_LOGIN) < 0) {
      fprintf(phr->log_f, "user %s does not have JUDGE_LOGIN bit for contest %d", phr->login, phr->contest_id);
      return error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
    }
  } else {
    // user privileges checked locally
    if (nsdb_check_role(phr->user_id, phr->contest_id, phr->role) < 0) {
      fprintf(phr->log_f, "user %s has no permission to login as role %d for contest %d", phr->login, phr->role, phr->contest_id);
      return error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
    }
  }

  ns_refresh_page(fout, phr, NEW_SRV_ACTION_MAIN_PAGE, 0);
}

static void
privileged_page_login(FILE *fout,
                      struct http_request_info *phr)
{
  const unsigned char *login = NULL, *password = NULL, *s;
  int r, n;
  const struct contest_desc *cnts = 0;
  opcap_t caps;

  if ((r = hr_cgi_param(phr, "login", &login)) < 0) {
    fprintf(phr->log_f, "cannot parse login");
    return error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
  }
  if (login && *login && !is_valid_login(login)) {
    fprintf(phr->log_f, "invalid login");
    return error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
  }
  if (!r || phr->action == NEW_SRV_ACTION_LOGIN_PAGE)
    return privileged_page_login_page(fout, phr);

  phr->login = xstrdup(login);
  if ((r = hr_cgi_param(phr, "password", &password)) <= 0) {
    fprintf(phr->log_f, "cannot parse password");
    return error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
  }
  if (phr->contest_id<=0 || contests_get(phr->contest_id, &cnts)<0 || !cnts) {
    fprintf(phr->log_f, "invalid contest_id");
    return error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
  }
  if (!cnts->managed) {
    fprintf(phr->log_f, "contest is not managed");
    return error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
  }

  if (!phr->role) {
    phr->role = USER_ROLE_OBSERVER;
    if (hr_cgi_param(phr, "role", &s) > 0) {
      if (sscanf(s, "%d%n", &r, &n) == 1 && !s[n]
          && r >= USER_ROLE_CONTESTANT && r < USER_ROLE_LAST)
        phr->role = r;
    }
  }
  if (phr->role == USER_ROLE_CONTESTANT)
    return unprivileged_page_login(fout, phr);

  // analyze IP limitations
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (!contests_check_master_ip(phr->contest_id, &phr->ip, phr->ssl_flag)) {
      fprintf(phr->log_f, "%s://%s is not allowed for MASTER for contest %d", ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ipv6(&phr->ip), phr->contest_id);
      return error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
    }
  } else {
    // as for judge program
    if (!contests_check_judge_ip(phr->contest_id, &phr->ip, phr->ssl_flag)) {
      fprintf(phr->log_f, "%s://%s is not allowed for JUDGE for contest %d", ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ipv6(&phr->ip), phr->contest_id);
      return error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
    }
  }

  if (ns_open_ul_connection(phr->fw_state) < 0)
    return error_page(fout, phr, 1, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
  if ((r = userlist_clnt_priv_login(ul_conn, ULS_PRIV_CHECK_USER,
                                    &phr->ip, phr->client_key,
                                    phr->ssl_flag, phr->contest_id,
                                    phr->locale_id, phr->role, login,
                                    password, &phr->user_id,
                                    &phr->session_id, &phr->client_key,
                                    0, &phr->name)) < 0) {
    switch (-r) {
    case ULS_ERR_INVALID_LOGIN:
    case ULS_ERR_INVALID_PASSWORD:
    case ULS_ERR_BAD_CONTEST_ID:
    case ULS_ERR_IP_NOT_ALLOWED:
    case ULS_ERR_NO_PERMS:
    case ULS_ERR_NOT_REGISTERED:
    case ULS_ERR_CANNOT_PARTICIPATE:
    case ULS_ERR_NO_COOKIE:
      fprintf(phr->log_f, "priv_login failed: %s", userlist_strerror(-r));
      return error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
    case ULS_ERR_DISCONNECT:
      return error_page(fout, phr, 1, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    default:
      fprintf(phr->log_f, "priv_login failed: %s", userlist_strerror(-r));
      return error_page(fout, phr, 1, NEW_SRV_ERR_INTERNAL);
    }
  }

  // analyze permissions
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0 || opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0) {
      fprintf(phr->log_f, "user %s does not have MASTER_LOGIN bit for contest %d", phr->login, phr->contest_id);
      return error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
    }
  } else if (phr->role == USER_ROLE_JUDGE) {
    // as for the judge program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0 || opcaps_check(caps, OPCAP_JUDGE_LOGIN) < 0) {
      fprintf(phr->log_f, "user %s does not have JUDGE_LOGIN bit for contest %d", phr->login, phr->contest_id);
      return error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
    }
  } else {
    // user privileges checked locally
    if (nsdb_check_role(phr->user_id, phr->contest_id, phr->role) < 0) {
      fprintf(phr->log_f, "user %s has no permission to login as role %d for contest %d", phr->login, phr->role, phr->contest_id);
      return error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
    }
  }

  ns_refresh_page(fout, phr, NEW_SRV_ACTION_MAIN_PAGE, 0);
}

static void
priv_parse_user_id_range(
        struct http_request_info *phr,
        int *p_first_id,
        int *p_last_id)
{
  int first = 0, last = -1, x, y;

  if (hr_cgi_param_int_opt(phr, "first_user_id", &x, 0) < 0) goto done;
  if (hr_cgi_param_int_opt(phr, "last_user_id", &y, -1) < 0) goto done;
  if (x <= 0 || y <= 0 || x > y || y - x > 100000) goto done;

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
  int i, n, new_status, cmd, flag;
  intarray_t uset;
  const unsigned char *s;
  int retcode = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char *disq_comment = 0;
  enum { FLAGS_COUNT = 7 };
  int flags[FLAGS_COUNT] = { 0, 0, 0, 0, 0, 0, 0 };
  int flag_map[FLAGS_COUNT] =
  {
    USERLIST_UC_BANNED,
    USERLIST_UC_INVISIBLE,
    USERLIST_UC_LOCKED,
    USERLIST_UC_INCOMPLETE,
    USERLIST_UC_DISQUALIFIED,
    USERLIST_UC_PRIVILEGED,
    USERLIST_UC_REG_READONLY
  };

  // extract the selected set of users
  memset(&uset, 0, sizeof(uset));

  if (parse_user_list(phr, cs, &uset, 1) < 0) {
    error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
    retcode = -1;
    goto cleanup;
  }

  if (phr->action == NEW_SRV_ACTION_USERS_SET_DISQUALIFIED) {
    if (hr_cgi_param(phr, "disq_comment", &s) < 0) {
      fprintf(phr->log_f, "invalid parameter disq_comment");
      error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
      retcode = -1;
      goto cleanup;
    }
    disq_comment = text_area_process_string(s, 0, 0);
  }
  if (phr->action == NEW_SRV_ACTION_USERS_CHANGE_FLAGS) {
    hr_cgi_param_int_opt(phr, "flag_0", &flags[0], 0);
    hr_cgi_param_int_opt(phr, "flag_1", &flags[1], 0);
    hr_cgi_param_int_opt(phr, "flag_2", &flags[2], 0);
    hr_cgi_param_int_opt(phr, "flag_3", &flags[3], 0);
    hr_cgi_param_int_opt(phr, "flag_4", &flags[4], 0);
    hr_cgi_param_int_opt(phr, "flag_5", &flags[5], 0);
    hr_cgi_param_int_opt(phr, "flag_6", &flags[6], 0);
  }

  // FIXME: probably we need to sort user_ids and remove duplicates

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    error_page(fout, phr, 1, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    retcode = -1;
    goto cleanup;
  }

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, (int) uset.u);

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
    case NEW_SRV_ACTION_USERS_SET_STATUS:
    case NEW_SRV_ACTION_USERS_SET_PENDING:
    case NEW_SRV_ACTION_USERS_SET_OK:
    case NEW_SRV_ACTION_USERS_SET_REJECTED:
      switch (phr->action) {
      case NEW_SRV_ACTION_USERS_SET_STATUS:
        hr_cgi_param_int_opt(phr, "new_status", &new_status, -1);
        if (new_status < 0 || new_status >= USERLIST_REG_LAST) {
          error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
          retcode = -1;
          goto cleanup;
        }
        break;
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
        if (cs->xuser_state) {
          cs->xuser_state->vt->set_disq_comment(cs->xuser_state, uset.v[i], disq_comment);
        }
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

    case NEW_SRV_ACTION_USERS_CHANGE_FLAGS:
      for (int j = 0; j < FLAGS_COUNT; ++j) {
        if (flags[j] > 0 && flags[j] <= 3) {
          // FIXME: handle error
          userlist_clnt_change_registration(ul_conn, uset.v[i],
                                            phr->contest_id, -1, flags[j],
                                            flag_map[j]);
        }
      }
      break;

    default:
      fprintf(phr->log_f, "invalid action %d", phr->action);
      error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
      retcode = -1;
      goto cleanup;
    }
  }

  if (phr->action == NEW_SRV_ACTION_USERS_SET_DISQUALIFIED) {
    if (cs->xuser_state) {
      cs->xuser_state->vt->flush(cs->xuser_state);
    }
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

  if ((r = hr_cgi_param(phr, "add_user_id", &s)) < 0 || !s
      || sscanf(s, "%d%n", &x, &n) != 1 || s[n] || x <= 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    error_page(fout, phr, 1, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    retval = -1;
    goto cleanup;
  }

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, x);

  r = userlist_clnt_register_contest(ul_conn, ULS_PRIV_REGISTER_CONTEST,
                                     x, phr->contest_id, &phr->ip,
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

  if ((r = hr_cgi_param(phr, "add_login", &s)) < 0 || !s) {
    ns_error(log_f, NEW_SRV_ERR_INV_USER_LOGIN);
    goto cleanup;
  }
  if (ns_open_ul_connection(phr->fw_state) < 0) {
    error_page(fout, phr, 1, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    retval = -1;
    goto cleanup;
  }
  if ((r = userlist_clnt_lookup_user(ul_conn, s, 0, &user_id, 0)) < 0) {
    ns_error(log_f, NEW_SRV_ERR_USER_LOGIN_NONEXISTANT, ARMOR(s));
    goto cleanup;
  }

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  if ((r = userlist_clnt_register_contest(ul_conn, ULS_PRIV_REGISTER_CONTEST,
                                          user_id, phr->contest_id,
                                          &phr->ip, phr->ssl_flag)) < 0) {
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
      fprintf(phr->log_f, "invalid parameter name %s", ARMOR(phr->param_names[i]));
      error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
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

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, (int) uset.u);

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
      fprintf(phr->log_f, "invalid action %d", phr->action);
      error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
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

  if ((r = hr_cgi_param(phr, "add_user_id", &s)) < 0 || !s
      || sscanf(s, "%d%n", &user_id, &n) != 1 || s[n] || user_id <= 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_USER_ID);
    goto cleanup;
  }
  if ((r = hr_cgi_param(phr, "add_role_2", &s)) < 0 || !s
      || sscanf(s, "%d%n", &add_role, &n) != 1 || s[n]
      || add_role < USER_ROLE_OBSERVER || add_role > USER_ROLE_COORDINATOR) {
    ns_error(log_f, NEW_SRV_ERR_INV_USER_ROLE);
    goto cleanup;
  }

  info("audit:%s:%d:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, add_role, user_id);

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

  if ((r = hr_cgi_param(phr, "add_login", &login)) < 0 || !login) {
    ns_error(log_f, NEW_SRV_ERR_INV_USER_LOGIN);
    goto cleanup;
  }
  if ((r = hr_cgi_param(phr, "add_role_1", &s)) < 0 || !s
      || sscanf(s, "%d%n", &add_role, &n) != 1 || s[n]
      || add_role < USER_ROLE_OBSERVER || add_role > USER_ROLE_COORDINATOR) {
    ns_error(log_f, NEW_SRV_ERR_INV_USER_ROLE);
    goto cleanup;
  }
  if (ns_open_ul_connection(phr->fw_state) < 0) {
    error_page(fout, phr, 1, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    retval = -1;
    goto cleanup;
  }
  if ((r = userlist_clnt_lookup_user(ul_conn, login, 0, &user_id, 0)) < 0) {
    ns_error(log_f, NEW_SRV_ERR_USER_LOGIN_NONEXISTANT, ARMOR(s));
    goto cleanup;
  }

  info("audit:%s:%d:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, add_role, user_id);

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

  if (hr_cgi_param(phr, "user_id", &s) <= 0
      || sscanf(s, "%d%n", &user_id, &n) != 1 || s[n]
      || user_id <= 0 || !teamdb_lookup(cs->teamdb_state, user_id))
    FAIL(NEW_SRV_ERR_INV_USER_ID);

  switch (phr->action) {
  case NEW_SRV_ACTION_USER_CHANGE_STATUS:
    if (hr_cgi_param(phr, "status", &s) <= 0
        || sscanf(s, "%d%n", &new_status, &n) != 1 || s[n]
        || new_status < 0 || new_status >= cs->global->contestant_status_num)
      FAIL(NEW_SRV_ERR_INV_STATUS);
    if (opcaps_check(phr->caps, OPCAP_EDIT_REG) < 0)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    if (cs->xuser_state) {
      t_extra = cs->xuser_state->vt->get_entry(cs->xuser_state, user_id);
    }
    if (!t_extra)
      FAIL(NEW_SRV_ERR_DISK_READ_ERROR);

    info("audit:%s:%d:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, user_id, new_status);

    if (t_extra->status == new_status) goto cleanup;
    if (cs->xuser_state) {
      cs->xuser_state->vt->set_status(cs->xuser_state, user_id, new_status);
      cs->xuser_state->vt->flush(cs->xuser_state);
    }
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
  if (hr_cgi_param(phr, "user_id", &s) <= 0
      || sscanf(s, "%d%n", &user_id, &n) != 1 || s[n]
      || teamdb_lookup(cs->teamdb_state, user_id) <= 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);
  if ((n = hr_cgi_param(phr, "warn_text", &s)) < 0)
    FAIL(NEW_SRV_ERR_INV_WARN_TEXT);
  if (!n) FAIL(NEW_SRV_ERR_WARN_TEXT_EMPTY);
  warn_len = strlen(warn_txt = dos2unix_str(s));
  while (warn_len > 0 && isspace(warn_txt[warn_len - 1])) warn_len--;
  warn_txt[warn_len] = 0;
  if (!warn_len) FAIL(NEW_SRV_ERR_WARN_TEXT_EMPTY);
  if ((n = hr_cgi_param(phr, "warn_comment", &s)) < 0)
    FAIL(NEW_SRV_ERR_INV_WARN_CMT);
  if (!n) {
    cmt_len = strlen(cmt_txt = xstrdup(""));
  } else {
    cmt_len = strlen(cmt_txt = dos2unix_str(s));
    while (cmt_len > 0 && isspace(cmt_txt[cmt_len - 1])) cmt_len--;
    cmt_txt[cmt_len] = 0;
  }

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, user_id);

  if (cs->xuser_state) {
    cs->xuser_state->vt->append_warning(cs->xuser_state, user_id, phr->user_id,
                                        &phr->ip, cs->current_time, warn_txt, cmt_txt);
    cs->xuser_state->vt->flush(cs->xuser_state);
  }

 cleanup:
  xfree(warn_txt);
  xfree(cmt_txt);
  return retval;
}

static int
priv_user_change_status_2(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0, user_id, status, n;

  if (phr->role < USER_ROLE_JUDGE)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (opcaps_check(phr->caps, OPCAP_EDIT_REG) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (hr_cgi_param_int(phr, "user_id", &user_id) < 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);
  if (hr_cgi_param_int(phr, "status", &status) < 0)
    FAIL(NEW_SRV_ERR_INV_STATUS);
  if (status < 0 || status >= USERLIST_REG_LAST)
    FAIL(NEW_SRV_ERR_INV_STATUS);

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, status);

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    error_page(fout, phr, 1, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    retval = -1;
    goto cleanup;
  }
  n = userlist_clnt_change_registration(ul_conn, user_id, phr->contest_id, status, 0, 0);
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
  if (hr_cgi_param_int(phr, "user_id", &user_id) < 0)
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
  case NEW_SRV_ACTION_TOGGLE_PRIVILEGED:
    flag = USERLIST_UC_PRIVILEGED;
    break;
  case NEW_SRV_ACTION_TOGGLE_REG_READONLY:
    flag = USERLIST_UC_REG_READONLY;
    break;
  default:
    abort();
  }

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, user_id);

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    error_page(fout, phr, 1, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
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
int_sort_func(const void *p1, const void *p2)
{
  int r;
  if (!__builtin_sub_overflow(*(const int *) p1, *(const int *) p2, &r)) {
    return r;
  }
  return *(const int*) p1;
}

static int
parse_user_list(
        struct http_request_info *phr,
        serve_state_t cs,
        intarray_t *uset,
        int skip_user_check)
{
  const unsigned char *s = NULL;
  char *eptr;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int retval = -1;

  if (hr_cgi_param(phr, "new_user_id_list", &s) > 0) {
    while (1) {
      while (isspace(*s)) ++s;
      if (!*s) break;
      errno = 0;
      long v = strtol(s, &eptr, 10);
      if (errno || (*eptr && !isspace(*eptr)) || v <= 0 || (int) v != v) {
        if (phr->log_f) {
          fprintf(phr->log_f, "invalid parameter new_user_id_list value %s", ARMOR(s));
        }
        goto cleanup;
      }
      s = eptr;
      XEXPAND2(*uset);
      uset->v[uset->u++] = v;
    }
  } else {
    for (int i = 0; i < phr->param_num; i++) {
      const unsigned char *p = phr->param_names[i];
      if (strncmp(p, "user_", 5) != 0) continue;
      errno = 0;
      long v = strtol(p + 5, &eptr, 10);
      if (!p[5] || errno || *eptr || v <= 0 || (int) v != v) {
        if (phr->log_f) {
          fprintf(phr->log_f, "invalid parameter name %s", ARMOR(p));
        }
        goto cleanup;
      }
      XEXPAND2(*uset);
      uset->v[uset->u++] = v;
    }
    int first_user_id = 0, last_user_id = -1;
    priv_parse_user_id_range(phr, &first_user_id, &last_user_id);
    if (first_user_id > 0) {
      for (int i = first_user_id; i <= last_user_id; i++) {
        XEXPAND2(*uset);
        uset->v[uset->u++] = i;
      }
    }
  }

  qsort(uset->v, uset->u, sizeof(uset->v[0]), int_sort_func);
  if (uset->u > 0) {
    int i = 0;
    for (int j = 1; j < uset->u; ++j) {
      if (uset->v[i] != uset->v[j] && ++i != j) {
        uset->v[i] = uset->v[j];
      }
    }
    uset->u = i + 1;
  }

  if (skip_user_check <= 0) {
    for (int i = 0; i < uset->u; ++i) {
      if (teamdb_lookup(cs->teamdb_state, uset->v[i]) <= 0) {
        if (phr->log_f) {
          fprintf(phr->log_f, "invalid user id %d", uset->v[i]);
        }
        goto cleanup;
      }
    }
  }
  retval = 1;

cleanup:;
  html_armor_free(&ab);
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
  int retval = 0, i;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  intarray_t uset;
  struct timeval tt;
  long nsec;
  int run_id;

  memset(&uset, 0, sizeof(uset));

  if (phr->role < USER_ROLE_JUDGE)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (opcaps_check(phr->caps, OPCAP_EDIT_REG) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (!global->is_virtual)
    FAIL(NEW_SRV_ERR_NOT_VIRTUAL);

  if (parse_user_list(phr, cs, &uset, 0) < 0) {
    error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
    retval = -1;
    goto cleanup;
  }

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  gettimeofday(&tt, 0);
  nsec = tt.tv_usec * 1000;
  // FIXME: it's a bit risky, need to check the database...
  if (nsec + uset.u >= NSEC_MAX + 1) nsec = NSEC_MAX - 1 - uset.u;

  int legacy_mode = run_is_virtual_legacy_mode(cs->runlog_state);
  for (i = 0; i < uset.u; i++, nsec++) {
    run_id = run_virtual_start(cs->runlog_state, uset.v[i], tt.tv_sec,0,0,nsec);
    if (run_id >= 0 && legacy_mode) {
      serve_move_files_to_insert_run(cs, run_id);
    }
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
  if (hr_cgi_param(phr, "user_id", &s) <= 0
      || sscanf(s, "%d%n", &user_id, &n) != 1 || s[n]
      || teamdb_lookup(cs->teamdb_state, user_id) <= 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);
  if ((n = hr_cgi_param(phr, "disq_comment", &s)) < 0)
    FAIL(NEW_SRV_ERR_INV_WARN_TEXT);
  warn_txt = text_area_process_string(s, 0, 0);

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, user_id);

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    error_page(fout, phr, 1, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
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

  if (cs->xuser_state) {
    cs->xuser_state->vt->set_disq_comment(cs->xuser_state, user_id, warn_txt);
    cs->xuser_state->vt->flush(cs->xuser_state);
  }

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
  time_t sloc = 0, start_time, stop_time;

  if (hr_cgi_param(phr, "sched_time", &s) <= 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_TIME_SPEC);
    return;
  }

  if (xml_parse_date(NULL, 0, 0, 0, s, &sloc) < 0 || sloc < 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_TIME_SPEC);
    return;
  }

  if (sloc > 0) {
    run_get_times(cs->runlog_state, 0, &start_time, 0, 0, &stop_time, 0);
    if (stop_time > 0) {
      ns_error(log_f, NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
      return;
    }
    if (start_time > 0) {
      ns_error(log_f, NEW_SRV_ERR_CONTEST_ALREADY_STARTED);
      return;
    }
  }
  info("audit:%s:%d:%d:%lld", phr->action_str, phr->user_id, phr->contest_id, (long long) sloc);
  run_sched_contest(cs->runlog_state, sloc);
  serve_update_standings_file(phr->extra, cs, cnts, 0);
  serve_update_status_file(ejudge_config, cnts, cs, 1);
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

  if (hr_cgi_param(phr, "dur", &s) <= 0) {
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

  run_get_times(cs->runlog_state, 0, &start_time, 0, 0, &stop_time, 0);

  if (stop_time > 0 && !cs->global->enable_continue) {
    ns_error(log_f, NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
    return;
  }
  if (d > 0 && start_time && start_time + d < cs->current_time) {
    ns_error(log_f, NEW_SRV_ERR_DUR_TOO_SMALL);
    return;
  }

  info("audit:%s:%d:%d:%lld", phr->action_str, phr->user_id, phr->contest_id, (long long) d);
  run_set_duration(cs->runlog_state, d);
  serve_update_standings_file(phr->extra, cs, cnts, 0);
  serve_update_status_file(ejudge_config, cnts, cs, 1);
  return;
}

static void
do_change_finish_time(
        FILE *log_f,
        struct http_request_info *phr,
        serve_state_t cs,
        const struct contest_desc *cnts)
{
  const unsigned char *s = 0;
  time_t ft = 0, start_time = 0, stop_time = 0;

  if (hr_cgi_param(phr, "finish_time", &s) <= 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_TIME_SPEC);
    return;
  }
  if (!is_empty_string(s)) {
    if (xml_parse_date(NULL, 0, 0, 0, s, &ft) < 0 || ft < 0) {
      ns_error(log_f, NEW_SRV_ERR_INV_TIME_SPEC);
      return;
    }
    if (ft < cs->current_time) {
      ns_error(log_f, NEW_SRV_ERR_INV_TIME_SPEC);
      return;
    }
  }

  run_get_times(cs->runlog_state, 0, &start_time, 0, 0, &stop_time, 0);
  if (stop_time > 0) {
    ns_error(log_f, NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
    return;
  }

  info("audit:%s:%d:%d:%lld", phr->action_str, phr->user_id, phr->contest_id, (long long) ft);
  run_set_finish_time(cs->runlog_state, ft);
  serve_update_standings_file(phr->extra, cs, cnts, 0);
  serve_update_status_file(ejudge_config, cnts, cs, 1);
}

static void
do_reload_server(struct contest_extra *extra, void *ptr)
{
  extra->last_access_time = 0;
  expired_contest_last_check_time = 0;
}

void
ns_reload_server_all(void)
{
  ns_for_each_contest_extra(do_reload_server, NULL);
}

static void
ns_reload_contest_pages(int contest_id)
{
  ContestExternalActions *actions = ns_try_contest_external_actions(contest_id);
  if (!actions) return;

  for (int i = 0; i < actions->actions_size; ++i) {
    if (actions->priv_actions) {
      actions->priv_actions[i] = external_action_state_free(actions->priv_actions[i]);
    }
    if (actions->unpriv_actions) {
      actions->unpriv_actions[i] = external_action_state_free(actions->unpriv_actions[i]);
    }
    if (actions->reg_actions) {
      actions->reg_actions[i] = external_action_state_free(actions->reg_actions[i]);
    }
  }
  for (int i = 0; i < actions->errors_size; ++i) {
    if (actions->priv_errors) {
      actions->priv_errors[i] = external_action_state_free(actions->priv_errors[i]);
    }
    if (actions->unpriv_errors) {
      actions->unpriv_errors[i] = external_action_state_free(actions->unpriv_errors[i]);
    }
    if (actions->reg_errors) {
      actions->reg_errors[i] = external_action_state_free(actions->reg_errors[i]);
    }
  }
  if (actions->int_actions) {
    for (int i = 0; i < actions->ints_size; ++i) {
      actions->int_actions[i] = external_action_state_free(actions->int_actions[i]);
    }
  }
}

static void
ns_reload_all_contest_pages()
{
  for (int i = 0; i < cnts_ext_actions.u; ++i) {
    ns_reload_contest_pages(cnts_ext_actions.v[i].contest_id);
  }
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
  int param = 0;

  if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
      || opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  run_get_times(cs->runlog_state, 0, &start_time, 0, &duration, &stop_time, 0);

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
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    run_start_contest(cs->runlog_state, cs->current_time);
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    serve_invoke_start_script(cs);
    serve_update_standings_file(phr->extra, cs, cnts, 0);
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
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    run_stop_contest(cs->runlog_state, cs->current_time);
    serve_invoke_stop_script(cs);
    serve_update_status_file(ejudge_config, cnts, cs, 1);
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
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    run_set_finish_time(cs->runlog_state, 0);
    run_stop_contest(cs->runlog_state, 0);
    serve_invoke_stop_script(cs);
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;

  case NEW_SRV_ACTION_SCHEDULE:
    do_schedule(log_f, phr, cs, cnts);
    break;

  case NEW_SRV_ACTION_CHANGE_DURATION:
    do_change_duration(log_f, phr, cs, cnts);
    break;

  case NEW_SRV_ACTION_CHANGE_FINISH_TIME:
    do_change_finish_time(log_f, phr, cs, cnts);
    break;

  case NEW_SRV_ACTION_SUSPEND:
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    cs->clients_suspended = 1;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;

  case NEW_SRV_ACTION_RESUME:
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    cs->clients_suspended = 0;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;

  case NEW_SRV_ACTION_TEST_SUSPEND:
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    cs->testing_suspended = 1;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;

  case NEW_SRV_ACTION_TEST_RESUME:
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    cs->testing_suspended = 0;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;

  case NEW_SRV_ACTION_PRINT_SUSPEND:
    if (!global->enable_printing) break;
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    cs->printing_suspended = 1;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;

  case NEW_SRV_ACTION_PRINT_RESUME:
    if (!global->enable_printing) break;
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    cs->printing_suspended = 0;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;

  case NEW_SRV_ACTION_SET_JUDGING_MODE:
    if (global->score_system != SCORE_OLYMPIAD) break;
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    cs->accepting_mode = 0;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;

  case NEW_SRV_ACTION_SET_ACCEPTING_MODE:
    if (global->score_system != SCORE_OLYMPIAD) break;
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    cs->accepting_mode = 1;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;

  case NEW_SRV_ACTION_SET_TESTING_FINISHED_FLAG:
    if (global->score_system != SCORE_OLYMPIAD) break;
    if ((!global->is_virtual && cs->accepting_mode)
        ||(global->is_virtual && global->disable_virtual_auto_judge <= 0))
      break;
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    cs->testing_finished = 1;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;

  case NEW_SRV_ACTION_CLEAR_TESTING_FINISHED_FLAG:
    if (global->score_system != SCORE_OLYMPIAD) break;
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    cs->testing_finished = 0;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;

  case NEW_SRV_ACTION_RELOAD_SERVER:
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    extra->last_access_time = 0;
    expired_contest_last_check_time = 0;
    break;

  case NEW_SRV_ACTION_RELOAD_SERVER_ALL:
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    ns_reload_server_all();
    break;

  case NEW_SRV_ACTION_RELOAD_CONTEST_PAGES:
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    ns_reload_contest_pages(cs->contest_id);
    break;

  case NEW_SRV_ACTION_RELOAD_ALL_CONTEST_PAGES:
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    ns_reload_all_contest_pages();
    break;

  case NEW_SRV_ACTION_UPDATE_STANDINGS_2:
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    serve_update_standings_file(phr->extra, cs, cnts, 1);
    break;

  case NEW_SRV_ACTION_RESET_2:
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    serve_reset_contest(cnts, cs);
    extra->last_access_time = 0;
    expired_contest_last_check_time = 0;
    break;

  case NEW_SRV_ACTION_SQUEEZE_RUNS:
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    serve_squeeze_runs(cs);
    break;

  case NEW_SRV_ACTION_DISABLE_VIRTUAL_START:
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    cs->disable_virtual_start = 1;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;

  case NEW_SRV_ACTION_ENABLE_VIRTUAL_START:
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    cs->disable_virtual_start = 0;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;

  case NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_SOURCE:
  case NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_REPORT:
  case NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_JUDGE_SCORE:
  case NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_FINAL_VISIBILITY:
  case NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VALUER_JUDGE_COMMENTS:
    if (hr_cgi_param_int(phr, "param", &param) < 0) {
      ns_error(log_f, NEW_SRV_ERR_INV_PARAM);
      goto cleanup;
    }

    info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, param);

    switch (phr->action) {
    case NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_SOURCE:
      if (param < 0) param = -1;
      else if (param > 0) param = 1;
      cs->online_view_source = param;
      break;
    case NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_REPORT:
      if (param < 0) param = -1;
      else if (param > 0) param = 1;
      cs->online_view_report = param;
      break;
    case NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_JUDGE_SCORE:
      if (param) param = 1;
      cs->online_view_judge_score = param;
      break;
    case NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_FINAL_VISIBILITY:
      if (param) param = 1;
      cs->online_final_visibility = param;
      break;
    case NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VALUER_JUDGE_COMMENTS:
      if (param) param = 1;
      cs->online_valuer_judge_comments = param;
      break;
    }

    serve_update_status_file(ejudge_config, cnts, cs, 1);
    break;

  case NEW_SRV_ACTION_CLEAR_SESSION_CACHE:
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    nsc_clear(&main_id_cache.s);
    tc_clear(&main_id_cache.t);
    break;
  }

 cleanup:
  return 0;
}

static int
priv_regenerate_content(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0;
  opcap_t caps = 0;
  struct avatar_loaded_plugin *avt = NULL;
  struct content_loaded_plugin *cp = NULL;
  unsigned char *xml_text = NULL;
  struct userlist_list *users = NULL;
  struct avatar_info_vector avatars;

  avatar_vector_init(&avatars, 1);

  if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
      || opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) {
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  if (cnts->enable_avatar <= 0) goto cleanup;
  avt = avatar_plugin_get(phr->extra, phr->cnts, phr->config, NULL);
  if (!avt) goto cleanup;
  cp = content_plugin_get(phr->extra, phr->cnts, phr->config, NULL);
  if (!cp) goto cleanup;
  if (cp->iface->is_enabled(cp->data, phr->cnts) <= 0) goto cleanup;

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    goto cleanup;
  }
  int err = userlist_clnt_list_all_users(ul_conn, ULS_LIST_ALL_USERS, phr->contest_id, &xml_text);
  if (err < 0) {
    goto cleanup;
  }
  if (!(users = userlist_parse_str(xml_text))) {
    goto cleanup;
  }
  xfree(xml_text); xml_text = NULL;
  if (users->user_map_size <= 0) {
    goto cleanup;
  }

  for (int user_id = 1; user_id < users->user_map_size; ++user_id) {
    struct userlist_user *u = users->user_map[user_id];
    if (!u) continue;
    if (!u->cnts0) continue;
    if (!u->cnts0->avatar_id || !u->cnts0->avatar_id[0]) continue;

    avatar_vector_clear(&avatars);
    if (avt->iface->fetch_by_key(avt->data, u->cnts0->avatar_id, 0, &avatars) < 0) {
      continue;
    }
    if (avatars.u != 1) {
      continue;
    }
    struct avatar_info *av = &avatars.v[0];
    cp->iface->save_content(cp->data, NULL, phr->config, phr->cnts,
                            av->random_key, mime_type_get_suffix(av->mime_type),
                            av->img_data, av->img_size);
  }

cleanup:;
  avatar_vector_free(&avatars);
  if (users) userlist_free(&users->b);
  xfree(xml_text);
  return retval;
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
    error_page(fout, phr, 0, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    FAIL(1);
  }

  switch (phr->action) {
  case NEW_SRV_ACTION_GENERATE_PASSWORDS_2:
    if (opcaps_check(phr->caps, OPCAP_EDIT_USER) < 0
        && opcaps_check(phr->dbcaps, OPCAP_EDIT_USER) < 0)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    if (cnts->disable_team_password) FAIL(NEW_SRV_ERR_TEAM_PWD_DISABLED);
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    r = userlist_clnt_cnts_passwd_op(ul_conn,
                                     ULS_GENERATE_TEAM_PASSWORDS_2,
                                     cnts->id);
    break;
  case NEW_SRV_ACTION_GENERATE_REG_PASSWORDS_2:
    if (opcaps_check(phr->dbcaps, OPCAP_EDIT_USER) < 0)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
    r = userlist_clnt_cnts_passwd_op(ul_conn,
                                     ULS_GENERATE_PASSWORDS_2,
                                     cnts->id);
    break;
  case NEW_SRV_ACTION_CLEAR_PASSWORDS_2:
    if (opcaps_check(phr->caps, OPCAP_EDIT_USER) < 0
        && opcaps_check(phr->dbcaps, OPCAP_EDIT_USER) < 0)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    if (cnts->disable_team_password) FAIL(NEW_SRV_ERR_TEAM_PWD_DISABLED);
    info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);
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

  if ((r = hr_cgi_param(phr, "locale_id", &s)) < 0) goto invalid_param;
  if (r > 0) {
    if (sscanf(s, "%d%n", &new_locale_id, &n) != 1 || s[n] || new_locale_id < 0)
      goto invalid_param;
  }

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    return -1;
  }
  if ((r = userlist_clnt_set_cookie(ul_conn, ULS_SET_COOKIE_LOCALE,
                                    phr->session_id,
                                    phr->client_key,
                                    new_locale_id)) < 0) {
    ns_error(log_f, NEW_SRV_ERR_SESSION_UPDATE_FAILED, userlist_strerror(-r));
  }
  return 0;

 invalid_param:
  ns_error(log_f, NEW_SRV_ERR_INV_LOCALE_ID);
  return 0;
}

static void
priv_change_password(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const unsigned char *p0 = 0, *p1 = 0, *p2 = 0;
  int cmd, r;
  unsigned char url[1024];
  unsigned char login_buf[256];

  if (hr_cgi_param(phr, "oldpasswd", &p0) <= 0) {
    fprintf(phr->log_f, "cannot parse oldpasswd\n");
    error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
    goto cleanup;
  }
  if (hr_cgi_param(phr, "newpasswd1", &p1) <= 0) {
    fprintf(phr->log_f, "cannot parse newpasswd1\n");
    error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
    goto cleanup;
  }
  if (hr_cgi_param(phr, "newpasswd2", &p2) <= 0) {
    fprintf(phr->log_f, "cannot parse newpasswd2\n");
    error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
    goto cleanup;
  }

  if (strlen(p0) >= 256) {
    error_page(fout, phr, 1, NEW_SRV_ERR_OLD_PWD_TOO_LONG);
    goto cleanup;
  }
  if (strcmp(p1, p2)) {
    error_page(fout, phr, 1, NEW_SRV_ERR_NEW_PWD_MISMATCH);
    goto cleanup;
  }
  if (strlen(p1) >= 256) {
    error_page(fout, phr, 1, NEW_SRV_ERR_NEW_PWD_TOO_LONG);
    goto cleanup;
  }

  cmd = ULS_PRIV_SET_REG_PASSWD;

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    error_page(fout, phr, 1, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    goto cleanup;
  }
  r = userlist_clnt_set_passwd(ul_conn, cmd, phr->user_id, phr->contest_id, 0, p0, p1, NULL);
  if (r < 0) {
    fprintf(phr->log_f, "%s\n", userlist_strerror(-r));
    error_page(fout, phr, 1, NEW_SRV_ERR_PWD_UPDATE_FAILED);
    goto cleanup;
  }

  url_armor_string(login_buf, sizeof(login_buf), phr->login);
  if (phr->rest_mode > 0) {
    snprintf(url, sizeof(url),
             "%s/%s?contest_id=%d&role=%d&login=%s&locale_id=%d",
             phr->self_url, ns_symbolic_action_table[NEW_SRV_ACTION_LOGIN_PAGE],
             phr->contest_id, phr->role,
             login_buf, phr->locale_id);
  } else {
    snprintf(url, sizeof(url),
             "%s?contest_id=%d&role=%d&login=%s&locale_id=%d&action=%d",
             phr->self_url, phr->contest_id, phr->role,
             login_buf, phr->locale_id,
             NEW_SRV_ACTION_LOGIN_PAGE);
  }
  ns_refresh_page_2(fout, phr->client_key, url);

 cleanup:;
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

  case NEW_SRV_ACTION_LOCK_FILTER:
    html_lock_filter(cs, phr->user_id, phr->session_id);
    break;
  }
  return 0;
}

int
ns_load_problem_uuid(
        FILE *log_f,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        int variant)
{
  if (prob->uuid && prob->uuid[0]) return 0;
  if (global->enable_problem_history <= 0 || global->advanced_layout <= 0) {
    if (global->require_problem_uuid > 0) return -1;
    return 0;
  }

  // XXXXX
  unsigned char hist_path[PATH_MAX];
  get_advanced_layout_path(hist_path, sizeof(hist_path), global, prob, "history.txt", variant);
  FILE *hist_f = fopen(hist_path, "r");
  if (!hist_f) {
    if (global->require_problem_uuid <= 0) return 0;
    err("ns_load_problem_uuid: cannot open '%s': %s", hist_path, os_ErrorMsg());
    return -1;
  }
  unsigned char uuid_buf[80];
  if (!fgets(uuid_buf, sizeof(uuid_buf), hist_f)) {
    if (global->require_problem_uuid <= 0) return 0;
    err("ns_load_problem_uuid: file '%s' is empty", hist_path);
    fclose(hist_f);
    return -1;
  }
  fclose(hist_f); hist_f = NULL;
  size_t uuid_z = strlen(uuid_buf);
  if (uuid_z + 1 == sizeof(uuid_buf)) {
    err("ns_load_problem_uuid: line 1 in '%s' is too long", hist_path);
    return -1;
  }
  while (uuid_z > 0 && isspace(uuid_buf[uuid_z - 1])) --uuid_z;
  uuid_buf[uuid_z] = 0;
  if (!uuid_z) {
    if (global->require_problem_uuid <= 0) return 0;
    err("ns_load_problem_uuid: line 1 in '%s' is empty", hist_path);
    return -1;
  }
  // HHHHHHHH-HHHH-HHHH-HHHH-HHHHHHHHHHHH
  //         8901234567890123456789012345
  if (uuid_z != 36) {
    err("ns_load_problem_uuid: line 1 in '%s' is invalid", hist_path);
    return -1;
  }
  if (uuid_buf[8] != '-' || uuid_buf[13] != '-' || uuid_buf[18] != '-' || uuid_buf[23] != '-') {
    err("ns_load_problem_uuid: line 1 in '%s' is invalid, wrong separation", hist_path);
    return -1;
  }
  uuid_buf[8] = '0'; uuid_buf[13] = '0'; uuid_buf[18] = '0'; uuid_buf[23] = '0';
  for (size_t i = 0; i < 36; ++i) {
    if (!isxdigit(uuid_buf[i])) {
      err("ns_load_problem_uuid: line 1 in '%s' is invalid, bad char at %zu", hist_path, i);
      return -1;
    }
    uuid_buf[i] = tolower(uuid_buf[i]);
  }
  uuid_buf[8] = '-'; uuid_buf[13] = '-'; uuid_buf[18] = '-'; uuid_buf[23] = '-';
  if (prob->uuid) {
    xfree(prob->uuid);
    ((struct section_problem_data *) prob)->uuid = NULL;
  }
  ((struct section_problem_data *) prob)->uuid = xstrdup(uuid_buf);
  return 0;
}

static int
priv_submit_run(
        FILE *fout,
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
  int prob_id = 0, variant = 0, lang_id = 0, n, max_ans, ans, i, mime_type = 0, r;
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
  int skip_mime_type_test = 0;
  const unsigned char *text_form_text = 0;
  size_t text_form_size = 0;
  unsigned char *utf8_str = 0;
  int utf8_len = 0;
  int eoln_type = 0;
  int is_hidden = 1, is_visible = 0;
  int sender_user_id = -1;
  int sender_ssl_flag;
  ej_ip_t sender_ip;
  int not_ok_is_cf = 0;
  int rejudge_flag = 0;
  int priority_adjustment = 0;
  int ext_user_kind = 0;
  ej_mixed_id_t ext_user;
  ej_mixed_id_t *ext_user_ptr = NULL;
  int notify_driver = 0;
  int notify_kind = 0;
  ej_mixed_id_t notify_queue;
  ej_mixed_id_t *notify_queue_ptr = NULL;
  struct run_entry new_run;

  if (opcaps_check(phr->caps, OPCAP_SUBMIT_RUN) < 0) {
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }

  if (hr_cgi_param(phr, "sender_user_login", &s) > 0) {
    if (opcaps_check(phr->caps, OPCAP_EDIT_RUN) < 0) {
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    }
    if ((sender_user_id = teamdb_lookup_login(cs->teamdb_state, s)) <= 0) {
      FAIL(NEW_SRV_ERR_INV_USER_ID);
    }
  } else if (hr_cgi_param_int_opt(phr, "sender_user_id", &sender_user_id, -1) >= 0 && sender_user_id > 0) {
    if (opcaps_check(phr->caps, OPCAP_EDIT_RUN) < 0) {
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
    }
    if (teamdb_lookup(cs->teamdb_state, sender_user_id) <= 0) {
      FAIL(NEW_SRV_ERR_INV_USER_ID);
    }
  }
  if (sender_user_id <= 0) sender_user_id = phr->user_id;

  if (hr_cgi_param(phr, "sender_ip", &s) > 0) {
    if (!strcmp(s, "::1")) s = "127.0.0.1";
    if (xml_parse_ipv6(NULL, 0, 0, 0, s, &sender_ip) < 0) {
      fprintf(phr->log_f, "cannot parse sender_ip");
      FAIL(NEW_SRV_ERR_INV_PARAM);
    }
    hr_cgi_param_int_opt(phr, "sender_ssl_flag", &sender_ssl_flag, 0);
  } else {
    sender_ip = phr->ip;
    sender_ssl_flag = phr->ssl_flag;
  }

  hr_cgi_param_int_opt(phr, "not_ok_is_cf", &not_ok_is_cf, 0);
  hr_cgi_param_int_opt(phr, "rejudge_flag", &rejudge_flag, 0);

  if ((hr_cgi_param(phr, "ext_user_kind", &s)) > 0) {
    ext_user_kind = mixed_id_parse_kind(s);
    if (ext_user_kind < 0) {
      fprintf(phr->log_f, "failed to parse ext_user_kind");
      FAIL(NEW_SRV_ERR_INV_EXT_USER);
    }
    if (ext_user_kind > 0) {
      if (hr_cgi_param(phr, "ext_user", &s) <= 0) {
        fprintf(phr->log_f, "missing or binary ext_user");
        FAIL(NEW_SRV_ERR_INV_EXT_USER);
      }
      if (mixed_id_unmarshall(&ext_user, ext_user_kind, s) < 0) {
        fprintf(phr->log_f, "failed to parse ext_user");
        FAIL(NEW_SRV_ERR_INV_EXT_USER);
      }
      ext_user_ptr = &ext_user;
    }
  }

  hr_cgi_param_int_opt(phr, "notify_driver", &notify_driver, 0);
  if (notify_driver < 0 || notify_driver >= 128) {
    FAIL(NEW_SRV_ERR_INV_NOTIFY);
  }
  if (notify_driver > 0) {
    if (!notify_plugin_get(phr->config, notify_driver)) {
      FAIL(NEW_SRV_ERR_INV_NOTIFY);
    }
    if (hr_cgi_param(phr, "notify_kind", &s) <= 0) {
      FAIL(NEW_SRV_ERR_INV_NOTIFY);
    }
    notify_kind = mixed_id_parse_kind(s);
    if (notify_kind < 0) {
      FAIL(NEW_SRV_ERR_INV_NOTIFY);
    }
    if (notify_kind > 0) {
      if (hr_cgi_param(phr, "notify_queue", &s) <= 0) {
        FAIL(NEW_SRV_ERR_INV_NOTIFY);
      }
      if (mixed_id_unmarshall(&notify_queue, notify_kind, s) < 0) {
        FAIL(NEW_SRV_ERR_INV_NOTIFY);
      }
      notify_queue_ptr = &notify_queue;
    }
  }

  if (rejudge_flag > 0) {
    priority_adjustment = 3;
  }

  if (hr_cgi_param(phr, "problem_uuid", &s) > 0) {
    for (prob_id = 1; prob_id <= cs->max_prob; ++prob_id) {
      prob = cs->probs[prob_id];
      if (prob) {
        if (prob->uuid && !strcmp(s, prob->uuid)) {
          break;
        }
      }
    }
    if (prob_id > cs->max_prob) {
      fprintf(phr->log_f, "'problem_name' parameter is not set or invalid\n");
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
    }
  } else if (hr_cgi_param(phr, "problem_name", &s) > 0) {
    for (prob_id = 1; prob_id <= cs->max_prob; ++prob_id) {
      prob = cs->probs[prob_id];
      if (prob) {
        if ((/*prob->short_name &&*/ !strcmp(s, prob->short_name))
            || (prob->internal_name && !strcmp(s, prob->internal_name))) {
          break;
        }
      }
    }
    if (prob_id > cs->max_prob) {
      fprintf(phr->log_f, "'problem_name' parameter is not set or invalid\n");
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
    }
  } else {
    if (hr_cgi_param_int(phr, "problem", &prob_id) < 0) {
      fprintf(phr->log_f, "'problem' parameter is not set or invalid\n");
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
    }
    if (prob_id <= 0 || prob_id > cs->max_prob || !(prob = cs->probs[prob_id])) {
      fprintf(phr->log_f, "invalid problem id\n");
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
    }
  }
  if (hr_cgi_param_int_opt(phr, "variant", &variant, 0) < 0) {
    fprintf(phr->log_f, "'variant' parameter is invalid\n");
    FAIL(NEW_SRV_ERR_INV_VARIANT);
  }
  if (prob->variant_num <= 0 && variant != 0) {
    fprintf(phr->log_f, "variant is not allowed\n");
    FAIL(NEW_SRV_ERR_INV_VARIANT);
  } else if (prob->variant_num > 0 && (variant <= 0 || variant > prob->variant_num)) {
    fprintf(phr->log_f, "variant is invalid\n");
    FAIL(NEW_SRV_ERR_INV_VARIANT);
  }


  /*
  if (hr_cgi_param(phr, "problem", &s) <= 0) {
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
  */

  if (prob->type == PROB_TYPE_STANDARD) {
    if (hr_cgi_param(phr, "language_name", &s) > 0) {
      for (lang_id = 1; lang_id <= cs->max_lang; ++lang_id) {
        lang = cs->langs[lang_id];
        if (lang && /*lang->short_name &&*/ !strcmp(lang->short_name, s)) {
          break;
        }
      }
      if (lang_id > cs->max_lang) {
        fprintf(phr->log_f, "'lang_id' is invalid\n");
        FAIL(NEW_SRV_ERR_INV_LANG_ID);
      }
    } else {
      int r = hr_cgi_param(phr, "lang_id", &s);
      if (r < 0){
        fprintf(phr->log_f, "'lang_id' is binary\n");
        FAIL(NEW_SRV_ERR_INV_LANG_ID);
      }
      if (!r) {
        if (prob->custom_compile_cmd && prob->custom_compile_cmd[0]) {
          for (r = 1; r <= cs->max_lang; ++r) {
            if (cs->langs[r] && cs->langs[r]->enable_custom > 0) {
              break;
            }
          }
          if (r <= cs->max_lang) {
            lang_id = r;
            lang = cs->langs[r];
          } else {
            fprintf(phr->log_f, "'lang_id' is not set\n");
            FAIL(NEW_SRV_ERR_INV_LANG_ID);
          }
        } else {
          fprintf(phr->log_f, "'lang_id' is not set\n");
          FAIL(NEW_SRV_ERR_INV_LANG_ID);
        }
      } else {
        errno = 0;
        char *eptr = NULL;
        long v = strtol(s, &eptr, 10);
        if (!errno && !*eptr && eptr != (char *) s && v > 0 && v <= cs->max_lang) {
          lang_id = v;
          lang = cs->langs[lang_id];
          if (!lang) {
            fprintf(phr->log_f, "'lang_id' is invalid\n");
            FAIL(NEW_SRV_ERR_INV_LANG_ID);
          }
        } else {
          for (lang_id = 1; lang_id <= cs->max_lang; ++lang_id) {
            if (cs->langs[lang_id] && !strcmp(cs->langs[lang_id]->short_name, s)) {
              break;
            }
          }
          if (lang_id <= cs->max_lang) {
            lang = cs->langs[lang_id];
          } else {
            fprintf(phr->log_f, "'lang_id' is invalid\n");
            FAIL(NEW_SRV_ERR_INV_LANG_ID);
          }
        }
      }
    }
    if (cs->global->enable_eoln_select > 0) {
      hr_cgi_param_int_opt(phr, "eoln_type", &eoln_type, 0);
      if (eoln_type < 0 || eoln_type > EOLN_CRLF) eoln_type = 0;
    }
  }

  hr_cgi_param_int_opt(phr, "is_visible", &is_visible, 0);
  if (is_visible > 0) is_hidden = 0;

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

  /* get the submission text */
  switch (prob->type) {
    /*
  case PROB_TYPE_STANDARD:      // "file"
    if (!ns_cgi_param_bin(phr, "file", &run_text, &run_size)) {
      errmsg = "\"file\" parameter is not set";
      goto invalid_param;
    }
    break;
    */
  case PROB_TYPE_STANDARD:
  case PROB_TYPE_OUTPUT_ONLY:
  case PROB_TYPE_TESTS:
    if (prob->enable_text_form > 0) {
      int r1 = hr_cgi_param_bin(phr, "file", &run_text, &run_size);
      int r2 = hr_cgi_param_bin(phr, "text_form", &text_form_text,
                                &text_form_size);
      if (!r1 && !r2) {
        fprintf(phr->log_f, "neither 'file' nor 'text' parameters are set\n");
        FAIL(NEW_SRV_ERR_INV_PARAM);
      }
    } else {
      if (!hr_cgi_param_bin(phr, "file", &run_text, &run_size)) {
        fprintf(phr->log_f, "'file' parameter is not set\n");
        FAIL(NEW_SRV_ERR_INV_PARAM);
      }
    }
    break;
  case PROB_TYPE_TEXT_ANSWER:
  case PROB_TYPE_SHORT_ANSWER:
  case PROB_TYPE_SELECT_ONE:
    if (!hr_cgi_param_bin(phr, "file", &run_text, &run_size)) {
      fprintf(phr->log_f, "'file' parameter is not set\n");
      FAIL(NEW_SRV_ERR_INV_PARAM);
    }
    break;
  case PROB_TYPE_SELECT_MANY:   // "ans_*"
    for (i = 0, max_ans = -1, ans_size = 0; i < phr->param_num; i++)
      if (!strncmp(phr->param_names[i], "ans_", 4)) {
        if (sscanf(phr->param_names[i] + 4, "%d%n", &ans, &n) != 1 || phr->param_names[i][4 + n]) {
          fprintf(phr->log_f, "'ans_*' parameter is invalid\n");
          FAIL(NEW_SRV_ERR_INV_PARAM);
        }
        if (ans < 0 || ans > 65535) {
          fprintf(phr->log_f, "'ans_*' parameter is out of range");
          FAIL(NEW_SRV_ERR_INV_PARAM);
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
      fprintf(phr->log_f, "problem plugin is not available\n");
      FAIL(NEW_SRV_ERR_INV_PARAM);
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

  switch (prob->type) {
  case PROB_TYPE_STANDARD:
    if (!lang->binary && strlen(run_text) != run_size) {
      // guess utf-16/ucs-2
      if (((int) run_size) < 0) goto binary_submission;
      if ((utf8_len = ucs2_to_utf8(&utf8_str, run_text, run_size)) < 0)
        goto binary_submission;
      run_text = utf8_str;
      run_size = (size_t) utf8_len;
    }
    if (prob->enable_text_form > 0 && text_form_text
        && strlen(text_form_text) != text_form_size)
      goto binary_submission;
    if (prob->enable_text_form) {
      if (!run_size) {
        run_text = text_form_text; text_form_text = 0;
        run_size = text_form_size; text_form_size = 0;
        skip_mime_type_test = 1;
      } else {
        text_form_text = 0;
        text_form_size = 0;
      }
    }
    if (prob->disable_ctrl_chars > 0 && has_control_characters(run_text))
      goto invalid_characters;
    break;
  case PROB_TYPE_OUTPUT_ONLY:
  case PROB_TYPE_TESTS:
    if (!prob->binary_input && !prob->binary && strlen(run_text) != run_size)
      goto binary_submission;
    if (prob->enable_text_form > 0 && text_form_text
        && strlen(text_form_text) != text_form_size)
      goto binary_submission;
    if (prob->enable_text_form) {
      if (!run_size) {
        run_text = text_form_text; text_form_text = 0;
        run_size = text_form_size; text_form_size = 0;
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
    if (strlen(run_text) != run_size) goto binary_submission;
    break;

  case PROB_TYPE_SELECT_MANY:
  case PROB_TYPE_CUSTOM:
    break;

  binary_submission:
    fprintf(phr->log_f, "binary submission\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);

  invalid_characters:
    fprintf(phr->log_f, "binary submission\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }

  // ignore BOM
  if (global->ignore_bom > 0 && !prob->binary && (!lang || !lang->binary)) {
    if (run_text && run_size >= 3 && run_text[0] == 0xef
        && run_text[1] == 0xbb && run_text[2] == 0xbf) {
      run_text += 3; run_size -= 3;
    }
  }

  /* check for disabled languages */
  if (lang_id > 0) {
    if (lang->disabled) {
      fprintf(log_f, "Language '%s' is disabled\n", lang->short_name);
      FAIL(NEW_SRV_ERR_LANG_DISABLED);
    }

    if (prob->enable_language) {
      lang_list = prob->enable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], lang->short_name))
          break;
      if (!lang_list[i]) {
        fprintf(log_f, "Language '%s' is not enabled for problem '%s'\n", lang->short_name, prob->short_name);
        FAIL(NEW_SRV_ERR_LANG_NOT_AVAIL_FOR_PROBLEM);
      }
    } else if (prob->disable_language) {
      lang_list = prob->disable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], lang->short_name))
          break;
      if (lang_list[i]) {
        fprintf(log_f, "Language '%s' is disabled for problem '%s'\n", lang->short_name, prob->short_name);
        FAIL(NEW_SRV_ERR_LANG_DISABLED_FOR_PROBLEM);
      }
    }
  } else if (skip_mime_type_test) {
    mime_type = 0;
    mime_type_str = mime_type_get_type(mime_type);
  } else {
    // guess the content-type and check it against the list
    if ((mime_type = mime_type_guess(global->diff_work_dir, run_text, run_size)) < 0) {
      FAIL(NEW_SRV_ERR_CANNOT_DETECT_CONTENT_TYPE);
    }
    mime_type_str = mime_type_get_type(mime_type);
    if (prob->enable_language) {
      lang_list = prob->enable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], mime_type_str))
          break;
      if (!lang_list[i]) {
        fprintf(log_f, "Content type '%s' is not enabled for problem '%s'\n", mime_type_str, prob->short_name);
        FAIL(NEW_SRV_ERR_CONTENT_TYPE_NOT_AVAILABLE);
      }
    } else if (prob->disable_language) {
      lang_list = prob->disable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], mime_type_str))
          break;
      if (lang_list[i]) {
        fprintf(log_f, "Content type '%s' is disabled for problem '%s'\n", mime_type_str, prob->short_name);
        FAIL(NEW_SRV_ERR_CONTENT_TYPE_DISABLED);
        goto cleanup;
      }
    }
  }
  if (ns_load_problem_uuid(phr->log_f, global, prob, variant) < 0) {
    fprintf(log_f, "UUID for this problem is undefined\n");
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
    goto cleanup;
  }

  // OK, so all checks are done, now we add this submit to the database
  sha_buffer(run_text, run_size, shaval);

  ej_uuid_t run_uuid = {};
  int store_flags = 0;
  if (global->uuid_run_store > 0 && run_get_uuid_hash_state(cs->runlog_state) >= 0) {
    store_flags = STORE_FLAGS_UUID;
    if (testing_report_bson_available()) store_flags = STORE_FLAGS_UUID_BSON;
  }
  run_id = run_add_record(cs->runlog_state,
                          &precise_time,
                          run_size, shaval, &run_uuid,
                          &sender_ip, sender_ssl_flag,
                          phr->locale_id, sender_user_id,
                          prob_id, lang_id, eoln_type,
                          variant, is_hidden, mime_type,
                          prob->uuid,
                          store_flags,
                          phr->is_job /* is_vcs */,
                          ext_user_kind,
                          ext_user_ptr,
                          notify_driver,
                          notify_kind,
                          notify_queue_ptr,
                          &new_run);
  if (run_id < 0) {
    FAIL(NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
  }
  if (metrics.data) {
    ++metrics.data->runs_submitted;
  }
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

  const struct userlist_user *user = teamdb_get_userlist(cs->teamdb_state, sender_user_id);

  if (prob->type == PROB_TYPE_STANDARD) {
    // automatically tested programs
    if (prob->disable_auto_testing > 0
        || (prob->disable_testing > 0 && prob->enable_compilation <= 0)
        || lang->disable_auto_testing || lang->disable_testing) {
      serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                      "priv-submit", "ok", RUN_PENDING,
                      "  Testing disabled for this problem or language");
      run_change_status_4(cs->runlog_state, run_id, RUN_PENDING, &new_run);
      serve_notify_run_update(phr->config, cs, &new_run);
    } else {
      serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                      "priv-submit", "ok", RUN_COMPILING, NULL);
      if ((r = serve_compile_request(phr->config, cs, run_text, run_size, cnts->id,
                                     run_id, 0 /* submit_id */, sender_user_id,
                                     variant,
                                     phr->locale_id,
                                     0 /* output_only */,
                                     lang->src_sfx,
                                     0 /* style_check_only */,
                                     -1 /* accepting_mode */,
                                     priority_adjustment,
                                     0 /* notify_flag */,
                                     prob, lang, 0, &run_uuid,
                                     NULL /* judge_uuid */,
                                     store_flags, rejudge_flag,
                                     phr->is_job,
                                     not_ok_is_cf,
                                     user,
                                     &new_run)) < 0) {
        serve_report_check_failed(ejudge_config, cnts, cs, run_id, serve_err_str(r));
      }
    }
  } else if (prob->manual_checking > 0) {
    // manually tested outputs
    if (prob->check_presentation <= 0) {
      serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                      "priv-submit", "ok", RUN_ACCEPTED,
                      "  This problem is checked manually");
      run_change_status_4(cs->runlog_state, run_id, RUN_ACCEPTED, &new_run);
      serve_notify_run_update(phr->config, cs, &new_run);
    } else {
      serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                      "priv-submit", "ok", RUN_COMPILING, NULL);
      if (prob->style_checker_cmd && prob->style_checker_cmd[0]) {
        r = serve_compile_request(phr->config, cs, run_text, run_size, cnts->id,
                                  run_id, 0 /* submit_id */, sender_user_id,
                                  variant,
                                  0 /* locale_id */, 1 /* output_only*/,
                                  mime_type_get_suffix(mime_type),
                                  1 /* style_check_only */,
                                  0 /* accepting_mode */,
                                  priority_adjustment,
                                  0 /* notify flag */,
                                  prob, NULL /* lang */,
                                  0 /* no_db_flag */,
                                  &run_uuid,
                                  NULL /* judge_uuid */,
                                  store_flags,
                                  rejudge_flag,
                                  phr->is_job,
                                  not_ok_is_cf,
                                  user,
                                  &new_run);
        if (r < 0) {
          serve_report_check_failed(ejudge_config, cnts, cs, run_id, serve_err_str(r));
        }
      } else {
        if (serve_run_request(phr->config, cs, cnts, log_f, run_text, run_size,
                              cnts->id, run_id,
                              0 /* submit_id */,
                              sender_user_id, prob_id, 0, variant, 0,
                              -1, /* judge_id */
                              NULL, /* judge_uuid */
                              -1, 0,
                              mime_type, 0, phr->locale_id, 0, 0, 0, &run_uuid,
                              rejudge_flag, 0 /* zip_mode */,
                              store_flags,
                              not_ok_is_cf,
                              NULL, 0,
                              &new_run,
                              NULL /* src_text */,
                              0 /* src_size */) < 0) {
          FAIL(NEW_SRV_ERR_DISK_WRITE_ERROR);
        }
      }
    }
  } else {
    // automatically tested outputs
    if (prob->disable_auto_testing > 0
        || (prob->disable_testing > 0 && prob->enable_compilation <= 0)) {
      serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                      "priv-submit", "ok", RUN_PENDING,
                      "  Testing disabled for this problem");
      run_change_status_4(cs->runlog_state, run_id, RUN_PENDING, &new_run);
      serve_notify_run_update(phr->config, cs, &new_run);
    } else {
      serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                      "priv-submit", "ok", RUN_COMPILING, NULL);
      /* FIXME: check for XML problem */
      if (prob->style_checker_cmd && prob->style_checker_cmd[0]) {
        r = serve_compile_request(phr->config, cs, run_text, run_size, cnts->id,
                                  run_id, 0 /* submit_id */, sender_user_id,
                                  variant,
                                  0 /* locale_id */, 1 /* output_only*/,
                                  mime_type_get_suffix(mime_type),
                                  1 /* style_check_only */,
                                  0 /* accepting_mode */,
                                  priority_adjustment,
                                  0 /* notify flag */,
                                  prob, NULL /* lang */,
                                  0 /* no_db_flag */,
                                  &run_uuid,
                                  NULL /* judge_uuid */,
                                  store_flags,
                                  rejudge_flag,
                                  phr->is_job,
                                  not_ok_is_cf,
                                  user,
                                  &new_run);
        if (r < 0) {
          serve_report_check_failed(ejudge_config, cnts, cs, run_id, serve_err_str(r));
        }
      } else {
        if (serve_run_request(phr->config, cs, cnts, log_f, run_text, run_size,
                              cnts->id, run_id,
                              0 /* submit_id */,
                              sender_user_id, prob_id, 0, variant, 0,
                              -1, /* judge_id */
                              NULL, /* judge_uuid */
                              -1, 0,
                              mime_type, 0, phr->locale_id, 0, 0, 0, &run_uuid,
                              rejudge_flag, 0 /* zip_mode */,
                              store_flags,
                              not_ok_is_cf,
                              NULL, 0,
                              &new_run,
                              NULL /* src_text */,
                              0 /* src_size */) < 0) {
          FAIL(NEW_SRV_ERR_DISK_WRITE_ERROR);
        }
      }
    }
  }

  if (phr->json_reply) {
    fprintf(fout, "{\n");
    fprintf(fout, "  \"ok\" : %s", "true");
    fprintf(fout, ",\n  \"server_time\": %lld", (long long) cs->current_time);
    fprintf(fout, ",\n  \"result\": {");
    fprintf(fout, "\n    \"run_id\": %d", run_id);
    fprintf(fout, ",\n    \"run_uuid\": \"%s\"", ej_uuid_unparse(&run_uuid, ""));
    fprintf(fout, "\n  }");
    fprintf(fout, "\n}\n");
  }

 cleanup:
  xfree(utf8_str);
  return retval;
}

static int
priv_submit_clar(
        FILE *fout,
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
  struct timeval precise_time;
  int msg_dest_id_empty = 0, msg_dest_login_empty = 0;

  html_armor_init(&ab);

  if (opcaps_check(phr->caps, OPCAP_NEW_MESSAGE) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  // msg_dest_id, msg_dest_login, msg_subj, msg_hide_flag, msg_text
  if ((n = hr_cgi_param(phr, "msg_dest_id", &s)) < 0) {
    errmsg = "msg_dest_id is binary";
    goto invalid_param;
  }
  if (n <= 0 || is_empty_string(s)) {
    msg_dest_id_empty = 1;
  } else {
    if (sscanf(s, "%d%n", &user_id, &n) != 1 || s[n]) {
      errmsg = "msg_dest_id is invalid";
      goto invalid_param;
    }
    if (user_id && !teamdb_lookup(cs->teamdb_state, user_id)) {
      ns_error(log_f, NEW_SRV_ERR_USER_ID_NONEXISTANT, user_id);
      goto cleanup;
    }
  }
  if ((n = hr_cgi_param(phr, "msg_dest_login", &s)) < 0) {
    errmsg = "msg_dest_login is binary";
    goto invalid_param;
  }
  if (n <= 0 || is_empty_string(s)) {
    msg_dest_login_empty = 1;
  } else {
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
  if (msg_dest_id_empty && msg_dest_login_empty) {
    errmsg = "neither user_id nor login are not specified";
    goto invalid_param;
  }
  if ((n = hr_cgi_param(phr, "msg_subj", &subject)) < 0) {
    errmsg = "msg_subj is binary";
    goto invalid_param;
  }
  if (!subject) subject = "";
  if ((n = hr_cgi_param(phr, "msg_text", &text)) < 0) {
    errmsg = "msg_text is binary";
    goto invalid_param;
  }
  if (!text) text = "";
  if ((n = hr_cgi_param(phr, "msg_hide_flag", &s)) < 0) {
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

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

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

  if (text3_len > cs->global->max_clar_size) {
    ns_error(log_f, NEW_SRV_ERR_MESSAGE_TOO_LONG, text3_len);
    goto cleanup;
  }

  ej_uuid_t clar_uuid = {};
  gettimeofday(&precise_time, 0);
  if ((clar_id = clar_add_record(cs->clarlog_state,
                                 precise_time.tv_sec,
                                 precise_time.tv_usec * 1000,
                                 text3_len,
                                 &phr->ip,
                                 phr->ssl_flag,
                                 0, user_id, 0, phr->user_id,
                                 hide_flag, phr->locale_id,
                                 0 /* in_reply_to */,
                                 NULL /* in_reply_uuid */,
                                 0 /* run_id */,
                                 NULL /* run_uuid */,
                                 0 /* appeal_flag */,
                                 0 /* old_run_status */,
                                 0 /* new_run_status */,
                                 utf8_mode, NULL, subj2, &clar_uuid)) < 0) {
    ns_error(log_f, NEW_SRV_ERR_CLARLOG_UPDATE_FAILED);
    goto cleanup;
  }

  if (clar_add_text(cs->clarlog_state, clar_id, &clar_uuid, text3, text3_len) < 0) {
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto cleanup;
  }

  if (global->notify_clar_reply && user_id > 0) {
    unsigned char nsubj[1024];
    FILE *msg_f = 0;
    char *msg_t = 0;
    size_t msg_z = 0;

    if (cnts->default_locale_num > 0)
      l10n_setlocale(cnts->default_locale_num);
    snprintf(nsubj, sizeof(nsubj),
             _("You have received a message from judges in contest %d"),
             cnts->id);
    msg_f = open_memstream(&msg_t, &msg_z);
    fprintf(msg_f, _("You have received a message from judges\n"));
    fprintf(msg_f, _("Contest: %d (%s)\n"), cnts->id, cnts->name);
    if (cnts->team_url) {
      fprintf(msg_f, "URL: %s?contest_id=%d&login=%s\n", cnts->team_url,
              cnts->id, teamdb_get_login(cs->teamdb_state, user_id));
    }
    fprintf(msg_f, "%s\n", text3);
    fprintf(msg_f, "\n-\nRegards,\nthe ejudge contest management system (www.ejudge.ru)\n");
    close_memstream(msg_f); msg_f = 0;
    l10n_resetlocale();
    serve_send_email_to_user(ejudge_config, cnts, cs, user_id, nsubj, msg_t);
    xfree(msg_t); msg_t = 0; msg_z = 0;
  }

  /*
  serve_send_clar_notify_email(cs, cnts, phr->user_id, phr->name, subj3, text2);
  */

 cleanup:
  html_armor_free(&ab);
  return 0;

 invalid_param:
  fprintf(phr->log_f, "%s", errmsg);
  error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
  return -1;
}

static int
parse_run_id(FILE *fout, struct http_request_info *phr,
             const struct contest_desc *cnts,
             struct contest_extra *extra, int *p_run_id, struct run_entry *pe);

static int
priv_set_run_rejected_status(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  ns_error(log_f, NEW_SRV_ERR_NOT_SUPPORTED);
  return 0;
  /*
  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  int run_id = 0, rep_flags;
  struct run_entry re;
  const unsigned char *text = 0;
  unsigned char *text2 = 0;
  size_t text_len, text2_len;
  unsigned char errmsg[1024];
  unsigned char rep_path[PATH_MAX];

  if (opcaps_check(phr->caps, OPCAP_COMMENT_RUN) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  errmsg[0] = 0;
  if (parse_run_id(fout, phr, cnts, extra, &run_id, &re) < 0) return -1;
  if (re.user_id && !teamdb_lookup(cs->teamdb_state, re.user_id)) {
    ns_error(log_f, NEW_SRV_ERR_USER_ID_NONEXISTANT, re.user_id);
    goto cleanup;
  }
  if ((re.status != RUN_ACCEPTED && re.status != RUN_PENDING_REVIEW && re.status != RUN_SUMMONED) && opcaps_check(phr->caps, OPCAP_EDIT_RUN)<0){
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }
  if (hr_cgi_param(phr, "msg_text", &text) < 0) {
    snprintf(errmsg, sizeof(errmsg), "%s", "msg_text is binary");
    goto invalid_param;
  }
  if (!text) text = "";
  text_len = strlen(text);
  if (text_len > 128 * 1024) {
    ns_error(log_f, NEW_SRV_ERR_MESSAGE_TOO_LONG, text_len);
    goto cleanup;
  }
  text2 = text_area_process_string(text, 0, 0);
  text2_len = strlen(text2);

  if (re.store_flags == STORE_FLAG_UUID) {
    rep_flags = uuid_archive_prepare_write_path(cs, rep_path, sizeof(rep_path),
                                                &re.run_uuid, text2_len, DFLT_R_UUID_XML_REPORT, 0, 0);
  } else {
    rep_flags = archive_prepare_write_path(cs, rep_path, sizeof(rep_path),
                                           global->xml_report_archive_dir, run_id,
                                           text2_len, NULL, 0, 0);
  }
  if (rep_flags < 0) {
    snprintf(errmsg, sizeof(errmsg),
             "archive_make_write_path: %s, %d, %zu failed\n",
             global->xml_report_archive_dir, run_id,
             text2_len);
    goto invalid_param;
  }

  if (generic_write_file(text2, text2_len, rep_flags, 0, rep_path, "") < 0) {
    snprintf(errmsg, sizeof(errmsg), "generic_write_file: %s, %d, %zu failed\n",
             global->xml_report_archive_dir, run_id, text2_len);
    goto invalid_param;
  }
  if (run_change_status_4(cs->runlog_state, run_id, RUN_REJECTED) < 0)
    goto invalid_param;

  serve_audit_log(cs, run_id, &re, phr->user_id, &phr->ip, phr->ssl_flag,
                  "set-rejected", "ok", RUN_REJECTED, NULL);

  if (global->notify_status_change > 0 && !re.is_hidden) {
    serve_notify_user_run_status_change(ejudge_config, cnts, cs, re.user_id,
                                        run_id, RUN_REJECTED);
  }
  if (cnts->enable_user_telegram > 0 && !re.is_hidden) {
    serve_telegram_user_run_reviewed(ejudge_config, cnts, cs, re.user_id, run_id, RUN_REJECTED);
  }

 cleanup:
  xfree(text2);
  return 0;

 invalid_param:
  xfree(text2);
  fprintf(phr->log_f, "%s", errmsg);
  error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
  return -1;
  */
}

static int
priv_submit_run_comment(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  int run_id = 0, clar_id = 0;
  struct run_entry re;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *text = 0;
  const unsigned char *errmsg = 0;
  size_t text_len, subj_len, text3_len;
  unsigned char *text2 = 0, *text3 = 0;
  unsigned char subj2[1024];
  struct timeval precise_time;

  if (parse_run_id(fout, phr, cnts, extra, &run_id, &re) < 0) return -1;
  if (re.user_id && !teamdb_lookup(cs->teamdb_state, re.user_id)) {
    ns_error(log_f, NEW_SRV_ERR_USER_ID_NONEXISTANT, re.user_id);
    goto cleanup;
  }
  if (hr_cgi_param(phr, "msg_text", &text) < 0) {
    errmsg = "msg_text is binary";
    goto invalid_param;
  }
  if (!text) text = "";
  text_len = strlen(text);
  if (text_len > 56 * 1024) {
    ns_error(log_f, NEW_SRV_ERR_MESSAGE_TOO_LONG, text_len);
    goto cleanup;
  }
  text2 = alloca(text_len + 1);
  memcpy(text2, text, text_len + 1);
  while (text_len > 0 && isspace(text2[text_len - 1])) text2[--text_len] = 0;
  if (!text_len) {
    ns_error(log_f, NEW_SRV_ERR_MESSAGE_EMPTY);
    goto cleanup;
  }

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, run_id);

  snprintf(subj2, sizeof(subj2), "%d %s", run_id, _("is commented"));
  subj_len = strlen(subj2);

  text3 = alloca(subj_len + text_len + 32);
  text3_len = sprintf(text3, "Subject: %s\n\n%s\n", subj2, text2);

  int old_status = 0;
  int new_status = 0;
  if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT) {
  } else if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_IGNORE) {
    old_status = re.status + 1;
    new_status = RUN_IGNORED + 1;
  } else if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_REJECT) {
    old_status = re.status + 1;
    new_status = RUN_REJECTED + 1;
  } else if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_SUMMON) {
    old_status = re.status + 1;
    new_status = RUN_SUMMONED + 1;
  } else if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_OK) {
    old_status = re.status + 1;
    new_status = RUN_OK + 1;
  } else {
    abort();
  }

  ej_uuid_t clar_uuid = {};
  gettimeofday(&precise_time, 0);
  if ((clar_id = clar_add_record(cs->clarlog_state,
                                 precise_time.tv_sec,
                                 precise_time.tv_usec * 1000,
                                 text3_len,
                                 &phr->ip,
                                 phr->ssl_flag,
                                 0, re.user_id, 0, phr->user_id,
                                 0, phr->locale_id,
                                 0 /* in_reply_to */,
                                 NULL /* in_reply_uuid */,
                                 run_id + 1,
                                 &re.run_uuid,
                                 0 /* appeal_flag */,
                                 old_status,
                                 new_status,
                                 utf8_mode, NULL, subj2, &clar_uuid)) < 0) {
    ns_error(log_f, NEW_SRV_ERR_CLARLOG_UPDATE_FAILED);
    goto cleanup;
  }

  if (clar_add_text(cs->clarlog_state, clar_id, &clar_uuid, text3, text3_len) < 0) {
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto cleanup;
  }

  if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_IGNORE) {
    run_change_status_4(cs->runlog_state, run_id, RUN_IGNORED, &re);
    serve_notify_run_update(phr->config, cs, &re);
  } else if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_REJECT) {
    run_change_status_4(cs->runlog_state, run_id, RUN_REJECTED, &re);
    serve_notify_run_update(phr->config, cs, &re);
  } else if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_SUMMON) {
    run_change_status_4(cs->runlog_state, run_id, RUN_SUMMONED, &re);
    serve_notify_run_update(phr->config, cs, &re);
  } else if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_OK) {
    struct section_problem_data *prob = 0;
    int full_score = 0;
    int user_status = 0, user_score = 0;
    if (re.prob_id > 0 && re.prob_id <= cs->max_prob) prob = cs->probs[re.prob_id];
    if (prob) full_score = prob->full_score;
    if (global->separate_user_score > 0 && re.is_saved) {
      user_status = RUN_OK;
      user_score = -1;
      if (prob) user_score = prob->full_user_score;
      if (prob && user_score < 0) user_score = prob->full_score;
      if (user_score < 0) user_score = 0;
    }
    run_change_status_3(cs->runlog_state, /* state */
                        run_id,           /* runid */
                        RUN_OK,           /* newstatus */
                        re.test,          /* newtest */
                        re.passed_mode,   /* newpassedmode */
                        full_score,       /* newscore */
                        0,                /* is_marked */
                        re.saved_score,   /* has_user_score -> is_saved */
                        user_status,      /* user_status -> saved_status */
                        re.saved_test,    /* user_tests_passed -> saved_test */
                        user_score,       /* user_score -> saved_score */
                        re.verdict_bits, &re);
    serve_notify_run_update(phr->config, cs, &re);
  }

  const unsigned char *audit_cmd = NULL;
  int status = -1;
  if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT) {
    audit_cmd = "comment-run";
  } else if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_OK) {
    audit_cmd = "comment-run-ok";
    status = RUN_OK;
  } else if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_IGNORE) {
    audit_cmd = "comment-run-ignore";
    status = RUN_IGNORED;
  } else if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_REJECT) {
    audit_cmd = "comment-run-reject";
    status = RUN_REJECTED;
  } else if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_SUMMON) {
    audit_cmd = "comment-run-summon";
    status = RUN_SUMMONED;
  } else {
    abort();
  }

  serve_audit_log(cs, run_id, &re, phr->user_id, &phr->ip, phr->ssl_flag,
                  audit_cmd, "ok", status, NULL);

  if (global->notify_clar_reply) {
    unsigned char nsubj[1024];
    FILE *msg_f = 0;
    char *msg_t = 0;
    size_t msg_z = 0;

    if (cnts->default_locale_num > 0)
      l10n_setlocale(cnts->default_locale_num);
    snprintf(nsubj, sizeof(nsubj),
             _("Your submit has been commented in contest %d"),
             cnts->id);
    msg_f = open_memstream(&msg_t, &msg_z);
    if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_IGNORE) {
      fprintf(msg_f, _("Your submit has been commented and ignored\n"));
    } else if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_REJECT) {
      fprintf(msg_f, _("Your submit has been commented and rejected\n"));
    } else if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_SUMMON) {
      fprintf(msg_f, _("Your submit has been commented and summoned for defence\n"));
    } else if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_OK) {
      fprintf(msg_f, _("Your submit has been commented and accepted\n"));
    } else {
      fprintf(msg_f, _("Your submit has been commented\n"));
    }
    fprintf(msg_f, _("Contest: %d (%s)\n"), cnts->id, cnts->name);
    fprintf(msg_f, "Run Id: %d\n", run_id);
    if (cnts->team_url) {
      fprintf(msg_f, "URL: %s?contest_id=%d&login=%s\n", cnts->team_url,
              cnts->id, teamdb_get_login(cs->teamdb_state, re.user_id));
    }
    fprintf(msg_f, "%s\n", text3);
    fprintf(msg_f, "\n-\nRegards,\nthe ejudge contest management system (www.ejudge.ru)\n");
    close_memstream(msg_f); msg_f = 0;
    l10n_resetlocale();
    serve_send_email_to_user(ejudge_config, cnts, cs, re.user_id, nsubj, msg_t);
    xfree(msg_t); msg_t = 0; msg_z = 0;
  }

  if (cnts->enable_user_telegram > 0 && !re.is_hidden) {
    serve_telegram_user_run_reviewed(ejudge_config, cnts, cs, re.user_id, run_id, status);
  }

 cleanup:
  html_armor_free(&ab);
  return 0;

 invalid_param:
  fprintf(phr->log_f, "%s", errmsg);
  error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
  return -1;
}

static int
priv_clar_reply(
        FILE *fout,
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
  struct clar_entry_v2 clar;
  unsigned char *reply_txt_2;
  size_t reply_len;
  unsigned char *orig_txt = 0;
  size_t orig_len = 0;
  unsigned char *new_subj, *quoted, *msg;
  size_t new_subj_len, quoted_len, msg_len;
  struct timeval precise_time;

  // reply, in_reply_to
  if (hr_cgi_param(phr, "in_reply_to", &s) <= 0
      || sscanf(s, "%d%n", &in_reply_to, &n) != 1 || s[n]
      || in_reply_to < 0 || in_reply_to >= clar_get_total(cs->clarlog_state)) {
    errmsg = "in_reply_to parameter is invalid";
    goto invalid_param;
  }

  switch (phr->action) {
  case NEW_SRV_ACTION_CLAR_REPLY:
  case NEW_SRV_ACTION_CLAR_REPLY_ALL:
    if (hr_cgi_param(phr, "reply", &reply_txt) <= 0) {
      errmsg = "reply parameter is invalid";
      goto invalid_param;
    }
  }

  if (opcaps_check(phr->caps, OPCAP_REPLY_MESSAGE) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  if (clar_get_record(cs->clarlog_state, in_reply_to, &clar) < 0
      || clar.id < 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_CLAR_ID);
    goto cleanup;
  }

  if (!clar.from) {
    ns_error(log_f, NEW_SRV_ERR_CANNOT_REPLY_TO_JUDGE);
    goto cleanup;
  }

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, clar.id);

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
  l10n_resetlocale();

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

  if (clar_get_text(cs->clarlog_state, in_reply_to, &orig_txt, &orig_len) < 0) {
    ns_error(log_f, NEW_SRV_ERR_DISK_READ_ERROR);
    goto cleanup;
  }

  l10n_setlocale(clar.locale_id);
  new_subj = alloca(orig_len + 64);
  new_subj_len = message_reply_subj(orig_txt, new_subj);
  l10n_resetlocale();

  quoted_len = message_quoted_size(orig_txt);
  quoted = alloca(quoted_len + 16);
  message_quote(orig_txt, quoted);

  msg = alloca(reply_len + quoted_len + new_subj_len + 64);
  msg_len = sprintf(msg, "%s%s\n%s\n", new_subj, quoted, reply_txt_2);

  from_id = clar.from;
  if (phr->action == NEW_SRV_ACTION_CLAR_REPLY_ALL) from_id = 0;

  ej_uuid_t clar_uuid = {};
  gettimeofday(&precise_time, 0);
  clar_id = clar_add_record(cs->clarlog_state,
                            precise_time.tv_sec,
                            precise_time.tv_usec * 1000,
                            msg_len,
                            &phr->ip,
                            phr->ssl_flag,
                            0, from_id, 0, phr->user_id, 0,
                            clar.locale_id, in_reply_to + 1,
                            &clar.uuid,
                            0 /* run_id*/,
                            NULL /* run_uuid */,
                            0 /* appeal_flag */,
                            0 /* old_run_status */,
                            0 /* new_run_status */,
                            utf8_mode, NULL,
                            clar_get_subject(cs->clarlog_state, in_reply_to),
                            &clar_uuid);

  if (clar_id < 0) {
    ns_error(log_f, NEW_SRV_ERR_CLARLOG_UPDATE_FAILED);
    goto cleanup;
  }

  if (clar_add_text(cs->clarlog_state, clar_id, &clar_uuid, msg, msg_len) < 0) {
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto cleanup;
  }

  clar_update_flags(cs->clarlog_state, in_reply_to, 2);

  if (global->notify_clar_reply) {
    unsigned char nsubj[1024];
    FILE *msg_f = 0;
    char *msg_t = 0;
    size_t msg_z = 0;

    if (cnts->default_locale_num > 0)
      l10n_setlocale(cnts->default_locale_num);
    snprintf(nsubj, sizeof(nsubj),
             _("You have received a reply from judges in contest %d"),
             cnts->id);
    msg_f = open_memstream(&msg_t, &msg_z);
    fprintf(msg_f, _("You have received a reply from judges\n"));
    fprintf(msg_f, _("Contest: %d (%s)\n"), cnts->id, cnts->name);
    fprintf(msg_f, "Clar Id: %d\n", in_reply_to);
    if (cnts->team_url) {
      fprintf(msg_f, "URL: %s?contest_id=%d&login=%s\n", cnts->team_url,
              cnts->id, teamdb_get_login(cs->teamdb_state, from_id));
    }
    fprintf(msg_f, "%s\n", msg);
    fprintf(msg_f, "\n-\nRegards,\nthe ejudge contest management system (www.ejudge.ru)\n");
    close_memstream(msg_f); msg_f = 0;
    l10n_resetlocale();
    serve_send_email_to_user(ejudge_config, cnts, cs, from_id, nsubj, msg_t);
    xfree(msg_t); msg_t = 0; msg_z = 0;
  }

  if (cnts->enable_user_telegram > 0) {
    serve_telegram_user_clar_replied(ejudge_config, cnts, cs, clar.from, in_reply_to, msg);
  }

 cleanup:
  xfree(orig_txt);
  return 0;

 invalid_param:
  fprintf(phr->log_f, "%s", errmsg);
  error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
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

  if (!(n = hr_cgi_param(phr, "run_id", &s))) {
    errmsg = ns_strerror_r(msgbuf, sizeof(msgbuf),
                           NEW_SRV_ERR_RUN_ID_UNDEFINED);
    goto failure;
  }
  if (n < 0) {
    snprintf(msgbuf, sizeof(msgbuf), "`run_id' value is binary.\n");
    errmsg = msgbuf;
    goto failure;
  }
  if (n < 0 || sscanf(s, "%d%n", &run_id, &n) != 1 || s[n]) {
    //errmsg = ns_strerror_r(msgbuf, sizeof(msgbuf), NEW_SRV_ERR_INV_RUN_ID);
    snprintf(msgbuf, sizeof(msgbuf), "`run_id' value is invalid: |%s|.\n",
             s);
    errmsg = msgbuf;
    goto failure;
  }
  if (run_id < 0 || run_id >= run_get_total(cs->runlog_state)) {
          /*
    errmsg = ns_strerror_r(msgbuf, sizeof(msgbuf),
                           NEW_SRV_ERR_INV_RUN_ID, run_id);
                           */
    snprintf(msgbuf, sizeof(msgbuf), "`run_id' value %d is out of range.\n",
             run_id);
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
  phr->back_action = ns_priv_prev_state[phr->action];
  fprintf(phr->log_f, "%s", errmsg);
  error_page(fout, phr, 1, NEW_SRV_ERR_OPERATION_FAILED);
  return -1;
}

int
ns_parse_run_id(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int *p_run_id,
        struct run_entry *pe)
{
  return parse_run_id(fout, phr, cnts, extra, p_run_id, pe);
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

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, run_id);

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
  struct run_entry re;

  if (parse_run_id(fout, phr, cnts, extra, &run_id, 0) < 0) {
    retval = -1;
    goto cleanup;
  }
  if (opcaps_check(phr->caps, OPCAP_CONTROL_CONTEST) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (run_is_readonly(cs->runlog_state, run_id))
    FAIL(NEW_SRV_ERR_RUN_READ_ONLY);
  if (run_get_entry(cs->runlog_state, run_id, &re) < 0)
    FAIL(NEW_SRV_ERR_INV_RUN_ID);
  if (run_clear_entry(cs->runlog_state, run_id) < 0)
    FAIL(NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, run_id);

  if (re.store_flags == STORE_FLAGS_UUID) {
    uuid_archive_remove(cs, &re.run_uuid, 0);
  } else {
    archive_remove(cs, global->run_archive_dir, run_id, 0);
    archive_remove(cs, global->xml_report_archive_dir, run_id, 0);
    archive_remove(cs, global->report_archive_dir, run_id, 0);
    archive_remove(cs, global->team_report_archive_dir, run_id, 0);
    archive_remove(cs, global->full_archive_dir, run_id, 0);
    //archive_remove(cs, global->audit_log_dir, run_id, 0);
  }

  serve_audit_log(cs, run_id, &re, phr->user_id, &phr->ip, phr->ssl_flag,
                  "clear-run", "ok", -1, NULL);

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
 * NEW_SRV_ACTION_CHANGE_RUN_IS_MARKED
 * NEW_SRV_ACTION_CHANGE_RUN_IS_SAVED
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
  const unsigned char *audit_cmd = NULL;
  unsigned char old_buf[1024];
  unsigned char new_buf[1024];

  old_buf[0] = 0;
  new_buf[0] = 0;

  if (parse_run_id(fout, phr, cnts, extra, &run_id, &re) < 0) return -1;
  if (hr_cgi_param(phr, "param", &s) <= 0) {
    fprintf(phr->log_f, "param is not set");
    error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
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
      fprintf(phr->log_f, "invalid integer param");
      error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
      return -1;
    }
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_IS_IMPORTED:
  case NEW_SRV_ACTION_CHANGE_RUN_IS_HIDDEN:
  case NEW_SRV_ACTION_CHANGE_RUN_IS_EXAMINABLE:
  case NEW_SRV_ACTION_CHANGE_RUN_IS_READONLY:
  case NEW_SRV_ACTION_CHANGE_RUN_IS_MARKED:
  case NEW_SRV_ACTION_CHANGE_RUN_IS_SAVED:
    if (sscanf(s, "%d%n", &param_bool, &n) != 1 || s[n]
        || param_bool < 0 || param_bool > 1) {
      fprintf(phr->log_f, "invalid boolean param");
      error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
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
    ne_mask = RE_USER_ID;
    audit_cmd = "change-user-id";
    snprintf(old_buf, sizeof(old_buf), "%d", re.user_id);
    snprintf(new_buf, sizeof(new_buf), "%d", ne.user_id);
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_USER_ID:
    if (teamdb_lookup(cs->teamdb_state, param_int) <= 0)
      FAIL(NEW_SRV_ERR_INV_USER_ID);
    ne.user_id = param_int;
    ne_mask = RE_USER_ID;
    audit_cmd = "change-user-id";
    snprintf(old_buf, sizeof(old_buf), "%d", re.user_id);
    snprintf(new_buf, sizeof(new_buf), "%d", ne.user_id);
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_PROB_ID:
    if (param_int <= 0 || param_int > cs->max_prob || !cs->probs[param_int])
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
    ne.prob_id = param_int;
    ne_mask = RE_PROB_ID;
    audit_cmd = "change-prob-id";
    snprintf(old_buf, sizeof(old_buf), "%d", re.prob_id);
    snprintf(new_buf, sizeof(new_buf), "%d", ne.prob_id);
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
    ne_mask = RE_VARIANT;
    audit_cmd = "change-variant";
    snprintf(old_buf, sizeof(old_buf), "%d", re.variant);
    snprintf(new_buf, sizeof(new_buf), "%d", ne.variant);
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_LANG_ID:
    if (param_int <= 0 || param_int > cs->max_lang || !cs->langs[param_int])
      FAIL(NEW_SRV_ERR_INV_LANG_ID);
    ne.lang_id = param_int;
    ne_mask = RE_LANG_ID;
    audit_cmd = "change-lang-id";
    snprintf(old_buf, sizeof(old_buf), "%d", re.lang_id);
    snprintf(new_buf, sizeof(new_buf), "%d", ne.lang_id);
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_TEST:
    if (param_int < -1 || param_int >= 100000)
      FAIL(NEW_SRV_ERR_INV_TEST);
    if (global->score_system == SCORE_KIROV
        || global->score_system == SCORE_OLYMPIAD)
      param_int++;
    ne.test = param_int;
    ne.passed_mode = 1;
    ne_mask = RE_TEST | RE_PASSED_MODE;
    audit_cmd = "change-test";
    snprintf(old_buf, sizeof(old_buf), "%d", re.test);
    snprintf(new_buf, sizeof(new_buf), "%d", ne.test);
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_SCORE:
    /*
    if (global->score_system == SCORE_ACM
        || (global->score_system == SCORE_OLYMPIAD && cs->accepting_mode))
      FAIL(NEW_SRV_ERR_INV_PARAM);
    */
    if (re.prob_id <= 0 || re.prob_id > cs->max_prob
        || !(prob = cs->probs[re.prob_id]))
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
    if (param_int < 0 || param_int > prob->full_score)
      FAIL(NEW_SRV_ERR_INV_SCORE);
    ne.score = param_int;
    ne_mask = RE_SCORE;
    audit_cmd = "change-score";
    snprintf(old_buf, sizeof(old_buf), "%d", re.score);
    snprintf(new_buf, sizeof(new_buf), "%d", ne.score);
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_SCORE_ADJ:
    if (global->score_system != SCORE_KIROV
        && (global->score_system != SCORE_OLYMPIAD || cs->accepting_mode))
      FAIL(NEW_SRV_ERR_INV_PARAM);
    if (param_int <= -100000 || param_int >= 100000)
      FAIL(NEW_SRV_ERR_INV_SCORE_ADJ);
    ne.score_adj = param_int;
    ne_mask = RE_SCORE_ADJ;
    audit_cmd = "change-score-adj";
    snprintf(old_buf, sizeof(old_buf), "%d", re.score_adj);
    snprintf(new_buf, sizeof(new_buf), "%d", ne.score_adj);
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_PAGES:
    if (param_int < 0 || param_int >= 100000)
      FAIL(NEW_SRV_ERR_INV_PAGES);
    ne.pages = param_int;
    ne_mask = RE_PAGES;
    audit_cmd = "change-pages";
    snprintf(old_buf, sizeof(old_buf), "%d", re.pages);
    snprintf(new_buf, sizeof(new_buf), "%d", ne.pages);
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_IS_IMPORTED:
    ne.is_imported = param_bool;
    ne_mask = RE_IS_IMPORTED;
    audit_cmd = "change-is-imported";
    snprintf(old_buf, sizeof(old_buf), "%d", re.is_imported);
    snprintf(new_buf, sizeof(new_buf), "%d", ne.is_imported);
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_IS_HIDDEN:
    ne.is_hidden = param_bool;
    ne_mask = RE_IS_HIDDEN;
    audit_cmd = "change-is-hidden";
    snprintf(old_buf, sizeof(old_buf), "%d", re.is_hidden);
    snprintf(new_buf, sizeof(new_buf), "%d", ne.is_hidden);
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_IS_EXAMINABLE:
    /*
    ne.is_examinable = param_bool;
    ne_mask = RE_IS_EXAMINABLE;
    audit_cmd = "change-is-examinable";
    snprintf(old_buf, sizeof(old_buf), "%d", re.is_examinable);
    snprintf(new_buf, sizeof(new_buf), "%d", ne.is_examinable);
    */
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_IS_READONLY:
    ne.is_readonly = param_bool;
    ne_mask = RE_IS_READONLY;
    audit_cmd = "change-is-readonly";
    snprintf(old_buf, sizeof(old_buf), "%d", re.is_readonly);
    snprintf(new_buf, sizeof(new_buf), "%d", ne.is_readonly);
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_IS_MARKED:
    ne.is_marked = param_bool;
    ne_mask = RE_IS_MARKED;
    audit_cmd = "change-is-marked";
    snprintf(old_buf, sizeof(old_buf), "%d", re.is_marked);
    snprintf(new_buf, sizeof(new_buf), "%d", ne.is_marked);
    break;
  case NEW_SRV_ACTION_CHANGE_RUN_IS_SAVED:
    ne.is_saved = param_bool;
    ne_mask = RE_IS_SAVED;
    audit_cmd = "change-is-saved";
    snprintf(old_buf, sizeof(old_buf), "%d", re.is_saved);
    snprintf(new_buf, sizeof(new_buf), "%d", ne.is_saved);
    break;
  }

  if (!ne_mask) goto cleanup;

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, run_id);

  if (run_set_entry(cs->runlog_state, run_id, ne_mask, &ne, &ne) < 0)
    FAIL(NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
  serve_notify_run_update(phr->config, cs, &ne);

  serve_audit_log(cs, run_id, &re, phr->user_id, &phr->ip, phr->ssl_flag,
                  audit_cmd, "ok", -1,
                  "  Old value: %s\n"
                  "  New value: %s\n",
                  old_buf, new_buf);

 cleanup:
  return retval;
}

/*
 * NEW_SRV_ACTION_CHANGE_RUN_STATUS:
 */
static int
priv_change_status(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const unsigned char *errmsg = 0, *s;
  int run_id, n, status, flags;
  struct run_entry new_run, re;
  const struct section_problem_data *prob = 0;

  // run_id, status
  if (parse_run_id(fout, phr, cnts, extra, &run_id, 0) < 0) goto failure;
  snprintf(phr->next_extra, sizeof(phr->next_extra), "run_id=%d", run_id);
  if (hr_cgi_param(phr, "status", &s) <= 0
      || sscanf(s, "%d%n", &status, &n) != 1 || s[n]
      || (!run_is_normal_status(status) && status != RUN_REJUDGE && status != RUN_FULL_REJUDGE)) {
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
    serve_rejudge_run(extra, ejudge_config, cnts, cs, run_id, phr->user_id, &phr->ip, phr->ssl_flag,
                      (status == RUN_FULL_REJUDGE),
                      DFLT_G_REJUDGE_PRIORITY_ADJUSTMENT);
    goto cleanup;
  }
  if (!serve_is_valid_status(cs, status, 1)) {
    ns_error(log_f, NEW_SRV_ERR_INV_STATUS);
    goto cleanup;
  }

  if (run_get_entry(cs->runlog_state, run_id, &re) < 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  if (re.prob_id <= 0 || re.prob_id > cs->max_prob
      || !(prob = cs->probs[re.prob_id])) {
    ns_error(log_f, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }

  info("audit:%s:%d:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, run_id, status);

  memset(&new_run, 0, sizeof(new_run));
  new_run.status = status;
  flags = RE_STATUS;
  if (status == RUN_OK && prob->variable_full_score <= 0) {
    new_run.score = prob->full_score;
    flags |= RE_SCORE;
  }

  if (prob->type >= PROB_TYPE_OUTPUT_ONLY
      && prob->type <= PROB_TYPE_SELECT_MANY) {
    if (status == RUN_OK) {
      new_run.test = 1;
      new_run.passed_mode = 1;
      flags |= RE_TEST | RE_PASSED_MODE;
    } else if (status == RUN_WRONG_ANSWER_ERR
               || status == RUN_PRESENTATION_ERR
               || status == RUN_PARTIAL) {
      new_run.test = 0;
      new_run.passed_mode = 1;
      new_run.score = 0;
      flags |= RE_TEST | RE_PASSED_MODE | RE_SCORE;
    }
  }

  if (run_set_entry(cs->runlog_state, run_id, flags, &new_run, &new_run) < 0) {
    ns_error(log_f, NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
    goto cleanup;
  }
  serve_notify_run_update(phr->config, cs, &new_run);

  serve_audit_log(cs, run_id, &re, phr->user_id, &phr->ip, phr->ssl_flag,
                  "change-status", "ok", status, NULL);

  if (cs->global->notify_status_change > 0) {
    if (!re.is_hidden)
      serve_notify_user_run_status_change(ejudge_config, cnts, cs, re.user_id, run_id,
                                          status);
  }
  if (cnts->enable_user_telegram > 0 && !re.is_hidden) {
    serve_telegram_user_run_reviewed(ejudge_config, cnts, cs, re.user_id, run_id, status);
  }

 cleanup:
  return 0;

 invalid_param:
  fprintf(phr->log_f, "%s", errmsg);
  error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
 failure:
  return -1;
}

static int
priv_simple_change_status(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const unsigned char *errmsg = 0;
  int run_id, status, flags;
  struct run_entry new_run, re;
  const struct section_problem_data *prob = 0;
  const unsigned char *audit_cmd = NULL;

  if (parse_run_id(fout, phr, cnts, extra, &run_id, 0) < 0) goto failure;

  if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_JUST_IGNORE) {
    status = RUN_IGNORED;
    audit_cmd = "set-ignored";
  } else if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_JUST_OK) {
    status = RUN_OK;
    audit_cmd = "set-ok";
  } else if (phr->action == NEW_SRV_ACTION_PRIV_SUBMIT_RUN_JUST_SUMMON) {
    status = RUN_SUMMONED;
    audit_cmd = "set-summoned";
  } else {
    errmsg = "invalid status";
    goto invalid_param;
  }

  if (opcaps_check(phr->caps, OPCAP_COMMENT_RUN) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  if (run_get_entry(cs->runlog_state, run_id, &re) < 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  if (re.prob_id <= 0 || re.prob_id > cs->max_prob
      || !(prob = cs->probs[re.prob_id])) {
    ns_error(log_f, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  if ((re.status != RUN_ACCEPTED && re.status != RUN_PENDING_REVIEW && re.status != RUN_SUMMONED) && opcaps_check(phr->caps, OPCAP_EDIT_RUN)<0){
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, run_id);

  memset(&new_run, 0, sizeof(new_run));
  new_run.status = status;
  flags = RE_STATUS;
  if (status == RUN_OK && prob->variable_full_score <= 0) {
    new_run.score = prob->full_score;
    flags |= RE_SCORE;
  }
  if (run_set_entry(cs->runlog_state, run_id, flags, &new_run, &new_run) < 0) {
    ns_error(log_f, NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
    goto cleanup;
  }
  serve_notify_run_update(phr->config, cs, &new_run);

  serve_audit_log(cs, run_id, &re, phr->user_id, &phr->ip, phr->ssl_flag,
                  audit_cmd, "ok", status, NULL);

  if (cs->global->notify_status_change > 0) {
    if (!re.is_hidden)
      serve_notify_user_run_status_change(ejudge_config, cnts, cs, re.user_id, run_id,
                                          status);
  }
  if (cnts->enable_user_telegram > 0 && !re.is_hidden) {
    serve_telegram_user_run_reviewed(ejudge_config, cnts, cs, re.user_id, run_id, status);
  }

 cleanup:
  return 0;

 invalid_param:
  fprintf(phr->log_f, "%s", errmsg);
  error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
 failure:
  return -1;
}

int
ns_parse_run_mask(
        struct http_request_info *phr,
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

  if (hr_cgi_param(phr, "run_mask_size", &size_str) <= 0) {
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

  if (hr_cgi_param(phr, "run_mask", &mask_str) <= 0) {
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

  if (ns_parse_run_mask(phr, 0, 0, &mask_size, &mask) < 0) goto invalid_param;
  if (!mask_size) FAIL(NEW_SRV_ERR_NO_RUNS_TO_REJUDGE);
  if (opcaps_check(phr->caps, OPCAP_EDIT_RUN) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  switch (phr->action) {
  case NEW_SRV_ACTION_CLEAR_DISPLAYED_2:
    serve_clear_by_mask(cs, phr->user_id, &phr->ip, phr->ssl_flag,
                        mask_size, mask);
    break;
  case NEW_SRV_ACTION_IGNORE_DISPLAYED_2:
    serve_ignore_by_mask(phr->config, cs, phr->user_id, &phr->ip, phr->ssl_flag,
                         mask_size, mask, RUN_IGNORED);
    break;
  case NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_2:
    serve_ignore_by_mask(phr->config, cs, phr->user_id, &phr->ip, phr->ssl_flag,
                         mask_size, mask, RUN_DISQUALIFIED);
    break;
  case NEW_SRV_ACTION_MARK_DISPLAYED_2:
    serve_mark_by_mask(phr->config, cs, phr->user_id, &phr->ip, phr->ssl_flag,
                       mask_size, mask, 1);
    break;
  case NEW_SRV_ACTION_UNMARK_DISPLAYED_2:
    serve_mark_by_mask(phr->config, cs, phr->user_id, &phr->ip, phr->ssl_flag,
                       mask_size, mask, 0);
    break;
  default:
    abort();
  }

 cleanup:
  xfree(mask);
  return retval;

 invalid_param:
  error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
  xfree(mask);
  return -1;
}

static int
priv_tokenize_displayed(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  unsigned long *mask = 0;
  size_t mask_size = 0;
  int retval = 0;
  int token_count = 0;
  int token_flags = 0;
  const unsigned char *s = 0;

  if (ns_parse_run_mask(phr, 0, 0, &mask_size, &mask) < 0) goto invalid_param;
  if (!mask_size) FAIL(NEW_SRV_ERR_NO_RUNS_TO_REJUDGE);
  if (opcaps_check(phr->caps, OPCAP_EDIT_RUN) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (hr_cgi_param_int(phr, "token_count", &token_count) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  if (token_count < 0 || token_count > 1000000)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  s = NULL;
  if (hr_cgi_param(phr, "finalscore_bit", &s) > 0 && s != NULL)
    token_flags |= TOKEN_FINALSCORE_BIT;
  s = NULL;
  if (hr_cgi_param(phr, "valuer_judge_comment_bit", &s) > 0 && s != NULL)
    token_flags |= TOKEN_VALUER_JUDGE_COMMENT_BIT;
  s = NULL;
  if (hr_cgi_param(phr, "tests_bits", &s) > 0 && s != NULL) {
    if (!strcmp(s, "2")) {
      token_flags |= TOKEN_BASICTESTS_BIT;
    } else if (!strcmp(s, "4")) {
      token_flags |= TOKEN_TOKENTESTS_BIT;
    } else if (!strcmp(s, "6")) {
      token_flags |= TOKEN_FINALTESTS_BIT;
    }
  }

  info("audit:%s:%d:%d:%lld:%d:%d", phr->action_str, phr->user_id, phr->contest_id, (long long) mask_size, token_count, token_flags);

  serve_tokenize_by_mask(cs, phr->user_id, &phr->ip, phr->ssl_flag, mask_size, mask, token_count, token_flags);

 cleanup:
  xfree(mask);
  return retval;

 invalid_param:
  error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
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
  int prio_adj = DFLT_G_REJUDGE_PRIORITY_ADJUSTMENT;
  int retval = 0;
  int background_mode = 0;

  if (ns_parse_run_mask(phr, 0, 0, &mask_size, &mask) < 0) goto invalid_param;
  if (!mask_size) FAIL(NEW_SRV_ERR_NO_RUNS_TO_REJUDGE);
  hr_cgi_param_int_opt(phr, "background_mode", &background_mode, 0);
  if (background_mode != 1) background_mode = 0;

  if (opcaps_check(phr->caps, OPCAP_REJUDGE_RUN) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  info("audit:%s:%d:%d:%lld", phr->action_str, phr->user_id, phr->contest_id, (long long) mask_size);

  if (global->score_system == SCORE_OLYMPIAD
      && cs->accepting_mode
      && phr->action == NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_2) {
    force_full = 1;
    prio_adj = 10;
  }

  nsf_add_job(phr->fw_state, serve_rejudge_by_mask(extra, ejudge_config, cnts, cs, phr->user_id,
                                                   &phr->ip, phr->ssl_flag,
                                                   mask_size, mask, force_full, prio_adj,
                                                   background_mode));

 cleanup:
  xfree(mask);
  return retval;

 invalid_param:
  error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
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
  int background_mode = 0;

  if (hr_cgi_param(phr, "prob_id", &s) <= 0
      || sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n]
      || prob_id <= 0 || prob_id > cs->max_prob
      || !(prob = cs->probs[prob_id])
      || prob->disable_testing)
    goto invalid_param;
  hr_cgi_param_int_opt(phr, "background_mode", &background_mode, 0);
  if (background_mode != 1) background_mode = 0;

  if (opcaps_check(phr->caps, OPCAP_REJUDGE_RUN) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, prob_id);

  nsf_add_job(phr->fw_state, serve_rejudge_problem(extra, ejudge_config, cnts, cs, phr->user_id,
                                                   &phr->ip, phr->ssl_flag, prob_id,
                                                   DFLT_G_REJUDGE_PRIORITY_ADJUSTMENT,
                                                   background_mode));

 cleanup:
  return 0;

 invalid_param:
  error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
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
  int background_mode = 0;

  hr_cgi_param_int_opt(phr, "background_mode", &background_mode, 0);
  if (background_mode != 1) background_mode = 0;

  if (opcaps_check(phr->caps, OPCAP_REJUDGE_RUN) < 0) {
    ns_error(log_f, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  switch (phr->action) {
  case NEW_SRV_ACTION_REJUDGE_SUSPENDED_2:
    nsf_add_job(phr->fw_state, serve_judge_suspended(extra, ejudge_config, cnts, cs, phr->user_id, &phr->ip, phr->ssl_flag, DFLT_G_REJUDGE_PRIORITY_ADJUSTMENT, background_mode));
    break;
  case NEW_SRV_ACTION_REJUDGE_ALL_2:
    nsf_add_job(phr->fw_state, serve_rejudge_all(extra, ejudge_config, cnts, cs, phr->user_id, &phr->ip, phr->ssl_flag, DFLT_G_REJUDGE_PRIORITY_ADJUSTMENT, background_mode));

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
  if (hr_cgi_param(phr, "run_user_id", &s) > 0
      && sscanf(s, "%d%n", &x, &n) == 1 && !s[n]
      && teamdb_lookup(cs->teamdb_state, x))
    user_id = x;
  x = 0;
  if (hr_cgi_param(phr, "run_user_login", &s) > 0 && *s)
    x = teamdb_lookup_login(cs->teamdb_state, s);
  if (user_id <= 0 && x <= 0)
    FAIL(NEW_SRV_ERR_UNDEFINED_USER_ID_LOGIN);
  if (user_id > 0 && x > 0 && user_id != x)
    FAIL(NEW_SRV_ERR_CONFLICTING_USER_ID_LOGIN);
  if (user_id <= 0) user_id = x;

  if (hr_cgi_param(phr, "prob_id", &s) <= 0
      || sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n]
      || prob_id <= 0 || prob_id > cs->max_prob
      || !(prob = cs->probs[prob_id]))
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  if (hr_cgi_param(phr, "variant", &s) > 0 && *s) {
    if (sscanf(s, "%d%n", &variant, &n) != 1 || s[n]
        || prob->variant_num <= 0 || variant < 0
        || variant > prob->variant_num)
      FAIL(NEW_SRV_ERR_INV_VARIANT);
  }

  // check language, content-type, binariness and other stuff
  if (prob->type == PROB_TYPE_STANDARD) {
    if (hr_cgi_param(phr, "language", &s) <= 0
        || sscanf(s, "%d%n", &lang_id, &n) != 1 || s[n]
        || lang_id <= 0 || lang_id > cs->max_lang
        || !(lang = cs->langs[lang_id]))
      FAIL(NEW_SRV_ERR_INV_LANG_ID);
  }
  switch (prob->type) {
  case PROB_TYPE_STANDARD:      // "file"
  case PROB_TYPE_TESTS:
  case PROB_TYPE_OUTPUT_ONLY:
  case PROB_TYPE_TEXT_ANSWER:
  case PROB_TYPE_SHORT_ANSWER:
    if (!hr_cgi_param_bin(phr, "file", &run_text, &run_size)) {
      run_text = "";
      run_size = 0;
    }
    break;
  default:
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  }

  switch (prob->type) {
  case PROB_TYPE_STANDARD:
    if (!lang->binary && strlen(run_text) != run_size)
      FAIL(NEW_SRV_ERR_BINARY_FILE);
    if (prob->disable_ctrl_chars > 0 && has_control_characters(run_text))
      FAIL(NEW_SRV_ERR_INV_CHAR);
    break;

  case PROB_TYPE_OUTPUT_ONLY:
  case PROB_TYPE_TESTS:
    if (!prob->binary_input && !prob->binary && strlen(run_text) != run_size)
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

  if (hr_cgi_param(phr, "is_imported", &s) > 0 && *s) {
    if (sscanf(s, "%d%n", &is_imported, &n) != 1 || s[n]
        || is_imported < 0 || is_imported > 1)
      FAIL(NEW_SRV_ERR_INV_PARAM);
    re.is_imported = is_imported;
    re_flags |= RE_IS_IMPORTED;
  }
  if (hr_cgi_param(phr, "is_hidden", &s) > 0 && *s) {
    if (sscanf(s, "%d%n", &is_hidden, &n) != 1 || s[n]
        || is_hidden < 0 || is_hidden > 1)
      FAIL(NEW_SRV_ERR_INV_PARAM);
  }
  if (hr_cgi_param(phr, "is_readonly", &s) > 0 && *s) {
    if (sscanf(s, "%d%n", &is_readonly, &n) != 1 || s[n]
        || is_readonly < 0 || is_readonly > 1)
      FAIL(NEW_SRV_ERR_INV_PARAM);
    re.is_readonly = is_readonly;
    re_flags |= RE_IS_READONLY;
  }
  if (hr_cgi_param(phr, "status", &s) > 0 && *s) {
    if (sscanf(s, "%d%n", &status, &n) != 1 || s[n]
        || !run_is_normal_status(status)
        || !serve_is_valid_status(cs, status, 1))
      FAIL(NEW_SRV_ERR_INV_STATUS);
    re.status = status;
    re_flags |= RE_STATUS;
  }
  if (hr_cgi_param(phr, "tests", &s) > 0 && *s) {
    if (sscanf(s, "%d%n", &tests, &n) != 1 || s[n]
        || tests < -1 || tests > 100000)
      FAIL(NEW_SRV_ERR_INV_TEST);
    re.test = tests;
    re.passed_mode = 1;
    re_flags |= RE_TEST | RE_PASSED_MODE;
  }
  if (hr_cgi_param(phr, "score", &s) > 0 && *s) {
    if (sscanf(s, "%d%n", &score, &n) != 1 || s[n]
        || score < 0 || score > 100000)
      FAIL(NEW_SRV_ERR_INV_PARAM);
    re.score = score;
    re_flags |= RE_SCORE;
  }
  if (ns_load_problem_uuid(phr->log_f, global, prob, variant) < 0) {
    fprintf(log_f, "UUID for this problem is undefined\n");
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
    goto cleanup;
  }

  if (!lang) lang_id = 0;

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  ej_uuid_t run_uuid = {};
  int store_flags = 0;
  if (global->uuid_run_store > 0 && run_get_uuid_hash_state(cs->runlog_state) >= 0) {
    store_flags = STORE_FLAGS_UUID;
    if (testing_report_bson_available()) store_flags = STORE_FLAGS_UUID_BSON;
  }
  run_id = run_add_record(cs->runlog_state,
                          &precise_time,
                          run_size, shaval, &run_uuid,
                          &phr->ip, phr->ssl_flag, phr->locale_id,
                          user_id, prob_id, lang_id, 0, variant,
                          is_hidden, mime_type,
                          prob->uuid,
                          store_flags,
                          0 /* is_vcs */,
                          0 /* ext_user_kind */,
                          NULL /* ext_user */,
                          0 /* notify_driver */,
                          0 /* notify_kind */,
                          NULL /* notify_queue */,
                          NULL /* ure */);
  if (run_id < 0) FAIL(NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
  serve_move_files_to_insert_run(cs, run_id);
  if (metrics.data) {
    ++metrics.data->runs_submitted;
  }

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
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto cleanup;
  }

  if (generic_write_file(run_text, run_size, arch_flags, 0, run_path, "") < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
    goto cleanup;
  }
  run_set_entry(cs->runlog_state, run_id, re_flags, &re, &re);
  serve_notify_run_update(phr->config, cs, &re);

  serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                  "priv-new-run", "ok", RUN_PENDING, NULL);

 cleanup:
  return retval;
}

/*
static const unsigned char * const form_row_attrs[]=
{
  " bgcolor=\"#d0d0d0\"",
  " bgcolor=\"#e0e0e0\"",
};
*/

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
  int total_runs = run_get_total(cs->runlog_state);

  switch (phr->action) {
  case NEW_SRV_ACTION_REJUDGE_DISPLAYED_1:
  case NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_1:
  case NEW_SRV_ACTION_CLEAR_DISPLAYED_1:
  case NEW_SRV_ACTION_IGNORE_DISPLAYED_1:
  case NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_1:
    // run_mask_size, run_mask
    errmsg = "cannot parse run mask";
    if (ns_parse_run_mask(phr, &run_mask_size_str, &run_mask_str,
                       &run_mask_size, &run_mask) < 0)
      goto invalid_param;
    break;
  case NEW_SRV_ACTION_REJUDGE_PROBLEM_1:
    errmsg = "invalid problem";
    if (hr_cgi_param(phr, "prob_id", &s) <= 0
        || sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n]
        || prob_id <= 0 || prob_id > cs->max_prob
        || !(prob = cs->probs[prob_id])
        || prob->disable_testing)
      goto invalid_param;
    break;
  }

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->priv_header_txt, 0, 0, 0, 0, phr->locale_id, cnts,
            phr->client_key,
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
  case NEW_SRV_ACTION_REJUDGE_ALL_1:
    fprintf(fout, "<p><b>Attention! %d runs will be rejudged.</b></p>\n",
            total_runs);
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
  case NEW_SRV_ACTION_REJUDGE_ALL_1:
    fprintf(fout, "<select name=\"background_mode\">");
    s = "";
    if (total_runs < 5000) s = " selected=\"selected\"";
    fprintf(fout, "<option value=\"0\"%s>Foreground Mode</option>", s);
    s = "";
    if (total_runs >= 5000) s = " selected=\"selected\"";
    fprintf(fout, "<option value=\"1\"%s>Background Mode</option>", s);
    fprintf(fout, "</select>\n");
    break;
  }

  if (!disable_ok) {
    fprintf(fout, "%s", BUTTON(confirm_next_action[phr->action]));
  }
  fprintf(fout, "</form></td></tr></table>\n");

  ns_footer(fout, extra->priv_footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_resetlocale();
  html_armor_free(&ab);
  xfree(run_mask);
  return 0;

 invalid_param:
  if (errmsg) {
    fprintf(phr->log_f, "%s", errmsg);
  }
  error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
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
    error_page(fout, phr, 1, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
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
      fprintf(phr->log_f, "operation failed: %s", userlist_strerror(-r));
      error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
      return -1;
    case ULS_ERR_DISCONNECT:
      error_page(fout, phr, 1, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
      return -1;
    default:
      fprintf(phr->log_f, "operation failed: %s", userlist_strerror(-r));
      error_page(fout, phr, 1, NEW_SRV_ERR_INTERNAL);
      return -1;
    }
  }

  fprintf(fout, "Content-type: text/plain; charset=%s\n\n%s\n",
          EJUDGE_CHARSET, db_text);
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

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

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
  if (!(n = hr_cgi_param(phr, "run_id2", &s)) || (n > 0 && !*s))
    FAIL(NEW_SRV_ERR_RUN_TO_COMPARE_UNSPECIFIED);
  if (n < 0 || sscanf(s, "%d%n", &run_id2, &n) != 1 || s[n]
      || run_id2 < 0 || run_id2 >= total_runs)
    FAIL(NEW_SRV_ERR_INV_RUN_TO_COMPARE);
  if (opcaps_check(phr->caps, OPCAP_VIEW_SOURCE) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  info("audit:%s:%d:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, run_id1, run_id2);

  if (compare_runs(cs, fout, run_id1, run_id2) < 0)
    FAIL(NEW_SRV_ERR_RUN_COMPARE_FAILED);

 cleanup:
  return retval;

 failure:
  return -1;
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

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->priv_header_txt, 0, 0, 0, 0, phr->locale_id, cnts,
            phr->client_key,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm, _("Add new run"));
  ns_examiners_page(fout, log_f, phr, cnts, extra);
  ns_footer(fout, extra->priv_footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_resetlocale();

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

  if (hr_cgi_param_int(phr, "prob_id", &prob_id) < 0
      || prob_id <= 0 || prob_id > cs->max_prob || !cs->probs[prob_id]
      || cs->probs[prob_id]->manual_checking <= 0)
    FAIL(NEW_SRV_ERR_INV_PROB_ID);

  if (hr_cgi_param_int(phr, "chief_user_id", &user_id) < 0 || user_id < 0)
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

  info("audit:%s:%d:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, user_id, prob_id);

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

  if (hr_cgi_param_int(phr, "prob_id", &prob_id) < 0
      || prob_id <= 0 || prob_id > cs->max_prob || !cs->probs[prob_id]
      || cs->probs[prob_id]->manual_checking <= 0)
    FAIL(NEW_SRV_ERR_INV_PROB_ID);

  if (hr_cgi_param_int(phr, "exam_add_user_id", &user_id) < 0 || user_id < 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);
  if (!user_id) {
    retval = NEW_SRV_ACTION_EXAMINERS_PAGE;
    goto cleanup;
  }
  if (nsdb_check_role(user_id, phr->contest_id, USER_ROLE_EXAMINER) < 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);

  info("audit:%s:%d:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, user_id, prob_id);

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

  if (hr_cgi_param_int(phr, "prob_id", &prob_id) < 0
      || prob_id <= 0 || prob_id > cs->max_prob || !cs->probs[prob_id]
      || cs->probs[prob_id]->manual_checking <= 0)
    FAIL(NEW_SRV_ERR_INV_PROB_ID);

  if (hr_cgi_param_int(phr, "exam_del_user_id", &user_id) < 0 || user_id < 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);
  if (!user_id) {
    retval = NEW_SRV_ACTION_EXAMINERS_PAGE;
    goto cleanup;
  }
  /*
  if (nsdb_check_role(user_id, phr->contest_id, USER_ROLE_EXAMINER) < 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);
  */

  info("audit:%s:%d:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, user_id, prob_id);

  nsdb_remove_examiner(user_id, phr->contest_id, prob_id);
  retval = NEW_SRV_ACTION_EXAMINERS_PAGE;

 cleanup:
  return retval;
}

static int
priv_download_source(
        FILE *fout,
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
  const unsigned char *src_sfx = "";
  const unsigned char *content_type = "text/plain";

  if (parse_run_id(fout, phr, cnts, extra, &run_id, &re) < 0) goto failure;
  if (hr_cgi_param(phr, "no_disp", &s) > 0
      && sscanf(s, "%d%n", &x, &n) == 1 && !s[n]
      && x >= 0 && x <= 1)
    no_disp = x;

  if (opcaps_check(phr->caps, OPCAP_VIEW_SOURCE) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (re.prob_id <= 0 || re.prob_id > cs->max_prob ||
      !(prob = cs->probs[re.prob_id]))
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  if (!run_is_normal_or_transient_status(re.status))
    FAIL(NEW_SRV_ERR_SOURCE_UNAVAILABLE);

  if ((src_flags = serve_make_source_read_path(cs, src_path, sizeof(src_path), &re)) < 0) {
    FAIL(NEW_SRV_ERR_SOURCE_NONEXISTANT);
  }
  if (generic_read_file(&run_text, 0, &run_size, src_flags, 0, src_path, 0)<0)
    FAIL(NEW_SRV_ERR_DISK_READ_ERROR);

  if (prob->type > 0) {
    content_type = mime_type_get_type(re.mime_type);
    src_sfx = mime_type_get_suffix(re.mime_type);
  } else {
    if(re.lang_id <= 0 || re.lang_id > cs->max_lang ||
       !(lang = cs->langs[re.lang_id]))
      FAIL(NEW_SRV_ERR_INV_LANG_ID);
    src_sfx = lang->src_sfx;
    if (!src_sfx) src_sfx = "";

    if (lang->content_type && lang->content_type[0]) {
      content_type = lang->content_type;
    } else if (lang->binary) {
      if (re.mime_type <= 0 && !strcmp(src_sfx, ".tar")) {
        int mime_type = mime_type_guess(global->diff_work_dir,
                                        run_text, run_size);
        switch (mime_type) {
        case MIME_TYPE_APPL_GZIP: // application/x-gzip
          src_sfx = ".tar.gz";
          break;
        case MIME_TYPE_APPL_TAR:  // application/x-tar
          src_sfx = ".tar";
          break;
        case MIME_TYPE_APPL_ZIP:  // application/zip
          src_sfx = ".zip";
          break;
        case MIME_TYPE_APPL_BZIP2: // application/x-bzip2
          src_sfx = ".tar.bz2";
          break;
        case MIME_TYPE_APPL_7ZIP:  // application/x-7zip
          src_sfx = ".tar.7z";
          break;
        default:
          mime_type = MIME_TYPE_BINARY;
          break;
        }
        content_type = mime_type_get_type(mime_type);
      } else {
        content_type = "application/octet-stream";
      }
    } else {
      content_type = "text/plain";
    }
  }

  phr->json_reply = 0;

  fprintf(fout, "Content-type: %s\n", content_type);
  if (!no_disp) {
    fprintf(fout, "Content-Disposition: attachment; filename=\"%06d%s\"\n",
            run_id, src_sfx);
  }
  putc_unlocked('\n', fout);

  fwrite(run_text, 1, run_size, fout);

 cleanup:
  xfree(run_text);
  return retval;

 failure:
  xfree(run_text);
  return -1;
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
  if (hr_cgi_param(phr, "test_num", &s) <= 0
      || sscanf(s, "%d%n", &test_num, &n) != 1 || s[n]) {
    fprintf(phr->log_f, "cannot parse test_num");
    error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
    return -1;
  }

  if (opcaps_check(phr->caps, OPCAP_VIEW_REPORT) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (test_num <= 0) FAIL(NEW_SRV_ERR_INV_TEST);

  retval = ns_write_tests(cs, fout, log_f, phr->action, run_id, test_num);

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
  ns_header(fout, extra->priv_header_txt, 0, 0, 0, 0, phr->locale_id, cnts,
            phr->client_key,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm, "Add new runs in CSV format");
  html_start_form(fout, 2, phr->self_url, phr->hidden_vars);

  fprintf(fout, "<table>");
  /*
  fprintf(fout, "<tr><td>%s</td><td><input type=\"checkbox\" name=\"results_only\"/></td></tr>\n", _("Import results for existing runs"));
  */
  fprintf(fout, "<tr><td><input type=\"radio\" name=\"import_mode\" value=\"0\" checked=\"yes\" /></td><td>%s</td></tr>\n",
          "Create new submits, fail if a submit already exists");
  fprintf(fout, "<tr><td><input type=\"radio\" name=\"import_mode\" value=\"1\"  /></td><td>%s</td></tr>\n",
          "Modify existing submits, fail if a submit does not exist");
  fprintf(fout, "<tr><td><input type=\"radio\" name=\"import_mode\" value=\"2\"  /></td><td>%s</td></tr>\n",
          "Create non-existent submits and modify existent submits");
  fprintf(fout, "<tr><td>%s</td><td><input type=\"file\" name=\"file\"/></td></tr>\n",
          _("File"));
  fprintf(fout, "<tr><td>&nbsp;</td><td>%s</td></tr></table>\n",
          BUTTON(NEW_SRV_ACTION_UPLOAD_RUNLOG_CSV_2));

  fprintf(fout, "</form>\n");
  ns_footer(fout, extra->priv_footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_resetlocale();

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
  const unsigned char *s = 0, *p;
  char *log_text = 0;
  size_t log_size = 0;
  FILE *ff = 0;
  unsigned char *ss = 0;
  int import_mode = -1;

  if (opcaps_check(phr->caps, OPCAP_IMPORT_XML_RUNS) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (!(r = hr_cgi_param(phr, "file", &s)))
    FAIL(NEW_SRV_ERR_FILE_UNSPECIFIED);
  else if (r < 0)
    FAIL(NEW_SRV_ERR_BINARY_FILE);

  for (p = s; *p && isspace(*p); p++);
  if (!*p) FAIL(NEW_SRV_ERR_FILE_EMPTY);

  // import_mode:
  //  0 - new submits
  //  1 - existing submits
  //  2 - both
  if (hr_cgi_param_int(phr, "import_mode", &import_mode) < 0
      || import_mode < 0 || import_mode > 2)
    FAIL(NEW_SRV_ERR_INV_PARAM);

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  ff = open_memstream(&log_text, &log_size);
  switch (import_mode) {
  case 0:
    r = ns_upload_csv_runs(phr, cs, ff, s);
    break;
  case 1:
    r = ns_upload_csv_results(phr, cs, ff, s, 0);
    break;
  case 2:
    r = ns_upload_csv_results(phr, cs, ff, s, 1);
    break;
  default:
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }
  close_memstream(ff); ff = 0;

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->priv_header_txt, 0, 0, 0, 0, phr->locale_id, cnts,
            phr->client_key,
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

  ns_footer(fout, extra->priv_footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_resetlocale();

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
  ns_header(fout, extra->priv_header_txt, 0, 0, 0, 0, phr->locale_id, cnts,
            phr->client_key,
            "%s [%s, %d, %s]: %s", ns_unparse_role(phr->role), phr->name_arm,
            phr->contest_id, extra->contest_arm, "Merge XML runlog");
  html_start_form(fout, 2, phr->self_url, phr->hidden_vars);

  fprintf(fout, "<table><tr><td>%s</td><td><input type=\"file\" name=\"file\"/></td></tr>\n", _("File"));
  fprintf(fout, "<tr><td>&nbsp;</td><td>%s</td></tr></table>\n",
          BUTTON(NEW_SRV_ACTION_UPLOAD_RUNLOG_XML_2));

  fprintf(fout, "</form>\n");
  ns_footer(fout, extra->priv_footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_resetlocale();

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

  if (!(r = hr_cgi_param(phr, "file", &s)))
    FAIL(NEW_SRV_ERR_FILE_UNSPECIFIED);
  else if (r < 0)
    FAIL(NEW_SRV_ERR_BINARY_FILE);

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  for (p = s; *p && isspace(*p); p++);
  if (!*p) FAIL(NEW_SRV_ERR_FILE_EMPTY);

  ff = open_memstream(&log_text, &log_size);
  runlog_import_xml(cs, cs->runlog_state, ff, 1, s);
  close_memstream(ff); ff = 0;

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->priv_header_txt, 0, 0, 0, 0, phr->locale_id, cnts,
            phr->client_key,
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

  ns_footer(fout, extra->priv_footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_resetlocale();

 cleanup:
  if (ff) fclose(ff);
  xfree(log_text);
  xfree(ss);
  return retval;
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
  int use_problem_extid = 0;
  int use_problem_dir = 0;
  const unsigned char *s;
  char *ss = 0;
  const unsigned char *problem_dir_prefix = NULL;

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
  // file_pattern_contest
  if (hr_cgi_param(phr, "run_selection", &s) <= 0)
    FAIL(NEW_SRV_ERR_INV_RUN_SELECTION);
  errno = 0;
  x = strtol(s, &ss, 10);
  if (errno || *ss || x < 0 || x > 4) FAIL(NEW_SRV_ERR_INV_RUN_SELECTION);
  run_selection = x;

  if (hr_cgi_param(phr, "dir_struct", &s) <= 0)
    FAIL(NEW_SRV_ERR_INV_DIR_STRUCT);
  errno = 0;
  x = strtol(s, &ss, 10);
  if (errno || *ss || x < 0 || x > 10) FAIL(NEW_SRV_ERR_INV_DIR_STRUCT);
  dir_struct = x;

  if (hr_cgi_param(phr, "use_problem_extid", &s) > 0)
    use_problem_extid = 1;
  if (hr_cgi_param(phr, "use_problem_dir", &s) > 0)
    use_problem_dir = 1;

  hr_cgi_param(phr, "problem_dir_prefix", &problem_dir_prefix);

  if (hr_cgi_param(phr, "file_pattern_run", &s) > 0)
    file_name_mask |= NS_FILE_PATTERN_RUN;
  if (hr_cgi_param(phr, "file_pattern_uid", &s) > 0)
    file_name_mask |= NS_FILE_PATTERN_UID;
  if (hr_cgi_param(phr, "file_pattern_login", &s) > 0)
    file_name_mask |= NS_FILE_PATTERN_LOGIN;
  if (hr_cgi_param(phr, "file_pattern_name", &s) > 0)
    file_name_mask |= NS_FILE_PATTERN_NAME;
  if (hr_cgi_param(phr, "file_pattern_prob", &s) > 0)
    file_name_mask |= NS_FILE_PATTERN_PROB;
  if (hr_cgi_param(phr, "file_pattern_lang", &s) > 0)
    file_name_mask |= NS_FILE_PATTERN_LANG;
  if (hr_cgi_param(phr, "file_pattern_suffix", &s) > 0)
    file_name_mask |= NS_FILE_PATTERN_SUFFIX;
  if (hr_cgi_param(phr, "file_pattern_contest", &s) > 0)
    file_name_mask |= NS_FILE_PATTERN_CONTEST;
  if (hr_cgi_param(phr, "file_pattern_time", &s) > 0)
    file_name_mask |= NS_FILE_PATTERN_TIME;
  if (!file_name_mask) file_name_mask = NS_FILE_PATTERN_RUN;

  if (ns_parse_run_mask(phr, 0, 0, &mask_size, &mask) < 0)
    goto invalid_param;

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  ns_download_runs(cnts, cs, fout, log_f, run_selection, dir_struct, file_name_mask, use_problem_extid, use_problem_dir,
                   problem_dir_prefix, mask_size, mask);

  if (cs->xuser_state) {
    cs->xuser_state->vt->set_problem_dir_prefix(cs->xuser_state, phr->user_id, problem_dir_prefix);
  }

 cleanup:
  return retval;

 invalid_param:
  error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
  xfree(mask);
  return -1;
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
  run_get_saved_times(cs->runlog_state, &duration, &saved_stop_time, 0);
  stop_time = run_get_stop_time(cs->runlog_state, 0, 0);
  if (!cs->global->is_virtual && stop_time <= 0 && saved_stop_time <= 0) return 0;

  hr_cgi_param(phr, "freeze_standings", &freeze_standings);
  hr_cgi_param(phr, "view_source", &view_source);
  hr_cgi_param(phr, "view_protocol", &view_protocol);
  hr_cgi_param(phr, "full_protocol", &full_proto);
  hr_cgi_param(phr, "disable_clars", &disable_clars);

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  switch (phr->action) {
  case NEW_SRV_ACTION_UPSOLVING_CONFIG_2: // back to main page
    break;
  case NEW_SRV_ACTION_UPSOLVING_CONFIG_3: // stop upsolving
    if (!cs->upsolving_mode) break;
    // do not allow disabling upsolving for virtual contests
    if (cs->global->is_virtual > 0) break;
    run_stop_contest(cs->runlog_state, cs->current_time);
    serve_invoke_stop_script(cs);
    cs->upsolving_mode = 0;
    cs->upsolving_freeze_standings = 0;
    cs->upsolving_view_source = 0;
    cs->upsolving_view_protocol = 0;
    cs->upsolving_full_protocol = 0;
    cs->upsolving_disable_clars = 0;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    extra->last_access_time = 0;          // force reload
    expired_contest_last_check_time = 0;
    break;
  case NEW_SRV_ACTION_UPSOLVING_CONFIG_4: // start upsolving
    run_save_times(cs->runlog_state);
    run_set_duration(cs->runlog_state, 0);
    run_stop_contest(cs->runlog_state, 0);
    run_set_finish_time(cs->runlog_state, 0);
    cs->upsolving_mode = 1;
    cs->upsolving_freeze_standings = 0;
    cs->upsolving_view_source = 0;
    cs->upsolving_view_protocol = 0;
    cs->upsolving_full_protocol = 0;
    cs->upsolving_disable_clars = 0;
    if (freeze_standings && *freeze_standings) cs->upsolving_freeze_standings = 1;
    if (view_source && *view_source) cs->upsolving_view_source = 1;
    if (view_protocol && *view_protocol) cs->upsolving_view_protocol = 1;
    if (full_proto && *full_proto) cs->upsolving_full_protocol = 1;
    if (disable_clars && *disable_clars) cs->upsolving_disable_clars = 1;
    serve_update_status_file(ejudge_config, cnts, cs, 1);
    extra->last_access_time = 0;          // force reload
    expired_contest_last_check_time = 0;
    break;
  default:
    abort();
  }

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

  if (cs->global->disable_user_database > 0)
    FAIL(NEW_SRV_ERR_INV_ACTION);

  if (phr->role < USER_ROLE_ADMIN)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (opcaps_check(phr->caps, OPCAP_EDIT_REG) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (hr_cgi_param(phr, "prefix", &prefix) <= 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  if (hr_cgi_param_int(phr, "min_num", &min_num) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  if (hr_cgi_param_int(phr, "max_num", &max_num) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  if (hr_cgi_param_int(phr, "seed", &seed) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  if (hr_cgi_param_int_opt(phr, "mult", &mult, 1) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  if (hr_cgi_param_int_opt(phr, "shift", &shift, 1) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  if (min_num < 0 || max_num < 0 || min_num > max_num || seed < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

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
  close_memstream(msg_f); msg_f = 0;

  if (ns_open_ul_connection(phr->fw_state) < 0)
    FAIL(NEW_SRV_ERR_TRY_AGAIN);
  r = userlist_clnt_import_csv_users(ul_conn, ULS_IMPORT_CSV_USERS,
                                     phr->contest_id, ';', 0, msg_txt,
                                     &csv_reply);
  if (r < 0) FAIL(NEW_SRV_ERR_INTERNAL);

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->priv_header_txt, 0, 0, 0, 0, phr->locale_id, cnts,
            phr->client_key,
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

  ns_footer(fout, extra->priv_footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_resetlocale();

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
priv_set_priorities(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  //const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob;
  int retval = 0;
  int prob_id, prio;
  unsigned char varname[64];

  if (phr->role != USER_ROLE_ADMIN)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (opcaps_check(phr->caps, OPCAP_REJUDGE_RUN) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  for (prob_id = 1;
       prob_id <= cs->max_prob && prob_id < EJ_SERVE_STATE_TOTAL_PROBS;
       ++prob_id) {
    if (!(prob = cs->probs[prob_id])) continue;
    snprintf(varname, sizeof(varname), "prio_%d", prob_id);
    prio = 0;
    if (hr_cgi_param_int(phr, varname, &prio) < 0) continue;
    if (prio < -16) prio = -16;
    if (prio > 15) prio = 15;
    cs->prob_prio[prob_id] = prio;
  }

 cleanup:
  return retval;
}

static int
priv_delete_avatar(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int retval = 0;
  int other_user_id = -1;

  if (phr->role != USER_ROLE_ADMIN)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (opcaps_check(phr->caps, OPCAP_EDIT_USER) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  hr_cgi_param_int_opt(phr, "other_user_id", &other_user_id, -1);
  if (other_user_id <= 0) FAIL(NEW_SRV_ERR_INV_USER_ID);
  if (!teamdb_lookup(cs->teamdb_state, other_user_id)) FAIL(NEW_SRV_ERR_INV_USER_ID);

  if (ns_open_ul_connection(phr->fw_state) < 0) FAIL(NEW_SRV_ERR_USERLIST_SERVER_DOWN);
#define DELETED_FIELD_COUNT 3
  int deleted_ids[DELETED_FIELD_COUNT] =
  {
    USERLIST_NC_AVATAR_STORE,
    USERLIST_NC_AVATAR_ID,
    USERLIST_NC_AVATAR_SUFFIX,
  };

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, other_user_id);

  int r = userlist_clnt_edit_field_seq(ul_conn, ULS_EDIT_FIELD_SEQ,
                                       other_user_id, phr->contest_id, 0,
                                       DELETED_FIELD_COUNT, 0, deleted_ids,
                                       NULL, NULL);
  if (r < 0) FAIL(NEW_SRV_ERR_USERLIST_SERVER_DOWN);

  snprintf(phr->next_extra, sizeof(phr->next_extra), "user_id=%d", other_user_id);
  retval = NEW_SRV_ACTION_VIEW_USER_INFO;

 cleanup:
  return retval;
}

static int
priv_confirm_avatar(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int retval = 0;
  int other_user_id = -1;

  if (phr->role != USER_ROLE_ADMIN)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (opcaps_check(phr->caps, OPCAP_EDIT_USER) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  hr_cgi_param_int_opt(phr, "other_user_id", &other_user_id, -1);
  if (other_user_id <= 0) FAIL(NEW_SRV_ERR_INV_USER_ID);
  if (!teamdb_lookup(cs->teamdb_state, other_user_id)) FAIL(NEW_SRV_ERR_INV_USER_ID);

  if (ns_open_ul_connection(phr->fw_state) < 0) FAIL(NEW_SRV_ERR_USERLIST_SERVER_DOWN);

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, other_user_id);

  if (userlist_clnt_change_registration(ul_conn, other_user_id, phr->contest_id,
                                        USERLIST_REG_OK, 1, USERLIST_UC_REG_READONLY) < 0) {
    FAIL(NEW_SRV_ERR_USER_FLAGS_CHANGE_FAILED);
  }

  snprintf(phr->next_extra, sizeof(phr->next_extra), "user_id=%d", other_user_id);
  retval = NEW_SRV_ACTION_VIEW_USER_INFO;

 cleanup:
  return retval;
}

static int
priv_testing_queue_operation(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0;
  const unsigned char *packet_name = 0, *s, *queue_id = NULL;
  const serve_state_t cs = extra->serve_state;

  if (opcaps_check(phr->caps, OPCAP_CONTROL_CONTEST) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (hr_cgi_param(phr, "packet", &packet_name) <= 0 || !packet_name)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  for (s = packet_name; *s; ++s) {
    if (!isalnum(*s)) {
      FAIL(NEW_SRV_ERR_INV_PARAM);
    }
  }
  hr_cgi_param(phr, "queue", &queue_id);
  if (queue_id) {
    /*
    for (s = queue_id; *s; ++s) {
      if (!isalnum(*s)) {
        FAIL(NEW_SRV_ERR_INV_PARAM);
      }
    }
    */
  }

  info("audit:%s:%d:%d:%s", phr->action_str, phr->user_id, phr->contest_id, queue_id);

  switch (phr->action) {
  case NEW_SRV_ACTION_TESTING_DELETE:
    serve_testing_queue_delete(cnts, cs, queue_id, packet_name, phr->login);
    break;
  case NEW_SRV_ACTION_TESTING_UP:
    serve_testing_queue_change_priority(cnts, cs, queue_id, packet_name, -1, phr->login);
    break;
  case NEW_SRV_ACTION_TESTING_DOWN:
    serve_testing_queue_change_priority(cnts, cs, queue_id, packet_name, 1, phr->login);
    break;
  default:
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }

 cleanup:
  return retval;
}

static int
priv_whole_testing_queue_operation(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0;
  const serve_state_t cs = extra->serve_state;

  if (opcaps_check(phr->caps, OPCAP_CONTROL_CONTEST) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  switch (phr->action) {
  case NEW_SRV_ACTION_TESTING_DELETE_ALL:
    serve_testing_queue_delete_all(cnts, cs, phr->login);
    break;
  case NEW_SRV_ACTION_TESTING_UP_ALL:
    serve_testing_queue_change_priority_all(cnts, cs, -1, phr->login);
    break;
  case NEW_SRV_ACTION_TESTING_DOWN_ALL:
    serve_testing_queue_change_priority_all(cnts, cs, 1, phr->login);
    break;
  default:
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }

 cleanup:
  return retval;
}

static int
priv_invoker_operation(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0;
  const serve_state_t cs = extra->serve_state;
  const unsigned char *file = NULL, *s, *queue = NULL;
  opcap_t caps = 0;

  if (ejudge_cfg_opcaps_find(phr->config, phr->login, &caps) < 0) {
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (hr_cgi_param(phr, "file", &file) <= 0 || !file)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  for (s = file; *s; ++s) {
    if (*s <= ' ' || *s >= 0x7f || *s == '/') {
      FAIL(NEW_SRV_ERR_INV_PARAM);
    }
  }
  hr_cgi_param(phr, "queue", &queue);

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  switch (phr->action) {
  case NEW_SRV_ACTION_INVOKER_DELETE:
    serve_invoker_delete(cs, queue, file);
    break;
  case NEW_SRV_ACTION_INVOKER_STOP:
    serve_invoker_stop(cs, queue, file);
    break;
  case NEW_SRV_ACTION_INVOKER_DOWN:
    serve_invoker_down(cs, queue, file);
    break;
  case NEW_SRV_ACTION_INVOKER_REBOOT:
    serve_invoker_reboot(cs, queue, file);
    break;
  default:
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }

 cleanup:
  return retval;
}

static int
priv_compiler_operation(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0;
  const serve_state_t cs = extra->serve_state;
  const unsigned char *file = NULL, *s, *queue = NULL;
  opcap_t caps = 0;
  const unsigned char *op = NULL;

  if (ejudge_cfg_opcaps_find(phr->config, phr->login, &caps) < 0) {
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (hr_cgi_param(phr, "file", &file) <= 0 || !file)
    FAIL(NEW_SRV_ERR_INV_PARAM);
  for (s = file; *s; ++s) {
    if (*s <= ' ' || *s >= 0x7f || *s == '/') {
      FAIL(NEW_SRV_ERR_INV_PARAM);
    }
  }
  hr_cgi_param(phr, "queue", &queue);
  hr_cgi_param(phr, "op", &op);

  info("audit:%s:%d:%d:%s:%s", phr->action_str, phr->user_id, phr->contest_id, queue, op);
  serve_compiler_op(cs, queue, file, op);

cleanup:
  return retval;
}

static int
priv_stand_filter_operation(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0;
  const serve_state_t cs = extra->serve_state;

  /*
  if (opcaps_check(phr->caps, OPCAP_CONTROL_CONTEST) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  */

  switch (phr->action) {
  case NEW_SRV_ACTION_SET_STAND_FILTER:
    ns_set_stand_filter(cs, phr);
    break;
  case NEW_SRV_ACTION_RESET_STAND_FILTER:
    ns_reset_stand_filter(cs, phr);
    break;
  default:
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }

 cleanup:
  return retval;
}

static int
priv_change_run_fields(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0;
  const serve_state_t cs = extra->serve_state;

  if (phr->role <= 0) FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  const unsigned char *s = NULL;
  if (hr_cgi_param(phr, "cancel", &s) > 0 && s) goto cleanup;

  struct user_filter_info *u = user_filter_info_allocate(cs, phr->user_id, phr->session_id);
  if (!u) goto cleanup;

  if (hr_cgi_param(phr, "reset", &s) > 0 && s) {
    if (u->run_fields <= 0) goto cleanup;
    u->run_fields = 0;
    if (cs->xuser_state) {
      cs->xuser_state->vt->set_run_fields(cs->xuser_state, phr->user_id, 0);
      cs->xuser_state->vt->flush(cs->xuser_state);
    }
    goto cleanup;
  }

  long long new_fields = 0;
  for (int i = 0; i < RUN_VIEW_LAST; ++i) {
    unsigned char nbuf[64];
    snprintf(nbuf, sizeof(nbuf), "field_%d", i);
    if (hr_cgi_param(phr, nbuf, &s) > 0 && s) {
      new_fields |= 1LL << i;
    }
  }
  if (new_fields == u->run_fields) goto cleanup;
  u->run_fields = new_fields;
  if (cs->xuser_state) {
    cs->xuser_state->vt->set_run_fields(cs->xuser_state, phr->user_id, u->run_fields);
    cs->xuser_state->vt->flush(cs->xuser_state);
  }

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
  if (hr_cgi_param_int(phr, "user_id", &user_id) < 0)
    FAIL(NEW_SRV_ERR_INV_USER_ID);
  if (!teamdb_lookup(cs->teamdb_state, user_id))
    FAIL(NEW_SRV_ERR_INV_USER_ID);

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, user_id);

  if (phr->action == NEW_SRV_ACTION_PRINT_UFC_PROTOCOL) {
    full_report = 1;
    use_cypher = 1;
  } else if (phr->action == NEW_SRV_ACTION_PRINT_USER_FULL_PROTOCOL) {
    full_report = 1;
  } else {
    use_user_printer = 1;
  }

  if (cnts->default_locale_num > 0) locale_id = cnts->default_locale_num;
  if (locale_id > 0) l10n_setlocale(locale_id);
  ff = open_memstream(&log_text, &log_size);
  r = ns_print_user_exam_protocol(cnts, cs, ff, user_id, locale_id,
                                  use_user_printer, full_report, use_cypher);
  close_memstream(ff); ff = 0;
  if (locale_id > 0) l10n_resetlocale();

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->priv_header_txt, 0, 0, 0, 0, phr->locale_id, cnts,
            phr->client_key,
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

  ns_footer(fout, extra->priv_footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_resetlocale();

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
  int locale_id = 0;
  intarray_t uset;
  int use_user_printer = 0;
  int full_report = 0;
  int use_cypher = 0;
  int include_testing_report = 0;
  int run_latex = 0;
  int print_pdfs = 0;
  int clear_working_directory = 0;

  memset(&uset, 0, sizeof(uset));

  if (opcaps_check(phr->caps, OPCAP_PRINT_RUN) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (parse_user_list(phr, cs, &uset, 0) < 0)
    FAIL(NEW_SRV_ERR_INV_PARAM);

  hr_cgi_param_jsbool_opt(phr, "include_testing_report", &include_testing_report, 0);
  hr_cgi_param_jsbool_opt(phr, "run_latex", &run_latex, 0);
  hr_cgi_param_jsbool_opt(phr, "print_pdfs", &print_pdfs, 0);
  hr_cgi_param_jsbool_opt(phr, "clear_working_directory", &clear_working_directory, 0);
  if (!run_latex) print_pdfs = 0;
  if (!print_pdfs) clear_working_directory = 0;

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  if (phr->action == NEW_SRV_ACTION_PRINT_SELECTED_UFC_PROTOCOL) {
    full_report = 1;
    use_cypher = 1;
  } else if (phr->action == NEW_SRV_ACTION_PRINT_SELECTED_USER_FULL_PROTOCOL) {
    full_report = 1;
  } else {
    use_user_printer = 1;
  }

  if (cnts->default_locale_num > 0) locale_id = cnts->default_locale_num;
  if (locale_id > 0) l10n_setlocale(locale_id);
  ff = open_memstream(&log_text, &log_size);
  if (cs->contest_plugin && cs->contest_plugin->print_user_reports) {
    r = (*cs->contest_plugin->print_user_reports)
      (cs->contest_plugin_data, ff, cnts, cs, uset.u, uset.v, locale_id,
       use_user_printer, full_report, use_cypher);
  } else {
    r = ns_print_user_exam_protocols(cnts, cs, ff, uset.u, uset.v, locale_id,
                                     use_user_printer, full_report, use_cypher,
                                     include_testing_report,
                                     run_latex,
                                     print_pdfs,
                                     clear_working_directory);
  }
  close_memstream(ff); ff = 0;
  if (locale_id > 0) l10n_resetlocale();

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->priv_header_txt, 0, 0, 0, 0, phr->locale_id, cnts,
            phr->client_key,
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

  ns_footer(fout, extra->priv_footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_resetlocale();

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
  if (hr_cgi_param_int(phr, "prob_id", &prob_id) < 0)
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  if (prob_id <= 0 || prob_id > cs->max_prob || !cs->probs[prob_id])
    FAIL(NEW_SRV_ERR_INV_PROB_ID);

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, prob_id);

  if (cnts->default_locale_num > 0) locale_id = cnts->default_locale_num;
  if (locale_id > 0) l10n_setlocale(locale_id);
  ff = open_memstream(&log_text, &log_size);
  r = ns_print_prob_exam_protocol(cnts, cs, ff, prob_id, locale_id, 1);
  close_memstream(ff); ff = 0;
  if (locale_id > 0) l10n_resetlocale();

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->priv_header_txt, 0, 0, 0, 0, phr->locale_id, cnts,
            phr->client_key,
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

  ns_footer(fout, extra->priv_footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_resetlocale();

 cleanup:
  if (ff) fclose(ff);
  xfree(ss);
  xfree(log_text);
  return retval;
}

static int
ping_page(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  fprintf(fout, "Content-type: text/plain\n\nOK\n");
  return 0;
}

static int
priv_submit_run_batch_page(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int retval = 0;
  int run_id = 0;

  if (opcaps_check(phr->caps, OPCAP_SUBMIT_RUN) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  retval = ns_submit_run(log_f, phr, cnts, extra, NULL, NULL, 1, 1, 1, 1, 1, 1, 0, &run_id, NULL, NULL);
  if (retval >= 0) retval = run_id;

cleanup:
  fprintf(fout, "Content-type: text/plain\n\n%d\n", retval);
  return 0;
}

typedef int (*action_handler2_t)(FILE *fout,
                                 FILE *log_f,
                                 struct http_request_info *phr,
                                 const struct contest_desc *cnts,
                                 struct contest_extra *extra);

static action_handler2_t priv_actions_table_2[NEW_SRV_ACTION_LAST] =
{
  /* for priv_generic_operation */
  [NEW_SRV_ACTION_USERS_REMOVE_REGISTRATIONS] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_SET_PENDING] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_SET_STATUS] = priv_registration_operation,
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
  [NEW_SRV_ACTION_USERS_CHANGE_FLAGS] = priv_registration_operation,
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
  [NEW_SRV_ACTION_CHANGE_FINISH_TIME] = priv_contest_operation,
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
  [NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT] = priv_submit_run_comment,
  [NEW_SRV_ACTION_CLAR_REPLY] = priv_clar_reply,
  [NEW_SRV_ACTION_CLAR_REPLY_ALL] = priv_clar_reply,
  [NEW_SRV_ACTION_CLAR_REPLY_READ_PROBLEM] = priv_clar_reply,
  [NEW_SRV_ACTION_CLAR_REPLY_NO_COMMENTS] = priv_clar_reply,
  [NEW_SRV_ACTION_CLAR_REPLY_YES] = priv_clar_reply,
  [NEW_SRV_ACTION_CLAR_REPLY_NO] = priv_clar_reply,
  [NEW_SRV_ACTION_RELOAD_SERVER] = priv_contest_operation,
  [NEW_SRV_ACTION_RELOAD_SERVER_ALL] = priv_contest_operation,
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
  [NEW_SRV_ACTION_CHANGE_RUN_IS_MARKED] = priv_edit_run,
  [NEW_SRV_ACTION_CHANGE_RUN_IS_SAVED] = priv_edit_run,
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
  [NEW_SRV_ACTION_TOKENIZE_DISPLAYED_2] = priv_tokenize_displayed,
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
  [NEW_SRV_ACTION_SET_PRIORITIES] = priv_set_priorities,
  [NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_IGNORE] = priv_submit_run_comment,
  [NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_OK] = priv_submit_run_comment,
  [NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_REJECT] = priv_submit_run_comment,
  [NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_SUMMON] = priv_submit_run_comment,
  [NEW_SRV_ACTION_PRIV_SUBMIT_RUN_JUST_IGNORE] = priv_simple_change_status,
  [NEW_SRV_ACTION_PRIV_SUBMIT_RUN_JUST_OK] = priv_simple_change_status,
  [NEW_SRV_ACTION_PRIV_SUBMIT_RUN_JUST_SUMMON] = priv_simple_change_status,
  [NEW_SRV_ACTION_PRIV_OLD_SET_RUN_REJECTED] = priv_set_run_rejected_status,
  [NEW_SRV_ACTION_TESTING_DELETE] = priv_testing_queue_operation,
  [NEW_SRV_ACTION_TESTING_UP] = priv_testing_queue_operation,
  [NEW_SRV_ACTION_TESTING_DOWN] = priv_testing_queue_operation,
  [NEW_SRV_ACTION_TESTING_DELETE_ALL] = priv_whole_testing_queue_operation,
  [NEW_SRV_ACTION_TESTING_UP_ALL] = priv_whole_testing_queue_operation,
  [NEW_SRV_ACTION_TESTING_DOWN_ALL] = priv_whole_testing_queue_operation,
  [NEW_SRV_ACTION_INVOKER_DELETE] = priv_invoker_operation,
  [NEW_SRV_ACTION_INVOKER_STOP] = priv_invoker_operation,
  [NEW_SRV_ACTION_INVOKER_DOWN] = priv_invoker_operation,
  [NEW_SRV_ACTION_SET_STAND_FILTER] = priv_stand_filter_operation,
  [NEW_SRV_ACTION_RESET_STAND_FILTER] = priv_stand_filter_operation,
  [NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_SOURCE] = priv_contest_operation,
  [NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_REPORT] = priv_contest_operation,
  [NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_JUDGE_SCORE] = priv_contest_operation,
  [NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_FINAL_VISIBILITY] = priv_contest_operation,
  [NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VALUER_JUDGE_COMMENTS] = priv_contest_operation,
  [NEW_SRV_ACTION_CHANGE_RUN_FIELDS] = priv_change_run_fields,
  [NEW_SRV_ACTION_PRIV_EDIT_CLAR_ACTION] = ns_priv_edit_clar_action,
  [NEW_SRV_ACTION_PRIV_EDIT_RUN_ACTION] = ns_priv_edit_run_action,
  [NEW_SRV_ACTION_PRIV_REGENERATE_CONTENT] = priv_regenerate_content,
  [NEW_SRV_ACTION_DELETE_AVATAR] = priv_delete_avatar,
  [NEW_SRV_ACTION_TOGGLE_PRIVILEGED] = priv_user_toggle_flags,
  [NEW_SRV_ACTION_TOGGLE_REG_READONLY] = priv_user_toggle_flags,
  [NEW_SRV_ACTION_USER_CHANGE_STATUS_2] = priv_user_change_status_2,
  [NEW_SRV_ACTION_CONFIRM_AVATAR] = priv_confirm_avatar,

  /* for priv_generic_page */
  [NEW_SRV_ACTION_DOWNLOAD_RUN] = priv_download_source,
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
  [NEW_SRV_ACTION_UPDATE_STANDINGS_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_RESET_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_GENERATE_PASSWORDS_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_GENERATE_REG_PASSWORDS_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_CLEAR_PASSWORDS_1] = priv_confirmation_page,
  [NEW_SRV_ACTION_VIEW_USER_DUMP] = priv_view_user_dump,
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
  [NEW_SRV_ACTION_EXAMINERS_PAGE] = priv_examiners_page,
  [NEW_SRV_ACTION_PRINT_USER_PROTOCOL] = priv_print_user_exam_protocol,
  [NEW_SRV_ACTION_PRINT_USER_FULL_PROTOCOL] = priv_print_user_exam_protocol,
  [NEW_SRV_ACTION_PRINT_UFC_PROTOCOL] = priv_print_user_exam_protocol,
  [NEW_SRV_ACTION_PRINT_SELECTED_USER_PROTOCOL] = priv_print_users_exam_protocol,
  [NEW_SRV_ACTION_PRINT_SELECTED_USER_FULL_PROTOCOL] = priv_print_users_exam_protocol,
  [NEW_SRV_ACTION_PRINT_SELECTED_UFC_PROTOCOL] = priv_print_users_exam_protocol,
  [NEW_SRV_ACTION_PRINT_PROBLEM_PROTOCOL] = priv_print_problem_exam_protocol,
  [NEW_SRV_ACTION_MARK_DISPLAYED_2] = priv_clear_displayed,
  [NEW_SRV_ACTION_UNMARK_DISPLAYED_2] = priv_clear_displayed,
  [NEW_SRV_ACTION_PING] = ping_page,
  [NEW_SRV_ACTION_SUBMIT_RUN_BATCH] = priv_submit_run_batch_page,
  [NEW_SRV_ACTION_RELOAD_CONTEST_PAGES] = priv_contest_operation,
  [NEW_SRV_ACTION_RELOAD_ALL_CONTEST_PAGES] = priv_contest_operation,
  [NEW_SRV_ACTION_LOCK_FILTER] = priv_reset_filter,
  [NEW_SRV_ACTION_DISABLE_VIRTUAL_START] = priv_contest_operation,
  [NEW_SRV_ACTION_ENABLE_VIRTUAL_START] = priv_contest_operation,
  [NEW_SRV_ACTION_COMPILER_OP] = priv_compiler_operation,
  [NEW_SRV_ACTION_INVOKER_REBOOT] = priv_invoker_operation,
  [NEW_SRV_ACTION_CLEAR_SESSION_CACHE] = priv_contest_operation,
};

static void
priv_generic_operation(FILE *fout,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra)
{
  int r, rr;

  r = priv_actions_table_2[phr->action](fout, phr->log_f, phr, cnts, extra);
  if (r == -1) {
    return;
  }
  if (r < 0) {
    error_page(fout, phr, 1, r);
    return;
  }
  rr = r;
  if (!r) r = ns_priv_next_state[phr->action];
  if (!rr) rr = ns_priv_prev_state[phr->action];

  if (phr->json_reply) {
  } else if (phr->plain_text) {
    fprintf(fout, "Content-type: text/plain\n\n%d\n", 0);
  } else {
    ns_refresh_page(fout, phr, r, phr->next_extra);
  }
}

static void
priv_generic_page(FILE *fout,
                  struct http_request_info *phr,
                  const struct contest_desc *cnts,
                  struct contest_extra *extra)
{
  int r;

  r = priv_actions_table_2[phr->action](fout, phr->log_f, phr, cnts, extra);
  if (r == -1) {
    return;
  }
  if (r < 0) {
    error_page(fout, phr, 1, r);
    r = 0;
  }
  if (!r) r = ns_priv_prev_state[phr->action];
}

static void
priv_logout(FILE *fout,
            struct http_request_info *phr,
            const struct contest_desc *cnts,
            struct contest_extra *extra)
{
  //unsigned char locale_buf[64];
  unsigned char urlbuf[1024];

  ns_invalidate_session(phr->session_id, phr->client_key);

  if (ns_open_ul_connection(phr->fw_state) < 0)
    return error_page(fout, phr, 0, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
  userlist_clnt_delete_cookie(ul_conn, phr->user_id,
                              phr->contest_id,
                              phr->client_key,
                              phr->session_id);
  snprintf(urlbuf, sizeof(urlbuf),
           "%s?contest_id=%d&locale_id=%d&role=%d",
           phr->self_url, phr->contest_id, phr->locale_id, phr->role);
  ns_refresh_page_2(fout, phr->client_key, urlbuf);
}

void
ns_unparse_statement(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        const struct section_problem_data *prob,
        int variant,
        problem_xml_t px,
        const unsigned char *bb,
        int is_submittable);

void
ns_unparse_answers(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        const struct section_problem_data *prob,
        int variant,
        problem_xml_t px,
        const unsigned char *lang,
        int is_radio,
        int last_answer,
        int next_prob_id,
        int enable_js,
        const unsigned char *class_name);

static void
priv_get_file(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = 0;
  int retval = 0, prob_id, n, variant = 0, mime_type = 0;
  const unsigned char *s = 0;
  path_t fname, fpath, sfx;
  char *file_bytes = 0;
  size_t file_size = 0;
  const unsigned char *content_type = 0;

  if (opcaps_check(phr->caps, OPCAP_SUBMIT_RUN) < 0)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  // rest_mode: /PREFIX/ROLE/ACTION/SESSION/PROBLEM/FILE
  //                    [0]  [1]    [2]     [3]     [4]

  if (phr->rest_count > 3) {
    errno = 0;
    char *ep = NULL;
    long v = strtol(phr->rest_args[3], &ep, 10);
    if (errno || *ep || ep == (char*) phr->rest_args[3] || v <= 0 || v > cs->max_prob) {
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
    }
    prob_id = v;
    if (!(prob = cs->probs[prob_id])) {
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
    }
  } else {
    if (hr_cgi_param(phr, "prob_id", &s) <= 0
        || sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n]
        || prob_id <= 0 || prob_id > cs->max_prob
        || !(prob = cs->probs[prob_id]))
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
  }

  if (prob->variant_num > 0) {
    if (phr->rest_count > 5) {
      errno = 0;
      char *ep = NULL;
      long v = strtol(phr->rest_args[4], &ep, 10);
      if (errno || *ep || ep == (char*) phr->rest_args[4] || v <= 0 || v > prob->variant_num) {
        FAIL(NEW_SRV_ERR_INV_VARIANT);
      }
      variant = v;
      s = phr->rest_args[5];
    } else {
      if (hr_cgi_param_int_opt(phr, "variant", &variant, 0) < 0)
        FAIL(NEW_SRV_ERR_INV_VARIANT);
      if (variant <= 0 || variant > prob->variant_num)
        FAIL(NEW_SRV_ERR_INV_VARIANT);
      if (hr_cgi_param(phr, "file", &s) <= 0 || strchr(s, '/'))
        FAIL(NEW_SRV_ERR_INV_FILE_NAME);
    }
  } else {
    if (phr->rest_count > 4) {
      s = phr->rest_args[4];
    } else {
      if (hr_cgi_param(phr, "file", &s) <= 0 || strchr(s, '/'))
        FAIL(NEW_SRV_ERR_INV_FILE_NAME);
    }
  }

  if (strstr(s, "..")) FAIL(NEW_SRV_ERR_INV_FILE_NAME);
  snprintf(fname, sizeof(fname), "attachments/%s", s);

  os_rGetSuffix(s, sfx, sizeof(sfx));
  if (global->advanced_layout) {
    get_advanced_layout_path(fpath, sizeof(fpath), global, prob, fname, variant);
  } else {
    if (variant > 0) {
      snprintf(fpath, sizeof(fpath), "%s/%s-%d/%s", global->statement_dir, prob->short_name, variant, fname);
    } else {
      snprintf(fpath, sizeof(fpath), "%s/%s/%s", global->statement_dir, prob->short_name, fname);
    }
  }
  mime_type = mime_type_parse_suffix(sfx);
  content_type = mime_type_get_type(mime_type);

  if (generic_read_file(&file_bytes, 0, &file_size, 0, 0, fpath, "") < 0)
    FAIL(NEW_SRV_ERR_INV_FILE_NAME);

  fprintf(fout, "Content-type: %s\n", content_type);
  if (mime_type != MIME_TYPE_TEXT_HTML) {
    fprintf(fout, "Content-Disposition: attachment; filename=\"%s\"\n", s);
  }
  fprintf(fout, "\n");
  fwrite(file_bytes, 1, file_size, fout);

 cleanup:
  if (retval) {
    phr->back_action = NEW_SRV_ACTION_MAIN_PAGE;
    fprintf(phr->log_f, "Error %d", -retval);
    error_page(fout, phr, 1, NEW_SRV_ERR_OPERATION_FAILED);
  }
  xfree(file_bytes);
}

static void
priv_reload_server_2(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
}

static void
priv_get_avatar(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const unsigned char *key = NULL;
  struct avatar_info_vector avatars;
  struct avatar_loaded_plugin *avt = NULL;

  avatar_vector_init(&avatars, 1);
  if (hr_cgi_param(phr, "key", &key) <= 0) {
    error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
    goto cleanup;
  }

  avt = avatar_plugin_get(phr->extra, phr->cnts, phr->config, NULL);
  if (!avt) {
    error_page(fout, phr, 1, NEW_SRV_ERR_INV_PARAM);
    goto cleanup;
  }
  if (avt->iface->fetch_by_key(avt->data, key, 0, &avatars) < 0) {
    error_page(fout, phr, 1, NEW_SRV_ERR_DATABASE_FAILED);
    goto cleanup;
  }
  if (avatars.u > 1) {
    err("AVATAR_INTERNAL: multiple avatars with random key %s!", key);
    error_page(fout, phr, 1, NEW_SRV_ERR_INTERNAL);
    goto cleanup;
  }
  if (avatars.u < 1) {
    error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  struct avatar_info *av = &avatars.v[0];
  fprintf(fout, "Content-type: %s\n", mime_type_get_type(av->mime_type));
  fprintf(fout, "Content-Disposition: attachment; filename=\"%s%s\"\n", key, mime_type_get_suffix(av->mime_type));
  fprintf(fout, "\n");
  fwrite(av->img_data, 1, av->img_size, fout);

cleanup:;
  avatar_vector_free(&avatars);
}

enum { MAX_IMAGE_SIZE = 16 * 1024 * 1024, MAX_IMAGE_WIDTH = 10000, MAX_IMAGE_HEIGHT = 10000 };

static void
priv_upload_avatar(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int errcode = 0;
  int other_user_id = 0;
  const unsigned char *img_data = NULL;
  size_t img_size = 0;
  int mime_type = 0;
  int width = 0;
  int height = 0;
  FILE *log_f = 0;
  char *log_t = 0;
  size_t log_z = 0;
  unsigned char random_key_bin[AVATAR_RANDOM_KEY_SIZE];
  unsigned char random_key[AVATAR_RANDOM_KEY_SIZE * 2];
  unsigned char urlbuf[1024];

  urlbuf[0] = 0;

  if (opcaps_check(phr->caps, OPCAP_EDIT_USER) < 0) {
    errcode = NEW_SRV_ERR_PERMISSION_DENIED;
    goto cleanup;
  }

  if (hr_cgi_param_int(phr, "other_user_id", &other_user_id) < 0) {
    errcode = NEW_SRV_ERR_INV_USER_ID;
    goto cleanup;
  }
  if (!teamdb_lookup(extra->serve_state->teamdb_state, other_user_id)) {
    errcode = NEW_SRV_ERR_INV_USER_ID;
    goto cleanup;
  }
  if (hr_cgi_param_bin(phr, "img_file", &img_data, &img_size) <= 0) {
    errcode = NEW_SRV_ERR_INV_PARAM;
    goto cleanup;
  }
  if (img_size > MAX_IMAGE_SIZE) {
    errcode = NEW_SRV_ERR_INV_PARAM;
    goto cleanup;
  }
  log_f = open_memstream(&log_t, &log_z);
  mime_type = image_identify(log_f, NULL, img_data, img_size, &width, &height);
  fclose(log_f); log_f = NULL;
  free(log_t); log_t = NULL;
  log_z = 0;
  if (mime_type < 0) {
    errcode = NEW_SRV_ERR_INV_PARAM;
    goto cleanup;
  }
  if (mime_type < MIME_TYPE_IMAGE_FIRST || mime_type > MIME_TYPE_IMAGE_LAST) {
    errcode = NEW_SRV_ERR_INV_PARAM;
    goto cleanup;
  }
  if (width < 0 || height < 0) {
    errcode = NEW_SRV_ERR_INV_PARAM;
    goto cleanup;
  }
  if (width > MAX_IMAGE_WIDTH || height > MAX_IMAGE_HEIGHT) {
    errcode = NEW_SRV_ERR_INV_PARAM;
    goto cleanup;
  }
  if (width < AVATAR_WIDTH || height < AVATAR_HEIGHT) {
    errcode = NEW_SRV_ERR_INV_PARAM;
    goto cleanup;
  }

  // generate 128-bit random key
  if (random_init() < 0) {
    errcode = NEW_SRV_ERR_INTERNAL;
    goto cleanup;
  }
  random_bytes(random_key_bin, AVATAR_RANDOM_KEY_SIZE);
  base32_buf(random_key, random_key_bin, AVATAR_RANDOM_KEY_SIZE, 0);

  struct avatar_loaded_plugin *avt = avatar_plugin_get(extra, cnts, phr->config, NULL);
  if (!avt) {
    errcode = NEW_SRV_ERR_INTERNAL;
    goto cleanup;
  }

  int r = avt->iface->insert(avt->data, other_user_id, phr->contest_id,
                             0 /* is_cropped */,
                             1 /* is_temporary */,
                             0 /* is_public */,
                             mime_type, width, height, random_key,
                             phr->current_time,
                             img_data,
                             img_size,
                             NULL);
  if (r < 0) {
    errcode = NEW_SRV_ERR_INTERNAL;
    goto cleanup;
  }

  snprintf(urlbuf, sizeof(urlbuf), "%s?SID=%llx&action=%d&key=%s&other_user_id=%d",
           phr->self_url, phr->session_id, NEW_SRV_ACTION_CROP_AVATAR_PAGE,
           random_key, other_user_id);
  ns_refresh_page_2(fout, phr->client_key, urlbuf);

cleanup:
  if (errcode > 0) {
    error_page(fout, phr, 1, errcode);
  }
}

static const unsigned char *
get_client_url(
        unsigned char *buf,
        size_t size,
        const struct contest_desc *cnts,
        const struct http_request_info *phr)
{
  if (phr->rest_mode > 0) {
    snprintf(buf, size, "%s/user", phr->context_url);
  } else if (cnts->team_url) {
    snprintf(buf, size, "%s", cnts->team_url);
  } else {
#if defined CGI_PROG_SUFFIX
    snprintf(buf, size, "%s/new-client%s", phr->context_url, CGI_PROG_SUFFIX);
#else
    snprintf(buf, size, "%s/new-client", phr->contest_url);
#endif
  }
  return buf;
}

static void
priv_enter_contest(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  int errcode = 0;
  int other_user_id = 0;
  unsigned char urlbuf[1024];
  unsigned char clnturlbuf[1024];

  if (phr->role != USER_ROLE_ADMIN) {
    errcode = NEW_SRV_ERR_PERMISSION_DENIED;
    goto cleanup;
  }
  if (opcaps_check(phr->caps, OPCAP_EDIT_USER) < 0) {
    errcode = NEW_SRV_ERR_PERMISSION_DENIED;
    goto cleanup;
  }

  if (hr_cgi_param_int(phr, "other_user_id", &other_user_id) < 0) {
    errcode = NEW_SRV_ERR_INV_USER_ID;
    goto cleanup;
  }

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, other_user_id);

  struct userlist_cookie in_c;
  struct userlist_cookie out_c;

  memset(&in_c, 0, sizeof(in_c));
  memcpy(&in_c.ip, &phr->ip, sizeof(in_c.ip));
  in_c.ssl = phr->ssl_flag;
  in_c.user_id = other_user_id;
  in_c.contest_id = phr->contest_id;
  in_c.locale_id = 0;
  in_c.priv_level = 0;
  in_c.role = USER_ROLE_CONTESTANT;
  in_c.recovery = 0;
  in_c.team_login = 1;
  in_c.client_key = phr->client_key;

  int r = userlist_clnt_create_cookie(ul_conn, ULS_CREATE_COOKIE, &in_c, &out_c);
  if (r < 0) {
    errcode = NEW_SRV_ERR_INV_USER_ID;
    goto cleanup;
  }

  if (phr->rest_mode > 0) {
    snprintf(urlbuf, sizeof(urlbuf), "%s/%s/S%016llx",
             get_client_url(clnturlbuf, sizeof(clnturlbuf), phr->cnts, phr),
             ns_symbolic_action_table[NEW_SRV_ACTION_MAIN_PAGE],
             out_c.cookie);
  } else {
    snprintf(urlbuf, sizeof(urlbuf), "%s?action=%d&SID=%016llx",
             get_client_url(clnturlbuf, sizeof(clnturlbuf), phr->cnts, phr),
             NEW_SRV_ACTION_MAIN_PAGE,
             out_c.cookie);
  }
  ns_refresh_page_2(fout, phr->client_key, urlbuf);

cleanup:
  if (errcode > 0) {
    error_page(fout, phr, 1, errcode);
  }
}

static inline const unsigned char *
to_json_bool(int value)
{
  if (value > 0) return "true";
  else return "false";
}

static void
priv_run_status_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const unsigned char *s;
  ej_uuid_t run_uuid;
  int run_id = -1;
  struct run_entry re;
  int accepting_mode = 0;
  time_t start_time, stop_time;
  long long run_time_us = 0;
  long long duration = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const struct section_problem_data *prob = NULL;
  const struct section_language_data *lang = NULL;

  phr->json_reply = 1;

  if (hr_cgi_param(phr, "run_uuid", &s) > 0) {
    if (ej_uuid_parse(s, &run_uuid) < 0) {
      error_page(fout, phr, 1, NEW_SRV_ERR_INV_UUID);
      goto cleanup;
    }
    if ((run_id = run_find_run_id_by_uuid(cs->runlog_state, &run_uuid)) < 0) {
      error_page(fout, phr, 1, NEW_SRV_ERR_INV_UUID);
      goto cleanup;
    }
  } else if (hr_cgi_param_int(phr, "run_id", &run_id) >= 0) {
  } else {
    error_page(fout, phr, 1, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }

  if (run_id < 0 || run_id >= run_get_total(cs->runlog_state)) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  if (run_get_entry(cs->runlog_state, run_id, &re) < 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }

  if (re.status < 0 || re.status > RUN_TRANSIENT_LAST
      || (re.status > RUN_LOW_LAST && re.status < RUN_TRANSIENT_FIRST)) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }

  if (re.status == RUN_EMPTY) {
    fprintf(fout, "{");
    fprintf(fout, "\"ok\":true");
    fprintf(fout, ",\"server_time\":%lld", (long long) cs->current_time);
    fprintf(fout, ",\"result\":{");
    fprintf(fout, "\"run\":{");
    fprintf(fout, "\"run_id\":%d", re.run_id);
    fprintf(fout, ",\"status\":%d", re.status);
    fprintf(fout, ",\"status_str\":\"%s\"", run_status_short_str(re.status));
    fprintf(fout, "}");
    fprintf(fout, "}");
    fprintf(fout, "}\n");
    goto cleanup;
  }

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, re.user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, re.user_id, cs->current_time);
    if (stop_time <= 0 || cs->upsolving_mode) accepting_mode = 1;
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state, 0, 0);
    accepting_mode = cs->accepting_mode;
  }

  run_time_us = re.time * 1000000LL + re.nsec / 1000;
  if (start_time > 0) {
    duration = (long long) re.time - start_time;
    if (duration < 0) duration = 0;
  }

  if (re.status == RUN_VIRTUAL_START || re.status == RUN_VIRTUAL_STOP) {
    fprintf(fout, "{");
    fprintf(fout, "\"ok\":true");
    fprintf(fout, ",\"server_time\":%lld", (long long) cs->current_time);
    fprintf(fout, ",\"result\":{");
    fprintf(fout, "\"run\":{");
    fprintf(fout, "\"run_id\":%d", re.run_id);
    fprintf(fout, ",\"status\":%d", re.status);
    fprintf(fout, ",\"status_str\":\"%s\"", run_status_short_str(re.status));
    fprintf(fout, ",\"run_time\":%lld", (long long) re.time);
    fprintf(fout, ",\"nsec\":%d", re.nsec);
    fprintf(fout, ",\"run_time_us\":%lld", run_time_us);
    if (duration > 0) {
      fprintf(fout, ",\"duration\":%lld", duration);
    }
    fprintf(fout, ",\"user_id\":%d", re.user_id);
    s = teamdb_get_login(cs->teamdb_state, re.user_id);
    if (s && *s) {
      fprintf(fout, ",\"user_login\":%s", JARMOR(s));
    }
    s = teamdb_get_name(cs->teamdb_state, re.user_id);
    if (s && *s) {
      fprintf(fout, ",\"user_name\":%s", JARMOR(s));
    }
    fprintf(fout, "}");
    fprintf(fout, "}");
    fprintf(fout, "}\n");
    goto cleanup;
  }

  fprintf(fout, "{");
  fprintf(fout, "\"ok\":true");
  fprintf(fout, ",\"server_time\":%lld", (long long) cs->current_time);
  fprintf(fout, ",\"result\":{");
  if (accepting_mode) {
    fprintf(fout, ",\"accepting_mode\":%s", to_json_bool(accepting_mode));
  }
  fprintf(fout, "\"run\":{");
  fprintf(fout, "\"run_id\":%d", re.run_id);
  if (ej_uuid_is_nonempty(re.run_uuid)) {
    fprintf(fout, ",\"run_uuid\":\"%s\"", ej_uuid_unparse(&re.run_uuid, ""));
  }
  if (re.serial_id > 0) {
    fprintf(fout, ",\"serial_id\":%lld", (long long) re.serial_id);
  }
  fprintf(fout, ",\"status\":%d", re.status);
  fprintf(fout, ",\"status_str\":\"%s\"", run_status_short_str(re.status));
  fprintf(fout, ",\"run_time\":%lld", (long long) re.time);
  fprintf(fout, ",\"nsec\":%d", re.nsec);
  fprintf(fout, ",\"run_time_us\":%lld", run_time_us);
  if (duration > 0) {
    fprintf(fout, ",\"duration\":%lld", duration);
  }
  fprintf(fout, ",\"user_id\":%d", re.user_id);
  s = teamdb_get_login(cs->teamdb_state, re.user_id);
  if (s && *s) {
    fprintf(fout, ",\"user_login\":\"%s\"", JARMOR(s));
  }
  s = teamdb_get_name(cs->teamdb_state, re.user_id);
  if (s && *s) {
    fprintf(fout, ",\"user_name\":\"%s\"", JARMOR(s));
  }
  if (re.ext_user_kind > 0 && re.ext_user_kind < MIXED_ID_LAST) {
    unsigned char mbuf[64];
    fprintf(fout, ",\"ext_user_kind\":\"%s\"",
            mixed_id_unparse_kind(re.ext_user_kind));
    fprintf(fout, ",\"ext_user\":\"%s\"",
            JARMOR(mixed_id_marshall(mbuf, re.ext_user_kind, &re.ext_user)));
  }
  fprintf(fout, ",\"prob_id\":%d", re.prob_id);
  if (re.prob_id > 0 && re.prob_id <= cs->max_prob) prob = cs->probs[re.prob_id];
  if (prob && /*prob->short_name &&*/ prob->short_name[0]) {
    fprintf(fout, ",\"prob_name\":\"%s\"", JARMOR(prob->short_name));
  }
  if (prob && prob->internal_name && prob->internal_name[0]) {
    fprintf(fout, ",\"prob_internal_name\":\"%s\"", JARMOR(prob->internal_name));
  }
  if (ej_uuid_is_nonempty(re.prob_uuid)) {
    fprintf(fout, ",\"prob_uuid\":\"%s\"", ej_uuid_unparse(&re.prob_uuid, ""));
  } else if (prob && prob->uuid && prob->uuid[0]) {
    fprintf(fout, ",\"prob_uuid\":\"%s\"", JARMOR(prob->uuid));
  }
  if (prob && prob->variant_num > 0) {
    if (re.variant > 0) {
      fprintf(fout, ",\"raw_variant\":%d", re.variant);
      fprintf(fout, ",\"variant\":%d", re.variant);
    } else {
      int variant = find_variant(cs, re.user_id, re.prob_id, 0);
      if (variant > 0) {
        fprintf(fout, ",\"variant\":%d", re.variant);
      }
    }
  }
  fprintf(fout, ",\"lang_id\":%d", re.lang_id);
  if (re.lang_id > 0 && re.lang_id <= cs->max_lang) lang = cs->langs[re.lang_id];
  if (lang && /*lang->short_name &&*/ lang->short_name[0]) {
    fprintf(fout, ",\"lang_name\":\"%s\"", JARMOR(lang->short_name));
  }
  fprintf(fout, ",\"ip\":\"%s\"", xml_unparse_ip(re.a.ip));
  if (re.ssl_flag) {
    fprintf(fout, ",\"ssl_flag\":%s", to_json_bool(re.ssl_flag));
  }
  if (re.ipv6_flag) {
    fprintf(fout, ",\"ipv6_flag\":%s", to_json_bool(re.ipv6_flag));
  }
  if (re.sha256_flag) {
    fprintf(fout, ",\"sha256\":\"%s\"", unparse_sha256(re.h.sha256));
  } else {
    fprintf(fout, ",\"sha1\":\"%s\"", unparse_sha1(re.h.sha1));
  }
  if (re.locale_id > 0) {
    fprintf(fout, ",\"locale_id\":%d", re.locale_id);
  }
  if (re.eoln_type > 0) {
    fprintf(fout, ",\"eoln_type\":%d", re.eoln_type);
  }
  if (re.mime_type) {
    fprintf(fout, ",\"mime_type\":\"%s\"", mime_type_get_type(re.mime_type));
  }
  fprintf(fout, ",\"size\":%lld", (long long) re.size);
  if (re.store_flags) {
    fprintf(fout, ",\"store_flags\":%d", re.store_flags);
  }
  if (re.is_imported) {
    fprintf(fout, ",\"is_imported\":%s", to_json_bool(re.is_imported));
  }
  if (re.is_hidden) {
    fprintf(fout, ",\"is_hidden\":%s", to_json_bool(re.is_hidden));
  }
  if (re.is_readonly) {
    fprintf(fout, ",\"is_readonly\":%s", to_json_bool(re.is_readonly));
  }
  if (re.passed_mode) {
    fprintf(fout, ",\"passed_mode\":%d", re.passed_mode);
  }
  if (re.score >= 0) {
    fprintf(fout, ",\"raw_score\":%d", re.score);
  }
  if (re.test >= 0) {
    fprintf(fout, ",\"raw_test\":%d", re.test);
  }
  if (re.is_marked) {
    fprintf(fout, ",\"is_marked\":%s", to_json_bool(re.is_marked));
  }
  if (re.score_adj != 0) {
    fprintf(fout, ",\"score_adj\":%d", re.score_adj);
  }
  if (re.judge_uuid_flag) {
    if (ej_uuid_is_nonempty(re.j.judge_uuid)) {
      fprintf(fout, ",\"judge_uuid\":\"%s\"", ej_uuid_unparse(&re.j.judge_uuid, ""));
    }
  } else if (re.j.judge_id) {
    fprintf(fout, ",\"judge_id\":%d", re.j.judge_id);
  }
  if (re.pages) {
    fprintf(fout, ",\"pages\":%d", re.pages);
  }
  if (re.token_flags) {
    fprintf(fout, ",\"token_flags\":%d", re.token_flags);
  }
  if (re.token_count) {
    fprintf(fout, ",\"token_count\":%d", re.token_count);
  }
  if (re.is_saved) {
    fprintf(fout, ",\"is_saved\":%s", to_json_bool(re.is_saved));
    fprintf(fout, ",\"saved_status\":%d", re.saved_status);
    fprintf(fout, ",\"saved_status_str\":\"%s\"", run_status_short_str(re.saved_status));
    if (re.saved_score >= 0) {
      fprintf(fout, ",\"saved_score\":%d", re.saved_score);
    }
    if (re.saved_test >= 0) {
      fprintf(fout, ",\"saved_test\":%d", re.saved_test);
    }
  }
  if (re.is_checked) {
    fprintf(fout, ",\"is_checked\":true");
  }
  if (re.is_vcs) {
    fprintf(fout, ",\"is_vcs\":true");
  }
  if (re.verdict_bits) {
    fprintf(fout, ",\"verdict_bits\":%u", re.verdict_bits);
  }
  if (re.last_change_us > 0) {
    fprintf(fout, ",\"last_change_us\":%lld", re.last_change_us);
  }
  if (re.notify_driver > 0
      && re.notify_kind > 0 && re.notify_kind < MIXED_ID_LAST) {
    unsigned char mbuf[64];
    fprintf(fout, ",\"notify_driver\":%d", re.notify_driver);
    fprintf(fout, ",\"notify_kind\":\"%s\"",
            mixed_id_unparse_kind(re.notify_kind));
    fprintf(fout, ",\"notify_queue\":\"%s\"",
            JARMOR(mixed_id_marshall(mbuf, re.notify_kind, &re.notify_queue)));
  }

  fprintf(fout, "}");
  fprintf(fout, "}");
  fprintf(fout, "}\n");

cleanup:
  ;
  html_armor_free(&ab);
}

static void
priv_raw_audit_log(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const unsigned char *s;
  ej_uuid_t run_uuid;
  int run_id = -1;
  struct run_entry re;

  int rep_flag;
  path_t audit_log_path;
  struct stat stb;
  char *audit_text = 0;
  size_t audit_text_size = 0;

  phr->json_reply = 0;

  if (hr_cgi_param(phr, "run_uuid", &s) > 0) {
    if (ej_uuid_parse(s, &run_uuid) < 0) {
      error_page(fout, phr, 1, NEW_SRV_ERR_INV_UUID);
      goto cleanup;
    }
    if ((run_id = run_find_run_id_by_uuid(cs->runlog_state, &run_uuid)) < 0) {
      error_page(fout, phr, 1, NEW_SRV_ERR_INV_UUID);
      goto cleanup;
    }
  } else if (hr_cgi_param_int(phr, "run_id", &run_id) >= 0) {
  } else {
    error_page(fout, phr, 1, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }

  if (run_id < 0 || run_id >= run_get_total(cs->runlog_state)) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  if (run_get_entry(cs->runlog_state, run_id, &re) < 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  if ((rep_flag = serve_make_audit_read_path(cs, audit_log_path, sizeof(audit_log_path), &re)) < 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_AUDIT_LOG_NONEXISTANT);
    goto cleanup;
  }
  if (lstat(audit_log_path, &stb) < 0 || !S_ISREG(stb.st_mode)) {
    error_page(fout, phr, 0, NEW_SRV_ERR_AUDIT_LOG_NONEXISTANT);
    goto cleanup;
  }
  if (generic_read_file(&audit_text, 0, &audit_text_size, 0, 0, audit_log_path, 0) < 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_DISK_READ_ERROR);
    goto cleanup;
  }

  fprintf(fout, "Content-type: text/plain\n\n");
  if (audit_text_size > 0) {
    fwrite(audit_text, 1, audit_text_size, fout);
  }

cleanup:
  ;
  xfree(audit_text);
}

static void
priv_raw_report(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const unsigned char *s;
  ej_uuid_t run_uuid;
  int run_id = -1;
  struct run_entry re;
  path_t rep_path;
  int rep_flag;
  char *rep_text = NULL;
  size_t rep_len = 0;
  int content_type = 0;
  const unsigned char *start_ptr = NULL;

  phr->json_reply = 1;

  if (opcaps_check(phr->caps, OPCAP_VIEW_REPORT) < 0) {
    error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  if (hr_cgi_param(phr, "run_uuid", &s) > 0) {
    if (ej_uuid_parse(s, &run_uuid) < 0) {
      error_page(fout, phr, 1, NEW_SRV_ERR_INV_UUID);
      goto cleanup;
    }
    if ((run_id = run_find_run_id_by_uuid(cs->runlog_state, &run_uuid)) < 0) {
      error_page(fout, phr, 1, NEW_SRV_ERR_INV_UUID);
      goto cleanup;
    }
  } else if (hr_cgi_param_int(phr, "run_id", &run_id) >= 0) {
  } else {
    error_page(fout, phr, 1, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }

  if (run_id < 0 || run_id >= run_get_total(cs->runlog_state)) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  if (run_get_entry(cs->runlog_state, run_id, &re) < 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  if (!run_is_normal_status(re.status)) {
    error_page(fout, phr, 0, NEW_SRV_ERR_REPORT_UNAVAILABLE);
    goto cleanup;
  }
  if (!run_is_report_available(re.status)) {
    error_page(fout, phr, 0, NEW_SRV_ERR_REPORT_UNAVAILABLE);
    goto cleanup;
  }

  rep_flag = serve_make_xml_report_read_path(cs, rep_path, sizeof(rep_path), &re);
  if (rep_flag >= 0) {
    if (re.store_flags == STORE_FLAGS_UUID_BSON) {
      if (generic_read_file(&rep_text, 0, &rep_len, rep_flag, 0, rep_path, 0) < 0) {
        error_page(fout, phr, 0, NEW_SRV_ERR_DISK_READ_ERROR);
        goto cleanup;
      }
      content_type = CONTENT_TYPE_BSON;
    } else {
      if (generic_read_file(&rep_text, 0, &rep_len, rep_flag, 0, rep_path, 0) < 0) {
        error_page(fout, phr, 0, NEW_SRV_ERR_DISK_READ_ERROR);
        goto cleanup;
      }
      content_type = get_content_type(rep_text, &start_ptr);
    }
  } else {
    rep_flag = serve_make_report_read_path(cs, rep_path, sizeof(rep_path), &re);
    if (rep_flag < 0) {
      error_page(fout, phr, 0, NEW_SRV_ERR_REPORT_NONEXISTANT);
      goto cleanup;
    }
    if (generic_read_file(&rep_text, 0, &rep_len, rep_flag, 0, rep_path, 0) < 0) {
      error_page(fout, phr, 0, NEW_SRV_ERR_DISK_READ_ERROR);
      goto cleanup;
    }
    content_type = get_content_type(rep_text, &start_ptr);
  }

  phr->json_reply = 0;
  if (content_type == CONTENT_TYPE_BSON) {
    fprintf(fout, "Content-type: application/bson\n"
            "Content-length: %zu\n\n", rep_len);
    fwrite(rep_text, 1, rep_len, fout);
  } else if (content_type == CONTENT_TYPE_XML) {
    fprintf(fout, "Content-type: application/xml\n"
            "\n%s", start_ptr);
  } else if (content_type == CONTENT_TYPE_HTML) {
    fprintf(fout, "Content-type: text/html\n"
            "\n%s", start_ptr);
  } else if (content_type == CONTENT_TYPE_TEXT) {
    fprintf(fout, "Content-type: text/plain\n"
            "\n%s", start_ptr);
  } else {
    fprintf(fout, "Content-type: application/octet-stream\n"
            "Content-length: %zu\n\n", rep_len);
    fwrite(rep_text, 1, rep_len, fout);
  }

cleanup:
  ;
  xfree(rep_text);
}

static void
priv_contest_status_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  phr->json_reply = 1;
  int ok = 1;
  serve_state_t cs = extra->serve_state;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const struct section_global_data *global = cs->global;
  time_t duration = 0, sched_time = 0, finish_time = 0, start_time = 0, stop_time = 0;
  time_t fog_start_time = 0, fog_stop_time = 0;
  time_t server_start_time = nsf_get_server_start_time(phr->fw_state);
  int online_users = 0;

  run_get_times(cs->runlog_state, 0, 0, &sched_time, &duration, 0, &finish_time);
  start_time = run_get_start_time(cs->runlog_state);
  stop_time = run_get_stop_time(cs->runlog_state, 0, 0);

  if (duration > 0 && global->is_virtual <= 0 && start_time > 0 && global->board_fog_time > 0) {
    if (stop_time <= 0) {
      fog_start_time = start_time + duration - global->board_fog_time;
      if (fog_start_time < start_time) fog_start_time = start_time;
    }
    if (stop_time > 0 && global->board_unfog_time > 0) {
      fog_stop_time = stop_time + global->board_unfog_time;
    }
  }

  for (int i = 0; i < extra->user_access[USER_ROLE_CONTESTANT].u; i++) {
    struct last_access_info *pa = &extra->user_access[USER_ROLE_CONTESTANT].v[i];
    if (pa->time + 65 >= cs->current_time) online_users++;
  }

  fprintf(fout, "{\n");
  fprintf(fout, "  \"ok\" : %s", to_json_bool(ok));
  fprintf(fout, ",\n  \"server_time\": %lld", (long long) cs->current_time);
  fprintf(fout, ",\n  \"result\": {");
  fprintf(fout, "\n    \"contest\": {");
  fprintf(fout, "\n      \"id\": %d", cnts->id);
  fprintf(fout, ",\n      \"name\": \"%s\"", json_armor_buf(&ab, cnts->name));
  if (cnts->name_en && cnts->name_en[0]) {
    fprintf(fout, ",\n      \"name_en\": \"%s\"", json_armor_buf(&ab, cnts->name_en));
  }
  fprintf(fout, ",\n      \"server_start_time\": %lld", (long long) server_start_time);
  fprintf(fout, ",\n      \"contest_load_time\": %lld", (long long) cs->load_time);
  fprintf(fout, ",\n      \"score_system\": %d", global->score_system);
  if (global->enable_continue) {
    fprintf(fout, ",\n      \"is_continue_enabled\": %s", to_json_bool(1));
  }
  if (global->is_virtual) {
    fprintf(fout, ",\n      \"is_virtual\": %s", to_json_bool(global->is_virtual));
  }
  if (duration <= 0) {
    fprintf(fout, ",\n      \"is_unlimited\": %s", to_json_bool(duration <= 0));
  }
  if (duration > 0) {
    fprintf(fout, ",\n      \"duration\": %lld", (long long) duration);
    if (global->board_fog_time > 0) {
      fprintf(fout, ",\n      \"board_fog_duration\": %lld", (long long) global->board_fog_time);
      if (global->board_unfog_time > 0) {
        fprintf(fout, ",\n      \"board_unfog_duration\": %lld", (long long) global->board_unfog_time);
      }
    }
  }
  if (global->is_virtual > 0 && global->enable_virtual_restart > 0) {
    fprintf(fout, ",\n      \"is_restartable\": %s", to_json_bool(global->enable_virtual_restart));
  }
  if (cs->upsolving_mode > 0) {
    fprintf(fout, ",\n      \"is_upsolving\": %s", to_json_bool(cs->upsolving_mode));
  }
  if (start_time > 0) {
    fprintf(fout, ",\n      \"is_started\": %s", to_json_bool(start_time > 0));
  }
  if (cs->clients_suspended) {
    fprintf(fout, ",\n      \"is_clients_suspended\": %s", to_json_bool(cs->clients_suspended));
  }
  if (cs->testing_suspended) {
    fprintf(fout, ",\n      \"is_testing_suspended\": %s", to_json_bool(cs->testing_suspended));
  }
  if (global->enable_printing && cs->printing_suspended) {
    fprintf(fout, ",\n      \"is_printing_suspended\": %s", to_json_bool(cs->printing_suspended));
  }
  if (cs->online_view_source < 0) {
    fprintf(fout, ",\n      \"is_source_closed\": %s", to_json_bool(1));
  } else if (cs->online_view_source > 0) {
    fprintf(fout, ",\n      \"is_source_open\": %s", to_json_bool(1));
  }
  if (cs->online_view_report < 0) {
    fprintf(fout, ",\n      \"is_report_closed\": %s", to_json_bool(1));
  } else if (cs->online_view_report > 0) {
    fprintf(fout, ",\n      \"is_report_open\": %s", to_json_bool(1));
  }
  if (cs->online_view_judge_score > 0) {
    fprintf(fout, ",\n      \"is_judge_score\": %s", to_json_bool(1));
  }
  if (cs->online_final_visibility > 0) {
    fprintf(fout, ",\n      \"is_final_visibility\": %s", to_json_bool(1));
  }
  if (cs->online_valuer_judge_comments > 0) {
    fprintf(fout, ",\n      \"is_valuer_judge_comments\": %s", to_json_bool(1));
  }
  if (start_time > 0) {
    fprintf(fout, ",\n      \"start_time\": %lld", (long long) start_time);
    if (global->score_system == SCORE_OLYMPIAD && !global->is_virtual) {
      if (cs->accepting_mode) {
        fprintf(fout, ",\n      \"is_olympiad_accepting_mode\": %s", to_json_bool(cs->accepting_mode));
      }
      if (cs->testing_finished) {
        fprintf(fout, ",\n      \"is_testing_finished\": %s", to_json_bool(cs->testing_finished));
      }
    }
    if (stop_time > 0) {
      fprintf(fout, ",\n      \"is_stopped\": %s", to_json_bool(stop_time > 0));
      fprintf(fout, ",\n      \"stop_time\": %lld", (long long) stop_time);
      if (fog_stop_time > 0) {
        fprintf(fout, ",\n      \"is_freezable\": %s", to_json_bool(1));
        fprintf(fout, ",\n      \"unfreeze_time\": %lld", (long long) fog_stop_time);
        if (cs->standings_updated) {
          fprintf(fout, ",\n      \"is_standings_updated\": %s", to_json_bool(1));
        } else if (cs->current_time < fog_stop_time) {
          fprintf(fout, ",\n      \"is_frozen\": %s", to_json_bool(1));
        }
      }
    } else {
      if (fog_start_time > 0) {
        fprintf(fout, ",\n      \"is_freezable\": %s", to_json_bool(1));
        fprintf(fout, ",\n      \"freeze_time\": %lld", (long long) fog_start_time);
        if (cs->current_time >= fog_start_time) {
          fprintf(fout, ",\n      \"is_frozen\": %s", to_json_bool(1));
        }
      }
      if (duration > 0) {
        fprintf(fout, ",\n      \"expected_stop_time\": %lld", (long long) (start_time + duration));
      } else if (finish_time > 0) {
        fprintf(fout, ",\n      \"scheduled_finish_time\": %lld", (long long) finish_time);
      }
    }
  } else {
    // not started yet
    if (global->is_virtual > 0) {
      if (cnts->open_time > 0) {
        fprintf(fout, ",\n      \"open_time\": %lld", (long long) cnts->open_time);
      }
      if (cnts->close_time > 0) {
        fprintf(fout, ",\n      \"close_time\": %lld", (long long) cnts->close_time);
      }
    } else if (sched_time > 0) {
      fprintf(fout, ",\n      \"scheduled_start_time\": %lld", (long long) sched_time);
    }
  }
  fprintf(fout, "\n    }");

  fprintf(fout, ",\n    \"online\": {");
  fprintf(fout, "\n      \"user_count\": %d", online_users);
  fprintf(fout, ",\n      \"max_user_count\": %d", cs->max_online_count);
  fprintf(fout, ",\n      \"max_time\": %lld", (long long) cs->max_online_time);
  fprintf(fout, "\n    }");
  fprintf(fout, "\n  }");
  fprintf(fout, "\n}\n");

  html_armor_free(&ab);
}

static void
parse_error_func(void *data, unsigned char const *format, ...)
{
  filter_expr_nerrs++;
}

#define BITS_PER_LONG (8*sizeof(unsigned long))

static char const base64u_encode_table[]=
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void
encode_displayed_mask(FILE *outf, int displayed_size, const unsigned long *displayed_mask)
{
  if (!displayed_mask || displayed_size <= 0) {
    return;
  }

  fprintf(outf, "%d", (int) sizeof(unsigned long));
  const unsigned long *ptr = displayed_mask;
  int len = displayed_size;
  while (len > 0) {
    int zcnt = 0;
    while (zcnt < len && !ptr[zcnt]) ++zcnt;
    while (zcnt > 0) {
      // ,.:;
      unsigned zval = zcnt - 1;
      int zproc = 1;
      if (zval < 64) {
        putc_unlocked(',', outf);
        putc_unlocked(base64u_encode_table[zval], outf);
        zproc += zval;
      } else {
        zval -= 64;
        zproc += 64;
        if (zval < 64 * 64) {
          putc_unlocked('.', outf);
          putc_unlocked(base64u_encode_table[(zval >> 6) & 63], outf);
          putc_unlocked(base64u_encode_table[zval & 63], outf);
          zproc += zval;
        } else {
          zval -= 64 * 64;
          zproc += 64 * 64;
          if (zval < 64 * 64 * 64) {
            putc_unlocked(':', outf);
            putc_unlocked(base64u_encode_table[(zval >> 12) & 63], outf);
            putc_unlocked(base64u_encode_table[(zval >> 6) & 63], outf);
            putc_unlocked(base64u_encode_table[zval & 63], outf);
            zproc += zval;
          } else {
            zval -= 64 * 64 * 64;
            zproc += 64 * 64 * 64;
            if (zval >= 64 * 64 * 64 * 64) {
              zval = 64 * 64 * 64 * 64 - 1;
            }
            putc_unlocked(';', outf);
            putc_unlocked(base64u_encode_table[(zval >> 18) & 63], outf);
            putc_unlocked(base64u_encode_table[(zval >> 12) & 63], outf);
            putc_unlocked(base64u_encode_table[(zval >> 6) & 63], outf);
            putc_unlocked(base64u_encode_table[zval & 63], outf);
            zproc += zval;
          }
        }
      }
      len -= zproc;
      zcnt -= zproc;
      ptr += zproc;
    }
    if (len <= 0) break;
    int vcnt = 0;
    while (vcnt < len && ptr[vcnt]) ++vcnt;
    if (vcnt > 0) {
      base64u_encode_f((const char *) ptr, vcnt * sizeof(unsigned long), outf);
      len -= vcnt;
    }
  }
}

static void
priv_list_runs_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const unsigned char *filter_expr = NULL;
  int first_run_set = 0, last_run_set = 0, field_mask_set = 0;
  int first_run = 0, last_run = 0;
  long long field_mask = 0;
  int intval, r;
  struct user_filter_info *u = NULL;
  long long run_fields = RUN_VIEW_DEFAULT;
  int *match_idx = NULL;
  int match_tot = 0;
  int transient_tot = 0;
  int *list_idx = NULL;
  int list_tot = 0;
  unsigned long *displayed_mask = NULL;
  int displayed_size = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct filter_env env;
  const unsigned char *s = NULL;

  phr->json_reply = 1;
  memset(&env, 0, sizeof(env));

  if (hr_cgi_param(phr, "filter_expr", &filter_expr) < 0) {
    goto err_inv_param;
  }
  if ((r = hr_cgi_param_int_2(phr, "first_run", &intval)) < 0) {
    goto err_inv_param;
  } else if (r > 0) {
    first_run = intval;
    first_run_set = 1;
  }
  if ((r = hr_cgi_param_int_2(phr, "last_run", &intval)) < 0) {
    goto err_inv_param;
  } else if (r > 0) {
    last_run = intval;
    last_run_set = 1;
  }
  if ((r = hr_cgi_param(phr, "field_mask", &s)) < 0) {
    goto err_inv_param;
  } else if (r > 0 && s) {
    char *eptr = NULL;
    errno = 0;
    field_mask = strtoll(s, &eptr, 10);
    if (errno || *eptr || eptr == (char*) s || field_mask < 0) {
      goto err_inv_param;
    }
    field_mask_set = 1;
  }
  if (field_mask_set) {
    run_fields = field_mask;
  }

  XCALLOC(u, 1);
  if (filter_expr && *filter_expr) {
    u->prev_filter_expr = xstrdup(filter_expr);
    u->tree_mem = filter_tree_new();
    filter_expr_set_string(filter_expr, u->tree_mem, parse_error_func, cs);
    filter_expr_init_parser(u->tree_mem, parse_error_func, cs);
    r = filter_expr_parse();
    if (r + filter_expr_nerrs == 0 && filter_expr_lval && filter_expr_lval->type == FILTER_TYPE_BOOL && !u->error_msgs) {
      u->prev_tree = filter_expr_lval;
    } else {
      error_page(fout, phr, 0, NEW_SRV_ERR_INV_FILTER_EXPR);
      goto cleanup;
    }
  }

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

  displayed_size = (env.rtotal + BITS_PER_LONG - 1) / BITS_PER_LONG;
  if (!displayed_size) displayed_size = 1;
  XCALLOC(displayed_mask, displayed_size);

  XCALLOC(match_idx, env.rtotal + 1 - env.rbegin);
  XCALLOC(list_idx, (env.rtotal + 1 - env.rbegin));
  match_tot = 0;
  transient_tot = 0;

  for (int i = env.rbegin; i < env.rtotal; ++i) {
    if (env.rentries[i].status >= RUN_TRANSIENT_FIRST && env.rentries[i].status <= RUN_TRANSIENT_LAST) {
      transient_tot++;
    }
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
    for (int i = first_run; i <= last_run && i < match_tot; i++) {
      list_idx[list_tot++] = match_idx[i];
    }
  } else {
    for (int i = first_run; i >= last_run; i--) {
      list_idx[list_tot++] = match_idx[i];
    }
  }

  fprintf(fout, "{");
  fprintf(fout, "\"ok\":%s", to_json_bool(1));
  fprintf(fout, ",\"server_time\":%lld", (long long) cs->current_time);
  fprintf(fout, ",\"result\":{");
  fprintf(fout, "\"total_runs\":%d", env.rtotal);
  fprintf(fout, ",\"filtered_runs\":%d", match_tot);
  fprintf(fout, ",\"listed_runs\":%d", list_tot);
  fprintf(fout, ",\"transient_runs\":%d", transient_tot);
  if (filter_expr && filter_expr[0]) {
    fprintf(fout, ",\"filter_expr\":\"%s\"", JARMOR(filter_expr));
  }
  fprintf(fout, ",\"first_run\":%d", first_run);
  fprintf(fout, ",\"last_run\":%d", last_run);
  fprintf(fout, ",\"field_mask\":%llu", (unsigned long long) run_fields);
  fprintf(fout, ",\"runs\":[");

  for (int i = 0; i < list_tot; ++i) {
    int rid = list_idx[i];
    ASSERT(rid >= env.rbegin && rid < env.rtotal);
    const struct run_entry *pe = &env.rentries[rid];

    displayed_mask[rid / BITS_PER_LONG] |= (1L << (rid % BITS_PER_LONG));

    if (i > 0) {
      fprintf(fout, ",");
    }
    fprintf(fout, "{");
    fprintf(fout, "\"run_id\":%d", pe->run_id);
    fprintf(fout, ",\"serial_id\":%lld", (long long) pe->serial_id);
    fprintf(fout, ",\"last_change_us\":%lld", pe->last_change_us);
    if (run_fields & (1 << RUN_VIEW_STATUS)) {
      fprintf(fout, ",\"status\":%d", pe->status);
      fprintf(fout, ",\"status_str\":\"%s\"", run_status_short_str(pe->status));
    }
    if (pe->status != RUN_EMPTY) {
      long long run_time_us = pe->time * 1000000LL + pe->nsec / 1000;
      long long duration = 0;
      if (env.rhead.start_time > 0 && pe->time >= env.rhead.start_time) {
        duration = (long long) pe->time - env.rhead.start_time;
      }
      if ((run_fields & ((1 << RUN_VIEW_TIME) | (1 << RUN_VIEW_ABS_TIME)))) {
        fprintf(fout, ",\"run_time\":%lld", (long long) pe->time);
        fprintf(fout, ",\"run_time_us\":%lld", run_time_us);
      }
      if (run_fields & (1 << RUN_VIEW_NSEC)) {
        fprintf(fout, ",\"nsec\":%d", pe->nsec);
      }
      if ((run_fields & (1 << RUN_VIEW_REL_TIME)) && duration > 0) {
        fprintf(fout, ",\"duration\":%lld", duration);
      }
      if ((run_fields & (1 << RUN_VIEW_USER_ID))) {
        fprintf(fout, ",\"user_id\":%d", pe->user_id);
      }
      if ((run_fields & (1 << RUN_VIEW_USER_LOGIN))) {
        const unsigned char *s = teamdb_get_login(cs->teamdb_state, pe->user_id);
        if (s && *s) {
          fprintf(fout, ",\"user_login\":\"%s\"", JARMOR(s));
        }
      }
      if ((run_fields & (1 << RUN_VIEW_USER_NAME))) {
        const unsigned char *s = teamdb_get_name(cs->teamdb_state, pe->user_id);
        if (s && *s) {
          fprintf(fout, ",\"user_name\":\"%s\"", JARMOR(s));
        }
      }
      if ((run_fields & (1 << RUN_VIEW_EXT_USER))) {
        if (pe->ext_user_kind > 0 && pe->ext_user_kind < MIXED_ID_LAST) {
          unsigned char mbuf[64];
          fprintf(fout, ",\"ext_user_kind\":\"%s\"",
                  mixed_id_unparse_kind(pe->ext_user_kind));
          fprintf(fout, ",\"ext_user\":\"%s\"",
                  JARMOR(mixed_id_marshall(mbuf, pe->ext_user_kind, &pe->ext_user)));
        }
      }
      if ((run_fields & (1 << RUN_VIEW_NOTIFY))) {
        if (pe->notify_driver > 0
            && pe->notify_kind > 0 && pe->notify_kind < MIXED_ID_LAST) {
          unsigned char mbuf[64];
          fprintf(fout, ",\"notify_driver\":%d", pe->notify_driver);
          fprintf(fout, ",\"notify_kind\":\"%s\"",
                  mixed_id_unparse_kind(pe->notify_kind));
          fprintf(fout, ",\"notify_queue\":\"%s\"",
                  JARMOR(mixed_id_marshall(mbuf, pe->notify_kind, &pe->notify_queue)));
        }
      }
      if (pe->status == RUN_VIRTUAL_START || pe->status == RUN_VIRTUAL_STOP) {
        if (pe->is_checked > 0) {
          fprintf(fout, ",\"is_examinable\":%s", to_json_bool(1));
        }
      } else {
        const struct section_problem_data *prob = NULL;
        if (pe->prob_id > 0 && pe->prob_id <= cs->max_prob) {
          prob = cs->probs[pe->prob_id];
        }
        const struct section_language_data *lang = NULL;
        if (pe->lang_id > 0 && pe->lang_id <= cs->max_lang) {
          lang = cs->langs[pe->lang_id];
        }
        int prev_successes = RUN_TOO_MANY;
        if (global->score_system == SCORE_KIROV && pe->status == RUN_OK && prob && prob->score_bonus_total > 0) {
          if ((prev_successes = run_get_prev_successes(cs->runlog_state, rid)) < 0)
            prev_successes = RUN_TOO_MANY;
        }

        time_t effective_time = 0, *p_eff_time = NULL;
        if (prob && prob->enable_submit_after_reject > 0)
          p_eff_time = &effective_time;

        int attempts = 0, disq_attempts = 0, ce_attempts = 0;
        if (global->score_system == SCORE_KIROV && !pe->is_hidden) {
          int ice = 0, cep = -1;
          if (prob) {
            ice = prob->ignore_compile_errors;
            cep = prob->compile_error_penalty;
          }
          run_get_attempts(cs->runlog_state, rid, &attempts, &disq_attempts, &ce_attempts, p_eff_time, ice, cep);
        }

        if (pe->is_imported > 0) {
          fprintf(fout, ",\"is_imported\":%s", to_json_bool(1));
        }
        if (pe->is_hidden > 0) {
          fprintf(fout, ",\"is_hidden\":%s", to_json_bool(1));
        }
        if (pe->is_marked > 0) {
          fprintf(fout, ",\"is_marked\":%s", to_json_bool(1));
        }
        if (pe->is_saved > 0) {
          fprintf(fout, ",\"is_saved\":%s", to_json_bool(1));
        }
        if ((run_fields & (1 << RUN_VIEW_RUN_UUID)) && ej_uuid_is_nonempty(pe->run_uuid)) {
          fprintf(fout, ",\"run_uuid\":\"%s\"", ej_uuid_unparse(&pe->run_uuid, ""));
        }
        if ((run_fields & (1 << RUN_VIEW_STORE_FLAGS)) && pe->store_flags) {
          fprintf(fout, ",\"store_flags\":%d", pe->store_flags);
        }
        if (run_fields & (1 << RUN_VIEW_SIZE)) {
          fprintf(fout, ",\"size\":%u", pe->size);
        }
        if ((run_fields & (1 << RUN_VIEW_MIME_TYPE)) && pe->lang_id <= 0) {
          fprintf(fout, ",\"mime_type\":\"%s\"", mime_type_get_type(pe->mime_type));
        }
        if (run_fields & (1 << RUN_VIEW_IP)) {
          fprintf(fout, ",\"ip\":\"%s\"", xml_unparse_ip(pe->a.ip));
          fprintf(fout, ",\"ssl_flag\":%d", pe->ssl_flag);
        }
        if (run_fields & (1 << RUN_VIEW_SHA1)) {
          fprintf(fout, ",\"sha1\":\"%s\"", unparse_sha1(pe->h.sha1));
        }
        if (run_fields & (1 << RUN_VIEW_PROB_ID)) {
          fprintf(fout, ",\"prob_id\":%d", pe->prob_id);
        }
        int variant = 0;
        if (prob && prob->variant_num > 0) {
          variant = pe->variant;
          if (variant <= 0) {
            variant = find_variant(cs, pe->user_id, pe->prob_id, 0);
          }
          if (run_fields & (1 << RUN_VIEW_VARIANT)) {
            if (pe->variant > 0) {
              fprintf(fout, ",\"raw_variant\":%d", pe->variant);
            }
            if (variant > 0) {
              fprintf(fout, ",\"variant\":%d", variant);
            }
          }
        }
        if ((run_fields & (1 << RUN_VIEW_PROB_NAME)) && prob) {
          if (/*prob->short_name &&*/ prob->short_name[0]) {
            fprintf(fout, ",\"prob_name\":\"%s\"", JARMOR(prob->short_name));
          }
          if (prob->internal_name && prob->internal_name[0]) {
            fprintf(fout, ",\"prob_internal_name\":\"%s\"", JARMOR(prob->internal_name));
          }
          if (prob->uuid && prob->uuid[0]) {
            fprintf(fout, ",\"prob_uuid\":\"%s\"", JARMOR(prob->uuid));
          }
        }
        if (run_fields & (1 << RUN_VIEW_LANG_ID)) {
          fprintf(fout, ",\"lang_id\":%d", pe->lang_id);
        }
        if ((run_fields & (1 << RUN_VIEW_LANG_NAME)) && lang) {
          if (/*lang->short_name &&*/ lang->short_name[0]) {
            fprintf(fout, ",\"lang_name\":\"%s\"", JARMOR(lang->short_name));
          }
        }
        if (run_fields & (1 << RUN_VIEW_EOLN_TYPE)) {
          fprintf(fout, ",\"eoln_type\":%d", pe->eoln_type);
        }
        if (run_fields & (1 << RUN_VIEW_TOKENS)) {
          if (pe->token_flags) {
            fprintf(fout, ",\"token_flags\":%d", pe->token_flags);
          }
          if (pe->token_count) {
            fprintf(fout, ",\"token_count\":%d", pe->token_count);
          }
        }
        if (run_fields & (1 << RUN_VIEW_VERDICT_BITS)) {
          if (pe->verdict_bits) {
            fprintf(fout, ",\"verdict_bits\":%u", pe->verdict_bits);
          }
        }

        write_json_run_status(cs, fout, env.rhead.start_time, pe, 1, attempts, disq_attempts, ce_attempts, prev_successes,
                              0, run_fields, effective_time, "");

        if ((run_fields & (1 << RUN_VIEW_SCORE_ADJ)) && pe->score_adj != 0) {
          fprintf(fout, ",\"score_adj\":%d", pe->score_adj);
        }
        if ((run_fields & (1 << RUN_VIEW_SAVED_STATUS)) && pe->is_saved > 0) {
          fprintf(fout, ",\"is_saved\":%s", to_json_bool(pe->is_saved));
          fprintf(fout, ",\"saved_status\":%d", pe->saved_status);
          fprintf(fout, ",\"saved_status_str\":\"%s\"", run_status_short_str(pe->saved_status));
        }
        if ((run_fields & (1 << RUN_VIEW_SAVED_SCORE)) && pe->is_saved > 0 && pe->saved_score >= 0) {
          fprintf(fout, ",\"saved_score\":%d", pe->saved_score);
        }
        if ((run_fields & (1 << RUN_VIEW_SAVED_TEST)) && pe->is_saved > 0 && pe->saved_test >= 0) {
          fprintf(fout, ",\"saved_test\":%d", pe->saved_test);
        }
      }
    }
    fprintf(fout, "}");
  }

  fprintf(fout, "]");
  if (displayed_size > 0) {
    fprintf(fout, ",\"displayed_size\":%d", displayed_size);
    fprintf(fout, ",\"displayed_mask\":\"");
    encode_displayed_mask(fout, displayed_size, displayed_mask);
    fprintf(fout, "\"");
  }
  fprintf(fout, "}");
  fprintf(fout, "}\n");

cleanup:
  ;
  if (u) {
      xfree(u->prev_filter_expr);
      xfree(u->error_msgs);
      filter_tree_delete(u->tree_mem);
      serve_state_destroy_stand_expr(u);
      xfree(u);
  }
  xfree(match_idx);
  xfree(list_idx);
  xfree(displayed_mask);
  html_armor_free(&ab);
  return;

  // error handlers
err_inv_param:
  error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
  goto cleanup;
}

static void
ns_submit_run_input(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int admin_mode);

static void
priv_submit_run_input(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  ns_submit_run_input(fout, phr, cnts, extra, 1);
}

static void
ns_get_submit(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int admin_mode);

static void
priv_get_submit(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  ns_get_submit(fout, phr, cnts, extra, 1);
}

typedef PageInterface *(*external_action_handler_t)(void);

typedef int (*new_action_handler_t)(
        PageInterface *pg,
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr);

typedef void (*action_handler_t)(FILE *fout,
                                 struct http_request_info *phr,
                                 const struct contest_desc *cnts,
                                 struct contest_extra *extra);

static action_handler_t actions_table[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_USERS_REMOVE_REGISTRATIONS] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_SET_PENDING] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_SET_STATUS] = priv_generic_operation,
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
  [NEW_SRV_ACTION_USERS_CHANGE_FLAGS] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_ADD_BY_LOGIN] = priv_generic_operation,
  [NEW_SRV_ACTION_USERS_ADD_BY_USER_ID] = priv_generic_operation,
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
  [NEW_SRV_ACTION_CHANGE_FINISH_TIME] = priv_generic_operation,
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
  [NEW_SRV_ACTION_DOWNLOAD_RUN] = priv_generic_page,
  [NEW_SRV_ACTION_CHANGE_LANGUAGE] = priv_generic_operation,
  [NEW_SRV_ACTION_SUBMIT_RUN] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_SUBMIT_CLAR] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT] = priv_generic_operation,
  [NEW_SRV_ACTION_CLAR_REPLY] = priv_generic_operation,
  [NEW_SRV_ACTION_CLAR_REPLY_ALL] = priv_generic_operation,
  [NEW_SRV_ACTION_CLAR_REPLY_READ_PROBLEM] = priv_generic_operation,
  [NEW_SRV_ACTION_CLAR_REPLY_NO_COMMENTS] = priv_generic_operation,
  [NEW_SRV_ACTION_CLAR_REPLY_YES] = priv_generic_operation,
  [NEW_SRV_ACTION_CLAR_REPLY_NO] = priv_generic_operation,
  [NEW_SRV_ACTION_RELOAD_SERVER] = priv_generic_operation,
  [NEW_SRV_ACTION_RELOAD_SERVER_ALL] = priv_generic_operation,
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
  [NEW_SRV_ACTION_CHANGE_RUN_IS_MARKED] = priv_generic_operation,
  [NEW_SRV_ACTION_CHANGE_RUN_IS_SAVED] = priv_generic_operation,
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
  [NEW_SRV_ACTION_DOWNLOAD_ARCHIVE_1] = priv_generic_page,
  [NEW_SRV_ACTION_DOWNLOAD_ARCHIVE_2] = priv_generic_page,
  [NEW_SRV_ACTION_UPLOAD_RUNLOG_CSV_1] = priv_generic_page,
  [NEW_SRV_ACTION_UPLOAD_RUNLOG_CSV_2] = priv_generic_page, /// FIXME: do audit logging
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
  [NEW_SRV_ACTION_TOKENIZE_DISPLAYED_2] = priv_generic_operation,
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
  [NEW_SRV_ACTION_TOGGLE_PRIVILEGED] = priv_generic_operation,
  [NEW_SRV_ACTION_TOGGLE_REG_READONLY] = priv_generic_operation,
  [NEW_SRV_ACTION_USER_CHANGE_STATUS_2] = priv_generic_operation,
  [NEW_SRV_ACTION_VIEW_ONLINE_USERS] = priv_generic_page,
  [NEW_SRV_ACTION_PRINT_USER_PROTOCOL] = priv_generic_page,
  [NEW_SRV_ACTION_PRINT_USER_FULL_PROTOCOL] = priv_generic_page,
  [NEW_SRV_ACTION_PRINT_UFC_PROTOCOL] = priv_generic_page,
  [NEW_SRV_ACTION_FORCE_START_VIRTUAL] = priv_generic_operation,
  [NEW_SRV_ACTION_PRINT_SELECTED_USER_PROTOCOL] = priv_generic_page,
  [NEW_SRV_ACTION_PRINT_SELECTED_USER_FULL_PROTOCOL] = priv_generic_page,
  [NEW_SRV_ACTION_PRINT_SELECTED_UFC_PROTOCOL] = priv_generic_page,
  [NEW_SRV_ACTION_PRINT_PROBLEM_PROTOCOL] = priv_generic_page,
  [NEW_SRV_ACTION_ASSIGN_CYPHERS_2] = priv_generic_page,
  [NEW_SRV_ACTION_VIEW_EXAM_INFO] = priv_generic_page,
  [NEW_SRV_ACTION_GET_FILE] = priv_get_file,
  [NEW_SRV_ACTION_SET_PRIORITIES] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_IGNORE] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_OK] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_REJECT] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_SUBMIT_RUN_COMMENT_AND_SUMMON] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_SUBMIT_RUN_JUST_IGNORE] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_SUBMIT_RUN_JUST_OK] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_SUBMIT_RUN_JUST_SUMMON] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_OLD_SET_RUN_REJECTED] = priv_generic_operation,
  [NEW_SRV_ACTION_TESTING_DELETE] = priv_generic_operation,
  [NEW_SRV_ACTION_TESTING_UP] = priv_generic_operation,
  [NEW_SRV_ACTION_TESTING_DOWN] = priv_generic_operation,
  [NEW_SRV_ACTION_TESTING_DELETE_ALL] = priv_generic_operation,
  [NEW_SRV_ACTION_TESTING_UP_ALL] = priv_generic_operation,
  [NEW_SRV_ACTION_TESTING_DOWN_ALL] = priv_generic_operation,
  [NEW_SRV_ACTION_INVOKER_DELETE] = priv_generic_operation,
  [NEW_SRV_ACTION_INVOKER_STOP] = priv_generic_operation,
  [NEW_SRV_ACTION_INVOKER_DOWN] = priv_generic_operation,
  [NEW_SRV_ACTION_MARK_DISPLAYED_2] = priv_generic_operation,
  [NEW_SRV_ACTION_UNMARK_DISPLAYED_2] = priv_generic_operation,
  [NEW_SRV_ACTION_SET_STAND_FILTER] = priv_generic_operation,
  [NEW_SRV_ACTION_RESET_STAND_FILTER] = priv_generic_operation,
  [NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_SOURCE] = priv_generic_operation,
  [NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_REPORT] = priv_generic_operation,
  [NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VIEW_JUDGE_SCORE] = priv_generic_operation,
  [NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_FINAL_VISIBILITY] = priv_generic_operation,
  [NEW_SRV_ACTION_ADMIN_CHANGE_ONLINE_VALUER_JUDGE_COMMENTS] = priv_generic_operation,
  [NEW_SRV_ACTION_RELOAD_SERVER_2] = priv_reload_server_2,
  [NEW_SRV_ACTION_CHANGE_RUN_FIELDS] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_EDIT_CLAR_ACTION] = priv_generic_operation,
  [NEW_SRV_ACTION_PRIV_EDIT_RUN_ACTION] = priv_generic_operation, ///
  [NEW_SRV_ACTION_PING] = priv_generic_page,
  [NEW_SRV_ACTION_SUBMIT_RUN_BATCH] = priv_generic_page,
  [NEW_SRV_ACTION_GET_AVATAR] = priv_get_avatar,
  [NEW_SRV_ACTION_UPLOAD_AVATAR] = priv_upload_avatar,
  [NEW_SRV_ACTION_PRIV_REGENERATE_CONTENT] = priv_generic_operation,
  [NEW_SRV_ACTION_RELOAD_CONTEST_PAGES] = priv_generic_operation,
  [NEW_SRV_ACTION_RELOAD_ALL_CONTEST_PAGES] = priv_generic_operation,
  [NEW_SRV_ACTION_DELETE_AVATAR] = priv_generic_operation,
  [NEW_SRV_ACTION_CONFIRM_AVATAR] = priv_generic_operation,
  [NEW_SRV_ACTION_ENTER_CONTEST] = priv_enter_contest,
  [NEW_SRV_ACTION_LOCK_FILTER] = priv_generic_operation,
  [NEW_SRV_ACTION_CONTEST_STATUS_JSON] = priv_contest_status_json,
  /*
  [NEW_SRV_ACTION_PROBLEM_STATUS_JSON] = unpriv_problem_status_json,
  [NEW_SRV_ACTION_PROBLEM_STATEMENT_JSON] = unpriv_problem_statement_json,
  */
  [NEW_SRV_ACTION_LIST_RUNS_JSON] = priv_list_runs_json,
  /*
  [NEW_SRV_ACTION_RUN_MESSAGES_JSON] = unpriv_run_messages_json,
  [NEW_SRV_ACTION_RUN_TEST_JSON] = unpriv_run_test_json,
   */
  [NEW_SRV_ACTION_RUN_STATUS_JSON] = priv_run_status_json,
  [NEW_SRV_ACTION_RAW_AUDIT_LOG] = priv_raw_audit_log,
  [NEW_SRV_ACTION_RAW_REPORT] = priv_raw_report,
  [NEW_SRV_ACTION_ENABLE_VIRTUAL_START] = priv_generic_operation,
  [NEW_SRV_ACTION_DISABLE_VIRTUAL_START] = priv_generic_operation,
  [NEW_SRV_ACTION_SUBMIT_RUN_INPUT] = priv_submit_run_input,
  [NEW_SRV_ACTION_GET_SUBMIT] = priv_get_submit,
  [NEW_SRV_ACTION_COMPILER_OP] = priv_generic_operation,
  [NEW_SRV_ACTION_INVOKER_REBOOT] = priv_generic_operation,
  [NEW_SRV_ACTION_CLEAR_SESSION_CACHE] = priv_generic_operation,
};

static const unsigned char * const external_priv_action_names[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_MAIN_PAGE] = "priv_main_page",
  [NEW_SRV_ACTION_VIEW_USERS] = "priv_users_page",
  [NEW_SRV_ACTION_PRIV_USERS_VIEW] = "priv_priv_users_page",
  [NEW_SRV_ACTION_DOWNLOAD_ARCHIVE_1] = "priv_download_runs_confirmation_page",
  [NEW_SRV_ACTION_VIEW_CLAR] = "priv_clar_page",
  [NEW_SRV_ACTION_PRIV_EDIT_RUN_PAGE] = "priv_edit_run_page",
  [NEW_SRV_ACTION_VIEW_EXAM_INFO] = "priv_exam_info_page",
  [NEW_SRV_ACTION_VIEW_ONLINE_USERS] = "priv_online_users_page",
  [NEW_SRV_ACTION_VIEW_CNTS_PWDS] = "priv_passwords_page",
  [NEW_SRV_ACTION_VIEW_USER_IPS] = "priv_user_ips_page",
  [NEW_SRV_ACTION_VIEW_IP_USERS] = "priv_ip_users_page",
  [NEW_SRV_ACTION_PRIV_EDIT_CLAR_PAGE] = "priv_edit_clar_page",
  [NEW_SRV_ACTION_NEW_RUN_FORM] = "priv_new_run_page",
  [NEW_SRV_ACTION_VIEW_USER_INFO] = "priv_user_info_page",
  [NEW_SRV_ACTION_ADMIN_CONTEST_SETTINGS] = "priv_settings_page",
  [NEW_SRV_ACTION_PRIO_FORM] = "priv_priorities_page",
  [NEW_SRV_ACTION_VIEW_SOURCE] = "priv_source_page",
  [NEW_SRV_ACTION_STANDINGS] = "priv_standings_page",
  [NEW_SRV_ACTION_ASSIGN_CYPHERS_1] = "priv_assign_cyphers_page",
  [NEW_SRV_ACTION_PRIV_SUBMIT_PAGE] = "priv_submit_page",
  [NEW_SRV_ACTION_VIEW_AUDIT_LOG] = "priv_audit_log_page",
  [NEW_SRV_ACTION_UPSOLVING_CONFIG_1] = "priv_upsolving_page",
  [NEW_SRV_ACTION_VIEW_REPORT] = "priv_report_page",
  [NEW_SRV_ACTION_VIEW_TESTING_QUEUE] = "priv_testing_queue_page",
  [NEW_SRV_ACTION_LOGIN_PAGE] = "priv_login_page",
  [NEW_SRV_ACTION_TOKENIZE_DISPLAYED_1] = "priv_tokenize_displayed_1_page",
  [NEW_SRV_ACTION_RELOAD_STATEMENT] = "priv_reload_statement_action",
  [NEW_SRV_ACTION_ADD_REVIEW_COMMENT] = "priv_add_review_comment_action",
  [NEW_SRV_ACTION_VIEW_USERS_NEW_PAGE] = "priv_users_new_page",
  [NEW_SRV_ACTION_VIEW_USERS_NEW_AJAX] = "priv_users_new_ajax",
  [NEW_SRV_ACTION_CROP_AVATAR_PAGE] = "priv_crop_avatar_page",
  [NEW_SRV_ACTION_SAVE_CROPPED_AVATAR_AJAX] = "priv_save_cropped_avatar_ajax",
  [NEW_SRV_ACTION_LANGUAGE_STATS_PAGE] = "priv_language_stats_page",
  [NEW_SRV_ACTION_PROBLEM_STATS_PAGE] = "priv_problem_stats_page",
  [NEW_SRV_ACTION_API_KEYS_PAGE] = "priv_api_keys_page",
  [NEW_SRV_ACTION_CREATE_API_KEY] = "priv_create_api_key",
  [NEW_SRV_ACTION_DELETE_API_KEY] = "priv_delete_api_key",
  [NEW_SRV_ACTION_USER_RUN_HEADERS_PAGE] = "priv_user_run_headers_page",
  [NEW_SRV_ACTION_USER_RUN_HEADER_PAGE] = "priv_user_run_header_page",
  [NEW_SRV_ACTION_USER_RUN_HEADER_DELETE] = "priv_user_run_header_delete",
  [NEW_SRV_ACTION_USER_RUN_HEADER_CHANGE_DURATION] = "priv_user_run_header_change_duration",
  [NEW_SRV_ACTION_USER_RUN_HEADER_CLEAR_STOP_TIME] = "priv_user_run_header_clear_stop_time",
  [NEW_SRV_ACTION_SERVER_INFO_PAGE] = "priv_server_info_page",
};

static const int external_priv_action_aliases[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_VIEW_REG_PWDS] = NEW_SRV_ACTION_VIEW_CNTS_PWDS,
  [NEW_SRV_ACTION_VIEW_USER_REPORT] = NEW_SRV_ACTION_VIEW_REPORT,
  [NEW_SRV_ACTION_RELOAD_STATEMENT_ALL] = NEW_SRV_ACTION_RELOAD_STATEMENT,
};

static const unsigned char * const external_priv_error_names[NEW_SRV_ERR_LAST] =
{
  [NEW_SRV_ERR_UNKNOWN_ERROR] = "priv_error_unknown",
  [NEW_SRV_ERR_USERLIST_SERVER_DOWN] = "priv_error_userlist_server_down",
  [NEW_SRV_ERR_DISQUALIFIED] = "priv_error_disqualified",
  [NEW_SRV_ERR_INTERNAL] = "priv_error_internal",
  [NEW_SRV_ERR_INV_PARAM] = "priv_error_inv_param",
  [NEW_SRV_ERR_PERMISSION_DENIED] = "priv_error_no_perm",
  [NEW_SRV_ERR_OPERATION_FAILED] = "priv_error_oper_failed",
};

static ExternalActionState *external_priv_action_states[NEW_SRV_ACTION_LAST];
static ExternalActionState *external_priv_error_states[NEW_SRV_ERR_LAST];

static const unsigned char * const external_unpriv_error_names[NEW_SRV_ERR_LAST] =
{
  [NEW_SRV_ERR_UNKNOWN_ERROR] = "unpriv_error_unknown",
  [NEW_SRV_ERR_USERLIST_SERVER_DOWN] = "unpriv_error_userlist_server_down",
  [NEW_SRV_ERR_DISQUALIFIED] = "unpriv_error_disqualified",
  [NEW_SRV_ERR_REGISTRATION_INCOMPLETE] = "unpriv_error_registration_incomplete",
  [NEW_SRV_ERR_CNTS_UNAVAILABLE] = "unpriv_error_cnts_unavailable",
  [NEW_SRV_ERR_INTERNAL] = "unpriv_error_internal",
  [NEW_SRV_ERR_SERVICE_NOT_AVAILABLE] = "unpriv_error_service_not_available",
  [NEW_SRV_ERR_INV_PARAM] = "unpriv_error_inv_param",
  [NEW_SRV_ERR_PERMISSION_DENIED] = "unpriv_error_no_perm",
  [NEW_SRV_ERR_OPERATION_FAILED] = "unpriv_error_oper_failed",
};
static ExternalActionState *external_unpriv_action_states[NEW_SRV_ACTION_LAST];
static ExternalActionState *external_unpriv_error_states[NEW_SRV_ERR_LAST];

static unsigned char *
read_file_range(
        const unsigned char *path,
        long long begpos,
        long long endpos)
{
  FILE *f = NULL;
  unsigned char *str = NULL, *s;
  int count, c;

  if (begpos < 0 || endpos < 0 || begpos > endpos || (endpos - begpos) > 16777216LL) return NULL;
  count = endpos - begpos;
  if (!(f = fopen(path, "rb"))) return NULL;
  if (fseek(f, begpos, SEEK_SET) < 0) {
    fclose(f);
    return NULL;
  }
  s = str = xmalloc(count + 1);
  while ((c = getc(f)) != EOF && count) {
    *s++ = c;
    --count;
  }
  *s = 0;
  fclose(f); f = NULL;
  return str;
}

static void
json_error(
        FILE *fout,
        struct http_request_info *phr,
        struct html_armor_buffer *pab,
        int num,
        const unsigned char *log_msg);

static void
error_page(
        FILE *out_f,
        struct http_request_info *phr,
        int priv_mode,
        int error_code)
{
  const unsigned char * const * error_names = external_unpriv_error_names;
  ExternalActionState **error_states = external_unpriv_error_states;

  if (error_code < 0) error_code = -error_code;

  if (phr->json_reply) {
    struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
    if (phr->log_f) {
      fclose(phr->log_f); phr->log_f = 0;
    }
    if (phr->log_t) {
      unsigned char *ps = phr->log_t;
      for (;*ps; ++ps) {
        if (*ps < ' ') *ps = ' ';
      }
    }
    fprintf(out_f, "{\n");
    fprintf(out_f, "  \"ok\": %s", "false");
    fprintf(out_f, ",\n  \"server_time\": %lld", (long long) phr->current_time);
    json_error(out_f, phr, &ab, error_code, phr->log_t);
    fprintf(out_f, "\n}\n");
    free(phr->log_t); phr->log_t = NULL;
    html_armor_free(&ab);
    return;
  }

  if (phr->log_f) {
    fclose(phr->log_f); phr->log_f = 0;
  }

  if (phr->log_t && !*phr->log_t) {
    xfree(phr->log_t); phr->log_t = NULL; phr->log_z = 0;
  }

  if (error_code <= 0 || error_code >= NEW_SRV_ERR_LAST) error_code = NEW_SRV_ERR_UNKNOWN_ERROR;
  phr->error_code = error_code;

  if (priv_mode) {
    error_names = external_priv_error_names;
    error_states = external_priv_error_states;
  }

  const unsigned char *error_name = error_names[error_code];
  if (!error_name) error_name = error_names[NEW_SRV_ERR_UNKNOWN_ERROR];
  if (!error_name) {
    return ns_html_error(out_f, phr, priv_mode, error_code);
  }
  error_states[error_code] = external_action_load(error_states[error_code],
                                                  "csp/contests",
                                                  error_name,
                                                  "csp_get_",
                                                  NULL /* fixed_src_dir */,
                                                  phr->current_time,
                                                  0 /* contest_id */,
                                                  0 /* allow_fail */);
  if (!error_states[error_code] || !error_states[error_code]->action_handler) {
    return ns_html_error(out_f, phr, priv_mode, error_code);
  }
  PageInterface *pg = ((external_action_handler_t) error_states[error_code]->action_handler)();
  if (!pg) {
    return ns_html_error(out_f, phr, priv_mode, error_code);
  }

  snprintf(phr->content_type, sizeof(phr->content_type), "text/html; charset=%s", EJUDGE_CHARSET);
  pg->ops->render(pg, NULL, out_f, phr);
  xfree(phr->log_t); phr->log_t = NULL;
  phr->log_z = 0;
}

static int
priv_external_action(FILE *out_f, struct http_request_info *phr)
{
  int action = phr->action;
  if (external_priv_action_aliases[action] > 0) action = external_priv_action_aliases[action];

  if (external_priv_action_names[action]) {
    external_priv_action_states[action] = external_action_load(external_priv_action_states[action],
                                                               "csp/contests",
                                                               external_priv_action_names[action],
                                                               "csp_get_",
                                                               NULL /* fixed_src_dir */,
                                                               phr->current_time,
                                                               0 /* contest_id */,
                                                               0 /* allow_fail */);
  }

  if (external_priv_action_states[action] && external_priv_action_states[action]->action_handler) {
    PageInterface *pg = ((external_action_handler_t) external_priv_action_states[action]->action_handler)();

    if (pg->ops->execute) {
      int r = pg->ops->execute(pg, phr->log_f, phr);
      if (r < 0) {
        error_page(out_f, phr, 0, -r);
        goto cleanup;
      }
    }

    if (pg->ops->render) {
      snprintf(phr->content_type, sizeof(phr->content_type), "text/html; charset=%s", EJUDGE_CHARSET);
      int r = pg->ops->render(pg, phr->log_f, out_f, phr);
      if (r < 0) {
        error_page(out_f, phr, 0, -r);
        goto cleanup;
      }
    }

    if (pg->ops->destroy) {
      pg->ops->destroy(pg);
      pg = NULL;
    }

    goto cleanup;
  }

  return 0;

cleanup:
  return 1;
}

static __attribute__((unused)) int
ej_ip_cmp(const ej_ip_t *v1, const ej_ip_t *v2)
{
  int r = v1->ipv6_flag - v2->ipv6_flag;
  if (r != 0) {
    return r;
  }
  if (v1->ipv6_flag) {
    return memcmp(v1->u.v6.addr, v2->u.v6.addr, 16);
  }
  if (v1->u.v4.addr < v2->u.v4.addr) return -1;
  if (v1->u.v4.addr > v2->u.v4.addr) return 1;
  return 0;
}

static void
copy_nsi_to_phr(
        struct http_request_info *phr,
        struct new_session_info *nsi,
        time_t current_time)
{
  phr->user_id = nsi->user_id;
  phr->contest_id = nsi->contest_id;
  if (phr->locale_id < 0 && nsi->locale_id >= 0) {
    phr->locale_id = nsi->locale_id;
  }
  if (phr->locale_id < 0) phr->locale_id = 0;
  phr->role = nsi->role;
  phr->passwd_method = nsi->passwd_method;
  phr->is_job = nsi->is_job;
  phr->login = xstrdup(nsi->login);
  phr->name = xstrdup(nsi->name);
  phr->nsi = nsi;
  nsi->access_time = current_time;
}

static void
copy_cti_to_phr(
        struct http_request_info *phr,
        struct cached_token_info *cti,
        time_t current_time)
{
  phr->user_id = cti->user_id;
  phr->contest_id = cti->contest_id;
  phr->login = xstrdup(cti->login);
  phr->name = xstrdup(cti->name);
  phr->role = cti->role;
  phr->reg_flags = cti->reg_flags;
  phr->reg_status = cti->reg_status;
  cti->access_time = current_time;
}

static int
priv_check_cached_key(struct http_request_info *phr)
{
  long long tsc_start;
  long long tsc_end;
  unsigned key_contest_id = phr->contest_id;

  rdtscll(tsc_start);

  time_t current_time = time(NULL);
  struct cached_token_info *cti = tc_find(&main_id_cache.t, phr->token, key_contest_id);

  while (1) {
    if (!cti || !cti->used) break;
    if (cti->cmd != ULS_GET_API_KEY) break;

    /*
    if (ej_ip_cmp(&phr->ip, &cti->origin_ip) != 0) {
      break;
    }
    if (phr->ssl_flag != cti->ssl_flag) {
      break;
    }
    */
    if (cti->expiry_time > 0 && current_time >= cti->expiry_time) {
      break;
    }
    if (current_time >= cti->refresh_time) {
      break;
    }
    if (phr->role > cti->role) {
      break;
    }

    copy_cti_to_phr(phr, cti, current_time);
    rdtscll(tsc_end);
    if (metrics.data) {
      metrics.data->hit_key_tsc += (tsc_end - tsc_start);
      ++metrics.data->hit_key_count;
    }
    return 0;
  }

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    if (cti && cti->used && cti->cmd == ULS_GET_API_KEY
        //&& !ej_ip_cmp(&phr->ip, &cti->origin_ip)
        //&& phr->ssl_flag == cti->ssl_flag
        && (cti->expiry_time <= 0 || current_time < cti->expiry_time)
        && phr->role <= cti->role) {
      copy_cti_to_phr(phr, cti, current_time);
      rdtscll(tsc_end);
      if (metrics.data) {
        metrics.data->hit_key_tsc += (tsc_end - tsc_start);
        ++metrics.data->hit_key_count;
      }
      return 0;
    }
    return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
  }

  struct userlist_api_key in_api_key = {};
  memcpy(in_api_key.token, phr->token, 32);
  in_api_key.contest_id = phr->contest_id;
  struct userlist_contest_info cnts_info = {};
  struct userlist_api_key *out_keys = NULL;
  int out_count = 0;
  int r = userlist_clnt_api_key_request(ul_conn, ULS_GET_API_KEY, 1, &in_api_key, &out_count, &out_keys, &cnts_info);
  if (r == -ULS_ERR_DISCONNECT) {
    if (cti && cti->used && cti->cmd == ULS_GET_API_KEY
        //&& !ej_ip_cmp(&phr->ip, &cti->origin_ip)
        //&& phr->ssl_flag == cti->ssl_flag
        && (cti->expiry_time <= 0 || current_time < cti->expiry_time)
        && phr->role <= cti->role) {
      copy_cti_to_phr(phr, cti, current_time);
      rdtscll(tsc_end);
      if (metrics.data) {
        metrics.data->hit_key_tsc += (tsc_end - tsc_start);
        ++metrics.data->hit_key_count;
      }
      return 0;
    }
    return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
  }

  if (r <= 0) {
    r = -NEW_SRV_ERR_PERMISSION_DENIED;
  } else if (out_count != 1) {
    r = -NEW_SRV_ERR_INTERNAL;
  } else if (cnts_info.user_id == 0 || cnts_info.contest_id == 0) {
    r = -NEW_SRV_ERR_PERMISSION_DENIED;
  } else if (phr->contest_id > 0 && cnts_info.contest_id != phr->contest_id) {
    r = -NEW_SRV_ERR_PERMISSION_DENIED;
  } else if (cnts_info.reg_status != USERLIST_REG_OK) {
    r = -NEW_SRV_ERR_PERMISSION_DENIED;
  } else if ((cnts_info.reg_flags & (USERLIST_UC_BANNED | USERLIST_UC_LOCKED | USERLIST_UC_DISQUALIFIED)) != 0) {
    r = -NEW_SRV_ERR_PERMISSION_DENIED;
  } else if (phr->role > out_keys[0].role) {
    r = -NEW_SRV_ERR_PERMISSION_DENIED;
  } else if (out_keys[0].expiry_time > 0 && current_time >= out_keys[0].expiry_time) {
    r = -NEW_SRV_ERR_PERMISSION_DENIED;
  }

  if (r < 0) {
    xfree(cnts_info.login);
    xfree(cnts_info.name);
    for (int i = 0; i < out_count; ++i) {
      xfree(out_keys[i].origin);
      xfree(out_keys[i].payload);
    }
    xfree(out_keys);

    if (cti && cti->used) {
      struct cached_token_info del_item;
      if (tc_remove(&main_id_cache.t, phr->token, key_contest_id, &del_item)) {
        xfree(del_item.login);
        xfree(del_item.name);
      }
    }

    return r;
  }

  if (!cti) {
    cti = tc_insert(&main_id_cache.t, phr->token, key_contest_id);
  } else {
    xfree(cti->login);
    xfree(cti->name);
    memset(cti, 0, sizeof(*cti));
    memcpy(cti->token, phr->token, 32);
    cti->key_contest_id = key_contest_id;
    cti->used = 1;
  }

  cti->origin_ip = phr->ip;
  cti->ssl_flag = phr->ssl_flag;
  cti->expiry_time = out_keys[0].expiry_time;
  cti->refresh_time = current_time + 3600;
  cti->login = cnts_info.login; cnts_info.login = NULL;
  cti->name = cnts_info.name; cnts_info.name = NULL;
  cti->cmd = ULS_GET_API_KEY;
  cti->user_id = cnts_info.user_id;
  cti->contest_id = cnts_info.contest_id;
  cti->reg_flags = cnts_info.reg_flags;
  cti->reg_status = cnts_info.reg_status;
  cti->role = out_keys[0].role;
  cti->all_contests = out_keys[0].all_contests;
  xfree(out_keys[0].payload);
  xfree(out_keys[0].origin);
  xfree(out_keys);

  copy_cti_to_phr(phr, cti, current_time);
  rdtscll(tsc_end);
  if (metrics.data) {
    metrics.data->get_key_tsc += (tsc_end - tsc_start);
    ++metrics.data->get_key_count;
  }
  return 0;
}

static int
priv_check_cached_session(struct http_request_info *phr)
{
  long long tsc_start;
  long long tsc_end;

  rdtscll(tsc_start);

  time_t current_time = time(NULL);
  struct new_session_info *nsi = nsc_find(&main_id_cache.s, phr->session_id, phr->client_key);
  while (nsi) {
    // check additional parameters
    if (nsi->cmd != ULS_PRIV_GET_COOKIE) {
      break;
    }
    /*
    if (ej_ip_cmp(&phr->ip, &nsi->origin_ip) != 0) {
      break;
    }
    if (phr->ssl_flag != nsi->ssl_flag) {
      break;
    }
    */
    if (current_time >= nsi->expire_time) {
      break;
    }
    if (current_time >= nsi->refresh_time) {
      break;
    }

    // cache hit
    copy_nsi_to_phr(phr, nsi, current_time);
    rdtscll(tsc_end);
    if (metrics.data) {
      metrics.data->hit_cookie_tsc += (tsc_end - tsc_start);
      ++metrics.data->hit_cookie_count;
    }
    return 0;
  }

  // cache entry is stale or nonexistant
  if (ns_open_ul_connection(phr->fw_state) < 0) {
    if (nsi && nsi->cmd == ULS_PRIV_GET_COOKIE
        && current_time < nsi->expire_time
        //&& nsi->ssl_flag == phr->ssl_flag
        //&& !ej_ip_cmp(&phr->ip, &nsi->origin_ip)
        ) {
      // still try to use cached session value
      copy_nsi_to_phr(phr, nsi, current_time);
      rdtscll(tsc_end);
      if (metrics.data) {
        metrics.data->hit_cookie_tsc += (tsc_end - tsc_start);
        ++metrics.data->hit_cookie_count;
      }
      return 0;
    }
    return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
  }

  struct UserlistGetCookieResult result;
  int r = userlist_clnt_get_cookie_2(ul_conn, ULS_PRIV_GET_COOKIE,
        &phr->ip, phr->ssl_flag,
        phr->session_id,
        phr->client_key,
        &result);

  if (r == -ULS_ERR_DISCONNECT) {
    if (nsi && nsi->cmd == ULS_PRIV_GET_COOKIE
        && current_time < nsi->expire_time
        //&& nsi->ssl_flag == phr->ssl_flag
        //&& !ej_ip_cmp(&phr->ip, &nsi->origin_ip)
        ) {
      // still try to use cached session value
      copy_nsi_to_phr(phr, nsi, current_time);
      rdtscll(tsc_end);
      if (metrics.data) {
        metrics.data->hit_cookie_tsc += (tsc_end - tsc_start);
        ++metrics.data->hit_cookie_count;
      }
      return 0;
    }
    return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
  }
  if (r < 0) {
    switch (-r) {
    case ULS_ERR_NO_COOKIE:
    case ULS_ERR_CANNOT_PARTICIPATE:
    case ULS_ERR_NOT_REGISTERED:
    case ULS_ERR_INCOMPLETE_REG:
      r = -NEW_SRV_ERR_INV_SESSION;
      break;
    default:
      fprintf(phr->log_f, "get_cookie failed: %s\n", userlist_strerror(-r));
      r = -NEW_SRV_ERR_INTERNAL;
      break;
    }
    if (nsi) {
      ns_invalidate_session(phr->session_id, phr->client_key);
    }
    return r;
  }

  if (!nsi) {
    nsi = nsc_insert(&main_id_cache.s, phr->session_id, phr->client_key);
  } else {
    xfree(nsi->login); nsi->login = NULL;
    xfree(nsi->name); nsi->name = NULL;
    memset(nsi, 0, sizeof(*nsi));
    nsi->session_id = phr->session_id;
    nsi->client_key = phr->client_key;
  }

  nsi->cmd = ULS_PRIV_GET_COOKIE;
  nsi->origin_ip = phr->ip;
  nsi->ssl_flag = phr->ssl_flag;
  nsi->user_id = result.data->user_id;
  nsi->contest_id = result.data->contest_id;
  nsi->locale_id = result.data->locale_id;
  nsi->priv_level = result.data->priv_level;
  nsi->role = result.data->role;
  nsi->team_login = result.data->team_login;
  nsi->reg_status = result.data->reg_status;
  nsi->reg_flags = result.data->reg_flags;
  nsi->is_ws = result.data->is_ws;
  nsi->is_job = result.data->is_job;
  nsi->passwd_method = result.data->passwd_method;
  nsi->expire_time = result.data->expire;
  nsi->refresh_time = current_time + 1200;
  nsi->access_time = current_time;
  nsi->login = xstrdup(result.login);
  nsi->name = xstrdup(result.name);

  xfree(result.data);
  copy_nsi_to_phr(phr, nsi, current_time);
  rdtscll(tsc_end);
  if (metrics.data) {
    metrics.data->get_cookie_tsc += (tsc_end - tsc_start);
    ++metrics.data->get_cookie_count;
  }
  return 0;
}

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
  long long log_file_pos_1 = -1LL;
  long long log_file_pos_2 = -1LL;
  unsigned char *msg = NULL;

  if (phr->token_mode) {
    // blacklisted for token_mode
    if (phr->action == NEW_SRV_ACTION_CREATE_API_KEY || phr->action == NEW_SRV_ACTION_API_KEYS_PAGE || phr->action == NEW_SRV_ACTION_DELETE_API_KEY
        || phr->action == NEW_SRV_ACTION_COOKIE_LOGIN || phr->action == NEW_SRV_ACTION_LOGIN || phr->action == NEW_SRV_ACTION_LOGIN_PAGE
        || phr->action == NEW_SRV_ACTION_LOGIN_JSON) {
      fprintf(phr->log_f, "invalid action for token auth\n");
      error_page(fout, phr, 0, -NEW_SRV_ERR_PERMISSION_DENIED);
      goto cleanup;
    }

    r = priv_check_cached_key(phr);
    if (r < 0) {
      error_page(fout, phr, 0, r);
      goto cleanup;
    }
  } else {
    if (phr->action == NEW_SRV_ACTION_COOKIE_LOGIN)
      return privileged_page_cookie_login(fout, phr);

    if (!phr->session_id || phr->action == NEW_SRV_ACTION_LOGIN_PAGE)
      return privileged_page_login(fout, phr);

    r = priv_check_cached_session(phr);
    if (r < 0) {
      error_page(fout, phr, 1, r);
      goto cleanup;
    }
  }

  if (phr->locale_id < 0) phr->locale_id = 0;

  if (phr->contest_id < 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts) {
    fprintf(phr->log_f, "invalid contest_id %d", phr->contest_id);
    error_page(fout, phr, 1, NEW_SRV_ERR_INV_CONTEST_ID);
    goto cleanup;
  }
  if (!cnts->managed) {
    fprintf(phr->log_f, "contest is not managed");
    error_page(fout, phr, 1, NEW_SRV_ERR_INV_CONTEST_ID);
    goto cleanup;
  }
  extra = ns_get_contest_extra(cnts, phr->config);
  if (cnts->enable_local_pages > 0 && !extra->cnts_actions) {
    extra->cnts_actions = ns_get_contest_external_actions(phr->contest_id, cur_time);
  }
  ASSERT(extra);

  phr->cnts = cnts;
  phr->extra = extra;

  // analyze IP limitations
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (!contests_check_master_ip(phr->contest_id, &phr->ip, phr->ssl_flag)) {
      fprintf(phr->log_f, "%s://%s is not allowed for MASTER for contest %d",
              ns_ssl_flag_str[phr->ssl_flag],
              xml_unparse_ipv6(&phr->ip), phr->contest_id);
      error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
      goto cleanup;
    }
  } else {
    // as for judge program
    if (!contests_check_judge_ip(phr->contest_id, &phr->ip, phr->ssl_flag)) {
      fprintf(phr->log_f, "%s://%s is not allowed for JUDGE for contest %d",
              ns_ssl_flag_str[phr->ssl_flag],
              xml_unparse_ipv6(&phr->ip), phr->contest_id);
      error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
      goto cleanup;
    }
  }

  // analyze permissions
  if (phr->role <= 0 || phr->role >= USER_ROLE_LAST) {
    fprintf(phr->log_f, "invalid role %d", phr->role);
    error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
        || opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0) {
      fprintf(phr->log_f, "user %s does not have MASTER_LOGIN bit for contest %d",
              phr->login, phr->contest_id);
      error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
      goto cleanup;
    }
  } else if (phr->role == USER_ROLE_JUDGE) {
    // as for the judge program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
        || opcaps_check(caps, OPCAP_JUDGE_LOGIN) < 0) {
      fprintf(phr->log_f, "user %s does not have JUDGE_LOGIN bit for contest %d",
              phr->login, phr->contest_id);
      error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
      goto cleanup;
    }
  } else {
    // user privileges checked locally
    if (nsdb_check_role(phr->user_id, phr->contest_id, phr->role) < 0) {
      fprintf(phr->log_f, "user %s has no permission to login as role %d for contest %d",
              phr->login, phr->role, phr->contest_id);
      error_page(fout, phr, 1, NEW_SRV_ERR_PERMISSION_DENIED);
      goto cleanup;
    }
  }

  if (ejudge_config->new_server_log && ejudge_config->new_server_log[0]) {
    log_file_pos_1 = generic_file_size(NULL, ejudge_config->new_server_log, NULL);
  }

  if (!extra->priv_header_txt || !extra->priv_footer_txt) {
    extra->priv_header_txt = ns_fancy_priv_header;
    extra->priv_footer_txt = ns_fancy_priv_footer;
    extra->priv_separator_txt = ns_fancy_priv_separator;
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
  phr->caps = 0;
  if (opcaps_find(&cnts->capabilities, phr->login, &caps) >= 0) {
    phr->caps = caps;
  }
  phr->dbcaps = 0;
  if (ejudge_cfg_opcaps_find(ejudge_config, phr->login, &caps) >= 0) {
    phr->dbcaps = caps;
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
    if (log_file_pos_1 >= 0) {
      log_file_pos_2 = generic_file_size(NULL, ejudge_config->new_server_log, NULL);
    }
    if (log_file_pos_1 >= 0 && log_file_pos_2 >= 0) {
      msg = read_file_range(ejudge_config->new_server_log, log_file_pos_1, log_file_pos_2);
    }
    if (msg) {
      fprintf(phr->log_f, "%s", msg);
    }
    xfree(msg);
    error_page(fout, phr, 0, NEW_SRV_ERR_CNTS_UNAVAILABLE);
    goto cleanup;
  }

  extra->serve_state->current_time = time(0);
  ns_check_contest_events(phr->extra, extra->serve_state, cnts);

  if (phr->action <= 0 || phr->action >= NEW_SRV_ACTION_LAST) {
    phr->action = NEW_SRV_ACTION_MAIN_PAGE;
  }
  if (!external_priv_action_names[phr->action] && !external_priv_action_aliases[phr->action] && !actions_table[phr->action]) {
    phr->action = NEW_SRV_ACTION_MAIN_PAGE;
  }

  if (priv_external_action(fout, phr) > 0) goto cleanup;

  if (phr->action > 0 && phr->action < NEW_SRV_ACTION_LAST && actions_table[phr->action]) {
    actions_table[phr->action](fout, phr, cnts, extra);
  } else {
    fprintf(phr->log_f, "action is undefined");
    error_page(fout, phr, 0, NEW_SRV_ERR_OPERATION_FAILED);
  }

cleanup:
  if (phr->log_f) fclose(phr->log_f);
  free(phr->log_t);
  phr->log_f = NULL;
  phr->log_t = NULL;
  phr->log_z = 0;
}

void
unpriv_load_html_style(struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra **p_extra,
                       time_t *p_cur_time)
{
  struct contest_extra *extra = 0;
  time_t cur_time = 0;
#if defined CONF_ENABLE_AJAX && CONF_ENABLE_AJAX
  unsigned char bb[8192];
  char *state_json_txt = 0;
  size_t state_json_len = 0;
  FILE *state_json_f = 0;
#endif

  extra = ns_get_contest_extra(cnts, phr->config);
  if (cnts->enable_local_pages > 0 && !extra->cnts_actions) {
    extra->cnts_actions = ns_get_contest_external_actions(phr->contest_id, cur_time);
  }
  ASSERT(extra);

  cur_time = time(0);
  watched_file_update(&extra->copyright, cnts->copyright_file, cur_time);
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
    state_json_f = open_memstream(&state_json_txt, &state_json_len);
    do_json_user_state(state_json_f, extra->serve_state, phr->user_id, 0);
    close_memstream(state_json_f); state_json_f = 0;
  } else {
    state_json_txt = xstrdup("");
  }

  snprintf(bb, sizeof(bb),
           "<script type=\"text/javascript\" src=\"" CONF_STYLE_PREFIX "dojo/dojo.js\" djConfig=\"isDebug: false, parseOnLoad: true, dojoIframeHistoryUrl:'" CONF_STYLE_PREFIX "dojo/resources/iframe_history.html'\"></script>\n"
           "<script type=\"text/javascript\" src=\"" CONF_STYLE_PREFIX "unpriv.js\"></script>\n"
           "<script type=\"text/javascript\">\n"
           "  var SID=\"%016llx\";\n"
           "  var NEW_SRV_ACTION_JSON_USER_STATE=%d;\n"
           "  var NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY=%d;\n"
           "  var self_url=\"%s\";\n"
           "  var script_name=\"%s\";\n"
           "  dojo.require(\"dojo.parser\");\n"
           "  var jsonState = %s;\n"
           "  var updateFailedMessage = \"%s\";\n"
           "  var testingInProgressMessage = \"%s\";\n"
           "  var testingCompleted = \"%s\";\n"
           "  var waitingTooLong = \"%s\";\n"
           "</script>\n", phr->session_id, NEW_SRV_ACTION_JSON_USER_STATE,
           NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY,
           phr->self_url, phr->script_name, state_json_txt,
           _("STATUS UPDATE FAILED!"), _("TESTING IN PROGRESS..."),
           _("TESTING COMPLETED"), _("REFRESH PAGE MANUALLY!"));
  xfree(state_json_txt); state_json_txt = 0;
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

  if (!(n = hr_cgi_param(phr, "run_id", &s))) {
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
  phr->back_action = ns_unpriv_prev_state[phr->action];
  fprintf(phr->log_f, "%s", errmsg);
  error_page(fout, phr, 0, NEW_SRV_ERR_OPERATION_FAILED);
  return -1;
}

int
ns_unpriv_parse_run_id(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int *p_run_id,
        struct run_entry *pe)
{
  return unpriv_parse_run_id(fout, phr, cnts, extra, p_run_id, pe);
}

static int
unpriv_external_action(FILE *out_f, struct http_request_info *phr);

void
unprivileged_page_login_page(FILE *fout, struct http_request_info *phr)
{
  phr->action = NEW_SRV_ACTION_LOGIN_PAGE;
  unpriv_external_action(fout, phr);
}

static void
unprivileged_page_login(FILE *fout, struct http_request_info *phr)
{
  const unsigned char *login = 0;
  const unsigned char *password = 0;
  const unsigned char *prob_name = 0;
  int r;
  const struct contest_desc *cnts = 0;
  unsigned char prob_name_2[1024];
  unsigned char prob_name_3[1024];
  int action = NEW_SRV_ACTION_MAIN_PAGE;

  if ((r = hr_cgi_param(phr, "login", &login)) < 0) {
    fprintf(phr->log_f, "cannot parse login");
    return error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
  }
  if (login && *login && !is_valid_login(login)) {
    fprintf(phr->log_f, "invalid login");
    return error_page(fout, phr, 0, NEW_SRV_ERR_PERMISSION_DENIED);
  }
  if (!r || phr->action == NEW_SRV_ACTION_LOGIN_PAGE)
    return unprivileged_page_login_page(fout, phr);

  if (phr->contest_id<=0 || contests_get(phr->contest_id, &cnts)<0 || !cnts) {
    fprintf(phr->log_f, "invalid contest_id");
    return error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
  }
  if (phr->locale_id < 0 && cnts->default_locale_num >= 0)
    phr->locale_id = cnts->default_locale_num;
  if (phr->locale_id < 0) phr->locale_id = 0;

  phr->login = xstrdup(login);
  if ((r = hr_cgi_param(phr, "password", &password)) <= 0) {
    fprintf(phr->log_f, "cannot parse password");
    xfree(phr->login); phr->login = NULL;
    return error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
  }
  if (!contests_check_team_ip(phr->contest_id, &phr->ip, phr->ssl_flag)) {
    fprintf(phr->log_f, "%s://%s is not allowed for USER for contest %d", ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ipv6(&phr->ip), phr->contest_id);
    xfree(phr->login); phr->login = NULL;
    return error_page(fout, phr, 0, NEW_SRV_ERR_PERMISSION_DENIED);
  }
  if (cnts->closed) {
    fprintf(phr->log_f, "contest %d is closed", cnts->id);
    xfree(phr->login); phr->login = NULL;
    return error_page(fout, phr, 0, NEW_SRV_ERR_SERVICE_NOT_AVAILABLE);
  }
  if (!cnts->managed) {
    fprintf(phr->log_f, "contest %d is not managed", cnts->id);
    xfree(phr->login); phr->login = NULL;
    return error_page(fout, phr, 0, NEW_SRV_ERR_SERVICE_NOT_AVAILABLE);
  }

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    xfree(phr->login); phr->login = NULL;
    return error_page(fout, phr, 0, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
  }

  if ((r = userlist_clnt_login(ul_conn, ULS_TEAM_CHECK_USER,
                               &phr->ip,
                               0 /* cookie */,
                               phr->client_key,
                               0 /* expire */,
                               phr->ssl_flag, phr->contest_id,
                               phr->locale_id,
                               0, /* pwd_special */
                               0, /* is_ws */
                               0, /* is_job */
                               login, password,
                               &phr->user_id,
                               &phr->session_id, &phr->client_key,
                               &phr->name,
                               NULL /* expire */,
                               &phr->priv_level,
                               &phr->reg_status,
                               &phr->reg_flags)) < 0) {
    switch (-r) {
    case ULS_ERR_INVALID_LOGIN:
    case ULS_ERR_INVALID_PASSWORD:
    case ULS_ERR_BAD_CONTEST_ID:
    case ULS_ERR_IP_NOT_ALLOWED:
    case ULS_ERR_NO_PERMS:
    case ULS_ERR_NOT_REGISTERED:
    case ULS_ERR_CANNOT_PARTICIPATE:
      fprintf(phr->log_f, "user_login failed: %s", userlist_strerror(-r));
      xfree(phr->login); phr->login = NULL;
      return error_page(fout, phr, 0, NEW_SRV_ERR_PERMISSION_DENIED);
    case ULS_ERR_DISCONNECT:
      xfree(phr->login); phr->login = NULL;
      return error_page(fout, phr, 0, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    case ULS_ERR_INCOMPLETE_REG:
      xfree(phr->login); phr->login = NULL;
      return error_page(fout, phr, 0, NEW_SRV_ERR_REGISTRATION_INCOMPLETE);
    default:
      fprintf(phr->log_f, "user_login failed: %s", userlist_strerror(-r));
      xfree(phr->login); phr->login = NULL;
      return error_page(fout, phr, 0, NEW_SRV_ERR_INTERNAL);
    }
  }

  hr_cgi_param(phr, "prob_name", &prob_name);
  prob_name_3[0] = 0;
  if (prob_name && prob_name[0]) {
    url_armor_string(prob_name_2, sizeof(prob_name_2), prob_name);
    action = NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT;
    snprintf(prob_name_3, sizeof(prob_name_3), "lt=1&prob_name=%s", prob_name_2);
  } else {
    snprintf(prob_name_3, sizeof(prob_name_3), "lt=1");
  }

  ns_refresh_page(fout, phr, action, prob_name_3);
}

static void
unpriv_change_language(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const unsigned char *s;
  int r, n;
  int new_locale_id;

  if ((r = hr_cgi_param(phr, "locale_id", &s)) < 0) {
    fprintf(phr->log_f, "cannot parse locale_id\n");
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
    goto cleanup;
  }
  if (r > 0) {
    if (sscanf(s, "%d%n", &new_locale_id, &n) != 1 || s[n] || new_locale_id < 0) {
      fprintf(phr->log_f, "cannot parse locale_id\n");
      error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
      goto cleanup;
    }
  }

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    goto cleanup;
  }
  if ((r = userlist_clnt_set_cookie(ul_conn, ULS_SET_COOKIE_LOCALE,
                                    phr->session_id,
                                    phr->client_key,
                                    new_locale_id)) < 0) {
    fprintf(phr->log_f, "set_cookie failed: %s\n", userlist_strerror(-r));
    error_page(fout, phr, 0, NEW_SRV_ERR_INTERNAL);
    goto cleanup;
  }

  ns_refresh_page(fout, phr, NEW_SRV_ACTION_MAIN_PAGE, 0);

 cleanup:;
}

static void
unpriv_change_password(FILE *fout,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra)
{
  const unsigned char *p0 = 0, *p1 = 0, *p2 = 0;
  int cmd, r;
  unsigned char url[1024];
  unsigned char login_buf[256];

  if (hr_cgi_param(phr, "oldpasswd", &p0) <= 0) {
    fprintf(phr->log_f, "cannot parse oldpasswd\n");
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
    goto cleanup;
  }
  if (hr_cgi_param(phr, "newpasswd1", &p1) <= 0) {
    fprintf(phr->log_f, "cannot parse newpasswd1\n");
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
    goto cleanup;
  }
  if (hr_cgi_param(phr, "newpasswd2", &p2) <= 0) {
    fprintf(phr->log_f, "cannot parse newpasswd2\n");
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
    goto cleanup;
  }

  if (strlen(p0) >= 256) {
    error_page(fout, phr, 0, NEW_SRV_ERR_OLD_PWD_TOO_LONG);
    goto cleanup;
  }
  if (strcmp(p1, p2)) {
    error_page(fout, phr, 0, NEW_SRV_ERR_NEW_PWD_MISMATCH);
    goto cleanup;
  }
  if (strlen(p1) >= 256) {
    error_page(fout, phr, 0, NEW_SRV_ERR_NEW_PWD_TOO_LONG);
    goto cleanup;
  }

  cmd = ULS_PRIV_SET_TEAM_PASSWD;
  if (cnts->disable_team_password) cmd = ULS_PRIV_SET_REG_PASSWD;

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    goto cleanup;
  }
  r = userlist_clnt_set_passwd(ul_conn, cmd, phr->user_id, phr->contest_id, 0, p0, p1, NULL);
  if (r < 0) {
    fprintf(phr->log_f, "%s\n", userlist_strerror(-r));
    error_page(fout, phr, 0, NEW_SRV_ERR_PWD_UPDATE_FAILED);
    goto cleanup;
  }

  url_armor_string(login_buf, sizeof(login_buf), phr->login);
  if (phr->rest_mode > 0) {
    snprintf(url, sizeof(url),
             "%s/%s?contest_id=%d&login=%s&locale_id=%d",
             phr->self_url, ns_symbolic_action_table[NEW_SRV_ACTION_LOGIN_PAGE],
             phr->contest_id, login_buf, phr->locale_id);
  } else {
    snprintf(url, sizeof(url),
             "%s?contest_id=%d&login=%s&locale_id=%d&action=%d",
             phr->self_url, phr->contest_id, login_buf, phr->locale_id,
             NEW_SRV_ACTION_LOGIN_PAGE);
  }
  ns_refresh_page_2(fout, phr->client_key, url);

 cleanup:;
}

static void
unpriv_print_run(FILE *fout,
                 struct http_request_info *phr,
                 const struct contest_desc *cnts,
                 struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int run_id, n;
  struct run_entry re;

  if (unpriv_parse_run_id(fout, phr, cnts, extra, &run_id, &re) < 0)
    goto cleanup;

  if (!cs->global->enable_printing || cs->printing_suspended) {
    error_page(fout, phr, 0, NEW_SRV_ERR_PRINTING_DISABLED);
    goto cleanup;
  }

  if (!run_is_normal_or_transient_status(re.status) || re.user_id != phr->user_id) {
    error_page(fout, phr, 0, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  if (re.pages > 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_ALREADY_PRINTED);
    goto cleanup;
  }

  if ((n = team_print_run(cs, run_id, phr->user_id)) < 0) {
    switch (-n) {
    case SRV_ERR_PAGES_QUOTA:
      fprintf(phr->log_f, "Quota: %d\n", cs->global->team_page_quota);
      error_page(fout, phr, 0, NEW_SRV_ERR_ALREADY_PRINTED);
      goto cleanup;
    default:
      fprintf(phr->log_f, "%d (%s)", -n, protocol_strerror(-n));
      error_page(fout, phr, 0, NEW_SRV_ERR_PRINTING_FAILED);
      goto cleanup;
    }
  }

  serve_audit_log(cs, run_id, &re, phr->user_id, &phr->ip, phr->ssl_flag,
                  "print", "ok", -1, "  %d pages printed\n", n);
  ns_refresh_page(fout, phr, NEW_SRV_ACTION_MAIN_PAGE, 0);

 cleanup:;
}

int
compute_available_tokens(
        serve_state_t cs,
        const struct section_problem_data *prob,
        time_t start_time)
{
  const struct section_global_data *global = cs->global;
  int available_tokens = 0;

  if (global->token_info) {
    available_tokens += global->token_info->initial_count;
  }
  if (prob->token_info) {
    available_tokens += prob->token_info->initial_count;
  }
  if (start_time > 0 && cs->current_time > start_time) {
    long long td = (long long) cs->current_time - start_time;
    if (global->token_info) {
      if (global->token_info->time_sign > 0) {
        available_tokens += global->token_info->time_increment * (td / global->token_info->time_interval);
      } else if (global->token_info->time_sign < 0) {
        available_tokens -= global->token_info->time_increment * (td / global->token_info->time_interval);
      }
    }
    if (prob->token_info) {
      if (prob->token_info->time_sign > 0) {
        available_tokens += prob->token_info->time_increment * (td / prob->token_info->time_interval);
      } else if (prob->token_info->time_sign < 0) {
        available_tokens -= prob->token_info->time_increment * (td / prob->token_info->time_interval);
      }
    }
  }
  if (available_tokens < 0) available_tokens = 0;
  return available_tokens;
}

static void
unpriv_use_token(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int run_id;
  struct run_entry re;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = 0;
  int back_action = 0;
  unsigned char param_buf[1024];
  time_t start_time = 0, stop_time = 0;

  if (unpriv_parse_run_id(fout, phr, cnts, extra, &run_id, &re) < 0)
    goto cleanup;
  if (re.prob_id <= 0 || re.prob_id > cs->max_prob || !(prob = cs->probs[re.prob_id])) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_PROB_ID);
    goto cleanup;
  }

  hr_cgi_param_int_opt(phr, "back_action", &back_action, 0);
  param_buf[0] = 0;
  if (back_action == NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT) {
    snprintf(param_buf, sizeof(param_buf), "prob_id=%d", re.prob_id);
  } else if (back_action == NEW_SRV_ACTION_VIEW_SUBMISSIONS) {
    // nothing
  } else {
    back_action = NEW_SRV_ACTION_MAIN_PAGE;
  }

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
  }

  if (cs->clients_suspended) goto back_action;
  if (start_time <= 0) goto back_action;
  if (stop_time > 0) goto back_action;

  if (prob->enable_tokens <= 0 || !prob->token_info || !prob->token_info->open_sign || prob->token_info->open_cost <= 0) {
    goto back_action;
  }

  if ((re.token_flags & prob->token_info->open_flags) == prob->token_info->open_flags) {
    // nothing new to open
    goto back_action;
  }

  if (!run_is_team_report_available(re.status)) {
    goto back_action;
  }

  int separate_user_score = global->separate_user_score > 0 && cs->online_view_judge_score <= 0;
  int status = re.status;
  if (separate_user_score > 0 && re.is_saved) {
    status = re.saved_status;
  }
  if (separate_user_score && prob->tokens_for_user_ac > 0 && re.is_saved && re.saved_status != RUN_ACCEPTED) {
    goto back_action;
  }

  switch (status) {
  case RUN_OK:
  case RUN_RUN_TIME_ERR:
  case RUN_TIME_LIMIT_ERR:
  case RUN_PRESENTATION_ERR:
  case RUN_WRONG_ANSWER_ERR:
  case RUN_PARTIAL:
  case RUN_ACCEPTED:
  case RUN_DISQUALIFIED:
  case RUN_MEM_LIMIT_ERR:
  case RUN_SECURITY_ERR:
  case RUN_SYNC_ERR:
  case RUN_WALL_TIME_LIMIT_ERR:
  case RUN_PENDING_REVIEW:
  case RUN_SUMMONED:
  case RUN_REJECTED:
    /*
    if (prob->team_enable_rep_view > 0) {
      ns_refresh_page(fout, phr, back_action, param_buf);
      goto cleanup;
    }
    */
    break;

  case RUN_COMPILE_ERR:
  case RUN_STYLE_ERR:
    if (prob->team_enable_ce_view > 0 || prob->team_enable_rep_view > 0) {
      goto back_action;
    }
    break;

    /*
      case RUN_CHECK_FAILED:
      case RUN_IGNORED:
      case RUN_PENDING:
      case RUN_SKIPPED:
    */
  default:
    goto back_action;
  }

  // count the amount of spent and available tokens
  int available_tokens = compute_available_tokens(cs, prob, start_time) - run_count_tokens(cs->runlog_state, phr->user_id, prob->id);
  if (available_tokens < 0) available_tokens = 0;
  if (available_tokens < prob->token_info->open_cost) {
    error_page(fout, phr, 0, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  re.token_flags = prob->token_info->open_flags;
  re.token_count = prob->token_info->open_cost;
  if (run_set_entry(cs->runlog_state, run_id, RE_TOKEN_FLAGS | RE_TOKEN_COUNT,
                    &re, &re) < 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
    goto cleanup;
  }
  serve_notify_run_update(phr->config, cs, &re);

  serve_audit_log(cs, run_id, &re, phr->user_id, &phr->ip, phr->ssl_flag,
                  "use_token", "ok", -1, "  %d tokens used\n  %d new token flags\n", prob->token_info->open_cost,
                  prob->token_info->open_flags);
  ns_refresh_page(fout, phr, back_action, param_buf);

cleanup:;
  return;

back_action:
  ns_refresh_page(fout, phr, back_action, param_buf);
  goto cleanup;
}

static void
unpriv_generate_telegram_token(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  unsigned char param_buf[1024];
  unsigned char token_buf[64];
  int telegram_token;

  random_init();
  telegram_token = (random_u32() & 0x7fffffff) % 1000000;
  snprintf(token_buf, sizeof(token_buf), "%d", telegram_token);
  snprintf(param_buf, sizeof(param_buf), "telegram_token=%d", telegram_token);

  serve_send_telegram_token(ejudge_config, cs, cnts, phr->locale_id, phr->user_id, phr->login, phr->name, token_buf, 0);

  ns_refresh_page(fout, phr, NEW_SRV_ACTION_VIEW_SETTINGS, param_buf);
}

void
ns_get_accepted_set(
        serve_state_t cs,
        int user_id,
        unsigned char *acc_set)
{
  run_get_accepted_set(cs->runlog_state, user_id, cs->accepting_mode, cs->max_prob, acc_set);
  if (!cs->accepting_mode) return;
  for (int prob_id = 1; prob_id <= cs->max_prob; ++prob_id) {
    if (acc_set[prob_id] == 2) {
      const struct section_problem_data *p = cs->probs[prob_id];
      if (p && p->type != PROB_TYPE_STANDARD) {
        acc_set[prob_id] = 1;
      } else {
        acc_set[prob_id] = 0;
      }
    }
  }
}

int
ns_submit_run(
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        const unsigned char *prob_param_name,
        const unsigned char *lang_param_name,
        int enable_ans_collect,
        int enable_path,
        int enable_uuid,
        int enable_user_id,
        int enable_status,
        int admin_mode,
        int is_hidden,
        int *p_run_id,
        int *p_mime_type,
        int *p_next_prob_id)
{
  int retval = 0, r;
  int user_id = 0, prob_id = 0, lang_id = 0, status = -1;
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = NULL;
  const struct section_language_data *lang = NULL;
  unsigned char *utf8_str = NULL;
  ssize_t utf8_len = 0;
  const unsigned char *s;
  const unsigned char *run_text = NULL;
  ssize_t run_size = 0;
  size_t tmpsz;
  char *ans_text = NULL;
  int skip_mime_type_test = 0;
  char *run_file = NULL;
  ej_uuid_t run_uuid = { { 0, 0, 0, 0 } };
  ej_uuid_t *uuid_ptr = NULL;
  int eoln_type = 0;
  struct run_entry new_run;

  if (!prob_param_name) prob_param_name = "prob_id";
  if (hr_cgi_param(phr, prob_param_name, &s) <= 0 || !s) {
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  }
  for (prob_id = 1; prob_id <= cs->max_prob; ++prob_id) {
    if ((prob = cs->probs[prob_id]) /*&& prob->short_name*/ && !strcmp(s, prob->short_name))
      break;
  }
  if (prob_id > cs->max_prob) {
    char *eptr = NULL;
    errno = 0;
    prob_id = strtol(s, &eptr, 10);
    if (errno || *eptr || prob_id <= 0 || prob_id > cs->max_prob || !(prob = cs->probs[prob_id])) {
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
    }
  }

  if (prob->type == PROB_TYPE_STANDARD) {
    // "STANDARD" problems need programming language identifier
    if (!lang_param_name) lang_param_name = "lang_id";
    int r = hr_cgi_param(phr, lang_param_name, &s);
    if (r < 0) {
      FAIL(NEW_SRV_ERR_INV_LANG_ID);
    }
    if (!r || !s) {
      if (prob->custom_compile_cmd && prob->custom_compile_cmd[0]) {
        for (r = 1; r <= cs->max_lang; ++r) {
          if (cs->langs[r] && cs->langs[r]->enable_custom > 0) {
            break;
          }
        }
        if (r <= cs->max_lang) {
          lang_id = r;
          lang = cs->langs[r];
        } else {
          FAIL(NEW_SRV_ERR_INV_LANG_ID);
        }
      } else {
        FAIL(NEW_SRV_ERR_INV_LANG_ID);
      }
    } else {
      for (lang_id = 1; lang_id <= cs->max_lang; ++lang_id) {
        if ((lang = cs->langs[lang_id]) /*&& lang->short_name*/ && !strcmp(lang->short_name, s))
          break;
      }
      if (lang_id > cs->max_lang) {
        char *eptr = NULL;
        errno = 0;
        lang_id = strtol(s, &eptr, 10);
        if (errno || *eptr || lang_id <= 0 || lang_id > cs->max_lang || !(lang = cs->langs[lang_id])) {
          FAIL(NEW_SRV_ERR_INV_LANG_ID);
        }
      }
    }
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

  switch (prob->type) {
  case PROB_TYPE_STANDARD:
  case PROB_TYPE_OUTPUT_ONLY:
    if (enable_path > 0) {
      const unsigned char *path = NULL;
      if (hr_cgi_param(phr, "path", &path) <= 0 || !path) FAIL(NEW_SRV_ERR_FILE_UNSPECIFIED);
      if (generic_read_file(&run_file, 0, &tmpsz, 0, NULL, path, NULL) < 0)
        FAIL(NEW_SRV_ERR_FILE_UNSPECIFIED);
      run_text = run_file;
      run_size = tmpsz;
      r = 1;
    } else {
      r = hr_cgi_param_bin(phr, "file", &run_text, &tmpsz); run_size = tmpsz;
    }
    if (r <= 0 || !run_text || run_size <= 0) {
      if (prob->enable_text_form > 0) {
        r = hr_cgi_param_bin(phr, "text_form", &run_text, &tmpsz); run_size = tmpsz;
        if (r <= 0 || !run_text || run_size <= 0) {
          FAIL(NEW_SRV_ERR_FILE_EMPTY);
        }
        if (run_size != strlen(run_text)) {
          FAIL(NEW_SRV_ERR_BINARY_FILE);
        }
        skip_mime_type_test = 1;
      } else {
        FAIL(NEW_SRV_ERR_FILE_UNSPECIFIED);
      }
    }
    break;

  case PROB_TYPE_TESTS:
  case PROB_TYPE_TEXT_ANSWER:
  case PROB_TYPE_SHORT_ANSWER:
  case PROB_TYPE_SELECT_ONE:
    if (enable_path > 0) {
      const unsigned char *path = NULL;
      if (hr_cgi_param(phr, "path", &path) <= 0 || !path) FAIL(NEW_SRV_ERR_FILE_UNSPECIFIED);
      if (generic_read_file(&run_file, 0, &tmpsz, 0, NULL, path, NULL) < 0)
        FAIL(NEW_SRV_ERR_FILE_UNSPECIFIED);
      run_text = run_file;
      run_size = tmpsz;
      r = 1;
    } else {
      r = hr_cgi_param_bin(phr, "file", &run_text, &tmpsz); run_size = tmpsz;
    }
    if (r <= 0 || !run_text || run_size <= 0) {
      FAIL(NEW_SRV_ERR_FILE_UNSPECIFIED);
    }
    break;

  case PROB_TYPE_SELECT_MANY:
    if (enable_ans_collect > 0) {
      // "ans_*"
      int max_ans = -1;
      for (int i = 0; i < phr->param_num; ++i) {
        if (!strncmp(phr->param_names[i], "ans_", 4) && isdigit(phr->param_names[i][4])) {
          char *eptr = NULL;
          errno = 0;
          int ans = strtol(phr->param_names[i] + 4, &eptr, 10);
          if (errno || *eptr || ans < 0 || ans > 65535) {
            FAIL(NEW_SRV_ERR_INV_ANSWER);
          }
          if (ans > max_ans) max_ans = ans;
        }
      }
      if (max_ans >= 0) {
        unsigned char *ans_map = NULL;
        XCALLOC(ans_map, max_ans + 1);
        for (int i = 0; i < phr->param_num; ++i) {
          if (!strncmp(phr->param_names[i], "ans_", 4) && isdigit(phr->param_names[i][4])) {
            char *eptr = NULL;
            errno = 0;
            int ans = strtol(phr->param_names[i] + 4, &eptr, 10);
            if (!errno && !*eptr && ans >= 0 && ans <= max_ans) {
              ans_map[ans] = 1;
            }
          }
        }
        int nonfirst = 0;
        FILE *f = open_memstream(&ans_text, &tmpsz);
        for (int ans = 0; ans <= max_ans; ++ans) {
          if (ans_map[ans]) {
            if (nonfirst) putc(' ', f);
            nonfirst = 1;
            fprintf(f, "%d", ans);
          }
        }
        if (nonfirst) putc('\n', f);
        fclose(f); f = NULL;
        xfree(ans_map); ans_map = NULL;
        run_text = ans_text; run_size = tmpsz;
      } else {
        run_text = ""; run_size = 0;
      }
    } else {
      if (enable_path > 0) {
        const unsigned char *path = NULL;
        if (hr_cgi_param(phr, "path", &path) <= 0 || !path) FAIL(NEW_SRV_ERR_FILE_UNSPECIFIED);
        if (generic_read_file(&run_file, 0, &tmpsz, 0, NULL, path, NULL) < 0)
          FAIL(NEW_SRV_ERR_FILE_UNSPECIFIED);
        run_text = run_file;
        run_size = tmpsz;
        r = 1;
      } else {
        r = hr_cgi_param_bin(phr, "file", &run_text, &tmpsz); run_size = tmpsz;
      }
      if (r <= 0 || !run_text || run_size <= 0) {
        run_text = ""; run_size = 0;
      }
    }
    break;
  case PROB_TYPE_CUSTOM:
    {
      // invoke problem plugin
      struct problem_plugin_iface *plg = NULL;
      load_problem_plugin(cs, prob_id);
      if (!(plg = cs->prob_extras[prob_id].plugin) || !plg->parse_form) {
        FAIL(NEW_SRV_ERR_PLUGIN_NOT_AVAIL);
      }
      if ((ans_text = (*plg->parse_form)(cs->prob_extras[prob_id].plugin_data, log_f, phr, cnts, extra))) {
        run_text = ans_text;
        run_size = strlen(ans_text);
      } else {
        // FIXME: ERROR?
        run_text = ""; run_size = 0;
      }
    }
    break;
  }

  switch (prob->type) {
  case PROB_TYPE_STANDARD:
    if (lang->binary <= 0 && strlen(run_text) != run_size) {
      if ((utf8_len = ucs2_to_utf8(&utf8_str, run_text, run_size)) < 0) {
        FAIL(NEW_SRV_ERR_BINARY_FILE);
      }
      run_text = utf8_str;
      run_size = utf8_len;
    }
    if (prob->disable_ctrl_chars > 0 && has_control_characters(run_text)) {
      FAIL(NEW_SRV_ERR_INV_CHAR);
    }
    break;
  case PROB_TYPE_OUTPUT_ONLY:
    if (prob->binary_input <= 0 && prob->binary <= 0 && strlen(run_text) != run_size) {
      FAIL(NEW_SRV_ERR_BINARY_FILE);
    }
    break;
  case PROB_TYPE_TEXT_ANSWER:
  case PROB_TYPE_SHORT_ANSWER:
  case PROB_TYPE_SELECT_MANY:
    if (strlen(run_text) != run_size) {
      FAIL(NEW_SRV_ERR_BINARY_FILE);
    }
    break;

  case PROB_TYPE_SELECT_ONE:
    {
      if (strlen(run_text) != run_size) {
        FAIL(NEW_SRV_ERR_BINARY_FILE);
      }
      const unsigned char *eptr1 = run_text + run_size;
      while (eptr1 > run_text && isspace(eptr1[-1])) --eptr1;
      if (eptr1 == run_text) {
        FAIL(NEW_SRV_ERR_ANSWER_UNSPECIFIED);
      }
      char *eptr2 = NULL;
      errno = 0;
      int ans_val = strtol(run_text, &eptr2, 10);
      if (errno || eptr1 != (const unsigned char *) eptr2 || ans_val < 0) {
        FAIL(NEW_SRV_ERR_INV_ANSWER);
      }
    }
    break;

  case PROB_TYPE_TESTS:
  case PROB_TYPE_CUSTOM:
    break;
  }

  // ignore BOM
  if (global->ignore_bom > 0 && prob->binary <= 0 && (!lang || lang->binary <= 0)) {
    if (run_text && run_size >= 3 && run_text[0] == 0xef && run_text[1] == 0xbb && run_text[2] == 0xbf) {
      run_text += 3; run_size -= 3;
    }
  }

  if (enable_user_id > 0) {
    if (hr_cgi_param_int(phr, "user_id", &user_id) < 0 || user_id <= 0)
      FAIL(NEW_SRV_ERR_INV_USER_ID);
  } else {
    user_id = phr->user_id;
  }
  if (enable_status > 0) {
    if (hr_cgi_param_int(phr, "status", &status) < 0 || status < 0)
      FAIL(NEW_SRV_ERR_INV_STATUS);
  }

  time_t start_time = 0;
  time_t stop_time = 0;
  if (global->is_virtual > 0 && !admin_mode) {
    start_time = run_get_virtual_start_time(cs->runlog_state, user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, user_id, cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state, user_id, cs->current_time);
  }

  // availability checks
  if (!admin_mode && cs->clients_suspended) {
    FAIL(NEW_SRV_ERR_CLIENTS_SUSPENDED);
  }
  if (!admin_mode && start_time <= 0) {
    FAIL(NEW_SRV_ERR_CONTEST_NOT_STARTED);
  }
  if (!admin_mode && stop_time > 0 && !cs->upsolving_mode) {
    FAIL(NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
  }
  if (!admin_mode && serve_check_user_quota(cs, user_id, run_size) < 0) {
    FAIL(NEW_SRV_ERR_RUN_QUOTA_EXCEEDED);
  }
  if (!admin_mode && !serve_is_problem_started(cs, user_id, prob)) {
    FAIL(NEW_SRV_ERR_PROB_UNAVAILABLE);
  }
  time_t user_deadline = 0;
  if (!admin_mode && serve_is_problem_deadlined(cs, user_id, phr->login, prob, &user_deadline)) {
    FAIL(NEW_SRV_ERR_PROB_DEADLINE_EXPIRED);
  }

  int mime_type = 0;
  if (p_mime_type) *p_mime_type = 0;
  if (!admin_mode && lang_id > 0) {
    if (lang->disabled > 0) {
      FAIL(NEW_SRV_ERR_LANG_DISABLED);
    }
    if (prob->enable_container <= 0 && lang->insecure > 0 && global->secure_run > 0 && prob->disable_security <= 0) {
      FAIL(NEW_SRV_ERR_LANG_DISABLED);
    }
    if (prob->enable_language) {
      char **lang_list = prob->enable_language;
      int i;
      for (i = 0; lang_list[i]; ++i)
        if (!strcmp(lang_list[i], lang->short_name))
          break;
      if (!lang_list[i]) {
        FAIL(NEW_SRV_ERR_LANG_NOT_AVAIL_FOR_PROBLEM);
      }
    } else if (prob->disable_language) {
      char **lang_list = prob->disable_language;
      int i;
      for (i = 0; lang_list[i]; ++i)
        if (!strcmp(lang_list[i], lang->short_name))
          break;
      if (lang_list[i]) {
        FAIL(NEW_SRV_ERR_LANG_DISABLED_FOR_PROBLEM);
      }
    }
  } else if (!admin_mode && !skip_mime_type_test) {
    // guess the content-type and check it against the list
    if ((mime_type = mime_type_guess(global->diff_work_dir, run_text, run_size)) < 0) {
      FAIL(NEW_SRV_ERR_CANNOT_DETECT_CONTENT_TYPE);
    }
    if (p_mime_type) *p_mime_type = mime_type;
    const unsigned char *mime_type_str = mime_type_get_type(mime_type);
    if (prob->enable_language) {
      char **lang_list = prob->enable_language;
      int i;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], mime_type_str))
          break;
      if (!lang_list[i]) {
        FAIL(NEW_SRV_ERR_CONTENT_TYPE_NOT_AVAILABLE);
      }
    } else if (prob->disable_language) {
      char **lang_list = prob->disable_language;
      int i;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], mime_type_str))
          break;
      if (lang_list[i]) {
        FAIL(NEW_SRV_ERR_CONTENT_TYPE_DISABLED);
      }
    }
  }

  int variant = 0;
  if (prob->variant_num > 0) {
    if (admin_mode) {
      if (hr_cgi_param_int_opt(phr, "variant", &variant, 0) < 0) {
        FAIL(NEW_SRV_ERR_INV_VARIANT);
      }
      if (!variant && (variant = find_variant(cs, user_id, prob_id, 0)) <= 0) {
        FAIL(NEW_SRV_ERR_VARIANT_UNASSIGNED);
      }
      if (variant < 0 || variant > prob->variant_num) {
        FAIL(NEW_SRV_ERR_INV_VARIANT);
      }
    } else {
      if ((variant = find_variant(cs, user_id, prob_id, 0)) <= 0) {
        FAIL(NEW_SRV_ERR_VARIANT_UNASSIGNED);
      }
    }
  }

  ruint32_t shaval[5];
  sha_buffer(run_text, run_size, shaval);

  if (enable_uuid) {
    const unsigned char *uuid_str = NULL;
    if (hr_cgi_param(phr, "uuid", &uuid_str) > 0 && uuid_str && *uuid_str) {
      if (ej_uuid_parse(uuid_str, &run_uuid) < 0) {
        FAIL(NEW_SRV_ERR_INV_PARAM);
      }
      uuid_ptr = &run_uuid;
    }
  }

  int run_id = 0;
  if (!admin_mode && global->ignore_duplicated_runs != 0) {
    if ((run_id = run_find_duplicate(cs->runlog_state, user_id, prob_id,
                                     lang_id, variant, run_size, shaval)) >= 0) {
      if (p_run_id) *p_run_id = run_id;
      FAIL(NEW_SRV_ERR_DUPLICATE_SUBMIT);
    }
  }

  unsigned char *acc_probs = NULL;
  if (!admin_mode && prob->disable_submit_after_ok > 0
      && global->score_system != SCORE_OLYMPIAD && !cs->accepting_mode) {
    if (!acc_probs) {
      XALLOCAZ(acc_probs, cs->max_prob + 1);
      ns_get_accepted_set(cs, user_id, acc_probs);
    }
    if (acc_probs[prob_id]) {
      FAIL(NEW_SRV_ERR_PROB_ALREADY_SOLVED);
    }
  }

  if (!admin_mode && prob->require) {
    if (!acc_probs) {
      XALLOCAZ(acc_probs, cs->max_prob + 1);
      ns_get_accepted_set(cs, user_id, acc_probs);
    }
    if (prob->require_any > 0) {
      int i;
      for (i = 0; prob->require[i]; ++i) {
        int j;
        for (j = 1; j <= cs->max_prob; ++j)
          if (cs->probs[j] && !strcmp(cs->probs[j]->short_name, prob->require[i]))
            break;
        if (j <= cs->max_prob && cs->probs[j] && acc_probs[j]) break;
      }
      if (!prob->require[i]) {
        FAIL(NEW_SRV_ERR_NOT_ALL_REQ_SOLVED);
      }
    } else {
      int i;
      for (i = 0; prob->require[i]; ++i) {
        int j;
        for (j = 1; j <= cs->max_prob; ++j)
          if (cs->probs[j] && !strcmp(cs->probs[j]->short_name, prob->require[i]))
            break;
        if (j > cs->max_prob || !acc_probs[j]) break;
      }
      if (prob->require[i]) {
        FAIL(NEW_SRV_ERR_NOT_ALL_REQ_SOLVED);
      }
    }
  }

  int accept_immediately = 0;
  if (prob->type == PROB_TYPE_SELECT_ONE || prob->type == PROB_TYPE_SELECT_MANY) {
    // add this run and if we're in olympiad accepting mode mark as accepted
    if (global->score_system == SCORE_OLYMPIAD && cs->accepting_mode)
      accept_immediately = 1;
  }
  if (ns_load_problem_uuid(phr->log_f, global, prob, variant) < 0) {
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  }

  // OK, so all checks are done, now we add this submit to the database
  int db_variant = variant;
  struct timeval precise_time;
  if (admin_mode) {
    if (is_hidden < 0) is_hidden = 0;
    if (is_hidden > 1) is_hidden = 1;
  } else {
    is_hidden = 0;
    db_variant = 0;
  }

  int store_flags = 0;
  if (uuid_ptr == NULL) {
    uuid_ptr = &run_uuid;
  }
  if (global->uuid_run_store > 0 && run_get_uuid_hash_state(cs->runlog_state) >= 0) {
    store_flags = STORE_FLAGS_UUID;
    if (testing_report_bson_available()) store_flags = STORE_FLAGS_UUID_BSON;
  }
  run_id = run_add_record(cs->runlog_state,
                          &precise_time,
                          run_size, shaval, uuid_ptr,
                          &phr->ip, phr->ssl_flag,
                          phr->locale_id, user_id,
                          prob_id, lang_id, eoln_type,
                          db_variant, is_hidden, mime_type,
                          prob->uuid,
                          store_flags,
                          phr->is_job /* is_vcs */,
                          0 /* ext_user_kind */,
                          NULL /* ext_user */,
                          0 /* notify_driver */,
                          0 /* notify_kind */,
                          NULL /* notify_queue */,
                          &new_run);
  if (run_id < 0) {
    FAIL(NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
  }
  serve_move_files_to_insert_run(cs, run_id);
  if (metrics.data) {
    ++metrics.data->runs_submitted;
  }

  unsigned char run_path[PATH_MAX];
  run_path[0] = 0;
  int arch_flags = 0;
  if (store_flags == STORE_FLAGS_UUID || store_flags == STORE_FLAGS_UUID_BSON) {
    arch_flags = uuid_archive_prepare_write_path(cs, run_path, sizeof(run_path),
                                                 uuid_ptr, run_size, DFLT_R_UUID_SOURCE,
                                                 0, 0);
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
  if (p_run_id) *p_run_id = run_id;

  if (accept_immediately) {
    serve_audit_log(cs, run_id, NULL, user_id, &phr->ip, phr->ssl_flag,
                    "submit", "ok", RUN_ACCEPTED, NULL);
    run_change_status_4(cs->runlog_state, run_id, RUN_ACCEPTED, &new_run);
    serve_notify_run_update(phr->config, cs, &new_run);
    goto done;
  }

  if ((status >= 0 && status == RUN_PENDING)
      || prob->disable_auto_testing > 0
      || (prob->disable_testing > 0 && prob->enable_compilation <= 0)
      || cs->testing_suspended) {
    serve_audit_log(cs, run_id, NULL, user_id, &phr->ip, phr->ssl_flag,
                    "submit", "ok", RUN_PENDING,
                    "  Testing disabled for this problem");
    run_change_status_4(cs->runlog_state, run_id, RUN_PENDING, &new_run);
    serve_notify_run_update(phr->config, cs, &new_run);
    goto done;
  }

  const struct userlist_user *user = teamdb_get_userlist(cs->teamdb_state, phr->user_id);

  if (prob->type == PROB_TYPE_STANDARD) {
    if (lang->disable_auto_testing > 0 || lang->disable_testing > 0) {
      serve_audit_log(cs, run_id, NULL, user_id, &phr->ip, phr->ssl_flag,
                      "submit", "ok", RUN_PENDING,
                      "  Testing disabled for this language");
      run_change_status_4(cs->runlog_state, run_id, RUN_PENDING, &new_run);
      serve_notify_run_update(phr->config, cs, &new_run);
      goto done;
    }

    serve_audit_log(cs, run_id, NULL, user_id, &phr->ip, phr->ssl_flag,
                    "submit", "ok", RUN_COMPILING, NULL);
    r = serve_compile_request(phr->config, cs, run_text, run_size, cnts->id,
                              run_id, 0 /* submit_id */, user_id,
                              variant,
                              phr->locale_id, 0 /* output_only */,
                              lang->src_sfx,
                              0 /* style_check_only */,
                              -1 /* accepting_mode */,
                              0 /* priority_adjustment */,
                              1 /* notify_flag */, prob, lang,
                              0 /* no_db_flag */, &run_uuid,
                              NULL /* judge_uuid */,
                              store_flags,
                              0 /* rejudge_flag */,
                              phr->is_job,
                              0 /* not_ok_is_cf */,
                              user,
                              &new_run);
    if (r < 0) {
      serve_report_check_failed(ejudge_config, cnts, cs, run_id, serve_err_str(r));
      goto cleanup;
    }
    goto done;
  }

  /* manually checked problems */
  if (prob->manual_checking > 0) {
    if (prob->check_presentation <= 0) {
      serve_audit_log(cs, run_id, NULL, user_id, &phr->ip, phr->ssl_flag,
                      "submit", "ok", RUN_ACCEPTED,
                      "  This problem is checked manually");
      run_change_status_4(cs->runlog_state, run_id, RUN_ACCEPTED, &new_run);
      serve_notify_run_update(phr->config, cs, &new_run);
      goto done;
    }

    if (prob->style_checker_cmd && prob->style_checker_cmd[0]) {
      serve_audit_log(cs, run_id, NULL, user_id, &phr->ip, phr->ssl_flag,
                      "submit", "ok", RUN_COMPILING, NULL);
      r = serve_compile_request(phr->config, cs, run_text, run_size, cnts->id,
                                run_id, 0 /* submit_id */, user_id,
                                variant,
                                0 /* locale_id */, 1 /* output_only */,
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
                                &new_run);
      if (r < 0) {
        serve_report_check_failed(ejudge_config, cnts, cs, run_id, serve_err_str(r));
        goto cleanup;
      }
      goto done;
    }

    serve_audit_log(cs, run_id, NULL, user_id, &phr->ip, phr->ssl_flag,
                    "submit", "ok", RUN_RUNNING, NULL);
    r = serve_run_request(phr->config, cs, cnts, log_f, run_text, run_size,
                          cnts->id, run_id,
                          0 /* submit_id */,
                          user_id, prob_id, 0, variant, 0,
                          -1,   /* judge_id */
                          NULL, /* judge_uuid */
                          -1, 1,
                          mime_type, 0, phr->locale_id, 0, 0, 0, &run_uuid,
                          0 /* rejudge_flag */, 0 /* zip_mode */, store_flags,
                          0 /* not_ok_is_cf */,
                          NULL, 0,
                          &new_run,
                          NULL /* src_text */,
                          0 /* src_size */);
    if (r < 0) {
      serve_report_check_failed(ejudge_config, cnts, cs, run_id, serve_err_str(r));
      goto cleanup;
    }
    goto done;
  }

  /* built-in problem checker */
  problem_xml_t px = NULL;
  if (prob->variant_num > 0 && prob->xml.a && variant > 0) {
    px = prob->xml.a[variant - 1];
  } else if (prob->variant_num <= 0) {
    px = prob->xml.p;
  }
  if (px && px->ans_num > 0) {
    struct run_entry re;
    run_get_entry(cs->runlog_state, run_id, &re);
    serve_audit_log(cs, run_id, &re, user_id, &phr->ip, phr->ssl_flag,
                    "submit", "ok", RUN_RUNNING, NULL);
    serve_judge_built_in_problem(extra, ejudge_config, cs, cnts, run_id,
                                 1 /* judge_id */,
                                 NULL, /* judge_uuid */
                                 variant, cs->accepting_mode, &re,
                                 prob, px, user_id, &phr->ip,
                                 phr->ssl_flag);
    goto done;
  }

  if (prob->style_checker_cmd && prob->style_checker_cmd[0]) {
    r = serve_compile_request(phr->config, cs, run_text, run_size, cnts->id,
                              run_id, 0 /* submit_id */, user_id,
                              variant,
                              0 /* locale_id */, 1 /* output_only */,
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
                              &new_run);
    if (r < 0) {
      serve_report_check_failed(ejudge_config, cnts, cs, run_id, serve_err_str(r));
      goto cleanup;
    }
    goto done;
  }

  r = serve_run_request(phr->config, cs, cnts, log_f, run_text, run_size,
                        cnts->id, run_id,
                        0 /* submit_id */,
                        user_id, prob_id, 0, variant, 0,
                        -1,     /* judge_id */
                        NULL,   /* judge_uuid */
                        -1, 1,
                        mime_type, 0, phr->locale_id, 0, 0, 0, &run_uuid,
                        0 /* rejudge_flag */, 0 /* zip_mode */, store_flags,
                        0 /* not_ok_is_cf */,
                        NULL, 0,
                        &new_run,
                        NULL /* src_text */,
                        0 /* src_size */);
  if (r < 0) {
    serve_report_check_failed(ejudge_config, cnts, cs, run_id, serve_err_str(r));
    goto cleanup;
  }

done:
  if (global->problem_navigation > 0) {
    int i = prob->id;
    if (prob->advance_to_next > 0) {
      for (++i; i <= cs->max_prob; ++i) {
        const struct section_problem_data *prob2 = cs->probs[i];
        if (!prob2) continue;
        if (!serve_is_problem_started(cs, user_id, prob2)) continue;
        // FIXME: standard applicability checks
        break;
      }
      if (i > cs->max_prob) i = 0;
    }
    if (p_next_prob_id) *p_next_prob_id = i;
  }

cleanup:
  xfree(ans_text);
  xfree(utf8_str);
  xfree(run_file);
  return retval;
}

#define FAIL2(err) do { retval = -(err); goto fail; } while (0)

static void
unpriv_submit_run(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = 0, *prob2;
  const struct section_language_data *lang = 0;
  int prob_id, n, lang_id = 0, i, ans, max_ans, j, r;
  const unsigned char *s, *run_text = 0, *text_form_text = 0;
  size_t run_size = 0, ans_size, text_form_size = 0;
  unsigned char *ans_buf, *ans_map, *ans_tmp;
  time_t start_time, stop_time, user_deadline = 0;
  const unsigned char *mime_type_str = 0;
  char **lang_list;
  int mime_type = 0;
  ruint32_t shaval[5];
  int variant = 0, run_id = 0, arch_flags = 0;
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
  unsigned char *utf8_str = 0;
  int utf8_len = 0;
  int eoln_type = 0;
  int retval = 0;
  int rejudge_flag = 0;
  int priority_adjustment = 0;
  struct run_entry new_run;

  l10n_setlocale(phr->locale_id);

  if (hr_cgi_param(phr, "prob_id", &s) <= 0
      || sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n]
      || prob_id <= 0 || prob_id > cs->max_prob
      || !(prob = cs->probs[prob_id])) {
    FAIL2(NEW_SRV_ERR_INV_PROB_ID);
  }

  if (prob->disable_user_submit > 0) {
    FAIL2(NEW_SRV_ERR_PERMISSION_DENIED);
  }

  // "STANDARD" problems need programming language identifier
  if (prob->type == PROB_TYPE_STANDARD) {
    int r = hr_cgi_param(phr, "lang_id", &s);
    if (r < 0) {
      FAIL2(NEW_SRV_ERR_INV_LANG_ID);
    }
    if (!r || !s) {
      if (prob->custom_compile_cmd && prob->custom_compile_cmd[0]) {
        for (r = 1; r <= cs->max_lang; ++r) {
          if (cs->langs[r] && cs->langs[r]->enable_custom > 0) {
            break;
          }
        }
        if (r <= cs->max_lang) {
          lang_id = r;
          lang = cs->langs[r];
        } else {
          FAIL2(NEW_SRV_ERR_INV_LANG_ID);
        }
      } else {
        FAIL2(NEW_SRV_ERR_INV_LANG_ID);
      }
    } else {
      errno = 0;
      char *eptr = NULL;
      long v = strtol(s, &eptr, 10);
      if (!errno && eptr != (char *)s && !*eptr && (int) v == v) {
        lang_id = v;
        if (lang_id <= 0 || lang_id > cs->max_lang || !(lang = cs->langs[lang_id])) {
          FAIL2(NEW_SRV_ERR_INV_LANG_ID);
        }
      } else {
        for (int i = 1; i <= cs->max_lang; ++i) {
          lang = cs->langs[i];
          if (lang /* && lang->short_name */ && !strcmp(lang->short_name, s)) {
            lang_id = i;
            break;
          }
          lang = NULL;
        }
        if (!lang) {
          FAIL2(NEW_SRV_ERR_INV_LANG_ID);
        }
      }
    }
    /*
    if (hr_cgi_param(phr, "lang_id", &s) <= 0
        || sscanf(s, "%d%n", &lang_id, &n) != 1 || s[n]
        || lang_id <= 0 || lang_id > cs->max_lang
        || !(lang = cs->langs[lang_id])) {
      FAIL2(NEW_SRV_ERR_INV_LANG_ID);
    }
    */
    if (global->enable_eoln_select > 0) {
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

  switch (prob->type) {
    /*
  case PROB_TYPE_STANDARD:      // "file"
    if (!ns_cgi_param_bin(phr, "file", &run_text, &run_size)) {
      ns_error(log_f, NEW_SRV_ERR_FILE_UNSPECIFIED);
      goto done;
    }
    break;
    */
  case PROB_TYPE_STANDARD:
  case PROB_TYPE_OUTPUT_ONLY:
  case PROB_TYPE_TESTS:
    if (prob->enable_text_form > 0) {
      int r1 = hr_cgi_param_bin(phr, "file", &run_text, &run_size);
      int r2 =hr_cgi_param_bin(phr,"text_form",&text_form_text,&text_form_size);
      if (!r1 && !r2) {
        FAIL2(NEW_SRV_ERR_FILE_UNSPECIFIED);
      }
      if (!run_text) run_text = "";
    } else {
      if (!hr_cgi_param_bin(phr, "file", &run_text, &run_size)) {
        FAIL2(NEW_SRV_ERR_FILE_UNSPECIFIED);
      }
    }
    break;
  case PROB_TYPE_TEXT_ANSWER:
  case PROB_TYPE_SHORT_ANSWER:
  case PROB_TYPE_SELECT_ONE:
    if (!hr_cgi_param_bin(phr, "file", &run_text, &run_size)) {
      FAIL2(NEW_SRV_ERR_ANSWER_UNSPECIFIED);
    }
    break;
  case PROB_TYPE_SELECT_MANY:   // "ans_*"
    for (i = 0, max_ans = -1, ans_size = 0; i < phr->param_num; i++)
      if (!strncmp(phr->param_names[i], "ans_", 4)) {
        if (sscanf(phr->param_names[i] + 4, "%d%n", &ans, &n) != 1
            || phr->param_names[i][4 + n]
            || ans < 0 || ans > 65535) {
          FAIL2(NEW_SRV_ERR_INV_ANSWER);
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
      FAIL2(NEW_SRV_ERR_PLUGIN_NOT_AVAIL);
    }
    ans_tmp = (*plg->parse_form)(cs->prob_extras[prob_id].plugin_data,
                                 phr->log_f, phr, cnts, extra);
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

  switch (prob->type) {
  case PROB_TYPE_STANDARD:
    if (!lang->binary && strlen(run_text) != run_size) {
      // guess utf-16/ucs-2
      if (((int) run_size) < 0
          || (utf8_len = ucs2_to_utf8(&utf8_str, run_text, run_size)) < 0) {
        FAIL2(NEW_SRV_ERR_BINARY_FILE);
      }
      run_text = utf8_str;
      run_size = (size_t) utf8_len;
    }
    if (prob->enable_text_form > 0 && text_form_text
        && strlen(text_form_text) != text_form_size) {
      FAIL2(NEW_SRV_ERR_BINARY_FILE);
    }
    if (prob->enable_text_form) {
      if (!run_size && !text_form_size) {
        FAIL2(NEW_SRV_ERR_SUBMIT_EMPTY);
      }
      if (!run_size) {
        run_text = text_form_text;
        run_size = text_form_size;
        skip_mime_type_test = 1;
      } else {
        text_form_text = 0;
        text_form_size = 0;
      }
    } else if (!run_size) {
      FAIL2(NEW_SRV_ERR_SUBMIT_EMPTY);
    }
    if (prob->disable_ctrl_chars > 0 && has_control_characters(run_text)) {
      FAIL2(NEW_SRV_ERR_INV_CHAR);
    }
    break;
  case PROB_TYPE_OUTPUT_ONLY:
  case PROB_TYPE_TESTS:
    if (!prob->binary_input && !prob->binary && strlen(run_text) != run_size) {
      FAIL2(NEW_SRV_ERR_BINARY_FILE);
    }
    if (prob->enable_text_form > 0 && text_form_text
        && strlen(text_form_text) != text_form_size) {
      FAIL2(NEW_SRV_ERR_BINARY_FILE);
    }
    if (prob->enable_text_form > 0) {
      if (!run_size && !text_form_size) {
        FAIL2(NEW_SRV_ERR_SUBMIT_EMPTY);
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
      FAIL2(NEW_SRV_ERR_BINARY_FILE);
    }
    if (!run_size) {
      FAIL2(NEW_SRV_ERR_SUBMIT_EMPTY);
    }
    break;

  case PROB_TYPE_SELECT_MANY:
    if (strlen(run_text) != run_size) {
      FAIL2(NEW_SRV_ERR_BINARY_FILE);
    }
    break;

  case PROB_TYPE_CUSTOM:
    break;
  }

  // ignore BOM
  if (global->ignore_bom > 0 && !prob->binary && (!lang || !lang->binary)) {
    if (run_text && run_size >= 3 && run_text[0] == 0xef
        && run_text[1] == 0xbb && run_text[2] == 0xbf) {
      run_text += 3; run_size -= 3;
    }
  }

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
  }

  if (cs->clients_suspended) {
    FAIL2(NEW_SRV_ERR_CLIENTS_SUSPENDED);
  }
  if (!start_time && !cs->upsolving_mode) {
    FAIL2(NEW_SRV_ERR_CONTEST_NOT_STARTED);
  }
  if (stop_time && !cs->upsolving_mode) {
    FAIL2(NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
  }
  if (serve_check_user_quota(cs, phr->user_id, run_size) < 0) {
    FAIL2(NEW_SRV_ERR_RUN_QUOTA_EXCEEDED);
  }
  // problem submit start time
  if (!serve_is_problem_started(cs, phr->user_id, prob)) {
    FAIL2(NEW_SRV_ERR_PROB_UNAVAILABLE);
  }
  int is_deadlined = serve_is_problem_deadlined(cs, phr->user_id, phr->login, prob, &user_deadline);
  if (is_deadlined && prob->enable_submit_after_reject > 0) {
    int ok_count = 0;
    int rejected_count = 0;
    run_get_ok_and_reject_count(cs->runlog_state, phr->user_id, prob_id, &ok_count, &rejected_count);
    if (rejected_count > 0 && ok_count <= 0) is_deadlined = 0;
    user_deadline = 0;
  }

  if (is_deadlined) {
    FAIL2(NEW_SRV_ERR_PROB_DEADLINE_EXPIRED);
  }

  if (prob->max_user_run_count > 0) {
    int ignored_set = 0;
    if (prob->ignore_compile_errors > 0) ignored_set |= 1 << RUN_COMPILE_ERR;
    ignored_set |= 1 << RUN_IGNORED;
    if (run_count_all_attempts_2(cs->runlog_state, phr->user_id, prob_id, ignored_set) >= prob->max_user_run_count) {
      FAIL2(NEW_SRV_ERR_PROB_TOO_MANY_ATTEMPTS);
    }
  }

  int testing_count = run_count_all_attempts_3(cs->runlog_state, phr->user_id, prob_id);
  if (prob->enable_dynamic_priority > 0 && testing_count > 0) {
    //rejudge_flag = 1;
    priority_adjustment = (testing_count - 1) / 2 + 3;
    if (priority_adjustment > 12) priority_adjustment = 12;
  }

  /* check for disabled languages */
  if (lang_id > 0) {
    if (lang->disabled || (prob->enable_container <= 0 && lang->insecure > 0 && global->secure_run)) {
      FAIL2(NEW_SRV_ERR_LANG_DISABLED);
    }

    if (prob->enable_language) {
      lang_list = prob->enable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], lang->short_name))
          break;
      if (!lang_list[i]) {
        FAIL2(NEW_SRV_ERR_LANG_NOT_AVAIL_FOR_PROBLEM);
      }
    } else if (prob->disable_language) {
      lang_list = prob->disable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], lang->short_name))
          break;
      if (lang_list[i]) {
        FAIL2(NEW_SRV_ERR_LANG_DISABLED_FOR_PROBLEM);
      }
    }
  } else if (skip_mime_type_test) {
    mime_type = 0;
    mime_type_str = mime_type_get_type(mime_type);
  } else {
    // guess the content-type and check it against the list
    if ((mime_type = mime_type_guess(cs->global->diff_work_dir,
                                     run_text, run_size)) < 0) {
      FAIL2(NEW_SRV_ERR_CANNOT_DETECT_CONTENT_TYPE);
    }
    mime_type_str = mime_type_get_type(mime_type);
    if (prob->enable_language) {
      lang_list = prob->enable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], mime_type_str))
          break;
      if (!lang_list[i]) {
        FAIL2(NEW_SRV_ERR_CONTENT_TYPE_NOT_AVAILABLE);
      }
    } else if (prob->disable_language) {
      lang_list = prob->disable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], mime_type_str))
          break;
      if (lang_list[i]) {
        FAIL2(NEW_SRV_ERR_CONTENT_TYPE_DISABLED);
      }
    }
  }

  if (prob->variant_num > 0) {
    if ((variant = find_variant(cs, phr->user_id, prob_id, 0)) <= 0) {
      FAIL2(NEW_SRV_ERR_VARIANT_UNASSIGNED);
    }
  }

  sha_buffer(run_text, run_size, shaval);
  if (global->ignore_duplicated_runs != 0) {
    if ((run_id = run_find_duplicate(cs->runlog_state, phr->user_id, prob_id,
                                     lang_id, variant, run_size, shaval)) >= 0){
      FAIL2(NEW_SRV_ERR_DUPLICATE_SUBMIT);
    }
  }

  if (prob->disable_submit_after_ok
      && global->score_system != SCORE_OLYMPIAD && !cs->accepting_mode) {
    XALLOCAZ(acc_probs, cs->max_prob + 1);
    ns_get_accepted_set(cs, phr->user_id, acc_probs);
    if (acc_probs[prob_id]) {
      FAIL2(NEW_SRV_ERR_PROB_ALREADY_SOLVED);
    }
  }

  if (prob->require) {
    if (!acc_probs) {
      XALLOCAZ(acc_probs, cs->max_prob + 1);
      ns_get_accepted_set(cs, phr->user_id, acc_probs);
    }
    if (prob->require_any > 0) {
      for (i = 0; prob->require[i]; ++i) {
        for (j = 1; j <= cs->max_prob; ++j)
          if (cs->probs[j] && !strcmp(cs->probs[j]->short_name, prob->require[i]))
            break;
        if (j <= cs->max_prob && cs->probs[j] && acc_probs[j]) break;
      }
      if (!prob->require[i]) {
        FAIL(NEW_SRV_ERR_NOT_ALL_REQ_SOLVED);
      }
    } else {
      for (i = 0; prob->require[i]; i++) {
        for (j = 1; j <= cs->max_prob; j++)
          if (cs->probs[j] && !strcmp(cs->probs[j]->short_name, prob->require[i]))
            break;
        if (j > cs->max_prob || !acc_probs[j]) break;
      }
      if (prob->require[i]) {
        FAIL2(NEW_SRV_ERR_NOT_ALL_REQ_SOLVED);
      }
    }
  }

  if (prob->type == PROB_TYPE_SELECT_ONE) {
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
      FAIL2(NEW_SRV_ERR_INV_ANSWER);
    }

    // add this run and if we're in olympiad accepting mode mark
    // as accepted
    if (global->score_system == SCORE_OLYMPIAD && cs->accepting_mode)
      accept_immediately = 1;
  }
  if (ns_load_problem_uuid(phr->log_f, global, prob, variant) < 0) {
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  }

  // OK, so all checks are done, now we add this submit to the database
  ej_uuid_t run_uuid = {};
  int store_flags = 0;
  if (global->uuid_run_store > 0 && run_get_uuid_hash_state(cs->runlog_state) >= 0) {
    store_flags = STORE_FLAGS_UUID;
    if (testing_report_bson_available()) store_flags = STORE_FLAGS_UUID_BSON;
  }
  int is_hidden = 0;
  if (cs->upsolving_mode) {
    if (start_time <= 0 || cs->current_time < start_time) {
      is_hidden = 1;
    } else if (stop_time > 0 && cs->current_time >= stop_time) {
      is_hidden = 1;
    }
  }
  run_id = run_add_record(cs->runlog_state,
                          &precise_time,
                          run_size, shaval, &run_uuid,
                          &phr->ip, phr->ssl_flag,
                          phr->locale_id, phr->user_id,
                          prob_id, lang_id, eoln_type,
                          0 /* variant */,
                          is_hidden,
                          mime_type,
                          prob->uuid,
                          store_flags,
                          phr->is_job /* is_vcs */,
                          0 /* ext_user_kind */,
                          NULL /* ext_user */,
                          0 /* notify_driver */,
                          0 /* notify_kind */,
                          NULL /* notify_queue */,
                          &new_run);
  if (run_id < 0) {
    FAIL2(NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
  }
  serve_move_files_to_insert_run(cs, run_id);
  if (metrics.data) {
    ++metrics.data->runs_submitted;
  }

  if (store_flags == STORE_FLAGS_UUID || store_flags == STORE_FLAGS_UUID_BSON) {
    arch_flags = uuid_archive_prepare_write_path(cs, run_path, sizeof(run_path),
                                                 &run_uuid, run_size, DFLT_R_UUID_SOURCE,
                                                 0, 0);
  } else {
    arch_flags = archive_prepare_write_path(cs, run_path, sizeof(run_path),
                                            global->run_archive_dir, run_id,
                                            run_size, NULL, 0, 0);
  }
  if (arch_flags < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    FAIL2(NEW_SRV_ERR_DISK_WRITE_ERROR);
  }

  if (generic_write_file(run_text, run_size, arch_flags, 0, run_path, "") < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    FAIL2(NEW_SRV_ERR_DISK_WRITE_ERROR);
  }

  const struct userlist_user *user = teamdb_get_userlist(cs->teamdb_state, phr->user_id);

  if (prob->type == PROB_TYPE_STANDARD) {
    if (prob->disable_auto_testing > 0
        || (prob->disable_testing > 0 && prob->enable_compilation <= 0)
        || lang->disable_auto_testing || lang->disable_testing
        || cs->testing_suspended) {
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
                                     0 /* style_check_only */,
                                     -1 /* accepting_mode */,
                                     priority_adjustment,
                                     1 /* notify_flag */,
                                     prob, lang,
                                     0 /* no_db_flag*/ ,
                                     &run_uuid,
                                     NULL /* judge_uuid */,
                                     store_flags,
                                     rejudge_flag,
                                     phr->is_job,
                                     0 /* not_ok_is_cf */,
                                     user,
                                     &new_run)) < 0) {
        serve_report_check_failed(ejudge_config, cnts, cs, run_id, serve_err_str(r));
      }
    }
  } else if (prob->manual_checking > 0 && !accept_immediately) {
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
        r = serve_compile_request(phr->config, cs, run_text, run_size, cnts->id,
                                  run_id, 0 /* submit_id */, phr->user_id,
                                  variant,
                                  0 /* locale_id */, 1 /* output_only*/,
                                  mime_type_get_suffix(mime_type),
                                  1 /* style_check_only */,
                                  0 /* accepting_mode */,
                                  priority_adjustment,
                                  0 /* notify flag */,
                                  prob, NULL /* lang */,
                                  0 /* no_db_flag */, &run_uuid,
                                  NULL /* judge_uuid */,
                                  store_flags,
                                  rejudge_flag,
                                  phr->is_job,
                                  0 /* not_ok_is_cf */,
                                  user,
                                  &new_run);
        if (r < 0) {
          serve_report_check_failed(ejudge_config, cnts, cs, run_id, serve_err_str(r));
        }
      } else {
        if (serve_run_request(phr->config, cs, cnts, phr->log_f, run_text, run_size,
                              cnts->id, run_id,
                              0 /* submit_id */,
                              phr->user_id, prob_id, 0, variant, 0,
                              -1, /* judge_id */
                              NULL, /* judge_uuid */
                              -1, 1,
                              mime_type, 0, phr->locale_id, 0, 0, 0, &run_uuid,
                              rejudge_flag, 0 /* zip_mode */,
                              store_flags,
                              0 /* not_ok_is_cf */,
                              NULL, 0,
                              &new_run,
                              NULL /* src_text */,
                              0 /* src_size */) < 0) {
          FAIL2(NEW_SRV_ERR_DISK_WRITE_ERROR);
        }
      }
    }
  } else {
    if (accept_immediately) {
      serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                      "submit", "ok", RUN_ACCEPTED, NULL);
      run_change_status_4(cs->runlog_state, run_id, RUN_ACCEPTED, &new_run);
      serve_notify_run_update(phr->config, cs, &new_run);
    } else if (prob->disable_auto_testing > 0
        || (prob->disable_testing > 0 && prob->enable_compilation <= 0)) {
      serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                      "submit", "ok", RUN_PENDING,
                      "  Testing disabled for this problem");
      run_change_status_4(cs->runlog_state, run_id, RUN_PENDING, &new_run);
      serve_notify_run_update(phr->config, cs, &new_run);
    } else {
      if (prob->variant_num > 0 && prob->xml.a) {
        px = prob->xml.a[variant -  1];
      } else {
        px = prob->xml.p;
      }
      if (px && px->ans_num > 0) {
        run_get_entry(cs->runlog_state, run_id, &re);
        serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                        "submit", "ok", RUN_RUNNING, NULL);
        serve_judge_built_in_problem(extra, ejudge_config, cs, cnts, run_id,
                                     1 /* judge_id */,
                                     NULL, /* judge_uuid */
                                     variant, cs->accepting_mode, &re,
                                     prob, px, phr->user_id, &phr->ip,
                                     phr->ssl_flag);
        goto done;
      }

      if (prob->style_checker_cmd && prob->style_checker_cmd[0]) {
        serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                        "submit", "ok", RUN_COMPILING, NULL);

        r = serve_compile_request(phr->config, cs, run_text, run_size, cnts->id,
                                  run_id, 0 /* submit_id */, phr->user_id,
                                  variant,
                                  0 /* locale_id */, 1 /* output_only*/,
                                  mime_type_get_suffix(mime_type),
                                  1 /* style_check_only */,
                                  0 /* accepting_mode */,
                                  priority_adjustment,
                                  0 /* notify flag */,
                                  prob, NULL /* lang */,
                                  0 /* no_db_flag */, &run_uuid,
                                  NULL /* judge_uuid */,
                                  store_flags,
                                  rejudge_flag,
                                  phr->is_job,
                                  0 /* not_ok_is_cf */,
                                  user,
                                  &new_run);
        if (r < 0) {
          serve_report_check_failed(ejudge_config, cnts, cs, run_id, serve_err_str(r));
        }
      } else {
        serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                        "submit", "ok", RUN_RUNNING, NULL);

        if (serve_run_request(phr->config, cs, cnts, phr->log_f, run_text, run_size,
                              cnts->id, run_id,
                              0 /* submit_id */,
                              phr->user_id, prob_id, 0, variant, 0,
                              -1, /* judge_id */
                              NULL, /* judge_uuid */
                              -1, 1,
                              mime_type, 0, phr->locale_id, 0, 0, 0, &run_uuid,
                              rejudge_flag, 0 /* zip_mode */,
                              store_flags,
                              0 /* not_ok_is_cf */,
                              NULL, 0,
                              &new_run,
                              NULL /* src_text */,
                              0 /* src_size */) < 0) {
          FAIL2(NEW_SRV_ERR_DISK_WRITE_ERROR);
        }
      }
    }
  }

 done:;
  i = 0;
  if (global->problem_navigation) {
    i = prob->id;
    if (prob->advance_to_next > 0) {
      for (i++; i <= cs->max_prob; i++) {
        if (!(prob2 = cs->probs[i])) continue;
        if (!serve_is_problem_started(cs, phr->user_id, prob2))
          continue;
        // FIXME: standard applicability checks
        break;
      }
      if (i > cs->max_prob) i = 0;
    }
  }
  if (phr->json_reply) {
    fprintf(fout, "{\n");
    fprintf(fout, "  \"ok\" : %s", "true");
    fprintf(fout, ",\n  \"server_time\": %lld", (long long) cs->current_time);
    fprintf(fout, ",\n  \"result\": {");
    fprintf(fout, "\n    \"run_id\": %d", run_id);
    fprintf(fout, ",\n    \"run_uuid\": \"%s\"", ej_uuid_unparse(&run_uuid, ""));
    fprintf(fout, "\n  }");
    fprintf(fout, "\n}");
  } else {
    if (i > 0) {
      snprintf(bb, sizeof(bb), "prob_id=%d", i);
      ns_refresh_page(fout, phr, NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT, bb);
    }  else {
      ns_refresh_page(fout, phr, NEW_SRV_ACTION_VIEW_SUBMISSIONS, 0);
    }
  }

cleanup:;
  l10n_resetlocale();
  xfree(utf8_str);
  return;

fail:
  error_page(fout, phr, 0, -retval);
  goto cleanup;
}

static void
emit_json_result(
        FILE *fout,
        struct http_request_info *phr,
        int ok,
        int err_num,
        unsigned err_id,
        const unsigned char *err_msg,
        cJSON *jr)
{
  phr->json_reply = 1;
  if (!ok) {
    if (err_num < 0) err_num = -err_num;
    if (!err_id) {
      random_init();
      err_id = random_u32();
    }
    if (!err_msg || !*err_msg) {
      err_msg = NULL;
      if (err_num > 0) {
        err_msg = ns_error_title_2(err_num);
        if (err_msg && !*err_msg) {
          err_msg = NULL;
        }
      }
    }
    cJSON_AddFalseToObject(jr, "ok");
    cJSON *jerr = cJSON_CreateObject();
    if (err_num > 0) {
      cJSON_AddNumberToObject(jerr, "num", err_num);
      cJSON_AddStringToObject(jerr, "symbol", ns_error_symbol(err_num));
    }
    if (err_id) {
      char xbuf[64];
      sprintf(xbuf, "%08x", err_id);
      cJSON_AddStringToObject(jerr, "log_id", xbuf);
    }
    if (err_msg) {
      cJSON_AddStringToObject(jerr, "message", err_msg);
    }
    cJSON_AddItemToObject(jr, "error", jerr);
    // FIXME: log event
  } else {
    cJSON_AddTrueToObject(jr, "ok");
  }
  cJSON_AddNumberToObject(jr, "server_time", (double) phr->current_time);
  if (phr->request_id > 0) {
    cJSON_AddNumberToObject(jr, "request_id", (double) phr->request_id);
  }
  if (phr->action > 0 && phr->action < NEW_SRV_ACTION_LAST && ns_symbolic_action_table[phr->action]) {
    cJSON_AddStringToObject(jr, "action", ns_symbolic_action_table[phr->action]);
  }
  if (phr->client_state && phr->client_state->ops->get_reply_id) {
    int reply_id = phr->client_state->ops->get_reply_id(phr->client_state);
    cJSON_AddNumberToObject(jr, "reply_id", (double) reply_id);
  }
  char *jrstr = cJSON_PrintUnformatted(jr);
  fprintf(fout, "%s\n", jrstr);
  free(jrstr);
}

static void
ns_submit_run_input(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int admin_mode)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  int ok = 0;
  int err_num = 0;
  unsigned char *err_msg = 0;
  unsigned err_id = 0;
  cJSON *jr = cJSON_CreateObject(); // reply object
  const unsigned char *s;
  int prob_id;
  const struct section_problem_data *prob = NULL;
  int lang_id;
  const struct section_language_data *lang = NULL;
  int eoln_type = 0;
  const unsigned char *run_text = NULL;
  ssize_t run_size = 0;
  size_t tmpsz;
  int r;
  const unsigned char *inp_text = NULL;
  ssize_t inp_size = 0;
  unsigned char *acc_probs = NULL;
  struct storage_entry src_se = {};
  struct storage_entry inp_se = {};
  struct submit_entry se = {};
  const struct userlist_user *user = teamdb_get_userlist(cs->teamdb_state, phr->user_id);
  struct submit_entry *ses = NULL;
  size_t sez = 0;
  struct submit_totals st = {};
  unsigned char *run_fixed_text = NULL;
  unsigned char *inp_fixed_text = NULL;
  int sender_user_id = 0;
  ej_ip_t sender_ip = {};
  int sender_ssl_flag = 0;
  int ext_user_kind = 0;
  ej_mixed_id_t ext_user = {};
  int notify_driver = 0;
  int notify_kind = 0;
  ej_mixed_id_t notify_queue = {};

  if (admin_mode) {
    if (opcaps_check(phr->caps, OPCAP_SUBMIT_RUN) < 0) {
      err_num = NEW_SRV_ERR_PERMISSION_DENIED;
      goto done;
    }

    if (hr_cgi_param(phr, "sender_user_login", &s) > 0) {
      if (opcaps_check(phr->caps, OPCAP_EDIT_RUN) < 0) {
        err_num = NEW_SRV_ERR_PERMISSION_DENIED;
        goto done;
      }
      if ((sender_user_id = teamdb_lookup_login(cs->teamdb_state, s)) <= 0) {
        err_num = NEW_SRV_ERR_INV_USER_ID;
        goto done;
      }
    } else if (hr_cgi_param_int_opt(phr, "sender_user_id", &sender_user_id, -1) >= 0 && sender_user_id > 0) {
      if (opcaps_check(phr->caps, OPCAP_EDIT_RUN) < 0) {
        err_num = NEW_SRV_ERR_PERMISSION_DENIED;
        goto done;
      }
      if (teamdb_lookup(cs->teamdb_state, sender_user_id) <= 0) {
        err_num = NEW_SRV_ERR_INV_USER_ID;
        goto done;
      }
    }
    if (sender_user_id <= 0) sender_user_id = phr->user_id;

    if (hr_cgi_param(phr, "sender_ip", &s) > 0) {
      if (!strcmp(s, "::1")) s = "127.0.0.1";
      if (xml_parse_ipv6(NULL, 0, 0, 0, s, &sender_ip) < 0) {
        //fprintf(phr->log_f, "cannot parse sender_ip");
        err_num = NEW_SRV_ERR_INV_PARAM;
        goto done;
      }
      hr_cgi_param_int_opt(phr, "sender_ssl_flag", &sender_ssl_flag, 0);
    } else {
      sender_ip = phr->ip;
      sender_ssl_flag = phr->ssl_flag;
    }

    if (hr_cgi_param(phr, "ext_user_kind", &s) > 0) {
      ext_user_kind = mixed_id_parse_kind(s);
      if (ext_user_kind < 0 || ext_user_kind >= MIXED_ID_LAST) {
        err_num = NEW_SRV_ERR_INV_EXT_USER;
        goto done;
      }
      if (ext_user_kind > 0) {
        if (hr_cgi_param(phr, "ext_user", &s) <= 0) {
          err_num = NEW_SRV_ERR_INV_EXT_USER;
          goto done;
        }
        if (mixed_id_unmarshall(&ext_user, ext_user_kind, s) < 0) {
          err_num = NEW_SRV_ERR_INV_EXT_USER;
          goto done;
        }
      }
    }

    hr_cgi_param_int_opt(phr, "notify_driver", &notify_driver, 0);
    if (notify_driver < 0 || notify_driver > 127) {
      err_num = NEW_SRV_ERR_INV_NOTIFY;
      goto done;
    }
    if (notify_driver > 0) {
      if (!notify_plugin_get(phr->config, notify_driver)) {
        err_num = NEW_SRV_ERR_INV_NOTIFY;
        goto done;
      }
      if (hr_cgi_param(phr, "notify_kind", &s) <= 0) {
        err_num = NEW_SRV_ERR_INV_NOTIFY;
        goto done;
      }
      notify_kind = mixed_id_parse_kind(s);
      if (notify_kind < 0 || notify_kind >= MIXED_ID_LAST) {
        err_num = NEW_SRV_ERR_INV_NOTIFY;
        goto done;
      }
      if (notify_kind > 0) {
        if (hr_cgi_param(phr, "notify_queue", &s) <= 0) {
          err_num = NEW_SRV_ERR_INV_NOTIFY;
          goto done;
        }
        if (mixed_id_unmarshall(&notify_queue, notify_kind, s) < 0) {
          err_num = NEW_SRV_ERR_INV_NOTIFY;
          goto done;
        }
      }
    }
  } else {
    // unprivileged mode
    sender_user_id = phr->user_id;
    sender_ip = phr->ip;
    sender_ssl_flag = phr->ssl_flag;
  }

  // parse prob_id
  if (hr_cgi_param(phr, "prob_id", &s) <= 0 || !s) {
    err_num = NEW_SRV_ERR_INV_PROB_ID;
    goto done;
  }
  for (prob_id = 1; prob_id <= cs->max_prob; ++prob_id) {
    if ((prob = cs->probs[prob_id]) && !strcmp(s, prob->short_name))
      break;
  }
  if (prob_id > cs->max_prob) {
    char *eptr = NULL;
    errno = 0;
    long v = strtol(s, &eptr, 10);
    if (errno || *eptr || (unsigned char *) eptr == s || (int) v != v) {
      err_num = NEW_SRV_ERR_INV_PROB_ID;
      goto done;
    }
    prob_id = v;
  }
  if (prob_id <= 0 || prob_id > cs->max_prob || !(prob = cs->probs[prob_id])) {
    err_num = NEW_SRV_ERR_INV_PROB_ID;
    goto done;
  }
  if (prob->type != PROB_TYPE_STANDARD || prob->enable_user_input <= 0) {
    err_num = NEW_SRV_ERR_INV_PROB_ID;
    goto done;
  }

  // parse lang_id
  r = hr_cgi_param(phr, "lang_id", &s);
  if (r < 0) {
    err_num = NEW_SRV_ERR_INV_LANG_ID;
    goto done;
  } else if (!r || !s) {
    if (prob->custom_compile_cmd && prob->custom_compile_cmd[0]) {
      for (r = 1; r <= cs->max_lang; ++r) {
        if (cs->langs[r] && cs->langs[r]->enable_custom > 0) {
          break;
        }
      }
      if (r <= cs->max_lang) {
        lang_id = r;
        lang = cs->langs[r];
      } else {
        err_num = NEW_SRV_ERR_INV_LANG_ID;
        goto done;
      }
    } else {
      err_num = NEW_SRV_ERR_INV_LANG_ID;
      goto done;
    }
  } else {
    for (lang_id = 1; lang_id <= cs->max_lang; ++lang_id) {
      if ((lang = cs->langs[lang_id]) && !strcmp(s, lang->short_name))
        break;
    }
    if (lang_id > cs->max_lang) {
      char *eptr = NULL;
      errno = 0;
      long v = strtol(s, &eptr, 10);
      if (errno || *eptr || (unsigned char *) eptr == s || (int) v != v) {
        err_num = NEW_SRV_ERR_INV_LANG_ID;
        goto done;
      }
      lang_id = v;
    }
    if (lang_id <= 0 || lang_id > cs->max_lang || !(lang = cs->langs[lang_id])) {
      err_num = NEW_SRV_ERR_INV_LANG_ID;
      goto done;
    }
  }

  if (cs->global->enable_eoln_select > 0) {
    hr_cgi_param_int_opt(phr, "eoln_type", &eoln_type, 0);
    if (eoln_type < 0 || eoln_type > EOLN_CRLF) eoln_type = 0;
  }

  r = hr_cgi_param_bin(phr, "file", &run_text, &tmpsz); run_size = tmpsz;
  if ((r <= 0 || !run_text || run_size <= 0) && prob->enable_text_form > 0) {
    r = hr_cgi_param_bin(phr, "text_form", &run_text, &tmpsz); run_size = tmpsz;
  }
  if (r <= 0 || !run_text || run_size <= 0) {
    err_num = NEW_SRV_ERR_FILE_UNSPECIFIED;
    goto done;
  }
  if (strlen(run_text) != run_size) {
    err_num = NEW_SRV_ERR_BINARY_FILE;
    goto done;
  }
  if (prob->disable_ctrl_chars > 0 && has_control_characters(run_text)) {
    err_num = NEW_SRV_ERR_INV_CHAR;
    goto done;
  }
  if (global->ignore_bom > 0) {
    if (run_text && run_size >= 3 && run_text[0] == 0xef && run_text[1] == 0xbb && run_text[2] == 0xbf) {
      run_text += 3; run_size -= 3;
    }
  }
  run_size = text_normalize_dup(run_text, run_size, TEXT_FIX_CR | TEXT_FIX_TR_SP | TEXT_FIX_FINAL_NL | TEXT_FIX_NP, &run_fixed_text, NULL, NULL);
  run_text = run_fixed_text;
  if (!admin_mode && global->max_run_size > 0 && run_size > global->max_run_size) {
    err_num = NEW_SRV_ERR_RUN_QUOTA_EXCEEDED;
    goto done;
  }

  r = hr_cgi_param_bin(phr, "file_input", &inp_text, &tmpsz); inp_size = tmpsz;
  if ((r <= 0 || !inp_text || inp_size <= 0) && prob->enable_text_form > 0) {
    r = hr_cgi_param_bin(phr, "text_form_input", &inp_text, &tmpsz); inp_size = tmpsz;
  }
  if (r <= 0 || !inp_text || inp_size <= 0) {
    err_num = NEW_SRV_ERR_FILE_UNSPECIFIED;
    goto done;
  }
  if (strlen(inp_text) != inp_size) {
    err_num = NEW_SRV_ERR_BINARY_FILE;
    goto done;
  }
  if (prob->disable_ctrl_chars > 0 && has_control_characters(inp_text)) {
    err_num = NEW_SRV_ERR_INV_CHAR;
    goto done;
  }
  if (global->ignore_bom > 0) {
    if (inp_text && inp_size >= 3 && inp_text[0] == 0xef && inp_text[1] == 0xbb && inp_text[2] == 0xbf) {
      inp_text += 3; inp_size -= 3;
    }
  }
  inp_size = text_normalize_dup(inp_text, inp_size, TEXT_FIX_CR | TEXT_FIX_TR_SP | TEXT_FIX_FINAL_NL | TEXT_FIX_NP, &inp_fixed_text, NULL, NULL);
  inp_text = inp_fixed_text;
  {
    int max_input_size = 1024;
    if (global->max_input_size > 0) max_input_size = global->max_input_size;
    if (!admin_mode && inp_size > max_input_size) {
      err_num = NEW_SRV_ERR_RUN_QUOTA_EXCEEDED;
      goto done;
    }
  }


  time_t start_time = 0;
  time_t stop_time = 0;
  if (global->is_virtual > 0) {
    start_time = run_get_virtual_start_time(cs->runlog_state, sender_user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, sender_user_id, cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state, sender_user_id, cs->current_time);
  }

  if (!admin_mode) {
    // availability checks
    if (cs->clients_suspended) {
      err_num = NEW_SRV_ERR_CLIENTS_SUSPENDED;
      goto done;
    }
    if (start_time <= 0 && !cs->upsolving_mode) {
      err_num = NEW_SRV_ERR_CONTEST_NOT_STARTED;
      goto done;
    }
    if (stop_time > 0 && !cs->upsolving_mode) {
      err_num = NEW_SRV_ERR_CONTEST_ALREADY_FINISHED;
      goto done;
    }
    if (!serve_is_problem_started(cs, sender_user_id, prob)) {
      err_num = NEW_SRV_ERR_PROB_UNAVAILABLE;
      goto done;
    }
    time_t user_deadline = 0;
    if (serve_is_problem_deadlined(cs, sender_user_id, phr->login, prob, &user_deadline)) {
      err_num = NEW_SRV_ERR_PROB_DEADLINE_EXPIRED;
      goto done;
    }
  }

  if (lang->disabled > 0) {
    err_num = NEW_SRV_ERR_LANG_DISABLED;
    goto done;
  }
  if (prob->enable_container <= 0 && lang->insecure > 0 && global->secure_run > 0 && prob->disable_security <= 0) {
    err_num = NEW_SRV_ERR_LANG_DISABLED;
    goto done;
  }
  if (prob->enable_language) {
    char **lang_list = prob->enable_language;
    int i;
    for (i = 0; lang_list[i]; ++i)
      if (!strcmp(lang_list[i], lang->short_name))
        break;
    if (!lang_list[i]) {
      err_num = NEW_SRV_ERR_LANG_NOT_AVAIL_FOR_PROBLEM;
      goto done;
    }
  } else if (prob->disable_language) {
    char **lang_list = prob->disable_language;
    int i;
    for (i = 0; lang_list[i]; ++i)
      if (!strcmp(lang_list[i], lang->short_name))
        break;
    if (lang_list[i]) {
      err_num = NEW_SRV_ERR_LANG_DISABLED_FOR_PROBLEM;
      goto done;
    }
  }

  int variant = 0;
  if (prob->variant_num > 0) {
    if ((variant = find_variant(cs, sender_user_id, prob_id, 0)) <= 0) {
      err_num = NEW_SRV_ERR_VARIANT_UNASSIGNED;
      goto done;
    }
  }

  if (!cs->storage_state) {
    cs->storage_state = storage_plugin_get(extra, cnts, ejudge_config, NULL);
    if (!cs->storage_state) {
      err_num = NEW_SRV_ERR_PLUGIN_NOT_AVAIL;
      goto done;
    }
  }

  if (!cs->submit_state) {
    cs->submit_state = submit_plugin_open(ejudge_config, cnts, cs, NULL, 0);
    if (!cs->submit_state) {
      err_num = NEW_SRV_ERR_PLUGIN_NOT_AVAIL;
      goto done;
    }
  }

  if (prob->require) {
    XALLOCAZ(acc_probs, cs->max_prob + 1);
    ns_get_accepted_set(cs, sender_user_id, acc_probs);
    if (prob->require_any > 0) {
      int i;
      for (i = 0; prob->require[i]; ++i) {
        int j;
        for (j = 1; j <= cs->max_prob; ++j)
          if (cs->probs[j] && !strcmp(cs->probs[j]->short_name, prob->require[i]))
            break;
        if (j <= cs->max_prob && cs->probs[j] && acc_probs[j]) break;
      }
      if (!prob->require[i]) {
        err_num = NEW_SRV_ERR_NOT_ALL_REQ_SOLVED;
        goto done;
      }
    } else {
      int i;
      for (i = 0; prob->require[i]; ++i) {
        int j;
        for (j = 1; j <= cs->max_prob; ++j)
          if (cs->probs[j] && !strcmp(cs->probs[j]->short_name, prob->require[i]))
            break;
        if (j > cs->max_prob || !acc_probs[j]) break;
      }
      if (prob->require[i]) {
        err_num = NEW_SRV_ERR_NOT_ALL_REQ_SOLVED;
        goto done;
      }
    }
  }

  if (cs->submit_state->vt->fetch_for_user(cs->submit_state, sender_user_id, 1, 0, &sez, &ses) < 0) {
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    goto done;
  }
  // rate limit check
  if (global->time_between_submits != 0) {
    long long tbs_us = DFLT_G_TIME_BETWEEN_SUBMITS * 1000000LL;
    if (global->time_between_submits > 0) {
      tbs_us = global->time_between_submits * 1000000LL;
    }
    if (!admin_mode && sez > 0 && ses[0].create_time_us + tbs_us > cs->current_time * 1000000LL) {
      err_num = NEW_SRV_ERR_RATE_EXCEEDED;
      goto done;
    }
  }
  free(ses); ses = NULL; sez = 0;

  if (cs->submit_state->vt->fetch_totals(cs->submit_state, sender_user_id, &st) < 0) {
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    goto done;
  }
  {
    int max_submit_num = DFLT_G_MAX_SUBMIT_NUM;
    if (global->max_submit_num > 0) max_submit_num = global->max_submit_num;
    if (!admin_mode && st.count >= max_submit_num) {
      err_num = NEW_SRV_ERR_RUN_QUOTA_EXCEEDED;
      goto done;
    }
  }
  {
    long long max_submit_total = DFLT_G_MAX_SUBMIT_TOTAL;
    if (global->max_submit_total > 0) max_submit_total = global->max_submit_total;
    long long new_size = st.source_size + st.input_size + run_size + inp_size;
    if (!admin_mode && new_size > max_submit_total) {
      err_num = NEW_SRV_ERR_RUN_QUOTA_EXCEEDED;
      goto done;
    }
  }

  if (cs->storage_state->vt->insert(cs->storage_state, 0, 0, run_size, run_text, &src_se) < 0) {
    err_num = NEW_SRV_ERR_RUNLOG_UPDATE_FAILED;
    goto done;
  }
  if (cs->storage_state->vt->insert(cs->storage_state, 0, 0, inp_size, inp_text, &inp_se) < 0) {
    err_num = NEW_SRV_ERR_RUNLOG_UPDATE_FAILED;
    goto done;
  }
  if (ns_load_problem_uuid(phr->log_f, global, prob, variant) < 0) {
    err_num = NEW_SRV_ERR_INV_PROB_ID;
    goto done;
  }

  if (prob->uuid && prob->uuid[0]) {
    ej_uuid_parse(prob->uuid, &se.prob_uuid);
  }
  se.source_id = src_se.serial_id;
  se.input_id = inp_se.serial_id;
  se.ip = sender_ip;
  se.user_id = sender_user_id;
  se.prob_id = prob_id;
  se.variant = variant;
  se.lang_id = lang_id;
  se.status = RUN_AVAILABLE;
  se.locale_id = phr->locale_id;
  se.ssl_flag = sender_ssl_flag;
  se.eoln_type = eoln_type;
  se.source_size = run_size;
  se.input_size = inp_size;
  se.ext_user_kind = ext_user_kind;
  se.ext_user = ext_user;
  se.notify_driver = notify_driver;
  se.notify_kind = notify_kind;
  se.notify_queue = notify_queue;

  if ((cs->submit_state->vt->insert(cs->submit_state, &se)) < 0) {
    err_num = NEW_SRV_ERR_RUNLOG_UPDATE_FAILED;
    goto done;
  }

  ej_uuid_generate(&se.judge_uuid);
  r = serve_compile_request(phr->config,
                            cs,
                            run_text,
                            run_size,
                            cnts->id,
                            0  /* run_id */,
                            se.serial_id,
                            sender_user_id,
                            variant,
                            phr->locale_id,
                            0 /* output_only */,
                            lang->src_sfx,
                            0 /* style_check_only */,
                            -1 /* accepting_mode */,
                            0 /* priority_adjustment */,
                            1 /* notify_flag */,
                            prob,
                            lang,
                            1 /* no_db_flag */,
                            NULL /* run_uuid */,
                            &se.judge_uuid,
                            0 /* store_flags */,
                            0 /* rejudge_flag */,
                            0 /* vcs_mode */,
                            0 /* not_ok_is_cf */,
                            user,
                            NULL);
  if (r < 0) {
    err_num = NEW_SRV_ERR_RUNLOG_UPDATE_FAILED;
    goto done;
  }


  if ((cs->submit_state->vt->change_status(cs->submit_state,
                                           se.serial_id,
                                           SUBMIT_FIELD_STATUS | SUBMIT_FIELD_JUDGE_UUID,
                                           RUN_COMPILING,
                                           0,
                                           &se.judge_uuid, NULL)) < 0) {
    err_num = NEW_SRV_ERR_RUNLOG_UPDATE_FAILED;
    goto done;
  }

  cJSON *jrr = cJSON_CreateObject();
  cJSON_AddNumberToObject(jrr, "submit_id", se.serial_id);
  cJSON_AddItemToObject(jr, "result", jrr);
  ok = 1;

done:;
  emit_json_result(fout, phr, ok, err_num, err_id, err_msg, jr);

//cleanup:;
  if (jr) cJSON_Delete(jr);
  free(err_msg);
  free(ses);
  free(run_fixed_text);
  free(inp_fixed_text);
}

static void
unpriv_submit_run_input(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  ns_submit_run_input(fout, phr, cnts, extra, 0);
}

static void
ns_get_submit(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int admin_mode)
{
  serve_state_t cs = extra->serve_state;
  int ok = 0;
  int err_num = 0;
  unsigned char *err_msg = NULL;
  unsigned err_id = 0;
  cJSON *jr = cJSON_CreateObject(); // reply object
  int64_t submit_id = 0;
  const unsigned char *s = NULL;
  struct submit_entry se = {};
  struct storage_entry prot_se = {};
  int r;
  testing_report_xml_t tr = NULL;

  if (hr_cgi_param(phr, "submit_id", &s) <= 0 || !s) {
    err_num = NEW_SRV_ERR_INV_SUBMIT_ID;
    goto done;
  }
  {
    char *eptr = NULL;
    errno = 0;
    long long v = strtoll(s, &eptr, 10);
    if (errno || *eptr || (unsigned char *) eptr == s || v <= 0) {
      err_num = NEW_SRV_ERR_INV_SUBMIT_ID;
      goto done;
    }
    submit_id = v;
  }

  if (!cs->storage_state) {
    cs->storage_state = storage_plugin_get(extra, cnts, ejudge_config, NULL);
    if (!cs->storage_state) {
      err_num = NEW_SRV_ERR_PLUGIN_NOT_AVAIL;
      goto done;
    }
  }

  if (!cs->submit_state) {
    cs->submit_state = submit_plugin_open(ejudge_config, cnts, cs, NULL, 0);
    if (!cs->submit_state) {
      err_num = NEW_SRV_ERR_PLUGIN_NOT_AVAIL;
      goto done;
    }
  }

  r = cs->submit_state->vt->fetch(cs->submit_state, submit_id, &se);
  if (r < 0) {
    err_num = NEW_SRV_ERR_INV_SUBMIT_ID;
    goto done;
  }
  if (se.contest_id != cnts->id) {
    err("submit %lld contest_id mismatch", (long long) submit_id);
    err_num = NEW_SRV_ERR_INV_SUBMIT_ID;
    goto done;
  }
  if (!admin_mode && se.user_id != phr->user_id) {
    err("submit %lld user_id mismatch", (long long) submit_id);
    err_num = NEW_SRV_ERR_INV_SUBMIT_ID;
    goto done;
  }
  if (se.protocol_id > 0) {
    r = cs->storage_state->vt->get_by_serial_id(cs->storage_state, se.protocol_id, &prot_se);
    if (r < 0) {
      err_num = NEW_SRV_ERR_INV_SUBMIT_ID;
      goto done;
    }
    if (prot_se.mime_type == MIME_TYPE_BSON) {
      tr = testing_report_parse_bson_data(prot_se.content, prot_se.size);
    } else if (!prot_se.mime_type) {
      size_t len = strlen(prot_se.content);
      if (len != prot_se.size) {
        err("invalid length of testing XML report");
        err_num = NEW_SRV_ERR_INV_SUBMIT_ID;
        goto done;
      }
      tr = testing_report_parse_xml(prot_se.content);
    } else {
      err("invalid mime type of testing protocol");
      err_num = NEW_SRV_ERR_INV_SUBMIT_ID;
      goto done;
    }
    if (!tr) {
      err("failed to parse testing report");
      err_num = NEW_SRV_ERR_INV_SUBMIT_ID;
      goto done;
    }
  }

  cJSON_AddItemToObject(jr, "result", json_serialize_submit(&se, tr));
  ok = 1;

done:;
  emit_json_result(fout, phr, ok, err_num, err_id, err_msg, jr);

  if (jr) cJSON_Delete(jr);
  free(err_msg);
  testing_report_free(tr);
  free(prot_se.content);
}

static void
unpriv_get_submit(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  ns_get_submit(fout, phr, cnts, extra, 0);
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
  size_t subj_len, text_len, subj3_len, text3_len;
  unsigned char *subj2, *text2, *subj3, *text3;
  struct timeval precise_time;
  int clar_id;
  int retval = 0;

  // parameters: prob_id, subject, text,

  if ((n = hr_cgi_param(phr, "prob_id", &s)) < 0) {
    FAIL2(NEW_SRV_ERR_INV_PROB_ID);
  }
  if (n > 0 && *s) {
    if (sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n]) {
      FAIL2(NEW_SRV_ERR_INV_PROB_ID);
    }
    if (prob_id <= 0 || prob_id > cs->max_prob || !(prob = cs->probs[prob_id])) {
      FAIL2(NEW_SRV_ERR_INV_PROB_ID);
    }
  }
  if (hr_cgi_param(phr, "subject", &subject) < 0) {
    fprintf(phr->log_f, "subject is binary\n");
    FAIL2(NEW_SRV_ERR_INV_PARAM);
  }
  if (hr_cgi_param(phr, "text", &text) <= 0) {
    fprintf(phr->log_f, "text is not set or binary\n");
    FAIL2(NEW_SRV_ERR_INV_PARAM);
  }

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
  }

  if (cs->clients_suspended) {
    FAIL2(NEW_SRV_ERR_CLIENTS_SUSPENDED);
  }
  if (global->disable_team_clars) {
    FAIL2(NEW_SRV_ERR_CLARS_DISABLED);
  }
  if (!start_time) {
    FAIL2(NEW_SRV_ERR_CONTEST_NOT_STARTED);
  }
  if (stop_time) {
    FAIL2(NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
  }

  if (!subject) subject = "";
  subj_len = strlen(subject);
  if (subj_len > 128 * 1024 * 1024) {
    FAIL2(NEW_SRV_ERR_SUBJECT_TOO_LONG);
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
    FAIL2(NEW_SRV_ERR_MESSAGE_TOO_LONG);
  }
  text2 = alloca(text_len + 1);
  strcpy(text2, text);
  while (text_len > 0 && isspace(text2[text_len - 1])) text2[--text_len] = 0;
  if (!text_len) {
    FAIL2(NEW_SRV_ERR_MESSAGE_EMPTY);
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
    FAIL2(NEW_SRV_ERR_CLAR_QUOTA_EXCEEDED);
  }

  ej_uuid_t clar_uuid = {};
  gettimeofday(&precise_time, 0);
  if ((clar_id = clar_add_record(cs->clarlog_state,
                                 precise_time.tv_sec,
                                 precise_time.tv_usec * 1000,
                                 text3_len,
                                 &phr->ip,
                                 phr->ssl_flag,
                                 phr->user_id, 0, 0, 0, 0,
                                 phr->locale_id,
                                 0 /* in_reply_to */,
                                 NULL /* in_reply_uuid */,
                                 0 /* run_id */,
                                 NULL /* run_uuid */,
                                 0 /* appeal_flag */,
                                 0 /* old_run_status */,
                                 0 /* new_run_status */,
                                 utf8_mode, NULL, subj3, &clar_uuid)) < 0) {
    FAIL2(NEW_SRV_ERR_CLARLOG_UPDATE_FAILED);
  }

  if (clar_add_text(cs->clarlog_state, clar_id, &clar_uuid, text3, text3_len) < 0) {
    FAIL2(NEW_SRV_ERR_DISK_WRITE_ERROR);
  }

  serve_send_clar_notify_email(ejudge_config, cs, cnts, phr->user_id, phr->name, subj3, text2);
  serve_send_clar_notify_telegram(ejudge_config, cs, cnts, phr->user_id, phr->name, subj3, text2);
  ns_refresh_page(fout, phr, NEW_SRV_ACTION_VIEW_CLARS, 0);

cleanup:;
  return;

fail:
  error_page(fout, phr, 0, -retval);
  goto cleanup;
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
  size_t text_len, subj3_len, text3_len;
  unsigned char *text2, *subj3, *text3;
  struct timeval precise_time;
  int clar_id, test;
  int retval = 0;

  // parameters: prob_id, subject, text,

  if ((n = hr_cgi_param(phr, "prob_id", &s)) < 0) {
    FAIL2(NEW_SRV_ERR_INV_PROB_ID);
  }
  if (n > 0 && *s) {
    if (sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n]) {
      FAIL2(NEW_SRV_ERR_INV_PROB_ID);
    }
    if (prob_id <= 0 || prob_id > cs->max_prob || !(prob = cs->probs[prob_id])) {
      FAIL2(NEW_SRV_ERR_INV_PROB_ID);
    }
  }
  if ((n = hr_cgi_param(phr, "test", &s)) < 0) {
    fprintf(phr->log_f, "test is binary\n");
    FAIL2(NEW_SRV_ERR_INV_PARAM);
  }
  if (hr_cgi_param(phr, "text", &text) <= 0) {
    fprintf(phr->log_f, "text is not set or binary\n");
    FAIL2(NEW_SRV_ERR_INV_PARAM);
  }

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
  }

  if (cs->clients_suspended) {
    FAIL2(NEW_SRV_ERR_CLIENTS_SUSPENDED);
  }
  if (global->disable_team_clars) {
    FAIL2(NEW_SRV_ERR_CLARS_DISABLED);
  }
  if (!start_time) {
    FAIL2(NEW_SRV_ERR_CONTEST_NOT_STARTED);
  }
  if (!stop_time) {
    FAIL2(NEW_SRV_ERR_CONTEST_NOT_FINISHED);
  }
  if (global->appeal_deadline <= 0) {
    FAIL2(NEW_SRV_ERR_APPEALS_DISABLED);
  }
  if (cs->current_time >= global->appeal_deadline) {
    FAIL2(NEW_SRV_ERR_APPEALS_FINISHED);
  }
  if (hr_cgi_param(phr, "test", &s) <= 0
      || sscanf(s, "%d%n", &test, &n) != 1 || s[n]
      || test <= 0 || test > 100000) {
    FAIL2(NEW_SRV_ERR_INV_TEST);
  }
  if (!prob) {
    FAIL2(NEW_SRV_ERR_INV_PROB_ID);
  }

  if (!text) text = "";
  text_len = strlen(text);
  if (text_len > 128 * 1024 * 1024) {
    FAIL2(NEW_SRV_ERR_MESSAGE_TOO_LONG);
  }
  text2 = alloca(text_len + 1);
  strcpy(text2, text);
  while (text_len > 0 && isspace(text2[text_len - 1])) text2[--text_len] = 0;
  if (!text_len) {
    FAIL2(NEW_SRV_ERR_MESSAGE_EMPTY);
  }

  subj3 = alloca(strlen(prob->short_name) + 128);
  subj3_len = sprintf(subj3, "Appeal: %s, %d", prob->short_name, test);

  text3 = alloca(subj3_len + text_len + 32);
  text3_len = sprintf(text3, "Subject: %s\n\n%s\n", subj3, text2);

  if (serve_check_clar_quota(cs, phr->user_id, text3_len) < 0) {
    FAIL2(NEW_SRV_ERR_CLAR_QUOTA_EXCEEDED);
  }

  ej_uuid_t clar_uuid = {};
  gettimeofday(&precise_time, 0);
  if ((clar_id = clar_add_record(cs->clarlog_state,
                                 precise_time.tv_sec,
                                 precise_time.tv_usec * 1000,
                                 text3_len,
                                 &phr->ip,
                                 phr->ssl_flag,
                                 phr->user_id, 0, 0, 0, 0,
                                 phr->locale_id,
                                 0 /* in_reply_to */,
                                 NULL /* in_reply_uuid */,
                                 0 /* run_id */,
                                 NULL /* run_uuid */,
                                 1,
                                 0 /* old_run_status */,
                                 0 /* new_run_status */,
                                 utf8_mode, NULL, subj3, &clar_uuid)) < 0) {
    FAIL2(NEW_SRV_ERR_CLARLOG_UPDATE_FAILED);
  }

  if (clar_add_text(cs->clarlog_state, clar_id, &clar_uuid, text3, text3_len) < 0) {
    FAIL2(NEW_SRV_ERR_DISK_WRITE_ERROR);
  }

  serve_send_clar_notify_email(ejudge_config, cs, cnts, phr->user_id, phr->name, subj3, text2);
  serve_send_clar_notify_telegram(ejudge_config, cs, cnts, phr->user_id, phr->name, subj3, text2);
  ns_refresh_page(fout, phr, NEW_SRV_ACTION_VIEW_CLARS, 0);

cleanup:;
  return;

fail:
  error_page(fout, phr, 0, -retval);
  goto cleanup;
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
  if (cnts->default_locale_num > 0) locale_id = cnts->default_locale_num;
  if (locale_id > 0) l10n_setlocale(locale_id);
  tmpf = open_memstream(&tmps, &tmpz);
  ns_print_user_exam_protocol(cnts, cs, tmpf, p->user_id, locale_id, 1, 0, 0);
  close_memstream(tmpf); tmpf = 0;
  xfree(tmps); tmps = 0; tmpz = 0;
  if (locale_id > 0) l10n_resetlocale();
}

static void
unpriv_command(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob;
  time_t start_time, stop_time;
  struct timeval precise_time;
  int run_id, i;
  unsigned char bb[1024];
  int retval = 0;
  struct run_header hdr;

  run_get_header(cs->runlog_state, &hdr);

  l10n_setlocale(phr->locale_id);

  switch (phr->action) {
  case NEW_SRV_ACTION_VIRTUAL_START:
  case NEW_SRV_ACTION_VIRTUAL_STOP:
  case NEW_SRV_ACTION_VIRTUAL_RESTART:
    if (global->is_virtual <= 0) {
      FAIL2(NEW_SRV_ERR_NOT_VIRTUAL);
    }
    if (hdr.start_time <= 0) {
      FAIL2(NEW_SRV_ERR_VIRTUAL_NOT_STARTED);
    }
    if (run_get_start_time(cs->runlog_state) <= 0) {
      FAIL2(NEW_SRV_ERR_VIRTUAL_NOT_STARTED);
    }
    break;
  default:
    FAIL2(NEW_SRV_ERR_UNHANDLED_ACTION);
  }

  switch (phr->action) {
  case NEW_SRV_ACTION_VIRTUAL_RESTART:
    if (global->enable_virtual_restart <= 0) {
      FAIL2(NEW_SRV_ERR_PERMISSION_DENIED);
    }
    if (cnts->open_time > 0 && cs->current_time < cnts->open_time) {
      FAIL2(NEW_SRV_ERR_PERMISSION_DENIED);
    }
    if (cnts->close_time > 0 && cs->current_time >= cnts->close_time) {
      FAIL2(NEW_SRV_ERR_PERMISSION_DENIED);
    }
    if (hdr.stop_time > 0) {
      FAIL2(NEW_SRV_ERR_PERMISSION_DENIED);
    }
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    if (start_time <= 0) {
      FAIL2(NEW_SRV_ERR_CONTEST_NOT_STARTED);
    }
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
    if (stop_time <= 0) {
      FAIL2(NEW_SRV_ERR_CONTEST_NOT_STOPPED);
    }
    run_clear_user_entries(cs->runlog_state, phr->user_id);
    // FALLTHROUGH!
  case NEW_SRV_ACTION_VIRTUAL_START:
    if (global->disable_virtual_start || cs->disable_virtual_start > 0) {
      FAIL2(NEW_SRV_ERR_PERMISSION_DENIED);
    }
    if (cnts->open_time > 0 && cs->current_time < cnts->open_time) {
      FAIL2(NEW_SRV_ERR_PERMISSION_DENIED);
    }
    if (cnts->close_time > 0 && cs->current_time >= cnts->close_time) {
      FAIL2(NEW_SRV_ERR_PERMISSION_DENIED);
    }
    if (hdr.stop_time > 0) {
      FAIL2(NEW_SRV_ERR_PERMISSION_DENIED);
    }
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    if (start_time > 0) {
      FAIL2(NEW_SRV_ERR_CONTEST_ALREADY_STARTED);
    }
    gettimeofday(&precise_time, 0);
    run_id = run_virtual_start(cs->runlog_state, phr->user_id,
                               precise_time.tv_sec, &phr->ip, phr->ssl_flag,
                               precise_time.tv_usec * 1000);
    if (run_id < 0) {
      FAIL2(NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
    }
    if (run_is_virtual_legacy_mode(cs->runlog_state)) {
      serve_move_files_to_insert_run(cs, run_id);
    }
    serve_event_add(cs,
                    precise_time.tv_sec + run_get_duration(cs->runlog_state, phr->user_id),
                    SERVE_EVENT_VIRTUAL_STOP, phr->user_id,
                    virtual_stop_callback);
    break;
  case NEW_SRV_ACTION_VIRTUAL_STOP:
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    if (start_time <= 0) {
      FAIL2(NEW_SRV_ERR_CONTEST_NOT_STARTED);
    }
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
    if (stop_time > 0) {
      FAIL2(NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
    }
    gettimeofday(&precise_time, 0);
    run_id = run_virtual_stop(cs->runlog_state, phr->user_id,
                              precise_time.tv_sec, &phr->ip, phr->ssl_flag,
                              precise_time.tv_usec * 1000);
    if (run_id < 0) {
      FAIL2(NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
    }
    if (run_is_virtual_legacy_mode(cs->runlog_state)) {
      serve_move_files_to_insert_run(cs, run_id);
    }
    if (global->score_system == SCORE_OLYMPIAD && global->is_virtual > 0) {
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
      if (cnts->default_locale_num > 0) locale_id = cnts->default_locale_num;
      if (locale_id > 0) l10n_setlocale(locale_id);
      tmpf = open_memstream(&tmps, &tmpz);
      ns_print_user_exam_protocol(cnts, cs, tmpf, phr->user_id, locale_id, 1,
                                  0, 0);
      fclose(tmpf); tmpf = 0;
      xfree(tmps); tmps = 0; tmpz = 0;
      if (locale_id > 0) l10n_resetlocale();
    }

    break;
  }

  i = 0;
  if ((phr->action == NEW_SRV_ACTION_VIRTUAL_START || phr->action == NEW_SRV_ACTION_VIRTUAL_RESTART)
      && global->problem_navigation) {
    for (i = 1; i <= cs->max_prob; i++) {
      if (!(prob = cs->probs[i])) continue;
      if (!serve_is_problem_started(cs, phr->user_id, prob))
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

cleanup:;
  l10n_resetlocale();
  return;

fail:
  error_page(fout, phr, 0, -retval);
  goto cleanup;
}

static void
unpriv_download_run(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  int run_id, src_flags;
  struct run_entry re;
  const struct section_language_data *lang = 0;
  const struct section_problem_data *prob = 0;
  char *run_text = 0;
  size_t run_size = 0;
  path_t src_path;
  int retval = 0;

  if (unpriv_parse_run_id(fout, phr, cnts, extra, &run_id, &re) < 0)
    goto cleanup;

  if (cs->clients_suspended) {
    FAIL2(NEW_SRV_ERR_CLIENTS_SUSPENDED);
  }
  if (cs->online_view_source < 0 || (!cs->online_view_source && global->team_enable_src_view <= 0)) {
    FAIL2(NEW_SRV_ERR_SOURCE_VIEW_DISABLED);
  }
  if (re.user_id != phr->user_id) {
    FAIL2(NEW_SRV_ERR_PERMISSION_DENIED);
  }
  if (re.prob_id <= 0 || re.prob_id > cs->max_prob ||
      !(prob = cs->probs[re.prob_id])) {
    FAIL2(NEW_SRV_ERR_INV_PROB_ID);
  }
  if (!run_is_normal_or_transient_status(re.status)) {
    FAIL2(NEW_SRV_ERR_SOURCE_UNAVAILABLE);
  }

  if ((src_flags = serve_make_source_read_path(cs, src_path, sizeof(src_path), &re)) < 0) {
    FAIL2(NEW_SRV_ERR_SOURCE_NONEXISTANT);
  }
  if (generic_read_file(&run_text, 0, &run_size, src_flags, 0, src_path, 0)<0) {
    FAIL2(NEW_SRV_ERR_DISK_READ_ERROR);
  }

  // never json
  phr->json_reply = 0;

  if (prob->type > 0) {
    fprintf(fout, "Content-type: %s\n", mime_type_get_type(re.mime_type));
    /*
    fprintf(fout, "Content-Disposition: attachment; filename=\"%06d%s\"\n",
            run_id, mime_type_get_suffix(re.mime_type));
    */
    putc_unlocked('\n', fout);
  } else {
    if(re.lang_id <= 0 || re.lang_id > cs->max_lang ||
       !(lang = cs->langs[re.lang_id])) {
      FAIL2(NEW_SRV_ERR_INV_LANG_ID);
    }

    if (lang->content_type && lang->content_type[0]) {
      fprintf(fout, "Content-type: %s\n", lang->content_type);
      fprintf(fout, "Content-Disposition: attachment; filename=\"%06d%s\"\n\n",
              run_id, lang->src_sfx);
    } else if (lang->binary) {
      fprintf(fout, "Content-type: application/octet-stream\n");
      fprintf(fout, "Content-Disposition: attachment; filename=\"%06d%s\"\n\n",
              run_id, lang->src_sfx);
    } else {
      fprintf(fout, "Content-type: text/plain\n\n");
    }
  }
  fwrite(run_text, 1, run_size, fout);

cleanup:
  xfree(run_text);
  return;

fail:
  error_page(fout, phr, 0, -retval);
  goto cleanup;
}

static void
unpriv_view_test(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  const struct section_problem_data *prob = 0;
  const struct section_global_data *global = cs->global;
  int run_id, test_num, n;
  const unsigned char *s = 0;
  struct run_entry re;
  int enable_rep_view = -1;
  int retval = 0;

  // run_id, test_num
  if (unpriv_parse_run_id(fout, phr, cnts, extra, &run_id, &re) < 0)
    goto cleanup;
  if (hr_cgi_param(phr, "test_num", &s) <= 0
      || sscanf(s, "%d%n", &test_num, &n) != 1 || s[n] || test_num <= 0) {
    FAIL2(NEW_SRV_ERR_INV_TEST);
  }
  if (re.prob_id <= 0 || re.prob_id > cs->max_prob || !(prob = cs->probs[re.prob_id])) {
    FAIL2(NEW_SRV_ERR_INV_PROB_ID);
  }

  if (global->score_system == SCORE_OLYMPIAD && prob->tests_to_accept > 0 && test_num <= prob->tests_to_accept && prob->team_enable_rep_view > 0) {
    enable_rep_view = 1;
  }

  // report view is explicitly disabled by the current contest setting
  if (cs->online_view_report < 0) enable_rep_view = 0;
  // report view is explicitly enabled by the current contest setting
  //if (cs->online_view_report > 0) enable_rep_view = 1;
  // report view is disabled by the problem configuration
  if (enable_rep_view < 0 && prob->team_enable_rep_view <= 0) enable_rep_view = 0;
  // report view is enabled by the problem configuration
  if (enable_rep_view < 0 && prob->team_show_judge_report > 0) enable_rep_view = 1;
  if (enable_rep_view < 0) {
    int visibility = cntsprob_get_test_visibility(prob, test_num, cs->online_final_visibility, re.token_flags);
    if (visibility == TV_FULLIFMARKED) {
      visibility = TV_HIDDEN;
      if (re.is_marked) visibility = TV_FULL;
    }
    if (visibility == TV_FULL) enable_rep_view = 1;
  }

  if (enable_rep_view < 0) enable_rep_view = 0;

  if (cs->clients_suspended) {
    FAIL2(NEW_SRV_ERR_CLIENTS_SUSPENDED);
  }
  if (enable_rep_view <= 0) {
    FAIL2(NEW_SRV_ERR_PERMISSION_DENIED);
  }
  if (re.user_id != phr->user_id) {
    FAIL2(NEW_SRV_ERR_PERMISSION_DENIED);
  }
  switch (re.status) {
  case RUN_OK:
  case RUN_RUN_TIME_ERR:
  case RUN_TIME_LIMIT_ERR:
  case RUN_WALL_TIME_LIMIT_ERR:
  case RUN_PRESENTATION_ERR:
  case RUN_WRONG_ANSWER_ERR:
  case RUN_PARTIAL:
  case RUN_ACCEPTED:
  case RUN_PENDING_REVIEW:
  case RUN_SUMMONED:
  case RUN_MEM_LIMIT_ERR:
  case RUN_SECURITY_ERR:
  case RUN_SYNC_ERR:
    break;
  default:
    FAIL2(NEW_SRV_ERR_PERMISSION_DENIED);
  }

  retval = ns_write_tests(cs, fout, phr->log_f, phr->action, run_id, test_num);
  if (retval < 0) goto fail;

cleanup:
  return;

fail:
  error_page(fout, phr, 0, -retval);
  goto cleanup;
}

void
html_problem_selection(serve_state_t cs,
                       FILE *fout,
                       struct http_request_info *phr,
                       const UserProblemInfo *pinfo,
                       const unsigned char *var_name,
                       int light_mode,
                       time_t start_time)
{
  int i, dpi, j, k;
  time_t user_deadline = 0;
  int user_penalty = 0, variant = 0;
  unsigned char deadline_str[64];
  unsigned char penalty_str[64];
  unsigned char problem_str[128];
  const unsigned char *problem_ptr = 0;
  const struct section_problem_data *prob;

  if (!var_name) var_name = "prob_id";

  fprintf(fout, "<select name=\"%s\"><option value=\"\"></option>\n", var_name);

  for (i = 1; i <= cs->max_prob; i++) {
    if (!(prob = cs->probs[i])) continue;
    if (!light_mode && prob->disable_submit_after_ok>0 && pinfo[i].solved_flag)
      continue;
    if (!serve_is_problem_started(cs, phr->user_id, prob))
      continue;
    if (start_time <= 0) continue;
    //if (prob->disable_user_submit) continue;

    penalty_str[0] = 0;
    deadline_str[0] = 0;
    if (!light_mode) {
      // try to find personal rules
      user_deadline = 0;
      user_penalty = 0;
      if (serve_is_problem_deadlined(cs, phr->user_id, phr->login,
                                     prob, &user_deadline))
        continue;

      // check `require' variable
      if (prob->require) {
        if (prob->require_any > 0) {
          for (j = 0; prob->require[j]; ++j) {
            for (k = 1; k <= cs->max_prob; ++k) {
              if (cs->probs[k] && !strcmp(cs->probs[k]->short_name, prob->require[j]))
                break;
            }
            if (k <= cs->max_prob) {
              if (pinfo[k].solved_flag || pinfo[k].accepted_flag || pinfo[k].pr_flag) break;
            }
          }
          if (!prob->require[j]) continue;
        } else {
          for (j = 0; prob->require[j]; j++) {
            for (k = 1; k <= cs->max_prob; k++) {
              if (cs->probs[k]
                  && !strcmp(cs->probs[k]->short_name, prob->require[j]))
                break;
            }
            // no such problem :(
            if (k > cs->max_prob) break;
            // this problem is not yet accepted or solved
            if (!pinfo[k].solved_flag && !pinfo[k].accepted_flag && !pinfo[k].pr_flag) break;
          }
          if (prob->require[j]) continue;
        }
      }

      // find date penalty
      for (dpi = 0; dpi < prob->dp_total; dpi++)
        if (cs->current_time < prob->dp_infos[dpi].date)
          break;
      if (dpi < prob->dp_total)
        user_penalty = prob->dp_infos[dpi].penalty;

      if (user_deadline > 0 && cs->global->show_deadline)
        snprintf(deadline_str, sizeof(deadline_str),
                 " (%s)", xml_unparse_date(user_deadline));
      if (user_penalty && cs->global->show_deadline)
        snprintf(penalty_str, sizeof(penalty_str), " [%d]", user_penalty);
    }

    if (prob->variant_num > 0 && prob->hide_variant <= 0) {
      if ((variant = find_variant(cs, phr->user_id, i, 0)) <= 0) continue;
      snprintf(problem_str, sizeof(problem_str),
               "%s-%d", prob->short_name, variant);
      problem_ptr = problem_str;
    } else {
      problem_ptr = prob->short_name;
    }

    const unsigned char *long_name = prob->long_name;
    if (!long_name) long_name = "";
    fprintf(fout, "<option value=\"%d\">%s - %s%s%s</option>\n",
            i, problem_ptr, long_name, penalty_str,
            deadline_str);
  }

  fprintf(fout, "</select>");
}

// for "Statements" section
void
html_problem_selection_2(serve_state_t cs,
                         FILE *fout,
                         struct http_request_info *phr,
                         const unsigned char *var_name,
                         time_t start_time)
{
  int i, dpi;
  time_t user_deadline = 0;
  int variant = 0;
  unsigned char deadline_str[64];
  unsigned char problem_str[128];
  const unsigned char *problem_ptr = 0;
  const struct section_problem_data *prob;

  if (!var_name) var_name = "prob_id";

  fprintf(fout, "<select name=\"%s\"><option value=\"\"></option>\n", var_name);
  fprintf(fout, "<option value=\"-1\">%s</option>\n", _("View all"));

  for (i = 1; i <= cs->max_prob; i++) {
    if (!(prob = cs->probs[i])) continue;
    if (!serve_is_problem_started(cs, phr->user_id, prob))
      continue;
    if (start_time <= 0) continue;

    if (serve_is_problem_deadlined(cs, phr->user_id, phr->login,
                                   prob, &user_deadline))
      continue;

    // find date penalty
    for (dpi = 0; dpi < prob->dp_total; dpi++)
      if (cs->current_time < prob->dp_infos[dpi].date)
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

    const unsigned char *long_name = prob->long_name;
    if (!long_name) long_name = "";
    fprintf(fout, "<option value=\"%d\">%s - %s%s</option>\n",
            i, problem_ptr, long_name, deadline_str);
  }

  fprintf(fout, "</select>");
}

int
get_last_language(serve_state_t cs, int user_id, int *p_last_eoln_type)
{
  int total_runs = run_get_total(cs->runlog_state), run_id;
  struct run_entry re;

  if (p_last_eoln_type) *p_last_eoln_type = 0;
  for (run_id = total_runs - 1; run_id >= 0; run_id--) {
    if (run_get_entry(cs->runlog_state, run_id, &re) < 0) continue;
    if (!run_is_source_available(re.status)) continue;
    if (re.user_id != user_id) continue;
    if (re.lang_id <= 0 || re.lang_id > cs->max_lang || !cs->langs[re.lang_id])
      continue;
    if (p_last_eoln_type) *p_last_eoln_type = re.eoln_type;
    return re.lang_id;
  }
  return 0;
}

unsigned char *
get_last_source(serve_state_t cs, int user_id, int prob_id)
{
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

  if ((src_flag = serve_make_source_read_path(cs, src_path, sizeof(src_path), &re)) < 0)
    return 0;
  if (generic_read_file(&src_txt, 0, &src_len, src_flag, 0, src_path, 0) < 0)
    return 0;

  s = src_txt;
  while (src_len > 0 && isspace(s[src_len])) src_len--;
  s[src_len] = 0;

  return s;
}

int
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

int
is_judged_virtual_olympiad(serve_state_t cs, int user_id)
{
  return run_get_virtual_is_checked(cs->runlog_state, user_id);
}

static void
rewrite_self_url(unsigned char *out, const unsigned char *in)
{
  const unsigned char *role = "client";
  strcpy(out, in);
  unsigned char *p1 = strrchr(out, '/');
  if (!p1) return;
  ++p1;
  if (!strcmp(p1, "master") || !strcmp(p1, "new-master")) {
    role = "master";
  } else if (!strcmp(p1, "judge") || !strcmp(p1, "new-judge")) {
    role = "judge";
  } else if (!strcmp(p1, "register") || !strcmp(p1, "new-register")) {
    role = "register";
  } else if (!strcmp(p1, "client") || !strcmp(p1, "new-client") || !strcmp(p1, "team") || !strcmp(p1, "new-team")) {
    role = "client";
  } else {
    return;
  }
  *--p1 = 0;
  unsigned char *p2 = strrchr(out, '/');
  if (!p2) {
    strcpy(out, in);
    return;
  }
  if (!strcmp(p2 + 1, "cgi-bin")) {
    p1 = p2;
  }

  strcpy(p1, EJUDGE_REST_PREFIX);
  p1 += EJUDGE_REST_PREFIX_LEN ;
  strcpy(p1, role);
}

void
ns_unparse_statement(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        const struct section_problem_data *prob,
        int variant,
        problem_xml_t px,
        const unsigned char *bb,
        int is_submittable /* unused */)
{
  struct problem_stmt *pp = 0;
  struct xml_tree *p, *q;
  unsigned char b1[1024];
  unsigned char b2[1024];
  unsigned char b3[1024];
  unsigned char b4[1024];
  unsigned char b5[1024];
  unsigned char b6[1024];
  unsigned char b7[1024];
  unsigned char b8[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  serve_state_t cs = extra->serve_state;
  struct problem_extra_info *prob_extra = &cs->prob_extras[prob->id];

  if (prob_extra && prob_extra->plugin && prob_extra->plugin->write_statement){
    prob_extra->plugin->write_statement(prob_extra->plugin_data,
                                        fout,
                                        phr,
                                        cnts,
                                        extra,
                                        prob,
                                        variant);
    return;
  }

  //const unsigned char *vars[8] = { "self", "prob", "get", "getfile", "input_file", "output_file", "variant", 0 };
  //const unsigned char *vals[8] = { b1, b2, b3, b4, b5, b6, b7, 0 };

  const unsigned char **vars = NULL;
  const unsigned char **vals = NULL;
  unsigned int *flags = NULL;
  int varcount = 8;
  if (prob->statement_env) {
    for (int i = 0; prob->statement_env[i]; ++i)
      ++varcount;
  }
  vars = alloca((varcount + 1) * sizeof(vars[0]));
  vals = alloca((varcount + 1) * sizeof(vals[0]));
  flags = alloca((varcount + 1) * sizeof(flags[0]));
  memset(flags, 0, (varcount + 1) * sizeof(flags[0]));
  int curvar = 0;
  vars[curvar] = "self"; vals[curvar] = b1; ++curvar;
  vars[curvar] = "prob"; vals[curvar] = b2; ++curvar;
  vars[curvar] = "get"; vals[curvar] = b3; ++curvar;
  vars[curvar] = "getfile"; vals[curvar] = b4; ++curvar;
  vars[curvar] = "input_file"; vals[curvar] = b5; ++curvar;
  vars[curvar] = "output_file"; vals[curvar] = b6; ++curvar;
  vars[curvar] = "variant"; vals[curvar] = b7; ++curvar;
  vars[curvar] = "rawvariant"; vals[curvar] = b8; ++curvar;
  if (prob->statement_env) {
    for (int i = 0; prob->statement_env[i]; ++i) {
      const unsigned char *envvar = prob->statement_env[i];
      const unsigned char *sep = strchr(envvar, '=');
      if (!sep) {
        vars[curvar] = envvar; vals[curvar] = "1"; ++curvar;
      } else {
        int ll = sep - envvar;
        unsigned char *dst = alloca(ll + 1);
        vars[curvar] = dst;
        memcpy(dst, envvar, ll);
        dst[ll] = 0;
        vals[curvar] = sep + 1;
        ++curvar;
      }
    }
  }
  vars[curvar] = NULL; vals[curvar] = NULL;

  snprintf(b1, sizeof(b1), "%s?SID=%016llx", phr->self_url, phr->session_id);
  snprintf(b2, sizeof(b2), "&prob_id=%d", prob->id);
  snprintf(b3, sizeof(b3), "&action=%d", NEW_SRV_ACTION_GET_FILE);
  b7[0] = 0;
  if (prob->enable_iframe_statement > 0) {
    int len = strlen(phr->self_url);
    unsigned char *self_url = alloca(len + EJUDGE_REST_PREFIX_LEN + 1);
    rewrite_self_url(self_url, phr->self_url);
    if (variant > 0) {
      snprintf(b7, sizeof(b7), "&variant=%d", variant);
      snprintf(b4, sizeof(b4), "%s/get-file/S%016llx/%d/%d/", self_url, phr->session_id, prob->id, variant);
    } else {
      snprintf(b4, sizeof(b4), "%s/get-file/S%016llx/%d/", self_url, phr->session_id, prob->id);
    }
    flags[3] = 1;
  } else {
    if (variant > 0) snprintf(b7, sizeof(b7), "&variant=%d", variant);
    snprintf(b4, sizeof(b4), "%s%s%s%s&file", b1, b2, b3, b7);
  }
  b5[0] = 0;
  if (prob->input_file) {
    snprintf(b5, sizeof(b5), "%s", prob->input_file);
  }
  b6[0] = 0;
  if (prob->output_file) {
    snprintf(b6, sizeof(b6), "%s", prob->output_file);
  }
  b8[0] = 0;
  if (variant > 0) snprintf(b8, sizeof(b8), "%d", variant);

  if (bb && *bb && !cnts->exam_mode) fprintf(fout, "%s", bb);

  pp = problem_xml_find_statement(px, 0);
  if (pp->title) {
    fprintf(fout, "<h3>");
    problem_xml_unparse_node(fout, pp->title, vars, vals, flags);
    fprintf(fout, "</h3>");
  } else if (prob->enable_iframe_statement <= 0) {
    fprintf(fout, "<h3>");
    fprintf(fout, "%s %s", _("Problem"), ARMOR(prob->short_name));
    if (prob->long_name && prob->long_name[0]) {
      fprintf(fout, ": %s", ARMOR(prob->long_name));
    }
    fprintf(fout, "</h3>");
  }

  if (pp->desc) {
    problem_xml_unparse_node(fout, pp->desc, vars, vals, flags);
  }

  if (pp->input_format) {
    fprintf(fout, "<h3>%s</h3>", _("Input format"));
    problem_xml_unparse_node(fout, pp->input_format, vars, vals, flags);
  }
  if (pp->output_format) {
    fprintf(fout, "<h3>%s</h3>", _("Output format"));
    problem_xml_unparse_node(fout, pp->output_format, vars, vals, flags);
  }

  if (px->examples) {
    fprintf(fout, "<h3>%s</h3>", _("Examples"));
    /*
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
    */
    for (p = px->examples->first_down; p; p = p->right) {
      if (p->tag != PROB_T_EXAMPLE) continue;
      //fprintf(fout, "<tr><td class=\"b1\" valign=\"top\"><pre>");
      for (q = p->first_down; q && q->tag != PROB_T_INPUT; q = q->right);
      if (q && q->tag == PROB_T_INPUT) {
        fprintf(fout, "<h4>");
        if (prob->use_stdin) {
          fprintf(fout, "%s", _("Input"));
        } else if (prob->input_file && prob->input_file[0]) {
          fprintf(fout, "%s <tt>%s</tt>", _("Input in"), prob->input_file);
        }
        fprintf(fout, "</h4>\n<pre>");
        problem_xml_unparse_node(fout, q, 0, 0, NULL);
        fprintf(fout, "</pre>\n");
      }
      //fprintf(fout, "</pre></td><td class=\"b1\" valign=\"top\"><pre>");
      for (q = p->first_down; q && q->tag != PROB_T_OUTPUT; q = q->right);
      if (q && q->tag == PROB_T_OUTPUT) {
        fprintf(fout, "<h4>");
        if (prob->use_stdout) {
          fprintf(fout, "%s", _("Output"));
        } else if (prob->output_file && prob->output_file[0]) {
          fprintf(fout, "%s <tt>%s</tt>", _("Output in"), prob->output_file);
        }
        fprintf(fout, "</h4>\n<pre>");
        problem_xml_unparse_node(fout, q, 0, 0, NULL);
        fprintf(fout, "</pre>\n");
      }
      //fprintf(fout, "</pre></td></tr>");
    }
    /*
    fprintf(fout, "</table>");
    */
  }

  if (pp->notes) {
    fprintf(fout, "<h3>%s</h3>", _("Notes"));
    problem_xml_unparse_node(fout, pp->notes, vars, vals, flags);
  }

  html_armor_free(&ab);
}

void
ns_unparse_answers(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        const struct section_problem_data *prob,
        int variant,
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

  unsigned char b1[1024];
  unsigned char b2[1024];
  unsigned char b3[1024];
  unsigned char b4[1024];
  unsigned char b5[1024];
  unsigned char b6[1024];
  unsigned char b7[1024];
  const unsigned char *vars[8] = { "self", "prob", "get", "getfile", "input_file", "output_file", "variant", 0 };
  const unsigned char *vals[8] = { b1, b2, b3, b4, b5, b6, b7, 0 };
  unsigned int flags[8] = { 0 };

  snprintf(b1, sizeof(b1), "%s?SID=%016llx", phr->self_url, phr->session_id);
  snprintf(b2, sizeof(b2), "&prob_id=%d", prob->id);
  snprintf(b3, sizeof(b3), "&action=%d", NEW_SRV_ACTION_GET_FILE);
  b7[0] = 0;
  if (prob->enable_iframe_statement > 0) {
    int len = strlen(phr->self_url);
    unsigned char *self_url = alloca(len + EJUDGE_REST_PREFIX_LEN + 1);
    rewrite_self_url(self_url, phr->self_url);
    if (variant > 0) {
      snprintf(b7, sizeof(b7), "&variant=%d", variant);
      snprintf(b4, sizeof(b4), "%s/get-file/S%016llx/%d/%d/", self_url, phr->session_id, prob->id, variant);
    } else {
      snprintf(b4, sizeof(b4), "%s/get-file/S%016llx/%d/", self_url, phr->session_id, prob->id);
    }
    flags[3] = 1;
  } else {
    if (variant > 0) snprintf(b7, sizeof(b7), "&variant=%d", variant);
    snprintf(b4, sizeof(b4), "%s%s%s%s&file", b1, b2, b3, b7);
  }
  b5[0] = 0;
  if (prob->input_file) {
    snprintf(b5, sizeof(b5), "%s", prob->input_file);
  }
  b6[0] = 0;
  if (prob->output_file) {
    snprintf(b6, sizeof(b6), "%s", prob->output_file);
  }

  if (class_name && *class_name) {
    cl = (unsigned char *) alloca(strlen(class_name) + 32);
    sprintf(cl, " class=\"%s\"", class_name);
  }

  l = problem_xml_find_language(lang, px->tr_num, px->tr_names);
  for (i = 0; i < px->ans_num; i++) {
    if (is_radio) {
      jsbuf[0] = 0;
      if (prob->id > 0 && enable_js) {
        snprintf(jsbuf, sizeof(jsbuf), " onclick=\"submitAnswer(%d,%d,%d,%d,%d)\"", NEW_SRV_ACTION_UPDATE_ANSWER, prob->id, i + 1, NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT, next_prob_id);
      }
      s = "";
      if (last_answer == i + 1) s = " checked=\"1\"";
      fprintf(fout, "<tr><td%s>%d)</td><td%s><input type=\"radio\" name=\"file\" value=\"%d\"%s%s/></td><td%s>", cl, i + 1, cl, i + 1, s, jsbuf, cl);
      problem_xml_unparse_node(fout, px->answers[i][l], vars, vals, flags);
      fprintf(fout, "</td></tr>\n");
    } else {
      fprintf(fout, "<tr><td%s>%d)</td><td%s><input type=\"checkbox\" name=\"ans_%d\"/></td><td%s>", cl, i + 1, cl, i + 1, cl);
      problem_xml_unparse_node(fout, px->answers[i][l], vars, vals, flags);
      fprintf(fout, "</td></tr>\n");
    }
  }
}

static void
unpriv_logout(FILE *fout,
              struct http_request_info *phr,
              const struct contest_desc *cnts,
              struct contest_extra *extra)
{
  //unsigned char locale_buf[64];
  unsigned char urlbuf[1024];

  ns_invalidate_session(phr->session_id, phr->client_key);

  if (ns_open_ul_connection(phr->fw_state) < 0)
    return error_page(fout, phr, 0, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
  userlist_clnt_delete_cookie(ul_conn, phr->user_id, phr->contest_id,
                              phr->session_id,
                              phr->client_key);

  if (phr->client_state->ops->set_client_auth) {
    phr->client_state->ops->set_client_auth(phr->client_state, NULL);
  }

  if (phr->json_reply) {
    struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
    int ok = 1;
    time_t current_time = time(NULL);

    fprintf(fout, "{\n");
    fprintf(fout, "  \"ok\" : %s", ok?"true":"false");
    fprintf(fout, ",\n  \"server_time\": %lld", (long long) current_time);
    if (phr->request_id > 0) {
      fprintf(fout, ",\n  \"request_id\": %d", phr->request_id);
    }
    if (phr->action > 0 && phr->action < NEW_SRV_ACTION_LAST && ns_symbolic_action_table[phr->action]) {
      fprintf(fout, ",\n  \"action\": \"%s\"", ns_symbolic_action_table[phr->action]);
    }
    if (phr->client_state->ops->get_reply_id) {
      int reply_id = phr->client_state->ops->get_reply_id(phr->client_state);
      fprintf(fout, ",\n  \"reply_id\": %d", reply_id);
    }
    fprintf(fout, ",\n  \"result\": {");
    if (phr->contest_id > 0) {
      fprintf(fout, "\n    \"contest_id\": %d", phr->contest_id);
    }
    fprintf(fout, "\n  }");
    fprintf(fout, "\n}\n");
    html_armor_free(&ab);
  } else {
    snprintf(urlbuf, sizeof(urlbuf),
             "%s?contest_id=%d&locale_id=%d",
             phr->self_url, phr->contest_id, phr->locale_id);
    ns_refresh_page_2(fout, phr->client_key, urlbuf);
  }
}

void
do_json_user_state(
        FILE *fout,
        const serve_state_t cs,
        int user_id,
        int need_reload_check)
{
  const struct section_global_data *global = cs->global;
  struct tm *ptm;
  time_t start_time = 0, stop_time = 0, duration = 0, remaining;
  int has_transient;

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, user_id,
                                          cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state, user_id, cs->current_time);
  }
  duration = run_get_duration(cs->runlog_state, user_id);

  ptm = localtime(&cs->current_time);
  fprintf(fout, "{"
          " \"h\": %d,"
          " \"m\": %d,"
          " \"s\": %d,"
          " \"d\": %d,"
          " \"o\": %d,"
          " \"y\": %d",
          ptm->tm_hour, ptm->tm_min, ptm->tm_sec,
          ptm->tm_mday, ptm->tm_mon + 1, ptm->tm_year + 1900);
  if (start_time > 0 && stop_time <= 0 && duration > 0) {
    remaining = start_time + duration - cs->current_time;
    if (remaining < 0) remaining = 0;
    fprintf(fout, ", \"r\": %ld", remaining);
  }
  if (global->disable_auto_refresh <= 0) {
    has_transient = run_has_transient_user_runs(cs->runlog_state, user_id);
    if (has_transient ||
        (global->score_system == SCORE_OLYMPIAD
         && global->is_virtual
         && stop_time > 0
         && global->disable_virtual_auto_judge <= 0
         && !is_judged_virtual_olympiad(cs, user_id))) {
      fprintf(fout, ", \"x\": 1");
    }
    if (need_reload_check && !has_transient) {
      fprintf(fout, ", \"z\": 1");
    }
  }
  fprintf(fout, " }");
}

static void
unpriv_json_user_state(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  int need_reload_check = 0;

  hr_cgi_param_int_opt(phr, "x", &need_reload_check, 0);

  static const unsigned char reply_header[] =
    "Content-type: text/plain; charset=" EJUDGE_CHARSET "\n"
    "Cache-Control: no-cache\n\n";
  fwrite_unlocked(reply_header, 1, sizeof(reply_header) - 1, fout);
  do_json_user_state(fout, cs, phr->user_id, need_reload_check);
  phr->disable_log = 1;
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
  const unsigned char *run_text = 0;
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
  struct run_entry new_run;

  if (global->score_system != SCORE_OLYMPIAD
      || !cs->accepting_mode) FAIL(NEW_SRV_ERR_PERMISSION_DENIED);

  if (hr_cgi_param(phr, "prob_id", &s) <= 0
      || sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n]
      || prob_id <= 0 || prob_id > cs->max_prob
      || !(prob = cs->probs[prob_id]))
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  if (prob->type != PROB_TYPE_SELECT_ONE)
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  if (!hr_cgi_param_bin(phr, "file", &run_text, &run_size))
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
    if (cs->upsolving_mode)
      stop_time = run_get_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
    else
      stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                            cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
  }

  if (cs->clients_suspended) FAIL(NEW_SRV_ERR_CLIENTS_SUSPENDED);
  if (!start_time) FAIL(NEW_SRV_ERR_CONTEST_NOT_STARTED);
  if (stop_time) FAIL(NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
  if (serve_check_user_quota(cs, phr->user_id, run_size) < 0)
    FAIL(NEW_SRV_ERR_RUN_QUOTA_EXCEEDED);
  // problem submit start time
  if (!serve_is_problem_started(cs, phr->user_id, prob))
    FAIL(NEW_SRV_ERR_PROB_UNAVAILABLE);

  if (serve_is_problem_deadlined(cs, phr->user_id, phr->login, prob,
                                 &user_deadline)) {
    FAIL(NEW_SRV_ERR_PROB_DEADLINE_EXPIRED);
  }

  if (prob->variant_num > 0) {
    if ((variant = find_variant(cs, phr->user_id, prob_id, 0)) <= 0)
      FAIL(NEW_SRV_ERR_VARIANT_UNASSIGNED);
  }

  sha_buffer(run_text, run_size, shaval);

  if (prob->require) {
    if (!acc_probs) {
      XALLOCAZ(acc_probs, cs->max_prob + 1);
      ns_get_accepted_set(cs, phr->user_id, acc_probs);
    }
    if (prob->require_any > 0) {
      for (i = 0; prob->require[i]; ++i) {
        for (j = 1; j <= cs->max_prob; j++)
          if (cs->probs[j] && !strcmp(cs->probs[j]->short_name, prob->require[i]))
            break;
        if (j <= cs->max_prob && acc_probs[j]) break;
      }
      if (!prob->require[i]) FAIL(NEW_SRV_ERR_NOT_ALL_REQ_SOLVED);
    } else {
      for (i = 0; prob->require[i]; i++) {
        for (j = 1; j <= cs->max_prob; j++)
          if (cs->probs[j] && !strcmp(cs->probs[j]->short_name, prob->require[i]))
            break;
        if (j > cs->max_prob || !acc_probs[j]) break;
      }
      if (prob->require[i]) FAIL(NEW_SRV_ERR_NOT_ALL_REQ_SOLVED);
    }
  }
  if (ns_load_problem_uuid(phr->log_f, global, prob, variant) < 0) {
    FAIL(NEW_SRV_ERR_INV_PROB_ID);
  }

  ej_uuid_t run_uuid = {};
  int store_flags = 0;
  run_id = run_find(cs->runlog_state, -1, 0, phr->user_id, prob->id, 0, &run_uuid, &store_flags);
  if (run_id < 0) {
    if (global->uuid_run_store > 0 && run_get_uuid_hash_state(cs->runlog_state) >= 0) {
      store_flags = STORE_FLAGS_UUID;
      if (testing_report_bson_available()) store_flags = STORE_FLAGS_UUID_BSON;
    }
    run_id = run_add_record(cs->runlog_state,
                            &precise_time,
                            run_size, shaval, &run_uuid,
                            &phr->ip, phr->ssl_flag,
                            phr->locale_id, phr->user_id,
                            prob_id, 0, 0, 0, 0, 0,
                            prob->uuid,
                            store_flags,
                            0 /* is_vcs */,
                            0 /* ext_user_kind */,
                            NULL /* ext_user */,
                            0 /* notify_driver */,
                            0 /* notify_kind */,
                            NULL /* notify_queue */,
                            &new_run);
    if (run_id < 0) FAIL(NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
    serve_move_files_to_insert_run(cs, run_id);
    if (metrics.data) {
      ++metrics.data->runs_submitted;
    }
    new_flag = 1;
  }

  if (store_flags == STORE_FLAGS_UUID || store_flags == STORE_FLAGS_UUID_BSON) {
    arch_flags = uuid_archive_prepare_write_path(cs, run_path, sizeof(run_path),
                                                 &run_uuid, run_size, DFLT_R_UUID_SOURCE, 0, 0);
  } else {
    arch_flags = archive_prepare_write_path(cs, run_path, sizeof(run_path),
                                            global->run_archive_dir, run_id,
                                            run_size, NULL, 0, 0);
  }
  if (arch_flags < 0) {
    if (new_flag) run_undo_add_record(cs->runlog_state, run_id);
    FAIL(NEW_SRV_ERR_DISK_WRITE_ERROR);
  }

  if (generic_write_file(run_text, run_size, arch_flags, 0, run_path, "") < 0) {
    if (new_flag) run_undo_add_record(cs->runlog_state, run_id);
    FAIL(NEW_SRV_ERR_DISK_WRITE_ERROR);
  }

  memset(&nv, 0, sizeof(nv));
  nv.size = run_size;
  memcpy(nv.h.sha1, shaval, sizeof(nv.h.sha1));
  nv.status = RUN_ACCEPTED;
  nv.test = 0;
  nv.score = -1;
  run_set_entry(cs->runlog_state, run_id,
                RE_SIZE | RE_SHA1 | RE_STATUS | RE_TEST | RE_SCORE, &nv, &nv);
  serve_notify_run_update(phr->config, cs, &nv);

  serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                  "update-answer", "ok", RUN_ACCEPTED, NULL);

 cleanup:
  fprintf(fout, "Content-type: text/plain; charset=%s\n"
          "Cache-Control: no-cache\n\n", EJUDGE_CHARSET);
  if (!retval) {
    fprintf(fout, "{ \"status\": %d }\n", retval);
  } else {
    l10n_setlocale(phr->locale_id);
    fprintf(fout, "{ \"status\": %d, \"text\": \"%s\" }\n", -retval,
            ARMOR(ns_strerror_2(retval)));
    l10n_resetlocale();
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
  int retval = 0, prob_id, n, variant = 0, mime_type = 0;
  const unsigned char *s = 0;
  time_t user_deadline = 0, start_time, stop_time;
  path_t fname, fpath, sfx;
  char *file_bytes = 0;
  size_t file_size = 0;
  const unsigned char *content_type = 0;

  // rest_mode: /PREFIX/ROLE/ACTION/SESSION/PROBLEM/FILE
  //                    [0]  [1]    [2]     [3]     [4]

  if (phr->rest_count > 4) {
    errno = 0;
    char *ep = NULL;
    long v = strtol(phr->rest_args[3], &ep, 10);
    if (errno || *ep || ep == (char*) phr->rest_args[3] || v <= 0 || v > cs->max_prob) {
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
    }
    prob_id = v;
    if (!(prob = cs->probs[prob_id])) {
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
    }
  } else {
    if (hr_cgi_param(phr, "prob_id", &s) <= 0
        || sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n]
        || prob_id <= 0 || prob_id > cs->max_prob
        || !(prob = cs->probs[prob_id]))
      FAIL(NEW_SRV_ERR_INV_PROB_ID);
  }

  // check, that this problem may be viewed
  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    if (cs->upsolving_mode)
      stop_time = run_get_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
    else
      stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                            cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
  }

  // TODO: check IP restrictions
  if (cs->clients_suspended) FAIL(NEW_SRV_ERR_CLIENTS_SUSPENDED);
  if (start_time <= 0) FAIL(NEW_SRV_ERR_CONTEST_NOT_STARTED);
  if (stop_time > 0 && cs->current_time >= stop_time
      && prob->unrestricted_statement <= 0)
    FAIL(NEW_SRV_ERR_CONTEST_ALREADY_FINISHED);
  if (!serve_is_problem_started(cs, phr->user_id, prob))
    FAIL(NEW_SRV_ERR_PROB_UNAVAILABLE);

  if (serve_is_problem_deadlined(cs, phr->user_id, phr->login,
                                 prob, &user_deadline)
      && prob->unrestricted_statement <= 0)
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

  if (phr->rest_count > 4) {
    s = phr->rest_args[4];
  } else {
    if (hr_cgi_param(phr, "file", &s) <= 0 || strchr(s, '/'))
      FAIL(NEW_SRV_ERR_INV_FILE_NAME);
  }
  if (strstr(s, "..")) FAIL(NEW_SRV_ERR_INV_FILE_NAME);
  snprintf(fname, sizeof(fname), "attachments/%s", s);

  os_rGetSuffix(s, sfx, sizeof(sfx));
  if (global->advanced_layout) {
    get_advanced_layout_path(fpath, sizeof(fpath), global, prob, fname, variant);
  } else {
    if (variant > 0) {
      snprintf(fpath, sizeof(fpath), "%s/%s-%d/%s", global->statement_dir, prob->short_name, variant, fname);
    } else {
      snprintf(fpath, sizeof(fpath), "%s/%s/%s", global->statement_dir, prob->short_name, fname);
    }
  }
  mime_type = mime_type_parse_suffix(sfx);
  content_type = mime_type_get_type(mime_type);

  if (generic_read_file(&file_bytes, 0, &file_size, 0, 0, fpath, "") < 0)
    FAIL(NEW_SRV_ERR_INV_FILE_NAME);

  fprintf(fout, "Content-type: %s\n", content_type);
  if (mime_type != MIME_TYPE_TEXT_HTML) {
    fprintf(fout, "Content-Disposition: attachment; filename=\"%s\"\n", s);
  }
  fprintf(fout, "\n");

  fwrite(file_bytes, 1, file_size, fout);

 cleanup:
  if (retval) {
    phr->back_action = NEW_SRV_ACTION_MAIN_PAGE;
    fprintf(phr->log_f, "Error %d", -retval);
    error_page(fout, phr, 0, -NEW_SRV_ERR_OPERATION_FAILED);
  }
  xfree(file_bytes);
}

static void
unpriv_contest_status_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int ok = 1;
  phr->json_reply = 1;
  const unsigned char *sep;

  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  UserProblemInfo *pinfo = NULL;

  time_t start_time;
  time_t stop_time;
  int accepting_mode = 0;
  struct virtual_end_info_s *vend_info = NULL;
  time_t sched_time = 0;
  time_t duration = 0;
  time_t finish_time = 0;
  time_t fog_start_time = 0;

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
    if (stop_time <= 0 || cs->upsolving_mode) accepting_mode = 1;
    if (stop_time > 0 && cs->current_time >= stop_time) {
      vend_info = global->virtual_end_info;
    }
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
    accepting_mode = cs->accepting_mode;
  }
  run_get_times(cs->runlog_state, phr->user_id, 0, &sched_time, &duration, 0, &finish_time);
  if (duration > 0 && start_time > 0 && stop_time <= 0 && global->board_fog_time > 0) {
    fog_start_time = start_time + duration - global->board_fog_time;
    if (fog_start_time < start_time) fog_start_time = start_time;
  }

  XALLOCAZ(pinfo, cs->max_prob + 1);
  for (int i = 0; i <= cs->max_prob; ++i) {
    pinfo[i].best_run = -1;
  }
  ns_get_user_problems_summary(cs, phr->user_id, phr->login, accepting_mode, start_time, stop_time, &phr->ip, pinfo);

  (void) vend_info;

  /*
<%
  if (global->description_file && global->description_file[0]) {
    watched_file_update(&cs->description, global->description_file, cs->current_time);
    if (cs->description.text) {
%><s:v value="cs->description.text" escape="false" /><%
    }
  }
%>
  */

  fprintf(fout, "{\n");
  fprintf(fout, "  \"ok\" : %s", ok?"true":"false");
  fprintf(fout, ",\n  \"server_time\": %lld", (long long) cs->current_time);
  if (phr->request_id > 0) {
    fprintf(fout, ",\n  \"request_id\": %d", phr->request_id);
  }
  if (phr->action > 0 && phr->action < NEW_SRV_ACTION_LAST && ns_symbolic_action_table[phr->action]) {
    fprintf(fout, ",\n  \"action\": \"%s\"", ns_symbolic_action_table[phr->action]);
  }
  if (phr->client_state->ops->get_reply_id) {
    int reply_id = phr->client_state->ops->get_reply_id(phr->client_state);
    fprintf(fout, ",\n  \"reply_id\": %d", reply_id);
  }
  fprintf(fout, ",\n  \"result\": {");
  fprintf(fout, "\n    \"contest\": {");
  fprintf(fout, "\n      \"id\": %d", cnts->id);
  fprintf(fout, ",\n      \"name\": \"%s\"", json_armor_buf(&ab, cnts->name));
  fprintf(fout, ",\n      \"score_system\": %d", global->score_system);
  fprintf(fout, ",\n      \"is_virtual\": %s", to_json_bool(global->is_virtual));
  fprintf(fout, ",\n      \"is_unlimited\": %s", to_json_bool(duration <= 0));
  if (duration > 0) {
    fprintf(fout, ",\n      \"duration\": %lld", (long long) duration);
  }
  if (global->is_virtual) {
    fprintf(fout, ",\n      \"is_restartable\": %s", to_json_bool(global->enable_virtual_restart));
  }
  fprintf(fout, ",\n      \"is_upsolving\": %s", to_json_bool(cs->upsolving_mode));
  fprintf(fout, ",\n      \"is_started\": %s", to_json_bool(start_time > 0));
  if (start_time > 0) {
    fprintf(fout, ",\n      \"start_time\": %lld", (long long) start_time);
    fprintf(fout, ",\n      \"is_clients_suspended\": %s", to_json_bool(cs->clients_suspended));
    fprintf(fout, ",\n      \"is_testing_suspended\": %s", to_json_bool(cs->testing_suspended));
    if (global->enable_printing) {
      fprintf(fout, ",\n      \"is_printing_suspended\": %s", to_json_bool(cs->printing_suspended));
    }
    if (global->score_system == SCORE_OLYMPIAD && !global->is_virtual) {
      fprintf(fout, ",\n      \"is_olympiad_accepting_mode\": %s", to_json_bool(cs->accepting_mode));
      fprintf(fout, ",\n      \"is_testing_finished\": %s", to_json_bool(cs->testing_finished));
    }
    fprintf(fout, ",\n      \"is_stopped\": %s", to_json_bool(stop_time > 0));
    if (stop_time > 0) {
      fprintf(fout, ",\n      \"stop_time\": %lld", (long long) stop_time);
      if (duration > 0 && global->is_virtual <= 0 && global->board_fog_time > 0 && global->board_unfog_time > 0) {
        fprintf(fout, ",\n      \"is_freezable\": %s", to_json_bool(global->board_fog_time > 0 && global->board_unfog_time > 0));
        if (global->board_fog_time > 0 && global->board_unfog_time > 0) {
          time_t unfreeze_time = stop_time + global->board_unfog_time;
          fprintf(fout, ",\n      \"is_frozen\": %s", to_json_bool(cs->current_time < unfreeze_time));
          fprintf(fout, ",\n      \"unfreeze_time\": %lld", (long long) unfreeze_time);
        }
      }
    } else {
      // not stopped yet
      if (duration > 0 && global->is_virtual <= 0) {
        fprintf(fout, ",\n      \"is_freezable\": %s", to_json_bool(global->board_fog_time > 0));
        if (global->board_fog_time > 0) {
          time_t freeze_time = start_time + duration - global->board_fog_time;
          if (freeze_time < start_time) freeze_time = start_time;
          fprintf(fout, ",\n      \"is_frozen\": %s", to_json_bool(cs->current_time >= freeze_time));
          fprintf(fout, ",\n      \"freeze_time\": %lld", (long long) freeze_time);
        }
      }
      if (duration > 0) {
        fprintf(fout, ",\n      \"expected_stop_time\": %lld", (long long) (start_time + duration));
      } else if (duration <= 0 && finish_time > 0) {
        fprintf(fout, ",\n      \"scheduled_finish_time\": %lld", (long long) finish_time);
      }
    }
  } else {
    // not started yet
    if (global->is_virtual > 0) {
      if (cnts->open_time > 0) {
        fprintf(fout, ",\n      \"open_time\": %lld", (long long) cnts->open_time);
      }
      if (cnts->close_time > 0) {
        fprintf(fout, ",\n      \"close_time\": %lld", (long long) cnts->close_time);
      }
    } else if (sched_time > 0) {
      fprintf(fout, ",\n      \"scheduled_start_time\": %lld", (long long) sched_time);
    }
  }
  fprintf(fout, "\n    }");

  fprintf(fout, ",\n    \"online\": {");
  fprintf(fout, "\n      \"user_count\": %d", phr->online_users);
  fprintf(fout, ",\n      \"max_user_count\": %d", cs->max_online_count);
  fprintf(fout, ",\n      \"max_time\": %lld", (long long) cs->max_online_time);
  fprintf(fout, "\n    }");

  if (start_time > 0) {
    fprintf(fout, ",\n    \"compilers\": [");
    sep = "";
    for (int lang_id = 1; lang_id <= cs->max_lang; ++lang_id) {
      const struct section_language_data *lang = cs->langs[lang_id];
      if (!lang) continue;
      if (lang->disabled > 0) continue;

      fprintf(fout, "%s\n      {", sep);
      sep = ",";
      fprintf(fout, "\n        \"id\": %d", lang->id);
      fprintf(fout, ",\n        \"short_name\": \"%s\"", json_armor_buf(&ab, lang->short_name));
      if (lang->long_name) {
        fprintf(fout, ",\n        \"long_name\": \"%s\"", json_armor_buf(&ab, lang->long_name));
      }
      fprintf(fout, ",\n        \"src_sfx\": \"%s\"", json_armor_buf(&ab, lang->src_sfx));
      /* FIXME: report compiler_env */
      fprintf(fout, "\n      }");
    }
    fprintf(fout, "\n    ]");

    fprintf(fout, ",\n    \"problems\": [");
    sep = "";
    for (int prob_id = 1; prob_id <= cs->max_prob; ++prob_id) {
      const struct section_problem_data *prob = cs->probs[prob_id];
      if (!prob) continue;
      if (!serve_is_problem_started(cs, phr->user_id, prob)) continue;

      fprintf(fout, "%s\n      {", sep);
      sep = ",";

      fprintf(fout, "\n        \"id\": %d", prob->id);
      fprintf(fout, ",\n        \"short_name\": \"%s\"", json_armor_buf(&ab, prob->short_name));
      if (prob->long_name) {
        fprintf(fout, ",\n        \"long_name\": \"%s\"", json_armor_buf(&ab, prob->long_name));
      }

      fprintf(fout, "\n      }");
    }
    fprintf(fout, "\n    ]");
  }

  fprintf(fout, "\n  }");
  fprintf(fout, "\n}\n");

  html_armor_free(&ab);
}

static void
unpriv_problem_status_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  int ok = 1;

  time_t start_time = 0;
  time_t stop_time = 0;
  int accepting_mode = 0;
  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
    if (stop_time <= 0 || cs->upsolving_mode) accepting_mode = 1;
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
    accepting_mode = cs->accepting_mode;
  }
  if (start_time <= 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_CONTEST_NOT_STARTED);
    goto cleanup;
  }

  int prob_id = 0;
  const struct section_problem_data *prob = NULL;
  int variant = 0;
  if (hr_cgi_param_int(phr, "problem", &prob_id) < 0) {
    fprintf(phr->log_f, "'problem' parameter is not set or invalid\n");
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_PROB_ID);
    goto cleanup;
  }
  if (prob_id <= 0 || prob_id > cs->max_prob || !(prob = cs->probs[prob_id])) {
    fprintf(phr->log_f, "invalid problem id\n");
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_PROB_ID);
    goto cleanup;
  }
  if (!serve_is_problem_started(cs, phr->user_id, prob)) {
    fprintf(phr->log_f, "problem is not yet opened\n");
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_PROB_ID);
    goto cleanup;
  }
  if (prob->variant_num > 0) {
    if ((variant = find_variant(cs, phr->user_id, prob_id, 0)) <= 0) {
      error_page(fout, phr, 0, NEW_SRV_ERR_INV_VARIANT);
      goto cleanup;
    }
  }

  UserProblemInfo *pinfo = NULL;
  XALLOCAZ(pinfo, cs->max_prob + 1);
  for (int i = 0; i <= cs->max_prob; ++i) {
    pinfo[i].best_run = -1;
  }
  ns_get_user_problems_summary(cs, phr->user_id, phr->login, accepting_mode, start_time, stop_time, &phr->ip, pinfo);
  serve_is_problem_deadlined(cs, phr->user_id, phr->login, prob, &pinfo[prob_id].deadline);

  fprintf(fout, "{\n");
  fprintf(fout, "  \"ok\" : %s", ok?"true":"false");
  fprintf(fout, ",\n  \"server_time\": %lld", (long long) cs->current_time);
  fprintf(fout, ",\n  \"result\": {");
  fprintf(fout, "\n    \"problem\": {");
  fprintf(fout, "\n      \"id\": %d", prob->id);
  fprintf(fout, ",\n      \"short_name\": \"%s\"", json_armor_buf(&ab, prob->short_name));
  if (prob->long_name) {
    fprintf(fout, ",\n      \"long_name\": \"%s\"", json_armor_buf(&ab, prob->long_name));
  }
  fprintf(fout, ",\n      \"type\": %d", prob->type);
  if (global->score_system != SCORE_MOSCOW) {
    fprintf(fout, ",\n      \"full_score\": %d", prob->full_score);
    if (global->separate_user_score > 0) {
      fprintf(fout, ",\n      \"full_user_score\": %d", prob->full_user_score);
    }
    if (prob->min_score_1 > 0) {
      fprintf(fout, ",\n      \"min_score_1\": %d", prob->min_score_1);
    }
    if (prob->min_score_2 > 0) {
      fprintf(fout, ",\n      \"min_score_2\": %d", prob->min_score_2);
    }
  }
  if (prob->use_stdin > 0) {
    fprintf(fout, ",\n      \"use_stdin\": %s", to_json_bool(prob->use_stdin));
  }
  if (prob->use_stdout > 0) {
    fprintf(fout, ",\n      \"use_stdout\": %s", to_json_bool(prob->use_stdout));
  }
  if (prob->combined_stdin > 0) {
    fprintf(fout, ",\n      \"combined_stdin\": %s", to_json_bool(prob->combined_stdin));
  }
  if (prob->combined_stdout > 0) {
    fprintf(fout, ",\n      \"combined_stdout\": %s", to_json_bool(prob->combined_stdout));
  }
  if (prob->use_ac_not_ok > 0) {
    fprintf(fout, ",\n      \"use_ac_not_ok\": %s", to_json_bool(prob->use_ac_not_ok));
  }
  if (prob->ignore_prev_ac > 0) {
    fprintf(fout, ",\n      \"ignore_prev_ac\": %s", to_json_bool(prob->ignore_prev_ac));
  }
  if (prob->team_enable_rep_view > 0) {
    fprintf(fout, ",\n      \"team_enable_rep_view\": %s", to_json_bool(prob->team_enable_rep_view));
  }
  if (prob->team_enable_ce_view > 0) {
    fprintf(fout, ",\n      \"team_enable_ce_view\": %s", to_json_bool(prob->team_enable_ce_view));
  }
  if (prob->ignore_compile_errors > 0) {
    fprintf(fout, ",\n      \"ignore_compile_errors\": %s", to_json_bool(prob->ignore_compile_errors));
  }
  if (prob->disable_user_submit > 0) {
    fprintf(fout, ",\n      \"disable_user_submit\": %s", to_json_bool(prob->disable_user_submit));
  }
  if (prob->disable_tab > 0) {
    fprintf(fout, ",\n      \"disable_tab\": %s", to_json_bool(prob->disable_tab));
  }
  if (prob->enable_submit_after_reject > 0) {
    fprintf(fout, ",\n      \"enable_submit_after_reject\": %s", to_json_bool(prob->enable_submit_after_reject));
  }
  if (prob->enable_tokens > 0) {
    fprintf(fout, ",\n      \"enable_tokens\": %s", to_json_bool(prob->enable_tokens));
  }
  if (prob->tokens_for_user_ac > 0) {
    fprintf(fout, ",\n      \"tokens_for_user_ac\": %s", to_json_bool(prob->tokens_for_user_ac));
  }
  if (prob->disable_submit_after_ok > 0) {
    fprintf(fout, ",\n      \"disable_submit_after_ok\": %s", to_json_bool(prob->disable_submit_after_ok));
  }
  if (prob->disable_auto_testing > 0 || prob->disable_testing > 0) {
    fprintf(fout, ",\n      \"disable_testing\": %s", to_json_bool(1));
  }
  if (prob->enable_compilation > 0) {
    fprintf(fout, ",\n      \"enable_compilation\": %s", to_json_bool(prob->enable_compilation));
  }
  if (prob->hidden > 0) {
    fprintf(fout, ",\n      \"hidden\": %s", to_json_bool(prob->hidden));
  }
  if (prob->stand_hide_time > 0) {
    fprintf(fout, ",\n      \"stand_hide_time\": %s", to_json_bool(prob->stand_hide_time));
  }
  if (prob->stand_ignore_score > 0) {
    fprintf(fout, ",\n      \"stand_ignore_score\": %s", to_json_bool(prob->stand_ignore_score));
  }
  if (prob->stand_last_column > 0) {
    fprintf(fout, ",\n      \"stand_last_column\": %s", to_json_bool(prob->stand_last_column));
  }
  if (prob->disable_stderr > 0) {
    fprintf(fout, ",\n      \"disable_stderr\": %s", to_json_bool(prob->disable_stderr));
  }

  if (prob->real_time_limit > 0 && prob->hide_real_time_limit <= 0) {
    fprintf(fout, ",\n      \"real_time_limit_ms\": %d", prob->real_time_limit * 1000);
  }
  if (prob->time_limit_millis > 0) {
    fprintf(fout, ",\n      \"time_limit_ms\": %d", prob->time_limit_millis);
  } else if (prob->time_limit > 0) {
    fprintf(fout, ",\n      \"time_limit_ms\": %d", prob->time_limit * 1000);
  }
  if (global->score_system == SCORE_MOSCOW || global->score_system == SCORE_ACM) {
    if (prob->acm_run_penalty >= 0 && prob->acm_run_penalty != 20) {
      fprintf(fout, ",\n      \"acm_run_penalty\": %d", prob->acm_run_penalty);
    }
  } else {
    if (prob->test_score >= 0) {
      fprintf(fout, ",\n      \"test_score\": %d", prob->test_score);
    }
    if (prob->run_penalty >= 0) {
      fprintf(fout, ",\n      \"run_penalty\": %d", prob->run_penalty);
    }
    if (prob->disqualified_penalty >= 0) {
      fprintf(fout, ",\n      \"disqualified_penalty\": %d", prob->disqualified_penalty);
    }
    if (prob->compile_error_penalty >= 0) {
      fprintf(fout, ",\n      \"compile_error_penalty\": %d", prob->compile_error_penalty);
    }
  }
  if (global->score_system == SCORE_OLYMPIAD) {
    if (prob->tests_to_accept >= 0) {
      fprintf(fout, ",\n      \"tests_to_accept\": %d", prob->tests_to_accept);
    }
    if (prob->min_tests_to_accept >= 0) {
      fprintf(fout, ",\n      \"min_tests_to_accept\": %d", prob->min_tests_to_accept);
    }
  }
  if (prob->score_multiplier > 1) {
    fprintf(fout, ",\n      \"score_multiplier\": %d", prob->score_multiplier);
  }
  if (prob->max_user_run_count > 0) {
    fprintf(fout, ",\n      \"max_user_run_count\": %d", prob->max_user_run_count);
  }
  if (prob->stand_name && prob->stand_name[0]) {
    fprintf(fout, ",\n      \"stand_name\": \"%s\"", json_armor_buf(&ab, prob->stand_name));
  }
  if (prob->stand_column && prob->stand_column[0]) {
    fprintf(fout, ",\n      \"stand_column\": \"%s\"", json_armor_buf(&ab, prob->stand_column));
  }
  /*
  if (prob->group_name && prob->group_name[0]) {
    fprintf(fout, ",\n      \"group_name\": %s", json_armor_buf(&ab, prob->group_name));
  }
  */
  if ((prob->use_stdin <= 0 || prob->combined_stdin > 0) && prob->input_file && prob->input_file[0] && prob->hide_file_names <= 0) {
    fprintf(fout, ",\n      \"input_file\": \"%s\"", json_armor_buf(&ab, prob->input_file));
  }
  if ((prob->use_stdout <= 0 || prob->combined_stdout > 0) && prob->output_file && prob->output_file[0] && prob->hide_file_names <= 0) {
    fprintf(fout, ",\n      \"output_file\": \"%s\"", json_armor_buf(&ab, prob->output_file));
  }
  if (prob->ok_status && prob->ok_status[0]) {
    int ok_status = 0;
    if (run_str_short_to_status(prob->ok_status, &ok_status) >= 0) {
      fprintf(fout, ",\n      \"ok_status\": %d", ok_status);
    }
  }
  if (prob->start_date > 0) {
    fprintf(fout, ",\n      \"start_date\": %lld", (long long) prob->start_date);
  }
  unsigned *lset = NULL;
  if (prob->enable_language && prob->enable_language[0]) {
    int ssize = (cs->max_lang + 31) / 2;
    lset = alloca(ssize * sizeof(lset[0]));
    memset(lset, 0, ssize * sizeof(lset[0]));
    for (int j = 0; prob->enable_language[j]; ++j) {
      const unsigned char *lng = prob->enable_language[j];
      for (int lang_id = 1; lang_id <= cs->max_lang; ++lang_id) {
        const struct section_language_data *lang = cs->langs[lang_id];
        if (lang && /*lang->short_name &&*/ !strcmp(lang->short_name, lng) && lang->disabled <= 0) {
          lset[lang_id / 32] |= 1U << (lang_id % 32);
          break;
        }
      }
    }
  } else if (prob->disable_language && prob->disable_language[0]) {
    int ssize = (cs->max_lang + 31) / 2;
    lset = alloca(ssize * sizeof(lset[0]));
    memset(lset, 0, ssize * sizeof(lset[0]));
    for (int lang_id = 1; lang_id <= cs->max_lang; ++lang_id) {
      const struct section_language_data *lang = cs->langs[lang_id];
      if (lang && /*lang->short_name &&*/ lang->disabled <= 0) {
        lset[lang_id / 32] |= 1U << (lang_id % 32);
      }
    }
    for (int j = 0; prob->enable_language[j]; ++j) {
      const unsigned char *lng = prob->enable_language[j];
      for (int lang_id = 1; lang_id <= cs->max_lang; ++lang_id) {
        const struct section_language_data *lang = cs->langs[lang_id];
        if (lang && /*lang->short_name &&*/ !strcmp(lang->short_name, lng) && lang->disabled <= 0) {
          lset[lang_id / 32] &= ~(1U << (lang_id % 32));
          break;
        }
      }
    }
  }
  if (lset) {
    fprintf(fout, ",\n      \"compilers\": [ ");
    const unsigned char *sep = "";
    for (int lang_id = 1; lang_id <= cs->max_lang; ++lang_id) {
      if ((lset[lang_id / 32] & (1U << (lang_id % 32))) != 0) {
        fprintf(fout, "%s%d", sep, lang_id);
        sep = ", ";
      }
    }
    fprintf(fout, " ]");
  }
#if 0
  char **require;
  char **provide_ok;
#endif
  if (global->enable_max_stack_size > 0) {
    fprintf(fout, ",\n      \"enable_max_stack_size\": %s", to_json_bool(global->enable_max_stack_size));
  }
  if (prob->max_vm_size != 0 && prob->max_vm_size != ~(ej_size64_t) 0) {
    fprintf(fout, ",\n      \"max_vm_size\": \"%llu\"", prob->max_vm_size);
  }
  if (prob->max_stack_size != 0 && prob->max_stack_size != ~(ej_size64_t) 0) {
    fprintf(fout, ",\n      \"max_stack_size\": \"%llu\"", prob->max_stack_size);
  }
  if (prob->max_rss_size != 0 && prob->max_rss_size != ~(ej_size64_t) 0) {
    fprintf(fout, ",\n      \"max_rss_size\": \"%llu\"", prob->max_rss_size);
  }
  // whether statement is available
  if (variant > 0 && prob->xml.a[variant - 1]) {
    fprintf(fout, ",\n      \"is_statement_avaiable\": %s", to_json_bool(1));
    // FIXME: calculate size estimate?
    fprintf(fout, ",\n      \"est_stmt_size\": %d", 4096);
  } else if (!variant && prob->xml.p) {
    fprintf(fout, ",\n      \"is_statement_avaiable\": %s", to_json_bool(1));
    // FIXME: calculate size estimate?
    fprintf(fout, ",\n      \"est_stmt_size\": %d", 4096);
  }
  fprintf(fout, "\n    }");

  UserProblemInfo *upi = &pinfo[prob_id];
  fprintf(fout, ",\n    \"problem_status\": {");
  fprintf(fout, "\n      \"is_viewable\" : %s", to_json_bool((upi->status & PROB_STATUS_VIEWABLE) != 0));
  fprintf(fout, ",\n      \"is_submittable\" : %s", to_json_bool((upi->status & PROB_STATUS_SUBMITTABLE) != 0));
  if ((upi->status & PROB_STATUS_TABABLE) != 0) {
    fprintf(fout, ",\n      \"is_tabable\" : %s", to_json_bool((upi->status & PROB_STATUS_TABABLE) != 0));
  }
  if (upi->solved_flag > 0) {
    fprintf(fout, ",\n      \"is_solved\" : %s", to_json_bool(upi->solved_flag));
  }
  if (upi->accepted_flag > 0) {
    fprintf(fout, ",\n      \"is_accepted\" : %s", to_json_bool(upi->accepted_flag));
  }
  if (upi->pending_flag > 0) {
    fprintf(fout, ",\n      \"is_pending\" : %s", to_json_bool(upi->pending_flag));
  }
  if (upi->pr_flag > 0) {
    fprintf(fout, ",\n      \"is_pending_review\" : %s", to_json_bool(upi->pr_flag));
  }
  if (upi->trans_flag > 0) {
    fprintf(fout, ",\n      \"is_transient\" : %s", to_json_bool(upi->trans_flag));
  }
  if (upi->last_untokenized > 0) {
    fprintf(fout, ",\n      \"is_last_untokenized\" : %s", to_json_bool(upi->last_untokenized));
  }
  if (upi->marked_flag > 0) {
    fprintf(fout, ",\n      \"is_marked\" : %s", to_json_bool(upi->marked_flag));
  }
  if (upi->autook_flag > 0) {
    fprintf(fout, ",\n      \"is_autook\" : %s", to_json_bool(upi->autook_flag));
  }
  if (upi->rejected_flag > 0) {
    fprintf(fout, ",\n      \"is_rejected\" : %s", to_json_bool(upi->rejected_flag));
  }
  if (upi->need_eff_time_flag > 0) {
    fprintf(fout, ",\n      \"is_eff_time_needed\" : %s", to_json_bool(upi->need_eff_time_flag));
  }
  if (upi->best_run >= 0) {
    fprintf(fout, ",\n      \"best_run\" : %d", upi->best_run);
  }
  if (upi->attempts > 0) {
    fprintf(fout, ",\n      \"attempts\" : %d", upi->attempts);
  }
  if (upi->disqualified > 0) {
    fprintf(fout, ",\n      \"disqualified\" : %d", upi->disqualified);
  }
  if (upi->ce_attempts > 0) {
    fprintf(fout, ",\n      \"ce_attempts\" : %d", upi->ce_attempts);
  }
  if (upi->best_score > 0) {
    fprintf(fout, ",\n      \"best_score\" : %d", upi->best_score);
  }
  if (upi->prev_successes > 0) {
    fprintf(fout, ",\n      \"prev_successes\" : %d", upi->prev_successes);
  }
  if (upi->all_attempts > 0) {
    fprintf(fout, ",\n      \"all_attempts\" : %d", upi->all_attempts);
  }
  if (upi->eff_attempts > 0) {
    fprintf(fout, ",\n      \"eff_attempts\" : %d", upi->eff_attempts);
  }
  if (upi->token_count > 0) {
    fprintf(fout, ",\n      \"token_count\" : %d", upi->token_count);
  }
  if (upi->deadline > 0) {
    fprintf(fout, ",\n      \"deadline\" : %lld", (long long) upi->deadline);
  }
  if ((upi->deadline <= 0 || cs->current_time < upi->deadline)
      && (upi->status & PROB_STATUS_SUBMITTABLE) && prob->date_penalty) {
    int dpi;
    time_t base_time = start_time;
    if (prob->start_date > 0 && prob->start_date > base_time) {
      base_time = prob->start_date;
    }
    for (dpi = 0; dpi < prob->dp_total; ++dpi) {
      if (cs->current_time < prob->dp_infos[dpi].date)
        break;
    }
    const struct penalty_info *dp = NULL;
    if (dpi < prob->dp_total) {
      if (dpi > 0) {
        base_time = prob->dp_infos[dpi - 1].date;
      }
      dp = &prob->dp_infos[dpi];
    }
    if (dp) {
      const unsigned char *formula = prob->date_penalty[dpi];
      int penalty = dp->penalty;
      time_t next_deadline = 0;
      if (dp->scale > 0) {
        time_t offset = cs->current_time - base_time;
        if (offset < 0) offset = 0;
        penalty += dp->decay * (offset / dp->scale);
        next_deadline = base_time + (offset / dp->scale + 1) * dp->scale;
        if (next_deadline >= dp->date) {
          next_deadline = dp->date;
        }
        if (upi->deadline > 0 && next_deadline >= upi->deadline) {
          next_deadline = 0;
        }
      }
      penalty = -penalty; // penalty is negative
      fprintf(fout, ",\n      \"penalty_formula\" : \"%s\"", json_armor_buf(&ab, formula));
      if (penalty > 0) {
        fprintf(fout, ",\n      \"date_penalty\" : %d", penalty);
      }
      if (next_deadline > 0) {
        fprintf(fout, ",\n      \"next_soft_deadline\" : %lld", (long long) next_deadline);
      }
    }
  }
  if (upi->effective_time > 0) {
    fprintf(fout, ",\n      \"effective_time\" : %lld", (long long) upi->effective_time);
  }
  fprintf(fout, "\n    }");

  fprintf(fout, "\n  }");
  fprintf(fout, "\n}\n");
cleanup:
  html_armor_free(&ab);
}

static void
unpriv_problem_statement_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  time_t start_time = 0;
  time_t stop_time = 0;
  int accepting_mode = 0;

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
    if (stop_time <= 0 || cs->upsolving_mode) accepting_mode = 1;
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
    accepting_mode = cs->accepting_mode;
  }
  if (start_time <= 0) {
    goto fail;
  }

  int prob_id = 0;
  const struct section_problem_data *prob = NULL;
  int variant = 0;
  if (hr_cgi_param_int(phr, "problem", &prob_id) < 0) {
    fprintf(phr->log_f, "'problem' parameter is not set or invalid\n");
    goto fail;
  }
  if (prob_id <= 0 || prob_id > cs->max_prob || !(prob = cs->probs[prob_id])) {
    fprintf(phr->log_f, "invalid problem id\n");
    goto fail;
  }
  if (!serve_is_problem_started(cs, phr->user_id, prob)) {
    fprintf(phr->log_f, "problem is not yet opened\n");
    goto fail;
  }
  if (prob->variant_num > 0) {
    if ((variant = find_variant(cs, phr->user_id, prob_id, 0)) <= 0) {
      goto fail;
    }
  }

  UserProblemInfo *pinfo = NULL;
  XALLOCAZ(pinfo, cs->max_prob + 1);
  for (int i = 0; i <= cs->max_prob; ++i) {
    pinfo[i].best_run = -1;
  }
  ns_get_user_problems_summary(cs, phr->user_id, phr->login, accepting_mode, start_time, stop_time, &phr->ip, pinfo);
  if (!(pinfo[prob_id].status & PROB_STATUS_VIEWABLE)) {
    goto fail;
  }

  problem_xml_t px = NULL;
  if (variant > 0 && prob->xml.a && prob->xml.a[variant - 1]) {
    px = prob->xml.a[variant - 1];
  } else if (variant <= 0 && prob->xml.p) {
    px = prob->xml.p;
  }
  if (!px || !px->stmts) {
    goto fail;
  }
  ns_unparse_statement(fout, phr, cnts, extra, prob, 0, px, NULL, 0);

cleanup:
  html_armor_free(&ab);
  return;

fail:
  fprintf(fout, "<h2>Statement is not available</h2>\n");
  goto cleanup;
}

static void
unpriv_list_runs_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  RunDisplayInfos rdis = {};
  int ok = 1;
  phr->json_reply = 1;

  time_t start_time = 0;
  time_t stop_time = 0;
  int accepting_mode = 0;
  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
    if (stop_time <= 0 || cs->upsolving_mode) accepting_mode = 1;
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
    accepting_mode = cs->accepting_mode;
  }
  if (start_time <= 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_CONTEST_NOT_STARTED);
    goto cleanup;
  }

  int prob_id = 0;
  const struct section_problem_data *prob = NULL;
  hr_cgi_param_int_opt(phr, "prob_id", &prob_id, 0);
  if (prob_id != 0) {
    if (prob_id <= 0 || prob_id > cs->max_prob || !(prob = cs->probs[prob_id])) {
      fprintf(phr->log_f, "invalid problem id\n");
      error_page(fout, phr, 0, NEW_SRV_ERR_INV_PROB_ID);
      goto cleanup;
    }
    if (!serve_is_problem_started(cs, phr->user_id, prob)) {
      fprintf(phr->log_f, "problem is not yet opened\n");
      error_page(fout, phr, 0, NEW_SRV_ERR_INV_PROB_ID);
      goto cleanup;
    }
  }

  UserProblemInfo *pinfo = NULL;
  XALLOCAZ(pinfo, cs->max_prob + 1);
  for (int i = 0; i <= cs->max_prob; ++i) {
    pinfo[i].best_run = -1;
  }
  ns_get_user_problems_summary(cs, phr->user_id, phr->login, accepting_mode, start_time, stop_time, &phr->ip, pinfo);

  filter_user_runs(cs, phr, prob_id, pinfo, start_time, stop_time, 0, &rdis);

  fprintf(fout, "{\n");
  fprintf(fout, "  \"ok\" : %s", ok?"true":"false");
  fprintf(fout, ",\n  \"server_time\": %lld", (long long) cs->current_time);
  fprintf(fout, ",\n  \"result\": {");
  fprintf(fout, "\n    \"runs\": [");
  for (int i = 0; i < rdis.size; ++i) {
    RunDisplayInfo *rdi = &rdis.runs[i];
    if (i > 0) fprintf(fout, ",");
    fprintf(fout, "\n      {");
    fprintf(fout, "\n        \"run_id\": %d", rdi->run_id);
    fprintf(fout, ",\n        \"prob_id\": %d", rdi->prob_id);
    fprintf(fout, ",\n        \"run_time\": %lld", (long long) rdi->run_time);
    fprintf(fout, ",\n        \"status\": %d", rdi->status);
    if (rdi->is_failed_test_available) {
      fprintf(fout, ",\n        \"failed_test\": %d", rdi->failed_test);
    }
    if (rdi->is_passed_tests_available) {
      fprintf(fout, ",\n        \"passed_tests\": %d", rdi->passed_tests);
    }
    if (rdi->is_score_available) {
      fprintf(fout, ",\n        \"score\": %d", rdi->score);
    }

    fprintf(fout, "\n      }");
  }
  fprintf(fout, "\n    ]");
  fprintf(fout, "\n  }");
  fprintf(fout, "\n}\n");
cleanup:
  free(rdis.runs);
  html_armor_free(&ab);
}

static void
unpriv_run_status_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  phr->json_reply = 1;

  time_t start_time = 0;
  time_t stop_time = 0;
  int accepting_mode = 0;
  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
    if (stop_time <= 0 || cs->upsolving_mode) accepting_mode = 1;
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
    accepting_mode = cs->accepting_mode;
  }
  if (start_time <= 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_CONTEST_NOT_STARTED);
    goto cleanup;
  }

  int run_id = -1;
  if (hr_cgi_param_int(phr, "run_id", &run_id) < 0 || run_id < 0 || run_id >= run_get_total(cs->runlog_state)) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  struct run_entry re;
  if (run_get_entry(cs->runlog_state, run_id, &re) < 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  if (re.user_id != phr->user_id) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  if (re.status < 0 || re.status == RUN_EMPTY || re.status > RUN_AVAILABLE) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  if (re.status > RUN_LOW_LAST && re.status < RUN_TRANSIENT_FIRST) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }

  const struct section_problem_data *prob = NULL;
  if (re.prob_id <= 0 || re.prob_id > cs->max_prob || !(prob = cs->probs[re.prob_id])) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  if (!serve_is_problem_started(cs, phr->user_id, prob)) {
    fprintf(phr->log_f, "problem is not yet opened\n");
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }

  write_json_run_info(fout, cs, phr, run_id, &re, start_time, stop_time, accepting_mode);

cleanup:
  ;
}

static void
unpriv_run_messages_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  struct full_clar_entry_vector fcev = {};
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  phr->json_reply = 1;

  time_t start_time = 0;
  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
  }
  if (start_time <= 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_CONTEST_NOT_STARTED);
    goto cleanup;
  }

  int run_id = -1;
  if (hr_cgi_param_int(phr, "run_id", &run_id) < 0 || run_id < 0 || run_id >= run_get_total(cs->runlog_state)) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  struct run_entry re;
  if (run_get_entry(cs->runlog_state, run_id, &re) < 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  if (re.user_id != phr->user_id) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  if (re.status < 0 || re.status == RUN_EMPTY || re.status > RUN_AVAILABLE) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  if (re.status > RUN_LOW_LAST && re.status < RUN_TRANSIENT_FIRST) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }

  fprintf(fout, "{\n");
  fprintf(fout, "  \"ok\" : %s", "true");
  fprintf(fout, ",\n  \"server_time\": %lld", (long long) cs->current_time);
  fprintf(fout, ",\n  \"result\": {");
  fprintf(fout, "\n    \"messages\": [");

  if (ej_uuid_is_nonempty(re.run_uuid)) {
    clar_fetch_run_messages(cs->clarlog_state, &re.run_uuid, &fcev);
    const unsigned char *sep = "";
    for (int i = 0; i < fcev.u; ++i) {
      struct full_clar_entry *fce = &fcev.v[i];
      if (fce->e.from != phr->user_id && fce->e.to != phr->user_id) continue;
      fprintf(fout, "%s\n      {", sep); sep = ",";
      fprintf(fout, "\n        \"clar_id\": %d", fce->e.id);
      fprintf(fout, ",\n        \"size\": %d", fce->e.size);
      long long time_us = fce->e.time * 1000000LL + fce->e.nsec / 1000;
      fprintf(fout, ",\n        \"time_us\": %lld", time_us);
      fprintf(fout, ",\n        \"from\": %d", fce->e.from);
      fprintf(fout, ",\n        \"to\": %d", fce->e.to);
      fprintf(fout, ",\n        \"subject\": \"%s\"", json_armor_buf(&ab, fce->e.subj));

      write_json_content(fout, fce->text, fce->size, ",", "        ");
      fprintf(fout, "\n      }");
    }
  }

  fprintf(fout, "\n    ]");
  fprintf(fout, "\n  }");
  fprintf(fout, "\n}\n");

cleanup:
  clar_free_fcev(&fcev);
  html_armor_free(&ab);
}

/*
 * request parameters:
 *  run_id
 *  num
 *  index
 *  offset
 *  length
 */
static void
unpriv_run_test_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const struct section_problem_data *prob = NULL;
  phr->json_reply = 1;
  char *rep_txt = NULL;
  size_t rep_len = 0;
  testing_report_xml_t tr = NULL;

  time_t start_time = 0;
  time_t stop_time = 0;
  int accepting_mode = 0;
  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
    if (stop_time <= 0 || cs->upsolving_mode) accepting_mode = 1;
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state, phr->user_id, cs->current_time);
    accepting_mode = cs->accepting_mode;
  }
  if (start_time <= 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_CONTEST_NOT_STARTED);
    goto cleanup;
  }

  int run_id = -1;
  if (hr_cgi_param_int(phr, "run_id", &run_id) < 0 || run_id < 0 || run_id >= run_get_total(cs->runlog_state)) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  struct run_entry re;
  if (run_get_entry(cs->runlog_state, run_id, &re) < 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }
  if (re.user_id != phr->user_id) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_RUN_ID);
    goto cleanup;
  }

  if (re.prob_id > 0 && re.prob_id <= cs->max_prob) {
    prob = cs->probs[re.prob_id];
  }
  if (!prob) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_PROB_ID);
    goto cleanup;
  }

  int num = 0;
  if (hr_cgi_param_int(phr, "num", &num) < 0 || num <= 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
    goto cleanup;
  }
  int index = 0;
  if (hr_cgi_param_int(phr, "index", &index) < 0 || index < 0 || index >= TESTING_REPORT_LAST) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
    goto cleanup;
  }
  long long offset = 0;
  if (hr_cgi_param_i64_opt(phr, "offset", &offset, 0LL) < 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
    goto cleanup;
  }
  long long length = 0;
  if (hr_cgi_param_i64_opt(phr, "length", &length, -1LL) < 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
    goto cleanup;
  }

  UserProblemInfo *pinfo = NULL;
  XALLOCAZ(pinfo, cs->max_prob + 1);
  for (int i = 0; i <= cs->max_prob; ++i) {
    pinfo[i].best_run = -1;
  }
  ns_get_user_problems_summary(cs, phr->user_id, phr->login, accepting_mode, start_time, stop_time, &phr->ip, pinfo);

  RunDisplayInfo ri = {};
  fill_user_run_info(cs, pinfo, run_id, &re, start_time, stop_time, 0, &ri);

  if (!ri.is_report_enabled) {
    error_page(fout, phr, 0, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  unsigned char rep_path[PATH_MAX];
  int flags = serve_make_xml_report_read_path(cs, rep_path, sizeof(rep_path), &re);
  if (flags < 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_REPORT_NONEXISTANT);
    goto cleanup;
  }
  if (re.store_flags == STORE_FLAGS_UUID_BSON) {
    if (!(tr = testing_report_parse_bson_file(rep_path))) {
      error_page(fout, phr, 0, NEW_SRV_ERR_REPORT_NONEXISTANT);
      goto cleanup;
    }
  } else {
    if (generic_read_file(&rep_txt, 0, &rep_len, flags, 0, rep_path, 0) < 0) {
      error_page(fout, phr, 0, NEW_SRV_ERR_REPORT_NONEXISTANT);
      goto cleanup;
    }
    const unsigned char *start_ptr = NULL;
    if (get_content_type(rep_txt, &start_ptr) != CONTENT_TYPE_XML) {
      error_page(fout, phr, 0, NEW_SRV_ERR_REPORT_NONEXISTANT);
      goto cleanup;
    }
    if (!(tr = testing_report_parse_xml(start_ptr))) {
      error_page(fout, phr, 0, NEW_SRV_ERR_REPORT_NONEXISTANT);
      goto cleanup;
    }
  }
  if (num <= 0 || num > tr->run_tests) {
    error_page(fout, phr, 0, NEW_SRV_ERR_TEST_NONEXISTANT);
    goto cleanup;
  }
  struct testing_report_test *t = tr->tests[num - 1];
  if (t->num != num) {
    error_page(fout, phr, 0, NEW_SRV_ERR_TEST_NONEXISTANT);
    goto cleanup;
  }
  int token_flags = re.token_flags;
  int visibility = cntsprob_get_test_visibility(prob, num, cs->online_final_visibility, token_flags);
  if (visibility == TV_FULLIFMARKED) {
    visibility = TV_HIDDEN;
    if (re.is_marked) visibility = TV_FULL;
  }
  if (visibility != TV_FULL) {
    error_page(fout, phr, 0, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  const unsigned char *data = NULL;
  long long size = -1;

  switch (index) {
  case TESTING_REPORT_INPUT:
    if (t->input.size >= 0 && t->input.data && !t->input.is_too_big) {
      data = t->input.data;
      size = t->input.size;
    }
    break;
  case TESTING_REPORT_OUTPUT:
    if (t->output.size >= 0 && t->output.data && !t->output.is_too_big) {
      data = t->output.data;
      size = t->output.size;
    }
    break;
  case TESTING_REPORT_CORRECT:
    if (t->correct.size >= 0 && t->correct.data && !t->correct.is_too_big) {
      data = t->correct.data;
      size = t->correct.size;
    }
    break;
  case TESTING_REPORT_ERROR:
    if (t->error.size >= 0 && t->error.data && !t->error.is_too_big) {
      data = t->error.data;
      size = t->error.size;
    }
    break;
  case TESTING_REPORT_CHECKER:
    if (t->checker.size >= 0 && t->checker.data && !t->checker.is_too_big) {
      data = t->checker.data;
      size = t->checker.size;
    }
    break;
  case TESTING_REPORT_ARGS:
    if (t->args && !t->args_too_long) {
      data = t->args;
      size = strlen(t->args);
    }
    break;
  default:
    break;
  }
  if (!data || size < 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  if (offset < 0) offset = 0;
  if (offset > size) offset = size;
  if (length < 0) length = size;
  if (offset + length > size) length = size - offset;

  phr->json_reply = 0;
  snprintf(phr->content_type, sizeof(phr->content_type), "application/octet-stream");

  const unsigned char *outptr = data + offset;
  while (length > 0) {
    int portion = 65536;
    if (length < portion) portion = length;
    while (portion > 0) {
      size_t wz = fwrite(outptr, 1, portion, fout);
      if (ferror(fout)) {
        // FIXME: what to do?
        length = 0;
        break;
      }
      ASSERT(wz <= portion);
      portion -= wz;
      length -= wz;
      outptr += wz;
    }
  }

cleanup:
  html_armor_free(&ab);
  testing_report_free(tr);
  free(rep_txt);
}

static cJSON *
userprob_to_json(const struct userprob_entry *ue)
{
  cJSON *jrr = cJSON_CreateObject();
  cJSON_AddNumberToObject(jrr, "serial_id", ue->serial_id);
  cJSON_AddNumberToObject(jrr, "create_time_ms", ue->create_time_us / 1000);
  cJSON_AddNumberToObject(jrr, "last_change_time_ms", ue->last_change_time_us / 1000);
  cJSON_AddNumberToObject(jrr, "contest_id", ue->contest_id);
  cJSON_AddNumberToObject(jrr, "user_id", ue->user_id);
  cJSON_AddNumberToObject(jrr, "prob_id", ue->prob_id);
  if (ue->lang_name && *ue->lang_name) {
    cJSON_AddStringToObject(jrr, "lang_name", ue->lang_name);
  }
  if (ue->hook_id && *ue->hook_id) {
    cJSON_AddStringToObject(jrr, "hook_id", ue->hook_id);
  }
  if (ue->gitlab_token && *ue->gitlab_token) {
    cJSON_AddStringToObject(jrr, "gitlab_token", ue->gitlab_token);
  }
  if (ue->vcs_type && *ue->vcs_type) {
    cJSON_AddStringToObject(jrr, "vcs_type", ue->vcs_type);
  }
  if (ue->vcs_url && *ue->vcs_url) {
    cJSON_AddStringToObject(jrr, "vcs_url", ue->vcs_url);
  }
  if (ue->vcs_subdir && *ue->vcs_subdir) {
    cJSON_AddStringToObject(jrr, "vcs_subdir", ue->vcs_subdir);
  }
  if (ue->vcs_branch_spec && *ue->vcs_branch_spec) {
    cJSON_AddStringToObject(jrr, "vcs_branch_spec", ue->vcs_branch_spec);
  }
  if (ue->ssh_private_key && *ue->ssh_private_key) {
    cJSON_AddStringToObject(jrr, "ssh_private_key", ue->ssh_private_key);
  }
  return jrr;
}

static void
unpriv_get_userprob(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int ok = 0;
  int err_num = 0;
  unsigned char *err_msg = NULL;
  cJSON *jr = cJSON_CreateObject(); // reply object
  unsigned err_id = 0;
  const unsigned char *s = NULL;
  int prob_id;
  const struct section_problem_data *prob = NULL;
  struct userprob_plugin_data *up_plugin = NULL;
  struct userprob_entry *ue = NULL;

  if (hr_cgi_param(phr, "prob_id", &s) <= 0 || !s) {
    err_num = NEW_SRV_ERR_INV_PROB_ID;
    goto done;
  }
  {
    char *eptr = NULL;
    errno = 0;
    long v = strtol(s, &eptr, 10);
    if (errno || *eptr || (unsigned char *) eptr == s || (int) v != v) {
      err_num = NEW_SRV_ERR_INV_PROB_ID;
      goto done;
    }
    prob_id = v;
  }
  if (prob_id <= 0 || prob_id > cs->max_prob || !(prob = cs->probs[prob_id])) {
    err_num = NEW_SRV_ERR_INV_PROB_ID;
    goto done;
  }
  if (prob->enable_vcs <= 0) {
    err_num = NEW_SRV_ERR_INV_PROB_ID;
    goto done;
  }
  up_plugin = userprob_plugin_get(phr->config, NULL, 0);
  if (!up_plugin) {
    err_num = NEW_SRV_ERR_PLUGIN_NOT_AVAIL;
    goto done;
  }
  ue = up_plugin->vt->fetch_by_cup(up_plugin, phr->contest_id, phr->user_id, prob_id);

  if (ue) {
    cJSON *jrr = userprob_to_json(ue);
    cJSON_AddItemToObject(jr, "result", jrr);
  }

  ok = 1;

done:;
  emit_json_result(fout, phr, ok, err_num, err_id, err_msg, jr);

  userprob_entry_free(ue);
  if (jr) cJSON_Delete(jr);
  free(err_msg);
}

static void
unpriv_create_userprob(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int ok = 0;
  int err_num = 0;
  unsigned char *err_msg = NULL;
  cJSON *jr = cJSON_CreateObject(); // reply object
  unsigned err_id = 0;
  const unsigned char *s = NULL;
  int prob_id;
  const struct section_problem_data *prob = NULL;
  struct userprob_plugin_data *up_plugin = NULL;
  struct userprob_entry *ue = NULL;

  if (hr_cgi_param(phr, "prob_id", &s) <= 0 || !s) {
    err_num = NEW_SRV_ERR_INV_PROB_ID;
    goto done;
  }
  {
    char *eptr = NULL;
    errno = 0;
    long v = strtol(s, &eptr, 10);
    if (errno || *eptr || (unsigned char *) eptr == s || (int) v != v) {
      err_num = NEW_SRV_ERR_INV_PROB_ID;
      goto done;
    }
    prob_id = v;
  }
  if (prob_id <= 0 || prob_id > cs->max_prob || !(prob = cs->probs[prob_id])) {
    err_num = NEW_SRV_ERR_INV_PROB_ID;
    goto done;
  }
  if (prob->enable_vcs <= 0) {
    err_num = NEW_SRV_ERR_INV_PROB_ID;
    goto done;
  }
  up_plugin = userprob_plugin_get(phr->config, NULL, 0);
  if (!up_plugin) {
    err_num = NEW_SRV_ERR_PLUGIN_NOT_AVAIL;
    goto done;
  }
  ue = up_plugin->vt->create(up_plugin, phr->contest_id, phr->user_id, prob_id);
  if (!ue) {
    err_num = NEW_SRV_ERR_OPERATION_FAILED;
    goto done;
  }

  cJSON *jrr = userprob_to_json(ue);
  cJSON_AddItemToObject(jr, "result", jrr);
  ok = 1;

done:;
  emit_json_result(fout, phr, ok, err_num, err_id, err_msg, jr);

  userprob_entry_free(ue);
  if (jr) cJSON_Delete(jr);
  free(err_msg);
}

static void
unpriv_save_userprob(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int ok = 0;
  int err_num = 0;
  unsigned char *err_msg = NULL;
  cJSON *jr = cJSON_CreateObject(); // reply object
  unsigned err_id = 0;
  const unsigned char *s = NULL;
  int64_t serial_id = 0;
  struct userprob_plugin_data *up_plugin = NULL;
  struct userprob_entry *ue = NULL;
  const struct section_problem_data *prob = NULL;
  int r;

  if (hr_cgi_param(phr, "serial_id", &s) <= 0 || !s) {
    err_num = NEW_SRV_ERR_INV_USERPROB_ID;
    goto done;
  }
  {
    char *eptr = NULL;
    errno = 0;
    long long v = strtoll(s, &eptr, 10);
    if (errno || *eptr || (unsigned char *) eptr == s || v <= 0) {
      err_num = NEW_SRV_ERR_INV_USERPROB_ID;
      goto done;
    }
    serial_id = v;
  }

  up_plugin = userprob_plugin_get(phr->config, NULL, 0);
  if (!up_plugin) {
    err_num = NEW_SRV_ERR_PLUGIN_NOT_AVAIL;
    goto done;
  }
  ue = up_plugin->vt->fetch_by_serial_id(up_plugin, serial_id);
  if (!ue) {
    err_num = NEW_SRV_ERR_INV_USERPROB_ID;
    goto done;
  }
  if (ue->user_id != phr->user_id || ue->contest_id != cnts->id) {
    err_num = NEW_SRV_ERR_INV_USERPROB_ID;
    goto done;
  }
  if (ue->prob_id <= 0 || ue->prob_id > cs->max_prob || !(prob = cs->probs[ue->prob_id])) {
    err_num = NEW_SRV_ERR_INV_USERPROB_ID;
    goto done;
  }
  if (prob->enable_vcs <= 0) {
    err_num = NEW_SRV_ERR_INV_USERPROB_ID;
    goto done;
  }

  XCALLOC(ue, 1);
  if (hr_cgi_param(phr, "vcs_type", &s) > 0) {
    if (strcmp(s, "github") != 0) {
      s = "gitlab";
    }
  } else {
    s = "gitlab";
  }
  ue->vcs_type = xstrdup(s);
  if ((r = hr_cgi_param(phr, "lang_name", &s)) < 0) {
    err_num = NEW_SRV_ERR_INV_PARAM;
    goto done;
  }
  if (r > 0 && s) {
    if (!*(ue->lang_name = text_input_process_string(s, 0, 0))) {
      free(ue->lang_name); ue->lang_name = NULL;
    }
  }
  if ((r = hr_cgi_param(phr, "vcs_url", &s)) < 0) {
    err_num = NEW_SRV_ERR_INV_PARAM;
    goto done;
  }
  if (r > 0 && s) {
    if (!*(ue->vcs_url = text_input_process_string(s, 0, 0))) {
      free(ue->vcs_url); ue->vcs_url = NULL;
    }
  }
  if ((r = hr_cgi_param(phr, "vcs_subdir", &s)) < 0) {
    err_num = NEW_SRV_ERR_INV_PARAM;
    goto done;
  }
  if (r > 0 && s) {
    if (!*(ue->vcs_subdir = text_input_process_string(s, 0, 0))) {
      free(ue->vcs_subdir); ue->vcs_subdir = NULL;
    }
  }
  if ((r = hr_cgi_param(phr, "vcs_branch_spec", &s)) < 0) {
    err_num = NEW_SRV_ERR_INV_PARAM;
    goto done;
  }
  if (r > 0 && s) {
    if (!*(ue->vcs_branch_spec = text_input_process_string(s, 0, 0))) {
      free(ue->vcs_branch_spec); ue->vcs_branch_spec = NULL;
    }
  }
  if ((r = hr_cgi_param(phr, "ssh_private_key", &s)) < 0) {
    err_num = NEW_SRV_ERR_INV_PARAM;
    goto done;
  }
  if (r > 0 && s) {
    if (!*(ue->ssh_private_key = text_area_process_string(s, 0, 0))) {
      free(ue->ssh_private_key); ue->ssh_private_key = NULL;
    }
  }

  up_plugin->vt->save(up_plugin, serial_id, ue);

  ok = 1;

done:;
  emit_json_result(fout, phr, ok, err_num, err_id, err_msg, jr);

  userprob_entry_free(ue);
  if (jr) cJSON_Delete(jr);
  free(err_msg);
}

static void
unpriv_remove_userprob(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int ok = 0;
  int err_num = 0;
  unsigned char *err_msg = NULL;
  cJSON *jr = cJSON_CreateObject(); // reply object
  unsigned err_id = 0;
  const unsigned char *s = NULL;
  int64_t serial_id = 0;
  struct userprob_plugin_data *up_plugin = NULL;
  struct userprob_entry *ue = NULL;
  const struct section_problem_data *prob = NULL;

  if (hr_cgi_param(phr, "serial_id", &s) <= 0 || !s) {
    err_num = NEW_SRV_ERR_INV_USERPROB_ID;
    goto done;
  }
  {
    char *eptr = NULL;
    errno = 0;
    long long v = strtoll(s, &eptr, 10);
    if (errno || *eptr || (unsigned char *) eptr == s || v <= 0) {
      err_num = NEW_SRV_ERR_INV_USERPROB_ID;
      goto done;
    }
    serial_id = v;
  }

  up_plugin = userprob_plugin_get(phr->config, NULL, 0);
  if (!up_plugin) {
    err_num = NEW_SRV_ERR_PLUGIN_NOT_AVAIL;
    goto done;
  }
  ue = up_plugin->vt->fetch_by_serial_id(up_plugin, serial_id);
  if (!ue) {
    err_num = NEW_SRV_ERR_INV_USERPROB_ID;
    goto done;
  }
  if (ue->user_id != phr->user_id || ue->contest_id != cnts->id) {
    err_num = NEW_SRV_ERR_INV_USERPROB_ID;
    goto done;
  }
  if (ue->prob_id <= 0 || ue->prob_id > cs->max_prob || !(prob = cs->probs[ue->prob_id])) {
    err_num = NEW_SRV_ERR_INV_USERPROB_ID;
    goto done;
  }
  if (prob->enable_vcs <= 0) {
    err_num = NEW_SRV_ERR_INV_USERPROB_ID;
    goto done;
  }

  up_plugin->vt->remove(up_plugin, serial_id);

  ok = 1;

done:;
  emit_json_result(fout, phr, ok, err_num, err_id, err_msg, jr);

  userprob_entry_free(ue);
  if (jr) cJSON_Delete(jr);
  free(err_msg);
}

static action_handler_t user_actions_table[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_CHANGE_LANGUAGE] = unpriv_change_language,
  [NEW_SRV_ACTION_CHANGE_PASSWORD] = unpriv_change_password,
  [NEW_SRV_ACTION_SUBMIT_RUN] = unpriv_submit_run,
  [NEW_SRV_ACTION_SUBMIT_CLAR] = unpriv_submit_clar,
  [NEW_SRV_ACTION_LOGOUT] = unpriv_logout,
  [NEW_SRV_ACTION_DOWNLOAD_RUN] = unpriv_download_run,
  [NEW_SRV_ACTION_PRINT_RUN] = unpriv_print_run,
  [NEW_SRV_ACTION_VIEW_TEST_INPUT] = unpriv_view_test,
  [NEW_SRV_ACTION_VIEW_TEST_ANSWER] = unpriv_view_test,
  [NEW_SRV_ACTION_VIEW_TEST_INFO] = unpriv_view_test,
  [NEW_SRV_ACTION_VIEW_TEST_OUTPUT] = unpriv_view_test,
  [NEW_SRV_ACTION_VIEW_TEST_ERROR] = unpriv_view_test,
  [NEW_SRV_ACTION_VIEW_TEST_CHECKER] = unpriv_view_test,
  [NEW_SRV_ACTION_SUBMIT_APPEAL] = unpriv_submit_appeal,
  [NEW_SRV_ACTION_VIRTUAL_START] = unpriv_command,
  [NEW_SRV_ACTION_VIRTUAL_STOP] = unpriv_command,
  [NEW_SRV_ACTION_VIRTUAL_RESTART] = unpriv_command,
  [NEW_SRV_ACTION_JSON_USER_STATE] = unpriv_json_user_state,
  [NEW_SRV_ACTION_UPDATE_ANSWER] = unpriv_xml_update_answer,
  [NEW_SRV_ACTION_GET_FILE] = unpriv_get_file,
  [NEW_SRV_ACTION_USE_TOKEN] = unpriv_use_token,
  [NEW_SRV_ACTION_GENERATE_TELEGRAM_TOKEN] = unpriv_generate_telegram_token,
  [NEW_SRV_ACTION_CONTEST_STATUS_JSON] = unpriv_contest_status_json,
  [NEW_SRV_ACTION_PROBLEM_STATUS_JSON] = unpriv_problem_status_json,
  [NEW_SRV_ACTION_PROBLEM_STATEMENT_JSON] = unpriv_problem_statement_json,
  [NEW_SRV_ACTION_LIST_RUNS_JSON] = unpriv_list_runs_json,
  [NEW_SRV_ACTION_RUN_STATUS_JSON] = unpriv_run_status_json,
  [NEW_SRV_ACTION_RUN_MESSAGES_JSON] = unpriv_run_messages_json,
  [NEW_SRV_ACTION_RUN_TEST_JSON] = unpriv_run_test_json,
  [NEW_SRV_ACTION_SUBMIT_RUN_INPUT] = unpriv_submit_run_input,
  [NEW_SRV_ACTION_GET_SUBMIT] = unpriv_get_submit,
  [NEW_SRV_ACTION_GET_USERPROB] = unpriv_get_userprob,
  [NEW_SRV_ACTION_CREATE_USERPROB] = unpriv_create_userprob,
  [NEW_SRV_ACTION_SAVE_USERPROB] = unpriv_save_userprob,
  [NEW_SRV_ACTION_REMOVE_USERPROB] = unpriv_remove_userprob,
};

static const unsigned char * const external_unpriv_action_names[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_LOGIN_PAGE] = "unpriv_login_page",
  [NEW_SRV_ACTION_VIEW_CLAR] = "unpriv_clar_page",
  [NEW_SRV_ACTION_STANDINGS] = "unpriv_standings_page",
  [NEW_SRV_ACTION_CONTESTS_PAGE] = "unpriv_contests_page",
  [NEW_SRV_ACTION_VIEW_REPORT] = "unpriv_report_page",
  [NEW_SRV_ACTION_VIEW_SOURCE] = "unpriv_source_page",
  [NEW_SRV_ACTION_MAIN_PAGE] = "unpriv_main_page",
  [NEW_SRV_ACTION_FORGOT_PASSWORD_1] = "unpriv_recover_1_page",
  [NEW_SRV_ACTION_FORGOT_PASSWORD_2] = "unpriv_recover_2_page",
  [NEW_SRV_ACTION_FORGOT_PASSWORD_3] = "unpriv_recover_3_page",
  [NEW_SRV_ACTION_API_KEYS_PAGE] = "unpriv_api_keys_page",
  [NEW_SRV_ACTION_CREATE_API_KEY] = "unpriv_create_api_key",
  [NEW_SRV_ACTION_DELETE_API_KEY] = "unpriv_delete_api_key",
  [NEW_SRV_ACTION_OAUTH_LOGIN_1] = "unpriv_oauth_login_1",
  [NEW_SRV_ACTION_OAUTH_LOGIN_2] = "unpriv_oauth_login_2",
  [NEW_SRV_ACTION_OAUTH_LOGIN_3] = "unpriv_oauth_login_3",
};

static int external_unpriv_action_aliases[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_VIEW_STARTSTOP] = NEW_SRV_ACTION_MAIN_PAGE,
  [NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY] = NEW_SRV_ACTION_MAIN_PAGE,
  [NEW_SRV_ACTION_VIEW_PROBLEM_STATEMENTS] = NEW_SRV_ACTION_MAIN_PAGE,
  [NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT] = NEW_SRV_ACTION_MAIN_PAGE,
  [NEW_SRV_ACTION_VIEW_SUBMISSIONS] = NEW_SRV_ACTION_MAIN_PAGE,
  [NEW_SRV_ACTION_VIEW_CLAR_SUBMIT] = NEW_SRV_ACTION_MAIN_PAGE,
  [NEW_SRV_ACTION_VIEW_CLARS] = NEW_SRV_ACTION_MAIN_PAGE,
  [NEW_SRV_ACTION_VIEW_SETTINGS] = NEW_SRV_ACTION_MAIN_PAGE,
};

static int
unpriv_external_action(FILE *out_f, struct http_request_info *phr)
{
  int action = phr->action;
  if (external_unpriv_action_aliases[action] > 0) action = external_unpriv_action_aliases[action];

  ContestExternalActions *cnts_actions = NULL;
  if (phr->extra) cnts_actions = phr->extra->cnts_actions;

  ExternalActionState *action_state = NULL;
  if (external_unpriv_action_names[action]) {
    if (cnts_actions && cnts_actions->unpriv_actions && action >= 0 && action < cnts_actions->actions_size) {
      ExternalActionState *st = cnts_actions->unpriv_actions[action];
      const unsigned char *root_dir = NULL;
      if (phr->cnts) root_dir = phr->cnts->root_dir;
      if (st != EXTERNAL_ACTION_NONE) {
        st = external_action_load(st,
                                  "csp/contests",
                                  external_unpriv_action_names[action],
                                  "csp_get_",
                                  root_dir,
                                  phr->current_time,
                                  phr->contest_id,
                                  1 /* allow_fail */);
        if (!st) {
          cnts_actions->unpriv_actions[action] = EXTERNAL_ACTION_NONE;
        } else {
          cnts_actions->unpriv_actions[action] = st;
          action_state = st;
        }
      }
    }
    if (!action_state) {
      external_unpriv_action_states[action] = external_action_load(external_unpriv_action_states[action],
                                                                   "csp/contests",
                                                                   external_unpriv_action_names[action],
                                                                   "csp_get_",
                                                                   NULL /* fixed_src_dir */,
                                                                   phr->current_time,
                                                                   0 /* contest_id */,
                                                                   0 /* allow_fail */);
      action_state = external_unpriv_action_states[action];
    }
  }

  if (action_state && action_state->action_handler) {
    PageInterface *pg = ((external_action_handler_t) action_state->action_handler)();

    if (pg->ops->execute) {
      int r = pg->ops->execute(pg, phr->log_f, phr);
      if (r < 0) {
        error_page(out_f, phr, 0, -r);
        goto cleanup;
      }
    }

    if (pg->ops->render) {
      snprintf(phr->content_type, sizeof(phr->content_type), "text/html; charset=%s", EJUDGE_CHARSET);
      int r = pg->ops->render(pg, phr->log_f, out_f, phr);
      if (r < 0) {
        error_page(out_f, phr, 0, -r);
        goto cleanup;
      }
    }

    if (pg->ops->destroy) {
      pg->ops->destroy(pg);
      pg = NULL;
    }

    goto cleanup;
  }

  return 0;

cleanup:
  return 1;
}

extern const unsigned char login_accept_chars[257];
static int
check_login(const unsigned char *login_str)
{
  if (!login_str || !*login_str) return -1;
  return check_str(login_str, login_accept_chars);
}

struct UnprivLoginJsonResponse
{
  unsigned error_id;
  unsigned char log_msg[256];
  time_t expire;
};

static int
do_unpriv_login_json(FILE *fout, struct http_request_info *phr, struct UnprivLoginJsonResponse *resp)
{
  const struct contest_desc *cnts = NULL;
  struct contest_extra *extra = NULL;
  const struct client_auth *auth = NULL;

  if (phr->contest_id <= 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts){
    snprintf(resp->log_msg, sizeof(resp->log_msg), "invalid contest_id %d", phr->contest_id);
    return -NEW_SRV_ERR_INV_CONTEST_ID;
  }
  extra = ns_get_contest_extra(cnts, phr->config);
  ASSERT(extra);
  phr->cnts = cnts;
  phr->extra = extra;
  if (!contests_check_team_ip(phr->contest_id, &phr->ip, phr->ssl_flag)) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "%s://%s is banned for USER for contest %d",
             ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ipv6(&phr->ip), phr->contest_id);
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  if (cnts->closed) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "contest %d is closed\n", cnts->id);
    return -NEW_SRV_ERR_SERVICE_NOT_AVAILABLE;
  }
  if (!cnts->managed) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "contest %d is not managed", cnts->id);
    return -NEW_SRV_ERR_SERVICE_NOT_AVAILABLE;
  }
  const unsigned char *login = NULL;
  if (hr_cgi_param(phr, "login", &login) <= 0) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "login is not specified");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  if (!login || !*login) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "login is empty");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  if (check_login(login) < 0) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "login is invalid");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }

  const unsigned char *password = NULL;
  if (hr_cgi_param(phr, "password", &password) <= 0) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "password is not specified");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  if (!password || !*password) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "password is empty");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }

  if (phr->client_state->ops->get_client_auth) {
    auth = phr->client_state->ops->get_client_auth(phr->client_state);
  }
  if (auth && auth->user_id > 0) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "already authentificated");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
  }

  ej_cookie_t in_cookie = 0;
  ej_cookie_t in_client_key = 0;
  time_t in_expire = 0;
  int is_ws = 0;
  if (auth) {
    in_cookie = auth->session_id;
    in_client_key = auth->client_key;
    in_expire = auth->expire_time;
    is_ws = 1;
  }

  int r = userlist_clnt_login(ul_conn, ULS_TEAM_CHECK_USER,
                              &phr->ip,
                              in_cookie,
                              in_client_key,
                              in_expire,
                              phr->ssl_flag,
                              phr->contest_id,
                              phr->locale_id,
                              0, /* pwd_special */
                              is_ws,
                              0, /* is_job */
                              login, password,
                              &phr->user_id,
                              &phr->session_id, &phr->client_key,
                              &phr->name,
                              &resp->expire,
                              &phr->priv_level,
                              &phr->reg_status,
                              &phr->reg_flags);
  if (r < 0) {
    r = -r;
    switch (r) {
    case ULS_ERR_INVALID_LOGIN:
    case ULS_ERR_INVALID_PASSWORD:
    case ULS_ERR_BAD_CONTEST_ID:
    case ULS_ERR_IP_NOT_ALLOWED:
    case ULS_ERR_NO_PERMS:
    case ULS_ERR_NOT_REGISTERED:
    case ULS_ERR_CANNOT_PARTICIPATE:
      snprintf(resp->log_msg, sizeof(resp->log_msg), "TEAM_CHECK_USER failed: %s", userlist_strerror(r));
      return -NEW_SRV_ERR_PERMISSION_DENIED;
    case ULS_ERR_DISCONNECT:
      return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
    case ULS_ERR_INCOMPLETE_REG:
      return -NEW_SRV_ERR_REGISTRATION_INCOMPLETE;
    default:
      snprintf(resp->log_msg, sizeof(resp->log_msg), "TEAM_CHECK_USER failed: %s", userlist_strerror(r));
      return -NEW_SRV_ERR_INTERNAL;
    }
  }
  phr->login = xstrdup(login);
  return 0;
}

static void
json_error(
        FILE *fout,
        struct http_request_info *phr,
        struct html_armor_buffer *pab,
        int num,
        const unsigned char *log_msg)
{
  if (num < 0) num = -num;
  random_init();
  unsigned error_id = random_u32();

  fprintf(fout, ",\n  \"error\": {\n");
  fprintf(fout, "    \"num\": %d", num);
  fprintf(fout, ",\n    \"symbol\": \"%s\"", ns_error_symbol(num));
  const unsigned char *msg = ns_error_title_2(num);
  if (msg) {
    fprintf(fout, ",\n    \"message\": \"%s\"", json_armor_buf(pab, msg));
  }
  if (error_id) {
    fprintf(fout, ",\n    \"log_id\": \"%08x\"", error_id);
  }
  fprintf(fout, "\n  }");
  if (!msg) msg = "unknown error";
  err("%d: %s: error_id = %08x: %s", phr->id, msg, error_id, log_msg);
}

static void
unpriv_login_json(FILE *fout, struct http_request_info *phr)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct UnprivLoginJsonResponse resp = {};

  int res = do_unpriv_login_json(fout, phr, &resp);

  phr->json_reply = 1;
  fprintf(fout, "{\n");
  fprintf(fout, "  \"ok\": %s", (res?"false":"true"));
  fprintf(fout, ",\n  \"server_time\": %lld", (long long) phr->current_time);
  if (phr->request_id > 0) {
    fprintf(fout, ",\n  \"request_id\": %d", phr->request_id);
  }
  if (phr->action > 0 && phr->action < NEW_SRV_ACTION_LAST && ns_symbolic_action_table[phr->action]) {
    fprintf(fout, ",\n  \"action\": \"%s\"", ns_symbolic_action_table[phr->action]);
  }
  if (phr->client_state->ops->get_reply_id) {
    int reply_id = phr->client_state->ops->get_reply_id(phr->client_state);
    fprintf(fout, ",\n  \"reply_id\": %d", reply_id);
  }
  if (res) {
    json_error(fout, phr, &ab, res, resp.log_msg);
  } else {
    if (phr->client_state->ops->set_client_auth) {
      struct client_auth *auth = xcalloc(1, sizeof(*auth));
      auth->user_id = phr->user_id;
      auth->contest_id = phr->contest_id;
      auth->locale_id = phr->locale_id;
      auth->session_id = phr->session_id;
      auth->role = USER_ROLE_CONTESTANT;
      auth->client_key = phr->client_key;
      auth->create_time = phr->current_time;
      auth->expire_time = resp.expire;
      auth->login = xstrdup(phr->login);
      auth->name = xstrdup(phr->name);
      auth->priv_level = phr->priv_level;
      auth->reg_status = phr->reg_status;
      auth->reg_flags = phr->reg_flags;
      phr->client_state->ops->set_client_auth(phr->client_state, auth);
    }
    fprintf(fout, ",\n  \"result\": {");
    fprintf(fout, "\n    \"user_id\": %d", phr->user_id);
    fprintf(fout, ",\n    \"user_login\": \"%s\"", json_armor_buf(&ab, phr->login));
    if (phr->name && *phr->name) {
      fprintf(fout, ",\n    \"user_name\": \"%s\"", json_armor_buf(&ab, phr->name));
    }
    fprintf(fout, ",\n    \"session\": \"%016llx-%016llx\"", phr->session_id, phr->client_key);
    fprintf(fout, ",\n    \"SID\": \"%016llx\"", phr->session_id);
    fprintf(fout, ",\n    \"EJSID\": \"%016llx\"", phr->client_key);
    fprintf(fout, ",\n    \"contest_id\": %d", phr->contest_id);
    if (resp.expire > 0) {
      fprintf(fout, ",\n    \"expire\": %lld", (long long) resp.expire);
    }
    fprintf(fout, "\n  }");
  }
  fprintf(fout, "\n}\n");
  html_armor_free(&ab);
}

static void
unpriv_contest_info_json(FILE *fout, struct http_request_info *phr)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int res = 0;
  unsigned char log_msg[256];
  const struct contest_desc *cnts = NULL;
  struct contest_extra *extra = NULL;

  do {
    if (phr->contest_id <= 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts){
      snprintf(log_msg, sizeof(log_msg), "invalid contest_id %d", phr->contest_id);
      res = -NEW_SRV_ERR_INV_CONTEST_ID;
      break;
    }
    extra = ns_get_contest_extra(cnts, phr->config);
    phr->cnts = cnts;
    phr->extra = extra;
    if (!contests_check_team_ip(phr->contest_id, &phr->ip, phr->ssl_flag)) {
      snprintf(log_msg, sizeof(log_msg), "%s://%s is banned for USER for contest %d",
               ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ipv6(&phr->ip), phr->contest_id);
      res = -NEW_SRV_ERR_PERMISSION_DENIED;
      break;
    }
    if (cnts->closed) {
      snprintf(log_msg, sizeof(log_msg), "contest %d is closed\n", cnts->id);
      res = -NEW_SRV_ERR_SERVICE_NOT_AVAILABLE;
      break;
    }
    if (!cnts->managed) {
      snprintf(log_msg, sizeof(log_msg), "contest %d is not managed", cnts->id);
      res = -NEW_SRV_ERR_SERVICE_NOT_AVAILABLE;
      break;
    }
  } while (0);

  phr->json_reply = 1;
  fprintf(fout, "{\n");
  fprintf(fout, "  \"ok\": %s", (res?"false":"true"));
  fprintf(fout, ",\n  \"server_time\": %lld", (long long) phr->current_time);
  if (phr->request_id > 0) {
    fprintf(fout, ",\n  \"request_id\": %d", phr->request_id);
  }
  if (phr->action > 0 && phr->action < NEW_SRV_ACTION_LAST && ns_symbolic_action_table[phr->action]) {
    fprintf(fout, ",\n  \"action\": \"%s\"", ns_symbolic_action_table[phr->action]);
  }
  if (phr->client_state->ops->get_reply_id) {
    int reply_id = phr->client_state->ops->get_reply_id(phr->client_state);
    fprintf(fout, ",\n  \"reply_id\": %d", reply_id);
  }
  if (res) {
    json_error(fout, phr, &ab, res, log_msg);
  } else {
    fprintf(fout, ",\n  \"result\": {");
    fprintf(fout, "\n    \"contest_id\": %d", cnts->id);
    if (cnts->name) {
      fprintf(fout, ",\n    \"contest_name\": \"%s\"", json_armor_buf(&ab, cnts->name));
    }
    fprintf(fout, "\n  }");
  }
  fprintf(fout, "\n}\n");
  html_armor_free(&ab);
}

int
ns_ws_check_session(
        struct server_framework_state *state,
        struct ws_client_state *p,
        unsigned long long sid_1,
        unsigned long long sid_2)
{
  if (ns_open_ul_connection(state) < 0) {
    return -1;
  }

  int s_user_id = 0;
  int s_contest_id = 0;
  int s_locale_id = 0;
  int s_priv_level = 0;
  int s_role = 0;
  int s_team_login = 0;
  int s_reg_status = 0;
  int s_reg_flags = 0;
  int s_passwd_method = 0;
  int s_is_ws = 0;
  time_t s_expire = 0;
  unsigned char *s_login = NULL;
  unsigned char *s_name = NULL;
  ej_ip_t ip = {};

  //fprintf(stderr, "check session: %016llx%016llx\n", sid_1, sid_2);

  if (xml_parse_ipv6(NULL, 0, 0, 0, p->remote_addr, &ip) < 0) {
    err("ns_ws_check_session: cannot parse REMOTE_ADDR");
    return -1;
  }

  int r = userlist_clnt_get_cookie(
    ul_conn,
    ULS_FETCH_COOKIE,
    &ip,
    p->ssl_flag,
    sid_1,
    sid_2,
    &s_user_id,
    &s_contest_id,
    &s_locale_id,
    &s_priv_level,
    &s_role,
    &s_team_login,
    &s_reg_status,
    &s_reg_flags,
    &s_passwd_method,
    &s_is_ws,
    NULL, /* p_is_job */
    &s_expire,
    &s_login,
    &s_name);
  if (r < 0) {
    xfree(s_login);
    xfree(s_name);
    return r;
  }

  if (!s_is_ws) {
    xfree(s_login);
    xfree(s_name);
    return r;
  }

  ASSERT(!p->auth);

  struct client_auth *auth = NULL;
  XCALLOC(auth, 1);
  p->auth = auth;

  auth->login = s_login; s_login = NULL;
  auth->name = s_name; s_name = NULL;
  auth->session_id = sid_1;
  auth->client_key = sid_2;
  auth->expire_time = s_expire;
  auth->contest_id = s_contest_id;
  auth->locale_id = s_locale_id;
  auth->priv_level = s_priv_level;
  auth->locale_id = s_locale_id;
  auth->priv_level = s_priv_level;
  auth->role = s_role;
  auth->user_id = s_user_id;
  auth->reg_status = s_reg_status;
  auth->reg_flags = s_reg_flags;

  return 0;
}

int
ns_ws_create_session(
        struct server_framework_state *state,
        struct ws_client_state *p)
{
  // as we are not yet authentificated, we cannot create a regular session :(
  random_init();

  XCALLOC(p->auth, 1);
  p->auth->session_id = random_u64();
  p->auth->client_key = random_u64();
  p->auth->create_time = time(NULL);
  p->auth->expire_time = p->auth->create_time + 24 * 60 * 60;

  //fprintf(stderr, "session created: %016llx%016llx\n", p->auth->session_id, p->auth->client_key);

  return 0;
}

static void
unpriv_session_info_json(FILE *fout, struct http_request_info *phr)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const struct client_auth *auth = NULL;
  unsigned char log_msg[256];
  int res = 0;

  if (phr && phr->client_state && phr->client_state->ops && phr->client_state->ops->get_client_auth) {
    auth = phr->client_state->ops->get_client_auth(phr->client_state);
  }
  if (!auth) {
    snprintf(log_msg, sizeof(log_msg), "connection has no session");
    res = -NEW_SRV_ERR_PERMISSION_DENIED;
  }

  phr->json_reply = 1;
  fprintf(fout, "{\n");
  fprintf(fout, "  \"ok\": %s", (res?"false":"true"));
  fprintf(fout, ",\n  \"server_time\": %lld", (long long) phr->current_time);
  if (phr->request_id > 0) {
    fprintf(fout, ",\n  \"request_id\": %d", phr->request_id);
  }
  if (phr->action > 0 && phr->action < NEW_SRV_ACTION_LAST && ns_symbolic_action_table[phr->action]) {
    fprintf(fout, ",\n  \"action\": \"%s\"", ns_symbolic_action_table[phr->action]);
  }
  if (phr->client_state->ops->get_reply_id) {
    int reply_id = phr->client_state->ops->get_reply_id(phr->client_state);
    fprintf(fout, ",\n  \"reply_id\": %d", reply_id);
  }
  if (res) {
    json_error(fout, phr, &ab, res, log_msg);
  } else {
    fprintf(fout, ",\n  \"result\": {");
    const unsigned char *sep = "";
    if (auth->user_id > 0) {
      fprintf(fout, "%s\n    \"user_id\": %d", sep, auth->user_id); sep = ",";
    }
    if (auth->login && *auth->login) {
      fprintf(fout, "%s\n    \"user_login\": \"%s\"", sep, json_armor_buf(&ab, auth->login)); sep = ",";
    }
    if (auth->name && *auth->name) {
      fprintf(fout, "%s\n    \"user_name\": \"%s\"", sep, json_armor_buf(&ab, auth->name)); sep = ",";
    }
    if (auth->session_id || auth->client_key) {
      fprintf(fout, "%s\n    \"session\": \"%016llx-%016llx\"", sep, auth->session_id, auth->client_key); sep = ",";
      fprintf(fout, "%s\n    \"SID\": \"%016llx\"", sep, auth->session_id);
      fprintf(fout, "%s\n    \"EJSID\": \"%016llx\"", sep, auth->client_key);
    }
    if (auth->contest_id > 0) {
      fprintf(fout, "%s\n    \"contest_id\": %d", sep, auth->contest_id); sep = ",";
    }
    if (auth->expire_time > 0) {
      fprintf(fout, "%s\n    \"expire\": %lld", sep, (long long) auth->expire_time);
    }
    fprintf(fout, "\n  }");
  }
  fprintf(fout, "\n}\n");
  html_armor_free(&ab);
}

static void
unpriv_gitlab_webhook(
        FILE *fout,
        struct http_request_info *phr)
{
  cJSON *jr = cJSON_CreateObject();
  unsigned char *jrstr = NULL;
  const unsigned char *s;
  unsigned char hook_id[64];
  struct userprob_plugin_data *up_data = NULL;
  struct userprob_entry *ue = NULL;
  const unsigned char *gitlab_token = NULL;
  const unsigned char *gitlab_event = NULL;
  const unsigned char *gitlab_event_uuid = NULL;
  const unsigned char *gitlab_json = NULL;
  struct serve_state *cs = NULL;
  const struct section_problem_data *prob = NULL;
  const unsigned char *jobs_args[16];
  unsigned char serial_id_buf[32];
  const unsigned char *post_pull_cmd = "";
  struct teamdb_db_callbacks callbacks = {};
  struct userlist_cookie in_c = {};
  struct userlist_cookie out_c = {};
  unsigned char user_session[64];
  int r;

  s = hr_getenv(phr, "REQUEST_METHOD");
  if (!s) {
    err("unpriv_gitlab_webhook: REQUEST_METHOD undefined");
    goto done;
  }
  if (strcmp(s, "POST")) {
    err("unpriv_gitlab_webhook: POST method expected");
    goto done;
  }

  s = hr_getenv(phr, "CONTENT_TYPE");
  if (!s) {
    err("unpriv_gitlab_webhook: CONTENT_TYPE undefined");
    goto done;
  }
  if (strcmp(s, "application/json")) {
    err("unpriv_gitlab_webhook: json request expected");
    goto done;
  }

  if (hr_cgi_param(phr, "JSON", &s) <= 0 && !s) {
    err("unpriv_gitlab_webhook: JSON expected");
    goto done;
  }
  gitlab_json = s;

  if (!phr->session_id || !phr->client_key) {
    err("unpriv_gitlab_webhook: hook_id is invalid");
    goto done;
  }
  snprintf(hook_id, sizeof(hook_id), "%016llx-%016llx", phr->session_id, phr->client_key);

  up_data = userprob_plugin_get(phr->config, NULL, 0);
  if (!up_data) {
    err("unpriv_gitlab_webhook: userprob plugin not available");
    goto done;
  }
  ue = up_data->vt->fetch_by_hook_id(up_data, hook_id);
  if (!ue) {
    err("unpriv_gitlab_webhook: no such hook configured");
    goto done;
  }

  if (ue->vcs_type && !strcmp(ue->vcs_type, "github")) {
    gitlab_event = hr_getenv(phr, "HTTP_X_GITHUB_EVENT");
    if (!gitlab_event || !*gitlab_event) {
      err("unpriv_gitlab_webhook: GITHUB_EVENT is not provided");
      goto done;
    }
    gitlab_event_uuid = hr_getenv(phr, "HTTP_X_GITHUB_DELIVERY");
    if (!gitlab_event_uuid || !*gitlab_event_uuid) {
      err("unpriv_gitlab_webhook: GITHUB_DELIVERY is not provided");
      goto done;
    }
    // FIXME: check secret
    if (!ue->gitlab_token || !*ue->gitlab_token) {
      err("unpriv_gitlab_webhook: empty gitlab token in DB");
      goto done;
    }
    s = hr_getenv(phr, "HTTP_X_HUB_SIGNATURE_256");
    if (!s) {
      err("unpriv_gitlab_webhook: missing github 'X-Hub-Signature-256'");
      goto done;
    }
    s = strstr(s, "sha256=");
    if (!s) {
      err("unpriv_gitlab_webhook: invalid github 'X-Hub-Signature-256'");
      goto done;
    }
    s += 7;
    uint8_t hmac_str[HMAC_SHA256_DIGEST_SIZE * 2 + 1];
    hmac_sha256_str(hmac_str, gitlab_json, strlen(gitlab_json),
                ue->gitlab_token, strlen(ue->gitlab_token));
    if (strcmp(hmac_str, s) != 0) {
      err("unpriv_gitlab_webhook: HMAC mismatch: received: %s, computed: %s", s, hmac_str);
      goto done;
    }
  } else {
    gitlab_token = hr_getenv(phr, "HTTP_X_GITLAB_TOKEN");
    if (!gitlab_token || !*gitlab_token) {
      err("unpriv_gitlab_webhook: GITLAB_TOKEN is not provided");
      goto done;
    }
    gitlab_event = hr_getenv(phr, "HTTP_X_GITLAB_EVENT");
    if (!gitlab_event || !*gitlab_event) {
      err("unpriv_gitlab_webhook: GITLAB_EVENT is not provided");
      goto done;
    }
    gitlab_event_uuid = hr_getenv(phr, "HTTP_X_GITLAB_EVENT_UUID");
    if (!gitlab_event_uuid || !*gitlab_event_uuid) {
      err("unpriv_gitlab_webhook: GITLAB_EVENT_UUID is not provided");
      goto done;
    }

    if (!ue->gitlab_token || !*ue->gitlab_token) {
      err("unpriv_gitlab_webhook: empty gitlab token in DB");
      goto done;
    }
    if (strcmp(gitlab_token, ue->gitlab_token) != 0) {
      err("unpriv_gitlab_webhook: gitlab token mismatch");
      goto done;
    }
  }

  if (ue->contest_id <= 0) {
    err("unpriv_gitlab_webhook: invalid contest_id");
    goto done;
  }
  if (contests_get(ue->contest_id, &phr->cnts) < 0 || !phr->cnts) {
    err("unpriv_gitlab_webhook: invalid contest_id");
    goto done;
  }
  if (phr->cnts->closed) {
    err("unpriv_gitlab_webhook: contest is closed");
    goto done;
  }
  phr->contest_id = ue->contest_id;
  phr->extra = ns_get_contest_extra(phr->cnts, phr->config);

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    err("unpriv_gitlab_webhook: failed to open userlist connection");
    goto done;
  }

  callbacks.user_data = (void*) phr->fw_state;
  callbacks.list_all_users = ns_list_all_users_callback;

  if (serve_state_load_contest(phr->extra, phr->config, phr->contest_id,
                               ul_conn, &callbacks, 0, 0,
                               ns_load_problem_plugin) < 0) {
    err("unpriv_gitlab_webhook: failed to load contest");
    goto done;
  }
  cs = phr->extra->serve_state;
  if (!cs) {
    err("unpriv_gitlab_webhook: invalid contest");
    goto done;
  }
  cs->current_time = time(0);
  ns_check_contest_events(phr->extra, cs, phr->cnts);

  if (teamdb_lookup(cs->teamdb_state, ue->user_id) <= 0) {
    err("unpriv_gitlab_webhook: invalid user_id");
    goto done;
  }

  if (ue->prob_id <= 0 || ue->prob_id > cs->max_prob) {
    err("unpriv_gitlab_webhook: invalid prob_id");
    goto done;
  }
  if (!(prob = cs->probs[ue->prob_id])) {
    err("unpriv_gitlab_webhook: invalid prob_id");
    goto done;
  }
  // FIXME: check limitations for submit
  if (prob->enable_vcs <= 0) {
    err("unpriv_gitlab_webhook: problem does not allow gitlab");
    goto done;
  }
  if (prob->post_pull_cmd) {
    post_pull_cmd = prob->post_pull_cmd;
  }

  in_c.ip = phr->ip;
  in_c.ssl = phr->ssl_flag;
  in_c.user_id = ue->user_id;
  in_c.contest_id = phr->contest_id;
  in_c.locale_id = 0;
  in_c.priv_level = 0;
  in_c.role = USER_ROLE_CONTESTANT;
  in_c.recovery = 0;
  in_c.team_login = 1;
  in_c.is_job = 1;

  random_init();
  in_c.cookie = random_u64();
  in_c.client_key = random_u64();
  r = userlist_clnt_create_cookie(ul_conn, ULS_CREATE_COOKIE, &in_c, &out_c);
  if (r < 0) {
    err("unpriv_gitlab_webhook: cannot create session");
    goto done;
  }
  snprintf(user_session, sizeof(user_session), "%016llx-%016llx",
           out_c.cookie, out_c.client_key);

  jobs_args[0] = "gitlab_webhook";
  jobs_args[1] = gitlab_event;
  jobs_args[2] = gitlab_event_uuid;
  snprintf(serial_id_buf, sizeof(serial_id_buf), "%lld", (long long) ue->serial_id);
  jobs_args[3] = serial_id_buf;
  jobs_args[4] = prob->problem_dir;
  jobs_args[5] = post_pull_cmd;
  jobs_args[6] = user_session;
  jobs_args[7] = phr->self_url;
  jobs_args[8] = gitlab_json;
  jobs_args[9] = NULL;

  send_job_packet(phr->config, (unsigned char**) jobs_args);

done:;
  phr->json_reply = 1;
  cJSON_AddTrueToObject(jr, "ok");
  jrstr = cJSON_PrintUnformatted(jr);
  fprintf(fout, "%s\n", jrstr);

  userprob_entry_free(ue);
  free(jrstr);
  cJSON_Delete(jr);
}

static int
unpriv_check_cached_key(struct http_request_info *phr)
{
  long long tsc_start;
  long long tsc_end;
  unsigned int key_contest_id = phr->contest_id;

  rdtscll(tsc_start);

  time_t current_time = time(NULL);
  struct cached_token_info *cti = tc_find(&main_id_cache.t, phr->token, key_contest_id);
  while (1) {
    if (!cti || !cti->used) break;
    if (cti->cmd != ULS_GET_API_KEY) break;

    /*
    if (ej_ip_cmp(&phr->ip, &cti->origin_ip) != 0) {
      break;
    }
    if (phr->ssl_flag != cti->ssl_flag) {
      break;
    }
    */
    if (cti->expiry_time > 0 && current_time >= cti->expiry_time) {
      break;
    }
    if (current_time >= cti->refresh_time) {
      break;
    }
    if (phr->role > cti->role) {
      break;
    }

    copy_cti_to_phr(phr, cti, current_time);
    rdtscll(tsc_end);
    if (metrics.data) {
      metrics.data->hit_key_tsc += (tsc_end - tsc_start);
      ++metrics.data->hit_key_count;
    }
    return 0;
  }

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    if (cti && cti->used && cti->cmd == ULS_GET_API_KEY
        //&& !ej_ip_cmp(&phr->ip, &cti->origin_ip)
        //&& phr->ssl_flag == cti->ssl_flag
        && (cti->expiry_time <= 0 || current_time < cti->expiry_time)
        && phr->role <= cti->role) {
      copy_cti_to_phr(phr, cti, current_time);
      rdtscll(tsc_end);
      if (metrics.data) {
        metrics.data->hit_key_tsc += (tsc_end - tsc_start);
        ++metrics.data->hit_key_count;
      }
      return 0;
    }
    return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
  }

  struct userlist_api_key in_api_key = {};
  memcpy(in_api_key.token, phr->token, 32);
  in_api_key.contest_id = phr->contest_id;
  struct userlist_contest_info cnts_info = {};
  struct userlist_api_key *out_keys = NULL;
  int out_count = 0;
  int r = userlist_clnt_api_key_request(ul_conn, ULS_GET_API_KEY, 1, &in_api_key, &out_count, &out_keys, &cnts_info);
  if (r == -ULS_ERR_DISCONNECT) {
    if (cti && cti->used && cti->cmd == ULS_GET_API_KEY
        //&& !ej_ip_cmp(&phr->ip, &cti->origin_ip)
        //&& phr->ssl_flag == cti->ssl_flag
        && (cti->expiry_time <= 0 || current_time < cti->expiry_time)
        && phr->role <= cti->role) {
      copy_cti_to_phr(phr, cti, current_time);
      rdtscll(tsc_end);
      if (metrics.data) {
        metrics.data->hit_key_tsc += (tsc_end - tsc_start);
        ++metrics.data->hit_key_count;
      }
      return 0;
    }
    return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
  }

  if (r <= 0) {
    r = -NEW_SRV_ERR_PERMISSION_DENIED;
  } else if (out_count != 1) {
    r = -NEW_SRV_ERR_INTERNAL;
  } else if (cnts_info.user_id == 0 || cnts_info.contest_id == 0) {
    r = -NEW_SRV_ERR_PERMISSION_DENIED;
  } else if (phr->contest_id > 0 && cnts_info.contest_id != phr->contest_id) {
    r = -NEW_SRV_ERR_PERMISSION_DENIED;
  } else if (cnts_info.reg_status != USERLIST_REG_OK) {
    r = -NEW_SRV_ERR_PERMISSION_DENIED;
  } else if ((cnts_info.reg_flags & (USERLIST_UC_BANNED | USERLIST_UC_LOCKED | USERLIST_UC_INCOMPLETE | USERLIST_UC_DISQUALIFIED)) != 0) {
    r = -NEW_SRV_ERR_PERMISSION_DENIED;
  } else if (out_keys[0].expiry_time > 0 && current_time >= out_keys[0].expiry_time) {
    r = -NEW_SRV_ERR_PERMISSION_DENIED;
  }

  if (r < 0) {
    xfree(cnts_info.login);
    xfree(cnts_info.name);
    for (int i = 0; i < out_count; ++i) {
      xfree(out_keys[i].origin);
      xfree(out_keys[i].payload);
    }
    xfree(out_keys);

    if (cti && cti->used) {
      struct cached_token_info del_item;
      if (tc_remove(&main_id_cache.t, phr->token, key_contest_id, &del_item)) {
        xfree(del_item.login);
        xfree(del_item.name);
      }
    }

    return r;
  }

  if (!cti) {
    cti = tc_insert(&main_id_cache.t, phr->token, key_contest_id);
  } else {
    xfree(cti->login);
    xfree(cti->name);
    memset(cti, 0, sizeof(*cti));
    memcpy(cti->token, phr->token, 32);
    cti->key_contest_id = key_contest_id;
    cti->used = 1;
  }

  cti->origin_ip = phr->ip;
  cti->ssl_flag = phr->ssl_flag;
  cti->expiry_time = out_keys[0].expiry_time;
  cti->refresh_time = current_time + 3600;
  cti->login = cnts_info.login; cnts_info.login = NULL;
  cti->name = cnts_info.name; cnts_info.name = NULL;
  cti->cmd = ULS_GET_API_KEY;
  cti->user_id = cnts_info.user_id;
  cti->contest_id = cnts_info.contest_id;
  cti->reg_flags = cnts_info.reg_flags;
  cti->reg_status = cnts_info.reg_status;
  cti->role = out_keys[0].role;
  cti->all_contests = out_keys[0].all_contests;
  xfree(out_keys[0].payload);
  xfree(out_keys[0].origin);
  xfree(out_keys);

  copy_cti_to_phr(phr, cti, current_time);
  rdtscll(tsc_end);
  if (metrics.data) {
    metrics.data->get_key_tsc += (tsc_end - tsc_start);
    ++metrics.data->get_key_count;
  }
  return 0;
}

static int
unpriv_check_cached_session(struct http_request_info *phr)
{
  long long tsc_start;
  long long tsc_end;

  rdtscll(tsc_start);

  time_t current_time = time(NULL);
  struct new_session_info *nsi = nsc_find(&main_id_cache.s, phr->session_id, phr->client_key);
  while (nsi) {
    // check additional parameters
    if (nsi->cmd != ULS_TEAM_GET_COOKIE) {
      break;
    }
    /*
    if (ej_ip_cmp(&phr->ip, &nsi->origin_ip) != 0) {
      break;
    }
    if (phr->ssl_flag != nsi->ssl_flag) {
      break;
    }
    */
    if (current_time >= nsi->expire_time) {
      break;
    }
    if (current_time >= nsi->refresh_time) {
      break;
    }

    // cache hit
    copy_nsi_to_phr(phr, nsi, current_time);
    rdtscll(tsc_end);
    if (metrics.data) {
      metrics.data->hit_cookie_tsc += (tsc_end - tsc_start);
      ++metrics.data->hit_cookie_count;
    }
    return 0;
  }

  // cache entry is stale or nonexistant
  if (ns_open_ul_connection(phr->fw_state) < 0) {
    if (nsi && nsi->cmd == ULS_TEAM_GET_COOKIE
        && current_time < nsi->expire_time
        //&& nsi->ssl_flag == phr->ssl_flag
        //&& !ej_ip_cmp(&phr->ip, &nsi->origin_ip)
        ) {
      // still try to use cached session value
      copy_nsi_to_phr(phr, nsi, current_time);
      rdtscll(tsc_end);
      if (metrics.data) {
        metrics.data->hit_cookie_tsc += (tsc_end - tsc_start);
        ++metrics.data->hit_cookie_count;
      }
      return 0;
    }
    return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
  }

  struct UserlistGetCookieResult result;
  int r = userlist_clnt_get_cookie_2(ul_conn, ULS_TEAM_GET_COOKIE,
        &phr->ip, phr->ssl_flag,
        phr->session_id,
        phr->client_key,
        &result);

  if (r == -ULS_ERR_DISCONNECT) {
    if (nsi && nsi->cmd == ULS_TEAM_GET_COOKIE
        && current_time < nsi->expire_time
        //&& nsi->ssl_flag == phr->ssl_flag
        //&& !ej_ip_cmp(&phr->ip, &nsi->origin_ip)
        ) {
      // still try to use cached session value
      copy_nsi_to_phr(phr, nsi, current_time);
      rdtscll(tsc_end);
      if (metrics.data) {
        metrics.data->hit_cookie_tsc += (tsc_end - tsc_start);
        ++metrics.data->hit_cookie_count;
      }
      return 0;
    }
    return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
  }
  if (r < 0) {
    switch (-r) {
    case ULS_ERR_NO_COOKIE:
    case ULS_ERR_CANNOT_PARTICIPATE:
    case ULS_ERR_NOT_REGISTERED:
      r = -NEW_SRV_ERR_INV_SESSION;
      break;
    case ULS_ERR_INCOMPLETE_REG:
      r = -NEW_SRV_ERR_REGISTRATION_INCOMPLETE;
      break;
    default:
      fprintf(phr->log_f, "get_cookie failed: %s\n", userlist_strerror(-r));
      r = -NEW_SRV_ERR_INTERNAL;
      break;
    }
    if (nsi) {
      ns_invalidate_session(phr->session_id, phr->client_key);
    }
    return r;
  }

  if (!nsi) {
    nsi = nsc_insert(&main_id_cache.s, phr->session_id, phr->client_key);
  } else {
    xfree(nsi->login); nsi->login = NULL;
    xfree(nsi->name); nsi->name = NULL;
    memset(nsi, 0, sizeof(*nsi));
    nsi->session_id = phr->session_id;
    nsi->client_key = phr->client_key;
  }

  nsi->cmd = ULS_TEAM_GET_COOKIE;
  nsi->origin_ip = phr->ip;
  nsi->ssl_flag = phr->ssl_flag;
  nsi->user_id = result.data->user_id;
  nsi->contest_id = result.data->contest_id;
  nsi->locale_id = result.data->locale_id;
  nsi->priv_level = result.data->priv_level;
  nsi->role = result.data->role;
  nsi->team_login = result.data->team_login;
  nsi->reg_status = result.data->reg_status;
  nsi->reg_flags = result.data->reg_flags;
  nsi->is_ws = result.data->is_ws;
  nsi->is_job = result.data->is_job;
  nsi->passwd_method = result.data->passwd_method;
  nsi->expire_time = result.data->expire;
  nsi->refresh_time = current_time + 1200;
  nsi->access_time = current_time;
  nsi->login = xstrdup(result.login);
  nsi->name = xstrdup(result.name);

  xfree(result.data);
  copy_nsi_to_phr(phr, nsi, current_time);
  rdtscll(tsc_end);
  if (metrics.data) {
    metrics.data->get_cookie_tsc += (tsc_end - tsc_start);
    ++metrics.data->get_cookie_count;
  }
  return 0;
}

static void
unprivileged_entry_point(
        FILE *fout,
        struct http_request_info *phr)
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
  const unsigned char *s = 0;

  if (phr->action == NEW_SRV_ACTION_VCS_WEBHOOK) {
    unpriv_gitlab_webhook(fout, phr);
    return;
  }

  if (phr->action == NEW_SRV_ACTION_FORGOT_PASSWORD_1) {
    contests_get(phr->contest_id, &cnts);
    phr->cnts = cnts;
    phr->extra = ns_get_contest_extra(cnts, phr->config);
    unpriv_external_action(fout, phr);
    return;
  }
  if (phr->action == NEW_SRV_ACTION_FORGOT_PASSWORD_2) {
    contests_get(phr->contest_id, &cnts);
    phr->cnts = cnts;
    phr->extra = ns_get_contest_extra(cnts, phr->config);
    unpriv_external_action(fout, phr);
    return;
  }
  if (phr->action == NEW_SRV_ACTION_FORGOT_PASSWORD_3) {
    contests_get(phr->contest_id, &cnts);
    phr->cnts = cnts;
    phr->extra = ns_get_contest_extra(cnts, phr->config);
    unpriv_external_action(fout, phr);
    return;
  }
  if (phr->action == NEW_SRV_ACTION_LOGIN_JSON) {
    return unpriv_login_json(fout, phr);
  }
  if (phr->action == NEW_SRV_ACTION_CONTEST_INFO_JSON) {
    return unpriv_contest_info_json(fout, phr);
  }
  if (phr->action == NEW_SRV_ACTION_SESSION_INFO_JSON) {
    return unpriv_session_info_json(fout, phr);
  }
  if (!phr->token_mode && phr->action == NEW_SRV_ACTION_OAUTH_LOGIN_2) {
    unpriv_external_action(fout, phr);
    return;
  }
  if (!phr->token_mode && phr->action == NEW_SRV_ACTION_OAUTH_LOGIN_3) {
    unpriv_external_action(fout, phr);
    return;
  }

  if (!phr->token_mode && phr->action == NEW_SRV_ACTION_OAUTH_LOGIN_1) {
    phr->extra = ns_get_contest_extra(cnts, phr->config);
    phr->cnts = cnts;
    unpriv_external_action(fout, phr);
    return;
  }

  if (!phr->token_mode && (phr->contest_id < 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts)
      && !phr->session_id && ejudge_config->enable_contest_select){
    phr->action = NEW_SRV_ACTION_CONTESTS_PAGE;
    phr->cnts = cnts;
    phr->extra = ns_get_contest_extra(cnts, phr->config);
    unpriv_external_action(fout, phr);
    return;
  }

  phr->cnts = cnts;

  if (!phr->token_mode && (!phr->session_id || phr->action == NEW_SRV_ACTION_LOGIN_PAGE)) {
    phr->extra = ns_get_contest_extra(phr->cnts, phr->config);
    return unprivileged_page_login(fout, phr);
  }

  const struct client_auth *auth = NULL;
  if (phr->client_state->ops->get_client_auth) {
    auth = phr->client_state->ops->get_client_auth(phr->client_state);
  }
  if (auth) {
    if (auth->session_id != phr->session_id || auth->client_key != phr->client_key || auth->user_id <= 0) {
      error_page(fout, phr, 0, -NEW_SRV_ERR_PERMISSION_DENIED);
      goto cleanup;
    }
    phr->user_id = auth->user_id;
    phr->contest_id = auth->contest_id;
    phr->role = auth->role;
    //phr->passwd_method = 0;
    phr->login = xstrdup(auth->login);
    phr->name = xstrdup(auth->name);
  } else if (phr->token_mode) {
    if (phr->action == NEW_SRV_ACTION_CREATE_API_KEY || phr->action == NEW_SRV_ACTION_API_KEYS_PAGE || phr->action == NEW_SRV_ACTION_DELETE_API_KEY
        || phr->action == NEW_SRV_ACTION_COOKIE_LOGIN || phr->action == NEW_SRV_ACTION_LOGIN || phr->action == NEW_SRV_ACTION_LOGIN_PAGE
        || phr->action == NEW_SRV_ACTION_LOGIN_JSON) {
      error_page(fout, phr, 0, -NEW_SRV_ERR_PERMISSION_DENIED);
      goto cleanup;
    }

    r = unpriv_check_cached_key(phr);
    if (r < 0) {
      error_page(fout, phr, 0, r);
      goto cleanup;
    }
  } else {
    r = unpriv_check_cached_session(phr);
    if (r < 0) {
      error_page(fout, phr, 0, r);
      goto cleanup;
    }
  }

  if (phr->contest_id < 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts){
    fprintf(phr->log_f, "invalid contest_id %d\n", phr->contest_id);
    error_page(fout, phr, 0, -NEW_SRV_ERR_INV_CONTEST_ID);
    goto cleanup;
  }

  if (phr->locale_id < 0 && cnts && cnts->default_locale_num >= 0) {
    phr->locale_id = cnts->default_locale_num;
  }
  if (phr->locale_id < 0) phr->locale_id = 0;

  extra = ns_get_contest_extra(cnts, phr->config);
  ASSERT(extra);
  phr->cnts = cnts;
  phr->extra = extra;

  if (!contests_check_team_ip(phr->contest_id, &phr->ip, phr->ssl_flag)) {
    fprintf(phr->log_f, "%s://%s is not allowed for USER for contest %d\n",
            ns_ssl_flag_str[phr->ssl_flag], xml_unparse_ipv6(&phr->ip), phr->contest_id);
    error_page(fout, phr, 0, -NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }
  if (cnts->closed) {
    fprintf(phr->log_f, "contest %d is closed\n", cnts->id);
    error_page(fout, phr, 0, -NEW_SRV_ERR_SERVICE_NOT_AVAILABLE);
    goto cleanup;
  }
  if (!cnts->managed) {
    fprintf(phr->log_f, "contest %d is not managed", cnts->id);
    error_page(fout, phr, 0, -NEW_SRV_ERR_SERVICE_NOT_AVAILABLE);
    goto cleanup;
  }

  watched_file_update(&extra->copyright, cnts->copyright_file, cur_time);
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

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.user_data = (void*) phr->fw_state;
  callbacks.list_all_users = ns_list_all_users_callback;

  // invoke the contest
  if (serve_state_load_contest(extra, ejudge_config, phr->contest_id,
                               ul_conn,
                               &callbacks,
                               0, 0,
                               ns_load_problem_plugin) < 0) {
    error_page(fout, phr, 0, NEW_SRV_ERR_CNTS_UNAVAILABLE);
    goto cleanup;
  }

  cs = extra->serve_state;
  cs->current_time = time(0);
  ns_check_contest_events(phr->extra, cs, cnts);

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

  // don't count online users as it is quite expensive
  online_users = -1;
  if (0) {
    // count number of users online
    online_users = 0;
    for (i = 0; i < extra->user_access[USER_ROLE_CONTESTANT].u; i++) {
      pp = &extra->user_access[USER_ROLE_CONTESTANT].v[i];
      if (pp->time + 65 >= cs->current_time) online_users++;
    }
    if (online_users > cs->max_online_count) {
      cs->max_online_count = online_users;
      cs->max_online_time = cs->current_time;
      serve_update_status_file(ejudge_config, cnts, cs, 1);
    }
  }
  phr->online_users = online_users;

  if ((teamdb_get_flags(cs->teamdb_state, phr->user_id) & TEAM_DISQUALIFIED))
    return error_page(fout, phr, 0, NEW_SRV_ERR_DISQUALIFIED);

  /* FIXME: redirect just logged in user to an appropriate page */
  if (hr_cgi_param(phr, "lt", &s) > 0) {
    // contest is not started: no nothing
    // contest finished, not olympiad, standings enabled -> standings
  }

  if (cnts->force_password_change > 0 && !cnts->disable_password_change && phr->passwd_method == USERLIST_PWD_PLAIN
      && phr->action != NEW_SRV_ACTION_CHANGE_PASSWORD && phr->action != NEW_SRV_ACTION_JSON_USER_STATE) {
    phr->action = NEW_SRV_ACTION_VIEW_SETTINGS;
  }
  if (phr->action <= 0 || phr->action >= NEW_SRV_ACTION_LAST) {
    phr->action = NEW_SRV_ACTION_MAIN_PAGE;
  }
  if (external_unpriv_action_aliases[phr->action] > 0 || external_unpriv_action_names[phr->action]) {
    if (unpriv_external_action(fout, phr)) goto cleanup;
  }
  /*
  if (!external_unpriv_action_names[phr->action] && !user_actions_table[phr->action]) {
    phr->action = NEW_SRV_ACTION_MAIN_PAGE;
  }
  */

  //if (unpriv_external_action(fout, phr)) goto cleanup;
  if (!user_actions_table[phr->action]) {
    phr->action = NEW_SRV_ACTION_MAIN_PAGE;
    if (unpriv_external_action(fout, phr)) goto cleanup;
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_ACTION);
  }
  user_actions_table[phr->action](fout, phr, cnts, extra);

cleanup:
  if (phr->log_f) close_memstream(phr->log_f);
  phr->log_f = 0;
  xfree(phr->log_t); phr->log_t = NULL; phr->log_z = 0;
}

static const unsigned char * const external_int_action_names[NEW_SRV_INT_LAST] =
{
  [NEW_SRV_INT_STANDINGS] = "int_standings",
  [NEW_SRV_INT_PUBLIC_LOG] = "int_public_log",
};
static ExternalActionState *external_int_action_states[NEW_SRV_INT_LAST];

int
ns_int_external_action(
        struct http_request_info *phr,
        int action)
{
  if (action <= 0 || action >= NEW_SRV_INT_LAST) {
    err("ns_int_external_action: invalid action: %d", action);
    return -1;
  }
  if (!external_int_action_names[action]) {
    err("ns_int_external_action: action %d is undefined", action);
    return -1;
  }

  ContestExternalActions *cnts_actions = NULL;
  if (phr->extra) cnts_actions = phr->extra->cnts_actions;

  ExternalActionState *action_state = NULL;
  if (cnts_actions && cnts_actions->int_actions && action < cnts_actions->ints_size) {
    ExternalActionState *st = cnts_actions->int_actions[action];
    const unsigned char *root_dir = NULL;
    if (phr->cnts) root_dir = phr->cnts->root_dir;
    if (st != EXTERNAL_ACTION_NONE) {
      st = external_action_load(st,
                                "csp/contests",
                                external_int_action_names[action],
                                "csp_get_",
                                root_dir,
                                phr->current_time,
                                phr->contest_id,
                                1 /* allow_fail */);
      if (!st) {
        cnts_actions->int_actions[action] = EXTERNAL_ACTION_NONE;
      } else {
        cnts_actions->int_actions[action] = st;
        action_state = st;
      }
    }
  }

  if (!action_state) {
    external_int_action_states[action] = external_action_load(external_int_action_states[action],
                                                              "csp/contests",
                                                              external_int_action_names[action],
                                                              "csp_get_",
                                                              NULL /* fixed_src_dir */,
                                                              phr->current_time,
                                                              0 /* contest_id */,
                                                              0 /* allow_fail */);
    action_state = external_int_action_states[action];
  }

  if (!action_state) {
    err("ns_int_external_action: failed to load action %d", action);
    return -1;
  }
  if (!action_state->action_handler) {
    err("ns_int_external_action: action %d handler is NULL", action);
    return -1;
  }

  PageInterface *pg = ((external_action_handler_t) action_state->action_handler)();
  if (!pg) {
    err("ns_int_external_action: action %d create error", action);
    return -1;
  }

  if (pg->ops->execute) {
    int r = pg->ops->execute(pg, phr->log_f, phr);
    if (r < 0) {
      if (pg->ops->destroy) pg->ops->destroy(pg);
      return r;
    }
  }

  if (pg->ops->render) {
    int r = pg->ops->render(pg, phr->log_f, phr->out_f, phr);
    if (r < 0) {
      if (pg->ops->destroy) pg->ops->destroy(pg);
      return r;
    }
  }

  if (pg->ops->destroy) pg->ops->destroy(pg);

  return 0;
}

void
ns_write_standings(
        struct http_request_info *phr,
        struct contest_extra *extra,
        const struct contest_desc *cnts,
        FILE *f,
        const unsigned char *stand_dir,
        const unsigned char *file_name,
        const unsigned char *file_name2,
        int users_on_page,
        int page_index,
        int client_flag,
        int only_table_flag,
        int user_id,
        const unsigned char *header_str,
        const unsigned char *footer_str,
        int accepting_mode,
        const unsigned char *user_name,
        int force_fancy_style,
        int charset_id,
        struct user_filter_info *user_filter,
        int user_mode,
        time_t stand_time,
        int compat_mode)
{
  if (phr && !extra) extra = phr->extra;
  if (phr && !cnts) cnts = phr->cnts;

  ASSERT(extra);

  int hr_allocated = 0;

  StandingsExtraInfo extra_info =
  {
    .stand_dir = stand_dir,
    .file_name = file_name,
    .file_name2 = file_name2,
    .users_on_page = users_on_page,
    .page_index = page_index,
    .client_flag = client_flag,
    .only_table_flag = only_table_flag,
    .user_id = user_id,
    .header_str = header_str,
    .footer_str = footer_str,
    .accepting_mode = accepting_mode,
    .user_name = user_name,
    .force_fancy_style = force_fancy_style,
    .charset_id = charset_id,
    .user_filter = user_filter,
    .user_mode = user_mode,
    .stand_time = stand_time
  };
  if (!phr) {
    phr = alloca(sizeof(*phr));
    memset(phr, 0, sizeof(*phr));
    phr->contest_id = cnts->id;
    phr->anonymous_mode = 1;
    phr->current_time = time(0);
    phr->cnts = cnts;
    phr->extra = extra;
    hr_allocated = 1;
  }
  phr->config = ejudge_config;
  phr->extra_info = &extra_info;
  int r = ns_int_external_action(phr, NEW_SRV_INT_STANDINGS);
  if (r < 0) {
    err("ns_write_standings: int_standings action failed");
    return;
  }
  if (hr_allocated) {
    if (phr->log_f) fclose(phr->log_f);
    xfree(phr->log_t);
    if (phr->out_f) fclose(phr->out_f);
    xfree(phr->out_t);
  }
  return;
}

void
ns_write_public_log(
        struct http_request_info *phr,
        struct contest_extra *extra,
        const struct contest_desc *cnts,
        FILE *f,
        char const *header_str,
        char const *footer_str,
        int user_mode)
{
  if (phr && !extra) extra = phr->extra;
  if (phr && !cnts) cnts = phr->cnts;

  ASSERT(extra);

  // temporary
  ASSERT(!phr);

    PublicLogExtraInfo extra_info =
  {
    .header_str = header_str,
    .footer_str = footer_str,
    .user_mode = user_mode
  };
  struct http_request_info hr;

  memset(&hr, 0, sizeof(hr));
  hr.contest_id = cnts->id;
  hr.extra = extra;
  hr.anonymous_mode = 1;
  hr.current_time = time(NULL);
  hr.cnts = cnts;
  hr.config = ejudge_config;
  hr.out_f = f;
  hr.log_f = open_memstream(&hr.log_t, &hr.log_z);
  hr.extra_info = &extra_info;
  ns_int_external_action(&hr, NEW_SRV_INT_PUBLIC_LOG);
  if (hr.log_f) fclose(hr.log_f);
  xfree(hr.log_t);
}

const unsigned char *
ns_get_register_url(
        unsigned char *buf,
        size_t size,
        const struct contest_desc *cnts,
        const struct http_request_info *phr)
{
  if (phr->rest_mode > 0) {
    snprintf(buf, size, "%s/register", phr->context_url);
  } else if (cnts->register_url) {
    snprintf(buf, size, "%s", cnts->register_url);
  } else {
#if defined CGI_PROG_SUFFIX
    snprintf(buf, size, "%s/new-register%s", phr->context_url, CGI_PROG_SUFFIX);
#else
    snprintf(buf, size, "%s/new-register", phr->contest_url);
#endif
  }
  return buf;
}

static void
batch_register(
        FILE *fout,
        struct http_request_info *phr)
{
  // l=login
  // c=contest_id
  // p=password
  // e=email
  // n=name
  const unsigned char *login_str = NULL;
  if (hr_cgi_param(phr, "l", &login_str) <= 0) {
    err("batch_register: login is undefined");
    goto invalid_parameter;
  }

  const unsigned char *password = NULL;
  hr_cgi_param(phr, "p", &password);

  const unsigned char *email = NULL;
  hr_cgi_param(phr, "e", &email);

  const unsigned char *name = NULL;
  hr_cgi_param(phr, "n", &name);
  if (!name) name = login_str;

  int contest_id = 0;
  if (hr_cgi_param_int(phr, "c", &contest_id) < 0) {
    err("batch_register: contest_id is undefined");
    goto invalid_parameter;
  }
  if (contest_id <= 0) {
    err("batch_register: contest_id %d is invalid", contest_id);
    goto invalid_parameter;
  }
  const struct contest_desc *cnts = NULL;
  if (contests_get(contest_id, &cnts) < 0 || !cnts) {
    err("batch_register: contest_id %d is invalid", contest_id);
    goto invalid_parameter;
  }

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    err("batch_register: failed to open userlist connection");
    goto database_error;
  }
  int user_id = 0;
  int r = userlist_clnt_lookup_user(ul_conn, login_str, 0, &user_id, 0);
  if (r < 0 && r != -ULS_ERR_INVALID_LOGIN) {
    err("batch_register: userlist error %d", r);
    goto database_error;
  }
  if (r < 0) {
    // create new user
    struct userlist_pk_create_user_2 up;
    memset(&up, 0, sizeof(up));

    up.never_clean_flag = 1;
    up.simple_registration_flag = 1;
    up.contest_id = contest_id;
    up.cnts_status = USERLIST_REG_OK;
    up.random_password_flag = (password == NULL);

    r = userlist_clnt_create_user_2(ul_conn, ULS_CREATE_USER_2, &up,
                                    login_str, email, password, NULL,
                                    name, &user_id);
    if (r < 0 && r == -ULS_ERR_LOGIN_USED) {
      err("batch_register: user '%s' already exists", login_str);
      goto database_error;
    }
    if (r < 0) {
      err("batch_register: userlist error %d", r);
      goto database_error;
    }
    if (user_id <= 0) {
      err("batch_register: registration returned invalid user_id %d", user_id);
      goto database_error;
    }
  } else {
    if (user_id <= 0) {
      err("batch_register: lookup returned invalid user_id %d", user_id);
      goto database_error;
    }
    r = userlist_clnt_register_contest(ul_conn, ULS_PRIV_REGISTER_CONTEST, user_id, contest_id, 0, 0);
    if (r < 0) {
      err("batch_register: userlist error %d", r);
      goto database_error;
    }
    r = userlist_clnt_change_registration(ul_conn, user_id, contest_id, USERLIST_REG_OK, 0, 0);
    if (r < 0) {
      err("batch_register: userlist error %d", r);
      goto database_error;
    }
  }

  fprintf(fout, "Content-type: text/plain; charset=%s\n\n", EJUDGE_CHARSET);
  fprintf(fout, "ok\n");
  fprintf(fout, "%d\n", user_id);

  // FIXME: mark that the user database is updated

  goto cleanup;

database_error:
  fprintf(fout, "Content-type: text/plain; charset=%s\n\n", EJUDGE_CHARSET);
  fprintf(fout, "fail\n");
  goto cleanup;

invalid_parameter:
  fprintf(fout, "Content-type: text/plain; charset=%s\n\n", EJUDGE_CHARSET);
  fprintf(fout, "invalid\n");
  goto cleanup;

cleanup:
  return;
}

static void
do_load_contest(struct http_request_info *phr, const struct contest_desc *cnts)
{
  struct contest_extra *extra = ns_get_contest_extra(cnts, phr->config);
  if (!extra) return;

  phr->extra = extra;

  if (!extra->priv_header_txt || !extra->priv_footer_txt) {
    extra->priv_header_txt = ns_fancy_priv_header;
    extra->priv_footer_txt = ns_fancy_priv_footer;
    extra->priv_separator_txt = ns_fancy_priv_separator;
  }
  if (!extra->header_txt || !extra->footer_txt || !extra->separator_txt) {
    extra->header_txt = ns_fancy_header;
    extra->footer_txt = ns_fancy_footer;
    extra->separator_txt = ns_fancy_separator;
  }

  if (extra->contest_arm) xfree(extra->contest_arm);
  if (phr->locale_id == 0 && cnts->name_en) {
    extra->contest_arm = html_armor_string_dup(cnts->name_en);
  } else {
    extra->contest_arm = html_armor_string_dup(cnts->name);
  }

  struct teamdb_db_callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.user_data = (void*) phr->fw_state;
  callbacks.list_all_users = ns_list_all_users_callback;

  // invoke the contest
  if (serve_state_load_contest(extra, ejudge_config, phr->contest_id,
                               ul_conn,
                               &callbacks,
                               0, 0,
                               ns_load_problem_plugin) < 0) {
    return;
  }

  extra->serve_state->current_time = time(0);
  ns_check_contest_events(extra, extra->serve_state, cnts);
}

static void
batch_login(
        FILE *fout,
        struct http_request_info *phr)
{
  // l=login
  // c=contest_id
  // p=prob_name
  // x=expire_time
  // s=ssl_flag
  // i=ip
  // o=locale_id

  const unsigned char *login_str = NULL;
  if (hr_cgi_param(phr, "l", &login_str) <= 0) {
    err("batch_login: login is undefined");
    goto invalid_parameter;
  }

  int contest_id = 0;
  if (hr_cgi_param_int(phr, "c", &contest_id) < 0) {
    err("batch_login: contest_id is undefined");
    goto invalid_parameter;
  }
  if (contest_id <= 0) {
    err("batch_login: contest_id %d is invalid", contest_id);
    goto invalid_parameter;
  }
  const struct contest_desc *cnts = NULL;
  if (contests_get(contest_id, &cnts) < 0 || !cnts) {
    err("batch_login: contest_id %d is invalid", contest_id);
    goto invalid_parameter;
  }
  phr->contest_id = contest_id;
  phr->cnts = cnts;

  int locale_id = -1;
  hr_cgi_param_int_opt(phr, "o", &locale_id, -1);
  if (locale_id < 0) locale_id = 0;
  phr->locale_id = locale_id;

  int ssl_flag = -1;
  hr_cgi_param_int_opt(phr, "s", &ssl_flag, -1);
  if (ssl_flag >= 0 && ssl_flag != phr->ssl_flag) {
    err("batch_login: ssl flag mismatch");
    goto invalid_parameter;
  }

  const unsigned char *ip = NULL;
  hr_cgi_param(phr, "i", &ip);
  if (ip) {
    /*
    const unsigned char *this_ip = xml_unparse_ipv6(&phr->ip);
    if (strcmp(ip, this_ip) != 0) {
      err("batch_login: IP mismatch: required: %s, actual: %s", ip, this_ip);
      goto invalid_parameter;
    }
    */
  }

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    err("batch_login: failed to open userlist connection");
    goto database_error;
  }

  // in the final view mode try to select contest_id to which the user is not banned
  int final_view_mode = 0;
  if (hr_cgi_param_int(phr, "z", &final_view_mode) >= 0 && final_view_mode == 1) {
    int check_contests_id[10];
    int check_contests_count = 0;
    if (cnts->comment && cnts->comment[0]) {
      char *p = cnts->comment;
      char *ep = NULL;
      while (*p) {
        errno = 0;
        long v = strtol(p, &ep, 10);
        if (p == ep) break;
        if (errno || (*ep && !isspace(*ep)) || v <= 0 || (int) v != v) {
          err("batch_login: contest %d: contests list '%s' is invalid", contest_id, cnts->comment);
          goto invalid_parameter;
        }
        if (check_contests_count == 10) {
          err("batch_login: contest %d: too many contests", contest_id);
          goto invalid_parameter;
        }
        check_contests_id[check_contests_count++] = (int) v;

        p = ep;
      }
    } else {
      check_contests_id[check_contests_count++] = contest_id;
    }

    int user_id = 0;
    int r = userlist_clnt_lookup_user(ul_conn, login_str, 0, &user_id, 0);
    if (r < 0 && r != -ULS_ERR_INVALID_LOGIN) {
      err("batch_register: userlist error %d", r);
      goto database_error;
    }
    if (r < 0 || user_id <= 0) {
      err("batch_register: user '%s' is not registered", login_str);
      goto invalid_parameter;
    }

    // iterate over the contests and find an appropriate registration
    int best_contest_id = 0;
    for (int i = 0; i < check_contests_count; ++i) {
      int cur_contest_id = check_contests_id[i];
      const struct contest_desc *cur_cnts = NULL;
      if (contests_get(cur_contest_id, &cur_cnts) < 0 || !cur_cnts) {
        err("batch_register: invalid contest %d", cur_contest_id);
        goto invalid_parameter;
      }
      int r = userlist_clnt_login(ul_conn, ULS_TEAM_CHECK_USER,
                                  &phr->ip,
                                  0 /* cookie */,
                                  phr->client_key,
                                  0 /* expire */,
                                  phr->ssl_flag, cur_contest_id,
                                  locale_id,
                                  0x73629ae8, /* pwd_special */
                                  0, /* is_ws */
                                  0, /* is_job */
                                  login_str, "xxx",
                                  &phr->user_id,
                                  &phr->session_id, &phr->client_key,
                                  &phr->name,
                                  NULL /* expire */,
                                  &phr->priv_level,
                                  &phr->reg_status,
                                  &phr->reg_flags);
      if (r >= 0 && !(phr->reg_flags & USERLIST_UC_BANNED) && phr->reg_status == USERLIST_REG_OK) {
        if (cur_contest_id > best_contest_id) {
          best_contest_id = cur_contest_id;
        }
      }
    }
    if (best_contest_id <= 0) {
      err("batch_login: user not registered");
      goto invalid_parameter;
    }
    phr->contest_id = best_contest_id;
    contest_id = best_contest_id;
    contests_get(phr->contest_id, &phr->cnts);
  }

  const unsigned char *prob_name = NULL;
  hr_cgi_param(phr, "p", &prob_name);

  int expire_time = 0;
  hr_cgi_param_int_opt(phr, "x", &expire_time, 0);
  if (expire_time > 0) {
    time_t current_time = time(NULL);
    if (current_time >= expire_time) {
      err("batch_login: operation expired");
      goto invalid_parameter;
    }
  }

  int action = NEW_SRV_ACTION_MAIN_PAGE;
  int r = userlist_clnt_login(ul_conn, ULS_TEAM_CHECK_USER,
                              &phr->ip,
                              0 /* cookie */,
                              phr->client_key,
                              0 /* expire */,
                              phr->ssl_flag, contest_id,
                              locale_id,
                              0x73629ae8, /* pwd_special */
                              0, /* is_ws */
                              0, /* is_job */
                              login_str, "xxx",
                              &phr->user_id,
                              &phr->session_id, &phr->client_key,
                              &phr->name,
                              NULL /* expire */,
                              &phr->priv_level,
                              &phr->reg_status,
                              &phr->reg_flags);
  if (r < 0) {
    err("batch_login: login failed: %d", r);
    goto database_error;
  }

  do_load_contest(phr, cnts);
  if (phr->extra && phr->extra->serve_state && phr->extra->serve_state->global && phr->extra->serve_state->global->start_on_first_login > 0) {
    serve_state_t cs = phr->extra->serve_state;
    const struct section_global_data *global = cs->global;
    if (global->disable_virtual_start > 0 || cs->disable_virtual_start > 0) {
      err("batch_login: virtual start disabled");
      goto database_error;
    }
    if (cnts->open_time > 0 && cs->current_time < cnts->open_time) {
      err("batch_login: contest is not opened yet");
      goto database_error;
    }
    if (cnts->close_time > 0 && cs->current_time >= cnts->close_time) {
      err("batch_login: contest already closed");
      goto database_error;
    }
    time_t start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    if (start_time <= 0) {
      struct timeval precise_time;
      gettimeofday(&precise_time, 0);
      int run_id = run_virtual_start(cs->runlog_state, phr->user_id,
                                     precise_time.tv_sec, &phr->ip, phr->ssl_flag,
                                     precise_time.tv_usec * 1000);
      if (run_id >= 0) {
        if (run_is_virtual_legacy_mode(cs->runlog_state)) {
          serve_move_files_to_insert_run(cs, run_id);
        }
        serve_event_add(cs,
                        precise_time.tv_sec + run_get_duration(cs->runlog_state, phr->user_id),
                        SERVE_EVENT_VIRTUAL_STOP, phr->user_id,
                        virtual_stop_callback);
      }
      if (!prob_name) {
        for (int i = 1; i <= cs->max_prob; ++i) {
          if (cs->probs && cs->probs[i]) {
            prob_name = cs->probs[i]->short_name;
            break;
          }
        }
      }
    }
  }

  unsigned char prob_name_2[1024];
  unsigned char prob_name_3[1024];

  prob_name_3[0] = 0;
  if (prob_name && prob_name[0]) {
    url_armor_string(prob_name_2, sizeof(prob_name_2), prob_name);
    action = NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT;
    snprintf(prob_name_3, sizeof(prob_name_3), "lt=1&prob_name=%s", prob_name_2);
  } else {
    snprintf(prob_name_3, sizeof(prob_name_3), "lt=1");
  }

  ns_refresh_page(fout, phr, action, prob_name_3);
  goto cleanup;

database_error:
  fprintf(fout, "Content-type: text/plain; charset=%s\n\n", EJUDGE_CHARSET);
  fprintf(fout, "PERMISSION DENIED: did you participate in the first day?\n");
  goto cleanup;

invalid_parameter:
  fprintf(fout, "Content-type: text/plain; charset=%s\n\n", EJUDGE_CHARSET);
  fprintf(fout, "invalid\n");
  goto cleanup;

cleanup:
  return;
}

static void
ulltobe(unsigned char *out, unsigned long long value)
{
    out[0] = value >> 56;
    out[1] = value >> 48;
    out[2] = value >> 40;
    out[3] = value >> 32;
    out[4] = value >> 24;
    out[5] = value >> 16;
    out[6] = value >> 8;
    out[7] = value;
}

static void
swb(unsigned char *buf)
{
    unsigned char t;
    t = buf[0]; buf[0] = buf[3]; buf[3] = t;
    t = buf[1]; buf[1] = buf[2]; buf[2] = t;
}

static void
batch_entry_point(
        FILE *fout,
        struct http_request_info *phr)
{
  int keyno = 0;
  const unsigned char *s = NULL;
  unsigned char *in_b64 = NULL;
  FILE *kf = NULL;
  unsigned char *in_cbc = NULL;
  BLOWFISH_CTX *ctx = NULL;

  if (hr_cgi_param_int(phr, "k", &keyno) < 0 || keyno <= 0) {
    err("batch_entry_point: 'k' parameter is unset or invalid");
    goto invalid_parameter;
  }
  if (hr_cgi_param(phr, "s", &s) < 0) {
    err("batch_entry_point: 's' parameter is unset or invalid");
    goto invalid_parameter;
  }
  if (!s) {
    err("batch_entry_point: 's' parameter is unset or invalid");
    goto invalid_parameter;
  }
  int in_len = strlen(s);
  if (in_len <= 0 || in_len > 16384) {
    err("batch_entry_point: 's' parameter is too short or too long");
    goto invalid_parameter;
  }

  in_b64 = xstrdup(s);
  while (in_len > 0 && isspace(in_b64[in_len - 1])) --in_len;
  in_b64[in_len] = 0;
  if (in_len <= 0) {
    err("batch_entry_point: 's' parameter is empty");
    goto invalid_parameter;
  }
  for (int i = 0; i < in_len; ++i) {
    if (in_b64[i] == '.') {
      in_b64[i] = '/';
    } else if (in_b64[i] == '-') {
      in_b64[i] = '=';
    } else if (in_b64[i] == '_') {
      in_b64[i] = '+';
    }
  }

  unsigned long long key = 0, iv = 0;
  unsigned char keyfile[PATH_MAX];
  snprintf(keyfile, sizeof(keyfile), "%s/keys/%d.key", EJUDGE_CONF_DIR, keyno);
  kf = fopen(keyfile, "r");
  if (!kf) {
    err("batch_entry_point: key %d is not available", keyno);
    goto invalid_parameter;
  }
  if (fscanf(kf, "%llx%llx", &key, &iv) != 2) {
    err("batch_entry_point: key %d parse error", keyno);
    goto invalid_parameter;
  }
  fclose(kf); kf = NULL;

  int errflg = 0;
  in_cbc = malloc(in_len);
  memset(in_cbc, 0, in_len);
  int cbc_len = base64_decode(in_b64, in_len, in_cbc, &errflg);
  if (errflg) {
    err("batch_entry_point: invalid base64");
    goto invalid_parameter;
  }
  if ((cbc_len % 8) != 0) {
    err("batch_entry_point: invalid data length %d", cbc_len);
    goto invalid_parameter;
  }
  xfree(in_b64); in_b64 = NULL;

  ctx = calloc(1, sizeof(*ctx));
  unsigned char kb[8];
  ulltobe(kb, key);
  Blowfish_Init(ctx, kb, sizeof(key));

  unsigned char ivb[8];
  ulltobe(ivb, iv);
  swb(ivb);
  swb(ivb + 4);

  for (int i = 0; i < cbc_len; i += 8) {
    unsigned char saved[8];
    swb(in_cbc + i);
    swb(in_cbc + i + 4);

    memcpy(saved, in_cbc + i, 8);

    Blowfish_Decrypt(ctx, (uint32_t *) (in_cbc + i), (uint32_t *) (in_cbc + i + 4));

    in_cbc[i] ^= ivb[0];
    in_cbc[i + 1] ^= ivb[1];
    in_cbc[i + 2] ^= ivb[2];
    in_cbc[i + 3] ^= ivb[3];
    in_cbc[i + 4] ^= ivb[4];
    in_cbc[i + 5] ^= ivb[5];
    in_cbc[i + 6] ^= ivb[6];
    in_cbc[i + 7] ^= ivb[7];

    swb(in_cbc + i);
    swb(in_cbc + i + 4);

    memcpy(ivb, saved, 8);
  }
  xfree(ctx); ctx = NULL;

  // check and count parameters
  int param_num = 0;
  unsigned char *curp = (unsigned char*) in_cbc;
  unsigned char *endp = curp + cbc_len;
  while (1) {
    int curl = strlen(curp);
    if (!curl) break;
    if (curp + curl >= endp) {
      err("batch_entry_point: invalid data block");
      goto invalid_parameter;
    }
    if (!strchr(curp, '=')) {
      err("batch_entry_point: '=' missing");
      goto invalid_parameter;
    }
    ++param_num;
    curp += curl + 1;
  }
  if (param_num > 256) {
    err("batch_entry_point: too many parameters (%d)", param_num);
    goto invalid_parameter;
  }

  phr->param_num = param_num;
  phr->param_names = NULL;
  phr->param_sizes = NULL;
  phr->params = NULL;
  if (param_num > 0) {
    unsigned char **param_names = NULL;
    size_t *param_sizes = NULL;
    unsigned char **params = NULL;
    XALLOCAZ(param_names, param_num);
    XALLOCAZ(param_sizes, param_num);
    XALLOCAZ(params, param_num);

    unsigned char *curp = (unsigned char*) in_cbc;
    int count = 0;
    while (1) {
      int curl = strlen(curp);
      if (!curl) break;

      unsigned char *zp = strchr(curp, '=');
      *zp = 0;
      param_names[count] = curp;
      params[count] = zp + 1;
      param_sizes[count] = strlen(zp + 1);

      ++count;
      curp += curl + 1;
    }

    phr->param_names = (const unsigned char **) param_names;
    phr->param_sizes = param_sizes;
    phr->params = (const unsigned char **) params;
  }

  const unsigned char *action_str = NULL;
  if (hr_cgi_param(phr, "a", &action_str) <= 0) {
    err("batch_entry_point: no action");
    goto invalid_parameter;
  }

  if (!strcmp(action_str, "r")) {
    // register action
    batch_register(fout, phr);
    goto cleanup;
  } else if (!strcmp(action_str, "l")) {
    // login action
    batch_login(fout, phr);
  } else {
    err("batch_entry_point: invalid action '%s'", action_str);
    goto invalid_parameter;
  }

  /*
  //success:
  fprintf(fout, "Content-type: text/plain; charset=%s\n\n", EJUDGE_CHARSET);
  fprintf(fout, "ok\n");
  */

  for (int i = 0; i < phr->param_num; ++i) {
    fprintf(fout, "<%s>=<%s>\n", phr->param_names[i], phr->params[i]);
  }

  goto cleanup;

invalid_parameter:
  fprintf(fout, "Content-type: text/plain; charset=%s\n\n", EJUDGE_CHARSET);
  fprintf(fout, "invalid\n");
  goto cleanup;

cleanup:
  xfree(ctx);
  xfree(in_cbc);
  xfree(in_b64);
  if (kf) fclose(kf);
  return;
}

#include "lib/new_server_at.c"

static void
parse_cookie(struct http_request_info *phr)
{
  if (phr->json_reply) {
    const unsigned char *s = NULL;
    if (hr_cgi_param(phr, "EJSID", &s) > 0 && *s) {
      unsigned long long x;
      char *eptr = NULL;
      errno = 0;
      x = strtoull(s, &eptr, 16);
      if (!errno && !*eptr && (unsigned char *) eptr != s && x) {
        phr->client_key = x;
        return;
      }
    }
  }

  const unsigned char *cookies = hr_getenv(phr, "HTTP_COOKIE");
  if (!cookies) return;
  const unsigned char *s = cookies;
  ej_cookie_t client_key = 0;
  while (1) {
    while (isspace(*s)) ++s;
    if (strncmp(s, "EJSID=", 6) != 0) {
      while (*s && *s != ';') ++s;
      if (!*s) return;
      ++s;
      continue;
    }
    int n = 0;
    if (sscanf(s + 6, "%llx%n", &client_key, &n) == 1) {
      s += 6 + n;
      if (!*s || isspace(*s) || *s == ';') {
        phr->client_key = client_key;
        return;
      }
    }
    phr->client_key = 0;
    return;
  }
}

/* returns -1 - no bearer header, 0 - parsing failed, 1 - parsed ok */
static int
parse_bearer(struct http_request_info *phr, const unsigned char *str)
{
  if (!str) return -1;
  const unsigned char *p = str;

  if ((p[0] != 'b' && p[0] != 'B')
      || (p[1] != 'e' && p[1] != 'E')
      || (p[2] != 'a' && p[2] != 'A')
      || (p[3] != 'r' && p[3] != 'R')
      || (p[4] != 'e' && p[4] != 'E')
      || (p[5] != 'r' && p[5] != 'R')
      || p[6] != ' ') return -1;
  p += 7;

  phr->token_mode = 1;
  phr->json_reply = 1;

  // AQAA - token type 1
  if (p[0] == 'A' && p[1] == 'Q' && p[2] == 'A' && p[3] == 'A') {
    p += 4;
    int token_len = strlen(p);
    if (token_len != 43) return 0;
    char token[32];
    static const char zero_token[32] = {};
    int err_flag = 0;
    base64u_decode(p, 43, token, &err_flag);
    if (err_flag) return 0;
    if (!memcmp(token, zero_token, 32)) return 0;

    // bearer parsed ok
    memcpy(phr->token, token, 32);
    return 1;
  }
  return 0;
}

// forced linking
static void *forced_linking[] =
{
  userlist_clnt_recover_passwd_2,
};

void
ns_handle_http_request(
        struct server_framework_state *state,
        FILE *fout,
        struct http_request_info *phr)
{
  const unsigned char *script_filename = 0;
  path_t last_name;
  const unsigned char *http_host;
  const unsigned char *script_name = NULL;
  const unsigned char *protocol = "http";
  const unsigned char *remote_addr = NULL;
  const unsigned char *http_authorization = NULL;
  const unsigned char *s;
  path_t self_url;
  path_t context_url;
  int r, n;
  unsigned char *rest_action = NULL;

  (void) forced_linking;

  phr->log_f = open_memstream(&phr->log_t, &phr->log_z);

  // make a self-referencing URL
  if (phr->client_state->ops->get_ssl_flag) {
    phr->ssl_flag = phr->client_state->ops->get_ssl_flag(phr->client_state);
    protocol = "ws";
    if (phr->ssl_flag) protocol = "wss";
  } else {
    if (hr_getenv(phr, "SSL_PROTOCOL") || hr_getenv(phr, "HTTPS")) {
      phr->ssl_flag = 1;
      protocol = "https";
    }
  }
  if (phr->client_state->ops->get_host) {
    if (!(http_host = phr->client_state->ops->get_host(phr->client_state))) http_host = "localhost";
  } else {
    if (!(http_host = hr_getenv(phr, "HTTP_HOST"))) http_host = "localhost";
  }

  if (phr->json) {
    cJSON *jj = cJSON_GetObjectItem(phr->json, "SCRIPT_NAME");
    if (jj && jj->type == cJSON_String) {
      script_name = jj->valuestring;
    }
  }
  if (!script_name) {
    if (!(script_name = hr_getenv(phr, "SCRIPT_NAME")))
      script_name = "/cgi-bin/new-client";
  }

#if defined EJUDGE_REST_PREFIX
  int s_offset = 0;
  if (!strncmp(script_name, EJUDGE_REST_PREFIX, EJUDGE_REST_PREFIX_LEN)) {
    // extract second part

    s = script_name + EJUDGE_REST_PREFIX_LEN;
    s_offset = EJUDGE_REST_PREFIX_LEN;

    // EJUDGE_REST_PREFIX "/ej/"
    // skip api/v1/ part
    if (s[0] == 'a' && s[1] =='p' && s[2] == 'i' && s[3] == '/'
        && s[4] == 'v' && s[5] == '1' && s[6] == '/') {
      s += 7;
      s_offset += 7;
      phr->json_reply = 1;
    }

    int args_count = 1;
    while (*s) {
      args_count += (*s++ == '/');
    }
    phr->rest_count = args_count;
    phr->rest_args = alloca(sizeof(phr->rest_args[0]) * (args_count + 1));
    memset(phr->rest_args, 0, sizeof(phr->rest_args[0]) * (args_count + 1));

    {
      s = script_name + s_offset;
      int args_i = 0;
      while (*s) {
        const unsigned char *p = s;
        while (*p && *p != '/') ++p;
        int len = (int) (p - s);
        unsigned char *q = alloca(len + 1);
        phr->rest_args[args_i++] = q;
        memcpy(q, s, len);
        q[len] = 0;
        s = p;
        if (*s == '/') {
          // trim the new script_name
          if (args_i == 1) {
            int len = (int) (s - script_name);
            unsigned char *tmp = alloca(len + 1);
            memcpy(tmp, script_name, len);
            tmp[len] = 0;
            script_name = tmp;
          }
          ++s;
        }
      }
      for (; args_i < phr->rest_count; ++args_i) {
        unsigned char *q = alloca(1);
        q[0] = 0;
        phr->rest_args[args_i] = q;
      }
    }

    /*
    fprintf(stderr, "Rest Args:");
    for (int i = 0; i < phr->rest_count; ++i) {
      fprintf(stderr, " %s", phr->rest_args[i]);
    }
    fprintf(stderr, "\n");
    */

    if (phr->rest_count > 0) {
      n = strlen(phr->rest_args[0]);
      if (n >= (int) sizeof(phr->role_name)) {
        phr->rest_args[0][sizeof(phr->role_name) - 1] = 0;
      }
      strcpy(phr->role_name, phr->rest_args[0]);
    }

    if (phr->rest_count > 1) {
      rest_action = phr->rest_args[1];
    }

    if (phr->rest_count > 2 && phr->rest_args[2][0] == 'S') {
      // SID
      unsigned long long v1 = 0, v2 = 0;
      if (xml_parse_full_cookie(phr->rest_args[2] + 1, &v1, &v2) >= 0) {
        phr->session_id = v1;
        phr->client_key = v2;
      }
    }

    phr->rest_mode = 1;

    /*
    fprintf(stderr, "role_name: %s\n", phr->role_name);
    fprintf(stderr, "rest_action: %s\n", rest_action);
    fprintf(stderr, "script_name: %s\n", script_name);
    */
  }
#endif

  phr->script_name = script_name;
  snprintf(self_url, sizeof(self_url), "%s://%s%s", protocol,
           http_host, script_name);
  phr->self_url = self_url;
  snprintf(context_url, sizeof(context_url), "%s", self_url);
  unsigned char *rs = strrchr(context_url, '/');
  if (rs) *rs = 0;
  phr->context_url = context_url;

  if (phr->json) {
    phr->json_reply = 1;
  } else {
    if (hr_cgi_param(phr, "json", &s) > 0) {
      phr->json_reply = 1;
    }
    if (hr_cgi_param(phr, "plain_text", &s) > 0) {
      phr->plain_text = 1;
    }
  }

  // parse the client IP address
  if (phr->client_state->ops->get_remote_addr) {
    remote_addr = phr->client_state->ops->get_remote_addr(phr->client_state);
  }
  if (!remote_addr) {
    if (!(remote_addr = hr_getenv(phr, "REMOTE_ADDR"))) {
      err("REMOTE_ADDR does not exist");
      fprintf(phr->log_f, "REMOTE_ADDR does not exist");
      return error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
    }
  }
  if (!strcmp(remote_addr, "::1")) remote_addr = "127.0.0.1";
  if (xml_parse_ipv6(NULL, 0, 0, 0, remote_addr, &phr->ip) < 0) {
    err("cannot parse REMOTE_ADDR");
    fprintf(phr->log_f, "cannot parse REMOTE_ADDR");
    return error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
  }

  if (!phr->client_key) {
    parse_cookie(phr);
  }

  http_authorization = hr_getenv(phr, "HTTP_AUTHORIZATION");
  if (http_authorization) {
    int r = parse_bearer(phr, http_authorization);
    if (r == 0) {
      fprintf(phr->log_f, "cannot parse authorization bearer");
      return error_page(fout, phr, 0, NEW_SRV_ERR_PERMISSION_DENIED);
    }
  }

  // parse the contest_id
  if ((r = hr_cgi_param_int_opt(phr, "contest_id", &phr->contest_id, 0)) < 0) {
    err("cannot parse contest_id");
    fprintf(phr->log_f, "cannot parse contest_id");
    return error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
  }
  /*
  if ((r = hr_cgi_param(phr, "contest_id", &s)) < 0) {
    err("cannot parse contest_id");
    if (phr->log_f) {
      fprintf(phr->log_f, "cannot parse contest_id");
    }
    return error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
  }
  if (r > 0) {
    if (sscanf(s, "%d%n", &phr->contest_id, &n) != 1 || s[n] || phr->contest_id <= 0) {
      err("cannot parse contest_id");
      if (phr->log_f) {
        fprintf(phr->log_f, "cannot parse contest_id");
      }
      return error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
    }
  }
  */

  // parse request_id
  if ((r = hr_cgi_param_int_opt(phr, "request_id", &phr->request_id, 0)) < 0) {
    err("cannot parse request_id");
    fprintf(phr->log_f, "cannot parse request_id");
    return error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
  }

  // parse the session_id
  if (!phr->session_id) {
    if ((r = hr_cgi_param(phr, "SID", &s)) < 0) {
      err("cannot parse SID");
      fprintf(phr->log_f, "cannot parse SID");
      return error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
    }
    if (r > 0) {
      if (sscanf(s, "%llx%n", &phr->session_id, &n) != 1 || s[n] || !phr->session_id) {
        err("cannot parse SID");
        fprintf(phr->log_f, "cannot parse SID");
        return error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
      }
    }
  }

  // parse the locale_id
  if ((r = hr_cgi_param(phr, "locale_id", &s)) < 0) {
    err("cannot parse locale_id");
    fprintf(phr->log_f, "cannot parse locale_id");
    return error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
  }
  if (r > 0) {
    if (sscanf(s, "%d%n", &phr->locale_id, &n) != 1 || s[n] || phr->locale_id < 0) {
      err("cannot parse locale_id");
      fprintf(phr->log_f, "cannot parse locale_id");
      return error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
    }
  }

  // parse the action
  if (rest_action && *rest_action) {
    phr->action = ns_match_action(rest_action);
    if (phr->action < 0) {
      err("invalid action");
      fprintf(phr->log_f, "invalid action");
      return error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
    }
  } else if ((s = hr_cgi_nname(phr, "action_", 7))) {
    if (sscanf(s, "action_%d%n", &phr->action, &n) != 1 || s[n] || phr->action <= 0) {
      err("cannot parse action");
      fprintf(phr->log_f, "cannot parse action");
      return error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
    }
  } else if ((r = hr_cgi_param(phr, "action", &s)) < 0) {
    err("cannot parse action");
    fprintf(phr->log_f, "cannot parse action");
    return error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
  } else if (r > 0) {
    if (sscanf(s, "%d%n", &phr->action, &n) != 1 || s[n] || phr->action <= 0) {
      for (r = 0; r < NEW_SRV_ACTION_LAST; ++r)
        if (ns_symbolic_action_table[r]
            && !strcasecmp(ns_symbolic_action_table[r], s))
          break;
      if (r == NEW_SRV_ACTION_LAST) {
        err("cannot parse action");
        fprintf(phr->log_f, "cannot parse action");
        return error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
      }
      phr->action = r;
    }
  }

  if (*phr->role_name) {
    if (phr->action == NEW_SRV_ACTION_CONTEST_BATCH) {
      batch_entry_point(fout, phr);
      return;
    } else if (!strcmp(phr->role_name, "master")) {
      phr->role = USER_ROLE_ADMIN;
      privileged_entry_point(fout, phr);
      return;
    } else if (!strcmp(phr->role_name, "judge")) {
      phr->role = USER_ROLE_JUDGE;
      privileged_entry_point(fout, phr);
      return;
    } else if (!strcmp(phr->role_name, "observer")) {
      phr->role = USER_ROLE_OBSERVER;
      privileged_entry_point(fout, phr);
      return;
    } else if (!strcmp(phr->role_name, "user")) {
      unprivileged_entry_point(fout, phr);
      return;
    } else if (!strcmp(phr->role_name, "register")) {
      ns_register_pages(fout, phr);
      return;
    } else if (!strcmp(phr->role_name, "rest")) {
      phr->protocol_reply = new_server_cmd_handler(fout, phr);
      return;
    }
  }

  // check how we've been called
  if (phr->json) {
    cJSON *jj = cJSON_GetObjectItem(phr->json, "SCRIPT_FILENAME");
    if (jj && jj->type == cJSON_String) {
      script_filename = jj->valuestring;
    }
    if (!script_filename) {
      cJSON *jj = cJSON_GetObjectItem(phr->json, "SCRIPT_NAME");
      if (jj && jj->type == cJSON_String) {
        script_filename = jj->valuestring;
      }
    }
  }
  if (!script_filename) script_filename = hr_getenv(phr, "SCRIPT_FILENAME");
  if (!script_filename && phr->arg_num > 0) script_filename = phr->args[0];
  if (!script_filename) {
    err("cannot get script filename");
    fprintf(phr->log_f, "cannot get script filename");
    error_page(fout, phr, 0, NEW_SRV_ERR_INV_PARAM);
  }

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

  if (phr->action >= 0 && phr->action < NEW_SRV_ACTION_LAST) {
    phr->action_str = ns_symbolic_action_table[phr->action];
  }

  if (phr->action == NEW_SRV_ACTION_CONTEST_BATCH) {
    batch_entry_point(fout, phr);
  } else if (!strcmp(last_name, "priv-client")) {
    strcpy(phr->role_name, "priv");
    privileged_entry_point(fout, phr);
  } else if (!strcmp(last_name, "new-master") || !strcmp(last_name, "master")) {
    phr->role = USER_ROLE_ADMIN;
    strcpy(phr->role_name, "master");
    privileged_entry_point(fout, phr);
  } else if (!strcmp(last_name, "new-judge") || !strcmp(last_name, "judge")) {
    phr->role = USER_ROLE_JUDGE;
    strcpy(phr->role_name, "judge");
    privileged_entry_point(fout, phr);
  } else if (!strcmp(last_name, "new-register") || !strcmp(last_name, "register")) {
    // FIXME: temporary hack
    strcpy(phr->role_name, "register");
    ns_register_pages(fout, phr);
  } else if (!strcmp(last_name, "ejudge-contests-cmd")) {
    strcpy(phr->role_name, "cmd");
    phr->protocol_reply = new_server_cmd_handler(fout, phr);
  } else {
    strcpy(phr->role_name, "user");
    unprivileged_entry_point(fout, phr);
  }
}

struct compile_packet_file
{
  unsigned char *name;
  struct compile_reply_packet *pkt;
  int contest_id;
};

static struct compile_reply_packet *
read_compile_reply_packet_from_file(
        const unsigned char *name,
        const unsigned char *path)
{
  int unlink_on_fail = 1;
  unsigned char *buf = NULL;
  struct compile_reply_packet *comp_pkt = NULL;
  int fd = -1;

  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK, 0);
  if (fd < 0) {
    if (errno != ENOENT) {
      err("%s: failed to open '%s': %s", __FUNCTION__, path, os_ErrorMsg());
    } else {
      unlink_on_fail = 0;
    }
    goto fail;
  }

  struct stat stb;
  if (fstat(fd, &stb)) {
    abort();
  }
  if (!S_ISREG(stb.st_mode)) {
    err("%s: not regular file '%s'", __FUNCTION__, path);
    goto fail;
  }
  if (stb.st_size <= 0) {
    err("%s: empty file '%s'", __FUNCTION__, path);
    goto fail;
  }
  size_t size = stb.st_size;
  if (size > 1024 * 128) {
    err("%s: file '%s' too big: %zu", __FUNCTION__, path, size);
    goto fail;
  }

  buf = xmalloc(size + 1);
  buf[size] = 0;
  unsigned char *p = buf;
  size_t rm = size;
  while (rm > 0) {
    ssize_t rr = read(fd, p, rm);
    if (rr < 0) {
      err("%s: read error on '%s': %s", __FUNCTION__, path, os_ErrorMsg());
      goto fail;
    }
    if (!rr) {
      err("%s: unexpected EOF on '%s'", __FUNCTION__, path);
      goto fail;
    }
    p += rr;
    rm -= rr;
  }
  close(fd); fd = -1;

  if (compile_reply_packet_read(size, buf, &comp_pkt) < 0) {
    err("%s: invalid packet '%s'", __FUNCTION__, path);
    goto fail;
  }

  info("%s: compile packet '%s' read", __FUNCTION__, name);
  free(buf);
  unlink(path);
  return comp_pkt;

fail:;
  if (fd >= 0) close(fd);
  free(buf);
  if (unlink_on_fail) unlink(path);
  return NULL;
}

static int
compile_packet_sort_func(const void *p1, const void *p2)
{
  const struct compile_packet_file *f1 = (const struct compile_packet_file *) p1;
  const struct compile_packet_file *f2 = (const struct compile_packet_file *) p2;
  return f1->contest_id - f2->contest_id;
}

void
ns_compile_dir_ready(
        const struct ejudge_cfg *config,
        struct server_framework_state *state,
        const unsigned char *dir,
        const unsigned char *dir_dir,
        const unsigned char *dir_out,
        const unsigned char *data_dir,
        const unsigned char *data2_dir,
        void *user)
{
  struct compile_packet_file *files = NULL;
  size_t fileu = 0, filea = 0;
  DIR *d = NULL;
  __attribute__((unused)) int ur;

  d = opendir(dir_dir);
  if (!d) {
    err("ns_compile_dir_ready: cannot open '%s': %s", dir_dir, os_ErrorMsg());
    goto done;
  }
  struct dirent *dd;
  while ((dd = readdir(d))) {
    if (strcmp(dd->d_name, ".") && strcmp(dd->d_name, "..")) {
      if (fileu == filea) {
        if (!filea) {
          filea = 16;
        } else {
          filea *= 2;
        }
        XREALLOC(files, filea);
      }
      memset(&files[fileu], 0, sizeof(files[0]));
      files[fileu].name = xstrdup(dd->d_name);
      ++fileu;
    }
  }
  closedir(d); d = NULL;
  if (!fileu) goto done;

  for (size_t i = 0; i < fileu; ++i) {
    unsigned char pkt_path[PATH_MAX];
    ur = snprintf(pkt_path, sizeof(pkt_path), "%s/%s", dir_dir, files[i].name);
    files[i].pkt = read_compile_reply_packet_from_file(files[i].name, pkt_path);
    if (files[i].pkt) {
      files[i].contest_id = files[i].pkt->contest_id;
    }
  }

  qsort(files, fileu, sizeof(files[0]), compile_packet_sort_func);

  struct teamdb_db_callbacks callbacks = {};
  callbacks.user_data = (void*) state;
  callbacks.list_all_users = ns_list_all_users_callback;

  int prev_contest_id = 0;
  const struct contest_desc *cnts = NULL;
  struct contest_extra *extra = NULL;
  serve_state_t cs = NULL;
  for (size_t i = 0; i < fileu; ++i) {
    if (files[i].contest_id <= 0) continue;
    if (files[i].contest_id != prev_contest_id) {
      prev_contest_id = files[i].contest_id;

      if (contests_get(prev_contest_id, &cnts) < 0 || !cnts) {
        // FIXME: probably it is a transient error, and this contest will be
        // available shortly?
        err("%s: dropping packets because of invalid contest %d", __FUNCTION__, prev_contest_id);
        cnts = NULL;
        extra = NULL;
        cs = NULL;
        continue;
      }

      extra = ns_get_contest_extra(cnts, config);
      ASSERT(extra);

      if (serve_state_load_contest(extra, config, prev_contest_id, ul_conn,
                                   &callbacks, 0, 0,
                                   ns_load_problem_plugin) < 0) {
        err("%s: dropping packets because of unavailable contest %d", __FUNCTION__, prev_contest_id);
        cnts = NULL;
        extra = NULL;
        cs = NULL;
        continue;
      }

      cs = extra->serve_state;
      cs->current_time = time(NULL);
    }

    if (serve_read_compile_packet(extra, config, cs, cnts, dir, data_dir, files[i].name, files[i].pkt) < 0) {
      // what to do?
    }
    files[i].pkt = NULL; // ownership transferred to 'serve_read_compile_packet'
  }

done:
  if (d) closedir(d);
  for (size_t i = 0; i < fileu; ++i) {
    free(files[i].name);
    compile_reply_packet_free(files[i].pkt);
  }
  free(files);
}

static struct run_reply_packet *
read_run_reply_packet_from_file(
        const unsigned char *name,
        const unsigned char *path)
{
  int unlink_on_fail = 1;
  unsigned char *buf = NULL;
  struct run_reply_packet *run_pkt = NULL;
  int fd = -1;

  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK, 0);
  if (fd < 0) {
    if (errno != ENOENT) {
      err("%s: failed to open '%s': %s", __FUNCTION__, path, os_ErrorMsg());
    } else {
      unlink_on_fail = 0;
    }
    goto fail;
  }

  struct stat stb;
  if (fstat(fd, &stb)) {
    abort();
  }
  if (!S_ISREG(stb.st_mode)) {
    err("%s: not regular file '%s'", __FUNCTION__, path);
    goto fail;
  }
  if (stb.st_size <= 0) {
    err("%s: empty file '%s'", __FUNCTION__, path);
    goto fail;
  }
  size_t size = stb.st_size;
  if (size > 1024 * 128) {
    err("%s: file '%s' too big: %zu", __FUNCTION__, path, size);
    goto fail;
  }

  buf = xmalloc(size + 1);
  buf[size] = 0;
  unsigned char *p = buf;
  size_t rm = size;
  while (rm > 0) {
    ssize_t rr = read(fd, p, rm);
    if (rr < 0) {
      err("%s: read error on '%s': %s", __FUNCTION__, path, os_ErrorMsg());
      goto fail;
    }
    if (!rr) {
      err("%s: unexpected EOF on '%s'", __FUNCTION__, path);
      goto fail;
    }
    p += rr;
    rm -= rr;
  }
  close(fd); fd = -1;

  if (run_reply_packet_read(size, buf, &run_pkt) < 0) {
    err("%s: invalid packet '%s'", __FUNCTION__, path);
    goto fail;
  }

  info("%s: run packet '%s' read", __FUNCTION__, name);
  free(buf);
  unlink(path);
  return run_pkt;

fail:;
  if (fd >= 0) close(fd);
  free(buf);
  if (unlink_on_fail) unlink(path);
  return NULL;
}

struct run_packet_file
{
  unsigned char *name;
  struct run_reply_packet *pkt;
  int contest_id;
};

static int
run_packet_sort_func(const void *p1, const void *p2)
{
  const struct run_packet_file *f1 = (const struct run_packet_file *) p1;
  const struct run_packet_file *f2 = (const struct run_packet_file *) p2;
  return f1->contest_id - f2->contest_id;
}

void
ns_run_dir_ready(
        const struct ejudge_cfg *config,
        struct server_framework_state *state,
        const unsigned char *dir,
        const unsigned char *dir_dir,
        const unsigned char *dir_out,
        const unsigned char *data_dir,
        const unsigned char *data2_dir,
        void *user)
{
  struct run_packet_file *files = NULL;
  size_t fileu = 0, filea = 0;
  DIR *d = NULL;
  __attribute__((unused)) int ur;

  d = opendir(dir_dir);
  if (!d) {
    err("%s: cannot open '%s': %s", __FUNCTION__, dir_dir, os_ErrorMsg());
    goto done;
  }
  struct dirent *dd;
  while ((dd = readdir(d))) {
    if (strcmp(dd->d_name, ".") && strcmp(dd->d_name, "..")) {
      if (fileu == filea) {
        if (!filea) {
          filea = 16;
        } else {
          filea *= 2;
        }
        XREALLOC(files, filea);
      }
      memset(&files[fileu], 0, sizeof(files[0]));
      files[fileu].name = xstrdup(dd->d_name);
      ++fileu;
    }
  }
  closedir(d); d = NULL;
  if (!fileu) goto done;

  for (size_t i = 0; i < fileu; ++i) {
    unsigned char pkt_path[PATH_MAX];
    ur = snprintf(pkt_path, sizeof(pkt_path), "%s/%s", dir_dir, files[i].name);
    files[i].pkt = read_run_reply_packet_from_file(files[i].name, pkt_path);
    if (files[i].pkt) {
      files[i].contest_id = files[i].pkt->contest_id;
    }
  }

  qsort(files, fileu, sizeof(files[0]), run_packet_sort_func);

  struct teamdb_db_callbacks callbacks = {};
  callbacks.user_data = (void*) state;
  callbacks.list_all_users = ns_list_all_users_callback;

  int prev_contest_id = 0;
  const struct contest_desc *cnts = NULL;
  struct contest_extra *extra = NULL;
  serve_state_t cs = NULL;
  for (size_t i = 0; i < fileu; ++i) {
    if (files[i].contest_id <= 0) continue;
    if (files[i].contest_id != prev_contest_id) {
      prev_contest_id = files[i].contest_id;

      if (contests_get(prev_contest_id, &cnts) < 0 || !cnts) {
        // FIXME: probably it is a transient error, and this contest will be
        // available shortly?
        err("%s: dropping packets because of invalid contest %d", __FUNCTION__, prev_contest_id);
        cnts = NULL;
        extra = NULL;
        cs = NULL;
        continue;
      }

      extra = ns_get_contest_extra(cnts, config);
      ASSERT(extra);

      if (serve_state_load_contest(extra, config, prev_contest_id, ul_conn,
                                   &callbacks, 0, 0,
                                   ns_load_problem_plugin) < 0) {
        err("%s: dropping packets because of unavailable contest %d", __FUNCTION__, prev_contest_id);
        cnts = NULL;
        extra = NULL;
        cs = NULL;
        continue;
      }

      cs = extra->serve_state;
      cs->current_time = time(NULL);
    }

    if (serve_read_run_packet(extra, config, cs, cnts,
                              dir, data_dir, data2_dir,
                              files[i].name, files[i].pkt) < 0) {
      // what to do?
    }
    files[i].pkt = NULL;
  }

done:
  if (d) closedir(d);
  for (size_t i = 0; i < fileu; ++i) {
    free(files[i].name);
    run_reply_packet_free(files[i].pkt);
  }
  free(files);
}
