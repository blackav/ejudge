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

#include "serve_state.h"
#include "filter_tree.h"
#include "runlog.h"
#include "team_extra.h"
#include "teamdb.h"
#include "clarlog.h"
#include "prepare.h"
#include "pathutl.h"
#include "errlog.h"
#include "userlist_proto.h"
#include "userlist_clnt.h"
#include "ejudge_plugin.h"

#include <reuse/xalloc.h>
#include <reuse/osdeps.h>
#include <reuse/logger.h>

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

serve_state_t
serve_state_init(void)
{
  serve_state_t state;

  XCALLOC(state, 1);
  state->clarlog_state = clar_init();
  state->teamdb_state = teamdb_init();
  state->team_extra_state = team_extra_init();
  state->runlog_state = run_init(state->teamdb_state);
  return state;
}

serve_state_t
serve_state_destroy(serve_state_t state,
                    const struct contest_desc *cnts,
                    struct userlist_clnt *ul_conn)
{
  int i, j;
  struct user_filter_info *ufp, *ufp2;

  if (!state) return 0;

  serve_event_destroy_queue(state);
  if (state->pending_xml_import) {
    if (state->saved_testing_suspended != state->testing_suspended) {
      state->testing_suspended = state->saved_testing_suspended;
      serve_update_status_file(state, 1);
      if (!state->testing_suspended)
        serve_judge_suspended(cnts, state, 0, 0, 0);
    }
    if (state->destroy_callback) (*state->destroy_callback)(state);
    xfree(state->pending_xml_import);
  }

  if (ul_conn && state->global && state->global->contest_id > 0) {
    // ignore error code
    userlist_clnt_notify(ul_conn, ULS_DEL_NOTIFY, state->global->contest_id);
  }

  xfree(state->config_path);
  run_destroy(state->runlog_state);
  team_extra_destroy(state->team_extra_state);
  teamdb_destroy(state->teamdb_state);
  clar_destroy(state->clarlog_state);

  watched_file_clear(&state->description);

  if (state->prob_extras) {
    for (i = 1; i <= state->max_prob; i++) {
      watched_file_clear(&state->prob_extras[i].stmt);
      watched_file_clear(&state->prob_extras[i].alt);
      if (state->probs[i] && state->probs[i]->variant_num > 0
          && state->prob_extras[i].v_stmts) {
        for (j = 1; j <= state->probs[i]->variant_num; j++)
          watched_file_clear(&state->prob_extras[i].v_stmts[j]);
        xfree(state->prob_extras[i].v_stmts);
      }
      if (state->probs[i] && state->probs[i]->variant_num > 0
          && state->prob_extras[i].v_alts) {
        for (j = 1; j <= state->probs[i]->variant_num; j++)
          watched_file_clear(&state->prob_extras[i].v_alts[j]);
        xfree(state->prob_extras[i].v_alts);
      }

      if (state->prob_extras[i].plugin && state->prob_extras[i].plugin_data) {
        (*state->prob_extras[i].plugin->finalize)(state->prob_extras[i].plugin_data);
      }
      if (state->prob_extras[i].plugin) {
        plugin_unload((struct ejudge_plugin_iface*) state->prob_extras[i].plugin);
      }
    }
  }
  xfree(state->prob_extras);

  prepare_free_config(state->config);

  for (i = 1; i < state->users_a; i++) {
    if (!state->users[i]) continue;
    for (ufp = state->users[i]->first_filter; ufp; ufp = ufp2) {
      ufp2 = ufp->next;
      xfree(ufp->prev_filter_expr);
      xfree(ufp->error_msgs);
      filter_tree_delete(ufp->tree_mem);
      xfree(ufp);
    }
    xfree(state->users[i]);
  }
  xfree(state->users);

  for (i = 0; i < state->compile_dirs_u; i++) {
    xfree(state->compile_dirs[i].status_dir);
    xfree(state->compile_dirs[i].report_dir);
  }
  xfree(state->compile_dirs);
  for (i = 0; i < state->run_dirs_u; i++) {
    xfree(state->run_dirs[i].status_dir);
    xfree(state->run_dirs[i].report_dir);
    xfree(state->run_dirs[i].team_report_dir);
    xfree(state->run_dirs[i].full_report_dir);
  }
  xfree(state->run_dirs);

  memset(state, 0, sizeof(*state));
  xfree(state);
  return 0;
}

void
serve_state_set_config_path(serve_state_t state, const unsigned char *path)
{
  xstrdup(state->config_path);
}

void
serve_set_upsolving_mode(serve_state_t state)
{
  time_t saved_duration = 0, saved_stop_time = 0;
  int prob_id;
  struct section_problem_data *prob;

  if (!state->upsolving_mode) return;

  run_get_saved_times(state->runlog_state, &saved_duration, &saved_stop_time);
  if (saved_stop_time <= 0) return;

  if (state->freeze_standings)
    state->global->stand_ignore_after_d = saved_stop_time;
  if (state->disable_clars)
    state->global->disable_team_clars = 1;
  if (state->view_source)
    state->global->team_enable_src_view = 1;

  for (prob_id = 1; prob_id <= state->max_prob; prob_id++) {
    if (!(prob = state->probs[prob_id])) continue;
    if (state->view_protocol)
      prob->team_enable_rep_view = 1;
    if (state->full_protocol)
      prob->team_show_judge_report = 1;
  }
}

int
serve_state_load_contest(int contest_id,
                         struct userlist_clnt *ul_conn,
                         struct teamdb_db_callbacks *teamdb_callbacks,
                         serve_state_t *p_state,
                         const struct contest_desc **p_cnts)
{
  serve_state_t state = 0;
  const struct contest_desc *cnts = 0;
  path_t config_path;
  const unsigned char *conf_dir;
  struct stat stbuf;
  int i;
  

  if (*p_state) return 0;
  if (contests_get(contest_id, &cnts) < 0 || !cnts) goto failure;

  if (cnts->conf_dir && os_IsAbsolutePath(cnts->conf_dir)) {
    snprintf(config_path, sizeof(config_path), "%s/serve.cfg", cnts->conf_dir);
  } else {
    if (!cnts->root_dir) {
      err("load_contest: contest %d root_dir is not set", contest_id);
      goto failure;
    } else if (!os_IsAbsolutePath(cnts->root_dir)) {
      err("load_contest: contest %d root_dir %s is not absolute",
          contest_id, cnts->root_dir);
      goto failure;
    }
    if (!(conf_dir = cnts->conf_dir)) conf_dir = "conf";
    snprintf(config_path, sizeof(config_path),
             "%s/%s/serve.cfg", cnts->root_dir, conf_dir);
  }

  if (stat(config_path, &stbuf) < 0) {
    err("load_contest: contest %d config file %s does not exist",
        contest_id, config_path);
    goto failure;
  }
  if (!S_ISREG(stbuf.st_mode)) {
    err("load_contest: contest %d config file %s is not a regular file",
        contest_id, config_path);
    goto failure;
  }
  if (access(config_path, R_OK) < 0) {
    err("load_contest: contest %d config file %s is not readable",
        contest_id, config_path);
    goto failure;
  }

  state = serve_state_init();
  state->config_path = xstrdup(config_path);
  state->current_time = time(0);

  info("loading contest %d configuration file", contest_id);
  if (prepare(state, state->config_path, 0, PREPARE_SERVE, "", 1) < 0)
    goto failure;
  if (prepare_serve_defaults(state, p_cnts) < 0) goto failure;
  if (create_dirs(state, PREPARE_SERVE) < 0) goto failure;

  team_extra_set_dir(state->team_extra_state, state->global->team_extra_dir);

  if (teamdb_set_callbacks(state->teamdb_state, teamdb_callbacks, cnts->id) < 0)
    goto failure;

  if (ul_conn) {
    // ignore error code
    userlist_clnt_notify(ul_conn, ULS_ADD_NOTIFY, contest_id);
  }

  if (state->global->is_virtual) {
    if (state->global->score_system_val != SCORE_ACM
        && state->global->score_system_val != SCORE_OLYMPIAD) {
      err("invalid score system for virtual contest");
      goto failure;
    }
  }

  while (1) {
    if (run_open(state->runlog_state, state->global->run_log_file, 0,
                 state->global->contest_time,
                 state->global->contest_finish_time_d) < 0) goto failure;
    if (!serve_collect_virtual_stop_events(state)) break;
    state->runlog_state = run_destroy(state->runlog_state);
    state->runlog_state = run_init(state->teamdb_state);
  }

  if (clar_open(state->clarlog_state, state->global->clar_log_file, 0) < 0)
    goto failure;
  serve_load_status_file(state);
  serve_set_upsolving_mode(state);
  serve_build_compile_dirs(state);
  serve_build_run_dirs(state);

  XCALLOC(state->prob_extras, state->max_prob + 1);
  for (i = 1; i <= state->max_prob; i++) {
    if (!state->probs[i] || state->probs[i]->variant_num <= 0) continue;
    XCALLOC(state->prob_extras[i].v_stmts, state->probs[i]->variant_num + 1);
    XCALLOC(state->prob_extras[i].v_alts, state->probs[i]->variant_num + 1);
  }

  teamdb_refresh(state->teamdb_state);
  serve_create_symlinks(state);
  serve_update_standings_file(state, cnts, 0);

  *p_state = state;
  return 1;

 failure:
  serve_state_destroy(state, cnts, ul_conn);
  return -1;
}

struct user_filter_info *
user_filter_info_allocate(serve_state_t state, int user_id,
                          ej_cookie_t session_id)
{
  struct user_filter_info *p;

  if (user_id == -1) user_id = 0;

  if (user_id >= state->users_a) {
    int new_users_a = state->users_a;
    struct user_state_info **new_users;

    if (!new_users_a) new_users_a = 64;
    while (new_users_a <= user_id) new_users_a *= 2;
    new_users = xcalloc(new_users_a, sizeof(new_users[0]));
    if (state->users_a > 0)
      memcpy(new_users, state->users, state->users_a * sizeof(state->users[0]));
    xfree(state->users);
    state->users_a = new_users_a;
    state->users = new_users;
    info("allocate_user_info: new size %d", state->users_a);
  }
  if (!state->users[user_id]) {
    state->users[user_id] = xcalloc(1, sizeof(*state->users[user_id]));
  }

  for (p = state->users[user_id]->first_filter; p; p = p->next) {
    if (p->session_id == session_id) break;
  }
  if (!p) {
    XCALLOC(p, 1);
    p->next = state->users[user_id]->first_filter;
    p->session_id = session_id;
    state->users[user_id]->first_filter = p;
  }

  state->cur_user = p;
  return p;
}

void
serve_event_add(serve_state_t state, time_t time, int type, int user_id)
{
  struct serve_event_queue *e, *p;

  ASSERT(time > 0);
  ASSERT(type > 0);
  ASSERT(user_id > 0);

  XCALLOC(e, 1);
  e->time = time;
  e->type = type;
  e->user_id = user_id;

  for (p = state->event_first; p && p->time < time; p = p->next);
  if (!p) {
    if (!state->event_first) {
      state->event_first = state->event_last = e;
    } else {
      e->prev = state->event_last;
      state->event_last->next = e;
      state->event_last = e;
    }
  } else {
    if (!p->prev) {
      state->event_first = e;
    } else {
      e->prev = p->prev;
      p->prev->next = e;
    }
    p->prev = e;
    e->next = p;
  }
}

void
serve_event_remove(serve_state_t state, struct serve_event_queue *event)
{
  if (!event->prev) {
    state->event_first = event->next;
  } else {
    event->prev->next = event->next;
  }
  if (!event->next) {
    state->event_last = event->prev;
  } else {
    event->next->prev = event->prev;
  }
  xfree(event);
}

void
serve_event_destroy_queue(serve_state_t state)
{
  struct serve_event_queue *p, *q;

  for (p = state->event_first; p; p = q) {
    q = p->next;
    xfree(p);
  }
  state->event_first = state->event_last = 0;
}

int
serve_event_remove_matching(serve_state_t state, time_t time,
                            int type, int user_id)
{
  struct serve_event_queue *p, *q;
  int count = 0;

  for (p = state->event_first; p; p = q) {
    q = p->next;
    if (time > 0 && time != p->time) continue;
    if (type > 0 && type != p->type) continue;
    if (user_id > 0 && user_id != p->user_id) continue;
    serve_event_remove(state, p);
    count++;
  }
  return count;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
