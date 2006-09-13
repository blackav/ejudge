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

#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

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
serve_state_destroy(serve_state_t state)
{
  int i;
  struct user_filter_info *ufp, *ufp2;

  if (!state) return 0;
  xfree(state->config_path);
  run_destroy(state->runlog_state);
  team_extra_destroy(state->team_extra_state);
  teamdb_destroy(state->teamdb_state);
  clar_destroy(state->clarlog_state);

  prepare_free_config(state->config);

  for (i = 0; i < state->users_a; i++) {
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

int
serve_state_load_contest(int contest_id,
                         struct userlist_clnt *ul_conn,
                         struct teamdb_db_callbacks *teamdb_callbacks,
                         serve_state_t *p_state)
{
  serve_state_t state = 0;
  const struct contest_desc *cnts = 0;
  path_t config_path;
  const unsigned char *conf_dir;
  struct stat stbuf;
  

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

  if (prepare(state, state->config_path, 0, PREPARE_SERVE, "", 1) < 0)
    goto failure;
  if (prepare_serve_defaults(state) < 0) goto failure;
  if (create_dirs(state, PREPARE_SERVE) < 0) goto failure;

  team_extra_set_dir(state->team_extra_state, state->global->team_extra_dir);

  if (teamdb_set_callbacks(state->teamdb_state, teamdb_callbacks, cnts->id) < 0)
    goto failure;

  if (ul_conn) {
    // ignore error code
    userlist_clnt_notify(ul_conn, ULS_ADD_NOTIFY, contest_id);
  }

  if (run_open(state->runlog_state, state->global->run_log_file, 0,
               state->global->contest_time) < 0) goto failure;
  if (state->global->virtual && state->global->score_system_val != SCORE_ACM) {
    err("invalid score system for virtual contest");
    goto failure;
  }
  if (clar_open(state->clarlog_state, state->global->clar_log_file, 0) < 0)
    goto failure;
  serve_load_status_file(state);
  serve_build_compile_dirs(state);
  serve_build_run_dirs(state);

  *p_state = state;
  return 1;

 failure:
  serve_state_destroy(state);
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
