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

#include "ejudge/serve_state.h"
#include "ejudge/filter_tree.h"
#include "ejudge/runlog.h"
#include "ejudge/team_extra.h"
#include "ejudge/teamdb.h"
#include "ejudge/clarlog.h"
#include "ejudge/prepare.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/userlist_proto.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/ejudge_plugin.h"
#include "ejudge/csv.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/misctext.h"
#include "ejudge/new-server.h"
#include "ejudge/sformat.h"
#include "ejudge/testing_report_xml.h"
#include "ejudge/prepare_serve.h"
#include "ejudge/userlist.h"
#include "ejudge/xml_utils.h"
#include "ejudge/win32_compat.h"
#include "ejudge/variant_map.h"
#include "ejudge/xuser_plugin.h"
#include "ejudge/statusdb.h"
#include "ejudge/variant_plugin.h"
#include "ejudge/submit_plugin.h"
#include "ejudge/metrics_contest.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

serve_state_t
serve_state_init(int contest_id)
{
  serve_state_t state;

  XCALLOC(state, 1);
  state->contest_id = contest_id;
  state->clarlog_state = clar_init();
  state->teamdb_state = teamdb_init(contest_id);
  state->runlog_state = run_init(state->teamdb_state);

  if (metrics.data) {
    ++metrics.data->loaded_contests;
  }

  return state;
}

void
serve_state_destroy_stand_expr(struct user_filter_info *u)
{
  if (!u) return;

  xfree(u->stand_user_expr); u->stand_user_expr = 0;
  xfree(u->stand_prob_expr); u->stand_prob_expr = 0;
  xfree(u->stand_run_expr); u->stand_run_expr = 0;
  xfree(u->stand_time_expr); u->stand_time_expr = NULL;
  xfree(u->stand_error_msgs); u->stand_error_msgs = 0;
  filter_tree_delete(u->stand_mem); u->stand_mem = 0;
  u->stand_user_tree = 0;
  u->stand_prob_tree = 0;
  u->stand_run_tree = 0;
  u->stand_time_expr_mode = 0;
  u->stand_time_expr_time = 0;
  u->stand_user_mode = 0;
}

serve_state_t
serve_state_destroy(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        struct userlist_clnt *ul_conn)
{
  int i, j;
  struct user_filter_info *ufp, *ufp2;
  struct serve_user_group *srv_grp;
  struct serve_group_member *srv_gm;

  if (!state) return 0;

  serve_event_destroy_queue(state);
  if (state->pending_xml_import) {
    if (state->saved_testing_suspended != state->testing_suspended) {
      state->testing_suspended = state->saved_testing_suspended;
      serve_update_status_file(config, cnts, state, 1);
      if (!state->testing_suspended && cnts)
        serve_judge_suspended(extra, config, cnts, state, 0, 0, 0, 0, 0);
    }
    if (state->destroy_callback) (*state->destroy_callback)(state);
    xfree(state->pending_xml_import);
  }

  if (ul_conn && state->global && cnts && cnts->id > 0) {
    // ignore error code
    userlist_clnt_notify(ul_conn, ULS_DEL_NOTIFY, cnts->id);
  }

  xfree(state->config_path);
  run_destroy(state->runlog_state);
  if (state->xuser_state) {
    state->xuser_state->vt->close(state->xuser_state);
  }
  teamdb_destroy(state->teamdb_state);
  clar_destroy(state->clarlog_state);
  if (state->variant_state) {
    state->variant_state->vt->close(state->variant_state);
  }
  if (state->submit_state) {
    state->submit_state->vt->close(state->submit_state);
  }

  watched_file_clear(&state->description);

  if (state->statusdb_state) {
    statusdb_close(state->statusdb_state);
  }

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

      struct ejudge_plugin_iface *iface = (struct ejudge_plugin_iface*) state->prob_extras[i].plugin;
      if (plugin_get_refcount(iface) == 1) {
        if (state->prob_extras[i].plugin && state->prob_extras[i].plugin_data) {
          (*state->prob_extras[i].plugin->finalize)(state->prob_extras[i].plugin_data);
        }
        if (state->prob_extras[i].plugin) {
          plugin_unload_2(iface);
        }
      }
    }
  }
  xfree(state->prob_extras);

  if (state->contest_plugin && state->contest_plugin_data) {
    (*state->contest_plugin->finalize)(state->contest_plugin_data);
  }
  if (state->contest_plugin) {
    plugin_unload((struct ejudge_plugin_iface*) state->contest_plugin);
  }

  if (state->user_group_count > 0) {
    for (i = 0; i < state->user_group_count; ++i) {
      srv_grp = &state->user_groups[i];
      xfree(srv_grp->group_name);
      xfree(srv_grp->description);
      xfree(srv_grp->members);
    }
  }
  xfree(state->user_groups);
  xfree(state->user_group_map);

  if (state->group_member_count) {
    for (i = 0; i < state->group_member_count; ++i) {
      srv_gm = &state->group_members[i];
      xfree(srv_gm->group_bitmap);
      srv_gm->group_bitmap = 0;
    }
  }
  xfree(state->group_members);
  xfree(state->group_member_map);

  prepare_free_config(state->config);

  for (i = 1; i < state->users_a; i++) {
    if (!state->users[i]) continue;
    for (ufp = state->users[i]->first_filter; ufp; ufp = ufp2) {
      ufp2 = ufp->next;
      xfree(ufp->prev_filter_expr);
      xfree(ufp->error_msgs);
      filter_tree_delete(ufp->tree_mem);
      serve_state_destroy_stand_expr(ufp);
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

  for (i = 0; i < state->compile_queues_u; ++i) {
    struct compile_queue_item *item = &state->compile_queues[i];
    xfree(item->id);
    xfree(item->queue_dir);
    xfree(item->src_dir);
    xfree(item->heartbeat_dir);
  }
  xfree(state->compile_queues);

  for (i = 0; i < state->run_dirs_u; i++) {
    struct run_dir_item *rdi = &state->run_dirs[i];
    xfree(rdi->id);
    xfree(rdi->status_dir);
    xfree(rdi->report_dir);
    xfree(rdi->team_report_dir);
    xfree(rdi->full_report_dir);
  }
  xfree(state->run_dirs);

  for (i = 0; i < state->run_queues_u; ++i) {
    struct run_queue_item *rqi = &state->run_queues[i];
    xfree(rqi->id);
    xfree(rqi->queue_dir);
    xfree(rqi->exe_dir);
    xfree(rqi->heartbeat_dir);
  }
  xfree(state->run_queues);

  xfree(state->abstr_probs);
  xfree(state->abstr_testers);

  xfree(state->langs);
  xfree(state->probs);
  xfree(state->testers);

  xfree(state->user_results);

  if (state->compiler_options) {
    for (i = 1; i <= state->max_lang; ++i) {
      xfree(state->compiler_options[i]);
    }
    xfree(state->compiler_options);
  }

  if (metrics.data) {
    --metrics.data->loaded_contests;
  }

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
  time_t saved_duration = 0, saved_stop_time = 0, saved_finish_time = 0;
  int prob_id;
  struct section_problem_data *prob;

  if (!state->upsolving_mode) return;

  run_get_saved_times(state->runlog_state, &saved_duration, &saved_stop_time,
                      &saved_finish_time);
  if (saved_stop_time <= 0) return;

  if (state->upsolving_freeze_standings)
    state->global->stand_ignore_after = saved_stop_time;
  if (state->upsolving_disable_clars)
    state->global->disable_team_clars = 1;
  if (state->upsolving_view_source)
    state->global->team_enable_src_view = 1;

  for (prob_id = 1; prob_id <= state->max_prob; prob_id++) {
    if (!(prob = state->probs[prob_id])) continue;
    if (state->upsolving_view_protocol)
      prob->team_enable_rep_view = 1;
    if (state->upsolving_full_protocol)
      prob->team_show_judge_report = 1;
  }
}

int
serve_load_user_groups(
        int contest_id,
        serve_state_t state,
        struct userlist_clnt *ul_conn)
{
  const struct section_global_data *global = state->global;
  int i, j, total_len = 0, len, r;
  unsigned char *grp_list = 0, *grp_p;
  unsigned char *xml_text = 0;
  struct userlist_list *grp_info = 0;
  struct xml_tree *xml_ptr;
  const struct userlist_group *grp;
  const struct userlist_groupmember *gm;
  struct serve_user_group *srv_grp;
  struct serve_group_member *srv_gm;
  int user_group_count, user_group_map_size;
  int member_map_size = 0, group_member_count = 0;
  int bs_size;

  if (!global) return 0;
  if (!global->load_user_group) return 0;
  if (!ul_conn) {
    info("load_contest: contest %d groups are not loaded", contest_id);
    return 0;
  }
  for (i = 0; global->load_user_group[i]; ++i) {
    total_len += strlen(global->load_user_group[i]) + 1;
  }
  if (total_len >= 65536) {
    err("load_contest: contest %d: total group length too high (%d)",
        contest_id, total_len);
    return -1;
  }
  grp_list = (unsigned char *) alloca(total_len + 10);
  grp_p = grp_list;
  for (i = 0; global->load_user_group[i]; ++i) {
    if (i > 0) {
      *grp_p++ = ' ';
    }
    len = strlen(global->load_user_group[i]);
    memcpy(grp_p, global->load_user_group[i], len);
    grp_p += len;
  }
  *grp_p = 0;

  r = userlist_clnt_get_xml_by_text(ul_conn, ULS_GET_GROUPS, grp_list,
                                    &xml_text);
  if (r < 0) {
    err("load_contest: contest %d: failed to load groups: %s",
        contest_id, userlist_strerror(-r));
    goto failed;
  }
  if (!xml_text) {
    err("load_contest: contest %d: group XML is NULL", contest_id);
    goto failed;
  }
  grp_info = userlist_parse_str(xml_text);
  if (!grp_info) {
    err("load_contest: contest %d: XML parse error", contest_id);
    goto failed;
  }
  xfree(xml_text); xml_text = 0;

  if (grp_info->group_map_size <= 0 || !grp_info->group_map) {
    err("load_contest: contest %d: no groups loaded", contest_id);
    goto failed;
  }

  user_group_map_size = grp_info->group_map_size;
  while (user_group_map_size > 0
         && !grp_info->group_map[user_group_map_size - 1])
    user_group_map_size--;

  // find the max group_id and the group counter
  user_group_count = 0;
  for (i = 0; i < user_group_map_size; ++i) {
    if (grp_info->group_map[i]) {
      ++user_group_count;
    }
  }

  if (user_group_count <= 0) {
    err("load_contest: contest %d: no groups loaded", contest_id);
    goto failed;
  }

  state->user_group_count = user_group_count;
  state->user_group_map_size = user_group_map_size;
  XCALLOC(state->user_groups, state->user_group_count);
  XCALLOC(state->user_group_map, state->user_group_map_size);
  memset(state->user_group_map, -1,
         sizeof(state->user_group_map[0]) * state->user_group_map_size);
  for (i = 0, j = 0; i < state->user_group_map_size; ++i) {
    if (grp_info->group_map[i]) {
      grp = grp_info->group_map[i];
      srv_grp = &state->user_groups[j];
      srv_grp->group_id = grp->group_id;
      srv_grp->group_name = xstrdup(grp->group_name);
      srv_grp->description = xstrdup(grp->description);
      state->user_group_map[i] = j;
      ++j;
    }
  }

  // calculate the member_map_size
  if (!grp_info->groupmembers_node) goto done;
  for (xml_ptr = grp_info->groupmembers_node->first_down; xml_ptr;
       xml_ptr = xml_ptr->right) {
    ASSERT(xml_ptr->tag == USERLIST_T_USERGROUPMEMBER);
    gm = (struct userlist_groupmember*) xml_ptr;
    ASSERT(gm->group_id > 0 && gm->group_id < state->user_group_map_size);
    ASSERT(state->user_group_map[gm->group_id] >= 0);
    ASSERT(gm->user_id > 0);
    if (gm->user_id + 1 > member_map_size) {
      member_map_size = gm->user_id + 1;
    }
    j = state->user_group_map[gm->group_id];
    ++state->user_groups[j].member_count;
  }
  if (member_map_size <= 0) {
    goto done;
  }

  state->group_member_map_size = member_map_size;
  XCALLOC(state->group_member_map, member_map_size);
  memset(state->group_member_map, -1,
         member_map_size * sizeof(state->group_member_map[0]));

  for (i = 0; i < state->user_group_count; ++i) {
    srv_grp = &state->user_groups[i];
    if (srv_grp->member_count > 0) {
      XCALLOC(srv_grp->members, srv_grp->member_count);
    }
  }

  for (xml_ptr = grp_info->groupmembers_node->first_down; xml_ptr;
       xml_ptr = xml_ptr->right) {
    gm = (struct userlist_groupmember*) xml_ptr;
    ASSERT(gm->user_id < member_map_size);
    if (state->group_member_map[gm->user_id] < 0) {
      state->group_member_map[gm->user_id] = group_member_count++;
    }
  }
  if (group_member_count <= 0) goto done;

  state->group_member_count = group_member_count;
  XCALLOC(state->group_members, group_member_count);
  bs_size = (user_group_count + 31) / 32;
  ASSERT(bs_size > 0);
  for (i = 0; i < group_member_count; ++i) {
    XCALLOC(state->group_members[i].group_bitmap, bs_size);
  }

  for (i = 0, xml_ptr = grp_info->groupmembers_node->first_down; xml_ptr;
       xml_ptr = xml_ptr->right) {
    gm = (struct userlist_groupmember*) xml_ptr;
    ASSERT(state->group_member_map[gm->user_id] >= 0);
    srv_gm = &state->group_members[state->group_member_map[gm->user_id]];
    srv_gm->user_id = gm->user_id;
    j = state->user_group_map[gm->group_id];
    ASSERT(j >= 0 && j < state->user_group_count);
    srv_gm->group_bitmap[j >> 5] |= (1U << (j & 0x1f));
    srv_grp = &state->user_groups[j];
    srv_grp->members[srv_grp->serial++] = gm->user_id;
  }

  /*
  // just for debug
  fprintf(stderr, "user_group_count:      %d\n", state->user_group_count);
  fprintf(stderr, "user_group_map_size:   %d\n", state->user_group_map_size);
  fprintf(stderr, "group_member_count:    %d\n", state->group_member_count);
  fprintf(stderr, "group_member_map_size: %d\n", state->group_member_map_size);
  */

done:
  if (grp_info) userlist_free(&grp_info->b);
  xfree(xml_text);
  return 0;

failed:
  if (grp_info) userlist_free(&grp_info->b);
  xfree(xml_text);
  return -1;
}

static int
parse_group_dates(
        int contest_id,
        serve_state_t state,
        struct section_problem_data *prob,
        const unsigned char *var_name,
        struct group_dates *gd,
        char **strs)
{
  int len, i, j;
  const unsigned char *pcur, *pend;
  const unsigned char *group_name;

  memset(gd, 0, sizeof(*gd));
  if (!strs || !strs[0]) return 0;
  len = sarray_len(strs);
  XCALLOC(gd->info, len + 1);
  for (i = 0; i < len + 1; ++i)
    gd->info[i].group_ind = -2;

  /* "@GROUP_NAME DATE" */
  for (i = 0; i < len; ++i) {
    pcur = (const unsigned char*) strs[i];
    while (isspace(*pcur)) ++pcur;
    if (!*pcur) {
      err("contest %d: problem %s: %s: line %d: empty specification",
          contest_id, prob->short_name, var_name, i + 1);
      return -1;
    }
    if (*pcur == '*') {
      pend = pcur + 1;
    } else {
      if (*pcur != '@') {
        err("contest %d: problem %s: %s: line %d: '@' expected",
            contest_id, prob->short_name, var_name, i + 1);
        return -1;
      }
      ++pcur;
      while (isspace(*pcur)) ++pcur;
      if (!*pcur) {
        err("contest %d: problem %s: %s: line %d: group_name expected",
            contest_id, prob->short_name, var_name, i + 1);
        return -1;
      }
      pend = pcur;
      while (*pend && !isspace(*pend)) ++pend;
    }

    group_name = gd->info[i].group_name = xmemdup(pcur, pend - pcur);
    pcur = pend;

    while (isspace(*pcur)) ++pcur;
    if (!*pcur) {
      err("contest %d: problem %s: %s: line %d: date expected",
          contest_id, prob->short_name, var_name, i + 1);
      return -1;
    }

    if (xml_parse_date(NULL, NULL, 0, 0, pcur, &gd->info[i].p.date) < 0) {
      err("contest %d: problem %s: %s: line %d: invalid date",
          contest_id, prob->short_name, var_name, i + 1);
      return -1;
    }

    if (!strcmp(group_name, "*")) {
      gd->info[i].group_ind = -1;
    } else {
      for (j = 0; j < state->user_group_count; ++j) {
        if (!strcmp(state->user_groups[j].group_name, group_name)) {
          break;
        }
      }
      if (j >= state->user_group_count) {
        err("contest %d: problem %s: %s: line %d: invalid group %s",
            contest_id, prob->short_name, var_name, i + 1, group_name);
        return -1;
      }
      gd->info[i].group_ind = j;
    }
  }
  gd->count = len;

  /*
  // barrier entry
  if (len > 0 && gd->info[len - 1].group_ind >= 0) {
    gd->info[len].group_name = xstrdup("*");
    gd->info[len].group_ind = -1;
    gd->info[len].date = 0;
    ++gd->count;
  }
  */

  return 0;
}

int
serve_parse_group_dates(int contest_id, serve_state_t state)
{
  int i;
  struct section_problem_data *prob;

  for (i = 1; i <= state->max_prob; ++i) {
    if (!(prob = state->probs[i])) continue;
    if (parse_group_dates(contest_id, state, prob, "group_start_date",
                          &prob->gsd, prob->group_start_date) < 0)
      return -1;
    if (parse_group_dates(contest_id, state, prob, "group_deadline",
                          &prob->gdl, prob->group_deadline) < 0)
      return -1;
  }
  return 0;
}

const size_t serve_struct_sizes_array[] =
{
  sizeof(struct clar_entry_v2),
  sizeof(struct compile_dir_item),
  sizeof(struct compile_run_extra),
  sizeof(struct contest_access),
  sizeof(struct contest_desc),
  sizeof(struct contest_field),
  sizeof(struct contest_ip),
  sizeof(struct contest_member),
  sizeof(struct csv_file),
  sizeof(struct csv_line),
  sizeof(struct ejudge_cfg),
  sizeof(struct ejudge_cfg_user_map),
  sizeof(struct generic_section_config),
  sizeof(struct html_armor_buffer),
  sizeof(struct http_request_info),
  sizeof(struct int_iterator),
  sizeof(struct _opcaplist),
  sizeof(struct opcap_list_item),
  sizeof(struct penalty_info),
  sizeof(struct pers_dead_info),
  sizeof(struct problem_desc),
  sizeof(struct problem_extra_info),
  sizeof(struct problem_stmt),
  sizeof(struct problem_time_limit),
  sizeof(struct ptr_iterator),
  sizeof(struct run_data),
  sizeof(struct run_dir_item),
  sizeof(struct run_entry),
  sizeof(struct run_file),
  sizeof(struct run_header),
  sizeof(struct run_xml_helpers),
  sizeof(struct section_global_data),
  sizeof(struct section_language_data),
  sizeof(struct section_problem_data),
  sizeof(struct section_tester_data),
  sizeof(struct serve_event_queue),
  sizeof(struct serve_state),
  sizeof(struct sformat_extra_data),
  sizeof(struct teamdb_db_callbacks),
  sizeof(struct teamdb_export),
  sizeof(struct team_extra),
  sizeof(struct team_warning),
  sizeof(struct testing_report_test),
  sizeof(struct testing_report_xml),
  sizeof(struct testset_info),
  sizeof(struct user_adjustment_info),
  sizeof(struct user_adjustment_map),
  sizeof(struct user_filter_info),
  sizeof(struct userlist_contest),
  sizeof(struct userlist_cookie),
  sizeof(struct userlist_list),
  sizeof(struct userlist_member),
  sizeof(struct userlist_members),
  sizeof(struct userlist_user),
  sizeof(struct userlist_user_info),
  sizeof(struct user_state_info),
  sizeof(struct variant_map),
  sizeof(struct variant_map_item),
  sizeof(struct watched_file),
  sizeof(struct xml_attr),
  sizeof(struct xml_parse_spec),
  sizeof(struct xml_tree),
};
const size_t serve_struct_sizes_array_size = sizeof(serve_struct_sizes_array);
const size_t serve_struct_sizes_array_num = sizeof(serve_struct_sizes_array) / sizeof(serve_struct_sizes_array[0]);

int
serve_state_load_contest_config(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        int contest_id,
        const struct contest_desc *cnts,
        serve_state_t *p_state)
{
  serve_state_t state = 0;
  path_t config_path;
  const unsigned char *conf_dir;
  struct stat stbuf;

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

  state = serve_state_init(contest_id);
  state->config_path = xstrdup(config_path);
  state->current_time = time(0);
  state->load_time = state->current_time;

  if (prepare(config, cnts, state, state->config_path, 0, PREPARE_SERVE, "", 1, 0, 0) < 0)
    goto failure;
  if (prepare_serve_defaults(cnts, state, NULL) < 0) goto failure;

  if (state->global) {
    teamdb_disable(state->teamdb_state, state->global->disable_user_database);
  }

  *p_state = state;

  return 1;

 failure:
  serve_state_destroy(extra, config, state, cnts, NULL);
  return -1;
}

int
serve_state_load_contest(
        struct contest_extra *extra,
        const struct ejudge_cfg *config,
        int contest_id,
        struct userlist_clnt *ul_conn,
        struct teamdb_db_callbacks *teamdb_callbacks,
        const struct contest_desc **p_cnts,
        int no_users_flag,
        void (*load_plugin_func)(
                serve_state_t cs,
                struct problem_extra_info *extra,
                const struct section_problem_data *prob))
{
  serve_state_t state = 0;
  const struct contest_desc *cnts = 0;
  const struct section_problem_data *prob = 0;
  path_t config_path;
  const unsigned char *conf_dir;
  struct stat stbuf;
  int i;
  const size_t *sza;
  struct contest_plugin_iface *iface;
  const unsigned char *f = __FUNCTION__;
  const struct section_global_data *global = 0;
  time_t contest_finish_time = 0;

  if (extra->serve_state) return 0;

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

  state = serve_state_init(contest_id);
  state->config_path = xstrdup(config_path);
  state->current_time = time(0);
  state->load_time = state->current_time;
  extra->serve_state = state;

  info("loading contest %d configuration file", contest_id);
  if (prepare(config, cnts, state, state->config_path, 0, PREPARE_SERVE, "", 1, 0, 0) < 0)
    goto failure;
  if (prepare_serve_defaults(cnts, state, p_cnts) < 0) goto failure;
  if (create_dirs(cnts, state, PREPARE_SERVE) < 0) goto failure;

  global = state->global;
  teamdb_disable(state->teamdb_state, global->disable_user_database);

  /* find olympiad_mode problems in KIROV contests */
  if (global->score_system == SCORE_KIROV) {
    for (i = 1; i <= state->max_prob; i++) {
      if (!(prob = state->probs[i])) continue;
      if (prob->olympiad_mode > 0) state->has_olympiad_mode = 1;
    }
  }

  state->statusdb_state = statusdb_open(config, cnts, global, NULL, 0, 1);
  if (!state->statusdb_state) {
    err("load_contest: contest %d statusdb plugin failed to load", contest_id);
    goto failure;
  }

  if (no_users_flag) {
    return 1;
  }

  state->xuser_state = team_extra_open(config, cnts, global, NULL, 0);
  if (!state->xuser_state) {
    err("load_contest: contest %d xuser plugin failed to load", contest_id);
    goto failure;
  }

  if (teamdb_set_callbacks(state->teamdb_state, teamdb_callbacks, cnts->id) < 0)
    goto failure;

  if (ul_conn) {
    // ignore error code
    userlist_clnt_notify(ul_conn, ULS_ADD_NOTIFY, contest_id);
  }

  if (serve_load_user_groups(contest_id, state, ul_conn) < 0) {
    goto failure;
  }
  if (serve_parse_group_dates(contest_id, state) < 0) {
    goto failure;
  }

  // load reporting plugin
  if (global->contest_plugin_file && global->contest_plugin_file[0]) {
    iface = (struct contest_plugin_iface *) plugin_load(global->contest_plugin_file, "report", "");
    if (!iface) goto failure;
    state->contest_plugin = iface;
    if (iface->contest_plugin_version != CONTEST_PLUGIN_IFACE_VERSION) {
      err("%s: contest %d plugin version mismatch", f, contest_id);
      goto failure;
    }
    if (!(sza = iface->sizes_array)) {
      err("%s: contest %d plugin sizes array is NULL", f, contest_id);
      goto failure;
    }
    if (iface->sizes_array_size != serve_struct_sizes_array_size) {
      err("%s: contest %d plugin sizes array size mismatch: %" EJ_PRINTF_ZSPEC "u instead of %" EJ_PRINTF_ZSPEC "u",
          f, contest_id, EJ_PRINTF_ZCAST(iface->sizes_array_size),
          EJ_PRINTF_ZCAST(serve_struct_sizes_array_size));
      goto failure;
    }
    for (i = 0; i < serve_struct_sizes_array_num; ++i) {
      if (sza[i] && sza[i] != serve_struct_sizes_array[i]) {
        err("%s: contest %d plugin sizes array element %d mismatch: %" EJ_PRINTF_ZSPEC "u instead of %" EJ_PRINTF_ZSPEC "u",
            f, contest_id, i, EJ_PRINTF_ZCAST(sza[i]), EJ_PRINTF_ZCAST(serve_struct_sizes_array[i]));
        goto failure;
      }
    }

    if (state->contest_plugin->init)
      state->contest_plugin_data = (*state->contest_plugin->init)();
  }

  if (global->is_virtual) {
    if (global->score_system != SCORE_ACM
        && global->score_system != SCORE_OLYMPIAD
        && global->score_system != SCORE_KIROV) {
      err("invalid score system for virtual contest");
      goto failure;
    }
  }

  while (1) {
    contest_finish_time = 0;
    if (global->contest_finish_time > 0) {
      contest_finish_time = global->contest_finish_time;
    }
    if (contest_finish_time > 0 && contest_finish_time <= state->current_time){
      contest_finish_time = 0;
    }
    if (run_open(state->runlog_state, config, cnts, global, 0,
                 metrics.data,
                 0,
                 global->contest_time, cnts->sched_time,
                 contest_finish_time) < 0) goto failure;
    if (!serve_collect_virtual_stop_events(state)) break;
    state->runlog_state = run_destroy(state->runlog_state);
    state->runlog_state = run_init(state->teamdb_state);
  }

  if (clar_open(state->clarlog_state, config, cnts, global, 0, 0) < 0)
    goto failure;
  serve_load_status_file(config, cnts, state);
  serve_set_upsolving_mode(state);
  serve_build_compile_dirs(config, state);
  serve_build_run_dirs(config, state, cnts);

  int need_variant_plugin = 0;
  XCALLOC(state->prob_extras, state->max_prob + 1);
  for (i = 1; i <= state->max_prob; i++) {
    const struct section_problem_data *prob = state->probs[i];
    if (!prob) continue;
    struct problem_extra_info *extra = &state->prob_extras[i];
    if (prob->plugin_file && prob->plugin_file[0] && load_plugin_func) {
      load_plugin_func(state, extra, prob);
    }
    if (prob->variant_num > 0) {
      need_variant_plugin = 1;
      XCALLOC(extra->v_stmts, prob->variant_num + 1);
      XCALLOC(extra->v_alts, prob->variant_num + 1);
    }
  }
  if (need_variant_plugin) {
    state->variant_state = variant_plugin_open(NULL, config, cnts, state, NULL, 0);
    if (!state->variant_state) {
      err("load_contest: contest %d variant plugin failed to load", contest_id);
      goto failure;
    }
  }

  teamdb_refresh(state->teamdb_state);
  serve_create_symlinks(cnts, state);
  serve_update_standings_file(extra, state, cnts, 0);

  return 1;

 failure:
  extra->serve_state = NULL;
  serve_state_destroy(extra, config, state, cnts, ul_conn);
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
    p->prev_first_clar = -1;
    p->prev_last_clar = -10;
    p->next = state->users[user_id]->first_filter;
    p->session_id = session_id;
    state->users[user_id]->first_filter = p;
  }

  state->cur_user = p;
  return p;
}

void
serve_event_add(
        serve_state_t state,
        time_t time,
        int type,
        int user_id,
        serve_event_hander_t handler)
{
  struct serve_event_queue *e, *p;

  ASSERT(time > 0);
  ASSERT(type > 0);
  ASSERT(user_id > 0);

  XCALLOC(e, 1);
  e->time = time;
  e->type = type;
  e->user_id = user_id;
  e->handler = handler;
  e->real_time = time;

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

void
serve_store_user_result(
        serve_state_t state,
        int user_id,
        int score)
{
  if (!state) return;
  if (user_id <= 0 || user_id > EJ_MAX_USER_ID) return;

  if (user_id >= state->user_result_a) {
    int new_size = state->user_result_a;
    if (!new_size) new_size = 128;
    while (user_id >= new_size) new_size *= 2;
    struct serve_user_results *new_results = 0;
    XCALLOC(new_results, new_size);
    if (state->user_result_a > 0) {
      memcpy(new_results, state->user_results,
             state->user_result_a * sizeof(new_results[0]));
    }
    xfree(state->user_results);
    state->user_results = new_results;
    state->user_result_a = new_size;
  }

  state->user_results[user_id].total_score = score;
}

int
serve_get_user_result_score(
        serve_state_t state,
        int user_id)
{
  if (!state || user_id <= 0 || user_id >= state->user_result_a) return 0;
  return state->user_results[user_id].total_score;
}
