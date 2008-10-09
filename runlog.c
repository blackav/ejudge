/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2008 Alexander Chernov <cher@ejudge.ru> */

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

#include "runlog.h"
#include "teamdb.h"

#include "pathutl.h"
#include "errlog.h"
#include "unix/unix_fileutl.h"
#include "xml_utils.h"
#include "random.h"
#include "runlog_state.h"
#include "rldb_plugin.h"
#include "prepare.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

/* plugin information */
struct rldb_loaded_plugin
{
  struct rldb_plugin_iface *iface;
  struct rldb_plugin_data *data;
};

enum { RLDB_PLUGIN_MAX_NUM = 16 };
static int rldb_plugins_num;
static struct rldb_loaded_plugin rldb_plugins[RLDB_PLUGIN_MAX_NUM];

#define ERR_R(t, args...) do { do_err_r(__FUNCTION__ , t , ##args); return -1; } while (0)
#define ERR_C(t, args...) do { do_err_r(__FUNCTION__ , t , ##args); goto _cleanup; } while (0)

/* these constants are for old text-based runlog */
#define RUN_MAX_IP_LEN 15
#define RUN_RECORD_SIZE 105
#define RUN_HEADER_SIZE 105

struct run_header_v1
{
  int    version;
  ej_time_t start_time;
  ej_time_t sched_time;
  ej_time_t duration;
  ej_time_t stop_time;
  unsigned char pad[44];
};

struct run_entry_v1
{
  rint32_t       submission;
  ej_time_t      timestamp;
  ej_size_t      size;
  ej_ip_t        ip;
  ruint32_t      sha1[5];
  rint32_t       team;
  rint32_t       problem;
  rint32_t       score;
  signed char    locale_id;
  unsigned char  language;
  unsigned char  status;
  signed char    test;
  unsigned char  is_imported;
  unsigned char  variant;
  unsigned char  is_hidden;
  unsigned char  is_readonly;
  unsigned char  pages;
  signed char    score_adj;     /* manual score adjustment */
  unsigned short judge_id;      /* judge required identifier */
  rint32_t       nsec;          /* nanosecond component of timestamp */
};

static int update_user_flags(runlog_state_t state);
static void build_indices(runlog_state_t state);
static struct user_entry *get_user_entry(runlog_state_t state, int user_id);

runlog_state_t
run_init(teamdb_state_t ts)
{
  runlog_state_t p;

  random_init();
  XCALLOC(p, 1);
  p->teamdb_state = ts;
  p->user_flags.nuser = -1;

  return p;
}

runlog_state_t
run_destroy(runlog_state_t state)
{
  int i;
  struct user_entry *ue;

  if (!state) return 0;

  xfree(state->runs); state->runs = 0;
  state->run_a = state->run_u = 0;
  for (i = 0; i < state->ut_size; i++) {
    if (!(ue = state->ut_table[i])) continue;
    xfree(ue);
  }
  xfree(state->ut_table);
  xfree(state->user_flags.flags);

  if (state->iface) state->iface->close(state->cnts);

  memset(state, 0, sizeof(*state));
  xfree(state);
  return 0;
}

int
run_set_runlog(
        runlog_state_t state,
        int total_entries,
        struct run_entry *entries)
{
  if (runlog_check(0, &state->head, total_entries, entries) < 0)
    return -1;

  if (state->iface->set_runlog(state->cnts, total_entries, entries) < 0)
    return -1;

  build_indices(state);
  return 0;
}

static void teamdb_update_callback(void *);

int
run_open(
        runlog_state_t state,
        struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        const unsigned char *plugin_name,
        int flags,
        time_t init_duration,
        time_t init_finish_time)
{
  int i;
  const struct xml_tree *p;
  const struct ejudge_plugin *plg;
  struct ejudge_plugin_iface *base_iface = 0;
  struct rldb_plugin_iface *rldb_iface = 0;
  struct rldb_plugin_data *plugin_data = 0;

  teamdb_register_update_hook(state->teamdb_state, teamdb_update_callback,
                              state);

  if (!rldb_plugins_num) {
    rldb_plugins[0].iface = &rldb_plugin_file;
    if (!(rldb_plugins[0].data = rldb_plugin_file.init())
        || rldb_plugin_file.prepare(rldb_plugins[0].data, config, 0) < 0) {
      err("cannot initialize `file' runlog plugin");
      return -1;
    }
    rldb_plugins_num++;
  }

  if (!plugin_name) {
    // use the default plugin
    if (global) plugin_name = global->rundb_plugin;
  }
  if (!plugin_name) plugin_name = "";

  if (!plugin_name[0] || !strcmp(plugin_name, "file")) {
    state->iface = rldb_plugins[0].iface;
    state->data = rldb_plugins[0].data;

    if (!(state->cnts = state->iface->open(state->data, state, config, cnts,
                                           global, flags,
                                           init_duration, init_finish_time)))
      return -1;
    runlog_check(0, &state->head, state->run_u, state->runs);
    build_indices(state);
    return 0;
  }

  // look up the table of loaded plugins
  for (i = 1; i < rldb_plugins_num; i++) {
    if (!strcmp(rldb_plugins[i].iface->b.name, plugin_name))
      break;
  }
  if (i < rldb_plugins_num) {
    state->iface = rldb_plugins[i].iface;
    state->data = rldb_plugins[i].data;
    if (!(state->cnts = state->iface->open(state->data, state, config, cnts,
                                           global, flags,
                                           init_duration, init_finish_time)))
      return -1;
    runlog_check(0, &state->head, state->run_u, state->runs);
    build_indices(state);
    return 0;
  }

  if (!config) {
    err("cannot load any plugin");
    return -1;
  }

  // find an appropriate plugin
  for (p = config->plugin_list; p; p = p->right) {
    plg = (const struct ejudge_plugin*) p;
    if (plg->load_flag && !strcmp(plg->type, "rldb")
        && !strcmp(plg->name, plugin_name))
      break;
  }
  if (!p) {
    err("runlog plugin `%s' is not registered", plugin_name);
    return -1;
  }
  if (rldb_plugins_num == RLDB_PLUGIN_MAX_NUM) {
    err("too many runlog plugins already loaded");
    return -1;
  }
  plugin_set_directory(config->plugin_dir);
  if (!(base_iface = plugin_load(plg->path, plg->type, plg->name))) {
    err("cannot load plugin `%s'", plg->name);
    return -1;
  }
  rldb_iface = (struct rldb_plugin_iface*) base_iface;
  if (base_iface->size != sizeof(*rldb_iface)) {
    err("plugin `%s' size mismatch", plg->name);
    return -1;
  }
  if (rldb_iface->rldb_version != RLDB_PLUGIN_IFACE_VERSION) {
    err("plugin `%s' version mismatch", plg->name);
    return -1;
  }
  if (!(plugin_data = rldb_iface->init())) {
    err("plugin `%s' initialization failed", plg->name);
    return -1;
  }
  if (rldb_iface->prepare(plugin_data, config, plg->data) < 0) {
    err("plugin %s failed to parse its configuration", plg->name);
    return -1;
  }

  rldb_plugins[rldb_plugins_num].iface = rldb_iface;
  rldb_plugins[rldb_plugins_num].data = plugin_data;
  rldb_plugins_num++;

  state->iface = rldb_iface;
  state->data = plugin_data;
  if (!(state->cnts = state->iface->open(state->data, state, config, cnts,
                                         global, flags,
                                         init_duration, init_finish_time)))
    return -1;
  runlog_check(0, &state->head, state->run_u, state->runs);
  build_indices(state);
  return 0;
}

int
run_backup(runlog_state_t state, const unsigned char *path)
{
  return state->iface->backup(state->cnts);
}

int
runlog_flush(runlog_state_t state)
{
  return state->iface->flush(state->cnts);
}

int
run_add_record(
        runlog_state_t state,
        time_t         timestamp,
        int            nsec,
        size_t         size,
        ruint32_t      sha1[5],
        ruint32_t      ip,
        int            ssl_flag,
        int            locale_id,
        int            team,
        int            problem,
        int            language,
        int            variant,
        int            is_hidden,
        int            mime_type)
{
  int i;
  struct user_entry *ue;
  time_t stop_time;

  if (timestamp <= 0) {
    err("run_add_record: invalid timestamp %ld", timestamp);
    return -1;
  }
  if (!is_hidden) {
    if (!state->head.start_time) {
      err("run_add_record: contest is not yet started");
      return -1;
    }
    if (timestamp < state->head.start_time) {
      err("run_add_record: timestamp < start_time");
      return -1;
    }
  }

  if (locale_id < -1 || locale_id > EJ_MAX_LOCALE_ID) {
    err("run_add_record: locale_id is out of range");
    return -1;
  }
  if (team <= 0 || team > EJ_MAX_USER_ID) {
    err("run_add_record: team is out of range");
    return -1;
  }
  if (language < 0 || language > EJ_MAX_LANG_ID) {
    err("run_add_record: language is out of range");
    return -1;
  }
  if (problem <= 0 || problem > EJ_MAX_PROB_ID) {
    err("run_add_record: problem is out of range");
    return -1;
  }
  if (variant < 0 || variant > EJ_MAX_VARIANT) {
    err("run_add_record: variant is out of range");
    return -1;
  }
  if (IS_INVALID_BOOL(is_hidden)) {
    err("run_add_record: is_hidden field value is invalid");
    return -1;
  }
  if (nsec < 0 || nsec > NSEC_MAX) {
    err("run_add_record: nsec field value %d is invalid", nsec);
    return -1;
  }
  if (mime_type < 0 || mime_type > EJ_MAX_MIME_TYPE) {
    err("run_add_record: mime_type field value %d is invalid", mime_type);
    return -1;
  }
  if (IS_INVALID_BOOL(ssl_flag)) {
    err("run_add_record: ssl_flag field value is invalid");
    return -1;
  }

  if (!is_hidden) {
    ue = get_user_entry(state, team);
    if (ue->status == V_VIRTUAL_USER) {
      if (!ue->start_time) {
        err("run_add_record: virtual contest not started");
        return -1;
      }
      if (timestamp < ue->start_time) {
        err("run_add_record: timestamp < virtual start time");
        return -1;
      }
      stop_time = ue->stop_time;
      if (!stop_time && state->head.duration)
        stop_time = ue->start_time + state->head.duration;
      if (stop_time && timestamp > stop_time) {
        err("run_add_record: timestamp > virtual stop time");
        return -1;
      }
    } else {
      stop_time = state->head.stop_time;
      if (!stop_time && state->head.duration)
        stop_time = state->head.start_time + state->head.duration;
      if (stop_time && timestamp > stop_time) {
        err("run_add_record: timestamp overrun");
        return -1;
      }
      ue->status = V_REAL_USER;
    }
  }

  if ((i = state->iface->get_insert_run_id(state->cnts,timestamp,team,nsec))<0)
    return -1;
  state->runs[i].size = size;
  state->runs[i].locale_id = locale_id;
  state->runs[i].user_id = team;
  state->runs[i].lang_id = language;
  state->runs[i].prob_id = problem;
  state->runs[i].status = 99;
  state->runs[i].test = 0;
  state->runs[i].score = -1;
  state->runs[i].a.ip = ip;
  state->runs[i].ssl_flag = ssl_flag;
  state->runs[i].variant = variant;
  state->runs[i].is_hidden = is_hidden;
  state->runs[i].mime_type = mime_type;
  if (sha1) {
    memcpy(state->runs[i].sha1, sha1, sizeof(state->runs[i].sha1));
  }
  if (state->iface->add_entry(state->cnts, i) < 0) return -1;
  return i;
}

int
run_undo_add_record(runlog_state_t state, int run_id)
{
  if (run_id < 0 || run_id >= state->run_u) {
    err("run_undo_add_record: invalid run_id");
    return -1;
  }
  return state->iface->undo_add_entry(state->cnts, run_id);
}

int
run_change_status(
        runlog_state_t state,
        int runid,
        int newstatus,
        int newtest,
        int newscore,
        int judge_id)
{
  if (runid < 0 || runid >= state->run_u) ERR_R("bad runid: %d", runid);
  if (newstatus < 0 || newstatus > 255) ERR_R("bad newstatus: %d", newstatus);
  if (newtest < -1) ERR_R("bad newtest: %d", newtest);
  if (newscore < -1 || newscore > EJ_MAX_SCORE)
    ERR_R("bad newscore: %d", newscore);
  if (judge_id < 0 || judge_id > EJ_MAX_JUDGE_ID)
    ERR_R("bad judge_id: %d", judge_id);

  if (newstatus == RUN_VIRTUAL_START || newstatus == RUN_VIRTUAL_STOP)
    ERR_R("virtual status cannot be changed that way");
  if (newstatus == RUN_EMPTY)
    ERR_R("EMPTY status cannot be set this way");
  if (state->runs[runid].status == RUN_VIRTUAL_START
      || state->runs[runid].status == RUN_VIRTUAL_STOP
      || state->runs[runid].status == RUN_EMPTY)
    ERR_R("this entry cannot be changed");

  if (state->runs[runid].is_readonly)
    ERR_R("this entry is read-only");

  return state->iface->change_status(state->cnts, runid, newstatus, newtest,
                                     newscore, judge_id);
}

int
run_get_status(runlog_state_t state, int runid)
{
  if (runid < 0 || runid >= state->run_u) ERR_R("bad runid: %d", runid);
  return state->runs[runid].status;
}

int
run_is_imported(runlog_state_t state, int runid)
{
  if (runid < 0 || runid >= state->run_u) ERR_R("bad runid: %d", runid);
  return state->runs[runid].is_imported;
}

int
run_start_contest(runlog_state_t state, time_t start_time)
{
  if (state->head.start_time) ERR_R("Contest already started");
  return state->iface->start(state->cnts, start_time);
}

int
run_stop_contest(runlog_state_t state, time_t stop_time)
{
  return state->iface->stop(state->cnts, stop_time);
}

int
run_set_duration(runlog_state_t state, time_t dur)
{
  return state->iface->set_duration(state->cnts, dur);
}

int
run_sched_contest(runlog_state_t state, time_t sched)
{
  return state->iface->schedule(state->cnts, sched);
}

int
run_set_finish_time(runlog_state_t state, time_t finish_time)
{
  return state->iface->set_finish_time(state->cnts, finish_time);
}

time_t
run_get_start_time(runlog_state_t state)
{
  return state->head.start_time;
}

time_t
run_get_stop_time(runlog_state_t state)
{
  return state->head.stop_time;
}

time_t
run_get_duration(runlog_state_t state)
{
  return state->head.duration;
}

time_t
run_get_finish_time(runlog_state_t state)
{
  return state->head.finish_time;
}

void
run_get_times(
        runlog_state_t state, 
        time_t *start,
        time_t *sched,
        time_t *dur,
        time_t *stop,
        time_t *p_finish_time)
{
  if (start) *start = state->head.start_time;
  if (sched) *sched = state->head.sched_time;
  if (dur)   *dur   = state->head.duration;
  if (stop)  *stop  = state->head.stop_time;
  if (p_finish_time) *p_finish_time = state->head.finish_time;
}

void
run_get_saved_times(
        runlog_state_t state,
        time_t *p_saved_duration,
        time_t *p_saved_stop_time,
        time_t *p_saved_finish_time)
{
  if (p_saved_duration) *p_saved_duration = state->head.saved_duration;
  if (p_saved_stop_time) *p_saved_stop_time = state->head.saved_stop_time;
  if (p_saved_finish_time) *p_saved_finish_time =state->head.saved_finish_time;
}

int
run_save_times(runlog_state_t state)
{
  if (state->head.saved_duration || state->head.saved_stop_time
      || state->head.saved_finish_time)
    return 0;
  return state->iface->save_times(state->cnts);
}

int
run_get_total(runlog_state_t state)
{
  return state->run_u;
}

void
run_get_team_usage(
        runlog_state_t state,
        int teamid,
        int *pn,
        size_t *ps)
{
  int i;
  int n = 0;
  size_t sz = 0;

  for (i = 0; i < state->run_u; i++) {
    if (state->runs[i].status == RUN_VIRTUAL_START
        || state->runs[i].status == RUN_VIRTUAL_STOP
        || state->runs[i].status == RUN_EMPTY)
      continue;
    if (state->runs[i].user_id == teamid) {
      sz += state->runs[i].size;
      n++;
    }
  }
  if (pn) *pn = n;
  if (ps) *ps = sz;
}

/* FIXME: VERY DUMB */
int
run_get_attempts(
        runlog_state_t state,
        int runid,
        int *pattempts,
        int *pdisqattempts,
        int skip_ce_flag)
{
  int i, n = 0, m = 0;

  *pattempts = 0;
  if (runid < 0 || runid >= state->run_u) ERR_R("bad runid: %d", runid);

  for (i = 0; i < runid; i++) {
    if (state->runs[i].status == RUN_VIRTUAL_START
        || state->runs[i].status == RUN_VIRTUAL_STOP
        || state->runs[i].status == RUN_EMPTY)
      continue;
    if (state->runs[i].user_id != state->runs[runid].user_id) continue;
    if (state->runs[i].prob_id != state->runs[runid].prob_id) continue;
    if (state->runs[i].status == RUN_COMPILE_ERR && skip_ce_flag) continue;
    if (state->runs[i].status == RUN_IGNORED) continue;
    if (state->runs[i].is_hidden) continue;
    if (state->runs[i].status == RUN_DISQUALIFIED) {
      m++;
    } else {
      n++;
    }
  }
  if (pattempts) *pattempts = n;
  if (pdisqattempts) *pdisqattempts = m;
  return 0;
}

int
run_count_all_attempts(runlog_state_t state, int user_id, int prob_id)
{
  int i, count = 0;

  for (i = 0; i < state->run_u; i++) {
    if (state->runs[i].status > RUN_MAX_STATUS
        && state->runs[i].status < RUN_TRANSIENT_FIRST) continue;
    if (state->runs[i].user_id != user_id
        || (prob_id > 0 && state->runs[i].prob_id != prob_id)) continue;
    count++;
  }
  return count;
}

/* FIXME: EVER DUMBER */
/*
 * if the specified run_id is OK run, how many successes were on the
 * same problem by other people before.
 * returns: -1 on error
 *          number of previous successes
 *          RUN_TOO_MANY (100000), if invisible or banned user or run
 */
int
run_get_prev_successes(runlog_state_t state, int run_id)
{
  int user_id, successes = 0, i, cur_uid;
  unsigned char *has_success = 0;

  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  if (state->runs[run_id].status !=RUN_OK) ERR_R("runid %d is not OK", run_id);

  // invisible run
  if (state->runs[run_id].is_hidden) return RUN_TOO_MANY;

  if (update_user_flags(state) < 0) return -1;

  // invalid, banned or invisible user
  user_id = state->runs[run_id].user_id;
  if (user_id <= 0 || user_id >= state->user_flags.nuser
      || state->user_flags.flags[user_id] < 0
      || (state->user_flags.flags[user_id] & TEAM_BANNED)
      || (state->user_flags.flags[user_id] & TEAM_INVISIBLE))
    return RUN_TOO_MANY;

  XALLOCAZ(has_success, state->user_flags.nuser);
  for (i = 0; i < run_id; i++) {
    if (state->runs[i].status != RUN_OK) continue;
    if (state->runs[i].is_hidden) continue;
    if (state->runs[i].prob_id != state->runs[run_id].prob_id) continue;
    cur_uid = state->runs[i].user_id;
    if (cur_uid <= 0 || cur_uid >= state->user_flags.nuser
        || state->user_flags.flags[cur_uid] < 0
        || (state->user_flags.flags[cur_uid] & TEAM_BANNED)
        || (state->user_flags.flags[cur_uid] & TEAM_INVISIBLE))
      continue;
    if (cur_uid == user_id) {
      // the user already had OK before
      return successes;
    }
    if (has_success[cur_uid]) continue;
    has_success[cur_uid] = 1;
    successes++;
  }
  return successes;
}

int
run_get_fog_period(
        runlog_state_t state,
        time_t cur_time,
        int fog_time,
        int unfog_time)
{
  time_t estimated_stop;
  time_t fog_start;

  ASSERT(cur_time);
  ASSERT(fog_time >= 0);
  ASSERT(unfog_time >= 0);

  if (!state->head.start_time) return -1;
  if (!fog_time || !state->head.duration) return 0;

  ASSERT(cur_time >= state->head.start_time);
  if (state->head.stop_time) {
    ASSERT(state->head.stop_time >= state->head.start_time);
    ASSERT(cur_time >= state->head.stop_time);
    if (cur_time > state->head.stop_time + unfog_time) return 2;
    return 1;
  } else {
    estimated_stop = state->head.start_time + state->head.duration;
    //ASSERT(cur_time <= estimated_stop);
    if (fog_time > state->head.duration) fog_time = state->head.duration;
    fog_start = estimated_stop - fog_time;
    if (cur_time >= fog_start) return 1;
    return 0;
  }
}

int
run_reset(runlog_state_t state, time_t new_duration, time_t new_finish_time)
{
  int i;

  for (i = 0; i < state->ut_size; i++)
    xfree(state->ut_table[i]);
  xfree(state->ut_table);
  state->ut_table = 0;
  state->ut_size = 0;

  return state->iface->reset(state->cnts, new_duration, new_finish_time);
}

int
run_check_duplicate(runlog_state_t state, int run_id)
{
  int i;
  struct run_entry *p, *q;

  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  p = &state->runs[run_id];
  for (i = run_id - 1; i >= 0; i--) {
    q = &state->runs[i];
    if (q->status == RUN_EMPTY || q->status == RUN_VIRTUAL_START
        || q->status == RUN_VIRTUAL_STOP)
      continue;
    if (p->size == q->size
        && p->a.ip == q->a.ip
        && p->sha1[0] == q->sha1[0]
        && p->sha1[1] == q->sha1[1]
        && p->sha1[2] == q->sha1[2]
        && p->sha1[3] == q->sha1[3]
        && p->sha1[4] == q->sha1[4]
        && p->user_id == q->user_id
        && p->prob_id == q->prob_id
        && p->lang_id == q->lang_id
        && p->variant == q->variant) {
      break;
    }
  }
  if (i < 0) return 0;
  if (state->iface->set_status(state->cnts, run_id, RUN_IGNORED) < 0)
    return -1;
  return i + 1;
}

int
run_find_duplicate(
        runlog_state_t state,
        int user_id,
        int prob_id,
        int lang_id,
        int variant,
        size_t size,
        ruint32_t sha1[])
{
  int i;
  const struct run_entry *q;

  if (!state->run_u) return -1;

  for (i = state->run_u - 1; i >= 0; i--) {
    q = &state->runs[i];
    if (q->status == RUN_EMPTY || q->status == RUN_VIRTUAL_START
        || q->status == RUN_VIRTUAL_STOP)
      continue;
    if (q->user_id == user_id
        && q->prob_id == prob_id
        && q->variant == variant) {
      if (q->lang_id == lang_id
          && q->size == size
          && q->sha1[0] == sha1[0]
          && q->sha1[1] == sha1[1]
          && q->sha1[2] == sha1[2]
          && q->sha1[3] == sha1[3]
          && q->sha1[4] == sha1[4])
        return i;
      return -1;
    }
  }
  return -1;
}

void
run_get_accepted_set(
        runlog_state_t state,
        int user_id,
        int accepting_mode,
        int max_prob,
        unsigned char *acc_set)
{
  int i;
  const struct run_entry *q;

  if (accepting_mode) {
    for (i = 0; i < state->run_u; i++) {
      q = &state->runs[i];
      if ((q->status == RUN_OK || q->status == RUN_ACCEPTED
           || q->status == RUN_PARTIAL)
          && q->user_id == user_id && q->prob_id > 0 && q->prob_id <= max_prob)
        acc_set[q->prob_id] = 1;
    }
  } else {
    for (i = 0; i < state->run_u; i++) {
      q = &state->runs[i];
      if (q->status == RUN_OK && q->user_id == user_id
          && q->prob_id > 0 && q->prob_id <= max_prob)
        acc_set[q->prob_id] = 1;
    }
  }
}

void
run_get_header(runlog_state_t state, struct run_header *out)
{
  memcpy(out, &state->head, sizeof(state->head));
}

void
run_get_all_entries(runlog_state_t state, struct run_entry *out)
{
  memcpy(out, state->runs, sizeof(out[0]) * state->run_u);
}

const struct run_entry *
run_get_entries_ptr(runlog_state_t state)
{
  return state->runs;
}

int
run_get_entry(runlog_state_t state, int run_id, struct run_entry *out)
{
  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  memcpy(out, &state->runs[run_id], sizeof(*out));
  return 0;
}

int
run_get_virtual_start_entry(
        runlog_state_t state,
        int user_id,
        struct run_entry *out)
{
  int i;

  for (i = 0; i < state->run_u; i++)
    if (state->runs[i].status == RUN_VIRTUAL_START
        && state->runs[i].user_id == user_id)
      break;
  if (i >= state->run_u) return -1;
  if (out) memcpy(out, &state->runs[i], sizeof(*out));
  return i;
}

int
run_set_entry(
        runlog_state_t state,
        int run_id,
        unsigned int mask,
        const struct run_entry *in)
{
  struct run_entry *out;
  struct run_entry te;
  int f = 0;
  struct user_entry *ue = 0;
  time_t stop_time;

  ASSERT(in);
  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  out = &state->runs[run_id];
  ASSERT(out->run_id == run_id);

  ASSERT(state->head.start_time >= 0);
  if (!out->is_hidden && !state->head.start_time) {
    err("run_set_entry: %d: the contest is not started", run_id);
    return -1;
  }

  /* refuse to edit some kind of entries */
  if (out->status == RUN_VIRTUAL_START || out->status == RUN_VIRTUAL_STOP) {
    err("run_set_entry: %d: virtual contest start/stop cannot be edited",
        run_id);
    return -1;
  }
  if (out->status == RUN_EMPTY) {
    err("run_set_entry: %d: empty entry cannot be edited", run_id);
    return -1;
  }

  if (out->is_readonly && mask != RUN_ENTRY_READONLY) {
    err("run_set_entry: %d: this entry is read-only", run_id);
    return -1;
  }

  /* blindly update all fields */
  memcpy(&te, out, sizeof(te));
  if ((mask & RUN_ENTRY_STATUS) && te.status != in->status) {
    te.status = in->status;
    f = 1;
  }
  if ((mask & RUN_ENTRY_TIME) && te.time != in->time) {
    te.time = in->time;
    f = 1;
  }
  if ((mask & RUN_ENTRY_NSEC) && te.nsec != in->nsec) {
    te.nsec = in->nsec;
    f = 1;
  }
  if ((mask & RUN_ENTRY_SIZE) && te.size != in->size) {
    te.size = in->size;
    f = 1;
  }
  if ((mask & RUN_ENTRY_IP) && te.a.ip != in->a.ip) {
    te.a.ip = in->a.ip;
    f = 1;
  }
  if ((mask&RUN_ENTRY_SHA1) && memcmp(te.sha1,in->sha1,sizeof(te.sha1))) {
    memcpy(te.sha1, in->sha1, sizeof(te.sha1));
    f = 1;
  }
  if ((mask & RUN_ENTRY_USER) && te.user_id != in->user_id) {
    te.user_id = in->user_id;
    f = 1;
  }
  if ((mask & RUN_ENTRY_PROB) && te.prob_id != in->prob_id) {
    te.prob_id = in->prob_id;
    f = 1;
  }
  if ((mask & RUN_ENTRY_LANG) && te.lang_id != in->lang_id) {
    te.lang_id = in->lang_id;
    f = 1;
  }
  if ((mask & RUN_ENTRY_LOCALE) && te.locale_id != in->locale_id) {
    te.locale_id = in->locale_id;
    f = 1;
  }
  if ((mask & RUN_ENTRY_TEST) && te.test != in->test) {
    te.test = in->test;
    f = 1;
  }
  if ((mask & RUN_ENTRY_SCORE) && te.score != in->score) {
    te.score = in->score;
    f = 1;
  }
  if ((mask & RUN_ENTRY_IMPORTED) && te.is_imported != in->is_imported) {
    te.is_imported = in->is_imported;
    f = 1;
  }
  if ((mask & RUN_ENTRY_VARIANT) && te.variant != in->variant) {
    te.variant = in->variant;
    f = 1;
  }
  if ((mask & RUN_ENTRY_HIDDEN) && te.is_hidden != in->is_hidden) {
    te.is_hidden = in->is_hidden;
    f = 1;
  }
  if ((mask & RUN_ENTRY_READONLY) && te.is_readonly != in->is_readonly) {
    te.is_readonly = in->is_readonly;
    f = 1;
  }
  if ((mask & RUN_ENTRY_PAGES) && te.pages != in->pages) {
    te.pages = in->pages;
    f = 1;
  }
  if ((mask & RUN_ENTRY_SCORE_ADJ) && te.score_adj != in->score_adj) {
    te.score_adj = in->score_adj;
    f = 1;
  }
  if ((mask & RUN_ENTRY_EXAMINABLE) && te.is_examinable != in->is_examinable) {
    te.is_examinable = in->is_examinable;
    f = 1;
  }

  /* check consistency of a new record */
  if (te.status == RUN_VIRTUAL_START || te.status == RUN_VIRTUAL_STOP
      || te.status == RUN_EMPTY) {
      err("run_set_entry: %d: special status cannot be set this way", run_id);
      return -1;
  }
  if (te.status > RUN_TRANSIENT_LAST
      || (te.status > RUN_PSEUDO_LAST && te.status < RUN_TRANSIENT_FIRST)
      || (te.status > RUN_MAX_STATUS && te.status < RUN_PSEUDO_FIRST)) {
    err("run_set_entry: %d: invalid status %d", run_id, te.status);
    return -1;
  }
  if (te.user_id <= 0 || te.user_id > EJ_MAX_USER_ID) {
    err("run_set_entry: %d: invalid team %d", run_id, te.user_id);
    return -1;
  }

  if (!te.is_hidden) {
    ue = get_user_entry(state, te.user_id);
    if (ue->status == V_VIRTUAL_USER) {
      ASSERT(ue->start_time > 0);
      stop_time = ue->stop_time;
      if (!stop_time && state->head.duration > 0)
        stop_time = ue->start_time + state->head.duration;
      if (te.time < ue->start_time) {
        err("run_set_entry: %d: timestamp < virtual start_time", run_id);
        return -1;
      }
      if (stop_time && te.time > stop_time) {
        err("run_set_entry: %d: timestamp > virtual stop_time", run_id);
        return -1;
      }
    } else {
      stop_time = state->head.stop_time;
      if (!stop_time && state->head.duration > 0)
        stop_time = state->head.start_time + state->head.duration;
      if (te.time < state->head.start_time) {
        err("run_set_entry: %d: timestamp < start_time", run_id);
        return -1;
      }
      if (stop_time && te.time > stop_time) {
        err("run_set_entry: %d: timestamp > stop_time", run_id);
        return -1;
      }
    }
  }

  if (te.size > RUNLOG_MAX_SIZE) {
    err("run_set_entry: %d: size %u is invalid", run_id, te.size);
    return -1;
  }
  if (te.prob_id <= 0 || te.prob_id > EJ_MAX_PROB_ID) {
    err("run_set_entry: %d: problem %d is invalid", run_id, te.prob_id);
    return -1;
  }
  if (te.score < -1 || te.score > EJ_MAX_SCORE) {
    err("run_set_entry: %d: score %d is invalid", run_id, te.score);
    return -1;
  }
  if (te.locale_id < -1 || te.locale_id > EJ_MAX_LOCALE_ID) {
    err("run_set_entry: %d: locale_id %d is invalid", run_id, te.locale_id);
    return -1;
  }
  /*
  if (te.lang_id <= 0 || te.lang_id >= 255) {
    err("run_set_entry: %d: language %d is invalid", run_id, te.lang_id);
    return -1;
  }
  */
  if (te.test < -1) {
    err("run_set_entry: %d: test %d is invalid", run_id, te.test);
    return -1;
  }
  if (IS_INVALID_BOOL(te.is_imported)) {
    err("run_set_entry: %d: is_imported %d is invalid", run_id,te.is_imported);
    return -1;
  }
  if (IS_INVALID_BOOL(te.is_hidden)) {
    err("run_set_entry: %d: is_hidden %d is invalid", run_id, te.is_hidden);
    return -1;
  }
  if (te.is_imported && te.is_hidden) {
    err("run_set_entry: %d: is_hidden and is_imported both cannot be set",
        run_id);
    return -1;
  }
  if (IS_INVALID_BOOL(te.is_readonly)) {
    err("run_set_entry: %d: is_readonly %d is invalid", run_id,te.is_readonly);
    return -1;
  }
  if (te.nsec < 0 || te.nsec > NSEC_MAX) {
    err("run_set_entry: %d: nsec %d is invalid", run_id, te.nsec);
    return -1;
  }

  if (!f) return 0;

  if (!te.is_hidden && !ue->status) ue->status = V_REAL_USER;
  return state->iface->set_entry(state->cnts, run_id, &te);
}

static struct user_entry *
get_user_entry(runlog_state_t state, int user_id)
{
  ASSERT(user_id > 0);

  if (user_id >= state->ut_size) {
    struct user_entry **new_ut_table = 0;
    int new_ut_size = state->ut_size;

    if (!new_ut_size) new_ut_size = 16;
    while (new_ut_size <= user_id)
      new_ut_size *= 2;
    new_ut_table = xcalloc(new_ut_size, sizeof(new_ut_table[0]));
    if (state->ut_size > 0) {
      memcpy(new_ut_table, state->ut_table, state->ut_size * sizeof(state->ut_table[0]));
    }
    state->ut_size = new_ut_size;
    xfree(state->ut_table);
    state->ut_table = new_ut_table;
    info("runlog: ut_table is extended to %d", state->ut_size);
  }

  if (!state->ut_table[user_id]) {
    state->ut_table[user_id] = xcalloc(1, sizeof(state->ut_table[user_id][0]));
  }
  return state->ut_table[user_id];
}

time_t
run_get_virtual_start_time(runlog_state_t state, int user_id)
{
  struct user_entry *pvt = get_user_entry(state, user_id);
  if (pvt->status == V_REAL_USER) return state->head.start_time;
  return pvt->start_time;
}

time_t
run_get_virtual_stop_time(runlog_state_t state, int user_id, time_t cur_time)
{
  struct user_entry *pvt = get_user_entry(state, user_id);
  if (!pvt->start_time) return 0;
  if (!cur_time) return pvt->stop_time;
  if (pvt->status == V_REAL_USER) return state->head.stop_time;
  if (pvt->status != V_VIRTUAL_USER) return 0;
  if (!state->head.duration || pvt->stop_time) return pvt->stop_time;
  if (pvt->start_time + state->head.duration < cur_time) {
    pvt->stop_time = pvt->start_time + state->head.duration;
  }
  return pvt->stop_time;
}

int
run_get_virtual_status(runlog_state_t state, int user_id)
{
  struct user_entry *pvt = get_user_entry(state, user_id);
  return pvt->status;
}

int
run_virtual_start(
        runlog_state_t state,
        int user_id,
        time_t t,
        ej_ip_t ip,
        int ssl_flag,
        int nsec)
{
  struct user_entry *pvt = get_user_entry(state, user_id);
  int i;

  if (!state->head.start_time) {
    err("run_virtual_start: the contest is not started");
    return -1;
  }
  ASSERT(state->head.start_time > 0);
  if (t < state->head.start_time) {
    err("run_virtual_start: timestamp < start_time");
    return -1;
  }
  if (pvt->status == V_REAL_USER) {
    err("run_virtual_start: user %d is not virtual", user_id);
    return -1;
  }
  if (pvt->status == V_VIRTUAL_USER) {
    err("run_virtual_start: virtual contest for %d already started", user_id);
    return -1;
  }
  if (nsec < 0 || nsec > NSEC_MAX) {
    err("run_virtual_start: nsec field value %d is invalid", nsec);
    return -1;
  }
  if ((i = state->iface->get_insert_run_id(state->cnts, t, user_id, nsec)) < 0)
    return -1;
  state->runs[i].user_id = user_id;
  state->runs[i].a.ip = ip;
  state->runs[i].ssl_flag = ssl_flag;
  state->runs[i].status = RUN_VIRTUAL_START;
  pvt->start_time = t;
  pvt->status = V_VIRTUAL_USER;
  return state->iface->add_entry(state->cnts, i);
}

int
run_virtual_stop(
        runlog_state_t state,
        int user_id,
        time_t t,
        ej_ip_t ip,
        int ssl_flag,
        int nsec)
{
  struct user_entry *pvt = get_user_entry(state, user_id);
  int i;
  time_t exp_stop_time = 0;

  if (!state->head.start_time) {
    err("run_virtual_stop: the contest is not started");
    return -1;
  }
  ASSERT(state->head.start_time > 0);
  if (t < state->head.start_time) {
    err("run_virtual_stop: timestamp < start_time");
    return -1;
  }
  if (pvt->status != V_VIRTUAL_USER) {
    err("run_virtual_stop: user %d is not virtual", user_id);
    return -1;
  }
  ASSERT(pvt->start_time > 0);
  if (pvt->stop_time) {
    err("run_virtual_stop: virtual contest for %d already stopped", user_id);
    return -1;
  }
  if (state->head.duration > 0) exp_stop_time = pvt->start_time + state->head.duration;
  if (t > exp_stop_time) {
    err("run_virtual_stop: the virtual time ended");
    return -1;
  }

  if ((i = state->iface->get_insert_run_id(state->cnts, t, user_id, nsec)) < 0)
    return -1;
  state->runs[i].user_id = user_id;
  state->runs[i].a.ip = ip;
  state->runs[i].ssl_flag = ssl_flag;
  state->runs[i].status = RUN_VIRTUAL_STOP;
  pvt->stop_time = t;
  return state->iface->add_entry(state->cnts, i);
}

int
run_is_readonly(runlog_state_t state, int run_id)
{
  if (run_id < 0 || run_id >= state->run_u) return 1;
  return state->runs[run_id].is_readonly;
}

int
run_clear_entry(runlog_state_t state, int run_id)
{
  struct user_entry *ue;
  int i;

  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  if (state->runs[run_id].is_readonly) ERR_R("run %d is readonly", run_id);
  switch (state->runs[run_id].status) {
  case RUN_EMPTY:
    memset(&state->runs[run_id], 0, sizeof(state->runs[run_id]));
    state->runs[run_id].status = RUN_EMPTY;
    state->runs[run_id].run_id = run_id;
    break;
  case RUN_VIRTUAL_STOP:
    /* VSTOP events can safely be cleared */ 
    ue = get_user_entry(state, state->runs[run_id].user_id);
    ASSERT(ue->status == V_VIRTUAL_USER);
    ASSERT(ue->start_time > 0);
    ue->stop_time = 0;
    break;
  case RUN_VIRTUAL_START:
    /* VSTART event must be the only event of this team */
    for (i = 0; i < state->run_u; i++) {
      if (i == run_id) continue;
      if (state->runs[i].status == RUN_EMPTY) continue;
      if (state->runs[i].user_id == state->runs[run_id].user_id) break;
    }
    if (i < state->run_u) {
      err("run_clear_entry: VSTART must be the only record for a team");
      return -1;
    }
    ue = get_user_entry(state, state->runs[run_id].user_id);
    ASSERT(ue->status == V_VIRTUAL_USER);
    ASSERT(ue->start_time == state->runs[run_id].time);
    ASSERT(!ue->stop_time);
    ue->status = 0;
    ue->start_time = 0;
    break;
  default:
    /* maybe update indices */
    break;
  }
  return state->iface->clear_entry(state->cnts, run_id);
}

int
run_forced_clear_entry(runlog_state_t state, int run_id)
{
  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  return state->iface->clear_entry(state->cnts, run_id);
}

int
run_forced_set_hidden(runlog_state_t state, int run_id)
{
  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  return state->iface->set_hidden(state->cnts, run_id, 1);
}

int
run_forced_set_judge_id(runlog_state_t state, int run_id, int judge_id)
{
  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  if (judge_id < 0 || judge_id > EJ_MAX_JUDGE_ID)
    ERR_R("bad judge_id: %d", judge_id);
  return state->iface->set_judge_id(state->cnts, run_id, judge_id);
}

int
run_has_transient_user_runs(runlog_state_t state, int user_id)
{
  int i;

  for (i = state->run_u - 1; i >= 0; i--) {
    if (state->runs[i].status == RUN_EMPTY) continue;
    if (state->runs[i].user_id != user_id) continue;
    if (state->runs[i].status == RUN_VIRTUAL_START) return 0;
    if (state->runs[i].status >= RUN_TRANSIENT_FIRST
        && state->runs[i].status <= RUN_TRANSIENT_LAST)
      return 1;
  }
  return 0;
}

int
run_squeeze_log(runlog_state_t state)
{
  return state->iface->squeeze(state->cnts);
}

int
run_write_xml(
        runlog_state_t state,
        void *serve_state,
        const struct contest_desc *cnts,
        FILE *f,
        int export_mode,
        int source_mode,
        time_t current_time)
{
  //int i;

  if (!state->head.start_time) {
    err("Contest is not yet started");
    return -1;
  }

  unparse_runlog_xml(serve_state, cnts, f, &state->head, state->run_u,
                     state->runs, export_mode, source_mode, current_time);
  return 0;
}

static void
check_msg(int is_err, FILE *flog, const char *format, ...)
  __attribute__((format(printf,3,4)));
static void
check_msg(int is_err, FILE *flog, const char *format, ...)
{
  va_list args;
  unsigned char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  if (is_err) {
    err("%s", buf);
    if (flog) fprintf(flog, "Error: %s\n", buf);
  } else {
    info("%s", buf);
    if (flog) fprintf(flog, "%s\n", buf);
  }
}

int
runlog_check(
        FILE *ferr,
        const struct run_header *phead,
        size_t nentries,
        const struct run_entry *pentries)
{
  int i, j;
  int max_team_id;
  struct user_entry *ventries, *v;
  const struct run_entry *e;
  int nerr = 0;
  struct run_entry te;
  unsigned char *pp;
  time_t prev_time = 0;
  time_t stop_time = 0, v_stop_time;
  int retcode = 0;
  int prev_nsec = 0;

  ASSERT(phead);

  if (phead->start_time < 0) {
    check_msg(1, ferr,"Start time %lld is before the epoch",phead->start_time);
    return -1;
  }
  if (phead->stop_time < 0) {
    check_msg(1,ferr, "Stop time %lld is before the epoch", phead->stop_time);
    return -1;
  }
  if (phead->duration < -1) {
    check_msg(1,ferr, "Contest duration %lld is negative", phead->duration);
    return -1;
  }
  if (!phead->start_time && phead->stop_time) {
    check_msg(1,ferr, "Contest start time is not set, but stop time is set!");
    return -1;
  }
  if (phead->start_time && phead->stop_time
      && phead->start_time > phead->stop_time) {
    check_msg(1,ferr, "Contest stop time %lld is less than start time %lld",
              phead->stop_time, phead->start_time);
    return -1;
  }
  if (!nentries) {
    check_msg(0,ferr, "The runlog is empty");
    return 0;
  }
  /*
  if (!phead->start_time) {
    check_msg(1,ferr, "Start time is not set, but runs present");
    return -1;
  }
  */

  /* check local consistency of fields */
  for (i = 0; i < nentries; i++) {
    e = &pentries[i];
    if (e->status > RUN_TRANSIENT_LAST
        || (e->status > RUN_PSEUDO_LAST && e->status < RUN_TRANSIENT_FIRST)
        || (e->status > RUN_MAX_STATUS && e->status < RUN_PSEUDO_FIRST)) {
      check_msg(1,ferr, "Run %d invalid status %d", i, e->status);
      nerr++;
      continue;
    }

    if (e->status == RUN_EMPTY) {
      if (i > 0 && !e->run_id) {
        check_msg(0,ferr, "Run %d submission for EMPTY is not set", i);
        //e->run_id = i;
      } else if (e->run_id != i) {
        check_msg(1,ferr, "Run %d submission %d does not match index",
                  i, e->run_id);
        //e->run_id = i;
        retcode = 1;
        //nerr++;
        //continue;
      }
      /* kinda paranoia */
      memcpy(&te, e, sizeof(te));
      te.run_id = 0;
      te.status = 0;
      pp = (unsigned char *) &te;
      for (j = 0; j < sizeof(te) && !pp[j]; j++);
      if (j < sizeof(te)) {
        check_msg(1,ferr, "Run %d is EMPTY and contain garbage", i);
        nerr++;
        continue;
      }
      continue;
    }

    if (e->run_id != i) {
      check_msg(1,ferr, "Run %d submission %d does not match index",
                i, e->run_id);
      //e->run_id = i;
      retcode = 1;
      //nerr++;
      //continue;
    }
    if (e->user_id <= 0) {
      check_msg(1,ferr, "Run %d team %d is invalid", i, e->user_id);
      nerr++;
      continue;
    }
    if (e->time < 0) {
      check_msg(1, ferr, "Run %d timestamp %lld is negative", i, e->time);
      nerr++;
      continue;
    }
    if (!e->time) {
      check_msg(1, ferr, "Run %d timestamp is not set", i);
      nerr++;
      continue;
    }
    if (e->time < prev_time) {
      check_msg(1, ferr, "Run %d timestamp %lld is less than previous %ld",
                i, e->time, prev_time);
      nerr++;
      continue;
    }
    if (e->time == prev_time && e->nsec < prev_nsec) {
      check_msg(1, ferr, "Run %d nsec %d is less than previous %d",
                i, e->nsec, prev_nsec);
    }
    prev_time = e->time;
    prev_nsec = e->nsec;

    if (e->status == RUN_VIRTUAL_START || e->status == RUN_VIRTUAL_STOP) {
      /* kinda paranoia */
      memcpy(&te, e, sizeof(te));
      te.run_id = 0;
      te.status = 0;
      te.user_id = 0;
      te.time = 0;
      te.nsec = 0;
      te.a.ip = 0;
      te.ssl_flag = 0;
      te.ipv6_flag = 0;
      te.judge_id = 0;
      pp = (unsigned char *) &te;
      for (j = 0; j < sizeof(te) && !pp[j]; j++);
      if (j < sizeof(te)) {
        check_msg(1,ferr, "Run %d is virtual and contain garbage at byte %d",
                  i, j);
        nerr++;
      }
      continue;
    }

    /* a regular or transient run */
    if (e->size > RUNLOG_MAX_SIZE) {
      check_msg(1, ferr, "Run %d has huge size %zu", i, (size_t) e->size);
      nerr++;
      continue;
    }
    if (!e->a.ip) {
      check_msg(0, ferr, "Run %d IP is not set", i);
    }
    if (!e->sha1[0]&&!e->sha1[1]&&!e->sha1[2]&&!e->sha1[3]&&!e->sha1[4]) {
      //check_msg(0, ferr, "Run %d SHA1 is not set", i);
    }
    if (e->prob_id <= 0) {
      check_msg(1, ferr, "Run %d problem %d is invalid", i, e->prob_id);
      nerr++;
      continue;
    }
    if (e->prob_id > EJ_MAX_PROB_ID) {
      check_msg(1, ferr, "Run %d problem %d is too large", i, e->prob_id);
      nerr++;
      continue;
    }
    if (e->score < -1) {
      check_msg(1, ferr, "Run %d score %d is invalid", i, e->score);
      nerr++;
      continue;
    }
    if (e->score > EJ_MAX_SCORE) {
      check_msg(1, ferr, "Run %d score %d is too large", i, e->score);
      nerr++;
      continue;
    }
    if (e->locale_id < -1) {
      check_msg(1, ferr, "Run %d locale_id %d is invalid", i, e->locale_id);
      nerr++;
      continue;
    }
    /*
    if (e->lang_id == 0 || e->lang_id == 255) {
      check_msg(1, ferr, "Run %d language %d is invalid", i, e->lang_id);
      nerr++;
      continue;
    }
    */
    if (e->test < -1) {
      check_msg(1, ferr, "Run %d test %d is invalid", i, e->test);
      nerr++;
      continue;
    }
    if (IS_INVALID_BOOL(e->is_imported)) {
      check_msg(1,ferr, "Run %d is_imported %d is invalid", i, e->is_imported);
      nerr++;
      continue;
    }
    if (IS_INVALID_BOOL(e->is_readonly)) {
      check_msg(1,ferr, "Run %d is_readonly %d is invalid",i,e->is_readonly);
      nerr++;
      continue;
    }
    if (e->nsec < 0 || e->nsec > NSEC_MAX) {
      check_msg(1,ferr, "Run %d nsec %d is invalid", i, e->nsec);
      nerr++;
      continue;
    }
  } /* end of local consistency check */

  /* do not continue check in case of errors */
  if (nerr > 0) return -1;

  max_team_id = -1;
  for (i = 0; i < nentries; i++) {
    if (pentries[i].status == RUN_EMPTY) continue;
    if (pentries[i].user_id > max_team_id) max_team_id = pentries[i].user_id;
  }
  if (max_team_id == -1) {
    check_msg(0,ferr, "The runlog contains only EMPTY records");
    return 0;
  }
  ventries = alloca((max_team_id + 1) * sizeof(ventries[0]));
  memset(ventries, 0, (max_team_id + 1) * sizeof(ventries[0]));

  stop_time = phead->stop_time;
  if (!stop_time && phead->start_time && phead->duration) {
    // this may be in future
    stop_time = phead->start_time + phead->duration;
  }

  for (i = 0; i < nentries; i++) {
    e = &pentries[i];
    if (e->is_hidden) continue;
    switch (e->status) {
    case RUN_EMPTY: break;
    case RUN_VIRTUAL_START:
      ASSERT(e->user_id <= max_team_id);
      v = &ventries[e->user_id];
      if (v->status == V_VIRTUAL_USER) {
        ASSERT(v->start_time > 0);
        check_msg(1, ferr, "Run %d: duplicated VSTART", i);
        nerr++;
        continue;
      } else if (v->status == V_REAL_USER) {
        ASSERT(!v->start_time);
        ASSERT(!v->stop_time);
        check_msg(1, ferr, "Run %d: VSTART for non-virtual user", i);
        nerr++;
        continue;
      } else {
        ASSERT(!v->start_time);
        v->status = V_VIRTUAL_USER;
        v->start_time = e->time;
      }
      break;
    case RUN_VIRTUAL_STOP:
      ASSERT(e->user_id <= max_team_id);
      v = &ventries[e->user_id];
      ASSERT(v->status >= 0 && v->status <= V_LAST);
      if (v->status == V_VIRTUAL_USER) {
        ASSERT(v->start_time > 0);
        ASSERT(v->stop_time >= 0);
        if (v->stop_time) {
          check_msg(1, ferr, "Run %d: duplicated VSTOP", i);
          nerr++;
          continue;
        }
        if (phead->duration
            && e->time > v->start_time + phead->duration) {
          check_msg(1, ferr, "Run %d: VSTOP after expiration of contest", i);
          nerr++;
          continue;
        }
        v->stop_time = e->time;
      } else {
        ASSERT(!v->start_time);
        ASSERT(!v->stop_time);
        ASSERT(v->status == 0 || v->status == V_REAL_USER);
        check_msg(1, ferr, "Run %d: unexpected VSTOP without VSTART", i);
        nerr++;
        continue;
      }
      break;
    default:
      ASSERT(e->user_id <= max_team_id);
      v = &ventries[e->user_id];
      ASSERT(v->status >= 0 && v->status <= V_LAST);
      if (v->status == V_VIRTUAL_USER) {
        ASSERT(v->start_time > 0);
        ASSERT(v->stop_time >= 0);
        v_stop_time = v->stop_time;
        if (!v_stop_time && phead->duration)
          v_stop_time = v->start_time + phead->duration;
        if (e->time < v->start_time) {
          check_msg(1, ferr,
                    "Run %d timestamp %lld is less that virtual start %d",
                    i, e->time, v->start_time);
          nerr++;
          continue;
        }
        if (v_stop_time && e->time > v_stop_time) {
          check_msg(1, ferr,
                    "Run %d timestamp %lld is greater than virtual stop %ld",
                    i, e->time, v_stop_time);
          nerr++;
          continue;
        }
      } else {
        ASSERT(!v->start_time);
        ASSERT(!v->stop_time);
        ASSERT(v->status == 0 || v->status == V_REAL_USER);
        if (e->time < phead->start_time) {
          check_msg(1,ferr,
                    "Run %d timestamp %lld is less than contest start %lld",
                    i, e->time, phead->start_time);
          nerr++;
          continue;
        }
        if (stop_time && e->time > stop_time) {
          check_msg(1, ferr,
                    "Run %d timestamp %lld is greater than contest stop %ld",
                    i, e->time, stop_time);
          nerr++;
          continue;
        }
        v->status = V_REAL_USER;
      }
      break;
    }
  }

  if (nerr > 0) return -1;

  return retcode;
}

static void
build_indices(runlog_state_t state)
{
  int i;
  int max_team_id = -1;
  struct user_entry *ue;

  if (state->ut_table) {
    for (i = 0; i < state->ut_size; i++)
      xfree(state->ut_table[i]);
    xfree(state->ut_table);
    state->ut_table = 0;
  }
  state->ut_size = 0;
  state->ut_table = 0;

  /* assume, that the runlog is consistent
   * scan the whole runlog and build various indices
   */
  for (i = 0; i < state->run_u; i++) {
    if (state->runs[i].status == RUN_EMPTY) continue;
    ASSERT(state->runs[i].user_id > 0);
    if (state->runs[i].user_id > max_team_id) max_team_id = state->runs[i].user_id;
  }
  if (max_team_id <= 0) return;

  state->ut_size = 128;
  while (state->ut_size <= max_team_id)
    state->ut_size *= 2;

  XCALLOC(state->ut_table, state->ut_size);
  for (i = 0; i < state->run_u; i++) {
    if (state->runs[i].is_hidden) continue;
    switch (state->runs[i].status) {
    case RUN_EMPTY:
      break;
    case RUN_VIRTUAL_START:
      ue = get_user_entry(state, state->runs[i].user_id);
      ASSERT(!ue->status);
      ue->status = V_VIRTUAL_USER;
      ue->start_time = state->runs[i].time;
      break;
    case RUN_VIRTUAL_STOP:
      ue = get_user_entry(state, state->runs[i].user_id);
      ASSERT(ue->status == V_VIRTUAL_USER);
      ASSERT(ue->start_time > 0);
      ue->stop_time = state->runs[i].time;
      break;
    default:
      ue = get_user_entry(state, state->runs[i].user_id);
      if (!ue->status) ue->status = V_REAL_USER;
      break;
    }
  }
}

int
run_get_pages(runlog_state_t state, int run_id)
{
  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  return state->runs[run_id].pages;
}

int
run_set_pages(runlog_state_t state, int run_id, int pages)
{
  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  if (pages < 0 || pages > 255) ERR_R("bad pages: %d", pages);
  return state->iface->set_pages(state->cnts, run_id, pages);
}

int
run_get_total_pages(runlog_state_t state, int user_id)
{
  int i, total = 0;

  if (user_id <= 0 || user_id > EJ_MAX_USER_ID) ERR_R("bad user_id: %d", user_id);
  for (i = 0; i < state->run_u; i++) {
    if (state->runs[i].status == RUN_VIRTUAL_START || state->runs[i].status == RUN_VIRTUAL_STOP
        || state->runs[i].status == RUN_EMPTY) continue;
    if (state->runs[i].user_id != user_id) continue;
    total += state->runs[i].pages;
  }
  return total;
}

int
run_find(
        runlog_state_t state,
        int first_run,
        int last_run,
        int team_id,
        int prob_id,
        int lang_id)
{
  int i;

  if (!state->run_u) return -1;

  if (first_run < 0) first_run = state->run_u + first_run;
  if (first_run < 0) first_run = 0;
  if (first_run >= state->run_u) first_run = state->run_u - 1;

  if (last_run < 0) last_run = state->run_u + last_run;
  if (last_run < 0) last_run = 0;
  if (last_run >= state->run_u) last_run = state->run_u - 1;

  if (first_run <= last_run) {
    for (i = first_run; i <= last_run; i++) {
      if (team_id && team_id != state->runs[i].user_id) continue;
      if (prob_id && prob_id != state->runs[i].prob_id) continue;
      if (lang_id && lang_id != state->runs[i].lang_id) continue;
      return i;
    }
  } else {
    for (i = first_run; i >= last_run; i--) {
      if (team_id && team_id != state->runs[i].user_id) continue;
      if (prob_id && prob_id != state->runs[i].prob_id) continue;
      if (lang_id && lang_id != state->runs[i].lang_id) continue;
      return i;
    }
  }
  return -1;
}

static void
teamdb_update_callback(void *user_ptr)
{
  // invalidate user_flags
  runlog_state_t state = (runlog_state_t) user_ptr;
  xfree(state->user_flags.flags);
  memset(&state->user_flags, 0, sizeof(state->user_flags));
  state->user_flags.nuser = -1;
}

static int
update_user_flags(runlog_state_t state)
{
  int size = 0;
  int *map = 0;

  if (state->user_flags.nuser >= 0) return 0;
  if (teamdb_get_user_status_map(state->teamdb_state, &size, &map) < 0)
    return -1;
  state->user_flags.nuser = size;
  state->user_flags.flags = map;
  return 1;
}

int
run_get_virtual_info(
        runlog_state_t state,
        int user_id,
        struct run_entry *vs,
        struct run_entry *ve)
{
  int count = 0, i, run_start = -1, run_end = -1, s;

  for (i = state->run_u; i >= 0; i--) {
    if ((s = state->runs[i].status) == RUN_EMPTY) continue;
    if (state->runs[i].user_id != user_id) continue;
    if (s >= RUN_TRANSIENT_FIRST && s <= RUN_TRANSIENT_LAST) {
      count++;
    } else if (s == RUN_VIRTUAL_START) {
      if (run_start >= 0) return -1;
      run_start = i;
    } else if (s == RUN_VIRTUAL_STOP) {
      if (run_end >= 0) return -1;
      run_end = i;
    }
  }

  if (run_start < 0 || run_end < 0) return -1;
  if (vs) memcpy(vs, &state->runs[run_start], sizeof(*vs));
  if (ve) memcpy(ve, &state->runs[run_end], sizeof(*ve));  
  return count;
}

int
run_count_examinable_runs(
        runlog_state_t state,
        int prob_id,
        int exam_num,
        int *p_assigned)
{
  int count = 0, i, assigned_count = 0, j;
  struct run_entry *p;

  ASSERT(exam_num >= 1 && exam_num <= 3);

  for (i = state->run_u; i >= 0; i--) {
    p = &state->runs[i];
    if (p->status > RUN_LAST) continue;
    if (!run_is_source_available(p->status)) continue;
    if (p->prob_id == prob_id && p->is_examinable) {
      count++;
      for (j = 0; j < exam_num; j++)
        if (p->examiners[j] <= 0)
          break;
      if (j == exam_num) assigned_count++;
    }
  }
  if (p_assigned) *p_assigned = assigned_count;
  return count;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
