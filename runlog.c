/* -*- c -*- */

/* Copyright (C) 2000-2015 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/runlog.h"
#include "ejudge/teamdb.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "unix/unix_fileutl.h"
#include "ejudge/xml_utils.h"
#include "ejudge/random.h"
#include "ejudge/runlog_state.h"
#include "ejudge/rldb_plugin.h"
#include "ejudge/prepare.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/win32_compat.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

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
  ej_ip4_t       ip;
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
static void build_indices(runlog_state_t state, int flags);
static struct user_entry *get_user_entry(runlog_state_t state, int user_id);
static struct user_entry *try_user_entry(runlog_state_t state, int user_id);
static void extend_run_extras(runlog_state_t state);
static void run_drop_uuid_hash(runlog_state_t state);
static int find_free_uuid_hash_index(runlog_state_t state, const ej_uuid_t *puuid);

runlog_state_t
run_init(teamdb_state_t ts)
{
  runlog_state_t p;

  random_init();
  XCALLOC(p, 1);
  p->teamdb_state = ts;
  p->user_flags.nuser = -1;

  p->max_user_id = -1;
  p->user_count = -1;

  p->uuid_hash_state = -1;

  return p;
}

runlog_state_t
run_destroy(runlog_state_t state)
{
  int i;
  struct user_entry *ue;

  if (!state) return 0;

  for (i = 0; i < state->ut_size; i++) {
    if (!(ue = state->ut_table[i])) continue;
    xfree(ue);
  }
  xfree(state->ut_table);
  xfree(state->user_flags.flags);
  xfree(state->run_extras);

  run_drop_uuid_hash(state);

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

  build_indices(state, 0);
  return 0;
}

static void teamdb_update_callback(void *);

int
run_open(
        runlog_state_t state,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        const unsigned char *plugin_name,
        int flags,
        time_t init_duration,
        time_t init_sched_time,
        time_t init_finish_time)
{
  const struct xml_tree *p;
  const struct ejudge_plugin *plg;
  const struct common_loaded_plugin *loaded_plugin;

  if (state->teamdb_state) {
    teamdb_register_update_hook(state->teamdb_state, teamdb_update_callback,
                                state);
  }

  if (!plugin_register_builtin(&rldb_plugin_file.b, config)) {
    err("cannot register default plugin");
    return -1;
  }

  if (!plugin_name) {
    // use the default plugin
    if (global) plugin_name = global->rundb_plugin;
  }
  if (!plugin_name) plugin_name = "";

  if (global && global->uuid_run_store > 0) {
    flags |= RUN_LOG_UUID_INDEX;
  }

  if (!plugin_name[0] || !strcmp(plugin_name, "file")) {
    if (!(loaded_plugin = plugin_get("rldb", "file"))) {
      err("cannot load default plugin");
      return -1;
    }
    state->iface = (struct rldb_plugin_iface*) loaded_plugin->iface;
    state->data = (struct rldb_plugin_data*) loaded_plugin->data;

    if (!(state->cnts = state->iface->open(state->data, state, config, cnts,
                                           global, flags,
                                           init_duration,
                                           init_sched_time,
                                           init_finish_time)))
      return -1;
    if (!(flags & RUN_LOG_NOINDEX)) {
      if (state->iface->check && state->iface->check(state->cnts, 0) < 0)
        return -1;
      if (runlog_check(0, &state->head, state->run_u, state->runs) < 0)
        return -1;
      build_indices(state, flags);
    }
    return 0;
  }

  // look up the table of loaded plugins
  if ((loaded_plugin = plugin_get("rldb", plugin_name))) {
    state->iface = (struct rldb_plugin_iface*) loaded_plugin->iface;
    state->data = (struct rldb_plugin_data*) loaded_plugin->data;

    if (!(state->cnts = state->iface->open(state->data, state, config, cnts,
                                           global, flags,
                                           init_duration,
                                           init_sched_time,
                                           init_finish_time)))
      return -1;
    if (!(flags & RUN_LOG_NOINDEX)) {
      if (state->iface->check && state->iface->check(state->cnts, 0) < 0)
        return -1;
      if (runlog_check(0, &state->head, state->run_u, state->runs) < 0)
        return -1;
      build_indices(state, flags);
    }
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

  loaded_plugin = plugin_load_external(plg->path, plg->type, plg->name, config);
  if (!loaded_plugin) {
    err("cannot load plugin %s, %s", plg->type, plg->name);
    return -1;
  }

  state->iface = (struct rldb_plugin_iface*) loaded_plugin->iface;
  state->data = (struct rldb_plugin_data*) loaded_plugin->data;

  if (!(state->cnts = state->iface->open(state->data, state, config, cnts,
                                         global, flags,
                                         init_duration,
                                         init_sched_time,
                                         init_finish_time)))
    return -1;
  if (!(flags & RUN_LOG_NOINDEX)) {
    if (state->iface->check && state->iface->check(state->cnts, 0) < 0)
      return -1;
    if (runlog_check(0, &state->head, state->run_u, state->runs) < 0)
      return -1;
    build_indices(state, flags);
  }
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
        const ruint32_t sha1[5],
        const ej_uuid_t *puuid,
        const ej_ip_t *pip,
        int            ssl_flag,
        int            locale_id,
        int            team,
        int            problem,
        int            language,
        int            eoln_type,
        int            variant,
        int            is_hidden,
        int            mime_type,
        int            store_flags)
{
  int i;
  struct user_entry *ue;
  time_t stop_time;
  struct run_entry re;
  int flags = 0;

  state->uuid_hash_last_added_index = -1;
  state->uuid_hash_last_added_run_id = -1;
  if (timestamp <= 0) {
    err("run_add_record: invalid timestamp %ld", (long) timestamp);
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

  ue = get_user_entry(state, team);
  ASSERT(ue);
  ASSERT(ue->run_id_valid > 0); // run index is ok

  if (!is_hidden) {
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

  memset(&re, 0, sizeof(re));
  re.size = size;
  re.locale_id = locale_id;
  re.user_id = team;
  re.lang_id = language;
  re.eoln_type = eoln_type;
  re.prob_id = problem;
  re.status = 99;
  re.test = 0;
  re.score = -1;
  ipv6_to_run_entry(pip, &re);
  re.ssl_flag = ssl_flag;
  re.variant = variant;
  re.is_hidden = is_hidden;
  re.mime_type = mime_type;
  re.store_flags = store_flags;
  flags = RE_SIZE | RE_LOCALE_ID | RE_USER_ID | RE_LANG_ID | RE_PROB_ID | RE_STATUS | RE_TEST | RE_SCORE | RE_IP | RE_SSL_FLAG | RE_VARIANT | RE_IS_HIDDEN | RE_MIME_TYPE | RE_EOLN_TYPE | RE_STORE_FLAGS;
  if (sha1) {
    memcpy(re.sha1, sha1, sizeof(state->runs[i].sha1));
    flags |= RE_SHA1;
  }
#if CONF_HAS_LIBUUID - 0 != 0
  if (!puuid) {
    ej_uuid_t tmp_uuid;
    ej_uuid_generate(&tmp_uuid);
    memcpy(&re.run_uuid, &tmp_uuid, sizeof(ej_uuid_t));
    flags |= RE_RUN_UUID;
  } else {
    memcpy(&re.run_uuid, puuid, sizeof(ej_uuid_t));
    flags |= RE_RUN_UUID;
  }
#endif

  int uuid_hash_index = -1;
  if (state->uuid_hash_state >= 0) {
    if (!re.run_uuid.v[0] && !re.run_uuid.v[1] && !re.run_uuid.v[2] && !re.run_uuid.v[3]) {
      err("run_add_record: UUID is NULL");
      return -1;
    }
    uuid_hash_index = find_free_uuid_hash_index(state, &re.run_uuid);
    if (uuid_hash_index < 0) {
      err("run_add_record: failed to find UUID hash index");
      return -1;
    }
  }

  if (state->max_user_id >= 0 && re.user_id > state->max_user_id) {
    state->max_user_id = re.user_id;
  }
  state->user_count = -1;

  if (state->iface->add_entry(state->cnts, i, &re, flags) < 0) return -1;

  // updating user_id index
  extend_run_extras(state);
  if (i == state->run_u - 1) {
    // inserting at the last position
    state->run_extras[i].prev_user_id = ue->run_id_last;
    state->run_extras[i].next_user_id = -1;
    if (ue->run_id_last < 0) {
      ue->run_id_first = i;
    } else {
      state->run_extras[ue->run_id_last].next_user_id = i;
    }
    ue->run_id_last = i;
  } else {
    // inserting somewhere in the middle
    ue->run_id_valid = 0;
    state->run_extras[i].prev_user_id = -1;
    state->run_extras[i].next_user_id = -1;
    // increase run_id for runs inserted after the given
    if (state->uuid_hash_state > 0) {
      for (int i = 0; i < state->uuid_hash_size; ++i) {
        if (state->uuid_hash[i].run_id >= i) {
          ++state->uuid_hash[i].run_id;
        }
      }
    }
  }

  if (uuid_hash_index >= 0) {
    state->uuid_hash[uuid_hash_index].run_id = i;
    memcpy(&state->uuid_hash[uuid_hash_index].uuid, &re.run_uuid, sizeof(re.run_uuid));
    state->uuid_hash_last_added_index = uuid_hash_index;
    state->uuid_hash_last_added_run_id = i;
    ++state->uuid_hash_used;
  }

  return i;
}

int
run_undo_add_record(runlog_state_t state, int run_id)
{
  if (run_id < 0 || run_id >= state->run_u) {
    err("run_undo_add_record: invalid run_id");
    return -1;
  }
  state->user_count = -1;
  struct user_entry *ue = try_user_entry(state, state->runs[run_id].user_id);
  if (ue) {
    ue->run_id_valid = 0;
  }
  if (state->uuid_hash_state > 0) {
    if (state->uuid_hash_last_added_run_id == run_id) {
      state->uuid_hash[state->uuid_hash_last_added_index].run_id = -1;
      memset(&state->uuid_hash[state->uuid_hash_last_added_index].uuid, 0, sizeof(ej_uuid_t));
      --state->uuid_hash_used;
    } else {
      run_drop_uuid_hash(state);
    }
    state->uuid_hash_last_added_run_id = -1;
    state->uuid_hash_last_added_index = -1;
  }
  return state->iface->undo_add_entry(state->cnts, run_id);
}

int
run_change_status(
        runlog_state_t state,
        int runid,
        int newstatus,
        int newtest,
        int newpassedmode,
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
                                     newpassedmode, newscore, judge_id);
}

int
run_change_status_2(
        runlog_state_t state,
        int runid,
        int newstatus,
        int newtest,
        int newpassedmode,
        int newscore,
        int judge_id,
        int is_marked)
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

  return state->iface->change_status_2(state->cnts, runid, newstatus, newtest,
                                       newpassedmode, newscore, judge_id, is_marked);
}

int
run_change_status_3(
        runlog_state_t state,
        int runid,
        int newstatus,
        int newtest,
        int newpassedmode,
        int newscore,
        int judge_id,
        int is_marked,
        int has_user_score,
        int user_status,
        int user_tests_passed,
        int user_score)
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

  return state->iface->change_status_3(state->cnts, runid, newstatus, newtest,
                                       newpassedmode, newscore, judge_id, is_marked,
                                       has_user_score, user_status,
                                       user_tests_passed, user_score);
}

int
run_change_status_4(
        runlog_state_t state,
        int runid,
        int newstatus)
{
  if (runid < 0 || runid >= state->run_u) ERR_R("bad runid: %d", runid);
  if (newstatus < 0 || newstatus > 255) ERR_R("bad newstatus: %d", newstatus);

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

  return state->iface->change_status_4(state->cnts, runid, newstatus);
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
        int user_id,
        int *pn,
        size_t *ps)
{
  int n = 0;
  size_t sz = 0;

  struct user_entry *ue = get_user_entry(state, user_id);
  ASSERT(ue);
  ASSERT(ue->run_id_valid > 0); // run index is ok

  for (int run_id = ue->run_id_first; run_id >= 0; run_id = state->run_extras[run_id].next_user_id) {
    ASSERT(run_id < state->run_u);
    ASSERT(state->runs[run_id].user_id == user_id);
    if (state->runs[run_id].status != RUN_VIRTUAL_START && state->runs[run_id].status != RUN_VIRTUAL_STOP) {
      sz += state->runs[run_id].size;
      n++;
    }
  }

  if (pn) *pn = n;
  if (ps) *ps = sz;
}

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
  if (pdisqattempts) *pdisqattempts = 0;

  if (runid < 0 || runid >= state->run_u) ERR_R("bad runid: %d", runid);
  const struct run_entry *sample_re = &state->runs[runid];
  if (sample_re->status >= RUN_PSEUDO_FIRST && sample_re->status <= RUN_PSEUDO_LAST) {
    return 0;
  }

  struct user_entry *ue = get_user_entry(state, sample_re->user_id);
  ASSERT(ue);
  ASSERT(ue->run_id_valid > 0); // run index is ok

  // FIXME: use user_id+prob_id index

  for (i = ue->run_id_first; i >= 0; i = state->run_extras[i].next_user_id) {
    ASSERT(i < state->run_u);
    const struct run_entry *re = &state->runs[i];
    ASSERT(re->user_id == sample_re->user_id);
    if (i >= runid) break;

    if (re->status == RUN_VIRTUAL_START || re->status == RUN_VIRTUAL_STOP) continue;
    if (re->prob_id != sample_re->prob_id) continue;
    if ((re->status == RUN_COMPILE_ERR || re->status == RUN_STYLE_ERR || re->status == RUN_REJECTED)
        && skip_ce_flag) continue;
    if (re->status == RUN_IGNORED) continue;
    if (re->is_hidden) continue;
    if (re->status == RUN_DISQUALIFIED) {
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

  struct user_entry *ue = get_user_entry(state, user_id);
  ASSERT(ue);
  ASSERT(ue->run_id_valid > 0); // run index is ok

  // FIXME: use user_id+prob_id index

  for (i = ue->run_id_first; i >= 0; i = state->run_extras[i].next_user_id) {
    ASSERT(i < state->run_u);
    const struct run_entry *re = &state->runs[i];
    ASSERT(re->user_id == user_id);
    if (re->status > RUN_MAX_STATUS && re->status < RUN_TRANSIENT_FIRST) continue;
    if (prob_id <= 0 || re->prob_id == prob_id) {
      ++count;
    }
  }
  ASSERT(i == -1);

  return count;
}

int
run_count_all_attempts_2(runlog_state_t state, int user_id, int prob_id, int ignored_set)
{
  int i, count = 0;

  struct user_entry *ue = get_user_entry(state, user_id);
  ASSERT(ue);
  ASSERT(ue->run_id_valid > 0); // run index is ok

  for (i = ue->run_id_first; i >= 0; i = state->run_extras[i].next_user_id) {
    ASSERT(i < state->run_u);
    const struct run_entry *re = &state->runs[i];
    ASSERT(re->user_id == user_id);
    if (re->status > RUN_MAX_STATUS && re->status < RUN_TRANSIENT_FIRST) continue;
    if (re->status <= RUN_MAX_STATUS && ((1 << re->status) & ignored_set)) continue;
    if (prob_id <= 0 || re->prob_id == prob_id) {
      ++count;
    }
  }
  ASSERT(i == -1);

  return count;
}

int
run_count_tokens(runlog_state_t state, int user_id, int prob_id)
{
  int i, count = 0;

  struct user_entry *ue = get_user_entry(state, user_id);
  ASSERT(ue);
  ASSERT(ue->run_id_valid > 0); // run index is ok

  for (i = ue->run_id_first; i >= 0; i = state->run_extras[i].next_user_id) {
    ASSERT(i < state->run_u);
    const struct run_entry *re = &state->runs[i];
    ASSERT(re->user_id == user_id);
    if (prob_id <= 0 || re->prob_id == prob_id) {
      count += re->token_count;
    }
  }
  ASSERT(i == -1);

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
run_reset(
        runlog_state_t state,
        time_t init_duration,
        time_t init_sched_time,
        time_t init_finish_time)
{
  int i;

  for (i = 0; i < state->ut_size; i++)
    xfree(state->ut_table[i]);
  xfree(state->ut_table);
  state->ut_table = 0;
  state->ut_size = 0;
  state->max_user_id = -1;
  state->user_count = -1;
  xfree(state->run_extras);
  state->run_extras = NULL;
  state->run_extra_u = 0;
  state->run_extra_a = 0;

  run_drop_uuid_hash(state);

  return state->iface->reset(state->cnts, init_duration, init_sched_time,
                             init_finish_time);
}

int
run_check_duplicate(runlog_state_t state, int run_id)
{
  int i;
  const struct run_entry *p, *q;

  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  p = &state->runs[run_id];

  struct user_entry *ue = get_user_entry(state, p->user_id);
  (void) ue;
  ASSERT(ue);
  ASSERT(ue->run_id_valid > 0); // run index is ok

  // FIXME: use user_id+prob_id index

  for (i = state->run_extras[run_id].prev_user_id; i >= 0; i = state->run_extras[i].prev_user_id) {
    ASSERT(i < state->run_u);
    q = &state->runs[i];
    ASSERT(q->user_id == p->user_id);
    if (q->status == RUN_VIRTUAL_START || q->status == RUN_VIRTUAL_STOP)
      continue;
    if (p->size == q->size
        && p->a.ip == q->a.ip
        && p->sha1[0] == q->sha1[0]
        && p->sha1[1] == q->sha1[1]
        && p->sha1[2] == q->sha1[2]
        && p->sha1[3] == q->sha1[3]
        && p->sha1[4] == q->sha1[4]
        && p->prob_id == q->prob_id
        && p->lang_id == q->lang_id
        && p->variant == q->variant) {
      break;
    }
  }
  ASSERT(i >= -1);

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

  struct user_entry *ue = get_user_entry(state, user_id);
  ASSERT(ue);
  ASSERT(ue->run_id_valid > 0); // run index is ok

  // FIXME: use user_id+prob_id index

  for (i = ue->run_id_last; i >= 0; i = state->run_extras[i].prev_user_id) {
    ASSERT(i < state->run_u);
    q = &state->runs[i];
    ASSERT(q->user_id == user_id);
    if (q->status == RUN_VIRTUAL_START || q->status == RUN_VIRTUAL_STOP)
      continue;
    if (q->prob_id == prob_id && q->variant == variant) {
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
  ASSERT(i == -1);

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

  struct user_entry *ue = get_user_entry(state, user_id);
  ASSERT(ue);
  ASSERT(ue->run_id_valid > 0); // run index is ok

  for (i = ue->run_id_first; i >= 0; i = state->run_extras[i].next_user_id) {
    ASSERT(i < state->run_u);
    q = &state->runs[i];
    ASSERT(q->user_id == user_id);

    if (accepting_mode) {
      if ((q->status == RUN_OK || q->status == RUN_ACCEPTED || q->status == RUN_PARTIAL)
          && q->prob_id > 0 && q->prob_id <= max_prob)
        acc_set[q->prob_id] = 1;
    } else {
      if (q->status == RUN_OK && q->prob_id > 0 && q->prob_id <= max_prob)
        acc_set[q->prob_id] = 1;
    }
  }
  ASSERT(i == -1);
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
  const struct run_entry *out;
  struct run_entry te;
  int f = 0;
  struct user_entry *ue = 0;
  time_t stop_time;
  int old_user_id = 0;

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

  if (out->is_readonly && mask != RE_IS_READONLY) {
    err("run_set_entry: %d: this entry is read-only", run_id);
    return -1;
  }

  /* blindly update all fields */
  memcpy(&te, out, sizeof(te));
  old_user_id = out->user_id;
  if ((mask & RE_STATUS) && te.status != in->status) {
    te.status = in->status;
    f = 1;
  }
  if ((mask & RE_SIZE) && te.size != in->size) {
    te.size = in->size;
    f = 1;
  }
  if ((mask & RE_IP) && te.a.ip != in->a.ip) {
    te.a.ip = in->a.ip;
    f = 1;
  }
  if ((mask & RE_SHA1) && memcmp(te.sha1,in->sha1,sizeof(te.sha1))) {
    memcpy(te.sha1, in->sha1, sizeof(te.sha1));
    f = 1;
  }
  if ((mask & RE_RUN_UUID) && memcmp(&te.run_uuid, &in->run_uuid, sizeof(te.run_uuid))) {
    if (state->uuid_hash_state >= 0) {
      err("run_set_entry: %d: change of 'uuid' is not permitted", run_id);
      return -1;
    }
    memcpy(&te.run_uuid, &in->run_uuid, sizeof(te.run_uuid));
    f = 1;
  }
  if ((mask & RE_USER_ID) && te.user_id != in->user_id) {
    te.user_id = in->user_id;
    f = 1;
    state->max_user_id = -1;
    state->user_count = -1;
  }
  if ((mask & RE_PROB_ID) && te.prob_id != in->prob_id) {
    te.prob_id = in->prob_id;
    f = 1;
  }
  if ((mask & RE_LANG_ID) && te.lang_id != in->lang_id) {
    te.lang_id = in->lang_id;
    f = 1;
  }
  if ((mask & RE_LOCALE_ID) && te.locale_id != in->locale_id) {
    te.locale_id = in->locale_id;
    f = 1;
  }
  if ((mask & RE_TEST) && te.test != in->test) {
    te.test = in->test;
    f = 1;
  }
  if ((mask & RE_SCORE) && te.score != in->score) {
    te.score = in->score;
    f = 1;
  }
  if ((mask & RE_IS_IMPORTED) && te.is_imported != in->is_imported) {
    te.is_imported = in->is_imported;
    f = 1;
  }
  if ((mask & RE_VARIANT) && te.variant != in->variant) {
    te.variant = in->variant;
    f = 1;
  }
  if ((mask & RE_IS_HIDDEN) && te.is_hidden != in->is_hidden) {
    te.is_hidden = in->is_hidden;
    f = 1;
  }
  if ((mask & RE_IS_READONLY) && te.is_readonly != in->is_readonly) {
    te.is_readonly = in->is_readonly;
    f = 1;
  }
  if ((mask & RE_PAGES) && te.pages != in->pages) {
    te.pages = in->pages;
    f = 1;
  }
  if ((mask & RE_SCORE_ADJ) && te.score_adj != in->score_adj) {
    te.score_adj = in->score_adj;
    f = 1;
  }
  /*
  if ((mask & RE_IS_EXAMINABLE) && te.is_examinable != in->is_examinable) {
    te.is_examinable = in->is_examinable;
    f = 1;
  }
  */
  if ((mask & RE_IS_MARKED) && te.is_marked != in->is_marked) {
    te.is_marked = in->is_marked;
    f = 1;
  }
  if ((mask & RE_IS_SAVED) && te.is_saved != in->is_saved) {
    te.is_saved = in->is_saved;
    f = 1;
  }
  if ((mask & RE_SAVED_STATUS) && te.saved_status != in->saved_status) {
    te.saved_status = in->saved_status;
    f = 1;
  }
  if ((mask & RE_SAVED_SCORE) && te.saved_score != in->saved_score) {
    te.saved_score = in->saved_score;
    f = 1;
  }
  if ((mask & RE_SAVED_TEST) && te.saved_test != in->saved_test) {
    te.saved_test = in->saved_test;
    f = 1;
  }
  if ((mask & RE_PASSED_MODE) && te.passed_mode != in->passed_mode) {
    te.passed_mode = in->passed_mode;
    f = 1;
  }
  if ((mask & RE_EOLN_TYPE) && te.eoln_type != in->eoln_type) {
    te.eoln_type = in->eoln_type;
    f = 1;
  }
  if ((mask & RE_STORE_FLAGS) && te.store_flags != in->store_flags) {
    te.store_flags = in->store_flags;
    f = 1;
  }
  if ((mask & RE_TOKEN_FLAGS) && te.token_flags != in->token_flags) {
    te.token_flags = in->token_flags;
    f = 1;
  }
  if ((mask & RE_TOKEN_COUNT) && te.token_count != in->token_count) {
    te.token_count = in->token_count;
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
  if (IS_INVALID_BOOL_2(te.is_imported)) {
    err("run_set_entry: %d: is_imported %d is invalid", run_id,te.is_imported);
    return -1;
  }
  if (IS_INVALID_BOOL_2(te.is_hidden)) {
    err("run_set_entry: %d: is_hidden %d is invalid", run_id, te.is_hidden);
    return -1;
  }
  if (te.is_imported && te.is_hidden) {
    err("run_set_entry: %d: is_hidden and is_imported both cannot be set",
        run_id);
    return -1;
  }
  if (IS_INVALID_BOOL_2(te.is_readonly)) {
    err("run_set_entry: %d: is_readonly %d is invalid", run_id,te.is_readonly);
    return -1;
  }
  if (te.nsec < 0 || te.nsec > NSEC_MAX) {
    err("run_set_entry: %d: nsec %d is invalid", run_id, te.nsec);
    return -1;
  }

  if (!f) return 0;

  if (!te.is_hidden && !ue->status) ue->status = V_REAL_USER;
  if (state->iface->set_entry(state->cnts, run_id, &te, mask) < 0) return -1;
  if (state->runs[run_id].user_id != old_user_id) {
    if ((ue = try_user_entry(state, old_user_id))) {
      ue->run_id_valid = 0;
    }
    if ((ue = try_user_entry(state, state->runs[run_id].user_id))) {
      ue->run_id_valid = 0;
    }
  }
  return 0;
}

static void
extend_run_extras(runlog_state_t state)
{
  if (state->run_extra_u == state->run_u) return;
  if (state->run_extra_u > state->run_u) {
    state->run_extra_u = state->run_u;
    return;
  }
  if (state->run_u <= state->run_extra_a) {
    state->run_extra_u = state->run_u;
    return;
  }
  int new_a = state->run_extra_a * 2;
  if (!new_a) new_a = 32;
  while (new_a < state->run_u) new_a *= 2;
  struct run_entry_extra *new_x = calloc(new_a, sizeof(new_x[0]));
  if (state->run_extra_u > 0) {
    memcpy(new_x, state->run_extras, state->run_extra_u * sizeof(new_x[0]));
  }
  xfree(state->run_extras); state->run_extras = new_x;
  state->run_extra_a = new_a;
  state->run_extra_u = state->run_u;
}

static const unsigned char valid_user_run_statuses[256] =
{
  [RUN_OK]                  = 1,
  [RUN_COMPILE_ERR]         = 1,
  [RUN_RUN_TIME_ERR]        = 1,
  [RUN_TIME_LIMIT_ERR]      = 1,
  [RUN_PRESENTATION_ERR]    = 1,
  [RUN_WRONG_ANSWER_ERR]    = 1,
  [RUN_CHECK_FAILED]        = 1,
  [RUN_PARTIAL]             = 1,
  [RUN_ACCEPTED]            = 1,
  [RUN_IGNORED]             = 1,
  [RUN_DISQUALIFIED]        = 1,
  [RUN_PENDING]             = 1,
  [RUN_MEM_LIMIT_ERR]       = 1,
  [RUN_SECURITY_ERR]        = 1,
  [RUN_STYLE_ERR]           = 1,
  [RUN_WALL_TIME_LIMIT_ERR] = 1,
  [RUN_PENDING_REVIEW]      = 1,
  [RUN_REJECTED]            = 1,
  [RUN_SKIPPED]             = 0,

  [RUN_VIRTUAL_START]       = 1,
  [RUN_VIRTUAL_STOP]        = 1,
  [RUN_EMPTY]               = 0,

  [RUN_FULL_REJUDGE]        = 0,
  [RUN_RUNNING]             = 1,
  [RUN_COMPILED]            = 1,
  [RUN_COMPILING]           = 1,
  [RUN_AVAILABLE]           = 1,
  [RUN_REJUDGE]             = 1,
  [RUN_TRANSIENT_LAST]      = 1,
};

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

  // check user indices and rebuild them, if necessary
  struct user_entry *ut = state->ut_table[user_id];
  if (ut->run_id_valid <= 0) {
    info("runlog: rebuilding indices for user_id %d", user_id);
    ut->run_id_first = -1;
    ut->run_id_last = -1;

    if (state->run_extra_u != state->run_u) {
      extend_run_extras(state);
    }

    for (int run_id = 0; run_id < state->run_u; ++run_id) {
      const struct run_entry *re = &state->runs[run_id];
      if (valid_user_run_statuses[re->status] && re->user_id == user_id) {
        // append to the double-linked list
        state->run_extras[run_id].prev_user_id = ut->run_id_last;
        state->run_extras[run_id].next_user_id = -1;
        if (ut->run_id_first < 0) {
          ut->run_id_first = run_id;
        }
        if (ut->run_id_last >= 0) {
          state->run_extras[ut->run_id_last].next_user_id = run_id;
        }
        ut->run_id_last = run_id;
      }
    }

    ut->run_id_valid = 1;
  }

  return ut;
}

static struct user_entry *
try_user_entry(runlog_state_t state, int user_id)
{
  if (user_id <= 0 || user_id >= state->ut_size) return NULL;
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
        const ej_ip_t *pip,
        int ssl_flag,
        int nsec)
{
  struct user_entry *pvt = get_user_entry(state, user_id);
  int i;
  struct run_entry re;

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

  memset(&re, 0, sizeof(re));
  re.user_id = user_id;
  ipv6_to_run_entry(pip, &re);
  re.ssl_flag = ssl_flag;
  re.status = RUN_VIRTUAL_START;
  pvt->start_time = t;
  pvt->status = V_VIRTUAL_USER;

  if (state->max_user_id >= 0 && user_id > state->max_user_id) {
    state->max_user_id = user_id;
  }
  state->user_count = -1;

  if ((i = state->iface->add_entry(state->cnts, i, &re, RE_USER_ID | RE_IP | RE_SSL_FLAG | RE_STATUS)) < 0) return -1;
  struct user_entry *ue = try_user_entry(state, user_id);
  if (ue) ue->run_id_valid = 0;
  return i;
}

int
run_virtual_stop(
        runlog_state_t state,
        int user_id,
        time_t t,
        const ej_ip_t *pip,
        int ssl_flag,
        int nsec)
{
  struct user_entry *pvt = get_user_entry(state, user_id);
  int i;
  time_t exp_stop_time = 0;
  struct run_entry re;

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
  memset(&re, 0, sizeof(re));
  re.user_id = user_id;
  ipv6_to_run_entry(pip, &re);
  re.ssl_flag = ssl_flag;
  re.status = RUN_VIRTUAL_STOP;
  pvt->stop_time = t;

  if (state->max_user_id >= 0 && user_id > state->max_user_id) {
    state->max_user_id = user_id;
  }
  state->user_count = -1;

  if ((i = state->iface->add_entry(state->cnts, i, &re, RE_USER_ID | RE_IP | RE_SSL_FLAG | RE_STATUS)) < 0) return -1;
  struct user_entry *ue = try_user_entry(state, user_id);
  if (ue) ue->run_id_valid = 0;
  return i;
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
    // FIXME: use index
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

  if ((ue = try_user_entry(state, state->runs[run_id].user_id))) {
    ue->run_id_valid = 0;
  }
  state->max_user_id = -1;
  state->user_count = -1;

  return state->iface->clear_entry(state->cnts, run_id);
}

int
run_forced_clear_entry(runlog_state_t state, int run_id)
{
  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);

  struct user_entry *ue;
  if ((ue = try_user_entry(state, state->runs[run_id].user_id))) {
    ue->run_id_valid = 0;
  }
  state->max_user_id = -1;
  state->user_count = -1;

  return state->iface->clear_entry(state->cnts, run_id);
}

int
run_set_hidden(runlog_state_t state, int run_id)
{
  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  return state->iface->set_hidden(state->cnts, run_id, 1);
}

int
run_set_judge_id(runlog_state_t state, int run_id, int judge_id)
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

  struct user_entry *ue = get_user_entry(state, user_id);
  ASSERT(ue);
  ASSERT(ue->run_id_valid > 0); // run index is ok

  for (i = ue->run_id_first; i >= 0; i = state->run_extras[i].next_user_id) {
    ASSERT(i < state->run_u);
    const struct run_entry *re = &state->runs[i];
    ASSERT(re->user_id == user_id);
    if (re->status == RUN_EMPTY) continue;
    if (re->status == RUN_VIRTUAL_START) return 0;
    if (re->status >= RUN_TRANSIENT_FIRST && re->status <= RUN_TRANSIENT_LAST)
      return 1;
  }
  ASSERT(i == -1);

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
  struct user_entry *ventries = NULL, *v;
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
    check_msg(1, ferr,"Start time %" EJ_PRINTF_LLSPEC "d is before the epoch",phead->start_time);
    return -1;
  }
  if (phead->stop_time < 0) {
    check_msg(1,ferr, "Stop time %" EJ_PRINTF_LLSPEC "d is before the epoch", phead->stop_time);
    return -1;
  }
  if (phead->duration < -1) {
    check_msg(1,ferr, "Contest duration %" EJ_PRINTF_LLSPEC "d is negative", phead->duration);
    return -1;
  }
  if (!phead->start_time && phead->stop_time) {
    check_msg(1,ferr, "Contest start time is not set, but stop time is set!");
    return -1;
  }
  if (phead->start_time && phead->stop_time
      && phead->start_time > phead->stop_time) {
    check_msg(1,ferr, "Contest stop time %" EJ_PRINTF_LLSPEC "d is less than start time %" EJ_PRINTF_LLSPEC "d",
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
      te.time = 0;
      te.nsec = 0;
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
      check_msg(1, ferr, "Run %d timestamp %" EJ_PRINTF_LLSPEC "d is negative", i, e->time);
      nerr++;
      continue;
    }
    if (!e->time) {
      check_msg(1, ferr, "Run %d timestamp is not set", i);
      nerr++;
      continue;
    }
    if (e->time < prev_time) {
      check_msg(1, ferr, "Run %d timestamp %" EJ_PRINTF_LLSPEC "d is less than previous %ld",
                i, e->time, (long) prev_time);
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
      check_msg(1, ferr, "Run %d has huge size %" EJ_PRINTF_ZSPEC "u", i, EJ_PRINTF_ZCAST((size_t) e->size));
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
    if (IS_INVALID_BOOL_2(e->is_imported)) {
      check_msg(1,ferr, "Run %d is_imported %d is invalid", i, e->is_imported);
      nerr++;
      continue;
    }
    if (IS_INVALID_BOOL_2(e->is_readonly)) {
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
    ASSERT(pentries[i].user_id >= 0);
    if (pentries[i].user_id > max_team_id) max_team_id = pentries[i].user_id;
  }
  if (max_team_id == -1) {
    check_msg(0,ferr, "The runlog contains only EMPTY records");
    return 0;
  }
  XCALLOC(ventries, max_team_id + 1);

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
                    "Run %d timestamp %" EJ_PRINTF_LLSPEC "d is less that virtual start %ld",
                    i, e->time, (long) v->start_time);
          nerr++;
          continue;
        }
        if (v_stop_time && e->time > v_stop_time) {
          check_msg(1, ferr,
                    "Run %d timestamp %" EJ_PRINTF_LLSPEC "d is greater than virtual stop %ld",
                    i, e->time, (long) v_stop_time);
          nerr++;
          continue;
        }
      } else {
        ASSERT(!v->start_time);
        ASSERT(!v->stop_time);
        ASSERT(v->status == 0 || v->status == V_REAL_USER);
        if (e->time < phead->start_time) {
          check_msg(1,ferr,
                    "Run %d timestamp %" EJ_PRINTF_LLSPEC "d is less than contest start %" EJ_PRINTF_LLSPEC "d",
                    i, e->time, phead->start_time);
          nerr++;
          continue;
        }
        if (stop_time && e->time > stop_time) {
          check_msg(1, ferr,
                    "Run %d timestamp %" EJ_PRINTF_LLSPEC "d is greater than contest stop %ld",
                    i, e->time, (long) stop_time);
          nerr++;
          continue;
        }
        v->status = V_REAL_USER;
      }
      break;
    }
  }

  xfree(ventries); ventries = NULL;

  if (nerr > 0) return -1;

  return retcode;
}

static const int primes[] =
{
  4099,
  8209,
  16411,
  32771,
  65537,
  131101,
  262147,
  524309,
  1048583,
  2097169,
  4194319,
  8388617,
  16777259,
  0,
};

static void
build_uuid_hash(runlog_state_t state, int incr);

int
run_find_run_id_by_uuid(runlog_state_t state, const ej_uuid_t *puuid)
{
  if (state->uuid_hash_state <= 0) return -1;
  int index = puuid->v[0] % state->uuid_hash_size;
  while (state->uuid_hash[index].run_id >= 0) {
    if (!memcmp(puuid, &state->uuid_hash[index].uuid, sizeof(ej_uuid_t))) {
      return state->uuid_hash[index].run_id;
    }
    index = (index + 1) % state->uuid_hash_size;
  }
  return -1;
}

static int
find_free_uuid_hash_index(runlog_state_t state, const ej_uuid_t *puuid)
{
  ej_uuid_t tmp_uuid;

  if (state->uuid_hash_state < 0) return -1;
  if (!state->uuid_hash_state || 2 * (state->uuid_hash_used + 1) >= state->uuid_hash_size) {
    build_uuid_hash(state, 1);
    if (state->uuid_hash_state < 0) return -1;
  }

  int index = puuid->v[0] % state->uuid_hash_size;
  while (state->uuid_hash[index].run_id >= 0) {
    if (!memcmp(puuid, &state->uuid_hash[index].uuid, sizeof(tmp_uuid))) {
      err("find_uuid_hash_index: UUID collision");
      return -1;
    }
    index = (index + 1) % state->uuid_hash_size;
  }
  return index;
}

static void
build_uuid_hash(runlog_state_t state, int incr)
{
  state->uuid_hash_state = -1;
  state->uuid_hash_size = 0;
  state->uuid_hash_used = 0;
  xfree(state->uuid_hash); state->uuid_hash = NULL;

  int run_count = 0;
  for (int run_id = 0; run_id < state->run_u; ++run_id) {
    const struct run_entry *re = &state->runs[run_id];
    if (re->status < 0 || (re->status > RUN_MAX_STATUS && re->status < RUN_TRANSIENT_FIRST) || re->status > RUN_LAST) continue;
    if (!re->run_uuid.v[0] && !re->run_uuid.v[1] && !re->run_uuid.v[2] && !re->run_uuid.v[3]) {
      err("run_id %d has NULL UUID, uuid indexing is not possible", run_id);
      return;
    }
    ++run_count;
  }

  int primes_ind = 0;
  while (primes[primes_ind] > 0 && 2 * (run_count + incr) >= primes[primes_ind]) ++primes_ind;
  if (primes[primes_ind] <= 0) {
    err("build_uuid_hash: run table is too big");
    return;
  }
  int hash_size = primes[primes_ind];
  struct uuid_hash_entry *hash = xcalloc(hash_size, sizeof(hash[0]));
  for (int i = 0; i < hash_size; ++i) {
    hash[i].run_id = -1;
  }
  int hash_count = 0;
  int conflicts = 0;
  for (int run_id = 0; run_id < state->run_u; ++run_id) {
    const struct run_entry *re = &state->runs[run_id];
    if (re->status < 0 || (re->status > RUN_MAX_STATUS && re->status < RUN_TRANSIENT_FIRST) || re->status > RUN_LAST) continue;
    int index = re->run_uuid.v[0] % hash_size;
    while (hash[index].run_id >= 0) {
      if (!memcmp(&re->run_uuid, &hash[index].uuid, sizeof(re->run_uuid))) {
        err("build_uuid_hash: UUID collision for run_ids %d and %d", run_id, hash[index].run_id);
        return;
      }
      ++conflicts;
      index = (index + 1) % hash_size;
    }
    hash[index].run_id = run_id;
    memcpy(&hash[index].uuid, &re->run_uuid, sizeof(hash[index].uuid));
    ++hash_count;
  }
  ASSERT(hash_count == run_count);

  state->uuid_hash_state = 1;
  state->uuid_hash_size = hash_size;
  state->uuid_hash_used = hash_count;
  state->uuid_hash = hash;
  info("build_uuid_hash: success, size = %d, used = %d, conflicts = %d", hash_size, hash_count, conflicts);
}

static void
build_indices(runlog_state_t state, int flags)
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
  if (max_team_id <= 0) {
    if ((flags & RUN_LOG_UUID_INDEX)) {
      build_uuid_hash(state, 0);
    }
    return;
  }

  state->max_user_id = max_team_id;

  state->ut_size = 128;
  while (state->ut_size <= max_team_id)
    state->ut_size *= 2;

  extend_run_extras(state);
  XCALLOC(state->ut_table, state->ut_size);
  for (i = 0; i < state->run_u; i++) {
    if (state->runs[i].status == RUN_EMPTY) continue;
    ASSERT(state->runs[i].user_id > 0);
    if (!(ue = state->ut_table[state->runs[i].user_id])) {
      ue = state->ut_table[state->runs[i].user_id] = xcalloc(1, sizeof(state->ut_table[0][0]));
      ue->run_id_first = -1;
      ue->run_id_last = -1;
    }

    // append to the double-linked list
    state->run_extras[i].prev_user_id = ue->run_id_last;
    state->run_extras[i].next_user_id = -1;
    if (ue->run_id_first < 0) {
      ue->run_id_first = i;
    }
    if (ue->run_id_last >= 0) {
      state->run_extras[ue->run_id_last].next_user_id = i;
    }
    ue->run_id_last = i;

    if (state->runs[i].is_hidden) continue;
    switch (state->runs[i].status) {
    case RUN_VIRTUAL_START:
      ASSERT(!ue->status);
      ue->status = V_VIRTUAL_USER;
      ue->start_time = state->runs[i].time;
      break;
    case RUN_VIRTUAL_STOP:
      ASSERT(ue->status == V_VIRTUAL_USER);
      ASSERT(ue->start_time > 0);
      ue->stop_time = state->runs[i].time;
      break;
    default:
      if (!ue->status) ue->status = V_REAL_USER;
      break;
    }
  }

  if ((flags & RUN_LOG_UUID_INDEX)) {
    build_uuid_hash(state, 0);
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
        int lang_id,
        ej_uuid_t *p_run_uuid,
        int *p_store_flags)
{
  int i;

  if (!state->run_u) return -1;

  if (first_run < 0) first_run = state->run_u + first_run;
  if (first_run < 0) first_run = 0;
  if (first_run >= state->run_u) first_run = state->run_u - 1;

  if (last_run < 0) last_run = state->run_u + last_run;
  if (last_run < 0) last_run = 0;
  if (last_run >= state->run_u) last_run = state->run_u - 1;

  if (team_id > 0) {
    // use user index
    struct user_entry *ue = get_user_entry(state, team_id);
    ASSERT(ue);
    ASSERT(ue->run_id_valid > 0);
    if (first_run <= last_run) {
      // forward search
      for (i = ue->run_id_first; i >= 0 && i <= last_run; i = state->run_extras[i].next_user_id) {
        if (i < first_run) continue;
        if (prob_id && prob_id != state->runs[i].prob_id) continue;
        if (lang_id && lang_id != state->runs[i].lang_id) continue;

        if (p_run_uuid) memcpy(p_run_uuid, &state->runs[i].run_uuid, sizeof(state->runs[i].run_uuid));
        if (p_store_flags) *p_store_flags = state->runs[i].store_flags;
        return i;
      }
    } else {
      // backward search
      for (i = ue->run_id_last; i >= 0 && i >= last_run; i = state->run_extras[i].prev_user_id) {
        if (i > first_run) continue;
        if (prob_id && prob_id != state->runs[i].prob_id) continue;
        if (lang_id && lang_id != state->runs[i].lang_id) continue;

        if (p_run_uuid) memcpy(p_run_uuid, &state->runs[i].run_uuid, sizeof(state->runs[i].run_uuid));
        if (p_store_flags) *p_store_flags = state->runs[i].store_flags;
        return i;
      }
    }
  } else {
    // use plain linear search
    if (first_run <= last_run) {
      // forward search
      for (i = first_run; i <= last_run; i++) {
        if (prob_id && prob_id != state->runs[i].prob_id) continue;
        if (lang_id && lang_id != state->runs[i].lang_id) continue;

        if (p_run_uuid) memcpy(p_run_uuid, &state->runs[i].run_uuid, sizeof(state->runs[i].run_uuid));
        if (p_store_flags) *p_store_flags = state->runs[i].store_flags;
        return i;
      }
    } else {
      // backward search
      for (i = first_run; i >= last_run; i--) {
        if (prob_id && prob_id != state->runs[i].prob_id) continue;
        if (lang_id && lang_id != state->runs[i].lang_id) continue;

        if (p_run_uuid) memcpy(p_run_uuid, &state->runs[i].run_uuid, sizeof(state->runs[i].run_uuid));
        if (p_store_flags) *p_store_flags = state->runs[i].store_flags;
        return i;
      }
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

  if (!state->teamdb_state) return 0;

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

  struct user_entry *ue = get_user_entry(state, user_id);
  ASSERT(ue);
  ASSERT(ue->run_id_valid);

  for (i = ue->run_id_last; i >= 0; i = state->run_extras[i].prev_user_id) {
    ASSERT(i < state->run_u);
    ASSERT(state->runs[i].user_id == user_id);
    if ((s = state->runs[i].status) == RUN_EMPTY) continue;
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
  return 0;

  /*
  int count = 0, i, assigned_count = 0, j;
  const struct run_entry *p;

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
  */
}

int
run_put_entry(
        runlog_state_t state,
        const struct run_entry *re)
{
  return state->iface->put_entry(state->cnts, re);
}

int
run_put_header(
        runlog_state_t state,
        const struct run_header *rh)
{
  return state->iface->put_header(state->cnts, rh);
}

void
run_get_all_statistics(
        runlog_state_t state,
        size_t size,
        int *counts,
        size_t *sizes)
{
  int i;
  const struct run_entry *p;

  for (i = 0; i < state->run_u; i++) {
    p = &state->runs[i];
    if (p->status != RUN_EMPTY && p->user_id >= 1 && p->user_id < size) {
      if (counts) counts[p->user_id]++;
      if (sizes) sizes[p->user_id] += p->size;
    }
  }
}

int
run_get_max_user_id(runlog_state_t state)
{
  if (state->max_user_id < 0) {
    int max_user_id = 0;
    for (int i = 0; i < state->run_u; ++i) {
      const struct run_entry *p = &state->runs[i];
      if (p->status != RUN_EMPTY && p->user_id > 0 && p->user_id > max_user_id) {
        max_user_id = p->user_id;
      }
    }
    state->max_user_id = max_user_id;
  }
  return state->max_user_id;
}

int
run_get_total_users(runlog_state_t state)
{
  if (state->user_count < 0) {
    int user_id_bound = run_get_max_user_id(state) + 1;
    int user_count = 0;
    if (user_id_bound > 1) {
      unsigned char *map = (unsigned char*) xcalloc(user_id_bound, sizeof(map[0]));
      for (int run_id = 0; run_id < state->run_u; ++run_id) {
        const struct run_entry *p = &state->runs[run_id];
        if (p->status != RUN_EMPTY && p->user_id > 0 && p->user_id < user_id_bound) {
          map[p->user_id] = 1;
        }
      }
      for (int user_id = 1; user_id < user_id_bound; ++user_id) {
        user_count += map[user_id];
      }
      xfree(map); map = NULL;
    }
    state->user_count = user_count;
  }
  return state->user_count;
}

int
run_get_insert_position(runlog_state_t state, time_t t, int uid, int nsec)
{
  if (state->run_u <= 0) return 0;

  int j = state->run_u - 1;
  while (j >= 0 && state->runs[j].status == RUN_EMPTY) j--;
  if (j < 0) return state->run_u;
  if (t > state->runs[j].time) return state->run_u;
  if (t == state->runs[j].time) {
    if (nsec < 0 && state->runs[j].nsec < NSEC_MAX) {
      nsec = state->runs[j].nsec + 1;
      return state->run_u;
    }
    if (nsec > state->runs[j].nsec) return state->run_u;
    if (nsec == state->runs[j].nsec && uid >= state->runs[j].user_id)
      return state->run_u;
  }

  int i = 0;

  if (nsec < 0) {
    for (i = 0; i < state->run_u; i++) {
      if (state->runs[i].status == RUN_EMPTY) continue;
      if (state->runs[i].time > t) break;
      if (state->runs[i].time < t) continue;
      // runs[i].time == t
      while (state->runs[i].status == RUN_EMPTY || state->runs[i].time == t) i++;
      j = i - 1;
      while (state->runs[j].status == RUN_EMPTY) j--;
      if (state->runs[j].nsec < NSEC_MAX) {
        nsec = state->runs[j].nsec + 1;
        break;
      }
      // DUMB :(
      nsec = random_u32() % (NSEC_MAX + 1);
      goto try_with_nsec;
    }
    ASSERT(i < state->run_u);
  } else {
  try_with_nsec:
    for (i = 0; i < state->run_u; i++) {
      if (state->runs[i].status == RUN_EMPTY) continue;
      if (state->runs[i].time > t) break;
      if (state->runs[i].time < t) continue;
      if (state->runs[i].nsec > nsec) break;
      if (state->runs[i].nsec < nsec) continue;
      if (state->runs[i].user_id > uid) break;
    }
  }

  for (j = i; j < state->run_u; j++)
    if (state->runs[j].status >= RUN_TRANSIENT_FIRST
        && state->runs[j].status <= RUN_TRANSIENT_LAST)
      break;
  if (j < state->run_u) {
    return -1;
  }

  return i;
}

int
run_clear_index(runlog_state_t state, int run_id)
{
  if (run_id < 0 || run_id >= state->run_u) return 0;
  if (state->runs[run_id].status == RUN_EMPTY) return 0;
  struct user_entry *ue = try_user_entry(state, state->runs[run_id].user_id);
  if (ue) {
    ue->run_id_valid = 0;
  }
  return 0;
}

int
run_get_user_last_run_id(runlog_state_t state, int user_id)
{
  struct user_entry *ue = get_user_entry(state, user_id);
  ASSERT(ue);
  ASSERT(ue->run_id_valid > 0);
  return ue->run_id_last;
}

int
run_get_user_first_run_id(runlog_state_t state, int user_id)
{
  struct user_entry *ue = get_user_entry(state, user_id);
  ASSERT(ue);
  ASSERT(ue->run_id_valid > 0);
  return ue->run_id_first;
}

int
run_get_user_next_run_id(runlog_state_t state, int run_id)
{
  if (run_id < 0 || run_id >= state->run_extra_u) return -1;
  return state->run_extras[run_id].next_user_id;
}

int
run_get_user_prev_run_id(runlog_state_t state, int run_id)
{
  if (run_id < 0 || run_id >= state->run_extra_u) return -1;
  return state->run_extras[run_id].prev_user_id;
}

int
run_get_uuid_hash_state(runlog_state_t state)
{
  return state->uuid_hash_state;
}

static void
run_drop_uuid_hash(runlog_state_t state)
{
  if (state->uuid_hash_state < 0) return;

  state->uuid_hash_state = 0;
  state->uuid_hash_size = 0;
  state->uuid_hash_used = 0;
  xfree(state->uuid_hash); state->uuid_hash = NULL;
}
