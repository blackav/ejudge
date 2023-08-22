/* -*- c -*- */

/* Copyright (C) 2012-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_limits.h"
#include "ejudge/version.h"
#include "ejudge/startstop.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/fileutl.h"
#include "ejudge/errlog.h"
#include "ejudge/prepare.h"
#include "ejudge/interrupt.h"
#include "ejudge/super_run_packet.h"
#include "ejudge/run_packet.h"
#include "ejudge/run.h"
#include "ejudge/curtime.h"
#include "ejudge/ej_process.h"
#include "ejudge/xml_utils.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/super_run_status.h"
#include "ejudge/agent_client.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/inotify.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <fcntl.h>

enum { DEFAULT_WAIT_TIMEOUT_MS = 300000 }; // 5m

struct ignored_problem_info
{
  int contest_id;
  unsigned char *short_name;
};

#define SUPER_RUN_DIRECTORY "super-run"
static unsigned char *super_run_dir = NULL;
static unsigned char *run_server_id = NULL;

static const unsigned char *program_name = 0;
//struct ejudge_cfg *ejudge_config = NULL;
static __attribute__((unused)) unsigned char super_run_server_path[PATH_MAX];
static unsigned char super_run_path[PATH_MAX];
static unsigned char super_run_spool_path[PATH_MAX];
static unsigned char super_run_exe_path[PATH_MAX];
static unsigned char super_run_conf_path[PATH_MAX];
static unsigned char super_run_log_path[PATH_MAX];
static unsigned char super_run_heartbeat_path[PATH_MAX];
static int utf8_mode = 0;
static struct serve_state serve_state;
static int restart_flag = 0;
static unsigned char *contests_home_dir = NULL;
static int heartbeat_mode = 1;
static unsigned char *super_run_id = NULL;
static unsigned char *instance_id = NULL;
static unsigned char *local_ip = NULL;
static unsigned char *local_hostname = NULL;
static unsigned char *public_ip = NULL;
static unsigned char *public_hostname = NULL;
static unsigned char *super_run_name = NULL;
static unsigned char *queue_name = NULL;
static unsigned char *status_file_name = NULL;
static unsigned char *agent_name = NULL;
static unsigned char *agent_instance_id = NULL;
static struct AgentClient *agent;
static int verbose_mode;
static int daemon_mode;
static unsigned char *ip_address = NULL;

static int ignored_archs_count = 0;
static int ignored_problems_count = 0;
static unsigned char **ignored_archs = NULL;
static struct ignored_problem_info *ignored_problems = NULL;
static int ignore_rejudge = 0;

static unsigned char **host_names = NULL;
static unsigned char *mirror_dir = NULL;
static unsigned char *local_cache = NULL;

#define HEARTBEAT_SAVE_INTERVAL_MS 5000
static long long last_heartbear_save_time = 0;

static unsigned char master_stop_enabled = 0;
static unsigned char master_down_enabled = 0;
static unsigned char master_reboot_enabled = 0;
static unsigned char pending_stop_flag = 0;
static unsigned char pending_down_flag = 0;
static unsigned char pending_reboot_flag = 0;

static int remap_spec_a = 0;
static int remap_spec_u = 0;
static struct remap_spec *remap_specs = 0;

static void
fatal(const char *format, ...)
  __attribute__((noreturn, format(printf, 1, 2)));
static void
fatal(const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: %s\n", program_name, buf);
  exit(1);
}

static int
is_packet_to_ignore(
        const unsigned char *pkt_name,
        int contest_id,
        int rejudge_flag,
        const unsigned char *short_name,
        const unsigned char *arch)
{
  int i;

  if (ignore_rejudge > 0 && rejudge_flag > 0) return 1;

  if (ignored_archs_count > 0) {
    for (i = 0; i < ignored_archs_count; ++i) {
      if (!strcmp(ignored_archs[i], arch))
        break;
    }
    if (i < ignored_archs_count) {
      info("packet %s: ignored because of arch == '%s'", pkt_name, arch);
      return 1;
    }
  }
  if (ignored_problems_count > 0) {
    for (i = 0; i < ignored_problems_count; ++i) {
      if (ignored_problems[i].contest_id > 0 && ignored_problems[i].short_name) {
        if (contest_id == ignored_problems[i].contest_id
            && !strcmp(short_name, ignored_problems[i].short_name))
          break;
      } else if (ignored_problems[i].contest_id > 0) {
        if (contest_id == ignored_problems[i].contest_id)
          break;
      } else if (ignored_problems[i].short_name) {
        if (!strcmp(short_name, ignored_problems[i].short_name))
          break;
      }
    }
    if (i < ignored_problems_count) {
      info("packet %s: ignored because of contest_id == %d, short_name == '%s'",
           pkt_name, contest_id, short_name);
      return 1;
    }
  }
  return 0;
}

static const struct section_tester_data *
find_abstract_tester(serve_state_t state, const unsigned char *arch)
{
  if (!state || !arch || state->max_abstr_tester <= 0) return NULL;
  for (int i = 0; i < state->max_abstr_tester; ++i) {
    if (!strcmp(arch, state->abstr_testers[i]->arch)) {
      return state->abstr_testers[i];
    }
  }
  return NULL;
}

struct super_run_listener
{
  struct run_listener b;
  int contest_id;
  int run_id;
  const unsigned char *packet_name;
  const unsigned char *user;
  const unsigned char *prob_short_name;
  const unsigned char *lang_short_name;
  long long queue_ts;
  long long testing_start_ts;
  int test_count;
};

static void
do_super_run_status_init(struct super_run_status *prs);

static void
super_run_before_tests(struct run_listener *gself, int test_no)
{
  struct super_run_listener *self = (struct super_run_listener *) gself;
  if (!heartbeat_mode) return;

  struct super_run_status rs;
  do_super_run_status_init(&rs);

  struct timeval ctv;
  gettimeofday(&ctv, NULL);
  long long current_time_ms = ((long long) ctv.tv_sec) * 1000 + ctv.tv_usec / 1000;

  rs.timestamp = current_time_ms;
  rs.last_run_ts = current_time_ms;
  rs.status = SRS_TESTING;
  rs.contest_id = self->contest_id;
  rs.run_id = self->run_id;
  rs.pkt_name_idx = super_run_status_add_str(&rs, self->packet_name);
  rs.test_num = test_no;
  rs.test_count = self->test_count;
  if (self->user) rs.user_idx = super_run_status_add_str(&rs, self->user);
  if (self->prob_short_name) rs.prob_idx = super_run_status_add_str(&rs, self->prob_short_name);
  if (self->lang_short_name) rs.lang_idx = super_run_status_add_str(&rs, self->lang_short_name);
  rs.queue_ts = self->queue_ts;
  rs.testing_start_ts = self->testing_start_ts;

  super_run_status_save(agent, super_run_heartbeat_path, status_file_name, &rs,
                        current_time_ms, &last_heartbear_save_time, HEARTBEAT_SAVE_INTERVAL_MS,
                        &pending_stop_flag, &pending_down_flag,
                        &pending_reboot_flag);
  if (!master_stop_enabled) pending_stop_flag = 0;
  if (!master_down_enabled) pending_down_flag = 0;
  if (!master_reboot_enabled) pending_reboot_flag = 0;
}

static const struct run_listener_ops super_run_listener_ops =
{
  super_run_before_tests,
};

static int
do_copy_regular_file(
        const unsigned char *dst_path,
        const unsigned char *src_path)
{
  int src_fd = -1;
  int retval = -1;
  size_t src_size = 0;
  unsigned char *src_ptr = MAP_FAILED;
  int dst_fd = -1;
  int need_unlink = 0;
  unsigned char *dst_ptr = MAP_FAILED;

  src_fd = open(src_path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK, 0);
  if (src_fd < 0) {
    err("%s: open '%s' failed: %s", __FUNCTION__, src_path, os_ErrorMsg());
    goto done;
  }
  struct stat stb;
  if (fstat(src_fd, &stb) < 0) {
    err("%s: fstat failed: %s", __FUNCTION__, os_ErrorMsg());
    goto done;
  }
  if (!S_ISREG(stb.st_mode)) {
    err("%s: '%s' is not regular", __FUNCTION__, src_path);
    goto done;
  }
  if (stb.st_size < 0 || stb.st_size > 128 * 1024 * 1024) {
    err("%s: '%s' is too big", __FUNCTION__, src_path);
    goto done;
  }
  src_size = stb.st_size;

  dst_fd = open(dst_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOCTTY | O_NONBLOCK, stb.st_mode & 0777);
  if (dst_fd < 0) {
    err("%s: open '%s' failed: %s", __FUNCTION__, dst_path, os_ErrorMsg());
    goto done;
  }
  need_unlink = 1;
  if (fstat(dst_fd, &stb) < 0) {
    err("%s: fstat failed: %s", __FUNCTION__, os_ErrorMsg());
    goto done;
  }
  if (!S_ISREG(stb.st_mode)) {
    err("%s: '%s' is not regular", __FUNCTION__, dst_path);
    goto done;
  }

  if (src_size > 0) {
    src_ptr = mmap(NULL, src_size, PROT_READ, MAP_PRIVATE, src_fd, 0);
    if (src_ptr == MAP_FAILED) {
      err("%s: mmap of '%s' failed: %s", __FUNCTION__, src_path, os_ErrorMsg());
      goto done;
    }

    if (posix_fallocate(dst_fd, 0, src_size) < 0) {
      err("%s: fallocate failed: %s", __FUNCTION__, os_ErrorMsg());
      goto done;
    }
    dst_ptr = mmap(NULL, src_size, PROT_READ | PROT_WRITE, MAP_SHARED, dst_fd, 0);
    if (dst_ptr == MAP_FAILED) {
      err("%s: mmap of '%s' failed: %s", __FUNCTION__, dst_path, os_ErrorMsg());
      goto done;
    }
    memcpy(dst_ptr, src_ptr, src_size);
  }

  retval = 0;
  need_unlink = 0;

done:;
  if (dst_ptr != MAP_FAILED) munmap(dst_ptr, src_size);
  if (src_ptr != MAP_FAILED) munmap(src_ptr, src_size);
  if (need_unlink) unlink(dst_path);
  if (dst_fd >= 0) close(dst_fd);
  if (src_fd >= 0) close(src_fd);
  return retval;
}

static int
move_from_local_cache(
        const unsigned char *judge_uuid,
        const unsigned char *dst_dir,
        const unsigned char *dst_name,
        const unsigned char *dst_sfx)
{
  unsigned char src_path[PATH_MAX];
  unsigned char dst_path[PATH_MAX];
  int r;

  if (!dst_sfx) dst_sfx = "";
  r = snprintf(src_path, sizeof(src_path), "%s/%s%s", local_cache, judge_uuid, dst_sfx);
  if (r >= (int)sizeof(src_path)) {
    err("%s: source path too long", __FUNCTION__);
    return -1;
  }

  if (dst_dir && *dst_dir) {
    r = snprintf(dst_path, sizeof(dst_path), "%s/%s%s", dst_dir, dst_name, dst_sfx);
  } else {
    r = snprintf(dst_path, sizeof(dst_path), "%s%s", dst_name, dst_sfx);
  }
  if (r >= (int)sizeof(dst_path)) {
    err("%s: destination path too long", __FUNCTION__);
    unlink(src_path);
    return -1;
  }

  if (rename(src_path, dst_path) >= 0) {
    return 0;
  }
  if (errno != EXDEV) {
    err("%s: rename failed: %s", __FUNCTION__, os_ErrorMsg());
    unlink(src_path);
    return -1;
  }
  if (do_copy_regular_file(dst_path, src_path) < 0) {
    unlink(src_path);
    return -1;
  }
  unlink(src_path);
  return 0;
}

static int
handle_packet(
        serve_state_t state,
        const unsigned char *pkt_name,
        char *srp_b,
        size_t srp_z)
{
  int r;
  struct super_run_in_packet *srp = NULL;
  struct super_run_in_global_packet *srgp = NULL;
  struct super_run_in_problem_packet *srpp = NULL;
  unsigned char run_base[PATH_MAX];
  unsigned char report_path[PATH_MAX];
  unsigned char full_report_path[PATH_MAX];

  unsigned char full_report_dir[PATH_MAX];
  unsigned char full_status_dir[PATH_MAX];
  unsigned char full_full_dir[PATH_MAX];

  unsigned char exe_pkt_name[PATH_MAX];
  unsigned char exe_name[PATH_MAX];
  unsigned char reply_packet_name[PATH_MAX];

  struct section_global_data *global = state->global;

  struct run_reply_packet reply_pkt;
  void *reply_pkt_buf = 0;
  size_t reply_pkt_buf_size = 0;
  int retval = 1;
  unsigned char *arch = NULL;
  unsigned char *short_name = NULL;
  const struct section_tester_data *tst = NULL;
  struct super_run_listener run_listener;
  char *inp_data = NULL;
  size_t inp_size = 0;

  unsigned char source_code_buf[PATH_MAX];
  const unsigned char *source_code_path = NULL;

  memset(&reply_pkt, 0, sizeof(reply_pkt));
  memset(&run_listener, 0, sizeof(run_listener));
  run_listener.b.ops = &super_run_listener_ops;

  if (agent) {
    if (!srp_b) {
      r = agent->ops->get_packet(agent, pkt_name, &srp_b, &srp_z);
      if (r < 0) {
        err("agent get_packet failed");
        goto cleanup;
      }
    } else {
      r = 1;
    }
  } else {
    r = generic_read_file(&srp_b, 0, &srp_z, SAFE | REMOVE, super_run_spool_path, pkt_name, "");
    if (r < 0) {
      err("generic_read_file failed for packet %s in %s", pkt_name, super_run_spool_path);
      goto cleanup;
    }
  }
  if (r == 0) {
    // ignore this packet
    retval = 0;
    goto cleanup;
  }

  if (verbose_mode) {
    fprintf(stderr, "packet: <<%.*s>>\n", (int) srp_z, srp_b);
  }

  srp = super_run_in_packet_parse_cfg_str(pkt_name, srp_b, srp_z);
  if (!srp) {
    err("failed to parse packet %s", pkt_name);
    goto cleanup;
  }
  if (!(srgp = srp->global)) {
    err("packet %s has no global section", pkt_name);
    goto cleanup;
  }
  if (srgp->contest_id <= 0) {
    err("packet %s: undefined contest_id", pkt_name);
    goto cleanup;
  }
  if (srgp->restart > 0) {
    info("ignoring force quit packet %s", pkt_name);
    goto cleanup;
  }

  if (!(srpp = srp->problem)) {
    err("packet %s: no [problem] section", pkt_name);
    goto cleanup;
  }

  arch = srgp->arch;
  if (!arch) arch = "";
  short_name = srpp->short_name;
  if (!short_name) short_name = "";

  if (is_packet_to_ignore(pkt_name, srgp->contest_id, srgp->rejudge_flag, short_name, arch)) {
    retval = 0;
    if (agent) {
      agent->ops->put_packet(agent, pkt_name, srp_b, srp_z);
    } else {
      generic_write_file(srp_b, srp_z, SAFE, super_run_spool_path, pkt_name, "");
    }
    goto cleanup;
  }

  snprintf(run_base, sizeof(run_base), "%06d", srgp->run_id);
  report_path[0] = 0;
  full_report_path[0] = 0;

  if (srpp->type_val == PROB_TYPE_TESTS) {
    //cr_serialize_lock(state);
    run_inverse_testing(state, srp, &reply_pkt,
                        pkt_name, super_run_exe_path,
                        report_path, sizeof(report_path),
                        utf8_mode);
    //cr_serialize_unlock(state);
  } else {
    if (!srpp->type_val) {
      tst = find_abstract_tester(state, arch);
      if (!tst) {
        err("no support for architecture %s here", arch);
        retval = 0;
        if (agent) {
          agent->ops->put_packet(agent, pkt_name, srp_b, srp_z);
        } else {
          generic_write_file(srp_b, srp_z, SAFE, super_run_spool_path, pkt_name, "");
        }
        goto cleanup;
      }
    }

    snprintf(exe_pkt_name, sizeof(exe_pkt_name), "%s%s", pkt_name, srgp->exe_sfx);
    snprintf(exe_name, sizeof(exe_name), "%s%s", run_base, srgp->exe_sfx);

    if (agent) {
      r = agent->ops->get_data_2(agent, pkt_name, srgp->exe_sfx,
                                 global->run_work_dir, run_base, srgp->exe_sfx);
      if (local_cache && *local_cache && srgp->judge_uuid && *srgp->judge_uuid && srgp->cached_on_remote > 0) {
        move_from_local_cache(srgp->judge_uuid, global->run_work_dir, run_base, srgp->exe_sfx);
      }
    } else {
      r = generic_copy_file(REMOVE, super_run_exe_path, exe_pkt_name, "",
                            0, global->run_work_dir, exe_name, "");
    }
    if (r <= 0) {
      // FIXME: handle this differently?
      retval = 0;
      if (agent) {
        agent->ops->put_packet(agent, pkt_name, srp_b, srp_z);
      } else {
        generic_write_file(srp_b, srp_z, SAFE, super_run_spool_path, pkt_name, "");
      }
      goto cleanup;
    }

    // copy the source code file
    if (srgp->src_file && *srgp->src_file) {
      const unsigned char *src_sfx = srgp->src_sfx;
      if (!src_sfx) src_sfx = "";
      snprintf(source_code_buf, sizeof(source_code_buf), "%s/%s%s",
               global->run_work_dir, srgp->src_file, src_sfx);
      if (agent) {
        r = agent->ops->get_data_2(agent, srgp->src_file, src_sfx,
                                   global->run_work_dir, srgp->src_file,
                                   src_sfx);
        // FIXME: support local cache
      } else {
        r = generic_copy_file(REMOVE, super_run_exe_path,srgp->src_file, src_sfx,
                              0, global->run_work_dir, srgp->src_file, src_sfx);
      }
      if (r < 0) {
        err("failed to copy source code file");
        goto cleanup;
      }
      source_code_path = source_code_buf;
      (void) source_code_path;
    }

    if (srgp->submit_id > 0) {
      if (!srpp->user_input_file || !*srpp->user_input_file) {
        err("user_input_file is undefined");
        goto cleanup;
      }
      if (agent) {
        r = agent->ops->get_data(agent, srpp->user_input_file, NULL,
                                 &inp_data, &inp_size);
      } else {
        r = generic_read_file(&inp_data, 0, &inp_size, REMOVE, super_run_exe_path, srpp->user_input_file, NULL);
      }
      if (r < 0 || !inp_size || !inp_data) {
        err("user_input_file is nonexistant or empty");
        goto cleanup;
      }
    }

    reply_pkt.judge_id = srgp->judge_id;
    reply_pkt.contest_id = srgp->contest_id;
    reply_pkt.run_id = srgp->run_id;
    reply_pkt.submit_id = srgp->submit_id;
    reply_pkt.notify_flag = srgp->notify_flag;
    reply_pkt.user_status = -1;
    reply_pkt.user_tests_passed = -1;
    reply_pkt.user_score = -1;
    reply_pkt.ts1 = srgp->ts1;
    reply_pkt.ts1_us = srgp->ts1_us;
    reply_pkt.ts2 = srgp->ts2;
    reply_pkt.ts2_us = srgp->ts2_us;
    reply_pkt.ts3 = srgp->ts3;
    reply_pkt.ts3_us = srgp->ts3_us;
    reply_pkt.ts4 = srgp->ts4;
    reply_pkt.ts4_us = srgp->ts4_us;
    get_current_time(&reply_pkt.ts5, &reply_pkt.ts5_us);
    if (srgp->run_uuid && srgp->run_uuid[0]) {
      ej_uuid_parse(srgp->run_uuid, &reply_pkt.uuid);
    }
    if (srgp->judge_uuid && srgp->judge_uuid[0]) {
      ej_uuid_parse(srgp->judge_uuid, &reply_pkt.judge_uuid);
    }

    run_listener.contest_id = srgp->contest_id;
    run_listener.run_id = srgp->run_id;
    run_listener.packet_name = pkt_name;
    run_listener.prob_short_name = srpp->short_name;
    run_listener.lang_short_name = srgp->lang_short_name;
    run_listener.queue_ts = ((long long) srgp->ts1) * 1000 + srgp->ts1_us / 1000;
    run_listener.testing_start_ts = ((long long) reply_pkt.ts5) * 1000 + reply_pkt.ts5_us / 1000;
    if (srgp->user_name) {
      run_listener.user = srgp->user_name;
    } else {
      run_listener.user = srgp->user_login;
    }
    run_listener.test_count = srpp->test_count;

    //if (cr_serialize_lock(state) < 0) return -1;
    run_tests(ejudge_config, state, tst, srp, &reply_pkt,
              agent,
              exe_name, run_base,
              report_path, full_report_path,
              mirror_dir, utf8_mode,
              &run_listener.b, super_run_name,
              remap_specs,
              srgp->submit_id > 0,
              inp_data,
              inp_size,
              source_code_path);
    //if (cr_serialize_unlock(state) < 0) return -1;
  }

#if defined EJUDGE_RUN_SPOOL_DIR
  snprintf(full_report_dir, sizeof(full_report_dir), "%s/%s/report", EJUDGE_RUN_SPOOL_DIR, srgp->contest_server_id);
  snprintf(full_status_dir, sizeof(full_status_dir), "%s/%s/status", EJUDGE_RUN_SPOOL_DIR, srgp->contest_server_id);
  if (srgp->enable_full_archive > 0) {
    snprintf(full_full_dir, sizeof(full_full_dir), "%s/%s/output", EJUDGE_RUN_SPOOL_DIR, srgp->contest_server_id);
  }
#else
  if (srgp->reply_report_dir && srgp->reply_report_dir[0]) {
    if (os_IsAbsolutePath(srgp->reply_report_dir)) {
      snprintf(full_report_dir, sizeof(full_report_dir), "%s", srgp->reply_report_dir);
    } else {
      snprintf(full_report_dir, sizeof(full_report_dir), "%s/%s/%s",
               EJUDGE_CONTESTS_HOME_DIR, super_run_dir, srgp->reply_report_dir);
    }
  } else {
    snprintf(full_report_dir, sizeof(full_report_dir), "%s/%06d/var/run/%06d/report",
             contests_home_dir, srgp->contest_id, srgp->contest_id);
  }
  if (srgp->reply_spool_dir && srgp->reply_spool_dir[0]) {
    if (os_IsAbsolutePath(srgp->reply_spool_dir)) {
      snprintf(full_status_dir, sizeof(full_status_dir), "%s", srgp->reply_spool_dir);
    } else {
      snprintf(full_status_dir, sizeof(full_status_dir), "%s/%s/%s",
               EJUDGE_CONTESTS_HOME_DIR, super_run_dir, srgp->reply_spool_dir);
    }
  } else {
    snprintf(full_status_dir, sizeof(full_status_dir), "%s/%06d/var/run/%06d/status",
             contests_home_dir, srgp->contest_id, srgp->contest_id);
  }
  if (srgp->reply_full_archive_dir && srgp->reply_full_archive_dir[0]) {
    if (os_IsAbsolutePath(srgp->reply_full_archive_dir)) {
      snprintf(full_full_dir, sizeof(full_full_dir), "%s", srgp->reply_full_archive_dir);
    } else {
      snprintf(full_status_dir, sizeof(full_status_dir), "%s/%s/%s",
               EJUDGE_CONTESTS_HOME_DIR, super_run_dir,
               srgp->reply_full_archive_dir);
    }
  } else {
    snprintf(full_full_dir, sizeof(full_full_dir), "%s/%06d/var/run/%06d/output",
             contests_home_dir, srgp->contest_id, srgp->contest_id);
  }
#endif

  if (full_report_dir[0]) {
    os_MakeDirPath(full_report_dir, 0777);
  }
  if (full_full_dir[0]) {
    os_MakeDirPath(full_full_dir, 0777);
  }
  if (full_status_dir[0]) {
    os_MakeDirPath(full_status_dir, 0777);
    make_all_dir(full_status_dir, 0777);
  }

  if (srgp->reply_packet_name && srgp->reply_packet_name[0]) {
    snprintf(reply_packet_name, sizeof(reply_packet_name), "%s", srgp->reply_packet_name);
  } else {
    snprintf(reply_packet_name, sizeof(reply_packet_name), "%s", run_base);
  }

  // copy full report from temporary location
  if (agent) {
    if (agent->ops->put_output_2(agent,
                                 srgp->contest_server_id,
                                 srgp->contest_id,
                                 reply_packet_name,
                                 "",
                                 report_path) < 0) {
      goto cleanup;
    }
  } else {
    if (generic_copy_file(0, NULL, report_path, "", 0, full_report_dir, reply_packet_name, "") < 0) {
      goto cleanup;
    }
  }

#if defined CONF_HAS_LIBZIP
  const unsigned char *zip_suffix = ".zip";
#else
  const unsigned char *zip_suffix = "";
#endif

  if (full_report_path[0]) {
    if (agent) {
      if (agent->ops->put_archive_2(agent,
                                    srgp->contest_server_id,
                                    srgp->contest_id,
                                    reply_packet_name,
                                    zip_suffix,
                                    full_report_path) < 0) {
        goto cleanup;
      }
    } else {
      if (generic_copy_file(0, NULL, full_report_path, "", 0, full_full_dir, reply_packet_name, zip_suffix) < 0) {
        goto cleanup;
      }
    }
  }

  //run_reply_packet_dump(&reply_pkt);

  if (run_reply_packet_write(&reply_pkt, &reply_pkt_buf_size, &reply_pkt_buf) < 0) {
    goto cleanup;
  }

  if (agent) {
    if (agent->ops->put_reply(agent,
                              srgp->contest_server_id,
                              srgp->contest_id,
                              reply_packet_name,
                              reply_pkt_buf, reply_pkt_buf_size) < 0)
      goto cleanup;
  } else {
    if (generic_write_file(reply_pkt_buf, reply_pkt_buf_size, SAFE, full_status_dir, reply_packet_name, "") < 0) {
      goto cleanup;
    }
  }

cleanup:
  xfree(srp_b); srp_b = NULL; srp_z = 0;
  srp = super_run_in_packet_free(srp);
  xfree(reply_pkt_buf); reply_pkt_buf = NULL;
  free(inp_data);
  clear_directory(global->run_work_dir);
  return retval;
}

static void
do_super_run_status_init(struct super_run_status *prs)
{
  super_run_status_init(prs);

  if (instance_id) prs->inst_id_idx = super_run_status_add_str(prs, instance_id);
  if (local_ip) prs->local_ip_idx = super_run_status_add_str(prs, local_ip);
  if (local_hostname) prs->local_host_idx = super_run_status_add_str(prs, local_hostname);
  if (ip_address && *ip_address) {
    prs->public_ip_idx = super_run_status_add_str(prs, ip_address);
  } else if (public_ip) {
    prs->public_ip_idx = super_run_status_add_str(prs, public_ip);
  }
  if (public_hostname) prs->public_host_idx = super_run_status_add_str(prs, public_hostname);
  if (queue_name) prs->queue_idx = super_run_status_add_str(prs, queue_name);
  prs->ej_ver_idx = super_run_status_add_str(prs, compile_version);
  if (super_run_id) {
    prs->super_run_idx = super_run_status_add_str(prs, super_run_id);
  } else if (agent_instance_id) {
    prs->super_run_idx = super_run_status_add_str(prs, agent_instance_id);
  }
  prs->super_run_pid = getpid();
  prs->stop_pending = pending_stop_flag;
  prs->down_pending = pending_down_flag;
}

static void
report_waiting_state(long long current_time_ms, long long last_check_time_ms)
{
  struct super_run_status rs;

  if (!heartbeat_mode) return;

  do_super_run_status_init(&rs);
  rs.timestamp = current_time_ms;
  rs.last_run_ts = last_check_time_ms;
  rs.status = SRS_WAITING;
  super_run_status_save(agent, super_run_heartbeat_path, status_file_name, &rs,
                        current_time_ms, &last_heartbear_save_time, HEARTBEAT_SAVE_INTERVAL_MS,
                        &pending_stop_flag, &pending_down_flag,
                        &pending_reboot_flag);
  if (!master_stop_enabled) pending_stop_flag = 0;
  if (!master_down_enabled) pending_down_flag = 0;
  if (!master_reboot_enabled) pending_reboot_flag = 0;
}

static int
do_loop(
        serve_state_t state,
        int halt_timeout,
        int *p_halt_requested)
{
  struct section_global_data *global = state->global;
  unsigned char pkt_name[PATH_MAX];
  int r;
  struct timeval ctv;
  time_t last_handled = 0;
  long long last_handled_ms = 0;
  long long current_time_ms = 0;
  struct Future *future = NULL;
  char *pkt_data = NULL;
  size_t pkt_size = 0;
  int ifd = -1;
  int efd = -1;
  int ifd_wd = -1;
  sigset_t emptymask;

  sigemptyset(&emptymask);

  if (agent_name && *agent_name) {
    if (!strncmp(agent_name, "ssh:", 4)) {
      if (!agent_instance_id && super_run_id) {
        agent_instance_id = xstrdup(super_run_id);
      }
      agent = agent_client_ssh_create();
      if (agent->ops->init(agent, agent_instance_id,
                           agent_name + 4, run_server_id,
                           PREPARE_RUN, verbose_mode, ip_address) < 0) {
        err("failed to initalize agent");
        return -1;
      }
      if (agent->ops->connect(agent) < 0) {
        err("failed to connect to client");
        return -1;
      }
    } else {
      err("invalid agent");
      return -1;
    }
  } else {
    ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ifd < 0) {
      err("inotify_init1 failed: %s", os_ErrorMsg());
      return -1;
    }

    unsigned char srspd[PATH_MAX];
    snprintf(srspd, sizeof(srspd), "%s/dir", super_run_spool_path);
    ifd_wd = inotify_add_watch(ifd, srspd, IN_CREATE | IN_MOVED_TO);
    if (ifd_wd < 0) {
      err("inotify_add_watch failed: %s", os_ErrorMsg());
      return -1;
    }

    efd = epoll_create1(EPOLL_CLOEXEC);
    if (efd < 0) {
      err("epoll_create1 failed: %s", os_ErrorMsg());
      return -1;
    }

    struct epoll_event ev =
    {
      .events = EPOLLIN,
      .data.fd = ifd,
    };
    if (epoll_ctl(efd, EPOLL_CTL_ADD, ifd, &ev) < 0) {
      err("epoll_ctl failed: %s", os_ErrorMsg());
      return -1;
    }
  }

  gettimeofday(&ctv, NULL);
  last_handled = ctv.tv_sec;
  last_handled_ms = ((long long) ctv.tv_sec) * 1000 + ctv.tv_usec / 1000;

  if (global->sleep_time <= 0) global->sleep_time = 1000;

  /*
  if (state->global->cr_serialization_key > 0) {
    if (cr_serialize_init(state) < 0) {
      err("cr_serialize_init() failed");
      return -1;
    }
  }
  */
  interrupt_init();
  interrupt_setup_usr1();
  interrupt_setup_usr2();
  interrupt_disable();

  while (1) {
    interrupt_enable();
    /* time window for immediate signal delivery */
    interrupt_disable();

    // terminate, if signaled
    if (interrupt_get_status()) break;
    if (interrupt_restart_requested()) {
      restart_flag = 1;
    }
    if (restart_flag) break;

    if (pending_stop_flag) break;
    if (pending_down_flag) break;
    if (pending_reboot_flag) break;
    if (interrupt_was_usr1()) {
      if (daemon_mode) {
        start_open_log(super_run_log_path);
      }
      interrupt_reset_usr1();
    }

    time_t current_time = time(NULL);
    if (halt_timeout > 0 && last_handled + halt_timeout <= current_time) {
      if (p_halt_requested) *p_halt_requested = 1;
      break;
    }

    r = 0;
    pkt_name[0] = 0;
    if (agent) {
      if (interrupt_was_usr2()) {
        interrupt_reset_usr2();
        if (future) {
          r = agent->ops->async_wait_complete(agent, &future,
                                              pkt_name, sizeof(pkt_name),
                                              &pkt_data,
                                              &pkt_size);
          if (r < 0) {
            err("async_wait_complete failed");
            break;
          }
          if (!pkt_name[0]) {
            free(pkt_data); pkt_data = NULL;
            pkt_size = 0;
            continue;
          }
        }
      } else if (!future) {
        r = agent->ops->async_wait_init(agent, SIGUSR2, 1,
                                        1,
                                        pkt_name, sizeof(pkt_name), &future,
                                        DEFAULT_WAIT_TIMEOUT_MS,
                                        &pkt_data,
                                        &pkt_size);
        if (r < 0) {
          err("async_wait_init failed");
          break;
        }
      }
      /*
      r = agent->ops->poll_queue(agent, pkt_name, sizeof(pkt_name), 1);
      if (r < 0) {
        err("agent poll_queue failed, waiting...");
      }
      */
    } else {
      r = scan_dir(super_run_spool_path, pkt_name, sizeof(pkt_name), 1);
      if (r < 0) {
        err("scan_dir failed for %s, waiting...", super_run_spool_path);
      }
    }
    if (r < 0) {
      gettimeofday(&ctv, NULL);
      current_time_ms = ((long long) ctv.tv_sec) * 1000 + ctv.tv_usec / 1000;
      report_waiting_state(current_time_ms, last_handled_ms);

      int sleep_time = agent?30000:global->sleep_time;
      interrupt_enable();
      os_Sleep(sleep_time);
      interrupt_disable();
      free(pkt_data); pkt_data = NULL;
      pkt_size = 0;
      continue;
    }

    if (!r) {
      free(pkt_data); pkt_data = NULL;
      pkt_size = 0;

      gettimeofday(&ctv, NULL);
      current_time_ms = ((long long) ctv.tv_sec) * 1000 + ctv.tv_usec / 1000;
      report_waiting_state(current_time_ms, last_handled_ms);

      if (efd >= 0) {
        struct epoll_event events[1];
        int r = epoll_pwait(efd, events, 1, 30000, &emptymask);
        if (r == 1) {
          if (events[0].data.fd != ifd) abort();
          // just read all the data in the ifd without any processing
          unsigned char ibuf[4096];
          while (1) {
            int r = read(ifd, ibuf, sizeof(ibuf));
            if (r <= 0) break;
          }
        }
      } else {
        interrupt_enable();
        os_Sleep(5000);
        interrupt_disable();
      }
      continue;
    }

    r = handle_packet(state, pkt_name, pkt_data, pkt_size);
    pkt_data = NULL;
    pkt_size = 0;
    if (!r) {
      if (agent) {
        //agent->ops->add_ignored(agent, pkt_name);
      } else {
        scan_dir_add_ignored(super_run_spool_path, pkt_name);
      }
    }

    gettimeofday(&ctv, NULL);
    last_handled = ctv.tv_sec;
    last_handled_ms = ((long long) ctv.tv_sec) * 1000 + ctv.tv_usec / 1000;
  }

  super_run_status_remove(agent, super_run_heartbeat_path, status_file_name);

  if (agent) {
    agent->ops->close(agent);
  }

  return 0;
}

static void write_help(void) __attribute__((noreturn));
static void
write_help(void)
{
  printf("%s: ejudge testing super server\n"
         "Usage: %s [OPTIONS]\n"
         "  OPTIONS:\n"
         "    --help       write this message and exit\n"
         "    --version    report version and exit\n"
         "    -u USER      specify the user to run under\n"
         "    -g GROUP     specify the group to run under\n"
         "    -C DIR       specify the working directory\n"
         "    -D           daemon mode\n"
         "    -s ARCH      ignore specified architecture\n"
         "    -i CNTS:PROB ignore specified problem\n"
         "    -r           ignore rejudging\n"
         "    -p DIR       specify alternate name for super-run directory\n"
         "    -a           write log file to an alternate location\n"
         "    -m DIR       specify a directory for file mirroring\n"
         "    -e DIR1=DIR2 remap directory DIR1 to directory DIR2\n"
         "    -ht TIMEOUT  machine halt timeout (in minutes)\n"
         "    -hc CMD      machine halt command\n"
         "    -hb          enable heartbeat mode (default)\n"
         "    -nhb         disable heartbeat mode\n"
         "    -hi          set super_run id\n",
         program_name, program_name);
  exit(0);
}

static void write_version(void) __attribute__((noreturn));
static void
write_version(void)
{
  printf("%s %s, compiled %s\n", program_name, compile_version, compile_date);
  exit(0);
}

static void
create_directories(void)
{
#if defined EJUDGE_RUN_SPOOL_DIR
  snprintf(super_run_server_path, sizeof(super_run_server_path), "%s/%s", EJUDGE_RUN_SPOOL_DIR, run_server_id);
  os_MakeDirPath(super_run_server_path, 0775);
  snprintf(super_run_spool_path, sizeof(super_run_spool_path), "%s/%s", super_run_server_path, "queue");
  snprintf(super_run_exe_path, sizeof(super_run_exe_path), "%s/%s", super_run_server_path, "exe");
  if (heartbeat_mode) {
    snprintf(super_run_heartbeat_path, sizeof(super_run_heartbeat_path), "%s/%s", super_run_server_path, "heartbeat");
  }
#else
  snprintf(super_run_spool_path, sizeof(super_run_spool_path), "%s/var/%s", super_run_path, "queue");
  snprintf(super_run_exe_path, sizeof(super_run_exe_path), "%s/var/%s", super_run_path, "exe");
  if (heartbeat_mode) {
    snprintf(super_run_heartbeat_path, sizeof(super_run_heartbeat_path), "%s/var/%s", super_run_path, "heartbeat");
  }
#endif
  os_MakeDirPath(super_run_spool_path, 0777);
  os_MakeDirPath(super_run_exe_path, 0777);
  make_all_dir(super_run_spool_path, 0777);
  if (heartbeat_mode) {
    os_MakeDirPath(super_run_heartbeat_path, 0777);
    make_all_dir(super_run_heartbeat_path, 0777);
  }
}

static int
create_working_directories(serve_state_t state)
{
  struct section_global_data *global = state->global;
  const unsigned char *hostname = os_NodeName();
  int pid = getpid();
  int retval = 0;

#if defined EJUDGE_LOCAL_DIR
  if (!global->run_work_dir || !global->run_work_dir[0]) {
    usprintf(&global->run_work_dir, "%s/%s/work", EJUDGE_LOCAL_DIR, super_run_dir);
  }
  if (!global->run_check_dir || !global->run_check_dir[0]) {
    usprintf(&global->run_check_dir, "%s/%s/check", EJUDGE_LOCAL_DIR, super_run_dir);
  }
#endif
  if (!global->run_work_dir || !global->run_work_dir[0]) {
    usprintf(&global->run_work_dir, "%s/var/work", super_run_path);
  }
  if (!global->run_check_dir || !global->run_check_dir[0]) {
    usprintf(&global->run_check_dir, "%s/var/check", super_run_path);
  }

  usprintf(&global->run_work_dir, "%s/%s_%d", global->run_work_dir, hostname, pid);
  usprintf(&global->run_check_dir, "%s/%s_%d", global->run_check_dir, hostname, pid);

  if (os_MakeDirPath(global->run_work_dir, 0755) < 0) {
    err("failed to create working directory '%s'", global->run_work_dir);
    retval = -1;
  }
  if (os_MakeDirPath(global->run_check_dir, 0755) < 0) {
    err("failed to create check directory '%s'", global->run_check_dir);
    retval = -1;
  }

  return retval;
}

static void
remove_working_directory(serve_state_t state)
{
  struct section_global_data *global = state->global;

  if (!global) return;
  if (global->run_work_dir && global->run_work_dir[0]) {
    remove_directory_recursively(global->run_work_dir, 0);
  }
  if (global->run_check_dir && global->run_check_dir[0]) {
    remove_directory_recursively(global->run_check_dir, 0);
  }
}

static void
collect_sections(serve_state_t state)
{
  struct generic_section_config *p;
  struct section_global_data *global = NULL;
  struct section_tester_data    *t;
  int abstr_tester_count = 0, i;
  unsigned char start_path[PATH_MAX];

  for (p = state->config; p; p = p->next) {
    if (!strcmp(p->name, "") || !strcmp(p->name, "global")) {
      if (state->global != NULL) {
        fatal("duplicate global section");
      }
      global = state->global = (struct section_global_data*) p;
    } else if (!strcmp(p->name, "problem")) {
      fatal("section [problem] is not supported");
    } else if (!strcmp(p->name, "language")) {
      fatal("section [language] is not supported");
    } else if (!strcmp(p->name, "tester")) {
      t = (struct section_tester_data *) p;
      if (t->abstract <= 0 && t->any <= 0) {
        fatal("problem-specific [tester] section is not supported");
      }
      if (t->abstract > 0) {
        ++abstr_tester_count;
      }
    }
  }

  if (!global) {
    fatal("no global section");
  }
  if (abstr_tester_count <= 0) {
    fatal("no abstract testers");
  }

  state->max_abstr_tester = abstr_tester_count;
  XCALLOC(state->abstr_testers, abstr_tester_count);

  for (p = state->config, i = 0; p; p = p->next) {
    if (!strcmp(p->name, "tester")) {
      t = (struct section_tester_data *) p;
      if (t->abstract > 0) {
        state->abstr_testers[i++] = t;
      }
    }
  }

#if defined EJUDGE_SCRIPT_DIR
  if (!global->script_dir || !global->script_dir[0]) {
    xstrdup3(&global->script_dir, EJUDGE_SCRIPT_DIR);
  }
  if (!global->ejudge_checkers_dir || !global->ejudge_checkers_dir[0]) {
    usprintf(&global->ejudge_checkers_dir, "%s/checkers", EJUDGE_SCRIPT_DIR);
  }
#endif

  if (!global->ejudge_checkers_dir || !global->ejudge_checkers_dir[0]) {
    fatal("ejudge_checkers_dir parameter is undefined");
  }

  for (i = 0; i < state->max_abstr_tester; ++i) {
    if (!(t = state->abstr_testers[i])) continue;

    if (t->memory_limit_type) {
      t->memory_limit_type_val = prepare_parse_memory_limit_type(t->memory_limit_type);
      if (t->memory_limit_type_val < 0) {
        fatal("invalid memory_limit_type `%s'", t->memory_limit_type);
      }
    }

    if (t->secure_exec_type) {
      t->secure_exec_type_val = prepare_parse_secure_exec_type(t->secure_exec_type);
      if (t->secure_exec_type_val < 0) {
        fatal("invalid secure_exec_type `%s'", t->secure_exec_type);
      }
    }

    if (t->start_cmd && t->start_cmd[0]) {
      if (!os_IsAbsolutePath(t->start_cmd)) {
        snprintf(start_path, sizeof(start_path), "%s", t->start_cmd);
        if (ejudge_config && ejudge_config->compile_home_dir) {
          pathmake2(start_path, ejudge_config->compile_home_dir,
                    "/", "scripts", "/", start_path, NULL);
        } else if (ejudge_config && ejudge_config->contests_home_dir) {
          pathmake2(start_path, ejudge_config->contests_home_dir,
                    "/", "compile", "/", "scripts", "/", start_path, NULL);
        }
#if defined EJUDGE_CONTESTS_HOME_DIR
        else {
          pathmake2(start_path, EJUDGE_CONTESTS_HOME_DIR,
                    "/", "compile", "/", "scripts", "/", start_path, NULL);
        }
#endif
        if (access(start_path, X_OK) >= 0) {
          xstrdup3(&t->start_cmd, start_path);
        } else {
          if (!os_IsAbsolutePath(t->start_cmd)) {
            usprintf(&t->start_cmd, "%s/lang/%s", global->script_dir, t->start_cmd);
          }
        }
      }
    }
  }
}

static int
parse_ignored_problem(
        const unsigned char *arg,
        struct ignored_problem_info *info)
{
  // [ CONTEST-ID : PROBLEM-SHORT-NAME ]
  const unsigned char *c = arg;
  int x, n;
  unsigned char *s = NULL;

  info->contest_id = 0;

  if (!arg) return -1;
  while (isspace(*c)) ++c;
  if (!*c) return -1;
  if (isdigit(*c)) {
    if (sscanf(c, "%d%n", &x, &n) != 1) return -1;
    if (x < 0 || x > 1000000) return -1;
    info->contest_id = x;
    c += n;
    while (isspace(*c)) ++c;
  }
  if (*c != ':') return -1;
  ++c;
  while (isspace(*c)) ++c;
  if (!*c) return 0;
  s = (unsigned char*) xmalloc((strlen(arg) + 1) * sizeof(*s));
  info->short_name = s;
  while (*c && !isspace(*c)) *s++ = *c++;
  *s = 0;
  while (isspace(*c)) ++c;
  if (*c) return -1;
  return 0;
}

static void
parse_remap_spec(const unsigned char *arg)
{
  const unsigned char *sep = strchr(arg, '=');
  if (!sep) fatal("'=' expected in remap specification");
  unsigned char *src_dir = xmemdup(arg, (sep - arg));
  unsigned char *dst_dir = xstrdup(sep + 1);
  int len1 = strlen(src_dir);
  int len2 = strlen(dst_dir);
  if (len1 <= 0) fatal("remap source dir cannot be empty");
  if (len2 <= 0) fatal("remap dest dir cannot be empty");
  if (!strcmp(src_dir, "/")) fatal("remap source dir cannot be '/'");
  if (!strcmp(dst_dir, "/")) fatal("remap dest dir cannot be '/'");
  if (src_dir[0] != '/' || src_dir[len1 - 1] != '/') fatal("remap source dir must begin and end with '/'");
  if (dst_dir[0] != '/' || dst_dir[len2 - 1] != '/') fatal("remap dest dir must begin and end with '/'");
  if (remap_spec_u + 1 >= remap_spec_a) {
    if (!(remap_spec_a *= 2)) remap_spec_a = 8;
    remap_specs = xrealloc(remap_specs, remap_spec_a * sizeof(remap_specs[0]));
  }
  struct remap_spec *rs = &remap_specs[remap_spec_u++];
  rs->src_dir = src_dir;
  rs->dst_dir = dst_dir;
  rs->src_len = len1;
  rs->dst_len = len2;
  ++remap_spec_u;
  memset(&remap_specs[remap_spec_u], 0, sizeof(remap_specs[0]));
}

static void
create_configs(
        const unsigned char *super_run_path,
        const unsigned char *super_run_conf_path)
{
  unsigned char dir_path[PATH_MAX];
  FILE *f = NULL;

  if (os_MakeDirPath(super_run_path, 0775) < 0)
    fatal("cannot create directory '%s'", super_run_path);
  snprintf(dir_path, sizeof(dir_path), "%s/var", super_run_path);
  if (os_MakeDir(dir_path, 0775) < 0)
    fatal("cannot create directory '%s'", dir_path);
  snprintf(dir_path, sizeof(dir_path), "%s/conf", super_run_path);
  if (os_MakeDir(dir_path, 0775) < 0)
    fatal("cannot create directory '%s'", dir_path);

  if (!(f = fopen(super_run_conf_path, "w")))
    fatal("cannot open file '%s' for writing", super_run_conf_path);
  fprintf(f, "sleep_time = 1000\n\n");

  fprintf(f,
          "[tester]\n"
          "name = Generic\n"
          "arch = \"\"\n"
          "abstract\n"
          "no_core_dump\n"
          "enable_memory_limit_error\n"
          "kill_signal = KILL\n"
          "memory_limit_type = \"default\"\n"
          "secure_exec_type = \"static\"\n"
          "clear_env\n"
          "start_env = \"PATH=/usr/local/bin:/usr/bin:/bin\"\n"
          "start_env = \"LANG=en_US.UTF-8\"\n"
          "start_env = \"LC_CTYPE=en_US.UTF-8\"\n"
          "start_env = \"HOME\"\n\n");

  fprintf(f,
          "[tester]\n"
          "name = Linux-shared\n"
          "arch = \"linux-shared\"\n"
          "abstract\n"
          "no_core_dump\n"
          "enable_memory_limit_error\n"
          "kill_signal = KILL\n"
          "memory_limit_type = \"default\"\n"
          "secure_exec_type = \"dll\"\n"
          "clear_env\n"
          "start_env = \"PATH=/usr/local/bin:/usr/bin:/bin\"\n"
          "start_env = \"LANG=en_US.UTF-8\"\n"
          "start_env = \"LC_CTYPE=en_US.UTF-8\"\n"
          "start_env = \"HOME\"\n\n");

  fprintf(f,
          "[tester]\n"
          "name = Linux-shared-32\n"
          "arch = \"linux-shared-32\"\n"
          "abstract\n"
          "no_core_dump\n"
          "enable_memory_limit_error\n"
          "kill_signal = KILL\n"
          "memory_limit_type = \"default\"\n"
          "secure_exec_type = \"dll32\"\n"
          "clear_env\n"
          "start_env = \"PATH=/usr/local/bin:/usr/bin:/bin\"\n"
          "start_env = \"LANG=en_US.UTF-8\"\n"
          "start_env = \"LC_CTYPE=en_US.UTF-8\"\n"
          "start_env = \"HOME\"\n\n");

  fprintf(f,
          "[tester]\n"
          "name = Linux-java\n"
          "arch = \"java\"\n"
          "abstract\n"
          "no_core_dump\n"
          "kill_signal = TERM\n"
          "memory_limit_type = \"java\"\n"
          "secure_exec_type = \"java\"\n"
          "start_cmd = \"runjava\"\n"
          "start_env = \"LANG=en_US.UTF-8\"\n"
          "start_env = \"LC_CTYPE=en_US.UTF-8\"\n"
          "start_env = \"EJUDGE_PREFIX_DIR\"\n\n");

  fprintf(f,
          "[tester]\n"
          "name = Linux-msil\n"
          "arch = \"msil\"\n"
          "abstract\n"
          "no_core_dump\n"
          "kill_signal = TERM\n"
          "memory_limit_type = \"mono\"\n"
          "secure_exec_type = \"mono\"\n"
          "start_cmd = \"runmono\"\n"
          "start_env = \"LANG=C\"\n"
          "start_env = \"EJUDGE_PREFIX_DIR\"\n"
          "start_env = \"MONO_DEBUG=no-gdb-backtrace\"\n\n");

  fprintf(f, "[tester]\n"
          "name = DOSTester\n"
          "arch = dos\n"
          "abstract\n"
          "no_core_dump\n"
          "no_redirect\n"
          "ignore_stderr\n"
          "time_limit_adjustment\n"
          "is_dos\n"
          "kill_signal = KILL\n"
          "memory_limit_type = \"dos\"\n"
          "errorcode_file = \"retcode.txt\"\n"
          "start_cmd = \"dosrun3\"\n\n");

  fprintf(f, "[tester]\n"
          "name = Win32\n"
          "arch = win32\n"
          "abstract\n"
          "nwrun_spool_dir = \"win32_nwrun\"\n\n");

  fprintf(f,
          "[tester]\n"
          "name = Valgrind\n"
          "arch = \"valgrind\"\n"
          "abstract\n"
          "no_core_dump\n"
          "kill_signal = TERM\n"
          "memory_limit_type = \"valgrind\"\n"
          "secure_exec_type = \"valgrind\"\n"
          "clear_env\n"
          "start_cmd = \"runvg\"\n"
          "start_env = \"PATH=/usr/local/bin:/usr/bin:/bin\"\n"
          "start_env = \"LANG=en_US.UTF-8\"\n"
          "start_env = \"LC_CTYPE=en_US.UTF-8\"\n"
          "start_env = \"HOME\"\n\n");

  fprintf(f,
          "[tester]\n"
          "name = Dotnet\n"
          "arch = \"dotnet\"\n"
          "abstract\n"
          "no_core_dump\n"
          "kill_signal = TERM\n"
          "memory_limit_type = \"dotnet\"\n"
          "secure_exec_type = \"dotnet\"\n"
          "clear_env\n"
          "start_cmd = \"rundotnet\"\n"
          "start_env = \"PATH=/usr/local/bin:/usr/bin:/bin\"\n"
          "start_env = \"LANG=en_US.UTF-8\"\n"
          "start_env = \"EJUDGE_PREFIX_DIR\"\n"
          "start_env = \"HOME\"\n\n");

  fclose(f); f = NULL;
}

const unsigned char * const
upgrade_times[] =
{
  "2012/05/01 00:00:00",
  "2012/05/26 00:00:00",
  "2012/06/21 00:00:00",
  "2012/11/05 00:00:00",
  "2015/11/01 00:00:00",
  "2016/01/18 18:00:00",
  "2016/05/15 00:00:00",
  "2019/11/16 00:00:00",

  NULL
};

static void
remove_if_upgrade_needed(const unsigned char *path)
{
  struct stat stb;

  if (!path || !*path) return;
  if (stat(path, &stb) < 0) return;
  if (!S_ISREG(stb.st_mode)) return;
  for (int i = 0; upgrade_times[i]; ++i) {
    time_t t = 0;
    if (xml_parse_date(NULL, 0, 0, 0, upgrade_times[i], &t) < 0) continue;
    if (t <= 0) continue;
    if (stb.st_mtime < t) {
      struct tm *tt = localtime(&t);
      unsigned char bak_path[PATH_MAX];
      snprintf(bak_path, sizeof(bak_path), "%s.%04d%02d%02d", path,
               tt->tm_year + 1900, tt->tm_mon + 1, tt->tm_mday);
      rename(path, bak_path);
      return;
    }
  }
}

static void
check_environment(void)
{
  const unsigned char *s;
  // AWS_INSTANCE_ID AWS_LOCAL_HOSTNAME AWS_LOCAL_IP AWS_PUBLIC_HOSTNAME AWS_PUBLIC_IP
  if ((s = getenv("AWS_INSTANCE_ID")) && *s) {
    instance_id = xstrdup(s);
  }
  if ((s = getenv("AWS_LOCAL_HOSTNAME")) && *s) {
    local_hostname = xstrdup(s);
  }
  if ((s = getenv("AWS_LOCAL_IP")) && *s) {
    local_ip = xstrdup(s);
  }
  if ((s = getenv("AWS_PUBLIC_HOSTNAME")) && *s) {
    public_hostname = xstrdup(s);
  }
  if ((s = getenv("AWS_PUBLIC_IP")) && *s) {
    public_ip = xstrdup(s);
  }
  if ((s = getenv("EJ_SUPER_RUN_ID")) && *s) {
    xfree(super_run_id);
    super_run_id = xstrdup(s);
  }
}

static void
make_super_run_name(void)
{
  char *text = NULL;
  size_t size = 0;
  FILE *f = open_memstream(&text, &size);
  if (super_run_id) {
    fprintf(f, "%s", super_run_id);
    if (instance_id && public_hostname) {
      fprintf(f, " (%s, %s)", instance_id, public_hostname);
    } else if (instance_id) {
      fprintf(f, " (%s)", instance_id);
    } else if (public_hostname) {
      fprintf(f, " (%s)", public_hostname);
    }
  } else if (instance_id) {
    fprintf(f, "%s", instance_id);
    if (public_hostname) {
      fprintf(f, " (%s)", public_hostname);
    }
  } else if (public_hostname) {
    fprintf(f, "%s", public_hostname);
  }
  fclose(f); f = NULL;
  if (text && *text) {
    super_run_name = text; text = NULL;
  } else if (text) {
    xfree(text); text = NULL;
  }

  const unsigned char *basename = NULL;
  if (super_run_id) {
    basename = super_run_id;
  } else if (instance_id) {
    basename = instance_id;
  } else if (public_hostname) {
    basename = public_hostname;
  } else if (local_hostname) {
    basename = local_hostname;
  } else {
    basename = os_NodeName();
  }

  unsigned char status_buf[1024];
  snprintf(status_buf, sizeof(status_buf), "%s.%d", basename, getpid());
  status_file_name = xstrdup(status_buf);
}

int
main(int argc, char *argv[])
{
  char **argv_restart = 0;
  int argc_restart = 0;
  int cur_arg = 1;
  int pid_count;
  int *pids = NULL;
  unsigned char ejudge_xml_path[PATH_MAX];
  serve_state_t state = &serve_state;
  int retval = 0;
  int restart_mode = 0, alternate_log_mode = 0;
  const unsigned char *user = NULL, *group = NULL, *workdir = NULL;
  int halt_timeout = 0, halt_requested = 0;
  unsigned char *halt_command = NULL;
  unsigned char *reboot_command = NULL;
  int disable_stack_trace = 0;

  signal(SIGPIPE, SIG_IGN);

  program_name = os_GetBasename(argv[0]);
  start_set_self_args(argc, argv);
  XCALLOC(argv_restart, argc + 2);
  argv_restart[argc_restart++] = argv[0];
  ejudge_xml_path[0] = 0;

  XCALLOC(ignored_archs, argc);
  XCALLOC(ignored_problems, argc);

  while (cur_arg < argc) {
    if (!strcmp(argv[cur_arg], "--help")) {
      write_help();
    } else if (!strcmp(argv[cur_arg], "--version")) {
      write_version();
    } else if (!strcmp(argv[cur_arg], "-u")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -u");
      user = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-g")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -g");
      group = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-C")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -C");
      workdir = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-D")) {
      daemon_mode = 1;
      ++cur_arg;
    } else if (!strcmp(argv[cur_arg], "-R")) {
      restart_mode = 1;
      ++cur_arg;
    } else if (!strcmp(argv[cur_arg], "-nst")) {
      disable_stack_trace = 1;
      ++cur_arg;
    } else if (!strcmp(argv[cur_arg], "-s")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -s");
      ignored_archs[ignored_archs_count++] = xstrdup(argv[cur_arg + 1]);
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-a")) {
      argv_restart[argc_restart++] = argv[cur_arg];
      alternate_log_mode = 1;
      ++cur_arg;
    } else if (!strcmp(argv[cur_arg], "-hb")) {
      argv_restart[argc_restart++] = argv[cur_arg];
      heartbeat_mode = 1;
      ++cur_arg;
    } else if (!strcmp(argv[cur_arg], "-nhb")) {
      argv_restart[argc_restart++] = argv[cur_arg];
      heartbeat_mode = 0;
      ++cur_arg;
    } else if (!strcmp(argv[cur_arg], "-r")) {
      argv_restart[argc_restart++] = argv[cur_arg];
      ignore_rejudge = 1;
      ++cur_arg;
    } else if (!strcmp(argv[cur_arg], "-v")) {
      argv_restart[argc_restart++] = argv[cur_arg];
      verbose_mode = 1;
      ++cur_arg;
    } else if (!strcmp(argv[cur_arg], "-p")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -p");
      xfree(super_run_dir); super_run_dir = NULL;
      super_run_dir = xstrdup(argv[cur_arg + 1]);
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-d")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -d");
      xfree(run_server_id); run_server_id = NULL;
      run_server_id = xstrdup(argv[cur_arg + 1]);
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-m")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -m");
      xfree(mirror_dir); mirror_dir = NULL;
      mirror_dir = xstrdup(argv[cur_arg + 1]);
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "--local-cache")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for --local-cache");
      xfree(local_cache); local_cache = NULL;
      local_cache = xstrdup(argv[cur_arg + 1]);
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-i")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -i");
      if (parse_ignored_problem(argv[cur_arg + 1], &ignored_problems[ignored_problems_count++]) < 0) {
        fatal("invalid argument for -i: '%s'", argv[cur_arg + 1]);
      }
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-ht")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -ht");
      errno = 0;
      char *eptr = NULL;
      int val = strtol(argv[cur_arg + 1], &eptr, 10);
      if (*eptr || errno || val <= 0) {
        fatal("invalid argument for -ht: %s", argv[cur_arg + 1]);
      }
      if (val >= 100000) val = 0; // infinity
      halt_timeout = val * 60;
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-hc")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -hc");
      xfree(halt_command); halt_command = NULL;
      halt_command = xstrdup(argv[cur_arg + 1]);
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-rc")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -rc");
      xfree(reboot_command); reboot_command = NULL;
      reboot_command = xstrdup(argv[cur_arg + 1]);
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-hi")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -hi");
      xfree(super_run_id); super_run_id = NULL;
      super_run_id = xstrdup(argv[cur_arg + 1]);
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-e")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -e");
      parse_remap_spec(argv[cur_arg + 1]);
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "--agent")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for --agent");
      xfree(agent_name);
      agent_name = xstrdup(argv[cur_arg + 1]);
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "--instance-id")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for --instance-id");
      xfree(agent_instance_id);
      agent_instance_id = xstrdup(argv[cur_arg + 1]);
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "--ip")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for --ip");
      xfree(ip_address);
      ip_address = xstrdup(argv[cur_arg + 1]);
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-x")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -x");
      errno = 0;
      char *ep = NULL;
      long val = strtol(argv[cur_arg + 1], &ep, 10);
      if (errno || *ep || ep == argv[cur_arg + 1] || val < 0 || (int) val != val)
        fatal("invalid argument for -x");
      state->exec_user_serial = val;
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else {
      fatal("invalid command line parameter");
    }
  }

  argv_restart[argc_restart++] = "-R";

  argv_restart[argc_restart] = NULL;
  start_set_args(argv_restart);
  if (disable_stack_trace <= 0) {
    start_enable_stacktrace(NULL);
  }

  if (halt_command) {
    master_down_enabled = 1;
  }
  if (reboot_command) {
    master_reboot_enabled = 1;
  }
  master_stop_enabled = 1;

  check_environment();

  if (!(host_names = ejudge_get_host_names())) {
    fatal("cannot obtain the list of host names");
  }
  if (!host_names[0]) {
    fatal("cannot determine the name of the host");
  }

  if (super_run_dir && !*super_run_dir) {
    xfree(super_run_dir); super_run_dir = NULL;
  }
  if (run_server_id && !*run_server_id) {
    xfree(run_server_id); run_server_id = NULL;
  }
  xfree(queue_name); queue_name = NULL;

  if (!super_run_dir) {
    // default zero-setup mode
    if (!run_server_id) {
      const unsigned char *s = getenv("EJ_RUN_SERVER_ID");
      if (s && *s) {
        run_server_id = xstrdup(s);
      }
    }
    if (!run_server_id) {
      const unsigned char *s = os_NodeName();
      if (s && *s) {
        run_server_id = xstrdup(s);
      }
    }
    if (!run_server_id) {
      run_server_id = xstrdup("localhost");
    }
    super_run_dir = xstrdup(SUPER_RUN_DIRECTORY);
  } else if (super_run_dir && !run_server_id) {
    run_server_id = xstrdup(super_run_dir);
  } else {
  }
  queue_name = xstrdup(run_server_id);

  if (!ejudge_xml_path[0]) {
#if defined EJUDGE_CONTESTS_HOME_DIR
    contests_home_dir = EJUDGE_CONTESTS_HOME_DIR;
#endif
    if (!contests_home_dir) {
      fatal("CONTESTS_HOME_DIR is undefined");
    }
#if defined EJUDGE_XML_PATH
    snprintf(ejudge_xml_path, sizeof(ejudge_xml_path), "%s", EJUDGE_XML_PATH);
#endif
    if (!ejudge_xml_path[0]) {
      snprintf(ejudge_xml_path, sizeof(ejudge_xml_path), "%s/conf/ejudge.xml", contests_home_dir);
    }
  }

  ejudge_config = ejudge_cfg_parse(ejudge_xml_path, 1);
  if (!ejudge_config) return 1;

  int parallelism = ejudge_cfg_get_host_option_int(ejudge_config, host_names, "parallelism", 1, 0);
  if (parallelism <= 0 || parallelism > 128) {
    fatal("invalid value of parallelism host option");
  }

  if ((pid_count = start_find_all_processes("ej-super-run", NULL, &pids)) < 0) {
    fatal("cannot get the list of processes");
  }
  if (pid_count >= parallelism) {
    fprintf(stderr, "%d", pids[0]);
    for (int i = 1; i < pid_count; ++i) {
      fprintf(stderr, " %d", pids[i]);
    }
    fprintf(stderr, "\n");
    fatal("%d processes are already running", pid_count);
  }

  info("%s %s, compiled %s", program_name, compile_version, compile_date);

  if (!contests_home_dir && ejudge_config->contests_home_dir) {
    contests_home_dir = ejudge_config->contests_home_dir;
  }

  if (!os_IsAbsolutePath(contests_home_dir)) {
    fatal("contests home directory is not an absolute path");
  }
  if (os_IsFile(contests_home_dir) != OSPK_DIR) {
    fatal("contests home directory is not a directory");
  }
  snprintf(super_run_path, sizeof(super_run_path), "%s/%s", contests_home_dir, super_run_dir);
  snprintf(super_run_conf_path, sizeof(super_run_conf_path), "%s/conf/super-run.cfg", super_run_path);

  super_run_log_path[0] = 0;
  if (alternate_log_mode) {
#if defined EJUDGE_LOCAL_DIR
    snprintf(super_run_log_path, sizeof(super_run_log_path),
      "%s/%s/ej-super-run.log", EJUDGE_LOCAL_DIR, super_run_dir);
#endif
    if (!super_run_log_path[0]) {
      snprintf(super_run_log_path, sizeof(super_run_log_path),
               "%s/var/ej-super-run.log", super_run_path);
    }
  } else {
    snprintf(super_run_log_path, sizeof(super_run_log_path), "%s/var/ej-super-run.log", contests_home_dir);
  }

  remove_if_upgrade_needed(super_run_conf_path);

  if (os_IsFile(super_run_conf_path) < 0) {
    create_configs(super_run_path, super_run_conf_path);
    if (os_IsFile(super_run_path) != OSPK_DIR) {
      fatal("path '%s' must be a directory", super_run_path);
    }
  }

  if (!workdir || *workdir) {
    workdir = super_run_path;
  }
  if (start_prepare(user, group, workdir) < 0) return 1;

  create_directories();

  if (!strcasecmp(EJUDGE_CHARSET, "UTF-8")) utf8_mode = 1;

  state->config = prepare_parse_config_file(super_run_conf_path, NULL);
  if (state->config == NULL) {
    fatal("config file parsing failed");
  }
  collect_sections(state);

  if (daemon_mode) {
    if (start_daemon(super_run_log_path) < 0) {
      retval = 1;
      goto cleanup;
    }
  } else if (restart_mode) {
    if (start_open_log(super_run_log_path) < 0) {
      retval = 1;
      goto cleanup;
    }
  }

  if (create_working_directories(state) < 0) {
    retval = 1;
    goto cleanup;
  }

  make_super_run_name();

  if (do_loop(state, halt_timeout, &halt_requested) < 0) {
    retval = 1;
  }

  if (halt_requested) {
    info("DOWN due to timeout");
    start_shutdown(halt_command);
  }
  if (pending_down_flag) {
    info("DOWN request from the server");
    start_shutdown(halt_command);
  }
  if (pending_reboot_flag) {
    info("REBOOT request from the server");
    start_shutdown(reboot_command);
  }

  if (interrupt_restart_requested()) start_restart();

cleanup:
  remove_working_directory(state);
  return retval;
}
