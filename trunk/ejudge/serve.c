/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2000-2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "runlog.h"
#include "parsecfg.h"
#include "teamdb.h"
#include "prepare.h"
#include "prepare_vars.h"
#include "html.h"
#include "clarlog.h"
#include "protocol.h"
#include "userlist.h"
#include "sha.h"
#include "l10n.h"
#include "archive_paths.h"
#include "team_extra.h"
#include "printing.h"
#include "diff.h"
#include "compile_packet.h"
#include "run_packet.h"
#include "curtime.h"
#include "xml_utils.h"
#include "job_packet.h"

#include "misctext.h"
#include "base64.h"
#include "pathutl.h"
#include "errlog.h"
#include "fileutl.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>
#include <reuse/number_io.h>
#include <reuse/format_io.h>
#include <reuse/exec.h>

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdarg.h>
#include <ctype.h>
#include <pwd.h>

#ifndef EJUDGE_CHARSET
#define EJUDGE_CHARSET EJUDGE_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#include <locale.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

#ifndef XALLOCAZ
#define XALLOCAZ(p,s) (XALLOCA((p),(s)),XMEMZERO((p),(s)))
#endif

#define PACKET_NAME_SIZE SERVE_PACKET_NAME_SIZE
#define MAX_EXPECTED_LEN MAX_SERVE_PACKET_LEN

// server connection states
enum
  {
    STATE_READ_CREDS,
    STATE_READ_DATA,
    STATE_READ_FDS,
    STATE_AUTOCLOSE,
  };
struct client_state
{
  struct client_state *next;
  struct client_state *prev;

  int id;
  int fd;

  /* write status */
  int write_len;
  int written;
  unsigned char *write_buf;

  /* read status */
  int read_state;
  int expected_len;
  int read_len;
  unsigned char *read_buf;
  int processed;

  int state;

  // some peer information
  int peer_pid;
  int peer_uid;
  int peer_gid;

  int user_id;
  int priv_level;
  ej_cookie_t cookie;
  ej_ip_t ip;
  int ssl;

  // passed file descriptors
  int client_fds[2];
};
static struct client_state *client_first;
static struct client_state *client_last;
static int                  client_serial_id = 1;

static int cmdline_socket_fd = -1;
static time_t last_activity_time = 0;

clarlog_state_t clarlog_state;

static struct client_state *
client_new_state(int fd)
{
  struct client_state *p;

  XCALLOC(p, 1);
  p->id = client_serial_id++;
  if (!client_last) {
    p->next = p->prev = 0;
    client_first = client_last = p;
  } else {
    p->next = 0;
    p->prev = client_last;
    client_last->next = p;
    client_last = p;
  }

  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
  p->fd = fd;
  p->user_id = -1;
  p->client_fds[0] = -1;
  p->client_fds[1] = -1;

  return p;
}
static struct client_state *
client_disconnect(struct client_state *p, int force_flag)
{
  ASSERT(p);

  if (!force_flag && p->state != STATE_AUTOCLOSE && p->write_len > 0) {
    p->state = STATE_AUTOCLOSE;
  }

  fcntl(p->fd, F_SETFL, fcntl(p->fd, F_GETFL) & ~O_NONBLOCK);
  close(p->fd);
  if (p->write_buf) xfree(p->write_buf);
  if (p->read_buf) xfree(p->read_buf);
  if (p->client_fds[0] >= 0) close(p->client_fds[0]);
  if (p->client_fds[1] >= 0) close(p->client_fds[1]);

  if (p->prev) {
    p->prev->next = p->next;
  } else {
    client_first = p->next;
  }
  if (p->next) {
    p->next->prev = p->prev;
  } else {
    client_last = p->prev;
  }
  xfree(p);
  return 0;
}

/* max. packet size */
#define MAX_PACKET_SIZE 256
typedef char packet_t[MAX_PACKET_SIZE];

static time_t current_time;

static time_t contest_start_time;
static time_t contest_sched_time;
static time_t contest_duration;
static time_t contest_stop_time;
static int clients_suspended;
static int testing_suspended;
static int printing_suspended;
static int olympiad_judging_mode;
static time_t stat_reported_before;
static time_t stat_report_time;

static int socket_fd = -1;
static unsigned char *socket_name = 0;
static int interrupt_signaled = 0;
static int forced_mode = 0;
static int initialize_mode = 0;

struct server_cmd
{
  char const  *cmd;
  int        (*func)(char const *, packet_t const, void *);
  void        *ptr;
};

/* remove queue stuff */
struct remove_queue_item
{
  struct remove_queue_item *next;

  time_t rmtime;
  int    token;
  int    is_dir;
  path_t path;
};

static struct remove_queue_item *remove_queue_first, *remove_queue_last;
static int remove_queue_token = 1;

static int
remove_queue_add(time_t rmtime, int is_dir, path_t path)
{
  struct remove_queue_item *p = 0;

  XCALLOC(p, 1);
  p->token = remove_queue_token++;
  p->rmtime = rmtime;
  p->is_dir = is_dir;
  pathcpy(p->path, path);

  if (!remove_queue_last) {
    remove_queue_first = remove_queue_last = p;
  } else {
    remove_queue_last->next = p;
    remove_queue_last = p;
  }

  return p->token;
}

static void
interrupt_signal(int s)
{
  interrupt_signaled = 1;
}

static void
update_standings_file(int force_flag)
{
  time_t start_time, stop_time, duration;
  int p = 0;
  int accepting_mode = 0;

  run_get_times(&start_time, 0, &duration, &stop_time);

  while (1) {
    if (global->virtual) break;
    if (force_flag) break;
    if (!global->autoupdate_standings) return;
    if (!duration) break;
    if (!global->board_fog_time) break;

    ASSERT(current_time >= start_time);
    ASSERT(global->board_fog_time >= 0);
    ASSERT(global->board_unfog_time >= 0);
    
    p = run_get_fog_period(current_time, global->board_fog_time,
                           global->board_unfog_time);
    if (p == 1) return;
    break;
  }

  if (!global->virtual) {
    p = run_get_fog_period(current_time, global->board_fog_time,
                           global->board_unfog_time);
  }
  l10n_setlocale(global->standings_locale_id);
  if (global->score_system_val == SCORE_OLYMPIAD && !olympiad_judging_mode)
    accepting_mode = 1;
  write_standings(global->status_dir, global->standings_file_name,
                  global->users_on_page,
                  global->stand_header_txt, global->stand_footer_txt,
                  accepting_mode);
  if (global->stand2_file_name[0]) {
    write_standings(global->status_dir, global->stand2_file_name, 0,
                    global->stand2_header_txt, global->stand2_footer_txt,
                    accepting_mode);
  }
  l10n_setlocale(0);
  if (global->virtual) return;
  switch (p) {
  case 0:
    global->start_standings_updated = 1;
    break;
  case 1:
    global->fog_standings_updated = 1;
    break;
  case 2:
    global->unfog_standings_updated = 1;
    break;
  }
}

static void
update_public_log_file(void)
{
  static time_t last_update = 0;
  time_t start_time, stop_time, duration;
  int p;

  if (!global->plog_update_time) return;
  if (current_time < last_update + global->plog_update_time) return;

  run_get_times(&start_time, 0, &duration, &stop_time);

  while (1) {
    if (!duration) break;
    if (!global->board_fog_time) break;

    ASSERT(current_time >= start_time);
    ASSERT(global->board_fog_time >= 0);
    ASSERT(global->board_unfog_time >= 0);
    
    p = run_get_fog_period(current_time, global->board_fog_time,
                           global->board_unfog_time);
    if (p == 1) return;
    break;
  }

  l10n_setlocale(global->standings_locale_id);
  write_public_log(global->status_dir, global->plog_file_name,
                   global->plog_header_txt, global->plog_footer_txt);
  last_update = current_time;
  l10n_setlocale(0);
}

static void
do_update_xml_log(char const *name, int external_mode)
{
  struct run_header rhead;
  int rtotal;
  const struct run_entry *rentries;
  path_t path1;
  path_t path2;
  FILE *fout;

  run_get_header(&rhead);
  rtotal = run_get_total();
  rentries = run_get_entries_ptr();

  snprintf(path1, sizeof(path1), "%s/in/%s.tmp", global->status_dir, name);
  snprintf(path2, sizeof(path2), "%s/dir/%s", global->status_dir, name);

  if (!(fout = fopen(path1, "w"))) {
    err("update_xml_log: cannot open %s", path1);
    return;
  }
  unparse_runlog_xml(fout, &rhead, rtotal, rentries, external_mode,
                     current_time);
  if (ferror(fout)) {
    err("update_xml_log: write error");
    fclose(fout);
    unlink(path1);
    return;
  }
  if (fclose(fout) < 0) {
    err("update_xml_log: write error");
    unlink(path1);
    return;
  }
  if (rename(path1, path2) < 0) {
    err("update_xml_log: rename %s -> %s failed", path1, path2);
    unlink(path1);
    return;
  }
}

static void
update_external_xml_log(void)
{
  static time_t last_update = 0;

  if (!global->external_xml_update_time) return;
  if (current_time < last_update + global->external_xml_update_time) return;
  last_update = current_time;
  do_update_xml_log("external.xml", 1);
}

static void
update_internal_xml_log(void)
{
  static time_t last_update = 0;

  if (!global->internal_xml_update_time) return;
  if (current_time < last_update + global->internal_xml_update_time) return;
  last_update = current_time;
  do_update_xml_log("internal.xml", 0);
}

static int
update_status_file(int force_flag)
{
  static time_t prev_status_update = 0;
  struct prot_serve_status_v2 status;
  time_t t1, t2, t3, t4;
  int p;

  if (!force_flag && current_time <= prev_status_update) return 0;

  memset(&status, 0, sizeof(status));
  status.magic = PROT_SERVE_STATUS_MAGIC_V2;

  status.cur_time = current_time;
  run_get_times(&t1, &t2, &t3, &t4);
  status.start_time = t1;
  status.sched_time = t2;
  status.duration = t3;
  status.stop_time = t4;
  status.total_runs = run_get_total();
  status.total_clars = clar_get_total(clarlog_state);
  status.clars_disabled = global->disable_clars;
  status.team_clars_disabled = global->disable_team_clars;
  status.score_system = global->score_system_val;
  status.clients_suspended = clients_suspended;
  status.testing_suspended = testing_suspended;
  status.download_interval = global->team_download_time / 60;
  status.is_virtual = global->virtual;
  status.olympiad_judging_mode = olympiad_judging_mode;
  status.continuation_enabled = global->enable_continue;
  status.printing_enabled = global->enable_printing;
  status.printing_suspended = printing_suspended;
  status.always_show_problems = global->always_show_problems;
  if (status.start_time && status.duration && global->board_fog_time > 0
      && !status.is_virtual) {
    status.freeze_time = status.start_time + status.duration - global->board_fog_time;
    if (status.freeze_time < status.start_time) {
      status.freeze_time = status.start_time;
    }
  }
  if (!status.duration && global->contest_finish_time_d)
    status.finish_time = global->contest_finish_time_d;
  //if (status.duration) status.continuation_enabled = 0;

  if (!global->virtual) {
    p = run_get_fog_period(current_time,
                           global->board_fog_time, global->board_unfog_time);
    if (p == 1 && global->autoupdate_standings) {
      status.standings_frozen = 1;
    }
  }

  status.stat_reported_before = stat_reported_before;
  status.stat_report_time = stat_report_time;

  generic_write_file((char*) &status, sizeof(status), SAFE,
                     global->status_dir, "status", "");
  prev_status_update = current_time;
  return 1;
}

static void
load_status_file(void)
{
  struct prot_serve_status_v2 status;
  size_t stat_len = 0;
  char *ptr = 0;

  if (generic_read_file(&ptr, 0, &stat_len, 0, global->status_dir,
                        "dir/status", "") < 0) return;
  if (stat_len != sizeof(status)) {
    info("load_status_file: length %zu does not match %zu",
         stat_len, sizeof(status));
    xfree(ptr);
    return;
  }
  memcpy(&status, ptr, sizeof(status));
  xfree(ptr);
  if (status.magic != PROT_SERVE_STATUS_MAGIC_V2) {
    info("load_status_file: bad magic value");
    return;
  }

  clients_suspended = status.clients_suspended;
  info("load_status_file: clients_suspended = %d", clients_suspended);
  testing_suspended = status.testing_suspended;
  info("load_status_file: testing_suspended = %d", testing_suspended);
  olympiad_judging_mode = status.olympiad_judging_mode;
  info("load_status_file: olympiad_judging_mode = %d", olympiad_judging_mode);
  printing_suspended = status.printing_suspended;
  info("load_status_file: printing_suspended = %d", printing_suspended);
  stat_reported_before = status.stat_reported_before;
  stat_report_time = status.stat_report_time;
}

static int
check_cnts_caps(int user_id, int bit)
{
  const struct contest_desc *cnts = 0;
  opcap_t caps;
  int errcode = 0;
  unsigned char const *login = 0;

  if ((errcode = contests_get(global->contest_id, &cnts)) < 0) {
    err("contests_get(%d): %s", global->contest_id,
        contests_strerror(-errcode));
    return 0;
  }
  login = teamdb_get_login(user_id);
  if (!login || !*login) return 0;

  if (opcaps_find(&cnts->capabilities, login, &caps) < 0) return 0;
  if (opcaps_check(caps, bit) < 0) return 0;
  return 1;
}

static int
get_cnts_caps(int user_id, opcap_t *out_caps)
{
  const struct contest_desc *cnts = 0;
  opcap_t caps;
  int errcode = 0;
  unsigned char const *login = 0;

  if ((errcode = contests_get(global->contest_id, &cnts)) < 0) {
    err("contests_get(%d): %s", global->contest_id,
        contests_strerror(-errcode));
    return -1;
  }
  login = teamdb_get_login(user_id);
  if (!login || !*login) return -1;

  if (opcaps_find(&cnts->capabilities, login, &caps) < 0) return -1;
  if (out_caps) *out_caps = caps;
  return 0;
}

static int
check_team_quota(int teamid, unsigned int size)
{
  int num;
  size_t total;

  if (size > global->max_run_size) return -1;
  run_get_team_usage(teamid, &num, &total);
  if (num > global->max_run_num || total + size > global->max_run_total)
    return -1;
  return 0;
}

static int
check_clar_qouta(int teamid, unsigned int size)
{
  int num;
  size_t total;

  if (size > global->max_clar_size) return -1;
  clar_get_team_usage(clarlog_state, teamid, &num, &total);
  if (num > global->max_clar_num || total + size > global->max_clar_total)
    return -1;
  return 0;
}

/* mode == 1 - from master, mode == 2 - from run */
static int
is_valid_status(int status, int mode)
{
  if (global->score_system_val == SCORE_OLYMPIAD) {
    switch (status) {
    case RUN_OK:
    case RUN_PARTIAL:
    case RUN_RUN_TIME_ERR:
    case RUN_TIME_LIMIT_ERR:
    case RUN_PRESENTATION_ERR:
    case RUN_WRONG_ANSWER_ERR:
    case RUN_ACCEPTED:
    case RUN_CHECK_FAILED:
    case RUN_MEM_LIMIT_ERR:
    case RUN_SECURITY_ERR:
      return 1;
    case RUN_COMPILE_ERR:
    case RUN_FULL_REJUDGE:
    case RUN_REJUDGE:
    case RUN_IGNORED:
    case RUN_DISQUALIFIED:
    case RUN_PENDING:
      if (mode != 1) return 0;
      return 1;
    default:
      return 0;
    }
  } else if (global->score_system_val == SCORE_KIROV) {
    switch (status) {
    case RUN_OK:
    case RUN_PARTIAL:
    case RUN_CHECK_FAILED:
      return 1;
    case RUN_COMPILE_ERR:
    case RUN_REJUDGE:
    case RUN_IGNORED:
    case RUN_DISQUALIFIED:
    case RUN_PENDING:
      if (mode != 1) return 0;
      return 1;
    default:
      return 0;
    }
  } else {
    switch (status) {
    case RUN_OK:
    case RUN_RUN_TIME_ERR:
    case RUN_TIME_LIMIT_ERR:
    case RUN_PRESENTATION_ERR:
    case RUN_WRONG_ANSWER_ERR:
    case RUN_CHECK_FAILED:
    case RUN_MEM_LIMIT_ERR:
    case RUN_SECURITY_ERR:
      return 1;
    case RUN_COMPILE_ERR:
    case RUN_REJUDGE:
    case RUN_IGNORED:
    case RUN_DISQUALIFIED:
    case RUN_PENDING:
      if (mode != 1) return 0;
      return 1;
    default:
      return 0;
    }
  }
}

static void
new_enqueue_reply(struct client_state *p, int msg_length, void const *msg)
{
  ASSERT(p);
  ASSERT(msg_length > 0);
  ASSERT(msg);

  if (p->write_len) {
    SWERR(("Server->client reply slot is busy!"));
  }
  p->write_buf = xmalloc(msg_length + 4);
  memcpy(p->write_buf, &msg_length, 4);
  memcpy(p->write_buf + 4, msg, msg_length);
  p->write_len = msg_length + 4;
}

static void
new_send_reply(struct client_state *p, short answer)
{
  struct prot_serve_packet pack;

  pack.id = answer;
  pack.magic = PROT_SERVE_PACKET_MAGIC;
  new_enqueue_reply(p, sizeof(pack), &pack);
}

static void
new_bad_packet(struct client_state *p, char const *format, ...)
{
  unsigned char msgbuf[1024];

  if (format && *format) {
    va_list args;

    va_start(args, format);
    vsnprintf(msgbuf, sizeof(msgbuf), format, args);
    va_end(args);
    err("%d: bad packet: %s", p->id, msgbuf);
  } else {
    err("%d: bad packet", p->id);
  }
  client_disconnect(p, 0);
}

static int
get_peer_local_user(struct client_state *p)
{
  ej_cookie_t cookie = 0;
  ej_ip_t ip = 0;
  int user_id = 0, priv_level = 0, ssl = 0;
  int r;

  if (p->user_id >= 0) return p->user_id;
  r = teamdb_get_uid_by_pid(p->peer_uid, p->peer_gid, p->peer_pid,
                            global->contest_id,
                            &user_id, &priv_level, &cookie, &ip, &ssl);
  if (r < 0) {
    // FIXME: what else can we do?
    err("%d: cannot get local user_id", p->id);
    client_disconnect(p, 0);
    return -1;
  }
  if (r >= 0 && !teamdb_lookup(user_id)) {
    err("%d: no local information about user %d", p->id, user_id);
    client_disconnect(p, 0);
    return -1;
  }
  p->user_id = user_id;
  p->priv_level = priv_level;
  p->cookie = cookie;
  p->ip = ip;
  p->ssl = ssl;
  info("%d: user_id is %d", p->id, user_id);
  return user_id;
}

static void
cmd_pass_descriptors(struct client_state *p, int len,
                     struct prot_serve_packet *pkt)
{
  if (len != sizeof(*pkt)) {
    new_bad_packet(p, "cmd_pass_descriptors: bad packet length: %d", len);
    return;
  }

  if (p->client_fds[0] >= 0 || p->client_fds[1] >= 0) {
    err("%d: cannot stack unprocessed client descriptors", p->id);
    new_send_reply(p, -SRV_ERR_PROTOCOL);
    return;
  }

  //if (get_peer_local_user(p) < 0) return;

  p->state = STATE_READ_FDS;
}

static void append_audit_log(int, struct client_state *, const char *, ...)
  __attribute__((format(printf, 3, 4)));
static void
append_audit_log(int run_id, struct client_state *p, const char *format, ...)
{
  unsigned char buf[16384];
  unsigned char tbuf[128];
  va_list args;
  struct tm *ltm;
  path_t audit_path;
  FILE *f;
  unsigned char *login;
  size_t buf_len;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);
  buf_len = strlen(buf);
  while (buf_len > 0 && isspace(buf[buf_len - 1])) buf[--buf_len] = 0;

  ltm = localtime(&current_time);
  snprintf(tbuf, sizeof(tbuf), "%04d/%02d/%02d %02d:%02d:%02d",
           ltm->tm_year + 1900, ltm->tm_mon + 1, ltm->tm_mday,
           ltm->tm_hour, ltm->tm_min, ltm->tm_sec);

  archive_make_write_path(audit_path, sizeof(audit_path),
                          global->audit_log_dir, run_id, 0, 0);
  if (archive_dir_prepare(global->audit_log_dir, run_id, 0, 1) < 0) return;
  if (!(f = fopen(audit_path, "a"))) return;

  fprintf(f, "Date: %s\n", tbuf);
  if (!p) {
    fprintf(f, "From: SYSTEM\n");
  } else if (p->user_id <= 0) {
    fprintf(f, "From: unauthentificated user\n");
  } else if (!(login = teamdb_get_login(p->user_id))) {
    fprintf(f, "From: user %d (login unknown)\n", p->user_id);
  } else {
    fprintf(f, "From: %s (uid %d)\n", login, p->user_id);
  }
  if (p) {
    fprintf(f, "Ip: %s\n", xml_unparse_ip(p->ip));
  }
  fprintf(f, "%s\n\n", buf);

  fclose(f);
}

static void
cmd_team_get_archive(struct client_state *p, int len,
                     struct prot_serve_pkt_get_archive *pkt)
{
  time_t last_time;
  path_t dirname, fullpath, linkpath, origpath;
  int total_runs, r, token, path_len, out_size, arch_flag;
  struct prot_serve_pkt_archive_path *out;
  struct run_entry re;

  if (get_peer_local_user(p) < 0) return;

  if (len != sizeof(*pkt)) {
    new_bad_packet(p, "team_get_archive: bad packet length: %d", len);
    return;
  }
  info("%d: team_get_archive: %d, %d, %d", p->id,
       pkt->user_id, pkt->contest_id, pkt->locale_id);
  if (global->contest_id <= 0) {
    new_send_reply(p, -SRV_ERR_NOT_SUPPORTED);
    err("%d: operation is not supported", p->id);
    return;
  }
  if (!teamdb_lookup(pkt->user_id)) {
    new_send_reply(p, -SRV_ERR_BAD_USER_ID);
    err("%d: bad user id", p->id);
    return;
  }
  if (pkt->contest_id != global->contest_id) {
    new_send_reply(p, -SRV_ERR_BAD_CONTEST_ID);
    err("%d: contest_id does not match", p->id);
    return;
  }
  if (p->user_id && pkt->user_id != p->user_id) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: pkt->user_id != p->user_id", p->id);
    return;
  }

  last_time = teamdb_get_archive_time(pkt->user_id);
  if (last_time + global->team_download_time > current_time) {
    new_send_reply(p, -SRV_ERR_DOWNLOAD_TOO_OFTEN);
    err("%d: download is too often", p->id);
    return;
  }

  snprintf(dirname, sizeof(dirname), "runs_%d_%d",
           global->contest_id, pkt->user_id);
  snprintf(fullpath, sizeof(fullpath), "%s/%s", global->var_dir, dirname);
  if (mkdir(fullpath, 0755) < 0) {
    new_send_reply(p, -SRV_ERR_TRY_AGAIN);
    err("%d: cannot create new directory %s", p->id, fullpath);
    return;
  }
  total_runs = run_get_total();
  for (r = 0; r < total_runs; r++) {
    if (run_get_entry(r, &re) < 0) continue;
    if (re.team != pkt->user_id) continue;
    arch_flag = archive_make_read_path(origpath, sizeof(origpath),
                                       global->run_archive_dir, r, 0, 0);
    if (arch_flag < 0) continue;
    snprintf(linkpath, sizeof(linkpath), "%s/%s_%06d%s%s",
             fullpath, probs[re.problem]->short_name, r,
             langs[re.language]->src_sfx,
             ((arch_flag & GZIP))?".gz":"");
    if (link(origpath, linkpath) < 0) {
      err("link %s->%s failed: %s", linkpath, origpath, os_ErrorMsg());
    }
  }
  token = remove_queue_add(current_time + global->team_download_time / 2,
                           1, fullpath);

  teamdb_set_archive_time(pkt->user_id, current_time);
  path_len = strlen(fullpath);
  out_size = sizeof(*out) + path_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->b.magic = PROT_SERVE_PACKET_MAGIC;
  out->b.id = SRV_RPL_ARCHIVE_PATH;
  out->token = token;
  out->path_len = path_len;
  memcpy(out->data, fullpath, path_len);
  new_enqueue_reply(p, out_size, out);
  info("%d: completed: %d, %s", p->id, token, fullpath);
}

static void
cmd_team_page(struct client_state *p, int len,
              struct prot_serve_pkt_team_page *pkt)
{
  unsigned char *self_url_ptr, *hidden_vars_ptr, *extra_args_ptr;
  FILE *f = 0;
  struct client_state *q = 0;
  char *html_ptr = 0;
  size_t html_len = 0;
  int accepting_mode = 0;

  if (get_peer_local_user(p) < 0) return;

  if (len < sizeof(*pkt)) {
    new_bad_packet(p, "cmd_team_page: packet is too small: %d", len);
    return;
  }
  self_url_ptr = pkt->data;
  if (strlen(self_url_ptr) != pkt->self_url_len) {
    new_bad_packet(p, "cmd_team_page: self_url_len mismatch");
    return;
  }
  hidden_vars_ptr = self_url_ptr + pkt->self_url_len + 1;
  if (strlen(hidden_vars_ptr) != pkt->hidden_vars_len) {
    new_bad_packet(p, "cmd_team_page: hidden_vars_len mismatch");
    return;
  }
  extra_args_ptr = hidden_vars_ptr + pkt->hidden_vars_len + 1;
  if (strlen(extra_args_ptr) != pkt->extra_args_len) {
    new_bad_packet(p, "cmd_team_page: extra_args_len mismatch");
    return;
  }
  if (len != sizeof(*pkt) + pkt->self_url_len + pkt->hidden_vars_len + pkt->extra_args_len) {
    new_bad_packet(p, "cmd_team_page: packet length mismatch");
    return;
  }

  info("%d: cmd_team_page: %d", p->id, pkt->locale_id);

  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    err("%d: two client file descriptors required", p->id);
    new_send_reply(p, -SRV_ERR_PROTOCOL);
    return;
  }

  if (!(f = open_memstream(&html_ptr, &html_len))) {
    err("%d: open_memstream failed", p->id);
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  l10n_setlocale(pkt->locale_id);
  if (global->score_system_val == SCORE_OLYMPIAD && !olympiad_judging_mode)
    accepting_mode = 1;
  write_team_page(f, p->user_id, printing_suspended,
                  p->cookie, (pkt->flags & 1), (pkt->flags & 2) >> 1,
                  self_url_ptr, hidden_vars_ptr, extra_args_ptr,
                  contest_start_time, contest_stop_time, accepting_mode);
  l10n_setlocale(0);
  fclose(f);

  if (!html_ptr) {
    html_ptr = xstrdup("");
    html_len = 0;
  }

  q = client_new_state(p->client_fds[0]);
  q->client_fds[0] = -1;
  q->client_fds[1] = p->client_fds[1];
  p->client_fds[0] = -1;
  p->client_fds[1] = -1;
  q->state = STATE_AUTOCLOSE;
  q->write_buf = html_ptr;
  q->write_len = html_len;

  info("%d: cmd_team_page: ok", p->id);
  new_send_reply(p, SRV_RPL_OK);
}

static const unsigned char * const contest_types[] =
{
  [SCORE_ACM] "acm",
  [SCORE_KIROV] "kirov",
  [SCORE_OLYMPIAD] "olympiad",
  [SCORE_MOSCOW] "moscow",
};

static void
cmd_get_param(struct client_state *p, int len,
              struct prot_serve_packet *pkt)
{
  opcap_t caps;
  FILE *f = 0;
  char *txt_ptr = 0;
  size_t txt_len = 0;
  size_t out_len;
  struct prot_serve_pkt_data *out_pkt = 0;

  if (get_peer_local_user(p) < 0) return;

  if (len != sizeof(*pkt)) {
    new_bad_packet(p, "cmd_get_param: packet length mismatch", len);
    return;
  }

  /*
  if (p->priv_level < PRIV_LEVEL_JUDGE) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: unsifficient privilege level", p->id);
    return;
  }
  */

  if (get_cnts_caps(p->user_id, &caps) < 0) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: cannot get capabilities", p->id);
    return;
  }
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: no CONTROL_CONTEST capability", p->id);
    return;
  }

  if (!(f = open_memstream(&txt_ptr, &txt_len))) {
    err("%d: open_memstream failed", p->id);
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  switch (pkt->id) {
  case SRV_CMD_GET_CONTEST_TYPE:
    if (global->score_system_val < SCORE_ACM ||
        global->score_system_val >= SCORE_TOTAL) {
      // FIXME:!!!
      abort();
    }
    fprintf(f, "%s", contest_types[global->score_system_val]);
    break;
  default:
    abort();
  }
  fclose(f); f = 0;

  if (!txt_ptr) txt_ptr = xstrdup("");
  txt_len = strlen(txt_ptr);
  out_len = sizeof(*out_pkt) + txt_len;
  out_pkt = alloca(out_len);
  memset(out_pkt, 0, out_len);
  out_pkt->b.magic = PROT_SERVE_PACKET_MAGIC;
  out_pkt->b.id = SRV_RPL_DATA;
  out_pkt->data_len = txt_len;
  if (txt_len > 0) memcpy(out_pkt->data, txt_ptr, txt_len);
  xfree(txt_ptr);
  
  info("%d: cmd_get_param: %zu", p->id, out_len);
  new_enqueue_reply(p, out_len, out_pkt);
}

static void
cmd_master_page(struct client_state *p, int len,
                struct prot_serve_pkt_master_page *pkt)
{
  unsigned char *self_url_ptr, *filter_expr_ptr, *hidden_vars_ptr;
  unsigned char *extra_args_ptr;
  FILE *f;
  char *html_ptr = 0;
  size_t html_len = 0;
  struct client_state *q;
  opcap_t caps;
  int r, accepting_mode = 0;

  if (get_peer_local_user(p) < 0) return;

  if (global->score_system_val == SCORE_OLYMPIAD && !olympiad_judging_mode)
    accepting_mode = 1;

  if (len < sizeof(*pkt)) {
    new_bad_packet(p, "cmd_master_page: packet is too small: %d", len);
    return;
  }
  self_url_ptr = pkt->data;
  if (strlen(self_url_ptr) != pkt->self_url_len) {
    new_bad_packet(p, "cmd_master_page: self_url_len mismatch");
    return;
  }
  filter_expr_ptr = self_url_ptr + pkt->self_url_len + 1;
  if (strlen(filter_expr_ptr) != pkt->filter_expr_len) {
    new_bad_packet(p, "cmd_master_page: filter_expr_len mismatch");
    return;
  }
  hidden_vars_ptr = filter_expr_ptr + pkt->filter_expr_len + 1;
  if (strlen(hidden_vars_ptr) != pkt->hidden_vars_len) {
    new_bad_packet(p, "cmd_master_page: hidden_vars_len mismatch");
    return;
  }
  extra_args_ptr = hidden_vars_ptr + pkt->hidden_vars_len + 1;
  if (strlen(extra_args_ptr) != pkt->extra_args_len) {
    new_bad_packet(p, "cmd_master_page: extra_args_len mismatch");
    return;
  }
  if (len != sizeof(*pkt) + pkt->self_url_len + pkt->filter_expr_len + pkt->hidden_vars_len + pkt->extra_args_len) {
    new_bad_packet(p, "cmd_master_page: packet length mismatch");
    return;
  }

  info("%d: cmd_master_page: %d, %d, %d",
       p->id, p->user_id, pkt->contest_id, pkt->locale_id);

  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    err("%d: two client file descriptors required", p->id);
    new_send_reply(p, -SRV_ERR_PROTOCOL);
    return;
  }
  /*
  if (!teamdb_lookup(pkt->user_id)) {
    err("%d: user_id is invalid", p->id);
    new_send_reply(p, -SRV_ERR_BAD_USER_ID);
    return;
  }
  */
  if (pkt->contest_id != global->contest_id) {
    err("%d: contest_id does not match", p->id);
    new_send_reply(p, -SRV_ERR_BAD_CONTEST_ID);
    return;
  }
  /*
  if (p->user_id && pkt->user_id != p->user_id) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: pkt->user_id != p->user_id", p->id);
    return;
  }
  */
  if (p->priv_level < PRIV_LEVEL_JUDGE) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: unsifficient privilege level", p->id);
    return;
  }
  if (p->priv_level < pkt->priv_level) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: priv_level does not match", p->id);
    return;
  }
  if (get_cnts_caps(p->user_id, &caps) < 0) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: cannot get capabilities", p->id);
    return;
  }

  if (!(f = open_memstream(&html_ptr, &html_len))) {
    err("%d: open_memstream failed", p->id);
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }

  if (pkt->b.id == SRV_CMD_MASTER_PAGE) {
    /* l10n_setlocale(pkt->locale_id); */
    write_master_page(f, p->user_id, pkt->priv_level,
                      p->cookie,
                      pkt->first_run, pkt->last_run,
                      pkt->mode_clar, pkt->first_clar, pkt->last_clar,
                      accepting_mode,
                      self_url_ptr, filter_expr_ptr, hidden_vars_ptr,
                      extra_args_ptr, &caps);
    /* l10n_setlocale(0); */
  } else {
    /* SRV_CMD_DUMP_MASTER_RUNS */
    r = write_priv_all_runs(f, p->user_id, 0, pkt->priv_level,
                            p->cookie,
                            pkt->first_run, pkt->last_run,
                            accepting_mode,
                            0, filter_expr_ptr, 0, 0);
    if (r < 0) {
      fclose(f);
      free(html_ptr); html_ptr = 0; html_len = 0;
      new_send_reply(p, r);
      return;
    }
  }

  fclose(f);

  if (!html_ptr) {
    html_ptr = xstrdup("");
    html_len = 0;
  }

  if (html_len > 0) {
    q = client_new_state(p->client_fds[0]);
    q->client_fds[0] = -1;
    q->client_fds[1] = p->client_fds[1];
    p->client_fds[0] = -1;
    p->client_fds[1] = -1;
    q->state = STATE_AUTOCLOSE;
    q->write_buf = html_ptr;
    q->write_len = html_len;
  } else {
    // nothing to reply
    close(p->client_fds[0]);
    close(p->client_fds[1]);
    p->client_fds[0] = -1;
    p->client_fds[1] = -1;
  }

  info("%d: cmd_master_page: ok %zu", p->id, html_len);
  new_send_reply(p, SRV_RPL_OK);
}

static void
cmd_priv_standings(struct client_state *p, int len,
                   struct prot_serve_pkt_standings *pkt)
{
  unsigned char *self_url_ptr, *hidden_vars_ptr, *extra_args_ptr;
  FILE *f;
  char *html_ptr = 0;
  size_t html_len = 0;
  struct client_state *q;
  int accepting_mode = 0;

  if (get_peer_local_user(p) < 0) return;

  if (len < sizeof(*pkt)) {
    new_bad_packet(p, "priv_standings: packet is too small: %d", len);
    return;
  }
  self_url_ptr = pkt->data;
  if (strlen(self_url_ptr) != pkt->self_url_len) {
    new_bad_packet(p, "priv_standings: self_url_len mismatch");
    return;
  }
  hidden_vars_ptr = self_url_ptr + pkt->self_url_len + 1;
  if (strlen(hidden_vars_ptr) != pkt->hidden_vars_len) {
    new_bad_packet(p, "priv_standings: hidden_vars_len mismatch");
    return;
  }
  extra_args_ptr = hidden_vars_ptr + pkt->hidden_vars_len + 1;
  if (strlen(extra_args_ptr) != pkt->extra_args_len) {
    new_bad_packet(p, "priv_standings: extra_args_len mismatch");
    return;
  }
  if (len != sizeof(*pkt) + pkt->self_url_len + pkt->hidden_vars_len + pkt->extra_args_len) {
    new_bad_packet(p, "priv_standings: packet length mismatch");
    return;
  }

  info("%d: priv_standings: %d", p->id, pkt->user_id);

  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    err("%d: two client file descriptors required", p->id);
    new_send_reply(p, -SRV_ERR_PROTOCOL);
    return;
  }
  if (!teamdb_lookup(pkt->user_id)) {
    err("%d: user_id is invalid", p->id);
    new_send_reply(p, -SRV_ERR_BAD_USER_ID);
    return;
  }
  if (pkt->contest_id != global->contest_id) {
    err("%d: contest_id does not match", p->id);
    new_send_reply(p, -SRV_ERR_BAD_CONTEST_ID);
    return;
  }
  if (pkt->user_id != p->user_id) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: pkt->user_id != p->user_id", p->id);
    return;
  }
  if (p->priv_level < PRIV_LEVEL_JUDGE) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: unsifficient privilege level", p->id);
    return;
  }
  if (p->priv_level < pkt->priv_level) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: priv_level does not match", p->id);
    return;
  }
  if (!check_cnts_caps(p->user_id, OPCAP_VIEW_STANDINGS)) {
    err("%d: user %d has no capability %d for the contest",
        p->id, p->user_id, OPCAP_VIEW_STANDINGS);
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    return;
  }

  if (!(f = open_memstream(&html_ptr, &html_len))) {
    err("%d: open_memstream failed", p->id);
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  /* l10n_setlocale(pkt->locale_id); */
  if (global->score_system_val == SCORE_OLYMPIAD && !olympiad_judging_mode)
    accepting_mode = 1;
  write_priv_standings(f, p->cookie,
                       self_url_ptr, hidden_vars_ptr, extra_args_ptr,
                       accepting_mode);
  /* l10n_setlocale(0); */
  fclose(f);

  if (!html_ptr) {
    html_ptr = xstrdup("");
    html_len = 0;
  }

  q = client_new_state(p->client_fds[0]);
  q->client_fds[0] = -1;
  q->client_fds[1] = p->client_fds[1];
  p->client_fds[0] = -1;
  p->client_fds[1] = -1;
  q->state = STATE_AUTOCLOSE;
  q->write_buf = html_ptr;
  q->write_len = html_len;

  info("%d: priv_standings: ok %zu", p->id, html_len);
  new_send_reply(p, SRV_RPL_OK);
}

static int
dump_problems(FILE *f)
{
  int i;
  struct section_problem_data *prob;

  for (i = 0; i <= max_prob; i++) {
    if (!(prob = probs[i])) continue;
    fprintf(f, "%d;%s;%s\n", prob->id, prob->short_name, prob->long_name);
  }
  return 0;
}

static void
cmd_view(struct client_state *p, int len,
         struct prot_serve_pkt_view *pkt)
{
  unsigned char *self_url_ptr, *hidden_vars_ptr, *extra_args_ptr;
  char *html_ptr = 0;
  size_t html_len = 0;
  struct client_state *q;
  int r = 0, accepting_mode = 0, need_priv_check = 1;
  FILE *f;
  opcap_t caps;
  struct run_entry re;
  struct section_problem_data *prob;

  if (get_peer_local_user(p) < 0) return;

  if (global->score_system_val == SCORE_OLYMPIAD && !olympiad_judging_mode)
    accepting_mode = 1;

  if (len < sizeof(*pkt)) {
    new_bad_packet(p, "view: packet is too small: %d", len);
    return;
  }
  self_url_ptr = pkt->data;
  if (strlen(self_url_ptr) != pkt->self_url_len) {
    new_bad_packet(p, "view: self_url_len mismatch");
    return;
  }
  hidden_vars_ptr = self_url_ptr + pkt->self_url_len + 1;
  if (strlen(hidden_vars_ptr) != pkt->hidden_vars_len) {
    new_bad_packet(p, "view: hidden_vars_len mismatch");
    return;
  }
  extra_args_ptr = hidden_vars_ptr + pkt->hidden_vars_len + 1;
  if (strlen(extra_args_ptr) != pkt->extra_args_len) {
    new_bad_packet(p, "view: extra_args_len mismatch");
    return;
  }
  if (len != sizeof(*pkt) + pkt->self_url_len + pkt->hidden_vars_len + pkt->extra_args_len) {
    new_bad_packet(p, "view: packet length mismatch");
    return;
  }

  info("%d: view %d, %d", p->id, pkt->b.id, pkt->item);

  if (pkt->b.id == SRV_CMD_SHOW_REPORT ||
      pkt->b.id == SRV_CMD_VIEW_TEST_INPUT ||
      pkt->b.id == SRV_CMD_VIEW_TEST_OUTPUT ||
      pkt->b.id == SRV_CMD_VIEW_TEST_ANSWER ||
      pkt->b.id == SRV_CMD_VIEW_TEST_ERROR ||
      pkt->b.id == SRV_CMD_VIEW_TEST_CHECKER ||
      pkt->b.id == SRV_CMD_VIEW_TEST_INFO)
    need_priv_check = 0;

  if (need_priv_check && get_cnts_caps(p->user_id, &caps) < 0) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: cannot get capabilities", p->id);
    return;
  }

  if (!(f = open_memstream(&html_ptr, &html_len))) {
    err("%d: open_memstream failed", p->id);
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  switch (pkt->b.id) {
  case SRV_CMD_VIEW_SOURCE:
    if (!p->priv_level) {
      err("%d: source view for unprivileged users not yet supported", p->id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (opcaps_check(caps, OPCAP_VIEW_SOURCE) < 0) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_VIEW_SOURCE);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    r = write_priv_source(f, p->user_id, p->priv_level, p->cookie,
                          accepting_mode, self_url_ptr, hidden_vars_ptr,
                          extra_args_ptr, pkt->item, &caps);
    break;
  case SRV_CMD_NEW_RUN_FORM:
    if (p->priv_level != PRIV_LEVEL_ADMIN) {
      err("%d: master privilege required", p->id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (opcaps_check(caps, OPCAP_VIEW_SOURCE) < 0
        || opcaps_check(caps, OPCAP_SUBMIT_RUN) < 0) {
      err("%d: user %d cannot add new runs", p->id, p->user_id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    r = write_new_run_form(f, p->user_id, p->priv_level, p->cookie,
                           self_url_ptr, hidden_vars_ptr,
                           extra_args_ptr, pkt->item, &caps);
    break;
  case SRV_CMD_PRIV_DOWNLOAD_RUN:
    if (!p->priv_level) {
      err("%d: not enough privileges", p->id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }
    if (opcaps_check(caps, OPCAP_VIEW_SOURCE) < 0) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_VIEW_SOURCE);
      r = -SRV_ERR_NO_PERMS;
      break;
    }
    r = write_raw_source(f, self_url_ptr, pkt->item);
    break;
  case SRV_CMD_PRIV_DOWNLOAD_REPORT:
  case SRV_CMD_PRIV_DOWNLOAD_TEAM_REPORT:
    if (!p->priv_level) {
      err("%d: not enough privileges", p->id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }
    if (opcaps_check(caps, OPCAP_VIEW_REPORT) < 0) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_VIEW_REPORT);
      r = -SRV_ERR_NO_PERMS;
      break;
    }
    r = write_raw_report(f, self_url_ptr, pkt->item,
                         pkt->b.id==SRV_CMD_PRIV_DOWNLOAD_TEAM_REPORT?1:0);
    break;
  case SRV_CMD_COMPARE_RUNS:
    if (!p->priv_level) {
      err("%d: not enough privileges", p->id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }
    if (opcaps_check(caps, OPCAP_VIEW_SOURCE) < 0) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_VIEW_SOURCE);
      r = -SRV_ERR_NO_PERMS;
      break;
    }
    r = compare_runs(f, pkt->item, pkt->item2);
    break;
  case SRV_CMD_VIEW_REPORT:
    if (!p->priv_level) {
      err("%d: report view for unprivileged users not yet supported", p->id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (opcaps_check(caps, OPCAP_VIEW_REPORT) < 0) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_VIEW_REPORT);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    r = write_priv_report(f, p->user_id, p->priv_level, p->cookie, (int) pkt->flags,
                          self_url_ptr, hidden_vars_ptr, extra_args_ptr,
                          pkt->item, &caps);
    break;
  case SRV_CMD_VIEW_CLAR:
    if (!p->priv_level) {
      err("%d: clar view for unprivileged users not yet supported", p->id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (opcaps_check(caps, OPCAP_VIEW_CLAR) < 0) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_VIEW_CLAR);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    r = write_priv_clar(f, p->user_id, p->priv_level, p->cookie,
                        self_url_ptr, hidden_vars_ptr, extra_args_ptr,
                        pkt->item, &caps);
    if (p->priv_level == PRIV_LEVEL_JUDGE) {
      int flags = 1;

      clar_get_record(clarlog_state, pkt->item, 0, 0, 0, 0, 0, &flags, 0, 0, 0);
      if (!flags) {
        flags = 1;
        clar_update_flags(clarlog_state, pkt->item, flags);
      }
    }
    break;
  case SRV_CMD_VIEW_USERS:
    if (!p->priv_level) {
      err("%d: unprivileged users cannot view teams", p->id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (opcaps_check(caps, OPCAP_LIST_CONTEST_USERS) < 0) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_LIST_CONTEST_USERS);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    r = write_priv_users(f, p->user_id, p->priv_level, p->cookie,
                         self_url_ptr, hidden_vars_ptr, extra_args_ptr, &caps);
    break;

  case SRV_CMD_VIEW_TEAM:
    if (!p->priv_level) {
      err("%d: unprivileged users cannot view team", p->id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (opcaps_check(caps, OPCAP_GET_USER) < 0) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_LIST_CONTEST_USERS);
      r = -SRV_ERR_NO_PERMS;
      break;
    }
    r = write_priv_user(f, p->user_id, p->priv_level, p->cookie,
                        self_url_ptr, hidden_vars_ptr, extra_args_ptr,
                        pkt->item, &caps);
    break;

  case SRV_CMD_DUMP_RUNS:
    if (!p->priv_level) {
      err("%d: unprivileged users cannot dump run database", p->id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (!check_cnts_caps(p->user_id, OPCAP_DUMP_RUNS)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_DUMP_RUNS);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    write_runs_dump(f, self_url_ptr, global->charset);
    break;

  case SRV_CMD_WRITE_XML_RUNS:
    if (!p->priv_level) {
      err("%d: unprivileged users cannot export XML runs", p->id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (!check_cnts_caps(p->user_id, OPCAP_DUMP_RUNS)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_DUMP_RUNS);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (self_url_ptr && *self_url_ptr) {
      fprintf(f, "Content-type: text/plain; charset=%s\n\n", EJUDGE_CHARSET);
    }
    if (run_write_xml(f, 0, current_time) < 0) r = -SRV_ERR_TRY_AGAIN;
    break;

  case SRV_CMD_DUMP_PROBLEMS:
    if (!p->priv_level) {
      err("%d: unprivileged users cannot dump problems", p->id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (!check_cnts_caps(p->user_id, OPCAP_DUMP_RUNS)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_DUMP_RUNS);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (self_url_ptr && *self_url_ptr) {
      fprintf(f, "Content-type: text/plain; charset=%s\n\n", EJUDGE_CHARSET);
    }
    r = dump_problems(f);
    break;

  case SRV_CMD_EXPORT_XML_RUNS:
    if (!p->priv_level) {
      err("%d: unprivileged users cannot export XML runs", p->id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (!check_cnts_caps(p->user_id, OPCAP_DUMP_RUNS)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_DUMP_RUNS);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (self_url_ptr && *self_url_ptr) {
      fprintf(f, "Content-type: text/plain; charset=%s\n\n", EJUDGE_CHARSET);
    }
    if (run_write_xml(f, 1, current_time) < 0) r = -SRV_ERR_TRY_AGAIN;
    break;

  case SRV_CMD_DUMP_STANDINGS:
    if (!p->priv_level) {
      err("%d: unprivileged users cannot dump standings", p->id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (!check_cnts_caps(p->user_id, OPCAP_DUMP_STANDINGS)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_DUMP_STANDINGS);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (self_url_ptr && *self_url_ptr) {
      fprintf(f, "Content-type: text/plain; charset=%s\n\n", global->charset);
    }

    write_raw_standings(f, global->charset);
    break;

  case SRV_CMD_VIEW_TEST_INPUT:
  case SRV_CMD_VIEW_TEST_OUTPUT:
  case SRV_CMD_VIEW_TEST_ANSWER:
  case SRV_CMD_VIEW_TEST_ERROR:
  case SRV_CMD_VIEW_TEST_CHECKER:
  case SRV_CMD_VIEW_TEST_INFO:
    /* either user has priv_level > 0, OPCAP_VIEW_REPORT cap bit
     * or team_show_judge_report is on, and the user is the author
     */
    if (!p->priv_level) {
      if (!global->team_show_judge_report) {
        err("%d: user %d attempted to view judge report", p->id, p->user_id);
        r = -SRV_ERR_NO_PERMS;
        break;
      }
      if (run_get_entry(pkt->item, &re) < 0 || re.team != p->user_id) {
        err("%d: user %d tries to view another's runs", p->id, p->user_id);
        r = -SRV_ERR_NO_PERMS;
        break;
      }
      if (global->score_system_val==SCORE_OLYMPIAD && !olympiad_judging_mode) {
        if (re.problem <= 0 || re.problem > max_prob
            || !(prob = probs[re.problem])) {
          err("%d: invalid problem %d", p->id, re.problem);
          r = -SRV_ERR_BAD_PROB_ID;
          break;
        }
        if (pkt->item2 <= 0 || pkt->item2 > prob->tests_to_accept) {
          err("%d: user %d tries to view real tests", p->id, p->user_id);
          r = -SRV_ERR_NO_PERMS;
          break;
        }
      }
    } else {
      if (!check_cnts_caps(p->user_id, OPCAP_VIEW_REPORT)) {
        err("%d: user %d has no capability %d for the contest",
            p->id, p->user_id, OPCAP_VIEW_REPORT);
        r = -SRV_ERR_NO_PERMS;
        break;
      }
    }
    r = write_tests(f, pkt->b.id, pkt->item, pkt->item2);
    break;

  case SRV_CMD_VIEW_AUDIT_LOG:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      r = -SRV_ERR_NO_PERMS;
      break;
    }
    r = write_audit_log(f, pkt->item);
    break;

  case SRV_CMD_SHOW_REPORT:
    // this is unprivileged command
    if (run_get_entry(pkt->item, &re) < 0 || re.team != p->user_id) {
      err("%d: user %d tries to view another's runs", p->id, p->user_id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }
    l10n_setlocale(pkt->item2);
    r = new_write_user_report_view(f, p->user_id, pkt->item,
                                   accepting_mode, p->cookie,
                                   self_url_ptr, hidden_vars_ptr, extra_args_ptr);
    l10n_setlocale(0);

    break;

  default:
    err("%d: operation is not yet supported", p->id);
    fprintf(f, "<h2>Operation is not yet supported.</h2>\n");
  }
  fclose(f);
  if (r < 0) {
    xfree(html_ptr); html_len = 0;
    new_send_reply(p, r);
    return;
  }

  if (!html_ptr) {
    html_ptr = xstrdup("");
    html_len = 0;
  }

  q = client_new_state(p->client_fds[0]);
  q->client_fds[0] = -1;
  q->client_fds[1] = p->client_fds[1];
  p->client_fds[0] = -1;
  p->client_fds[1] = -1;
  q->state = STATE_AUTOCLOSE;
  q->write_buf = html_ptr;
  q->write_len = html_len;

  info("%d: view: ok %zu", p->id, html_len);
  new_send_reply(p, SRV_RPL_OK);
}

static void
cmd_import_xml_runs(struct client_state *p, int len,
                    struct prot_serve_pkt_archive_path *pkt)
{
  size_t xml_data_len, html_len = 0;
  FILE *f;
  char *html_ptr = 0;
  struct client_state *q;

  if (get_peer_local_user(p) < 0) return;

  if (len < sizeof(*pkt)) {
    new_bad_packet(p, "import_xml_runs: packet is too small: %d", len);
    return;
  }
  xml_data_len = strlen(pkt->data);
  if (pkt->path_len != xml_data_len) {
    new_bad_packet(p, "import_xml_runs: data length mismatch: %d, %d",
                   (int) xml_data_len, pkt->path_len);
    return;
  }
  if (len != sizeof(*pkt) + xml_data_len) {
    new_bad_packet(p, "import_xml_runs: packet length mismatch: %d, %d",
                   len, sizeof(*pkt) + xml_data_len);
    return;
  }

  if (!p->priv_level) {
    err("%d: unprivileged users cannot import XML runs", p->id);
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    return;
  }
  if (!check_cnts_caps(p->user_id, OPCAP_IMPORT_XML_RUNS)) {
    err("%d: user %d has no capability %d for the contest",
        p->id, p->user_id, OPCAP_IMPORT_XML_RUNS);
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    return;
  }
  if (!global->enable_runlog_merge) {
    err("%d: runlog merging is disabled", p->id);
    new_send_reply(p, -SRV_ERR_NOT_SUPPORTED);
    return;
  }

  info("%d: import_xml_runs: %d", p->id, (int) xml_data_len);
  if (!(f = open_memstream(&html_ptr, &html_len))) {
    err("%d: open_memstream failed", p->id);
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  runlog_import_xml(f, pkt->token, pkt->data);
  fclose(f);

  if (!html_ptr) {
    html_ptr = xstrdup("");
    html_len = 0;
  }

  q = client_new_state(p->client_fds[0]);
  q->client_fds[0] = -1;
  q->client_fds[1] = p->client_fds[1];
  p->client_fds[0] = -1;
  p->client_fds[1] = -1;
  q->state = STATE_AUTOCLOSE;
  q->write_buf = html_ptr;
  q->write_len = html_len;

  info("%d: import_xml_runs: ok %zu", p->id, html_len);
  new_send_reply(p, SRV_RPL_OK);
}

static void
cmd_message(struct client_state *p, int len,
            struct prot_serve_pkt_submit_clar *pkt)
{
  unsigned char const *dest_login_ptr, *subj_ptr, *text_ptr;
  int dest_uid, hide_flag = 0;
  unsigned char txt_subj_short[CLAR_MAX_SUBJ_TXT_LEN + 10];
  unsigned char b64_subj_short[CLAR_MAX_SUBJ_LEN + 10];
  unsigned char *msg, *quoted_ptr, *new_subj;
  char *orig_txt = 0;
  size_t msg_len, orig_txt_len, new_subj_len, quoted_len;
  int clar_id;
  unsigned char clar_name[64], orig_clar_name[64];

  if (get_peer_local_user(p) < 0) return;

  if (len < sizeof(*pkt)) {
    new_bad_packet(p, "cmd_message: packet is too small: %d", len);
    return;
  }
  dest_login_ptr = pkt->data;
  if (strlen(dest_login_ptr) != pkt->dest_login_len) {
    new_bad_packet(p, "cmd_message: dest_login_len mismatch");
    return;
  }
  subj_ptr = dest_login_ptr + pkt->dest_login_len + 1;
  if (strlen(subj_ptr) != pkt->subj_len) {
    new_bad_packet(p, "cmd_message: subj_len mismatch");
    return;
  }
  text_ptr = subj_ptr + pkt->subj_len + 1;
  if (strlen(text_ptr) != pkt->text_len) {
    new_bad_packet(p, "cmd_message: text_len mismatch");
    return;
  }
  if (len != sizeof(*pkt)+pkt->dest_login_len+pkt->subj_len+pkt->text_len) {
    new_bad_packet(p, "cmd_message: packet length mismatch");
    return;
  }

  info("%d: cmd_message: %d %d %d %s", p->id, pkt->b.id, pkt->dest_user_id,
       pkt->ref_clar_id, dest_login_ptr);

  if (contest_start_time <= 0 && pkt->hide_flag) hide_flag = 1;

  switch (pkt->b.id) {
  case SRV_CMD_PRIV_MSG:
    if (p->priv_level < PRIV_LEVEL_JUDGE) {
      err("%d: inappropriate privilege level", p->id);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    if (!check_cnts_caps(p->user_id, OPCAP_NEW_MESSAGE)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_NEW_MESSAGE);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    dest_uid = pkt->dest_user_id;
    if (dest_uid == -1) {
      if (!strcasecmp(dest_login_ptr, "all")) {
        dest_uid = 0;
      } else {
        dest_uid = teamdb_lookup_login(dest_login_ptr);
        if (dest_uid <= 0) {
          err("%d: nonexistant login <%s>", p->id, dest_login_ptr);
          new_send_reply(p, -SRV_ERR_BAD_USER_ID);
          return;
        }
      }
    } else if (dest_uid != 0 && !teamdb_lookup(dest_uid)) {
      err("%d: nonexistant user id %d", p->id, dest_uid);
      new_send_reply(p, -SRV_ERR_BAD_USER_ID);
      return;
    }
    strncpy(txt_subj_short, subj_ptr, CLAR_MAX_SUBJ_TXT_LEN);
    if (txt_subj_short[CLAR_MAX_SUBJ_TXT_LEN - 1]) {
      txt_subj_short[CLAR_MAX_SUBJ_TXT_LEN - 1] = 0;
      txt_subj_short[CLAR_MAX_SUBJ_TXT_LEN - 2] = '.';
      txt_subj_short[CLAR_MAX_SUBJ_TXT_LEN - 3] = '.';
      txt_subj_short[CLAR_MAX_SUBJ_TXT_LEN - 4] = '.';
    }
    base64_encode_str(txt_subj_short, b64_subj_short);
    msg = alloca(pkt->subj_len + pkt->text_len + 32);
    msg_len = sprintf(msg, "Subject: %s\n\n%s", subj_ptr, text_ptr);
    clar_id = clar_add_record(clarlog_state, current_time, msg_len,
                              run_unparse_ip(p->ip),
                              0, dest_uid, 0, p->user_id,
                              hide_flag, b64_subj_short);
    if (clar_id < 0) {
      err("%d: cannot add new message", p->id);
      new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
      return;
    }
    snprintf(clar_name, sizeof(clar_name), "%06d", clar_id);
    if (generic_write_file(msg, msg_len, 0, global->clar_archive_dir,
                           clar_name, "") < 0) {
      new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
      return;
    }

    info("%d: cmd_message: ok %d %zu", p->id, clar_id, msg_len);
    new_send_reply(p, SRV_RPL_OK);
    return;

  case SRV_CMD_PRIV_REPLY:
    if (p->priv_level < PRIV_LEVEL_JUDGE) {
      err("%d: inappropriate privilege level", p->id);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    if (!check_cnts_caps(p->user_id, OPCAP_REPLY_MESSAGE)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_REPLY_MESSAGE);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    // subj_ptr, dest_login_ptr to be ignored
    // if dest_user_id == 0, the reply is sent to all
    // ref_clar_id to be processed
    if (clar_get_record(clarlog_state, pkt->ref_clar_id, 0, 0, 0, &dest_uid, 0, 0,0,0,0) < 0) {
      err("%d: invalid ref_clar_id %d", p->id, pkt->ref_clar_id);
      new_send_reply(p, -SRV_ERR_BAD_CLAR_ID);
      return;
    }
    snprintf(orig_clar_name, sizeof(orig_clar_name), "%06d", pkt->ref_clar_id);
    orig_txt = 0;
    orig_txt_len = 0;
    if (generic_read_file(&orig_txt, 0, &orig_txt_len, 0,
                          global->clar_archive_dir, orig_clar_name, "") < 0) {
      new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
      return;
    }

    new_subj = alloca(orig_txt_len + 64);
    new_subj_len = message_reply_subj(orig_txt, new_subj);
    message_base64_subj(new_subj, b64_subj_short, CLAR_MAX_SUBJ_TXT_LEN);
    quoted_len = message_quoted_size(orig_txt);
    quoted_ptr = alloca(quoted_len + 16);
    message_quote(orig_txt, quoted_ptr);
    msg = alloca(pkt->text_len + quoted_len + new_subj_len + 64);
    msg_len = sprintf(msg, "%s%s\n%s", new_subj, quoted_ptr, text_ptr);
    if (!pkt->dest_user_id) dest_uid = 0;
    clar_id = clar_add_record(clarlog_state, current_time, msg_len,
                              run_unparse_ip(p->ip), 0, dest_uid, 0,
                              p->user_id, hide_flag, b64_subj_short);
    if (clar_id < 0) {
      new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
      return;
    }
    snprintf(clar_name, sizeof(clar_name), "%06d", clar_id);
    if (generic_write_file(msg, msg_len, 0, global->clar_archive_dir,
                           clar_name, "") < 0) {
      new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
      return;
    }
    clar_update_flags(clarlog_state, pkt->ref_clar_id, 2);
    xfree(orig_txt);
    info("%d: cmd_message: ok %d %zu", p->id, clar_id, msg_len);
    new_send_reply(p, SRV_RPL_OK);
    return;

  default:
    new_bad_packet(p, "cmd_message: unsupported command %d", pkt->b.id);
    return;
  }
}

static void
cmd_team_show_item(struct client_state *p, int len,
                   struct prot_serve_pkt_show_item *pkt)
{
  FILE *f;
  char *html_ptr = 0;
  size_t html_len = 0;
  struct client_state *q;
  int r, accepting_mode;

  if (get_peer_local_user(p) < 0) return;

  if (len != sizeof(*pkt)) {
    new_bad_packet(p, "cmd_team_show_item: bad packet length: %d", len);
    return;
  }
  /*
  if (pkt->b.id != SRV_CMD_SHOW_CLAR
      && pkt->b.id != SRV_CMD_SHOW_REPORT
      && pkt->b.id != SRV_CMD_VIRTUAL_STANDINGS
      && pkt->b.id != SRV_CMD_SHOW_SOURCE
      && pkt->b.id != SRV_CMD_DUMP_SOURCE
      && pkt->b.id != SRV_CMD_DUMP_CLAR
      && pkt->b.id != SRV_CMD_RUN_STATUS) {
    new_bad_packet(p, "cmd_team_show_item: bad command: %d", pkt->b.id);
    return;
  }
  */

  accepting_mode = 0;
  if (global->score_system_val == SCORE_OLYMPIAD && !olympiad_judging_mode)
    accepting_mode = 1;

  info("%d: team_show_item: %d, %d, %d, %d, %d", p->id, pkt->b.id,
       pkt->user_id, pkt->contest_id, pkt->locale_id, pkt->item_id);
  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    err("%d: two client file descriptors required", p->id);
    new_send_reply(p, -SRV_ERR_PROTOCOL);
    return;
  }
  if (!teamdb_lookup(pkt->user_id)) {
    err("%d: user_id is invalid", p->id);
    new_send_reply(p, -SRV_ERR_BAD_USER_ID);
    return;
  }
  if (pkt->contest_id != global->contest_id) {
    err("%d: contest_id does not match", p->id);
    new_send_reply(p, -SRV_ERR_BAD_CONTEST_ID);
    return;
  }
  if (p->user_id && pkt->user_id != p->user_id) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: pkt->user_id != p->user_id", p->id);
    return;
  }

  if (!(f = open_memstream(&html_ptr, &html_len))) {
    err("%d: open_memstream failed", p->id);
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  l10n_setlocale(pkt->locale_id);
  switch (pkt->b.id) {
  case SRV_CMD_SHOW_CLAR:
    r = new_write_user_clar(f, pkt->user_id, pkt->item_id, 0);
    break;
  case SRV_CMD_DUMP_CLAR:
    r = new_write_user_clar(f, pkt->user_id, pkt->item_id, 1);
    break;
  case SRV_CMD_SHOW_SOURCE:
    r = new_write_user_source_view(f, pkt->user_id, pkt->item_id, 0);
    break;
  case SRV_CMD_DUMP_SOURCE:
    r = new_write_user_source_view(f, pkt->user_id, pkt->item_id, 1);
    break;
  case SRV_CMD_DUMP_SOURCE_2:
    r = new_write_user_source_view(f, pkt->user_id, pkt->item_id, 2);
    break;
  case SRV_CMD_VIRTUAL_STANDINGS:
    if (!global->virtual) r = -SRV_ERR_ONLY_VIRTUAL;
    else r = write_virtual_standings(f, pkt->user_id);
    break;
  case SRV_CMD_RUN_STATUS:
    r = write_user_run_status(f, pkt->user_id, pkt->item_id, accepting_mode, 1);
    break;
  default:
    abort();
  }
  l10n_setlocale(0);
  fclose(f);

  if (r < 0) {
    xfree(html_ptr);
    new_send_reply(p, r);
    return;
  }

  q = client_new_state(p->client_fds[0]);
  q->client_fds[0] = -1;
  q->client_fds[1] = p->client_fds[1];
  p->client_fds[0] = -1;
  p->client_fds[1] = -1;
  q->state = STATE_AUTOCLOSE;
  q->write_buf = html_ptr;
  q->write_len = html_len;

  info("%d: team_show_item: ok", p->id);
  new_send_reply(p, SRV_RPL_OK);
}

/* extra data, which is passed through compilation phase */
struct compile_run_extra
{
  int accepting_mode;
  int priority_adjustment;
};

static int queue_compile_request(unsigned char const *str, int len,
                                 int run_id, int lang_id, int locale_id,
                                 int output_only,
                                 unsigned char const *sfx,
                                 char **, int accepting_mode,
                                 int priority_adjustment);

static void
move_files_to_insert_run(int run_id)
{
  int total = run_get_total();
  int i, s;

  if (run_id >= total - 1) return;
  for (i = total - 1; i >= run_id; i--) {
    archive_remove(global->run_archive_dir, i + 1, 0);
    archive_remove(global->xml_report_archive_dir, i + 1, 0);
    archive_remove(global->report_archive_dir, i + 1, 0);
    if (global->team_enable_rep_view) {
      archive_remove(global->team_report_archive_dir, i + 1, 0);
    }
    if (global->enable_full_archive) {
      archive_remove(global->full_archive_dir, i + 1, 0);
    }
    archive_remove(global->audit_log_dir, i + 1, 0);
    s = run_get_status(i);
    if (s >= RUN_PSEUDO_FIRST && s <= RUN_PSEUDO_LAST) continue;
    archive_rename(global->run_archive_dir, 0, i, 0, i + 1, 0, 0);
    archive_rename(global->xml_report_archive_dir, 0, i, 0, i + 1, 0, 0);
    archive_rename(global->report_archive_dir, 0, i, 0, i + 1, 0, 0);
    if (global->team_enable_rep_view) {
      archive_rename(global->team_report_archive_dir, 0, i, 0, i + 1, 0, 0);
    }
    if (global->enable_full_archive) {
      archive_rename(global->full_archive_dir, 0, i, 0, i + 1, 0, 0);
    }
    archive_rename(global->audit_log_dir, 0, i, 0, i + 1, 0, 0);
  }

  /* FIXME: add audit information for all the renamed runs */
}

static void
cmd_priv_submit_run(struct client_state *p, int len, 
                    struct prot_serve_pkt_submit_run *pkt)
{
  int run_id, arch_flags;
  path_t run_arch;
  ruint32_t shaval[5];
  time_t start_time, stop_time;
  struct timeval precise_time;

  if (get_peer_local_user(p) < 0) return;
  if (len < sizeof(*pkt)) {
    new_bad_packet(p, "priv_submit_run: packet is too small: %d", len);
    return;
  }
  if (pkt->lang_id < 1 || pkt->lang_id > max_lang || !langs[pkt->lang_id]) {
    err("%d: lang_id is invalid", p->id);
    new_send_reply(p, -SRV_ERR_BAD_LANG_ID);
    return;
  }
  if (!langs[pkt->lang_id]->binary && pkt->run_len != strlen(pkt->data)) {
    err("%d: data format error: binary file?", p->id);
    new_send_reply(p, -SRV_ERR_DATA_FORMAT);
    return;
  }
  if (len != sizeof(*pkt) + pkt->run_len) {
    new_bad_packet(p, "priv_submit_run: packet length does not match");
    return;
  }

  info("%d: priv_submit_run: %d, %d, %d, %d, %d, %d",
       p->id, pkt->user_id, pkt->contest_id, pkt->locale_id,
       pkt->prob_id, pkt->lang_id, pkt->variant);
  if (p->user_id <= 0) {
    err("%d: user is not authentificated", p->id);
    new_send_reply(p, -SRV_ERR_BAD_USER_ID);
    return;
  }
  if (pkt->contest_id != global->contest_id) {
    err("%d: contest_id does not match", p->id);
    new_send_reply(p, -SRV_ERR_BAD_CONTEST_ID);
    return;
  }
  if (!teamdb_lookup(pkt->user_id)) {
    err("%d: user_id is invalid", p->id);
    new_send_reply(p, -SRV_ERR_BAD_USER_ID);
    return;
  }
  if (p->user_id != pkt->user_id) {
    err("%d: user_ids do not match", p->id);
    new_send_reply(p, -SRV_ERR_BAD_USER_ID);
    return;
  }
  if (!check_cnts_caps(p->user_id, OPCAP_SUBMIT_RUN)) {
    err("%d: user has no capability to submit runs", p->id);
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    return;
  }
  if (pkt->prob_id < 1 || pkt->prob_id > max_prob || !probs[pkt->prob_id]) {
    err("%d: prob_id is invalid", p->id);
    new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
    return;
  }
  if (probs[pkt->prob_id]->variant_num > 0) {
    if (pkt->variant < 0 || pkt->variant > probs[pkt->prob_id]->variant_num) {
      err("%d: invalid variant", p->id);
      new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
      return;
    }
    if (!pkt->variant) pkt->variant = find_variant(pkt->user_id, pkt->prob_id);
    if (!pkt->variant) {
      err("%d: variant is not known", p->id);
      new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
      return;
    }
  } else {
    if (pkt->variant) {
      err("%d: this problem has no variants", p->id);
      new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
      return;
    }
  }

  start_time = contest_start_time;
  stop_time = contest_stop_time;
  if (global->virtual) {
    start_time = run_get_virtual_start_time(p->user_id);
    stop_time = run_get_virtual_stop_time(p->user_id, current_time);
  }
  /*
  if (!start_time) {
    err("%d: contest is not started", p->id);
    new_send_reply(p, -SRV_ERR_CONTEST_NOT_STARTED);
    return;
  }
  if (stop_time) {
    err("%d: contest already finished", p->id);
    new_send_reply(p, -SRV_ERR_CONTEST_FINISHED);
    return;
  }
  */
  sha_buffer(pkt->data, pkt->run_len, shaval);
  gettimeofday(&precise_time, 0);
  if ((run_id = run_add_record(precise_time.tv_sec,
                               precise_time.tv_usec * 1000,
                               pkt->run_len,
                               shaval,
                               pkt->ip,
                               pkt->locale_id,
                               pkt->user_id,
                               pkt->prob_id,
                               pkt->lang_id,
                               pkt->variant, 1)) < 0){
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  move_files_to_insert_run(run_id);

  arch_flags = archive_make_write_path(run_arch, sizeof(run_arch),
                                       global->run_archive_dir, run_id,
                                       pkt->run_len, 0);
  if (arch_flags < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  if (archive_dir_prepare(global->run_archive_dir, run_id, 0, 0) < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  if (generic_write_file(pkt->data, pkt->run_len, arch_flags,
                         0, run_arch, "") < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }

  if (testing_suspended) {
    info("%d: testing is suspended", p->id);
    run_change_status(run_id, RUN_PENDING, 0, -1, 0);
    append_audit_log(run_id, p, "Command: priv_submit\nStatus: pending\nRun-id: %d\n  Testing is suspended by the contest administrator\n", run_id);
    new_send_reply(p, SRV_RPL_OK);
    return;
  }

  if (probs[pkt->prob_id]->disable_auto_testing
      || (probs[pkt->prob_id]->disable_testing
          && probs[pkt->prob_id]->enable_compilation <= 0)
      || langs[pkt->lang_id]->disable_auto_testing
      || langs[pkt->lang_id]->disable_testing) {
    info("%d: priv_submit_run: auto testing disabled", p->id);
    run_change_status(run_id, RUN_PENDING, 0, -1, 0);
    append_audit_log(run_id, p, "Command: priv_submit\nStatus: pending\nRun-id: %d\n  Testing is disabled for this language or problem\n", run_id);
    new_send_reply(p, SRV_RPL_OK);
    return;
  }

  if (queue_compile_request(pkt->data, pkt->run_len, run_id,
                            langs[pkt->lang_id]->compile_id,
                            pkt->locale_id,
                            probs[pkt->prob_id]->output_only,
                            langs[pkt->lang_id]->src_sfx,
                            langs[pkt->lang_id]->compiler_env, -1, 0) < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }

  info("%d: priv_submit_run: ok", p->id);
  append_audit_log(run_id, p, "Command: priv_submit\nStatus: ok\nRun-id: %d\n", run_id);
  new_send_reply(p, SRV_RPL_OK);
}

static void
cmd_upload_report(struct client_state *p, int len,
                  struct prot_serve_pkt_upload_report *pkt)
{
  path_t wpath;
  int wflags;
  const unsigned char *t1 = "", *t2 = "";

  if (get_peer_local_user(p) < 0) return;
  if (len < sizeof(*pkt)) {
    new_bad_packet(p, "cmd_upload_report: packet is too small: %d", len);
    return;
  }
  if (len != sizeof(*pkt) + pkt->report_size) {
    new_bad_packet(p, "cmd_upload_report: packet size does not match");
    return;
  }

  info("%d: upload_report: %d, %d, %d, %d",
       p->id, pkt->user_id, pkt->contest_id, pkt->run_id,
       pkt->report_size);

  if (!global->enable_report_upload) {
    err("%d: report uploading is disabled", p->id);
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    return;
  }

  if (p->user_id <= 0) {
    err("%d: user is not authentificated", p->id);
    new_send_reply(p, -SRV_ERR_BAD_USER_ID);
    return;
  }
  if (pkt->contest_id != global->contest_id) {
    err("%d: contest_id does not match", p->id);
    new_send_reply(p, -SRV_ERR_BAD_CONTEST_ID);
    return;
  }
  if (!teamdb_lookup(pkt->user_id)) {
    err("%d: user_id is invalid", p->id);
    new_send_reply(p, -SRV_ERR_BAD_USER_ID);
    return;
  }
  if (p->user_id != pkt->user_id) {
    err("%d: user_ids do not match", p->id);
    new_send_reply(p, -SRV_ERR_BAD_USER_ID);
    return;
  }
  if (!check_cnts_caps(p->user_id, OPCAP_EDIT_RUN)) {
    err("%d: user has no capability to submit runs", p->id);
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    return;
  }

  if (pkt->run_id < 0 || pkt->run_id >= run_get_total()) {
    err("%d: invalid run_id %d", p->id, pkt->run_id);
    new_send_reply(p, -SRV_ERR_BAD_RUN_ID);
    return;
  }

  if (!global->team_enable_rep_view || (pkt->flags & 1)) {
    archive_remove(global->xml_report_archive_dir, pkt->run_id, 0);
    wflags = archive_make_write_path(wpath, sizeof(wpath),
                                     global->report_archive_dir,
                                     pkt->run_id, pkt->report_size, 0);
    if (archive_dir_prepare(global->report_archive_dir, pkt->run_id, 0, 0) < 0) {
      new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
      return;
    }
    if (generic_write_file(pkt->data, pkt->report_size, wflags, 0,
                           wpath, "") < 0) {
      new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
      return;
    }
    t1 = "  Judge's report uploaded\n";
  }

  if (global->team_enable_rep_view && (pkt->flags & 2)) {
    archive_remove(global->xml_report_archive_dir, pkt->run_id, 0);
    wflags = archive_make_write_path(wpath, sizeof(wpath),
                                     global->team_report_archive_dir,
                                     pkt->run_id, pkt->report_size, 0);
    if (archive_dir_prepare(global->team_report_archive_dir,pkt->run_id,0,0)< 0){
      new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
      return;
    }
    if (generic_write_file(pkt->data, pkt->report_size, wflags, 0,
                           wpath, "") < 0) {
      new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
      return;
    }
    t2 = "  Participant's report uploaded\n";
  }

  info("%d: cmd_upload_report: ok", p->id);
  append_audit_log(pkt->run_id, p, "Command: upload_report\nStatus: ok\n%s%s", t2, t2);
  new_send_reply(p, SRV_RPL_OK);
}

static void
cmd_team_print(struct client_state *p, int len,
               struct prot_serve_pkt_simple *pkt)
{
  int res;

  if (get_peer_local_user(p) < 0) return;

  if (len != sizeof(*pkt)) {
    new_bad_packet(p, "team_print: invalid packet size %d", len);
    return;
  }

  if (!global->enable_printing || printing_suspended) {
    err("%d: printing request is denied", p->id);
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    return;
  }

  res = team_print_run(pkt->v.i, p->user_id);
  if (res < 0) {
    new_send_reply(p, res);
    return;
  }

  info("%d: team_print: ok, %d pages printed", p->id, res);
  append_audit_log(pkt->v.i, p, "Command: print\nStatus: ok\n  %d pages printed\n", res);
  new_send_reply(p, SRV_RPL_OK);
}

static void
do_submit_run(struct client_state *p,
              const unsigned char *proc_name,
              int need_retval,
              int priv_submit,  /* not used yet... */
              const struct section_problem_data *cur_prob,
              const struct section_language_data *cur_lang,
              int user_id,
              int contest_id,
              int locale_id,
              int variant,
              ej_ip_t ip,
              int ssl,
              size_t run_size,
              const unsigned char *run_bytes)
{
  char **dis_lang;
  const unsigned char *login;
  int i, run_id, arch_flags, r;
  time_t start_time, stop_time, user_deadline = 0;
  ruint32_t shaval[5];
  struct timeval precise_time;
  path_t run_arch;
  struct prot_serve_pkt_val retpack;

  info("%d: %s: %d, %d, %d, %d, %s, %s",
       p->id, proc_name, user_id, contest_id, locale_id,
       variant, cur_prob->short_name, cur_lang->short_name);

  /* sanity check for contest validity */
  if (contest_id != global->contest_id) {
    err("%d: contest_id does not match", p->id);
    new_send_reply(p, -SRV_ERR_BAD_CONTEST_ID);
    return;
  }

  /* check for user validity */
  if (!teamdb_lookup(user_id)) {
    err("%d: user_id is invalid", p->id);
    new_send_reply(p, -SRV_ERR_BAD_USER_ID);
    return;
  }
  if (user_id != p->user_id) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: pkt->user_id != p->user_id", p->id);
    return;
  }
  if (teamdb_get_flags(user_id) & (TEAM_BANNED | TEAM_LOCKED)) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: user %d cannot submit runs", p->id, user_id);
    return;
  }

  /* check for disabled languages */
  if (cur_prob->disable_language) {
    dis_lang = cur_prob->disable_language;
    for (i = 0; dis_lang[i]; i++)
      if (!strcmp(dis_lang[i], cur_lang->short_name))
        break;
    if (dis_lang[i]) {
      err("%d: the language %s is disabled for problem %s", p->id,
          cur_lang->short_name, cur_prob->short_name);
      new_send_reply(p, -SRV_ERR_LANGUAGE_DISABLED);
      return;
    }
  }

  /* check for variant validity */
  if (variant) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: variant cannot be set", p->id);
    return;
  }
  if (cur_prob->variant_num > 0) {
    if (!find_variant(user_id, cur_prob->id)) {
      new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
      err("%d: cannot get variant", p->id);
      return;
    }
  }

  /* check for start/stop times and deadlines */
  start_time = contest_start_time;
  stop_time = contest_stop_time;
  if (global->virtual) {
    start_time = run_get_virtual_start_time(user_id);
    stop_time = run_get_virtual_stop_time(user_id, current_time);
  }
  // personal deadline
  if (cur_prob->pd_total > 0) {
    login = teamdb_get_login(user_id);
    for (i = 0; i < cur_prob->pd_total; i++) {
      if (!strcmp(login, cur_prob->pd_infos[i].login)) {
        user_deadline = cur_prob->pd_infos[i].deadline;
        break;
      }
    }
  }
  // common problem deadline
  if (!user_deadline) user_deadline = cur_prob->t_deadline;
  if (user_deadline && current_time >= user_deadline) {
    err("%d: deadline expired", p->id);
    new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
    return;
  }
  // problem submit start time
  if (cur_prob->t_start_date && current_time < cur_prob->t_start_date) {
    err("%d: problem is not started", p->id);
    new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
    return;
  }
  // contest start/stop times
  if (!start_time) {
    err("%d: contest is not started", p->id);
    new_send_reply(p, -SRV_ERR_CONTEST_NOT_STARTED);
    return;
  }
  if (stop_time) {
    err("%d: contest already finished", p->id);
    new_send_reply(p, -SRV_ERR_CONTEST_FINISHED);
    return;
  }
  if (check_team_quota(user_id, run_size) < 0) {
    err("%d: user quota exceeded", p->id);
    new_send_reply(p, -SRV_ERR_QUOTA_EXCEEDED);
    return;
  }

  sha_buffer(run_bytes, run_size, shaval);
  gettimeofday(&precise_time, 0);
  if ((run_id = run_add_record(precise_time.tv_sec,
                               precise_time.tv_usec * 1000,
                               run_size,
                               shaval,
                               ip,
                               locale_id,
                               user_id,
                               cur_prob->id,
                               cur_lang->id, 0, 0)) < 0){
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  move_files_to_insert_run(run_id);

  arch_flags = archive_make_write_path(run_arch, sizeof(run_arch),
                                       global->run_archive_dir, run_id,
                                       run_size, 0);
  if (arch_flags < 0) {
    run_undo_add_record(run_id);
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  if (archive_dir_prepare(global->run_archive_dir, run_id, 0, 0) < 0) {
    run_undo_add_record(run_id);
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  if (generic_write_file(run_bytes, run_size, arch_flags, 0, run_arch, "") < 0) {
    run_undo_add_record(run_id);
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }

  if (global->ignore_duplicated_runs) {
    if ((r = run_check_duplicate(run_id)) < 0) {
      run_undo_add_record(run_id);
      new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
      return;
    } else if (r) {
      info("%d: %s: duplicated run, match %d", p->id, proc_name, r - 1);
      new_send_reply(p, -SRV_ERR_DUPLICATED_RUN);
      return;
    }
  }

  if (testing_suspended) {
    info("%d: testing is suspended", p->id);
    run_change_status(run_id, RUN_PENDING, 0, -1, 0);
    append_audit_log(run_id, p, "Command: submit\nStatus: pending\nRun-id: %d\n  Testing is suspended by the contest administrator\n", run_id);
    goto success;
  }

  if (cur_prob->disable_auto_testing 
      || (cur_prob->disable_testing && cur_prob->enable_compilation <= 0)
      || cur_lang->disable_auto_testing || cur_lang->disable_testing) {
    info("%d: %s: auto testing disabled", p->id, proc_name);
    run_change_status(run_id, RUN_PENDING, 0, -1, 0);
    append_audit_log(run_id, p, "Command: submit\nStatus: pending\nRun-id: %d\n  Testing disabled for this problem or language\n", run_id);
    goto success;
  }

  if (queue_compile_request(run_bytes, run_size, run_id,
                            cur_lang->compile_id, locale_id,
                            cur_prob->output_only,
                            cur_lang->src_sfx,
                            cur_lang->compiler_env, -1, 0) < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }

  info("%d: %s: ok", p->id, proc_name);
  append_audit_log(run_id, p, "Command: submit\nStatus: ok\nRun-id: %d\n", run_id);
  /* fallthrough */

 success:
  if (!need_retval) return new_send_reply(p, SRV_RPL_OK);

  memset(&retpack, 0, sizeof(retpack));
  retpack.b.id = SRV_RPL_VALUE;
  retpack.b.magic = PROT_SERVE_PACKET_MAGIC;
  retpack.value = run_id;
  new_enqueue_reply(p, sizeof(retpack), &retpack);
}

static void
cmd_team_submit_run(struct client_state *p, int len, 
                    struct prot_serve_pkt_submit_run *pkt)
{
  if (get_peer_local_user(p) < 0) return;

  if (len < sizeof(*pkt)) {
    new_bad_packet(p, "team_submit_run: packet is too small: %d", len);
    return;
  }
  if (pkt->lang_id < 1 || pkt->lang_id > max_lang || !langs[pkt->lang_id]
      || langs[pkt->lang_id]->disabled) {
    err("%d: lang_id is invalid", p->id);
    new_send_reply(p, -SRV_ERR_BAD_LANG_ID);
    return;
  }
  if (!langs[pkt->lang_id]->binary && pkt->run_len != strlen(pkt->data)) {
    err("%d: data format error: binary file?", p->id);
    new_send_reply(p, -SRV_ERR_DATA_FORMAT);
    return;
  }
  if (len != sizeof(*pkt) + pkt->run_len) {
    new_bad_packet(p, "team_submit_run: packet length does not match");
    return;
  }
  if (pkt->prob_id < 1 || pkt->prob_id > max_prob || !probs[pkt->prob_id]) {
    err("%d: prob_id is invalid", p->id);
    new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
    return;
  }

  do_submit_run(p, "team_submit_run", 0, 0,
                probs[pkt->prob_id], langs[pkt->lang_id],
                pkt->user_id, pkt->contest_id, pkt->locale_id, pkt->variant,
                p->ip, p->ssl, pkt->run_len, pkt->data);
  return;
}

static void
cmd_user_submit_run_2(struct client_state *p, int len,
                      struct prot_serve_pkt_submit_run_2 *pkt)
{
  const unsigned char *prob_ptr, *lang_ptr, *src_ptr;
  size_t prob_len, lang_len, pkt_len, src_len;
  int prob_id, lang_id;
  struct section_problem_data *cur_prob;
  struct section_language_data *cur_lang;

  if (get_peer_local_user(p) < 0) return;

  pkt_len = sizeof(*pkt);
  if (len < pkt_len) {
    new_bad_packet(p, "user_submit_run_2: packet is too small: %d", len);
    return;
  }
  prob_ptr = pkt->data;
  prob_len = strlen(prob_ptr);
  pkt_len += prob_len;
  if (prob_len != pkt->prob_size || len < pkt_len) {
    new_bad_packet(p, "user_submit_run_2: prob_name length mismatch");
    return;
  }
  lang_ptr = prob_ptr + prob_len + 1;
  lang_len = strlen(lang_ptr);
  pkt_len += lang_len;
  if (lang_len != pkt->lang_size || len < pkt_len) {
    new_bad_packet(p, "user_submit_run_2: lang_name length mismatch");
    return;
  }
  src_ptr = lang_ptr + lang_len + 1;
  src_len = strlen(src_ptr);
  pkt_len += pkt->run_size;
  if (pkt_len != len) {
    new_bad_packet(p, "user_submit_run_2: packet length mismatch");
    return;
  }

  for (prob_id = 1; prob_id <= max_prob; prob_id++)
    if (probs[prob_id] && !strcmp(probs[prob_id]->short_name, prob_ptr))
      break;
  if (prob_id > max_prob) {
    err("%d: prob_name `%s' is invalid", p->id, prob_ptr);
    new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
    return;
  }
  cur_prob = probs[prob_id];
  for (lang_id = 1; lang_id <= max_lang; lang_id++)
    if (langs[lang_id] && !strcmp(langs[lang_id]->short_name, lang_ptr))
      break;
  if (lang_id > max_lang) {
    err("%d: lang_name `%s' is invalid", p->id, lang_ptr);
    new_send_reply(p, -SRV_ERR_BAD_LANG_ID);
    return;
  }
  cur_lang = langs[lang_id];

  if (cur_lang->disabled) {
    err("%d: language %d is disabled", p->id, lang_id);
    new_send_reply(p, -SRV_ERR_BAD_LANG_ID);
    return;
  }
  if (!cur_lang->binary && pkt->run_size != src_len) {
    err("%d: data format error: binary file?", p->id);
    new_send_reply(p, -SRV_ERR_DATA_FORMAT);
    return;
  }

  do_submit_run(p, "user_submit_run_2", 1, 0,
                cur_prob, cur_lang,
                pkt->user_id, pkt->contest_id, 0, pkt->variant,
                p->ip, p->ssl, pkt->run_size, src_ptr);
}

static unsigned char *
get_email_sender(const struct contest_desc *cnts)
{
  int sysuid;
  struct passwd *ppwd;

  if (cnts && cnts->register_email) return cnts->register_email;
  sysuid = getuid();
  ppwd = getpwuid(sysuid);
  return ppwd->pw_name;
}

static void
cmd_team_submit_clar(struct client_state *p, int len, 
                     struct prot_serve_pkt_submit_clar *pkt)
{
  unsigned char *subj_ptr, *text_ptr;
  int clar_id, subj_len, full_len;
  path_t clar_name;
  unsigned char *full_txt = 0;
  time_t start_time, stop_time;
  const struct contest_desc *cnts = 0;

  unsigned char subj[CLAR_MAX_SUBJ_TXT_LEN + 16];
  unsigned char bsubj[CLAR_MAX_SUBJ_LEN + 16];

  if (get_peer_local_user(p) < 0) return;

  if (len < sizeof(*pkt)) {
    new_bad_packet(p, "team_submit_clar: packet is too small: %d", len);
    return;
  }
  subj_ptr = pkt->data;
  if (strlen(subj_ptr) != pkt->subj_len) {
    new_bad_packet(p, "team_submit_clar: subj_len does not match");
    return;
  }
  text_ptr = subj_ptr + pkt->subj_len + 1;
  if (strlen(text_ptr) != pkt->text_len) {
    new_bad_packet(p, "team_submit_clar: text_len does not match");
    return;
  }
  if (len != sizeof(*pkt) + pkt->subj_len + pkt->text_len) {
    new_bad_packet(p, "team_submit_clar: packet length does not match");
    return;
  }

  info("%d: team_submit_clar: %d, %d, %d",
       p->id, pkt->user_id, pkt->contest_id, pkt->locale_id);

  if (pkt->contest_id != global->contest_id) {
    err("%d: contest_id does not match", p->id);
    new_send_reply(p, -SRV_ERR_BAD_CONTEST_ID);
    return;
  }
  if (!teamdb_lookup(pkt->user_id)) {
    err("%d: user_id is invalid", p->id);
    new_send_reply(p, -SRV_ERR_BAD_USER_ID);
    return;
  }
  if (p->user_id && pkt->user_id != p->user_id) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: pkt->user_id != p->user_id", p->id);
    return;
  }
  if (global->disable_clars || global->disable_team_clars) {
    err("%d: clarifications are disabled", p->id);
    new_send_reply(p, -SRV_ERR_CLARS_DISABLED);
    return;
  }
  /* FIXME: parametrize it! */
  if (pkt->subj_len > 80) {
    err("%d: subject length exceeds maximal", p->id);
    new_send_reply(p, -SRV_ERR_SUBJECT_TOO_LONG);
    return;
  }
  start_time = contest_start_time;
  stop_time = contest_stop_time;
  if (global->virtual) {
    start_time = run_get_virtual_start_time(p->user_id);
    stop_time = run_get_virtual_stop_time(p->user_id, current_time);
  }
  if (!start_time) {
    err("%d: contest is not started", p->id);
    new_send_reply(p, -SRV_ERR_CONTEST_NOT_STARTED);
    return;
  }
  if (stop_time) {
    err("%d: contest already finished", p->id);
    new_send_reply(p, -SRV_ERR_CONTEST_FINISHED);
    return;
  }

  // process subject and message body
  memset(subj, 0, sizeof(subj));
  if (pkt->subj_len >= CLAR_MAX_SUBJ_TXT_LEN) {
    strncpy(subj, subj_ptr, CLAR_MAX_SUBJ_TXT_LEN);
    subj[CLAR_MAX_SUBJ_TXT_LEN - 1] = '.';
    subj[CLAR_MAX_SUBJ_TXT_LEN - 2] = '.';
    subj[CLAR_MAX_SUBJ_TXT_LEN - 3] = '.';
  } else if (!pkt->subj_len) {
    subj_ptr = _("(no subject)");
    strcpy(subj, subj_ptr);
  } else {
    strcpy(subj, subj_ptr);
  }
  subj_len = strlen(subj_ptr);
  base64_encode_str(subj, bsubj);

  full_txt = alloca(subj_len + pkt->text_len + 64);
  full_len = sprintf(full_txt, "Subject: %s\n\n%s", subj_ptr, text_ptr);

  if (check_clar_qouta(pkt->user_id, full_len) < 0) {
    err("%d: user quota exceeded", p->id);
    new_send_reply(p, -SRV_ERR_QUOTA_EXCEEDED);
    return;
  }

  if ((clar_id = clar_add_record(clarlog_state, current_time, full_len,
                                 run_unparse_ip(pkt->ip),
                                 pkt->user_id, 0, 0, 0, 0, bsubj)) < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  sprintf(clar_name, "%06d", clar_id);
  if (generic_write_file(full_txt, full_len, 0,
                         global->clar_archive_dir, clar_name, "") < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }

  // send an e-mail
  if (contests_get(global->contest_id, &cnts) >= 0
      && cnts && cnts->clar_notify_email) {
    unsigned char esubj[1024];
    FILE *fmsg = 0;
    char *ftxt = 0;
    size_t flen = 0;
    unsigned char *user_name = 0;
    unsigned char *originator = 0;
    unsigned char *mail_args[7];

    snprintf(esubj, sizeof(esubj),
             "New clar request in contest %d",
             global->contest_id);
    user_name = teamdb_get_name(pkt->user_id);
    if (!user_name || !*user_name)
      user_name = teamdb_get_login(pkt->user_id);
    originator = get_email_sender(cnts);
    fmsg = open_memstream(&ftxt, &flen);
    fprintf(fmsg, "Hello,\n\nNew clarification request is received\n"
            "Contest: %d (%s)\n"
            "User: %d (%s)\n"
            "Subject: %s\n\n"
            "%s\n\n-\n"
            "Regards,\n"
            "the ejudge contest management system\n",
            global->contest_id, cnts->name,
            pkt->user_id, user_name,
            subj_ptr, text_ptr);
    fclose(fmsg); fmsg = 0;
    mail_args[0] = "mail";
    mail_args[1] = "";
    mail_args[2] = esubj;
    mail_args[3] = originator;
    mail_args[4] = cnts->clar_notify_email;
    mail_args[5] = ftxt;
    mail_args[6] = 0;
    send_job_packet(NULL, mail_args);
    xfree(ftxt); ftxt = 0;
  }

  info("%d: team_submit_clar: ok", p->id);
  new_send_reply(p, SRV_RPL_OK);
}

static void
cmd_command_0(struct client_state *p, int len,
              struct prot_serve_pkt_simple *pkt)
{
  time_t start_time, stop_time;
  int run_id;
  struct timeval precise_time;

  if (get_peer_local_user(p) < 0) return;

  if (len != sizeof(*pkt)) {
    new_bad_packet(p, "command_0: invalid packet length");
    return;
  }

  info("%d: command_0: %d", p->id, pkt->b.id);
  if (!global->virtual) {
    err("%d: command allowed only in virtual contest mode", p->id);
    new_send_reply(p, -SRV_ERR_ONLY_VIRTUAL);
    return;
  }
  if (!contest_start_time) {
    err("%d: contest is not started by administrator", p->id);
    new_send_reply(p, -SRV_ERR_CONTEST_NOT_STARTED);
    return;
  }

  switch (pkt->b.id) {
  case SRV_CMD_VIRTUAL_START:
    start_time = run_get_virtual_start_time(p->user_id);
    if (start_time) {
      err("%d: virtual contest for %d already started", p->id, p->user_id);
      new_send_reply(p, -SRV_ERR_CONTEST_STARTED);
      return;
    }
    gettimeofday(&precise_time, 0);
    run_id = run_virtual_start(p->user_id, precise_time.tv_sec, p->ip,
                               precise_time.tv_usec * 1000);
    if (run_id < 0) return;
    move_files_to_insert_run(run_id);
    info("%d: virtual contest started for %d", p->id, p->user_id);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_VIRTUAL_STOP:
    start_time = run_get_virtual_start_time(p->user_id);
    if (!start_time) {
      err("%d: virtual contest for %d is not started", p->id, p->user_id);
      new_send_reply(p, -SRV_ERR_CONTEST_NOT_STARTED);
      return;
    }
    stop_time = run_get_virtual_stop_time(p->user_id, current_time);
    if (stop_time) {
      err("%d: virtual contest for %d already stopped", p->id, p->user_id);
      new_send_reply(p, -SRV_ERR_CONTEST_FINISHED);
      return;
    }
    gettimeofday(&precise_time, 0);
    run_id = run_virtual_stop(p->user_id, precise_time.tv_sec, p->ip,
                              precise_time.tv_usec * 1000);
    if (run_id < 0) return;
    move_files_to_insert_run(run_id);
    info("%d: virtual contest stopped for %d", p->id, p->user_id);
    new_send_reply(p, SRV_RPL_OK);
    return;
  default:
    err("%d: unhandled command", p->id);
    new_send_reply(p, -SRV_ERR_PROTOCOL);
  }
}

static void
cmd_reset_filter(struct client_state *p, int len,
                 struct prot_serve_pkt_reset_filter *pkt)
{
  if (get_peer_local_user(p) < 0) return;

  if (len != sizeof(*pkt)) {
    new_bad_packet(p, "reset_filter: bad packet length");
    return;
  }

  info("%d: reset_filter: %016llx,%d,%d", p->id, pkt->session_id,
       pkt->user_id, pkt->contest_id);

  if (p->user_id != pkt->user_id) {
    err("%d: user_ids do not match: %d, %d", p->id, p->user_id, pkt->user_id);
    new_send_reply(p, -SRV_ERR_BAD_USER_ID);
    return;
  }
  if (pkt->contest_id != global->contest_id) {
    err("%d: contest_ids do not match: %d, %d", p->id,
        global->contest_id, pkt->contest_id);
    new_send_reply(p, -SRV_ERR_BAD_CONTEST_ID);
    return;
  }
  if (!pkt->session_id) {
    err("%d: session_id is not set", p->id);
    new_send_reply(p, -SRV_ERR_BAD_SESSION_ID);
    return;
  }
  if (p->priv_level < PRIV_LEVEL_JUDGE) {
    err("%d: not enough privileges", p->id);
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    return;
  }

  switch (pkt->b.id) {
  case SRV_CMD_RESET_FILTER:
    html_reset_filter(p->user_id, pkt->session_id);
    break;
  case SRV_CMD_RESET_CLAR_FILTER:
    html_reset_clar_filter(p->user_id, pkt->session_id);
    break;
  }

  info("%d: reset_filter: ok", p->id);
  new_send_reply(p, SRV_RPL_OK);
  return;
}

#if 0
/* not yet used */
static void
cmd_judge_command_0(struct client_state *p, int len,
                    struct prot_serve_pkt_simple *pkt)
{
  if (get_peer_local_user(p) < 0) return;

  if (len != sizeof(*pkt)) {
    new_bad_packet(p, "judge_command: invalid packet length");
    return;
  }

  info("%d: judge_command: %d", p->id, pkt->b.id);

  if (p->priv_level < PRIV_LEVEL_JUDGE) {
    err("%d: not enough privileges", p->id);
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    return;
  }

  switch (pkt->b.id) {
  case SRV_CMD_RESET_FILTER:
    html_reset_filter(p->user_id);
    info("%d: reset_filter: ok", p->id);
    new_send_reply(p, SRV_RPL_OK);
    return;
  default:
    err("%d: unhandled command", p->id);
    new_send_reply(p, -SRV_ERR_PROTOCOL);
  }
}
#endif /* cmd_judge_command_0 is not compiled */

static void do_rejudge_all(struct client_state *p);
static void do_judge_suspended(struct client_state *p);
static void do_rejudge_problem(int, struct client_state *p);
static void do_rejudge_by_mask(int, unsigned long *, struct client_state *p,
                               int force_flag, int priority_adjustment);
static int count_transient_runs(void);

static void
do_squeeze_runs(void)
{
  int i, j, tot;

  tot = run_get_total();
  for (i = 0, j = 0; i < tot; i++) {
    if (run_get_status(i) == RUN_EMPTY) continue;
    if (i != j) {
      archive_rename(global->run_archive_dir, 0, i, 0, j, 0, 0);
      archive_rename(global->xml_report_archive_dir, 0, i, 0, j, 0, 1);
      archive_rename(global->report_archive_dir, 0, i, 0, j, 0, 1);
      if (global->team_enable_rep_view) {
        archive_rename(global->team_report_archive_dir, 0, i, 0, j, 0, 0);
      }
      if (global->enable_full_archive) {
        archive_rename(global->full_archive_dir, 0, i, 0, j, 0, 0);
      }
      archive_rename(global->audit_log_dir, 0, i, 0, j, 0, 1);
    }
    j++;
  }
  for (; j < tot; j++) {
    archive_remove(global->run_archive_dir, j, 0);
    archive_remove(global->xml_report_archive_dir, j, 0);
    archive_remove(global->report_archive_dir, j, 0);
    if (global->team_enable_rep_view) {
      archive_remove(global->team_report_archive_dir, j, 0);
    }
    if (global->enable_full_archive) {
      archive_remove(global->full_archive_dir, j, 0);
    }
    archive_remove(global->audit_log_dir, j, 0);
  }
  run_squeeze_log();

  /* FIXME: add an audit record for each renumbered run */
}

static void
cmd_rejudge_by_mask(struct client_state *p, int len,
                    struct prot_serve_pkt_rejudge_by_mask *pkt)
{
  int force_full = 0;
  int priority_adjustment = 0;

  if (get_peer_local_user(p) < 0) return;

  if (len < sizeof(*pkt)) {
    new_bad_packet(p, "rejudge_by_mask: packet size %d is too small", len);
    return;
  }
  if (pkt->mask_size <= 0) {
    new_bad_packet(p, "rejudge_by_mask: mask_size == %d is invalid",
                   pkt->mask_size);
    return;
  }
  if (len != sizeof(*pkt) + sizeof(pkt->mask[0]) * (pkt->mask_size - 1)) {
    new_bad_packet(p, "rejudge_by_mask: length %d mismatch", len);
    return;
  }

  info("%d: rejudge_by_mask: %d", p->id, pkt->mask_size);

  if (!check_cnts_caps(p->user_id, OPCAP_REJUDGE_RUN)) {
    err("%d: user %d has no capability %d for the contest",
        p->id, p->user_id, OPCAP_REJUDGE_RUN);
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    return;
  }

  if (global->score_system_val == SCORE_OLYMPIAD &&
      !olympiad_judging_mode && pkt->b.id == SRV_CMD_FULL_REJUDGE_BY_MASK) {
    force_full = 1;
    priority_adjustment = 10;
  }

  do_rejudge_by_mask(pkt->mask_size, pkt->mask, p, force_full,
                     priority_adjustment);
  new_send_reply(p, SRV_RPL_OK);
}

static void
do_start_cmd(void)
{
  tpTask tsk = 0;

  if (!global->contest_start_cmd[0]) return;
  if (!(tsk = task_New())) return;
  task_AddArg(tsk, global->contest_start_cmd);
  task_SetPathAsArg0(tsk);
  if (task_Start(tsk) < 0) {
    task_Delete(tsk);
    return;
  }
  task_Wait(tsk);
  task_Delete(tsk);
}

static void
send_run_quit_command(void)
{
  void *pkt_buf = 0;
  size_t pkt_size = 0;

  run_request_packet_quit(&pkt_size, &pkt_buf);
  generic_write_file(pkt_buf, pkt_size, SAFE, global->run_queue_dir, "QUIT", "");
  xfree(pkt_buf);
}

static void
cmd_priv_command_0(struct client_state *p, int len,
                   struct prot_serve_pkt_simple *pkt)
{
  int res;

  if (get_peer_local_user(p) < 0) return;

  if (len != sizeof(*pkt)) {
    new_bad_packet(p, "priv_command_0: invalid packet length");
    return;
  }

  info("%d: priv_command_0: %d", p->id, pkt->b.id);

  if (p->priv_level != PRIV_LEVEL_ADMIN) {
    err("%d: not enough privileges", p->id);
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    return;
  }
  switch (pkt->b.id) {
  case SRV_CMD_SUSPEND:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    clients_suspended = 1;
    update_status_file(1);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_RESUME:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    clients_suspended = 0;
    update_status_file(1);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_TEST_SUSPEND:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    testing_suspended = 1;
    update_status_file(1);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_TEST_RESUME:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    testing_suspended = 0;
    update_status_file(1);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_PRINT_SUSPEND:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    printing_suspended = 1;
    update_status_file(1);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_PRINT_RESUME:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    printing_suspended = 0;
    update_status_file(1);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_SET_JUDGING_MODE:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    if (global->score_system_val != SCORE_OLYMPIAD) {
      new_send_reply(p, -SRV_ERR_NOT_SUPPORTED);
      return;
    }
    /*
    if (!contest_stop_time) {
      new_send_reply(p, -SRV_ERR_CONTEST_NOT_FINISHED);
      return;
    }
    */
    olympiad_judging_mode = 1;
    update_status_file(1);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_SET_ACCEPTING_MODE:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    if (global->score_system_val != SCORE_OLYMPIAD) {
      new_send_reply(p, -SRV_ERR_NOT_SUPPORTED);
      return;
    }
    /*
    if (!contest_stop_time) {
      new_send_reply(p, -SRV_ERR_CONTEST_NOT_FINISHED);
      return;
    }
    */
    olympiad_judging_mode = 0;
    update_status_file(1);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_UPDATE_STAND:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    update_standings_file(1);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_SOFT_UPDATE_STAND:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    update_standings_file(0);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_RESET:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    /* FIXME: we need to reset all the components (compile, serve) as well */
    /* reset run log */
    run_reset(global->contest_time);
    contest_duration = global->contest_time;
    run_set_duration(contest_duration);
    clar_reset(clarlog_state);
    /* clear all submissions and clarifications */
    if (global->clar_archive_dir[0])
      clear_directory(global->clar_archive_dir);
    if (global->xml_report_archive_dir[0])
      clear_directory(global->xml_report_archive_dir);
    if (global->report_archive_dir[0])
      clear_directory(global->report_archive_dir);
    if (global->run_archive_dir[0])
      clear_directory(global->run_archive_dir);
    if (global->team_report_archive_dir[0])
      clear_directory(global->team_report_archive_dir);
    if (global->full_archive_dir[0])
      clear_directory(global->full_archive_dir);
    if (global->audit_log_dir[0])
      clear_directory(global->audit_log_dir);
    if (global->team_extra_dir[0])
      clear_directory(global->team_extra_dir);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_START:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    if (contest_stop_time) {
      err("%d: contest already finished", p->id);
      new_send_reply(p, -SRV_ERR_CONTEST_FINISHED);
      return;
    }
    if (contest_start_time) {
      err("%d: contest already started", p->id);
      new_send_reply(p, -SRV_ERR_CONTEST_STARTED);
      return;
    }
    run_start_contest(current_time);
    do_start_cmd();
    contest_start_time = current_time;
    info("contest started: %lu", current_time);
    update_status_file(1);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_STOP:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    if (contest_stop_time) {
      err("%d: contest already finished", p->id);
      new_send_reply(p, -SRV_ERR_CONTEST_FINISHED);
      return;
    }
    if (!contest_start_time) {
      err("%d: contest is not started", p->id);
      new_send_reply(p, -SRV_ERR_CONTEST_NOT_STARTED);
      return;
    }
    run_stop_contest(current_time);
    contest_stop_time = current_time;
    info("contest stopped: %lu", current_time);
    update_status_file(1);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_REJUDGE_ALL:
    if (!check_cnts_caps(p->user_id, OPCAP_EDIT_RUN)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    do_rejudge_all(p);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_JUDGE_SUSPENDED:
    if (!check_cnts_caps(p->user_id, OPCAP_EDIT_RUN)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    do_judge_suspended(p);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_REJUDGE_PROBLEM:
    if (!check_cnts_caps(p->user_id, OPCAP_EDIT_RUN)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    if (pkt->v.i < 1 || pkt->v.i > max_prob || !probs[pkt->v.i]) {
      err("%d: invalid problem id %d", p->id, pkt->v.i);
      new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
      return;
    }
    do_rejudge_problem(pkt->v.i, p);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_SCHEDULE:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    if (contest_stop_time) {
      err("%d: contest already finished", p->id);
      new_send_reply(p, -SRV_ERR_CONTEST_FINISHED);
      return;
    }
    if (contest_start_time) {
      err("%d: contest already started", p->id);
      new_send_reply(p, -SRV_ERR_CONTEST_STARTED);
      return;
    }
    run_sched_contest(pkt->v.t);
    contest_sched_time = pkt->v.t;
    info("%d: contest scheduled: %lu", p->id, pkt->v.t);
    update_standings_file(0);
    update_status_file(1);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_DURATION:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    if (contest_stop_time && !global->enable_continue) {
      err("%d: contest already finished", p->id);
      new_send_reply(p, -SRV_ERR_CONTEST_FINISHED);
      return;
    }
    if (pkt->v.t < 0 || pkt->v.t > 1000000) {
      err("%d: invalid duration: %ld", p->id, pkt->v.t);
      new_send_reply(p, -SRV_ERR_BAD_DURATION);
      return;
    }
    if (!pkt->v.t) {
      contest_duration = 0;
      run_set_duration(contest_duration);
      info("contest duration set to infinite time");
      update_standings_file(0);
      update_status_file(1);
      new_send_reply(p, SRV_RPL_OK);
      return;
    }
    /*
    if (!pkt->v.t) {
      err("%d: duration cannot be set to unlimited", p->id);
      new_send_reply(p, -SRV_ERR_BAD_DURATION);
      return;
    }
    */
    /*
    if (!contest_duration) {
      err("%d: unlimited contest duration cannot be changed", p->id);
      new_send_reply(p, -SRV_ERR_BAD_DURATION);
      return;
    }
    */
    if (contest_start_time && contest_start_time+pkt->v.t*60 < current_time) {
      err("%d: contest duration is too short", p->id);
      new_send_reply(p, -SRV_ERR_BAD_DURATION);
      return;
    }
    contest_duration = pkt->v.t * 60;
    run_set_duration(contest_duration);
    info("contest duration reset to %ld", pkt->v.t);
    update_standings_file(0);
    update_status_file(1);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_SQUEEZE_RUNS:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    do_squeeze_runs();
    info("%d: run log is squeezed", p->id);
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_CLEAR_RUN:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    if (pkt->v.i < 0 || pkt->v.i >= run_get_total()) {
      err("%d: invalid run id %d", p->id, pkt->v.i);
      new_send_reply(p, -SRV_ERR_BAD_RUN_ID);
      return;
    }
    if (run_is_readonly(pkt->v.i)) {
      err("%d: run %d is readonly", p->id, pkt->v.i);
      new_send_reply(p, -SRV_ERR_READONLY_RUN);
      return;
    }
    if (run_clear_entry(pkt->v.i) < 0) {
      new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
      return;
    }
    info("%d: run %d is cleared", p->id, pkt->v.i);
    new_send_reply(p, SRV_RPL_OK);
    return;

  case SRV_CMD_PRIV_PRINT_RUN:
    if (!check_cnts_caps(p->user_id, OPCAP_PRINT_RUN)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_PRINT_RUN);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    if (pkt->v.i < 0 || pkt->v.i >= run_get_total()) {
      err("%d: invalid run id %d", p->id, pkt->v.i);
      new_send_reply(p, -SRV_ERR_BAD_RUN_ID);
      return;
    }

    res = priv_print_run(pkt->v.i, p->user_id);
    if (res < 0) {
      new_send_reply(p, res);
      return;
    }
    info("%d: run %d is printed, %d pages", p->id, pkt->v.i, res);
    new_send_reply(p, SRV_RPL_OK);
    return;

  case SRV_CMD_CONTINUE:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    if (!global->enable_continue) {
      err("%d: contest cannot be continued", p->id);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }
    if (!contest_start_time) {
      err("%d: contest is not started", p->id);
      new_send_reply(p, -SRV_ERR_CONTEST_NOT_STARTED);
      return;
    }
    if (!contest_stop_time) {
      err("%d: contest is not finished", p->id);
      new_send_reply(p, -SRV_ERR_CONTEST_NOT_FINISHED);
      return;
    }
    if (contest_duration && current_time >= contest_start_time + contest_duration) {
      err("%d: insufficient duration to continue the contest", p->id);
      new_send_reply(p, -SRV_ERR_BAD_DURATION);
      return;
    }
    contest_stop_time = 0;
    run_stop_contest(0);
    update_status_file(1);
    new_send_reply(p, SRV_RPL_OK);
    return;

  case SRV_CMD_QUIT:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }
    if (cmdline_socket_fd < 0) {
      err("%d: quit: not in daemonized mode", p->id);
      new_send_reply(p, -SRV_ERR_NOT_SUPPORTED);
      return;
    }
    send_run_quit_command();
    interrupt_signaled = 1;
    new_send_reply(p, SRV_RPL_OK);
    return;
  case SRV_CMD_HAS_TRANSIENT_RUNS:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }
    if ((res = count_transient_runs()) > 0) {
      err("%d: there are %d transient runs", p->id, res);
      new_send_reply(p, -SRV_ERR_TRANSIENT_RUNS);
      return;
    }
    new_send_reply(p, SRV_RPL_OK);
    return;

  default:
    err("%d: unhandled command", p->id);
    new_send_reply(p, -SRV_ERR_PROTOCOL);
  }
}

static void
cmd_simple_command(struct client_state *p, int len,
                   struct prot_serve_pkt_simple *pkt)
{
  if (get_peer_local_user(p) < 0) return;

  if (len != sizeof(*pkt)) {
    new_bad_packet(p, "simple_command: invalid packet length");
    return;
  }

  info("%d: simple_command: %d", p->id, pkt->b.id);

  switch (pkt->b.id) {
  case SRV_CMD_GET_TEST_SUSPEND:
    new_send_reply(p, !!clients_suspended);
    return;
  default:
    err("%d: unhandled command", p->id);
    new_send_reply(p, -SRV_ERR_PROTOCOL);
  }
}

static void rejudge_run(int run_id, struct client_state *p,
                        int force_full_rejudge, int priority_adjustment);

static void
cmd_edit_run(struct client_state *p, int len,
             struct prot_serve_pkt_run_info *pkt)
{
  unsigned char const *user_login_ptr;
  struct run_entry run, cur_run;
  unsigned int run_flags = 0;
  int prob_id;

  if (get_peer_local_user(p) < 0) return;

  if (len < sizeof(*pkt)) {
    new_bad_packet(p, "edit_run: packet is too small: %d", len);
    return;
  }
  user_login_ptr = pkt->data;
  if (strlen(user_login_ptr) != pkt->user_login_len) {
    new_bad_packet(p, "edit_run: user_login_len mismatch");
    return;
  }
  if (pkt->run_src_len < 0) {
    new_bad_packet(p, "edit_run: src_len < 0");
    return;
  }
  if (pkt->run_src_len > 0) {
    new_bad_packet(p, "edit_run: src_len > 0");
    return;
  }
  if (len != sizeof(*pkt) + pkt->user_login_len) {
    new_bad_packet(p, "edit_run: packet length mismatch");
    return;
  }
  if (run_get_entry(pkt->run_id, &cur_run) < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }

  if (cur_run.is_readonly && pkt->mask != PROT_SERVE_RUN_READONLY_SET) {
    new_send_reply(p, -SRV_ERR_READONLY_RUN);
    return;
  }

  info("%d: edit_run: %d, %d", p->id, pkt->run_id, pkt->mask);
  if (p->priv_level != PRIV_LEVEL_ADMIN) {
    err("%d: unsifficiend privileges", p->id);
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    return;
  }
  if (pkt->run_id < 0 || pkt->run_id >= run_get_total()) {
    err("%d: invalid run_id", p->id);
    new_send_reply(p, -SRV_ERR_BAD_RUN_ID);
    return;
  }
  if ((pkt->mask & PROT_SERVE_RUN_UID_SET)
      && (pkt->mask & PROT_SERVE_RUN_LOGIN_SET)) {
    err("%d: both uid and login are set", p->id);
    new_send_reply(p, -SRV_ERR_PROTOCOL);
    return;
  }

  memset(&run, 0, sizeof(run));
  if ((pkt->mask & PROT_SERVE_RUN_UID_SET)) {
    if (teamdb_lookup(pkt->user_id) != 1) {
      err("%d: invalid user_id %d", p->id, pkt->user_id);
      new_send_reply(p, -SRV_ERR_BAD_USER_ID);
      return;
    }
    run.team = pkt->user_id;
    run_flags |= RUN_ENTRY_USER;
  }
  if ((pkt->mask & PROT_SERVE_RUN_LOGIN_SET)) {
    if ((run.team = teamdb_lookup_login(user_login_ptr)) <= 0) {
      err("%d: invalid login <%s>", p->id, user_login_ptr);
      new_send_reply(p, -SRV_ERR_BAD_USER_ID);
      return;
    }
    run_flags |= RUN_ENTRY_USER;
  }
  if ((pkt->mask & PROT_SERVE_RUN_PROB_SET)) {
    if (pkt->prob_id <= 0 || pkt->prob_id > max_prob || !probs[pkt->prob_id]) {
      err("%d: invalid problem %d", p->id, pkt->prob_id);
      new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
      return;
    }
    run.problem = pkt->prob_id;
    run_flags |= RUN_ENTRY_PROB;
  }
  if ((pkt->mask & PROT_SERVE_RUN_LANG_SET)) {
    if (pkt->lang_id <= 0 || pkt->lang_id > max_lang || !langs[pkt->lang_id]) {
      err("%d: invalid language %d", p->id, pkt->lang_id);
      new_send_reply(p, -SRV_ERR_BAD_LANG_ID);
      return;
    }
    run.language = pkt->lang_id;
    run_flags |= RUN_ENTRY_LANG;
  }
  if ((pkt->mask & PROT_SERVE_RUN_STATUS_SET)) {
    if (!is_valid_status(pkt->status, 1)) {
      err("%d: invalid status %d", p->id, pkt->status);
      new_send_reply(p, -SRV_ERR_BAD_STATUS);
      return;
    }
    run.status = pkt->status;
    run_flags |= RUN_ENTRY_STATUS;
  }
  if ((pkt->mask & PROT_SERVE_RUN_IMPORTED_SET)) {
    if (pkt->is_imported < 0 || pkt->is_imported > 1) {
      err("%d: invalid is_imported value %d", p->id, pkt->is_imported);
      new_send_reply(p, -SRV_ERR_PROTOCOL);
      return;
    }
    run.is_imported = pkt->is_imported;
    run_flags |= RUN_ENTRY_IMPORTED;
  }
  if ((pkt->mask & PROT_SERVE_RUN_HIDDEN_SET)) {
    if (pkt->is_hidden < 0 || pkt->is_hidden > 1) {
      err("%d: invalid is_hidden value %d", p->id, pkt->is_hidden);
      new_send_reply(p, -SRV_ERR_PROTOCOL);
      return;
    }
    run.is_hidden = pkt->is_hidden;
    run_flags |= RUN_ENTRY_HIDDEN;
  }
  if ((pkt->mask & PROT_SERVE_RUN_VARIANT_SET)) {
    prob_id = cur_run.problem;
    if ((run_flags & RUN_ENTRY_PROB)) {
      prob_id = run.problem;
    }
    if (prob_id <= 0 || prob_id > max_prob || !probs[prob_id]) {
      err("%d: invalid problem id %d", p->id, prob_id);
      new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
      return;
    }
    if (probs[prob_id]->variant_num <= 0) {
      err("%d: problem %d has no variants", p->id, prob_id);
      new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
      return;
    }
    if (pkt->variant < 0 || pkt->variant > probs[prob_id]->variant_num) {
      err("%d: invalid variant %d for problem %d", p->id,pkt->variant,prob_id);
      new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
      return;
    }
    run.variant = pkt->variant;
    run_flags |= RUN_ENTRY_VARIANT;
  }
  if ((pkt->mask & PROT_SERVE_RUN_TESTS_SET)) {
    if (pkt->tests < -1 || pkt->tests > 126) {
      err("%d: new test value %d is out of range", p->id, pkt->tests);
      new_send_reply(p, -SRV_ERR_PROTOCOL);
      return;
    }
    if (global->score_system_val == SCORE_OLYMPIAD
        || global->score_system_val == SCORE_KIROV) {
      pkt->tests++;
    }
    if (pkt->tests == -1) pkt->tests = 0;

    run.test = pkt->tests;
    run_flags |= RUN_ENTRY_TEST;
  }
  if ((pkt->mask & PROT_SERVE_RUN_SCORE_SET)) {
    if (pkt->score < -1 || pkt->score > 100000) {
      err("%d: new score value %d is out of range", p->id, pkt->score);
      new_send_reply(p, -SRV_ERR_PROTOCOL);
      return;
    }
    if (global->score_system_val != SCORE_OLYMPIAD
        && global->score_system_val != SCORE_KIROV
        && global->score_system_val != SCORE_MOSCOW) {
      err("%d: score cannot be set in the current scoring system", p->id);
      new_send_reply(p, -SRV_ERR_PROTOCOL);
      return;
    }
    run.score = pkt->score;
    run_flags |= RUN_ENTRY_SCORE;
  }
  if ((pkt->mask & PROT_SERVE_RUN_SCORE_ADJ_SET)) {
    if (pkt->score_adj < -128 || pkt->score_adj > 127) {
      err("%d: new score_adj value %d is out of range", p->id, pkt->score_adj);
      new_send_reply(p, -SRV_ERR_PROTOCOL);
      return;
    }
    if (global->score_system_val != SCORE_OLYMPIAD
        && global->score_system_val != SCORE_KIROV
        && global->score_system_val != SCORE_MOSCOW) {
      err("%d: score_adj cannot be set in the current scoring system", p->id);
      new_send_reply(p, -SRV_ERR_PROTOCOL);
      return;
    }
    run.score_adj = pkt->score_adj;
    run_flags |= RUN_ENTRY_SCORE_ADJ;
  }
  if ((pkt->mask & PROT_SERVE_RUN_READONLY_SET)) {
    if (pkt->is_readonly < 0 || pkt->is_readonly > 1) {
      err("%d: invalid is_readonly value %d", p->id, pkt->is_readonly);
      new_send_reply(p, -SRV_ERR_PROTOCOL);
      return;
    }
    run.is_readonly = pkt->is_readonly;
    run_flags |= RUN_ENTRY_READONLY;
  }
  if ((pkt->mask & PROT_SERVE_RUN_PAGES_SET)) {
    if (pkt->pages < 0 || pkt->pages > 255) {
      err("%d: invalid pages value %d", p->id, pkt->pages);
      new_send_reply(p, -SRV_ERR_PROTOCOL);
      return;
    }
    run.pages = pkt->pages;
    run_flags |= RUN_ENTRY_PAGES;
  }

  // check capabilities
  if (!check_cnts_caps(p->user_id, OPCAP_EDIT_RUN)
      && (run_flags != RUN_ENTRY_STATUS
          || (run.status != RUN_REJUDGE && run.status != RUN_FULL_REJUDGE)
          || !check_cnts_caps(p->user_id, OPCAP_REJUDGE_RUN))) {
    err("%d: user %d has no capability to edit run", p->id, p->user_id);
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    return;
  }

  /* refuse to rejudge imported run */
  if ((run_flags & RUN_ENTRY_STATUS)
      && (run.status == RUN_REJUDGE || run.status == RUN_FULL_REJUDGE)) {
    if (cur_run.is_imported) {
      err("%d: refuse to rejudge imported run %d", p->id, pkt->run_id);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }
  }

  if (run_set_entry(pkt->run_id, run_flags, &run) < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }

  if ((run_flags & RUN_ENTRY_STATUS)
      && (run.status == RUN_REJUDGE || run.status == RUN_FULL_REJUDGE)) {
    rejudge_run(pkt->run_id, p, (run.status == RUN_FULL_REJUDGE), 0);
  }
  info("%d: edit_run: ok", p->id);
  new_send_reply(p, SRV_RPL_OK);
  return;
}

static void
cmd_new_run(struct client_state *p, int len,
            struct prot_serve_pkt_run_info *pkt)
{
  const unsigned char *user_login_ptr, *run_src_ptr;
  int user_login_len, run_src_len, packet_len;
  struct run_entry new_run;
  int new_run_flags = 0;
  int run_id, arch_flags, locale_id;
  ruint32_t shaval[5];
  struct timeval precise_time;
  path_t run_arch;

  if (get_peer_local_user(p) < 0) return;

  if (len < sizeof(*pkt)) {
    err("%d: cmd_new_run: packet is too small (%d < %zu)",
        p->id, len, sizeof(*pkt));
    goto protocol_error;
  }
  user_login_ptr = pkt->data;
  user_login_len = strlen(user_login_ptr);
  if (user_login_len != pkt->user_login_len) {
    err("%d: cmd_new_run: user_login_len mismatch (%d != %d)",
        p->id, user_login_len, pkt->user_login_len);
    goto protocol_error;
  }
  run_src_ptr = user_login_ptr + user_login_len + 1;
  run_src_len = strlen(run_src_ptr);
  if (pkt->run_src_len < 0) {
    err("%d: cmd_new_run: run_src_len is negative (%d)",
        p->id, pkt->run_src_len);
    goto protocol_error;
  }
  packet_len = sizeof(*pkt) + user_login_len + run_src_len;
  if (packet_len != len) {
    err("%d: cmd_new_run: packet length mismatch (%d != %d)",
        p->id, packet_len, len);
    goto protocol_error;
  }

  info("%d: new_run: %d", p->id, pkt->mask);
  memset(&new_run, 0, sizeof(new_run));

  if (p->priv_level != PRIV_LEVEL_ADMIN) goto permission_denied;
  if (!check_cnts_caps(p->user_id, OPCAP_EDIT_RUN)
      || !check_cnts_caps(p->user_id, OPCAP_SUBMIT_RUN))
    goto permission_denied;

  // user_id or login, prob_id, lang_id, status must be specified
  if ((pkt->mask & PROT_SERVE_RUN_UID_SET)
      && (pkt->mask & PROT_SERVE_RUN_LOGIN_SET)) {
    err("%d: new_run: both uid and login are set", p->id);
    goto protocol_error;
  } else if ((pkt->mask & PROT_SERVE_RUN_UID_SET)) {
    if (teamdb_lookup(pkt->user_id) != 1) {
      err("%d: invalid user_id %d", p->id, pkt->user_id);
      new_send_reply(p, -SRV_ERR_BAD_USER_ID);
      return;
    }
  } else if ((pkt->mask & PROT_SERVE_RUN_LOGIN_SET)) {
    if ((pkt->user_id = teamdb_lookup_login(user_login_ptr)) <= 0) {
      err("%d: invalid login <%s>", p->id, user_login_ptr);
      new_send_reply(p, -SRV_ERR_BAD_USER_ID);
      return;
    }
  } else {
    err("%d: new_run: uid or login must be specified", p->id);
    new_send_reply(p, -SRV_ERR_BAD_USER_ID);
    return;
  }

  if ((pkt->mask & PROT_SERVE_RUN_PROB_SET)) {
    if (pkt->prob_id <= 0 || pkt->prob_id > max_prob || !probs[pkt->prob_id]) {
      err("%d: new_run: invalid problem %d", p->id, pkt->prob_id);
      new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
      return;
    }
  } else {
    err("%d: new_run: problem must be specified", p->id);
    new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
    return;
  }

  if ((pkt->mask & PROT_SERVE_RUN_LANG_SET)) {
    if (pkt->lang_id <= 0 || pkt->lang_id > max_lang || !langs[pkt->lang_id]) {
      err("%d: new_run: invalid language %d", p->id, pkt->lang_id);
      new_send_reply(p, -SRV_ERR_BAD_LANG_ID);
      return;
    }
  } else {
    err("%d: new_run: language must be specified", p->id);
    new_send_reply(p, -SRV_ERR_BAD_LANG_ID);
    return;
  }

  if (!langs[pkt->lang_id]->binary) {
    if (pkt->run_src_len != run_src_len) {
      err("%d: new_run: source length mismatch (%d != %d)",
          p->id, run_src_len, pkt->run_src_len);
      goto protocol_error;
    }
  }

  if ((pkt->mask & PROT_SERVE_RUN_STATUS_SET)) {
    if (!is_valid_status(pkt->status, 1)) {
      err("%d: new_run: invalid status %d", p->id, pkt->status);
      new_send_reply(p, -SRV_ERR_BAD_STATUS);
      return;
    }
    new_run.status = pkt->status;
    new_run_flags = RUN_ENTRY_STATUS;
  } else {
    err("%d: new_run: status must be specified", p->id);
    new_send_reply(p, -SRV_ERR_BAD_STATUS);
    return;
  }

  if ((pkt->mask & PROT_SERVE_RUN_VARIANT_SET)) {
    if (probs[pkt->prob_id]->variant_num <= 0) {
      err("%d: new_run: problem %d has no variants", p->id, pkt->prob_id);
      new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
      return;
    }
    if (pkt->variant < 0 || pkt->variant > probs[pkt->prob_id]->variant_num) {
      err("%d: new_run: invalid variant %d for problem %d",
          p->id, pkt->variant, pkt->prob_id);
      new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
      return;
    }
  } else {
    pkt->variant = 0;
  }

  // check optional fields
  if ((pkt->mask & PROT_SERVE_RUN_IMPORTED_SET)) {
    if (pkt->is_imported < 0 || pkt->is_imported > 1) {
      err("%d: new_run: invalid is_imported value %d", p->id,pkt->is_imported);
      goto protocol_error;
    }
    new_run.is_imported = pkt->is_imported;
    new_run_flags |= RUN_ENTRY_IMPORTED;
  }

  if ((pkt->mask & PROT_SERVE_RUN_HIDDEN_SET)) {
    if (pkt->is_hidden < 0 || pkt->is_hidden > 1) {
      err("%d: new_run: invalid is_hidden value %d", p->id, pkt->is_hidden);
      goto protocol_error;
    }
    new_run.is_hidden = pkt->is_hidden;
    new_run_flags |= RUN_ENTRY_HIDDEN;
  }

  if ((pkt->mask & PROT_SERVE_RUN_TESTS_SET)) {
    if (pkt->tests < -1 || pkt->tests > 126) {
      err("%d: new_run: new test value %d is out of range", p->id, pkt->tests);
      goto protocol_error;
    }
    if (global->score_system_val == SCORE_OLYMPIAD
        || global->score_system_val == SCORE_KIROV) {
      pkt->tests++;
    }
    if (pkt->tests == -1) pkt->tests = 0;
    new_run.test = pkt->tests;
    new_run_flags |= RUN_ENTRY_TEST;
  }

  if ((pkt->mask & PROT_SERVE_RUN_SCORE_SET)) {
    if (pkt->score < -1 || pkt->score > 100000) {
      err("%d: new_run: new score value %d is out of range", p->id,
          pkt->score);
      goto protocol_error;
    }
    if (global->score_system_val != SCORE_OLYMPIAD
        && global->score_system_val != SCORE_KIROV
        && global->score_system_val != SCORE_MOSCOW) {
      err("%d: new_run: score cannot be set in the current scoring system",
          p->id);
      goto protocol_error;
    }
    new_run.score = pkt->score;
    new_run_flags |= RUN_ENTRY_SCORE;
  }

  if ((pkt->mask & PROT_SERVE_RUN_READONLY_SET)) {
    if (pkt->is_readonly < 0 || pkt->is_readonly > 1) {
      err("%d: new_run: invalid is_readonly value %d", p->id,
          pkt->is_readonly);
      goto protocol_error;
    }
    new_run.is_readonly = pkt->is_readonly;
    new_run_flags |= RUN_ENTRY_READONLY;
  }

  if ((pkt->mask & PROT_SERVE_RUN_PAGES_SET)) {
    if (pkt->pages < 0 || pkt->pages > 255) {
      err("%d: new_run: invalid pages value %d", p->id, pkt->pages);
      goto protocol_error;
    }
    new_run.pages = pkt->pages;
    new_run_flags |= RUN_ENTRY_PAGES;
  }

  sha_buffer(run_src_ptr, run_src_len, shaval);
  gettimeofday(&precise_time, 0);
  locale_id = 0;
  if ((run_id = run_add_record(precise_time.tv_sec,
                               precise_time.tv_usec * 1000,
                               run_src_len,
                               shaval,
                               pkt->ip,
                               locale_id,
                               pkt->user_id,
                               pkt->prob_id,
                               pkt->lang_id,
                               pkt->variant, 1)) < 0){
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  move_files_to_insert_run(run_id);

  arch_flags = archive_make_write_path(run_arch, sizeof(run_arch),
                                       global->run_archive_dir, run_id,
                                       pkt->run_src_len, 0);
  if (arch_flags < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  if (archive_dir_prepare(global->run_archive_dir, run_id, 0, 0) < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  if (generic_write_file(run_src_ptr, run_src_len, arch_flags,
                         0, run_arch, "") < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }

  if (run_set_entry(run_id, new_run_flags, &new_run) < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }

  info("%d: new_run: ok", p->id);
  new_send_reply(p, SRV_RPL_OK);
  return;

 protocol_error:
  new_send_reply(p, -SRV_ERR_PROTOCOL);
  return;

 permission_denied:
  err("%d: permission denied", p->id);
  new_send_reply(p, -SRV_ERR_NO_PERMS);
  return;
}


static void
cmd_edit_user(struct client_state *p, int len,
              struct prot_serve_pkt_user_info *pkt)
{
  size_t expected_pkt_size, actual_txt_len, actual_cmt_len;
  struct team_extra *t_extra;
  const unsigned char *txt_ptr, *cmt_ptr;

  if (get_peer_local_user(p) < 0) return;

  if (len < sizeof(*pkt)) {
    err("%d: cmd_edit_user: packet is too small (%d < %zu)",
        p->id, len, sizeof(*pkt));
    goto protocol_error;
  }
  txt_ptr = pkt->data;
  actual_txt_len = strlen(txt_ptr);
  if (actual_txt_len != pkt->txt_len) {
    err("%d: cmd_edit_user: txt_len mismatch (%zu != %d)",
        p->id, actual_txt_len, pkt->txt_len);
    goto protocol_error;
  }
  cmt_ptr = txt_ptr + pkt->txt_len + 1;
  actual_cmt_len = strlen(cmt_ptr);
  if (actual_cmt_len != pkt->cmt_len) {
    err("%d: cmd_edit_user: cmt_len mismatch (%zu != %d)",
        p->id, actual_cmt_len, pkt->cmt_len);
    goto protocol_error;
  }
  expected_pkt_size = sizeof(*pkt) + pkt->txt_len + pkt->cmt_len;
  if (len != expected_pkt_size) {
    err("%d: cmd_edit_user: packet length mismatch (%d != %zu)",
        p->id, len, expected_pkt_size);
    goto protocol_error;
  }
  if (!teamdb_lookup(pkt->user_id)) {
    err("%d: cmd_edit_user: user_id is invalid", p->id);
    new_send_reply(p, -SRV_ERR_BAD_USER_ID);
    return;
  }

  switch (pkt->b.id) {
  case SRV_CMD_SET_TEAM_STATUS:
    if (pkt->status < 0 || pkt->status >= global->contestant_status_num) {
      err("%d: cmd_edit_user: bad status %d", p->id, pkt->status);
      new_send_reply(p, -SRV_ERR_BAD_STATUS);
      return;
    }
    if (!check_cnts_caps(p->user_id, OPCAP_EDIT_REG)) {
      err("%d: user %d cannot set team status", p->id, p->user_id);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }
    if (!(t_extra = team_extra_get_entry(pkt->user_id))) {
      err("%d: cannot get team extra information for %d", p->id, pkt->user_id);
      new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
      return;
    }
    if (t_extra->status == pkt->status) {
      info("%d: cmd_edit_user: nothing to do", p->id);
      new_send_reply(p, SRV_RPL_OK);
      return;
    }
    t_extra->status = pkt->status;
    t_extra->is_dirty = 1;
    team_extra_flush();
    break;
  case SRV_CMD_ISSUE_WARNING:
    if (!check_cnts_caps(p->user_id, OPCAP_EDIT_REG)) {
      err("%d: user %d cannot set team status", p->id, p->user_id);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }
    if (team_extra_append_warning(pkt->user_id, p->user_id,
                                  p->ip, current_time, txt_ptr, cmt_ptr) < 0) {
      err("%d: warning append failed", p->id);
      new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
      return;
    }
    team_extra_flush();
    break;
  default:
    err("%d: cmd_edit_user: unexpected command %d", p->id, pkt->b.id);
    goto protocol_error;
  }

  info("%d: new_run: ok", p->id);
  new_send_reply(p, SRV_RPL_OK);
  return;

 protocol_error:
  new_send_reply(p, -SRV_ERR_PROTOCOL);
  return;
}

static void
mail_check_failed(int run_id)
{
  const struct contest_desc *cnts = 0;
  unsigned char esubj[1024];
  unsigned char *originator = 0;
  FILE *fmsg = 0;
  char *ftxt = 0;
  size_t flen = 0;
  unsigned char *mail_args[7];

  if (contests_get(global->contest_id, &cnts) < 0 || !cnts
      || !cnts->cf_notify_email) return;

  snprintf(esubj, sizeof(esubj),
           "Check failed in contest %d", global->contest_id);
  originator = get_email_sender(cnts);

  fmsg = open_memstream(&ftxt, &flen);
  fprintf(fmsg, "Hello,\n\nRun evaluation got \"Check failed\"!\n"
          "Contest: %d (%s)\n"
          "Run Id: %d\n\n-\n"
          "Regards,\n"
          "the ejudge contest management system\n",
          global->contest_id, cnts->name, run_id);
  fclose(fmsg); fmsg = 0;
  mail_args[0] = "mail";
  mail_args[1] = "";
  mail_args[2] = esubj;
  mail_args[3] = originator;
  mail_args[4] = cnts->cf_notify_email;
  mail_args[5] = ftxt;
  mail_args[6] = 0;
  send_job_packet(NULL, mail_args);
  xfree(ftxt); ftxt = 0;
}


static void generate_packet_name(int run_id, int prio,
                                 unsigned char buf[PACKET_NAME_SIZE]);

static int
read_compile_packet(const unsigned char *compile_status_dir,
                    const unsigned char *compile_report_dir,
                    char *pname)
{
  unsigned char pkt_base[PACKET_NAME_SIZE];
  unsigned char exe_in_name[128];
  unsigned char exe_out_name[128];
  unsigned char rep_path[PATH_MAX];
  struct teamdb_export te;

  int  r, cn, rep_flags = 0, prio, i;

  int  variant = 0;
  struct run_entry re;

  char *comp_pkt_buf = 0;       /* need char* for generic_read_file */
  size_t comp_pkt_size = 0;
  struct compile_reply_packet *comp_pkt = 0;
  long report_size = 0;
  unsigned char errmsg[1024] = { 0 };
  unsigned char *team_name = 0;
  struct compile_run_extra *comp_extra = 0;
  struct run_request_packet *run_pkt = 0;
  size_t run_pkt_out_size = 0;
  void *run_pkt_out = 0;
  struct section_problem_data *prob = 0;
  struct section_language_data *lang = 0;

  r = generic_read_file(&comp_pkt_buf, 0, &comp_pkt_size, SAFE | REMOVE,
                        compile_status_dir, pname, "");
  if (r == 0) return 0;
  if (r < 0) return -1;

  if (compile_reply_packet_read(comp_pkt_size, comp_pkt_buf, &comp_pkt) < 0) {
    /* failed to parse a compile packet */
    /* we can't do any reasonable recovery, just drop the packet */
    goto non_fatal_error;
  }
  if (comp_pkt->contest_id != global->contest_id) {
    err("read_compile_packet: mismatched contest_id %d", comp_pkt->contest_id);
    goto non_fatal_error;
  }
  if (run_get_entry(comp_pkt->run_id, &re) < 0) {
    err("read_compile_packet: invalid run_id %d", comp_pkt->run_id);
    goto non_fatal_error;
  }
  if (comp_pkt->judge_id != re.judge_id) {
    err("read_compile_packet: judge_id mismatch: %d, %d", comp_pkt->judge_id,
        re.judge_id);
    goto non_fatal_error;
  }
  if (re.status != RUN_COMPILING) {
    err("read_compile_packet: run %d is not compiling", comp_pkt->run_id);
    goto non_fatal_error;
  }

  if (comp_pkt->status == RUN_CHECK_FAILED || comp_pkt->status == RUN_COMPILE_ERR) {
    if ((report_size = generic_file_size(compile_report_dir, pname, "")) < 0) {
      err("read_compile_packet: cannot get report file size");
      snprintf(errmsg, sizeof(errmsg), "cannot get size of %s/%s\n",
               compile_report_dir, pname);
      goto report_check_failed;
    }

    rep_flags = archive_make_write_path(rep_path, sizeof(rep_path),
                                        global->xml_report_archive_dir,comp_pkt->run_id,
                                        report_size, 0);
    if (rep_flags < 0) {
      snprintf(errmsg, sizeof(errmsg), "archive_make_write_path: %s, %d, %ld failed\n",
               global->xml_report_archive_dir, comp_pkt->run_id, report_size);
      goto report_check_failed;
    }
  }
  /*
  if (comp_pkt->status == RUN_COMPILE_ERR && global->team_enable_rep_view) {
    team_flags = archive_make_write_path(team_path, sizeof(team_path),
                                         global->team_report_archive_dir,
                                         comp_pkt->run_id, report_size, 0);
    if (team_flags < 0) {
      snprintf(errmsg, sizeof(errmsg),"archive_make_write_path: %s, %d, %ld failed\n",
               global->team_report_archive_dir, comp_pkt->run_id, report_size);
      goto report_check_failed;
    }
  }
  */

  if (comp_pkt->status == RUN_CHECK_FAILED) {
    /* if status change fails, we cannot do reasonable recovery */
    if (run_change_status(comp_pkt->run_id, RUN_CHECK_FAILED, 0, -1, 0) < 0)
      goto non_fatal_error;
    if (archive_dir_prepare(global->xml_report_archive_dir, comp_pkt->run_id, 0, 0) < 0)
      goto non_fatal_error;
    if (generic_copy_file(REMOVE, compile_report_dir, pname, "",
                          rep_flags, 0, rep_path, "") < 0) {
      snprintf(errmsg, sizeof(errmsg), "generic_copy_file: %s, %s, %d, %s failed\n",
               compile_report_dir, pname, rep_flags, rep_path);
      goto report_check_failed;
    }
    mail_check_failed(comp_pkt->run_id);
    goto success;
  }

  if (comp_pkt->status == RUN_COMPILE_ERR) {
    /* if status change fails, we cannot do reasonable recovery */
    if (run_change_status(comp_pkt->run_id, RUN_COMPILE_ERR, 0, -1, 0) < 0)
      goto non_fatal_error;

    /*
    if (global->team_enable_rep_view) {
      if (archive_dir_prepare(global->team_report_archive_dir,comp_pkt->run_id,0,0)<0) {
        snprintf(errmsg, sizeof(errmsg), "archive_dir_prepare: %s, %d failed\n",
                 global->team_report_archive_dir, comp_pkt->run_id);
        goto report_check_failed;
      }
      if (generic_copy_file(0, compile_report_dir, pname, "",
                            team_flags, 0, team_path, "") < 0) {
        snprintf(errmsg, sizeof(errmsg), "generic_copy_file: %s, %s, %d, %s failed\n",
                 compile_report_dir, pname, team_flags, team_path);
        goto report_check_failed;
      }
    }
    */
    if (archive_dir_prepare(global->xml_report_archive_dir, comp_pkt->run_id, 0, 0) < 0) {
      snprintf(errmsg, sizeof(errmsg), "archive_dir_prepare: %s, %d failed\n",
               global->xml_report_archive_dir, comp_pkt->run_id);
      goto report_check_failed;
    }
    if (generic_copy_file(REMOVE, compile_report_dir, pname, "",
                          rep_flags, 0, rep_path, "") < 0) {
      snprintf(errmsg, sizeof(errmsg), "generic_copy_file: %s, %s, %d, %s failed\n",
               compile_report_dir, pname, rep_flags, rep_path);
      goto report_check_failed;
    }
    update_standings_file(0);
    goto success;
  }

  /* check run parameters */
  if (re.problem < 1 || re.problem > max_prob || !(prob = probs[re.problem])) {
    snprintf(errmsg, sizeof(errmsg), "invalid problem %d\n", re.problem);
    goto report_check_failed;
  }
  if (re.language < 1 || re.language > max_lang || !(lang = langs[re.language])) {
    snprintf(errmsg, sizeof(errmsg), "invalid language %d\n", re.language);
    goto report_check_failed;
  }
  if (!(team_name = teamdb_get_name(re.team))) {
    snprintf(errmsg, sizeof(errmsg), "invalid team %d\n", re.team);
    goto report_check_failed;
  }
  if (prob->disable_testing && prob->enable_compilation > 0) {
    if (run_change_status(comp_pkt->run_id, RUN_ACCEPTED, 0, -1,
                          comp_pkt->judge_id) < 0)
      goto non_fatal_error;
    goto success;
  }

  comp_extra = (typeof(comp_extra)) comp_pkt->run_block;
  if (!comp_extra || comp_pkt->run_block_len != sizeof(*comp_extra)
      || comp_extra->accepting_mode < 0 || comp_extra->accepting_mode > 1) {
    snprintf(errmsg, sizeof(errmsg), "invalid run block\n");
    goto report_check_failed;
  }

  if (run_change_status(comp_pkt->run_id, RUN_COMPILED, 0, -1, comp_pkt->judge_id) < 0)
    goto non_fatal_error;

  /*
   * so far compilation is successful, and now we prepare a run packet
   */

  /* find appropriate checker */
  cn = find_tester(re.problem, lang->arch);
  if (cn < 1 || cn > max_tester || !testers[cn]) {
    snprintf(errmsg, sizeof(errmsg), "no appropriate checker for <%s>, <%s>\n",
             prob->short_name, lang->arch);
    goto report_check_failed;
  }

  if (prob->variant_num > 0) {
    variant = re.variant;
    if (!variant) variant = find_variant(re.team, re.problem);
    if (!variant) {
      snprintf(errmsg, sizeof(errmsg), "no appropriate variant for <%s>, <%s>\n",
               team_name, prob->short_name);
      goto report_check_failed;
    }
  }

  /* calculate a priority */
  prio = 0;
  prio += lang->priority_adjustment;
  prio += prob->priority_adjustment;
  prio += find_user_priority_adjustment(re.team);
  prio += testers[cn]->priority_adjustment;
  prio += comp_extra->priority_adjustment;

  /* generate a packet name */
  generate_packet_name(comp_pkt->run_id, prio, pkt_base);
  snprintf(exe_in_name, sizeof(exe_in_name),
           "%06d%s", comp_pkt->run_id, lang->exe_sfx);
  snprintf(exe_out_name, sizeof(exe_out_name),
           "%s%s", pkt_base, lang->exe_sfx);

  /* copy the executable into the testers's queue */
  if (generic_copy_file(REMOVE, compile_report_dir, exe_in_name, "",
                        0, global->run_exe_dir, exe_out_name, "") < 0) {
    snprintf(errmsg, sizeof(errmsg), "generic_copy_file: %s, %s, %s, %s failed\n",
             compile_report_dir, exe_in_name, global->run_exe_dir,
             exe_out_name);
    goto report_check_failed;
  }

  /* create an internal representation of run packet */
  XALLOCAZ(run_pkt, 1);

  run_pkt->judge_id = comp_pkt->judge_id;
  run_pkt->contest_id = global->contest_id;
  run_pkt->run_id = comp_pkt->run_id;
  run_pkt->problem_id = prob->tester_id;
  run_pkt->accepting_mode = comp_extra->accepting_mode;
  run_pkt->scoring_system = global->score_system_val;
  run_pkt->variant = variant;
  run_pkt->accept_partial = prob->accept_partial;
  run_pkt->user_id = re.team;
  run_pkt->disable_sound = global->disable_sound;
  run_pkt->full_archive = global->enable_full_archive;
  run_pkt->memory_limit = global->enable_memory_limit_error;
  run_pkt->ts1 = comp_pkt->ts1;
  run_pkt->ts1_us = comp_pkt->ts1_us;
  run_pkt->ts2 = comp_pkt->ts2;
  run_pkt->ts2_us = comp_pkt->ts2_us;
  run_pkt->ts3 = comp_pkt->ts3;
  run_pkt->ts3_us = comp_pkt->ts3_us;
  get_current_time(&run_pkt->ts4, &run_pkt->ts4_us);
  run_pkt->exe_sfx = lang->exe_sfx;
  run_pkt->arch = lang->arch;

  // process language-specific time adjustments
  if (prob->lang_time_adj) {
    size_t lsn = strlen(lang->short_name);
    size_t vl;
    int adj, n;
    unsigned char *sn;
    for (i = 0; (sn = prob->lang_time_adj[i]); i++) {
      vl = strlen(sn);
      if (vl > lsn + 1
          && !strncmp(sn, lang->short_name, lsn)
          && sn[lsn] == '='
          && sscanf(sn + lsn + 1, "%d%n", &adj, &n) == 1
          && !sn[lsn + 1 + n]
          && adj >= 0
          && adj <= 100) {
        run_pkt->time_limit_adj = adj;
      }
    }
  }

  /* in new binary packet format we don't care about neither "special"
   * characters in spellings nor about spelling length
   */
  teamdb_export_team(re.team, &te);
  if (te.user && te.user->i.spelling && te.user->i.spelling[0]) {
    run_pkt->user_spelling = te.user->i.spelling;
  }
  if (!run_pkt->user_spelling && te.user && te.user->i.name && te.user->i.name[0]) {
    run_pkt->user_spelling = te.user->i.name;
  }
  if (!run_pkt->user_spelling && te.login && te.user->login && te.user->login[0]) {
    run_pkt->user_spelling = te.user->login;
  }
  /* run_pkt->user_spelling is allowed to be NULL */

  if (prob->spelling[0]) {
    run_pkt->prob_spelling = prob->spelling;
  }
  if (!run_pkt->prob_spelling) {
    run_pkt->prob_spelling = prob->short_name;
  }
  /* run_pkt->prob_spelling is allowed to be NULL */

  /* generate external representation of the packet */
  if (run_request_packet_write(run_pkt, &run_pkt_out_size, &run_pkt_out) < 0) {
    snprintf(errmsg, sizeof(errmsg), "run_request_packet_write failed\n");
    goto report_check_failed;
  }

  if (generic_write_file(run_pkt_out, run_pkt_out_size, SAFE,
                         global->run_queue_dir, pkt_base, "") < 0) {
    snprintf(errmsg, sizeof(errmsg), "failed to write run packet\n");
    goto report_check_failed;
  }

  /* update status */
  if (run_change_status(comp_pkt->run_id, RUN_RUNNING, 0, -1, comp_pkt->judge_id) < 0)
    goto non_fatal_error;

 success:
  xfree(comp_pkt_buf);
  xfree(run_pkt_out);
  compile_reply_packet_free(comp_pkt);
  return 1;

 report_check_failed:
  mail_check_failed(comp_pkt->run_id);

  /* this is error recover, so if error happens again, we cannot do anything */
  if (run_change_status(comp_pkt->run_id, RUN_CHECK_FAILED, 0, -1, 0) < 0)
    goto non_fatal_error;
  report_size = strlen(errmsg);
  rep_flags = archive_make_write_path(rep_path, sizeof(rep_path),
                                      global->xml_report_archive_dir, comp_pkt->run_id,
                                      report_size, 0);
  if (archive_dir_prepare(global->xml_report_archive_dir, comp_pkt->run_id, 0, 0) < 0)
    goto non_fatal_error;
  /* error code is ignored */
  generic_write_file(errmsg, report_size, rep_flags, 0, rep_path, 0);
  /* goto non_fatal_error; */

 non_fatal_error:
  xfree(comp_pkt_buf);
  xfree(run_pkt_out);
  compile_reply_packet_free(comp_pkt);
  return 0;
}

static unsigned char *
time_to_str(unsigned char *buf, size_t size, int secs, int usecs)
{
  struct tm *ltm;
  time_t tt = secs;

  if (secs <= 0) {
    snprintf(buf, size, "N/A");
    return buf;
  }
  ltm = localtime(&tt);
  snprintf(buf, size, "%04d/%02d/%02d %02d:%02d:%02d.%06d",
           ltm->tm_year + 1900, ltm->tm_mon + 1, ltm->tm_mday,
           ltm->tm_hour, ltm->tm_min, ltm->tm_sec, usecs);
  return buf;
}
static unsigned char *
dur_to_str(unsigned char *buf, size_t size, int sec1, int usec1,
           int sec2, int usec2)
{
  long long d;

  if (sec1 <= 0 || sec2 <= 0) {
    snprintf(buf, size, "N/A");
    return buf;
  }
  if ((d = sec2 * 1000000 + usec2 - (sec1 * 1000000 + usec1)) < 0) {
    snprintf(buf, size, "t1 > t2");
    return buf;
  }
  d = (d + 500) / 1000;
  snprintf(buf, size, "%lld.%03lld", d / 1000, d % 1000);
  return buf;
}

static int
read_run_packet(const unsigned char *run_status_dir,
                const unsigned char *run_report_dir,
                const unsigned char *run_team_report_dir,
                const unsigned char *run_full_archive_dir,
                char *pname)
{
  path_t rep_path, full_path;
  int r, rep_flags, rep_size, full_flags;
  struct run_entry re;
  char *reply_buf = 0;          /* need char* for generic_read_file */
  size_t reply_buf_size = 0;
  struct run_reply_packet *reply_pkt = 0;
  char *audit_text = 0;
  size_t audit_text_size = 0;
  FILE *f = 0;
  int ts8, ts8_us;
  unsigned char time_buf[64];

  get_current_time(&ts8, &ts8_us);
  r = generic_read_file(&reply_buf, 0, &reply_buf_size, SAFE | REMOVE,
                        run_status_dir, pname, "");
  if (r < 0) return -1;
  if (r == 0) return 0;

  if (run_reply_packet_read(reply_buf_size, reply_buf, &reply_pkt) < 0)
    goto failed;
  xfree(reply_buf), reply_buf = 0;

  if (reply_pkt->contest_id != global->contest_id) {
    err("read_run_packet: contest_id mismatch: %d in packet",
        reply_pkt->contest_id);
    goto failed;
  }
  if (run_get_entry(reply_pkt->run_id, &re) < 0) {
    err("read_run_packet: invalid run_id: %d", reply_pkt->run_id);
    goto failed;
  }
  if (re.status != RUN_RUNNING) {
    err("read_run_packet: run %d status is not RUNNING", reply_pkt->run_id);
    goto failed;
  }
  if (re.judge_id != reply_pkt->judge_id) {
    err("read_run_packet: judge_id mismatch: packet: %d, db: %d",
        reply_pkt->judge_id, re.judge_id);
    goto failed;
  }

  if (!is_valid_status(reply_pkt->status, 2)) goto bad_packet_error;

  if (global->score_system_val == SCORE_OLYMPIAD) {
    if (re.problem < 1 || re.problem > max_prob || !probs[re.problem])
      goto bad_packet_error;
  } else if (global->score_system_val == SCORE_KIROV) {
    /*
    if (status != RUN_PARTIAL && status != RUN_OK
        && status != RUN_CHECK_FAILED) goto bad_packet_error;
    */
    if (re.problem < 1 || re.problem > max_prob || !probs[re.problem])
      goto bad_packet_error;
    if (reply_pkt->score < 0 || reply_pkt->score>probs[re.problem]->full_score)
      goto bad_packet_error;
    /*
    for (n = 0; n < probs[re.problem]->dp_total; n++)
      if (re.timestamp < probs[re.problem]->dp_infos[n].deadline)
        break;
    if (n < probs[re.problem]->dp_total) {
      score += probs[re.problem]->dp_infos[n].penalty;
      if (score > probs[re.problem]->full_score)
        score = probs[re.problem]->full_score;
      if (score < 0) score = 0;
    }
    */
  } else if (global->score_system_val == SCORE_MOSCOW) {
    if (re.problem < 1 || re.problem > max_prob || !probs[re.problem])
      goto bad_packet_error;
    if (reply_pkt->score < 0 || reply_pkt->score>probs[re.problem]->full_score)
      goto bad_packet_error;
  } else {
    reply_pkt->score = -1;
  }
  if (reply_pkt->status == RUN_CHECK_FAILED)
    mail_check_failed(reply_pkt->run_id);
  if (run_change_status(reply_pkt->run_id, reply_pkt->status,
                        reply_pkt->failed_test,
                        reply_pkt->score, 0) < 0) return -1;
  update_standings_file(0);
  rep_size = generic_file_size(run_report_dir, pname, "");
  if (rep_size < 0) return -1;
  rep_flags = archive_make_write_path(rep_path, sizeof(rep_path),
                                      global->xml_report_archive_dir,
                                      reply_pkt->run_id,
                                      rep_size, 0);
  if (archive_dir_prepare(global->xml_report_archive_dir, reply_pkt->run_id, 0, 0) < 0)
    return -1;
  if (generic_copy_file(REMOVE, run_report_dir, pname, "",
                        rep_flags, 0, rep_path, "") < 0)
    return -1;
  /*
  if (global->team_enable_rep_view) {
    team_size = generic_file_size(run_team_report_dir, pname, "");
    team_flags = archive_make_write_path(team_path, sizeof(team_path),
                                         global->team_report_archive_dir,
                                         reply_pkt->run_id, team_size, 0);
    if (archive_dir_prepare(global->team_report_archive_dir,
                            reply_pkt->run_id, 0, 0) < 0)
      return -1;
    if (generic_copy_file(REMOVE, run_team_report_dir, pname, "",
                          team_flags, 0, team_path, "") < 0)
      return -1;
  }
  */
  if (global->enable_full_archive) {
    full_flags = archive_make_write_path(full_path, sizeof(full_path),
                                         global->full_archive_dir,
                                         reply_pkt->run_id, 0, 0);
    if (archive_dir_prepare(global->full_archive_dir, reply_pkt->run_id, 0, 0) < 0)
      return -1;
    if (generic_copy_file(REMOVE, run_full_archive_dir, pname, "",
                          0, 0, full_path, "") < 0)
      return -1;
  }

  /* add auditing information */
  if (!(f = open_memstream(&audit_text, &audit_text_size))) return 1;
  fprintf(f, "Status: Judging complete\n");
  fprintf(f, "  Profiling information:\n");
  fprintf(f, "  Request start time:                %s\n",
          time_to_str(time_buf, sizeof(time_buf),
                      reply_pkt->ts1, reply_pkt->ts1_us));
  fprintf(f, "  Request completion time:           %s\n",
          time_to_str(time_buf, sizeof(time_buf),
                      ts8, ts8_us));
  fprintf(f, "  Total testing duration:            %s\n",
          dur_to_str(time_buf, sizeof(time_buf),
                     reply_pkt->ts1, reply_pkt->ts1_us,
                     ts8, ts8_us));
  fprintf(f, "  Waiting in compile queue duration: %s\n",
          dur_to_str(time_buf, sizeof(time_buf),
                     reply_pkt->ts1, reply_pkt->ts1_us,
                     reply_pkt->ts2, reply_pkt->ts2_us));
  fprintf(f, "  Compilation duration:              %s\n",
          dur_to_str(time_buf, sizeof(time_buf),
                     reply_pkt->ts2, reply_pkt->ts2_us,
                     reply_pkt->ts3, reply_pkt->ts3_us));
  fprintf(f, "  Waiting in serve queue duration:   %s\n",
          dur_to_str(time_buf, sizeof(time_buf),
                     reply_pkt->ts3, reply_pkt->ts3_us,
                     reply_pkt->ts4, reply_pkt->ts4_us));
  fprintf(f, "  Waiting in run queue duration:     %s\n",
          dur_to_str(time_buf, sizeof(time_buf),
                     reply_pkt->ts4, reply_pkt->ts4_us,
                     reply_pkt->ts5, reply_pkt->ts5_us));
  fprintf(f, "  Testing duration:                  %s\n",
          dur_to_str(time_buf, sizeof(time_buf),
                     reply_pkt->ts5, reply_pkt->ts5_us,
                     reply_pkt->ts6, reply_pkt->ts6_us));
  fprintf(f, "  Post-processing duration:          %s\n",
          dur_to_str(time_buf, sizeof(time_buf),
                     reply_pkt->ts6, reply_pkt->ts6_us,
                     reply_pkt->ts7, reply_pkt->ts7_us));
  fprintf(f, "  Waiting in serve queue duration:   %s\n",
          dur_to_str(time_buf, sizeof(time_buf),
                     reply_pkt->ts7, reply_pkt->ts7_us,
                     ts8, ts8_us));
  fprintf(f, "\n");
  fclose(f);
  append_audit_log(reply_pkt->run_id, 0, "%s", audit_text);

  return 1;

 bad_packet_error:
  err("bad_packet");

 failed:
  xfree(reply_buf);
  run_reply_packet_free(reply_pkt);
  return 0;
}

static const unsigned char b32_digits[]=
"0123456789ABCDEFGHIJKLMNOPQRSTUV";
static void
b32_number(unsigned long long num, unsigned char buf[PACKET_NAME_SIZE])
{
  int i;

  memset(buf, '0', PACKET_NAME_SIZE - 1);
  buf[PACKET_NAME_SIZE - 1] = 0;
  i = PACKET_NAME_SIZE - 2;
  while (num > 0 && i >= 0) {
    buf[i] = b32_digits[num & 0x1f];
    i--;
    num >>= 5;
  }
  ASSERT(!num);
}

static void
generate_packet_name(int run_id, int prio, unsigned char buf[PACKET_NAME_SIZE])
{
  unsigned long long num = 0;
  struct timeval ts;

  // generate "random" number, that would include the
  // pid of "serve", the current time (with microseconds)
  // and some small random component.
  // pid is 2 byte (15 bit)
  // run_id is 2 byte
  // time_t component - 4 byte
  // nanosec component - 4 byte

  num = (getpid() & 0x7fffLLU) << 25LLU;
  num |= (run_id & 0x7fffLLU) << 40LLU;
  gettimeofday(&ts, 0);
  num |= (ts.tv_sec ^ ts.tv_usec) & 0x1ffffff;
  b32_number(num, buf);
  if (prio < -16) prio = -16;
  if (prio > 15) prio = 15;
  buf[0] = b32_digits[prio + 16];
}

static unsigned short compile_request_id;
static int
queue_compile_request(unsigned char const *str, int len,
                      int run_id, int lang_id, int locale_id, int output_only,
                      unsigned char const *sfx,
                      char **compiler_env,
                      int accepting_mode,
                      int priority_adjustment)
{
  struct compile_run_extra rx;
  struct compile_request_packet cp;
  void *pkt_buf = 0;
  size_t pkt_len = 0;
  unsigned char pkt_name[PACKET_NAME_SIZE];
  int arch_flags;
  path_t run_arch;

  if (accepting_mode == -1) {
    accepting_mode = 0;
    if (global->score_system_val == SCORE_OLYMPIAD && !olympiad_judging_mode) {
      accepting_mode = 1;
    }
  }

  memset(&cp, 0, sizeof(cp));
  cp.judge_id = compile_request_id++;
  cp.contest_id = global->contest_id;
  cp.run_id = run_id;
  cp.lang_id = lang_id;
  cp.locale_id = locale_id;
  cp.output_only = output_only;
  get_current_time(&cp.ts1, &cp.ts1_us);
  cp.run_block_len = sizeof(rx);
  cp.run_block = &rx;
  cp.env_num = -1;
  cp.env_vars = (unsigned char**) compiler_env;

  memset(&rx, 0, sizeof(rx));
  rx.accepting_mode = accepting_mode;
  rx.priority_adjustment = priority_adjustment;

  if (compile_request_packet_write(&cp, &pkt_len, &pkt_buf) < 0) {
    // FIXME: need reasonable recovery?
    goto failed;
  }

  if (!sfx) sfx = "";
  generate_packet_name(run_id, 0, pkt_name);

  if (len == -1) {
    // copy from archive
    arch_flags = archive_make_read_path(run_arch, sizeof(run_arch),
                                        global->run_archive_dir, run_id, 0,0);
    if (arch_flags < 0) return -1;
    if (generic_copy_file(arch_flags, 0, run_arch, "",
                          0, global->compile_src_dir, pkt_name, sfx) < 0)
      goto failed;
  } else {
    // write from memory
    if (generic_write_file(str, len, 0,
                           global->compile_src_dir, pkt_name, sfx) < 0)
      goto failed;
  }

  if (generic_write_file(pkt_buf, pkt_len, SAFE,
                         global->compile_queue_dir, pkt_name, "") < 0) {
    goto failed;
  }

  if (run_change_status(run_id, RUN_COMPILING, 0, -1, cp.judge_id) < 0) {
    goto failed;
  }

  xfree(pkt_buf);
  return 0;

 failed:
  xfree(pkt_buf);
  return -1;
}

static void
rejudge_run(int run_id, struct client_state *p, int force_full_rejudge,
            int priority_adjustment)
{
  struct run_entry re;
  int accepting_mode = -1;

  if (run_get_entry(run_id, &re) < 0) return;
  if (re.is_imported) return;
  if (re.is_readonly) return;
  if (re.language <= 0 || re.language > max_lang || !langs[re.language]) {
    err("rejudge_run: bad language: %d", re.language);
    return;
  }
  if (re.problem <= 0 || re.problem > max_prob || !probs[re.problem]) {
    err("rejudge_run: bad problem: %d", re.problem);
    return;
  }

  if (force_full_rejudge && global->score_system_val == SCORE_OLYMPIAD
      && !olympiad_judging_mode) {
    accepting_mode = 0;
  }

  queue_compile_request(0, -1, run_id,
                        langs[re.language]->compile_id, re.locale_id,
                        probs[re.problem]->output_only,
                        langs[re.language]->src_sfx,
                        langs[re.language]->compiler_env,
                        accepting_mode, priority_adjustment);

  append_audit_log(run_id, p, "Command: Rejudge");
}

static int
count_transient_runs(void)
{
  int total_runs, r, counter = 0;
  struct run_entry re;

  total_runs = run_get_total();
  for (r = 0; r < total_runs; r++) {
    if (run_get_entry(r, &re) < 0) continue;
    if (re.status >= RUN_TRANSIENT_FIRST && re.status <= RUN_TRANSIENT_LAST)
      counter++;
  }
  return counter;
}

static void
do_rejudge_all(struct client_state *p)
{
  int total_runs, r;
  struct run_entry re;

  total_runs = run_get_total();

  if (global->score_system_val == SCORE_OLYMPIAD
      && olympiad_judging_mode) {
    // rejudge only "ACCEPTED", "OK", "PARTIAL SOLUTION" runs,
    // considering only the last run for the given problem and
    // the given participant
    int total_ids = teamdb_get_max_team_id() + 1;
    int total_probs = max_prob + 1;
    int size = total_ids * total_probs;
    int idx;
    unsigned char *flag;

    if (total_ids <= 0 || total_probs <= 0) return;
    flag = (unsigned char *) alloca(size);
    memset(flag, 0, size);
    for (r = total_runs - 1; r >= 0; r--) {
      if (run_get_entry(r, &re) < 0) continue;
      if (re.status != RUN_OK && re.status != RUN_PARTIAL
          && re.status != RUN_ACCEPTED) continue;
      if (re.is_imported) continue;
      if (re.team <= 0 || re.team >= total_ids) continue;
      if (re.problem <= 0 || re.problem >= total_probs) {
        fprintf(stderr, "Invalid problem %d for run %d", re.problem, r);
        continue;
      }
      if (re.is_readonly) continue;
      if (!probs[re.problem] || probs[re.problem]->disable_testing) continue;
      if (!langs[re.language] || langs[re.language]->disable_testing) continue;
      idx = re.team * total_probs + re.problem;
      if (flag[idx]) continue;
      flag[idx] = 1;
      rejudge_run(r, p, 0, 0);
    }
    return;
  }

  for (r = 0; r < total_runs; r++) {
    if (run_get_entry(r, &re) >= 0
        && re.status <= RUN_MAX_STATUS
        && re.status != RUN_IGNORED
        && re.status != RUN_DISQUALIFIED
        && re.problem >= 1 && re.problem <= max_prob
        && probs[re.problem]
        && !probs[re.problem]->disable_testing
        && !langs[re.language]->disable_testing
        && !re.is_readonly
        && !re.is_imported) {
      rejudge_run(r, p, 0, 0);
    }
  }
}

static void
do_judge_suspended(struct client_state *p)
{
  int total_runs, r;
  struct run_entry re;

  total_runs = run_get_total();

  if (global->score_system_val == SCORE_OLYMPIAD && olympiad_judging_mode)
    return;

  for (r = 0; r < total_runs; r++) {
    if (run_get_entry(r, &re) >= 0
        && re.status == RUN_PENDING
        && !re.is_imported
        && re.problem > 0
        && re.problem <= max_prob
        && probs[re.problem]
        && !re.is_readonly
        && !probs[re.problem]->disable_testing
        && !probs[re.problem]->disable_auto_testing
        && !langs[re.language]->disable_testing
        && !langs[re.language]->disable_auto_testing) {
      rejudge_run(r, p, 0, 0);
    }
  }
}

static void
do_rejudge_problem(int prob_id, struct client_state *p)
{
  int total_runs, r;
  struct run_entry re;

  if (prob_id <= 0 || prob_id > max_prob || !probs[prob_id]
      || probs[prob_id]->disable_testing) return;
  total_runs = run_get_total();

  if (global->score_system_val == SCORE_OLYMPIAD
      && olympiad_judging_mode) {
    // rejudge only "ACCEPTED", "OK", "PARTIAL SOLUTION" runs,
    // considering only the last run for the given participant
    int total_ids = teamdb_get_max_team_id() + 1;
    unsigned char *flag;

    if (total_ids <= 0) return;
    flag = (unsigned char *) alloca(total_ids);
    memset(flag, 0, total_ids);
    for (r = total_runs - 1; r >= 0; r--) {
      if (run_get_entry(r, &re) < 0) continue;
      if (re.status != RUN_OK && re.status != RUN_PARTIAL
          && re.status != RUN_ACCEPTED) continue;
      if (re.problem != prob_id) continue;
      if (re.is_imported) continue;
      if (re.is_readonly) continue;
      if (re.team <= 0 || re.team >= total_ids) continue;
      if (flag[re.team]) continue;
      if (!langs[re.language] || langs[re.language]->disable_testing) continue;
      flag[re.team] = 1;
      rejudge_run(r, p, 0, 0);
    }
    return;
  }

  for (r = 0; r < total_runs; r++) {
    if (run_get_entry(r, &re) >= 0
        && re.problem == prob_id && re.status <= RUN_MAX_STATUS
        && !re.is_readonly
        && re.status != RUN_IGNORED
        && re.status != RUN_DISQUALIFIED
        && !re.is_imported) {
      rejudge_run(r, p, 0, 0);
    }
  }
}

#define BITS_PER_LONG (8*sizeof(unsigned long)) 

static void
do_rejudge_by_mask(int mask_size, unsigned long *mask, struct client_state *p,
                   int force_flag, int priority_adjustment)
{
  int total_runs, r;
  struct run_entry re;

  ASSERT(mask_size > 0);

  total_runs = run_get_total();
  if (total_runs > mask_size * BITS_PER_LONG) {
    total_runs = mask_size * BITS_PER_LONG;
  }

  if (global->score_system_val == SCORE_OLYMPIAD
      && olympiad_judging_mode) {
    // rejudge only "ACCEPTED", "OK", "PARTIAL SOLUTION" runs,
    // considering only the last run for the given problem and
    // the given participant
    int total_ids = teamdb_get_max_team_id() + 1;
    int total_probs = max_prob + 1;
    int size = total_ids * total_probs;
    int idx;
    unsigned char *flag;

    if (total_ids <= 0 || total_probs <= 0) return;
    flag = (unsigned char *) alloca(size);
    memset(flag, 0, size);
    for (r = total_runs - 1; r >= 0; r--) {
      if (run_get_entry(r, &re) < 0) continue;
      if (re.status != RUN_OK && re.status != RUN_PARTIAL
          && re.status != RUN_ACCEPTED) continue;
      if (re.is_imported) continue;
      if (re.team <= 0 || re.team >= total_ids) continue;
      if (re.problem <= 0 || re.problem >= total_probs) {
        fprintf(stderr, "Invalid problem %d for run %d", re.problem, r);
        continue;
      }
      if (re.is_readonly) continue;
      if (!probs[re.problem] || probs[re.problem]->disable_testing) continue;
      if (!langs[re.language]|| langs[re.language]->disable_testing) continue;
      if (!(mask[r / BITS_PER_LONG] & (1 << (r % BITS_PER_LONG)))) continue;
      idx = re.team * total_probs + re.problem;
      if (flag[idx]) continue;
      flag[idx] = 1;
      rejudge_run(r, p, 0, 0);
    }
    return;
  }

  for (r = 0; r < total_runs; r++) {
    if (run_get_entry(r, &re) >= 0
        && re.status <= RUN_MAX_STATUS
        && re.status != RUN_IGNORED
        && re.status != RUN_DISQUALIFIED
        && re.problem >= 1 && re.problem <= max_prob
        && probs[re.problem]
        && !probs[re.problem]->disable_testing
        && !langs[re.language]->disable_testing
        && !re.is_readonly
        && !re.is_imported
        && (mask[r / BITS_PER_LONG] & (1 << (r % BITS_PER_LONG)))) {
      rejudge_run(r, p, force_flag, priority_adjustment);
    }
  }
}

static void
check_remove_queue(void)
{
  struct remove_queue_item *p;

  while (1) {
    if (!remove_queue_first) return;
    if (remove_queue_first->rmtime > current_time) return;

    clear_directory(remove_queue_first->path);
    if (rmdir(remove_queue_first->path) < 0) {
      err("rmdir failed: %s", os_ErrorMsg());
    }

    p = remove_queue_first;
    remove_queue_first = p->next;
    if (!remove_queue_first) remove_queue_last = 0;
    xfree(p);
  }
}

struct packet_handler
{
  void (*func)();
};

static const struct packet_handler packet_handlers[SRV_CMD_LAST] =
{
  [SRV_CMD_PASS_FD] { cmd_pass_descriptors },
  [SRV_CMD_GET_ARCHIVE] { cmd_team_get_archive },
  [SRV_CMD_SHOW_CLAR] { cmd_team_show_item },
  [SRV_CMD_SHOW_SOURCE] { cmd_team_show_item },
  [SRV_CMD_SHOW_REPORT] { cmd_view },
  [SRV_CMD_SUBMIT_RUN] { cmd_team_submit_run },
  [SRV_CMD_SUBMIT_CLAR] { cmd_team_submit_clar },
  [SRV_CMD_TEAM_PAGE] { cmd_team_page },
  [SRV_CMD_MASTER_PAGE] { cmd_master_page },
  [SRV_CMD_PRIV_STANDINGS] { cmd_priv_standings },
  [SRV_CMD_VIEW_SOURCE] { cmd_view },
  [SRV_CMD_VIEW_REPORT] { cmd_view },
  [SRV_CMD_VIEW_CLAR] { cmd_view },
  [SRV_CMD_VIEW_USERS] { cmd_view },
  [SRV_CMD_PRIV_MSG] { cmd_message },
  [SRV_CMD_PRIV_REPLY] { cmd_message },
  [SRV_CMD_SUSPEND] { cmd_priv_command_0 },
  [SRV_CMD_RESUME] { cmd_priv_command_0 },
  [SRV_CMD_TEST_SUSPEND] { cmd_priv_command_0 },
  [SRV_CMD_TEST_RESUME] { cmd_priv_command_0 },
  [SRV_CMD_UPDATE_STAND] { cmd_priv_command_0 },
  [SRV_CMD_START] { cmd_priv_command_0 },
  [SRV_CMD_STOP] { cmd_priv_command_0 },
  [SRV_CMD_RESET] { cmd_priv_command_0 },
  [SRV_CMD_REJUDGE_ALL] { cmd_priv_command_0 },
  [SRV_CMD_REJUDGE_PROBLEM] { cmd_priv_command_0 },
  [SRV_CMD_JUDGE_SUSPENDED] { cmd_priv_command_0 },
  [SRV_CMD_SCHEDULE] { cmd_priv_command_0 },
  [SRV_CMD_DURATION] { cmd_priv_command_0 },
  [SRV_CMD_EDIT_RUN] { cmd_edit_run },
  [SRV_CMD_VIRTUAL_START] { cmd_command_0 },
  [SRV_CMD_VIRTUAL_STOP] { cmd_command_0 },
  [SRV_CMD_VIRTUAL_STANDINGS] { cmd_team_show_item },
  [SRV_CMD_RESET_FILTER] { cmd_reset_filter },
  [SRV_CMD_CLEAR_RUN] { cmd_priv_command_0 },
  [SRV_CMD_SQUEEZE_RUNS] { cmd_priv_command_0 },
  [SRV_CMD_DUMP_RUNS] { cmd_view },
  [SRV_CMD_DUMP_PROBLEMS] { cmd_view },
  [SRV_CMD_DUMP_STANDINGS] { cmd_view },
  [SRV_CMD_SET_JUDGING_MODE] { cmd_priv_command_0 },
  [SRV_CMD_CONTINUE] { cmd_priv_command_0 },
  [SRV_CMD_WRITE_XML_RUNS] { cmd_view },
  [SRV_CMD_IMPORT_XML_RUNS] { cmd_import_xml_runs },
  [SRV_CMD_QUIT] { cmd_priv_command_0 },
  [SRV_CMD_EXPORT_XML_RUNS] { cmd_view },
  [SRV_CMD_PRIV_SUBMIT_RUN] { cmd_priv_submit_run },
  [SRV_CMD_SET_ACCEPTING_MODE] { cmd_priv_command_0 },
  [SRV_CMD_PRIV_PRINT_RUN] { cmd_priv_command_0 },
  [SRV_CMD_PRINT_RUN] { cmd_team_print },
  [SRV_CMD_PRIV_DOWNLOAD_RUN] { cmd_view },
  [SRV_CMD_PRINT_SUSPEND] { cmd_priv_command_0 },
  [SRV_CMD_PRINT_RESUME] { cmd_priv_command_0 },
  [SRV_CMD_COMPARE_RUNS] { cmd_view },
  [SRV_CMD_UPLOAD_REPORT] { cmd_upload_report },
  [SRV_CMD_REJUDGE_BY_MASK] { cmd_rejudge_by_mask },
  [SRV_CMD_NEW_RUN_FORM] { cmd_view },
  [SRV_CMD_NEW_RUN] { cmd_new_run },
  [SRV_CMD_VIEW_TEAM] { cmd_view },
  [SRV_CMD_SET_TEAM_STATUS] { cmd_edit_user },
  [SRV_CMD_ISSUE_WARNING] { cmd_edit_user },
  [SRV_CMD_SOFT_UPDATE_STAND] { cmd_priv_command_0 },
  [SRV_CMD_PRIV_DOWNLOAD_REPORT] { cmd_view },
  [SRV_CMD_PRIV_DOWNLOAD_TEAM_REPORT] { cmd_view },
  [SRV_CMD_DUMP_MASTER_RUNS] { cmd_master_page },
  [SRV_CMD_RESET_CLAR_FILTER] { cmd_reset_filter },
  [SRV_CMD_HAS_TRANSIENT_RUNS] { cmd_priv_command_0 },
  [SRV_CMD_GET_TEST_SUSPEND] { cmd_simple_command },
  [SRV_CMD_VIEW_TEST_INPUT] { cmd_view },
  [SRV_CMD_VIEW_TEST_OUTPUT] { cmd_view },
  [SRV_CMD_VIEW_TEST_ANSWER] { cmd_view },
  [SRV_CMD_VIEW_TEST_ERROR] { cmd_view },
  [SRV_CMD_VIEW_TEST_CHECKER] { cmd_view },
  [SRV_CMD_VIEW_TEST_INFO] { cmd_view },
  [SRV_CMD_VIEW_AUDIT_LOG] { cmd_view },
  [SRV_CMD_GET_CONTEST_TYPE] { cmd_get_param },
  [SRV_CMD_SUBMIT_RUN_2] { cmd_user_submit_run_2 },
  [SRV_CMD_FULL_REJUDGE_BY_MASK] { cmd_rejudge_by_mask },
  [SRV_CMD_DUMP_SOURCE] { cmd_team_show_item },
  [SRV_CMD_DUMP_CLAR] { cmd_team_show_item },
  [SRV_CMD_RUN_STATUS] { cmd_team_show_item },
  [SRV_CMD_DUMP_SOURCE_2] { cmd_team_show_item },
};

static void
process_packet(struct client_state *p, int len,
               struct prot_serve_packet *pack)
{
  if (len < sizeof(*pack)) {
    err("%d: packet length is too small: %d", p->id, len);
    client_disconnect(p, 0);
    return;
  }
  if (pack->magic != PROT_SERVE_PACKET_MAGIC) {
    err("%d: bad magic header: %04x", p->id, pack->magic);
    client_disconnect(p, 0);
    return;
  }

  if (pack->id <= 0 || pack->id >= SRV_CMD_LAST
      || !packet_handlers[pack->id].func) {
    err("%d: unknown request id: %d, %d", p->id, pack->id, len);
    client_disconnect(p, 0);
    return;
  }

  (*packet_handlers[pack->id].func)(p, len, pack);
}

static int
create_socket(void)
{
  struct sockaddr_un addr;

  if (cmdline_socket_fd >= 0) {
    socket_fd = cmdline_socket_fd;
    return 0;
  }

  if ((socket_fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
    err("socket() failed :%s", os_ErrorMsg());
    return -1;
  }
  if (forced_mode) unlink(global->serve_socket);
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, global->serve_socket, 108);
  addr.sun_path[107] = 0;
  if (bind(socket_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    err("bind() failed: %s", os_ErrorMsg());
    return -1;
  }
  socket_name = global->serve_socket;

  if (chmod(global->serve_socket, 0777) < 0) {
    err("chmod() failed: %s", os_ErrorMsg());
    return -1;
  }
  if (listen(socket_fd, 20) < 0) {
    err("listen() failed: %s", os_ErrorMsg());
    return -1;
  }

  return 0;
}

static int
check_sockets(int may_wait_flag)
{
  fd_set rset, wset;
  int max_fd, val, new_fd, addrlen, l, w, r;
  struct client_state *p, *q;
  struct timeval timeout;
  struct sockaddr_un addr;

  if (may_wait_flag && socket_fd < 0) {
    os_Sleep(global->serve_sleep_time);
    return 1;
  }

  FD_ZERO(&rset);
  FD_ZERO(&wset);
  max_fd = -1;

  if (!interrupt_signaled) {
    FD_SET(socket_fd, &rset);
    max_fd = socket_fd + 1;
  }
  for (p = client_first; p; p = p->next) {
    p->processed = 0;
    if (p->write_len > 0) {
      FD_SET(p->fd, &wset);
      if (p->fd >= max_fd) max_fd = p->fd + 1;
    } else if (!interrupt_signaled) {
      FD_SET(p->fd, &rset);
      if (p->fd >= max_fd) max_fd = p->fd + 1;
    }
  }

  if (max_fd == -1) {
    info("no file descriptors to wait on");
    return 0;
  }

  if (may_wait_flag) {
    timeout.tv_sec = global->serve_sleep_time / 1000;
    timeout.tv_usec = (global->serve_sleep_time % 1000) * 1000;
  } else {
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
  }

  val = select(max_fd, &rset, &wset, NULL, &timeout);
  if (val < 0 && errno == EINTR) {
    info("select interrupted, restarting it");
    return 0;
  }
  if (val < 0) {
    err("select() failed: %s", os_ErrorMsg());
    return 0;
  }
  if (!val) {
    // nothing... :-(
    return 1;
  }
  may_wait_flag = 1;

  last_activity_time = current_time;
  
  while (FD_ISSET(socket_fd, &rset)) {
    memset(&addr, 0, sizeof(addr));
    addrlen = sizeof(addr);
    new_fd = accept(socket_fd, (struct sockaddr*) &addr, &addrlen);
    if (new_fd < 0) {
      int e = errno;
      err("accept failed: %s", os_ErrorMsg());
      if (e == ENOTSOCK) return 0;
      break;
    }

    p = client_new_state(new_fd);
    val = 1;
    if (setsockopt(new_fd, SOL_SOCKET, SO_PASSCRED, &val, sizeof(val)) < 0) {
      err("%d: setsockopt() failed: %s", p->id, os_ErrorMsg());
      client_disconnect(p, 1);
      break;
    }

    info("%d: connection accepted", p->id);
    may_wait_flag = 0;
    break;
  }

  /* check writers */
  while (1) {
    for (p = client_first; p; p = p->next) {
      if (FD_ISSET(p->fd, &wset) && !p->processed) break;
    }
    if (!p) break;

    p->processed = 1;
    may_wait_flag = 0;
    l = p->write_len - p->written;
    w = write(p->fd, &p->write_buf[p->written], l);

    if (w < 0 && (errno == EINTR || errno == EAGAIN)) {
      info("%d: not ready for write descriptor", p->id);
      continue;
    }
    if (w <= 0) {
      err("%d: write() failed: %s (%d, %d, %d)", p->id, os_ErrorMsg(),
          p->fd, l, p->write_len);
      client_disconnect(p, 1);
      continue;
    }
    p->written += w;
    if (p->write_len == p->written) {
      p->written = 0;
      p->write_len = 0;
      xfree(p->write_buf);
      p->write_buf = 0;
      if (p->state == STATE_AUTOCLOSE) {
        info("%d: auto-disconnecting: %d, %d, %d", p->id,
             p->fd, p->client_fds[0], p->client_fds[1]);
        client_disconnect(p, 1);
        continue;
      }
    }
  }

  while (1) {
    for (p = client_first; p; p = p->next)
      if (FD_ISSET(p->fd, &rset) && !p->processed) break;
    if (!p) break;

    p->processed = 1;
    may_wait_flag = 0;

    /* read peer credentials */
    if (p->state == STATE_READ_CREDS) {
      struct msghdr msg;
      unsigned char msgbuf[512];
      struct cmsghdr *pmsg;
      struct ucred *pcred;
      struct iovec recv_vec[1];
      int val;

      // we expect 4 zero bytes and credentials
      memset(&msg, 0, sizeof(msg));
      msg.msg_flags = 0;
      msg.msg_control = msgbuf;
      msg.msg_controllen = sizeof(msgbuf);
      recv_vec[0].iov_base = &val;
      recv_vec[0].iov_len = 4;
      msg.msg_iov = recv_vec;
      msg.msg_iovlen = 1;
      val = -1;
      r = recvmsg(p->fd, &msg, 0);
      if (r < 0) {
        err("%d: recvmsg failed: %s", p->id, os_ErrorMsg());
        client_disconnect(p, 1);
        continue;
      }
      if (r != 4) {
        err("%d: read %d bytes instead of 4", p->id, r);
        client_disconnect(p, 1);
        continue;
      }
      if (val != 0) {
        err("%d: expected 4 zero bytes", p->id);
        client_disconnect(p, 1);
        continue;
      }
      if ((msg.msg_flags & MSG_CTRUNC)) {
        err("%d: protocol error: control buffer too small", p->id);
        client_disconnect(p, 1);
        continue;
      }

      pmsg = CMSG_FIRSTHDR(&msg);
      if (!pmsg) {
        err("%d: empty control data", p->id);
        client_disconnect(p, 1);
        continue;
      }
      /* cmsg_len, cmsg_level, cmsg_type */
      if (pmsg->cmsg_level != SOL_SOCKET
          || pmsg->cmsg_type != SCM_CREDENTIALS
          || pmsg->cmsg_len != CMSG_LEN(sizeof(*pcred))) {
        err("%d: protocol error: unexpected control data", p->id);
        client_disconnect(p, 1);
        continue;
      }
      pcred = (struct ucred*) CMSG_DATA(pmsg);
      p->peer_pid = pcred->pid;
      p->peer_uid = pcred->uid;
      p->peer_gid = pcred->gid;
      if (CMSG_NXTHDR(&msg, pmsg)) {
        err("%d: protocol error: unexpected control data", p->id);
        client_disconnect(p, 1);
        continue;
      }

      info("%d: received peer information: %d, %d, %d", p->id,
           p->peer_pid, p->peer_uid, p->peer_gid);

      p->state = STATE_READ_DATA;
      continue;
    }

    /* read peer file descriptors */
    if (p->state == STATE_READ_FDS) {
      struct msghdr msg;
      unsigned char msgbuf[512];
      struct cmsghdr *pmsg;
      struct iovec recv_vec[1];
      int *fds;
      int val;

      // we expect 4 zero bytes and 1 or 2 file descriptors
      memset(&msg, 0, sizeof(msg));
      msg.msg_flags = 0;
      msg.msg_control = msgbuf;
      msg.msg_controllen = sizeof(msgbuf);
      recv_vec[0].iov_base = &val;
      recv_vec[0].iov_len = 4;
      msg.msg_iov = recv_vec;
      msg.msg_iovlen = 1;
      val = -1;
      r = recvmsg(p->fd, &msg, 0);
      if (r < 0) {
        err("%d: recvmsg failed: %s", p->id, os_ErrorMsg());
        client_disconnect(p, 1);
        continue;
      }
      if (r != 4) {
        err("%d: read %d bytes instead of 4", p->id, r);
        client_disconnect(p, 1);
        continue;
      }
      if (val != 0) {
        err("%d: expected 4 zero bytes", p->id);
        client_disconnect(p, 1);
        continue;
      }
      if ((msg.msg_flags & MSG_CTRUNC)) {
        err("%d: protocol error: control buffer too small", p->id);
        client_disconnect(p, 1);
        continue;
      }

      /*
       * actually, the first control message could be credentials
       * so we need to skip it
       */
      pmsg = CMSG_FIRSTHDR(&msg);
      while (1) {
        if (!pmsg) break;
        if (pmsg->cmsg_level == SOL_SOCKET
            && pmsg->cmsg_type == SCM_RIGHTS) break;
        pmsg = CMSG_NXTHDR(&msg, pmsg);
      }
      if (!pmsg) {
        err("%d: empty control data", p->id);
        client_disconnect(p, 1);
        continue;
      }
      fds = (int*) CMSG_DATA(pmsg);
      if (pmsg->cmsg_len == CMSG_LEN(2 * sizeof(int))) {
        info("%d: received 2 file descriptors: %d, %d",p->id,fds[0],fds[1]);
        p->client_fds[0] = fds[0];
        p->client_fds[1] = fds[1];
      } else if (pmsg->cmsg_len == CMSG_LEN(1 * sizeof(int))) {
        info("%d: received 1 file descriptor: %d", p->id, fds[0]);
        p->client_fds[0] = fds[0];
        p->client_fds[1] = -1;
      } else {
        err("%d: invalid number of file descriptors passed", p->id);
        client_disconnect(p, 1);
        continue;
      }

      p->state = STATE_READ_DATA;
      continue;
    }

    /* read packet length */
    if (p->read_state < 4) {
      unsigned char rbuf[4];

      memcpy(rbuf, &p->expected_len, 4);
      l = 4 - p->read_state;
      r = read(p->fd, &rbuf[p->read_state], l);
      if (!p->read_state && !r) {
        info("%d: client closed connection", p->id);
        client_disconnect(p, 1);
        continue;
      }
      if (!r) {
        err("%d: unexpected EOF from client", p->id);
        client_disconnect(p, 1);
        continue;
      }
      if (r < 0) {
        if (errno == EINTR || errno == EAGAIN) {
          info("%d: not ready descriptor", p->id);
          continue;
        }
        err("%d: read() failed: %s", p->id, os_ErrorMsg());
        client_disconnect(p, 1);
        continue;
      }

      p->read_state += l;
      memcpy(&p->expected_len, rbuf, 4);
      if (p->read_state == 4) {
        if (p->expected_len <= 0 || p->expected_len > MAX_EXPECTED_LEN) {
          err("%d: protocol error: bad packet length: %d",
              p->id, p->expected_len);
          client_disconnect(p, 0);
          continue;
        }
        p->read_len = 0;
        p->read_buf = (unsigned char*) xcalloc(1, p->expected_len);
      }
      continue;
    }

    /* read packet data */
    l = p->expected_len - p->read_len;
    r = read(p->fd, &p->read_buf[p->read_len], l);
    if (!r) {
      err("%d: unexpected EOF from client", p->id);
      client_disconnect(p, 1);
      continue;
    }
    if (r < 0) {
      if (errno == EINTR || errno == EAGAIN) {
        info("%d: not ready descriptor", p->id);
        continue;
      }
      err("%d: read() failed: %s", p->id, os_ErrorMsg());
      client_disconnect(p, 1);
      continue;
    }

    p->read_len += r;
    if (p->expected_len == p->read_len) {
      /* as packet read completely, we may run handle function */
      process_packet(p, p->expected_len,
                     (struct prot_serve_packet*) p->read_buf);
      /* it is very well possible, that p is no longer valid */
      for (q = client_first; q && q != p; q = q->next);
      if (q) {
        /* p is valid! */
        p->read_len = 0;
        p->expected_len = 0;
        p->read_state = 0;
        xfree(p->read_buf);
        p->read_buf = 0;
      }
    }
  }

  return may_wait_flag;
}

static void
generate_statistics_email(time_t from_time, time_t to_time)
{
  unsigned char esubj[1024];
  struct tm *ptm;
  char *etxt = 0, *ftxt = 0;
  size_t elen = 0, flen = 0;
  FILE *eout = 0, *fout = 0;
  const struct contest_desc *cnts = 0;
  unsigned char *mail_args[7];
  unsigned char *originator;
  struct tm tm1;

  if (contests_get(global->contest_id, &cnts) < 0 || !cnts) return;

  ptm = localtime(&from_time);
  snprintf(esubj, sizeof(esubj),
           "Daily statistics for %04d/%02d/%02d, contest %d",
           ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
           global->contest_id);

  eout = open_memstream(&etxt, &elen);
  generate_daily_statistics(eout, from_time, to_time);
  fclose(eout); eout = 0;
  if (!etxt || !*etxt) {
    xfree(etxt);
    return;
  }

  localtime_r(&from_time, &tm1);

  fout = open_memstream(&ftxt, &flen);
  fprintf(fout,
          "Hello,\n"
          "\n"
          "This is daily report for contest %d (%s)\n"
          "Report day: %04d/%02d/%02d\n\n"
          "%s\n\n"
          "-\n"
          "Regards,\n"
          "the ejudge contest management system\n",
          global->contest_id, cnts->name,
          tm1.tm_year + 1900, tm1.tm_mon + 1, tm1.tm_mday,
          etxt);
  fclose(fout); fout = 0;

  originator = get_email_sender(cnts);
  mail_args[0] = "mail";
  mail_args[1] = "";
  mail_args[2] = esubj;
  mail_args[3] = originator;
  mail_args[4] = cnts->daily_stat_email;
  mail_args[5] = ftxt;
  mail_args[6] = 0;
  send_job_packet(NULL, mail_args);
  xfree(ftxt); ftxt = 0;
  xfree(etxt); etxt = 0;
}

static void
check_stat_generation(int force_flag)
{
  static time_t last_check_time = 0;
  const struct contest_desc *cnts = 0;
  struct tm *ptm;
  time_t thisday, nextday;

  if (!force_flag && last_check_time > 0
      && last_check_time + 600 > current_time)
    return;
  last_check_time = current_time;
  if (contests_get(global->contest_id, &cnts) < 0 || !cnts) return;
  if (!cnts->daily_stat_email) return;

  if (!stat_reported_before) {
    // set the time to the beginning of this day
    ptm = localtime(&current_time);
    ptm->tm_hour = 0;
    ptm->tm_min = 0;
    ptm->tm_sec = 0;
    ptm->tm_isdst = -1;
    if ((thisday = mktime(ptm)) == (time_t) -1) {
      err("check_stat_generation: mktime() failed");
      thisday = 0;
    }
    stat_reported_before = thisday;
  }
  if (!stat_report_time) {
    // set the time to the beginning of the next day
    ptm = localtime(&current_time);
    ptm->tm_hour = 0;
    ptm->tm_min = 0;
    ptm->tm_sec = 0;
    ptm->tm_isdst = -1;
    ptm->tm_mday++;             // pretty valid. see man mktime
    if ((nextday = mktime(ptm)) == (time_t) -1) {
      err("check_stat_generation: mktime() failed");
      nextday = 0;
    }
    stat_report_time = nextday;
  }

  if (current_time < stat_report_time) return;

  // generate report for each day from stat_reported_before to stat_report_time
  thisday = stat_reported_before;
  while (thisday < stat_report_time) {
    ptm = localtime(&thisday);
    ptm->tm_hour = 0;
    ptm->tm_min = 0;
    ptm->tm_sec = 0;
    ptm->tm_isdst = -1;
    ptm->tm_mday++;
    if ((nextday = mktime(ptm)) == (time_t) -1) {
      err("check_stat_generation: mktime() failed");
      stat_reported_before = 0;
      stat_report_time = 0;
      return;
    }
    generate_statistics_email(thisday, nextday);
    thisday = nextday;
  }

  ptm = localtime(&thisday);
  ptm->tm_hour = 0;
  ptm->tm_min = 0;
  ptm->tm_sec = 0;
  ptm->tm_isdst = -1;
  ptm->tm_mday++;
  if ((nextday = mktime(ptm)) == (time_t) -1) {
    err("check_stat_generation: mktime() failed");
    stat_reported_before = 0;
    stat_report_time = 0;
    return;
  }
  stat_reported_before = thisday;
  stat_report_time = nextday;
}

static int
may_safely_exit(void)
{
  struct client_state *p;

  for (p = client_first; p; p = p->next) {
    if (p->write_len > 0) break;
  }
  if (p) return 0;
  return 1;
}

static int
create_symlinks(void)
{
  unsigned char src_path[PATH_MAX];
  unsigned char dst_path[PATH_MAX];
  path_t stand_file;
  int npages, pgn;

  if (global->stand_symlink_dir[0] && global->htdocs_dir[0]) {
    if (global->users_on_page > 0) {
      // FIXME: check, that standings_file_name depends on page number
      npages = (teamdb_get_total_teams() + global->users_on_page - 1)
        / global->users_on_page;
      for (pgn = 0; pgn < npages; pgn++) {
        if (!pgn) {
          snprintf(stand_file, sizeof(stand_file), global->standings_file_name,
                   pgn + 1);
        } else {
          snprintf(stand_file, sizeof(stand_file), global->stand_file_name_2,
                   pgn + 1);
        }
        snprintf(src_path, sizeof(src_path), "%s/dir/%s",
                 global->status_dir, stand_file);
        snprintf(dst_path, sizeof(dst_path), "%s/%s/%s",
                 global->htdocs_dir, global->stand_symlink_dir,
                 stand_file);
        os_normalize_path(dst_path);
        if (unlink(dst_path) < 0 && errno != ENOENT) {
          err("unlink %s failed: %s", dst_path, os_ErrorMsg());
          //return -1;
        }
        if (symlink(src_path, dst_path) < 0) {
          err("symlink %s->%s failed: %s", dst_path, src_path, os_ErrorMsg());
          //return -1;
        }
      }
    } else {
      snprintf(src_path, sizeof(src_path), "%s/dir/%s",
               global->status_dir, global->standings_file_name);
      snprintf(dst_path, sizeof(dst_path), "%s/%s/%s",
               global->htdocs_dir, global->stand_symlink_dir,
               global->standings_file_name);
      os_normalize_path(dst_path);
      if (unlink(dst_path) < 0 && errno != ENOENT) {
        err("unlink %s failed: %s", dst_path, os_ErrorMsg());
        //return -1;
      }
      if (symlink(src_path, dst_path) < 0) {
        err("symlink %s->%s failed: %s", dst_path, src_path, os_ErrorMsg());
        //return -1;
      }
    }
  }
  if (global->stand2_symlink_dir[0] && global->htdocs_dir[0]
      && global->stand2_file_name[0]) {
    snprintf(src_path, sizeof(src_path), "%s/dir/%s",
             global->status_dir, global->stand2_file_name);
    snprintf(dst_path, sizeof(dst_path), "%s/%s/%s",
             global->htdocs_dir, global->stand2_symlink_dir,
             global->stand2_file_name);
    os_normalize_path(dst_path);
    if (unlink(dst_path) < 0 && errno != ENOENT) {
      err("unlink %s failed: %s", dst_path, os_ErrorMsg());
      //return -1;
    }
    if (symlink(src_path, dst_path) < 0) {
      err("symlink %s->%s failed: %s", dst_path, src_path, os_ErrorMsg());
      //return -1;
    }
  }
  if (global->plog_symlink_dir[0] && global->htdocs_dir[0]
      && global->plog_file_name[0] && global->plog_update_time > 0) {
    snprintf(src_path, sizeof(src_path), "%s/dir/%s",
             global->status_dir, global->plog_file_name);
    snprintf(dst_path, sizeof(dst_path), "%s/%s/%s",
             global->htdocs_dir, global->plog_symlink_dir,
             global->plog_file_name);
    os_normalize_path(dst_path);
    if (unlink(dst_path) < 0 && errno != ENOENT) {
      err("unlink %s failed: %s", dst_path, os_ErrorMsg());
      //return -1;
    }
    if (symlink(src_path, dst_path) < 0) {
      err("symlink %s->%s failed: %s", dst_path, src_path, os_ErrorMsg());
      //return -1;
    }
  }
  return 0;
}

/* a collated list of different compile directories we need to look into */
struct compile_dir_item
{
  unsigned char *status_dir;
  unsigned char *report_dir;
};
static struct compile_dir_item *compile_dirs = 0;
static int compile_dirs_u = 0, compile_dirs_a = 0;
static int
do_build_compile_dirs(const unsigned char *status_dir, const unsigned char *report_dir)
{
  int i;

  if (!status_dir || !*status_dir || !report_dir || !*report_dir) abort();

  for (i = 0; i < compile_dirs_u; i++)
    if (!strcmp(compile_dirs[i].status_dir, status_dir))
      break;
  if (i < compile_dirs_u) return i;

  if (compile_dirs_u == compile_dirs_a) {
    if (!compile_dirs_a) compile_dirs_a = 8;
    compile_dirs_a *= 2;
    XREALLOC(compile_dirs, compile_dirs_a);
  }

  compile_dirs[compile_dirs_u].status_dir = xstrdup(status_dir);
  compile_dirs[compile_dirs_u].report_dir = xstrdup(report_dir);
  return compile_dirs_u++;
}
static void
build_compile_dirs(void)
{
  int i;

  for (i = 1; i <= max_lang; i++) {
    if (!langs[i]) continue;
    do_build_compile_dirs(langs[i]->compile_status_dir, langs[i]->compile_report_dir);
  }
}

struct run_dir_item
{
  unsigned char *status_dir;
  unsigned char *report_dir;
  unsigned char *team_report_dir;
  unsigned char *full_report_dir;
};
static struct run_dir_item *run_dirs = 0;
static int run_dirs_u = 0, run_dirs_a = 0;
static int
do_build_run_dirs(const unsigned char *status_dir,
                  const unsigned char *report_dir,
                  const unsigned char *team_report_dir,
                  const unsigned char *full_report_dir)
{
  int i;

  if (!status_dir || !*status_dir) abort();

  for (i = 0; i < run_dirs_u; i++)
    if (!strcmp(run_dirs[i].status_dir, status_dir))
      break;
  if (i < run_dirs_u) return i;

  if (run_dirs_u == run_dirs_a) {
    if (!run_dirs_a) run_dirs_a = 8;
    run_dirs_a *= 2;
    XREALLOC(run_dirs, run_dirs_a);
  }

  run_dirs[run_dirs_u].status_dir = xstrdup(status_dir);
  run_dirs[run_dirs_u].report_dir = xstrdup(report_dir);
  run_dirs[run_dirs_u].team_report_dir = xstrdup(team_report_dir);
  run_dirs[run_dirs_u].full_report_dir = xstrdup(full_report_dir);
  return run_dirs_u++;
}
static void
build_run_dirs(void)
{
  int i;

  for (i = 1; i <= max_tester; i++) {
    if (!testers[i]) continue;
    do_build_run_dirs(testers[i]->run_status_dir,
                      testers[i]->run_report_dir,
                      testers[i]->run_team_report_dir,
                      testers[i]->run_full_archive_dir);
  }
}

static int
do_loop(void)
{
  path_t packetname;
  int    r, p, i;
  int    may_wait_flag = 0;

  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, interrupt_signal);
  signal(SIGTERM, interrupt_signal);
  if (create_socket() < 0) return -1;

  // we need the number of users to create correct the number of symlinks
  teamdb_refresh();
  if (create_symlinks() < 0) return -1;

  current_time = time(0);
  last_activity_time = current_time;

  if (!global->virtual) {
    p = run_get_fog_period(time(0), global->board_fog_time,
                           global->board_unfog_time);
    if (p == 1) {
      global->fog_standings_updated = 1;
    }
  }
  update_standings_file(0);

  run_get_times(&contest_start_time, &contest_sched_time,
                &contest_duration, &contest_stop_time);
  if (!contest_duration == -1) {
    contest_duration = global->contest_time;
    run_set_duration(contest_duration);
  }

  while (1) {
    /* update current time */
    current_time = time(0);

    if (interrupt_signaled && may_safely_exit()) {
      info("Interrupt signaled");
      return 0;
    }
    if (cmdline_socket_fd >= 0 && global->inactivity_timeout > 0
        && current_time > last_activity_time + global->inactivity_timeout) {
      info("no activity for %d seconds, exiting", global->inactivity_timeout);
      return 0;
    }

    /* refresh user database */
    teamdb_refresh();

    /* check items pending for removal */
    check_remove_queue();

    /* check whether we should generate dayly statistics */
    check_stat_generation(0);

    /* check stop and start times */
    if (!global->virtual) {
      if (contest_start_time && !contest_stop_time && !contest_duration
          && global->contest_finish_time_d > 0
          && current_time >= global->contest_finish_time_d) {
        /* the contest is over! */
        info("CONTEST OVER");
        run_stop_contest(global->contest_finish_time_d);
        contest_stop_time = global->contest_finish_time_d;
      } else if (contest_start_time && !contest_stop_time && contest_duration) {
        if (current_time >= contest_start_time + contest_duration) {
          /* the contest is over! */
          info("CONTEST OVER");
          run_stop_contest(contest_start_time + contest_duration);
          contest_stop_time = contest_start_time + contest_duration;
        }
      } else if (contest_sched_time && !contest_start_time) {
        if (current_time >= contest_sched_time) {
          /* it's time to start! */
          info("CONTEST STARTED");
          run_start_contest(contest_sched_time);
          do_start_cmd();
          contest_start_time = contest_sched_time;
        }
      }
    }

    /* indicate, that we're alive, and do it somewhat quiet  */
    logger_set_level(-1, LOG_WARNING);
    update_status_file(0);
    logger_set_level(-1, 0);

    /* automatically update standings in certain situations */
    if (!global->virtual) {
      p = run_get_fog_period(time(0),
                             global->board_fog_time, global->board_unfog_time);
      if (p == 0 && !global->start_standings_updated) {
        update_standings_file(0);
      } else if (global->autoupdate_standings
                 && p == 1 && !global->fog_standings_updated) {
        update_standings_file(1);
      } else if (global->autoupdate_standings
                 && p == 2 && !global->unfog_standings_updated) {
        update_standings_file(0);
      }
    }

    /* update public log */
    update_public_log_file();
    update_external_xml_log();
    update_internal_xml_log();

    if (initialize_mode) {
      interrupt_signaled = 1;
      continue;
    }

    may_wait_flag = check_sockets(may_wait_flag);

    for (i = 0; i < compile_dirs_u; i++) {
      r = scan_dir(compile_dirs[i].status_dir, packetname);
      if (r < 0) return -1;
      if (r > 0) {
        if (read_compile_packet(compile_dirs[i].status_dir,
                                compile_dirs[i].report_dir,
                                packetname) < 0) return -1;
        may_wait_flag = 0;
      }
    }

    for (i = 0; i < run_dirs_u; i++) {
      r = scan_dir(run_dirs[i].status_dir, packetname);
      if (r < 0) return -1;
      if (!r) continue;
      if (read_run_packet(run_dirs[i].status_dir,
                          run_dirs[i].report_dir,
                          run_dirs[i].team_report_dir,
                          run_dirs[i].full_report_dir,
                          packetname) < 0) return -1;
      may_wait_flag = 0;
    }
  }
}

int
main(int argc, char *argv[])
{
  path_t  cpp_opts = { 0 };
  int     code = 0;
  int     p_flags = 0, T_flag = 0;
  int     i = 1;

  if (argc == 1) goto print_usage;
  code = 1;

  while (i < argc) {
    if (!strcmp(argv[i], "-T")) {
      i++;
      T_flag = 1;
    } else if (!strncmp(argv[i], "-D", 2)) {
      if (cpp_opts[0]) pathcat(cpp_opts, " ");
      pathcat(cpp_opts, argv[i++]);
    } else if (!strcmp(argv[i], "-f")) {
      i++;
      forced_mode = 1;
    } else if (!strcmp(argv[i], "-i")) {
      i++;
      initialize_mode = 1;
    } else if (!strncmp(argv[i], "-S", 2)) {
      int x = 0, n = 0;

      if (sscanf(argv[i] + 2, "%d%n", &x, &n) != 1
          || argv[i][n+2] || x < 0 || x > 10000) {
        err("invalid parameter for -S");
        return 1;
      }
      i++;
      cmdline_socket_fd = x;
    } else break;
  }
  if (i >= argc) goto print_usage;

  if (getuid() == 0) {
    err("sorry, will not run as the root");
    return 1;
  }

  // initialize the current time to avoid some asserts
  current_time = time(0);

  if (prepare(argv[i], p_flags, PREPARE_SERVE, cpp_opts,
              (cmdline_socket_fd >= 0)) < 0) return 1;
  if (prepare_serve_defaults() < 0) return 1;

  l10n_prepare(global->enable_l10n, global->l10n_dir);

  if (T_flag) {
    print_configuration(stdout);
    return 0;
  }
  if (create_dirs(PREPARE_SERVE) < 0) return 1;
  if (global->contest_id <= 0) {
    err("contest_id is not defined");
    return 1;
  }
  if (teamdb_open_client(global->socket_path, global->contest_id) < 0)
    return 1;
  if (run_open(global->run_log_file, 0, global->contest_time) < 0) return 1;
  if (global->virtual && global->score_system_val != SCORE_ACM) {
    err("invalid score system for virtual contest");
    return 1;
  }
  clarlog_state = clar_init();
  if (clar_open(clarlog_state, global->clar_log_file, 0) < 0) return 1;
  load_status_file();
  build_compile_dirs();
  build_run_dirs();
  i = do_loop();
  check_stat_generation(1);
  update_status_file(1);
  team_extra_flush();
  if (i < 0) i = 1;
  if (socket_name && cmdline_socket_fd < 0) {
    unlink(socket_name);
  }
  return i;

 print_usage:
  printf("Usage: %s [ OPTS ] config-file\n", argv[0]);
  printf("  -T     - print configuration and exit\n");
  printf("  -SSOCK - set a socket fd\n");
  printf("  -DDEF  - define a symbol for preprocessor\n");
  return code;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "fd_set" "tpTask")
 * End:
 */
