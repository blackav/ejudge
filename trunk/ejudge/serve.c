/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2000-2003 Alexander Chernov <cher@ispras.ru> */

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

#include "runlog.h"
#include "parsecfg.h"
#include "teamdb.h"
#include "prepare.h"
#include "html.h"
#include "clarlog.h"
#include "protocol.h"
#include "userlist.h"
#include "sha.h"
#include "l10n.h"

#include "misctext.h"
#include "base64.h"
#include "pathutl.h"
#include "fileutl.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>
#include <reuse/number_io.h>
#include <reuse/format_io.h>

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

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#include <locale.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

#define XALLOCAZ(p,s) (XALLOCA((p),(s)),XMEMZERO((p),(s)))

#define PACKET_NAME_SIZE 12

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
  unsigned long long cookie;
  unsigned long ip;

  // passed file descriptors
  int client_fds[2];
};
static struct client_state *client_first;
static struct client_state *client_last;
static int                  client_serial_id = 1;

static int cmdline_socket_fd = -1;
static time_t last_activity_time = 0;

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

static unsigned long current_time;

static unsigned long contest_start_time;
static unsigned long contest_sched_time;
static unsigned long contest_duration;
static unsigned long contest_stop_time;
static int clients_suspended;
static int olympiad_judging_mode;

static int socket_fd = -1;
static unsigned char *socket_name = 0;
static int interrupt_signaled = 0;

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
  write_standings(global->status_dir, global->standings_file_name,
                  global->stand_header_txt, global->stand_footer_txt);
  if (global->stand2_file_name[0]) {
    write_standings(global->status_dir, global->stand2_file_name,
                    global->stand2_header_txt, global->stand2_footer_txt);
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

static int
update_status_file(int force_flag)
{
  static time_t prev_status_update = 0;
  struct prot_serve_status status;
  int p;

  if (!force_flag && current_time <= prev_status_update) return 0;

  memset(&status, 0, sizeof(status));
  status.magic = PROT_SERVE_STATUS_MAGIC;

  status.cur_time = current_time;
  run_get_times(&status.start_time,
                &status.sched_time,
                &status.duration,
                &status.stop_time);
  status.total_runs = run_get_total();
  status.total_clars = clar_get_total();
  status.clars_disabled = global->disable_clars;
  status.team_clars_disabled = global->disable_team_clars;
  status.score_system = global->score_system_val;
  status.clients_suspended = clients_suspended;
  status.download_interval = global->team_download_time / 60;
  status.is_virtual = global->virtual;
  status.olympiad_judging_mode = olympiad_judging_mode;
  status.continuation_enabled = global->enable_continue;
  if (status.duration) status.continuation_enabled = 0;

  if (!global->virtual) {
    p = run_get_fog_period(current_time,
                           global->board_fog_time, global->board_unfog_time);
    if (p == 1 && global->autoupdate_standings) {
      status.standings_frozen = 1;
    }
  }

  generic_write_file((char*) &status, sizeof(status), SAFE,
                     global->status_dir, "status", "");
  prev_status_update = current_time;
  return 1;
}

static int
check_cnts_caps(int user_id, int bit)
{
  struct contest_desc *cnts = 0;
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
  unsigned long total;

  if (size > global->max_clar_size) return -1;
  clar_get_team_usage(teamid, &num, &total);
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
      return 1;
    case RUN_COMPILE_ERR:
    case RUN_REJUDGE:
    case RUN_IGNORED:
      if (mode != 1) return 0;
      return 1;
    default:
      return 0;
    }
  } else if (global->score_system_val == SCORE_KIROV) {
    switch (status) {
    case RUN_OK:
    case RUN_PARTIAL:
      return 1;
    case RUN_COMPILE_ERR:
    case RUN_REJUDGE:
    case RUN_IGNORED:
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
      return 1;
    case RUN_COMPILE_ERR:
    case RUN_REJUDGE:
    case RUN_IGNORED:
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
  unsigned long long cookie = 0;
  unsigned long ip = 0;
  int user_id = 0, priv_level = 0;
  int r;

  if (p->user_id >= 0) return p->user_id;
  r = teamdb_get_uid_by_pid(p->peer_uid, p->peer_gid, p->peer_pid,
                            &user_id, &priv_level, &cookie, &ip);
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

static void
cmd_team_get_archive(struct client_state *p, int len,
                     struct prot_serve_pkt_get_archive *pkt)
{
  time_t last_time;
  path_t dirname, fullpath, linkpath, origpath;
  int total_runs, r, run_team, run_lang, run_prob, token, path_len, out_size;
  struct prot_serve_pkt_archive_path *out;

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
    if (run_get_record(r,0,0,0,0,0,&run_team,&run_lang,&run_prob,0,0,0) < 0)
      continue;
    if (run_team != pkt->user_id) continue;
    snprintf(linkpath, sizeof(linkpath), "%s/%s_%06d%s",
             fullpath, probs[run_prob]->short_name, r,
             langs[run_lang]->src_sfx);
    snprintf(origpath, sizeof(origpath), "%s/%06d", global->run_archive_dir,
             r);
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
  unsigned char *html_ptr = 0;
  size_t html_len = 0;

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

  info("%d: cmd_team_page: %d, %d", p->id, pkt->sid_mode, pkt->locale_id);

  if (p->client_fds[0] < 0 || p->client_fds[1] < 0) {
    err("%d: two client file descriptors required", p->id);
    new_send_reply(p, -SRV_ERR_PROTOCOL);
    return;
  }

  if (!(f = open_memstream((char**) &html_ptr, &html_len))) {
    err("%d: open_memstream failed", p->id);
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  l10n_setlocale(pkt->locale_id);
  write_team_page(f, p->user_id,
                  pkt->sid_mode, p->cookie,
                  (pkt->flags & 1), (pkt->flags & 2) >> 1,
                  self_url_ptr, hidden_vars_ptr, extra_args_ptr,
                  contest_start_time, contest_stop_time);
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

static void
cmd_master_page(struct client_state *p, int len,
                struct prot_serve_pkt_master_page *pkt)
{
  unsigned char *self_url_ptr, *filter_expr_ptr, *hidden_vars_ptr;
  unsigned char *extra_args_ptr;
  FILE *f;
  unsigned char *html_ptr = 0;
  size_t html_len = 0;
  struct client_state *q;

  if (get_peer_local_user(p) < 0) return;

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
       p->id, pkt->user_id, pkt->contest_id, pkt->locale_id);

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
  if (p->priv_level < PRIV_LEVEL_OBSERVER) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: unsifficient privilege level", p->id);
    return;
  }
  if (p->priv_level < pkt->priv_level) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: priv_level does not match", p->id);
    return;
  }
  if (pkt->sid_mode < 0 || pkt->sid_mode > 3) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: sid_mode %d is invalid", p->id, pkt->sid_mode);
    return;
  }

  if (!(f = open_memstream((char**) &html_ptr, &html_len))) {
    err("%d: open_memstream failed", p->id);
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  /* l10n_setlocale(pkt->locale_id); */
  write_master_page(f, p->user_id, pkt->priv_level,
                    pkt->sid_mode, p->cookie,
                    pkt->first_run, pkt->last_run,
                    pkt->first_clar, pkt->last_clar,
                    self_url_ptr, filter_expr_ptr, hidden_vars_ptr,
                    extra_args_ptr);
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

  info("%d: cmd_master_page: ok %d", p->id, html_len);
  new_send_reply(p, SRV_RPL_OK);
}

static void
cmd_priv_standings(struct client_state *p, int len,
                   struct prot_serve_pkt_standings *pkt)
{
  unsigned char *self_url_ptr, *hidden_vars_ptr, *extra_args_ptr;
  FILE *f;
  unsigned char *html_ptr = 0;
  size_t html_len = 0;
  struct client_state *q;

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

  info("%d: priv_standings: %d, %d",
       p->id, pkt->user_id, pkt->sid_mode);

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
  if (p->priv_level < PRIV_LEVEL_OBSERVER) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: unsifficient privilege level", p->id);
    return;
  }
  if (p->priv_level < pkt->priv_level) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: priv_level does not match", p->id);
    return;
  }
  if (pkt->sid_mode < 0 || pkt->sid_mode > 3) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: sid_mode %d is invalid", p->id, pkt->sid_mode);
    return;
  }
  if (!check_cnts_caps(p->user_id, OPCAP_VIEW_STANDINGS)) {
    err("%d: user %d has no capability %d for the contest",
        p->id, p->user_id, OPCAP_VIEW_STANDINGS);
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    return;
  }

  if (!(f = open_memstream((char**) &html_ptr, &html_len))) {
    err("%d: open_memstream failed", p->id);
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  /* l10n_setlocale(pkt->locale_id); */
  write_priv_standings(f, pkt->sid_mode, p->cookie,
                       self_url_ptr, hidden_vars_ptr, extra_args_ptr);
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

  info("%d: priv_standings: ok %d", p->id, html_len);
  new_send_reply(p, SRV_RPL_OK);
}

static void
cmd_view(struct client_state *p, int len,
         struct prot_serve_pkt_view *pkt)
{
  unsigned char *self_url_ptr, *hidden_vars_ptr, *extra_args_ptr;
  unsigned char *html_ptr = 0;
  size_t html_len = 0;
  struct client_state *q;
  int r = 0;
  FILE *f;

  if (get_peer_local_user(p) < 0) return;

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

  info("%d: view %d, %d, %d", p->id, pkt->b.id, pkt->item, pkt->sid_mode);
  if (pkt->sid_mode < 0 || pkt->sid_mode > 3) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: sid_mode %d is invalid", p->id, pkt->sid_mode);
    return;
  }

  if (!(f = open_memstream((char**) &html_ptr, &html_len))) {
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

    if (!check_cnts_caps(p->user_id, OPCAP_VIEW_SOURCE)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_VIEW_SOURCE);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    r = write_priv_source(f, p->user_id, p->priv_level,
                          pkt->sid_mode, p->cookie,
                          self_url_ptr, hidden_vars_ptr,
                          extra_args_ptr, pkt->item);
    break;
  case SRV_CMD_VIEW_REPORT:
    if (!p->priv_level) {
      err("%d: report view for unprivileged users not yet supported", p->id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (!check_cnts_caps(p->user_id, OPCAP_VIEW_REPORT)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_VIEW_REPORT);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    r = write_priv_report(f, p->user_id, p->priv_level,
                          pkt->sid_mode, p->cookie,
                          self_url_ptr, hidden_vars_ptr, extra_args_ptr,
                          pkt->item);
    break;
  case SRV_CMD_VIEW_CLAR:
    if (!p->priv_level) {
      err("%d: clar view for unprivileged users not yet supported", p->id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (!check_cnts_caps(p->user_id, OPCAP_VIEW_CLAR)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_VIEW_CLAR);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    r = write_priv_clar(f, p->user_id, p->priv_level,
                        pkt->sid_mode, p->cookie,
                        self_url_ptr, hidden_vars_ptr, extra_args_ptr,
                        pkt->item);
    if (p->priv_level == PRIV_LEVEL_JUDGE) {
      int flags = 1;

      clar_get_record(pkt->item, 0, 0, 0, 0, 0, &flags, 0);
      if (!flags) {
        flags = 1;
        clar_update_flags(pkt->item, flags);
      }
    }
    break;
  case SRV_CMD_VIEW_USERS:
    if (!p->priv_level) {
      err("%d: unprivileged users cannot view teams", p->id);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    if (!check_cnts_caps(p->user_id, OPCAP_LIST_CONTEST_USERS)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_LIST_CONTEST_USERS);
      r = -SRV_ERR_NO_PERMS;
      break;
    }

    r = write_priv_users(f, p->user_id, p->priv_level,
                         pkt->sid_mode, p->cookie,
                         self_url_ptr, hidden_vars_ptr, extra_args_ptr);
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

    write_runs_dump(f, global->charset);
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

    write_raw_standings(f, global->charset);
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

  info("%d: view: ok %d", p->id, html_len);
  new_send_reply(p, SRV_RPL_OK);
}

static void
cmd_message(struct client_state *p, int len,
            struct prot_serve_pkt_submit_clar *pkt)
{
  unsigned char const *dest_login_ptr, *subj_ptr, *text_ptr;
  int dest_uid;
  unsigned char txt_subj_short[CLAR_MAX_SUBJ_TXT_LEN + 10];
  unsigned char b64_subj_short[CLAR_MAX_SUBJ_LEN + 10];
  unsigned char *msg, *orig_txt, *quoted_ptr, *new_subj;
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
  switch (pkt->b.id) {
  case SRV_CMD_PRIV_MSG:
    if (p->priv_level <= PRIV_LEVEL_OBSERVER) {
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
    clar_id = clar_add_record(current_time, msg_len,
                              run_unparse_ip(p->ip),
                              0, dest_uid, 0, b64_subj_short);
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

    info("%d: cmd_message: ok %d %d", p->id, clar_id, msg_len);
    new_send_reply(p, SRV_RPL_OK);
    return;

  case SRV_CMD_PRIV_REPLY:
    if (p->priv_level <= PRIV_LEVEL_OBSERVER) {
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
    if (clar_get_record(pkt->ref_clar_id, 0, 0, 0, &dest_uid, 0, 0, 0) < 0) {
      err("%d: invalid ref_clar_id %d", p->id, pkt->ref_clar_id);
      new_send_reply(p, -SRV_ERR_BAD_CLAR_ID);
      return;
    }
    snprintf(orig_clar_name, sizeof(orig_clar_name), "%06d", pkt->ref_clar_id);
    orig_txt = 0;
    orig_txt_len = 0;
    if (generic_read_file((char**) &orig_txt, 0, &orig_txt_len, 0,
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
    clar_id = clar_add_record(current_time, msg_len,
                              run_unparse_ip(p->ip), 0, dest_uid, 0,
                              b64_subj_short);
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
    clar_update_flags(pkt->ref_clar_id, 2);
    xfree(orig_txt);
    info("%d: cmd_message: ok %d %d", p->id, clar_id, msg_len);
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
  unsigned char *html_ptr = 0;
  size_t html_len = 0;
  struct client_state *q;
  int r;

  if (get_peer_local_user(p) < 0) return;

  if (len != sizeof(*pkt)) {
    new_bad_packet(p, "cmd_team_show_item: bad packet length: %d", len);
    return;
  }
  if (pkt->b.id != SRV_CMD_SHOW_CLAR
      && pkt->b.id != SRV_CMD_SHOW_REPORT
      && pkt->b.id != SRV_CMD_VIRTUAL_STANDINGS
      && pkt->b.id != SRV_CMD_SHOW_SOURCE) {
    new_bad_packet(p, "cmd_team_show_item: bad command: %d", pkt->b.id);
    return;
  }
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

  if (!(f = open_memstream((char**) &html_ptr, &html_len))) {
    err("%d: open_memstream failed", p->id);
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  l10n_setlocale(pkt->locale_id);
  switch (pkt->b.id) {
  case SRV_CMD_SHOW_CLAR:
    r = new_write_user_clar(f, pkt->user_id, pkt->item_id);
    break;
  case SRV_CMD_SHOW_SOURCE:
    r = new_write_user_source_view(f, pkt->user_id, pkt->item_id);
    break;
  case SRV_CMD_SHOW_REPORT:
    r = new_write_user_report_view(f, pkt->user_id, pkt->item_id);
    break;
  case SRV_CMD_VIRTUAL_STANDINGS:
    if (!global->virtual) r = -SRV_ERR_ONLY_VIRTUAL;
    else r = write_virtual_standings(f, pkt->user_id);
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

static int queue_compile_request(unsigned char const *str, int len,
                                 int run_id, int lang_id, int locale_id,
                                 unsigned char const *sfx);

static void
cmd_team_submit_run(struct client_state *p, int len, 
                    struct prot_serve_pkt_submit_run *pkt)
{
  int run_id, r;
  path_t run_name, run_full;
  unsigned long shaval[5];
  time_t start_time, stop_time;

  if (get_peer_local_user(p) < 0) return;

  if (len < sizeof(*pkt)) {
    new_bad_packet(p, "team_submit_run: packet is too small: %d", len);
    return;
  }
  if (pkt->run_len != strlen(pkt->data)) {
    new_bad_packet(p, "team_submit_run: run_len does not match");
    return;
  }
  if (len != sizeof(*pkt) + pkt->run_len) {
    new_bad_packet(p, "team_submit_run: packet length does not match");
    return;
  }

  info("%d: team_submit_run: %d, %d, %d, %d, %d",
       p->id, pkt->user_id, pkt->contest_id, pkt->locale_id,
       pkt->prob_id, pkt->lang_id);
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
  if (pkt->prob_id < 1 || pkt->prob_id > max_prob || !probs[pkt->prob_id]) {
    err("%d: prob_id is invalid", p->id);
    new_send_reply(p, -SRV_ERR_BAD_PROB_ID);
    return;
  }
  if (pkt->lang_id < 1 || pkt->lang_id > max_lang || !langs[pkt->lang_id]
      || langs[pkt->lang_id]->disabled) {
    err("%d: lang_id is invalid", p->id);
    new_send_reply(p, -SRV_ERR_BAD_LANG_ID);
    return;
  }
  if (p->user_id && pkt->user_id != p->user_id) {
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    err("%d: pkt->user_id != p->user_id", p->id);
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
  if (check_team_quota(pkt->user_id, pkt->run_len) < 0) {
    err("%d: user quota exceeded", p->id);
    new_send_reply(p, -SRV_ERR_QUOTA_EXCEEDED);
    return;
  }
  sha_buffer(pkt->data, pkt->run_len, shaval);
  if ((run_id = run_add_record(current_time,
                               pkt->run_len,
                               shaval,
                               pkt->ip,
                               pkt->locale_id,
                               pkt->user_id,
                               pkt->prob_id,
                               pkt->lang_id)) < 0){
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }

  sprintf(run_name, "%06d", run_id);
  sprintf(run_full, "%06d%s", run_id, langs[pkt->lang_id]->src_sfx);
  if (generic_write_file(pkt->data, pkt->run_len, 0,
                         global->run_archive_dir, run_name, "") < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }

  if (global->ignore_duplicated_runs) {
    if ((r = run_check_duplicate(run_id)) < 0) {
      new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
      return;
    } else if (r) {
      info("%d: team_submit_run: duplicated run, match %d", p->id, r - 1);
      new_send_reply(p, -SRV_ERR_DUPLICATED_RUN);
      return;
    }
  }

  if (queue_compile_request(pkt->data, pkt->run_len, run_id,
                            langs[pkt->lang_id]->compile_id,
                            pkt->locale_id,
                            langs[pkt->lang_id]->src_sfx) < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  if (run_change_status(run_id, RUN_COMPILING, 0, -1) < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }

  info("%d: team_submit_run: ok", p->id);
  new_send_reply(p, SRV_RPL_OK);
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

  if ((clar_id = clar_add_record(current_time, full_len,
                                 run_unparse_ip(pkt->ip),
                                 pkt->user_id, 0, 0, bsubj)) < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  sprintf(clar_name, "%06d", clar_id);
  if (generic_write_file(full_txt, full_len, 0,
                         global->clar_archive_dir, clar_name, "") < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }

  info("%d: team_submit_clar: ok", p->id);
  new_send_reply(p, SRV_RPL_OK);
}

static void
cmd_command_0(struct client_state *p, int len,
              struct prot_serve_pkt_simple *pkt)
{
  time_t start_time, stop_time;

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
    run_virtual_start(p->user_id, current_time, p->ip);
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
    run_virtual_stop(p->user_id, current_time, p->ip);
    info("%d: virtual contest stopped for %d", p->id, p->user_id);
    new_send_reply(p, SRV_RPL_OK);
    return;
  default:
    err("%d: unhandled command", p->id);
    new_send_reply(p, -SRV_ERR_PROTOCOL);
  }
}

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

  if (p->priv_level < PRIV_LEVEL_OBSERVER) {
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

static void do_rejudge_all(void);
static void do_rejudge_problem(int);

static int
do_rename(unsigned char const *base, int from, int to)
{
  path_t fromp, top;
  struct stat s;

  snprintf(fromp, sizeof(fromp), "%s/%06d", base, from);
  snprintf(top, sizeof(top), "%s/%06d", base, to);
  if (lstat(top, &s) >= 0) {
    if (unlink(top) < 0) {
      err("cannot unlink %s: %s", fromp, os_ErrorMsg());
      return -1;
    }
  }
  if (rename(fromp, top) < 0) {
    err("cannot rename %s -> %s: %s", fromp, top, os_ErrorMsg());
    return -1;
  }
  return 0;
}

static int
do_remove_archive_entry(unsigned char const *base, int n)
{
  path_t s;

  snprintf(s, sizeof(s), "%s/%06d", base, n);
  unlink(s);
  return 0;
}

static void
do_squeeze_runs(void)
{
  int i, j, tot;

  tot = run_get_total();
  for (i = 0, j = 0; i < tot; i++) {
    if (run_get_status(i) == RUN_EMPTY) continue;
    if (i != j) {
      do_rename(global->run_archive_dir, i, j);
      do_rename(global->report_archive_dir, i, j);
      if (global->team_enable_rep_view) {
        do_rename(global->team_report_archive_dir, i, j);
      }
    }
    j++;
  }
  for (; j < tot; j++) {
    do_remove_archive_entry(global->run_archive_dir, j);
    do_remove_archive_entry(global->report_archive_dir, j);
    if (global->team_enable_rep_view) {
      do_remove_archive_entry(global->team_report_archive_dir, j);
    }
  }
  run_squeeze_log();
}

static void
cmd_priv_command_0(struct client_state *p, int len,
                   struct prot_serve_pkt_simple *pkt)
{
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
    if (!contest_stop_time) {
      new_send_reply(p, -SRV_ERR_CONTEST_NOT_FINISHED);
      return;
    }
    olympiad_judging_mode = 1;
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
  case SRV_CMD_RESET:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
      new_send_reply(p, -SRV_ERR_NO_PERMS);
      return;
    }

    /* FIXME: we need to reset all the components (compile, serve) as well */
    /* reset run log */
    run_reset();
    contest_duration = global->contest_time;
    run_set_duration(contest_duration);
    clar_reset();
    /* clear all submissions and clarifications */
    clear_directory(global->clar_archive_dir);
    clear_directory(global->report_archive_dir);
    clear_directory(global->run_archive_dir);
    clear_directory(global->team_report_archive_dir);
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

    do_rejudge_all();
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
    do_rejudge_problem(pkt->v.i);
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

    if (contest_stop_time) {
      err("%d: contest already finished", p->id);
      new_send_reply(p, -SRV_ERR_CONTEST_FINISHED);
      return;
    }
    if (pkt->v.t < 0 || pkt->v.t > 1000000) {
      err("%d: invalid duration: %ld", p->id, pkt->v.t);
      new_send_reply(p, -SRV_ERR_BAD_DURATION);
      return;
    }
    if (pkt->v.t * 60 < global->contest_time) {
      err("%d: duration cannot be decreased", p->id);
      new_send_reply(p, -SRV_ERR_BAD_DURATION);
      return;
    }
    contest_duration = pkt->v.t * 60;
    run_set_duration(contest_duration);
    info("contest time reset to %ld", pkt->v.t);
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
    if (run_clear_entry(pkt->v.i) < 0) {
      new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
      return;
    }
    info("%d: run %d is cleared", p->id, pkt->v.i);
    new_send_reply(p, SRV_RPL_OK);
    return;

  case SRV_CMD_CONTINUE:
    if (!check_cnts_caps(p->user_id, OPCAP_CONTROL_CONTEST)) {
      err("%d: user %d has no capability %d for the contest",
          p->id, p->user_id, OPCAP_CONTROL_CONTEST);
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
    if (contest_duration) {
      err("%d: duration cannot be limited", p->id);
      new_send_reply(p, -SRV_ERR_BAD_DURATION);
      return;
    }
    contest_stop_time = 0;
    run_stop_contest(0);
    update_status_file(1);
    new_send_reply(p, SRV_RPL_OK);
    return;

  default:
    err("%d: unhandled command", p->id);
    new_send_reply(p, -SRV_ERR_PROTOCOL);
  }
}

static void rejudge_run(int);

static void
cmd_edit_run(struct client_state *p, int len,
             struct prot_serve_pkt_run_info *pkt)
{
  unsigned char const *user_login_ptr;
  struct run_entry run;
  unsigned int run_flags = 0;

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
  if (len != sizeof(*pkt) + pkt->user_login_len) {
    new_bad_packet(p, "edit_run: packet length mismatch");
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

  // check capabilities
  if (!check_cnts_caps(p->user_id, OPCAP_EDIT_RUN)
      && (run_flags != RUN_ENTRY_STATUS || run.status != RUN_REJUDGE
          || !check_cnts_caps(p->user_id, OPCAP_REJUDGE_RUN))) {
    err("%d: user %d has no capability to edit run", p->id, p->user_id);
    new_send_reply(p, -SRV_ERR_NO_PERMS);
    return;
  }

  if (run_set_entry(pkt->run_id, run_flags, &run) < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }

  if ((run_flags & RUN_ENTRY_STATUS) && run.status == RUN_REJUDGE) {
    rejudge_run(pkt->run_id);
  }
  info("%d: edit_run: ok", p->id);
  new_send_reply(p, SRV_RPL_OK);
  return;
}

static void generate_packet_name(int run_id,
                                 unsigned char buf[PACKET_NAME_SIZE]);

static int
read_compile_packet(char *pname)
{
  unsigned char buf[256];
  unsigned char pkt_base[PACKET_NAME_SIZE];
  unsigned char exe_in_name[128];
  unsigned char exe_out_name[128];

  int  r, n;
  int  rsize, wsize;
  int  code;
  int  runid;
  int  cn;

  int  lang, prob, stat, loc, final_test;

  char *pbuf = buf;

  memset(buf, 0, sizeof(buf));
  r = generic_read_file(&pbuf, sizeof(buf), &rsize, SAFE|REMOVE,
                        global->compile_status_dir, pname, "");
  if (r == 0) return 0;
  if (r < 0) return -1;

  info("compile packet: %s", chop(buf));
  if (sscanf(pname, "%d%n", &runid, &n) != 1 || pname[n])
    goto bad_packet_error;
  if (sscanf(buf, "%d %n", &code, &n) != 1 || buf[n])
    goto bad_packet_error;
  if (run_get_param(runid, &loc, &lang, &prob, &stat) < 0)
    goto bad_packet_error;
  if (stat != RUN_COMPILING) goto bad_packet_error;
  if (code != RUN_OK && code != RUN_COMPILE_ERR && code != RUN_CHECK_FAILED)
    goto bad_packet_error;
  if (code == RUN_CHECK_FAILED) {
    if (run_change_status(runid, RUN_CHECK_FAILED, 0, -1) < 0) return -1;
    if (generic_copy_file(REMOVE, global->compile_report_dir, pname, "",
                          0, global->report_archive_dir, pname, "") < 0)
      return -1;
    return 1;
  }
  if (code == RUN_COMPILE_ERR) {
    /* compilation error */
    if (run_change_status(runid, RUN_COMPILE_ERR, 0, -1) < 0) return -1;
    /* probably we need a user's copy of compilation log */
    if (global->team_enable_rep_view) {
      if (generic_copy_file(0, global->compile_report_dir, pname, "",
                            0, global->team_report_archive_dir, pname, "") < 0)
        return -1;
    }
    if (generic_copy_file(REMOVE, global->compile_report_dir, pname, "",
                          0, global->report_archive_dir, pname, "") < 0)
      return -1;
    update_standings_file(0);
    return 1;
  }
  if (run_change_status(runid, RUN_COMPILED, 0, -1) < 0) return -1;

  /* find appropriate checker */
  cn = find_tester(prob, langs[lang]->arch);
  ASSERT(cn >= 1 && cn <= max_tester && testers[cn]);

  /* generate a packet name */
  generate_packet_name(runid, pkt_base);
  snprintf(exe_in_name, sizeof(exe_in_name),
           "%06d%s", runid, langs[lang]->exe_sfx);
  snprintf(exe_out_name, sizeof(exe_out_name),
           "%s%s", pkt_base, langs[lang]->exe_sfx);

  /* copy the executable into the testers's queue */
  if (generic_copy_file(REMOVE, global->compile_report_dir, exe_in_name, "",
                        0, global->run_exe_dir, exe_out_name, "") < 0)
    return -1;

  final_test = 0;
  if (global->score_system_val == SCORE_OLYMPIAD
      && !olympiad_judging_mode) final_test = 1;

  /* create tester packet */
  wsize = snprintf(buf, sizeof(buf),
                   "%d %d %d %d %d %d %d %d \"%s\" \"%s\"\n",
                   global->contest_id, runid, probs[prob]->tester_id,
                   final_test, loc,
                   global->score_system_val,
                   global->team_enable_rep_view,
                   global->report_error_code,
                   langs[lang]->exe_sfx, langs[lang]->arch);
  if (generic_write_file(buf, wsize, SAFE, global->run_queue_dir,
                         pkt_base, "") < 0)
    return -1;

  /* update status */
  if (run_change_status(runid, RUN_RUNNING, 0, -1) < 0) return -1;

  return 1;

 bad_packet_error:
  err("bad_packet");
  return 0;
}

static int
read_run_packet(char *pname)
{
  char  buf[256];
  char *pbuf = buf;
  int   r, rsize, n;

  int   runid;
  int   status;
  int   test;
  int   score;

  int   log_stat, log_prob, log_lang;

  memset(buf, 0 ,sizeof(buf));
  r = generic_read_file(&pbuf, sizeof(buf), &rsize, SAFE|REMOVE,
                        global->run_status_dir, pname, "");
  if (r < 0) return -1;
  if (r == 0) return 0;

  info("run packet: %s", chop(buf));
  if (sscanf(pname, "%d%n", &runid, &n) != 1 || pname[n])
    goto bad_packet_error;
  if (sscanf(buf, "%d%d%d %n", &status, &test, &score, &n) != 3 || buf[n])
    goto bad_packet_error;
  if (run_get_param(runid, 0, &log_lang, &log_prob, &log_stat) < 0)
    goto bad_packet_error;
  if (log_stat != RUN_RUNNING) goto bad_packet_error;
  if (status<0 || status>RUN_ACCEPTED || test<0) goto bad_packet_error;
  if (global->score_system_val == SCORE_OLYMPIAD) {
    if (log_prob < 1 || log_prob > max_prob || !probs[log_prob])
      goto bad_packet_error;
  } else if (global->score_system_val == SCORE_KIROV) {
    if (status != RUN_PARTIAL && status != RUN_OK
        && status != RUN_CHECK_FAILED) goto bad_packet_error;
    if (log_prob < 1 || log_prob > max_prob || !probs[log_prob])
      goto bad_packet_error;
    if (score < 0 || score > probs[log_prob]->full_score)
      goto bad_packet_error;
  } else {
    score = -1;
  }
  if (run_change_status(runid, status, test, score) < 0) return -1;
  update_standings_file(0);
  if (generic_copy_file(REMOVE, global->run_report_dir, pname, "",
                        0, global->report_archive_dir, pname, "") < 0)
    return -1;
  if (global->team_enable_rep_view) {
    if (generic_copy_file(REMOVE, global->run_team_report_dir, pname, "",
                          0, global->team_report_archive_dir, pname, "") < 0)
      return -1;
  }
  return 1;

 bad_packet_error:
  err("bad_packet");
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
generate_packet_name(int run_id, unsigned char buf[PACKET_NAME_SIZE])
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
}

static int
queue_compile_request(unsigned char const *str, int len,
                      int run_id, int lang_id, int locale_id,
                      unsigned char const *sfx)
{
  unsigned char pkt_buf[1024];
  unsigned char pkt_name[PACKET_NAME_SIZE];
  unsigned char run_name[64];
  int pkt_len;

  if (!sfx) sfx = "";
  generate_packet_name(run_id, pkt_name);
  snprintf(run_name, sizeof(run_name), "%06d", run_id);
  pkt_len = snprintf(pkt_buf, sizeof(pkt_buf),
                     "%d %d %d %d\n",
                     global->contest_id, run_id,
                     lang_id, locale_id);

  if (len == -1) {
    // copy from archive
    if (generic_copy_file(0, global->run_archive_dir, run_name, "",
                          0, global->compile_src_dir, pkt_name, sfx) < 0)
      return -1;
  } else {
    // write from memory
    if (generic_write_file(str, len, 0,
                           global->compile_src_dir, pkt_name, sfx) < 0)
      return -1;
  }

  if (generic_write_file(pkt_buf, pkt_len, SAFE,
                         global->compile_queue_dir, pkt_name, "") < 0) {
    return -1;
  }
  return 0;
}

static void
rejudge_run(int run_id)
{
  int lang, loc;
  path_t src_path;

  if (run_get_record(run_id, 0, 0, 0, 0, &loc, 0, &lang, 0, 0, 0, 0) < 0)
    return;
  if (lang <= 0 || lang > max_lang || !langs[lang]) {
    err("rejudge_run: bad language: %d", lang);
    return;
  }

  snprintf(src_path, sizeof(src_path), "%s/%06d",
           global->run_archive_dir, run_id);
  queue_compile_request(src_path, -1, run_id,
                        langs[lang]->compile_id, loc, langs[lang]->src_sfx);

  run_change_status(run_id, RUN_COMPILING, 0, -1);
}

static void
do_rejudge_all(void)
{
  int total_runs, r;
  int status;

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
    struct run_entry entry;

    if (total_ids <= 0 || total_probs <= 0) return;
    flag = (unsigned char *) alloca(size);
    memset(flag, 0, size);
    for (r = total_runs - 1; r >= 0; r--) {
      if (run_get_entry(r, &entry) < 0) continue;
      if (entry.status != RUN_OK && entry.status != RUN_PARTIAL
          && entry.status != RUN_ACCEPTED) continue;
      if (entry.team <= 0 || entry.team >= total_ids) continue;
      if (entry.problem <= 0 || entry.problem >= total_probs) {
        fprintf(stderr, "Invalid problem %d for run %d", entry.problem, r);
        continue;
      }
      idx = entry.team * total_probs + entry.problem;
      if (flag[idx]) continue;
      flag[idx] = 1;
      rejudge_run(r);
    }
    return;
  }

  for (r = 0; r < total_runs; r++) {
    if (run_get_record(r, 0, 0, 0, 0, 0, 0, 0, 0, &status, 0, 0) >= 0
        && status >= RUN_OK && status <= RUN_MAX_STATUS
        && status != RUN_IGNORED) {
      rejudge_run(r);
    }
  }
}

static void
do_rejudge_problem(int prob_id)
{
  int total_runs, r, status, prob;

  total_runs = run_get_total();

  if (global->score_system_val == SCORE_OLYMPIAD
      && olympiad_judging_mode) {
    // rejudge only "ACCEPTED", "OK", "PARTIAL SOLUTION" runs,
    // considering only the last run for the given participant
    int total_ids = teamdb_get_max_team_id() + 1;
    unsigned char *flag;
    struct run_entry entry;

    if (total_ids <= 0) return;
    flag = (unsigned char *) alloca(total_ids);
    memset(flag, 0, total_ids);
    for (r = total_runs - 1; r >= 0; r--) {
      if (run_get_entry(r, &entry) < 0) continue;
      if (entry.status != RUN_OK && entry.status != RUN_PARTIAL
          && entry.status != RUN_ACCEPTED) continue;
      if (entry.problem != prob_id) continue;
      if (entry.team <= 0 || entry.team >= total_ids) continue;
      if (flag[entry.team]) continue;
      flag[entry.team] = 1;
      rejudge_run(r);
    }
    return;
  }

  for (r = 0; r < total_runs; r++) {
    if (run_get_record(r, 0, 0, 0, 0, 0, 0, 0, &prob, &status, 0, 0) >= 0
        && prob == prob_id && status >= RUN_OK && status <= RUN_MAX_STATUS
        && status != RUN_IGNORED) {
      rejudge_run(r);
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
  [SRV_CMD_SHOW_REPORT] { cmd_team_show_item },
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
  [SRV_CMD_UPDATE_STAND] { cmd_priv_command_0 },
  [SRV_CMD_START] { cmd_priv_command_0 },
  [SRV_CMD_STOP] { cmd_priv_command_0 },
  [SRV_CMD_RESET] { cmd_priv_command_0 },
  [SRV_CMD_REJUDGE_ALL] { cmd_priv_command_0 },
  [SRV_CMD_REJUDGE_PROBLEM] { cmd_priv_command_0 },
  [SRV_CMD_SCHEDULE] { cmd_priv_command_0 },
  [SRV_CMD_DURATION] { cmd_priv_command_0 },
  [SRV_CMD_EDIT_RUN] { cmd_edit_run },
  [SRV_CMD_VIRTUAL_START] { cmd_command_0 },
  [SRV_CMD_VIRTUAL_STOP] { cmd_command_0 },
  [SRV_CMD_VIRTUAL_STANDINGS] { cmd_team_show_item },
  [SRV_CMD_RESET_FILTER] { cmd_judge_command_0 },
  [SRV_CMD_CLEAR_RUN] { cmd_priv_command_0 },
  [SRV_CMD_SQUEEZE_RUNS] { cmd_priv_command_0 },
  [SRV_CMD_DUMP_RUNS] { cmd_view },
  [SRV_CMD_DUMP_STANDINGS] { cmd_view },
  [SRV_CMD_SET_JUDGING_MODE] { cmd_priv_command_0 },
  [SRV_CMD_CONTINUE] { cmd_priv_command_0 },
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
      err("accept failed: %s", os_ErrorMsg());
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
        err("%d: read() failed: %s", p->id, os_ErrorMsg());
        client_disconnect(p, 1);
        continue;
      }

      p->read_state += l;
      memcpy(&p->expected_len, rbuf, 4);
      if (p->read_state == 4) {
        if (p->expected_len <= 0 || p->expected_len > 128 * 1024) {
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
do_loop(void)
{
  path_t packetname;
  int    r, p;
  int    may_wait_flag = 0;

  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, interrupt_signal);
  signal(SIGTERM, interrupt_signal);
  if (create_socket() < 0) return -1;

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
  if (!contest_duration) {
    contest_duration = global->contest_time;
    run_set_duration(contest_duration);
  }

  while (1) {
    /* update current time */
    current_time = time(0);

    if (interrupt_signaled && may_safely_exit()) {
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

    /* check stop and start times */
    if (!global->virtual) {
      if (contest_start_time && !contest_stop_time && contest_duration) {
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
          run_start_contest(current_time);
          contest_start_time = current_time;
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

    may_wait_flag = check_sockets(may_wait_flag);

    r = scan_dir(global->compile_status_dir, packetname);
    if (r < 0) return -1;
    if (r > 0) {
      if (read_compile_packet(packetname) < 0) return -1;
      may_wait_flag = 0;
    }

    r = scan_dir(global->run_status_dir, packetname);
    if (r < 0) return -1;
    if (r > 0) {
      if (read_run_packet(packetname) < 0) return -1;
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
    } else if (!strcmp(argv[i], "-E")) {
      i++;
      p_flags |= PREPARE_USE_CPP;
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

  if (prepare(argv[i], p_flags, PREPARE_SERVE, cpp_opts) < 0) return 1;

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
  if (run_open(global->run_log_file, 0) < 0) return 1;
  if (global->virtual && global->score_system_val != SCORE_ACM) {
    err("invalid score system for virtual contest");
    return 1;
  }
  if (global->virtual && run_build_virtual_table() < 0) return 1;
  if (clar_open(global->clar_log_file, 0) < 0) return 1;
  i = do_loop();
  if (i < 0) i = 1;
  if (socket_name && cmdline_socket_fd < 0) {
    unlink(socket_name);
  }
  return i;

 print_usage:
  printf("Usage: %s [ OPTS ] config-file\n", argv[0]);
  printf("  -T     - print configuration and exit\n");
  printf("  -E     - enable C preprocessor\n");
  printf("  -SSOCK - set a socket fd\n");
  printf("  -DDEF  - define a symbol for preprocessor\n");
  return code;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "fd_set")
 * End:
 */

