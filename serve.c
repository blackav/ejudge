/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2000-2002 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

  // passed file descriptors
  int client_fds[2];
};
static struct client_state *client_first;
static struct client_state *client_last;
static int                  client_serial_id = 1;

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

static int
setup_locale(int locale_id)
{
#if CONF_HAS_LIBINTL - 0 == 1
  char *e = 0;
  char env_buf[128];

  if (!global->enable_l10n) return 0;

  switch (locale_id) {
  case 1:
    e = "ru_RU.KOI8-R";
    break;
  case 0:
  default:
    locale_id = 0;
    e = "C";
    break;
  }

  sprintf(env_buf, "LC_ALL=%s", e);
  putenv(env_buf);
  setlocale(LC_ALL, "");
  return locale_id;
#else
  return 0;
#endif /* CONF_HAS_LIBINTL */
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
  int p;

  run_get_times(&start_time, 0, &duration, &stop_time);

  while (1) {
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

  p = run_get_fog_period(current_time, global->board_fog_time,
                         global->board_unfog_time);
  setup_locale(global->standings_locale_id);
  write_standings(global->status_dir, global->standings_file_name,
                  global->stand_header_txt, global->stand_footer_txt);
  if (global->stand2_file_name[0]) {
    write_standings(global->status_dir, global->stand2_file_name,
                    global->stand2_header_txt, global->stand2_footer_txt);
  }
  setup_locale(0);
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

  setup_locale(global->standings_locale_id);
  write_public_log(global->status_dir, global->plog_file_name,
                   global->plog_header_txt, global->plog_footer_txt);
  last_update = current_time;
  setup_locale(0);
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

  p = run_get_fog_period(current_time,
                         global->board_fog_time, global->board_unfog_time);
  if (p == 1 && global->autoupdate_standings) {
    status.standings_frozen = 1;
  }

  generic_write_file((char*) &status, sizeof(status), SAFE,
                     global->status_dir, "status", "");
  prev_status_update = current_time;
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

static int
report_to_client(char const *pk_name, char const *str)
{
  if (str) {
    generic_write_file(str, strlen(str), PIPE,
                       global->pipe_dir, pk_name, "");
  }
  return 0;
}

static int
report_error(char const *pk_name, int rm_mode,
             char const *header, char const *msg)
{
  char buf[1024];

  if (!header) header = _("Server is unable to perform your request");
  os_snprintf(buf, 1020, "<h2>%s</h2><p>%s</p>\n",
              header, msg);
  report_to_client(pk_name, buf);
  if (rm_mode == 2) relaxed_remove(global->judge_data_dir, pk_name);

  return 0;
}

static int
report_bad_packet(char const *pk_name, int rm_mode)
{
  err("bad packet");
  return report_error(pk_name, rm_mode, 0, _("Misformed request"));
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

int
report_ok(char const *pk_name)
{
  char *msg = "OK";

  report_to_client(pk_name, msg);
  return 0;
}

static int
check_period(char const *pk_name, char const *func, char const *extra,
             int before, int during, int after)
{
  char *s = 0;
  char *t = 0;
  if (!contest_start_time) {
    /* before the contest */
    if (!before) {
      s = _("contest is not started");
      t = _("<p>The contest is not started.");
      goto _failed;
    }
  } else if (!contest_stop_time) {
    /* during the contest */
    if (!during) {
      s = _("contest is already started");
      t = _("<p>The contest is already started.");
      goto _failed;
    }
  } else {
    /* after the contest */
    if (!after) {
      s = _("contest is stopped");
      t = _("<p>The contest is already over.");
      goto _failed;
    }
  }
  return 0;

 _failed:
  {
    int len = 0;
    char *buf, *p;

    if (func) len += strlen(func) + 2;
    if (extra) len += strlen(extra) + 2;
    len += strlen(s);

    buf = p = alloca(len + 4);
    buf[0] = 0;
    if (func)  p += sprintf(p, "%s: ", func);
    if (extra) p += sprintf(p, "%s: ", extra);
    sprintf(p, "%s", s);
    err(buf);

    report_to_client(pk_name, t);
  }
  return -1;
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

  last_time = teamdb_get_archive_time(pkt->user_id);
  if (last_time + global->team_download_time > current_time) {
    new_send_reply(p, -SRV_ERR_DOWNLOAD_TOO_OFTEN);
    err("%d: download is too often", p->id);
    return;
  }

  snprintf(dirname, sizeof(dirname), "runs_%d_%d",
           global->contest_id, pkt->user_id);
  snprintf(fullpath, sizeof(fullpath), "%s/%s", global->pipe_dir, dirname);
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
cmd_team_list_runs(struct client_state *p, int len,
                   struct prot_serve_pkt_list_runs *pkt)
{
  FILE *f = 0;
  struct client_state *q = 0;
  unsigned char *html_ptr = 0;
  size_t html_len = 0;

  if (len < sizeof(*pkt)) {
    new_bad_packet(p, "cmd_team_list_runs: packet is too small: %d", len);
    return;
  }
  if (strlen(pkt->data) != pkt->form_start_len) {
    new_bad_packet(p, "cmd_team_list_runs: form_start_len mismatch");
    return;
  }
  if (len != sizeof(*pkt) + pkt->form_start_len) {
    new_bad_packet(p, "cmd_team_list_runs: packet length mismatch");
    return;
  }
  if (pkt->b.id != SRV_CMD_LIST_RUNS && pkt->b.id != SRV_CMD_LIST_CLARS) {
    new_bad_packet(p, "cmd_team_list_runs: bad command: %d", pkt->b.id);
    return;
  }

  info("%d: cmd_team_list_runs: %d, %d, %d, %d, %d", p->id, pkt->b.id,
       pkt->user_id, pkt->contest_id, pkt->locale_id, pkt->flags);
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

  if (!(f = open_memstream((char**) &html_ptr, &html_len))) {
    err("%d: open_memstream failed", p->id);
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  setup_locale(pkt->locale_id);
  switch (pkt->b.id) {
  case SRV_CMD_LIST_RUNS:
    new_write_user_runs(f, pkt->user_id, pkt->flags, pkt->data);
    break;
  case SRV_CMD_LIST_CLARS:
    new_write_user_clars(f, pkt->user_id, pkt->flags, pkt->data);
    break;
  }
  setup_locale(0);
  fclose(f);

  q = client_new_state(p->client_fds[0]);
  q->client_fds[0] = -1;
  q->client_fds[1] = p->client_fds[1];
  p->client_fds[0] = -1;
  p->client_fds[1] = -1;
  q->state = STATE_AUTOCLOSE;
  q->write_buf = html_ptr;
  q->write_len = html_len;

  info("%d: cmd_team_list_runs: ok", p->id);
  new_send_reply(p, SRV_RPL_OK);
}

static void
cmd_team_page(struct client_state *p, int len,
              struct prot_serve_pkt_team_page *pkt)
{
  unsigned char *simple_form_ptr, *multi_form_ptr;
  FILE *f = 0;
  struct client_state *q = 0;
  unsigned char *html_ptr = 0;
  size_t html_len = 0;

  if (len < sizeof(*pkt)) {
    new_bad_packet(p, "cmd_team_page: packet is too small: %d", len);
    return;
  }
  simple_form_ptr = pkt->data;
  if (strlen(simple_form_ptr) != pkt->simple_form_len) {
    new_bad_packet(p, "cmd_team_page: simple_form_len mismatch");
    return;
  }
  multi_form_ptr = simple_form_ptr + pkt->simple_form_len + 1;
  if (strlen(multi_form_ptr) != pkt->multi_form_len) {
    new_bad_packet(p, "cmd_team_page: multi_form_len mismatch");
    return;
  }
  if (len != sizeof(*pkt) + pkt->simple_form_len + pkt->multi_form_len) {
    new_bad_packet(p, "cmd_team_page: packet length mismatch");
    return;
  }

  info("%d: cmd_team_page: %d, %d, %d",
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

  if (!(f = open_memstream((char**) &html_ptr, &html_len))) {
    err("%d: open_memstream failed", p->id);
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  setup_locale(pkt->locale_id);
  write_team_page(f, pkt->user_id, (pkt->flags & 1),
                  (pkt->flags & 2) >> 1,
                  simple_form_ptr, multi_form_ptr,
                  contest_start_time, contest_stop_time);
  setup_locale(0);
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
cmd_team_show_item(struct client_state *p, int len,
                   struct prot_serve_pkt_show_item *pkt)
{
  FILE *f;
  unsigned char *html_ptr = 0;
  size_t html_len = 0;
  struct client_state *q;
  int r;

  if (len != sizeof(*pkt)) {
    new_bad_packet(p, "cmd_team_show_item: bad packet length: %d", len);
    return;
  }
  if (pkt->b.id != SRV_CMD_SHOW_CLAR
      && pkt->b.id != SRV_CMD_SHOW_REPORT
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

  if (!(f = open_memstream((char**) &html_ptr, &html_len))) {
    err("%d: open_memstream failed", p->id);
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  setup_locale(pkt->locale_id);
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
  default:
    abort();
  }
  setup_locale(0);
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

static void
cmd_team_submit_run(struct client_state *p, int len, 
                    struct prot_serve_pkt_submit_run *pkt)
{
  int run_id, comp_pkt_len, r;
  path_t run_name, run_full;
  unsigned char comp_pkt_buf[256];
  unsigned long shaval[5];

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
  if (pkt->lang_id < 1 || pkt->lang_id > max_lang || !langs[pkt->lang_id]) {
    err("%d: lang_id is invalid", p->id);
    new_send_reply(p, -SRV_ERR_BAD_LANG_ID);
    return;
  }
  if (!contest_start_time) {
    err("%d: contest is not started", p->id);
    new_send_reply(p, -SRV_ERR_CONTEST_NOT_STARTED);
    return;
  }
  if (contest_stop_time) {
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

  if (generic_write_file(pkt->data, pkt->run_len, 0,
                         global->compile_src_dir, run_full, "") < 0) {
    new_send_reply(p, -SRV_ERR_SYSTEM_ERROR);
    return;
  }
  comp_pkt_len = sprintf(comp_pkt_buf, "%s %d\n", run_full, 0);
  if (generic_write_file(comp_pkt_buf, comp_pkt_len, SAFE,
                         langs[pkt->lang_id]->queue_dir, run_name, "") < 0) {
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

  unsigned char subj[CLAR_MAX_SUBJ_TXT_LEN + 16];
  unsigned char bsubj[CLAR_MAX_SUBJ_LEN + 16];

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
  if (!contest_start_time) {
    err("%d: contest is not started", p->id);
    new_send_reply(p, -SRV_ERR_CONTEST_NOT_STARTED);
    return;
  }
  if (contest_stop_time) {
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

static int
read_compile_packet(char *pname)
{
  char   buf[256];
  char   exe_name[64];
  char   pkt_name[64];

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
  if (code != RUN_OK && code != RUN_COMPILE_ERR) goto bad_packet_error;
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

  /* copy the executable into the testers's queue */
  sprintf(exe_name, "%06d%s", runid, langs[lang]->exe_sfx);
  if (generic_copy_file(REMOVE, global->compile_report_dir, exe_name, "",
                        0, global->run_exe_dir, exe_name, "") < 0)
    return -1;

  /* create tester packet */
  final_test = 0;
  if (global->score_system_val == SCORE_OLYMPIAD
      && !contest_stop_time) final_test = 1;
  sprintf(pkt_name, "%06d", runid);
  wsize = sprintf(buf, "%s %d %d\n", exe_name, loc, final_test);
  if (generic_write_file(buf, wsize, SAFE, testers[cn]->queue_dir,
                         pkt_name, "") < 0)
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

  info("run packed: %s", chop(buf));
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
  } else if (global->score_system_val == SCORE_KIROV
             && (status == RUN_PARTIAL || status == RUN_OK)) {
    // paranoidal?
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

static void
process_judge_reply(int clar_ref, int to_all,
                    char const *pname, char const *ip)
{
  char *txt = 0;
  int   tsize = 0;
  int   from;
  char *stxt = 0;
  int   ssize = 0;
  char  name1[64];
  char  name2[64];
  char *newsubj = 0;
  int   newsubjlen;
  char *fullmsg = 0;
  int   fullmsglen;
  char  codedsubj[CLAR_MAX_SUBJ_LEN + 4];
  int   to, newclar;
  int   qsize;
  char *qbuf;

  if (generic_read_file(&txt, 0, &tsize, REMOVE,
                        global->judge_data_dir, pname, "") < 0)
    goto exit_notok;
  if (clar_get_record(clar_ref, 0, 0, 0, &from, 0, 0, 0) < 0)
    goto exit_notok;
  if (!from) {
    err("cannot reply to judge's message %d", clar_ref);
    goto exit_notok;
  }
  sprintf(name1, "%06d", clar_ref);
  if (generic_read_file(&stxt, 0, &ssize, 0,
                        global->clar_archive_dir, name1, "") < 0)
    goto exit_notok;
  newsubj = alloca(ssize + 64);
  newsubjlen = message_reply_subj(stxt, newsubj);
  message_base64_subj(newsubj, codedsubj, CLAR_MAX_SUBJ_TXT_LEN);
  ASSERT(strlen(codedsubj) <= CLAR_MAX_SUBJ_LEN);
  qsize = message_quoted_size(stxt);
  qbuf = alloca(qsize + 16);
  fullmsg = alloca(tsize + qsize + newsubjlen + 64);
  message_quote(stxt, qbuf);
  //fprintf(stderr, ">>%s<<\n>>%s<<\n", newsubj, qbuf);
  strcpy(fullmsg, newsubj);
  strcat(fullmsg, qbuf);
  strcat(fullmsg, "\n");
  strcat(fullmsg, txt);
  fullmsglen = strlen(fullmsg);
  to = 0;
  if (!to_all) to = from;

  /* create new clarid */
  info("coded (%d): %s", strlen(codedsubj), codedsubj);
  if ((newclar = clar_add_record(current_time, fullmsglen,
                                 ip, 0, to, 0, codedsubj)) < 0)
    goto exit_notok;
  sprintf(name2, "%06d", newclar);
  generic_write_file(fullmsg, fullmsglen, 0,
                     global->clar_archive_dir, name2, "");
  clar_update_flags(clar_ref, 2);
  xfree(txt);
  generic_write_file("OK\n", 3, PIPE,
                     global->pipe_dir, pname, "");
  return;

 exit_notok:
  xfree(txt);
  generic_write_file("NOT OK\n", 7, PIPE,
                     global->pipe_dir, pname, "");
}

static void
rejudge_run(int run_id)
{
  int lang, loc;
  char run_name[64];
  char pkt_buf[128];
  char pkt_len;

  if (run_get_record(run_id, 0, 0, 0, 0, &loc, 0, &lang, 0, 0, 0, 0) < 0)
    return;
  if (lang <= 0 || lang > max_lang || !langs[lang]) {
    err("rejudge_run: bad language: %d", lang);
    return;
  }

  sprintf(run_name, "%06d", run_id);
  if (generic_copy_file(0, global->run_archive_dir, run_name, "",
                        0, global->compile_src_dir, run_name,
                        langs[lang]->src_sfx) < 0)
    return;
  pkt_len = sprintf(pkt_buf, "%s%s %d\n", run_name, langs[lang]->src_sfx, loc);
  if (generic_write_file(pkt_buf, pkt_len, SAFE,
                         langs[lang]->queue_dir, run_name, "") < 0) {
    return;
  }

  run_change_status(run_id, RUN_COMPILING, 0, -1);
}

static int
judge_stat(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t cmd;
  int      all_runs_flag = 0;
  int      all_clars_flag = 0;
  int      master_mode = (int) ptr;
  int      n;

  if (sscanf(pk_str, "%s %d %d %n", cmd,
             &all_runs_flag, &all_clars_flag, &n) != 3
      || pk_str[n])
    return report_bad_packet(pk_name, 0);

  write_judge_allstat(master_mode,
                      all_runs_flag, all_clars_flag,
                      global->pipe_dir, pk_name);
  return 1;
}

static int
judge_standings(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t cmd;
  int      n;

  if (sscanf(pk_str, "%s %n", cmd, &n) != 1 || pk_str[n])
    return report_bad_packet(pk_name, 0);
  write_judge_standings(pk_name);
  return 0;
}

static int
judge_update_public_standings(char const     *pk_name,
                              const packet_t  pk_str,
                              void           *ptr)
{
  packet_t cmd;
  int      n;

  if (sscanf(pk_str, "%s %n", cmd, &n) != 1 || pk_str[n])
    return report_bad_packet(pk_name, 0);
  update_standings_file(1);
  report_ok(pk_name);
  return 0;
}

static int
judge_view_clar(char const *pk_name, const packet_t pk_str, void *ptr)
{
  int      is_master = (int) ptr;
  packet_t cmd;
  int      c_id, n, flags = 0;

  if (sscanf(pk_str, "%s %d %n", cmd, &c_id, &n) != 2 || pk_str[n]
      || c_id < 0 || c_id >= clar_get_total())
    return report_bad_packet(pk_name, 0);

  if (is_master) {
    write_clar_view(c_id, global->clar_archive_dir,
                    global->pipe_dir, pk_name, 0);
  } else {
    write_clar_view(c_id, global->clar_archive_dir,
                      global->pipe_dir, pk_name, 0);
    clar_get_record(c_id, 0, 0, 0, 0, 0, &flags, 0);
    if (!flags) flags = 1;
    clar_update_flags(c_id, flags);
  }
  return 0;
}

static int
judge_view_report(char const *pk_name, const packet_t pk_str, void *ptr)
{
  int      n, rid;
  packet_t cmd;

  if (sscanf(pk_str, "%s %d %n", cmd, &rid, &n) != 2
      || pk_str[n]
      || rid < 0 || rid >= run_get_total())
    return report_bad_packet(pk_name, 0);

  write_judge_report_view(pk_name, rid);
  return 0;
}

static int
judge_view_src(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t  cmd;
  int       rid, n;

  if (sscanf(pk_str, "%s %d %n", cmd, &rid, &n) != 2
      || pk_str[n]
      || rid < 0 || rid >= run_get_total())
    return report_bad_packet(pk_name, 0);

  write_judge_source_view(pk_name, rid);
  return 0;
}

static int
judge_start(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t cmd;
  int      n;

  if(sscanf(pk_str, "%s %n", cmd, &n) != 1 || pk_str[n])
    return report_bad_packet(pk_name, 0);
  if (check_period(pk_name, "START", 0, 1, 0, 0) < 0) return 0;

  run_start_contest(current_time);
  contest_start_time = current_time;
  info("contest started: %lu", current_time);
  update_status_file(1);
  report_ok(pk_name);
  return 0;
}

static int
judge_stop(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t cmd;
  int      n;

  if (sscanf(pk_str, "%s %n", cmd, &n) != 1 || pk_str[n])
    return report_bad_packet(pk_name, 0);
  if (check_period(pk_name, "STOP", 0, 1, 1, 0) < 0) return 0;

  run_stop_contest(current_time);
  contest_stop_time = current_time;
  info("contest stopped: %lu", current_time);
  update_status_file(1);
  report_ok(pk_name);
  return 0;
}

static int
judge_sched(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t  cmd;
  int       n;
  time_t    newtime;
  char     *reply = "OK";

  if (sscanf(pk_str, "%s %lu %n", cmd, &newtime, &n) != 2 || pk_str[n])
    return report_bad_packet(pk_name, 0);
  if (check_period(pk_name, "SCHED", 0, 1, 0, 0) < 0) return 0;

  run_sched_contest(newtime);
  contest_sched_time = newtime;
  info("contest scheduled: %lu", newtime);
  update_standings_file(0);
  update_status_file(1);

  report_to_client(pk_name, reply);
  return 0;
}

static int
judge_time(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t  cmd;
  int       newtime, n;
  char     *reply = "OK";

  if (sscanf(pk_str, "%s %d %n", cmd, &newtime, &n) != 2 ||
      pk_str[n] || newtime <= 0 || newtime > 60 * 10)
    return report_bad_packet(pk_name, 0);

  if (check_period(pk_name, "TIME", 0, 1, 1, 0) < 0) return 0;
  if (newtime * 60 < global->contest_time) {
    err("contest time cannot be decreased");
    reply = _("<p>The contest time cannot be decreased.");
    goto _cleanup;
  }

  contest_duration = newtime * 60;
  run_set_duration(contest_duration);
  info("contest time reset to %d", newtime);
  update_standings_file(0);
  update_status_file(1);

 _cleanup:
  report_to_client(pk_name, reply);
  return 0;  
}

static int
judge_change_status(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t cmd;
  int      runid, status, test, score, n;

  if (sscanf(pk_str, "%s %d %d %d %d %n", cmd, &runid, &status, &test,
             &score, &n) != 5
      || pk_str[n]
      || runid < 0 || runid >= run_get_total()
      || !is_valid_status(status, 1)
      || test < -1 || test > 99
      || score < -1 || score > 99)
    return report_bad_packet(pk_name, 0);

  if (global->score_system_val == SCORE_KIROV) {
    if (status == RUN_COMPILE_ERR || status == RUN_REJUDGE
        || status == RUN_IGNORED) test = 0;
    else test++;
  } else {
  }

  // FIXME: probably score should not be changed, if -1?
  run_change_status(runid, status, test, score);
  if (status == RUN_REJUDGE) {
    rejudge_run(runid);
  }

  report_ok(pk_name);
  return 0;
}

static int
judge_reply(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t cmd, ip;
  int      c_id, toall, n;

  if (sscanf(pk_str, "%s %d %d %s %n", cmd, &c_id, &toall, ip, &n) != 4
      || pk_str[n]
      || c_id < 0 || c_id >= clar_get_total()
      || strlen(ip) > RUN_MAX_IP_LEN)
    return report_bad_packet(pk_name, 2);

  process_judge_reply(c_id, toall, pk_name, ip);
  return 0;
}

static int
judge_view_teams(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t cmd;
  int      n;

  if (sscanf(pk_str, "%s %n", cmd, &n) != 1
      || pk_str[n])
    return report_bad_packet(pk_name, 2);

  write_judge_teams_view(pk_name, (int) ptr);
  return 0;
}

static int
judge_view_one_team(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t cmd;
  int      teamid, n;

  if (sscanf(pk_str, "%s %d %n", cmd, &teamid, &n) != 2
      || pk_str[n] || teamid <= 0 || teamid > 10000)
    return report_bad_packet(pk_name, 2);

  write_judge_one_team_view(pk_name, teamid);
  return 0;
}

static int
judge_change_team_login(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t cmd, l_b64, l_asc;
  int      tid, n, b64_f = 0;

  if (sscanf(pk_str, "%s %d %s %n", cmd, &tid, l_b64, &n) != 3
      || pk_str[n] || tid <= 0 || tid > 10000)
    return report_bad_packet(pk_name, 2);
  if (!teamdb_lookup(tid)) {
    report_error(pk_name, 0, 0, _("Nonexistent team id"));
    return 0;
  }
  base64_decode_str(l_b64, l_asc, &b64_f);
  if (b64_f) report_bad_packet(pk_name, 2);
  if (!teamdb_is_valid_login(l_asc)) {
    report_error(pk_name, 0, 0, _("Invalid team login"));
    return 0;
  }
  teamdb_transaction();
  if (teamdb_change_login(tid, l_asc) < 0) {
    teamdb_rollback();
    report_error(pk_name, 0, 0, _("Cannot change team login"));
    return 0;
  }
  if (teamdb_write_teamdb(global->teamdb_file) < 0) {
    teamdb_rollback();
    return report_error(pk_name, 0, 0, _("Cannot write teamdb file"));
  }
  teamdb_commit();
  report_ok(pk_name);
  return 0;
}

static int
judge_change_team_name(char const *pk_name, const packet_t pk_str, void *p)
{
  packet_t cmd, l_b64, l_asc;
  int      tid, n, b64_f = 0;

  if (sscanf(pk_str, "%s %d %s %n", cmd, &tid, l_b64, &n) != 3
      || pk_str[n] || tid <= 0 || tid > 10000)
    return report_bad_packet(pk_name, 2);
  if (!teamdb_lookup(tid)) {
    report_error(pk_name, 0, 0, _("Nonexistent team id"));
    return 0;
  }
  base64_decode_str(l_b64, l_asc, &b64_f);
  if (b64_f) report_bad_packet(pk_name, 2);
  if (!teamdb_is_valid_name(l_asc)) {
    report_error(pk_name, 0, 0, _("Invalid team name"));
    return 0;
  }
  teamdb_transaction();
  if (teamdb_change_name(tid, l_asc) < 0) {
    teamdb_rollback();
    report_error(pk_name, 0, 0, _("Cannot change team name"));
    return 0;
  }
  if (teamdb_write_teamdb(global->teamdb_file) < 0) {
    teamdb_rollback();
    return report_error(pk_name, 0, 0, _("Cannot write teamdb file"));
  }
  teamdb_commit();
  report_ok(pk_name);
  return 0;
}

static int
judge_change_team_password(char const *pk_name, const packet_t pk_str, void *p)
{
  packet_t cmd, passwd;
  int      tid, n;

  if (sscanf(pk_str, "%s %d %s %n", cmd, &tid, passwd, &n) != 3
      || pk_str[n] || tid <= 0 || tid > 10000)
    return report_bad_packet(pk_name, 2);
  if (!teamdb_lookup(tid)) {
    report_error(pk_name, 0, 0, _("Nonexistent team id"));
    return 0;
  }
  teamdb_transaction();
  if (!teamdb_set_scrambled_passwd(tid, passwd)) {
    teamdb_rollback();
    report_error(pk_name, 0, 0, _("Cannot change password"));
    return 0;
  }
  if (teamdb_write_passwd(global->passwd_file) < 0) {
    teamdb_rollback();
    return report_error(pk_name, 0, 0, _("Cannot write passwd file"));
  }
  teamdb_commit();
  report_ok(pk_name);
  return 0;
}

static int
judge_change_team_vis(char const *pk_name, const packet_t pk_str, void *p)
{
  int tid, n;
  packet_t cmd;

  if (sscanf(pk_str, "%s %d %n", cmd, &tid, &n) != 2
      || pk_str[n] || tid <= 0 || tid > 10000)
    return report_bad_packet(pk_name, 0);
  if (!teamdb_lookup(tid))
    return report_error(pk_name, 0, 0, _("Nonexistent team id"));
  teamdb_transaction();
  if (teamdb_toggle_vis(tid) < 0) {
    teamdb_rollback();
    return report_error(pk_name, 0, 0, _("Cannot perform operation"));
  }
  if (teamdb_write_passwd(global->passwd_file) < 0) {
    teamdb_rollback();
    return report_error(pk_name, 0, 0, _("Cannot write passwd file"));    
  }
  teamdb_commit();
  report_ok(pk_name);
  return 0;
}

static int
judge_change_team_ban(char const *pk_name, const packet_t pk_str, void *p)
{
  int tid, n;
  packet_t cmd;

  if (sscanf(pk_str, "%s %d %n", cmd, &tid, &n) != 2
      || pk_str[n] || tid <= 0 || tid > 10000)
    return report_bad_packet(pk_name, 0);
  if (!teamdb_lookup(tid))
    return report_error(pk_name, 0, 0, _("Nonexistent team id"));
  teamdb_transaction();
  if (teamdb_toggle_ban(tid) < 0) {
    teamdb_rollback();
    return report_error(pk_name, 0, 0, _("Cannot perform operation"));
  }
  if (teamdb_write_passwd(global->passwd_file) < 0) {
    teamdb_rollback();
    return report_error(pk_name, 0, 0, _("Cannot write passwd file"));    
  }
  teamdb_commit();
  report_ok(pk_name);
  return 0;
}

static int
do_add_team(char const *s, char **msg)
{
  int n;
  int tid;
  int name_len, login_len, passwd_len, vis, ban;
  char *name, *login, *passwd;

  if (sscanf(s, "%d%n", &tid, &n) != 1) goto _bad_packet;
  if (tid < 0 || tid > 10000) goto _bad_packet;
  s += n;
  if (sscanf(s, "%d%n", &login_len, &n) != 1) goto _bad_packet;
  if (login_len <= 0 || login_len > 32767) goto _bad_packet;
  login = alloca(login_len + 32);
  s += n;
  if (*s++ != ' ') goto _bad_packet;
  memcpy(login, s, login_len);
  login[login_len] = 0;
  s += login_len;
  if (sscanf(s, "%d%n", &name_len, &n) != 1) goto _bad_packet;
  if (name_len <= 0 || name_len > 32767) goto _bad_packet;
  name = alloca(name_len + 32);
  name[name_len] = 0;
  s += n;
  if (*s++ != ' ') goto _bad_packet;
  memcpy(name, s, name_len);
  s += name_len;
  if (sscanf(s, "%d%n", &passwd_len, &n) != 1) goto _bad_packet;
  if (passwd_len <= 0 || passwd_len > 32767) goto _bad_packet;
  passwd = alloca(passwd_len + 32);
  passwd[passwd_len] = 0;
  s += n;
  if (*s++ != ' ') goto _bad_packet;
  memcpy(passwd, s, passwd_len);
  s += passwd_len;
  if (sscanf(s, "%d%d %n", &vis, &ban, &n) != 2) goto _bad_packet;
  if (s[n] || vis < 0 || vis > 1 || ban < 0 || ban > 1) goto _bad_packet;

  return teamdb_add_team(tid, login, name, passwd, vis, ban, msg);

 _bad_packet:
  *msg = _("Bad packet (internal error)");
  return -1;
}

static int
judge_add_team(char const *pk_name, const packet_t pk_str, void *p)
{
  packet_t cmd;
  int n;
  char *msg = 0;
  int msg_len = 0;
  char *errmsg;

  if (sscanf(pk_str, "%s %n", cmd, &n) != 1
      || pk_str[n])
    return report_bad_packet(pk_name, 2);

  if (generic_read_file(&msg, 0, &msg_len, REMOVE,
                        global->judge_data_dir, pk_name, "") < 0) {
    return report_error(pk_name, 2, 0, "Cannot read data file");
  }
  teamdb_transaction();
  if (do_add_team(msg, &errmsg) < 0) {
    xfree(msg);
    teamdb_rollback();
    return report_error(pk_name, 0, 0, errmsg);
  }
  if (teamdb_write_passwd(global->passwd_file) < 0) {
    xfree(msg);
    teamdb_rollback();
    return report_error(pk_name, 0, 0, _("Cannot write passwd file"));    
  }
  if (teamdb_write_teamdb(global->teamdb_file) < 0) {
    xfree(msg);
    teamdb_rollback();
    return report_error(pk_name, 0, 0, _("Cannot write teamdb file"));
  }
  teamdb_commit();
  xfree(msg);
  report_ok(pk_name);
  return 0;
}

static int
judge_message(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t cmd, subj, ip, c_name;
  char *msg = 0;
  int   mlen, n;
  char *reply = "OK";
  int   c_id;

  if (sscanf(pk_str, "%s %s %s %n", cmd, subj, ip, &n) != 3
      || pk_str[n]
      || strlen(subj) > CLAR_MAX_SUBJ_LEN
      || strlen(ip) > RUN_MAX_IP_LEN)
    return report_bad_packet(pk_name, 2);

  if (generic_read_file(&msg, 0, &mlen, REMOVE,
                        global->judge_data_dir, pk_name, "") < 0) {
    reply = _("<p>Server failed to read the message file.");
    goto _cleanup;
  }

  if ((c_id = clar_add_record(current_time, mlen, ip, 0, 0, 0, subj)) < 0) {
    reply = _("<p>Server failed to update message log.");
    goto _cleanup;
  }

  sprintf(c_name, "%06d", c_id);
  if (generic_write_file(msg, mlen, 0,
                         global->clar_archive_dir, c_name, "") < 0) {
    reply = _("<p>Server failed to save the message.");
  }

 _cleanup:
  report_to_client(pk_name, reply);
  xfree(msg);
  return 0;
}

/* FORMAT: "REJUDGE <locale_id>" */
static int
judge_rejudge_all(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t cmd;
  int locale_id = 0, n = 0;
  int total_runs, r;
  int status;

  if (sscanf(pk_str, "%s %d %n", cmd, &locale_id, &n) != 2 || pk_str[n]) {
    return report_bad_packet(pk_name, 0);
  }
  /* locale_id is currently unused */

  total_runs = run_get_total();
  for (r = 0; r < total_runs; r++) {
    if (run_get_record(r, 0, 0, 0, 0, 0, 0, 0, 0, &status, 0, 0) >= 0
        && status >= RUN_OK && status <= RUN_MAX_STATUS
        && status != RUN_IGNORED) {
      rejudge_run(r);
    }
  }
  report_ok(pk_name);
  return 0;
}

/* FORMAT: "REJUDGEP <locale_id> <problem_id>" */
static int
judge_rejudge_problem(char const *pk_name, const packet_t pk_str, void *str)
{
  packet_t cmd;
  int locale_id = 0, prob_id = 0, n = 0;
  int total_runs, r, status, prob;

  if (sscanf(pk_str, "%s %d %d %n", cmd, &locale_id, &prob_id, &n) != 3
      || pk_str[n] || prob_id < 1 || prob_id > max_prob
      || !probs[prob_id]) {
    return report_bad_packet(pk_name, 0);
  }
  /* locale_id is currently unused */

  total_runs = run_get_total();
  for (r = 0; r < total_runs; r++) {
    if (run_get_record(r, 0, 0, 0, 0, 0, 0, 0, &prob, &status, 0, 0) >= 0
        && prob == prob_id && status >= RUN_OK && status <= RUN_MAX_STATUS
        && status != RUN_IGNORED) {
      rejudge_run(r);
    }
  }
  report_ok(pk_name);
  return 0;
}

/* FORMAT: "RESET <locale_id>" */
static int
judge_reset_contest(char const *pk_name, const packet_t pk_str, void *str)
{
  packet_t cmd;
  int locale_id = 0, n = 0;

  if (sscanf(pk_str, "%s %d %n", cmd, &locale_id, &n) != 2 || pk_str[n]) {
    return report_bad_packet(pk_name, 0);
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

  update_status_file(1);
  report_ok(pk_name);
  return 0;
}

static int
judge_suspend_clients(char const *pk_name, const packet_t pk_str, void *str)
{
  packet_t cmd;
  int n = 0;

  if (sscanf(pk_str, "%s %n", cmd, &n) != 1 || pk_str[n]) {
    return report_bad_packet(pk_name, 0);
  }

  clients_suspended = 1;
  update_status_file(1);
  report_ok(pk_name);
  return 0;
}

static int
judge_resume_clients(char const *pk_name, const packet_t pk_str, void *str)
{
  packet_t cmd;
  int n = 0;

  if (sscanf(pk_str, "%s %n", cmd, &n) != 1 || pk_str[n]) {
    return report_bad_packet(pk_name, 0);
  }

  clients_suspended = 0;
  update_status_file(1);
  report_ok(pk_name);
  return 0;
}

static int
judge_generate_passwords(char const *pk_name, const packet_t pk_str, void *p)
{
  packet_t cmd;
  int n = 0, locale_id = -1;
  path_t path;

  if (!global->contest_id) {
    return report_bad_packet(pk_name, 0);
  }

  if (sscanf(pk_str, "%s %d %n", cmd, &locale_id, &n) != 2 || pk_str[n]) {
    return report_bad_packet(pk_name, 0);
  }

  pathmake(path, global->pipe_dir, "/", pk_name, 0);
  teamdb_regenerate_passwords(path);
  return 0;
}

static struct server_cmd judge_cmds[] =
{
  { "START", judge_start, 0 },
  { "STOP", judge_stop, 0 },
  { "SCHED", judge_sched, 0 },
  { "TIME", judge_time, 0 },
  { "MSTAT", judge_stat, (void*) 1 },
  { "JSTAT", judge_stat, 0},
  { "CHGSTAT", judge_change_status, 0 },
  { "SRC", judge_view_src, 0 },
  { "REPORT", judge_view_report, 0 },
  { "MPEEK", judge_view_clar, (void*) 1 },
  { "JPEEK", judge_view_clar, 0 },
  { "REPLY", judge_reply, 0 },
  { "MSG", judge_message, 0 },
  { "STAND", judge_standings, 0 },
  { "UPDATE", judge_update_public_standings, 0 },
  { "MTEAMS", judge_view_teams, (void*) 1 },
  { "JTEAMS", judge_view_teams, 0 },
  { "VTEAM", judge_view_one_team, 0 },
  { "CHGLOGIN", judge_change_team_login, 0 },
  { "CHGNAME", judge_change_team_name, 0 },
  { "CHGBAN", judge_change_team_ban, 0 },
  { "CHGVIS", judge_change_team_vis, 0 },
  { "CHGPASSWD", judge_change_team_password, 0 },
  { "NEWTEAM", judge_add_team, 0 },
  { "REJUDGE", judge_rejudge_all, 0 },
  { "REJUDGEP", judge_rejudge_problem, 0 },
  { "RESET", judge_reset_contest, 0 },
  { "SUSPEND", judge_suspend_clients, 0 },
  { "RESUME", judge_resume_clients, 0 },
  { "GENPASSWD", judge_generate_passwords, 0 },

  { 0, 0, 0 },
};

static int
read_judge_packet(char const *pk_name)
{
  int       rsize, i, r;
  packet_t  pk_str, cmd;
  char     *pbuf = pk_str;

  memset(pk_str, 0, sizeof(pk_str));
  r = generic_read_file(&pbuf, sizeof(pk_str), &rsize, SAFE|REMOVE,
                        global->judge_cmd_dir, pk_name, "");
  if (r == 0) return 0;
  if (r < 0) return -1;

  info("judge packet: %s", chop(pk_str));
  sscanf(pk_str, "%s", cmd);
  for (i = 0; judge_cmds[i].cmd; i++)
    if (!strcmp(judge_cmds[i].cmd, cmd))
      return judge_cmds[i].func(pk_name, pk_str, judge_cmds[i].ptr);
  report_bad_packet(pk_name, 2);
  return 0;
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
  [SRV_CMD_LIST_RUNS] { cmd_team_list_runs },
  [SRV_CMD_LIST_CLARS] { cmd_team_list_runs },
  [SRV_CMD_SHOW_CLAR] { cmd_team_show_item },
  [SRV_CMD_SHOW_SOURCE] { cmd_team_show_item },
  [SRV_CMD_SHOW_REPORT] { cmd_team_show_item },
  [SRV_CMD_SUBMIT_RUN] { cmd_team_submit_run },
  [SRV_CMD_SUBMIT_CLAR] { cmd_team_submit_clar },
  [SRV_CMD_TEAM_PAGE] { cmd_team_page },
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
  struct client_state *p;
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
      p->read_len = 0;
      p->expected_len = 0;
      p->read_state = 0;
      xfree(p->read_buf);
      p->read_buf = 0;
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
  p = run_get_fog_period(time(0), global->board_fog_time,
                         global->board_unfog_time);
  if (p == 1) {
    global->fog_standings_updated = 1;
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

    /* refresh user database */
    teamdb_refresh();

    /* check items pending for removal */
    check_remove_queue();

    /* check stop and start times */
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

    /* indicate, that we're alive, and do it somewhat quiet  */
    logger_set_level(-1, LOG_WARNING);
    update_status_file(0);
    logger_set_level(-1, 0);

    /* automatically update standings in certain situations */
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

    /* update public log */
    update_public_log_file();

    if (interrupt_signaled && may_safely_exit()) {
      return 0;
    }

    may_wait_flag = check_sockets(may_wait_flag);

    r = scan_dir(global->judge_cmd_dir, packetname);
    if (r < 0) return -1;
    if (r > 0) {
      if (read_judge_packet(packetname) < 0) return -1;
      may_wait_flag = 0;
    }

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

static int
write_submit_templates(char const *status_dir)
{
  char  buf[1024];
  char *s;
  int   i;

  /* generate problem selection control */
  s = buf + sprintf(buf, "<select name=\"problem\">"
                    "<option value=\"\">\n");
  for (i = 1; i <= max_prob; i++)
    if (probs[i])
      s += sprintf(s, "<option value=\"%d\">%s - %s\n",
                   probs[i]->id, probs[i]->short_name, probs[i]->long_name);
  sprintf(s, "</select>\n");
  if (generic_write_file(buf,strlen(buf),SAFE,status_dir,"problems","") < 0)
    return -1;

  /* generate problem2 selection control */
  s = buf + sprintf(buf, "<select name=\"problem\">"
                    "<option value=\"\">\n");
  for (i = 1; i <= max_prob; i++)
    if (probs[i])
      s += sprintf(s, "<option value=\"%s\">%s - %s\n",
                   probs[i]->short_name,
                   probs[i]->short_name, probs[i]->long_name);
  sprintf(s, "</select>\n");
  if (generic_write_file(buf,strlen(buf),SAFE,status_dir,"problems2","") < 0)
    return -1;

  /* generate language selection control */
  s = buf + sprintf(buf, "<select name=\"language\">"
                    "<option value=\"\">\n");
  for (i = 1; i <= max_lang; i++)
    if (langs[i])
      s += sprintf(s, "<option value=\"%d\">%s - %s\n",
                   langs[i]->id, langs[i]->short_name, langs[i]->long_name);
  sprintf(s, "</select>\n");
  if (generic_write_file(buf,strlen(buf),SAFE,status_dir,"languages","") < 0)
    return -1;

  return 0;
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
    } else break;
  }
  if (i >= argc) goto print_usage;

  if (prepare(argv[i], p_flags, PREPARE_SERVE, cpp_opts) < 0) return 1;

#if CONF_HAS_LIBINTL - 0 == 1
  /* load the language used */
  if (global->enable_l10n) {
    bindtextdomain("ejudge", global->l10n_dir);
    textdomain("ejudge");
  }
#endif /* CONF_HAS_LIBINTL */

  if (T_flag) {
    print_configuration(stdout);
    return 0;
  }
  if (create_dirs(PREPARE_SERVE) < 0) return 1;
  if (global->contest_id) {
    if (teamdb_open_client(global->socket_path, global->contest_id) < 0)
      return 1;
  } else {
    if (teamdb_open(global->teamdb_file, global->passwd_file, 0) < 0)
      return 1;
  }
  if (run_open(global->run_log_file, 0) < 0) return 1;
  if (clar_open(global->clar_log_file, 0) < 0) return 1;
  if (write_submit_templates(global->status_dir) < 0) return 1;
  i = do_loop();
  if (i < 0) i = 1;
  if (socket_name) {
    unlink(socket_name);
  }
  return i;

 print_usage:
  printf("Usage: %s [ OPTS ] config-file\n", argv[0]);
  printf("  -T     - print configuration and exit\n");
  printf("  -E     - enable C preprocessor\n");
  printf("  -DDEF  - define a symbol for preprocessor\n");
  return code;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "fd_set")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */

