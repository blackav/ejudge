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

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#include <locale.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

/* max. packet size */
#define MAX_PACKET_SIZE 256
typedef char packet_t[MAX_PACKET_SIZE];

static unsigned long current_time;

static unsigned long contest_start_time;
static unsigned long contest_sched_time;
static unsigned long contest_duration;
static unsigned long contest_stop_time;
static int clients_suspended;

struct server_cmd
{
  char const  *cmd;
  int        (*func)(char const *, packet_t const, void *);
  void        *ptr;
};

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

void
update_standings_file(int force_flag)
{
  time_t cur_time = time(0);
  time_t start_time, stop_time, duration;
  int p;

  run_get_times(&start_time, 0, &duration, &stop_time);

  while (1) {
    if (force_flag) break;
    if (!global->autoupdate_standings) return;
    if (!duration) break;
    if (!global->board_fog_time) break;

    ASSERT(cur_time >= start_time);
    ASSERT(global->board_fog_time >= 0);
    ASSERT(global->board_unfog_time >= 0);
    
    p = run_get_fog_period(cur_time, global->board_fog_time,
                           global->board_unfog_time);
    if (p == 1) return;
    break;
  }

  p = run_get_fog_period(cur_time, global->board_fog_time,
                         global->board_unfog_time);
  setup_locale(global->standings_locale_id);
  write_standings(global->status_dir, "standings.html");
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

int
update_status_file(int force_flag)
{
  static time_t prev_status_update = 0;
  time_t cur_time;
  struct prot_serve_status status;
  int p;

  cur_time = time(0);
  if (!force_flag && cur_time <= prev_status_update) return 0;

  memset(&status, 0, sizeof(status));
  status.magic = PROT_SERVE_STATUS_MAGIC;

  status.cur_time = cur_time;
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

  p = run_get_fog_period(cur_time,
                         global->board_fog_time, global->board_unfog_time);
  if (p == 1 && global->autoupdate_standings) {
    status.standings_frozen = 1;
  }

  generic_write_file((char*) &status, sizeof(status), SAFE,
                     global->status_dir, "status", "");
  prev_status_update = cur_time;
  return 1;
}

int
check_team_quota(int teamid, unsigned int size)
{
  int num;
  unsigned long total;

  if (size > global->max_run_size) return -1;
  run_get_team_usage(teamid, &num, &total);
  if (num > global->max_run_num || total + size > global->max_run_total)
    return -1;
  return 0;
}

int
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

int
report_to_client(char const *pk_name, char const *str)
{
  if (str) {
    generic_write_file(str, strlen(str), PIPE,
                       global->pipe_dir, pk_name, "");
  }
  return 0;
}

int
report_error(char const *pk_name, int rm_mode,
             char const *header, char const *msg)
{
  char buf[1024];

  if (!header) header = _("Server is unable to perform your request");
  os_snprintf(buf, 1020, "<h2>%s</h2><p>%s</p>\n",
              header, msg);
  report_to_client(pk_name, buf);
  if (rm_mode == 1) relaxed_remove(global->team_data_dir, pk_name);
  if (rm_mode == 2) relaxed_remove(global->judge_data_dir, pk_name);

  return 0;
}

int
report_bad_packet(char const *pk_name, int rm_mode)
{
  err("bad packet");
  return report_error(pk_name, rm_mode, 0, _("Misformed request"));
}

/* mode == 1 - from master, mode == 2 - from run */
int
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

int
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

int
team_view_clar(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t cmd;
  int  locale_id, team_id, clar_id, n;

  if (sscanf(pk_str, "%s %d %d %d %n", cmd, &locale_id,
             &team_id, &clar_id, &n) != 4)
    return report_bad_packet(pk_name ,1);

  setup_locale(locale_id);
  if (global->disable_clars) {
    err("attempt to read a clar, but clars are disabled");
    return report_error(pk_name, 0, 0, _("Clarifications are disabled"));
  }
  if (pk_str[n] || !teamdb_lookup(team_id))
    return report_bad_packet(pk_name, 1);
  if (clar_id < 0 || clar_id >= clar_get_total())
    return report_bad_packet(pk_name, 1);
  write_team_clar(team_id, clar_id,
                  global->clar_archive_dir, global->pipe_dir, pk_name);
  return 0;
}

int
team_send_clar(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t cmd, subj, ip;
  int  locale_id, team, n;

  char *msg = 0;
  int   rsize = 0;
  char *reply = 0;
  int   clar_id;
  char  clar_name[64];

  if (sscanf(pk_str, "%s %d %d %s %s %n", cmd,
             &locale_id, &team, subj, ip, &n) != 5)
    return report_bad_packet(pk_name, 1);
  setup_locale(locale_id);
  if (global->disable_clars || global->disable_team_clars) {
    err("clarifications are disabled!");
    return report_error(pk_name, 1, 0, _("Clarifications are disabled"));
  }
  if (pk_str[n] || !teamdb_lookup(team))
    return report_bad_packet(pk_name, 1);
  if (strlen(subj) > CLAR_MAX_SUBJ_LEN)
    return report_bad_packet(pk_name, 1);
  if (strlen(ip) > RUN_MAX_IP_LEN)
    return report_bad_packet(pk_name, 1);

  /* disallow sending messages from team before and after the contest */
  if (check_period(pk_name, "team_send_clar", teamdb_get_login(team),
                   0, 1, 0) < 0) {
    relaxed_remove(global->team_data_dir, pk_name);
    return 0;
  }

  if (generic_read_file(&msg, 0, &rsize, REMOVE,
                        global->team_data_dir, pk_name, "") < 0) {
    reply = _("<p>Server failed to read the message body.");
    goto report_to_client;
  }

  if (check_clar_qouta(team, rsize) < 0) {
    reply = _("<p>The message cannot be sent. Message quota exceeded for this team.");
    goto report_to_client;
  }

  /* update log */
  if ((clar_id = clar_add_record(time(0), rsize, ip,
                                 team, 0, 0, subj)) < 0) {
    reply = _("<p>The message is not sent. Error while updating message log.");
    goto report_to_client;
  }

  /* write this request to base */
  sprintf(clar_name, "%06d", clar_id);
  if (generic_write_file(msg, rsize, 0,
                         global->clar_archive_dir, clar_name, "") < 0) {
    reply = _("<p>The message is not sent. Failed to write the message to the archive.");
    goto report_to_client;
  }

  reply = _("<p>The message is sent.");

 report_to_client:
  if (reply) {
    generic_write_file(reply, strlen(reply), PIPE,
                       global->pipe_dir, pk_name, "");
  }
  xfree(msg);
  return 0;
} 

int
team_submit(char const *pk_name, const packet_t pk_str, void *ptr)
{
  char cmd[256];
  char ip[256];
  int  team, prob, lang, n;
  char *reply = 0;
  char *src = 0;
  int   src_len = 0;
  int   run_id;
  int   locale_id;
  char  run_name[64];
  char  run_full[64];
  int   needs_remove = 1;

  char comp_pkt_buf[128];
  char comp_pkt_len;

  if (sscanf(pk_str, "%s %d %d %d %d %s %n",
             cmd, &locale_id, &team, &prob, &lang, ip, &n) != 6
      || pk_str[n]
      || strlen(ip) > RUN_MAX_IP_LEN
      || !teamdb_lookup(team)
      || lang < 1 || lang > max_lang
      || !(langs[lang])
      || prob < 1 || prob > max_prob
      || !(probs[prob]))
    return report_bad_packet(pk_name, 1);

  locale_id = setup_locale(locale_id);

  /* disallow submissions out of contest time */
  if (check_period(pk_name, "SUBMIT", teamdb_get_login(team), 0, 1, 0) < 0)
    goto _cleanup;

  /* this looks like a valid packet */
  /* try to read source file */
  if (generic_read_file(&src, 0, &src_len, REMOVE,
                        global->team_data_dir, pk_name, "") < 0) {
    reply = _("<p>Server failed to read the program source.");
    goto report_to_client;
  }

  /* the last generic_read_file should remove the data file */
  needs_remove = 0;

  /* check the limits */
  if (check_team_quota(team, src_len) < 0) {
    reply = _("<p>The submission cannot be accepted. Quota exceeded.");
    err("team %d:run quota exceeded", team);
    goto report_to_client;
  }

    /* now save the source and create a log record */
  if ((run_id = run_add_record(time(NULL),src_len,ip,
                               locale_id, team, prob, lang)) < 0){
    reply = _("<p>Server failed to update submission log.");
    goto report_to_client;
  }

  sprintf(run_name, "%06d", run_id);
  sprintf(run_full, "%06d%s", run_id, langs[lang]->src_sfx);

  if (generic_write_file(src, src_len, 0,
                         global->run_archive_dir, run_name, "") < 0) {
    reply = _("<p>Server failed to save the program in the archive.");
    goto report_to_client;
  }

  if (generic_write_file(src, src_len, 0,
                         global->compile_src_dir, run_full, "") < 0) {
    reply = _("<p>Server failed to pass the program for compilation");
    goto report_to_client;
  }

  comp_pkt_len = sprintf(comp_pkt_buf, "%s %d\n", run_full, 0);
  if (generic_write_file(comp_pkt_buf, comp_pkt_len, SAFE,
                         langs[lang]->queue_dir, run_name, "") < 0) {
    reply = _("<p>Server failed to pass the program for compilation");
    goto report_to_client;
  }

  if (run_change_status(run_id, RUN_COMPILING, 0, -1) < 0) {
    reply = _("<p>Server failed to update submission log.");
    goto report_to_client;
  }
  reply = _("<p>Submission is sent.");
  
 report_to_client:
  if (reply) {
    generic_write_file(reply, strlen(reply), PIPE,
                       global->pipe_dir, pk_name, "");
  }

 _cleanup:
  if (needs_remove) relaxed_remove(global->team_data_dir, pk_name);
  xfree(src);
  return 0;
}

int
team_change_passwd(char const *pk_name, const packet_t pk_str, void *ptr)
{
  char  cmd[256];
  char  passwd[256];
  int   team_id, n;
  char *reply = 0;
  int   locale_id;

  if (sscanf(pk_str, "%s %d %d %s %n", cmd, &locale_id,
             &team_id, passwd, &n) != 4
      || pk_str[n]
      || !teamdb_lookup(team_id)
      || strlen(passwd) > TEAMDB_MAX_SCRAMBLED_PASSWD_SIZE)
    report_bad_packet(pk_name, 0);

  setup_locale(locale_id);
  if (!teamdb_set_scrambled_passwd(team_id, passwd)) {
    reply = _("<p>New password cannot be set.");
    goto report_to_client;
  }
  if (teamdb_write_passwd(global->passwd_file) < 0) {
    reply = _("<p>New password cannot be saved.");
    goto report_to_client;
  }

  reply = _("<p>Password is changed successfully.");

 report_to_client:
  if (reply) {
    generic_write_file(reply, strlen(reply), PIPE,
                       global->pipe_dir, pk_name, "");
  }
  return 0;
}

int
team_stat(char const *pk_name, packet_t const pk_str, void *ptr)
{
  packet_t cmd;
  int      team, p1, p2, n, locale_id;

  if (sscanf(pk_str, "%s %d %d %d %d %n", cmd, &locale_id,
             &team, &p1, &p2, &n) != 5
      || pk_str[n] || !teamdb_lookup(team))
    return report_bad_packet(pk_name, 0);

  setup_locale(locale_id);
  write_team_statistics(team, p1, p2, global->pipe_dir, pk_name);
  return 0;
}

int
team_view_report(char const *pk_name, const packet_t pk_str, void *ptr)
{
  int      n, rid, team, locale_id;
  packet_t cmd;

  /* teams not allowed to do that */
  if (!global->team_enable_rep_view)
    return report_bad_packet(pk_name, 1);

  if (sscanf(pk_str, "%s %d %d %d %n", cmd, &locale_id, &team, &rid, &n) != 4
      || pk_str[n]
      || rid < 0 || rid >= run_get_total()
      || !teamdb_lookup(team))
    return report_bad_packet(pk_name, 1);

  setup_locale(locale_id);
  write_team_report_view(pk_name, team, rid);
  return 0;
}

int
team_view_source(char const *pk_name, const packet_t pk_str, void *ptr)
{
  int      n, rid, team, locale_id;
  packet_t cmd;

  if (!global->team_enable_src_view)
    return report_bad_packet(pk_name, 1);

  if (sscanf(pk_str, "%s %d %d %d %n", cmd, &locale_id, &team, &rid, &n) != 4
      || pk_str[n]
      || rid < 0 || rid >= run_get_total()
      || !teamdb_lookup(team))
    return report_bad_packet(pk_name, 0);

  setup_locale(locale_id);
  write_team_source_view(pk_name, team, rid);
  return 0;
}

struct server_cmd team_commands[]=
{
  { "SUBMIT", team_submit, 0 },
  { "STAT", team_stat, 0 },
  { "PASSWD", team_change_passwd, 0 },
  { "VIEW", team_view_clar, 0 },
  { "CLAR", team_send_clar, 0 },
  { "REPORT", team_view_report, 0 },
  { "SOURCE", team_view_source, 0 },
  { 0, 0, 0 }
};

int
read_team_packet(char const *pk_name)
{
  packet_t  pk_str, cmd;
  char     *pbuf = pk_str;
  int       i, r, rsize;

  memset(pk_str, 0, sizeof(pk_str));
  r = generic_read_file(&pbuf, sizeof(pk_str), &rsize, SAFE|REMOVE,
                        global->team_cmd_dir, pk_name, "");
  if (r == 0) return 0;
  if (r < 0) return -1;

  info("packet: %s", chop(pk_str));
  sscanf(pk_str, "%s", cmd);
  for (i = 0; team_commands[i].cmd; i++) {
    if (!strcmp(team_commands[i].cmd, cmd)) {
      r = team_commands[i].func(pk_name, pk_str, team_commands[i].ptr);
      setup_locale(0);
      return r;
    }
  }
  report_bad_packet(pk_name, 0);
  return 0;
}

int
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

int
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

void
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
  if ((newclar = clar_add_record(time(0), fullmsglen,
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

void
rejudge_run(int run_id)
{
  int lang, loc;
  char run_name[64];
  char pkt_buf[128];
  char pkt_len;

  if (run_get_record(run_id, 0, 0, 0, &loc, 0, &lang, 0, 0, 0, 0) < 0) return;
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

int
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

int
judge_standings(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t cmd;
  int      n;

  if (sscanf(pk_str, "%s %n", cmd, &n) != 1 || pk_str[n])
    return report_bad_packet(pk_name, 0);
  write_judge_standings(pk_name);
  return 0;
}

int
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

int
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

int
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

int
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

int
judge_start(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t cmd;
  int      n;
  time_t   ts;

  if(sscanf(pk_str, "%s %n", cmd, &n) != 1 || pk_str[n])
    return report_bad_packet(pk_name, 0);
  if (check_period(pk_name, "START", 0, 1, 0, 0) < 0) return 0;

  run_start_contest(time(&ts));
  contest_start_time = ts;
  info("contest started: %lu", ts);
  update_status_file(1);
  report_ok(pk_name);
  return 0;
}

int
judge_stop(char const *pk_name, const packet_t pk_str, void *ptr)
{
  packet_t cmd;
  int      n;
  time_t   ts;

  if (sscanf(pk_str, "%s %n", cmd, &n) != 1 || pk_str[n])
    return report_bad_packet(pk_name, 0);
  if (check_period(pk_name, "STOP", 0, 1, 1, 0) < 0) return 0;

  run_stop_contest(time(&ts));
  contest_stop_time = ts;
  info("contest stopped: %lu", ts);
  update_status_file(1);
  report_ok(pk_name);
  return 0;
}

int
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

int
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

int
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
    if (status == RUN_COMPILE_ERR || status == RUN_REJUDGE) test = 0;
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

int
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

int
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

int
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

int
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

int
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

int
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

int
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

int
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

int
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

int
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

int
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

  if ((c_id = clar_add_record(time(0), mlen, ip, 0, 0, 0, subj)) < 0) {
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
int
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
    if (run_get_record(r, 0, 0, 0, 0, 0, 0, 0, &status, 0, 0) >= 0
        && status >= RUN_OK && status <= RUN_MAX_STATUS) {
      rejudge_run(r);
    }
  }
  report_ok(pk_name);
  return 0;
}

/* FORMAT: "REJUDGEP <locale_id> <problem_id>" */
int
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
    if (run_get_record(r, 0, 0, 0, 0, 0, 0, &prob, &status, 0, 0) >= 0
        && prob == prob_id && status >= RUN_OK && status <= RUN_MAX_STATUS) {
      rejudge_run(r);
    }
  }
  report_ok(pk_name);
  return 0;
}

/* FORMAT: "RESET <locale_id>" */
int
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

int
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

int
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

struct server_cmd judge_cmds[] =
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

int
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

int
do_loop(void)
{
  path_t packetname;
  int    r, p;

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
    while (1) {
      /* update current time */
      current_time = time(0);

      /* refresh user database */
      teamdb_refresh();

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

      if (!clients_suspended) {
        r = scan_dir(global->team_cmd_dir, packetname);
        if (r < 0) return -1;
        if (r > 0) {
          if (read_team_packet(packetname) < 0) return -1;
          break;
        }
      }

      r = scan_dir(global->judge_cmd_dir, packetname);
      if (r < 0) return -1;
      if (r > 0) {
        if (read_judge_packet(packetname) < 0) return -1;
        break;
      }

      r = scan_dir(global->compile_status_dir, packetname);
      if (r < 0) return -1;
      if (r > 0) {
        if (read_compile_packet(packetname) < 0) return -1;
        break;
      }

      r = scan_dir(global->run_status_dir, packetname);
      if (r < 0) return -1;
      if (r > 0) {
        if (read_run_packet(packetname) < 0) return -1;
        break;
      }
    
      os_Sleep(global->serve_sleep_time);
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
  if (do_loop() < 0) return 1;

  return 0;

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
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */

