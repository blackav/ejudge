/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2000,2001 Alexander Chernov <cher@ispras.ru> */

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

#include "cgi.h"
#include "fileutl.h"
#include "pathutl.h"
#include "xalloc.h"
#include "logger.h"
#include "clarlog.h"
#include "base64.h"
#include "osdeps.h"
#include "parsecfg.h"
#include "clntutil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

/*
 * The default path to data directory
 */
#if !defined CGI_DATA_PATH
#define CGI_DATA_PATH "../cgi-data"
#endif

/* defaults */
#define DEFAULT_VAR_DIR        "var"
#define DEFAULT_CONF_DIR       "conf"
#define DEFAULT_PIPE_DIR       "pipe"
#define DEFAULT_JUDGE_DIR      "judge"
#define DEFAULT_JUDGE_CMD_DIR  "cmd"
#define DEFAULT_JUDGE_DATA_DIR "data"
#define DEFAULT_STATUS_FILE    "status/dir/status"
#define DEFAULT_RUN_PAGE_SIZE  10
#define DEFAULT_CLAR_PAGE_SIZE 10
#define DEFAULT_CHARSET        "iso8859-1"

struct section_global_data
{
  struct generic_section_config g;

  int    run_page_size;
  int    clar_page_size;
  int    allow_deny;
  path_t contest_name;
  path_t password;
  path_t root_dir;
  path_t conf_dir;
  path_t var_dir;
  path_t pipe_dir;
  path_t judge_dir;
  path_t judge_cmd_dir;
  path_t judge_data_dir;
  path_t status_file;
  path_t allow_from;
  path_t deny_from;
  path_t standings_url;
  path_t charset;
};

static struct generic_section_config *config;
static struct section_global_data    *global;

#define GLOBAL_OFFSET(x)   XOFFSET(struct section_global_data, x)
#define GLOBAL_PARAM(x, t) { #x, t, GLOBAL_OFFSET(x) }
static struct config_parse_info section_global_params[] =
{
  GLOBAL_PARAM(run_page_size, "d"),
  GLOBAL_PARAM(clar_page_size, "d"),
  GLOBAL_PARAM(allow_deny, "d"),
  GLOBAL_PARAM(contest_name, "s"),
  GLOBAL_PARAM(password, "s"),
  GLOBAL_PARAM(root_dir, "s"),
  GLOBAL_PARAM(var_dir, "s"),
  GLOBAL_PARAM(pipe_dir, "s"),
  GLOBAL_PARAM(judge_dir, "s"),
  GLOBAL_PARAM(judge_cmd_dir, "s"),
  GLOBAL_PARAM(judge_data_dir, "s"),
  GLOBAL_PARAM(status_file, "s"),
  GLOBAL_PARAM(allow_from, "s"),
  GLOBAL_PARAM(deny_from, "s"),
  GLOBAL_PARAM(standings_url, "s"),
  GLOBAL_PARAM(charset, "s"),
  { 0, 0, 0, 0 }
};

static struct config_section_info params[] =
{
  { "global" ,sizeof(struct section_global_data), section_global_params },
  { NULL, 0, NULL }
};

static char *client_password;
//static int   client_first_runid;
//static int   client_first_clarid;

static int force_recheck_status = 0;

static char *runs_statistics = 0;
static char *clars_statistics = 0;

static int    judge_mode = 0;

int view_all_runs = 0;
int view_all_clars = 0;

/* form headers */
static char    form_start_simple[1024];
static char    form_start_multipart[1024];

static void
read_state_params(void)
{
  if (cgi_param("view_all_runs")) view_all_runs = 1;
  if (cgi_param("view_all_clars")) view_all_clars = 1;

  sprintf(form_start_simple,
          "%s"
          "<input type=\"hidden\" name=\"password\" value=\"%s\">",
          form_header_simple, client_password);

  sprintf(form_start_multipart,
          "%s"
          "<input type=\"hidden\" name=\"password\" value=\"%s\">",
          form_header_multipart, client_password);

  /*
  t = cgi_param("first_runid");
  client_first_runid = 0;
  if (t) sscanf(t, "%d", &client_first_runid);

  t = cgi_param("first_clarid");
  client_first_clarid = 0;
  if (t) sscanf(t, "%d", &client_first_clarid);

  sprintf(form_start_simple,
          "%s"
          "<input type=\"hidden\" name=\"password\" value=\"%s\">"
          "<input type=\"hidden\" name=\"first_runid\" value=\"%d\">"
          "<input type=\"hidden\" name=\"first_clarid\" value=\"%d\">",
          form_header_simple,
          client_password,
          client_first_runid,
          client_first_clarid);

  sprintf(form_start_multipart,
          "%s"
          "<input type=\"hidden\" name=\"password\" value=\"%s\">"
          "<input type=\"hidden\" name=\"first_runid\" value=\"%d\">"
          "<input type=\"hidden\" name=\"first_clarid\" value=\"%d\">",
          form_header_multipart,
          client_password,
          client_first_runid,
          client_first_clarid);
  */
}

static int
display_enter_password(void)
{
  client_put_header(global->charset, _("Enter password"));
  puts(form_header_simple);
  puts("<input type=\"password\" size=16 name=\"password\">");
  puts("<input type=\"submit\" value=\"submit\">");
  puts("</form>");
  client_put_footer();
  return 0;
}

static int
ask_passwd(void)
{
  char *passwd = cgi_param("password");
  return passwd == 0;
}

static int
check_passwd(void)
{
  char *passwd = cgi_param("password");

  client_password = passwd;
  if (!passwd) return 0;
  if (!strcmp(passwd, global->password)) return 1;
  return 0;
}

static void
print_refresh_button(char const *str)
{
  if (!str) str = _("refresh");

  puts(form_start_simple);
  printf("<input type=\"submit\" name=\"refresh\" value=\"%s\">", str);
  puts("</form>");
}

static void
print_standings_button(char const *str)
{
  if (!str) str = _("standings");
  puts(form_start_simple);
  printf("<input type=\"submit\" name=\"stand\" value=\"%s\">", str);
  puts("</form>");
}

static void
print_update_button(char const *str)
{
  if (!str) str = _("update public standings");
  puts(form_start_simple);
  printf("<input type=\"submit\" name=\"update\" value=\"%s\">", str);
  puts("</form>");
}

static void
print_teamview_button(char const *str)
{
  if (!str) str = _("view teams");
  puts(form_start_simple);
  printf("<input type=\"submit\" name=\"viewteams\" value=\"%s\">", str);
  puts("</form>");
}

static void
start_if_asked(void)
{
  char *sstr = cgi_param("start");
  char  buf[64];
  char  tname[64];

  if (!sstr) return;
  sprintf(buf, "START\n");
  sprintf(tname, "%lu%d", time(0), getpid());
  /* FIXME: be less ignorant about completion state */
  client_transaction(tname, buf, 0, 0);
  force_recheck_status = 1;
}

void
stop_if_asked(void)
{
  char buf[64];
  char tname[64];

  if (!cgi_param("stop")) return;
  sprintf(buf, "STOP\n");
  /* FIXME: be less ignorant about completion state */
  client_transaction(client_packet_name(tname), buf, 0, 0);
  force_recheck_status = 1;
}

void
update_standings_if_asked(void)
{
  char buf[64];
  char tname[64];

  if (!cgi_param("update")) return;
  sprintf(buf, "UPDATE\n");
  client_transaction(client_packet_name(tname), buf, 0, 0);
  force_recheck_status = 1;
}

void
changedur_if_asked(void)
{
  char *sstr = cgi_param("changedur");
  char *sdur = cgi_param("dur");
  int   dh = 0, dm = 0;
  char  buf[64];
  char  tname[64];

  if (!sstr) return;
  if (sscanf(sdur, "%d:%d", &dh, &dm) != 2) {
    dm = 0;
    if (sscanf(sdur, "%d", &dh) != 1) return;
  }
  sprintf(buf, "TIME %d\n", dh * 60 + dm);
  /* FIXME: be less ignorant about completion state */
  client_transaction(client_packet_name(tname), buf, 0, 0);
  force_recheck_status = 1;
}

void
sched_if_asked(void)
{
  char *s;
  char  buf[64];
  char  tname[64];

  int   h, m;
  time_t     tloc;
  time_t     sloc;
  struct tm *ploc;

  if (!cgi_param("reschedule")) return;
  s = cgi_param("sched_time");
  if (!s) return;
  if (sscanf(s, "%d:%d", &h, &m) != 2) {
    m = 0;
    if (sscanf(s, "%d", &h) != 1) return;
  }

  time(&tloc);
  ploc = localtime(&tloc);
  ploc->tm_hour = h;
  ploc->tm_min = m;
  ploc->tm_sec = 0;
  sloc = mktime(ploc);
  if (sloc == (time_t) -1) return;

  sprintf(buf, "SCHED %lu\n", sloc);
  /* FIXME: be less ignorant about completion state */
  client_transaction(client_packet_name(tname), buf, 0, 0);
  force_recheck_status = 1;
}

void
change_status_if_asked()
{
  char *s = cgi_nname("change_", 6);
  char *s1, *s2, *s3;
  int   runid, n, status, test, score = -1;
  char  p1[32];
  char  p2[32];
  char  p3[32];
  char  cmd[32];
  char  pname[32];

  if (!s) return;
  if (sscanf(s, "change_%d%n", &runid, &n) != 1 || s[n]) return;
  if (runid < 0 || runid >= server_total_runs) return;
  sprintf(p1, "stat_%d", runid);
  sprintf(p2, "failed_%d", runid);
  sprintf(p3, "score_%d", runid);
  s1 = cgi_param(p1);
  s2 = cgi_param(p2);
  s3 = cgi_param(p3);
  if (!s1 || !s2) return;
  if (sscanf(s1, "%d%n", &status, &n) != 1 || s1[n]) return;
  /* FIXME: symbolic constants should be used */
  /* We don't have information about scoring mode, so allow any */
  if (status < 0 || status > 99 || (status > 7 && status < 99)
      || status == 6) return;
  if (sscanf(s2, "%d%n", &test, &n) != 1 || s2[n]) test = -1;
  //if (status == 7 && test >= 0) test++;
  if (test < -1 || test > 99) test = -1;
  if (s3) {
    if (sscanf(s3, "%d%n", &score, &n) != 1 || s3[n]) score = -1;
  }
  if (score < -1 || score > 99) score = -1;

  sprintf(cmd, "CHGSTAT %d %d %d %d\n", runid, status, test, score);
  /* FIXME: be less ignorant about completion state */
  client_transaction(client_packet_name(pname), cmd, 0, 0);
  force_recheck_status = 1;
}

void
view_source_if_asked()
{
  char *s = cgi_nname("source_", 7);
  int   runid, n;
  char  cmd[64];
  char  pname[64];
  char *src = 0;
  int   slen;

  if (!s) return;
  if (sscanf(s, "source_%d%n", &runid, &n) != 1
      || (s[n] && s[n] != '.')) return;
  if (runid < 0 || runid >= server_total_runs) return;

  sprintf(cmd, "SRC %d\n", runid);
  client_transaction(client_packet_name(pname), cmd, &src, &slen);

  printf("Content-Type: text/html; charset=%s\n\n", global->charset);
  printf("<html><head><title>%s %d</title></head><body>\n",
         _("View source for run"),
         runid);
  printf("<h1>%s %d</h1>\n", _("View source for run"), runid);
  print_refresh_button(_("back"));
  printf("<hr>");

  for (s = src; slen; s++, slen--) putchar(*s);
  printf("<hr>");
  print_refresh_button(_("back"));
  printf("</body></html>");

  xfree(src);
  exit(0);
}

void
view_report_if_asked()
{
  char *s = cgi_nname("report_", 7);
  int   runid, n;
  char  cmd[64];
  char  pname[64];
  char *src = 0;
  int   slen = 0;

  if (!s) return;
  if (sscanf(s, "report_%d%n", &runid, &n) != 1
      || (s[n] && s[n] != '.')) return;
  if (runid < 0 || runid >= server_total_runs) return;

  sprintf(cmd, "REPORT %d\n", runid);
  client_transaction(client_packet_name(pname), cmd, &src, &slen);

  printf("Content-Type: text/html; charset=%s\n\n", global->charset);
  printf("<html><head><title>%s %d</title></head><body>\n",
         _("View report for run"), runid);
  printf("<h1>%s %d</h1>\n", _("View report for run"), runid);
  print_refresh_button(_("back"));
  printf("<hr>");

  for (s = src; slen; s++, slen--) putchar(*s);
  printf("<hr>");
  print_refresh_button(_("back"));
  printf("</body></html>");

  xfree(src);
  exit(0);
}

/*
 * this is experimental: html generated on client side.
 * file format for teams view:
 *   <number of teams: int>
 * for each team the following information is passed
 *   <table line length> <space> <table line>
 */
void
view_teams_if_asked(int forced_flag)
{
  char cmd[64], pk_name[64] = { 0 };
  char *teams = 0;
  int teams_len = 0;
  int nteams;
  char *p;
  int i, n;

  if (!forced_flag && !cgi_param("viewteams")) return;

  sprintf(cmd, "%cTEAMS\n", judge_mode?'J':'M');
  client_transaction(pk_name, cmd, &teams, &teams_len);
  client_put_header(global->charset, "Teams information");
  printf("<table><tr><td>");
  print_refresh_button(_("back"));
  printf("</td></tr></table><hr>");
  printf("<h2>%s</h2>\n", _("Existing teams"));
  if (sscanf(teams, "%d%n", &nteams, &n) != 1) goto _format_error;
  p = teams + n;
  if (nteams <= 0 || nteams > 10000) goto _format_error;
  printf("<table border=\"1\"><tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th>",
         _("Team login"), _("Team id"), _("Team name"), _("Flags"));
  if (!judge_mode) {
    printf("<th>%s</th>", _("Change"));
  }
  printf("</tr>\n");
  for (i = 0; i < nteams; i++) {
    int tll;
    char *tl = 0;

    if (sscanf(p, "%d%n", &tll, &n) != 1) goto _format_error;
    if (tll <= 0 || tll > 2048) goto _format_error;
    p += n;
    if (*p++ != ' ') goto _format_error;
    XCALLOC(tl, tll + 1);
    memcpy(tl, p, tll);
    tl[tll] = 0;
    p += tll;

    printf("%s%s</form>\n", form_start_simple, tl);
    xfree(tl);
  }
  printf("</table>\n");
  printf("<hr><h2>%s</h2>%s<table>",
         _("Add new team"), form_start_simple);
  printf("<tr><td>%s:</td><td><input type=\"text\" name=\"tnewid\" size=\"3\"></td><td>(%s)</td></tr>\n",
         _("Team id"),
         _("if empty, assigned automatically"));
  printf("<tr><td>%s:</td><td><input type=\"text\" name=\"tnewlogin\" size=\"32\"></td></tr>\n",
         _("Team login"));
  printf("<tr><td>%s:</td><td><input type=\"text\" name=\"tnewname\" size=\"32\"></td></tr>\n",
         _("Team name"));
  printf("<tr><td>%s:</td><td><input type=\"password\" name=\"tnewpass1\" size=\"16\"></td></tr>\n",
         _("Password"));
  printf("<tr><td>%s:</td><td><input type=\"password\" name=\"tnewpass2\" size=\"16\"></td></tr>\n",
         _("Retype password"));
  printf("<tr><td>%s:</td><td><select name=\"tnewvis\"><option>%s<option>%s</select></td></tr>\n",
         _("Visible?"), _("yes"), _("no"));
  printf("<tr><td>%s:</td><td><select name=\"tnewban\"><option>%s<option>%s</select></td></tr>\n",
         _("Banned?"), _("no"), _("yes"));
  printf("<tr><td>&nbsp;</td><td><input type=\"submit\" name=\"tnewteam\" value=\"%s\"></td><tr>\n", _("Add!"));
  printf("</table></form>\n");
  printf("<hr><table><tr><td>");
  print_refresh_button(_("back"));
  printf("</td></tr></table>");
  client_put_footer();
  exit(0);
 _format_error:
  printf("</td></tr></table></form><hr><b>Format error!</b>");
  printf("<hr><table><tr><td>");
  print_refresh_button(_("back"));
  printf("</td></tr></table>");
  client_put_footer();
  exit(0);
}

void
view_one_team_if_asked(int forced_teamid, char const *reply)
{
  char *s;
  char  cmd[64], pk_name[64] = { 0 };
  int   teamid, n;
  char *team_data = 0;
  int   team_len = 0;

  if (forced_teamid <= 0) {
    if (!(s = cgi_nname("team_", 5))) return;
    if (sscanf(s, "team_%d%n", &teamid, &n) != 1 || s[n]) return;
    if (teamid <= 0 || teamid > 10000) return;
  } else {
    teamid = forced_teamid;
  }
  // FIXME: magic
  sprintf(cmd, "%s %d", "VTEAM", teamid);
  client_transaction(pk_name, cmd, &team_data, &team_len);
  client_put_header(global->charset, "Team %d information", teamid);
  printf("<table><tr><td>");
  print_refresh_button(_("top"));
  printf("</td><td>");
  print_teamview_button(_("back"));
  printf("</td></tr></table><hr>\n");
  if (reply) {
    /*
    printf("<h2>%s</h2>\n%s\n",
           _("Last command completion status"), reply);
    */
    printf("%s<hr>\n", reply);
  }
  printf("%s%s</form>\n", form_start_simple, team_data);
  printf("<hr><table><tr><td>");
  print_refresh_button(_("top"));
  printf("</td><td>");
  print_teamview_button(_("back"));
  printf("</td></tr></table>\n");
  client_put_footer();
  exit(0);
}

void
do_team_action_if_asked(void)
{
  char cmd[64], pk_name[64] = { 0 };
  char *reply = 0;
  int   reply_len = 0;
  char *stid;
  int   n, teamid;
  char *reply1 = 0;

  if (!(stid = cgi_param("teamid"))) return;
  if (sscanf(stid, "%d %n", &teamid, &n) != 1
      || stid[n] || teamid <= 0 || teamid > 10000) return;

  if (cgi_param("tchglogin")) {
    // change team's login
    char *new_login = cgi_param("tlogin");
    char *b64_login;
    if (!new_login) {
      reply1 = _("New team login not specified");
      goto _failed;
    }
    b64_login = alloca(strlen(new_login) * 2 + 16);
    base64_encode_str(new_login, b64_login);
    if (strlen(b64_login) > 48) {
      reply1 = _("New team login is too long");
      goto _failed;
    }
    sprintf(cmd, "CHGLOGIN %d %s", teamid, b64_login);
  } else if (cgi_param("tchgname")) {
    // change team's name
    char *new_name = cgi_param("tname");
    char *b64_name;
    if (!new_name) {
      reply1 = _("New team name not specified");
      goto _failed;
    }
    b64_name = alloca(strlen(new_name) * 2 + 16);
    base64_encode_str(new_name, b64_name);
    if (strlen(b64_name) > 48) {
      reply1 = _("New team name is too long");
      goto _failed;
    }
    sprintf(cmd, "CHGNAME %d %s", teamid, b64_name);
  } else if (cgi_param("tbanchg")) {
    // change team's ban status
    sprintf(cmd, "CHGBAN %d", teamid);
  } else if (cgi_param("tinvchg")) {
    // change team's visibility status
    sprintf(cmd, "CHGVIS %d", teamid);
  } else if (cgi_param("tchgpwd")) {
    // change team's password
    char *p1 = cgi_param("tpasswd1");
    char *p2 = cgi_param("tpasswd2");
    char b64_p[64];
    if (!p1 || !p2 || !*p1 || !*p2) {
      reply1 = _("Passwords not specified");
    }
    if (strcmp(p1, p2)) {
      reply1 = _("Passwords do not match");
      goto _failed;
    }
    if (strlen(p1) > 16) {
      reply1 = _("Password is too long (>16 characters)");
      goto _failed;
    }
    base64_encode_str(p1, b64_p);
    sprintf(cmd, "CHGPASSWD %d %s", teamid, b64_p);
  } else {
    return;
  }

  client_transaction(pk_name, cmd, &reply, &reply_len);
  if (!strcmp(reply, "OK")) {
    reply = "<h2>Operation complete</h2><p>The last operation completed successfully</p>";
  }
  view_one_team_if_asked(teamid, reply);

 _failed:
  XALLOCA(reply, strlen(reply1) + 64);
  sprintf(reply, "<h2>%s</h2>%s<p>",
          _("Operation is not performed"), reply1);
  view_one_team_if_asked(teamid, reply);
}

void
add_team_if_asked(void)
{
  char *reply = 0;
  int   reply_len = 0;
  char *reply1 = 0;
  char *snewid, *snewlogin, *snewname, *snewpass1, *snewpass2, *svis, *sban;
  int   vis, ban;
  int   newid, n;
  char  cmd[64], pk_name[64] = { 0 };
  int   approx_len;
  char *msg;
  int   msg_len;

  if (!(cgi_param("tnewteam"))) return;
  if (!(snewid = cgi_param("tnewid")) || !*snewid) {
    newid = 0;
  } else {
    if (sscanf(snewid, "%d %n", &newid, &n) != 1
        || snewid[n] || newid <= 0 || newid > 10000) {
      reply1 = _("Invalid team id");
      goto _failed;
    }
  }
  if (!(snewlogin = cgi_param("tnewlogin"))) {
    reply1 = _("Team login not specified");
    goto _failed;
  }
  if (!(snewname = cgi_param("tnewname"))) {
    reply1 = _("Team name not specified");
    goto _failed;
  }
  snewpass1 = cgi_param("tnewpass1");
  snewpass2 = cgi_param("tnewpass2");
  if (!snewpass1 || !snewpass2 || !*snewpass1 || !*snewpass2) {
    reply1 = _("Password not specified");
    goto _failed;
  }
  if (strcmp(snewpass1, snewpass2)) {
    reply1 = _("Passwords do not match");
    goto _failed;
  }
  vis = 1;
  if ((svis = cgi_param("tnewvis"))) {
    if (!strcmp(svis, "yes")) vis = 1;
    else if (!strcmp(svis, "no")) vis = 0;
    else {
      reply = _("Invalid visible flag");
      goto _failed;
    }
  }
  ban = 0;
  if ((sban = cgi_param("tnewban"))) {
    if (!strcmp(sban, "yes")) ban = 1;
    else if (!strcmp(sban, "no")) ban = 0;
    else {
      reply = _("Invalid banned flag");
      goto _failed;
    }
  }

  approx_len = strlen(snewlogin) + strlen(snewname) + strlen(snewpass1) + 128;
  msg = alloca(approx_len);
  msg_len = sprintf(msg, "%d %d %s %d %s %d %s %d %d\n",
                   newid, strlen(snewlogin), snewlogin,
                   strlen(snewname), snewname,
                   strlen(snewpass1), snewpass1,
                   vis, ban);

  client_packet_name(pk_name);
  generic_write_file(msg, msg_len, 0,
                     global->judge_data_dir, pk_name, "");

  sprintf(cmd, "NEWTEAM");
  client_transaction(pk_name, cmd, &reply, &reply_len);
  if (strcmp(reply, "OK")) goto _failed2;
  view_teams_if_asked(1);
  exit(0);

 _failed:  
  XALLOCA(reply, strlen(reply1) + 64);
  sprintf(reply, "<h2>%s</h2>%s<p>",
          _("Operation is not performed"), reply1);

 _failed2:
  client_put_header(global->charset, "Team add failed");
  printf("%s<hr>\n", reply);
  printf("<table><tr><td>");
  print_refresh_button(_("top"));
  printf("</td><td>");
  print_teamview_button(_("back"));
  printf("</td></tr></table>\n");
  client_put_footer();
  exit(0);
}

void
view_standings_if_asked()
{
  char cmd[64], pk_name[64] = {0};
  char *stand = 0;
  int   stand_len = 0;
  char *header = 0;
  char *body   = 0;

  if (!cgi_param("stand")) return;

  sprintf(cmd, "%s\n", "STAND");
  client_transaction(pk_name, cmd, &stand, &stand_len);
  client_split(stand, 1, &header, &body, 0);

  client_put_header(global->charset, "%s", header);

  printf("<table><tr><td>");
  print_refresh_button(_("back"));
  printf("</td><td>");
  print_standings_button(_("refresh"));
  printf("</td></tr></table>");

  printf("%s", body);

  printf("<table><tr><td>");
  print_refresh_button(_("back"));
  printf("</td><td>");
  print_standings_button(_("refresh"));
  printf("</td></tr></table>");
  client_put_footer();
  exit(0);
}

void
view_clar_if_asked()
{
  char *s = cgi_nname("clar_", 5);
  int   clarid, n;
  char  cmd[64], pname[64];
  char *src = 0;
  int   slen = 0;
  int   enable_reply = 1;

  if (!s) return;
  if (sscanf(s, "clar_%d%n", &clarid, &n) != 1 || (s[n] && s[n]!='.')) return;
  if (clarid < 0 || clarid >= server_total_clars) return;

  sprintf(cmd, "%s %d\n", judge_mode?"JPEEK":"MPEEK", clarid);
  client_transaction(client_packet_name(pname), cmd, &src, &slen);

  s = cgi_param("enable_reply");
  sscanf(s, "%d", &enable_reply);
  enable_reply = !!enable_reply;

  client_put_header(global->charset, _("Message view"));
  for (s = src; slen; s++, slen--) putchar(*s);
  xfree(src);

  printf("<p>%s<input type=\"submit\" name=\"refresh\" value=\"%s\"></form></p>",
         form_start_simple, _("back"));

  if (enable_reply) {
    puts(form_start_multipart);
    printf("<input type=\"hidden\" name=\"in_reply_to\" value=\"%d\">",
           clarid);
    printf("<p><input type=\"submit\" name=\"answ_read\" value=\"%s\">",
           _("Answer: Read the problem"));
    printf("<input type=\"submit\" name=\"answ_no_comments\" value=\"%s\"><input type=\"submit\" name=\"answ_yes\" value=\"%s\"><input type=\"submit\" name=\"answ_no\" value=\"%s\"></p>",
           _("Answer: No comments"), _("Answer: YES"), _("Answer: NO"));
    printf("<p><textarea name=\"reply\" rows=\"20\" cols=\"60\"></textarea></p>");
    printf("<p><input type=\"submit\" name=\"answ_text\" value=\"%s\">"
           "<input type=\"submit\" name=\"answ_all\" value=\"%s\"></p>",
           _("Send to sender"), _("Send to all"));
    printf("</form>");
  }

  exit(0);
}

void
send_msg_if_asked(void)
{
  char cmd[64];
  char pname[64];
  char subj1[CLAR_MAX_SUBJ_TXT_LEN + 4];
  char subj2[CLAR_MAX_SUBJ_LEN + 4];
  char *s, *t;
  int  l2;
  char *msg;
  int   msglen;

  if (!cgi_param("msg_send")) return;
  s = cgi_param("msg_subj");
  t = cgi_param("msg_text");
  if (!s) s = "";
  if (!t) t = "";
  memset(subj1, 0, sizeof(subj1));
  if (!s || !*s) {
    strncpy(subj1, _("(no subject)"), CLAR_MAX_SUBJ_TXT_LEN);
  } else {
    strncpy(subj1, s, CLAR_MAX_SUBJ_TXT_LEN);
  }
  if (subj1[CLAR_MAX_SUBJ_TXT_LEN - 1]) {
    subj1[CLAR_MAX_SUBJ_TXT_LEN - 1] = 0;
    subj1[CLAR_MAX_SUBJ_TXT_LEN - 2] = '.';
    subj1[CLAR_MAX_SUBJ_TXT_LEN - 3] = '.';
    subj1[CLAR_MAX_SUBJ_TXT_LEN - 4] = '.';
  }
  l2 = base64_encode(subj1, strlen(subj1), subj2);
  subj2[l2] = 0;

  msg = alloca(strlen(s) + strlen(t) + 32);
  strcpy(msg, "Subject: ");
  strcat(msg, s);
  strcat(msg, "\n\n");
  strcat(msg, t);
  msglen = strlen(msg);

  sprintf(cmd, "MSG %s %s\n", subj2, getenv("REMOTE_ADDR"));
  client_packet_name(pname);
  generic_write_file(msg, msglen, 0,
                     global->judge_data_dir, pname, "");
  /* FIXME: check transaction status */
  client_transaction(pname, cmd, 0, 0);
}

void
send_reply_if_asked(void)
{
  int   to_all = 0;
  char *txt = 0;
  int   ref, n;
  char *s;
  char  cmd[64];
  char  pname[64];

  if (cgi_param("answ_all")) {
    to_all = 1;
    txt = cgi_param("reply");
    if (!txt) return;
  } else if (cgi_param("answ_text")) {
    txt = cgi_param("reply");
    if (!txt) return;
  } else if (cgi_param("answ_read")) {
    txt = xstrdup(_("Read the problem.\n"));
  } else if (cgi_param("answ_no_comments")) {
    txt = xstrdup(_("No comments.\n"));
  } else if (cgi_param("answ_yes")) {
    txt = xstrdup(_("YES."));
  } else if (cgi_param("answ_no")) {
    txt = xstrdup(_("NO."));
  } else {
    return;
  }

  s = cgi_param("in_reply_to");
  if (!s || sscanf(s, "%d%n", &ref, &n) != 1 || s[n]
      || ref < 0 || ref >= server_total_clars) return;

  sprintf(cmd, "REPLY %d %d %s\n", ref, to_all, getenv("REMOTE_ADDR"));
  client_packet_name(pname);
  generic_write_file(txt, strlen(txt), 0,
                     global->judge_data_dir, pname, "");
  /* FIXME: check transaction status */
  client_transaction(pname, cmd, 0, 0);
}

/*
void
navigate_if_asked()
{
  if (cgi_param("go_first")) {
    client_first_runid = 0;
  } else if (cgi_param("go_last")) {
    client_first_runid = server_total_runs;
  } else if (cgi_param("go_next")) {
    client_first_runid += global->run_page_size;
  } else if (cgi_param("go_prev")) {
    client_first_runid -= global->run_page_size;
  } else if (cgi_param("go_to")) {
    char *s = cgi_param("new_first_runid");
    if (s) sscanf(s, "%d", &client_first_runid);
  }

  if (client_first_runid < 0)
    client_first_runid = server_total_runs + client_first_runid;
  if (client_first_runid + global->run_page_size > server_total_runs)
    client_first_runid = server_total_runs - global->run_page_size;
  if (client_first_runid < 0) client_first_runid = 0;
}
*/

/*
void
clar_navigate_if_asked()
{
  if (cgi_param("clar_first")) {
    client_first_clarid = 0;
  } else if (cgi_param("clar_last")) {
    client_first_clarid = server_total_clars;
  } else if (cgi_param("clar_next")) {
    client_first_clarid += global->clar_page_size;
  } else if (cgi_param("clar_prev")) {
    client_first_clarid -= global->clar_page_size;
  } else if (cgi_param("clar_to")) {
    char *s = cgi_param("new_first_clarid");
    if (s) sscanf(s, "%d", &client_first_clarid);
  }

  if (client_first_clarid < 0)
    client_first_clarid = server_total_clars + client_first_clarid;
  if (client_first_clarid + global->clar_page_size > server_total_clars)
    client_first_clarid = server_total_clars - global->clar_page_size;
  if (client_first_clarid < 0) client_first_clarid = 0;
}
*/

void
get_contest_statistics()
{
  char   tname[64];
  char   cmd[64];
  char  *reply = 0;

  sprintf(cmd, "%cSTAT %d %d\n", judge_mode?'J':'M', 
          view_all_runs, view_all_clars);
  client_transaction(client_packet_name(tname), cmd, &reply, 0);

  client_split(reply, 1, &runs_statistics, &clars_statistics, NULL);
  xfree(reply);
}

static int
set_defaults(void)
{
  if (global->run_page_size <= 0 || global->run_page_size > 25) {
    global->run_page_size = DEFAULT_RUN_PAGE_SIZE;
  }
  if (global->clar_page_size <= 0 || global->clar_page_size > 25) {
    global->clar_page_size = DEFAULT_CLAR_PAGE_SIZE;
  }
  if (!global->password[0]) {
    err(_("password must be set"));
    return -1;
  }
  if (!global->root_dir[0]) {
    err(_("root_dir must be set"));
    return -1;
  }
  path_init(global->var_dir, global->root_dir, DEFAULT_VAR_DIR);
  path_init(global->pipe_dir, global->var_dir, DEFAULT_PIPE_DIR);
  path_init(global->judge_dir, global->var_dir, DEFAULT_JUDGE_DIR);
  path_init(global->judge_cmd_dir, global->judge_dir, DEFAULT_JUDGE_CMD_DIR);
  path_init(global->judge_data_dir, global->judge_dir, DEFAULT_JUDGE_DATA_DIR);
  path_init(global->status_file, global->var_dir, DEFAULT_STATUS_FILE);
  if (!global->charset[0]) {
    pathcpy(global->charset, DEFAULT_CHARSET);
  }
  return 0;
}

static void
initialize(int argc, char *argv[])
{
  path_t  fullname;
  path_t  dirname;
  path_t  basename;
  path_t  cfgname;
  struct generic_section_config *p;
  char   *s = getenv("SCRIPT_FILENAME");
  
  pathcpy(fullname, argv[0]);
  if (s) pathcpy(fullname, s);
  os_rDirName(fullname, dirname, PATH_MAX);
  os_rGetBasename(fullname, basename, PATH_MAX);
  strcpy(program_name, basename);
  if (!strncmp(basename, "master", 6)) {
  } else if (!strncmp(basename, "judge", 5)) {
    judge_mode = 1;
  } else {
    client_not_configured(0, _("bad program name"));
  }

  /*
   * if CGI_DATA_PATH is absolute, do not append the program start dir
   */
  /* FIXME: we need to perform "/" translation */
  if (CGI_DATA_PATH[0] == '/') {
    pathmake(cfgname, CGI_DATA_PATH, "/", basename, ".cfg", NULL);
  } else {
    pathmake(cfgname, dirname, "/",CGI_DATA_PATH, "/", basename, ".cfg", NULL);
  }
  config = parse_param(cfgname, 0, params, 1);
  if (!config)
    client_not_configured(0, _("config file not parsed"));

  for (p = config; p; p = p->next) {
    if (!p->name[0] || !strcmp(p->name, "global"))
      break;
  }
  if (!p)
    client_not_configured(0, _("no global section"));
  global = (struct section_global_data *) p;

  if (set_defaults() < 0)
    client_not_configured(global->charset, _("bad configuration"));
  logger_set_level(-1, LOG_WARNING);
  client_make_form_headers();

  /* copy this to help client utility functions */
  pathcpy(client_pipe_dir, global->pipe_dir);
  pathcpy(client_cmd_dir, global->judge_cmd_dir);
}

int
main(int argc, char *argv[])
{
  initialize(argc, argv);

  if (!client_check_source_ip(global->allow_deny,
                              global->allow_from,
                              global->deny_from))
    client_access_denied(global->charset);

  cgi_read(global->charset);

  if (ask_passwd()) {
    display_enter_password();
    return 0;
  }
  if (!check_passwd()) client_access_denied(global->charset);
  read_state_params();

  if (!client_check_server_status(global->charset, global->status_file, 3)) {
    return 0;
  }

  if (!judge_mode) {
    stop_if_asked();
    start_if_asked();
    changedur_if_asked();
    sched_if_asked();
    update_standings_if_asked();
    change_status_if_asked();
    view_one_team_if_asked(-1, 0);
    do_team_action_if_asked();
    add_team_if_asked();
  }
  /*
  navigate_if_asked();
  clar_navigate_if_asked();
  */
  view_source_if_asked();
  view_report_if_asked();
  view_clar_if_asked();
  view_teams_if_asked(0);
  view_standings_if_asked();
  send_reply_if_asked();
  send_msg_if_asked();
  get_contest_statistics();

  if (force_recheck_status) {
    client_check_server_status(global->charset, global->status_file, 3);
    force_recheck_status = 0;
  }

  if (global->contest_name[0]) {
    client_put_header(global->charset, "%s: %s - &quot;%s&quot;",
                      _("Monitor"),
                      judge_mode?_("Judge"):_("Administrator"),
                      global->contest_name);
  } else {
    client_put_header(global->charset, "%s: %s",
                      _("Monitor"),
                      judge_mode?_("Judge"):_("Administrator"));
  }
  printf("<table><tr><td>");
  print_refresh_button(0);
  printf("</td><td>");
  print_standings_button(0);
  printf("</td><td>");
  print_teamview_button(0);
  printf("</td></tr></table>\n");
  client_print_server_status(judge_mode, form_start_simple, 0);
  printf("<table><tr><td>");
  print_refresh_button(0);
  printf("</td><td>");
  print_standings_button(0);
  if (!judge_mode) {
    printf("</td><td>");
    print_update_button(0);
  }
  printf("</td></tr></table>\n");

  if (runs_statistics) {
    printf("<hr><h2>%s</h2>", _("Submissions"));
    client_puts(runs_statistics, form_start_simple);

    //puts(runs_statistics);
    
    /*
    printf("<p>%s"
           "<input type=\"text\" size=\"8\" name=\"new_first_runid\">\n"
           "<input type=\"submit\" name=\"go_to\" value=\"go\"><br>\n"
           "<input type=\"submit\" name=\"go_first\" value=\"first %d\">\n"
           "<input type=\"submit\" name=\"go_prev\" value=\"prev %d\">\n"
           "<input type=\"submit\" name=\"go_next\" value=\"next %d\">\n"
           "<input type=\"submit\" name=\"go_last\" value=\"last %d\">\n"
           "</form></p>\n",
           form_start_simple,
           global->run_page_size, global->run_page_size,
           global->run_page_size, global->run_page_size);
    */

    printf("<table><tr><td>");
    printf("%s<input type=\"submit\" name=\"view_all_runs\" value=\"%s\"></form>", form_start_simple, _("View all"));
    printf("</td><td>");
    print_refresh_button(0);
    printf("</td><td>");
    print_standings_button(0);
    printf("</td></tr></table>\n");
  }

  if (clars_statistics) {
    printf("<hr><h2>%s</h2>\n", _("Messages"));
    client_puts(clars_statistics, form_start_simple);

    /* navigation */
    /*
    printf("<p>%s"
           "<input type=\"text\" size=\"8\" name=\"new_first_clarid\">\n"
           "<input type=\"submit\" name=\"clar_to\" value=\"go\"><br>\n"
           "<input type=\"submit\" name=\"clar_first\" value=\"first %d\">\n"
           "<input type=\"submit\" name=\"clar_prev\" value=\"prev %d\">\n"
           "<input type=\"submit\" name=\"clar_next\" value=\"next %d\">\n"
           "<input type=\"submit\" name=\"clar_last\" value=\"last %d\">\n"
           "</form></p>\n",
           form_start_simple,
           global->clar_page_size, global->clar_page_size,
           global->clar_page_size, global->clar_page_size);
    */

    printf("<table><tr><td>");
    printf("%s<input type=\"submit\" name=\"view_all_clars\" value=\"%s\"></form>", form_start_simple, _("View all"));
    printf("</td><td>");
    print_refresh_button(0);
    printf("</td><td>");
    print_standings_button(0);
    printf("</td></tr></table>\n");
  }

  printf("<hr><h2>%s</h2>", _("Compose a message to all the teams"));
  puts(form_start_multipart);
  printf("<p>%s: <input type=\"text\" size=\"64\" name=\"msg_subj\"></p>\n",
         _("Subject"));
  printf("<p><textarea name=\"msg_text\" rows=\"20\" cols=\"60\">"
         "</textarea></p>");


  printf("<p><input type=\"submit\" name=\"msg_send\" value=\"%s\">",
         _("Send"));
  printf("</form>\n");

  printf("<p><table><tr><td>");
  print_refresh_button(0);
  printf("</td><td>");
  print_standings_button(0);
  printf("</td></tr></table>\n");

#if 0
  puts("<hr><pre>");
  //fflush(0);
  //system("printenv");
  puts("");
  for (i = 0; i < argc; i++) {
    printf("argv[%d] = '%s'\n", i, argv[i]);
  }
  puts("");
  cgi_print_param();
#endif
  client_put_footer();

  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 *  enable-multibute-characters: nil
 * End:
 */

