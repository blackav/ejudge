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
#include "ej_types.h"

#include "clntutil.h"

#include "pathutl.h"
#include "errlog.h"
#include "fileutl.h"
#include "unix/unix_fileutl.h"
#include "misctext.h"
#include "protocol.h"
#include "client_actions.h"
#include "copyright.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

#if defined EJUDGE_CHARSET
#define DEFAULT_CHARSET              EJUDGE_CHARSET
#else
#define DEFAULT_CHARSET              "iso8859-1"
#endif /* EJUDGE_CHARSET */

time_t server_cur_time;
time_t server_start_time;
time_t server_sched_time;
time_t server_duration;
time_t server_stop_time;
time_t server_freeze_time;
time_t server_finish_time;
int    server_total_runs;
int    server_total_clars;
int    server_clars_disabled;
int    server_team_clars_disabled;
int    server_standings_frozen;
int    server_score_system;
int    server_clients_suspended;
int    server_testing_suspended;
int    server_download_interval;
int    server_is_virtual;
int    server_continuation_enabled;
int    server_printing_enabled;
int    server_printing_suspended;
int    server_always_show_problems;
int    server_accepting_mode;

time_t client_cur_time;

path_t  program_name;
char    form_header_simple[1024];
char    form_header_multipart[1024];

static unsigned char default_header_template[] =
"<html><head>"
"<meta http-equiv=\"Content-Type\" content=\"%T; charset=%C\">\n"
"<title>%H</title>\n"
"</head>\n"
"<body><h1>%H</h1>\n";
static unsigned char default_footer_template[] =
"<hr>%R</body></html>\n";

static void
process_template(FILE *out,
                 unsigned char const *template,
                 unsigned char const *content_type,
                 unsigned char const *charset,
                 unsigned char const *title,
                 unsigned char const *copyright,
                 int locale_id)
{
  unsigned char const *s = template;

  while (*s) {
    if (*s != '%') {
      putc(*s++, out);
      continue;
    }
    switch (*++s) {
    case 'L':
      fprintf(out, "%d", locale_id);
      break;
    case 'C':
      fputs(charset, out);
      break;
    case 'T':
      fputs(content_type, out);
      break;
    case 'H':
      fputs(title, out);
      break;
    case 'R':
      fputs(copyright, out);
      break;
    default:
      putc('%', out);
      continue;
    }
    s++;
  }
}

void
client_put_header(FILE *out, unsigned char const *template,
                  unsigned char const *content_type,
                  unsigned char const *charset,
                  int http_flag,
                  int locale_id,
                  char const *format, ...)
{
  va_list args;
  unsigned char title[1024];

  title[0] = 0;
  if (format) {
    va_start(args, format);
    vsnprintf(title, sizeof(title), format, args);
    va_end(args);
  }

  if (!charset) charset = DEFAULT_CHARSET;
  if (!content_type) content_type = "text/html";
  if (!template) template = default_header_template;

  if (http_flag) {
    fprintf(out, "Content-Type: %s; charset=%s\n"
            "Cache-Control: no-cache\n"
            "Pragma: no-cache\n\n", content_type, charset);

  }

  process_template(out, template, content_type, charset, title, 0, locale_id);
}

void
client_put_footer(FILE *out, unsigned char const *template)
{
  if (!template) template = default_footer_template;
  process_template(out, template, 0, 0, 0, get_copyright(0), 0);
}

int
client_lookup_ip(char const *ip, char const *iplist)
{
  char *cip;
  char const *s;
  int   i1, i2, i3, i4, n;
  int   l1, l2, l3, l4;

  if (!ip) return 0;
  if (!iplist) return 0;
  // ugly hack
  if (!strcmp(ip, "::1")) ip = "127.0.0.1";
  if (sscanf(ip, "%d.%d.%d.%d%n", &i1, &i2, &i3, &i4, &n) != 4
      || ip[n]) {
    err("bad ip: %s", ip);
    return 0;
  }

  //fprintf(stderr, "client_lookup_ip: source ip is %s\n", ip);

  cip = alloca(strlen(iplist) + 1);
  s = iplist;
  while (*s) {
    if (sscanf(s, " %s%n", cip, &n) != 1) break;
    s += n;
    if (sscanf(cip, "%d.%d.%d.%d%n",&l1,&l2,&l3,&l4,&n)==4&&!cip[n]) {
      if (l1==i1&&l2==i2&&l3==i3&&l4==i4) return 1;
    } else if (sscanf(cip,"%d.%d.%d.%n",&l1,&l2,&l3,&n)==3&&!cip[n]) {
      if (l1==i1&&l2==i2&&l3==i3) return 1;
    } else if (sscanf(cip,"%d.%d.%n",&l1,&l2,&n)==2&&!cip[n]) {
      if (l1==i1&&l2==i2) return 1;
    } else if (sscanf(cip,"%d.%n",&l1,&n)==1&&!cip[n]) {
      if (l1 == i1) return 1;
    } else {
      err("bad ip: %s", cip);
    }
  }
  return 0;
}

int
client_check_source_ip(int allow_first,
                       char const *allow_addr,
                       char const *deny_addr)
{
  char *s = getenv("REMOTE_ADDR");
  if (allow_first) {
    if (!s) return 1;
    if (client_lookup_ip(s, allow_addr)) return 1;
    if (client_lookup_ip(s, deny_addr)) return 0;
    return 1;
  } else {
    if (client_lookup_ip(s, deny_addr)) return 0;
    if (client_lookup_ip(s, allow_addr)) return 1;
    if (!s) return 0;
  }
  return 0;
}

char *
client_time_to_str(char *buf, time_t time)
{
  char *s = ctime(&time);
  strcpy(buf, s);
  buf[strlen(buf)-1] = 0;
  return buf;
}

void
client_access_denied(char const *charset, int locale_id)
{
  client_put_header(stdout, 0, 0, charset, 1, locale_id, _("Access denied"));
  printf("<p>%s</p>", _("You do not have permissions to use this service."));
  client_put_footer(stdout, 0);
  exit(0);
}

void
client_not_configured(char const *charset, char const *str, int locale_id)
{
  write_log(0, LOG_ERR, (char*) str);
  client_put_header(stdout, 0, 0, charset, 1, locale_id, _("Service is not available"));
  printf("<p>%s</p>", _("Service is not available. Please, come later."));
  client_put_footer(stdout, 0);
  exit(0);
}

int
client_check_server_status(char const *charset, char const *path, int lag,
                           int locale_id)
{
  int fd = -1, r, tmp;
  unsigned int struct_magic;
  struct prot_serve_status_v1 status_v1;
  struct prot_serve_status_v2 status_v2;
  void *read_ptr = 0;
  size_t read_size = 0;

  memset(&status_v2, 0, sizeof(status_v2));
  if ((fd = open(path, O_RDONLY)) < 0) {
    err("cannot open status file %s: %s", path, os_ErrorMsg());
    goto server_down;
  }
  r = read(fd, &struct_magic, sizeof(struct_magic));
  if (r < 0) {
    err("read error from %s: %s", path, os_ErrorMsg());
    goto server_down;
  }
  if (r != sizeof(struct_magic)) {
    err("short read from %s: %d", path, r);
    goto server_down;
  }
  if (lseek(fd, 0, SEEK_SET) < 0) {
    err("seek failed on %s: %s", path, os_ErrorMsg());
    goto server_down;
  }

  if (struct_magic == PROT_SERVE_STATUS_MAGIC_V1) {
    read_ptr = &status_v1;
    read_size = sizeof(status_v1);
  } else if (struct_magic == PROT_SERVE_STATUS_MAGIC_V2) {
    read_ptr = &status_v2;
    read_size = sizeof(status_v2);
  } else {
    err("magic number does not match in %s", path);
    goto bad_server;
  }

  r = read(fd, read_ptr, read_size);
  if (r < 0) {
    err("read error from %s: %s", path, os_ErrorMsg());
    goto server_down;
  }
  if (r != read_size) {
    err("short read from %s: %d", path, r);
    goto server_down;
  }
  r = read(fd, &tmp, sizeof(tmp));
  if (r < 0) {
    err("read error from %s: %s", path, os_ErrorMsg());
    goto server_down;
  }
  if (r > 0) {
    err("garbage after data in %s", path);
    goto bad_server;
  }
  close(fd);

  if (struct_magic == PROT_SERVE_STATUS_MAGIC_V1) {
    memcpy(&status_v2, &status_v1, sizeof(status_v1));
  }

  server_cur_time = status_v2.cur_time;
  server_start_time = status_v2.start_time;
  server_sched_time = status_v2.sched_time;
  server_duration = status_v2.duration;
  server_stop_time = status_v2.stop_time;
  server_total_runs = status_v2.total_runs;
  server_total_clars = status_v2.total_clars;
  server_clars_disabled = status_v2.clars_disabled;
  server_team_clars_disabled = status_v2.team_clars_disabled;
  server_standings_frozen = status_v2.standings_frozen;
  server_score_system = status_v2.score_system;
  server_clients_suspended = status_v2.clients_suspended;
  server_testing_suspended = status_v2.testing_suspended;
  server_download_interval = status_v2.download_interval;
  server_is_virtual = status_v2.is_virtual;
  server_accepting_mode = status_v2.accepting_mode;
  server_continuation_enabled = status_v2.continuation_enabled;
  client_cur_time = time(0);
  server_freeze_time = status_v2.freeze_time;
  server_printing_enabled = status_v2.printing_enabled;
  server_printing_suspended = status_v2.printing_suspended;
  server_finish_time = status_v2.finish_time;
  server_always_show_problems = status_v2.always_show_problems;

  if (lag > 0) {
    if (client_cur_time>=server_cur_time
        && client_cur_time - server_cur_time > lag) {
      err("client current time > timestamp by %lu",
          client_cur_time - server_cur_time);
      goto server_down;
    }
  }
  if (client_cur_time < server_cur_time)
    goto server_down;

  return 1;

 bad_server:
  client_put_header(stdout, 0, 0, charset, 1, locale_id, _("Incompatible server"));
  printf("<p>%s</p>", _("Server configuration error."));
  client_put_footer(stdout, 0);
  exit(0);

 server_down:
  client_put_header(stdout, 0, 0, charset, 1, locale_id, _("Server is down"));
  printf("<p>%s</p>", _("Server is down. Please, come later."));
  client_put_footer(stdout, 0);
  exit(0);
}

int
client_print_server_status(int priv_level,
                           char const *form_start,
                           char const *anchor)
{
  char str_serv_time[32];
  char str_clnt_time[32];
  char str_strt_time[32];
  char str_schd_time[32];
  char str_duration[32];
  char str_end_time[32];
  char str_left_dur[32];
  char str_el_dur[32];

  client_time_to_str(str_serv_time, server_cur_time);
  client_time_to_str(str_clnt_time, client_cur_time);

  puts("<hr>");
  if (anchor) printf("<a name=\"%s\"></a>\n", anchor);
  printf("<h2>%s</h2>", _("Server status"));
  if (!server_is_virtual) {
    if (server_stop_time) {
      printf("<p><big><b>%s</b></big></p>", _("The contest is over"));
    } else if (server_start_time && server_standings_frozen) {
      printf("<p><big><b>%s</b></big></p>",
             _("The contest is in progress (standings are frozen)"));    
    } else if (server_start_time) {
      printf("<p><big><b>%s</b></big></p>", _("The contest is in progress"));
      if (server_score_system == SCORE_OLYMPIAD
          && server_accepting_mode) {
        printf("<p><big><b>%s</b></big></p>\n",
               _("Participants' solutions are being accepted"));
      }
    } else {
      printf("<p><big><b>%s</b></big></p>", _("The contest is not started"));
    }
  }
  if (server_clients_suspended) {
    printf("<p><big><b>%s</b></big></p>", _("Team requests are suspended"));
  }
  if (server_testing_suspended) {
    printf("<p><big><b>%s</b></big></p>",
           _("Testing of team's submits is suspended"));
  }
  if (server_printing_suspended) {
    printf("<p><big><b>%s</b></big></p>", _("Print requests are suspended"));
  }
  puts("");

  if (server_is_virtual && priv_level == 0) return 0;


  if (server_score_system == SCORE_OLYMPIAD
      && !server_accepting_mode) {
    printf("<p><big><b>%s</b></big></p>\n",
           _("Participants' solutions are being judged"));
  }

  if (priv_level == PRIV_LEVEL_ADMIN) puts(form_start);
  puts("<table border=\"0\">");

  printf("<tr><td>%s:</td><td>%s</td>", _("Server time"), str_serv_time);
  if (priv_level == PRIV_LEVEL_ADMIN) puts("<td>&nbsp;</td><td>&nbsp;</td>");
  puts("</tr>");

  if (priv_level >= PRIV_LEVEL_JUDGE) {
    printf("<tr><td>%s:</td><td>%s</td>", _("Client time"), str_clnt_time);
    if (priv_level == PRIV_LEVEL_ADMIN) puts("<td>&nbsp;</td><td>&nbsp;</td>");
    puts("</tr>");
  }

  if (!server_start_time) {
    printf("<tr><td colspan=\"2\"><b><big>%s</big></b></td>\n",
         _("Contest is not started"));
    if (priv_level == PRIV_LEVEL_ADMIN) printf("<td>&nbsp;</td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>", ACTION_START, _("Start"));
    puts("</tr>");
  } else {
    client_time_to_str(str_strt_time, server_start_time);
    printf("<tr><td>%s:</td><td>%s</td>",
           _("Contest start time"), str_strt_time);
    if (priv_level == PRIV_LEVEL_ADMIN) {
      puts("<td>&nbsp;</td>");
      if (!server_stop_time)
        printf("<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>", ACTION_STOP, _("Stop"));
      else if (server_continuation_enabled
               && (!server_duration || server_stop_time < server_start_time + server_duration))
        printf("<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>", ACTION_CONTINUE, _("Continue"));
      else
        puts("<td>&nbsp;</td>");

    }
  }

  if (!server_start_time) {
    if (!server_sched_time) {
      strcpy(str_schd_time, _("Not set"));
    } else {
      client_time_to_str(str_schd_time, server_sched_time);
    }
    printf("<tr><td>%s:</td><td>%s</td>",
           _("Planned start time"),
           str_schd_time);
    if (priv_level == PRIV_LEVEL_ADMIN)
      printf("<td><input type=\"text\" name=\"sched_time\" size=\"16\"></td>"
             "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>",
             ACTION_SCHEDULE, _("Reschedule"));
    puts("</tr>");
  }

  if (server_duration || !server_finish_time || priv_level==PRIV_LEVEL_ADMIN) {
    if (server_duration) {
      duration_str(0, server_duration, 0, str_duration, 0);
    } else {
      sprintf(str_duration, "%s", _("Unlimited"));
    }
    printf("<tr><td>%s:</td><td>%s</td>", _("Duration"), str_duration);
    if (priv_level == PRIV_LEVEL_ADMIN) {
      if (!server_stop_time || server_continuation_enabled)
        printf("<td><input type=\"text\" name=\"dur\" size=\"16\"></td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>",
               ACTION_DURATION, _("Change duration"));
      else
        puts("<td>&nbsp;</td><td>&nbsp;</td>");
    }
    puts("</tr>");
  }

  if (!server_duration && server_finish_time && !server_stop_time) {
    client_time_to_str(str_end_time, server_finish_time);
    printf("<tr><td>%s:</td><td>%s</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n",
           _("Scheduled end time"), str_end_time);
  }

  if (server_stop_time) {
    client_time_to_str(str_end_time, server_stop_time);
    printf("<tr><td>%s:</td><td>%s</td>", _("End time"), str_end_time);
    if (priv_level == PRIV_LEVEL_ADMIN) puts("<td>&nbsp;</td><td>&nbsp;</td>");
    puts("</tr>");
  } else if (server_start_time && server_duration && !server_is_virtual) {
    client_time_to_str(str_end_time, server_start_time + server_duration);
    printf("<tr><td>%s:</td><td>%s</td>", _("End time"), str_end_time);
    if (priv_level == PRIV_LEVEL_ADMIN) puts("<td>&nbsp;</td><td>&nbsp;</td>");
    puts("</tr>");

    if (server_freeze_time) {
      client_time_to_str(str_el_dur, server_freeze_time);
      printf("<tr><td>%s:</td><td>%s</td>",
             _("Standings freeze time"), str_el_dur);
      if (priv_level == PRIV_LEVEL_ADMIN)
        puts("<td>&nbsp;</td><td>&nbsp</td>");
      puts("</tr>");
    }

    duration_str(0, server_cur_time, server_start_time, str_el_dur, 0);
    printf("<tr><td>%s:</td><td>%s</td>", _("Elapsed time"), str_el_dur);
    if (priv_level == PRIV_LEVEL_ADMIN) puts("<td>&nbsp;</td><td>&nbsp</td>");
    puts("</tr>");
    
    if (server_duration) {
      duration_str(0, server_start_time + server_duration - server_cur_time,
                   0, str_left_dur, 0);
      printf("<tr><td>%s:</td><td>%s</td>",
             _("Remaining time"), str_left_dur);
      if (priv_level == PRIV_LEVEL_ADMIN) puts("<td>&nbsp;</td><td>&nbsp</td>");
      puts("</tr>");
    }
  }
  puts("</table>");
  if (priv_level == PRIV_LEVEL_ADMIN) puts("</form>");
  return 0;
}

void
client_make_form_headers(unsigned char const *self_url)
{

  sprintf(form_header_simple,
          "<form method=\"POST\" action=\"%s\" "
          "ENCTYPE=\"application/x-www-form-urlencoded\">",
          self_url);
  sprintf(form_header_multipart,
          "<form method=\"POST\" action=\"%s\" "
          "ENCTYPE=\"multipart/form-data\">",
          self_url);  
}

ej_ip_t
parse_client_ip(void)
{
  unsigned int b1, b2, b3, b4;
  int n = 0;
  unsigned char *s = getenv("REMOTE_ADDR");
  ej_ip_t client_ip = 0;

  if (!s) return client_ip;

  // ugly hack
  if (!strcmp(s, "::1")) s = "127.0.0.1";

  if (sscanf(s, "%d.%d.%d.%d%n", &b1, &b2, &b3, &b4, &n) != 4
      || s[n] || b1 > 255 || b2 > 255 || b3 > 255 || b4 > 255) {
    client_ip = 0xffffffff;
  } else {
    client_ip = b1 << 24 | b2 << 16 | b3 << 8 | b4;
  }
  return client_ip;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
