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

#include "clntutil.h"

#include "version.h"
#include "pathutl.h"
#include "fileutl.h"
#include "unix/unix_fileutl.h"
#include "misctext.h"
#include "protocol.h"

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

unsigned long server_cur_time;
unsigned long server_start_time;
unsigned long server_sched_time;
unsigned long server_duration;
unsigned long server_stop_time;
int           server_total_runs;
int           server_total_clars;
int           server_clars_disabled;
int           server_team_clars_disabled;
int           server_standings_frozen;
int           server_score_system;
int           server_clients_suspended;

unsigned long client_cur_time;

path_t  client_pipe_dir;
path_t  client_cmd_dir;

path_t  program_name;
char    form_header_simple[1024];
char    form_header_multipart[1024];
char    form_header_simple_ext[1024];
char    form_header_multipart_ext[1024];

void
client_puts(char const *s, ...)
{
  char const **ps = &s;
  /* hack!!! */
  for (; *s; s++) {
    if (*s == '$') {
      s++;
      if (*s >= '1' && *s <= '9') {
        fputs(ps[(unsigned char)(*s - '0')], stdout);
        continue;
      }
    }
    putchar(*s);
  }
}

char *
client_packet_name(char *buf)
{
  sprintf(buf, "%lu%d", time(0), getpid());
  return buf;
}

int
client_make_pipe(char const *name)
{
  path_t fifo_path;

  pathmake(fifo_path, client_pipe_dir, "/", name, NULL);
  if (sf_mkfifo(fifo_path, 0666) < 0) return -1;
  if (sf_chmod(fifo_path, 0777) < 0) return -1;

  return 0;
}

int
client_get_reply(char **pstr, int *psize, char const *name)
{
  char   *myptr = 0;
  size_t  rlen;
  int     code = -1, n;

  if (pstr) myptr = *pstr;

  xfree(myptr); myptr = 0;
  if (generic_read_file(&myptr, 0, &rlen, REMOVE|PIPE,
                        client_pipe_dir, name, "") < 0) {
    asprintf(&myptr, "<p><big><b>%s</b></big></p>",
             _("Cannot read server response."));
  } else {
    if (myptr && sscanf(myptr, "%d%n", &code, &n) != 1) code = -1;
  }

  if (psize) *psize = rlen;
  if (pstr) *pstr = myptr;
  else xfree(myptr);
  return code;
}

int
client_transaction(char *packet_name, char const *cmd,
                   char **preply, int *preply_len)
{
  if (!packet_name[0]) client_packet_name(packet_name);
  if (client_make_pipe(packet_name) < 0) return -1;
  if (generic_write_file(cmd, strlen(cmd), SAFE,
                         client_cmd_dir, packet_name, "") < 0)
    return -1;
  return client_get_reply(preply, preply_len, packet_name);
}


void
client_put_header(char const *coding, char const *format, ...)
{
  va_list args;

  if (!coding) coding = "iso8859-1";

  va_start(args, format);
  fprintf(stdout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\n\n<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"><title>\n", coding, coding);
  vfprintf(stdout, format, args);
  fputs("\n</title></head><body><h1>\n", stdout);
  vfprintf(stdout, format, args);
  fputs("\n</h1>\n", stdout);
}

void
client_put_footer(void)
{
  puts("<hr>");
  printf(_("<p>This is <b>ejudge</b> contest administration system, version %s, compiled %s.\n"
           "<p>This program is copyright (C) 2000-2002 Alexander Chernov.\n"
           "<p>"
           "This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.\n"
           "<p>You can download the latest version from <a href=\"%s\">this site</a>.\n"), 
         compile_version, compile_date,
         "http://contest.cmc.msu.ru/download");
  puts("</body></html>");
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
client_time_to_str(char *buf, unsigned long time)
{
  char *s = ctime(&time);
  strcpy(buf, s);
  buf[strlen(buf)-1] = 0;
  return buf;
}

void
client_access_denied(char const *charset)
{
  client_put_header(charset, _("Access denied"));
  printf("<p>%s</p>", _("You do not have permissions to use this service."));
  client_put_footer();
  exit(0);
}

void
client_not_configured(char const *charset, char const *str)
{
  write_log(0, LOG_ERR, (char*) str);
  client_put_header(charset, _("Service is not available"));
  printf("<p>%s</p>", _("Service is not available. Please, come later."));
  client_put_footer();
  exit(0);
}

int
client_check_server_status(char const *charset, char const *path, int lag)
{
  int fd = -1, r, tmp;
  struct prot_serve_status status;

  memset(&status, 0, sizeof(status));
  if ((fd = open(path, O_RDONLY)) < 0) {
    err("cannot open status file %s: %s", path, os_ErrorMsg());
    goto server_down;
  }
  r = read(fd, &status, sizeof(status));
  if (r < 0) {
    err("read error from %s: %s", path, os_ErrorMsg());
    goto server_down;
  }
  if (r != sizeof(status)) {
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

  if (status.magic != PROT_SERVE_STATUS_MAGIC) {
    err("invalid magic header in %s", path);
    goto bad_server;
  }

  server_cur_time = status.cur_time;
  server_start_time = status.start_time;
  server_sched_time = status.sched_time;
  server_duration = status.duration;
  server_stop_time = status.stop_time;
  server_total_runs = status.total_runs;
  server_total_clars = status.total_clars;
  server_clars_disabled = status.clars_disabled;
  server_team_clars_disabled = status.team_clars_disabled;
  server_standings_frozen = status.standings_frozen;
  server_score_system = status.score_system;
  server_clients_suspended = status.clients_suspended;
  client_cur_time = time(0);

  if (client_cur_time>=server_cur_time
      && client_cur_time - server_cur_time > lag) {
    err("client current time > timestamp by %lu",
        client_cur_time - server_cur_time);
    goto server_down;
  }
  if (client_cur_time < server_cur_time)
    goto server_down;

  return 1;

 bad_server:
  client_put_header(charset, _("Incompatible server"));
  printf("<p>%s</p>", _("Server configuration error."));
  client_put_footer();
  exit(0);

 server_down:
  client_put_header(charset, _("Server is down"));
  printf("<p>%s</p>", _("Server is down. Please, come later."));
  client_put_footer();
  exit(0);
}

int
client_print_server_status(int read_only, char const *form_start,
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
  if (anchor) printf("<a name=\"%s\">\n", anchor);
  printf("<h2>%s</h2>", _("Server status"));
  if (server_stop_time) {
    printf("<p><big><b>%s</b></big></p>", _("The contest is over"));
  } else if (server_start_time && server_standings_frozen) {
    printf("<p><big><b>%s</b></big></p>",
           _("The contest is in progress (standings are frozen)"));    
  } else if (server_start_time) {
    printf("<p><big><b>%s</b></big></p>", _("The contest is in progress"));
  } else {
    printf("<p><big><b>%s</b></big></p>", _("The contest is not started"));
  }
  if (server_clients_suspended) {
    printf("<p><big><b>%s</b></big></p>", _("Team requests are suspended"));
  }
  puts("");

  if (!read_only) puts(form_start);
  puts("<table border=\"0\">");

  printf("<tr><td>%s:</td><td>%s</td>", _("Server time"), str_serv_time);
  if (!read_only) puts("<td>&nbsp;</td><td>&nbsp;</td>");
  puts("</tr>");

  printf("<tr><td>%s:</td><td>%s</td>", _("Client time"), str_clnt_time);
  if (!read_only) puts("<td>&nbsp;</td><td>&nbsp;</td>");
  puts("</tr>");

  if (!server_start_time) {
    printf("<tr><td colspan=\"2\"><b><big>%s</big></b></td>\n",
         _("Contest is not started"));
    if (!read_only) printf("<td>&nbsp;</td><td><input type=\"submit\" name=\"start\" value=\"%s\"></td>", _("start"));
    puts("</tr>");
  } else {
    client_time_to_str(str_strt_time, server_start_time);
    printf("<tr><td>%s:</td><td>%s</td>",
           _("Contest start time"), str_strt_time);
    if (!read_only) {
      puts("<td>&nbsp;</td>");
      if (!server_stop_time)
        printf("<td><input type=\"submit\" name=\"stop\" value=\"%s\"></td>",
               _("stop"));
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
    if (!read_only)
      printf("<td><input type=\"text\" name=\"sched_time\" size=\"16\"></td>"
             "<td><input type=\"submit\" name=\"reschedule\" value=\"%s\"></td>",
             _("Reschedule"));
    puts("</tr>");
  }

  if (server_duration) {
    duration_str(server_duration, str_duration, 0);
  } else {
    sprintf(str_duration, "%s", _("Unlimited"));
  }
  printf("<tr><td>%s:</td><td>%s</td>", _("Duration"), str_duration);
  if (!read_only) {
    if (!server_stop_time)
      printf("<td><input type=\"text\" name=\"dur\" size=\"16\"></td><td><input type=\"submit\" name=\"changedur\" value=\"%s\"></td>",
             _("Change duration"));
    else
      puts("<td>&nbsp;</td><td>&nbsp;</td>");
  }
  puts("</tr>");

  if (server_start_time && server_duration) {
    client_time_to_str(str_end_time, server_start_time + server_duration);
    printf("<tr><td>%s:</td><td>%s</td>", _("End time"), str_end_time);
    if (!read_only) puts("<td>&nbsp;</td><td>&nbsp;</td>");
    puts("</tr>");

    if (!server_stop_time) {
      duration_str(server_cur_time - server_start_time, str_el_dur, 0);
      printf("<tr><td>%s:</td><td>%s</td>", _("Elapsed time"), str_el_dur);
      if (!read_only) puts("<td>&nbsp;</td><td>&nbsp</td>");
      puts("</tr>");

      if (server_duration) {
        duration_str(server_start_time + server_duration - server_cur_time,
                     str_left_dur, 0);
        printf("<tr><td>%s:</td><td>%s</td>",
               _("Remaining time"), str_left_dur);
        if (!read_only) puts("<td>&nbsp;</td><td>&nbsp</td>");
        puts("</tr>");
      }
    }
  }
  puts("</table>");
  if (!read_only) puts("</form>");
  return 0;
}

void
client_make_form_headers(void)
{

  sprintf(form_header_simple,
          "<form method=\"POST\" action=\"%s\" "
          "ENCTYPE=\"application/x-www-form-urlencoded\">",
          program_name);

  /*
  sprintf(form_header_simple,
          "<form method=\"POST\" action=\"%s\" "
          "ENCTYPE=\"multipart/form-data\">",
          program_name);  
  */
  sprintf(form_header_multipart,
          "<form method=\"POST\" action=\"%s\" "
          "ENCTYPE=\"multipart/form-data\">",
          program_name);  

  /* to put anchor for quick navigation */

  sprintf(form_header_simple_ext,
          "<form method=\"POST\" action=\"%s%%s\" "
          "ENCTYPE=\"application/x-www-form-urlencoded\">",
          program_name);
  sprintf(form_header_multipart_ext,
          "<form method=\"POST\" action=\"%s%%s\" "
          "ENCTYPE=\"multipart/form-data\">",
          program_name);  

}

char *
client_file_to_str(char const *txt, int len)
{
  char *s = xmalloc(len + 1);
  memcpy(s, txt, len);
  s[len] = 0;
  return s;
}

int
client_file_to_stdout(char const *txt, int len)
{
  char const *s;

  for (s = txt; len > 0; s++, len--) putchar(*s);
  return len;
}

void
client_split(char const *buf, int sep, ...)
{
  va_list args;
  char **curp, **nextp;
  char *p;
  char const *s;

  va_start(args, sep);
  curp = va_arg(args, char **);
  if (!curp) return;
  nextp = va_arg(args, char **);
  while (nextp) {
    for (s = buf; *s != 0 && *s != sep; s++);
    if (!*s) {
      *curp = xstrdup(buf);
      while (nextp) {
        *nextp = 0;
        nextp = va_arg(args, char **);
      }
      return;
    }
    *curp = p = malloc(s - buf + 1);
    memcpy(p, buf, s - buf);
    p[s - buf] = 0;
    buf = s + 1;
    curp = nextp;
    nextp = va_arg(args, char **);
  }
  *curp = xstrdup(buf);
  va_end(args);
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
