/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004 Alexander Chernov <cher@unicorn.cmc.msu.ru> */

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
#include "version.h"

#include "super_html.h"
#include "super-serve.h"
#include "super_actions.h"
#include "super_proto.h"
#include "contests.h"
#include "misctext.h"
#include "opcaps.h"
#include "protocol.h"
#include "userlist_cfg.h"
#include "pathutl.h"
#include "fileutl.h"
#include "xml_utils.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <errno.h>

#define MAX_LOG_VIEW_SIZE (8 * 1024 * 1024)

static unsigned char *
hyperref(unsigned char *buf, size_t size,
         unsigned long long session_id,
         const unsigned char *self_url,
         const unsigned char *extra_args,
         const unsigned char *format, ...)
{
  unsigned char b[1024] = { 0 };
  va_list args;

  if (format && *format) {
    va_start(args, format);
    vsnprintf(b, sizeof(b), format, args);
    va_end(args);
  }

  if (extra_args && *extra_args && *b) {
    snprintf(buf,size,"%s?SID=%016llx&%s&%s",self_url,session_id,extra_args,b);
  } else if (extra_args && *extra_args) {
    snprintf(buf, size, "%s?SID=%016llx&%s", self_url, session_id, extra_args);
  } else if (*b) {
    snprintf(buf, size, "%s?SID=%016llx&%s", self_url, session_id, b);
  } else {
    snprintf(buf, size, "%s?SID=%016llx", self_url, session_id);
  }

  return buf;
}

static const unsigned char form_header_get[] =
"form method=\"GET\" action=";
static const unsigned char form_header_post[] =
"form method=\"POST\" ENCTYPE=\"application/x-www-form-urlencoded\" action=";
static const unsigned char form_header_multipart[] =
"form method=\"POST\" ENCTYPE=\"multipart/form-data\" action=";

static void
html_start_form(FILE *f, int mode, unsigned long long sid,
                unsigned char const *self_url,
                unsigned char const *hidden_vars,
                unsigned char const *extra_args)
{
  switch (mode) {
  case 0:                       /* simple idempotent form */
    fprintf(f, "<%s\"%s\">%s%s", form_header_get, self_url, hidden_vars,
            extra_args);
    break;
  case 1:                       /* simple side-effect form */
    fprintf(f, "<%s\"%s\">%s%s", form_header_post, self_url, hidden_vars,
            extra_args);
    break;
  case 2:                       /* multipart form */
    fprintf(f, "<%s\"%s\">%s%s", form_header_multipart, self_url, hidden_vars,
            extra_args);
    break;
  default:
    SWERR(("unhandled form start mode: %d", mode));
  }
}

static void
html_submit_button(FILE *f,
                   int action,
                   const unsigned char *label)
{
  fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
          action, label);
}

enum
{
  MNG_STAT_FIRST,
  MNG_STAT_NOT_MANAGED = MNG_STAT_FIRST,
  MNG_STAT_TEMP_NOT_MANAGED,
  MNG_STAT_TEMP_FAILED,
  MNG_STAT_TEMP_RUNNING,
  MNG_STAT_TEMP_WAITING,
  MNG_STAT_FAILED,
  MNG_STAT_RUNNING,
  MNG_STAT_WAITING,
  MNG_STAT_LAST = MNG_STAT_WAITING,
};
static int
get_serve_management_status(struct contest_desc *cnts,
                            struct contest_extra *extra)
{
  if (!cnts->managed && (!extra || !extra->serve_used)) {
    return MNG_STAT_NOT_MANAGED;
  } else if (!extra || !extra->serve_used) {
    return MNG_STAT_TEMP_NOT_MANAGED;
  } else if (!cnts->managed) {
    if (extra->serve_suspended) {
      return MNG_STAT_TEMP_FAILED;
    } else if (extra->serve_pid > 0) {
      return MNG_STAT_TEMP_RUNNING;
    } else {
      return MNG_STAT_TEMP_WAITING;
    }
  } else {
    if (extra->serve_suspended) {
      return MNG_STAT_FAILED;
    } else if (extra->serve_pid > 0) {
      return MNG_STAT_RUNNING;
    } else {
      return MNG_STAT_WAITING;
    }
  }
}
static int
get_run_management_status(struct contest_desc *cnts,
                          struct contest_extra *extra)
{
  if (!cnts->run_managed && (!extra || !extra->run_used)) {
    return MNG_STAT_NOT_MANAGED;
  } else if (!extra || !extra->run_used) {
    return MNG_STAT_TEMP_NOT_MANAGED;
  } else if (!cnts->run_managed) {
    if (extra->run_suspended) {
      return MNG_STAT_TEMP_FAILED;
    } else if (extra->run_pid > 0) {
      return MNG_STAT_TEMP_RUNNING;
    } else {
      return MNG_STAT_TEMP_WAITING;
    }
  } else {
    if (extra->run_suspended) {
      return MNG_STAT_FAILED;
    } else if (extra->run_pid > 0) {
      return MNG_STAT_RUNNING;
    } else {
      return MNG_STAT_WAITING;
    }
  }
}

/* a piece of dirty hacks */
static unsigned char *
logged_contest_get(struct userlist_cfg *config, int contest_id)
{
  unsigned char *dir_name = 0;
  unsigned char *s, *outbuf;
  unsigned char tmplog_path[1024];
  int serial = 0, tmplog_fd, saved_log_fd, errcode, sz, r;
  struct contest_desc *cnts;
  struct stat logstat;

  // get the directory to create a temporary file
  if (config->super_serve_log) dir_name = os_DirName(config->super_serve_log);
  if (!dir_name && config->var_dir) dir_name = xstrdup(config->var_dir);
  if (!dir_name && (s = getenv("TMPDIR"))) dir_name = xstrdup(s);
#if defined P_tmpdir
  if (!dir_name) dir_name = xstrdup(P_tmpdir);
#endif /* P_tmpdir */
  if (!dir_name) dir_name = xstrdup("/tmp");

  while (1) {
    snprintf(tmplog_path, sizeof(tmplog_path), "%s/super-serve-tmp.%d.txt",
             dir_name, serial++);
    tmplog_fd = open(tmplog_path,
                     O_RDWR | O_CREAT | O_TRUNC | O_EXCL, 0600);
    if (tmplog_fd >= 0) break;
    if (errno != EEXIST) {
      // sorry, it did not work out
      err("logged_contest_get: open %s failed: %s", tmplog_path,
          os_ErrorMsg());
      xfree(dir_name);
      return 0;
    }
  }

  xfree(dir_name);
  fflush(stderr);
  unlink(tmplog_path);
  saved_log_fd = dup(2);
  dup2(tmplog_fd, 2);

  if ((errcode = contests_get(contest_id, &cnts)) < 0) {
    fprintf(stderr, "%s", contests_strerror(-errcode));
  } else {
    fprintf(stderr, "no error");
  }
  fflush(stderr);

  dup2(saved_log_fd, 2);
  close(saved_log_fd);

  if (fstat(tmplog_fd, &logstat) < 0) {
    err("logged_contest_get: fstat failed: %s", os_ErrorMsg());
    close(tmplog_fd);
    return 0;
  }
  if (!S_ISREG(logstat.st_mode)) {
    err("logged_contest_get: not a regular file");
    close(tmplog_fd);
    return 0;
  }
  if (lseek(tmplog_fd, 0, SEEK_SET) < 0) {
    err("logged_contest_get: lseek failed: %s", os_ErrorMsg());
    close(tmplog_fd);
    return 0;
  }
  outbuf = s = calloc(1, logstat.st_size + 1);
  sz = logstat.st_size;
  while (sz > 0) {
    if ((r = read(tmplog_fd, s, sz)) < 0) {
      err("logged_contest_get: read() failed: %s", os_ErrorMsg());
      close(tmplog_fd);
      xfree(outbuf);
      return 0;
    }
    if (!r) {
      err("logged_contest_get: unexpected EOF");
      close(tmplog_fd);
      xfree(outbuf);
      return 0;
    }
    s += r;
    sz -= r;
  }
  if ((r = read(tmplog_fd, &sz, 1)) < 0) {
    err("logged_contest_get: read() failed: %s", os_ErrorMsg());
    close(tmplog_fd);
    xfree(outbuf);
    return 0;
  }
  if (r) {
    err("logged_contest_get: size of the log file changed!");
    close(tmplog_fd);
    xfree(outbuf);
    return 0;
  }

  close(tmplog_fd);
  return outbuf;
}

int
super_html_main_page(FILE *f,
                     int priv_level,
                     int user_id,
                     const unsigned char *login,
                     unsigned long long session_id,
                     unsigned long ip_address,
                     unsigned int flags,
                     struct userlist_cfg *config,
                     const unsigned char *self_url,
                     const unsigned char *hidden_vars,
                     const unsigned char *extra_args)
{
  unsigned char *contests_map = 0;
  int contest_max_id, contest_id, errcode;
  unsigned char *html_name;
  struct contest_desc *cnts;
  struct contest_extra *extra;
  unsigned char hbuf[1024];
  opcap_t caps;
  unsigned char judge_url[1024] = { 0 };
  unsigned char master_url[1024] = { 0 };
  unsigned char prog_pat[128];
  int prog_pat_len, self_url_len;

#if defined CGI_PROG_SUFFIX
  snprintf(prog_pat, sizeof(prog_pat), "serve-control%s", CGI_PROG_SUFFIX);
#else
  snprintf(prog_pat, sizeof(prog_pat), "serve-control");
#endif
  prog_pat_len = strlen(prog_pat);
  self_url_len = strlen(self_url);
  if (self_url_len > prog_pat_len
      && !strcmp(self_url + self_url_len - prog_pat_len, prog_pat)) {
    snprintf(judge_url, sizeof(judge_url),
             "%.*sjudge", self_url_len - prog_pat_len, self_url);
    snprintf(master_url, sizeof(master_url),
             "%.*smaster", self_url_len - prog_pat_len, self_url);

  }

  // display information about known contests
  contest_max_id = contests_get_list(&contests_map);
  if (contest_max_id <= 0 || !contests_map) {
    fprintf(f, "<h2>No contests available</h2>\n");
    return 0;
  }

  fprintf(f, "<h2>Contests</h2>\n");
  fprintf(f, "<table border=\"1\">\n"
          "<tr>\n"
          "<th>Id</th>\n"
          "<th>Name</th>\n"
          "<th>Closed?</th>\n"
          "<th>Serve status</th>\n"
          "<th>Run status</th>\n"
          "<th>Judge</th>\n"
          "<th>Master</th>\n"
          "<th>Details</th>\n"
          "</tr>\n");
  for (contest_id = 1; contest_id < contest_max_id; contest_id++) {
    if (!contests_map[contest_id]) {
      if (priv_level < PRIV_LEVEL_ADMIN) continue;

      extra = get_existing_contest_extra(contest_id);
      if (!extra) continue;
      if (!extra->serve_used && !extra->run_used) continue;

      fprintf(f, "<tr>");
      fprintf(f, "<td>%d</td>", contest_id);
      fprintf(f, "<td>(removed)</td>");
      fprintf(f, "<td>&nbsp;</td>");

      if (!extra || !extra->serve_used) {
        fprintf(f, "<td><i>Not managed</i></td>\n");
      } else {
        if (extra->serve_suspended) {
          fprintf(f, "<td bgcolor=\"#ff8888\">Failed</td>\n");
        } else if (extra->serve_pid > 0) {
          fprintf(f, "<td bgcolor=\"#ffff88\">Running, %d</td>\n",
                  extra->serve_pid);
        } else {
          fprintf(f, "<td bgcolor=\"#ffff88\">Waiting</td>\n");
        }
      }

      if (!extra || !extra->run_used) {
        fprintf(f, "<td><i>Not managed</i></td>\n");
      } else {
        if (extra->run_suspended) {
          fprintf(f, "<td bgcolor=\"#ff8888\">Failed</td>\n");
        } else if (extra->run_pid > 0) {
          fprintf(f, "<td bgcolor=\"#ffff88\">Running, %d</td>\n",
                  extra->run_pid);
        } else {
          fprintf(f, "<td bgcolor=\"#ffff88\">Waiting</td>\n");
        }
      }

      fprintf(f, "<td>&nbsp;</td><td>&nbsp;</td>");
      fprintf(f, "<td><a href=\"%s\">Details</a></td>\n",
              hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                       "contest_id=%d&action=%d", contest_id,
                       SUPER_ACTION_VIEW_CONTEST));
      continue;
    }
    if ((errcode = contests_get(contest_id, &cnts)) < 0) {
      if (priv_level < PRIV_LEVEL_ADMIN) continue;

      fprintf(f, "<tr>");
      fprintf(f, "<td>%d</td>", contest_id);
      fprintf(f, "<td bgcolor=\"#ff8888\">(XML parse error)</td>");
      fprintf(f, "<td>&nbsp;</td>");

      if (!extra || !extra->serve_used) {
        fprintf(f, "<td><i>Not managed</i></td>\n");
      } else {
        if (extra->serve_suspended) {
          fprintf(f, "<td bgcolor=\"#ff8888\">Failed</td>\n");
        } else if (extra->serve_pid > 0) {
          fprintf(f, "<td bgcolor=\"#ffff88\">Running, %d</td>\n",
                  extra->serve_pid);
        } else {
          fprintf(f, "<td bgcolor=\"#ffff88\">Waiting</td>\n");
        }
      }

      if (!extra || !extra->run_used) {
        fprintf(f, "<td><i>Not managed</i></td>\n");
      } else {
        if (extra->run_suspended) {
          fprintf(f, "<td bgcolor=\"#ff8888\">Failed</td>\n");
        } else if (extra->run_pid > 0) {
          fprintf(f, "<td bgcolor=\"#ffff88\">Running, %d</td>\n",
                  extra->run_pid);
        } else {
          fprintf(f, "<td bgcolor=\"#ffff88\">Waiting</td>\n");
        }
      }

      fprintf(f, "<td>&nbsp;</td><td>&nbsp;</td>");
      fprintf(f, "<td><a href=\"%s\">Details</a></td>\n",
              hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                       "contest_id=%d&action=%d", contest_id,
                       SUPER_ACTION_VIEW_CONTEST));
      continue;
    }
    if (priv_level < PRIV_LEVEL_ADMIN) {
      // skip contests, where nor ADMIN neither JUDGE permissions are set
      if (opcaps_find(&cnts->capabilities, login, &caps) < 0) continue;
      if (opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0
          && opcaps_check(caps, OPCAP_JUDGE_LOGIN) < 0) continue;
    } else {
      caps = 0;
      opcaps_find(&cnts->capabilities, login, &caps);
    }

    if (!(flags & SSERV_VIEW_INVISIBLE) && cnts->invisible) continue;

    extra = get_existing_contest_extra(contest_id);

    fprintf(f, "<tr>");
    fprintf(f, "<td>%d</td>", contest_id);
    html_name = html_armor_string_dup(cnts->name);
    fprintf(f, "<td>%s</td>", html_name);
    xfree(html_name);

    // report "closed" flag
    fprintf(f, "<td>%s</td>", cnts->closed?"closed":"&nbsp;");

    // report serve mastering status
    if (priv_level >= PRIV_LEVEL_ADMIN) {
      if (!cnts->managed && (!extra || !extra->serve_used)) {
        fprintf(f, "<td><i>Not managed</i></td>\n");
      } else if (!extra || !extra->serve_used) {
        fprintf(f, "<td bgcolor=\"#ffff88\">Not yet managed</td>\n");
      } else if (!cnts->managed) {
        // still managed, but not necessary
        if (extra->serve_suspended) {
          fprintf(f, "<td bgcolor=\"#ff8888\">Failed, not managed</td>\n");
        } else if (extra->serve_pid > 0) {
          fprintf(f, "<td bgcolor=\"#ffff88\">Running, %d, not managed</td>\n",
                  extra->serve_pid);
        } else {
          fprintf(f, "<td bgcolor=\"#ffff88\">Waiting, not managed</td>\n");
        }
      } else {
        // managed as need to
        if (extra->serve_suspended) {
          fprintf(f, "<td bgcolor=\"#ff8888\">Failed</td>\n");
        } else if (extra->serve_pid > 0) {
          fprintf(f, "<td>Running, %d</td>\n", extra->serve_pid);
        } else {
          fprintf(f, "<td>Waiting</td>\n");
        }
      }
    } else {
      fprintf(f, "<td>&nbsp;</td>\n");
    }

    // report run mastering status
    if (priv_level >= PRIV_LEVEL_ADMIN) {
      if (!cnts->run_managed && (!extra || !extra->run_used)) {
        fprintf(f, "<td><i>Not managed</i></td>\n");
      } else if (!extra || !extra->run_used) {
        fprintf(f, "<td bgcolor=\"#ffff88\">Not yet managed</td>\n");
      } else if (!cnts->run_managed) {
        // still managed, but not necessary
        if (extra->run_suspended) {
          fprintf(f, "<td bgcolor=\"#ff8888\">Failed, not managed</td>\n");
        } else if (extra->run_pid > 0) {
          fprintf(f, "<td bgcolor=\"#ffff88\">Running, %d, not managed</td>\n",
                  extra->run_pid);
        } else {
          fprintf(f, "<td bgcolor=\"#ffff88\">Waiting, not managed</td>\n");
        }
      } else {
        // managed as need to
        if (extra->run_suspended) {
          fprintf(f, "<td bgcolor=\"#ff8888\">Failed</td>\n");
        } else if (extra->run_pid > 0) {
          fprintf(f, "<td>Running, %d</td>\n", extra->run_pid);
        } else {
          fprintf(f, "<td>Waiting</td>\n");
        }
      }
    } else {
      fprintf(f, "<td>&nbsp;</td>\n");
    }

    // report judge URL
    if (opcaps_check(caps, OPCAP_JUDGE_LOGIN) >= 0 && judge_url[0]
        && contests_check_judge_ip_2(cnts, ip_address)) {
      fprintf(f, "<td><a href=\"%s?sid_mode=2&SID=%016llx&contest_id=%d\">Judge</a></td>\n",
              judge_url, session_id, contest_id);
    } else {
      fprintf(f, "<td>&nbsp;</td>\n");
    }
    // report master URL
    if (opcaps_check(caps, OPCAP_MASTER_LOGIN) >= 0 && master_url[0]
        && contests_check_master_ip_2(cnts, ip_address)) {
      fprintf(f, "<td><a href=\"%s?sid_mode=2&SID=%016llx&contest_id=%d\">Master</a></td>\n",
              master_url, session_id, contest_id);
    } else {
      fprintf(f, "<td>&nbsp;</td>\n");
    }

    if (priv_level >= PRIV_LEVEL_ADMIN
        && opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0
        && contests_check_serve_control_ip_2(cnts, ip_address)) {
      fprintf(f, "<td><a href=\"%s\">Details</a></td>\n",
              hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                       "contest_id=%d&action=%d", contest_id,
                       SUPER_ACTION_VIEW_CONTEST));
    } else {
      fprintf(f, "<td>&nbsp;</td>\n");
    }

    fprintf(f, "</tr>\n");
  }
  fprintf(f, "</table>\n");
  return 0;
}

static const unsigned char * const mng_status_table[] =
{
  [MNG_STAT_NOT_MANAGED] = "not managed",
  [MNG_STAT_TEMP_NOT_MANAGED] = "temporarily not managed",
  [MNG_STAT_TEMP_FAILED] = "temporarily managed, failed to start",
  [MNG_STAT_TEMP_RUNNING] = "temporarily managed, running as pid %d",
  [MNG_STAT_TEMP_WAITING] = "temporarily managed, waiting",
  [MNG_STAT_FAILED] = "managed, failed to start",
  [MNG_STAT_RUNNING] = "managed, running as pid %d",
  [MNG_STAT_WAITING] = "managed, waiting",
};

int
super_html_contest_page(FILE *f,
                        int priv_level,
                        int user_id,
                        int contest_id,
                        const unsigned char *login,
                        unsigned long long session_id,
                        unsigned long ip_address,
                        struct userlist_cfg *config,
                        const unsigned char *self_url,
                        const unsigned char *hidden_vars,
                        const unsigned char *extra_args)
{
  unsigned char judge_url[1024] = { 0 };
  unsigned char master_url[1024] = { 0 };
  unsigned char prog_pat[128];
  unsigned char hbuf[1024];
  unsigned char contest_id_hidden[1024];
  unsigned char mng_status_str[128];
  unsigned char log_file_path[1024];
  int prog_pat_len, self_url_len;
  int errcode;
  struct contest_desc *cnts;
  struct contest_extra *extra;
  opcap_t caps;
  unsigned char *str;
  int mng_status, nodevnull = 0, logfilemode = 0;
  struct stat devnullstat, logfilestat;
  unsigned char *raw_log, *html_log;

#if defined CGI_PROG_SUFFIX
  snprintf(prog_pat, sizeof(prog_pat), "serve-control%s", CGI_PROG_SUFFIX);
#else
  snprintf(prog_pat, sizeof(prog_pat), "serve-control");
#endif
  prog_pat_len = strlen(prog_pat);
  self_url_len = strlen(self_url);
  if (self_url_len > prog_pat_len
      && !strcmp(self_url + self_url_len - prog_pat_len, prog_pat)) {
    snprintf(judge_url, sizeof(judge_url),
             "%.*sjudge", self_url_len - prog_pat_len, self_url);
    snprintf(master_url, sizeof(master_url),
             "%.*smaster", self_url_len - prog_pat_len, self_url);

  }

  snprintf(contest_id_hidden, sizeof(contest_id_hidden),
           "<input type=\"hidden\" name=\"contest_id\" value=\"%d\">",
           contest_id);

  if ((errcode = contests_get(contest_id, &cnts)) < 0) {
    if (priv_level < PRIV_LEVEL_ADMIN) {
      err("super_html_contest_page: cannot parse contest.xml file");
      return -SSERV_ERR_INVALID_CONTEST;
    }
    if (!(raw_log = logged_contest_get(config, contest_id))) {
      err("super_html_contest_page: logged_contest_get failed");
      return -SSERV_ERR_INVALID_CONTEST;
    }
    html_log = html_armor_string_dup(raw_log);
    xfree(raw_log);

    fprintf(f, "<h2>Detailed information about contest %d</h2>\n", contest_id);

    fprintf(f, "<p>Loading of the contest failed.\n");
    fprintf(f, "<hr><pre>%s</pre></hr>", html_log);
    xfree(html_log);
    return 0;
  }
  extra = get_existing_contest_extra(contest_id);

  if (opcaps_find(&cnts->capabilities, login, &caps) < 0) {
    err("super_html_contest_page: not enough privileges");
    return -SSERV_ERR_PERMISSION_DENIED;
  }

  if (opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0
      && opcaps_check(caps, OPCAP_JUDGE_LOGIN) < 0) {
    err("super_html_contest_page: not enough privileges");
    return -SSERV_ERR_PERMISSION_DENIED;
  }

  if (!contests_check_serve_control_ip_2(cnts, ip_address)) {
    err("super_html_contest_page: invalid IP address");
    return -SSERV_ERR_BANNED_IP;
  }
  
  fprintf(f, "<h2>Detailed information about contest %d</h2>\n", contest_id);

  fprintf(f, "<table>\n");

  // report contest_id
  fprintf(f, "<tr><td>Contest ID:</td><td>%d</td></tr>\n", contest_id);
  str = html_armor_string_dup(cnts->name);
  fprintf(f, "<tr><td>Contest name:</td><td>%s</td></tr>\n", str);
  xfree(str);
  if (cnts->name_en) {
    str = html_armor_string_dup(cnts->name_en);
    fprintf(f, "<tr><td>Contest name (en):</td><td>%s</td></tr>\n", str);
    xfree(str);
  }

  // report judge URL
  if (opcaps_check(caps, OPCAP_JUDGE_LOGIN) >= 0 && judge_url[0]
      && contests_check_judge_ip_2(cnts, ip_address)) {
    fprintf(f, "<tr><td>Judge CGI program</td><td><a href=\"%s?sid_mode=2&SID=%016llx&contest_id=%d\">Judge</a></td></tr>\n",
            judge_url, session_id, contest_id);
  }

  // report master URL
  if (opcaps_check(caps, OPCAP_MASTER_LOGIN) >= 0 && master_url[0]
      && contests_check_master_ip_2(cnts, ip_address)) {
    fprintf(f, "<tr><td>Master CGI program</td><td><a href=\"%s?sid_mode=2&SID=%016llx&contest_id=%d\">Master</a></td></tr>\n",
            master_url, session_id, contest_id);
  }

  // participant's status
  fprintf(f, "<tr><td>Open for participation?</td><td>%s</td>",
          cnts->closed?"closed":"open");
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0) {
    fprintf(f, "<td>");
    html_start_form(f, 1, session_id, self_url, hidden_vars,
                    contest_id_hidden);
    if (cnts->closed) {
      html_submit_button(f, SUPER_ACTION_OPEN_CONTEST, "Open");
    } else {
      html_submit_button(f, SUPER_ACTION_CLOSE_CONTEST, "Close");
    }
    fprintf(f, "</form>");
    fprintf(f, "</td>");
  }
  fprintf(f, "</tr>\n");

  // visibility
  fprintf(f, "<tr><td>Visible for <tt>serve-control</tt>?</td><td>%s</td>",
          cnts->invisible?"invisible":"visible");
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0) {
    fprintf(f, "<td>");
    html_start_form(f, 1, session_id, self_url, hidden_vars,
                    contest_id_hidden);
    if (cnts->invisible) {
      html_submit_button(f, SUPER_ACTION_CONTEST_VISIBLE, "Make visible");
    } else {
      html_submit_button(f, SUPER_ACTION_CONTEST_INVISIBLE, "Make invisible");
    }
    fprintf(f, "</form>");
    fprintf(f, "</td>");
  }
  fprintf(f, "</tr>\n");

  // report serve status
  mng_status = get_serve_management_status(cnts, extra);
  snprintf(mng_status_str, sizeof(mng_status_str),
           mng_status_table[mng_status], extra?extra->serve_pid:0);
  fprintf(f, "<tr><td><tt>serve</tt> management status:</td><td>%s</td>",
          mng_status_str);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0) {
    fprintf(f, "<td>");
    html_start_form(f, 1, session_id, self_url, hidden_vars,
                    contest_id_hidden);
    switch (mng_status) {
    case MNG_STAT_NOT_MANAGED:
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_TEMP,
                         "Manage temporarily");
      html_submit_button(f, SUPER_ACTION_SERVE_MNG, "Manage permanently");
      break;
    case MNG_STAT_TEMP_NOT_MANAGED:
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_RESUME,
                         "Resume management");
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_STOP, "Stop management");
      break;
    case MNG_STAT_TEMP_FAILED:
      html_submit_button(f, SUPER_ACTION_SERVE_MNG, "Manage permanently");
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_STOP, "Stop management");
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_RESET_ERROR,
                         "Reset error flag");
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_PROBE_RUN,
                         "Do probe run");
      break;
    case MNG_STAT_TEMP_RUNNING:
      html_submit_button(f, SUPER_ACTION_SERVE_MNG, "Manage permanently");
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_STOP, "Stop management");
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_TERM, "Terminate serve");
      break;
    case MNG_STAT_TEMP_WAITING:
      html_submit_button(f, SUPER_ACTION_SERVE_MNG, "Manage permanently");
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_STOP, "Stop management");
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_PROBE_RUN,
                         "Do probe run");
      break;
    case MNG_STAT_FAILED:
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_SUSPEND,
                         "Suspend management");
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_STOP, "Stop management");
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_RESET_ERROR,
                         "Reset error flag");
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_PROBE_RUN,
                         "Do probe run");
      break;
    case MNG_STAT_RUNNING:
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_SUSPEND,
                         "Suspend management");
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_STOP, "Stop management");
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_TERM, "Terminate serve");
      break;
    case MNG_STAT_WAITING:
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_SUSPEND,
                         "Suspend management");
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_STOP,
                         "Stop management");
      html_submit_button(f, SUPER_ACTION_SERVE_MNG_PROBE_RUN,
                         "Do probe run");
      break;
    default:
      abort();
    }
    fprintf(f, "</form>");
    fprintf(f, "</td>");
  }

  // whether /dev/null exists?
  if (stat("/dev/null", &devnullstat) < 0) {
    // :( how come???
    nodevnull = 1;
  }

  // serve log file status
  if (!cnts->root_dir) {
    logfilemode = 3;
    snprintf(mng_status_str, sizeof(mng_status_str), "N/A");
  } else {
    snprintf(log_file_path, sizeof(log_file_path),
             "%s/var/messages", cnts->root_dir);
    if (stat(log_file_path, &logfilestat) < 0) {
      logfilemode = 0;
      snprintf(mng_status_str, sizeof(mng_status_str), "nonexistant");
    } else if (!nodevnull
               && logfilestat.st_dev == devnullstat.st_dev
               && logfilestat.st_ino == devnullstat.st_ino) {
      logfilemode = 1;
      snprintf(mng_status_str, sizeof(mng_status_str), "/dev/null");
    } else {
      logfilemode = 2;
      snprintf(mng_status_str, sizeof(mng_status_str), "%lld bytes",
               (long long) logfilestat.st_size);
    }
  }

  fprintf(f, "<tr><td>Serve log:</td><td>%s</td>", mng_status_str);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0
      && logfilemode != 3) {
    fprintf(f, "<td>");
    html_start_form(f, 1, session_id, self_url, hidden_vars,
                    contest_id_hidden);
    if (logfilemode == 0) {
      html_submit_button(f, SUPER_ACTION_SERVE_LOG_DEV_NULL,
                         "Redirect to /dev/null");
    } else if (logfilemode == 2) {
      html_submit_button(f, SUPER_ACTION_SERVE_LOG_TRUNC, "Truncate log");
      html_submit_button(f, SUPER_ACTION_SERVE_LOG_DEV_NULL,
                         "Redirect to /dev/null");
      if (logfilestat.st_size <= MAX_LOG_VIEW_SIZE) {
        fprintf(f, "<a href=\"%s\">View</a>",
                hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                         "contest_id=%d&action=%d", contest_id,
                         SUPER_ACTION_SERVE_LOG_VIEW));
      }
    } else if (logfilemode == 1) {
      html_submit_button(f, SUPER_ACTION_SERVE_LOG_FILE, "Redirect to file");
    }
    fprintf(f, "</form>");
    fprintf(f, "</td>");
  }
  fprintf(f, "</tr>\n");

  // report run status
  mng_status = get_run_management_status(cnts, extra);
  snprintf(mng_status_str, sizeof(mng_status_str),
           mng_status_table[mng_status], extra?extra->run_pid:0);
  fprintf(f, "<tr><td><tt>run</tt> management status:</td><td>%s</td>",
          mng_status_str);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0) {
    fprintf(f, "<td>");
    html_start_form(f, 1, session_id, self_url, hidden_vars,
                    contest_id_hidden);
    switch (mng_status) {
    case MNG_STAT_NOT_MANAGED:
      html_submit_button(f, SUPER_ACTION_RUN_MNG_TEMP,
                         "Manage temporarily");
      html_submit_button(f, SUPER_ACTION_RUN_MNG, "Manage permanently");
      break;
    case MNG_STAT_TEMP_NOT_MANAGED:
      html_submit_button(f, SUPER_ACTION_RUN_MNG_RESUME,
                         "Resume management");
      html_submit_button(f, SUPER_ACTION_RUN_MNG_STOP, "Stop management");
      break;
    case MNG_STAT_TEMP_FAILED:
      html_submit_button(f, SUPER_ACTION_RUN_MNG, "Manage permanently");
      html_submit_button(f, SUPER_ACTION_RUN_MNG_STOP, "Stop management");
      html_submit_button(f, SUPER_ACTION_RUN_MNG_RESET_ERROR,
                         "Reset error flag");
      html_submit_button(f, SUPER_ACTION_RUN_MNG_PROBE_RUN,
                         "Do probe run");
      break;
    case MNG_STAT_TEMP_RUNNING:
      html_submit_button(f, SUPER_ACTION_RUN_MNG, "Manage permanently");
      html_submit_button(f, SUPER_ACTION_RUN_MNG_STOP, "Stop management");
      html_submit_button(f, SUPER_ACTION_RUN_MNG_TERM, "Terminate serve");
      break;
    case MNG_STAT_TEMP_WAITING:
      html_submit_button(f, SUPER_ACTION_RUN_MNG, "Manage permanently");
      html_submit_button(f, SUPER_ACTION_RUN_MNG_STOP, "Stop management");
      html_submit_button(f, SUPER_ACTION_RUN_MNG_PROBE_RUN,
                         "Do probe run");
      break;
    case MNG_STAT_FAILED:
      html_submit_button(f, SUPER_ACTION_RUN_MNG_SUSPEND,
                         "Suspend management");
      html_submit_button(f, SUPER_ACTION_RUN_MNG_STOP, "Stop management");
      html_submit_button(f, SUPER_ACTION_RUN_MNG_RESET_ERROR,
                         "Reset error flag");
      html_submit_button(f, SUPER_ACTION_RUN_MNG_PROBE_RUN,
                         "Do probe run");
      break;
    case MNG_STAT_RUNNING:
      html_submit_button(f, SUPER_ACTION_RUN_MNG_SUSPEND,
                         "Suspend management");
      html_submit_button(f, SUPER_ACTION_RUN_MNG_STOP, "Stop management");
      html_submit_button(f, SUPER_ACTION_RUN_MNG_TERM, "Terminate serve");
      break;
    case MNG_STAT_WAITING:
      html_submit_button(f, SUPER_ACTION_RUN_MNG_SUSPEND,
                         "Suspend management");
      html_submit_button(f, SUPER_ACTION_RUN_MNG_STOP,
                         "Stop management");
      html_submit_button(f, SUPER_ACTION_RUN_MNG_PROBE_RUN,
                         "Do probe run");
      break;
    default:
      abort();
    }
    fprintf(f, "</form>");
    fprintf(f, "</td>");
  }

  // run log file status
  if (!cnts->root_dir) {
    logfilemode = 3;
    snprintf(mng_status_str, sizeof(mng_status_str), "N/A");
  } else {
    snprintf(log_file_path, sizeof(log_file_path),
             "%s/var/run_messages", cnts->root_dir);
    if (stat(log_file_path, &logfilestat) < 0) {
      logfilemode = 0;
      snprintf(mng_status_str, sizeof(mng_status_str), "nonexistant");
    } else if (!nodevnull
               && logfilestat.st_dev == devnullstat.st_dev
               && logfilestat.st_ino == devnullstat.st_ino) {
      logfilemode = 1;
      snprintf(mng_status_str, sizeof(mng_status_str), "/dev/null");
    } else {
      logfilemode = 2;
      snprintf(mng_status_str, sizeof(mng_status_str), "%lld bytes",
               (long long) logfilestat.st_size);
    }
  }

  fprintf(f, "<tr><td>Run log:</td><td>%s</td>", mng_status_str);
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0
      && logfilemode != 3) {
    fprintf(f, "<td>");
    html_start_form(f, 1, session_id, self_url, hidden_vars,
                    contest_id_hidden);
    if (logfilemode == 0) {
      html_submit_button(f, SUPER_ACTION_RUN_LOG_DEV_NULL,
                         "Redirect to /dev/null");
    } else if (logfilemode == 2) {
      html_submit_button(f, SUPER_ACTION_RUN_LOG_TRUNC, "Truncate log");
      html_submit_button(f, SUPER_ACTION_RUN_LOG_DEV_NULL,
                         "Redirect to /dev/null");
      if (logfilestat.st_size <= MAX_LOG_VIEW_SIZE) {
        fprintf(f, "<a href=\"%s\">View</a>",
                hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                         "contest_id=%d&action=%d", contest_id,
                         SUPER_ACTION_RUN_LOG_VIEW));
      }
    } else {
      html_submit_button(f, SUPER_ACTION_RUN_LOG_FILE, "Redirect to file");
    }
    fprintf(f, "</form>");
    fprintf(f, "</td>");
  }
  fprintf(f, "</tr>\n");

  fprintf(f, "<tr><td>XML configuration file:</td><td>&nbsp;</td>");
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0) {
    fprintf(f, "<td><a href=\"%s\">View</a></td>",
            hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                     "contest_id=%d&action=%d", contest_id,
                     SUPER_ACTION_VIEW_CONTEST_XML));
  } else {
    fprintf(f, "<td>&nbsp;</td>");
  }
  fprintf(f, "</tr>\n");

  fprintf(f, "<tr><td>serve configuration file:</td><td>&nbsp;</td>");
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0) {
    fprintf(f, "<td><a href=\"%s\">View</a></td>",
            hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                     "contest_id=%d&action=%d", contest_id,
                     SUPER_ACTION_VIEW_SERVE_CFG));
  } else {
    fprintf(f, "<td>&nbsp;</td>");
  }
  fprintf(f, "</tr>\n");

  fprintf(f, "</table>\n");

  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0) {
    fprintf(f, "<p>");
    html_submit_button(f, SUPER_ACTION_CONTEST_RESTART, "Restart management");
  }

  fprintf(f, "<table border=\"0\"><tr>");
  fprintf(f, "<td><a href=\"%s\">Back</a></td>",
          hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args, 0));
  fprintf(f, "<td><a href=\"%s\">Refresh</a></td>",
          hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                   "contest_id=%d&action=%d", contest_id,
                   SUPER_ACTION_VIEW_CONTEST));
  fprintf(f, "<td><a href=\"%s\">Logout</a></td>",
          hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                   "action=%d", SUPER_ACTION_LOGOUT));
  fprintf(f, "</tr></table>");

  if (extra && extra->messages) {
    fprintf(f, "<hr><h3>Start-up messages</h3>\n");
    if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0) {
      fprintf(f, "<p>");
      html_submit_button(f, SUPER_ACTION_CONTEST_RESTART, "Clear");
    }
    html_log = html_armor_string_dupa(extra->messages);
    fprintf(f, "<p><pre>%s</pre>\n", html_log);
  }

  return 0;
}

int
super_html_log_page(FILE *f,
                    int cmd,
                    int priv_level,
                    int user_id,
                    int contest_id,
                    const unsigned char *login,
                    unsigned long long session_id,
                    unsigned long ip_address,
                    struct userlist_cfg *config,
                    const unsigned char *self_url,
                    const unsigned char *hidden_vars,
                    const unsigned char *extra_args)
{
  int errcode, refresh_action;
  struct contest_desc *cnts;
  opcap_t caps;
  unsigned char log_file_path[1024];
  const unsigned char *progname;
  struct stat devnullstat;
  struct stat logfilestat;
  char *raw_log = 0;
  size_t raw_log_size = 0;
  unsigned char *html_log;
  unsigned char hbuf[1024];

  if ((errcode = contests_get(contest_id, &cnts)) < 0) {
    return -SSERV_ERR_INVALID_CONTEST;
  }
  if (priv_level < PRIV_LEVEL_JUDGE) {
    err("super_html_log_page: inappropriate privilege level");
    return -SSERV_ERR_PERMISSION_DENIED;
  }
  if (opcaps_find(&cnts->capabilities, login, &caps) < 0) {
    err("super_html_log_page: not enough privileges");
    return -SSERV_ERR_PERMISSION_DENIED;
  }
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0) {
    err("super_html_log_page: not enough privileges");
    return -SSERV_ERR_PERMISSION_DENIED;
  }
  if (!contests_check_serve_control_ip_2(cnts, ip_address)) {
    err("super_html_log_page: invalid IP address");
    return -SSERV_ERR_BANNED_IP;
  }
  if (!cnts->root_dir) {
    err("super_html_log_page: contest root dir is not set");
    return -SSERV_ERR_ROOT_DIR_NOT_SET;
  }
  switch (cmd) {
  case SSERV_CMD_VIEW_SERVE_LOG:
    snprintf(log_file_path, sizeof(log_file_path),
             "%s/var/messages", cnts->root_dir);
    progname = "serve";
    refresh_action = SUPER_ACTION_SERVE_LOG_VIEW;
    break;
  case SSERV_CMD_VIEW_RUN_LOG:
    snprintf(log_file_path, sizeof(log_file_path),
             "%s/var/run_messages", cnts->root_dir);
    progname = "run";
    refresh_action = SUPER_ACTION_RUN_LOG_VIEW;
    break;
  case SSERV_CMD_VIEW_CONTEST_XML:
    contests_make_path(log_file_path, sizeof(log_file_path), cnts->id);
    progname = "contest.xml";
    refresh_action = SUPER_ACTION_VIEW_CONTEST_XML;
    break;
  case SSERV_CMD_VIEW_SERVE_CFG:
    snprintf(log_file_path, sizeof(log_file_path),
             "%s/conf/serve.cfg", cnts->root_dir);
    progname = "serve.cfg";
    refresh_action = SUPER_ACTION_VIEW_SERVE_CFG;
    break;
  default:
    abort();
  }
  if (stat(log_file_path, &logfilestat) < 0) {
    err("super_html_log_page: stat failed: %s", os_ErrorMsg());
    return -SSERV_ERR_FILE_NOT_EXIST;
  }
  if (stat("/dev/null", &devnullstat) >= 0
      && devnullstat.st_dev == logfilestat.st_dev
      && devnullstat.st_ino == logfilestat.st_ino) {
    err("super_html_log_page: log is redirected to /dev/null");
    return -SSERV_ERR_LOG_IS_DEV_NULL;
  }

  switch (cmd) {
  case SSERV_CMD_VIEW_SERVE_LOG:
  case SSERV_CMD_VIEW_RUN_LOG:
    fprintf(f, "<h2><tt>%s</tt> log file</h2>\n", progname);
    break;
  case SSERV_CMD_VIEW_CONTEST_XML:
  case SSERV_CMD_VIEW_SERVE_CFG:
    fprintf(f, "<h2><tt>%s</tt> configuration file</h2>\n", progname);
    break;
  }

  fprintf(f, "<table border=\"0\"><tr>");
  fprintf(f, "<td><a href=\"%s\">To contests list</a></td>",
          hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args, 0));
  fprintf(f, "<td><a href=\"%s\">To contest details</a></td>",
          hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                   "contest_id=%d&action=%d", contest_id,
                   SUPER_ACTION_VIEW_CONTEST));
  fprintf(f, "<td><a href=\"%s\">Refresh</a></td>",
          hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                   "contest_id=%d&action=%d", contest_id,
                   refresh_action));
  fprintf(f, "<td><a href=\"%s\">Logout</a></td>",
          hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                   "action=%d", SUPER_ACTION_LOGOUT));
  fprintf(f, "</tr></table>");

  if (generic_read_file(&raw_log, 0, &raw_log_size, 0,
                        0, log_file_path, 0) < 0) {
    return -SSERV_ERR_FILE_READ_ERROR;
  }

  /* FIXME: colorize logs? */
  html_log = html_armor_string_dup(raw_log);

  fprintf(f, "<hr>\n<pre>%s</pre>\n", html_log);
  xfree(html_log);
  xfree(raw_log);

  return 0;
}

int
super_html_parse_contest_xml(int contest_id,
                             unsigned char **before_start,
                             unsigned char **after_start)
{
  unsigned char path[1024];
  char *raw_xml = 0, *s, *p;
  unsigned char *xml_1 = 0, *xml_2 = 0;
  size_t raw_xml_size = 0;
  struct stat statbuf;
  int errcode;

  contests_make_path(path, sizeof(path), contest_id);
  if (stat(path, &statbuf) < 0) return -SSERV_ERR_FILE_NOT_EXIST;

  if (generic_read_file(&raw_xml, 0, &raw_xml_size, 0,
                        0, path, 0) < 0) {
    return -SSERV_ERR_FILE_READ_ERROR;
  }

  xml_1 = (unsigned char*) xmalloc(raw_xml_size + 10);
  xml_2 = (unsigned char*) xmalloc(raw_xml_size + 10);

  // find opening <contest tag
  s = raw_xml;
  while (*s) {
    if (s[0] != '<') {
      s++;
      continue;
    }
    if (s[1] == '!' && s[2] == '-' && s[3] == '-') {
      while (*s) {
        if (s[0] == '-' && s[1] == '-' && s[2] == '>') break;
        s++;
      }
      if (!*s) break;
      continue;
    }
    p = s;
    p++;
    while (*p && isspace(*p)) s++;
    if (!*p) {
      errcode = -SSERV_ERR_FILE_FORMAT_INVALID;
      goto failure;
    }
    if (!strncmp(p, "contest", 7) && p[7] && isspace(p[7])) break;
    s++;
  }
  if (!*s) {
    errcode = -SSERV_ERR_FILE_FORMAT_INVALID;
    goto failure;
  }

  memcpy(xml_1, raw_xml, s - raw_xml);
  xml_1[s - raw_xml] = 0;

  // find closing > tag
  while (*s && *s != '>') s++;
  if (!*s) {
    errcode = -SSERV_ERR_FILE_FORMAT_INVALID;
    goto failure;
  }
  s++;
  strcpy(xml_2, s);

  *before_start = xml_1;
  *after_start = xml_2;
  xfree(raw_xml);
  return 0;

 failure:
  xfree(xml_1);
  xfree(xml_2);
  xfree(raw_xml);
  return errcode;
}

// assume, that the permissions are checked
int
super_html_open_contest(struct contest_desc *cnts, int user_id,
                        const unsigned char *user_login)
{
  int errcode;
  unsigned char *txt1, *txt2;
  unsigned char audit_str[1024];

  if (!cnts->closed) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->closed = 0;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: closed->open %s %d (%s) -->\n",
           xml_unparse_date(time(0)), user_id, user_login);

  if ((errcode = contests_save_xml(cnts, txt1, txt2, audit_str)) < 0) {
    xfree(txt1);
    xfree(txt2);
    return -SSERV_ERR_SYSTEM_ERROR;
  }

  xfree(txt1);
  xfree(txt2);
  return 0;
}

int
super_html_close_contest(struct contest_desc *cnts, int user_id,
                         const unsigned char *user_login)
{
  int errcode = 0;
  unsigned char *txt1 = 0, *txt2 = 0;
  unsigned char audit_str[1024];

  if (cnts->closed) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->closed = 1;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: open->closed %s %d (%s) -->\n",
           xml_unparse_date(time(0)), user_id, user_login);

  if ((errcode = contests_save_xml(cnts, txt1, txt2, audit_str)) < 0) {
    xfree(txt1);
    xfree(txt2);
    return -SSERV_ERR_SYSTEM_ERROR;
  }

  xfree(txt1);
  xfree(txt2);
  return 0;
}

int
super_html_make_invisible_contest(struct contest_desc *cnts, int user_id,
                                  const unsigned char *user_login)
{
  int errcode;
  unsigned char *txt1, *txt2;
  unsigned char audit_str[1024];

  if (cnts->invisible) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->invisible = 1;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: visible->invisible %s %d (%s) -->\n",
           xml_unparse_date(time(0)), user_id, user_login);

  if ((errcode = contests_save_xml(cnts, txt1, txt2, audit_str)) < 0) {
    xfree(txt1);
    xfree(txt2);
    return -SSERV_ERR_SYSTEM_ERROR;
  }

  xfree(txt1);
  xfree(txt2);
  return 0;
}

int
super_html_make_visible_contest(struct contest_desc *cnts, int user_id,
                                const unsigned char *user_login)
{
  int errcode;
  unsigned char *txt1, *txt2;
  unsigned char audit_str[1024];

  if (!cnts->invisible) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->invisible = 0;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: invisible->visible %s %d (%s) -->\n",
           xml_unparse_date(time(0)), user_id, user_login);

  if ((errcode = contests_save_xml(cnts, txt1, txt2, audit_str)) < 0) {
    xfree(txt1);
    xfree(txt2);
    return -SSERV_ERR_SYSTEM_ERROR;
  }

  xfree(txt1);
  xfree(txt2);
  return 0;
}

int
super_html_serve_managed_contest(struct contest_desc *cnts, int user_id,
                                 const unsigned char *user_login)
{
  int errcode;
  unsigned char *txt1, *txt2;
  unsigned char audit_str[1024];

  if (cnts->managed) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->managed = 1;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: unmanaged->managed %s %d (%s) -->\n",
           xml_unparse_date(time(0)), user_id, user_login);

  if ((errcode = contests_save_xml(cnts, txt1, txt2, audit_str)) < 0) {
    xfree(txt1);
    xfree(txt2);
    return -SSERV_ERR_SYSTEM_ERROR;
  }

  xfree(txt1);
  xfree(txt2);
  return 0;
}

int
super_html_serve_unmanaged_contest(struct contest_desc *cnts, int user_id,
                                   const unsigned char *user_login)
{
  int errcode;
  unsigned char *txt1, *txt2;
  unsigned char audit_str[1024];

  if (!cnts->managed) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->managed = 0;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: managed->unmanaged %s %d (%s) -->\n",
           xml_unparse_date(time(0)), user_id, user_login);

  if ((errcode = contests_save_xml(cnts, txt1, txt2, audit_str)) < 0) {
    xfree(txt1);
    xfree(txt2);
    return -SSERV_ERR_SYSTEM_ERROR;
  }

  xfree(txt1);
  xfree(txt2);
  return 0;
}

int
super_html_run_managed_contest(struct contest_desc *cnts, int user_id,
                               const unsigned char *user_login)
{
  int errcode;
  unsigned char *txt1, *txt2;
  unsigned char audit_str[1024];

  if (cnts->run_managed) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->run_managed = 1;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: run_unmanaged->run_managed %s %d (%s) -->\n",
           xml_unparse_date(time(0)), user_id, user_login);

  if ((errcode = contests_save_xml(cnts, txt1, txt2, audit_str)) < 0) {
    xfree(txt1);
    xfree(txt2);
    return -SSERV_ERR_SYSTEM_ERROR;
  }

  xfree(txt1);
  xfree(txt2);
  return 0;
}

int
super_html_run_unmanaged_contest(struct contest_desc *cnts, int user_id,
                                 const unsigned char *user_login)
{
  int errcode;
  unsigned char *txt1, *txt2;
  unsigned char audit_str[1024];

  if (!cnts->run_managed) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->run_managed = 0;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: run_managed->run_unmanaged %s %d (%s) -->\n",
           xml_unparse_date(time(0)), user_id, user_login);

  if ((errcode = contests_save_xml(cnts, txt1, txt2, audit_str)) < 0) {
    xfree(txt1);
    xfree(txt2);
    return -SSERV_ERR_SYSTEM_ERROR;
  }

  xfree(txt1);
  xfree(txt2);
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
