/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004-2007 Alexander Chernov <cher@ejudge.ru> */

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
#include "super_proto.h"
#include "contests.h"
#include "misctext.h"
#include "mischtml.h"
#include "opcaps.h"
#include "protocol.h"
#include "ejudge_cfg.h"
#include "pathutl.h"
#include "errlog.h"
#include "fileutl.h"
#include "xml_utils.h"
#include "prepare.h"
#include "vcs.h"

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
#include <time.h>

#define MAX_LOG_VIEW_SIZE (8 * 1024 * 1024)

static void
html_submit_button(FILE *f,
                   int action,
                   const unsigned char *label)
{
  fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\"/>",
          action, label);
}

static void
html_hidden_var(FILE *f, const unsigned char *name, const unsigned char *value)
{
  fprintf(f, "<input type=\"hidden\" name=\"%s\" value=\"%s\"/>", name, value);
}

static void
html_boolean_select(FILE *f,
                    int value,
                    const unsigned char *param_name,
                    const unsigned char *false_txt,
                    const unsigned char *true_txt)
{
  if (!false_txt) false_txt = "No";
  if (!true_txt) true_txt = "Yes";

  fprintf(f, "<select name=\"%s\"><option value=\"0\"%s>%s</option><option value=\"1\"%s>%s</option></select>",
          param_name,
          value?"":" selected=\"1\"", false_txt,
          value?" selected=\"1\"":"", true_txt);
}

static void
html_edit_text_form(FILE *f,
                    int size,
                    int maxlength,
                    const unsigned char *param_name,
                    const unsigned char *value)
{
  unsigned char *s, *p = "";

  if (!size) size = 48;
  if (!maxlength) maxlength = 1024;
  if (!value) p = "<i>(Not set)</i>";
  s = html_armor_string_dup(value);

  fprintf(f, "<input type=\"text\" name=\"%s\" value=\"%s\" size=\"%d\" maxlength=\"%d\"/>%s", param_name, s, size, maxlength, p);
  xfree(s);
}

static void
html_numeric_select(FILE *f, const unsigned char *param,
                    int val, int min_val, int max_val)
{
  int i;

  fprintf(f, "<select name=\"%s\">", param);
  for (i = min_val; i <= max_val; i++) {
    fprintf(f, "<option value=\"%d\"%s>%d</option>",
            i, (i == val)?" selected=\"1\"":"", i);
  }
  fprintf(f, "</select>");
}

enum
{
  MNG_STAT_FIRST,
  MNG_STAT_NOT_MANAGED = MNG_STAT_FIRST,
  MNG_STAT_NEW_MANAGED,
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
get_serve_management_status(const struct contest_desc *cnts,
                            struct contest_extra *extra)
{
  if (cnts->new_managed) {
    return MNG_STAT_NEW_MANAGED;
  } else if (!cnts->managed && (!extra || !extra->serve_used)) {
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
get_run_management_status(const struct contest_desc *cnts,
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
logged_contest_get(struct ejudge_cfg *config, int contest_id)
{
  unsigned char *dir_name = 0;
  unsigned char *s, *outbuf;
  unsigned char tmplog_path[1024];
  int serial = 0, tmplog_fd, saved_log_fd, errcode, sz, r;
  const struct contest_desc *cnts;
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
                     ej_cookie_t session_id,
                     ej_ip_t ip_address,
                     int ssl,
                     unsigned int flags,
                     struct ejudge_cfg *config,
                     struct sid_state *sstate,
                     const unsigned char *self_url,
                     const unsigned char *hidden_vars,
                     const unsigned char *extra_args)
{
  unsigned char *contests_map = 0;
  int contest_max_id, contest_id, errcode;
  unsigned char *html_name;
  const struct contest_desc *cnts;
  struct contest_extra *extra = 0;
  unsigned char hbuf[1024];
  opcap_t caps;
  unsigned char judge_url[1024] = { 0 };
  unsigned char master_url[1024] = { 0 };
  unsigned char client_url[1024] = { 0 };
  unsigned char new_judge_url[1024] = { 0 };
  unsigned char new_master_url[1024] = { 0 };
  unsigned char new_client_url[1024] = { 0 };
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
    snprintf(client_url, sizeof(client_url),
             "%.*steam", self_url_len - prog_pat_len, self_url);
    snprintf(new_judge_url, sizeof(new_judge_url),
             "%.*snew-judge", self_url_len - prog_pat_len, self_url);
    snprintf(new_master_url, sizeof(new_master_url),
             "%.*snew-master", self_url_len - prog_pat_len, self_url);
    snprintf(new_client_url, sizeof(new_client_url),
             "%.*snew-client", self_url_len - prog_pat_len, self_url);
  }

  fprintf(f, "<h2>Controls</h2>\n");

  fprintf(f, "<table border=\"0\"><tr>\n");
  fprintf(f, "<td>");
  html_start_form(f, 1, self_url, hidden_vars);
  if ((sstate->flags & SID_STATE_SHOW_HIDDEN)) {
    html_submit_button(f, SSERV_CMD_HIDE_HIDDEN, "Hide hidden contests");
  } else {
    html_submit_button(f, SSERV_CMD_SHOW_HIDDEN, "Show hidden contests");
  }
  fprintf(f, "</form></td>");
  fprintf(f, "<td>");
  html_start_form(f, 1, self_url, hidden_vars);
  if ((sstate->flags & SID_STATE_SHOW_CLOSED)) {
    html_submit_button(f, SSERV_CMD_HIDE_CLOSED, "Hide closed contests");
  } else {
    html_submit_button(f, SSERV_CMD_SHOW_CLOSED, "Show closed contests");
  }
  fprintf(f, "</form></td>");
  fprintf(f, "<td>");
  html_start_form(f, 1, self_url, hidden_vars);
  if ((sstate->flags & SID_STATE_SHOW_UNMNG)) {
    html_submit_button(f, SSERV_CMD_HIDE_UNMNG, "Hide unmanageable contests");
  } else {
    html_submit_button(f, SSERV_CMD_SHOW_UNMNG, "Show unmanageable contests");
  }
  fprintf(f, "</form></td>");
  fprintf(f, "</tr></table>");

  /*
  fprintf(f, "<table border=\"0\"><tr>\n");
  fprintf(f, "<td>");
  html_start_form(f, 1, session_id, self_url, hidden_vars);
  html_submit_button(f, SSERV_CMD_RESTART, "Restart the daemon");
  fprintf(f, "</form></td>");
  fprintf(f, "</tr></table>");
  */

  fprintf(f, "<table border=\"0\"><tr><td>%sCreate new contest</a></td>", html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args, "action=%d", SSERV_CMD_CREATE_CONTEST));
  if (sstate->edited_cnts) {
    fprintf(f, "<td>%sEdit current contest</a></td>",
            html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                          "action=%d", SSERV_CMD_EDIT_CURRENT_CONTEST));
  }
  fprintf(f, "</tr></table>\n");

  fprintf(f, "<table border=\"0\"><tr><td>%sRefresh</a></td></tr></table>\n", html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args, 0));

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
          "<th>User</th>\n"
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
      fprintf(f, "<td>%sDetails</a></td>\n",
              html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                            "contest_id=%d&action=%d", contest_id,
                            SSERV_CMD_CONTEST_PAGE));
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
      fprintf(f, "<td>%sDetails</a></td>\n",
              html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                            "contest_id=%d&action=%d", contest_id,
                            SSERV_CMD_CONTEST_PAGE));
      continue;
    }
    if (priv_level < PRIV_LEVEL_ADMIN && !(sstate->flags & SID_STATE_SHOW_UNMNG)) {
      // skip contests, where nor ADMIN neither JUDGE permissions are set
      if (opcaps_find(&cnts->capabilities, login, &caps) < 0) continue;
      if (opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0
          && opcaps_check(caps, OPCAP_JUDGE_LOGIN) < 0) continue;
    } else {
      caps = 0;
      opcaps_find(&cnts->capabilities, login, &caps);
    }

    if (!(sstate->flags & SID_STATE_SHOW_HIDDEN) && cnts->invisible) continue;
    if (!(sstate->flags & SID_STATE_SHOW_CLOSED) && cnts->closed) continue;

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
      if (cnts->new_managed) {
        fprintf(f, "<td><font color=\"green\"><i>New server</i></font></td>\n");
      } else if (!cnts->managed && (!extra || !extra->serve_used)) {
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
        && contests_check_judge_ip_2(cnts, ip_address, ssl)) {
      if (cnts->new_managed) {
        fprintf(f, "<td><a href=\"%s?SID=%016llx&contest_id=%d&action=3\" target=\"_blank\">Judge</a></td>\n",
                new_judge_url, session_id, contest_id);
      } else {
        fprintf(f, "<td><a href=\"%s?SID=%016llx&contest_id=%d\" target=\"_blank\">Judge</a></td>\n",
                judge_url, session_id, contest_id);
      }
    } else {
      fprintf(f, "<td>&nbsp;</td>\n");
    }
    // report master URL
    if (opcaps_check(caps, OPCAP_MASTER_LOGIN) >= 0 && master_url[0]
        && contests_check_master_ip_2(cnts, ip_address, ssl)) {
      if (cnts->new_managed) {
        fprintf(f, "<td><a href=\"%s?SID=%016llx&contest_id=%d&action=3\" target=\"_blank\">Master</a></td>\n",
                new_master_url, session_id, contest_id);
      } else {
        fprintf(f, "<td><a href=\"%s?SID=%016llx&contest_id=%d\" target=\"_blank\">Master</a></td>\n",
                master_url, session_id, contest_id);
      }
    } else {
      fprintf(f, "<td>&nbsp;</td>\n");
    }
    // report user URL
    if (client_url[0] && contests_check_team_ip_2(cnts, ip_address, ssl)) {
      if (cnts->new_managed) {
        fprintf(f, "<td><a href=\"%s?contest_id=%d\" target=\"_blank\">User</a></td>\n",
                new_client_url, contest_id);
      } else {
        fprintf(f, "<td><a href=\"%s?contest_id=%d\" target=\"_blank\">User</a></td>\n",
                client_url, contest_id);
      }
    } else {
      fprintf(f, "<td>&nbsp;</td>\n");
    }

    if (priv_level >= PRIV_LEVEL_ADMIN
        && opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0
        && contests_check_serve_control_ip_2(cnts, ip_address, ssl)) {
      fprintf(f, "<td>%sDetails</a></td>\n",
              html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                            "contest_id=%d&action=%d", contest_id,
                            SSERV_CMD_CONTEST_PAGE));
    } else {
      fprintf(f, "<td>&nbsp;</td>\n");
    }

    fprintf(f, "</tr>\n");
  }
  fprintf(f, "</table>\n");

  xfree(contests_map);
  return 0;
}

static const unsigned char * const mng_status_table[] =
{
  [MNG_STAT_NOT_MANAGED] = "not managed",
  [MNG_STAT_NEW_MANAGED] = "new server",
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
                        ej_cookie_t session_id,
                        ej_ip_t ip_address,
                        int ssl,
                        struct ejudge_cfg *config,
                        const unsigned char *self_url,
                        const unsigned char *hidden_vars,
                        const unsigned char *extra_args)
{
  unsigned char judge_url[1024] = { 0 };
  unsigned char master_url[1024] = { 0 };
  unsigned char client_url[1024] = { 0 };
  unsigned char new_judge_url[1024] = { 0 };
  unsigned char new_master_url[1024] = { 0 };
  unsigned char new_client_url[1024] = { 0 };
  unsigned char prog_pat[128];
  unsigned char hbuf[1024];
  unsigned char new_hidden_vars[1024];
  unsigned char mng_status_str[128];
  unsigned char log_file_path[1024];
  int prog_pat_len, self_url_len;
  int errcode, refcount;
  const struct contest_desc *cnts;
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
    snprintf(client_url, sizeof(client_url),
             "%.*steam", self_url_len - prog_pat_len, self_url);
    snprintf(new_judge_url, sizeof(new_judge_url),
             "%.*snew-judge", self_url_len - prog_pat_len, self_url);
    snprintf(new_master_url, sizeof(new_master_url),
             "%.*snew-master", self_url_len - prog_pat_len, self_url);
    snprintf(new_client_url, sizeof(new_client_url),
             "%.*snew-client", self_url_len - prog_pat_len, self_url);
  }

  snprintf(new_hidden_vars, sizeof(new_hidden_vars),
           "%s<input type=\"hidden\" name=\"contest_id\" value=\"%d\"/>",
           hidden_vars, contest_id);

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

  if (!contests_check_serve_control_ip_2(cnts, ip_address, ssl)) {
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
  if (cnts->main_url) {
    fprintf(f, "<tr><td>Contest main URL:</td><td><tt><a href=\"%s\" target=\"_blank\">%s</a></tt></td></tr>\n", cnts->main_url, cnts->main_url);
  }

  // report judge URL
  if (opcaps_check(caps, OPCAP_JUDGE_LOGIN) >= 0 && judge_url[0]
      && contests_check_judge_ip_2(cnts, ip_address, ssl)) {
    if (cnts->new_managed) {
      fprintf(f, "<tr><td>Judge CGI program</td><td><a href=\"%s?SID=%016llx&contest_id=%d&action=3\" target=\"_blank\">Judge</a></td></tr>\n",
              new_judge_url, session_id, contest_id);
    } else {
      fprintf(f, "<tr><td>Judge CGI program</td><td><a href=\"%s?SID=%016llx&contest_id=%d\" target=\"_blank\">Judge</a></td></tr>\n",
              judge_url, session_id, contest_id);
    }
  }

  // report master URL
  if (opcaps_check(caps, OPCAP_MASTER_LOGIN) >= 0 && master_url[0]
      && contests_check_master_ip_2(cnts, ip_address, ssl)) {
    if (cnts->new_managed) {
      fprintf(f, "<tr><td>Master CGI program</td><td><a href=\"%s?SID=%016llx&contest_id=%d&action=3\" target=\"_blank\">Master</a></td></tr>\n",
              new_master_url, session_id, contest_id);
    } else {
      fprintf(f, "<tr><td>Master CGI program</td><td><a href=\"%s?SID=%016llx&contest_id=%d\" target=\"_blank\">Master</a></td></tr>\n",
              master_url, session_id, contest_id);
    }
  }

  // report user URL
  if (client_url[0] && contests_check_team_ip_2(cnts, ip_address, ssl)) {
    if (cnts->new_managed) {
      fprintf(f, "<tr><td>Client CGI program</td><td><a href=\"%s?contest_id=%d\" target=\"_blank\">Client</a></td></tr>\n",
              new_client_url, contest_id);
    } else {
      fprintf(f, "<tr><td>Client CGI program</td><td><a href=\"%s?contest_id=%d\" target=\"_blank\">Client</a></td></tr>\n",
              client_url, contest_id);
    }
  }

  // participant's status
  fprintf(f, "<tr><td>Open for participation?</td><td>%s</td>",
          cnts->closed?"closed":"open");
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0) {
    fprintf(f, "<td>");
    html_start_form(f, 1, self_url, new_hidden_vars);
    if (cnts->closed) {
      html_submit_button(f, SSERV_CMD_OPEN_CONTEST, "Open");
    } else {
      html_submit_button(f, SSERV_CMD_CLOSE_CONTEST, "Close");
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
    html_start_form(f, 1, self_url, new_hidden_vars);
    if (cnts->invisible) {
      html_submit_button(f, SSERV_CMD_VISIBLE_CONTEST, "Make visible");
    } else {
      html_submit_button(f, SSERV_CMD_INVISIBLE_CONTEST, "Make invisible");
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
    html_start_form(f, 1, self_url, new_hidden_vars);
    switch (mng_status) {
    case MNG_STAT_NOT_MANAGED:
    case MNG_STAT_NEW_MANAGED:
      fprintf(f, "&nbsp;");
      /* FIXME: disabled for now
      html_submit_button(f, SSERV_CMD_SERVE_MNG_TEMP,
                         "Manage temporarily");
      html_submit_button(f, SSERV_CMD_SERVE_MNG, "Manage permanently");
      */
      break;
    case MNG_STAT_TEMP_NOT_MANAGED:
      fprintf(f, "&nbsp;");
      /*
      html_submit_button(f, SSERV_CMD_SERVE_MNG_RESUME,
                         "Resume management");
      html_submit_button(f, SSERV_CMD_SERVE_MNG_STOP, "Stop management");
      */
      break;
    case MNG_STAT_TEMP_FAILED:
      /*
      html_submit_button(f, SSERV_CMD_SERVE_MNG, "Manage permanently");
      html_submit_button(f, SSERV_CMD_SERVE_MNG_STOP, "Stop management");
      */
      html_submit_button(f, SSERV_CMD_SERVE_MNG_RESET_ERROR,
                         "Reset error flag");
      html_submit_button(f, SSERV_CMD_SERVE_MNG_PROBE_RUN,
                         "Do probe run");
      break;
    case MNG_STAT_TEMP_RUNNING:
      /*
      html_submit_button(f, SSERV_CMD_SERVE_MNG, "Manage permanently");
      html_submit_button(f, SSERV_CMD_SERVE_MNG_STOP, "Stop management");
      */
      html_submit_button(f, SSERV_CMD_SERVE_MNG_TERM, "Terminate serve");
      break;
    case MNG_STAT_TEMP_WAITING:
      /*
      html_submit_button(f, SSERV_CMD_SERVE_MNG, "Manage permanently");
      html_submit_button(f, SSERV_CMD_SERVE_MNG_STOP, "Stop management");
      */
      html_submit_button(f, SSERV_CMD_SERVE_MNG_PROBE_RUN,
                         "Do probe run");
      break;
    case MNG_STAT_FAILED:
      /*
      html_submit_button(f, SSERV_CMD_SERVE_MNG_SUSPEND,
                         "Suspend management");
      html_submit_button(f, SSERV_CMD_SERVE_MNG_STOP, "Stop management");
      */
      html_submit_button(f, SSERV_CMD_SERVE_MNG_RESET_ERROR,
                         "Reset error flag");
      html_submit_button(f, SSERV_CMD_SERVE_MNG_PROBE_RUN,
                         "Do probe run");
      break;
    case MNG_STAT_RUNNING:
      /*
      html_submit_button(f, SSERV_CMD_SERVE_MNG_SUSPEND,
                         "Suspend management");
      html_submit_button(f, SSERV_CMD_SERVE_MNG_STOP, "Stop management");
      */
      html_submit_button(f, SSERV_CMD_SERVE_MNG_TERM, "Terminate serve");
      break;
    case MNG_STAT_WAITING:
      fprintf(f, "&nbsp;");
      /*
      html_submit_button(f, SSERV_CMD_SERVE_MNG_SUSPEND,
                         "Suspend management");
      html_submit_button(f, SSERV_CMD_SERVE_MNG_STOP,
                         "Stop management");
      */
      html_submit_button(f, SSERV_CMD_SERVE_MNG_PROBE_RUN,
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
    html_start_form(f, 1, self_url, new_hidden_vars);
    if (logfilemode == 0) {
      html_submit_button(f, SSERV_CMD_SERVE_LOG_DEV_NULL,
                         "Redirect to /dev/null");
    } else if (logfilemode == 2) {
      html_submit_button(f, SSERV_CMD_SERVE_LOG_TRUNC, "Truncate log");
      html_submit_button(f, SSERV_CMD_SERVE_LOG_DEV_NULL,
                         "Redirect to /dev/null");
      if (logfilestat.st_size <= MAX_LOG_VIEW_SIZE) {
        fprintf(f, "%sView</a>",
                html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                              "contest_id=%d&action=%d", contest_id,
                              SSERV_CMD_VIEW_SERVE_LOG));
      }
    } else if (logfilemode == 1) {
      html_submit_button(f, SSERV_CMD_SERVE_LOG_FILE, "Redirect to file");
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
    html_start_form(f, 1, self_url, new_hidden_vars);
    switch (mng_status) {
    case MNG_STAT_NOT_MANAGED:
      fprintf(f, "&nbsp;");
      /*
      html_submit_button(f, SSERV_CMD_RUN_MNG_TEMP,
                         "Manage temporarily");
      html_submit_button(f, SSERV_CMD_RUN_MNG, "Manage permanently");
      */
      break;
    case MNG_STAT_TEMP_NOT_MANAGED:
      fprintf(f, "&nbsp;");
      /*
      html_submit_button(f, SSERV_CMD_RUN_MNG_RESUME,
                         "Resume management");
      html_submit_button(f, SSERV_CMD_RUN_MNG_STOP, "Stop management");
      */
      break;
    case MNG_STAT_TEMP_FAILED:
      /*
      html_submit_button(f, SSERV_CMD_RUN_MNG, "Manage permanently");
      html_submit_button(f, SSERV_CMD_RUN_MNG_STOP, "Stop management");
      */
      html_submit_button(f, SSERV_CMD_RUN_MNG_RESET_ERROR,
                         "Reset error flag");
      /*
      html_submit_button(f, SSERV_CMD_RUN_MNG_PROBE_RUN,
                         "Do probe run");
      */
      break;
    case MNG_STAT_TEMP_RUNNING:
      /*
      html_submit_button(f, SSERV_CMD_RUN_MNG, "Manage permanently");
      html_submit_button(f, SSERV_CMD_RUN_MNG_STOP, "Stop management");
      */
      html_submit_button(f, SSERV_CMD_RUN_MNG_TERM, "Terminate run");
      break;
    case MNG_STAT_TEMP_WAITING:
      fprintf(f, "&nbsp;");
      /*
      html_submit_button(f, SSERV_CMD_RUN_MNG, "Manage permanently");
      html_submit_button(f, SSERV_CMD_RUN_MNG_STOP, "Stop management");
      html_submit_button(f, SSERV_CMD_RUN_MNG_PROBE_RUN,
                         "Do probe run");
      */
      break;
    case MNG_STAT_FAILED:
      /*
      html_submit_button(f, SSERV_CMD_RUN_MNG_SUSPEND,
                         "Suspend management");
      html_submit_button(f, SSERV_CMD_RUN_MNG_STOP, "Stop management");
      */
      html_submit_button(f, SSERV_CMD_RUN_MNG_RESET_ERROR,
                         "Reset error flag");
      /*
      html_submit_button(f, SSERV_CMD_RUN_MNG_PROBE_RUN,
                         "Do probe run");
      */
      break;
    case MNG_STAT_RUNNING:
      /*
      html_submit_button(f, SSERV_CMD_RUN_MNG_SUSPEND,
                         "Suspend management");
      html_submit_button(f, SSERV_CMD_RUN_MNG_STOP, "Stop management");
      */
      html_submit_button(f, SSERV_CMD_RUN_MNG_TERM, "Terminate run");
      break;
    case MNG_STAT_WAITING:
      fprintf(f, "&nbsp;");
      /*
      html_submit_button(f, SSERV_CMD_RUN_MNG_SUSPEND,
                         "Suspend management");
      html_submit_button(f, SSERV_CMD_RUN_MNG_STOP,
                         "Stop management");
      html_submit_button(f, SSERV_CMD_RUN_MNG_PROBE_RUN,
                         "Do probe run");
      */
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
    html_start_form(f, 1, self_url, new_hidden_vars);
    if (logfilemode == 0) {
      html_submit_button(f, SSERV_CMD_RUN_LOG_DEV_NULL,
                         "Redirect to /dev/null");
    } else if (logfilemode == 2) {
      html_submit_button(f, SSERV_CMD_RUN_LOG_TRUNC, "Truncate log");
      html_submit_button(f, SSERV_CMD_RUN_LOG_DEV_NULL,
                         "Redirect to /dev/null");
      if (logfilestat.st_size <= MAX_LOG_VIEW_SIZE) {
        fprintf(f, "%sView</a>",
                html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                              "contest_id=%d&action=%d", contest_id,
                              SSERV_CMD_VIEW_RUN_LOG));
      }
    } else {
      html_submit_button(f, SSERV_CMD_RUN_LOG_FILE, "Redirect to file");
    }
    fprintf(f, "</form>");
    fprintf(f, "</td>");
  }
  fprintf(f, "</tr>\n");

  fprintf(f, "<tr><td>XML configuration file:</td><td>&nbsp;</td>");
  fprintf(f, "<td>");
  refcount = 0;
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0) {
    fprintf(f, "%sView</a>",
            html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                          "contest_id=%d&action=%d", contest_id,
                          SSERV_CMD_VIEW_CONTEST_XML));
    refcount++;
  }
  // FIXME: check editing permissions
  if (1 >= 0)
  {
    if (refcount) fprintf(f, "&nbsp;");
    fprintf(f, "%sEdit</a>",
            html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                          "contest_id=%d&action=%d", contest_id,
                          SSERV_CMD_EDIT_CONTEST_XML));
    refcount++;
  }
  if (!refcount) fprintf(f, "&nbsp;");
  fprintf(f, "</td>");
  fprintf(f, "</tr>\n");

  fprintf(f, "<tr><td>serve configuration file:</td><td>&nbsp;</td>");
  fprintf(f, "<td>");
  refcount = 0;
  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0) {
    fprintf(f, "%sView</a>",
            html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                          "contest_id=%d&action=%d", contest_id,
                          SSERV_CMD_VIEW_SERVE_CFG));
    refcount++;
  }
  // FIXME: check editing permissions
  if (1 >= 0)
  {
    if (refcount) fprintf(f, "&nbsp;");
    fprintf(f, "%sEdit</a>",
            html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                          "contest_id=%d&action=%d", contest_id,
                          SSERV_CMD_EDIT_CONTEST_XML));
    refcount++;
  }
  if (!refcount) fprintf(f, "&nbsp;");
  fprintf(f, "</td>");
  fprintf(f, "</tr>\n");

  fprintf(f, "</table>\n");

  if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0) {
    fprintf(f, "<p>");
    html_start_form(f, 1, self_url, new_hidden_vars);
    html_submit_button(f, SSERV_CMD_CONTEST_RESTART, "Restart management");
    fprintf(f, "</form>\n");

    fprintf(f, "<p>");
    html_start_form(f, 1, self_url, new_hidden_vars);
    html_submit_button(f, SSERV_CMD_CHECK_TESTS, "Check contest settings");
    fprintf(f, "</form>\n");
  }

  fprintf(f, "<table border=\"0\"><tr>");
  fprintf(f, "<td>%sBack</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args, 0));
  fprintf(f, "<td>%sRefresh</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                        "contest_id=%d&action=%d", contest_id,
                        SSERV_CMD_CONTEST_PAGE));
  fprintf(f, "<td>%sLogout</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                        "action=%d", SSERV_CMD_LOGOUT));
  fprintf(f, "</tr></table>");

  if (extra && extra->messages) {
    fprintf(f, "<hr><h3>Start-up messages</h3>\n");
    if (opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0) {
      fprintf(f, "<p>");
      html_submit_button(f, SSERV_CMD_CLEAR_MESSAGES, "Clear");
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
                    ej_cookie_t session_id,
                    ej_ip_t ip_address,
                    int ssl,
                    struct ejudge_cfg *config,
                    const unsigned char *self_url,
                    const unsigned char *hidden_vars,
                    const unsigned char *extra_args)
{
  int errcode, refresh_action;
  const struct contest_desc *cnts;
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
  if (!contests_check_serve_control_ip_2(cnts, ip_address, ssl)) {
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
    refresh_action = SSERV_CMD_VIEW_SERVE_LOG;
    break;
  case SSERV_CMD_VIEW_RUN_LOG:
    snprintf(log_file_path, sizeof(log_file_path),
             "%s/var/run_messages", cnts->root_dir);
    progname = "run";
    refresh_action = SSERV_CMD_VIEW_RUN_LOG;
    break;
  case SSERV_CMD_VIEW_CONTEST_XML:
    contests_make_path(log_file_path, sizeof(log_file_path), cnts->id);
    progname = "contest.xml";
    refresh_action = SSERV_CMD_VIEW_CONTEST_XML;
    break;
  case SSERV_CMD_VIEW_SERVE_CFG:
    snprintf(log_file_path, sizeof(log_file_path),
             "%s/conf/serve.cfg", cnts->root_dir);
    progname = "serve.cfg";
    refresh_action = SSERV_CMD_VIEW_SERVE_CFG;
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
  fprintf(f, "<td>%sTo contests list</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args, 0));
  fprintf(f, "<td>%sTo contest details</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                        "contest_id=%d&action=%d", contest_id,
                        SSERV_CMD_CONTEST_PAGE));
  fprintf(f, "<td>%sRefresh</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                        "contest_id=%d&action=%d", contest_id,
                        refresh_action));
  fprintf(f, "<td>%sLogout</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                        "action=%d", SSERV_CMD_LOGOUT));
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

static void
commit_contest_xml(int id)
{
  path_t xml_path;

  contests_make_path(xml_path, sizeof(xml_path), id);
  vcs_commit(xml_path, 0);
}

// assume, that the permissions are checked
int
super_html_open_contest(struct contest_desc *cnts, int user_id,
                        const unsigned char *user_login, ej_ip_t ip)
{
  int errcode;
  unsigned char *txt1, *txt2;
  unsigned char audit_str[1024];

  if (!cnts->closed) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->closed = 0;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: closed->open %s %d (%s) %s -->\n",
           xml_unparse_date(time(0)), user_id, user_login, xml_unparse_ip(ip));

  if ((errcode = contests_save_xml(cnts, txt1, txt2, audit_str)) < 0) {
    xfree(txt1);
    xfree(txt2);
    return -SSERV_ERR_SYSTEM_ERROR;
  }
  commit_contest_xml(cnts->id);

  xfree(txt1);
  xfree(txt2);
  return 0;
}

int
super_html_close_contest(struct contest_desc *cnts, int user_id,
                         const unsigned char *user_login, ej_ip_t ip)
{
  int errcode = 0;
  unsigned char *txt1 = 0, *txt2 = 0;
  unsigned char audit_str[1024];

  if (cnts->closed) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->closed = 1;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: open->closed %s %d (%s) %s -->\n",
           xml_unparse_date(time(0)), user_id, user_login, xml_unparse_ip(ip));

  if ((errcode = contests_save_xml(cnts, txt1, txt2, audit_str)) < 0) {
    xfree(txt1);
    xfree(txt2);
    return -SSERV_ERR_SYSTEM_ERROR;
  }
  commit_contest_xml(cnts->id);

  xfree(txt1);
  xfree(txt2);
  return 0;
}

int
super_html_make_invisible_contest(struct contest_desc *cnts, int user_id,
                                  const unsigned char *user_login,
                                  ej_ip_t ip)
{
  int errcode;
  unsigned char *txt1, *txt2;
  unsigned char audit_str[1024];

  if (cnts->invisible) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->invisible = 1;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: visible->invisible %s %d (%s) %s -->\n",
           xml_unparse_date(time(0)), user_id, user_login, xml_unparse_ip(ip));

  if ((errcode = contests_save_xml(cnts, txt1, txt2, audit_str)) < 0) {
    xfree(txt1);
    xfree(txt2);
    return -SSERV_ERR_SYSTEM_ERROR;
  }
  commit_contest_xml(cnts->id);

  xfree(txt1);
  xfree(txt2);
  return 0;
}

int
super_html_make_visible_contest(struct contest_desc *cnts, int user_id,
                                const unsigned char *user_login,
                                ej_ip_t ip)
{
  int errcode;
  unsigned char *txt1, *txt2;
  unsigned char audit_str[1024];

  if (!cnts->invisible) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->invisible = 0;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: invisible->visible %s %d (%s) %s -->\n",
           xml_unparse_date(time(0)), user_id, user_login, xml_unparse_ip(ip));

  if ((errcode = contests_save_xml(cnts, txt1, txt2, audit_str)) < 0) {
    xfree(txt1);
    xfree(txt2);
    return -SSERV_ERR_SYSTEM_ERROR;
  }
  commit_contest_xml(cnts->id);

  xfree(txt1);
  xfree(txt2);
  return 0;
}

int
super_html_serve_managed_contest(struct contest_desc *cnts, int user_id,
                                 const unsigned char *user_login,
                                 ej_ip_t ip)
{
  int errcode;
  unsigned char *txt1, *txt2;
  unsigned char audit_str[1024];

  if (cnts->managed) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->managed = 1;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: unmanaged->managed %s %d (%s) %s -->\n",
           xml_unparse_date(time(0)), user_id, user_login, xml_unparse_ip(ip));

  if ((errcode = contests_save_xml(cnts, txt1, txt2, audit_str)) < 0) {
    xfree(txt1);
    xfree(txt2);
    return -SSERV_ERR_SYSTEM_ERROR;
  }
  commit_contest_xml(cnts->id);

  xfree(txt1);
  xfree(txt2);
  return 0;
}

int
super_html_serve_unmanaged_contest(struct contest_desc *cnts, int user_id,
                                   const unsigned char *user_login,
                                   ej_ip_t ip)
{
  int errcode;
  unsigned char *txt1, *txt2;
  unsigned char audit_str[1024];

  if (!cnts->managed) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->managed = 0;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: managed->unmanaged %s %d (%s) %s -->\n",
           xml_unparse_date(time(0)), user_id, user_login, xml_unparse_ip(ip));

  if ((errcode = contests_save_xml(cnts, txt1, txt2, audit_str)) < 0) {
    xfree(txt1);
    xfree(txt2);
    return -SSERV_ERR_SYSTEM_ERROR;
  }
  commit_contest_xml(cnts->id);

  xfree(txt1);
  xfree(txt2);
  return 0;
}

int
super_html_run_managed_contest(struct contest_desc *cnts, int user_id,
                               const unsigned char *user_login,
                               ej_ip_t ip)
{
  int errcode;
  unsigned char *txt1, *txt2;
  unsigned char audit_str[1024];

  if (cnts->run_managed) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->run_managed = 1;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: run_unmanaged->run_managed %s %d (%s) %s -->\n",
           xml_unparse_date(time(0)), user_id, user_login, xml_unparse_ip(ip));

  if ((errcode = contests_save_xml(cnts, txt1, txt2, audit_str)) < 0) {
    xfree(txt1);
    xfree(txt2);
    return -SSERV_ERR_SYSTEM_ERROR;
  }
  commit_contest_xml(cnts->id);

  xfree(txt1);
  xfree(txt2);
  return 0;
}

int
super_html_run_unmanaged_contest(struct contest_desc *cnts, int user_id,
                                 const unsigned char *user_login,
                                 ej_ip_t ip)
{
  int errcode;
  unsigned char *txt1, *txt2;
  unsigned char audit_str[1024];

  if (!cnts->run_managed) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->run_managed = 0;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: run_managed->run_unmanaged %s %d (%s) %s -->\n",
           xml_unparse_date(time(0)), user_id, user_login, xml_unparse_ip(ip));

  if ((errcode = contests_save_xml(cnts, txt1, txt2, audit_str)) < 0) {
    xfree(txt1);
    xfree(txt2);
    return -SSERV_ERR_SYSTEM_ERROR;
  }
  commit_contest_xml(cnts->id);

  xfree(txt1);
  xfree(txt2);
  return 0;
}

int
super_html_report_error(FILE *f,
                        ej_cookie_t session_id,
                        const unsigned char *self_url,
                        const unsigned char *extra_args,
                        const char *format, ...)
{
  unsigned char msgbuf[1024];
  unsigned char hbuf[1024];
  va_list args;
  size_t arm_len;
  unsigned char *arm_str = 0;

  va_start(args, format);
  vsnprintf(msgbuf, sizeof(msgbuf), format, args);
  va_end(args);
  arm_len = html_armored_strlen(msgbuf);
  arm_str = (unsigned char*) alloca(arm_len + 1);
  html_armor_string(msgbuf, arm_str);

  fprintf(f, "<h2><font color=\"red\">Error: %s</font></h2>\n", arm_str);
  fprintf(f, "<table border=\"0\"><tr>");
  fprintf(f, "<td>%sTo the top</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url,extra_args,0));
  fprintf(f, "<td>%sBack</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                        "action=%d", SSERV_CMD_EDIT_CURRENT_CONTEST));
  fprintf(f, "</tr></table>\n");
  return 0;
}

void
super_html_contest_page_menu(FILE *f, 
                             ej_cookie_t session_id,
                             struct sid_state *sstate,
                             int cur_page,
                             const unsigned char *self_url,
                             const unsigned char *hidden_vars,
                             const unsigned char *extra_args)
{
  unsigned char hbuf[1024];

  fprintf(f, "<table border=\"0\"><tr><td>%sTo the top (postpone editing)</a></td><td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url,extra_args,0));
  if (cur_page != 1) {
    fprintf(f, "%s", html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                                   "action=%d", SSERV_CMD_EDIT_CURRENT_CONTEST));
  }
  fprintf(f, "General settings (contest.xml)");
  if (cur_page != 1) {
    fprintf(f, "</a>");
  }
  fprintf(f, "</td><td>");
  if (cur_page != 2) {
    fprintf(f, "%s", html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                                   "action=%d", SSERV_CMD_EDIT_CURRENT_GLOBAL));
  }
  fprintf(f, "Global settings (serve.cfg)");
  if (cur_page != 2) {
    fprintf(f, "</a>");
  }
  fprintf(f, "</td><td>");
  if (cur_page != 3) {
    fprintf(f, "%s", html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                                   "action=%d", SSERV_CMD_EDIT_CURRENT_LANG));
  }
  fprintf(f, "Language settings (serve.cfg)");
  if (cur_page != 3) {
    fprintf(f, "</a>");
  }
  fprintf(f, "</td><td>");
  if (cur_page != 4) {
    fprintf(f, "%s", html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                                   "action=%d", SSERV_CMD_EDIT_CURRENT_PROB));
  }
  fprintf(f, "Problems (serve.cfg)");
  if (cur_page != 4) {
    fprintf(f, "</a>");
  }
  fprintf(f, "</td><td>");
  if (cur_page != 5) {
    fprintf(f, "%s", html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                                   "action=%d", SSERV_CMD_PROB_EDIT_VARIANTS));
  }
  fprintf(f, "Variants (variant.map)");
  if (cur_page != 5) {
    fprintf(f, "</a>");
  }
  fprintf(f, "</td></tr></table>");
}

void
super_html_contest_footer_menu(FILE *f, 
                               ej_cookie_t session_id,
                               struct sid_state *sstate,
                               const unsigned char *self_url,
                               const unsigned char *hidden_vars,
                               const unsigned char *extra_args)
{
  unsigned char hbuf[1024];

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<table border=\"0\"><tr><td>%sTo the top</a></td><td>\n", html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args, 0));
  html_submit_button(f, SSERV_CMD_CNTS_FORGET, "Forget it");
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_COMMIT, "COMMIT changes!");
  fprintf(f, "</td><td>%sView serve.cfg</a>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                        "action=%d", SSERV_CMD_VIEW_NEW_SERVE_CFG));
  fprintf(f, "</td></tr></table></form>\n");
}

int
super_html_create_contest(FILE *f,
                          int priv_level,
                          int user_id,
                          const unsigned char *login,
                          ej_cookie_t session_id,
                          ej_ip_t ip_address,
                          struct ejudge_cfg *config,
                          struct sid_state *sstate,
                          const unsigned char *self_url,
                          const unsigned char *hidden_vars,
                          const unsigned char *extra_args)
{
  int contest_max_id = 0;
  unsigned char *contests_map = 0;
  int recomm_id = 1, cnts_id;
  const struct contest_desc *cnts = 0;
  unsigned char *cnts_name = 0;

  contest_max_id = contests_get_list(&contests_map);
  if (contest_max_id > 0) recomm_id = contest_max_id;

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<h2>Contest number</h2>\n");
  fprintf(f, "<table border=\"0\">"
          "<tr><td><input type=\"radio\" name=\"num_mode\" value=\"0\" checked=\"yes\"/></td><td>Assign automatically</td><td>&nbsp;</td></tr>\n"
          "<tr><td><input type=\"radio\" name=\"num_mode\" value=\"1\"/></td><td>Assign manually:</td><td><input type=\"text\" name=\"contest_id\" value=\"%d\" size=\"6\"/></td></tr>\n"
          "</table>", recomm_id);

  fprintf(f, "<h2>Contest template</h2>\n");
  fprintf(f, "<table border=\"0\">"
          "<tr><td><input type=\"radio\" name=\"templ_mode\" value=\"0\" checked=\"yes\"/></td><td>From scratch</td><td>&nbsp;</td></tr>\n"
          "<tr><td><input type=\"radio\" name=\"templ_mode\" value=\"1\"/></td><td>Use existing contest:</td><td><select name=\"templ_id\">\n");

  for (cnts_id = 1; cnts_id < contest_max_id; cnts_id++) {
    if (!contests_map[cnts_id]) continue;
    if (contests_get(cnts_id, &cnts) < 0) continue;
    cnts_name = html_armor_string_dup(cnts->name);
    fprintf(f, "<option value=\"%d\">%d - %s</option>", cnts_id, cnts_id, cnts_name);
    xfree(cnts_name);
  }

  fprintf(f, "</select></td></tr></table>\n");

  fprintf(f, "<h2>Actions</h2>\n");
  html_submit_button(f, SSERV_CMD_CREATE_CONTEST_2, "Create contest!");
  fprintf(f, "</form>\n");

  xfree(contests_map);
  return 0;
}

static void
print_string_editing_row(FILE *f,
                         const unsigned char *title,
                         const unsigned char *value,
                         int change_action,
                         int clear_action,
                         int edit_action,
                         ej_cookie_t session_id,
                         const unsigned char *row_attr,
                         const unsigned char *self_url,
                         const unsigned char *extra_args,
                         const unsigned char *hidden_vars)
{
  unsigned char hbuf[1024];

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>%s</td><td>", row_attr, title);
  html_edit_text_form(f, 0, 0, "param", value);
  fprintf(f, "</td><td>");
  html_submit_button(f, change_action, "Change");
  html_submit_button(f, clear_action, "Clear");
  if (edit_action > 0 && value && *value)
    fprintf(f, "%sEdit file</a>",
            html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                          "action=%d", edit_action));
  fprintf(f, "</td></tr></form>\n");
}

static void
print_access_summary(FILE *f, struct contest_access *acc,
                     const unsigned char *title,
                     int edit_action,
                     ej_cookie_t session_id,
                     const unsigned char *row_attr,
                     const unsigned char *self_url,
                     const unsigned char *extra_args)
{
  char *acc_txt = 0;
  size_t acc_len = 0;
  unsigned char hbuf[1024];
  FILE *af;
  struct contest_ip *p;
  unsigned char ssl_str[64];

  af = open_memstream(&acc_txt, &acc_len);
  ASSERT(af);
  if (!acc) {
    fprintf(af, "default deny\n");
  } else {
    for (p = (struct contest_ip*) acc->b.first_down;
         p; p = (struct contest_ip*) p->b.right) {
      ssl_str[0] = 0;
      if (p->ssl >= 0)
        snprintf(ssl_str, sizeof(ssl_str), " %s", p->ssl?"(SSL)":"(No SSL)");
      fprintf(af, "%s%s %s\n",
              xml_unparse_ip_mask(p->addr, p->mask), ssl_str,
              p->allow?"allow":"deny");
    }
    fprintf(af, "default %s\n", acc->default_is_allow?"allow":"deny");
  }
  fclose(af);

  fprintf(f, "<tr valign=\"top\"%s><td>%s</td><td><pre>%s</pre></td><td>%sEdit</a></td></tr>", row_attr, title, acc_txt, html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args, "action=%d", edit_action));
  xfree(acc_txt);
}

static void
print_permissions(FILE *f, struct contest_desc *cnts,
                  ej_cookie_t session_id,
                  const unsigned char * const *row_attrs,
                  const unsigned char *self_url,
                  const unsigned char *hidden_vars,
                  const unsigned char *extra_args)
{
  struct opcap_list_item *p = cnts->capabilities.first;
  unsigned char *s;
  unsigned char href[1024];
  int i, r = 0;

  for (i = 0; p; p = (struct opcap_list_item*) p->b.right, i++) {
    snprintf(href, sizeof(href), "%d", i);
    html_start_form(f, 1, self_url, hidden_vars);
    html_hidden_var(f, "num", href);
    fprintf(f, "<tr valign=\"top\"%s><td>", row_attrs[r]);
    r ^= 1;
    s = html_armor_string_dup(p->login);
    fprintf(f, "%d: %s", i, s);
    xfree(s);
    fprintf(f, "</td><td><font size=\"-2\"><pre>");
    s = opcaps_unparse(0, 32, p->caps);
    fprintf(f, "%s</pre></font></td><td>%sEdit</a>", s,
            html_hyperref(href, sizeof(href), session_id, self_url, extra_args,
                          "action=%d&num=%d", SSERV_CMD_CNTS_EDIT_PERMISSION, i));
    xfree(s);
    html_submit_button(f, SSERV_CMD_CNTS_DELETE_PERMISSION, "Delete");
    fprintf(f, "</td></tr></form>");
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr valign=\"top\"%s><td>Add new user:</td><td>Login:",
          row_attrs[r]);
  html_edit_text_form(f, 32, 32, "param", "");
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_ADD_PERMISSION, "Add");
  fprintf(f, "</td></tr></form>");
}

static const unsigned char *const form_field_names[] =
{
  [CONTEST_F_HOMEPAGE] = "Home page",
  [CONTEST_F_PHONE] = "Phone",
  [CONTEST_F_INST] = "Institution",
  [CONTEST_F_INST_EN] = "Institution (English)",
  [CONTEST_F_INSTSHORT] = "Institution, short",
  [CONTEST_F_INSTSHORT_EN] = "Institution, short (English)",
  [CONTEST_F_FAC] = "Faculty",
  [CONTEST_F_FAC_EN] = "Faculty (English)",
  [CONTEST_F_FACSHORT] = "Faculty, short",
  [CONTEST_F_FACSHORT_EN] = "Faculty, short (English)",
  [CONTEST_F_CITY] = "City",
  [CONTEST_F_CITY_EN] = "City (English)",
  [CONTEST_F_COUNTRY] = "Country",
  [CONTEST_F_COUNTRY_EN] = "Country (English)",
  [CONTEST_F_REGION] = "Region",
  [CONTEST_F_LANGUAGES] = "Programming Languages",
};

static const unsigned char *const member_field_names[] =
{
  [CONTEST_MF_FIRSTNAME] = "First Name",
  [CONTEST_MF_FIRSTNAME_EN] = "First Name (English)",
  [CONTEST_MF_MIDDLENAME] = "Middle Name",
  [CONTEST_MF_MIDDLENAME_EN] = "Middle Name (English)",
  [CONTEST_MF_SURNAME] = "Surname",
  [CONTEST_MF_SURNAME_EN] = "Surname (English)",
  [CONTEST_MF_STATUS] = "Status",
  [CONTEST_MF_GRADE] = "Grade",
  [CONTEST_MF_GROUP] = "Group",
  [CONTEST_MF_GROUP_EN] = "Group (English)",
  [CONTEST_MF_EMAIL] = "E-mail",
  [CONTEST_MF_HOMEPAGE] = "Homepage",
  [CONTEST_MF_PHONE] = "Phone",
  [CONTEST_MF_INST] = "Institution",
  [CONTEST_MF_INST_EN] = "Institution (English)",
  [CONTEST_MF_INSTSHORT] = "Institution, short",
  [CONTEST_MF_INSTSHORT_EN] = "Institution, short (English)",
  [CONTEST_MF_FAC] = "Faculty",
  [CONTEST_MF_FAC_EN] = "Faculty (English)",
  [CONTEST_MF_FACSHORT] = "Faculty, short",
  [CONTEST_MF_FACSHORT_EN] = "Faculty, short (English)",
  [CONTEST_MF_OCCUPATION] = "Occupation",
  [CONTEST_MF_OCCUPATION_EN] = "Occupation (English)",
  [CONTEST_MF_BIRTH_DATE] = "Birth date",
  [CONTEST_MF_ENTRY_DATE] = "Entry date",
  [CONTEST_MF_GRADUATION_DATE] = "Graduation date",
};

static void
print_form_fields_2(FILE *f, struct contest_member *memb,
                    const unsigned char *title,
                    int edit_action,
                    ej_cookie_t session_id,
                    const unsigned char *row_attr,
                    const unsigned char *self_url,
                    const unsigned char *hidden_vars,
                    const unsigned char *extra_args)
{
  struct contest_field **descs;
  char *out_txt = 0;
  size_t out_len = 0;
  FILE *af;
  int i;
  unsigned char href[1024];

  af = open_memstream(&out_txt, &out_len);
  if (!memb) {
    fprintf(af, "minimal count = %d\n", 0);
    fprintf(af, "maximal count = %d\n", 0);
    fprintf(af, "initial count = %d\n", 0);
  } else {
    descs = memb->fields;
    fprintf(af, "minimal count = %d\n", memb->min_count);
    fprintf(af, "maximal count = %d\n", memb->max_count);
    fprintf(af, "initial count = %d\n", memb->init_count);
    for (i = 1; i < CONTEST_LAST_MEMBER_FIELD; i++) {
      if (!descs[i]) continue;
      fprintf(af, "\"%s\" %s\n", member_field_names[i],
              descs[i]->mandatory?"mandatory":"optional");
    }
  }
  fclose(af);

  fprintf(f, "<tr valign=\"top\"%s><td>%s</td><td><font size=\"-1\"><pre>%s</pre></font></td><td>%sEdit</a></td></tr>\n", row_attr, title, out_txt,
          html_hyperref(href, sizeof(href), session_id, self_url, extra_args,
                        "action=%d", edit_action));
  xfree(out_txt);
}

static void
print_form_fields_3(FILE *f, struct contest_field **descs,
                    const unsigned char *title,
                    int edit_action,
                    ej_cookie_t session_id,
                    const unsigned char *row_attr,
                    const unsigned char *self_url,
                    const unsigned char *hidden_vars,
                    const unsigned char *extra_args)
{
  char *out_txt = 0;
  size_t out_len = 0;
  FILE *af;
  int i;
  unsigned char href[1024];

  af = open_memstream(&out_txt, &out_len);
  if (descs) {
    for (i = 1; i < CONTEST_LAST_FIELD; i++) {
      if (!descs[i]) continue;
      fprintf(af, "\"%s\" %s\n", form_field_names[i],
              descs[i]->mandatory?"mandatory":"optional");
    }
  }
  fclose(af);

  fprintf(f, "<tr valign=\"top\"%s><td>%s</td><td><font size=\"-1\"><pre>%s</pre></font></td><td>%sEdit</a></td></tr>\n", row_attr, title, out_txt,
          html_hyperref(href, sizeof(href), session_id, self_url, extra_args,
                   "action=%d", edit_action));
  xfree(out_txt);
}

static void
print_form_fields(FILE *f, struct contest_desc *cnts,
                  ej_cookie_t session_id,
                  const unsigned char * const *row_attrs,
                  const unsigned char *self_url,
                  const unsigned char *hidden_vars,
                  const unsigned char *extra_args)
{
  struct contest_member *memb;

  print_form_fields_3(f, cnts->fields, "Primary registration fields",
                      SSERV_CMD_CNTS_EDIT_FORM_FIELDS,
                      session_id, row_attrs[0],
                      self_url, hidden_vars, extra_args);
  memb = 0;
  if (cnts->members) memb = cnts->members[CONTEST_M_CONTESTANT];
  print_form_fields_2(f, memb, "\"Contestant\" member parameters",
                      SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS,
                      session_id, row_attrs[1],
                      self_url, hidden_vars, extra_args);
  memb = 0;
  if (cnts->members) memb = cnts->members[CONTEST_M_RESERVE];
  print_form_fields_2(f, memb, "\"Reserve\" member parameters",
                      SSERV_CMD_CNTS_EDIT_RESERVE_FIELDS,
                      session_id, row_attrs[0],
                      self_url, hidden_vars, extra_args);
  memb = 0;
  if (cnts->members) memb = cnts->members[CONTEST_M_COACH];
  print_form_fields_2(f, memb, "\"Coach\" member parameters",
                      SSERV_CMD_CNTS_EDIT_COACH_FIELDS,
                      session_id, row_attrs[1],
                      self_url, hidden_vars, extra_args);
  memb = 0;
  if (cnts->members) memb = cnts->members[CONTEST_M_ADVISOR];
  print_form_fields_2(f, memb, "\"Advisor\" member parameters",
                      SSERV_CMD_CNTS_EDIT_ADVISOR_FIELDS,
                      session_id, row_attrs[0],
                      self_url, hidden_vars, extra_args);
  memb = 0;
  if (cnts->members) memb = cnts->members[CONTEST_M_GUEST];
  print_form_fields_2(f, memb, "\"Guest\" member parameters",
                      SSERV_CMD_CNTS_EDIT_GUEST_FIELDS,
                      session_id, row_attrs[1],
                      self_url, hidden_vars, extra_args);
}

static const unsigned char head_row_attr[] =
  " bgcolor=\"#a0a0a0\"";
static const unsigned char * const form_row_attrs[]=
{
  " bgcolor=\"#d0d0d0\"",
  " bgcolor=\"#e0e0e0\"",
};

int
super_html_edit_contest_page(FILE *f,
                             int priv_level,
                             int user_id,
                             const unsigned char *login,
                             ej_cookie_t session_id,
                             ej_ip_t ip_address,
                             struct ejudge_cfg *config,
                             struct sid_state *sstate,
                             const unsigned char *self_url,
                             const unsigned char *hidden_vars,
                             const unsigned char *extra_args)
{
  struct contest_desc *cnts = sstate->edited_cnts;
  unsigned char hbuf[1024];
  int row = 1;

  if (!cnts) {
    fprintf(f, "<h2>No current contest!</h2>\n"
            "<p>%sTo the top</a></p>\n",
            html_hyperref(hbuf, sizeof(hbuf),session_id,self_url,extra_args,0));
    return 0;
  }

  super_html_contest_page_menu(f, session_id, sstate, 1, self_url, hidden_vars,
                               extra_args);

  fprintf(f, "<table border=\"0\">\n");

  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Basic contest identification</b></td></tr>", head_row_attr);
  row = 1;

  fprintf(f, "<tr%s><td>Contest ID:</td><td>%d</td><td>&nbsp;</td></tr>\n",
          form_row_attrs[row ^= 1], cnts->id);
  print_string_editing_row(f, "Name:", cnts->name,
                           SSERV_CMD_CNTS_CHANGE_NAME,
                           SSERV_CMD_CNTS_CLEAR_NAME,
                           0,
                           session_id,
                           form_row_attrs[row ^= 1],
                           self_url,
                           extra_args,
                           hidden_vars);
  print_string_editing_row(f, "Name (English):", cnts->name_en,
                           SSERV_CMD_CNTS_CHANGE_NAME_EN,
                           SSERV_CMD_CNTS_CLEAR_NAME_EN,
                           0,
                           session_id,
                           form_row_attrs[row ^= 1],
                           self_url,
                           extra_args,
                           hidden_vars);
  print_string_editing_row(f, "Main URL:", cnts->main_url,
                           SSERV_CMD_CNTS_CHANGE_MAIN_URL,
                           SSERV_CMD_CNTS_CLEAR_MAIN_URL,
                           0,
                           session_id,
                           form_row_attrs[row ^= 1],
                           self_url,
                           extra_args,
                           hidden_vars);
  // FIXME: use the locale selection dialog
  print_string_editing_row(f, "Default locale:", cnts->default_locale,
                           SSERV_CMD_CNTS_CHANGE_DEFAULT_LOCALE,
                           SSERV_CMD_CNTS_CLEAR_DEFAULT_LOCALE,
                           0,
                           session_id,
                           form_row_attrs[row ^= 1],
                           self_url,
                           extra_args,
                           hidden_vars);
  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>The contest is personal?</td><td>",
          form_row_attrs[row ^= 1]);
  html_boolean_select(f, cnts->personal, "param", 0, 0);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_CHANGE_PERSONAL, "Change");
  fprintf(f, "</td></tr></form>\n");

  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Registration settings</b></td></tr>", head_row_attr);
  row = 1;

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Registration mode:</td><td>", form_row_attrs[row ^= 1]);
  html_boolean_select(f, cnts->autoregister, "param", "Moderated registration",
                      "Free registration");
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_CHANGE_AUTOREGISTER, "Change");
  fprintf(f, "</td></tr></form>\n");

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Registration deadline:</td><td>",
          form_row_attrs[row ^= 1]);
  html_date_select(f, cnts->reg_deadline);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_CHANGE_DEADLINE, "Change");
  html_submit_button(f, SSERV_CMD_CNTS_CLEAR_DEADLINE, "Clear");
  fprintf(f, "</td></tr></form>\n");

  print_string_editing_row(f, "Registration email sender (From: field):",
                           cnts->register_email,
                           SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL,
                           SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL,
                           0,
                           session_id,
                           form_row_attrs[row ^= 1],
                           self_url,
                           extra_args,
                           hidden_vars);
  print_string_editing_row(f, "URL to complete registration:",
                           cnts->register_url,
                           SSERV_CMD_CNTS_CHANGE_REGISTER_URL,
                           SSERV_CMD_CNTS_CLEAR_REGISTER_URL,
                           0,
                           session_id,
                           form_row_attrs[row ^= 1],
                           self_url,
                           extra_args,
                           hidden_vars);
  print_string_editing_row(f, "Registration letter template file:",
                           cnts->register_email_file,
                           SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL_FILE,
                           SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE,
                           SSERV_CMD_CNTS_EDIT_REGISTER_EMAIL_FILE,
                           session_id,
                           form_row_attrs[row ^= 1],
                           self_url,
                           extra_args,
                           hidden_vars);

  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Participation settings</b></td></tr>", head_row_attr);
  row = 1;

  print_string_editing_row(f, "URL for the `team' CGI program:",
                           cnts->team_url,
                           SSERV_CMD_CNTS_CHANGE_TEAM_URL,
                           SSERV_CMD_CNTS_CLEAR_TEAM_URL,
                           0,
                           session_id,
                           form_row_attrs[row ^= 1],
                           self_url,
                           extra_args,
                           hidden_vars);
  print_string_editing_row(f, "URL for the current standings:",
                           cnts->standings_url,
                           SSERV_CMD_CNTS_CHANGE_STANDINGS_URL,
                           SSERV_CMD_CNTS_CLEAR_STANDINGS_URL,
                           0,
                           session_id,
                           form_row_attrs[row ^= 1],
                           self_url,
                           extra_args,
                           hidden_vars);
  print_string_editing_row(f, "URL for the problemset:",
                           cnts->problems_url,
                           SSERV_CMD_CNTS_CHANGE_PROBLEMS_URL,
                           SSERV_CMD_CNTS_CLEAR_PROBLEMS_URL,
                           0,
                           session_id,
                           form_row_attrs[row ^= 1],
                           self_url,
                           extra_args,
                           hidden_vars);

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Various contest's flags</b>", head_row_attr);
  row = 1;
  if (sstate->advanced_view) {
    html_submit_button(f, SSERV_CMD_CNTS_BASIC_VIEW, "Basic view");
  } else {
    html_submit_button(f, SSERV_CMD_CNTS_ADVANCED_VIEW, "Advanced view");
  }
  fprintf(f, "</td></tr></form>");

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Disable separate team password?</td><td>",
          form_row_attrs[row ^= 1]);
  html_boolean_select(f, cnts->disable_team_password, "param", 0, 0);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_CHANGE_TEAM_PASSWD, "Change");
  fprintf(f, "</td></tr></form>\n");

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Enable simple registration (no email)?</td><td>",
          form_row_attrs[row ^= 1]);
  html_boolean_select(f, cnts->simple_registration, "param", 0, 0);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_CHANGE_SIMPLE_REGISTRATION, "Change");
  fprintf(f, "</td></tr></form>\n");

  if (cnts->simple_registration) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Send e-mail with password anyway?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->send_passwd_email, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_SEND_PASSWD_EMAIL, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  if (!cnts->new_managed) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Manage the contest server?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->managed, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_MANAGED, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  if (!cnts->managed) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Use the new-server for this contest?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->new_managed, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_NEW_MANAGED, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Manage the testing server?</td><td>",
          form_row_attrs[row ^= 1]);
  html_boolean_select(f, cnts->run_managed, "param", 0, 0);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_CHANGE_RUN_MANAGED, "Change");
  fprintf(f, "</td></tr></form>\n");

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Allow pruning users?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->clean_users, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_CLEAN_USERS, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Closed for participation?</td><td>",
          form_row_attrs[row ^= 1]);
  html_boolean_select(f, cnts->closed, "param", 0, 0);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_CHANGE_CLOSED, "Change");
  fprintf(f, "</td></tr></form>\n");

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Invisible in serve-control?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->invisible, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_INVISIBLE, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Allow time desync between `team' and `serve'?</td><td>", form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->client_ignore_time_skew, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_TIME_SKEW, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Disallow team login?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->client_disable_team, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_TEAM_LOGIN, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Disallow team member removal?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->disable_member_delete, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_MEMBER_DELETE, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Auto-assign logins?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->assign_logins, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_ASSIGN_LOGINS, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Force contest registration?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->force_registration, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_FORCE_REGISTRATION, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Disable &quot;Name&quot; field?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->disable_name, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_DISABLE_NAME, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Enable password restoration?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->enable_forgot_password, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_ENABLE_FORGOT_PASSWORD, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Examination mode?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->exam_mode, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_EXAM_MODE, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Disable locale change?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->disable_locale_change, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_DISABLE_LOCALE_CHANGE, "Change");
    fprintf(f, "</td></tr></form>\n");
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>IP-address access rules for CGI programs</b>", head_row_attr);
  row = 1;
  if (sstate->show_access_rules) {
    html_submit_button(f, SSERV_CMD_CNTS_HIDE_ACCESS_RULES, "Hide");
  } else {
    html_submit_button(f, SSERV_CMD_CNTS_SHOW_ACCESS_RULES, "Show");
  }
  fprintf(f, "</td></tr></form>");

  if (sstate->show_access_rules) {
    print_access_summary(f, cnts->register_access, "Access to `register' program",
                         SSERV_CMD_EDIT_REGISTER_ACCESS,
                         session_id, form_row_attrs[row ^= 1],
                         self_url, extra_args);
    print_access_summary(f, cnts->users_access, "Access to `users' program",
                         SSERV_CMD_EDIT_USERS_ACCESS,
                         session_id, form_row_attrs[row ^= 1],
                         self_url, extra_args);
    print_access_summary(f, cnts->master_access, "Access to `master' program",
                         SSERV_CMD_EDIT_MASTER_ACCESS,
                         session_id, form_row_attrs[row ^= 1],
                         self_url, extra_args);
    print_access_summary(f, cnts->judge_access, "Access to `judge' program",
                         SSERV_CMD_EDIT_JUDGE_ACCESS,
                         session_id, form_row_attrs[row ^= 1],
                         self_url, extra_args);
    print_access_summary(f, cnts->team_access, "Access to `team' program",
                         SSERV_CMD_EDIT_TEAM_ACCESS,
                         session_id, form_row_attrs[row ^= 1],
                         self_url, extra_args);
    print_access_summary(f, cnts->serve_control_access,
                         "Access to `serve-control' program",
                         SSERV_CMD_EDIT_SERVE_CONTROL_ACCESS,
                         session_id, form_row_attrs[row ^= 1],
                         self_url, extra_args);
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Users permissions</b>", head_row_attr);
  if (sstate->show_permissions) {
    html_submit_button(f, SSERV_CMD_CNTS_HIDE_PERMISSIONS, "Hide");
  } else {
    html_submit_button(f, SSERV_CMD_CNTS_SHOW_PERMISSIONS, "Show");
  }
  fprintf(f, "</td></tr></form>");

  if (sstate->show_permissions) {
    print_permissions(f, cnts, session_id, form_row_attrs,
                      self_url, hidden_vars, extra_args);
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Registration form fields</b>", head_row_attr);
  if (sstate->show_form_fields) {
    html_submit_button(f, SSERV_CMD_CNTS_HIDE_FORM_FIELDS, "Hide");
  } else {
    html_submit_button(f, SSERV_CMD_CNTS_SHOW_FORM_FIELDS, "Show");
  }
  fprintf(f, "</td></tr></form>");

  if (sstate->show_form_fields) {
    print_form_fields(f, cnts, session_id, form_row_attrs,
                      self_url, hidden_vars, extra_args);
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>HTML headers and footers for CGI-programs</b>", head_row_attr);
  row = 1;
  if (sstate->show_html_headers) {
    html_submit_button(f, SSERV_CMD_CNTS_HIDE_HTML_HEADERS, "Hide");
  } else {
    html_submit_button(f, SSERV_CMD_CNTS_SHOW_HTML_HEADERS, "Show");
  }
  fprintf(f, "</td></tr></form>");

  if (sstate->show_html_headers) {
    print_string_editing_row(f, "HTML header file for `users' CGI-program:",
                             cnts->users_header_file,
                             SSERV_CMD_CNTS_CHANGE_USERS_HEADER,
                             SSERV_CMD_CNTS_CLEAR_USERS_HEADER,
                             SSERV_CMD_CNTS_EDIT_USERS_HEADER,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML footer file for `users' CGI-program:",
                             cnts->users_footer_file,
                             SSERV_CMD_CNTS_CHANGE_USERS_FOOTER,
                             SSERV_CMD_CNTS_CLEAR_USERS_FOOTER,
                             SSERV_CMD_CNTS_EDIT_USERS_FOOTER,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML header file for `register' CGI-program:",
                             cnts->register_header_file,
                             SSERV_CMD_CNTS_CHANGE_REGISTER_HEADER,
                             SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER,
                             SSERV_CMD_CNTS_EDIT_REGISTER_HEADER,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML footer file for `register' CGI-program:",
                             cnts->register_footer_file,
                             SSERV_CMD_CNTS_CHANGE_REGISTER_FOOTER,
                             SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER,
                             SSERV_CMD_CNTS_EDIT_REGISTER_FOOTER,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML header file for `team' CGI-program:",
                             cnts->team_header_file,
                             SSERV_CMD_CNTS_CHANGE_TEAM_HEADER,
                             SSERV_CMD_CNTS_CLEAR_TEAM_HEADER,
                             SSERV_CMD_CNTS_EDIT_TEAM_HEADER,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML footer file for `team' CGI-program:",
                             cnts->team_footer_file,
                             SSERV_CMD_CNTS_CHANGE_TEAM_FOOTER,
                             SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER,
                             SSERV_CMD_CNTS_EDIT_TEAM_FOOTER,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML header file for privileged CGI-programs:",
                             cnts->priv_header_file,
                             SSERV_CMD_CNTS_CHANGE_PRIV_HEADER,
                             SSERV_CMD_CNTS_CLEAR_PRIV_HEADER,
                             SSERV_CMD_CNTS_EDIT_PRIV_HEADER,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML footer file for privileged CGI-programs:",
                             cnts->priv_footer_file,
                             SSERV_CMD_CNTS_CHANGE_PRIV_FOOTER,
                             SSERV_CMD_CNTS_CLEAR_PRIV_FOOTER,
                             SSERV_CMD_CNTS_EDIT_PRIV_FOOTER,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "Copyright notice for CGI-program:",
                             cnts->copyright_file,
                             SSERV_CMD_CNTS_CHANGE_COPYRIGHT,
                             SSERV_CMD_CNTS_CLEAR_COPYRIGHT,
                             SSERV_CMD_CNTS_EDIT_COPYRIGHT,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>extra HTML attributes for CGI-programs</b>",head_row_attr);
  row = 1;
  if (sstate->show_html_attrs) {
    html_submit_button(f, SSERV_CMD_CNTS_HIDE_HTML_ATTRS, "Hide");
  } else {
    html_submit_button(f, SSERV_CMD_CNTS_SHOW_HTML_ATTRS, "Show");
  }
  fprintf(f, "</td></tr></form>");

  if (sstate->show_html_attrs) {
    print_string_editing_row(f, "HTML attributes for `users' headers:",
                             cnts->users_head_style,
                             SSERV_CMD_CNTS_CHANGE_USERS_HEAD_STYLE,
                             SSERV_CMD_CNTS_CLEAR_USERS_HEAD_STYLE,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML attributes for `users' paragraphs:",
                             cnts->users_par_style,
                             SSERV_CMD_CNTS_CHANGE_USERS_PAR_STYLE,
                             SSERV_CMD_CNTS_CLEAR_USERS_PAR_STYLE,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML attributes for `users' tables:",
                             cnts->users_table_style,
                             SSERV_CMD_CNTS_CHANGE_USERS_TABLE_STYLE,
                             SSERV_CMD_CNTS_CLEAR_USERS_TABLE_STYLE,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML attributes for `users' verbatim texts:",
                             cnts->users_verb_style,
                             SSERV_CMD_CNTS_CHANGE_USERS_VERB_STYLE,
                             SSERV_CMD_CNTS_CLEAR_USERS_VERB_STYLE,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "Format specification for users table:",
                             cnts->users_table_format,
                             SSERV_CMD_CNTS_CHANGE_USERS_TABLE_FORMAT,
                             SSERV_CMD_CNTS_CLEAR_USERS_TABLE_FORMAT,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "Format specification for users table (En):",
                             cnts->users_table_format_en,
                             SSERV_CMD_CNTS_CHANGE_USERS_TABLE_FORMAT_EN,
                             SSERV_CMD_CNTS_CLEAR_USERS_TABLE_FORMAT_EN,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "Legend specification for users table:",
                             cnts->users_table_legend,
                             SSERV_CMD_CNTS_CHANGE_USERS_TABLE_LEGEND,
                             SSERV_CMD_CNTS_CLEAR_USERS_TABLE_LEGEND,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "Legend specification for users table (En):",
                             cnts->users_table_legend_en,
                             SSERV_CMD_CNTS_CHANGE_USERS_TABLE_LEGEND_EN,
                             SSERV_CMD_CNTS_CLEAR_USERS_TABLE_LEGEND_EN,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML attributes for `register' headers:",
                             cnts->register_head_style,
                             SSERV_CMD_CNTS_CHANGE_REGISTER_HEAD_STYLE,
                             SSERV_CMD_CNTS_CLEAR_REGISTER_HEAD_STYLE,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML attributes for `register' paragraphs:",
                             cnts->register_par_style,
                             SSERV_CMD_CNTS_CHANGE_REGISTER_PAR_STYLE,
                             SSERV_CMD_CNTS_CLEAR_REGISTER_PAR_STYLE,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML attributes for `register' tables:",
                             cnts->register_table_style,
                             SSERV_CMD_CNTS_CHANGE_REGISTER_TABLE_STYLE,
                             SSERV_CMD_CNTS_CLEAR_REGISTER_TABLE_STYLE,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "Additional comment for user name field:",
                             cnts->user_name_comment,
                             SSERV_CMD_CNTS_CHANGE_REGISTER_NAME_COMMENT,
                             SSERV_CMD_CNTS_CLEAR_REGISTER_NAME_COMMENT,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML attributes for `team' headers:",
                             cnts->team_head_style,
                             SSERV_CMD_CNTS_CHANGE_TEAM_HEAD_STYLE,
                             SSERV_CMD_CNTS_CLEAR_TEAM_HEAD_STYLE,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML attributes for `team' paragraphs:",
                             cnts->team_par_style,
                             SSERV_CMD_CNTS_CHANGE_TEAM_PAR_STYLE,
                             SSERV_CMD_CNTS_CLEAR_TEAM_PAR_STYLE,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "Allowed programming languages:",
                             cnts->allowed_languages,
                             SSERV_CMD_CNTS_CHANGE_ALLOWED_LANGUAGES,
                             SSERV_CMD_CNTS_CLEAR_ALLOWED_LANGUAGES,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "Allowed regions:",
                             cnts->allowed_regions,
                             SSERV_CMD_CNTS_CHANGE_ALLOWED_REGIONS,
                             SSERV_CMD_CNTS_CLEAR_ALLOWED_REGIONS,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>E-mail notifications</b>", head_row_attr);
  row = 1;
  if (sstate->show_notifications) {
    html_submit_button(f, SSERV_CMD_CNTS_HIDE_NOTIFICATIONS, "Hide");
  } else {
    html_submit_button(f, SSERV_CMD_CNTS_SHOW_NOTIFICATIONS, "Show");
  }
  fprintf(f, "</td></tr></form>");

  if (sstate->show_notifications) {
    print_string_editing_row(f, "Check failed e-mail notification address:",
                             cnts->cf_notify_email,
                             SSERV_CMD_CNTS_CHANGE_CF_NOTIFY_EMAIL,
                             SSERV_CMD_CNTS_CLEAR_CF_NOTIFY_EMAIL,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "Clar request e-mail notification address:",
                             cnts->clar_notify_email,
                             SSERV_CMD_CNTS_CHANGE_CLAR_NOTIFY_EMAIL,
                             SSERV_CMD_CNTS_CLEAR_CLAR_NOTIFY_EMAIL,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "Daily statistics email:",
                             cnts->daily_stat_email,
                             SSERV_CMD_CNTS_CHANGE_DAILY_STAT_EMAIL,
                             SSERV_CMD_CNTS_CLEAR_DAILY_STAT_EMAIL,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    if (cnts->assign_logins) {
      print_string_editing_row(f, "Template for new logins:",
                               cnts->login_template,
                               SSERV_CMD_CNTS_CHANGE_LOGIN_TEMPLATE,
                               SSERV_CMD_CNTS_CLEAR_LOGIN_TEMPLATE,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);
      print_string_editing_row(f, "Template options:",
                               cnts->login_template_options,
                               SSERV_CMD_CNTS_CHANGE_LOGIN_TEMPLATE_OPTIONS,
                               SSERV_CMD_CNTS_CLEAR_LOGIN_TEMPLATE_OPTIONS,
                               0,
                               session_id,
                               form_row_attrs[row ^= 1],
                               self_url,
                               extra_args,
                               hidden_vars);
    }
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"3\" align=\"center\"><b>Advanced path settings</b>", head_row_attr);
  row = 1;
  if (sstate->show_paths) {
    html_submit_button(f, SSERV_CMD_CNTS_HIDE_PATHS, "Hide");
  } else {
    html_submit_button(f, SSERV_CMD_CNTS_SHOW_PATHS, "Show");
  }
  fprintf(f, "</td></tr></form>");

  if (sstate->show_paths) {
    print_string_editing_row(f, "The contest root directory:",
                             cnts->root_dir,
                             SSERV_CMD_CNTS_CHANGE_ROOT_DIR,
                             SSERV_CMD_CNTS_CLEAR_ROOT_DIR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "The contest configuration directory:",
                             cnts->conf_dir,
                             SSERV_CMD_CNTS_CHANGE_CONF_DIR,
                             SSERV_CMD_CNTS_CLEAR_CONF_DIR,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);

    print_string_editing_row(f, "The directory permissions (octal):",
                             cnts->dir_mode,
                             SSERV_CMD_CNTS_CHANGE_DIR_MODE,
                             SSERV_CMD_CNTS_CLEAR_DIR_MODE,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "The directory group:",
                             cnts->dir_group,
                             SSERV_CMD_CNTS_CHANGE_DIR_GROUP,
                             SSERV_CMD_CNTS_CLEAR_DIR_GROUP,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "The file permissions (octal):",
                             cnts->file_mode,
                             SSERV_CMD_CNTS_CHANGE_FILE_MODE,
                             SSERV_CMD_CNTS_CLEAR_FILE_MODE,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "The file group:",
                             cnts->file_group,
                             SSERV_CMD_CNTS_CHANGE_FILE_GROUP,
                             SSERV_CMD_CNTS_CLEAR_FILE_GROUP,
                             0,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
  }

  fprintf(f, "</table>\n");

  super_html_contest_footer_menu(f, session_id, sstate,
                                 self_url, hidden_vars, extra_args);

  return 0;
}

static void
html_ssl_select(FILE *f, int value)
{
  fprintf(f, "<select name=\"ssl\"><option value=\"-1\"%s>Any</option><option value=\"0\"%s>No SSL</option><option value=\"1\"%s>SSL</option></select>",
          value < 0 ? " selected=\"1\"" : "",
          !value ? " selected=\"1\"" : "",
          value > 0 ? " selected=\"1\"" : "");

}

int
super_html_edit_access_rules(FILE *f,
                             int priv_level,
                             int user_id,
                             const unsigned char *login,
                             ej_cookie_t session_id,
                             ej_ip_t ip_address,
                             struct ejudge_cfg *config,
                             struct sid_state *sstate,
                             int cmd,
                             const unsigned char *self_url,
                             const unsigned char *hidden_vars,
                             const unsigned char *extra_args)
{
  struct contest_desc *cnts = sstate->edited_cnts;
  struct contest_access *acc;
  struct contest_ip *p;
  const unsigned char *acc_mode;
  const unsigned char *acc_desc;
  int default_is_allow = 0, i;
  unsigned char num_str[128];
  unsigned char hbuf[1024];
  unsigned char *contests_map = 0;
  int contest_max_id, cnts_id;
  const struct contest_desc *tmp_cnts = 0;
  unsigned char *cnts_name = 0;
  int row = 1;

  if (!cnts) {
    fprintf(f, "<h2>No current contest!</h2>\n"
            "<p>%sTo the top</a></p>\n",
            html_hyperref(hbuf,sizeof(hbuf),session_id,self_url,extra_args,0));
    return 0;
  }

  switch (cmd) {
  case SSERV_CMD_EDIT_REGISTER_ACCESS:
    acc = cnts->register_access;
    acc_mode = "0";
    acc_desc = "Access rules for `register' program";
    break;
  case SSERV_CMD_EDIT_USERS_ACCESS:
    acc = cnts->users_access;
    acc_mode = "1";
    acc_desc = "Access rules for `users' program";
    break;
  case SSERV_CMD_EDIT_MASTER_ACCESS:
    acc = cnts->master_access;
    acc_mode = "2";
    acc_desc = "Access rules for `master' program";
    break;
  case SSERV_CMD_EDIT_JUDGE_ACCESS:
    acc = cnts->judge_access;
    acc_mode = "3";
    acc_desc = "Access rules for `judge' program";
    break;
  case SSERV_CMD_EDIT_TEAM_ACCESS:
    acc = cnts->team_access;
    acc_mode = "4";
    acc_desc = "Access rules for `team' program";
    break;
  case SSERV_CMD_EDIT_SERVE_CONTROL_ACCESS:
    acc = cnts->serve_control_access;
    acc_mode = "5";
    acc_desc = "Access rules for `serve-control' program";
    break;
  default:
    abort();
  }

  if (acc) default_is_allow = acc->default_is_allow;

  fprintf(f, "<h2>%s, contest %d</h2>\n", acc_desc, cnts->id);
  fprintf(f, "<table border=\"0\">\n");

  if (acc) {
    for (p = (struct contest_ip*) acc->b.first_down, i = 0;
         p; p = (struct contest_ip*) p->b.right, i++) {
      snprintf(num_str, sizeof(num_str), "%d", i);
      html_start_form(f, 1, self_url, hidden_vars);
      html_hidden_var(f, "acc_mode", acc_mode);
      html_hidden_var(f, "rule_num", num_str);
      fprintf(f, "<tr%s><td>%d</td><td><tt>%s</tt></td><td>",
              form_row_attrs[row ^= 1], i,
              xml_unparse_ip_mask(p->addr, p->mask));
      html_boolean_select(f, p->allow, "access", "deny", "allow");
      fprintf(f, "</td><td>");
      html_ssl_select(f, p->ssl);
      fprintf(f, "</td><td>");
      html_submit_button(f, SSERV_CMD_CNTS_CHANGE_RULE, "Change");
      html_submit_button(f, SSERV_CMD_CNTS_DELETE_RULE, "Delete");
      if (i > 0) html_submit_button(f, SSERV_CMD_CNTS_UP_RULE, "Move up");
      if (p->b.right) html_submit_button(f, SSERV_CMD_CNTS_DOWN_RULE, "Move down");
      fprintf(f, "</td></tr></form>\n");
    }
  }

  html_start_form(f, 1, self_url, hidden_vars);
  html_hidden_var(f, "acc_mode", acc_mode);
  fprintf(f, "<tr%s><td>New address:</td><td>", form_row_attrs[row ^= 1]);
  html_edit_text_form(f, 16, 16, "ip", "");
  fprintf(f, "</td><td>");
  html_boolean_select(f, 0, "access", "deny", "allow");
  fprintf(f, "</td><td>");
  html_ssl_select(f, -1);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_ADD_RULE, "Add");
  fprintf(f, "</td></tr></form>\n");

  html_start_form(f, 1, self_url, hidden_vars);
  html_hidden_var(f, "acc_mode", acc_mode);
  fprintf(f, "<tr%s><td>Default access:</td><td>", form_row_attrs[row ^= 1]);
  html_boolean_select(f, default_is_allow, "access", "deny", "allow");
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_DEFAULT_ACCESS, "Change");
  fprintf(f, "</td></tr></form>\n");
  fprintf(f, "</table>\n");

  contest_max_id = contests_get_list(&contests_map);
  fprintf(f, "<p><table border=\"0\">\n");
  html_start_form(f, 1, self_url, hidden_vars);
  html_hidden_var(f, "acc_mode", acc_mode);
  fprintf(f, "<tr><td>Copy access rules from:</td><td>");
  fprintf(f, "<select name=\"templ_id\">\n");
  fprintf(f, "<option value=\"0\">Current contest</option>\n");
  for (cnts_id = 1; cnts_id < contest_max_id; cnts_id++) {
    if (!contests_map[cnts_id]) continue;
    if (contests_get(cnts_id, &tmp_cnts) < 0) continue;
    cnts_name = html_armor_string_dup(tmp_cnts->name);
    fprintf(f, "<option value=\"%d\">%d - %s</option>", cnts_id, cnts_id, cnts_name);
    xfree(cnts_name);
  }
  fprintf(f,
          "</td><td><select name=\"acc_from\">\n"
          "<option value=\"0\">&lt;register_access&gt;</option>\n"
          "<option value=\"1\">&lt;users_access&gt;</option>\n"
          "<option value=\"2\">&lt;master_access&gt;</option>\n"
          "<option value=\"3\">&lt;judge_access&gt;</option>\n"
          "<option value=\"4\">&lt;team_access&gt;</option>\n"
          "<option value=\"5\">&lt;serve_control_access&gt;</option>\n"
          "</select></td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_COPY_ACCESS, "Copy");
  fprintf(f, "</td></tr></form>");
  fprintf(f, "</table>\n");
  xfree(contests_map); contests_map = 0;

  fprintf(f, "<table border=\"0\"><tr><td>%sTo the top</a></td>",
          html_hyperref(hbuf,sizeof(hbuf),session_id,self_url,extra_args, 0));
  fprintf(f, "<td>%sBack</a></td></tr></table>\n",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                        "action=%d", SSERV_CMD_EDIT_CURRENT_CONTEST));

  return 0;
}

static const char * contest_cap_descs[] =
{
  [OPCAP_MASTER_LOGIN] = "Use the `master' CGI-program",
  [OPCAP_JUDGE_LOGIN] = "Use the `judge' CGI-program",
  [OPCAP_SUBMIT_RUN] = "Submit a run from the `master' or `judge' programs",
  [OPCAP_MAP_CONTEST] = "Start the `serve' from the command line",
  [OPCAP_LIST_CONTEST_USERS] = "List all the participating users (incl. invisible, banned)",
  [OPCAP_GET_USER] = "View the user details for the participating users",
  [OPCAP_EDIT_USER] = "Edit the user details for the non-privileged participating users",
  [OPCAP_PRIV_EDIT_USER] = "Edit the user details for the privileged participating users",
  [OPCAP_GENERATE_TEAM_PASSWORDS] = "Generate random `team' passwords for non-privileged users",
  [OPCAP_CREATE_REG] = "Register non-privileged users for the contest",
  [OPCAP_EDIT_REG] = "Change the registration status for non-privileged users",
  [OPCAP_DELETE_REG] = "Delete registration for non-privileged users",
  [OPCAP_PRIV_CREATE_REG] = "Register privileged users for the contest",
  [OPCAP_PRIV_DELETE_REG] = "Delete registration for privileged users",
  [OPCAP_DUMP_USERS] = "Dump the database of participating users in CSV-format",
  [OPCAP_DUMP_RUNS] = "Dump the runs database in CSV or XML formats",
  [OPCAP_DUMP_STANDINGS] = "Dump the standings in CSV format",
  [OPCAP_VIEW_STANDINGS] = "View the actual standings (even during freeze period)",
  [OPCAP_VIEW_SOURCE] = "View the program source code for the runs",
  [OPCAP_VIEW_REPORT] = "View the judge testing protocol for the runs",
  [OPCAP_VIEW_CLAR] = "View the clarification requests",
  [OPCAP_EDIT_RUN] = "Edit the run parameters",
  [OPCAP_REJUDGE_RUN] = "Rejudge runs",
  [OPCAP_NEW_MESSAGE] = "Compose a new message to the participants",
  [OPCAP_REPLY_MESSAGE] = "Reply for clarification requests",
  [OPCAP_CONTROL_CONTEST] = "Perform contest administration (start/stop, etc)",
  [OPCAP_IMPORT_XML_RUNS] = "Import and merge the XML run database",
  [OPCAP_PRINT_RUN] = "Print any run without quota restrictions",
  [OPCAP_EDIT_CONTEST] = "Edit the contest settings using `serve-control'",
};

int
super_html_edit_permission(FILE *f,
                           int priv_level,
                           int user_id,
                           const unsigned char *login,
                           ej_cookie_t session_id,
                           ej_ip_t ip_address,
                           struct ejudge_cfg *config,
                           struct sid_state *sstate,
                           int num,
                           const unsigned char *self_url,
                           const unsigned char *hidden_vars,
                           const unsigned char *extra_args)
{
  struct contest_desc *cnts = sstate->edited_cnts;
  int i;
  struct opcap_list_item *p;
  unsigned char hbuf[1024];
  int row = 1;

  if (!cnts) {
    fprintf(f, "<h2>No current contest!</h2>\n"
            "<p>%sTo the top</a></p>\n",
            html_hyperref(hbuf,sizeof(hbuf),session_id,self_url,extra_args,0));
    return 0;
  }

  for (i = 0, p = cnts->capabilities.first;
       i < num && p;
       i++, p = (struct opcap_list_item*) p->b.right);
  if (i != num || !p || !p->login) {
    return -SSERV_ERR_INVALID_PARAMETER;
  }

  fprintf(f, "<h2>Editing capabilities for user %s, contest %d</h2>",
          p->login, cnts->id);

  html_start_form(f, 1, self_url, hidden_vars);
  snprintf(hbuf, sizeof(hbuf), "%d", num);
  html_hidden_var(f, "num", hbuf);
  fprintf(f, "<table border=\"0\">\n");
  for (i = 0; i < OPCAP_LAST; i++) {
    if (!opcaps_is_contest_cap(i)) continue;
    fprintf(f, "<tr%s><td>%d</td><td><input type=\"checkbox\" name=\"cap_%d\"",
            form_row_attrs[row ^= 1], i, i);
    if (opcaps_check(p->caps, i) >= 0) fprintf(f, " checked=\"yes\"");
    fprintf(f, "/></td><td><tt>%s</tt></td><td>%s</td></tr>\n",
            opcaps_get_name(i), contest_cap_descs[i]);
  }
  fprintf(f, "</table>");

  fprintf(f, "<table border=\"0\"><tr><td>%sTo the top</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url,extra_args,0));
  fprintf(f, "<td>%sForget changes</a></td><td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                        "action=%d", SSERV_CMD_EDIT_CURRENT_CONTEST));
  html_submit_button(f, SSERV_CMD_CNTS_SAVE_PERMISSIONS, "Save");
  fprintf(f, "</td></tr></table>\n");
  fprintf(f, "</form>\n");

  // predefined permission sets
  fprintf(f, "<h2>Predefined permission sets</h2>\n");
  html_start_form(f, 1, self_url, hidden_vars);
  snprintf(hbuf, sizeof(hbuf), "%d", num);
  html_hidden_var(f, "num", hbuf);
  fprintf(f, "<table border=\"0\"><tr><td>");
  fprintf(f, "<select name=\"param\">");
  fprintf(f, "<option value=\"0\"></option>"
          "<option value=\"1\">Observer</option>"
          "<option value=\"2\">Judge</option>"
          "<option value=\"3\">Full control</option>"
          "</select></td><td>");
  fprintf(f, "</select>");

  html_submit_button(f, SSERV_CMD_CNTS_SET_PREDEF_PERMISSIONS, "Set permissions");
  fprintf(f, "</td></tr></table>");
  fprintf(f, "</form>\n");

  return 0;
}

static void
print_field_row_select(FILE *f, int num, const unsigned char *comment, int value, const unsigned char *row_attr)
{
  fprintf(f, "<tr%s><td>%s</td><td><select name=\"field_%d\">",
          row_attr, comment, num);
  fprintf(f, "<option value=\"0\"%s>Disabled</option>",
          value == 0?" selected=\"1\"":"");
  fprintf(f, "<option value=\"1\"%s>Optional</option>",
          value == 1?" selected=\"1\"":"");
  fprintf(f, "<option value=\"2\"%s>Mandatory</option>",
          value == 2?" selected=\"1\"":"");
  fprintf(f, "</select></td></tr>\n");
}

int
super_html_edit_form_fields(FILE *f,
                            int priv_level,
                            int user_id,
                            const unsigned char *login,
                            ej_cookie_t session_id,
                            ej_ip_t ip_address,
                            struct ejudge_cfg *config,
                            struct sid_state *sstate,
                            int cmd,
                            const unsigned char *self_url,
                            const unsigned char *hidden_vars,
                            const unsigned char *extra_args)
{
  struct contest_desc *cnts = sstate->edited_cnts;
  unsigned char hbuf[1024];
  int first_index, last_index, allow_setting_minmax, commit_action, val, i;
  const unsigned char * const *field_names;
  struct contest_member *memb = 0;
  struct contest_field **fields = 0;
  unsigned char *desc_txt;
  int row = 1;

  if (!cnts) {
    fprintf(f, "<h2>No current contest!</h2>\n"
            "<p>%sTo the top</a></p>\n",
            html_hyperref(hbuf, sizeof(hbuf),session_id,self_url,extra_args,0));
    return 0;
  }

  switch (cmd) {
  case SSERV_CMD_CNTS_EDIT_FORM_FIELDS:
    first_index = 1;
    last_index = CONTEST_LAST_FIELD;
    field_names = form_field_names;
    allow_setting_minmax = 0;
    fields = cnts->fields;
    desc_txt = "Basic fields";
    commit_action = SSERV_CMD_CNTS_SAVE_FORM_FIELDS;
    break;
  case SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS:
    first_index = 1;
    last_index = CONTEST_LAST_MEMBER_FIELD;
    field_names = member_field_names;
    allow_setting_minmax = 1;
    memb = cnts->members[CONTEST_M_CONTESTANT];
    if (memb) fields = memb->fields;
    desc_txt = "Fields for \"Contestant\" participants";
    commit_action = SSERV_CMD_CNTS_SAVE_CONTESTANT_FIELDS;
    break;
  case SSERV_CMD_CNTS_EDIT_RESERVE_FIELDS:
    first_index = 1;
    last_index = CONTEST_LAST_MEMBER_FIELD;
    field_names = member_field_names;
    allow_setting_minmax = 1;
    memb = cnts->members[CONTEST_M_RESERVE];
    if (memb) fields = memb->fields;
    desc_txt = "Fields for \"Reserve\" participants";
    commit_action = SSERV_CMD_CNTS_SAVE_RESERVE_FIELDS;
    break;
  case SSERV_CMD_CNTS_EDIT_COACH_FIELDS:
    first_index = 1;
    last_index = CONTEST_LAST_MEMBER_FIELD;
    field_names = member_field_names;
    allow_setting_minmax = 1;
    memb = cnts->members[CONTEST_M_COACH];
    if (memb) fields = memb->fields;
    desc_txt = "Fields for \"Coach\" participants";
    commit_action = SSERV_CMD_CNTS_SAVE_COACH_FIELDS;
    break;
  case SSERV_CMD_CNTS_EDIT_ADVISOR_FIELDS:
    first_index = 1;
    last_index = CONTEST_LAST_MEMBER_FIELD;
    field_names = member_field_names;
    allow_setting_minmax = 1;
    memb = cnts->members[CONTEST_M_ADVISOR];
    if (memb) fields = memb->fields;
    desc_txt = "Fields for \"Advisor\" participants";
    commit_action = SSERV_CMD_CNTS_SAVE_ADVISOR_FIELDS;
    break;
  case SSERV_CMD_CNTS_EDIT_GUEST_FIELDS:
    first_index = 1;
    last_index = CONTEST_LAST_MEMBER_FIELD;
    field_names = member_field_names;
    allow_setting_minmax = 1;
    memb = cnts->members[CONTEST_M_GUEST];
    if (memb) fields = memb->fields;
    desc_txt = "Fields for \"Guest\" participants";
    commit_action = SSERV_CMD_CNTS_SAVE_GUEST_FIELDS;
    break;
  default:
    abort();
  }

  fprintf(f, "<h2>Editing %s, Contest %d</h2>", desc_txt, cnts->id);

  html_start_form(f, 1, self_url, hidden_vars);

  fprintf(f, "<table border=\"0\">");
  if (allow_setting_minmax) {
    val = 0;
    if (memb) val = memb->min_count;
    fprintf(f, "<tr%s><td>Minimal number:</td><td>", form_row_attrs[row ^= 1]);
    html_numeric_select(f, "min_count", val, 0, 5);
    fprintf(f, "</td></tr>\n");
    val = 0;
    if (memb) val = memb->max_count;
    fprintf(f, "<tr%s><td>Maximal number:</td><td>", form_row_attrs[row ^= 1]);
    html_numeric_select(f, "max_count", val, 0, 5);
    fprintf(f, "</td></tr>\n");
    val = 0;
    if (memb) val = memb->init_count;
    fprintf(f, "<tr%s><td>Initial number:</td><td>", form_row_attrs[row ^= 1]);
    html_numeric_select(f, "init_count", val, 0, 5);
    fprintf(f, "</td></tr>\n");
  }
  for (i = first_index; i < last_index; i++) {
    val = 0;
    if (fields && fields[i]) {
      val = 1;
      if (fields[i]->mandatory) val = 2;
    }
    print_field_row_select(f, i, field_names[i], val, form_row_attrs[row ^= 1]);
  }
  fprintf(f, "</table>");

  fprintf(f, "<table border=\"0\"><tr><td>%sTo the top</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url,extra_args,0));
  fprintf(f, "<td>%sBack</a></td><td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                        "action=%d", SSERV_CMD_EDIT_CURRENT_CONTEST));
  html_submit_button(f, commit_action, "Save");
  fprintf(f, "</td></tr></table></form>\n");
  return 0;
}

static const unsigned char template_help_1[] =
"<table border=\"1\">\n"
"<tr><td><tt>%L</tt></td><td>The locale number (0 - English, 1 - Russian)</td></tr>\n"
"<tr><td><tt>%C</tt></td><td>The page character set</td></tr>\n"
"<tr><td><tt>%T</tt></td><td>The content type (text/html)</td></tr>\n"
"<tr><td><tt>%H</tt></td><td>The page title</td></tr>\n"
"<tr><td><tt>%R</tt></td><td>The ejudge copyright notice</td></tr>\n"
"<tr><td><tt>%%</tt></td><td>The percent sign <tt>%</tt></td></tr>\n"
"</table>\n";
static const unsigned char template_help_2[] =
"<table border=\"1\">\n"
"<tr><td><tt>%Ui</tt></td>The user identifier<td></td></tr>\n"
"<tr><td><tt>%Un</tt></td>The user name<td></td></tr>\n"
"<tr><td><tt>%Ul</tt></td>The user login<td></td></tr>\n"
"<tr><td><tt>%Ue</tt></td>The user e-mail<td></td></tr>\n"
"<tr><td><tt>%Uz</tt></td>The user registration password<td></td></tr>\n"
"<tr><td><tt>%UZ</tt></td>The user team password<td></td></tr>\n"
"<tr><td><tt>%Vl</tt></td>The locale number (0 - English, 1 - Russian)<td></td></tr>\n"
"<tr><td><tt>%Vu</tt></td>The `register' CGI-program URL<td></td></tr>\n"
"<tr><td><tt>%%</tt></td><td>The percent sign <tt>%</tt></td></tr>\n"
"</table>\n";
static const unsigned char template_help_3[] = "";

int
super_html_edit_template_file(FILE *f,
                              int priv_level,
                              int user_id,
                              const unsigned char *login,
                              ej_cookie_t session_id,
                              ej_ip_t ip_address,
                              struct ejudge_cfg *config,
                              struct sid_state *sstate,
                              int cmd,
                              const unsigned char *self_url,
                              const unsigned char *hidden_vars,
                              const unsigned char *extra_args)
{
  struct contest_desc *cnts = sstate->edited_cnts;
  struct section_global_data *global = sstate->global;
  unsigned char hbuf[1024];
  unsigned char conf_path[PATH_MAX];
  unsigned char full_path[PATH_MAX];
  unsigned char *file_path1 = 0;
  unsigned char *failure_text = 0;
  unsigned char *param_expl;
  unsigned char **p_str;
  unsigned char *s;
  struct stat stb;
  int commit_action, reread_action, clear_action, back_action;
  const unsigned char *help_txt;

  switch (cmd) {
  case SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD:
    if (!global) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = global->contest_start_cmd;
    param_expl = "Contest start script";
    p_str = &sstate->contest_start_cmd_text;
    commit_action = SSERV_CMD_GLOB_SAVE_CONTEST_START_CMD;
    reread_action = SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD_TEXT;
    clear_action = SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_GLOBAL;
    help_txt = template_help_3;
    break;

  case SSERV_CMD_GLOB_EDIT_STAND_HEADER_FILE:
    if (!global) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = global->stand_header_file;
    param_expl = "Standings HTML header file";
    p_str = &sstate->stand_header_text;
    commit_action = SSERV_CMD_GLOB_SAVE_STAND_HEADER;
    reread_action = SSERV_CMD_GLOB_CLEAR_STAND_HEADER_TEXT;
    clear_action = SSERV_CMD_GLOB_CLEAR_STAND_HEADER_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_GLOBAL;
    help_txt = template_help_1;
    break;
  case SSERV_CMD_GLOB_EDIT_STAND_FOOTER_FILE:
    if (!global) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = global->stand_footer_file;
    param_expl = "Standings HTML footer file";
    p_str = &sstate->stand_footer_text;
    commit_action = SSERV_CMD_GLOB_SAVE_STAND_FOOTER;
    reread_action = SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_TEXT;
    clear_action = SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_GLOBAL;
    help_txt = template_help_1;
    break;
  case SSERV_CMD_GLOB_EDIT_STAND2_HEADER_FILE:
    if (!global) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = global->stand2_header_file;
    param_expl = "Supplementary standings HTML header file";
    p_str = &sstate->stand2_header_text;
    commit_action = SSERV_CMD_GLOB_SAVE_STAND2_HEADER;
    reread_action = SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_TEXT;
    clear_action = SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_GLOBAL;
    help_txt = template_help_1;
    break;
  case SSERV_CMD_GLOB_EDIT_STAND2_FOOTER_FILE:
    if (!global) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = global->stand2_footer_file;
    param_expl = "Supplementary standings HTML footer file";
    p_str = &sstate->stand2_footer_text;
    commit_action = SSERV_CMD_GLOB_SAVE_STAND2_FOOTER;
    reread_action = SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_TEXT;
    clear_action = SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_GLOBAL;
    help_txt = template_help_1;
    break;
  case SSERV_CMD_GLOB_EDIT_PLOG_HEADER_FILE:
    if (!global) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = global->plog_header_file;
    param_expl = "Public submission log HTML header file";
    p_str = &sstate->plog_header_text;
    commit_action = SSERV_CMD_GLOB_SAVE_PLOG_HEADER;
    reread_action = SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_TEXT;
    clear_action = SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_GLOBAL;
    help_txt = template_help_1;
    break;
  case SSERV_CMD_GLOB_EDIT_PLOG_FOOTER_FILE:
    if (!global) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = global->plog_footer_file;
    param_expl = "Public submission log HTML footer file";
    p_str = &sstate->plog_footer_text;
    commit_action = SSERV_CMD_GLOB_SAVE_PLOG_FOOTER;
    reread_action = SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_TEXT;
    clear_action = SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_GLOBAL;
    help_txt = template_help_1;
    break;

  case SSERV_CMD_CNTS_EDIT_USERS_HEADER:
    if (!cnts) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = cnts->users_header_file;
    param_expl = "`users' HTML header file";
    p_str = &sstate->users_header_text;
    commit_action = SSERV_CMD_CNTS_SAVE_USERS_HEADER;
    reread_action = SSERV_CMD_CNTS_CLEAR_USERS_HEADER_TEXT;
    clear_action = SSERV_CMD_CNTS_CLEAR_USERS_HEADER_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_CONTEST;
    help_txt = template_help_1;
    break;
  case SSERV_CMD_CNTS_EDIT_USERS_FOOTER:
    if (!cnts) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = cnts->users_footer_file;
    param_expl = "`users' HTML footer file";
    p_str = &sstate->users_footer_text;
    commit_action = SSERV_CMD_CNTS_SAVE_USERS_FOOTER;
    reread_action = SSERV_CMD_CNTS_CLEAR_USERS_FOOTER_TEXT;
    clear_action = SSERV_CMD_CNTS_CLEAR_USERS_FOOTER_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_CONTEST;
    help_txt = template_help_1;
    break;
  case SSERV_CMD_CNTS_EDIT_REGISTER_HEADER:
    if (!cnts) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = cnts->register_header_file;
    param_expl = "`register' HTML header file";
    p_str = &sstate->register_header_text;
    commit_action = SSERV_CMD_CNTS_SAVE_REGISTER_HEADER;
    reread_action = SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER_TEXT;
    clear_action = SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_CONTEST;
    help_txt = template_help_1;
    break;
  case SSERV_CMD_CNTS_EDIT_REGISTER_FOOTER:
    if (!cnts) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = cnts->register_footer_file;
    param_expl = "`register' HTML footer file";
    p_str = &sstate->register_footer_text;
    commit_action = SSERV_CMD_CNTS_SAVE_REGISTER_FOOTER;
    reread_action = SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER_TEXT;
    clear_action = SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_CONTEST;
    help_txt = template_help_1;
    break;
  case SSERV_CMD_CNTS_EDIT_TEAM_HEADER:
    if (!cnts) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = cnts->team_header_file;
    param_expl = "`team' HTML header file";
    p_str = &sstate->team_header_text;
    commit_action = SSERV_CMD_CNTS_SAVE_TEAM_HEADER;
    reread_action = SSERV_CMD_CNTS_CLEAR_TEAM_HEADER_TEXT;
    clear_action = SSERV_CMD_CNTS_CLEAR_TEAM_HEADER_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_CONTEST;
    help_txt = template_help_1;
    break;
  case SSERV_CMD_CNTS_EDIT_TEAM_FOOTER:
    if (!cnts) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = cnts->team_footer_file;
    param_expl = "`team' HTML footer file";
    p_str = &sstate->team_footer_text;
    commit_action = SSERV_CMD_CNTS_SAVE_TEAM_FOOTER;
    reread_action = SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER_TEXT;
    clear_action = SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_CONTEST;
    help_txt = template_help_1;
    break;
  case SSERV_CMD_CNTS_EDIT_PRIV_HEADER:
    if (!cnts) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = cnts->priv_header_file;
    param_expl = "privileged HTML header file";
    p_str = &sstate->priv_header_text;
    commit_action = SSERV_CMD_CNTS_SAVE_PRIV_HEADER;
    reread_action = SSERV_CMD_CNTS_CLEAR_PRIV_HEADER_TEXT;
    clear_action = SSERV_CMD_CNTS_CLEAR_PRIV_HEADER_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_CONTEST;
    help_txt = template_help_1;
    break;
  case SSERV_CMD_CNTS_EDIT_PRIV_FOOTER:
    if (!cnts) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = cnts->priv_footer_file;
    param_expl = "privileged HTML footer file";
    p_str = &sstate->priv_footer_text;
    commit_action = SSERV_CMD_CNTS_SAVE_PRIV_FOOTER;
    reread_action = SSERV_CMD_CNTS_CLEAR_PRIV_FOOTER_TEXT;
    clear_action = SSERV_CMD_CNTS_CLEAR_PRIV_FOOTER_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_CONTEST;
    help_txt = template_help_1;
    break;
  case SSERV_CMD_CNTS_EDIT_COPYRIGHT:
    if (!cnts) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = cnts->copyright_file;
    param_expl = "copyright notice file";
    p_str = &sstate->copyright_text;
    commit_action = SSERV_CMD_CNTS_SAVE_COPYRIGHT;
    reread_action = SSERV_CMD_CNTS_CLEAR_COPYRIGHT_TEXT;
    clear_action = SSERV_CMD_CNTS_CLEAR_COPYRIGHT_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_CONTEST;
    help_txt = template_help_1;
    break;
  case SSERV_CMD_CNTS_EDIT_REGISTER_EMAIL_FILE:
    if (!cnts) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = cnts->register_email_file;
    param_expl = "registration letter template";
    p_str = &sstate->register_email_text;
    commit_action = SSERV_CMD_CNTS_SAVE_REGISTER_EMAIL_FILE;
    reread_action = SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE_TEXT;
    clear_action = SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_CONTEST;
    help_txt = template_help_2;
    break;
  default:
    abort();
  }

  if (!file_path1 || !*file_path1) {
    failure_text = "path variable is not set";
    goto failure;
  }
  if (!cnts->root_dir || !*cnts->root_dir) {
    failure_text = "root_dir is not set";
    goto failure;
  }
  if (!os_IsAbsolutePath(cnts->root_dir)) {
    failure_text = "root_dir is not absolute";
    goto failure;
  }

  if (!cnts->conf_dir) {
    snprintf(conf_path, sizeof(conf_path), "%s/%s", cnts->root_dir, "conf");
  } else if (!os_IsAbsolutePath(cnts->conf_dir)) {
    snprintf(conf_path, sizeof(conf_path), "%s/%s", cnts->root_dir, cnts->conf_dir);
  }
  if (!os_IsAbsolutePath(file_path1)) {
    snprintf(full_path, sizeof(full_path), "%s/%s", conf_path, file_path1);
  } else {
    snprintf(full_path, sizeof(full_path), "%s", file_path1);
  }

  fprintf(f, "<h2>Editing %s, contest %d</h2>\n", param_expl, cnts->id);

  s = html_armor_string_dup(file_path1);
  fprintf(f, "<table border=\"0\">"
          "<tr><td>Parameter value:</td><td>%s</td></tr>\n", s);
  xfree(s);
  s = html_armor_string_dup(full_path);
  fprintf(f, "<tr><td>Full path:</td><td>%s</td></tr></table>\n", s);
  xfree(s);

  if (stat(full_path, &stb) < 0) {
    fprintf(f, "<p><big><font color=\"red\">Note: file does not exist</font></big></p>\n");
  } else if (!S_ISREG(stb.st_mode)) {
    fprintf(f, "<p><big><font color=\"red\">Note: file is not regular</font></big></p>\n");
  } else if (access(full_path, R_OK) < 0) {
    fprintf(f, "<p><big><font color=\"red\">Note: file is not readable</font></big></p>\n");
  } else {
    if (!*p_str) {
      char *tmp_b = 0;
      size_t tmp_sz = 0;

      if (generic_read_file(&tmp_b, 0, &tmp_sz, 0, 0, full_path, 0) < 0) {
        fprintf(f, "<p><big><font color=\"red\">Note: cannot read file</font></big></p>\n");
      } else {
        *p_str = tmp_b;
      }
    }
  }
  if (!*p_str) *p_str = xstrdup("");

  html_start_form(f, 2, self_url, hidden_vars);
  s = html_armor_string_dup(*p_str);
  fprintf(f, "<textarea name=\"param\" rows=\"20\" cols=\"80\">%s</textarea>\n",
          s);
  xfree(s);

  fprintf(f, "<table border=\"0\"><tr><td>%sTo the top</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url,extra_args,0));
  fprintf(f, "<td>%sBack</a></td><td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                   "action=%d", back_action));
  fprintf(f, "</td><td>");
  html_submit_button(f, reread_action, "Re-read");
  fprintf(f, "</td><td>");
  html_submit_button(f, commit_action, "Save");
  fprintf(f, "</td><td>");
  html_submit_button(f, clear_action, "Clear");
  fprintf(f, "</td></tr></table></form>\n");

  fprintf(f, "<hr><h2>Summary of valid format substitutions</h2>%s\n", help_txt);

  return 0;

 failure:
  return super_html_report_error(f, session_id, self_url, extra_args,
                                 "%s", failure_text);
}

void
super_html_load_serve_cfg(const struct contest_desc *cnts,
                          const struct ejudge_cfg *config,
                          struct sid_state *sstate)
{
  path_t serve_cfg_path;
  char *flog_txt = 0;
  size_t flog_len = 0;
  FILE *flog = 0;

  if (!cnts->conf_dir || !*cnts->conf_dir) {
    snprintf(serve_cfg_path,sizeof(serve_cfg_path),"%s/conf/serve.cfg",cnts->root_dir);
  } else if (!os_IsAbsolutePath(cnts->conf_dir)) {
    snprintf(serve_cfg_path, sizeof(serve_cfg_path), "%s/%s/serve.cfg",
             cnts->root_dir, cnts->conf_dir);
  } else {
    snprintf(serve_cfg_path, sizeof(serve_cfg_path), "%s/serve.cfg", cnts->conf_dir);
  }

  flog = open_memstream(&flog_txt, &flog_len);

  if (access(serve_cfg_path, R_OK) < 0) {
    fprintf(flog, "file %s does not exist or is not readable\n", serve_cfg_path);
    fclose(flog); flog = 0;
    sstate->serve_parse_errors = flog_txt;
    flog_txt = 0; flog_len = 0;
  } else if (super_html_read_serve(flog, serve_cfg_path, config, cnts, sstate) < 0) {
    fclose(flog); flog = 0;
    sstate->serve_parse_errors = flog_txt;
    flog_txt = 0; flog_len = 0;
  } else {
    fclose(flog); flog = 0;
    xfree(flog_txt); flog_txt = 0;
    flog_len = 0;
  }
}

int
super_html_create_contest_2(FILE *f,
                            int priv_level,
                            int user_id,
                            const unsigned char *login,
                            const unsigned char *ss_login,
                            ej_cookie_t session_id,
                            ej_ip_t ip_address,
                            struct ejudge_cfg *config,
                            struct sid_state *sstate,
                            int num_mode,
                            int templ_mode,
                            int contest_id,
                            int templ_id,
                            const unsigned char *self_url,
                            const unsigned char *hidden_vars,
                            const unsigned char *extra_args)
{
  unsigned char *contests_map = 0;
  int contests_num;
  int errcode = 0;
  const struct contest_desc *templ_cnts = 0;

  if (sstate->edited_cnts) {
    errcode = -SSERV_ERR_CONTEST_EDITED;
    goto cleanup;
  }

  contests_num = contests_get_list(&contests_map);
  if (contests_num < 0 || !contests_num) {
    errcode = -SSERV_ERR_SYSTEM_ERROR;
    goto cleanup;
  }
  if (!num_mode) {
    contest_id = contests_num;
    if (!contest_id) contest_id = 1;
  } else {
    if (contest_id <= 0 || contest_id > 999999) {
      errcode = -SSERV_ERR_INVALID_CONTEST;
      goto cleanup;
    }
    if (contest_id < contests_num && contests_map[contest_id]) {
      errcode = -SSERV_ERR_CONTEST_ALREADY_USED;
      goto cleanup;
    }
  }
  if (templ_mode) {
    if (templ_id <= 0 || templ_id >= contests_num || !contests_map[templ_id]) {
      errcode = -SSERV_ERR_INVALID_CONTEST;
      goto cleanup;
    }
    if (contests_get(templ_id, &templ_cnts) < 0) {
      errcode = -SSERV_ERR_INVALID_CONTEST;
      goto cleanup;
    }
  }

  // FIXME: touch the contest file
  if (!templ_mode) {
    sstate->edited_cnts = contest_tmpl_new(contest_id,
                                           login,
                                           self_url,
                                           ss_login,
                                           config);
    sstate->global = prepare_new_global_section(contest_id,
                                                sstate->edited_cnts->root_dir,
                                                config);
  } else {
    super_html_load_serve_cfg(templ_cnts, config, sstate);
    super_html_fix_serve(sstate, templ_id, contest_id);
    sstate->edited_cnts = contest_tmpl_clone(sstate, contest_id, templ_id, login,
                                             ss_login);
  }

  xfree(contests_map);
  return super_html_edit_contest_page(f, priv_level, user_id, login,
                                      session_id, ip_address, config, sstate,
                                      self_url, hidden_vars, extra_args);

 cleanup:
  xfree(contests_map);
  return errcode;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
