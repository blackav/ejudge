/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004-2014 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/version.h"
#include "ejudge/super_html.h"
#include "ejudge/super-serve.h"
#include "ejudge/super_proto.h"
#include "ejudge/contests.h"
#include "ejudge/misctext.h"
#include "ejudge/mischtml.h"
#include "ejudge/opcaps.h"
#include "ejudge/protocol.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/fileutl.h"
#include "ejudge/xml_utils.h"
#include "ejudge/prepare.h"
#include "ejudge/vcs.h"
#include "ejudge/compat.h"

#include "reuse/xalloc.h"
#include "reuse/logger.h"
#include "reuse/osdeps.h"

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

#define ARMOR(s)  html_armor_buf(&ab, s)

extern void print_help_url(FILE *, int);

static void
html_submit_button(FILE *f,
                   int action,
                   const unsigned char *label)
{
  fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\"/>",
          action, label);
}

void
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
super_html_open_contest(
        struct contest_desc *cnts,
        int user_id,
        const unsigned char *user_login,
        const ej_ip_t *ip_address)
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
           xml_unparse_date(time(0)), user_id, user_login,
           xml_unparse_ipv6(ip_address));

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
super_html_close_contest(
        struct contest_desc *cnts,
        int user_id,
        const unsigned char *user_login,
        const ej_ip_t *ip_address)
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
           xml_unparse_date(time(0)), user_id, user_login,
           xml_unparse_ipv6(ip_address));

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
super_html_make_invisible_contest(
        struct contest_desc *cnts,
        int user_id,
        const unsigned char *user_login,
        const ej_ip_t *ip_address)
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
           xml_unparse_date(time(0)), user_id, user_login,
           xml_unparse_ipv6(ip_address));

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
super_html_make_visible_contest(
        struct contest_desc *cnts,
        int user_id,
        const unsigned char *user_login,
        const ej_ip_t *ip_address)
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
           xml_unparse_date(time(0)), user_id, user_login,
           xml_unparse_ipv6(ip_address));

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
super_html_serve_managed_contest(
        struct contest_desc *cnts,
        int user_id,
        const unsigned char *user_login,
        const ej_ip_t *ip_address)
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
           xml_unparse_date(time(0)), user_id, user_login,
           xml_unparse_ipv6(ip_address));

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
super_html_serve_unmanaged_contest(
        struct contest_desc *cnts,
        int user_id,
        const unsigned char *user_login,
        const ej_ip_t *ip_address)
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
           xml_unparse_date(time(0)), user_id, user_login,
           xml_unparse_ipv6(ip_address));

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
super_html_run_managed_contest(
        struct contest_desc *cnts,
        int user_id,
        const unsigned char *user_login,
        const ej_ip_t *ip_address)
{
  int errcode;
  unsigned char *txt1, *txt2;
  unsigned char audit_str[1024];

  if (cnts->old_run_managed) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->old_run_managed = 1;
  cnts->run_managed = 0;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: run_unmanaged->old_run_managed %s %d (%s) %s -->\n",
           xml_unparse_date(time(0)), user_id, user_login,
           xml_unparse_ipv6(ip_address));

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
super_html_run_unmanaged_contest(
        struct contest_desc *cnts,
        int user_id,
        const unsigned char *user_login,
        const ej_ip_t *ip_address)
{
  int errcode;
  unsigned char *txt1, *txt2;
  unsigned char audit_str[1024];

  if (!cnts->old_run_managed) return 0;
  if ((errcode = super_html_parse_contest_xml(cnts->id, &txt1, &txt2)) < 0)
    return errcode;

  cnts->old_run_managed = 0;
  snprintf(audit_str, sizeof(audit_str),
           "<!-- audit: old_run_managed->run_unmanaged %s %d (%s) %s -->\n",
           xml_unparse_date(time(0)), user_id, user_login,
           xml_unparse_ipv6(ip_address));

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
                        "action=%d", SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE));
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
    /*
    fprintf(f, "%s", html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                                   "action=%d", SSERV_CMD_EDIT_CURRENT_CONTEST));
    */
    fprintf(f, "%s", html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                                   "action=%d", SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE));
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
super_html_locked_cnts_dialog(
        FILE *out_f,
        int priv_level,
        int user_id,
        const unsigned char *login,
        ej_cookie_t session_id,
        const ej_ip_t *ip_address,
        const struct ejudge_cfg *config,
        struct sid_state *sstate,
        const unsigned char *self_url,
        const unsigned char *hidden_vars,
        const unsigned char *extra_args,
        int contest_id,
        const struct sid_state *other_ss,
        int new_edit_mode)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  ASSERT(!sstate->edited_cnts);

  if (other_ss->user_id != user_id) {
    fprintf(out_f, "<p>Contest %d is already edited in session %016llx by user %s (%s). Please contact this user to release the lock.</p>",
            contest_id, other_ss->sid,
            other_ss->user_login, ARMOR(other_ss->user_name));

    fprintf(out_f, "<table border=\"0\">");
    fprintf(out_f, "<tr><td>");
    html_start_form(out_f, 1, self_url, hidden_vars);
    html_hidden(out_f, "op", "%d", SSERV_CMD_EDITED_CNTS_BACK);
    html_submit_button(out_f, SSERV_CMD_HTTP_REQUEST, "Back");
    fprintf(out_f, "</form>\n");
    fprintf(out_f, "</td><td>Return to the main page</td></tr>");
    fprintf(out_f, "</table>\n");

    html_armor_free(&ab);
    return 0;
  }

  fprintf(out_f,
          "<p>Contest %d is already edited by you in session %016llx.</p>",
          contest_id, other_ss->sid);

  fprintf(out_f, "<table border=\"0\">");
  fprintf(out_f, "<tr><td>");
  html_start_form(out_f, 1, self_url, hidden_vars);
  html_hidden(out_f, "op", "%d", SSERV_CMD_EDITED_CNTS_BACK);
  html_submit_button(out_f, SSERV_CMD_HTTP_REQUEST, "Back");
  fprintf(out_f, "</form>\n");
  fprintf(out_f, "</td><td>Return to the main page</td></tr>");

  fprintf(out_f, "<tr><td>");
  html_start_form(out_f, 1, self_url, hidden_vars);
  html_hidden(out_f, "op", "%d", SSERV_CMD_LOCKED_CNTS_FORGET);
  if (new_edit_mode) html_hidden(out_f, "new_edit", "1");
  html_hidden(out_f, "contest_id", "%d", contest_id);
  html_submit_button(out_f, SSERV_CMD_HTTP_REQUEST, "Forget editing");
  fprintf(out_f, "</form>\n");
  fprintf(out_f, "</td><td>Forget editing in that session and return to the top page<font color=\"red\">(All changes to the old contest will be lost)!</font></td></tr>");

  fprintf(out_f, "<tr><td>");
  html_start_form(out_f, 1, self_url, hidden_vars);
  html_hidden(out_f, "op", "%d", SSERV_CMD_LOCKED_CNTS_CONTINUE);
  if (new_edit_mode) html_hidden(out_f, "new_edit", "1");
  html_hidden(out_f, "contest_id", "%d", contest_id);
  html_submit_button(out_f, SSERV_CMD_HTTP_REQUEST, "Continue here");
  fprintf(out_f, "</form>\n");
  fprintf(out_f, "</td><td>Continue editing in this session</font></td></tr>");

  fprintf(out_f, "</table>\n");

  html_armor_free(&ab);
  return 0;
}

int
super_html_edited_cnts_dialog(
        FILE *out_f,
        int priv_level,
        int user_id,
        const unsigned char *login,
        ej_cookie_t session_id,
        const ej_ip_t *ip_address,
        const struct ejudge_cfg *config,
        struct sid_state *sstate,
        const unsigned char *self_url,
        const unsigned char *hidden_vars,
        const unsigned char *extra_args,
        const struct contest_desc *new_cnts,
        int new_edit_mode)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int contest_id = 0;

  ASSERT(sstate->edited_cnts);

  if (new_cnts) contest_id = new_cnts->id;
  fprintf(out_f, "<h2>Another contest opened for editing</h2>\n");
  fprintf(out_f, "<p>You have already opened another contest (");
  fprintf(out_f, "%d", sstate->edited_cnts->id);
  if (sstate->edited_cnts->name) {
    fprintf(out_f, ", %s", ARMOR(sstate->edited_cnts->name));
  }
  fprintf(out_f, ") for editing. Editing of several contests "
          "at a time is not supported. You may either continue "
          "suspended editing of contest ");
  fprintf(out_f, "%d", sstate->edited_cnts->id);
  fprintf(out_f, " or cancel that editing and ");
  if (!new_cnts) {
    fprintf(out_f, " create a new contest");
  } else {
    fprintf(out_f, " start editing of contest ");
    fprintf(out_f, "%d", new_cnts->id);
    if (new_cnts->name) {
      fprintf(out_f, " (%s)", ARMOR(new_cnts->name));
    }
  }
  fprintf(out_f, ".</p>\n");
  fprintf(out_f, "<table border=\"0\">");

  fprintf(out_f, "<tr><td>");
  html_start_form(out_f, 1, self_url, hidden_vars);
  html_hidden(out_f, "op", "%d", SSERV_CMD_EDITED_CNTS_BACK);
  html_submit_button(out_f, SSERV_CMD_HTTP_REQUEST, "Back");
  fprintf(out_f, "</form>\n");
  fprintf(out_f, "</td><td>Return to the main page</td></tr>");

  fprintf(out_f, "<tr><td>");
  html_start_form(out_f, 1, self_url, hidden_vars);
  html_hidden(out_f, "op", "%d", SSERV_CMD_EDITED_CNTS_CONTINUE);
  if (new_edit_mode) html_hidden(out_f, "new_edit", "1");
  html_submit_button(out_f, SSERV_CMD_HTTP_REQUEST, "Continue");
  fprintf(out_f, "</form>\n");
  fprintf(out_f, "</td><td>Continue suspended editing</td></tr>");

  fprintf(out_f, "<tr><td>");
  html_start_form(out_f, 1, self_url, hidden_vars);
  html_hidden(out_f, "op", "%d", SSERV_CMD_EDITED_CNTS_START_NEW);
  if (new_edit_mode) html_hidden(out_f, "new_edit", "1");
  if (contest_id > 0)
    html_hidden(out_f, "contest_id", "%d", contest_id);
  html_submit_button(out_f, SSERV_CMD_HTTP_REQUEST, "Start new");
  fprintf(out_f, "</form>\n");
  fprintf(out_f, "</td><td>Start new editing <font color=\"red\">All changes to the old contest will be lost!</font></td></tr>");

  fprintf(out_f, "</table>\n");

  html_armor_free(&ab);
  return 0;
}

void
super_html_unparse_access_2(FILE *out_f, const struct contest_access *acc)
{
  const struct contest_ip *p;
  unsigned char ssl_str[64];

  if (!acc) {
    fprintf(out_f, "default deny\n");
  } else {
    for (p = (const struct contest_ip*) acc->b.first_down;
         p; p = (const struct contest_ip*) p->b.right) {
      ssl_str[0] = 0;
      if (p->ssl >= 0)
        snprintf(ssl_str, sizeof(ssl_str), " %s", p->ssl?"(SSL)":"(No SSL)");
      fprintf(out_f, "%s%s %s\n",
              xml_unparse_ipv6_mask(&p->addr, &p->mask), ssl_str,
              p->allow?"allow":"deny");
    }
    fprintf(out_f, "default %s\n", acc->default_is_allow?"allow":"deny");
  }
}

unsigned char *
super_html_unparse_access(const struct contest_access *acc)
{
  char *acc_txt = 0;
  size_t acc_len = 0;
  FILE *af = 0;

  af = open_memstream(&acc_txt, &acc_len);
  super_html_unparse_access_2(af, acc);
  close_memstream(af); af = 0;
  return acc_txt;
}

static const unsigned char head_row_attr[] =
  " bgcolor=\"#a0a0a0\"";
static const unsigned char * const form_row_attrs[]=
{
  " bgcolor=\"#d0d0d0\"",
  " bgcolor=\"#e0e0e0\"",
};

const char * super_html_contest_cap_descs[OPCAP_LAST] =
{
  [OPCAP_MASTER_LOGIN] = "Use the `master' CGI-program",
  [OPCAP_JUDGE_LOGIN] = "Use the `judge' CGI-program",
  [OPCAP_SUBMIT_RUN] = "Submit a run from the `master' or `judge' programs",
  [OPCAP_MAP_CONTEST] = "Start the programs from the command line",
  [OPCAP_LIST_USERS] = "List the participating users (incl. invisible, banned)",
  [OPCAP_PRIV_EDIT_REG] = "Change the registration status for privileged users",
  [OPCAP_CREATE_USER] = "Create users in the database",
  [OPCAP_GET_USER] = "View the user details for the participating users",
  [OPCAP_EDIT_USER] = "Edit the user details for the non-privileged participating users",
  [OPCAP_DELETE_USER] = "Delete non-privileged users from the database",
  [OPCAP_PRIV_EDIT_USER] = "Edit the user details for the privileged participating users",
  [OPCAP_PRIV_DELETE_USER] = "Delete privileged users from the database",
  [OPCAP_EDIT_CONTEST] = "Edit the contest settings using `serve-control'",
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
  [OPCAP_EDIT_PASSWD] = "View and edit passwords for regular users",
  [OPCAP_PRIV_EDIT_PASSWD] = "View and edit passwords for privileged users",
  [OPCAP_RESTART] = "Restart the server programs",
  [OPCAP_COMMENT_RUN] = "Comment the runs",
  [OPCAP_UNLOAD_CONTEST] = "Unload contests",
};

void
super_html_print_caps_table(
        FILE *out_f,
        opcap_t caps,
        const unsigned char *table_opts,
        const unsigned char *td_opts)
{
  int i, row = 1;
  const unsigned char *s;

  if (!table_opts) table_opts = "";
  if (!td_opts) td_opts = "";

  fprintf(out_f, "<table%s>\n", table_opts);
  for (i = 0; i < OPCAP_LAST; i++) {
    s = "";
    if (opcaps_check(caps, i) >= 0) s = " checked=\"yes\"";

    fprintf(out_f,
            "<tr%s>"
            "<td%s>%d</td>"
            "<td%s><input type=\"checkbox\" name=\"cap_%d\"%s /></td>"
            "<td%s><tt>%s</tt></td>"
            "<td%s>%s</td>"
            "</tr>\n",
            form_row_attrs[row ^= 1], td_opts, i, td_opts, i, s,
            td_opts, opcaps_get_name(i), td_opts, super_html_contest_cap_descs[i]);
  }
  fprintf(out_f, "</table>");
}

const unsigned char super_html_template_help_1[] =
"<table border=\"1\">\n"
"<tr><td><tt>%L</tt></td><td>The locale number (0 - English, 1 - Russian)</td></tr>\n"
"<tr><td><tt>%C</tt></td><td>The page character set</td></tr>\n"
"<tr><td><tt>%T</tt></td><td>The content type (text/html)</td></tr>\n"
"<tr><td><tt>%H</tt></td><td>The page title</td></tr>\n"
"<tr><td><tt>%R</tt></td><td>The ejudge copyright notice</td></tr>\n"
"<tr><td><tt>%%</tt></td><td>The percent sign <tt>%</tt></td></tr>\n"
"</table>\n";
const unsigned char super_html_template_help_2[] =
"<table border=\"1\">\n"
"<tr><td><tt>%Ui</tt></td><td>The user identifier</td></tr>\n"
"<tr><td><tt>%Un</tt></td><td>The user name</td></tr>\n"
"<tr><td><tt>%Ul</tt></td><td>The user login</td></tr>\n"
"<tr><td><tt>%Ue</tt></td><td>The user e-mail</td></tr>\n"
"<tr><td><tt>%Uz</tt></td><td>The user registration password</td></tr>\n"
"<tr><td><tt>%UZ</tt></td><td>The user team password</td></tr>\n"
"<tr><td><tt>%Vl</tt></td><td>The locale number (0 - English, 1 - Russian)</td></tr>\n"
"<tr><td><tt>%Vu</tt></td><td>The `register' CGI-program URL</td></tr>\n"
"<tr><td><tt>%%</tt></td><td>The percent sign <tt>%</tt></td></tr>\n"
"</table>\n";
const unsigned char super_html_template_help_3[] = "";

int
super_html_edit_template_file(
        FILE *f,
        int priv_level,
        int user_id,
        const unsigned char *login,
        ej_cookie_t session_id,
        const ej_ip_t *ip_address,
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
  case _SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD:
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
    help_txt = super_html_template_help_3;
    break;

  case _SSERV_CMD_GLOB_EDIT_CONTEST_STOP_CMD:
    if (!global) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = global->contest_stop_cmd;
    if (!file_path1) file_path1 = "";
    param_expl = "Contest start script";
    p_str = &sstate->contest_stop_cmd_text;
    commit_action = SSERV_CMD_GLOB_SAVE_CONTEST_STOP_CMD;
    reread_action = SSERV_CMD_GLOB_CLEAR_CONTEST_STOP_CMD_TEXT;
    clear_action = SSERV_CMD_GLOB_CLEAR_CONTEST_STOP_CMD_TEXT;
    back_action = SSERV_CMD_EDIT_CURRENT_GLOBAL;
    help_txt = super_html_template_help_3;
    break;

  case _SSERV_CMD_GLOB_EDIT_STAND_HEADER_FILE:
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
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_GLOB_EDIT_STAND_FOOTER_FILE:
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
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_GLOB_EDIT_STAND2_HEADER_FILE:
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
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_GLOB_EDIT_STAND2_FOOTER_FILE:
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
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_GLOB_EDIT_PLOG_HEADER_FILE:
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
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_GLOB_EDIT_PLOG_FOOTER_FILE:
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
    help_txt = super_html_template_help_1;
    break;

  case _SSERV_CMD_CNTS_EDIT_USERS_HEADER:
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
    back_action = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE;
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_CNTS_EDIT_USERS_FOOTER:
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
    back_action = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE;
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_CNTS_EDIT_REGISTER_HEADER:
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
    back_action = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE;
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_CNTS_EDIT_REGISTER_FOOTER:
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
    back_action = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE;
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_CNTS_EDIT_TEAM_HEADER:
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
    back_action = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE;
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_CNTS_EDIT_TEAM_MENU_1:
    if (!cnts) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = cnts->team_menu_1_file;
    param_expl = "`team' HTML menu1 file";
    p_str = &sstate->team_menu_1_text;
    commit_action = SSERV_CMD_CNTS_SAVE_TEAM_MENU_1;
    reread_action = SSERV_CMD_CNTS_CLEAR_TEAM_MENU_1_TEXT;
    clear_action = SSERV_CMD_CNTS_CLEAR_TEAM_MENU_1_TEXT;
    back_action = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE;
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_CNTS_EDIT_TEAM_MENU_2:
    if (!cnts) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = cnts->team_menu_2_file;
    param_expl = "`team' HTML menu2 file";
    p_str = &sstate->team_menu_2_text;
    commit_action = SSERV_CMD_CNTS_SAVE_TEAM_MENU_2;
    reread_action = SSERV_CMD_CNTS_CLEAR_TEAM_MENU_2_TEXT;
    clear_action = SSERV_CMD_CNTS_CLEAR_TEAM_MENU_2_TEXT;
    back_action = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE;
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_CNTS_EDIT_TEAM_MENU_3:
    if (!cnts) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = cnts->team_menu_3_file;
    param_expl = "`team' HTML menu2 file";
    p_str = &sstate->team_menu_3_text;
    commit_action = SSERV_CMD_CNTS_SAVE_TEAM_MENU_3;
    reread_action = SSERV_CMD_CNTS_CLEAR_TEAM_MENU_3_TEXT;
    clear_action = SSERV_CMD_CNTS_CLEAR_TEAM_MENU_3_TEXT;
    back_action = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE;
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_CNTS_EDIT_TEAM_SEPARATOR:
    if (!cnts) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = cnts->team_separator_file;
    param_expl = "`team' HTML separator file";
    p_str = &sstate->team_separator_text;
    commit_action = SSERV_CMD_CNTS_SAVE_TEAM_SEPARATOR;
    reread_action = SSERV_CMD_CNTS_CLEAR_TEAM_SEPARATOR_TEXT;
    clear_action = SSERV_CMD_CNTS_CLEAR_TEAM_SEPARATOR_TEXT;
    back_action = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE;
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_CNTS_EDIT_TEAM_FOOTER:
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
    back_action = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE;
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_CNTS_EDIT_PRIV_HEADER:
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
    back_action = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE;
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_CNTS_EDIT_PRIV_FOOTER:
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
    back_action = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE;
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_CNTS_EDIT_COPYRIGHT:
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
    back_action = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE;
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_CNTS_EDIT_WELCOME:
    if (!cnts) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = cnts->welcome_file;
    param_expl = "`team' HTML header file";
    p_str = &sstate->welcome_text;
    commit_action = SSERV_CMD_CNTS_SAVE_WELCOME;
    reread_action = SSERV_CMD_CNTS_CLEAR_WELCOME_TEXT;
    clear_action = SSERV_CMD_CNTS_CLEAR_WELCOME_TEXT;
    back_action = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE;
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_CNTS_EDIT_REG_WELCOME:
    if (!cnts) {
      failure_text = "no current contest";
      goto failure;
    }
    file_path1 = cnts->reg_welcome_file;
    param_expl = "`team' HTML header file";
    p_str = &sstate->reg_welcome_text;
    commit_action = SSERV_CMD_CNTS_SAVE_REG_WELCOME;
    reread_action = SSERV_CMD_CNTS_CLEAR_REG_WELCOME_TEXT;
    clear_action = SSERV_CMD_CNTS_CLEAR_REG_WELCOME_TEXT;
    back_action = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE;
    help_txt = super_html_template_help_1;
    break;
  case _SSERV_CMD_CNTS_EDIT_REGISTER_EMAIL_FILE:
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
    back_action = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE;
    help_txt = super_html_template_help_2;
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
    close_memstream(flog); flog = 0;
    sstate->serve_parse_errors = flog_txt;
    flog_txt = 0; flog_len = 0;
  } else if (super_html_read_serve(flog, serve_cfg_path, config, cnts, sstate) < 0) {
    close_memstream(flog); flog = 0;
    sstate->serve_parse_errors = flog_txt;
    flog_txt = 0; flog_len = 0;
  } else {
    close_memstream(flog); flog = 0;
    xfree(flog_txt); flog_txt = 0;
    flog_len = 0;
  }
}
