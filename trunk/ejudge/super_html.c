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
  fprintf(f, "</td>");
  print_help_url(f, change_action);
  fprintf(f, "</tr></form>\n");
}

unsigned char *
super_html_unparse_access(const struct contest_access *acc)
{
  char *acc_txt = 0;
  size_t acc_len = 0;
  FILE *af = 0;
  const struct contest_ip *p;
  unsigned char ssl_str[64];

  af = open_memstream(&acc_txt, &acc_len);
  if (!acc) {
    fprintf(af, "default deny\n");
  } else {
    for (p = (const struct contest_ip*) acc->b.first_down;
         p; p = (const struct contest_ip*) p->b.right) {
      ssl_str[0] = 0;
      if (p->ssl >= 0)
        snprintf(ssl_str, sizeof(ssl_str), " %s", p->ssl?"(SSL)":"(No SSL)");
      fprintf(af, "%s%s %s\n",
              xml_unparse_ipv6_mask(&p->addr, &p->mask), ssl_str,
              p->allow?"allow":"deny");
    }
    fprintf(af, "default %s\n", acc->default_is_allow?"allow":"deny");
  }
  close_memstream(af); af = 0;
  return acc_txt;
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
  unsigned char hbuf[1024];

  acc_txt = super_html_unparse_access(acc);
  fprintf(f, "<tr valign=\"top\"%s><td>%s</td><td><pre>%s</pre></td><td>%sEdit</a></td>", row_attr, title, acc_txt, html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args, "action=%d", edit_action));
  print_help_url(f, edit_action);
  fprintf(f, "</tr>");
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
  struct opcap_list_item *p;
  unsigned char *s;
  unsigned char href[1024];
  int i, r = 0;

  for (i = 0, p = CNTS_FIRST_PERM(cnts); p; ++i, p = CNTS_NEXT_PERM_NC(p)) {
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
                          "action=%d&num=%d", SSERV_CMD_CNTS_EDIT_PERMISSIONS_PAGE, i));
    xfree(s);
    html_submit_button(f, SSERV_CMD_CNTS_DELETE_PERMISSION, "Delete");
    fprintf(f, "</td><td>&nbsp;</td></tr></form>");
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr valign=\"top\"%s><td>Add new user:</td><td>Login:",
          row_attrs[r]);
  html_edit_text_form(f, 32, 32, "param", "");
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_ADD_PERMISSION, "Add");
  fprintf(f, "</td><td>&nbsp;</td></tr></form>");
}

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
      fprintf(af, "\"%s\" %s\n", contests_get_member_field_name(i),
              descs[i]->mandatory?"mandatory":"optional");
    }
  }
  close_memstream(af); af = 0;

  fprintf(f, "<tr valign=\"top\"%s><td>%s</td><td><font size=\"-1\"><pre>%s</pre></font></td><td>%sEdit</a></td><td>&nbsp;</td></tr>\n", row_attr, title, out_txt,
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
      fprintf(af, "\"%s\" %s\n", contests_get_form_field_name(i),
              descs[i]->mandatory?"mandatory":"optional");
    }
  }
  close_memstream(af); af = 0;

  fprintf(f, "<tr valign=\"top\"%s><td>%s</td><td><font size=\"-1\"><pre>%s</pre></font></td><td>%sEdit</a></td><td>&nbsp;</td></tr>\n", row_attr, title, out_txt,
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
super_html_edit_contest_page(
        FILE *f,
        int priv_level,
        int user_id,
        const unsigned char *login,
        ej_cookie_t session_id,
        const ej_ip_t *ip_address,
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

  fprintf(f, "<tr%s><td colspan=\"4\" align=\"center\"><b>Basic contest identification</b></td></tr>", head_row_attr);
  row = 1;

  fprintf(f, "<tr%s><td>Contest ID:</td><td>%d</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n",
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
  print_string_editing_row(f, "Keywords:", cnts->keywords,
                           SSERV_CMD_CNTS_CHANGE_KEYWORDS,
                           SSERV_CMD_CNTS_CLEAR_KEYWORDS,
                           0,
                           session_id,
                           form_row_attrs[row ^= 1],
                           self_url,
                           extra_args,
                           hidden_vars);
  print_string_editing_row(f, "Contest to share users with:",
                           cnts->user_contest,
                           SSERV_CMD_CNTS_CHANGE_USER_CONTEST,
                           SSERV_CMD_CNTS_CLEAR_USER_CONTEST,
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
  fprintf(f, "</td>");
  print_help_url(f, SSERV_CMD_CNTS_CHANGE_PERSONAL);
  fprintf(f, "</tr></form>\n");

  fprintf(f, "<tr%s><td colspan=\"4\" align=\"center\"><b>Registration settings</b></td></tr>", head_row_attr);
  row = 1;

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Registration mode:</td><td>", form_row_attrs[row ^= 1]);
  html_boolean_select(f, cnts->autoregister, "param", "Moderated registration",
                      "Free registration");
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_CHANGE_AUTOREGISTER, "Change");
  fprintf(f, "</td>");
  print_help_url(f, SSERV_CMD_CNTS_CHANGE_AUTOREGISTER);
  fprintf(f, "</tr></form>\n");

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Registration deadline:</td><td>",
          form_row_attrs[row ^= 1]);
  html_date_select(f, cnts->reg_deadline);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_CHANGE_DEADLINE, "Change");
  html_submit_button(f, SSERV_CMD_CNTS_CLEAR_DEADLINE, "Clear");
  fprintf(f, "</td>");
  print_help_url(f, SSERV_CMD_CNTS_CHANGE_DEADLINE);
  fprintf(f, "</tr></form>\n");

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Contest start date:</td><td>",
          form_row_attrs[row ^= 1]);
  html_date_select(f, cnts->sched_time);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_CHANGE_SCHED_TIME, "Change");
  html_submit_button(f, SSERV_CMD_CNTS_CLEAR_SCHED_TIME, "Clear");
  fprintf(f, "</td>");
  print_help_url(f, SSERV_CMD_CNTS_CHANGE_SCHED_TIME);
  fprintf(f, "</tr></form>\n");

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Virtual contest open date:</td><td>",
          form_row_attrs[row ^= 1]);
  html_date_select(f, cnts->open_time);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_CHANGE_OPEN_TIME, "Change");
  html_submit_button(f, SSERV_CMD_CNTS_CLEAR_OPEN_TIME, "Clear");
  fprintf(f, "</td>");
  print_help_url(f, SSERV_CMD_CNTS_CHANGE_OPEN_TIME);
  fprintf(f, "</tr></form>\n");

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Virtual contest close date:</td><td>",
          form_row_attrs[row ^= 1]);
  html_date_select(f, cnts->close_time);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_CHANGE_CLOSE_TIME, "Change");
  html_submit_button(f, SSERV_CMD_CNTS_CLEAR_CLOSE_TIME, "Clear");
  fprintf(f, "</td>");
  print_help_url(f, SSERV_CMD_CNTS_CHANGE_CLOSE_TIME);
  fprintf(f, "</tr></form>\n");

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
  print_string_editing_row(f, "Registration letter subject:",
                           cnts->register_subject,
                           SSERV_CMD_CNTS_CHANGE_REGISTER_SUBJECT,
                           SSERV_CMD_CNTS_CLEAR_REGISTER_SUBJECT,
                           0,
                           session_id,
                           form_row_attrs[row ^= 1],
                           self_url,
                           extra_args,
                           hidden_vars);
  print_string_editing_row(f, "Registration letter subject (en):",
                           cnts->register_subject_en,
                           SSERV_CMD_CNTS_CHANGE_REGISTER_SUBJECT_EN,
                           SSERV_CMD_CNTS_CLEAR_REGISTER_SUBJECT_EN,
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

  fprintf(f, "<tr%s><td colspan=\"4\" align=\"center\"><b>Participation settings</b></td></tr>", head_row_attr);
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
  print_string_editing_row(f, "URL for the contest logo:",
                           cnts->logo_url,
                           SSERV_CMD_CNTS_CHANGE_LOGO_URL,
                           SSERV_CMD_CNTS_CLEAR_LOGO_URL,
                           0,
                           session_id,
                           form_row_attrs[row ^= 1],
                           self_url,
                           extra_args,
                           hidden_vars);
  print_string_editing_row(f, "URL for the contest CSS:",
                           cnts->css_url,
                           SSERV_CMD_CNTS_CHANGE_CSS_URL,
                           SSERV_CMD_CNTS_CLEAR_CSS_URL,
                           0,
                           session_id,
                           form_row_attrs[row ^= 1],
                           self_url,
                           extra_args,
                           hidden_vars);

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"4\" align=\"center\"><b>Various contest's flags</b>", head_row_attr);
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
  fprintf(f, "</td>");
  print_help_url(f, SSERV_CMD_CNTS_CHANGE_TEAM_PASSWD);
  fprintf(f, "</tr></form>\n");

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Enable simple registration (no email)?</td><td>",
          form_row_attrs[row ^= 1]);
  html_boolean_select(f, cnts->simple_registration, "param", 0, 0);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_CHANGE_SIMPLE_REGISTRATION, "Change");
  fprintf(f, "</td>");
  print_help_url(f, SSERV_CMD_CNTS_CHANGE_SIMPLE_REGISTRATION);
  fprintf(f, "</tr></form>\n");

  if (cnts->simple_registration) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Send e-mail with password anyway?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->send_passwd_email, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_SEND_PASSWD_EMAIL, "Change");
    fprintf(f, "</td>");
    print_help_url(f, SSERV_CMD_CNTS_CHANGE_SEND_PASSWD_EMAIL);
    fprintf(f, "</tr></form>\n");
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Manage the contest server?</td><td>",
          form_row_attrs[row ^= 1]);
  html_boolean_select(f, cnts->managed, "param", 0, 0);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_CHANGE_MANAGED, "Change");
  fprintf(f, "</td>");
  print_help_url(f, SSERV_CMD_CNTS_CHANGE_MANAGED);
  fprintf(f, "</tr></form>\n");

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>User ej-super-run for testing?</td><td>",
          form_row_attrs[row ^= 1]);
  html_boolean_select(f, cnts->run_managed, "param", 0, 0);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_CHANGE_RUN_MANAGED, "Change");
  fprintf(f, "</td>");
  print_help_url(f, SSERV_CMD_CNTS_CHANGE_RUN_MANAGED);
  fprintf(f, "</tr></form>\n");

  if (!cnts->run_managed) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Testing compabilitiy mode?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->old_run_managed, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_OLD_RUN_MANAGED, "Change");
    fprintf(f, "</td>");
    print_help_url(f, SSERV_CMD_CNTS_CHANGE_OLD_RUN_MANAGED);
    fprintf(f, "</tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Allow pruning users?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->clean_users, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_CLEAN_USERS, "Change");
    fprintf(f, "</td>");
    print_help_url(f, SSERV_CMD_CNTS_CHANGE_CLEAN_USERS);
    fprintf(f, "</tr></form>\n");
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td>Closed for participation?</td><td>",
          form_row_attrs[row ^= 1]);
  html_boolean_select(f, cnts->closed, "param", 0, 0);
  fprintf(f, "</td><td>");
  html_submit_button(f, SSERV_CMD_CNTS_CHANGE_CLOSED, "Change");
  fprintf(f, "</td>");
  print_help_url(f, SSERV_CMD_CNTS_CHANGE_CLOSED);
  fprintf(f, "</tr></form>\n");

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Invisible in serve-control?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->invisible, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_INVISIBLE, "Change");
    fprintf(f, "</td>");
    print_help_url(f, SSERV_CMD_CNTS_CHANGE_INVISIBLE);
    fprintf(f, "</tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Disallow team member removal?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->disable_member_delete, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_MEMBER_DELETE, "Change");
    fprintf(f, "</td>");
    print_help_url(f, SSERV_CMD_CNTS_CHANGE_MEMBER_DELETE);
    fprintf(f, "</tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Auto-assign logins?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->assign_logins, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_ASSIGN_LOGINS, "Change");
    fprintf(f, "</td>");
    print_help_url(f, SSERV_CMD_CNTS_CHANGE_ASSIGN_LOGINS);
    fprintf(f, "</tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Force contest registration?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->force_registration, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_FORCE_REGISTRATION, "Change");
    fprintf(f, "</td>");
    print_help_url(f, SSERV_CMD_CNTS_CHANGE_FORCE_REGISTRATION);
    fprintf(f, "</tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Disable &quot;Name&quot; field?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->disable_name, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_DISABLE_NAME, "Change");
    fprintf(f, "</td>");
    print_help_url(f, SSERV_CMD_CNTS_CHANGE_DISABLE_NAME);
    fprintf(f, "</tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Enable password restoration?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->enable_password_recovery, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_ENABLE_PASSWORD_RECOVERY, "Change");
    fprintf(f, "</td>");
    print_help_url(f, SSERV_CMD_CNTS_CHANGE_ENABLE_PASSWORD_RECOVERY);
    fprintf(f, "</tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Examination mode?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->exam_mode, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_EXAM_MODE, "Change");
    fprintf(f, "</td>");
    print_help_url(f, SSERV_CMD_CNTS_CHANGE_EXAM_MODE);
    fprintf(f, "</tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Disable password change?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->disable_password_change, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_DISABLE_PASSWORD_CHANGE, "Change");
    fprintf(f, "</td>");
    print_help_url(f, SSERV_CMD_CNTS_CHANGE_DISABLE_PASSWORD_CHANGE);
    fprintf(f, "</tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Disable locale change?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->disable_locale_change, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_DISABLE_LOCALE_CHANGE, "Change");
    fprintf(f, "</td>");
    print_help_url(f, SSERV_CMD_CNTS_CHANGE_DISABLE_LOCALE_CHANGE);
    fprintf(f, "</tr></form>\n");
  }

  if (sstate->advanced_view) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<tr%s><td>Allow edit registration data during contest?</td><td>",
            form_row_attrs[row ^= 1]);
    html_boolean_select(f, cnts->allow_reg_data_edit, "param", 0, 0);
    fprintf(f, "</td><td>");
    html_submit_button(f, SSERV_CMD_CNTS_CHANGE_ALLOW_REG_DATA_EDIT, "Change");
    fprintf(f, "</td>");
    print_help_url(f, SSERV_CMD_CNTS_CHANGE_ALLOW_REG_DATA_EDIT);
    fprintf(f, "</tr></form>\n");
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"4\" align=\"center\"><b>IP-address access rules for CGI programs</b>", head_row_attr);
  row = 1;
  if (sstate->show_access_rules) {
    html_submit_button(f, SSERV_CMD_CNTS_HIDE_ACCESS_RULES, "Hide");
  } else {
    html_submit_button(f, SSERV_CMD_CNTS_SHOW_ACCESS_RULES, "Show");
  }
  fprintf(f, "</td></tr></form>");

  if (sstate->show_access_rules) {
    print_access_summary(f, cnts->register_access, "Access to `register' program",
                         SSERV_CMD_NEW_EDIT_REGISTER_ACCESS_PAGE,
                         session_id, form_row_attrs[row ^= 1],
                         self_url, extra_args);
    print_access_summary(f, cnts->users_access, "Access to `users' program",
                         SSERV_CMD_NEW_EDIT_USERS_ACCESS_PAGE,
                         session_id, form_row_attrs[row ^= 1],
                         self_url, extra_args);
    print_access_summary(f, cnts->master_access, "Access to `master' program",
                         SSERV_CMD_NEW_EDIT_MASTER_ACCESS_PAGE,
                         session_id, form_row_attrs[row ^= 1],
                         self_url, extra_args);
    print_access_summary(f, cnts->judge_access, "Access to `judge' program",
                         SSERV_CMD_NEW_EDIT_JUDGE_ACCESS_PAGE,
                         session_id, form_row_attrs[row ^= 1],
                         self_url, extra_args);
    print_access_summary(f, cnts->team_access, "Access to `team' program",
                         SSERV_CMD_NEW_EDIT_TEAM_ACCESS_PAGE,
                         session_id, form_row_attrs[row ^= 1],
                         self_url, extra_args);
    print_access_summary(f, cnts->serve_control_access,
                         "Access to `serve-control' program",
                         SSERV_CMD_NEW_EDIT_SERVE_CONTROL_ACCESS_PAGE,
                         session_id, form_row_attrs[row ^= 1],
                         self_url, extra_args);
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"4\" align=\"center\"><b>Users permissions</b>", head_row_attr);
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
  fprintf(f, "<tr%s><td colspan=\"4\" align=\"center\"><b>Registration form fields</b>", head_row_attr);
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
  fprintf(f, "<tr%s><td colspan=\"4\" align=\"center\"><b>HTML headers and footers for CGI-programs</b>", head_row_attr);
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
    print_string_editing_row(f, "HTML menu1 content file for `team' CGI-program:",
                             cnts->team_menu_1_file,
                             SSERV_CMD_CNTS_CHANGE_TEAM_MENU_1,
                             SSERV_CMD_CNTS_CLEAR_TEAM_MENU_1,
                             SSERV_CMD_CNTS_EDIT_TEAM_MENU_1,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML menu2 content file for `team' CGI-program:",
                             cnts->team_menu_2_file,
                             SSERV_CMD_CNTS_CHANGE_TEAM_MENU_2,
                             SSERV_CMD_CNTS_CLEAR_TEAM_MENU_2,
                             SSERV_CMD_CNTS_EDIT_TEAM_MENU_2,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML menu3 content file for `team' CGI-program:",
                             cnts->team_menu_3_file,
                             SSERV_CMD_CNTS_CHANGE_TEAM_MENU_3,
                             SSERV_CMD_CNTS_CLEAR_TEAM_MENU_3,
                             SSERV_CMD_CNTS_EDIT_TEAM_MENU_3,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML separator file for `team' CGI-program:",
                             cnts->team_separator_file,
                             SSERV_CMD_CNTS_CHANGE_TEAM_SEPARATOR,
                             SSERV_CMD_CNTS_CLEAR_TEAM_SEPARATOR,
                             SSERV_CMD_CNTS_EDIT_TEAM_SEPARATOR,
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
    print_string_editing_row(f, "HTML header file for welcome message:",
                             cnts->welcome_file,
                             SSERV_CMD_CNTS_CHANGE_WELCOME,
                             SSERV_CMD_CNTS_CLEAR_WELCOME,
                             SSERV_CMD_CNTS_EDIT_WELCOME,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
    print_string_editing_row(f, "HTML header file for registration welcome message:",
                             cnts->reg_welcome_file,
                             SSERV_CMD_CNTS_CHANGE_REG_WELCOME,
                             SSERV_CMD_CNTS_CLEAR_REG_WELCOME,
                             SSERV_CMD_CNTS_EDIT_REG_WELCOME,
                             session_id,
                             form_row_attrs[row ^= 1],
                             self_url,
                             extra_args,
                             hidden_vars);
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<tr%s><td colspan=\"4\" align=\"center\"><b>extra HTML attributes for CGI-programs</b>",head_row_attr);
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
  fprintf(f, "<tr%s><td colspan=\"4\" align=\"center\"><b>E-mail notifications</b>", head_row_attr);
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
  fprintf(f, "<tr%s><td colspan=\"4\" align=\"center\"><b>Advanced path settings</b>", head_row_attr);
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
super_html_edit_form_fields(
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
  unsigned char hbuf[1024];
  int first_index, last_index, allow_setting_minmax, commit_action, val, i;
  const unsigned char *(*field_names_func)(int ff);
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
    field_names_func = contests_get_form_field_name;
    allow_setting_minmax = 0;
    fields = cnts->fields;
    desc_txt = "Basic fields";
    commit_action = SSERV_CMD_CNTS_SAVE_FORM_FIELDS;
    break;
  case SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS:
    first_index = 1;
    last_index = CONTEST_LAST_MEMBER_FIELD;
    field_names_func = contests_get_member_field_name;
    allow_setting_minmax = 1;
    memb = cnts->members[CONTEST_M_CONTESTANT];
    if (memb) fields = memb->fields;
    desc_txt = "Fields for \"Contestant\" participants";
    commit_action = SSERV_CMD_CNTS_SAVE_CONTESTANT_FIELDS;
    break;
  case SSERV_CMD_CNTS_EDIT_RESERVE_FIELDS:
    first_index = 1;
    last_index = CONTEST_LAST_MEMBER_FIELD;
    field_names_func = contests_get_member_field_name;
    allow_setting_minmax = 1;
    memb = cnts->members[CONTEST_M_RESERVE];
    if (memb) fields = memb->fields;
    desc_txt = "Fields for \"Reserve\" participants";
    commit_action = SSERV_CMD_CNTS_SAVE_RESERVE_FIELDS;
    break;
  case SSERV_CMD_CNTS_EDIT_COACH_FIELDS:
    first_index = 1;
    last_index = CONTEST_LAST_MEMBER_FIELD;
    field_names_func = contests_get_member_field_name;
    allow_setting_minmax = 1;
    memb = cnts->members[CONTEST_M_COACH];
    if (memb) fields = memb->fields;
    desc_txt = "Fields for \"Coach\" participants";
    commit_action = SSERV_CMD_CNTS_SAVE_COACH_FIELDS;
    break;
  case SSERV_CMD_CNTS_EDIT_ADVISOR_FIELDS:
    first_index = 1;
    last_index = CONTEST_LAST_MEMBER_FIELD;
    field_names_func = contests_get_member_field_name;
    allow_setting_minmax = 1;
    memb = cnts->members[CONTEST_M_ADVISOR];
    if (memb) fields = memb->fields;
    desc_txt = "Fields for \"Advisor\" participants";
    commit_action = SSERV_CMD_CNTS_SAVE_ADVISOR_FIELDS;
    break;
  case SSERV_CMD_CNTS_EDIT_GUEST_FIELDS:
    first_index = 1;
    last_index = CONTEST_LAST_MEMBER_FIELD;
    field_names_func = contests_get_member_field_name;
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
    print_field_row_select(f, i, (*field_names_func)(i), val, form_row_attrs[row ^= 1]);
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
    help_txt = super_html_template_help_3;
    break;

  case SSERV_CMD_GLOB_EDIT_CONTEST_STOP_CMD:
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
    help_txt = super_html_template_help_1;
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
    help_txt = super_html_template_help_1;
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
    help_txt = super_html_template_help_1;
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
    help_txt = super_html_template_help_1;
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
    help_txt = super_html_template_help_1;
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
    help_txt = super_html_template_help_1;
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
    help_txt = super_html_template_help_1;
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
    help_txt = super_html_template_help_1;
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
    help_txt = super_html_template_help_1;
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
    help_txt = super_html_template_help_1;
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
    help_txt = super_html_template_help_1;
    break;
  case SSERV_CMD_CNTS_EDIT_TEAM_MENU_1:
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
    back_action = SSERV_CMD_EDIT_CURRENT_CONTEST;
    help_txt = super_html_template_help_1;
    break;
  case SSERV_CMD_CNTS_EDIT_TEAM_MENU_2:
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
    back_action = SSERV_CMD_EDIT_CURRENT_CONTEST;
    help_txt = super_html_template_help_1;
    break;
  case SSERV_CMD_CNTS_EDIT_TEAM_MENU_3:
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
    back_action = SSERV_CMD_EDIT_CURRENT_CONTEST;
    help_txt = super_html_template_help_1;
    break;
  case SSERV_CMD_CNTS_EDIT_TEAM_SEPARATOR:
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
    back_action = SSERV_CMD_EDIT_CURRENT_CONTEST;
    help_txt = super_html_template_help_1;
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
    help_txt = super_html_template_help_1;
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
    help_txt = super_html_template_help_1;
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
    help_txt = super_html_template_help_1;
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
    help_txt = super_html_template_help_1;
    break;
  case SSERV_CMD_CNTS_EDIT_WELCOME:
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
    back_action = SSERV_CMD_EDIT_CURRENT_CONTEST;
    help_txt = super_html_template_help_1;
    break;
  case SSERV_CMD_CNTS_EDIT_REG_WELCOME:
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
    back_action = SSERV_CMD_EDIT_CURRENT_CONTEST;
    help_txt = super_html_template_help_1;
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

int
super_html_create_contest_2(
        FILE *f,
        int priv_level,
        int user_id,
        const unsigned char *login,
        const unsigned char *ss_login,
        ej_cookie_t session_id,
        const ej_ip_t *ip_address,
        int ssl_flag,
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
  const int *contests = 0;
  int contest_num, i;
  int errcode = 0;
  const struct contest_desc *templ_cnts = 0;

  if (sstate->edited_cnts) {
    errcode = -SSERV_ERR_CONTEST_EDITED;
    goto cleanup;
  }

  contest_num = contests_get_list(&contests);
  if (contest_num < 0 || !contests) {
    errcode = -SSERV_ERR_SYSTEM_ERROR;
    goto cleanup;
  }
  if (!num_mode) {
    contest_id = 1;
    if (contest_num > 0) contest_id = contests[contest_num - 1] + 1;
  } else {
    if (contest_id <= 0 || contest_id > EJ_MAX_CONTEST_ID) {
      errcode = -SSERV_ERR_INVALID_CONTEST;
      goto cleanup;
    }
    // FIXME: bsearch would be better
    // creating a new contest is a rare operation, though
    for (i = 0; i < contest_num && contests[i] != contest_id; i++);
    if (i < contest_num) {
      errcode = -SSERV_ERR_CONTEST_ALREADY_USED;
      goto cleanup;
    }
  }
  if (templ_mode) {
    for (i = 0; i < contest_num && contests[i] != templ_id; i++);
    if (i >= contest_num) {
      errcode = -SSERV_ERR_INVALID_CONTEST;
      goto cleanup;
    }
    if (contests_get(templ_id, &templ_cnts) < 0) {
      errcode = -SSERV_ERR_INVALID_CONTEST;
      goto cleanup;
    }
  }

  if (super_serve_sid_state_get_cnts_editor(contest_id)) {
    errcode = -SSERV_ERR_CONTEST_ALREADY_USED;
    goto cleanup;
  }

  // FIXME: touch the contest file
  if (!templ_mode) {
    sstate->edited_cnts = contest_tmpl_new(contest_id,
                                           login,
                                           self_url,
                                           ss_login,
                                           ip_address,
                                           ssl_flag,
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

  return super_html_edit_contest_page(f, priv_level, user_id, login,
                                      session_id, ip_address, config, sstate,
                                      self_url, hidden_vars, extra_args);

 cleanup:
  return errcode;
}
