/* -*- mode: c -*- */

/* Copyright (C) 2004-2017 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/file_perms.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

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

void
super_html_load_serve_cfg(const struct contest_desc *cnts,
                          const struct ejudge_cfg *config,
                          struct sid_state *sstate)
{
  path_t serve_cfg_path;
  unsigned char var_dir_path[PATH_MAX];
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

  snprintf(var_dir_path, sizeof(var_dir_path), "%s/var", cnts->root_dir);
  int dir_mode = file_perms_parse_mode(cnts->dir_mode);
  int dir_group = file_perms_parse_group(cnts->dir_group);
  struct stat stb;
  if (stat(var_dir_path, &stb) >= 0) {
    if (!S_ISDIR(stb.st_mode)) {
      fprintf(flog, "%s is not a directory\n", var_dir_path);
      close_memstream(flog); flog = 0;
      sstate->serve_parse_errors = flog_txt;
      flog_txt = 0; flog_len = 0;
      return;
    }
  } else {
    if (mkdir(var_dir_path, 0777) < 0) {
      fprintf(flog, "cannot create directory '%s': %s\n", var_dir_path, os_ErrorMsg());
      close_memstream(flog); flog = 0;
      sstate->serve_parse_errors = flog_txt;
      flog_txt = 0; flog_len = 0;
      return;
    }
    file_perms_set(flog, var_dir_path, dir_group, dir_mode, 0, 0);
  }

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
