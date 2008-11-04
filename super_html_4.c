/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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
#include "ej_limits.h"

#include "super_html.h"
#include "super-serve.h"
#include "super-serve_meta.h"
#include "super_proto.h"
#include "copyright.h"
#include "misctext.h"
#include "contests.h"
#include "contests_meta.h"
#include "l10n.h"
#include "charsets.h"
#include "fileutl.h"
#include "xml_utils.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/stat.h>

/* These error codes are only used in this module */
enum
{
  S_ERR_EMPTY_REPLY = 2,
  S_ERR_INV_OPER,
  S_ERR_CONTEST_EDITED,
  S_ERR_INV_SID,
  S_ERR_INV_CONTEST,
  S_ERR_PERM_DENIED,
  S_ERR_INTERNAL,
  S_ERR_ALREADY_EDITED,
  S_ERR_NO_EDITED_CNTS,
  S_ERR_INVALID_FIELD_ID,
  S_ERR_NOT_IMPLEMENTED,
  S_ERR_INVALID_VALUE,

  S_ERR_LAST
};

#if !defined CONF_STYLE_PREFIX
#define CONF_STYLE_PREFIX "/ejudge/"
#endif

#define ARMOR(s)  html_armor_buf(&ab, s)
#define URLARMOR(s)  url_armor_buf(&ab, s)
#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

static const unsigned char*
ss_getenv(
        const struct super_http_request_info *phr,
        const unsigned char *var)
  __attribute__((unused));
static const unsigned char*
ss_getenv(
        const struct super_http_request_info *phr,
        const unsigned char *var)
{
  int i;
  size_t var_len;

  if (!var) return 0;
  var_len = strlen(var);
  for (i = 0; i < phr->env_num; i++)
    if (!strncmp(phr->envs[i], var, var_len) && phr->envs[i][var_len] == '=')
      break;
  if (i < phr->env_num)
    return phr->envs[i] + var_len + 1;
  return 0;
}

static int
ss_cgi_param(
        const struct super_http_request_info *phr,
        const unsigned char *param,
        const unsigned char **p_value)
  __attribute__((unused));
static int
ss_cgi_param(
        const struct super_http_request_info *phr,
        const unsigned char *param,
        const unsigned char **p_value)
{
  int i;

  if (!param) return -1;
  for (i = 0; i < phr->param_num; i++)
    if (!strcmp(phr->param_names[i], param))
      break;
  if (i >= phr->param_num) return 0;
  if (strlen(phr->params[i]) != phr->param_sizes[i]) return -1;
  *p_value = phr->params[i];
  return 1;
}

static int
ss_cgi_param_bin(
        const struct super_http_request_info *phr,
        const unsigned char *param,
        const unsigned char **p_value,
        size_t *p_size)
  __attribute__((unused));
static int
ss_cgi_param_bin(
        const struct super_http_request_info *phr,
        const unsigned char *param,
        const unsigned char **p_value,
        size_t *p_size)
{
  int i;

  if (!param) return -1;
  for (i = 0; i < phr->param_num; i++)
    if (!strcmp(phr->param_names[i], param))
      break;
  if (i >= phr->param_num) return 0;
  *p_value = phr->params[i];
  *p_size = phr->param_sizes[i];
  return 1;
}

static const unsigned char *
ss_cgi_nname(
        const struct super_http_request_info *phr,
        const unsigned char *prefix,
        size_t pflen)
  __attribute__((unused));
static const unsigned char *
ss_cgi_nname(
        const struct super_http_request_info *phr,
        const unsigned char *prefix,
        size_t pflen)
{
  int i;

  if (!prefix || !pflen) return 0;
  for (i = 0; i < phr->param_num; i++)
    if (!strncmp(phr->param_names[i], prefix, pflen))
      return phr->param_names[i];
  return 0;
}

static int
ss_cgi_param_int(
        struct super_http_request_info *phr,
        const unsigned char *name,
        int *p_val)
  __attribute__((unused));
static int
ss_cgi_param_int(
        struct super_http_request_info *phr,
        const unsigned char *name,
        int *p_val)
{
  const unsigned char *s = 0;
  char *eptr = 0;
  int x;

  if (ss_cgi_param(phr, name, &s) <= 0) return -1;
  errno = 0;
  x = strtol(s, &eptr, 10);
  if (errno || *eptr) return -1;
  if (p_val) *p_val = x;
  return 0;
}

static int
ss_cgi_param_int_opt(
        struct super_http_request_info *phr,
        const unsigned char *name,
        int *p_val,
        int default_value)
  __attribute__((unused));
static int
ss_cgi_param_int_opt(
        struct super_http_request_info *phr,
        const unsigned char *name,
        int *p_val,
        int default_value)
{
  const unsigned char *s = 0, *p;
  char *eptr = 0;
  int x;

  if (!(x = ss_cgi_param(phr, name, &s))) {
    if (p_val) *p_val = default_value;
    return 0;
  } else if (x < 0) return -1;
  p = s;
  while (*p && isspace(*p)) p++;
  if (!*p) {
    if (p_val) *p_val = default_value;
    return 0;
  }
  errno = 0;
  x = strtol(s, &eptr, 10);
  if (errno || *eptr) return -1;
  if (p_val) *p_val = x;
  return 0;
}

const unsigned char *
veprintf(unsigned char *buf, size_t size, const char *format, va_list args)
{
  vsnprintf(buf, size, format, args);
  return buf;
}

const unsigned char *
eprintf(unsigned char *buf, size_t size, const char *format, ...)
  __attribute__((format(printf,3,4)));
const unsigned char *
eprintf(unsigned char *buf, size_t size, const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vsnprintf(buf, size, format, args);
  va_end(args);
  return buf;
}

static void
ss_html_select(
        FILE *out_f,
        const unsigned char *id,
        const unsigned char *class,
        const unsigned char *name,
        const unsigned char *onchange,
        const unsigned char *value,
        int n,
        const char **values,
        const char **labels)
{
  int i;
  const unsigned char *s = 0;

  fprintf(out_f, "<select");
  if (id) fprintf(out_f, " id=\"%s\"", id);
  if (name) fprintf(out_f, " name=\"%s\"", name);
  /* if (value) fprintf(out_f, " value=\"%s\"", value); */
  if (onchange) fprintf(out_f, " onChange='%s'", onchange);
  fprintf(out_f, ">");
  for (i = 0; i < n; ++i) {
    s = "";
    if (!strcmp(value, values[i])) s = " selected=\"1\"";
    fprintf(out_f, "<option value=\"%s\"%s>%s</option>",
            values[i], s, labels[i]);
  }
  fprintf(out_f, "</select>");
}

static void
ss_html_int_select(
        FILE *out_f,
        const unsigned char *id,
        const unsigned char *class,
        const unsigned char *name,
        const unsigned char *onchange,
        int value,
        int n,
        const char **labels)
{
  int i;
  const unsigned char *s = 0;

  fprintf(out_f, "<select");
  if (id) fprintf(out_f, " id=\"%s\"", id);
  if (name) fprintf(out_f, " name=\"%s\"", name);
  /* if (value) fprintf(out_f, " value=\"%s\"", value); */
  if (onchange) fprintf(out_f, " onChange='%s'", onchange);
  fprintf(out_f, ">");
  for (i = 0; i < n; ++i) {
    s = "";
    if (value == i) s = " selected=\"1\"";
    fprintf(out_f, "<option value=\"%d\"%s>%s</option>", i, s, labels[i]);
  }
  fprintf(out_f, "</select>");
}

static const char fancy_priv_header[] =
"Content-Type: %s; charset=%s\n"
"Cache-Control: no-cache\n"
"Pragma: no-cache\n\n"
"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
"<html><head>\n<meta http-equiv=\"Content-type\" content=\"text/html; charset=%s\"/>\n"
"<link rel=\"stylesheet\" href=\"%spriv.css\" type=\"text/css\">\n"
  //"<link rel=\"shortcut icon\" type=\"image/x-icon\" href=\"/favicon.ico\">\n"
"<title>%s</title></head>\n"
"<body>\n";

static void
write_html_header(
        FILE *out_f,
        struct super_http_request_info *phr,
        const unsigned char *title,
        int use_dojo,
        const unsigned char *body_class)
{
  unsigned char cl[64];

  if (use_dojo && !body_class) body_class = "nihilo";

  fprintf(out_f, fancy_priv_header,
          "text/html", EJUDGE_CHARSET, EJUDGE_CHARSET, CONF_STYLE_PREFIX,
          title);

  if (use_dojo) {
    fprintf(out_f, "<link href=\"%sdijit/themes/%s/%s.css\" rel=\"stylesheet\" type=\"text/css\" />\n", CONF_STYLE_PREFIX, body_class, body_class);
    fprintf(out_f, "<link href=\"%sdojo/resources/dojo.css\" rel=\"stylesheet\" type=\"text/css\" />\n", CONF_STYLE_PREFIX);
    fprintf(out_f,
            "<style type=\"text/css\">\n"
            "  @import \"%sdojox/highlight/resources/highlight.css\";\n"
            "  @import \"%sdojox/highlight/resources/pygments/default.css\";\n"
            "  @import \"%sdojo/resources/dojo.css\";\n"
            "  @import \"%sdojox/grid/_grid/Grid.css\";\n"
            "  @import \"%sdojox/grid/_grid/nihiloGrid.css\";\n"
            "</style>\n",
            CONF_STYLE_PREFIX, CONF_STYLE_PREFIX, CONF_STYLE_PREFIX,
            CONF_STYLE_PREFIX, CONF_STYLE_PREFIX);
  }
  fprintf(out_f, "<style type=\"text/css\" id=\"generatedStyles\"></style>\n");

  if (use_dojo) {
    fprintf(out_f, "<script type=\"text/javascript\" src=\"%sdojo/dojo.js\" djConfig=\"isDebug: false, parseOnLoad: true, dojoIframeHistoryUrl:'%sdojo/resources/iframe_history.html'\"></script>\n",
            CONF_STYLE_PREFIX, CONF_STYLE_PREFIX);
  }

  if (use_dojo) {
    fprintf(out_f, "<script type=\"text/javascript\" src=\"" CONF_STYLE_PREFIX "priv.js\"></script>\n");

    fprintf(out_f,
            "<script type=\"text/javascript\">\n"
            "  dojo.require(\"dojo.parser\");\n"
            "  dojo.require(\"dijit.InlineEditBox\");\n"
            "  dojo.require(\"dijit.form.Button\");\n"
            "  dojo.require(\"dijit.form.DateTextBox\");\n"
            "  dojo.require(\"dijit.form.Textarea\");\n");
    fprintf(out_f,
            "  var SSERV_CMD_HTTP_REQUEST=%d;\n"
            "  var SID=\"%016llx\";\n"
            "  var self_url=\"%s\";\n"
            "  var script_name=\"%s\";\n",
            SSERV_CMD_HTTP_REQUEST,
            phr->session_id,
            phr->self_url,
            phr->script_name);
    fprintf(out_f, "</script>\n");
  }

  fprintf(out_f, "</head>");

  cl[0] = 0;
  if (body_class) snprintf(cl, sizeof(cl), " class=\"%s\"", body_class);
  fprintf(out_f, "<body%s>", cl);
}

static const char fancy_priv_footer[] =
"<hr/>%s</body></html>\n";
static void
write_html_footer(FILE *out_f)
{
  fprintf(out_f, fancy_priv_footer, get_copyright(0));
}

static void
write_json_header(FILE *out_f)
{
  fprintf(out_f, "Content-type: text/plain; charset=%s\n\n",
          EJUDGE_CHARSET);
}

static void
refresh_page(
        FILE *out_f,
        struct super_http_request_info *phr,
        const char *format,
        ...)
  __attribute__((format(printf, 3, 4)));
static void
refresh_page(
        FILE *out_f,
        struct super_http_request_info *phr,
        const char *format,
        ...)
{
  va_list args;
  char buf[1024];
  char url[1024];

  buf[0] = 0;
  if (format && *format) {
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
  }

  if (!buf[0] && !phr->session_id) {
    snprintf(url, sizeof(url), "%s", phr->self_url);
  } else if (!buf[0]) {
    snprintf(url, sizeof(url), "%s?SID=%016llx", phr->self_url,
             phr->session_id);
  } else if (!phr->session_id) {
    snprintf(url, sizeof(url), "%s?%s", phr->self_url, buf);
  } else {
    snprintf(url, sizeof(url), "%s?SID=%016llx&%s", phr->self_url,
             phr->session_id, buf);
  }

  fprintf(out_f, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\nLocation: %s\n\n", EJUDGE_CHARSET, url);
}

typedef int (*handler_func_t)(FILE *log_f, FILE *out_f, struct super_http_request_info *phr);

static int
cmd_cnts_details(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  struct sid_state *ss = phr->ss;

  if (ss->edited_cnts) FAIL(S_ERR_CONTEST_EDITED);

 cleanup:
  return retval;
}

static int
cmd_edited_cnts_back(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  refresh_page(out_f, phr, NULL);
  return 0;
}

static int
cmd_edited_cnts_continue(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  refresh_page(out_f, phr, "action=%d", SSERV_CMD_EDIT_CURRENT_CONTEST);
  return 0;
}

static int
cmd_edited_cnts_start_new(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int contest_id = 0;

  if (ss_cgi_param_int_opt(phr, "contest_id", &contest_id, 0) < 0
      || contest_id < 0) contest_id = 0;
  super_serve_clear_edited_contest(phr->ss);
  if (!contest_id) {
    refresh_page(out_f, phr, "action=%d", SSERV_CMD_CREATE_CONTEST);
  } else {
    refresh_page(out_f, phr, "action=%d&contest_id=%d",
                 SSERV_CMD_EDIT_CONTEST_XML, contest_id);
  }

  return 0;
}

static const unsigned char head_row_attr[] =
  " bgcolor=\"#dddddd\"";
static const unsigned char * const form_row_attrs[]=
{
  " bgcolor=\"#e4e4e4\"",
  " bgcolor=\"#eeeeee\"",
};

static void
dojo_button(
        FILE *out_f,
        const unsigned char *id,
        const unsigned char *icon,
        const unsigned char *alt,
        const char *onclick,
        ...)
  __attribute__((format(printf, 5, 6)));

static void
dojo_button(
        FILE *out_f,
        const unsigned char *id,
        const unsigned char *icon,
        const unsigned char *alt,
        const char *onclick,
        ...)
{
  unsigned char onclick_buf[1024];
  va_list args;

  onclick_buf[0] = 0;
  if (onclick) {
    va_start(args, onclick);
    vsnprintf(onclick_buf, sizeof(onclick_buf), onclick, args);
    va_end(args);
  }

  fprintf(out_f, "<button dojoType=\"dijit.form.Button\" iconClass=\"plusIcon\"");
  if (id) {
    fprintf(out_f, " id=\"%s\"", id);
  }
  if (onclick) {
    fprintf(out_f, " onClick='%s'", onclick_buf);
  }
  fprintf(out_f, ">");
  if (icon) {
    fprintf(out_f, "<img src=\"%sicons/%s.png\"", CONF_STYLE_PREFIX, icon);
    if (alt) {
      fprintf(out_f, " alt=\"%s\"", alt);
    }
    fprintf(out_f, "/>");
  }
  fprintf(out_f, "</button>\n");
}

enum
{
  NS_CONTEST = 1,
  NS_SID_STATE,
};

#define push(val) do { if (sp >= ST_SIZE) goto stack_overflow; st[sp++] = (val1); } while (0)
#define pop(var) do { if (!sp) goto stack_undeflow; (var) = st[--sp]; } while (0)

static int
eval_check_expr(
        struct super_http_request_info *phr,
        const unsigned char *str)
{
  enum { ST_SIZE = 32 };
  long st[ST_SIZE];
  long val1, val2;
  int sp = 0;
  unsigned char *buf;
  unsigned char *q;
  int len, f_id, f_type;
  const unsigned char *p;
  void *f_ptr;
  char *eptr;

  if (!str) return 0;
  len = strlen(str);
  if (!len) return 0;
  if (len >= 2048) {
    fprintf(stderr, "eval_check_expr: expression is too long\n");
    return -1;
  }
  buf = (unsigned char*) alloca(len + 1);
  p = str;
  while (*p) {
    if (isspace(*p)) {
      ++p;
      continue;
    }
    if (isalpha(*p) || *p == '_' || *p == '.') {
      q = buf;
      while (isalnum(*p) || *p == '_' || *p == '.')
        *q++ = *p++;
      *q = 0;

      if (!strncmp(buf, "Contest.", 8)) {
        if (!(f_id = contest_desc_lookup_field(buf + 8)))
          goto invalid_field;
        f_type = contest_desc_get_type(f_id);
        if (!(f_ptr = contest_desc_get_ptr_nc(phr->ss->edited_cnts, f_id)))
          goto invalid_field;
      } else if (!strncmp(buf, "SidState.", 9)) {
        if (!(f_id = ss_sid_state_lookup_field(buf + 9)))
          goto invalid_field;
        f_type = ss_sid_state_get_type(f_id);
        if (!(f_ptr = ss_sid_state_get_ptr_nc(phr->ss, f_id)))
          goto invalid_field;
      } else goto invalid_field;

      val1 = 0;
      switch (f_type) {
      case 'b':
        if (*(unsigned char*) f_ptr) val1 = 1;
        break;
      case 'B':
        if (*(int*) f_ptr) val1 = 1;
        break;
      case 's':
        if (*(unsigned char **) f_ptr) val1 = 1;
        break;
      case 't':
        if (*(time_t*) f_ptr) val1 = 1;
        break;
      case 'i':
        if (*(int*) f_ptr) val1 = 1;
        break;
      default:
        fprintf(stderr, "eval_check_expr: invalid type\n");
        return -1;
      }
      push(val1);
      continue;
    }
    if (*p >= '0' && *p <= '9') {
      q = buf;
      while (*p >= '0' && *p <= '9')
        *q++ = *p++;
      *q = 0;

      errno = 0; eptr = 0;
      val1 = strtol(buf, &eptr, 0);
      if (*eptr || errno) {
        fprintf(stderr, "eval_check_expr: invalid value\n");
        return -1;
      }
      push(val1);
      continue;
    }
    switch (*p) {
    case '!':
      pop(val1);
      push(!val1);
      break;
    case '~':
      pop(val1);
      push(~val1);
      break;

    case '&':
      pop(val2);
      pop(val1);
      if (p[1] == '&') {
        p++;
        val1 = val1 && val2;
      } else {
        val1 = val1 & val2;
      }
      push(val1);
      break;
    case '|':
      pop(val2);
      pop(val1);
      if (p[1] == '|') {
        p++;
        val1 = val1 || val2;
      } else {
        val1 = val1 | val2;
      }
      push(val1);
      break;
    case '+':
      pop(val2);
      pop(val1);
      push(val1 + val2);
      break;
    case '-':
      pop(val2);
      pop(val1);
      push(val1 - val2);
      break;
    default:
      fprintf(stderr, "eval_check_expr: invalid operation <%c>\n", *p);
      return -1;
    }
    p++;
  }
  if (!sp) {
    fprintf(stderr, "eval_check_expr: no expression\n");
    return -1;
  }
  if (sp > 1) {
    fprintf(stderr, "eval_check_expr: incomplete expression\n");
    return -1;
  }
  return st[0];

 stack_overflow:
  fprintf(stderr, "eval_check_expr: stack overflow\n");
  return -1;

 stack_undeflow:
  fprintf(stderr, "eval_check_expr: stack underflow\n");
  return -1;

 invalid_field:
  fprintf(stderr, "eval_check_expr: invalid field %s\n", buf + 8);
  return -1;
}

struct cnts_edit_info
{
  int nspace;
  int field_id;
  int type;
  int is_editable;
  int is_clearable;
  int dojo_inline_edit;
  int is_nullable;
  int has_details;
  unsigned char *legend;
  unsigned char *hint;
  unsigned char *guard_expr;
};
static struct cnts_edit_info cnts_edit_info[] =
{
  { 0, 0, '-', 0, 0, 0, 0, 0, "Basic Contest Settings", 0, 0 },
  { NS_CONTEST, CNTS_id, 'd', 0, 0, 0, 0, 0, "Contest ID", "Contest ID", 0 },
  { NS_CONTEST, CNTS_name, 's', 1, 1, 1, 1, 0, "Contest Name", "Contest Name", 0 },
  { NS_CONTEST, CNTS_name_en, 's', 1, 1, 1, 1, 0, "Contest Name (English)", "Contest Name (English)", 0 },
  { NS_CONTEST, CNTS_main_url, 's', 1, 1, 1, 1, 0, "Main URL", "Contest Main URL", 0 },
  { NS_CONTEST, CNTS_keywords, 's', 1, 1, 1, 1, 0, "Keywords", "Keywords describing the contest", 0 },
  { NS_CONTEST, CNTS_default_locale, 128, 1, 1, 0, 1, 0, "Default locale", 0, 0 },
  { NS_CONTEST, CNTS_personal, 'y', 1, 0, 0, 0, 0, "Contest is personal", "Contest is personal", 0 },
  { NS_CONTEST, CNTS_disable_team_password, 'y', 1, 0, 0, 0, 0, "Disable separate contest password", "Use the registration password for participation in the contest", 0 },
  { 0, 0, '-', 0, 0, 0, 0, 0, "Registration Settings", 0, 0 },
  { NS_CONTEST, CNTS_autoregister, 129, 1, 0, 0, 0, 0, "Registration mode", "Contest registration mode", 0 },
  { NS_CONTEST, CNTS_reg_deadline, 't', 1, 1, 0, 1, 0, "Registration deadline", "Registration deadline", 0 },
  { NS_CONTEST, CNTS_register_email, 's', 1, 1, 1, 1, 0, "Registration email sender", "From: field for registration email", 0 },
  { NS_CONTEST, CNTS_register_url, 's', 1, 1, 1, 1, 0, "URL to complete registration", "URL to complete registration", 0 },
  { NS_CONTEST, CNTS_register_email_file, 'e', 1, 1, 1, 1, 1, "Registration letter template file", "Registration letter template file", 0 },
  { 0, 0, '-', 0, 0, 0, 0, 0, "Participation Settings", 0, 0 },
  { NS_CONTEST, CNTS_team_url, 's', 1, 1, 1, 1, 0, "URL for the client CGI program", "URL for the client CGI program", 0 },
  { NS_CONTEST, CNTS_standings_url, 's', 1, 1, 1, 1, 0, "URL for the current standings", "URL for the current standings", 0 },
  { NS_CONTEST, CNTS_problems_url, 's', 1, 1, 1, 1, 0, "URL for the problemset", "URL for the problemset", 0 },
  { 0, 0, '-', 0, 0, 0, 0, 0, "Contest Management", 0, 0 },
  { NS_CONTEST, CNTS_managed, 'y', 1, 0, 0, 0, 0, "Enable the contest service", "Enable the contest service", 0 },
  { NS_CONTEST, CNTS_run_managed, 'y', 1, 0, 0, 0, 0, "Enable the run service", "Enable the run service", 0 },
  { NS_CONTEST, CNTS_closed, 'y', 1, 0, 0, 0, 0, "Close the contest for participants", "Close the contest for participants", 0 },
  { NS_CONTEST, CNTS_invisible, 'y', 1, 0, 0, 0, 0, "Hide the contest for administrators", "Hide the contest for administrators", 0 },

  { NS_SID_STATE, SSSS_show_access_rules, '-', 1, 0, 0, 0, SSERV_OP_COPY_ALL_ACCESS_RULES_PAGE, "IP Access Rules", 0, 0 },
  { NS_CONTEST, CNTS_register_access, 'p', 0, 0, 0, 1, 1, "<tt>register</tt> access rules", "Access rules for the register program", "SidState.show_access_rules" },
  { NS_CONTEST, CNTS_users_access, 'p', 0, 0, 0, 1, 1, "<tt>users</tt> access rules", "Access rules for the users program", "SidState.show_access_rules" },
  { NS_CONTEST, CNTS_team_access, 'p', 0, 0, 0, 1, 1, "<tt>client</tt> access rules", "Access rules for the client program", "SidState.show_access_rules" },
  { NS_CONTEST, CNTS_judge_access, 'p', 0, 0, 0, 1, 1, "<tt>judge</tt> access rules", "Access rules for the judge program", "SidState.show_access_rules" },
  { NS_CONTEST, CNTS_master_access, 'p', 0, 0, 0, 1, 1, "<tt>master</tt> access rules", "Access rules for the master program", "SidState.show_access_rules" },
  { NS_CONTEST, CNTS_serve_control_access, 'p', 0, 0, 0, 1, 1, "<tt>serve-control</tt> access rules", "Access rules for the serve-control program", "SidState.show_access_rules" },

  { NS_SID_STATE, SSSS_show_permissions, '-', 1, 0, 0, 0, SSERV_OP_COPY_ALL_PRIV_USERS_PAGE, "Administrators, Judges, etc", 0, 0 },
  { 0, 0, 130, 0, 0, 0, 0, 0, 0, 0, 0, },
  { NS_SID_STATE, SSSS_show_form_fields, '-', 1, 0, 0, 0, 0, "Registration Form Fields", 0, 0 },
  { 0, 0, 131, 0, 0, 0, 0, 0, 0, 0, 0, },

  { NS_SID_STATE, SSSS_show_html_headers, '-', 1, 0, 0, 0, 0, "HTML Headers and Footers", 0, 0 },
  { NS_CONTEST, CNTS_users_header_file, 'e', 1, 1, 1, 1, 1, "HTML header file for <tt>users</tt>", "HTML header file for the users program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_users_footer_file, 'e', 1, 1, 1, 1, 1, "HTML footer file for <tt>users</tt>", "HTML footer file for the users program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_register_header_file, 'e', 1, 1, 1, 1, 1, "HTML header file for <tt>register</tt>", "HTML header file for the register program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_register_footer_file, 'e', 1, 1, 1, 1, 1, "HTML footer file for <tt>register</tt>", "HTML footer file for the register program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_team_header_file, 'e', 1, 1, 1, 1, 1, "HTML header file for <tt>client</tt>", "HTML header file for the client program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_team_menu_1_file, 'e', 1, 1, 1, 1, 1, "HTML menu 1 file for <tt>client</tt>", "HTML menu 1 file for the client program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_team_menu_2_file, 'e', 1, 1, 1, 1, 1, "HTML menu 2 file for <tt>client</tt>", "HTML menu 2 file for the client program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_team_menu_3_file, 'e', 1, 1, 1, 1, 1, "HTML menu 3 file for <tt>client</tt>", "HTML menu 3 file for the client program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_team_separator_file, 'e', 1, 1, 1, 1, 1, "HTML separator file for <tt>client</tt>", "HTML separator file for the client program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_team_footer_file, 'e', 1, 1, 1, 1, 1, "HTML footer file for <tt>client</tt>", "HTML footer file for the client program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_priv_header_file, 'e', 1, 1, 1, 1, 1, "HTML header file for <tt>master</tt>", "HTML header file for the master program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_priv_footer_file, 'e', 1, 1, 1, 1, 1, "HTML footer file for <tt>master</tt>", "HTML footer file for the master program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_copyright_file, 'e', 1, 1, 1, 1, 1, "HTML copyright notice file", "HTML copyright notice file", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_welcome_file, 'e', 1, 1, 1, 1, 1, "HTML welcome message file", "HTML welcome message file", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_reg_welcome_file, 'e', 1, 1, 1, 1, 1, "HTML registration welcome message file", "HTML registration welcome message file", "SidState.show_html_headers" },

  { NS_SID_STATE, SSSS_show_html_attrs, '-', 1, 0, 0, 0, 0, "HTML Styles", 0, 0 },
  { NS_CONTEST, CNTS_users_head_style, 's', 1, 1, 1, 1, 0, "HTML attributes for <tt>users</tt> headers", "Attributes for users headers", "SidState.show_html_attrs" },
  { NS_CONTEST, CNTS_users_par_style, 's', 1, 1, 1, 1, 0, "HTML attributes for <tt>users</tt> paragraphs", "Attributes for users paragraphs", "SidState.show_html_attrs" },
  { NS_CONTEST, CNTS_users_table_style, 's', 1, 1, 1, 1, 0, "HTML attributes for <tt>users</tt> tables", "Attributes for users tables", "SidState.show_html_attrs" },
  { NS_CONTEST, CNTS_users_verb_style, 's', 1, 1, 1, 1, 0, "HTML attributes for <tt>users</tt> verbatim texts", "Attributes for users verbatim texts", "SidState.show_html_attrs" },
  { NS_CONTEST, CNTS_users_table_format, 's', 1, 1, 1, 1, 0, "Format specification for the table of the users", "Format specification for the table of the users", "SidState.show_html_attrs" },
  { NS_CONTEST, CNTS_users_table_legend, 's', 1, 1, 1, 1, 0, "Legend for the table of the users", "Legend for the table of the users", "SidState.show_html_attrs Contest.users_table_format &&" },
  { NS_CONTEST, CNTS_users_table_format_en, 's', 1, 1, 1, 1, 0, "Format specification for the table of the users (en)", "Format specification for the table of the users (English)", "SidState.show_html_attrs" },
  { NS_CONTEST, CNTS_users_table_legend_en, 's', 1, 1, 1, 1, 0, "Legend for the table of the users(en)", "Legend for the table of the users (English)", "SidState.show_html_attrs Contest.users_table_format_en &&" },
  /*
  { NS_CONTEST, CNTS_register_head_style, 's', 1, 1, 1, 1, 0, "HTML attributes for <tt>register</tt> headers", "HTML attributes for register headers", "SidState.show_html_attrs" },
  { NS_CONTEST, CNTS_register_par_style, 's', 1, 1, 1, 1, 0, "HTML attributes for <tt>register</tt> paragraphs", "HTML attributes for register paragraphs", "SidState.show_html_attrs" },
  { NS_CONTEST, CNTS_register_table_style, 's', 1, 1, 1, 1, 0, "HTML attributes for <tt>register</tt> tables", "HTML attributes for register tables", "SidState.show_html_attrs" },
  { NS_CONTEST, CNTS_user_name_comment, 's', 1, 1, 1, 1, 0, "Additional comment for the user name field", "Additional comment for the user name field", "SidState.show_html_attrs Contest.disable_name ! &&" },
  { NS_CONTEST, CNTS_team_head_style, 's', 1, 1, 1, 1, 0, "HTML attributes for <tt>client</tt> headers", "HTML attributes for client headers", "SidState.show_html_attrs" },
  { NS_CONTEST, CNTS_team_par_style, 's', 1, 1, 1, 1, 0, "HTML attributes for <tt>client</tt> paragraphs", "HTML attributes for client paragraphs", "SidState.show_html_attrs" },
  */

  { NS_SID_STATE, SSSS_show_notifications, '-', 1, 0, 0, 0, 0, "E-mail Notifications", 0, 0 },
  { NS_CONTEST, CNTS_cf_notify_email, 's', 1, 1, 1, 1, 0, "e-mail for &quot;Check failed&quot; messages", "e-mail for &quot;Check failed&quot; messages", "SidState.show_notifications" },
  { NS_CONTEST, CNTS_clar_notify_email, 's', 1, 1, 1, 1, 0, "e-mail for clar notifications", "e-mail for clar notifications", "SidState.show_notifications" },
  { NS_CONTEST, CNTS_daily_stat_email, 's', 1, 1, 1, 1, 0, "e-mail for daily statistics", "e-mail for daily statistics", "SidState.show_notifications" },

  { NS_SID_STATE, SSSS_advanced_view, '-', 1, 0, 0, 0, 0, "Advanced Contest Settings", 0, 0 },
  // FIXME: add share users with contest item
  { NS_CONTEST, CNTS_simple_registration, 'y', 1, 0, 0, 0, 0, "Enable simple registration", "Do not validate e-mail during registration (not recommended)", "SidState.advanced_view" },
  { NS_CONTEST, CNTS_send_passwd_email, 'y', 1, 0, 0, 0, 0, "Send e-mail with password anyway", "Send e-mail with password", "SidState.advanced_view Contest.simple_registration &&" },
  { NS_CONTEST, CNTS_assign_logins, 'y', 1, 0, 0, 0, 0, "Auto assign logins", "Generate logins for users automatically", "SidState.advanced_view" },
  { NS_CONTEST, CNTS_login_template, 's', 1, 1, 1, 1, 0, "Template for new logins", "Template for new logins", "SidState.advanced_view Contest.assign_logins &&" },
  { NS_CONTEST, CNTS_login_template_options, 's', 1, 1, 1, 1, 0, "Options for new logins", "Options for new logins", "SidState.advanced_view Contest.assign_logins &&" },
  { NS_CONTEST, CNTS_force_registration, 'y', 1, 0, 0, 0, 0, "Automatic contest registration", "Register to the contest automatically (no Confirm registration button", "SidState.advanced_view" },
  { NS_CONTEST, CNTS_disable_name, 'y', 1, 0, 0, 0, 0, "Disable &quot;Name&quot; user field", "Disable &quot;Name&quot; user field, only login is used", "SidState.advanced_view" },
  { NS_CONTEST, CNTS_enable_password_recovery, 'y', 1, 0, 0, 0, 0, "Enable password restoration", "Enable password restoration", "SidState.advanced_view" },
  { NS_CONTEST, CNTS_allow_reg_data_edit, 'y', 1, 0, 0, 0, 0, "Allow editing of registration data during the contest", "Allow editing of registration data during the contest", "SidState.advanced_view" },
  { NS_CONTEST, CNTS_exam_mode, 'y', 1, 0, 0, 0, 0, "Enable examination mode", "Enable simplified user interface", "SidState.advanced_view" },
  { NS_CONTEST, CNTS_disable_password_change, 'y', 1, 0, 0, 0, 0, "Disable password changing", "Disable password changing by users", "SidState.advanced_view" },
  { NS_CONTEST, CNTS_disable_locale_change, 'y', 1, 0, 0, 0, 0, "Disable locale changing", "Disable interface language changing by users", "SidState.advanced_view" },
  { NS_CONTEST, CNTS_clean_users, 'y', 1, 0, 0, 0, 0, "Allow pruning users", "Allow removal of users without submits from the database", "SidState.advanced_view" },
  { NS_CONTEST, CNTS_disable_member_delete, 'y', 1, 0, 0, 0, 0, "Disallow removal of team members", "Disallow removal of team members", "SidState.advanced_view" },
  { NS_CONTEST, CNTS_allowed_languages, 's', 1, 1, 1, 1, 0, "Allowed programming languages", "Allowed programming languages", "SidState.advanced_view" },
  { NS_CONTEST, CNTS_allowed_regions, 's', 1, 1, 1, 1, 0, "Allowed regions", "Allowed regions", "SidState.advanced_view" },

  { NS_SID_STATE, SSSS_show_paths, '-', 1, 0, 0, 0, 0, "Advanced Filesystem Settings", 0, 0 },
  { NS_CONTEST, CNTS_dir_mode, 's', 1, 1, 1, 1, 0, "The directories permission", "Octal number", "SidState.show_paths" },
  { NS_CONTEST, CNTS_dir_group, 's', 1, 1, 1, 1, 0, "The directories group", "Octal number", "SidState.show_paths" },
  { NS_CONTEST, CNTS_file_mode, 's', 1, 1, 1, 1, 0, "The files permission", "Octal number", "SidState.show_paths" },
  { NS_CONTEST, CNTS_file_group, 's', 1, 1, 1, 1, 0, "The files group", "Octal number", "SidState.show_paths" },

  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

static void
separator_row(
	FILE *out_f,
        const unsigned char *text,
        const int *p_detail_flag,
        int field_id,
        int copy_cmd)
{
  int colspan = 3;
  unsigned char bbuf[1024];

  if (p_detail_flag) colspan = 2;
  fprintf(out_f, "<tr%s>", head_row_attr);
  fprintf(out_f, "<td class=\"cnts_edit_head\" colspan=\"%d\">%s</td>",
          colspan, text);
  if (p_detail_flag) {
    snprintf(bbuf, sizeof(bbuf), "toggleButton(%d, %d, %d)",
             SSERV_OP_TOGGLE_CONTEST_XML_VISIBILITY,
             field_id, SSERV_OP_EDIT_CONTEST_PAGE_2);
    fprintf(out_f, "<td class=\"cnts_edit_head\">");
    if (copy_cmd) {
      dojo_button(out_f, 0, "promotion-16x16", "Copy",
                  "ssLoad1(%d)", copy_cmd);
    }
    if (!*p_detail_flag) {
      dojo_button(out_f, 0, "zoom_in-16x16", "Show Detail", bbuf);
    } else {
      dojo_button(out_f, 0, "zoom_out-16x16", "Hide Detail", bbuf);
    }
    fprintf(out_f, "</td>");
  }
  fprintf(out_f, "</tr>\n");
}

static const char * predef_caps_names[] =
{
  [0] = "",
  [OPCAP_PREDEF_NO_PERMS] = "No permissions",
  [OPCAP_PREDEF_OBSERVER] = "Observer",
  [OPCAP_PREDEF_JUDGE] = "Judge",
  [OPCAP_PREDEF_MASTER] = "Master",
};

static void
print_registration_fields(
        FILE *out_f,
        struct contest_desc *ecnts,
        struct super_http_request_info *phr)
{
  int row = 1;
  int i, m;
  struct contest_member *memb;
  struct contest_field **fields;

  fprintf(out_f,
          "<tr%s>"
          "<td class=\"cnts_edit_legend\" valign=\"top\">%s</td>"
          "<td class=\"cnts_edit_legend\"><font size=\"-1\"><pre>",
          form_row_attrs[row ^= 1], "General registration fields");
  if (ecnts->fields) {
    for (i = 1; i < CONTEST_LAST_FIELD; i++) {
      if (!ecnts->fields[i]) continue;
      fprintf(out_f, "\"%s\" %s\n", contests_get_form_field_name(i),
              ecnts->fields[i]->mandatory?"mandatory":"optional");
    }
  }
  fprintf(out_f, "</pre></font></td><td class=\"cnts_edit_clear\" valign=\"top\">");
  dojo_button(out_f, 0, "edit_page-16x16", "Edit contents",
              "ssLoad1(%d)", SSERV_OP_EDIT_GENERAL_FIELDS_PAGE);
  fprintf(out_f, "</td></tr>\n");

  for (m = 0; m < CONTEST_LAST_MEMBER; ++m) {
    if (ecnts->personal && m == CONTEST_M_RESERVE) continue;

    fprintf(out_f,
            "<tr%s>"
            "<td class=\"cnts_edit_legend\" valign=\"top\">&quot;%s&quot; fields</td>"
            "<td class=\"cnts_edit_legend\"><font size=\"-1\"><pre>",
            form_row_attrs[row ^= 1], contests_get_member_name(m));
    if ((memb = ecnts->members[m])) {
      fprintf(out_f, "minimal count = %d\n", memb->min_count);
      fprintf(out_f, "maximal count = %d\n", memb->max_count);
      fprintf(out_f, "initial count = %d\n", memb->init_count);
      if ((fields = memb->fields)) {
        for (i = 1; i < CONTEST_LAST_MEMBER_FIELD; i++) {
          if (!fields[i]) continue;
          fprintf(out_f, "\"%s\" %s\n", contests_get_member_field_name(i),
                  fields[i]->mandatory?"mandatory":"optional");
        }
      }
    }
    fprintf(out_f, "</pre></font></td><td class=\"cnts_edit_clear\" valign=\"top\">");
    dojo_button(out_f, 0, "edit_page-16x16", "Edit contents",
                "ssLoad2(%d, %d)", SSERV_OP_EDIT_MEMBER_FIELDS_PAGE, m);
    fprintf(out_f, "</td></tr>\n");

  }
}

static int
contest_xml_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  struct contest_desc *ecnts = phr->ss->edited_cnts;
  unsigned char buf[1024];
  unsigned char jbuf[1024];
  int is_empty;
  int row = 1, i, j, k;
  struct cnts_edit_info *ce;
  void *v_ptr;
  struct opcap_list_item *perms;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char *s = 0;

  snprintf(buf, sizeof(buf), "serve-control: %s, editing contest %d",
           phr->html_name, ecnts->id);
  write_html_header(out_f, phr, buf, 1, 0);

  fprintf(out_f, "<h1>%s</h1>\n", buf);

  // write tabs
  fprintf(out_f, "<div id=\"tabs\">\n");
  fprintf(out_f, "<ul>\n");
  fprintf(out_f, "<li id=\"selected\"><a href=\"#\">General Settings</a></li>\n");
  fprintf(out_f, "<li><a href=\"#\">Global Settings</a></li>\n");
  fprintf(out_f, "<li><a href=\"#\">Language Settings</a></li>\n");
  fprintf(out_f, "<li><a href=\"#\">Problem Settings</a></li>\n");
  fprintf(out_f, "</ul>\n");
  fprintf(out_f, "</div>\n");

  // write the main content
  fprintf(out_f, "<div id=\"cnts_edit_content\">\n");
  fprintf(out_f, "<table class=\"cnts_edit\">\n");

  for (i = 0, ce = cnts_edit_info; ce->type; ++i, ++ce) {
    if (ce->type == '-') {
      if (ce->is_editable) {
        int *p_flag = 0;

        ASSERT(ce->nspace == NS_SID_STATE);
        p_flag = (int*) ss_sid_state_get_ptr_nc(phr->ss, ce->field_id);
        separator_row(out_f, ce->legend, p_flag, ce->field_id, ce->has_details);
      } else {
        separator_row(out_f, ce->legend, 0, 0, 0);
      }
      row = 0;
      continue;
    }

    if (ce->type == 130) {
      if (!phr->ss->show_permissions) continue;

      perms = ecnts->capabilities.first;
      for (j = 0; perms; perms = (struct opcap_list_item*) perms->b.right,j++) {
        fprintf(out_f, "<tr%s>", form_row_attrs[row ^= 1]);
        fprintf(out_f, "<td valign=\"top\" class=\"cnts_edit_legend\">%s</td>",
                ARMOR(perms->login));
        fprintf(out_f, "<td valign=\"top\" class=\"cnts_edit_legend\">");
        if ((k = opcaps_is_predef_caps(perms->caps)) > 0) {
          fprintf(out_f, "<i>%s</i>", predef_caps_names[k]);
        } else {
          s = opcaps_unparse(0, 50, perms->caps);
          fprintf(out_f, "<font size=\"-2\"><pre>%s</pre></font>", s);
          xfree(s);
        }
        fprintf(out_f, "</td>");
        fprintf(out_f, "<td class=\"cnts_edit_clear\">");
        dojo_button(out_f, 0, "edit_page-16x16", "Edit permissions",
                    "ssLoad2(%d, %d)", SSERV_OP_EDIT_PERMISSIONS_PAGE, j);
        dojo_button(out_f, 0, "delete-16x16", "Delete permissions",
                    "alert(\"Delete permissions\")");
        fprintf(out_f, "</td>");
        fprintf(out_f, "</tr>\n");
      }

      continue;
    }

    if (ce->type == 131) {
      if (!phr->ss->show_form_fields) continue;
      print_registration_fields(out_f, ecnts, phr);
      continue;
    }

    if (ce->guard_expr) {
      if (!eval_check_expr(phr, ce->guard_expr)) continue;
    }

    is_empty = 0;

    fprintf(out_f, "<tr%s>", form_row_attrs[row ^= 1]);
    fprintf(out_f, "<td valign=\"top\" class=\"cnts_edit_legend\">%s:</td>", ce->legend);
    fprintf(out_f, "<td valign=\"middle\" class=\"cnts_edit_data\" width=\"600px\">");
    if (ce->is_editable && ce->dojo_inline_edit) {
      fprintf(out_f, "<div class=\"cnts_edit_data\" dojoType=\"dijit.InlineEditBox\" onChange=\"editField(%d, %d, %d, arguments[0])\" autoSave=\"true\" title=\"%s\">",
              SSERV_OP_EDIT_CONTEST_XML_FIELD,
              ce->field_id, SSERV_OP_EDIT_CONTEST_PAGE_2,
              ce->hint);
    } else if (ce->type != 't') {
      fprintf(out_f, "<div class=\"cnts_edit_data\">");
    }

    v_ptr = contest_desc_get_ptr_nc(ecnts, ce->field_id);
    switch (ce->type) {
    case 'd':
      {
        int *d_ptr = (int*) v_ptr;
        fprintf(out_f, "%d", *d_ptr);
      }
      break;
    case 's': case 'e':
      {
        unsigned char **s_ptr = (unsigned char**) v_ptr;
        if (*s_ptr) fprintf(out_f, "%s", *s_ptr);
        if (!*s_ptr) is_empty = 1;
      }
      break;
    case 'y':
      {
        unsigned char *y_ptr = (unsigned char*) v_ptr;
        if (!ce->is_editable) {
          fprintf(out_f, "%s", *y_ptr?"Yes":"No");
          break;
        }
        ss_html_int_select(out_f, 0, 0, 0,
                           eprintf(jbuf, sizeof(jbuf), "editField(%d, %d, %d, this.options[this.selectedIndex].value)", SSERV_OP_EDIT_CONTEST_XML_FIELD, ce->field_id, SSERV_OP_EDIT_CONTEST_PAGE_2),
                           !!*y_ptr,
                           2, (const char *[]) { "No", "Yes" });
      }
      break;
    case 't':
      {
        time_t tval = *(const time_t*) v_ptr;
        struct tm *ptm = 0;
        unsigned char time_buf[64];
        unsigned char date_buf[128];

        if (tval < 0) tval = 0;
        if (!tval) is_empty = 1;
        time_buf[0] = 0;
        date_buf[0] = 0;
        if (tval) {
          ptm = localtime(&tval);
          snprintf(time_buf, sizeof(time_buf), "%02d:%02d:%02d",
                   ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
          snprintf(date_buf, sizeof(date_buf), " value=\"%04d-%02d-%02d\"",
                   ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday);
        }

        fprintf(out_f, "<div class=\"cnts_edit_inlined\">Time: </div><div class=\"cnts_edit_inlined\" dojoType=\"dijit.InlineEditBox\" onChange=\"editField2(%d, %d, %d, %d, arguments[0])\" autoSave=\"true\" title=\"Time (HH:MM:SS)\">%s</div>",
                SSERV_OP_EDIT_CONTEST_XML_FIELD,
                ce->field_id, 1, SSERV_OP_EDIT_CONTEST_PAGE_2, time_buf);

        fprintf(out_f, "<div class=\"cnts_edit_inlined\">&nbsp;Day: </div><div class=\"cnts_edit_inlined\">");
        fprintf(out_f,
                "<input type=\"text\" name=\"date\"%s"
                " size=\"12\""
                " dojoType=\"dijit.form.DateTextBox\""
                " constraints=\"{datePattern: 'y/M/d', min:'1970-01-01', max:'2037-12-31'}\""
                /*                " required=\"true\"" */
                " onChange=\"editField2(%d, %d, %d, %d, this.getDisplayedValue())\""
                " promptMessage=\"yyyy/mm/dd\""
                " invalidMessage=\"Invalid date. Use yyyy/mm/dd format.\" />",
                date_buf,
                SSERV_OP_EDIT_CONTEST_XML_FIELD,
                ce->field_id, 2, SSERV_OP_EDIT_CONTEST_PAGE_2);
        fprintf(out_f, "</div>");
      }
      break;

    case 'p':
      {
        const struct contest_access *acc = 0;
        acc = *(const struct contest_access**) v_ptr;
        unsigned char *txt = super_html_unparse_access(acc);
        fprintf(out_f, "<pre class=\"ip_summary\">%s</pre>", txt);
        xfree(txt); txt = 0;
      }
      break;

      // locale change dialog
    case 128:
      {
        unsigned char *y_ptr = *(unsigned char**) v_ptr;
        int locale_code = -1;

        is_empty = 1;
        if (!y_ptr) y_ptr = "";
        if (*y_ptr) locale_code = l10n_parse_locale(y_ptr);
        if (locale_code >= 0) is_empty = 0;

        l10n_html_locale_select_2(out_f, 0, 0, 0, eprintf(jbuf, sizeof(jbuf), "editField(%d, %d, %d, this.options[this.selectedIndex].value)", SSERV_OP_EDIT_CONTEST_XML_FIELD, ce->field_id, SSERV_OP_EDIT_CONTEST_PAGE_2), locale_code);
      }
      break;
    case 129:
      {
        int reg_mode = *(unsigned char*) v_ptr;

        ss_html_int_select(out_f, 0, 0, 0,
                           eprintf(jbuf, sizeof(jbuf), "editField(%d, %d, %d, this.options[this.selectedIndex].value)", SSERV_OP_EDIT_CONTEST_XML_FIELD, ce->field_id, SSERV_OP_EDIT_CONTEST_PAGE_2),
                           !!reg_mode,
                           2, (const char *[]) { "Moderated registration", "Free registration" });
      }
      break;
    default:
      abort();
    }
    fprintf(out_f, "</div></td>");

    fprintf(out_f, "<td class=\"cnts_edit_clear\">");
    if (ce->is_clearable) {
      if (ce->is_nullable && is_empty) {
        fprintf(out_f, "<i>Not set</i>");
      } else {
        if (ce->has_details) {
          dojo_button(out_f, 0, "edit_page-16x16", "Edit contents",
                    "ssLoad2(%d, %d)",
                    SSERV_OP_CONTEST_XML_FIELD_EDIT_PAGE, ce->field_id);
        }
        dojo_button(out_f, 0, "delete-16x16", "Clear variable",
                    "clearField(%d, %d, %d)",
                    SSERV_OP_CLEAR_CONTEST_XML_FIELD,
                    ce->field_id, SSERV_OP_EDIT_CONTEST_PAGE_2);
      }
    } else if (ce->has_details) {
      dojo_button(out_f, 0, "edit_page-16x16", "Edit contents",
                  "ssLoad2(%d, %d)",
                  SSERV_OP_CONTEST_XML_FIELD_EDIT_PAGE, ce->field_id);
    }
    fprintf(out_f, "</td>");

    fprintf(out_f, "<tr>\n");
  }

  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</div>\n");

  dojo_button(out_f, "1", "home-32x32", "To the top level (postpone editing)",
              "ssTopLevel()");
  dojo_button(out_f, "2", "accept-32x32", "Save Changes",
              "alert(\"Clicked SaveChanges\")");
  dojo_button(out_f, "3", "cancel-32x32", "Cancel Editing",
              "alert(\"Clicked CancelEditing\")");

  write_html_footer(out_f);
  html_armor_free(&ab);
  return 0;
}

static int
cmd_edit_contest_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  const struct contest_desc *cnts = 0;
  struct contest_desc *rw_cnts = 0;

  if (ss_cgi_param_int(phr, "contest_id", &contest_id) < 0
      || contest_id <= 0 || contest_id > EJ_MAX_CONTEST_ID)
    FAIL(S_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts)
    FAIL(S_ERR_INV_CONTEST);

  if (phr->priv_level != PRIV_LEVEL_ADMIN)
    FAIL(S_ERR_PERM_DENIED);
  if (opcaps_find(&cnts->capabilities, phr->login, &phr->caps) < 0)
    FAIL(S_ERR_PERM_DENIED);
  if (opcaps_check(phr->caps, OPCAP_EDIT_CONTEST) < 0)
    FAIL(S_ERR_PERM_DENIED);

  if (phr->ss->edited_cnts && phr->ss->edited_cnts->id == contest_id) {
    return contest_xml_page(log_f, out_f, phr);
  }

  if (phr->ss->edited_cnts)
    FAIL(S_ERR_ALREADY_EDITED);

  if (contests_load(contest_id, &rw_cnts) < 0 || !rw_cnts)
    FAIL(S_ERR_INV_CONTEST);
  phr->ss->edited_cnts = rw_cnts;

  // enough for now
  return contest_xml_page(log_f, out_f, phr);

  /*
    if (sstate->edited_cnts) {
      r = super_html_edited_cnts_dialog(f, p->priv_level, p->user_id, p->login,
                                        p->cookie, p->ip, config, sstate,
                                        self_url_ptr, hidden_vars_ptr,
                                        extra_args_ptr, cnts);
      break;
    }
    if ((r = contests_load(pkt->contest_id, &rw_cnts)) < 0 || !rw_cnts) {
      return send_reply(p, -SSERV_ERR_INVALID_CONTEST);
    }
    sstate->edited_cnts = rw_cnts;
    super_html_load_serve_cfg(rw_cnts, config, sstate);
    r = super_html_edit_contest_page(f, p->priv_level, p->user_id, p->login,
                                     p->cookie, p->ip, config, sstate,
                                     self_url_ptr, hidden_vars_ptr, extra_args_ptr);
  */
 cleanup:
  return retval;
}

static int
cmd_edit_contest_page_2(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;

  if (!phr->ss->edited_cnts)
    FAIL(S_ERR_NO_EDITED_CNTS);

  return contest_xml_page(log_f, out_f, phr);

 cleanup:
  return retval;
}

static int
cnts_text_edit_map[CNTS_LAST_FIELD] =
{
  [CNTS_users_header_file] = SSSS_users_header_text,
  [CNTS_users_footer_file] = SSSS_users_footer_text,
  [CNTS_register_header_file] = SSSS_register_header_text,
  [CNTS_register_footer_file] = SSSS_register_footer_text,
  [CNTS_team_header_file] = SSSS_team_header_text,
  [CNTS_team_menu_1_file] = SSSS_team_menu_1_text,
  [CNTS_team_menu_2_file] = SSSS_team_menu_2_text,
  [CNTS_team_menu_3_file] = SSSS_team_menu_3_text,
  [CNTS_team_separator_file] = SSSS_team_separator_text,
  [CNTS_team_footer_file] = SSSS_team_footer_text,
  [CNTS_priv_header_file] = SSSS_priv_header_text,
  [CNTS_priv_footer_file] = SSSS_priv_footer_text,
  [CNTS_copyright_file] = SSSS_copyright_text,
  [CNTS_register_email_file] = SSSS_register_email_text,
  [CNTS_welcome_file] = SSSS_welcome_text,
  [CNTS_reg_welcome_file] = SSSS_reg_welcome_text,
};

static int
cnts_text_load_map[CNTS_LAST_FIELD] =
{
  [CNTS_users_header_file] = SSSS_users_header_loaded,
  [CNTS_users_footer_file] = SSSS_users_footer_loaded,
  [CNTS_register_header_file] = SSSS_register_header_loaded,
  [CNTS_register_footer_file] = SSSS_register_footer_loaded,
  [CNTS_team_header_file] = SSSS_team_header_loaded,
  [CNTS_team_menu_1_file] = SSSS_team_menu_1_loaded,
  [CNTS_team_menu_2_file] = SSSS_team_menu_2_loaded,
  [CNTS_team_menu_3_file] = SSSS_team_menu_3_loaded,
  [CNTS_team_separator_file] = SSSS_team_separator_loaded,
  [CNTS_team_footer_file] = SSSS_team_footer_loaded,
  [CNTS_priv_header_file] = SSSS_priv_header_loaded,
  [CNTS_priv_footer_file] = SSSS_priv_footer_loaded,
  [CNTS_copyright_file] = SSSS_copyright_loaded,
  [CNTS_register_email_file] = SSSS_register_email_loaded,
  [CNTS_welcome_file] = SSSS_welcome_loaded,
  [CNTS_reg_welcome_file] = SSSS_reg_welcome_loaded,
};

static int
cmd_clear_contest_xml_field(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int f_id = 0;
  int f_type = 0;
  void *f_ptr = 0;
  int f_id2;

  phr->json_reply = 1;

  if (phr->priv_level != PRIV_LEVEL_ADMIN)
    FAIL(S_ERR_PERM_DENIED);
  /*
  if (opcaps_find(&cnts->capabilities, phr->login, &phr->caps) < 0)
    FAIL(S_ERR_PERM_DENIED);
  if (opcaps_check(phr->caps, OPCAP_EDIT_CONTEST) < 0)
    FAIL(S_ERR_PERM_DENIED);
  */
  if (!phr->ss->edited_cnts)
    FAIL(S_ERR_NO_EDITED_CNTS);
  if (ss_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD)
    FAIL(S_ERR_INVALID_FIELD_ID);
  if (!(f_ptr = contest_desc_get_ptr_nc(phr->ss->edited_cnts, f_id)))
    FAIL(S_ERR_INVALID_FIELD_ID);
  if (!(f_type = contest_desc_get_type(f_id)))
    FAIL(S_ERR_INVALID_FIELD_ID);
  if (f_id == CNTS_user_contest_num || f_id == CNTS_default_locale_num)
    FAIL(S_ERR_INVALID_FIELD_ID);

  switch (f_type) {
  case 'b':
    {
      unsigned char *b_ptr = (unsigned char*) f_ptr;
      b_ptr = 0;
    }
    break;
  case 's':
    {
      unsigned char **s_ptr = (unsigned char **) f_ptr;
      xfree(*s_ptr);
      *s_ptr = 0;
    }
    break;
  case 'i':
    {
      int *i_ptr = (int*) f_ptr;
      *i_ptr = 0;
    }
    break;
  case 't':
    {
      time_t *t_ptr = (time_t*) f_ptr;
      *t_ptr = 0;
    }
    break;
  default:
    FAIL(S_ERR_INVALID_FIELD_ID);
  }

  // special cases
  switch (f_id) {
  case CNTS_user_contest:
    phr->ss->edited_cnts->user_contest_num = 0;
    break;
  case CNTS_default_locale:
    phr->ss->edited_cnts->default_locale_num = 0;
    break;
  default:;
  }

  if ((f_id2 = cnts_text_edit_map[f_id]) > 0) {
    char **s_ptr = (char**) ss_sid_state_get_ptr_nc(phr->ss, f_id2);
    xfree(*s_ptr); *s_ptr = 0;
  }
  if ((f_id2 = cnts_text_load_map[f_id]) > 0) {
    int *i_ptr = (int*) ss_sid_state_get_ptr_nc(phr->ss, f_id2);
    *i_ptr = 0;
  }

  write_json_header(out_f);
  fprintf(out_f, "{ \"status\": 1 }");

 cleanup:
  return retval;
}

static unsigned char check_path_set[CNTS_LAST_FIELD] =
{
  [CNTS_users_header_file] = 1,
  [CNTS_users_footer_file] = 1,
  [CNTS_register_header_file] = 1,
  [CNTS_register_footer_file] = 1,
  [CNTS_team_header_file] = 1,
  [CNTS_team_menu_1_file] = 1,
  [CNTS_team_menu_2_file] = 1,
  [CNTS_team_menu_3_file] = 1,
  [CNTS_team_separator_file] = 1,
  [CNTS_team_footer_file] = 1,
  [CNTS_priv_header_file] = 1,
  [CNTS_priv_footer_file] = 1,
  [CNTS_register_email_file] = 1,
  [CNTS_copyright_file] = 1,
  [CNTS_welcome_file] = 1,
  [CNTS_reg_welcome_file] = 1,
};

static int
ends_with(const unsigned char *str, const unsigned char *suffix)
{
  int slen, xlen;

  if (!suffix || !*suffix) return 1;
  if (!str || !*str) return 0;

  slen = strlen(str);
  xlen = strlen(suffix);
  if (xlen > slen) return 0;
  if (!strcmp(str + slen - xlen, suffix)) return 1;
  return 0;
}

static int
cmd_edit_contest_xml_field(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int f_id = 0, f_id2 = 0;
  int f_type = 0;
  void *f_ptr = 0;
  const unsigned char *valstr = 0;
  struct contest_desc *ecnts = 0;
  int utf8_id = 0;
  struct html_armor_buffer vb = HTML_ARMOR_INITIALIZER;

  phr->json_reply = 1;

  if (phr->priv_level != PRIV_LEVEL_ADMIN)
    FAIL(S_ERR_PERM_DENIED);
  /*
  if (opcaps_find(&cnts->capabilities, phr->login, &phr->caps) < 0)
    FAIL(S_ERR_PERM_DENIED);
  if (opcaps_check(phr->caps, OPCAP_EDIT_CONTEST) < 0)
    FAIL(S_ERR_PERM_DENIED);
  */
  if (!phr->ss->edited_cnts)
    FAIL(S_ERR_NO_EDITED_CNTS);
  ecnts = phr->ss->edited_cnts;
  if (ss_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD)
    FAIL(S_ERR_INVALID_FIELD_ID);
  if (!(f_ptr = contest_desc_get_ptr_nc(ecnts, f_id)))
    FAIL(S_ERR_INVALID_FIELD_ID);
  if (!(f_type = contest_desc_get_type(f_id)))
    FAIL(S_ERR_INVALID_FIELD_ID);
  if (f_id == CNTS_user_contest_num || f_id == CNTS_default_locale_num)
    FAIL(S_ERR_INVALID_FIELD_ID);
  if (ss_cgi_param(phr, "value", &valstr) <= 0 || !valstr)
    FAIL(S_ERR_INVALID_VALUE);

  // value is in utf-8, translate it to the local charset
  utf8_id = charset_get_id("utf-8");
  valstr = charset_decode(utf8_id, &vb, valstr);

  if (check_path_set[f_id]) {
    // must end in '.html' or '.shtml'
    // must not contain / or start with .
    if (strchr(valstr, '/')) 
      FAIL(S_ERR_INVALID_VALUE);
    if (valstr[0] == '.')
      FAIL(S_ERR_INVALID_VALUE);
    if (!ends_with(valstr, ".html") && !ends_with(valstr, ".shtml")
        && !ends_with(valstr, ".txt"))
      FAIL(S_ERR_INVALID_VALUE);
  }

  switch (f_type) {
  case 'b':
    {
      unsigned char *p_bool = (unsigned char *) f_ptr;
      int newval, n = 0;

      if (sscanf(valstr, "%d%n", &newval, &n) != 1 || valstr[n]
          || newval < 0 || newval > 1)
        FAIL(S_ERR_INVALID_VALUE);
      if (*p_bool == newval) goto done;
      *p_bool = newval;
      switch (f_id) {
      case CNTS_autoregister:
      case CNTS_simple_registration:
      case CNTS_send_passwd_email:
      case CNTS_assign_logins:
      case CNTS_personal:
        retval = 1;
        break;
      }
    }
    break;
  case 's':
    {
      unsigned char **p_str = (unsigned char**) f_ptr;
      int newval = -1, n = 0;
      const struct contest_desc *cnts = 0;

      if (f_id == CNTS_user_contest) {
        if (sscanf(valstr, "%d%n", &newval, &n) != 1 || valstr[n]
            || newval < 0)
          FAIL(S_ERR_INVALID_VALUE);
        if (!newval) {
          xfree(ecnts->user_contest);
          ecnts->user_contest = 0;
          ecnts->user_contest_num = 0;
          retval = 1;
          goto done;
        }
        if (ecnts->id == newval)
          FAIL(S_ERR_INVALID_VALUE);
        if (contests_get(newval, &cnts) < 0 || !cnts)
          FAIL(S_ERR_INVALID_VALUE);
        if (cnts->user_contest_num > 0)
          FAIL(S_ERR_INVALID_VALUE);
      }
      if (f_id == CNTS_default_locale) {
        if ((newval = l10n_parse_locale(valstr)) < 0)
          FAIL(S_ERR_INVALID_VALUE);
      }

      if (!*p_str) {
        retval = 1;
      } else {
        if (!strcmp(*p_str, valstr)) goto done;
        xfree(*p_str);
        *p_str = 0;
      }
      *p_str = xstrdup(valstr);
      switch (f_id) {
      case CNTS_users_header_file:
      case CNTS_users_footer_file:
      case CNTS_register_header_file:
      case CNTS_register_footer_file:
      case CNTS_team_header_file:
      case CNTS_team_menu_1_file:
      case CNTS_team_menu_2_file:
      case CNTS_team_menu_3_file:
      case CNTS_team_separator_file:
      case CNTS_team_footer_file:
      case CNTS_priv_header_file:
      case CNTS_priv_footer_file:
      case CNTS_copyright_file:
      case CNTS_login_template:
      case CNTS_register_email_file:
      case CNTS_users_table_format:
      case CNTS_users_table_format_en:
      case CNTS_users_table_legend:
      case CNTS_users_table_legend_en:
      case CNTS_default_locale:
      case CNTS_welcome_file:
      case CNTS_reg_welcome_file:
        retval = 1;
        break;
      }
      if (f_id == CNTS_user_contest) {
        phr->ss->edited_cnts->user_contest_num = newval;
      }
      if (f_id == CNTS_default_locale) {
        phr->ss->edited_cnts->default_locale_num = newval;
      }
      if ((f_id2 = cnts_text_edit_map[f_id]) > 0) {
        char **s_ptr = (char**) ss_sid_state_get_ptr_nc(phr->ss, f_id2);
        xfree(*s_ptr); *s_ptr = 0;
      }
      if ((f_id2 = cnts_text_load_map[f_id]) > 0) {
        int *i_ptr = (int*) ss_sid_state_get_ptr_nc(phr->ss, f_id2);
        *i_ptr = 0;
      }
    }
    break;
  case 't':
    {
      int subf_id = 0;
      time_t *p_time = (time_t*) f_ptr;

      if (ss_cgi_param_int(phr, "subfield_id", &subf_id) < 0
          || subf_id < 1 || subf_id > 2)
        FAIL(S_ERR_INVALID_FIELD_ID);

      // 1 means time, 2 means date
      switch (subf_id) {
      case 1:
        {
          int h, m, s, n;
          int v_len = strlen(valstr);
          unsigned char *v_val;
          time_t t_val;
          struct tm *ptm;

          if (v_len > 1024) FAIL(S_ERR_INVALID_VALUE);
          v_val = (unsigned char*) alloca(v_len + 1);
          strcpy(v_val, valstr);
          if (v_len > 0 && isspace(v_val[v_len - 1])) --v_len;
          v_val[v_len] = 0;
          if (sscanf(v_val, "%d:%d:%d%n", &h, &m, &s, &n) == 3 && !v_val[n]) {
          } else if (sscanf(v_val, "%d:%d%n", &h, &m, &n) == 2 && !v_val[n]) {
            s = 0;
          } else if (sscanf(v_val, "%d%n", &h, &n) == 1 && !v_val[n]) {
            m = s = 0;
          } else {
            FAIL(S_ERR_INVALID_VALUE);
          }
          if (h < 0 || h >= 24) FAIL(S_ERR_INVALID_VALUE);
          if (m < 0 || m >= 60) FAIL(S_ERR_INVALID_VALUE);
          if (s < 0 || s >= 60) FAIL(S_ERR_INVALID_VALUE);
          t_val = *p_time;
          if (t_val <= 0) t_val = time(0);
          ptm = localtime(&t_val);
          ptm->tm_hour = h;
          ptm->tm_min = m;
          ptm->tm_sec = s;
          if ((t_val = mktime(ptm)) <= 0) FAIL(S_ERR_INVALID_VALUE);
          *p_time = t_val;
          retval = 1;
        }
        break;
      case 2:
        {
          int v_len, y, m, d, n;
          unsigned char *v_val;
          struct tm btm, *ptm;
          time_t t_val;

          v_len = strlen(valstr);
          if (v_len > 1024) FAIL(S_ERR_INVALID_VALUE);
          v_val = (unsigned char*) alloca(v_len + 1);
          strcpy(v_val, valstr);
          if (v_len > 0 && isspace(v_val[v_len - 1])) --v_len;
          v_val[v_len] = 0;

          if (sscanf(v_val, "%d/%d/%d%n", &y, &m, &d, &n) != 3 || v_val[n])
            FAIL(S_ERR_INVALID_VALUE);
          if (y < 1970 || y > 2030) FAIL(S_ERR_INVALID_VALUE);
          if (m < 1 || m > 12) FAIL(S_ERR_INVALID_VALUE);
          if (d < 1 || d > 31) FAIL(S_ERR_INVALID_VALUE);
          t_val = *p_time;
          if (t_val <= 0) {
            memset(&btm, 0, sizeof(btm));
            btm.tm_isdst = -1;
          } else {
            ptm = localtime(&t_val);
            btm = *ptm;
          }
          btm.tm_year = y - 1900;
          btm.tm_mon = m - 1;
          btm.tm_mday = d;
          if ((t_val = mktime(&btm)) <= 0) FAIL(S_ERR_INVALID_VALUE);
          *p_time = t_val;
          retval = 1;
        }
        break;
      default:
        FAIL(S_ERR_INVALID_FIELD_ID);
      }
    }
    break;
  default:
    FAIL(S_ERR_INVALID_FIELD_ID);
  }

 done:
  write_json_header(out_f);
  fprintf(out_f, "{ \"status\": %d }", retval);

 cleanup:
  html_armor_free(&vb);
  return retval;
}

static unsigned char valid_ss_visibilities[SSSS_LAST_FIELD] =
{
  [SSSS_advanced_view] = 1,
  [SSSS_show_html_attrs] = 1,
  [SSSS_show_html_headers] = 1,
  [SSSS_show_paths] = 1,
  [SSSS_show_access_rules] = 1,
  [SSSS_show_permissions] = 1,
  [SSSS_show_form_fields] = 1,
  [SSSS_show_notifications] = 1,
};

static int
cmd_toggle_contest_xml_vis(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0, f_id;
  struct contest_desc *ecnts = 0;
  int *p_int;

  phr->json_reply = 1;

  if (phr->priv_level != PRIV_LEVEL_ADMIN)
    FAIL(S_ERR_PERM_DENIED);
  /*
  if (opcaps_find(&cnts->capabilities, phr->login, &phr->caps) < 0)
    FAIL(S_ERR_PERM_DENIED);
  if (opcaps_check(phr->caps, OPCAP_EDIT_CONTEST) < 0)
    FAIL(S_ERR_PERM_DENIED);
  */
  if (!phr->ss->edited_cnts)
    FAIL(S_ERR_NO_EDITED_CNTS);
  ecnts = phr->ss->edited_cnts;
  if (ss_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= SSSS_LAST_FIELD
      || !valid_ss_visibilities[f_id])
    FAIL(S_ERR_INVALID_FIELD_ID);
  p_int = ss_sid_state_get_ptr_nc(phr->ss, f_id);
  if (*p_int) *p_int = 0;
  else *p_int = 1;

  write_json_header(out_f);
  fprintf(out_f, "{ \"status\": 1 }");

 cleanup:
  return retval;
}

extern unsigned char super_html_template_help_1[];
extern unsigned char super_html_template_help_2[];

static const unsigned char *
cnts_text_help_map[CNTS_LAST_FIELD] =
{
  [CNTS_users_header_file] = super_html_template_help_1,
  [CNTS_users_footer_file] = super_html_template_help_1,
  [CNTS_register_header_file] = super_html_template_help_1,
  [CNTS_register_footer_file] = super_html_template_help_1,
  [CNTS_team_header_file] = super_html_template_help_1,
  [CNTS_team_menu_1_file] = super_html_template_help_1,
  [CNTS_team_menu_2_file] = super_html_template_help_1,
  [CNTS_team_menu_3_file] = super_html_template_help_1,
  [CNTS_team_separator_file] = super_html_template_help_1,
  [CNTS_team_footer_file] = super_html_template_help_1,
  [CNTS_priv_header_file] = super_html_template_help_1,
  [CNTS_priv_footer_file] = super_html_template_help_1,
  [CNTS_copyright_file] = 0,
  [CNTS_register_email_file] = super_html_template_help_2,
  [CNTS_welcome_file] = 0,
  [CNTS_reg_welcome_file] = 0,
};

static int
cmd_edit_contest_xml_file(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  struct contest_desc *ecnts = 0;
  int f_id, ss_id;
  unsigned char buf[1024];
  unsigned char **t_ptr;
  unsigned char **v_ptr;
  unsigned char fpath[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *cl = " class=\"cnts_edit_legend\"";
  struct stat stb;
  unsigned char zbuf[1024];
  int *l_ptr;
  unsigned char *edit_text = 0;
  const unsigned char *help_text = 0;

  if (!phr->ss->edited_cnts)
    FAIL(S_ERR_NO_EDITED_CNTS);
  ecnts = phr->ss->edited_cnts;
  if (ss_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD
      || !(ss_id = cnts_text_edit_map[f_id]))
    FAIL(S_ERR_INVALID_FIELD_ID);

  v_ptr = (unsigned char **) contest_desc_get_ptr_nc(ecnts, f_id);
  t_ptr = (unsigned char **) ss_sid_state_get_ptr_nc(phr->ss, ss_id);
  l_ptr = (int*) ss_sid_state_get_ptr_nc(phr->ss, cnts_text_load_map[f_id]);
  contests_get_path_in_conf_dir(fpath, sizeof(fpath), ecnts, *v_ptr);
  help_text = cnts_text_help_map[f_id];
  if (!help_text) help_text = "";

  if (stat(fpath, &stb) < 0) {
    snprintf(zbuf, sizeof(zbuf),
             "<i><font color=\"red\">nonexistant</font></i>");
    *l_ptr = 1;
  } else {
    snprintf(zbuf, sizeof(zbuf), "<tt>%zu</tt>", (size_t) stb.st_size);
    if (!*l_ptr) {
      char *txt = 0;
      size_t sz = 0;

      if (generic_read_file(&txt, 0, &sz, 0, 0, fpath, 0) >= 0) {
        xfree(*t_ptr); *t_ptr = txt; txt = 0;
      }
    }
    *l_ptr = 1;
  }

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d, editing file %s",
           phr->html_name, ecnts->id, contest_desc_get_name(f_id));
  write_html_header(out_f, phr, buf, 1, 0);

  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<table class=\"cnts_edit\">\n");
  fprintf(out_f, "<tr><td%s>%s:&nbsp;</td><td%s><tt>%s</tt></td></tr>\n",
          cl, "Parameter value", cl, ARMOR(*v_ptr));
  fprintf(out_f, "<tr><td%s>%s</td><td%s><tt>%s</tt></td></tr>\n",
          cl, "Full path", cl, ARMOR(fpath));
  fprintf(out_f, "<tr><td%s>%s</td><td%s>%s</td></tr>\n",
          cl, "File size", cl, zbuf);
  fprintf(out_f, "</table>\n");

  edit_text = *t_ptr;
  if (!edit_text) edit_text = "";

  fprintf(out_f, "<h2>File contents</h2>\n");

  fprintf(out_f, "<form id=\"editBox\"><textarea dojoType=\"dijit.form.Textarea\" name=\"param\" rows=\"20\" cols=\"80\">%s</textarea></form>\n",
          ARMOR(edit_text));

  fprintf(out_f, "<br/>\n");

  /*
  dojo_button(out_f, "1", "home-32x32", "To the top level (postpone editing)",
              "alert(\"Clicked TopLevel\")");
  */
  dojo_button(out_f, 0, "accept-32x32", "OK",
              "editFileSave(\"editBox\", %d, %d, %d)",
              SSERV_OP_SAVE_FILE_CONTEST_XML, f_id,
              SSERV_OP_EDIT_CONTEST_PAGE_2);
  dojo_button(out_f, 0, "cancel-32x32", "Cancel",
              "ssLoad1(%d)",
              SSERV_OP_EDIT_CONTEST_PAGE_2);
  dojo_button(out_f, 0, "delete_page-32x32", "Clear",
              "editFileClear(%d, %d, %d)",
              SSERV_OP_CLEAR_FILE_CONTEST_XML, f_id,
              SSERV_OP_CONTEST_XML_FIELD_EDIT_PAGE);
  dojo_button(out_f, 0, "refresh-32x32", "Reload",
              "editFileReload(%d, %d, %d)",
              SSERV_OP_RELOAD_FILE_CONTEST_XML, f_id,
              SSERV_OP_CONTEST_XML_FIELD_EDIT_PAGE);

  fprintf(out_f, "<br/><hr/>\n");

  fprintf(out_f, "%s\n", help_text);

  write_html_footer(out_f);

 cleanup:
  html_armor_free(&ab);
  return retval;
}

static int
cmd_clear_file_contest_xml(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0, f_id, f_id2;
  int *p_int;
  unsigned char **p_str;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts)
    FAIL(S_ERR_NO_EDITED_CNTS);
  if (ss_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD
      || !(f_id2 = cnts_text_edit_map[f_id]))
    FAIL(S_ERR_INVALID_FIELD_ID);

  p_str = (unsigned char**) ss_sid_state_get_ptr_nc(phr->ss, f_id2);
  xfree(*p_str); *p_str = 0;
  p_int = (int*) ss_sid_state_get_ptr_nc(phr->ss, cnts_text_load_map[f_id]);
  if (phr->opcode == SSERV_OP_CLEAR_FILE_CONTEST_XML) {
    *p_int = 1;
  } else {
    *p_int = 0;
  }

  write_json_header(out_f);
  fprintf(out_f, "{ \"status\": 1 }");

 cleanup:
  return retval;
}

static int
cmd_save_file_contest_xml(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int f_id = 0, f_id2 = 0;
  const unsigned char *valstr = 0;
  int utf8_id = 0;
  struct html_armor_buffer vb = HTML_ARMOR_INITIALIZER;
  unsigned char **p_str;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts)
    FAIL(S_ERR_NO_EDITED_CNTS);
  if (ss_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD)
    FAIL(S_ERR_INVALID_FIELD_ID);
  if (!(f_id2 = cnts_text_edit_map[f_id]))
    FAIL(S_ERR_INVALID_FIELD_ID);
  if (ss_cgi_param(phr, "param", &valstr) <= 0 || !valstr)
    FAIL(S_ERR_INVALID_VALUE);

  // value is in utf-8, translate it to the local charset
  utf8_id = charset_get_id("utf-8");
  valstr = charset_decode(utf8_id, &vb, valstr);
  p_str = (unsigned char**) ss_sid_state_get_ptr_nc(phr->ss, f_id2);
  xfree(*p_str);
  *p_str = xstrdup(valstr);
  retval = 1;

  write_json_header(out_f);
  fprintf(out_f, "{ \"status\": %d }", retval);

 cleanup:
  html_armor_free(&vb);
  return retval;
}

const unsigned char access_field_set[CNTS_LAST_FIELD] =
{
  [CNTS_register_access] = 1,
  [CNTS_users_access] = 1,
  [CNTS_master_access] = 1,
  [CNTS_judge_access] = 1,
  [CNTS_team_access] = 1,
  [CNTS_serve_control_access] = 1,
};

static int
cmd_contest_xml_access_edit_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0, i, f_id;
  struct contest_desc *ecnts = 0;
  unsigned char buf[1024];
  unsigned char jbuf[1024];
  unsigned char vbuf[1024];
  const struct contest_access *acc = 0;
  const struct contest_ip *p;
  int row = 0;

  if (!phr->ss->edited_cnts)
    FAIL(S_ERR_NO_EDITED_CNTS);
  ecnts = phr->ss->edited_cnts;
  if (ss_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD
      || !(access_field_set[f_id]))
    FAIL(S_ERR_INVALID_FIELD_ID);
  acc = *(const struct contest_access**) contest_desc_get_ptr(ecnts, f_id);

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d, editing %s",
           phr->html_name, ecnts->id, contest_desc_get_name(f_id));
  write_html_header(out_f, phr, buf, 1, 0);
  fprintf(out_f, "<h1>%s</h1>\n", buf);
  fprintf(out_f, "<br/>\n");

  fprintf(out_f, "<div id=\"cnts_edit_content\">\n");
  fprintf(out_f, "<table class=\"cnts_edit\">\n");

  if (acc) {
    fprintf(out_f,
            "<tr%s>"
            "<th class=\"cnts_edit_legend\">Rule N</th>"
            "<th class=\"cnts_edit_legend\">IP Mask</th>"
            "<th class=\"cnts_edit_legend\">SSL?</th>"
            "<th class=\"cnts_edit_legend\">Allow?</th>"
            "<th class=\"cnts_edit_legend\">Actions</th>"
            "</tr>\n",
            head_row_attr);

    for (p = (const struct contest_ip *) acc->b.first_down, i = 0;
         p; p = (const struct contest_ip *) p->b.right, ++i) {
      fprintf(out_f, "<tr%s>", form_row_attrs[row ^= 1]);
      fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"100px\">%d</td>", i);
      fprintf(out_f, "<td class=\"cnts_edit_data\" width=\"200px\">");
      fprintf(out_f, "<div class=\"cnts_edit_data\" dojoType=\"dijit.InlineEditBox\" onChange=\"alert(arguments[0])\" autoSave=\"true\" title=\"%s\">",
              "IP address");
      fprintf(out_f, "%s", xml_unparse_ip_mask(p->addr, p->mask));
      fprintf(out_f, "</div></td>");

      fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"100px\">");
      ss_html_select(out_f, 0, 0, 0,
                     eprintf(jbuf, sizeof(jbuf), "alert(this.options[this.selectedIndex].value)"),
                     eprintf(vbuf, sizeof(vbuf), "%d", p->ssl),
                     3,
                     (const char*[]) { "-1", "0", "1" },
                     (const char*[]) { "Any", "No SSL", "SSL" });
      fprintf(out_f, "</td>");

      fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"100px\">");
      ss_html_int_select(out_f, 0, 0, 0,
                         eprintf(jbuf, sizeof(jbuf), "alert(this.options[this.selectedIndex].value)"),
                         !!p->allow, 2,
                         (const char*[]) { "Deny", "Allow" });
      fprintf(out_f, "</td>");
      fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"150px\">");
      dojo_button(out_f, 0, "back-16x16", "Move Up",
                  "alert(\"Move Up\")");
      dojo_button(out_f, 0, "next-16x16", "Move Down",
                  "alert(\"Move Down\")");
      dojo_button(out_f, 0, "delete-16x16", "Move Down",
                  "alert(\"Remove Rule\")");
      fprintf(out_f, "</td>");
      fprintf(out_f, "</tr>\n");
    }
  }

  fprintf(out_f, "<tr%s><td class=\"cnts_edit_legend\" colspan=\"5\" style=\"text-align: center;\"><b>Add a new rule</b></td></tr>\n", head_row_attr);

  fprintf(out_f, "<tr%s>", form_row_attrs[0]);
  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"100px\">&nbsp;</td>");
  fprintf(out_f, "<td class=\"cnts_edit_data\" width=\"200px\">");
  fprintf(out_f, "<div class=\"cnts_edit_data\" dojoType=\"dijit.InlineEditBox\" onChange=\"alert(arguments[0])\" autoSave=\"true\" title=\"%s\"></div></td>",
          "IP address");
  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"100px\">");
  ss_html_select(out_f, 0, 0, 0,
                 eprintf(jbuf, sizeof(jbuf), "alert(this.options[this.selectedIndex].value)"),
                 eprintf(vbuf, sizeof(vbuf), "%d", -1),
                 3,
                 (const char*[]) { "-1", "0", "1" },
                 (const char*[]) { "Any", "No SSL", "SSL" });
  fprintf(out_f, "</td>");

  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"100px\">");
  ss_html_int_select(out_f, 0, 0, 0,
                     eprintf(jbuf, sizeof(jbuf), "alert(this.options[this.selectedIndex].value)"),
                     1, 2,
                     (const char*[]) { "Deny", "Allow" });
  fprintf(out_f, "</td>");
  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"150px\">");
  dojo_button(out_f, 0, "add-16x16", "Move Up",
              "alert(\"Move Up\")");
  fprintf(out_f, "</td>");
  fprintf(out_f, "</tr>\n");

  fprintf(out_f, "<tr%s><td class=\"cnts_edit_legend\" colspan=\"5\" style=\"text-align: center;\"><b>Default access</b></td></tr>\n", head_row_attr);

  fprintf(out_f, "<tr%s>", form_row_attrs[0]);
  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"100px\">&nbsp;</td>");
  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"200px\" style=\"text-align: center;\">&nbsp;</td>");
  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"100px\">&nbsp;</td>");

  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"100px\">");
  ss_html_int_select(out_f, 0, 0, 0,
                     eprintf(jbuf, sizeof(jbuf), "alert(this.options[this.selectedIndex].value)"),
                     1, 2,
                     (const char*[]) { "Deny", "Allow" });
  fprintf(out_f, "</td>");
  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"150px\">&nbsp;</td>");
  fprintf(out_f, "</tr>\n");

  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</div>\n");

  fprintf(out_f, "<br/>\n");

  dojo_button(out_f, 0, "accept-32x32", "OK", "alert(\"OK\")");
  dojo_button(out_f, 0, "cancel-32x32", "Cancel", "alert(\"Cancel\")");
  dojo_button(out_f, 0, "promotion-32x32", "Copy",
              "ssLoad2(%d, %d)", SSERV_OP_COPY_ACCESS_RULES_PAGE, f_id);

  write_html_footer(out_f);

 cleanup:
  return retval;
}

static handler_func_t contest_xml_field_edit_cmd[CNTS_LAST_FIELD] =
{
  [CNTS_users_header_file] = cmd_edit_contest_xml_file,
  [CNTS_users_footer_file] = cmd_edit_contest_xml_file,
  [CNTS_register_header_file] = cmd_edit_contest_xml_file,
  [CNTS_register_footer_file] = cmd_edit_contest_xml_file,
  [CNTS_team_header_file] = cmd_edit_contest_xml_file,
  [CNTS_team_menu_1_file] = cmd_edit_contest_xml_file,
  [CNTS_team_menu_2_file] = cmd_edit_contest_xml_file,
  [CNTS_team_menu_3_file] = cmd_edit_contest_xml_file,
  [CNTS_team_separator_file] = cmd_edit_contest_xml_file,
  [CNTS_team_footer_file] = cmd_edit_contest_xml_file,
  [CNTS_priv_header_file] = cmd_edit_contest_xml_file,
  [CNTS_priv_footer_file] = cmd_edit_contest_xml_file,
  [CNTS_copyright_file] = cmd_edit_contest_xml_file,
  [CNTS_register_email_file] = cmd_edit_contest_xml_file,
  [CNTS_register_access] = cmd_contest_xml_access_edit_page,
  [CNTS_users_access] = cmd_contest_xml_access_edit_page,
  [CNTS_master_access] = cmd_contest_xml_access_edit_page,
  [CNTS_judge_access] = cmd_contest_xml_access_edit_page,
  [CNTS_team_access] = cmd_contest_xml_access_edit_page,
  [CNTS_serve_control_access] = cmd_contest_xml_access_edit_page,
  [CNTS_welcome_file] = cmd_edit_contest_xml_file,
  [CNTS_reg_welcome_file] = cmd_edit_contest_xml_file,
};

static int
cmd_contest_xml_field_edit_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int f_id, retval = 0;

  if (ss_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD)
    FAIL(S_ERR_INVALID_FIELD_ID);
  if (!contest_xml_field_edit_cmd[f_id])
    FAIL(S_ERR_INVALID_FIELD_ID);
  return (*contest_xml_field_edit_cmd[f_id])(log_f, out_f, phr);

 cleanup:
  return retval;
}

static int
cmd_copy_access_rules_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int f_id, i, cnts_num;
  struct contest_desc *ecnts;
  unsigned char buf[1024];
  const unsigned char *s;
  const int *cnts_list = 0;
  const struct contest_desc *cnts = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (ss_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD
      || !access_field_set[f_id])
    FAIL(S_ERR_INVALID_FIELD_ID);
  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(S_ERR_NO_EDITED_CNTS);

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d, copy %s from another contest",
           phr->html_name, ecnts->id, contest_desc_get_name(f_id));
  write_html_header(out_f, phr, buf, 1, 0);
  fprintf(out_f, "<h1>%s</h1>\n", buf);
  fprintf(out_f, "<br/>\n");

  fprintf(out_f, "<form id=\"copyForm\">\n");
  fprintf(out_f, "<p><select name=\"contest_id_2\">");

  cnts_num = contests_get_list(&cnts_list);
  for (i = 0; i < cnts_num; ++i) {
    if (contests_get(cnts_list[i], &cnts) < 0 || !cnts) continue;
    fprintf(out_f, "<option value=\"%d\">%d-%s</option>",
            cnts_list[i], cnts_list[i], ARMOR(cnts->name));
  }

  fprintf(out_f, "</select></p>");
  fprintf(out_f, "<p><select name=\"field_id_2\">");
  for (i = 1; i < CNTS_LAST_FIELD; ++i) {
    if (!access_field_set[i]) continue;
    s = "";
    if (i == f_id) s = " selected=\"1\"";
    fprintf(out_f, "<option value=\"%d\"%s><tt>&lt;%s&gt;</tt></option>",
            i, s, contest_desc_get_name(i));
  }
  fprintf(out_f, "</select></p>\n");
  fprintf(out_f, "</form>\n");

  fprintf(out_f, "<br/>\n");

  dojo_button(out_f, 0, "accept-32x32", "OK", "alert(\"OK\")");
  dojo_button(out_f, 0, "cancel-32x32", "Cancel", "alert(\"Cancel\")");

  write_html_footer(out_f);

 cleanup:
  html_armor_free(&ab);
  return retval;
}

static int
cmd_copy_all_access_rules_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int i, cnts_num;
  struct contest_desc *ecnts;
  unsigned char buf[1024];
  const int *cnts_list = 0;
  const struct contest_desc *cnts = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(S_ERR_NO_EDITED_CNTS);

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d, copy access rules from another contest",
           phr->html_name, ecnts->id);
  write_html_header(out_f, phr, buf, 1, 0);
  fprintf(out_f, "<h1>%s</h1>\n", buf);
  fprintf(out_f, "<br/>\n");

  fprintf(out_f, "<form id=\"copyForm\">\n");
  fprintf(out_f, "<p><select name=\"contest_id_2\">");

  cnts_num = contests_get_list(&cnts_list);
  for (i = 0; i < cnts_num; ++i) {
    if (contests_get(cnts_list[i], &cnts) < 0 || !cnts) continue;
    fprintf(out_f, "<option value=\"%d\">%d-%s</option>",
            cnts_list[i], cnts_list[i], ARMOR(cnts->name));
  }

  fprintf(out_f, "</select></p>");
  fprintf(out_f, "</form>\n");

  fprintf(out_f, "<br/>\n");

  dojo_button(out_f, 0, "accept-32x32", "OK",
              "ssFormOp1(\"copyForm\", %d, %d)",
              SSERV_OP_COPY_ALL_ACCESS_RULES,
              SSERV_OP_EDIT_CONTEST_PAGE_2);
  dojo_button(out_f, 0, "cancel-32x32", "Cancel", "ssLoad1(%d)",
              SSERV_OP_EDIT_CONTEST_PAGE_2);

  write_html_footer(out_f);

 cleanup:
  html_armor_free(&ab);
  return retval;
}

static int
cmd_copy_all_access_rules(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 1;
  int contest_id_2, i;
  struct contest_desc *ecnts = 0;
  const struct contest_desc *cnts = 0;
  const struct contest_access **p_src_access = 0;
  struct contest_access **p_dst_access = 0;

  phr->json_reply = 1;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(S_ERR_NO_EDITED_CNTS);
  if (ss_cgi_param_int(phr, "contest_id_2", &contest_id_2) < 0
      || contest_id_2 <= 0)
    FAIL(S_ERR_INV_CONTEST);
  if (contest_id_2 == ecnts->id) goto done;
  if (contests_get(contest_id_2, &cnts) < 0 || !cnts)
    FAIL(S_ERR_INV_CONTEST);

  for (i = 1; i < CNTS_LAST_FIELD; ++i) {
    if (!access_field_set[i]) continue;
    p_src_access = (const struct contest_access**)contest_desc_get_ptr(cnts, i);
    p_dst_access = (struct contest_access**) contest_desc_get_ptr_nc(ecnts, i);
    if (*p_src_access == *p_dst_access) continue;

    xml_unlink_node(&(*p_dst_access)->b);
    contests_free_2(&(*p_dst_access)->b);
    *p_dst_access = super_html_copy_contest_access(*p_src_access);
    xml_link_node_last(&ecnts->b, &(*p_dst_access)->b);
  }

 done:
  write_json_header(out_f);
  fprintf(out_f, "{ \"status\": %d }", retval);

 cleanup:
    return retval;
}

static int
cmd_copy_all_priv_users_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int i, cnts_num;
  struct contest_desc *ecnts;
  unsigned char buf[1024];
  const int *cnts_list = 0;
  const struct contest_desc *cnts = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(S_ERR_NO_EDITED_CNTS);

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d, copy user privilege from another contest",
           phr->html_name, ecnts->id);
  write_html_header(out_f, phr, buf, 1, 0);
  fprintf(out_f, "<h1>%s</h1>\n", buf);
  fprintf(out_f, "<br/>\n");

  fprintf(out_f, "<form id=\"copyForm\">\n");
  fprintf(out_f, "<p><select name=\"contest_id_2\">");

  cnts_num = contests_get_list(&cnts_list);
  for (i = 0; i < cnts_num; ++i) {
    if (contests_get(cnts_list[i], &cnts) < 0 || !cnts) continue;
    fprintf(out_f, "<option value=\"%d\">%d-%s</option>",
            cnts_list[i], cnts_list[i], ARMOR(cnts->name));
  }

  fprintf(out_f, "</select></p>");
  fprintf(out_f, "</form>\n");

  fprintf(out_f, "<br/>\n");

  dojo_button(out_f, 0, "accept-32x32", "OK",
              "ssFormOp1(\"copyForm\", %d, %d)",
              SSERV_OP_COPY_ALL_PRIV_USERS,
              SSERV_OP_EDIT_CONTEST_PAGE_2);
  dojo_button(out_f, 0, "cancel-32x32", "Cancel", "ssLoad1(%d)",
              SSERV_OP_EDIT_CONTEST_PAGE_2);

  fprintf(out_f, "<br/><hr/>\n");

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d, add a new privileged user",
           phr->html_name, ecnts->id);
  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<br/>\n");

  fprintf(out_f, "<form id=\"addUser\">\n");
  fprintf(out_f, "<table>\n");
  fprintf(out_f, "<tr><td>User Login:</td><td><input type=\"text\" name=\"login\" /></td></tr>\n");
  fprintf(out_f, "<tr><td>Permissions:</td><td>"
          "<select name=\"perms\">"
          "<option value=\"0\"></option>"
          "<option value=\"1\">Observer</option>"
          "<option value=\"2\">Judge</option>"
          "<option value=\"3\">Full control</option>"
          "</select></td></tr>\n");
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  fprintf(out_f, "<br/>\n");

  dojo_button(out_f, 0, "accept-32x32", "OK",
              "ssFormOp1(\"addUser\", %d, %d)",
              SSERV_OP_ADD_PRIV_USER,
              SSERV_OP_EDIT_CONTEST_PAGE_2);
  dojo_button(out_f, 0, "cancel-32x32", "Cancel", "ssLoad1(%d)",
              SSERV_OP_EDIT_CONTEST_PAGE_2);

  write_html_footer(out_f);

 cleanup:
  html_armor_free(&ab);
  return retval;
}

static int
cmd_edit_permissions_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  int field_id, j;
  struct opcap_list_item *perms;
  struct contest_desc *ecnts;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char buf[1024];

  if (!(ecnts = phr->ss->edited_cnts)) FAIL(S_ERR_NO_EDITED_CNTS);
  if (ss_cgi_param_int(phr, "field_id", &field_id) < 0 || field_id < 0)
    FAIL(S_ERR_INVALID_FIELD_ID);

  perms = ecnts->capabilities.first;
  for (j = 0; perms && j != field_id;
       perms = (struct opcap_list_item*) perms->b.right, j++);
  if (!perms || j != field_id) FAIL(S_ERR_INVALID_FIELD_ID);

  snprintf(buf, sizeof(buf),
           "serve-control: %s, contest %d, edit user privileges for user %s",
           phr->html_name, ecnts->id, ARMOR(perms->login));
  write_html_header(out_f, phr, buf, 1, 0);
  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<br/><h2>Typical permissions</h2><br/>\n");

  ss_html_int_select(out_f, 0, 0, 0,
                     "alert(this.options[this.selectedIndex].value)",
                     opcaps_is_predef_caps(perms->caps),
                     5, predef_caps_names);

  fprintf(out_f, "<br/><hr/><br/><h2>Capabilities in detail</h2><br/>\n");

  fprintf(out_f, "<form id=\"capsList\">\n");
  super_html_print_caps_table(out_f, perms->caps, " class=\"cnts_edit\"",
                              " class=\"cnts_edit_legend\"");
  fprintf(out_f, "</form>\n");
  fprintf(out_f, "<br/>\n");

  dojo_button(out_f, 0, "accept-32x32", "OK", "alert(\"OK\")");
  dojo_button(out_f, 0, "cancel-32x32", "Cancel", "ssLoad1(%d)",
              SSERV_OP_EDIT_CONTEST_PAGE_2);
  
  fprintf(out_f, "<br/>\n");
  write_html_footer(out_f);

 cleanup:
  html_armor_free(&ab);
  return retval;
}

static int
cmd_edit_general_fields_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  struct contest_desc *ecnts;
  int row = 1, ff, val;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char buf[1024];

  if (!(ecnts = phr->ss->edited_cnts)) FAIL(S_ERR_NO_EDITED_CNTS);

  snprintf(buf, sizeof(buf),
           "serve-control: %s, contest %d, edit general fields",
           phr->html_name, ecnts->id);
  write_html_header(out_f, phr, buf, 1, 0);
  fprintf(out_f, "<h1>%s</h1>\n", buf);
  fprintf(out_f, "<br/>\n");
  fprintf(out_f, "<form id=\"fieldList\">\n");
  fprintf(out_f, "<table class=\"cnts_edit\">\n");
  fprintf(out_f,
          "<tr%s>"
          "<th class=\"cnts_edit_legend\">Field</th>"
          "<th class=\"cnts_edit_legend\">Selection</th>"
          "<th class=\"cnts_edit_legend\">Legend</th>"
          "</tr>", head_row_attr);
  for (ff = 1; ff < CONTEST_LAST_FIELD; ++ff) {
    fprintf(out_f, "<tr%s><td class=\"cnts_edit_legend\">%s</td>",
            form_row_attrs[row ^= 1], contests_get_form_field_name(ff));
    fprintf(out_f, "<td class=\"cnts_edit_legend\">");
    val = 0;
    if (ecnts->fields[ff]) {
      val = 1;
      if (ecnts->fields[ff]->mandatory) val = 2;
    }
    snprintf(buf, sizeof(buf), "field_%d", ff);
    ss_html_int_select(out_f, 0, 0, buf, 0, val, 3,
                       (const char *[]) { "Disabled", "Optional", "Mandatory"});
    fprintf(out_f, "</td>");
    fprintf(out_f, "<td class=\"cnts_edit_legend\"><input type=\"text\" name=\"legend_%d\"", ff);
    if (ecnts->fields[ff] && ecnts->fields[ff]->legend)
      fprintf(out_f, " value=\"%s\"", ARMOR(ecnts->fields[ff]->legend));
    fprintf(out_f, " /></td></tr>\n");
  }
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");
  fprintf(out_f, "<br/>\n");
  dojo_button(out_f, 0, "accept-32x32", "OK", "alert(\"OK\")");
  dojo_button(out_f, 0, "cancel-32x32", "Cancel", "ssLoad1(%d)",
              SSERV_OP_EDIT_CONTEST_PAGE_2);
  fprintf(out_f, "<br/>\n");
  write_html_footer(out_f);

 cleanup:
  html_armor_free(&ab);
  return retval;
}

static int
cmd_edit_member_fields_page(
        FILE *log_f,
        FILE *out_f,
        struct super_http_request_info *phr)
{
  int retval = 0;
  struct contest_desc *ecnts;
  unsigned char buf[1024];
  int memb_id, ff, row = 1, val;
  struct contest_member *memb;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *cl = " class=\"cnts_edit_legend\"";

  if (!(ecnts = phr->ss->edited_cnts)) FAIL(S_ERR_NO_EDITED_CNTS);
  if (ss_cgi_param_int(phr, "field_id", &memb_id) < 0
      || memb_id < 0 || memb_id >= CONTEST_LAST_MEMBER)
    FAIL(S_ERR_INVALID_FIELD_ID);
  memb = ecnts->members[memb_id];

  snprintf(buf, sizeof(buf),
           "serve-control: %s, contest %d, edit &quot;%s&quot; fields",
           phr->html_name, ecnts->id,
           contests_get_member_name(memb_id));
  write_html_header(out_f, phr, buf, 1, 0);
  fprintf(out_f, "<h1>%s</h1>\n", buf);
  fprintf(out_f, "<br/>\n");
  fprintf(out_f, "<form id=\"fieldList\">\n");
  fprintf(out_f, "<table class=\"cnts_edit\">\n");
  val = 0;
  if (memb) val = memb->min_count;
  fprintf(out_f, "<tr%s><td%s>Minimal number:</td><td%s>",
          form_row_attrs[row ^= 1], cl, cl);
  html_numeric_select(out_f, "min_count", val, 0, 5);
  fprintf(out_f, "</td></tr>\n");
  val = 0;
  if (memb) val = memb->max_count;
  fprintf(out_f, "<tr%s><td%s>Maximal number:</td><td%s>",
          form_row_attrs[row ^= 1], cl, cl);
  html_numeric_select(out_f, "max_count", val, 0, 5);
  fprintf(out_f, "</td></tr>\n");
  val = 0;
  if (memb) val = memb->init_count;
  fprintf(out_f, "<tr%s><td%s>Initial number:</td><td%s>",
          form_row_attrs[row ^= 1], cl, cl);
  html_numeric_select(out_f, "init_count", val, 0, 5);
  fprintf(out_f, "</td></tr>\n");
  fprintf(out_f, "</table>\n");

  row = 1;
  fprintf(out_f, "<br/><table class=\"cnts_edit\">\n");
  fprintf(out_f,
          "<tr%s>"
          "<th class=\"cnts_edit_legend\">Field</th>"
          "<th class=\"cnts_edit_legend\">Selection</th>"
          "<th class=\"cnts_edit_legend\">Legend</th>"
          "</tr>", head_row_attr);
  for (ff = 1; ff < CONTEST_LAST_MEMBER_FIELD; ++ff) {
    fprintf(out_f, "<tr%s><td class=\"cnts_edit_legend\">%s</td>",
            form_row_attrs[row ^= 1], contests_get_member_field_name(ff));
    fprintf(out_f, "<td class=\"cnts_edit_legend\">");
    val = 0;
    if (memb && memb->fields[ff]) {
      val = 1;
      if (memb->fields[ff]->mandatory) val = 2;
    }
    snprintf(buf, sizeof(buf), "field_%d", ff);
    ss_html_int_select(out_f, 0, 0, buf, 0, val, 3,
                       (const char *[]) { "Disabled", "Optional", "Mandatory"});
    fprintf(out_f, "</td>");
    fprintf(out_f, "<td class=\"cnts_edit_legend\"><input type=\"text\" name=\"legend_%d\"", ff);
    if (memb && memb->fields[ff] && memb->fields[ff]->legend)
      fprintf(out_f, " value=\"%s\"", ARMOR(memb->fields[ff]->legend));
    fprintf(out_f, " /></td></tr>\n");
  }
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");
  fprintf(out_f, "<br/>\n");
  dojo_button(out_f, 0, "accept-32x32", "OK", "alert(\"OK\")");
  dojo_button(out_f, 0, "cancel-32x32", "Cancel", "ssLoad1(%d)",
              SSERV_OP_EDIT_CONTEST_PAGE_2);
  fprintf(out_f, "<br/>\n");
  write_html_footer(out_f);

 cleanup:
  html_armor_free(&ab);
  return retval;
}

static handler_func_t op_handlers[SSERV_OP_LAST] =
{
  [SSERV_OP_VIEW_CNTS_DETAILS] = cmd_cnts_details,
  [SSERV_OP_EDITED_CNTS_BACK] = cmd_edited_cnts_back,
  [SSERV_OP_EDITED_CNTS_CONTINUE] = cmd_edited_cnts_continue,
  [SSERV_OP_EDITED_CNTS_START_NEW] = cmd_edited_cnts_start_new,
  [SSERV_OP_EDIT_CONTEST_PAGE] = cmd_edit_contest_page,
  [SSERV_OP_EDIT_CONTEST_PAGE_2] = cmd_edit_contest_page_2,
  [SSERV_OP_CLEAR_CONTEST_XML_FIELD] = cmd_clear_contest_xml_field,
  [SSERV_OP_EDIT_CONTEST_XML_FIELD] = cmd_edit_contest_xml_field,
  [SSERV_OP_TOGGLE_CONTEST_XML_VISIBILITY] = cmd_toggle_contest_xml_vis,
  [SSERV_OP_CONTEST_XML_FIELD_EDIT_PAGE] = cmd_contest_xml_field_edit_page,
  [SSERV_OP_CLEAR_FILE_CONTEST_XML] = cmd_clear_file_contest_xml,
  [SSERV_OP_RELOAD_FILE_CONTEST_XML] = cmd_clear_file_contest_xml,
  [SSERV_OP_SAVE_FILE_CONTEST_XML] = cmd_save_file_contest_xml,
  [SSERV_OP_COPY_ACCESS_RULES_PAGE] = cmd_copy_access_rules_page,
  [SSERV_OP_COPY_ALL_ACCESS_RULES_PAGE] = cmd_copy_all_access_rules_page,
  [SSERV_OP_COPY_ALL_ACCESS_RULES] = cmd_copy_all_access_rules,
  [SSERV_OP_COPY_ALL_PRIV_USERS_PAGE] = cmd_copy_all_priv_users_page,
  [SSERV_OP_EDIT_PERMISSIONS_PAGE] = cmd_edit_permissions_page,
  [SSERV_OP_EDIT_GENERAL_FIELDS_PAGE] = cmd_edit_general_fields_page,
  [SSERV_OP_EDIT_MEMBER_FIELDS_PAGE] = cmd_edit_member_fields_page,
};

static int
do_http_request(FILE *log_f, FILE *out_f, struct super_http_request_info *phr)
{
  int opcode = 0;
  int retval = 0;

  if (ss_cgi_param_int(phr, "op", &opcode) < 0
      || opcode <= 0 || opcode >= SSERV_OP_LAST || !op_handlers[opcode])
    FAIL(S_ERR_INV_OPER);
  phr->opcode = opcode;

  retval = (*op_handlers[opcode])(log_f, out_f, phr);

 cleanup:
  return retval;
}

static unsigned char const * const error_messages[] =
{
  [S_ERR_EMPTY_REPLY] = "Reply text is empty",
  [S_ERR_INV_OPER] = "Invalid operation",
  [S_ERR_CONTEST_EDITED] = "Cannot edit more than one contest at a time",
  [S_ERR_INV_SID] = "Invalid session id",
  [S_ERR_INV_CONTEST] = "Invalid contest id",
  [S_ERR_PERM_DENIED] = "Permission denied",
  [S_ERR_INTERNAL] = "Internal error",
  [S_ERR_ALREADY_EDITED] = "Contest is already edited",
  [S_ERR_NO_EDITED_CNTS] = "No contest is edited",
  [S_ERR_INVALID_FIELD_ID] = "Invalid field ID",
  [S_ERR_NOT_IMPLEMENTED] = "Not implemented yet",
  [S_ERR_INVALID_VALUE] = "Invalid value",
};

void
super_html_http_request(
        char **p_out_t,
        size_t *p_out_z,
        struct super_http_request_info *phr)
{
  FILE *out_f = 0, *log_f = 0;
  char *out_t = 0, *log_t = 0;
  size_t out_z = 0, log_z = 0;
  int r = 0, n;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *http_host = 0;
  const unsigned char *script_name = 0;
  const unsigned char *protocol = "http";
  unsigned char self_url[4096];
  const unsigned char *s = 0;

  if (ss_getenv(phr, "SSL_PROTOCOL") || ss_getenv(phr, "HTTPS")) {
    phr->ssl_flag = 1;
    protocol = "https";
  }
  if (!(http_host = ss_getenv(phr, "HTTP_HOST"))) http_host = "localhost";
  if (!(script_name = ss_getenv(phr, "SCRIPT_NAME")))
    script_name = "/cgi-bin/serve-control";
  snprintf(self_url, sizeof(self_url), "%s://%s%s", protocol, http_host,
           script_name);
  phr->self_url = self_url;
  phr->script_name = script_name;

  if ((r = ss_cgi_param(phr, "SID", &s)) < 0) {
    r = -S_ERR_INV_SID;
  }
  if (r > 0) {
    r = 0;
    if (sscanf(s, "%llx%n", &phr->session_id, &n) != 1
        || s[n] || !phr->session_id) {
      r = -S_ERR_INV_SID;
    }
  }

  if (!r) {
    out_f = open_memstream(&out_t, &out_z);
    log_f = open_memstream(&log_t, &log_z);
    r = do_http_request(log_f, out_f, phr);
    fclose(out_f); out_f = 0;
    fclose(log_f); log_f = 0;
  }

  if (r < 0) {
    xfree(out_t); out_t = 0; out_z = 0;
    out_f = open_memstream(&out_t, &out_z);
    if (phr->json_reply) {
      write_json_header(out_f);
      fprintf(out_f, "{ \"status\": %d, \"text\": \"%s\" }",
              r, error_messages[-r]);
    } else {
      write_html_header(out_f, phr, "Request failed", 0, 0);
      if (r < -1 && r > -S_ERR_LAST) {
        fprintf(out_f, "<h1>Request failed: error %d</h1>\n", -r);
        fprintf(out_f, "<h2>%s</h2>\n", error_messages[-r]);
      } else {
        fprintf(out_f, "<h1>Request failed</h1>\n");
      }
      fprintf(out_f, "<pre><font color=\"red\">%s</font></pre>\n",
              ARMOR(log_t));
      write_html_footer(out_f);
    }
    fclose(out_f); out_f = 0;
  }
  xfree(log_t); log_t = 0; log_z = 0;

  if (!out_t || !*out_t) {
    xfree(out_t); out_t = 0; out_z = 0;
    out_f = open_memstream(&out_t, &out_z);
    if (phr->json_reply) {
      write_json_header(out_f);
      fprintf(out_f, "{ \"status\": %d, \"text\": \"%s\" }",
              -S_ERR_EMPTY_REPLY, error_messages[S_ERR_EMPTY_REPLY]);
    } else {
      write_html_header(out_f, phr, "Empty output", 0, 0);
      fprintf(out_f, "<h1>Empty output</h1>\n");
      fprintf(out_f, "<p>The output page is empty!</p>\n");
      write_html_footer(out_f);
    }
    fclose(out_f); out_f = 0;
  }

  /*
  if (phr->json_reply) {
    fprintf(stderr, "json: %s\n", out_t);
  }
  */

  *p_out_t = out_t;
  *p_out_z = out_z;
  html_armor_free(&ab);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
