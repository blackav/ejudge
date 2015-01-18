/* -*- mode: c -*- */

/* Copyright (C) 2008-2015 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_limits.h"
#include "ejudge/super_html.h"
#include "ejudge/super-serve.h"
#include "ejudge/meta/super-serve_meta.h"
#include "ejudge/super_proto.h"
#include "ejudge/copyright.h"
#include "ejudge/misctext.h"
#include "ejudge/contests.h"
#include "ejudge/meta/contests_meta.h"
#include "ejudge/l10n.h"
#include "ejudge/charsets.h"
#include "ejudge/fileutl.h"
#include "ejudge/xml_utils.h"
#include "ejudge/userlist.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/mischtml.h"
#include "ejudge/prepare.h"
#include "ejudge/meta/prepare_meta.h"
#include "ejudge/meta_generic.h"
#include "ejudge/prepare_dflt.h"
#include "ejudge/cpu.h"
#include "ejudge/compat.h"
#include "ejudge/errlog.h"
#include "ejudge/external_action.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <dlfcn.h>

#if !defined CONF_STYLE_PREFIX
#define CONF_STYLE_PREFIX "/ejudge/"
#endif

#define ARMOR(s)  html_armor_buf(&ab, s)
#define URLARMOR(s)  url_armor_buf(&ab, s)
#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

static int
ss_cgi_param_utf8_str(
        const struct http_request_info *phr,
        const unsigned char *param,
        struct html_armor_buffer *pab,
        const unsigned char **p_value)
{
  int i, len, utf8_id;
  const unsigned char *s;

  if (!param) return -1;
  for (i = 0; i < phr->param_num; i++)
    if (!strcmp(phr->param_names[i], param))
      break;
  if (i >= phr->param_num) return 0;
  if ((len = strlen(phr->params[i])) != phr->param_sizes[i]) return -1;
  utf8_id = charset_get_id("utf-8");
  s = charset_decode(utf8_id, pab, phr->params[i]);
  len = strlen(s);
  if (!len || !isspace(s[len - 1])) {
    *p_value = s;
    return 1;
  }
  if (s != pab->buf) {
    html_armor_reserve(pab, len + 1);
    strcpy(pab->buf, s);
  }
  while (len > 0 && isspace(pab->buf[len - 1])) --len;
  pab->buf[len] = 0;
  *p_value = pab->buf;
  return 1;
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

static void
ss_html_int_select_undef(
        FILE *out_f,
        const unsigned char *id,
        const unsigned char *class,
        const unsigned char *name,
        const unsigned char *onchange,
        int is_undef,
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
  s = "";
  if (is_undef) s = " selected=\"1\"";
  fprintf(out_f, "<option value=\"\"%s>%s</option>", s, "Undefined");
  for (i = 0; i < n; ++i) {
    s = "";
    if (value == i) s = " selected=\"1\"";
    fprintf(out_f, "<option value=\"%d\"%s>%s</option>", i, s, labels[i]);
  }
  fprintf(out_f, "</select>");
}

// size must be < 2GiB
int
parse_size(const unsigned char *valstr, size_t *p_size)
{
  unsigned long long val;
  char *eptr = 0;

  if (!valstr || !*valstr) return -1;

  errno = 0;
  val = strtoull(valstr, &eptr, 10);
  if (errno || valstr == (const unsigned char*) eptr) return -1;

  if (*eptr == 'G' || *eptr == 'g') {
    if (val >= 2) return -1;
    val *= 1 * 1024 * 1024 * 1024;
    eptr++;
  } else if (*eptr == 'M' || *eptr == 'm') {
    if (val >= 2 * 1024) return -1;
    val *= 1 * 1024 * 1024;
    eptr++;
  } else if (*eptr == 'K' || *eptr == 'k') {
    if (val >= 2 * 1024 * 1024) return -1;
    val *= 1 * 1024;
    eptr++;
  }
  if (*eptr) return -1;
  *p_size = (size_t) val;
  return 0;
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
        struct http_request_info *phr,
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
    fprintf(out_f, "<style type=\"text/css\" id=\"generatedStyles\"></style>\n");
  }

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

void
ss_write_html_header(
        FILE *out_f,
        struct http_request_info *phr,
        const unsigned char *title,
        int use_dojo,
        const unsigned char *body_class)
{
  write_html_header(out_f, phr, title, use_dojo, body_class);
}

static const char fancy_priv_footer[] =
"<hr/>%s</body></html>\n";
static void
write_html_footer(FILE *out_f)
{
  fprintf(out_f, fancy_priv_footer, get_copyright(0));
}

void
ss_write_html_footer(FILE *out_f)
{
  write_html_footer(out_f);
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
        struct http_request_info *phr,
        const char *format,
        ...)
  __attribute__((format(printf, 3, 4)));
static void
refresh_page(
        FILE *out_f,
        struct http_request_info *phr,
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

  fprintf(out_f, "Location: %s\n", url);
  if (phr->client_key) {
    fprintf(out_f, "Set-Cookie: EJSID=%016llx; Path=/\n", phr->client_key);
  }
  putc('\n', out_f);
}

typedef int (*handler_func_t)(FILE *log_f, FILE *out_f, struct http_request_info *phr);

static int
cmd_cnts_details(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct sid_state *ss = phr->ss;

  if (ss->edited_cnts) FAIL(SSERV_ERR_CONTEST_EDITED);

 cleanup:
  return retval;
}

static int
cmd_edited_cnts_back(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  refresh_page(out_f, phr, NULL);
  return 0;
}

static int
cmd_edited_cnts_continue(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int new_edit = -1;

  if (hr_cgi_param_int(phr, "new_edit", &new_edit) >= 0 && new_edit == 1) {
    refresh_page(out_f, phr, "action=%d&op=%d", SSERV_CMD_HTTP_REQUEST,
                 SSERV_CMD_EDIT_CONTEST_PAGE_2);
  } else {
    refresh_page(out_f, phr, "action=%d", SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE);
  }
  return 0;
}

static int
cmd_edited_cnts_start_new(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int contest_id = 0;
  int new_edit = -1;

  hr_cgi_param_int_opt(phr, "new_edit", &new_edit, 0);
  if (hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0) < 0
      || contest_id < 0) contest_id = 0;
  super_serve_clear_edited_contest(phr->ss);
  if (new_edit == 1) {
    if (!contest_id) {
      refresh_page(out_f, phr, "action=%d&op=%d",
                   SSERV_CMD_HTTP_REQUEST, SSERV_CMD_CREATE_NEW_CONTEST_PAGE);
    } else {
      refresh_page(out_f, phr, "action=%d&op=%d&contest_id=%d",
                   SSERV_CMD_HTTP_REQUEST, SSERV_CMD_EDIT_CONTEST_PAGE,
                   contest_id);
    }
  } else {
    if (!contest_id) {
      refresh_page(out_f, phr, "action=%d", SSERV_CMD_CREATE_CONTEST_PAGE);
    } else {
      refresh_page(out_f, phr, "action=%d&contest_id=%d",
                   SSERV_CMD_CNTS_START_EDIT_ACTION, contest_id);
    }
  }

  return 0;
}

// forget the contest editing from the other session and return
// to the main page
// all errors are silently ignored
static int
cmd_locked_cnts_forget(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  struct sid_state *ss;
  int contest_id = -1;

  if (phr->ss->edited_cnts)
    goto done;
  if (hr_cgi_param_int(phr, "contest_id", &contest_id) < 0 || contest_id <= 0)
    goto done;
  if (!(ss = super_serve_sid_state_get_cnts_editor_nc(contest_id)))
    goto done;
  if (ss->user_id != phr->user_id)
    goto done;
  super_serve_clear_edited_contest(ss);

 done:;
  refresh_page(out_f, phr, NULL);
  return 0;
}

// move the editing information to this session and continue editing
// all errors are silently ignored
static int
cmd_locked_cnts_continue(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  struct sid_state *ss;
  int contest_id = 0;
  int new_edit = -1;

  if (phr->ss->edited_cnts)
    goto top_level;
  if (hr_cgi_param_int(phr, "contest_id", &contest_id) < 0 || contest_id <= 0)
    goto top_level;
  if (!(ss = super_serve_sid_state_get_cnts_editor_nc(contest_id)))
    goto top_level;
  if (ss->user_id != phr->user_id)
    goto top_level;

  super_serve_move_edited_contest(phr->ss, ss);

  if (hr_cgi_param_int(phr, "new_edit", &new_edit) >= 0 && new_edit == 1) {
    refresh_page(out_f, phr, "action=%d&op=%d", SSERV_CMD_HTTP_REQUEST,
                 SSERV_CMD_EDIT_CONTEST_PAGE_2);
  } else {
    refresh_page(out_f, phr, "action=%d", SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE);
  }
  return 0;

 top_level:;
  refresh_page(out_f, phr, NULL);
  return 0;
}

static const unsigned char head_row_attr[] =
  " bgcolor=\"#dddddd\"";
static const unsigned char * const form_row_attrs[]=
{
  " bgcolor=\"#e4e4e4\"",
  " bgcolor=\"#eeeeee\"",
};

void
ss_dojo_button(
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
  NS_GLOBAL,
  NS_LANGUAGE,
  NS_PROBLEM,
};

#define push(val) do { if (sp >= ST_SIZE) goto stack_overflow; st[sp++] = (val); } while (0)
#define pop(var) do { if (!sp) goto stack_undeflow; (var) = st[--sp]; } while (0)

static int
eval_check_expr(
        struct http_request_info *phr,
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
  const void *f_ptr;
  char *eptr;
  const unsigned char *func = __FUNCTION__;

  if (!str) return 0;
  len = strlen(str);
  if (!len) return 0;
  if (len >= 2048) {
    fprintf(stderr, "%s: expression is too long\n", func);
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

      val2 = 0;
      if (!strncmp(buf, "Contest.", 8)) {
        if (!(f_id = contest_desc_lookup_field(buf + 8)))
          goto invalid_field;
        f_type = contest_desc_get_type(f_id);
        if (!(f_ptr = contest_desc_get_ptr(phr->ss->edited_cnts, f_id)))
          goto invalid_field;
      } else if (!strncmp(buf, "SidState.", 9)) {
        if (!(f_id = ss_sid_state_lookup_field(buf + 9)))
          goto invalid_field;
        f_type = ss_sid_state_get_type(f_id);
        if (!(f_ptr = ss_sid_state_get_ptr(phr->ss, f_id)))
          goto invalid_field;
      } else if (!strncmp(buf, "Global.", 7)) {
        if (!(f_id = cntsglob_lookup_field(buf + 7)))
          goto invalid_field;
        f_type = cntsglob_get_type(f_id);
        if (!(f_ptr = cntsglob_get_ptr(phr->ss->global, f_id)))
          goto invalid_field;
      } else if (!strncmp(buf, "Language.", 9)) {
        if (!(f_id = cntslang_lookup_field(buf + 9)))
          goto invalid_field;
        f_type = cntslang_get_type(f_id);
        if (!(f_ptr = cntslang_get_ptr(phr->ss->cur_lang, f_id)))
          goto invalid_field;
      } else if (!strncmp(buf, "Problem.", 8)) {
        if (!(f_id = cntsprob_lookup_field(buf + 8)))
          goto invalid_field;
        f_type = cntsprob_get_type(f_id);
        if (!(f_ptr = cntsprob_get_ptr(phr->ss->cur_prob, f_id)))
          goto invalid_field;
      } else if (!strcmp(buf, "SCORE_ACM")) {
        f_type = 0;
        val2 = SCORE_ACM;
      } else if (!strcmp(buf, "SCORE_KIROV")) {
        f_type = 0;
        val2 = SCORE_KIROV;
      } else if (!strcmp(buf, "SCORE_OLYMPIAD")) {
        f_type = 0;
        val2 = SCORE_OLYMPIAD;
      } else if (!strcmp(buf, "SCORE_MOSCOW")) {
        f_type = 0;
        val2 = SCORE_MOSCOW;
      } else goto invalid_field;

      val1 = 0;
      switch (f_type) {
      case 0:
        val1 = val2;
        break;
      case 'b':
        //if (*(unsigned char*) f_ptr) val1 = 1;
        val1 = *(unsigned char*) f_ptr;
        break;
      case 'B':
        //if (*(int*) f_ptr) val1 = 1;
        val1 = *(int*) f_ptr;
        break;
      case 's':
        if (*(unsigned char **) f_ptr) val1 = 1;
        break;
      case 'S':
        {
          const unsigned char *s = (const unsigned char*) f_ptr;
          if (*s && *s != 1) val1 = 1;
        }
        break;
      case 't':
        //if (*(time_t*) f_ptr) val1 = 1;
        val1 = *(time_t*) f_ptr;
        break;
      case 'i':
        //if (*(int*) f_ptr) val1 = 1;
        val1 = *(int*) f_ptr;
        break;
      default:
        fprintf(stderr, "%s: invalid type\n", func);
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
        fprintf(stderr, "%s: invalid value\n", func);
        return -1;
      }
      push(val1);
      continue;
    }
    switch (*p) {
    case '=':
      if (p[1] != '=') {
        fprintf(stderr, "%s: invalid operation\n", func);
        return -1;
      }
      p++;
      pop(val2);
      pop(val1);
      push(val1 == val2);
      break;
    case '!':
      if (p[1] == '=') {
        p++;
        pop(val2);
        pop(val1);
        push(val1 != val2);
      } else {
        pop(val1);
        push(!val1);
      }
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
    case '>':
      pop(val2);
      pop(val1);
      if (p[1] == '=') {
        p++;
        push(val1 >= val2);
      } else {
        push(val1 > val2);
      }
      break;
    case '<':
      pop(val2);
      pop(val1);
      if (p[1] == '=') {
        p++;
        push(val1 <= val2);
      } else {
        push(val1 < val2);
      }
      break;
    default:
      fprintf(stderr, "%s: invalid operation <%c>\n", func, *p);
      return -1;
    }
    p++;
  }
  if (!sp) {
    fprintf(stderr, "%s: no expression\n", func);
    return -1;
  }
  if (sp > 1) {
    fprintf(stderr, "%s: incomplete expression\n", func);
    return -1;
  }
  return st[0];

 stack_overflow:
  fprintf(stderr, "%s: stack overflow\n", func);
  return -1;

 stack_undeflow:
  fprintf(stderr, "%s: stack underflow\n", func);
  return -1;

 invalid_field:
  fprintf(stderr, "%s: invalid field %s\n", func, buf);
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
static const struct cnts_edit_info cnts_edit_info[] =
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
  { NS_CONTEST, CNTS_register_subject, 's', 1, 1, 1, 1, 0, "Registration letter subject", "Registration letter subject", 0 },
  { NS_CONTEST, CNTS_register_subject_en, 's', 1, 1, 1, 1, 0, "Registration letter subject (En)", "Registration letter subject (En)", 0 },
  { NS_CONTEST, CNTS_register_email_file, 'e', 1, 1, 1, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "Registration letter template file", "Registration letter template file", 0 },
  { 0, 0, '-', 0, 0, 0, 0, 0, "Participation Settings", 0, 0 },
  { NS_CONTEST, CNTS_sched_time, 't', 1, 1, 0, 1, 0, "Scheduled start time", "Scheduled start time", 0 },
  { NS_CONTEST, CNTS_open_time, 't', 1, 1, 0, 1, 0, "Virtual contest open time", "Virtual contest open time", 0 },
  { NS_CONTEST, CNTS_close_time, 't', 1, 1, 0, 1, 0, "Virtual contest close time", "Virtual contest close time", 0 },
  { NS_CONTEST, CNTS_team_url, 's', 1, 1, 1, 1, 0, "URL for the client CGI program", "URL for the client CGI program", 0 },
  { NS_CONTEST, CNTS_standings_url, 's', 1, 1, 1, 1, 0, "URL for the current standings", "URL for the current standings", 0 },
  { NS_CONTEST, CNTS_problems_url, 's', 1, 1, 1, 1, 0, "URL for the problemset", "URL for the problemset", 0 },
  { NS_CONTEST, CNTS_logo_url, 's', 1, 1, 1, 1, 0, "URL for the contest logo", "URL for the contest logo", 0 },
  { NS_CONTEST, CNTS_css_url, 's', 1, 1, 1, 1, 0, "URL for the contest CSS", "URL for the contest CSS", 0 },
  { 0, 0, '-', 0, 0, 0, 0, 0, "Contest Management", 0, 0 },
  { NS_CONTEST, CNTS_managed, 'y', 1, 0, 0, 0, 0, "Enable the contest service", "Enable the contest service", 0 },
  { NS_CONTEST, CNTS_run_managed, 'y', 1, 0, 0, 0, 0, "Enable the run service", "Enable the run service", 0 },
  { NS_CONTEST, CNTS_old_run_managed, 'y', 1, 0, 0, 0, 0, "Run service compatibility mode", "Run server compatibility mode", 0 },
  { NS_CONTEST, CNTS_closed, 'y', 1, 0, 0, 0, 0, "Close the contest for participants", "Close the contest for participants", 0 },
  { NS_CONTEST, CNTS_invisible, 'y', 1, 0, 0, 0, 0, "Hide the contest for administrators", "Hide the contest for administrators", 0 },

  { NS_SID_STATE, SSSS_show_access_rules, '-', 1, 0, 0, 0, SSERV_CMD_COPY_ALL_ACCESS_RULES_PAGE, "IP Access Rules", 0, 0 },
  { NS_CONTEST, CNTS_register_access, 'p', 0, 0, 0, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "<tt>register</tt> access rules", "Access rules for the register program", "SidState.show_access_rules" },
  { NS_CONTEST, CNTS_users_access, 'p', 0, 0, 0, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "<tt>users</tt> access rules", "Access rules for the users program", "SidState.show_access_rules" },
  { NS_CONTEST, CNTS_team_access, 'p', 0, 0, 0, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "<tt>client</tt> access rules", "Access rules for the client program", "SidState.show_access_rules" },
  { NS_CONTEST, CNTS_judge_access, 'p', 0, 0, 0, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "<tt>judge</tt> access rules", "Access rules for the judge program", "SidState.show_access_rules" },
  { NS_CONTEST, CNTS_master_access, 'p', 0, 0, 0, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "<tt>master</tt> access rules", "Access rules for the master program", "SidState.show_access_rules" },
  { NS_CONTEST, CNTS_serve_control_access, 'p', 0, 0, 0, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "<tt>serve-control</tt> access rules", "Access rules for the serve-control program", "SidState.show_access_rules" },

  { NS_SID_STATE, SSSS_show_permissions, '-', 1, 0, 0, 0, SSERV_CMD_COPY_ALL_PRIV_USERS_PAGE, "Administrators, Judges, etc", 0, 0 },
  { 0, 0, 130, 0, 0, 0, 0, 0, 0, 0, 0, },
  { NS_SID_STATE, SSSS_show_form_fields, '-', 1, 0, 0, 0, 0, "Registration Form Fields", 0, 0 },
  { 0, 0, 131, 0, 0, 0, 0, 0, 0, 0, 0, },

  { NS_SID_STATE, SSSS_show_html_headers, '-', 1, 0, 0, 0, 0, "HTML Headers and Footers", 0, 0 },
  { NS_CONTEST, CNTS_users_header_file, 'e', 1, 1, 1, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "HTML header file for <tt>users</tt>", "HTML header file for the users program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_users_footer_file, 'e', 1, 1, 1, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "HTML footer file for <tt>users</tt>", "HTML footer file for the users program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_register_header_file, 'e', 1, 1, 1, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "HTML header file for <tt>register</tt>", "HTML header file for the register program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_register_footer_file, 'e', 1, 1, 1, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "HTML footer file for <tt>register</tt>", "HTML footer file for the register program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_team_header_file, 'e', 1, 1, 1, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "HTML header file for <tt>client</tt>", "HTML header file for the client program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_team_menu_1_file, 'e', 1, 1, 1, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "HTML menu 1 file for <tt>client</tt>", "HTML menu 1 file for the client program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_team_menu_2_file, 'e', 1, 1, 1, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "HTML menu 2 file for <tt>client</tt>", "HTML menu 2 file for the client program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_team_menu_3_file, 'e', 1, 1, 1, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "HTML menu 3 file for <tt>client</tt>", "HTML menu 3 file for the client program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_team_separator_file, 'e', 1, 1, 1, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "HTML separator file for <tt>client</tt>", "HTML separator file for the client program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_team_footer_file, 'e', 1, 1, 1, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "HTML footer file for <tt>client</tt>", "HTML footer file for the client program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_priv_header_file, 'e', 1, 1, 1, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "HTML header file for <tt>master</tt>", "HTML header file for the master program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_priv_footer_file, 'e', 1, 1, 1, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "HTML footer file for <tt>master</tt>", "HTML footer file for the master program", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_copyright_file, 'e', 1, 1, 1, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "HTML copyright notice file", "HTML copyright notice file", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_welcome_file, 'e', 1, 1, 1, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "HTML welcome message file", "HTML welcome message file", "SidState.show_html_headers" },
  { NS_CONTEST, CNTS_reg_welcome_file, 'e', 1, 1, 1, 1, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, "HTML registration welcome message file", "HTML registration welcome message file", "SidState.show_html_headers" },

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
  { NS_CONTEST, CNTS_user_contest, 's',  1, 1, 1, 1, 0, "Contest number to share users from", "Contest number to share users from", "SidState.advanced_view" },
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

/*
  int is_editable;
  int is_clearable;
  int dojo_inline_edit;
  int is_nullable;
  int has_details;
*/
static const struct cnts_edit_info cnts_global_info[] =
{
  { NS_GLOBAL, CNTSGLOB_score_system, 132, 1, 0, 0, 0, 0, "Scoring system", "Scoring system", 0 },
  { NS_GLOBAL, CNTSGLOB_contest_time, 'u', 1, 1, 1, 1, 0, "Contest duration (HH:MM)", "Contest duration (HH:MM)", 0 },
  { NS_GLOBAL, CNTSGLOB_contest_finish_time, 't', 1, 1, 0, 1, 0, "Contest finish time", "Contest finish time", "Global.contest_time 0 <=" },
  { NS_GLOBAL, CNTSGLOB_board_fog_time, 'u', 1, 1, 1, 1, 0, "Standings freeze time (HH:MM)", "Standings freeze time (before contest finish)", "Global.contest_time 0 >" },
  { NS_GLOBAL, CNTSGLOB_board_unfog_time, 'u', 1, 1, 1, 1, 0, "Standings unfreeze time (HH:MM)", "Standings unfreeze time (after contest finish)", "Global.contest_time 0 > Global.board_fog_time 0 > &&" },
  { NS_SID_STATE, SSSS_disable_compilation_server, 133, 1, 0, 0, 0, 0, "Use the main compilation server", 0, 0 },
  { NS_SID_STATE, SSSS_enable_win32_languages, 143, 1, 0, 0, 0, 0, "Enable Win32 languages", 0, 0 },
  { NS_GLOBAL, CNTSGLOB_secure_run, 'Y', 1, 0, 0, 0, 0, "Run programs securely", "Run programs securely (needs kernel patch)", 0 },
  { NS_GLOBAL, CNTSGLOB_enable_memory_limit_error, 'Y', 1, 0, 0, 0, 0, "Enable support for MemoryLimit error", "Enable support for MemoryLimit error (needs kernel patch)", 0 },
  { NS_GLOBAL, CNTSGLOB_detect_violations, 'Y', 1, 0, 0, 0, 0, "Detect security violations", "Detect security violations (needs kernel patch)", 0 },
  { NS_GLOBAL, CNTSGLOB_enable_max_stack_size, 'Y', 1, 0, 0, 0, 0, "Assume max_stack_size == max_vm_size", 0, 0 },
  { NS_GLOBAL, CNTSGLOB_standings_locale, 134, 1, 1, 0, 1, 0, "Standings locale", 0, 0 },
  { NS_GLOBAL, CNTSGLOB_checker_locale, 's', 1, 1, 1, 1, 0, "Checker locale", 0, 0 },
  { NS_GLOBAL, CNTSGLOB_enable_32bit_checkers, 'Y', 1, 0, 0, 0, 0, "Compile 32-bit checkers on 64-bit platforms", 0, 0 },

  { NS_SID_STATE, SSSS_show_global_1, '-', 1, 0, 0, 0, 0, "Contestant's capabilities", 0, 0 },
  { NS_GLOBAL, CNTSGLOB_team_enable_src_view, 'Y', 1, 0, 0, 0, 0, "Contestants may view their source code", 0, "SidState.show_global_1" },
  { NS_GLOBAL, CNTSGLOB_disable_failed_test_view, 'Y', 1, 0, 0, 0, 0, "The number of the failed test is not shown", 0, "SidState.show_global_1 Global.score_system SCORE_ACM == Global.score_system SCORE_MOSCOW == || &&" },
  { NS_GLOBAL, CNTSGLOB_team_enable_rep_view, 'Y', 1, 0, 0, 0, 0, "Contestants may view testing protocols", 0, "SidState.show_global_1" },
  { NS_GLOBAL, CNTSGLOB_team_enable_ce_view, 'Y', 1, 0, 0, 0, 0, "Contestants may view compilation errors", 0, "SidState.show_global_1 Global.team_enable_rep_view ! &&" },
  { NS_GLOBAL, CNTSGLOB_team_show_judge_report, 'Y', 1, 0, 0, 0, 0, "Contestants may view FULL testing protocols", 0, "SidState.show_global_1 Global.team_enable_rep_view &&" },
  { NS_GLOBAL, CNTSGLOB_report_error_code, 'Y', 1, 0, 0, 0, 0, "Contestants may view process exit codes", 0, "SidState.show_global_1 Global.team_enable_rep_view && Global.team_show_judge_report &&" },
  { NS_GLOBAL, CNTSGLOB_disable_clars, 'Y', 1, 0, 0, 0, 0, "Clarification requests and messages from judges are disabled", 0, "SidState.show_global_1" },
  { NS_GLOBAL, CNTSGLOB_disable_team_clars, 'Y', 1, 0, 0, 0, 0, "Clarification requests from contestants are disabled", 0, "SidState.show_global_1 Global.disable_clars ! &&" },
  { NS_GLOBAL, CNTSGLOB_enable_eoln_select, 'Y', 1, 0, 0, 0, 0, "Participants may select desired EOLN type", 0, "SidState.show_global_1" },
  { NS_GLOBAL, CNTSGLOB_disable_submit_after_ok, 'Y', 1, 0, 0, 0, 0, "Disable submits to already solved problems", 0, "SidState.show_global_1" },
  { NS_GLOBAL, CNTSGLOB_ignore_compile_errors, 'Y', 1, 0, 0, 0, 0, "Do not penalize compilation errors", 0, "SidState.show_global_1" },
  { NS_GLOBAL, CNTSGLOB_ignore_duplicated_runs, 'Y', 1, 0, 0, 0, 0, "Do not allow duplicate submissions", 0, "SidState.show_global_1" },
  { NS_GLOBAL, CNTSGLOB_show_deadline, 'Y', 1, 0, 0, 0, 0, "Show problem submit deadline", 0, "SidState.show_global_1" },
  { NS_GLOBAL, CNTSGLOB_enable_printing, 'Y', 1, 0, 0, 0, 0, "Enable printing of submissions by contestants", 0, "SidState.show_global_1" },
  { NS_GLOBAL, CNTSGLOB_disable_banner_page, 'Y', 1, 0, 0, 0, 0, "Disable banner page in printouts", 0, "SidState.show_global_1 Global.enable_printing &&" },
  { NS_GLOBAL, CNTSGLOB_printout_uses_login, 'Y', 1, 0, 0, 0, 0, "Show login rather than name in printouts", 0, "SidState.show_global_1 Global.enable_printing &&" },
  { NS_GLOBAL, CNTSGLOB_prune_empty_users, 'Y', 1, 0, 0, 0, 0, "Do not show contestants with no submits in the standings", 0, "SidState.show_global_1" },
  { NS_GLOBAL, CNTSGLOB_enable_full_archive, 'Y', 1, 0, 0, 0, 0, "Store the full output in the archive", 0, "SidState.show_global_1" },
  { NS_GLOBAL, CNTSGLOB_always_show_problems, 'Y', 1, 0, 0, 0, 0, "Problem statements are available before the contest start", 0, "SidState.show_global_1" },
  { NS_GLOBAL, CNTSGLOB_disable_user_standings, 'Y', 1, 0, 0, 0, 0, "Disable standings on the contestant's client pages", 0, "SidState.show_global_1" },
  { NS_GLOBAL, CNTSGLOB_disable_language, 'Y', 1, 0, 0, 0, 0, "Do not show the language column to contestants", 0, "SidState.show_global_1" },
  { NS_GLOBAL, CNTSGLOB_problem_navigation, 'Y', 1, 0, 0, 0, 0, "Tabbed problem navigation", 0, "SidState.show_global_1" },
  { NS_GLOBAL, CNTSGLOB_vertical_navigation, 'Y', 1, 0, 0, 0, 0, "Place problem tabs vertically", 0, "SidState.show_global_1 Global.problem_navigation &&" },
  { NS_GLOBAL, CNTSGLOB_disable_virtual_start, 'Y', 1, 0, 0, 0, 0, "Disable virtual start button for contestants", 0, "SidState.show_global_1 Global.is_virtual &&" },
  { NS_GLOBAL, CNTSGLOB_disable_virtual_auto_judge, 'Y', 1, 0, 0, 0, 0, "Disable auto-judging after virtual olympiad is over", 0, "SidState.show_global_1 Global.score_system SCORE_OLYMPIAD == && Global.is_virtual &&" },
  { NS_GLOBAL, CNTSGLOB_enable_auto_print_protocol, 'Y', 1, 0, 0, 0, 0, "Enable automatic printing of olympiad protocols", 0, "SidState.show_global_1 Global.score_system SCORE_OLYMPIAD == &&" },
  { NS_GLOBAL, CNTSGLOB_notify_clar_reply, 'Y', 1, 0, 0, 0, 0, "Enable e-mail clar notifications", 0, "SidState.show_global_1 Global.disable_clars ! &&" },
  { NS_GLOBAL, CNTSGLOB_notify_status_change, 'Y', 1, 0, 0, 0, 0, "Enable e-mail status change notifications", 0, "SidState.show_global_1" },
  { NS_GLOBAL, CNTSGLOB_disable_auto_refresh, 'Y', 1, 0, 0, 0, 0, "Disable auto-refreshing", 0, "SidState.show_global_1" },

  { NS_SID_STATE, SSSS_show_global_2, '-', 1, 0, 0, 0, 0, "Files and directories", 0, 0 },
  { NS_GLOBAL, CNTSGLOB_advanced_layout, 'Y', 1, 0, 0, 0, 0, "Advanced layout of problem files", 0, "SidState.show_global_2" },
  { NS_GLOBAL, CNTSGLOB_uuid_run_store, 'Y', 1, 0, 0, 0, 0, "Use UUID instead of runid to store runs", 0, "SidState.show_global_2" },
  { NS_GLOBAL, CNTSGLOB_test_dir, 'S', 1, 1, 1, 1, 0, "Directory for tests", "Directory for tests (relative to the contest configuration directory)", "SidState.show_global_2" },
  { NS_GLOBAL, CNTSGLOB_corr_dir, 'S', 1, 1, 1, 1, 0, "Directory for correct answers", "Directory for correct answers (relative to the contest configuration directory)", "SidState.show_global_2" },
  { NS_GLOBAL, CNTSGLOB_info_dir, 'S', 1, 1, 1, 1, 0, "Directory for test information files", "Directory for test information files (relative to the contest configuration directory)", "SidState.show_global_2" },
  { NS_GLOBAL, CNTSGLOB_tgz_dir, 'S', 1, 1, 1, 1, 0, "Directory for test working dir archives", "Directory for test working dir archives (relative to the contest configuration directory)", "SidState.show_global_2" },
  { NS_GLOBAL, CNTSGLOB_checker_dir, 'S', 1, 1, 1, 1, 0, "Directory for checkers", "Directory for checkers (relative to the contest configuration directory)", "SidState.show_global_2" },
  { NS_GLOBAL, CNTSGLOB_statement_dir, 'S', 1, 1, 1, 1, 0, "Directory for problem statements", "Directory for problem statements (relative to the contest configuration directory)", "SidState.show_global_2" },
  { NS_GLOBAL, CNTSGLOB_plugin_dir, 'S', 1, 1, 1, 1, 0, "Directory for the problem plugins", "Directory for problem plugins (relative to the contest configuration directory)", "SidState.show_global_2" },
  { NS_GLOBAL, CNTSGLOB_contest_start_cmd, 'S', 1, 1, 1, 1, 0, "The contest start script", 0, "SidState.show_global_2" },
  { NS_GLOBAL, CNTSGLOB_contest_stop_cmd, 'S', 1, 1, 1, 1, 0, "The contest stop script", 0, "SidState.show_global_2" },
  { NS_GLOBAL, CNTSGLOB_description_file, 'S', 1, 1, 1, 1, 0, "The contest description file", 0, "SidState.show_global_2" },

  { NS_SID_STATE, SSSS_show_global_3, '-', 1, 0, 0, 0, 0, "Contestants' quotas", 0, 0 },
  { NS_GLOBAL, CNTSGLOB_max_run_size, 'z', 1, 0, 1, 1, 0, "Maximum size of one submit", 0, "SidState.show_global_3" },
  { NS_GLOBAL, CNTSGLOB_max_run_total, 'z', 1, 0, 1, 1, 0, "Maximum total size of all submits", 0, "SidState.show_global_3" },
  { NS_GLOBAL, CNTSGLOB_max_run_num, 'd', 1, 0, 1, 1, 0, "Maximum number of submits", 0, "SidState.show_global_3" },
  { NS_GLOBAL, CNTSGLOB_max_clar_size, 'z', 1, 0, 1, 1, 0, "Maximum size of one clarification request", 0, "SidState.show_global_3 Global.disable_clars ! && Global.disable_team_clars ! &&" },
  { NS_GLOBAL, CNTSGLOB_max_clar_total, 'z', 1, 0, 1, 1, 0, "Maximum total size of all clars", 0, "SidState.show_global_3 Global.disable_clars ! && Global.disable_team_clars ! &&" },
  { NS_GLOBAL, CNTSGLOB_max_clar_num, 'd', 1, 0, 1, 1, 0, "Maximum number of clars", 0, "SidState.show_global_3 Global.disable_clars ! && Global.disable_team_clars ! &&" },
  { NS_GLOBAL, CNTSGLOB_team_page_quota, 'd', 1, 0, 1, 1, 0, "Maximum number of prited pages", 0, "SidState.show_global_3 Global.enable_printing &&" },

  { NS_SID_STATE, SSSS_show_global_4, '-', 1, 0, 0, 0, 0, "Standing files and URLs", 0, 0 },
  { NS_GLOBAL, CNTSGLOB_team_info_url, 'S', 1, 1, 1, 1, 0, "URL for contestant information", 0, "SidState.show_global_4" },
  { NS_GLOBAL, CNTSGLOB_prob_info_url, 'S', 1, 1, 1, 1, 0, "URL for problem statement", 0, "SidState.show_global_4" },
  { NS_GLOBAL, CNTSGLOB_standings_file_name, 'S', 1, 1, 1, 1, 0, "Primary standings file name", 0, "SidState.show_global_4" },
  { NS_GLOBAL, CNTSGLOB_users_on_page, 'd', 1, 1, 1, 1, 0, "Number of users on a standings page", 0, "SidState.show_global_4" },
  { NS_GLOBAL, CNTSGLOB_stand_header_file, 'S', 1, 1, 1, 1, 0, "HTML header file for primary standings", 0, "SidState.show_global_4" },
  { NS_GLOBAL, CNTSGLOB_stand_footer_file, 'S', 1, 1, 1, 1, 0, "HTML footer file for primary standings", 0, "SidState.show_global_4" },
  { NS_GLOBAL, CNTSGLOB_stand_symlink_dir, 'S', 1, 1, 1, 1, 0, "Symlink directory for primary standings", 0, "SidState.show_global_4" },
  { NS_GLOBAL, CNTSGLOB_stand_ignore_after, 't', 1, 1, 0, 1, 0, "Ignore submissions after", 0, "SidState.show_global_4" },
  { NS_SID_STATE, SSSS_enable_stand2, 135, 1, 0, 0, 0, 0, "Enable secondary standings table", 0, "SidState.show_global_4" },
  { NS_GLOBAL, CNTSGLOB_stand2_file_name, 'S', 1, 1, 1, 1, 0, "Secondary standings file name", 0, "SidState.show_global_4 SidState.enable_stand2 &&" },
  { NS_GLOBAL, CNTSGLOB_stand2_header_file, 'S', 1, 1, 1, 1, 0, "HTML header file for secondary standings", 0, "SidState.show_global_4 SidState.enable_stand2 &&" },
  { NS_GLOBAL, CNTSGLOB_stand2_footer_file, 'S', 1, 1, 1, 1, 0, "HTML footer file for secondary standings", 0, "SidState.show_global_4 SidState.enable_stand2 &&" },
  { NS_GLOBAL, CNTSGLOB_stand2_symlink_dir, 'S', 1, 1, 1, 1, 0, "Symlink directory for secondary standings", 0, "SidState.show_global_4 SidState.enable_stand2 &&" },
  { NS_SID_STATE, SSSS_enable_plog, 135, 1, 0, 0, 0, 0, "Enable public submission log", 0, "SidState.show_global_4" },
  { NS_GLOBAL, CNTSGLOB_plog_file_name, 'S', 1, 1, 1, 1, 0, "Public submission log file name", 0, "SidState.show_global_4 SidState.enable_plog &&" },
  { NS_GLOBAL, CNTSGLOB_plog_header_file, 'S', 1, 1, 1, 1, 0, "HTML header file for public submission log", 0, "SidState.show_global_4 SidState.enable_plog &&" },
  { NS_GLOBAL, CNTSGLOB_plog_footer_file, 'S', 1, 1, 1, 1, 0, "HTML footer file for public submission log", 0, "SidState.show_global_4 SidState.enable_plog &&" },
  { NS_GLOBAL, CNTSGLOB_plog_symlink_dir, 'S', 1, 1, 1, 1, 0, "Symlink directory for public submission log", 0, "SidState.show_global_4 SidState.enable_plog &&" },
  { NS_GLOBAL, CNTSGLOB_plog_update_time, 'd', 1, 1, 1, 1, 0, "Public submission log update interval", 0, "SidState.show_global_4 SidState.enable_plog &&" },
  { NS_GLOBAL, CNTSGLOB_external_xml_update_time, 'd', 1, 1, 1, 1, 0, "External XML log update interval", 0, "SidState.show_global_4" },
  { NS_GLOBAL, CNTSGLOB_internal_xml_update_time, 'd', 1, 1, 1, 1, 0, "Internal XML log update interval", 0, "SidState.show_global_4" },

  { NS_SID_STATE, SSSS_show_global_5, '-', 1, 0, 0, 0, 0, "Standings table attributes", 0, 0 },
  { NS_GLOBAL, CNTSGLOB_stand_fancy_style, 'Y', 1, 0, 0, 0, 0, "Use fancy decorations", 0, "SidState.show_global_5" },
  { NS_GLOBAL, CNTSGLOB_stand_success_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for \"Last success\"", 0, "SidState.show_global_5" },
  { NS_GLOBAL, CNTSGLOB_stand_table_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for standings table", 0, "SidState.show_global_5" },
  { NS_GLOBAL, CNTSGLOB_stand_row_attr, 'x', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_GLOBAL_FIELD_DETAIL_PAGE, "Standings row attributes", 0, "SidState.show_global_5" },
  { NS_GLOBAL, CNTSGLOB_stand_place_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for the \"Place\" column", 0, "SidState.show_global_5" },
  { NS_GLOBAL, CNTSGLOB_stand_team_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for the \"User name\" column", 0, "SidState.show_global_5" },
  { NS_GLOBAL, CNTSGLOB_stand_prob_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for the \"Problem\" columns", 0, "SidState.show_global_5" },
  { NS_GLOBAL, CNTSGLOB_stand_solved_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for the \"Solved\" column", 0, "SidState.show_global_5" },
  { NS_GLOBAL, CNTSGLOB_stand_score_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for the \"Score\" column", 0, "SidState.show_global_5 Global.score_system SCORE_KIROV == Global.score_system SCORE_OLYMPIAD == || &&" },
  { NS_GLOBAL, CNTSGLOB_stand_penalty_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for the \"Penalty\" column", 0, "SidState.show_global_5 Global.score_system SCORE_ACM == Global.score_system SCORE_MOSCOW == || &&" },
  { NS_GLOBAL, CNTSGLOB_stand_use_login, 'Y', 1, 0, 0, 0, 0, "Use user login instead of user name", 0, "SidState.show_global_5" },
  { NS_GLOBAL, CNTSGLOB_stand_show_ok_time, 'Y', 1, 0, 0, 0, 0, "Show success time in standings", 0, "SidState.show_global_5" },
  { NS_GLOBAL, CNTSGLOB_stand_show_att_num, 'Y', 1, 0, 0, 0, 0, "Show number of attempts in the standings", 0, "SidState.show_global_5 Global.score_system SCORE_KIROV == Global.score_system SCORE_OLYMPIAD == || &&" },
  { NS_GLOBAL, CNTSGLOB_stand_sort_by_solved, 'Y', 1, 0, 0, 0, 0, "Sort participants by the number of solved problems first", 0, "SidState.show_global_5 Global.score_system SCORE_KIROV == Global.score_system SCORE_OLYMPIAD == || &&" },
  { NS_GLOBAL, CNTSGLOB_stand_collate_name, 'Y', 1, 0, 0, 0, 0, "Collate the standings by the user name", 0, "SidState.show_global_5 Global.score_system SCORE_KIROV == Global.score_system SCORE_OLYMPIAD == || &&" },
  { NS_GLOBAL, CNTSGLOB_stand_enable_penalty, 'Y', 1, 0, 0, 0, 0, "Enable time penalties", 0, "SidState.show_global_5 Global.score_system SCORE_KIROV == Global.score_system SCORE_OLYMPIAD == || &&" },
  { NS_GLOBAL, CNTSGLOB_ignore_success_time, 'Y', 1, 0, 0, 0, 0, "Ignore success time in penalty calculations", 0, "SidState.show_global_5 Global.score_system SCORE_ACM == Global.score_system SCORE_MOSCOW == || &&" },
  { NS_GLOBAL, CNTSGLOB_stand_time_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for the success time", 0, "SidState.show_global_5 Global.stand_show_ok_time &&" },
  { NS_GLOBAL, CNTSGLOB_stand_fail_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for \"Check failed\" cells", 0, "SidState.show_global_5" },
  { NS_GLOBAL, CNTSGLOB_stand_trans_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for transient cells", 0, "SidState.show_global_5" },
  { NS_GLOBAL, CNTSGLOB_stand_disq_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for disqualified cells", 0, "SidState.show_global_5" },
  { NS_GLOBAL, CNTSGLOB_stand_self_row_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for the participant's row", 0, "SidState.show_global_5 Global.is_virtual &&" },
  { NS_GLOBAL, CNTSGLOB_stand_v_row_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for virtual participant's rows", 0, "SidState.show_global_5 Global.is_virtual &&" },
  { NS_GLOBAL, CNTSGLOB_stand_r_row_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for real participant's rows", 0, "SidState.show_global_5 Global.is_virtual &&" },
  { NS_GLOBAL, CNTSGLOB_stand_u_row_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for unknown participant's rows", 0, "SidState.show_global_5 Global.is_virtual &&" },
  { NS_SID_STATE, SSSS_enable_extra_col, 135, 1, 0, 0, 0, 0, "Enable the \"Extra information\" column", 0, "SidState.show_global_5" },
  { NS_GLOBAL, CNTSGLOB_stand_extra_format, 'S', 1, 1, 1, 1, 0, "Format string for the \"Extra information\" column", 0, "SidState.show_global_5 SidState.enable_extra_col &&" },
  { NS_GLOBAL, CNTSGLOB_stand_extra_legend, 'S', 1, 1, 1, 1, 0, "Legend for the \"Extra information\" column", 0, "SidState.show_global_5 SidState.enable_extra_col &&" },
  { NS_GLOBAL, CNTSGLOB_stand_extra_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for the \"Extra information\" column", 0, "SidState.show_global_5 SidState.enable_extra_col &&" },
  { NS_GLOBAL, CNTSGLOB_stand_show_warn_number, 'Y', 1, 0, 0, 0, 0, "Enable the \"Warning\" column", 0, "SidState.show_global_5" },
  { NS_GLOBAL, CNTSGLOB_stand_warn_number_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for the \"Warnings\" column", 0, "SidState.show_global_5 Global.stand_show_warn_number &&" },
  { NS_GLOBAL, CNTSGLOB_stand_page_table_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for the page table", 0, "SidState.show_global_5 Global.users_on_page 0 > &&" },
  { NS_GLOBAL, CNTSGLOB_stand_page_cur_attr, 'S', 1, 1, 1, 1, 0, "HTML attributes for current page message", 0, "SidState.show_global_5 Global.users_on_page 0 > &&" },
  { NS_GLOBAL, CNTSGLOB_stand_page_row_attr, 'x', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_GLOBAL_FIELD_DETAIL_PAGE, "Page table row attributes", 0, "SidState.show_global_5 Global.users_on_page 0 > &&" },
  { NS_GLOBAL, CNTSGLOB_stand_page_col_attr, 'x', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_GLOBAL_FIELD_DETAIL_PAGE, "Page table column attributes", 0, "SidState.show_global_5 Global.users_on_page 0 > &&" },

  { NS_SID_STATE, SSSS_show_global_6, '-', 1, 0, 0, 0, 0, "Advanced settings", 0, 0 },
  { NS_GLOBAL, CNTSGLOB_appeal_deadline, 't', 1, 1, 0, 0, 0, "Appeal deadline", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_sleep_time, 'd', 1, 0, 1, 1, 0, "Directory poll interval (ms)", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_serve_sleep_time, 'd', 1, 0, 1, 1, 0, "Serve directory poll interval (ms)", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_autoupdate_standings, 'Y', 1, 0, 0, 0, 0, "Update standings automatically (except freeze time)", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_use_ac_not_ok, 'Y', 1, 0, 0, 0, 0, "Use AC status instead of OK", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_rounding_mode, 136, 1, 0, 0, 0, 0, "Seconds to minutes rounding mode", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_max_file_length, 'z', 1, 1, 1, 1, 0, "Maximum file size to include into testing protocols", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_max_line_length, 'z', 1, 1, 1, 1, 0, "Maximum line length to include into testing protocols", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_inactivity_timeout, 'd', 1, 1, 1, 1, 0, "Inactivity timeout for `run'", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_ignore_bom, 'Y', 1, 0, 0, 0, 0, "Ignore BOM in text submits", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_disable_testing, 'Y', 1, 0, 0, 0, 0, "Disable any testing of submissions", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_disable_auto_testing, 'Y', 1, 0, 0, 0, 0, "Disable automatic testing of submissions", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_cr_serialization_key, 'd', 1, 1, 1, 1, 0, "Serialization semaphore for `compile' and `run'", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_show_astr_time, 'Y', 1, 0, 0, 0, 0, "Use astronomic time", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_memoize_user_results, 'Y', 1, 0, 0, 0, 0, "Memoize user results", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_enable_continue, 'Y', 1, 0, 0, 0, 0, "Enable contest continuation", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_enable_report_upload, 'Y', 1, 0, 0, 0, 0, "Enable testing protocol upload", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_enable_runlog_merge, 'Y', 1, 0, 0, 0, 0, "Enable run database merging", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_disable_user_database, 'Y', 1, 0, 0, 0, 0, "Disable loading of the user database", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_enable_l10n, 'Y', 1, 0, 0, 0, 0, "Enable message translation", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_charset, 'S', 1, 1, 1, 1, 0, "Character set", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_standings_charset, 'S', 1, 1, 1, 1, 0, "Standings character set", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_stand2_charset, 'S', 1, 1, 1, 1, 0, "Secondary standings character set", 0, "SidState.show_global_6 SidState.enable_stand2 &&" },
  { NS_GLOBAL, CNTSGLOB_plog_charset, 'S', 1, 1, 1, 1, 0, "Submission log character set", 0, "SidState.show_global_6 SidState.enable_stand2 &&" },
  { NS_GLOBAL, CNTSGLOB_team_download_time, 'U', 1, 1, 0, 0, 0, "Contestant's archive download interval", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_cpu_bogomips, 'd', 1, 1, 1, 1, 0, "CPU speed (BogoMIPS)", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_clardb_plugin, 'S', 1, 1, 1, 1, 0, "ClarDB storage engine", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_rundb_plugin, 'S', 1, 1, 1, 1, 0, "RunDB storage engine", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_xuser_plugin, 'S', 1, 1, 1, 1, 0, "XuserDB storage engine", 0, "SidState.show_global_6" },
  { NS_GLOBAL, CNTSGLOB_load_user_group, 'x', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_GLOBAL_FIELD_DETAIL_PAGE, "User groups to load", 0, "SidState.show_global_6" },

  { NS_SID_STATE, SSSS_show_global_7, '-', 1, 0, 0, 0, 0, "Other parameters", 0, 0 },
  { NS_GLOBAL, CNTSGLOB_unhandled_vars, 137, 0, 0, 0, 0, SSERV_CMD_EDIT_SERVE_GLOBAL_FIELD_DETAIL_PAGE, 0, 0, "SidState.show_global_7" },

  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

/*
  int is_editable;
  int is_clearable;
  int dojo_inline_edit;
  int is_nullable;
  int has_details;
*/
static const struct cnts_edit_info cnts_language_info[] =
{
  { NS_LANGUAGE, CNTSLANG_id, 'd', 0, 0, 0, 0, 0, "Language ID", "Language ID", 0 },
  { NS_LANGUAGE, CNTSLANG_compile_id, 'd', 0, 0, 0, 0, 0, "Compile ID", "Compile ID", 0 },
  { NS_LANGUAGE, CNTSLANG_short_name, 'S', 0, 0, 0, 0, 0, "Short name", "Short name", 0 },
  { NS_LANGUAGE, CNTSLANG_arch, 'S', 0, 0, 0, 0, 0, "Architecture", "Architecture", 0 },
  { NS_LANGUAGE, CNTSLANG_src_sfx, 'S', 0, 0, 0, 0, 0, "Source suffix", "Source suffix", 0 },
  { NS_LANGUAGE, CNTSLANG_exe_sfx, 'S', 0, 0, 0, 0, 0, "Executable suffix", "Executable suffix", 0 },

  { NS_LANGUAGE, CNTSLANG_long_name, 'S', 1, 1, 1, 1, 0, "Long name", "Long name", 0 },
  { NS_LANGUAGE, CNTSLANG_disabled, 'Y', 1, 0, 0, 0, 0, "Disable language", "Disable this language for participants", 0 },
  { NS_LANGUAGE, CNTSLANG_insecure, 'Y', 1, 0, 0, 0, 0, "Language is insecure", "This language is insecure", 0 },
  { NS_LANGUAGE, CNTSLANG_disable_security, 'Y', 1, 0, 0, 0, 0, "Disable security restrictions", "Disable security restrictions", 0 },
  { NS_LANGUAGE, CNTSLANG_disable_testing, 'Y', 1, 0, 0, 0, 0, "Disable testing of submissions in this language", 0, 0 },
  { NS_LANGUAGE, CNTSLANG_disable_auto_testing, 'Y', 1, 0, 0, 0, 0, "Disable automatic testing of submissions", 0, "Language.disable_testing !" },
  { NS_LANGUAGE, CNTSLANG_binary, 'Y', 1, 0, 0, 0, 0, "Source files are binary", 0, 0 },
  // content_type
  { NS_LANGUAGE, CNTSLANG_style_checker_cmd, 'S', 1, 1, 1, 1, 0, "Style checker command", "Style checker command", 0 },
  { NS_LANGUAGE, CNTSLANG_style_checker_env, 'X', 1, 1, 1, 1, 0, "Style checker environment", "Style checker environment", 0 },
  { NS_SID_STATE, SSSS_lang_opts, 138, 1, 1, 1, 1, 0, "Compilation options", 0, 0 },
  { NS_SID_STATE, SSSS_lang_libs, 144, 1, 1, 1, 1, 0, "Compilation libraries", 0, 0 },
  { NS_LANGUAGE, CNTSLANG_compiler_env, 'X', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_LANG_FIELD_DETAIL_PAGE, "Additional environment variables", 0, 0 },
  { 0, 0, '-', 0, 0, 0, 0, 0, "Other parameters", 0, 0 },
  { NS_LANGUAGE, CNTSLANG_unhandled_vars, 137, 0, 0, 0, 0, SSERV_CMD_EDIT_SERVE_LANG_FIELD_DETAIL_PAGE, 0, 0, 0 },

  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

static const struct cnts_edit_info cnts_problem_info[] =
{
  { NS_PROBLEM, CNTSPROB_short_name, 'S', 1, 1, 1, 1, 0, "Short name", 0, 0 },
  { NS_PROBLEM, CNTSPROB_long_name, 'S', 1, 1, 1, 1, 0, "Long name", 0, "Problem.abstract !" },
  { NS_PROBLEM, CNTSPROB_super, 139, 0, 0, 0, 0, 0, "Base abstract problem", 0, "Problem.abstract !" },
  { NS_PROBLEM, CNTSPROB_stand_name, 'S', 1, 1, 1, 1, 0, "Standings column title", 0, "Problem.abstract ! SidState.prob_show_adv &&" },
  { NS_PROBLEM, CNTSPROB_stand_column, 140, 0, 0, 0, 0, 0, "Collate this problem with another one", 0, "Problem.abstract ! SidState.prob_show_adv &&" },
  { NS_PROBLEM, CNTSPROB_internal_name, 'S', 1, 1, 1, 1, 0, "Internal name", 0, "Problem.abstract ! SidState.prob_show_adv &&" },
  { NS_PROBLEM, CNTSPROB_type, 141, 1, 0, 0, 0, 0, "Problem type", 0, 0 },
  { NS_PROBLEM, CNTSPROB_manual_checking, 'Y', 1, 0, 0, 0, 0, "Check problem manually", 0, 0 },
  { NS_PROBLEM, CNTSPROB_examinator_num, 'd', 1, 1, 1, 1, 0, "Number of examinators", 0, "Problem.manual_checking 0 >" },
  { NS_PROBLEM, CNTSPROB_check_presentation, 'Y', 1, 0, 0, 0, 0, "Check the format of answers", 0, "Problem.manual_checking 0 >" },
  { NS_PROBLEM, CNTSPROB_use_stdin, 'Y', 1, 0, 0, 0, 0, "Read the data from the stdin", 0, "Problem.manual_checking !" },
  { NS_PROBLEM, CNTSPROB_input_file, 'S', 1, 1, 1, 1, 0, "Name of the input file", 0, "Problem.manual_checking !" },
  { NS_PROBLEM, CNTSPROB_combined_stdin, 'Y', 1, 0, 0, 0, 0, "Combine the standard and file input", 0, "Problem.manual_checking !" },
  { NS_PROBLEM, CNTSPROB_use_stdout, 'Y', 1, 0, 0, 0, 0, "Write output to the stdin", 0, "Problem.manual_checking !" },
  { NS_PROBLEM, CNTSPROB_output_file, 'S', 1, 1, 1, 1, 0, "Name of the output file", 0, "Problem.manual_checking !" },
  { NS_PROBLEM, CNTSPROB_combined_stdout, 'Y', 1, 0, 0, 0, 0, "Combine the standard and file output", 0, "Problem.manual_checking !" },
  { NS_PROBLEM, CNTSPROB_disable_stderr, 'Y', 1, 0, 0, 0, 0, "Consider output to stderr as PE", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_binary_input, 'Y', 1, 0, 0, 0, 0, "Input data in binary", 0, "Problem.manual_checking ! SidState.prob_show_adv &&" },
  { NS_PROBLEM, CNTSPROB_binary, 'Y', 1, 0, 0, 0, 0, "Submit is binary", 0, "Problem.manual_checking ! SidState.prob_show_adv &&" },
  { NS_PROBLEM, CNTSPROB_xml_file, 'S', 1, 1, 1, 1, 0, "Name of XML file with problem statement", 0, 0 },
  { NS_PROBLEM, CNTSPROB_plugin_file, 'S', 1, 1, 1, 1, 0, "Problem plugin file", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_test_dir, 'S', 1, 1, 1, 1, 0, "Directory with tests", 0, 0 },
  { NS_PROBLEM, CNTSPROB_test_sfx, 'S', 1, 1, 1, 1, 0, "Suffix of test files", 0, 0 },
  { NS_PROBLEM, CNTSPROB_test_pat, 'S', 1, 1, 1, 1, 0, "Pattern of test files", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_use_corr, 'Y', 1, 0, 0, 0, 0, "Use answer files", 0, 0 },
  { NS_PROBLEM, CNTSPROB_corr_dir, 'S', 1, 1, 1, 1, 0, "Directory with answers", 0, "Problem.use_corr 0 >" },
  { NS_PROBLEM, CNTSPROB_corr_sfx, 'S', 1, 1, 1, 1, 0, "Suffix of answer files", 0, "Problem.use_corr 0 >" },
  { NS_PROBLEM, CNTSPROB_corr_pat, 'S', 1, 1, 1, 1, 0, "Pattern of answer files", 0, "Problem.use_corr 0 > SidState.prob_show_adv &&" },
  { NS_PROBLEM, CNTSPROB_use_info, 'Y', 1, 0, 0, 0, 0, "Use test info files", 0, 0, },
  { NS_PROBLEM, CNTSPROB_info_dir, 'S', 1, 1, 1, 1, 0, "Directory with test info files", 0, "Problem.use_info 0 >" },
  { NS_PROBLEM, CNTSPROB_info_sfx, 'S', 1, 1, 1, 1, 0, "Suffix of test info files", 0, "Problem.use_info 0 >" },
  { NS_PROBLEM, CNTSPROB_info_pat, 'S', 1, 1, 1, 1, 0, "Pattern of test info files", 0, "Problem.use_info 0 > SidState.prob_show_adv &&" },
  { NS_PROBLEM, CNTSPROB_use_tgz, 'Y', 1, 0, 0, 0, 0, "Use tgz files", 0, "Problem.manual_checking !" },
  { NS_PROBLEM, CNTSPROB_tgz_dir, 'S', 1, 1, 1, 1, 0, "Directory with tgz files", 0, "Problem.use_tgz 0 >" },
  { NS_PROBLEM, CNTSPROB_tgz_sfx, 'S', 1, 1, 1, 1, 0, "Suffix of tgz files", 0, "Problem.manual_checking ! Problem.use_tgz 0 > &&" },
  { NS_PROBLEM, CNTSPROB_tgz_pat, 'S', 1, 1, 1, 1, 0, "Pattern of tgz files", 0, "Problem.manual_checking ! Problem.use_tgz 0 > SidState.prob_show_adv && &&" },
  { NS_PROBLEM, CNTSPROB_tgzdir_sfx, 'S', 1, 1, 1, 1, 0, "Suffix of master working directories", 0, "Problem.manual_checking ! Problem.use_tgz 0 > &&" },
  { NS_PROBLEM, CNTSPROB_tgzdir_pat, 'S', 1, 1, 1, 1, 0, "Pattern of master working directories", 0, "Problem.manual_checking ! Problem.use_tgz 0 > SidState.prob_show_adv && &&" },
  { NS_PROBLEM, CNTSPROB_time_limit, 'd', 1, 1, 1, 1, 0, "CPU time limit (s)", 0, "Problem.manual_checking ! Problem.time_limit_millis 0 <= &&" },
  { NS_PROBLEM, CNTSPROB_time_limit_millis, 'd', 1, 1, 1, 1, 0, "CPU time limit (ms)", 0, "Problem.manual_checking ! SidState.prob_show_adv Problem.time_limit_millis 0 > || &&" },
  { NS_PROBLEM, CNTSPROB_real_time_limit, 'd', 1, 1, 1, 1, 0, "Real time limit (s)", 0, "Problem.manual_checking !" },
  { NS_PROBLEM, CNTSPROB_max_vm_size, 'Z', 1, 1, 1, 1, 0, "Maximum VM size", 0, "Problem.manual_checking !" },
  { NS_PROBLEM, CNTSPROB_max_stack_size, 'Z', 1, 1, 1, 1, 0, "Maximum stack size", 0, "Problem.manual_checking !" },
  { NS_PROBLEM, CNTSPROB_max_core_size, 'Z', 1, 1, 1, 1, 0, "Maximum core file size", 0, "Problem.manual_checking ! SidState.prob_show_adv &&" },
  { NS_PROBLEM, CNTSPROB_max_file_size, 'Z', 1, 1, 1, 1, 0, "Maximum file size", 0, "Problem.manual_checking ! SidState.prob_show_adv &&" },
  { NS_PROBLEM, CNTSPROB_max_open_file_count, 'd', 1, 1, 1, 1, 0, "Maximum number of opened files", 0, "Problem.manual_checking ! SidState.prob_show_adv &&" },
  { NS_PROBLEM, CNTSPROB_max_process_count, 'd', 1, 1, 1, 1, 0, "Maximum number of processes", 0, "Problem.manual_checking ! SidState.prob_show_adv &&" },
  { NS_PROBLEM, CNTSPROB_enable_process_group, 'Y', 1, 0, 0, 0, 0, "Enable process groups", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_checker_real_time_limit, 'd', 1, 1, 1, 1, 0, "Checker real time limit (s)", 0, 0 },
  { NS_PROBLEM, CNTSPROB_use_ac_not_ok, 'Y', 1, 0, 0, 0, 0, "Use AC status instead of OK", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_ignore_prev_ac, 'Y', 1, 0, 0, 0, 0, "Mark previous AC as IG", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_team_enable_rep_view, 'Y', 1, 0, 0, 0, 0, "Contestants may view testing protocols", 0, 0 },
  { NS_PROBLEM, CNTSPROB_team_enable_ce_view, 'Y', 1, 0, 0, 0, 0, "Contestants may view compilation errors", 0, "Problem.team_enable_rep_view !" },
  { NS_PROBLEM, CNTSPROB_team_show_judge_report, 'Y', 1, 0, 0, 0, 0, "Contestants may view FULL testing protocols", 0, "Problem.team_enable_rep_view 0 >" },
  { NS_PROBLEM, CNTSPROB_show_checker_comment, 'Y', 1, 0, 0, 0, 0, "Contestants may view checker comment", 0, "Problem.team_enable_rep_view 0 >" },
  { NS_PROBLEM, CNTSPROB_ignore_compile_errors, 'Y', 1, 0, 0, 0, 0, "Ignore compile errors", 0, 0 },
  { NS_PROBLEM, CNTSPROB_disable_user_submit, 'Y', 1, 0, 0, 0, 0, "Disable user submissions", 0, 0 },
  { NS_PROBLEM, CNTSPROB_disable_tab, 'Y', 1, 0, 0, 0, 0, "Disable navigation tab", 0, "Global.problem_navigation SidState.prob_show_adv &&" },
  { NS_PROBLEM, CNTSPROB_unrestricted_statement, 'Y', 1, 0, 0, 0, 0, "Unrestricted problem statement", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_hide_file_names, 'Y', 1, 0, 0, 0, 0, "Hide input/output file names in statement display", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_disable_submit_after_ok, 'Y', 1, 0, 0, 0, 0, "Disable submissions after OK", 0, 0 },
  { NS_PROBLEM, CNTSPROB_disable_security, 'Y', 1, 0, 0, 0, 0, "Disable security restrictions", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_disable_testing, 'Y', 1, 0, 0, 0, 0, "Disable testing of submissions", 0, 0 },
  { NS_PROBLEM, CNTSPROB_disable_auto_testing, 'Y', 1, 0, 0, 0, 0, "Disable automatic testing of submissions", 0, "Problem.disable_testing 0 <=" },
  { NS_PROBLEM, CNTSPROB_enable_compilation, 'Y', 1, 0, 0, 0, 0, "Compile submissions to mark AC", 0, "Problem.disable_testing 0 <= Problem.disable_auto_testing 0 > &&" },
  { NS_PROBLEM, CNTSPROB_ignore_exit_code, 'Y', 1, 0, 0, 0, 0, "Ignore process exit code", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_olympiad_mode, 'Y', 1, 0, 0, 0, 0, "Use Olympiad mode", 0, "SidState.prob_show_adv Global.score_system SCORE_KIROV == &&" },
  { NS_PROBLEM, CNTSPROB_score_latest, 'Y', 1, 0, 0, 0, 0, "Score the latest submit", 0, "SidState.prob_show_adv Global.score_system SCORE_KIROV == &&" },
  { NS_PROBLEM, CNTSPROB_score_latest_or_unmarked, 'Y', 1, 0, 0, 0, 0, "Score the latest submit or the best unmarked", 0, "SidState.prob_show_adv Global.score_system SCORE_KIROV == &&" },
  { NS_PROBLEM, CNTSPROB_score_latest_marked, 'Y', 1, 0, 0, 0, 0, "Score the latest marked submit", 0, "SidState.prob_show_adv Global.score_system SCORE_KIROV == &&" },
  { NS_PROBLEM, CNTSPROB_full_score, 'd', 1, 1, 1, 1, 0, "Full problem score", 0, "Global.score_system SCORE_ACM !=" },
  { NS_PROBLEM, CNTSPROB_variable_full_score, 'Y', 1, 0, 0, 0, 0, "Allow variable full score", 0, "SidState.prob_show_adv Global.score_system SCORE_KIROV == Global.score_system SCORE_OLYMPIAD == || &&" },
  { NS_PROBLEM, CNTSPROB_test_score, 'd', 1, 1, 1, 1, 0, "Score for one passed test", 0, "Global.score_system SCORE_KIROV == Global.score_system SCORE_OLYMPIAD == ||" },
  { NS_PROBLEM, CNTSPROB_run_penalty, 'd', 1, 1, 1, 1, 0, "Penalty for a failed submit", 0, "Global.score_system SCORE_KIROV ==" },
  { NS_PROBLEM, CNTSPROB_disqualified_penalty, 'd', 1, 1, 1, 1, 0, "Penalty for a disqualified submit", 0, "Global.score_system SCORE_KIROV ==" },
  { NS_PROBLEM, CNTSPROB_test_score_list, 's', 1, 1, 1, 1, 0, "Test scores for tests", 0, "Global.score_system SCORE_KIROV == Global.score_system SCORE_OLYMPIAD == ||" },
  { NS_PROBLEM, CNTSPROB_acm_run_penalty, 'd', 1, 1, 1, 1, 0, "Penalty for a submit", 0, "SidState.prob_show_adv Global.score_system SCORE_ACM == Global.score_system SCORE_MOSCOW == || &&" },
  { NS_PROBLEM, CNTSPROB_score_tests, 'S', 1, 1, 1, 1, 0, "Tests for problem scoring", 0, "Global.score_system SCORE_MOSCOW ==" },
  { NS_PROBLEM, CNTSPROB_test_sets, 'x', 1, 1, 1, 1, 0, "Specially scored test sets", 0, "SidState.prob_show_adv Global.score_system SCORE_KIROV == Global.score_system SCORE_OLYMPIAD == || &&" },
  { NS_PROBLEM, CNTSPROB_score_bonus, 'S', 1, 1, 1, 1, 0, "Additional score bonus", 0, "Global.score_system SCORE_KIROV ==" },
  { NS_PROBLEM, CNTSPROB_open_tests, 'S', 1, 1, 1, 1, 0, "Tests open for participants", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_final_open_tests, 'S', 1, 1, 1, 1, 0, "Tests open for participants on final show", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_tests_to_accept, 'd', 1, 1, 1, 1, 0, "Number of accept tests", 0, "Global.score_system SCORE_OLYMPIAD ==" },
  { NS_PROBLEM, CNTSPROB_accept_partial, 'Y', 1, 0, 0, 0, 0, "Accept submits, which do not pass accept tests", 0, "SidState.prob_show_adv Global.score_system SCORE_OLYMPIAD == &&" },
  { NS_PROBLEM, CNTSPROB_min_tests_to_accept, 'd', 1, 1, 1, 1, 0, "Minimum number of tests to accept", 0, "SidState.prob_show_adv Global.score_system SCORE_OLYMPIAD == &&" },
  { NS_PROBLEM, CNTSPROB_hidden, 'Y', 1, 0, 0, 0, 0, "Do not show problem in standings", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_stand_hide_time, 'Y', 1, 0, 0, 0, 0, "Do not show OK time in the standings", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_advance_to_next, 'Y', 1, 0, 0, 0, 0, "Advance to the next problem", 0, "SidState.prob_show_adv Global.problem_navigation &&" },
  { NS_PROBLEM, CNTSPROB_disable_ctrl_chars, 'Y', 1, 0, 0, 0, 0, "Disable control characters in the source", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_valuer_sets_marked, 'Y', 1, 0, 0, 0, 0, "Valuer sets _marked_ flag", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_ignore_unmarked, 'Y', 1, 0, 0, 0, 0, "Ignore unmarked runs in scoring", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_enable_text_form, 'Y', 1, 0, 0, 0, 0, "Enable text input form", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_stand_attr, 'S', 1, 1, 1, 1, 0, "Standings attributes", 0, 0 },
  { NS_PROBLEM, CNTSPROB_standard_checker, 142, 1, 0, 0, 0, 0, "Standard checker", 0, 0 },
  { NS_PROBLEM, CNTSPROB_lang_compiler_env, 'X', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, "Compiler environment", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_check_cmd, 'S', 1, 1, 1, 1, 0, "Checker", 0, 0 /*"Problem.standard_checker"*/ },
  { NS_PROBLEM, CNTSPROB_disable_pe, 'Y', 1, 0, 0, 0, 0, "Treat PE as WA", 0, 0 },
  { NS_PROBLEM, CNTSPROB_disable_wtl, 'Y', 1, 0, 0, 0, 0, "Treat WTL as TL", 0, 0 },
  { NS_PROBLEM, CNTSPROB_checker_env, 'X', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, "Checker environment", 0, 0 },
  { NS_PROBLEM, CNTSPROB_scoring_checker, 'Y', 1, 0, 0, 0, 0, "Checker calculates score", 0, 0 },
  { NS_PROBLEM, CNTSPROB_valuer_cmd, 'S', 1, 1, 1, 1, 0, "Valuer", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_valuer_sets_marked, 'Y', 1, 0, 0, 0, 0, "Valuer sets _marked_ flag", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_interactive_valuer, 'Y', 1, 0, 0, 0, 0, "Valuer works interactively", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_valuer_env, 'X', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, "Valuer environment", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_interactor_cmd, 'S', 1, 1, 1, 1, 0, "Interactor", 0, "SidState.prob_show_adv"  },
  { NS_PROBLEM, CNTSPROB_interactor_env, 'X', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, "Interactor environment", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_interactor_time_limit, 'd', 1, 1, 1, 1, 0, "Interactor time limit (s)", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_style_checker_cmd, 'S', 1, 1, 1, 1, 0, "Style checker", 0, "SidState.prob_show_adv"  },
  { NS_PROBLEM, CNTSPROB_style_checker_env, 'X', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, "Style checker environment", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_test_checker_cmd, 's', 1, 1, 1, 1, 0, "Test checker", 0, "SidState.prob_show_adv"  },
  { NS_PROBLEM, CNTSPROB_test_checker_env, 'X', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, "Test checker environment", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_init_cmd, 's', 1, 1, 1, 1, 0, "Init-style interactor", 0, "SidState.prob_show_adv"  },
  { NS_PROBLEM, CNTSPROB_init_env, 'X', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, "Init-style interactor environment", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_start_env, 'X', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, "Start environment", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_solution_src, 's', 1, 1, 1, 1, 0, "Solution source", 0, "SidState.prob_show_adv"  },
  { NS_PROBLEM, CNTSPROB_solution_cmd, 's', 1, 1, 1, 1, 0, "Solution command", 0, "SidState.prob_show_adv"  },
  { NS_PROBLEM, CNTSPROB_score_view, 'x', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, "Special view for score", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_stand_ignore_score, 'Y', 1, 0, 0, 0, 0, "Ignore problem score", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_stand_last_column, 'Y', 1, 0, 0, 0, 0, "Show as the last column", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_lang_time_adj, 'x', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, "Language time-limit adjustments (s)", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_lang_time_adj_millis, 'x', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, "Language time-limit adjustments (ms)", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_lang_max_vm_size, 'x', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, "Language-specific memory limit", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_lang_max_stack_size, 'x', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, "Language-specific stack limit", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_disable_language, 'x', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, "Disabled languages", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_enable_language, 'x', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, "Enabled languages", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_require, 'x', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, "Required problems", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_provide_ok, 'x', 1, 1, 1, 1, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, "Provide OK to problems", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_variant_num, 'd', 1, 1, 1, 1, 0, "Number of variants", 0, 0 },
  { NS_PROBLEM, CNTSPROB_start_date, 't', 1, 1, 0, 0, 0, "Accept start date", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_deadline, 't', 1, 1, 0, 0, 0, "Accept deadline", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_source_header, 'S', 1, 1, 1, 1, 0, "Source header file", 0, "SidState.prob_show_adv" },
  { NS_PROBLEM, CNTSPROB_source_footer, 'S', 1, 1, 1, 1, 0, "Source footer file", 0, "SidState.prob_show_adv" },
  { 0, 0, '-', 0, 0, 0, 0, 0, "Other parameters", 0, 0 },
  { NS_PROBLEM, CNTSPROB_unhandled_vars, 137, 0, 0, 0, 0, SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE, 0, 0, 0 },

  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

/**
   A page descripting structure.
 */
struct edit_page_desc
{
  const unsigned char *label;
  const struct cnts_edit_info *edit_descs;
  const struct meta_methods *methods;
  int edit_op;
  int clear_op;
  int (*is_undef_value)(const void *, int);
};

static const struct edit_page_desc edit_page_descs[] =
{
  { "General Settings", cnts_edit_info, &contest_desc_methods,
    SSERV_CMD_EDIT_CONTEST_XML_FIELD, SSERV_CMD_CLEAR_CONTEST_XML_FIELD },
  { "Global Settings", cnts_global_info, &cntsglob_methods,
    SSERV_CMD_EDIT_SERVE_GLOBAL_FIELD, SSERV_CMD_CLEAR_SERVE_GLOBAL_FIELD },
  { "Language Settings", cnts_language_info, &cntslang_methods,
    SSERV_CMD_SET_SERVE_LANG_FIELD, SSERV_CMD_CLEAR_SERVE_LANG_FIELD },
  { "Problem Settings", cnts_problem_info, &cntsprob_methods,
    SSERV_CMD_SET_SERVE_PROB_FIELD, SSERV_CMD_CLEAR_SERVE_PROB_FIELD,
    cntsprob_is_undefined
  },
  { 0, 0, 0, 0 },
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
    snprintf(bbuf, sizeof(bbuf), "ssFieldRequest(%d, %d, %d)",
             SSERV_CMD_TOGGLE_CONTEST_XML_VISIBILITY,
             field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2);
    fprintf(out_f, "<td class=\"cnts_edit_head\">");
    if (copy_cmd) {
      ss_dojo_button(out_f, 0, "promotion-16x16", "Copy",
                     "ssLoad1(%d)", copy_cmd);
    }
    if (!*p_detail_flag) {
      ss_dojo_button(out_f, 0, "zoom_in-16x16", "Show Detail", "%s", bbuf);
    } else {
      ss_dojo_button(out_f, 0, "zoom_out-16x16", "Hide Detail", "%s", bbuf);
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
        const struct contest_desc *ecnts,
        struct http_request_info *phr)
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
  ss_dojo_button(out_f, 0, "edit_page-16x16", "Edit contents",
              "ssLoad1(%d)", SSERV_CMD_EDIT_GENERAL_FIELDS_PAGE);
  fprintf(out_f, "</td></tr>\n");

  for (m = 0; m < CONTEST_LAST_MEMBER; ++m) {
    if (ecnts->personal && m == CONTEST_M_RESERVE) continue;

    fprintf(out_f,
            "<tr%s>"
            "<td class=\"cnts_edit_legend\" valign=\"top\">&quot;%s&quot; fields</td>"
            "<td class=\"cnts_edit_legend\"><font size=\"-1\"><pre>",
            form_row_attrs[row ^= 1], contests_get_member_name(m));
    if ((memb = ecnts->members[m])) {
      fprintf(out_f, "minimum count = %d\n", memb->min_count);
      fprintf(out_f, "maximum count = %d\n", memb->max_count);
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
    ss_dojo_button(out_f, 0, "edit_page-16x16", "Edit contents",
                "ssLoad2(%d, %d)", SSERV_CMD_EDIT_MEMBER_FIELDS_PAGE, m);
    fprintf(out_f, "</td></tr>\n");

  }
}

extern struct std_checker_info super_html_std_checkers[];

static void
write_editing_rows(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr,
        const struct edit_page_desc *pg,
        const struct contest_desc *ecnts,
        const struct section_global_data *global,
        const void *edit_ptr,
        int item_id,
        int need_dv_column,
        const void *dflt_ptr)
{
  int i, row = 1, j, k, is_empty, edit_op, clear_op, has_dv_column;
  int is_undef;
  const struct cnts_edit_info *ce;
  const unsigned char *hint;
  const struct opcap_list_item *perms;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char *s;
  const void *v_ptr, *u_ptr = 0;
  unsigned char buf[1024], jbuf[1024];
  unsigned char dflt_str[1024];

  for (i = 0, ce = pg->edit_descs; ce->type; ++i, ++ce) {
    hint = ce->hint;
    if (!hint) hint = ce->legend;
    edit_op = pg->edit_op;
    clear_op = pg->clear_op;
    has_dv_column = 0;
    is_undef = 0;
    dflt_str[0] = 0;

    if (ce->type == '-') {
      if (ce->guard_expr) {
        if (!eval_check_expr(phr, ce->guard_expr)) continue;
      }

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

      for (perms = CNTS_FIRST_PERM(ecnts), j = 0; perms;
           perms = CNTS_NEXT_PERM(perms), ++j) {
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
        ss_dojo_button(out_f, 0, "edit_page-16x16", "Edit permissions",
                    "ssLoad2(%d, %d)", SSERV_CMD_EDIT_PERMISSIONS_PAGE, j);
        ss_dojo_button(out_f, 0, "delete-16x16", "Delete permissions",
                    "ssFieldRequest(%d, %d, %d)",
                    SSERV_CMD_DELETE_PRIV_USER, j,
                    SSERV_CMD_EDIT_CONTEST_PAGE_2);
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

    if (ce->type == 138) {
      edit_op = SSERV_CMD_SET_SID_STATE_LANG_FIELD;
      clear_op = SSERV_CMD_CLEAR_SID_STATE_LANG_FIELD;
    }

    is_empty = 0;
    if (dflt_ptr && (is_undef = pg->is_undef_value(edit_ptr, ce->field_id))) {
      u_ptr = pg->methods->get_ptr(dflt_ptr, ce->field_id);
    }

    fprintf(out_f, "<tr%s>", form_row_attrs[row ^= 1]);
    if (ce->type == 137) {
      fprintf(out_f, "<td valign=\"top\" class=\"cnts_edit_data\" colspan=\"2\">");
    } else {
      fprintf(out_f, "<td valign=\"top\" class=\"cnts_edit_legend\">%s:</td>", ce->legend);
      fprintf(out_f, "<td valign=\"top\" class=\"cnts_edit_data\" width=\"600px\">");
    }
    if (ce->is_editable && ce->dojo_inline_edit) {
      if (item_id) {
        snprintf(jbuf, sizeof(jbuf),
                 "ssEditField4(%d, %d, %d, %d, arguments[0])",
                 edit_op, item_id, ce->field_id,
                 SSERV_CMD_EDIT_CONTEST_PAGE_2);
      } else {
        snprintf(jbuf, sizeof(jbuf), "ssEditField(%d, %d, %d, arguments[0])",
                 edit_op, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2);
      }
      fprintf(out_f, "<div class=\"cnts_edit_data\" dojoType=\"dijit.InlineEditBox\" onChange=\"%s\" autoSave=\"true\" title=\"%s\">", jbuf, hint);
    } else if (ce->type != 't') {
      fprintf(out_f, "<div class=\"cnts_edit_data\">");
    }

    v_ptr = 0;
    if (ce->type != 135 && ce->type != 138)
      v_ptr = pg->methods->get_ptr(edit_ptr, ce->field_id);

    switch (ce->type) {
    case 'd':
      if (!is_undef) {
        int *d_ptr = (int*) v_ptr;
        fprintf(out_f, "%d", *d_ptr);
      } else if (dflt_ptr) {
        snprintf(dflt_str, sizeof(dflt_str), "%d", *(int*) u_ptr);
      }
      break;
    case 'u':
      if (!is_undef) {
        int *d_ptr = (int*) v_ptr;
        if (*d_ptr <= 0) {
          fprintf(out_f, "0");
        } else {
          fprintf(out_f, "%d:%02d", *d_ptr / 60, *d_ptr % 60);
        }
      } else if (dflt_ptr) {
        int *d_ptr = (int*) v_ptr;
        if (*d_ptr <= 0) {
          snprintf(dflt_str, sizeof(dflt_str), "0");
        } else {
          snprintf(dflt_str, sizeof(dflt_str),
                   "%d:%02d", *d_ptr / 60, *d_ptr % 60);
        }
      }
      break;
    case 'U':
      if (!is_undef) {
        int *d_ptr = (int*) v_ptr;
        int h, m, s;
        if (*d_ptr <= 0) {
          fprintf(out_f, "0");
        } else {
          h = *d_ptr / 3600;
          m = (*d_ptr / 60) % 60;
          s = *d_ptr % 60;
          fprintf(out_f, "%d:%02d:%02d", h, m, s);
        }
      }
      break;
    case 'z':
      if (!is_undef) {
        ejintsize_t val = *(ejintsize_t*) v_ptr;
        fprintf(out_f, "%s", num_to_size_str(buf, sizeof(buf), val));
      } else {
        ejintsize_t val = *(ejintsize_t*) u_ptr;
        snprintf(dflt_str, sizeof(dflt_str), "%s",
                 num_to_size_str(buf, sizeof(buf), val));
      }
      break;
    case 'Z':
      if (!is_undef) {
        size_t val = *(size_t*) v_ptr;
        fprintf(out_f, "%s", size_t_to_size_str(buf, sizeof(buf), val));
      } else {
        size_t val = *(size_t*) u_ptr;
        snprintf(dflt_str, sizeof(dflt_str), "%s",
                 size_t_to_size_str(buf, sizeof(buf), val));
      }
      break;
    case 137:
      if (!is_undef) {
        unsigned char **s_ptr = (unsigned char**) v_ptr;
        if (*s_ptr) fprintf(out_f, "<pre>%s</pre>", ARMOR(*s_ptr));
        if (!*s_ptr) is_empty = 1;
      }
      break;
    case 's': case 'e':
      if (!is_undef) {
        unsigned char **s_ptr = (unsigned char**) v_ptr;
        if (*s_ptr) fprintf(out_f, "%s", *s_ptr);
        if (!*s_ptr) is_empty = 1;
      }
      break;
    case 'S':
      if (!is_undef) {
        unsigned char *s = (unsigned char *) v_ptr;
        fprintf(out_f, "%s", s);
        is_empty = 0;
      } else {
        unsigned char *s = (unsigned char *) u_ptr;
        snprintf(dflt_str, sizeof(dflt_str), "%s", s);
      }
      break;
    case 'x':
      {
        char **s = *(char ***) v_ptr;
        unsigned char *ss = sarray_unparse_2(s);
        fprintf(out_f, "%s", ss);
        xfree(ss);
      }
      break;
    case 'X':
      {
        char **s = *(char ***) v_ptr;
        unsigned char *ss = sarray_unparse(s);
        fprintf(out_f, "%s", ss);
        xfree(ss);
      }
      break;
    case 'y':
      {
        unsigned char *y_ptr = (unsigned char*) v_ptr;
        if (!ce->is_editable) {
          if (is_undef) break;
          fprintf(out_f, "%s", *y_ptr?"Yes":"No");
          break;
        }
        if (item_id) {
          snprintf(jbuf, sizeof(jbuf), "ssEditField4(%d, %d, %d, %d, this.options[this.selectedIndex].value)", edit_op, item_id, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2);
        } else {
          snprintf(jbuf, sizeof(jbuf), "ssEditField(%d, %d, %d, this.options[this.selectedIndex].value)", edit_op, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2);
        }
        if (dflt_ptr) {
          ss_html_int_select_undef(out_f, 0, 0, 0, jbuf, is_undef, *y_ptr,
                             2, (const char *[]) { "No", "Yes" });
        } else {
          ss_html_int_select(out_f, 0, 0, 0, jbuf, !!*y_ptr,
                             2, (const char *[]) { "No", "Yes" });
        }
      }
      break;
    case 'Y':
      {
        ejintbool_t *y_ptr = (ejintbool_t*) v_ptr;
        if (!ce->is_editable) {
          fprintf(out_f, "%s", *y_ptr?"Yes":"No");
          break;
        }
        if (item_id) {
          snprintf(jbuf, sizeof(jbuf), "ssEditField4(%d, %d, %d, %d, this.options[this.selectedIndex].value)", edit_op, item_id, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2);
        } else {
          snprintf(jbuf, sizeof(jbuf), "ssEditField(%d, %d, %d, this.options[this.selectedIndex].value)", edit_op, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2);
        }
        if (dflt_ptr) {
          ss_html_int_select_undef(out_f, 0, 0, 0, jbuf, is_undef, *y_ptr,
                             2, (const char *[]) { "No", "Yes" });
        } else {
          ss_html_int_select(out_f, 0, 0, 0, jbuf, !!*y_ptr,
                             2, (const char *[]) { "No", "Yes" });
        }
        if (dflt_ptr && is_undef) {
          int val = *(ejintbool_t*) u_ptr;
          snprintf(dflt_str, sizeof(dflt_str), "%s", val?"Yes":"No");
        }
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
        if (tval && !is_undef) {
          ptm = localtime(&tval);
          snprintf(time_buf, sizeof(time_buf), "%02d:%02d:%02d",
                   ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
          snprintf(date_buf, sizeof(date_buf), " value=\"%04d-%02d-%02d\"",
                   ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday);
        }

        if (item_id) {
          snprintf(jbuf, sizeof(jbuf),
                   "ssEditField5(%d, %d, %d, %d, %d, arguments[0])",
                   edit_op, item_id, ce->field_id, 1,
                   SSERV_CMD_EDIT_CONTEST_PAGE_2);
        } else {
          snprintf(jbuf, sizeof(jbuf),
                   "ssEditField2(%d, %d, %d, %d, arguments[0])",
                   edit_op, ce->field_id, 1,
                   SSERV_CMD_EDIT_CONTEST_PAGE_2);
        }
        fprintf(out_f, "<div class=\"cnts_edit_inlined\">Time: </div><div class=\"cnts_edit_inlined\" dojoType=\"dijit.InlineEditBox\" onChange=\"%s\" autoSave=\"true\" title=\"Time (HH:MM:SS)\">%s</div>", jbuf, time_buf);

        if (item_id) {
          snprintf(jbuf, sizeof(jbuf),
                   "ssEditField5(%d, %d, %d, %d, %d,this.getDisplayedValue())",
                   edit_op, item_id, ce->field_id, 2,
                   SSERV_CMD_EDIT_CONTEST_PAGE_2);
        } else {
          snprintf(jbuf, sizeof(jbuf),
                   "ssEditField2(%d, %d, %d, %d, this.getDisplayedValue())",
                   edit_op, ce->field_id, 2,
                   SSERV_CMD_EDIT_CONTEST_PAGE_2);
        }
        fprintf(out_f, "<div class=\"cnts_edit_inlined\">&nbsp;Day: </div><div class=\"cnts_edit_inlined\">");
        fprintf(out_f,
                "<input type=\"text\" name=\"date\"%s"
                " size=\"12\""
                " dojoType=\"dijit.form.DateTextBox\""
                " constraints=\"{datePattern: 'y/M/d', min:'1970-01-01', max:'2037-12-31'}\""
                /*                " required=\"true\"" */
                " onChange=\"%s\""
                " promptMessage=\"yyyy/mm/dd\""
                " invalidMessage=\"Invalid date. Use yyyy/mm/dd format.\" />",
                date_buf, jbuf);
        fprintf(out_f, "</div>");

        if (dflt_ptr && is_undef) {
          time_t val = *(time_t *) u_ptr;
          if (val > 0) {
            snprintf(dflt_str, sizeof(dflt_str), "%s", xml_unparse_date(val));
          }
        }
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

        l10n_html_locale_select_2(out_f, 0, 0, 0, eprintf(jbuf, sizeof(jbuf), "ssEditField(%d, %d, %d, this.options[this.selectedIndex].value)", SSERV_CMD_EDIT_CONTEST_XML_FIELD, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2), locale_code);
      }
      break;
    case 129:
      {
        int reg_mode = *(unsigned char*) v_ptr;

        ss_html_int_select(out_f, 0, 0, 0,
                           eprintf(jbuf, sizeof(jbuf), "ssEditField(%d, %d, %d, this.options[this.selectedIndex].value)", SSERV_CMD_EDIT_CONTEST_XML_FIELD, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2),
                           !!reg_mode,
                           2, (const char *[]) { "Moderated registration", "Free registration" });
      }
      break;
    case 132:
      {
        int param = global->score_system;
        if (global->is_virtual) {
          if (global->score_system == SCORE_ACM) param = SCORE_TOTAL;
          else param = SCORE_TOTAL + 1;
        }

        ss_html_int_select(out_f, 0, 0, 0,
                           eprintf(jbuf, sizeof(jbuf), "ssEditField(%d, %d, %d, this.options[this.selectedIndex].value)", SSERV_CMD_EDIT_SERVE_GLOBAL_FIELD, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2), param,
                           6, (const char *[]) { "ACM", "Kirov", "Olympiad", "Moscow", "Virtual ACM", "Virtual Olympiad" });
      }
      break;
    case 133:
      {
        int value = !phr->ss->disable_compilation_server;
        if (!ce->is_editable) {
          fprintf(out_f, "%s", value?"Yes":"No");
          break;
        }
        ss_html_int_select(out_f, 0, 0, 0,
                           eprintf(jbuf, sizeof(jbuf), "ssEditField(%d, %d, %d, this.options[this.selectedIndex].value)", SSERV_CMD_EDIT_SID_STATE_FIELD_NEGATED, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2),
                           value,
                           2, (const char *[]) { "No", "Yes" });
      }
      break;
    case 134:
      {
        unsigned char *y_ptr = (unsigned char*) v_ptr;
        int locale_code = -1;

        is_empty = 1;
        if (!y_ptr) y_ptr = "";
        if (*y_ptr) locale_code = l10n_parse_locale(y_ptr);
        if (locale_code >= 0) is_empty = 0;

        l10n_html_locale_select_2(out_f, 0, 0, 0, eprintf(jbuf, sizeof(jbuf), "ssEditField(%d, %d, %d, this.options[this.selectedIndex].value)", SSERV_CMD_EDIT_SERVE_GLOBAL_FIELD, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2), locale_code);
      }
      break;
    case 135:
      // ejintbool_t from serve_state
      {
        ejintbool_t *y_ptr = (ejintbool_t*) ss_sid_state_get_ptr_nc(phr->ss, ce->field_id);
        if (!ce->is_editable) {
          fprintf(out_f, "%s", *y_ptr?"Yes":"No");
          break;
        }
        ss_html_int_select(out_f, 0, 0, 0,
                           eprintf(jbuf, sizeof(jbuf), "ssEditField(%d, %d, %d, this.options[this.selectedIndex].value)", SSERV_CMD_EDIT_SID_STATE_FIELD, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2),
                           !!*y_ptr,
                           2, (const char *[]) { "No", "Yes" });
      }
      break;
    case 136:
      {
        int param = global->rounding_mode;
        ss_html_int_select(out_f, 0, 0, 0,
                           eprintf(jbuf, sizeof(jbuf), "ssEditField(%d, %d, %d, this.options[this.selectedIndex].value)", SSERV_CMD_EDIT_SERVE_GLOBAL_FIELD, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2), param,
                           3, (const char *[]) { "Truncating up (ceil)", "Truncating down (floor)", "Rounding" });
      }
      break;
    case 138:
      // lang_opts
      {
        const unsigned char *s = phr->ss->lang_opts[item_id];
        if (s) fprintf(out_f, "%s", s);
        if (!s || !*s) is_empty = 1;
      }
      break;
    case 144:
      // lang_libs
      {
        const unsigned char *s = phr->ss->lang_libs[item_id];
        if (s) fprintf(out_f, "%s", s);
        if (!s || !*s) is_empty = 1;
      }
      break;
    case 139:
      // base problem dialog
      {
        const unsigned char *base_prob = (const unsigned char *) v_ptr;
        const unsigned char *s;
        const struct section_problem_data *ap;

        snprintf(jbuf, sizeof(jbuf), "ssEditField4(%d, %d, %d, %d, this.options[this.selectedIndex].value)", edit_op, item_id, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2);
        fprintf(out_f, "<select onChange='%s'>", jbuf);
        fprintf(out_f, "<option></option>");
        for (i = 0; i < phr->ss->aprob_u; ++i) {
          if (!(ap = phr->ss->aprobs[i])) continue;
          s = "";
          if (!strcmp(ap->short_name, base_prob))
            s = " selected=\"1\"";
          fprintf(out_f, "<option%s>%s</option>", s, ARMOR(ap->short_name));
        }
        fprintf(out_f, "</select>");
      }
      break;
    case 140:
      // stand_column dialog
      {
        const unsigned char *st_prob = (const unsigned char *) v_ptr;
        const unsigned char *s;
        const struct section_problem_data *p;

        snprintf(jbuf, sizeof(jbuf), "ssEditField4(%d, %d, %d, %d, this.options[this.selectedIndex].value)", edit_op, item_id, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2);
        fprintf(out_f, "<select onChange='%s'>", jbuf);
        fprintf(out_f, "<option></option>");
        for (i = 0; i < phr->ss->prob_a; ++i) {
          if (!(p = phr->ss->probs[i])) continue;
          if (i == item_id) continue;
          s = "";
          if (!strcmp(p->short_name, st_prob))
            s = " selected=\"1\"";
          fprintf(out_f, "<option%s>%s</option>", s, ARMOR(p->short_name));
          if (p->stand_name[0]) {
            s = "";
            if (!strcmp(p->stand_name, st_prob))
              s = " selected=\"1\"";
            fprintf(out_f, "<option%s>%s</option>", s, ARMOR(p->stand_name));
          }
        }
        fprintf(out_f, "</select>");
      }
      break;
    case 141:
      {
        int prob_type = *(int*) v_ptr;
        const unsigned char *s = "";

        snprintf(jbuf, sizeof(jbuf), "ssEditField4(%d, %d, %d, %d, this.options[this.selectedIndex].value)", edit_op, item_id, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2);
        fprintf(out_f, "<select onChange='%s'>", jbuf);
        if (prob_type == -1) s = " selected=\"1\"";
        fprintf(out_f, "<option value=\"-1\"%s>Undefined</option>", s);
        for (i = 0; i < PROB_TYPE_LAST; i++) {
          s = "";
          if (prob_type == i) s = " selected=\"1\"";
          fprintf(out_f, "<option value=\"%d\"%s>%s</option>\n",
                  i, s, problem_unparse_type(i));
        }
        fprintf(out_f, "</select>");
      }
      break;
    case 142:
      {
        int was_marked = 0;
        const unsigned char *checker = (const unsigned char *) v_ptr;
        const unsigned char *s = "";
        struct std_checker_info *si;

        snprintf(jbuf, sizeof(jbuf), "ssEditField4(%d, %d, %d, %d, this.options[this.selectedIndex].value)", edit_op, item_id, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2);
        fprintf(out_f, "<select onChange='%s'>", jbuf);
        if (is_undef) {
          s = " selected=\"1\"";
          was_marked = 1;
        }
        fprintf(out_f, "<option value=\"%s\"%s>%s</option>",
                "__undefined__", s, "Undefined");
        for (si = super_html_std_checkers; si->name; ++si) {
          s = "";
          if (!strcmp(checker, si->name)) {
            s = " selected=\"1\"";
            was_marked = 1;
          }
          fprintf(out_f, "<option value=\"%s\"%s>%s</option>",
                  si->name, s, si->desc);
        }
        if (!was_marked) {
          s = " selected=\"1\"";
          fprintf(out_f, "<option value=\"%s\"%s>", ARMOR(checker), s);
          fprintf(out_f, "Unknown - %s</option>", ARMOR(checker));
        }
        fprintf(out_f, "</select>\n");
      }
      break;
    case 143:
      {
        int value = phr->ss->enable_win32_languages;
        if (!ce->is_editable) {
          fprintf(out_f, "%s", value?"Yes":"No");
          break;
        }
        ss_html_int_select(out_f, 0, 0, 0,
                           eprintf(jbuf, sizeof(jbuf), "ssEditField(%d, %d, %d, this.options[this.selectedIndex].value)", SSERV_CMD_EDIT_SID_STATE_FIELD, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2),
                           value,
                           2, (const char *[]) { "No", "Yes" });
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
          if (item_id) {
            snprintf(jbuf, sizeof(jbuf), "ssLoad3(%d, %d, %d)",
                     ce->has_details, item_id, ce->field_id);
          } else {
            snprintf(jbuf, sizeof(jbuf), "ssLoad2(%d, %d)",
                     ce->has_details, ce->field_id);
          }
          ss_dojo_button(out_f, 0, "edit_page-16x16", "Edit contents","%s", jbuf);
        }
        if (item_id) {
          snprintf(jbuf, sizeof(jbuf), "ssFieldRequest2(%d, %d, %d, %d)",
                   clear_op, item_id, ce->field_id,
                   SSERV_CMD_EDIT_CONTEST_PAGE_2);
        } else {
          snprintf(jbuf, sizeof(jbuf), "ssFieldRequest(%d, %d, %d)",
                   clear_op, ce->field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2);

        }
        ss_dojo_button(out_f, 0, "delete-16x16", "Clear variable", "%s", jbuf);
      }
    } else if (ce->has_details) {
      if (item_id) {
        snprintf(jbuf, sizeof(jbuf), "ssLoad3(%d, %d, %d)",
                 ce->has_details, item_id, ce->field_id);
      } else {
        snprintf(jbuf, sizeof(jbuf), "ssLoad2(%d, %d)",
                 ce->has_details, ce->field_id);
      }
      ss_dojo_button(out_f, 0, "edit_page-16x16", "Edit contents", "%s", jbuf);
    }
    fprintf(out_f, "</td>");

    if (need_dv_column && dflt_str[0]) {
      fprintf(out_f, "<td class=\"cnts_edit_legend\">(<i>%s</i>)</td>",
              dflt_str);
      has_dv_column = 1;
    }
    if (need_dv_column && !has_dv_column) {
      fprintf(out_f, "<td class=\"cnts_edit_legend\">&nbsp;</td>");
    }

    fprintf(out_f, "<tr>\n");
  }

  html_armor_free(&ab);
}

static void
write_languages_page(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int i;
  const struct section_global_data *global = phr->ss->global;
  const struct section_language_data *cs_lang, *lang;
  const unsigned char *cs_name, *lang_name, *cmt, *td_attr;
  unsigned char buf[1024];
  const struct edit_page_desc *pg = &edit_page_descs[2];
  const struct contest_desc *ecnts = phr->ss->edited_cnts;
  unsigned char cs_conf_file[PATH_MAX];

  if (phr->ss->serve_parse_errors) {
    fprintf(out_f, "<h2><tt>serve.cfg</tt> cannot be edited</h2>\n"
            "<font color=\"red\"><pre>%s</pre></font>\n",
            ARMOR(phr->ss->serve_parse_errors));
    goto cleanup;
  }

  if (phr->ss->disable_compilation_server) {
    fprintf(out_f, "<h2>Compilation server is disabled</h2>\n");
    goto cleanup;
  }

  if (!phr->ss->global) {
    fprintf(out_f, "<h2><tt>serve.cfg</tt> is not existant</h2>\n");
    goto cleanup;
  }

  if (!phr->ss->cs_langs_loaded) {
    super_load_cs_languages(phr->config, phr->ss, global->extra_compile_dirs,
                            1, cs_conf_file, sizeof(cs_conf_file));
  }

  if (!phr->ss->cs_langs) {
    fprintf(out_f, "<h2>No compilation server is available</h2>\n");
    goto cleanup;
  }

  for (i = 1; i < phr->ss->cs_lang_total; i++) {
    if (!(cs_lang = phr->ss->cs_langs[i])) continue;
    if (!(cs_name = phr->ss->cs_lang_names[i]) || !*cs_name) continue;
    lang = 0;
    if (phr->ss->cs_loc_map[i] > 0)
      lang = phr->ss->langs[phr->ss->cs_loc_map[i]];
    if (lang && lang->long_name[0]) {
      lang_name = lang->long_name;
      if (!phr->ss->cs_lang_names[i]) {
        cmt = " <font color=\"magenta\">(No version script!)</font>";
      } else if (!*phr->ss->cs_lang_names[i]) {
        cmt = " <font color=\"red\">(Version script failed!)</font>";
      } else {
        snprintf(buf, sizeof(buf), " (%s)", phr->ss->cs_lang_names[i]);
        cmt = buf;
      }
    } else if (!phr->ss->cs_lang_names[i]) {
      cmt = " <font color=\"magenta\">(No version script!)</font>";
      lang_name = cs_lang->long_name;
    } else if (!*phr->ss->cs_lang_names[i]) {
      cmt = " <font color=\"red\">(Version script failed!)</font>";
      lang_name = cs_lang->long_name;
    } else {
      cmt = "";
      lang_name = phr->ss->cs_lang_names[i];
    }
    td_attr = "";
    if (lang && lang->insecure && global && global->secure_run > 0) {
      td_attr = " bgcolor=\"#ffffdd\"";
    } else if (lang) {
      td_attr = " bgcolor=\"#ddffdd\"";
    }

    fprintf(out_f,
            "<tr%s><td class=\"cnts_edit_head\" colspan=\"2\">%s %s</td>",
            td_attr, ARMOR(lang_name), cmt);
    fprintf(out_f, "<td class=\"cnts_edit_head\">");

    if (lang) {
      if (!phr->ss->lang_flags[lang->id]) {
        ss_dojo_button(out_f, 0, "zoom_in-16x16", "Show Detail",
                    "ssSetValue3(%d, %d, %d, %d, 1)",
                    SSERV_CMD_SET_SID_STATE_LANG_FIELD, i,
                    SSSS_lang_flags, SSERV_CMD_EDIT_CONTEST_PAGE_2);
      } else {
        ss_dojo_button(out_f, 0, "zoom_out-16x16", "Hide Detail",
                    "ssSetValue3(%d, %d, %d, %d, 0)",
                    SSERV_CMD_SET_SID_STATE_LANG_FIELD, i,
                    SSSS_lang_flags, SSERV_CMD_EDIT_CONTEST_PAGE_2);
      }
      if (!phr->ss->loc_cs_map[lang->id]) {
        ss_dojo_button(out_f, 0, "delete-16x16", "Deactivate",
                    "ssSetValue3(%d, %d, %d, %d, 0)",
                    SSERV_CMD_SET_SID_STATE_LANG_FIELD, i,
                    SSSS_langs, SSERV_CMD_EDIT_CONTEST_PAGE_2);
      }
    } else {
      ss_dojo_button(out_f, 0, "add-16x16", "Activate",
                  "ssSetValue3(%d, %d, %d, %d, 1)",
                  SSERV_CMD_SET_SID_STATE_LANG_FIELD, i,
                  SSSS_langs, SSERV_CMD_EDIT_CONTEST_PAGE_2);
    }

    fprintf(out_f, "</td>");
    fprintf(out_f, "</tr>\n");

    if (!lang || !phr->ss->lang_flags[lang->id]) continue;
    ASSERT(lang->compile_id == i);

    phr->ss->cur_lang = lang;
    write_editing_rows(log_f, out_f, phr, pg, ecnts, global, lang, lang->id,
                       0, 0);
  }

 cleanup:
  html_armor_free(&ab);
}

static void
write_problem_page(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr,
        int ind,
        const struct section_problem_data *prob)
{
  int flags = 0;
  struct sid_state *ss = phr->ss;
  int show_details = 0;
  int show_adv = 0;
  int item_id, i;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const struct section_global_data *global = phr->ss->global, *glob = 0;
  const struct edit_page_desc *pg = &edit_page_descs[3];
  const struct contest_desc *ecnts = phr->ss->edited_cnts;
  struct section_problem_data tmp_prob;
  const struct section_problem_data *aprob = 0;

  if (!prob) return;

  if (prob->abstract) {
    flags = ss->aprob_flags[ind];
    item_id = -ind - 1;
  } else {
    flags = ss->prob_flags[ind];
    item_id = ind;
    for (i = 0; i < phr->ss->aprob_u; ++i)
      if (phr->ss->aprobs[i] && prob->super[0]
          && !strcmp(phr->ss->aprobs[i]->short_name, prob->super))
        aprob = phr->ss->aprobs[i];
    glob = global;
  }
  if ((flags & SID_STATE_SHOW_HIDDEN)) show_details = 1;
  if ((flags & SID_STATE_SHOW_CLOSED)) show_adv = 1;
  cntsprob_copy_and_set_default(&tmp_prob, prob, aprob, glob);
  ss->cur_prob = &tmp_prob;
  ss->prob_show_adv = show_adv;

  fprintf(out_f,
          "<tr%s><td class=\"cnts_edit_head\" colspan=\"2\">", head_row_attr);
  if (prob->abstract) {
    fprintf(out_f, "%s", ARMOR(prob->short_name));
  } else {
    if (!prob->short_name[0]) {
      fprintf(out_f, "Problem %d", prob->id);
    } else if (!prob->long_name[0]) {
      fprintf(out_f, "%s", ARMOR(prob->short_name));
    } else {
      fprintf(out_f, "%s: ", ARMOR(prob->short_name));
      fprintf(out_f, "%s", ARMOR(prob->long_name));
    }
  }
  fprintf(out_f, "</td><td class=\"cnts_edit_head\">");
  if (!show_details) {
    ss_dojo_button(out_f, 0, "zoom_in-16x16", "Show Problem",
                "ssSetValue3(%d, %d, %d, %d, 1)",
                SSERV_CMD_SET_SID_STATE_PROB_FIELD, item_id,
                SSSS_prob_flags, SSERV_CMD_EDIT_CONTEST_PAGE_2);
  } else {
    ss_dojo_button(out_f, 0, "zoom_out-16x16", "Hide Problem",
                "ssSetValue3(%d, %d, %d, %d, 0)",
                SSERV_CMD_SET_SID_STATE_PROB_FIELD, item_id,
                SSSS_prob_flags, SSERV_CMD_EDIT_CONTEST_PAGE_2);
  }
  ss_dojo_button(out_f, 0, "delete-16x16", "Delete Problem",
              "ssFieldRequest2(%d, %d, 0, %d)",
              SSERV_CMD_DELETE_PROB, item_id,
              SSERV_CMD_EDIT_CONTEST_PAGE_2);
  fprintf(out_f, "</td><td class=\"cnts_edit_head\">&nbsp;</td></tr>\n");
  if (!show_details) goto cleanup;

  fprintf(out_f, "<tr%s><td class=\"cnts_edit_legend\">%s</td><td class=\"cnts_edit_legend\" width=\"600px\">%d</td><td class=\"cnts_edit_clear\">",
          form_row_attrs[1], "Id", prob->id);
  if (!show_adv) {
    ss_dojo_button(out_f, 0, "zoom_in-16x16", "Show Extra Info",
                "ssSetValue3(%d, %d, %d, %d, 1)",
                SSERV_CMD_SET_SID_STATE_PROB_FIELD, item_id,
                SSSS_cur_prob, SSERV_CMD_EDIT_CONTEST_PAGE_2);
  } else {
    ss_dojo_button(out_f, 0, "zoom_out-16x16", "Hide Extra Info",
                "ssSetValue3(%d, %d, %d, %d, 0)",
                SSERV_CMD_SET_SID_STATE_PROB_FIELD, item_id,
                SSSS_cur_prob, SSERV_CMD_EDIT_CONTEST_PAGE_2);
  }
  fprintf(out_f, "</td><td class=\"cnts_edit_legend\">&nbsp;</td></tr>\n");

  write_editing_rows(log_f, out_f, phr, pg, ecnts, global, prob, item_id, 1,
                     &tmp_prob);

 cleanup:
  html_armor_free(&ab);
}

static void
write_problems_page(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int i;

  if (phr->ss->serve_parse_errors) {
    fprintf(out_f, "<h2><tt>serve.cfg</tt> cannot be edited</h2>\n"
            "<font color=\"red\"><pre>%s</pre></font>\n",
            ARMOR(phr->ss->serve_parse_errors));
    goto cleanup;
  }

  if (!phr->ss->global) {
    fprintf(out_f, "<h2><tt>serve.cfg</tt> is not existant</h2>\n");
    goto cleanup;
  }

  fprintf(out_f,
          "<tr%s><td class=\"cnts_edit_head\" colspan=\"4\">%s</td></tr>\n",
          head_row_attr, "Abstract problems");
  for (i = 0; i < phr->ss->aprob_u; ++i) {
    write_problem_page(log_f, out_f, phr, i, phr->ss->aprobs[i]);
  }
  fprintf(out_f,
          "<tr%s><td class=\"cnts_edit_head\" colspan=\"4\">%s</td></tr>\n",
          head_row_attr, "Create a new abstract problem");
  fprintf(out_f, "<form id=\"createAbstrProb\"><tr%s><td class=\"cnts_edit_legend\">%s:</td><td class=\"cnts_edit_data\" width=\"600px\">", form_row_attrs[0], "Name");
  fprintf(out_f, "<input type=\"text\" name=\"prob_name\" />");
  fprintf(out_f, "</td><td class=\"cnts_edit_clear\">");
  ss_dojo_button(out_f, 0, "add-16x16", "Create",
              "ssFormOp1(\"createAbstrProb\", %d, %d)",
              SSERV_CMD_CREATE_ABSTR_PROB, SSERV_CMD_EDIT_CONTEST_PAGE_2);
  fprintf(out_f, "</td><td class=\"cnts_edit_legend\">&nbsp;</td></tr>\n");

  fprintf(out_f,
          "<tr%s><td class=\"cnts_edit_head\" colspan=\"4\">%s</td></tr>\n",
          head_row_attr, "Concrete problems");
  for (i = 0; i < phr->ss->prob_a; ++i) {
    write_problem_page(log_f, out_f, phr, i, phr->ss->probs[i]);
  }
  fprintf(out_f,
          "<tr%s><td class=\"cnts_edit_head\" colspan=\"4\">%s</td></tr>\n",
          head_row_attr, "Create a new concrete problem");
  fprintf(out_f, "<form id=\"createConcrProb\"><tr%s><td class=\"cnts_edit_legend\">%s:</td><td class=\"cnts_edit_data\" width=\"600px\">", form_row_attrs[0], "Id (optional)");
  fprintf(out_f, "<input type=\"text\" name=\"prob_id\" />");
  fprintf(out_f, "</td><td class=\"cnts_edit_clear\">");
  ss_dojo_button(out_f, 0, "add-16x16", "Create",
              "ssFormOp1(\"createAbstrProb\", %d, %d)",
              SSERV_CMD_CREATE_CONCRETE_PROB, SSERV_CMD_EDIT_CONTEST_PAGE_2);
  fprintf(out_f, "</td><td class=\"cnts_edit_legend\">&nbsp;</td></tr>\n");

 cleanup:
  html_armor_free(&ab);
}

static int
contest_xml_page(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  struct contest_desc *ecnts = phr->ss->edited_cnts;
  unsigned char buf[1024];
  int i, page = 0;
  const unsigned char *ss = 0;
  const struct edit_page_desc *pg;
  const struct section_global_data *global = 0;
  void *edit_ptr = 0;

  if (hr_cgi_param_int(phr, "page", &page) < 0 || page < 0 || page > 3)
    page = phr->ss->edit_page;
  phr->ss->edit_page = page;
  pg = &edit_page_descs[page];

  snprintf(buf, sizeof(buf), "serve-control: %s, editing contest %d",
           phr->html_name, ecnts->id);
  write_html_header(out_f, phr, buf, 1, 0);

  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  // write tabs
  fprintf(out_f, "<div id=\"tabs\">\n");
  fprintf(out_f, "<ul>\n");
  for (i = 0; i < 4; ++i) {
    ss = "";
    if (page == i) ss = " id=\"selected\"";
    fprintf(out_f, "<li%s onClick='ssEditPage(%d,%d)'>%s</li>\n", ss,
            SSERV_CMD_EDIT_CONTEST_PAGE_2, i, edit_page_descs[i].label);
  }
  fprintf(out_f, "</ul>\n");
  fprintf(out_f, "</div>\n");

  switch (page) {
  case 0:
    edit_ptr = ecnts;
    break;
  case 1:
    edit_ptr = phr->ss->global;
    global = phr->ss->global;
    break;
  }

  // write the main content
  fprintf(out_f, "<div id=\"cnts_edit_content\">\n");
  fprintf(out_f, "<table class=\"cnts_edit\">\n");
  switch (page) {
  case 2:                       /* languages */
    write_languages_page(log_f, out_f, phr);
    break;
  case 3:
    write_problems_page(log_f, out_f, phr);
    break;
  default:
    write_editing_rows(log_f, out_f, phr, pg, ecnts, global, edit_ptr, -1, 0,
                       0);
  }
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</div>\n");

  if (page == 2) {
    ss_dojo_button(out_f, "100", "refresh-32x32", "Update versions",
                "ssFieldRequest(%d, 0, %d)",
                SSERV_CMD_SERVE_LANG_UPDATE_VERSIONS,
                SSERV_CMD_EDIT_CONTEST_PAGE_2);
  }

  ss_dojo_button(out_f, "1", "home-32x32", "To the Top",
              "ssTopLevel()");
  ss_dojo_button(out_f, "2", "accept-32x32", "Save Changes",
              "ssCommitContest(%d)", SSERV_CMD_CNTS_COMMIT_PAGE);
  ss_dojo_button(out_f, "3", "cancel-32x32", "Forget Changes",
              "ssForgetContest(%d)", SSERV_CMD_FORGET_CONTEST);

  write_html_footer(out_f);
  return 0;
}

static int
cmd_edit_contest_page(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int contest_id = 0;
  const struct contest_desc *cnts = 0;
  struct contest_desc *rw_cnts = 0;
  unsigned char buf[1024];
  const struct sid_state *other_ss;

  if (hr_cgi_param_int(phr, "contest_id", &contest_id) < 0
      || contest_id <= 0 || contest_id > EJ_MAX_CONTEST_ID)
    FAIL(SSERV_ERR_INV_CONTEST);
  if (contests_get(contest_id, &cnts) < 0 || !cnts)
    FAIL(SSERV_ERR_INV_CONTEST);

  if (phr->priv_level != PRIV_LEVEL_ADMIN)
    FAIL(SSERV_ERR_PERM_DENIED);
  if (opcaps_find(&cnts->capabilities, phr->login, &phr->caps) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);
  if (opcaps_check(phr->caps, OPCAP_EDIT_CONTEST) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);

  if (phr->ss->edited_cnts && phr->ss->edited_cnts->id == contest_id) {
    return contest_xml_page(log_f, out_f, phr);
  }

  if (phr->ss->edited_cnts) {
    snprintf(buf, sizeof(buf), "serve-control: %s, another contest is edited",
             phr->html_name);
    write_html_header(out_f, phr, buf, 1, 0);
    fprintf(out_f, "<h1>%s</h1>\n", buf);

    snprintf(buf, sizeof(buf),
             "<input type=\"hidden\" name=\"SID\" value=\"%016llx\" />",
             phr->session_id);
    super_html_edited_cnts_dialog(out_f,
                                  phr->priv_level, phr->user_id, phr->login,
                                  phr->session_id, &phr->ip, phr->config,
                                  phr->ss, phr->self_url, buf,
                                  "", cnts, 1);

    write_html_footer(out_f);
    return 0;
  }

  if ((other_ss = super_serve_sid_state_get_cnts_editor(contest_id))) {
    snprintf(buf, sizeof(buf),
             "serve-control: %s, the contest is edited in another session",
             phr->html_name);
    write_html_header(out_f, phr, buf, 1, 0);
    fprintf(out_f, "<h1>%s</h1>\n", buf);

    snprintf(buf, sizeof(buf),
             "<input type=\"hidden\" name=\"SID\" value=\"%016llx\" />",
             phr->session_id);
    super_html_locked_cnts_dialog(out_f,
                                  phr->priv_level, phr->user_id, phr->login,
                                  phr->session_id, &phr->ip, phr->config,
                                  phr->ss, phr->self_url, buf,
                                  "", contest_id, other_ss, 1);

    write_html_footer(out_f);
    return 0;
  }

  if (contests_load(contest_id, &rw_cnts) < 0 || !rw_cnts)
    FAIL(SSERV_ERR_INV_CONTEST);
  phr->ss->edited_cnts = rw_cnts;
  super_html_load_serve_cfg(rw_cnts, phr->config, phr->ss);

  return contest_xml_page(log_f, out_f, phr);

 cleanup:
  return retval;
}

static int
cmd_edit_contest_page_2(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;

  if (!phr->ss->edited_cnts)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);

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
        struct http_request_info *phr)
{
  int retval = 0;
  int f_id = 0;
  int f_type = 0;
  void *f_ptr = 0;
  int f_id2;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_ptr = contest_desc_get_ptr_nc(phr->ss->edited_cnts, f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_type = contest_desc_get_type(f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (f_id == CNTS_user_contest_num || f_id == CNTS_default_locale_num)
    FAIL(SSERV_ERR_INV_FIELD_ID);

  switch (f_type) {
  case 'b':
    {
      unsigned char *b_ptr = (unsigned char*) f_ptr;
      *b_ptr = 0;
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
    FAIL(SSERV_ERR_INV_FIELD_ID);
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

  retval = 1;

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
handle_time_t_editing(
	struct http_request_info *phr,
        const unsigned char *valstr,
        time_t *p_time)
{
  int retval = 0;
  int subf_id = 0;

  if (hr_cgi_param_int(phr, "subfield_id", &subf_id) < 0
      || subf_id < 1 || subf_id > 2)
    FAIL(SSERV_ERR_INV_FIELD_ID);

  // 1 means time, 2 means date
  switch (subf_id) {
  case 1:
    {
      int h, m, s, n;
      int v_len = strlen(valstr);
      unsigned char *v_val;
      time_t t_val;
      struct tm *ptm;

      if (v_len > 1024) FAIL(SSERV_ERR_INV_VALUE);
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
        FAIL(SSERV_ERR_INV_VALUE);
      }
      if (h < 0 || h >= 24) FAIL(SSERV_ERR_INV_VALUE);
      if (m < 0 || m >= 60) FAIL(SSERV_ERR_INV_VALUE);
      if (s < 0 || s >= 60) FAIL(SSERV_ERR_INV_VALUE);
      t_val = *p_time;
      if (t_val <= 0) t_val = time(0);
      ptm = localtime(&t_val);
      ptm->tm_hour = h;
      ptm->tm_min = m;
      ptm->tm_sec = s;
      if ((t_val = mktime(ptm)) <= 0) FAIL(SSERV_ERR_INV_VALUE);
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
      if (v_len > 1024) FAIL(SSERV_ERR_INV_VALUE);
      v_val = (unsigned char*) alloca(v_len + 1);
      strcpy(v_val, valstr);
      if (v_len > 0 && isspace(v_val[v_len - 1])) --v_len;
      v_val[v_len] = 0;

      if (sscanf(v_val, "%d/%d/%d%n", &y, &m, &d, &n) != 3 || v_val[n])
        FAIL(SSERV_ERR_INV_VALUE);
      if (y < 1970 || y > 2030) FAIL(SSERV_ERR_INV_VALUE);
      if (m < 1 || m > 12) FAIL(SSERV_ERR_INV_VALUE);
      if (d < 1 || d > 31) FAIL(SSERV_ERR_INV_VALUE);
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
      if ((t_val = mktime(&btm)) <= 0) FAIL(SSERV_ERR_INV_VALUE);
      *p_time = t_val;
      retval = 1;
    }
    break;
  default:
    FAIL(SSERV_ERR_INV_FIELD_ID);
  }

 cleanup:
  return retval;
}

static unsigned char contest_str_need_space[CNTS_LAST_FIELD] =
{
  [CNTS_users_head_style] = 1,
  [CNTS_users_par_style] = 1,
  [CNTS_users_table_style] = 1,
  [CNTS_users_verb_style] = 1,
  [CNTS_register_head_style] = 1,
  [CNTS_register_par_style] = 1,
  [CNTS_register_table_style] = 1,
  [CNTS_team_head_style] = 1,
  [CNTS_team_par_style] = 1,
};

static int
cmd_edit_contest_xml_field(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int f_id = 0, f_id2 = 0;
  int f_type = 0;
  void *f_ptr = 0;
  const unsigned char *valstr = 0;
  struct contest_desc *ecnts = 0;
  int utf8_id = 0, vallen;
  struct html_armor_buffer vb = HTML_ARMOR_INITIALIZER;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  ecnts = phr->ss->edited_cnts;
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_ptr = contest_desc_get_ptr_nc(ecnts, f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_type = contest_desc_get_type(f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (f_id == CNTS_user_contest_num || f_id == CNTS_default_locale_num)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (hr_cgi_param(phr, "value", &valstr) <= 0 || !valstr)
    FAIL(SSERV_ERR_INV_VALUE);
  if ((vallen = strlen(valstr)) > 16384)
    FAIL(SSERV_ERR_INV_VALUE);

  // strip off trailing space
  if (vallen > 0 && isspace(valstr[vallen - 1])) {
    unsigned char *tmps = (unsigned char*) alloca(vallen + 1);
    memcpy(tmps, valstr, vallen + 1);
    while (vallen > 0 && isspace(tmps[vallen - 1])) --vallen;
    tmps[vallen] = 0;
    valstr = tmps;
  }
  // insert the first space, if needed
  if (vallen > 0 && contest_str_need_space[f_id] && !isspace(valstr[0])) {
    unsigned char *tmps = (unsigned char*) alloca(vallen + 2);
    tmps[0] = ' ';
    memcpy(tmps + 1, valstr, vallen + 1);
    valstr = tmps;
  }

  // value is in utf-8, translate it to the local charset
  utf8_id = charset_get_id("utf-8");
  valstr = charset_decode(utf8_id, &vb, valstr);

  if (check_path_set[f_id]) {
    // must end in '.html' or '.shtml'
    // must not contain / or start with .
    if (strchr(valstr, '/')) 
      FAIL(SSERV_ERR_INV_VALUE);
    if (valstr[0] == '.')
      FAIL(SSERV_ERR_INV_VALUE);
    if (!ends_with(valstr, ".html") && !ends_with(valstr, ".shtml")
        && !ends_with(valstr, ".txt"))
      FAIL(SSERV_ERR_INV_VALUE);
  }

  switch (f_type) {
  case 'b':
    {
      unsigned char *p_bool = (unsigned char *) f_ptr;
      int newval, n = 0;

      if (sscanf(valstr, "%d%n", &newval, &n) != 1 || valstr[n]
          || newval < 0 || newval > 1)
        FAIL(SSERV_ERR_INV_VALUE);
      if (*p_bool == newval) goto cleanup;
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
          FAIL(SSERV_ERR_INV_VALUE);
        if (!newval) {
          xfree(ecnts->user_contest);
          ecnts->user_contest = 0;
          ecnts->user_contest_num = 0;
          retval = 1;
          goto cleanup;
        }
        if (ecnts->id == newval)
          FAIL(SSERV_ERR_INV_VALUE);
        if (contests_get(newval, &cnts) < 0 || !cnts)
          FAIL(SSERV_ERR_INV_VALUE);
        if (cnts->user_contest_num > 0)
          FAIL(SSERV_ERR_INV_VALUE);
      }
      if (f_id == CNTS_default_locale) {
        if ((newval = l10n_parse_locale(valstr)) < 0)
          FAIL(SSERV_ERR_INV_VALUE);
      }
      if (f_id == CNTS_register_email
          || f_id == CNTS_cf_notify_email
          || f_id == CNTS_clar_notify_email
          || f_id == CNTS_daily_stat_email) {
        if (valstr && *valstr && !is_valid_email_address(valstr)) {
          FAIL(SSERV_ERR_INV_VALUE);
        }
      }

      if (!*p_str) {
        retval = 1;
      } else {
        if (!strcmp(*p_str, valstr)) goto cleanup;
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
    retval = handle_time_t_editing(phr, valstr, (time_t*) f_ptr);
    break;
  default:
    FAIL(SSERV_ERR_INV_FIELD_ID);
  }

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

  // these are visibilities for global configuration page
  [SSSS_show_global_1] = 1,
  [SSSS_show_global_2] = 1,
  [SSSS_show_global_3] = 1,
  [SSSS_show_global_4] = 1,
  [SSSS_show_global_5] = 1,  
  [SSSS_show_global_6] = 1,  
  [SSSS_show_global_7] = 1,  
};

static int
cmd_toggle_contest_xml_vis(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0, f_id;
  int *p_int;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= SSSS_LAST_FIELD
      || !valid_ss_visibilities[f_id])
    FAIL(SSERV_ERR_INV_FIELD_ID);
  p_int = ss_sid_state_get_ptr_nc(phr->ss, f_id);
  if (*p_int) *p_int = 0;
  else *p_int = 1;

  retval = 1;

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
        struct http_request_info *phr)
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
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  ecnts = phr->ss->edited_cnts;
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD
      || !(ss_id = cnts_text_edit_map[f_id]))
    FAIL(SSERV_ERR_INV_FIELD_ID);

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
  ss_dojo_button(out_f, "1", "home-32x32", "To the top level (postpone editing)",
              "alert(\"Clicked TopLevel\")");
  */
  ss_dojo_button(out_f, 0, "accept-32x32", "OK",
              "editFileSave(\"editBox\", %d, %d, %d)",
              SSERV_CMD_SAVE_FILE_CONTEST_XML, f_id,
              SSERV_CMD_EDIT_CONTEST_PAGE_2);
  ss_dojo_button(out_f, 0, "cancel-32x32", "Cancel",
              "ssLoad1(%d)",
              SSERV_CMD_EDIT_CONTEST_PAGE_2);
  ss_dojo_button(out_f, 0, "delete_page-32x32", "Clear",
              "editFileClear(%d, %d, %d)",
              SSERV_CMD_CLEAR_FILE_CONTEST_XML, f_id,
              SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE);
  ss_dojo_button(out_f, 0, "refresh-32x32", "Reload",
              "editFileReload(%d, %d, %d)",
              SSERV_CMD_RELOAD_FILE_CONTEST_XML, f_id,
              SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE);

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
        struct http_request_info *phr)
{
  int retval = 0, f_id, f_id2;
  int *p_int;
  unsigned char **p_str;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD
      || !(f_id2 = cnts_text_edit_map[f_id]))
    FAIL(SSERV_ERR_INV_FIELD_ID);

  p_str = (unsigned char**) ss_sid_state_get_ptr_nc(phr->ss, f_id2);
  xfree(*p_str); *p_str = 0;
  p_int = (int*) ss_sid_state_get_ptr_nc(phr->ss, cnts_text_load_map[f_id]);
  if (phr->action == SSERV_CMD_CLEAR_FILE_CONTEST_XML) {
    *p_int = 1;
  } else {
    *p_int = 0;
  }

  retval = 1;

 cleanup:
  return retval;
}

static int
cmd_save_file_contest_xml(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int f_id = 0, f_id2 = 0;
  const unsigned char *valstr = 0;
  struct html_armor_buffer vb = HTML_ARMOR_INITIALIZER;
  unsigned char **p_str;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_id2 = cnts_text_edit_map[f_id]))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (ss_cgi_param_utf8_str(phr, "param", &vb, &valstr) <= 0 || !valstr)
    FAIL(SSERV_ERR_INV_VALUE);
  p_str = (unsigned char**) ss_sid_state_get_ptr_nc(phr->ss, f_id2);
  xfree(*p_str);
  *p_str = xstrdup(valstr);
  retval = 1;

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

const int access_field_tag[CNTS_LAST_FIELD] =
{
  [CNTS_register_access] = CONTEST_REGISTER_ACCESS,
  [CNTS_users_access] = CONTEST_USERS_ACCESS,
  [CNTS_master_access] = CONTEST_MASTER_ACCESS,
  [CNTS_judge_access] = CONTEST_JUDGE_ACCESS,
  [CNTS_team_access] = CONTEST_TEAM_ACCESS,
  [CNTS_serve_control_access] = CONTEST_SERVE_CONTROL_ACCESS,
};

static int
cmd_contest_xml_access_edit_page(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
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
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  ecnts = phr->ss->edited_cnts;
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD
      || !(access_field_set[f_id]))
    FAIL(SSERV_ERR_INV_FIELD_ID);
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
      fprintf(out_f, "<div class=\"cnts_edit_data\" dojoType=\"dijit.InlineEditBox\" onChange=\"ssEditField3(%d, %d, %d, %d, arguments[0])\" autoSave=\"true\" title=\"%s\">",
              SSERV_CMD_SET_RULE_IP, f_id, i,
              SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE,
              "IP address");
      fprintf(out_f, "%s", xml_unparse_ipv6_mask(&p->addr, &p->mask));
      fprintf(out_f, "</div></td>");

      fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"100px\">");
      ss_html_select(out_f, 0, 0, 0,
                     eprintf(jbuf, sizeof(jbuf), "ssEditField3(%d, %d, %d, %d, this.options[this.selectedIndex].value)", SSERV_CMD_SET_RULE_SSL, f_id, i, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE),
                     eprintf(vbuf, sizeof(vbuf), "%d", p->ssl),
                     3,
                     (const char*[]) { "-1", "0", "1" },
                     (const char*[]) { "Any", "No SSL", "SSL" });
      fprintf(out_f, "</td>");

      fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"100px\">");
      ss_html_int_select(out_f, 0, 0, 0,
                         eprintf(jbuf, sizeof(jbuf), "ssEditField3(%d, %d, %d, %d, this.options[this.selectedIndex].value)", SSERV_CMD_SET_RULE_ACCESS, f_id, i, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE),
                         !!p->allow, 2,
                         (const char*[]) { "Deny", "Allow" });
      fprintf(out_f, "</td>");
      fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"150px\">");
      if (p->b.left) {
        ss_dojo_button(out_f, 0, "back-16x16", "Move Up",
                    "ssFieldCmd3(%d, %d, %d, %d)",
                    SSERV_CMD_FORWARD_RULE, f_id, i,
                    SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE);
      }
      if (p->b.right) {
        ss_dojo_button(out_f, 0, "next-16x16", "Move Down",
                    "ssFieldCmd3(%d, %d, %d, %d)",
                    SSERV_CMD_BACKWARD_RULE, f_id, i,
                    SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE);
      }
      ss_dojo_button(out_f, 0, "delete-16x16", "Delete Rule",
                  "ssFieldCmd3(%d, %d, %d, %d)",
                  SSERV_CMD_DELETE_RULE, f_id, i,
                  SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE);
      fprintf(out_f, "</td>");
      fprintf(out_f, "</tr>\n");
    }
  }

  fprintf(out_f, "<tr%s><td class=\"cnts_edit_legend\" colspan=\"5\" style=\"text-align: center;\"><b>Add a new rule</b></td></tr>\n", head_row_attr);

  fprintf(out_f, "<tr%s>", form_row_attrs[0]);
  fprintf(out_f, "<form id=\"NewIPForm\">\n");
  fprintf(out_f, "<input id=\"HiddenMask\" type=\"hidden\" name=\"ip_mask\" value=\"\" />\n");
  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"100px\">&nbsp;</td>");
  fprintf(out_f, "<td class=\"cnts_edit_data\" width=\"200px\">");
  fprintf(out_f, "<div id=\"NewIPText\" class=\"cnts_edit_data\" dojoType=\"dijit.InlineEditBox\" onChange=\"ssSetHiddenMask('HiddenMask', %d, arguments[0])\" autoSave=\"true\" title=\"%s\"></div></td>",
          SSERV_CMD_CHECK_IP_MASK, "IP address");
  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"100px\">");
  ss_html_select(out_f, 0, 0, "ssl_flag", 0,
                 eprintf(vbuf, sizeof(vbuf), "%d", -1),
                 3,
                 (const char*[]) { "-1", "0", "1" },
                 (const char*[]) { "Any", "No SSL", "SSL" });
  fprintf(out_f, "</td>");

  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"100px\">");
  ss_html_int_select(out_f, 0, 0, "default_allow", 0,
                     1, 2,
                     (const char*[]) { "Deny", "Allow" });
  fprintf(out_f, "</td>");
  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"150px\">");
  ss_dojo_button(out_f, 0, "add-16x16", "Add",
              "ssFormOp3(\"NewIPForm\", %d, %d, %d)",
              SSERV_CMD_ADD_IP, f_id, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE);
  fprintf(out_f, "</td>");
  fprintf(out_f, "</form>");
  fprintf(out_f, "</tr>\n");

  fprintf(out_f, "<tr%s><td class=\"cnts_edit_legend\" colspan=\"5\" style=\"text-align: center;\"><b>Default access</b></td></tr>\n", head_row_attr);

  fprintf(out_f, "<tr%s>", form_row_attrs[0]);
  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"100px\">&nbsp;</td>");
  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"200px\" style=\"text-align: center;\">&nbsp;</td>");
  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"100px\">&nbsp;</td>");

  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"100px\">");
  ss_html_int_select(out_f, 0, 0, 0,
                     eprintf(jbuf, sizeof(jbuf), "ssSetValue2(%d, %d, %d, this.options[this.selectedIndex].value)", SSERV_CMD_SET_DEFAULT_ACCESS, f_id, SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE),
                     1, 2,
                     (const char*[]) { "Deny", "Allow" });
  fprintf(out_f, "</td>");
  fprintf(out_f, "<td class=\"cnts_edit_legend\" width=\"150px\">&nbsp;</td>");
  fprintf(out_f, "</tr>\n");

  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</div>\n");

  fprintf(out_f, "<br/>\n");

  ss_dojo_button(out_f, 0, "back-32x32", "Back", "ssLoad1(%d)",
              SSERV_CMD_EDIT_CONTEST_PAGE_2);
  ss_dojo_button(out_f, 0, "promotion-32x32", "Copy",
              "ssLoad2(%d, %d)", SSERV_CMD_COPY_ACCESS_RULES_PAGE, f_id);

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
        struct http_request_info *phr)
{
  int f_id, retval = 0;

  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!contest_xml_field_edit_cmd[f_id])
    FAIL(SSERV_ERR_INV_FIELD_ID);
  return (*contest_xml_field_edit_cmd[f_id])(log_f, out_f, phr);

 cleanup:
  return retval;
}

static int
cmd_copy_access_rules_page(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int f_id, i, cnts_num;
  struct contest_desc *ecnts;
  unsigned char buf[1024];
  const unsigned char *s;
  const int *cnts_list = 0;
  const struct contest_desc *cnts = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD
      || !access_field_set[f_id])
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);

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

  ss_dojo_button(out_f, 0, "accept-32x32", "OK",
              "ssFormOp3(\"copyForm\", %d, %d, %d)",
              SSERV_CMD_COPY_ACCESS_RULES, f_id,
              SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE);
  ss_dojo_button(out_f, 0, "cancel-32x32", "Cancel",
              "ssLoad2(%d, %d)", SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE, f_id);

  write_html_footer(out_f);

 cleanup:
  html_armor_free(&ab);
  return retval;
}

static int
cmd_copy_all_access_rules_page(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int i, cnts_num;
  struct contest_desc *ecnts;
  unsigned char buf[1024];
  const int *cnts_list = 0;
  const struct contest_desc *cnts = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);

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

  ss_dojo_button(out_f, 0, "accept-32x32", "OK",
              "ssFormOp1(\"copyForm\", %d, %d)",
              SSERV_CMD_COPY_ALL_ACCESS_RULES,
              SSERV_CMD_EDIT_CONTEST_PAGE_2);
  ss_dojo_button(out_f, 0, "cancel-32x32", "Cancel", "ssLoad1(%d)",
              SSERV_CMD_EDIT_CONTEST_PAGE_2);

  write_html_footer(out_f);

 cleanup:
  html_armor_free(&ab);
  return retval;
}

static int
cmd_copy_all_access_rules(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 1;
  int contest_id_2, i;
  struct contest_desc *ecnts = 0;
  const struct contest_desc *cnts = 0;
  const struct contest_access **p_src_access = 0;
  struct contest_access **p_dst_access = 0;

  phr->json_reply = 1;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "contest_id_2", &contest_id_2) < 0
      || contest_id_2 <= 0)
    FAIL(SSERV_ERR_INV_CONTEST);
  if (contest_id_2 == ecnts->id) goto cleanup;
  if (contests_get(contest_id_2, &cnts) < 0 || !cnts)
    FAIL(SSERV_ERR_INV_CONTEST);

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

 cleanup:
    return retval;
}

static int
cmd_copy_all_priv_users_page(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int i, cnts_num;
  struct contest_desc *ecnts;
  unsigned char buf[1024];
  const int *cnts_list = 0;
  const struct contest_desc *cnts = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d, privilege operations",
           phr->html_name, ecnts->id);
  write_html_header(out_f, phr, buf, 1, 0);
  fprintf(out_f, "<h1>%s</h1>\n", buf);
  fprintf(out_f, "<br/>\n");

  fprintf(out_f, "<h2>%s</h2><br/>",
          "Copy user privileges from another contest");

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

  ss_dojo_button(out_f, 0, "accept-32x32", "OK",
              "ssFormOp1(\"copyForm\", %d, %d)",
              SSERV_CMD_COPY_ALL_PRIV_USERS,
              SSERV_CMD_EDIT_CONTEST_PAGE_2);
  ss_dojo_button(out_f, 0, "cancel-32x32", "Cancel", "ssLoad1(%d)",
              SSERV_CMD_EDIT_CONTEST_PAGE_2);

  fprintf(out_f, "<br/><hr/>\n");

  fprintf(out_f, "<h2>%s</h2><br/>",
          "Add a new privileged user");

  fprintf(out_f, "<br/>\n");

  fprintf(out_f, "<form id=\"addUser\">\n");
  fprintf(out_f, "<table>\n");
  fprintf(out_f, "<tr><td>User Login:</td><td><input type=\"text\" name=\"login\" /></td></tr>\n");
  fprintf(out_f, "<tr><td>Permissions:</td><td>"
          "<select name=\"perms\">"
          "<option value=\"1\"></option>"
          "<option value=\"2\">Observer</option>"
          "<option value=\"3\">Judge</option>"
          "<option value=\"4\">Full control</option>"
          "</select></td></tr>\n");
  fprintf(out_f, "</table>\n");
  fprintf(out_f, "</form>\n");

  fprintf(out_f, "<br/>\n");

  ss_dojo_button(out_f, 0, "accept-32x32", "OK",
              "ssFormOp1(\"addUser\", %d, %d)",
              SSERV_CMD_ADD_PRIV_USER,
              SSERV_CMD_EDIT_CONTEST_PAGE_2);
  ss_dojo_button(out_f, 0, "cancel-32x32", "Cancel", "ssLoad1(%d)",
              SSERV_CMD_EDIT_CONTEST_PAGE_2);

  write_html_footer(out_f);

 cleanup:
  html_armor_free(&ab);
  return retval;
}

static int
cmd_edit_permissions_page(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int field_id, j;
  struct opcap_list_item *perms;
  struct contest_desc *ecnts;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char buf[1024];

  if (!(ecnts = phr->ss->edited_cnts)) FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &field_id) < 0 || field_id < 0)
    FAIL(SSERV_ERR_INV_FIELD_ID);

  for (perms = CNTS_FIRST_PERM(ecnts), j = 0; perms && j != field_id;
       perms = CNTS_NEXT_PERM_NC(perms), ++j);
  if (!perms || j != field_id) FAIL(SSERV_ERR_INV_FIELD_ID);

  snprintf(buf, sizeof(buf),
           "serve-control: %s, contest %d, edit user privileges for user %s",
           phr->html_name, ecnts->id, ARMOR(perms->login));
  write_html_header(out_f, phr, buf, 1, 0);
  fprintf(out_f, "<h1>%s</h1>\n", buf);

  fprintf(out_f, "<br/><h2>Typical permissions</h2><br/>\n");

  snprintf(buf, sizeof(buf),
           "ssEditField(%d, %d, %d, this.options[this.selectedIndex].value)",
           SSERV_CMD_SET_PREDEF_PRIV, field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2);

  ss_html_int_select(out_f, 0, 0, 0, buf,
                     opcaps_is_predef_caps(perms->caps),
                     5, predef_caps_names);

  fprintf(out_f, "<br/><hr/><br/><h2>Capabilities in detail</h2><br/>\n");

  fprintf(out_f, "<form id=\"capsList\">\n");
  super_html_print_caps_table(out_f, perms->caps, " class=\"cnts_edit\"",
                              " class=\"cnts_edit_legend\"");
  fprintf(out_f, "</form>\n");
  fprintf(out_f, "<br/>\n");

  ss_dojo_button(out_f, 0, "accept-32x32", "OK",
              "ssFormOp2(\"capsList\", %d, %d, %d)",
              SSERV_CMD_SET_PRIV, field_id, SSERV_CMD_EDIT_CONTEST_PAGE_2);
  ss_dojo_button(out_f, 0, "cancel-32x32", "Cancel", "ssLoad1(%d)",
              SSERV_CMD_EDIT_CONTEST_PAGE_2);
  
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
        struct http_request_info *phr)
{
  int retval = 0;
  struct contest_desc *ecnts;
  int row = 1, ff, val;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char buf[1024];

  if (!(ecnts = phr->ss->edited_cnts)) FAIL(SSERV_ERR_NO_EDITED_CNTS);

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
  ss_dojo_button(out_f, 0, "accept-32x32", "OK", 
              "ssFormOp1(\"fieldList\", %d, %d)",
              SSERV_CMD_EDIT_GENERAL_FIELDS, SSERV_CMD_EDIT_CONTEST_PAGE_2);
  ss_dojo_button(out_f, 0, "cancel-32x32", "Cancel", "ssLoad1(%d)",
              SSERV_CMD_EDIT_CONTEST_PAGE_2);
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
        struct http_request_info *phr)
{
  int retval = 0;
  struct contest_desc *ecnts;
  unsigned char buf[1024];
  int memb_id, ff, row = 1, val;
  struct contest_member *memb;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *cl = " class=\"cnts_edit_legend\"";

  if (!(ecnts = phr->ss->edited_cnts)) FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &memb_id) < 0
      || memb_id < 0 || memb_id >= CONTEST_LAST_MEMBER)
    FAIL(SSERV_ERR_INV_FIELD_ID);
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
  fprintf(out_f, "<tr%s><td%s>Maximum number:</td><td%s>",
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
  ss_dojo_button(out_f, 0, "accept-32x32", "OK",
              "ssFormOp2(\"fieldList\", %d, %d, %d)",
              SSERV_CMD_EDIT_MEMBER_FIELDS, memb_id,
              SSERV_CMD_EDIT_CONTEST_PAGE_2);
  ss_dojo_button(out_f, 0, "cancel-32x32", "Cancel", "ssLoad1(%d)",
              SSERV_CMD_EDIT_CONTEST_PAGE_2);
  fprintf(out_f, "<br/>\n");
  write_html_footer(out_f);

 cleanup:
  html_armor_free(&ab);
  return retval;
}

static int
cmd_op_delete_priv_user(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct contest_desc *ecnts;
  int user_num = -1;

  phr->json_reply = 1;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &user_num) < 0 || user_num < 0)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (contests_remove_nth_permission(ecnts, user_num) < 0)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  retval = 1;

 cleanup:
  return retval;
}

static int
cmd_op_add_priv_user(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct contest_desc *ecnts;
  const unsigned char *login = 0;
  int perms_id = -1;
  opcap_t caps;

  phr->json_reply = 1;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param(phr, "login", &login) <= 0 || !login)
    FAIL(SSERV_ERR_INV_VALUE);
  if (!*login || check_str(login, login_accept_chars) < 0)
    FAIL(SSERV_ERR_INV_VALUE);
  if (hr_cgi_param_int(phr, "perms", &perms_id) < 0
      || perms_id <= 0 || perms_id >= OPCAP_PREDEF_LAST)
    FAIL(SSERV_ERR_INV_VALUE);

  caps = opcaps_get_predef_caps(perms_id);
  contests_add_permission(ecnts, login, caps);
  retval = 1;

 cleanup:
  return retval;
}

static int
cmd_op_copy_all_priv_users(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct contest_desc *ecnts;
  int contest_id_2 = -1;
  const struct contest_desc *cnts = 0;

  phr->json_reply = 1;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "contest_id_2", &contest_id_2) < 0
      || contest_id_2 < 0)
    FAIL(SSERV_ERR_INV_CONTEST);

  if (contest_id_2 != ecnts->id) {
    if (contests_get(contest_id_2, &cnts) < 0 || !cnts)
      FAIL(SSERV_ERR_INV_CONTEST);
    contests_copy_permissions(ecnts, cnts);
  }
  retval = 1;

 cleanup:
  return retval;
}

static int
cmd_op_set_predef_priv(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct contest_desc *ecnts;
  int user_num = -1;
  int perms_id = -1;
  opcap_t caps;

  phr->json_reply = 1;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &user_num) < 0 || user_num < 0)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (hr_cgi_param_int(phr, "value", &perms_id) < 0)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (perms_id < 0 || perms_id >= OPCAP_PREDEF_LAST)
    FAIL(SSERV_ERR_INV_VALUE);
  if (perms_id > 0) {
    caps = opcaps_get_predef_caps(perms_id);
    if (contests_set_permission(ecnts, user_num, caps) < 0)
      FAIL(SSERV_ERR_INV_FIELD_ID);
  }
  retval = 1;

 cleanup:
  return retval;
}

static int
cmd_op_set_priv(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int user_num = -1;
  struct contest_desc *ecnts = 0;
  int i;
  opcap_t caps = 0;
  unsigned char capname[64];
  const unsigned char *s;

  phr->json_reply = 1;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &user_num) < 0 || user_num < 0)
    FAIL(SSERV_ERR_INV_FIELD_ID);

  for (i = 0; i < OPCAP_LAST; ++i) {
    snprintf(capname, sizeof(capname), "cap_%d", i);
    if (hr_cgi_param(phr, capname, &s) > 0)
      caps |= 1ULL << i;
  }
  if (contests_set_permission(ecnts, user_num, caps) < 0)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  retval = 1;

 cleanup:
  return retval;
}

static int
cmd_op_set_default_access(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct contest_desc *ecnts;
  int f_id = -1;
  struct contest_access **p_acc;
  int val = -1;

  phr->json_reply = 1;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD
      || !(access_field_set[f_id]))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  p_acc = (struct contest_access**) contest_desc_get_ptr(ecnts, f_id);
  if (hr_cgi_param_int(phr, "value", &val) < 0
      || val < 0 || val > 1)
    FAIL(SSERV_ERR_INV_VALUE);
  contests_set_default(ecnts, p_acc, access_field_tag[f_id], val);
  retval = 0;

 cleanup:
  return retval;
}

static int
cmd_op_check_ip_mask(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  const unsigned char *value = 0;
  ej_ip_t addr, mask;

  phr->json_reply = 1;

  if (hr_cgi_param(phr, "value", &value) <= 0 || !value)
    FAIL(SSERV_ERR_INV_VALUE);
  if (xml_parse_ipv6_mask(NULL, 0, 0, 0, value, &addr, &mask) < 0)
    FAIL(SSERV_ERR_INV_VALUE);
  retval = 0;

 cleanup:
  return retval;
}

static int
cmd_op_add_ip(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct contest_desc *ecnts;
  const unsigned char *mask_str = 0;
  int ssl_flag = -2;
  int default_allow = -1;
  struct contest_access **p_acc;
  int f_id;
  ej_ip_t addr, mask;

  phr->json_reply = 1;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD
      || !(access_field_set[f_id]))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  p_acc = (struct contest_access**) contest_desc_get_ptr(ecnts, f_id);
  if (hr_cgi_param(phr, "ip_mask", &mask_str) <= 0)
    FAIL(SSERV_ERR_INV_VALUE);
  if (xml_parse_ipv6_mask(NULL, 0, 0, 0, mask_str, &addr, &mask) < 0)
    FAIL(SSERV_ERR_INV_VALUE);
  if (hr_cgi_param_int(phr, "ssl_flag", &ssl_flag) < 0
      || ssl_flag < -1 || ssl_flag > 1)
    FAIL(SSERV_ERR_INV_VALUE);
  if (hr_cgi_param_int(phr, "default_allow", &default_allow) < 0
      || default_allow < 0 || default_allow > 1)
    FAIL(SSERV_ERR_INV_VALUE);
  contests_add_ip(ecnts, p_acc, access_field_tag[f_id],
                  &addr, &mask, ssl_flag, default_allow);
  retval = 1;

 cleanup:
  return retval;
}

static int
cmd_op_set_rule_access(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct contest_desc *ecnts;
  int allow = -1;
  struct contest_access *acc;
  struct contest_ip *p;
  int f_id, subf_id;

  phr->json_reply = 1;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD
      || !(access_field_set[f_id]))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  acc = *(struct contest_access**) contest_desc_get_ptr(ecnts, f_id);
  if (hr_cgi_param_int(phr, "subfield_id", &subf_id) < 0 || subf_id < 0)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (hr_cgi_param_int(phr, "value", &allow) < 0 || allow < 0 || allow > 1)
    FAIL(SSERV_ERR_INV_VALUE);
  if (!(p = contests_get_ip_rule_nc(acc, subf_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  p->allow = allow;
  retval = 0;

 cleanup:
  return retval;
}

static int
cmd_op_set_rule_ssl(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct contest_desc *ecnts;
  int ssl = -2;
  struct contest_access *acc;
  struct contest_ip *p;
  int f_id, subf_id;

  phr->json_reply = 1;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD
      || !(access_field_set[f_id]))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  acc = *(struct contest_access**) contest_desc_get_ptr(ecnts, f_id);
  if (hr_cgi_param_int(phr, "subfield_id", &subf_id) < 0 || subf_id < 0)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (hr_cgi_param_int(phr, "value", &ssl) < 0 || ssl < -1 || ssl > 1)
    FAIL(SSERV_ERR_INV_VALUE);
  if (!(p = contests_get_ip_rule_nc(acc, subf_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  p->ssl = ssl;
  retval = 0;

 cleanup:
  return retval;
}

static int
cmd_op_set_rule_ip(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct contest_desc *ecnts;
  struct contest_access *acc;
  struct contest_ip *p;
  int f_id, subf_id;
  const unsigned char *mask_str = 0;
  ej_ip_t addr, mask;

  phr->json_reply = 1;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD
      || !(access_field_set[f_id]))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  acc = *(struct contest_access**) contest_desc_get_ptr(ecnts, f_id);
  if (hr_cgi_param_int(phr, "subfield_id", &subf_id) < 0 || subf_id < 0)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (hr_cgi_param(phr, "value", &mask_str) <= 0)
    FAIL(SSERV_ERR_INV_VALUE);
  if (xml_parse_ipv6_mask(NULL, 0, 0, 0, mask_str, &addr, &mask) < 0)
    FAIL(SSERV_ERR_INV_VALUE);
  if (!(p = contests_get_ip_rule_nc(acc, subf_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  p->addr = addr;
  p->mask = mask;
  retval = 0;

 cleanup:
  return retval;
}

static int
cmd_op_rule_cmd(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int f_id = -1, subf_id = -1;
  struct contest_desc *ecnts;
  struct contest_access **p_acc;
  int (*contest_func)(struct contest_access **, int);
  static int (*contest_funcs[])(struct contest_access **, int) =
  {
    [SSERV_CMD_DELETE_RULE - SSERV_CMD_DELETE_RULE] = contests_delete_ip_rule,
    [SSERV_CMD_FORWARD_RULE - SSERV_CMD_DELETE_RULE] = contests_forward_ip_rule,
    [SSERV_CMD_BACKWARD_RULE - SSERV_CMD_DELETE_RULE] = contests_backward_ip_rule,
  };

  phr->json_reply = 1;

  if (phr->action < SSERV_CMD_DELETE_RULE
      || phr->action > SSERV_CMD_BACKWARD_RULE)
    FAIL(SSERV_ERR_INV_OPER);
  if (!(contest_func = contest_funcs[phr->action - SSERV_CMD_DELETE_RULE]))
    FAIL(SSERV_ERR_INV_OPER);

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD
      || !(access_field_set[f_id]))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  p_acc = (struct contest_access**) contest_desc_get_ptr(ecnts, f_id);
  if (hr_cgi_param_int(phr, "subfield_id", &subf_id) < 0 || subf_id < 0)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (contest_func(p_acc, subf_id) < 0)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  retval = 1;

 cleanup:
  return retval;
}

static int
cmd_op_copy_access_rules(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct contest_desc *ecnts = 0;
  const struct contest_desc *cnts = 0;
  int f_id = -1, f_id_2 = -1, contest_id_2 = -1;
  struct contest_access **p_acc;
  const struct contest_access *acc_2;

  phr->json_reply = 1;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTS_LAST_FIELD
      || !(access_field_set[f_id]))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  p_acc = (struct contest_access**) contest_desc_get_ptr(ecnts, f_id);
  if (hr_cgi_param_int(phr, "contest_id_2", &contest_id_2) < 0
      || contest_id_2 <= 0)
    FAIL(SSERV_ERR_INV_VALUE);
  if (contests_get(contest_id_2, &cnts) < 0 || !cnts)
    FAIL(SSERV_ERR_INV_VALUE);
  if (hr_cgi_param_int(phr, "field_id_2", &f_id_2) < 0
      || f_id_2 <= 0 || f_id_2 >= CNTS_LAST_FIELD
      || !(access_field_set[f_id_2]))
    FAIL(SSERV_ERR_INV_VALUE);
  acc_2 = *(const struct contest_access**) contest_desc_get_ptr(cnts, f_id_2);

  if (*p_acc == acc_2) return 0;
  xml_unlink_node(&(*p_acc)->b);
  contests_free_2(&(*p_acc)->b);
  *p_acc = super_html_copy_contest_access(acc_2);
  xml_link_node_last(&ecnts->b, &(*p_acc)->b);
  retval = 1;

 cleanup:
  return retval;
}

static int
cmd_op_edit_general_fields(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int ff, opt_val;
  struct contest_desc *ecnts;
  unsigned char vbuf[64];
  const unsigned char *s;
  struct html_armor_buffer vb = HTML_ARMOR_INITIALIZER;

  phr->json_reply = 1;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);

  for (ff = 1; ff < CONTEST_LAST_FIELD; ++ff) {
    snprintf(vbuf, sizeof(vbuf), "field_%d", ff);
    if (hr_cgi_param_int(phr, vbuf, &opt_val) < 0
        || opt_val < 0 || opt_val > 2)
      FAIL(SSERV_ERR_INV_VALUE);
    snprintf(vbuf, sizeof(vbuf), "legend_%d", ff);
    if (ss_cgi_param_utf8_str(phr, vbuf, &vb, &s) < 0)
      FAIL(SSERV_ERR_INV_VALUE);
    contests_set_general_field(ecnts, ff, opt_val, s);
  }
  retval = 1;

 cleanup:
  html_armor_free(&vb);
  return retval;
}

static int
cmd_op_edit_member_fields(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int opt_vals[CONTEST_LAST_MEMBER_FIELD];
  const unsigned char *legends[CONTEST_LAST_MEMBER_FIELD];
  struct contest_desc *ecnts;
  int m_id = -1, init_count = -1, max_count = -1, min_count = -1;
  int ff, opt_val, has_fields = 0;
  unsigned char vbuf[64];
  const unsigned char *s = 0;
  struct html_armor_buffer vb = HTML_ARMOR_INITIALIZER;

  memset(opt_vals, 0, sizeof(opt_vals));
  memset(legends, 0, sizeof(legends));

  phr->json_reply = 1;

  if (!(ecnts = phr->ss->edited_cnts))
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &m_id) < 0
      || m_id < 0 || m_id >= CONTEST_LAST_MEMBER)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (hr_cgi_param_int(phr, "init_count", &init_count) < 0
      || init_count < 0 || init_count > 5)
    FAIL(SSERV_ERR_INV_VALUE);
  if (hr_cgi_param_int(phr, "min_count", &min_count) < 0
      || min_count < 0 || min_count > 5)
    FAIL(SSERV_ERR_INV_VALUE);
  if (hr_cgi_param_int(phr, "max_count", &max_count) < 0
      || max_count < 0 || max_count > 5)
    FAIL(SSERV_ERR_INV_VALUE);
  for (ff = 1; ff < CONTEST_LAST_MEMBER_FIELD; ++ff) {
    snprintf(vbuf, sizeof(vbuf), "field_%d", ff);
    if (hr_cgi_param_int(phr, vbuf, &opt_val) < 0
        || opt_val < 0 || opt_val > 2)
      FAIL(SSERV_ERR_INV_VALUE);
    opt_vals[ff] = opt_val;
    if (opt_val) has_fields = 1;
    snprintf(vbuf, sizeof(vbuf), "legend_%d", ff);
    if (ss_cgi_param_utf8_str(phr, vbuf, &vb, &s) < 0)
      FAIL(SSERV_ERR_INV_VALUE);
    legends[ff] = s;
  }

  if (!has_fields && !min_count && !max_count && !init_count) {
    retval = 1;
    contests_delete_member_fields(ecnts, m_id);
    goto cleanup;
  }

  contests_set_member_counts(ecnts, m_id, min_count, max_count, init_count);
  for (ff = 1; ff < CONTEST_LAST_MEMBER_FIELD; ++ff) {
    contests_set_member_field(ecnts, m_id, ff, opt_vals[ff], legends[ff]);
  }
  retval = 1;

 cleanup:
  html_armor_free(&vb);
  return retval;
}

static int
cmd_op_create_new_contest_page(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  unsigned char buf[1024];
  int contest_num = 0, recomm_id = 1, j, cnts_id;
  const int *contests = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const struct contest_desc *cnts = 0;

  if (phr->ss->edited_cnts) {
    snprintf(buf, sizeof(buf), "serve-control: %s, another contest is edited",
             phr->html_name);
    write_html_header(out_f, phr, buf, 1, 0);
    fprintf(out_f, "<h1>%s</h1>\n", buf);

    snprintf(buf, sizeof(buf),
             "<input type=\"hidden\" name=\"SID\" value=\"%016llx\" />",
             phr->session_id);
    super_html_edited_cnts_dialog(out_f,
                                  phr->priv_level, phr->user_id, phr->login,
                                  phr->session_id, &phr->ip, phr->config,
                                  phr->ss, phr->self_url, buf,
                                  "", NULL, 1);

    write_html_footer(out_f);
    return 0;
  }

  if (phr->priv_level != PRIV_LEVEL_ADMIN)
    FAIL(SSERV_ERR_PERM_DENIED);
  if (ejudge_cfg_opcaps_find(phr->config, phr->login, &phr->caps) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);
  if (opcaps_check(phr->caps, OPCAP_EDIT_CONTEST) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);

  contest_num = contests_get_list(&contests);
  if (contest_num > 0) recomm_id = contests[contest_num - 1] + 1;
  j = super_serve_sid_state_get_max_edited_cnts();
  if (j >= recomm_id) recomm_id = j + 1;

  snprintf(buf, sizeof(buf), "serve-control: %s, create a new contest",
           phr->html_name);
  write_html_header(out_f, phr, buf, 1, 0);
  fprintf(out_f, "<h1>%s</h1>\n", buf);

  html_start_form(out_f, 1, phr->self_url, "");
  html_hidden(out_f, "SID", "%016llx", phr->session_id);
  html_hidden(out_f, "action", "%d", SSERV_CMD_HTTP_REQUEST);
  html_hidden(out_f, "op", "%d", SSERV_CMD_CREATE_NEW_CONTEST);

  fprintf(out_f, "<table border=\"0\">");
  fprintf(out_f, "<tr><td>Contest number:</td><td>%s</td></tr>\n",
          html_input_text(buf, sizeof(buf), "contest_id", 20, 0, "%d", recomm_id));
  fprintf(out_f, "<tr><td>Contest template:</td><td>");
  fprintf(out_f, "<select name=\"templ_id\">"
          "<option value=\"0\">From scratch</option>");
  for (j = 0; j < contest_num; j++) {
    cnts_id = contests[j];
    if (contests_get(cnts_id, &cnts) < 0) continue;
    fprintf(out_f, "<option value=\"%d\">%d - %s</option>", cnts_id, cnts_id,
            ARMOR(cnts->name));
  }
  fprintf(out_f, "</select></td></tr>\n");
  fprintf(out_f, "<tr><td>&nbsp;</td><td>");
  fprintf(out_f, "<input type=\"submit\" value=\"%s\"/>", "Create contest!");
  fprintf(out_f, "</td></tr>\n");
  fprintf(out_f, "</table></form>\n");
  write_html_footer(out_f);

 cleanup:
  html_armor_free(&ab);
  return retval;
}

static int
cmd_op_create_new_contest(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int contest_id = -1;
  int templ_id = -1;
  int contest_num, i;
  const int *contests = 0;
  const struct contest_desc *templ_cnts = 0;

  if (phr->ss->edited_cnts)
    FAIL(SSERV_ERR_CONTEST_EDITED);
  if (phr->priv_level != PRIV_LEVEL_ADMIN)
    FAIL(SSERV_ERR_PERM_DENIED);
  if (ejudge_cfg_opcaps_find(phr->config, phr->login, &phr->caps) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);
  if (opcaps_check(phr->caps, OPCAP_EDIT_CONTEST) < 0)
    FAIL(SSERV_ERR_PERM_DENIED);
  if (hr_cgi_param_int(phr, "contest_id", &contest_id) < 0
      || contest_id < 0 || contest_id > EJ_MAX_CONTEST_ID)
    FAIL(SSERV_ERR_INV_VALUE);
  if (hr_cgi_param_int(phr, "templ_id", &templ_id) < 0 || templ_id < 0)
    FAIL(SSERV_ERR_INV_VALUE);

  contest_num = contests_get_list(&contests);
  if (contest_num < 0 || !contests)
    FAIL(SSERV_ERR_INTERNAL);

  if (!contest_id) {
    contest_id = contests[contest_num - 1] + 1;
    i = super_serve_sid_state_get_max_edited_cnts();
    if (i >= contest_id) contest_id = i + 1;
  }
  for (i = 0; i < contest_num && contests[i] != contest_id; i++);
  if (i < contest_num)
    FAIL(SSERV_ERR_CONTEST_ALREADY_EXISTS);
  if (super_serve_sid_state_get_cnts_editor(contest_id))
    FAIL(SSERV_ERR_CONTEST_ALREADY_EDITED);
  if (templ_id > 0) {
    for (i = 0; i < contest_num && contests[i] != templ_id; i++);
    if (i >= contest_num)
      FAIL(SSERV_ERR_INV_CONTEST);
    if (contests_get(templ_id, &templ_cnts) < 0 || !templ_cnts)
      FAIL(SSERV_ERR_INV_CONTEST);
  }

  if (!templ_cnts) {
    phr->ss->edited_cnts = contest_tmpl_new(contest_id, phr->login, phr->self_url, phr->system_login, &phr->ip, phr->ssl_flag, phr->config);
    phr->ss->global = prepare_new_global_section(contest_id, phr->ss->edited_cnts->root_dir, phr->config);
  } else {
    super_html_load_serve_cfg(templ_cnts, phr->config, phr->ss);
    super_html_fix_serve(phr->ss, templ_id, contest_id);
    phr->ss->edited_cnts = contest_tmpl_clone(phr->ss, contest_id, templ_id, phr->login, phr->system_login);
  }

  refresh_page(out_f, phr, "action=%d&op=%d", SSERV_CMD_HTTP_REQUEST,
               SSERV_CMD_EDIT_CONTEST_PAGE_2);

 cleanup:
  return retval;
}

static int
cmd_op_forget_contest(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  phr->json_reply = 1;
  super_serve_clear_edited_contest(phr->ss);
  return 1;
}

// initialized upon first access
static unsigned char *editable_global_fields = NULL;

static void
init_editable_global_fields(void)
{
  int i, f;

  if (editable_global_fields) return;
  XCALLOC(editable_global_fields, CNTSGLOB_LAST_FIELD);

  for (i = 0; cnts_global_info[i].nspace; ++i)
    if (cnts_global_info[i].nspace == NS_GLOBAL) {
      f = cnts_global_info[i].field_id;
      ASSERT(f > 0 && f < CNTSGLOB_LAST_FIELD);
      editable_global_fields[f] = 1;
    }
}

static unsigned char
global_bool_fields_return_val[CNTSGLOB_LAST_FIELD] =
{
  [CNTSGLOB_secure_run] = 1,
  [CNTSGLOB_team_enable_rep_view] = 1,
  [CNTSGLOB_disable_clars] = 1,
  [CNTSGLOB_enable_eoln_select] = 1,
  [CNTSGLOB_problem_navigation] = 1,
  [CNTSGLOB_stand_fancy_style] = 1,
  [CNTSGLOB_stand_show_ok_time] = 1,
  [CNTSGLOB_enable_printing] = 1,
  [CNTSGLOB_stand_show_contestant_status] = 1,
  [CNTSGLOB_stand_show_warn_number] = 1,
};

static unsigned char
global_str_need_space[CNTSGLOB_LAST_FIELD] =
{
  [CNTSGLOB_stand_success_attr] = 1,
  [CNTSGLOB_stand_table_attr] = 1,
  [CNTSGLOB_stand_place_attr] = 1,
  [CNTSGLOB_stand_team_attr] = 1,
  [CNTSGLOB_stand_prob_attr] = 1,
  [CNTSGLOB_stand_solved_attr] = 1,
  [CNTSGLOB_stand_score_attr] = 1,
  [CNTSGLOB_stand_penalty_attr] = 1,
  [CNTSGLOB_stand_time_attr] = 1,
  [CNTSGLOB_stand_fail_attr] = 1,
  [CNTSGLOB_stand_trans_attr] = 1,
  [CNTSGLOB_stand_disq_attr] = 1,
  [CNTSGLOB_stand_self_row_attr] = 1,
  [CNTSGLOB_stand_v_row_attr] = 1,
  [CNTSGLOB_stand_r_row_attr] = 1,
  [CNTSGLOB_stand_u_row_attr] = 1,
  [CNTSGLOB_stand_extra_attr] = 1,
  [CNTSGLOB_stand_warn_number_attr] = 1,
  [CNTSGLOB_stand_page_table_attr] = 1,
  [CNTSGLOB_stand_page_cur_attr] = 1,
};

/* TODO list:
  { NS_GLOBAL, CNTSGLOB_unhandled_vars, 137, 0, 0, 0, 0, 0, 0, 0, "Global.unhandled_vars SidState.show_global_7 &&" },
 */

static const int global_int_min_val[CNTSGLOB_LAST_FIELD] =
{
  [CNTSGLOB_max_run_size] = 1,
  [CNTSGLOB_max_run_total] = 1,
  [CNTSGLOB_max_run_num] = 1,
  [CNTSGLOB_max_clar_size] = 1,
  [CNTSGLOB_max_clar_total] = 1,
  [CNTSGLOB_max_clar_num] = 1,
  [CNTSGLOB_team_page_quota] = 1,
  [CNTSGLOB_users_on_page] = 0,
  [CNTSGLOB_plog_update_time] = 0,
  [CNTSGLOB_external_xml_update_time] = 0,
  [CNTSGLOB_internal_xml_update_time] = 0,
  [CNTSGLOB_sleep_time] = 1,
  [CNTSGLOB_serve_sleep_time] = 1,
  [CNTSGLOB_max_file_length] = 1,
  [CNTSGLOB_max_line_length] = 1,
  [CNTSGLOB_inactivity_timeout] = 1,
  [CNTSGLOB_cr_serialization_key] = 1,
  [CNTSGLOB_cpu_bogomips] = 0
};

static const int global_int_max_val[CNTSGLOB_LAST_FIELD] =
{
  [CNTSGLOB_max_run_size] = 1*1024*1024*1024,
  [CNTSGLOB_max_run_total] = 1*1024*1024*1024,
  [CNTSGLOB_max_run_num] = 1*1024*1024*1024,
  [CNTSGLOB_max_clar_size] = 1*1024*1024*1024,
  [CNTSGLOB_max_clar_total] = 1*1024*1024*1024,
  [CNTSGLOB_max_clar_num] = 1*1024*1024*1024,
  [CNTSGLOB_team_page_quota] = 1*1024*1024*1024,
  [CNTSGLOB_users_on_page] = 1*1024*1024*1024,
  [CNTSGLOB_plog_update_time] = 1*1024*1024*1024,
  [CNTSGLOB_external_xml_update_time] = 1*1024*1024*1024,
  [CNTSGLOB_internal_xml_update_time] = 1*1024*1024*1024,
  [CNTSGLOB_sleep_time] = 1*1024*1024*1024,
  [CNTSGLOB_serve_sleep_time] = 1*1024*1024*1024,
  [CNTSGLOB_max_file_length] = 1*1024*1024*1024,
  [CNTSGLOB_max_line_length] = 1*1024*1024*1024,
  [CNTSGLOB_inactivity_timeout] = 1*1024*1024*1024,
  [CNTSGLOB_cr_serialization_key] = 1*1024*1024*1024,
  [CNTSGLOB_cpu_bogomips] = 1*1024*1024*1024
};

static int
cmd_op_edit_serve_global_field(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct section_global_data *global = 0;
  int f_id = 0;
  void *f_ptr;
  int f_type;
  const unsigned char *valstr = 0;
  int vallen;
  int intval, n = 0, h = 0, m = 0, s = 0;
  char *eptr;
  struct html_armor_buffer vb = HTML_ARMOR_INITIALIZER;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts || !phr->ss->global)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  global = phr->ss->global;
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTSGLOB_LAST_FIELD)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!editable_global_fields)
    init_editable_global_fields();
  if (!editable_global_fields[f_id])
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_ptr = cntsglob_get_ptr_nc(global, f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_type = cntsglob_get_type(f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (ss_cgi_param_utf8_str(phr, "value", &vb, &valstr) <= 0 || !valstr)
    FAIL(SSERV_ERR_INV_VALUE);
  vallen = strlen(valstr);
  if (global_str_need_space[f_id] && vallen > 0 && !isspace(valstr[0])) {
    unsigned char *tmps = (unsigned char*) alloca(vallen + 2);
    tmps[0] = ' ';
    memcpy(tmps + 1, valstr, vallen + 1);
    valstr = tmps;
  }

  // individual field editing
  switch (f_id) {
  case CNTSGLOB_score_system:
    if (!vallen) FAIL(SSERV_ERR_INV_VALUE);
    errno = 0;
    intval = strtol(valstr, &eptr, 10);
    if (errno || *eptr) FAIL(SSERV_ERR_INV_VALUE);
    if (intval < 0 || intval >= 6) FAIL(SSERV_ERR_INV_VALUE);
    static int score_system_to_int[6] = { SCORE_ACM, SCORE_KIROV, SCORE_OLYMPIAD, SCORE_MOSCOW, SCORE_ACM, SCORE_OLYMPIAD };
    static int score_system_to_vir[6] = { 0, 0, 0, 0, 1, 1 };
    global->score_system = score_system_to_int[intval];
    global->is_virtual = score_system_to_vir[intval];
    retval = 1;
    goto cleanup;
  case CNTSGLOB_contest_time:
  case CNTSGLOB_board_fog_time:
  case CNTSGLOB_board_unfog_time:
    if (!vallen) FAIL(SSERV_ERR_INV_VALUE);
    if (sscanf(valstr, "%d:%d%n", &h, &m, &n) == 2 && !valstr[n]
	&& m >= 0 && m < 60 && h >= 0) {
      *(int*) f_ptr = h * 60 + m;
    } else if (sscanf(valstr, "%d%n", &h, &n) == 1 && !valstr[n]
	       && h >= 0) {
      *(int*) f_ptr = h * 60;
    } else {
      FAIL(SSERV_ERR_INV_VALUE);
    }
    retval = 1;
    goto cleanup;
  case CNTSGLOB_standings_locale:
    {
      int locale_code = 0;
      if (vallen > 0) {
        locale_code = l10n_parse_locale(valstr);
      }
      snprintf(global->standings_locale, sizeof(global->standings_locale),
               "%s", l10n_unparse_locale(locale_code));
      global->standings_locale_id = locale_code;
      retval = 1;
    }
    goto cleanup;

  case CNTSGLOB_rounding_mode:
    {
      if (!vallen) FAIL(SSERV_ERR_INV_VALUE);
      errno = 0;
      intval = strtol(valstr, &eptr, 10);
      if (errno || *eptr || intval < 0 || intval > 2) FAIL(SSERV_ERR_INV_VALUE);
      global->rounding_mode = intval;
    }
    goto cleanup;

  case CNTSGLOB_team_download_time:
    if (!vallen) FAIL(SSERV_ERR_INV_VALUE);
    if (sscanf(valstr, "%d:%d:%d%n", &h, &m, &s, &n) == 3 && !valstr[n]
        && s >= 0 && s < 60 && m >= 0 && m < 60 && h >= 0) {
      *(int*) f_ptr = h * 3600 + m * 60 + s;
    } else if (sscanf(valstr, "%d:%d%n", &h, &m, &n) == 2 && !valstr[n]
	&& m >= 0 && m < 60 && h >= 0) {
      *(int*) f_ptr = h * 3600 + m * 60;
    } else if (sscanf(valstr, "%d%n", &h, &n) == 1 && !valstr[n]
	       && h >= 0) {
      *(int*) f_ptr = h * 3600;
    } else {
      FAIL(SSERV_ERR_INV_VALUE);
    }
    retval = 1;
    goto cleanup;

  default:
    // do nothing
    ;
  }

  switch (f_type) {
  case 'B': // ejintbool_t
    {
      if (!vallen) FAIL(SSERV_ERR_INV_VALUE);
      errno = 0;
      int bval = strtol(valstr, &eptr, 10);
      if (errno || *eptr) FAIL(SSERV_ERR_INV_VALUE);
      if (bval < 0 || bval > 1) FAIL(SSERV_ERR_INV_VALUE);
      *(ejintbool_t*) f_ptr = bval;
      retval = global_bool_fields_return_val[f_id];
    }    
    break;

  case 't':
    retval = handle_time_t_editing(phr, valstr, (time_t*) f_ptr);
    break;

  case 'S':
    {
      size_t size = cntsglob_get_size(f_id);
      snprintf((unsigned char*) f_ptr, size, "%s", valstr);
    }
    break;

  case 'i':
    {
      if (!vallen) FAIL(SSERV_ERR_INV_VALUE);
      errno = 0;
      int val = strtol(valstr, &eptr, 10);
      if (errno || *eptr) FAIL(SSERV_ERR_INV_VALUE);
      if (val < global_int_min_val[f_id] || val > global_int_max_val[f_id])
        FAIL(SSERV_ERR_INV_VALUE);
      *(int*) f_ptr = val;
    }
    break;

  case 'z':
    {
      size_t val = 0;
      if (parse_size(valstr, &val) < 0) FAIL(SSERV_ERR_INV_VALUE);
      if (val < global_int_min_val[f_id] || val > global_int_max_val[f_id])
        FAIL(SSERV_ERR_INV_VALUE);
      *(ejintsize_t*) f_ptr = (ejintsize_t) val;
    }
    break;

  case 'x':
    {
      char **tmp_args = 0;
      char ***f_args = (char***) f_ptr;

      if (sarray_parse_2(valstr, &tmp_args) < 0) FAIL(SSERV_ERR_INV_VALUE);
      sarray_free(*f_args);
      *f_args = tmp_args;
    }
    break;

  default:
    FAIL(SSERV_ERR_INV_FIELD_ID);
  }

 cleanup:
  html_armor_free(&vb);
  return retval;
}

static const unsigned char *global_str_default_val[CNTSGLOB_LAST_FIELD] =
{
  [CNTSGLOB_test_dir] = DFLT_G_TEST_DIR,
  [CNTSGLOB_corr_dir] = DFLT_G_CORR_DIR,
  [CNTSGLOB_info_dir] = DFLT_G_INFO_DIR,
  [CNTSGLOB_tgz_dir] = DFLT_G_TGZ_DIR,
  [CNTSGLOB_checker_dir] = DFLT_G_CHECKER_DIR,
  [CNTSGLOB_statement_dir] = DFLT_G_STATEMENT_DIR,
  [CNTSGLOB_plugin_dir] = DFLT_G_PLUGIN_DIR,
  [CNTSGLOB_standings_file_name] = DFLT_G_STANDINGS_FILE_NAME
};

static const int global_int_default_val[CNTSGLOB_LAST_FIELD] =
{
  [CNTSGLOB_max_run_size] = DFLT_G_MAX_RUN_SIZE,
  [CNTSGLOB_max_run_total] = DFLT_G_MAX_RUN_TOTAL,
  [CNTSGLOB_max_run_num] = DFLT_G_MAX_RUN_NUM,
  [CNTSGLOB_max_clar_size] = DFLT_G_MAX_CLAR_SIZE,
  [CNTSGLOB_max_clar_total] = DFLT_G_MAX_CLAR_TOTAL,
  [CNTSGLOB_max_clar_num] = DFLT_G_MAX_CLAR_NUM,
  [CNTSGLOB_team_page_quota] = DFLT_G_TEAM_PAGE_QUOTA,
  [CNTSGLOB_sleep_time] = DFLT_G_SLEEP_TIME,
  [CNTSGLOB_serve_sleep_time] = DFLT_G_SERVE_SLEEP_TIME,
  [CNTSGLOB_max_file_length] = DFLT_G_MAX_FILE_LENGTH,
  [CNTSGLOB_max_line_length] = DFLT_G_MAX_LINE_LENGTH,
  [CNTSGLOB_inactivity_timeout] = DFLT_G_INACTIVITY_TIMEOUT,
};

static int
cmd_op_clear_serve_global_field(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct section_global_data *global = 0;
  int f_id = 0, f_type = 0;
  void *f_ptr = 0;
  size_t f_size = 0;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts || !phr->ss->global)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  global = phr->ss->global;
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTSGLOB_LAST_FIELD)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!editable_global_fields)
    init_editable_global_fields();
  if (!editable_global_fields[f_id])
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_ptr = cntsglob_get_ptr_nc(global, f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_type = cntsglob_get_type(f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_size = cntsglob_get_size(f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);

  // individual field editing
  switch (f_id) {
  case CNTSGLOB_score_system:
    global->score_system = SCORE_ACM;
    global->is_virtual = 0;
    retval = 1;
    goto cleanup;
  case CNTSGLOB_contest_time:
  case CNTSGLOB_board_fog_time:
  case CNTSGLOB_board_unfog_time:
  case CNTSGLOB_team_download_time:
    *(int*) f_ptr = 0;
    retval = 1;
    goto cleanup;
  case CNTSGLOB_standings_locale:
    global->standings_locale[0] = 0;
    global->standings_locale_id = 0;
    retval = 1;
    goto cleanup;
  case CNTSGLOB_rounding_mode:
    global->rounding_mode = 0;
    retval = 1;
    goto cleanup;
  case CNTSGLOB_cpu_bogomips:
    global->cpu_bogomips = cpu_get_bogomips();
    retval = 1;
    goto cleanup;
  case CNTSGLOB_cr_serialization_key:
    global->cr_serialization_key = phr->config->serialization_key;
    retval = 1;
    goto cleanup;
  default:
    ;
  }

  switch (f_type) {
  case 'B':
    *(ejintbool_t*) f_ptr = 0;
    break;

  case 't':
    *(time_t*) f_ptr = 0;
    break;

  case 'i':
    *(int*) f_ptr = global_int_default_val[f_id];
    break;

  case 'z':
    *(ejintsize_t*) f_ptr = global_int_default_val[f_id];
    break;

  case 's':
    xfree(*(char**) f_ptr);
    *(char**) f_ptr = 0;
    break;

  case 'S':
    *(char*) f_ptr = 0;
    if (global_str_default_val[f_id]) {
      snprintf((char*) f_ptr, f_size, "%s", global_str_default_val[f_id]);
    }
    break;

  case 'x':
    sarray_free(* (char***) f_ptr);
    *(char***) f_ptr = 0;
    break;

  default:
    FAIL(SSERV_ERR_INV_FIELD_ID);
  }
  retval = 1;

 cleanup:
  return retval;
}

static const unsigned char editable_sid_state_fields[SSSS_LAST_FIELD] =
{
  [SSSS_enable_stand2] = 1,
  [SSSS_enable_plog] = 1,
  [SSSS_enable_extra_col] = 1,
  [SSSS_enable_win32_languages] = 1,
};

static int
cmd_op_edit_sid_state_field(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int f_id = 0;
  void *f_ptr;
  int f_type;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTSGLOB_LAST_FIELD)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!editable_sid_state_fields[f_id])
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_ptr = ss_sid_state_get_ptr_nc(phr->ss, f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_type = ss_sid_state_get_type(f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  switch (f_type) {
  case 'B':
    {
      int val;

      if (hr_cgi_param_int(phr, "value", &val) < 0 || val < 0 || val > 1)
        FAIL(SSERV_ERR_INV_VALUE);
      *(ejintbool_t*) f_ptr = val;
      retval = 1;
    }
    break;
  default:
    FAIL(SSERV_ERR_INV_FIELD_ID);
  }

 cleanup:
  return retval;
}

static const unsigned char editable_sid_state_fields_neg[SSSS_LAST_FIELD] =
{
  [SSSS_disable_compilation_server] = 1,
};

static int
cmd_op_edit_sid_state_field_neg(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int f_id = 0;
  int val;
  void *f_ptr;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTSGLOB_LAST_FIELD)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!editable_sid_state_fields_neg[f_id])
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (hr_cgi_param_int(phr, "value", &val) < 0 || val < 0 || val > 1)
    FAIL(SSERV_ERR_INV_VALUE);
  if (!(f_ptr = ss_sid_state_get_ptr_nc(phr->ss, f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (ss_sid_state_get_type(f_id) != 'B')
    FAIL(SSERV_ERR_INV_FIELD_ID);
  *(ejintbool_t*) f_ptr = !val;
  retval = 1;

 cleanup:
  return retval;
}

static unsigned char global_editable_details[CNTSGLOB_LAST_FIELD] =
{
  [CNTSGLOB_a2ps_args] = 1,
  [CNTSGLOB_lpr_args] = 1,
  [CNTSGLOB_stand_row_attr] = 1,
  [CNTSGLOB_stand_page_row_attr] = 1,
  [CNTSGLOB_stand_page_col_attr] = 1,
  [CNTSGLOB_user_priority_adjustments] = 1,
  [CNTSGLOB_contestant_status_legend] = 1,
  [CNTSGLOB_contestant_status_row_attr] = 1,
  [CNTSGLOB_unhandled_vars] = 1,
};

static int
cmd_op_edit_serve_global_field_detail_page(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  struct section_global_data *global;
  const struct contest_desc *ecnts;
  int f_id, f_type;
  unsigned char buf[1024];
  FILE *text_f = 0;
  char *text_t = 0;
  size_t text_z = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const void *f_ptr;

  if (!phr->ss->edited_cnts || !phr->ss->global)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  ecnts = phr->ss->edited_cnts;
  global = phr->ss->global;
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTSGLOB_LAST_FIELD
      || !(global_editable_details[f_id]))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_ptr = cntsglob_get_ptr(global, f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_type = cntsglob_get_type(f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);

  text_f = open_memstream(&text_t, &text_z);
  switch (f_type) {
  case 's':
    {
      const unsigned char *s = *(const unsigned char**) f_ptr;
      if (s) fprintf(text_f, "%s", s);
    }
    break;
  case 'x':
    {
      const char *const * ss = *(const char *const **) f_ptr;
      if (ss) {
        for (int i = 0; ss[i]; ++i)
          fprintf(text_f, "%s\n", ss[i]);
      }
    }
    break;
  default:
    FAIL(SSERV_ERR_INV_FIELD_ID);
  }
  close_memstream(text_f); text_f = 0;

  snprintf(buf, sizeof(buf), "serve-control: %s, contest %d, editing %s",
           phr->html_name, ecnts->id, cntsglob_get_name(f_id));
  write_html_header(out_f, phr, buf, 1, 0);
  fprintf(out_f, "<h1>%s</h1>\n", buf);
  fprintf(out_f, "<br/>\n");

  fprintf(out_f, "<form id=\"editBox\"><textarea dojoType=\"dijit.form.Textarea\" name=\"param\" rows=\"20\" cols=\"80\">%s</textarea></form>\n",
          ARMOR(text_t));

  fprintf(out_f, "<br/>\n");

  ss_dojo_button(out_f, 0, "accept-32x32", "OK",
              "editFileSave(\"editBox\", %d, %d, %d)",
              SSERV_CMD_EDIT_SERVE_GLOBAL_FIELD_DETAIL, f_id,
              SSERV_CMD_EDIT_CONTEST_PAGE_2);
  ss_dojo_button(out_f, 0, "cancel-32x32", "Cancel",
              "ssLoad1(%d)",
              SSERV_CMD_EDIT_CONTEST_PAGE_2);

  write_html_footer(out_f);

 cleanup:
  if (text_f) fclose(text_f);
  xfree(text_t);
  html_armor_free(&ab);
  return retval;
}

static int
cmd_op_edit_serve_global_field_detail(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int f_id, f_type;
  void *f_ptr;
  struct section_global_data *global;
  const unsigned char *valstr;
  int vallen;
  char **lns = 0;
  unsigned char *filt_txt = 0;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts || !phr->ss->global)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  global = phr->ss->global;
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTSGLOB_LAST_FIELD
      || !(global_editable_details[f_id]))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_ptr = cntsglob_get_ptr_nc(global, f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_type = cntsglob_get_type(f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (hr_cgi_param(phr, "param", &valstr) <= 0)
    FAIL(SSERV_ERR_INV_VALUE);
  if ((vallen = strlen(valstr)) > 128 * 1024)
    FAIL(SSERV_ERR_INV_VALUE);
  filt_txt = text_area_process_string(valstr, 0, 0);

  switch (f_id) {
  case CNTSGLOB_a2ps_args:
  case CNTSGLOB_lpr_args:
  case CNTSGLOB_user_priority_adjustments:
  case CNTSGLOB_contestant_status_legend:
    split_to_lines(filt_txt, &lns, 2);
    sarray_free(*(char***) f_ptr);
    *(char***) f_ptr = lns;
    lns = 0;
    break;

  case CNTSGLOB_stand_row_attr:
  case CNTSGLOB_stand_page_row_attr:
  case CNTSGLOB_stand_page_col_attr:
  case CNTSGLOB_contestant_status_row_attr:
    split_to_lines(filt_txt, &lns, 1);
    sarray_free(*(char***) f_ptr);
    *(char***) f_ptr = lns;
    lns = 0;
    break;

  case CNTSGLOB_unhandled_vars:
    xfree(*(unsigned char**) f_ptr);
    *(unsigned char**) f_ptr = 0;
    if (filt_txt && *filt_txt) {
      *(unsigned char**) f_ptr = filt_txt;
      filt_txt = 0;
    }
    break;
  default:
    FAIL(SSERV_ERR_INV_FIELD_ID);
  }
  retval = 1;

 cleanup:
  xfree(filt_txt);
  sarray_free(lns);
  return retval;
}

static int
cmd_op_set_sid_state_lang_field(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int lang_id = 0, cs_lang_id = 0;
  int f_id = 0;
  int val = -1;
  int new_id;
  struct html_armor_buffer vb = HTML_ARMOR_INITIALIZER;
  const unsigned char *sval = 0;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts || !phr->ss->global)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0)
    FAIL(SSERV_ERR_INV_FIELD_ID);

  switch (f_id) {
  case SSSS_lang_flags:         // show/hide
    // cs_lang_id is the compilation server language ID
    if (hr_cgi_param_int(phr, "item_id", &cs_lang_id) < 0)
      FAIL(SSERV_ERR_INV_LANG_ID);
    if (cs_lang_id <= 0 || cs_lang_id >= phr->ss->cs_lang_total
        || !phr->ss->cs_langs[cs_lang_id])
      FAIL(SSERV_ERR_INV_LANG_ID);
    new_id = phr->ss->cs_loc_map[cs_lang_id];
    if (hr_cgi_param_int(phr, "value", &val) < 0 || val < 0 || val > 1)
      FAIL(SSERV_ERR_INV_VALUE);
    phr->ss->lang_flags[new_id] = val;
    break;

  case SSSS_langs:              // activate/deactivate
    // cs_lang_id is the compilation server language ID
    if (hr_cgi_param_int(phr, "item_id", &cs_lang_id) < 0)
      FAIL(SSERV_ERR_INV_LANG_ID);
    if (cs_lang_id <= 0 || cs_lang_id >= phr->ss->cs_lang_total
        || !phr->ss->cs_langs[cs_lang_id])
      FAIL(SSERV_ERR_INV_LANG_ID);
    if (hr_cgi_param_int(phr, "value", &val) < 0 || val < 0 || val > 1)
      FAIL(SSERV_ERR_INV_VALUE);
    (val?super_html_lang_activate:super_html_lang_deactivate)(phr->ss, cs_lang_id);
    break;

  case SSSS_lang_opts:          // compiler options
    if (hr_cgi_param_int(phr, "item_id", &lang_id) < 0)
      FAIL(SSERV_ERR_INV_LANG_ID);
    if (lang_id <= 0 || lang_id >= phr->ss->lang_a
        || !phr->ss->langs[lang_id])
      FAIL(SSERV_ERR_INV_LANG_ID);
    if (ss_cgi_param_utf8_str(phr, "value", &vb, &sval) <= 0 || !sval)
      FAIL(SSERV_ERR_INV_VALUE);
    xfree(phr->ss->lang_opts[lang_id]);
    phr->ss->lang_opts[lang_id] = xstrdup(sval);
    break;

  case SSSS_lang_libs:          // compiler options
    if (hr_cgi_param_int(phr, "item_id", &lang_id) < 0)
      FAIL(SSERV_ERR_INV_LANG_ID);
    if (lang_id <= 0 || lang_id >= phr->ss->lang_a
        || !phr->ss->langs[lang_id])
      FAIL(SSERV_ERR_INV_LANG_ID);
    if (ss_cgi_param_utf8_str(phr, "value", &vb, &sval) <= 0 || !sval)
      FAIL(SSERV_ERR_INV_VALUE);
    xfree(phr->ss->lang_libs[lang_id]);
    phr->ss->lang_libs[lang_id] = xstrdup(sval);
    break;

  default:
    FAIL(SSERV_ERR_INV_FIELD_ID);
  }
  retval = 1;

 cleanup:
  html_armor_free(&vb);
  return retval;
}

static int
cmd_op_clear_sid_state_lang_field(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int lang_id = 0;
  int f_id = 0;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts || !phr->ss->langs)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "item_id", &lang_id) < 0)
    FAIL(SSERV_ERR_INV_LANG_ID);
  if (lang_id <= 0 || lang_id >= phr->ss->lang_a || !phr->ss->langs[lang_id])
    FAIL(SSERV_ERR_INV_LANG_ID);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  switch (f_id) {
  case SSSS_lang_opts:
    xfree(phr->ss->lang_opts[lang_id]);
    phr->ss->lang_opts[lang_id] = 0;
    break;
  case SSSS_lang_libs:
    xfree(phr->ss->lang_libs[lang_id]);
    phr->ss->lang_libs[lang_id] = 0;
    break;
  default:
    FAIL(SSERV_ERR_INV_FIELD_ID);
  }
  retval = 1;

 cleanup:
  return retval;
}

const unsigned char lang_editable_fields[CNTSLANG_LAST_FIELD] =
{
  [CNTSLANG_long_name] = 1,
  [CNTSLANG_disabled] = 1,
  [CNTSLANG_insecure] = 1,
  [CNTSLANG_disable_testing] = 1,
  [CNTSLANG_disable_auto_testing] = 1,
  [CNTSLANG_binary] = 1,
  [CNTSLANG_style_checker_cmd] = 1,
  [CNTSLANG_style_checker_env] = 1,
  [CNTSLANG_compiler_env] = 1,
  [CNTSLANG_unhandled_vars] = 1,
};

static int
cmd_op_set_serve_lang_field(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int lang_id = 0, f_id = 0, f_type;
  void *f_ptr;
  size_t f_size;
  struct html_armor_buffer vb = HTML_ARMOR_INITIALIZER;
  const unsigned char *valstr;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts || !phr->ss->langs)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "item_id", &lang_id) < 0)
    FAIL(SSERV_ERR_INV_LANG_ID);
  if (lang_id <= 0 || lang_id >= phr->ss->lang_a || !phr->ss->langs[lang_id])
    FAIL(SSERV_ERR_INV_LANG_ID);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!lang_editable_fields[f_id])
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_ptr = cntslang_get_ptr_nc(phr->ss->langs[lang_id], f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  f_type = cntslang_get_type(f_id);
  f_size = cntslang_get_size(f_id);
  switch (f_type) {
  case 'B':
    {
      ejintbool_t *p_bool = (ejintbool_t*) f_ptr;
      ejintbool_t val = -1;

      if (hr_cgi_param_int(phr, "value", &val) < 0 || val < 0 || val > 1)
        FAIL(SSERV_ERR_INV_VALUE);
      *p_bool = val;
      if (f_id == CNTSLANG_disable_auto_testing) retval = 1;
    }
    break;
  case 's':
    {
      unsigned char **p_str = (unsigned char **) f_ptr;

      if (ss_cgi_param_utf8_str(phr, "value", &vb, &valstr) < 0)
        FAIL(SSERV_ERR_INV_VALUE);
      xfree(*p_str); *p_str = 0;
      if (valstr) *p_str = xstrdup(valstr);
      retval = 1;
    }
    break;
  case 'S':
    {
      unsigned char *str = (unsigned char *) f_ptr;

      if (ss_cgi_param_utf8_str(phr, "value", &vb, &valstr) < 0)
        FAIL(SSERV_ERR_INV_VALUE);
      str[0] = 0;
      if (valstr) snprintf(str, f_size, "%s", valstr);
    }
    break;
  case 'X':
    {
      char **tmp_args = 0;
      char ***f_args = (char***) f_ptr;

      if (ss_cgi_param_utf8_str(phr, "value", &vb, &valstr) < 0)
        FAIL(SSERV_ERR_INV_VALUE);
      if (sarray_parse(valstr, &tmp_args) < 0) FAIL(SSERV_ERR_INV_VALUE);
      sarray_free(*f_args);
      *f_args = tmp_args;
      retval = 1;
    }
    break;
  default:
    FAIL(SSERV_ERR_INV_FIELD_ID);
  }

 cleanup:
  html_armor_free(&vb);
  return retval;
}

static int
cmd_op_clear_serve_lang_field(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int lang_id = 0, f_id = 0, f_type;
  void *f_ptr;
  size_t f_size;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts || !phr->ss->langs)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "item_id", &lang_id) < 0)
    FAIL(SSERV_ERR_INV_LANG_ID);
  if (lang_id <= 0 || lang_id >= phr->ss->lang_a || !phr->ss->langs[lang_id])
    FAIL(SSERV_ERR_INV_LANG_ID);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!lang_editable_fields[f_id])
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_ptr = cntslang_get_ptr_nc(phr->ss->langs[lang_id], f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  f_type = cntslang_get_type(f_id);
  f_size = cntslang_get_size(f_id);
  switch (f_type) {
  case 'B':
    *(ejintbool_t*) f_ptr = 0;
    break;
  case 's':
    xfree(*(char**) f_ptr);
    *(char**) f_ptr = 0;
    break;
  case 'S':
    memset(f_ptr, 0, f_size);
    break;
  case 'X':
    sarray_free(*(char***) f_ptr);
    *(char***) f_ptr = 0;
    break;
  default:
    FAIL(SSERV_ERR_INV_FIELD_ID);
  }
  retval = 1;

 cleanup:
  return retval;
}

const unsigned char lang_editable_details[CNTSLANG_LAST_FIELD] =
{
  [CNTSLANG_compiler_env] = 1,
  [CNTSLANG_style_checker_env] = 1,
  [CNTSLANG_unhandled_vars] = 1,
};

static int
cmd_op_edit_serve_lang_field_detail_page(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  const struct contest_desc *ecnts;
  int f_id, f_type, lang_id;
  unsigned char buf[1024];
  FILE *text_f = 0;
  char *text_t = 0;
  size_t text_z = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const void *f_ptr;

  if (!phr->ss->edited_cnts || !phr->ss->langs)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  ecnts = phr->ss->edited_cnts;
  if (hr_cgi_param_int(phr, "item_id", &lang_id) < 0
      || lang_id <= 0 || lang_id >= phr->ss->lang_a
      || !phr->ss->langs[lang_id])
    FAIL(SSERV_ERR_INV_LANG_ID);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTSLANG_LAST_FIELD
      || !(lang_editable_details[f_id]))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_ptr = cntslang_get_ptr(phr->ss->langs[lang_id], f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_type = cntslang_get_type(f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);

  text_f = open_memstream(&text_t, &text_z);
  switch (f_type) {
  case 's':
    {
      const unsigned char *s = *(const unsigned char**) f_ptr;
      if (s) fprintf(text_f, "%s", s);
    }
    break;
  case 'X':
    {
      const char *const * ss = *(const char *const **) f_ptr;
      if (ss) {
        for (int i = 0; ss[i]; ++i)
          fprintf(text_f, "%s\n", ss[i]);
      }
    }
    break;
  default:
    FAIL(SSERV_ERR_INV_FIELD_ID);
  }
  close_memstream(text_f); text_f = 0;

  snprintf(buf, sizeof(buf),
           "serve-control: %s, contest %d, language %s, editing %s",
           phr->html_name, ecnts->id, phr->ss->langs[lang_id]->short_name,
           cntslang_get_name(f_id));
  write_html_header(out_f, phr, buf, 1, 0);
  fprintf(out_f, "<h1>%s</h1>\n", buf);
  fprintf(out_f, "<br/>\n");

  fprintf(out_f, "<form id=\"editBox\"><textarea dojoType=\"dijit.form.Textarea\" name=\"param\" rows=\"20\" cols=\"80\">%s</textarea></form>\n",
          ARMOR(text_t));

  fprintf(out_f, "<br/>\n");

  ss_dojo_button(out_f, 0, "accept-32x32", "OK",
              "ssEditFileSave2(\"editBox\", %d, %d, %d, %d)",
              SSERV_CMD_EDIT_SERVE_LANG_FIELD_DETAIL, lang_id, f_id,
              SSERV_CMD_EDIT_CONTEST_PAGE_2);
  ss_dojo_button(out_f, 0, "cancel-32x32", "Cancel",
              "ssLoad1(%d)",
              SSERV_CMD_EDIT_CONTEST_PAGE_2);

  write_html_footer(out_f);

 cleanup:
  if (text_f) fclose(text_f);
  xfree(text_t);
  html_armor_free(&ab);
  return retval;
}

static int
cmd_op_edit_serve_lang_field_detail(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int f_id, f_type, lang_id;
  void *f_ptr;
  const unsigned char *valstr;
  int vallen;
  char **lns = 0;
  unsigned char *filt_txt = 0;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts || !phr->ss->langs)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "item_id", &lang_id) < 0
      || lang_id <= 0 || lang_id >= phr->ss->lang_a
      || !phr->ss->langs[lang_id])
    FAIL(SSERV_ERR_INV_LANG_ID);
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTSLANG_LAST_FIELD
      || !(lang_editable_details[f_id]))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_ptr = cntslang_get_ptr_nc(phr->ss->langs[lang_id], f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_type = cntslang_get_type(f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (hr_cgi_param(phr, "param", &valstr) <= 0)
    FAIL(SSERV_ERR_INV_VALUE);
  if ((vallen = strlen(valstr)) > 128 * 1024)
    FAIL(SSERV_ERR_INV_VALUE);
  filt_txt = text_area_process_string(valstr, 0, 0);

  switch (f_id) {
  case CNTSLANG_compiler_env:
  case CNTSLANG_style_checker_env:
    split_to_lines(filt_txt, &lns, 2);
    sarray_free(*(char***) f_ptr);
    *(char***) f_ptr = lns;
    lns = 0;
    break;

  case CNTSLANG_unhandled_vars:
    xfree(*(unsigned char**) f_ptr);
    *(unsigned char**) f_ptr = 0;
    if (filt_txt && *filt_txt) {
      *(unsigned char**) f_ptr = filt_txt;
      filt_txt = 0;
    }
    break;
  default:
    FAIL(SSERV_ERR_INV_FIELD_ID);
  }
  retval = 1;

 cleanup:
  xfree(filt_txt);
  sarray_free(lns);
  return retval;
}

static int
cmd_op_serve_lang_update_versions(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts || !phr->ss->langs)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  super_html_update_versions(phr->ss);

  retval = 1;

 cleanup:
  return retval;
}

static int
cmd_op_create_abstr_prob(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  const unsigned char *prob_name = 0;

  phr->json_reply = 1;

  if (hr_cgi_param(phr, "prob_name", &prob_name) <= 0) FAIL(SSERV_ERR_INV_PROB_ID);
  if (super_html_add_abstract_problem(phr->ss, prob_name) < 0)
    FAIL(SSERV_ERR_INV_PROB_ID);

  retval = 1;

 cleanup:
  return retval;
}

static int
cmd_op_create_concrete_prob(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  const unsigned char *s = 0, *p = 0;
  char *eptr = 0;
  int prob_id = 0;

  phr->json_reply = 1;

  if (hr_cgi_param(phr, "prob_id", &s) < 0) FAIL(SSERV_ERR_INV_PROB_ID);
  if (s) {
    p = s;
    while (*p && isspace(*p)) ++p;
    if (!*p) s = 0;
  }
  if (s) {
    errno = 0;
    prob_id = strtol(s, &eptr, 10);
    if (errno || *eptr || (char*) s == eptr) FAIL(SSERV_ERR_INV_PROB_ID);
    if (prob_id < 0 || prob_id > EJ_MAX_PROB_ID) FAIL(SSERV_ERR_INV_PROB_ID);
  }

  if (super_html_add_problem(phr->ss, prob_id) < 0) FAIL(SSERV_ERR_INV_PROB_ID);

  retval = 1;

 cleanup:
  return retval;
}

static int
cmd_op_delete_prob(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int prob_id = 0, i;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts || !phr->ss->global)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "item_id", &prob_id) < 0)
    FAIL(SSERV_ERR_INV_PROB_ID);
  if (prob_id < 0) {
    prob_id = -prob_id - 1;
    if (prob_id >= phr->ss->aprob_u) FAIL(SSERV_ERR_INV_PROB_ID);
    if (!phr->ss->aprobs[prob_id]) FAIL(SSERV_ERR_INV_PROB_ID);
    for (i = prob_id + 1; i < phr->ss->aprob_u; i++) {
      phr->ss->aprobs[i - 1] = phr->ss->aprobs[i];
      phr->ss->aprob_flags[i - 1] = phr->ss->aprob_flags[i];
    }
    phr->ss->aprob_u--;
    phr->ss->aprobs[phr->ss->aprob_u] = 0;
    phr->ss->aprob_flags[phr->ss->aprob_u] = 0;
  } else {
    if (prob_id <= 0 || prob_id >= phr->ss->prob_a) FAIL(SSERV_ERR_INV_PROB_ID);
    if (!phr->ss->probs[prob_id]) FAIL(SSERV_ERR_INV_PROB_ID);
    phr->ss->probs[prob_id] = 0;
    phr->ss->prob_flags[prob_id] = 0;
  }

  retval = 1;

 cleanup:
  return retval;
}

static int
cmd_op_set_sid_state_prob_field(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int f_id = -1, prob_id = 0, value = -1;
  int *p_flags = 0;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts || !phr->ss->global)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "item_id", &prob_id) < 0)
    FAIL(SSERV_ERR_INV_PROB_ID);
  if (prob_id < 0) {
    prob_id = -prob_id - 1;
    if (prob_id >= phr->ss->aprob_u) FAIL(SSERV_ERR_INV_PROB_ID);
    if (!phr->ss->aprobs[prob_id]) FAIL(SSERV_ERR_INV_PROB_ID);
    p_flags = &phr->ss->aprob_flags[prob_id];
  } else {
    if (prob_id <= 0 || prob_id >= phr->ss->prob_a) FAIL(SSERV_ERR_INV_PROB_ID);
    if (!phr->ss->probs[prob_id]) FAIL(SSERV_ERR_INV_PROB_ID);
    p_flags = &phr->ss->prob_flags[prob_id];
  }
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (hr_cgi_param_int(phr, "value", &value) < 0 || value < 0 || value > 1)
    FAIL(SSERV_ERR_INV_VALUE);

  switch (f_id) {
  case SSSS_prob_flags:         /* view details */
    if (value) {
      *p_flags |= SID_STATE_SHOW_HIDDEN;
    } else {
      *p_flags &= ~SID_STATE_SHOW_HIDDEN;
    }
    break;
  case SSSS_cur_prob:           /* view advanced details */
    if (value) {
      *p_flags |= SID_STATE_SHOW_CLOSED;
    } else {
      *p_flags &= ~SID_STATE_SHOW_CLOSED;
    }
    break;
  default:
    FAIL(SSERV_ERR_INV_FIELD_ID);
  }

  retval = 1;

 cleanup:
  return retval;
}

static const unsigned char prob_reloadable_set[CNTSPROB_LAST_FIELD] =
{
  [CNTSPROB_scoring_checker] = 0,
  [CNTSPROB_interactive_valuer] = 0,
  [CNTSPROB_disable_pe] = 0,
  [CNTSPROB_disable_wtl] = 0,
  [CNTSPROB_manual_checking] = 1,  
  [CNTSPROB_examinator_num] = 0,
  [CNTSPROB_check_presentation] = 1,
  [CNTSPROB_use_stdin] = 0,
  [CNTSPROB_use_stdout] = 0,
  [CNTSPROB_combined_stdin] = 0,
  [CNTSPROB_combined_stdout] = 0,
  [CNTSPROB_binary_input] = 0,
  [CNTSPROB_binary] = 0,
  [CNTSPROB_ignore_exit_code] = 0,
  [CNTSPROB_olympiad_mode] = 1,
  [CNTSPROB_score_latest] = 0,
  [CNTSPROB_score_latest_or_unmarked] = 0,
  [CNTSPROB_score_latest_marked] = 0,
  [CNTSPROB_time_limit] = 1,
  [CNTSPROB_time_limit_millis] = 1,
  [CNTSPROB_real_time_limit] = 1,
  [CNTSPROB_use_ac_not_ok] = 0,
  [CNTSPROB_ignore_prev_ac] = 0,
  [CNTSPROB_team_enable_rep_view] = 1,
  [CNTSPROB_team_enable_ce_view] = 1,
  [CNTSPROB_team_show_judge_report] = 1,
  [CNTSPROB_show_checker_comment] = 0,
  [CNTSPROB_ignore_compile_errors] = 0,
  [CNTSPROB_full_score] = 0,
  [CNTSPROB_test_score] = 0,
  [CNTSPROB_run_penalty] = 0,
  [CNTSPROB_acm_run_penalty] = 0,
  [CNTSPROB_disqualified_penalty] = 0,
  [CNTSPROB_ignore_penalty] = 0,
  [CNTSPROB_use_corr] = 1,
  [CNTSPROB_use_info] = 1,
  [CNTSPROB_use_tgz] = 1,
  [CNTSPROB_tests_to_accept] = 0,
  [CNTSPROB_accept_partial] = 0,
  [CNTSPROB_min_tests_to_accept] = 0,
  [CNTSPROB_checker_real_time_limit] = 0,
  [CNTSPROB_interactor_time_limit] = 0,
  [CNTSPROB_disable_auto_testing] = 1,
  [CNTSPROB_disable_testing] = 1,
  [CNTSPROB_disable_user_submit] = 1,
  [CNTSPROB_disable_tab] = 1,
  [CNTSPROB_unrestricted_statement] = 1,
  [CNTSPROB_hide_file_names] = 1,
  [CNTSPROB_disable_submit_after_ok] = 1,
  [CNTSPROB_disable_security] = 1,
  [CNTSPROB_enable_compilation] = 1,
  [CNTSPROB_skip_testing] = 1,
  [CNTSPROB_variable_full_score] = 1,
  [CNTSPROB_hidden] = 1,
  [CNTSPROB_priority_adjustment] = 0,
  [CNTSPROB_spelling] = 0,
  [CNTSPROB_stand_hide_time] = 0,
  [CNTSPROB_advance_to_next] = 0,
  [CNTSPROB_disable_ctrl_chars] = 0,
  [CNTSPROB_valuer_sets_marked] = 0,
  [CNTSPROB_ignore_unmarked] = 0,
  [CNTSPROB_disable_stderr] = 0,
  [CNTSPROB_enable_process_group] = 0,
  [CNTSPROB_enable_text_form] = 0,
  [CNTSPROB_stand_ignore_score] = 0,
  [CNTSPROB_stand_last_column] = 0,
  [CNTSPROB_score_multiplier] = 0,
  [CNTSPROB_prev_runs_to_show] = 0,
  [CNTSPROB_max_vm_size] = 0,
  [CNTSPROB_max_stack_size] = 0,
  [CNTSPROB_max_data_size] = 0,
  [CNTSPROB_max_core_size] = 0,
  [CNTSPROB_max_file_size] = 0,
  [CNTSPROB_max_open_file_count] = 0,
  [CNTSPROB_max_process_count] = 0,
  [CNTSPROB_super] = 1,
  [CNTSPROB_short_name] = 1,
  [CNTSPROB_long_name] = 1,
  [CNTSPROB_group_name] = 0,
  [CNTSPROB_stand_name] = 0,
  [CNTSPROB_stand_column] = 0,
  [CNTSPROB_internal_name] = 1,
  [CNTSPROB_test_dir] = 1,
  [CNTSPROB_test_sfx] = 1,
  [CNTSPROB_corr_dir] = 1,
  [CNTSPROB_corr_sfx] = 1,
  [CNTSPROB_info_dir] = 1,
  [CNTSPROB_info_sfx] = 1,
  [CNTSPROB_tgz_dir] = 1,
  [CNTSPROB_tgz_sfx] = 1,
  [CNTSPROB_tgzdir_sfx] = 1,
  [CNTSPROB_input_file] = 0,
  [CNTSPROB_output_file] = 0,
  [CNTSPROB_test_score_list] = 0,
  [CNTSPROB_score_tests] = 0,
  [CNTSPROB_test_sets] = 0,
  [CNTSPROB_deadline] = 0,
  [CNTSPROB_start_date] = 0,
  [CNTSPROB_variant_num] = 1,
  [CNTSPROB_date_penalty] = 0,
  [CNTSPROB_group_start_date] = 0,
  [CNTSPROB_group_deadline] = 0,
  [CNTSPROB_disable_language] = 0,
  [CNTSPROB_enable_language] = 0,
  [CNTSPROB_require] = 0,
  [CNTSPROB_provide_ok] = 0,
  [CNTSPROB_standard_checker] = 1,
  [CNTSPROB_lang_compiler_env] = 0,
  [CNTSPROB_checker_env] = 0,
  [CNTSPROB_valuer_env] = 0,
  [CNTSPROB_interactor_env] = 0,
  [CNTSPROB_style_checker_env] = 0,
  [CNTSPROB_test_checker_env] = 0,
  [CNTSPROB_init_env] = 0,
  [CNTSPROB_start_env] = 0,
  [CNTSPROB_lang_time_adj] = 0,
  [CNTSPROB_lang_time_adj_millis] = 0,
  [CNTSPROB_lang_max_vm_size] = 0,
  [CNTSPROB_lang_max_stack_size] = 0,
  [CNTSPROB_check_cmd] = 0,
  [CNTSPROB_valuer_cmd] = 0,
  [CNTSPROB_interactor_cmd] = 0,
  [CNTSPROB_style_checker_cmd] = 0,
  [CNTSPROB_test_checker_cmd] = 0,
  [CNTSPROB_init_cmd] = 0,
  [CNTSPROB_solution_src] = 0,
  [CNTSPROB_solution_cmd] = 0,
  [CNTSPROB_test_pat] = 1,
  [CNTSPROB_corr_pat] = 1,
  [CNTSPROB_info_pat] = 1,
  [CNTSPROB_tgz_pat] = 1,
  [CNTSPROB_tgzdir_pat] = 1,
  [CNTSPROB_personal_deadline] = 0,
  [CNTSPROB_score_bonus] = 0,
  [CNTSPROB_open_tests] = 0,
  [CNTSPROB_final_open_tests] = 0,
  [CNTSPROB_statement_file] = 1,
  [CNTSPROB_alternatives_file] = 0,
  [CNTSPROB_plugin_file] = 1,
  [CNTSPROB_xml_file] = 1,
  [CNTSPROB_type] = 1,
  [CNTSPROB_alternative] = 0,
  [CNTSPROB_stand_attr] = 0,
  [CNTSPROB_source_header] = 0,
  [CNTSPROB_source_footer] = 0,
  [CNTSPROB_score_view] = 0,
};

static int prob_int_field_min[CNTSPROB_LAST_FIELD] =
{
  [CNTSPROB_examinator_num] = 0,
  [CNTSPROB_time_limit] = 0,
  [CNTSPROB_time_limit_millis] = 0,
  [CNTSPROB_real_time_limit] = 0,
  [CNTSPROB_checker_real_time_limit] = 0,
  [CNTSPROB_interactor_time_limit] = 0,
  [CNTSPROB_full_score] = 0,
  [CNTSPROB_test_score] = 0,
  [CNTSPROB_run_penalty] = 0,
  [CNTSPROB_disqualified_penalty] = 0,
  [CNTSPROB_acm_run_penalty] = 0,
  [CNTSPROB_tests_to_accept] = 0,
  [CNTSPROB_min_tests_to_accept] = 0,
  [CNTSPROB_variant_num] = 0,
};

static int prob_int_field_max[CNTSPROB_LAST_FIELD] =
{
  [CNTSPROB_type] = PROB_TYPE_LAST - 1,
  [CNTSPROB_examinator_num] = 3,
  [CNTSPROB_time_limit] = 2000000000,
  [CNTSPROB_time_limit_millis] = 2000000000,
  [CNTSPROB_real_time_limit] = 2000000000,
  [CNTSPROB_checker_real_time_limit] = 2000000000,
  [CNTSPROB_interactor_time_limit] = 2000000000,
  [CNTSPROB_full_score] = 2000000000,
  [CNTSPROB_test_score] = 2000000000,
  [CNTSPROB_run_penalty] = 2000000000,
  [CNTSPROB_disqualified_penalty] = 2000000000,
  [CNTSPROB_acm_run_penalty] = 2000000000,
  [CNTSPROB_tests_to_accept] = 2000000000,
  [CNTSPROB_min_tests_to_accept] = 2000000000,
  [CNTSPROB_variant_num] = 255,
};

static int
cmd_op_set_serve_prob_field(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int prob_id = 0, f_id = 0, is_inh, f_type, i, was_undef, is_undef;
  struct section_problem_data *prob = 0;
  const struct section_problem_data *p2 = 0;
  const unsigned char *valstr = 0;
  size_t vallen, f_size;
  void *f_ptr;
  struct html_armor_buffer vb = HTML_ARMOR_INITIALIZER;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts || !phr->ss->global)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "item_id", &prob_id) < 0)
    FAIL(SSERV_ERR_INV_PROB_ID);
  if (prob_id >= 0) {
    if (prob_id <= 0 || prob_id >= phr->ss->prob_a
        || !(prob = phr->ss->probs[prob_id]))
      FAIL(SSERV_ERR_INV_PROB_ID);
  } else if (prob_id < 0) {
    prob_id = ~prob_id;
    if (prob_id >= phr->ss->aprob_u || !(prob = phr->ss->aprobs[prob_id]))
      FAIL(SSERV_ERR_INV_PROB_ID);
  }
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTSPROB_LAST_FIELD)
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (f_id == CNTSPROB_id 
      || f_id == CNTSPROB_tester_id
      || f_id == CNTSPROB_abstract
      || !cntsprob_is_settable_field(f_id))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  was_undef = cntsprob_is_undefined(prob, f_id);
  if (!(f_ptr = cntsprob_get_ptr_nc(prob, f_id))) FAIL(SSERV_ERR_INV_FIELD_ID);
  f_type = cntsprob_get_type(f_id);
  f_size = cntsprob_get_size(f_id);
  if (hr_cgi_param(phr, "value", &valstr) <= 0)
    FAIL(SSERV_ERR_INV_VALUE);
  if ((vallen = strlen(valstr)) >= 128 * 1024)
    FAIL(SSERV_ERR_INV_VALUE);
  is_inh = cntsprob_is_inheritable_field(f_id);

  // 'i', 'B', 'S', 'x', 't', 'X', 'Z', 'z'
  switch (f_type) {
  case 'i':
    errno = 0;
    {
      char *eptr = 0;
      int val = strtol(valstr, &eptr, 10);
      if (errno || *eptr || (char*) valstr == eptr) FAIL(SSERV_ERR_INV_VALUE);
      if (val < prob_int_field_min[f_id] || val > prob_int_field_max[f_id])
        FAIL(SSERV_ERR_INV_VALUE);
      * (int*) f_ptr = val;
    }
    break;
  case 'B':
    errno = 0;
    {
      char *eptr = 0;
      ejintbool_t val = -1;
      if (valstr && *valstr) {
        val = strtol(valstr, &eptr, 10);
        if (errno || *eptr || (char*) valstr == eptr) FAIL(SSERV_ERR_INV_VALUE);
      }
      if (val < -is_inh || val > 1) FAIL(SSERV_ERR_INV_VALUE);
      * (ejintbool_t*) f_ptr = val;
      retval = 1;
    }
    break;
  case 'S':
    if (ss_cgi_param_utf8_str(phr, "value", &vb, &valstr) <= 0 || !valstr)
      FAIL(SSERV_ERR_INV_VALUE);
    switch (f_id) {
    case CNTSPROB_short_name:
      if (check_str(valstr, login_accept_chars) < 0)
        FAIL(SSERV_ERR_INV_VALUE);
      for (i = 0; i < phr->ss->aprob_u; ++i)
        if ((p2 = phr->ss->aprobs[i]) && p2 != prob
            && !strcmp(valstr, p2->short_name))
          FAIL(SSERV_ERR_INV_VALUE);
      for (i = 0; i < phr->ss->prob_a; ++i)
        if ((p2 = phr->ss->probs[i]) && p2 != prob
            && !strcmp(valstr, p2->short_name))
          FAIL(SSERV_ERR_INV_VALUE);
      break;
    case CNTSPROB_super:
      if (prob->abstract) FAIL(SSERV_ERR_INV_VALUE);
      for (i = 0; i < phr->ss->aprob_u; ++i)
        if ((p2 = phr->ss->aprobs[i]) && !strcmp(valstr, p2->short_name))
          break;
      if (i >= phr->ss->aprob_u) FAIL(SSERV_ERR_INV_VALUE);
      break;
      //case CNTSPROB_internal_name:
    case CNTSPROB_standard_checker:
      if (!strcmp(valstr, "__undefined__")) valstr = "\1";
      break;
    }
    snprintf((unsigned char*) f_ptr, f_size, "%s", valstr);
    break;
  case 't':
    retval = handle_time_t_editing(phr, valstr, (time_t*) f_ptr);
    break;
  case 'x':
    {
      char **tmp_args = 0;
      char ***f_args = (char***) f_ptr;

      if (ss_cgi_param_utf8_str(phr, "value", &vb, &valstr) < 0)
        FAIL(SSERV_ERR_INV_VALUE);
      if (sarray_parse_2(valstr, &tmp_args) < 0) FAIL(SSERV_ERR_INV_VALUE);
      sarray_free(*f_args);
      *f_args = tmp_args;
      retval = 1;
    }
    break;
  case 'X':
    {
      char **tmp_args = 0;
      char ***f_args = (char***) f_ptr;

      if (ss_cgi_param_utf8_str(phr, "value", &vb, &valstr) < 0)
        FAIL(SSERV_ERR_INV_VALUE);
      if (sarray_parse(valstr, &tmp_args) < 0) FAIL(SSERV_ERR_INV_VALUE);
      sarray_free(*f_args);
      *f_args = tmp_args;
      retval = 1;
    }
    break;
  case 'Z':
    {
      size_t val = 0;
      if (parse_size(valstr, &val) < 0) FAIL(SSERV_ERR_INV_VALUE);
      * (size_t*) f_ptr = val;
    }
    break;
  case 'z':
    {
      size_t val = 0;
      if (parse_size(valstr, &val) < 0) FAIL(SSERV_ERR_INV_VALUE);
      * (ejintsize_t*) f_ptr = val;
    }
    break;
  default:
    FAIL(SSERV_ERR_INV_FIELD_ID);
  }

  is_undef = cntsprob_is_undefined(prob, f_id);
  retval = prob_reloadable_set[f_id] || is_undef || was_undef;

 cleanup:
  return retval;
}

static int
cmd_op_clear_serve_prob_field(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int prob_id = 0, f_id = 0;
  struct section_problem_data *prob = 0;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts || !phr->ss->global)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "item_id", &prob_id) < 0)
    FAIL(SSERV_ERR_INV_PROB_ID);
  if (prob_id >= 0) {
    if (prob_id <= 0 || prob_id >= phr->ss->prob_a
        || !(prob = phr->ss->probs[prob_id]))
      FAIL(SSERV_ERR_INV_PROB_ID);
  } else if (prob_id < 0) {
    prob_id = ~prob_id;
    if (prob_id >= phr->ss->aprob_u || !(prob = phr->ss->aprobs[prob_id]))
      FAIL(SSERV_ERR_INV_PROB_ID);
  }
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTSPROB_LAST_FIELD)
    FAIL(SSERV_ERR_INV_FIELD_ID);

  cntsprob_clear_field(prob, f_id);
 
  retval = 1;

 cleanup:
  return retval;
}

const unsigned char prob_editable_details[CNTSPROB_LAST_FIELD] =
{
  [CNTSPROB_lang_compiler_env] = 1,
  [CNTSPROB_checker_env] = 1,
  [CNTSPROB_valuer_env] = 1,
  [CNTSPROB_interactor_env] = 1,
  [CNTSPROB_style_checker_env] = 1,
  [CNTSPROB_test_checker_env] = 1,
  [CNTSPROB_init_env] = 1,
  [CNTSPROB_start_env] = 1,
  [CNTSPROB_score_view] = 1,
  [CNTSPROB_lang_time_adj] = 1,
  [CNTSPROB_lang_time_adj_millis] = 1,
  [CNTSPROB_lang_max_vm_size] = 1,
  [CNTSPROB_lang_max_stack_size] = 1,
  [CNTSPROB_disable_language] = 1,
  [CNTSPROB_enable_language] = 1,
  [CNTSPROB_require] = 1,
  [CNTSPROB_provide_ok] = 1,
  [CNTSPROB_unhandled_vars] = 1,
};

static int
cmd_op_edit_serve_prob_field_detail_page(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  const struct contest_desc *ecnts;
  int f_id, f_type, prob_id;
  unsigned char buf[1024];
  FILE *text_f = 0;
  char *text_t = 0;
  size_t text_z = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const void *f_ptr;
  const struct section_problem_data *prob = 0;

  if (!phr->ss->edited_cnts || !phr->ss->global)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  ecnts = phr->ss->edited_cnts;
  if (hr_cgi_param_int(phr, "item_id", &prob_id) < 0)
    FAIL(SSERV_ERR_INV_PROB_ID);
  if (prob_id >= 0) {
    if (prob_id <= 0 || prob_id >= phr->ss->prob_a
        || !(prob = phr->ss->probs[prob_id]))
      FAIL(SSERV_ERR_INV_PROB_ID);
  } else if (prob_id < 0) {
    prob_id = ~prob_id;
    if (prob_id >= phr->ss->aprob_u || !(prob = phr->ss->aprobs[prob_id]))
      FAIL(SSERV_ERR_INV_PROB_ID);
  }
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTSPROB_LAST_FIELD
      || !(prob_editable_details[f_id]))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_ptr = cntsprob_get_ptr(prob, f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_type = cntsprob_get_type(f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);

  text_f = open_memstream(&text_t, &text_z);
  switch (f_type) {
  case 's':
    {
      const unsigned char *s = *(const unsigned char**) f_ptr;
      if (s) fprintf(text_f, "%s", s);
    }
    break;
  case 'X':
  case 'x':
    {
      const char *const * ss = *(const char *const **) f_ptr;
      if (ss) {
        for (int i = 0; ss[i]; ++i)
          fprintf(text_f, "%s\n", ss[i]);
      }
    }
    break;
  default:
    FAIL(SSERV_ERR_INV_FIELD_ID);
  }
  close_memstream(text_f); text_f = 0;

  snprintf(buf, sizeof(buf),
           "serve-control: %s, contest %d, problem %s, editing %s",
           phr->html_name, ecnts->id, prob->short_name,
           cntsprob_get_name(f_id));
  write_html_header(out_f, phr, buf, 1, 0);
  fprintf(out_f, "<h1>%s</h1>\n", buf);
  fprintf(out_f, "<br/>\n");

  fprintf(out_f, "<form id=\"editBox\"><textarea dojoType=\"dijit.form.Textarea\" name=\"param\" rows=\"20\" cols=\"80\">%s</textarea></form>\n",
          ARMOR(text_t));

  fprintf(out_f, "<br/>\n");

  ss_dojo_button(out_f, 0, "accept-32x32", "OK",
              "ssEditFileSave2(\"editBox\", %d, %d, %d, %d)",
              SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL, prob_id, f_id,
              SSERV_CMD_EDIT_CONTEST_PAGE_2);
  ss_dojo_button(out_f, 0, "cancel-32x32", "Cancel",
              "ssLoad1(%d)",
              SSERV_CMD_EDIT_CONTEST_PAGE_2);

  write_html_footer(out_f);

 cleanup:
  if (text_f) fclose(text_f);
  xfree(text_t);
  html_armor_free(&ab);
  return retval;
}

static int
cmd_op_edit_serve_prob_field_detail(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  int f_id, f_type, prob_id;
  void *f_ptr;
  const unsigned char *valstr;
  int vallen;
  unsigned char *filt_txt = 0;
  struct section_problem_data *prob = 0;
  char **lns = 0;

  phr->json_reply = 1;

  if (!phr->ss->edited_cnts || !phr->ss->global)
    FAIL(SSERV_ERR_NO_EDITED_CNTS);
  if (hr_cgi_param_int(phr, "item_id", &prob_id) < 0)
    FAIL(SSERV_ERR_INV_PROB_ID);
  if (prob_id >= 0) {
    if (prob_id <= 0 || prob_id >= phr->ss->prob_a
        || !(prob = phr->ss->probs[prob_id]))
      FAIL(SSERV_ERR_INV_PROB_ID);
  } else if (prob_id < 0) {
    prob_id = ~prob_id;
    if (prob_id >= phr->ss->aprob_u || !(prob = phr->ss->aprobs[prob_id]))
      FAIL(SSERV_ERR_INV_PROB_ID);
  }
  if (hr_cgi_param_int(phr, "field_id", &f_id) < 0
      || f_id <= 0 || f_id >= CNTSPROB_LAST_FIELD
      || !(prob_editable_details[f_id]))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_ptr = cntsprob_get_ptr_nc(prob, f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (!(f_type = cntsprob_get_type(f_id)))
    FAIL(SSERV_ERR_INV_FIELD_ID);
  if (hr_cgi_param(phr, "param", &valstr) <= 0)
    FAIL(SSERV_ERR_INV_VALUE);
  if ((vallen = strlen(valstr)) > 128 * 1024)
    FAIL(SSERV_ERR_INV_VALUE);
  filt_txt = text_area_process_string(valstr, 0, 0);

  switch (f_id) {
  case CNTSPROB_lang_compiler_env:
  case CNTSPROB_checker_env:
  case CNTSPROB_valuer_env:
  case CNTSPROB_interactor_env:
  case CNTSPROB_style_checker_env:
  case CNTSPROB_test_checker_env:
  case CNTSPROB_init_env:
  case CNTSPROB_start_env:
  case CNTSPROB_score_view:
  case CNTSPROB_lang_time_adj:
  case CNTSPROB_lang_time_adj_millis:
  case CNTSPROB_lang_max_vm_size:
  case CNTSPROB_lang_max_stack_size:
  case CNTSPROB_disable_language:
  case CNTSPROB_enable_language:
  case CNTSPROB_require:
  case CNTSPROB_provide_ok:
    split_to_lines(filt_txt, &lns, 2);
    sarray_free(*(char***) f_ptr);
    *(char***) f_ptr = lns;
    lns = 0;
    break;

  case CNTSPROB_unhandled_vars:
    xfree(*(unsigned char**) f_ptr);
    *(unsigned char**) f_ptr = 0;
    if (filt_txt && *filt_txt) {
      *(unsigned char**) f_ptr = filt_txt;
      filt_txt = 0;
    }
    break;
  default:
    FAIL(SSERV_ERR_INV_FIELD_ID);
  }

  retval = 1;

 cleanup:
  xfree(filt_txt);
  sarray_free(lns);
  return retval;
}

static handler_func_t op_handlers[SSERV_CMD_LAST] =
{
  [SSERV_CMD_VIEW_CNTS_DETAILS] = cmd_cnts_details,
  [SSERV_CMD_EDITED_CNTS_BACK] = cmd_edited_cnts_back,
  [SSERV_CMD_EDITED_CNTS_CONTINUE] = cmd_edited_cnts_continue,
  [SSERV_CMD_EDITED_CNTS_START_NEW] = cmd_edited_cnts_start_new,
  [SSERV_CMD_LOCKED_CNTS_FORGET] = cmd_locked_cnts_forget,
  [SSERV_CMD_LOCKED_CNTS_CONTINUE] = cmd_locked_cnts_continue,
  [SSERV_CMD_EDIT_CONTEST_PAGE] = cmd_edit_contest_page,
  [SSERV_CMD_EDIT_CONTEST_PAGE_2] = cmd_edit_contest_page_2,
  [SSERV_CMD_CLEAR_CONTEST_XML_FIELD] = cmd_clear_contest_xml_field,
  [SSERV_CMD_EDIT_CONTEST_XML_FIELD] = cmd_edit_contest_xml_field,
  [SSERV_CMD_TOGGLE_CONTEST_XML_VISIBILITY] = cmd_toggle_contest_xml_vis,
  [SSERV_CMD_CONTEST_XML_FIELD_EDIT_PAGE] = cmd_contest_xml_field_edit_page,
  [SSERV_CMD_CLEAR_FILE_CONTEST_XML] = cmd_clear_file_contest_xml,
  [SSERV_CMD_RELOAD_FILE_CONTEST_XML] = cmd_clear_file_contest_xml,
  [SSERV_CMD_SAVE_FILE_CONTEST_XML] = cmd_save_file_contest_xml,
  [SSERV_CMD_COPY_ACCESS_RULES_PAGE] = cmd_copy_access_rules_page,
  [SSERV_CMD_COPY_ALL_ACCESS_RULES_PAGE] = cmd_copy_all_access_rules_page,
  [SSERV_CMD_COPY_ALL_ACCESS_RULES] = cmd_copy_all_access_rules,
  [SSERV_CMD_COPY_ALL_PRIV_USERS_PAGE] = cmd_copy_all_priv_users_page,
  [SSERV_CMD_EDIT_PERMISSIONS_PAGE] = cmd_edit_permissions_page,
  [SSERV_CMD_EDIT_GENERAL_FIELDS_PAGE] = cmd_edit_general_fields_page,
  [SSERV_CMD_EDIT_MEMBER_FIELDS_PAGE] = cmd_edit_member_fields_page,
  [SSERV_CMD_DELETE_PRIV_USER] = cmd_op_delete_priv_user,
  [SSERV_CMD_ADD_PRIV_USER] = cmd_op_add_priv_user,
  [SSERV_CMD_COPY_ALL_PRIV_USERS] = cmd_op_copy_all_priv_users,
  [SSERV_CMD_SET_PREDEF_PRIV] = cmd_op_set_predef_priv,
  [SSERV_CMD_SET_PRIV] = cmd_op_set_priv,
  [SSERV_CMD_SET_DEFAULT_ACCESS] = cmd_op_set_default_access,
  [SSERV_CMD_CHECK_IP_MASK] = cmd_op_check_ip_mask,
  [SSERV_CMD_ADD_IP] = cmd_op_add_ip,
  [SSERV_CMD_SET_RULE_ACCESS] = cmd_op_set_rule_access,
  [SSERV_CMD_SET_RULE_SSL] = cmd_op_set_rule_ssl,
  [SSERV_CMD_SET_RULE_IP] = cmd_op_set_rule_ip,
  [SSERV_CMD_DELETE_RULE] = cmd_op_rule_cmd,
  [SSERV_CMD_FORWARD_RULE] = cmd_op_rule_cmd,
  [SSERV_CMD_BACKWARD_RULE] = cmd_op_rule_cmd,
  [SSERV_CMD_COPY_ACCESS_RULES] = cmd_op_copy_access_rules,
  [SSERV_CMD_EDIT_GENERAL_FIELDS] = cmd_op_edit_general_fields,
  [SSERV_CMD_EDIT_MEMBER_FIELDS] = cmd_op_edit_member_fields,
  [SSERV_CMD_CREATE_NEW_CONTEST_PAGE] = cmd_op_create_new_contest_page,
  [SSERV_CMD_CREATE_NEW_CONTEST] = cmd_op_create_new_contest,
  [SSERV_CMD_FORGET_CONTEST] = cmd_op_forget_contest,
  [SSERV_CMD_EDIT_SERVE_GLOBAL_FIELD] = cmd_op_edit_serve_global_field,
  [SSERV_CMD_CLEAR_SERVE_GLOBAL_FIELD] = cmd_op_clear_serve_global_field,
  [SSERV_CMD_EDIT_SID_STATE_FIELD] = cmd_op_edit_sid_state_field,
  [SSERV_CMD_EDIT_SID_STATE_FIELD_NEGATED] = cmd_op_edit_sid_state_field_neg,
  [SSERV_CMD_EDIT_SERVE_GLOBAL_FIELD_DETAIL_PAGE] = cmd_op_edit_serve_global_field_detail_page,
  [SSERV_CMD_EDIT_SERVE_GLOBAL_FIELD_DETAIL] = cmd_op_edit_serve_global_field_detail,
  [SSERV_CMD_SET_SID_STATE_LANG_FIELD] = cmd_op_set_sid_state_lang_field,
  [SSERV_CMD_CLEAR_SID_STATE_LANG_FIELD] = cmd_op_clear_sid_state_lang_field,
  [SSERV_CMD_SET_SERVE_LANG_FIELD] = cmd_op_set_serve_lang_field,
  [SSERV_CMD_CLEAR_SERVE_LANG_FIELD] = cmd_op_clear_serve_lang_field,
  [SSERV_CMD_EDIT_SERVE_LANG_FIELD_DETAIL_PAGE] = cmd_op_edit_serve_lang_field_detail_page,
  [SSERV_CMD_EDIT_SERVE_LANG_FIELD_DETAIL] = cmd_op_edit_serve_lang_field_detail,
  [SSERV_CMD_SERVE_LANG_UPDATE_VERSIONS] = cmd_op_serve_lang_update_versions,
  [SSERV_CMD_CREATE_ABSTR_PROB] = cmd_op_create_abstr_prob,
  [SSERV_CMD_CREATE_CONCRETE_PROB] = cmd_op_create_concrete_prob,
  [SSERV_CMD_DELETE_PROB] = cmd_op_delete_prob,
  [SSERV_CMD_SET_SID_STATE_PROB_FIELD] = cmd_op_set_sid_state_prob_field,
  [SSERV_CMD_SET_SERVE_PROB_FIELD] = cmd_op_set_serve_prob_field,
  [SSERV_CMD_CLEAR_SERVE_PROB_FIELD] = cmd_op_clear_serve_prob_field,
  [SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL_PAGE] = cmd_op_edit_serve_prob_field_detail_page,
  [SSERV_CMD_EDIT_SERVE_PROB_FIELD_DETAIL] = cmd_op_edit_serve_prob_field_detail,

  [SSERV_CMD_BROWSE_PROBLEM_PACKAGES] = super_serve_op_browse_problem_packages,
  [SSERV_CMD_CREATE_PACKAGE] = super_serve_op_package_operation,
  [SSERV_CMD_CREATE_PROBLEM] = super_serve_op_edit_problem,
  [SSERV_CMD_DELETE_ITEM] = super_serve_op_package_operation,
  [SSERV_CMD_EDIT_PROBLEM] = super_serve_op_edit_problem,

  /* Note: operations SSERV_CMD_USER_*, SSERV_CMD_GROUP_* are loaded using dlsym */
};

extern void super_html_6_force_link(void);
void *super_html_6_force_link_ptr = super_html_6_force_link;
extern void super_html_7_force_link(void);
void *super_html_7_force_link_ptr = super_html_7_force_link;

static int
parse_opcode(struct http_request_info *phr, int *p_opcode)
{
  const unsigned char *s = NULL;
  if (hr_cgi_param(phr, "op", &s) <= 0 || !s || !*s) {
    *p_opcode = 0;
    return 0;
  }
  const unsigned char *q;
  for (q = s; isdigit(*q); ++q) {}
  if (!*q) {
    char *eptr = NULL;
    errno = 0;
    long val = strtol(s, &eptr, 10);
    if (errno || *eptr) return SSERV_ERR_INV_OPER;
    if (val < 0 || val >= SSERV_CMD_LAST) return SSERV_ERR_INV_OPER;
    *p_opcode = val;
    return 0;
  }

  for (int i = 1; i < SSERV_CMD_LAST; ++i) {
    if (!strcasecmp(super_proto_cmd_names[i], s)) {
      *p_opcode = i;
      return 0;
    }
  }
  *p_opcode = 0;
  return 0;
}

static int
parse_action(struct http_request_info *phr)
{
  int action = 0;
  int n = 0, r = 0;
  const unsigned char *s = 0;

  if ((s = hr_cgi_nname(phr, "action_", 7))) {
    if (sscanf(s, "action_%d%n", &action, &n) != 1 || s[n] || action < 0 || action >= SSERV_CMD_LAST) {
      return -1;
    }
  } else if ((r = hr_cgi_param(phr, "action", &s)) < 0 || !s || !*s) {
    phr->action = 0;
    return 0;
  } else {
    if (sscanf(s, "%d%n", &action, &n) != 1 || s[n] || action < 0 || action >= SSERV_CMD_LAST) {
      return -1;
    }
  }

  if (action == SSERV_CMD_HTTP_REQUEST) {
    // compatibility option: parse op
    if ((s = hr_cgi_nname(phr, "op_", 3))) {
      if (sscanf(s, "op_%d%n", &action, &n) != 1 || s[n] || action < 0 || action >= SSERV_CMD_LAST)
        return -1;
    } else if (parse_opcode(phr, &action) < 0) {
      return -1;
    }
  }
  phr->action = action;
  return action;
}

static void *self_dl_handle = 0;
static int
do_http_request(FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
  int action = 0;
  int retval = 0;

  if ((action = parse_action(phr)) < 0) {
    FAIL(SSERV_ERR_INV_OPER);
  }

  if (!super_proto_cmd_names[action]) FAIL(SSERV_ERR_INV_OPER);
  if (op_handlers[action] == (handler_func_t) 1) FAIL(SSERV_ERR_NOT_IMPLEMENTED);

  if (!op_handlers[action]) {
    if (self_dl_handle == (void*) 1) FAIL(SSERV_ERR_NOT_IMPLEMENTED);
    self_dl_handle = dlopen(NULL, RTLD_NOW);
    if (!self_dl_handle) {
      err("do_http_request: dlopen failed: %s", dlerror());
      self_dl_handle = (void*) 1;
      FAIL(SSERV_ERR_NOT_IMPLEMENTED);
    }

    int redir_action = action;
    if (super_proto_op_redirect[action] > 0) {
      redir_action = super_proto_op_redirect[action];
      if (redir_action <= 0 || redir_action >= SSERV_CMD_LAST || !super_proto_cmd_names[redir_action]) {
        err("do_http_request: invalid action redirect %d->%d", action, redir_action);
        op_handlers[action] = (handler_func_t) 1;
        FAIL(SSERV_ERR_NOT_IMPLEMENTED);
      }
      if (op_handlers[redir_action] == (handler_func_t) 1) {
        err("do_http_request: not implemented action redirect %d->%d", action, redir_action);
        op_handlers[action] = (handler_func_t) 1;
        FAIL(SSERV_ERR_NOT_IMPLEMENTED);
      }
    }

    if (op_handlers[redir_action]) {
      op_handlers[action] = op_handlers[redir_action];
    } else {
      unsigned char func_name[512];
      snprintf(func_name, sizeof(func_name), "super_serve_op_%s", super_proto_cmd_names[redir_action]);
      void *void_func = dlsym(self_dl_handle, func_name);
      if (!void_func) {
        err("do_http_request: function %s is not found", func_name);
        op_handlers[action] = (handler_func_t) 1;
        FAIL(SSERV_ERR_NOT_IMPLEMENTED);
      }
      op_handlers[action] = (handler_func_t) void_func;
    }
  }

  retval = (*op_handlers[action])(log_f, out_f, phr);

 cleanup:
  return retval;
}

static void
parse_cookie(struct http_request_info *phr)
{
  const unsigned char *cookies = hr_getenv(phr, "HTTP_COOKIE");
  if (!cookies) return;
  const unsigned char *s = cookies;
  ej_cookie_t client_key = 0;
  while (1) {
    while (isspace(*s)) ++s;
    if (strncmp(s, "EJSID=", 6) != 0) {
      while (*s && *s != ';') ++s;
      if (!*s) return;
      ++s;
      continue;
    }
    int n = 0;
    if (sscanf(s + 6, "%llx%n", &client_key, &n) == 1) {
      s += 6 + n;
      if (!*s || isspace(*s) || *s == ';') {
        phr->client_key = client_key;
        return;
      }
    }
    phr->client_key = 0;
    return;
  }
}

static const int external_action_aliases[SSERV_CMD_LAST] =
{
  [SSERV_CMD_SERVE_CFG_PAGE] = SSERV_CMD_CONTEST_XML_PAGE,
  [SSERV_CMD_CNTS_EDIT_USERS_ACCESS_PAGE] = SSERV_CMD_CNTS_EDIT_REGISTER_ACCESS_PAGE,
  [SSERV_CMD_CNTS_EDIT_MASTER_ACCESS_PAGE] = SSERV_CMD_CNTS_EDIT_REGISTER_ACCESS_PAGE,
  [SSERV_CMD_CNTS_EDIT_JUDGE_ACCESS_PAGE] = SSERV_CMD_CNTS_EDIT_REGISTER_ACCESS_PAGE,
  [SSERV_CMD_CNTS_EDIT_TEAM_ACCESS_PAGE] = SSERV_CMD_CNTS_EDIT_REGISTER_ACCESS_PAGE,
  [SSERV_CMD_CNTS_EDIT_SERVE_CONTROL_ACCESS_PAGE] = SSERV_CMD_CNTS_EDIT_REGISTER_ACCESS_PAGE,
  [SSERV_CMD_CNTS_EDIT_RESERVE_FIELDS_PAGE] = SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS_PAGE,
  [SSERV_CMD_CNTS_EDIT_COACH_FIELDS_PAGE] = SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS_PAGE,
  [SSERV_CMD_CNTS_EDIT_ADVISOR_FIELDS_PAGE] = SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS_PAGE,
  [SSERV_CMD_CNTS_EDIT_GUEST_FIELDS_PAGE] = SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS_PAGE,
  [SSERV_CMD_GLOB_EDIT_CONTEST_STOP_CMD_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_GLOB_EDIT_STAND_HEADER_FILE_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_GLOB_EDIT_STAND_FOOTER_FILE_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_GLOB_EDIT_STAND2_HEADER_FILE_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_GLOB_EDIT_STAND2_FOOTER_FILE_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_GLOB_EDIT_PLOG_HEADER_FILE_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_GLOB_EDIT_PLOG_FOOTER_FILE_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_CNTS_EDIT_USERS_HEADER_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_CNTS_EDIT_USERS_FOOTER_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_CNTS_EDIT_COPYRIGHT_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_CNTS_EDIT_WELCOME_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_CNTS_EDIT_REG_WELCOME_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_CNTS_EDIT_REGISTER_EMAIL_FILE_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_CNTS_START_EDIT_VARIANT_ACTION] = SSERV_CMD_CNTS_EDIT_CUR_VARIANT_PAGE,
};
static const unsigned char * const external_action_names[SSERV_CMD_LAST] =
{
  [SSERV_CMD_BROWSE_PROBLEM_PACKAGES] = "problem_packages_page",
  [SSERV_CMD_LOGIN_PAGE] = "login_page",
  [SSERV_CMD_MAIN_PAGE] = "main_page",
  [SSERV_CMD_CONTEST_PAGE] = "contest_page",
  [SSERV_CMD_CONTEST_XML_PAGE] = "contest_xml_page",
  [SSERV_CMD_CREATE_CONTEST_PAGE] = "create_contest_page",
  [SSERV_CMD_CREATE_CONTEST_2_ACTION] = "create_contest_2_action",
  [SSERV_CMD_CONTEST_ALREADY_EDITED_PAGE] = "contest_already_edited_page",
  [SSERV_CMD_CONTEST_LOCKED_PAGE] = "contest_locked_page",
  [SSERV_CMD_CHECK_TESTS_PAGE] = "check_tests_page",
  [SSERV_CMD_CNTS_EDIT_PERMISSIONS_PAGE] = "cnts_edit_permissions_page",
  [SSERV_CMD_CNTS_EDIT_REGISTER_ACCESS_PAGE] = "cnts_edit_access_page",
  [SSERV_CMD_CNTS_EDIT_USER_FIELDS_PAGE] = "cnts_edit_user_fields_page",
  [SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS_PAGE] = "cnts_edit_member_fields_page",
  [SSERV_CMD_CNTS_START_EDIT_ACTION] = "cnts_start_edit_action",
  [SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE] = "cnts_edit_cur_contest_page",
  [SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE] = "cnts_edit_file_page",
  [SSERV_CMD_CNTS_RELOAD_FILE_ACTION] = "cnts_reload_file_action",
  [SSERV_CMD_CNTS_CLEAR_FILE_ACTION] = "cnts_clear_file_action",
  [SSERV_CMD_CNTS_SAVE_FILE_ACTION] = "cnts_save_file_action",
  [SSERV_CMD_CNTS_EDIT_CUR_GLOBAL_PAGE] = "cnts_edit_cur_global_page",
  [SSERV_CMD_CNTS_EDIT_CUR_LANGUAGE_PAGE] = "cnts_edit_cur_language_page",
  [SSERV_CMD_CNTS_EDIT_CUR_PROBLEM_PAGE] = "cnts_edit_cur_problem_page",
  [SSERV_CMD_CNTS_START_EDIT_PROBLEM_ACTION] = "cnts_start_edit_problem_action",
  [SSERV_CMD_CNTS_EDIT_CUR_VARIANT_PAGE] = "cnts_edit_cur_variant_page",
  [SSERV_CMD_CNTS_NEW_SERVE_CFG_PAGE] = "cnts_new_serve_cfg_page",
  [SSERV_CMD_CNTS_COMMIT_PAGE] = "cnts_commit_page",
};

static const unsigned char * const external_error_names[SSERV_ERR_LAST] = 
{
  [1] = "error_unknown_page", // here comes the default error handler
};

static ExternalActionState *external_action_states[SSERV_CMD_LAST];
static ExternalActionState *external_error_states[SSERV_ERR_LAST];

static void
default_error_page(
        char **p_out_t,
        size_t *p_out_z,
        struct http_request_info *phr)
{
  if (phr->log_f) {
    fclose(phr->log_f); phr->log_f = NULL;
  }
  FILE *out_f = open_memstream(p_out_t, p_out_z);

  if (phr->error_code < 0) phr->error_code = -phr->error_code;
  unsigned char buf[32];
  const unsigned char *errmsg = 0;
  if (phr->error_code > 0 && phr->error_code < SSERV_ERR_LAST) {
    errmsg = super_proto_error_messages[phr->error_code];
  }
  if (!errmsg) {
    snprintf(buf, sizeof(buf), "%d", phr->error_code);
    errmsg = buf;
  }

  fprintf(out_f, "Content-type: text/html; charset=%s\n\n", EJUDGE_CHARSET);
  fprintf(out_f,
          "<html>\n"
          "<head>\n"
          "<title>Error: %s</title>\n"
          "</head>\n"
          "<body>\n"
          "<h1>Error: %s</h1>\n",
          errmsg, errmsg);
  if (phr->log_t && *phr->log_t) {
    fprintf(out_f, "<p>Additional messages:</p>\n");
    unsigned char *s = html_armor_string_dup(phr->log_t);
    fprintf(out_f, "<pre><font color=\"red\">%s</font></pre>\n", s);
    xfree(s); s = NULL;
    xfree(phr->log_t); phr->log_t = NULL;
    phr->log_z = 0;
  }
  fprintf(out_f, "</body>\n</html>\n");
  fclose(out_f); out_f = NULL;
}

typedef PageInterface *(*external_action_handler_t)(void);

static void
external_error_page(
        char **p_out_t,
        size_t *p_out_z,
        struct http_request_info *phr,
        int error_code)
{
  if (error_code < 0) error_code = -error_code;
  if (error_code <= 0 || error_code >= SSERV_ERR_LAST) error_code = 1;
  phr->error_code = error_code;

  if (!external_error_names[error_code]) error_code = 1;
  if (!external_error_names[error_code]) {
    default_error_page(p_out_t, p_out_z, phr);
    return;
  }

  external_error_states[error_code] = external_action_load(external_error_states[error_code],
                                                           "csp/super-server",
                                                           external_error_names[error_code],
                                                           "csp_get_",
                                                           phr->current_time);
  if (!external_error_states[error_code] || !external_error_states[error_code]->action_handler) {
    default_error_page(p_out_t, p_out_z, phr);
    return;
  }
  PageInterface *pg = ((external_action_handler_t) external_error_states[error_code]->action_handler)();
  if (!pg) {
    default_error_page(p_out_t, p_out_z, phr);
    return;
  }

  phr->out_f = open_memstream(p_out_t, p_out_z);
  fprintf(phr->out_f, "Content-type: text/html; charset=%s\n\n", EJUDGE_CHARSET);
  pg->ops->render(pg, NULL, phr->out_f, phr);
  xfree(phr->log_t); phr->log_t = NULL;
  phr->log_z = 0;
  fclose(phr->out_f); phr->out_f = NULL;
}

void
super_html_http_request(
        char **p_out_t,
        size_t *p_out_z,
        struct http_request_info *phr)
{
  int r = 0, n;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *script_name = 0;
  const unsigned char *protocol = "http";
  const unsigned char *s = 0;
  unsigned char self_url_buf[4096];
  unsigned char context_url[4096];
  unsigned char hid_buf[4096];
  int ext_action = 0;

  if (hr_getenv(phr, "SSL_PROTOCOL") || hr_getenv(phr, "HTTPS")) {
    phr->ssl_flag = 1;
    protocol = "https";
  }
  if (!(phr->http_host = hr_getenv(phr, "HTTP_HOST"))) phr->http_host = "localhost";
  if (!(script_name = hr_getenv(phr, "SCRIPT_NAME")))
    script_name = "/cgi-bin/serve-control";
  snprintf(self_url_buf, sizeof(self_url_buf), "%s://%s%s", protocol, phr->http_host, script_name);
  phr->self_url = self_url_buf;
  phr->script_name = script_name;

  snprintf(context_url, sizeof(context_url), "%s", phr->self_url);
  unsigned char *rs = strrchr(context_url, '/');
  if (rs) *rs = 0;
  phr->context_url = context_url;

  if (phr->anonymous_mode) {
    phr->action = SSERV_CMD_LOGIN_PAGE;
  } else {
    parse_cookie(phr);
    if (parse_action(phr) < 0) {
      r = -SSERV_ERR_INV_OPER;
    } else {
      r = 0;
    }

    if (!r) {
      if ((r = hr_cgi_param(phr, "SID", &s)) < 0) {
        r = -SSERV_ERR_INV_SID;
      }
      if (r > 0) {
        r = 0;
        if (sscanf(s, "%llx%n", &phr->session_id, &n) != 1
            || s[n] || !phr->session_id) {
          r = -SSERV_ERR_INV_SID;
        }
      }
    }
  }

  hr_cgi_param_int_opt(phr, "contest_id", &phr->contest_id, 0);

  if (!r) {
    // try external actions
    ext_action = phr->action;

redo_action:
    // main_page by default
    if (!super_proto_cmd_names[ext_action]) ext_action = SSERV_CMD_MAIN_PAGE;

    if (ext_action < 0 || ext_action >= SSERV_CMD_LAST) ext_action = 0;
    if (external_action_aliases[ext_action] > 0) ext_action = external_action_aliases[ext_action];
    if (external_action_names[ext_action]) {
      if (phr->current_time <= 0) phr->current_time = time(NULL);
      external_action_states[ext_action] = external_action_load(external_action_states[ext_action],
                                                                "csp/super-server",
                                                                external_action_names[ext_action],
                                                                "csp_get_",
                                                                phr->current_time);
      if (!external_action_states[ext_action] || !external_action_states[ext_action]->action_handler) {
        external_error_page(p_out_t, p_out_z, phr, SSERV_ERR_INV_OPER);
        return;
      }

      snprintf(hid_buf, sizeof(hid_buf),
               "<input type=\"hidden\" name=\"SID\" value=\"%016llx\"/>",
               phr->session_id);
      phr->hidden_vars = hid_buf;

      phr->log_f = open_memstream(&phr->log_t, &phr->log_z);
      phr->out_f = open_memstream(&phr->out_t, &phr->out_z);
      PageInterface *pg = ((external_action_handler_t) external_action_states[ext_action]->action_handler)();
      if (pg->ops->execute) {
        r = pg->ops->execute(pg, phr->log_f, phr);
        if (r < 0) {
          fclose(phr->out_f); phr->out_f = NULL;
          xfree(phr->out_t); phr->out_t = NULL;
          phr->out_z = 0;
          external_error_page(p_out_t, p_out_z, phr, -r);
          return;
        }
      }
      if (pg->ops->render) {
        snprintf(phr->content_type, sizeof(phr->content_type), "text/html; charset=%s", EJUDGE_CHARSET);
        r = pg->ops->render(pg, phr->log_f, phr->out_f, phr);
        if (r < 0) {
          fclose(phr->out_f); phr->out_f = NULL;
          xfree(phr->out_t); phr->out_t = NULL;
          phr->out_z = 0;
          external_error_page(p_out_t, p_out_z, phr, -r);
          return;
        }
        if (r > 0) {
          ext_action = r;
          if (pg->ops->destroy) pg->ops->destroy(pg);
          pg = NULL;
          fclose(phr->out_f); phr->out_f = NULL;
          xfree(phr->out_t); phr->out_t = NULL;
          goto redo_action;
        }
      }
      if (pg->ops->destroy) {
        pg->ops->destroy(pg);
      }
      pg = NULL;

      fclose(phr->log_f); phr->log_f = NULL;
      xfree(phr->log_t); phr->log_t = NULL;
      phr->log_z = 0;
      fclose(phr->out_f); phr->out_f = NULL;

      if (phr->redirect) {
        xfree(phr->out_t); phr->out_t = NULL;
        phr->out_z = 0;

        FILE *tmp_f = open_memstream(p_out_t, p_out_z);
        if (phr->client_key) {
          fprintf(tmp_f, "Set-Cookie: EJSID=%016llx; Path=/\n", phr->client_key);
        }
        fprintf(tmp_f, "Location: %s\n\n", phr->redirect);
        fclose(tmp_f); tmp_f = NULL;

        xfree(phr->redirect); phr->redirect = NULL;
      } else {
        FILE *tmp_f = open_memstream(p_out_t, p_out_z);
        fprintf(tmp_f, "Content-type: %s\n\n", phr->content_type);
        fwrite(phr->out_t, 1, phr->out_z, tmp_f);
        fclose(tmp_f); tmp_f = NULL;

        xfree(phr->out_t); phr->out_t = NULL;
        phr->out_z = 0;
      }
      return;
    }
  }

  if (!r) {
    phr->out_f = open_memstream(&phr->out_t, &phr->out_z);
    phr->log_f = open_memstream(&phr->log_t, &phr->log_z);
    r = do_http_request(phr->log_f, phr->out_f, phr);
    if (r >= 0 && phr->suspend_reply) {
      html_armor_free(&ab);
      return;
    }
    close_memstream(phr->out_f); phr->out_f = 0;
    close_memstream(phr->log_f); phr->log_f = 0;
  }

  if (r < 0) {
    xfree(phr->out_t); phr->out_t = 0; phr->out_z = 0;
    phr->out_f = open_memstream(&phr->out_t, &phr->out_z);
    if (phr->json_reply) {
      write_json_header(phr->out_f);
      fprintf(phr->out_f, "{ \"status\": %d, \"text\": \"%s\" }",
              r, super_proto_error_messages[-r]);
    } else {
      write_html_header(phr->out_f, phr, "Request failed", 0, 0);
      if (r < -1 && r > -SSERV_ERR_LAST) {
        fprintf(phr->out_f, "<h1>Request failed: error %d</h1>\n", -r);
        fprintf(phr->out_f, "<h2>%s</h2>\n", super_proto_error_messages[-r]);
      } else {
        fprintf(phr->out_f, "<h1>Request failed</h1>\n");
      }
      fprintf(phr->out_f, "<pre><font color=\"red\">%s</font></pre>\n",
              ARMOR(phr->log_t));
      write_html_footer(phr->out_f);
    }
    close_memstream(phr->out_f); phr->out_f = 0;
  }
  xfree(phr->log_t); phr->log_t = 0; phr->log_z = 0;

  if (!phr->out_t || !*phr->out_t) {
    xfree(phr->out_t); phr->out_t = 0; phr->out_z = 0;
    phr->out_f = open_memstream(&phr->out_t, &phr->out_z);
    if (phr->json_reply) {
      write_json_header(phr->out_f);
      fprintf(phr->out_f, "{ \"status\": %d }", r);
    } else {
      write_html_header(phr->out_f, phr, "Empty output", 0, 0);
      fprintf(phr->out_f, "<h1>Empty output</h1>\n");
      fprintf(phr->out_f, "<p>The output page is empty!</p>\n");
      write_html_footer(phr->out_f);
    }
    close_memstream(phr->out_f); phr->out_f = 0;
  }

  /*
  if (phr->json_reply) {
    fprintf(stderr, "json: %s\n", out_t);
  }
  */

  *p_out_t = phr->out_t;
  *p_out_z = phr->out_z;
  html_armor_free(&ab);
}

void *super_html_forced_link[] =
{
  html_date_select
};
