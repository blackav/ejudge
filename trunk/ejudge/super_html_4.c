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

#include "super_html.h"
#include "super-serve.h"
#include "super_proto.h"
#include "copyright.h"
#include "misctext.h"

#include <reuse/xalloc.h>

#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>

/* These error codes are only used in this module */
enum
{
  S_ERR_INV_OPER = 2,
  S_ERR_CONTEST_EDITED,
  S_ERR_INVALID_SID,

  S_ERR_LAST
};

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
write_html_header(FILE *out_f, const unsigned char *title)
{
  fprintf(out_f, fancy_priv_header,
          "text/html", EJUDGE_CHARSET, EJUDGE_CHARSET, CONF_STYLE_PREFIX,
          title);
}

static const char fancy_priv_footer[] =
"<hr/>%s</body></html>\n";
static void
write_html_footer(FILE *out_f)
{
  fprintf(out_f, fancy_priv_footer, get_copyright(0));
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

static handler_func_t op_handlers[SSERV_OP_LAST] =
{
  [SSERV_OP_VIEW_CNTS_DETAILS] = cmd_cnts_details,
  [SSERV_OP_EDITED_CNTS_BACK] = cmd_edited_cnts_back,
  [SSERV_OP_EDITED_CNTS_CONTINUE] = cmd_edited_cnts_continue,
  [SSERV_OP_EDITED_CNTS_START_NEW] = cmd_edited_cnts_start_new,
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
  [S_ERR_INV_OPER] = "Invalid operation",
  [S_ERR_CONTEST_EDITED] = "Cannot edit more than one contest at a time",
  [S_ERR_INVALID_SID] = "Invalid session id",
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

  if ((r = ss_cgi_param(phr, "SID", &s)) < 0) {
    r = -S_ERR_INVALID_SID;
  }
  if (r > 0) {
    r = 0;
    if (sscanf(s, "%llx%n", &phr->session_id, &n) != 1
        || s[n] || !phr->session_id) {
      r = -S_ERR_INVALID_SID;
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
    write_html_header(out_f, "Request failed");
    if (r < -1 && r > -S_ERR_LAST) {
      fprintf(out_f, "<h1>Request failed: error %d</h1>\n", -r);
      fprintf(out_f, "<h2>%s</h2>\n", error_messages[-r]);
    } else {
      fprintf(out_f, "<h1>Request failed</h1>\n");
    }
    fprintf(out_f, "<pre><font color=\"red\">%s</font></pre>\n", ARMOR(log_t));
    write_html_footer(out_f);
    fclose(out_f); out_f = 0;
  }
  xfree(log_t); log_t = 0; log_z = 0;

  if (!out_t || !*out_t) {
    xfree(out_t); out_t = 0; out_z = 0;
    out_f = open_memstream(&out_t, &out_z);
    write_html_header(out_f, "Empty output");
    fprintf(out_f, "<h1>Empty output</h1>\n");
    fprintf(out_f, "<p>The output page is empty!</p>\n");
    write_html_footer(out_f);
    fclose(out_f); out_f = 0;
  }

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
