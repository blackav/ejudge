/* -*- mode: c -*- */

/* Copyright (C) 2006-2021 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_types.h"
#include "ejudge/ej_limits.h"
#include "ejudge/new-server.h"
#include "ejudge/new_server_proto.h"
#include "ejudge/prepare.h"
#include "ejudge/misctext.h"
#include "ejudge/errlog.h"
#include "ejudge/contests.h"
#include "ejudge/l10n.h"
#include "ejudge/xml_utils.h"
#include "ejudge/copyright.h"
#include "ejudge/team_extra.h"
#include "ejudge/xuser_plugin.h"

#include "ejudge/xalloc.h"

#include <stdarg.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif
#define __(x) x

#if !defined CONF_STYLE_PREFIX
#define CONF_STYLE_PREFIX "/ejudge/"
#endif

#pragma GCC diagnostic ignored "-Wformat-security"

#define ARMOR(s)  html_armor_buf(&ab, s)

const unsigned char ns_default_header[] =
"<html><head>"
"<meta http-equiv=\"Content-Type\" content=\"%T; charset=%C\">\n"
"<title>%H</title>\n"
"</head>\n"
"<body><h1>%H</h1>\n";
const unsigned char ns_default_separator[] = "";
const unsigned char ns_default_footer[] =
"<hr>%R</body></html>\n";

const unsigned char ns_fancy_priv_header[] =
"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
"<html><head>\n<meta http-equiv=\"Content-type\" content=\"text/html; charset=%C\">\n"
"<link rel=\"stylesheet\" href=\"" CONF_STYLE_PREFIX "priv.css\" type=\"text/css\">\n"
  //"<link rel=\"shortcut icon\" type=\"image/x-icon\" href=\"/favicon.ico\">\n"
"<script type=\"text/javascript\" charset=\"UTF-8\" src=\"" CONF_STYLE_PREFIX "priv.js\"></script>\n"
"<title>%H</title></head>\n"
"<body>"
"<h1>%H</h1>\n";
const unsigned char ns_fancy_priv_separator[] = "";
const unsigned char ns_fancy_priv_footer[] =
"<hr>%R</body></html>\n";

const unsigned char ns_fancy_header[] =
"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
"<html><head>\n<meta http-equiv=\"Content-type\" content=\"text/html; charset=%C\"/>\n"
"%S"
"<link rel=\"stylesheet\" href=\"%Y\" type=\"text/css\"/>\n"
  //"<link rel=\"shortcut icon\" type=\"image/x-icon\" href=\"/favicon.ico\"/>\n"
"<title>%H</title></head>\n"
  //"<body onload=\"startClock()\">"
  //"<body>"
"<body%B>"
"<div id=\"container\"><div id=\"l12\">\n"
"<div class=\"main_phrase\">%H</div>\n";
const unsigned char ns_fancy_empty_status[] =
"<div class=\"user_actions\"><table class=\"menu\"><tr>\n"
"<td class=\"menu\"><div class=\"user_action_item\">&nbsp;</div></td></tr></table></div>\n"
"<div class=\"white_empty_block\">&nbsp;</div>\n"
"<div class=\"contest_actions\"><table class=\"menu\"><tr>\n"
"<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td></tr></table></div>\n";
const unsigned char ns_fancy_separator[] =
"</div>\n"
"<div id=\"l11\"><img src=\"%O\" alt=\"logo\"/></div>\n"
"<div id=\"l13\">\n";
const unsigned char ns_fancy_footer[] =
"<div id=\"footer\">%R</div>\n"
"</div>"
"</div>"
"</body>"
"</html>";
const unsigned char ns_fancy_footer_2[] =
"%R"
"</div>"
"</div>"
"</body>"
"</html>";

// %1 - upper menu
// %2 - lower menu
// %3 - separator text
// %4 - contest status
const unsigned char ns_fancy_unpriv_content_header[] =
"<div class=\"user_actions\"><table class=\"menu\"><tr>%1</tr></table></div><div class=\"white_empty_block\">&nbsp;</div><div class=\"contest_actions\"><table class=\"menu\"><tr>%2</tr></table></div>%3%4";
//"%2<div class=\"white_empty_block\">&nbsp;</div>%4%3";

const unsigned char * const ns_ssl_flag_str[] =
{
  "http", "https",
};

static void
process_template(
        FILE *out,
        unsigned char const *templ,
        unsigned char const *content_type,
        unsigned char const *charset,
        unsigned char const *title,
        unsigned char const *copyright,
        const unsigned char *script_part,
        const unsigned char *body_attr,
        int locale_id,
        const unsigned char *logo_url,
        const unsigned char *css_url)
{
  unsigned char const *s = templ;

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
    case 'S':
      fputs(script_part, out);
      break;
    case 'B':
      fputs(body_attr, out);
      break;
    case 'O':
      fputs(logo_url, out);
      break;
    case 'Y':
      fputs(css_url, out);
      break;
    default:
      putc('%', out);
      continue;
    }
    s++;
  }
}

void
ns_header(
        FILE *out,
        unsigned char const *templ,
        unsigned char const *content_type,
        unsigned char const *charset,
        const unsigned char *script_part,
        const unsigned char *body_attr,
        int locale_id,
        const struct contest_desc *cnts,
        ej_cookie_t client_key,
        char const *format,
        ...)
{
  va_list args;
  unsigned char title[1024];
  const unsigned char *logo_url = 0;
  const unsigned char *css_url = 0;

  title[0] = 0;
  if (format) {
    va_start(args, format);
    vsnprintf(title, sizeof(title), format, args);
    va_end(args);
  }

  if (!charset) charset = EJUDGE_CHARSET;
  if (!content_type) content_type = "text/html";
  if (!templ) templ = ns_default_header;
  if (!script_part) script_part = "";
  if (!body_attr) body_attr = "";

  if (cnts) {
    logo_url = cnts->logo_url;
    css_url = cnts->css_url;
  }
  if (!logo_url) {
#if defined CONF_STYLE_PREFIX
    logo_url = CONF_STYLE_PREFIX "logo.gif";
#else
    logo_url = "logo.gif";
#endif
  }
  if (!css_url) {
#if defined CONF_STYLE_PREFIX
    css_url = CONF_STYLE_PREFIX "unpriv.css";
#else
    css_url = "unpriv.css";
#endif
  }

  fprintf(out, "Content-Type: %s; charset=%s\n"
          "Cache-Control: no-cache\n"
          "Pragma: no-cache\n", content_type, charset);
  if (client_key) {
    fprintf(out, "Set-Cookie: EJSID=%016llx; Path=/; SameSite=Lax\n", client_key);
  }
  putc('\n', out);

  process_template(out, templ, content_type, charset, title, 0,
                   script_part, body_attr, locale_id, logo_url, css_url);
}

void
ns_separator(
        FILE *out,
        unsigned char const *templ,
        const struct contest_desc *cnts)
{
  const unsigned char *logo_url = 0;

  if (cnts) logo_url = cnts->logo_url;
  if (!logo_url) {
#if defined CONF_STYLE_PREFIX
    logo_url = CONF_STYLE_PREFIX "logo.gif";
#else
    logo_url = "logo.gif";
#endif
  }

  process_template(out, templ, NULL, NULL, NULL, NULL, NULL, NULL, 0, logo_url, NULL);
}

void
ns_footer(
        FILE *out,
        unsigned char const *templ,
        const unsigned char *copyright,
        int locale_id)
{
  if (!copyright) copyright = get_copyright(locale_id);
  if (!templ) templ = ns_default_footer;
  process_template(out, templ, 0, 0, 0, copyright, 0, 0, 0, NULL, NULL);
}

// very basic error messaging
void
ns_html_error(
        FILE *fout,
        struct http_request_info *phr,
        int priv_mode,
        int error_code)
{
  const unsigned char *title = ns_error_title(error_code);
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  err("%d: html error: %d, %d (%s)", phr->id, priv_mode, error_code, title);

  if (phr->log_f) {
    fclose(phr->log_f); phr->log_f = NULL;
  }

  l10n_setlocale(phr->locale_id);
  title = ns_error_title(error_code);
  fprintf(fout, "<html><head>\n"
          "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\">\n"
          "<title>%s</title>\n"
          "</head>\n"
          "<body><h1>%s</h1>\n",
          EJUDGE_CHARSET, title, title);
  if (phr->log_t && *phr->log_t) {
    fprintf(fout, "<p>%s</p>\n", _("Error details follow"));
    fprintf(fout, "<font color=\"red\"><pre>%s</pre></font>\n", ARMOR(phr->log_t));
  }
  fprintf(fout, "</body></html>\n");
  xfree(phr->log_t); phr->log_t = NULL;
  phr->log_z = 0;
  l10n_resetlocale();
}
