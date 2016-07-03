/* -*- mode: c -*- */

/* Copyright (C) 2006-2016 Alexander Chernov <cher@ejudge.ru> */

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
    fprintf(out, "Set-Cookie: EJSID=%016llx; Path=/\n", client_key);
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

void
ns_html_err_no_perm(
        FILE *fout,
        struct http_request_info *phr,
        int priv_mode,
        const char *format, ...)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  const unsigned char *header = 0, *footer = 0, *separator = 0;
  const unsigned char *copyright = 0;
  time_t cur_time = time(0);
  unsigned char buf[1024];
  va_list args;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);
  err("%d: permission denied: %s", phr->id, buf);

  if (phr->contest_id > 0) contests_get(phr->contest_id, &cnts);
  if (cnts) extra = ns_get_contest_extra(phr->contest_id);
  if (extra && !priv_mode) {
    watched_file_update(&extra->copyright, cnts->copyright_file, cur_time);
    copyright = extra->copyright.text;
  } else if (extra && priv_mode) {
  }
  if (!priv_mode) {
    header = ns_fancy_header;
    separator = ns_fancy_separator;
    if (copyright) footer = ns_fancy_footer_2;
    else footer = ns_fancy_footer;
  } else {
    header = ns_fancy_priv_header;
    separator = ns_fancy_priv_separator;
    footer = ns_fancy_priv_footer;
  }
  l10n_setlocale(phr->locale_id);
  ns_header(fout, header, 0, 0, 0, 0, phr->locale_id, cnts, NULL_CLIENT_KEY, _("Permission denied"));
  fprintf(fout, "%s", ns_fancy_empty_status);
  ns_separator(fout, separator, cnts);
  fprintf(fout, "<p>%s</p>\n",
          _("Permission denied. The possible reasons are as follows."));
  fprintf(fout, "<ul>\n");
  fprintf(fout, _("<li>You have typed an invalid login (<tt>%s</tt>).</li>\n"),
          ARMOR(phr->login));
  fprintf(fout, _("<li>You have typed an invalid password.</li>\n"));
  if (!priv_mode) {
    if (cnts) {
      fprintf(fout, _("<li>You are not registered for contest %s.</li>\n"),
              ARMOR(cnts->name));
    } else {
      fprintf(fout, _("<li>You are not registered for contest %d.</li>\n"),
              phr->contest_id);
    }
    fprintf(fout, _("<li>Your registration was not confirmed.</li>\n"));
    fprintf(fout, _("<li>You were banned by the administrator.</li>\n"));
    fprintf(fout, _("<li>Your IP-address (<tt>%s</tt>) or protocol (<tt>%s</tt>) is banned for participation.</li>"), xml_unparse_ipv6(&phr->ip),
            ns_ssl_flag_str[phr->ssl_flag]);
    fprintf(fout, _("<li>The contest is closed for participation.</li>\n"));
    //fprintf(fout, _("<li>The server might be overloaded.</li>\n"));
  } else {
    fprintf(fout, _("<li>Your IP-address (<tt>%s</tt>) or protocol (<tt>%s</tt>) is banned for participation.</li>"), xml_unparse_ipv6(&phr->ip), ns_ssl_flag_str[phr->ssl_flag]);
    fprintf(fout, _("<li>You do not have permissions to login using the specified role.</li>"));
  }
  fprintf(fout, "</ul>\n");
  fprintf(fout, _("<p>Note, that the exact reason is not reported due to security reasons.</p>"));

  fprintf(fout, "<p><big><a href=\"%s?contest_id=%d&amp;locale_id=%d\">%s</a></big></p>", phr->self_url, phr->contest_id, phr->locale_id,
          _("Try again"));

  ns_footer(fout, footer, copyright, phr->locale_id);
  l10n_resetlocale();
  html_armor_free(&ab);
}

void
ns_html_err_inv_param(FILE *fout,
                      struct http_request_info *phr,
                      int priv_mode,
                      const char *format, ...)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  const unsigned char *header = 0, *footer = 0, *separator = 0;
  const unsigned char *copyright = 0;
  time_t cur_time = time(0);
  unsigned char buf[1024];
  va_list args;

  if (format && *format) {
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    err("%d: invalid parameter: %s", phr->id, buf);
  } else {
    err("%d: invalid parameter", phr->id);
  }

  if (phr->contest_id > 0) contests_get(phr->contest_id, &cnts);
  if (cnts) extra = ns_get_contest_extra(phr->contest_id);
  if (extra && !priv_mode) {
    watched_file_update(&extra->copyright, cnts->copyright_file, cur_time);
    copyright = extra->copyright.text;
  } else if (extra && priv_mode) {
  }
  if (!priv_mode) {
    header = ns_fancy_header;
    separator = ns_fancy_separator;
    if (copyright) footer = ns_fancy_footer_2;
    else footer = ns_fancy_footer;
  } else {
    header = ns_fancy_priv_header;
    separator = ns_fancy_priv_separator;
    footer = ns_fancy_priv_footer;
  }
  l10n_setlocale(phr->locale_id);
  ns_header(fout, header, 0, 0, 0, 0, phr->locale_id, cnts, NULL_CLIENT_KEY, _("Invalid parameter"));
  fprintf(fout, "%s", ns_fancy_empty_status);
  ns_separator(fout, separator, cnts);
  fprintf(fout, "<p>%s</p>\n",
          _("A request parameter is invalid. Please, contact the site administrator."));
  ns_footer(fout, footer, copyright, phr->locale_id);
  l10n_resetlocale();
}

void
ns_html_err_service_not_available(FILE *fout,
                                  struct http_request_info *phr,
                                  int priv_mode,
                                  const char *format, ...)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  const unsigned char *header = 0, *footer = 0, *separator = 0;
  const unsigned char *copyright = 0;
  time_t cur_time = time(0);
  unsigned char buf[1024];
  va_list args;

  if (format && *format) {
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    err("%d: service not available: %s", phr->id, buf);
  } else {
    err("%d: service not available", phr->id);
  }

  if (phr->contest_id > 0) contests_get(phr->contest_id, &cnts);
  if (cnts) extra = ns_get_contest_extra(phr->contest_id);
  if (extra) {
    watched_file_update(&extra->copyright, cnts->copyright_file, cur_time);
    copyright = extra->copyright.text;
  }

  // try fancy headers
  if (!priv_mode) {
    header = ns_fancy_header;
    separator = ns_fancy_separator;
    if (copyright) footer = ns_fancy_footer_2;
    else footer = ns_fancy_footer;
  } else {
    header = ns_fancy_priv_header;
    separator = ns_fancy_priv_separator;
    footer = ns_fancy_priv_footer;
  }
  l10n_setlocale(phr->locale_id);
  ns_header(fout, header, 0, 0, 0, 0, phr->locale_id, cnts, NULL_CLIENT_KEY, _("Service not available"));
  fprintf(fout, "%s", ns_fancy_empty_status);
  ns_separator(fout, separator, cnts);
  fprintf(fout, "<p>%s</p>\n",
          _("Service that you requested is not available."));
  ns_footer(fout, footer, copyright, phr->locale_id);
  l10n_resetlocale();
}

// very basic error messaging
void
ns_html_error(
        FILE *fout,
        struct http_request_info *phr,
        int priv_mode,
        int error_code)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  const unsigned char *header = 0, *footer = 0, *separator = 0;
  const unsigned char *copyright = 0;
  time_t cur_time = time(0);
  const unsigned char *title = ns_error_title(error_code);
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  err("%d: html error: %d, %d (%s)", phr->id, priv_mode, error_code, title);

  if (phr->contest_id > 0) contests_get(phr->contest_id, &cnts);
  if (cnts) extra = ns_get_contest_extra(phr->contest_id);
  if (extra && !priv_mode) {
    watched_file_update(&extra->copyright, cnts->copyright_file, cur_time);
    copyright = extra->copyright.text;
  } else if (extra && priv_mode) {
  }
  if (!priv_mode) {
    header = ns_fancy_header;
    separator = ns_fancy_separator;
    if (copyright) footer = ns_fancy_footer_2;
    else footer = ns_fancy_footer;
  } else {
    header = ns_fancy_priv_header;
    separator = ns_fancy_priv_separator;
    footer = ns_fancy_priv_footer;
  }

  if (phr->log_f) {
    fclose(phr->log_f); phr->log_f = NULL;
  }

  l10n_setlocale(phr->locale_id);
  title = ns_error_title(error_code);
  ns_header(fout, header, 0, 0, 0, 0, phr->locale_id, cnts, NULL_CLIENT_KEY, title);
  fprintf(fout, "%s", ns_fancy_empty_status);
  ns_separator(fout, separator, cnts);
  if (phr->log_t && *phr->log_t) {
    fprintf(fout, "<p>%s</p>\n", _("Error details follow"));
    fprintf(fout, "<font color=\"red\"><pre>%s</pre></font>\n", ARMOR(phr->log_t));
  }
  xfree(phr->log_t); phr->log_t = NULL;
  phr->log_z = 0;
  ns_footer(fout, footer, copyright, phr->locale_id);
  l10n_resetlocale();
}

void
ns_html_err_status_page(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        const unsigned char *log_txt,
        int back_action,
        const char *format,
        ...)
{
  unsigned char url[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char urlextra[1024];
  va_list args;

  urlextra[0] = 0;
  if (format && *format) {
    va_start(args, format);
    vsnprintf(urlextra, sizeof(urlextra), format, args);
    va_end(args);
  }

  l10n_setlocale(phr->locale_id);
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id, NULL,
            NULL_CLIENT_KEY,
            _("Operation completed with errors"));
  if (extra->separator_txt && *extra->separator_txt) {
    fprintf(fout, "%s", ns_fancy_empty_status);
    ns_separator(fout, extra->separator_txt, cnts);
  }
  fprintf(fout, "<font color=\"red\"><pre>%s</pre></font>\n", ARMOR(log_txt));
  fprintf(fout, "<hr>%s%s</a>\n",
          ns_aref(url, sizeof(url), phr, back_action, "%s", urlextra),
          _("Back"));
  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_resetlocale();
  html_armor_free(&ab);
}
