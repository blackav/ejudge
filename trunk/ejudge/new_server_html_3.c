/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2007 Alexander Chernov <cher@ejudge.ru> */

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
#include "settings.h"
#include "ej_types.h"
#include "ej_limits.h"

#include "new-server.h"
#include "new_server_proto.h"
#include "prepare.h"
#include "misctext.h"
#include "errlog.h"
#include "contests.h"
#include "l10n.h"
#include "xml_utils.h"
#include "copyright.h"

#include <stdarg.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif
#define __(x) x

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
"<link rel=\"stylesheet\" href=\"/ejudge/priv.css\" type=\"text/css\">\n"
"<link rel=\"shortcut icon\" type=image/x-icon href=\"/favicon.ico\">\n"
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
"<link rel=\"stylesheet\" href=\"/ejudge/unpriv.css\" type=\"text/css\"/>\n"
"<link rel=\"shortcut icon\" type=image/x-icon href=\"/favicon.ico\"/>\n"
"<title>%H</title></head>\n"
"<body onLoad=\"startClock()\">"
  //"<body>"
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
"<div id=\"l11\"><img src=\"/ejudge/logo.gif\"></div>\n"
"<div id=\"l13\">\n";
const unsigned char ns_fancy_footer[] =
"<div id=\"footer\">%R</div>\n"
"</div>"
"</BODY>"
"</HTML>";

const unsigned char * const ns_ssl_flag_str[] =
{
  "http", "https",
};

static void
process_template(FILE *out,
                 unsigned char const *templ,
                 unsigned char const *content_type,
                 unsigned char const *charset,
                 unsigned char const *title,
                 unsigned char const *copyright,
                 const unsigned char *script_part,
                 int locale_id)
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
    default:
      putc('%', out);
      continue;
    }
    s++;
  }
}

void
ns_header(FILE *out, unsigned char const *templ,
          unsigned char const *content_type,
          unsigned char const *charset,
          const unsigned char *script_part,
          int locale_id,
          char const *format, ...)
{
  va_list args;
  unsigned char title[1024];

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

  fprintf(out, "Content-Type: %s; charset=%s\n"
          "Cache-Control: no-cache\n"
          "Pragma: no-cache\n\n", content_type, charset);

  process_template(out, templ, content_type, charset, title, 0,
                   script_part, locale_id);
}

void
ns_footer(FILE *out, unsigned char const *templ, int locale_id)
{
  if (!templ) templ = ns_default_footer;
  process_template(out, templ, 0, 0, 0, get_copyright(locale_id), 0, 0);
}

void
ns_html_err_no_perm(FILE *fout,
                    struct http_request_info *phr,
                    int priv_mode,
                    const char *format, ...)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  const unsigned char *header = 0, *footer = 0, *separator = 0;
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
    watched_file_update(&extra->header, cnts->team_header_file, cur_time);
    watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  } else if (extra && priv_mode) {
    watched_file_update(&extra->priv_header, cnts->priv_header_file, cur_time);
    watched_file_update(&extra->priv_footer, cnts->priv_footer_file, cur_time);
    header = extra->priv_header.text;
    footer = extra->priv_footer.text;
  }
  if (!priv_mode) {
    if (!header || !footer) {
      header = ns_fancy_header;
      separator = ns_fancy_separator;
      footer = ns_fancy_footer;
    }
  } else {
    if (!header || !footer) {
      header = ns_fancy_priv_header;
      separator = ns_fancy_priv_separator;
      footer = ns_fancy_priv_footer;
    }    
  }
  l10n_setlocale(phr->locale_id);
  ns_header(fout, header, 0, 0, 0, phr->locale_id, _("Permission denied"));
  if (separator && *separator) {
    fprintf(fout, "%s", ns_fancy_empty_status);
    fprintf(fout, "%s", separator);
  }
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
    fprintf(fout, _("<li>Your IP-address (<tt>%s</tt>) or protocol (<tt>%s</tt>) is banned for participation.</li>"), xml_unparse_ip(phr->ip),
            ns_ssl_flag_str[phr->ssl_flag]);
    fprintf(fout, _("<li>The contest is closed for participation.</li>\n"));
  } else {
    fprintf(fout, _("<li>Your IP-address (<tt>%s</tt>) or protocol (<tt>%s</tt>) is banned for participation.</li>"), xml_unparse_ip(phr->ip), ns_ssl_flag_str[phr->ssl_flag]);
    fprintf(fout, _("<li>You do not have permissions to login using the specified role.</li>"));
  }
  fprintf(fout, "</ul>\n");
  fprintf(fout, _("<p>Note, that the exact reason is not reported due to security reasons.</p>"));
  ns_footer(fout, footer, phr->locale_id);
  l10n_setlocale(0);
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
    watched_file_update(&extra->header, cnts->team_header_file, cur_time);
    watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  } else if (extra && priv_mode) {
    watched_file_update(&extra->priv_header, cnts->priv_header_file, cur_time);
    watched_file_update(&extra->priv_footer, cnts->priv_footer_file, cur_time);
    header = extra->priv_header.text;
    footer = extra->priv_footer.text;
  }
  if (!priv_mode) {
    if (!header || !footer) {
      header = ns_fancy_header;
      separator = ns_fancy_separator;
      footer = ns_fancy_footer;
    }
  } else {
    if (!header || !footer) {
      header = ns_fancy_priv_header;
      separator = ns_fancy_priv_separator;
      footer = ns_fancy_priv_footer;
    }    
  }
  l10n_setlocale(phr->locale_id);
  ns_header(fout, header, 0, 0, 0, phr->locale_id, _("Invalid parameter"));
  if (separator && *separator) {
    fprintf(fout, "%s", ns_fancy_empty_status);
    fprintf(fout, "%s", separator);
  }
  fprintf(fout, "<p>%s</p>\n",
          _("A request parameter is invalid. Please, contact the site administrator."));
  ns_footer(fout, footer, phr->locale_id);
  l10n_setlocale(0);
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
    watched_file_update(&extra->header, cnts->team_header_file, cur_time);
    watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  }

  // try fancy headers
  if (!header || !footer) {
    header = ns_fancy_header;
    separator = ns_fancy_separator;
    footer = ns_fancy_footer;
  } else {
    if (!header || !footer) {
      header = ns_fancy_priv_header;
      separator = ns_fancy_priv_separator;
      footer = ns_fancy_priv_footer;
    }    
  }
  l10n_setlocale(phr->locale_id);
  ns_header(fout, header, 0, 0, 0, phr->locale_id, _("Service not available"));
  if (separator && *separator) {
    fprintf(fout, "%s", ns_fancy_empty_status);
    fprintf(fout, "%s", separator);
  }
  fprintf(fout, "<p>%s</p>\n",
          _("Service that you requested is not available."));
  ns_footer(fout, footer, phr->locale_id);
  l10n_setlocale(0);
}

void
ns_html_err_cnts_unavailable(FILE *fout,
                             struct http_request_info *phr,
                             int priv_mode,
                             const char *format, ...)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  const unsigned char *header = 0, *footer = 0, *separator = 0;
  time_t cur_time = time(0);
  unsigned char buf[1024];
  va_list args;

  if (format && *format) {
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    err("%d: contest not available: %s", phr->id, buf);
  } else {
    err("%d: contest not available", phr->id);
  }

  if (phr->contest_id > 0) contests_get(phr->contest_id, &cnts);
  if (cnts) extra = ns_get_contest_extra(phr->contest_id);
  if (extra) {
    watched_file_update(&extra->header, cnts->team_header_file, cur_time);
    watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  }

  // try fancy headers
  if (!header || !footer) {
    header = ns_fancy_header;
    separator = ns_fancy_separator;
    footer = ns_fancy_footer;
  } else {
    if (!header || !footer) {
      header = ns_fancy_priv_header;
      separator = ns_fancy_priv_separator;
      footer = ns_fancy_priv_footer;
    }    
  }
  l10n_setlocale(phr->locale_id);
  ns_header(fout, header, 0, 0, 0, phr->locale_id, _("Contest not available"));
  if (separator && *separator) {
    fprintf(fout, "%s", ns_fancy_empty_status);
    fprintf(fout, "%s", separator);
  }
  fprintf(fout, "<p>%s</p>\n",
          _("The contest is temporarily not available. Please, retry the request a bit later."));
  ns_footer(fout, footer, phr->locale_id);
  l10n_setlocale(0);
}

void
ns_html_err_ul_server_down(FILE *fout,
                           struct http_request_info *phr,
                           int priv_mode,
                           const char *format, ...)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  const unsigned char *header = 0, *footer = 0, *separator = 0;
  time_t cur_time = time(0);
  unsigned char buf[1024];
  va_list args;

  if (format && *format) {
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    err("%d: userlist server is down: %s", phr->id, buf);
  } else {
    err("%d: userlist server is down", phr->id);
  }

  if (phr->contest_id > 0) contests_get(phr->contest_id, &cnts);
  if (cnts) extra = ns_get_contest_extra(phr->contest_id);
  if (extra && !priv_mode) {
    watched_file_update(&extra->header, cnts->team_header_file, cur_time);
    watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  } else if (extra && priv_mode) {
    watched_file_update(&extra->priv_header, cnts->priv_header_file, cur_time);
    watched_file_update(&extra->priv_footer, cnts->priv_footer_file, cur_time);
    header = extra->priv_header.text;
    footer = extra->priv_footer.text;
  }
  if (!priv_mode) {
    if (!header || !footer) {
      header = ns_fancy_header;
      separator = ns_fancy_separator;
      footer = ns_fancy_footer;
    }
  } else {
    if (!header || !footer) {
      header = ns_fancy_priv_header;
      separator = ns_fancy_priv_separator;
      footer = ns_fancy_priv_footer;
    }    
  }
  l10n_setlocale(phr->locale_id);
  ns_header(fout, header, 0, 0, 0, phr->locale_id,
            _("User database server is down"));
  if (separator && *separator) {
    fprintf(fout, "%s", ns_fancy_empty_status);
    fprintf(fout, "%s", separator);
  }
  fprintf(fout, "<p>%s</p>\n",
          _("The user database server is currently not available. Please, retry the request later."));
  ns_footer(fout, footer, phr->locale_id);
  l10n_setlocale(0);
}

void
ns_html_err_internal_error(FILE *fout,
                           struct http_request_info *phr,
                           int priv_mode,
                           const char *format, ...)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  const unsigned char *header = 0, *footer = 0, *separator = 0;
  time_t cur_time = time(0);
  unsigned char buf[1024];
  va_list args;

  if (format && *format) {
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    err("%d: internal error: %s", phr->id, buf);
  } else {
    err("%d: internal error", phr->id);
  }

  if (phr->contest_id > 0) contests_get(phr->contest_id, &cnts);
  if (cnts) extra = ns_get_contest_extra(phr->contest_id);
  if (extra && !priv_mode) {
    watched_file_update(&extra->header, cnts->team_header_file, cur_time);
    watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  } else if (extra && priv_mode) {
    watched_file_update(&extra->priv_header, cnts->priv_header_file, cur_time);
    watched_file_update(&extra->priv_footer, cnts->priv_footer_file, cur_time);
    header = extra->priv_header.text;
    footer = extra->priv_footer.text;
  }
  if (!priv_mode) {
    if (!header || !footer) {
      header = ns_fancy_header;
      separator = ns_fancy_separator;
      footer = ns_fancy_footer;
    }
  } else {
    if (!header || !footer) {
      header = ns_fancy_priv_header;
      separator = ns_fancy_priv_separator;
      footer = ns_fancy_priv_footer;
    }    
  }
  l10n_setlocale(phr->locale_id);
  ns_header(fout, header, 0, 0, 0, phr->locale_id, _("Internal error"));
  if (separator && *separator) {
    fprintf(fout, "%s", ns_fancy_empty_status);
    fprintf(fout, "%s", separator);
  }
  fprintf(fout, "<p>%s</p>\n",
          _("Your request has caused an internal server error. Please, report it as a bug."));
  ns_footer(fout, footer, phr->locale_id);
  l10n_setlocale(0);
}

void
ns_html_err_inv_session(FILE *fout,
                        struct http_request_info *phr,
                        int priv_mode,
                        const char *format, ...)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  const unsigned char *header = 0, *footer = 0, *separator = 0;
  time_t cur_time = time(0);
  unsigned char buf[1024];
  va_list args;

  if (format && *format) {
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    err("%d: invalid session: %s", phr->id, buf);
  } else {
    err("%d: invalid session", phr->id);
  }

  if (phr->contest_id > 0) contests_get(phr->contest_id, &cnts);
  if (cnts) extra = ns_get_contest_extra(phr->contest_id);
  if (extra && !priv_mode) {
    watched_file_update(&extra->header, cnts->team_header_file, cur_time);
    watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  } else if (extra && priv_mode) {
    watched_file_update(&extra->priv_header, cnts->priv_header_file, cur_time);
    watched_file_update(&extra->priv_footer, cnts->priv_footer_file, cur_time);
    header = extra->priv_header.text;
    footer = extra->priv_footer.text;
  }
  if (!priv_mode) {
    if (!header || !footer) {
      header = ns_fancy_header;
      separator = ns_fancy_separator;
      footer = ns_fancy_footer;
    }
  } else {
    if (!header || !footer) {
      header = ns_fancy_priv_header;
      separator = ns_fancy_priv_separator;
      footer = ns_fancy_priv_footer;
    }    
  }
  l10n_setlocale(phr->locale_id);
  ns_header(fout, header, 0, 0, 0, phr->locale_id, _("Invalid session"));
  if (separator && *separator) {
    fprintf(fout, "%s", ns_fancy_empty_status);
    fprintf(fout, "%s", separator);
  }
  fprintf(fout, "<p>%s</p>\n",
          _("Invalid session identifier. The possible reasons are as follows."));
  fprintf(fout, "<ul>\n");
  fprintf(fout, _("<li>The specified session does not exist.</li>"));
  fprintf(fout, _("<li>The specified has expired.</li>\n"));
  fprintf(fout, _("<li>The session was created from a different IP-address or protocol, that yours (%s,%s).</li>\n"), xml_unparse_ip(phr->ip), ns_ssl_flag_str[phr->ssl_flag]);
  fprintf(fout, _("<li>The session was removed by an administrator.</li>"));
  fprintf(fout, "</ul>\n");
  fprintf(fout, _("<p>Note, that the exact reason is not reported due to security reasons.</p>"));
  ns_footer(fout, footer, phr->locale_id);
  l10n_setlocale(0);
}

#define SET_FANCY_DECOR(f,s) do { if (!global->f[0]) snprintf(global->f, sizeof(global->f), "%s", s); } while (0)
void
ns_set_fancy_standings_style(struct section_global_data *global)
{
  /*
  GLOBAL_PARAM(stand_success_attr, "s"),
  GLOBAL_PARAM(stand_fail_attr, "s"),
  GLOBAL_PARAM(stand_trans_attr, "s"),
*/

  SET_FANCY_DECOR(stand_table_attr, " width=\"100%\" class=\"standings\"");
  SET_FANCY_DECOR(stand_extra_attr, " class=\"st_extra\"");
  SET_FANCY_DECOR(stand_place_attr, " class=\"st_place\"");
  SET_FANCY_DECOR(stand_team_attr, " class=\"st_team\"");
  SET_FANCY_DECOR(stand_prob_attr, " class=\"st_prob\"");
  SET_FANCY_DECOR(stand_solved_attr, " class=\"st_total\"");
  SET_FANCY_DECOR(stand_time_attr, " class=\"st_time\"");
  SET_FANCY_DECOR(stand_score_attr, " class=\"st_score\"");
  SET_FANCY_DECOR(stand_penalty_attr, " class=\"st_pen\"");
  SET_FANCY_DECOR(stand_warn_number_attr, " class=\"st_warns\"");
  SET_FANCY_DECOR(stand_contestant_status_attr, " class=\"st_status\"");
  SET_FANCY_DECOR(stand_fail_attr, " class=\"st_prob\" bgcolor=\"#ff8888\"");
  SET_FANCY_DECOR(stand_trans_attr, " class=\"st_prob\" bgcolor=\"#ffff88\"");
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
