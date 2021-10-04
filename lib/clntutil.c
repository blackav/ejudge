/* -*- mode: c -*- */

/* Copyright (C) 2000-2021 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/clntutil.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/fileutl.h"
#include "unix/unix_fileutl.h"
#include "ejudge/misctext.h"
#include "ejudge/protocol.h"
#include "ejudge/copyright.h"
#include "ejudge/xml_utils.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

#if defined EJUDGE_CHARSET
#define DEFAULT_CHARSET              EJUDGE_CHARSET
#else
#define DEFAULT_CHARSET              "utf-8"
#endif /* EJUDGE_CHARSET */

path_t  program_name;
char    form_header_simple[1024];
char    form_header_multipart[1024];

static unsigned char default_header_template[] =
"<html><head>"
"<meta http-equiv=\"Content-Type\" content=\"%T; charset=%C\">\n"
"<title>%H</title>\n"
"</head>\n"
"<body><h1>%H</h1>\n";
static unsigned char default_footer_template[] =
"<hr>%R</body></html>\n";

static void
process_template(FILE *out,
                 unsigned char const *template,
                 unsigned char const *content_type,
                 unsigned char const *charset,
                 unsigned char const *title,
                 unsigned char const *copyright,
                 int locale_id)
{
  unsigned char const *s = template;

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
    default:
      putc('%', out);
      continue;
    }
    s++;
  }
}

void
client_put_header(
        FILE *out,
        unsigned char const *template,
        unsigned char const *content_type,
        unsigned char const *charset,
        int http_flag,
        int locale_id,
        ej_cookie_t client_key,
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

  if (!charset) charset = DEFAULT_CHARSET;
  if (!content_type) content_type = "text/html";
  if (!template) template = default_header_template;

  if (http_flag) {
    fprintf(out, "Content-Type: %s; charset=%s\n"
            "Cache-Control: no-cache\n"
            "Pragma: no-cache\n", content_type, charset);
    if (client_key) {
      fprintf(out, "Set-Cookie: EJSID=%016llx; Path=/; SameSite=Lax\n", client_key);
    }
    putc('\n', out);
  }

  process_template(out, template, content_type, charset, title, 0, locale_id);
}

void
client_put_footer(FILE *out, unsigned char const *template)
{
  if (!template) template = default_footer_template;
  process_template(out, template, 0, 0, 0, get_copyright(0), 0);
}

void
client_access_denied(char const *charset, int locale_id)
{
  client_put_header(stdout, 0, 0, charset, 1, locale_id, NULL_CLIENT_KEY, _("Access denied"));
  printf("<p>%s</p>", _("You do not have permissions to use this service."));
  client_put_footer(stdout, 0);
  exit(0);
}

void
client_not_configured(
        char const *charset,
        char const *str,
        int locale_id,
        const char *messages)
{
  write_log(0, LOG_ERR, (char*) str);
  client_put_header(stdout, 0, 0, charset, 1, locale_id, NULL_CLIENT_KEY, _("Service is not available"));
  printf("<p>%s</p>", _("Service is not available. Please, come later."));
  if (messages) {
    printf("<pre>%s</pre>\n", messages);
  }
  client_put_footer(stdout, 0);
  exit(0);
}

void
client_make_form_headers(unsigned char const *self_url)
{

  sprintf(form_header_simple,
          "<form method=\"post\" action=\"%s\" "
          "enctype=\"application/x-www-form-urlencoded\">",
          self_url);
  sprintf(form_header_multipart,
          "<form method=\"post\" action=\"%s\" "
          "enctype=\"multipart/form-data\">",
          self_url);
}

void
parse_client_ip(ej_ip_t *p_ip)
{
  memset(p_ip, 0, sizeof(*p_ip));
  unsigned char *s = getenv("REMOTE_ADDR");
  if (!s) {
    return;
  }

  xml_parse_ipv6_2(s, p_ip);
}
