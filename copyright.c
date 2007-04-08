/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "copyright.h"
#include "version.h"

#include <reuse/xalloc.h>

#include <stdio.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

static void
make_copyright(unsigned char *buf, size_t size)
{
  snprintf(buf, size,
           _("<p class=\"ejudge_copyright\">This is <a href=\"%s\"><b>ejudge</b></a> contest administration system, version %s, compiled %s.</p>\n"
             "<p class=\"ejudge_copyright\">This program is copyright &copy; %s Alexander Chernov.</p>\n"
             "<p class=\"ejudge_copyright\">"
             "This program is free software; you can redistribute it and/or modify it under the terms of the <a href=\"http://www.gnu.org/licenses/gpl.html\">GNU General Public License</a> as published by the <a href=\"http://www.fsf.org\">Free Software Foundation</a>; either version 2 of the License, or (at your option) any later version.</p>\n"
             "<p class=\"ejudge_copyright\">Visual design and web-interface &copy; %s <a href=\"%s\">Toto Lasvik</a>.</p>"),
           "http://www.ejudge.ru",
           compile_version, compile_date, "2000-2007",
           "2006-2007", "http://www.lasvik.ru");
}

static unsigned char *copyright_str = 0;
static int copyright_locale = 0;
unsigned char *
get_copyright(int locale_id)
{
  //fprintf(stderr, "get_copyright: %d, %s, %s\n", locale_id, getenv("LANG"), getenv("LC_ALL"));
  if (!copyright_str || locale_id != copyright_locale) {
    unsigned char buf[8192];

    buf[0] = 0;
    make_copyright(buf, sizeof(buf));
    xfree(copyright_str);
    copyright_str = xstrdup(buf);
    copyright_locale = locale_id;
  }
  return copyright_str;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
