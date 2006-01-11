/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2006 Alexander Chernov <cher@ispras.ru> */

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
           "<p class=\"ejudge_copyright\">This program is copyright (C) 2000-2006 Alexander Chernov.</p>\n"
           "<p class=\"ejudge_copyright\">"
           "This program is free software; you can redistribute it and/or modify it under the terms of the <a href=\"http://www.fsf.org/licenses/licenses.html#GPL\">GNU General Public License</a> as published by the <a href=\"http://www.fsf.org\">Free Software Foundation</a>; either version 2 of the License, or (at your option) any later version.</p>\n"),
           "http://www.ejudge.ru",
           compile_version, compile_date);
}

static unsigned char *copyright_str = 0;
unsigned char *
get_copyright(void)
{
  if (!copyright_str) {
    unsigned char buf[1024];

    buf[0] = 0;
    make_copyright(buf, sizeof(buf));
    copyright_str = xstrdup(buf);
  }
  return copyright_str;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
