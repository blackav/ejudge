/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003 Alexander Chernov <cher@ispras.ru> */

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
           _("<p>This is <b>ejudge</b> contest administration system, version %s, compiled %s.\n"
           "<p>This program is copyright (C) 2000-2003 Alexander Chernov.\n"
           "<p>"
           "This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.\n"
           "<p>You can download the latest version from <a href=\"%s\">this site</a>.\n"), 
         compile_version, compile_date,
         "http://contest.cmc.msu.ru/download");
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
