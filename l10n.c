/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "l10n.h"

#include <stdlib.h>
#include <stdio.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#include <locale.h>
#endif

#if CONF_HAS_LIBINTL - 0 == 1
static int l10n_flag = 0;
#endif /* CONF_HAS_LIBINTL */

static const unsigned char *locales[] =
{
  "English",
  "Russian",

  0
};

void
l10n_prepare(int _l10n_flag, unsigned char const *l10n_dir)
{
#if CONF_HAS_LIBINTL - 0 == 1
  if (!l10n_dir) _l10n_flag = 0;
  if (_l10n_flag != 1) return;
  l10n_flag = 1;
  bindtextdomain("ejudge", l10n_dir);
  textdomain("ejudge");
#endif /* CONF_HAS_LIBINTL */
}

void
l10n_setlocale(int locale_id)
{
#if CONF_HAS_LIBINTL - 0 == 1
  unsigned char *e = 0;
  unsigned char env_buf[512];

  if (locale_id < 0 || !l10n_flag) return;

  switch (locale_id) {
  case 1:
    e = "ru_RU.KOI8-R";
    break;
  case 0:
  default:
    locale_id = 0;
    e = "C";
    break;
  }

  snprintf(env_buf, sizeof(env_buf), "LC_ALL=%s", e);
  putenv(env_buf);
  setlocale(LC_ALL, "");
#endif /* CONF_HAS_LIBINTL */
}

void
l10n_html_locale_select(FILE *fout, int locale_id)
{
#if CONF_HAS_LIBINTL - 0 == 1
  int i;
  const unsigned char *ss;

  if (l10n_flag) {
    if (locale_id < 0 || locale_id > 1) locale_id = 0;
    fprintf(fout, "<select name=\"locale_id\">");
    for (i = 0; locales[i]; i++) {
      ss = "";
      if (i == locale_id) ss = " selected=\"1\"";
      fprintf(fout, "<option value=\"%d\"%s>%s</option>",
              i, ss, gettext(locales[i]));
    }
    fprintf(fout, "</select>\n");
  } else {
    fprintf(fout, "<input type=\"hidden\" name=\"locale_id\" value=\"0\">%s\n",
            locales[0]);
  }
#else
  fprintf(fout, "<input type=\"hidden\" name=\"locale_id\" value=\"0\">%s\n",
          locales[0]);
#endif
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
