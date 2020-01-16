/* -*- mode: c -*- */

/* Copyright (C) 2003-2016 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/l10n.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#include <locale.h>
#endif

#if CONF_HAS_LIBINTL - 0 == 1
static int l10n_flag = 0;
#endif /* CONF_HAS_LIBINTL */

static const unsigned char * const locales[] =
{
  "English",
  "Russian",
  "Ukrainian",
  "Kazakh",

  0
};

#if CONF_HAS_LIBINTL - 0 == 1
static unsigned char lc_all_env_buf[1024] = "LC_ALL=C";
static unsigned char *lc_all_env_ptr = &lc_all_env_buf[7];
static int current_locale_id = -1;
#endif

void
l10n_prepare(int l10n_flag_, unsigned char const *l10n_dir)
{
#if CONF_HAS_LIBINTL - 0 == 1
  static unsigned char env_buf[64] = "LANG";
  static unsigned char env_buf2[64] = "LANGUAGE";
  static unsigned char env_buf3[64] = "LC_MESSAGES";

  if (!l10n_dir) l10n_flag_ = 0;
  if (l10n_flag_ != 1) return;
  l10n_flag = 1;
  bindtextdomain("ejudge", l10n_dir);
  textdomain("ejudge");
  putenv(env_buf); // remove LANG env var
  putenv(env_buf2); // remove LANGUAGE env var
  putenv(env_buf3); // remove LC_MESSAGES env var
  putenv(lc_all_env_buf); // set LC_ALL=C
  current_locale_id = 0;
#endif /* CONF_HAS_LIBINTL */
}

void
l10n_resetlocale(void)
{
#if CONF_HAS_LIBINTL - 0 == 1
  if (current_locale_id == 0) return;
  strcpy(lc_all_env_ptr, "C");
  setlocale(LC_ALL, "");
  current_locale_id = 0;
#endif /* CONF_HAS_LIBINTL */
}

void
l10n_setlocale(int locale_id)
{
#if CONF_HAS_LIBINTL - 0 == 1
  unsigned char *e = 0;
  static unsigned char russian_locale_name[512];
  static unsigned char ukrainian_locale_name[512];
  static unsigned char kazakh_locale_name[512];

  if (locale_id < 0 || !l10n_flag) return;
  if (locale_id == current_locale_id) return;

  switch (locale_id) {
  case 3:
    if (!kazakh_locale_name[0]) {
      unsigned char cbuf[512];
      int i;
#if !defined EJUDGE_CHARSET
      snprintf(cbuf, sizeof(cbuf), "%s", "UTF-8");
#else
      snprintf(cbuf, sizeof(cbuf), "%s", EJUDGE_CHARSET);
#endif
      for (i = 0; cbuf[i]; i++)
        cbuf[i] = toupper(cbuf[i]);
      snprintf(kazakh_locale_name, sizeof(kazakh_locale_name),
               "kk_KZ.%s", cbuf);
    }
    e = kazakh_locale_name;
    break;
  case 2:
    if (!ukrainian_locale_name[0]) {
      unsigned char cbuf[512];
      int i;
#if !defined EJUDGE_CHARSET
      snprintf(cbuf, sizeof(cbuf), "%s", "UTF-8");
#else
      snprintf(cbuf, sizeof(cbuf), "%s", EJUDGE_CHARSET);
#endif
      for (i = 0; cbuf[i]; i++)
        cbuf[i] = toupper(cbuf[i]);
      snprintf(ukrainian_locale_name, sizeof(ukrainian_locale_name),
               "uk_UA.%s", cbuf);
    }
    e = ukrainian_locale_name;
    break;
  case 1:
    if (!russian_locale_name[0]) {
      unsigned char cbuf[512];
      int i;
#if !defined EJUDGE_CHARSET
      snprintf(cbuf, sizeof(cbuf), "%s", "UTF-8");
#else
      snprintf(cbuf, sizeof(cbuf), "%s", EJUDGE_CHARSET);
#endif
      for (i = 0; cbuf[i]; i++)
        cbuf[i] = toupper(cbuf[i]);
      snprintf(russian_locale_name, sizeof(russian_locale_name),
               "ru_RU.%s", cbuf);
    }
    e = russian_locale_name;
    break;
  case 0:
  default:
    locale_id = 0;
    e = "C";
    break;
  }

  strcpy(lc_all_env_ptr, e);
  setlocale(LC_ALL, "");
  current_locale_id = locale_id;
#endif /* CONF_HAS_LIBINTL */
}

void
l10n_html_locale_select(FILE *fout, int locale_id)
{
#if CONF_HAS_LIBINTL - 0 == 1
  int i;
  const unsigned char *ss;

  if (l10n_flag) {
    if (locale_id < 0 || locale_id >= sizeof(locales)/sizeof(locales[0]) ) locale_id = 0;
    fprintf(fout, "<select name=\"locale_id\">");
    for (i = 0; locales[i]; i++) {
      ss = "";
      if (i == locale_id) ss = " selected=\"selected\"";
      fprintf(fout, "<option value=\"%d\"%s>%s</option>",
              i, ss, gettext(locales[i]));
    }
    fprintf(fout, "</select>\n");
  } else {
    fprintf(fout, "<input type=\"hidden\" name=\"locale_id\" value=\"0\"/>%s\n",
            locales[0]);
  }
#else
  fprintf(fout, "<input type=\"hidden\" name=\"locale_id\" value=\"0\"/>%s\n",
          locales[0]);
#endif
}

void
l10n_html_locale_select_2(
        FILE *out_f,
        const unsigned char *id,
        const unsigned char *cl,
        const unsigned char *name,
        const unsigned char *onchange,
        int locale_id)
{
#if CONF_HAS_LIBINTL - 0 == 1
  const unsigned char *ss = 0;
  int i;

  if (locale_id < 0 || locale_id >= sizeof(locales)/sizeof(locales[0])) locale_id = 0;
  fprintf(out_f, "<select");
  if (id) fprintf(out_f, " id=\"%s\"", id);
  if (cl) fprintf(out_f, " class=\"%s\"", cl);
  if (name) fprintf(out_f, " name=\"%s\"", name);
  if (onchange) fprintf(out_f, " onChange='%s'", onchange);
  fprintf(out_f, ">");
  for (i = 0; locales[i]; i++) {
    ss = "";
    if (i == locale_id) ss = " selected=\"selected\"";
    fprintf(out_f, "<option value=\"%d\"%s>%s</option>",
            i, ss, gettext(locales[i]));
  }
  fprintf(out_f, "</select>\n");
#endif
}

void
l10n_html_locale_select_3(
        FILE *out_f,
        const unsigned char *id,
        const unsigned char *cl,
        const unsigned char *name,
        const unsigned char *onchange,
        int locale_id)
{
#if CONF_HAS_LIBINTL - 0 == 1
  const unsigned char *ss = 0;
  int i;

  if (locale_id < -1 || locale_id >= (int)(sizeof(locales)/sizeof(locales[0]))) locale_id = 0;
  fprintf(out_f, "<select");
  if (id) fprintf(out_f, " id=\"%s\"", id);
  if (cl) fprintf(out_f, " class=\"%s\"", cl);
  if (name) fprintf(out_f, " name=\"%s\"", name);
  if (onchange) fprintf(out_f, " onChange='%s'", onchange);
  fprintf(out_f, ">");
  fprintf(out_f, "<option></option>");
  for (i = 0; locales[i]; i++) {
    ss = "";
    if (i == locale_id) ss = " selected=\"selected\"";
    fprintf(out_f, "<option value=\"%s\"%s>%s</option>",
            locales[i], ss, gettext(locales[i]));
  }
  fprintf(out_f, "</select>\n");
#endif
}

static struct locale_names
{
  const char * const name;
  int value;
} locale_names[] =
{
  { "0", 0 },
  { "en", 0 },
  { "en_US", 0 },
  { "English", 0 },

  { "1", 1 },
  { "ru", 1 },
  { "ru_RU", 1 },
  { "Russian", 1 },

  { "2", 2 },
  { "uk", 2 },
  { "uk_UA", 2 },
  { "Ukrainian", 2 },

  { "3", 3 },
  { "kk", 3 },
  { "kk_KZ", 3 },
  { "Kazakh", 3 },

  { 0, 0 }
};

int
l10n_parse_locale(const unsigned char *locale_str)
{
  int i;

  if (!locale_str || !*locale_str) return -1;
  for (i = 0; locale_names[i].name; i++)
    if (!strcasecmp(locale_str, locale_names[i].name))
      return locale_names[i].value;
  return -1;
}

const unsigned char * const locale_name_strs[] =
{
  "English", "Russian", "Ukrainian", "Kazakh",
};
const unsigned char *
l10n_unparse_locale(int n)
{
  if (n < 0 || n >= sizeof(locale_name_strs) / sizeof(locale_name_strs[0]))
    return 0;
  return locale_name_strs[n];
}

const unsigned char *
l10n_normalize(const unsigned char *str)
{
  if (!str || !*str) return NULL;
  int id = l10n_parse_locale(str);
  if (id < 0) return NULL;
  return l10n_unparse_locale(id);
}
