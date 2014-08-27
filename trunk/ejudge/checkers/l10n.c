/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2013-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "../include/ejudge/config.h"

#include "checker_internal.h"

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#include <locale.h>
#endif

void
checker_l10n_prepare(void)
{
#if CONF_HAS_LIBINTL - 0 == 1
    const char *ej_locale = getenv("EJUDGE_LOCALE");
    if (!ej_locale || !*ej_locale) return;

    // shortcuts
    if (!strcasecmp(ej_locale, "russian") || !strcasecmp(ej_locale, "ru") || !strcasecmp(ej_locale, "1")) {
        ej_locale = "ru_RU.UTF-8";
    } else if (!strcasecmp(ej_locale, "ukrainian") || !strcasecmp(ej_locale, "uk") || !strcasecmp(ej_locale, "2")) {
        ej_locale = "uk_UA.UTF-8";
    } else if (!strcasecmp(ej_locale, "kazakh") || !strcasecmp(ej_locale, "kk") || !strcasecmp(ej_locale, "3")) {
        ej_locale = "kk_KZ.UTF-8";
    }

    // some memory is definitely leaked here
    char envbuf[1024];
    snprintf(envbuf, sizeof(envbuf), "LANG");
    putenv(xstrdup(envbuf));
    snprintf(envbuf, sizeof(envbuf), "LANGUAGE");
    putenv(xstrdup(envbuf));
    snprintf(envbuf, sizeof(envbuf), "LC_ALL");
    putenv(xstrdup(envbuf));
    snprintf(envbuf, sizeof(envbuf), "LC_MESSAGES=%s", ej_locale);
    putenv(xstrdup(envbuf));
    snprintf(envbuf, sizeof(envbuf), "LC_CTYPE=%s", ej_locale);
    putenv(xstrdup(envbuf));

    bindtextdomain("ejudgecheckers", EJUDGE_LOCALE_DIR);
    textdomain("ejudgecheckers");
    setlocale(LC_MESSAGES, "");
    setlocale(LC_CTYPE, "");
#endif
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
