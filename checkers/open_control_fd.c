/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2022 Alexander Chernov <cher@ejudge.ru> */

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

#include "checker_internal.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

int
checker_open_control_fd(void)
{
    char *s = getenv("EJUDGE_CONTROL_FD");
    if (!s) {
        checker_drain();
        fatal_CF("EJUDGE_CONTROL_FD environment not set");
    }
    char *eptr = NULL;
    errno = 0;
    long v = strtol(s, &eptr, 10);
    if (errno || *eptr || eptr == s || (int) v != v || v < 0) {
        checker_drain();
        fatal_CF("EJUDGE_CONTROL_FD value '%s' is invalid", s);
    }
    struct stat stb;
    if (fstat(v, &stb) < 0) {
        checker_drain();
        fatal_CF("EJUDGE_CONTROL_FD %ld nonexistant", v);
    }
    if (!S_ISSOCK(stb.st_mode)) {
        checker_drain();
        fatal_CF("EJUDGE_CONTROL_FD %ld is not socket", v);
    }

    return v;
}
