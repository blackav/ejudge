/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2014 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

const unsigned char *
session_unparse(
        unsigned char *buf,
        size_t size,
        const Session *ps)
{
    if (ps->client_key) {
        snprintf(buf, size, "%016llx-%016llx", ps->session_id, ps->client_key);
    } else {
        snprintf(buf, size, "%016llx", ps->session_id);
    }
    return buf;
}

const unsigned char *
session_unparse_2(
        unsigned char *buf,
        size_t size,
        unsigned long long session_id,
        unsigned long long client_key)
{
    if (client_key) {
        snprintf(buf, size, "%016llx-%016llx", session_id, client_key);
    } else {
        snprintf(buf, size, "%016llx", session_id);
    }
    return buf;
}

void
session_unparse_f(
        FILE *out_f,
        const Session *ps)
{
    if (ps->client_key) {
        fprintf(out_f, "%016llx-%016llx", ps->session_id, ps->client_key);
    } else {
        fprintf(out_f, "%016llx", ps->session_id);
    }
}

void
session_unparse_2_f(
        FILE *out_f,
        unsigned long long session_id,
        unsigned long long client_key)
{
    if (client_key) {
        fprintf(out_f, "%016llx-%016llx", session_id, client_key);
    } else {
        fprintf(out_f, "%016llx", session_id);
    }
}

int
session_parse(
        Session *ps,
        const unsigned char *str)
{
    char *eptr = 0;
    const unsigned char *p = str;

    ps->session_id = 0;
    ps->client_key = 0;
    errno = 0;
    ps->session_id = strtoull(p, &eptr, 16);
    if (errno) return -1;
    if (!*eptr) return 0;
    if (*eptr != '-') return -1;
    p = (const unsigned char *) eptr + 1;
    errno = 0;
    ps->client_key = strtoull(p, &eptr, 16);
    if (errno || *eptr) return -1;
    return 1;
}
