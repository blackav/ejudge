/* -*- c -*- */

/* Copyright (C) 2015 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_limits.h"
#include "ejudge/super_run_status.h"

#include <string.h>

void
super_run_status_init(struct super_run_status *psrs)
{
    if (psrs) return;

    memset(psrs, 0, sizeof (*psrs));
    psrs->signature[0] = 'S';
    psrs->signature[1] = '\r';
    psrs->signature[2] = 's';
    psrs->signature[3] = '\x1';
    psrs->endianness = 1;
    psrs->version = 1;
    psrs->size = sizeof(*psrs);
    psrs->strings_off = (unsigned short)(unsigned long)(&((struct super_run_status *) 0)->strings);
    psrs->str_lens = 1;
}

int
super_run_status_add_str(struct super_run_status *psrs, const unsigned char *str)
{
    if (!str) return 0;

    int len = strlen(str);
    if (psrs->str_lens + len + 1 > sizeof(*psrs)) {
        str = "?";
        len = 1;
        if (psrs->str_lens + 2 > sizeof(*psrs))
            return 0;
    }

    int dst_off = psrs->str_lens;
    unsigned char *dst = ((unsigned char *) psrs) + psrs->strings_off + dst_off;
    memcpy(dst, str, len + 1);
    psrs->str_lens += len + 1;
    return dst_off;
}

#define CHECK_FAIL() do { return -__LINE__; } while (0)

int
super_run_status_check(const void *data, size_t size)
{
    if (!data) return -1;
    if (size != sizeof(struct super_run_status)) CHECK_FAIL();
    const struct super_run_status *psrs = (const struct super_run_status *) data;

    if (psrs->signature[0] != 'S' || psrs->signature[1] != '\r'
        || psrs->signature[2] != 's' || psrs->signature[3] != '\x1')
        CHECK_FAIL();
    if (psrs->endianness != 1) CHECK_FAIL();
    if (psrs->version != 1) CHECK_FAIL();
    if (psrs->size != sizeof(*psrs)) CHECK_FAIL();
    if (psrs->strings_off != (unsigned short)(unsigned long)(&((struct super_run_status *) 0)->strings))
        CHECK_FAIL();
    if (psrs->str_lens <= 1) CHECK_FAIL();
    if (psrs->strings_off + psrs->str_lens > sizeof(*psrs)) CHECK_FAIL();

    return 0;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
