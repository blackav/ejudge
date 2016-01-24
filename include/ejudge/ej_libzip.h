/* -*- c -*- */
#ifndef __EJ_LIBZIP_H__
#define __EJ_LIBZIP_H__

/* Copyright (C) 2016 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <stdio.h>

struct ZipData;
struct ZipInterface
{
    struct ZipData *(*close)(struct ZipData *zdata);
    int (*read_file)(
        struct ZipData *zdata,
        const unsigned char *name,
        unsigned char **p_data,
        ssize_t *p_size);
    int (*add_file)(
        struct ZipData *zdata,
        const unsigned char *name,
        const unsigned char *path);
};

struct ZipData
{
    const struct ZipInterface *ops;
};

struct ZipData *ej_libzip_open(FILE *log_f, const unsigned char *path, int flags);

#endif /* __EJ_LIBZIP_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
