/* -*- c -*- */
/* $Id$ */
#ifndef __ARCHIVE_PATHS_H__
#define __ARCHIVE_PATHS_H__

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

#include <stdio.h>
#include <stdlib.h>

int archive_dir_prepare(const unsigned char *, int);
int archive_make_read_path(unsigned char *, size_t,
                           const unsigned char *, int,
                           const unsigned char *, int);
int archive_make_write_path(unsigned char *, size_t,
                            const unsigned char *, int,
                            size_t, const unsigned char *);
int archive_make_move_path(unsigned char *, size_t,
                           const unsigned char *, int,
                           int, const unsigned char *);

int archive_rename(const unsigned char *, FILE *,
                   int, const unsigned char *,
                   int, const unsigned char *, int);
int archive_remove(const unsigned char *, int, const unsigned char *, int);


#endif /* __ARCHIVE_PATHS_H__ */
