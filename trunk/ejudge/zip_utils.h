/* -*- c -*- */
/* $Id$ */
#ifndef __ZIP_UTILS_H__
#define __ZIP_UTILS_H__

/* Copyright (C) 2010 Alexander Chernov <cher@ejudge.ru> */

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

int
gzip_uncompress_to_memory(
        unsigned char **p_out_buf,
        int *p_out_size,
        const unsigned char *in_buf,
        int in_size);

#endif /* __ZIP_UTILS_H__ */
