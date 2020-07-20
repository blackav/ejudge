/* -*- c -*- */

#ifndef __IMAGEMAGICK_H__
#define __IMAGEMAGICK_H__

/* Copyright (C) 2017 Alexander Chernov <cher@ejudge.ru> */

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

int
image_identify(
        FILE *log_f,
        const unsigned char *tmp_dir,
        const unsigned char *data,
        size_t size,
        int *p_width,
        int *p_height);

int
image_convert(
        FILE *log_f,
        const unsigned char *tmp_dir,
        int in_mime_type,
        int in_left,
        int in_top,
        int in_width,
        int in_height,
        const unsigned char *in_data,
        size_t in_size,
        int out_mime_type,
        int out_width,
        int out_height,
        unsigned char **p_out_data,
        size_t *p_out_size);

#endif /* __IMAGEMAGICK_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
