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

#endif /* __IMAGEMAGICK_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
