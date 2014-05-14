/* -*- c -*- */
/* $Id$ */

#ifndef __TIMESTAMP_H__
#define __TIMESTAMP_H__

/* Copyright (C) 2005 Alexander Chernov <cher@ispras.ru> */

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

struct file_stamp;
typedef struct file_stamp *file_stamp_t;

file_stamp_t file_stamp_get(const unsigned char *path);
int file_stamp_is_updated(const unsigned char *path, const file_stamp_t ts);
file_stamp_t file_stamp_update(const unsigned char *path, file_stamp_t ts);
file_stamp_t file_stamp_free(file_stamp_t ts);

#endif /* __TIMESTAMP_H__ */
