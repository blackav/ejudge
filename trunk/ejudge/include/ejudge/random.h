/* -*- c -*- */
/* $Id$ */

#ifndef __RANDOM_H__
#define __RANDOM_H__

/* Copyright (C) 2006-2014 Alexander Chernov <cher@ejudge.ru> */

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

int random_init(void);
void random_cleanup(void);

int random_u16(void);
unsigned random_u32(void);
unsigned long long random_u64(void);
void random_bytes(unsigned char *buf, int count);

int random_range(int low, int high);

#endif /* __RANDOM_H__ */
