/* -*- c -*- */
/* $Id$ */
#ifndef __PACKET_NAME_H__
#define __PACKET_NAME_H__

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

unsigned char *b32_number_2(unsigned char *dst, unsigned int num, int digits);
unsigned char *b32_number_3(unsigned char *dst, unsigned int num);

void
serve_packet_name(
        int contest_id,
        int run_id,
        int prio,
        unsigned char buf[],
        int size);


#endif /* __PACKET_NAME_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
