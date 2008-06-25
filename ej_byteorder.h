/* -*- c -*- */
/* $Id$ */
#ifndef __EJ_BYTEORDER_H__
#define __EJ_BYTEORDER_H__

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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

/* FIXME: current binary order is LE, as on i386
 * need fixing for BE machines
 */
#define cvt_bin_to_host_64(x) (x)
#define cvt_host_to_bin_64(x) (x)
#define cvt_bin_to_host_32(x) (x)
#define cvt_host_to_bin_32(x) (x)
#define cvt_bin_to_host_16(x) (x)
#define cvt_host_to_bin_16(x) (x)

/* FIXME: assuming `unsigned long' is safe to store a pointer value
 * should use `size_t' or `ptrdiff_t' though
 */
#define pkt_bin_align(v) (((v) + 0xf) & ~0xf)
#define pkt_bin_align_addr(v,b) ((v) = (typeof(v)) ((unsigned long) b + pkt_bin_align((unsigned long) v - (unsigned long) b)))

#endif /* __EJ_BYTEORDER_H__ */
