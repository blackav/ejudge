/* -*- c -*- */
/* $Id$ */
#ifndef __BASE64_H__
#define __BASE64_H__

/* Copyright (C) 2000 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

int base64_encode(char const *, int, char *);
int base64_encode_str(char const *, char *);
int base64_decode(char const *, int, char *, int *);
int base64_decode_str(char const *, char *, int *);

#endif /* __BASE64_H__ */
