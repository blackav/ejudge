/* -*- c -*- */
/* $Id$ */

#ifndef __DIGEST_IO_H__
#define __DIGEST_IO_H__

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

/* supported digest types */
enum
{
  DIGEST_SHA1 = 0,
};

int digest_get_ascii_size(int kind);
int digest_get_size(int kind);
int digest_to_ascii(int kind, const void *raw, unsigned char *asc);
int digest_from_ascii(int kind, const unsigned char *asc, void *raw);
int digest_is_equal(int kind, const void *dig1, const void *dig2);

#endif /* __DIGEST_IO_H__ */

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
