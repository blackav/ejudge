/* -*- c -*- */

#ifndef __SHA256UTILS_H__
#define __SHA256UTILS_H__

/* Copyright (C) 2016-2022 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdlib.h>
#include <stdio.h>

void sha256b64buf(char *out, size_t out_size, const unsigned char *in, size_t in_size);
void sha256b64ubuf(char *out, size_t out_size, const unsigned char *in, size_t in_size);
void sha256b64str(char *out, size_t out_size, const unsigned char *str);
void sha256b64file(char *out, size_t out_size, FILE *fin);

#endif
