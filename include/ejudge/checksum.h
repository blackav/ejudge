/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __CHECKSUM_H__
#define __CHECKSUM_H__

/* Copyright (C) 2025 Alexander Chernov <cher@ejudge.ru> */

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
#include <stdlib.h>

struct checksum_context
{
    unsigned char **paths;
    size_t path_a, path_u;
    unsigned char checksum[32];
};

void checksum_free(struct checksum_context *cntx);
void checksum_add_file(struct checksum_context *cntx, const unsigned char *path);
void checksum_sort(struct checksum_context *cntx);
int checksum_compute(struct checksum_context *cntx, FILE *log_f);
unsigned char *checksum_bytes(struct checksum_context *cntx);
unsigned char *checksum_hex(struct checksum_context *cntx, unsigned char *buf);

 #endif /* __CHECKSUM_H__ */
