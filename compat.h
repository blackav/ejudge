/* -*- c -*- */
/* $Id$ */
#ifndef __COMPAT_H__
#define __COMPAT_H__

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

#include <stdio.h>

#ifndef __linux__
#include "config.h"

#if HAVE_FMEMOPEN - 0 == 0
FILE *fmemopen(void *buf, size_t size, const char *mode);
#endif

#if HAVE_OPEN_MEMSTREAM - 0 == 0
FILE *open_memstream(char **ptr, size_t *sizeloc);
#endif

#endif

void close_memstream(FILE *f);
void fmemclose(FILE *f);

#endif /* __COMPAT_H__ */
