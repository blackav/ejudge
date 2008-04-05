/* -*- c -*- */
/* $Id$ */
#ifndef __STRINGSET_H__
#define __STRINGSET_H__

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

#include <stdlib.h>

struct stringset;
typedef struct stringset *stringset_t;

stringset_t stringset_new(void);
stringset_t stringset_free(stringset_t);
size_t stringset_size(stringset_t);
void stringset_add(stringset_t, const unsigned char *);
void stringset_del(stringset_t, const unsigned char *);
int stringset_check(stringset_t, const unsigned char *);

#endif /* __STRINGSET_H__ */
