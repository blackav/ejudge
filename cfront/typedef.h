/* -*- mode:c -*- */
#ifndef __TYPEDEF_H__
#define __TYPEDEF_H__

/* $Id$ */

/* Copyright (C) 2003-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/hash.h"

void typedef_new_scope(void);
void typedef_drop_scope(void);
void typedef_register_typedef(ident_t id);
void typedef_register_regular(ident_t id);
int  typedef_is_typedef(ident_t id);
void typedef_free(void);

#endif /* __TYPEDEF_H__ */
