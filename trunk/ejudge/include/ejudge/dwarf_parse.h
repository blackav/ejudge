/* -*- c -*- */
/* $Id$ */
#ifndef __DWARF_PARSE_H__
#define __DWARF_PARSE_H__

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

#include "ejudge/type_info.h"

#include <stdio.h>

int dwarf_parse(FILE *log_f, const unsigned char *path, TypeContext *cntx, IdScope *scope);

#endif /* __DWARF_PARSE_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
