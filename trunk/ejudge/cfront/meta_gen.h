/* -*- mode:c -*- */
#ifndef __META_GEN_H__
#define __META_GEN_H__

/* $Id$ */

/* Copyright (C) 2008-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "tree.h"

#include "ejudge/xalloc.h"

#include <stdio.h>

int meta_generate(
        tree_t,
        const unsigned char *,
        const unsigned char *,
        const unsigned char *,
        FILE *,
        FILE *,
        const strarray_t *p_strs,
        const strarray_t *p_enum_pfxs,
        const strarray_t *p_func_pfxs);

#endif /* __META_GEN_H__ */
