/* -*- mode:c -*- */
/* $Id$ */

#ifndef __REUSE_POSITIONSP_H__
#define __REUSE_POSITIONSP_H__

/* Copyright (C) 2002-2014 Alexander Chernov <cher@ejudge.ru> */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include "ejudge/positions.h"

typedef struct posstate_t
{
  int initialized;
  tssDesc fname_table;
} posstate_t;

#endif /* __REUSE_POSITIONSP_H__ */
