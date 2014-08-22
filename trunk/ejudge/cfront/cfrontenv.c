/* -*- mode: c -*- */
/* $Id$ */

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

#include "ejudge/config.h"
#include "lconfig.h"

#include "cfrontenv.h"

const unsigned char *
get_PRJ_HOME(void)
{
  return EJUDGE_PREFIX_DIR;
}

const unsigned char *
get_PRJ_CONFIG(void)
{
  return "ejudge/cfront";
}

