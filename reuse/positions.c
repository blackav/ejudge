/* $Id$ */

/* Copyright (C) 1995-2014 Alexander Chernov <cher@ejudge.ru> */
/* Ich, Doktor Josef Grosch, Informatiker, Juli 1992 */
/* Alexander Chernov, October 1995 */

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

/*
 * File Position.c is derived from Positions.c which came with
 * Cocktail toolbox. Original copyrights are preserved.
 * The module has been tailored for RASTA specific goal.
 * Field GRef is added to struct tPosition.
 */

#define __REUSE__ 1

/* reuse include directives */
#include "ejudge/integral.h"
#include "ejudge/positionsp.h"
#include "ejudge/logger.h"
#include "ejudge/number_io.h"

#include <assert.h>
#include <stdlib.h>

posstate_t positions_state;
#define S positions_state
