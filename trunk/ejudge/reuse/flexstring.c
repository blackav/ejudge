/* $Id$ */

/* Copyright (C) 1995-2014 Alexander Chernov <cher@ejudge.ru> */
/* Created: <95/11/01 17:30:28 cher> */

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

#define __REUSE__ 1

/* reuse include directives */
#include "ejudge/integral.h"
#include "ejudge/xalloc.h"
#include "ejudge/flexstring.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

/* memory management macros */

#define CLUSTER           32
#define ALIGN(size)       ((size+31) & 0xffffffe0)

#ifdef REUSE_DEBUG

#define CHECK(ptr)        assert((ptr) != NULL)
#define CHECKPFS(pfs)     assert((pfs)->Used == 0 || (pfs)->Used < (pfs)->Allocd)

#else

#define CHECK(p)
#define CHECKPFS(p)

#endif /* REUSE_DEBUG */

void
reuse_fs_range_error(char *func)
{
  fprintf(stderr, "Range error in function %s\n", func);
  abort();
}
