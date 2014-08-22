/* -*- mode:c -*- */
/* $Id$ */

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

#define __REUSE__ 1

/* reuse include directives */
#include "ejudge/flexstring.h"
#include "ejudge/xalloc.h"

#include <assert.h>

#define CLUSTER           32
#define ALIGN(size)       ((size+31) & 0xffffffe0)

#ifdef REUSE_DEBUG
#  define CHECK(ptr)        assert((ptr) != NULL)
#  define CHECKPFS(pfs)     assert((pfs)->Used == 0 || (pfs)->Used < (pfs)->Allocd)
#else
#  define CHECK(p)
#  define CHECKPFS(p)
#endif /* REUSE_DEBUG */

  void
_fsDestroy(tFString *pfs)
{
  CHECKPFS(pfs);
  
  if (pfs->String == NULL)
    return;
  xfree(pfs->String);
  pfs->Used = 0;
  pfs->Allocd = 0;
  pfs->String = NULL;
}
