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

void reuse_fs_range_error(char const *);

  void
_fsInsChar(tFString *pfs,char c,int pos)
{
  CHECKPFS(pfs);
  
  if(pos < 0 || (unsigned int) pos > pfs->Used)
    reuse_fs_range_error("_fsInsChar");
  
  if(pfs->Used + 1 >= pfs->Allocd)
    {
      pfs->String = (char*) xrealloc(pfs->String, pfs->Allocd += CLUSTER);
      pfs->String[pfs->Used] = 0;
      
      CHECK(pfs->String);
    }
  
  memmove(pfs->String+pos+1,pfs->String+pos,pfs->Used-pos+1);
  
  pfs->String[pos] = (char) c;
  pfs->Used++;
}
