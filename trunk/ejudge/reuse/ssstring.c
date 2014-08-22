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
#include "ejudge/r_stringset.h"

#include <assert.h>

#define CLUSTER            16

#ifdef REUSE_DEBUG
#define CHECKSSD(ssd) \
assert((ssd) != NULL && (ssd)->Table != NULL && (ssd)->Allocd >= (ssd)->Used)
#define CHECK(ptr)     assert(ptr != NULL)
#define CHECKSS(tss,pssd)  assert(tss < (pssd)->Used)
#else
#define CHECKSSD(s)
#define CHECK(ptr)
#define CHECKSS(tss,pssd)
#endif

  char *
_ssString(tssDesc *pssd,tssEntry sse)
{
  CHECKSSD(pssd);
  CHECKSS(sse,pssd);
  
  return pssd->Table[sse];
}
