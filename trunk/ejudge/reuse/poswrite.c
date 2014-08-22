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
#include "ejudge/positionsp.h"

#include <assert.h>

extern posstate_t positions_state;
#define S positions_state

  void
_posWrite(tPosition *pos,FILE *f)
{
  assert(pos != NULL && f != NULL);
  if (!S.initialized) posInitModule();
  
  fprintf(f,"%u %u ",pos->Line,pos->Column);
  ssWrite(S.fname_table,pos->FName,f);
}
