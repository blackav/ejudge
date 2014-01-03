/* $Id$ */

#ifndef __REUSE_MEMPAGE_H__
#define __REUSE_MEMPAGE_H__

/* Copyright (C) 1995-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdio.h>
#include <stdlib.h>

struct tPageBlock;
struct tPageDesc;
typedef struct tPageDesc tPageDesc;

#if defined __cplusplus
extern "C" {
#endif /* __cplusplus */

  void pgInitModule(void);
  void pgCloseModule(void);
  void pgStatistics(FILE *);

  tPageDesc *pgCreate(size_t Size);
  void       pgDestroy(tPageDesc *);
  void      *pgMalloc(tPageDesc *,size_t);
  void      *pgCalloc(tPageDesc *, size_t nelem, size_t elem_size);
  void       pgPageStatistics(tPageDesc *, FILE *);    

#if defined __cplusplus
}
#endif /* __cplusplus */

#endif /* __MEMPAGE_H__ */

