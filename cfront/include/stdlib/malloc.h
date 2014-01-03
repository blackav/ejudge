/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_MALLOC_H__
#define __RCC_MALLOC_H__

/* Copyright (C) 2003,2004 Alexander Chernov <cher@ispras.ru> */

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

#include <features.h>

#ifndef RCC_SIZE_T_DEFINED
#define RCC_SIZE_T_DEFINED 1
typedef unsigned long size_t;
#endif /* RCC_SIZE_T_DEFINED */


#ifndef RCC_PTRDIFF_T_DEFINED
#define RCC_PTRDIFF_T_DEFINED 1
typedef long ptrdiff_t;
#endif /* RCC_PTRDIFF_T_DEFINED */

#if !defined NULL
#define NULL 0
#endif

void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void  free(void *ptr);
void  cfree(void *ptr);

void *memalign(size_t alignment, size_t size);
void *valloc(size_t size);
void *pvalloc(size_t size);

extern void *(*__morecore)(ptrdiff_t size);
void *__default_morecore(ptrdiff_t size);

struct mallinfo 
{
  int arena;    /* non-mmapped space allocated from system */
  int ordblks;  /* number of free chunks */
  int smblks;   /* number of fastbin blocks */
  int hblks;    /* number of mmapped regions */
  int hblkhd;   /* space in mmapped regions */
  int usmblks;  /* maximum total allocated space */
  int fsmblks;  /* space available in freed fastbin blocks */
  int uordblks; /* total allocated space */
  int fordblks; /* total free space */
  int keepcost; /* top-most, releasable (via malloc_trim) space */
};

/* Returns a copy of the updated current mallinfo. */
struct mallinfo mallinfo(void);

int enum
{
  M_MXFAST = 1,
#define M_MXFAST M_MXFAST
  M_NLBLKS = 2,
#define M_NLBLKS M_NLBLKS
  M_GRAIN = 3,
#define M_GRAIN M_GRAIN
  M_KEEP = 4,
#define M_KEEP M_KEEP
};

int enum
{
  M_TRIM_THRESHOLD = -1,
#define M_TRIM_THRESHOLD M_TRIM_THRESHOLD
  M_TOP_PAD = -2,
#define M_TOP_PAD M_TOP_PAD
  M_MMAP_THRESHOLD = -3,
#define M_MMAP_THRESHOLD M_MMAP_THRESHOLD
  M_MMAP_MAX = -4,
#define M_MMAP_MAX M_MMAP_MAX
  M_CHECK_ACTION = -5,
#define M_CHECK_ACTION M_CHECK_ACTION
};

int     mallopt(int param, int val);
int     malloc_trim(size_t pad);
size_t  malloc_usable_size(void *ptr);
void    malloc_stats(void);
void   *malloc_get_state(void);
int     malloc_set_state(void *ptr);

extern void (*__malloc_initialize_hook)(void);

/* Hooks for debugging and user-defined versions. */
extern void (*__free_hook)(void *ptr, const void *);
extern void *(*__malloc_hook)(size_t size, const void *);
extern void *(*__realloc_hook)(void * ptr, size_t size, const void *);
extern void *(*__memalign_hook)(size_t alignment, size_t size, const void *);
extern void (*__after_morecore_hook)(void);

extern void __malloc_check_init(void);

#endif /* __RCC_MALLOC_H__ */
