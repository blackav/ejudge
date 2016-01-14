#ifndef __REUSE_XALLOC_H__
#define __REUSE_XALLOC_H__

/* Copyright (C) 1996-2016 Alexander Chernov <cher@ejudge.ru> */
/* Created: Fri Nov  1 18:58:50 1996 by cher (Alexander Chernov) */

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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdlib.h>

void *xmalloc(size_t size);
void *xcalloc(size_t nelem, size_t elsize);
void *xrealloc(void *ptr, size_t newsize);
void xfree(void *ptr);
char *xstrdup(char const*);
char *xmemdup(char const *, size_t size);

#if defined __GNUC__
#define XCALLOC(p,s)  ((p) = (typeof(p)) xcalloc((s), sizeof((p)[0])))
#define XREALLOC(p,s) ((p) = (typeof(p)) xrealloc((p), (s) * sizeof((p)[0])))
#define XALLOCA(p,s)  ((p) = (typeof(p)) alloca((s) * sizeof((p)[0])))
#define XALLOCAZ(p,s) ((p) = (typeof(p)) alloca((s) * sizeof((p)[0])), memset((p), 0, ((s) * sizeof((p)[0]))))
#else /* __GNUC__ */
#define XCALLOC(p,s)  ((p) = xcalloc((s), sizeof((p)[0])))
#define XREALLOC(p,s) ((p) = xrealloc((p), (s) * sizeof((p)[0])))
#endif /* __GNUC__ */

#define XMEMMOVE(d,s,c) (memmove((d),(s),(c)*sizeof(*(d))))
#define XMEMZERO(d,c)   (memset((d),0,(c)*sizeof(*(d))))
#define XEXPAND2(a)     (xexpand2(&(a),sizeof((a).v[0])))

#define XOFFSET(type,field)       ((long) &((type*) 0)->field)
#define XDEREF(type,base,offset)  (((type*) (((char*) &(base)) + (offset))))
#define XPDEREF(type,base,offset) (((type*) (((char*) (base)) + (offset))))

/* s1 and s2 both dropped after merging */
char *xstrmerge0(char *s1, char *s2);
/* only s1 dropped after merging */  
char *xstrmerge1(char *s1, char const *s2);
/* neither s1 nor x2 are dropped after merging */
char *xstrmerge2(char const *s1, char const *s2);
/* only s2 dropped after merging */
char *xstrmerge3(char const *s1, char *s2);

/* extendable array of strings */
typedef struct strarray_t
{
  int    a;
  int    u;
  char **v;
} strarray_t;

/* extendable array of ints */
typedef struct intarray_t
{
  int    a;
  int    u;
  int   *v;
} intarray_t;

/* generic extendable array */
typedef struct genarray_t
{
  int    a;
  int    u;
  void  *v;
} genarray_t;

void  xexpand(strarray_t *);
void  xexpand2(/* array, elsize */);
void  xexpand3(/* array, elsize */);
void  xexpand4(/* array, elsize, newsize */);

void  xstrarrayfree(strarray_t *);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REUSE_XALLOC_H__ */
