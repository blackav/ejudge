/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `strings.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1991,92,96,97,99,2000,2001 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef __RCC_STRINGS_H__
#define __RCC_STRINGS_H__ 1

/* We don't need and should not read this file if <string.h> was already
   read. The one exception being that if __USE_BSD isn't defined, then
   these aren't defined in string.h, so we need to define them here.  */
#if !defined __RCC_STRING_H__

#include <features.h>
#include <stddef.h>
#include <sys/types.h>

int bcmp(const void *s1, const void *s2, size_t n);
void bcopy(const void *src, void *dest, size_t n);
void bzero(void *s, size_t n);
int ffs(int i);
char *index(const char *s, int c);
char *rindex(const char *s, int c);
int strcasecmp(const char *s1, const char *s2);
int strncasecmp(const char *s1, const char *s2, size_t n);

#endif  /* __RCC_STRING_H__ */

#endif  /* __RCC_STRINGS_H__  */
