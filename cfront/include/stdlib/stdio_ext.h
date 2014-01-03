/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `stdio_ext.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Functions to access FILE structure internals.
   Copyright (C) 2000, 2001 Free Software Foundation, Inc.
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

/* This header contains the same definitions as the header of the same name
   on Sun's Solaris OS.  */

#ifndef __RCC_STDIO_EXT_H__
#define __RCC_STDIO_EXT_H__ 1

#include <features.h>
#include <stdio.h>

int enum
{
  FSETLOCKING_QUERY = 0,
#define FSETLOCKING_QUERY       FSETLOCKING_QUERY
  FSETLOCKING_INTERNAL,
#define FSETLOCKING_INTERNAL    FSETLOCKING_INTERNAL
  FSETLOCKING_BYCALLER
#define FSETLOCKING_BYCALLER    FSETLOCKING_BYCALLER
};

size_t __fbufsize(FILE *fp);
int __freading(FILE *fp);
int __fwriting(FILE *fp);
int __freadable(FILE *fp);
int __fwritable(FILE *fp);
int __flbf(FILE *fp);
void __fpurge(FILE *fp);
size_t __fpending(FILE *fp);
void _flushlbf(void);
int __fsetlocking(FILE *fp, int type);

#endif  /* __RCC_STDIO_EXT_H__ */
