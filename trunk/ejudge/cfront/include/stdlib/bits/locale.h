/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `bits/locale.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Definition of locale category symbol values.
   Copyright (C) 2001 Free Software Foundation, Inc.
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

#ifndef __RCC_BITS_LOCALE_H__
#define __RCC_BITS_LOCALE_H__ 1

int enum
{
#defconst LC_CTYPE          0
#defconst LC_NUMERIC        1
#defconst LC_TIME           2
#defconst LC_COLLATE        3
#defconst LC_MONETARY       4
#defconst LC_MESSAGES       5
#defconst LC_ALL            6
#defconst LC_PAPER          7
#defconst LC_NAME           8
#defconst LC_ADDRESS        9
#defconst LC_TELEPHONE      10
#defconst LC_MEASUREMENT    11
#defconst LC_IDENTIFICATION 12
};

#endif  /* __RCC_BITS_LOCALE_H__ */
