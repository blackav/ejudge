/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `nl_types.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1996, 1997, 1999 Free Software Foundation, Inc.
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

#ifndef __RCC_NL_TYPES_H__
#define __RCC_NL_TYPES_H__ 1

#include <features.h>

int enum
{
#defconst NL_SETD       1
#defconst NL_CAT_LOCALE 1
};

typedef void *nl_catd;
typedef int nl_item;

nl_catd catopen(const char *cat_name, int flag);
char *catgets(nl_catd catalog, int set, int number, const char *string);
int catclose(nl_catd catalog);

#endif /* __RCC_NL_TYPES_H__ */

/*
 * Local variables:
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "nl_catd")
 * End:
 */
