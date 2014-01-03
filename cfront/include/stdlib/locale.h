/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `locale.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1991,92,95-99,2000,01,02 Free Software Foundation, Inc.
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

/*
 *      ISO C99 Standard: 7.11 Localization     <locale.h>
 */

#ifndef __RCC_LOCALE_H__
#define __RCC_LOCALE_H__ 1

#include <features.h>
#include <bits/locale.h>

/* Structure giving information about numeric and monetary notation.  */
struct lconv
{
  char *decimal_point;
  char *thousands_sep;
  char *grouping;
  char *int_curr_symbol;
  char *currency_symbol;
  char *mon_decimal_point;
  char *mon_thousands_sep;
  char *mon_grouping;
  char *positive_sign;
  char *negative_sign;
  char int_frac_digits;
  char frac_digits;
  char p_cs_precedes;
  char p_sep_by_space;
  char n_cs_precedes;
  char n_sep_by_space;
  char p_sign_posn;
  char n_sign_posn;
  char int_p_cs_precedes;
  char int_p_sep_by_space;
  char int_n_cs_precedes;
  char int_n_sep_by_space;
  char int_p_sign_posn;
  char int_n_sign_posn;
  char __int_p_cs_precedes;
  char __int_p_sep_by_space;
  char __int_n_cs_precedes;
  char __int_n_sep_by_space;
  char __int_p_sign_posn;
  char __int_n_sign_posn;
};

char *setlocale(int category, const char *locale);
struct lconv *localeconv(void);

# include <xlocale.h>

typedef __locale_t locale_t;

__locale_t newlocale(int category_mask, const char *locale, __locale_t base);

int enum
{
#defconst LC_CTYPE_MASK          (1 << LC_CTYPE)
#defconst LC_NUMERIC_MASK        (1 << LC_NUMERIC)
#defconst LC_TIME_MASK           (1 << LC_TIME)
#defconst LC_COLLATE_MASK        (1 << LC_COLLATE)
#defconst LC_MONETARY_MASK       (1 << LC_MONETARY)
#defconst LC_MESSAGES_MASK       (1 << LC_MESSAGES)
#defconst LC_PAPER_MASK          (1 << LC_PAPER)
#defconst LC_NAME_MASK           (1 << LC_NAME)
#defconst LC_ADDRESS_MASK        (1 << LC_ADDRESS)
#defconst LC_TELEPHONE_MASK      (1 << LC_TELEPHONE)
#defconst LC_MEASUREMENT_MASK    (1 << LC_MEASUREMENT)
#defconst LC_IDENTIFICATION_MASK (1 << LC_IDENTIFICATION)
#defconst LC_ALL_MASK            (LC_CTYPE_MASK | LC_NUMERIC_MASK | LC_TIME_MASK | LC_COLLATE_MASK | LC_MONETARY_MASK | LC_MESSAGES_MASK | LC_PAPER_MASK | LC_NAME_MASK | LC_ADDRESS_MASK | LC_TELEPHONE_MASK | LC_MEASUREMENT_MASK | LC_IDENTIFICATION_MASK)
};

__locale_t duplocale(__locale_t dataset);
void freelocale(__locale_t dataset);
__locale_t uselocale(__locale_t dataset);

#define LC_GLOBAL_LOCALE       ((__locale_t) -1L)

#endif /* __RCC_LOCALE_H__  */
