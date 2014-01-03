/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `wctype.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1996,97,98,99,2000,01,02 Free Software Foundation, Inc.
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
 *      ISO C99 Standard: 7.25
 *      Wide character classification and mapping utilities  <wctype.h>
 */

#ifndef __RCC_WCTYPE_H__
#define __RCC_WCTYPE_H__ 1

#include <features.h>
#include <sys/types.h>

#ifndef _WINT_T
#define _WINT_T
typedef unsigned int wint_t;
#endif /* _WINT_T */

/* Constant expression of type `wint_t' whose value does not correspond
   to any member of the extended character set.  */
#ifndef WEOF
unsigned int enum { WEOF  = (0xffffffffu) };
#define WEOF WEOF
#endif

/* The following part is also used in the <wcsmbs.h> header when compiled
   in the Unix98 compatibility mode.  */
typedef unsigned long int wctype_t;

#define _ISwbit(bit) \
        ((bit) < 8 ? (int) ((1UL << (bit)) << 24)                             \
         : ((bit) < 16 ? (int) ((1UL << (bit)) << 8)                          \
            : ((bit) < 24 ? (int) ((1UL << (bit)) >> 8)                       \
               : (int) ((1UL << (bit)) >> 24))))

int enum
{
  __ISwupper = 0,                       /* UPPERCASE.  */
  __ISwlower = 1,                       /* lowercase.  */
  __ISwalpha = 2,                       /* Alphabetic.  */
  __ISwdigit = 3,                       /* Numeric.  */
  __ISwxdigit = 4,                      /* Hexadecimal numeric.  */
  __ISwspace = 5,                       /* Whitespace.  */
  __ISwprint = 6,                       /* Printing.  */
  __ISwgraph = 7,                       /* Graphical.  */
  __ISwblank = 8,                       /* Blank (usually SPC and TAB).  */
  __ISwcntrl = 9,                       /* Control character.  */
  __ISwpunct = 10,                      /* Punctuation.  */
  __ISwalnum = 11,                      /* Alphanumeric.  */

  _ISwupper = _ISwbit (__ISwupper),     /* UPPERCASE.  */
  _ISwlower = _ISwbit (__ISwlower),     /* lowercase.  */
  _ISwalpha = _ISwbit (__ISwalpha),     /* Alphabetic.  */
  _ISwdigit = _ISwbit (__ISwdigit),     /* Numeric.  */
  _ISwxdigit = _ISwbit (__ISwxdigit),   /* Hexadecimal numeric.  */
  _ISwspace = _ISwbit (__ISwspace),     /* Whitespace.  */
  _ISwprint = _ISwbit (__ISwprint),     /* Printing.  */
  _ISwgraph = _ISwbit (__ISwgraph),     /* Graphical.  */
  _ISwblank = _ISwbit (__ISwblank),     /* Blank (usually SPC and TAB).  */
  _ISwcntrl = _ISwbit (__ISwcntrl),     /* Control character.  */
  _ISwpunct = _ISwbit (__ISwpunct),     /* Punctuation.  */
  _ISwalnum = _ISwbit (__ISwalnum)      /* Alphanumeric.  */
};

int iswalnum(wint_t wc);
int iswalpha(wint_t wc);
int iswcntrl(wint_t wc);
int iswdigit(wint_t wc);
int iswgraph(wint_t wc);
int iswlower(wint_t wc);
int iswprint(wint_t wc);
int iswpunct(wint_t wc);
int iswspace(wint_t wc);
int iswupper(wint_t wc);
int iswxdigit(wint_t wc);
int iswblank(wint_t wc);

/*
 * Extensible wide-character classification functions: 7.15.2.2.
 */
wctype_t wctype(const char *property);
int iswctype(wint_t wc, wctype_t desc);


/*
 * Wide-character case-mapping functions: 7.15.3.1.
 */

typedef const int32_t *wctrans_t;
wint_t towlower(wint_t wc);
wint_t towupper(wint_t wc);

/*
 * Extensible wide-character mapping functions: 7.15.3.2.
 */

wctrans_t wctrans(const char *property);
wint_t towctrans(wint_t wc, wctrans_t desc);

#include <xlocale.h>

int iswalnum_l(wint_t wc, __locale_t locale);
int iswalpha_l(wint_t wc, __locale_t locale);
int iswcntrl_l(wint_t wc, __locale_t locale);
int iswdigit_l(wint_t wc, __locale_t locale);
int iswgraph_l(wint_t wc, __locale_t locale);
int iswlower_l(wint_t wc, __locale_t locale);
int iswprint_l(wint_t wc, __locale_t locale);
int iswpunct_l(wint_t wc, __locale_t locale);
int iswspace_l(wint_t wc, __locale_t locale);
int iswupper_l(wint_t wc, __locale_t locale);
int iswxdigit_l(wint_t wc, __locale_t locale);
int iswblank_l(wint_t wc, __locale_t locale);
wctype_t wctype_l(const char *property, __locale_t locale);
int iswctype_l(wint_t wc, wctype_t desc, __locale_t locale);

/*
 * Wide-character case-mapping functions.
 */

wint_t towlower_l(wint_t wc, __locale_t locale);
wint_t towupper_l(wint_t wc, __locale_t locale);
wctrans_t wctrans_l(const char *property, __locale_t locale);
wint_t towctrans_l(wint_t wc, wctrans_t desc, __locale_t locale);

#endif /* __RCC_WCTYPE_H__  */
