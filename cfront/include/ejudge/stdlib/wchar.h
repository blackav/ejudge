/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `wchar.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1995-99,2000,01,02 Free Software Foundation, Inc.
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
 *      ISO C99 Standard: 7.24
 *      Extended multibyte and wide character utilities <wchar.h>
 */

#ifndef __RCC_WCHAR_H__
#define __RCC_WCHAR_H__ 1

/* Get FILE definition.  */
#include <features.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>

int enum
{
  __WCHAR_MIN = (-2147483647l - 1l),
#define __WCHAR_MIN __WCHAR_MIN
  __WCHAR_MAX = (2147483647l),
#define __WCHAR_MAX __WCHAR_MAX
};

#ifndef _WINT_T
#define _WINT_T
typedef unsigned int wint_t;
#endif /* _WINT_T */

#ifndef __mbstate_t_defined
#define __mbstate_t_defined 1
/* Conversion state information.  */
typedef struct
{
  int __count;
  union
  {
    wint_t __wch;
    char __wchb[4];
  } __value;            /* Value so far.  */
} __mbstate_t;
#endif /* __mbstate_t_defined */

/* Public type.  */
typedef __mbstate_t mbstate_t;

#ifndef WCHAR_MIN
int enum
{
  WCHAR_MIN = __WCHAR_MIN,
#define WCHAR_MIN WCHAR_MIN
  WCHAR_MAX = __WCHAR_MAX,
#define WCHAR_MAX WCHAR_MAX
};
#endif /* WCHAR_MIN */

#ifndef WEOF
unsigned int enum { WEOF = (0xffffffffu) };
#define WEOF WEOF
#endif /* WEOF */

/* For XPG4 compliance we have to define the stuff from <wctype.h> here
   as well.  */
#include <wctype.h>

/* This incomplete type is defined in <time.h> but needed here because
   of `wcsftime'.  */
struct tm;

wchar_t *wcscpy(wchar_t *dest, const wchar_t *src);
wchar_t *wcsncpy(wchar_t *dest, const wchar_t *src, size_t n);
wchar_t *wcscat(wchar_t *dest, const wchar_t *src);
wchar_t *wcsncat(wchar_t *dest, const wchar_t *src, size_t n);

int wcscmp(const wchar_t *s1, const wchar_t *s2);
int wcsncmp(const wchar_t *s1, const wchar_t *s2, size_t n);
int wcscasecmp(const wchar_t *s1, const wchar_t *s2);
int wcsncasecmp(const wchar_t *s1, const wchar_t *s2, size_t n);

/* Similar to the two functions above but take the information from
   the provided locale and not the global locale.  */
#include <xlocale.h>

int wcscasecmp_l(const wchar_t *s1, const wchar_t *s2, __locale_t loc);
int wcsncasecmp_l(const wchar_t *s1, const wchar_t *s2,
                  size_t n, __locale_t loc);

int wcscoll(const wchar_t *s1, const wchar_t *s2);
size_t wcsxfrm(wchar_t *s1, const wchar_t *s2, size_t n);
int wcscoll_l(const wchar_t *s1, const wchar_t *s2, __locale_t loc);
size_t wcsxfrm_l(wchar_t *s1, const wchar_t *s2, size_t n, __locale_t loc);

wchar_t *wcsdup(const wchar_t *s);

wchar_t *wcschr(const wchar_t *wcs, wchar_t wc);
wchar_t *wcsrchr(const wchar_t *wcs, wchar_t wc);
wchar_t *wcschrnul(const wchar_t *s, wchar_t wc);
size_t wcscspn(const wchar_t *wcs, const wchar_t *reject);
size_t wcsspn(const wchar_t *wcs, const wchar_t *accept);
wchar_t *wcspbrk(const wchar_t *wcs, const wchar_t *accept);
wchar_t *wcsstr(const wchar_t *haystack, const wchar_t *needle);
wchar_t *wcstok(wchar_t *s, const wchar_t *delim, wchar_t **ptr);
size_t wcslen(const wchar_t *s);
wchar_t *wcswcs(const wchar_t *haystack, const wchar_t *needle);
size_t wcsnlen(const wchar_t *s, size_t maxlen);
wchar_t *wmemchr(const wchar_t *s, wchar_t c, size_t n);
int wmemcmp(const wchar_t *s1, const wchar_t *s2, size_t n);
wchar_t *wmemcpy(wchar_t *s1, const wchar_t *s2, size_t n);
wchar_t *wmemmove(wchar_t *s1, const wchar_t *s2, size_t n);
wchar_t *wmemset(wchar_t *s, wchar_t c, size_t n);
wchar_t *wmempcpy(wchar_t *s1, const wchar_t *s2, size_t n);

wint_t btowc(int c);
int wctob(wint_t c);
int mbsinit(const mbstate_t *ps);
size_t mbrtowc(wchar_t *pwc, const char *s, size_t n, mbstate_t *p);
size_t wcrtomb(char *s, wchar_t wc, mbstate_t *ps);
size_t __mbrlen(const char *s, size_t n, mbstate_t *ps);
size_t mbrlen(const char *s, size_t n, mbstate_t *ps);
size_t mbsrtowcs(wchar_t *dst, const char **src, size_t len, mbstate_t *ps);
size_t wcsrtombs(char *dst, const wchar_t **src, size_t len, mbstate_t *ps);
size_t mbsnrtowcs(wchar_t *dst, const char **src, size_t nmc,
                  size_t len, mbstate_t *ps);
size_t wcsnrtombs(char *dst, const wchar_t **src, size_t nwc, size_t len,
                  mbstate_t *ps);
int wcwidth(wchar_t c);
int wcswidth(const wchar_t *s, size_t n);

double wcstod(const wchar_t *nptr, wchar_t **endptr);
float wcstof(const wchar_t *nptr, wchar_t **endptr);
long double wcstold(const wchar_t *nptr, wchar_t **endptr);
long int wcstol(const wchar_t *nptr, wchar_t **endptr, int base);
unsigned long int wcstoul(const wchar_t *nptr, wchar_t **endptr, int base);
long long wcstoll(const wchar_t *nptr, wchar_t **endptr, int base);
unsigned long long wcstoull(const wchar_t *nptr, wchar_t **endptr, int base);
long long wcstoq(const wchar_t *nptr, wchar_t **endptr, int base);
unsigned long long wcstouq(const wchar_t *nptr, wchar_t **endptr, int base);

/* The concept of one static locale per category is not very well
   thought out.  Many applications will need to process its data using
   information from several different locales.  Another application is
   the implementation of the internationalization handling in the
   upcoming ISO C++ standard library.  To support this another set of
   the functions using locale data exist which have an additional
   argument.

   Attention: all these functions are *not* standardized in any form.
   This is a proof-of-concept implementation.  */

/* Structure for reentrant locale using functions.  This is an
   (almost) opaque type for the user level programs.  */
# include <xlocale.h>

/* Special versions of the functions above which take the locale to
   use as an additional parameter.  */
long int wcstol_l(const wchar_t *nptr, wchar_t **endptr, int base,
                  __locale_t loc);
unsigned long int wcstoul_l(const wchar_t *nptr, wchar_t **endptr,
                            int base, __locale_t loc);
long long int wcstoll_l(const wchar_t *nptr, wchar_t **endptr,
                        int base, __locale_t loc);
unsigned long long wcstoull_l(const wchar_t *nptr, wchar_t **endptr,
                              int base, __locale_t loc);
double wcstod_l(const wchar_t *nptr, wchar_t **endptr, __locale_t loc);
float wcstof_l(const wchar_t *nptr, wchar_t **endptr, __locale_t loc);
long double wcstold_l(const wchar_t *nptr, wchar_t **endptr, __locale_t loc);

/* The internal entry points for `wcstoX' take an extra flag argument
   saying whether or not to parse locale-dependent number grouping.  */
double __wcstod_internal(const wchar_t *nptr, wchar_t **endptr, int group);
float __wcstof_internal(const wchar_t *nptr, wchar_t **endptr, int group);
long double __wcstold_internal(const wchar_t *nptr, wchar_t **endptr, int grp);
long int __wcstol_internal(const wchar_t *nptr, wchar_t **endptr,
                           int base, int group);
unsigned long int __wcstoul_internal(const wchar_t *npt,
                                     wchar_t **endptr,
                                     int base, int group);
long long int __wcstoll_internal(const wchar_t *nptr,
                                 wchar_t **endptr,
                                 int base, int group);
unsigned long long int __wcstoull_internal(const wchar_t *nptr,
                                           wchar_t **endptr,
                                           int base, int group);

wchar_t *wcpcpy(wchar_t *dest, const wchar_t *src);
wchar_t *wcpncpy(wchar_t *dest, const wchar_t *src, size_t n);

/* Wide character I/O functions.  */
int fwide(FILE *fp, int mode);

int fwprintf(FILE *stream, const wchar_t *format, ...)
      /* __attribute__ ((__format__ (__wprintf__, 2, 3))) */;
int wprintf(const wchar_t *format, ...)
      /* __attribute__ ((__format__ (__wprintf__, 1, 2))) */;
int swprintf(wchar_t *s, size_t n, const wchar_t *format, ...)
      /* __attribute__ ((__format__ (__wprintf__, 3, 4))) */;

int vfwprintf(FILE *s, const wchar_t *format, va_list arg)
      /* __attribute__ ((__format__ (__wprintf__, 2, 0))) */;
int vwprintf(const wchar_t *format, va_list __arg)
      /* __attribute__ ((__format__ (__wprintf__, 1, 0))) */;
int vswprintf(wchar_t *s, size_t n, const wchar_t *format, va_list __arg)
      /* __attribute__ ((__format__ (__wprintf__, 3, 0))) */;

int fwscanf(FILE *stream, const wchar_t *format, ...)
      /* __attribute__ ((__format__ (__wscanf__, 2, 3))) */;
int wscanf(const wchar_t *format, ...)
      /* __attribute__ ((__format__ (__wscanf__, 1, 2))) */;
int swscanf(const wchar_t *s, const wchar_t *format, ...)
      /* __attribute__ ((__format__ (__wscanf__, 2, 3))) */;

int vfwscanf(FILE *s, const wchar_t *format, va_list arg)
      /* __attribute__ ((__format__ (__wscanf__, 2, 0))) */;
int vwscanf(const wchar_t *format, va_list arg)
      /* __attribute__ ((__format__ (__wscanf__, 1, 0))) */;
int vswscanf(const wchar_t *s, const wchar_t *format, va_list arg)
      /* __attribute__ ((__format__ (__wscanf__, 2, 0))) */;

wint_t fgetwc(FILE *stream);
wint_t getwc(FILE *stream);
wint_t getwchar(void);
wint_t fputwc(wchar_t wc, FILE *stream);
wint_t putwc(wchar_t wc, FILE *stream);
wint_t putwchar(wchar_t wc);
wchar_t *fgetws(wchar_t *ws, int n, FILE *stream);
int fputws(const wchar_t *ws, FILE *stream);
wint_t ungetwc(wint_t wc, FILE *stream);
wint_t getwc_unlocked(FILE *__stream);
wint_t getwchar_unlocked(void);
wint_t fgetwc_unlocked(FILE *stream);
wint_t fputwc_unlocked(wchar_t wc, FILE *stream);
wint_t putwc_unlocked(wchar_t wc, FILE *stream);
wint_t putwchar_unlocked(wchar_t wc);
wchar_t *fgetws_unlocked(wchar_t *ws, int n, FILE *stream);
int fputws_unlocked(const wchar_t *ws, FILE *stream);

size_t wcsftime(wchar_t *s, size_t maxsize, const wchar_t *format,
                const struct tm *tp);

# include <xlocale.h>

size_t wcsftime_l(wchar_t *s, size_t maxsize, const wchar_t *format,
                  const struct tm *tp, __locale_t loc);

#endif /* __RCC_WCHAR_H__  */


/*
 * Local variables:
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
