/* -*- mode: c -*- */
/* $Id$ */

#ifndef __REUSE_NUMBER_IO_H__
#define __REUSE_NUMBER_IO_H__

/* Copyright (C) 2002-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdlib.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/* numeric write flags */
enum
{
  REUSE_FORMAT_ALT = 1,
  REUSE_FORMAT_SPC = 2,
  REUSE_FORMAT_PLUS = 4,
  REUSE_FORMAT_UP = 8
};

/* do not define prototypes unconditionally due to compatbility */
#ifdef __REUSE_FORCE_STRTOLL
rllong_t reuse_strtoll(char const *str, char **eptr, int base);
rullong_t reuse_strtoull(char const *str, char **eptr, int base);
#endif

/* convert a long long value into a character string */
int reuse_writell(char *, size_t, void const *, int, int, int);
/* convert an unsigned long long value into a character string */
int reuse_writeull(char *, size_t, void const *, int, int, int);

int os_readint(char const *, int *);
int os_readdouble(char const *, double *);

int os_readll(char const *, char **, int, void *);
int os_readull(char const *, char **, int, void *);

/* convert a float value into a hexadecimal character string */
int reuse_writehf(char *, size_t size, float const *pval, int, int);
/* convert a double value into a hexadecimal character string */
int reuse_writehd(char *, size_t size, double const *pval, int, int);
/* convert a long double value into a hexadecimal character string */
int reuse_writehld(char *, size_t size, long double const *pval, int, int);

/* convert a hexadecimal representation of float number into float */
int reuse_readhf(char const *, char **, float *);
/* convert a hexadecimal representation of double number */
int reuse_readhd(char const *, char **, double *);
/* convert a hexadecimal representation of long double number */
int reuse_readhld(char const *, char **, long double *);

int os_readdf(char const *, char **, float *);
int os_readdd(char const *, char **, double *);
int os_readdld(char const *, char **, long double *);

int reuse_writedld(char *, size_t, long double const *, int, int, int);

long double reuse_strtold(char const *, char **);
double reuse_strtod(char const *, char **);
float reuse_strtof(char const *, char **);

void reuse_init_fp(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REUSE_NUMBER_IO_H__ */
