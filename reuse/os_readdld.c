/* -*- mode:c -*- */
/* $Id$ */

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

#define __REUSE__ 1

/* reuse include directives */
#include "ejudge/integral.h"
#include "ejudge/number_io.h"

#include <stdlib.h>
#include <errno.h>

/* if endptr == 0, we don't care about string termination */
/* if endptr == (char**) 1, string must end at the last character */
/* inf, -inf, nan literal values are supported */
/* returns:
 *  0  - ok,
 *  -1 - format error,
 *  1  - overflow ([-]INFINITY returned)
 *  2  - loss of precision ([-]0 returned)
 */
int
os_readdld(char const *str, char **endptr, long double *pval)
{
#if R_LONG_DOUBLE_IS_DOUBLE - 0 == 1
  return os_readdd(str, endptr, (double*) pval);
#else
  long double v = 0.0L;
  int ret_val = -1;

  if (!str) goto _exit;
  errno = 0;
  v = reuse_strtold(str, (char**) &str);
  if (endptr == (char**) 1 && *str) {
    ret_val = -1;
  } else if (errno == ERANGE && v == 0.0L) {
    ret_val = 2;
  } else if (errno == ERANGE) {
    ret_val = 1;
  } else {
    ret_val = 0;
  }

 _exit:
  if (pval) *pval = v;
  if (endptr && endptr != (char**) 1) *endptr = (char*) str;
  return ret_val;
#endif
}
