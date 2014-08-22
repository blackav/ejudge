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
#include "ejudge/fp_props.h"

#include <errno.h>

int
os_readdf(char const *str, char **endptr, float *pval)
{
  float v = 0.0f;
  double vv = 0.0;
  int ret_val = -1;

  if (!str) goto _exit;
  errno = 0;
  vv = strtod(str, (char**) &str);
  if (endptr == (char**) 1 && *str) {
    ret_val = -1;
  } else if (errno == ERANGE && v == 0.0) {
    ret_val = 2;
  } else if (errno == ERANGE) {
    ret_val = 1;
  } else if (vv != 0.0) {
    v = (float) vv;
    if (reuse_is_infinity_f(&v)) {
      ret_val = 1;
    } else if (v == 0.0f) {
      ret_val = 2;
    } else {
      ret_val = 0;
    }
  } else {
    ret_val = 0;
  }

 _exit:
  if (pval) *pval = v;
  if (endptr && endptr != (char**) 1) *endptr = (char*) str;
  return ret_val;
}
