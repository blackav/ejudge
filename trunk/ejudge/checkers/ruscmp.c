/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2007 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "checker_internal.h"

int
checker_strcmp_ucs4(const int *s1, const int *s2)
{
  while (*s1 == *s2 && *s1) {
    s1++, s2++;
  }
  return *s1 - *s2;
}

int
checker_eq_str_rus_ucs4(const char *s1, const int *s2)
{
  size_t s1len;
  int *s1buf;

  s1len = strlen(s1) + 1;
  s1buf = (int*) alloca(s1len * sizeof(s1buf[0]));

  checker_koi8r_to_ucs4_buf(s1buf, s1, s1len);
  if (!checker_strcmp_ucs4(s1buf, s2)) return 1;
  checker_cp1251_to_ucs4_buf(s1buf, s1, s1len);
  if (!checker_strcmp_ucs4(s1buf, s2)) return 1;
  checker_cp866_to_ucs4_buf(s1buf, s1, s1len);
  if (!checker_strcmp_ucs4(s1buf, s2)) return 1;
  checker_iso_to_ucs4_buf(s1buf, s1, s1len);
  if (!checker_strcmp_ucs4(s1buf, s2)) return 1;
  checker_mac_to_ucs4_buf(s1buf, s1, s1len);
  if (!checker_strcmp_ucs4(s1buf, s2)) return 1;
  if (checker_utf8_to_ucs4_buf(s1buf, s1, s1len) >= 0) {
    if (!checker_strcmp_ucs4(s1buf, s2)) return 1;
  }
  return 0;
}

int
checker_eq_str_rus_ucs4_nocase(const char *s1, const int *s2)
{
  size_t s1len;
  int *s1buf;
  int l;

  s1len = strlen(s1) + 1;
  s1buf = (int*) alloca(s1len * sizeof(s1buf[0]));

  checker_koi8r_to_ucs4_buf(s1buf, s1, s1len);
  checker_ucs4_tolower_buf(s1buf, s1len);
  if (!checker_strcmp_ucs4(s1buf, s2)) return 1;
  checker_cp1251_to_ucs4_buf(s1buf, s1, s1len);
  checker_ucs4_tolower_buf(s1buf, s1len);
  if (!checker_strcmp_ucs4(s1buf, s2)) return 1;
  checker_cp866_to_ucs4_buf(s1buf, s1, s1len);
  checker_ucs4_tolower_buf(s1buf, s1len);
  if (!checker_strcmp_ucs4(s1buf, s2)) return 1;
  checker_iso_to_ucs4_buf(s1buf, s1, s1len);
  checker_ucs4_tolower_buf(s1buf, s1len);
  if (!checker_strcmp_ucs4(s1buf, s2)) return 1;
  checker_mac_to_ucs4_buf(s1buf, s1, s1len);
  checker_ucs4_tolower_buf(s1buf, s1len);
  if (!checker_strcmp_ucs4(s1buf, s2)) return 1;
  if ((l = checker_utf8_to_ucs4_buf(s1buf, s1, s1len)) >= 0) {
    checker_ucs4_tolower_buf(s1buf, l);
    if (!checker_strcmp_ucs4(s1buf, s2)) return 1;
  }
  return 0;
}
