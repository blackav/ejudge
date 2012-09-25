/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2012 Alexander Chernov <cher@ejudge.ru> */

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

#define NEED_CORR 1
#include "checker.h"

enum { BUFSIZE = 1024 };

static int
is_number(const char *buf)
{
  const char *p = buf;

  if (!*p) return 0;
  if (*p == '+' || *p == '-') p++;
  if (!*p) return 0;
  while (*p >= '0' && *p <= '9') p++;
  if (!*p) return 1;
  return 0;
}

static void
normalize_number(char *buf)
{
  char *pin = buf, *pout = buf;

  if (*pin == '+') {
    pin++;
  } else if (*pin == '-') {
    pout++;
    pin++;
  }

  while (*pin == '0') pin++;
  if (pin == pout) return;
  if (!*pin) {
    buf[0] = '0';
    buf[1] = 0;
    return;
  }
  while (*pin) *pout++ = *pin++;
  *pout = 0;
}

int
checker_main(int argc, char *argv[])
{
  char outsbuf[BUFSIZE], corrsbuf[BUFSIZE];
  char *outdbuf = 0, *corrdbuf = 0;
  size_t outdsz = 0, corrdsz = 0;
  char *outval, *corrval;

  if (getenv("EJ_REQUIRE_NL")) {
    if (fseek(f_out, -1L, SEEK_END) >= 0) {
      if (getc(f_out) != '\n') fatal_PE("no final \\n in the output file");
      fseek(f_out, 0L, SEEK_SET);
    }
  }

  corrval = checker_read_buf_2(2,"corr",1,corrsbuf,BUFSIZE,&corrdbuf,&corrdsz);
  checker_corr_eof();
  if (!is_number(corrval)) fatal_CF("corr: not a number");
  normalize_number(corrval);

  outval = checker_read_buf_2(1, "out", 1, outsbuf, BUFSIZE, &outdbuf, &outdsz);
  checker_out_eof();
  if (!is_number(outval)) fatal_PE("out: not a number");
  normalize_number(outval);

  if (strcmp(outval, corrval) != 0)
    fatal_WA("wrong answer: out: %s, corr: %s", outval, corrval);

  checker_OK();
}
