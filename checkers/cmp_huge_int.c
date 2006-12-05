/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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

enum { BUFSIZE = 1048576 };

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
}

int
checker_main(int argc, char *argv[])
{
  char outbuf[BUFSIZE], corrbuf[BUFSIZE];

  checker_read_buf(1, "out", 1, outbuf, BUFSIZE);
  checker_out_eof();
  if (!is_number(outbuf)) fatal_PE("out: not a number");
  normalize_number(outbuf);

  checker_read_buf(2, "corr", 1, corrbuf, BUFSIZE);
  checker_corr_eof();
  if (!is_number(corrbuf)) fatal_CF("corr: not a number");
  normalize_number(corrbuf);

  if (strcmp(outbuf, corrbuf) != 0)
    fatal_WA("wrong answer: out: %s, corr: %s", outbuf, corrbuf);

  checker_OK();
}
