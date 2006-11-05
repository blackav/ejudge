/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005, 2006 Alexander Chernov <cher@ejudge.ru> */

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
#define NEED_INFO 0
#define NEED_TGZ  0
#include "checker.h"

int checker_main(int argc, char **argv)
{
  double team_ans, corr_ans, eps;
  unsigned char *s, *abs_flag = 0;
  int n, i = 0;
  unsigned char buf[32];

  if (!(s = getenv("EPS")))
    fatal_CF("environment variable EPS is not set");
  if (sscanf(s, "%lf%n", &eps, &n) != 1 || s[n])
    fatal_CF("cannot parse EPS value");
  if (eps <= 0.0)
    fatal_CF("EPS <= 0");
  if (eps >= 1)
    fatal_CF("EPS >= 1");
  abs_flag = getenv("ABSOLUTE");

  while (1) {
    i++;
    snprintf(buf, sizeof(buf), "[%d]", i);
    if (checker_read_corr_double(buf, 0, &corr_ans) < 0) break;
    if (checker_read_team_double(buf, 0, &team_ans) < 0) {
      fatal_WA("Too few numbers in the team output");
    }
    if (!(abs_flag?checker_eq_double_abs:checker_eq_double)(team_ans, corr_ans, eps))
      fatal_WA("Answers differ: %s: team: %.10g, corr: %.10g",
	       buf, team_ans, corr_ans);
  }
  if (checker_read_team_double("x", 0, &team_ans) >= 0) {
    fatal_WA("Too many numbers in the team output");
  }
  checker_team_eof();

  checker_OK();
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
