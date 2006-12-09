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

#include "checker_internal.h"

int
checker_eq_sexpr(checker_sexpr_t l_out, checker_sexpr_t l_corr)
{
  if (!l_corr && !l_out) return 1;
  if (!l_corr || !l_out) return 0;
  if (l_corr->kind != l_out->kind) return 0;
  if (l_corr->kind == CHECKER_SEXPR_ATOM) {
    if (strcmp(l_corr->a.value, l_out->a.value) != 0) return 0;
    return 1;
  }

  while (l_corr && l_out
         && l_corr->kind==CHECKER_SEXPR_PAIR
         && l_out->kind==CHECKER_SEXPR_PAIR) {
    if (!checker_eq_sexpr(l_corr->p.head, l_out->p.head)) return 0;
    l_corr = l_corr->p.tail;
    l_out = l_out->p.tail;
  }
  if (!l_corr && !l_out) return 1;
  if (!l_corr || !l_out) return 0;
  return checker_eq_sexpr(l_corr, l_out);
}
