/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "sema.h"
#include "sema_an.h"
#include "tree.h"

#include "ejudge/getopt.h"

short sema_option_float_arith = 0;
short sema_option_aggreg_return = 1;
short sema_option_warn_register_param = 0;

optrec_t sema_options[] =
{
  /* --float-arith */
  { 1, 0, "--float-arith", "s1", &sema_option_float_arith,
    "enable arithmetics in float", 0, 0 },
  /* --no-float-arith */
  { 1, 0, "--no-float-arith", "s0", &sema_option_float_arith,
    "disable arithmetics in float (default)", 0, 0 },
  /* --aggreg-return */
  { 1, 0, "--aggreg-return", "s1", &sema_option_aggreg_return,
    "enable functions returning aggregate types (default)", 0, 0 },
  /* --no-aggreg-return */
  { 1, 0, "--no-aggreg-return", "s0", &sema_option_aggreg_return,
    "disable functions returning aggregate types", 0, 0 },
  /* -Wregister-param */
  { 1, 0, "-Wregister-param", "s1", &sema_option_warn_register_param,
    "issue warnings about `register' keyword in parameters", 0, 0 },

  { 0, 0, 0, 0, 0, 0, 0 }
};

int
main_sema_analyze(tree_t tree)
{
  sema_analyze(tree);
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
