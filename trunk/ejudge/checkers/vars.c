/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003 Alexander Chernov <cher@ispras.ru> */

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
#include <dirent.h>

FILE *f_in;
FILE *f_team;
FILE *f_corr;
FILE *f_arr[3];

DIR *dir_in;
DIR *dir_out;

unsigned char *dir_in_path;
unsigned char *dir_out_path;

const unsigned char * const f_arr_names[3] =
{
  "input",
  "team output",
  "correct output"
};

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
