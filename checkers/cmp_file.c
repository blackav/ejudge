/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004-2006 Alexander Chernov <cher@ejudge.ru> */

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
  char **out_lines, **corr_lines;
  size_t out_lines_num, corr_lines_num, i;

  // считываем файл результата работы программы
  checker_read_file_by_line(1, &out_lines, &out_lines_num);
  // считываем эталонный файл
  checker_read_file_by_line(2, &corr_lines, &corr_lines_num);
  // отбрасываем пробелы в результате работы программы
  checker_normalize_file(out_lines, &out_lines_num);
  // отбрасываем пробелы в эталонном файле
  checker_normalize_file(corr_lines, &corr_lines_num);

  if (out_lines_num != corr_lines_num)
    fatal_WA("Different number of lines: out = %zu, corr = %zu",
             out_lines_num, corr_lines_num);
  for (i = 0; i < out_lines_num; i++)
    if (strcmp(out_lines[i], corr_lines[i]) != 0)
      fatal_WA("Line %zu differs: out:\n>%s<\ncorr:\n>%s<",
               i + 1, out_lines[i], corr_lines[i]);
  
  checker_OK();
}

/*
 * Local variables:
 *  compile-command: "gcc -Wall -O2 -s -I. -L. cmp_file.c -ocmp_file -lchecker"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
