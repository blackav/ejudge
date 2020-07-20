/* -*- mode: c -*- */

/* Copyright (C) 2004-2017 Alexander Chernov <cher@ejudge.ru> */

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

#include "l10n_impl.h"

int checker_main(int argc, char **argv)
{
  char **out_lines, **corr_lines;
  size_t out_lines_num, corr_lines_num, i;
  int nocase = 0;

  checker_l10n_prepare();

  if (getenv("EJ_REQUIRE_NL")) {
    checker_require_nl(f_out, 1);
  }

  if (getenv("EJUDGE_NOCASE")) nocase = 1;

  checker_skip_bom(f_corr);
  checker_skip_bom(f_out);

  // считываем файл результата работы программы
  checker_read_file_by_line(1, &out_lines, &out_lines_num);
  // считываем эталонный файл
  checker_read_file_by_line(2, &corr_lines, &corr_lines_num);
  // убираем "лишние" пробелы в результате работы программы
  checker_normalize_spaces_in_file(out_lines, &out_lines_num);
  // убираем "лишние" пробелы в эталонном файле
  checker_normalize_spaces_in_file(corr_lines, &corr_lines_num);

  if (out_lines_num != corr_lines_num)
    fatal_WA(_("Different number of lines: output: %zu, correct: %zu"),
             out_lines_num, corr_lines_num);
  for (i = 0; i < out_lines_num; i++)
    if (nocase) {
      if (strcasecmp(out_lines[i], corr_lines[i]) != 0)
        fatal_WA(_("Line %zu differs: output:\n>%s<\ncorrect:\n>%s<"),
                 i + 1, out_lines[i], corr_lines[i]);
    } else {
      if (strcmp(out_lines[i], corr_lines[i]) != 0)
        fatal_WA(_("Line %zu differs: output:\n>%s<\ncorrect:\n>%s<"),
                 i + 1, out_lines[i], corr_lines[i]);
    }

  checker_OK();
}
