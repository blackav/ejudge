/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2010-2013 Alexander Chernov <cher@ejudge.ru> */

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

#include "l10n_impl.h"

void
valuer_parse_input(
        int *p_test_count,
        struct valuer_test_info **p_infos)
{
  int test_count = 0, v1, v2, v3, i;
  struct valuer_test_info *infos = 0;

  if (scanf("%d", &test_count) != 1) {
    fatal_CF(_("Cannot read test count"));
  }
  if (test_count <= 0 || test_count > 1000) {
    fatal_CF(_("Test count (%d) is invalid"), test_count);
  }
  XCALLOC(infos, test_count);

  for (i = 0; i < test_count; ++i) {
    if (scanf("%d%d%d", &v1, &v2, &v3) != 3)
      fatal_CF(_("Cannot read test description %d"), i + 1);
    if (v1 < 0 || v1 >= RUN_MAX_STATUS)
      fatal_CF(_("Invalid result %d in description %d"), v1, i + 1);
    if (v2 < 0 || v2 > 999999)
      fatal_CF(_("Invalid score %d in description %d"), v2, i + 1);
    if (v3 < 0)
      fatal_CF(_("Invalid time %d in description %d"), v3, i + 1);
    infos[i].result = v1;
    infos[i].score = v2;
    infos[i].time_ms = v3;
  }

  *p_test_count = test_count;
  *p_infos = infos;
}
