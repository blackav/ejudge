/* -*- mode: c -*- */

/* Copyright (C) 2008-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/opcaps.h"
#include "ejudge/compat.h"

#include <string.h>

extern const unsigned char * const opcaps_cap_list [];
extern const opcap_t OPCAP_OBSERVER_PERMS;
extern const opcap_t OPCAP_JUDGE_PERMS;
extern const opcap_t OPCAP_MASTER_PERMS;

void
opcaps_unparse_2(FILE *out_f, int left_margin, int max_width, opcap_t cap)
{
  int first_flag = 1;
  int cur_pos = 0, i, j;
  const unsigned char *perm_set = 0;

  // check, that capability set is a subset of predefined sets
  if (cap == (1ULL << OPCAP_LAST) - 1) {
    perm_set = "FULL_SET";
    cap &= ~((1ULL << OPCAP_LAST) - 1);
  } else if ((cap & OPCAP_MASTER_PERMS) == OPCAP_MASTER_PERMS) {
    perm_set = "MASTER_SET";
    cap &= ~OPCAP_MASTER_PERMS;
  } else if ((cap & OPCAP_JUDGE_PERMS) == OPCAP_JUDGE_PERMS) {
    perm_set = "JUDGE_SET";
    cap &= ~OPCAP_JUDGE_PERMS;
  } else if ((cap & OPCAP_OBSERVER_PERMS) == OPCAP_OBSERVER_PERMS) {
    perm_set = "OBSERVER_SET";
    cap &= ~OPCAP_OBSERVER_PERMS;
  }

  if (perm_set) {
    if (first_flag) {
      first_flag = 0;
      for (j = 0; j < left_margin; j++) putc(' ', out_f);
      cur_pos = left_margin;
    }
    fprintf(out_f, "%s,", perm_set);
    cur_pos += strlen(perm_set) + 1;
    if (cur_pos >= max_width) {
      fprintf(out_f, "\n");
      first_flag = 1;
    }
  }
  for (i = 0; i < OPCAP_LAST; i++) {
    if (!(cap & (1ULL << i))) continue;
    if (first_flag) {
      first_flag = 0;
      for (j = 0; j < left_margin; j++) putc(' ', out_f);
      cur_pos = left_margin;
    }
    fprintf(out_f, "%s,", opcaps_cap_list[i]);
    cur_pos += strlen(opcaps_cap_list[i]) + 1;
    if (cur_pos >= max_width) {
      fprintf(out_f, "\n");
      first_flag = 1;
    }
  }
  if (!first_flag) fprintf(out_f, "\n");
}

unsigned char *
opcaps_unparse(int left_margin, int max_width, opcap_t cap)
{
  char *out_str = 0;
  size_t out_len = 0;
  FILE *f;

  f = open_memstream(&out_str, &out_len);
  opcaps_unparse_2(f, left_margin, max_width, cap);
  close_memstream(f);
  return out_str;
}
