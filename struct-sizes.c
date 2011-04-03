/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2007-2010 Alexander Chernov <cher@ejudge.ru> */

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

#include "ej_types.h"
#include "config.h"

#include "protocol.h"
#include "runlog.h"
#include "clarlog.h"
#include "prepare.h"
#include "super-serve.h"
#include "compile_packet_priv.h"

#include <stdio.h>

int main(void)
{
  printf("prot_serve_status_v2:  %zu\n", sizeof(struct prot_serve_status_v2));
  printf("run_header:            %zu\n", sizeof(struct run_header));
  printf("run_entry:             %zu\n", sizeof(struct run_entry));
  printf("clar_entry_v1:         %zu\n", sizeof(struct clar_entry_v1));
  printf("section_global_data:   %zu\n", sizeof(struct section_global_data));
  printf("section_problem_data:  %zu\n", sizeof(struct section_problem_data));
  printf("section_language_data: %zu\n", sizeof(struct section_language_data));
  printf("section_tester_data:   %zu\n", sizeof(struct section_tester_data));
  printf("sid_state:             %zu\n", sizeof(struct sid_state));
  printf("compile_packet:        %zu\n", sizeof(struct compile_request_bin_packet));
  return 0;
}
