/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005-2012 Alexander Chernov <cher@ejudge.ru> */

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

#define INCLUDE_RUN_REQUEST 1

#include "run_packet.h"
#include "run_packet_priv.h"
#include "pathutl.h"
#include "prepare.h"
#include "runlog.h"

#include "reuse_xalloc.h"
#include "reuse_logger.h"
#include "reuse_integral.h"

#include <stdlib.h>
#include <string.h>

struct run_request_packet *
run_request_packet_free(struct run_request_packet *in_data)
{
  if (!in_data) return 0;

  xfree(in_data->exe_sfx);
  xfree(in_data->arch);
  xfree(in_data->user_spelling);
  xfree(in_data->prob_spelling);
  xfree(in_data);
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
