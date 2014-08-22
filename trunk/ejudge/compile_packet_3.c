/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/compile_packet.h"
#include "ejudge/compile_packet_priv.h"
#include "ejudge/pathutl.h"
#include "ejudge/prepare.h"
#include "ejudge/runlog.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/integral.h"

#include <stdlib.h>
#include <string.h>

struct compile_request_packet *
compile_request_packet_free(struct compile_request_packet *in_data)
{
  int i;

  if (!in_data) return 0;
  if (in_data->run_block_len > 0) xfree(in_data->run_block);
  xfree(in_data->style_checker);
  xfree(in_data->src_sfx);
  if (in_data->env_num > 0 && in_data->env_vars) {
    for (i = 0; i < in_data->env_num; i++) {
      xfree(in_data->env_vars[i]);
      in_data->env_vars[i] = 0;
    }
    xfree(in_data->env_vars);
  }
  memset(in_data, 0, sizeof(*in_data));
  xfree(in_data);
  return 0;
}
