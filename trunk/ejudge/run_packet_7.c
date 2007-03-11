/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005-2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "run_packet.h"
#include "run_packet_priv.h"

#include <reuse/xalloc.h>

#include <stdlib.h>

int
run_request_packet_quit(size_t *p_out_size, void **p_out_data)
{
  size_t out_size = sizeof(struct run_request_bin_packet);
  struct run_request_bin_packet *out_data = 0;

  out_size = pkt_bin_align(out_size);
  out_data = (struct run_request_bin_packet*) xcalloc(1, out_size);

  out_data->packet_len = cvt_host_to_bin_32(out_size);
  out_data->version = cvt_host_to_bin_32(1);
  out_data->contest_id = cvt_host_to_bin_32(-1);

  *p_out_size = out_size;
  *p_out_data = out_data;
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
