/* -*- c -*- */
/* $Id$ */
#ifndef __NCHECK_PACKET_H__
#define __NCHECK_PACKET_H__

/* Copyright (C) 2010-2014 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include "ejudge/parsecfg.h"

#ifndef EJ_PATH_MAX
#define EJ_PATH_MAX 4096
#endif

struct ncheck_in_packet
{
  struct generic_section_config g;

  /* testing priority */
  int priority;
  int contest_id;
  int run_id;
  int prob_id;
  int test_num;
  int judge_id;
  int use_contest_id_in_reply;
  int type;
};

struct ncheck_out_packet
{
  struct generic_section_config g;
};

struct generic_section_config *
ncheck_in_packet_parse(const unsigned char *path, struct ncheck_in_packet **pkt);
struct generic_section_config *
ncheck_in_packet_free(struct generic_section_config *config);

struct generic_section_config *
ncheck_out_packet_parse(const unsigned char*path,struct ncheck_out_packet**pkt);
struct generic_section_config *
ncheck_out_packet_free(struct generic_section_config *config);
void
ncheck_out_packet_print(FILE *fout, const struct ncheck_out_packet *result);

#endif /* __NCHECK_PACKET_H__ */
