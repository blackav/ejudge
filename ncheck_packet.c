/* -*- c -*- */

/* Copyright (C) 2010-2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/ej_limits.h"
#include "ejudge/version.h"
#include "ejudge/ncheck_packet.h"
#include "ejudge/parsecfg.h"

#include "ejudge/xalloc.h"

#define XFSIZE(t, x) (sizeof(((t*) 0)->x))

#define NCHECK_IN_OFFSET(x)   XOFFSET(struct ncheck_in_packet, x)
#define NCHECK_IN_SIZE(x)     XFSIZE(struct ncheck_in_packet, x)
#define NCHECK_IN_PARAM(x, t) { #x, t, NCHECK_IN_OFFSET(x), NCHECK_IN_SIZE(x) }

static const struct config_parse_info ncheck_in_params[] =
{
  NCHECK_IN_PARAM(priority, "d"),
  NCHECK_IN_PARAM(contest_id, "d"),
  NCHECK_IN_PARAM(run_id, "d"),
  NCHECK_IN_PARAM(prob_id, "d"),
  NCHECK_IN_PARAM(test_num, "d"),
  NCHECK_IN_PARAM(judge_id, "d"),
  NCHECK_IN_PARAM(use_contest_id_in_reply, "d"),
  NCHECK_IN_PARAM(type, "d"),
};
static const struct config_section_info ncheck_in_config[] __attribute__((unused)) =
{
  { "global", sizeof(struct ncheck_in_packet), ncheck_in_params, 0, 0, 0 },
  { NULL, 0, NULL }
};

#define NCHECK_OUT_OFFSET(x)   XOFFSET(struct nwrun_out_packet, x)
#define NCHECK_OUT_SIZE(x)     XFSIZE(struct nwrun_out_packet, x)
#define NCHECK_OUT_PARAM(x, t) { #x,t,NCHECK_OUT_OFFSET(x),NCHECK_OUT_SIZE(x) }

static const struct config_parse_info ncheck_out_params[] =
{
};
static const struct config_section_info ncheck_out_config[] __attribute__((unused)) =
{
  { "global", sizeof(struct ncheck_out_packet), ncheck_out_params, 0, 0, 0 },
  { NULL, 0, NULL }
};
