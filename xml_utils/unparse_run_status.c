/* -*- c -*- */

/* Copyright (C) 2005-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/xml_utils.h"
#include "ejudge/runlog.h"

#include <string.h>

static const unsigned char tree_result_strs[RUN_STATUS_SIZE][4] =
{
  [RUN_OK] =               "OK",
  [RUN_COMPILE_ERR] =      "CE",
  [RUN_RUN_TIME_ERR] =     "RT",
  [RUN_TIME_LIMIT_ERR] =   "TL",
  [RUN_PRESENTATION_ERR] = "PE",
  [RUN_WRONG_ANSWER_ERR] = "WA",
  [RUN_CHECK_FAILED] =     "CF",
  [RUN_PARTIAL] =          "PT",
  [RUN_ACCEPTED] =         "AC",
  [RUN_IGNORED] =          "IG",
  [RUN_DISQUALIFIED] =     "DQ",
  [RUN_PENDING] =          "PD",
  [RUN_MEM_LIMIT_ERR] =    "ML",
  [RUN_SECURITY_ERR] =     "SE",
  [RUN_SYNC_ERR] =         "SY",
  [RUN_STYLE_ERR] =        "SV",
  [RUN_WALL_TIME_LIMIT_ERR] = "WT",
  [RUN_PENDING_REVIEW] =   "PR",
  [RUN_SUMMONED] =         "SM",
  [RUN_SKIPPED] =          "SK",
  [RUN_REJECTED] =         "RJ",
  [RUN_VIRTUAL_START] =    "VS",
  [RUN_VIRTUAL_STOP] =     "VT",
  [RUN_EMPTY] =            "EM",
  [RUN_RUNNING] =          "RU",
  [RUN_COMPILED] =         "CD",
  [RUN_COMPILING] =        "CG",
  [RUN_AVAILABLE] =        "AV",
};

int
run_status_to_str_short(unsigned char *buf, size_t size, int val)
{
  if (((unsigned) val) < RUN_STATUS_SIZE /*&& tree_result_strs[val]*/) {
    return snprintf(buf, size, "%s", tree_result_strs[val]);
  }
  return snprintf(buf, size, "result_%d", val);
}
