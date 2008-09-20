/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"

#include "runlog.h"

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

char *
run_status_str(
        int status,
        char *out,
        int len,
        int prob_type,
        int var_score)
{
  static char  buf[128];
  char const  *s;

  switch (status) {
  case RUN_OK:               s = _("OK");                  break;
  case RUN_COMPILE_ERR:      s = _("Compilation error");   break;
  case RUN_RUN_TIME_ERR:     s = _("Run-time error");      break;
  case RUN_TIME_LIMIT_ERR:   s = _("Time-limit exceeded"); break;
  case RUN_PRESENTATION_ERR:
    if (prob_type) s = _("Wrong output format");
    else s = _("Presentation error");
    break;
  case RUN_WRONG_ANSWER_ERR: s = _("Wrong answer");        break;
  case RUN_CHECK_FAILED:     s = _("Check failed");        break;
  case RUN_PARTIAL:
    if (prob_type && !var_score) s = _("Wrong answer");
    else s = _("Partial solution");
    break;
  case RUN_ACCEPTED:         s = _("Accepted for testing"); break;
  case RUN_IGNORED:          s = _("Ignored");             break;
  case RUN_DISQUALIFIED:     s = _("Disqualified");        break;
  case RUN_PENDING:          s = _("Pending check");       break;
  case RUN_MEM_LIMIT_ERR:    s = _("Memory limit exceeded"); break;
  case RUN_SECURITY_ERR:     s = _("Security violation");  break;
  case RUN_RUNNING:          s = _("Running...");          break;
  case RUN_COMPILED:         s = _("Compiled");            break;
  case RUN_COMPILING:        s = _("Compiling...");        break;
  case RUN_AVAILABLE:        s = _("Available");           break;
  case RUN_VIRTUAL_START:    s = _("Virtual start");       break;
  case RUN_VIRTUAL_STOP:     s = _("Virtual stop");        break;
  case RUN_EMPTY:            s = _("EMPTY");               break;
  default:
    sprintf(buf, _("Unknown: %d"), status);
    s = buf;
    break;
  }
  if (!out) return (char*) s;
  if (len <= 0) return strcpy(out, s);
  snprintf(out, len, "%s", s);
  return out;
}

static const unsigned char is_failed_attempt_table[RUN_LAST + 1] =
{
  [RUN_RUN_TIME_ERR]     = 1,
  [RUN_TIME_LIMIT_ERR]   = 1,
  [RUN_PRESENTATION_ERR] = 1,
  [RUN_WRONG_ANSWER_ERR] = 1,
  [RUN_MEM_LIMIT_ERR]    = 1,
  [RUN_SECURITY_ERR]     = 1,
};
int
run_is_failed_attempt(int status)
{
  if (status < 0 || status > RUN_LAST) return 0;
  return is_failed_attempt_table[status];
}

static const unsigned char is_valid_test_status_table[RUN_LAST + 1] =
{
  [RUN_OK]               = 1,
  [RUN_RUN_TIME_ERR]     = 1,
  [RUN_TIME_LIMIT_ERR]   = 1,
  [RUN_PRESENTATION_ERR] = 1,
  [RUN_WRONG_ANSWER_ERR] = 1,
  [RUN_MEM_LIMIT_ERR]    = 1,
  [RUN_SECURITY_ERR]     = 1,
  [RUN_CHECK_FAILED]     = 1,
};
int
run_is_valid_test_status(int status)
{
  if (status < 0 || status > RUN_LAST) return 0;
  return is_valid_test_status_table[status];
}

static const unsigned char is_team_report_available_table[RUN_LAST + 1] =
{
  [RUN_OK]               = 1,
  [RUN_COMPILE_ERR]      = 1,
  [RUN_RUN_TIME_ERR]     = 1,
  [RUN_TIME_LIMIT_ERR]   = 1,
  [RUN_PRESENTATION_ERR] = 1,
  [RUN_WRONG_ANSWER_ERR] = 1,
  [RUN_PARTIAL]          = 1,
  [RUN_ACCEPTED]         = 1,
  [RUN_MEM_LIMIT_ERR]    = 1,
  [RUN_SECURITY_ERR]     = 1,

};
int
run_is_team_report_available(int status)
{
  if (status < 0 || status > RUN_LAST) return 0;
  return is_team_report_available_table[status];
}

static const unsigned char is_report_available_table[RUN_LAST + 1] =
{
  [RUN_OK]               = 1,
  [RUN_COMPILE_ERR]      = 1,
  [RUN_RUN_TIME_ERR]     = 1,
  [RUN_TIME_LIMIT_ERR]   = 1,
  [RUN_PRESENTATION_ERR] = 1,
  [RUN_WRONG_ANSWER_ERR] = 1,
  [RUN_CHECK_FAILED]     = 1,
  [RUN_PARTIAL]          = 1,
  [RUN_ACCEPTED]         = 1,
  [RUN_MEM_LIMIT_ERR]    = 1,
  [RUN_SECURITY_ERR]     = 1,

};
int
run_is_report_available(int status)
{
  if (status < 0 || status > RUN_LAST) return 0;
  return is_report_available_table[status];
}

/*
 * the set of status strings is as follows:
    OK CE RT TL PE WA CF PT AC IG DQ PD ML SE RU CD CG AV RJ EM VS VT
   for now we use a dumb linear search :-(
 */
struct str_to_status_data
{
  unsigned char str[4];
  int value;
};
static const struct str_to_status_data str_to_status_table[] =
{
  { "OK", RUN_OK },
  { "CE", RUN_COMPILE_ERR },
  { "RT", RUN_RUN_TIME_ERR },
  { "TL", RUN_TIME_LIMIT_ERR },
  { "PE", RUN_PRESENTATION_ERR },
  { "WA", RUN_WRONG_ANSWER_ERR },
  { "CF", RUN_CHECK_FAILED },
  { "PT", RUN_PARTIAL },
  { "AC", RUN_ACCEPTED },
  { "IG", RUN_IGNORED },
  { "DQ", RUN_DISQUALIFIED },
  { "PD", RUN_PENDING },
  { "ML", RUN_MEM_LIMIT_ERR },
  { "SE", RUN_SECURITY_ERR },
  { "RU", RUN_RUNNING },
  { "CD", RUN_COMPILED },
  { "CG", RUN_COMPILING },
  { "AV", RUN_AVAILABLE },
  { "RJ", RUN_REJUDGE },
  { "EM", RUN_EMPTY },
  { "VS", RUN_VIRTUAL_START },
  { "VT", RUN_VIRTUAL_STOP },
  { "", -1 },
};
int
run_str_short_to_status(const unsigned char *str, int *pr)
{
  int i;

  for (i = 0; str_to_status_table[i].str[0]; i++)
    if (!strcasecmp(str, str_to_status_table[i].str)) {
      if (pr) *pr = str_to_status_table[i].value;
      return str_to_status_table[i].value;
    }
  return -1;
}

static const unsigned char run_valid_statuses[RUN_LAST + 1] = 
{
  [RUN_OK]               = 1,
  [RUN_COMPILE_ERR]      = 1,
  [RUN_RUN_TIME_ERR]     = 1,
  [RUN_TIME_LIMIT_ERR]   = 1,
  [RUN_PRESENTATION_ERR] = 1,
  [RUN_WRONG_ANSWER_ERR] = 1,
  [RUN_CHECK_FAILED]     = 1,
  [RUN_PARTIAL]          = 1,
  [RUN_ACCEPTED]         = 1,
  [RUN_IGNORED]          = 1,
  [RUN_DISQUALIFIED]     = 1,
  [RUN_PENDING]          = 1,
  [RUN_MEM_LIMIT_ERR]    = 1,
  [RUN_SECURITY_ERR]     = 1,
  [RUN_VIRTUAL_START]    = 1,
  [RUN_VIRTUAL_STOP]     = 1,
  [RUN_EMPTY]            = 1,
  [RUN_RUNNING]          = 1,
  [RUN_COMPILED]         = 1,
  [RUN_COMPILING]        = 1,
  [RUN_AVAILABLE]        = 1,
};
int
run_is_valid_status(int status)
{
  if (status < 0 || status > RUN_LAST) return 0;
  return run_valid_statuses[status];
}

static const unsigned char run_valid_user_statuses[RUN_LAST + 1] = 
{
  [RUN_OK]               = 1,
  [RUN_COMPILE_ERR]      = 1,
  [RUN_RUN_TIME_ERR]     = 1,
  [RUN_TIME_LIMIT_ERR]   = 1,
  [RUN_PRESENTATION_ERR] = 1,
  [RUN_WRONG_ANSWER_ERR] = 1,
  [RUN_CHECK_FAILED]     = 1,
  [RUN_PARTIAL]          = 1,
  [RUN_ACCEPTED]         = 1,
  [RUN_IGNORED]          = 1,
  [RUN_DISQUALIFIED]     = 1,
  [RUN_PENDING]          = 1,
  [RUN_MEM_LIMIT_ERR]    = 1,
  [RUN_SECURITY_ERR]     = 1,
  [RUN_RUNNING]          = 1,
  [RUN_COMPILED]         = 1,
  [RUN_COMPILING]        = 1,
  [RUN_AVAILABLE]        = 1,
};
int
run_is_valid_user_status(int status)
{
  if (status < 0 || status > RUN_LAST) return 0;
  return run_valid_user_statuses[status];
}

static const unsigned char run_source_available_statuses[RUN_LAST + 1] = 
{
  [RUN_OK]               = 1,
  [RUN_COMPILE_ERR]      = 1,
  [RUN_RUN_TIME_ERR]     = 1,
  [RUN_TIME_LIMIT_ERR]   = 1,
  [RUN_PRESENTATION_ERR] = 1,
  [RUN_WRONG_ANSWER_ERR] = 1,
  [RUN_CHECK_FAILED]     = 1,
  [RUN_PARTIAL]          = 1,
  [RUN_ACCEPTED]         = 1,
  [RUN_IGNORED]          = 1,
  [RUN_DISQUALIFIED]     = 1,
  [RUN_PENDING]          = 1,
  [RUN_MEM_LIMIT_ERR]    = 1,
  [RUN_SECURITY_ERR]     = 1,
  [RUN_RUNNING]          = 1,
  [RUN_COMPILED]         = 1,
  [RUN_COMPILING]        = 1,
  [RUN_AVAILABLE]        = 1,
};
int
run_is_source_available(int status)
{
  if (status < 0 || status > RUN_LAST) return 0;
  return run_source_available_statuses[status];
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "DIR" "gzFile")
 * End:
 */
