/* -*- c -*- */

/* Copyright (C) 2008-2018 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/runlog.h"
#include "ejudge/problem_common.h"
#include "ejudge/xml_utils.h"

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
    if (prob_type && prob_type != PROB_TYPE_TESTS) s = _("Wrong output format");
    else s = _("Presentation error");
    break;
  case RUN_WRONG_ANSWER_ERR: s = _("Wrong answer");        break;
  case RUN_CHECK_FAILED:     s = _("Check failed");        break;
  case RUN_PARTIAL:
    if (prob_type && !var_score && prob_type != PROB_TYPE_TESTS) {
      s = _("Wrong answer");
    } else {
      s = _("Partial solution");
    }
    break;
  case RUN_ACCEPTED:         s = _("Accepted for testing"); break;
  case RUN_IGNORED:          s = _("Ignored");             break;
  case RUN_DISQUALIFIED:     s = _("Disqualified");        break;
  case RUN_PENDING:          s = _("Pending check");       break;
  case RUN_MEM_LIMIT_ERR:    s = _("Memory limit exceeded"); break;
  case RUN_SECURITY_ERR:     s = _("Security violation");  break;
  case RUN_SYNC_ERR:         s = _("Synchronization error");  break;
  case RUN_STYLE_ERR:        s = _("Coding style violation"); break;
  case RUN_REJECTED:         s = _("Rejected"); break;
  case RUN_WALL_TIME_LIMIT_ERR: s = _("Wall time-limit exceeded"); break;
  case RUN_SKIPPED:          s = _("Skipped"); break;
  case RUN_PENDING_REVIEW:   s = _("Pending review");      break;
  case RUN_SUMMONED:         s = _("Summoned for defence");break;
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

static const unsigned char is_failed_attempt_table[RUN_STATUS_SIZE] =
{
  [RUN_RUN_TIME_ERR]     = 1,
  [RUN_TIME_LIMIT_ERR]   = 1,
  [RUN_WALL_TIME_LIMIT_ERR] = 1,
  [RUN_PRESENTATION_ERR] = 1,
  [RUN_WRONG_ANSWER_ERR] = 1,
  [RUN_MEM_LIMIT_ERR]    = 1,
  [RUN_SECURITY_ERR]     = 1,
  [RUN_SYNC_ERR]         = 1,
};
int
run_is_failed_attempt(int status)
{
  if (((unsigned) status) >= RUN_STATUS_SIZE) return 0;
  return is_failed_attempt_table[status];
}

static const unsigned char is_valid_test_status_table[RUN_STATUS_SIZE] =
{
  [RUN_OK]               = 1,
  [RUN_RUN_TIME_ERR]     = 1,
  [RUN_TIME_LIMIT_ERR]   = 1,
  [RUN_WALL_TIME_LIMIT_ERR] = 1,
  [RUN_PRESENTATION_ERR] = 1,
  [RUN_WRONG_ANSWER_ERR] = 1,
  [RUN_MEM_LIMIT_ERR]    = 1,
  [RUN_SECURITY_ERR]     = 1,
  [RUN_SYNC_ERR]         = 1,
  [RUN_CHECK_FAILED]     = 1,
  [RUN_SKIPPED]          = 1,
};
int
run_is_valid_test_status(int status)
{
  if (((unsigned) status)  >= RUN_STATUS_SIZE) return 0;
  return is_valid_test_status_table[status];
}

static const unsigned char is_team_report_available_table[RUN_STATUS_SIZE] =
{
  [RUN_OK]               = 1,
  [RUN_COMPILE_ERR]      = 1,
  [RUN_RUN_TIME_ERR]     = 1,
  [RUN_TIME_LIMIT_ERR]   = 1,
  [RUN_WALL_TIME_LIMIT_ERR] = 1,
  [RUN_PRESENTATION_ERR] = 1,
  [RUN_WRONG_ANSWER_ERR] = 1,
  [RUN_PARTIAL]          = 1,
  [RUN_ACCEPTED]         = 1,
  [RUN_PENDING_REVIEW]   = 1,
  [RUN_SUMMONED]         = 1,
  [RUN_MEM_LIMIT_ERR]    = 1,
  [RUN_SECURITY_ERR]     = 1,
  [RUN_SYNC_ERR]         = 1,
  [RUN_STYLE_ERR]        = 1,
  [RUN_REJECTED]         = 1,
};
int
run_is_team_report_available(int status)
{
  if (((unsigned) status) >= RUN_STATUS_SIZE) return 0;
  return is_team_report_available_table[status];
}

static const unsigned char is_report_available_table[RUN_STATUS_SIZE] =
{
  [RUN_OK]               = 1,
  [RUN_COMPILE_ERR]      = 1,
  [RUN_RUN_TIME_ERR]     = 1,
  [RUN_TIME_LIMIT_ERR]   = 1,
  [RUN_WALL_TIME_LIMIT_ERR] = 1,
  [RUN_PRESENTATION_ERR] = 1,
  [RUN_WRONG_ANSWER_ERR] = 1,
  [RUN_CHECK_FAILED]     = 1,
  [RUN_PARTIAL]          = 1,
  [RUN_ACCEPTED]         = 1,
  [RUN_PENDING_REVIEW]   = 1,
  [RUN_SUMMONED]         = 1,
  [RUN_MEM_LIMIT_ERR]    = 1,
  [RUN_SECURITY_ERR]     = 1,
  [RUN_SYNC_ERR]         = 1,
  [RUN_STYLE_ERR]        = 1,
  [RUN_REJECTED]         = 1,
};
int
run_is_report_available(int status)
{
  if (((unsigned) status) >= RUN_STATUS_SIZE) return 0;
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
  { "SY", RUN_SYNC_ERR },
  { "SV", RUN_STYLE_ERR },
  { "WT", RUN_WALL_TIME_LIMIT_ERR },
  { "PR", RUN_PENDING_REVIEW },
  { "SM", RUN_SUMMONED },
  { "RJ", RUN_REJECTED },
  { "SK", RUN_SKIPPED },
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

static const unsigned char run_valid_statuses[RUN_STATUS_SIZE] =
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
  [RUN_SYNC_ERR]         = 1,
  [RUN_STYLE_ERR]        = 1,
  [RUN_WALL_TIME_LIMIT_ERR] = 1,
  [RUN_PENDING_REVIEW]   = 1,
  [RUN_SUMMONED]         = 1,
  [RUN_REJECTED]         = 1,
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
  if (((unsigned) status) >= RUN_STATUS_SIZE) return 0;
  return run_valid_statuses[status];
}

static const unsigned char run_valid_user_statuses[RUN_STATUS_SIZE] =
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
  [RUN_SYNC_ERR]         = 1,
  [RUN_STYLE_ERR]        = 1,
  [RUN_WALL_TIME_LIMIT_ERR] = 1,
  [RUN_PENDING_REVIEW]   = 1,
  [RUN_SUMMONED]         = 1,
  [RUN_REJECTED]         = 1,
  [RUN_RUNNING]          = 1,
  [RUN_COMPILED]         = 1,
  [RUN_COMPILING]        = 1,
  [RUN_AVAILABLE]        = 1,
};
int
run_is_valid_user_status(int status)
{
  if (((unsigned) status) >= RUN_STATUS_SIZE) return 0;
  return run_valid_user_statuses[status];
}

static const unsigned char run_source_available_statuses[RUN_STATUS_SIZE] =
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
  [RUN_SYNC_ERR]         = 1,
  [RUN_STYLE_ERR]        = 1,
  [RUN_WALL_TIME_LIMIT_ERR] = 1,
  [RUN_PENDING_REVIEW]   = 1,
  [RUN_SUMMONED]         = 1,
  [RUN_REJECTED]         = 1,
  [RUN_RUNNING]          = 1,
  [RUN_COMPILED]         = 1,
  [RUN_COMPILING]        = 1,
  [RUN_AVAILABLE]        = 1,
};
int
run_is_source_available(int status)
{
  if (((unsigned) status) >= RUN_STATUS_SIZE) return 0;
  return run_source_available_statuses[status];
}

int
run_fix_runlog_time(
        FILE *log_f,
        int run_f,
        int run_u,
        struct run_entry *runs,
        unsigned char *fix_mask)
{
  int run_id = run_f + 1, run_id2;
  time_t cur_time, prev_time = 0, new_time;
  //struct tm prev_tm, cur_tm;

  if (run_u <= 0 || !runs) return 0;
  if (!log_f) log_f = stderr;

  if (fix_mask) {
    memset(fix_mask, 0, run_u);
  }
  prev_time = runs[0].time;

  while (run_id < run_u) {
    if (runs[run_id - run_f].status == RUN_EMPTY) {
      ++run_id;
      continue;
    }

    if (runs[run_id - run_f].time >= prev_time) {
      prev_time = runs[run_id - run_f].time;
      ++run_id;
      continue;
    }

    // check that we have the DST problem
    cur_time = (time_t) runs[run_id - run_f].time;

    if (prev_time >= cur_time + 3600) {
      fprintf(log_f, "Error: timestamp for run %d: %ld (%s); ",
              run_id - 1, (long) prev_time, xml_unparse_date(prev_time));
      fprintf(log_f, "timestamp for run %d: %ld (%s); ",
              run_id, (long) cur_time, xml_unparse_date(cur_time));
      fprintf(log_f, "no DST change detected\n");
      return -1;
    }

/*
    cur_time += 3600;
    memset(&prev_tm, 0, sizeof(prev_tm));
    memset(&cur_tm, 0, sizeof(cur_tm));
    prev_tm.tm_isdst = -1;
    cur_tm.tm_isdst = -1;
    localtime_r(&prev_time, &prev_tm);
    localtime_r(&cur_time, &cur_tm);
    if (prev_tm.tm_isdst == cur_tm.tm_isdst) {
      fprintf(log_f, "Error: timestamp for run %d: %ld (%s); ",
              run_id - 1, prev_time, xml_unparse_date(prev_time));
      fprintf(log_f, "timestamp for run %d: %ld (%s); ",
              run_id, cur_time, xml_unparse_date(cur_time));
      fprintf(log_f, "no DST change detected\n");
      fprintf(log_f, "Error: ignoring this error for now...\n");
      prev_time = 0;
      ++run_id;
      continue;
    }
*/

    fprintf(log_f, "Warning: timestamp for run %d: %ld (%s); ",
            run_id - 1, (long) prev_time, xml_unparse_date(prev_time));
    fprintf(log_f, "timestamp for run %d: %ld (%s); ",
            run_id, (long) cur_time, xml_unparse_date(cur_time));
    fprintf(log_f, "DST change detected, fixing\n");

    // find how many runs need fixing
    new_time = prev_time + 1;
    run_id2 = run_id;
    while (run_id2 < run_u - 1 && new_time > runs[run_id2 + 1 - run_f].time) {
      ++new_time;
      ++run_id2;
    }

    fprintf(log_f, "Warning: runs %d-%d to be fixed\n", run_id, run_id2);
    for (new_time = prev_time + 1; run_id <= run_id2; ++run_id, ++new_time) {
      runs[run_id - run_f].time = new_time;
      if (fix_mask) {
        fix_mask[run_id - run_f] = 1;
      }
    }
    prev_time = 0;
  }

  return 0;

}

void
run_entry_to_ipv6(const struct run_entry *p_re, ej_ip_t *p_ip)
{
  memset(p_ip, 0, sizeof(*p_ip));
  if (p_re->ipv6_flag) {
    p_ip->ipv6_flag = 1;
    memcpy(p_ip->u.v6.addr, p_re->a.ipv6, sizeof(p_ip->u.v6.addr));
  } else {
    p_ip->u.v4.addr = p_re->a.ip;
  }
}

void
ipv6_to_run_entry(const ej_ip_t *p_ip, struct run_entry *p_re)
{
  p_re->ipv6_flag = 0;
  memset(&p_re->a, 0, sizeof(p_re->a));
  if (!p_ip) return;
  if (p_ip->ipv6_flag) {
    p_re->ipv6_flag = 1;
    memcpy(p_re->a.ipv6, p_ip->u.v6.addr, sizeof(p_re->a.ipv6));
  } else {
    p_re->a.ip = p_ip->u.v4.addr;
  }
}

static const unsigned char * const status_short_str[] =
{
  [RUN_OK] = "OK",
  [RUN_COMPILE_ERR] = "CE",
  [RUN_RUN_TIME_ERR] = "RT",
  [RUN_TIME_LIMIT_ERR] = "TL",
  [RUN_PRESENTATION_ERR] = "PE",
  [RUN_WRONG_ANSWER_ERR] = "WA",
  [RUN_CHECK_FAILED] = "CF",
  [RUN_PARTIAL] = "PT",
  [RUN_ACCEPTED] = "AC",
  [RUN_IGNORED] = "IG",
  [RUN_DISQUALIFIED] = "DQ",
  [RUN_PENDING] = "PD",
  [RUN_MEM_LIMIT_ERR] = "ML",
  [RUN_SECURITY_ERR] = "SE",
  [RUN_SYNC_ERR] = "SY",
  [RUN_STYLE_ERR] = "SV",
  [RUN_WALL_TIME_LIMIT_ERR] = "WT",
  [RUN_PENDING_REVIEW] = "PR",
  [RUN_SUMMONED] = "SM",
  [RUN_REJECTED] = "RJ",
  [RUN_SKIPPED] = "SK",
  [RUN_RUNNING ] = "RU",
  [RUN_COMPILED] = "CD",
  [RUN_COMPILING] = "CG",
  [RUN_AVAILABLE] = "AV",
  [RUN_EMPTY] = "EM",
  [RUN_VIRTUAL_START] = "VS",
  [RUN_VIRTUAL_STOP] = "VT",
};

const unsigned char *
run_status_short_str(int status)
{
  if (status < 0 || status >= sizeof(status_short_str) / sizeof(status_short_str[0]) || !status_short_str[status]) {
    static unsigned char buf[64];
    snprintf(buf, sizeof(buf), "%d", status);
    return buf;
  }
  return status_short_str[status];
}
