/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2002 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "runlog.h"

#include "pathutl.h"
#include "unix/unix_fileutl.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

#define RUN_RECORD_SIZE 105
#define RUN_HEADER_SIZE 105

struct run_header
{
  unsigned long start_time;
  unsigned long sched_time;
  unsigned long duration;
  unsigned long stop_time;
};

struct run_entry
{
  unsigned long  timestamp;
  int            submission;
  unsigned long  size;
  int            locale_id;
  int            team;
  int            language;
  int            problem;
  int            status;
  int            test;
  int            score;
  char           ip[RUN_MAX_IP_LEN + 1];
};

static struct run_header  head;
static struct run_entry  *runs;
static int                run_u;
static int                run_a;
static int                run_fd = -1;

#define ERR_R(t, args...) do { do_err_r(__FUNCTION__ , t , ##args); return -1; } while (0)
#define ERR_C(t, args...) do { do_err_r(__FUNCTION__ , t , ##args); goto _cleanup; } while (0)

static int
run_read_record(char *buf, int size)
{
  int  rsz;
  int  i;

  if ((rsz = sf_read(run_fd, buf, size, "run")) < 0) return -1;
  if (rsz != size) ERR_R("short read: %d", rsz);
  for (i = 0; i < size - 1; i++) {
    if (buf[i] >= 0 && buf[i] < ' ') break;
  }
  if (i < size - 1) ERR_R("bad characters in record");
  if (buf[size - 1] != '\n') ERR_R("record improperly terminated");
  return 0;
}

static int
run_read_header(void)
{
  char buf[RUN_HEADER_SIZE + 16];
  int  n, r;

  memset(buf, 0, sizeof(buf));
  if (run_read_record(buf, RUN_HEADER_SIZE) < 0) return -1;
  r = sscanf(buf, " %lu %lu %lu %lu %n",
             &head.start_time,
             &head.sched_time,
             &head.duration,
             &head.stop_time, &n);
  if (r != 4) ERR_R("sscanf returned %d", r);
  if (buf[n] != 0) ERR_R("excess data: %d", n);
  return 0;
}

static int
run_read_entry(int n)
{
  char buf[RUN_RECORD_SIZE + 16];
  char tip[RUN_RECORD_SIZE + 16];
  int  k, r;

  memset(buf, 0, sizeof(buf));
  if (run_read_record(buf, RUN_RECORD_SIZE) < 0) return -1;
  r = sscanf(buf, " %lu %d %lu %d %d %d %d %d %d %d %s %n",
             &runs[n].timestamp, &runs[n].submission, &runs[n].size,
             &runs[n].locale_id,
             &runs[n].team, &runs[n].language, &runs[n].problem,
             &runs[n].status, &runs[n].test, &runs[n].score, tip, &k);
  if (r != 11) ERR_R("[%d]: sscanf returned %d", n, r);
  if (buf[k] != 0) ERR_R("[%d]: excess data", n);
  if (strlen(tip) > RUN_MAX_IP_LEN) ERR_R("[%d]: ip is to long", n);

  strcpy(runs[n].ip, tip);
  return 0;
}

int
run_open(char *path, int flags)
{
  int           oflags = 0;
  unsigned long filesize;
  int           i;

  if (runs) {
    xfree(runs); runs = 0; run_u = run_a = 0;
  }
  if (run_fd >= 0) {
    close(run_fd);
    run_fd = -1;
  }
  if (flags == RUN_LOG_CREATE) {
    oflags = O_RDWR | O_CREAT | O_TRUNC;
  } else {
    oflags = O_RDWR | O_CREAT;
  }
  if ((run_fd = sf_open(path, oflags, 0666)) < 0) return -1;

  /* calculate the size of the file */
  if ((filesize = sf_lseek(run_fd, 0, SEEK_END, "run")) == (off_t) -1)
    return -1;
  if (sf_lseek(run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;

  info("runs file size: %lu", filesize);
  if (filesize == 0) {
    /* runs file is empty */
    XMEMZERO(&head, 1);
    run_u = 0;
    return 0;
  }

  if ((filesize - RUN_HEADER_SIZE) % RUN_RECORD_SIZE != 0)
    ERR_C("bad runs file size: remainder %d", (filesize - RUN_HEADER_SIZE) % RUN_RECORD_SIZE);

  run_u = (filesize - RUN_HEADER_SIZE) / RUN_RECORD_SIZE;
  run_a = 128;
  while (run_u > run_a) run_a *= 2;
  XCALLOC(runs, run_a);

  if (run_read_header() < 0) goto _cleanup;
  for (i = 0; i < run_u; i++) {
    if (run_read_entry(i) < 0) goto _cleanup;
  }

  return 0;

 _cleanup:
  XMEMZERO(&head, 1);
  if (runs) {
    xfree(runs); runs = 0; run_u = run_a = 0;
  }
  if (run_fd >= 0) {
    close(run_fd);
    run_fd = -1;
  }
  return -1;
}

static int
run_make_record(char *buf, unsigned long int ts,
                int sb, unsigned long sz, int le,
                int tm, int lg, int pr, int st, int tt,
                int sc, char const *ip)
{
  memset(buf, ' ', RUN_RECORD_SIZE);
  buf[RUN_RECORD_SIZE] = 0;
  buf[RUN_RECORD_SIZE - 1] = '\n';
  sprintf(buf, "%12lu %6d %8lu %4d %8d %4d %4d %3d %4d %3d %15s",
          ts, sb, sz, le, tm, lg, pr, st, tt, sc, ip);
  buf[strlen(buf)] = ' ';
  if (strlen(buf) != RUN_RECORD_SIZE)
    ERR_R("record size is bad: %d", strlen(buf));
  if (buf[RUN_RECORD_SIZE - 1] != '\n')
    ERR_R("last \\n is overwritten");
  return 0;
}

static int
run_make_header(char *buf)
{
  memset(buf, ' ', RUN_HEADER_SIZE);
  buf[RUN_HEADER_SIZE] = 0;
  buf[RUN_HEADER_SIZE - 1] = '\n';
  sprintf(buf, "%-10lu %-10lu %-10lu %-10lu",
          head.start_time, head.sched_time, head.duration,
          head.stop_time);
  buf[strlen(buf)] = ' ';
  if (strlen(buf) != RUN_HEADER_SIZE)
    ERR_R("header size is bad: %d", strlen(buf));
  if (buf[RUN_HEADER_SIZE - 1] != '\n')
    ERR_R("last \\n is overwritten");
  return 0;
}

static int
run_flush_entry(int num)
{
  char buf[RUN_RECORD_SIZE + 16];
  int  wsz;

  if (run_fd < 0) ERR_R("invalid descriptor %d", run_fd);
  if (num < 0 || num >= run_u) ERR_R("invalid entry number %d", num);
  if (run_make_record(buf, 
                      runs[num].timestamp, runs[num].submission,
                      runs[num].size, runs[num].locale_id,
                      runs[num].team, runs[num].language,
                      runs[num].problem, runs[num].status,
                      runs[num].test, runs[num].score, runs[num].ip) < 0)
    return -1;
  if (sf_lseek(run_fd, RUN_HEADER_SIZE + RUN_RECORD_SIZE * num, SEEK_SET, "run") == (off_t) -1) return -1;

  if ((wsz = sf_write(run_fd, buf, RUN_RECORD_SIZE, "run")) < 0) return -1;
  if (wsz != RUN_RECORD_SIZE) ERR_R("%d - short write", wsz);
  return 0;
}

int
run_add_record(unsigned long  timestamp, 
               unsigned long  size,
               char const    *ip,
               int            locale_id,
               int            team,
               int            problem,
               int            language)
{
  int i;

  /* FIXME: add parameter checking? */
  if (strlen(ip) > RUN_MAX_IP_LEN) ERR_R("ip address '%s' too long", ip);

  /* now add a new record */
  if (run_u >= run_a) {
    if (!(run_a *= 2)) run_a = 128;
    runs = xrealloc(runs, run_a * sizeof(runs[0]));
    info("run_add_record: array extended: %d", run_a);
  }
  runs[run_u].timestamp = timestamp;
  runs[run_u].submission = run_u;
  runs[run_u].size = size;
  runs[run_u].locale_id = locale_id;
  runs[run_u].team = team;
  runs[run_u].language = language;
  runs[run_u].problem = problem;
  runs[run_u].status = 99;
  runs[run_u].test = 0;
  runs[run_u].score = -1;
  strncpy(runs[run_u].ip, ip, RUN_MAX_IP_LEN);
  runs[run_u].ip[RUN_MAX_IP_LEN - 1] = 0;
  i = run_u++;
  if (run_flush_entry(i) < 0) return -1;
  return i;
}

static int
run_flush_header(void)
{
  char buf[RUN_HEADER_SIZE + 16];
  int  wsz;

  if (run_make_header(buf) < 0) return -1;
  if (sf_lseek(run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;

  if ((wsz = sf_write(run_fd, buf, RUN_HEADER_SIZE, "run")) < 0) return -1;
  if (wsz != RUN_HEADER_SIZE) ERR_R("%d - short write", wsz);
  return 0;
}

int
run_change_status(int runid, int newstatus, int newtest, int newscore)
{
  if (runid < 0 || runid >= run_u) ERR_R("bad runid: %d", runid);
  runs[runid].status = newstatus;
  runs[runid].test = newtest;
  runs[runid].score = newscore;
  run_flush_entry(runid);
  return 0;
}

int
run_get_status(int runid)
{
  if (runid < 0 || runid >= run_u) ERR_R("bad runid: %d", runid);
  return runs[runid].status;
}

int
run_get_param(int runid, int *ploc, int *plang, int *pprob, int *pstat)
{
  if (runid < 0 || runid >= run_u) ERR_R("bad runid: %d", runid);
  if (ploc)  *ploc  = runs[runid].locale_id;
  if (plang) *plang = runs[runid].language;
  if (pprob) *pprob = runs[runid].problem;
  if (pstat) *pstat = runs[runid].status;
  return 0;
}

int
run_get_record(int runid, unsigned long *ptime,
               unsigned long *psize,
               char *pip, int *ploc,
               int *pteamid, int *plangid, int *pprobid,
               int *pstatus, int *ptest, int *pscore)
{
  if (runid < 0 || runid >= run_u) ERR_R("bad runid: %d", runid);

  if (ptime)   *ptime   = runs[runid].timestamp;
  if (psize)   *psize   = runs[runid].size;
  if (ploc)    *ploc    = runs[runid].locale_id;
  if (pteamid) *pteamid = runs[runid].team;
  if (plangid) *plangid = runs[runid].language;
  if (pprobid) *pprobid = runs[runid].problem;
  if (pstatus) *pstatus = runs[runid].status;
  if (ptest)   *ptest   = runs[runid].test;
  if (pscore)  *pscore  = runs[runid].score;
  if (pip)     strcpy(pip, runs[runid].ip);
  return 0;
}

int
run_start_contest(unsigned long start_time)
{
  if (head.start_time) ERR_R("Contest already started");
  head.start_time = start_time;
  head.sched_time = 0;
  return run_flush_header();
}

int
run_stop_contest(unsigned long stop_time)
{
  head.stop_time = stop_time;
  return run_flush_header();
}

int
run_set_duration(unsigned long dur)
{
  head.duration = dur;
  return run_flush_header();
}

int
run_sched_contest(unsigned long sched)
{
  head.sched_time = sched;
  return run_flush_header();
}

unsigned long
run_get_start_time(void)
{
  return head.start_time;
}

unsigned long
run_get_stop_time(void)
{
  return head.stop_time;
}

void
run_get_times(unsigned long *start, unsigned long *sched,
              unsigned long *dur, unsigned long *stop)
{
  if (start) *start = head.start_time;
  if (sched) *sched = head.sched_time;
  if (dur)   *dur   = head.duration;
  if (stop)  *stop  = head.stop_time;
}

int
run_get_total(void)
{
  return run_u;
}

void
run_get_team_usage(int teamid, int *pn, unsigned long *ps)
{
  int i;
  int n = 0;
  unsigned long sz = 0;

  for (i = 0; i < run_u; i++) {
    if (runs[i].team == teamid) {
      sz += runs[i].size;
      n++;
    }
  }
  if (pn) *pn = n;
  if (ps) *ps = sz;
}

/* FIXME: VERY DUMP */
int
run_get_attempts(int runid, int *pattempts)
{
  int i, n = 0;

  *pattempts = 0;
  if (runid < 0 || runid >= run_u) ERR_R("bad runid: %d", runid);

  for (i = 0; i < runid; i++) {
    if (runs[i].team == runs[runid].team
        && runs[i].problem == runs[runid].problem) n++;
  }
  *pattempts = n;
  return 0;
}

char *
run_status_str(int status, char *out, int len)
{
  static char  buf[128];
  char const  *s;

  switch (status) {
  case RUN_OK:               s = _("OK");                  break;
  case RUN_COMPILE_ERR:      s = _("Compilation error");   break;
  case RUN_RUN_TIME_ERR:     s = _("Run-time error");      break;
  case RUN_TIME_LIMIT_ERR:   s = _("Time-limit exceeded"); break;
  case RUN_PRESENTATION_ERR: s = _("Presentation error");  break;
  case RUN_WRONG_ANSWER_ERR: s = _("Wrong answer");        break;
  case RUN_CHECK_FAILED:     s = _("Check failed");        break;
  case RUN_PARTIAL:          s = _("Partial solution");    break;
  case RUN_RUNNING:          s = _("Running...");          break;
  case RUN_COMPILED:         s = _("Compiled");            break;
  case RUN_COMPILING:        s = _("Compiling...");        break;
  case RUN_AVAILABLE:        s = _("Available");           break;
  default:
    sprintf(buf, _("Unknown: %d"), status);
    s = buf;
    break;
  }
  if (!out) return (char*) s;
  if (len <= 0) return strcpy(out, s);
  strncpy(out, s, len);
  out[len - 1] = 0;
  return out;
}

int
run_get_fog_period(unsigned long cur_time, int fog_time, int unfog_time)
{
  unsigned long estimated_stop;
  unsigned long fog_start;

  ASSERT(cur_time);
  ASSERT(fog_time >= 0);
  ASSERT(unfog_time >= 0);

  if (!head.start_time) return -1;
  if (!fog_time || !head.duration) return 0;

  ASSERT(cur_time >= head.start_time);
  if (head.stop_time) {
    ASSERT(head.stop_time >= head.start_time);
    ASSERT(cur_time >= head.stop_time);
    if (cur_time > head.stop_time + unfog_time) return 2;
    return 1;
  } else {
    estimated_stop = head.start_time + head.duration;
    ASSERT(cur_time <= estimated_stop);
    if (fog_time > head.duration) fog_time = head.duration;
    fog_start = estimated_stop - fog_time;
    if (cur_time >= fog_start) return 1;
    return 0;
  }
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */

