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
#include <reuse/osdeps.h>

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

#define RUN_MAX_IP_LEN 15
#define RUN_RECORD_SIZE 105
#define RUN_HEADER_SIZE 105

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
  r = sscanf(buf, " %lu %d %zu %hhu %d %hhu %d %hhu %hhu %d %s %n",
             &runs[n].timestamp, &runs[n].submission, &runs[n].size,
             &runs[n].locale_id,
             &runs[n].team, &runs[n].language, &runs[n].problem,
             &runs[n].status, &runs[n].test, &runs[n].score, tip, &k);
  if (r != 11) ERR_R("[%d]: sscanf returned %d", n, r);
  if (buf[k] != 0) ERR_R("[%d]: excess data", n);
  if (strlen(tip) > RUN_MAX_IP_LEN) ERR_R("[%d]: ip is to long", n);
  runs[n].ip = run_parse_ip(tip);
  if (runs[n].ip == (unsigned long) -1) ERR_R("[%d]: cannot parse IP");
  return 0;
}

static int
is_runlog_version_0(void)
{
  unsigned char buf[RUN_HEADER_SIZE + 16];
  int r, n;
  unsigned long v1, v2, v3, v4;

  memset(buf, 0, sizeof(buf));
  if (sf_lseek(run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;
  if ((r = sf_read(run_fd, buf, RUN_HEADER_SIZE, "run")) < 0) return -1;
  if (r != RUN_HEADER_SIZE) return 0;
  if (buf[r - 1] != '\n') {
    //fprintf(stderr, "record improperly terminated\n");
    return 0;
  }
  for (r = 0; r < RUN_HEADER_SIZE - 1; r++) {
    if (buf[r] < ' ' || buf[r] >= 127) {
      //fprintf(stderr, "invalid character at pos %d: %d", r, buf[r]);
      return 0;
    }
  }
  r = sscanf(buf, " %lu %lu %lu %lu %n", &v1, &v2, &v3, &v4, &n);
  if (r != 4 || buf[n]) {
    //fprintf(stderr, "cannot parse header <%s>\n", buf);
    return 0;
  }
  return 1;
}

static int
read_runlog_version_0(void)
{
  unsigned long filesize;
  int i;

  info("reading runs log version 0");

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
save_runlog_backup(const unsigned char *path)
{
  unsigned char *back;
  size_t len;

  len = strlen(path);
  back = alloca(len + 16);
  sprintf(back, "%s.bak", path);
  if (rename(path, back) < 0) {
    err("save_runlog_backup: rename failed: %s", os_ErrorMsg());
    return -1;
  }
  info("old runlog is saved as %s", back);
  return 0;
}

static int
do_write(int fd, void const *buf, size_t size)
{
  const unsigned char *p = (const unsigned char *) buf;
  int w;

  ASSERT(buf);
  ASSERT(size);

  while (size) {
    w = write(fd, p, size);
    if (w <= 0) {
      err("do_write: write error: %s", os_ErrorMsg());
      return -1;
    }
    p += w;
    size -= w;
  }
  return 0;
}

static int
do_read(int fd, void *buf, size_t size)
{
  unsigned char *p = (unsigned char*) buf;
  int r;

  while (size) {
    r = read(fd, p, size);
    if (r < 0) {
      err("do_read: read failed: %s", os_ErrorMsg());
      return -1;
    }
    if (!r) {
      err("do_read: unexpected EOF");
      return -1;
    }
    p += r;
    size -= r;
  }
  return 0;
}

static int
write_full_runlog_current_version(const char *path)
{
  int run_fd;

  if ((run_fd = sf_open(path, O_RDWR | O_CREAT | O_TRUNC, 0666)) < 0)
    return -1;

  head.version = 1;
  if (do_write(run_fd, &head, sizeof(head)) < 0) return -1;
  if (run_u > 0) {
    if (do_write(run_fd, runs, sizeof(runs[0]) * run_u) < 0) return -1;
  }

  return run_fd;
}

static int
read_runlog(void)
{
  int filesize;
  int rem;

  info("reading runs log (binary)");

  /* calculate the size of the file */
  if ((filesize = sf_lseek(run_fd, 0, SEEK_END, "run")) == (off_t) -1)
    return -1;
  if (sf_lseek(run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;

  info("runs file size: %d", filesize);
  if (filesize == 0) {
    /* runs file is empty */
    XMEMZERO(&head, 1);
    head.version = 1;
    run_u = 0;
    return 0;
  }

  // read header
  if (do_read(run_fd, &head, sizeof(head)) < 0) return -1;
  info("run log version %d", head.version);
  if (head.version != 1) {
    err("unsupported run log version %d", head.version);
    return -1;
  }

  rem = (filesize - sizeof(struct run_header)) % sizeof(struct run_entry);
  if (rem != 0) ERR_C("bad runs file size: remainder %d", rem);

  run_u = (filesize - sizeof(struct run_header)) / sizeof(struct run_entry);
  run_a = 128;
  while (run_u > run_a) run_a *= 2;
  XCALLOC(runs, run_a);
  if (run_u > 0) {
    if (do_read(run_fd, runs, sizeof(runs[0]) * run_u) < 0) return -1;
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

int
run_open(const char *path, int flags)
{
  int           oflags = 0;
  int           i;

  if (runs) {
    xfree(runs); runs = 0; run_u = run_a = 0;
  }
  if (run_fd >= 0) {
    close(run_fd);
    run_fd = -1;
  }
  if (flags == RUN_LOG_READONLY) {
    oflags = O_RDONLY;
  } else if (flags == RUN_LOG_CREATE) {
    oflags = O_RDWR | O_CREAT | O_TRUNC;
  } else {
    oflags = O_RDWR | O_CREAT;
  }
  if ((run_fd = sf_open(path, oflags, 0666)) < 0) return -1;

  if ((i = is_runlog_version_0()) < 0) return -1;
  else if (i) {
    if (read_runlog_version_0() < 0) return -1;
    if (flags != RUN_LOG_READONLY) {
      if (save_runlog_backup(path) < 0) return -1;
      close(run_fd);
      if ((run_fd = write_full_runlog_current_version(path)) < 0) return -1;
    }
  } else {
    if (read_runlog() < 0) return -1;
  }
  return 0;
}

static int
run_flush_entry(int num)
{
  if (run_fd < 0) ERR_R("invalid descriptor %d", run_fd);
  if (num < 0 || num >= run_u) ERR_R("invalid entry number %d", num);
  if (sf_lseek(run_fd, sizeof(head) + sizeof(runs[0]) * num,
               SEEK_SET, "run") == (off_t) -1) return -1;
  if (do_write(run_fd, &runs[num], sizeof(runs[0])) < 0) return -1;
  return 0;
}

static int
append_record(void)
{
  if (run_u >= run_a) {
    if (!(run_a *= 2)) run_a = 128;
    runs = xrealloc(runs, run_a * sizeof(runs[0]));
    info("run_add_record: array extended: %d", run_a);
  }
  memset(&runs[run_u], 0, sizeof(runs[0]));
  runs[run_u].submission = run_u;
  return run_u++;
}

int
run_add_record(time_t  timestamp, 
               size_t  size,
               unsigned long sha1[5],
               unsigned long  ip,
               int            locale_id,
               int            team,
               int            problem,
               int            language)
{
  int i;

  /* FIXME: add parameter checking? */
  if (locale_id < -1 || locale_id > 127) {
    err("run_add_record: locale_id is out of range");
    return -1;
  }
  if (language < 0 || language > 255) {
    err("run_add_record: language is out of range");
    return -1;
  }

  i = append_record();
  runs[i].timestamp = timestamp;
  runs[i].size = size;
  runs[i].locale_id = locale_id;
  runs[i].team = team;
  runs[i].language = language;
  runs[i].problem = problem;
  runs[i].status = 99;
  runs[i].test = 0;
  runs[i].score = -1;
  runs[i].ip = ip;
  if (sha1) {
    memcpy(runs[i].sha1, sha1, sizeof(runs[i].sha1));
  }
  if (run_flush_entry(i) < 0) return -1;
  return i;
}

static int
run_flush_header(void)
{
  if (sf_lseek(run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;
  if (do_write(run_fd, &head, sizeof(head)) < 0) return -1;
  return 0;
}

int
run_change_status(int runid, int newstatus, int newtest, int newscore)
{
  if (runid < 0 || runid >= run_u) ERR_R("bad runid: %d", runid);
  if (newstatus < 0 || newstatus > 255) ERR_R("bad newstatus: %d", newstatus);
  if (newtest < -128 || newtest > 127) ERR_R("bad newtest: %d", newtest);

  if (newstatus == RUN_VIRTUAL_START || newstatus == RUN_VIRTUAL_STOP)
    ERR_R("virtual status cannot be changed that way");
  if (newstatus == RUN_EMPTY)
    ERR_R("EMPTY status cannot be set this way");
  if (runs[runid].status == RUN_VIRTUAL_START
      || runs[runid].status == RUN_VIRTUAL_STOP
      || runs[runid].status == RUN_EMPTY)
    ERR_R("this entry cannot be changed");

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
run_get_record(int runid, time_t *ptime,
               size_t *psize,
               unsigned long *psha1,
               unsigned long *pip, int *ploc,
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
  if (pip)     *pip     = runs[runid].ip;
  if (psha1)   memcpy(psha1, runs[runid].sha1, sizeof(runs[runid].sha1));
  return 0;
}

int
run_start_contest(time_t start_time)
{
  if (head.start_time) ERR_R("Contest already started");
  head.start_time = start_time;
  head.sched_time = 0;
  return run_flush_header();
}

int
run_stop_contest(time_t stop_time)
{
  head.stop_time = stop_time;
  return run_flush_header();
}

int
run_set_duration(time_t dur)
{
  head.duration = dur;
  return run_flush_header();
}

int
run_sched_contest(time_t sched)
{
  head.sched_time = sched;
  return run_flush_header();
}

time_t
run_get_start_time(void)
{
  return head.start_time;
}

time_t
run_get_stop_time(void)
{
  return head.stop_time;
}

time_t
run_get_duration(void)
{
  return head.duration;
}

void
run_get_times(time_t *start, time_t *sched, time_t *dur, time_t *stop)
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
run_get_team_usage(int teamid, int *pn, size_t *ps)
{
  int i;
  int n = 0;
  size_t sz = 0;

  for (i = 0; i < run_u; i++) {
    if (runs[i].status == RUN_VIRTUAL_START
        || runs[i].status == RUN_VIRTUAL_STOP
        || runs[i].status == RUN_EMPTY)
      continue;
    if (runs[i].team == teamid) {
      sz += runs[i].size;
      n++;
    }
  }
  if (pn) *pn = n;
  if (ps) *ps = sz;
}

/* FIXME: VERY DUMB */
int
run_get_attempts(int runid, int *pattempts, int skip_ce_flag)
{
  int i, n = 0;

  *pattempts = 0;
  if (runid < 0 || runid >= run_u) ERR_R("bad runid: %d", runid);

  for (i = 0; i < runid; i++) {
    if (runs[i].status == RUN_VIRTUAL_START
        || runs[i].status == RUN_VIRTUAL_STOP
        || runs[i].status == RUN_EMPTY)
      continue;
    if (runs[i].team != runs[runid].team) continue;
    if (runs[i].problem != runs[runid].problem) continue;
    if (runs[i].status == RUN_COMPILE_ERR && skip_ce_flag) continue;
    if (runs[i].status == RUN_IGNORED) continue;
    n++;
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
  case RUN_ACCEPTED:         s = _("Accepted for testing"); break;
  case RUN_IGNORED:          s = _("Ignored");             break;
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
  strncpy(out, s, len);
  out[len - 1] = 0;
  return out;
}

int
run_get_fog_period(time_t cur_time, int fog_time, int unfog_time)
{
  time_t estimated_stop;
  time_t fog_start;

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

void
run_reset(void)
{
  if (ftruncate(run_fd, 0) < 0) {
    err("ftruncate failed: %s", os_ErrorMsg());
    return;
  }
  
  run_u = 0;
  if (run_a > 0) {
    memset(runs, 0, sizeof(runs[0]) * run_a);
  }
  memset(&head, 0, sizeof(head));
}

unsigned char *
run_unparse_ip(unsigned long ip)
{
  static unsigned char buf[64];

  snprintf(buf, sizeof(buf), "%lu.%lu.%lu.%lu",
           ip >> 24, (ip >> 16) & 0xff,
           (ip >> 8) & 0xff, ip & 0xff);
  return buf;
}

unsigned long
run_parse_ip(unsigned char const *buf)
{
  unsigned int b1, b2, b3, b4;
  int n;

  if (!buf) return (unsigned long) -1;
  if (!buf || sscanf(buf, "%d.%d.%d.%d%n", &b1, &b2, &b3, &b4, &n) != 4
      || buf[n] || b1 > 255 || b2 > 255 || b3 > 255 || b4 > 255) {
    return (unsigned long) -1;
  }
  return b1 << 24 | b2 << 16 | b3 << 8 | b4;
}

int
run_check_duplicate(int run_id)
{
  int i;
  struct run_entry *p, *q;

  if (run_id < 0 || run_id >= run_u) ERR_R("bad runid: %d", run_id);
  p = &runs[run_id];
  for (i = run_id - 1; i >= 0; i--) {
    q = &runs[i];
    if (p->size == q->size
        && p->ip == q->ip
        && p->sha1[0] == q->sha1[0]
        && p->sha1[1] == q->sha1[1]
        && p->sha1[2] == q->sha1[2]
        && p->sha1[3] == q->sha1[3]
        && p->sha1[4] == q->sha1[4]
        && p->team == q->team
        && p->problem == q->problem
        && p->language == q->language) {
      break;
    }
  }
  if (i < 0) return 0;
  p->status = RUN_IGNORED;
  if (run_flush_entry(run_id) < 0) return -1;
  return i + 1;
}

void
run_get_header(struct run_header *out)
{
  memcpy(out, &head, sizeof(head));
}

void
run_get_all_entries(struct run_entry *out)
{
  memcpy(out, runs, sizeof(out[0]) * run_u);
}

int
run_get_entry(int run_id, struct run_entry *out)
{
  if (run_id < 0 || run_id >= run_u) ERR_R("bad runid: %d", run_id);
  memcpy(out, &runs[run_id], sizeof(*out));
  return 0;
}

int
run_set_entry(int run_id, unsigned int mask, const struct run_entry *in)
{
  struct run_entry *out;
  int f = 0;

  ASSERT(in);
  if (run_id < 0 || run_id >= run_u) ERR_R("bad runid: %d", run_id);
  out = &runs[run_id];
  if (out->status == RUN_VIRTUAL_START || out->status == RUN_VIRTUAL_STOP) {
    err("run_set_entry: %d: virtual contest start/stop cannot be edited",
        run_id);
    return -1;
  }
  if (out->status == RUN_EMPTY) {
    err("run_set_entry: %d: empty entry cannot be edited", run_id);
    return -1;
  }

  if ((mask & RUN_ENTRY_STATUS) && out->status != in->status) {
    if (in->status == RUN_VIRTUAL_START
        || in->status == RUN_VIRTUAL_STOP
        || in->status == RUN_EMPTY) {
      err("run_set_entry: %d: special status cannot be set this way", run_id);
      return -1;
    }
    out->status = in->status;
    f = 1;
  }
  if ((mask & RUN_ENTRY_TIME) && out->timestamp != in->timestamp) {
    out->timestamp = in->timestamp;
    f = 1;
  }
  if ((mask & RUN_ENTRY_SIZE) && out->size != in->size) {
    out->size = in->size;
    f = 1;
  }
  if ((mask & RUN_ENTRY_IP) && out->ip != in->ip) {
    out->ip = in->ip;
    f = 1;
  }
  if ((mask&RUN_ENTRY_SHA1) && memcmp(out->sha1,in->sha1,sizeof(out->sha1))) {
    memcmp(out->sha1, in->sha1, sizeof(out->sha1));
    f = 1;
  }
  if ((mask & RUN_ENTRY_USER) && out->team != in->team) {
    out->team = in->team;
    f = 1;
  }
  if ((mask & RUN_ENTRY_PROB) && out->problem != in->problem) {
    out->problem = in->problem;
    f = 1;
  }
  if ((mask & RUN_ENTRY_LANG) && out->language != in->language) {
    out->language = in->language;
    f = 1;
  }
  if ((mask & RUN_ENTRY_LOCALE) && out->locale_id != in->locale_id) {
    out->locale_id = in->locale_id;
    f = 1;
  }
  if ((mask & RUN_ENTRY_TEST) && out->test != in->test) {
    out->test = in->test;
    f = 1;
  }
  if ((mask & RUN_ENTRY_SCORE) && out->score != in->score) {
    out->score = in->score;
    f = 1;
  }

  if (f && run_flush_entry(run_id) < 0) return -1;
  return 0;
}

enum
  {
    V_REAL_USER = 1,
    V_VIRTUAL_USER = 2,
  };

struct vt_entry
{
  int status;
  int start_time;
  int stop_time;
};

static int vt_size;
static struct vt_entry **vt_table;

static struct vt_entry *
get_entry(int user_id)
{
  ASSERT(user_id > 0);

  if (user_id >= vt_size) {
    struct vt_entry **new_vt_table = 0;
    int new_vt_size = vt_size;

    if (!new_vt_size) new_vt_size = 16;
    while (new_vt_size <= user_id)
      new_vt_size *= 2;
    new_vt_table = xcalloc(new_vt_size, sizeof(new_vt_table[0]));
    if (vt_size > 0) {
      memcpy(new_vt_table, vt_table, vt_size * sizeof(vt_table[0]));
    }
    vt_size = new_vt_size;
    xfree(vt_table);
    vt_table = new_vt_table;
    info("runlog: vt_table is extended to %d", vt_size);
  }

  if (!vt_table[user_id]) {
    vt_table[user_id] = xcalloc(1, sizeof(vt_table[user_id][0]));
  }
  return vt_table[user_id];
}

int
run_build_virtual_table(void)
{
  int i;
  int max_uid = -1;
  struct vt_entry *pvt;
  int err_cnt = 0;
  time_t current_time;

  if (!head.start_time || !head.duration) {
    if (run_u > 0) {
      err("runlog: contest is not started, but runlog is not empty!");
      return -1;
    }
    return 0;
  }

  current_time = time(0);

  // scan the run log for maximum user_id and find the initial size
  // get_entry function could extend the array as well, but just
  // to reduce the number of reallocations
  for (i = 0; i < run_u; i++)
    if (runs[i].team > max_uid)
      max_uid = runs[i].team;
  vt_size = 16;
  while (vt_size <= max_uid)
    vt_size *= 2;
  vt_table = xcalloc(vt_size, sizeof(vt_table[0]));

  for (i = 0; i < run_u; i++) {
    if (runs[i].status == RUN_EMPTY) continue;
    pvt = get_entry(runs[i].team);
    if (runs[i].timestamp == 0) {
      err("runlog: run %d has zero timestamp", i);
      err_cnt++;
      continue;
    }
    if (runs[i].timestamp <= 0) {
      err("runlog: run %d has timestamp <= 0", i);
      err_cnt++;
      continue;
    }
    if (runs[i].timestamp < head.start_time) {
      err("runlog: run %d has timestamp < start_time", i);
      err_cnt++;
      continue;
    }
    if (runs[i].timestamp > current_time) {
      err("runlog: run %d has timestamp in the future (difference %ld)",
          i, runs[i].timestamp - current_time);
      err_cnt++;
      continue;
    }
    if (runs[i].status == RUN_VIRTUAL_START) {
      switch (pvt->status) {
      case 0:
        pvt->status = V_VIRTUAL_USER;
        pvt->start_time = runs[i].timestamp;
        break;
      case V_REAL_USER:
        err("runlog: run %d: virtual_start for non virtual user %d",
            i, runs[i].team);
        err_cnt++;
        break;
      case V_VIRTUAL_USER:
        err("runlog: run %d: virtual_start for virtual user %d",
            i, runs[i].team);
        err_cnt++;
        break;
      default:
        abort();
      }
    } else if (runs[i].status == RUN_VIRTUAL_STOP) {
      // this record is optional
      switch (pvt->status) {
      case 0:
        err("runlog: run %d: virtual_stop without virtual_start for user %d",
            i, runs[i].team);
        err_cnt++;
        break;
      case V_REAL_USER:
        err("runlog: run %d: virtual_stop for non-virtual user %d",
            i, runs[i].team);
        err_cnt++;
        break;
      case V_VIRTUAL_USER:
        ASSERT(pvt->start_time);
        if (pvt->stop_time) {
          err("runlog: run %d: duplicated virtual_stop for user %d",
              i, runs[i].team);
          err_cnt++;
        } else if (runs[i].timestamp < pvt->start_time) {
          err("runlog: run %d: virtual_stop earlier than virtual_start for %d",
              i, runs[i].team);
          err_cnt++;
        } else {
          // FIXME: check for duration overrun?
          pvt->stop_time = runs[i].timestamp;
        }
        break;
      default:
        abort();
      }
    } else {
      switch (pvt->status) {
      case 0:
        ASSERT(!pvt->start_time);
        pvt->status = V_REAL_USER;
        pvt->start_time = head.start_time;
        pvt->stop_time = head.stop_time;
        /* FALLTHROUGH */
      case V_REAL_USER:
      case V_VIRTUAL_USER:
        if (runs[i].timestamp - pvt->start_time > head.duration + 1) {
          err("runlog: run %d: duration overrun %ld",
              i, runs[i].timestamp - pvt->start_time);
          err("problematic timestamp: %ld, should be fixed to: %ld",
              runs[i].timestamp, pvt->start_time + head.duration);
          //runs[i].timestamp = pvt->start_time + head.duration;
          err_cnt++;
        }
        if (pvt->stop_time && runs[i].timestamp > pvt->stop_time) {
          err("runlog: run %d: stop time overrun %ld",
              i, runs[i].timestamp - pvt->stop_time);
          err_cnt++;
        }
        break;
      default:
        abort();
      }
    }
  }

  if (err_cnt > 0) return -1;

  ASSERT(vt_table[0] == 0);
  for (i = 1; i < vt_size; i++) {
    if (!vt_table[i]) continue;
    if (!vt_table[i]->status) {
      err("runlog: user %d status is zero", i);
      err_cnt++;
      continue;
    }
    if (!vt_table[i]->start_time) {
      err("runlog: user %d start_time is zero", i);
      err_cnt++;
      continue;
    }
    if (vt_table[i]->start_time < 0) {
      err("runlog: user %d start_time < 0", i);
      err_cnt++;
      continue;
    }
    if (vt_table[i]->stop_time == 0
        && current_time - vt_table[i]->start_time > head.duration) {
      vt_table[i]->stop_time = vt_table[i]->start_time + head.duration;
    }
    if (vt_table[i]->stop_time
        && vt_table[i]->stop_time < vt_table[i]->start_time) {
      err("runlog: user %d stop_time < start_time", i);
      err_cnt++;
      continue;
    }
  }

  if (err_cnt > 0) return -1;
  return 0;
}

time_t
run_get_virtual_start_time(int user_id)
{
  struct vt_entry *pvt = get_entry(user_id);
  return pvt->start_time;
}

time_t
run_get_virtual_stop_time(int user_id, time_t cur_time)
{
  struct vt_entry *pvt = get_entry(user_id);
  if (!pvt->start_time) return 0;
  if (!cur_time) return pvt->stop_time;
  if (pvt->status == V_REAL_USER) return head.stop_time;
  if (pvt->status != V_VIRTUAL_USER) return 0;
  if (head.duration || pvt->stop_time) return pvt->stop_time;
  if (pvt->start_time + head.duration < cur_time) {
    pvt->stop_time = pvt->start_time + head.duration;
  }
  return pvt->stop_time;
}

int
run_get_virtual_status(int user_id)
{
  struct vt_entry *pvt = get_entry(user_id);
  return pvt->status;
}

int
run_virtual_start(int user_id, time_t t, unsigned long ip)
{
  struct vt_entry *pvt = get_entry(user_id);
  int i;

  if (pvt->start_time) {
    err("runlog: virtual contest for %d already started", user_id);
    return -1;
  }
  i = append_record();
  runs[i].team = user_id;
  runs[i].timestamp = t;
  runs[i].ip = ip;
  runs[i].status = RUN_VIRTUAL_START;
  pvt->start_time = t;
  pvt->status = V_VIRTUAL_USER;
  if (run_flush_entry(i) < 0) return -1;
  return -1;
}

int
run_virtual_stop(int user_id, time_t t, unsigned long ip)
{
  struct vt_entry *pvt = get_entry(user_id);
  int i;

  if (!pvt->start_time) {
    err("runlog: virtual contest for %d is not yet started", user_id);
    return -1;
  }
  if (pvt->stop_time) {
    err("runlog: virtual contest for %d already stopped", user_id);
    return -1;
  }
  if (pvt->status != V_VIRTUAL_USER) {
    err("runlog: user %d is not virtual", user_id);
    return -1;
  }
  i = append_record();
  runs[i].team = user_id;
  runs[i].timestamp = t;
  runs[i].ip = ip;
  runs[i].status = RUN_VIRTUAL_STOP;
  pvt->stop_time = t;
  if (run_flush_entry(i) < 0) return -1;
  return -1;
}

int
run_clear_entry(int run_id)
{
  if (run_id < 0 || run_id >= run_u) ERR_R("bad runid: %d", run_id);
  memset(&runs[run_id], 0, sizeof(runs[run_id]));
  runs[run_id].status = RUN_EMPTY;
  return run_flush_entry(run_id);
}

int
run_squeeze_log(void)
{
  int i, j, retval, first_moved = -1, w;
  unsigned char *ptr;
  size_t tot;

  for (i = 0, j = 0; i < run_u; i++) {
    if (runs[i].status == RUN_EMPTY) continue;
    if (i != j) {
      if (first_moved < 0) first_moved = j;
      memcpy(&runs[j], &runs[i], sizeof(runs[j]));
    }
    j++;
  }
  if  (run_u == j) {
    // no runs were removed
    ASSERT(first_moved == -1);
    return 0;
  }

  retval = run_u - j;
  run_u = j;
  if (run_u < run_a) {
    memset(&runs[run_u], 0, (run_a - run_u) * sizeof(runs[0]));
  }

  // update log on disk
  if (ftruncate(run_fd, sizeof(head) + run_u * sizeof(runs[0])) < 0) {
    err("run_squeeze_log: ftruncate failed: %s", os_ErrorMsg());
    return -1;
  }
  if (first_moved == -1) {
    // no entries were moved because the only entries empty were the last
    return retval;
  }
  ASSERT(first_moved >= 0 && first_moved < run_u);
  if (sf_lseek(run_fd, sizeof(head) + first_moved * sizeof(runs[0]),
               SEEK_SET, "run") == (off_t) -1)
    return -1;
  tot = (run_u - first_moved) * sizeof(runs[0]);
  ptr = (unsigned char *) &runs[first_moved];
  while (tot > 0) {
    w = write(run_fd, ptr, tot);
    if (w <= 0) {
      err("run_squeeze_log: write error: %s", os_ErrorMsg());
      return -1;
    }
    tot -= w;
    ptr += w;
  }
  return retval;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */

