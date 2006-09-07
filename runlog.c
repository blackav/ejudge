/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"

#include "runlog.h"
#include "teamdb.h"

#include "pathutl.h"
#include "errlog.h"
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

#define ERR_R(t, args...) do { do_err_r(__FUNCTION__ , t , ##args); return -1; } while (0)
#define ERR_C(t, args...) do { do_err_r(__FUNCTION__ , t , ##args); goto _cleanup; } while (0)

/* these constants are for old text-based runlog */
#define RUN_MAX_IP_LEN 15
#define RUN_RECORD_SIZE 105
#define RUN_HEADER_SIZE 105

#define RUNLOG_MAX_SIZE    (1024 * 1024)
#define RUNLOG_MAX_TEAM_ID 100000
#define RUNLOG_MAX_PROB_ID 100000
#define RUNLOG_MAX_SCORE   100000

static struct run_header  head;
static struct run_entry  *runs;
static int                run_u;
static int                run_a;
static int                run_fd = -1;
static teamdb_state_t     teamdb_state;

enum
  {
    V_REAL_USER = 1,
    V_VIRTUAL_USER = 2,
    V_LAST = 2,
  };

struct user_entry
{
  int status;                   /* virtual or real user */
  int start_time;
  int stop_time;
};

/* index for users */
static int ut_size;
static struct user_entry **ut_table;

static void build_indices(void);
static struct user_entry *get_user_entry(int user_id);

struct user_flags_info_s
{
  int nuser;
  int *flags;
};
static struct user_flags_info_s user_flags = { -1, 0 };
static int update_user_flags(void);

void
run_init(teamdb_state_t ts)
{
  teamdb_state = ts;
}

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
  r = sscanf(buf, " %u %u %u %u %n",
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
  r = sscanf(buf, " %d %d %u %hhu %d %hhu %d %hhu %hhu %d %s %n",
             &runs[n].timestamp, &runs[n].submission, &runs[n].size,
             &runs[n].locale_id,
             &runs[n].team, &runs[n].language, &runs[n].problem,
             &runs[n].status, &runs[n].test, &runs[n].score, tip, &k);
  if (r != 11) ERR_R("[%d]: sscanf returned %d", n, r);
  if (buf[k] != 0) ERR_R("[%d]: excess data", n);
  if (strlen(tip) > RUN_MAX_IP_LEN) ERR_R("[%d]: ip is to long", n);
  runs[n].ip = run_parse_ip(tip);
  if (runs[n].ip == (ej_ip_t) -1) ERR_R("[%d]: cannot parse IP");
  return 0;
}

static int
is_runlog_version_0(void)
{
  unsigned char buf[RUN_HEADER_SIZE + 16];
  int r, n;
  time_t v1, v2, v3, v4;

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
  r = sscanf(buf, " %ld %ld %ld %ld %n", &v1, &v2, &v3, &v4, &n);
  if (r != 4 || buf[n]) {
    //fprintf(stderr, "cannot parse header <%s>\n", buf);
    return 0;
  }
  return 1;
}

static int
read_runlog_version_0(void)
{
  off_t filesize;
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
  if (runlog_check(0, &head, run_u, runs) < 0) goto _cleanup;
  build_indices();

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
  int w, se;

  ASSERT(buf);
  ASSERT(size);

  while (size) {
    w = write(fd, p, size);
    if (w <= 0) {
      se = errno;
      if (se == EINTR) continue;
      err("do_write: write error: %s", os_ErrorMsg());
      errno = se;
      return -se;
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
  int r, se;

  while (size) {
    r = read(fd, p, size);
    if (r < 0) {
      se = errno;
      if (se == EINTR) continue;
      err("do_read: read failed: %s", os_ErrorMsg());
      errno = se;
      return -se;
    }
    if (!r) {
      err("do_read: unexpected EOF");
      errno = EPIPE;
      return -EPIPE;
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

int
run_set_runlog(int total_entries, struct run_entry *entries)
{
  if (runlog_check(0, &head, total_entries, entries) < 0)
    return -1;

  if (total_entries > run_a) {
    if (!run_a) run_a = 128;
    xfree(runs);
    while (total_entries > run_a) run_a *= 2;
    runs = xcalloc(run_a, sizeof(runs[0]));
  } else {
    memset(runs, 0, run_a * sizeof(runs[0]));
  }
  run_u = total_entries;
  if (run_u > 0) {
    memcpy(runs, entries, run_u * sizeof(runs[0]));
  }
  sf_lseek(run_fd, sizeof(struct run_header), SEEK_SET, "run");
  do_write(run_fd, runs, sizeof(runs[0]) * run_u);
  ftruncate(run_fd, sizeof(runs[0]) * run_u + sizeof(struct run_header));
  build_indices();
  return 0;
}

static int run_flush_header(void);

static int
read_runlog(time_t init_duration)
{
  off_t filesize;
  int rem;
  int r;

  info("reading runs log (binary)");

  /* calculate the size of the file */
  if ((filesize = sf_lseek(run_fd, 0, SEEK_END, "run")) == (off_t) -1)
    return -1;
  if (sf_lseek(run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;

  info("runs file size: %ld", filesize);
  if (filesize == 0) {
    /* runs file is empty */
    XMEMZERO(&head, 1);
    head.version = 1;
    head.duration = init_duration;
    run_u = 0;
    run_flush_header();
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
  if ((r = runlog_check(0, &head, run_u, runs)) < 0) return -1;
  if (r > 0) runlog_flush();
  build_indices();
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

static void teamdb_update_callback(void *);

int
run_open(const char *path, int flags, time_t init_duration)
{
  int           oflags = 0;
  int           i;

  teamdb_register_update_hook(teamdb_state, teamdb_update_callback, 0);
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
    if (read_runlog(init_duration) < 0) return -1;
  }
  return 0;
}

int
run_backup(const unsigned char *path)
{
  unsigned char *newlog;
  int i = 1, r;
  struct stat sb;

  if (!path) ERR_R("invalid path");
  newlog = alloca(strlen(path) + 16);
  do {
    sprintf(newlog, "%s.%d", path, i++);
  } while (stat(newlog, &sb) >= 0);
  r = write_full_runlog_current_version(newlog);
  if (r < 0) return r;
  close(r);
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

int
runlog_flush(void)
{
  if (run_fd < 0) ERR_R("invalid descriptor %d", run_fd);
  if (sf_lseek(run_fd, sizeof(head), SEEK_SET, "run") == (off_t) -1) return -1;
  if (do_write(run_fd, runs, run_u * sizeof(runs[0])) < 0) return -1;
  return 0;
}

static int
append_record(time_t t, int uid, int nsec)
{
  int i, j, k;

  ASSERT(run_u <= run_a);
  if (run_u == run_a) {
    if (!(run_a *= 2)) run_a = 128;
    runs = xrealloc(runs, run_a * sizeof(runs[0]));
    memset(&runs[run_u], 0, (run_a - run_u) * sizeof(runs[0]));
    info("append_record: array extended: %d", run_a);
  }

  while (1) {
    if (run_u > 0) {
      if (runs[run_u - 1].timestamp > t) break;
      if (runs[run_u - 1].timestamp == t) {
        if (runs[run_u - 1].nsec > nsec) break;
        if (runs[run_u - 1].nsec == nsec) {
          if (runs[run_u - 1].team > uid) break;
        }
      }
    }

    /* it is safe to insert a record at the end */
    memset(&runs[run_u], 0, sizeof(runs[0]));
    runs[run_u].submission = run_u;
    runs[run_u].status = RUN_EMPTY;
    runs[run_u].timestamp = t;
    runs[run_u].nsec = nsec;
    return run_u++;
  }

  i = 0, j = run_u - 1;
  while (i < j) {
    k = (i + j) / 2;
    if (runs[k].timestamp > t
        || (runs[k].timestamp == t && runs[k].nsec > nsec)
        || (runs[k].timestamp == t && runs[k].nsec == nsec
            && runs[k].team > uid)) {
      j = k;
    } else {
      i = k + 1;
    }
  }
  ASSERT(i == j);
  ASSERT(i < run_u);
  ASSERT(i >= 0);

  /* So we going to insert a run at position i.
   * Check, that there is no "transient"-statused runs after this position.
   * This is very unlikely, because such runs appears when the run
   * is being compiled or run, and in this case its precise (nanosecond)
   * timestamp should be less, than the current run. However, if such
   * sutuation is detected, we fail because we cannot safely change
   * the run_id's when it is possible to receive compile or run response
   * packets.
   */
  for (j = i; j < run_u; j++)
    if (runs[j].status >= RUN_TRANSIENT_FIRST
        && runs[j].status <= RUN_TRANSIENT_LAST)
      break;
  if (j < run_u) {
    err("append_record: cannot safely insert a run at position %d", i);
    err("append_record: the run %d is transient!", j);
    return -1;
  }

  memmove(&runs[i + 1], &runs[i], (run_u - i) * sizeof(runs[0]));
  run_u++;
  for (j = i + 1; j < run_u; j++)
    runs[j].submission = j;

  memset(&runs[i], 0, sizeof(runs[0]));
  runs[i].submission = i;
  runs[i].status = RUN_EMPTY;
  runs[i].timestamp = t;
  runs[i].nsec = nsec;
  if (sf_lseek(run_fd, sizeof(head) + i * sizeof(runs[0]), SEEK_SET,
               "run") == (off_t) -1) return -1;
  if (do_write(run_fd, &runs[i], (run_u - i) * sizeof(runs[0])) < 0)
    return -1;
  return i;
}

int
run_add_record(time_t         timestamp,
               int            nsec,
               size_t         size,
               ruint32_t      sha1[5],
               ruint32_t      ip,
               int            locale_id,
               int            team,
               int            problem,
               int            language,
               int            variant,
               int            is_hidden)
{
  int i;
  struct user_entry *ue;
  time_t stop_time;

  if (timestamp <= 0) {
    err("run_add_record: invalid timestamp %ld", timestamp);
    return -1;
  }
  if (!is_hidden) {
    if (!head.start_time) {
      err("run_add_record: contest is not yet started");
      return -1;
    }
    if (timestamp < head.start_time) {
      err("run_add_record: timestamp < start_time");
      return -1;
    }
  }

  if (locale_id < -1 || locale_id > 127) {
    err("run_add_record: locale_id is out of range");
    return -1;
  }
  if (team <= 0 || team > RUNLOG_MAX_TEAM_ID) {
    err("run_add_record: team is out of range");
    return -1;
  }
  if (language <= 0 || language >= 255) {
    err("run_add_record: language is out of range");
    return -1;
  }
  if (problem <= 0 || problem > RUNLOG_MAX_PROB_ID) {
    err("run_add_record: problem is out of range");
    return -1;
  }
  if (variant < 0 || variant > 255) {
    err("run_add_record: variant is out of range");
    return -1;
  }
  if (is_hidden < 0 || is_hidden > 1) {
    err("run_add_record: is_hidden field value is invalid");
    return -1;
  }
  if (nsec < 0 || nsec >= 1000000000) {
    err("run_add_record: nsec field value %d is invalid", nsec);
    return -1;
  }

  if (!is_hidden) {
    ue = get_user_entry(team);
    if (ue->status == V_VIRTUAL_USER) {
      if (!ue->start_time) {
        err("run_add_record: virtual contest not started");
        return -1;
      }
      if (timestamp < ue->start_time) {
        err("run_add_record: timestamp < virtual start time");
        return -1;
      }
      stop_time = ue->stop_time;
      if (!stop_time && head.duration)
        stop_time = ue->start_time + head.duration;
      if (stop_time && timestamp > stop_time) {
        err("run_add_record: timestamp > virtual stop time");
        return -1;
      }
    } else {
      stop_time = head.stop_time;
      if (!stop_time && head.duration)
        stop_time = head.start_time + head.duration;
      if (stop_time && timestamp > stop_time) {
        err("run_add_record: timestamp overrun");
        return -1;
      }
      ue->status = V_REAL_USER;
    }
  }

  if ((i = append_record(timestamp, team, nsec)) < 0) return -1;
  runs[i].size = size;
  runs[i].locale_id = locale_id;
  runs[i].team = team;
  runs[i].language = language;
  runs[i].problem = problem;
  runs[i].status = 99;
  runs[i].test = 0;
  runs[i].score = -1;
  runs[i].ip = ip;
  runs[i].variant = variant;
  runs[i].is_hidden = is_hidden;
  if (sha1) {
    memcpy(runs[i].sha1, sha1, sizeof(runs[i].sha1));
  }
  if (run_flush_entry(i) < 0) return -1;
  return i;
}

int
run_undo_add_record(int run_id)
{
  if (run_id < 0 || run_id >= run_u) {
    err("run_undo_add_record: invalid run_id");
    return -1;
  }
  if (run_id == run_u - 1) {
    run_u--;
    memset(&runs[run_u], 0, sizeof(runs[0]));
    if (ftruncate(run_fd, sizeof(head) + sizeof(runs[0]) * run_u) < 0) {
      err("run_undo_add_record: ftruncate failed: %s", os_ErrorMsg());
      return -1;
    }
    return 0;
  }
  // clear run
  memset(&runs[run_id], 0, sizeof(runs[0]));
  runs[run_id].submission = run_id;
  runs[run_id].status = RUN_EMPTY;
  return 0;
}

static int
run_flush_header(void)
{
  if (sf_lseek(run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;
  if (do_write(run_fd, &head, sizeof(head)) < 0) return -1;
  return 0;
}

int
run_change_status(int runid, int newstatus, int newtest, int newscore, int judge_id)
{
  if (runid < 0 || runid >= run_u) ERR_R("bad runid: %d", runid);
  if (newstatus < 0 || newstatus > 255) ERR_R("bad newstatus: %d", newstatus);
  if (newtest < -1 || newtest > 127) ERR_R("bad newtest: %d", newtest);
  if (newscore < -1 || newscore > RUNLOG_MAX_SCORE)
    ERR_R("bad newscore: %d", newscore);
  if (judge_id < 0 || judge_id > 65535) ERR_R("bad judge_id: %d", judge_id);

  if (newstatus == RUN_VIRTUAL_START || newstatus == RUN_VIRTUAL_STOP)
    ERR_R("virtual status cannot be changed that way");
  if (newstatus == RUN_EMPTY)
    ERR_R("EMPTY status cannot be set this way");
  if (runs[runid].status == RUN_VIRTUAL_START
      || runs[runid].status == RUN_VIRTUAL_STOP
      || runs[runid].status == RUN_EMPTY)
    ERR_R("this entry cannot be changed");

  if (runs[runid].is_readonly)
    ERR_R("this entry is read-only");

  runs[runid].status = newstatus;
  runs[runid].test = newtest;
  runs[runid].score = newscore;
  runs[runid].judge_id = judge_id;
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
run_get_attempts(int runid, int *pattempts,
                 int *pdisqattempts, int skip_ce_flag)
{
  int i, n = 0, m = 0;

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
    if (runs[i].is_hidden) continue;
    if (runs[i].status == RUN_DISQUALIFIED) {
      m++;
    } else {
      n++;
    }
  }
  if (pattempts) *pattempts = n;
  if (pdisqattempts) *pdisqattempts = m;
  return 0;
}

/* FIXME: EVER DUMBER */
/*
 * if the specified run_id is OK run, how many successes were on the
 * same problem by other people before.
 * returns: -1 on error
 *          number of previous successes
 *          RUN_TOO_MANY (100000), if invisible or banned user or run
 */
int
run_get_prev_successes(int run_id)
{
  int user_id, successes = 0, i, cur_uid;
  unsigned char *has_success = 0;

  if (run_id < 0 || run_id >= run_u) ERR_R("bad runid: %d", run_id);
  if (runs[run_id].status != RUN_OK) ERR_R("runid %d is not OK", run_id);

  // invisible run
  if (runs[run_id].is_hidden) return RUN_TOO_MANY;

  if (update_user_flags() < 0) return -1;

  // invalid, banned or invisible user
  user_id = runs[run_id].team;
  if (user_id <= 0 || user_id >= user_flags.nuser
      || user_flags.flags[user_id] < 0
      || (user_flags.flags[user_id] & TEAM_BANNED)
      || (user_flags.flags[user_id] & TEAM_INVISIBLE))
    return RUN_TOO_MANY;

  XALLOCAZ(has_success, user_flags.nuser);
  for (i = 0; i < run_id; i++) {
    if (runs[i].status != RUN_OK) continue;
    if (runs[i].is_hidden) continue;
    if (runs[i].problem != runs[run_id].problem) continue;
    cur_uid = runs[i].team;
    if (cur_uid <= 0 || cur_uid >= user_flags.nuser
        || user_flags.flags[cur_uid] < 0
        || (user_flags.flags[cur_uid] & TEAM_BANNED)
        || (user_flags.flags[cur_uid] & TEAM_INVISIBLE))
      continue;
    if (cur_uid == user_id) {
      // the user already had OK before
      return successes;
    }
    if (has_success[cur_uid]) continue;
    has_success[cur_uid] = 1;
    successes++;
  }
  return successes;
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
    //ASSERT(cur_time <= estimated_stop);
    if (fog_time > head.duration) fog_time = head.duration;
    fog_start = estimated_stop - fog_time;
    if (cur_time >= fog_start) return 1;
    return 0;
  }
}

int
run_reset(time_t new_duration)
{
  int i;

  run_u = 0;
  if (run_a > 0) {
    memset(runs, 0, sizeof(runs[0]) * run_a);
  }
  for (i = 0; i < ut_size; i++)
    xfree(ut_table[i]);
  xfree(ut_table);
  ut_table = 0;
  ut_size = 0;
  memset(&head, 0, sizeof(head));
  head.version = 1;
  head.duration = new_duration;

  if (ftruncate(run_fd, 0) < 0) {
    err("ftruncate failed: %s", os_ErrorMsg());
    return -1;
  }
  run_flush_header();
  return 0;
}

unsigned char *
run_unparse_ip(ej_ip_t ip)
{
  static unsigned char buf[64];

  snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
           ip >> 24, (ip >> 16) & 0xff,
           (ip >> 8) & 0xff, ip & 0xff);
  return buf;
}

ej_ip_t
run_parse_ip(unsigned char const *buf)
{
  unsigned int b1, b2, b3, b4;
  int n;

  if (!buf) return (ej_ip_t) -1;
  if (!buf || sscanf(buf, "%d.%d.%d.%d%n", &b1, &b2, &b3, &b4, &n) != 4
      || buf[n] || b1 > 255 || b2 > 255 || b3 > 255 || b4 > 255) {
    return (ej_ip_t) -1;
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
    if (q->status == RUN_EMPTY || q->status == RUN_VIRTUAL_START
        || q->status == RUN_VIRTUAL_STOP)
      continue;
    if (p->size == q->size
        && p->ip == q->ip
        && p->sha1[0] == q->sha1[0]
        && p->sha1[1] == q->sha1[1]
        && p->sha1[2] == q->sha1[2]
        && p->sha1[3] == q->sha1[3]
        && p->sha1[4] == q->sha1[4]
        && p->team == q->team
        && p->problem == q->problem
        && p->language == q->language
        && p->variant == q->variant) {
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

const struct run_entry *
run_get_entries_ptr(void)
{
  return runs;
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
  struct run_entry te;
  int f = 0;
  struct user_entry *ue = 0;
  time_t stop_time;

  ASSERT(in);
  if (run_id < 0 || run_id >= run_u) ERR_R("bad runid: %d", run_id);
  out = &runs[run_id];
  ASSERT(out->submission == run_id);

  ASSERT(head.start_time >= 0);
  if (!out->is_hidden && !head.start_time) {
    err("run_set_entry: %d: the contest is not started", run_id);
    return -1;
  }

  /* refuse to edit some kind of entries */
  if (out->status == RUN_VIRTUAL_START || out->status == RUN_VIRTUAL_STOP) {
    err("run_set_entry: %d: virtual contest start/stop cannot be edited",
        run_id);
    return -1;
  }
  if (out->status == RUN_EMPTY) {
    err("run_set_entry: %d: empty entry cannot be edited", run_id);
    return -1;
  }

  if (out->is_readonly && mask != RUN_ENTRY_READONLY) {
    err("run_set_entry: %d: this entry is read-only", run_id);
    return -1;
  }

  /* blindly update all fields */
  memcpy(&te, out, sizeof(te));
  if ((mask & RUN_ENTRY_STATUS) && te.status != in->status) {
    te.status = in->status;
    f = 1;
  }
  if ((mask & RUN_ENTRY_TIME) && te.timestamp != in->timestamp) {
    te.timestamp = in->timestamp;
    f = 1;
  }
  if ((mask & RUN_ENTRY_NSEC) && te.nsec != in->nsec) {
    te.nsec = in->nsec;
    f = 1;
  }
  if ((mask & RUN_ENTRY_SIZE) && te.size != in->size) {
    te.size = in->size;
    f = 1;
  }
  if ((mask & RUN_ENTRY_IP) && te.ip != in->ip) {
    te.ip = in->ip;
    f = 1;
  }
  if ((mask&RUN_ENTRY_SHA1) && memcmp(te.sha1,in->sha1,sizeof(te.sha1))) {
    memcpy(te.sha1, in->sha1, sizeof(te.sha1));
    f = 1;
  }
  if ((mask & RUN_ENTRY_USER) && te.team != in->team) {
    te.team = in->team;
    f = 1;
  }
  if ((mask & RUN_ENTRY_PROB) && te.problem != in->problem) {
    te.problem = in->problem;
    f = 1;
  }
  if ((mask & RUN_ENTRY_LANG) && te.language != in->language) {
    te.language = in->language;
    f = 1;
  }
  if ((mask & RUN_ENTRY_LOCALE) && te.locale_id != in->locale_id) {
    te.locale_id = in->locale_id;
    f = 1;
  }
  if ((mask & RUN_ENTRY_TEST) && te.test != in->test) {
    te.test = in->test;
    f = 1;
  }
  if ((mask & RUN_ENTRY_SCORE) && te.score != in->score) {
    te.score = in->score;
    f = 1;
  }
  if ((mask & RUN_ENTRY_IMPORTED) && te.is_imported != in->is_imported) {
    te.is_imported = in->is_imported;
    f = 1;
  }
  if ((mask & RUN_ENTRY_VARIANT) && te.variant != in->variant) {
    te.variant = in->variant;
    f = 1;
  }
  if ((mask & RUN_ENTRY_HIDDEN) && te.is_hidden != in->is_hidden) {
    te.is_hidden = in->is_hidden;
    f = 1;
  }
  if ((mask & RUN_ENTRY_READONLY) && te.is_readonly != in->is_readonly) {
    te.is_readonly = in->is_readonly;
    f = 1;
  }
  if ((mask & RUN_ENTRY_PAGES) && te.pages != in->pages) {
    te.pages = in->pages;
    f = 1;
  }
  if ((mask & RUN_ENTRY_SCORE_ADJ) && te.score_adj != in->score_adj) {
    te.score_adj = in->score_adj;
    f = 1;
  }

  /* check consistency of a new record */
  if (te.status == RUN_VIRTUAL_START || te.status == RUN_VIRTUAL_STOP
      || te.status == RUN_EMPTY) {
      err("run_set_entry: %d: special status cannot be set this way", run_id);
      return -1;
  }
  if (te.status > RUN_TRANSIENT_LAST
      || (te.status > RUN_PSEUDO_LAST && te.status < RUN_TRANSIENT_FIRST)
      || (te.status > RUN_MAX_STATUS && te.status < RUN_PSEUDO_FIRST)) {
    err("run_set_entry: %d: invalid status %d", run_id, te.status);
    return -1;
  }
  if (te.team <= 0 || te.team > RUNLOG_MAX_TEAM_ID) {
    err("run_set_entry: %d: invalid team %d", run_id, te.team);
    return -1;
  }

  if (!te.is_hidden) {
    ue = get_user_entry(te.team);
    if (ue->status == V_VIRTUAL_USER) {
      ASSERT(ue->start_time > 0);
      stop_time = ue->stop_time;
      if (!stop_time && head.duration > 0)
        stop_time = ue->start_time + head.duration;
      if (te.timestamp < ue->start_time) {
        err("run_set_entry: %d: timestamp < virtual start_time", run_id);
        return -1;
      }
      if (stop_time && te.timestamp > stop_time) {
        err("run_set_entry: %d: timestamp > virtual stop_time", run_id);
        return -1;
      }
    } else {
      stop_time = head.stop_time;
      if (!stop_time && head.duration > 0)
        stop_time = head.start_time + head.duration;
      if (te.timestamp < head.start_time) {
        err("run_set_entry: %d: timestamp < start_time", run_id);
        return -1;
      }
      if (stop_time && te.timestamp > stop_time) {
        err("run_set_entry: %d: timestamp > stop_time", run_id);
        return -1;
      }
    }
  }

  if (te.size > RUNLOG_MAX_SIZE) {
    err("run_set_entry: %d: size %u is invalid", run_id, te.size);
    return -1;
  }
  if (te.problem <= 0 || te.problem > RUNLOG_MAX_PROB_ID) {
    err("run_set_entry: %d: problem %d is invalid", run_id, te.problem);
    return -1;
  }
  if (te.score < -1 || te.score > RUNLOG_MAX_SCORE) {
    err("run_set_entry: %d: score %d is invalid", run_id, te.score);
    return -1;
  }
  if (te.locale_id < -1) {
    err("run_set_entry: %d: locale_id %d is invalid", run_id, te.locale_id);
    return -1;
  }
  if (te.language <= 0 || te.language >= 255) {
    err("run_set_entry: %d: language %d is invalid", run_id, te.language);
    return -1;
  }
  if (te.test < -1) {
    err("run_set_entry: %d: test %d is invalid", run_id, te.test);
    return -1;
  }
  if (te.is_imported != 0 && te.is_imported != 1) {
    err("run_set_entry: %d: is_imported %d is invalid", run_id,te.is_imported);
    return -1;
  }
  if (te.is_hidden != 0 && te.is_hidden != 1) {
    err("run_set_entry: %d: is_hidden %d is invalid", run_id, te.is_hidden);
    return -1;
  }
  if (te.is_imported && te.is_hidden) {
    err("run_set_entry: %d: is_hidden and is_imported both cannot be set",
        run_id);
    return -1;
  }
  if (te.is_readonly != 0 && te.is_readonly != 1) {
    err("run_set_entry: %d: is_readonly %d is invalid", run_id,te.is_readonly);
    return -1;
  }
  if (te.nsec < 0 || te.nsec >= 1000000000) {
    err("run_set_entry: %d: nsec %d is invalid", run_id, te.nsec);
    return -1;
  }

  memcpy(out, &te, sizeof(*out));
  if (!te.is_hidden && !ue->status) ue->status = V_REAL_USER;
  if (f && run_flush_entry(run_id) < 0) return -1;
  return 0;
}

static struct user_entry *
get_user_entry(int user_id)
{
  ASSERT(user_id > 0);

  if (user_id >= ut_size) {
    struct user_entry **new_ut_table = 0;
    int new_ut_size = ut_size;

    if (!new_ut_size) new_ut_size = 16;
    while (new_ut_size <= user_id)
      new_ut_size *= 2;
    new_ut_table = xcalloc(new_ut_size, sizeof(new_ut_table[0]));
    if (ut_size > 0) {
      memcpy(new_ut_table, ut_table, ut_size * sizeof(ut_table[0]));
    }
    ut_size = new_ut_size;
    xfree(ut_table);
    ut_table = new_ut_table;
    info("runlog: ut_table is extended to %d", ut_size);
  }

  if (!ut_table[user_id]) {
    ut_table[user_id] = xcalloc(1, sizeof(ut_table[user_id][0]));
  }
  return ut_table[user_id];
}

time_t
run_get_virtual_start_time(int user_id)
{
  struct user_entry *pvt = get_user_entry(user_id);
  if (pvt->status == V_REAL_USER) return head.start_time;
  return pvt->start_time;
}

time_t
run_get_virtual_stop_time(int user_id, time_t cur_time)
{
  struct user_entry *pvt = get_user_entry(user_id);
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
  struct user_entry *pvt = get_user_entry(user_id);
  return pvt->status;
}

int
run_virtual_start(int user_id, time_t t, ej_ip_t ip, int nsec)
{
  struct user_entry *pvt = get_user_entry(user_id);
  int i;

  if (!head.start_time) {
    err("run_virtual_start: the contest is not started");
    return -1;
  }
  ASSERT(head.start_time > 0);
  if (t < head.start_time) {
    err("run_virtual_start: timestamp < start_time");
    return -1;
  }
  if (pvt->status == V_REAL_USER) {
    err("run_virtual_start: user %d is not virtual", user_id);
    return -1;
  }
  if (pvt->status == V_VIRTUAL_USER) {
    err("run_virtual_start: virtual contest for %d already started", user_id);
    return -1;
  }
  if (nsec < 0 || nsec >= 1000000000) {
    err("run_virtual_start: nsec field value %d is invalid", nsec);
    return -1;
  }
  if ((i = append_record(t, user_id, nsec)) < 0) return -1;
  runs[i].team = user_id;
  runs[i].ip = ip;
  runs[i].status = RUN_VIRTUAL_START;
  pvt->start_time = t;
  pvt->status = V_VIRTUAL_USER;
  if (run_flush_entry(i) < 0) return -1;
  return i;
}

int
run_virtual_stop(int user_id, time_t t, ej_ip_t ip, int nsec)
{
  struct user_entry *pvt = get_user_entry(user_id);
  int i;
  time_t exp_stop_time = 0;

  if (!head.start_time) {
    err("run_virtual_stop: the contest is not started");
    return -1;
  }
  ASSERT(head.start_time > 0);
  if (t < head.start_time) {
    err("run_virtual_stop: timestamp < start_time");
    return -1;
  }
  if (pvt->status != V_VIRTUAL_USER) {
    err("run_virtual_stop: user %d is not virtual", user_id);
    return -1;
  }
  ASSERT(pvt->start_time > 0);
  if (pvt->stop_time) {
    err("run_virtual_stop: virtual contest for %d already stopped", user_id);
    return -1;
  }
  if (head.duration > 0) exp_stop_time = pvt->start_time + head.duration;
  if (t > exp_stop_time) {
    err("run_virtual_stop: the virtual time ended");
    return -1;
  }
  if (nsec < 0 || nsec >= 1000000000) {
    err("run_virtual_stop: nsec field value is invalid");
    return -1;
  }

  if ((i = append_record(t, user_id, nsec)) < 0) return -1;
  runs[i].team = user_id;
  runs[i].ip = ip;
  runs[i].status = RUN_VIRTUAL_STOP;
  pvt->stop_time = t;
  if (run_flush_entry(i) < 0) return -1;
  return i;
}

int
run_is_readonly(int run_id)
{
  if (run_id < 0 || run_id >= run_u) return 1;
  return runs[run_id].is_readonly;
}

int
run_clear_entry(int run_id)
{
  struct user_entry *ue;
  int i;

  if (run_id < 0 || run_id >= run_u) ERR_R("bad runid: %d", run_id);
  if (runs[run_id].is_readonly) ERR_R("run %d is readonly", run_id);
  switch (runs[run_id].status) {
  case RUN_EMPTY:
    memset(&runs[run_id], 0, sizeof(runs[run_id]));
    runs[run_id].status = RUN_EMPTY;
    runs[run_id].submission = run_id;
    break;
  case RUN_VIRTUAL_STOP:
    /* VSTOP events can safely be cleared */ 
    ue = get_user_entry(runs[run_id].team);
    ASSERT(ue->status == V_VIRTUAL_USER);
    ASSERT(ue->start_time > 0);
    ue->stop_time = 0;
    memset(&runs[run_id], 0, sizeof(runs[run_id]));
    runs[run_id].status = RUN_EMPTY;
    runs[run_id].submission = run_id;
    break;
  case RUN_VIRTUAL_START:
    /* VSTART event must be the only event of this team */
    for (i = 0; i < run_u; i++) {
      if (i == run_id) continue;
      if (runs[i].status == RUN_EMPTY) continue;
      if (runs[i].team == runs[run_id].team) break;
    }
    if (i < run_u) {
      err("run_clear_entry: VSTART must be the only record for a team");
      return -1;
    }
    ue = get_user_entry(runs[run_id].team);
    ASSERT(ue->status == V_VIRTUAL_USER);
    ASSERT(ue->start_time == runs[run_id].timestamp);
    ASSERT(!ue->stop_time);
    ue->status = 0;
    ue->start_time = 0;
    memset(&runs[run_id], 0, sizeof(runs[run_id]));
    runs[run_id].status = RUN_EMPTY;
    runs[run_id].submission = run_id;
    break;
  default:
    /* maybe update indices */
    memset(&runs[run_id], 0, sizeof(runs[run_id]));
    runs[run_id].status = RUN_EMPTY;
    runs[run_id].submission = run_id;
    break;
  }
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
      runs[j].submission = j;
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

void
run_clear_variables(void)
{
  int i;

  memset(&head, 0, sizeof(head));
  if (runs) xfree(runs);
  runs = 0;
  run_u = run_a = 0;
  if (run_fd >= 0) close(run_fd);
  run_fd = -1;
  if (ut_table) {
    for (i = 0; i < ut_size; i++) {
      if (ut_table[i]) xfree(ut_table[i]);
      ut_table[i] = 0;
    }
    xfree(ut_table);
  }
  ut_table = 0;
}

int
run_write_xml(FILE *f, int export_mode, time_t current_time)
{
  //int i;

  if (!head.start_time) {
    err("Contest is not yet started");
    return -1;
  }

  // this is not necessary such runs are ignored anyway
  /*
  for (i = 0; i < run_u; i++) {
    switch (runs[i].status) {
    case RUN_OK:
    case RUN_COMPILE_ERR:
    case RUN_RUN_TIME_ERR:
    case RUN_TIME_LIMIT_ERR:
    case RUN_PRESENTATION_ERR:
    case RUN_WRONG_ANSWER_ERR:
    case RUN_CHECK_FAILED:
    case RUN_PARTIAL:
    case RUN_ACCEPTED:
    case RUN_IGNORED:
    case RUN_EMPTY:
    case RUN_VIRTUAL_START:
    case RUN_VIRTUAL_STOP:
      break;
    default:
      err("run_write_xml: refuse to export XML: runs[%d].status == \"%s\"",
          i, run_status_str(runs[i].status, 0, 0));
      return -1;
    }
  }
  */

  unparse_runlog_xml(teamdb_state, f, &head, run_u, runs, export_mode,
                     current_time);
  return 0;
}

static void
check_msg(int is_err, FILE *flog, const unsigned char *format, ...)
{
  va_list args;
  unsigned char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  if (is_err) {
    err("%s", buf);
    if (flog) fprintf(flog, "Error: %s\n", buf);
  } else {
    info("%s", buf);
    if (flog) fprintf(flog, "%s\n", buf);
  }
}

int
runlog_check(FILE *ferr,
             struct run_header *phead,
             size_t nentries,
             struct run_entry *pentries)
{
  int i, j;
  int max_team_id;
  struct user_entry *ventries, *v;
  struct run_entry *e;
  int nerr = 0;
  struct run_entry te;
  unsigned char *pp;
  time_t prev_time = 0;
  time_t stop_time = 0, v_stop_time;
  int retcode = 0;
  int prev_nsec = 0;

  ASSERT(phead);

  if (phead->start_time < 0) {
    check_msg(1, ferr, "Start time %ld is before the epoch",phead->start_time);
    return -1;
  }
  if (phead->stop_time < 0) {
    check_msg(1,ferr, "Stop time %ld is before the epoch", phead->stop_time);
    return -1;
  }
  if (phead->duration < -1) {
    check_msg(1,ferr, "Contest duration %ld is negative", phead->duration);
    return -1;
  }
  if (!phead->start_time && phead->stop_time) {
    check_msg(1,ferr, "Contest start time is not set, but stop time is set!");
    return -1;
  }
  if (phead->start_time && phead->stop_time
      && phead->start_time > phead->stop_time) {
    check_msg(1,ferr, "Contest stop time %ld is less than start time %ld",
              phead->stop_time, phead->start_time);
    return -1;
  }
  if (!nentries) {
    check_msg(0,ferr, "The runlog is empty");
    return 0;
  }
  /*
  if (!phead->start_time) {
    check_msg(1,ferr, "Start time is not set, but runs present");
    return -1;
  }
  */

  /* check local consistency of fields */
  for (i = 0; i < nentries; i++) {
    e = &pentries[i];
    if (e->status > RUN_TRANSIENT_LAST
        || (e->status > RUN_PSEUDO_LAST && e->status < RUN_TRANSIENT_FIRST)
        || (e->status > RUN_MAX_STATUS && e->status < RUN_PSEUDO_FIRST)) {
      check_msg(1,ferr, "Run %d invalid status %d", i, e->status);
      nerr++;
      continue;
    }

    if (e->status == RUN_EMPTY) {
      if (i > 0 && !e->submission) {
        check_msg(0,ferr, "Run %d submission for EMPTY is not set", i);
        e->submission = i;
      } else if (e->submission != i) {
        check_msg(1,ferr, "Run %d submission %d does not match index",
                  i, e->submission);
        e->submission = i;
        retcode = 1;
        //nerr++;
        //continue;
      }
      /* kinda paranoia */
      memcpy(&te, e, sizeof(te));
      te.submission = 0;
      te.status = 0;
      pp = (unsigned char *) &te;
      for (j = 0; j < sizeof(te) && !pp[j]; j++);
      if (j < sizeof(te)) {
        check_msg(1,ferr, "Run %d is EMPTY and contain garbage", i);
        nerr++;
        continue;
      }
      continue;
    }

    if (e->submission != i) {
      check_msg(1,ferr, "Run %d submission %d does not match index",
                i, e->submission);
      e->submission = i;
      retcode = 1;
      //nerr++;
      //continue;
    }
    if (e->team <= 0) {
      check_msg(1,ferr, "Run %d team %d is invalid", i, e->team);
      nerr++;
      continue;
    }
    if (e->timestamp < 0) {
      check_msg(1, ferr, "Run %d timestamp %ld is negative", i, e->timestamp);
      nerr++;
      continue;
    }
    if (!e->timestamp) {
      check_msg(1, ferr, "Run %d timestamp is not set", i);
      nerr++;
      continue;
    }
    if (e->timestamp < prev_time) {
      check_msg(1, ferr, "Run %d timestamp %ld is less than previous %ld",
                i, e->timestamp, prev_time);
      nerr++;
      continue;
    }
    if (e->timestamp == prev_time && e->nsec < prev_nsec) {
      check_msg(1, ferr, "Run %d nsec %d is less than previous %d",
                i, e->nsec, prev_nsec);
    }
    prev_time = e->timestamp;
    prev_nsec = e->nsec;

    if (e->status == RUN_VIRTUAL_START || e->status == RUN_VIRTUAL_STOP) {
      /* kinda paranoia */
      memcpy(&te, e, sizeof(te));
      te.submission = 0;
      te.status = 0;
      te.team = 0;
      te.timestamp = 0;
      te.nsec = 0;
      te.ip = 0;
      pp = (unsigned char *) &te;
      for (j = 0; j < sizeof(te) && !pp[j]; j++);
      if (j < sizeof(te)) {
        check_msg(1,ferr, "Run %d is virtual and contain garbage at byte %d",
                  i, j);
        nerr++;
      }
      continue;
    }

    /* a regular or transient run */
    if (e->size > RUNLOG_MAX_SIZE) {
      check_msg(1, ferr, "Run %d has huge size %zu", i, e->size);
      nerr++;
      continue;
    }
    if (!e->ip) {
      check_msg(0, ferr, "Run %d IP is not set", i);
    }
    if (!e->sha1[0]&&!e->sha1[1]&&!e->sha1[2]&&!e->sha1[3]&&!e->sha1[4]) {
      //check_msg(0, ferr, "Run %d SHA1 is not set", i);
    }
    if (e->problem <= 0) {
      check_msg(1, ferr, "Run %d problem %d is invalid", i, e->problem);
      nerr++;
      continue;
    }
    if (e->problem > RUNLOG_MAX_PROB_ID) {
      check_msg(1, ferr, "Run %d problem %d is too large", i, e->problem);
      nerr++;
      continue;
    }
    if (e->score < -1) {
      check_msg(1, ferr, "Run %d score %d is invalid", i, e->score);
      nerr++;
      continue;
    }
    if (e->score > RUNLOG_MAX_SCORE) {
      check_msg(1, ferr, "Run %d score %d is too large", i, e->score);
      nerr++;
      continue;
    }
    if (e->locale_id < -1) {
      check_msg(1, ferr, "Run %d locale_id %d is invalid", i, e->locale_id);
      nerr++;
      continue;
    }
    if (e->language == 0 || e->language == 255) {
      check_msg(1, ferr, "Run %d language %d is invalid", i, e->language);
      nerr++;
      continue;
    }
    if (e->test < -1) {
      check_msg(1, ferr, "Run %d test %d is invalid", i, e->test);
      nerr++;
      continue;
    }
    if (e->is_imported != 0 && e->is_imported != 1) {
      check_msg(1,ferr, "Run %d is_imported %d is invalid", i, e->is_imported);
      nerr++;
      continue;
    }
    if (e->is_readonly != 0 && e->is_readonly != 1) {
      check_msg(1,ferr, "Run %d is_readonly %d is invalid",i,e->is_readonly);
      nerr++;
      continue;
    }
    if (e->nsec < 0 || e->nsec >= 1000000000) {
      check_msg(1,ferr, "Run %d nsec %d is invalid", i, e->nsec);
      nerr++;
      continue;
    }
  } /* end of local consistency check */

  /* do not continue check in case of errors */
  if (nerr > 0) return -1;

  max_team_id = -1;
  for (i = 0; i < nentries; i++) {
    if (pentries[i].status == RUN_EMPTY) continue;
    if (pentries[i].team > max_team_id) max_team_id = pentries[i].team;
  }
  if (max_team_id == -1) {
    check_msg(0,ferr, "The runlog contains only EMPTY records");
    return 0;
  }
  ventries = alloca((max_team_id + 1) * sizeof(ventries[0]));
  memset(ventries, 0, (max_team_id + 1) * sizeof(ventries[0]));

  stop_time = phead->stop_time;
  if (!stop_time && phead->start_time && phead->duration) {
    // this may be in future
    stop_time = phead->start_time + phead->duration;
  }

  for (i = 0; i < nentries; i++) {
    e = &pentries[i];
    if (e->is_hidden) continue;
    switch (e->status) {
    case RUN_EMPTY: break;
    case RUN_VIRTUAL_START:
      ASSERT(e->team <= max_team_id);
      v = &ventries[e->team];
      if (v->status == V_VIRTUAL_USER) {
        ASSERT(v->start_time > 0);
        check_msg(1, ferr, "Run %d: duplicated VSTART", i);
        nerr++;
        continue;
      } else if (v->status == V_REAL_USER) {
        ASSERT(!v->start_time);
        ASSERT(!v->stop_time);
        check_msg(1, ferr, "Run %d: VSTART for non-virtual user", i);
        nerr++;
        continue;
      } else {
        ASSERT(!v->start_time);
        v->status = V_VIRTUAL_USER;
        v->start_time = e->timestamp;
      }
      break;
    case RUN_VIRTUAL_STOP:
      ASSERT(e->team <= max_team_id);
      v = &ventries[e->team];
      ASSERT(v->status >= 0 && v->status <= V_LAST);
      if (v->status == V_VIRTUAL_USER) {
        ASSERT(v->start_time > 0);
        ASSERT(v->stop_time >= 0);
        if (v->stop_time) {
          check_msg(1, ferr, "Run %d: duplicated VSTOP", i);
          nerr++;
          continue;
        }
        if (phead->duration
            && e->timestamp > v->start_time + phead->duration) {
          check_msg(1, ferr, "Run %d: VSTOP after expiration of contest", i);
          nerr++;
          continue;
        }
        v->stop_time = e->timestamp;
      } else {
        ASSERT(!v->start_time);
        ASSERT(!v->stop_time);
        ASSERT(v->status == 0 || v->status == V_REAL_USER);
        check_msg(1, ferr, "Run %d: unexpected VSTOP without VSTART", i);
        nerr++;
        continue;
      }
      break;
    default:
      ASSERT(e->team <= max_team_id);
      v = &ventries[e->team];
      ASSERT(v->status >= 0 && v->status <= V_LAST);
      if (v->status == V_VIRTUAL_USER) {
        ASSERT(v->start_time > 0);
        ASSERT(v->stop_time >= 0);
        v_stop_time = v->stop_time;
        if (!v_stop_time && phead->duration)
          v_stop_time = v->start_time + phead->duration;
        if (e->timestamp < v->start_time) {
          check_msg(1, ferr,
                    "Run %d timestamp %ld is less that virtual start %ld",
                    i, e->timestamp, v->start_time);
          nerr++;
          continue;
        }
        if (v_stop_time && e->timestamp > v_stop_time) {
          check_msg(1, ferr,
                    "Run %d timestamp %ld is greater than virtual stop %ld",
                    i, e->timestamp, v_stop_time);
          nerr++;
          continue;
        }
      } else {
        ASSERT(!v->start_time);
        ASSERT(!v->stop_time);
        ASSERT(v->status == 0 || v->status == V_REAL_USER);
        if (e->timestamp < phead->start_time) {
          check_msg(1,ferr,
                    "Run %d timestamp %ld is less than contest start %ld",
                    i, e->timestamp, phead->start_time);
          nerr++;
          continue;
        }
        if (stop_time && e->timestamp > stop_time) {
          check_msg(1, ferr,
                    "Run %d timestamp %ld is greater than contest stop %ld",
                    i, e->timestamp, stop_time);
          nerr++;
          continue;
        }
        v->status = V_REAL_USER;
      }
      break;
    }
  }

  if (nerr > 0) return -1;

  return retcode;
}

static void
build_indices(void)
{
  int i;
  int max_team_id = -1;
  struct user_entry *ue;

  if (ut_table) {
    for (i = 0; i < ut_size; i++)
      xfree(ut_table[i]);
    xfree(ut_table);
    ut_table = 0;
  }
  ut_size = 0;
  ut_table = 0;

  /* assume, that the runlog is consistent
   * scan the whole runlog and build various indices
   */
  for (i = 0; i < run_u; i++) {
    if (runs[i].status == RUN_EMPTY) continue;
    ASSERT(runs[i].team > 0);
    if (runs[i].team > max_team_id) max_team_id = runs[i].team;
  }
  if (max_team_id <= 0) return;

  ut_size = 128;
  while (ut_size <= max_team_id)
    ut_size *= 2;

  XCALLOC(ut_table, ut_size);
  for (i = 0; i < run_u; i++) {
    if (runs[i].is_hidden) continue;
    switch (runs[i].status) {
    case RUN_EMPTY:
      break;
    case RUN_VIRTUAL_START:
      ue = get_user_entry(runs[i].team);
      ASSERT(!ue->status);
      ue->status = V_VIRTUAL_USER;
      ue->start_time = runs[i].timestamp;
      break;
    case RUN_VIRTUAL_STOP:
      ue = get_user_entry(runs[i].team);
      ASSERT(ue->status == V_VIRTUAL_USER);
      ASSERT(ue->start_time > 0);
      ue->stop_time = runs[i].timestamp;
      break;
    default:
      ue = get_user_entry(runs[i].team);
      if (!ue->status) ue->status = V_REAL_USER;
      break;
    }
  }
}

int
run_get_pages(int run_id)
{
  if (run_id < 0 || run_id >= run_u) ERR_R("bad runid: %d", run_id);
  return runs[run_id].pages;
}

int
run_set_pages(int run_id, int pages)
{
  if (run_id < 0 || run_id >= run_u) ERR_R("bad runid: %d", run_id);
  if (pages < 0 || pages > 255) ERR_R("bad pages: %d", pages);
  runs[run_id].pages = pages;
  run_flush_entry(run_id);
  return 0;
}

int
run_get_total_pages(int user_id)
{
  int i, total = 0;

  if (user_id <= 0 || user_id > 100000) ERR_R("bad user_id: %d", user_id);
  for (i = 0; i < run_u; i++) {
    if (runs[i].status == RUN_VIRTUAL_START || runs[i].status == RUN_VIRTUAL_STOP
        || runs[i].status == RUN_EMPTY) continue;
    if (runs[i].team != user_id) continue;
    total += runs[i].pages;
  }
  return total;
}

int
run_find(int first_run, int last_run,
         int team_id, int prob_id, int lang_id)
{
  int i;

  if (!run_u) return -1;

  if (first_run < 0) first_run = run_u + first_run;
  if (first_run < 0) first_run = 0;
  if (first_run >= run_u) first_run = run_u - 1;

  if (last_run < 0) last_run = run_u + last_run;
  if (last_run < 0) last_run = 0;
  if (last_run >= run_u) last_run = run_u - 1;

  if (first_run <= last_run) {
    for (i = first_run; i <= last_run; i++) {
      if (team_id && team_id != runs[i].team) continue;
      if (prob_id && prob_id != runs[i].problem) continue;
      if (lang_id && lang_id != runs[i].language) continue;
      return i;
    }
  } else {
    for (i = first_run; i >= last_run; i--) {
      if (team_id && team_id != runs[i].team) continue;
      if (prob_id && prob_id != runs[i].problem) continue;
      if (lang_id && lang_id != runs[i].language) continue;
      return i;
    }
  }
  return -1;
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
  [RUN_IGNORED]          = 1,
  [RUN_DISQUALIFIED]     = 1,
  [RUN_PENDING]          = 1,
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
static struct str_to_status_data
{
  unsigned char str[4];
  int value;
} str_to_status_table[] =
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

static void
teamdb_update_callback(void *user_ptr)
{
  // invalidate user_flags
  xfree(user_flags.flags);
  memset(&user_flags, 0, sizeof(user_flags));
  user_flags.nuser = -1;
}

static int
update_user_flags(void)
{
  int size = 0;
  int *map = 0;

  if (user_flags.nuser >= 0) return 0;
  if (teamdb_get_user_status_map(teamdb_state, &size, &map) < 0) return -1;
  user_flags.nuser = size;
  user_flags.flags = map;
  return 1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
