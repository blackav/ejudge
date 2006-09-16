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

struct run_header_v1
{
  int    version;
  ej_time_t start_time;
  ej_time_t sched_time;
  ej_time_t duration;
  ej_time_t stop_time;
  unsigned char pad[44];
};

struct run_entry_v1
{
  rint32_t       submission;
  ej_time_t      timestamp;
  ej_size_t      size;
  ej_ip_t        ip;
  ruint32_t      sha1[5];
  rint32_t       team;
  rint32_t       problem;
  rint32_t       score;
  signed char    locale_id;
  unsigned char  language;
  unsigned char  status;
  signed char    test;
  unsigned char  is_imported;
  unsigned char  variant;
  unsigned char  is_hidden;
  unsigned char  is_readonly;
  unsigned char  pages;
  signed char    score_adj;     /* manual score adjustment */
  unsigned short judge_id;      /* judge required identifier */
  rint32_t       nsec;          /* nanosecond component of timestamp */
};

#define RUNLOG_MAX_SIZE    (1024 * 1024)
#define RUNLOG_MAX_TEAM_ID 100000
#define RUNLOG_MAX_PROB_ID 100000
#define RUNLOG_MAX_SCORE   100000

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

struct user_flags_info_s
{
  int nuser;
  int *flags;
};

struct runlog_state
{
  struct run_header  head;
  struct run_entry  *runs;
  int                run_u;
  int                run_a;
  int                run_fd;
  teamdb_state_t     teamdb_state;
  int ut_size;
  struct user_entry **ut_table;
  struct user_flags_info_s user_flags;
};

static int update_user_flags(runlog_state_t state);
static void build_indices(runlog_state_t state);
static struct user_entry *get_user_entry(runlog_state_t state, int user_id);

runlog_state_t
run_init(teamdb_state_t ts)
{
  runlog_state_t p;

  XCALLOC(p, 1);
  p->teamdb_state = ts;
  p->run_fd = -1;
  p->user_flags.nuser = -1;

  return p;
}

runlog_state_t
run_destroy(runlog_state_t state)
{
  int i;
  struct user_entry *ue;

  if (!state) return 0;
  xfree(state->runs);
  if (state->run_fd >= 0) close(state->run_fd);
  for (i = 0; i < state->ut_size; i++) {
    if (!(ue = state->ut_table[i])) continue;
    xfree(ue);
  }
  xfree(state->ut_table);
  xfree(state->user_flags.flags);

  memset(state, 0, sizeof(*state));
  xfree(state);
  return 0;
}

static int
run_read_record_v0(runlog_state_t state, char *buf, int size)
{
  int  rsz;
  int  i;

  if ((rsz = sf_read(state->run_fd, buf, size, "run")) < 0) return -1;
  if (rsz != size) ERR_R("short read: %d", rsz);
  for (i = 0; i < size - 1; i++) {
    if (buf[i] >= 0 && buf[i] < ' ') break;
  }
  if (i < size - 1) ERR_R("bad characters in record");
  if (buf[size - 1] != '\n') ERR_R("record improperly terminated");
  return 0;
}

static int
run_read_header_v0(runlog_state_t state)
{
  char buf[RUN_HEADER_SIZE + 16];
  int  n, r;

  memset(buf, 0, sizeof(buf));
  if (run_read_record_v0(state, buf, RUN_HEADER_SIZE) < 0) return -1;
  r = sscanf(buf, " %lld %lld %lld %lld %n",
             &state->head.start_time,
             &state->head.sched_time,
             &state->head.duration,
             &state->head.stop_time, &n);
  if (r != 4) ERR_R("sscanf returned %d", r);
  if (buf[n] != 0) ERR_R("excess data: %d", n);
  return 0;
}

static int
run_read_entry_v0(runlog_state_t state, int n)
{
  char buf[RUN_RECORD_SIZE + 16];
  char tip[RUN_RECORD_SIZE + 16];
  int  k, r;

  memset(buf, 0, sizeof(buf));
  if (run_read_record_v0(state, buf, RUN_RECORD_SIZE) < 0) return -1;
  r = sscanf(buf, " %lld %d %u %hd %d %d %d %hhu %d %d %s %n",
             &state->runs[n].time, &state->runs[n].run_id,
             &state->runs[n].size, &state->runs[n].locale_id,
             &state->runs[n].user_id, &state->runs[n].lang_id,
             &state->runs[n].prob_id, &state->runs[n].status,
             &state->runs[n].test, &state->runs[n].score, tip, &k);
  if (r != 11) ERR_R("[%d]: sscanf returned %d", n, r);
  if (buf[k] != 0) ERR_R("[%d]: excess data", n);
  if (strlen(tip) > RUN_MAX_IP_LEN) ERR_R("[%d]: ip is to long", n);
  state->runs[n].a.ip = run_parse_ip(tip);
  if (state->runs[n].a.ip == (ej_ip_t) -1) ERR_R("[%d]: cannot parse IP");
  return 0;
}

static int
is_runlog_version_0(runlog_state_t state)
{
  unsigned char buf[RUN_HEADER_SIZE + 16];
  int r, n;
  time_t v1, v2, v3, v4;

  memset(buf, 0, sizeof(buf));
  if (sf_lseek(state->run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;
  if ((r = sf_read(state->run_fd, buf, RUN_HEADER_SIZE, "run")) < 0) return -1;
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
read_runlog_version_0(runlog_state_t state)
{
  off_t filesize;
  int i;

  info("reading runs log version 0");

  /* calculate the size of the file */
  if ((filesize = sf_lseek(state->run_fd, 0, SEEK_END, "run")) == (off_t) -1)
    return -1;
  if (sf_lseek(state->run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;

  info("runs file size: %lu", filesize);
  if (filesize == 0) {
    /* runs file is empty */
    XMEMZERO(&state->head, 1);
    state->run_u = 0;
    return 0;
  }

  if ((filesize - RUN_HEADER_SIZE) % RUN_RECORD_SIZE != 0)
    ERR_C("bad runs file size: remainder %d", (filesize - RUN_HEADER_SIZE) % RUN_RECORD_SIZE);

  state->run_u = (filesize - RUN_HEADER_SIZE) / RUN_RECORD_SIZE;
  state->run_a = 128;
  while (state->run_u > state->run_a) state->run_a *= 2;
  XCALLOC(state->runs, state->run_a);

  if (run_read_header_v0(state) < 0) goto _cleanup;
  for (i = 0; i < state->run_u; i++) {
    if (run_read_entry_v0(state, i) < 0) goto _cleanup;
  }
  if (runlog_check(0, &state->head, state->run_u, state->runs) < 0)
    goto _cleanup;
  build_indices(state);

  return 0;

 _cleanup:
  XMEMZERO(&state->head, 1);
  if (state->runs) {
    xfree(state->runs); state->runs = 0; state->run_u = state->run_a = 0;
  }
  if (state->run_fd >= 0) {
    close(state->run_fd);
    state->run_fd = -1;
  }
  return -1;
}

static int
is_runlog_version_1(runlog_state_t state)
{
  struct run_header_v1 header_v1;
  struct stat stbuf;
  int r;

  memset(&header_v1, 0, sizeof(header_v1));
  if (sf_lseek(state->run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;
  if ((r = sf_read(state->run_fd, &header_v1, sizeof(header_v1), "run")) < 0)
    return -1;
  if (r != sizeof(header_v1)) return 0;
  if (header_v1.version != 1) return 0;
  if (fstat(state->run_fd, &stbuf) < 0) return -1;
  if (stbuf.st_size < sizeof(header_v1)) return 0;
  stbuf.st_size -= sizeof(header_v1);
  if (stbuf.st_size % sizeof(struct run_entry_v1) != 0) return 0;
  return 1;
}

static int
save_runlog_backup(const unsigned char *path, const unsigned char *suffix)
{
  unsigned char *back;
  size_t len;
  if (!suffix) suffix = ".bak";

  len = strlen(path);
  back = alloca(len + 16);
  sprintf(back, "%s%s", path, suffix);
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
read_runlog_version_1(runlog_state_t state)
{
  int rem;
  int r;
  struct stat stbuf;
  struct run_header_v1 header_v1;
  int run_v1_u, i;
  struct run_entry_v1 *runs_v1;
  struct run_entry_v1 *po;
  struct run_entry    *pn;

  info("reading runs log version 1 (binary)");

  /* calculate the size of the file */
  if (fstat(state->run_fd, &stbuf) < 0) {
    err("read_runlog_version_1: fstat() failed: %s", os_ErrorMsg());
    return -1;
  }
  if (sf_lseek(state->run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;
  if (stbuf.st_size < sizeof (header_v1)) {
    err("read_runlog_version_1: file is too small");
    return -1;
  }

  // read header
  if (do_read(state->run_fd, &header_v1, sizeof(header_v1)) < 0) return -1;
  info("run log version %d", header_v1.version);
  if (header_v1.version != 1) {
    err("unsupported run log version %d", state->head.version);
    return -1;
  }

  stbuf.st_size -= sizeof(header_v1);
  if (stbuf.st_size % sizeof(struct run_entry_v1) != 0) {
    err("bad runs file size: remainder %d", rem);
    return -1;
  }
  run_v1_u = stbuf.st_size / sizeof(struct run_entry_v1);
  if (run_v1_u > 0) {
    XCALLOC(runs_v1, run_v1_u);
    if (do_read(state->run_fd, runs_v1, sizeof(runs_v1[0]) * run_v1_u) < 0)
      return -1;
  }

  // assign the header
  memset(&state->head, 0, sizeof(state->head));
  state->head.version = 2;
  state->head.byte_order = 0;
  state->head.start_time = header_v1.start_time;
  state->head.sched_time = header_v1.sched_time;
  state->head.duration = header_v1.duration;
  state->head.stop_time = header_v1.stop_time;

  // copy version 1 runlog to version 2 runlog
  state->run_a = 128;
  state->run_u = run_v1_u;
  while (run_v1_u > state->run_a) state->run_a *= 2;
  XCALLOC(state->runs, state->run_a);

  for (i = 0; i < state->run_u; i++) {
    po = &runs_v1[i];
    pn = &state->runs[i];

    pn->run_id = po->submission;
    pn->time = po->timestamp;
    pn->size = po->size;
    pn->a.ip = po->ip;
    memcpy(&pn->sha1, &po->sha1, sizeof(pn->sha1));
    pn->user_id = po->team;
    pn->prob_id = po->problem;
    pn->score = po->score;
    pn->locale_id = po->locale_id;
    pn->lang_id = po->language;
    pn->status = po->status;
    pn->test = po->test;
    pn->is_imported = po->is_imported;
    pn->variant = po->variant;
    pn->is_hidden = po->is_hidden;
    pn->is_readonly = po->is_readonly;
    pn->pages = po->pages;
    pn->score_adj = po->score_adj;
    pn->judge_id = po->judge_id;
    pn->nsec = po->nsec;
  }

  xfree(runs_v1);
  if ((r = runlog_check(0, &state->head, state->run_u,
                        state->runs)) < 0) return -1;

  build_indices(state);
  return 0;
}

static int
write_full_runlog_current_version(runlog_state_t state, const char *path)
{
  int run_fd;

  if ((run_fd = sf_open(path, O_RDWR | O_CREAT | O_TRUNC, 0666)) < 0)
    return -1;

  state->head.version = 2;
  if (do_write(run_fd, &state->head, sizeof(state->head)) < 0) return -1;
  if (state->run_u > 0) {
    if (do_write(run_fd, state->runs, sizeof(state->runs[0]) * state->run_u) < 0) return -1;
  }

  return run_fd;
}

int
run_set_runlog(runlog_state_t state,
               int total_entries, struct run_entry *entries)
{
  if (runlog_check(0, &state->head, total_entries, entries) < 0)
    return -1;

  if (total_entries > state->run_a) {
    if (!state->run_a) state->run_a = 128;
    xfree(state->runs);
    while (total_entries > state->run_a) state->run_a *= 2;
    state->runs = xcalloc(state->run_a, sizeof(state->runs[0]));
  } else {
    memset(state->runs, 0, state->run_a * sizeof(state->runs[0]));
  }
  state->run_u = total_entries;
  if (state->run_u > 0) {
    memcpy(state->runs, entries, state->run_u * sizeof(state->runs[0]));
  }
  sf_lseek(state->run_fd, sizeof(struct run_header), SEEK_SET, "run");
  do_write(state->run_fd, state->runs, sizeof(state->runs[0]) * state->run_u);
  ftruncate(state->run_fd,
            sizeof(state->runs[0]) * state->run_u + sizeof(struct run_header));
  build_indices(state);
  return 0;
}

static int run_flush_header(runlog_state_t state);

static int
read_runlog(runlog_state_t state, time_t init_duration)
{
  off_t filesize;
  int rem;
  int r;

  info("reading runs log (binary)");

  /* calculate the size of the file */
  if ((filesize = sf_lseek(state->run_fd, 0, SEEK_END, "run")) == (off_t) -1)
    return -1;
  if (sf_lseek(state->run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;

  info("runs file size: %ld", filesize);
  if (filesize == 0) {
    /* runs file is empty */
    XMEMZERO(&state->head, 1);
    state->head.version = 2;
    state->head.duration = init_duration;
    state->run_u = 0;
    run_flush_header(state);
    return 0;
  }

  if (sizeof(struct run_entry) != 128) abort();

  // read header
  if (do_read(state->run_fd, &state->head, sizeof(state->head)) < 0) return -1;
  info("run log version %d", state->head.version);
  if (state->head.version != 2) {
    err("unsupported run log version %d", state->head.version);
    return -1;
  }

  rem = (filesize - sizeof(struct run_header)) % sizeof(struct run_entry);
  if (rem != 0) ERR_C("bad runs file size: remainder %d", rem);

  state->run_u = (filesize - sizeof(struct run_header)) / sizeof(struct run_entry);
  state->run_a = 128;
  while (state->run_u > state->run_a) state->run_a *= 2;
  XCALLOC(state->runs, state->run_a);
  if (state->run_u > 0) {
    if (do_read(state->run_fd, state->runs, sizeof(state->runs[0]) * state->run_u) < 0) return -1;
  }
  if ((r = runlog_check(0, &state->head, state->run_u, state->runs)) < 0) return -1;
  if (r > 0) runlog_flush(state);
  build_indices(state);
  return 0;

 _cleanup:
  XMEMZERO(&state->head, 1);
  if (state->runs) {
    xfree(state->runs); state->runs = 0; state->run_u = state->run_a = 0;
  }
  if (state->run_fd >= 0) {
    close(state->run_fd);
    state->run_fd = -1;
  }
  return -1;
}

static void teamdb_update_callback(void *);

int
run_open(runlog_state_t state, const char *path, int flags,
         time_t init_duration)
{
  int           oflags = 0;
  int           i;

  teamdb_register_update_hook(state->teamdb_state, teamdb_update_callback,
                              state);
  if (state->runs) {
    xfree(state->runs); state->runs = 0; state->run_u = state->run_a = 0;
  }
  if (state->run_fd >= 0) {
    close(state->run_fd);
    state->run_fd = -1;
  }
  if (flags == RUN_LOG_READONLY) {
    oflags = O_RDONLY;
  } else if (flags == RUN_LOG_CREATE) {
    oflags = O_RDWR | O_CREAT | O_TRUNC;
  } else {
    oflags = O_RDWR | O_CREAT;
  }
  if ((state->run_fd = sf_open(path, oflags, 0666)) < 0) return -1;

  if ((i = is_runlog_version_0(state)) < 0) return -1;
  else if (i) {
    if (read_runlog_version_0(state) < 0) return -1;
    if (flags != RUN_LOG_READONLY) {
      if (save_runlog_backup(path, 0) < 0) return -1;
      close(state->run_fd);
      if ((state->run_fd = write_full_runlog_current_version(state, path)) < 0)
        return -1;
    }
  } else if ((i = is_runlog_version_1(state)) < 0) return -1;
  else if (i) {
    if (read_runlog_version_1(state) < 0) return -1;
    if (flags != RUN_LOG_READONLY) {
      if (save_runlog_backup(path, ".v1") < 0) return -1;
      close(state->run_fd);
      if ((state->run_fd = write_full_runlog_current_version(state, path)) < 0)
        return -1;
    }
  } else {
    if (read_runlog(state, init_duration) < 0) return -1;
  }
  return 0;
}

int
run_backup(runlog_state_t state, const unsigned char *path)
{
  unsigned char *newlog;
  int i = 1, r;
  struct stat sb;

  if (!path) ERR_R("invalid path");
  newlog = alloca(strlen(path) + 16);
  do {
    sprintf(newlog, "%s.%d", path, i++);
  } while (stat(newlog, &sb) >= 0);
  r = write_full_runlog_current_version(state, newlog);
  if (r < 0) return r;
  close(r);
  return 0;
}

static int
run_flush_entry(runlog_state_t state, int num)
{
  if (state->run_fd < 0) ERR_R("invalid descriptor %d", state->run_fd);
  if (num < 0 || num >= state->run_u) ERR_R("invalid entry number %d", num);
  if (sf_lseek(state->run_fd, sizeof(state->head) + sizeof(state->runs[0]) * num,
               SEEK_SET, "run") == (off_t) -1) return -1;
  if (do_write(state->run_fd, &state->runs[num], sizeof(state->runs[0])) < 0) return -1;
  return 0;
}

int
runlog_flush(runlog_state_t state)
{
  if (state->run_fd < 0) ERR_R("invalid descriptor %d", state->run_fd);
  if (sf_lseek(state->run_fd, sizeof(state->head), SEEK_SET, "run") == (off_t) -1) return -1;
  if (do_write(state->run_fd, state->runs, state->run_u * sizeof(state->runs[0])) < 0) return -1;
  return 0;
}

static int
append_record(runlog_state_t state, time_t t, int uid, int nsec)
{
  int i, j, k;

  ASSERT(state->run_u <= state->run_a);
  if (state->run_u == state->run_a) {
    if (!(state->run_a *= 2)) state->run_a = 128;
    state->runs = xrealloc(state->runs, state->run_a * sizeof(state->runs[0]));
    memset(&state->runs[state->run_u], 0, (state->run_a - state->run_u) * sizeof(state->runs[0]));
    info("append_record: array extended: %d", state->run_a);
  }

  while (1) {
    if (state->run_u > 0) {
      if (state->runs[state->run_u - 1].time > t) break;
      if (state->runs[state->run_u - 1].time == t) {
        if (state->runs[state->run_u - 1].nsec > nsec) break;
        if (state->runs[state->run_u - 1].nsec == nsec) {
          if (state->runs[state->run_u - 1].user_id > uid) break;
        }
      }
    }

    /* it is safe to insert a record at the end */
    memset(&state->runs[state->run_u], 0, sizeof(state->runs[0]));
    state->runs[state->run_u].run_id = state->run_u;
    state->runs[state->run_u].status = RUN_EMPTY;
    state->runs[state->run_u].time = t;
    state->runs[state->run_u].nsec = nsec;
    return state->run_u++;
  }

  i = 0, j = state->run_u - 1;
  while (i < j) {
    k = (i + j) / 2;
    if (state->runs[k].time > t
        || (state->runs[k].time == t && state->runs[k].nsec > nsec)
        || (state->runs[k].time == t && state->runs[k].nsec == nsec
            && state->runs[k].user_id > uid)) {
      j = k;
    } else {
      i = k + 1;
    }
  }
  ASSERT(i == j);
  ASSERT(i < state->run_u);
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
  for (j = i; j < state->run_u; j++)
    if (state->runs[j].status >= RUN_TRANSIENT_FIRST
        && state->runs[j].status <= RUN_TRANSIENT_LAST)
      break;
  if (j < state->run_u) {
    err("append_record: cannot safely insert a run at position %d", i);
    err("append_record: the run %d is transient!", j);
    return -1;
  }

  memmove(&state->runs[i + 1], &state->runs[i], (state->run_u - i) * sizeof(state->runs[0]));
  state->run_u++;
  for (j = i + 1; j < state->run_u; j++)
    state->runs[j].run_id = j;

  memset(&state->runs[i], 0, sizeof(state->runs[0]));
  state->runs[i].run_id = i;
  state->runs[i].status = RUN_EMPTY;
  state->runs[i].time = t;
  state->runs[i].nsec = nsec;
  if (sf_lseek(state->run_fd, sizeof(state->head) + i * sizeof(state->runs[0]), SEEK_SET,
               "run") == (off_t) -1) return -1;
  if (do_write(state->run_fd, &state->runs[i], (state->run_u - i) * sizeof(state->runs[0])) < 0)
    return -1;
  return i;
}

int
run_add_record(runlog_state_t state,
               time_t         timestamp,
               int            nsec,
               size_t         size,
               ruint32_t      sha1[5],
               ruint32_t      ip,
               int            locale_id,
               int            team,
               int            problem,
               int            language,
               int            variant,
               int            is_hidden,
               int            mime_type)
{
  int i;
  struct user_entry *ue;
  time_t stop_time;

  if (timestamp <= 0) {
    err("run_add_record: invalid timestamp %ld", timestamp);
    return -1;
  }
  if (!is_hidden) {
    if (!state->head.start_time) {
      err("run_add_record: contest is not yet started");
      return -1;
    }
    if (timestamp < state->head.start_time) {
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
  if (mime_type < 0 || mime_type > 32767) {
    err("run_add_record: mime_type field value %d is invalid", mime_type);
    return -1;
  }

  if (!is_hidden) {
    ue = get_user_entry(state, team);
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
      if (!stop_time && state->head.duration)
        stop_time = ue->start_time + state->head.duration;
      if (stop_time && timestamp > stop_time) {
        err("run_add_record: timestamp > virtual stop time");
        return -1;
      }
    } else {
      stop_time = state->head.stop_time;
      if (!stop_time && state->head.duration)
        stop_time = state->head.start_time + state->head.duration;
      if (stop_time && timestamp > stop_time) {
        err("run_add_record: timestamp overrun");
        return -1;
      }
      ue->status = V_REAL_USER;
    }
  }

  if ((i = append_record(state, timestamp, team, nsec)) < 0) return -1;
  state->runs[i].size = size;
  state->runs[i].locale_id = locale_id;
  state->runs[i].user_id = team;
  state->runs[i].lang_id = language;
  state->runs[i].prob_id = problem;
  state->runs[i].status = 99;
  state->runs[i].test = 0;
  state->runs[i].score = -1;
  state->runs[i].a.ip = ip;
  state->runs[i].variant = variant;
  state->runs[i].is_hidden = is_hidden;
  state->runs[i].mime_type = mime_type;
  if (sha1) {
    memcpy(state->runs[i].sha1, sha1, sizeof(state->runs[i].sha1));
  }
  if (run_flush_entry(state, i) < 0) return -1;
  return i;
}

int
run_undo_add_record(runlog_state_t state, int run_id)
{
  if (run_id < 0 || run_id >= state->run_u) {
    err("run_undo_add_record: invalid run_id");
    return -1;
  }
  if (run_id == state->run_u - 1) {
    state->run_u--;
    memset(&state->runs[state->run_u], 0, sizeof(state->runs[0]));
    if (ftruncate(state->run_fd, sizeof(state->head) + sizeof(state->runs[0]) * state->run_u) < 0) {
      err("run_undo_add_record: ftruncate failed: %s", os_ErrorMsg());
      return -1;
    }
    return 0;
  }
  // clear run
  memset(&state->runs[run_id], 0, sizeof(state->runs[0]));
  state->runs[run_id].run_id = run_id;
  state->runs[run_id].status = RUN_EMPTY;
  return 0;
}

static int
run_flush_header(runlog_state_t state)
{
  if (sf_lseek(state->run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;
  if (do_write(state->run_fd, &state->head, sizeof(state->head)) < 0) return -1;
  return 0;
}

int
run_change_status(runlog_state_t state, int runid, int newstatus,
                  int newtest, int newscore, int judge_id)
{
  if (runid < 0 || runid >= state->run_u) ERR_R("bad runid: %d", runid);
  if (newstatus < 0 || newstatus > 255) ERR_R("bad newstatus: %d", newstatus);
  if (newtest < -1 || newtest > 127) ERR_R("bad newtest: %d", newtest);
  if (newscore < -1 || newscore > RUNLOG_MAX_SCORE)
    ERR_R("bad newscore: %d", newscore);
  if (judge_id < 0 || judge_id > 65535) ERR_R("bad judge_id: %d", judge_id);

  if (newstatus == RUN_VIRTUAL_START || newstatus == RUN_VIRTUAL_STOP)
    ERR_R("virtual status cannot be changed that way");
  if (newstatus == RUN_EMPTY)
    ERR_R("EMPTY status cannot be set this way");
  if (state->runs[runid].status == RUN_VIRTUAL_START
      || state->runs[runid].status == RUN_VIRTUAL_STOP
      || state->runs[runid].status == RUN_EMPTY)
    ERR_R("this entry cannot be changed");

  if (state->runs[runid].is_readonly)
    ERR_R("this entry is read-only");

  state->runs[runid].status = newstatus;
  state->runs[runid].test = newtest;
  state->runs[runid].score = newscore;
  state->runs[runid].judge_id = judge_id;
  run_flush_entry(state, runid);
  return 0;
}

int
run_get_status(runlog_state_t state, int runid)
{
  if (runid < 0 || runid >= state->run_u) ERR_R("bad runid: %d", runid);
  return state->runs[runid].status;
}

int
run_start_contest(runlog_state_t state, time_t start_time)
{
  if (state->head.start_time) ERR_R("Contest already started");
  state->head.start_time = start_time;
  state->head.sched_time = 0;
  return run_flush_header(state);
}

int
run_stop_contest(runlog_state_t state, time_t stop_time)
{
  state->head.stop_time = stop_time;
  return run_flush_header(state);
}

int
run_set_duration(runlog_state_t state, time_t dur)
{
  state->head.duration = dur;
  return run_flush_header(state);
}

int
run_sched_contest(runlog_state_t state, time_t sched)
{
  state->head.sched_time = sched;
  return run_flush_header(state);
}

time_t
run_get_start_time(runlog_state_t state)
{
  return state->head.start_time;
}

time_t
run_get_stop_time(runlog_state_t state)
{
  return state->head.stop_time;
}

time_t
run_get_duration(runlog_state_t state)
{
  return state->head.duration;
}

void
run_get_times(runlog_state_t state, 
              time_t *start, time_t *sched, time_t *dur, time_t *stop)
{
  if (start) *start = state->head.start_time;
  if (sched) *sched = state->head.sched_time;
  if (dur)   *dur   = state->head.duration;
  if (stop)  *stop  = state->head.stop_time;
}

int
run_get_total(runlog_state_t state)
{
  return state->run_u;
}

void
run_get_team_usage(runlog_state_t state, int teamid, int *pn, size_t *ps)
{
  int i;
  int n = 0;
  size_t sz = 0;

  for (i = 0; i < state->run_u; i++) {
    if (state->runs[i].status == RUN_VIRTUAL_START
        || state->runs[i].status == RUN_VIRTUAL_STOP
        || state->runs[i].status == RUN_EMPTY)
      continue;
    if (state->runs[i].user_id == teamid) {
      sz += state->runs[i].size;
      n++;
    }
  }
  if (pn) *pn = n;
  if (ps) *ps = sz;
}

/* FIXME: VERY DUMB */
int
run_get_attempts(runlog_state_t state, int runid, int *pattempts,
                 int *pdisqattempts, int skip_ce_flag)
{
  int i, n = 0, m = 0;

  *pattempts = 0;
  if (runid < 0 || runid >= state->run_u) ERR_R("bad runid: %d", runid);

  for (i = 0; i < runid; i++) {
    if (state->runs[i].status == RUN_VIRTUAL_START
        || state->runs[i].status == RUN_VIRTUAL_STOP
        || state->runs[i].status == RUN_EMPTY)
      continue;
    if (state->runs[i].user_id != state->runs[runid].user_id) continue;
    if (state->runs[i].prob_id != state->runs[runid].prob_id) continue;
    if (state->runs[i].status == RUN_COMPILE_ERR && skip_ce_flag) continue;
    if (state->runs[i].status == RUN_IGNORED) continue;
    if (state->runs[i].is_hidden) continue;
    if (state->runs[i].status == RUN_DISQUALIFIED) {
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
run_get_prev_successes(runlog_state_t state, int run_id)
{
  int user_id, successes = 0, i, cur_uid;
  unsigned char *has_success = 0;

  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  if (state->runs[run_id].status != RUN_OK) ERR_R("runid %d is not OK", run_id);

  // invisible run
  if (state->runs[run_id].is_hidden) return RUN_TOO_MANY;

  if (update_user_flags(state) < 0) return -1;

  // invalid, banned or invisible user
  user_id = state->runs[run_id].user_id;
  if (user_id <= 0 || user_id >= state->user_flags.nuser
      || state->user_flags.flags[user_id] < 0
      || (state->user_flags.flags[user_id] & TEAM_BANNED)
      || (state->user_flags.flags[user_id] & TEAM_INVISIBLE))
    return RUN_TOO_MANY;

  XALLOCAZ(has_success, state->user_flags.nuser);
  for (i = 0; i < run_id; i++) {
    if (state->runs[i].status != RUN_OK) continue;
    if (state->runs[i].is_hidden) continue;
    if (state->runs[i].prob_id != state->runs[run_id].prob_id) continue;
    cur_uid = state->runs[i].user_id;
    if (cur_uid <= 0 || cur_uid >= state->user_flags.nuser
        || state->user_flags.flags[cur_uid] < 0
        || (state->user_flags.flags[cur_uid] & TEAM_BANNED)
        || (state->user_flags.flags[cur_uid] & TEAM_INVISIBLE))
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
run_get_fog_period(runlog_state_t state, time_t cur_time, int fog_time,
                   int unfog_time)
{
  time_t estimated_stop;
  time_t fog_start;

  ASSERT(cur_time);
  ASSERT(fog_time >= 0);
  ASSERT(unfog_time >= 0);

  if (!state->head.start_time) return -1;
  if (!fog_time || !state->head.duration) return 0;

  ASSERT(cur_time >= state->head.start_time);
  if (state->head.stop_time) {
    ASSERT(state->head.stop_time >= state->head.start_time);
    ASSERT(cur_time >= state->head.stop_time);
    if (cur_time > state->head.stop_time + unfog_time) return 2;
    return 1;
  } else {
    estimated_stop = state->head.start_time + state->head.duration;
    //ASSERT(cur_time <= estimated_stop);
    if (fog_time > state->head.duration) fog_time = state->head.duration;
    fog_start = estimated_stop - fog_time;
    if (cur_time >= fog_start) return 1;
    return 0;
  }
}

int
run_reset(runlog_state_t state, time_t new_duration)
{
  int i;

  state->run_u = 0;
  if (state->run_a > 0) {
    memset(state->runs, 0, sizeof(state->runs[0]) * state->run_a);
  }
  for (i = 0; i < state->ut_size; i++)
    xfree(state->ut_table[i]);
  xfree(state->ut_table);
  state->ut_table = 0;
  state->ut_size = 0;
  memset(&state->head, 0, sizeof(state->head));
  state->head.version = 2;
  state->head.duration = new_duration;

  if (ftruncate(state->run_fd, 0) < 0) {
    err("ftruncate failed: %s", os_ErrorMsg());
    return -1;
  }
  run_flush_header(state);
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
run_check_duplicate(runlog_state_t state, int run_id)
{
  int i;
  struct run_entry *p, *q;

  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  p = &state->runs[run_id];
  for (i = run_id - 1; i >= 0; i--) {
    q = &state->runs[i];
    if (q->status == RUN_EMPTY || q->status == RUN_VIRTUAL_START
        || q->status == RUN_VIRTUAL_STOP)
      continue;
    if (p->size == q->size
        && p->a.ip == q->a.ip
        && p->sha1[0] == q->sha1[0]
        && p->sha1[1] == q->sha1[1]
        && p->sha1[2] == q->sha1[2]
        && p->sha1[3] == q->sha1[3]
        && p->sha1[4] == q->sha1[4]
        && p->user_id == q->user_id
        && p->prob_id == q->prob_id
        && p->lang_id == q->lang_id
        && p->variant == q->variant) {
      break;
    }
  }
  if (i < 0) return 0;
  p->status = RUN_IGNORED;
  if (run_flush_entry(state, run_id) < 0) return -1;
  return i + 1;
}

void
run_get_header(runlog_state_t state, struct run_header *out)
{
  memcpy(out, &state->head, sizeof(state->head));
}

void
run_get_all_entries(runlog_state_t state, struct run_entry *out)
{
  memcpy(out, state->runs, sizeof(out[0]) * state->run_u);
}

const struct run_entry *
run_get_entries_ptr(runlog_state_t state)
{
  return state->runs;
}

int
run_get_entry(runlog_state_t state, int run_id, struct run_entry *out)
{
  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  memcpy(out, &state->runs[run_id], sizeof(*out));
  return 0;
}

int
run_set_entry(runlog_state_t state, int run_id, unsigned int mask,
              const struct run_entry *in)
{
  struct run_entry *out;
  struct run_entry te;
  int f = 0;
  struct user_entry *ue = 0;
  time_t stop_time;

  ASSERT(in);
  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  out = &state->runs[run_id];
  ASSERT(out->run_id == run_id);

  ASSERT(state->head.start_time >= 0);
  if (!out->is_hidden && !state->head.start_time) {
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
  if ((mask & RUN_ENTRY_TIME) && te.time != in->time) {
    te.time = in->time;
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
  if ((mask & RUN_ENTRY_IP) && te.a.ip != in->a.ip) {
    te.a.ip = in->a.ip;
    f = 1;
  }
  if ((mask&RUN_ENTRY_SHA1) && memcmp(te.sha1,in->sha1,sizeof(te.sha1))) {
    memcpy(te.sha1, in->sha1, sizeof(te.sha1));
    f = 1;
  }
  if ((mask & RUN_ENTRY_USER) && te.user_id != in->user_id) {
    te.user_id = in->user_id;
    f = 1;
  }
  if ((mask & RUN_ENTRY_PROB) && te.prob_id != in->prob_id) {
    te.prob_id = in->prob_id;
    f = 1;
  }
  if ((mask & RUN_ENTRY_LANG) && te.lang_id != in->lang_id) {
    te.lang_id = in->lang_id;
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
  if (te.user_id <= 0 || te.user_id > RUNLOG_MAX_TEAM_ID) {
    err("run_set_entry: %d: invalid team %d", run_id, te.user_id);
    return -1;
  }

  if (!te.is_hidden) {
    ue = get_user_entry(state, te.user_id);
    if (ue->status == V_VIRTUAL_USER) {
      ASSERT(ue->start_time > 0);
      stop_time = ue->stop_time;
      if (!stop_time && state->head.duration > 0)
        stop_time = ue->start_time + state->head.duration;
      if (te.time < ue->start_time) {
        err("run_set_entry: %d: timestamp < virtual start_time", run_id);
        return -1;
      }
      if (stop_time && te.time > stop_time) {
        err("run_set_entry: %d: timestamp > virtual stop_time", run_id);
        return -1;
      }
    } else {
      stop_time = state->head.stop_time;
      if (!stop_time && state->head.duration > 0)
        stop_time = state->head.start_time + state->head.duration;
      if (te.time < state->head.start_time) {
        err("run_set_entry: %d: timestamp < start_time", run_id);
        return -1;
      }
      if (stop_time && te.time > stop_time) {
        err("run_set_entry: %d: timestamp > stop_time", run_id);
        return -1;
      }
    }
  }

  if (te.size > RUNLOG_MAX_SIZE) {
    err("run_set_entry: %d: size %u is invalid", run_id, te.size);
    return -1;
  }
  if (te.prob_id <= 0 || te.prob_id > RUNLOG_MAX_PROB_ID) {
    err("run_set_entry: %d: problem %d is invalid", run_id, te.prob_id);
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
  if (te.lang_id <= 0 || te.lang_id >= 255) {
    err("run_set_entry: %d: language %d is invalid", run_id, te.lang_id);
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
  if (f && run_flush_entry(state, run_id) < 0) return -1;
  return 0;
}

static struct user_entry *
get_user_entry(runlog_state_t state, int user_id)
{
  ASSERT(user_id > 0);

  if (user_id >= state->ut_size) {
    struct user_entry **new_ut_table = 0;
    int new_ut_size = state->ut_size;

    if (!new_ut_size) new_ut_size = 16;
    while (new_ut_size <= user_id)
      new_ut_size *= 2;
    new_ut_table = xcalloc(new_ut_size, sizeof(new_ut_table[0]));
    if (state->ut_size > 0) {
      memcpy(new_ut_table, state->ut_table, state->ut_size * sizeof(state->ut_table[0]));
    }
    state->ut_size = new_ut_size;
    xfree(state->ut_table);
    state->ut_table = new_ut_table;
    info("runlog: ut_table is extended to %d", state->ut_size);
  }

  if (!state->ut_table[user_id]) {
    state->ut_table[user_id] = xcalloc(1, sizeof(state->ut_table[user_id][0]));
  }
  return state->ut_table[user_id];
}

time_t
run_get_virtual_start_time(runlog_state_t state, int user_id)
{
  struct user_entry *pvt = get_user_entry(state, user_id);
  if (pvt->status == V_REAL_USER) return state->head.start_time;
  return pvt->start_time;
}

time_t
run_get_virtual_stop_time(runlog_state_t state, int user_id, time_t cur_time)
{
  struct user_entry *pvt = get_user_entry(state, user_id);
  if (!pvt->start_time) return 0;
  if (!cur_time) return pvt->stop_time;
  if (pvt->status == V_REAL_USER) return state->head.stop_time;
  if (pvt->status != V_VIRTUAL_USER) return 0;
  if (state->head.duration || pvt->stop_time) return pvt->stop_time;
  if (pvt->start_time + state->head.duration < cur_time) {
    pvt->stop_time = pvt->start_time + state->head.duration;
  }
  return pvt->stop_time;
}

int
run_get_virtual_status(runlog_state_t state, int user_id)
{
  struct user_entry *pvt = get_user_entry(state, user_id);
  return pvt->status;
}

int
run_virtual_start(runlog_state_t state, int user_id, time_t t, ej_ip_t ip,
                  int nsec)
{
  struct user_entry *pvt = get_user_entry(state, user_id);
  int i;

  if (!state->head.start_time) {
    err("run_virtual_start: the contest is not started");
    return -1;
  }
  ASSERT(state->head.start_time > 0);
  if (t < state->head.start_time) {
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
  if ((i = append_record(state, t, user_id, nsec)) < 0) return -1;
  state->runs[i].user_id = user_id;
  state->runs[i].a.ip = ip;
  state->runs[i].status = RUN_VIRTUAL_START;
  pvt->start_time = t;
  pvt->status = V_VIRTUAL_USER;
  if (run_flush_entry(state, i) < 0) return -1;
  return i;
}

int
run_virtual_stop(runlog_state_t state, int user_id, time_t t, ej_ip_t ip,
                 int nsec)
{
  struct user_entry *pvt = get_user_entry(state, user_id);
  int i;
  time_t exp_stop_time = 0;

  if (!state->head.start_time) {
    err("run_virtual_stop: the contest is not started");
    return -1;
  }
  ASSERT(state->head.start_time > 0);
  if (t < state->head.start_time) {
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
  if (state->head.duration > 0) exp_stop_time = pvt->start_time + state->head.duration;
  if (t > exp_stop_time) {
    err("run_virtual_stop: the virtual time ended");
    return -1;
  }
  if (nsec < 0 || nsec >= 1000000000) {
    err("run_virtual_stop: nsec field value is invalid");
    return -1;
  }

  if ((i = append_record(state, t, user_id, nsec)) < 0) return -1;
  state->runs[i].user_id = user_id;
  state->runs[i].a.ip = ip;
  state->runs[i].status = RUN_VIRTUAL_STOP;
  pvt->stop_time = t;
  if (run_flush_entry(state, i) < 0) return -1;
  return i;
}

int
run_is_readonly(runlog_state_t state, int run_id)
{
  if (run_id < 0 || run_id >= state->run_u) return 1;
  return state->runs[run_id].is_readonly;
}

int
run_clear_entry(runlog_state_t state, int run_id)
{
  struct user_entry *ue;
  int i;

  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  if (state->runs[run_id].is_readonly) ERR_R("run %d is readonly", run_id);
  switch (state->runs[run_id].status) {
  case RUN_EMPTY:
    memset(&state->runs[run_id], 0, sizeof(state->runs[run_id]));
    state->runs[run_id].status = RUN_EMPTY;
    state->runs[run_id].run_id = run_id;
    break;
  case RUN_VIRTUAL_STOP:
    /* VSTOP events can safely be cleared */ 
    ue = get_user_entry(state, state->runs[run_id].user_id);
    ASSERT(ue->status == V_VIRTUAL_USER);
    ASSERT(ue->start_time > 0);
    ue->stop_time = 0;
    memset(&state->runs[run_id], 0, sizeof(state->runs[run_id]));
    state->runs[run_id].status = RUN_EMPTY;
    state->runs[run_id].run_id = run_id;
    break;
  case RUN_VIRTUAL_START:
    /* VSTART event must be the only event of this team */
    for (i = 0; i < state->run_u; i++) {
      if (i == run_id) continue;
      if (state->runs[i].status == RUN_EMPTY) continue;
      if (state->runs[i].user_id == state->runs[run_id].user_id) break;
    }
    if (i < state->run_u) {
      err("run_clear_entry: VSTART must be the only record for a team");
      return -1;
    }
    ue = get_user_entry(state, state->runs[run_id].user_id);
    ASSERT(ue->status == V_VIRTUAL_USER);
    ASSERT(ue->start_time == state->runs[run_id].time);
    ASSERT(!ue->stop_time);
    ue->status = 0;
    ue->start_time = 0;
    memset(&state->runs[run_id], 0, sizeof(state->runs[run_id]));
    state->runs[run_id].status = RUN_EMPTY;
    state->runs[run_id].run_id = run_id;
    break;
  default:
    /* maybe update indices */
    memset(&state->runs[run_id], 0, sizeof(state->runs[run_id]));
    state->runs[run_id].status = RUN_EMPTY;
    state->runs[run_id].run_id = run_id;
    break;
  }
  return run_flush_entry(state, run_id);
}

int
run_squeeze_log(runlog_state_t state)
{
  int i, j, retval, first_moved = -1, w;
  unsigned char *ptr;
  size_t tot;

  for (i = 0, j = 0; i < state->run_u; i++) {
    if (state->runs[i].status == RUN_EMPTY) continue;
    if (i != j) {
      if (first_moved < 0) first_moved = j;
      memcpy(&state->runs[j], &state->runs[i], sizeof(state->runs[j]));
      state->runs[j].run_id = j;
    }
    j++;
  }
  if  (state->run_u == j) {
    // no runs were removed
    ASSERT(first_moved == -1);
    return 0;
  }

  retval = state->run_u - j;
  state->run_u = j;
  if (state->run_u < state->run_a) {
    memset(&state->runs[state->run_u], 0, (state->run_a - state->run_u) * sizeof(state->runs[0]));
  }

  // update log on disk
  if (ftruncate(state->run_fd, sizeof(state->head) + state->run_u * sizeof(state->runs[0])) < 0) {
    err("run_squeeze_log: ftruncate failed: %s", os_ErrorMsg());
    return -1;
  }
  if (first_moved == -1) {
    // no entries were moved because the only entries empty were the last
    return retval;
  }
  ASSERT(first_moved >= 0 && first_moved < state->run_u);
  if (sf_lseek(state->run_fd, sizeof(state->head) + first_moved * sizeof(state->runs[0]),
               SEEK_SET, "run") == (off_t) -1)
    return -1;
  tot = (state->run_u - first_moved) * sizeof(state->runs[0]);
  ptr = (unsigned char *) &state->runs[first_moved];
  while (tot > 0) {
    w = write(state->run_fd, ptr, tot);
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
run_clear_variables(runlog_state_t state)
{
  int i;

  memset(&state->head, 0, sizeof(state->head));
  if (state->runs) xfree(state->runs);
  state->runs = 0;
  state->run_u = state->run_a = 0;
  if (state->run_fd >= 0) close(state->run_fd);
  state->run_fd = -1;
  if (state->ut_table) {
    for (i = 0; i < state->ut_size; i++) {
      if (state->ut_table[i]) xfree(state->ut_table[i]);
      state->ut_table[i] = 0;
    }
    xfree(state->ut_table);
  }
  state->ut_table = 0;
}

int
run_write_xml(runlog_state_t state, FILE *f, int export_mode,
              time_t current_time)
{
  //int i;

  if (!state->head.start_time) {
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

  // !!!!!!!!!!!!!!
  unparse_runlog_xml(0, f, &state->head, state->run_u,
                     state->runs, export_mode, current_time);
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
      if (i > 0 && !e->run_id) {
        check_msg(0,ferr, "Run %d submission for EMPTY is not set", i);
        e->run_id = i;
      } else if (e->run_id != i) {
        check_msg(1,ferr, "Run %d submission %d does not match index",
                  i, e->run_id);
        e->run_id = i;
        retcode = 1;
        //nerr++;
        //continue;
      }
      /* kinda paranoia */
      memcpy(&te, e, sizeof(te));
      te.run_id = 0;
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

    if (e->run_id != i) {
      check_msg(1,ferr, "Run %d submission %d does not match index",
                i, e->run_id);
      e->run_id = i;
      retcode = 1;
      //nerr++;
      //continue;
    }
    if (e->user_id <= 0) {
      check_msg(1,ferr, "Run %d team %d is invalid", i, e->user_id);
      nerr++;
      continue;
    }
    if (e->time < 0) {
      check_msg(1, ferr, "Run %d timestamp %ld is negative", i, e->time);
      nerr++;
      continue;
    }
    if (!e->time) {
      check_msg(1, ferr, "Run %d timestamp is not set", i);
      nerr++;
      continue;
    }
    if (e->time < prev_time) {
      check_msg(1, ferr, "Run %d timestamp %ld is less than previous %ld",
                i, e->time, prev_time);
      nerr++;
      continue;
    }
    if (e->time == prev_time && e->nsec < prev_nsec) {
      check_msg(1, ferr, "Run %d nsec %d is less than previous %d",
                i, e->nsec, prev_nsec);
    }
    prev_time = e->time;
    prev_nsec = e->nsec;

    if (e->status == RUN_VIRTUAL_START || e->status == RUN_VIRTUAL_STOP) {
      /* kinda paranoia */
      memcpy(&te, e, sizeof(te));
      te.run_id = 0;
      te.status = 0;
      te.user_id = 0;
      te.time = 0;
      te.nsec = 0;
      te.a.ip = 0;
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
    if (!e->a.ip) {
      check_msg(0, ferr, "Run %d IP is not set", i);
    }
    if (!e->sha1[0]&&!e->sha1[1]&&!e->sha1[2]&&!e->sha1[3]&&!e->sha1[4]) {
      //check_msg(0, ferr, "Run %d SHA1 is not set", i);
    }
    if (e->prob_id <= 0) {
      check_msg(1, ferr, "Run %d problem %d is invalid", i, e->prob_id);
      nerr++;
      continue;
    }
    if (e->prob_id > RUNLOG_MAX_PROB_ID) {
      check_msg(1, ferr, "Run %d problem %d is too large", i, e->prob_id);
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
    if (e->lang_id == 0 || e->lang_id == 255) {
      check_msg(1, ferr, "Run %d language %d is invalid", i, e->lang_id);
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
    if (pentries[i].user_id > max_team_id) max_team_id = pentries[i].user_id;
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
      ASSERT(e->user_id <= max_team_id);
      v = &ventries[e->user_id];
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
        v->start_time = e->time;
      }
      break;
    case RUN_VIRTUAL_STOP:
      ASSERT(e->user_id <= max_team_id);
      v = &ventries[e->user_id];
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
            && e->time > v->start_time + phead->duration) {
          check_msg(1, ferr, "Run %d: VSTOP after expiration of contest", i);
          nerr++;
          continue;
        }
        v->stop_time = e->time;
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
      ASSERT(e->user_id <= max_team_id);
      v = &ventries[e->user_id];
      ASSERT(v->status >= 0 && v->status <= V_LAST);
      if (v->status == V_VIRTUAL_USER) {
        ASSERT(v->start_time > 0);
        ASSERT(v->stop_time >= 0);
        v_stop_time = v->stop_time;
        if (!v_stop_time && phead->duration)
          v_stop_time = v->start_time + phead->duration;
        if (e->time < v->start_time) {
          check_msg(1, ferr,
                    "Run %d timestamp %ld is less that virtual start %ld",
                    i, e->time, v->start_time);
          nerr++;
          continue;
        }
        if (v_stop_time && e->time > v_stop_time) {
          check_msg(1, ferr,
                    "Run %d timestamp %ld is greater than virtual stop %ld",
                    i, e->time, v_stop_time);
          nerr++;
          continue;
        }
      } else {
        ASSERT(!v->start_time);
        ASSERT(!v->stop_time);
        ASSERT(v->status == 0 || v->status == V_REAL_USER);
        if (e->time < phead->start_time) {
          check_msg(1,ferr,
                    "Run %d timestamp %ld is less than contest start %ld",
                    i, e->time, phead->start_time);
          nerr++;
          continue;
        }
        if (stop_time && e->time > stop_time) {
          check_msg(1, ferr,
                    "Run %d timestamp %ld is greater than contest stop %ld",
                    i, e->time, stop_time);
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
build_indices(runlog_state_t state)
{
  int i;
  int max_team_id = -1;
  struct user_entry *ue;

  if (state->ut_table) {
    for (i = 0; i < state->ut_size; i++)
      xfree(state->ut_table[i]);
    xfree(state->ut_table);
    state->ut_table = 0;
  }
  state->ut_size = 0;
  state->ut_table = 0;

  /* assume, that the runlog is consistent
   * scan the whole runlog and build various indices
   */
  for (i = 0; i < state->run_u; i++) {
    if (state->runs[i].status == RUN_EMPTY) continue;
    ASSERT(state->runs[i].user_id > 0);
    if (state->runs[i].user_id > max_team_id) max_team_id = state->runs[i].user_id;
  }
  if (max_team_id <= 0) return;

  state->ut_size = 128;
  while (state->ut_size <= max_team_id)
    state->ut_size *= 2;

  XCALLOC(state->ut_table, state->ut_size);
  for (i = 0; i < state->run_u; i++) {
    if (state->runs[i].is_hidden) continue;
    switch (state->runs[i].status) {
    case RUN_EMPTY:
      break;
    case RUN_VIRTUAL_START:
      ue = get_user_entry(state, state->runs[i].user_id);
      ASSERT(!ue->status);
      ue->status = V_VIRTUAL_USER;
      ue->start_time = state->runs[i].time;
      break;
    case RUN_VIRTUAL_STOP:
      ue = get_user_entry(state, state->runs[i].user_id);
      ASSERT(ue->status == V_VIRTUAL_USER);
      ASSERT(ue->start_time > 0);
      ue->stop_time = state->runs[i].time;
      break;
    default:
      ue = get_user_entry(state, state->runs[i].user_id);
      if (!ue->status) ue->status = V_REAL_USER;
      break;
    }
  }
}

int
run_get_pages(runlog_state_t state, int run_id)
{
  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  return state->runs[run_id].pages;
}

int
run_set_pages(runlog_state_t state, int run_id, int pages)
{
  if (run_id < 0 || run_id >= state->run_u) ERR_R("bad runid: %d", run_id);
  if (pages < 0 || pages > 255) ERR_R("bad pages: %d", pages);
  state->runs[run_id].pages = pages;
  run_flush_entry(state, run_id);
  return 0;
}

int
run_get_total_pages(runlog_state_t state, int user_id)
{
  int i, total = 0;

  if (user_id <= 0 || user_id > 100000) ERR_R("bad user_id: %d", user_id);
  for (i = 0; i < state->run_u; i++) {
    if (state->runs[i].status == RUN_VIRTUAL_START || state->runs[i].status == RUN_VIRTUAL_STOP
        || state->runs[i].status == RUN_EMPTY) continue;
    if (state->runs[i].user_id != user_id) continue;
    total += state->runs[i].pages;
  }
  return total;
}

int
run_find(runlog_state_t state, int first_run, int last_run,
         int team_id, int prob_id, int lang_id)
{
  int i;

  if (!state->run_u) return -1;

  if (first_run < 0) first_run = state->run_u + first_run;
  if (first_run < 0) first_run = 0;
  if (first_run >= state->run_u) first_run = state->run_u - 1;

  if (last_run < 0) last_run = state->run_u + last_run;
  if (last_run < 0) last_run = 0;
  if (last_run >= state->run_u) last_run = state->run_u - 1;

  if (first_run <= last_run) {
    for (i = first_run; i <= last_run; i++) {
      if (team_id && team_id != state->runs[i].user_id) continue;
      if (prob_id && prob_id != state->runs[i].prob_id) continue;
      if (lang_id && lang_id != state->runs[i].lang_id) continue;
      return i;
    }
  } else {
    for (i = first_run; i >= last_run; i--) {
      if (team_id && team_id != state->runs[i].user_id) continue;
      if (prob_id && prob_id != state->runs[i].prob_id) continue;
      if (lang_id && lang_id != state->runs[i].lang_id) continue;
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

static void
teamdb_update_callback(void *user_ptr)
{
  // invalidate user_flags
  runlog_state_t state = (runlog_state_t) user_ptr;
  xfree(state->user_flags.flags);
  memset(&state->user_flags, 0, sizeof(state->user_flags));
  state->user_flags.nuser = -1;
}

static int
update_user_flags(runlog_state_t state)
{
  int size = 0;
  int *map = 0;

  if (state->user_flags.nuser >= 0) return 0;
  if (teamdb_get_user_status_map(state->teamdb_state, &size, &map) < 0)
    return -1;
  state->user_flags.nuser = size;
  state->user_flags.flags = map;
  return 1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
