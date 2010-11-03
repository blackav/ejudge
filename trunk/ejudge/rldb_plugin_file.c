/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008-2010 Alexander Chernov <cher@ejudge.ru> */

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

#include "rldb_plugin.h"
#include "ejudge_cfg.h"
#include "runlog.h"
#include "teamdb.h"

#define RUNS_ACCESS 
#include "runlog_state.h"

#include "pathutl.h"
#include "contests.h"
#include "prepare.h"
#include "errlog.h"
#include "fileutl.h"
#include "unix/unix_fileutl.h"
#include "xml_utils.h"
#include "random.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

struct rldb_file_state
{
  int nref;
};

struct rldb_file_cnts
{
  struct rldb_file_state *plugin_state;
  struct runlog_state *rl_state;
  int run_fd;
  unsigned char *runlog_path;
};

static struct common_plugin_data *
init_func(void);
static int
finish_func(struct common_plugin_data *);
static int
prepare_func(
        struct common_plugin_data *data,
        struct ejudge_cfg *config,
        struct xml_tree *plugin_config);
static struct rldb_plugin_cnts *
open_func(
        struct rldb_plugin_data *,
        struct runlog_state *,
        const struct ejudge_cfg *,
        const struct contest_desc *,
        const struct section_global_data *,
        int flags,
        time_t init_duration,
        time_t init_sched_time,
        time_t init_finish_time);
static struct rldb_plugin_cnts *
close_func(struct rldb_plugin_cnts *cdata);
static int
reset_func(
        struct rldb_plugin_cnts *cdata,
        time_t init_duration,
        time_t init_sched_time,
        time_t init_finish_time);
static int
set_runlog_func(
        struct rldb_plugin_cnts *cdata,
        int total_entries,
        struct run_entry *entries);
static int
backup_func(struct rldb_plugin_cnts *cdata);
static int
flush_func(struct rldb_plugin_cnts *cdata);
static int
get_insert_run_id(
        struct rldb_plugin_cnts *cdata,
        time_t t,
        int uid,
        int nsec);
static int
add_entry_func(
        struct rldb_plugin_cnts *cdata,
        int i,
        const struct run_entry *re,
        int flags);
static int
undo_add_entry_func(
        struct rldb_plugin_cnts *cdata,
        int run_id);
static int
change_status_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_status,
        int new_test,
        int new_score,
        int judge_id);
static int
start_func(
        struct rldb_plugin_cnts *cdata,
        time_t start_time);
static int
stop_func(
        struct rldb_plugin_cnts *cdata,
        time_t stop_time);
static int
set_duration_func(
        struct rldb_plugin_cnts *cdata,
        int duration);
static int
schedule_func(
        struct rldb_plugin_cnts *cdata,
        time_t sched_time);
static int
set_finish_time_func(
        struct rldb_plugin_cnts *cdata,
        time_t finish_time);
static int
save_times_func(struct rldb_plugin_cnts *cdata);
static int
set_status_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_status);
static int
clear_entry_func(
        struct rldb_plugin_cnts *,
        int run_id);
static int
set_hidden_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_hidden);
static int
set_judge_id_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_judge_id);
static int
set_pages_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_pages);
static int
set_entry_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        const struct run_entry *in,
        int flags);
static int
squeeze_func(struct rldb_plugin_cnts *cdata);
static int
change_status_2_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_status,
        int new_test,
        int new_score,
        int judge_id,
        int is_marked);
static int
check_func(
        struct rldb_plugin_cnts *cdata,
        FILE *log_f);

struct rldb_plugin_iface rldb_plugin_file =
{
  {
    {
      sizeof (struct rldb_plugin_iface),
      EJUDGE_PLUGIN_IFACE_VERSION,
      "rldb",
      "file",
    },
    COMMON_PLUGIN_IFACE_VERSION,
    init_func,
    finish_func,
    prepare_func,
  },
  RLDB_PLUGIN_IFACE_VERSION,

  open_func,
  close_func,
  reset_func,
  set_runlog_func,
  backup_func,
  flush_func,
  get_insert_run_id,
  add_entry_func,
  undo_add_entry_func,
  change_status_func,
  start_func,
  stop_func,
  set_duration_func,
  schedule_func,
  set_finish_time_func,
  save_times_func,
  set_status_func,
  clear_entry_func,
  set_hidden_func,
  set_judge_id_func,
  set_pages_func,
  set_entry_func,
  squeeze_func,
  NULL, // put_entry
  NULL, // put_header
  change_status_2_func,
  check_func,
};

static struct common_plugin_data *
init_func(void)
{
  struct rldb_file_state *state = 0;
  XCALLOC(state, 1);
  return (struct common_plugin_data *) state;
}

static int
finish_func(struct common_plugin_data *data)
{
  struct rldb_file_state *state = (struct rldb_file_state*) data;
  xfree(state);
  return 0;
}

static int
prepare_func(
        struct common_plugin_data *data,
        struct ejudge_cfg *config,
        struct xml_tree *plugin_config)
{
  return 0;
}

#define ERR_R(t, args...) do { do_err_r(__FUNCTION__ , t , ##args); return -1; } while (0)
#define ERR_C(t, args...) do { do_err_r(__FUNCTION__ , t , ##args); goto _cleanup; } while (0)

/* these constants are for old text-based runlog */
#define RUN_MAX_IP_LEN 15
#define RUN_RECORD_SIZE 105
#define RUN_HEADER_SIZE 105

static int
is_runlog_version_0(struct rldb_file_cnts *cs)
{
  unsigned char buf[RUN_HEADER_SIZE + 16];
  int r, n;
  time_t v1, v2, v3, v4;

  memset(buf, 0, sizeof(buf));
  if (sf_lseek(cs->run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;
  if ((r = sf_read(cs->run_fd, buf, RUN_HEADER_SIZE, "run")) < 0) return -1;
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
run_read_record_v0(
        struct rldb_file_cnts *cs,
        char *buf,
        int size)
{
  int  rsz;
  int  i;

  if ((rsz = sf_read(cs->run_fd, buf, size, "run")) < 0) return -1;
  if (rsz != size) ERR_R("short read: %d", rsz);
  for (i = 0; i < size - 1; i++) {
    if (buf[i] >= 0 && buf[i] < ' ') break;
  }
  if (i < size - 1) ERR_R("bad characters in record");
  if (buf[size - 1] != '\n') ERR_R("record improperly terminated");
  return 0;
}

static int
run_read_header_v0(struct rldb_file_cnts *cs)
{
  struct runlog_state *rls = cs->rl_state;
  char buf[RUN_HEADER_SIZE + 16];
  int  n, r;

  memset(buf, 0, sizeof(buf));
  if (run_read_record_v0(cs, buf, RUN_HEADER_SIZE) < 0) return -1;
  r = sscanf(buf, " %lld %lld %lld %lld %n",
             &rls->head.start_time,
             &rls->head.sched_time,
             &rls->head.duration,
             &rls->head.stop_time, &n);
  if (r != 4) ERR_R("sscanf returned %d", r);
  if (buf[n] != 0) ERR_R("excess data: %d", n);
  return 0;
}

static int
run_read_entry_v0(struct rldb_file_cnts *cs, int n)
{
  struct runlog_state *rls = cs->rl_state;
  char buf[RUN_RECORD_SIZE + 16];
  char tip[RUN_RECORD_SIZE + 16];
  int  k, r;
  ej_ip_t ip;

  memset(buf, 0, sizeof(buf));
  if (run_read_record_v0(cs, buf, RUN_RECORD_SIZE) < 0) return -1;
  r = sscanf(buf, " %lld %d %u %hd %d %d %d %hhu %d %d %s %n",
             &rls->runs[n].time, &rls->runs[n].run_id,
             &rls->runs[n].size, &rls->runs[n].locale_id,
             &rls->runs[n].user_id, &rls->runs[n].lang_id,
             &rls->runs[n].prob_id, &rls->runs[n].status,
             &rls->runs[n].test, &rls->runs[n].score, tip, &k);
  if (r != 11) ERR_R("[%d]: sscanf returned %d", n, r);
  if (buf[k] != 0) ERR_R("[%d]: excess data", n);
  if (strlen(tip) > RUN_MAX_IP_LEN) ERR_R("[%d]: ip is to long", n);
  if (xml_parse_ip(0, 0, 0, tip, &ip) < 0) ERR_R("[%d]: cannot parse IP");
  rls->runs[n].a.ip = ip;
  return 0;
}

static int
save_runlog_backup(
        const unsigned char *path,
        const unsigned char *suffix)
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
read_runlog_version_0(struct rldb_file_cnts *cs)
{
  struct runlog_state *rls = cs->rl_state;
  off_t filesize;
  int i;

  info("reading runs log version 0");

  /* calculate the size of the file */
  if ((filesize = sf_lseek(cs->run_fd, 0, SEEK_END, "run")) == (off_t) -1)
    return -1;
  if (sf_lseek(cs->run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;

  info("runs file size: %lu", (unsigned long) filesize);
  if (filesize == 0) {
    /* runs file is empty */
    XMEMZERO(&rls->head, 1);
    rls->run_u = 0;
    return 0;
  }

  if ((filesize - RUN_HEADER_SIZE) % RUN_RECORD_SIZE != 0)
    ERR_C("bad runs file size: remainder %d", (filesize - RUN_HEADER_SIZE) % RUN_RECORD_SIZE);

  rls->run_u = (filesize - RUN_HEADER_SIZE) / RUN_RECORD_SIZE;
  rls->run_a = 128;
  while (rls->run_u > rls->run_a) rls->run_a *= 2;
  XCALLOC(rls->runs, rls->run_a);
  for (i = 0; i < rls->run_a; i++)
    rls->runs[i].status = RUN_EMPTY;

  if (run_read_header_v0(cs) < 0) goto _cleanup;
  for (i = 0; i < rls->run_u; i++) {
    if (run_read_entry_v0(cs, i) < 0) goto _cleanup;
  }
  return 0;

 _cleanup:
  XMEMZERO(&rls->head, 1);
  if (rls->runs) {
    xfree(rls->runs); rls->runs = 0;
    rls->run_u = rls->run_a = 0;
  }
  if (cs->run_fd >= 0) {
    close(cs->run_fd);
    cs->run_fd = -1;
  }
  return -1;
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
do_truncate(struct rldb_file_cnts *cs)
{
  struct runlog_state *rls = cs->rl_state;
  size_t size = sizeof(rls->head) + sizeof(rls->runs[0]) * rls->run_u;

  if (ftruncate(cs->run_fd, size) < 0) {
    err("%s: ftruncate failed: %s", __FILE__, os_ErrorMsg());
    return -1;
  }
  return 0;
}

static int
write_full_runlog_current_version(
        struct rldb_file_cnts *cs,
        const char *path)
{
  struct runlog_state *rls = cs->rl_state;
  int run_fd;

  if ((run_fd = sf_open(path, O_RDWR | O_CREAT | O_TRUNC, 0666)) < 0)
    return -1;

  rls->head.version = 2;
  if (do_write(run_fd, &rls->head, sizeof(rls->head)) < 0) return -1;
  if (rls->run_u > 0) {
    if (do_write(run_fd, rls->runs, sizeof(rls->runs[0]) * rls->run_u) < 0)
      return -1;
  }

  return run_fd;
}

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

static int
is_runlog_version_1(struct rldb_file_cnts *cs)
{
  struct run_header_v1 header_v1;
  struct stat stbuf;
  int r;

  memset(&header_v1, 0, sizeof(header_v1));
  if (sf_lseek(cs->run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;
  if ((r = sf_read(cs->run_fd, &header_v1, sizeof(header_v1), "run")) < 0)
    return -1;
  if (r != sizeof(header_v1)) return 0;
  if (header_v1.version != 1) return 0;
  if (fstat(cs->run_fd, &stbuf) < 0) return -1;
  if (stbuf.st_size < sizeof(header_v1)) return 0;
  stbuf.st_size -= sizeof(header_v1);
  if (stbuf.st_size % sizeof(struct run_entry_v1) != 0) return 0;
  return 1;
}

static int
read_runlog_version_1(struct rldb_file_cnts *cs)
{
  struct runlog_state *rls = cs->rl_state;
  int rem;
  struct stat stbuf;
  struct run_header_v1 header_v1;
  int run_v1_u, i;
  struct run_entry_v1 *runs_v1 = 0;
  struct run_entry_v1 *po;
  struct run_entry    *pn;

  info("reading runs log version 1 (binary)");

  /* calculate the size of the file */
  if (fstat(cs->run_fd, &stbuf) < 0) {
    err("read_runlog_version_1: fstat() failed: %s", os_ErrorMsg());
    return -1;
  }
  if (sf_lseek(cs->run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;
  if (stbuf.st_size < sizeof (header_v1)) {
    err("read_runlog_version_1: file is too small");
    return -1;
  }

  // read header
  if (do_read(cs->run_fd, &header_v1, sizeof(header_v1)) < 0) return -1;
  info("run log version %d", header_v1.version);
  if (header_v1.version != 1) {
    err("unsupported run log version %d", rls->head.version);
    return -1;
  }

  stbuf.st_size -= sizeof(header_v1);
  if ((rem = stbuf.st_size % sizeof(struct run_entry_v1)) != 0) {
    err("bad runs file size: remainder %d", rem);
    return -1;
  }
  run_v1_u = stbuf.st_size / sizeof(struct run_entry_v1);
  if (run_v1_u > 0) {
    XCALLOC(runs_v1, run_v1_u);
    if (do_read(cs->run_fd, runs_v1, sizeof(runs_v1[0]) * run_v1_u) < 0)
      return -1;
  }

  // assign the header
  memset(&rls->head, 0, sizeof(rls->head));
  rls->head.version = 2;
  rls->head.byte_order = 0;
  rls->head.start_time = header_v1.start_time;
  rls->head.sched_time = header_v1.sched_time;
  rls->head.duration = header_v1.duration;
  rls->head.stop_time = header_v1.stop_time;

  // copy version 1 runlog to version 2 runlog
  rls->run_a = 128;
  rls->run_u = run_v1_u;
  while (run_v1_u > rls->run_a) rls->run_a *= 2;
  XCALLOC(rls->runs, rls->run_a);
  for (i = 0; i < rls->run_a; ++i)
    rls->runs[i].status = RUN_EMPTY;

  for (i = 0; i < rls->run_u; i++) {
    po = &runs_v1[i];
    pn = &rls->runs[i];

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
  return 0;
}

static int
run_flush_header(struct rldb_file_cnts *cs)
{
  struct runlog_state *rls = cs->rl_state;

  if (sf_lseek(cs->run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;
  if (do_write(cs->run_fd, &rls->head, sizeof(rls->head)) < 0)
    return -1;
  return 0;
}

static int
read_runlog(
        struct rldb_file_cnts *cs,
        time_t init_duration,
        time_t init_sched_time,
        time_t init_finish_time)
{
  struct runlog_state *rls = cs->rl_state;
  off_t filesize;
  int rem;
  int i;

  info("reading runs log (binary)");

  /* calculate the size of the file */
  if ((filesize = sf_lseek(cs->run_fd, 0, SEEK_END, "run")) == (off_t) -1)
    return -1;
  if (sf_lseek(cs->run_fd, 0, SEEK_SET, "run") == (off_t) -1) return -1;

  info("runs file size: %lu", (unsigned long) filesize);
  if (filesize == 0) {
    /* runs file is empty */
    XMEMZERO(&rls->head, 1);
    rls->head.version = 2;
    rls->head.duration = init_duration;
    rls->head.sched_time = init_sched_time;
    rls->head.finish_time = init_finish_time;
    rls->run_u = 0;
    run_flush_header(cs);
    return 0;
  }

  if (sizeof(struct run_entry) != 128) abort();

  // read header
  if (do_read(cs->run_fd, &rls->head, sizeof(rls->head)) < 0)
    return -1;
  info("run log version %d", rls->head.version);
  if (rls->head.version != 2) {
    err("unsupported run log version %d", rls->head.version);
    return -1;
  }

  rem = (filesize - sizeof(struct run_header)) % sizeof(struct run_entry);
  if (rem != 0) ERR_C("bad runs file size: remainder %d", rem);

  rls->run_u = (filesize - sizeof(struct run_header))/sizeof(struct run_entry);
  rls->run_a = 128;
  while (rls->run_u > rls->run_a) rls->run_a *= 2;
  XCALLOC(rls->runs, rls->run_a);
  for (i = 0; i < rls->run_a; ++i)
    rls->runs[i].status = RUN_EMPTY;
  if (rls->run_u > 0) {
    if (do_read(cs->run_fd, rls->runs, sizeof(rls->runs[0]) * rls->run_u) < 0)
      return -1;
  }

  if (init_finish_time > 0 && rls->head.finish_time != init_finish_time) {
    rls->head.finish_time = init_finish_time;
    run_flush_header(cs);
  } else if (init_finish_time == -1 && rls->head.finish_time > 0) {
    rls->head.finish_time = 0;
    run_flush_header(cs);
  }
  return 0;

 _cleanup:
  XMEMZERO(&rls->head, 1);
  if (rls->runs) {
    xfree(rls->runs); rls->runs = 0;
    rls->run_u = rls->run_a = 0;
  }
  if (cs->run_fd >= 0) {
    close(cs->run_fd);
    cs->run_fd = -1;
  }
  return -1;
}

static int
do_run_open(
	struct rldb_file_cnts *cs,
        char const *path,
        int flags,
        time_t init_duration,
        time_t init_sched_time,
        time_t init_finish_time)
{
  struct runlog_state *rls = cs->rl_state;
  int i, oflags;

  info("run_open: opening database %s", path);

  if (rls->runs) {
    xfree(rls->runs); rls->runs = 0;
    rls->run_u = rls->run_a = 0;
  }
  if (cs->run_fd >= 0) {
    close(cs->run_fd);
    cs->run_fd = -1;
  }
  if (flags == RUN_LOG_READONLY) {
    oflags = O_RDONLY;
  } else if (flags == RUN_LOG_CREATE) {
    oflags = O_RDWR | O_CREAT | O_TRUNC;
  } else {
    oflags = O_RDWR | O_CREAT;
  }
  if ((cs->run_fd = sf_open(path, oflags, 0666)) < 0) return -1;

  if ((i = is_runlog_version_0(cs)) < 0) return -1;
  else if (i) {
    if (read_runlog_version_0(cs) < 0) return -1;
    if (flags != RUN_LOG_READONLY) {
      if (save_runlog_backup(path, 0) < 0) return -1;
      close(cs->run_fd);
      if ((cs->run_fd = write_full_runlog_current_version(cs, path)) < 0)
        return -1;
    }
  } else if ((i = is_runlog_version_1(cs)) < 0) return -1;
  else if (i) {
    if (read_runlog_version_1(cs) < 0) return -1;
    if (flags != RUN_LOG_READONLY) {
      if (save_runlog_backup(path, ".v1") < 0) return -1;
      close(cs->run_fd);
      if ((cs->run_fd = write_full_runlog_current_version(cs, path)) < 0)
        return -1;
    }
  } else {
    if (read_runlog(cs, init_duration, init_sched_time,
                    init_finish_time) < 0) return -1;
  }
  return 0;
}

static struct rldb_plugin_cnts *
open_func(
        struct rldb_plugin_data *data,
        struct runlog_state *rl_state,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags,
        time_t init_duration,
        time_t init_sched_time,
        time_t init_finish_time)
{
  struct rldb_file_state *state = (struct rldb_file_state*) data;
  struct rldb_file_cnts *cs = 0;
  path_t runlog_path;

  ASSERT(state);
  XCALLOC(cs, 1);
  cs->plugin_state = state;
  state->nref++;
  cs->rl_state = rl_state;
  cs->run_fd = -1;

  runlog_path[0] = 0;
  if (global && global->run_log_file[0]) {
    snprintf(runlog_path, sizeof(runlog_path), "%s", global->run_log_file);
  }
  if (!runlog_path[0] && cnts && cnts->root_dir) {
    snprintf(runlog_path, sizeof(runlog_path), "%s/var/run.log",
             cnts->root_dir);
  }
  if (!runlog_path[0]) {
    err("`run_log_file' is undefined");
    goto fail;
  }
  cs->runlog_path = xstrdup(runlog_path);

  if (do_run_open(cs, runlog_path, flags, init_duration,
                  init_sched_time, init_finish_time) < 0)
    goto fail;

  return (struct rldb_plugin_cnts*) cs;

 fail:
  close_func((struct rldb_plugin_cnts*) cs);
  return 0;
}

static struct rldb_plugin_cnts *
close_func(struct rldb_plugin_cnts *cdata)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  if (!cs) return 0;
  rls = cs->rl_state;
  if (rls) {
    xfree(rls->runs); rls->runs = 0;
    rls->run_a = rls->run_u = 0;
  }
  if (cs->plugin_state) cs->plugin_state->nref--;
  if (cs->run_fd >= 0) close(cs->run_fd);
  xfree(cs->runlog_path);
  xfree(cs);
  return 0;
}

static int
reset_func(
        struct rldb_plugin_cnts *cdata,
        time_t init_duration,
        time_t init_sched_time,
        time_t init_finish_time)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;
  int i;

  rls->run_u = 0;
  if (rls->run_a > 0) {
    memset(rls->runs, 0, sizeof(rls->runs[0]) * rls->run_a);
    for (i = 0; i < rls->run_a; ++i)
      rls->runs[i].status = RUN_EMPTY;
  }

  memset(&rls->head, 0, sizeof(rls->head));
  rls->head.version = 2;
  rls->head.duration = init_duration;
  rls->head.sched_time = init_sched_time;
  rls->head.finish_time = init_finish_time;

  if (ftruncate(cs->run_fd, 0) < 0) {
    err("ftruncate failed: %s", os_ErrorMsg());
    return -1;
  }
  return run_flush_header(cs);
}

static int
set_runlog_func(
        struct rldb_plugin_cnts *cdata,
        int total_entries,
        struct run_entry *entries)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;
  int i;
  size_t size;

  if (total_entries > rls->run_a) {
    if (!rls->run_a) rls->run_a = 128;
    xfree(rls->runs);
    while (total_entries > rls->run_a) rls->run_a *= 2;
    XCALLOC(rls->runs, rls->run_a);
  } else {
    XMEMZERO(rls->runs, rls->run_a);
  }
  for (i = 0; i < rls->run_a; ++i)
    rls->runs[i].status = RUN_EMPTY;
  rls->run_u = total_entries;
  size = rls->run_u * sizeof(rls->runs[0]);
  if (rls->run_u > 0) memcpy(rls->runs, entries, size);
  sf_lseek(cs->run_fd, sizeof(struct run_header), SEEK_SET, "run");
  do_write(cs->run_fd, rls->runs, size);
  if (do_truncate(cs) < 0) return -1;
  return 0;
}

static int
backup_func(struct rldb_plugin_cnts *cdata)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  unsigned char *newlog = 0;
  struct stat sb;
  int r, i = 0;

  newlog = alloca(strlen(cs->runlog_path) + 16);
  do {
    sprintf(newlog, "%s.%d", cs->runlog_path, i++);
  } while (stat(newlog, &sb) >= 0);
  r = write_full_runlog_current_version(cs, newlog);
  if (r < 0) return r;
  close(r);
  return 0;
}

static int
flush_func(struct rldb_plugin_cnts *cdata)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  if (cs->run_fd < 0) ERR_R("invalid descriptor %d", cs->run_fd);
  if (sf_lseek(cs->run_fd, sizeof(rls->head), SEEK_SET, "run") == (off_t) -1)
    return -1;
  if (do_write(cs->run_fd, rls->runs, rls->run_u * sizeof(rls->runs[0])) < 0)
    return -1;
  return 0;
}

static int
append_to_end(runlog_state_t state, time_t t, int nsec)
{
  struct run_entry *runs = runs = state->runs;

  if (nsec < 0) nsec = 0;
  memset(&runs[state->run_u], 0, sizeof(runs[0]));
  runs[state->run_u].run_id = state->run_u;
  runs[state->run_u].status = RUN_EMPTY;
  runs[state->run_u].time = t;
  runs[state->run_u].nsec = nsec;
  return state->run_u++;
}

static int
get_insert_run_id(
        struct rldb_plugin_cnts *cdata,
        time_t t,
        int uid,
        int nsec)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  int i, j, k;
  struct run_entry *runs = 0;

  ASSERT(rls->run_u <= rls->run_a);
  if (rls->run_u == rls->run_a) {
    int new_a = rls->run_a * 2;
    struct run_entry *new_r = 0;

    if (!new_a) new_a = 128;
    XCALLOC(new_r, new_a);
    for (i = 0; i < new_a; ++i)
      new_r[i].status = RUN_EMPTY;
    if (rls->run_u > 0)
      memcpy(new_r, rls->runs, rls->run_u * sizeof(rls->runs[0]));
    xfree(rls->runs);
    rls->runs = new_r;
    rls->run_a = new_a;
  }
  runs = rls->runs;

  /*
   * RUN_EMPTY compilicates things! :(
   */
  if (!rls->run_u) return append_to_end(rls, t, nsec);

  j = rls->run_u - 1;
  while (j >= 0 && runs[j].status == RUN_EMPTY) j--;
  if (j < 0) return append_to_end(rls, t, nsec);
  if (t > runs[j].time) return append_to_end(rls, t, nsec);
  if (t == runs[j].time) {
    if (nsec < 0 && runs[j].nsec < NSEC_MAX) {
      nsec = runs[j].nsec + 1;
      return append_to_end(rls, t, nsec);
    }
    if (nsec > runs[j].nsec) return append_to_end(rls, t, nsec);
    if (nsec == runs[j].nsec && uid >= runs[j].user_id)
      return append_to_end(rls, t, nsec);
  }

  if (nsec < 0) {
    for (i = 0; i < rls->run_u; i++) {
      if (runs[i].status == RUN_EMPTY) continue;
      if (runs[i].time > t) break;
      if (runs[i].time < t) continue;
      // runs[i].time == t
      k = i;
      while (runs[i].status == RUN_EMPTY || runs[i].time == t) i++;
      j = i - 1;
      while (runs[j].status == RUN_EMPTY) j--;
      if (runs[j].nsec < NSEC_MAX) {
        nsec = runs[j].nsec + 1;
        break;
      }
      // DUMB :(
      nsec = random_u32() % (NSEC_MAX + 1);
      goto try_with_nsec;
    }
    ASSERT(i < rls->run_u);
  } else {
  try_with_nsec:
    for (i = 0; i < rls->run_u; i++) {
      if (runs[i].status == RUN_EMPTY) continue;
      if (runs[i].time > t) break;
      if (runs[i].time < t) continue;
      if (runs[i].nsec > nsec) break;
      if (runs[i].nsec < nsec) continue;
      if (runs[i].user_id > uid) break;
    }
  }

  /* So we going to insert a run at position i.
   * Check, that there is no "transient"-statused runs after this position.
   * This is very unlikely, because such runs appears when the run
   * is being compiled or run, and in this case its precise (nanosecond)
   * timestamp should be less, than the current run. However, if such
   * sutuation is detected, we fail because we cannot safely change
   * the run_id's when it is possible to receive compile or run response
   * packets.
   */
  for (j = i; j < rls->run_u; j++)
    if (runs[j].status >= RUN_TRANSIENT_FIRST
        && runs[j].status <= RUN_TRANSIENT_LAST)
      break;
  if (j < rls->run_u) {
    err("append_record: cannot safely insert a run at position %d", i);
    err("append_record: the run %d is transient!", j);
    return -1;
  }

  memmove(&runs[i + 1], &runs[i], (rls->run_u - i) * sizeof(runs[0]));
  rls->run_u++;
  for (j = i + 1; j < rls->run_u; j++)
    runs[j].run_id = j;

  if (nsec < 0) nsec = 0;
  memset(&runs[i], 0, sizeof(runs[0]));
  runs[i].run_id = i;
  runs[i].status = RUN_EMPTY;
  runs[i].time = t;
  runs[i].nsec = nsec;
  if (sf_lseek(cs->run_fd, sizeof(rls->head) + i * sizeof(runs[0]),
               SEEK_SET, "run") == (off_t) -1) return -1;
  if (do_write(cs->run_fd, &runs[i], (rls->run_u - i) * sizeof(runs[0])) < 0)
    return -1;
  return i;
}

static int
do_flush_entry(struct rldb_file_cnts *cs, int num)
{
  struct runlog_state *rls = cs->rl_state;

  ASSERT(num >= 0);

  if (cs->run_fd < 0) ERR_R("invalid descriptor %d", cs->run_fd);
  if (num < 0 || num >= rls->run_u) ERR_R("invalid entry number %d", num);
  if (sf_lseek(cs->run_fd, sizeof(rls->head) + sizeof(rls->runs[0]) * num,
               SEEK_SET, "run") == (off_t) -1) return -1;
  if (do_write(cs->run_fd, &rls->runs[num], sizeof(rls->runs[0])) < 0)
    return -1;
  return num;
}

static int
add_entry_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        const struct run_entry *re,
        int flags)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;
  struct run_entry *de;

  ASSERT(run_id >= 0 && run_id < rls->run_a);
  de = &rls->runs[run_id];

  if ((flags & RE_SIZE)) {
    de->size = re->size;
  }
  if ((flags & RE_IP)) {
    de->a = re->a;
    de->ipv6_flag = re->ipv6_flag;
  }
  if ((flags & RE_SHA1)) {
    memcpy(de->sha1, re->sha1, sizeof(de->sha1));
  }
  if ((flags & RE_USER_ID)) {
    de->user_id = re->user_id;
  }
  if ((flags & RE_PROB_ID)) {
    de->prob_id = re->prob_id;
  }
  if ((flags & RE_LANG_ID)) {
    de->lang_id = re->lang_id;
  }
  if ((flags & RE_LOCALE_ID)) {
    de->locale_id = re->locale_id;
  }
  if ((flags & RE_STATUS)) {
    de->status = re->status;
  }
  if ((flags & RE_TEST)) {
    de->test = re->test;
  }
  if ((flags & RE_SCORE)) {
    de->score = re->score;
  }
  if ((flags & RE_IS_IMPORTED)) {
    de->is_imported = re->is_imported;
  }
  if ((flags & RE_VARIANT)) {
    de->variant = re->variant;
  }
  if ((flags & RE_IS_HIDDEN)) {
    de->is_hidden = re->is_hidden;
  }
  if ((flags & RE_IS_READONLY)) {
    de->is_readonly = re->is_readonly;
  }
  if ((flags & RE_PAGES)) {
    de->pages = re->pages;
  }
  if ((flags & RE_SCORE_ADJ)) {
    de->score_adj = re->score_adj;
  }
  if ((flags & RE_IS_EXAMINABLE)) {
    de->is_examinable = re->is_examinable;
  }
  if ((flags & RE_JUDGE_ID)) {
    de->judge_id = re->judge_id;
  }
  if ((flags & RE_SSL_FLAG)) {
    de->ssl_flag = re->ssl_flag;
  }
  if ((flags & RE_MIME_TYPE)) {
    de->mime_type = re->mime_type;
  }
  if ((flags & RE_EXAMINERS)) {
    memcpy(de->examiners, re->examiners, sizeof(de->examiners));
  }
  if ((flags & RE_EXAM_SCORE)) {
    memcpy(de->exam_score, re->exam_score, sizeof(de->exam_score));
  }
  if ((flags & RE_IS_MARKED)) {
    de->is_marked = re->is_marked;
  }
  if ((flags & RE_IS_SAVED)) {
    de->is_saved = re->is_saved;
  }
  if ((flags & RE_SAVED_STATUS)) {
    de->saved_status = re->saved_status;
  }
  if ((flags & RE_SAVED_SCORE)) {
    de->saved_score = re->saved_score;
  }
  if ((flags & RE_SAVED_TEST)) {
    de->saved_test = re->saved_test;
  }

  return do_flush_entry(cs, run_id);
}

static int
undo_add_entry_func(
        struct rldb_plugin_cnts *cdata,
        int run_id)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  ASSERT(run_id >= 0 && run_id < rls->run_u);

  if (run_id == rls->run_u - 1) {
    rls->run_u--;
    memset(&rls->runs[rls->run_u], 0, sizeof(rls->runs[0]));
    rls->runs[rls->run_u].status = RUN_EMPTY;
    if (do_truncate(cs) < 0) return -1;
    return 0;
  }
  // clear run
  memset(&rls->runs[run_id], 0, sizeof(rls->runs[0]));
  rls->runs[run_id].run_id = run_id;
  rls->runs[run_id].status = RUN_EMPTY;
  return 0;
}

static int
change_status_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_status,
        int new_test,
        int new_score,
        int judge_id)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  ASSERT(run_id >= 0 && run_id < rls->run_u);

  rls->runs[run_id].status = new_status;
  rls->runs[run_id].test = new_test;
  rls->runs[run_id].score = new_score;
  rls->runs[run_id].judge_id = judge_id;
  return do_flush_entry(cs, run_id);
}

static int
start_func(
        struct rldb_plugin_cnts *cdata,
        time_t start_time)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  rls->head.start_time = start_time;
  rls->head.sched_time = 0;
  return run_flush_header(cs);
}

static int
stop_func(
        struct rldb_plugin_cnts *cdata,
        time_t stop_time)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  rls->head.stop_time = stop_time;
  return run_flush_header(cs);
}

static int
set_duration_func(
        struct rldb_plugin_cnts *cdata,
        int duration)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  rls->head.duration = duration;
  return run_flush_header(cs);
}

static int
schedule_func(
        struct rldb_plugin_cnts *cdata,
        time_t sched_time)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  rls->head.sched_time = sched_time;
  return run_flush_header(cs);
}

static int
set_finish_time_func(
        struct rldb_plugin_cnts *cdata,
        time_t finish_time)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  rls->head.finish_time = finish_time;
  return run_flush_header(cs);
}

static int
save_times_func(struct rldb_plugin_cnts *cdata)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  rls->head.saved_duration = rls->head.duration;
  rls->head.saved_stop_time = rls->head.stop_time;
  rls->head.saved_finish_time = rls->head.finish_time;
  return run_flush_header(cs);
}

static int
set_status_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_status)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  ASSERT(run_id >= 0 && run_id < rls->run_u);

  rls->runs[run_id].status = new_status;
  return do_flush_entry(cs, run_id);
}

static int
clear_entry_func(
        struct rldb_plugin_cnts *cdata,
        int run_id)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  ASSERT(run_id >= 0 && run_id < rls->run_u);

  if (run_id == rls->run_u - 1) {
    rls->run_u--;
    memset(&rls->runs[rls->run_u], 0, sizeof(rls->runs[0]));
    rls->runs[rls->run_u].status = RUN_EMPTY;
    if (do_truncate(cs) < 0) return -1;
    return 0;
  }

  memset(&rls->runs[run_id], 0, sizeof(rls->runs[run_id]));
  rls->runs[run_id].status = RUN_EMPTY;
  rls->runs[run_id].run_id = run_id;
  return do_flush_entry(cs, run_id);
}

static int
set_hidden_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_hidden)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  ASSERT(run_id >= 0 && run_id < rls->run_u);

  rls->runs[run_id].is_hidden = new_hidden;
  return do_flush_entry(cs, run_id);
}

static int
set_judge_id_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_judge_id)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  ASSERT(run_id >= 0 && run_id < rls->run_u);

  rls->runs[run_id].judge_id = new_judge_id;
  return do_flush_entry(cs, run_id);
}

static int
set_pages_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_pages)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  ASSERT(run_id >= 0 && run_id < rls->run_u);

  rls->runs[run_id].pages = new_pages;
  return do_flush_entry(cs, run_id);
}

static int
set_entry_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        const struct run_entry *in,
        int flags)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  ASSERT(run_id >= 0 && run_id < rls->run_u);

  memcpy(&rls->runs[run_id], in, sizeof(*in));
  return do_flush_entry(cs, run_id);
}

static int
squeeze_func(struct rldb_plugin_cnts *cdata)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  int i, j, retval, first_moved = -1, w;
  unsigned char *ptr;
  size_t tot;

  for (i = 0, j = 0; i < rls->run_u; i++) {
    if (rls->runs[i].status == RUN_EMPTY) continue;
    if (i != j) {
      if (first_moved < 0) first_moved = j;
      memcpy(&rls->runs[j], &rls->runs[i], sizeof(rls->runs[j]));
      rls->runs[j].run_id = j;
    }
    j++;
  }
  if  (rls->run_u == j) {
    // no runs were removed
    ASSERT(first_moved == -1);
    return 0;
  }

  retval = rls->run_u - j;
  rls->run_u = j;
  if (rls->run_u < rls->run_a) {
    memset(&rls->runs[rls->run_u], 0,
           (rls->run_a - rls->run_u) * sizeof(rls->runs[0]));
  }

  // update log on disk
  if (do_truncate(cs) < 0) return -1;
  if (first_moved == -1) {
    // no entries were moved because the only entries empty were the last
    return retval;
  }
  ASSERT(first_moved >= 0 && first_moved < rls->run_u);
  if (sf_lseek(cs->run_fd,
               sizeof(rls->head) + first_moved * sizeof(rls->runs[0]),
               SEEK_SET, "run") == (off_t) -1)
    return -1;
  tot = (rls->run_u - first_moved) * sizeof(rls->runs[0]);
  ptr = (unsigned char *) &rls->runs[first_moved];
  while (tot > 0) {
    w = write(cs->run_fd, ptr, tot);
    if (w <= 0) {
      err("run_squeeze_log: write error: %s", os_ErrorMsg());
      return -1;
    }
    tot -= w;
    ptr += w;
  }
  return retval;
}

static int
change_status_2_func(
        struct rldb_plugin_cnts *cdata,
        int run_id,
        int new_status,
        int new_test,
        int new_score,
        int judge_id,
        int is_marked)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  ASSERT(run_id >= 0 && run_id < rls->run_u);

  rls->runs[run_id].status = new_status;
  rls->runs[run_id].test = new_test;
  rls->runs[run_id].score = new_score;
  rls->runs[run_id].judge_id = judge_id;
  rls->runs[run_id].is_marked = is_marked;
  return do_flush_entry(cs, run_id);
}

static int
check_func(
        struct rldb_plugin_cnts *cdata,
        FILE *log_f)
{
  struct rldb_file_cnts *cs = (struct rldb_file_cnts*) cdata;
  struct runlog_state *rls = cs->rl_state;

  int retval = 0;

  retval = run_fix_runlog_time(log_f, rls->run_u, rls->runs, NULL);
  if (retval < 0) {
    return retval;
  }

  // FIXME: save the updated runs
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
