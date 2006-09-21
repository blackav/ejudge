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
#include "ej_types.h"

#include "clarlog.h"

#include "teamdb.h"
#include "base64.h"

#include "unix/unix_fileutl.h"
#include "pathutl.h"
#include "errlog.h"
#include "xml_utils.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define CLAR_RECORD_SIZE 79
#define SUBJ_STRING_SIZE 24
#define IP_STRING_SIZE   15

static const char signature_v1[] = "eJudge clar log";

/* new clarification log header */
struct clar_header_v1
{
  unsigned char signature[16];  /* "eJudge clar log" */
  unsigned char version;        /* file version */
  unsigned char endianness;     /* 0 - little, 1 - big endian */
  unsigned char _pad[110];
};

/* new version of the clarification log */
struct clar_array
{
  int                   a, u;
  struct clar_entry_v1 *v;
};

struct clarlog_state
{
  struct clar_header_v1 header;
  struct clar_array clars;
  int clar_fd;
};

#define ERR_R(t, args...) do { do_err_r(__FUNCTION__, t , ##args); return -1; } while (0)

static int
clar_read_record_v0(clarlog_state_t state, char *buf, int size)
{
  int rsz, i;

  if ((rsz = sf_read(state->clar_fd, buf, size, "clar")) < 0) return rsz;
  if (rsz != size) ERR_R("short read: %d", rsz);

  for (i = 0; i < size - 1; i++) {
    if (buf[i] >= 0 && buf[i] < ' ') break;
  }
  if (i < size - 1) ERR_R("bad characters in record");
  if (buf[size - 1] != '\n') ERR_R("record improperly terminated");
  return 0;
}

static int
clar_read_entry(clarlog_state_t state, int n)
{
  char buf[CLAR_RECORD_SIZE + 16];
  char b2[CLAR_RECORD_SIZE + 16];
  char b3[CLAR_RECORD_SIZE + 16];
  int  k, r;

  int r_time;
  unsigned int r_size;
  ej_ip_t r_ip;

  memset(buf, 0, sizeof(buf));
  memset(&state->clars.v[n], 0, sizeof(state->clars.v[0]));
  if (clar_read_record_v0(state, buf, CLAR_RECORD_SIZE) < 0) return -1;

  r = sscanf(buf, "%d %d %u %d %d %d %s %s %n",
             &state->clars.v[n].id, &r_time, &r_size,
             &state->clars.v[n].from,
             &state->clars.v[n].to, &state->clars.v[n].flags,
             b2, b3, &k);
  if (r != 8) ERR_R("[%d]: sscanf returned %d", n, r);
  if (buf[k] != 0) ERR_R("[%d]: excess data", n);

  /* do sanity checking */
  state->clars.v[n].size = r_size;
  state->clars.v[n].time = r_time;
  if (state->clars.v[n].id != n) ERR_R("[%d]: bad id: %d", n,
                                       state->clars.v[n].id);
  if (state->clars.v[n].size == 0 || state->clars.v[n].size >= 10000)
    ERR_R("[%d]: bad size: %d", n, state->clars.v[n].size);
  // FIXME: how to check consistency?
  /*
  if (clars.v[n].from && !teamdb_lookup(clars.v[n].from))
    ERR_R("[%d]: bad from: %d", n, clars.v[n].from);
  if (clars.v[n].to && !teamdb_lookup(clars.v[n].to))
    ERR_R("[%d]: bad to: %d", n, clars.v[n].to);
  */
  if (state->clars.v[n].flags < 0 || state->clars.v[n].flags > 255)
    ERR_R("[%d]: bad flags: %d", n, state->clars.v[n].flags);
  if (strlen(b2) > IP_STRING_SIZE) ERR_R("[%d]: ip is too long", n);
  if (strlen(b3) > SUBJ_STRING_SIZE) ERR_R("[%d]: subj is too long", n);
  if (xml_parse_ip(0, n + 1, 0, b2, &r_ip) < 0) ERR_R("[%d]: ip is invalid", n);
  state->clars.v[n].a.ip = r_ip;
  base64_decode_str(b3, state->clars.v[n].subj, 0);
  return 0;
}

static int
create_new_clar_log(clarlog_state_t state, int flags)
{
  int wsz;

  memset(&state->header, 0, sizeof(state->header));
  strncpy(state->header.signature, signature_v1,
          sizeof(state->header.signature));
  state->header.version = 1;

  if (state->clars.v) {
    xfree(state->clars.v);
    state->clars.v = 0;
    state->clars.u = state->clars.a = 0;
  }
  state->clars.a = 128;
  XCALLOC(state->clars.v, state->clars.a);

  if (flags == CLAR_LOG_READONLY) return 0;

  if (ftruncate(state->clar_fd, 0) < 0) {
    err("clar_log: ftruncate() failed: %s", os_ErrorMsg());
    return -1;
  }
  if (sf_lseek(state->clar_fd, 0, SEEK_SET, "clar") == (off_t) -1)
    return -1;
  wsz = write(state->clar_fd, &state->header, sizeof(state->header));
  if (wsz <= 0) {
    err("clar_log: write() failed: %s", os_ErrorMsg());
    return -1;
  }
  if (wsz != sizeof(state->header)) {
    err("clar_log: short write: %d instead of %zu", wsz, sizeof(state->header));
    return -1;
  }
  return 0;
}

static int
write_all_clarlog(clarlog_state_t state)
{
  int wsz, bsz;
  const unsigned char *buf;

  if (sf_lseek(state->clar_fd, 0, SEEK_SET, "clar_write") < 0) return -1;

  if ((wsz = sf_write(state->clar_fd, &state->header, sizeof(state->header),
                      "clar_write")) < 0)
    return -1;
  if (wsz != sizeof(state->header)) {
    err("clar_write: short write: %d", wsz);
    return -1;
  }

  buf = (const unsigned char*) state->clars.v;
  bsz = sizeof(state->clars.v[0]) * state->clars.u;
  while (bsz > 0) {
    if ((wsz = sf_write(state->clar_fd, buf, bsz, "clar_write")) <= 0)
      return -1;
    buf += wsz;
    bsz -= wsz;
  }
  return 0;
}

static int
convert_log_from_version_0(clarlog_state_t state, int flags, off_t length,
                           const unsigned char *path)
{
  path_t v0_path;
  int i;

  if (length % CLAR_RECORD_SIZE != 0) {
    err("invalid size %d of clar file (version 0)", (int) length);
    return -1;
  }

  state->clars.u = length / CLAR_RECORD_SIZE;
  state->clars.a = 128;
  while (state->clars.u > state->clars.a) state->clars.a *= 2;
  XCALLOC(state->clars.v, state->clars.a);
  for (i = 0; i < state->clars.u; i++) {
    if (clar_read_entry(state, i) < 0) return -1;
  }

  info("clar log version 0 successfully read");

  memset(&state->header, 0, sizeof(state->header));
  strncpy(state->header.signature, signature_v1,
          sizeof(state->header.signature));
  state->header.version = 1;

  if (flags == CLAR_LOG_READONLY) return 0;

  close(state->clar_fd); state->clar_fd = -1;
  snprintf(v0_path, sizeof(v0_path), "%s.v0", path);
  if (rename(path, v0_path) < 0) {
    err("rename() failed: %s", os_ErrorMsg());
    return -1;
  }

  if ((state->clar_fd = sf_open(path, O_RDWR|O_CREAT|O_TRUNC, 0666)) < 0)
    return -1;

  return write_all_clarlog(state);
}

static int
read_clar_file_header(clarlog_state_t state, off_t length)
{
  int rsz = 0;

  if (length < sizeof(struct clar_header_v1)) return 0;
  if ((length - sizeof(struct clar_header_v1))
      % sizeof(struct clar_entry_v1) != 0) return 0;
  if (sf_lseek(state->clar_fd, 0, SEEK_SET, "clar_open") < 0) return -1;
  if ((rsz = sf_read(state->clar_fd, &state->header, sizeof(state->header),
                     "clar_open")) < 0)
    return -1;
  if (rsz != sizeof(state->header)) return -1;
  if (strcmp(state->header.signature, signature_v1)) return 0;
  if (state->header.endianness > 1) return 0;
  return state->header.version;
}

static int
read_clar_file(clarlog_state_t state, off_t length)
{
  unsigned char *buf;
  int bsz, rsz;

  state->clars.u = (length - sizeof(struct clar_header_v1))
    / sizeof(struct clar_entry_v1);
  state->clars.a = 128;
  while (state->clars.a < state->clars.u) state->clars.a *= 2;
  XCALLOC(state->clars.v, state->clars.a);

  if (sf_lseek(state->clar_fd, sizeof(struct clar_header_v1), SEEK_SET,
               "clar_read")<0)
    return -1;

  buf = (unsigned char*) state->clars.v;
  bsz = sizeof(state->clars.v[0]) * state->clars.u;
  while (bsz > 0) {
    if ((rsz = sf_read(state->clar_fd, buf, bsz, "clar_read")) < 0) return -1;
    if (!rsz) {
      err("clar_read: unexpected EOF");
      return -1;
    }
    bsz -= rsz; buf += rsz;
  }
  return 0;
}

clarlog_state_t
clar_init(void)
{
  clarlog_state_t p;

  XCALLOC(p, 1);
  p->clar_fd = -1;
  return p;
}

clarlog_state_t
clar_destroy(clarlog_state_t state)
{
  if (!state) return 0;
  xfree(state->clars.v);
  if (state->clar_fd >= 0) close(state->clar_fd);
  memset(state, 0, sizeof(*state));
  xfree(state);
  return 0;
}

int
clar_open(clarlog_state_t state, char const *path, int flags)
{
  int version;
  struct stat stb;

  info("clar_open: opening database %s", path);
  if (state->clars.v) {
    xfree(state->clars.v);
    state->clars.v = 0;
    state->clars.u = state->clars.a = 0;
  }
  if (state->clar_fd >= 0) {
    close(state->clar_fd); state->clar_fd = -1;
  }
  if (flags == CLAR_LOG_READONLY) {
    if ((state->clar_fd = sf_open(path, O_RDONLY, 0)) < 0) return -1;
  } else {
    if ((state->clar_fd = sf_open(path, O_RDWR | O_CREAT, 0666)) < 0) return -1;
  }

  if (fstat(state->clar_fd, &stb) < 0) {
    err("fstat() failed: %s", os_ErrorMsg());
    close(state->clar_fd); state->clar_fd = -1;
    return -1;
  }
  if (!stb.st_size) {
    return create_new_clar_log(state, flags);
  }
  if ((version = read_clar_file_header(state, stb.st_size)) < 0)
    return -1;
  if (!version) {
    return convert_log_from_version_0(state, flags, stb.st_size, path);
  }
  if (version > 1) {
    err("clar_log: cannot handle clar log file of version %d", version);
    return -1;
  }
  return read_clar_file(state, stb.st_size);
}

static int
clar_flush_entry(clarlog_state_t state, int num)
{
  int wsz;

  if (sf_lseek(state->clar_fd,
               sizeof(struct clar_entry_v1) * num
               + sizeof(struct clar_header_v1),
               SEEK_SET, "clar_flush_entry") < 0)
    return -1;

  if ((wsz = sf_write(state->clar_fd, &state->clars.v[num], sizeof(state->clars.v[0]), "clar_flush_entry")) < 0) return -1;
  if (wsz != sizeof(state->clars.v[0])) ERR_R("short write: %d", wsz);
  return 0;
}

int
clar_add_record(clarlog_state_t state,
                time_t         time,
                size_t         size,
                char const    *ip,
                int            from,
                int            to,
                int            flags,
                int            j_from,
                int            hide_flag,
                char const    *subj)
{
  int i;
  ej_ip_t r_ip;

  if (size == 0 || size > 9999) ERR_R("bad size: %lu", size);
  // FIXME: how to check consistency?
  /*
  if (from && !teamdb_lookup(from)) ERR_R("bad from: %d", from);
  if (to && !teamdb_lookup(to)) ERR_R("bad to: %d", to);
  */
  if (flags < 0 || flags > 255) ERR_R("bad flags: %d", flags);
  if (strlen(subj) > SUBJ_STRING_SIZE)
    ERR_R("bad subj size: %d", strlen(subj));
  if (strlen(ip) > IP_STRING_SIZE) ERR_R("bad ip size: %d", strlen(ip));
  if (xml_parse_ip(0, 0, 0, ip, &r_ip) < 0) ERR_R("bad IP");

  if (state->clars.u >= state->clars.a) {
    if (!(state->clars.a *= 2)) state->clars.a = 128;
    state->clars.v = xrealloc(state->clars.v, state->clars.a * sizeof(state->clars.v[0]));
    info("clar_add_record: array extended: %d", state->clars.a);
  }
  i = state->clars.u++;

  memset(&state->clars.v[i], 0, sizeof(state->clars.v[0]));
  state->clars.v[i].id = i;
  state->clars.v[i].time = time;
  state->clars.v[i].size = size;
  state->clars.v[i].from = from;
  state->clars.v[i].to = to;
  state->clars.v[i].flags = flags;
  state->clars.v[i].j_from = j_from;
  state->clars.v[i].hide_flag = hide_flag;
  state->clars.v[i].a.ip = r_ip;
  base64_decode_str(subj, state->clars.v[i].subj, 0);
  if (clar_flush_entry(state, i) < 0) return -1;
  return i;
}

int
clar_add_record_new(clarlog_state_t state,
                    time_t         time,
                    int            nsec,
                    size_t         size,
                    ej_ip_t        ip,
                    int            ssl_flag,
                    int            from,
                    int            to,
                    int            flags,
                    int            j_from,
                    int            hide_flag,
                    const unsigned char *subj)
{
  int i;
  unsigned char subj2[CLAR_ENTRY_SUBJ_SIZE];
  size_t subj_len;
  struct clar_entry_v1 *pc;

  if (state->clars.u >= state->clars.a) {
    if (!(state->clars.a *= 2)) state->clars.a = 128;
    state->clars.v = xrealloc(state->clars.v, state->clars.a * sizeof(state->clars.v[0]));
    info("clar_add_record: array extended: %d", state->clars.a);
  }
  i = state->clars.u++;
  pc = &state->clars.v[i];

  memset(pc, 0, sizeof(*pc));
  pc->id = i;
  pc->time = time;
  pc->nsec = nsec;
  pc->size = size;
  pc->from = from;
  pc->to = to;
  pc->flags = flags;
  pc->j_from = j_from;
  pc->hide_flag = hide_flag;
  pc->a.ip = ip;
  pc->ssl_flag = ssl_flag;

  if (!subj) subj = "";
  subj_len = strlen(subj);
  if (subj_len >= CLAR_ENTRY_SUBJ_SIZE) {
    memcpy(subj2, subj, CLAR_ENTRY_SUBJ_SIZE - 4);
    subj2[CLAR_ENTRY_SUBJ_SIZE - 1] = 0;
    subj2[CLAR_ENTRY_SUBJ_SIZE - 2] = '.';
    subj2[CLAR_ENTRY_SUBJ_SIZE - 3] = '.';
    subj2[CLAR_ENTRY_SUBJ_SIZE - 4] = '.';
    memcpy(pc->subj, subj2, CLAR_ENTRY_SUBJ_SIZE);
  } else {
    strcpy(pc->subj, subj);
  }

  if (clar_flush_entry(state, i) < 0) return -1;
  return i;
}

int
clar_get_record(clarlog_state_t state,
                int id,
                time_t        *ptime,
                size_t        *psize,
                char          *ip,
                int           *pfrom,
                int           *pto,
                int           *pflags,
                int           *pj_from,
                int           *p_hide_flag,
                char          *subj)
{
  if (id < 0 || id >= state->clars.u) ERR_R("bad id: %d", id);
  if (state->clars.v[id].id != id)
    ERR_R("id mismatch: %d, %d", id, state->clars.v[id].id);

  if (ptime)   *ptime   = state->clars.v[id].time;
  if (psize)   *psize   = state->clars.v[id].size;
  if (ip)                 strcpy(ip, xml_unparse_ip(state->clars.v[id].a.ip));
  if (pfrom)   *pfrom   = state->clars.v[id].from;
  if (pto)     *pto     = state->clars.v[id].to;
  if (pflags)  *pflags  = state->clars.v[id].flags;
  if (pj_from) *pj_from = state->clars.v[id].j_from;
  if (p_hide_flag) *p_hide_flag = state->clars.v[id].hide_flag;
  if (subj)               base64_encode_str(state->clars.v[id].subj, subj);
  return 0;
}

int
clar_get_record_new(clarlog_state_t state,
                    int clar_id,
                    struct clar_entry_v1 *pclar)
{
  if (clar_id < 0 || clar_id >= state->clars.u) ERR_R("bad id: %d", clar_id);
  if (state->clars.v[clar_id].id != clar_id)
    ERR_R("id mismatch: %d, %d", clar_id, state->clars.v[clar_id].id);
  memcpy(pclar, &state->clars.v[clar_id], sizeof(*pclar));
  return 0;
}

int
clar_update_flags(clarlog_state_t state, int id, int flags)
{
  if (id < 0 || id >= state->clars.u) ERR_R("bad id: %d", id);
  if (state->clars.v[id].id != id)
    ERR_R("id mismatch: %d, %d", id, state->clars.v[id].id);
  if (flags < 0 || flags > 255) ERR_R("bad flags: %d", flags);

  state->clars.v[id].flags = flags;
  if (clar_flush_entry(state, id) < 0) return -1;
  return 0;
}

int
clar_get_total(clarlog_state_t state)
{
  return state->clars.u;
}

void
clar_get_team_usage(clarlog_state_t state, int from, int *pn, size_t *ps)
{
  int i;
  size_t total = 0;
  int n = 0;

  for (i = 0; i < state->clars.u; i++)
    if (state->clars.v[i].from == from) {
      total += state->clars.v[i].size;
      n++;
    }
  if (pn) *pn = n;
  if (ps) *ps = total;
}

char *
clar_flags_html(clarlog_state_t state, int flags, int from, int to, char *buf,
                int len)
{
  char *s = "";

  if (!from)           s = "&nbsp;";
  else if (flags == 0) s = "N";
  else if (flags == 1) s = "R";
  else if (flags == 2) s = "A";
  else s = "?";

  if (!buf) return s;
  if (len <= 0) return strcpy(buf, s);
  strncpy(buf, s, len);
  buf[len - 1] = 0;
  return buf;
}

void
clar_reset(clarlog_state_t state)
{
  create_new_clar_log(state, 0);
}

void
clar_clear_variables(clarlog_state_t state)
{
  if (state->clars.v) xfree(state->clars.v);
  state->clars.v = 0;
  state->clars.u = state->clars.a = 0;
  if (state->clar_fd >= 0) close(state->clar_fd);
  state->clar_fd = -1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
