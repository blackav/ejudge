/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2006 Alexander Chernov <cher@ispras.ru> */

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
struct clar_entry_v1
{
  int id;                       /* 4 */
  ej_size_t size;               /* 4 */
  ej_time64_t time;             /* 8 */
  int nsec;                     /* 4 */
  int from;                     /* 4 */
  int to;                       /* 4 */
  int j_from;                   /* 4 */
  unsigned int flags;           /* 4 */
  unsigned char ip6_flag;       /* 1 */
  unsigned char hide_flag;      /* 1 */
  unsigned char _pad1[2];       /* 2 */
  union
  {
    ej_ip_t ip;
    unsigned char ip6[16];
  } a;                          /* 16 */
  unsigned char _pad2[40];
  unsigned char subj[32];
};                              /* 128 */

struct clar_array
{
  int                   a, u;
  struct clar_entry_v1 *v;
};

static struct clar_header_v1 header;
static struct clar_array     clars;
static int                   clar_fd = -1;

#define ERR_R(t, args...) do { do_err_r(__FUNCTION__, t , ##args); return -1; } while (0)

static int
clar_read_record_v0(char *buf, int size)
{
  int rsz, i;

  if ((rsz = sf_read(clar_fd, buf, size, "clar")) < 0) return rsz;
  if (rsz != size) ERR_R("short read: %d", rsz);

  for (i = 0; i < size - 1; i++) {
    if (buf[i] >= 0 && buf[i] < ' ') break;
  }
  if (i < size - 1) ERR_R("bad characters in record");
  if (buf[size - 1] != '\n') ERR_R("record improperly terminated");
  return 0;
}

static int
clar_read_entry(int n)
{
  char buf[CLAR_RECORD_SIZE + 16];
  char b2[CLAR_RECORD_SIZE + 16];
  char b3[CLAR_RECORD_SIZE + 16];
  int  k, r;

  int r_time;
  unsigned int r_size;
  ej_ip_t r_ip;

  memset(buf, 0, sizeof(buf));
  memset(&clars.v[n], 0, sizeof(clars.v[0]));
  if (clar_read_record_v0(buf, CLAR_RECORD_SIZE) < 0) return -1;

  r = sscanf(buf, "%d %d %u %d %d %d %s %s %n",
             &clars.v[n].id, &r_time, &r_size,
             &clars.v[n].from,
             &clars.v[n].to, &clars.v[n].flags,
             b2, b3, &k);
  if (r != 8) ERR_R("[%d]: sscanf returned %d", n, r);
  if (buf[k] != 0) ERR_R("[%d]: excess data", n);

  /* do sanity checking */
  clars.v[n].size = r_size;
  clars.v[n].time = r_time;
  if (clars.v[n].id != n) ERR_R("[%d]: bad id: %d", n, clars.v[n].id);
  if (clars.v[n].size == 0 || clars.v[n].size >= 10000)
    ERR_R("[%d]: bad size: %d", n, clars.v[n].size);
  // FIXME: how to check consistency?
  /*
  if (clars.v[n].from && !teamdb_lookup(clars.v[n].from))
    ERR_R("[%d]: bad from: %d", n, clars.v[n].from);
  if (clars.v[n].to && !teamdb_lookup(clars.v[n].to))
    ERR_R("[%d]: bad to: %d", n, clars.v[n].to);
  */
  if (clars.v[n].flags < 0 || clars.v[n].flags > 255)
    ERR_R("[%d]: bad flags: %d", n, clars.v[n].flags);
  if (strlen(b2) > IP_STRING_SIZE) ERR_R("[%d]: ip is too long", n);
  if (strlen(b3) > SUBJ_STRING_SIZE) ERR_R("[%d]: subj is too long", n);
  if (xml_parse_ip(0, n + 1, 0, b2, &r_ip) < 0) ERR_R("[%d]: ip is invalid", n);
  clars.v[n].a.ip = r_ip;
  base64_decode_str(b3, clars.v[n].subj, 0);
  return 0;
}

static int
create_new_clar_log(int flags)
{
  int wsz;

  memset(&header, 0, sizeof(header));
  strncpy(header.signature, signature_v1, sizeof(header.signature));
  header.version = 1;

  if (clars.v) {
    xfree(clars.v); clars.v = 0; clars.u = clars.a = 0;
  }
  clars.a = 128;
  XCALLOC(clars.v, clars.a);

  if (flags == CLAR_LOG_READONLY) return 0;

  if (ftruncate(clar_fd, 0) < 0) {
    err("clar_log: ftruncate() failed: %s", os_ErrorMsg());
    return -1;
  }
  if (sf_lseek(clar_fd, 0, SEEK_SET, "clar") == (off_t) -1)
    return -1;
  wsz = write(clar_fd, &header, sizeof(header));
  if (wsz <= 0) {
    err("clar_log: write() failed: %s", os_ErrorMsg());
    return -1;
  }
  if (wsz != sizeof(header)) {
    err("clar_log: short write: %d instead of %d", wsz, sizeof(header));
    return -1;
  }
  return 0;
}

static int
write_all_clarlog(void)
{
  int wsz, bsz;
  const unsigned char *buf;

  if (sf_lseek(clar_fd, 0, SEEK_SET, "clar_write") < 0) return -1;

  if ((wsz = sf_write(clar_fd, &header, sizeof(header), "clar_write")) < 0)
    return -1;
  if (wsz != sizeof(header)) {
    err("clar_write: short write: %d", wsz);
    return -1;
  }

  buf = (const unsigned char*) clars.v;
  bsz = sizeof(clars.v[0]) * clars.u;
  while (bsz > 0) {
    if ((wsz = sf_write(clar_fd, buf, bsz, "clar_write")) <= 0)
      return -1;
    buf += wsz;
    bsz -= wsz;
  }
  return 0;
}

static int
convert_log_from_version_0(int flags, off_t length,
                           const unsigned char *path)
{
  path_t v0_path;
  int i;

  if (length % CLAR_RECORD_SIZE != 0) {
    err("invalid size %d of clar file (version 0)", (int) length);
    return -1;
  }

  clars.u = length / CLAR_RECORD_SIZE;
  clars.a = 128;
  while (clars.u > clars.a) clars.a *= 2;
  XCALLOC(clars.v, clars.a);
  for (i = 0; i < clars.u; i++) {
    if (clar_read_entry(i) < 0) return -1;
  }

  info("clar log version 0 successfully read");

  memset(&header, 0, sizeof(header));
  strncpy(header.signature, signature_v1, sizeof(header.signature));
  header.version = 1;

  if (flags == CLAR_LOG_READONLY) return 0;

  close(clar_fd); clar_fd = -1;
  snprintf(v0_path, sizeof(v0_path), "%s.v0", path);
  if (rename(path, v0_path) < 0) {
    err("rename() failed: %s", os_ErrorMsg());
    return -1;
  }

  if ((clar_fd = sf_open(path, O_RDWR|O_CREAT|O_TRUNC, 0666)) < 0) return -1;

  return write_all_clarlog();
}

static int
read_clar_file_header(off_t length)
{
  int rsz = 0;

  if (length < sizeof(struct clar_header_v1)) return 0;
  if ((length - sizeof(struct clar_header_v1)) % sizeof(struct clar_entry_v1) != 0) return 0;
  if (sf_lseek(clar_fd, 0, SEEK_SET, "clar_open") < 0) return -1;
  if ((rsz = sf_read(clar_fd, &header, sizeof(header), "clar_open")) < 0)
    return -1;
  if (rsz != sizeof(header)) return -1;
  if (strcmp(header.signature, signature_v1)) return 0;
  if (header.endianness > 1) return 0;
  return header.version;
}

static int
read_clar_file(off_t length)
{
  unsigned char *buf;
  int bsz, rsz;

  clars.u = (length - sizeof(struct clar_header_v1)) / sizeof(struct clar_entry_v1);
  clars.a = 128;
  while (clars.a < clars.u) clars.a *= 2;
  XCALLOC(clars.v, clars.a);

  if (sf_lseek(clar_fd, sizeof(struct clar_header_v1), SEEK_SET, "clar_read")<0)
    return -1;

  buf = (unsigned char*) clars.v;
  bsz = sizeof(clars.v[0]) * clars.u;
  while (bsz > 0) {
    if ((rsz = sf_read(clar_fd, buf, bsz, "clar_read")) < 0) return -1;
    if (!rsz) {
      err("clar_read: unexpected EOF");
      return -1;
    }
    bsz -= rsz; buf += rsz;
  }
  return 0;
}

int
clar_open(char const *path, int flags)
{
  int version;
  struct stat stb;

  info("clar_open: opening database %s", path);
  if (clars.v) {
    xfree(clars.v); clars.v = 0; clars.u = clars.a = 0;
  }
  if (clar_fd >= 0) {
    close(clar_fd); clar_fd = -1;
  }
  if (flags == CLAR_LOG_READONLY) {
    if ((clar_fd = sf_open(path, O_RDONLY, 0)) < 0) return -1;
  } else {
    if ((clar_fd = sf_open(path, O_RDWR | O_CREAT, 0666)) < 0) return -1;
  }

  if (fstat(clar_fd, &stb) < 0) {
    err("fstat() failed: %s", os_ErrorMsg());
    close(clar_fd); clar_fd = -1;
    return -1;
  }
  if (!stb.st_size) {
    return create_new_clar_log(flags);
  }
  if ((version = read_clar_file_header(stb.st_size)) < 0)
    return -1;
  if (!version) {
    return convert_log_from_version_0(flags, stb.st_size, path);
  }
  if (version > 1) {
    err("clar_log: cannot handle clar log file of version %d", version);
    return -1;
  }
  return read_clar_file(stb.st_size);
}

static int
clar_flush_entry(int num)
{
  int wsz;

  if (sf_lseek(clar_fd, sizeof(struct clar_entry_v1) * num + sizeof(struct clar_header_v1), SEEK_SET, "clar_flush_entry") < 0)
    return -1;

  if ((wsz = sf_write(clar_fd, &clars.v[num], sizeof(clars.v[0]), "clar_flush_entry")) < 0) return -1;
  if (wsz != sizeof(clars.v[0])) ERR_R("short write: %d", wsz);
  return 0;
}

int
clar_add_record(time_t         time,
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

  if (clars.u >= clars.a) {
    if (!(clars.a *= 2)) clars.a = 128;
    clars.v = xrealloc(clars.v, clars.a * sizeof(clars.v[0]));
    info("clar_add_record: array extended: %d", clars.a);
  }
  i = clars.u++;

  memset(&clars.v[i], 0, sizeof(clars.v[0]));
  clars.v[i].id = i;
  clars.v[i].time = time;
  clars.v[i].size = size;
  clars.v[i].from = from;
  clars.v[i].to = to;
  clars.v[i].flags = flags;
  clars.v[i].j_from = j_from;
  clars.v[i].hide_flag = hide_flag;
  clars.v[i].a.ip = r_ip;
  base64_decode_str(subj, clars.v[i].subj, 0);
  if (clar_flush_entry(i) < 0) return -1;
  return i;
}

int
clar_get_record(int id,
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
  if (id < 0 || id >= clars.u) ERR_R("bad id: %d", id);
  if (clars.v[id].id != id)
    ERR_R("id mismatch: %d, %d", id, clars.v[id].id);

  if (ptime)   *ptime   = clars.v[id].time;
  if (psize)   *psize   = clars.v[id].size;
  if (ip)                 strcpy(ip, xml_unparse_ip(clars.v[id].a.ip));
  if (pfrom)   *pfrom   = clars.v[id].from;
  if (pto)     *pto     = clars.v[id].to;
  if (pflags)  *pflags  = clars.v[id].flags;
  if (pj_from) *pj_from = clars.v[id].j_from;
  if (p_hide_flag) *p_hide_flag = clars.v[id].hide_flag;
  if (subj)               base64_encode_str(clars.v[id].subj, subj);
  return 0;
}

int
clar_update_flags(int id, int flags)
{
  if (id < 0 || id >= clars.u) ERR_R("bad id: %d", id);
  if (clars.v[id].id != id)
    ERR_R("id mismatch: %d, %d", id, clars.v[id].id);
  if (flags < 0 || flags > 255) ERR_R("bad flags: %d", flags);

  clars.v[id].flags = flags;
  if (clar_flush_entry(id) < 0) return -1;
  return 0;
}

int
clar_get_total(void)
{
  return clars.u;
}

void
clar_get_team_usage(int from, int *pn, size_t *ps)
{
  int i;
  size_t total = 0;
  int n = 0;

  for (i = 0; i < clars.u; i++)
    if (clars.v[i].from == from) {
      total += clars.v[i].size;
      n++;
    }
  if (pn) *pn = n;
  if (ps) *ps = total;
}

char *
clar_flags_html(int flags, int from, int to, char *buf, int len)
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
clar_reset(void)
{
  create_new_clar_log(0);
}

void
clar_clear_variables(void)
{
  if (clars.v) xfree(clars.v);
  clars.v = 0;
  clars.u = clars.a = 0;
  if (clar_fd >= 0) close(clar_fd);
  clar_fd = -1;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
