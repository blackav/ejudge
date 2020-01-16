/* -*- mode: c -*- */

/* Copyright (C) 2008-2019 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/cldb_plugin.h"
#include "ejudge/clarlog.h"
#include "ejudge/clarlog_state.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/pathutl.h"
#include "ejudge/prepare.h"
#include "ejudge/errlog.h"
#include "unix/unix_fileutl.h"
#include "ejudge/xml_utils.h"
#include "ejudge/base64.h"
#include "ejudge/fileutl.h"
#include "ejudge/ej_uuid.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define CURRENT_VERSION 2

/* new clarification log header */
struct clar_header_v1
{
  unsigned char signature[16];  /* "eJudge clar log" */
  unsigned char version;        /* file version */
  unsigned char endianness;     /* 0 - little, 1 - big endian */
  unsigned char _pad[110];
};

enum { CLAR_ENTRY_V1_SUBJ_SIZE = 32, CLAR_ENTRY_V1_CHARSET_SIZE = 16 };

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
  unsigned char ipv6_flag;      /* 1 */
  unsigned char hide_flag;      /* 1 */
  unsigned char ssl_flag;       /* 1 */
  unsigned char appeal_flag;    /* 1 */
  union
  {
    ej_ip4_t ip;
    unsigned char ipv6[16];
  } a;                          /* 16 */
  unsigned short locale_id;     /* 2 */
  unsigned char _pad2[2];       /* 2 */
  int in_reply_to;              /* 4 */ /* 1 means in clar_id 0! */
  int run_id;                   /* 4 */ /* 1 means run_id 0! */
  unsigned char _pad3[12];
  unsigned char charset[CLAR_ENTRY_V1_CHARSET_SIZE];
  unsigned char subj[CLAR_ENTRY_V1_SUBJ_SIZE];
};                              /* 128 */

struct cldb_file_state
{
  int nref;
};

struct cldb_file_cnts
{
  struct cldb_file_state *plugin_state;
  struct clarlog_state *cl_state;
  int clar_fd;
  unsigned char *clar_archive_dir;
  struct clar_header_v1 header;
};

static int do_flush_entry(struct cldb_file_cnts *cs, int num);

static struct common_plugin_data *
init_func(void);
static int
finish_func(struct common_plugin_data *);
static int
prepare_func(
        struct common_plugin_data *,
        const struct ejudge_cfg *,
        struct xml_tree*);
static struct cldb_plugin_cnts *
open_func(
        struct cldb_plugin_data *cdata,
        struct clarlog_state *cl_state,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags);
static struct cldb_plugin_cnts *
close_func(struct cldb_plugin_cnts *cdata);
static int
reset_func(struct cldb_plugin_cnts *cdata);
static int
add_entry_func(struct cldb_plugin_cnts *cdata, int num);
static int
set_flags_func(struct cldb_plugin_cnts *cdata, int num);
static int
set_charset_func(struct cldb_plugin_cnts *cdata, int num);
static int
get_raw_text_func(struct cldb_plugin_cnts *cdata, int clar_id,
                  unsigned char **p_text, size_t *p_size);
static int
add_text_func(
        struct cldb_plugin_cnts *cdata,
        int clar_id,
        const ej_uuid_t *puuid,
        const unsigned char *text,
        size_t size);
static int
modify_text_func(
        struct cldb_plugin_cnts *cdata,
        int clar_id,
        const unsigned char *text,
        size_t size);
static int
modify_record_func(
        struct cldb_plugin_cnts *cdata,
        int clar_id,
        int mask,
        const struct clar_entry_v2 *pe);
static int
fetch_run_messages_func(
        struct cldb_plugin_cnts *cdata,
        const ej_uuid_t *p_run_uuid,
        struct full_clar_entry **pp);
static int
fetch_run_messages_2_func(
        struct cldb_plugin_cnts *cdata,
        int uuid_count,
        const ej_uuid_t *p_run_uuid,
        struct full_clar_entry **pp);

struct cldb_plugin_iface cldb_plugin_file =
{
  {
    {
      sizeof (struct cldb_plugin_iface),
      EJUDGE_PLUGIN_IFACE_VERSION,
      "cldb",
      "file",
    },
    COMMON_PLUGIN_IFACE_VERSION,
    init_func,
    finish_func,
    prepare_func,
  },
  CLDB_PLUGIN_IFACE_VERSION,

  open_func,
  close_func,
  reset_func,
  add_entry_func,
  set_flags_func,
  set_charset_func,
  get_raw_text_func,
  add_text_func,
  modify_text_func,
  modify_record_func,
  fetch_run_messages_func,
  fetch_run_messages_2_func,
};

static struct common_plugin_data *
init_func(void)
{
  struct cldb_file_state *state = 0;
  XCALLOC(state, 1);
  return (struct common_plugin_data*) state;
}

static int
finish_func(struct common_plugin_data *data)
{
  struct cldb_file_state *state = (struct cldb_file_state*) data;
  xfree(state);
  return 0;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *plugin_config)
{
  return 0;
}

#define ERR_R(t, args...) do { do_err_r(__FUNCTION__, t , ##args); return -1; } while (0)

static int
clar_read_record_v0(
        struct cldb_file_cnts *cs,
        char *buf,
        int size)
{
  int rsz, i;

  if ((rsz = sf_read(cs->clar_fd, buf, size, "clar")) < 0) return rsz;
  if (rsz != size) ERR_R("short read: %d", rsz);

  for (i = 0; i < size - 1; i++) {
    if (buf[i] >= 0 && buf[i] < ' ') break;
  }
  if (i < size - 1) ERR_R("bad characters in record");
  if (buf[size - 1] != '\n') ERR_R("record improperly terminated");
  return 0;
}

#define CLAR_RECORD_SIZE 79
#define SUBJ_STRING_SIZE 24
#define IP_STRING_SIZE   15

static const char signature_v1[] = "eJudge clar log";

static int
clar_read_entry(
        struct cldb_file_cnts *cs,
        int n)
{
  struct clarlog_state *cl_state = cs->cl_state;
  char buf[CLAR_RECORD_SIZE + 16];
  char b2[CLAR_RECORD_SIZE + 16];
  char b3[CLAR_RECORD_SIZE + 16];
  int  k, r;

  int r_time;
  unsigned int r_size;
  ej_ip4_t r_ip;

  memset(buf, 0, sizeof(buf));
  memset(&cl_state->clars.v[n], 0, sizeof(cl_state->clars.v[0]));
  if (clar_read_record_v0(cs, buf, CLAR_RECORD_SIZE) < 0) return -1;

  r = sscanf(buf, "%d %d %u %d %d %d %s %s %n",
             &cl_state->clars.v[n].id, &r_time, &r_size,
             &cl_state->clars.v[n].from,
             &cl_state->clars.v[n].to, &cl_state->clars.v[n].flags,
             b2, b3, &k);
  if (r != 8) ERR_R("[%d]: sscanf returned %d", n, r);
  if (buf[k] != 0) ERR_R("[%d]: excess data", n);

  /* do sanity checking */
  cl_state->clars.v[n].size = r_size;
  cl_state->clars.v[n].time = r_time;
  if (cl_state->clars.v[n].id != n)
    ERR_R("[%d]: bad id: %d", n, cl_state->clars.v[n].id);
  if (cl_state->clars.v[n].size == 0 || cl_state->clars.v[n].size >= 10000)
    ERR_R("[%d]: bad size: %d", n, cl_state->clars.v[n].size);
  // FIXME: how to check consistency?
  /*
  if (clars.v[n].from && !teamdb_lookup(clars.v[n].from))
    ERR_R("[%d]: bad from: %d", n, clars.v[n].from);
  if (clars.v[n].to && !teamdb_lookup(clars.v[n].to))
    ERR_R("[%d]: bad to: %d", n, clars.v[n].to);
  */
  if (/*cl_state->clars.v[n].flags < 0 ||*/ cl_state->clars.v[n].flags > 255)
    ERR_R("[%d]: bad flags: %d", n, cl_state->clars.v[n].flags);
  if (strlen(b2) > IP_STRING_SIZE) ERR_R("[%d]: ip is too long", n);
  if (strlen(b3) > SUBJ_STRING_SIZE) ERR_R("[%d]: subj is too long", n);
  if (xml_parse_ip(NULL, 0, n + 1, 0, b2, &r_ip) < 0) ERR_R("[%d]: ip is invalid", n);
  cl_state->clars.v[n].a.ip = r_ip;
  base64_decode_str(b3, cl_state->clars.v[n].subj, 0);
  return 0;
}

static int
create_new_clar_log(
        struct cldb_file_cnts *cs,
        int flags)
{
  struct clarlog_state *cl_state = cs->cl_state;
  int wsz;
  int i;

  memset(&cs->header, 0, sizeof(cs->header));
  strncpy(cs->header.signature, signature_v1, sizeof(cs->header.signature));
  cs->header.version = CURRENT_VERSION;

  if (cl_state->clars.v) {
    xfree(cl_state->clars.v);
    cl_state->clars.v = 0;
    cl_state->clars.u = cl_state->clars.a = 0;
  }
  cl_state->clars.a = 128;
  XCALLOC(cl_state->clars.v, cl_state->clars.a);
  for (i = 0; i < cl_state->clars.a; cl_state->clars.v[i++].id = -1);

  if (flags == CLAR_LOG_READONLY) return 0;

  if (ftruncate(cs->clar_fd, 0) < 0) {
    err("clar_log: ftruncate() failed: %s", os_ErrorMsg());
    return -1;
  }
  if (sf_lseek(cs->clar_fd, 0, SEEK_SET, "clar") == (off_t) -1)
    return -1;
  wsz = write(cs->clar_fd, &cs->header, sizeof(cs->header));
  if (wsz <= 0) {
    err("clar_log: write() failed: %s", os_ErrorMsg());
    return -1;
  }
  if (wsz != sizeof(cs->header)) {
    err("clar_log: short write: %d instead of %zu", wsz, sizeof(cs->header));
    return -1;
  }
  return 0;
}

static int
write_all_clarlog(struct cldb_file_cnts *cs)
{
  struct clarlog_state *cl_state = cs->cl_state;
  int wsz, bsz;
  const unsigned char *buf;

  if (sf_lseek(cs->clar_fd, 0, SEEK_SET, "clar_write") < 0) return -1;

  if ((wsz = sf_write(cs->clar_fd, &cs->header, sizeof(cs->header),
                      "clar_write")) < 0)
    return -1;
  if (wsz != sizeof(cs->header)) {
    err("clar_write: short write: %d", wsz);
    return -1;
  }

  buf = (const unsigned char*) cl_state->clars.v;
  bsz = sizeof(cl_state->clars.v[0]) * cl_state->clars.u;
  while (bsz > 0) {
    if ((wsz = sf_write(cs->clar_fd, buf, bsz, "clar_write")) <= 0)
      return -1;
    buf += wsz;
    bsz -= wsz;
  }
  return 0;
}

static int
convert_log_from_version_0(
        struct cldb_file_cnts *cs,
        int flags,
        off_t length,
        const unsigned char *path)
{
  struct clarlog_state *cl_state = cs->cl_state;
  path_t v0_path;
  int i;

  if (length % CLAR_RECORD_SIZE != 0) {
    err("invalid size %d of clar file (version 0)", (int) length);
    return -1;
  }

  cl_state->clars.u = length / CLAR_RECORD_SIZE;
  cl_state->clars.a = 128;
  while (cl_state->clars.u > cl_state->clars.a) cl_state->clars.a *= 2;
  XCALLOC(cl_state->clars.v, cl_state->clars.a);
  for (i = 0; i < cl_state->clars.a; cl_state->clars.v[i++].id = -1);
  for (i = 0; i < cl_state->clars.u; i++) {
    if (clar_read_entry(cs, i) < 0) return -1;
  }

  info("clar log version 0 successfully read");

  memset(&cs->header, 0, sizeof(cs->header));
  strncpy(cs->header.signature, signature_v1, sizeof(cs->header.signature));
  cs->header.version = 1;

  if (flags == CLAR_LOG_READONLY) return 0;

  close(cs->clar_fd); cs->clar_fd = -1;
  snprintf(v0_path, sizeof(v0_path), "%s.v0", path);
  if (rename(path, v0_path) < 0) {
    err("rename() failed: %s", os_ErrorMsg());
    return -1;
  }

  if ((cs->clar_fd = sf_open(path, O_RDWR|O_CREAT|O_TRUNC, 0666)) < 0)
    return -1;

  return write_all_clarlog(cs);
}

static int
read_clar_file_header(
        struct cldb_file_cnts *cs,
        off_t length)
{
  int rsz = 0;

  // read signature bytes
  unsigned char file_signature[16];
  if (sf_lseek(cs->clar_fd, 0, SEEK_SET, "clar_open") < 0) return -1;
  if ((rsz = sf_read(cs->clar_fd, file_signature, sizeof(file_signature), "clar_open")) < 0)
    return -1;
  if (rsz != sizeof(file_signature)) return 0;
  if (memcmp(file_signature, signature_v1, sizeof(file_signature)) != 0) {
    // file signature mismatch
    return 0;
  }
  unsigned char version = 0xff;
  unsigned char endianness = 0xff;

  if ((rsz = sf_read(cs->clar_fd, &version, sizeof(version), "clar_open")) < 0) return -1;
  if (rsz != 1) return 0;
  if ((rsz = sf_read(cs->clar_fd, &endianness, sizeof(endianness), "clar_open")) < 0) return -1;
  if (rsz != 1) return 0;

  if (endianness == 1) {
    err("big-endian clarlog files are not supported");
    return -1;
  }
  if (endianness != 0) {
    err("invalid endianness");
    return -1;
  }
  if (version > 2) return -1;

  memset(&cs->header, 0, sizeof(cs->header));
  memcpy(cs->header.signature, file_signature, sizeof(file_signature));
  cs->header.version = version;
  cs->header.endianness = endianness;

  return version;
}

static int
read_clar_file(
        struct cldb_file_cnts *cs,
        off_t length)
{
  struct clarlog_state *cl_state = cs->cl_state;
  unsigned char *buf;
  int bsz, rsz, i;

  cl_state->clars.u = (length - sizeof(struct clar_header_v1)) / sizeof(struct clar_entry_v2);
  cl_state->clars.a = 128;
  while (cl_state->clars.a < cl_state->clars.u) cl_state->clars.a *= 2;
  XCALLOC(cl_state->clars.v, cl_state->clars.a);
  for (i = 0; i < cl_state->clars.a; cl_state->clars.v[i++].id = -1);

  if (sf_lseek(cs->clar_fd, sizeof(struct clar_header_v1), SEEK_SET, "clar_read") < 0)
    return -1;

  buf = (unsigned char*) cl_state->clars.v;
  bsz = sizeof(cl_state->clars.v[0]) * cl_state->clars.u;
  while (bsz > 0) {
    if ((rsz = sf_read(cs->clar_fd, buf, bsz, "clar_read")) < 0) return -1;
    if (!rsz) {
      err("clar_read: unexpected EOF");
      return -1;
    }
    bsz -= rsz; buf += rsz;
  }
  return 0;
}

static int
read_clar_file_v1(
        struct cldb_file_cnts *cs,
        off_t length)
{
  struct clarlog_state *cl_state = cs->cl_state;

  cl_state->clars.u = (length - sizeof(struct clar_header_v1)) / sizeof(struct clar_entry_v1);
  cl_state->clars.a = 128;
  while (cl_state->clars.a < cl_state->clars.u) cl_state->clars.a *= 2;
  XCALLOC(cl_state->clars.v, cl_state->clars.a);
  for (int i = 0; i < cl_state->clars.a; cl_state->clars.v[i++].id = -1);

  if (sf_lseek(cs->clar_fd, sizeof(struct clar_header_v1), SEEK_SET, "clar_read") < 0)
    return -1;

  for (int i = 0; i < cl_state->clars.u; ++i) {
    struct clar_entry_v1 ce;

    memset(&ce, 0, sizeof(ce));
    int rsz = sf_read(cs->clar_fd, &ce, sizeof(ce), "read_clar_file_v1");
    if (rsz < 0) return -1;
    if (!rsz) {
      err("read_clar_file_v1: unexpected EOF");
      return -1;
    }
    if (rsz != sizeof(ce)) {
      err("read_clar_file_v1: invalid read size");
      return -1;
    }

    struct clar_entry_v2 *nce = &cl_state->clars.v[i];
    nce->id = ce.id;
    ej_uuid_generate(&nce->uuid);
    nce->size = ce.size;
    nce->time = ce.time;
    nce->nsec = ce.nsec;
    nce->from = ce.from;
    nce->to = ce.to;
    nce->j_from = ce.j_from;
    nce->flags = ce.flags;
    nce->ipv6_flag = ce.ipv6_flag;
    nce->hide_flag = ce.hide_flag;
    nce->ssl_flag = ce.ssl_flag;
    nce->appeal_flag = ce.appeal_flag;
    memcpy(&nce->a, &ce.a, sizeof(nce->a));
    nce->locale_id = ce.locale_id;
    nce->in_reply_to = ce.in_reply_to;
    nce->run_id = ce.run_id;
    snprintf(nce->charset, CLAR_ENTRY_V2_CHARSET_SIZE, "%s", ce.charset);
    snprintf(nce->subj, CLAR_ENTRY_V2_SUBJ_SIZE, "%s", ce.subj);
  }

  for (int i = 0; i < cl_state->clars.u; ++i) {
    struct clar_entry_v2 *ce = &cl_state->clars.v[i];
    if (ce->id >= 0 && ce->in_reply_to > 0) {
      for (int j = 0; j < cl_state->clars.u; ++j) {
        struct clar_entry_v2 *ce2 = &cl_state->clars.v[j];
        if (ce2->id == ce->in_reply_to - 1) {
          ej_uuid_copy(&ce->in_reply_uuid, &ce2->uuid);
          break;
        }
      }
    }
  }

  return 0;
}

static int
convert_log_from_version_1(
        struct cldb_file_cnts *cs,
        int flags,
        off_t length,
        const unsigned char *path)
{
  path_t v1_path;

  if (read_clar_file_v1(cs, length) < 0) return -1;

  info("clar log version 1 successfully read");

  if (flags == CLAR_LOG_READONLY) return 0;

  cs->header.version = 2;
  close(cs->clar_fd); cs->clar_fd = -1;
  snprintf(v1_path, sizeof(v1_path), "%s.v1", path);
  if (rename(path, v1_path) < 0) {
    err("rename() failed: %s", os_ErrorMsg());
    return -1;
  }

  if ((cs->clar_fd = sf_open(path, O_RDWR|O_CREAT|O_TRUNC, 0666)) < 0)
    return -1;

  return write_all_clarlog(cs);
}

static int
do_clar_open(
	struct cldb_file_cnts *cs,
        char const *path,
        int flags)
{
  struct clarlog_state *cl_state = cs->cl_state;
  int version, r, i, f;
  struct stat stb;

  info("clar_open: opening database %s", path);
  if (cl_state->clars.v) {
    xfree(cl_state->clars.v);
    cl_state->clars.v = 0;
    cl_state->clars.u = cl_state->clars.a = 0;
  }
  if (cs->clar_fd >= 0) {
    close(cs->clar_fd); cs->clar_fd = -1;
  }
  if (flags == CLAR_LOG_READONLY) {
    if ((cs->clar_fd = sf_open(path, O_RDONLY, 0)) < 0) return -1;
  } else {
    if ((cs->clar_fd = sf_open(path, O_RDWR | O_CREAT, 0666)) < 0) return -1;
  }

  if (fstat(cs->clar_fd, &stb) < 0) {
    err("fstat() failed: %s", os_ErrorMsg());
    close(cs->clar_fd); cs->clar_fd = -1;
    return -1;
  }
  if (!stb.st_size) {
    return create_new_clar_log(cs, flags);
  }
  if ((version = read_clar_file_header(cs, stb.st_size)) < 0)
    return -1;
  if (version == 0) {
    return convert_log_from_version_0(cs, flags, stb.st_size, path);
  }
  if (version == 1) {
    return convert_log_from_version_1(cs, flags, stb.st_size, path);
  }
  if (version > 2) {
    err("clar_log: cannot handle clar log file of version %d", version);
    return -1;
  }
  r = read_clar_file(cs, stb.st_size);
  // fix a bug
  for (i = 0; i < cl_state->clars.u; i++) {
    f = 0;
    if (cl_state->clars.v[i].from == -1) {
      cl_state->clars.v[i].from = 0;
      f = 1;
    }
    if (cl_state->clars.v[i].to == -1) {
      cl_state->clars.v[i].to = 0;
      f = 1;
    }
    if (f) {
      do_flush_entry(cs, i);
      info("clar_log: entry %d fixed", i);
    }
  }
  return r;
}

static struct cldb_plugin_cnts *
open_func(
        struct cldb_plugin_data *data,
        struct clarlog_state *cl_state,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags)
{
  struct cldb_file_state *state = (struct cldb_file_state*) data;
  struct cldb_file_cnts *cs = 0;
  path_t clarlog_path;

  ASSERT(state);
  XCALLOC(cs, 1);
  cs->plugin_state = state;
  state->nref++;
  cs->cl_state = cl_state;
  cs->clar_fd = -1;
  if (global && global->clar_archive_dir && global->clar_archive_dir[0])
    cs->clar_archive_dir = xstrdup(global->clar_archive_dir);
  if (!cs->clar_archive_dir && cnts && cnts->root_dir) {
    snprintf(clarlog_path, sizeof(clarlog_path),
             "%s/var/archive/clars", cnts->root_dir);
    cs->clar_archive_dir = xstrdup(clarlog_path);
  }
  make_dir(cs->clar_archive_dir, 0700);

  clarlog_path[0] = 0;
  if (global && global->clar_log_file && global->clar_log_file[0]) {
    snprintf(clarlog_path, sizeof(clarlog_path), "%s", global->clar_log_file);
  }
  if (!clarlog_path[0] && cnts && cnts->root_dir) {
    snprintf(clarlog_path, sizeof(clarlog_path), "%s/var/clar.log",
             cnts->root_dir);
  }
  if (!clarlog_path[0]) {
    err("`clar_log_file' is undefined");
    goto fail;
  }
  if (do_clar_open(cs, clarlog_path, flags) < 0) goto fail;

  return (struct cldb_plugin_cnts*) cs;

 fail:
  close_func((struct cldb_plugin_cnts*) cs);
  return 0;
}

static struct cldb_plugin_cnts *
close_func(struct cldb_plugin_cnts *cdata)
{
  struct cldb_file_cnts *cs = (struct cldb_file_cnts*) cdata;

  if (cs->plugin_state) cs->plugin_state->nref--;
  if (cs->clar_fd >= 0) close(cs->clar_fd);
  xfree(cs->clar_archive_dir);
  xfree(cs);
  return 0;
}

static int
reset_func(struct cldb_plugin_cnts *cdata)
{
  struct cldb_file_cnts *cs = (struct cldb_file_cnts*) cdata;
  create_new_clar_log(cs, 0);
  if (cs->clar_archive_dir) clear_directory(cs->clar_archive_dir);
  return 0;
}

static int
do_flush_entry(struct cldb_file_cnts *cs, int num)
{
  struct clarlog_state *cl_state = cs->cl_state;
  int wsz;

  if (sf_lseek(cs->clar_fd,
               sizeof(struct clar_entry_v2) * num
               + sizeof(struct clar_header_v1),
               SEEK_SET, "clar_flush_entry") < 0)
    return -1;

  if ((wsz = sf_write(cs->clar_fd, &cl_state->clars.v[num],
                      sizeof(cl_state->clars.v[0]),
                      "clar_flush_entry")) < 0) return -1;
  if (wsz != sizeof(cl_state->clars.v[0])) ERR_R("short write: %d", wsz);
  return 0;
}

static int
add_entry_func(struct cldb_plugin_cnts *cdata, int num)
{
  struct cldb_file_cnts *cs = (struct cldb_file_cnts*) cdata;
  return do_flush_entry(cs, num);
}

static int
set_flags_func(struct cldb_plugin_cnts *cdata, int num)
{
  struct cldb_file_cnts *cs = (struct cldb_file_cnts*) cdata;
  return do_flush_entry(cs, num);
}

static int
set_charset_func(struct cldb_plugin_cnts *cdata, int num)
{
  struct cldb_file_cnts *cs = (struct cldb_file_cnts*) cdata;
  return do_flush_entry(cs, num);
}

static int
get_raw_text_func(
        struct cldb_plugin_cnts *cdata,
        int clar_id,
        unsigned char **p_text,
        size_t *p_size)
{
  struct cldb_file_cnts *cs = (struct cldb_file_cnts*) cdata;
  char **p = (char**) p_text;
  unsigned char name_buf[64];

  if (!cs->clar_archive_dir) {
    err("clar_archive_dir is undefined");
    return -1;
  }
  snprintf(name_buf, sizeof(name_buf), "%06d", clar_id);
  return generic_read_file(p, 0, p_size, 0, cs->clar_archive_dir, name_buf, "");
}

static int
add_text_func(
        struct cldb_plugin_cnts *cdata,
        int clar_id,
        const ej_uuid_t *puuid,
        const unsigned char *text,
        size_t size)
{
  struct cldb_file_cnts *cs = (struct cldb_file_cnts*) cdata;
  unsigned char name_buf[64];

  if (!cs->clar_archive_dir) {
    err("clar_archive_dir is undefined");
    return -1;
  }
  snprintf(name_buf, sizeof(name_buf), "%06d", clar_id);
  return generic_write_file(text, size, 0, cs->clar_archive_dir, name_buf, "");
}

static int
modify_text_func(
        struct cldb_plugin_cnts *cdata,
        int clar_id,
        const unsigned char *text,
        size_t size)
{
  struct cldb_file_cnts *cs = (struct cldb_file_cnts*) cdata;
  unsigned char name_buf[64];

  if (!cs->clar_archive_dir) {
    err("clar_archive_dir is undefined");
    return -1;
  }
  snprintf(name_buf, sizeof(name_buf), "%06d", clar_id);
  return generic_write_file(text, size, 0, cs->clar_archive_dir, name_buf, "");
}

static int
modify_record_func(
        struct cldb_plugin_cnts *cdata,
        int clar_id,
        int mask,
        const struct clar_entry_v2 *pe)
{
  struct cldb_file_cnts *cs = (struct cldb_file_cnts*) cdata;
  return do_flush_entry(cs, clar_id);
}

static int
fetch_run_messages_func(
        struct cldb_plugin_cnts *cdata,
        const ej_uuid_t *p_run_uuid,
        struct full_clar_entry **pp)
{
  struct cldb_file_cnts *cs = (struct cldb_file_cnts*) cdata;
  struct clarlog_state *cl_state = cs->cl_state;
  int i, j, count = 0;
  struct full_clar_entry *fce = NULL;
  unsigned char name_buf[PATH_MAX];

  for (i = 0; i < cl_state->clars.u; ++i) {
    const struct clar_entry_v2 *pe = &cl_state->clars.v[i];
    if (pe->id >= 0
        && pe->run_uuid.v[0] == p_run_uuid->v[0]
        && pe->run_uuid.v[1] == p_run_uuid->v[1]
        && pe->run_uuid.v[2] == p_run_uuid->v[2]
        && pe->run_uuid.v[3] == p_run_uuid->v[3]) {
      ++count;
    }
  }
  if (count <= 0) return 0;

  XCALLOC(fce, count);

  for (i = 0, j = 0; i < cl_state->clars.u; ++i) {
    const struct clar_entry_v2 *pe = &cl_state->clars.v[i];
    if (pe->id >= 0
        && pe->run_uuid.v[0] == p_run_uuid->v[0]
        && pe->run_uuid.v[1] == p_run_uuid->v[1]
        && pe->run_uuid.v[2] == p_run_uuid->v[2]
        && pe->run_uuid.v[3] == p_run_uuid->v[3]) {
      char *p = 0;
      fce[j].e = *pe;
      snprintf(name_buf, sizeof(name_buf), "%06d", pe->id);
      generic_read_file(&p, 0, &fce[j].size, 0, cs->clar_archive_dir, name_buf, NULL);
      fce[j].text = p; p = NULL;
      ++j;
    }
  }

  *pp = fce;
  return count;
}

static int
fetch_run_messages_2_func(
        struct cldb_plugin_cnts *cdata,
        int uuid_count,
        const ej_uuid_t *p_run_uuid,
        struct full_clar_entry **pp)
{
  struct cldb_file_cnts *cs = (struct cldb_file_cnts*) cdata;
  struct clarlog_state *cl_state = cs->cl_state;
  int i, j, count = 0;
  struct full_clar_entry *fce = NULL;
  unsigned char name_buf[PATH_MAX];

  if (uuid_count <= 0) {
    return 0;
  }

  for (i = 0; i < cl_state->clars.u; ++i) {
    const struct clar_entry_v2 *pe = &cl_state->clars.v[i];
    if (pe->id >= 0) {
      for (int k = 0; k < uuid_count; ++k) {
        if (pe->run_uuid.v[0] == p_run_uuid[k].v[0]
            && pe->run_uuid.v[1] == p_run_uuid[k].v[1]
            && pe->run_uuid.v[2] == p_run_uuid[k].v[2]
            && pe->run_uuid.v[3] == p_run_uuid[k].v[3]) {
          ++count;
        }
      }
    }
  }
  if (count <= 0) return 0;

  XCALLOC(fce, count);

  for (i = 0, j = 0; i < cl_state->clars.u; ++i) {
    const struct clar_entry_v2 *pe = &cl_state->clars.v[i];
    if (pe->id >= 0) {
      for (int k = 0; k < uuid_count; ++k) {
        if (pe->run_uuid.v[0] == p_run_uuid[k].v[0]
            && pe->run_uuid.v[1] == p_run_uuid[k].v[1]
            && pe->run_uuid.v[2] == p_run_uuid[k].v[2]
            && pe->run_uuid.v[3] == p_run_uuid[k].v[3]) {
          char *p = 0;
          fce[j].e = *pe;
          snprintf(name_buf, sizeof(name_buf), "%06d", pe->id);
          generic_read_file(&p, 0, &fce[j].size, 0, cs->clar_archive_dir, name_buf, NULL);
          fce[j].text = p; p = NULL;
          ++j;
        }
      }
    }
  }

  *pp = fce;
  return count;
}
