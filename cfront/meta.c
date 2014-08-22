/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "meta.h"
#include "tree.h"
#include "meta_gen.h"

#include "ejudge/getopt.h"
#include "ejudge/osdeps.h"
#include "ejudge/xalloc.h"

#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <utime.h>

static strarray_t meta_structs;
static strarray_t meta_enum_prefixes;
static strarray_t meta_func_prefixes;
static short meta_timestamp;

optrec_t meta_options[] =
{
  { 1, 0, "--meta-struct", "V+", &meta_structs,
    "Specify a structure tag for metageneration", 0 },
  { 1, 0, "--meta-enum-prefix", "V+", &meta_enum_prefixes,
    "Specify an enum tag prefix for metageneration", 0 },
  { 1, 0, "--meta-func-prefix", "V+", &meta_func_prefixes,
    "Specify function prefix for metageneration", 0 },
  { 1, 0, "--meta-timestamp", "s1", &meta_timestamp,
    "Timestamp the generated files", 0 },

  { 0, 0, 0, 0, 0, 0, 0 }
};

static void
strip_suffix(unsigned char *buf)
{
  unsigned char *p1 = strrchr(buf, '.');
  unsigned char *p2 = strrchr(buf, '/');

  if (p1 && (!p2 || p1 > p2 + 1)) *p1 = 0;
}

static int
read_file(FILE *f, unsigned char **out, size_t *out_len)
{
  unsigned char read_buf[4096];
  unsigned char *buf = 0;
  size_t buf_len = 0, read_len = 0;

  while (1) {
    read_len = fread(read_buf, 1, sizeof(read_buf), f);
    if (!read_len) break;
    if (!buf_len) {
      buf = (unsigned char*) xcalloc(read_len + 1, 1);
      memcpy(buf, read_buf, read_len);
      buf_len = read_len;
    } else {
      buf = (unsigned char*) xrealloc(buf, buf_len + read_len + 1);
      memcpy(buf + buf_len, read_buf, read_len);
      buf_len += read_len;
      buf[buf_len] = 0;
    }
  }
  if (ferror(f)) {
    fprintf(stderr, "input error: %s", os_ErrorMsg());
    return -1;
  }
  if (!buf_len) {
    buf = (unsigned char*) xmalloc(1);
    buf[0] = 0;
    buf_len = 0;
  }
  if (out) *out = buf;
  if (out_len) *out_len = buf_len;
  return 0;
}

static int
update_if_needed(const unsigned char *dstname, const unsigned char *srcname)
{
  FILE *f_dst = 0;
  FILE *f_src = 0;
  unsigned char *t_dst = 0, *t_src = 0;
  size_t z_dst = 0, z_src = 0;

  if (os_CheckAccess(dstname, REUSE_F_OK) < 0) {
    if (rename(srcname, dstname) < 0) {
      fprintf(stderr, "rename failed: %s\n", os_ErrorMsg());
      return -1;
    }
    return 1;
  }

  if (!(f_dst = fopen(dstname, "r"))) {
    fprintf(stderr, "cannot open %s for reading: %s\n", dstname, os_ErrorMsg());
    goto cleanup;
  }
  if (read_file(f_dst, &t_dst, &z_dst) < 0) goto cleanup;
  fclose(f_dst); f_dst = 0;

  if (!(f_src = fopen(srcname, "r"))) {
    fprintf(stderr, "cannot open %s for reading: %s\n", srcname, os_ErrorMsg());
    goto cleanup;
  }
  if (read_file(f_src, &t_src, &z_src) < 0) goto cleanup;
  fclose(f_src); f_src = 0;

  if (z_src == z_dst && !memcmp(t_src, t_dst, z_src)) {
    fprintf(stderr, "no update to %s is needed\n", dstname);
    // update last_modified stamp of dstname

    time_t cur_time = time(0);
    struct utimbuf utb = { cur_time, cur_time };
    utime(dstname, &utb);

    remove(srcname);
    return 0;
  }

  if (rename(srcname, dstname) < 0) {
    fprintf(stderr, "rename failed: %s\n", os_ErrorMsg());
    return -1;
  }
  return 1;

 cleanup:
  if (f_dst) fclose(f_dst);
  if (f_src) fclose(f_src);
  xfree(t_dst);
  xfree(t_src);
  return -1;
}

int
main_meta_generate(tree_t tree, const unsigned char *output_name)
{
  unsigned char bn_buf[4096];
  unsigned char temp_c_buf[4096];
  unsigned char temp_h_buf[4096];
  unsigned char c_buf[4096];
  unsigned char h_buf[4096];
  int serial = 0;
  FILE *out_c = 0;
  FILE *out_h = 0;
  unsigned char ts_buf[1024];
  //time_t ts_time;
  //struct tm *ts_tm;

  if (!output_name) output_name = "output.c";
  snprintf(bn_buf, sizeof(bn_buf), "%s", output_name);
  strip_suffix(bn_buf);
  snprintf(c_buf, sizeof(c_buf), "%s_meta.c", bn_buf);
  snprintf(h_buf, sizeof(h_buf), "include/ejudge/meta/%s_meta.h", bn_buf);

  if (!meta_structs.u) {
    fprintf(stderr, "no structure tags specified\n");
    return 1;
  }
  if (meta_enum_prefixes.u > 0 && meta_enum_prefixes.u != meta_structs.u) {
    fprintf(stderr, "number of prefixes does not match number of tags\n");
    return 1;
  }
  if (meta_func_prefixes.u > 0 && meta_func_prefixes.u != meta_structs.u) {
    fprintf(stderr, "number of prefixes does not match number of tags\n");
    return 1;
  }

  serial = 0;
  do {
    snprintf(temp_c_buf, sizeof(temp_c_buf), "%s_meta_tmp%d.c", bn_buf, serial);
    serial++;
  } while (os_CheckAccess(temp_c_buf, REUSE_F_OK) >= 0);
  serial = 0;
  do {
    snprintf(temp_h_buf, sizeof(temp_h_buf), "include/ejudge/meta/%s_meta_tmp%d.h", bn_buf, serial);
    serial++;
  } while (os_CheckAccess(temp_h_buf, REUSE_F_OK) >= 0);

  if (!(out_c = fopen(temp_c_buf, "w"))) {
    fprintf(stderr, "cannot open %s for writing\n", temp_c_buf);
    return 1;
  }
  if (!(out_h = fopen(temp_h_buf, "w"))) {
    fprintf(stderr, "cannot open %s for writing\n", temp_h_buf);
    fclose(out_c);
    remove(temp_c_buf);
    return 1;
  }

  ts_buf[0] = 0;
  /*
  if (meta_timestamp) {
    ts_time = time(0);
    ts_tm = localtime(&ts_time);
    snprintf(ts_buf, sizeof(ts_buf), "// Generated %04d/%02d/%02d %02d:%02d:%02d\n", ts_tm->tm_year + 1900, ts_tm->tm_mon + 1, ts_tm->tm_mday, ts_tm->tm_hour, ts_tm->tm_min, ts_tm->tm_sec);
  }
  */

  if (meta_generate(tree, ts_buf, bn_buf, h_buf, out_c, out_h, &meta_structs, &meta_enum_prefixes, &meta_func_prefixes) < 0) {
    fclose(out_c);
    fclose(out_h);
    remove(temp_c_buf);
    remove(temp_h_buf);
    return 1;
  }

  fclose(out_c); out_c = 0;
  fclose(out_h); out_h = 0;
  if (update_if_needed(c_buf, temp_c_buf) < 0) {
    remove(temp_c_buf);
    remove(temp_h_buf);
    return 1;
  }
  if (update_if_needed(h_buf, temp_h_buf) < 0) {
    remove(c_buf);
    remove(h_buf);
    remove(temp_h_buf);
    return 1;
  }

  return 0;
}
