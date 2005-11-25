/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2003-2005 Alexander Chernov <cher@ispras.ru> */

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

#include "ej_types.h"
#include "ej_limits.h"

#include "archive_paths.h"
#include "prepare.h"
#include "prepare_vars.h"
#include "fileutl.h"
#include "pathutl.h"
#include "errlog.h"

#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

static const unsigned char b32_digits[]=
"0123456789ABCDEFGHIJKLMNOPQRSTUV";
static void
b32_number(unsigned int num, size_t size, unsigned char buf[])
{
  int i;

  ASSERT(size > 1);

  memset(buf, '0', size - 1);
  buf[size - 1] = 0;
  i = size - 2;
  while (num > 0 && i >= 0) {
    buf[i] = b32_digits[num & 0x1f];
    i--;
    num >>= 5;
  }
  ASSERT(!num);
}

int
archive_dir_prepare(const unsigned char *base_dir, int serial,
                    const unsigned char *prefix, int no_unlink_flag)
{
  unsigned char sbuf[16];
  path_t path;
  unsigned char *pp;
  struct stat sb;
  int i;

  ASSERT(base_dir);
  if (!global->use_dir_hierarchy) return 0;

  if (strlen(base_dir) + 32 >= sizeof(path)) {
    err("archive_dir_prepare: `%s' is too long", base_dir);
    return -1;
  }
  if (lstat(base_dir, &sb) < 0) {
    err("archive_dir_prepare: `%s' does not exist", base_dir);
    return -1;
  }
  if (!S_ISDIR(sb.st_mode)) {
    err("archive_dir_prepare: `%s' is not a directory", base_dir);
    return -1;
  }

  ASSERT(serial >= 0 && serial <= EJ_MAX_RUN_ID);
  b32_number(serial, EJ_MAX_32DIGITS + 1, sbuf);
  ASSERT(strlen(sbuf) == EJ_MAX_32DIGITS);
  strcpy(path, base_dir);
  pp = (unsigned char*) path;
  pp += strlen(pp);
  for (i = 0; i < EJ_MAX_32DIGITS - 1; i++) {
    *pp++ = '/';
    *pp++ = sbuf[i];
    *pp = 0;

    if (lstat(path, &sb) < 0) {
      if (mkdir(path, 0755) < 0) {
        err("archive_dir_prepare: mkdir `%s' failed: %s", path, os_ErrorMsg());
        return -1;
      }
    } else {
      if (!S_ISDIR(sb.st_mode)) {
        err("archive_dir_prepare: `%s' is not a directory", path);
        return -1;
      }
    }
  }

  if (!no_unlink_flag) {
    if (!prefix) prefix = "";
    sprintf(pp, "/%s%06d", prefix, serial);
    unlink(path);
    strcat(pp, ".gz");
    unlink(path);
  }

  return 0;
}

static size_t
make_hier_path(unsigned char *buf, size_t size,
               const unsigned char *base_dir, int serial)
{
  size_t blen = strlen(base_dir);
  unsigned char *tb, *pp, b32[16];
  int i;

  if (blen + 32 < size) {
    tb = buf;
  } else {
    tb = alloca(blen + 32);
  }
  strcpy(tb, base_dir);
  pp = tb + blen;
  b32_number(serial, EJ_MAX_32DIGITS + 1, b32);
  ASSERT(strlen(b32) == EJ_MAX_32DIGITS);
  for (i = 0; i < EJ_MAX_32DIGITS - 1; i++) {
    *pp++ = '/';
    *pp++ = b32[i];
  }
  *pp = 0;
  if (tb == buf) return pp - tb;
  return snprintf(buf, size, "%s", tb);
}

int
archive_make_read_path(unsigned char *path, size_t size,
                       const unsigned char *base_dir, int serial,
                       const unsigned char *name_prefix, int gzip_preferred)
{
  unsigned char *pp;
  struct stat sb;

  ASSERT(serial >= 0 && serial <= EJ_MAX_RUN_ID);
  if (!name_prefix) name_prefix = "";

  if (global->use_dir_hierarchy) {
    if (strlen(base_dir) + 32 >= size) {
      err("archive_make_read_path: `%s' is too long", base_dir);
      return -1;
    }
    pp = path + make_hier_path(path, size, base_dir, serial);
    if (gzip_preferred) {
      if (global->use_gzip) {
        sprintf(pp, "/%s%06d.gz", name_prefix, serial);
        if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return GZIP;
      }
      sprintf(pp, "/%s%06d", name_prefix, serial);
      if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return 0;
    } else {
      sprintf(pp, "/%s%06d", name_prefix, serial);
      if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return 0;
      if (global->use_gzip) {
        sprintf(pp, "/%s%06d.gz", name_prefix, serial);
        if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return GZIP;
      }
    }
  }

  if (gzip_preferred) {
    if (global->use_gzip) {
      snprintf(path, size, "%s/%s%06d.gz", base_dir, name_prefix, serial);
      if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return GZIP;
    }
    snprintf(path, size, "%s/%s%06d", base_dir, name_prefix, serial);
    if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return 0;
  } else {
    snprintf(path, size, "%s/%s%06d", base_dir, name_prefix, serial);
    if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return 0;
    if (global->use_gzip) {
      snprintf(path, size, "%s/%s%06d.gz", base_dir, name_prefix, serial);
      if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return GZIP;
    }
  }

  err("archive_make_read_path: no entry %d in `%s'", serial, base_dir);
  return -1;
}

int
archive_make_write_path(unsigned char *path, size_t size,
                        const unsigned char *base_dir, int serial,
                        size_t file_size, const unsigned char *name_prefix)
{
  unsigned char *pp;

  ASSERT(serial >= 0 && serial <= EJ_MAX_RUN_ID);
  if (!name_prefix) name_prefix = "";

  if (strlen(base_dir) + 32 >= size) {
    err("archive_make_write_path: `%s' is too long", base_dir);
    return -1;
  }

  if (global->use_dir_hierarchy) {
    pp = path + make_hier_path(path, size, base_dir, serial);
    if (global->use_gzip && file_size > global->min_gzip_size) {
      sprintf(pp, "/%s%06d.gz", name_prefix, serial);
      return GZIP;
    }
    sprintf(pp, "/%s%06d", name_prefix, serial);
    return 0;
  } else {
    if (global->use_gzip && file_size > global->min_gzip_size) {
      snprintf(path, size, "%s/%s%06d.gz", base_dir, name_prefix, serial);
      return GZIP;
    }
    snprintf(path, size, "%s/%s%06d", base_dir, name_prefix, serial);
    return 0;
  }
}

int
archive_make_move_path(unsigned char *path, size_t size,
                       const unsigned char *base_dir, int serial,
                       int flags, const unsigned char *name_prefix)
{
  unsigned char *pp;

  ASSERT(serial >= 0 && serial <= EJ_MAX_RUN_ID);
  if (!name_prefix) name_prefix = "";

  if (strlen(base_dir) + 32 >= size) {
    err("archive_make_move_path: `%s' is too long", base_dir);
    return -1;
  }

  if (global->use_dir_hierarchy) {
    pp = path + make_hier_path(path, size, base_dir, serial);
    if (global->use_gzip && (flags & GZIP)) {
      sprintf(pp, "/%s%06d.gz", name_prefix, serial);
      return GZIP;
    }
    sprintf(pp, "/%s%06d", name_prefix, serial);
    return 0;
  } else {
    if (global->use_gzip && (flags & GZIP)) {
      snprintf(path, size, "%s/%s%06d.gz", base_dir, name_prefix, serial);
      return GZIP;
    }
    snprintf(path, size, "%s/%s%06d", base_dir, name_prefix, serial);
    return 0;
  }
}

int
archive_rename(const unsigned char *dir, FILE *flog,
               int n1, const unsigned char *pfx1,
               int n2, const unsigned char *pfx2,
               int gzip_preferred)
{
  path_t name1, name2;
  int f;

  if ((f = archive_make_read_path(name1, sizeof(name1), dir, n1, pfx1,
                                  gzip_preferred)) < 0) {
    if (flog) {
      fprintf(flog, "entry %d does not exist in `%s'\n", n1, dir);
    }
    return -1;
  }
  archive_make_move_path(name2, sizeof(name2), dir, n2, f, pfx2);
  if (archive_dir_prepare(dir, n2, pfx2, 0) < 0) {
    if (flog) {
      fprintf(flog, "cannot create directory for entry %d in `%s'\n", n2, dir);
    }
    return -1;
  }
  if (rename(name1, name2) < 0) {
    if (flog) {
      fprintf(flog, "rename %s -> %s failed: %s\n",
              name1, name2, os_ErrorMsg());
    }
    err("rename(%s,%s) failed: %s", name1, name2, os_ErrorMsg());
    return -1;
  }
  return 0;
}

int
archive_remove(const unsigned char *base_dir, int serial,
               const unsigned char *name_prefix)
{
  unsigned char *path, *pp;
  size_t plen;

  if (!name_prefix) name_prefix = "";
  plen = strlen(base_dir) + strlen(name_prefix) + 128;
  path = (unsigned char *) alloca(plen);

  if (global->use_dir_hierarchy) {
    pp = path + make_hier_path(path, plen, base_dir, serial);
    pp += sprintf(pp, "/%s%06d", name_prefix, serial);
    unlink(path);
    strcpy(pp, ".gz");
    unlink(path);
  }

  pp = path + sprintf(path, "%s/%s%06d", base_dir, name_prefix, serial);
  unlink(path);
  strcpy(pp, ".gz");
  unlink(path);

  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
