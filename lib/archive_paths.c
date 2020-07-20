/* -*- c -*- */

/* Copyright (C) 2003-2019 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ej_types.h"
#include "ejudge/ej_limits.h"
#include "ejudge/archive_paths.h"
#include "ejudge/prepare.h"
#include "ejudge/fileutl.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/serve_state.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/prepare_dflt.h"

#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

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
archive_dir_prepare(const serve_state_t state,
                    const unsigned char *base_dir, int serial,
                    const unsigned char *prefix, int no_unlink_flag)
{
  unsigned char sbuf[16];
  path_t path;
  unsigned char *pp;
  struct stat sb;
  int i;

  ASSERT(base_dir);
  if (!state->global->use_dir_hierarchy) return 0;

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
      if (mkdir(path, 0775) < 0) {
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
archive_make_read_path(const serve_state_t state,
                       unsigned char *path, size_t size,
                       const unsigned char *base_dir, int serial,
                       const unsigned char *name_prefix, int gzip_preferred)
{
  unsigned char *pp;
  struct stat sb;

  ASSERT(serial >= 0 && serial <= EJ_MAX_RUN_ID);
  if (!name_prefix) name_prefix = "";

  if (state->global->use_dir_hierarchy) {
    if (strlen(base_dir) + 32 >= size) {
      err("archive_make_read_path: `%s' is too long", base_dir);
      return -1;
    }
    pp = path + make_hier_path(path, size, base_dir, serial);
    if ((gzip_preferred & ZIP)) {
      sprintf(pp, "/%s%06d.zip", name_prefix, serial);
      if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return ZIP;
      sprintf(pp, "/%s%06d", name_prefix, serial);
      if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return 0;
    } else if (gzip_preferred) {
      if (state->global->use_gzip) {
        sprintf(pp, "/%s%06d.gz", name_prefix, serial);
        if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return GZIP;
      }
      sprintf(pp, "/%s%06d", name_prefix, serial);
      if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return 0;
    } else {
      sprintf(pp, "/%s%06d", name_prefix, serial);
      if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return 0;
      if (state->global->use_gzip) {
        sprintf(pp, "/%s%06d.gz", name_prefix, serial);
        if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return GZIP;
      }
    }
  }

  if ((gzip_preferred & ZIP)) {
    snprintf(path, size, "%s/%s%06d.zip", base_dir, name_prefix, serial);
    if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return ZIP;
    snprintf(path, size, "%s/%s%06d", base_dir, name_prefix, serial);
    if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return 0;
  } else if (gzip_preferred) {
    if (state->global->use_gzip) {
      snprintf(path, size, "%s/%s%06d.gz", base_dir, name_prefix, serial);
      if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return GZIP;
    }
    snprintf(path, size, "%s/%s%06d", base_dir, name_prefix, serial);
    if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return 0;
  } else {
    snprintf(path, size, "%s/%s%06d", base_dir, name_prefix, serial);
    if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return 0;
    if (state->global->use_gzip) {
      snprintf(path, size, "%s/%s%06d.gz", base_dir, name_prefix, serial);
      if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return GZIP;
    }
  }

  err("archive_make_read_path: no entry %d in `%s'", serial, base_dir);
  return -1;
}

int
archive_make_write_path(
        const serve_state_t state,
        unsigned char *path,
        size_t size,
        const unsigned char *base_dir,
        int serial,
        size_t file_size,
        const unsigned char *name_prefix,
        int zip_mode)
{
  unsigned char *pp;

  ASSERT(serial >= 0 && serial <= EJ_MAX_RUN_ID);
  if (!name_prefix) name_prefix = "";

  if (strlen(base_dir) + 32 >= size) {
    err("archive_make_write_path: `%s' is too long", base_dir);
    return -1;
  }

  if (state->global->use_dir_hierarchy) {
    pp = path + make_hier_path(path, size, base_dir, serial);
    if ((zip_mode & ZIP)) {
      sprintf(pp, "/%s%06d.zip", name_prefix, serial);
      return ZIP;
    } else {
      if (zip_mode >= 0 && state->global->use_gzip && file_size > state->global->min_gzip_size) {
        sprintf(pp, "/%s%06d.gz", name_prefix, serial);
        return GZIP;
      }
      sprintf(pp, "/%s%06d", name_prefix, serial);
      return 0;
    }
  } else {
    if ((zip_mode & ZIP)) {
      snprintf(path, size, "%s/%s%06d.zip", base_dir, name_prefix, serial);
      return ZIP;
    } else {
      if (zip_mode >= 0 && state->global->use_gzip && file_size > state->global->min_gzip_size) {
        snprintf(path, size, "%s/%s%06d.gz", base_dir, name_prefix, serial);
        return GZIP;
      }
      snprintf(path, size, "%s/%s%06d", base_dir, name_prefix, serial);
      return 0;
    }
  }
}

int
archive_prepare_write_path(
        const serve_state_t state,
        unsigned char *path,
        size_t size,
        const unsigned char *base_dir,
        int run_id,
        long long file_size,
        const unsigned char *prefix,
        int zip_mode,
        int no_unlink_flag)
{
  int flags = archive_make_write_path(state, path, size, base_dir, run_id, file_size, prefix, zip_mode);
  if (flags < 0) return flags;
  if (archive_dir_prepare(state, base_dir, run_id, prefix, no_unlink_flag) < 0) return -1;
  return flags;
}

static int
archive_make_move_path(const serve_state_t state,
                       unsigned char *path, size_t size,
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

  if (state->global->use_dir_hierarchy) {
    pp = path + make_hier_path(path, size, base_dir, serial);
    if ((flags & ZIP)) {
      sprintf(pp, "/%s%06d.zip", name_prefix, serial);
      return ZIP;
    } else if (state->global->use_gzip && (flags & GZIP)) {
      sprintf(pp, "/%s%06d.gz", name_prefix, serial);
      return GZIP;
    }
    sprintf(pp, "/%s%06d", name_prefix, serial);
    return 0;
  } else {
    if ((flags & ZIP)) {
      snprintf(path, size, "%s/%s%06d.zip", base_dir, name_prefix, serial);
      return ZIP;
    } else if (state->global->use_gzip && (flags & GZIP)) {
      snprintf(path, size, "%s/%s%06d.gz", base_dir, name_prefix, serial);
      return GZIP;
    }
    snprintf(path, size, "%s/%s%06d", base_dir, name_prefix, serial);
    return 0;
  }
}

int
archive_rename(const serve_state_t state,
               const unsigned char *dir, FILE *flog,
               int n1, const unsigned char *pfx1,
               int n2, const unsigned char *pfx2,
               int gzip_preferred)
{
  path_t name1, name2;
  int f;

  if ((f = archive_make_read_path(state, name1, sizeof(name1), dir, n1, pfx1,
                                  gzip_preferred)) < 0) {
    if (flog) {
      fprintf(flog, "entry %d does not exist in `%s'\n", n1, dir);
    }
    return -1;
  }
  archive_make_move_path(state, name2, sizeof(name2), dir, n2, f, pfx2);
  if (archive_dir_prepare(state, dir, n2, pfx2, 0) < 0) {
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
archive_remove(
        const serve_state_t state,
        const unsigned char *base_dir,
        int serial,
        const unsigned char *name_prefix)
{
  unsigned char *path, *pp;
  size_t plen;
  unsigned char path2[PATH_MAX];

  if (!name_prefix) name_prefix = "";
  plen = strlen(base_dir) + strlen(name_prefix) + 128;
  path = (unsigned char *) alloca(plen);

  if (state->global->use_dir_hierarchy) {
    pp = path + make_hier_path(path, plen, base_dir, serial);
    pp += sprintf(pp, "/%s%06d", name_prefix, serial);
    unlink(path);
    snprintf(path2, sizeof(path2), "%s.zip", path);
    unlink(path2);
    snprintf(path2, sizeof(path2), "%s.gz", path);
    unlink(path2);
  }

  pp = path + sprintf(path, "%s/%s%06d", base_dir, name_prefix, serial);
  unlink(path);
  snprintf(path2, sizeof(path2), "%s.zip", path);
  unlink(path2);
  snprintf(path2, sizeof(path2), "%s.gz", path);
  unlink(path2);

  return 0;
}

int
uuid_archive_make_write_path(
        const serve_state_t state,
        unsigned char *path,
        size_t size,
        const ej_uuid_t *prun_uuid,
        long long file_size,
        const unsigned char *name,
        int zip_mode)
{
  ASSERT(prun_uuid);
  ASSERT(ej_uuid_is_nonempty(*prun_uuid));

  const unsigned char *suffix = "";
  if (zip_mode >= 0) {
    if ((zip_mode & ZIP)) {
      suffix = ".zip";
      zip_mode = ZIP;
    } else if (state->global->use_gzip > 0 && file_size > state->global->min_gzip_size) {
      suffix = ".gz";
      zip_mode = GZIP;
    }
  } else {
    zip_mode = 0;
  }

  snprintf(path, size, "%s/%02x/%02x/%s/%s%s",
           state->global->uuid_archive_dir, ej_uuid_bytes(prun_uuid)[0],
           ej_uuid_bytes(prun_uuid)[1],
           ej_uuid_unparse(prun_uuid, NULL), name, suffix);
  return zip_mode;
}

int
uuid_archive_make_read_path(
        const serve_state_t state,
        unsigned char *path,
        size_t size,
        const ej_uuid_t *prun_uuid,
        const unsigned char *name,
        int gzip_preferred)
{
  struct stat sb;

  ASSERT(prun_uuid);
  ASSERT(ej_uuid_is_nonempty(*prun_uuid));

  int len = snprintf(path, size - 4, "%s/%02x/%02x/%s/%s",
                     state->global->uuid_archive_dir, ej_uuid_bytes(prun_uuid)[0],
                     ej_uuid_bytes(prun_uuid)[1],
                     ej_uuid_unparse(prun_uuid, NULL), name);
  if (len >= size - 4) {
    err("uuid_archive_make_read_path: archive path is too long");
    return -1;
  }
  if (gzip_preferred > 0 && (gzip_preferred & ZIP)) {
    path[len] = '.'; path[len + 1] = 'z'; path[len + 2] = 'i'; path[len + 3] = 'p'; path[len + 4] = 0;
    if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return ZIP;
    path[len] = 0;
    if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return 0;
  } else if (gzip_preferred > 0) {
    if (state->global->use_gzip) {
      path[len] = '.'; path[len + 1] = 'g'; path[len + 2] = 'z'; path[len + 3] = 0;
      if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return GZIP;
    }
    path[len] = 0;
    if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return 0;
  } else if (!gzip_preferred) {
    if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return 0;
    if (state->global->use_gzip) {
      path[len] = '.'; path[len + 1] = 'g'; path[len + 2] = 'z'; path[len + 3] = 0;
      if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return GZIP;
    }
  } else {
    // never try .gz files
    if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode)) return 0;
  }

  path[len] = 0;
  err("uuid_archive_make_read_path: no entry %s", path);
  return -1;
}

int
uuid_archive_dir_prepare(
        const serve_state_t state,
        const ej_uuid_t *prun_uuid,
        const unsigned char *name,
        int no_unlink_flag)
{
  unsigned char path[PATH_MAX];
  unsigned char path2[PATH_MAX];

  ASSERT(prun_uuid);
  ASSERT(ej_uuid_is_nonempty(*prun_uuid));

  snprintf(path, sizeof(path), "%s/%02x/%02x/%s",
           state->global->uuid_archive_dir, ej_uuid_bytes(prun_uuid)[0],
           ej_uuid_bytes(prun_uuid)[1],
           ej_uuid_unparse(prun_uuid, NULL));
  if (os_MakeDirPath(path, 0755) < 0) {
    err("uuid_archive_dir_prepare: mkdir '%s' failed: %s", path, os_ErrorMsg());
    return -1;
  }

  if (!no_unlink_flag) {
    snprintf(path2, sizeof(path2), "%s/%s", path, name);
    unlink(path2);
    snprintf(path2, sizeof(path2), "%s/%s.gz", path, name);
    unlink(path2);
    snprintf(path2, sizeof(path2), "%s/%s.zip", path, name);
    unlink(path2);
  }

  return 0;
}

int
uuid_archive_prepare_write_path(
        const serve_state_t state,
        unsigned char *path,
        size_t size,
        const ej_uuid_t *prun_uuid,
        long long file_size,
        const unsigned char *name,
        int zip_mode,
        int no_unlink_flag)
{
  int flags = uuid_archive_make_write_path(state, path, size, prun_uuid, file_size, name, zip_mode);
  if (flags < 0) return flags;
  if (uuid_archive_dir_prepare(state, prun_uuid, name, no_unlink_flag) < 0) return -1;
  return flags;
}

static void
remove_all_suffixes(const unsigned char *base)
{
  unsigned char path[PATH_MAX];

  snprintf(path, sizeof(path), "%s", base);
  unlink(path);
  snprintf(path, sizeof(path), "%s.gz", base);
  unlink(path);
  snprintf(path, sizeof(path), "%s.zip", base);
  unlink(path);
}

int
uuid_archive_remove(
        const serve_state_t state,
        const ej_uuid_t *prun_uuid,
        int preserve_source)
{
  unsigned char base[PATH_MAX];
  unsigned char path[PATH_MAX];

  ASSERT(prun_uuid);
  ASSERT(ej_uuid_is_nonempty(*prun_uuid));

  snprintf(base, sizeof(base), "%s/%02x/%02x/%s",
           state->global->uuid_archive_dir,
           ej_uuid_bytes(prun_uuid)[0],
           ej_uuid_bytes(prun_uuid)[1],
           ej_uuid_unparse(prun_uuid, NULL));
  if (preserve_source <= 0) {
    snprintf(path, sizeof(path), "%s/%s", base, DFLT_R_UUID_SOURCE);
    remove_all_suffixes(path);
  }

  snprintf(path, sizeof(path), "%s/%s", base, DFLT_R_UUID_XML_REPORT);
  remove_all_suffixes(path);

  // bson is never compressed
  snprintf(path, sizeof(path), "%s/%s", base, DFLT_R_UUID_BSON_REPORT);
  unlink(path);

  snprintf(path, sizeof(path), "%s/%s", base, DFLT_R_UUID_REPORT);
  remove_all_suffixes(path);

  snprintf(path, sizeof(path), "%s/%s", base, DFLT_R_UUID_FULL_ARCHIVE);
  remove_all_suffixes(path);

  return 0;
}
