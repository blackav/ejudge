/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/full_archive.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/fileutl.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <zlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>

#if defined CONF_HAS_LIBZIP
#include <zip.h>
#endif

static const unsigned char file_sig[8] = "Ej. Ar.";

#if defined CONF_HAS_LIBZIP
static full_archive_t full_archive_open_write_zip(const unsigned char *path);
static full_archive_t full_archive_open_read_zip(const unsigned char *path);
static full_archive_t full_archive_close_zip(full_archive_t af);
static int
full_archive_append_file_zip(
        full_archive_t af,
        const unsigned char *entry_name,
        unsigned int flags,
        const unsigned char *path);
static int
full_archive_find_file_zip(
        full_archive_t af,
        const unsigned char *name,
        long *p_raw_size,
        unsigned int *p_flags,
        unsigned char **p_data);
#endif

full_archive_t
full_archive_open_write(const unsigned char *path)
{
  full_archive_t af = 0;
  int fd = -1;
  struct full_archive_file_header header;
  char *buf;
  int wtot, wsz, plen;

  if (!path || !*path) {
    err("full_archive_open_write: path == NULL");
    goto failure;
  }

#if defined CONF_HAS_LIBZIP
  if ((plen = strlen(path)) > 4 && !strcmp(path + plen - 4, ".zip")) {
    return full_archive_open_write_zip(path);
  }
#endif

  if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0) {
    err("full_archive_open_write: cannot open: %s", os_ErrorMsg());
    goto failure;
  }

  memset(&header, 0, sizeof(header));
  strcpy(header.sig, file_sig);
  header.version = 1;

  wtot = sizeof(header), buf = (char*) &header;
  while (wtot > 0) {
    if ((wsz = write(fd, buf, wtot)) <= 0) {
      err("full_archive_open_write: write error: %s", os_ErrorMsg());
      goto failure;
    }
    wtot -= wsz, buf += wsz;
  }

  XCALLOC(af, 1);
  af->fd = fd;
  af->cur_size = sizeof(header);
  return af;

 failure:
  if (fd >= 0) {
    close(fd);
    unlink(path);
  }
  xfree(af);
  return 0;
}

full_archive_t
full_archive_close(full_archive_t af)
{
  if (!af) return 0;

#if defined CONF_HAS_LIBZIP
  if (af->zip_mode) {
    return full_archive_close_zip(af);
  }
#endif

  ASSERT(af->fd >= 0);

  if (af->mptr) {
    munmap((void*) af->mptr, af->msize);
  }

  close(af->fd);
  xfree(af);
  return 0;
}

int
full_archive_append_file(
        full_archive_t af,
        const unsigned char *entry_name,
        unsigned int flags,
        const unsigned char *path)
{
  size_t entry_name_len;
  size_t header_size;
  int fd2 = -1;
  struct full_archive_entry_header *cur_head = 0;
  char *file_buf = 0, *comp_buf = 0, *buf;
  size_t file_size = 0;
  uLong comp_size = 0;
  long wtot, wsz;
  unsigned char pad_buf[16];

  ASSERT(af);
  ASSERT(path);

#if defined CONF_HAS_LIBZIP
  if (af->zip_mode) {
    return full_archive_append_file_zip(af, entry_name, flags, path);
  }
#endif

  if (af->fd < 0) {
    err("full_archive_append_file: file descriptor is invalid");
    goto failure;
  }
  if (!entry_name) entry_name = "";
  if ((entry_name_len = strlen(entry_name)) > FULL_ARCHIVE_MAX_NAME_LEN) {
    err("full_archive_append_file: entry name `%s' is too long", entry_name);
    goto failure;
  }
  header_size = sizeof(struct full_archive_entry_header) + entry_name_len;
  header_size = (header_size + 15) & ~15;

  if (generic_read_file(&file_buf, 0, &file_size, 0, 0, path, 0) < 0) {
    err("full_archive_append_file: reading of `%s' failed", path);
    goto failure;
  }
  if (file_size > 0) {
    comp_size = compressBound(file_size);
    comp_buf = xcalloc(1, comp_size);
    if (compress2(comp_buf, &comp_size, file_buf, file_size, 9) != Z_OK) {
      err("full_archive_append_file: compressing failed");
      goto failure;
    }
  } else {
    comp_size = 0;
    comp_buf = 0;
  }

  cur_head = (struct full_archive_entry_header*) xcalloc(1, header_size);
  cur_head->header_size = header_size;
  cur_head->flags = flags;
  strcpy(cur_head->name, entry_name);
  cur_head->raw_size = file_size;
  cur_head->size = comp_size;

  if (lseek(af->fd, af->cur_size, SEEK_SET) < 0) {
    err("full_archive_append_file: lseek failed: %s", os_ErrorMsg());
    goto failure;
  }

  // write header
  wtot = header_size, buf = (char*) cur_head;
  while (wtot > 0) {
    if ((wsz = write(af->fd, buf, wtot)) <= 0) {
      err("full_archive_append_file: write error: %s", os_ErrorMsg());
      goto failure;
    }
    wtot -= wsz, buf += wsz;
  }

  if (comp_size > 0) {
    // write compressed file
    wtot = comp_size, buf = comp_buf;
    while (wtot > 0) {
      if ((wsz = write(af->fd, buf, wtot)) <= 0) {
        err("full_archive_append_file: write error: %s", os_ErrorMsg());
        goto failure;
      }
      wtot -= wsz, buf += wsz;
    }

    // pad with zeroes
    memset(pad_buf, 0, sizeof(pad_buf));
    wtot = ((comp_size + 15) & ~15) - comp_size;
    buf = pad_buf;
    while (wtot > 0) {
      if ((wsz = write(af->fd, buf, wtot)) <= 0) {
        err("full_archive_append_file: write error: %s", os_ErrorMsg());
        goto failure;
      }
      wtot -= wsz, buf += wsz;
    }
  }

  xfree(cur_head);
  xfree(file_buf);
  xfree(comp_buf);
  af->cur_size += header_size + comp_size;
  af->cur_size = (af->cur_size + 15) & ~15;

  return 0;

 failure:
  xfree(cur_head);
  xfree(file_buf);
  xfree(comp_buf);
  if (fd2 >= 0) close(fd2);
  return -1;
}

full_archive_t
full_archive_open_read(const unsigned char *path)
{
  int fd = -1, plen;
  void *mptr = 0;
  size_t msize = 0;
  struct stat finfo;
  struct full_archive_file_header *fhead = 0;
  full_archive_t af = 0;

  if (!path || !*path) {
    err("full_archive_open_read: path == NULL");
    goto failure;
  }

#if defined CONF_HAS_LIBZIP
  if ((plen = strlen(path)) > 4 && !strcmp(path + plen - 4, ".zip")) {
    return full_archive_open_read_zip(path);
  }
#endif

  if ((fd = open(path, O_RDONLY, 0)) < 0) {
    err("full_archive_open_read: cannot open `%s': %s", path, os_ErrorMsg());
    goto failure;
  }
  if (fstat(fd, &finfo) < 0) {
    err("full_archive_open_read: fstat failed: %s", os_ErrorMsg());
    goto failure;
  }
  if (!S_ISREG(finfo.st_mode)) {
    err("full_archive_open_read: file %s is not a regular file",os_ErrorMsg());
    goto failure;
  }
  msize = finfo.st_size;
  if (msize < sizeof(struct full_archive_file_header)) {
    err("full_archive_open_read: file is too small (size %zu)", msize);
    goto failure;
  }
  if ((mptr = mmap(0, msize, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
    err("full_archive_open_read: mmap failed: %s", os_ErrorMsg());
    goto failure;
  }

  fhead = (struct full_archive_file_header*) mptr;
  if (strncmp(fhead->sig, file_sig, sizeof(file_sig)) != 0) {
    err("full_archive_open_read: file signature mismatch");
    goto failure;
  }
  if (fhead->version != 1) {
    err("full_archive_open_read: version mismatch");
    goto failure;
  }

  XCALLOC(af, 1);
  af->fd = fd;
  af->mptr = mptr;
  af->msize = msize;
  return af;

 failure:
  if (af) xfree(af);
  if (mptr) munmap(mptr, msize);
  if (fd) close(fd);
  return 0;
}

int
full_archive_find_file(
        full_archive_t af,
        const unsigned char *name,
        long *p_raw_size,
        unsigned int *p_flags,
        unsigned char **p_data)
{
  const unsigned char *cur_ptr;
  const unsigned char *end_ptr = af->mptr + af->msize;
  const full_archive_entry_header_t *cur_head;
  size_t name_len;
  int errcode = 0;

  ASSERT(af);

#if defined CONF_HAS_LIBZIP
  if (af->zip_mode) {
    return full_archive_find_file_zip(af, name, p_raw_size, p_flags, p_data);
  }
#endif

  ASSERT(af->mptr);

  cur_ptr = af->mptr + sizeof(struct full_archive_file_header);
  while (1) {
    if (((unsigned long) cur_ptr & 15)) {
      errcode = 1;
      goto failure;
    }
    if (cur_ptr == end_ptr) break;
    if (cur_ptr > end_ptr) {
      errcode = 2;
      goto failure;
    }
    if (cur_ptr + sizeof(*cur_head) > end_ptr) {
      errcode = 3;
      goto failure;
    }
    cur_head = (const full_archive_entry_header_t *) cur_ptr;
    if (cur_head->header_size < 0) {
      errcode = 4;
      goto failure;
    }
    if ((cur_head->header_size & 15)) {
      errcode = 5;
      goto failure;
    }
    if (cur_head->header_size < sizeof(*cur_head)) {
      errcode = 6;
      goto failure;
    }
    if (cur_head->header_size > (((sizeof(*cur_head) + FULL_ARCHIVE_MAX_NAME_LEN) + 15) & ~15)) {
      errcode = 7;
      goto failure;
    }
    name_len = strnlen(cur_head->name, cur_head->header_size - sizeof(*cur_head));
    if (cur_head->name[name_len]) {
      errcode = 8;
      goto failure;
    }
    if (name_len > FULL_ARCHIVE_MAX_NAME_LEN) {
      errcode = 9;
      goto failure;
    }

    cur_ptr += cur_head->header_size;
    if (cur_head->size < 0) {
      errcode = 10;
      goto failure;
    }
    if (cur_ptr + cur_head->size > end_ptr) {
      errcode = 11;
      goto failure;
    }

    if (!strcmp(cur_head->name, name)) {
      *p_raw_size = cur_head->raw_size;
      *p_flags = cur_head->flags;

      if (cur_head->raw_size <= 0) {
        *p_data = xmalloc(1);
        **p_data = 0;
        return 1;
      }

      *p_data = xmalloc(cur_head->raw_size + 1);
      if (uncompress(*p_data, p_raw_size, cur_ptr, cur_head->size) != Z_OK) {
        xfree(*p_data);
        errcode = 13;
        goto failure;
      }
      (*p_data)[cur_head->raw_size] = 0;
      return 1;
    }

    cur_ptr += cur_head->size;
    cur_ptr = (const unsigned char*)(((unsigned long) cur_ptr + 15) & ~15);
    if (cur_ptr > end_ptr) {
      errcode = 12;
      goto failure;
    }
  }

  /* entry not found */
  return 0;

 failure:
  err("full_archive_find_file: error %d", errcode);
  return -1;
}

#if defined CONF_HAS_LIBZIP
static full_archive_t
full_archive_open_write_zip(const unsigned char *path)
{
  full_archive_t af = NULL;
  int zip_err = 0;
  struct zip *zzz = NULL;
  char errbuf[1024];

  if (!(zzz = zip_open(path, ZIP_CREATE, &zip_err))) {
    zip_error_to_str(errbuf, sizeof(errbuf), zip_err, errno);
    err("%s: failed to open ZIP '%s': %s", __FUNCTION__, path, errbuf);
    goto cleanup;
  }

  XCALLOC(af, 1);
  af->zip_mode = 1;
  af->hzip = zzz;
  return af;

cleanup:
  return NULL;
}

static full_archive_t
full_archive_open_read_zip(const unsigned char *path)
{
  full_archive_t af = NULL;
  int zip_err = 0;
  struct zip *zzz = NULL;
  char errbuf[1024];

  if (!(zzz = zip_open(path, ZIP_CHECKCONS, &zip_err))) {
    zip_error_to_str(errbuf, sizeof(errbuf), zip_err, errno);
    err("%s: failed to open ZIP '%s': %s", __FUNCTION__, path, errbuf);
    goto cleanup;
  }

  XCALLOC(af, 1);
  af->zip_mode = 1;
  af->hzip = zzz;
  return af;

cleanup:
  return NULL;
}

static full_archive_t
full_archive_close_zip(full_archive_t af)
{
  if (!af) return NULL;

  ASSERT(af->zip_mode);
  if (af->hzip) {
    if (zip_close(af->hzip) < 0) {
      err("%s: close failed: %s", __FUNCTION__, zip_strerror(af->hzip));
    }
  }
  memset(af, 0, sizeof(*af));
  xfree(af);
  return NULL;
}

static int
full_archive_append_file_zip(
        full_archive_t af,
        const unsigned char *entry_name,
        unsigned int flags,
        const unsigned char *path)
{
  struct zip_source *zsrc = NULL;
  char *file_buf = NULL;
  size_t file_size = 0;

  ASSERT(af);
  ASSERT(af->zip_mode);
  ASSERT(af->hzip);

  if (generic_read_file(&file_buf, 0, &file_size, 0, 0, path, 0) < 0) {
    err("%s: read of '%s' failed", __FUNCTION__, path);
    goto cleanup;
  }

  if (!(zsrc = zip_source_buffer(af->hzip, file_buf, file_size, 1))) {
    err("%s: append of '%s' failed: %s", __FUNCTION__, path, zip_strerror(af->hzip));
    goto cleanup;
  }
  file_buf = NULL;

  if (zip_add(af->hzip, entry_name, zsrc) < 0) {
    err("%s: append of '%s' failed: %s", __FUNCTION__, path, zip_strerror(af->hzip));
    goto cleanup;
  }

  zsrc = NULL;
  return 0;

cleanup:
  if (zsrc) {
    zip_source_free(zsrc); zsrc = NULL;
  }
  xfree(file_buf);
  return -1;
}

static int
full_archive_find_file_zip(
        full_archive_t af,
        const unsigned char *name,
        long *p_raw_size,
        unsigned int *p_flags,
        unsigned char **p_data)
{
  int file_ind = 0;
  struct zip_stat zs;
  unsigned char *data = NULL, *ptr;
  struct zip_file *zf = NULL;
  long rz, remz;

  ASSERT(af);
  ASSERT(af->zip_mode);
  ASSERT(af->hzip);

  if (p_flags) *p_flags = 0;

  if ((file_ind = zip_name_locate(af->hzip, name, 0)) < 0) {
    err("%s: file '%s' does not exist", __FUNCTION__, name);
    return 0;
  }

  zip_stat_init(&zs);
  if (zip_stat_index(af->hzip, file_ind, 0, &zs) < 0) {
    err("%s: file '%s' stat failed", __FUNCTION__, name);
    goto cleanup;
  }

  if (zs.size <= 0) {
    *p_raw_size = 0;
    *p_data = xmalloc(1);
    **p_data = 0;
    return 1;
  }

  *p_raw_size = zs.size;
  data = xmalloc(zs.size + 1);
  if (!(zf = zip_fopen_index(af->hzip, file_ind, 0))) {
    err("%s: failed to open entry '%s': %s", __FUNCTION__, name, zip_strerror(af->hzip));
    goto cleanup;
  }
  ptr = data; remz = zs.size;
  while (remz > 0) {
    if ((rz = zip_fread(zf, ptr, remz)) < 0) {
      err("%s: read error: %s", __FUNCTION__, zip_file_strerror(zf));
      goto cleanup;
    }
    if (!rz) {
      err("%s: read returned 0", __FUNCTION__);
      goto cleanup;
    }
    ptr += rz;
    remz -= rz;
  }

  zip_fclose(zf); zf = NULL;
  data[zs.size] = 0;
  *p_data = data;
  return 1;

cleanup:
  if (zf) zip_fclose(zf);
  xfree(data);
  return -1;
}
#endif

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
