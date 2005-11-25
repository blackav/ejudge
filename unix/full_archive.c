/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005 Alexander Chernov <cher@ispras.ru> */

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

#include "full_archive.h"

#include "pathutl.h"
#include "errlog.h"
#include "fileutl.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <zlib.h>
#include <stdio.h>
#include <sys/mman.h>

static const unsigned char file_sig[8] = "Ej. Ar.";

full_archive_t
full_archive_open_write(const unsigned char *path)
{
  full_archive_t af = 0;
  int fd = -1;
  struct full_archive_file_header header;
  char *buf;
  int wtot, wsz;

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

  ASSERT(af->fd >= 0);

  if (af->mptr) {
    munmap((void*) af->mptr, af->msize);
  }

  close(af->fd);
  xfree(af);
  return 0;
}

int
full_archive_append_file(full_archive_t af,
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

  if (lseek64(af->fd, af->cur_size, SEEK_SET) < 0) {
    err("full_archive_append_file: lseek64 failed: %s", os_ErrorMsg());
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
  int fd = -1;
  void *mptr = 0;
  size_t msize = 0;
  struct stat finfo;
  struct full_archive_file_header *fhead = 0;
  full_archive_t af = 0;

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
full_archive_find_file(full_archive_t af,
                       const unsigned char *name,
                       long *p_size,
                       long *p_raw_size,
                       unsigned int *p_flags,
                       const unsigned char **p_data)
{
  const unsigned char *cur_ptr;
  const unsigned char *end_ptr = af->mptr + af->msize;
  const full_archive_entry_header_t *cur_head;
  size_t name_len;
  int errcode = 0;

  ASSERT(af);
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
      *p_size = cur_head->size;
      *p_raw_size = cur_head->raw_size;
      *p_flags = cur_head->flags;
      *p_data = cur_ptr;
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

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
