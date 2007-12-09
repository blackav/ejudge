/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ispras.ru> */

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

#include <windows.h>
#include <zlib.h>

static const unsigned char file_sig[8] = "Ej. Ar.";

full_archive_t
full_archive_open_write(const unsigned char *path)
{
  full_archive_t af = 0;
  //int fd = -1;
  struct full_archive_file_header header;
  char *buf;
  int wtot;
  unsigned long wsz;
  HANDLE fd = INVALID_HANDLE_VALUE;

  fd = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
  if (fd == INVALID_HANDLE_VALUE) {
    err("full_archive_open_write: cannot open: %s", os_ErrorMsg());
    goto failure;
  }

  memset(&header, 0, sizeof(header));
  strcpy(header.sig, file_sig);
  header.version = 1;

  wtot = sizeof(header), buf = (char*) &header;
  while (wtot > 0) {
        if (!WriteFile(fd, buf, wtot, &wsz, NULL)) {
      err("full_archive_open_write: write error: %s", os_ErrorMsg());
      goto failure;
    }
    wtot -= wsz, buf += wsz;
  }

  XCALLOC(af, 1);
  af->fd = (int) fd; // FIXME: UGLY!:(
  af->cur_size = sizeof(header);
  return af;

 failure:
  if (fd >= 0) {
    CloseHandle(fd);
    DeleteFile(path);
  }
  xfree(af);
  return 0;
}

full_archive_t
full_archive_close(full_archive_t af)
{
  HANDLE fd;

  if (!af) return 0;

  fd = (HANDLE) af->fd;
  ASSERT(fd != INVALID_HANDLE_VALUE);

  if (af->mptr) {
        //CreateFileMapping
    // Here we must remove (possible) file mapping
        // but since mappings are created for read operations, we ignore for now
  }

  CloseHandle(fd);
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
  struct full_archive_entry_header *cur_head = 0;
  char *file_buf = 0, *comp_buf = 0, *buf;
  size_t file_size = 0;
  uLong comp_size = 0;
  long wtot;
  unsigned char pad_buf[16];
  unsigned long wsz;
  HANDLE fd = INVALID_HANDLE_VALUE;
  HANDLE fd2 = INVALID_HANDLE_VALUE;

  ASSERT(af);
  ASSERT(path);

  fd = (HANDLE) af->fd;
  if (fd < 0) {
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

  if (SetFilePointer(fd, af->cur_size, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
    err("full_archive_append_file: lseek64 failed: %s", os_ErrorMsg());
    goto failure;
  }

  // write header
  wtot = header_size, buf = (char*) cur_head;
  while (wtot > 0) {
    if (!WriteFile(fd, buf, wtot, &wsz, NULL)) {
      err("full_archive_append_file: write error: %s", os_ErrorMsg());
      goto failure;
    }
    wtot -= wsz, buf += wsz;
  }

  if (comp_size > 0) {
    // write compressed file
    wtot = comp_size, buf = comp_buf;
    while (wtot > 0) {
          if (!WriteFile(fd, buf, wtot, &wsz, NULL)) {
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
          if (!WriteFile(fd, buf, wtot, &wsz, NULL)) {
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
  if (fd2 != INVALID_HANDLE_VALUE) CloseHandle(fd2);
  return -1;

}

full_archive_t
full_archive_open_read(const unsigned char *path)
{
        SWERR(("not implemented"));
}

int
full_archive_find_file(full_archive_t af,
                       const unsigned char *name,
                       long *p_size,
                       long *p_raw_size,
                       unsigned int *p_flags,
                       const unsigned char **p_data)
{
        SWERR(("not implemented"));
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
