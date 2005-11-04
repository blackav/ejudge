/* -*- c -*- */
/* $Id$ */
#ifndef __FULL_ARCHIVE_H__
#define __FULL_ARCHIVE_H__

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

#include <reuse/integral.h>

struct full_archive
{
  int fd;

  // for writing
  long cur_size;

  // for reading
  const unsigned char *mptr;    /* memory mapping address */
  long msize;                   /* file size */
};
typedef struct full_archive *full_archive_t;

struct full_archive_file_header
{
  unsigned char sig[8];         /* the file signature */
  unsigned int  version;        /* the archive format version */
  unsigned char pad[4];         /* padding to 16 bytes */
};

#define FULL_ARCHIVE_MAX_NAME_LEN 255

typedef struct full_archive_entry_header
{
  rint32_t size;                /* entry size (compressed in file) */
  rint32_t raw_size;            /* uncompressed entry size */
  rint32_t header_size;         /* size of this header */
  unsigned int flags;           /* various flags */
  unsigned char name[1];        /* name (up to 255 chars + \0) */
} full_archive_entry_header_t;

full_archive_t full_archive_open_write(const unsigned char *path);
full_archive_t full_archive_open_read(const unsigned char *path);
full_archive_t full_archive_close(full_archive_t af);
int full_archive_append_file(full_archive_t af,
                             const unsigned char *entry_name,
                             unsigned int flags,
                             const unsigned char *path);
int full_archive_find_file(full_archive_t af,
                           const unsigned char *name,
                           long *p_size,
                           long *p_raw_size,
                           unsigned int *p_flags,
                           const unsigned char **p_data);

#endif /* __FULL_ARCHIVE_H__ */
