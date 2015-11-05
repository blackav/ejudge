/* -*- c -*- */
#ifndef __FILEUTL_H__
#define __FILEUTL_H__

/* Copyright (C) 2000-2015 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <stdlib.h>
#include <sys/types.h>

#include "ejudge/xalloc.h"

int   scan_dir(char const *dir, char *result, size_t res_size, int random_mode);
void  scan_dir_add_ignored(const unsigned char *dir,
                           const unsigned char *filename);

int get_file_list(const char *partial_path, strarray_t *files);

/* operation flags */
enum { SAFE = 1, REMOVE = 2, CONVERT = 4, PIPE = 8, GZIP = 16, KEEP_ON_FAIL = 32, ZIP = 64 };

int generic_read_file(char **buf, size_t maxsz, size_t *readsz, int flags,
                      char const *dir, char const *name, char const *sfx);
int generic_write_file(char const *buf, size_t size, int flags,
                       char const *dir, char const *name, char const *sfx);
int generic_copy_file(int sflags,
                      char const *sdir, char const *sname, char const *ssfx,
                      int dflags,
                      char const *ddir, char const *dname, char const *dsfx);
int fast_copy_file(const unsigned char *oldname, const unsigned char *newname);
ssize_t generic_file_size(const unsigned char *dir,
                          const unsigned char *name,
                          const unsigned char *sfx);

int   clear_directory(char const *path);
int   make_dir(char const *, int);
int   make_all_dir(char const *, int);

void  get_uniq_prefix(char *);

int   make_executable(char const *);
int   make_writable(char const *);

int   check_executable(char const *);
int   check_readable_dir(char const *);
int   check_writable_dir(char const *);
enum { SPOOL_IN, SPOOL_OUT };
int   check_writable_spool(char const *, int);

int   relaxed_remove(char const *, char const *);
int   remove_directory_recursively(const unsigned char *path, int preserve_root);

int make_symlink(unsigned char const *dest, unsigned char const *path);
int make_hardlink(const unsigned char *src, const unsigned char *dst);

int generic_truncate(const char *path, ssize_t size);

const unsigned char * get_tmp_dir(unsigned char *buf, size_t size);

int
scan_executable_files(
        const unsigned char *dir,
        int *p_count,
        unsigned char ***p_files);

int
write_tmp_file(
        unsigned char *path,
        size_t path_size,
        const unsigned char *bytes,
        size_t bytes_count);

#endif /* __FILEUTL_H__ */
