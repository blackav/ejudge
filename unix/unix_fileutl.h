/* -*- c -*- */
/* $Id$ */
#ifndef __UNIX_FILEUTL_H__
#define __UNIX_FILEUTL_H__

/* Copyright (C) 2000,2001 Alexander Chernov <cher@ispras.ru> */

/*
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

ssize_t sf_read(int, void *, size_t, char const *);
ssize_t sf_write(int, void const *, size_t, char const *);
int     sf_close(int, char const *);
int     sf_open(char const *path, int flags, mode_t mode);
off_t   sf_lseek(int fd, off_t offset, int whence, char const *);
int     sf_chmod(char const *path, mode_t mode);
int     sf_mkfifo(char const *path, mode_t mode);

#endif /* __UNIX_FILEUTL_H__ */
