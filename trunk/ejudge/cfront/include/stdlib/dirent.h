/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_DIRENT_H__
#define __RCC_DIRENT_H__

/* Copyright (C) 2002-2004 Alexander Chernov <cher@ispras.ru> */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <features.h>
#include <sys/types.h>

struct dirent
{
  ino_t d_ino;
  off_t d_off;
  unsigned short int d_reclen;
  unsigned char d_type;
  char d_name[256];
};

struct dirent64
{
  ino64_t d_ino;
  off64_t d_off;
  unsigned short int d_reclen;
  unsigned char d_type;
  char d_name[256];
};

#define d_fileno	d_ino

#define _DIRENT_HAVE_D_RECLEN 1
#define _DIRENT_HAVE_D_OFF    1
#define _DIRENT_HAVE_D_TYPE   1

#define _D_EXACT_NAMLEN(d) (strlen ((d)->d_name))
#define _D_ALLOC_NAMLEN(d) (((char *) (d) + (d)->d_reclen) - &(d)->d_name[0])

int enum
{
  DT_UNKNOWN = 0,
  DT_FIFO = 1,
  DT_CHR = 2,
  DT_DIR = 4,
  DT_BLK = 6,
  DT_REG = 8,
  DT_LNK = 10,
  DT_SOCK = 12
};

int IFTODT(int);
int DTTOIF(int);

struct __dirstream;
typedef struct __dirstream DIR;

DIR *opendir(const char *);
int closedir(DIR *);

struct dirent *readdir(DIR *);
struct dirent64 *readdir64(DIR *);
int readdir_r(DIR *, struct dirent *, struct dirent **);
int readdir64_r(DIR *, struct dirent64 *, struct dirent64 **);
void rewinddir(DIR *);
void seekdir(DIR *, long int);
long int telldir(DIR *);
int dirfd(DIR *);

int scandir(const char *, struct dirent ***,
            int (*)(const struct dirent *),
            int (*)(const void *, const void *));
int scandir64(const char *, struct dirent64 ***,
              int (*)(const struct dirent64 *),
              int (*)(const void *, const void *));
int alphasort(const void *, const void *);
int alphasort64(const void *, const void *);
int versionsort(const void *, const void *);
int versionsort64(const void *, const void *);

ssize_t getdirentries(int, char *, size_t, off_t *);
ssize_t getdirentries64(int, char *, size_t, off64_t *);

#endif /* __RCC_DIRENT_H__ */
