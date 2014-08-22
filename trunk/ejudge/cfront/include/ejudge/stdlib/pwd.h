/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_PWD_H__
#define __RCC_PWD_H__

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

struct passwd
{
  char *pw_name;
  char *pw_passwd;
  uid_t pw_uid;
  gid_t pw_gid;
  char *pw_gecos;
  char *pw_dir;
  char *pw_shell;
};

void setpwent(void);
void endpwent(void);
struct passwd *getpwent(void);

#ifndef RCC_FILE_DEFINED
#define RCC_FILE_DEFINED 1
typedef struct
{
  int dummy;
} FILE;
#endif /* RCC_FILE_DEFINED */

struct passwd *fgetpwent(FILE *);
int putpwent(const struct passwd *, FILE *);

struct passwd *getpwuid(uid_t);
struct passwd *getpwnam(const char *);

int enum { NSS_BUFLEN_PASSWD = 1024 };

int getpwent_r(struct passwd *, char *, size_t, struct passwd **);
int getpwuid_r(uid_t, struct passwd *, char *, size_t, struct passwd **);
int getpwnam_r(const char*, struct passwd*, char*, size_t, struct passwd **);
int fgetpwent_r(FILE *, struct passwd *, char *, size_t, struct passwd **);
int getpw(uid_t, char *);

#endif /* __RCC_PWD_H__ */
