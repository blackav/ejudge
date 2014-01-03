/* -*- c -*- */
/* $Id$ */

#ifndef	__RCC_GRP_H__
#define	__RCC_GRP_H__	1

/* Copyright (C) 2003,2004 Alexander Chernov <cher@ispras.ru> */

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
#include <stdlib.h>
#include <stdio.h>

struct group
{
  char *gr_name;                /* Group name.	*/
  char *gr_passwd;              /* Password.	*/
  gid_t gr_gid;                 /* Group ID.	*/
  char **gr_mem;                /* Member list.	*/
};

void setgrent(void);
void endgrent(void);
struct group *getgrent(void);
struct group *fgetgrent(FILE *);
int putgrent (const struct group *, FILE *);
struct group *getgrgid(gid_t);
struct group *getgrnam(const char *);

int enum { NSS_BUFLEN_GROUP = 1024 };
#define NSS_BUFLEN_GROUP NSS_BUFLEN_GROUP

int getgrent_r(struct group *, char *, size_t , struct group **);
int getgrgid_r(gid_t, struct group *, char *, size_t, struct group **);
int getgrnam_r(const char *, struct group *, char *, size_t, struct group **);
int fgetgrent_r(FILE *, struct group *, char *, size_t, struct group **);

int setgroups(size_t, const gid_t *);
int getgrouplist(const char *, gid_t, gid_t *, int *);
int initgroups(const char *, gid_t );

#endif /* __RCC_GRP_H__ */
