/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_SYS_SELECT_H__
#define __RCC_SYS_SELECT_H__

/* Copyright (C) 2003,2004 Alexander Chernov */

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
#include <sys/time.h>
#include <bits/sigset.h>

int enum { FD_SETSIZE = 1024 };

typedef long int fd_mask;

typedef struct
{
  fd_mask fds_bits[FD_SETSIZE / (8 * sizeof (fd_mask))];
#define __FDS_BITS(set) ((set)->fds_bits)
} fd_set;
int enum {
#defconst NFDBITS (8 * sizeof (fd_mask))
};

void FD_SET(int, fd_set *);
#define FD_SET(a,b) (FD_SET(a,b))

void FD_CLR(int, fd_set *);
#define FD_CLR(a,b) (FD_CLR(a,b))

void FD_ZERO(fd_set *);
#define FD_ZERO(a) (FD_ZERO(a))

int FD_ISSET(int, const fd_set *);
#define FD_ISSET(a,b) (FD_ISSET(a,b))

int select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int pselect(int, fd_set *, fd_set *, fd_set *, const struct timespec *,
            const sigset_t *);

#endif /* __RCC_SYS_SELECT_H__ */

/**
 * Local variables:
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "fd_set" "fd_mask")
 * End:
 */
