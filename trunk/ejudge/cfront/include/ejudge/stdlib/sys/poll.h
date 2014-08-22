/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `sys/poll.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Compatibility definitions for System V `poll' interface.
   Copyright (C) 1994,96,97,98,99,2000,2001 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef __RCC_SYS_POLL_H__
#define __RCC_SYS_POLL_H__ 1

#include <features.h>

int enum
{
  POLLIN = 0x001,
#define POLLIN POLLIN
  POLLPRI = 0x002,
#define POLLPRI POLLPRI
  POLLOUT = 0x004,
#define POLLOUT POLLOUT
  POLLRDNORM = 0x040,
#define POLLRDNORM POLLRDNORM
  POLLRDBAND = 0x080,
#define POLLRDBAND POLLRDBAND
  POLLWRNORM = 0x100,
#define POLLWRNORM POLLWRNORM
  POLLWRBAND = 0x200,
#define POLLWRBAND POLLWRBAND
  POLLMSG = 0x400,
#define POLLMSG POLLMSG
  POLLERR = 0x008,
#define POLLERR POLLERR
  POLLHUP = 0x010,
#define POLLHUP POLLHUP
  POLLNVAL = 0x020,
#define POLLNVAL POLLNVAL
};

/* Type used for the number of file descriptors.  */
typedef unsigned long int nfds_t;

/* Data structure describing a polling request.  */
struct pollfd
{
  int fd;
  short int events;
  short int revents;
};

int poll(struct pollfd *fds, nfds_t nfds, int timeout);

#endif  /* __RCC_SYS_POLL_H__ */
