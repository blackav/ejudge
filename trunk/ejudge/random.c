/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "random.h"
#include "errlog.h"

#include <reuse/osdeps.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static int urandom_fd = -1;

int
random_init(void)
{
  if (urandom_fd >= 0) return 0;

  if((urandom_fd = open("/dev/urandom", O_RDONLY)) < 0) {
    err("open of /dev/urandom failed: %s", os_ErrorMsg());
    return -1;
  }
  return 0;
}

void
random_cleanup(void)
{
  if (urandom_fd < 0) return;
  close(urandom_fd);
  urandom_fd = 0;
}

int
random_u16(void)
{
  unsigned short val = 0;
  int n, r;
  char *p;

  ASSERT(urandom_fd >= 0);

  while (!val) {
    p = (char*) &val;
    r = sizeof(val);
    while (r > 0) {
      n = read(urandom_fd, p, r);
      if (n < 0) {
        err("read from /dev/urandom failed: %s", os_ErrorMsg());
        return (unsigned) random();
      }
      if (!n) {
        err("EOF on /dev/urandom???");
        return (unsigned) random();
      }
      p += n;
      r -= n;
    }
  }

  return val;
}

unsigned
random_u32(void)
{
  unsigned val = 0;
  int n, r;
  char *p;

  ASSERT(urandom_fd >= 0);

  while (!val) {
    p = (char*) &val;
    r = sizeof(val);
    while (r > 0) {
      n = read(urandom_fd, p, r);
      if (n < 0) {
        err("read from /dev/urandom failed: %s", os_ErrorMsg());
        return (unsigned) random();
      }
      if (!n) {
        err("EOF on /dev/urandom???");
        return (unsigned) random();
      }
      p += n;
      r -= n;
    }
  }

  return val;
}

unsigned long long
random_u64(void)
{
  unsigned long long val = 0;
  int n, r;
  char *p;

  ASSERT(urandom_fd >= 0);

  while (!val) {
    p = (char*) &val;
    r = sizeof(val);
    while (r > 0) {
      n = read(urandom_fd, p, r);
      if (n < 0) {
        err("read from /dev/urandom failed: %s", os_ErrorMsg());
        return (unsigned long long) random();
      }
      if (!n) {
        err("EOF on /dev/urandom???");
        return (unsigned long long) random();
      }
      p += n;
      r -= n;
    }
  }

  return val;
}

void
random_bytes(unsigned char *buf, int count)
{
  int r, n;
  unsigned char *p;

  ASSERT(urandom_fd >= 0);

  // generate the needed number of bytes
  r = count;
  p = buf;
  while (r > 0) {
    n = read(urandom_fd, p, r);
    if (n < 0) {
      err("read from /dev/urandom failed: %s", os_ErrorMsg());
      goto fail;
    }
    if (!n) {
      err("EOF on /dev/urandom???");
      goto fail;
    }
    p += n;
    r -= n;
  }
  return;

 fail:
  for (; r; r--, p++)
    *p = (unsigned char) random();
}

/*
 * Local variables:
 *  compile-command: "make"
 * End:
 */
