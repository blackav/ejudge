/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2012-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/pollfds.h"

#include "ejudge/xalloc.h"

#include <poll.h>
#include <string.h>

struct pollextra
{
  pollfds_callback_t callback;
  void *user;
};

struct pollfds
{
  int reserved;
  int size;

  struct pollfd *fds;
  struct pollextra *extras;
};

enum { INIT_SIZE = 512 };

pollfds_t *
pollfds_create(void)
{
  pollfds_t *pfd = NULL;

  XCALLOC(pfd, 1);
  pfd->reserved = INIT_SIZE;
  XCALLOC(pfd->fds, pfd->reserved);
  XCALLOC(pfd->extras, pfd->reserved);
  return pfd;
}

pollfds_t *
pollfds_free(pollfds_t *pfd)
{
  if (pfd) {
    xfree(pfd->fds);
    xfree(pfd->extras);
    memset(pfd, 0, sizeof(*pfd));
    xfree(pfd);
  }
  return NULL;
}

void
pollfds_clear(pollfds_t *pl)
{
  if (pl && pl->reserved > 0) {
    memset(pl->fds, 0, sizeof(pl->fds[0]) * pl->reserved);
    memset(pl->extras, 0, sizeof(pl->extras[0]) * pl->reserved);
    pl->size = 0;
  }
}

void
pollfds_add(
        pollfds_t *pl,
        int fd,
        int events,
        pollfds_callback_t callback,
        void *user)
{
  if (!pl) return;

  if (pl->size == pl->reserved) {
    pl->reserved *= 2;
    XREALLOC(pl->fds, pl->reserved);
    XREALLOC(pl->extras, pl->reserved);
  }

  memset(&pl->fds[pl->size], 0, sizeof(pl->fds[0]));
  pl->fds[pl->size].fd = fd;
  pl->fds[pl->size].events = events;
  pl->extras[pl->size].callback = callback;
  pl->extras[pl->size].user = user;
  ++pl->size;
}

int
pollfds_poll(
        pollfds_t *pl,
        long timeout_ms,
        const void *mask)
{
  struct timespec ts, *pts = &ts;

  if (timeout_ms < 0) {
    pts = NULL;
  } else {
    ts.tv_sec = timeout_ms / 1000;
    ts.tv_nsec = (timeout_ms % 1000) * 1000000;
  }
  return ppoll(pl->fds, pl->size, pts, (const sigset_t*) mask);
}

void
pollfds_call_handlers(
        pollfds_t *pl,
        void *context)
{
  if (!pl) return;

  for (int i = 0; i < pl->size; ++i) {
    if (pl->fds[i].revents) {
      pl->extras[i].callback(context, &pl->fds[i], pl->extras[i].user);
    }
  }
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
