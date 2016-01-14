/* -*- mode: c -*- */

/* Copyright (C) 2005-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ej_process.h"

unsigned char *
read_process_output(const unsigned char *cmd,
                    const unsigned char *workdir,
                    int max_ok_code,
                    int redirect_stderr)
{
  // FIXME: stub
  return 0;
}

int
ejudge_timed_write(
        const unsigned char *log,
        int fd,
        const void *data,
        ssize_t size,
        int timeout_ms)
{
  fprintf(stderr, "%s: not implemented\n", __FUNCTION__);
  return -1;
}

int
ejudge_timed_fdgets(
        const unsigned char *log,
        int fd,
        unsigned char *buf,
        ssize_t size,
        int timeout_ms)
{
  fprintf(stderr, "%s: not implemented\n", __FUNCTION__);
  return -1;
}
