/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2022 Alexander Chernov <cher@ejudge.ru> */

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

#include "checker_internal.h"

#include <unistd.h>
#include <errno.h>

int
checker_kill_2(int socket_fd, int signal)
{
    unsigned cmd = 0xe0000000 | (1 << 8) | signal;
    int r = write(socket_fd, &cmd, sizeof(cmd));
    if (r < 0) {
        fprintf(stderr, "sending cmd to control_fd: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}
