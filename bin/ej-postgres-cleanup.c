/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/version.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <signal.h>

static const char *program_name;

static __attribute__((unused, noreturn, format(printf, 1, 2))) void
die(const char *format, ...)
{
    va_list args;
    char buf[1024];

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    if (program_name) {
        fprintf(stderr, "%s:%s\n", program_name, buf);
    } else {
        fprintf(stderr, "%s\n", buf);
    }

    exit(1);
}

int
main(int argc, char *argv[])
{
    char *s = strrchr(argv[0], '/');
    if (s) {
        program_name = s + 1;
    } else {
        program_name = argv[0];
    }
}
