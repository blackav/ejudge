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

/*
 * Environment to handle:
 *   PGHOST
 *   PGPORT
 *   PG_BASE_PREFIX
 *   PG_ROOT_USER
 *   PG_ROOT_PASSWORD
 *   PG_USER_PREFIX
 *   PG_PASSWORDS
 *   EJUDGE_SUPER_RUN_SERIAL
 *   EJUDGE_TEST_RANDOM_VALUE
 */

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
        fprintf(stderr, "%s: %s\n", program_name, buf);
    } else {
        fprintf(stderr, "%s\n", buf);
    }

    exit(1);
}

static int
drop_database(
        const char *host,
        const char *port,
        const char *user,
        const char *password,
        const char *database)
{
    int pid = fork();
    if (pid < 0) {
        fprintf(stderr, "%s: fork failed: %s\n", program_name,
                strerror(errno));
        return -1;
    }
    if (!pid) {
        const char *args[64];
        int i = 0;

        setenv("PGPASSWORD", password, 1);
        args[i++] = "dropdb";
        args[i++] = "-f";
        args[i++] = "--if-exists";
        args[i++] = "-h";
        args[i++] = host;
        args[i++] = "-p";
        args[i++] = port;
        args[i++] = "-U";
        args[i++] = user;
        args[i++] = "-w";
        args[i++] = database;
        args[i] = NULL;

        execvp(args[0], (char**) args);
        fprintf(stderr, "%s: exec failed: %s\n", program_name,
                strerror(errno));
        _exit(1);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "%s: dropdb terminated with signal %d\n",
                program_name, WTERMSIG(status));
        return 256 + WTERMSIG(status);
    }
    if (!WIFEXITED(status)) {
        abort();
    }
    if (WEXITSTATUS(status) != 0) {
        fprintf(stderr, "%s: dropdb exited with status %d\n",
                program_name, WEXITSTATUS(status));
        return WEXITSTATUS(status);
    }
    return 0;
}

int
main(int argc, char *argv[])
{
    const char *s = strrchr(argv[0], '/');
    if (s) {
        program_name = s + 1;
    } else {
        program_name = argv[0];
    }

/*
 * Environment to handle:
 *   PGHOST
 *   PGPORT
 *   PG_BASE_PREFIX
 *   PG_ROOT_USER
 *   PG_ROOT_PASSWORD
 *   EJUDGE_TEST_RANDOM_VALUE
 */
    const char *host = getenv("PGHOST");
    if (!host || !*host) {
        die("PGHOST env var is not set");
    }
    unsetenv("PGHOST");
    const char *port = getenv("PGPORT");
    if (!port || !*port) {
        die("PGPORT env var is not set");
    }
    unsetenv("PGPORT");
    s = getenv("EJUDGE_TEST_RANDOM_VALUE");
    if (!s || !*s) {
        die("EJUDGE_TEST_RANDOM_VALUE env var is not set");
    }
    unsetenv("EJUDGE_TEST_RANDOM_VALUE");
    unsigned long long random_value = 0;
    {
        char *eptr = NULL;
        errno = 0;
        random_value = strtoull(s, &eptr, 16);
        if (errno || *eptr || eptr == s) {
            die("invalid EJUDGE_TEST_RANDOM_VALUE: %s", s);
        }
    }
    const char *base_prefix = getenv("PG_BASE_PREFIX");
    if (!base_prefix || !*base_prefix) {
        die("PG_BASE_PREFIX env var is not set");
    }
    unsetenv("PG_BASE_PREFIX");
    const char *root_user = getenv("PG_ROOT_USER");
    if (!root_user || !*root_user) {
        die("PG_ROOT_USER env var is not set");
    }
    unsetenv("PG_ROOT_USER");
    const char *root_password = getenv("PG_ROOT_PASSWORD");
    if (!root_password || !*root_password) {
        die("PG_ROOT_PASSWORD env var is not set");
    }
    unsetenv("PG_ROOT_PASSWORD");

    unsetenv("PG_USER_PREFIX");
    unsetenv("PG_PASSWORDS");
    unsetenv("EJUDGE_SUPER_RUN_SERIAL");

    unsigned r32 = (unsigned) ((random_value >> 32) ^ random_value);
    char database[128];
    int r = snprintf(database, sizeof(database), "%s%x", base_prefix, r32);
    if (r >= (int) sizeof(database)) {
        die("PG_BASE_PREFIX is too long");
    }

    r = drop_database(host, port, root_user, root_password, database);
    if (r < 0) {
        die("failed to run dropdb");
    }
    if (r) {
        die("dropdb failed");
    }
    return 0;
}
