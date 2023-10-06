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
#include <stdarg.h>

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

static int
run_psql(
        const char *host,
        const char *port,
        const char *user,
        const char *password,
        const char *database,
        int ignore_stdout,
        int html_output_flag,
        int tuples_only_flag,
        ...)
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
        args[i++] = "psql";
        args[i++] = "-h";
        args[i++] = host;
        args[i++] = "-p";
        args[i++] = port;
        args[i++] = "-U";
        args[i++] = user;
        if (database) {
            args[i++] = "-d";
            args[i++] = database;
        }
        args[i++] = "-X";
        args[i++] = "-w";
        if (html_output_flag > 0) {
            args[i++] = "--html";
        } else {
            args[i++] = "--csv";
        }
        if (tuples_only_flag > 0) {
            args[i++] = "-t";
        }
        args[i++] = "-q";

        va_list lst;
        va_start(lst, tuples_only_flag);
        const char *ptr = NULL;
        while ((ptr = va_arg(lst, const char *))) {
            args[i++] = ptr;
        }
        va_end(lst);
        args[i] = NULL;

        if (ignore_stdout) {
            int fd = open("/dev/null", O_WRONLY | O_CLOEXEC, 0);
            if (fd < 0) {
                _exit(1);
            }
            dup2(fd, 1);
        }

        execvp(args[0], (char**) args);
        fprintf(stderr, "%s: exec failed: %s\n", program_name,
                strerror(errno));
        _exit(1);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "%s: psql terminated with signal %d\n",
                program_name, WTERMSIG(status));
        return 256 + WTERMSIG(status);
    }
    if (!WIFEXITED(status)) {
        abort();
    }
    if (WEXITSTATUS(status) != 0) {
        fprintf(stderr, "%s: psql exited with status %d\n",
                program_name, WEXITSTATUS(status));
        return WEXITSTATUS(status);
    }
    return 0;
}

static int
create_database(
        const char *host,
        const char *port,
        const char *root_user,
        const char *root_password,
        const char *database,
        const char *other_user)
{
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "CREATE DATABASE %s", database);
    if (other_user) {
        fprintf(cmd_f, " OWNER %s", other_user);
    }
    fprintf(cmd_f, ";");
    fclose(cmd_f); cmd_f = NULL;

    int r = run_psql(host, port, root_user, root_password, NULL,
                     1 /* ignore_stdout */,
                     0 /* html_output_flag */,
                     0 /* tuples_only_flag */,
                     "-c", cmd_s, NULL);
    free(cmd_s); cmd_s = NULL;

    return r;
}

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
 *   EJUDGE_HTML_OUTPUT
 *   EJUDGE_TUPLES_ONLY
 */
int
main(int argc, char *argv[])
{
    const char *s = strrchr(argv[0], '/');
    if (s) {
        program_name = s + 1;
    } else {
        program_name = argv[0];
    }

    if (argc != 2) {
        die("wrong number of arguments");
    }
    const char *exec_file = argv[1];

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
    const char *user_prefix = getenv("PG_USER_PREFIX");
    if (user_prefix && !*user_prefix) {
        user_prefix = NULL;
    }
    unsetenv("PG_USER_PREFIX");

    int run_serial = 0;
    if (user_prefix) {
        s = getenv("EJUDGE_SUPER_RUN_SERIAL");
        if (s && *s) {
            char *eptr = NULL;
            errno = 0;
            long v = strtol(s, &eptr, 10);
            if (errno || *eptr || s == eptr || v < 0 || v > 100) {
                die("invalid EJUDGE_SUPER_RUN_SERIAL: %s", s);
            }
            run_serial = (int) v;
        }
    }
    unsetenv("EJUDGE_SUPER_RUN_SERIAL");

    char *user_password = NULL;
    if (user_prefix) {
        s = getenv("PG_PASSWORDS");
        if (!s || !*s) {
            die("PG_PASSWORDS env var is not set");
        }
        const char *cur = s;
        const char *next = strchr(cur, ':');
        for (int i = 0; i < run_serial; ++i) {
            if (!next) {
                die("PG_PASSWORDS does not contain password for serial %d",
                    run_serial);
            }
            cur = next + 1;
            next = strchr(cur, ':');
        }
        user_password = strdup(cur);
        if (next) {
            user_password[next - cur] = 0;
        }
    }
    unsetenv("PG_PASSWORDS");

    unsigned r32 = (unsigned) ((random_value >> 32) ^ random_value);
    char database[128];
    int r = snprintf(database, sizeof(database), "%s%x", base_prefix, r32);
    if (r >= (int) sizeof(database)) {
        die("PG_BASE_PREFIX is too long");
    }

    char *user_name = NULL;
    if (user_prefix) {
        if (!run_serial) {
            user_name = strdup(user_prefix);
        } else {
            __attribute__((unused)) int _;
            _ = asprintf(&user_name, "%s%d", user_prefix, run_serial);
        }
    }

    const char *input_file = getenv("INPUT_FILE");
    if (input_file && !*input_file) {
        input_file = NULL;
    }
    if (!input_file) {
        input_file = "input";
    }

    r = create_database(host, port, root_user, root_password,
                        database, user_name);
    if (r != 0) {
        die("database creation failed");
    }

    int html_output_flag = -1;
    if ((s = getenv("EJUDGE_HTML_OUTPUT")) && *s) {
        errno = 0;
        char *eptr = NULL;
        long v = strtol(s, &eptr, 10);
        if (errno || !eptr || eptr == s || (int) v != v || v < 0) {
            die("invalid EJUDGE_HTML_OUTPUT value: %s", s);
        }
        html_output_flag = v;
    }

    int tuples_only_flag = -1;
    if ((s = getenv("EJUDGE_TUPLES_ONLY")) && *s) {
        errno = 0;
        char *eptr = NULL;
        long v = strtol(s, &eptr, 10);
        if (errno || !eptr || eptr == s || (int) v != v || v < 0) {
            die("invalid EJUDGE_TUPLES_ONLY value: %s", s);
        }
        tuples_only_flag = v;
    }

    const char *exec_user = root_user;
    const char *exec_password = root_password;
    if (user_name) {
        exec_user = user_name;
        exec_password = user_password;
    }

    r = run_psql(host, port, exec_user, exec_password, database,
                 0 /* ignore_stdout */,
                 html_output_flag,
                 tuples_only_flag,
                 "-f", input_file, "-f", exec_file, NULL);
    if (r != 0) {
        die("postgres execution failed");
    }

    return 0;
}
