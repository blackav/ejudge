/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2015-2020 Alexander Chernov <cher@ejudge.ru> */

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

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>

#include "config.h"

#if defined EJUDGE_PRIMARY_USER
#define PRIMARY_USER EJUDGE_PRIMARY_USER
#else
#define PRIMARY_USER "ejudge"
#endif

#if defined EJUDGE_EXEC_USER
#define EXEC_USER EJUDGE_EXEC_USER
#define EXEC_GROUP EJUDGE_EXEC_USER
#else
#define EXEC_USER "ejexec"
#define EXEC_GROUP "ejexec"
#endif

int
main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "%s: wrong number of arguments\n", argv[0]);
        abort();
    }

    int primary_uid = -1;
    int exec_uid = -1;
    int exec_gid = -1;

    {
        struct passwd *pwd = getpwnam(EXEC_USER);
        struct group *grp = getgrnam(EXEC_GROUP);
        if (!pwd) {
            fprintf(stderr, "%s: user '%s' does not exist\n", argv[0], EXEC_USER);
            abort();
        }
        exec_uid = pwd->pw_uid;
        if (exec_uid <= 0) {
            fprintf(stderr, "%s: user '%s' has uid %d\n", argv[0], EXEC_USER, exec_uid);
            abort();
        }
        if (!grp) {
            fprintf(stderr, "%s: group '%s' does not exist\n", argv[0], EXEC_GROUP);
            abort();
        }
        exec_gid = grp->gr_gid;
        if (exec_gid <= 0) {
            fprintf(stderr, "%s: group '%s' has gid %d\n", argv[0], EXEC_GROUP, exec_gid);
            abort();
        }
        endpwent();
        endgrent();
    }

    {
        struct passwd *pwd = getpwnam(PRIMARY_USER);
        if (!pwd) {
            fprintf(stderr, "%s: user '%s' does not exist\n", argv[0], PRIMARY_USER);
            abort();
        }
        primary_uid = pwd->pw_uid;
        if (primary_uid <= 0) {
            fprintf(stderr, "%s: user '%s' has uid %d\n", argv[0], PRIMARY_USER, primary_uid);
            abort();
        }
        if (getuid() != primary_uid) {
            fprintf(stderr, "%s: only user '%s' can run this program\n", argv[0], PRIMARY_USER);
            abort();
        }
        endpwent();
    }

    errno = 0;
    char *eptr = NULL;
    int dst_pid = strtol(argv[1], &eptr, 10);
    enum { PID_MAX_LIMIT = 1 << 22 };
    if (errno || *eptr || dst_pid < -PID_MAX_LIMIT || dst_pid > PID_MAX_LIMIT || dst_pid == 0) {
        fprintf(stderr, "%s: invalid pid '%s'\n", argv[0], argv[1]);
        abort();
    }
    int kill_sig = strtol(argv[2], &eptr, 10);
    if (errno || *eptr || kill_sig < 0 || kill_sig > 64) {
        fprintf(stderr, "%s: invalid signal '%s'\n", argv[0], argv[1]);
        abort();
    }
    if (dst_pid == -1) {
        // kill all mode
        // fork a subprocess, which changes the user and kill everything of this user (including the forked process)
        int subpid = fork();
        if (subpid < 0) {
            fprintf(stderr, "%s: failed to create a new process: %s\n", argv[0], strerror(errno));
            return 1;
        }
        if (!subpid) {
            if (setgid(exec_gid) < 0) {
                fprintf(stderr, "%s: setgid failed\n", argv[0]);
            } else if (setuid(exec_uid) < 0) {
                fprintf(stderr, "%s: setuid failed\n", argv[0]);
            } else {
                kill(dst_pid, kill_sig);
            }
            _exit(0);
        }
        waitpid(subpid, NULL, 0);
        return 0;
    } else {
        if (setgid(exec_gid) < 0) {
            fprintf(stderr, "%s: setgid failed\n", argv[0]);
            abort();
        }
        if (setuid(exec_uid) < 0) {
            fprintf(stderr, "%s: setuid failed\n", argv[0]);
            abort();
        }
        return kill(dst_pid, kill_sig) < 0;
    }
}
