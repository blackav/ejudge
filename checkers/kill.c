/* -*- mode: c -*- */

/* Copyright (C) 2017 Alexander Chernov <cher@ejudge.ru> */

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

#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define EJUDGE_KILL_HELPER "/opt/ejudge/libexec/ejudge/bin/ej-suid-kill"

static void
invoke_kill_helper(int pid, int signal)
{
    char pid_buf[64];
    char signal_buf[64];
    char *helper_args[] = { EJUDGE_KILL_HELPER, pid_buf, signal_buf, NULL };
    sigset_t empty;

    sigemptyset(&empty);
    sigprocmask(SIG_SETMASK, &empty, NULL);
    snprintf(pid_buf, sizeof(pid_buf), "%d", pid);
    snprintf(signal_buf, sizeof(signal_buf), "%d", signal);
    execv(EJUDGE_KILL_HELPER, helper_args);
    _exit(1);
}

int
checker_kill(int pid, int signal)
{
    static int suid_flag = -1;
    if (suid_flag < 0) {
        suid_flag = getenv("EJUDGE_SUID_RUN") != NULL;
    }
    if (suid_flag <= 0) {
        return kill(pid, signal);
    }

    int helper_pid = fork();
    if (helper_pid < 0) {
        return -1;
    } else if (!helper_pid) {
        invoke_kill_helper(pid, signal);
        _exit(1);
    }

    // block any signal while waiting for helper program
    sigset_t cur, temp;
    sigfillset(&temp);
    sigprocmask(SIG_SETMASK, &temp, &cur);
    int status = 0;
    waitpid(helper_pid, &status, 0);
    sigprocmask(SIG_SETMASK, &cur, NULL);
    return (WIFEXITED(status) && !WEXITSTATUS(status))?0:-1;
}
