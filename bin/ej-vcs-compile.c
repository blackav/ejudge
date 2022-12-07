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

#include "ejudge/config.h"
#include "ejudge/version.h"

#include "ejudge/base64.h"

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

static __attribute__((noreturn, format(printf, 1, 2))) void
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

const char separator[] = "-----BEGIN CONTENT-----";

static void
do_unpack(int argc, char *argv[])
{
    signal(SIGPIPE, SIG_IGN);

    int fd = open(argv[1], O_CLOEXEC | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK | O_RDONLY, 0);
    if (fd < 0) {
        die("open failed: %s", strerror(errno));
    }

    struct stat stb;
    if (fstat(fd, &stb) < 0) {
        die("fstat failed: %s", strerror(errno));
    }
    if (!S_ISREG(stb.st_mode)) {
        die("source file is not regular");
    }
    if (stb.st_size <= 0) {
        die("source file is empty");
    }
    size_t sz = stb.st_size;
    if (sz != stb.st_size) {
        die("invalid size");
    }
    unsigned char *txt = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
    if (txt == MAP_FAILED) {
        die("mmap failed: %s", strerror(errno));
    }
    unsigned char *endptr = txt + sz;
    unsigned char *body = strstr(txt, separator);
    if (!body) {
        die("file contains no content");
    }
    body += sizeof(separator) - 1;

    unsigned char *outbuf = malloc(sz + 1);
    int outsize = base64_decode(body, endptr - body, outbuf, NULL);
    unsigned char *outptr = outbuf;
    while (outsize > 0) {
        int w = write(STDOUT_FILENO, outptr, outsize);
        if (w < 0) {
            die("write error: %s", strerror(errno));
        }
        outptr += w;
        outsize -= w;
    }
    exit(0);
}

/*
Arguments:
 [1] - source file
 [2] - destination file
 [3] - programming language
 [4] - build command
 */
int main(int argc, char *argv[])
{
    char *s = strrchr(argv[0], '/');
    if (s) {
        program_name = s + 1;
    } else {
        program_name = argv[0];
    }

    if (argc < 3) {
        die("too few arguments");
    }
    const unsigned char *lang_name = "";
    if (argc >= 4) {
        lang_name = argv[3];
    }
    const unsigned char *build_command = "";
    if (argc >= 5) {
        build_command = argv[4];
    }

    int pfd1[2];
    if (pipe2(pfd1, O_CLOEXEC) < 0) {
        die("pipe failed: %s", strerror(errno));
    }
    int pid1 = fork();
    if (pid1 < 0) {
        die("fork failed: %s", strerror(errno));
    }
    if (!pid1) {
        close(pfd1[0]);
        dup2(pfd1[1], 1); close(pfd1[1]);
        do_unpack(argc, argv);
        _exit(0);
    }
    close(pfd1[1]);
    int pid2 = fork();
    if (pid2 < 0) {
        kill(pid1, SIGKILL);
        die("fork failed: %s", strerror(errno));
    }
    if (!pid2) {
        dup2(pfd1[0], 0);
        execlp("tar", "tar", "xfj", "-", NULL);
        die("tar failed: %s", strerror(errno));
        _exit(1);
    }
    close(pfd1[0]);
    int stat1 = 0, stat2 = 0;
    waitpid(pid1, &stat1, 0);
    waitpid(pid2, &stat2, 0);
    int retval = 0;
    if (!WIFEXITED(stat1) || WEXITSTATUS(stat1)) {
        fprintf(stderr, "%s: unpack process failed\n", program_name);
        retval = 1;
    }
    if (!WIFEXITED(stat1) || WEXITSTATUS(stat1)) {
        fprintf(stderr, "%s: tar process failed\n", program_name);
        retval = 1;
    }
    if (retval != 0) {
        return retval;
    }

    // start build script: build language destdir destname
    if (!build_command || !*build_command) {
        build_command = "./build";
    }

    char *curdir = get_current_dir_name();

    if (chdir("source") < 0) {
        die("cannot change directory to source");
    }

    execlp(build_command, build_command, lang_name, curdir, argv[2], NULL);
    die("failed to execute build command %s: %s", build_command, strerror(errno));
}
