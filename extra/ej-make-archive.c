/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2011 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>

#define MAX_ALLOWED_TEST_NUMBER 999
#define TAR_PROGRAM "/bin/tar"

const unsigned char *progname = NULL;
const unsigned char *tgzdir_pattern = NULL;
const unsigned char *tgz_pattern = NULL;
const unsigned char *tgzdir_name = NULL;

static void
fatal(const char *format, ...)
    __attribute__((noreturn, format(printf, 1, 2)));
static void
fatal(const char *format, ...)
{
    unsigned char buf[512];
    va_list args;

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    fprintf(stderr, "%s: %s\n", progname, buf);
    exit(2);
}

static void
report_version(void)
{
    exit(0);
}

static const unsigned char help_str[] =
"--version                print the version and exit\n"
"--help                   print this help and exit\n"
"--                       stop option processing\n"
"--tgzdir-pattern=PATTERN printf-style pattern for master working directory\n"
"--tgz-pattern=PATTERN    printf-style pattern for master directory archive\n"
  ;

static void
report_help(void)
{
  printf("%s usage: ej-make-archive [OPTIONS]... program [ARGUMENTS]...\n", progname);
  fputs(help_str, stdout);
  exit(0);
}

const unsigned char *
check_option(const unsigned char *opt_name, const unsigned char *opt)
{
    int opt_len = strlen(opt_name);
    if (strncmp(opt_name, opt, opt_len) != 0) return NULL;
    if (opt[opt_len] != '=') return NULL;
    return opt + opt_len + 1;
}

static int
handle_options(const unsigned char *opt)
{
    const unsigned char *s;

    if (!strcmp("--version", opt)) {
        report_version();
    } else if (!strcmp("--help", opt)) {
        report_help();
    } else if ((s = check_option("--tgzdir-pattern", opt))) {
        tgzdir_pattern = s;
    } else if ((s = check_option("--tgz-pattern", opt))) {
        tgz_pattern = s;
    } else if (!strcmp("--", opt)) {
        return 1;
    } else if (!strncmp("--", opt, 2)) {
        fatal("invalid option %s", opt);
    } else {
        return 2;
    }
    return 0;
}

int
main(int argc, char *argv[])
{
    int i = 1, r, n;
    unsigned char buf[PATH_MAX];
    unsigned char tgz_name[PATH_MAX];
    char *args[10];

    signal(SIGPIPE, SIG_IGN);

    tgzdir_pattern = getenv("EJ_TGZDIR_PATTERN");
    tgz_pattern = getenv("EJ_TGZ_PATTERN");

    progname = argv[0];
    for (i = 1; i < argc; i++) {
        r = handle_options(argv[i]);
        if (r == 1) i++;
        if (r > 0) break;
    }

    if (i >= argc) fatal("archive name is not specified");

    tgzdir_name = argv[i++];
    if (!tgzdir_name || !tgzdir_name[0]) {
        fatal("master working dir is not specified");
    }
    if (i < argc) {
        fatal("too many arguments");
    }

    if (!tgzdir_pattern || !tgzdir_pattern[0]) {
        tgzdir_pattern = "%03d.dir";
    }
    if (!tgz_pattern || !tgz_pattern[0]) {
        tgz_pattern = "%03d.tgz";
    }

    for (n = 1; n <= MAX_ALLOWED_TEST_NUMBER; ++n) {
        snprintf(buf, sizeof(buf), tgzdir_pattern, n);
        if (!strcmp(buf, tgzdir_name))
            break;
    }
    if (n > MAX_ALLOWED_TEST_NUMBER) {
        fatal("cannot guess test number");
    }

    snprintf(tgz_name, sizeof(tgz_name), tgz_pattern, n);

    args[0] = TAR_PROGRAM;
    args[1] = "cfz";
    args[2] = (char*) tgz_name;
    args[3] = (char*) tgzdir_name;
    args[4] = NULL;
    execv(TAR_PROGRAM, args);

    fatal("cannot execute %s", TAR_PROGRAM);
    return 0;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
