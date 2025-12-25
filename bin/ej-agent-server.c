/* -*- mode: c -*- */

/* Copyright (C) 2025 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/agent_server.h"
#include "ejudge/version.h"
#include "ejudge/osdeps.h"
#include "ejudge/xalloc.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static const char help_text[] =
"  --version - print the version and exit\n"
"  --help    - print this help and exit\n"
"  -D        - daemon mode\n"
"  -u USER   - switch to USER\n"
"  -g GROUP  - switch to GROUP\n"
"  -C DIR    - change directory to DIR\n";

int main(int argc, char *argv[])
{
    AgentServerParams params = {};
    int i = 1;
    params.process_name = os_GetLastname(argv[0]);
    params.compile_version = compile_version;
    params.compile_date = compile_date;

    while (i < argc) {
        if (!strcmp(argv[i], "-D")) {
            params.daemon_mode = 1;
            ++i;
        } else if (!strcmp(argv[i], "-u")) {
            if (++i >= argc) {
                fprintf(stderr, "%s: option '%s' missing parameters\n", params.process_name, argv[i-1]);
                exit(1);
            }
            params.user = xstrdup(argv[i++]);
        } else if (!strcmp(argv[i], "-g")) {
            if (++i >= argc) {
                fprintf(stderr, "%s: option '%s' missing parameters\n", params.process_name, argv[i-1]);
                exit(1);
            }
            params.group = xstrdup(argv[i++]);
        } else if (!strcmp(argv[i], "-C")) {
            if (++i >= argc) {
                fprintf(stderr, "%s: option '%s' missing parameters\n", params.process_name, argv[i-1]);
                exit(1);
            }
            params.workdir = xstrdup(argv[i++]);
        } else if (!strcmp(argv[i], "--version")) {
            printf("%s %s, compiled %s\n", params.process_name, compile_version, compile_date);
            exit(0);
        } else if (!strcmp(argv[i], "--help")) {
            printf("Usage: %s [ OPTS ] [config-file]\n", params.process_name);
            printf("%s", help_text);
            exit(0);
        } else if (!strcmp(argv[i], "--")) {
            ++i;
            break;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "%s: invalid option '%s'\n", params.process_name, argv[i]);
            exit(1);
        } else {
            break;
        }
    }
    if (i < argc) {
        params.config_file = xstrdup(argv[i]);
        ++i;
    }
    if (i < argc) {
        fprintf(stderr, "%s: extra parameters in the command line\n", params.process_name);
        exit(1);
    }

    return agent_server_start(&params) < 0;
}
