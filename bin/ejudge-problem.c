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

#include "ejudge/ejudge_problem_impl.h"
#include "ejudge/config.h"
#include "ejudge/ej_types.h"
#include "ejudge/version.h"
#include "ejudge/random.h"
#include "ejudge/polygon_xml.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

static const unsigned char *program_name = "";

static void
get_program_name(const unsigned char *arg0)
{
    if (!arg0) {
        fprintf(stderr, "no program name\n");
        exit(1);
    }
    char *s = strrchr(arg0, '/');
    if (s) {
        program_name = s + 1;
    } else {
        program_name = arg0;
    }
}

static __attribute__((noreturn,format(printf, 1, 2))) void
die(const char *format, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    fprintf(stderr, "%s:fatal:%s\n", program_name, buf);
    exit(1);
}

static __attribute__((noreturn)) void
print_version(void)
{
    printf("%s: ejudge version %s compiled %s\n",
            program_name, compile_version, compile_date);
    exit(0);
}

static const unsigned char help_str[] =
"--version                print the version and exit\n"
"--help                   print this help and exit\n"
"--                       stop option processing\n"
"Supported tools:\n"
"print-hash               print SHA256 hash of the source files\n"
"print-makefile           print Makefile (for debugging)\n"
"print-source-files       print the list of the source files\n"
"normalize                normalize the test files\n"
;

static __attribute__((noreturn)) void
print_help(void)
{
    printf("%s usage: ejudge-problem [OPTION]... TOOL ...\n", program_name);
    fputs(help_str, stdout);
    exit(0);
}

struct tool_registry
{
    const unsigned char *name;
    int (*handler)(FILE *log_f, struct problem_state *ps, char *args[]);
};
static const struct tool_registry tools[] =
{
    { "print-hash", ejudge_problem_print_hash },
    { "print-makefile", ejudge_problem_print_makefile },
    { "print-source-files", ejudge_problem_print_source_files },
    { "print-topological", ejudge_problem_print_topological },
    { "print-build-info", ejudge_problem_print_build_info },
    { "normalize", ejudge_problem_normalize_tests },
    { "build", ejudge_problem_build },
    { "clean", ejudge_problem_clean },
    { "zip", ejudge_problem_create_zip_tool }
};

int
main(int argc, char *argv[])
{
    unsigned char *problem_xml_file = NULL;
    unsigned char *p_xml_s = NULL;
    size_t p_xml_z = 0;
    struct ppxml_problem *ppxml = NULL;
    struct problem_state *ps = NULL;
    int (*tool)(FILE *log_f, struct problem_state *ps, char *args[]) = NULL;
    int no_norm_check = 0;

    get_program_name(argv[0]);
    random_init();
    ps = ejudge_problem_new_state();

    int cur_arg = 1;
    while (cur_arg < argc) {
        if (!strcmp(argv[cur_arg], "--version")) {
            print_version();
        } else if (!strcmp(argv[cur_arg], "--help")) {
            print_help();
        } else if (!strcmp(argv[cur_arg], "--")) {
            ++cur_arg;
            break;
        } else if (argv[cur_arg][0] == '-') {
            die("invalid option '%s'", argv[cur_arg]);
        } else {
            break;
        }
    }
    if (cur_arg == argc) {
        die("tool expected");
    }
    for (size_t i = 0; i < sizeof(tools)/sizeof(tools[0]); ++i) {
        if (!strcmp(tools[i].name, argv[cur_arg])) {
            tool = tools[i].handler;
        }
    }
    if (!tool) {
        die("invalid tool '%s'", argv[cur_arg]);
    }
    if (tool == ejudge_problem_normalize_tests) {
        no_norm_check = 1;
    }
    ++cur_arg;

    problem_xml_file = "ejproblem.xml";
    if (ejudge_problem_read_full_file(stderr, problem_xml_file, &p_xml_s, &p_xml_z) < 0) {
        die("failed to read '%s'", problem_xml_file);
    }
    ppxml = ppxml_parse_str(stderr, problem_xml_file, p_xml_s);
    if (!ppxml) {
        die("failed to parse '%s'", problem_xml_file);
    }
    ejudge_problem_set_ppxml(ps, ppxml, problem_xml_file);
    if (ejudge_problem_collect_dependencies(stderr, ps, no_norm_check) < 0) {
        die("failed to collect dependencies");
    }

    int res = tool(stderr, ps, &argv[cur_arg]);

    // TODO: free ps

    return res < 0;
}
