/* $Id$ */

extern "C" {
#include "config.h"
#include "ej_types.h"
#include "ej_limits.h"
#include "version.h"

#include "ejudge_cfg.h"
#include "contests.h"
#include "runlog.h"
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <string>

#define USTR(c) ((unsigned char*) c)

static char *program_name = nullptr;
static struct ejudge_cfg *config = nullptr;
static int contest_id = 0;
static const struct contest_desc *cnts = nullptr;
static runlog_state_t runlog = nullptr;

static void
die(const char *format, ...)
    __attribute__((format(printf, 1, 2), noreturn));
static void
die(const char *format, ...)
{
    va_list args;
    char buf[1024];

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    fprintf(stderr, "%s: %s\n", program_name, buf);
    exit(1);
}

int
main(int argc, char *argv[])
{
    program_name = argv[0];

    if (argc != 2) die("wrong number of arguments");

    config = ejudge_cfg_parse(EJUDGE_XML_PATH);
    if (!config) die("invalid configuration file");
    contests_set_directory(config->contests_dir);

    try {
        contest_id = std::stoi(argv[1]);
    } catch (...) {
        die("invalid contest_id");
    }
    if (contests_get(contest_id, &cnts) < 0 || !cnts) die("invalid contest_id");

    runlog = run_init(0);
    if (!runlog) die("failed to initialize runlog");

    if (run_open(runlog, config, cnts, 0, USTR("mysql"), 0, 0, 0, 0) < 0)
        die("cannot open the runlog");

    return 0;
}

/*
 * Local variables:
 *  compile-command: "g++ -Wall -g -std=gnu++11 -L. fix-runs.cpp -ofix-runs -lcommon -luserlist_clnt -lplatform -lcommon -lexpat -lz -lzip -luuid -ldl"
 *  c-basic-offset: 4
 * End:
 */
