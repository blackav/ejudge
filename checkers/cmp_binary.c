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

#define NEED_CORR 1
#define NEED_INFO 1
#define NEED_TGZ  1
#include "checker.h"

#include "l10n_impl.h"

#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>

int checker_main(int argc, char **argv)
{
    if (argc != 7) {
        fatal_CF("wrong number of arguments: %d instead of 7", argc);
    }

    checker_l10n_prepare();

    const testinfo_t *pti = get_test_info_ptr();
    if (!pti) {
        fatal_CF("invalid testinfo");
    }

    const char *s = getenv("EJ_EXPECT_ARGS");
    if (s && *s) {
        errno = 0;
        char *eptr = NULL;
        long v = strtol(s, &eptr, 10);
        if (errno || *eptr || s == eptr || (int) v != v || v <= 0) {
            fatal_CF("EJ_EXPECT_ARGS environment value '%s' is invalid", s);
        }
        if (pti->cmd.u != v) {
            fatal_CF("wrong argc for tested program: expected: %d, actual %d", (int) v + 1, (int) pti->cmd.u);
        }
    }

    s = getenv("EJ_OUTPUT_ARG");
    if (!s || !*s) {
        fatal_CF("EJ_OUTPUT_ARG environment is not set");
    }
    int output_arg = 0;
    {
        errno = 0;
        char *eptr = NULL;
        long v = strtol(s, &eptr, 10);
        if (errno || *eptr || s == eptr || (int) v != v || v < 0) {
            fatal_CF("EJ_OUTPUT_ARG environment value '%s' is invalid", s);
        }
        output_arg = v;
        if (v <= 0 || v > pti->cmd.u) {
            fatal_CF("EJ_OUTPUT_ARG environment value %d is out of range [1;%d]", output_arg, (int) pti->cmd.u);
        }
    }

    int expect_mode = -1;
    s = getenv("EJ_EXPECT_MODE");
    if (s && *s) {
        errno = 0;
        char *eptr = NULL;
        long v = strtol(s, &eptr, 8);
        if (errno || *eptr || s == eptr || v < 0 || v > 07777) {
            fatal_CF("EJ_EXPECT_MODE environment value '%s' is invalid", s); 
        }
        expect_mode = v;
    }
    int expect_1_bits = -1;
    s = getenv("EJ_EXPECT_1_BITS");
    if (s && *s) {
        errno = 0;
        char *eptr = NULL;
        long v = strtol(s, &eptr, 8);
        if (errno || *eptr || s == eptr || v < 0 || v > 07777) {
            fatal_CF("EJ_EXPECT_1_BITS environment value '%s' is invalid", s); 
        }
        expect_1_bits = v;
    }
    int expect_0_bits = -1;
    s = getenv("EJ_EXPECT_0_BITS");
    if (s && *s) {
        errno = 0;
        char *eptr = NULL;
        long v = strtol(s, &eptr, 8);
        if (errno || *eptr || s == eptr || v < 0 || v > 07777) {
            fatal_CF("EJ_EXPECT_0_BITS environment value '%s' is invalid", s); 
        }
        expect_0_bits = v;
    }

    char uopath[PATH_MAX];
    const char *uoname = pti->cmd.v[output_arg - 1];
    if (snprintf(uopath, sizeof(uopath), "%s/%s", argv[6], uoname) >= (int) sizeof(uopath)) {
        fatal_CF("path to output file is too long");
    }

    int uofd = open(uopath, O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (uofd < 0) {
        fatal_PE("cannot open program output file '%s': %s", uoname, strerror(errno));
    }
    struct stat stb;
    if (fstat(uofd, &stb) < 0) {
        fatal_CF("fstat failed: %s", strerror(errno));
    }
    if (!S_ISREG(stb.st_mode)) {
        fatal_PE("program output file '%s' is not regular", uoname);
    }
    int actual_mode = expect_mode & 07777;
    if (expect_mode >= 0 && expect_mode != actual_mode) {
        fatal_PE("wrong permissions on output file '%s': expected: %04o, actual: %04o", uoname, expect_mode, actual_mode);
    }
    if (expect_0_bits >= 0 && (actual_mode & expect_0_bits) != 0) {
        fatal_PE("wrong permissions on output file '%s': expected 0 bits: %04o, actual: %04o", uoname, expect_0_bits, actual_mode);
    }
    if (expect_1_bits >= 0 && (actual_mode & expect_1_bits) != expect_1_bits) {
        fatal_PE("wrong permissions on output file '%s': expected 1 bits: %04o, actual: %04o", uoname, expect_1_bits, actual_mode);
    }

    char *cpath = argv[3];
    int cfd = open(cpath, O_RDONLY | O_NOCTTY | O_NONBLOCK | O_CLOEXEC, 0);
    if (cfd < 0) {
        fatal_CF("failed to open answer file '%s': %s", cpath, strerror(errno));
    }
    struct stat cstb;
    if (fstat(cfd, &cstb) < 0) {
        fatal_CF("fstat failed: %s", strerror(errno));
    }
    if (!S_ISREG(cstb.st_mode)) {
        fatal_CF("answer file '%s' is not regular", cpath);
    }

    if (cstb.st_size != stb.st_size) {
        fatal_WA("wrong output file length: expected: %lld, actual: %lld", (long long) cstb.st_size, (long long) stb.st_size);
    }

    if (stb.st_size == 0) {
        checker_OK();
        return 0;
    }

    size_t size = stb.st_size;
    if (size != stb.st_size) {
        fatal_CF("output file is too big: %lld", (long long) stb.st_size);
    }

    const uint8_t *omem = mmap(NULL, size, PROT_READ, MAP_PRIVATE, uofd, 0);
    if (omem == MAP_FAILED) {
        fatal_CF("mmap of output file '%s' failed: %s", uoname, strerror(errno));
    }

    const uint8_t *cmem = mmap(NULL, size, PROT_READ, MAP_PRIVATE, cfd, 0);
    if (cmem == MAP_FAILED) {
        fatal_CF("mmap of answer file failed: %s", strerror(errno));
    }

    if (memcmp(omem, cmem, size) != 0){
        fatal_WA("wrong output");
    }

    checker_OK();
}
