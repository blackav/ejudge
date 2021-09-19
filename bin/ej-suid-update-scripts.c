/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2021 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "config.h"

#if defined EJUDGE_PRIMARY_USER
#define PRIMARY_USER EJUDGE_PRIMARY_USER
#else
#define PRIMARY_USER "ejudge"
#endif

#if defined EJUDGE_PRIMARY_GROUP
#define PRIMARY_GROUP EJUDGE_PRIMARY_GROUP
#else
#define PRIMARY_GROUP PRIMARY_USER
#endif

#ifndef EJUDGE_PREFIX_DIR
#define EJUDGE_PREFIX_DIR "/opt/ejudge"
#endif

enum { MAX_FILE_SIZE = 1024 * 1024 };

static const char *program_name = "";
static int primary_uid = -1;

static void __attribute__((noreturn, unused, format(printf, 1, 2)))
fatal(const char *format, ...)
{
    char buf[4096];
    va_list args;

    va_start(args, format);
    if (vsnprintf(buf, sizeof(buf), format, args) >= sizeof(buf)) {
        buf[sizeof(buf) - 1] = '.';
        buf[sizeof(buf) - 2] = '.';
        buf[sizeof(buf) - 3] = '.';
    }
    va_end(args);

    fprintf(stderr, "%s: %s\n", program_name, buf);
    exit(1);
}

struct Content
{
    char *data;
    size_t size;
};

static struct Content
process_include(const char *path, const char *src_s, size_t src_z)
{
    FILE *src_f = fmemopen((char*) src_s, src_z, "r");
    if (!src_f) {
        fatal("fmemopen failed");
    }

    char *dst_s = NULL;
    size_t dst_z = 0;
    FILE *dst_f = open_memstream(&dst_s, &dst_z);

    char buf[1024];
    while (fgets(buf, sizeof(buf), src_f)) {
        int len = strlen(buf);
        if (len + 1 >= sizeof(buf)) {
            fatal("input line is too long in '%s'", path);
        }
        while (len > 0 && isspace((unsigned char) buf[len - 1])) --len;
        buf[len] = 0;

        if (!strncmp(buf, "#include ", 9)) {
            char *i_name = buf + 9;
            while (isspace((unsigned char) *i_name)) ++i_name;
            for (char *p = i_name; *p; ++p) {
                if ((unsigned char) *p <= ' ' || (unsigned char) *p >= 128
                    || *p == '/' || *p == '\\' || *p == '\'' || *p == '"') {
                    fatal("invalid char in include name '%s'", i_name);
                }
            }

            char i_path[PATH_MAX];
            if (snprintf(i_path, sizeof(i_path), "%s/%s",
                         EJUDGE_LANG_CONFIG_DIR, i_name) >= sizeof(i_path))
                fatal("include file path is too long");

            int i_fd = open(i_path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW, 0);
            if (i_fd < 0) fatal("cannot open '%s': %s", i_path, strerror(errno));
            struct stat i_stb;
            if (fstat(i_fd, &i_stb) < 0) fatal("fstat failed: %s", strerror(errno));
            if (!S_ISREG(i_stb.st_mode)) fatal("%s must be a regular file", i_path);
            if (i_stb.st_size <= 0) fatal("%s must not be empty", i_path);
            if (i_stb.st_size > 1024 * 1024) fatal("%s is too big", i_path);
            size_t i_z = i_stb.st_size;
            char *i_s = mmap(NULL, i_z, PROT_READ, MAP_PRIVATE, i_fd, 0);
            if (i_s == MAP_FAILED) fatal("%s mmap failed: %s", i_path, strerror(errno));
            fwrite(i_s, 1, i_z, dst_f);
            fprintf(dst_f, "\n");
            close(i_fd);
            munmap(i_s, i_z);
        } else {
            fprintf(dst_f, "%s\n", buf);
        }
    }

    fclose(dst_f);
    fclose(src_f);
    return (struct Content) { dst_s, dst_z };
}

static const char * const whitelist[] =
{
    "runmono2", "runjava2", "runvg2", "rundotnet2", NULL
};

static void
process_file(const char *name, int allow_missing)
{
    {
        int i;
        for (i = 0; whitelist[i]; ++i) {
            if (!strcmp(whitelist[i], name))
                break;
        }
        if (!whitelist[i])
            fatal("program name '%s' is invalid", name);
    }

    char src_path[PATH_MAX];
    if (snprintf(src_path, sizeof(src_path), "%s/ejudge/lang/in/%s.in",
                 EJUDGE_LIBEXEC_DIR, name) >= sizeof(src_path)) {
        fatal("path is too long");
    }
    int src_fd = open(src_path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW, 0);
    if (src_fd < 0 && errno == ENOENT) return;
    if (src_fd < 0)
        fatal("cannot open '%s': %s", src_path, strerror(errno));
    struct stat src_stat;
    if (fstat(src_fd, &src_stat) < 0)
        fatal("fstat failed: %s", strerror(errno));
    // safety checks
    if (!S_ISREG(src_stat.st_mode))
        fatal("%s must be a regular file", src_path);
    if (src_stat.st_size <= 0)
        fatal("%s is empty", src_path);
    if (src_stat.st_size > MAX_FILE_SIZE)
        fatal("%s is too big", src_path);

    // only root, primary_uid and owner of src_path
    // allowed to use this program
    int self_uid = getuid();
    if (self_uid != 0 && self_uid != primary_uid && self_uid != src_stat.st_uid)
        fatal("not allowed to run this program");

    size_t src_z = (size_t) src_stat.st_size;
    char *src_bytes = mmap(NULL, src_z,
                           PROT_READ, MAP_PRIVATE,
                           src_fd, 0);
    if (src_bytes == MAP_FAILED)
        fatal("cannot read content of %s", src_path);
    close(src_fd); src_fd = -1;

    struct Content new_c = process_include(src_path, src_bytes, src_z);
    munmap(src_bytes, src_z);

    char dst_path[PATH_MAX];
    if (snprintf(dst_path, sizeof(dst_path), "%s/ejudge/lang/%s",
                 EJUDGE_LIBEXEC_DIR, name) >= sizeof(src_path)) {
        fatal("path is too long");
    }

    int dst_fd = open(dst_path, O_RDWR | O_CREAT | O_NONBLOCK | O_NOFOLLOW, 0755);
    if (dst_fd < 0) fatal("cannot open '%s': %s", dst_path, strerror(errno));
    struct stat dst_st;
    if (fstat(dst_fd, &dst_st) < 0) fatal("fstat failed: %s", strerror(errno));
    if (dst_st.st_uid != 0 && dst_st.st_uid != primary_uid && dst_st.st_uid != self_uid && dst_st.st_uid != src_stat.st_uid)
        fatal("invalid owner of '%s'", dst_path);

    if (dst_st.st_size > 0) {
        if (!S_ISREG(dst_st.st_mode)) fatal("file '%s' must be regular", dst_path);
        if (dst_st.st_size > 1024 * 1024) fatal("file '%s' too big", dst_path);
        size_t tmp_z = (size_t) dst_st.st_size;
        char *tmp_s = mmap(NULL, tmp_z, PROT_READ, MAP_PRIVATE, dst_fd, 0);
        if (tmp_s == MAP_FAILED) fatal("mmap of '%s' failed: %s", dst_path, strerror(errno));
        if (tmp_z == new_c.size && !memcmp(tmp_s, new_c.data, tmp_z)) {
            // unchanged file
            munmap(tmp_s, tmp_z);
            close(dst_fd);
            free(new_c.data);
            return;
        }
        munmap(tmp_s, tmp_z);
    }

    if (ftruncate(dst_fd, new_c.size) < 0) fatal("ftruncate failed: %s", strerror(errno));
    char *dst_s = mmap(NULL, new_c.size, PROT_READ | PROT_WRITE, MAP_SHARED, dst_fd, 0);
    if (dst_s == MAP_FAILED) fatal("mmap failed: %s", strerror(errno));
    memcpy(dst_s, new_c.data, new_c.size);
    munmap(dst_s, new_c.size);
    if (fchmod(dst_fd, 0755) < 0) fatal("fchmod failed: %s", strerror(errno));
    if (fchown(dst_fd, src_stat.st_uid, src_stat.st_gid) < 0) fatal("fchown failed: %s", strerror(errno));
    close(dst_fd);
    free(new_c.data);
}

int
main(int argc, char *argv[])
{
    {
        char *p = strrchr(argv[0], '/');
        if (p) program_name = p + 1;
        else program_name = argv[0];
    }

    {
        struct passwd *pwd = getpwnam(PRIMARY_USER);
        if (!pwd) fatal("user '%s' does not exist", PRIMARY_USER);
        primary_uid = pwd->pw_uid;
        if (primary_uid <= 0) fatal("invalid uid %d for %s", primary_uid, PRIMARY_USER);
    }

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "all")) {
            for (const char * const *plang = whitelist; *plang; ++plang) {
                process_file(*plang, 1);
            }
        } else {
            process_file(argv[i], 0);
        }
    }
}
