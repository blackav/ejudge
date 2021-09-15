/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2020-2021 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

static const char *progname;

static __attribute__((unused)) const unsigned char config_ejudge_primary_user[]
#if defined EJUDGE_PRIMARY_USER
= EJUDGE_PRIMARY_USER
#else
= ""
#endif
;

static __attribute__((unused)) const unsigned char config_ejudge_exec_user[]
#if defined EJUDGE_EXEC_USER
= EJUDGE_EXEC_USER
#else
= ""
#endif
;

static __attribute__((unused)) const unsigned char config_ejudge_compile_user[]
#if defined EJUDGE_COMPILE_USER
= EJUDGE_COMPILE_USER
#else
= ""
#endif
;

static __attribute__((unused)) const unsigned char config_ejudge_prefix_dir[]
#if defined EJUDGE_PREFIX_DIR
= EJUDGE_PREFIX_DIR
#else
= ""
#endif
;

static __attribute__((unused)) const unsigned char config_ejudge_server_bin_path[]
#if defined EJUDGE_SERVER_BIN_PATH
= EJUDGE_SERVER_BIN_PATH
#else
= ""
#endif
;

static int
need_separate_compile_user(void)
{
    if (!config_ejudge_compile_user[0]) return 0;
    if (!strcmp(config_ejudge_primary_user, config_ejudge_compile_user)) return 0;
    return 1;
}

static int
need_separate_exec_user(void)
{
    if (!config_ejudge_exec_user[0]) return 0;
    if (!strcmp(config_ejudge_primary_user, config_ejudge_exec_user)) return 0;
    return 1;
}

static int
make_bin_path(unsigned char *bin_path, size_t path_size)
{
    bin_path[0] = 0;
    if (config_ejudge_server_bin_path[0]) {
        if (snprintf(bin_path, path_size, "%s", config_ejudge_server_bin_path) >= path_size) {
            fprintf(stderr, "%s: path '%s' is too long\n", progname, config_ejudge_server_bin_path);
            return 1;
        }
    } else if (config_ejudge_prefix_dir[0]) {
        if (snprintf(bin_path, path_size, "%s/bin", config_ejudge_prefix_dir) >= path_size) {
            fprintf(stderr, "%s: path '%s/bin' is too long\n", progname, config_ejudge_prefix_dir);
            return 1;
        }
    }
    if (!bin_path[0]) {
        fprintf(stderr, "%s: path to the ejudge binaries is not specified\n", progname);
        return 1;
    }
    return 0;
}

static int
is_update_needed(
        const unsigned char *dst_file,
        const unsigned char *src_file,
        const unsigned char *file,
        int dfd,
        int sfd,
        int suid_mode)
{
    int tfd = openat(dfd, file, O_RDONLY | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK, 0);
    if (tfd < 0 && errno == ELOOP) {
        // file is a symbolic link
        if (unlinkat(dfd, file, 0) < 0) {
            fprintf(stderr, "%s: cannot remove '%s': %s\n", progname, dst_file, strerror(errno));
            goto fail;
        }
        goto needed;
    }
    if (tfd < 0 && errno == ENOENT) {
        goto needed;
    }
    if (tfd < 0 && errno == EACCES) {
        // not accessible file
        if (unlinkat(dfd, file, 0) < 0) {
            fprintf(stderr, "%s: cannot remove '%s': %s\n", progname, dst_file, strerror(errno));
            goto fail;
        }
        goto needed;
    }
    if (tfd < 0) {
        fprintf(stderr, "%s: cannot open '%s': %s\n", progname, dst_file, strerror(errno));
        goto fail;
    }

    struct stat stb;
    if (fstat(tfd, &stb) < 0) {
        fprintf(stderr, "%s: cannot fstat '%s': %s\n", progname, dst_file, strerror(errno));
        goto fail;
    }
    if (S_ISDIR(stb.st_mode)) {
        fprintf(stderr, "%s: file '%s' must not be directory\n", progname, dst_file);
        goto fail;
    }
    if (!S_ISREG(stb.st_mode)) {
        if (unlinkat(dfd, file, 0) < 0) {
            fprintf(stderr, "%s: cannot remove '%s': %s\n", progname, dst_file, strerror(errno));
            goto fail;
        }
        goto needed;
    }
    if (suid_mode && (stb.st_uid != 0 || stb.st_gid != 0 || (stb.st_mode & 06000) != 06000)) {
        goto needed;
    }

    struct stat stb2;
    if (fstat(sfd, &stb2) < 0) {
        fprintf(stderr, "%s: cannot fstat '%s': %s\n", progname, src_file, strerror(errno));
        goto fail;
    }

    if (stb.st_size != stb2.st_size) {
        if (unlinkat(dfd, file, 0) < 0) {
            fprintf(stderr, "%s: cannot remove '%s': %s\n", progname, dst_file, strerror(errno));
            goto fail;
        }
        goto needed;
    }
    if (!stb.st_size) {
        goto not_needed;
    }
    if ((int) stb.st_size != stb.st_size) {
        fprintf(stderr, "%s: file '%s' is too big\n", progname, src_file);
        goto fail;
    }

    const unsigned char *psrc = mmap(NULL, stb.st_size, PROT_READ, MAP_PRIVATE, sfd, 0);
    if (psrc == MAP_FAILED) {
        fprintf(stderr, "%s: mmap failed for '%s': %s\n", progname, src_file, strerror(errno));
        goto fail;
    }
    const unsigned char *pdst = mmap(NULL, stb.st_size, PROT_READ, MAP_PRIVATE, tfd, 0);
    if (pdst == MAP_FAILED) {
        fprintf(stderr, "%s: mmap failed for '%s': %s\n", progname, dst_file, strerror(errno));
        munmap((void*) psrc, stb.st_size);
        goto fail;
    }
    for (int i = 0; i < stb.st_size; ++i) {
        if (psrc[i] != pdst[i]) {
            munmap((void*) psrc, stb.st_size);
            munmap((void*) pdst, stb.st_size);
            if (unlinkat(dfd, file, 0) < 0) {
                fprintf(stderr, "%s: cannot remove '%s': %s\n", progname, dst_file, strerror(errno));
                goto fail;
            }
            goto needed;
        }
    }

    munmap((void*) psrc, stb.st_size);
    munmap((void*) pdst, stb.st_size);

not_needed:
    if (tfd >= 0) close(tfd);
    return 0;

needed:
    if (tfd >= 0) close(tfd);
    return 1;

fail:
    if (tfd >= 0) close(tfd);
    return -1;
}

static int
install_file(
        const unsigned char *dst_dir,
        const unsigned char *src_dir,
        const unsigned char *file,
        int suid_mode,
        int *p_updated_count)
{
    const unsigned char *destdir_env = getenv("DESTDIR");
    unsigned char full_dst_dir[PATH_MAX];

    if (destdir_env && *destdir_env) {
        if (destdir_env[strlen(destdir_env) - 1] == '/' || dst_dir[0] == '/') {
            if (snprintf(full_dst_dir, sizeof(full_dst_dir), "%s%s", destdir_env, dst_dir) >= sizeof(full_dst_dir)) {
                fprintf(stderr, "%s: path '%s%s' is too long\n", progname, destdir_env, dst_dir);
                return 1;
            }
        } else {
            if (snprintf(full_dst_dir, sizeof(full_dst_dir), "%s/%s", destdir_env, dst_dir) >= sizeof(full_dst_dir)) {
                fprintf(stderr, "%s: path '%s/%s' is too long\n", progname, destdir_env, dst_dir);
                return 1;
            }
        }
    } else {
        if (snprintf(full_dst_dir, sizeof(full_dst_dir), "%s", dst_dir) >= sizeof(full_dst_dir)) {
            fprintf(stderr, "%s: path '%s' is too long\n", progname, dst_dir);
            return 1;
        }
    }

    unsigned char dst_file[PATH_MAX];
    if (snprintf(dst_file, sizeof(dst_file), "%s/%s", full_dst_dir, file) >= sizeof(dst_file)) {
        fprintf(stderr, "%s: path '%s/%s' is too long\n", progname, full_dst_dir, file);
        return 1;
    }
    unsigned char src_file[PATH_MAX];
    if (snprintf(src_file, sizeof(src_file), "%s/%s", src_dir, file) >= sizeof(src_file)) {
        fprintf(stderr, "%s: path '%s/%s' is too long\n", progname, src_dir, file);
        return 1;
    }
    int sfd = open(src_file, O_RDONLY | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK, 0);
    if (sfd < 0) {
        fprintf(stderr, "%s: cannot open source path '%s': %s\n", progname, src_file, strerror(errno));
        return 1;
    }
    struct stat stb;
    if (fstat(sfd, &stb) < 0) {
        fprintf(stderr, "%s: fstat of '%s' failed: %s\n", progname, src_file, strerror(errno));
        close(sfd);
        return 1;
    }
    if (!S_ISREG(stb.st_mode)) {
        fprintf(stderr, "%s: '%s' is not a regular file\n", progname, src_file);
        close(sfd);
        return 1;
    }
    if ((stb.st_mode & 0111) != 0111) {
        // must have 'x' bit set
        fprintf(stderr, "%s: '%s' invalid permissions\n", progname, src_file);
        close(sfd);
        return 1;
    }
    if ((int) stb.st_size != stb.st_size) {
        fprintf(stderr, "%s: '%s' file is too big\n", progname, src_file);
        close(sfd);
        return 1;
    }
    int file_length = stb.st_size;

    int dfd = open(full_dst_dir, O_RDONLY | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK | O_DIRECTORY | O_PATH, 0);
    if (dfd < 0) {
        fprintf(stderr, "%s: cannot open directory '%s': %s\n", progname, full_dst_dir, strerror(errno));
        close(sfd);
        return 1;
    }
    if (fstat(dfd, &stb) < 0) {
        fprintf(stderr, "%s: fstat of '%s' failed: %s\n", progname, full_dst_dir, strerror(errno));
        close(sfd);
        close(dfd);
        return 1;
    }
    if (!S_ISDIR(stb.st_mode)) {
        fprintf(stderr, "%s: '%s' is not a directory\n", progname, full_dst_dir);
        close(sfd);
        close(dfd);
        return 1;
    }

    int res = is_update_needed(dst_file, src_file, file, dfd, sfd, suid_mode);
    if (res < 0) {
        close(sfd);
        close(dfd);
        return 1;
    }
    if (!res) {
        close(sfd);
        close(dfd);
        return 0;
    }

    unlinkat(dfd, file, 0);

    int tfd = openat(dfd, file, O_RDWR | O_CREAT | O_TRUNC | O_EXCL, 0755);
    if (tfd < 0) {
        fprintf(stderr, "%s: cannot open output file '%s': %s\n", progname, dst_file, strerror(errno));
        close(tfd);
        close(sfd);
        close(dfd);
        return 1;
    }
    if (ftruncate(tfd, file_length) < 0) {
        fprintf(stderr, "%s: ftruncate failed on '%s': %s\n", progname, dst_file, strerror(errno));
        close(tfd);
        close(sfd);
        close(dfd);
        return 1;
    }

    const unsigned char *psrc = mmap(NULL, file_length, PROT_READ, MAP_PRIVATE, sfd, 0);
    if (psrc == MAP_FAILED) {
        fprintf(stderr, "%s: mmap failed for '%s': %s\n", progname, src_file, strerror(errno));
        close(tfd);
        close(sfd);
        close(dfd);
        return 1;
    }
    unsigned char *pdst = mmap(NULL, file_length, PROT_READ | PROT_WRITE, MAP_SHARED, tfd, 0);
    if (pdst == MAP_FAILED) {
        fprintf(stderr, "%s: mmap failed for '%s': %s\n", progname, dst_file, strerror(errno));
        munmap((void*) psrc, file_length);
        close(tfd);
        close(sfd);
        close(dfd);
        return 1;
    }

    memcpy(pdst, psrc, file_length);
    munmap((void*) psrc, file_length);
    munmap(pdst, file_length);
    close(tfd);
    close(sfd);
    close(dfd);
    ++(*p_updated_count);

    return 0;
}

static int chmod_mode(void);

static int
install_mode(void)
{
    int need_compile = need_separate_compile_user();
    int need_exec = need_separate_exec_user();

    unsigned char bin_path[PATH_MAX];
    if (make_bin_path(bin_path, sizeof(bin_path))) {
        return 1;
    }

    int updated_count = 0;
    if (install_file(bin_path, ".", "ej-compile-control", need_compile, &updated_count)) {
        return 1;
    }
    static const unsigned char * const files[] =
    {
        "ej-suid-chown",
        "ej-suid-exec",
        "ej-suid-ipcrm",
        "ej-suid-kill",
        "ej-suid-container",
        "ej-suid-update-scripts",
        NULL
    };
    for (int i = 0; files[i]; ++i) {
        if (install_file(bin_path, ".", files[i], need_exec, &updated_count)) {
            return 1;
        }
    }

    if (!updated_count) {
        return 0;
    }

    if (getuid() == 0) {
        // change permissions immediately
        return chmod_mode();
    }

    if (need_compile || need_exec) {
        printf("=========================================\n"
               "Please, execute 'ejudge-suid-setup' as root!\n"
               "=========================================\n");
    }
    return 0;
}

static int
set_setuid_bit(const unsigned char *bin_path, const unsigned char *programs[])
{
    unsigned char full_path[PATH_MAX];

    for (int i = 0; programs[i]; ++i) {
        if (snprintf(full_path, sizeof(full_path), "%s/%s", bin_path, programs[i]) >= sizeof(full_path)) {
            fprintf(stderr, "%s: path '%s/%s' is too long\n", progname, bin_path, programs[i]);
            return 1;
        }
        int fd = open(full_path, O_RDONLY | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK, 0);
        if (fd < 0) {
            fprintf(stderr, "%s: cannot open '%s': %s\n", progname, full_path, strerror(errno));
            return 1;
        }
        struct stat stb;
        if (fstat(fd, &stb) < 0) {
            fprintf(stderr, "%s: fstat of '%s' failed: %s\n", progname, full_path, strerror(errno));
            close(fd);
            return 1;
        }
        if (!S_ISREG(stb.st_mode)) {
            fprintf(stderr, "%s: '%s' is not a regular file\n", progname, full_path);
            close(fd);
            return 1;
        }
        if ((stb.st_mode & 0111) != 0111) {
            // must have 'x' bit set
            fprintf(stderr, "%s: '%s' invalid permissions\n", progname, full_path);
            close(fd);
            return 1;
        }
        if (fchown(fd, 0, 0) < 0) {
            fprintf(stderr, "%s: chown failed for '%s': %s\n", progname, full_path, strerror(errno));
            close(fd);
            return 1;
        }
        if (fchmod(fd, 06555) < 0) {
            fprintf(stderr, "%s: chmod failed for '%s': %s\n", progname, full_path, strerror(errno));
            close(fd);
            return 1;
        }
        close(fd); fd = -1;
    }

    return 0;
}

static int
chmod_mode(void)
{
    int need_compile = need_separate_compile_user();
    int need_exec = need_separate_exec_user();

    if (!need_compile && !need_exec) {
        printf("%s: separate compile or exec user mode is not activated\n", progname);
        return 0;
    }

    if (getuid() != 0) {
        fprintf(stderr, "%s: run this program as root user\n", progname);
        return 1;
    }

    unsigned char bin_path[PATH_MAX];
    if (make_bin_path(bin_path, sizeof(bin_path))) {
        return 1;
    }

    struct stat stb;
    if (lstat(bin_path, &stb) < 0) {
        fprintf(stderr, "%s: directory '%s' does not exist\n", progname, bin_path);
        return 1;
    }
    if (!S_ISDIR(stb.st_mode)) {
        fprintf(stderr, "%s: '%s' not a directory\n", progname, bin_path);
        return 1;
    }

    if (need_compile) {
        int retval = set_setuid_bit(bin_path, (const unsigned char *[]) { "ej-compile-control", NULL });
        if (retval) return retval;
    }

    if (need_exec) {
        int retval = set_setuid_bit(bin_path, (const unsigned char *[]) { "ej-suid-chown", "ej-suid-exec", "ej-suid-ipcrm", "ej-suid-kill", "ej-suid-container", "ej-suid-update-scripts", NULL });
        if (retval) return retval;
    }

    return 0;
}

int
main(int argc, char *argv[])
{
    if (!argc) {
        fprintf(stderr, "invalid arguments\n");
        exit(1);
    }
    progname = argv[0];

    if (argc == 2 && !strcmp(argv[1], "--install")) {
        return install_mode();
    } else {
        return chmod_mode();
    }
}
