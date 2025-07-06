/* -*- mode: c; c-basic-offset: 4 -*- */

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

#include "ejudge/checksum.h"
#include "ejudge/sha256.h"
#include "ejudge/xalloc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

void
checksum_free(struct checksum_context *cntx)
{
    for (size_t i = 0; i < cntx->path_u; ++i) {
        xfree(cntx->paths[i]);
    }
    xfree(cntx->paths);
}

void
checksum_add_file(struct checksum_context *cntx, const unsigned char *path)
{
    for (size_t i = 0; i < cntx->path_u; ++i) {
        if (!strcmp(path, cntx->paths[i])) {
            return;
        }
    }

    if (cntx->path_a == cntx->path_u) {
        if (!cntx->path_a) {
            cntx->path_a = 16;
        } else {
            cntx->path_a *= 2;
        }
        XREALLOC(cntx->paths, cntx->path_a);
    }
    cntx->paths[cntx->path_u++] = xstrdup(path);
}

static int
sort_func(const void *p1, const void *p2)
{
    const unsigned char *s1 = *(const unsigned char **) p1;
    const unsigned char *s2 = *(const unsigned char **) p2;
    return strcmp(s1, s2);
}

void
checksum_sort(struct checksum_context *cntx)
{
    qsort(cntx->paths, cntx->path_u, sizeof(cntx->paths[0]), sort_func);
}

static int
sha256_file(FILE *log_f, const char *path, unsigned char *res)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK, 0);
    if (fd < 0) {
        if (log_f) {
            fprintf(log_f, "%s: failed to open '%s': %s\n",
                __FUNCTION__, path, strerror(errno));
        }
        return -1;
    }
    struct stat stb;
    if (fstat(fd, &stb) < 0) {
        if (log_f) {
            fprintf(log_f, "%s: fstat failed on '%s': %s\n",
                __FUNCTION__, path, strerror(errno));
        }
        close(fd);
        return -1;
    }
    if (!S_ISREG(stb.st_mode)) {
        if (log_f) {
            fprintf(log_f, "%s: '%s' is not a regular file\n",
                __FUNCTION__, path);
        }
        close(fd);
        return -1;
    }
    SHA256_CTX ctx;
    sha256_init(&ctx);
    if (stb.st_size == 0) {
        sha256_final(&ctx, res);
        return 0;
    }
    size_t size = stb.st_size;
    if (size != stb.st_size) {
        if (log_f) {
            fprintf(log_f, "%s: '%s' is too big\n",
                __FUNCTION__, path);
        }
        close(fd);
        return -1;
    }
    unsigned char *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        if (log_f) {
            fprintf(log_f, "%s: mmap failed on '%s': %s\n",
                __FUNCTION__, path, strerror(errno));
        }
        close(fd);
        return -1;
    }
    close(fd);
    sha256_update(&ctx, data, size);
    munmap(data, size);
    sha256_final(&ctx, res);
    return 0;
}

int
checksum_compute(struct checksum_context *cntx, FILE *log_f)
{
    checksum_sort(cntx);
    SHA256_CTX ctx;
    sha256_init(&ctx);
    for (size_t i = 0; i < cntx->path_u; ++i) {
        size_t len = strlen(cntx->paths[i]);
        sha256_update(&ctx, cntx->paths[i], len);
        unsigned char buf[32];
        if (sha256_file(log_f, cntx->paths[i], buf) < 0) {
            return -1;
        }
        sha256_update(&ctx, buf, sizeof(buf));
    }
    sha256_final(&ctx, cntx->checksum);
    return 0;
}

unsigned char *
checksum_bytes(struct checksum_context *cntx)
{
    return cntx->checksum;
}

unsigned char *
checksum_hex(struct checksum_context *cntx, unsigned char *buf)
{
    const unsigned char hh[] = "0123456789abcdef";
    unsigned char *p = buf;
    unsigned char *s = cntx->checksum;
    for (size_t i = 0; i < 32; ++i) {
        *p++ = hh[*s++ >> 4];
        *p++ = hh[*s++ & 0xf];
    }
    *p = 0;
    return buf;
}
