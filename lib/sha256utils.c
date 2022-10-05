/* -*- mode: c -*- */

/* Copyright (C) 2016-2022 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/sha256utils.h"
#include "ejudge/sha256.h"
#include "ejudge/base64.h"

#include <string.h>
#include <stdio.h>

void sha256b64buf(char *out, size_t out_size, const unsigned char *in, size_t in_size)
{
    unsigned char hash[SHA256_BLOCK_SIZE];
    SHA256_CTX cntx;
    sha256_init(&cntx);
    sha256_update(&cntx, in, in_size);
    sha256_final(&cntx, hash);
    if (out_size >= 48) {
        int z = base64_encode(hash, SHA256_BLOCK_SIZE, out);
        out[z] = 0;
    } else {
        char buf[48];
        int z = base64_encode(hash, SHA256_BLOCK_SIZE, buf);
        buf[z] = 0;
        snprintf(out, out_size, "%s", buf);
    }
}

void sha256b64ubuf(
        char *out,
        size_t out_size,
        const unsigned char *in,
        size_t in_size)
{
    unsigned char hash[SHA256_BLOCK_SIZE];
    SHA256_CTX cntx;
    sha256_init(&cntx);
    sha256_update(&cntx, in, in_size);
    sha256_final(&cntx, hash);
    if (out_size >= 48) {
        int z = base64u_encode(hash, SHA256_BLOCK_SIZE, out);
        out[z] = 0;
    } else {
        char buf[48];
        int z = base64u_encode(hash, SHA256_BLOCK_SIZE, buf);
        buf[z] = 0;
        snprintf(out, out_size, "%s", buf);
    }
}

void sha256b64str(char *out, size_t out_size, const unsigned char *str)
{
    size_t in_size = strlen(str);
    sha256b64buf(out, out_size, str, in_size);
}

void sha256b64file(char *out, size_t out_size, FILE *in)
{
    SHA256_CTX cntx;
    uint8_t buf[4096];
    unsigned char hash[SHA256_BLOCK_SIZE];

    sha256_init(&cntx);
    while (1) {
        size_t rsz = fread(buf, 1, sizeof(buf), in);
        if (!rsz) break;
        sha256_update(&cntx, buf, rsz);
    }
    sha256_final(&cntx, hash);
    if (out_size >= 48) {
        int z = base64_encode(hash, SHA256_BLOCK_SIZE, out);
        out[z] = 0;
    } else {
        char buf[48];
        int z = base64_encode(hash, SHA256_BLOCK_SIZE, buf);
        buf[z] = 0;
        snprintf(out, out_size, "%s", buf);
    }
}
