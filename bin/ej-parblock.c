/* -*- mode: c -*- */

/* Copyright (C) 2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/blowfish.h"
#include "ejudge/base64.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

static void
ulltobe(unsigned char *out, unsigned long long value)
{
    out[0] = value >> 56;
    out[1] = value >> 48;
    out[2] = value >> 40;
    out[3] = value >> 32;
    out[4] = value >> 24;
    out[5] = value >> 16;
    out[6] = value >> 8;
    out[7] = value;
}

static void
swb(unsigned char *buf)
{
    unsigned char t;
    t = buf[0]; buf[0] = buf[3]; buf[3] = t;
    t = buf[1]; buf[1] = buf[2]; buf[2] = t;
}

void
encode(unsigned long long key, unsigned long long iv)
{
    unsigned char buf[8192];
    size_t out_a = 8, out_z = 0;
    unsigned char *out_p = malloc(out_a);
    memset(out_p, 0, out_a);

    while (fgets(buf, sizeof(buf), stdin)) {
        int len = strlen(buf);
        while (len > 0 && isspace(buf[len - 1])) --len;
        buf[len] = 0;
        if (!len) continue;

        if (!strchr(buf, '=')) {
            fprintf(stderr, "'=' expected\n");
            exit(1);
        }

        if (out_z + len + 2 >= out_a) {
            size_t new_a = out_a;
            while (out_z + len + 2 >= new_a) new_a *= 2;
            unsigned char *new_p = malloc(new_a);
            memset(new_p, 0, new_a);
            memcpy(new_p, out_p, out_a);
            free(out_p);
            out_p = new_p;
            out_a = new_a;
        }

        memcpy(out_p + out_z, buf, len + 1);
        out_z += len + 1;
    }

    if (!out_z) {
        fprintf(stderr, "no data\n");
        exit(1);
    }

    ++out_z;
    out_z = (out_z + 7) & ~7;

    BLOWFISH_CTX *ctx = calloc(1, sizeof(*ctx));
    unsigned char kb[8];
    ulltobe(kb, key);
    Blowfish_Init(ctx, kb, sizeof(kb));

    unsigned char ivb[8];
    ulltobe(ivb, iv);
    swb(ivb);
    swb(ivb + 4);

    unsigned char *cbc = malloc(out_z);
    memcpy(cbc, out_p, out_z);

    for (int i = 0; i < out_z; i += 8) {
        swb(cbc + i);
        swb(cbc + i + 4);

        cbc[i] ^= ivb[0];
        cbc[i + 1] ^= ivb[1];
        cbc[i + 2] ^= ivb[2];
        cbc[i + 3] ^= ivb[3];
        cbc[i + 4] ^= ivb[4];
        cbc[i + 5] ^= ivb[5];
        cbc[i + 6] ^= ivb[6];
        cbc[i + 7] ^= ivb[7];

        Blowfish_Encrypt(ctx, (uint32_t *) (cbc + i), (uint32_t *) (cbc + i + 4));

        memcpy(ivb, cbc + i, 8);

        swb(cbc + i);
        swb(cbc + i + 4);
    }

    unsigned char *b64buf = malloc(out_z * 2);
    int b64len = base64_encode(cbc, out_z, b64buf);
    b64buf[b64len] = 0;

    for (int i = 0; i < b64len; ++i) {
        if (b64buf[i] == '/') {
            b64buf[i] = '.';
        } else if (b64buf[i] == '=') {
            b64buf[i] = '-';
        } else if (b64buf[i] == '+') {
            b64buf[i] = '_';
        }
    }
    printf("%s\n", b64buf);
}

static void
decode(unsigned long long key, unsigned long long iv)
{
    unsigned char buf[8192];
    if (!fgets(buf, sizeof(buf), stdin)) {
        fprintf(stderr, "unexpected EOF\n");
        exit(1);
    }
    int len = strlen(buf);
    while (len > 0 && isspace(buf[len - 1])) --len;
    buf[len] = 0;
    if (len <= 0) {
        fprintf(stderr, "no data\n");
        exit(1);
    }

    for (int i = 0; i < len; ++i) {
        if (buf[i] == '.') {
            buf[i] = '/';
        } else if (buf[i] == '-') {
            buf[i] = '=';
        } else if (buf[i] == '_') {
            buf[i] = '+';
        }
    }

    int errflg = 0;
    unsigned char *cbc = malloc(len);
    memset(cbc, 0, len);
    int dlen = base64_decode(buf, len, cbc, &errflg);
    if (errflg) {
        fprintf(stderr, "invalid base64\n");
        exit(1);
    }
    if ((dlen % 8) != 0) {
        fprintf(stderr, "invalid data length (%d)\n", dlen);
        exit(1);
    }

    BLOWFISH_CTX *ctx = calloc(1, sizeof(*ctx));
    unsigned char kb[8];
    ulltobe(kb, key);
    Blowfish_Init(ctx, kb, sizeof(kb));

    unsigned char ivb[8];
    ulltobe(ivb, iv);
    swb(ivb);
    swb(ivb + 4);

    for (int i = 0; i < dlen; i += 8) {
        unsigned char saved[8];
        swb(cbc + i);
        swb(cbc + i + 4);

        memcpy(saved, cbc + i, 8);

        Blowfish_Decrypt(ctx, (uint32_t *) (cbc + i), (uint32_t *) (cbc + i + 4));

        cbc[i] ^= ivb[0];
        cbc[i + 1] ^= ivb[1];
        cbc[i + 2] ^= ivb[2];
        cbc[i + 3] ^= ivb[3];
        cbc[i + 4] ^= ivb[4];
        cbc[i + 5] ^= ivb[5];
        cbc[i + 6] ^= ivb[6];
        cbc[i + 7] ^= ivb[7];

        swb(cbc + i);
        swb(cbc + i + 4);

        memcpy(ivb, saved, 8);
    }

    unsigned char *curp = (unsigned char*) cbc;
    unsigned char *endp = curp + dlen;
    while (1) {
        int curl = strlen(curp);
        if (!curl) break;
        if (curp + curl >= endp) {
            fprintf(stderr, "invalid data block\n");
            exit(1);
        }
        printf("%s\n", curp);
        curp += curl + 1;
    }
}

int
main(int argc, char *argv[])
{
    int decode_mode = 0;

    int ap = 1;
    if (ap < argc) {
        if (!strcmp(argv[ap], "-d")) {
            decode_mode = 1;
            ++ap;
        } else if (!strcmp(argv[ap], "-e")) {
            decode_mode = 0;
            ++ap;
        }
    }

    if (argc != ap + 1) {
        fprintf(stderr, "invalid number of args\n");
        exit(1);
    }

    if (!argv[ap][0]) {
        fprintf(stderr, "invalid argument\n");
        exit(1);
    }
    char *ep = NULL;
    errno = 0;
    int keyno = strtol(argv[ap], &ep, 10);
    if (errno || *ep) {
        fprintf(stderr, "invalid argument\n");
        exit(1);
    }

    unsigned long long key = 0, iv = 0;
    unsigned char keyfile[PATH_MAX];
    snprintf(keyfile, sizeof(keyfile), "%s/keys/%d.key", EJUDGE_CONF_DIR, keyno);
    FILE *kf = fopen(keyfile, "r");
    if (!kf) {
        fprintf(stderr, "cannot open key file '%s'\n", keyfile);
        exit(1);
    }
    if (fscanf(kf, "%llx%llx", &key, &iv) != 2) {
        fprintf(stderr, "cannot read key file\n");
        exit(1);
    }
    fclose(kf); kf = NULL;

    if (decode_mode) {
        decode(key, iv);
    } else {
        encode(key, iv);
    }

    return 0;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
