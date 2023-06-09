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

#include "ejudge/ulid.h"

// https://github.com/suyash/ulid

/**
 * dec storesdecimal encodings for characters.
 * 0xFF indicates invalid character.
 * 48-57 are digits.
 * 65-90 are capital alphabets.
 * */
static const unsigned char dec_table[256] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 0     1     2     3     4     5     6     7  */
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    /* 8     9                                      */
    0x08, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

    /*    10(A) 11(B) 12(C) 13(D) 14(E) 15(F) 16(G) */
    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    /*17(H)     18(J) 19(K)       20(M) 21(N)       */
    0x11, 0xFF, 0x12, 0x13, 0xFF, 0x14, 0x15, 0xFF,
    /*22(P)23(Q)24(R) 25(S) 26(T)       27(V) 28(W) */
    0x16, 0x17, 0x18, 0x19, 0x1A, 0xFF, 0x1B, 0x1C,
    /*29(X)30(Y)31(Z)                               */
    0x1D, 0x1E, 0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/**
 * Crockford's Base32
 * */
static const unsigned char enc_table[33] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * ulid_marshall will marshal a ULID to the passed character array.
 *
 * Implementation taken directly from oklog/ulid
 * (https://sourcegraph.com/github.com/oklog/ulid@0774f81f6e44af5ce5e91c8d7d76cf710e889ebb/-/blob/ulid.go#L162-190)
 *
 * timestamp:<br>
 * dst[0]: first 3 bits of data[0]<br>
 * dst[1]: last 5 bits of data[0]<br>
 * dst[2]: first 5 bits of data[1]<br>
 * dst[3]: last 3 bits of data[1] + first 2 bits of data[2]<br>
 * dst[4]: bits 3-7 of data[2]<br>
 * dst[5]: last bit of data[2] + first 4 bits of data[3]<br>
 * dst[6]: last 4 bits of data[3] + first bit of data[4]<br>
 * dst[7]: bits 2-6 of data[4]<br>
 * dst[8]: last 2 bits of data[4] + first 3 bits of data[5]<br>
 * dst[9]: last 5 bits of data[5]<br>
 *
 * entropy:
 * follows similarly, except now all components are set to 5 bits.
 * */
void
ulid_marshall(unsigned char *dst, const unsigned char *data)
{
    // 10 byte timestamp
    dst[0] = enc_table[(data[0] & 224) >> 5];
    dst[1] = enc_table[data[0] & 31];
    dst[2] = enc_table[(data[1] & 248) >> 3];
    dst[3] = enc_table[((data[1] & 7) << 2) | ((data[2] & 192) >> 6)];
    dst[4] = enc_table[(data[2] & 62) >> 1];
    dst[5] = enc_table[((data[2] & 1) << 4) | ((data[3] & 240) >> 4)];
    dst[6] = enc_table[((data[3] & 15) << 1) | ((data[4] & 128) >> 7)];
    dst[7] = enc_table[(data[4] & 124) >> 2];
    dst[8] = enc_table[((data[4] & 3) << 3) | ((data[5] & 224) >> 5)];
    dst[9] = enc_table[data[5] & 31];

    // 16 bytes of entropy
    dst[10] = enc_table[(data[6] & 248) >> 3];
    dst[11] = enc_table[((data[6] & 7) << 2) | ((data[7] & 192) >> 6)];
    dst[12] = enc_table[(data[7] & 62) >> 1];
    dst[13] = enc_table[((data[7] & 1) << 4) | ((data[8] & 240) >> 4)];
    dst[14] = enc_table[((data[8] & 15) << 1) | ((data[9] & 128) >> 7)];
    dst[15] = enc_table[(data[9] & 124) >> 2];
    dst[16] = enc_table[((data[9] & 3) << 3) | ((data[10] & 224) >> 5)];
    dst[17] = enc_table[data[10] & 31];
    dst[18] = enc_table[(data[11] & 248) >> 3];
    dst[19] = enc_table[((data[11] & 7) << 2) | ((data[12] & 192) >> 6)];
    dst[20] = enc_table[(data[12] & 62) >> 1];
    dst[21] = enc_table[((data[12] & 1) << 4) | ((data[13] & 240) >> 4)];
    dst[22] = enc_table[((data[13] & 15) << 1) | ((data[14] & 128) >> 7)];
    dst[23] = enc_table[(data[14] & 124) >> 2];
    dst[24] = enc_table[((data[14] & 3) << 3) | ((data[15] & 224) >> 5)];
    dst[25] = enc_table[data[15] & 31];
    dst[26] = 0;
}

/**
 * ulid_unmarshall
 * */
int
ulid_unmarshall(unsigned char *data, const unsigned char *str)
{
    if ((signed char)(dec_table[str[0]] | dec_table[str[1]] | dec_table[str[2]]
                      | dec_table[str[3]] | dec_table[str[4]] | dec_table[str[5]]
                      | dec_table[str[6]] | dec_table[str[7]] | dec_table[str[8]]
                      | dec_table[str[9]] | dec_table[str[10]] | dec_table[str[11]]
                      | dec_table[str[12]] | dec_table[str[13]] | dec_table[str[14]]
                      | dec_table[str[15]] | dec_table[str[16]] | dec_table[str[17]]
                      | dec_table[str[18]] | dec_table[str[19]] | dec_table[str[20]]
                      | dec_table[str[21]] | dec_table[str[22]] | dec_table[str[23]]
                      | dec_table[str[24]] | dec_table[str[25]]) < 0) {
        return -1;
    }

    // timestamp
    data[0] = (dec_table[str[0]] << 5) | dec_table[str[1]];
    data[1] = (dec_table[str[2]] << 3) | (dec_table[str[3]] >> 2);
    data[2] = (dec_table[str[3]] << 6) | (dec_table[str[4]] << 1) | (dec_table[str[5]] >> 4);
    data[3] = (dec_table[str[5]] << 4) | (dec_table[str[6]] >> 1);
    data[4] = (dec_table[str[6]] << 7) | (dec_table[str[7]] << 2) | (dec_table[str[8]] >> 3);
    data[5] = (dec_table[str[8]] << 5) | dec_table[str[9]];

    // entropy
    data[6] = (dec_table[str[10]] << 3) | (dec_table[str[11]] >> 2);
    data[7] = (dec_table[str[11]] << 6) | (dec_table[str[12]] << 1) | (dec_table[str[13]] >> 4);
    data[8] = (dec_table[str[13]] << 4) | (dec_table[str[14]] >> 1);
    data[9] = (dec_table[str[14]] << 7) | (dec_table[str[15]] << 2) | (dec_table[str[16]] >> 3);
    data[10] = (dec_table[str[16]] << 5) | dec_table[str[17]];
    data[11] = (dec_table[str[18]] << 3) | (dec_table[str[19]] >> 2);
    data[12] = (dec_table[str[19]] << 6) | (dec_table[str[20]] << 1) | (dec_table[str[21]] >> 4);
    data[13] = (dec_table[str[21]] << 4) | (dec_table[str[22]] >> 1);
    data[14] = (dec_table[str[22]] << 7) | (dec_table[str[23]] << 2) | (dec_table[str[24]] >> 3);
    data[15] = (dec_table[str[24]] << 5) | dec_table[str[25]];

    return 0;
}
