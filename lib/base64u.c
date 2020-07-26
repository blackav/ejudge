/* -*- c -*- */

/* Copyright (C) 2020 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/base64.h"

#include <string.h>

/*
                   0 A            17 R            34 i            51 z
                   1 B            18 S            35 j            52 0
                   2 C            19 T            36 k            53 1
                   3 D            20 U            37 l            54 2
                   4 E            21 V            38 m            55 3
                   5 F            22 W            39 n            56 4
                   6 G            23 X            40 o            57 5
                   7 H            24 Y            41 p            58 6
                   8 I            25 Z            42 q            59 7
                   9 J            26 a            43 r            60 8
                  10 K            27 b            44 s            61 9
                  11 L            28 c            45 t            62 -
                  12 M            29 d            46 u            63 _
                  13 N            30 e            47 v
                  14 O            31 f            48 w
                  15 P            32 g            49 x
                  16 Q            33 h            50 y
*/

static char const base64u_encode_table[]=
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * NAME:    base64u_encode
 * PURPOSE: convert a char array into base64url-encoded char array
 * ARGS:    in  - pointer to the input char array
 *          out - pointer to the output char array
 * RETURN:  number of chars converted
 * NOTE:    buffer out must contain enough space
 *          to put all chars (base64-encoded char array is larger than
 *          the original char array in ratio 4/3)
 */
int
base64u_encode(char const *in, size_t size, char *out)
{
  unsigned int   ebuf;
  int            nw = size / 3;
  int            l = size - nw * 3;
  int            i;
  char const    *p = in;
  char          *s = out;

  for (i = 0; i < nw; i++) {
    ebuf  = *(unsigned const char*) p++ << 16;
    ebuf |= *(unsigned const char*) p++ << 8;
    ebuf |= *(unsigned const char*) p++;
    ebuf += (ebuf & ~0x3FFFF);
    ebuf += (ebuf & ~0x3FFFF);
    ebuf += (ebuf & ~0xFFF);
    ebuf += (ebuf & ~0xFFF);
    ebuf += (ebuf & ~0x3F);
    ebuf += (ebuf & ~0x3F);
    *s++ = base64u_encode_table[ebuf >> 24];
    *s++ = base64u_encode_table[(ebuf >> 16) & 0xFF];
    *s++ = base64u_encode_table[(ebuf >> 8) & 0xFF];
    *s++ = base64u_encode_table[ebuf & 0xFF];
  }
  if (l == 2) {
    /* make a 18-bit group */
    ebuf  = *(unsigned const char*) p++ << 10;
    ebuf |= *(unsigned const char*) p++ << 2;
    ebuf += (ebuf & ~0xFFF);
    ebuf += (ebuf & ~0xFFF);
    ebuf += (ebuf & ~0x3F);
    ebuf += (ebuf & ~0x3F);
    *s++ = base64u_encode_table[(ebuf >> 16) & 0xFF];
    *s++ = base64u_encode_table[(ebuf >> 8) & 0xFF];
    *s++ = base64u_encode_table[ebuf & 0xFF];
  } else if (l == 1) {
    /* make a 12-bit group */
    ebuf = *(unsigned const char*) p++ << 4;
    ebuf += (ebuf & ~0x3F);
    ebuf += (ebuf & ~0x3F);
    *s++ = base64u_encode_table[(ebuf >> 8) & 0xFF];
    *s++ = base64u_encode_table[ebuf & 0xFF];
  }
  return s - out;
}

void
base64u_encode_f(char const *in, size_t size, FILE *fout)
{
  unsigned int   ebuf;
  int            nw = size / 3;
  int            l = size - nw * 3;
  int            i;
  char const    *p = in;

  for (i = 0; i < nw; i++) {
    ebuf  = *(unsigned const char*) p++ << 16;
    ebuf |= *(unsigned const char*) p++ << 8;
    ebuf |= *(unsigned const char*) p++;
    ebuf += (ebuf & ~0x3FFFF);
    ebuf += (ebuf & ~0x3FFFF);
    ebuf += (ebuf & ~0xFFF);
    ebuf += (ebuf & ~0xFFF);
    ebuf += (ebuf & ~0x3F);
    ebuf += (ebuf & ~0x3F);
    putc_unlocked(base64u_encode_table[ebuf >> 24], fout);
    putc_unlocked(base64u_encode_table[(ebuf >> 16) & 0xFF], fout);
    putc_unlocked(base64u_encode_table[(ebuf >> 8) & 0xFF], fout);
    putc_unlocked(base64u_encode_table[ebuf & 0xFF], fout);
  }
  if (l == 2) {
    /* make a 18-bit group */
    ebuf  = *(unsigned const char*) p++ << 10;
    ebuf |= *(unsigned const char*) p++ << 2;
    ebuf += (ebuf & ~0xFFF);
    ebuf += (ebuf & ~0xFFF);
    ebuf += (ebuf & ~0x3F);
    ebuf += (ebuf & ~0x3F);
    putc_unlocked(base64u_encode_table[(ebuf >> 16) & 0xFF], fout);
    putc_unlocked(base64u_encode_table[(ebuf >> 8) & 0xFF], fout);
    putc_unlocked(base64u_encode_table[ebuf & 0xFF], fout);
  } else if (l == 1) {
    /* make a 12-bit group */
    ebuf = *(unsigned const char*) p++ << 4;
    ebuf += (ebuf & ~0x3F);
    ebuf += (ebuf & ~0x3F);
    putc_unlocked(base64u_encode_table[(ebuf >> 8) & 0xFF], fout);
    putc_unlocked(base64u_encode_table[ebuf & 0xFF], fout);
  }
}

/**
 * NAME:    base64u_encode_str
 * PURPOSE: convert a string into base64url-encoded string
 * ARGS:    in  - pointer to the input string
 *          out - pointer to the output string
 * RETURN:  strlen of the encoded string
 * NOTE:    buffer out must contain enough space
 *          to put all chars and '\0' terminator
 *          (base64-encoded string is larger than
 *          the original string in ratio 4/3)
 */
int
base64u_encode_str(char const *in, char *out)
{
  int n = base64u_encode(in, strlen(in), out);
  out[n] = 0;
  return n;
}

static char const base64u_decode_table [] =
{
  64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
  64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
  64,64,64,64,64,64,64,64,64,64,64,64,64,62,64,64,
  52,53,54,55,56,57,58,59,60,61,64,64,64,65,64,64,
  64,0 ,1 ,2 ,3 ,4 ,5 ,6 ,7 ,8 ,9 ,10,11,12,13,14,
  15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,63,
  64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
  41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64,
  64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
  64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
  64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
  64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
  64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
  64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
  64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
  64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64
};

/**
 * NAME:    base64u_decode
 * PURPOSE: convert base64url-encoded chars to plain chars
 * ARGS:    in    - pointer to the input char array
 *          size  - size of the input char array
 *          out   - pointer to the resulting char array
 *          pflag - if NULL, no action, else
 *                  in case of decode error (invalid padding or alignment)
 *                  set to 1, else set to 0
 * RETURN:  number of chars converted
 * NOTE:    buffer out must contain enough space to
 *          accomodate all decoded chars
 */
int
base64u_decode(char const *in, size_t size, char *out, int *pflag)
{
  unsigned char const *p = (unsigned char const*) in;
  char *s = out;
  int i = 0;

  if (pflag) *pflag = 0;
  while (i + 4 <= size) {
    unsigned cc = base64u_decode_table[*p++];
    if (cc >= 64) {
      if (*pflag) *pflag = 1;
      cc = 63;
    }
    unsigned b = cc << 18;
    cc = base64u_decode_table[*p++];
    if (cc >= 64) {
      if (*pflag) *pflag = 1;
      cc = 63;
    }
    b |= cc << 12;
    cc = base64u_decode_table[*p++];
    if (cc >= 64) {
      if (*pflag) *pflag = 1;
      cc = 63;
    }
    b |= cc << 6;
    cc = base64u_decode_table[*p++];
    if (cc >= 64) {
      if (*pflag) *pflag = 1;
      cc = 63;
    }
    b |= cc;
    *s++ = b >> 16;
    *s++ = b >> 8;
    *s++ = b;
    i += 4;
  }
  if (i + 3 == size) {
    unsigned cc = base64u_decode_table[*p++];
    if (cc >= 64) {
      if (*pflag) *pflag = 1;
      cc = 63;
    }
    unsigned b = cc << 18;
    cc = base64u_decode_table[*p++];
    if (cc >= 64) {
      if (*pflag) *pflag = 1;
      cc = 63;
    }
    b |= cc << 12;
    cc = base64u_decode_table[*p++];
    if (cc >= 64) {
      if (*pflag) *pflag = 1;
      cc = 63;
    }
    b |= cc << 6;
    *s++ = b >> 16;
    *s++ = b >> 8;
  } else if (i + 2 == size) {
    unsigned cc = base64u_decode_table[*p++];
    if (cc >= 64) {
      if (*pflag) *pflag = 1;
      cc = 63;
    }
    unsigned b = cc << 18;
    cc = base64u_decode_table[*p++];
    if (cc >= 64) {
      if (*pflag) *pflag = 1;
      cc = 63;
    }
    b |= cc << 12;
    *s++ = b >> 16;
  } else if (i + 1 == size) {
    if (*pflag) *pflag = 1;
  }
  return (int)(s - out);
}

/**
 * NAME:    base64u_decode_str
 * PURPOSE: convert base64url-encoded string to plain form
 * ARGS:    in    - pointer to the input string
 *          out   - pointer to the resulting string
 *          pflag - if NULL, no action, else
 *                  in case of decode error (invalid padding or alignment)
 *                  set to 1, else set to 0
 * RETURN:  strlen of decoded string
 * NOTE:    buffer out must have enough space to accomodate
 *          all decoded chars and '\0' terminator
 */
int
base64u_decode_str(char const *in, char *out, int *pflag)
{
  int n = base64u_decode(in, strlen(in), out, pflag);
  out[n] = 0;
  return n;
}
