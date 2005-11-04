/* -*- mode: c -*- */
/* $Id$ */

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

static unsigned char *progname;
#ifdef __GNUC__
static void die(const char *format, ...)
  __attribute__((format(printf, 1, 2), noreturn));
#endif
static void
die(const char *format, ...)
{
  va_list args;
  unsigned char buf[1024];

  va_start(args, format);
#ifdef __GNUC__
  vsnprintf(buf, sizeof(buf), format, args);
#else
  vsprintf(buf, format, args);
#endif
  va_end(args);

  fprintf(stderr, "%s: %s\n", progname, buf);
  exit(1);
}

static char const base64_encode_table[]=
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int
base64_encode(char const *in, int size, char *out)
{
  unsigned       ebuf;
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
    *s++ = base64_encode_table[ebuf >> 24];
    *s++ = base64_encode_table[(ebuf >> 16) & 0xFF];
    *s++ = base64_encode_table[(ebuf >> 8) & 0xFF];
    *s++ = base64_encode_table[ebuf & 0xFF];
  }
  if (l == 2) {
    /* make a 18-bit group */
    ebuf  = *(unsigned const char*) p++ << 10;
    ebuf |= *(unsigned const char*) p++ << 2;
    ebuf += (ebuf & ~0xFFF);
    ebuf += (ebuf & ~0xFFF);
    ebuf += (ebuf & ~0x3F);
    ebuf += (ebuf & ~0x3F);
    *s++ = base64_encode_table[(ebuf >> 16) & 0xFF];
    *s++ = base64_encode_table[(ebuf >> 8) & 0xFF];
    *s++ = base64_encode_table[ebuf & 0xFF];
    *s++ = '=';
  } else if (l == 1) {
    /* make a 12-bit group */
    ebuf = *(unsigned const char*) p++ << 4;
    ebuf += (ebuf & ~0x3F);
    ebuf += (ebuf & ~0x3F);    
    *s++ = base64_encode_table[(ebuf >> 8) & 0xFF];
    *s++ = base64_encode_table[ebuf & 0xFF];
    *s++ = '=';
    *s++ = '=';
  }
  return s - out;
}

static void
generate_random_password(int fd, int size, unsigned char *buf)
{
  int rand_bytes;
  unsigned char *rnd_buf = 0;
  unsigned char *b64_buf = 0;
  unsigned char *p;
  int r, n;

  // estimate the number of random bytes to generate
  rnd_buf = (unsigned char*) alloca(size + 16);
  b64_buf = (unsigned char *) alloca(size + 16);
  if (size % 4) {
    rand_bytes = (size / 4 + 1) * 3;
  } else {
    rand_bytes = (size / 4) * 3;
  }

  // generate the needed number of bytes
  r = rand_bytes;
  p = rnd_buf;
  while (r > 0) {
    n = read(fd, p, r);
    if (n < 0) die("read from /dev/urandom failed: %s", strerror(errno));
    if (!n) die("EOF on /dev/urandom???");
    p += n;
    r -= n;
  }

  // convert to base64
  base64_encode(rnd_buf, rand_bytes, b64_buf);
  b64_buf[size] = 0;
  for (p = b64_buf; *p; p++) {
    /* rename: l, I, 1, O, 0*/
    switch (*p) {
    case 'l': *p = '!'; break;
    case 'I': *p = '@'; break;
    case '1': *p = '^'; break;
    case 'O': *p = '*'; break;
    case '0': *p = '-'; break;
    }
  }
  strcpy(buf, b64_buf);
}

int
main(int argc, char *argv[])
{
  int n, pwdlen, rand_fd;
  unsigned char pwdbuf[128];

  progname = argv[0];

  if (argc != 2) die("wrong number of parameters");
  if (sscanf(argv[1], "%d%n", &pwdlen, &n) != 1 || argv[1][n]
      || pwdlen <= 0 || pwdlen > 100) die("invalid parameter");
  if ((rand_fd = open("/dev/urandom", O_RDONLY, 0)) < 0)
    die("cannot open /dev/urandom");

  generate_random_password(rand_fd, pwdlen, pwdbuf);
  close(rand_fd);

  printf("%s\n", pwdbuf);

  return 0;
}

/*
 * Local variables:
 *  compile-command: "gcc -Wall -O2 -s genpasswd.c -o genpasswd"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "XML_Parser" "XML_Char" "XML_Encoding" "va_list" "gzFile")
 * End:
 */
