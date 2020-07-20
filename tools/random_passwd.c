#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>

static const char *progname = "";

static void die(const char *format, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void die(const char *format, ...)
{
  char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: fatal: %s\n", progname, buf);
  exit(1);
}

static char const base64_encode_table[]=
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_A";

static int
base64_encode(unsigned char const *in, size_t size, unsigned char *out)
{
  unsigned int   ebuf;
  int            nw = size / 3;
  int            l = size - nw * 3;
  int            i;
  unsigned char const    *p = in;
  unsigned char          *s = out;

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

int main(int argc, char *argv[])
{
  int nchars = 0;
  char *e = 0;
  int nbytes;
  int fd = -1;
  unsigned char *rbuf = 0, *obuf = 0;
  int obytes, olen;

  progname = argv[0];
  if (argc != 2) die("invalid number of args");

  errno = 0;
  nchars = strtol(argv[1], &e, 10);
  if (errno || *e) die("invalid argument");
  if (nchars <= 0 || nchars > 128) die("invalid argument");

  if (nchars % 4) {
    nbytes = nchars / 4 * 3 + 1;
  } else {
    nbytes = nchars / 4 * 3;
  }
  rbuf = (unsigned char*) alloca(nbytes + 1);

  if ((fd = open("/dev/urandom", O_RDONLY, 0)) < 0)
    die("cannot open /dev/urandom");
  if (read(fd, rbuf, nbytes) != nbytes)
    die("cannot read from /dev/urandom");
  close(fd); fd = -1;

  obytes = nbytes / 3 * 4 + 10;
  obuf = (unsigned char*) alloca(obytes);
  olen = base64_encode(rbuf, nbytes, obuf);
  obuf[olen] = 0;
  obuf[nchars] = 0;
  printf("%s\n", obuf);
  return 0;
}
