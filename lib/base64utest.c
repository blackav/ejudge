#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int base64u_encode(char const *in, size_t size, char *out);
int base64u_decode(char const *in, size_t size, char *out, int *pflag);

int main(int argc, char *argv[])
{
  int rfd = open("/dev/urandom", O_RDONLY);
  if (rfd < 0) abort();

  for (int testi = 0; testi < 100000; ++testi) {
    printf("\r%d", testi);
    unsigned len;
    if (read(rfd, &len, sizeof(len)) != sizeof(len)) abort();
    len &= 63;

    char *data = malloc(len);
    if (read(rfd, data, len) != len) abort();

    char *encdata = malloc(len + 64);
    unsigned enclen = base64u_encode(data, len, encdata);

    char *decdata = malloc(len + 64);
    int flag = 0;
    unsigned declen = base64u_decode(encdata, enclen, decdata, &flag);
    if (flag) {
      fprintf(stderr, "failed flag set\n");
      abort();
    }
    if (declen != len) {
      fprintf(stderr, "len mismatch: %u and %u\n", len, declen);
      abort();
    }
    if (memcmp(data, decdata, len) != 0) {
      fprintf(stderr, "decode mismatch\n");
      fprintf(stderr, "source size: %u\n", len);
      fprintf(stderr, "source bytes :");
      for (int i = 0; i < len; ++i) {
        fprintf(stderr, " %02x", (unsigned char) data[i]);
      }
      fprintf(stderr, "\n");
      fprintf(stderr, "encoded size: %u\n", enclen);
      fprintf(stderr, "encoded string: %.*s\n", enclen, encdata);
      fprintf(stderr, "decoded size: %u\n", declen);
      fprintf(stderr, "decoded bytes:");
      for (int i = 0; i < len; ++i) {
        fprintf(stderr, " %02x", (unsigned char) decdata[i]);
      }
      fprintf(stderr, "\n");
      abort();
    }
    free(decdata);
    free(encdata);
    free(data);
  }
  printf("\n");
}
