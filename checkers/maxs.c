#include <stdio.h>
#include <limits.h>

int
main(int argc, char *argv[])
{
  FILE *in, *tt;
  int   c, m = -1000000, r;

  if (argc <= 2) {
    fprintf(stderr, "Too few arguments\n");
    return 6;
  }
  if (!(in = fopen(argv[1], "r"))) {
    fprintf(stderr, "Cannot open input file '%s'\n", argv[1]);
    return 6;
  }
  while (fscanf(in, "%d", &c) == 1) {
    if (c > m) m = c;
  }
  fclose(in);
  if (!(tt = fopen(argv[2], "r"))) {
    fprintf(stderr, "Output file '%s' does not exist\n", argv[2]);
    return 4;
  }
  if (fscanf(tt, "%d", &r) != 1) {
    fprintf(stderr, "Cannot read the answer\n");
    return 4;
  }
  fscanf(tt, " ");
  if (getc(tt) != EOF) {
    fprintf(stderr, "Excess data\n");
    return 4;
  }
  fclose(tt);
  fprintf(stderr, "%d\n", m);
  if (r != m) {
    fprintf(stderr, "Wrong answer\n");
    return 5;
  }
  fprintf(stderr, "OK\n");
  return 0;
}

/**
 * Local variables:
 *  compile-command: "gcc maxs.c -o maxs"
 * End:
 */
