#include <stdio.h>

/*
 * argv[1] - input data
 * argv[2] - the program output
 * argv[3] - (not used) correct answer
 */

int
main(int argc, char *argv[])
{
  FILE *in, *tt;
  int   a, b, c;

  if (argc <= 2) {
    fprintf(stderr, "Too few arguments\n");
    return 6;
  }
  if (!(in = fopen(argv[1], "r"))) {
    fprintf(stderr, "Cannot open input file '%s'\n", argv[1]);
    return 6;
  }
  if (!(tt = fopen(argv[2], "r"))) {
    fprintf(stderr, "Presentation error: Output file '%s' does not exist\n",
            argv[2]);
    return 4;
  }
  if (fscanf(in, "%d%d", &a, &b) != 2) {
    fprintf(stderr, "Input error on source data\n");
    return 6;
  }
  if (fscanf(tt, "%d", &c) != 1) {
    fprintf(stderr, "Presentation error: cannot read the answer\n");
    return 4;
  }
  fscanf(tt, " ");
  if (getc(tt) != EOF) {
    fprintf(stderr, "Garbage at the end of file\n");
    return 4;
  }
  if (c != a + b) {
    fprintf(stderr, "Answer does not match");
    return 5;
  }

  fclose(in); fclose(tt);
  fprintf(stderr, "OK");
  return 0;
}
