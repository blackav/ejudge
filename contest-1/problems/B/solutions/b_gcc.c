#include <stdio.h>

int main(void)
{
  int s = 0, x;

  while (scanf("%d", &x) == 1)
    s += x;
  printf("%d\n", s);
  return 0;
}
