/* $Id$ */

#include <stdio.h>

int sub(int par, int a, int b)
{
    if (par <= 0) {
        return a + b;
    } else {
        int c = sub(par - 1, a - 1, b + a);
        return c + 1 - a + sub(-1, a - b, b - a);
    }
}

int main(void)
{
    int a, b;
    scanf("%d%d", &a, &b);
    printf("%d\n", sub(100000000, a, b));
    return 0;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
