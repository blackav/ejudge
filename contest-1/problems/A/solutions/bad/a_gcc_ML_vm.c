/* $Id$ */

#include <stdio.h>
#include <stdlib.h>

int sub(int par, int a, int b)
{
    int *pm = calloc(1024 * 1024, sizeof(*pm));
    if (pm) {
        pm[0] = a;
        pm[1] = b;
    }
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
    printf("%d\n", sub(1000, a, b));
    return 0;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
