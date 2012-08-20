/* $Id$ */

#include <stdio.h>

int main(void)
{
    int a, b, c;
    scanf("%d%d", &a, &b);
    c = a - 1;
    int s = 0;
    while (c != a) {
        b += c - a;
        s += c;
        --c;
    }
    b += c;
    s += c;
    printf("%d\n", b - s);
    return 0;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
