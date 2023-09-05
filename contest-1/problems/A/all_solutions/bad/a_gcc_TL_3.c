#include <stdio.h>

int main(void)
{
    char buf[4096];

    memset(buf, '0', sizeof(buf));
    buf[sizeof(buf) - 1] = 0;
    int count = 1024;

    int a, b, c;
    scanf("%d%d", &a, &b);
    c = a - 1;
    int s = 0;
    while (c != a) {
        b += c - a;
        s += c;
        --c;
        if (--count > 0) {
            printf("%s", buf); fflush(stdout);
        }
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
