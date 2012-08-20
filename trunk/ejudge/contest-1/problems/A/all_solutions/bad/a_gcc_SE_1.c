/* $Id$ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(void)
{
    int a, b, blen, pid;
    char buf[1024];
    int fd1[2], fd2[2];
    scanf("%d%d", &a, &b);
    snprintf(buf, sizeof(buf), "%d + %d\n", a, b);
    blen = strlen(buf);
    pipe(fd1);
    pipe(fd2);
    if (!(pid = fork())) {
        dup2(fd1[0], 0); close(fd1[0]); close(fd1[1]);
        dup2(fd2[1], 1); close(fd2[0]); close(fd2[1]);
        execlp("/usr/bin/bc", "/usr/bin/bc", "--quiet", NULL);
    }
    write(fd1[1], buf, blen);
    close(fd1[0]); close(fd1[1]);
    close(fd2[1]);
    blen = read(fd2[0], buf, sizeof(buf));
    buf[blen] = 0;
    printf("%s", buf);
    return 0;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
