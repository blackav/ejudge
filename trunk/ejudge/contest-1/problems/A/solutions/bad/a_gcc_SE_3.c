/* $Id$ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>

void die(const char *format, ...)
    __attribute__((noreturn, format(printf, 1, 2)));
void die(const char *format, ...)
{
    char buf[1024];
    va_list args;

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    fprintf(stderr, "fatal: %s\n", buf);
    exit(1);
}

int main(void)
{
    int a, b, blen, pid;
    char buf[1024];
    int fd1[2], fd2[2];
    scanf("%d%d", &a, &b);
    snprintf(buf, sizeof(buf), "%d + %d\n", a, b);
    blen = strlen(buf);
    if (pipe(fd1) < 0) {}
    if (pipe(fd2) < 0) {}
    if (!(pid = fork())) {
        dup2(fd1[0], 0); close(fd1[0]); close(fd1[1]);
        dup2(fd2[1], 1); close(fd2[0]); close(fd2[1]);
        execlp("/usr/bin/bc", "/usr/bin/bc", "--quiet", NULL);
        die("execlp failed");
    } else if (pid < 0) {
        die("fork failed");
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
