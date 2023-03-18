/* -*- mode: c; c-basic-offset: 4 -*- */

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

static void
handle_sigmask_bits(const char *descr, unsigned long long mask, FILE *f)
{
   fprintf(f, "%s", descr);
    if (!mask) {
        fprintf(f, " none");
    } else {
        for (int i = 0; i < CHAR_BIT * sizeof(mask); ++i, mask >>= 1) {
            int n = i + 1;
            if ((mask & 1) != 0) {
                const char *abbrev = sigabbrev_np(n);
                if (abbrev) {
                    fprintf(f, " %s", sigabbrev_np(n));
                }
            }
        }
    }
    fprintf(f, "\n");
}

static unsigned long long
handle_sigmask(const char *descr, const char *str, FILE *f)
{
    char *eptr = NULL;
    errno = 0;
    unsigned long long mask = strtoull(str, &eptr, 16);
    if (errno || *eptr || eptr == str) {
        fprintf(stderr, "invalid signal mask for %s: %s\n", descr, str);
        return 0;
    }
    handle_sigmask_bits(descr, mask, f);
    return mask;
 }

static void
process_pid(int pid)
{
    char dirpath[PATH_MAX];

    if (snprintf(dirpath, sizeof(dirpath), "/proc/%d", pid) >= (int) sizeof(dirpath)) abort();
    struct stat stb;
    if (lstat(dirpath, &stb) < 0) {
        fprintf(stderr, "invalid pid %d\n", pid);
        return;
    }
    if (!S_ISDIR(stb.st_mode)) {
        fprintf(stderr, "invalid pid %d\n", pid);
        return;
    }

    char statpath[PATH_MAX];
    if (snprintf(statpath, sizeof(statpath), "/proc/%d/status", pid) >= (int) sizeof(statpath)) abort();
    FILE *f = fopen(statpath, "r");
    if (!f) {
        fprintf(stderr, "cannot open '%s': %s\n", statpath, strerror(errno));
        return;
    }
    unsigned long long blocked_bits = 0;
    unsigned long long ignored_bits = 0;
    unsigned long long handled_bits = 0;
    char buf[1024];
    while (fgets(buf, sizeof(buf), f)) {
        size_t l = strlen(buf);
        if (l + 1 == sizeof(buf)) {
            fprintf(stderr, "input string is too long\n");
            continue;
        }
        while (l > 0 && isspace((unsigned char) buf[l - 1])) --l;
        buf[l] = 0;
        if (!l) continue;

        if (!strncasecmp("name:", buf, 5)) {
            char *s = buf + 5;
            while (*s && isspace((unsigned char) *s)) ++s;
            if (*s) {
                printf("Name: %s\n", s);
            }
            continue;
        }
        if (!strncasecmp("shdpnd:", buf, 7)) {
            handle_sigmask("Pending signals:", buf + 7, stdout);
        } else if (!strncasecmp("sigblk:", buf, 7)) {
            blocked_bits = handle_sigmask("Blocked signals:", buf + 7, stdout);
        } else if (!strncasecmp("sigign:", buf, 7)) {
            ignored_bits = handle_sigmask("Ignored signals:", buf + 7, stdout);
        } else if (!strncasecmp("sigcgt:", buf, 7)) {
            handled_bits = handle_sigmask("Handled signals:", buf + 7, stdout);
        }
    }
    if ((handled_bits & blocked_bits) != 0) {
        handle_sigmask_bits("Blocked & handled", handled_bits & blocked_bits, stdout);
    }
    if ((handled_bits & ignored_bits) != 0) {
        handle_sigmask_bits("Ignored & handled", handled_bits & ignored_bits, stdout);
    }
    if ((ignored_bits & blocked_bits) != 0) {
        handle_sigmask_bits("Blocked & ignored", ignored_bits & blocked_bits, stdout);
    }

    fclose(f); f = NULL;
}

static void
process_pid_str(const char *pidstr)
{
    char *eptr = NULL;
    errno = 0;
    long v = strtol(pidstr, &eptr, 10);
    if (errno || *eptr || pidstr == eptr || v <= 0 || (int) v != v) {
        fprintf(stderr, "invalid pid: %s\n", pidstr);
        return;
    }

    process_pid((int) v);
}

int
main(int argc, char *argv[])
{
    if (argc == 1) {
        process_pid(getpid());
    } else {
        for (int i = 1; i < argc; ++i) {
            process_pid_str(argv[i]);
        }
    }
}
