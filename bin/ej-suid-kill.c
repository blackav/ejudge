#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#define EXEC_USER "ejexec"
#define EXEC_GROUP "ejexec"

int
main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "%s: wrong number of arguments\n", argv[0]);
        abort();
    }
    struct passwd *pwd = getpwnam(EXEC_USER);
    struct group *grp = getgrnam(EXEC_GROUP);
    endpwent();
    endgrent();
    if (!pwd) {
        fprintf(stderr, "%s: user '%s' does not exist\n", argv[0], EXEC_USER);
        abort();
    }
    if (pwd->pw_uid <= 0) {
        fprintf(stderr, "%s: user '%s' has uid %d\n", argv[0], EXEC_USER, pwd->pw_uid);
        abort();
    }
    if (!grp) {
        fprintf(stderr, "%s: group '%s' does not exist\n", argv[0], EXEC_GROUP);
        abort();
    }
    if (grp->gr_gid <= 0) {
        fprintf(stderr, "%s: group '%s' has gid %d\n", argv[0], EXEC_GROUP, grp->gr_gid);
        abort();
    }

    errno = 0;
    char *eptr = NULL;
    int dst_pid = strtol(argv[1], &eptr, 10);
    if (errno || *eptr || dst_pid < -1000000 || dst_pid > 1000000 || dst_pid == 0) {
        fprintf(stderr, "%s: invalid pid '%s'\n", argv[0], argv[1]);
        abort();
    }
    int kill_sig = strtol(argv[2], &eptr, 10);
    if (errno || *eptr || kill_sig < 0 || kill_sig > 64) {
        fprintf(stderr, "%s: invalid signal '%s'\n", argv[0], argv[1]);
        abort();
    }
    if (setgid(grp->gr_gid) < 0) {
        fprintf(stderr, "%s: setgid failed\n", argv[0]);
        abort();
    }
    if (setuid(pwd->pw_uid) < 0) {
        fprintf(stderr, "%s: setuid failed\n", argv[0]);
        abort();
    }
    return kill(dst_pid, kill_sig) < 0;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
