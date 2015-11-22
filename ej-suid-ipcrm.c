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
#include <ctype.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>

#define EXEC_USER "ejexec"
#define EXEC_GROUP "ejexec"

static int
getl(char *buf, size_t size, FILE *f)
{
    if (!fgets(buf, size, f)) return -1;
    size_t len = strlen(buf);
    if (len + 1 == size) {
        fprintf(stderr, "input line is too long, increase buffer size!\n");
        abort();
    }
    while (len > 0 && isspace(buf[len - 1])) --len;
    buf[len] = 0;
    return len;
}

static int
scan_msg(int search_uid)
{
    int retval = 0;
    char buf[1024];
    FILE *f = fopen("/proc/sysvipc/msg", "r");
    if (!f) {
        fprintf(stderr, "cannot open file '/proc/sysvipc/msg'\n");
        return 1;
    }
    if (getl(buf, sizeof(buf), f) < 0) {
        fprintf(stderr, "unexpected EOF in '/proc/sysvipc/msg'\n");
        return 1;
    }
    while (getl(buf, sizeof(buf), f) >= 0) {
        int key = 0, msgid = 0, perms = 0, cbytes = 0, qnum = 0, lspid = 0, lrpid = 0, uid = 0, gid = 0;
        if (sscanf(buf, "%d%d%o%d%d%d%d%d%d", &key, &msgid, &perms, &cbytes, &qnum, &lspid, &lrpid, &uid, &gid) != 9) {
            fprintf(stderr, "format error in '/proc/sysvipc/msg'\n");
            return 1;
        }
        if (uid == search_uid) {
            printf("message queue: key = 0x%08x, msgid = %d, perms = %03o\n", key, msgid, perms);
            if (msgctl(msgid, IPC_RMID, NULL) < 0) {
                fprintf(stderr, "msgctl failed: %s\n", strerror(errno));
            }
            retval = 1;
        }
    }

    fclose(f);
    return retval;
}

static int
scan_sem(int search_uid)
{
    int retval = 0;
    char buf[1024];
    FILE *f = fopen("/proc/sysvipc/sem", "r");
    if (!f) {
        fprintf(stderr, "cannot open file '/proc/sysvipc/sem'\n");
        return 1;
    }
    if (getl(buf, sizeof(buf), f) < 0) {
        fprintf(stderr, "unexpected EOF in '/proc/sysvipc/sem'\n");
        return 1;
    }
    while (getl(buf, sizeof(buf), f) >= 0) {
        int key = 0, semid = 0, perms = 0, nsems = 0, uid = 0, gid = 0;
        if (sscanf(buf, "%d%d%o%d%d%d", &key, &semid, &perms, &nsems, &uid, &gid) != 6) {
            fprintf(stderr, "format error in '/proc/sysvipc/sem'\n");
            return 1;
        }
        if (uid == search_uid) {
            printf("semaphore array: key = 0x%08x, msgid = %d, perms = %03o\n", key, semid, perms);
            if (semctl(semid, 0, IPC_RMID, NULL) < 0) {
                fprintf(stderr, "semctl failed: %s\n", strerror(errno));
            }
            retval = 1;
        }
    }

    fclose(f);
    return retval;
}

static int
scan_shm(int search_uid)
{
    int retval = 0;
    char buf[1024];
    FILE *f = fopen("/proc/sysvipc/shm", "r");
    if (!f) {
        fprintf(stderr, "cannot open file '/proc/sysvipc/shm'\n");
        return 1;
    }
    if (getl(buf, sizeof(buf), f) < 0) {
        fprintf(stderr, "unexpected EOF in '/proc/sysvipc/shm'\n");
        return 1;
    }
    while (getl(buf, sizeof(buf), f) >= 0) {
        int key = 0, shmid = 0, perms = 0, size = 0, cpid = 0, lpid = 0, nattch = 0, uid = 0, gid = 0;
        if (sscanf(buf, "%d%d%o%d%d%d%d%d%d", &key, &shmid, &perms, &size, &cpid, &lpid, &nattch, &uid, &gid) != 9) {
            fprintf(stderr, "format error in '/proc/sysvipc/shm'\n");
            return 1;
        }
        if (uid == search_uid) {
            printf("shared memory: key = 0x%08x, msgid = %d, perms = %03o\n", key, shmid, perms);
            if (shmctl(shmid, IPC_RMID, NULL) < 0) {
                fprintf(stderr, "shmctl failed: %s\n", strerror(errno));
            }
            retval = 1;
        }
    }

    fclose(f);
    return retval;
}

int
main(int argc, char **argv)
{
    struct passwd *pwd = getpwnam(EXEC_USER);
    endpwent();
    if (!pwd) {
        fprintf(stderr, "%s: user '%s' does not exist\n", argv[0], EXEC_USER);
        abort();
    }
    if (pwd->pw_uid <= 0) {
        fprintf(stderr, "%s: user '%s' has uid %d\n", argv[0], EXEC_USER, pwd->pw_uid);
        abort();
    }

    return scan_msg(pwd->pw_uid) | scan_sem(pwd->pw_uid) | scan_shm(pwd->pw_uid);
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
