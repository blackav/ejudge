/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2015-2020 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

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

#include "config.h"

#if defined EJUDGE_PRIMARY_USER
#define PRIMARY_USER EJUDGE_PRIMARY_USER
#else
#define PRIMARY_USER "ejudge"
#endif

#if defined EJUDGE_EXEC_USER
#define EXEC_USER EJUDGE_EXEC_USER
#define EXEC_GROUP EJUDGE_EXEC_USER
#else
#define EXEC_USER "ejexec"
#define EXEC_GROUP "ejexec"
#endif

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

#define MQUEUE_MOUNT_DIR "/dev/mqueue"

static int
scan_posix_mqueue(int search_uid, int *p_count, FILE *rep_f)
{
    int retval = 0;
    DIR *d = NULL;
    struct dirent *dd;

    if (!(d = opendir(MQUEUE_MOUNT_DIR))) {
        fprintf(stderr, "failed to open /dev/mqueue\n");
        return 0;
    }
    while ((dd = readdir(d))) {
        char buf[PATH_MAX];
        snprintf(buf, sizeof(buf), "%s/%s", MQUEUE_MOUNT_DIR, dd->d_name);
        // FIXME: correctly handle possible races?
        struct stat stb;
        if (lstat(buf, &stb) < 0) continue;
        if (!S_ISREG(stb.st_mode)) continue;
        if (stb.st_uid != search_uid) continue;
        fprintf(rep_f, "POSIX message queue: name = /%s, perms = %03o\n", dd->d_name, (stb.st_mode & 0777));
        unlink(buf); // is that correct?
    }
    closedir(d); d = NULL;

    return retval;
}

static int
scan_msg(int search_uid, int *p_count, FILE *rep_f)
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
            fprintf(rep_f, "message queue: key = 0x%08x, msgid = %d, perms = %03o\n", key, msgid, perms);
            if (msgctl(msgid, IPC_RMID, NULL) < 0) {
                fprintf(stderr, "msgctl failed: %s\n", strerror(errno));
            }
            retval = 1;
            ++*p_count;
        }
    }

    fclose(f);
    return retval;
}

static int
scan_sem(int search_uid, int *p_count, FILE *rep_f)
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
        int key = 0, semid = 0, perms = 0, nsems = 0, uid = 0, gid = 0, cuid = 0;
        if (sscanf(buf, "%d%d%o%d%d%d%d", &key, &semid, &perms, &nsems, &uid, &gid, &cuid) != 7) {
            fprintf(stderr, "format error in '/proc/sysvipc/sem'\n");
            return 1;
        }
        if (uid == search_uid || cuid == search_uid) {
            fprintf(rep_f, "semaphore array: key = 0x%08x, semid = %d, perms = %03o\n", key, semid, perms);
            if (semctl(semid, 0, IPC_RMID, NULL) < 0) {
                fprintf(stderr, "semctl failed: %s\n", strerror(errno));
            }
            retval = 1;
            ++*p_count;
        }
    }

    fclose(f);
    return retval;
}

static int
scan_shm(int search_uid, int *p_count, FILE *rep_f)
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
            fprintf(rep_f, "shared memory: key = 0x%08x, shmid = %d, perms = %03o\n", key, shmid, perms);
            if (shmctl(shmid, IPC_RMID, NULL) < 0) {
                fprintf(stderr, "shmctl failed: %s\n", strerror(errno));
            }
            retval = 1;
            ++*p_count;
        }
    }

    fclose(f);
    return retval;
}

int
main(int argc, char **argv)
{
    int primary_uid = -1;
    int exec_uid = -1;
    {
        struct passwd *pwd = getpwnam(EXEC_USER);
        if (!pwd) {
            fprintf(stderr, "%s: user '%s' does not exist\n", argv[0], EXEC_USER);
            abort();
        }
        exec_uid = pwd->pw_uid;
        if (exec_uid <= 0) {
            fprintf(stderr, "%s: user '%s' has uid %d\n", argv[0], EXEC_USER, exec_uid);
            abort();
        }
        endpwent();
    }
    {
        struct passwd *pwd = getpwnam(PRIMARY_USER);
        if (!pwd) {
            fprintf(stderr, "%s: user '%s' does not exist\n", argv[0], PRIMARY_USER);
            abort();
        }
        primary_uid = pwd->pw_uid;
        if (primary_uid <= 0) {
            fprintf(stderr, "%s: user '%s' has uid %d\n", argv[0], PRIMARY_USER, primary_uid);
            abort();
        }
        if (getuid() != primary_uid) {
            fprintf(stderr, "%s: only user '%s' can run this program\n", argv[0], PRIMARY_USER);
            abort();
        }
    }

    char *rep_s = NULL;
    size_t rep_z = 0;
    FILE *rep_f = open_memstream(&rep_s, &rep_z);
    int count = 0;
    int retval = scan_msg(exec_uid, &count, rep_f)
        | scan_sem(exec_uid, &count, rep_f)
        | scan_shm(exec_uid, &count, rep_f)
        | scan_posix_mqueue(exec_uid, &count, rep_f);
    fclose(rep_f); rep_f = NULL;
    if (count > 0) {
        printf("System V IPC scan found the following objects:\n");
        printf("%s", rep_s);
        printf("Total %d objects found\n", count);
    }
    return retval;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
