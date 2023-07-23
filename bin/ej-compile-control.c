/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2006-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/ej_types.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/ej_process.h"
#include "ejudge/osdeps.h"
#include "ejudge/logrotate.h"
#include "ejudge/startstop.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <errno.h>
#include <grp.h>
#include <dirent.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/time.h>

#define EXIT_SYSTEM_ERROR 2
#define EXIT_OPERATION_FAILED 1

#define DEFAULT_EJUDGE_PRIMARY_USER "ejudge"

#define EJ_COMPILE_PROGRAM "ej-compile"
#define EJ_COMPILE_PROGRAM_DELETED "ej-compile (deleted)"

#define PROC_DIRECTORY "/proc"
#define EXE_LINK "exe"

#define START_WAIT_COUNT 10

#define WAIT_TIMEOUT_US 30000000 // 30s

extern char **environ;

static const unsigned char *program_name = "ej-compile-control";

enum
{
    OPERATION_START = 1,
    OPERATION_STOP = 2,
    OPERATION_KILL = 3,
    OPERATION_RESTART = 4,
    OPERATION_HARD_RESTART = 5,
    OPERATION_STATUS = 6,
    OPERATION_ROTATE = 7,
};

static void
write_help(void)
{
  printf("%s: ej-compile control utility\n"
         "Usage: %s [OPTIONS] COMMAND\n"
         "  OPTIONS:\n"
         "    --help    write message and exit\n"
         "  COMMAND:\n"
         "    start     start the ej-compile\n"
         "    stop      stop the ej-compile\n"
         "    restart   restart the ej-compile\n"
         "    status    report the ej-compile status\n"
         "    rotate    rotate log file\n",
         program_name, program_name);
}

static void __attribute__((format(printf, 1, 2), noreturn))
system_error(const char *format, ...)
{
    va_list args;
    char buf[1024];

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    fprintf(stderr, "%s: %s\n", program_name, buf);
    exit(EXIT_SYSTEM_ERROR);
}

static void __attribute__((format(printf, 1, 2), noreturn))
syscall_error(const char *format, ...)
{
    va_list args;
    char buf[1024];
    int saved_errno = errno;

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    fprintf(stderr, "%s: %s: %s\n", program_name, buf, strerror(saved_errno));
    exit(EXIT_SYSTEM_ERROR);
}

struct EnvVector
{
    char **v;
    int u, a;
};

static void
env_init(struct EnvVector *ev)
{
    ev->a = 16;
    ev->v = malloc(ev->a * sizeof(ev->v[0]));
    ev->u = 0;
    ev->v[0] = NULL;
}

static void
env_set(struct EnvVector *ev, const unsigned char *name, const unsigned char *value)
{
    __attribute__((unused)) int _;
    if (!value) return;

    int namelen = strlen(name);
    for (int i = 0; i < ev->u; ++i) {
        if (!strncmp(ev->v[i], name, namelen) && ev->v[i][namelen] == '=') {
            free(ev->v[i]); ev->v[i] = NULL;
            _ = asprintf(&ev->v[i], "%s=%s", name, value);
            return;
        }
    }
    if (ev->u + 1 == ev->a) {
        ev->v = realloc(ev->v, (ev->a *= 2) * sizeof(ev->v[0]));
    }
    _ = asprintf(&ev->v[ev->u++], "%s=%s", name, value);
    ev->v[ev->u] = NULL;
}

static const unsigned char __attribute__((unused)) *
env_get(struct EnvVector *ev, const unsigned char *name)
{
   int namelen = strlen(name);
    for (int i = 0; i < ev->u; ++i) {
        if (!strncmp(ev->v[i], name, namelen) && ev->v[i][namelen] == '=') {
            return ev->v[i] + namelen + 1;
        }
    }
    return NULL;
 }

struct PidVector
{
    int *v;
    int u, a;
};

static void
pv_free(struct PidVector *pv)
{
    free(pv->v);
    memset(pv, 0, sizeof(*pv));
}

static int
find_all(
        const unsigned char *process_name,
        const unsigned char *process_name_deleted,
        const unsigned char *ns,
        struct PidVector *pv)
{
    unsigned char pidns[PATH_MAX];
    unsigned char curns[PATH_MAX];
    if (!ns) {
        start_get_pid_namespace(curns, sizeof(curns), 0);
        ns = curns;
    }

    DIR *d = opendir(PROC_DIRECTORY);
    if (!d) {
        fprintf(stderr, "%s: cannot open %s: %s\n", program_name, PROC_DIRECTORY, strerror(errno));
        return -1;
    }
    struct dirent *dd;
    while ((dd = readdir(d))) {
        char *ep = NULL;
        errno = 0;
        long val = strtol(dd->d_name, &ep, 10);
        if (errno || *ep || (int) val != val || val <= 0) continue;

        start_get_pid_namespace(pidns, sizeof(pidns), val);
        if (strcmp(ns, pidns) != 0)
            continue;

        unsigned char entry_path[PATH_MAX];
        if (snprintf(entry_path, sizeof(entry_path), "%s/%s/%s", PROC_DIRECTORY, dd->d_name, EXE_LINK) >= sizeof(entry_path)) {
            continue;
        }
        unsigned char exe_path[PATH_MAX];
        ssize_t exe_len = readlink(entry_path, exe_path, sizeof(exe_path));
        if (exe_len <= 0 || exe_len >= sizeof(exe_path)) continue;
        exe_path[exe_len] = 0;
        const unsigned char *ptr = strrchr(exe_path, '/');
        if (!ptr) {
            ptr = exe_path;
        } else {
            ++ptr;
        }
        if (!strcmp(ptr, process_name) || !strcmp(ptr, process_name_deleted)) {
            if (pv->u == pv->a) {
                if (!(pv->a *= 2)) pv->a = 16;
                pv->v = realloc(pv->v, pv->a * sizeof(pv->v[0]));
                if (!pv->v) {
                    system_error("out of memory");
                }
            }
            pv->v[pv->u++] = val;
        }
    }
    closedir(d); d = NULL;
    return 0;
}

static int
kill_all(int signal, struct PidVector *pv)
{
    for (int i = 0; i < pv->u; ++i) {
        if (kill(pv->v[i], signal) < 0) {
            if (errno == EPERM) {
                fprintf(stderr, "%s: cannot send signal to %d: %s\n", program_name, pv->v[i], strerror(errno));
            }
        }
    }
    return 0;
}

static int
check_process(
        int pid,
        const unsigned char *process_name,
        const unsigned char *process_name_deleted)
{
    unsigned char exelink_path[PATH_MAX];
    if (snprintf(exelink_path, sizeof(exelink_path), "%s/%d/%s", PROC_DIRECTORY, pid, EXE_LINK) >= sizeof(exelink_path)) {
        return 0;
    }
    unsigned char exe_path[PATH_MAX];
    ssize_t exe_len = readlink(exelink_path, exe_path, sizeof(exe_path));
    if (exe_len <= 0 || exe_len >= sizeof(exe_path)) {
        return 0;
    }
    exe_path[exe_len] = 0;
    const unsigned char *ptr = strrchr(exe_path, '/');
    if (!ptr) {
        ptr = exe_path;
    } else {
        ++ptr;
    }
    return !strcmp(ptr, process_name) || !strcmp(ptr, process_name_deleted);
}

static int __attribute__((unused))
check_processes(
        const unsigned char *process_name,
        const unsigned char *process_name_deleted,
        struct PidVector *pv)
{
    for (int i = 0; i < pv->u; ) {
        if (check_process(pv->v[i], process_name, process_name_deleted)) {
            ++i;
        } else {
            for (int j = i + 1; j < pv->u; ++j) {
                pv->v[j - 1] = pv->v[j];
            }
            --pv->u;
        }
    }
    return pv->u;
}

static int
start_process(
        const struct ejudge_cfg *config,
        const unsigned char *process_name,
        int log_fd,
        const unsigned char *workdir,
        struct EnvVector *ev,
        const unsigned char *exepath,
        int is_parallel,
        int replace_env,
        int *ej_xml_fds,
        int compile_parallelism,
        int serial,
        const char *agent,
        const char *instance_id,
        const char *queue,
        int verbose_mode,
        const char *ip_address,
        const char *halt_command,
        const char *reboot_command,
        const char *heartbeat_instance_id,
        const char *lang_id_map,
        const char *local_cache)
{
    int pid = fork();
    if (pid < 0) {
        fprintf(stderr, "%s: cannot create process: %s\n", program_name, strerror(errno));
        return -1;
    }
    if (pid > 0) {
        return 0;
    }

    // this is child code
    pid = fork();
    if (pid < 0) {
        _exit(1);
    }
    if (pid > 0) {
        _exit(0);
    }

    // grandchild
    setsid(); // new session
    setpgid(0, 0); // new process group

    // save old stderr
    int saved_stderr = dup(STDERR_FILENO);

    // redirect standard streams
    int fd0 = open("/dev/null", O_RDONLY, 0);
    if (fd0 < 0) _exit(1);
    if (dup2(fd0, 0) < 0) _exit(1);
    if (dup2(log_fd, 1) < 0) _exit(1);
    if (dup2(log_fd, 2) < 0) _exit(1);
    close(fd0); fd0 = -1;
    close(log_fd); log_fd = -1;

    // change directory
    if (workdir && *workdir) {
        if (chdir(workdir) < 0) _exit(1);
    }

    // enable all signals
    sigset_t ss;
    sigemptyset(&ss);
    sigprocmask(SIG_SETMASK, &ss, NULL);

    char *args[64];
    char lbuf[64];
    char ebuf[64];
    int argi = 0;
    args[argi++] = (char*) exepath;
    if (is_parallel) args[argi++] = "-p";
    if (ej_xml_fds && ej_xml_fds[serial] >= 0) {
        args[argi++] = "-l";
        snprintf(lbuf, sizeof(lbuf), "%d", ej_xml_fds[serial]);
        args[argi++] = lbuf;
    }
    if (saved_stderr >= 0) {
        args[argi++] = "-e";
        snprintf(ebuf, sizeof(ebuf), "%d", saved_stderr);
        args[argi++] = ebuf;
    }
    if (agent && *agent) {
        args[argi++] = "--agent";
        args[argi++] = (char*) agent;
    }
    if (instance_id && *instance_id) {
        args[argi++] = "--instance-id";
        args[argi++] = (char*) instance_id;
    }
    if (heartbeat_instance_id && *heartbeat_instance_id) {
        args[argi++] = "-hi";
        args[argi++] = (char*) heartbeat_instance_id;
    }
    if (ip_address && *ip_address) {
        args[argi++] = "--ip";
        args[argi++] = (char*) ip_address;
    }
    if (queue && *queue) {
        args[argi++] = "-I";
        args[argi++] = (char*) queue;
    }
    if (halt_command && *halt_command) {
        args[argi++] = "-hc";
        args[argi++] = (char*) halt_command;
    }
    if (reboot_command && *reboot_command) {
        args[argi++] = "-rc";
        args[argi++] = (char*) reboot_command;
    }
    if (lang_id_map && *lang_id_map) {
        args[argi++] = "--lang-id-map";
        args[argi++] = (char*) lang_id_map;
    }
    if (local_cache && *local_cache) {
        args[argi++] = "--local-cache";
        args[argi++] = (char*) local_cache;
    }
    if (verbose_mode) {
        args[argi++] = "-v";
    }
    args[argi++] = "-S";
    args[argi++] = "conf/compile.cfg";
    args[argi] = NULL;

    if (replace_env) {
        environ = ev->v;
    }

    if (ej_xml_fds) {
        for (int i = 0; i < compile_parallelism; ++i) {
            if (ej_xml_fds[i] >= 0 && i != serial) {
                close(ej_xml_fds[i]);
            }
        }
    }

    execve(exepath, args, environ);
    // nobody will know...
    _exit(1);
}

static int
signal_and_wait(int signo, const unsigned char *signame, long long timeout_us)
{
    struct PidVector pv = {};
    if (find_all(EJ_COMPILE_PROGRAM, EJ_COMPILE_PROGRAM_DELETED, NULL, &pv) < 0) {
        system_error("cannot enumerate processes");
    }
    if (pv.u <= 0) return 0;

    fprintf(stderr, "%s: %s is running as pids", program_name,
            EJ_COMPILE_PROGRAM);
    for (int i = 0; i < pv.u; ++i) {
        fprintf(stderr, " %d", pv.v[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "%s: sending it the %s signal\n", program_name, signame);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    long long t1 = tv.tv_sec * 1000000LL + tv.tv_usec;

    kill_all(signo, &pv);
    do {
        usleep(100000);
        pv_free(&pv);

        gettimeofday(&tv, NULL);
        long long t2 = tv.tv_sec * 1000000LL + tv.tv_usec;
        if (timeout_us > 0 && t1 + timeout_us <= t2) {
            fprintf(stderr, "%s: wait timed out\n", program_name);
            return -1;
        }
    } while (find_all(EJ_COMPILE_PROGRAM, EJ_COMPILE_PROGRAM_DELETED, NULL, &pv) >= 0 && pv.u > 0);
    pv_free(&pv);
    return 0;
}

static void
emergency_stop(void)
{
    // wait some reasonable time - 0.5s
    usleep(500000);

    signal_and_wait(SIGTERM, "TERM", WAIT_TIMEOUT_US);
}

static void
change_ownership_and_permissions(const unsigned char *dir, const unsigned char *name, int uid, int gid, int perms)
{
    unsigned char p[PATH_MAX];
    if (snprintf(p, sizeof(p), "%s/%s", dir, name) >= sizeof(p)) return;
    struct stat stb;
    if (stat(p, &stb) < 0 || !S_ISDIR(stb.st_mode)) return;
    __attribute__((unused)) int _;

    _ = chown(p, uid, gid);
    _ = chmod(p, perms);
}

static void
spool_change_ownership_and_permissions(const unsigned char *dir, const unsigned char *name, int uid, int gid, int perms)
{
    unsigned char p[PATH_MAX];
    if (snprintf(p, sizeof(p), "%s/%s", dir, name) >= sizeof(p)) return;
    struct stat stb;
    if (stat(p, &stb) < 0 || !S_ISDIR(stb.st_mode)) return;

    change_ownership_and_permissions(p, "dir", uid, gid, perms);
    change_ownership_and_permissions(p, "in", uid, gid, perms);
    change_ownership_and_permissions(p, "out", uid, gid, perms);
}

static void
check_directories_2(int primary_uid, int primary_gid, const struct ejudge_cfg *config)
{
    // check compile working directory
    unsigned char d1[PATH_MAX];
    unsigned char d2[PATH_MAX];
    unsigned char d3[PATH_MAX];
    unsigned char d4[PATH_MAX];
    struct stat stb;
    __attribute__((unused)) int _;

#if defined EJUDGE_LOCAL_DIR
    snprintf(d1, sizeof(d1), "%s", EJUDGE_LOCAL_DIR);
    if (stat(d1, &stb) < 0 || !S_ISDIR(stb.st_mode)) {
        system_error("directory '%s' does not exist", d1);
    }
    snprintf(d2, sizeof(d2), "%s/compile", d1);
    if (stat(d2, &stb) >= 0) {
        if (!S_ISDIR(stb.st_mode)) {
            system_error("'%s' is not a directory", d2);
        }
        _ = chown(d2, primary_uid, primary_gid);
        _ = chmod(d2, 0770);
    } else {
        if (mkdir(d2, 0770) < 0) {
            syscall_error("cannot create '%s'", d2);
        }
        _ = chown(d2, primary_uid, primary_gid);
        _ = chmod(d2, 0770);
    }
    snprintf(d3, sizeof(d3), "%s/work", d2);
    if (stat(d3, &stb) >= 0) {
        if (!S_ISDIR(stb.st_mode)) {
            system_error("'%s' is not a directory", d3);
        }
        _ = chown(d3, primary_uid, primary_gid);
        _ = chmod(d3, 0770);
    } else {
        if (mkdir(d3, 0770) < 0) {
            syscall_error("cannot create '%s'", d3);
        }
        _ = chown(d3, primary_uid, primary_gid);
        _ = chmod(d3, 0770);
    }
#endif
    d1[0] = 0;
    if (config && config->compile_home_dir && config->compile_home_dir[0]) {
        snprintf(d1, sizeof(d1), "%s", config->compile_home_dir);
    }
#if defined EJUDGE_CONTESTS_HOME_DIR
    if (!d1[0]) {
        snprintf(d1, sizeof(d1), "%s/compile", EJUDGE_CONTESTS_HOME_DIR);
    }
#endif
    if (stat(d1, &stb) < 0 || !S_ISDIR(stb.st_mode)) {
        system_error("'%s' is not a directory", d1);
    }
    snprintf(d2, sizeof(d2), "%s/var", d1);
    if (stat(d2, &stb) >= 0) {
        if (!S_ISDIR(stb.st_mode)) {
            system_error("'%s' is not a directory", d2);
        }
        _ = chown(d2, primary_uid, primary_gid);
        chmod(d2, 0755);
    } else {
        if (mkdir(d2, 0750) < 0) {
            syscall_error("cannot create '%s'", d2);
        }
        _ = chown(d2, primary_uid, primary_gid);
        _ = chmod(d2, 0755);
    }
    // reserve working directory
    snprintf(d3, sizeof(d3), "%s/work", d2);
    if (stat(d3, &stb) >= 0) {
        if (!S_ISDIR(stb.st_mode)) {
            system_error("'%s' is not a directory", d3);
        }
        _ = chown(d3, primary_uid, primary_gid);
        _ = chmod(d3, 0770);
    } else {
        if (mkdir(d3, 0755) < 0) {
            syscall_error("cannot create '%s'", d3);
        }
        _ = chown(d3, primary_uid, primary_gid);
        _ = chmod(d3, 0770);
    }

#if defined EJUDGE_COMPILE_SPOOL_DIR
    if (snprintf(d1, sizeof(d1), "%s", EJUDGE_COMPILE_SPOOL_DIR) >= sizeof(d1)) {
        system_error("path '%s' is too long", EJUDGE_COMPILE_SPOOL_DIR);
    }
    if (stat(d1, &stb) < 0) {
        system_error("directory '%s' does not exist. please, create it", d1);
    }
    if (!S_ISDIR(stb.st_mode)) {
        system_error("'%s' is not a directory", d1);
    }
    const unsigned char *compile_server_id = getenv("EJ_COMPILE_SERVER_ID");
    if (!compile_server_id || !*compile_server_id) {
        compile_server_id = os_NodeName();
    }
    if (!compile_server_id || !*compile_server_id) {
        compile_server_id = "localhost";
    }
    if (snprintf(d3, sizeof(d3), "%s/%s", d1, compile_server_id) >= sizeof(d3)) {
        system_error("path '%s/%s' is too long", d1, compile_server_id);
    }
#else
    // spool directory: /home/judges/compile/var
    snprintf(d3, sizeof(d3), "%s/compile", d2);
#endif

    if (stat(d3, &stb) >= 0) {
        if (!S_ISDIR(stb.st_mode)) {
            system_error("'%s' is not a directory", d3);
        }
        _ = chown(d3, primary_uid, primary_gid);
        _ = chmod(d3, 0770);
    } else {
        if (mkdir(d3, 0755) < 0) {
            syscall_error("cannot create '%s'", d3);
        }
        _ = chown(d3, primary_uid, primary_gid);
        _ = chmod(d3, 0770);
    }

    // spool directory skeleton
    snprintf(d4, sizeof(d4), "%s/upgrade-v2", d3);
    if (lstat(d4, &stb) >= 0) {
        if (!S_ISREG(stb.st_mode)) {
            system_error("'%s' is not a regular file", d4);
        }
        return;
    }

    change_ownership_and_permissions(d3, "src", primary_uid, primary_gid, 0770);
    spool_change_ownership_and_permissions(d3, "queue", primary_uid, primary_gid, 0770);

#if defined EJUDGE_COMPILE_SPOOL_DIR
    // scan all hosts in EJUDGE_COMPILE_SPOOL_DIR
    {
        DIR *hd = opendir(d1);
        if (hd) {
            struct dirent *hdd;
            while ((hdd = readdir(hd))) {
                if (!strcmp(hdd->d_name, ".") || !strcmp(hdd->d_name, "..")) continue;
                if (snprintf(d2, sizeof(d2), "%s/%s", d1, hdd->d_name) >= sizeof(d2)) {
                    system_error("path '%s/%s' is too long", d1, hdd->d_name);
                }
                if (stat(d2, &stb) < 0) continue;
                if (!S_ISDIR(stb.st_mode)) continue;

                DIR *d = opendir(d2);
                if (d) {
                    struct dirent *dd;
                    while ((dd = readdir(d))) {
                        if (strlen(dd->d_name) == 6) {
                            errno = 0;
                            char *eptr = 0;
                            long cnts_id = strtol(dd->d_name, &eptr, 10);
                            if (!errno && !*eptr && (int) cnts_id == cnts_id && cnts_id > 0) {
                                snprintf(d4, sizeof(d4), "%s/%s", d2, dd->d_name);
                                if (stat(d4, &stb) >= 0 && S_ISDIR(stb.st_mode)) {
                                    change_ownership_and_permissions(d4, "report", primary_uid, primary_gid, 0770);
                                    spool_change_ownership_and_permissions(d4, "status", primary_uid, primary_gid, 0770);
                                }
                            }
                        }
                    }
                    closedir(d);
                }

                snprintf(d4, sizeof(d4), "%s/upgrade-v2", d2);
                close(open(d4, O_WRONLY | O_CREAT | O_NONBLOCK, 0660));
            }

            closedir(hd);
        }
    }
#else
    {
        DIR *d = opendir(d3);
        if (d) {
            struct dirent *dd;
            while ((dd = readdir(d))) {
                if (strlen(dd->d_name) == 6) {
                    errno = 0;
                    char *eptr = 0;
                    long cnts_id = strtol(dd->d_name, &eptr, 10);
                    if (!errno && !*eptr && (int) cnts_id == cnts_id && cnts_id > 0) {
                        snprintf(d4, sizeof(d4), "%s/%s", d3, dd->d_name);
                        if (stat(d4, &stb) >= 0 && S_ISDIR(stb.st_mode)) {
                            change_ownership_and_permissions(d4, "report", primary_uid, primary_gid, 0770);
                            spool_change_ownership_and_permissions(d4, "status", primary_uid, primary_gid, 0770);
                        }
                    }
                }
            }
            closedir(d);
        }
    }
#endif

    snprintf(d4, sizeof(d4), "%s/upgrade-v2", d3);
    close(open(d4, O_WRONLY | O_CREAT | O_NONBLOCK, 0660));
}

static void
check_directories(int primary_uid, int compile_uid, int primary_gid, int compile_gid, const struct ejudge_cfg *config)
{
    // check compile working directory
    unsigned char d1[PATH_MAX];
    unsigned char d2[PATH_MAX];
    unsigned char d3[PATH_MAX];
    unsigned char d4[PATH_MAX];
    struct stat stb;
    __attribute__((unused)) int _;

#if defined EJUDGE_LOCAL_DIR
    snprintf(d1, sizeof(d1), "%s", EJUDGE_LOCAL_DIR);
    if (stat(d1, &stb) < 0 || !S_ISDIR(stb.st_mode)) {
        system_error("directory '%s' does not exist", d1);
    }
    snprintf(d2, sizeof(d2), "%s/compile", d1);
    if (stat(d2, &stb) >= 0) {
        if (!S_ISDIR(stb.st_mode)) {
            system_error("'%s' is not a directory", d2);
        }
    } else {
        if (mkdir(d2, 0755) < 0) {
            syscall_error("cannot create '%s'", d2);
        }
    }
    snprintf(d3, sizeof(d3), "%s/work", d2);
    if (stat(d3, &stb) >= 0) {
        if (!S_ISDIR(stb.st_mode)) {
            system_error("'%s' is not a directory", d3);
        }
        // must be group-writable
        if (stb.st_gid != compile_gid) {
            _ = chown(d3, -1, compile_gid);
            _ = chmod(d3, 06775);
        }
    } else {
        if (mkdir(d3, 0755) < 0) {
            syscall_error("cannot create '%s'", d3);
        }
        _ = chown(d3, primary_uid, compile_gid);
        _ = chmod(d3, 06775);
    }
#endif
    d1[0] = 0;
    if (config && config->compile_home_dir && config->compile_home_dir[0]) {
        snprintf(d1, sizeof(d1), "%s", config->compile_home_dir);
    }
#if defined EJUDGE_CONTESTS_HOME_DIR
    if (!d1[0]) {
        snprintf(d1, sizeof(d1), "%s/compile", EJUDGE_CONTESTS_HOME_DIR);
    }
#endif
    if (stat(d1, &stb) < 0 || !S_ISDIR(stb.st_mode)) {
        system_error("'%s' is not a directory", d1);
    }
    snprintf(d2, sizeof(d2), "%s/var", d1);
    if (stat(d2, &stb) >= 0) {
        if (!S_ISDIR(stb.st_mode)) {
            system_error("'%s' is not a directory", d2);
        }
    } else {
        if (mkdir(d2, 0755) < 0) {
            syscall_error("cannot create '%s'", d2);
        }
        _ = chown(d3, primary_uid, primary_gid);
        _ = chmod(d3, 0755);
    }
    // reserve working directory
    snprintf(d3, sizeof(d3), "%s/work", d2);
    if (stat(d3, &stb) >= 0) {
        if (!S_ISDIR(stb.st_mode)) {
            system_error("'%s' is not a directory", d3);
        }
        // must be group-writable
        if (stb.st_gid != compile_gid) {
            _ = chown(d3, -1, compile_gid);
            _ = chmod(d3, 06775);
        }
    } else {
        if (mkdir(d3, 0755) < 0) {
            syscall_error("cannot create '%s'", d3);
        }
        _ = chown(d3, primary_uid, compile_gid);
        _ = chmod(d3, 06775);
    }

#if defined EJUDGE_COMPILE_SPOOL_DIR
    if (snprintf(d1, sizeof(d1), "%s", EJUDGE_COMPILE_SPOOL_DIR) >= sizeof(d1)) {
        system_error("path '%s' is too long", EJUDGE_COMPILE_SPOOL_DIR);
    }
    if (stat(d1, &stb) < 0) {
        system_error("directory '%s' does not exist. please, create it", d1);
    }
    if (!S_ISDIR(stb.st_mode)) {
        system_error("'%s' is not a directory", d1);
    }
    const unsigned char *compile_server_id = getenv("EJ_COMPILE_SERVER_ID");
    if (!compile_server_id || !*compile_server_id) {
        compile_server_id = os_NodeName();
    }
    if (!compile_server_id || !*compile_server_id) {
        compile_server_id = "localhost";
    }
    if (snprintf(d3, sizeof(d3), "%s/%s", d1, compile_server_id) >= sizeof(d3)) {
        system_error("path '%s/%s' is too long", d1, compile_server_id);
    }
#else
    // spool directory: /home/judges/compile/var
    snprintf(d3, sizeof(d3), "%s/compile", d2);
#endif

    if (stat(d3, &stb) >= 0) {
        if (!S_ISDIR(stb.st_mode)) {
            system_error("'%s' is not a directory", d3);
        }
        // must be group-writable
        if (stb.st_gid != compile_gid) {
            _ = chown(d3, -1, compile_gid);
            _ = chmod(d3, 06775);
        }
    } else {
        if (mkdir(d3, 0755) < 0) {
            syscall_error("cannot create '%s'", d3);
        }
        _ = chown(d3, primary_uid, compile_gid);
        _ = chmod(d3, 06775);
    }

    // spool directory skeleton
    snprintf(d4, sizeof(d4), "%s/upgrade-v2", d3);
    if (lstat(d4, &stb) >= 0) {
        if (!S_ISREG(stb.st_mode)) {
            system_error("'%s' is not a regular file", d4);
        }
        return;
    }

    change_ownership_and_permissions(d3, "src", primary_uid, compile_gid, 06777);
    spool_change_ownership_and_permissions(d3, "queue", primary_uid, compile_gid, 06777);

#if defined EJUDGE_COMPILE_SPOOL_DIR
    // scan all hosts in EJUDGE_COMPILE_SPOOL_DIR
    {
        DIR *hd = opendir(d1);
        if (hd) {
            struct dirent *hdd;
            while ((hdd = readdir(hd))) {
                if (!strcmp(hdd->d_name, ".") || !strcmp(hdd->d_name, "..")) continue;
                if (snprintf(d2, sizeof(d2), "%s/%s", d1, hdd->d_name) >= sizeof(d2)) {
                    system_error("path '%s/%s' is too long", d1, hdd->d_name);
                }
                if (stat(d2, &stb) < 0) continue;
                if (!S_ISDIR(stb.st_mode)) continue;

                DIR *d = opendir(d2);
                if (d) {
                    struct dirent *dd;
                    while ((dd = readdir(d))) {
                        if (strlen(dd->d_name) == 6) {
                            errno = 0;
                            char *eptr = 0;
                            long cnts_id = strtol(dd->d_name, &eptr, 10);
                            if (!errno && !*eptr && (int) cnts_id == cnts_id && cnts_id > 0) {
                                snprintf(d4, sizeof(d4), "%s/%s", d2, dd->d_name);
                                if (stat(d4, &stb) >= 0 && S_ISDIR(stb.st_mode)) {
                                    change_ownership_and_permissions(d4, "report", primary_uid, compile_gid, 06777);
                                    spool_change_ownership_and_permissions(d4, "status", primary_uid, compile_gid, 06777);
                                }
                            }
                        }
                    }
                    closedir(d);
                }

                snprintf(d4, sizeof(d4), "%s/upgrade-v2", d2);
                close(open(d4, O_WRONLY | O_CREAT | O_NONBLOCK, 0660));
            }

            closedir(hd);
        }
    }
#else
    {
        DIR *d = opendir(d3);
        if (d) {
            struct dirent *dd;
            while ((dd = readdir(d))) {
                if (strlen(dd->d_name) == 6) {
                    errno = 0;
                    char *eptr = 0;
                    long cnts_id = strtol(dd->d_name, &eptr, 10);
                    if (!errno && !*eptr && (int) cnts_id == cnts_id && cnts_id > 0) {
                        snprintf(d4, sizeof(d4), "%s/%s", d3, dd->d_name);
                        if (stat(d4, &stb) >= 0 && S_ISDIR(stb.st_mode)) {
                            change_ownership_and_permissions(d4, "report", primary_uid, compile_gid, 06777);
                            spool_change_ownership_and_permissions(d4, "status", primary_uid, compile_gid, 06777);
                        }
                    }
                }
            }
            closedir(d);
        }
    }
#endif

    snprintf(d4, sizeof(d4), "%s/upgrade-v2", d3);
    close(open(d4, O_WRONLY | O_CREAT | O_NONBLOCK, 0660));
}

int main(int argc, char *argv[])
{
    int *ejudge_xml_fds = NULL;
    const char *agent = NULL;
    const char *instance_id = NULL;
    const char *queue = NULL;
    int verbose_mode = 0;
    int res;
    long long timeout_us = -1;
    int date_suffix_flag = 0;
    const char *ip_address = NULL;
    const char *halt_command = NULL;
    const char *reboot_command = NULL;
    const char *heartbeat_instance_id = NULL;
    const char *lang_id_map = NULL;
    const char *local_cache = NULL;

    if (argc < 1) {
        system_error("no arguments");
    }

    {
        const unsigned char *p = strrchr(argv[0], '/');
        if (!p) {
            program_name = argv[0];
        } else {
            program_name = p + 1;
        }
    }

    const unsigned char *operation = NULL;
    int op = 0;
    {
        int aidx = 1;
        while (aidx < argc) {
            if (!strcmp(argv[aidx], "--help")) {
                write_help();
                return 0;
            } else if (!strcmp(argv[aidx], "--agent")) {
                if (aidx + 1 >= argc) {
                    system_error("argument expected for --agent");
                }
                agent = argv[aidx + 1];
                aidx += 2;
            } else if (!strcmp(argv[aidx], "--instance-id")) {
                if (aidx + 1 >= argc) {
                    system_error("argument expected for --instance-id");
                }
                instance_id = argv[aidx + 1];
                aidx += 2;
            } else if (!strcmp(argv[aidx], "-hi")) {
                if (aidx + 1 >= argc) {
                    system_error("argument expected for -hi");
                }
                heartbeat_instance_id = argv[aidx + 1];
                aidx += 2;
            } else if (!strcmp(argv[aidx], "--queue")) {
                if (aidx + 1 >= argc) {
                    system_error("argument expected for --queue");
                }
                queue = argv[aidx + 1];
                aidx += 2;
            } else if (!strcmp(argv[aidx], "--ip")) {
                if (aidx + 1 >= argc) {
                    system_error("argument expected for --ip");
                }
                ip_address = argv[aidx + 1];
                aidx += 2;
            } else if (!strcmp(argv[aidx], "-hc")) {
                if (aidx + 1 >= argc) {
                    system_error("argument expected for -hc");
                }
                halt_command = argv[aidx + 1];
                aidx += 2;
            } else if (!strcmp(argv[aidx], "-rc")) {
                if (aidx + 1 >= argc) {
                    system_error("argument expected for -rc");
                }
                reboot_command = argv[aidx + 1];
                aidx += 2;
            } else if (!strcmp(argv[aidx], "--lang-id-map")) {
                if (aidx + 1 >= argc) {
                    system_error("argument expected for --lang-id-map");
                }
                lang_id_map = argv[aidx + 1];
                aidx += 2;
            } else if (!strcmp(argv[aidx], "--local-cache")) {
                if (aidx + 1 >= argc) {
                    system_error("argument expected for --local-cache");
                }
                local_cache = argv[aidx + 1];
                aidx += 2;
            } else if (!strcmp(argv[aidx], "--timeout")) {
                if (aidx + 1 >= argc) {
                    system_error("argument expected for --timeout");
                }
                const char *v = argv[aidx + 1];
                aidx += 2;
                char *eptr = NULL;
                errno = 0;
                long vv = strtol(v, &eptr, 10);
                if (errno || *eptr || eptr == v || vv < 0 || vv > 3600) {
                    system_error("invalid argument for --timeout");
                }
                timeout_us = vv * 1000000LL;
            } else if (!strcmp(argv[aidx], "-v")) {
                verbose_mode = 1;
                ++aidx;
            } else if (!strcmp(argv[aidx], "--date-suffix")) {
                ++aidx;
                date_suffix_flag = 1;
            } else if (!strcmp(argv[aidx], "--")) {
                ++aidx;
                break;
            } else if (argv[aidx][0] == '-') {
                system_error("invalid option '%s'", argv[aidx]);
            } else {
                break;
            }
        }
        if (aidx != argc - 1) {
            // ignore remaining args -- for compatibility
            //system_error("invalid command line");
        }
        operation = argv[aidx];
    }
    if (!operation) {
        system_error("no operation");
    }
    if (!strcmp(operation, "start")) {
        op = OPERATION_START;
    } else if (!strcmp(operation, "stop")) {
        op = OPERATION_STOP;
    } else if (!strcmp(operation, "kill")) {
        op = OPERATION_KILL;
    } else if (!strcmp(operation, "restart")) {
        op = OPERATION_RESTART;
    } else if (!strcmp(operation, "hard-restart")) {
        op = OPERATION_HARD_RESTART;
    } else if (!strcmp(operation, "status")) {
        op = OPERATION_STATUS;
    } else if (!strcmp(operation, "rotate")) {
        op = OPERATION_ROTATE;
    } else {
        system_error("invalid operation '%s'", operation);
    }

    if (timeout_us < 0) {
        timeout_us = WAIT_TIMEOUT_US;
    }

    uid_t ruid = -1, euid = -1, suid = -1;

    getresuid(&ruid, &euid, &suid);
    // drop privileges for a while
    if (setresuid(-1, ruid, euid) < 0) {
        syscall_error("setresuid failed");
    }

    int compile_uid = -1;
    int compile_gid = -1;
    int primary_uid = -1;
    int primary_gid = -1;
    int current_uid = -1;
    unsigned char compile_home[PATH_MAX] = {};
#if defined EJUDGE_COMPILE_USER
    // privilege separation mode
    {
        struct passwd *upwd = getpwnam(EJUDGE_COMPILE_USER);
        if (!upwd) {
            system_error("no user '%s'", EJUDGE_COMPILE_USER);
        }
        compile_uid = upwd->pw_uid;
        compile_gid = upwd->pw_gid;
        if (snprintf(compile_home, sizeof(compile_home), "%s", upwd->pw_dir) >= sizeof(compile_home)) {
            system_error("invalid home directory");
        }
        const unsigned char *primary_user = NULL;
#if defined EJUDGE_PRIMARY_USER
        primary_user = EJUDGE_PRIMARY_USER;
#else
        primary_user = DEFAULT_EJUDGE_PRIMARY_USER;
#endif
        upwd = getpwnam(primary_user);
        if (!upwd) {
            system_error("no user '%s'", primary_user);
        }
        primary_uid = upwd->pw_uid;
        primary_gid = upwd->pw_gid;
    }
#endif
    current_uid = getuid();
    if (primary_uid != compile_uid) {
        // disallow running this program by unwanted users
        if (current_uid != 0 && current_uid != primary_uid) {
            system_error("this program cannot be run by this user");
        }
    }

    struct ejudge_cfg *config = NULL;
    const unsigned char *ejudge_xml_path = NULL;
#if defined EJUDGE_XML_PATH
    if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */
    if (!(config = ejudge_cfg_parse(ejudge_xml_path, 1))) {
        system_error("failed to parse '%s'", ejudge_xml_path);
    }

    unsigned char **host_names = NULL;
    if (!(host_names = ejudge_get_host_names())) {
        system_error("cannot obtain the list of host names");
    }
    if (!host_names[0]) {
        system_error("cannot determine the name of the host");
    }

    int compile_parallelism = 1;
    compile_parallelism = ejudge_cfg_get_host_option_int(config, host_names, "compile_parallelism", 1, 0);
    if (compile_parallelism <= 0 || compile_parallelism > 128) {
        system_error("invalid value of compile_parallelism host option");
    }

    ejudge_xml_fds = malloc(compile_parallelism * sizeof(ejudge_xml_fds[0]));
    memset(ejudge_xml_fds, -1, compile_parallelism * sizeof(ejudge_xml_fds[0]));
    if (primary_uid != compile_uid) {
        for (int i = 0; i < compile_parallelism; ++i) {
            ejudge_xml_fds[i] = open(ejudge_xml_path, O_RDONLY);
            if (ejudge_xml_fds[i] < 0) {
                system_error("cannot open '%s'", ejudge_xml_path);
            }
        }
    }

    // open log path before changing the user
    unsigned char logpath[PATH_MAX] = {};
    int log_fd = -1;
#if defined EJUDGE_CONTESTS_HOME_DIR
    if (!logpath[0]) {
      if (snprintf(logpath, sizeof(logpath), "%s/var/ej-compile.log", EJUDGE_CONTESTS_HOME_DIR) >= sizeof(logpath)) {
        system_error("log path is too long");
      }
    }
#endif
    if (!logpath[0]) {
      system_error("compile log file is not specified");
    }
    log_fd = open(logpath, O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK, 0600);
    if (log_fd < 0) {
        syscall_error("cannot open log file '%s'", logpath);
    }
    struct stat stb;
    fstat(log_fd, &stb);
    if (!S_ISREG(stb.st_mode)) {
        system_error("log file '%s' is not regular", logpath);
    }
    fcntl(log_fd, F_SETFL, fcntl(log_fd, F_GETFL) & ~O_NONBLOCK);

    unsigned char workdir[PATH_MAX] = {};
    if (config && config->compile_home_dir && config->compile_home_dir[0]) {
        if (snprintf(workdir, sizeof(workdir), "%s", config->compile_home_dir) >= sizeof(workdir)) {
            system_error("invalid working directory");
        }
    }
#if defined EJUDGE_CONTESTS_HOME_DIR
    if (!workdir[0]) {
        if (snprintf(workdir, sizeof(workdir), "%s/compile", EJUDGE_CONTESTS_HOME_DIR) >= sizeof(workdir)) {
            system_error("invalid working directory");
        }
    }
#endif
    if (!workdir[0]) {
        system_error("working directory not specified");
    }
    if (stat(workdir, &stb) < 0) {
        system_error("working directory does not exist");
    }
    if (!S_ISDIR(stb.st_mode)) {
        system_error("invalid working directory");
    }

    unsigned char ej_compile_path[PATH_MAX];
    if (snprintf(ej_compile_path, sizeof(ej_compile_path), "%s/%s", EJUDGE_SERVER_BIN_PATH, EJ_COMPILE_PROGRAM) >= sizeof(ej_compile_path)) {
        system_error("invalid ej-compile path");
    }

    if (op == OPERATION_ROTATE) {
        unsigned char log_dir[PATH_MAX];
        log_dir[0] = 0;
#if defined EJUDGE_CONTESTS_HOME_DIR
        if (!log_dir[0]) {
            snprintf(log_dir, sizeof(log_dir), "%s/var", EJUDGE_CONTESTS_HOME_DIR);
        }
#endif
        if (!log_dir[0] && config->var_dir && config->var_dir[0]) {
            snprintf(log_dir, sizeof(log_dir), "%s", config->var_dir);
        }
        if (!log_dir[0] && config->contests_home_dir && config->contests_home_dir[0]) {
            snprintf(log_dir, sizeof(log_dir), "%s/var", config->contests_home_dir);
        }
        if (!log_dir[0]) {
            system_error("ej-compile log dir is undefined");
        }
        const unsigned char *log_group = NULL;
        if (config->enable_compile_container > 0) {
#if defined EJUDGE_PRIMARY_USER
            log_group = EJUDGE_PRIMARY_USER;
#endif
        } else {
#if defined EJUDGE_COMPILE_USER
            log_group = EJUDGE_COMPILE_USER;
#endif
        }
        rotate_log_files(log_dir, "ej-compile.log", NULL, NULL, log_group, 0620, date_suffix_flag);
    }

    struct EnvVector ev = {};
    env_init(&ev);
    if (1 /*primary_uid != compile_uid*/) {
        if (primary_uid != compile_uid) {
#if defined EJUDGE_COMPILE_USER
            env_set(&ev, "USER", EJUDGE_COMPILE_USER);
            env_set(&ev, "LOGNAME", EJUDGE_COMPILE_USER);
#endif
            env_set(&ev, "HOME", compile_home);
        } else {
            env_set(&ev, "USER", getenv("USER"));
            env_set(&ev, "LOGNAME", getenv("LOGNAME"));
            env_set(&ev, "HOME", getenv("HOME"));
        }

        env_set(&ev, "TMPDIR", "/var/tmp");
        for (char **curenv = environ; *curenv; ++curenv) {
            const char *ee = *curenv;
            const char *ep = strchr(ee, '=');
            if (!ep) continue;
            int namelen = ep - ee + 1;
            if (namelen <= 0) continue;
            // whitelisted env vars
            if (!strncmp("HOSTNAME=", ee, namelen)) {
                env_set(&ev, "HOSTNAME", ep + 1);
            } else if (!strncmp("SHELL=", ee, namelen)) {
                env_set(&ev, "SHELL", ep + 1);
            } else if (!strncmp("PATH=", ee, namelen)) {
                env_set(&ev, "PATH", ep + 1);
            } else if (!strncmp("LANG=", ee, namelen)) {
                env_set(&ev, "LANG", ep + 1);
            } else if (!strncmp("EJ_COMPILE_SERVER_ID=", ee, namelen)) {
                env_set(&ev, "EJ_COMPILE_SERVER_ID", ep + 1);
            }
        }
    }

    if (op == OPERATION_START && primary_uid != compile_uid) {
        if (config->enable_compile_container) {
            check_directories_2(primary_uid, primary_gid, config);
        } else {
            check_directories(primary_uid, primary_gid, compile_uid, compile_gid, config);
        }
    }

    if (setresuid(-1, euid, euid) < 0) {
        syscall_error("setresuid failed");
    }
    if (config->enable_compile_container) {
        // in this mode the ej-compile service is started as ejudge
        // and ej-suid-container is responsible for switching to ejcompile
        if (setgid(primary_gid) < 0) {
            syscall_error("cannot change group to %d", primary_gid);
        }
        int supp_groups[1] = { primary_gid };
        if (setgroups(1, supp_groups) < 0) {
            syscall_error("cannot change groups to %d", primary_gid);
        }
        if (setuid(primary_uid) < 0) {
            syscall_error("cannot change user to %d", primary_uid);
        }
    } else if (primary_uid != compile_uid) {
        // change the identity
        if (setgid(compile_gid) < 0) {
            syscall_error("cannot change group to %d", compile_gid);
        }
        int supp_groups[1] = { compile_gid };
        if (setgroups(1, supp_groups) < 0) {
            syscall_error("cannot change groups to %d", compile_gid);
        }
        if (setuid(compile_uid) < 0) {
            syscall_error("cannot change user to %d", compile_uid);
        }
    }

    switch (op) {
    case OPERATION_HARD_RESTART:
        res = signal_and_wait(SIGTERM, "TERM", timeout_us);
        if (res < 0) {
            return EXIT_OPERATION_FAILED;
        }
        // FALLTHROUGH
    case OPERATION_START:
        {
            struct PidVector pv = {};

            if (find_all(EJ_COMPILE_PROGRAM, EJ_COMPILE_PROGRAM_DELETED, NULL, &pv) < 0) {
                system_error("cannot enumerate processes");
            }
            if (pv.u > 0) {
                printf("%s already running as:", EJ_COMPILE_PROGRAM);
                for (int i = 0; i < pv.u; ++i) {
                    printf(" %d", pv.v[i]);
                }
                printf("\n");
                return EXIT_OPERATION_FAILED;
            }

            for (int i = 0; i < compile_parallelism; ++i) {
                int ret = start_process(config, EJ_COMPILE_PROGRAM, log_fd, workdir, &ev, ej_compile_path, compile_parallelism > 1, 1 /* FIXME */, ejudge_xml_fds, compile_parallelism, i, agent, instance_id, queue, verbose_mode, ip_address, halt_command, reboot_command, heartbeat_instance_id, lang_id_map, local_cache);
                if (ret < 0) {
                    emergency_stop();
                    return EXIT_SYSTEM_ERROR;
                }
            }

            int sleep_count = 0;
            // wait 1s max
            while (sleep_count < START_WAIT_COUNT) {
                pv_free(&pv);
                usleep(100000);
                if (find_all(EJ_COMPILE_PROGRAM, EJ_COMPILE_PROGRAM_DELETED, NULL, &pv) < 0) {
                    system_error("cannot enumerate processes");
                }
                if (pv.u == compile_parallelism) break;
                ++sleep_count;
            }
            if (sleep_count >= START_WAIT_COUNT) {
                system_error("failed to start ej-compile, please see the logs");
            }
        }
        break;
    case OPERATION_STOP:
        res = signal_and_wait(SIGTERM, "TERM", timeout_us);
        if (res < 0) {
            return EXIT_OPERATION_FAILED;
        }
        break;
    case OPERATION_KILL:
        res = signal_and_wait(SIGKILL, "KILL", timeout_us);
        if (res < 0) {
            return EXIT_OPERATION_FAILED;
        }
        break;
    case OPERATION_RESTART:
        {
            struct PidVector pv = {};

            if (find_all(EJ_COMPILE_PROGRAM, EJ_COMPILE_PROGRAM_DELETED, NULL, &pv) < 0) {
                system_error("cannot enumerate processes");
            }
            if (pv.u <= 0) {
                return EXIT_OPERATION_FAILED;
            }
            kill_all(SIGHUP, &pv);
        }
        break;
    case OPERATION_STATUS:
        {
            struct PidVector pv = {};

            if (find_all(EJ_COMPILE_PROGRAM, EJ_COMPILE_PROGRAM_DELETED, NULL, &pv) < 0) {
                system_error("cannot enumerate processes");
            }
            if (pv.u > 0) {
                for (int i = 0; i < pv.u; ++i) {
                    if (i > 0) putchar(' ');
                    printf("%d", pv.v[i]);
                }
                printf("\n");
            } else {
                return EXIT_OPERATION_FAILED;
            }
        }
        break;
    case OPERATION_ROTATE: {
        struct PidVector pv = {};

        if (find_all(EJ_COMPILE_PROGRAM, EJ_COMPILE_PROGRAM_DELETED, NULL, &pv) < 0) {
            system_error("cannot enumerate processes");
        }

        if (pv.u > 0) {
            fprintf(stderr, "%s: %s is running as pids", program_name,
                    EJ_COMPILE_PROGRAM);
            for (int i = 0; i < pv.u; ++i) {
                fprintf(stderr, " %d", pv.v[i]);
            }
            fprintf(stderr, "\n");
            fprintf(stderr, "%s: sending it the %s signal\n", program_name, "USR1");

            kill_all(SIGUSR1, &pv);
        }

        break;
    }
    default:
        system_error("unhandled operation %d", op);
    }
}

