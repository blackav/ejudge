/* -*- mode: c -*- */

/* Copyright (C) 2006-2018 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/version.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/ej_process.h"

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

#define EXIT_SYSTEM_ERROR 2
#define EXIT_OPERATION_FAILED 1

#define DEFAULT_EJUDGE_PRIMARY_USER "ejudge"

#define EJ_COMPILE_PROGRAM "ej-compile"

#define PROC_DIRECTORY "/proc"
#define EXE_LINK "exe"

extern char **environ;

static const unsigned char *program_name = "ej-compile-control";

enum
{
    OPERATION_START = 1,
    OPERATION_STOP = 2,
    OPERATION_KILL = 3,
    OPERATION_RESTART = 4,
    OPERATION_HARD_RESTART = 5,
    OPERATION_STATUS = 6
};

static void
write_help(void)
{
  printf("%s: ej-compile control utility\n"
         "Usage: %s [OPTIONS] COMMAND\n"
         "  OPTIONS:\n"
         "    --help    write message and exit\n"
         "    --version report version and exit\n"
         "  COMMAND:\n"
         "    start     start the ej-compile\n"
         "    stop      stop the ej-compile\n"
         "    restart   restart the ej-compile\n"
         "    status    report the ej-compile status\n",
         program_name, program_name);
}
static void
write_version(void)
{
  printf("%s %s, compiled %s\n", program_name, compile_version, compile_date);
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
    if (!value) return;

    int namelen = strlen(name);
    for (int i = 0; i < ev->u; ++i) {
        if (!strncmp(ev->v[i], name, namelen) && ev->v[i][namelen] == '=') {
            free(ev->v[i]); ev->v[i] = NULL;
            asprintf(&ev->v[i], "%s=%s", name, value);
            return;
        }
    }
    if (ev->u + 1 == ev->a) {
        ev->v = realloc(ev->v, (ev->a *= 2) * sizeof(ev->v[0]));
    }
    asprintf(&ev->v[ev->u++], "%s=%s", name, value);
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
find_all(const unsigned char *process_name, struct PidVector *pv)
{
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
        if (!strcmp(ptr, process_name)) {
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
check_process(int pid, const unsigned char *process_name)
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
    return !strcmp(ptr, process_name);
}

static int __attribute__((unused))
check_processes(const unsigned char *process_name, struct PidVector *pv)
{
    for (int i = 0; i < pv->u; ) {
        if (check_process(pv->v[i], process_name)) {
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
        int ej_xml_fd)
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
    int argi = 0;
    args[argi++] = (char*) exepath;
    if (is_parallel) args[argi++] = "-p";
    if (ej_xml_fd >= 0) {
        args[argi++] = "-l";
        snprintf(lbuf, sizeof(lbuf), "%d", ej_xml_fd);
        args[argi++] = lbuf;
    }
    args[argi++] = "conf/compile.cfg";
    args[argi] = NULL;

    if (replace_env) {
        environ = ev->v;
    }

    execve(exepath, args, environ);
    // nobody will know...
    _exit(1);
}

static void
signal_and_wait(int signo)
{
    struct PidVector pv = {};
    if (find_all(EJ_COMPILE_PROGRAM, &pv) < 0) {
        system_error("cannot enumerate processes");
    }
    if (pv.u <= 0) return;

    kill_all(signo, &pv);
    do {
        usleep(100000);
        pv_free(&pv);
    } while (find_all(EJ_COMPILE_PROGRAM, &pv) >= 0 && pv.u > 0);
    pv_free(&pv);
}

static void
emergency_stop(void)
{
    // wait some reasonable time - 0.5s
    usleep(500000);

    signal_and_wait(SIGTERM);
}

static void
change_ownership_and_permissions(const unsigned char *dir, const unsigned char *name, int uid, int gid, int perms)
{
    unsigned char p[PATH_MAX];
    if (snprintf(p, sizeof(p), "%s/%s", dir, name) >= sizeof(p)) return;
    struct stat stb;
    if (stat(p, &stb) < 0 || !S_ISDIR(stb.st_mode)) return;

    chown(p, uid, gid);
    chmod(p, perms);
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
check_directories(int primary_uid, int compile_uid, int primary_gid, int compile_gid, const struct ejudge_cfg *config)
{
    // check compile working directory
    unsigned char d1[PATH_MAX];
    unsigned char d2[PATH_MAX];
    unsigned char d3[PATH_MAX];
    unsigned char d4[PATH_MAX];
    struct stat stb;

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
            chown(d3, -1, compile_gid);
            chmod(d3, 06775);
        }
    } else {
        if (mkdir(d3, 0755) < 0) {
            syscall_error("cannot create '%s'", d3);
        }
        chown(d3, primary_uid, compile_gid);
        chmod(d3, 06775);
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
        chown(d3, primary_uid, primary_gid);
        chmod(d3, 0755);
    }
    // reserve working directory
    snprintf(d3, sizeof(d3), "%s/work", d2);
    if (stat(d3, &stb) >= 0) {
        if (!S_ISDIR(stb.st_mode)) {
            system_error("'%s' is not a directory", d3);
        }
        // must be group-writable
        if (stb.st_gid != compile_gid) {
            chown(d3, -1, compile_gid);
            chmod(d3, 06775);
        }
    } else {
        if (mkdir(d3, 0755) < 0) {
            syscall_error("cannot create '%s'", d3);
        }
        chown(d3, primary_uid, compile_gid);
        chmod(d3, 06775);
    }
    // spool directory
    snprintf(d3, sizeof(d3), "%s/compile", d2);
    if (stat(d3, &stb) >= 0) {
        if (!S_ISDIR(stb.st_mode)) {
            system_error("'%s' is not a directory", d3);
        }
        // must be group-writable
        if (stb.st_gid != compile_gid) {
            chown(d3, -1, compile_gid);
            chmod(d3, 06775);
        }
    } else {
        if (mkdir(d3, 0755) < 0) {
            syscall_error("cannot create '%s'", d3);
        }
        chown(d3, primary_uid, compile_gid);
        chmod(d3, 06775);
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

    snprintf(d4, sizeof(d4), "%s/upgrade-v2", d3);
    close(open(d4, O_WRONLY | O_CREAT | O_NONBLOCK, 0660));
}

int main(int argc, char *argv[])
{
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
            } else if (!strcmp(argv[aidx], "--version")) {
                write_version();
                return 0;
            } else if (!strcmp(argv[aidx], "--")) {
                ++aidx;
                break;
            } else if (argv[aidx][0] == '-') {
                system_error("invalid option '%s'", argv[aidx]);
            } else {
                break;
            }
            ++aidx;
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
    } else {
        system_error("invalid operation '%s'", operation);
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

    int ejudge_xml_fd = -1;
    if (primary_uid != compile_uid) {
        ejudge_xml_fd = open(ejudge_xml_path, O_RDONLY);
        if (ejudge_xml_fd < 0) {
            system_error("cannot open '%s'", ejudge_xml_path);
        }
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
            }
        }
    }

    if (op == OPERATION_START && primary_uid != compile_uid) {
        check_directories(primary_uid, primary_gid, compile_uid, compile_gid, config);
    }

    if (setresuid(-1, euid, euid) < 0) {
        syscall_error("setresuid failed");
    }
    if (primary_uid != compile_uid) {
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
        signal_and_wait(SIGTERM);
        // FALLTHROUGH
    case OPERATION_START:
        {
            struct PidVector pv = {};

            if (find_all(EJ_COMPILE_PROGRAM, &pv) < 0) {
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
                int ret = start_process(config, EJ_COMPILE_PROGRAM, log_fd, workdir, &ev, ej_compile_path, compile_parallelism > 1, 1 /* FIXME */, ejudge_xml_fd);
                if (ret < 0) {
                    emergency_stop();
                    return EXIT_SYSTEM_ERROR;
                }
            }

            while (1) {
                pv_free(&pv);
                usleep(100000);
                if (find_all(EJ_COMPILE_PROGRAM, &pv) < 0) {
                    system_error("cannot enumerate processes");
                }
                if (pv.u == compile_parallelism) break;
            }
        }
        break;
    case OPERATION_STOP:
        signal_and_wait(SIGTERM);
        break;
    case OPERATION_KILL:
        signal_and_wait(SIGKILL);
        break;
    case OPERATION_RESTART:
        {
            struct PidVector pv = {};

            if (find_all(EJ_COMPILE_PROGRAM, &pv) < 0) {
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

            if (find_all(EJ_COMPILE_PROGRAM, &pv) < 0) {
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
    default:
        system_error("unhandled operation %d", op);
    }
}


#if 0
#include "ejudge/config.h"
#include "ejudge/ej_types.h"
#include "ejudge/version.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/pathutl.h"
#include "ejudge/serve_state.h"
#include "ejudge/prepare.h"
#include "ejudge/compile_packet.h"
#include "ejudge/fileutl.h"
#include "ejudge/startstop.h"
#include "ejudge/packet_name.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

/*
 * usage: ej-compile-control COMMAND CONFIG
 *   COMMAND is one of `stop', `restart', `status'
 */

static const unsigned char *program_name = "";

static void startup_error(const char *format, ...)
  __attribute__((format(printf, 1, 2), noreturn));
static void
startup_error(const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: %s\n  Use --help option for help.\n", program_name,
          buf);
  exit(1);
}

static void op_error(const char *format, ...)
  __attribute__((format(printf, 1, 2), noreturn));
static void
op_error(const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: %s\n", program_name, buf);
  exit(1);
}

static void write_help(void) __attribute__((noreturn));
static void
write_help(void)
{
  printf("%s: ej-compile control utility\n"
         "Usage: %s [OPTIONS] COMMAND [EJUDGE-XML-PATH]\n"
         "  OPTIONS:\n"
         "    --help    write message and exit\n"
         "    --version report version and exit\n"
         "  COMMAND:\n"
         "    stop      stop the ej-compile\n"
         "    restart   restart the ej-compile\n"
         /*"    status    report the ej-compile status\n"*/,
         program_name, program_name);
  exit(0);
}
static void write_version(void) __attribute__((noreturn));
static void
write_version(void)
{
  printf("%s %s, compiled %s\n", program_name, compile_version, compile_date);
  exit(0);
}

struct serve_state serve_state;

int
main(int argc, char *argv[])
{
  int i = 1;
  const char *command = 0;
  const char *ejudge_xml_path = 0;
  struct ejudge_cfg *config = 0;
  path_t pkt_path;
  int tot_wait = 0, cur_wait = 0;
  const char *config_path = 0;
  const char *conf_suffix = 0;
  const unsigned char *compile_home_dir = 0;
  path_t config_path_buf;
  path_t  cpp_opts = {0};
  int cmd = 0, signum = 0;
  struct compile_request_packet cp;
  void *pkt_buf = 0;
  size_t pkt_len = 0;
  unsigned char pkt_name[64];
  const unsigned char *signame = 0;
  unsigned char cmdstr[1024];
  int pid_count = 0;
  int *pids = NULL;

  logger_set_level(-1, LOG_WARNING);
  program_name = os_GetBasename(argv[0]);
  if (argc < 2) startup_error("not enough parameters");

  if (!strcmp(argv[i], "--help")) {
    write_help();
  } else if (!strcmp(argv[i], "--version")) {
    write_version();
  }

  command = argv[i];
  i++;

  if (i < argc) {
    config_path = argv[i];
    i++;
  }

  if (i < argc) startup_error("too many parameters");

  if (config_path) {
    conf_suffix = os_GetSuffix(config_path);
    if (strcmp(conf_suffix, ".cfg") != 0) {
      ejudge_xml_path = config_path;
      config_path = 0;
    }
  }

  if (!config_path) {
#if defined EJUDGE_XML_PATH
    if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */
    if (!ejudge_xml_path) startup_error("ejudge.xml path is not specified");
    if (!(config = ejudge_cfg_parse(ejudge_xml_path, 1))) return 1;
    compile_home_dir = config->compile_home_dir;
#if defined EJUDGE_CONTESTS_HOME_DIR
    if (!compile_home_dir) {
      snprintf(config_path_buf, sizeof(config_path_buf), "%s/compile",
               EJUDGE_CONTESTS_HOME_DIR);
      compile_home_dir = xstrdup(config_path_buf);
    }
#endif
    snprintf(config_path_buf, sizeof(config_path_buf),
             "%s/conf/compile.cfg", compile_home_dir);
    config_path = xstrdup(config_path_buf);
  }

  if (prepare(NULL, &serve_state, config_path, 0, PREPARE_COMPILE,cpp_opts,0,0,0) < 0)
    return 1;

  if (!strcmp(command, "stop")) {
    cmd = 1;
    signame = "TERM";
    signum = START_STOP;
  } else if (!strcmp(command, "restart")) {
    cmd = 2;
    signame = "HUP";
    signum = START_RESTART;
  } else {
    startup_error("invalid command");
  }
  (void) cmd;

  /*
  if (!(pid = start_find_process("ej-compile", 0))) {
    op_error("ej-compile is not running");
  } else if (pid > 0) {
    // FIXME: also analyze the uid
    fprintf(stderr, "%s: ej-compile is running as pid %d\n", program_name, pid);
    fprintf(stderr, "%s: sending it the %s signal\n", program_name, signame);
    if (start_kill(pid, signum) < 0) op_error("failed: %s", os_ErrorMsg());
    return 0;
  }
  */

  if ((pid_count = start_find_all_processes("ej-compile", &pids)) < 0) {
    op_error("cannot get the list of processes from /proc");
  } else if (!pid_count) {
    op_error("ej-compile is not running");
  } else {
    fprintf(stderr, "%s: ej-compile is running as pids", program_name);
    for (i = 0; i < pid_count; ++i) {
      fprintf(stderr, " %d", pids[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "%s: sending them the %s signal\n", program_name, signame);
    for (i = 0; i < pid_count; ++i) {
      if (start_kill(pids[i], signum) < 0) op_error("failed: %s", os_ErrorMsg());
    }
    return 0;
  }

  /* check, that compile is running */
  memset(&cp, 0, sizeof(cp));
  if (compile_request_packet_write(&cp, &pkt_len, &pkt_buf) < 0)
    op_error("compile packet error");
  serve_packet_name(0, 0, 0, pkt_name, sizeof(pkt_name));
  if (generic_write_file(pkt_buf, pkt_len, SAFE,
                         serve_state.global->compile_queue_dir,
                         pkt_name, "") < 0)
    op_error("compile packet write error");
  snprintf(pkt_path, sizeof(pkt_path), "%s/dir/%s",
           serve_state.global->compile_queue_dir, pkt_name);
  cur_wait = 100000;
  tot_wait = 0;
  while (1) {
    usleep(cur_wait);
    tot_wait += cur_wait;
    cur_wait += 100000;
    if (access(pkt_path, F_OK) < 0) break;
    if (tot_wait >= 5000000) {
      unlink(pkt_path);
      op_error("ej-compile seems to not running");
    }
  }

  /* FIXME: reimplement it normally */
  snprintf(cmdstr, sizeof(cmdstr), "killall -%s ej-compile", signame);
  if (system(cmdstr) < 0)
    op_error("killall failed");
#if 0
  memset(&cp, 0, sizeof(cp));
  cp.lang_id = cmd;
  if (compile_request_packet_write(&cp, &pkt_len, &pkt_buf) < 0)
    op_error("compile packet error");
  serve_packet_name(0, 0, 0, pkt_name);
  if (generic_write_file(pkt_buf, pkt_len, SAFE,
                         serve_state.global->compile_queue_dir,
                         pkt_name, "") < 0)
    op_error("compile packet write error");
  snprintf(pkt_path, sizeof(pkt_path), "%s/dir/%s",
           serve_state.global->compile_queue_dir, pkt_name);
  cur_wait = 100000;
  while (1) {
    usleep(cur_wait);
    cur_wait += 100000;
    if (cur_wait > 1000000) cur_wait = 1000000;
    if (access(pkt_path, F_OK) < 0) break;
  }
#endif

  return 0;
}
#endif
