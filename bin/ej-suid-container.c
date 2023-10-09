/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2021-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/resource.h>
#include <grp.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <ctype.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/prctl.h>
#include <asm/unistd.h>
#include <asm/param.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "config.h"

#include "ejudge/unistd_32_fixed.h"

#if defined EJUDGE_PRIMARY_USER
#define PRIMARY_USER EJUDGE_PRIMARY_USER
#else
#define PRIMARY_USER "ejudge"
#endif

#if defined EJUDGE_PRIMARY_GROUP
#define PRIMARY_GROUP EJUDGE_PRIMARY_GROUP
#else
#define PRIMARY_GROUP PRIMARY_USER
#endif

#if defined EJUDGE_EXEC_USER
#define EXEC_USER EJUDGE_EXEC_USER
#define EXEC_GROUP EJUDGE_EXEC_USER
#else
#define EXEC_USER "ejexec"
#define EXEC_GROUP "ejexec"
#endif

#if defined EJUDGE_COMPILE_USER
#define COMPILE_USER EJUDGE_COMPILE_USER
#define COMPILE_GROUP EJUDGE_COMPILE_USER
#else
#define COMPILE_USER "ejcompile"
#define COMPILE_GROUP "ejcompile"
#endif

#ifndef EJUDGE_PREFIX_DIR
#define EJUDGE_PREFIX_DIR "/opt/ejudge"
#endif

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS SECCOMP_RET_KILL
#endif

static char const sandbox_dir[] = "/sandbox";
static char const alternatives_dir[] = "/etc/alternatives";
static char const compile_dir[] = "/home/judges/compile";

static char safe_dir_path[PATH_MAX];
static char proc_path[PATH_MAX] = "/proc";
static char cgroup_path[PATH_MAX] = "/sys/fs/cgroup";
static char cgroup_name[PATH_MAX] = "";
static char cgroup_unified_path[PATH_MAX] = "";
static char cgroup_procs_path[PATH_MAX] = "";
static int cgroup_v2_detected = 0;

static const char cgroup_v1_memory_default_path[] = "/sys/fs/cgroup/memory";
static const char cgroup_v1_cpu_default_path[] = "/sys/fs/cgroup/cpu,cpuacct";
static char cgroup_memory_base_path[PATH_MAX] = "/sys/fs/cgroup/memory";
static char cgroup_cpu_base_path[PATH_MAX] = "/sys/fs/cgroup/cpu,cpuacct";
static char cgroup_memory_path[PATH_MAX] = "";
static char cgroup_cpu_path[PATH_MAX] = "";
static char cgroup_memory_procs_path[PATH_MAX] = "";
static char cgroup_cpu_procs_path[PATH_MAX] = "";

static const char *program_name = "prog";
static int response_fd = 2;
static char *log_s = NULL;
static size_t log_z = 0;
static FILE *log_f = NULL;
static int control_socket_fd = -1;

static int enable_cgroup = 1;
static int enable_ipc_ns = 1;
static int enable_net_ns = 1;
static int enable_mount_ns = 1;
static int enable_pid_ns = 1;
static int enable_proc = 0;
static int enable_sys = 0;
static int enable_dev = 0;
static int enable_var = 0;
static int enable_etc = 0;
static int enable_sandbox_dir = 1;
static int enable_home = 0;
static int enable_chown = 1;
static int enable_pgroup = 1;
static int enable_prc_count = 0;
static int enable_ipc_count = 0;
static int enable_subdir_mode = 0;
static int enable_compile_mode = 0;
static int enable_run = 0;
static int enable_loopback = 0;
static int enable_vm_limit = 1;

static int enable_seccomp = 1;
static int enable_sys_execve = 0;
static int enable_sys_fork = 0;
static int enable_sys_memfd = 0;
static int enable_sys_unshare = 0;

static char *working_dir = NULL;
static char *working_dir_parent = NULL;
static char *working_dir_name = NULL;

static int bash_mode = 0;

static int exec_user_serial = 0;
static int exec_uid = -1;
static int exec_gid = -1;
static int primary_uid = -1;
static int primary_gid = -1;
static int compile_uid = -1;
static int compile_gid = -1;
static int slave_uid = -1;
static int slave_gid = -1;

// standard stream redirections
static int enable_redirect_null = 0;
static int enable_output_merge = 0;
static int stdout_mode = O_WRONLY | O_CREAT | O_TRUNC;
static int stderr_mode = O_WRONLY | O_CREAT | O_TRUNC;
static char *stdin_name = NULL;
static char *stdout_name = NULL;
static char *stderr_name = NULL;
static int stdin_fd = -1;
static int stdout_fd = -1;
static int stderr_fd = -1;
static char *start_program_name = NULL;
static int stdin_external_fd = -1;
static int stdout_external_fd = -1;
static char *language_name = NULL;

enum { DEFAULT_LIMIT_VM_SIZE = 67108864 };
enum { DEFAULT_LIMIT_CPU_TIME_MS = 1000 };

// resource limits
static int limit_umask = -1;
static int limit_open_files = -1;
static long long limit_stack_size = -1;
static long long limit_vm_size = -1;
static long long limit_rss_size = -1;
static long long limit_file_size = -1;
static int limit_processes = 5;
static int limit_cpu_time_ms = DEFAULT_LIMIT_CPU_TIME_MS;
static int limit_real_time_ms = 5000;

static char *start_program;
static char **start_args;
extern char **environ;

static void __attribute__((noreturn))
fatal()
{
    if (log_f) {
        fclose(log_f); log_f = NULL;
    }
    (void) log_z;
    if (log_s && *log_s) {
        int len = strlen(log_s);
        dprintf(response_fd, "1L%d,%s", len, log_s);
    } else {
        dprintf(response_fd, "1");
    }
    _exit(1);
}

static void __attribute__((format(printf, 1, 2)))
flog(const char *format, ...)
{
    char buf[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    fprintf(log_f, "%s: %s\n", program_name, buf);
}

static void __attribute__((format(printf, 1, 2), noreturn))
ffatal(const char *format, ...)
{
    char buf[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    fprintf(log_f, "%s: %s\n", program_name, buf);

    if (log_f) {
        fclose(log_f); log_f = NULL;
    }
    (void) log_z;
    if (log_s && *log_s) {
        int len = strlen(log_s);
        dprintf(response_fd, "1L%d,%s", len, log_s);
    } else {
        dprintf(response_fd, "1");
    }
    _exit(1);
}

static int
getl(char *buf, size_t size, FILE *f)
{
    if (!fgets(buf, size, f)) return -1;
    size_t len = strlen(buf);
    if (len + 1 == size) {
        ffatal("input line is too long, increase buffer size!");
    }
    while (len > 0 && isspace((unsigned char) buf[len - 1])) --len;
    buf[len] = 0;
    return len;
}

static void
get_user_ids(void)
{
    // don't use getpwnam because it depends on PAM, etc
    char exec_user_str[64];
    if (exec_user_serial > 0) {
        if (snprintf(exec_user_str, sizeof(exec_user_str), "%s%d", EXEC_USER, exec_user_serial) >= sizeof(exec_user_str))
            ffatal("invalid user %s%d", EXEC_USER, exec_user_serial);
    } else {
        if (snprintf(exec_user_str, sizeof(exec_user_str), "%s", EXEC_USER) >= sizeof(exec_user_str))
            ffatal("invalid user %s", EXEC_USER);
    }
    char exec_group_str[64];
    if (exec_user_serial > 0) {
        if (snprintf(exec_group_str, sizeof(exec_group_str), "%s%d", EXEC_GROUP, exec_user_serial) >= sizeof(exec_group_str))
            ffatal("invalid group %s%d", EXEC_GROUP, exec_user_serial);
    } else {
        if (snprintf(exec_group_str, sizeof(exec_group_str), "%s", EXEC_GROUP) >= sizeof(exec_group_str))
            ffatal("invalid group %s", EXEC_GROUP);
    }

    FILE *f = fopen("/etc/passwd", "r");
    if (!f) ffatal("cannot open /etc/passwd: %s", strerror(errno));
    char buf[4096];
    while (fgets(buf, sizeof(buf), f)) {
        int len = strlen(buf);
        if (len + 1 >= sizeof(buf)) ffatal("input line in /etc/passwd is too long");

        const char *user_name = buf;
        char *s = strchr(buf, ':');
        if (!s) ffatal("invalid /etc/passwd (1)");
        *s = 0;
        s = strchr(s + 1, ':');
        if (!s) ffatal("invalid /etc/passwd (2)");
        const char *user_id_str = s + 1;
        s = strchr(s + 1, ':');
        if (!s) ffatal("invalid /etc/passwd (3)");
        *s = 0;
        int *dest_uid = NULL;
        if (!strcmp(user_name, exec_user_str)) dest_uid = &exec_uid;
        else if (!strcmp(user_name, PRIMARY_USER)) dest_uid = &primary_uid;
        else if (!strcmp(user_name, COMPILE_USER)) dest_uid = &compile_uid;
        if (dest_uid) {
            char *eptr = NULL;
            errno = 0;
            long v = strtol(user_id_str, &eptr, 10);
            if (errno || *eptr || eptr == user_id_str || v <= 0 || (int) v != v)
                ffatal("invalid uid in /etc/passwd for %s", user_name);
            *dest_uid = (int) v;
        }
    }
    fclose(f); f = NULL;

    if (exec_uid < 0) ffatal("no user %s", exec_user_str);
    if (exec_uid == 0) ffatal("user %s cannot be root", exec_user_str);
    if (primary_uid < 0) ffatal("no user %s", PRIMARY_USER);
    if (primary_uid == 0) ffatal("user %s cannot be root", PRIMARY_USER);

    if (!(f = fopen("/etc/group", "r"))) ffatal("cannot open /etc/group: %s", strerror(errno));
    while (fgets(buf, sizeof(buf), f)) {
        int len = strlen(buf);
        if (len + 1 >= sizeof(buf)) ffatal("input line in /etc/group is too long");

        const char *group_name = buf;
        char *s = strchr(buf, ':');
        if (!s) ffatal("invalid /etc/group (1)");
        *s = 0;
        s = strchr(s + 1, ':');
        if (!s) ffatal("invalid /etc/group (2)");
        const char *group_id_str = s + 1;
        s = strchr(s + 1, ':');
        if (!s) ffatal("invalid /etc/group (3)");
        *s = 0;
        int *dest_gid = NULL;
        if (!strcmp(group_name, exec_group_str)) dest_gid = &exec_gid;
        else if (!strcmp(group_name, PRIMARY_GROUP)) dest_gid = &primary_gid;
        else if (!strcmp(group_name, COMPILE_GROUP)) dest_gid = &compile_gid;
        if (dest_gid) {
            char *eptr = NULL;
            errno = 0;
            long v = strtol(group_id_str, &eptr, 10);
            if (errno || *eptr || eptr == group_id_str || v <= 0 || (int) v != v)
                ffatal("invalid uid in /etc/group for %s", group_name);
            *dest_gid = (int) v;
        }
    }
    fclose(f); f = NULL;

    if (exec_gid < 0) ffatal("no group %s", exec_group_str);
    if (exec_gid == 0) ffatal("group %s cannot be root", exec_group_str);
    if (primary_gid < 0) ffatal("no group %s", PRIMARY_GROUP);
    if (primary_gid == 0) ffatal("group %s cannot be root", PRIMARY_GROUP);
}

static void
safe_chown(const char *full, int to_user_id, int to_group_id, int from_user_id)
{
    __attribute__((unused)) int _;
    int fd = open(full, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0);
    if (fd < 0) return;
    struct stat stb;
    if (fstat(fd, &stb) < 0) {
        close(fd);
        return;
    }
    if (S_ISDIR(stb.st_mode)) {
        if (stb.st_uid == from_user_id) {
            _ = fchown(fd, to_user_id, to_group_id);
        }
    } else {
        if (stb.st_uid == from_user_id) {
            _ = fchown(fd, to_user_id, to_group_id);
        }
    }
    close(fd);
}

static void
safe_chown_rec(const char *path, int user_id, int group_id, int from_user_id)
{
    DIR *d = opendir(path);
    if (!d) return;
    struct dirent *dd;
    int names_a = 32, names_u = 0;
    char **names_s = malloc(names_a * sizeof(names_s[0]));
    while ((dd = readdir(d))) {
        if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, "..")) continue;
        if (names_u == names_a) {
            names_s = realloc(names_s, (names_a *= 2) * sizeof(names_s[0]));
        }
        names_s[names_u++] = strdup(dd->d_name);
    }
    closedir(d); d = NULL;
    for (int i = 0; i < names_u; ++i) {
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", path, names_s[i]);
        struct stat stb;
        if (lstat(full, &stb) < 0) continue;
        if (S_ISDIR(stb.st_mode)) {
            safe_chown_rec(full, user_id, group_id, from_user_id);
        }
        safe_chown(full, user_id, group_id, from_user_id);
    }
    for (int i = 0; i < names_u; ++i)
        free(names_s[i]);
    free(names_s);
}

static void
change_ownership(int user_id, int group_id, int from_user_id)
{
    const char *dir = (enable_subdir_mode && working_dir)? working_dir_parent : working_dir;
    if (!dir) dir = ".";
    safe_chown(dir, user_id, group_id, from_user_id);
    safe_chown_rec(dir, user_id, group_id, from_user_id);
}

static void
mount_tmpfs(
        const unsigned char *dir,
        const unsigned char *subdir,
        int user,
        int group)
{
    unsigned char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, subdir) >= (int) sizeof(path)) {
        ffatal("path %s/%s is too long", dir, subdir);
    }
    if (mkdir(path, 0700) < 0 && errno != EEXIST) {
        ffatal("mkdir '%s' failed: %s", path, strerror(errno));
    }
    if (chown(path, user, group) < 0) {
        ffatal("chown '%s' failed: %s", path, strerror(errno));
    }
    if (chmod(path, 0700) < 0) {
        ffatal("chmod '%s' failed: %s", path, strerror(errno));
    }
    if (mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NODEV, "size=1024m,nr_inodes=1024") < 0) {
        ffatal("mount '%s' failed: %s", path, strerror(errno));
    }
}

struct MountInfo
{
    char *src_path;
    char *dst_path;
    char *type;
    char *options;
    char *n1;
    char *n2;
    int   dst_len;
};

static int
sort_func_1(const void *p1, const void *p2)
{
    return ((struct MountInfo *) p2)->dst_len - ((struct MountInfo *) p1)->dst_len;
}

static void
reconfigure_fs(void)
{
    int r;
    char *mnt_s = NULL;
    size_t mnt_z = 0;
    FILE *mnt_f = open_memstream(&mnt_s, &mnt_z);
    int fd = open("/proc/self/mounts", O_RDONLY);
    if (fd < 0) ffatal("failed to open /proc/self/mounts: %s", strerror(errno));
    char buf[4096];
    ssize_t z;
    while ((z = read(fd, buf, sizeof(buf))) > 0) {
        fwrite(buf, 1, z, mnt_f);
    }
    if (z < 0) ffatal("read error from /proc/self/mounts");
    close(fd); fd = -1;
    fclose(mnt_f); mnt_f = NULL;

    if (!mnt_z) ffatal("empty file /proc/self/mounts");
    if (mnt_s[mnt_z - 1] != '\n') ffatal("invalid /proc/self/mounts (1)");

    // count lines
    int lcount = 0;
    for (int i = 0; mnt_s[i]; ++i) {
        lcount += (mnt_s[i] == '\n');
    }

    struct MountInfo *mi = calloc(lcount, sizeof(mi[0]));
    int ind = -1;
    char *p = mnt_s;
    while (*p) {
        ++ind;
        struct MountInfo *pmi = &mi[ind];
        char *q = strchr(p, ' ');
        if (!q) ffatal("invalid /proc/self/mounts (2)");
        *q = 0;
        pmi->src_path = p;
        p = q + 1;

        if (!(q = strchr(p, ' '))) ffatal("invalid /proc/self/mounts (3)");
        *q = 0;
        pmi->dst_path = p;
        pmi->dst_len = strlen(p);
        p = q + 1;

        if (!(q = strchr(p, ' '))) ffatal("invalid /proc/self/mounts (4)");
        *q = 0;
        pmi->type = p;
        p = q + 1;

        if (!(q = strchr(p, ' '))) ffatal("invalid /proc/self/mounts (5)");
        *q = 0;
        pmi->options = p;
        p = q + 1;

        if (!(q = strchr(p, ' '))) ffatal("invalid /proc/self/mounts (6)");
        *q = 0;
        pmi->n1 = p;
        p = q + 1;

        if (!(q = strchr(p, '\n'))) ffatal("invalid /proc/self/mounts (7)");
        *q = 0;
        pmi->n2 = p;
        p = q + 1;
    }

    qsort(mi, lcount, sizeof(mi[0]), sort_func_1);

    // make everything private
    for (int i = 0; i < lcount; ++i) {
        if ((r = mount(NULL, mi[i].dst_path, NULL, MS_PRIVATE, NULL)) < 0) {
            ffatal("failed to make '%s' private: %s", mi[i].dst_path, strerror(errno));
        }
    }

    // unmount what we don't need
    for (int i = 0; i < lcount; ++i) {
        struct MountInfo *pmi = &mi[i];
        
        if (!strcmp(pmi->type, "fusectl")
            || !strcmp(pmi->type, "rpc_pipefs")
            || !strcmp(pmi->type, "securityfs")
            || !strcmp(pmi->type, "tracefs")
            || !strcmp(pmi->type, "configfs")
            || !strcmp(pmi->type, "fuse.portal")
            || !strcmp(pmi->type, "debugfs")
            || !strcmp(pmi->type, "pstore")
            || !strcmp(pmi->type, "bpf")
            || !strcmp(pmi->type, "hugetlbfs")) {
            if ((r = umount(pmi->dst_path)) < 0) {
                ffatal("failed to unmount '%s': %s", mi[i].dst_path, strerror(errno));
            }
        }
    }

    if (enable_sandbox_dir) {
        if (mkdir(sandbox_dir, 0755) < 0 && errno != EEXIST) {
            ffatal("failed to create '%s': %s", sandbox_dir, strerror(errno));
        }

        if (working_dir_parent && *working_dir_parent) {
            if ((r = mount(working_dir_parent, sandbox_dir, NULL, MS_BIND, NULL)) < 0) {
                ffatal("failed to mount '%s' to %s: %s", working_dir_parent, sandbox_dir, strerror(errno));
            }
        } else if (working_dir && *working_dir) {
            if ((r = mount(working_dir, sandbox_dir, NULL, MS_BIND, NULL)) < 0) {
                ffatal("failed to mount '%s' to %s: %s", working_dir, sandbox_dir, strerror(errno));
            }
        } else {
            char wd[PATH_MAX];
            if (!getcwd(wd, sizeof(wd))) {
                ffatal("failed to get current dir: %s", strerror(errno));
            }
            if ((r = mount(wd, sandbox_dir, NULL, MS_BIND, NULL)) < 0) {
                ffatal("failed to mount %s: %s", sandbox_dir, strerror(errno));
            }
        }
    }

    char empty_bind_path[PATH_MAX];
    if (snprintf(empty_bind_path, sizeof(empty_bind_path), "%s/empty", safe_dir_path) >= sizeof(empty_bind_path)) abort();

    if (enable_proc) {
        if (enable_pid_ns) {
            // remout /proc to show restricted pids
            if ((r = mount("proc", "/proc", "proc", 0, NULL)) < 0) {
                ffatal("failed to mount /proc: %s", strerror(errno));
            }
        }
    } else {
        // remout /proc to empty directory, this might break things
        if ((r = mount(empty_bind_path, "/proc", NULL, MS_BIND, NULL)) < 0) {
            ffatal("failed to mount %s as /proc: %s", empty_bind_path, strerror(errno));
        }
    }

    if (!enable_sys) {
        // remout /sys to empty directory
        if ((r = mount(empty_bind_path, "/sys", NULL, MS_BIND, NULL)) < 0) {
            ffatal("failed to mount /sys: %s", strerror(errno));
        }
    }

    if ((r = mount(empty_bind_path, "/boot", NULL, MS_BIND, NULL)) < 0) {
        ffatal("failed to mount /boot: %s", strerror(errno));
    }
    if ((r = mount(empty_bind_path, "/srv", NULL, MS_BIND, NULL)) < 0) {
        ffatal("failed to mount /srv: %s", strerror(errno));
    }
    struct stat stb;
    if (lstat("/data", &stb) >= 0 && S_ISDIR(stb.st_mode)) {
        if ((r = mount(empty_bind_path, "/data", NULL, MS_BIND, NULL)) < 0) {
            ffatal("failed to mount /data: %s", strerror(errno));
        }
    }

    char bind_path[PATH_MAX];
    if (snprintf(bind_path, sizeof(bind_path), "%s/root", safe_dir_path) >= sizeof(bind_path)) abort();
    if (lstat(bind_path, &stb) >= 0 && S_ISDIR(stb.st_mode)) {
        if ((r = mount(bind_path, "/root", NULL, MS_BIND, NULL)) < 0) {
            ffatal("failed to mount %s as /root: %s", bind_path, strerror(errno));
        }
    }

    if (!enable_etc) {
        if (snprintf(bind_path, sizeof(bind_path), "%s/etc", safe_dir_path) >= sizeof(bind_path)) abort();
        if (lstat(bind_path, &stb) >= 0 && S_ISDIR(stb.st_mode)) {
            char alt_path[PATH_MAX];
            int need_alternatives = 0;
            if (lstat(alternatives_dir, &stb) >= 0 && S_ISDIR(stb.st_mode)) {
                // need to preserve the current /etc/alternatives
                need_alternatives = 1;
                if (snprintf(alt_path, sizeof(alt_path), "%s/alternatives", bind_path) >= sizeof(alt_path)) abort();
                if ((r = mount(alternatives_dir, alt_path, NULL, MS_BIND, NULL)) < 0) {
                    ffatal("failed to mount %s to %s: %s", alternatives_dir, alt_path, strerror(errno));
                }
            }
            if ((r = mount(bind_path, "/etc", NULL, MS_BIND, NULL)) < 0) {
                ffatal("failed to mount %s as /etc: %s", bind_path, strerror(errno));
            }
            if (need_alternatives) {
                if ((r = mount(alt_path, alternatives_dir, NULL, MS_BIND, NULL)) < 0) {
                    ffatal("failed to mount %s to %s: %s", alt_path, alternatives_dir, strerror(errno));
                }
            }
        } else {
            // FIXME: report error?
        }
    }
    if (!enable_var) {
        if (snprintf(bind_path, sizeof(bind_path), "%s/var", safe_dir_path) >= sizeof(bind_path)) abort();
        if (lstat(bind_path, &stb) >= 0 && S_ISDIR(stb.st_mode)) {
            if ((r = mount(bind_path, "/var", NULL, MS_BIND, NULL)) < 0) {
                ffatal("failed to mount %s as /var: %s", bind_path, strerror(errno));
            }
        } else {
            ffatal("no safe directory substitution for /var");
        }
    }
    if (!enable_dev) {
        if (snprintf(bind_path, sizeof(bind_path), "%s/dev", safe_dir_path) >= sizeof(bind_path)) abort();
        if (lstat(bind_path, &stb) >= 0 && S_ISDIR(stb.st_mode)) {
            if ((r = mount(bind_path, "/dev", NULL, MS_BIND, NULL)) < 0) {
                ffatal("failed to mount %s as /dev: %s", bind_path, strerror(errno));
            }
        }
    }

    // mount pristine /tmp, /dev/shm, /run
    if ((r = mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "size=1024m,nr_inodes=1024")) < 0) {
        ffatal("failed to mount /tmp: %s", strerror(errno));
    }
    if ((r = mount("mqueue", "/dev/mqueue", "mqueue", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, NULL)) < 0) {
        ffatal("failed to mount /dev/mqueue: %s", strerror(errno));
    }
    if (!enable_run) {
        if ((r = mount("/tmp", "/run", NULL, MS_BIND, NULL)) < 0){
            ffatal("failed to mount /run: %s", strerror(errno));
        }
    }
    if ((r = mount("/tmp", "/dev/shm", NULL, MS_BIND, NULL)) < 0){
        ffatal("failed to mount /dev/shm: %s", strerror(errno));
    }

    if (!enable_home) {
        if (snprintf(bind_path, sizeof(bind_path), "%s/home", safe_dir_path) >= sizeof(bind_path)) abort();
        if (lstat(bind_path, &stb) >= 0 && S_ISDIR(stb.st_mode)) {
            int preserve_compile = 0;
            char alt_path[PATH_MAX];
            if (lstat(compile_dir, &stb) >= 0 && S_ISDIR(stb.st_mode)) {
                // need to preserve /home/judges/compile
                if (snprintf(alt_path, sizeof(alt_path), "%s/judges/compile", bind_path) >= sizeof(alt_path)) abort();
                if ((r = mount(compile_dir, alt_path, NULL, MS_BIND, NULL)) < 0) {
                    ffatal("failed to mount %s to %s: %s", compile_dir, alt_path, strerror(errno));
                }
                preserve_compile = 1;
            }
            if ((r = mount(bind_path, "/home", NULL, MS_BIND, NULL)) < 0) {
                ffatal("failed to mount %s as /home: %s", bind_path, strerror(errno));
            }
            if (preserve_compile) {
                if ((r = mount(alt_path, compile_dir, NULL, MS_BIND, NULL)) < 0) {
                    ffatal("failed to mount %s to %s: %s", compile_dir, alt_path, strerror(errno));
                }
                if (enable_compile_mode) {
                    static const unsigned char * const subdirs[] =
                    {
                        ".cache", ".dotnet", ".local", ".nuget", ".template", ".templateengine", NULL,
                    };
                    for (int di = 0; subdirs[di]; ++di) {
                        mount_tmpfs(compile_dir, subdirs[di],
                                    compile_uid, compile_gid);
                    }
                }
            }
        } else {
            ffatal("no safe directory substitution for /home");
        }
        /*
        if ((r = mount(empty_bind_path, "/home", NULL, MS_BIND, NULL)) < 0) {
            ffatal("failed to mount /home: %s", strerror(errno));
        }
        */
    } else {
        struct stat stb;
        if (lstat("/home/judges", &stb) && S_ISDIR(stb.st_mode)) {
            if (lstat("/home/judges/data", &stb) && S_ISDIR(stb.st_mode)) {
                if ((r = mount(empty_bind_path, "/home/judges/data", NULL, MS_BIND, NULL)) < 0) {
                    ffatal("failed to mount /home/judges/data: %s", strerror(errno));
                }
            }
            if (lstat("/home/judges/var", &stb) && S_ISDIR(stb.st_mode)) {
                if ((r = mount(empty_bind_path, "/home/judges/var", NULL, MS_BIND, NULL)) < 0) {
                    ffatal("failed to mount /home/judges/var: %s", strerror(errno));
                }
            }
        }
    }

    if (!enable_proc || (!enable_sys && enable_cgroup)) {
        if (mkdir("/run/0", 0700) < 0) {
            ffatal("failed to mkdir /run/0: %s", strerror(errno));
        }
    }
    if (!enable_proc) {
        if (mkdir("/run/0/proc", 0700) < 0) {
            ffatal("failed to mkdir /run/0/proc: %s", strerror(errno));
        }
        if ((r = mount("proc", "/run/0/proc", "proc", 0, NULL)) < 0) {
            ffatal("failed to mount /run/0/proc: %s", strerror(errno));
        }
    }
    if (!enable_sys && enable_cgroup) {
        if (cgroup_v2_detected) {
            if (mkdir("/run/0/cgroup", 0700) < 0) {
                ffatal("failed to mkdir /run/0/cgroup: %s", strerror(errno));
            }
            if ((r = mount("cgroup2", "/run/0/cgroup", "cgroup2", 0, NULL)) < 0) {
                ffatal("failed to mount /run/0/cgroup: %s", strerror(errno));
            }
        } else {
            if (mkdir("/run/0/memory", 0700) < 0) {
                ffatal("failed to mkdir /run/0/memory: %s", strerror(errno));
            }
            if ((r = mount("cgroup", "/run/0/memory", "cgroup", 0, "rw,nosuid,nodev,noexec,relatime,memory")) < 0) {
                ffatal("failed to mount /run/0/memory: %s", strerror(errno));
            }
            if (mkdir("/run/0/cpu,cpuacct", 0700) < 0) {
                ffatal("failed to mkdir /run/0/cpu,cpuacct: %s", strerror(errno));
            }
            if ((r = mount("cgroup", "/run/0/cpu,cpuacct", "cgroup", 0, "rw,nosuid,nodev,noexec,relatime,cpu,cpuacct")) < 0) {
                ffatal("failed to mount /run/0/cpu,cpuacct: %s", strerror(errno));
            }
        }
    }

    free(mi);
    free(mnt_s);
}

static void
net_interface_up(
        const unsigned char *ifname,
        const unsigned char *ip,
        const unsigned char *netmask)
{
    int sfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sfd < 0) {
        ffatal("socket() failed: %s", strerror(errno));
    }

    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    struct sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = inet_addr(ip);
    memcpy(&ifr.ifr_addr, &sa, sizeof(sa));

    if (ioctl(sfd, SIOCSIFADDR, &ifr) < 0) {
        ffatal("cannot set ip addr '%s' on '%s'", ip, ifname);
    }

    sa.sin_addr.s_addr = inet_addr(netmask);
    memcpy(&ifr.ifr_addr, &sa, sizeof(sa));
    if (ioctl(sfd, SIOCSIFNETMASK, &ifr) < 0) {
        ffatal("cannot set netmask '%s' on '%s'", netmask, ifname);
    }

    ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST;
    if (ioctl(sfd, SIOCSIFFLAGS, &ifr) < 0) {
        ffatal("cannot set flags on '%s'", ifname);
    }

    close(sfd);
}

static int
open_redirections(void)
{
    int retval = -1;

    if (setegid(slave_gid) < 0) {
        flog("setegid failed to group %d: %s", slave_gid, strerror(errno));
        goto failed;
    }
    if (seteuid(slave_uid) < 0) {
        flog("seteuid failed to user %d: %s", slave_uid, strerror(errno));
        goto failed_2;
    }

    if (stdin_name && *stdin_name) {
        if ((stdin_fd = open(stdin_name, O_RDONLY | O_CLOEXEC, 0)) < 0) {
            flog("failed to open %s for stdin: %s", stdin_name, strerror(errno));
            goto failed_3;
        }
    } else if (stdin_external_fd >= 0) {
        stdin_fd = stdin_external_fd;
    } else if (enable_redirect_null) {
        if ((stdin_fd = open("/dev/null", O_RDONLY | O_CLOEXEC, 0)) < 0) {
            flog("failed to open /dev/null for stdin: %s", strerror(errno));
            goto failed_3;
        }
    }

    if (stdout_name && *stdout_name) {
        if ((stdout_fd = open(stdout_name, stdout_mode | O_CLOEXEC, 0600)) < 0) {
            flog("failed to open %s for stdout: %s", stdout_name, strerror(errno));
            goto failed_3;
        }
    } else if (stdout_external_fd >= 0) {
        stdout_fd = stdout_external_fd;
    } else if (enable_redirect_null) {
        if ((stdout_fd = open("/dev/null", stdout_mode | O_CLOEXEC, 0600)) < 0) {
            flog("failed to open /dev/null for stdout: %s", strerror(errno));
            goto failed_3;
        }
    }

    if (stderr_name && *stderr_name) {
        if ((stderr_fd = open(stderr_name, stderr_mode | O_CLOEXEC, 0600)) < 0) {
            flog("failed to open %s for stderr: %s", stderr_name, strerror(errno));
            goto failed_3;
        }
    } else if (enable_output_merge) {
        if ((stderr_fd = dup((stdout_fd >= 0)?stdout_fd:1)) < 0) {
            flog("failed to duplicate for stderr");
            goto failed_3;
        }
        fcntl(stderr_fd, F_SETFD, fcntl(stderr_fd, F_GETFD) | O_CLOEXEC);
    } else if (enable_redirect_null) {
        if ((stderr_fd = open("/dev/null", stderr_mode | O_CLOEXEC, 0600)) < 0) {
            flog("failed to open /dev/null for stderr: %s", strerror(errno));
            goto failed_3;
        }
    }

    retval = 0;

failed_3:
    if (seteuid(0) < 0) {
        ffatal("cannot restore user to 0: %s", strerror(errno));
    }

failed_2:
    if (setegid(0) < 0) {
        ffatal("cannot restore group to 0: %s", strerror(errno));
    }

failed:
    return retval;
}

// kill all ejexec processes
static int
kill_all(void)
{
    return 0;
    /*
     * this is not necessary if pid namespace is enabled:
     * all the remaining processes are killed by the kernel anyway
     * and more, this seems to break using of several instances
     * of ej-suid-container on the same host
     */
#if 0
    int pid = fork();
    if (pid < 0) {
        fprintf(stderr, "killing all processes: fork() failed: %s\n", strerror(errno));
        return -1;
    }
    if (!pid) {
        if (setuid(slave_uid) < 0) {
            fprintf(stderr, "killing all processes: setuid() failed: %s\n", strerror(errno));
            _exit(127);
        }
        // will kill this process as well
        kill(-1, SIGKILL);
        _exit(0);
    }

    // wait for any child remaining
    while (wait(NULL) > 0) {}

    return 0;
#endif
}

struct process_info
{
  char state;
  int ppid;
  int pgrp;
  int session;
  int tty_nr;
  int tpgid;
  unsigned flags;
  unsigned long minflt;
  unsigned long cminflt;
  unsigned long majflt;
  unsigned long cmajflt;
  unsigned long utime;
  unsigned long stime;
  unsigned long cutime;
  unsigned long cstime;
  long priority;
  long nice;
  long num_threads;
  long itrealvalue;
  long long starttime;
  unsigned long vsize;
  long rss;
  unsigned long rsslim;
  unsigned long startcode;
  unsigned long endcode;
  unsigned long startstack;
  unsigned long kstkesp;
  unsigned long kstkeip;
  unsigned long signal;
  unsigned long blocked;
  unsigned long sigignore;
  unsigned long sigcatch;
  unsigned long wchan;
  unsigned long nswap;
  unsigned long cnswap;
  int exit_signal;
  int processor;
};

static int
parse_proc_pid_stat(int pid, struct process_info *info)
{
  char path[PATH_MAX];
  FILE *f = NULL;
  char buf[8192];
  int blen;

  memset(info, 0, sizeof(*info));
  if (snprintf(path, sizeof(path), "%s/%d/stat", proc_path, pid) >= sizeof(path)) abort();
  f = fopen(path, "r");
  if (!f) {
      goto fail;
  }
  if (!fgets(buf, sizeof(buf), f)) goto fail;
  blen = strlen(buf);
  if (blen + 1 == sizeof(buf)) goto fail;
  fclose(f); f = NULL;

  char *p = strrchr(buf, ')');
  if (!p) goto fail;
  ++p;

  int r = sscanf(p, " %c%d%d%d%d%d%u%lu%lu%lu%lu%lu%lu%lu%lu%ld%ld%ld%ld%llu%lu%ld%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%d%d",
                 &info->state,
                 &info->ppid,
                 &info->pgrp,
                 &info->session,
                 &info->tty_nr,
                 &info->tpgid,
                 &info->flags,
                 &info->minflt,
                 &info->cminflt,
                 &info->majflt,
                 &info->cmajflt,
                 &info->utime,
                 &info->stime,
                 &info->cutime,
                 &info->cstime,
                 &info->priority,
                 &info->nice,
                 &info->num_threads,
                 &info->itrealvalue,
                 &info->starttime,
                 &info->vsize,
                 &info->rss,
                 &info->rsslim,
                 &info->startcode,
                 &info->endcode,
                 &info->startstack,
                 &info->kstkesp,
                 &info->kstkeip,
                 &info->signal,
                 &info->blocked,
                 &info->sigignore,
                 &info->sigcatch,
                 &info->wchan,
                 &info->nswap,
                 &info->cnswap,
                 &info->exit_signal,
                 &info->processor);
  if (r != 37) goto fail;

  return 0;

fail:
  if (f) fclose(f);
  return -1;
}

static int
count_processes(void)
{
    DIR *d = opendir(proc_path);
    if (!d) {
        kill_all();
        ffatal("failed to open %s: %s", proc_path, strerror(errno));
    }
    struct dirent *dd;
    int count = 0;
    while ((dd = readdir(d))) {
        errno = 0;
        char *eptr = NULL;
        long v = strtol(dd->d_name, &eptr, 10);
        if (!errno && !*eptr && eptr != dd->d_name && v > 1) {
            ++count;
        }
    }
    closedir(d);
    return count;
}

#define MQUEUE_MOUNT_DIR "/dev/mqueue"

static int
scan_posix_mqueue(int search_uid)
{
    DIR *d = NULL;
    struct dirent *dd;
    int count = 0;

    if (!(d = opendir(MQUEUE_MOUNT_DIR))) return 0;

    while ((dd = readdir(d))) {
        char buf[PATH_MAX];
        if (snprintf(buf, sizeof(buf), "%s/%s", MQUEUE_MOUNT_DIR, dd->d_name) >= sizeof(buf)) continue;
        struct stat stb;
        if (lstat(buf, &stb) < 0) continue;
        if (!S_ISREG(stb.st_mode)) continue;
        if (stb.st_uid != search_uid) continue;
        ++count;
        flog("POSIX message queue: name = /%s, perms = %03o", dd->d_name, (stb.st_mode & 0777));
    }
    closedir(d); d = NULL;

    return count;
}

static int
scan_msg(int search_uid)
{
    int count = 0;
    char buf[1024];

    char full_path[PATH_MAX];
    if (snprintf(full_path, sizeof(full_path), "%s/sysvipc/msg", proc_path) >= sizeof(full_path)) abort();

    FILE *f = fopen(full_path, "r");
    if (!f) return 0;

    if (getl(buf, sizeof(buf), f) < 0) {
        ffatal("unexpected EOF in '/proc/sysvipc/msg'");
    }
    while (getl(buf, sizeof(buf), f) >= 0) {
        int key = 0, msgid = 0, perms = 0, cbytes = 0, qnum = 0, lspid = 0, lrpid = 0, uid = 0, gid = 0;
        if (sscanf(buf, "%d%d%o%d%d%d%d%d%d", &key, &msgid, &perms, &cbytes, &qnum, &lspid, &lrpid, &uid, &gid) != 9) {
            ffatal("format error in '/proc/sysvipc/msg'");
        }
        if (uid == search_uid) {
            flog("message queue: key = 0x%08x, msgid = %d, perms = %03o", key, msgid, perms);
            if (msgctl(msgid, IPC_RMID, NULL) < 0) {
                flog("msgctl failed: %s", strerror(errno));
            }
            ++count;
        }
    }

    fclose(f);
    return count;
}

static int
scan_sem(int search_uid)
{
    int count = 0;
    char buf[1024];

    char full_path[PATH_MAX];
    if (snprintf(full_path, sizeof(full_path), "%s/sysvipc/sem", proc_path) >= sizeof(full_path)) abort();

    FILE *f = fopen(full_path, "r");
    if (!f) return 0;

    if (getl(buf, sizeof(buf), f) < 0) {
        ffatal("unexpected EOF in '/proc/sysvipc/sem'");
    }
    while (getl(buf, sizeof(buf), f) >= 0) {
        int key = 0, semid = 0, perms = 0, nsems = 0, uid = 0, gid = 0, cuid = 0;
        if (sscanf(buf, "%d%d%o%d%d%d%d", &key, &semid, &perms, &nsems, &uid, &gid, &cuid) != 7) {
            ffatal("format error in '/proc/sysvipc/sem'");
        }
        if (uid == search_uid || cuid == search_uid) {
            flog("semaphore array: key = 0x%08x, semid = %d, perms = %03o", key, semid, perms);
            if (semctl(semid, 0, IPC_RMID, NULL) < 0) {
                flog("semctl failed: %s", strerror(errno));
            }
            ++count;
        }
    }

    fclose(f);
    return count;
}

static int
scan_shm(int search_uid)
{
    int count = 0;
    char buf[1024];

    char full_path[PATH_MAX];
    if (snprintf(full_path, sizeof(full_path), "%s/sysvipc/shm", proc_path) >= sizeof(full_path)) abort();

    FILE *f = fopen(full_path, "r");
    if (!f) return 0;

    if (getl(buf, sizeof(buf), f) < 0) {
        ffatal("unexpected EOF in '/proc/sysvipc/shm'");
    }
    while (getl(buf, sizeof(buf), f) >= 0) {
        int key = 0, shmid = 0, perms = 0, size = 0, cpid = 0, lpid = 0, nattch = 0, uid = 0, gid = 0;
        if (sscanf(buf, "%d%d%o%d%d%d%d%d%d", &key, &shmid, &perms, &size, &cpid, &lpid, &nattch, &uid, &gid) != 9) {
            ffatal("format error in '/proc/sysvipc/shm'");
        }
        if (uid == search_uid) {
            flog("shared memory: key = 0x%08x, shmid = %d, perms = %03o", key, shmid, perms);
            if (shmctl(shmid, IPC_RMID, NULL) < 0) {
                flog("shmctl failed: %s", strerror(errno));
            }
            ++count;
        }
    }

    fclose(f);
    return count;
}

static void
write_buf_to_file(const char *path, const char *buf, int len)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
        _exit(127);
    }
    int z;
    errno = 0;
    if ((z = write(fd, buf, len)) != len) {
        fprintf(stderr, "failed to write to %s: %d, %s\n", path, z, strerror(errno));
        _exit(127);
    }
    if (close(fd) < 0) {
        fprintf(stderr, "failed to close %s: %s\n", path, strerror(errno));
        _exit(127);
    }
}

static void
write_buf_to_file_fatal(const char *path, const char *buf, int len)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        ffatal("failed to open %s: %s", path, strerror(errno));
    }
    int z;
    errno = 0;
    if ((z = write(fd, buf, len)) != len) {
        ffatal("failed to write to %s: %d, %s", path, z, strerror(errno));
    }
    if (close(fd) < 0) {
        ffatal("failed to close %s: %s", path, strerror(errno));
    }
}

static void
write_buf_to_file_if_exists(const char *path, const char *buf, int len)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        if (errno == ENOENT) return;
        ffatal("failed to open %s: %s", path, strerror(errno));
    }
    int z;
    errno = 0;
    if ((z = write(fd, buf, len)) != len) {
        ffatal("failed to write to %s: %d, %s", path, z, strerror(errno));
    }
    if (close(fd) < 0) {
        ffatal("failed to close %s: %s", path, strerror(errno));
    }
}

static void
enable_controllers(void)
{
    write_buf_to_file_fatal("/sys/fs/cgroup/cgroup.subtree_control", "+cpu", 4);
    write_buf_to_file_fatal("/sys/fs/cgroup/ejudge/cgroup.subtree_control", "+cpu +memory", 12);
}

static void
create_cgroup(void)
{
    // generate random cgroup name
    int rfd = open("/dev/urandom", O_RDONLY);
    if (rfd < 0) ffatal("cannot open /dev/urandom: %s", strerror(errno));
    unsigned long long ullval = 0;
    errno = 0;
    int z;
    if ((z = read(rfd, &ullval, sizeof(ullval))) != sizeof(ullval)) {
        ffatal("invalid read from /dev/urandom: %d, %s\n", z, strerror(errno));
    }
    close(rfd);
    snprintf(cgroup_name, sizeof(cgroup_name), "%llx", ullval);

    if (cgroup_v2_detected) {
        int r;
        if ((r = mkdir("/sys/fs/cgroup/ejudge", 0700)) < 0 && errno != EEXIST) {
            ffatal("cannot create directory /sys/fs/cgroup/ejudge: %s", strerror(errno));
        }
        if (r >= 0) {
            enable_controllers();
        }
        if (snprintf(cgroup_unified_path, sizeof(cgroup_unified_path), "/sys/fs/cgroup/ejudge/%s", cgroup_name) >= sizeof(cgroup_unified_path)) {
            ffatal("invalid cgroup path");
        }
        if (mkdir(cgroup_unified_path, 0700) < 0) {
            ffatal("failed to create %s: %s", cgroup_unified_path, strerror(errno));
        }
    } else {
        if (snprintf(cgroup_cpu_path, sizeof(cgroup_cpu_path), "%s/ejudge", cgroup_v1_cpu_default_path) >= sizeof(cgroup_cpu_path)) {
            ffatal("invalid cgroup path");
        }
        if (mkdir(cgroup_cpu_path, 0700) < 0 && errno != EEXIST) {
            ffatal("cannot create directory %s: %s", cgroup_cpu_path, strerror(errno));
        }
        if (snprintf(cgroup_cpu_path, sizeof(cgroup_cpu_path), "%s/ejudge/%s", cgroup_v1_cpu_default_path, cgroup_name) >= sizeof(cgroup_cpu_path)) {
            ffatal("invalid cgroup path");
        }
        if (mkdir(cgroup_cpu_path, 0700) < 0) {
            ffatal("failed to create %s: %s", cgroup_cpu_path, strerror(errno));
        }
        if (snprintf(cgroup_memory_path, sizeof(cgroup_memory_path), "%s/ejudge", cgroup_v1_memory_default_path) >= sizeof(cgroup_memory_path)) {
            ffatal("invalid cgroup path");
        }
        if (mkdir(cgroup_memory_path, 0700) < 0 && errno != EEXIST) {
            ffatal("cannot create directory cgroup_memory_path: %s", strerror(errno));
        }
        if (snprintf(cgroup_memory_path, sizeof(cgroup_memory_path), "%s/ejudge/%s", cgroup_v1_memory_default_path, cgroup_name) >= sizeof(cgroup_memory_path)) {
            ffatal("invalid cgroup path");
        }
        if (mkdir(cgroup_memory_path, 0700) < 0) {
            ffatal("failed to create %s: %s", cgroup_memory_path, strerror(errno));
        }
    }
}

static void
move_to_cgroup(void)
{
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%d", getpid());

    if (cgroup_v2_detected) {
        write_buf_to_file(cgroup_procs_path, buf, len);
    } else {
        write_buf_to_file(cgroup_memory_procs_path, buf, len);
        write_buf_to_file(cgroup_cpu_procs_path, buf, len);
    }
}

struct CGroupStat
{
    // CPU usage stats from cpu.stat
    long long usage_us;
    long long user_us;
    long long system_us;
};

static void
read_cgroup_stats_v2(struct CGroupStat *ps)
{
    FILE *f = NULL;

    char cpu_stat_path[PATH_MAX];
    if (snprintf(cpu_stat_path, sizeof(cpu_stat_path),
                 "%s/ejudge/%s/cpu.stat",
                 cgroup_path, cgroup_name) >= sizeof(cpu_stat_path)) {
        goto fail;
    }
    if (!(f = fopen(cpu_stat_path, "r"))) {
        goto fail;
    }
    char lbuf[1024];
    while (fgets(lbuf, sizeof(lbuf), f)) {
        int llen = strlen(lbuf);
        if (llen + 1 == sizeof(lbuf)) goto fail;
        while (isspace((unsigned char) lbuf[llen - 1])) --llen;
        lbuf[llen] = 0;
        char vbuf[1024];
        long long vval;
        int n;
        if (sscanf(lbuf, "%s%lld%n", vbuf, &vval, &n) != 2) goto fail;
        if (lbuf[n]) goto fail;
        if (!strcmp(vbuf, "usage_usec")) {
            ps->usage_us = vval;
        } else if (!strcmp(vbuf, "user_usec")) {
            ps->user_us = vval;
        } else if (!strcmp(vbuf, "system_usec")) {
            ps->system_us = vval;
        }
    }
    fclose(f);
    return;

fail:
    if (f) fclose(f);
    return;
}

static void
read_cgroup_stats_v1(struct CGroupStat *ps)
{
    FILE *f = NULL;

    char cpu_stat_path[PATH_MAX];
    if (snprintf(cpu_stat_path, sizeof(cpu_stat_path),
                 "%s/ejudge/%s/cpuacct.stat",
                 cgroup_cpu_base_path, cgroup_name) >= sizeof(cpu_stat_path)) {
        goto fail;
    }
    if (!(f = fopen(cpu_stat_path, "r"))) {
        goto fail;
    }
    char lbuf[1024];
    while (fgets(lbuf, sizeof(lbuf), f)) {
        int llen = strlen(lbuf);
        if (llen + 1 == sizeof(lbuf)) goto fail;
        while (isspace((unsigned char) lbuf[llen - 1])) --llen;
        lbuf[llen] = 0;
        char vbuf[1024];
        long long vval;
        int n;
        if (sscanf(lbuf, "%s%lld%n", vbuf, &vval, &n) != 2) goto fail;
        if (lbuf[n]) goto fail;
        if (!strcmp(vbuf, "user")) {
            ps->user_us = vval * (HZ * 1000);
        } else if (!strcmp(vbuf, "system")) {
            ps->system_us = vval * (HZ * 1000);
        }
    }
    ps->usage_us = ps->user_us + ps->system_us;
    fclose(f);
    return;

fail:
    if (f) fclose(f);
    return;
}

static void
read_cgroup_stats(struct CGroupStat *ps)
{
    if (cgroup_v2_detected) {
        read_cgroup_stats_v2(ps);
    } else {
        read_cgroup_stats_v1(ps);
    }
}

static struct sock_filter seccomp_filter_default[] =
{
    // load syscall number
    /*  0 */ BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, nr))),

    // blacklist fork-like syscalls
#if defined __NR_fork
    /*  1 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_fork, 0, 1),
    /*  2 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /*  1 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /*  2 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif
#if defined __NR_vfork
    /*  3 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_vfork, 0, 1),
    /*  4 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /*  3 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /*  4 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif
#if defined __NR_clone
    /*  5 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_clone, 0, 1),
    /*  6 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /*  5 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /*  6 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif
#if defined __NR_clone3
    /*  7 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_clone3, 0, 1),
    /*  8 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /*  7 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /*  8 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif

    // blacklist exec-like syscalls
#if defined __NR_execveat
    /*  9 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execveat, 0, 1),
    /* 10 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /*  9 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /* 10 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif

    // we have to allow initial execve into a starting program
    /* 11 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execve, 0, 3),
    /* 12 */ BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, args[0]))),
    /* 13 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0), // patched in tune_seccomp
    /* 14 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),

    // blacklist memfd_create
#if defined __NR_memfd_create
    /* 15 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_memfd_create, 0, 1),
    /* 16 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /* 15 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /* 16 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif

    // blacklist unshare
#if defined __NR_unshare
    /* 17 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_unshare, 0, 1),
    /* 18 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /* 17 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /* 18 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif

    // allow remaining
    /* 19 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
};

static struct sock_filter seccomp_filter_x86_64[] =
{
    /*  0 */ BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, arch))),
    /*  1 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 2, 0), // jeq (4)
    /*  2 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_I386, 21, 0),  // jeq (24)
    /*  3 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),

    // x86_64 part
    // load syscall number
    /*  4 */ BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, nr))),

    // blacklist fork-like syscalls
#if defined __NR_fork
    /*  5 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_fork, 0, 1),
    /*  6 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /*  5 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /*  6 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif
#if defined __NR_vfork
    /*  7 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_vfork, 0, 1),
    /*  8 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /*  7 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /*  8 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif
#if defined __NR_clone
    /*  9 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_clone, 0, 1),
    /* 10 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /*  9 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /* 10 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif
#if defined __NR_clone3
    /* 11 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_clone3, 0, 1),
    /* 12 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /* 11 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /* 12 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif

    // blacklist exec-like syscalls
#if defined __NR_execveat
    /* 13 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execveat, 0, 1),
    /* 14 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /* 13 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /* 14 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif

    // we have to allow initial execve into a starting program
    /* 15 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_execve, 0, 3),
    /* 16 */ BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, args[0]))),
    /* 17 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0), // patched in tune_seccomp
    /* 18 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),

    // blacklist memfd_create
#if defined __NR_memfd_create
    /* 19 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_memfd_create, 0, 1),
    /* 20 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /* 19 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /* 20 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif

    // blacklist unshare
#if defined __NR_unshare
    /* 21 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_unshare, 0, 1),
    /* 22 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /* 21 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /* 22 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif

    // allow remaining
    /* 23 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),

    // i686 under x86_64 part
    // load syscall number
    /* 24 */ BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, nr))),

    // blacklist fork-like syscalls
    /* 25 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_32_fork, 0, 1),
    /* 26 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
    /* 27 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_32_vfork, 0, 1),
    /* 28 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
    /* 29 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_32_clone, 0, 1),
    /* 30 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),

#if defined __NR_32_clone3
    /* 31 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_32_clone3, 0, 1),
    /* 32 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /* 31 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /* 32 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif

    // blacklist exec-like syscalls
    /* 33 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_32_execve, 0, 1),
    /* 34 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),

#if defined __NR_32_execveat
    /* 35 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_32_execveat, 0, 1),
    /* 36 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /* 35 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /* 36 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif

    // blacklist memfd_create
#if defined __NR_32_memfd_create
    /* 37 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_32_memfd_create, 0, 1),
    /* 38 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /* 37 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /* 38 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif

    // blacklist unshare
#if defined __NR_32_unshare
    /* 39 */ BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_32_unshare, 0, 1),
    /* 40 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
#else
    /* 39 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    /* 40 */ BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
#endif

    // allow remaining
    /* 41 */ BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
};

static __attribute__((unused)) struct sock_fprog seccomp_prog_x86_64 =
{
    .len = (unsigned short)(sizeof(seccomp_filter_x86_64) / sizeof(seccomp_filter_x86_64[0])),
    .filter = seccomp_filter_x86_64,
};

static __attribute__((unused)) struct sock_fprog seccomp_prog_default =
{
    .len = (unsigned short)(sizeof(seccomp_filter_default) / sizeof(seccomp_filter_default[0])),
    .filter = seccomp_filter_default,
};

static const struct sock_fprog *seccomp_prog_active = NULL;

static void
tune_seccomp()
{
    static struct sock_filter nop[] =
    {
        BPF_JUMP(BPF_JMP+BPF_JA, 0, 0, 0),
    };

    if (!enable_seccomp) return;

#if defined __x86_64__
    seccomp_prog_active = &seccomp_prog_x86_64;
    {
        struct sock_filter patch1[] =
        {
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (uintptr_t) start_program, 1, 0),
        };
        seccomp_filter_x86_64[17] = patch1[0];  // FIXME: index may change!
    }
    if (enable_sys_fork) {
        seccomp_filter_x86_64[5] = nop[0];
        seccomp_filter_x86_64[6] = nop[0];
        seccomp_filter_x86_64[7] = nop[0];
        seccomp_filter_x86_64[8] = nop[0];
        seccomp_filter_x86_64[9] = nop[0];
        seccomp_filter_x86_64[10] = nop[0];
        seccomp_filter_x86_64[11] = nop[0];
        seccomp_filter_x86_64[12] = nop[0];
        seccomp_filter_x86_64[25] = nop[0];
        seccomp_filter_x86_64[26] = nop[0];
        seccomp_filter_x86_64[27] = nop[0];
        seccomp_filter_x86_64[28] = nop[0];
        seccomp_filter_x86_64[29] = nop[0];
        seccomp_filter_x86_64[30] = nop[0];
        seccomp_filter_x86_64[31] = nop[0];
        seccomp_filter_x86_64[32] = nop[0];
    }
    if (enable_sys_execve) {
        seccomp_filter_x86_64[13] = nop[0];
        seccomp_filter_x86_64[14] = nop[0];
        seccomp_filter_x86_64[15] = nop[0];
        seccomp_filter_x86_64[16] = nop[0];
        seccomp_filter_x86_64[17] = nop[0];
        seccomp_filter_x86_64[18] = nop[0];
        seccomp_filter_x86_64[33] = nop[0];
        seccomp_filter_x86_64[34] = nop[0];
        seccomp_filter_x86_64[35] = nop[0];
        seccomp_filter_x86_64[36] = nop[0];
    }
    if (enable_sys_memfd) {
        seccomp_filter_x86_64[19] = nop[0];
        seccomp_filter_x86_64[20] = nop[0];
        seccomp_filter_x86_64[37] = nop[0];
        seccomp_filter_x86_64[38] = nop[0];
    }
    if (enable_sys_unshare) {
        seccomp_filter_x86_64[21] = nop[0];
        seccomp_filter_x86_64[22] = nop[0];
        seccomp_filter_x86_64[39] = nop[0];
        seccomp_filter_x86_64[40] = nop[0];
    }
#else
    seccomp_prog_active = &seccomp_prog_default;
    {
        struct sock_filter patch1[] =
        {
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (uintptr_t) start_program, 1, 0),
        };
        seccomp_filter_default[13] = patch1[0];  // FIXME: index may change!
    }
    if (enable_sys_fork) {
        seccomp_filter_default[1] = nop[0];
        seccomp_filter_default[2] = nop[0];
        seccomp_filter_default[3] = nop[0];
        seccomp_filter_default[4] = nop[0];
        seccomp_filter_default[5] = nop[0];
        seccomp_filter_default[6] = nop[0];
        seccomp_filter_default[7] = nop[0];
        seccomp_filter_default[8] = nop[0];
    }
    if (enable_sys_execve) {
        seccomp_filter_default[9] = nop[0];
        seccomp_filter_default[10] = nop[0];
        seccomp_filter_default[11] = nop[0];
        seccomp_filter_default[12] = nop[0];
        seccomp_filter_default[13] = nop[0];
        seccomp_filter_default[14] = nop[0];
    }
    if (enable_sys_memfd) {
        seccomp_filter_default[15] = nop[0];
        seccomp_filter_default[16] = nop[0];
    }
    if (enable_sys_unshare) {
        seccomp_filter_default[17] = nop[0];
        seccomp_filter_default[18] = nop[0];
    }
#endif
}

static void
set_cgroup_rss_limit(void)
{
    int len;
    char path[PATH_MAX], data[1024];

    if (cgroup_v2_detected) {
        if (snprintf(path, sizeof(path), "%s/memory.max", cgroup_unified_path) >= sizeof(path)) {
            ffatal("path too long");
        }
        if ((len = snprintf(data, sizeof(data), "%lld", limit_rss_size)) >= sizeof(data)) {
            ffatal("data too long");
        }
        write_buf_to_file_fatal(path, data, len);

        if (snprintf(path, sizeof(path), "%s/memory.swap.max", cgroup_unified_path) >= sizeof(path)) {
            ffatal("path too long");
        }
        write_buf_to_file_if_exists(path, "0", 1);
    } else {
        if ((len = snprintf(data, sizeof(data), "%lld", limit_rss_size)) >= sizeof(data)) {
            ffatal("data too long");
        }
        if (snprintf(path, sizeof(path), "%s/memory.limit_in_bytes", cgroup_memory_path) >= sizeof(path)) {
            ffatal("path too long");
        }
        write_buf_to_file_fatal(path, data, len);
        if (snprintf(path, sizeof(path), "%s/memory.memsw.limit_in_bytes", cgroup_memory_path) >= sizeof(path)) {
            ffatal("path too long");
        }
        write_buf_to_file_if_exists(path, data, len);
    }
}

static void
apply_language_profiles(void)
{
    if (!language_name || !*language_name) return;

    if (!strcmp(language_name, "javac7")
        || !strcmp(language_name, "javac")
        || !strcmp(language_name, "kotlin")
        || !strcmp(language_name, "scala")) {
        enable_sys_fork = 1;
        enable_sys_execve = 1;
        enable_proc = 1;
        limit_vm_size = -1;     // VM limit set by environment var
        limit_stack_size = 1024 * 1024; // 1M
        limit_processes = 40;
    } else if (!strcmp(language_name, "mcs") || !strcmp(language_name, "vbnc")
               || !strcmp(language_name, "pasabc-linux")) {
        enable_sys_fork = 1;
        enable_sys_execve = 1;
        enable_proc = 1;
        limit_stack_size = 1024 * 1024; // 1M
        if (limit_vm_size > 0 && limit_rss_size <= 0) {
            limit_rss_size = limit_vm_size;
            limit_vm_size = -1;
        }
    } else if (!strcmp(language_name, "pypy") || !strcmp(language_name, "pypy3")) {
        enable_proc = 1;
    } else if (!strcmp(language_name, "gcc-vg") || !strcmp(language_name, "g++-vg")) {
        enable_sys_fork = 1;
        enable_sys_execve = 1;
        enable_proc = 1;
        limit_vm_size = -1;
    } else if (!strcmp(language_name, "dotnet-cs") || !strcmp(language_name, "dotnet-vb")) {
        enable_sys_fork = 1;
        enable_sys_execve = 1;
        enable_sys_memfd = 1;
        enable_proc = 1;
        limit_processes = 40;
        limit_stack_size = 1024 * 1024; // 1M
        if (limit_vm_size > 0 && limit_rss_size <= 0) {
            limit_rss_size = limit_vm_size;
            limit_vm_size = -1;
        }
    } else if (!strcmp(language_name, "make")) {
        enable_sys_fork = 1;
        enable_sys_execve = 1;
        enable_proc = 1;
    } else if (!strcmp(language_name, "make-vg")) {
        enable_sys_fork = 1;
        enable_sys_execve = 1;
        enable_proc = 1;
        limit_vm_size = -1;
    } else if (!strcmp(language_name, "gccgo")) {
        enable_sys_fork = 1;
        enable_sys_execve = 1;
        enable_proc = 1;
        limit_processes = 20;
        if (limit_vm_size > 0 && limit_rss_size <= 0) {
            limit_rss_size = limit_vm_size;
            limit_vm_size = -1;
        }
    } else if (!strcmp(language_name, "node")) {
        enable_sys_fork = 1;
        limit_processes = 20;
        limit_stack_size = 1024 * 1024; // 1M
        if (limit_vm_size > 0 && limit_rss_size <= 0) {
            limit_rss_size = limit_vm_size;
            limit_vm_size = -1;
        }
    } else if (!strcmp(language_name, "tsnode")) {
        enable_sys_fork = 1;
        enable_sys_execve = 1;
        limit_processes = 20;
        limit_stack_size = 1024 * 1024; // 1M
        if (limit_vm_size > 0 && limit_rss_size <= 0) {
            limit_rss_size = limit_vm_size;
            limit_vm_size = -1;
        }
    } else if (!strcmp(language_name, "ruby")) {
        enable_sys_fork = 1;
        enable_sys_execve = 1;
    } else if (!strcmp(language_name, "postgres")) {
        enable_sys_fork = 1;
        enable_sys_execve = 1;
        enable_proc = 1;
        enable_sys = 1;
        enable_etc = 1;
        enable_net_ns = 0;
        limit_processes = 20;
    }
}

static char *
extract_string(const char **ppos, int init_offset, const char *opt_name)
{
    const char *pos = *ppos + init_offset;
    if (*pos >= '0' && *pos <= '9') {
        char *eptr = NULL;
        errno = 0;
        long v = strtol(pos, &eptr, 10);
        if (errno || v < 0 || (int) v != v) {
            ffatal("invalid specification for option %s", opt_name);
        }
        int len = v;
        pos = eptr;
        char *str = calloc(len + 1, 1);
        strncpy(str, pos, len);
        int len2 = strlen(pos);
        if (len2 < len) len = len2;
        pos += len;
        *ppos = pos;
        return str;
    } else if (*pos) {
        char sep = *pos++;
        const char *start = pos;
        int len = 0;
        while (*pos && *pos != sep) { ++len; ++pos; }
        if (!*pos) ffatal("invalid specification for option %s", opt_name);
        char *str = calloc(len + 1, 1);
        memcpy(str, start, len);
        *ppos = ++pos;
        return str;
    } else {
        ffatal("invalid specification for option %s", opt_name);
    }
}

static long long
extract_size(const char **ppos, int init_offset, const char *opt_name)
{
    const char *pos = *ppos + init_offset;
    errno = 0;
    char *eptr = NULL;
    long long v = strtoll(pos, &eptr, 10);
    if (errno || eptr == pos || v < 0) {
        ffatal("invalid size for option %s", opt_name);
    }
    pos = eptr;
    if (*pos == 'k' || *pos == 'K') {
        if (__builtin_mul_overflow(v, 1024LL, &v)) fatal("size overflow for option %s", opt_name);
        ++pos;
    } else if (*pos == 'm' || *pos == 'M') {
        if (__builtin_mul_overflow(v, 1048576LL, &v)) fatal("size overflow for option %s", opt_name);
        ++pos;
    } else if (*pos == 'g' || *pos == 'G') {
        if (__builtin_mul_overflow(v, 1073741824LL, &v)) fatal("size overflow for option %s", opt_name);
        ++pos;
    }
    if ((size_t) v != v) ffatal("size overflow for option %s", opt_name);
    *ppos = pos;
    return v;
}

/*
 * option specification:
 *   f<FD>  - set log file descriptor
 *   mg     - disable control group
 *   mi     - disable IPC namespace
 *   mn     - disable net namespace
 *   mm     - disable mount namespace
 *   mp     - disable PID namespace
 *   mP     - enable /proc filesystem
 *   mS     - enable /sys filesystem
 *   mv     - enable original /var filesystem
 *   me     - enable original /etc filesystem
 *   ms     - disable bindind of working dir to /sandbox
 *   mh     - enable /home filesystem
 *   mo     - disable chown to ejexec
 *   mG     - disable process group
 *   mc     - enable orphaned process count
 *   mI     - enable IPC count
 *   ma     - unlimited cpu time
 *   mb     - unlimited real time
 *   md     - enable /dev filesystem
 *   mD     - enable subdirectory mode
 *   mC     - switch to ejcompile user instead of ejexec
 *   mr     - preserve original /run directory
 *   ml     - setup lo inteface inside the container
 *   mV     - explicitly disable setting of VM size limit
 *   w<DIR> - working directory (cwd by default)
 *   rn     - redirect to/from /dev/null for standard streams
 *   rm     - merge stdout and stderr output
 *   ri<FI> - redirect stdin < FI
 *   ro<FI> - redirect stdout > FI
 *   rO<FI> - redirect stdout >> FI
 *   re<FI> - redirect stderr > FI
 *   rE<FI> - redirect stderr >> FI
 *   rp<S>  - set start program path if differ from argv[0]
 *   ra<FD> - redirect stdin from FD
 *   rb<FD> - redirect stdout to FD
 *   lt<T>  - set CPU time limit (ms)
 *   lr<T>  - set REAL time limit (ms)
 *   lm<M>  - set umask (M - octal value)
 *   lo<N>  - set limit to file descriptors
 *   ls<Z>  - set stack limit
 *   lv<Z>  - set VM limit
 *   lR<Z>  - set RSS limit
 *   lf<Z>  - set file size limit
 *   lu<N>  - set user processes limit
 *   ol<S>  - set programming language name
 *   s0     - disable syscall filtering
 *   se     - enable execve(at)
 *   sf     - enable fork, vfork, clone, clone3
 *   sm     - enable memfd_create
 *   su     - enable unshare
 *   cf<FD> - specify control socket fd
 *   cu<N>  - specify ejcompile/ejexec serial (ejexec1, ejexec2...)
 */

int
main(int argc, char *argv[])
{
    int argi = 1;
    int limit_vm_set = 0;

    {
        char *p = strrchr(argv[0], '/');
        if (p) program_name = p + 1;
        else program_name = argv[0];
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_DFL);
    log_f = open_memstream(&log_s, &log_z);

    snprintf(safe_dir_path, sizeof(safe_dir_path), "%s/share/ejudge/container", EJUDGE_PREFIX_DIR);

    if (argc < 1) {
        flog("wrong number of arguments");
        fatal();
    }

    if (argi < argc && argv[argi][0] == '-') {
        // parse options
        const char *opt = argv[argi++] + 1;
        while (*opt) {
            if (*opt == ',') {
                ++opt;
            } else if (*opt == 'f') {
                // log file descriptor
                char *eptr = NULL;
                errno = 0;
                long v = strtol(opt + 1, &eptr, 10);
                int flags;
                if (errno || eptr == opt + 1 || v < 0 || (int) v != v
                    || (flags = fcntl((int) v, F_GETFD)) < 0
                    || fcntl((int) v, F_SETFD, flags | O_CLOEXEC) < 0) {
                    flog("invalig log file descriptor");
                    fatal();
                }
                response_fd = v;
                opt = eptr;
            } else if (*opt == 'm' && opt[1] == 'g') {
                enable_cgroup = 0;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'i') {
                enable_ipc_ns = 0;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'n') {
                enable_net_ns = 0;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'm') {
                enable_mount_ns = 0;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'p') {
                enable_pid_ns = 0;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'P') {
                enable_proc = 1;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'S') {
                enable_sys = 1;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 's') {
                enable_sandbox_dir = 0;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'h') {
                enable_home = 1;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'o') {
                enable_chown = 0;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'G') {
                enable_pgroup = 0;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'c') {
                enable_prc_count = 1;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'I') {
                enable_ipc_count = 1;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'a') {
                limit_cpu_time_ms = -1;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'b') {
                limit_real_time_ms = -1;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'd') {
                enable_dev = 1;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'v') {
                enable_var = 1;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'e') {
                enable_etc = 1;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'D') {
                enable_subdir_mode = 1;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'C') {
                enable_compile_mode = 1;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'r') {
                enable_run = 1;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'l') {
                enable_loopback = 1;
                opt += 2;
            } else if (*opt == 'm' && opt[1] == 'V') {
                enable_vm_limit = 0;
                opt += 2;
            } else if (*opt == 'w') {
                working_dir = extract_string(&opt, 1, "w");
            } else if (*opt == 'r' && opt[1] == 'n') {
                enable_redirect_null = 1;
                opt += 2;
            } else if (*opt == 'r' && opt[1] == 'm') {
                enable_output_merge = 1;
                opt += 2;
            } else if (*opt == 'r' && opt[1] == 'i') {
                stdin_name = extract_string(&opt, 2, "ri");
            } else if (*opt == 'r' && opt[1] == 'o') {
                stdout_name = extract_string(&opt, 2, "ro");
                stdout_mode = O_WRONLY | O_CREAT | O_TRUNC;
            } else if (*opt == 'r' && opt[1] == 'O') {
                stdout_name = extract_string(&opt, 2, "rO");
                stdout_mode = O_WRONLY | O_CREAT | O_APPEND;
            } else if (*opt == 'r' && opt[1] == 'e') {
                stderr_name = extract_string(&opt, 2, "re");
                stderr_mode = O_WRONLY | O_CREAT | O_TRUNC;
            } else if (*opt == 'r' && opt[1] == 'E') {
                stderr_name = extract_string(&opt, 2, "rE");
                stderr_mode = O_WRONLY | O_CREAT | O_APPEND;
            } else if (*opt == 'r' && opt[1] == 'p') {
                start_program_name = extract_string(&opt, 2, "rp");
            } else if (*opt == 'r' && opt[1] == 'a') {
                char *eptr = NULL;
                errno = 0;
                long v = strtol(opt + 2, &eptr, 10);
                struct stat stb;
                if (errno || eptr == opt + 2 || v < 0 || (int) v != v || fstat(v, &stb) < 0) {
                    ffatal("invalid file descriptor");
                }
                stdin_external_fd = v;
                opt = eptr;
            } else if (*opt == 'r' && opt[1] == 'b') {
                char *eptr = NULL;
                errno = 0;
                long v = strtol(opt + 2, &eptr, 10);
                struct stat stb;
                if (errno || eptr == opt + 2 || v < 0 || (int) v != v || fstat(v, &stb) < 0) {
                    ffatal("invalid file descriptor");
                }
                stdout_external_fd = v;
                opt = eptr;
            } else if (*opt == 'l' && opt[1] == 'm') {
                char *eptr = NULL;
                errno = 0;
                long v = strtol(opt + 2, &eptr, 8);
                if (errno || eptr == opt + 2 || v < 0) {
                    ffatal("invalid umask");
                }
                limit_umask = v & 0777;
                opt = eptr;
            } else if (*opt == 'l' && opt[1] == 'o') {
                char *eptr = NULL;
                errno = 0;
                long v = strtol(opt + 2, &eptr, 10);
                if (errno || eptr == opt + 2 || v < 0 || (int) v != v) {
                    ffatal("invalid open files limit");
                }
                if (!v) v = -1;
                limit_open_files = v;
                opt = eptr;
            } else if (*opt == 'l' && opt[1] == 's') {
                limit_stack_size = extract_size(&opt, 2, "ls");
            } else if (*opt == 'l' && opt[1] == 'v') {
                limit_vm_size = extract_size(&opt, 2, "lv");
                limit_vm_set = 1;
            } else if (*opt == 'l' && opt[1] == 'R') {
                limit_rss_size = extract_size(&opt, 2, "lR");
            } else if (*opt == 'l' && opt[1] == 'f') {
                limit_file_size = extract_size(&opt, 2, "lf");
            } else if (*opt == 'l' && opt[1] == 'u') {
                char *eptr = NULL;
                errno = 0;
                long v = strtol(opt + 2, &eptr, 10);
                if (errno || eptr == opt + 2 || v < 0 || (int) v != v) {
                    ffatal("invalid processes limit");
                }
                if (!v) v = -1;
                limit_processes = v;
                opt = eptr;
            } else if (*opt == 'l' && opt[1] == 't') {
                char *eptr = NULL;
                errno = 0;
                long v = strtol(opt + 2, &eptr, 10);
                if (errno || eptr == opt + 2 || v < 0 || (int) v != v) {
                    ffatal("invalid cpu time limit");
                }
                if (!v) v = -1;
                limit_cpu_time_ms = v;
                opt = eptr;
            } else if (*opt == 'l' && opt[1] == 'r') {
                char *eptr = NULL;
                errno = 0;
                long v = strtol(opt + 2, &eptr, 10);
                if (errno || eptr == opt + 2 || v < 0 || (int) v != v) {
                    ffatal("invalid real time limit");
                }
                if (!v) v = -1;
                limit_real_time_ms = v;
                opt = eptr;
            } else if (*opt == 's' && opt[1] == '0') {
                enable_seccomp = 0;
                opt += 2;
            } else if (*opt == 's' && opt[1] == 'e') {
                enable_sys_execve = 1;
                opt += 2;
            } else if (*opt == 's' && opt[1] == 'f') {
                enable_sys_fork = 1;
                opt += 2;
            } else if (*opt == 's' && opt[1] == 'm') {
                enable_sys_memfd = 1;
                opt += 2;
            } else if (*opt == 's' && opt[1] == 'u') {
                enable_sys_unshare = 1;
                opt += 2;
            } else if (*opt == 'o' && opt[1] == 'l') {
                language_name = extract_string(&opt, 2, "ol");
            } else if (*opt == 'c' && opt[1] == 'f') {
                char *eptr = NULL;
                errno = 0;
                long v = strtol(opt + 2, &eptr, 10);
                if (errno || eptr == opt + 2 || v < 0 || (int) v != v) {
                    ffatal("invalid control socket fd");
                }
                struct stat stb;
                if (fstat(v, &stb) < 0 || !S_ISSOCK(stb.st_mode)) {
                    ffatal("invalid control socket fd");
                }
                control_socket_fd = v;
                opt = eptr;
            } else if (*opt == 'c' && opt[1] == 'u') {
                char *eptr = NULL;
                errno = 0;
                long v = strtol(opt + 2, &eptr, 10);
                if (errno || eptr == opt + 2 || v < 0 || (int) v != v) {
                    ffatal("invalid user serial");
                }
                exec_user_serial = v;
                opt = eptr;
            } else {
                flog("invalid option: %s", opt);
                fatal();
            }
        }

        char *p = argv[argi - 1];
        while (*p) *p++ = 0;
    }

    if (!limit_vm_set && limit_rss_size <= 0 && !enable_compile_mode) {
        limit_vm_size = DEFAULT_LIMIT_VM_SIZE;
    }

    get_user_ids();

    slave_uid = exec_uid;
    slave_gid = exec_gid;

#ifndef ENABLE_ANY_USER
    {
        int self_uid = getuid();
        if (self_uid != primary_uid && self_uid != 0) {
            ffatal("not allowed");
        }
    }
#endif

    if (enable_compile_mode) {
        if (compile_uid <= 0 || compile_gid <= 0) {
            ffatal("ejcompile user not set up");
        }
        slave_uid = compile_uid;
        slave_gid = compile_gid;
        if (limit_cpu_time_ms == DEFAULT_LIMIT_CPU_TIME_MS) {
            limit_cpu_time_ms = 60000;
        }
        limit_processes = 100;
    }

    apply_language_profiles();

    if (enable_subdir_mode && working_dir && working_dir[0]) {
        working_dir_parent = strdup(working_dir);
        int len = strlen(working_dir_parent);
        while (len > 0 && working_dir_parent[len - 1] == '/') --len;
        working_dir_parent[len] = 0;
        if (!len) ffatal("invalid working directory '%s'", working_dir);
        char *sl = strrchr(working_dir_parent, '/');
        if (!sl) ffatal("invalid working directory '%s'", working_dir);
        working_dir_name = strdup(sl + 1);
        *sl = 0;
        len = strlen(working_dir_parent);
        while (len > 0 && working_dir_parent[len - 1] == '/') --len;
        working_dir_parent[len] = 0;
        if (!len) ffatal("invalid working directory '%s'", working_dir);
    }

    start_args = argv + argi;
    if (start_program_name) {
        start_program = start_program_name;
    } else {
        start_program = argv[argi];
    }
    if (argi == argc) {
#ifdef ENABLE_BASH
        bash_mode = 1;
#else
        ffatal("no program to run");
#endif
    }

    if (enable_cgroup) {
        // check cgroup version
        if (access("/sys/fs/cgroup/cgroup.controllers", F_OK) >= 0) {
            cgroup_v2_detected = 1;
        } else {
            enable_sys = 1;
        }
    }

    if (!enable_proc) {
        snprintf(proc_path, sizeof(proc_path), "/run/0/proc");
    }
    if (!enable_sys) {
        if (cgroup_v2_detected) {
            snprintf(cgroup_path, sizeof(cgroup_path), "/run/0/cgroup");
        } else {
            snprintf(cgroup_memory_base_path, sizeof(cgroup_memory_base_path), "/run/0/memory");
            snprintf(cgroup_cpu_base_path, sizeof(cgroup_cpu_base_path), "/run/0/cpu,cpuacct");
        }
    }

    if (enable_chown) {
        change_ownership(slave_uid, slave_gid, primary_uid);
    }

    if (open_redirections() < 0) {
        if (enable_chown) {
            change_ownership(primary_uid, primary_gid, slave_uid);
        }
        fatal();
    }

    if (enable_cgroup) {
        create_cgroup();
    }

    unsigned clone_flags = CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID | SIGCHLD;
    if (enable_ipc_ns) clone_flags |= CLONE_NEWIPC;
    if (enable_net_ns) clone_flags |= CLONE_NEWNET;
    if (enable_mount_ns) clone_flags |= CLONE_NEWNS;
    if (enable_pid_ns) clone_flags |= CLONE_NEWPID;

    pid_t tidptr = 0;
    int pid = syscall(__NR_clone, clone_flags, NULL, NULL, &tidptr);
    if (pid < 0) {
        change_ownership(primary_uid, primary_gid, slave_uid);
        if (cgroup_unified_path[0]) rmdir(cgroup_unified_path);
        if (cgroup_cpu_path[0]) rmdir(cgroup_cpu_path);
        if (cgroup_memory_path[0]) rmdir(cgroup_memory_path);
        ffatal("clone failed: %s", strerror(errno));
    }

    if (!pid) {
        if (enable_mount_ns) {
            reconfigure_fs();
        }

        sigset_t bs;
        sigemptyset(&bs); sigaddset(&bs, SIGCHLD);
        sigprocmask(SIG_BLOCK, &bs, NULL);

        if (enable_loopback) {
            net_interface_up("lo", "127.0.0.1", "255.0.0.0");
        }

        if (enable_seccomp) {
            tune_seccomp();
        }

        if (enable_cgroup) {
            if (cgroup_v2_detected) {
                if (snprintf(cgroup_unified_path, sizeof(cgroup_unified_path), "%s/ejudge/%s", cgroup_path, cgroup_name) >= sizeof(cgroup_unified_path)) {
                    ffatal("cgroup path too long");
                }
                if (snprintf(cgroup_procs_path, sizeof(cgroup_procs_path), "%s/cgroup.procs", cgroup_unified_path) >= sizeof(cgroup_procs_path)) {
                    ffatal("cgroup path too long");
                }
            } else {
                if (snprintf(cgroup_memory_path, sizeof(cgroup_memory_path), "%s/ejudge/%s", cgroup_memory_base_path, cgroup_name) >= sizeof(cgroup_memory_path)) {
                    ffatal("cgroup path too long");
                }
                if (snprintf(cgroup_memory_procs_path, sizeof(cgroup_memory_procs_path), "%s/cgroup.procs", cgroup_memory_path) >= sizeof(cgroup_memory_procs_path)) {
                    ffatal("cgroup path too long");
                }
                if (snprintf(cgroup_cpu_path, sizeof(cgroup_cpu_path), "%s/ejudge/%s", cgroup_cpu_base_path, cgroup_name) >= sizeof(cgroup_cpu_path)) {
                    ffatal("cgroup path too long");
                }
                if (snprintf(cgroup_cpu_procs_path, sizeof(cgroup_cpu_procs_path), "%s/cgroup.procs", cgroup_cpu_path) >= sizeof(cgroup_cpu_procs_path)) {
                    ffatal("cgroup path too long");
                }
            }
        }

        if (enable_cgroup && limit_rss_size > 0) {
            set_cgroup_rss_limit();
        }

        // we need another child, because this one has PID 1
        int pid2 = fork();
        if (pid2 < 0) {
            ffatal("pid failed: %s", strerror(errno));
        }

        if (!pid2) {
            if (response_fd != 2) {
                close(response_fd);
                response_fd = -1;
            }
            if (control_socket_fd >= 0) {
                close(control_socket_fd);
                control_socket_fd = -1;
            }
            if (enable_cgroup) {
                move_to_cgroup();
            }
            if (enable_pgroup) {
                //setpgid(0, 0);
                if (setsid() < 0) fprintf(stderr, "setsid() failed: %s\n", strerror(errno));
            }
            if (enable_sandbox_dir) {
                if (chdir(sandbox_dir) < 0) {
                    fprintf(stderr, "failed to change dir to %s: %s\n", sandbox_dir, strerror(errno));
                    _exit(127);
                }
                if (working_dir_name && *working_dir_name) {
                    if (chdir(working_dir_name) < 0) {
                        fprintf(stderr, "failed to change dir to '%s': %s\n", working_dir_name, strerror(errno));
                        _exit(127);
                    }
                }
            } else if (working_dir && *working_dir) {
                if (chdir(working_dir) < 0) {
                    fprintf(stderr, "failed to change dir to %s: %s\n", working_dir, strerror(errno));
                    _exit(127);
                }
            }

            if (limit_umask >= 0) {
                umask(limit_umask & 0777);
            }

            /* not yet supported: RLIMIT_MEMLOCK, RLIMIT_MSGQUEUE, RLIMIT_NICE, RLIMIT_RTPRIO, RLIMIT_SIGPENDING */

            if (enable_vm_limit > 0 && limit_vm_size > 0) {
                struct rlimit lim = { .rlim_cur = limit_vm_size, .rlim_max = limit_vm_size };
                if (setrlimit(RLIMIT_AS, &lim) < 0) {
                    fprintf(stderr, "rlimit for RLIMIT_AS %lld failed: %s", limit_vm_size, strerror(errno));
                    _exit(127);
                }
            }

            if (limit_stack_size > 0) {
                struct rlimit lim = { .rlim_cur = limit_stack_size, .rlim_max = limit_stack_size };
                if (setrlimit(RLIMIT_STACK, &lim) < 0) {
                    fprintf(stderr, "rlimit for RLIMIT_STACK %lld failed: %s", limit_stack_size, strerror(errno));
                    _exit(127);
                }
            }

            if (limit_file_size >= 0) {
                struct rlimit lim = { .rlim_cur = limit_file_size, .rlim_max = limit_file_size };
                if (setrlimit(RLIMIT_FSIZE, &lim) < 0) {
                    fprintf(stderr, "rlimit for RLIMIT_FILE %lld failed: %s", limit_file_size, strerror(errno));
                    _exit(127);
                }
            }

            if (limit_processes >= 0) {
                struct rlimit lim = { .rlim_cur = limit_processes, .rlim_max = limit_processes };
                if (setrlimit(RLIMIT_NPROC, &lim) < 0) {
                    fprintf(stderr, "rlimit for RLIMIT_NPROC %d failed: %s", limit_processes, strerror(errno));
                    _exit(127);
                }
            }

            // disable core dumps
            {
                struct rlimit lim = { .rlim_cur = 0, .rlim_max = 0 };
                if (setrlimit(RLIMIT_CORE, &lim) < 0) {
                    fprintf(stderr, "rlimit for RLIMIT_CORE 0 failed: %s", strerror(errno));
                    _exit(127);
                }
            }

            if (stdin_fd >= 0) {
                dup2(stdin_fd, 0); close(stdin_fd);
            }
            if (stdout_fd >= 0) {
                dup2(stdout_fd, 1); close(stdout_fd);
            }
            if (stderr_fd >= 0) {
                dup2(stderr_fd, 2); close(stderr_fd);
            }

            if (limit_open_files >= 0) {
                struct rlimit lim = { .rlim_cur = limit_open_files, .rlim_max = limit_open_files };
                if (setrlimit(RLIMIT_NOFILE, &lim) < 0) {
                    fprintf(stderr, "rlimit for RLIMIT_NOFILE %d failed: %s", limit_open_files, strerror(errno));
                    _exit(127);
                }
            }

            sigset_t ss;
            sigemptyset(&ss);
            sigprocmask(SIG_SETMASK, &ss, NULL);
            signal(SIGPIPE, SIG_DFL);

            // switch to ejexec user
            if (setgid(slave_gid) < 0) {
                fprintf(stderr, "setgid failed: %s\n", strerror(errno));
                _exit(127);
            }
            gid_t supp_groups[1] = { slave_gid };
            if (setgroups(1, supp_groups) < 0) {
                fprintf(stderr, "setgroups failed: %s\n", strerror(errno));
                _exit(127);
            }
            if (setuid(slave_uid) < 0) {
                fprintf(stderr, "setuid setuid failed: %s\n", strerror(errno));
                _exit(127);
            }

            if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) < 0) {
                fprintf(stderr, "prctl failed: %s\n", strerror(errno));
                _exit(127);
            }

            if (enable_seccomp) {
                if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, seccomp_prog_active)) {
                    fprintf(stderr, "seccomp loading failed: %s\n", strerror(errno));
                    _exit(127);
                }
            }

            if (enable_compile_mode) {
                setenv("USER", COMPILE_USER, 1);
                setenv("LOGNAME", COMPILE_USER, 1);
                setenv("HOME", compile_dir, 1);
            }

            if (bash_mode) {
                printf("child: %d, %d, %d\n", getpid(), getppid(), tidptr);
                printf("init success, starting /bin/bash\n");
                execlp("/bin/bash", "/bin/bash", "-i", NULL);
                fprintf(stderr, "failed to exec /bin/bash: %s\n", strerror(errno));
            } else {
                execve(start_program, start_args, environ);
                fprintf(stderr, "failed to exec '%s': %s\n", start_program, strerror(errno));
            }

            _exit(127);
        }

        // now the child process is already running,
        // so we can't just fail, we have to kill created processes

        // parent

        if (enable_pgroup) {
            //setpgid(pid2, pid2);
        }
        if (stdin_fd >= 0) close(stdin_fd);
        if (stdout_fd >= 0) close(stdout_fd);
        if (stderr_fd >= 0) close(stderr_fd);
        stdin_fd = -1; stdout_fd = -1; stderr_fd = -1;

        int sfd = signalfd(-1, &bs, 0);
        if (sfd < 0) {
            kill_all();
            ffatal("failed to create signalfd: %s", strerror(errno));
        }

        int tfd = timerfd_create(CLOCK_REALTIME, 0);
        if (tfd < 0) {
            kill_all();
            ffatal("failed to create timerfd: %s", strerror(errno));
        }

        // 100ms interval
        struct itimerspec its = { .it_interval = { .tv_nsec = 100000000 }, .it_value = { .tv_nsec = 100000000 } };
        if (timerfd_settime(tfd, 0, &its, NULL) < 0) {
            kill_all();
            ffatal("failed timerfd_settime: %s", strerror(errno));
        }

        int efd = epoll_create1(0);
        if (efd < 0) {
            kill_all();
            ffatal("failed to create eventfd: %s", strerror(errno));
        }

        struct epoll_event see = { .events = EPOLLIN, .data = { .fd = sfd } };
        if (epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &see) < 0) {
            kill_all();
            ffatal("failed epoll_ctl: %s", strerror(errno));
        }

        struct epoll_event tee = { .events = EPOLLIN, .data = { .fd = tfd } };
        if (epoll_ctl(efd, EPOLL_CTL_ADD, tfd, &tee) < 0) {
            kill_all();
            ffatal("failed epoll_ctl: %s", strerror(errno));
        }

        if (control_socket_fd >= 0) {
            struct epoll_event ee = { .events = EPOLLIN, .data = { .fd = control_socket_fd } };
            if (epoll_ctl(efd, EPOLL_CTL_ADD, control_socket_fd, &ee) < 0) {
                kill_all();
                ffatal("failed epoll_ctl: %s", strerror(errno));
            }
        }

        long clock_ticks = sysconf(_SC_CLK_TCK);

        int prc_finished = 0;
        int prc_status = 0;
        struct rusage prc_usage = {};
        struct process_info prc_info = {};
        int prc_real_time_exceeded = 0;
        long long prc_start_time_us = 0;
        {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            prc_start_time_us = tv.tv_sec * 1000000LL + tv.tv_usec;
        }
        long long prc_stop_time_us = 0;
        long long prc_vm_size = -1;
        int prc_time_exceeded = 0;

        int flag = 1;
        while (flag) {
            struct epoll_event events[2];
            int res = epoll_wait(efd, events, 2, -1);
            if (res < 0) {
                kill_all();
                ffatal("failed epoll_wait: %s", strerror(errno));
            }
            if (!res) {
                kill_all();
                ffatal("unexpected 0 from epoll_wait");
            }
            for (int i = 0; i < res; ++i) {
                struct epoll_event *curev = &events[i];
                if (curev->data.fd == sfd) {
                    // received signal
                    struct signalfd_siginfo sss;
                    int z;
                    if ((z = read(sfd, &sss, sizeof(sss))) != sizeof(sss)) {
                        kill_all();
                        ffatal("read from signalfd return %d", z);
                    }
                    if (sss.ssi_signo != SIGCHLD) {
                        kill_all();
                        ffatal("unexpected signal %d", sss.ssi_signo);
                    }
                    int status = 0;
                    struct rusage ru;
                    while (1) {
                        int res = wait4(-1, &status, WNOHANG, &ru);
                        if (res < 0) {
                            if (errno == ECHILD) {
                                if (!prc_finished) {
                                    kill_all();
                                    ffatal("child lost");
                                }
                                break;
                            } else {
                                kill_all();
                                ffatal("wait4 failed %s", strerror(errno));
                            }
                        } else if (res == pid2) {
                            prc_finished = 1;
                            prc_status = status;
                            prc_usage = ru;
                            {
                                struct timeval tv;
                                gettimeofday(&tv, NULL);
                                prc_stop_time_us = tv.tv_sec * 1000000LL + tv.tv_usec;
                            }
                            flag = 0;
                        } else if (!res) {
                            break;
                        }
                    }
                } else if (curev->data.fd == tfd) {
                    uint64_t val;
                    if (read(tfd, &val, sizeof(val)) != sizeof(val)) {
                        kill_all();
                        ffatal("invalid timer read");
                    }

                    // 0.1s elapsed
                    if (!prc_finished) {
                        if (parse_proc_pid_stat(pid2, &prc_info) < 0) {
                            kill_all();
                            ffatal("parsing of /proc/pid/stat failed");
                        }

                        if (prc_info.vsize > 0) {
                            if (prc_vm_size < 0 || prc_info.vsize > prc_vm_size) {
                                prc_vm_size = prc_info.vsize;
                            }
                        }

                        long long cur_cpu_time = (long long) prc_info.utime + (long long) prc_info.stime;
                        cur_cpu_time = (cur_cpu_time * 1000) / clock_ticks;
                        if (limit_cpu_time_ms > 0 && cur_cpu_time >= limit_cpu_time_ms) {
                            prc_time_exceeded = 1;
                            kill(pid2, SIGKILL);
                        } else {
                            long long cur_time_us = 0;
                            {
                                struct timeval tv;
                                gettimeofday(&tv, NULL);
                                cur_time_us = tv.tv_sec * 1000000LL + tv.tv_usec;
                            }

                            if (limit_real_time_ms > 0 && (cur_time_us - prc_start_time_us) >= limit_real_time_ms * 1000LL) {
                                // REAL-TIME limit exceeded
                                prc_real_time_exceeded = 1;
                                kill(pid2, SIGKILL);
                            }
                        }
                    }
                } else if (control_socket_fd >= 0 && curev->data.fd == control_socket_fd) {
                    uint32_t val;
                    int r = read(control_socket_fd, &val, sizeof(val));
                    if (r < 0) {
                        kill_all();
                        ffatal("control socket read error: %s", strerror(errno));
                    } else if (!r) {
                        epoll_ctl(efd, EPOLL_CTL_DEL, control_socket_fd, NULL);
                        close(control_socket_fd); control_socket_fd = -1;
                    } else if (r != sizeof(val)) {
                        kill_all();
                        ffatal("invalid control socket read: %d", r);
                    } else {
                        if ((val & 0xf0000000) == 0xe0000000) {
                            uint32_t cmd = (val & 0x0fffff00) >> 8;
                            if (cmd == 1) {
                                // send signal
                                kill(pid2, val & 0xff);
                            }
                        }
                    }
                }
            }
        }

        if (!WIFEXITED(prc_status) && !WIFSIGNALED(prc_status)) {
            kill_all();
            ffatal("wait4 process is neither exited nor signaled");
        }

        int orphaned_processes = 0;
        if (enable_prc_count) {
            orphaned_processes = count_processes();
        }

        kill_all();

        int ipc_objects = 0;
        if (enable_ipc_count) {
            ipc_objects += scan_posix_mqueue(slave_uid);
            ipc_objects += scan_msg(slave_uid);
            ipc_objects += scan_sem(slave_uid);
            ipc_objects += scan_shm(slave_uid);
        }

        long long cpu_utime_us = prc_usage.ru_utime.tv_sec * 1000000LL + prc_usage.ru_utime.tv_usec;
        long long cpu_stime_us = prc_usage.ru_stime.tv_sec * 1000000LL + prc_usage.ru_stime.tv_usec;
        long long cpu_time_us = cpu_utime_us + cpu_stime_us;
        long long real_time_us = prc_stop_time_us - prc_start_time_us;

        // recheck TLs after termination
        if (limit_cpu_time_ms > 0 && cpu_time_us >= limit_cpu_time_ms * 1000LL) {
            prc_time_exceeded = 1;
            cpu_time_us = limit_cpu_time_ms * 1000LL;
            cpu_utime_us = cpu_time_us;
            cpu_stime_us = 0;
        }
        if (limit_real_time_ms > 0 && real_time_us >= limit_real_time_ms * 1000LL) {
            prc_real_time_exceeded = 1;
            real_time_us = limit_real_time_ms * 1000LL;
        }

        if (prc_time_exceeded) {
            dprintf(response_fd, "t");
        } else if (prc_real_time_exceeded) {
            dprintf(response_fd, "r");
        } else if (WIFEXITED(prc_status)) {
            dprintf(response_fd, "e%d", WEXITSTATUS(prc_status));
        } else if (WIFSIGNALED(prc_status)) {
            dprintf(response_fd, "s%d", WTERMSIG(prc_status));
        } else {
            abort();
        }

        struct CGroupStat cgstat = {};
        if (enable_cgroup) {
            read_cgroup_stats(&cgstat);
        }

        dprintf(response_fd, "T%lldR%lldu%lldk%lld", cpu_time_us, real_time_us, cpu_utime_us, cpu_stime_us);
        if (prc_vm_size > 0) dprintf(response_fd, "v%lld", prc_vm_size);
        if (prc_usage.ru_maxrss > 0) dprintf(response_fd, "e%lld", (long long) prc_usage.ru_maxrss * 1024LL);
        dprintf(response_fd, "a%lldb%lld", (long long) prc_usage.ru_nvcsw, (long long) prc_usage.ru_nivcsw);
        if (ipc_objects > 0) dprintf(response_fd, "i%d", ipc_objects);
        if (orphaned_processes > 0) dprintf(response_fd, "o%d", orphaned_processes);
        if (enable_cgroup) {
            if (cgstat.usage_us > 0) {
                dprintf(response_fd, "ct%lld", cgstat.usage_us);
            }
            if (cgstat.user_us > 0) {
                dprintf(response_fd, "cu%lld", cgstat.user_us);
            }
            if (cgstat.system_us > 0) {
                dprintf(response_fd, "cs%lld", cgstat.system_us);
            }
        }

        if (log_f) {
            fclose(log_f); log_f = NULL;
        }
        if (log_s && *log_s) {
            int len = strlen(log_s);
            dprintf(response_fd, "L%d,%s", len, log_s);
        }

        _exit(0);
    }

    if (stdin_fd >= 0) close(stdin_fd);
    if (stdout_fd >= 0) close(stdout_fd);
    if (stderr_fd >= 0) close(stderr_fd);
    stdin_fd = -1; stdout_fd = -1; stderr_fd = -1;
    if (control_socket_fd >= 0) close(control_socket_fd);
    control_socket_fd = -1;

    siginfo_t infop = {};
    waitid(P_PID, pid, &infop, WEXITED);
    if (bash_mode) {
        printf("bash finished\n");
        printf("parent: %d, %d\n", pid, tidptr);
    }

    change_ownership(primary_uid, primary_gid, slave_uid);
    if (cgroup_unified_path[0]) rmdir(cgroup_unified_path);
    if (cgroup_cpu_path[0]) rmdir(cgroup_cpu_path);
    if (cgroup_memory_path[0]) rmdir(cgroup_memory_path);

    if (infop.si_code == CLD_EXITED) {
        if (infop.si_status == 0 || infop.si_status == 1) _exit(infop.si_status);
        ffatal("unexpected exit code from container leader: %d", infop.si_status);
    } else if (infop.si_code == CLD_KILLED || infop.si_code == CLD_DUMPED) {
        ffatal("container leader terminated by signal %d", infop.si_status);
    } else {
        ffatal("unexpected si_code from waitid");
    }
}
