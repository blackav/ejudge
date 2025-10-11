/* -*- mode: c++; c-basic-offset: 4 -*- */

#include <string>
#include <optional>
#include <map>
#include <vector>
#include <string_view>
#include <cstdint>

#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdarg.h>
#include <dirent.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <sys/mman.h>

struct metrics_contest_data
{
    uint32_t size; // this struct size
    unsigned char pad0[12];
    struct timeval start_time;
    struct timeval update_time;
    long long client_serial;
    int loaded_contests;
    int runs_submitted;
    long long total_compile_time_ms;
    long long total_testing_time_ms;
    long long get_cookie_tsc;
    long long get_cookie_count;
    long long hit_cookie_tsc;
    long long hit_cookie_count;
    long long get_key_tsc;
    long long get_key_count;
    long long hit_key_tsc;
    long long hit_key_count;
    long long cookie_cache_size;
    long long key_cache_size;
    long long append_run_us;
    long long append_run_count;
    int submits_submitted;
    long long append_submit_us;
    long long append_submit_count;
};

namespace
{
    const char compile_spool_dir[] = "/home/ej-compile-spool/";
    const char run_spool_dir[] = "/home/ej-run-spool/";
    const std::vector<std::string_view> compile_queues{ };
    const std::vector<std::string_view> run_queues{ };
    const char ej_contests_metrics_path[] = "/home/judges/var/status/ej-contests-status";
    long long current_time_ms;
    long clock_ticks;
}

void pts(const char *format, ...)
{
    va_list args;
    char buf[1024];

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    printf("%s %lld\n", buf, current_time_ms);
}

int count_files_in_dir(const char *path)
{
    DIR *d = opendir(path);
    if (!d) return -1;

    int count = 0;
    struct dirent *dd;
    while ((dd = readdir(d))) {
        if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, ".."))
            continue;
        ++count;
    }

    closedir(d);
    return count;
}

std::optional<std::string> read_file(const char *path)
{
    std::string res;

    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK, 0);
    if (fd < 0) return {};
    struct stat stb;
    if (fstat(fd, &stb) < 0) {
        close(fd);
        return {};
    }
    if (!S_ISREG(stb.st_mode)) {
        close(fd);
        return {};
    }

    while (1) {
        char buf[16384];
        int r = read(fd, buf, sizeof(buf));
        if (r < 0) {
            close(fd);
            return {};
        }
        if (!r) break;
        res.append(buf, size_t(r));
    }

    return std::move(res);
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
  char *p = NULL;
  int r = 0;

  memset(info, 0, sizeof(*info));
  if (snprintf(path, sizeof(path), "/proc/%d/stat", pid) >= (int) sizeof(path)) abort();
  f = fopen(path, "r");
  if (!f) {
      goto fail;
  }
  if (!fgets(buf, sizeof(buf), f)) goto fail;
  blen = strlen(buf);
  if (blen + 1 == sizeof(buf)) goto fail;
  fclose(f); f = NULL;

  p = strrchr(buf, ')');
  if (!p) goto fail;
  ++p;

  r = sscanf(p, " %c%d%d%d%d%d%u%lu%lu%lu%lu%lu%lu%lu%lu%ld%ld%ld%ld%llu%lu%ld%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%lu%d%d",
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

struct process_status
{
    long long vm_size_kb;
    long long vm_rss_kb;
};

static int
parse_proc_pid_status(int pid, struct process_status *ps)
{
    char path[PATH_MAX];
    FILE *f = NULL;
    char buf[1024];

    if (snprintf(path, sizeof(path), "/proc/%d/status", pid) >= (int) sizeof(path)) {
        return -1;
    }
    f = fopen(path, "r");
    if (!f) {
        return -1;
    }
    while (fgets(buf, sizeof(buf), f)) {
        int len = strlen(buf);
        if (len >= (int) sizeof(buf) - 1) continue;
        while (len > 0 && isspace((unsigned char) buf[len - 1])) --len;
        buf[len] = 0;
        if (!strncmp(buf, "VmSize:", 7)) {
            ps->vm_size_kb = strtol(buf + 7, NULL, 10);
        } else if (!strncmp(buf, "VmRSS:", 6)) {
            ps->vm_rss_kb = strtol(buf + 6, NULL, 10);
        }
    }
    fclose(f);
    return 0;
}

void scan_proc(void)
{
    DIR *d = opendir("/proc");
    struct dirent *dd;
    std::map<std::string, int> counters {
        { "ej-compile", 0 },
        { "ej-contests", 0 },
        { "ej-jobs", 0 },
        { "ej-super-run", 0 },
        { "ej-super-server", 0 },
        { "ej-users", 0 },
        { "ej-agent", 0 },
    };
    static std::map<std::string, std::string> metrics_names {
        { "ej-compile", "ej_compile" },
        { "ej-contests", "ej_contests" },
        { "ej-jobs", "ej_jobs" },
        { "ej-super-run", "ej_super_run" },
        { "ej-super-server", "ej_super_server" },
        { "ej-users", "ej_users" },
        { "ej-agent", "ej_agent" },
    };
    std::map<std::string, double> cpu_times;
    std::map<std::string, long long> vm_sizes;
    std::map<std::string, long long> vm_rss;

    while ((dd = readdir(d))) {
        char *eptr = NULL;
        errno = 0;
        long v = strtol(dd->d_name, &eptr, 10);
        if (errno || *eptr || eptr == dd->d_name || v <= 0 || (int) v != v)
            continue;
        int pid = v;

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        auto cnt = read_file(path);
        if (!cnt) continue;

        auto ind = cnt->find('\0');
        auto cmd = (ind == std::string::npos)?*cnt:cnt->substr(0, ind);
        if (cmd.empty()) continue;
        ind = cmd.rfind('/');
        if (ind != std::string::npos) cmd.erase(0, ind + 1);

        auto it = counters.find(cmd);
        if (it != counters.end()) {
            ++it->second;
            struct process_info info = {};
            if (parse_proc_pid_stat(pid, &info) >= 0) {
                long long cur_cpu_time = (long long) info.utime + (long long) info.stime;
                cpu_times[cmd] += (double) cur_cpu_time / clock_ticks;;
            }
            struct process_status ps = {};
            if (parse_proc_pid_status(pid, &ps) >= 0) {
                vm_sizes[cmd] += ps.vm_size_kb;
                vm_rss[cmd] += ps.vm_rss_kb;
            }
        }
    }

    for (const auto &p : counters) {
        pts("%s_total %d", metrics_names[p.first].c_str(), p.second);
    }
    for (const auto &p : cpu_times) {
        pts("%s_cpu_seconds %f", metrics_names[p.first].c_str(), p.second);
    }
    for (const auto &p : vm_sizes) {
        pts("%s_vm_size_kib %lld", metrics_names[p.first].c_str(), p.second);
    }
    for (const auto &p : vm_rss) {
        pts("%s_vm_rss_kib %lld", metrics_names[p.first].c_str(), p.second);
    }

    closedir(d);
}

void ej_contests_metrics(void)
{
    int fd = open(ej_contests_metrics_path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return;

    struct stat stb;
    if (fstat(fd, &stb) < 0) {
        close(fd);
        return;
    }
    if (!S_ISREG(stb.st_mode)) {
        close(fd);
        return;
    }
    if (stb.st_size < int(sizeof(struct metrics_contest_data))) {
        close(fd);
        return;
    }
    size_t size = stb.st_size;
    if ((off_t) size != stb.st_size) {
        close(fd);
        return;
    }

    const struct metrics_contest_data *mcd = (const struct metrics_contest_data *) mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    if (mcd == MAP_FAILED) {
        close(fd);
        return;
    }
    close(fd); fd = -1;
    if (mcd->size < sizeof(struct metrics_contest_data)) {
        munmap((void *) mcd, size);
        return;
    }
    /*
    struct timeval ct;
    gettimeofday(&ct, NULL);
    if (ct.tv_sec - mcd->update_time.tv_sec > 10) {
        munmap((void *) mcd, size);
        return;
    }
    */

    long long start_time = mcd->start_time.tv_sec * 1000LL + mcd->start_time.tv_usec / 1000;
    long long update_time = mcd->update_time.tv_sec * 1000LL + mcd->update_time.tv_usec / 1000;
    double uptime = (update_time - start_time) / 1000.0;
    pts("ej_contests_uptime_seconds %.3f", uptime);
    pts("ej_contests_loaded_contests_total %d", mcd->loaded_contests);
    pts("ej_contests_requests_total %lld", mcd->client_serial / 2);
    pts("submitted_runs_total %d", mcd->runs_submitted);
    pts("submitted_submits_total %d", mcd->submits_submitted);
    pts("compilation_total_seconds %.3f", mcd->total_compile_time_ms / 1000.0);
    pts("testing_total_seconds %.3f", mcd->total_testing_time_ms / 1000.0);

    pts("ej_contests_get_cookie_tsc %lld", mcd->get_cookie_tsc);
    pts("ej_contests_get_cookie_count %lld", mcd->get_cookie_count);
    pts("ej_contests_hit_cookie_tsc %lld", mcd->hit_cookie_tsc);
    pts("ej_contests_hit_cookie_count %lld", mcd->hit_cookie_count);
    pts("ej_contests_get_key_tsc %lld", mcd->get_key_tsc);
    pts("ej_contests_get_key_count %lld", mcd->get_key_count);
    pts("ej_contests_hit_key_tsc %lld", mcd->hit_key_tsc);
    pts("ej_contests_hit_key_count %lld", mcd->hit_key_count);
    pts("ej_contests_cookie_cache_size %lld", mcd->cookie_cache_size);
    pts("ej_contests_key_cache_size %lld", mcd->key_cache_size);
    pts("ej_contests_append_run_seconds %.6f", mcd->append_run_us / 1000000.0);
    pts("ej_contests_append_run_total %lld", mcd->append_run_count);
}

int main(void)
{
    struct timeval ct;
    gettimeofday(&ct, NULL);
    clock_ticks = sysconf(_SC_CLK_TCK);

    current_time_ms = ct.tv_sec * 1000LL + ct.tv_usec / 1000;

    printf("Content-Type: text/plain; version=0.0.4\n\n");

    scan_proc();
    int count = 0;
    for (auto sv : compile_queues) {
        std::string p(compile_spool_dir);
        p += sv;
        p += "/queue/dir";
        count += count_files_in_dir(p.c_str());
    }
    if (count >= 0) {
        pts("compile_queue_total %d", count);
    }
    count = 0;
    for (auto sv : run_queues) {
        std::string p(run_spool_dir);
        p += sv;
        p += "/queue/dir";
        count += count_files_in_dir(p.c_str());
    }
    if (count >= 0) {
        pts("run_queue_total %d", count);
    }

    ej_contests_metrics();
}
