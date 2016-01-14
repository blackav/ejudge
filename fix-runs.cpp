extern "C" {
#include "ejudge/config.h"
#include "ejudge/ej_types.h"
#include "ejudge/ej_limits.h"
#include "ejudge/version.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/contests.h"
#include "ejudge/runlog.h"
#include "ejudge/xml_utils.h"
#include "ejudge/misctext.h"
#include "ejudge/fileutl.h"
#include "ejudge/sha.h"
#include "ejudge/compat.h"

#include "ejudge/xalloc.h"
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>

#include <string>
#include <set>
#include <map>
#include <vector>

using namespace std;

#define USTR(c) ((unsigned char*) c)
#define CSTR(c) ((char*) c)

static char *program_name = nullptr;
static struct ejudge_cfg *config = nullptr;
static int contest_id = 0;
static const struct contest_desc *cnts = nullptr;
static runlog_state_t runlog = nullptr;

static void
die(const char *format, ...)
    __attribute__((format(printf, 1, 2), noreturn));
static void
die(const char *format, ...)
{
    va_list args;
    char buf[1024];

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    fprintf(stderr, "%s: %s\n", program_name, buf);
    exit(1);
}

static void *forced_syms[] __attribute__((unused)) =
{
    (void*) xfree,
    (void*) close_memstream,
    (void*) xml_err_elem_undefined_s,

    nullptr,
};

static const unsigned char b32_digits[]=
"0123456789ABCDEFGHIJKLMNOPQRSTUV";
static void
b32_number(unsigned int num, size_t size, unsigned char buf[])
{
  int i;

  memset(buf, '0', size - 1);
  buf[size - 1] = 0;
  i = size - 2;
  while (num > 0 && i >= 0) {
    buf[i] = b32_digits[num & 0x1f];
    i--;
    num >>= 5;
  }
}

static size_t
make_hier_path(unsigned char *buf, size_t size,
               const unsigned char *base_dir, int serial)
{
    size_t blen = strlen(CSTR(base_dir));
    unsigned char *tb, *pp, b32[16];
  int i;

  if (blen + 32 < size) {
    tb = buf;
  } else {
      tb = (unsigned char*) alloca(blen + 32);
  }
  strcpy(CSTR(tb), CSTR(base_dir));
  pp = tb + blen;
  b32_number(serial, EJ_MAX_32DIGITS + 1, b32);
  for (i = 0; i < EJ_MAX_32DIGITS - 1; i++) {
    *pp++ = '/';
    *pp++ = b32[i];
  }
  *pp = 0;
  if (tb == buf) return pp - tb;
  return snprintf(CSTR(buf), size, "%s", CSTR(tb));
}

string
make_path(int contest_id, const char *dir, int run_id)
{
    char buf1[PATH_MAX];
    snprintf(buf1, sizeof(buf1), "/home/judges/%06d/var/archive/%s",
             contest_id, dir);
    char buf2[PATH_MAX];
    make_hier_path((unsigned char*) buf2, sizeof(buf2),
                   (const unsigned char*) buf1, run_id);
    char buf3[PATH_MAX];
    snprintf(buf3, sizeof(buf3), "%s/%06d", buf2, run_id);
    return string(buf3);
}

string
make_backup_path(int contest_id, const char *dir, int run_id, int gz_flag)
{
    const char *suffix = "";
    if (gz_flag > 0) suffix = ".gz";
    char buf1[PATH_MAX];
    snprintf(buf1, sizeof(buf1), "/home/judges/backup/%06d/var/archive/%s",
             contest_id, dir);
    char buf2[PATH_MAX];
    make_hier_path((unsigned char*) buf2, sizeof(buf2),
                   (const unsigned char*) buf1, run_id);
    char buf3[PATH_MAX];
    snprintf(buf3, sizeof(buf3), "%s/%06d%s", buf2, run_id, suffix);
    return string(buf3);
}

ssize_t
file_size(const string &str)
{
    return generic_file_size(nullptr,
                             (const unsigned char*) str.c_str(),
                             nullptr);
}

string
file_sha1(const string &path, int flags)
{
    char *text = nullptr;
    size_t size = 0;
    if (generic_read_file(&text, 0, &size, flags,
                          nullptr, path.c_str(), nullptr) < 0) {
        throw "cannot read file";
    }

    unsigned int shabuf[5] = {};
    sha_buffer(text, size, shabuf);
    return string((char*) unparse_sha1(shabuf));
}

int
main(int argc, char *argv[])
{
    program_name = argv[0];

    if (argc != 2) die("wrong number of arguments");

    config = ejudge_cfg_parse(EJUDGE_XML_PATH);
    if (!config) die("invalid configuration file");
    contests_set_directory(config->contests_dir);

    try {
        contest_id = std::stoi(argv[1]);
    } catch (...) {
        die("invalid contest_id");
    }
    if (contests_get(contest_id, &cnts) < 0 || !cnts) die("invalid contest_id");

    runlog = run_init(0);
    if (!runlog) die("failed to initialize runlog");

    if (run_open(runlog, config, cnts, 0, USTR("mysql"), 0, 0, 0, 0) < 0)
        die("cannot open the runlog");

    int total_runs = run_get_total(runlog);

    map<string, set<int> > shamap;
    vector<string> dbshas(total_runs);

    for (int run_id = 0; run_id < total_runs; ++run_id) {
        struct run_entry re = {};
        if (run_get_entry(runlog, run_id, &re) < 0) {
            die("cannot get run entry %d", run_id);
        }
        if (re.status == RUN_EMPTY || re.status == RUN_VIRTUAL_START || re.status == RUN_VIRTUAL_STOP) continue;
        if (re.sha1[0] == 0 && re.sha1[1] == 0 && re.sha1[2] == 0 && re.sha1[3] == 0 && re.sha1[4] == 0) {
            die("sha1 is NULL for %d", run_id);
        }

        string sha1s((char*) unparse_sha1(re.sha1));
        set<int> &s = shamap[sha1s];
        s.insert(run_id);
        dbshas[run_id] = sha1s;
    }

    printf("=== runs by DB ===\n");
    for (auto p : shamap) {
        printf("%s", p.first.c_str());
        for (auto i : p.second) {
            printf(" %d", i);
        }
        printf("\n");
    }

    // collect sha1 of source code
    map<string, set<int> > flmap;
    vector<string> flshas(total_runs);
    vector<int> files_gz_flag(total_runs);

    for (int run_id = 0; run_id < total_runs; ++run_id) {
        files_gz_flag[run_id] = -1;
        string sp = make_path(contest_id, "runs", run_id);
        ssize_t sz = file_size(sp);
        if (sz >= 0) {
            string ss = file_sha1(sp, 0);
            set<int> &s = flmap[ss];
            s.insert(run_id);
            flshas[run_id] = ss;
            files_gz_flag[run_id] = 0;
        } else {
            sp += ".gz";
            sz = file_size(sp);
            if (sz >= 0) {
                string ss = file_sha1(sp, GZIP);
                set<int> &s = flmap[ss];
                s.insert(run_id);
                flshas[run_id] = ss;
                files_gz_flag[run_id] = 1;
            }
        }
    }

    printf("=== runs by files ===\n");
    for (auto p : flmap) {
        printf("%s", p.first.c_str());
        for (auto i : p.second) {
            printf(" %d", i);
        }
        printf("\n");
    }

    printf("=== runs map ===\n");
    int missing_count = 0;

    vector<int> restore_run_id(total_runs);
    for (int run_id = 0; run_id < total_runs; ++run_id) {
        restore_run_id[run_id] = -1;
        struct run_entry re = {};
        if (run_get_entry(runlog, run_id, &re) < 0) {
            die("cannot get run entry %d", run_id);
        }
        if (re.status == RUN_EMPTY || re.status == RUN_VIRTUAL_START
            || re.status == RUN_VIRTUAL_STOP) continue;
        if (dbshas[run_id] == flshas[run_id]) continue;
        auto it = flmap.find(dbshas[run_id]);
        if (it == flmap.end()) {
            printf("%06d MISSING\n", run_id);
            ++missing_count;
        } else {
            auto &rs = it->second;
            printf("%06d", run_id);
            for (auto r  : rs) {
                printf(" %d", r);
                if (restore_run_id[run_id] < 0) restore_run_id[run_id] = r;
            }
            printf("\n");
        }
    }

    printf("Total: %d, missing: %d\n", total_runs, missing_count);

    printf("=== check against backup files\n");
    int mismatch_count = 0;
    for (int run_id = 0; run_id < total_runs; ++run_id) {
        int rrun_id = restore_run_id[run_id];
        if (rrun_id < 0) continue;
        string backup_path = make_backup_path(contest_id, "runs", rrun_id, files_gz_flag[rrun_id]);
        if (file_sha1(backup_path, (files_gz_flag[rrun_id] > 0)?GZIP:0) != dbshas[run_id]) {
            printf("%d: sha mismatch\n", run_id);
            ++mismatch_count;
        }
    }
    printf("Total mismatches: %d\n", mismatch_count);
    if (mismatch_count > 0) return 1;

    printf("=== copying runs ===\n");
    for (int run_id = 0; run_id < total_runs; ++run_id) {
        int rrun_id = restore_run_id[run_id];
        if (rrun_id < 0) continue;
        string base = make_path(contest_id, "runs", run_id);
        unlink(base.c_str());
        unlink((base + ".gz").c_str());
        unlink((base + ".zip").c_str());
        string target = base;
        if (files_gz_flag[rrun_id] > 0) target += ".gz";
        string source = make_backup_path(contest_id, "runs", rrun_id, files_gz_flag[rrun_id]);

        if (generic_copy_file(0, nullptr, source.c_str(), nullptr,
                              0, nullptr, target.c_str(), nullptr) < 0) {
            return 1;
        }
        printf("%d -> %d\n", rrun_id, run_id);
    }

    printf("=== done ===\n");

    return 0;
}

// g++ -Wall -g -std=gnu++11 -rdynamic -L. fix-runs.cpp -ofix-runs -lcommon -luserlist_clnt -lplatform -lcommon -lexpat -lz -lzip -luuid -ldl

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
