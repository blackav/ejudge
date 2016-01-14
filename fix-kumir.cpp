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

    for (int run_id = 0; run_id < total_runs; ++run_id) {
        struct run_entry re = {};
        if (run_get_entry(runlog, run_id, &re) < 0) {
            die("cannot get run entry %d", run_id);
        }
        if (re.status != RUN_COMPILE_ERR) continue;
        if (re.lang_id != 24) continue;

        string arch_path = make_path(contest_id, "runs", run_id);
        int arch_flag = 0;
        ssize_t arch_size = file_size(arch_path);
        if (arch_size < 0) {
            arch_path += ".gz";
            arch_size = file_size(arch_path);
            if (arch_size < 0) {
                die("cannot find source code for run %d", run_id);
            }
            arch_flag = GZIP;
        }

        char *text = nullptr;
        size_t size = 0;
        if (generic_read_file(&text, 0, &size, arch_flag, nullptr, arch_path.c_str(), nullptr) < 0) {
            die("cannot read source code for run %d", run_id);
        }
        if (text == nullptr) {
            die("text == null");
        }

        if (strlen(text) != size) {
            die("binary file for run %d", run_id);
        }

        int *wtext = new int[size + 1];
        int *wtext2 = new int[size + 1];
        int wlen = utf8_to_ucs4_str(wtext, (const unsigned char*) text);
        wtext[size] = 0;
        wtext2[wlen] = 0;
        int nl_count_1 = 0;
        int nl_count_2 = 0;
        for (int i = 0; i < wlen; ++i) {
            if (wtext[i] <= 0 || wtext[i] >= 0x10000) {
                die("invalid character in run %d (%x)", run_id, wtext[i]);
            }
            if (wtext[i] == '\n') ++nl_count_1;
            wtext2[i] = ((wtext[i] >> 8) & 0xff) | ((wtext[i] & 0xff) << 8);
            if (wtext2[i] == '\n') ++nl_count_2;
        }
        printf("%d", run_id);
        if (nl_count_1 > 0 && nl_count_2 > 0) {
            printf(" STRANGE");
        } else if (nl_count_1 > 0) {
            printf(" OK");
        } else if (nl_count_2 > 0) {
            printf(" BROKEN");
            size_t outlen = ucs4_to_utf8_size(wtext2);
            if ((int) outlen < 0) die("invalid size");
            char *outstr = new char[outlen + 1];
            ucs4_to_utf8_str((unsigned char*) outstr, outlen + 1, wtext2);
            if (strlen(outstr) + 1 != outlen) die("invalid length");
            string saved_path = arch_path + ".saved";
            unsigned int shabuf[5] = {};
            sha_buffer(outstr, outlen - 1, shabuf);
            string sha1((char*) unparse_sha1(shabuf));
            printf(" %s", sha1.c_str());

            rename(arch_path.c_str(), saved_path.c_str());
            if (generic_write_file(outstr, outlen - 1, arch_flag,
                                   nullptr, arch_path.c_str(), nullptr) < 0)
                die("write error");
            memcpy(re.sha1, shabuf, sizeof(re.sha1));
            run_set_entry(runlog, run_id, RE_SHA1, &re);

        } else {
            printf(" UNKNOWN");
        }
        printf("\n");
    }

    return 0;
}

// g++ -Wall -g -std=gnu++11 -rdynamic -L. fix-kumir.cpp -ofix-kumir -lcommon -luserlist_clnt -lplatform -lcommon -lexpat -lz -lzip -luuid -ldl

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
