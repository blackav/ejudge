/* $Id$ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>

struct verdb
{
  unsigned char *id;
  unsigned char *version;
  int     patch;
  time_t  time;
};
static struct verdb *verdb;
static int verdb_u, verdb_a;

static void
add_verdb(
        const unsigned char *id,
        char const *version,
        int patch,
        time_t rtime)
{
    if (verdb_u >= verdb_a) {
        if (!verdb_a) verdb_a = 8;
        verdb_a *= 2;
        verdb = realloc(verdb, verdb_a * sizeof(verdb[0])); // NULL is ignored
    }
    verdb[verdb_u].id = strdup(id);
    verdb[verdb_u].version = strdup(version);
    verdb[verdb_u].patch  = patch;
    verdb[verdb_u].time = rtime;
    verdb_u++;
}

static void
read_verdb(unsigned char const *name)
{
    FILE          *f;
    unsigned char  buf[1024];
    unsigned char  version[sizeof(buf)];
    unsigned char  id[sizeof(buf)];
    int            patch, n, buflen, year, month, mday;
    struct tm      ttm;
    time_t         tt;

    if (!(f = fopen(name, "r"))) {
        fprintf(stderr, "cannot open database file '%s'\n", name);
        exit(1);
    }

    while (fgets(buf, sizeof(buf), f)) {
        buflen = strlen(buf);
        if (buflen == sizeof(buf) - 1 && buf[buflen - 1] != '\n') {
            fprintf(stderr, "%s: line too long\n", name);
            exit(1);
        }
        if (buf[0] == '#') continue;
        if (buf[0] == '\n') continue;
        while (buflen > 0 && isspace(buf[buflen - 1])) buf[--buflen] = 0;

        tt = 0;
        if (sscanf(buf, "%s %s %d %d/%d/%d%n", id, version, &patch, &year, &month, &mday, &n) == 6 && !buf[n]) {
            if (patch < 0 || year < 1970 || year > 2040
                || month < 1 || month > 12 || mday < 1 || mday > 31) {
                fprintf(stderr, "%s: line invalid\n", name);
                exit(1);
            }
            memset(&ttm, 0, sizeof(ttm));
            ttm.tm_isdst = -1;
            ttm.tm_year = year - 1900;
            ttm.tm_mon = month - 1;
            ttm.tm_mday = mday;
            if ((tt = mktime(&ttm)) == (time_t) -1) {
                fprintf(stderr, "%s: time specification is invalid\n", name);
                exit(1);
            }
        } else if (sscanf(buf, "%s %s %d%n", id, version, &patch, &n) != 3
                   || buf[n] || patch < 0) {
            fprintf(stderr, "%s: line invalid\n", name);
            exit(1);
        }
        add_verdb(id, version, patch, tt);
    }
    if (ferror(f)) {
        fprintf(stderr, "%s: read error\n", name);
        exit(1);
    }

    fclose(f);
}

static int
does_directory_exist(const unsigned char *path)
{
    struct stat stbuf;

    if (stat(path, &stbuf) < 0) return 0;
    if (S_ISDIR(stbuf.st_mode)) return 1;
    return 0;
}

static void
read_build(char const *name, int *pbuild)
{
    FILE *f;

    if (pbuild) *pbuild = 0;
    if (!(f = fopen(name, "r"))) return;
    if (fscanf(f, "%d", pbuild) != 1) {
        fprintf(stderr, "%s: cannot read build number\n", name);
        exit(1);
    }
    fscanf(f, " ");
    if (getc(f) != EOF) {
        fprintf(stderr, "%s: garbage after build number\n", name);
        exit(1);
    }
    fclose(f);
}

static void
write_build(char const *name, int build)
{
    FILE *f;

    remove(name);

    if (!(f = fopen(name, "w"))) {
        fprintf(stderr, "%s: cannot open file for writing\n", name);
        exit(1);
    }
    fprintf(f, "%d\n", build);
    fclose(f);
}

static int
has_svn_changed_files(unsigned char *id_buf, int id_buf_size)
{
    FILE *f = popen("svn status -v", "r");
    if (!f) {
        fprintf(stderr, "cannot invoke svn\n");
        return -1;
    }

    int has_changed = 0;
    unsigned char buf[1024];
    int id_val = 0, max_id = 0;
    while (fgets(buf, sizeof(buf), f)) {
        int buflen = strlen(buf);
        if (buflen == sizeof(buf) - 1 && buf[buflen - 1] != '\n') {
            fprintf(stderr, "svn status line is too long\n");
            pclose(f);
            return -1;
        }
        while (buflen > 0 && isspace(buf[buflen - 1])) --buflen;
        buf[buflen] = 0;

        if (buflen > 3) {
            sscanf(buf + 2, "%d", &id_val);
            if (id_val > max_id) max_id = id_val;
        }
        if (strstr(buf, "db/revisions")) {
            continue;
        }
        if (buflen <= 0) continue;
        if (buf[0] == ' ' || buf[0] == '?') continue;
        has_changed = 1;
    }
    pclose(f); f = NULL;
    snprintf(id_buf, id_buf_size, "%d", max_id);
    return has_changed;
}

static void
write_output(
        unsigned char const *name,
        const unsigned char *variable_prefix,
        const unsigned char *version_string)
{
  FILE   *f;
  time_t  t;
  struct tm *ptm = 0;

  t = time(0);
  ptm = localtime(&t);

  remove(name);
  if (!(f = fopen(name, "w"))) {
    fprintf(stderr, "%s: cannot open for writing\n", name);
    exit(1);
  }
  if (!variable_prefix) variable_prefix = "compile";
  fprintf(f,
          "/* THIS IS AUTOGENERATED FILE */\n"
          "char const %s_version[] = \"%s\";\n"
          "char const %s_date[] = \"%04d-%02d-%02d %02d:%02d:%02d\";\n",
          variable_prefix, version_string, variable_prefix,
          ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
  fclose(f);
}

int
main(int argc, char **argv)
{
    const unsigned char *build_file = ".build";
    const unsigned char *version_file = "version.c";
    unsigned char version_string[1024];
    int build = 0;

    version_string[0] = 0;
    read_verdb("db/versions");
    if (verdb_u <= 0) {
        fprintf(stderr, "no latest version info\n");
        exit(1);
    }
    printf("Latest version: %s %s %d\n", verdb[verdb_u - 1].id, verdb[verdb_u - 1].version, verdb[verdb_u - 1].patch);

    int changed_flag = 0;
    unsigned char rev_id[1024];
    rev_id[0] = 0;
    if (does_directory_exist(".svn")) {
        changed_flag = has_svn_changed_files(rev_id, sizeof(rev_id));
        if (changed_flag < 0) exit(1);
        printf("changed flag: %d, id: %s\n", changed_flag, rev_id);
        if (!changed_flag && !strcmp(verdb[verdb_u - 1].id, rev_id)) {
            // the version exactly
            snprintf(version_string, sizeof(version_string), "%s.%d",
                     verdb[verdb_u - 1].version, verdb[verdb_u - 1].patch);
            write_build(build_file, 0);
        } else if (!changed_flag) {
            // some SVN rev exactly
            snprintf(version_string, sizeof(version_string), "%s.%d+ (SVN r%s)",
                     verdb[verdb_u - 1].version, verdb[verdb_u - 1].patch,
                     rev_id);
            write_build(build_file, 0);
        } else if (!strcmp(verdb[verdb_u - 1].id, rev_id)) {
            // some changed version
            read_build(build_file, &build);
            build++;
            write_build(build_file, build);
            sprintf(version_string, "%s.%d #%d", verdb[verdb_u - 1].version, verdb[verdb_u - 1].patch, build);
        } else {
            // some SVN changed revision
            read_build(build_file, &build);
            build++;
            write_build(build_file, build);
            snprintf(version_string, sizeof(version_string), "%s.%d+ (SVN r%s) #%d",
                     verdb[verdb_u - 1].version, verdb[verdb_u - 1].patch,
                     rev_id, build);
        }
    }

    if (version_string[0]) {
        write_output(version_file, 0, version_string);
    }

    return 0;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
