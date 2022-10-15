/* -*- mode: c -*- */

/* Copyright (C) 2014-2022 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>

enum
{
    MODE_SVN = 1,
    MODE_GIT = 2
};

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

struct file_info
{
    const unsigned char *summ;
    const unsigned char *path;
};
static struct file_info *file_infos;
static int file_info_a = 0, file_info_u = 0;

static void
add_file_info(const unsigned char *summ, const unsigned char *path)
{
    if (file_info_u >= file_info_a) {
        if (!(file_info_a *= 2)) file_info_a = 128;
        file_infos = realloc(file_infos, file_info_a * sizeof(file_infos[0]));
    }
    struct file_info *cur = &file_infos[file_info_u++];
    cur->summ = strdup(summ);
    cur->path = strdup(path);
}

static int
read_file_info(const unsigned char *name)
{
    FILE *f = fopen(name, "r");
    if (!f) return -1;

    unsigned char buf[1024];
    while (fgets(buf, sizeof(buf), f)) {
        int buflen = strlen(buf);
        if (buflen == sizeof(buf) - 1 && buf[buflen - 1] != '\n') {
            fprintf(stderr, "input line is too long\n");
            exit(1);
        }
        while (buflen > 0 && isspace(buf[buflen - 1])) --buflen;
        buf[buflen] = 0;
        if (buflen <= 0) continue;

        unsigned char summ[sizeof(buf)];
        int n = 0;
        if (sscanf(buf, "%s%n", summ, &n) != 1) {
            fprintf(stderr, "invalid input file\n");
            exit(1);
        }
        while (isspace(buf[n])) ++n;
        add_file_info(summ, buf + n);
    }
    fclose(f); f = NULL;
    return 0;
}

struct svn_info
{
    int is_changed;
    int rev1, rev2;
    unsigned char *user;
    unsigned char *path;
};
static struct svn_info *svn_infos;
static int svn_info_a = 0, svn_info_u = 0;

static void
add_svn_info(int is_changed, int rev1, int rev2, const unsigned char *user, const unsigned char *path)
{
    if (svn_info_u >= svn_info_a) {
        if (!(svn_info_a *= 2)) svn_info_a = 128;
        svn_infos = realloc(svn_infos, svn_info_a * sizeof(svn_infos[0]));
    }
    struct svn_info *cur = &svn_infos[svn_info_u++];
    cur->is_changed = is_changed;
    cur->rev1 = rev1;
    cur->rev2 = rev2;
    cur->user = strdup(user);
    cur->path = strdup(path);
}

enum { FILE_MISSING = -1, FILE_NORMAL = 0, FILE_DIR = 1, FILE_OTHER = 2 };

static int
get_file_type(const unsigned char *path)
{
    struct stat stbuf;

    if (stat(path, &stbuf) < 0) return FILE_MISSING;
    if (S_ISREG(stbuf.st_mode)) return FILE_NORMAL;
    if (S_ISDIR(stbuf.st_mode)) return FILE_DIR;
    return FILE_OTHER;
}

static int
read_git_commit_id_by_version(unsigned char *id_buf, int id_buf_size, const unsigned char *version)
{
    unsigned char cmd_buf[1024];
    snprintf(cmd_buf, sizeof(cmd_buf), "git show --format=%%h \"v%s\"", version);
    FILE *f = popen(cmd_buf, "r");
    if (!f) {
        fprintf(stderr, "cannot invoke git\n");
        exit(1);
    }

    unsigned char buf[1024];
    if (!fgets(buf, sizeof(buf), f)) {
        fprintf(stderr, "unexpected EOF in call to git show\n");
        exit(1);
    }
    int len = strlen(buf);
    while (len > 0 && isspace(buf[len - 1])) --len;
    buf[len] = 0;
    if (len <= 0) {
        fprintf(stderr, "empty commit_id for version '%s'\n", version);
        exit(1);
    }
    snprintf(id_buf, id_buf_size, "%s", buf);
    while (fgets(buf, sizeof(buf), f)) {}
    pclose(f); f = NULL;
    return 0;
}

static int
read_git_status(unsigned char *id_buf, int id_buf_size, int *p_has_changes)
{
    FILE *f = popen("git rev-parse --short HEAD", "r");
    if (!f) {
        fprintf(stderr, "cannot invoke git\n");
        exit(1);
    }

    unsigned char buf[1024];
    if (!fgets(buf, sizeof(buf), f)) {
        fprintf(stderr, "unexpected EOF in call to rev-parse\n");
        exit(1);
    }
    int len = strlen(buf);
    while (len > 0 && isspace(buf[len - 1])) --len;
    buf[len] = 0;
    snprintf(id_buf, id_buf_size, "%s", buf);
    while (fgets(buf, sizeof(buf), f)) {}
    pclose(f); f = NULL;

    int has_changes = 0;
    f = popen("git status --porcelain", "r");
    while (fgets(buf, sizeof(buf), f)) {
        int len = strlen(buf);
        while (len > 0 && isspace(buf[len - 1])) --len;
        buf[len] = 0;
        if (strstr(buf, "db/")) continue;
        if (strstr(buf, "libdwarf/")) continue;
        if (strstr(buf, "NEWS")) continue;
        if (len > 0) has_changes = 1;
    }
    pclose(f); f = NULL;
    if (p_has_changes) *p_has_changes = has_changes;
    return 0;
}

static int
read_svn_status(unsigned char *id_buf, int id_buf_size, int *p_has_changes)
{
    FILE *f = popen("svn status -v", "r");
    if (!f) {
        fprintf(stderr, "cannot invoke svn\n");
        exit(1);
    }

    unsigned char buf[1024];
    int max_rev = 0;
    int has_changes = 0;
    while (fgets(buf, sizeof(buf), f)) {
        int len = strlen(buf);
        if (len == sizeof(buf) - 1 && buf[len - 1] != '\n') {
            fprintf(stderr, "SVN status line is too long\n");
            exit(1);
        }
        while (len > 0 && isspace(buf[len - 1])) --len;
        buf[len] = 0;

        if (buf[0] == '?') continue;

        buf[2] = ' ';
        buf[3] = ' ';

        unsigned char c1 = 0, c2 = 0;
        int rev1 = 0, rev2 = 0, n = 0, is_changed = 0;
        unsigned char user[sizeof(buf)];
        unsigned char *path = 0;

        user[0] = 0;
        if (buf[0] == 'A') {
            unsigned char tmp1[64], tmp2[64], tmp3[64];
            if (sscanf(buf, "%c%c%s%s%s%n", &c1, &c2, tmp1, tmp2, tmp3, &n) != 5) {
                fprintf(stderr, "SVN status line parse error: <%s>\n", buf);
                exit(1);
            }
        } else {
            if (sscanf(buf, "%c%c%d%d%s%n", &c1, &c2, &rev1, &rev2, user, &n) != 5) {
                fprintf(stderr, "SVN status line parse error: <%s>\n", buf);
                exit(1);
            }
        }
        if (rev1 >= max_rev) max_rev = rev1;
        if (rev2 >= max_rev) max_rev = rev2;

        while (isspace(buf[n])) ++n;
        path = buf + n;

        // ignore "db/" stuff
        if (!strncmp(path, "db/", 3)) continue;
        if (!strncmp(path, "NEWS", 4)) continue;

        if (c1 != ' ' || c2 != ' ') {
            is_changed = 1;
            has_changes = 1;
        }
        int file_type = get_file_type(path);
        if (file_type == FILE_DIR) continue;
        if (file_type == FILE_OTHER) {
            fprintf(stderr, "file '%s' is neither file nor directory\n", path);
            exit(1);
        }
        if (file_type == FILE_MISSING) {
            is_changed = 1;
            has_changes = 1;
        }
        add_svn_info(is_changed, rev1, rev2, user, path);
    }
    pclose(f); f = NULL;

    if (p_has_changes) *p_has_changes = has_changes;
    if (id_buf && id_buf_size > 0) {
        snprintf(id_buf, id_buf_size, "%d", max_rev);
    }

    return 0;
}

static int
checksum_file(const unsigned char *name, unsigned char *buf, int size)
{
    FILE *f = fopen(name, "r");
    if (!f) return -1;
    long long sum = 0;
    int c;
    while ((c = getc(f)) != EOF) {
        sum += c;
    }
    fclose(f); f = NULL;
#ifdef _WIN32
	sprintf(buf, "%016I64x", sum);
#else
    snprintf(buf, size, "%016llx", sum);
#endif
    return 0;
}

static int
has_checksum_changed(void)
{
    int changed = 0;
    for (int i = 0; i < file_info_u; ++i) {
        struct file_info *cur = &file_infos[i];
        unsigned char checksum_buf[1024];
        if (checksum_file(cur->path, checksum_buf, sizeof(checksum_buf)) < 0) {
            changed = 1;
            printf("File '%s' no longer exists\n", cur->path);
        } else if (strcmp(checksum_buf, cur->summ) != 0) {
            changed = 1;
            printf("File '%s' is changed\n", cur->path);
        }
    }
    return changed;
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

static void
new_minor_version(const unsigned char *versions_file, const unsigned char *checksum_prefix, const unsigned char *version)
{
    struct verdb *latest = &verdb[verdb_u - 1];

    unsigned char id_str[1024];
    int changed_flag = 0;
    id_str[0] = 0;
    int mode = 0;

    if (get_file_type(".git") == FILE_DIR) {
        snprintf(id_str, sizeof(id_str), "tagged");
        mode = MODE_GIT;
    } else if (get_file_type(".svn") == FILE_DIR) {
        if (read_svn_status(id_str, sizeof(id_str), &changed_flag) < 0) {
            fprintf(stderr, "Failed to parse SVN status\n");
            exit(1);
        }
        int id_val = 0;
        if (sscanf(id_str, "%d", &id_val) != 1) {
            fprintf(stderr, "Invalid revision id\n");
            exit(1);
        }
        snprintf(id_str, sizeof(id_str), "%d", id_val + 1);
        mode = MODE_SVN;
    } else {
        fprintf(stderr, "SVN/GIT is not connected\n");
        exit(1);
    }
    if (changed_flag) {
        fprintf(stderr, "There are uncommited changes\n");
        exit(1);
    }

    int patch = 0;
    if (!version) {
        version = latest->version;
        patch = latest->patch + 1;
    }

    unsigned char full_version[1024];
    snprintf(full_version, sizeof(full_version), "%s.%d", version, patch);
    unsigned char out_file[1024];
    snprintf(out_file, sizeof(out_file), "%s%s", checksum_prefix, full_version);

    FILE *cf = fopen(out_file, "w");
    if (!cf) {
        fprintf(stderr, "Cannot open '%s' for writing\n", out_file);
        exit(1);
    }
    for (int i = 0; i < svn_info_u; ++i) {
        unsigned char checksum_buf[1024];
        if (checksum_file(svn_infos[i].path, checksum_buf, sizeof(checksum_buf)) < 0) {
            fprintf(stderr, "Failed to checksum file '%s'\n", svn_infos[i].path);
            exit(1);
        }
        fprintf(cf, "%s %s\n", checksum_buf, svn_infos[i].path);
    }
    fclose(cf); cf = NULL;

    time_t cur_time = time(0);
    struct tm *ptm = localtime(&cur_time);

    FILE *f = fopen(versions_file, "a");
    if (!f) {
        fprintf(stderr, "Cannot open '%s' for appending\n", versions_file);
        exit(1);
    }
    fprintf(f, "%s %s %d %04d/%02d/%02d\n", id_str, version, patch,
            ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday);
    fclose(f); f = NULL;

    if (mode == MODE_GIT) {
        unsigned char cmd_buf[1024];
        snprintf(cmd_buf, sizeof(cmd_buf), "git add \"%s\" \"%s\"", out_file, versions_file);
        if (system(cmd_buf) != 0) {
            fprintf(stderr, "Command '%s' failed\n", cmd_buf);
            exit(1);
        }
        snprintf(cmd_buf, sizeof(cmd_buf), "git commit -m \"version %s\"", full_version);
        if (system(cmd_buf) != 0) {
            fprintf(stderr, "Command '%s' failed\n", cmd_buf);
            exit(1);
        }
        snprintf(cmd_buf, sizeof(cmd_buf), "git tag \"v%s\"", full_version);
        if (system(cmd_buf) != 0) {
            fprintf(stderr, "Command '%s' failed\n", cmd_buf);
            exit(1);
        }
    }
}

int
main(int argc, char **argv)
{
    const unsigned char *build_file = ".build";
    const unsigned char *version_file = "version.c";
    const unsigned char *versions_file = "db/versions";
    const unsigned char *checksum_prefix = "db/info-";
    unsigned char full_version[1024];
    unsigned char version_string[2048];
    int build = 0;
    struct verdb *latest = NULL;

    version_string[0] = 0;
    read_verdb(versions_file);
    if (verdb_u <= 0) {
        fprintf(stderr, "no latest version info\n");
        exit(1);
    }
    latest = &verdb[verdb_u - 1];
    snprintf(full_version, sizeof(full_version), "%s.%d", latest->version, latest->patch);

    if (argc == 2 && !strcmp(argv[1], "new-minor")) {
        new_minor_version(versions_file, checksum_prefix, NULL);
        exit(0);
    }
    if (argc == 3 && !strcmp(argv[1], "new-major")) {
        new_minor_version(versions_file, checksum_prefix, argv[2]);
        exit(0);
    }

    int changed_flag = 0;
    unsigned char rev_id[1024];
    rev_id[0] = 0;
    if (get_file_type(".git") == FILE_DIR) {
        if (!strcmp(latest->id, "tagged")) {
            unsigned char full_version[1024];
            snprintf(full_version, sizeof(full_version), "%s.%d", latest->version, latest->patch);
            //fprintf(stderr, "Full version: %s\n", full_version);
            unsigned char version_rev_id[1024];
            read_git_commit_id_by_version(version_rev_id, sizeof(version_rev_id), full_version);
            //fprintf(stderr, "Commit ID: %s\n", version_rev_id);
            latest->id = strdup(version_rev_id);
        }

        read_git_status(rev_id, sizeof(rev_id), &changed_flag);
        if (changed_flag < 0) exit(1);
        if (!changed_flag && !strcmp(latest->id, rev_id)) {
            // the version exactly
            snprintf(version_string, sizeof(version_string), "%s", full_version);
            write_build(build_file, 0);
        } else if (!changed_flag) {
            // some SVN rev exactly
            snprintf(version_string, sizeof(version_string), "%s+ (GIT %s)", full_version, rev_id);
            write_build(build_file, 0);
        } else if (!strcmp(latest->id, rev_id)) {
            // some changed version
            read_build(build_file, &build);
            build++;
            write_build(build_file, build);
            sprintf(version_string, "%s #%d", full_version, build);
        } else {
            // some SVN changed revision
            read_build(build_file, &build);
            build++;
            write_build(build_file, build);
            snprintf(version_string, sizeof(version_string), "%s+ (GIT %s) #%d", full_version, rev_id, build);
        }
    } else if (get_file_type(".svn") == FILE_DIR) {
        read_svn_status(rev_id, sizeof(rev_id), &changed_flag);
        if (changed_flag < 0) exit(1);
        //printf("changed flag: %d, id: %s\n", changed_flag, rev_id);
        if (!changed_flag && !strcmp(latest->id, rev_id)) {
            // the version exactly
            snprintf(version_string, sizeof(version_string), "%s", full_version);
            write_build(build_file, 0);
        } else if (!changed_flag) {
            // some SVN rev exactly
            snprintf(version_string, sizeof(version_string), "%s+ (SVN r%s)", full_version, rev_id);
            write_build(build_file, 0);
        } else if (!strcmp(latest->id, rev_id)) {
            // some changed version
            read_build(build_file, &build);
            build++;
            write_build(build_file, build);
            sprintf(version_string, "%s #%d", full_version, build);
        } else {
            // some SVN changed revision
            read_build(build_file, &build);
            build++;
            write_build(build_file, build);
            snprintf(version_string, sizeof(version_string), "%s+ (SVN r%s) #%d", full_version, rev_id, build);
        }
    } else {
        unsigned char checksum_file[1024];
        snprintf(checksum_file, sizeof(checksum_file), "%s%s", checksum_prefix, full_version);
        if (read_file_info(checksum_file) < 0 || file_info_u <= 0) {
            // no data to compare
            read_build(build_file, &build);
            build++;
            write_build(build_file, build);
            sprintf(version_string, "%s #%d", full_version, build);
        } else if (has_checksum_changed()) {
            read_build(build_file, &build);
            build++;
            write_build(build_file, build);
            sprintf(version_string, "%s #%d", full_version, build);
        } else {
            snprintf(version_string, sizeof(version_string), "%s", full_version);
            write_build(build_file, 0);
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
