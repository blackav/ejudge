/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2020-2026 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/expat_iface.h"
#include "ejudge/version.h"

#include "ejudge/contests.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/fileutl.h"
#include "ejudge/xalloc.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/userlist_proto.h"
#include "ejudge/userlist.h"
#include "ejudge/xml_utils.h"
#include "ejudge/osdeps.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>

struct State
{
    struct ejudge_cfg *config;
    struct userlist_clnt *client;
    unsigned char ejudge_xml_path[PATH_MAX];
};

static const char *progname;

static void
write_help(void)
{
    printf("%s: ejudge batch contest settings editing utility\n"
           "Usage: %s [OPTIONS] [CONTEST-IDS]...\n"
           "  OPTIONS:\n"
           "    --add-full-cap USER\n"
           "              set FULL capabilities for the USER\n"
           "    --add-judge-cap USER\n"
           "              set JUDGE capabilities for the USER\n"
           "    --add-master-cap USER\n"
           "              set MASTER capabilities for the USER\n"
           "    --all-participant\n"
           "              enable access to 'client' (aka 'team') CGI from all IPs\n"
           "    --all-register\n"
           "              enable access to 'register' CGI from all IPs\n"
           "    --all-users\n"
           "              enable access to 'users' CGI from all IPs\n"
           "    --close   set 'closed' flag for contests\n"
           "    --db\n"
           "              also perform user database registration/unregistration\n"
           "    --ejudge-contests-dir DIR\n"
           "              specify custom contests directory\n"
           "    --ejudge-xml-path FILE\n"
           "              specify custom path to ejudge.xml configuration file\n"
           "    --global\n"
           "              perform the operations on the global level additionally\n"
           "    --help    write message and exit\n"
           "    --invisible\n"
           "              set 'invisible' flag for contests\n"
           "    --lock\n"
           "              lock the user in the contest instead of unregistering it for --remove-cap\n"
           "    --login\n"
           "              specify user login if no capability change operation is requested\n"
           "    --name NAME\n"
           "              update user name in the contests or the global user name\n"
           "    --no-audit\n"
           "              do not add audit comment to contest.xml file\n"
           "    --no-participant\n"
           "              disable access to 'client' (aka 'team') CGI from all IPs\n"
           "    --no-register\n"
           "              disable access to 'register' CGI from all IPs\n"
           "    --no-users\n"
           "              disable access to 'users' CGI from all IPs\n"
           "    --oauth   update oauth user aliases in capabilities.xml\n"
           "    --open    clear 'closed' flag for contests\n"
           "    --remove-cap USER\n"
           "              remove capabilities for the USER\n"
           "    --version report version and exit\n"
           "    --visible clear 'invisible' flag for contests\n"
           "  CONTEST-IDS:\n"
           "    NUM       handle this contest\n"
           "    NUM1-NUM2 handle all contests in the range\n",
           progname, progname);
    exit(0);
}

static int
find_cap_user(const struct contest_desc *cnts, const char *cap_user_name)
{
    const struct opcap_list_item *cap;
    int index = 0;
    for (cap = CNTS_FIRST_PERM(cnts); cap; cap = CNTS_NEXT_PERM(cap)) {
        if (!strcmp(cap->login, cap_user_name)) {
            return index;
        }
        ++index;
    }
    return -1;
}

static int
find_cap_user_2(const struct contest_desc *cnts, const char *cap_user_name, int id)
{
    const struct opcap_list_item *cap;
    int index = 0;
    for (cap = CNTS_FIRST_PERM(cnts); cap; cap = CNTS_NEXT_PERM(cap)) {
        if (!strcmp(cap->login, cap_user_name)) {
            if (cap->caps == opcaps_get_predef_caps(id)) return index;
            return -1;
        }
        ++index;
    }
    return -1;
}

static int
parse_contest_xml(
        int contest_id,
        unsigned char **before_start,
        unsigned char **after_end)
{
    unsigned char path[PATH_MAX];
    char *raw_xml = 0, *s, *p;
    unsigned char *xml_1 = 0, *xml_2 = 0;
    size_t raw_xml_size = 0;
    struct stat statbuf;
    int errcode;

    contests_make_path(path, sizeof(path), contest_id);
    if (stat(path, &statbuf) < 0) {
        return -1;
    }

    if (generic_read_file(&raw_xml, 0, &raw_xml_size, 0, 0, path, 0) < 0) {
        return -1;
    }

    xml_1 = (unsigned char*) xmalloc(raw_xml_size + 10);
    xml_2 = (unsigned char*) xmalloc(raw_xml_size + 10);

    // find opening <contest tag
    s = raw_xml;
    while (*s) {
        if (s[0] != '<') {
            s++;
            continue;
        }
        if (s[1] == '!' && s[2] == '-' && s[3] == '-') {
            while (*s) {
                if (s[0] == '-' && s[1] == '-' && s[2] == '>') break;
                s++;
            }
            if (!*s) break;
            continue;
        }
        p = s;
        p++;
        while (*p && isspace((unsigned char) *p)) p++;
        if (!*p) {
            errcode = -1;
            goto failure;
        }
        if (!strncmp(p, "contest", 7) && p[7] && isspace((unsigned char) p[7])) break;
        s++;
    }
    if (!*s) {
        errcode = -1;
        goto failure;
    }

    memcpy(xml_1, raw_xml, s - raw_xml);
    xml_1[s - raw_xml] = 0;

    // find closing > tag
    while (*s && *s != '>') s++;
    if (!*s) {
        errcode = -1;
        goto failure;
    }
    s++;

    xml_2[0] = 0;
    char *endptr = strstr(s, "</contest>");
    if (endptr) {
        strcpy(xml_2, endptr + 10);
    }

    *before_start = xml_1;
    *after_end = xml_2;
    xfree(raw_xml);
    return 0;

failure:
    xfree(xml_1);
    xfree(xml_2);
    xfree(raw_xml);
    return errcode;
}

#define DIE(format, ...) do { fprintf(stderr, "%s: " format "\n", progname, ##__VA_ARGS__); exit(1); } while(0)

static void
load_ejudge_config(struct State *state)
{
    if (state->config) {
        return;
    }
    if (!state->ejudge_xml_path[0]) {
#if defined EJUDGE_XML_PATH
        if (snprintf(state->ejudge_xml_path, sizeof(state->ejudge_xml_path), "%s", EJUDGE_XML_PATH) >= sizeof(state->ejudge_xml_path)) {
            DIE("path is too long: '%s'", EJUDGE_XML_PATH);
        }
#endif
    }
    if (!state->ejudge_xml_path[0]) {
        DIE("path to ejudge.xml is not specified");
    }
    state->config = ejudge_cfg_parse(state->ejudge_xml_path, 1);
    if (!state->config) {
        DIE("failed to parse config file '%s'", state->ejudge_xml_path);
    }
}

static void
open_userlist(struct State *state)
{
    if (state->client) {
        return;
    }
    load_ejudge_config(state);
    if (!(state->client = userlist_clnt_open(state->config->socket_path))) {
        DIE("cannot open server connection: %s", os_ErrorMsg());
    }
    int r = userlist_clnt_admin_process(state->client, 0, 0, 0);
    if (r < 0) {
        DIE("cannot become admin process: %s", userlist_strerror(-r));
    }
}

static int
unregister_user(struct State *state, int user_id, int contest_id, int lock_flag)
{
#define FAIL(format, ...) do { fprintf(stderr, "%s:%s:error:user_id=%d,contest_id=%d:" format "\n", progname, __PRETTY_FUNCTION__, user_id, contest_id, ##__VA_ARGS__); goto done; } while(0)
    int retval = -1;
    unsigned char *info_txt = NULL;
    struct userlist_user *u = NULL;
    __attribute__((unused)) const struct userlist_user_info *ui = NULL;
    const struct userlist_contest *uc = NULL;

    int r = userlist_clnt_get_info(state->client, ULS_PRIV_GET_USER_INFO,
                             user_id, contest_id, &info_txt);
    if (r < 0) {
        FAIL("get_info failed: %s", userlist_strerror(-r));
    }
    if (!(u = userlist_parse_user_str(info_txt))) {
        FAIL("userlist parse error");
    }
    ui = u->cnts0;
    uc = userlist_get_user_contest(u, contest_id);
    if (!uc) {
        retval = 0;
        goto done;
    }
    if (uc->status != USERLIST_REG_OK || lock_flag <= 0) {
        r = userlist_clnt_change_registration(state->client, user_id, contest_id, -2, 0, 0);
        if (r < 0) {
            FAIL("failed to delete registration: %s", userlist_strerror(-r));
        }
        retval = 0;
        goto done;

    }
    if ((uc->flags & USERLIST_UC_LOCKED)) {
        retval = 0;
        goto done;
    }
    r = userlist_clnt_change_registration(state->client, user_id,
                                          contest_id, -1, 1,
                                          USERLIST_UC_LOCKED);
    if (r < 0) {
        FAIL("failed to lock user: %s", userlist_strerror(-r));
    }

    retval = 0;

done:;
    if (u) userlist_free(&u->b);
    free(info_txt);
    return retval;
#undef FAIL
}

static int
register_privileged_user(struct State *state, int user_id, int contest_id, const unsigned char *name)
{
#define FAIL(format, ...) do { fprintf(stderr, "%s:%s:error:user_id=%d,contest_id=%d:" format "\n", progname, __PRETTY_FUNCTION__, user_id, contest_id, ##__VA_ARGS__); goto done; } while(0)
    int retval = -1;
    unsigned char *info_txt = NULL;
    struct userlist_user *u = NULL;
    const struct userlist_user_info *ui = NULL;
    const struct userlist_contest *uc = NULL;

    int r = userlist_clnt_get_info(state->client, ULS_PRIV_GET_USER_INFO,
                             user_id, contest_id, &info_txt);
    if (r < 0) {
        FAIL("get_info failed: %s", userlist_strerror(-r));
    }
    if (!(u = userlist_parse_user_str(info_txt))) {
        FAIL("userlist parse error");
    }

    ui = u->cnts0;
    if (name && name[0]) {
        if (!ui || !ui->name || strcmp(ui->name, name) != 0) {
            r = userlist_clnt_edit_field(state->client, ULS_EDIT_FIELD,
                                         user_id, contest_id, 0,
                                         USERLIST_NC_NAME, name);
            if (r < 0) {
                FAIL("failed to updated user name: %s", userlist_strerror(-r));
            }
        }
    }

    uc = userlist_get_user_contest(u, contest_id);
    if (!uc) {
        r = userlist_clnt_register_contest(state->client,
                                        ULS_PRIV_REGISTER_CONTEST,
                                            user_id, contest_id, 0, 0);
        if (r < 0) {
            FAIL("failed to register user: %s", userlist_strerror(-r));
        }
        r = userlist_clnt_change_registration(state->client, user_id,
                                          contest_id, USERLIST_REG_OK, 1,
                                          USERLIST_UC_INVISIBLE|USERLIST_UC_PRIVILEGED);
        if (r < 0) {
            FAIL("failed to update registration: %s", userlist_strerror(-r));
        }

        retval = 0;
        goto done;
    }
    if (uc->status != USERLIST_REG_OK) {
        r = userlist_clnt_change_registration(state->client, user_id,
                                          contest_id, USERLIST_REG_OK, 1,
                                          USERLIST_UC_INVISIBLE|USERLIST_UC_PRIVILEGED);
        if (r < 0) {
            FAIL("failed to update registration: %s", userlist_strerror(-r));
        }

        retval = 0;
        goto done;
    }
    if ((uc->flags & (USERLIST_UC_INVISIBLE|USERLIST_UC_PRIVILEGED)) != (USERLIST_UC_INVISIBLE|USERLIST_UC_PRIVILEGED)) {
        r = userlist_clnt_change_registration(state->client, user_id,
                                          contest_id, -1, 1,
                                          USERLIST_UC_INVISIBLE|USERLIST_UC_PRIVILEGED);
        if (r < 0) {
            FAIL("failed to update registration: %s", userlist_strerror(-r));
        }
    }
    retval = 0;

done:;
    if (u) userlist_free(&u->b);
    free(info_txt);
    return retval;
#undef FAIL
}

enum { PRESERVE_LAST_N_BACKUPS = 10 };
enum { MAX_COMPARABLE_FILE_SIZE = 1000000 };

struct FileInfo
{
    unsigned char *name;
    long long mtime_us;
};

static int
fileinfo_sort_func(const void *p1, const void *p2)
{
    const struct FileInfo *f1 = (const struct FileInfo *) p1;
    const struct FileInfo *f2 = (const struct FileInfo *) p2;
    return (f1->mtime_us > f2->mtime_us) - (f1->mtime_us < f2->mtime_us);
}

static int
remove_old_backups(const unsigned char *path)
{
#define FAIL(format, ...) do { fprintf(stderr, "%s:%s:%d:error:" format "\n", progname, __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__); goto done; } while(0)
    int retval = -1;
    unsigned char dir[PATH_MAX];
    unsigned char prefix[PATH_MAX];
    unsigned char fullpath[PATH_MAX];
    __attribute__((unused)) int _;
    DIR *d = NULL;
    size_t prefixlen;
    struct FileInfo *files = NULL;
    size_t file_u = 0, file_a = 0;

    if (snprintf(dir, sizeof(dir), "%s.bak.", path) >= (int) sizeof(dir)) {
        FAIL("path is too long");
    }
    unsigned char *p = strrchr(dir, '/');
    if (!p) {
        FAIL("expect non-empty directory part");
    }
    _ = snprintf(prefix, sizeof(prefix), "%s", p + 1);
    prefixlen = strlen(prefix);
    *p = 0;
    if (!(d = opendir(dir))) {
        FAIL("cannot open directory '%s': %s", dir, strerror(errno));
    }
    struct dirent *dd;
    while ((dd = readdir(d))) {
        if (strncmp(prefix, dd->d_name, prefixlen) != 0) {
            continue;
        }
        if (snprintf(fullpath, sizeof(fullpath), "%s/%s", dir, dd->d_name) >= (int) sizeof(fullpath)) {
            continue;
        }
        struct stat stb;
        if (lstat(fullpath, &stb) < 0) {
            continue;
        }
        if (!S_ISREG(stb.st_mode)) {
            continue;
        }
        if (file_u == file_a) {
            if (!file_a) file_a = 16;
            else file_a *= 2;
            XREALLOC(files, file_a);
        }
        files[file_u].name = xstrdup(dd->d_name);
        files[file_u].mtime_us = stb.st_mtim.tv_sec * 1000000LL + stb.st_mtim.tv_nsec / 1000;
        ++file_u;
    }
    closedir(d); d = NULL;
    if (file_u >= PRESERVE_LAST_N_BACKUPS) {
        qsort(files, file_u, sizeof(files[0]), fileinfo_sort_func);
        for (size_t i = PRESERVE_LAST_N_BACKUPS - 1; i < file_u; ++i) {
            if (snprintf(fullpath, sizeof(fullpath), "%s/%s", dir, files[i].name) >= (int) sizeof(fullpath)) {
                continue;
            }
            unlink(fullpath);
        }
    }
    retval = 0;

done:;
    if (d) closedir(d);
    for (size_t i = 0; i < file_u; ++i) {
        free(files[i].name);
    }
    free(files);
    return retval;
#undef FAIL
}

static int
are_files_equal(const unsigned char *path1, const unsigned char *path2)
{
#define FAIL(format, ...) do { fprintf(stderr, "%s:%s:%d:error:" format "\n", progname, __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__); goto done; } while(0)
    int retval = -1;
    int fd1 = -1;
    int fd2 = -1;
    unsigned char *mem1 = MAP_FAILED;
    unsigned char *mem2 = MAP_FAILED;
    size_t mem_size = 0;

    fd1 = open(path1, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW | O_NOCTTY, 0);
    if (fd1 < 0) {
        FAIL("cannot open '%s': %s", path1, strerror(errno));
    }
    struct stat st1;
    if (fstat(fd1, &st1) < 0) abort();
    if (!S_ISREG(st1.st_mode)) {
        FAIL("file '%s' is not regular", path1);
    }
    fd2 = open(path2, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW | O_NOCTTY, 0);
    if (fd2 < 0) {
        FAIL("cannot open '%s': %s", path2, strerror(errno));
    }
    struct stat st2;
    if (fstat(fd2, &st2) < 0) abort();
    if (!S_ISREG(st2.st_mode)) {
        FAIL("file '%s' is not regular", path2);
    }
    if (st1.st_size <= 0 && st2.st_size <= 0) {
        retval = 1;
        goto done;
    }
    if (st1.st_size != st2.st_size) {
        retval = 0;
        goto done;
    }
    if (st1.st_size > MAX_COMPARABLE_FILE_SIZE) {
        FAIL("files are too big (bigger than %d)", MAX_COMPARABLE_FILE_SIZE);
    }

    mem_size = st1.st_size;
    mem1 = mmap(NULL, mem_size, PROT_READ, MAP_PRIVATE, fd1, 0);
    if (mem1 == MAP_FAILED) {
        FAIL("mmap failed for '%s': %s", path1, strerror(errno));
    }
    close(fd1); fd1 = -1;
    mem2 = mmap(NULL, mem_size, PROT_READ, MAP_PRIVATE, fd2, 0);
    if (mem2 == MAP_FAILED) {
        FAIL("mmap failed for '%s': %s", path2, strerror(errno));
    }
    close(fd2); fd2 = -1;
    retval = memcmp(mem1, mem2, mem_size) == 0;

done:;
    if (fd1 >= 0) close(fd1);
    if (fd2 >= 0) close(fd2);
    if (mem1 != MAP_FAILED) munmap(mem1, mem_size);
    if (mem2 != MAP_FAILED) munmap(mem2, mem_size);
    return retval;
#undef FAIL
}

static int
replace_with_new_version(const unsigned char *path, const unsigned char *newpath)
{
#define FAIL(format, ...) do { fprintf(stderr, "%s:%s:%d:error:" format "\n", progname, __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__); goto done; } while(0)
    int retval = -1;
    __attribute__((unused)) int _;
    unsigned char backup_path[PATH_MAX];

    backup_path[0] = 0;
    struct stat dst;
    if (lstat(path, &dst) < 0) {
        FAIL("destination file '%s' lstat failed: %s", path, strerror(errno));
    }
    if (!S_ISREG(dst.st_mode)) {
        FAIL("destination file '%s' is not regular", path);
    }
    struct stat nst;
    if (lstat(newpath, &nst) < 0) {
        FAIL("new file '%s' lstat failed: %s", newpath, strerror(errno));
    }
    if (!S_ISREG(nst.st_mode)) {
        FAIL("new file '%s' is not regular", newpath);
    }
    if ((dst.st_mode & 07777) != (nst.st_mode & 07777)) {
        if (chmod(newpath, dst.st_mode & 07777) < 0) {
            FAIL("failed to change permissions for '%s': %s", newpath, strerror(errno));
        }
    }
    if (dst.st_gid != nst.st_gid) {
        _ = chown(newpath, nst.st_uid, dst.st_gid);
    }

    struct tm tt;
    localtime_r(&dst.st_mtim.tv_sec, &tt);
    if (snprintf(backup_path, sizeof(backup_path), "%s.bak.%04d%02d%02d%02d%02d%02d.%03d",
                    path,
                    tt.tm_year + 1900,
                    tt.tm_mon + 1,
                    tt.tm_mday,
                    tt.tm_hour,
                    tt.tm_min,
                    tt.tm_sec,
                    (int)(dst.st_mtim.tv_nsec / 1000000)) >= (int) sizeof(backup_path)) {
        backup_path[0] = 0;
        FAIL("backup path is too long");
    }
    _ = unlink(backup_path);
    if (link(path, backup_path) < 0) {
        FAIL("failed to link '%s' to backup path '%s': %s", path, backup_path, strerror(errno));
    }
    if (rename(newpath, path) < 0) {
        FAIL("failed to rename '%s' to '%s': %s", newpath, path, strerror(errno));
    }

    backup_path[0] = 0;
    retval = 0;

done:;
    if (backup_path[0]) _ = unlink(backup_path);
    return retval;
#undef FAIL
}

static int
save_caps_file(const struct ejudge_cfg *config)
{
#define FAIL(format, ...) do { fprintf(stderr, "%s:%s:%d:error:" format "\n", progname, __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__); goto done; } while(0)
    int retval = -1;
    unsigned char newpath[PATH_MAX];
    unsigned long long rnd64 = 0;
    int fd = -1;
    FILE *f = NULL;
    __attribute__((unused)) int _;

    newpath[0] = 0;

    if (!config->caps_file) return 0;
    if (!config->caps_file_info) return 0;
    if (!config->caps_file_info->root) return 0;
    if (!config->caps_file_info->path) return 0;

    ssize_t rr = getrandom(&rnd64, sizeof(rnd64), 0);
    if (rr < 0) {
        FAIL("getrandom failed: %s", strerror(errno));
    }
    if (rr != (ssize_t) sizeof(rnd64)) {
        FAIL("getrandom short read");
    }
    if (snprintf(newpath, sizeof(newpath), "%s.new.%016llx", config->caps_file_info->path, rnd64) >= (int) sizeof(newpath)) {
        newpath[0] = 0;
        FAIL("path is too long");
    }
    fd = open(newpath, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd < 0) {
        FAIL("cannot open file '%s: %s", newpath, strerror(errno));
    }
    f = fdopen(fd, "w");
    if (!f) {
        FAIL("cannot fdopen file: %s", strerror(errno));
    }
    fd = -1;
    printf("opened %s\n", newpath);
    ejudge_cfg_unparse_capabilities_xml(f, config);
    fclose(f); f = NULL;

    int r = are_files_equal(config->caps_file_info->path, newpath);
    if (r < 0) {
        FAIL("cannot compare files '%s' and '%s'", config->caps_file_info->path, newpath);
    }
    if (r > 0) {
        printf("file %s is unchanged\n", config->caps_file_info->path);
        retval = 0;
        goto done;
    }
    _ = remove_old_backups(config->caps_file_info->path);
    if (replace_with_new_version(config->caps_file_info->path, newpath) < 0) {
        FAIL("replace with new version failed");
    }
    newpath[0] = 0;
    retval = 0;

done:;
    if (f) fclose(f);
    if (fd >= 0) close(fd);
    if (newpath[0]) _ = unlink(newpath);
    return retval;
#undef FAIL
}

enum
{
    GLOBAL_JUDGE_CAPS = 
        (1ULL << OPCAP_JUDGE_LOGIN),
    GLOBAL_MASTER_CAPS =
        GLOBAL_JUDGE_CAPS
        | (1ULL << OPCAP_MASTER_LOGIN)
        | (1ULL << OPCAP_LIST_USERS)
        | (1ULL << OPCAP_GET_USER),
    GLOBAL_FULL_CAPS =
        GLOBAL_MASTER_CAPS
        | (1ULL << OPCAP_CREATE_REG)
        | (1ULL << OPCAP_EDIT_REG)
        | (1ULL << OPCAP_DELETE_REG)
        | (1ULL << OPCAP_PRIV_CREATE_REG)
        | (1ULL << OPCAP_PRIV_EDIT_REG)
        | (1ULL << OPCAP_PRIV_DELETE_REG)
        | (1ULL << OPCAP_CREATE_USER)
        | (1ULL << OPCAP_EDIT_USER)
        | (1ULL << OPCAP_DELETE_USER)
        | (1ULL << OPCAP_DUMP_USERS)
        | (1ULL << OPCAP_EDIT_PASSWD)
        | (1ULL << OPCAP_PRIV_EDIT_PASSWD)
        | (1ULL << OPCAP_EDIT_CONTEST)
        | (1ULL << OPCAP_CONTROL_CONTEST)
        | (1ULL << OPCAP_RESTART)
        | (1ULL << OPCAP_UNLOAD_CONTEST),
};

int
main(int argc, char *argv[])
{
    progname = argv[0];

    time_t current_time = time(NULL);

    unsigned char ejudge_contests_dir[PATH_MAX];
    ejudge_contests_dir[0] = 0;

    int open_flag = 0;
    int close_flag = 0;
    int visible_flag = 0;
    int invisible_flag = 0;
    int no_users_flag = 0;
    int no_register_flag = 0;
    int no_participant_flag = 0;
    int all_users_flag = 0;
    int all_register_flag = 0;
    int all_participant_flag = 0;
    int no_audit_flag = 0;
    int db_flag = 0;
    int global_flag = 0;
    const char *cap_user_name = NULL;
    int remove_cap_flag = 0;
    int add_judge_cap_flag = 0;
    int add_master_cap_flag = 0;
    int add_full_cap_flag = 0;
    const char *name = NULL;
    int user_id = 0;
    unsigned char *user_name = NULL;
    int lock_flag = 0;
    int oauth_flag = 0;

    struct State state = {};

    int argi = 1;
    while (argi < argc) {
        if (!strcmp(argv[argi], "--version")) {
            printf("%s %s, compiled %s\n", progname, compile_version, compile_date);
            exit(0);
        } else if (!strcmp(argv[argi], "--help")) {
            write_help();
            exit(0);
        } else if (!strcmp(argv[argi], "--open")) {
            if (close_flag) {
                DIE("conflicting flags: --open and --close");
            }
            open_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--close")) {
            if (open_flag) {
                DIE("conflicting flags: --open and --close");
            }
            close_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--visible")) {
            if (invisible_flag) {
                DIE("conflicting flags: --visible and --invisible");
            }
            visible_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--invisible")) {
            if (visible_flag) {
                DIE("conflicting flags: --visible and --invisible");
            }
            invisible_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--no-users")) {
            if (all_users_flag) {
                DIE("conflicting flags: --no-users and --all-users");
            }
            no_users_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--no-register")) {
            if (all_register_flag) {
                DIE("conflicting flags: --no-register and --all-register");
            }
            no_register_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--no-participant")) {
            if (all_participant_flag) {
                DIE("conflicting flags: --no-participant and --all-participant");
            }
            no_participant_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--all-users")) {
            if (no_users_flag) {
                DIE("conflicting flags: --no-users and --all-users");
            }
            all_users_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--all-register")) {
            if (no_register_flag) {
                DIE("conflicting flags: --no-register and --all-register");
            }
            all_register_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--all-participant")) {
            if (no_participant_flag) {
                DIE("conflicting flags: --no-participant and --all-participant");
            }
            all_participant_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--remove-cap")) {
            if (argi + 1 >= argc) {
                DIE("argument expected for --remove-cap");
            }
            if (cap_user_name) {
                DIE("conflicting options: capability change user already set");
            }
            remove_cap_flag = 1;
            cap_user_name = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--add-judge-cap")) {
            if (argi + 1 >= argc) {
                DIE("argument expected for --add-judge-cap");
            }
            if (cap_user_name) {
                DIE("conflicting options: capability change user already set");
            }
            add_judge_cap_flag = 1;
            cap_user_name = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--add-master-cap")) {
            if (argi + 1 >= argc) {
                DIE("argument expected for --add-master-cap");
            }
            if (cap_user_name) {
                DIE("conflicting options: capability change user already set");
            }
            add_master_cap_flag = 1;
            cap_user_name = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--add-full-cap")) {
            if (argi + 1 >= argc) {
                DIE("argument expected for --add-full-cap");
            }
            if (cap_user_name) {
                DIE("conflicting options: capability change user already set");
            }
            add_full_cap_flag = 1;
            cap_user_name = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--no-audit")) {
            no_audit_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--ejudge-xml-path")) {
            if (argi + 1 >= argc) {
                DIE("argument expected for --ejudge-xml-path");
            }
            if (snprintf(state.ejudge_xml_path, sizeof(state.ejudge_xml_path), "%s", argv[argi + 1]) >= sizeof(state.ejudge_xml_path)) {
                DIE("path '%s' is too long", argv[argi + 1]);
            }
            argi += 2;
        } else if (!strcmp(argv[argi], "--ejudge-contests-dir")) {
            if (argi + 1 >= argc) {
                DIE("argument expected for --ejudge-contests-dir");
            }
            if (snprintf(ejudge_contests_dir, sizeof(ejudge_contests_dir), "%s", argv[argi + 1]) >= sizeof(ejudge_contests_dir)) {
                DIE("path '%s' is too long", argv[argi + 1]);
            }
            argi += 2;
        } else if (!strcmp(argv[argi], "--db")) {
            db_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--name")) {
            if (argi + 1 >= argc) {
                DIE("argument expected for --name");
            }
            name = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--global")) {
            global_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--login")) {
            if (argi + 1 >= argc) {
                DIE("argument expected for --login");
            }
            if (cap_user_name) {
                DIE("conflicting options: capability change user already set");
            }
            cap_user_name = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--lock")) {
            lock_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--oauth")) {
            oauth_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--")) {
            ++argi;
            break;
        } else if (argv[argi][0] == '-') {
            DIE("invalid option '%s'", argv[argi]);
        } else {
            break;
        }
    }

    if (global_flag) {
        load_ejudge_config(&state);
        ejudge_cfg_refresh_caps_file(state.config, 1);
    }
    if (db_flag && cap_user_name && cap_user_name[0]) {
        open_userlist(&state);
        int r = userlist_clnt_lookup_user(state.client, cap_user_name, 0, &user_id, &user_name);
        if (r < 0) {
            DIE("failed to lookup user: %s", userlist_strerror(-r));
        }
        //fprintf(stderr, "user id: %d, user name: %s\n", user_id, user_name?(const char*) user_name:"null");
        if (global_flag && name && (!user_name || strcmp(user_name, name) != 0)) {
            r = userlist_clnt_edit_field(state.client, ULS_EDIT_FIELD,
                                         user_id, 0, 0,
                                         USERLIST_NC_NAME, name);
            if (r < 0) {
                DIE("failed to updated user: %s", userlist_strerror(-r));
            }
            free(user_name);
            user_name = xstrdup(cap_user_name);
        }
    }
    int max_contest_id = 0;
    for (int i = argi; i < argc; ++i) {
        errno = 0;
        char *eptr = NULL;
        long v1 = strtol(argv[i], &eptr, 10);
        if (errno || argv[i] == eptr || v1 <= 0 || (int) v1 != v1) {
            DIE("invalid contest '%s'", argv[i]);
        }
        long v2 = v1;
        if (*eptr == '-') {
            char *eptr2 = NULL;
            errno = 0;
            v2 = strtol(eptr + 1, &eptr2, 10);
            if (errno || *eptr2 || eptr + 1 == eptr2 || v2 <= 0 || (int) v2 != v2) {
                DIE("invalid contest range '%s'", argv[i]);
            }
            if (v2 < v1) {
                DIE("invalid contest range '%s'", argv[i]);
            }
        } else if (*eptr) {
            DIE("invalid contest '%s'", argv[i]);
        }
        max_contest_id = (int) v2;
    }

    if (max_contest_id == INT_MAX) {
        DIE("contest_id is too big %d", max_contest_id);
    }

    unsigned char *requested_map = malloc(max_contest_id + 1);
    if (!requested_map) {
        DIE("not enough memory");
    }
    memset(requested_map, 0, max_contest_id + 1);

    for (int i = argi; i < argc; ++i) {
        char *eptr = NULL;
        long v1 = strtol(argv[i], &eptr, 10);
        long v2 = v1;
        if (*eptr == '-') {
            v2 = strtol(eptr + 1, NULL, 10);
        }
        for (long id = v1; id <= v2; ++id) {
            requested_map[id] = 1;
        }
    }

    if (!ejudge_contests_dir[0]) {
        load_ejudge_config(&state);

        if (!state.config->contests_dir) {
            DIE("the contests config directory is not specified");
        }
        if (snprintf(ejudge_contests_dir, sizeof(ejudge_contests_dir), "%s", state.config->contests_dir) >= sizeof(ejudge_contests_dir)) {
            DIE("path is too long: '%s'", ejudge_contests_dir);
        }
    }

    contests_set_directory(ejudge_contests_dir);

    const int *contest_ids = NULL;
    int contest_count = contests_get_list(&contest_ids);

    int failed_count = 0;
    for (int contest_idx = 0; contest_idx < contest_count; ++contest_idx) {
        int contest_id = contest_ids[contest_idx];

        if (contest_id <= 0 || contest_id > max_contest_id || !requested_map[contest_id]) {
            continue;
        }

        struct contest_desc *cnts = NULL;
        if (contests_load(contest_id, &cnts) < 0 || !cnts) {
            printf("%d: failed to load contest\n", contest_id);
            ++failed_count;
            continue;
        }

        int need_update = 0;
        if (open_flag && cnts->closed) {
            need_update = 1;
        }
        if (close_flag && !cnts->closed) {
            need_update = 1;
        }
        if (visible_flag && cnts->invisible) {
            need_update = 1;
        }
        if (invisible_flag && !cnts->invisible) {
            need_update = 1;
        }
        if (no_users_flag && contests_get_users_access_type(cnts) != 0) {
            need_update = 1;
        }
        if (all_users_flag && contests_get_users_access_type(cnts) != 2) {
            need_update = 1;
        }
        if (no_register_flag && contests_get_register_access_type(cnts) != 0) {
            need_update = 1;
        }
        if (all_register_flag && contests_get_register_access_type(cnts) != 2) {
            need_update = 1;
        }
        if (no_participant_flag && contests_get_participant_access_type(cnts) != 0) {
            need_update = 1;
        }
        if (all_participant_flag && contests_get_participant_access_type(cnts) != 2) {
            need_update = 1;
        }
        if (remove_cap_flag && find_cap_user(cnts, cap_user_name) >= 0) {
            need_update = 1;
        }
        if (add_master_cap_flag && find_cap_user_2(cnts, cap_user_name, OPCAP_PREDEF_MASTER) < 0) {
            need_update = 1;
        }
        if (add_judge_cap_flag && find_cap_user_2(cnts, cap_user_name, OPCAP_PREDEF_JUDGE) < 0) {
            need_update = 1;
        }
        if (add_full_cap_flag && find_cap_user_2(cnts, cap_user_name, OPCAP_PREDEF_FULL) < 0) {
            need_update = 1;
        }

        if (need_update) {
            unsigned char *txt1 = NULL, *txt2 = NULL;
            if (parse_contest_xml(contest_id, &txt1, &txt2) < 0) {
                printf("%d: failed to load contest\n", contest_id);
                ++failed_count;
                continue;
            }

            unsigned char updates_buf[128];
            unsigned char *updates_ptr = updates_buf;

            if (open_flag && cnts->closed) {
                cnts->closed = 0;
                *updates_ptr++ = '+';
                *updates_ptr++ = 'O';
            }
            if (close_flag && !cnts->closed) {
                cnts->closed = 1;
                *updates_ptr++ = '-';
                *updates_ptr++ = 'O';
            }
            if (visible_flag && cnts->invisible) {
                cnts->invisible = 0;
                *updates_ptr++ = '+';
                *updates_ptr++ = 'V';
            }
            if (invisible_flag && !cnts->invisible) {
                cnts->invisible = 1;
                *updates_ptr++ = '-';
                *updates_ptr++ = 'V';
            }
            if (no_users_flag && contests_get_users_access_type(cnts) != 0) {
                cnts->users_access = NULL;
                *updates_ptr++ = '-';
                *updates_ptr++ = 'U';
            }
            if (all_users_flag && contests_get_users_access_type(cnts) != 2) {
                cnts->users_access = NULL;
                contests_set_default(cnts, &cnts->users_access, CONTEST_USERS_ACCESS, 1);
                *updates_ptr++ = '+';
                *updates_ptr++ = 'U';
            }
            if (no_register_flag && contests_get_register_access_type(cnts) != 0) {
                cnts->register_access = NULL;
                *updates_ptr++ = '-';
                *updates_ptr++ = 'R';
            }
            if (all_register_flag && contests_get_register_access_type(cnts) != 2) {
                cnts->register_access = NULL;
                contests_set_default(cnts, &cnts->register_access, CONTEST_REGISTER_ACCESS, 1);
                *updates_ptr++ = '+';
                *updates_ptr++ = 'R';
            }
            if (no_participant_flag && contests_get_participant_access_type(cnts) != 0) {
                cnts->team_access = NULL;
                *updates_ptr++ = '-';
                *updates_ptr++ = 'P';
            }
            if (all_participant_flag && contests_get_participant_access_type(cnts) != 2) {
                cnts->team_access = NULL;
                contests_set_default(cnts, &cnts->team_access, CONTEST_TEAM_ACCESS, 1);
                *updates_ptr++ = '+';
                *updates_ptr++ = 'P';
            }
            if (remove_cap_flag) {
                int index = find_cap_user(cnts, cap_user_name);
                if (index >= 0) {
                    contests_remove_nth_permission(cnts, index);
                    *updates_ptr++ = '-';
                    *updates_ptr++ = 'A';
                }
            }
            if (add_judge_cap_flag) {
                contests_upsert_permission(cnts, cap_user_name, opcaps_get_predef_caps(OPCAP_PREDEF_JUDGE));
                *updates_ptr++ = '+';
                *updates_ptr++ = 'A';
                *updates_ptr++ = 'J';
            }
            if (add_master_cap_flag) {
                contests_upsert_permission(cnts, cap_user_name, opcaps_get_predef_caps(OPCAP_PREDEF_MASTER));
                *updates_ptr++ = '+';
                *updates_ptr++ = 'A';
                *updates_ptr++ = 'M';
            }
            if (add_full_cap_flag) {
                contests_upsert_permission(cnts, cap_user_name, opcaps_get_predef_caps(OPCAP_PREDEF_FULL));
                *updates_ptr++ = '+';
                *updates_ptr++ = 'A';
                *updates_ptr++ = 'F';
            }

            *updates_ptr = 0;
            unsigned char audit_str[1024];
            audit_str[0] = 0;
            if (!no_audit_flag) {
                snprintf(audit_str, sizeof(audit_str),
                        "<!-- audit: ejudge-change-contests: %s, %s -->\n", updates_buf, xml_unparse_date(current_time));
            }

            // txt1 (file header) is not written back intentionally
            if (contests_unparse_and_save(cnts, NULL, "", txt2, audit_str, NULL, NULL, 0) < 0) {
                printf("%d: failed to save contest\n", contest_id);
                ++failed_count;
            }

            printf("%d: %s\n", contest_id, updates_buf);
            free(txt1);
            free(txt2);
        }

        if (db_flag) {
            if (remove_cap_flag) {
                if (unregister_user(&state, user_id, contest_id, lock_flag) < 0) {
                    ++failed_count;
                }
            } else if (add_judge_cap_flag || add_master_cap_flag || add_full_cap_flag) {
                const unsigned char *reg_name = name;
                if (!reg_name || !reg_name[0]) reg_name = user_name;
                if (register_privileged_user(&state, user_id, contest_id, reg_name) < 0) {
                    ++failed_count;
                }
            }
        }
    }

    if (global_flag && state.config && state.config->caps_file_info && state.config->caps_file_info->path && state.config->caps_file_info->root) {
        int changed = 0;
        struct ejudge_cfg *root = state.config->caps_file_info->root;
        if (remove_cap_flag) {
            changed |= ejudge_cfg_delete_caps(root, cap_user_name);
            if (oauth_flag) {
                changed |= ejudge_cfg_delete_oauth_entry(root, cap_user_name);
            }
        } else if (add_judge_cap_flag) {
            changed |= ejudge_cfg_upsert_caps(root, cap_user_name, GLOBAL_JUDGE_CAPS, 1);
            if (oauth_flag) {
                changed |= ejudge_cfg_upsert_oauth_entry(root, cap_user_name, cap_user_name, NULL);
            }
        } else if (add_master_cap_flag) {
            changed |= ejudge_cfg_upsert_caps(root, cap_user_name, GLOBAL_MASTER_CAPS, 1);
            if (oauth_flag) {
                changed |= ejudge_cfg_upsert_oauth_entry(root, cap_user_name, cap_user_name, NULL);
            }
        } else if (add_full_cap_flag) {
            changed |= ejudge_cfg_upsert_caps(root, cap_user_name, GLOBAL_FULL_CAPS, 1);
            if (oauth_flag) {
                changed |= ejudge_cfg_upsert_oauth_entry(root, cap_user_name, cap_user_name, NULL);
            }
        }
        if (changed) {
            if (save_caps_file(state.config) < 0) {
                ++failed_count;
            }
        }
    }

    if (failed_count > 0) {
        return 1;
    }
    return 0;
}
