/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/logrotate.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <unistd.h>

struct DirEntry
{
    unsigned char *prefix;
    unsigned char *suffix;
    int serial;
};

static int
sort_func(const void *v1, const void *v2)
{
    const struct DirEntry *d1 = (const struct DirEntry *) v1;
    const struct DirEntry *d2 = (const struct DirEntry *) v2;
    return d2->serial - d1->serial;
}

void
rotate_log_files(
        const unsigned char *log_dir,
        const unsigned char *log_file,
        const unsigned char *back_suffix,
        const unsigned char *log_user,
        const unsigned char *log_group,
        int log_perms,
        int date_suffix_flag)
{
    unsigned char log_path[PATH_MAX];
    DIR *d = NULL;
    struct DirEntry *de = NULL;
    int deu = 0, dea = 0;
    int lfn = strlen(log_file);
    int fd = -1;
    int user_id = -1, group_id = -1;
    unsigned char date_suffix_buf[128];

    date_suffix_buf[0] = 0;
    if (snprintf(log_path, sizeof(log_path), "%s/%s", log_dir, log_file) >= (int) sizeof(log_path)) {
        // path is too long
        goto cleanup;
    }

    struct stat stb;
    if (lstat(log_path, &stb) < 0) {
        // log file does not exist
        goto cleanup;
    }
    if (!S_ISREG(stb.st_mode)) {
        // not regular file
        goto cleanup;
    }

    if (date_suffix_flag <= 0) {
        d = opendir(log_dir);
        if (!d) {
            goto cleanup;
        }
        struct dirent *dd;
        while ((dd = readdir(d))) {
            if (strncmp(dd->d_name, log_file, lfn) != 0) {
                continue;
            }
            if (!dd->d_name[lfn]) {
                // "${log_file}"
                continue;
            }
            if (dd->d_name[lfn] != '.') {
                continue;
            }
            // "${log_file}."
            errno = 0;
            char *eptr = NULL;
            long v = strtol(dd->d_name + lfn + 1, &eptr, 10);
            if (errno || eptr == dd->d_name + lfn + 1) {
                continue;
            }
            if (v <= 0 || v >= 100000) {
                continue;
            }
            if (*eptr && *eptr != '.') {
                continue;
            }
            if (deu == dea) {
                if (!(dea *= 2)) dea = 16;
                de = realloc(de, dea * sizeof(de[0]));
            }
            struct DirEntry *cur = &de[deu++];
            cur->prefix = strdup(dd->d_name);
            cur->prefix[lfn + 1] = 0;
            cur->suffix = strdup(eptr);
            cur->serial = v;
        }
        closedir(d); d = NULL;
    }
    if (deu > 0) {
        qsort(de, deu, sizeof(de[0]), sort_func);
        for (int i = 0; i < deu; ++i) {
            struct DirEntry *cur = &de[i];
            unsigned char p1[PATH_MAX];
            if (snprintf(p1, sizeof(p1), "%s/%s%d%s", log_dir, cur->prefix, cur->serial, cur->suffix) >= (int) sizeof(p1)) {
                continue;
            }
            unsigned char p2[PATH_MAX];
            if (snprintf(p2, sizeof(p2), "%s/%s%d%s", log_dir, cur->prefix, cur->serial + 1, cur->suffix) >= (int) sizeof(p2)) {
                continue;
            }
            rename(p1, p2);
        }
    }
    {
        if (date_suffix_flag > 0) {
            time_t curtime = time(NULL);
            struct tm ttm;
            gmtime_r(&curtime, &ttm);
            snprintf(date_suffix_buf, sizeof(date_suffix_buf),
                     ".%04d%02d%02d",
                     ttm.tm_year + 1900, ttm.tm_mon + 1, ttm.tm_mday);
            back_suffix = date_suffix_buf;
        } else if (!back_suffix || !*back_suffix) {
            back_suffix = ".1";
        }
        unsigned char p1[PATH_MAX];
        if (snprintf(p1, sizeof(p1), "%s/%s%s", log_dir, log_file, back_suffix) >= (int) sizeof(p1)) {
            goto cleanup;
        }
        rename(log_path, p1);
    }

    if (log_user && *log_user) {
        struct passwd *pp = getpwnam(log_user);
        if (pp) {
            user_id = pp->pw_uid;
        }
    }
    if (user_id < 0) user_id = -1;
    if (log_group && *log_group) {
        struct group *gg = getgrnam(log_group);
        if (gg) {
            group_id = gg->gr_gid;
        }
    }
    if (group_id < 0) group_id = -1;

    fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK | O_NOFOLLOW | O_NOCTTY, 0600);
    if (fd < 0) goto cleanup;
    if (log_perms >= 0) {
        fchmod(fd, log_perms);
    }
    if (user_id >= 0 || group_id >= 0) {
        __attribute__((unused)) int _;
        _ = fchown(fd, user_id, group_id);
    }
    close(fd); fd = -1;

cleanup:;
    if (fd >= 0) close(fd);
    if (d) closedir(d);
}

int
rotate_get_log_dir_and_file(
        unsigned char *dir_buf,
        size_t dir_size,
        unsigned char *name_buf,
        size_t name_size,
        const struct ejudge_cfg *config,
        const unsigned char *config_var,
        const unsigned char *log_file)
{
    unsigned char lp[PATH_MAX];
    lp[0] = 0;

    if (config_var && config_var[0]) {
        log_file = config_var;
    }

    if (config_var && config_var[0] && os_IsAbsolutePath(config_var)) {
        if (snprintf(lp, sizeof(lp), "%s", config_var) >= (int) sizeof(lp)) {
            return -1;
        }
    }
    if (!lp[0] && config->var_dir && config->var_dir[0]) {
        if (snprintf(lp, sizeof(lp), "%s/%s", config->var_dir, log_file) >= (int) sizeof(lp)) {
            return -1;
        }
    }
    if (!lp[0] && config->contests_home_dir && config->contests_home_dir[0]) {
        if (snprintf(lp, sizeof(lp), "%s/var/%s", config->contests_home_dir, log_file) >= (int) sizeof(lp)) {
            return -1;
        }
    }
#if defined EJUDGE_CONTESTS_HOME_DIR
    if (!lp[0]) {
        if (snprintf(lp, sizeof(lp), "%s/var/%s", EJUDGE_CONTESTS_HOME_DIR, log_file) >= (int) sizeof(lp)) {
            return -1;
        }
    }
#endif
    if (!lp[0]) {
        return -1;
    }

    os_rDirName(lp, dir_buf, dir_size);
    os_rGetLastname(lp, name_buf, name_size);
    return 0;
}
