/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2022 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ejudge_cfg.h"
#include "ejudge/metrics_contest.h"
#include "ejudge/osdeps.h"
#include "ejudge/errlog.h"
#include "ejudge/xalloc.h"

#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

struct metrics_desc metrics;

int
setup_metrics_file(struct ejudge_cfg *config)
{
    char dir[PATH_MAX];
    char path[PATH_MAX];

    dir[0] = 0;
#if defined EJUDGE_CONTESTS_STATUS_DIR
    snprintf(dir, sizeof(dir), "%s", EJUDGE_CONTESTS_STATUS_DIR);
#elif defined EJUDGE_LOCAL_DIR
    snprintf(dir, sizeof(dir), "%s/status", EJUDGE_LOCAL_DIR);
#else
    snprintf(dir, sizeof(dir), "%s/var/status", EJUDGE_CONTESTS_HOME_DIR);
#endif

    if (os_MakeDirPath(dir, 0775) < 0) {
        err("failed to create '%s'", dir);
        return -1;
    }
    snprintf(path, sizeof(path), "%s/ej-contests-status", dir);

    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK, 0644);
    if (fd < 0) {
        err("failed to open '%s': %s", path, os_ErrorMsg());
        return -1;
    }
    struct stat stb;
    if (fstat(fd, &stb) < 0) {
        close(fd);
        err("fstat failed: %s", os_ErrorMsg());
        return -1;
    }
    if (!S_ISREG(stb.st_mode)) {
        err("status file '%s' must be regular", path);
        close(fd);
        return -1;
    }
    if (stb.st_size < (int) sizeof(struct metrics_contest_data)) {
        if (ftruncate(fd, (int) sizeof(struct metrics_contest_data)) < 0) {
            err("ftruncate '%s' failed: %s", path, os_ErrorMsg());
            close(fd);
            return -1;
        }
    }

    uint32_t msize = sizeof(struct metrics_contest_data);
    struct metrics_contest_data *mcd = mmap(NULL, msize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mcd == MAP_FAILED) {
        err("mmap '%s' failed: %s", path, os_ErrorMsg());
        close(fd);
        return -1;
    }
    close(fd); fd = -1;

    memset(mcd, 0, sizeof(*mcd));
    mcd->size = msize;
    gettimeofday(&mcd->start_time, NULL);
    mcd->update_time = mcd->start_time;
    mcd->client_serial = 1;

    metrics.path = xstrdup(path);
    metrics.data = mcd;

    return 0;
}
