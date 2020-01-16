/* -*- mode: c -*- */

/* Copyright (C) 2019 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/statusdb.h"
#include "ejudge/status_plugin.h"
#include "ejudge/contests.h"
#include "ejudge/prepare.h"
#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"
#include "ejudge/osdeps.h"
#include "ejudge/fileutl.h"

#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#define PROT_SERVE_STATUS_MAGIC_V1 (0xe739aa02)
struct prot_serve_status_v1
{
    unsigned int magic;
    ej_time_t cur_time;
    ej_time_t start_time;
    ej_time_t sched_time;
    ej_time_t duration;
    ej_time_t stop_time;
    ej_time_t freeze_time;
    int total_runs;
    int total_clars;
    int download_interval;
    unsigned char clars_disabled;
    unsigned char team_clars_disabled;
    unsigned char standings_frozen;
    unsigned char score_system;
    unsigned char clients_suspended;
    unsigned char testing_suspended;
    unsigned char is_virtual;
    unsigned char olympiad_judging_mode;
    unsigned char continuation_enabled;
};

// number of problems with dynamic priority stored in serve_status structure
#define EJ_SERVE_STATUS_TOTAL_PROBS_V2 28

#define PROT_SERVE_STATUS_MAGIC_V2 (0xe739aa03)
struct prot_serve_status_v2
{
    unsigned int magic;
    ej_time_t cur_time;
    ej_time_t start_time;
    ej_time_t sched_time;
    ej_time_t duration;
    ej_time_t stop_time;
    ej_time_t freeze_time;
    int total_runs;
    int total_clars;
    int download_interval;
    unsigned char clars_disabled;
    unsigned char team_clars_disabled;
    unsigned char standings_frozen;
    unsigned char score_system;
    unsigned char clients_suspended;
    unsigned char testing_suspended;
    unsigned char is_virtual;
    unsigned char _olympiad_judging_mode; /* unused */
    unsigned char continuation_enabled;
    unsigned char printing_enabled;
    unsigned char printing_suspended;
    unsigned char always_show_problems;
    ej_time_t finish_time;
    ej_time_t stat_reported_before;
    ej_time_t stat_report_time;
    unsigned char accepting_mode;

    // upsolving mode
    unsigned char upsolving_mode;
    unsigned char upsolving_freeze_standings;
    unsigned char upsolving_view_source;
    unsigned char upsolving_view_protocol;
    unsigned char upsolving_full_protocol;
    unsigned char upsolving_disable_clars;
    unsigned char testing_finished;

    ej_time64_t   max_online_time;
    int           max_online_count;

    // priority adjustments for problems
    signed char   prob_prio[EJ_SERVE_STATUS_TOTAL_PROBS_V2];

    signed char online_view_source;
    signed char online_view_report;
    unsigned char online_view_judge_score;
    unsigned char online_final_visibility;
    unsigned char online_valuer_judge_comments;

    unsigned char _pad[3];
    ej_time64_t last_daily_reminder;
};

#define PROT_SERVE_STATUS_MAGIC_V3 (0xe739aa04)
struct prot_serve_status_v3
{
    uint32_t magic;
    unsigned char _pad[12];
    struct prot_serve_status v;
};

/* global plugin state */
struct plugin_status_file_state
{
    int nref; // reference counter
};

struct statusdb_file_state
{
    struct statusdb_state b;
};

static struct common_plugin_data *
init_func(void);
static int
finish_func(struct common_plugin_data *data);
static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *plugin_config);
static struct statusdb_state *
open_func(
        const struct common_loaded_plugin *self,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags);
static void
close_func(struct statusdb_state *sds);
static int
load_func(
        struct statusdb_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags,
        struct prot_serve_status *stat);
static int
save_func(
        struct statusdb_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags,
        const struct prot_serve_status *stat);
static void
remove_func(
        struct statusdb_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global);
static int
has_status_func(
        const struct common_loaded_plugin *self,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags);

struct status_plugin_iface plugin_status_file =
{
    {
        {
            sizeof(struct status_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "status",
            "file"
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func
    },
    STATUS_PLUGIN_IFACE_VERSION,
    open_func,
    close_func,
    load_func,
    save_func,
    remove_func,
    has_status_func,
};

static struct common_plugin_data *
init_func(void)
{
    struct plugin_status_file_state *ps = NULL;
    XCALLOC(ps, 1);
    return (struct common_plugin_data *) ps;
}

static int
finish_func(struct common_plugin_data *data)
{
    struct plugin_status_file_state *ps = (struct plugin_status_file_state *) data;
    xfree(ps);
    return 0;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *plugin_config)
{
    return 0;
}

static struct statusdb_state *
open_func(
        const struct common_loaded_plugin *self,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags)
{
    struct statusdb_file_state *sfs = NULL;
    XCALLOC(sfs, 1);
    sfs->b.plugin = self;
    return (struct statusdb_state *) sfs;
}

static void
close_func(struct statusdb_state *sds)
{
    struct statusdb_file_state *sfs = (struct statusdb_file_state*) sds;
    xfree(sfs);
}

static int
load_func(
        struct statusdb_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags,
        struct prot_serve_status *stat)
{
    struct statusdb_file_state *sfs __attribute__((unused)) = (struct statusdb_file_state*) sds;

    void *memptr = MAP_FAILED;
    size_t memsize = 0;
    int fd = -1;

    unsigned char status_dir[PATH_MAX];
    unsigned char *status_dir_ptr = status_dir;
#if defined EJUDGE_CONTESTS_STATUS_DIR
    if (snprintf(status_dir, sizeof(status_dir), "%s/%06d", EJUDGE_CONTESTS_STATUS_DIR, cnts->id) >= sizeof(status_dir)) {
        err("status_plugin_file:load_func: path is too long: %s/%06d", EJUDGE_CONTESTS_STATUS_DIR, cnts->id);
        goto fail;
    }
#else
    status_dir_ptr = global->legacy_status_dir;
#endif

    unsigned char status_path[PATH_MAX];
    if (snprintf(status_path, sizeof(status_path), "%s/dir/status", status_dir_ptr) >= sizeof(status_path)) {
        err("status_plugin_file:load_func: path is too long: %s/dir/status", status_dir_ptr);
        goto fail;
    }

    //info("status_plugin_file:load_func: loading from %s", status_path);

    fd = open(status_path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
    if (fd < 0) {
        if (errno != ENOENT) {
            err("status_plugin_file:load_func: open on %s failed: %s", status_path, os_ErrorMsg());
            goto fail;
        }
        // nothing happened, but does not exist yet
        memset(stat, 0, sizeof(*stat));
        return 0;
    }

    struct stat stb;
    if (fstat(fd, &stb) < 0) {
        err("status_plugin_file:load_func: fstat on %s failed: %s", status_path, os_ErrorMsg());
        goto fail;
    }
    if (!S_ISREG(stb.st_mode)) {
        err("status_plugin_file:load_func: file %s is not regular", status_path);
        goto fail;
    }
    if (!stb.st_size) {
        memset(stat, 0, sizeof(*stat));
        close(fd);
        return 0;
    }
    if (stb.st_size < 32 || stb.st_size >= 4096) {
        err("status_plugin_file:load_func: file %s has invalid length %lld", status_path, (long long) stb.st_size);
        goto fail;
    }

    memsize = stb.st_size;
    memptr = mmap(NULL, memsize, PROT_READ, MAP_SHARED, fd, 0);
    if (memptr == MAP_FAILED) {
        err("status_plugin_file:load_func: mmap on %s failed: %s", status_path, os_ErrorMsg());
        goto fail;
    }
    close(fd); fd = -1;

    if (*(unsigned *) memptr == PROT_SERVE_STATUS_MAGIC_V1) {
        err("status_plugin_file:load_func: file %s has unsupported format V1", status_path);
        goto fail;
    } else if (*(unsigned *) memptr == PROT_SERVE_STATUS_MAGIC_V2) {
        if (stb.st_size != sizeof(struct prot_serve_status_v2)) {
            err("status_plugin_file:load_func: file %s has invalid size", status_path);
            goto fail;
        }
        info("status_plugin_file:load_func: %s version 2", status_path);
        const struct prot_serve_status_v2 *v2stat = (const struct prot_serve_status_v2*) memptr;
        memset(stat, 0, sizeof(*stat));
        stat->cur_time = v2stat->cur_time;
        stat->start_time = v2stat->start_time;
        stat->sched_time = v2stat->sched_time;
        stat->duration = v2stat->duration;
        stat->stop_time = v2stat->stop_time;
        stat->freeze_time = v2stat->freeze_time;
        stat->total_runs = v2stat->total_runs;
        stat->total_clars = v2stat->total_clars;
        stat->download_interval = v2stat->download_interval;
        stat->clars_disabled = v2stat->clars_disabled;
        stat->team_clars_disabled = v2stat->team_clars_disabled;
        stat->standings_frozen = v2stat->standings_frozen;
        stat->score_system = v2stat->score_system;
        stat->clients_suspended = v2stat->clients_suspended;
        stat->testing_suspended = v2stat->testing_suspended;
        stat->is_virtual = v2stat->is_virtual;
        stat->continuation_enabled = v2stat->continuation_enabled;
        stat->printing_enabled = v2stat->printing_enabled;
        stat->printing_suspended = v2stat->printing_suspended;
        stat->always_show_problems = v2stat->always_show_problems;
        stat->finish_time = v2stat->finish_time;
        stat->stat_reported_before = v2stat->stat_reported_before;
        stat->stat_report_time = v2stat->stat_report_time;
        stat->accepting_mode = v2stat->accepting_mode;
        stat->upsolving_mode = v2stat->upsolving_mode;
        stat->upsolving_freeze_standings = v2stat->upsolving_freeze_standings;
        stat->upsolving_view_source = v2stat->upsolving_view_source;
        stat->upsolving_view_protocol = v2stat->upsolving_view_protocol;
        stat->upsolving_full_protocol = v2stat->upsolving_full_protocol;
        stat->upsolving_disable_clars = v2stat->upsolving_disable_clars;
        stat->testing_finished = v2stat->testing_finished;
        stat->max_online_time = v2stat->max_online_time;
        stat->max_online_count = v2stat->max_online_count;
        stat->online_view_source = v2stat->online_view_source;
        stat->online_view_report = v2stat->online_view_report;
        stat->online_view_judge_score = v2stat->online_view_judge_score;
        stat->online_final_visibility = v2stat->online_final_visibility;
        stat->online_valuer_judge_comments = v2stat->online_valuer_judge_comments;
        stat->last_daily_reminder = v2stat->last_daily_reminder;

        memcpy(stat->prob_prio, v2stat->prob_prio, EJ_SERVE_STATUS_TOTAL_PROBS_V2 * sizeof(stat->prob_prio[0]));
    } else if (*(unsigned *) memptr == PROT_SERVE_STATUS_MAGIC_V3) {
        if (stb.st_size != sizeof(struct prot_serve_status_v3)) {
            err("status_plugin_file:load_func: file %s has invalid size", status_path);
            goto fail;
        }
        const struct prot_serve_status_v3 *v3stat = (const struct prot_serve_status_v3*) memptr;
        *stat = v3stat->v;
    } else {
        err("status_plugin_file:load_func: file %s has invalid format", status_path);
        goto fail;
    }

    munmap(memptr, stb.st_size);
    return 1;

fail:
    if (memptr) {
        munmap(memptr, memsize);
    }
    if (fd >= 0) {
        close(fd);
    }
    return -1;
}

static int
save_func(
        struct statusdb_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags,
        const struct prot_serve_status *stat)
{
    struct prot_serve_status_v3 v3stat = {};

    v3stat.magic = PROT_SERVE_STATUS_MAGIC_V3;
    v3stat.v = *stat;

    unsigned char status_dir[PATH_MAX];
    unsigned char *status_dir_ptr = status_dir;
#if defined EJUDGE_CONTESTS_STATUS_DIR
    if (snprintf(status_dir, sizeof(status_dir), "%s/%06d", EJUDGE_CONTESTS_STATUS_DIR, cnts->id) >= sizeof(status_dir)) {
        err("status_plugin_file:save_func: path %s/%06d is too long", EJUDGE_CONTESTS_STATUS_DIR, cnts->id);
        return -1;
    }
#else
    status_dir_ptr = global->legacy_status_dir;
#endif

    int res = generic_write_file((char*) &v3stat, sizeof(v3stat), SAFE, status_dir_ptr, "status", "");
    if (res < 0) {
        err("status_plugin_file:save_func: save to %s failed", status_dir_ptr);
        return -1;
    }
    return 1;
}

static void
remove_func(
        struct statusdb_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global)
{
    unsigned char status_dir[PATH_MAX];
    unsigned char status_path[PATH_MAX];
    unsigned char *status_dir_ptr = status_dir;
#if defined EJUDGE_CONTESTS_STATUS_DIR
    if (snprintf(status_dir, sizeof(status_dir), "%s/%06d", EJUDGE_CONTESTS_STATUS_DIR, cnts->id) >= sizeof(status_dir)) {
        err("status_plugin_file:remove_func: path %s/%06d is too long", EJUDGE_CONTESTS_STATUS_DIR, cnts->id);
        return;
    }
#else
    status_dir_ptr = global->legacy_status_dir;
#endif

    if (snprintf(status_path, sizeof(status_path), "%s/dir/status", status_dir_ptr) >= sizeof(status_path)) {
        err("status_plugin_file:remove_func: path %s/dir/status is too long", status_dir_ptr);
        return;
    }

    info("removing status file %s", status_path);
    unlink(status_path);
}

static int
has_status_func(
        const struct common_loaded_plugin *self,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags)
{
    unsigned char status_dir[PATH_MAX];
    unsigned char status_path[PATH_MAX];
    unsigned char *status_dir_ptr = status_dir;
#if defined EJUDGE_CONTESTS_STATUS_DIR
    if (snprintf(status_dir, sizeof(status_dir), "%s/%06d", EJUDGE_CONTESTS_STATUS_DIR, cnts->id) >= sizeof(status_dir)) {
        err("status_plugin_file:has_status_func: path %s/%06d is too long", EJUDGE_CONTESTS_STATUS_DIR, cnts->id);
        return -1;
    }
#else
    status_dir_ptr = global->legacy_status_dir;
#endif

    if (snprintf(status_path, sizeof(status_path), "%s/dir/status", status_dir_ptr) >= sizeof(status_path)) {
        err("status_plugin_file:has_status_func: path %s/dir/status is too long", status_dir_ptr);
        return -1;
    }

    return access(status_path, R_OK | W_OK) >= 0;
}
