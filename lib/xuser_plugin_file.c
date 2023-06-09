/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2015-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/xuser_plugin.h"
#include "ejudge/contests.h"
#include "ejudge/prepare.h"
#include "ejudge/team_extra.h"
#include "ejudge/errlog.h"
#include "ejudge/ej_uuid.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"
#include "ejudge/fileutl.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>

/* plugin state */
struct xuser_file_state
{
    int nref; // reference counter
};

/* per-contest plugin state */
struct xuser_file_cnts_state
{
    struct xuser_cnts_state b;
    struct xuser_file_state *plugin_state;
    int contest_id;
    unsigned char *team_extra_dir;
    size_t team_map_size;
    struct team_extra **team_map;
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

static struct xuser_cnts_state *
open_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags);
static struct xuser_cnts_state *
close_func(
        struct xuser_cnts_state *data);
static const struct team_extra*
get_entry_func(
        struct xuser_cnts_state *data,
        int user_id);
static int
get_clar_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int clar_id,
        const ej_uuid_t *p_clar_uuid);
static int
set_clar_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int clar_id,
        const ej_uuid_t *p_clar_uuid);
static void
flush_func(
        struct xuser_cnts_state *data);
static int
append_warning_func(
        struct xuser_cnts_state *data,
        int user_id,
        int issuer_id,
        const ej_ip_t *issuer_ip,
        time_t issue_date,
        const unsigned char *txt,
        const unsigned char *cmt);
static int
set_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int status);
static int
set_disq_comment_func(
        struct xuser_cnts_state *data,
        int user_id,
        const unsigned char *disq_comment);
static long long
get_run_fields_func(
        struct xuser_cnts_state *data,
        int user_id);
static int
set_run_fields_func(
        struct xuser_cnts_state *data,
        int user_id,
        long long run_fields);
static int
count_read_clars_func(
        struct xuser_cnts_state *data,
        int user_id);
static struct xuser_team_extras *
get_entries_func(
        struct xuser_cnts_state *data,
        int count,
        int *user_ids);
static int
set_problem_dir_prefix_func(
        struct xuser_cnts_state *data,
        int user_id,
        const unsigned char *problem_dir_prefix);
static int
get_user_ids_func(
        struct xuser_cnts_state *data,
        int *p_count,
        int **p_user_ids);

struct xuser_plugin_iface plugin_xuser_file =
{
    {
        {
            sizeof(struct xuser_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "xuser",
            "file",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    XUSER_PLUGIN_IFACE_VERSION,
    open_func,
    close_func,
    get_entry_func,
    get_clar_status_func,
    set_clar_status_func,
    flush_func,
    append_warning_func,
    set_status_func,
    set_disq_comment_func,
    get_run_fields_func,
    set_run_fields_func,
    count_read_clars_func,
    get_entries_func,
    set_problem_dir_prefix_func,
    get_user_ids_func,
};

static struct common_plugin_data *
init_func(void)
{
  struct xuser_file_state *state = NULL;
  XCALLOC(state, 1);
  return (struct common_plugin_data *) state;
}

static int
finish_func(struct common_plugin_data *data)
{
  struct xuser_file_state *state = (struct xuser_file_state*) data;
  xfree(state);
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

static struct xuser_cnts_state *
open_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags)
{
    struct xuser_file_state *plugin_state = (struct xuser_file_state *) data;
    struct xuser_file_cnts_state *state = NULL;

    if (!plugin_state) return NULL;

    XCALLOC(state, 1);
    state->b.vt = &plugin_xuser_file;
    state->plugin_state = plugin_state;
    ++state->plugin_state->nref;

    state->contest_id = cnts->id;
    if (global->team_extra_dir && global->team_extra_dir[0]) {
        state->team_extra_dir = xstrdup(global->team_extra_dir);
        // FIXME: handle an error
        make_dir(state->team_extra_dir, 0700);
    }

    return (struct xuser_cnts_state *) state;
}

static struct xuser_cnts_state *
close_func(
        struct xuser_cnts_state *data)
{
    struct xuser_file_cnts_state *state = (struct xuser_file_cnts_state *) data;
    if (!state) return NULL;

    xfree(state->team_extra_dir);
    for (int i = 0; i < state->team_map_size; i++) {
        team_extra_free(state->team_map[i]);
    }
    xfree(state->team_map);

    --state->plugin_state->nref;
    memset(state, 0, sizeof(*state));
    xfree(state);

    return NULL;
}

static void
extend_team_map(
        struct xuser_file_cnts_state *state,
        int user_id)
{
    size_t new_size = state->team_map_size;
    struct team_extra **new_map = 0;

    if (!new_size) new_size = 32;
    while (new_size <= user_id) new_size *= 2;
    XCALLOC(new_map, new_size);
    if (state->team_map_size > 0) {
        memcpy(new_map, state->team_map, state->team_map_size * sizeof(new_map[0]));
        xfree(state->team_map);
    }
    state->team_map = new_map;
    state->team_map_size = new_size;
}

#define MAX_USER_ID_32DIGITS 4

static const unsigned char b32_digits[]=
"0123456789ABCDEFGHIJKLMNOPQRSTUV";
static void
b32_number(unsigned num, size_t size, unsigned char buf[])
{
    int i;

    ASSERT(size > 1);

    memset(buf, '0', size - 1);
    buf[size - 1] = 0;
    i = size - 2;
    while (num > 0 && i >= 0) {
        buf[i] = b32_digits[num & 0x1f];
        i--;
        num >>= 5;
    }
    ASSERT(!num);
}

static int
make_read_path(
        struct xuser_file_cnts_state *state,
        unsigned char *path,
        size_t size,
        int user_id)
{
    unsigned char b32[16];

    ASSERT(user_id > 0 && user_id <= EJ_MAX_USER_ID);
    b32_number(user_id, MAX_USER_ID_32DIGITS + 1, b32);
    return snprintf(path, size, "%s/%c/%c/%c/%06d.xml",
                    state->team_extra_dir, b32[0], b32[1], b32[2], user_id);
}

static struct team_extra *
get_entry(
        struct xuser_file_cnts_state *state,
        int user_id,
        int try_flag)
{
    struct team_extra *te = state->team_map[user_id];
    path_t rpath;

    if (te) return te;

    make_read_path(state, rpath, sizeof(rpath), user_id);
    if (os_CheckAccess(rpath, REUSE_F_OK) < 0) {
        if (try_flag) return NULL;
        XCALLOC(te, 1);
        te->user_id = user_id;
        state->team_map[user_id] = te;
        return te;
    }
    if (team_extra_parse_xml(rpath, &te) < 0) {
        state->team_map[user_id] = (struct team_extra*) ~(size_t) 0;
        return (struct team_extra*) ~(size_t) 0;
    }
    if (te->user_id != user_id) {
        err("team_extra: %s: user_id mismatch: %d, %d", rpath, te->user_id, user_id);
        state->team_map[user_id] = (struct team_extra*) ~(size_t) 0;
        return (struct team_extra*) ~(size_t) 0;
    }
    if (te->contest_id <= 0) {
        te->contest_id = state->contest_id;
    }
    if (te->contest_id != state->contest_id) {
        err("team_extra: %s: contest_id mismatch: %d, %d", rpath, te->contest_id, state->contest_id);
        state->team_map[user_id] = (struct team_extra*) ~(size_t) 0;
        return (struct team_extra*) ~(size_t) 0;
    }
    state->team_map[user_id] = te;
    return te;
}

static const struct team_extra*
get_entry_func(
        struct xuser_cnts_state *data,
        int user_id)
{
    struct xuser_file_cnts_state *state = (struct xuser_file_cnts_state *) data;
    struct team_extra *tmpval = NULL;

    ASSERT(user_id > 0 && user_id <= EJ_MAX_USER_ID);
    if (user_id >= state->team_map_size) extend_team_map(state, user_id);

    tmpval = get_entry(state, user_id, 0);
    if (tmpval == (struct team_extra*) ~(size_t) 0) tmpval = 0;
    return tmpval;
}

#define BPE (CHAR_BIT * sizeof(((struct team_extra*)0)->clar_map[0]))

static int
get_clar_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int clar_id,
        const ej_uuid_t *p_clar_uuid)
{
    struct xuser_file_cnts_state *state = (struct xuser_file_cnts_state *) data;
    struct team_extra *te;

    ASSERT(user_id > 0 && user_id <= EJ_MAX_USER_ID);

    if (user_id >= state->team_map_size) extend_team_map(state, user_id);
    te = get_entry(state, user_id, 0);
    if (te == (struct team_extra*) ~(size_t) 0) return -1;
    ASSERT(te->user_id == user_id);

    if (p_clar_uuid && team_extra_find_clar_uuid(te, p_clar_uuid) >= 0) {
        return 1;
    }

    if (clar_id < 0 || clar_id >= te->clar_map_size) return 0;
    if ((te->clar_map[clar_id / BPE] & (1UL << clar_id % BPE))) {
        if (p_clar_uuid) {
            // migrate to uuid representation
            team_extra_add_clar_uuid(te, p_clar_uuid);
            te->clar_map[clar_id / BPE] &= ~(1UL << clar_id % BPE);
            te->is_dirty = 1;
        }
        return 1;
    }
    return 0;
}

static int
set_clar_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int clar_id,
        const ej_uuid_t *p_clar_uuid)
{
    struct xuser_file_cnts_state *state = (struct xuser_file_cnts_state *) data;
    struct team_extra *te;
    int retval = 0;

    ASSERT(user_id > 0 && user_id <= EJ_MAX_USER_ID);

    if (user_id >= state->team_map_size) extend_team_map(state, user_id);
    te = get_entry(state, user_id, 0);
    if (te == (struct team_extra*) ~(size_t) 0) return -1;
    ASSERT(te->user_id == user_id);

    if (p_clar_uuid) {
        if (team_extra_add_clar_uuid(te, p_clar_uuid) > 0) {
            retval = 1;
            te->is_dirty = 1;
        }
        if (clar_id >= 0 && clar_id < te->clar_map_size) {
            if ((te->clar_map[clar_id / BPE] & (1UL << clar_id % BPE))) {
                te->clar_map[clar_id / BPE] &= ~(1UL << clar_id % BPE);
                retval = 1;
                te->is_dirty = 1;
            }
        }
        return retval;
    }

    if (clar_id < 0) return -1;
    if (clar_id >= te->clar_map_size) team_extra_extend_clar_map(te, clar_id);
    if ((te->clar_map[clar_id / BPE] & (1UL << clar_id % BPE)))
        return 0;
    te->clar_map[clar_id / BPE] |= (1UL << clar_id % BPE);
    te->is_dirty = 1;
    return 1;
}

static int
make_write_path(
        struct xuser_file_cnts_state *state,
        unsigned char *path,
        size_t size,
        int user_id)
{
    unsigned char b32[16];
    unsigned char *mpath = 0, *p;
    //struct stat sb;
    int i;

    ASSERT(user_id > 0 && user_id <= EJ_MAX_USER_ID);
    b32_number(user_id, MAX_USER_ID_32DIGITS + 1, b32);

    mpath = alloca(strlen(state->team_extra_dir) + 32);
    strcpy(mpath, state->team_extra_dir);
    p = mpath + strlen(mpath);
    for (i = 0; i < MAX_USER_ID_32DIGITS - 1; i++) {
        *p++ = '/';
        *p++ = b32[i];
        *p = 0;
        if (os_MakeDir(mpath, 0770) < 0) {
            if (errno != EEXIST) {
                err("team_extra: %s: mkdir failed: %s", mpath, os_ErrorMsg());
                return -1;
            }
            /*
              if (lstat(mpath, &sb) < 0) {
              err("team_extra: %s: lstat failed: %s", mpath, os_ErrorMsg());
              return -1;
              }
              if (!S_ISDIR(sb.st_mode)) {
              err("team_extra: %s: is not a directory", mpath);
              return -1;
              }
            */
        }
    }

    return snprintf(path, size, "%s/%c/%c/%c/%06d.xml",
                    state->team_extra_dir, b32[0], b32[1], b32[2], user_id);
}


static void
flush_func(
        struct xuser_cnts_state *data)
{
    struct xuser_file_cnts_state *state = (struct xuser_file_cnts_state *) data;
    struct team_extra *te;
    int i;
    path_t wpath;
    FILE *f;

    for (i = 1; i < state->team_map_size; i++) {
        if (!(te = state->team_map[i])) continue;
        if (te == (struct team_extra*) ~(size_t) 0) continue;
        ASSERT(te->user_id == i);
        if (!te->is_dirty) continue;
        if (make_write_path(state, wpath, sizeof(wpath), i) < 0) continue;
        if (!ej_uuid_is_nonempty(te->uuid)) {
            ej_uuid_generate(&te->uuid);
        }
        if (!(f = fopen(wpath, "w"))) {
            unlink(wpath);
            continue;
        }
        team_extra_unparse_xml(f, te);
        fclose(f);
        te->is_dirty = 0;
    }
}

static int
append_warning_func(
        struct xuser_cnts_state *data,
        int user_id,
        int issuer_id,
        const ej_ip_t *issuer_ip,
        time_t issue_date,
        const unsigned char *txt,
        const unsigned char *cmt)
{
    struct xuser_file_cnts_state *state = (struct xuser_file_cnts_state *) data;
    struct team_extra *te;
    struct team_warning *cur_warn;

    ASSERT(user_id > 0 && user_id <= EJ_MAX_USER_ID);

    if (user_id >= state->team_map_size) extend_team_map(state, user_id);
    te = get_entry(state, user_id, 0);
    if (te == (struct team_extra*) ~(size_t) 0) return -1;
    ASSERT(te->user_id == user_id);

    if (te->warn_u == te->warn_a) {
        te->warn_a *= 2;
        if (!te->warn_a) te->warn_a = 8;
        XREALLOC(te->warns, te->warn_a);
    }
    XCALLOC(cur_warn, 1);
    te->warns[te->warn_u++] = cur_warn;

    cur_warn->date = issue_date;
    cur_warn->issuer_id = issuer_id;
    cur_warn->issuer_ip = *issuer_ip;
    cur_warn->text = xstrdup(txt);
    cur_warn->comment = xstrdup(cmt);

    te->is_dirty = 1;
    return 0;
}

static int
set_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int status)
{
    struct xuser_file_cnts_state *state = (struct xuser_file_cnts_state *) data;
    struct team_extra *te;

    ASSERT(user_id > 0 && user_id <= EJ_MAX_USER_ID);

    if (user_id >= state->team_map_size) extend_team_map(state, user_id);
    te = get_entry(state, user_id, 0);
    if (te == (struct team_extra*) ~(size_t) 0) return -1;
    ASSERT(te->user_id == user_id);

    if (te->status == status) return 0;
    te->status = status;
    te->is_dirty = 1;
    return 1;
}

static int
set_disq_comment_func(
        struct xuser_cnts_state *data,
        int user_id,
        const unsigned char *disq_comment)
{
    struct xuser_file_cnts_state *state = (struct xuser_file_cnts_state *) data;
    struct team_extra *te;

    ASSERT(user_id > 0 && user_id <= EJ_MAX_USER_ID);

    if (user_id >= state->team_map_size) extend_team_map(state, user_id);
    te = get_entry(state, user_id, 0);
    if (te == (struct team_extra*) ~(size_t) 0) return -1;
    ASSERT(te->user_id == user_id);

    xfree(te->disq_comment);
    te->disq_comment = xstrdup(disq_comment);
    te->is_dirty = 1;
    return 1;
}

static long long
get_run_fields_func(
        struct xuser_cnts_state *data,
        int user_id)
{
    struct xuser_file_cnts_state *state = (struct xuser_file_cnts_state *) data;
    struct team_extra *te;

    ASSERT(user_id > 0 && user_id <= EJ_MAX_USER_ID);

    if (user_id >= state->team_map_size) extend_team_map(state, user_id);
    te = get_entry(state, user_id, 1);
    if (!te || te == (struct team_extra*) ~(size_t) 0) return 0;
    ASSERT(te->user_id == user_id);
    return te->run_fields;
}

static int
set_run_fields_func(
        struct xuser_cnts_state *data,
        int user_id,
        long long run_fields)
{
    struct xuser_file_cnts_state *state = (struct xuser_file_cnts_state *) data;
    struct team_extra *te;

    ASSERT(user_id > 0 && user_id <= EJ_MAX_USER_ID);

    if (user_id >= state->team_map_size) extend_team_map(state, user_id);
    te = get_entry(state, user_id, 0);
    if (te == (struct team_extra*) ~(size_t) 0) return -1;
    ASSERT(te->user_id == user_id);

    if (te->run_fields == run_fields) return 0;
    te->run_fields = run_fields;
    te->is_dirty = 1;
    return 1;
}

static int
count_read_clars_func(
        struct xuser_cnts_state *data,
        int user_id)
{
    struct xuser_file_cnts_state *state = (struct xuser_file_cnts_state *) data;
    struct team_extra *te;

    if (user_id <= 0) return 0;
    if (user_id >= state->team_map_size) extend_team_map(state, user_id);
    if (!(te = get_entry(state, user_id, 0))) return 0;
    if (te == (struct team_extra*) ~(size_t) 0) return 0;
    int count = te->clar_uuids_size;
    for (int i = 0; i < te->clar_map_alloc; ++i) {
        count += __builtin_popcount(te->clar_map[i]);
    }
    return count;
}

struct xuser_file_team_extras
{
    struct xuser_team_extras b;

    struct xuser_file_cnts_state *state;
};

static struct xuser_team_extras *
xuser_file_team_extras_free(struct xuser_team_extras *x)
{
    struct xuser_file_team_extras *xf = (struct xuser_file_team_extras *) x;

    if (xf) {
        xfree(xf);
    }
    return NULL;
}

static const struct team_extra *
xuser_file_team_extras_get(struct xuser_team_extras *x, int user_id)
{
    struct xuser_file_team_extras *xf = (struct xuser_file_team_extras *) x;
    return get_entry_func(&xf->state->b, user_id);
}

static struct xuser_team_extras *
get_entries_func(
        struct xuser_cnts_state *data,
        int count,
        int *user_ids)
{
    struct xuser_file_cnts_state *state = (struct xuser_file_cnts_state *) data;
    struct xuser_file_team_extras *vec = NULL;

    if (count <= 0 || !user_ids) return NULL;

    XCALLOC(vec, 1);
    vec->b.free = xuser_file_team_extras_free;
    vec->b.get = xuser_file_team_extras_get;
    vec->state = state;
    return &vec->b;
}

static int
set_problem_dir_prefix_func(
        struct xuser_cnts_state *data,
        int user_id,
        const unsigned char *problem_dir_prefix)
{
    struct xuser_file_cnts_state *state = (struct xuser_file_cnts_state *) data;
    struct team_extra *te;

    ASSERT(user_id > 0 && user_id <= EJ_MAX_USER_ID);

    if (user_id >= state->team_map_size) extend_team_map(state, user_id);
    te = get_entry(state, user_id, 0);
    if (te == (struct team_extra*) ~(size_t) 0) return -1;
    ASSERT(te->user_id == user_id);

    xfree(te->problem_dir_prefix);
    te->problem_dir_prefix = xstrdup(problem_dir_prefix);
    te->is_dirty = 1;
    return 1;
}

static int
get_user_ids_func(
        struct xuser_cnts_state *data,
        int *p_count,
        int **p_user_ids)
{
    struct xuser_file_cnts_state *state = (struct xuser_file_cnts_state *) data;
    int count = 0;
    int reserved = 0;
    int *user_ids = NULL;
    int top_flag[32] = {};

    DIR *d = opendir(state->team_extra_dir);
    if (!d) {
        *p_count = 0;
        return 0;
    }
    struct dirent *dd;
    int max_top_digit = -1;
    while ((dd = readdir(d))) {
        if (strlen(dd->d_name) == 1) {
            int c = (unsigned char) dd->d_name[0];
            if (c >= '0' && c <= '9') {
                c -= '0';
            } else if (c >= 'A' && c <= 'V') {
                c -= ('A' - 10);
            } else {
                c = -1;
            }
            if (c >= 0) {
                top_flag[c] = 1;
                if (c > max_top_digit) max_top_digit = c;
            }
        }
    }
    closedir(d); d = NULL;

    for (int user_id = 1; user_id <= EJ_MAX_USER_ID; ++user_id) {
        unsigned char b32[16];
        b32_number(user_id, MAX_USER_ID_32DIGITS + 1, b32);
        int top_dig = -1;
        if (b32[0] >= '0' && b32[0] <= '9') {
            top_dig = (unsigned char) b32[0] - '0';
        } else if (b32[0] >= 'A' && b32[0] <= 'V') {
            top_dig = (unsigned char) b32[0] - ('A' - 10);
        }
        if (top_dig < 0 || top_dig > max_top_digit) break;
        if (top_flag[top_dig]) {
            char path[PATH_MAX];
            if (snprintf(path, sizeof(path), "%s/%c/%c/%c/%06d.xml",
                         state->team_extra_dir, b32[0], b32[1], b32[2],
                         user_id) >= (int) sizeof(path)) {
                break;
            }
            if (access(path, R_OK) >= 0) {
                if (count == reserved) {
                    if (!(reserved *= 2)) reserved = 16;
                    XREALLOC(user_ids, reserved);
                }
                user_ids[count++] = user_id;
            }
        }
    }

    *p_count = count;
    *p_user_ids = user_ids;

    return 0;
}
