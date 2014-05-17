/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2014 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/external_action.h"
#include "ejudge/errlog.h"

#include "reuse/xalloc.h"

#include <stdio.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <string.h>

static const unsigned char *
fix_action(
        unsigned char *buf,
        int size,
        const unsigned char *action)
{
    snprintf(buf, size, "%s", action);
    for (int i = 0; buf[i]; ++i) {
        if (buf[i] == '-') {
            buf[i] = '_';
        } else {
            buf[i] = tolower(buf[i]);
        }
    }
    return buf;
}

static int
try_load_action(
        ExternalActionState *state,
        const unsigned char *path,
        const unsigned char *dir,
        const unsigned char *action,
        const unsigned char *name_prefix)
{
    unsigned char full_path[PATH_MAX];
    unsigned char full_name[PATH_MAX];
    int retval = 0;

    snprintf(full_path, sizeof(full_path), "%s/%s/%s.so", path, dir, action);

    struct stat stb;
    if (lstat(full_path, &stb) < 0) {
        goto fail_use_errno;
    }
    if (S_ISLNK(stb.st_mode)) {
        retval = -ELOOP;
        goto fail_with_errno;
    }
    if (!S_ISREG(stb.st_mode)) {
        retval = -EISDIR;
        goto fail_with_errno;
    }
    if (access(full_path, X_OK | R_OK) < 0) {
        goto fail_use_errno;
    }
    state->dl_handle = dlopen(full_path, RTLD_GLOBAL | RTLD_NOW);
    if (!state->dl_handle) {
        retval = -ENOEXEC;
        goto fail_use_dlerror;
    }
    snprintf(full_name, sizeof(full_name), "%s%s", name_prefix, action);
    state->action_handler = dlsym(state->dl_handle, full_name);
    if (!state->action_handler) {
        retval = -ESRCH;
        goto fail_use_dlerror;
    }
    retval = 0;
    return retval;

fail_use_errno:
    retval = -errno;

fail_with_errno:
    xfree(state->err_msg);
    state->err_msg = xstrdup(strerror(-retval));
    return retval;

fail_use_dlerror:
    xfree(state->err_msg);
    state->err_msg = xstrdup(dlerror());
    state->action_handler = NULL;
    if (state->dl_handle) {
        dlclose(state->dl_handle);
        state->dl_handle = NULL;
    }
    return retval;
}

ExternalActionState *
external_action_load(
        ExternalActionState *state,
        const unsigned char *dir,
        const unsigned char *action,
        const unsigned char *name_prefix)
{
    unsigned char action_buf[128];

    if (state && state->action_handler) return state;

    if (!state) {
        XCALLOC(state, 1);
    }
    fix_action(action_buf, sizeof(action_buf), action);
    if (try_load_action(state, ".", dir, action, name_prefix) >= 0) {
        return state;
    }
    if (try_load_action(state, EJUDGE_LIBEXEC_DIR "/ejudge", dir, action, name_prefix) >= 0) {
        return state;
    }

    err("page load error: %s", state->err_msg);
    return state;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
