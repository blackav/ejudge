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

typedef struct ExternalActionDependency
{
    unsigned char *lhs; // left-hand side of the dependency
    int rhs_a;
    int rhs_u;
    unsigned char **rhs; // right-hand side
} ExternalActionDependency;

ExternalActionDependency *
external_action_dep_free(ExternalActionDependency *d)
{
    if (d) {
        xfree(d->lhs);
        for (int i = 0; i < d->rhs_u; ++i) {
            xfree(d->rhs[i]); d->rhs[i] = NULL;
        }
        xfree(d->rhs);
        memset(d, 0, sizeof(*d));
        xfree(d);
    }
    return NULL;
}

void
external_action_dep_add(ExternalActionDependency *d, const unsigned char *str)
{
    if (!d->rhs_a) {
        d->rhs_a = 16;
        XCALLOC(d->rhs, d->rhs_a);
    } else if (d->rhs_u == d->rhs_a) {
        XREALLOC(d->rhs, d->rhs_a *= 2);
    }
    d->rhs[d->rhs_u++] = xstrdup(str);
}

typedef struct ExternalActionDependencies
{
    int a, u;
    ExternalActionDependency **v;
} ExternalActionDependencies;

ExternalActionDependencies *
external_action_deps_free(ExternalActionDependencies *dd)
{
    if (dd) {
        for (int i = 0; i < dd->u; ++i) {
            dd->v[i] = external_action_dep_free(dd->v[i]);
        }
        xfree(dd->v);
        memset(dd, 0, sizeof(*dd));
        xfree(dd);
    }
    return NULL;
}

void
external_action_deps_add(ExternalActionDependencies *dd, ExternalActionDependency *d)
{
    for (int i = 0; i < dd->u; ++i) {
        if (!strcmp(dd->v[i]->lhs, d->lhs)) {
            external_action_dep_free(dd->v[i]);
            dd->v[i] = d;
            return;
        }
    }
    if (!dd->a) {
        XCALLOC(dd->v, (dd->a = 16));
    } else if (dd->u == dd->a) {
        XREALLOC(dd->v, (dd->a *= 2));
    }
    dd->v[dd->u++] = d;
}

static int
do_getc(FILE *f)
{
    int c = getc(f);
    if (c != '\\') return c;
    c = getc(f);
    if (c == EOF) return '\\';
    if (!isspace(c)) {
        ungetc(c, f);
        return '\\';
    }
    while (isspace(c) && c != '\n') {
        c = getc(f);
    }
    if (c == '\n') c = ' ';
    return c;
}

int
external_action_parse_deps(
        FILE *log_f,
        FILE *dep_f,
        ExternalActionDependencies *dd)
{
    int buf_a = 0, buf_u = 0;
    unsigned char *buf = NULL;
    ExternalActionDependency *d = NULL;

    int c = do_getc(dep_f);
    while (c != EOF) {
        if (c == '\t') {
            while (c != EOF && c != '\n') {
                c = do_getc(dep_f);
            }
            if (c == '\n') {
                c = do_getc(dep_f);
            }
            continue;
        }
        while (isspace(c) && c != '\n') {
            c = do_getc(dep_f);
        }
        if (c == '\n') {
            c = do_getc(dep_f);
            continue;
        }
        if (c == '#') {
            while (c != EOF && c != '\n') {
                c = do_getc(dep_f);
            }
            if (c == '\n') {
                c = do_getc(dep_f);
            }
            continue;
        }
        if (!buf) {
            buf_a = 32; buf_u = 0;
            buf = xmalloc(buf_a);
        }
        buf_u = 0;
        while (c != EOF && !isspace(c) && c != '=' && c != ':') {
            if (buf_u + 1 >= buf_a) {
                buf = xrealloc(buf, buf_a *= 2);
            }
            buf[buf_u++] = c;
            c = do_getc(dep_f);
        }
        buf[buf_u] = 0;
        if (!buf_u) {
            // invalid dependency line
            while (c != EOF && c != '\n') {
                c = do_getc(dep_f);
            }
            if (c == '\n') {
                c = do_getc(dep_f);
            }
            continue;
        }
        while (c != EOF && isspace(c)) {
            c = do_getc(dep_f);
        }
        if (c != ':') {
            // not a dependency line
            while (c != EOF && c != '\n') {
                c = do_getc(dep_f);
            }
            if (c == '\n') {
                c = do_getc(dep_f);
            }
            continue;
        }
        c = do_getc(dep_f);

        XCALLOC(d, 1);
        d->lhs = xstrdup(buf);

        while (isspace(c) && c != '\n') {
            c = do_getc(dep_f);
        }
        while (c != EOF && c != '\n') {
            buf_u = 0;
            while (c != EOF && !isspace(c)) {
                if (buf_u + 1 >= buf_a) {
                    buf = xrealloc(buf, buf_a *= 2);
                }
                buf[buf_u++] = c;
                c = do_getc(dep_f);
            }
            buf[buf_u] = 0;
            external_action_dep_add(d, buf);
            while (isspace(c) && c != '\n') {
                c = do_getc(dep_f);
            }
        }
        if (c == '\n') {
            c = do_getc(dep_f);
        }
        // one dependency done
        external_action_deps_add(dd, d);
        d = NULL;
    }

    xfree(buf);
    return 0;
}

/*
  PREFIX = /opt/ejudge
  ${PREFIX}/share/ejudge -- source path

  EJUDGE_LOCAL_DIR = /var/lib/ejudge
  ${EJUDGE_LOCAL_DIR}/bin
  ${EJUDGE_LOCAL_DIR}/obj -- temp dir for compilation
  ${EJUDGE_LOCAL_DIR}/gen -- generated .c, .d, .dd files

  EJUDGE_CONTESTS_HOME_DIR = /home/judges
  ${EJUDGE_CONTESTS_HOME_DIR}/bin
  ${EJUDGE_CONTESTS_HOME_DIR}/obj -- temp dir for compilation
  ${EJUDGE_CONTESTS_HOME_DIR}/gen -- generated .c, .d, .dd files
 */
static int initialized_flag = 0;
static unsigned char *csp_src_path = NULL;
static unsigned char *csp_gen_path = NULL;
static unsigned char *csp_obj_path = NULL;
static unsigned char *csp_bin_path = NULL;
static void
initialize_module(void)
{
    unsigned char prefix[PATH_MAX];
    unsigned char path[PATH_MAX];

    if (initialized_flag) return;

    prefix[0] = 0;
#if defined EJUDGE_PREFIX_DIR
    snprintf(prefix, sizeof(prefix), "%s", EJUDGE_PREFIX_DIR);
#endif
    if (!prefix[0]) {
        // should not get here...
        snprintf(prefix, sizeof(prefix), "%s", "/opt/ejudge");
    }
    snprintf(path, sizeof(path), "%s/share/ejudge", prefix);
    csp_src_path = xstrdup(path);

    prefix[0] = 0;
#if defined EJUDGE_LOCAL_DIR
    snprintf(prefix, sizeof(prefix), "%s", EJUDGE_LOCAL_DIR);
#endif
#if defined EJUDGE_CONTESTS_HOME_DIR
    if (!prefix[0]) {
        snprintf(prefix, sizeof(prefix), "%s", EJUDGE_CONTESTS_HOME_DIR);
    }
#endif
    if (!prefix[0] && getenv("TMPDIR")) {
        snprintf(prefix, sizeof(prefix), "%s", getenv("TMPDIR"));
    }
    if (!prefix[0] && getenv("TEMPDIR")) {
        snprintf(prefix, sizeof(prefix), "%s", getenv("TEMPDIR"));
    }
#if defined P_tmpdir
    if (!prefix[0]) {
        snprintf(prefix, sizeof(prefix), "%s", P_tmpdir);
    }
#endif
    if (!prefix[0]) {
        snprintf(prefix, sizeof(prefix), "%s", "/tmp");
    }

    snprintf(path, sizeof(path), "%s/gen", prefix);
    csp_gen_path = xstrdup(path);
    snprintf(path, sizeof(path), "%s/obj", prefix);
    csp_obj_path = xstrdup(path);
    snprintf(path, sizeof(path), "%s/bin", prefix);
    csp_bin_path = xstrdup(path);

    initialized_flag = 1;
}

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

    if (!initialized_flag) initialize_module();

    if (state && state->action_handler) return state;

    if (!state) {
        XCALLOC(state, 1);
    }
    fix_action(action_buf, sizeof(action_buf), action);
    /*
    if (try_load_action(state, ".", dir, action, name_prefix) >= 0) {
        return state;
    }
    */
    if (try_load_action(state, EJUDGE_LIBEXEC_DIR "/ejudge", dir, action_buf, name_prefix) >= 0) {
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
