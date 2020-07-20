/* -*- c -*- */

/* Copyright (C) 2014-2017 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_process.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

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

#define CHECK_INTERVAL 60

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

ExternalActionDependency *
external_action_deps_find(ExternalActionDependencies *dd, const unsigned char *file)
{
    if (!dd) return NULL;
    for (int i = 0; i < dd->u; ++i) {
        if (!strcmp(dd->v[i]->lhs, file)) {
            return dd->v[i];
        }
    }
    return NULL;
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

typedef struct FileInfo
{
    unsigned char *path;
    time_t check_time;
    time_t mod_time;
} FileInfo;

static int fileinfo_u, fileinfo_a;
static FileInfo **fileinfos;

static FileInfo *
file_info_get(
        const unsigned char *path,
        time_t current_time,
        int force_check)
{
    int i;
    struct stat stb;
    FileInfo *fi = NULL;
    for (i = 0; i < fileinfo_u; ++i) {
        fi = fileinfos[i];
        if (!strcmp(fi->path, path)) {
            if (force_check || fi->check_time + CHECK_INTERVAL <= current_time) {
                fi->check_time = current_time;
                fi->mod_time = 0;
                if (stat(path, &stb) >= 0) {
                    fi->mod_time = stb.st_mtime;
                }
            }
            return fi;
        }
    }
    if (!fileinfos) {
        XCALLOC(fileinfos, fileinfo_a = 16);
    } else if (fileinfo_u == fileinfo_a) {
        XREALLOC(fileinfos, fileinfo_a *= 2);
    }
    XCALLOC(fi, 1);
    fi->path = xstrdup(path);
    fi->check_time = current_time;
    if (stat(path, &stb) >= 0) {
        fi->mod_time = stb.st_mtime;
    }
    fileinfos[fileinfo_u++] = fi;
    return fi;
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

static ExternalActionState *
external_action_state_create(
        const unsigned char *dir,
        const unsigned char *action,
        const unsigned char *fixed_src_dir,
        int contest_id)
{
    ExternalActionState *state = NULL;
    unsigned char path[PATH_MAX];
    unsigned char action_buf[256];

    XCALLOC(state, 1);
    state->package = xstrdup(dir);
    state->contest_id = contest_id;
    state->fixed_src_dir = xstrdup2(fixed_src_dir);

    if (contest_id > 0) {
        snprintf(path, sizeof(path), "%s/%06d/%s", csp_gen_path, contest_id, dir);
        state->gen_dir = xstrdup(path);
        snprintf(path, sizeof(path), "%s/%06d/%s", csp_obj_path, contest_id, dir);
        state->obj_dir = xstrdup(path);
        snprintf(path, sizeof(path), "%s/%06d/%s", csp_bin_path, contest_id, dir);
        state->bin_dir = xstrdup(path);
    } else {
        snprintf(path, sizeof(path), "%s/%s", csp_gen_path, dir);
        state->gen_dir = xstrdup(path);
        snprintf(path, sizeof(path), "%s/%s", csp_obj_path, dir);
        state->obj_dir = xstrdup(path);
        snprintf(path, sizeof(path), "%s/%s", csp_bin_path, dir);
        state->bin_dir = xstrdup(path);
    }

    fix_action(action_buf, sizeof(action_buf), action);
    state->action = xstrdup(action_buf);

    snprintf(path, sizeof(path), "%s/%s.so", state->bin_dir, state->action);
    state->so_path = xstrdup(path);

    return state;
}

void
external_action_state_unload(ExternalActionState *state)
{
    if (state) {
        state->action_handler = NULL;
        if (state->dl_handle) {
            dlclose(state->dl_handle);
            state->dl_handle = NULL;
        }
    }
}

ExternalActionState *
external_action_state_free(ExternalActionState *state)
{
    if (!state || state == EXTERNAL_ACTION_NONE) return NULL;

    external_action_state_unload(state);
    xfree(state->fixed_src_dir);
    xfree(state->package);
    xfree(state->action);
    xfree(state->src_dir);
    xfree(state->gen_dir);
    xfree(state->obj_dir);
    xfree(state->bin_dir);
    xfree(state->so_path);
    xfree(state->err_msg);

    memset(state, 0, sizeof(*state));
    xfree(state);
    return NULL;
}

static int
invoke_page_gen(
        FILE *log_f,
        ExternalActionState *state)
{
    unsigned char arg0[PATH_MAX];
    unsigned char arg2[PATH_MAX];
    unsigned char arg4[PATH_MAX];
    unsigned char arg6[PATH_MAX];
    unsigned char arg7[PATH_MAX];
    char *args[9];
    unsigned char *stderr_text = NULL;

    snprintf(arg0, sizeof(arg0), "%s/ej-page-gen", EJUDGE_SERVER_BIN_PATH);
    args[0] = arg0;
    args[1] = "-x";
    //snprintf(arg2, sizeof(arg2), "%s/ejudge/ej-page-gen.debug", EJUDGE_LIB_DIR);
    snprintf(arg2, sizeof(arg2), "none");
    args[2] = arg2;
    args[3] = "-d";
    snprintf(arg4, sizeof(arg4), "%s/%s.ds", state->gen_dir, state->action);
    args[4] = arg4;
    args[5] = "-o";
    snprintf(arg6, sizeof(arg6), "%s/%s.c", state->gen_dir, state->action);
    args[6] = arg6;
    snprintf(arg7, sizeof(arg7), "%s.csp", state->action);
    args[7] = arg7;
    args[8] = NULL;

    int ret = ejudge_invoke_process(args, NULL, state->src_dir, NULL, NULL, 0, NULL, &stderr_text);
    if (log_f) {
        fprintf(log_f, "ej-page-gen status: %d\n", ret);
        fprintf(log_f, "command line: %s %s %s %s %s %s %s %s\n", args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
        fprintf(log_f, "output:\n");
        fprintf(log_f, "%s\n", stderr_text);
    }
    if (ret != 0) {
        ret = -1;
    }
    xfree(stderr_text);
    return ret;
}

static int
invoke_gcc(
        FILE *log_f,
        ExternalActionState *state,
        int enable_i_c)
{
    unsigned char mfile[PATH_MAX];
    snprintf(mfile, sizeof(mfile), "%s/%s.make", state->gen_dir, state->action);
    FILE *out_m = fopen(mfile, "w");
    fprintf(out_m, "include %s/lib/ejudge/make/csp_header.make\n\n", EJUDGE_PREFIX_DIR);
    fprintf(out_m, "all :\n");
    if (enable_i_c) {
        fprintf(out_m, "\t-rm -f \"I_%s.c\"\n", state->action);
        fprintf(out_m, "\tln -s \"%s/I_%s.c\" \"I_%s.c\"\n", state->src_dir, state->action, state->action);
    }
    fprintf(out_m, "\t$(CC) $(CCOMPFLAGS) ${WPTRSIGN} $(LDFLAGS) -I\"%s\" -MM %s.c", state->src_dir, state->action);
    if (enable_i_c) {
        fprintf(out_m, " I_%s.c", state->action);
    }
    fprintf(out_m, " > %s.dc\n", state->action);
    fprintf(out_m, "\t$(CC) $(CCOMPFLAGS) ${WPTRSIGN} $(LDFLAGS) -I\"%s\" %s.c", state->src_dir, state->action);
    if (enable_i_c) {
        fprintf(out_m, " I_%s.c", state->action);
    }
    fprintf(out_m, " -o %s/%s.so\n", state->obj_dir, state->action);
    fprintf(out_m, "\tmv %s/%s.so %s\n", state->obj_dir, state->action, state->so_path);
    fclose(out_m); out_m = NULL;

    char *args[5];
    unsigned char arg2[PATH_MAX];
    args[0] = "/usr/bin/make";
    args[1] = "-f";
    snprintf(arg2, sizeof(arg2), "%s.make", state->action);
    args[2] = arg2;
    args[3] = "all";
    args[4] = NULL;

    unsigned char *stderr_text = NULL;
    int ret = ejudge_invoke_process(args, NULL, state->gen_dir, NULL, NULL, 0, NULL, &stderr_text);
    if (ret != 0) {
        if (log_f) {
            fprintf(log_f, "compilation failed\n");
            fprintf(log_f, "command line: %s %s %s %s\n", args[0], args[1], args[2], args[3]);
            fprintf(log_f, "output:\n");
            fprintf(log_f, "%s\n", stderr_text);
        }
        ret = -1;
    }
    xfree(stderr_text);
    return ret;
}

static int
update_src_dir(
        FILE *log_f,
        ExternalActionState *state)
{
    unsigned char src_dir[PATH_MAX];
    unsigned char csp_name[PATH_MAX];
    struct stat stb;

    if (state->fixed_src_dir) {
        snprintf(src_dir, sizeof(src_dir), "%s/%s", state->fixed_src_dir, state->package);
        snprintf(csp_name, sizeof(csp_name), "%s/%s.csp", src_dir, state->action);
        if (stat(csp_name, &stb) < 0) {
            fprintf(stderr, "Action file '%s.csp' does not exist in '%s'\n", state->action, src_dir);
            return -1;
        }
    } else {
        snprintf(src_dir, sizeof(src_dir), "%s/%s", EJUDGE_CONTESTS_HOME_DIR, state->package);
        snprintf(csp_name, sizeof(csp_name), "%s/%s.csp", src_dir, state->action);
        if (stat(csp_name, &stb) < 0) {
            snprintf(src_dir, sizeof(src_dir), "%s/%s", csp_src_path, state->package);
            snprintf(csp_name, sizeof(csp_name), "%s/%s.csp", src_dir, state->action);
            if (stat(csp_name, &stb) < 0) {
                fprintf(stderr, "Action file '%s.csp' does not exist neither in '%s/%s' nor in '%s/%s'\n",
                        state->action, EJUDGE_CONTESTS_HOME_DIR, state->package, csp_src_path, state->package);
                return -1;
            }
        }
    }
    if (!S_ISREG(stb.st_mode)) {
        fprintf(stderr, "Action file '%s' is not a regular file\n", csp_name);
        return -1;
    }
    if (access(csp_name, R_OK) < 0) {
        fprintf(stderr, "Action file '%s' is not readable\n", csp_name);
        return -1;
    }

    if (!state->src_dir || strcmp(state->src_dir, src_dir) != 0) {
        xfree(state->src_dir);
        state->src_dir = xstrdup(src_dir);
        return 1;
    }
    return 0;
}

static int
full_recompile(
        FILE *log_f,
        ExternalActionState *state)
{
    unsigned char i_c_name[PATH_MAX];
    int enable_i_c = 0;
    struct stat stb;

    info("Compiling action %s", state->action);

    snprintf(i_c_name, sizeof(i_c_name), "%s/I_%s.c", state->src_dir, state->action);
    if (stat(i_c_name, &stb) < 0) {
    } else if (!S_ISREG(stb.st_mode)) {
        fprintf(log_f, "Support file '%s' is not a regular file\n", i_c_name);
    } else if (access(i_c_name, R_OK) < 0) {
        fprintf(log_f, "Support file '%s' is not readable\n", i_c_name);
    } else {
        enable_i_c = 1;
    }

    int ret = invoke_page_gen(log_f, state);
    if (ret < 0) return ret;
    ret = invoke_gcc(log_f, state, enable_i_c);
    if (ret < 0) return ret;

    return 0;
}

static int
check_so_file(
        FILE *log_f,
        ExternalActionState *state,
        const unsigned char *path)
{
    int retval = 0;
    struct stat stb;
    xfree(state->err_msg);
    state->err_msg = NULL;
    if (lstat(path, &stb) < 0) {
        retval = -errno;
        state->err_msg = xstrdup(strerror(-retval));
    } else if (S_ISLNK(stb.st_mode)) {
        retval = -ELOOP;
        state->err_msg = xstrdup(strerror(-retval));
    } else if (!S_ISREG(stb.st_mode)) {
        retval = -EISDIR;
        state->err_msg = xstrdup(strerror(-retval));
    } else if (access(path, X_OK | R_OK) < 0) {
        retval = -errno;
        state->err_msg = xstrdup(strerror(-retval));
    }
    return retval;
}

static ExternalActionDependencies *external_deps = NULL;

static int
load_ds_file(
        FILE *log_f,
        ExternalActionState *state)
{
    unsigned char path[PATH_MAX];

    if (!external_deps) {
        XCALLOC(external_deps, 1);
    }

    snprintf(path, sizeof(path), "%s/%s.ds", state->gen_dir, state->action);
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(log_f, "Dependency file '%s' does not exist\n", path);
        return -1;
    }
    if (external_action_parse_deps(log_f, f, external_deps) < 0) {
        fprintf(log_f, "Parsing of dependency file '%s' failed\n", path);
        return -1;
    }
    fclose(f); f = NULL;
    return 0;
}

static int
check_deps(
        FILE *log_f,
        ExternalActionState *state,
        time_t current_time)
{
    unsigned char c_file[PATH_MAX];
    snprintf(c_file, sizeof(c_file), "%s.c", state->action);
    ExternalActionDependency *d = external_action_deps_find(external_deps, c_file);
    if (!d) {
        return 1;
    }
    FileInfo *so_info = file_info_get(state->so_path, current_time, 0);
    if (!so_info || so_info->mod_time <= 0) {
        return 1;
    }
    for (int i = 0; i < d->rhs_u; ++i) {
        unsigned char rhs_path[PATH_MAX];
        snprintf(rhs_path, sizeof(rhs_path), "%s/%s", state->src_dir, d->rhs[i]);
        FileInfo *csp_info = file_info_get(rhs_path, current_time, 0);
        if (csp_info && csp_info->mod_time > 0 && csp_info->mod_time > so_info->mod_time) {
            return 1;
        }
    }
    unsigned char i_c_path[PATH_MAX];
    snprintf(i_c_path, sizeof(i_c_path), "%s/I_%s.c", state->src_dir, state->action);
    struct stat stb;
    if (stat(i_c_path, &stb) > 0) {
        FileInfo *i_c_info = file_info_get(i_c_path, current_time, 0);
        if (i_c_info && i_c_info->mod_time > 0 && i_c_info->mod_time > so_info->mod_time) {
            return 1;
        }
    }

    return 0;
}

static int
load_so_file(
        FILE *log_f,
        ExternalActionState *state,
        const unsigned char *name_prefix,
        time_t current_time)
{
    int retval = 0;
    unsigned char func_name[1024];

    xfree(state->err_msg); state->err_msg = NULL;

    state->dl_handle = dlopen(state->so_path, RTLD_LOCAL | RTLD_NOW);
    if (!state->dl_handle) {
        state->err_msg = xstrdup(dlerror());
        retval = -ENOEXEC;
        goto done;
    }

    snprintf(func_name, sizeof(func_name), "%s%s", name_prefix, state->action);
    state->action_handler = dlsym(state->dl_handle, func_name);
    if (!state->action_handler) {
        state->err_msg = xstrdup(dlerror());
        external_action_state_unload(state);
        retval = -ESRCH;
        goto done;
    }

done:
    state->last_check_time = current_time;
    return retval;
}

static int
recompile_and_load(
        FILE *log_f,
        ExternalActionState *state,
        const unsigned char *name_prefix,
        time_t current_time)
{
    int retval = 0;

    xfree(state->err_msg); state->err_msg = NULL;

    if (full_recompile(log_f, state) < 0) {
        state->err_msg = xstrdup("Compilation failed, see log for details");
        retval = -EINVAL;
        goto done;
    }

    if ((retval = check_so_file(log_f, state, state->so_path)) < 0) {
        goto done;
    }

    if (load_ds_file(log_f, state) < 0) {
        state->err_msg = xstrdup("Failed to load .csp dependencies file");
        retval = -EINVAL;
        goto done;
    }

    return load_so_file(log_f, state, name_prefix, current_time);

done:
    state->last_check_time = current_time;
    return retval;
}

static int
first_load(
        FILE *log_f,
        ExternalActionState *state,
        const unsigned char *name_prefix,
        time_t current_time)
{
    struct stat stb;
    if (lstat(state->so_path, &stb) < 0) {
        if (update_src_dir(log_f, state) < 0) {
            state->last_check_time = current_time;
            return -1;
        }
        return recompile_and_load(log_f, state, name_prefix, current_time);
    }

    if (update_src_dir(log_f, state) < 0) {
        return recompile_and_load(log_f, state, name_prefix, current_time);
    }
    if (load_ds_file(log_f, state) < 0) {
        return recompile_and_load(log_f, state, name_prefix, current_time);
    }
    if (check_deps(log_f, state, current_time)) {
        return recompile_and_load(log_f, state, name_prefix, current_time);
    }
    return load_so_file(log_f, state, name_prefix, current_time);
}

static int
check_and_compile_and_load(
        FILE *log_f,
        ExternalActionState *state,
        const unsigned char *name_prefix,
        time_t current_time)
{
    if (!state->action_handler || !state->dl_handle) {
        goto need_compile_and_load;
    }
    if (update_src_dir(stderr, state) != 0) {
        goto need_compile_and_load;
    }
    if (check_deps(stderr, state, current_time)) {
        goto need_compile_and_load;
    }
    return 0;

need_compile_and_load:
    external_action_state_unload(state);
    return recompile_and_load(log_f, state, name_prefix, current_time);
}

ExternalActionState *
external_action_load(
        ExternalActionState *state,
        const unsigned char *dir,
        const unsigned char *action,
        const unsigned char *name_prefix,
        const unsigned char *fixed_src_dir,
        time_t current_time,
        int contest_id,
        int allow_fail)
{
    if (!initialized_flag) initialize_module();

    if (!state) {
        state = external_action_state_create(dir, action, fixed_src_dir, contest_id);
        os_MakeDirPath(state->gen_dir, 0700);
        os_MakeDirPath(state->obj_dir, 0700);
        os_MakeDirPath(state->bin_dir, 0700);

        if (first_load(stderr, state, name_prefix, current_time) < 0) {
            if (allow_fail) {
                return external_action_state_free(state);
            }
            err("page load error: %s", state->err_msg);
        }
        return state;
    }

    if (state->last_check_time > 0 && current_time < state->last_check_time + CHECK_INTERVAL) {
        return state;
    }

    info("Checking dependencies for action %s", state->action);
    if (check_and_compile_and_load(stderr, state, name_prefix, current_time) < 0) {
        err("page load error: %s", state->err_msg);
    }
    state->last_check_time = current_time;
    return state;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
