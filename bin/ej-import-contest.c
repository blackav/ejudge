/* -*- c -*- */

/* Copyright (C) 2012-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_limits.h"
#include "ejudge/version.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/contests.h"
#include "ejudge/fileutl.h"
#include "ejudge/ej_process.h"
#include "ejudge/problem_config.h"
#include "ejudge/build_support.h"
#include "ejudge/super-serve.h"
#include "ejudge/xml_utils.h"
#include "ejudge/super_html.h"
#include "ejudge/prepare.h"
#include "ejudge/meta/problem_config_meta.h"
#include "ejudge/meta/prepare_meta.h"
#include "ejudge/prepare_dflt.h"
#include "ejudge/pathutl.h"
#include "ejudge/ej_import_packet.h"

#include "ejudge/osdeps.h"
#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <printf.h>
#include <pwd.h>

#define PROBLEMS_DIR  "problems"
#define UNZIP_PATH    "/usr/bin/unzip"
#define TAR_PATH      "/bin/tar"
#define PROBLEM_CFG   "problem.cfg"
#define TESTS_DIR     "tests"
#define SOLUTIONS_DIR "solutions"
#define IMPORT_DIR    "import"
#define SERVE_CFG     "serve.cfg"
#define BACKUP_DIR    "backup"
#define CONF_DIR      "conf"
#define ZIP_CONTENT_TYPE "application/zip"

static const unsigned char *progname = NULL;
static FILE *log_f = NULL;
static int exit_code;

static void
fatal(const char *format, ...)
    __attribute__((format(printf, 1, 2), noreturn));
static void
fatal(const char *format, ...)
{
    unsigned char buf[512];
    va_list args;

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    fprintf(stderr, "%s: fatal: %s\n", progname, buf);
    exit(2);
}

static void
fatal2(const char *format, ...)
    __attribute__((format(printf, 1, 2)));
static void
fatal2(const char *format, ...)
{
    unsigned char buf[512];
    va_list args;

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    if (!log_f) log_f = stderr;
    fprintf(stderr, "%s: fatal: %s\n", progname, buf);
    exit_code = 2;
}

static void
error(const char *format, ...)
    __attribute__((format(printf, 1, 2)));
static void
error(const char *format, ...)
{
    unsigned char buf[512];
    va_list args;

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    if (!log_f) log_f = stderr;
    fprintf(log_f, "%s: error: %s\n", progname, buf);
    if (exit_code < 1) exit_code = 1;
}

static void
warning(const char *format, ...)
    __attribute__((format(printf, 1, 2)));
static void
warning(const char *format, ...)
{
    unsigned char buf[512];
    va_list args;

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    if (!log_f) log_f = stderr;
    fprintf(log_f, "%s: warning: %s\n", progname, buf);
}

static void
info(const char *format, ...)
    __attribute__((format(printf, 1, 2)));
static void
info(const char *format, ...)
{
    unsigned char buf[512];
    va_list args;

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    if (!log_f) log_f = stderr;
    fprintf(log_f, "%s: info: %s\n", progname, buf);
}

static void
report_version(void)
    __attribute__((noreturn));
static void
report_version(void)
{
    printf("%s: ejudge version %s compiled %s\n", progname, compile_version, compile_date);
    exit(0);
}

static void
report_help(void)
    __attribute__((noreturn));
static void
report_help(void)
{
    printf("%s: ejudge version %s compiled %s\n", progname, compile_version, compile_date);
    // FIXME: usage
    exit(0);
}

static int
ends_with_nocase(const unsigned char *str, const unsigned char *suffix)
{
    if (!str) str = "";
    if (!suffix) suffix = "";
    int slen = strlen(str);
    int ulen = strlen(suffix);
    return slen >= ulen && !strcasecmp(str +slen - ulen, suffix);
}

static int
is_valid_name(const unsigned char *str)
{
    if (!str || !*str) return 0;
    // starts from letter
    if (!isalpha(*str)) return 0;
    while (*++str) {
        if (isalnum(*str) || *str == '_' || *str == '-' || *str == '.') {
            // ok
        } else {
            return 0;
        }
    }
    return 1;
}

struct problem_info
{
    unsigned char *problem_dir;
    unsigned char *dir_name;
    struct problem_config_section *cfg;
    int is_bad;
    int test_count;
    unsigned char *test_pat;
    unsigned char *corr_pat;
    unsigned char *info_pat;
    unsigned char *tgz_pat;
    unsigned char *tgzdir_pat;
    int prob_id;
};
struct problems_info
{
    struct problem_info *p;
    int u, a;
};

static struct problems_info *
problems_info_create(void)
{
    struct problems_info *pi = NULL;
    XCALLOC(pi, 1);
    return pi;
}
static struct problems_info *
problems_info_free(struct problems_info *pi)
{
    if (pi) {
        for (int i = 0; i < pi->u; ++i) {
            struct problem_info *p = &pi->p[i];
            xfree(p->problem_dir);
            xfree(p->dir_name);
            problem_config_section_free((struct generic_section_config*) p->cfg);
            xfree(p->test_pat);
            xfree(p->corr_pat);
            xfree(p->info_pat);
            xfree(p->tgz_pat);
            xfree(p->tgzdir_pat);
        }
        xfree(pi->p);
        xfree(pi);
    }
    return NULL;
}
static int
problems_info_append(
        struct problems_info *pi,
        const unsigned char *problem_dir,
        const unsigned char *dir_name)
{
    if (pi->u >= pi->a) {
        if (!(pi->a *= 2)) pi->a = 32;
        pi->p = realloc(pi->p, sizeof(pi->p[0]) * pi->a);
    }
    memset(&pi->p[pi->u], 0, sizeof(pi->p[0]));
    pi->p[pi->u].problem_dir = xstrdup(problem_dir);
    pi->p[pi->u].dir_name = xstrdup(dir_name);
    return pi->u++;
}

static int
problem_sort_func(const void *v1, const void *v2)
{
    const struct problem_info *p1 = (const struct problem_info *) v1;
    const struct problem_info *p2 = (const struct problem_info *) v2;
    return strcmp(p1->dir_name, p2->dir_name);
}

static int
count_by_format(const unsigned char *dir, const unsigned char *format)
{
    int serial = 0;
    unsigned char base[PATH_MAX];
    unsigned char path[PATH_MAX];
    while (1) {
        snprintf(base, sizeof(base), format, ++serial);
        snprintf(path, sizeof(path), "%s/%s", dir, base);
        if (access(path, R_OK) < 0) return serial - 1;
    }
}

static int
check_pattern(
        unsigned char *out_pat,
        int out_len,
        const unsigned char *tests_dir,
        const unsigned char *pat,
        unsigned char **sfx,
        const unsigned char *default_sfx,
        const unsigned char *prob_name,
        const unsigned char *var_name,
        const unsigned char *item_name)
{
    if (pat) {
        int printf_arg_types[10];
        int printf_arg_count;
        memset(printf_arg_types, 0, sizeof(printf_arg_types));
        printf_arg_count = parse_printf_format(pat, 10, printf_arg_types);
        if (printf_arg_count != 1 || (printf_arg_types[0] & ~PA_FLAG_MASK) != PA_INT) {
            error("'%s' attribute value ('%s') is invalid in '%s/%s/%s'", var_name, pat, PROBLEMS_DIR, prob_name, PROBLEM_CFG);
            return -1;
        }
        snprintf(out_pat, out_len, "%s", pat);
        xfree(*sfx); *sfx = NULL;
    } else if (*sfx) {
        snprintf(out_pat, out_len, "%%03d%s", *sfx);
    } else {
        *sfx = xstrdup(default_sfx);
        snprintf(out_pat, out_len, "%%03d%s", *sfx);
    }
    int count = count_by_format(tests_dir, out_pat);
    if (count <= 0) {
        error("no %s for problem '%s'", item_name, prob_name);
        return -1;
    }
    return count;
}

static int
check_checker(
        int require_flag,
        const unsigned char *cmd,
        const unsigned char *problem_dir,
        const unsigned char *var_name,
        const unsigned char *rel_path,
        const unsigned char *prob_name,
        const unsigned char *name)
{
    if (require_flag && !cmd) {
        error("'%s' attribute value is undefined in '%s'", var_name, rel_path);
        return -1;
    }
    if (!cmd) return 0;

    if (strchr(cmd, '/')) {
        error("'%s' attribute value ('%s') is invalid in '%s'", var_name, cmd, rel_path);
        return -1;
    }
    unsigned char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", problem_dir, cmd);
    int count = 0;
    unsigned mask = build_guess_language_by_cmd(path, &count);
    struct stat stb;
    if (count <= 0) {
        if (stat(path, &stb) >= 0 && S_ISREG(stb.st_mode) && access(path, R_OK | X_OK)) {
            warning("no source code in one of supported languages is provided for %s '%s' in '%s'",
                    name, cmd, rel_path);
            warning("executable file will be used without recompilation");
        } else {
            error("no source code in one of supported languages is provided for %s '%s' in '%s'",
                  name, cmd, rel_path);
            return -1;
        }
    } else if (count > 1) {
        error("cannot determine source language for %s '%s' in '%s': several possible source files exist",
              name, cmd, rel_path);
        return -1;
    } else {
        info("%s language is '%s' for problem '%s'", name, build_get_source_suffix(mask), prob_name);
    }
    return 0;
}

static void
copy_bool(struct section_problem_data *p,
          const struct section_problem_data *a,     // abstract problem
          const struct problem_config_section *c,
          int p_name,                               // CNTSPROB field tag
          int c_name)                               // PROBLEM_CONFIG field tag
{
    /* 'b' : ejbytebool_t, 'B' : ejintbool_t, 'f' : ejbyteflag_t */
    int c_type = meta_problem_config_section_get_type(c_name);
    int c_size = meta_problem_config_section_get_size(c_name);
    (void) c_size;
    const void *c_ptr = meta_problem_config_section_get_ptr(c, c_name);
    int c_value = 0;
    if (c_type == 'b') {
        ASSERT(c_size == 1);
        c_value = *(const ejbytebool_t *) c_ptr;
    } else if (c_type == 'B') {
        ASSERT(c_size == 4);
        c_value = *(const ejintbool_t *) c_ptr;
    } else if (c_type == 'f') {
        ASSERT(c_size == 1);
        c_value = *(const ejbyteflag_t *) c_ptr;
    } else {
        error("unsupported field type '%c'", c_type);
        return;
    }
    //if (c_value < 0) c_value = -1;
    if (c_value < 0) c_value = 0;
    if (c_value > 0) c_value = 1;

    int p_type = cntsprob_get_type(p_name);
    int p_size = cntsprob_get_size(p_name);
    (void) p_size; // only used in ASSERT
    int a_value = 0;
    if (a) {
        const void *a_ptr = cntsprob_get_ptr(a, p_name);
        if (p_type == 'b') {
            ASSERT(p_size == 1);
            a_value = *(const ejbytebool_t *) a_ptr;
        } else if (p_type == 'B') {
            ASSERT(p_size == 4);
            a_value = *(const ejintbool_t *) a_ptr;
        } else if (p_type == 'f') {
            ASSERT(p_size == 1);
            a_value = *(const ejbyteflag_t *) a_ptr;
        } else {
            error("unsupported field type '%c'", p_type);
            return;
        }
        //if (a_value < 0) a_value = -1;
        if (a_value < 0) a_value = 0;
        if (a_value > 0) a_value = 1;
    }

    int p_value = 0; // the resulting value
    void *p_ptr = cntsprob_get_ptr_nc(p, p_name);
    if (c_value > 0) {
        if (a && a_value > 0) {
            p_value = -1;
        } else {
            p_value = 1;
        }
    } else {
        if (a && a_value <= 0) {
            p_value = -1;
        } else {
            p_value = 0;
        }
    }

    if (p_type == 'b') {
        ASSERT(p_size == 1);
        * (ejbytebool_t *) p_ptr = c_value;
    } else if (p_type == 'B') {
        ASSERT(p_size == 4);
        * (ejintbool_t *) p_ptr = p_value;
    } else if (p_type == 'f') {
        ASSERT(p_size == 1);
        * (ejbyteflag_t *) p_ptr = p_value;
    } else {
        error("unsupported field type '%c'", p_type);
        return;
    }
}

static void
copy_int(struct section_problem_data *p,
         const struct section_problem_data *a,
         const struct problem_config_section *c,
         int p_name,
         int c_name,
         int p_default)
{
    const int *cv = (const int *) meta_problem_config_section_get_ptr(c, c_name);
    const int *av = NULL;
    if (a) {
        av = (const int *) cntsprob_get_ptr(a, p_name);
    }
    int *pv = (int *) cntsprob_get_ptr_nc(p, p_name);
    if (*cv >= 0) {
        // value set
        if (av && *av >= 0 && *av == *cv) {
            *pv = -1; // inherited from the abstract problem
        } else {
            *pv = *cv;
        }
    } else {
        // value unset
        if (av && *av >= 0 && *av != p_default) {
            *pv = p_default; // set to the default value
        } else {
            *pv = -1; // inherited value is ok
        }
    }
}

static void
copy_size(struct section_problem_data *p,
          const struct section_problem_data *a,
          const struct problem_config_section *c,
          int p_name,
          int c_name)
{
    const size_t *cv = (const size_t*) meta_problem_config_section_get_ptr(c, c_name);
    const size_t *av = NULL;
    if (a) {
        av = (const size_t*) cntsprob_get_ptr(a, p_name);
    }
    size_t *pv = (size_t*) cntsprob_get_ptr_nc(p, p_name);
    if (*cv && *cv != (size_t) -1L) {
        // value set
        if (av && *cv == *av) {
            *pv = -1L;
        } else {
            *pv = *cv;
        }
    } else {
        // value unset
        if (av && *av && *av != (size_t) -1L) {
            *pv = 0L;
        } else {
            *pv = -1L;
        }
    }
}

static void
copy_string(struct section_problem_data *p,
            const struct section_problem_data *a,
            const struct problem_config_section *c,
            int p_name,
            int c_name)
{
    int ct = meta_problem_config_section_get_type(c_name);
    ASSERT(ct == 's');
    (void) ct;
    unsigned char *cv = *(unsigned char**) meta_problem_config_section_get_ptr(c, c_name);
    int pt = cntsprob_get_type(p_name);
    ASSERT(pt == 's' || pt == 'S');
    (void) pt;
    if (pt == 'S') {
        // fixed-length string
        size_t z = cntsprob_get_size(p_name);
        unsigned char *pv = (unsigned char *) cntsprob_get_ptr_nc(p, p_name);
        const unsigned char *av = NULL;
        if (a) {
            av = (const unsigned char*) cntsprob_get_ptr(a, p_name);
        }
        if (cv) {
            if (a && av && av[0] != 1 && !strcmp(av, cv)) {
                pv[0] = 1; // undefined value
                pv[1] = 0;
            } else {
                snprintf(pv, z, "%s", cv);
            }
        } else {
            if (a && av && av[0] != 1) {
                pv[0] = 0;
            } else {
                pv[0] = 1;
                pv[1] = 0;
            }
        }
    } else {
        // string pointer
        unsigned char **ppv = (unsigned char **) cntsprob_get_ptr_nc(p, p_name);
        const unsigned char *av = NULL;
        if (a) {
            av = *(const unsigned char **) cntsprob_get_ptr(a, p_name);
        }
        if (cv) {
            if (a && av && !strcmp(av, cv)) {
                xfree(*ppv); *ppv = NULL;
            } else {
                xfree(*ppv); *ppv = xstrdup(cv);
            }
        } else {
            if (a && av) {
                xfree(*ppv); *ppv = xstrdup("");
            } else {
                xfree(*ppv); *ppv = NULL;
            }
        }
    }
}

static int
cntsprob_get_bool(
        const struct section_problem_data *p,
        int f_name)
{
    /* 'b' : ejbytebool_t, 'B' : ejintbool_t, 'f' : ejbyteflag_t */
    int f_type = cntsprob_get_type(f_name);
    int f_size = cntsprob_get_size(f_name);
    (void) f_size;
    const void *f_ptr = cntsprob_get_ptr(p, f_name);
    int value = 0;

    if (f_type == 'b') {
        ASSERT(f_size == 1);
        value = *(const ejbytebool_t *) f_ptr;
    } else if (f_type == 'B') {
        ASSERT(f_size == 4);
        value = *(const ejintbool_t *) f_ptr;
    } else if (f_type == 'f') {
        ASSERT(f_size == 1);
        value = *(const ejbyteflag_t *) f_ptr;
    } else {
        abort();
    }

    if (value < 0) value = -1;
    if (value > 1) value = 1;
    return value;
}

static const unsigned char *
cntsprob_get_string(
        const struct section_problem_data *p,
        int f_name)
{
    int f_type = cntsprob_get_type(f_name);
    (void) f_type;
    ASSERT(f_type == 's');
    return *(const unsigned char **) cntsprob_get_ptr(p, f_name);
}

static void
cntsprob_set_string(
        struct section_problem_data *p,
        int f_name,
        const unsigned char *str)
{
    int f_type = cntsprob_get_type(f_name);
    (void) f_type;
    ASSERT(f_type == 's');
    unsigned char *dst = NULL;
    if (str) dst = xstrdup(str);
    * (unsigned char **) cntsprob_get_ptr_nc(p, f_name) = dst;
}

static const unsigned char *
problem_config_section_get_string(
        const struct problem_config_section *c,
        int f_name)
{
    int f_type = meta_problem_config_section_get_type(f_name);
    (void) f_type;
    ASSERT(f_type == 's');
    return *(const unsigned char **) meta_problem_config_section_get_ptr(c, f_name);
}

static void
copy_suffix(
        struct section_problem_data *p,
        const struct section_problem_data *a,
        const struct problem_config_section *c,
        int pf_name,        // CNTSPROB use flag tag
        int ps_name,        // CNTSPROB suffix tag
        int pp_name,        // CNTSPROB pattern tag
        int cs_name,        // problem config suffix tag
        int cp_name)        // problem config pattern tag
{
    const unsigned char *c_suf = problem_config_section_get_string(c, cs_name);
    const unsigned char *c_pat = problem_config_section_get_string(c, cp_name);
    if (a) {
        int p_has = 1;
        int a_has = 1;
        if (pf_name > 0) {
            p_has = cntsprob_get_bool(p, pf_name);
            a_has = cntsprob_get_bool(a, pf_name);
        }
        if (p_has < 0) p_has = a_has;
        if (p_has < 0) p_has = 0;
        if (a_has < 0) a_has = 0;
        if (p_has && a_has) {
            const unsigned char *a_suf = cntsprob_get_string(a, ps_name);
            const unsigned char *a_pat = cntsprob_get_string(a, pp_name);
            if (c_suf && a_suf && !strcmp(c_suf, a_suf)) {
                // do nothing
            } else {
                cntsprob_set_string(p, ps_name, c_suf);
            }
            if (c_pat && a_pat && !strcmp(c_pat, a_pat)) {
                // do nothing
            } else {
                cntsprob_set_string(p, pp_name, c_pat);
            }
        } else if (p_has) {
            cntsprob_set_string(p, ps_name, c_suf);
            cntsprob_set_string(p, pp_name, c_pat);
        }
    } else {
        int p_has = 1;
        if (pf_name > 0) {
            p_has = cntsprob_get_bool(p, pf_name);
        }
        if (p_has < 0) p_has = 0;
        if (p_has) {
            cntsprob_set_string(p, ps_name, c_suf);
            cntsprob_set_string(p, pp_name, c_pat);
        }
    }
}

static void
copy_strarray(
        struct section_problem_data *p,
        const struct section_problem_data *a,
        const struct problem_config_section *c,
        int p_name,
        int c_name)
{
    int t = meta_problem_config_section_get_type(c_name);
    ASSERT(t == 'x' || t == 'X');
    t = cntsprob_get_type(p_name);
    ASSERT(t == 'x' || t == 'X');
    (void) t;
    char ***cv = (char ***) meta_problem_config_section_get_ptr(c, c_name);
    char ***pv = (char ***) cntsprob_get_ptr_nc(p, p_name);
    if (*cv) {
        sarray_free(*pv); *pv = sarray_copy(*cv);
    } else {
        sarray_free(*pv); *pv = NULL;
    }
}

static void
merge_problem_section(
        const struct ejudge_cfg *ejudge_config,
        struct section_problem_data *p,
        const struct section_problem_data *a,
        const struct problem_config_section *c)
{
    static const int bools_list[][2] =
    {
        { CNTSPROB_manual_checking, META_PROBLEM_CONFIG_SECTION_manual_checking },
        { CNTSPROB_check_presentation, META_PROBLEM_CONFIG_SECTION_check_presentation },
        { CNTSPROB_scoring_checker, META_PROBLEM_CONFIG_SECTION_scoring_checker },
        { CNTSPROB_enable_checker_token, META_PROBLEM_CONFIG_SECTION_enable_checker_token },
        { CNTSPROB_interactive_valuer, META_PROBLEM_CONFIG_SECTION_interactive_valuer },
        { CNTSPROB_disable_pe, META_PROBLEM_CONFIG_SECTION_disable_pe },
        { CNTSPROB_disable_wtl, META_PROBLEM_CONFIG_SECTION_disable_wtl },
        { CNTSPROB_wtl_is_cf, META_PROBLEM_CONFIG_SECTION_wtl_is_cf },
        { CNTSPROB_use_stdin, META_PROBLEM_CONFIG_SECTION_use_stdin },
        { CNTSPROB_use_stdout, META_PROBLEM_CONFIG_SECTION_use_stdout },
        { CNTSPROB_combined_stdin, META_PROBLEM_CONFIG_SECTION_combined_stdin },
        { CNTSPROB_combined_stdout, META_PROBLEM_CONFIG_SECTION_combined_stdout },
        { CNTSPROB_binary_input, META_PROBLEM_CONFIG_SECTION_binary_input },
        { CNTSPROB_binary, META_PROBLEM_CONFIG_SECTION_binary },
        { CNTSPROB_ignore_exit_code, META_PROBLEM_CONFIG_SECTION_ignore_exit_code },
        { CNTSPROB_ignore_term_signal, META_PROBLEM_CONFIG_SECTION_ignore_term_signal },
        { CNTSPROB_olympiad_mode, META_PROBLEM_CONFIG_SECTION_olympiad_mode },
        { CNTSPROB_score_latest, META_PROBLEM_CONFIG_SECTION_score_latest },
        { CNTSPROB_score_latest_or_unmarked, META_PROBLEM_CONFIG_SECTION_score_latest_or_unmarked },
        { CNTSPROB_score_latest_marked, META_PROBLEM_CONFIG_SECTION_score_latest_marked },
        { CNTSPROB_score_tokenized, META_PROBLEM_CONFIG_SECTION_score_tokenized },
        { CNTSPROB_use_ac_not_ok, META_PROBLEM_CONFIG_SECTION_use_ac_not_ok },
        { CNTSPROB_ignore_prev_ac, META_PROBLEM_CONFIG_SECTION_ignore_prev_ac },
        { CNTSPROB_team_enable_rep_view, META_PROBLEM_CONFIG_SECTION_team_enable_rep_view },
        { CNTSPROB_team_enable_ce_view, META_PROBLEM_CONFIG_SECTION_team_enable_ce_view },
        { CNTSPROB_team_show_judge_report, META_PROBLEM_CONFIG_SECTION_team_show_judge_report },
        { CNTSPROB_show_checker_comment, META_PROBLEM_CONFIG_SECTION_show_checker_comment },
        { CNTSPROB_ignore_compile_errors, META_PROBLEM_CONFIG_SECTION_ignore_compile_errors },
        { CNTSPROB_variable_full_score, META_PROBLEM_CONFIG_SECTION_variable_full_score },
        { CNTSPROB_ignore_penalty, META_PROBLEM_CONFIG_SECTION_ignore_penalty },
        { CNTSPROB_use_corr, META_PROBLEM_CONFIG_SECTION_use_corr },
        { CNTSPROB_use_info, META_PROBLEM_CONFIG_SECTION_use_info },
        { CNTSPROB_use_tgz, META_PROBLEM_CONFIG_SECTION_use_tgz },
        { CNTSPROB_accept_partial, META_PROBLEM_CONFIG_SECTION_accept_partial },
        { CNTSPROB_disable_user_submit, META_PROBLEM_CONFIG_SECTION_disable_user_submit },
        { CNTSPROB_disable_tab, META_PROBLEM_CONFIG_SECTION_disable_tab },
        { CNTSPROB_unrestricted_statement, META_PROBLEM_CONFIG_SECTION_unrestricted_statement },
        { CNTSPROB_statement_ignore_ip, META_PROBLEM_CONFIG_SECTION_statement_ignore_ip },
        { CNTSPROB_enable_submit_after_reject, META_PROBLEM_CONFIG_SECTION_enable_submit_after_reject },
        { CNTSPROB_hide_file_names, META_PROBLEM_CONFIG_SECTION_hide_file_names },
        { CNTSPROB_hide_real_time_limit, META_PROBLEM_CONFIG_SECTION_hide_real_time_limit },
        { CNTSPROB_enable_tokens, META_PROBLEM_CONFIG_SECTION_enable_tokens },
        { CNTSPROB_tokens_for_user_ac, META_PROBLEM_CONFIG_SECTION_tokens_for_user_ac },
        { CNTSPROB_disable_submit_after_ok, META_PROBLEM_CONFIG_SECTION_disable_submit_after_ok },
        { CNTSPROB_disable_auto_testing, META_PROBLEM_CONFIG_SECTION_disable_auto_testing },
        { CNTSPROB_disable_testing, META_PROBLEM_CONFIG_SECTION_disable_testing },
        { CNTSPROB_enable_compilation, META_PROBLEM_CONFIG_SECTION_enable_compilation },
        { CNTSPROB_skip_testing, META_PROBLEM_CONFIG_SECTION_skip_testing },
        { CNTSPROB_hidden, META_PROBLEM_CONFIG_SECTION_hidden },
        { CNTSPROB_stand_hide_time, META_PROBLEM_CONFIG_SECTION_stand_hide_time },
        { CNTSPROB_advance_to_next, META_PROBLEM_CONFIG_SECTION_advance_to_next },
        { CNTSPROB_disable_ctrl_chars, META_PROBLEM_CONFIG_SECTION_disable_ctrl_chars },
        { CNTSPROB_enable_text_form, META_PROBLEM_CONFIG_SECTION_enable_text_form },
        { CNTSPROB_stand_ignore_score, META_PROBLEM_CONFIG_SECTION_stand_ignore_score },
        { CNTSPROB_stand_last_column, META_PROBLEM_CONFIG_SECTION_stand_last_column },
        { CNTSPROB_disable_security, META_PROBLEM_CONFIG_SECTION_disable_security },
        { CNTSPROB_enable_suid_run, META_PROBLEM_CONFIG_SECTION_enable_suid_run },
        { CNTSPROB_enable_container, META_PROBLEM_CONFIG_SECTION_enable_container },
        { CNTSPROB_enable_multi_header, META_PROBLEM_CONFIG_SECTION_enable_multi_header },
        { CNTSPROB_use_lang_multi_header, META_PROBLEM_CONFIG_SECTION_use_lang_multi_header },
        { CNTSPROB_require_any, META_PROBLEM_CONFIG_SECTION_require_any },
        { CNTSPROB_valuer_sets_marked, META_PROBLEM_CONFIG_SECTION_valuer_sets_marked },
        { CNTSPROB_ignore_unmarked, META_PROBLEM_CONFIG_SECTION_ignore_unmarked },
        { CNTSPROB_disable_stderr, META_PROBLEM_CONFIG_SECTION_disable_stderr },
        { CNTSPROB_enable_process_group, META_PROBLEM_CONFIG_SECTION_enable_process_group },
        { CNTSPROB_enable_kill_all, META_PROBLEM_CONFIG_SECTION_enable_kill_all },
        { CNTSPROB_hide_variant, META_PROBLEM_CONFIG_SECTION_hide_variant },
        { CNTSPROB_enable_testlib_mode, META_PROBLEM_CONFIG_SECTION_enable_testlib_mode },

        { 0, 0 },
    };

    for (int i = 0; bools_list[i][0] > 0; ++i) {
        copy_bool(p, a, c, bools_list[i][0], bools_list[i][1]);
    }

    static const int ints_list[][3] =
    {
        { CNTSPROB_real_time_limit, META_PROBLEM_CONFIG_SECTION_real_time_limit, 0 },
        { CNTSPROB_full_score, META_PROBLEM_CONFIG_SECTION_full_score, 0 },
        { CNTSPROB_full_user_score, META_PROBLEM_CONFIG_SECTION_full_user_score, 0 },
        { CNTSPROB_min_score_1, META_PROBLEM_CONFIG_SECTION_min_score_1, 0 },
        { CNTSPROB_min_score_2, META_PROBLEM_CONFIG_SECTION_min_score_2, 0 },
        { CNTSPROB_test_score, META_PROBLEM_CONFIG_SECTION_test_score, 0 },
        { CNTSPROB_run_penalty, META_PROBLEM_CONFIG_SECTION_run_penalty, 0 },
        { CNTSPROB_acm_run_penalty, META_PROBLEM_CONFIG_SECTION_acm_run_penalty, DFLT_P_ACM_RUN_PENALTY },
        { CNTSPROB_disqualified_penalty, META_PROBLEM_CONFIG_SECTION_disqualified_penalty, 0 },
        { CNTSPROB_min_tests_to_accept, META_PROBLEM_CONFIG_SECTION_min_tests_to_accept, 0 },
        { CNTSPROB_tests_to_accept, META_PROBLEM_CONFIG_SECTION_tests_to_accept, 0 },
        { CNTSPROB_checker_real_time_limit, META_PROBLEM_CONFIG_SECTION_checker_real_time_limit, 0 },
        { CNTSPROB_checker_time_limit_ms, META_PROBLEM_CONFIG_SECTION_checker_time_limit_ms, 0 },
        { CNTSPROB_score_multiplier, META_PROBLEM_CONFIG_SECTION_score_multiplier, 0 },
        { CNTSPROB_prev_runs_to_show, META_PROBLEM_CONFIG_SECTION_prev_runs_to_show, 0 },
        { CNTSPROB_max_user_run_count, META_PROBLEM_CONFIG_SECTION_max_user_run_count, 0 },
        { CNTSPROB_interactor_time_limit, META_PROBLEM_CONFIG_SECTION_interactor_time_limit, 0 },
        { CNTSPROB_interactor_real_time_limit, META_PROBLEM_CONFIG_SECTION_interactor_real_time_limit, 0 },
        { CNTSPROB_max_open_file_count, META_PROBLEM_CONFIG_SECTION_max_open_file_count, 0 },
        { CNTSPROB_max_process_count, META_PROBLEM_CONFIG_SECTION_max_process_count, 0 },

        { 0, 0, 0 },
    };

    for (int i = 0; ints_list[i][0] > 0; ++i) {
        copy_int(p, a, c, ints_list[i][0], ints_list[i][1], ints_list[i][2]);
    }

    // NOT YET SUPPORTED
    /*
  int priority_adjustment;
     */

    long atl = -1;
    long ctl = -1;
    if (a) {
        if (a->time_limit_millis > 0) {
            atl = a->time_limit_millis;
        } else if (a->time_limit > 0) {
            atl = a->time_limit * 1000;
        }
    }
    if (c->time_limit_millis > 0) {
        ctl = c->time_limit_millis;
    } else if (c->time_limit > 0) {
        ctl = c->time_limit * 1000;
    }
    if (ctl > 0) {
        if (atl > 0 && atl == ctl) {
            p->time_limit_millis = -1;
            p->time_limit = -1;
        } else {
            if (!(ctl % 1000)) {
                p->time_limit = ctl / 1000;
                p->time_limit_millis = -1;
            } else {
                p->time_limit = -1;
                p->time_limit_millis = ctl;
            }
        }
    } else {
        if (atl > 0) {
            p->time_limit = 0;
            p->time_limit_millis = 0;
        } else {
            p->time_limit = -1;
            p->time_limit_millis = -1;
        }
    }

    // NOT YET SUPPORTED
    /*
  time_t deadline;
  time_t start_date;
    */

    static const int sizes_list[][2] =
    {
        { CNTSPROB_max_vm_size, META_PROBLEM_CONFIG_SECTION_max_vm_size },
        { CNTSPROB_max_data_size, META_PROBLEM_CONFIG_SECTION_max_data_size },
        { CNTSPROB_max_stack_size, META_PROBLEM_CONFIG_SECTION_max_stack_size },
        { CNTSPROB_max_core_size, META_PROBLEM_CONFIG_SECTION_max_core_size },
        { CNTSPROB_max_file_size, META_PROBLEM_CONFIG_SECTION_max_file_size },
        { CNTSPROB_checker_max_vm_size, META_PROBLEM_CONFIG_SECTION_checker_max_vm_size },
        { CNTSPROB_checker_max_stack_size, META_PROBLEM_CONFIG_SECTION_checker_max_stack_size },
        { CNTSPROB_checker_max_rss_size, META_PROBLEM_CONFIG_SECTION_checker_max_rss_size },

        { 0, 0 },
    };
    for (int i = 0; sizes_list[i][0] > 0; ++i) {
        copy_size(p, a, c, sizes_list[i][0], sizes_list[i][1]);
    }

    if (c->long_name) {
        xstrdup3(&p->long_name, c->long_name);
    } else {
        p->long_name = NULL;
    }
    if (c->stand_name) {
        xstrdup3(&p->stand_name, c->stand_name);
    } else {
        p->stand_name = NULL;
    }
    if (c->internal_name) {
        xstrdup3(&p->internal_name, c->internal_name);
    } else {
        p->internal_name = NULL;
    }
    if (c->extid && c->extid[0]) {
        xfree(p->extid); p->extid = xstrdup(c->extid);
    } else {
        xfree(p->extid); p->extid = NULL;
    }

    static const int strings_list[][2] =
    {
        { CNTSPROB_input_file, META_PROBLEM_CONFIG_SECTION_input_file },
        { CNTSPROB_output_file, META_PROBLEM_CONFIG_SECTION_output_file },
        { CNTSPROB_test_score_list, META_PROBLEM_CONFIG_SECTION_test_score_list },
        { CNTSPROB_score_tests, META_PROBLEM_CONFIG_SECTION_score_tests },
        { CNTSPROB_spelling, META_PROBLEM_CONFIG_SECTION_spelling },
        { CNTSPROB_plugin_file, META_PROBLEM_CONFIG_SECTION_plugin_file },
        { CNTSPROB_xml_file, META_PROBLEM_CONFIG_SECTION_xml_file },
        { CNTSPROB_stand_attr, META_PROBLEM_CONFIG_SECTION_stand_attr },
        { CNTSPROB_source_header, META_PROBLEM_CONFIG_SECTION_source_header },
        { CNTSPROB_source_footer, META_PROBLEM_CONFIG_SECTION_source_footer },
        { CNTSPROB_normalization, META_PROBLEM_CONFIG_SECTION_normalization },
        { CNTSPROB_check_cmd, META_PROBLEM_CONFIG_SECTION_check_cmd },
        { CNTSPROB_valuer_cmd, META_PROBLEM_CONFIG_SECTION_valuer_cmd },
        { CNTSPROB_interactor_cmd, META_PROBLEM_CONFIG_SECTION_interactor_cmd },
        { CNTSPROB_style_checker_cmd, META_PROBLEM_CONFIG_SECTION_style_checker_cmd },
        { CNTSPROB_test_checker_cmd, META_PROBLEM_CONFIG_SECTION_test_checker_cmd },
        { CNTSPROB_init_cmd, META_PROBLEM_CONFIG_SECTION_init_cmd },
        { CNTSPROB_start_cmd, META_PROBLEM_CONFIG_SECTION_start_cmd },
        { CNTSPROB_solution_src, META_PROBLEM_CONFIG_SECTION_solution_src },
        { CNTSPROB_solution_cmd, META_PROBLEM_CONFIG_SECTION_solution_cmd },
        { CNTSPROB_score_bonus, META_PROBLEM_CONFIG_SECTION_score_bonus },
        { CNTSPROB_open_tests, META_PROBLEM_CONFIG_SECTION_open_tests },
        { CNTSPROB_final_open_tests, META_PROBLEM_CONFIG_SECTION_final_open_tests },
        { CNTSPROB_token_open_tests, META_PROBLEM_CONFIG_SECTION_token_open_tests },
        { CNTSPROB_standard_checker, META_PROBLEM_CONFIG_SECTION_standard_checker },
        { CNTSPROB_tokens, META_PROBLEM_CONFIG_SECTION_tokens },
        { CNTSPROB_umask, META_PROBLEM_CONFIG_SECTION_umask },
        { CNTSPROB_ok_status, META_PROBLEM_CONFIG_SECTION_ok_status },
        { CNTSPROB_header_pat, META_PROBLEM_CONFIG_SECTION_header_pat },
        { CNTSPROB_footer_pat, META_PROBLEM_CONFIG_SECTION_footer_pat },
        { CNTSPROB_compiler_env_pat, META_PROBLEM_CONFIG_SECTION_compiler_env_pat },
        { CNTSPROB_container_options, META_PROBLEM_CONFIG_SECTION_container_options },

        { 0, 0 },
    };

    for (int i = 0; strings_list[i][0] > 0; ++i) {
        copy_string(p, a, c, strings_list[i][0], strings_list[i][1]);
    }

    static const int suffixes_list[][5] =
    {
        { 0, CNTSPROB_test_sfx, CNTSPROB_test_pat, META_PROBLEM_CONFIG_SECTION_test_sfx, META_PROBLEM_CONFIG_SECTION_test_pat },
        { CNTSPROB_use_corr, CNTSPROB_corr_sfx, CNTSPROB_corr_pat, META_PROBLEM_CONFIG_SECTION_corr_sfx, META_PROBLEM_CONFIG_SECTION_corr_pat },
        { CNTSPROB_use_info, CNTSPROB_info_sfx, CNTSPROB_info_pat, META_PROBLEM_CONFIG_SECTION_info_sfx, META_PROBLEM_CONFIG_SECTION_info_pat },
        { CNTSPROB_use_tgz, CNTSPROB_tgz_sfx, CNTSPROB_tgz_pat, META_PROBLEM_CONFIG_SECTION_tgz_sfx, META_PROBLEM_CONFIG_SECTION_tgz_pat },
        { CNTSPROB_use_tgz, CNTSPROB_tgzdir_sfx, CNTSPROB_tgzdir_pat, META_PROBLEM_CONFIG_SECTION_tgzdir_sfx, META_PROBLEM_CONFIG_SECTION_tgzdir_pat },

        { 0, 0, 0, 0, 0 },
    };

    for (int i = 0; suffixes_list[i][1] > 0; ++i) {
        copy_suffix(p, a, c, suffixes_list[i][0], suffixes_list[i][1], suffixes_list[i][2], suffixes_list[i][3], suffixes_list[i][4]);
    }

  /* unsupported:
  unsigned char *type;
  unsigned char *short_name;
  unsigned char *test_dir;
  */

    /* problem.cfg specific
  unsigned char *long_name_en;
  unsigned char *revision;
     */

    static const int strarrays_list[][2] =
    {
        { CNTSPROB_test_sets, META_PROBLEM_CONFIG_SECTION_test_sets },
        { CNTSPROB_date_penalty, META_PROBLEM_CONFIG_SECTION_date_penalty },
        { CNTSPROB_group_start_date, META_PROBLEM_CONFIG_SECTION_group_start_date },
        { CNTSPROB_group_deadline, META_PROBLEM_CONFIG_SECTION_group_deadline },
        { CNTSPROB_disable_language, META_PROBLEM_CONFIG_SECTION_disable_language },
        { CNTSPROB_enable_language, META_PROBLEM_CONFIG_SECTION_enable_language },
        { CNTSPROB_require, META_PROBLEM_CONFIG_SECTION_require },
        { CNTSPROB_lang_time_adj, META_PROBLEM_CONFIG_SECTION_lang_time_adj },
        { CNTSPROB_lang_time_adj_millis, META_PROBLEM_CONFIG_SECTION_lang_time_adj_millis },
        { CNTSPROB_lang_max_vm_size, META_PROBLEM_CONFIG_SECTION_lang_max_vm_size },
        { CNTSPROB_lang_max_stack_size, META_PROBLEM_CONFIG_SECTION_lang_max_stack_size },
        { CNTSPROB_personal_deadline, META_PROBLEM_CONFIG_SECTION_personal_deadline },
        { CNTSPROB_score_view, META_PROBLEM_CONFIG_SECTION_score_view },
        { CNTSPROB_score_view_text, META_PROBLEM_CONFIG_SECTION_score_view_text },

        { CNTSPROB_lang_compiler_env, META_PROBLEM_CONFIG_SECTION_lang_compiler_env },
        { CNTSPROB_lang_compiler_container_options, META_PROBLEM_CONFIG_SECTION_lang_compiler_container_options },
        { CNTSPROB_checker_env, META_PROBLEM_CONFIG_SECTION_checker_env },
        { CNTSPROB_valuer_env, META_PROBLEM_CONFIG_SECTION_valuer_env },
        { CNTSPROB_interactor_env, META_PROBLEM_CONFIG_SECTION_interactor_env },
        { CNTSPROB_style_checker_env, META_PROBLEM_CONFIG_SECTION_style_checker_env },
        { CNTSPROB_test_checker_env, META_PROBLEM_CONFIG_SECTION_test_checker_env },
        { CNTSPROB_init_env, META_PROBLEM_CONFIG_SECTION_init_env },
        { CNTSPROB_start_env, META_PROBLEM_CONFIG_SECTION_start_env },
        { CNTSPROB_statement_env, META_PROBLEM_CONFIG_SECTION_statement_env },

        { 0,  0 },
    };

    for (int i = 0; strarrays_list[i][0] > 0; ++i) {
        copy_strarray(p, a, c, strarrays_list[i][0], strarrays_list[i][1]);
    }
}

static void
generate_makefile(struct sid_state *ss,
                  const struct contest_desc *cnts,
                  struct section_problem_data *prob)
{
    struct section_problem_data *abstr = NULL;
    struct section_global_data *global = ss->global;

    if (/*prob->super &&*/ prob->super[0] && prob->super[0] != 1) {
        for (int i = 0; i < ss->aprob_u; ++i) {
            if (!strcmp(prob->super, ss->aprobs[i]->short_name)) {
                abstr = ss->aprobs[i];
                break;
            }
        }
        if (!abstr) {
            error("abstract problem '%s' is not found for problem '%s'",
                  prob->super, prob->short_name);
            return;
        }
    }

    struct section_problem_data *tmp_prob = prepare_copy_problem(prob);

    prepare_set_prob_value(CNTSPROB_type, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_xml_file, tmp_prob, abstr, global);

    if (tmp_prob->type == PROB_TYPE_SELECT_ONE && tmp_prob->xml_file && tmp_prob->xml_file[0]) {
        info("Select-one XML-specified problem, skipping");
        return;
    }

    prepare_set_prob_value(CNTSPROB_normalization, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_use_stdin, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_use_stdout, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_combined_stdin, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_combined_stdout, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_input_file, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_output_file, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_scoring_checker, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_enable_checker_token, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_interactive_valuer, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_disable_pe, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_disable_wtl, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_wtl_is_cf, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_manual_checking, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_examinator_num, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_check_presentation, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_binary_input, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_binary, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_ignore_exit_code, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_ignore_term_signal, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_valuer_cmd, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_interactor_cmd, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_style_checker_cmd, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_test_checker_cmd, tmp_prob, abstr, global);
    //prepare_set_prob_value(CNTSPROB_test_checker_env, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_test_dir, tmp_prob, abstr, 0);
    prepare_set_prob_value(CNTSPROB_use_corr, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_test_sfx, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_test_pat, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_test_score, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_full_score, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_full_user_score, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_min_score_1, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_min_score_2, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_solution_cmd, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_solution_src, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_source_header, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_source_footer, tmp_prob, abstr, global);
    //mkpath(test_path, g_test_path, tmp_prob->test_dir, "");
    if (tmp_prob->use_corr) {
        prepare_set_prob_value(CNTSPROB_corr_dir, tmp_prob, abstr, 0);
        prepare_set_prob_value(CNTSPROB_corr_sfx, tmp_prob, abstr, global);
        prepare_set_prob_value(CNTSPROB_corr_pat, tmp_prob, abstr, global);
        //mkpath(corr_path, g_corr_path, tmp_prob->corr_dir, "");
    }
    prepare_set_prob_value(CNTSPROB_use_info, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_use_tgz, tmp_prob, abstr, global);
    if (tmp_prob->use_info) {
        prepare_set_prob_value(CNTSPROB_info_dir, tmp_prob, abstr, 0);
        prepare_set_prob_value(CNTSPROB_info_sfx, tmp_prob, abstr, global);
        prepare_set_prob_value(CNTSPROB_info_pat, tmp_prob, abstr, global);
        //mkpath(info_path, g_info_path, tmp_prob->info_dir, "");
    }
    unsigned char checker_path[PATH_MAX];
    checker_path[0] = 0;
    if (!tmp_prob->standard_checker) {
        prepare_set_prob_value(CNTSPROB_check_cmd, tmp_prob, abstr, 0);
        get_advanced_layout_path(checker_path, sizeof(checker_path),
                                 global, tmp_prob, tmp_prob->check_cmd, -1);
    }

    if (build_generate_makefile(log_f, ejudge_config, cnts, NULL, ss, ss->global, tmp_prob, 0) < 0) {
        error("failed to generate Makefile for problem '%s'", tmp_prob->short_name);
    }
}

static void
update_contest_xml(
        int contest_id,
        struct sid_state *ss,
        int ready,
        time_t update_time,
        int problem_count)
{
    struct contest_desc *rw_cnts = NULL;
    unsigned char *xml_header = NULL;
    unsigned char *xml_footer = NULL;

    if (contests_load(contest_id, &rw_cnts) < 0 || !rw_cnts) {
        goto cleanup;
    }

    rw_cnts->ready = ready;
    if (update_time > 0) {
        rw_cnts->update_time = update_time;
    }
    xfree(rw_cnts->problem_count); rw_cnts->problem_count = NULL;
    if (problem_count > 0) {
        unsigned char buf[64];
        snprintf(buf, sizeof(buf), "%d", problem_count);
        rw_cnts->problem_count = xstrdup(buf);
    }

    unsigned char xml_path[PATH_MAX];
    contests_make_path(xml_path, sizeof(xml_path), contest_id);
    if (super_html_get_contest_header_and_footer(xml_path, &xml_header, &xml_footer) < 0)
        goto cleanup;

    unsigned char audit_rec[PATH_MAX];
    snprintf(audit_rec, sizeof(audit_rec),
             "<!-- audit: edited %s %d (%s) %s -->\n",
             xml_unparse_date(time(NULL)), ss->user_id, ss->user_login,
             xml_unparse_ipv6(&ss->remote_addr));

    if (!xml_header) {
        unsigned char hbuf[PATH_MAX];
        snprintf(hbuf, sizeof(hbuf),
                 "<!-- $%s$ -->\n", "Id");
        xml_header = xstrdup(hbuf);
    }
    if (!xml_footer) xml_footer = xstrdup("\n");

    contests_unparse_and_save(rw_cnts, NULL, xml_header, xml_footer,
                              audit_rec, NULL, NULL);
cleanup:
    xfree(xml_header);
    xfree(xml_footer);
}

static void
do_import_contest(
        int contest_id,
        struct sid_state *ss,
        const unsigned char *arch_file,
        const unsigned char *content_type,
        int require_master_solution,
        unsigned long required_solution_mask,
        int require_test_checker)
{
    const unsigned char *ejudge_xml_path = NULL;
    struct ejudge_cfg *ejudge_config = NULL;
    struct problems_info *pi = NULL;
    unsigned char *stdout_text = NULL;
    unsigned char *stderr_text = NULL;
    unsigned char working_dir[PATH_MAX];
    unsigned char *serve_header = NULL;
    unsigned char *serve_footer = NULL;
    int contest_problem_count = 0;
    time_t contest_update_time = 0;

    working_dir[0] = 0;

    unsigned char arch_path[PATH_MAX];
    if (os_IsAbsolutePath(arch_file)) {
        snprintf(arch_path, sizeof(arch_path), "%s", arch_file);
    } else {
        unsigned char cur_dir[PATH_MAX];
        if (!getcwd(cur_dir, sizeof(cur_dir))) {
            fatal2("getcwd failed: %s", os_ErrorMsg());
            goto cleanup;
        }
        const unsigned char *sep = "/";
        if (!strcmp(cur_dir, "/")) sep = "";
        snprintf(arch_path, sizeof(arch_path), "%s%s%s", cur_dir, sep, arch_file);
    }
    struct stat stb;
    if (stat(arch_path, &stb) < 0) {
        fatal2("stat failed on '%s': %s", arch_path, os_ErrorMsg());
        goto cleanup;
    }
    if (!S_ISREG(stb.st_mode)) {
        fatal2("'%s' is not a regular file", arch_path);
        goto cleanup;
    }
    if (access(arch_path, R_OK) < 0) {
        fatal2("'%s' is not readable", arch_path);
        goto cleanup;
    }

#if defined EJUDGE_XML_PATH
    if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */
    if (!ejudge_xml_path) {
        fatal2("'ejudge.xml' path is not specified");
        goto cleanup;
    }

    ejudge_config = ejudge_cfg_parse(ejudge_xml_path, 1);
    if (!ejudge_config) {
        fatal2("'ejudge.xml' parsing failed");
        goto cleanup;
    }
    if (contests_set_directory(ejudge_config->contests_dir) < 0) {
        fatal2("contests_set_directory failed");
        goto cleanup;
    }

    const struct contest_desc *cnts = NULL;
    if (contests_get(contest_id, &cnts) < 0 || !cnts) {
        fatal2("contest_id is invalid");
        goto cleanup;
    }

    unsigned char root_dir[PATH_MAX];
    root_dir[0] = 0;
    if (cnts->root_dir && cnts->root_dir[0] && os_IsAbsolutePath(cnts->root_dir)) {
        snprintf(root_dir, sizeof(root_dir), "%s", cnts->root_dir);
    } else if (cnts->root_dir && cnts->root_dir[0]) {
        if (ejudge_config->contests_home_dir && ejudge_config->contests_home_dir[0]) {
            snprintf(root_dir, sizeof(root_dir), "%s/%s", ejudge_config->contests_home_dir, cnts->root_dir);
        } else {
#if defined CONTESTS_HOME_DIR
            snprintf(root_dir, sizeof(root_dir), "%s/%s", CONTESTS_HOME_DIR, cnts->root_dir);
#endif
        }
    } else {
        if (ejudge_config->contests_home_dir && ejudge_config->contests_home_dir[0]) {
            snprintf(root_dir, sizeof(root_dir), "%s/%06d", ejudge_config->contests_home_dir, contest_id);
        } else {
#if defined CONTESTS_HOME_DIR
            snprintf(root_dir, sizeof(root_dir), "%s/%06d", CONTESTS_HOME_DIR, contest_id);
#endif
        }
    }
    if (!root_dir[0]) {
        fatal2("contest %d root dir is undefined", contest_id);
        goto cleanup;
    }


    if (os_MakeDirPath2(root_dir, cnts->dir_mode, cnts->dir_group) < 0) {
        fatal2("failed to create directory '%s': %s", root_dir, os_ErrorMsg());
        goto cleanup;
    }

    unsigned char import_dir[PATH_MAX];
    snprintf(import_dir, sizeof(import_dir), "%s/%s", root_dir, IMPORT_DIR);
    time_t cur_time = time(NULL);
    unsigned char rand_base[PATH_MAX];
    snprintf(rand_base, sizeof(rand_base), "%d_%d", (int) getpid(), (int) cur_time);
    snprintf(working_dir, sizeof(working_dir), "%s/ej_import_%s", import_dir, rand_base);
    if (os_MakeDirPath2(working_dir, cnts->dir_mode, cnts->dir_group) < 0) {
        fatal2("failed to create directory '%s': %s", root_dir, os_ErrorMsg());
        goto cleanup;
    }

    unsigned char conf_dir[PATH_MAX];
    snprintf(conf_dir, sizeof(conf_dir), "%s/%s", root_dir, CONF_DIR);
    if (os_MakeDirPath2(conf_dir, cnts->dir_mode, cnts->dir_group) < 0) {
        fatal2("failed to create directory '%s': %s", conf_dir, os_ErrorMsg());
        goto cleanup;
    }

    unsigned char problems_dir[PATH_MAX];
    snprintf(problems_dir, sizeof(problems_dir), "%s/%s", root_dir, PROBLEMS_DIR);
    if (os_MakeDirPath2(problems_dir, cnts->dir_mode, cnts->dir_group) < 0) {
        fatal2("failed to create directory '%s': %s", problems_dir, os_ErrorMsg());
        goto cleanup;
    }

    /* unpack the archive */
    char *args[10];
    if (ends_with_nocase(arch_path, ".zip") || (content_type && !strcasecmp(content_type, ZIP_CONTENT_TYPE))) {
        // use zip unpacker
        info("unpacking archive with %s", UNZIP_PATH);
        args[0] = UNZIP_PATH;
        args[1] = arch_path;
        args[2] = NULL;
    } else {
        // use tar unpacker
        info("unpacking archive with %s", TAR_PATH);
        args[0] = TAR_PATH;
        args[1] = "xf";
        args[2] = arch_path;
        args[3] = NULL;
    }

    int r = ejudge_invoke_process(args, NULL, working_dir, "/dev/null", NULL, 0, &stdout_text, &stderr_text);
    if (stdout_text && *stdout_text) {
        fprintf(log_f, "Stdout:\n%s\n", stdout_text);
    }
    xfree(stdout_text); stdout_text = NULL;
    if (stderr_text && *stderr_text) {
        fprintf(log_f, "Stderr:\n%s\n", stderr_text);
    }
    xfree(stderr_text); stderr_text = NULL;
    info("status: %d", r);
    if (r != 0) {
        error("failed to unpack the archive '%s'", arch_path);
        goto cleanup;
    }

    // if "problems" subdirectory exists in the working_dir, go with it
    // else if there is a signle subdirectory, go there and check for "problems" subdirectory
    unsigned char in_archive_dir[PATH_MAX];
    unsigned char in_problems_dir[PATH_MAX];
    snprintf(in_archive_dir, sizeof(in_archive_dir), "%s", working_dir);
    snprintf(in_problems_dir, sizeof(in_problems_dir), "%s/%s", in_archive_dir, PROBLEMS_DIR);
    if (stat(in_problems_dir, &stb) >= 0 && S_ISDIR(stb.st_mode) && access(in_problems_dir, R_OK | X_OK) >= 0) {
        // do nothing, "problems" is OK
    } else {
        unsigned char subdir[PATH_MAX];
        int count = 0;
        DIR *d = opendir(in_archive_dir);
        struct dirent *dd;
        if (!d) {
            fatal2("cannot open directory '%s': %s", in_archive_dir, os_ErrorMsg());
            goto cleanup;
        }
        while ((dd = readdir(d))) {
            if (strcmp(dd->d_name, ".") && strcmp(dd->d_name, "..")) {
                snprintf(subdir, sizeof(subdir), "%s/%s", in_archive_dir, dd->d_name);
                ++count;
            }
        }
        closedir(d); d = NULL;
        if (!count) {
            error("directory '%s' is empty: empty archive", in_archive_dir);
            goto cleanup;
        }
        if (count != 1) {
            error("too many files in directory '%s': invalid archive", in_archive_dir);
            goto cleanup;
        }
        if (stat(subdir, &stb) < 0 || !S_ISDIR(stb.st_mode)) {
            error("'%s' is not a directory", subdir);
            goto cleanup;
        }
        if (access(subdir, X_OK | R_OK) < 0) {
            error("'%s' is not readable", subdir);
            goto cleanup;
        }
        snprintf(in_archive_dir, sizeof(in_archive_dir), "%s", subdir);
        snprintf(in_problems_dir, sizeof(in_problems_dir), "%s/%s", in_archive_dir, PROBLEMS_DIR);
        if (stat(in_problems_dir, &stb) < 0) {
            error("'%s' does not exist", in_problems_dir);
            goto cleanup;
        }
        if (!S_ISDIR(stb.st_mode)) {
            error("'%s' is not a directory", in_problems_dir);
            goto cleanup;
        }
    }

    // scan every directory in "problems"
    pi = problems_info_create();
    DIR *d = opendir(in_problems_dir);
    if (!d) {
        error("cannot open directory '%s': %s", in_problems_dir, os_ErrorMsg());
        goto cleanup;
    }
    struct dirent *dd;
    while ((dd = readdir(d))) {
        if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, "..")) continue;
        unsigned char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", in_problems_dir, dd->d_name);
        if (stat(path, &stb) < 0) continue;
        if (!S_ISDIR(stb.st_mode)) {
            warning("entry '%s/%s' is not a directory, ignored", PROBLEMS_DIR, dd->d_name);
            continue;
        }
        problems_info_append(pi, path, dd->d_name);
    }
    closedir(d); d = NULL;

    if (!pi || pi->u <= 0) {
        info("no problems to import");
        goto cleanup;
    }

    qsort(pi->p, pi->u, sizeof(pi->p[0]), problem_sort_func);

    /*
    for (int i = 0; i < pi->u; ++i) {
        printf("%s;%s\n", pi->p[i].problem_dir, pi->p[i].dir_name);
    }
    */

    // basic identity checks
    for (int i = 0; i < pi->u; ++i) {
        struct problem_info *p = &pi->p[i];
        unsigned char path[PATH_MAX];
        unsigned char rel_path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", p->problem_dir, PROBLEM_CFG);
        snprintf(rel_path, sizeof(rel_path), "%s/%s/%s", PROBLEMS_DIR, p->dir_name, PROBLEM_CFG);
        if (stat(path, &stb) < 0) {
            error("'%s' does not exist", rel_path);
            continue;
        }
        if (!S_ISREG(stb.st_mode)) {
            error("'%s' is not a regular file", rel_path);
            continue;
        }
        if (access(path, R_OK) < 0) {
            error("'%s' is not readable", rel_path);
            continue;
        }
        FILE *f = NULL;
        if (!(f = fopen(path, "r"))) {
            error("cannot open '%s' for reading: %s", rel_path, os_ErrorMsg());
            continue;
        }
        p->cfg = problem_config_section_parse_cfg(path, f);
        f = NULL;
        if (!p->cfg) {
            error("failed to parse '%s'", rel_path);
            continue;
        }
        if (!p->cfg->short_name || !*p->cfg->short_name) {
            error("'short_name' attribute is undefined in '%s'", rel_path);
            p->is_bad = 1;
            continue;
        }
        if (!is_valid_name(p->cfg->short_name)) {
            error("'short_name' attribute value ('%s') is invalid in '%s'", p->cfg->short_name, rel_path);
            p->is_bad = 1;
            continue;
        }
        if (p->cfg->internal_name && !is_valid_name(p->cfg->internal_name)) {
            error("'internal_name' attribute value ('%s') is invalid in '%s'", p->cfg->internal_name, rel_path);
            p->is_bad = 1;
            continue;
        }
        if (p->cfg->internal_name) {
            if (strcmp(p->cfg->internal_name, p->dir_name) != 0) {
                error("'internal_name' attribute value ('%s') does not match directory name ('%s') in '%s'",
                      p->cfg->internal_name, p->dir_name, rel_path);
                p->is_bad = 1;
                continue;
            }
        } else {
            if (strcmp(p->cfg->short_name, p->dir_name) != 0) {
                error("'short_name' attribute value ('%s') does not match directory name ('%s') in '%s'",
                      p->cfg->short_name, p->dir_name, rel_path);
                p->is_bad = 1;
                continue;
            }
        }
        // check short_name uniqueness
        for (int j = 0; j < i; ++j) {
            struct problem_info *q = &pi->p[j];
            if (q->is_bad || !q->cfg) continue;
            if (!strcmp(q->cfg->short_name, p->cfg->short_name)) {
                error("'short_name' attribute value ('%s') is not unique in '%s'",
                      p->cfg->short_name, rel_path);
                p->is_bad = 1;
                break;
            }
            if (q->cfg->internal_name && !strcmp(q->cfg->internal_name, p->cfg->short_name)) {
                error("'short_name' attribute value ('%s') is not unique in '%s'",
                      p->cfg->short_name, rel_path);
                p->is_bad = 1;
                break;
            }
            if (p->cfg->internal_name) {
                if (!strcmp(q->cfg->short_name, p->cfg->internal_name)) {
                    error("'internal_name' attribute value ('%s') is not unique in '%s'",
                          p->cfg->internal_name, rel_path);
                    p->is_bad = 1;
                    break;
                }
                if (q->cfg->internal_name && !strcmp(q->cfg->internal_name, p->cfg->internal_name)) {
                    error("'internal_name' attribute value ('%s') is not unique in '%s'",
                          p->cfg->internal_name, rel_path);
                    p->is_bad = 1;
                    break;
                }
            }
        }
    }

    if (exit_code > 0) goto cleanup;

    // check tests correctness
    for (int i = 0; i < pi->u; ++i) {
        struct problem_info *p = &pi->p[i];
        unsigned char rel_path[PATH_MAX];
        snprintf(rel_path, sizeof(rel_path), "%s/%s/%s", PROBLEMS_DIR, p->dir_name, PROBLEM_CFG);
        if (p->is_bad || !p->cfg) continue;
        unsigned char tests_dir[PATH_MAX];
        snprintf(tests_dir, sizeof(tests_dir), "%s/%s", p->problem_dir, TESTS_DIR);
        if (stat(tests_dir, &stb) < 0) {
            error("directory '%s/%s/%s' does not exist", PROBLEMS_DIR, p->dir_name, TESTS_DIR);
            p->is_bad = 1;
            continue;
        }
        if (!S_ISDIR(stb.st_mode)) {
            error("'%s/%s/%s' is not a directory", PROBLEMS_DIR, p->dir_name, TESTS_DIR);
            p->is_bad = 1;
            continue;
        }
        if (access(tests_dir, X_OK | R_OK) < 0) {
            error("directory '%s/%s/%s' is not readable", PROBLEMS_DIR, p->dir_name, TESTS_DIR);
            p->is_bad = 1;
            continue;
        }

        unsigned char test_pat[128];
        test_pat[0] = 0;
        int test_count = check_pattern(test_pat, sizeof(test_pat), tests_dir, p->cfg->test_pat,
                                       &p->cfg->test_sfx, ".dat", p->dir_name, "test_pat", "tests");
        if (test_count <= 0) {
            p->is_bad = 1;
            continue;
        }
        info("test count = %d for problem '%s'", test_count, p->dir_name);
        p->test_count = test_count;
        p->test_pat = xstrdup(test_pat);

        if (p->cfg->use_corr > 0) {
            unsigned char pat[128];
            int count = check_pattern(pat, sizeof(pat), tests_dir, p->cfg->corr_pat, &p->cfg->corr_sfx, ".ans",
                                      p->dir_name, "corr_pat", "answers");
            if (count <= 0) {
                p->is_bad = 1;
                continue;
            }
            info("answer count = %d for problem '%s'", count, p->dir_name);
            if (count != test_count) {
                error("number of answers (%d) does not match number of tests (%d) for problem '%s'", count, test_count, p->dir_name);
                p->is_bad = 1;
                continue;
            }
            p->corr_pat = xstrdup(pat);
        }

        if (p->cfg->use_info > 0) {
            unsigned char pat[128];
            pat[0] = 0;
            int count = check_pattern(pat, sizeof(pat), tests_dir, p->cfg->info_pat, &p->cfg->info_sfx, ".inf",
                                      p->dir_name, "info_pat", "infos");
            if (count <= 0) {
                p->is_bad = 1;
                continue;
            }
            info("info count = %d for problem '%s'", count, p->dir_name);
            if (count != test_count) {
                error("number of infos (%d) does not match number of tests (%d) for problem '%s'", count, test_count, p->dir_name);
                p->is_bad = 1;
                continue;
            }
            p->info_pat = xstrdup(pat);
        }

        if (p->cfg->use_tgz > 0) {
            unsigned char pat[128];
            pat[0] = 0;
            int count = check_pattern(pat, sizeof(pat), tests_dir, p->cfg->tgz_pat, &p->cfg->tgz_sfx, ".tgz",
                                      p->dir_name, "tgz_pat", "archives");
            if (count <= 0) {
                p->is_bad = 1;
                continue;
            }
            info("archive count = %d for problem '%s'", count, p->dir_name);
            if (count != test_count) {
                error("number of archives (%d) does not match number of tests (%d) for problem '%s'", count, test_count, p->dir_name);
                p->is_bad = 1;
                continue;
            }
            p->tgz_pat = xstrdup(pat);

            pat[0] = 0;
            count = check_pattern(pat, sizeof(pat), tests_dir, p->cfg->tgzdir_pat, &p->cfg->tgzdir_sfx, ".dir",
                                      p->dir_name, "tgzdir_pat", "workdirs");
            if (count <= 0) {
                p->is_bad = 1;
                continue;
            }
            info("workdir count = %d for problem '%s'", count, p->dir_name);
            if (count != test_count) {
                error("number of workdirs (%d) does not match number of tests (%d) for problem '%s'", count, test_count, p->dir_name);
                p->is_bad = 1;
                continue;
            }
            p->tgzdir_pat = xstrdup(pat);
        }

        // check checker
        if (p->cfg->check_cmd) {
            if (check_checker(0, p->cfg->check_cmd, p->problem_dir,
                              "check_cmd", rel_path, p->dir_name, "checker") < 0) {
                p->is_bad = 1;
                continue;
            }
            xfree(p->cfg->standard_checker); p->cfg->standard_checker = NULL;
        } else if (p->cfg->standard_checker) {
            if (strchr(p->cfg->standard_checker, '/')) {
                error("'standard_checker' attribute value('%s') is invalid in '%s'",
                      p->cfg->standard_checker, rel_path);
                p->is_bad = 1;
                continue;
            }
            unsigned char checker_path[PATH_MAX];
            checker_path[0] = 0;
#if defined EJUDGE_SCRIPT_DIR
            if (!checker_path[0]) {
                snprintf(checker_path, sizeof(checker_path), "%s/checkers/%s",
                         EJUDGE_SCRIPT_DIR, p->cfg->standard_checker);
            }
#endif
#if defined EJUDGE_LIBEXEC_DIR
            if (!checker_path[0]) {
                snprintf(checker_path, sizeof(checker_path), "%s/ejudge/checkers/%s",
                         EJUDGE_LIBEXEC_DIR, p->cfg->standard_checker);
            }
#endif
#if defined EJUDGE_PREFIX_DIR
            if (!checker_path[0]) {
                snprintf(checker_path, sizeof(checker_path), "%s/libexec/ejudge/checkers/%s",
                         EJUDGE_PREFIX_DIR, p->cfg->standard_checker);
            }
#endif
            if (!checker_path[0]) {
                fatal2("cannot determine standard checker path");
                p->is_bad = 1;
                continue;
            }
            if (stat(checker_path, &stb) < 0 || !S_ISREG(stb.st_mode) || access(checker_path, X_OK) < 0) {
                error("'standard_checker' attribute value ('%s') is invalid in '%s'",
                      p->cfg->standard_checker, rel_path);
                p->is_bad = 1;
                continue;
            }
        } else {
            error("neither custom, nor standard checkers are defined in '%s'", rel_path);
            p->is_bad = 1;
            continue;
        }

        // check solution
        if (require_master_solution && !p->cfg->solution_cmd) {
            error("'solution_cmd' attribute value is undefined in '%s'", rel_path);
            p->is_bad = 1;
            continue;
        }
        if (p->cfg->solution_cmd) {
            if (p->cfg->source_header) {
                error("'source_header' attribute is not yet supported in '%s'", rel_path);
                p->is_bad = 1;
                continue;
            }
            if (p->cfg->source_footer) {
                error("'source_footer' attribute is not yet supported in '%s'", rel_path);
                p->is_bad = 1;
                continue;
            }
            if (strchr(p->cfg->solution_cmd, '/')) {
                error("'solution_cmd' attribute value ('%s') is invalid in '%s'",
                      p->cfg->solution_cmd, rel_path);
                p->is_bad = 1;
                continue;
            }
            unsigned char solution_path[PATH_MAX];
            snprintf(solution_path, sizeof(solution_path), "%s/%s", p->problem_dir, p->cfg->solution_cmd);
            int count = 0;
            build_guess_language_by_cmd(solution_path, &count);
            if (count <= 0) {
                error("no source code in one of supported languages is provided for solution '%s' in '%s'",
                      p->cfg->solution_cmd, rel_path);
                p->is_bad = 1;
                continue;
            } else if (count > 1) {
                error("cannot determine source language for solution '%s' in '%s': several possible source files exist",
                      p->cfg->solution_cmd, rel_path);
                p->is_bad = 1;
                continue;
            }
        }

        // check other solutions
        if (required_solution_mask) {
            unsigned char solutions_path[PATH_MAX];
            snprintf(solutions_path, sizeof(solutions_path), "%s/%s", p->problem_dir, SOLUTIONS_DIR);
            if (stat(solutions_path, &stb) < 0) {
                error("'%s/%s/%s' does not exist", PROBLEMS_DIR, p->dir_name, SOLUTIONS_DIR);
                p->is_bad = 1;
                continue;
            }
            if (!S_ISDIR(stb.st_mode)) {
                error("'%s/%s/%s' is not a directory", PROBLEMS_DIR, p->dir_name, SOLUTIONS_DIR);
                p->is_bad = 1;
                continue;
            }
            if (!(d = opendir(solutions_path))) {
                error("cannot open directory '%s/%s/%s'", PROBLEMS_DIR, p->dir_name, SOLUTIONS_DIR);
                p->is_bad = 1;
                continue;
            }
            unsigned long sol_mask = 0;
            while ((dd = readdir(d))) {
                if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, "..")) continue;
                unsigned char sol_path[PATH_MAX];
                snprintf(sol_path, sizeof(sol_path), "%s/%s", solutions_path, dd->d_name);
                if (stat(sol_path, &stb) < 0 || !S_ISREG(stb.st_mode)) continue;
                sol_mask |= build_find_suffix(sol_path);
            }
            closedir(d); d = NULL;
            unsigned long m2 = required_solution_mask;
            unsigned long m3 = 1;
            int failed = 0;
            while (m2) {
                if ((m2 & 1) > (sol_mask & 1)) {
                    error("no solution '%s' for problem '%s'", build_get_source_suffix(m3), p->dir_name);
                }
                sol_mask >>= 1;
                m2 >>= 1;
                m3 <<= 1;
            }
            if (failed) {
                p->is_bad = 1;
                continue;
            }
        }

        // check test_checker_cmd
        if (check_checker(require_test_checker, p->cfg->test_checker_cmd, p->problem_dir,
                          "test_checker_cmd", rel_path, p->dir_name, "test checker") < 0) {
            p->is_bad = 1;
            continue;
        }

        if (check_checker(0, p->cfg->valuer_cmd, p->problem_dir,
                          "valuer_cmd", rel_path, p->dir_name, "evaluator") < 0) {
            p->is_bad = 1;
            continue;
        }

        if (p->cfg->time_limit <= 0 && p->cfg->time_limit_millis <= 0) {
            warning("neither 'time_limit', nor 'time_limit_millis' is defined in '%s'",
                    rel_path);
            warning("'time_limit' attribute default value is %d", 1);
            p->cfg->time_limit = 1;
        } else if (p->cfg->time_limit_millis > 0) {
            p->cfg->time_limit = 0;
        }
        if (p->cfg->real_time_limit <= 0) {
            warning("'real_time_limit' value is undefined in '%s', default value is %d",
                    rel_path, p->cfg->time_limit * 3);
            p->cfg->real_time_limit = p->cfg->time_limit * 3;
            if (p->cfg->real_time_limit <= 0) p->cfg->real_time_limit = 3;
        }

        if (!p->cfg->max_vm_size || p->cfg->max_vm_size == (size_t) -1L) {
            warning("'max_vm_size' attribute is undefined in '%s', default value is %zu",
                    rel_path, (size_t) 256 * (size_t) 1024 * (size_t) 1024);
            p->cfg->max_vm_size = 256 * 1024 * 1024;
        }
        if (!p->cfg->max_stack_size || p->cfg->max_stack_size == (size_t) -1L) {
            warning("'max_stack_size' attribute is undefined in '%s', default value is %zu",
                    rel_path, p->cfg->max_vm_size);
            p->cfg->max_stack_size = p->cfg->max_vm_size;
        }

        if (p->cfg->full_score <= 0) {
            error("'full_score' attribute is undefined in '%s'", rel_path);
            p->is_bad = 1;
            continue;
        }
        if (p->cfg->test_score < 0) {
            warning("'test_score' attribute is undefined in '%s', default value is %d",
                    rel_path, 0);
            p->cfg->test_score = 0;
        }
        if (p->cfg->run_penalty < 0) {
            warning("'run_penalty' attribute is undefined in '%s', default value is %d",
                    rel_path, 0);
            p->cfg->run_penalty = 0;
        }
    }

    if (exit_code > 0) goto cleanup;

    // load the current contest configuration file
    struct contest_desc *rw_cnts = NULL;
    if (contests_load(contest_id, &rw_cnts) < 0 || !rw_cnts) {
        fatal2("cannot load contest XML file");
        goto cleanup;
    }

    unsigned char serve_cfg_path[PATH_MAX];
    snprintf(serve_cfg_path, sizeof(serve_cfg_path), "%s/%s", conf_dir, SERVE_CFG);

    if (super_html_read_serve(log_f, serve_cfg_path, ejudge_config, cnts, ss) < 0) {
        fatal2("cannot open serve.cfg for reading");
        goto cleanup;
    }

    for (int i = 0; i < pi->u; ++i) {
        struct problem_info *p = &pi->p[i];
        if (p->is_bad || !p->cfg) continue;
        unsigned char rel_path[PATH_MAX];
        snprintf(rel_path, sizeof(rel_path), "%s/%s/%s", PROBLEMS_DIR, p->dir_name, PROBLEM_CFG);
        int j;
        for (j = 0; j < ss->aprob_u; ++j) {
            const struct section_problem_data *prob = ss->aprobs[j];
            if (!prob) continue;
            if (!strcmp(p->cfg->short_name, prob->short_name)) {
                error("'short_name' attribute value ('%s') matches an abstract problem in '%s'",
                      p->cfg->short_name, serve_cfg_path);
                p->is_bad = 1;
            }
            if (prob->internal_name && !strcmp(p->cfg->short_name, prob->internal_name)) {
                error("'short_name' attribute value ('%s') matches an abstract problem in '%s'",
                      p->cfg->short_name, serve_cfg_path);
                p->is_bad = 1;
            }
            if (p->cfg->internal_name) {
                if (!strcmp(p->cfg->internal_name, prob->short_name)) {
                    error("'internal_name' attribute value ('%s') matches an abstract problem in '%s'",
                          p->cfg->internal_name, serve_cfg_path);
                    p->is_bad = 1;
                }
                if (prob->internal_name && !strcmp(p->cfg->internal_name, prob->internal_name)) {
                    error("'internal_name' attribute value ('%s') matches an abstract problem in '%s'",
                          p->cfg->internal_name, serve_cfg_path);
                    p->is_bad = 1;
                }
            }
        }
        for (j = 1; j < ss->prob_a; ++j) {
            const struct section_problem_data *prob = ss->probs[j];
            if (!prob) continue;
            if (!strcmp(p->cfg->short_name, prob->short_name))
                break;
        }
        if (j < ss->prob_a) {
            const struct section_problem_data *prob = ss->probs[j];
            if (p->cfg->internal_name && prob->internal_name
                && strcmp(p->cfg->internal_name, prob->internal_name) != 0) {
                error("'internal_name' attribute values ('%s' and '%s') mismatch in '%s' and '%s'",
                      p->cfg->internal_name, prob->internal_name,
                      rel_path, serve_cfg_path);
                p->is_bad = 1;
                continue;
            }
            info("updating problem %d: '%s'", j, p->cfg->short_name);
            p->prob_id = j;
        } else {
            // create new problem
            j = ss->prob_a - 1;
            while (j > 0 && !ss->probs[j]) --j;
            if (j <= 0) {
                j = 1;
            } else {
                ++j;
            }
            if (j < ss->prob_a && ss->probs[j]) {
                error("internal error: j == %d", j);
                p->is_bad = 1;
                continue;
            }
            struct section_problem_data *prob;
            if (!(prob = super_html_create_problem(ss, j))) {
                error("failed to create a new problem '%s' in '%s'",
                      p->dir_name, serve_cfg_path);
                p->is_bad = 1;
                continue;
            }
            info("created problem %d: '%s'", j, p->cfg->short_name);
            p->prob_id = j;
            prob->id = j;
            snprintf(prob->short_name, sizeof(prob->short_name), "%s", p->cfg->short_name);
            if (ss->aprob_u == 1 && ss->aprobs[0]) {
                snprintf(prob->super, sizeof(prob->super), "%s", ss->aprobs[0]->short_name);
            }
        }
    }

    if (exit_code > 0) goto cleanup;

    for (int i = 0; i < pi->u; ++i) {
        struct problem_info *p = &pi->p[i];
        if (p->is_bad || !p->cfg) continue;
        unsigned char rel_path[PATH_MAX];
        snprintf(rel_path, sizeof(rel_path), "%s/%s/%s", PROBLEMS_DIR, p->dir_name, PROBLEM_CFG);
        struct section_problem_data *prob;
        if (p->prob_id <= 0 || p->prob_id >= ss->prob_a || !(prob = ss->probs[p->prob_id])) {
            error("internal error: prob_id (%d) is incorrect for problem '%s'",
                  p->prob_id, p->cfg->short_name);
            p->is_bad = 1;
            continue;
        }

        const struct section_problem_data *aprob = NULL;
        if (/*prob->super &&*/ prob->super[0]) {
            for (int j = 0; j < ss->aprob_u; ++j) {
                const struct section_problem_data *aa = ss->aprobs[j];
                if (aa && /*aa->short_name &&*/ !strcmp(prob->super, aa->short_name)) {
                    aprob = aa;
                    break;
                }
            }
        }
        merge_problem_section(ejudge_config, prob, aprob, p->cfg);
    }

    if (exit_code > 0) goto cleanup;

    // backup config file and problem directories
    unsigned char backup_root_dir[PATH_MAX];
    snprintf(backup_root_dir, sizeof(backup_root_dir), "%s/%s", root_dir, BACKUP_DIR);
    if (os_MakeDirPath2(backup_root_dir, cnts->dir_mode, cnts->dir_group) < 0) {
        fatal2("failed to create directory '%s': %s", backup_root_dir, os_ErrorMsg());
        goto cleanup;
    }
    time_t ct = time(NULL);
    struct tm *ptm = localtime(&ct);
    unsigned char backup_base[PATH_MAX];
    snprintf(backup_base, sizeof(backup_base), "%04d%02d%02d%02d%02d%02d",
             ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
    unsigned char backup_dir[PATH_MAX];
    snprintf(backup_dir, sizeof(backup_dir), "%s/%s", backup_root_dir, backup_base);
    if (os_MakeDirPath2(backup_dir, cnts->dir_mode, cnts->dir_group) < 0) {
        fatal2("failed to create directory '%s': %s", backup_dir, os_ErrorMsg());
        goto cleanup;
    }
    unsigned char backup_conf_dir[PATH_MAX];
    snprintf(backup_conf_dir, sizeof(backup_conf_dir), "%s/%s", backup_dir, CONF_DIR);
    if (os_MakeDirPath2(backup_conf_dir, cnts->dir_mode, cnts->dir_group) < 0) {
        fatal2("failed to create directory '%s': %s", backup_conf_dir, os_ErrorMsg());
        goto cleanup;
    }
    unsigned char backup_problems_dir[PATH_MAX];
    snprintf(backup_problems_dir, sizeof(backup_problems_dir), "%s/%s", backup_dir, PROBLEMS_DIR);
    if (os_MakeDirPath2(backup_problems_dir, cnts->dir_mode, cnts->dir_group) < 0) {
        fatal2("failed to create directory '%s': %s", backup_problems_dir, os_ErrorMsg());
        goto cleanup;
    }
    if (generic_copy_file(0, NULL, serve_cfg_path, NULL, 0, backup_conf_dir, SERVE_CFG, NULL) < 0) {
        fatal2("copy %s->%s/%s operation failed", serve_cfg_path, backup_conf_dir, SERVE_CFG);
        goto cleanup;
    }

    for (int i = 0; i < pi->u; ++i) {
        struct problem_info *p = &pi->p[i];
        if (p->is_bad || !p->cfg) continue;
        unsigned char dst_path[PATH_MAX];
        snprintf(dst_path, sizeof(dst_path), "%s/%s", problems_dir, p->dir_name);
        if (stat(dst_path, &stb) >= 0) {
            if (!S_ISDIR(stb.st_mode)) {
                fatal2("'%s' is not a directory", dst_path);
                p->is_bad = 1;
                continue;
            }
            unsigned char bak_path[PATH_MAX];
            snprintf(bak_path, sizeof(bak_path), "%s/%s", backup_problems_dir, p->dir_name);
            if (rename(dst_path, bak_path) < 0) {
                fatal2("move %s->%s failed: %s", dst_path, bak_path, os_ErrorMsg());
                p->is_bad = 1;
                continue;
            }
        }
    }

    if (exit_code > 0) goto cleanup;

    if (super_html_get_serve_header_and_footer(serve_cfg_path, &serve_header, &serve_footer) < 0) {
        fatal2("cannot extract footer and header from '%s'", serve_cfg_path);
        goto cleanup;
    }
    unsigned char serve_audit_rec[PATH_MAX];
    snprintf(serve_audit_rec, sizeof(serve_audit_rec), "# audit: edited %s %d (%s) %s\n",
             xml_unparse_date(ct), ss->user_id, ss->user_login,
             xml_unparse_ipv6(&ss->remote_addr));
    unsigned char serve_cfg_tmp_path[PATH_MAX];
    snprintf(serve_cfg_tmp_path, sizeof(serve_cfg_tmp_path), "%s.tmp", serve_cfg_path);
    int save_status = super_html_serve_unparse_and_save(serve_cfg_path, serve_cfg_tmp_path, ss,
                                                        ejudge_config, NULL,
                                                        serve_header, serve_footer, serve_audit_rec);
    if (save_status < 0) {
        fatal2("cannot save serve.cfg");
        goto cleanup;
    }

    for (int i = 0; i < pi->u; ++i) {
        struct problem_info *p = &pi->p[i];
        if (p->is_bad || !p->cfg) continue;
        unsigned char dst_path[PATH_MAX];
        snprintf(dst_path, sizeof(dst_path), "%s/%s", problems_dir, p->dir_name);
        if (rename(p->problem_dir, dst_path) < 0) {
            fatal2("rename: %s->%s failed: %s", p->problem_dir, dst_path, os_ErrorMsg());
            p->is_bad = 1;
            continue;
        }
    }

    if (save_status > 0 && rename(serve_cfg_tmp_path, serve_cfg_path) < 0) {
        fatal2("rename: %s->%s failed: %s", serve_cfg_tmp_path, serve_cfg_path, os_ErrorMsg());
        goto cleanup;
    }

    // FIXME: free resources
    // ...

    // load the current contest configuration file, again
    rw_cnts = NULL;
    if (contests_load(contest_id, &rw_cnts) < 0 || !rw_cnts) {
        fatal2("cannot load contest XML file");
        goto cleanup;
    }
    snprintf(serve_cfg_path, sizeof(serve_cfg_path), "%s/%s", conf_dir, SERVE_CFG);
    if (super_html_read_serve(log_f, serve_cfg_path, ejudge_config, cnts, ss) < 0) {
        fatal2("cannot open serve.cfg for reading");
        goto cleanup;
    }

    for (int i = 1; i < ss->prob_a; ++i) {
        struct section_problem_data *prob = ss->probs[i];
        if (!prob) continue;
        info("generating makefile for '%s'", prob->short_name);
        generate_makefile(ss, cnts, prob);
    }

    if (exit_code > 0) goto cleanup;

    for (int i = 1; i < ss->prob_a; ++i) {
        struct section_problem_data *prob = ss->probs[i];
        if (!prob) continue;
        info("performing 'make clean' for problem '%s'", prob->short_name);
        unsigned char problem_dir[PATH_MAX];
        get_advanced_layout_path(problem_dir, sizeof(problem_dir), ss->global, prob, NULL, -1);
        char *args[10];
        args[0] = "/usr/bin/make";
        args[1] = "clean";
        args[2] = NULL;
        xfree(stdout_text); stdout_text = NULL;
        xfree(stderr_text); stderr_text = NULL;
        int r = ejudge_invoke_process(args, NULL, problem_dir, "/dev/null", NULL, 0, &stdout_text, &stderr_text);
        if (stdout_text) {
            fprintf(log_f, "Stdout: %s\n", stdout_text);
        }
        if (stderr_text) {
            fprintf(log_f, "Stderr: %s\n", stderr_text);
        }
        if (r) {
            error("'make clean' failed");
        }
    }

    if (exit_code > 0) goto cleanup;

    for (int i = 1; i < ss->prob_a; ++i) {
        struct section_problem_data *prob = ss->probs[i];
        if (!prob) continue;
        info("performing 'make all' for problem '%s'", prob->short_name);
        unsigned char problem_dir[PATH_MAX];
        get_advanced_layout_path(problem_dir, sizeof(problem_dir), ss->global, prob, NULL, -1);
        char *args[10];
        args[0] = "/usr/bin/make";
        args[1] = "all";
        args[2] = NULL;
        xfree(stdout_text); stdout_text = NULL;
        xfree(stderr_text); stderr_text = NULL;
        int r = ejudge_invoke_process(args, NULL, problem_dir, "/dev/null", NULL, 0, &stdout_text, &stderr_text);
        if (stdout_text) {
            fprintf(log_f, "Stdout: %s\n", stdout_text);
        }
        if (stderr_text) {
            fprintf(log_f, "Stderr: %s\n", stderr_text);
        }
        if (r) {
            error("'make all' failed");
        }
    }

    if (!exit_code) {
        contest_update_time = time(NULL);
        contest_problem_count = 0;
        for (int i = 1; i < ss->prob_a; ++i) {
            struct section_problem_data *prob = ss->probs[i];
            if (!prob) continue;
            ++contest_problem_count;
        }
    }

cleanup:;
    update_contest_xml(contest_id, ss, !exit_code, contest_update_time, contest_problem_count);
    xfree(serve_header);
    xfree(serve_footer);
    xfree(stdout_text);
    xfree(stderr_text);
    pi = problems_info_free(pi);
    if (working_dir[0] && stat(working_dir, &stb) >= 0) {
        remove_directory_recursively(working_dir, 0);
    }
}

static struct sid_state*
sid_state_create(
        ej_cookie_t sid,
        const ej_ip_t *remote_addr,
        int user_id,
        const unsigned char *user_login,
        const unsigned char *user_name)
{
  struct sid_state *n;

  XCALLOC(n, 1);
  n->sid = sid;
  n->remote_addr = *remote_addr;
  n->init_time = time(0);
  n->flags |= SID_STATE_SHOW_CLOSED;
  n->user_id = user_id;
  n->user_login = xstrdup(user_login);
  n->user_name = xstrdup(user_name);

  return n;
}

int
main(int argc, char **argv)
{
    unsigned long required_solution_mask = 0;

    progname = os_GetLastname(argv[0]);

    int cur_arg = 1;
    while (cur_arg < argc) {
        if (!strcmp(argv[cur_arg], "--version")) {
            report_version();
        } else if (!strcmp(argv[cur_arg], "--help")) {
            report_help();
        } else if (!strcmp(argv[cur_arg], "--")) {
            ++cur_arg;
            break;
        } else if (argv[cur_arg][0] == '-') {
            fatal("invalid option '%s'", argv[cur_arg]);
        } else {
            break;
        }
    }

    if (cur_arg >= argc) {
        fatal("packet path is expected");
    }
    if (cur_arg < argc - 1) {
        fatal("too many arguments");
    }

    FILE *f = fopen(argv[cur_arg], "r");
    if (!f) {
        fatal("cannot open packet file '%s'", argv[cur_arg]);
    }

    struct ej_import_packet *pkt = ej_import_packet_parse(argv[cur_arg], f);
    f = NULL;
    if (!pkt) {
        fatal("failed to parse packet file '%s'", argv[cur_arg]);
    }

    if (pkt->log_file) {
        log_f = fopen(pkt->log_file, "w");
        if (!log_f) fatal("cannot open log file '%s': %s", pkt->log_file, os_ErrorMsg());
    } else {
        log_f = stderr;
    }

    if (pkt->pid_file) {
        FILE *f = fopen(pkt->pid_file, "w");
        if (!f) fatal2("'pid_file' path '%s' cannot be opened for write", pkt->pid_file);
        fprintf(f, "%d\n", getpid());
        fflush(f);
        if (ferror(f)) fatal2("'pid_file' path '%s' write error", pkt->pid_file);
        fclose(f); f = NULL;
    }

    if (!pkt->remote_addr) pkt->remote_addr = xstrdup("127.0.0.1");
    ej_ip_t ip;
    if (xml_parse_ipv6(NULL, NULL, 0, 0, pkt->remote_addr, &ip) < 0) {
        fatal2("invalid IP-address '%s'", pkt->remote_addr);
    }
    if (pkt->user_id <= 0) {
        pkt->user_id = getuid();
        struct passwd *pwd = getpwuid(pkt->user_id);
        if (!pwd) {
            fatal2("user with uid %d is not in the system database", pkt->user_id);
        } else {
            pkt->user_login = xstrdup(pwd->pw_name);
            pkt->user_name = xstrdup(pwd->pw_gecos);
        }
    } else {
        if (!pkt->user_login) {
            unsigned char buf[256];
            snprintf(buf, sizeof(buf), "ejudge_user_%d", pkt->user_id);
            pkt->user_login = xstrdup(buf);
        }
        if (!pkt->user_name) {
            unsigned char buf[256];
            snprintf(buf, sizeof(buf), "Ejudge user %d", pkt->user_id);
            pkt->user_name = xstrdup(buf);
        }
    }

    if (pkt->required_solutions) {
        for (int i = 0; pkt->required_solutions[i]; ++i) {
            unsigned long mask = build_find_suffix(pkt->required_solutions[i]);
            if (!mask) {
                fatal2("source suffix '%s' is not supported", pkt->required_solutions[i]);
            }
            required_solution_mask |= mask;
        }
    }

    if (pkt->require_master_solution < 0) pkt->require_master_solution = 0;
    if (pkt->require_test_checker < 0) pkt->require_test_checker = 0;

    struct sid_state *ss = sid_state_create(0ULL, &ip, pkt->user_id, pkt->user_login, pkt->user_name);

    if (!exit_code) {
        do_import_contest(pkt->contest_id, ss, pkt->archive_file, pkt->content_type,
                          pkt->require_master_solution, required_solution_mask, pkt->require_test_checker);
    }

    if (pkt->status_file) {
        FILE *f = fopen(pkt->status_file, "w");
        if (!f) fatal2("'status_file' path '%s' cannot be opened for write", pkt->status_file);
        fprintf(f, "%d\n", exit_code);
        fflush(f);
        if (ferror(f)) fatal2("'status_file' path '%s' write error", pkt->status_file);
        fclose(f); f = NULL;
    }

    if (pkt->pid_file) {
        unlink(pkt->pid_file);
    }

    if (log_f != stderr) {
        fclose(log_f);
    }
    log_f = NULL;

    return exit_code;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
