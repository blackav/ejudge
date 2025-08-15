/* -*- mode: c -*- */

/* Copyright (C) 2025 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/misctext.h"
#include "ejudge/polygon_xml.h"
#include "ejudge/problem_config.h"
#include "ejudge/version.h"
#include "ejudge/depgraph.h"
#include "ejudge/safe_format.h"
#include "ejudge/xalloc.h"
#include "ejudge/checksum.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static const unsigned char *program_name = "";

static void
get_program_name(const unsigned char *arg0)
{
    if (!arg0) {
        fprintf(stderr, "no program name\n");
        exit(1);
    }
    char *s = strrchr(arg0, '/');
    if (s) {
        program_name = s + 1;
    } else {
        program_name = arg0;
    }
}

static __attribute__((noreturn,format(printf, 1, 2))) void
die(const char *format, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    fprintf(stderr, "%s:fatal:%s\n", program_name, buf);
    exit(1);
}

static __attribute__((noreturn)) void
print_version(void)
{
    printf("%s: ejudge version %s compiled %s\n",
            program_name, compile_version, compile_date);
    exit(0);
}

static const unsigned char help_str[] =
"--version                print the version and exit\n"
"--help                   print this help and exit\n"
"--                       stop option processing\n"
;

static __attribute__((noreturn)) void
print_help(void)
{
    printf("%s usage: execute [OPTIONS]... program [ARGUMENTS]...\n", program_name);
    fputs(help_str, stdout);
    exit(0);
}

static const unsigned char valid_filename_chars[256] =
{
    ['!'] = 1,
    ['%'] = 1,
    ['+'] = 1,
    [','] = 1,
    ['-'] = 1,
    ['.'] = 1,
    ['/'] = 1,
    ['0' ... '9'] = 1,
    [':'] = 1,
    ['='] = 1,
    ['@'] = 1,
    ['A' ... 'Z'] = 1,
    ['['] = 1,
    [']'] = 1,
    ['^'] = 1,
    ['_'] = 1,
    ['a' ... 'z'] = 1,
    ['~'] = 1,
    [128 ... 255] = 1,
};

static _Bool
is_valid_path(const unsigned char *s)
{
    if (!s) return 0;
    size_t len = strlen(s);
    if (!len) return 0;
    if (!is_valid_utf8(s, len, NULL)) return 0;
    const unsigned char *p = s;
    while (*p) {
        if (!valid_filename_chars[*p]) return 0;
        ++p;
    }
    if (s[0] == '.' && s[1] == '.' && (!s[2] || s[2] == '/')) return 0;
    if (len <= 2) return 1;
    if (p[-1] == '.' && p[-2] == '.' && p[-3] == '/') return 0;
    if (strstr(s, "/../")) return 0;
    return 1;
}

static int
read_full_file(FILE *log_f, const unsigned char *path, unsigned char **p_str, size_t *p_size)
{
    FILE *fin = fopen(path, "r");
    if (!fin) {
        return -1;
    }
    char *str = NULL;
    size_t size = 0;
    FILE *fout = open_memstream(&str, &size);
    if (!fout) {
        fclose(fin);
        return -1;
    }
    int c;
    while ((c = getc_unlocked(fin)) != EOF) {
        putc_unlocked(c, fout);
    }
    fclose(fin);
    fclose(fout);
    *p_str = str;
    *p_size = size;
    return 0;
}

static const unsigned char problem_cfg_name[] = "problem.cfg";

#define L_ERR(format, ...) fprintf(log_f, "%s:%d:" format "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

static int
split_path(
        FILE *log_f,
        const unsigned char *param_name,
        const unsigned char *path,
        unsigned char *dir, size_t dirlen,
        unsigned char *name, size_t namelen)
{
    size_t len = strlen(path);
    if (!len) {
        L_ERR("%s:empty path", param_name);
        return -1;
    }
    if (path[0] == '/') {
        L_ERR("%s:path '%s' must be relative", param_name, path);
        return -1;
    }
    if (path[len-1] == '/') {
        L_ERR("%s:path '%s' must not end with '/'", param_name, path);
        return -1;
    }
    size_t i = len;
    while (i > 0 && path[i-1] != '/') --i;
    if (!i) {
        // no directory part
        if (len - i >= namelen) {
            L_ERR("%s:path '%s' name part is too long", param_name, path);
            return -1;
        }
        if (dirlen > 0) dir[0] = 0;
        strcpy(name, path + i); // buffer size is checked
        return 0;
    }
    size_t j = i;
    while (j > 0 && path[j-1] == '/') --j;
    if (!j) {
        L_ERR("%s:path '%s' must be relative", param_name, path);
        return -1;
    }
    if (j >= dirlen) {
        L_ERR("%s:path '%s' directory part is too long", param_name, path);
        return -1;
    }
    if (len - i >= namelen) {
        L_ERR("%s:path '%s' name part is too long", param_name, path);
        return -1;
    }
    // buffer sizes are checked
    memcpy(dir, path, j); dir[j] = 0;
    strcpy(name, path + i);
    return 0;
}

static int
split_suffix(
        FILE *log_f,
        const unsigned char *param_name,
        const unsigned char *path,
        unsigned char *base, size_t baselen,
        unsigned char *suffix, size_t sufflen)
{
    size_t pathlen = strlen(path);
    size_t i = pathlen;
    size_t exp_baselen, exp_sufflen;
    while (i > 0 && path[i-1] != '/' && path[i-1] != '.') --i;
    if (i == 0 || path[i-1] == '/') {
        exp_baselen = pathlen;
        exp_sufflen = 0;
    } else if (i == 1) {
        // name starts with dot
        exp_baselen = pathlen;
        exp_sufflen = 0;
    } else if (i >= 2 && path[i-2] == '/') {
        // dot after slash
        exp_baselen = pathlen;
        exp_sufflen = 0;
    } else {
        exp_baselen = i - 1;
        exp_sufflen = pathlen - exp_baselen;
    }
    if (exp_baselen >= baselen) {
        L_ERR("base name is too long");
        return -1;
    }
    if (exp_sufflen >= sufflen) {
        L_ERR("suffix is too long");
        return -1;
    }
    // lengths are checked
    memcpy(base, path, exp_baselen);
    base[exp_baselen] = 0;
    memcpy(suffix, &path[i-1], exp_sufflen);
    suffix[exp_sufflen] = 0;
    return 0;
}

static _Bool
is_simple_name(const unsigned char *s)
{
    return !strchr(s, '/');
}

struct test_state
{
    const struct ppxml_test *xml_test;
    int serial;
    unsigned char method;
    unsigned char *generator;
};

struct language_profile_info
{
    const unsigned char *name;
    const unsigned char *command;
};

struct language_info
{
    const unsigned char *suffix;
    const unsigned char *name;
    const unsigned char *default_solution_profile;
    const unsigned char *default_checker_profile;
    const struct language_profile_info * const profiles;
};

struct problem_state
{
    struct ppxml_problem *ppxml;
    struct depgraph dg;

    struct test_state *tests;
    size_t test_a;
    size_t test_u;

    struct problem_config_section *cfg;

    size_t solution_exe_index;
};

static const struct language_profile_info c_profiles[] =
{
    {
        "gcc-gnu18-debug-sanitizers",
        "gcc -std=gnu18 -Wall -Werror -g -D_GNU_SOURCE -fsanitize=undefined,address,leak ${source} -o${target} -lm",
    },
    {
        "gcc-gnu18-release",
        "gcc -std=gnu18 -Wall -Werror -O2 -D_GNU_SOURCE ${source} -o${target} -lm",
    },
    {
        "gcc-gnu18-release-ejudge",
        "gcc -std=gnu18 -Wall -Werror -O2 -D_GNU_SOURCE -DEJUDGE ${source} -o${target} -lm",
    },
    {
        NULL,
        NULL,
    },
};

static const struct language_info languages[] =
{
    {
        ".c",
        "C",
        "gcc-gnu18-debug-sanitizers",
        "gcc-gnu18-release-ejudge",
        c_profiles,
    },
    {
        NULL,
    },
};

static const struct language_info *
find_language(const unsigned char *suffix)
{
    for (size_t i = 0; languages[i].suffix; ++i) {
        if (!strcmp(languages[i].suffix, suffix))
            return &languages[i];
    }
    return NULL;
}

static const struct language_profile_info *
find_profile(const struct language_info *lang, const unsigned char *profile)
{
    for (size_t i = 0; lang->profiles[i].name; ++i) {
        if (!strcmp(lang->profiles[i].name, profile))
            return &lang->profiles[i];
    }
    return NULL;
}

static struct test_state *
push_test(struct problem_state *ps)
{
    if (ps->test_u == ps->test_a) {
        if (!ps->test_a) {
            ps->test_a = 16;
            XCALLOC(ps->tests, ps->test_a);
        } else {
            ps->test_a *= 2;
            XREALLOC(ps->tests, ps->test_a);
        }
    }
    struct test_state *t = &ps->tests[ps->test_u++];
    XMEMZERO(t, 1);
    return t;
}

static int
check_file(
        FILE *log_f,
        const unsigned char *path)
{
    struct stat stb;
    int r;
    size_t size = 0;
    unsigned char *mem = MAP_FAILED;
    int fd = -1;
    int retval = -1;
    size_t err_offset = 0;

    r = lstat(path, &stb);
    if (r < 0) {
        L_ERR("file '%s' is invalid: %s", path, strerror(errno));
        goto done;
    }
    if (stb.st_size <= 0) {
        return 0;
    }
    if (!S_ISREG(stb.st_mode)) {
        L_ERR("file '%s' is not regular", path);
        goto done;
    }
    size = stb.st_size;
    if (size != stb.st_size) {
        L_ERR("file '%s' is too big: %lld", path, (long long) stb.st_size);
        goto done;
    }
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        L_ERR("failed to open file '%s': %s", path, strerror(errno));
        goto done;
    }
    mem = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mem == MAP_FAILED) {
        L_ERR("failed to map file '%s': %s", path, strerror(errno));
        goto done;
    }
    close(fd); fd = -1;
    // FIXME: check binary flag
    if (text_is_binary(mem, size)) {
        L_ERR("file '%s' is not text", path);
        goto done;
    }
    // FIXME: check utf-8 flag
    if (!is_valid_utf8(mem, size, &err_offset)) {
        L_ERR("file '%s' is not UTF-8 at offset %zu", path, err_offset);
        goto done;
    }
    // FIXME: check normalization flag
    if (!is_text_normalized(mem, size,
        TEXT_FIX_CR|TEXT_FIX_TR_SP|TEXT_FIX_FINAL_NL|TEXT_FIX_TR_NL|TEXT_FIX_NP,
        &err_offset)) {
        L_ERR("file '%s' is not normalized %zu", path, err_offset);
        goto done;
    }
    munmap(mem, size);
    retval = 0;

done:;
    if (fd >= 0) close(fd);
    if (mem != MAP_FAILED) munmap(mem, size);
    return retval;
}

static int
collect_tests(
        FILE *log_f,
        struct problem_state *ps)
{
    int r;
    unsigned char test_dir[PATH_MAX];
    unsigned char corr_dir[PATH_MAX];
    //unsigned char info_dir[PATH_MAX];
    //unsigned char tgz_dir[PATH_MAX];
    //unsigned char tgzdir_dir[PATH_MAX];
    unsigned char test_pat[PATH_MAX];
    unsigned char corr_pat[PATH_MAX];
    unsigned char test_name[64];
    unsigned char corr_name[64];
    unsigned char test_path[PATH_MAX];
    unsigned char corr_path[PATH_MAX];

    corr_pat[0] = 0;

    static const safe_format_type_t format_types[] =
    {
        SAFE_FORMAT_INT,
        0,
    };

    const struct ppxml_judging *ppj = ps->ppxml->judging;
    if (!ppj) return 0;
    if (ppj->testsets.u != 1) {
        L_ERR("judging section must specify exactly one testset");
        return -1;
    }
    const struct ppxml_testset *ppts = ppj->testsets.v[0];
    const struct ppxml_path_pattern *input = ppts->input;

    if (input->pattern && input->pattern[0]) {
        if ((r = split_path(log_f, "input_path_pattern", input->pattern, test_dir, sizeof test_dir, test_pat, sizeof test_pat)) < 0) {
            return r;
        }
        if (safe_format_validate(format_types, test_pat) < 0) {
            L_ERR("invalid test file format '%s'", input->pattern);
            return -1;
        }
        if (snprintf(test_name, sizeof(test_name), test_pat, INT_MAX) >= (int) sizeof(test_name)) {
            L_ERR("invalid test file format '%s'", input->pattern);
            return -1;
        }
    }

    if (!test_dir[0]) snprintf(test_dir, sizeof test_dir, ".");

    struct stat stb;
    if (lstat(test_dir, &stb) < 0) {
        L_ERR("test directory '%s' invalid: %s", test_dir, strerror(errno));
        return -1;
    }
    if (!S_ISDIR(stb.st_mode)) {
        L_ERR("test directory '%s' invalid: not a directory", test_dir);
        return -1;
    }

    const struct ppxml_path_pattern *answer = ppts->answer;
    if (answer->pattern && answer->pattern[0]) {
        if ((r = split_path(log_f, "answer_path_pattern", answer->pattern, corr_dir, sizeof corr_dir, corr_pat, sizeof corr_pat)) < 0) {
            return r;
        }
        if (strcmp(corr_dir, test_dir) != 0) {
            L_ERR("test directory '%s' and answer directory '%s' must be the same", test_dir, corr_dir);
            return -1;
        }
        if (safe_format_validate(format_types, corr_pat) < 0) {
            L_ERR("invalid answer file format '%s'", answer->pattern);
            return -1;
        }
        if (snprintf(corr_name, sizeof(corr_name), corr_pat, INT_MAX) >= (int) sizeof(corr_name)) {
            L_ERR("invalid answer file format '%s'", answer->pattern);
            return -1;
        }
    }

    int auto_test_count = -1;
    if (ppts->auto_count > 0) {
        int current = 0;
        while (1) {
            ++current;
            if (snprintf(test_name, sizeof(test_name), test_pat, current) >= (int) sizeof(test_name)) {
                L_ERR("invalid test file format '%s'", input->pattern);
                return -1;
            }
            if (snprintf(test_path, sizeof test_path, "%s/%s", test_dir, test_name) >= (int) sizeof(test_path)) {
                L_ERR("test path is too long");
                return -1;
            }
            if (lstat(test_path, &stb) < 0) {
                auto_test_count = current - 1;
                break;
            }
            if (!S_ISREG(stb.st_mode)) {
                L_ERR("file '%s' is not regular", test_path);
                return -1;
            }
        }
    }

    // auto-counted tests are manual
    int test_number = 1;
    for (int i = 0; i < ppts->tests->n.u; ++i, ++test_number) {
        const struct ppxml_test *ppt = ppts->tests->n.v[i];
        unsigned char method = ppt->method;
        struct test_state *t = push_test(ps);
        t->serial = test_number;
        t->xml_test = ppt;
        t->method = method;
    }
    if (auto_test_count >= test_number) {
        while (test_number <= auto_test_count) {
            struct test_state *t = push_test(ps);
            t->serial = test_number;
            t->method = PPXML_METHOD_MANUAL;
            ++test_number;
        }
    }

    // check test
    for (size_t i = 0; i < ps->test_u; ++i) {
        struct test_state *t = &ps->tests[i];
        if (snprintf(test_name, sizeof(test_name), test_pat, t->serial) >= (int) sizeof(test_name)) {
            L_ERR("invalid test file format '%s'", input->pattern);
            return -1;
        }
        if (snprintf(test_path, sizeof test_path, "%s/%s", test_dir, test_name) >= (int) sizeof(test_path)) {
            L_ERR("test path is too long");
            return -1;
        }

        if (corr_pat[0]) {
            if (snprintf(corr_name, sizeof(corr_name), corr_pat, t->serial) >= (int) sizeof(corr_name)) {
                L_ERR("invalid answer file format '%s'", answer->pattern);
                return -1;
            }
            if (snprintf(corr_path, sizeof corr_path, "%s/%s", corr_dir, corr_name) >= (int) sizeof(corr_path)) {
                L_ERR("answer path is too long");
                return -1;
            }
        }

        struct depgraph_file *tdf = depgraph_add_file(&ps->dg, test_path);

        if (t->method == PPXML_METHOD_GENERATED) {
            if (!t->xml_test->cmd || !t->xml_test->cmd[0]) {
                L_ERR("generation command for test '%s' is undefined", test_name);
                return -1;
            }
            strarray_t cc = {};
            if (split_cmdline(t->xml_test->cmd, &cc) < 0 || !cc.u || !cc.v[0] || !cc.v[0][0]) {
                L_ERR("invalid generation command for test '%s'", test_name);
                return -1;
            }
            t->generator = xstrdup(cc.v[0]);
            xstrarrayfree(&cc);
            struct depgraph_file *gen = depgraph_add_file(&ps->dg, t->generator);
            depgraph_add_dependency(tdf, gen);
            if (corr_pat[0]) {
                struct depgraph_file *ans = depgraph_add_file(&ps->dg, corr_path);
                depgraph_add_dependency(ans, tdf);
                if (!ps->solution_exe_index) {
                    L_ERR("main solution is undefined");
                    return -1;
                }
                struct depgraph_file *sol = &ps->dg.files[ps->solution_exe_index];
                depgraph_add_dependency(ans, sol);
                const unsigned char *sol_path = "";
                if (is_simple_name(sol->path)) {
                    sol_path = "./";
                }
                char *cmd = NULL;
                asprintf(&cmd, "%s%s < %s > %s", sol_path, sol->path, tdf->path, ans->path);
                depgraph_add_command_move(ans, cmd);
            }
            continue;
        }
        if (lstat(test_path, &stb) < 0) {
            L_ERR("manual test '%s' does not exist", test_name);
            return -1;
        }
        if (check_file(log_f, test_path) < 0) {
            return -1;
        }
        if (corr_pat[0] && ppts->generate_answer > 0) {
            struct depgraph_file *ans = depgraph_add_file(&ps->dg, corr_path);
            depgraph_add_dependency(ans, tdf);
            if (!ps->solution_exe_index) {
                L_ERR("main solution is undefined");
                return -1;
            }
            struct depgraph_file *sol = &ps->dg.files[ps->solution_exe_index];
            depgraph_add_dependency(ans, sol);
            const unsigned char *sol_path = "";
            if (is_simple_name(sol->path)) {
                sol_path = "./";
            }
            char *cmd = NULL;
            asprintf(&cmd, "%s%s < %s > %s", sol_path, sol->path, tdf->path, ans->path);
            depgraph_add_command_move(ans, cmd);
        } else if (corr_pat[0]) {
            depgraph_add_file(&ps->dg, corr_path);
            if (lstat(corr_path, &stb) < 0) {
                L_ERR("manual answer '%s' does not exist", corr_name);
                return -1;
            }
            if (check_file(log_f, corr_path) < 0) {
                return -1;
            }
        }
    }

    return 0;
}

struct variable_list
{
    const unsigned char * const * const names;
    const unsigned char * const * values;
};

static unsigned char *
find_in_variable_list(const void *p, const unsigned char *name)
{
    const struct variable_list *pp = (const struct variable_list *) p;
    size_t i = 0;
    while (pp->names[i] && strcmp(pp->names[i], name)) ++i;
    if (!pp->names[i]) return NULL;
    return xstrdup(pp->values[i]);
}

static unsigned char *
substitute_rule_vars(
        const unsigned char *pattern,
        const unsigned char *source,
        const unsigned char *target)
{
    static const unsigned char * const var_names[] =
    {
        "source",
        "target",
        NULL,
    };
    const unsigned char * const var_values[] =
    {
        source,
        target,
        NULL,
    };
    struct variable_list vars =
    {
        var_names,
        var_values,
    };
    return text_substitute(&vars, pattern, find_in_variable_list);
}

static int
collect_dependencies(
        FILE *log_f,
        struct problem_state *ps)
{
    struct ppxml_problem *ppxml = ps->ppxml;
    if (ppxml->statements) {
        for (size_t i = 0; i < ppxml->statements->n.u; ++i) {
            struct ppxml_statement *s = ppxml->statements->n.v[i];
            depgraph_add_file(&ps->dg, s->path);
        }
    }
    if (ppxml->files && ppxml->files->resources) {
        struct ppxml_resources *r = ppxml->files->resources;
        for (size_t i = 0; i < r->n.u; ++i) {
            depgraph_add_file(&ps->dg, r->n.v[i]->path);
        }
    }
    if (ppxml->judging && ppxml->judging->extra_config > 0) {
        struct depgraph_file *pcfg = depgraph_find_file(&ps->dg, problem_cfg_name);
        if (!pcfg) {
            L_ERR("extra problem configuration file '%s' not found", problem_cfg_name);
            return -1;
        }
        FILE *f = fopen(pcfg->path, "r");
        if (!f) {
            L_ERR("cannot open configuration file '%s': %s", pcfg->path, strerror(errno));
            return -1;
        }
        ps->cfg = problem_config_section_parse_cfg(pcfg->path, f);
        if (!ps->cfg) {
            L_ERR("failed to parse configuration file '%s'", pcfg->path);
            return -1;
        }
        f = NULL;
    }

    if (ppxml->assets && ppxml->assets->solutions) {
        struct ppxml_solutions *ppsols = ppxml->assets->solutions;
        for (size_t i = 0; i < ppsols->n.u; ++i) {
            struct ppxml_solution *ppsol = ppsols->n.v[i];
            if (ppsol->tag == PPXML_SOLUTION_TAG_MAIN) {
                if (!ppsol->source) {
                    L_ERR("main solution source code not available");
                    return -1;
                }
                if (!is_valid_path(ppsol->source->path)) {
                    L_ERR("invalid source path '%s'", ppsol->source->path);
                    return -1;
                }
                struct depgraph_file *sf = depgraph_add_file(&ps->dg, ppsol->source->path);

                unsigned char source_base[PATH_MAX];
                unsigned char source_suffix[64];
                if (split_suffix(log_f, "source", ppsol->source->path, source_base, sizeof source_base, source_suffix, sizeof source_suffix) < 0) {
                    L_ERR("invalid source path");
                    return -1;
                }
                struct depgraph_file *xf = depgraph_add_file(&ps->dg, source_base);
                ps->solution_exe_index = xf->index;
                depgraph_add_dependency(xf, sf);

                const struct language_info *lang = find_language(source_suffix);
                if (!lang) {
                    L_ERR("no rule to compile source file '%s", ppsol->source->path);
                    return -1;
                }
                const struct language_profile_info *prof = find_profile(lang, lang->default_solution_profile);
                if (!prof) {
                    L_ERR("profile '%s' is undefined for language '%s'", lang->default_solution_profile, lang->name);
                    return -1;
                }

                unsigned char *cmd = substitute_rule_vars(prof->command, ppsol->source->path, source_base);
                if (!cmd) {
                    L_ERR("command substitution failed for '%s'", prof->command);
                    return -1;
                }
                depgraph_add_command_move(xf, cmd);
            }
        }
    }

    if (collect_tests(log_f, ps) < 0) {
        L_ERR("failed to collect tests");
        return -1;
    }
    return 0;
}

static int
print_makefile(FILE *log_f, struct problem_state *ps, char *args[])
{
    if (depgraph_topological_sort(&ps->dg) < 0) {
        L_ERR("circular dependencies detected");
        return -1;
    }
    for (size_t i = 0; i < ps->dg.sorted_u; ++i) {
        struct depgraph_file *df = &ps->dg.files[ps->dg.sorted[i]];
        if (!df->dep_u) continue;
        printf("%s :", df->path);
        for (size_t j = 0; j < df->dep_u; ++j) {
            struct depgraph_file *sf = &ps->dg.files[df->deps[j]];
            printf(" %s", sf->path);
        }
        printf("\n");
        for (size_t j = 0; j < df->cmd_u; ++j) {
            printf("\t%s\n", df->cmds[j].command);
        }
    }
    return 0;
}

static int
print_hash(FILE *log_f, struct problem_state *ps, char *args[])
{
    struct checksum_context cc = {};
    for (size_t i = 1; i < ps->dg.file_u; ++i) {
        if (!ps->dg.files[i].dep_u) {
            checksum_add_file(&cc, ps->dg.files[i].path);
        }
    }
    checksum_sort(&cc);
    checksum_compute(&cc, stderr);
    unsigned char hbuf[128];
    printf("%s\n", checksum_hex(&cc, hbuf));
    checksum_free(&cc);

    return 0;
}

static int
print_source_files(FILE *log_f, struct problem_state *ps, char *args[])
{
    struct checksum_context cc = {};
    for (size_t i = 1; i < ps->dg.file_u; ++i) {
        if (!ps->dg.files[i].dep_u) {
            checksum_add_file(&cc, ps->dg.files[i].path);
        }
    }
    checksum_sort(&cc);
    for (size_t i = 0; i < cc.path_u; ++i) {
        printf("%s\n", cc.paths[i]);
    }
    checksum_free(&cc);

    return 0;
}

struct tool_registry
{
    const unsigned char *name;
    int (*handler)(FILE *log_f, struct problem_state *ps, char *args[]);
};
static const struct tool_registry tools[] =
{
    { "print-hash", print_hash },
    { "print-makefile", print_makefile },
    { "print-source-files", print_source_files },
};

int
main(int argc, char *argv[])
{
    unsigned char *problem_xml_file = NULL;
    unsigned char *p_xml_s = NULL;
    size_t p_xml_z = 0;
    struct ppxml_problem *ppxml = NULL;
    struct problem_state ps = {};
    int (*tool)(FILE *log_f, struct problem_state *ps, char *args[]);

    get_program_name(argv[0]);

    int cur_arg = 1;
    while (cur_arg < argc) {
        if (!strcmp(argv[cur_arg], "--version")) {
            print_version();
        } else if (!strcmp(argv[cur_arg], "--help")) {
            print_help();
        } else if (!strcmp(argv[cur_arg], "--")) {
            ++cur_arg;
            break;
        } else if (argv[cur_arg][0] == '-') {
            die("invalid option '%s'", argv[cur_arg]);
        } else {
            break;
        }
    }
    if (cur_arg == argc) {
        die("tool expected");
    }
    for (size_t i = 0; i < sizeof(tools)/sizeof(tools[0]); ++i) {
        if (!strcmp(tools[i].name, argv[cur_arg])) {
            tool = tools[i].handler;
        }
    }
    if (!tool) {
        die("invalid tool '%s'", argv[cur_arg]);
    }
    ++cur_arg;
    problem_xml_file = "ejproblem.xml";
    if (read_full_file(stderr, problem_xml_file, &p_xml_s, &p_xml_z) < 0) {
        die("failed to read '%s'", problem_xml_file);
    }
    ppxml = ppxml_parse_str(stderr, problem_xml_file, p_xml_s);
    if (!ppxml) {
        die("failed to parse '%s'", problem_xml_file);
    }
    ps.ppxml = ppxml;
    depgraph_add_file(&ps.dg, problem_xml_file);
    if (collect_dependencies(stderr, &ps) < 0) {
        die("failed to collect dependencies");
    }

    int res = tool(stderr, &ps, &argv[cur_arg]);

    // TODO: free ps

    return res < 0;
}
