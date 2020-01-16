/* -*- c -*- */

/* Copyright (C) 2015-2016 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/dates_config.h"
#include "ejudge/meta_generic.h"
#include "ejudge/meta/dates_config_meta.h"

#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"

#include <limits.h>
#include <string.h>

#define XFSIZE(t, x) (sizeof(((t*) 0)->x))

#define GLOBAL_OFFSET(x)   XOFFSET(struct dates_global_data, x)
#define GLOBAL_SIZE(x)     XFSIZE(struct dates_global_data, x)
#define GLOBAL_PARAM(x, t) { #x, t, GLOBAL_OFFSET(x), GLOBAL_SIZE(x) }

static const __attribute__((unused)) struct config_parse_info dates_global_params[] =
{
    { 0, 0, 0, 0 }
};

#define PROBLEM_OFFSET(x)   XOFFSET(struct dates_problem_data, x)
#define PROBLEM_SIZE(x)     XFSIZE(struct dates_problem_data, x)
#define PROBLEM_PARAM(x, t) { #x, t, PROBLEM_OFFSET(x), PROBLEM_SIZE(x) }

static const __attribute__((unused)) struct config_parse_info dates_problem_params[] =
{
    { 0, 0, 0, 0 }
};

static void dates_global_init_func(struct generic_section_config *);
static void dates_global_free_func(struct generic_section_config *);
static void dates_problem_init_func(struct generic_section_config *);
static void dates_problem_free_func(struct generic_section_config *);

static const struct config_section_info dates_params[] =
{
    {
        "global", sizeof(struct dates_global_data), NULL, NULL,
        dates_global_init_func, dates_global_free_func,
        &meta_dates_global_data_methods,
    },
    {
        "problem", sizeof(struct dates_problem_data), NULL, NULL,
        dates_problem_init_func, dates_problem_free_func,
        &meta_dates_problem_data_methods,
    },

    { NULL, 0, NULL }
};

static void
dates_global_init_func(struct generic_section_config *gp)
{
}

static void
dates_global_free_func(struct generic_section_config *gp)
{
  if (gp) {
    meta_destroy_fields(&meta_dates_global_data_methods, gp);
    xfree(gp);
  }
}

static void
dates_problem_init_func(struct generic_section_config *gp)
{
}

static void
dates_problem_free_func(struct generic_section_config *gp)
{
  if (gp) {
    meta_destroy_fields(&meta_dates_problem_data_methods, gp);
    xfree(gp);
  }
}

struct dates_config *
dates_config_parse_cfg(const unsigned char *path, const unsigned char *main_path)
{
    unsigned char file_path[PATH_MAX];
    FILE *f = NULL;
    struct generic_section_config *cfg = NULL;
    struct dates_config *dcfg = NULL;

    if (!path || !*path) return NULL;
    if (!main_path || !*main_path) {
        snprintf(file_path, sizeof(file_path), "%s", path);
    } else if (path[0] == '/') {
        snprintf(file_path, sizeof(file_path), "%s", path);
    } else {
        unsigned char *rs = strrchr(main_path, '/');
        if (!rs || rs == main_path) {
            snprintf(file_path, sizeof(file_path), "%s", path);
        } else {
            snprintf(file_path, sizeof(file_path), "%.*s%s", (int)(rs - main_path + 1), main_path, path);
        }
    }

    if (!(f = fopen(file_path, "r"))) {
        err("dates_config_parse_cfg: cannot open '%s'", file_path);
        return NULL;
    }
    if (!(cfg = parse_param(file_path, f, dates_params, 1, 0, 0, NULL))) {
        return NULL;
    }
    f = NULL;

    XCALLOC(dcfg, 1);
    dcfg->list = cfg; cfg = NULL;

    for (const struct generic_section_config *p = dcfg->list; p; p = p->next) {
        if (!strcmp(p->name, "problem")) {
            const struct dates_problem_data *dp = (const struct dates_problem_data *) p;
            if (dp->abstract > 0) {
                ++dcfg->aprob_count;
            } else {
                ++dcfg->prob_count;
            }
        }
    }

    XCALLOC(dcfg->aprobs, dcfg->aprob_count + 1);
    XCALLOC(dcfg->probs, dcfg->prob_count + 1);

    int i = 0, ai = 0;
    for (struct generic_section_config *p = dcfg->list; p; p = p->next) {
        if (!p->name[0] || !strcmp(p->name, "global")) {
            if (dcfg->global) {
                err("dates_config_parse_cfg: multiple global section");
                goto fail;
            }
            dcfg->global = (struct dates_global_data *) p;
        } else if (!strcmp(p->name, "problem")) {
            struct dates_problem_data *dp = (struct dates_problem_data *) p;
            if (!dp->short_name || !*dp->short_name) {
                err("dates_config_parse_cfg: short_name unspecified");
                goto fail;
            }
            for (int j = 0; j < i; ++j) {
                if (!strcmp(dcfg->probs[j]->short_name, dp->short_name)) {
                    err("dates_config_parse_cfg: short_name '%s' not unique", dp->short_name);
                    goto fail;
                }
            }
            for (int j = 0; j < ai; ++j) {
                if (!strcmp(dcfg->aprobs[j]->short_name, dp->short_name)) {
                    err("dates_config_parse_cfg: short_name '%s' not unique", dp->short_name);
                    goto fail;
                }
            }
            if (dp->abstract > 0) {
                dcfg->aprobs[ai++] = dp;
            } else {
                dcfg->probs[i++] = dp;
            }
        }
    }

    for (i = 0; i < dcfg->aprob_count; ++i) {
        if (dcfg->aprobs[i]->super) {
            err("dates_config_parse_cfg: super cannot be used in abstract problems");
            goto fail;
        }
        if (dcfg->aprobs[i]->use_dates_of) {
            err("dates_config_parse_cfg: use_dates_of cannot be used in abstract problems");
            goto fail;
        }
    }
    for (int i = 0; i < dcfg->prob_count; ++i) {
        struct dates_problem_data *prob = dcfg->probs[i];
        if (prob->use_dates_of) {
            if (prob->super) {
                err("dates_config_parse_cfg: super must not be set if use_dates_of set");
                goto fail;
            }
            struct dates_problem_data *uprob = NULL;
            for (int j = 0; j < dcfg->prob_count; ++j)
                if (!strcmp(dcfg->probs[j]->short_name, prob->use_dates_of)) {
                    uprob = dcfg->probs[j];
                    break;
                }
            if (!uprob) {
                err("dates_config_parse_cfg: concrete problem '%s' is undefined", prob->use_dates_of);
                goto fail;
            }
            if (uprob == prob) {
                err("dates_config_parse_cfg: use_dates_of '%s' refers to itself", prob->use_dates_of);
                goto fail;
            }
            prob->use_dates_of_ref = uprob;
        }
        if (prob->super) {
            struct dates_problem_data *aprob = NULL;
            for (int j = 0; j < dcfg->aprob_count; ++j) {
                if (!strcmp(dcfg->aprobs[j]->short_name, prob->super)) {
                    aprob = dcfg->aprobs[j];
                    break;
                }
            }
            if (!aprob) {
                err("dates_config_parse_cfg: abstract problem '%s' is undefined", prob->super);
                goto fail;
            }
            prob->super_ref = aprob;
        }
    }

    for (int i = 0; i < dcfg->prob_count; ++i) {
        struct dates_problem_data *prob = dcfg->probs[i];
        if (prob->use_dates_of_ref && prob->use_dates_of_ref->use_dates_of_ref) {
            err("dates_config_parse_cfg: use_dates_of refers to problem with use_dates_of set");
            goto fail;
        }
    }

    return dcfg;

fail:
    dates_config_free(dcfg);
    return NULL;
}

struct dates_config *
dates_config_free(struct dates_config *cfg)
{
    if (!cfg) return NULL;

    xfree(cfg->probs);
    xfree(cfg->aprobs);
    for (struct generic_section_config *p = cfg->list; p;) {
        struct generic_section_config *q = p;
        p = p->next;

        if (!*q->name || !strcmp(q->name, "global")) {
            dates_global_free_func(q);
        } else if (!strcmp(q->name, "problem")) {
            dates_problem_free_func(q);
        } else {
            abort();
        }
    }
    memset(cfg, 0, sizeof(*cfg));
    xfree(cfg);

    return NULL;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
