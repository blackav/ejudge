/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2022-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/version.h"

#include "ejudge/ejudge_cfg.h"
#include "ejudge/contests.h"
#include "ejudge/serve_state.h"
#include "ejudge/prepare.h"
#include "ejudge/team_extra.h"
#include "ejudge/xuser_plugin.h"
#include "ejudge/xml_utils.h"
#include "ejudge/base64.h"
#include "ejudge/compat.h"
#include "ejudge/osdeps.h"
#include "ejudge/xalloc.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>

static const char *program_name;

static void die(const char *format, ...)
  __attribute__((noreturn, format(printf, 1, 2)));
static void die(const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: %s\n", program_name, buf);
  exit(1);
}

static int
sort_func(const void *p1, const void *p2)
{
    int v1 = *(const int*) p1;
    int v2 = *(const int*) p2;
    if (v1 < v2) return -1;
    return v1 > v2;
}

static void
process_contest(
        struct ejudge_cfg *ejudge_config,
        int contest_id,
        const unsigned char *from_plugin,
        const unsigned char *to_plugin,
        int remove_mode,
        int force_from_mode)
{
    unsigned char config_path[PATH_MAX] = {};
    serve_state_t state = NULL;
    const struct section_global_data *global = NULL;
    struct xuser_cnts_state *old_xuser_state = NULL;
    struct xuser_cnts_state *new_xuser_state = NULL;
    int user_idz = 0;
    int *user_ids = NULL;

    const struct contest_desc *cnts = NULL;
    if (contests_get(contest_id, &cnts) < 0 || !cnts) {
        fprintf(stderr, "failed to load contest %d\n", contest_id);
        goto done;
    }

    if (cnts->conf_dir && os_IsAbsolutePath(cnts->conf_dir)) {
        snprintf(config_path, sizeof(config_path), "%s/serve.cfg", cnts->conf_dir);
    } else {
        if (!cnts->root_dir) {
            fprintf(stderr, "contest %d root dir is not set\n", contest_id);
            goto done;
        }
        if (!os_IsAbsolutePath(cnts->root_dir)) {
            fprintf(stderr, "contest %d root dir is not absolute\n", contest_id);
            goto done;
        }
        const char *conf_dir = cnts->conf_dir;
        if (!conf_dir) conf_dir = "conf";
        snprintf(config_path, sizeof(config_path),
                 "%s/%s/serve.cfg", cnts->root_dir, conf_dir);
    }

    struct stat stbuf;
    if (stat(config_path, &stbuf) < 0) {
        fprintf(stderr, "contest %d config file %s does not exist\n",
                contest_id, config_path);
        goto done;
    }
    if (!S_ISREG(stbuf.st_mode)) {
        fprintf(stderr, "contest %d config file %s is not regular\n",
                contest_id, config_path);
        goto done;
    }
    if (access(config_path, R_OK) < 0) {
        fprintf(stderr, "contest %d config file %s is not readable\n",
                contest_id, config_path);
        goto done;
    }

    state = serve_state_init(contest_id);
    state->config_path = xstrdup(config_path);
    state->current_time = time(NULL);
    state->load_time = state->current_time;

    if (prepare(ejudge_config, cnts, state, state->config_path, 0, PREPARE_SERVE, "", 1, 0, 0) < 0)
        goto done;
    if (prepare_serve_defaults(cnts, state, NULL) < 0) goto done;
    global = state->global;

    const unsigned char *current_plugin = global->xuser_plugin;
    if (!current_plugin || !*current_plugin) {
        current_plugin = ejudge_config->default_xuser_plugin;
    }
    if (!current_plugin || !*current_plugin) {
        current_plugin = "file";
    }

    if (!strcmp(from_plugin, "auto")) {
        // use the currently configured plugin
    } else {
        if (force_from_mode) {
            current_plugin = from_plugin;
        } else {
            if (strcmp(current_plugin, from_plugin) != 0) {
                printf("contest %d current statusdb it not %s, skipping\n",
                       contest_id, from_plugin);
                goto done;
            }
        }
    }

    if (!strcmp(current_plugin, to_plugin)) {
        printf("contest %d current xuser already %s, done\n",
               contest_id, current_plugin);
        goto done;
    }

    old_xuser_state = team_extra_open(ejudge_config, cnts, global, current_plugin, 0);
    if (!old_xuser_state) {
        fprintf(stderr, "contest %d failed to load plugin %s\n",
                contest_id, current_plugin);
        goto done;
    }
    new_xuser_state = team_extra_open(ejudge_config, cnts, global, to_plugin, 0);
    if (!new_xuser_state) {
        fprintf(stderr, "contest %d failed to load plugin %s\n",
                contest_id, to_plugin);
        goto done;
    }

    if (old_xuser_state->vt->get_user_ids(old_xuser_state, &user_idz, &user_ids) < 0) {
        fprintf(stderr, "contest %d failed to get list of users\n",
                contest_id);
        goto done;
    }

    printf("contest %d, users %d:", contest_id, user_idz);
    for (int i = 0; i < user_idz; ++i) {
        printf(" %d", user_ids[i]);
    }
    printf("\n");

    for (int i = 0; i < user_idz; ++i) {
        int user_id = user_ids[i];
        const struct team_extra *te = old_xuser_state->vt->get_entry(old_xuser_state, user_id);
        if (!te) {
            fprintf(stderr, "contest %d user %d entry is NULL\n",
                    contest_id, user_id);
            continue;
        }
        if (te->disq_comment && *te->disq_comment) {
            if (new_xuser_state->vt->set_disq_comment(new_xuser_state, user_id, te->disq_comment) < 0) {
                fprintf(stderr, "contest %d user %d set_disq_comment failed\n",
                        contest_id, user_id);
                continue;
            }
        }
        if (te->status) {
            if (new_xuser_state->vt->set_status(new_xuser_state, user_id, te->status) < 0) {
                fprintf(stderr, "contest %d user %d set_status failed\n",
                        contest_id, user_id);
                continue;
            }
        }
        if (te->run_fields) {
            if (new_xuser_state->vt->set_run_fields(new_xuser_state, user_id, te->run_fields) < 0) {
                fprintf(stderr, "contest %d user %d set_run_fields failed\n",
                        contest_id, user_id);
                continue;
            }
        }
        if (te->problem_dir_prefix && *te->problem_dir_prefix) {
            if (new_xuser_state->vt->set_problem_dir_prefix(new_xuser_state, user_id, te->disq_comment) < 0) {
                fprintf(stderr, "contest %d user %d set_problem_dir_prefix failed\n",
                        contest_id, user_id);
                continue;
            }
        }
        for (int j = 0; j < te->clar_uuids_size; ++j) {
            if (new_xuser_state->vt->set_clar_status(new_xuser_state, user_id, 0, &te->clar_uuids[j]) < 0) {
                fprintf(stderr, "contest %d user %d set_clar_status failed\n",
                        contest_id, user_id);
                continue;
            }
        }
        for (int j = 0; j < te->warn_u; ++j) {
            struct team_warning *tw = te->warns[j];
            if (new_xuser_state->vt->append_warning(new_xuser_state, user_id,
                                                    tw->issuer_id,
                                                    &tw->issuer_ip,
                                                    tw->date,
                                                    tw->text,
                                                    tw->comment) < 0) {
                fprintf(stderr, "contest %d user %d append_warning failed\n",
                        contest_id, user_id);
                continue;
            }
        }
    }

done:;
    free(user_ids);
    if (old_xuser_state) old_xuser_state->vt->close(old_xuser_state);
    if (new_xuser_state) new_xuser_state->vt->close(new_xuser_state);
}

/* force linking of certain functions that may be needed by plugins */
void *forced_link_table[] =
{
  xml_parse_ip,
  xml_parse_date,
  xml_parse_int,
  xml_parse_ip_mask,
  xml_parse_bool,
  xml_unparse_text,
  xml_unparse_bool,
  xml_unparse_ip,
  xml_unparse_date,
  xml_unparse_ip_mask,
  xml_err_get_elem_name,
  xml_err_get_attr_name,
  xml_err,
  xml_err_a,
  xml_err_attrs,
  xml_err_nested_elems,
  xml_err_attr_not_allowed,
  xml_err_elem_not_allowed,
  xml_err_elem_redefined,
  xml_err_top_level,
  xml_err_top_level_s,
  xml_err_attr_invalid,
  xml_err_elem_undefined,
  xml_err_elem_undefined_s,
  xml_err_attr_undefined,
  xml_err_attr_undefined_s,
  xml_err_elem_invalid,
  xml_err_elem_empty,
  xml_leaf_elem,
  xml_empty_text,
  xml_empty_text_c,
  xml_attr_bool,
  xml_attr_bool_byte,
  xml_attr_int,
  xml_attr_ulong,
  xml_attr_date,
  xml_do_parse_ipv6,
  xml_parse_ipv6_2,
  xml_parse_ipv6,
  xml_unparse_ipv6,
  ipv6cmp,
  ipv6_match_mask,
  xml_msg,
  xml_unparse_ipv6_mask,
  xml_parse_ipv6_mask,
  xml_elem_ipv6_mask,
  ipv6_is_empty,
  xml_unparse_full_cookie,
  xml_parse_full_cookie,
  base64u_decode,

  close_memstream,
};

int
main(int argc, char *argv[])
{
    int all_mode = 0;
    int remove_mode = 0;
    int force_from_mode = 0;
    const char *from_plugin = NULL;
    const char *to_plugin = NULL;
    int *cnts_ids = NULL;
    int cnts_idu = 0;
    int cnts_ida = 0;
    unsigned char ejudge_xml_path[PATH_MAX] = {};
    unsigned char ejudge_contests_dir[PATH_MAX] = {};
    struct ejudge_cfg *ejudge_config = NULL;
    const int *ej_cnts_ids = NULL;
    int ej_cnts_count = 0;

    {
        char *p = strrchr(argv[0], '/');
        if (!p) {
            program_name = argv[0];
        } else {
            program_name = p + 1;
        }
    }

    int argi = 1;
    while (argi < argc) {
        if (!strcmp(argv[argi], "--all")) {
            all_mode = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--remove-old")) {
            remove_mode = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--force-from")) {
            force_from_mode = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--from")) {
            if (argi + 1 >= argc) die("argument expected for --from");
            from_plugin = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--to")) {
            if (argi + 1 >= argc) die("argument expected for --to");
            to_plugin = argv[argi + 1];
            argi += 2;
        } else {
            break;
        }
    }

    if (all_mode) {
        if (argi != argc) die("contests not allowed after --all");
    } else {
        for (; argi < argc; ++argi) {
            char *eptr = NULL;
            errno = 0;
            long id1 = strtol(argv[argi], &eptr, 10);
            if (errno || eptr == argv[argi] || (int) id1 != id1 || id1 <= 0)
                die("invalid contest id '%s'", argv[argi]);
            if (!*eptr) {
                if (cnts_idu == cnts_ida) {
                    if (!(cnts_ida *= 2)) cnts_ida = 16;
                    cnts_ids = realloc(cnts_ids, cnts_ida * sizeof(cnts_ids[0]));
                }
                cnts_ids[cnts_idu++] = id1;
            } else if (*eptr == '-') {
                const char *s = eptr + 1;
                errno = 0;
                long id2 = strtol(s, &eptr, 10);
                if (errno || eptr == s || *eptr || (int) id2 != id2 || id2 <= 0)
                    die("invalid contest id '%s'", argv[argi]);
                if (id2 < id1) die("invalid contest range");
                if (id2 - id1 > 1000000) die("invalid contest range");
                for (long cc = id1; cc <= id2; ++cc) {
                    if (cnts_idu == cnts_ida) {
                        if (!(cnts_ida *= 2)) cnts_ida = 16;
                        cnts_ids = realloc(cnts_ids, cnts_ida * sizeof(cnts_ids[0]));
                    }
                    cnts_ids[cnts_idu++] = cc;
                }
            } else {
                die("invalid contest id '%s'", argv[argi]);
            }
        }
        qsort(cnts_ids, cnts_idu, sizeof(cnts_ids[0]), sort_func);
        if (cnts_idu > 1) {
            int dst = 1;
            for (int src = 1; src < cnts_idu; ++src) {
                if (cnts_ids[src - 1] != cnts_ids[src]) {
                    cnts_ids[dst++] = cnts_ids[src];
                }
            }
            cnts_idu = dst;
        }
    }

    if(cnts_idu <= 0 && !all_mode) {
        // nothing
        return 0;
    }

    if (!from_plugin || !*from_plugin) {
        from_plugin = "auto";
    }
    if (!to_plugin || !*to_plugin) {
        to_plugin = "mysql";
    }

    if (!ejudge_xml_path[0]) {
#if defined EJUDGE_XML_PATH
        if (snprintf(ejudge_xml_path, sizeof(ejudge_xml_path), "%s", EJUDGE_XML_PATH) >= sizeof(ejudge_xml_path)) die("path too long: %s", EJUDGE_XML_PATH);
#endif
    }
    if (!ejudge_xml_path[0])
        die("path to ejudge.xml is not set");

    ejudge_config = ejudge_cfg_parse(ejudge_xml_path, 1);
    if (!ejudge_config) die("failed to parse %s", ejudge_xml_path);

    if (!ejudge_config->contests_dir)
        die("contests config directory not specified");
    if (snprintf(ejudge_contests_dir, sizeof(ejudge_contests_dir), "%s", ejudge_config->contests_dir) >= sizeof(ejudge_contests_dir)) die("path too long: %s", ejudge_config->contests_dir);

    contests_set_directory(ejudge_contests_dir);
    ej_cnts_count = contests_get_list(&ej_cnts_ids);
    if (ej_cnts_count <= 0) {
        return 0;
    }

    if (all_mode) {
        cnts_idu = cnts_ida = ej_cnts_count;
        cnts_ids = calloc(cnts_idu, sizeof(cnts_ids[0]));
        memcpy(cnts_ids, ej_cnts_ids, cnts_idu * sizeof(cnts_ids[0]));
    }

    int i1 = 0, i2 = 0;
    while (i1 < cnts_idu && i2 < ej_cnts_count) {
        if (cnts_ids[i1] < ej_cnts_ids[i2]) {
            ++i1;
        } else if (cnts_ids[i1] > ej_cnts_ids[i2]) {
            ++i2;
        } else {
            process_contest(ejudge_config, cnts_ids[i1],
                            from_plugin, to_plugin, remove_mode, force_from_mode);
            ++i1; ++i2;
        }
    }
}
