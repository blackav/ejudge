/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2020 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/contests.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/fileutl.h"
#include "ejudge/xalloc.h"
#include "ejudge/xml_utils.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

static const char *progname;

static void
write_help(void)
{
    printf("%s: ejudge batch contest settings editing utility\n"
           "Usage: %s [OPTIONS] [CONTEST-IDS]...\n"
           "  OPTIONS:\n"
           "    --help    write message and exit\n"
           "    --version report version and exit\n"
           "    --open    clear 'closed' flag\n"
           "    --close   set 'closed' flag\n"
           "    --visible clear 'invisible' flag\n"
           "    --invisible\n"
           "              set 'invisible' flag\n"
           "    --no-users\n"
           "              disable access to 'users' CGI from all IPs\n"
           "    --all-users\n"
           "              enable access to 'users' CGI from all IPs\n"
           "    --no-register\n"
           "              disable access to 'register' CGI from all IPs\n"
           "    --all-register\n"
           "              enable access to 'register' CGI from all IPs\n"
           "    --no-participant\n"
           "              disable access to 'client' (aka 'team') CGI from all IPs\n"
           "    --all-participant\n"
           "              enable access to 'client' (aka 'team') CGI from all IPs\n"
           "    --remove-cap USER\n"
           "              remove capabilities for the USER\n"
           "    --add-judge-cap USER\n"
           "              set JUDGE capabilities for the USER\n"
           "    --add-master-cap USER\n"
           "              set MASTER capabilities for the USER\n"
           "    --add-full-cap USER\n"
           "              set FULL capabilities for the USER\n"
           "  CONTEST-IDS:\n"
           "    NUM       handle this contest\n"
           "    NUM1-NUM2 handle all contests in the range\n",
           progname, progname);
    exit(0);
}

static int
find_cap_user(const struct contest_desc *cnts, const char *cap_user_name)
{
    const struct opcap_list_item *cap;
    int index = 0;
    for (cap = CNTS_FIRST_PERM(cnts); cap; cap = CNTS_NEXT_PERM(cap)) {
        if (!strcmp(cap->login, cap_user_name)) {
            return index;
        }
        ++index;
    }
    return -1;
}

static int
find_cap_user_2(const struct contest_desc *cnts, const char *cap_user_name, int id)
{
    const struct opcap_list_item *cap;
    int index = 0;
    for (cap = CNTS_FIRST_PERM(cnts); cap; cap = CNTS_NEXT_PERM(cap)) {
        if (!strcmp(cap->login, cap_user_name)) {
            if (cap->caps == opcaps_get_predef_caps(id)) return index;
            return -1;
        }
        ++index;
    }
    return -1;
}

static int
parse_contest_xml(
        int contest_id,
        unsigned char **before_start,
        unsigned char **after_end)
{
    unsigned char path[PATH_MAX];
    char *raw_xml = 0, *s, *p;
    unsigned char *xml_1 = 0, *xml_2 = 0;
    size_t raw_xml_size = 0;
    struct stat statbuf;
    int errcode;

    contests_make_path(path, sizeof(path), contest_id);
    if (stat(path, &statbuf) < 0) {
        return -1;
    }

    if (generic_read_file(&raw_xml, 0, &raw_xml_size, 0, 0, path, 0) < 0) {
        return -1;
    }

    xml_1 = (unsigned char*) xmalloc(raw_xml_size + 10);
    xml_2 = (unsigned char*) xmalloc(raw_xml_size + 10);

    // find opening <contest tag
    s = raw_xml;
    while (*s) {
        if (s[0] != '<') {
            s++;
            continue;
        }
        if (s[1] == '!' && s[2] == '-' && s[3] == '-') {
            while (*s) {
                if (s[0] == '-' && s[1] == '-' && s[2] == '>') break;
                s++;
            }
            if (!*s) break;
            continue;
        }
        p = s;
        p++;
        while (*p && isspace(*p)) s++;
        if (!*p) {
            errcode = -1;
            goto failure;
        }
        if (!strncmp(p, "contest", 7) && p[7] && isspace(p[7])) break;
        s++;
    }
    if (!*s) {
        errcode = -1;
        goto failure;
    }

    memcpy(xml_1, raw_xml, s - raw_xml);
    xml_1[s - raw_xml] = 0;

    // find closing > tag
    while (*s && *s != '>') s++;
    if (!*s) {
        errcode = -1;
        goto failure;
    }
    s++;

    xml_2[0] = 0;
    char *endptr = strstr(s, "</contest>");
    if (endptr) {
        strcpy(xml_2, endptr + 10);
    }

    *before_start = xml_1;
    *after_end = xml_2;
    xfree(raw_xml);
    return 0;

failure:
    xfree(xml_1);
    xfree(xml_2);
    xfree(raw_xml);
    return errcode;
}

int
main(int argc, char *argv[])
{
    progname = argv[0];

    time_t current_time = time(NULL);

    unsigned char ejudge_xml_path[PATH_MAX];
    ejudge_xml_path[0] = 0;
    unsigned char ejudge_contests_dir[PATH_MAX];
    ejudge_contests_dir[0] = 0;

    struct ejudge_cfg *config = NULL;

    int open_flag = 0;
    int close_flag = 0;
    int visible_flag = 0;
    int invisible_flag = 0;
    int no_users_flag = 0;
    int no_register_flag = 0;
    int no_participant_flag = 0;
    int all_users_flag = 0;
    int all_register_flag = 0;
    int all_participant_flag = 0;
    int no_audit_flag = 0;
    const char *cap_user_name = NULL;
    int remove_cap_flag = 0;
    int add_judge_cap_flag = 0;
    int add_master_cap_flag = 0;
    int add_full_cap_flag = 0;

    int argi = 1;
    while (argi < argc) {
        if (!strcmp(argv[argi], "--version")) {
            printf("%s %s, compiled %s\n", progname, compile_version, compile_date);
            exit(0);
        } else if (!strcmp(argv[argi], "--help")) {
            write_help();
            exit(0);
        } else if (!strcmp(argv[argi], "--open")) {
            if (close_flag) {
                fprintf(stderr, "%s: conflicting flags: --open and --close\n", progname);
                exit(1);
            }
            open_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--close")) {
            if (open_flag) {
                fprintf(stderr, "%s: conflicting flags: --open and --close\n", progname);
                exit(1);
            }
            close_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--visible")) {
            if (invisible_flag) {
                fprintf(stderr, "%s: conflicting flags: --visible and --invisible\n", progname);
                exit(1);
            }
            visible_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--invisible")) {
            if (visible_flag) {
                fprintf(stderr, "%s: conflicting flags: --visible and --invisible\n", progname);
                exit(1);
            }
            invisible_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--no-users")) {
            if (all_users_flag) {
                fprintf(stderr, "%s: conflicting flags: --no-users and --all-users\n", progname);
                exit(1);
            }
            no_users_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--no-register")) {
            if (all_register_flag) {
                fprintf(stderr, "%s: conflicting flags: --no-register and --all-register\n", progname);
                exit(1);
            }
            no_register_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--no-participant")) {
            if (all_participant_flag) {
                fprintf(stderr, "%s: conflicting flags: --no-participant and --all-participant\n", progname);
                exit(1);
            }
            no_participant_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--all-users")) {
            if (no_users_flag) {
                fprintf(stderr, "%s: conflicting flags: --no-users and --all-users\n", progname);
                exit(1);
            }
            all_users_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--all-register")) {
            if (no_register_flag) {
                fprintf(stderr, "%s: conflicting flags: --no-register and --all-register\n", progname);
                exit(1);
            }
            all_register_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--all-participant")) {
            if (no_participant_flag) {
                fprintf(stderr, "%s: conflicting flags: --no-participant and --all-participant\n", progname);
                exit(1);
            }
            all_participant_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--remove-cap")) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "%s: argument expected for --remove-cap\n", progname);
                exit(1);
            }
            if (cap_user_name) {
                fprintf(stderr, "%s: conflicting options: capability change user already set\n", progname);
                exit(1);
            }
            remove_cap_flag = 1;
            cap_user_name = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--add-judge-cap")) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "%s: argument expected for --add-judge-cap\n", progname);
                exit(1);
            }
            if (cap_user_name) {
                fprintf(stderr, "%s: conflicting options: capability change user already set\n", progname);
                exit(1);
            }
            add_judge_cap_flag = 1;
            cap_user_name = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--add-master-cap")) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "%s: argument expected for --add-master-cap\n", progname);
                exit(1);
            }
            if (cap_user_name) {
                fprintf(stderr, "%s: conflicting options: capability change user already set\n", progname);
                exit(1);
            }
            add_master_cap_flag = 1;
            cap_user_name = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--add-full-cap")) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "%s: argument expected for --add-full-cap\n", progname);
                exit(1);
            }
            if (cap_user_name) {
                fprintf(stderr, "%s: conflicting options: capability change user already set\n", progname);
                exit(1);
            }
            add_full_cap_flag = 1;
            cap_user_name = argv[argi + 1];
            argi += 2;
        } else if (!strcmp(argv[argi], "--no-audit")) {
            no_audit_flag = 1;
            ++argi;
        } else if (!strcmp(argv[argi], "--ejudge-xml-path")) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "%s: argument expected for --ejudge-xml-path\n", progname);
                exit(1);
            }
            if (snprintf(ejudge_xml_path, sizeof(ejudge_xml_path), "%s", argv[argi + 1]) >= sizeof(ejudge_xml_path)) {
                fprintf(stderr, "%s: path '%s' is too long\n", progname, argv[argi + 1]);
                exit(1);
            }
            argi += 2;
        } else if (!strcmp(argv[argi], "--ejudge-contests-dir")) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "%s: argument expected for --ejudge-contests-dir\n", progname);
                exit(1);
            }
            if (snprintf(ejudge_contests_dir, sizeof(ejudge_contests_dir), "%s", argv[argi + 1]) >= sizeof(ejudge_contests_dir)) {
                fprintf(stderr, "%s: path '%s' is too long\n", progname, argv[argi + 1]);
                exit(1);
            }
            argi += 2;
        } else if (!strcmp(argv[argi], "--")) {
            ++argi;
            break;
        } else if (argv[argi][0] == '-') {
            fprintf(stderr, "%s: invalid option '%s'\n", progname, argv[argi]);
            exit(1);
        } else {
            break;
        }
    }

    int max_contest_id = 0;
    for (int i = argi; i < argc; ++i) {
        errno = 0;
        char *eptr = NULL;
        long v1 = strtol(argv[i], &eptr, 10);
        if (errno || argv[i] == eptr || v1 <= 0 || (int) v1 != v1) {
            fprintf(stderr, "%s: invalid contest '%s'\n", progname, argv[i]);
            exit(1);
        }
        long v2 = v1;
        if (*eptr == '-') {
            char *eptr2 = NULL;
            errno = 0;
            v2 = strtol(eptr + 1, &eptr2, 10);
            if (errno || *eptr2 || eptr + 1 == eptr2 || v2 <= 0 || (int) v2 != v2) {
                fprintf(stderr, "%s: invalid contest range '%s'\n", progname, argv[i]);
                exit(1);
            }
            if (v2 < v1) {
                fprintf(stderr, "%s: invalid contest range '%s'\n", progname, argv[i]);
                exit(1);
            }
        } else if (*eptr) {
            fprintf(stderr, "%s: invalid contest '%s'\n", progname, argv[i]);
            exit(1);
        }
        max_contest_id = (int) v2;
    }

    if (max_contest_id <= 0) {
        // no contests to process
        return 0;
    }

    if (max_contest_id == INT_MAX) {
        fprintf(stderr, "%s: contest_id is too big %d\n", progname, max_contest_id);
        exit(1);
    }

    unsigned char *requested_map = malloc(max_contest_id + 1);
    if (!requested_map) {
        fprintf(stderr, "%s: not enough memory\n", progname);
        exit(1);
    }
    memset(requested_map, 0, max_contest_id + 1);

    for (int i = argi; i < argc; ++i) {
        char *eptr = NULL;
        long v1 = strtol(argv[i], &eptr, 10);
        long v2 = v1;
        if (*eptr == '-') {
            v2 = strtol(eptr + 1, NULL, 10);
        }
        for (long id = v1; id <= v2; ++id) {
            requested_map[id] = 1;
        }
    }

    if (!ejudge_contests_dir[0]) {
        if (!ejudge_xml_path[0]) {
#if defined EJUDGE_XML_PATH
            if (snprintf(ejudge_xml_path, sizeof(ejudge_xml_path), "%s", EJUDGE_XML_PATH) >= sizeof(ejudge_xml_path)) {
                fprintf(stderr, "%s: path is too long: '%s'\n", progname, EJUDGE_XML_PATH);
                exit(1);
            }
#endif
        }
        if (!ejudge_xml_path[0]) {
            fprintf(stderr, "%s: path to ejudge.xml is not specified\n", progname);
            exit(1);
        }

        config = ejudge_cfg_parse(ejudge_xml_path, 1);
        if (!config) {
            fprintf(stderr, "%s: failed to parse config file '%s'\n", progname, ejudge_xml_path);
            exit(1);
        }

        if (!config->contests_dir) {
            fprintf(stderr, "%s: the contests config directory is not specified\n", progname);
            exit(1);
        }
        if (snprintf(ejudge_contests_dir, sizeof(ejudge_contests_dir), "%s", config->contests_dir) >= sizeof(ejudge_contests_dir)) {
            fprintf(stderr, "%s: path is too long: '%s'\n", progname, ejudge_contests_dir);
            exit(1);
        }
    }

    contests_set_directory(ejudge_contests_dir);

    const int *contest_ids = NULL;
    int contest_count = contests_get_list(&contest_ids);

    int failed_count = 0;
    for (int contest_idx = 0; contest_idx < contest_count; ++contest_idx) {
        int contest_id = contest_ids[contest_idx];

        if (contest_id <= 0 || contest_id > max_contest_id || !requested_map[contest_id]) {
            continue;
        }

        struct contest_desc *cnts = NULL;
        if (contests_load(contest_id, &cnts) < 0 || !cnts) {
            printf("%d: failed to load contest\n", contest_id);
            ++failed_count;
            continue;
        }

        int need_update = 0;
        if (open_flag && cnts->closed) {
            need_update = 1;
        }
        if (close_flag && !cnts->closed) {
            need_update = 1;
        }
        if (visible_flag && cnts->invisible) {
            need_update = 1;
        }
        if (invisible_flag && !cnts->invisible) {
            need_update = 1;
        }
        if (no_users_flag && contests_get_users_access_type(cnts) != 0) {
            need_update = 1;
        }
        if (all_users_flag && contests_get_users_access_type(cnts) != 2) {
            need_update = 1;
        }
        if (no_register_flag && contests_get_register_access_type(cnts) != 0) {
            need_update = 1;
        }
        if (all_register_flag && contests_get_register_access_type(cnts) != 2) {
            need_update = 1;
        }
        if (no_participant_flag && contests_get_participant_access_type(cnts) != 0) {
            need_update = 1;
        }
        if (all_participant_flag && contests_get_participant_access_type(cnts) != 2) {
            need_update = 1;
        }
        if (remove_cap_flag && find_cap_user(cnts, cap_user_name) >= 0) {
            need_update = 1;
        }
        if (add_master_cap_flag && find_cap_user_2(cnts, cap_user_name, OPCAP_PREDEF_MASTER) < 0) {
            need_update = 1;
        }
        if (add_judge_cap_flag && find_cap_user_2(cnts, cap_user_name, OPCAP_PREDEF_JUDGE) < 0) {
            need_update = 1;
        }
        if (add_full_cap_flag && find_cap_user_2(cnts, cap_user_name, OPCAP_PREDEF_FULL) < 0) {
            need_update = 1;
        }

        if (!need_update) {
            continue;
        }

        unsigned char *txt1 = NULL, *txt2 = NULL;
        if (parse_contest_xml(contest_id, &txt1, &txt2) < 0) {
            printf("%d: failed to load contest\n", contest_id);
            ++failed_count;
            continue;
        }

        unsigned char updates_buf[128];
        unsigned char *updates_ptr = updates_buf;

        if (open_flag && cnts->closed) {
            cnts->closed = 0;
            *updates_ptr++ = '+';
            *updates_ptr++ = 'O';
        }
        if (close_flag && !cnts->closed) {
            cnts->closed = 1;
            *updates_ptr++ = '-';
            *updates_ptr++ = 'O';
        }
        if (visible_flag && cnts->invisible) {
            cnts->invisible = 0;
            *updates_ptr++ = '+';
            *updates_ptr++ = 'V';
        }
        if (invisible_flag && !cnts->invisible) {
            cnts->invisible = 1;
            *updates_ptr++ = '-';
            *updates_ptr++ = 'V';
        }
        if (no_users_flag && contests_get_users_access_type(cnts) != 0) {
            cnts->users_access = NULL;
            *updates_ptr++ = '-';
            *updates_ptr++ = 'U';
        }
        if (all_users_flag && contests_get_users_access_type(cnts) != 2) {
            cnts->users_access = NULL;
            contests_set_default(cnts, &cnts->users_access, CONTEST_USERS_ACCESS, 1);
            *updates_ptr++ = '+';
            *updates_ptr++ = 'U';
        }
        if (no_register_flag && contests_get_register_access_type(cnts) != 0) {
            cnts->register_access = NULL;
            *updates_ptr++ = '-';
            *updates_ptr++ = 'R';
        }
        if (all_register_flag && contests_get_register_access_type(cnts) != 2) {
            cnts->register_access = NULL;
            contests_set_default(cnts, &cnts->register_access, CONTEST_REGISTER_ACCESS, 1);
            *updates_ptr++ = '+';
            *updates_ptr++ = 'R';
        }
        if (no_participant_flag && contests_get_participant_access_type(cnts) != 0) {
            cnts->team_access = NULL;
            *updates_ptr++ = '-';
            *updates_ptr++ = 'P';
        }
        if (all_participant_flag && contests_get_participant_access_type(cnts) != 2) {
            cnts->team_access = NULL;
            contests_set_default(cnts, &cnts->team_access, CONTEST_TEAM_ACCESS, 1);
            *updates_ptr++ = '+';
            *updates_ptr++ = 'P';
        }
        if (remove_cap_flag) {
            int index = find_cap_user(cnts, cap_user_name);
            if (index >= 0) {
                contests_remove_nth_permission(cnts, index);
                *updates_ptr++ = '-';
                *updates_ptr++ = 'A';
            }
        }
        if (add_judge_cap_flag) {
            contests_upsert_permission(cnts, cap_user_name, opcaps_get_predef_caps(OPCAP_PREDEF_JUDGE));
            *updates_ptr++ = '+';
            *updates_ptr++ = 'A';
            *updates_ptr++ = 'J';
        }
        if (add_master_cap_flag) {
            contests_upsert_permission(cnts, cap_user_name, opcaps_get_predef_caps(OPCAP_PREDEF_MASTER));
            *updates_ptr++ = '+';
            *updates_ptr++ = 'A';
            *updates_ptr++ = 'M';
        }
        if (add_full_cap_flag) {
            contests_upsert_permission(cnts, cap_user_name, opcaps_get_predef_caps(OPCAP_PREDEF_FULL));
            *updates_ptr++ = '+';
            *updates_ptr++ = 'A';
            *updates_ptr++ = 'F';
        }

        *updates_ptr = 0;
        unsigned char audit_str[1024];
        audit_str[0] = 0;
        if (!no_audit_flag) {
            snprintf(audit_str, sizeof(audit_str),
                     "<!-- audit: ejudge-change-contests: %s, %s -->\n", updates_buf, xml_unparse_date(current_time));
        }

        if (contests_unparse_and_save(cnts, NULL, "", txt2, audit_str, NULL, NULL) < 0) {
            printf("%d: failed to save contest\n", contest_id);
            ++failed_count;
        }

        printf("%d: %s\n", contest_id, updates_buf);
    }

    if (failed_count > 0) {
        return 1;
    }
    return 0;
}
