/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2005 Alexander Chernov <cher@unicorn.cmc.msu.ru> */

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

#include "config.h"

#include "version.h"
#include "userlist_cfg.h"
#include "userlist.h"
#include "contests.h"
#include "pathutl.h"
#include "runlog.h"
#include "clarlog.h"
#include "userlist_clnt.h"
#include "userlist_proto.h"

#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

#include <stdio.h>
#include <limits.h>
#include <ctype.h>

static struct userlist_cfg  *config;
static struct userlist_list *userlist;

struct vcntslist
{
  struct vcntslist *next;
  int contest_id;
};

struct user_stat
{
  int clar_num;
  size_t clar_size;
  int run_num;
  int run_size;
  int is_privileged;
  int never_clean;
  int virt_events;
  struct vcntslist *virt_contests;
};
static struct user_stat *user_stat;

#if 0
static void
print_info(unsigned char const *program_path)
{
  printf("clean-users %s, compiled %s\n", compile_version, compile_date);
  printf("Usage: %s [-r [-f]] config-file\n", program_path);
}
#endif

int
main(int argc, char **argv)
{
  int user_total, i, max_user_id, j = 0, r;
  int contest_max_ind, errcode;
  unsigned char *contest_map;
  struct contest_desc *cnts;
  unsigned char runlog_path[PATH_MAX];
  unsigned char clarlog_path[PATH_MAX];
  int total_runs, total_clars;
  struct run_entry *run_entries, *cur_entry;
  int empty_entries, virt_events, temp_events, inv_events, reg_events;
  size_t clar_size;
  int clar_from, clar_to;
  unsigned char *out_flags;
  struct vcntslist *cntsp;
  struct userlist_clnt *server_conn;
  int force_flag = 0, remove_flag = 0;
  const unsigned char *cfg_path = 0;
  unsigned char reply_buf[128], *reply;
  size_t reply_len;

  /*
  if (argc == 1) {
    print_info(argv[0]);
    return 0;
  }
  */
  for (i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-r")) {
      remove_flag = 1;
    } else if (!strcmp(argv[i], "-f")) {
      force_flag = 1;
    } else break;
  }

#if defined EJUDGE_XML_PATH
  if (argc == i) {
    info("using the default %s", EJUDGE_XML_PATH);
    cfg_path = EJUDGE_XML_PATH;
  } else if (argc != i + 1) {
    fprintf(stderr, "%s: invalid number of arguments\n", argv[0]);
    return 1;
  } else {
    cfg_path = argv[i];
  }
#else
  if (i + 1 != argc) {
    fprintf(stderr, "%s: invalid number of parameters\n", argv[0]);
    return 1;
  }
  cfg_path = argv[i];
#endif

  info("clean-users %s, compiled %s", compile_version, compile_date);

  config = userlist_cfg_parse(cfg_path);
  if (!config) return 1;
  if (!config->contests_dir) {
    err("<contests_dir> tag is not set!");
    return 1;
  }
  if (contests_set_directory(config->contests_dir) < 0) {
    err("contests directory is invalid");
    return 1;
  }

  userlist = userlist_parse(config->db_path);
  if (!userlist) return 1;

  user_total = 0;
  max_user_id = -1;
  for (i = 1; i < userlist->user_map_size; i++) {
    if (!userlist->user_map[i]) continue;
    user_total++;
    if (i > max_user_id) max_user_id = i;
  }
  info("%d users found, max user_id is %d", user_total, max_user_id);

  user_stat = (struct user_stat*) xcalloc(max_user_id+1,sizeof(user_stat[0]));
  for (i = 1; i < userlist->user_map_size; i++) {
    if (!userlist->user_map[i]) continue;
    user_stat[i].never_clean = userlist->user_map[i]->never_clean;
  }

  info("scanning available contests...");
  contest_max_ind = contests_get_list(&contest_map);
  if (contest_max_ind <= 0 || !contest_map) {
    info("no contests found");
    return 0;
  }

  for (i = 1; i < contest_max_ind; i++) {
    if (!contest_map[i]) continue;
    if ((errcode = contests_get(i, &cnts)) < 0) {
      err("cannot load contest %d: %s", i, contests_strerror(-errcode));
      return 1;
    }

    if (!cnts->clean_users) {
      info("contest %d ignored", i);
      continue;
    }

    if (!cnts->root_dir || !*cnts->root_dir) {
      err("contest %d root directory is not set", i);
      return 1;
    }

    snprintf(runlog_path, sizeof(runlog_path),
             "%s/var/run.log", cnts->root_dir);
    snprintf(clarlog_path, sizeof(clarlog_path),
             "%s/var/clar.log", cnts->root_dir);

    if (run_open(runlog_path, RUN_LOG_READONLY, 0) < 0) {
      err("contest %d cannot open runlog '%s'", i, runlog_path);
    } else if (!(total_runs = run_get_total())) {
      info("contest %d runlog is empty", i);
    } else {
      // runlog opened OK
      run_entries = xcalloc(total_runs, sizeof(run_entries[0]));
      run_get_all_entries(run_entries);
      info("contest %d found %d runlog entries", i, total_runs);

      reg_events = empty_entries = virt_events = temp_events = inv_events = 0;
      for (j = 0; j < total_runs; j++) {
        cur_entry = &run_entries[j];

        switch (cur_entry->status) {
        case RUN_OK:
        case RUN_COMPILE_ERR:
        case RUN_RUN_TIME_ERR:
        case RUN_TIME_LIMIT_ERR:
        case RUN_PRESENTATION_ERR:
        case RUN_WRONG_ANSWER_ERR:
        case RUN_CHECK_FAILED:
        case RUN_PARTIAL:
        case RUN_ACCEPTED:
        case RUN_IGNORED:
        case RUN_DISQUALIFIED:
        case RUN_PENDING:
        case RUN_MEM_LIMIT_ERR:
        case RUN_SECURITY_ERR:
          reg_events++;
          if (cur_entry->team <= 0 || cur_entry->team > max_user_id
              || !userlist->user_map[cur_entry->team]) {
            err("contest %d runid %d invalid user_id %d",
                i, j, cur_entry->team);
          } else {
            user_stat[cur_entry->team].run_num++;
            user_stat[cur_entry->team].run_size += cur_entry->size;
          }
          break;

        case RUN_VIRTUAL_START:
        case RUN_VIRTUAL_STOP:
          virt_events++;
          if (cur_entry->team <= 0 || cur_entry->team > max_user_id
              || !userlist->user_map[cur_entry->team]) {
            err("contest %d runid %d invalid user_id %d",
                i, j, cur_entry->team);
          } else {
            user_stat[cur_entry->team].virt_events++;
          }
          for (cntsp = user_stat[cur_entry->team].virt_contests;
               cntsp; cntsp = cntsp->next) {
            if (cntsp->contest_id == i) break;
          }
          if (!cntsp) {
            cntsp = (struct vcntslist*) xcalloc(1, sizeof(*cntsp));
            cntsp->contest_id = i;
            cntsp->next = user_stat[cur_entry->team].virt_contests;
            user_stat[cur_entry->team].virt_contests = cntsp;
          }
          break;

        case RUN_EMPTY:
          empty_entries++;
          break;
        case RUN_RUNNING:
        case RUN_COMPILED:
        case RUN_COMPILING:
        case RUN_REJUDGE:
          info("contest %d runid %d transient event %d",
               i, j, cur_entry->status);
          temp_events++;
          break;
        default:
          err("contest %d runid %d invalid status %d", i,j,cur_entry->status);
          inv_events++;
          break;
        }
      }
      printf("contest %d run statistics: %d regular, %d virtual, %d empty, %d transient, %d invalid\n", i, reg_events, virt_events, empty_entries, temp_events, inv_events);

      run_clear_variables();
      xfree(run_entries);
    }

    if (clar_open(clarlog_path, CLAR_LOG_READONLY) < 0) {
      err("contest %d cannot open clarlog '%s'", i, clarlog_path);
    } else {
      // clarlog opened OK
      total_clars = clar_get_total();
      info("contest %d found %d clarlog entries", i, total_clars);
      printf("contest %d clar statistics: %d total\n", i, total_clars);
      for (j = 0; j < total_clars; j++) {
        if (clar_get_record(j,0,&clar_size,0,&clar_from,&clar_to,0,0) < 0) {
          err("contest %d failed to read clar %d", i, j);
        } else {
          if (clar_from != 0 && clar_from == clar_to) {
            if (clar_from <= 0 || clar_from > max_user_id
                || !userlist->user_map[clar_from]) {
              err("contest %d clarlog %d invalid user_id %d", i, j, clar_from);
            } else {
              user_stat[clar_from].clar_num++;
              user_stat[clar_from].clar_size += clar_size;
            }
          } else {
            if (clar_from != 0) {
              if (clar_from <= 0 || clar_from > max_user_id
                  || !userlist->user_map[clar_from]) {
                err("contest %d clarlog %d invalid user_id %d",i,j,clar_from);
              } else {
                user_stat[clar_from].clar_num++;
                user_stat[clar_from].clar_size += clar_size;
              }
            }
            if (clar_to != 0) {
              if (clar_to <= 0 || clar_to > max_user_id
                  || !userlist->user_map[clar_to]) {
                err("contest %d clarlog %d invalid user_id %d",i,j,clar_to);
              } else {
                user_stat[clar_to].clar_num++;
                user_stat[clar_to].clar_size += clar_size;
              }
            }
          }
        }
      }

      clar_clear_variables();
    }
  }

  printf("%-8s%-8s%-16s%-8s%-8s%-8s%-8s%-8s\n",
         "Flags", "Id", "Login", "Virt", "Runs", "R. size",
         "Clars", "C. size");
  for (i = 1; i <= max_user_id; i++) {
    if (!userlist->user_map[i]) continue;
    if (user_stat[i].run_num == 0 && user_stat[i].clar_num == 0
        && user_stat[i].virt_events == 0 && !user_stat[i].is_privileged
        && !user_stat[i].never_clean) {
      out_flags = "**";
    } else if (user_stat[i].run_num == 0 && user_stat[i].clar_num == 0
               && user_stat[i].virt_events > 0
               && !user_stat[i].is_privileged && !user_stat[i].never_clean) {
      out_flags = "*";
    } else if (user_stat[i].is_privileged || user_stat[i].never_clean) {
      out_flags = "!";
    } else {
      out_flags = "";
    }
    printf("%-8s%-8d%-16.16s%-8d%-8d%-8d%-8d%-8zu\n",
           out_flags, i, userlist->user_map[i]->login,
           user_stat[i].virt_events,
           user_stat[i].run_num, user_stat[i].run_size,
           user_stat[i].clar_num, user_stat[i].clar_size);
  }

  printf("Virtual contests for start/stop only users\n");
  for (i = 1; i <= max_user_id; i++) {
    if (!userlist->user_map[i]) continue;
    if (user_stat[i].run_num == 0 && user_stat[i].clar_num == 0
        && user_stat[i].virt_events > 0
        && !user_stat[i].is_privileged && !user_stat[i].never_clean) {
      printf("%s", userlist->user_map[i]->login);
      for (cntsp = user_stat[i].virt_contests;
           cntsp; cntsp = cntsp->next) {
        printf(" %d", cntsp->contest_id);
      }
      printf("\n");
    }
  }
  if (!remove_flag) return 0;

  if (!(server_conn = userlist_clnt_open(config->socket_path))) {
    err("cannot open server connection: %s", os_ErrorMsg());
    return 1;
  }
  if ((r = userlist_clnt_admin_process(server_conn, 0, 0, 0)) < 0) {
    err("cannot become admin process: %s", userlist_strerror(-r));
    return 1;
  }

  printf("Removing users\n");
  for (i = 1; i <= max_user_id; i++) {
    if (!userlist->user_map[i]) continue;
    if (user_stat[i].run_num != 0 || user_stat[i].clar_num != 0) continue;
    if (user_stat[i].virt_events != 0 || user_stat[i].is_privileged) continue;
    if (user_stat[i].never_clean) continue;

    reply = 0;
    while (!force_flag) {
      printf("Remove user %d,%s,%s? ", i,
             userlist->user_map[i]->login,
             userlist->user_map[i]->name);
      if (!fgets(reply_buf, sizeof(reply_buf), stdin)) {
        err("cannot read input from the standard input");
        return 1;
      }
      if ((reply_len = strlen(reply_buf)) > sizeof(reply_buf) - 4) {
        printf("Answer is too long\n");
        continue;
      }
      while (reply_len > 0 && isspace(reply_buf[reply_len - 1]))
        reply_buf[--reply_len] = 0;
      reply = reply_buf;
      while (*reply && isspace(*reply)) reply++;
      if (!strcasecmp(reply, "n") || !strcasecmp(reply, "no")) break;
      if (!strcasecmp(reply, "y") || !strcasecmp(reply, "yes")) {
        reply = 0;
        break;
      }
      printf("Please answer y[es] or n[o].\n"); 
    }
    if (reply) continue;

    r = userlist_clnt_delete_field(server_conn, i, -2, 0, 0);
    if (r < 0) {
      err("Remove failed: %s", userlist_strerror(-j));
    }
  }

  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
