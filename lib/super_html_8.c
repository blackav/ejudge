/* -*- mode: c -*- */

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
#include "ejudge/super_html.h"
#include "ejudge/super-serve.h"
#include "ejudge/pathutl.h"
#include "ejudge/contests.h"
#include "ejudge/prepare.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/errlog.h"
#include "ejudge/compat.h"
#include "ejudge/fileutl.h"
#include "ejudge/ej_process.h"
#include "ejudge/super_proto.h"
#include "ejudge/misctext.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"
#include "ejudge/logger.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

static const unsigned char compile_dir_suffix[] = "/var/compile";

static unsigned char *
do_load_file(const unsigned char *conf_path, const unsigned char *file)
{
  unsigned char full_path[PATH_MAX];
  char *buf = 0;
  size_t buf_size = 0;

  if (!file || !*file) return 0;

  if (!os_IsAbsolutePath(file)) {
    snprintf(full_path, sizeof(full_path), "%s/%s", conf_path, file);
  } else {
    snprintf(full_path, sizeof(full_path), "%s", file);
  }

  if (generic_read_file(&buf, 0, &buf_size, 0, 0, full_path, 0) < 0) return 0;
  return buf;
}

int
super_html_read_serve(
        FILE *flog,
        const unsigned char *path,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        struct sid_state *sstate)
{
  struct stat sb;
  int cond_count = 0, total, i, cur_id, j, arch, k;
  struct generic_section_config *pg;
  struct section_global_data *global;
  struct section_problem_data *prob, *aprob;
  struct section_tester_data *tst, *atst;
  struct section_language_data *lang;
  size_t vm_size, st_size, rss_size;
  size_t *mem_lims, *st_lims;
  int *mem_cnt, *st_cnt;
  //int mem_u, st_u, max_i;
  path_t check_cmd = { 0 };
  FILE *fuh;
  char *fuh_text = 0;
  size_t fuh_size = 0;
  path_t cs_spool_dir;
  path_t conf_dir;
  unsigned char *prob_no_any = 0;
  size_t cs_spool_dir_len = 0;
  unsigned char cs_conf_file[PATH_MAX];

  if (!cnts) {
    fprintf(flog, "No contest XML description\n");
    return -1;
  }
  if (!cnts->conf_dir || !*cnts->conf_dir) {
    snprintf(conf_dir, sizeof(conf_dir), "%s/%s", cnts->root_dir, "conf");
  } else if (!os_IsAbsolutePath(cnts->conf_dir)) {
    snprintf(conf_dir, sizeof(conf_dir), "%s/%s", cnts->root_dir, cnts->conf_dir);
  } else {
    snprintf(conf_dir, sizeof(conf_dir), "%s", cnts->conf_dir);
  }

  if (stat(path, &sb) < 0) {
    // file do not exist
    return 0;
  }
  if (!S_ISREG(sb.st_mode)) {
    fprintf(flog, "File `%s' not a regular file\n", path);
    return -1;
  }
  if (access(path, R_OK) < 0) {
    fprintf(flog, "File `%s' is not readable\n", path);
    return -1;
  }

  // FIXME: redirect output?
  if (!(sstate->cfg = prepare_parse_config_file(path, &cond_count))) {
    fprintf(flog, "Parsing of `%s' failed\n", path);
    return -1;
  }
  if (cond_count > 0) {
    fprintf(flog, "The configuration file uses conditional compilation directives\n");
    return -1;
  }

  // find global section
  for (pg = sstate->cfg; pg; pg = pg->next)
    if (!pg->name[0] || !strcmp(pg->name, "global"))
      break;
  if (!pg) {
    fprintf(flog, "The global section is not defined\n");
    return -1;
  }
  global = sstate->global = (struct section_global_data *) pg;

  // set up the default value of the root_dir
  if (!global->root_dir || !global->root_dir[0]) {
    usprintf(&global->root_dir, "%06d", cnts->id);
  }
  if (!os_IsAbsolutePath(global->root_dir) && config
      && config->contests_home_dir
      && os_IsAbsolutePath(config->contests_home_dir)) {
    usprintf(&global->root_dir, "%s/%s", config->contests_home_dir, global->root_dir);
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!os_IsAbsolutePath(global->root_dir)) {
    usprintf(&global->root_dir, "%s/%s", EJUDGE_CONTESTS_HOME_DIR, global->root_dir);
  }
#endif
  if (!os_IsAbsolutePath(global->root_dir)) {
    err("global.root_dir must be absolute directory!");
    return -1;
  }

  // check variables that we don't want to be ever set
  if (prepare_check_forbidden_global(flog, global) < 0) return -1;

  // contest_id, conf_dir, root_dir must match
  if (strcmp(global->root_dir, cnts->root_dir)) {
    fprintf(flog, "root_dir does not match\n");
    return -1;
  }
  /*
  if ((!cnts->conf_dir && global->conf_dir)
      || (cnts->conf_dir && strcmp(cnts->conf_dir, global->conf_dir))) {
    fprintf(flog, "conf_dir does not match\n");
    return -1;
  }
  */

  // compile server must be used
  if (!global->compile_dir || !global->compile_dir[0]) {
    fprintf(flog, "compilation server is not used\n");
    return -1;
  }
  if (!os_IsAbsolutePath(global->compile_dir)) {
    usprintf(&global->compile_dir, "%s/var/%s", global->root_dir, global->compile_dir);
  }
  if (!config->compile_home_dir) {
    fprintf(flog, "compile server home dir is not set\n");
    return -1;
  }
  // cut off "/var/compile" suffix from the compile dir
  snprintf(cs_spool_dir, sizeof(cs_spool_dir), "%s", global->compile_dir);
  cs_spool_dir_len = strlen(cs_spool_dir);
  if (cs_spool_dir_len < sizeof(compile_dir_suffix)
      || strcmp(cs_spool_dir+cs_spool_dir_len-sizeof(compile_dir_suffix)+1,
                compile_dir_suffix) != 0) {
    fprintf(flog, "invalid `compile_dir' %s\n", cs_spool_dir);
    return -1;
  }
  cs_spool_dir[cs_spool_dir_len-sizeof(compile_dir_suffix)+1] = 0;
  sstate->compile_home_dir = xstrdup(cs_spool_dir);
  //fprintf(stderr, "compile_home_dir>>%s<<\n", sstate->compile_home_dir);
  /*
  snprintf(cs_spool_dir, sizeof(cs_spool_dir), "%s/var/compile",
           config->compile_home_dir);
  if (strcmp(cs_spool_dir, global->compile_dir)) {
    fprintf(flog, "non-default compilation server is used\n");
    return -1;
  }
  */

  prepare_set_global_defaults(config, global);
  if (global->stand2_file_name && global->stand2_file_name[0]) sstate->enable_stand2 = 1;
  if (global->plog_file_name && global->plog_file_name[0]) sstate->enable_plog = 1;
  if (global->stand_extra_format && global->stand_extra_format[0]) sstate->enable_extra_col = 1;

  fuh = open_memstream(&fuh_text, &fuh_size);
  prepare_unparse_unhandled_global(fuh, global);
  close_memstream(fuh); fuh = 0;
  if (fuh_text && *fuh_text) {
    global->unhandled_vars = fuh_text;
  } else {
    xfree(fuh_text);
  }
  fuh_text = 0; fuh_size = 0;

  // collect languages
  total = 0; cur_id = 0;
  for (pg = sstate->cfg; pg; pg = pg->next) {
    if (strcmp(pg->name, "language") != 0) continue;
    lang = (struct section_language_data*) pg;
    if (!lang->id) lang->id = cur_id + 1;
    cur_id = lang->id;
    if (lang->id <= 0 || lang->id > EJ_MAX_LANG_ID) {
      fprintf(flog, "Invalid language ID\n");
      return -1;
    }
    if (lang->id >= total) total = lang->id + 1;
  }

  sstate->lang_a = 0;
  sstate->langs = 0;
  sstate->loc_cs_map = 0;
  sstate->lang_opts = 0;
  sstate->lang_libs = 0;
  sstate->lang_flags = 0;
  if (total > 0) {
    sstate->lang_a = 4;
    while (total > sstate->lang_a) sstate->lang_a *= 2;
    XCALLOC(sstate->langs, sstate->lang_a);
    XCALLOC(sstate->loc_cs_map, sstate->lang_a);
    XCALLOC(sstate->lang_opts, sstate->lang_a);
    XCALLOC(sstate->lang_libs, sstate->lang_a);
    XCALLOC(sstate->lang_flags, sstate->lang_a);
    for (pg = sstate->cfg; pg; pg = pg->next) {
      if (strcmp(pg->name, "language") != 0) continue;
      lang = (struct section_language_data*) pg;
      if (sstate->langs[lang->id]) {
        fprintf(flog, "Duplicated language ID %d\n", lang->id);
        return -1;
      }
      sstate->langs[lang->id] = lang;
    }
  }

  // load the compilation server state and establish correspondence
  if (super_load_cs_languages(config, sstate, global->extra_compile_dirs, 0,
                              cs_conf_file, sizeof(cs_conf_file)) < 0) {
    fprintf(flog, "Failed to load compilation server configuration\n");
    return -1;
  }

  for (i = 1; i < sstate->lang_a; i++) {
    if (!(lang = sstate->langs[i])) continue;
    if (!lang->compile_id) lang->compile_id = lang->id;

    if (prepare_check_forbidden_lang(flog, lang) < 0)
      return -1;

    /*
    if (lang->compile_id <= 0 || lang->compile_id >= sstate->cs_lang_total
        || !sstate->cs_langs[lang->compile_id]) {
    }
    */
    // improve error messaging
    if (lang->compile_id > 0 && lang->compile_id < sstate->cs_lang_total
        && sstate->cs_langs[lang->compile_id]
        && strcmp(lang->short_name, sstate->cs_langs[lang->compile_id]->short_name) != 0) {
      fprintf(flog,
              "contest configuration file '%s' specifies language short name '%s' for language %d\n"
              "and it is different from language short name '%s' in compilation configuration file '%s'\n",
              path, lang->short_name, lang->compile_id,
              sstate->cs_langs[lang->compile_id]->short_name,
              cs_conf_file);
      return -1;
    }

    if (lang->compile_id <= 0
        || lang->compile_id >= sstate->cs_lang_total
        || !sstate->cs_langs[lang->compile_id]
        || strcmp(lang->short_name, sstate->cs_langs[lang->compile_id]->short_name) != 0) {
      lang->compile_id = 0;
    }
    for (int j = 1; j < sstate->cs_lang_total; ++j) {
      if (sstate->cs_langs[j]
          && !strcmp(lang->short_name, sstate->cs_langs[j]->short_name)) {
        lang->compile_id = j;
        break;
      }
    }
    if (lang->compile_id <= 0) {
      fprintf(flog, "contest configuration file '%s' specifies language short name '%s' with id %d\n"
              "but such language is not specified in compilation configuration file '%s'\n",
              path, lang->short_name, lang->id, cs_conf_file);
      return -1;
    }

    sstate->loc_cs_map[lang->id] = lang->compile_id;
    sstate->cs_loc_map[lang->compile_id] = lang->id;

    fuh = open_memstream(&fuh_text, &fuh_size);
    prepare_unparse_unhandled_lang(fuh, lang);
    close_memstream(fuh); fuh = 0;
    if (fuh_text && *fuh_text) {
      lang->unhandled_vars = fuh_text;
    } else {
      xfree(fuh_text);
    }
    fuh_text = 0; fuh_size = 0;

    if (lang->compiler_env) {
      for (j = 0; lang->compiler_env[j]; j++) {
        if (!strncmp(lang->compiler_env[j], "EJUDGE_FLAGS=", 13)) {
          sstate->lang_opts[lang->id] = xstrmerge1(sstate->lang_opts[lang->id],
                                                   lang->compiler_env[j] + 13);
        }
        if (!strncmp(lang->compiler_env[j], "EJUDGE_LIBS=", 12)) {
          sstate->lang_libs[lang->id] = xstrmerge1(sstate->lang_libs[lang->id], lang->compiler_env[j] + 12);
        }
      }
      for (--j; j >= 0; --j) {
        if (!strncmp(lang->compiler_env[j], "EJUDGE_FLAGS=", 13) || !strncmp(lang->compiler_env[j], "EJUDGE_LIBS=", 12)) {
          xfree(lang->compiler_env[j]); lang->compiler_env[j] = 0;
          for (k = j + 1; lang->compiler_env[k]; k++) {
            lang->compiler_env[k - 1] = lang->compiler_env[k];
          }
          lang->compiler_env[k - 1] = lang->compiler_env[k];
        }
      }
    }
  }

  // collect abstract problems
  for (pg = sstate->cfg, total = 0; pg; pg = pg->next) {
    if (!strcmp(pg->name, "problem")
        && (prob = (struct section_problem_data*) pg)->abstract)
      total++;
  }

  sstate->aprob_a = 0;
  sstate->aprob_u = 0;
  sstate->aprobs = 0;
  sstate->aprob_flags = 0;
  if (total) {
    sstate->aprob_a = 4;
    while (total > sstate->aprob_a) sstate->aprob_a *= 2;
    XCALLOC(sstate->aprobs, sstate->aprob_a);
    XCALLOC(sstate->aprob_flags, sstate->aprob_a);
    for (pg = sstate->cfg, i = 0; pg; pg = pg->next) {
      if (strcmp(pg->name, "problem") != 0) continue;
      prob = (struct section_problem_data*) pg;
      if (!prob->abstract) continue;
      sstate->aprobs[i++] = prob;
      if (!prob->short_name[0]) {
        fprintf(flog, "Abstract problem must have `short_name' field set\n");
        return -1;
      }
      if (prob->super[0]) {
        fprintf(flog, "Abstract problem must not have a superproblem\n");
        return -1;
      }

      if (prepare_check_forbidden_prob(flog, prob) < 0)
        return -1;

      prepare_set_abstr_problem_defaults(prob, global);

      fuh = open_memstream(&fuh_text, &fuh_size);
      prepare_unparse_unhandled_prob(fuh, prob, global);
      close_memstream(fuh); fuh = 0;
      if (fuh_text && *fuh_text) {
        prob->unhandled_vars = fuh_text;
      } else {
        xfree(fuh_text);
      }
      fuh_text = 0; fuh_size = 0;
    }
    ASSERT(i == total);
    sstate->aprob_u = total;
  }

  // collect concrete problems
  total = 0; cur_id = 0;
  for (pg = sstate->cfg; pg; pg = pg->next) {
    if (strcmp(pg->name, "problem") != 0) continue;
    prob = (struct section_problem_data*) pg;
    if (prob->abstract) continue;
    if (!prob->id) prob->id = cur_id + 1;
    cur_id = prob->id;
    if (prob->id <= 0 || prob->id > EJ_MAX_PROB_ID) {
      fprintf(flog, "Invalid problem ID\n");
      return -1;
    }
    if (prob->id >= total) total = prob->id + 1;
  }

  sstate->probs = 0;
  sstate->prob_a = 0;
  sstate->prob_flags = 0;
  if (total > 0) {
    sstate->prob_a = 4;
    while (total > sstate->prob_a) sstate->prob_a *= 2;
    XCALLOC(sstate->probs, sstate->prob_a);
    XCALLOC(sstate->prob_flags, sstate->prob_a);
    XALLOCAZ(prob_no_any, sstate->prob_a);
    for (pg = sstate->cfg; pg; pg = pg->next) {
      if (strcmp(pg->name, "problem") != 0) continue;
      prob = (struct section_problem_data*) pg;
      if (prob->abstract) continue;
      if (sstate->probs[prob->id]) {
        fprintf(flog, "Duplicated problem id %d\n", prob->id);
        return -1;
      }
      sstate->probs[prob->id] = prob;
      if (prob->super[0]) {
        for (i = 0; i < sstate->aprob_u; i++)
          if (!strcmp(prob->super, sstate->aprobs[i]->short_name))
            break;
        if (i == sstate->aprob_u) {
          fprintf(flog, "Abstract problem `%s' not found\n", prob->super);
          return -1;
        }
      }
      if (prepare_check_forbidden_prob(flog, prob) < 0)
        return -1;

      prepare_set_concr_problem_defaults(prob, global);

      fuh = open_memstream(&fuh_text, &fuh_size);
      prepare_unparse_unhandled_prob(fuh, prob, global);
      close_memstream(fuh); fuh = 0;
      if (fuh_text && *fuh_text) {
        prob->unhandled_vars = fuh_text;
      } else {
        xfree(fuh_text);
      }
      fuh_text = 0; fuh_size = 0;
    }
  }

  // collect abstract testers
  total = 0;
  for (pg = sstate->cfg; pg; pg = pg->next) {
    if (strcmp(pg->name, "tester")) continue;
    tst = (struct section_tester_data*) pg;
    if (!tst->abstract) continue;
    // check, that we know such abstract tester
    if ((arch = prepare_unparse_is_supported_tester(tst->name)) < 0) {
      fprintf(flog, "Unsupported abstract tester `%s'\n", tst->name);
      return -1;
    }
    if ((i = prepare_unparse_is_supported_arch(tst->arch)) < 0) {
      fprintf(flog, "Unsupported tester architecture `%s'\n", tst->arch);
      return -1;
    }
    if (i != arch) {
      fprintf(flog, "Abstract tester name does not match tester arch\n");
      return -1;
    }
    if (tst->id) {
      fprintf(flog, "Abstract tester must not define tester ID\n");
      return -1;
    }
    if (tst->problem_name[0]) {
      fprintf(flog, "Abstract tester must not define problem name\n");
      return -1;
    }
    if (tst->problem) {
      fprintf(flog, "Abstract tester must not define problem ID\n");
      return -1;
    }
    total++;
  }

  /* Relax, try to work without testers... */
  /*
  if (!total) {
    fprintf(flog, "No abstract testers defined\n");
    return -1;
  }
  */

  sstate->atester_total = total;
  if (total > 0) {
    XCALLOC(sstate->atesters, sstate->atester_total);
    for (pg = sstate->cfg, i = 0; pg; pg = pg->next) {
      if (strcmp(pg->name, "tester")) continue;
      tst = (struct section_tester_data*) pg;
      if (!tst->abstract) continue;
      sstate->atesters[i++] = tst;
      // FIXME: check for unhandled fields
    }
  }

  // collect concrete testers, attempting to recover vm limit, stack limit
  // and checker name
  total = 0; cur_id = 0;
  for (pg = sstate->cfg; pg; pg = pg->next) {
    if (strcmp(pg->name, "tester") != 0) continue;
    tst = (struct section_tester_data*) pg;
    if (tst->abstract) continue;
    if (!tst->id) tst->id = cur_id + 1;
    cur_id = tst->id;
    if (tst->id <= 0 || tst->id > EJ_MAX_TESTER) {
      fprintf(flog, "Invalid tester ID\n");
      return -1;
    }
    if (tst->id >= total) total = tst->id + 1;
  }

  sstate->tester_total = total;
  if (total > 0) {
    XCALLOC(sstate->testers, sstate->tester_total);
  }
  for (pg = sstate->cfg; pg; pg = pg->next) {
    if (strcmp(pg->name, "tester") != 0) continue;
    tst = (struct section_tester_data*) pg;
    if (tst->abstract) continue;
    if (sstate->testers[tst->id]) {
      fprintf(flog, "Duplicated tester ID %d\n", tst->id);
      return -1;
    }
    sstate->testers[tst->id] = tst;
    if (tst->super && tst->super[0] && tst->super[1]) {
      fprintf(flog, "Tester %d has several supertesters\n", tst->id);
      return -1;
    }
    atst = 0;
    if (tst->super) {
      for (i = 0; i < sstate->atester_total; i++)
        if (!strcmp(sstate->atesters[i]->name, tst->super[0]))
          break;
      if (i == sstate->atester_total) {
        fprintf(flog, "Abstract tester `%s' not found\n", tst->super[0]);
        return -1;
      }
      atst = sstate->atesters[i];
    }
    if (tst->any) {
      continue;
    }
    prob = 0;
    if (tst->problem && tst->problem_name[0]) {
      fprintf(flog, "Both problem and problem_name fields cannot be set\n");
      return -1;
    } else if (tst->problem) {
      if (tst->problem <= 0 || tst->problem >= sstate->prob_a
          || !sstate->probs[tst->problem]) {
        fprintf(flog, "problem %d is invalid\n", tst->problem);
        return -1;
      }
      prob = sstate->probs[tst->problem];
    } else if (tst->problem_name[0]) {
      for (i = 1; i < sstate->prob_a; i++)
        if (sstate->probs[i]
            && !strcmp(sstate->probs[i]->short_name, tst->problem_name))
          break;
      if (i == sstate->prob_a) {
        fprintf(flog, "Problem `%s' does not exist\n", tst->problem_name);
        return -1;
      }
      prob = sstate->probs[i];
    } else {
      fprintf(flog, "Neither problem not problem_name are set\n");
      return -1;
    }
    prob_no_any[prob->id] = 1;

    vm_size = tst->max_vm_size;
    if (vm_size == -1L && atst) vm_size = atst->max_vm_size;
    st_size = tst->max_stack_size;
    if (st_size == -1L && atst) st_size = atst->max_stack_size;
    rss_size = tst->max_rss_size;
    if (rss_size == -1L && atst) rss_size = atst->max_rss_size;
    if (vm_size != -1L) {
      if (prob->max_vm_size < 0) prob->max_vm_size = vm_size;
      if (prob->max_vm_size != vm_size) {
        fprintf(flog, "Conflicting max_vm_size specifications for problem `%s'\n", prob->short_name);
        return -1;
      }
    }
    if (st_size != -1L) {
      if (prob->max_stack_size < 0) prob->max_stack_size = st_size;
      if (prob->max_stack_size != st_size) {
        fprintf(flog, "Conflicting max_stack_size specifications for problem `%s'\n", prob->short_name);
        return -1;
      }
    }
    if (rss_size != -1L) {
      if (prob->max_rss_size < 0) prob->max_rss_size = rss_size;
      if (prob->max_rss_size != rss_size) {
        fprintf(flog, "Conflicting max_rss_size specifications for problem `%s'\n", prob->short_name);
        return -1;
      }
    }
  }

  for (i = 0; i < sstate->tester_total; i++) {
    if (!(tst = sstate->testers[i])) continue;

    atst = 0;
    if (tst->super) {
      for (j = 0; j < sstate->atester_total; j++)
        if (!strcmp(sstate->atesters[j]->name, tst->super[0]))
          break;
      if (j == sstate->atester_total) {
        fprintf(flog, "Abstract tester `%s' not found\n", tst->super[0]);
        return -1;
      }
      atst = sstate->atesters[j];
    }

    if (!tst->any) continue;

    for (j = 0; j < sstate->prob_a; j++) {
      if (!(prob = sstate->probs[j])) continue;
      if (prob_no_any[j]) continue;

      vm_size = tst->max_vm_size;
      if (vm_size == -1L && atst) vm_size = atst->max_vm_size;
      st_size = tst->max_stack_size;
      if (st_size == -1L && atst) st_size = atst->max_stack_size;
      rss_size = tst->max_rss_size;
      if (rss_size == -1L && atst) rss_size = atst->max_rss_size;
      if (vm_size != -1L) {
        if (prob->max_vm_size < 0) prob->max_vm_size = vm_size;
        if (prob->max_vm_size != vm_size) {
          fprintf(flog, "Conflicting max_vm_size specifications for problem `%s'\n", prob->short_name);
          return -1;
        }
      }
      if (st_size != -1L) {
        if (prob->max_stack_size < 0) prob->max_stack_size = st_size;
        if (prob->max_stack_size != st_size) {
          fprintf(flog, "Conflicting max_stack_size specifications for problem `%s'\n", prob->short_name);
          return -1;
        }
      }
      if (rss_size != -1L) {
        if (prob->max_rss_size < 0) prob->max_rss_size = rss_size;
        if (prob->max_rss_size != rss_size) {
          fprintf(flog, "Conflicting max_rss_size specifications for problem `%s'\n", prob->short_name);
          return -1;
        }
      }
    }
  }

  XALLOCA(mem_lims, sstate->prob_a);
  XALLOCA(st_lims, sstate->prob_a);
  XALLOCA(mem_cnt, sstate->prob_a);
  XALLOCA(st_cnt, sstate->prob_a);

  // propagate most used memory limit to superproblem
  /*
  for (i = 0; i < sstate->aprob_u; i++) {
    aprob = sstate->aprobs[i];
    mem_u = 0;
    st_u = 0;
    XMEMZERO(mem_cnt, sstate->prob_a);
    XMEMZERO(st_cnt, sstate->prob_a);
    for (j = 1; j < sstate->prob_a; j++) {
      if (!(prob = sstate->probs[j]) || !prob->super[0]
          || strcmp(prob->super, aprob->short_name)) continue;
      if (prob->max_vm_size != -1L) {
        for (k = 0; k < mem_u; k++)
          if (mem_lims[k] == prob->max_vm_size)
            break;
        if (k == mem_u) mem_u++;
        mem_lims[k] = prob->max_vm_size;
        mem_cnt[k]++;
      }
      if (prob->max_stack_size != -1L) {
        for (k = 0; k < st_u; k++)
          if (st_lims[k] == prob->max_stack_size)
            break;
        if (k == st_u) st_u++;
        st_lims[k] = prob->max_stack_size;
        st_cnt[k]++;
      }
    }
    if (mem_u > 0) {
      max_i = 0;
      for (i = 1; i < mem_u; i++)
        if (mem_cnt[i] > mem_cnt[max_i])
          max_i = i;
      aprob->max_vm_size = mem_lims[max_i];
      for (j = 1; j < sstate->prob_a; j++) {
        if (!(prob = sstate->probs[j]) || !prob->super[0]
            || strcmp(prob->super, aprob->short_name)) continue;
        if (prob->max_vm_size == -1L) {
          prob->max_vm_size = 0;
        } else if (prob->max_vm_size == aprob->max_vm_size) {
          prob->max_vm_size = -1L;
        }
      }
    }
    if (st_u > 0) {
      max_i = 0;
      for (i = 1; i < st_u; i++)
        if (st_cnt[i] > st_cnt[max_i])
          max_i = i;
      aprob->max_stack_size = st_lims[max_i];
      for (j = 1; j < sstate->prob_a; j++) {
        if (!(prob = sstate->probs[j]) || !prob->super[0]
            || strcmp(prob->super, aprob->short_name)) continue;
        if (prob->max_stack_size == -1L) {
          prob->max_stack_size = 0;
        } else if (prob->max_stack_size == aprob->max_stack_size) {
          prob->max_stack_size = -1L;
        }
      }
    }
  }
  */

  // assign this check_cmd to all abstract problems without check_cmd
  for (i = 0; i < sstate->aprob_u; i++)
    if (!(aprob = sstate->aprobs[i])->check_cmd) {
      usprintf(&aprob->check_cmd, "%s", check_cmd);
    }

  sstate->contest_start_cmd_text = do_load_file(conf_dir, global->contest_start_cmd);
  sstate->contest_stop_cmd_text = do_load_file(conf_dir, global->contest_stop_cmd);
  sstate->stand_header_text = do_load_file(conf_dir, global->stand_header_file);
  sstate->stand_footer_text = do_load_file(conf_dir, global->stand_footer_file);
  sstate->stand2_header_text = do_load_file(conf_dir, global->stand2_header_file);
  sstate->stand2_footer_text = do_load_file(conf_dir, global->stand2_footer_file);
  sstate->plog_header_text = do_load_file(conf_dir, global->plog_header_file);
  sstate->plog_footer_text = do_load_file(conf_dir, global->plog_footer_file);

  return 0;
}

int
super_load_cs_languages(
        const struct ejudge_cfg *config,
        struct sid_state *sstate,
        char **extra_compile_dirs,
        int check_version_flag,
        unsigned char *cs_conf_file_buf,
        int cs_conf_file_len)
{
  path_t extra_cs_conf_path;
  struct generic_section_config *cfg = 0, *p;
  struct section_language_data *lp;
  int max_lang = -1;
  int cur_lang = 1;
  path_t cmdpath;
  path_t script_dir;

  sstate->cs_langs_loaded = 1;

  if (!sstate->compile_home_dir) {
    sstate->compile_home_dir = xstrdup(config->compile_home_dir);
  }
  snprintf(cs_conf_file_buf, cs_conf_file_len, "%s/conf/compile.cfg",
           sstate->compile_home_dir);
  if (!(cfg = prepare_parse_config_file(cs_conf_file_buf, 0))) return -1;
  sstate->cs_cfg = cfg;

  if (extra_compile_dirs) {
    int extra_cs_total = sarray_len(extra_compile_dirs);
    if (extra_cs_total > 0) {
      sstate->extra_cs_cfgs_total = extra_cs_total;
      XCALLOC(sstate->extra_cs_cfgs, sstate->extra_cs_cfgs_total + 1);
    }
  }

  if (sstate->extra_cs_cfgs_total > 0) {
    for (int i = 0; i < sstate->extra_cs_cfgs_total; ++i) {
      // check for win32_compile
      if (!strcmp(extra_compile_dirs[i], "win32_compile")) {
        sstate->enable_win32_languages = 1;
      }
      extra_cs_conf_path[0] = 0;
      if (os_IsAbsolutePath(extra_compile_dirs[i])) {
        snprintf(extra_cs_conf_path, sizeof(extra_cs_conf_path),
                 "%s/conf/compile.cfg", extra_compile_dirs[i]);
      } else if (config && config->contests_home_dir) {
        snprintf(extra_cs_conf_path, sizeof(extra_cs_conf_path),
                 "%s/%s/conf/compile.cfg", config->contests_home_dir,
                 extra_compile_dirs[i]);
      } else {
#if defined EJUDGE_CONTESTS_HOME_DIR
        snprintf(extra_cs_conf_path, sizeof(extra_cs_conf_path),
                 "%s/%s/conf/compile.cfg", EJUDGE_CONTESTS_HOME_DIR,
                 extra_compile_dirs[i]);
#endif
      }
      if (extra_cs_conf_path[0]) {
        sstate->extra_cs_cfgs[i] = prepare_parse_config_file(extra_cs_conf_path, 0);
      }
    }
  }

  cfg = sstate->cs_cfg;
  for (p = cfg; p; p = p->next) {
    if (strcmp(p->name, "language") != 0) continue;
    lp = (typeof(lp)) p;
    if (lp->id < 0) {
      fprintf(stderr, "%s: language identifier is negative\n", cs_conf_file_buf);
      goto failed;
    }
    if (!lp->id) lp->id = cur_lang++;
    if (lp->id > max_lang) max_lang = lp->id;
  }

  if (max_lang <= 0) {
    fprintf(stderr, "%s: no languages defined\n", cs_conf_file_buf);
    goto failed;
  }

  if (sstate->extra_cs_cfgs_total > 0) {
    for (int i = 0; i < sstate->extra_cs_cfgs_total; ++i) {
      cfg = sstate->extra_cs_cfgs[i];
      for (p = cfg; p; p = p->next) {
        if (strcmp(p->name, "language") != 0) continue;
        lp = (typeof(lp)) p;
        if (lp->id > 0 && lp->id > max_lang) max_lang = lp->id;
      }
    }
  }

  sstate->cs_lang_total = max_lang + 1;
  XCALLOC(sstate->cs_langs, sstate->cs_lang_total);
  XCALLOC(sstate->cs_loc_map, sstate->cs_lang_total);
  XCALLOC(sstate->cs_lang_names, sstate->cs_lang_total);

  cfg = sstate->cs_cfg;
  for (p = cfg; p; p = p->next) {
    if (strcmp(p->name, "language") != 0) continue;
    lp = (typeof(lp)) p;
    if (sstate->cs_langs[lp->id]) {
      fprintf(stderr, "%s: duplicated language id %d\n", cs_conf_file_buf, lp->id);
      goto failed;
    }
    sstate->cs_langs[lp->id] = lp;
  }

  if (sstate->extra_cs_cfgs_total > 0) {
    for (int i = 0; i < sstate->extra_cs_cfgs_total; ++i) {
      cfg = sstate->extra_cs_cfgs[i];
      for (p = cfg; p; p = p->next) {
        if (strcmp(p->name, "language") != 0) continue;
        lp = (typeof(lp)) p;
        if (lp->id > 0 && !sstate->cs_langs[lp->id]) {
          sstate->cs_langs[lp->id] = lp;
          lp->compile_dir_index = i + 1;
        }
      }
    }
  }

  /*
  script_dir[0] = 0;
  if (config->script_dir) {
    snprintf(script_dir, sizeof(script_dir), "%s", config->script_dir);
  }
#if defined EJUDGE_SCRIPT_DIR
  if (!*script_dir) {
    snprintf(script_dir, sizeof(script_dir), "%s", EJUDGE_SCRIPT_DIR);
  }
#endif
  */
  script_dir[0] = 0;
  if (config->compile_home_dir) {
    snprintf(script_dir, sizeof(script_dir), "%s/scripts",
             config->compile_home_dir);
  }
  if (!script_dir[0] && config->contests_home_dir) {
    snprintf(script_dir, sizeof(script_dir), "%s/compile/scripts",
             config->contests_home_dir);
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!script_dir[0]) {
    snprintf(script_dir, sizeof(script_dir), "%s/compile/scripts",
             EJUDGE_CONTESTS_HOME_DIR);
  }
#endif

  if (*script_dir) {
    // detect actual language versions
    for (cur_lang = 1; cur_lang < sstate->cs_lang_total; cur_lang++) {
      if (!(lp = sstate->cs_langs[cur_lang])) continue;
      if (lp->compile_dir_index > 0) {
        sstate->cs_lang_names[cur_lang] = xstrdup(lp->long_name);
        continue;
      }
      if (!lp->cmd) continue;
      snprintf(cmdpath, sizeof(cmdpath), "%s/%s-version", script_dir, lp->cmd);

      if (access(cmdpath, X_OK) >= 0) {
        char *args[4];
        args[0] = cmdpath;
        args[1] = "-f";
        args[2] = NULL;
        unsigned char *stdout_text = NULL;
        unsigned char *stderr_text = NULL;
        int r = ejudge_invoke_process(args, NULL, NULL, "/dev/null", NULL, 0, &stdout_text, &stderr_text);
        if (!r) {
          if (!stdout_text) stdout_text = xstrdup("");
          sstate->cs_lang_names[cur_lang] = chop2(stdout_text);
          stdout_text = NULL;
        } else {
          sstate->cs_lang_names[cur_lang] = xstrdup("");
          if (!stderr_text) stderr_text = xstrdup("");
          for (unsigned char *s = stderr_text; *s; ++s) {
            if (*s < ' ') *s = ' ';
          }
          fprintf(stderr, "%s: %s\n", sstate->cs_langs[cur_lang]->short_name, stderr_text);
        }
        xfree(stdout_text); stdout_text = NULL;
        xfree(stderr_text); stderr_text = NULL;
      }
    }
  }

  return 0;

 failed:
  return -1;
}

struct section_problem_data *
super_html_create_problem(
        struct sid_state *sstate,
        int prob_id)
{
  if (prob_id >= sstate->prob_a) {
    int new_prob_a = sstate->prob_a;
    struct section_problem_data **new_probs;
    int *new_flags;

    if (!new_prob_a) new_prob_a = 16;
    while (prob_id >= new_prob_a) new_prob_a *= 2;
    XCALLOC(new_probs, new_prob_a);
    XCALLOC(new_flags, new_prob_a);
    if (sstate->prob_a) {
      XMEMMOVE(new_probs, sstate->probs, sstate->prob_a);
      XMEMMOVE(new_flags, sstate->prob_flags, sstate->prob_a);
    }
    xfree(sstate->probs);
    xfree(sstate->prob_flags);
    sstate->probs = new_probs;
    sstate->prob_flags = new_flags;
    sstate->prob_a = new_prob_a;
  }

  if (sstate->probs[prob_id])
    return NULL;

  struct section_problem_data *prob = prepare_alloc_problem();
  prepare_problem_init_func(&prob->g);
  sstate->cfg = param_merge(&prob->g, sstate->cfg);
  sstate->probs[prob_id] = prob;
  prob->id = prob_id;
  sstate->prob_flags[prob_id] = 0;
  return prob;
}

int
super_html_get_serve_header_and_footer(
        const unsigned char *path,
        unsigned char **p_header,
        unsigned char **p_footer)
{
  struct stat sb;
  char *text = 0;
  size_t size = 0;
  int at_beg = 1;
  unsigned char *s, *after_start = 0, *before_end = 0, *tstart, *p = 0;
  unsigned char *header = 0, *footer = 0;

  if (stat(path, &sb) < 0) return -SSERV_ERR_FILE_NOT_EXIST;
  if (generic_read_file(&text, 0, &size, 0, 0, path, 0) < 0)
    return -SSERV_ERR_FILE_READ_ERROR;

  tstart = (unsigned char *) text;
  if (!strncmp(tstart, "# -*- ", 6)) {
    while (*tstart && *tstart != '\n') tstart++;
    if (*tstart == '\n') tstart++;
    size -= (tstart - (unsigned char*) text);
  }

  s = tstart;
  while (s - tstart < size) {
    if (at_beg) {
      if (*s == '#' || *s == ';') {
        // comment line
        if (after_start && !before_end) before_end = s;
      } else {
        // regular line
        if (!after_start) after_start = s;
        else before_end = 0;
      }
    }
    at_beg = 0;
    if (*s == '\r' && s[1] == '\n') {
      s += 2;
      at_beg = 1;
    } else if (*s == '\n') {
      s++;
      at_beg = 1;
    } else if (*s == '\r') {
      s++;
      at_beg = 1;
    } else {
      s++;
    }
  }

  if (!before_end) {
    footer = xstrdup("");
  } else {
    footer = p = xmalloc(size + 1 - (before_end - tstart));
    at_beg = 1;
    s = before_end;
    while (s - tstart < size) {
      if (at_beg && (*s == '#' || *s == ';')) *s = '#';
      at_beg = 0;
      if (*s == '\r' && s[1] == '\n') {
        *p++ = '\n';
        s += 2;
        at_beg = 1;
      } else if (*s == '\n') {
        *p++ = *s++;
        at_beg = 1;
      } else if (*s == '\r') {
        *p++ = '\n';
        s++;
        at_beg = 1;
      } else {
        *p++ = *s++;
      }
    }
    *p = 0;
  }

  if (!after_start) after_start = tstart + size;
  header = p = xmalloc(after_start - tstart + 1);
  at_beg = 1;
  s = tstart;
  while (s != after_start) {
    if (at_beg && (*s == '#' || *s == ';')) *s = '#';
    at_beg = 0;
    if (*s == '\r' && s[1] == '\n') {
      *p++ = '\n';
      s += 2;
      at_beg = 1;
    } else if (*s == '\n') {
      *p++ = *s++;
      at_beg = 1;
    } else if (*s == '\r') {
      *p++ = '\n';
      s++;
      at_beg = 1;
    } else {
      *p++ = *s++;
    }
  }
  *p = 0;

  if (p_header) *p_header = header;
  if (p_footer) *p_footer = footer;

  xfree(text);
  return 0;
}

void
super_html_serve_unparse_serve_cfg(
        FILE *f,
        const struct ejudge_cfg *config,
        const struct sid_state *sstate)
{
  struct section_global_data *global = sstate->global;
  struct contest_desc *cnts = sstate->edited_cnts;
  int i, active_langs, need_variant_map = 0;

  if (!global) return;
  if (sstate->serve_parse_errors) return;

  if (cnts) {
    if (cnts->root_dir) {
      xstrdup3(&global->root_dir, cnts->root_dir);
    }
    if (cnts->conf_dir) {
      xstrdup3(&global->conf_dir, cnts->conf_dir);
    }
  }
  if (sstate->enable_stand2 && (!global->stand2_file_name || !global->stand2_file_name[0])) {
    xstrdup3(&global->stand2_file_name, "standings2.html");
  }
  if (!sstate->enable_stand2) {
    xfree(global->stand2_file_name);
    global->stand2_file_name = NULL;
  }
  if (sstate->enable_plog && (!global->plog_file_name || !global->plog_file_name[0])) {
    xstrdup3(&global->plog_file_name, "plog.html");
  }
  if (!sstate->enable_plog) {
    xfree(global->plog_file_name);
    global->plog_file_name = NULL;
  }
  if (sstate->enable_extra_col && (!global->stand_extra_format || !global->stand_extra_format[0])) {
    xstrdup3(&global->stand_extra_format, "%Mc");
  }
  if (!sstate->enable_extra_col) {
    xfree(global->stand_extra_format);
    global->stand_extra_format = NULL;
  }

  for (i = 1; i < sstate->prob_a; i++)
    if (sstate->probs[i] && sstate->probs[i]->variant_num > 0)
      need_variant_map = 1;

  prepare_unparse_global(f, cnts, global, sstate->compile_home_dir, need_variant_map);

  if (sstate->lang_a > 0) {
    for (i = 1, active_langs = 0; i < sstate->lang_a; i++) {
      if (!sstate->langs[i]) continue;
      prepare_unparse_lang(f, sstate->langs[i], 0, sstate->lang_opts[i], sstate->lang_libs[i]);
      active_langs++;
    }
  }

  for (i = 0; i < sstate->aprob_u; i++)
    prepare_unparse_prob(f, sstate->aprobs[i], NULL, global, global->score_system);

  for (i = 0; i < sstate->prob_a; i++) {
    const struct section_problem_data *prob = sstate->probs[i];
    if (!prob) continue;
    const struct section_problem_data *aprob = NULL;
    if (/*prob->super &&*/ prob->super[0]) {
      for (int j = 0; j < sstate->aprob_u; ++j) {
        const struct section_problem_data *aa = sstate->aprobs[j];
        if (aa && /*aa->short_name &&*/ !strcmp(prob->super, aa->short_name)) {
          aprob = aa;
          break;
        }
      }
    }

    prepare_unparse_prob(f, prob, aprob, global, global->score_system);
  }

  prepare_unparse_testers(f, global->secure_run,
                          sstate->global,
                          sstate->lang_a,
                          sstate->langs,
                          sstate->aprob_u,
                          sstate->aprobs,
                          sstate->prob_a,
                          sstate->probs,
                          sstate->atester_total,
                          sstate->atesters,
                          config->testing_work_dir,
                          config->contests_home_dir);
}

int
super_html_serve_unparse_and_save(
        const unsigned char *path,
        const unsigned char *tmp_path,
        const struct sid_state *sstate,
        const struct ejudge_cfg *config,
        const unsigned char *charset,
        const unsigned char *header,
        const unsigned char *footer,
        const unsigned char *audit)
{
  char *new_text = 0;
  size_t new_size = 0;
  char *old_text = 0;
  size_t old_size = 0;
  FILE *f;

  if (sstate->serve_parse_errors || !sstate->global) return 0;

  if (!charset || !*charset) charset = EJUDGE_CHARSET;
  if (!header) header = "";
  if (!footer) footer = "";
  f = open_memstream(&new_text, &new_size);
  fprintf(f, "# -*- coding: %s -*-\n", charset);
  fputs(header, f);
  super_html_serve_unparse_serve_cfg(f, config, sstate);
  fputs(footer, f);
  close_memstream(f); f = 0;

  if (generic_read_file(&old_text, 0, &old_size, 0, 0, path, 0) >= 0
      && new_size == old_size && memcmp(new_text, old_text, new_size) == 0) {
    info("serve_unparse_and_save: %s not changed", path);
    xfree(old_text);
    xfree(new_text);
    unlink(tmp_path);
    return 0;
  }
  xfree(old_text); old_text = 0; old_size = 0;

  if (!(f = fopen(tmp_path, "w"))) {
    xfree(new_text);
    return -1;
  }
  fwrite(new_text, 1, new_size, f);
  xfree(new_text); new_text = 0; new_size = 0;
  fputs(audit, f);
  if (ferror(f) || fclose(f) < 0) {
    fclose(f);
    unlink(tmp_path);
    return -1;
  }

  return 1;
}

int
super_html_get_contest_header_and_footer(
        const unsigned char *path,
        unsigned char **before_start,
        unsigned char **after_end)
{
  char *xml_text = 0, *p1, *p2, *p3;
  unsigned char *s1 = 0, *s2 = 0;
  size_t xml_text_size = 0;
  struct stat sb;
  int errcode = 0;

  if (stat(path, &sb) < 0) return -SSERV_ERR_FILE_NOT_EXIST;

  if (generic_read_file(&xml_text, 0, &xml_text_size, 0, 0, path, 0) < 0)
    return -SSERV_ERR_FILE_READ_ERROR;

  if (!(p1 = strstr(xml_text, "<contest "))) {
    errcode = -SSERV_ERR_FILE_FORMAT_INVALID;
    goto failure;
  }
  if (!(p2 = strstr(xml_text, "</contest>"))) {
    errcode = -SSERV_ERR_FILE_FORMAT_INVALID;
    goto failure;
  }
  p3 = xml_text;
  if (!strncmp(p3, "<?xml ", 6)) {
    while (*p3 != '\n' && p3 < p1) p3++;
    if (*p3 == '\n') p3++;
  }

  s1 = xmalloc(xml_text_size + 1);
  s2 = xmalloc(xml_text_size + 1);

  memcpy(s1, p3, p1 - p3);
  s1[p1 - p3] = 0;
  strcpy(s2, p2 + 10);

  *before_start = s1;
  *after_end = s2;

  xfree(xml_text);
  return 0;

 failure:
  xfree(xml_text);
  return errcode;
}
