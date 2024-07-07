/* -*- mode: c -*- */

/* Copyright (C) 2012-2024 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/parsecfg.h"
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
#include "ejudge/cJSON.h"
#include "ejudge/random.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"
#include "ejudge/logger.h"

#include <ctype.h>
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
  const unsigned char *compile_spool_dir = "";

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

  if (global->enable_language_import > 0) {
    sstate->cscs = xmalloc(sizeof(*sstate->cscs));
    compile_servers_config_init(sstate->cscs);
    const unsigned char *global_id = config->contest_server_id;
    if (global->compile_server_id && global->compile_server_id[0]) {
      global_id = global->compile_server_id;
    }
    (void) compile_servers_get(sstate->cscs, global_id);
  } else {
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
  }

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

  if (global->enable_language_import > 0) {
    int lang_count = 0;
    for (pg = sstate->cfg; pg; pg = pg->next) {
      if (!strcmp(pg->name, "language")) {
        ++lang_count;
      }
    }
    sstate->lang_a = lang_count + 1;
    XCALLOC(sstate->langs, sstate->lang_a + 1);
    int idx = 0;
    for (pg = sstate->cfg; pg; pg = pg->next) {
      if (strcmp(pg->name, "language") != 0) continue;
      lang = (struct section_language_data *) pg;
      if (lang->id < 0 || lang->id > EJ_MAX_LANG_ID) {
        fprintf(flog, "Invalid language id = %d for language '%s'\n", lang->id, lang->short_name);
        return -1;
      }
      if (lang->compile_server_id && lang->compile_server_id[0]) {
        (void) compile_servers_get(sstate->cscs, lang->compile_server_id);
      }
      sstate->langs[++idx] = lang;
    }

#if !defined EJUDGE_COMPILE_SPOOL_DIR
    fprintf(flog, "--enable-compile-spool-dir must be enabled\n");
    return -1;
#else
    compile_spool_dir = EJUDGE_COMPILE_SPOOL_DIR;
#endif
    if (compile_servers_collect(sstate->cscs, flog, compile_spool_dir) < 0) {
      return -1;
    }

    int max_lang_id = 0;
    for (int i = 0; i < sstate->lang_a; ++i) {
      lang = sstate->langs[i];
      if (!lang) continue;
      if (lang->id > 0) {
        if (lang->id > max_lang_id) max_lang_id = lang->id;
        if (lang->compile_id > 0 && lang->compile_id > max_lang_id) max_lang_id = lang->compile_id;
        struct compile_server_config *csc = NULL;
        if (lang->compile_server_id && lang->compile_server_id[0]) {
          csc = compile_servers_get(sstate->cscs, lang->compile_server_id);
          if (!csc) {
            fprintf(flog, "Compilation server '%s' is not available\n", lang->compile_server_id);
            return -1;
          }
        } else {
          csc = &sstate->cscs->v[0];
          if (!csc) {
            fprintf(flog, "Default compilation server is not available\n");
            return -1;
          }
        }
        if (csc->errors) {
          fprintf(flog, "Failed to load compilation server '%s' configuration\n", csc->id);
          return -1;
        }
        int compile_id = lang->id;
        if (lang->compile_id > 0) compile_id = lang->compile_id;
        if (compile_id <= 0 || compile_id > csc->max_lang || !csc->langs[compile_id]) {
          fprintf(flog, "Language id %d is invalid for compilation server '%s'\n", compile_id, csc->id);
          return -1;
        }
        struct section_language_data *serv_lang = csc->langs[compile_id];
        if (strcmp(serv_lang->short_name, lang->short_name) != 0) {
          fprintf(flog, "Short name mismatch: language %d (%s) and compile server %s language %d (%s)\n",
                  lang->id, lang->short_name, csc->id, serv_lang->id, serv_lang->short_name);
          return -1;
        }
      } else {
        lang->compile_id = 0;
        struct compile_server_config *csc = NULL;
        if (lang->compile_server_id && lang->compile_server_id[0]) {
          csc = compile_servers_get(sstate->cscs, lang->compile_server_id);
          if (!csc) {
            fprintf(flog, "Compilation server '%s' is not available\n", lang->compile_server_id);
            return -1;
          }
        } else {
          csc = &sstate->cscs->v[0];
          if (!csc) {
            fprintf(flog, "Default compilation server is not available\n");
            return -1;
          }
        }
        if (csc->errors) {
          fprintf(flog, "Failed to load compilation server '%s' configuration\n", csc->id);
          return -1;
        }
        struct section_language_data *serv_lang = NULL;
        for (int i = 0; i <= csc->max_lang; ++i) {
          struct section_language_data *sl = csc->langs[i];
          if (sl && !strcmp(sl->short_name, lang->short_name)) {
            serv_lang = sl;
            break;
          }
        }
        if (!serv_lang) {
          fprintf(flog, "Language '%s' not found on compilation server '%s'\n", lang->short_name, csc->id);
          return -1;
        }
        lang->id = serv_lang->id;
        if (lang->id > max_lang_id) max_lang_id = lang->id;
      }
    }
    // preallocate for all possible langs
    for (int i = 0; i < sstate->cscs->u; ++i) {
      int v = sstate->cscs->v[i].max_lang;
      if (v > max_lang_id) max_lang_id = v;
    }
    struct section_language_data **new_langs = NULL;
    XCALLOC(new_langs, max_lang_id + 1);
    for (int i = 0; i < sstate->lang_a; ++i) {
      struct section_language_data *lang = sstate->langs[i];
      if (!lang) continue;
      if (lang->id <= 0 || lang->id > max_lang_id) {
        fprintf(flog, "Invalid language id = %d for language '%s'\n", lang->id, lang->short_name);
        return -1;
      }
      if (new_langs[lang->id]) {
        fprintf(flog, "Duplicated language id %d for languages '%s' and '%s'\n", lang->id, new_langs[lang->id]->short_name, lang->short_name);
        return -1;
      }
      new_langs[lang->id] = lang;
    }
    xfree(sstate->langs);
    sstate->langs = new_langs;
    sstate->lang_a = max_lang_id + 1;

    XCALLOC(sstate->serv_langs, sstate->lang_a);
    XCALLOC(sstate->lang_extra, sstate->lang_a);
    XCALLOC(sstate->serv_extra, sstate->lang_a);

    for (int i = 0; i < sstate->lang_a; ++i) {
      sstate->lang_extra[i].enabled = -1;
    }

    for (int lang_id = 0; lang_id < sstate->lang_a; ++lang_id) {
      if (!(lang = sstate->langs[lang_id])) continue;
      struct compile_server_config *csc = NULL;
      if (lang->compile_server_id && lang->compile_server_id[0]) {
        csc = compile_servers_get(sstate->cscs, lang->compile_server_id);
      } else {
        csc = &sstate->cscs->v[0];
      }
      ASSERT(csc);
      int compile_id = lang->id;
      if (lang->compile_id > 0) compile_id = lang->compile_id;
      ASSERT(compile_id > 0 && compile_id <= csc->max_lang);
      struct section_language_data *serv_lang = csc->langs[compile_id];
      ASSERT(serv_lang);
      sstate->serv_langs[compile_id] = serv_lang;
      sstate->serv_extra[compile_id].rev_lang_id = lang->id;
    }

    // inject languages from the primary compilation server
    struct compile_server_config *csc = &sstate->cscs->v[0];
    for (int serv_lang_id = 0; serv_lang_id <= csc->max_lang; ++serv_lang_id) {
      struct section_language_data *serv_lang = csc->langs[serv_lang_id];
      if (!serv_lang) continue;
      int found = 0;
      for (int lang_id = 0; lang_id < sstate->lang_a; ++lang_id) {
        if (sstate->serv_langs[lang_id] == serv_lang) {
          found = 1;
          break;
        }
      }
      if (found) continue;
      if (sstate->serv_langs[serv_lang_id]) {
        fprintf(flog, "Conflicting compile server '%s' languages with id %d: '%s', '%s'\n", csc->id, serv_lang_id, serv_lang->short_name, sstate->serv_langs[serv_lang_id]->short_name);
        return -1;
      }
      sstate->serv_langs[serv_lang_id] = serv_lang;
    }

    // collect server disabled languages
    for (int serv_lang_id = 0; serv_lang_id < sstate->lang_a; ++serv_lang_id) {
      struct section_language_data *serv_lang = sstate->serv_langs[serv_lang_id];
      if (!serv_lang) continue;
      int id = serv_lang_id;
      if (sstate->serv_extra[serv_lang_id].rev_lang_id > 0) id = sstate->serv_extra[serv_lang_id].rev_lang_id;
      if (serv_lang->disabled > 0) {
        sstate->lang_extra[id].enabled = 2;
      } else if (serv_lang->default_disabled > 0) {
        sstate->lang_extra[id].enabled = 0;
      }
      // 'enabled' is ignored in compile server config
    }

    // parse global language_import specs
    if (global->language_import && global->language_import[0]) {
      for (int i = 0; global->language_import[i]; ++i) {
        const unsigned char *str = global->language_import[i];
        int enable_flag = 0;
        const unsigned char *s = str;
        unsigned char short_name[64];
        if (!strncmp(str, "enable ", 7)) {
          s += 7;
          enable_flag = 1;
        } else if (!strncmp(str, "disable ", 8)) {
          s += 8;
        } else {
          fprintf(flog, "Invalid language import specification\n");
          return -1;
        }
        while (*s) {
          while (isspace(*s) || *s == ',') ++s;
          if (!*s) break;
          const unsigned char *q = s;
          while (*q && !isspace(*q) && *q != ',') ++q;
          if (q - s >= sizeof(short_name)) {
            fprintf(flog, "Language name is too long: '%s'", s);
            return -1;
          }
          memcpy(short_name, s, q - s);
          short_name[q-s] = 0;
          s = q;

          if (!strcmp(short_name, "all")) {
            for (int i = 0; i < sstate->lang_a; ++i) {
              if (sstate->lang_extra[i].enabled != 2) {
                sstate->lang_extra[i].enabled = enable_flag;
              }
            }
          } else {
            int found = 0;
            for (int lang_id = 0; lang_id < sstate->lang_a; ++lang_id) {
              lang = sstate->langs[lang_id];
              if (lang && !strcmp(lang->short_name, short_name)) {
                found = 1;
                if (sstate->lang_extra[lang_id].enabled != 2) {
                  sstate->lang_extra[lang_id].enabled = enable_flag;
                }
              }
            }
            if (!found) {
              for (int serv_lang_id = 0; serv_lang_id < sstate->lang_a; ++serv_lang_id) {
                struct section_language_data *serv_lang = sstate->serv_langs[serv_lang_id];
                if (serv_lang && sstate->serv_extra[serv_lang_id].rev_lang_id <= 0 && !strcmp(serv_lang->short_name, short_name)) {
                  found = 1;
                  if (sstate->lang_extra[serv_lang_id].enabled != 2) {
                    sstate->lang_extra[serv_lang_id].enabled = enable_flag;
                  }
                }
              }
            }
            if (!found) {
              fprintf(flog, "Language '%s' in import_languages is not found in the supported languages\n", short_name);
              return -1;
            }
          }
        }
      }
    }

    for (int lang_id = 0; lang_id < sstate->lang_a; ++lang_id) {
      if (!(lang = sstate->langs[lang_id])) continue;
      if (sstate->lang_extra[lang_id].enabled != 2) {
        if (lang->enabled > 0) {
          sstate->lang_extra[lang_id].enabled = 1;
        } else if (lang->disabled > 0) {
          sstate->lang_extra[lang_id].enabled = 0;
        }
      }
    }

    // collect unhandled vars and process options
    for (int lang_id = 0; lang_id < sstate->lang_a; ++lang_id) {
      if (!(lang = sstate->langs[lang_id])) continue;
      fuh = open_memstream(&fuh_text, &fuh_size);
      prepare_unparse_unhandled_lang(fuh, lang);
      close_memstream(fuh); fuh = NULL;
      if (fuh_text && *fuh_text) {
        lang->unhandled_vars = fuh_text;
      } else {
        xfree(fuh_text);
      }
      fuh_text = NULL; fuh_size = 0;

      if (lang->compiler_env && lang->compiler_env[0]) {
        char *l_opts_s = NULL, *l_libs_s = NULL, *l_flags_s = NULL;
        size_t l_opts_z = 0, l_libs_z = 0, l_flags_z = 0;
        FILE *l_opts_f = open_memstream(&l_opts_s, &l_opts_z);
        FILE *l_libs_f = open_memstream(&l_libs_s, &l_libs_z);
        FILE *l_flags_f = open_memstream(&l_flags_s, &l_flags_z);
        for (int j = 0; lang->compiler_env[j]; ++j) {
          if (!strncmp(lang->compiler_env[j], "EJUDGE_FLAGS=", 13)) {
            fprintf(l_flags_f, "%s\n", lang->compiler_env[j] + 13);
          } else if (!strncmp(lang->compiler_env[j], "EJUDGE_LIBS=", 12)) {
            fprintf(l_libs_f, "%s\n", lang->compiler_env[j] + 12);
          } else {
            fprintf(l_opts_f, "%s\n", lang->compiler_env[j]);
          }
        }
        fclose(l_opts_f);
        fclose(l_flags_f);
        fclose(l_libs_f);
        if (l_opts_z > 0) {
          sstate->lang_extra[lang_id].compiler_env = l_opts_s; l_opts_s = NULL;
        }
        if (l_flags_z > 0) {
          sstate->lang_extra[lang_id].ejudge_flags = l_flags_s; l_flags_s = NULL;
        }
        if (l_libs_z > 0) {
          sstate->lang_extra[lang_id].ejudge_libs = l_libs_s; l_libs_s = NULL;
        }
        free(l_opts_s);
        free(l_libs_s);
        free(l_flags_s);
      }
    }

    for (int serv_lang_id = 0; serv_lang_id < sstate->lang_a; ++serv_lang_id) {
      if (!(lang = sstate->serv_langs[serv_lang_id])) continue;
      if (lang->compiler_env && lang->compiler_env[0]) {
        char *l_opts_s = NULL, *l_libs_s = NULL, *l_flags_s = NULL;
        size_t l_opts_z = 0, l_libs_z = 0, l_flags_z = 0;
        FILE *l_opts_f = open_memstream(&l_opts_s, &l_opts_z);
        FILE *l_libs_f = open_memstream(&l_libs_s, &l_libs_z);
        FILE *l_flags_f = open_memstream(&l_flags_s, &l_flags_z);
        for (int j = 0; lang->compiler_env[j]; ++j) {
          if (!strncmp(lang->compiler_env[j], "EJUDGE_FLAGS=", 13)) {
            fprintf(l_flags_f, "%s\n", lang->compiler_env[j] + 13);
          } else if (!strncmp(lang->compiler_env[j], "EJUDGE_LIBS=", 12)) {
            fprintf(l_libs_f, "%s\n", lang->compiler_env[j] + 12);
          } else {
            fprintf(l_opts_f, "%s\n", lang->compiler_env[j]);
          }
        }
        fclose(l_opts_f);
        fclose(l_flags_f);
        fclose(l_libs_f);
        if (l_opts_z > 0) {
          sstate->serv_extra[serv_lang_id].compiler_env = l_opts_s; l_opts_s = NULL;
        }
        if (l_flags_z > 0) {
          sstate->serv_extra[serv_lang_id].ejudge_flags = l_flags_s; l_flags_s = NULL;
        }
        if (l_libs_z > 0) {
          sstate->serv_extra[serv_lang_id].ejudge_libs = l_libs_s; l_libs_s = NULL;
        }
        free(l_opts_s);
        free(l_libs_s);
        free(l_flags_s);
      }
    }
  } else {
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

static const unsigned char *
simple_trim(unsigned char *s)
{
  if (!s) return "";

  while (*s && isspace(*s)) ++s;

  int len = strlen(s);
  while (len > 0 && isspace(s[len-1])) --len;
  s[len] = 0;

  return s;
}

int
super_html_simplify_lang(
        const struct sid_state *sstate,
        struct section_language_data *lang,
        struct section_language_data *serv_lang)
{
  __attribute__((unused)) int _;
  int need_section = 0;

  if (!lang) {
    return 0;
  }
  if (!serv_lang) {
    return 1;
  }

  lang->id = serv_lang->id;
  _ = snprintf(lang->short_name, sizeof(lang->short_name), "%s", serv_lang->short_name);
  _ = snprintf(lang->src_sfx, sizeof(lang->src_sfx), "%s", serv_lang->src_sfx);
  _ = snprintf(lang->exe_sfx, sizeof(lang->exe_sfx), "%s", serv_lang->exe_sfx);
  if (lang->compile_id == lang->id) {
    lang->compile_id = 0;
  }

  // evaluated later
  lang->disable_auto_update = -1;
  lang->disabled = -1;
  lang->default_disabled = -1;
  lang->enabled = -1;

#define PROCESS_BOOL(field) do { if (lang->field < 0) { lang->field = -1; } else if (lang->field > 0 && serv_lang->field <= 0) { lang->field = 1; need_section = 1; } else if (lang->field == 0 && serv_lang->field > 0) { need_section = 1; } } while (0)
  PROCESS_BOOL(binary);
  PROCESS_BOOL(insecure);
  PROCESS_BOOL(disable_security);
  PROCESS_BOOL(enable_suid_run);
  PROCESS_BOOL(is_dos);
  PROCESS_BOOL(disable_auto_testing);
  PROCESS_BOOL(disable_testing);
  PROCESS_BOOL(enable_custom);
  PROCESS_BOOL(enable_ejudge_env);
  PROCESS_BOOL(preserve_line_numbers);
#undef PROCESS_BOOL

#define PROCESS_SIZE(field) do { if (lang->field <= 0) { lang->field = -1; } else if (lang->field > 0 && lang->field == serv_lang->field) { lang->field = -1; } else if (lang->field > 0) { need_section = 1; } } while (0)
  PROCESS_SIZE(max_vm_size);
  PROCESS_SIZE(max_stack_size);
  PROCESS_SIZE(max_file_size);
  PROCESS_SIZE(max_rss_size);
  PROCESS_SIZE(run_max_stack_size);
  PROCESS_SIZE(run_max_vm_size);
  PROCESS_SIZE(run_max_rss_size);
#undef PROCESS_SIZE

  if (lang->compile_real_time_limit < 0) {
    lang->compile_real_time_limit = 0;
  } else if (lang->compile_real_time_limit > 0 && lang->compile_real_time_limit == serv_lang->compile_real_time_limit) {
    lang->compile_real_time_limit = 0;
  } else {
    need_section = 1;
  }
  if (lang->priority_adjustment != 0 && lang->priority_adjustment != serv_lang->priority_adjustment) {
    need_section = 1;
  }
  lang->compile_dir_index = 0;

  if (lang->compile_server_id && !*lang->compile_server_id) {
    xfree(lang->compile_server_id); lang->compile_server_id = NULL;
  }
  if (lang->compile_server_id && sstate->cscs && sstate->cscs->u > 0 && sstate->cscs->v[0].id && !strcmp(lang->compile_server_id, sstate->cscs->v[0].id)) {
    xfree(lang->compile_server_id); lang->compile_server_id = NULL;
  }
  if (lang->compile_server_id) {
    need_section = 1;
  }

  if (lang->super_run_dir && *lang->super_run_dir) {
    xfree(lang->super_run_dir); lang->super_run_dir = NULL;
  }
  if (lang->super_run_dir) {
    need_section = 1;
  }

#define PROCESS_STRING(field) do { \
  if (lang->field && !*lang->field) { \
    xfree(lang->field); lang->field = NULL; \
  } \
  if (lang->field && serv_lang->field && !strcmp(lang->field, serv_lang->field)) { \
    xfree(lang->field); lang->field = NULL; \
  } \
  if (lang->field) { \
    need_section = 1; \
  } \
  } while (0)
  PROCESS_STRING(long_name);
  PROCESS_STRING(version);
  PROCESS_STRING(key);
  PROCESS_STRING(arch);
  PROCESS_STRING(content_type);
  PROCESS_STRING(style_checker_cmd);
  PROCESS_STRING(extid);
  PROCESS_STRING(multi_header_suffix);
  PROCESS_STRING(container_options);
  PROCESS_STRING(compiler_container_options);
  PROCESS_STRING(clean_up_cmd);
  PROCESS_STRING(run_env_file);
  PROCESS_STRING(clean_up_env_file);
#undef PROCESS_STRING

  if (lang->style_checker_env && lang->style_checker_env[0]) {
    need_section = 1;
  }

  sarray_free(lang->compiler_env); lang->compiler_env = NULL;

  struct language_extra *extra = &sstate->lang_extra[lang->id];
  if (extra->ejudge_flags && *extra->ejudge_flags) {
    char *tmp = NULL;
    _ = asprintf(&tmp, "EJUDGE_FLAGS=%s", simple_trim(extra->ejudge_flags));
    lang->compiler_env = sarray_append(lang->compiler_env, tmp);
    free(tmp);
    need_section = 1;
  }
  if (extra->ejudge_libs && *extra->ejudge_libs) {
    char *tmp = NULL;
    _ = asprintf(&tmp, "EJUDGE_LIBS=%s", simple_trim(extra->ejudge_libs));
    lang->compiler_env = sarray_append(lang->compiler_env, tmp);
    free(tmp);
    need_section = 1;
  }
  if (extra->compiler_env && *extra->compiler_env) {
    char **envs = NULL;
    split_to_lines(extra->compiler_env, &envs, 0);
    lang->compiler_env = sarray_merge_pf(lang->compiler_env, envs);
    need_section = 1;
  }

  return need_section;
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
  int *langs_to_enable = NULL;
  int *langs_to_disable = NULL;
  int langs_to_enable_u = 0;
  int langs_to_disable_u = 0;
  int default_enable = 0;

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

  if (global->enable_language_import) {
    // count the number of languages to disable or enable
    int disable_count = 0;
    int enable_count = 0;
    for (i = 0; i < sstate->lang_a; ++i) {
      if (!sstate->serv_langs[i]) {
        continue;
      }
      if (!super_html_simplify_lang(sstate, sstate->langs[i], sstate->serv_langs[i])) {
        sstate->langs[i] = NULL;
      }
      if (sstate->serv_langs[i] && sstate->lang_extra[i].enabled != 1 && sstate->lang_extra[i].enabled != 2 && !sstate->langs[i]) {
        ++disable_count;
      }
      if (sstate->serv_langs[i] && sstate->lang_extra[i].enabled == 1 && !sstate->langs[i]) {
        ++enable_count;
      }
    }
    if (enable_count < disable_count) {
      // default mode is disabled, enable languages explicitly
      // language_import = "enable L1,L2,L3"
      // language_import = "disable all"
      XALLOCAZ(langs_to_enable, enable_count);
      for (i = 0; i < sstate->lang_a; ++i) {
        if (sstate->serv_langs[i] && sstate->lang_extra[i].enabled == 1) {
          if (sstate->langs[i]) {
            sstate->langs[i]->enabled = 1;
          } else {
            langs_to_enable[langs_to_enable_u++] = i;
          }
        }
      }
    } else {
      // default mode is enabled, disable languages explicitly
      // language_import = "disable L1, L2, L3"
      // language_import = "enable all"
      XALLOCAZ(langs_to_disable, disable_count);
      default_enable = 1;
      for (i = 0; i < sstate->lang_a; ++i) {
        if (sstate->serv_langs[i] && sstate->lang_extra[i].enabled != 1 && sstate->lang_extra[i].enabled != 2) {
          if (sstate->langs[i]) {
            sstate->langs[i]->disabled = 1;
          } else {
            langs_to_disable[langs_to_disable_u++] = i;
          }
        }
      }
    }

    sarray_free(global->language_import); global->language_import = NULL;
    if (langs_to_enable_u > 0) {
      char *txt_s = NULL;
      size_t txt_z = 0;
      FILE *txt_f = open_memstream(&txt_s, &txt_z);
      fprintf(txt_f, "enable ");
      for (i = 0; i < langs_to_enable_u; ++i) {
        if (i > 0) {
          fprintf(txt_f, ",");
        }
        fprintf(txt_f, "%s", sstate->serv_langs[langs_to_enable[i]]->short_name);
      }
      fclose(txt_f);
      global->language_import = sarray_append(global->language_import, txt_s);
      free(txt_s);
    }
    if (langs_to_disable_u > 0) {
      char *txt_s = NULL;
      size_t txt_z = 0;
      FILE *txt_f = open_memstream(&txt_s, &txt_z);
      fprintf(txt_f, "disable ");
      for (i = 0; i < langs_to_disable_u; ++i) {
        if (i > 0) {
          fprintf(txt_f, ",");
        }
        fprintf(txt_f, "%s", sstate->serv_langs[langs_to_disable[i]]->short_name);
      }
      fclose(txt_f);
      global->language_import = sarray_append(global->language_import, txt_s);
      free(txt_s);
    }
    if (default_enable) {
      global->language_import = sarray_append(global->language_import, "enable all");
    } else {
      global->language_import = sarray_append(global->language_import, "disable all");
    }
  }

  prepare_unparse_global(f, cnts, global, sstate->compile_home_dir, need_variant_map, 0);

  if (global->enable_language_import > 0) {
    for (i = 0; i < sstate->lang_a; ++i) {
      struct section_language_data *lang = sstate->langs[i];
      if (!lang) continue;

      if (lang->compile_id > 0 && lang->id == lang->compile_id) lang->compile_id = 0;
      if (sstate->serv_langs[i]->id == i && !strcmp(sstate->serv_langs[i]->short_name, lang->short_name)) lang->id = 0;

      prepare_unparse_lang(f, sstate->langs[i], 0, NULL, NULL, NULL);
    }
  } else {
    if (sstate->lang_a > 0) {
      for (i = 1, active_langs = 0; i < sstate->lang_a; i++) {
        if (!sstate->langs[i]) continue;
        prepare_unparse_lang(f, sstate->langs[i], 0, 0, sstate->lang_opts[i], sstate->lang_libs[i]);
        active_langs++;
      }
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

  if (global->enable_language_import <= 0) {
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

void
super_html_emit_json_result(
        FILE *fout,
        struct http_request_info *phr,
        int ok,
        int err_num,
        unsigned err_id,
        const unsigned char *err_msg,
        cJSON *jr)
{
  phr->json_reply = 1;
  if (!ok) {
    if (err_num < 0) err_num = -err_num;
    if (!err_id) {
      random_init();
      err_id = random_u32();
    }
    if (!err_msg || !*err_msg) {
      err_msg = NULL;
      if (err_num > 0 && err_num < SSERV_ERR_LAST) {
        err_msg = super_proto_strerror(err_num);
      }
    }
    cJSON_AddFalseToObject(jr, "ok");
    cJSON *jerr = cJSON_CreateObject();
    if (err_num > 0) {
      cJSON_AddNumberToObject(jerr, "num", err_num);
      //cJSON_AddStringToObject(jerr, "symbol", ns_error_symbol(err_num));
    }
    if (err_id) {
      char xbuf[64];
      sprintf(xbuf, "%08x", err_id);
      cJSON_AddStringToObject(jerr, "log_id", xbuf);
    }
    if (err_msg) {
      cJSON_AddStringToObject(jerr, "message", err_msg);
    }
    cJSON_AddItemToObject(jr, "error", jerr);
    // FIXME: log event
  } else {
    cJSON_AddTrueToObject(jr, "ok");
  }
  cJSON_AddNumberToObject(jr, "server_time", (double) phr->current_time);
  if (phr->request_id > 0) {
    cJSON_AddNumberToObject(jr, "request_id", (double) phr->request_id);
  }
  if (phr->action > 0 && phr->action < SSERV_CMD_LAST && super_proto_cmd_names[phr->action]) {
    cJSON_AddStringToObject(jr, "action", super_proto_cmd_names[phr->action]);
  }
  char *jrstr = cJSON_PrintUnformatted(jr);
  fprintf(fout, "%s\n", jrstr);
  free(jrstr);
}
