/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2010 Alexander Chernov <cher@ejudge.ru> */

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
#include "ej_types.h"
#include "ej_limits.h"
#include "version.h"

#include "ejudge_cfg.h"
#include "contests.h"
#include "prepare.h"
#include "common_plugin.h"

#define EJUDGE_SKIP_MYSQL 1
#include "plugins/mysql-common/common_mysql.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static const unsigned char *program_name = "";
static const unsigned char *ejudge_xml_path = 0;
static unsigned char compile_cfg_path[PATH_MAX];

static struct ejudge_cfg *config = 0;
static struct generic_section_config *cs_config;
static int cs_lang_total;
static struct section_language_data **cs_langs;

static const struct common_loaded_plugin *mysql_plugin;
static struct common_mysql_state *mysql_state;
static struct common_mysql_iface *mysql_iface;

static void
die(const char *format, ...)
  __attribute__((format(printf, 1, 2), noreturn));
static void
die(const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: fatal: %s\n", program_name, buf);
  exit(1);
}

static void
error(const char *format, ...)
  __attribute__((format(printf, 1, 2)));
static void
error(const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: error: %s\n", program_name, buf);
}

static void write_help(void) __attribute__((noreturn));
static void
write_help(void)
{
  printf("%s: Ejudge database normalizer\n"
         "Usage: %s [OPTIONS]\n"
         "  OPTIONS:\n"
         "    --help    write this message and exit\n"
         "    --version report version and exit\n"
         "    -f CFG    specify the ejudge configuration file\n",
         program_name, program_name);
  exit(0);
}
static void write_version(void) __attribute__((noreturn));
static void
write_version(void)
{
  printf("%s %s, compiled %s\n", program_name, compile_version, compile_date);
  exit(0);
}

static void
handle_cs_config(void)
{
  struct generic_section_config *p;
  struct section_language_data *lang;
  int cur_lang = 1;
  int max_lang = 0;

  for (p = cs_config; p; p = p->next) {
    if (strcmp(p->name, "language") != 0) continue;
    lang = (struct section_language_data*) p;
    if (lang->id < 0) {
      die("%s: language identifier is invalid", compile_cfg_path);
    }
    if (!lang->id) lang->id = cur_lang;
    cur_lang = lang->id + 1;
    if (lang->id > max_lang) max_lang = lang->id;
  }

  if (max_lang <= 0) {
    die("no languages defined");
  }

  cs_lang_total = max_lang + 1;
  XCALLOC(cs_langs, cs_lang_total);

  for (p = cs_config; p; p = p->next) {
    if (strcmp(p->name, "language") != 0) continue;
    lang = (struct section_language_data*) p;
    if (cs_langs[lang->id]) {
      die("%s: duplicated language id %d", compile_cfg_path, lang->id);
    }
    cs_langs[lang->id] = lang;
  }
}

static void
load_mysql_plugin(void)
{
  if (!(mysql_plugin = plugin_load_external(0, "common", "mysql", config))) {
    die("cannot load common_mysql plugin");
  }

  mysql_state = (struct common_mysql_state*) mysql_plugin->data;
  if (!mysql_state) {
    die("mysql plugin loading failed: mysql_state == NULL");
  }
  mysql_iface = (struct common_mysql_iface*) mysql_plugin->iface;
  if (!mysql_iface) {
    die("mysql plugin loading failed mysql_iface == NULL");
  }
}

static int
process_contest(int contest_id)
{
  const struct contest_desc *cnts = 0;
  unsigned char config_path[PATH_MAX];
  const unsigned char *conf_dir = 0;
  struct stat stbuf;
  serve_state_t state = 0;
  struct section_global_data *global = 0;
  int lang_id;
  struct section_language_data *lang, *cs_lang_by_short, *cs_lang_by_id, *cs_lang;
  int compile_id;
  int i;
  int has_to_convert = 0, has_errors = 0;
  int *lang_map = 0;

  fprintf(stderr, "Processing contest %d\n", contest_id);

  if (contests_get(contest_id, &cnts) < 0 || !cnts) {
    error("cannot read contest XML for contest %d", contest_id);
    goto failure;
  }

  if (cnts->conf_dir && os_IsAbsolutePath(cnts->conf_dir)) {
    snprintf(config_path, sizeof(config_path), "%s/serve.cfg", cnts->conf_dir);
  } else {
    if (!cnts->root_dir) {
      error("contest %d root_dir is not set", contest_id);
      goto failure;
    } else if (!os_IsAbsolutePath(cnts->root_dir)) {
      error("contest %d root_dir %s is not absolute", contest_id, cnts->root_dir);
      goto failure;
    }
    if (!(conf_dir = cnts->conf_dir)) conf_dir = "conf";
    snprintf(config_path, sizeof(config_path),
             "%s/%s/serve.cfg", cnts->root_dir, conf_dir);
  }

  if (stat(config_path, &stbuf) < 0) {
    error("contest %d config file %s does not exist", contest_id, config_path);
    goto failure;
  }
  if (!S_ISREG(stbuf.st_mode)) {
    error("contest %d config file %s is not a regular file",
          contest_id, config_path);
    goto failure;
  }
  if (access(config_path, R_OK) < 0) {
    error("contest %d config file %s is not readable",
          contest_id, config_path);
    goto failure;
  }

  state = serve_state_init();
  state->config_path = xstrdup(config_path);
  state->current_time = time(0);
  state->load_time = state->current_time;
  if (prepare(state, state->config_path, 0, PREPARE_SERVE, "", 1) < 0)
    goto failure;
  global = state->global;
  if (!global) {
    error("contest %d has no global section", contest_id);
    goto failure;
  }
  if (strcmp(global->rundb_plugin, "mysql") != 0) {
    fprintf(stderr, "contest %d does not use mysql\n", contest_id);
    goto failure;
  }

  if (state->max_lang >= 0) {
    XCALLOC(lang_map, state->max_lang + 1);
  }

  for (lang_id = 1; lang_id <= state->max_lang; ++lang_id) {
    if (!(lang = state->langs[lang_id])) continue;
    compile_id = lang->compile_id;
    if (compile_id <= 0) compile_id = lang->id;

    if (lang->id > 1000) {
      fprintf(stderr, "  language %s id > 1000 (%d)\n",
              lang->short_name, lang->id);
      has_errors = 1;
      continue;
    }

    /* search the language in the compilation server by short_name and by id */
    cs_lang_by_short = 0;
    cs_lang_by_id = 0;
    for (i = 1; i < cs_lang_total; ++i) {
      if ((cs_lang = cs_langs[i]) && cs_lang->id == compile_id) {
        cs_lang_by_id = cs_lang;
        break;
      }
    }
    for (i = 1; i < cs_lang_total; ++i) {
      if ((cs_lang = cs_langs[i]) && !strcmp(cs_lang->short_name, lang->short_name)) {
        cs_lang_by_short = cs_lang;
        break;
      }
    }

    /*
      condition to convert:
        1) contest language id does not match to compilation server language id;
        2) contest language short name, compilation server language short name match.
     */
    if (lang->id != compile_id && cs_lang_by_short != NULL
        && cs_lang_by_short == cs_lang_by_id) {
      has_to_convert = 1;
      fprintf(stderr, "  language %s id %d to be changed to %d\n",
              lang->short_name, lang->id, compile_id);
      lang_map[lang_id] = compile_id;
    } else if (lang->id == compile_id && cs_lang_by_short != NULL
               && cs_lang_by_short == cs_lang_by_id) {
      /*
        condition to do nothing:
          1) contest language id match compilation server language id;
          2) contest language short name, compilation server language short name match.
      */
    } else {
      has_errors = 1;
      fprintf(stderr, "  unexpected language %s, id %d, compile id %d\n",
              lang->short_name, lang->id, lang->compile_id);
      if (cs_lang_by_id) {
        fprintf(stderr, "    CS lang by id: id %d, short %s\n",
                cs_lang_by_id->id, cs_lang_by_id->short_name);
      } else {
        fprintf(stderr, "    CS lang by id: NULL\n");
      }
      if (cs_lang_by_short) {
        fprintf(stderr, "    CS lang by short name: id %d, short %s\n",
                cs_lang_by_short->id, cs_lang_by_short->short_name);
      } else {
        fprintf(stderr, "    CS lang by short name: NULL\n");
      }
    }
  }

  if (has_errors) {
    fprintf(stderr, "contest %d cannot be converted\n", contest_id);
    return 0;
  }
  if (!has_to_convert) {
    fprintf(stderr, "contest %d is ok\n", contest_id);
    return 0;
  }

  return 0;

 failure:
  return 1;
}

static int
process_all_contests(void)
{
  const int *contests_list = 0;
  int contest_count, i, res = 0;

  contest_count = contests_get_list(&contests_list);
  if (contest_count < 0) {
    die("cannot obtain the list of contests");
  }
  if (!contest_count) {
    printf("no contests\n");
    return 0;
  }

  for (i = 0; i < contest_count; ++i) {
    res |= process_contest(contests_list[i]);
  }

  return res;
}

int
main(int argc, char *argv[])
{
  program_name = os_GetBasename(argv[0]);

  if (argc <= 1) die("not enough parameters");

  if (!strcmp(argv[1], "--help")) {
    write_help();
  } else if (!strcmp(argv[1], "--version")) {
    write_version();
  }

#if defined EJUDGE_XML_PATH
  if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */
  if (!ejudge_xml_path) die("ejudge.xml path is not specified");
  if (!(config = ejudge_cfg_parse(ejudge_xml_path))) return 1;
  if (!config->contests_dir) die("<contests_dir> tag is not set!");
  if (contests_set_directory(config->contests_dir) < 0)
    die("contests directory is invalid");

  load_mysql_plugin();

  /* consult the main compilation configuration */
  compile_cfg_path[0] = 0;
  if (config->compile_home_dir) {
    snprintf(compile_cfg_path, sizeof(compile_cfg_path), "%s/conf/compile.cfg",
             config->compile_home_dir);
  }
  if (!compile_cfg_path[0] && config->contests_home_dir) {
    snprintf(compile_cfg_path, sizeof(compile_cfg_path), "%s/compile/conf/compile.cfg",
             config->contests_home_dir);
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!compile_cfg_path[0]) {
    snprintf(compile_cfg_path, sizeof(compile_cfg_path), "%s/compile/conf/compile.cfg",
             EJUDGE_CONTESTS_HOME_DIR);
  }
#endif

  cs_config = prepare_parse_config_file(compile_cfg_path, 0);
  if (!cs_config) {
    die("failed to parse compilation configuration file %s", compile_cfg_path);
  }
  handle_cs_config();

  process_all_contests();

  return 0;
}
