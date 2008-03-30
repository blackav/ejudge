/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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

#include "prepare.h"
#include "shellcfg_parse.h"

#include <string.h>
#include <dirent.h>

int
lang_config_configure(
	FILE *log_f,
	const unsigned char *config_dir,
        int max_lang,
        struct section_language_data **langs)
{
  DIR *d = 0;
  int retcode = -1;
  struct dirent *dd;
  int len, i, j;
  unsigned char base[1024], short_name[1024];
  const unsigned char *val;
  path_t script_path;
  struct section_language_data *lang;
  shellconfig_t cfg = 0;
  FILE *cfg_f = 0;

  if (!config_dir || !*config_dir) return 0;

  for (i = 1; i <= max_lang; i++)
    if ((lang = langs[i]))
      lang->disabled_by_config = -1;

  if (!(d = opendir(config_dir))) {
    fprintf(log_f, "cannot open directory `%s'\n", config_dir);
    goto cleanup;
  }
  while ((dd = readdir(d))) {
    len = strlen(dd->d_name);
    if (len <= 4) continue;
    if (strcmp(dd->d_name + len - 4, ".cfg") != 0) continue;
    snprintf(base, sizeof(base), "%.*s", len - 4, dd->d_name);
    fprintf(log_f, "info: config_file=%s, ", dd->d_name);
    snprintf(script_path, sizeof(script_path), "%s/%s", config_dir,
             dd->d_name);
    if (!(cfg_f = fopen(script_path, "r"))) {
      fprintf(log_f, "open error\n");
      continue;
    }
    if (!(cfg = shellconfig_parse(log_f, cfg_f, script_path))) {
      fprintf(log_f, "parse error\n");
      fclose(cfg_f); cfg_f = 0;
      continue;
    }
    fclose(cfg_f); cfg_f = 0;
    if ((j = shellconfig_find_by_prefix(cfg, "short_name", 10)) < 0) {
      snprintf(short_name, sizeof(short_name), "%s", base);
    } else {
      snprintf(short_name, sizeof(short_name), "%s",
               shellconfig_get_value_by_num(cfg, j));
    }
    fprintf(log_f, "short_name=%s, ", short_name);
    for (i = 1; i <= max_lang; i++)
      if ((lang = langs[i]) && !strcmp(lang->short_name, short_name))
        break;
    if (i <= max_lang) {
      lang = langs[i];
      fprintf(log_f, "lang_id=%d, ", lang->id);
      if ((j = shellconfig_find_by_prefix(cfg, "version", 7)) < 0) {
        fprintf(log_f, "no version variable, disabled\n");
        lang->disabled_by_config = 1;
      } else {
        val = shellconfig_get_value_by_num(cfg, j);
        if (val && *val) {
          fprintf(log_f, "OK\n");
          lang->disabled_by_config = 0;
        } else {
          fprintf(log_f, "disabled\n");
          lang->disabled_by_config = 1;
        }
      }
    } else {
      fprintf(log_f, "no land_id\n");
    }
    cfg = shellconfig_free(cfg);
  }
  closedir(d); d = 0;

  for (i = 1; i <= max_lang; i++)
    if ((lang = langs[i]) && lang->disabled_by_config < 0) {
      fprintf(log_f, "no configuration script for language `%s', disabled\n",
              lang->short_name);
      lang->disabled_by_config = 1;
    }


  retcode = 0;

 cleanup:
  if (d) closedir(d);
  return retcode;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
