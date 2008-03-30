/* -*- mode:c -*- */
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
#include "version.h"

#include "ncurses_utils.h"
#include "lang_config_vis.h"
#include "pathutl.h"

#include <reuse/xalloc.h>

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <libintl.h>
#include <locale.h>
#include <langinfo.h>
#include <sys/types.h>
#include <sys/stat.h>

static int utf8_mode;
static path_t script_dir;
static path_t config_dir;
static const unsigned char *progname;

static void die(const char *format, ...)
  __attribute__((noreturn, format(printf, 1, 2)));
static void die(const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: %s\n", progname, buf);
  exit(1);
}

static void log_printf(FILE *out_f, WINDOW *out_win, const char *format, ...)
  __attribute__((format(printf, 3, 4)));
static void log_printf(FILE *out_f, WINDOW *out_win, const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  if (out_f) {
    fprintf(out_f, "%s", buf);
  }
  if (out_win) {
    wprintw(out_win, "%s", buf);
    update_panels();
    doupdate();
  }
}

static int
is_file_changed(
        const unsigned char *path,
        const unsigned char *text,
        size_t size)
{
  FILE *f = 0;
  FILE *mem_f = 0;
  char *mem_t = 0;
  size_t mem_z = 0;
  unsigned char buf[4096];
  int retval = 0;

  if (!(f = fopen(path, "r"))) return 1;
  mem_f = open_memstream(&mem_t, &mem_z);
  while (fgets(buf, sizeof(buf), f))
    fputs(buf, mem_f);
  fclose(mem_f); mem_f = 0;
  fclose(f); f = 0;

  if (mem_z != size || memcmp(mem_t, text, size)) retval = 1;
  xfree(mem_t);
  return retval;
}

static int
do_save(const unsigned char *path, const unsigned char *text, size_t size)
{
  FILE *f = 0;
  size_t i;

  /* FIXME: write to temporary file and then rename */
  if (!(f = fopen(path, "w"))) return -1;
  for (i = 0; i < size; i++)
    putc(text[i], f);
  fflush(f);
  if (ferror(f)) {
    fclose(f);
    return -1;
  }
  fclose(f);
  return 0;
}

static void
save_config_file(
	const struct lang_config_info *cfg,
        FILE *out_f,
        WINDOW *out_win)
{
  path_t outpath;

  if (!cfg) return;
  if (!cfg->cfg || !cfg->cfg_txt) return;

  snprintf(outpath, sizeof(outpath), "%s/%s.cfg", config_dir, cfg->lang);
  log_printf(out_f, out_win, "%s: ", outpath);

  if (is_file_changed(outpath, cfg->cfg_txt, cfg->cfg_len)) {
    if (do_save(outpath, cfg->cfg_txt, cfg->cfg_len) < 0) {
      log_printf(out_f, out_win, "failed");
    } else {
      log_printf(out_f, out_win, "saved");
    }
  } else {
    log_printf(out_f, out_win, "not changed");
  }

  log_printf(out_f, out_win, "\n");
}

static void
save_config_files(FILE *log_f, WINDOW *out_win)
{
  struct lang_config_info *pcfg;

  for (pcfg = lang_config_get_first(); pcfg; pcfg = pcfg->next) {
    if (!pcfg->cfg || !pcfg->cfg_txt) continue;
    save_config_file(pcfg, log_f, out_win);
  }
}

static void
visual_save_config(const unsigned char *header)
{
  WINDOW *in_win = 0, *out_win = 0;
  PANEL *in_pan = 0, *out_pan = 0;
  int c;

  out_win = newwin(LINES - 2, COLS, 1, 0);
  in_win = newwin(LINES - 4, COLS - 2, 2, 1);
  wattrset(out_win, COLOR_PAIR(1));
  wbkgdset(out_win, COLOR_PAIR(1));
  wattrset(in_win, COLOR_PAIR(1));
  wbkgdset(in_win, COLOR_PAIR(1));
  wclear(in_win);
  wclear(out_win);
  box(out_win, 0, 0);
  out_pan = new_panel(out_win);
  in_pan = new_panel(in_win);

  mvwprintw(stdscr, 0, 0, "%s > Compiler auto-configuration", header);
  wclrtoeol(stdscr);
  ncurses_print_help("");
  show_panel(out_pan);
  show_panel(in_pan);
  update_panels();
  doupdate();

  save_config_files(0, in_win);
  ncurses_print_help("Press any key");
  doupdate();
  c = getch();

  if (in_pan) del_panel(in_pan);
  if (out_pan) del_panel(out_pan);
  if (out_win) delwin(out_win);
  if (in_win) delwin(in_win);
}

static int
visual_setup(unsigned char **keys, unsigned char **vals)
{
  unsigned char header[1024];
  int cur_item = 0, j;

  if (ncurses_init() < 0) return 1;

  snprintf(header, sizeof(header), "Ejudge %s compiler configuration",
           compile_version);
  lang_configure_screen(script_dir, config_dir, keys, vals, header);
  while (lang_config_menu(script_dir, header, utf8_mode, &cur_item));

  j = ncurses_yesno(0, "\\begin{center}\nSave the configuration updates?\n\\end{center}\n");
  if (j == 1) visual_save_config(header);

  ncurses_shutdown();
  return 0;
}

static int
is_prefix(
        const unsigned char *str,
        const unsigned char *pfx,
        const unsigned char **val_ptr)
{
  int len = strlen(pfx);
  if (!strncmp(str, pfx, len)) {
    if (val_ptr) *val_ptr = str + len;
    return 1;
  } else {
    if (val_ptr) *val_ptr = 0;
    return 0;
  }
}

int
main(int argc, char **argv)
{
  int i, j, k;
  unsigned char **keys;
  unsigned char **vals;
  const unsigned char *val;
  int batch_mode = 0;
  char *p;
  unsigned char key[1024];
  unsigned char path[1024];
  struct stat sb;

  XCALLOC(keys, argc + 1);
  XCALLOC(vals, argc + 1);

  for (i = 1; i < argc; i++) {
    key[0] = 0;
    if (is_prefix(argv[i], "--enable-lang-config-dir=", &val)) {
      snprintf(config_dir, sizeof(config_dir), "%s", val);
    } else if (is_prefix(argv[i], "--enable-lang-script-dir=", &val)) {
      snprintf(script_dir, sizeof(script_dir), "%s", val);
    } else if (!strcmp(argv[i], "--batch")) {
      batch_mode = 1;
    } else if (!strncmp(argv[i], "--with-", 7)) {
      if (!(p = strchr(argv[i], '='))) {
        snprintf(key, sizeof(key), "%s", argv[i] + 7);
        path[0] = 0;
      } else {
        snprintf(key, sizeof(key), "%.*s", p - argv[i] - 7, argv[i] + 7);
        snprintf(path, sizeof(path), "%s", p + 1);
      }
    } else if (!strncmp(argv[i], "--without-", 10)) {
      if (strchr(argv[i], '='))
        die("option value is not permitted for %s", argv[i]);
      snprintf(key, sizeof(key), "%s", argv[i] + 10);
      snprintf(path, sizeof(path), "%s", "false");
    } else {
      die("invalid option %s\n", argv[i]);
    }

    if (key[0]) {
      if (!strcmp(key, "gpp")) snprintf(key, sizeof(key), "%s", "g++");
      //fprintf(stderr, ">>%s,>%s<\n", key, path);
      for (j = 0; keys[j]; j++)
        if (!strcmp(keys[j], key))
          break;
      if (!keys[j]) {
        if (path[0]) {
          keys[j] = xstrdup(key);
          vals[j] = xstrdup(path);
          j++;
          keys[j] = 0;
          vals[j] = 0;
        }
      } else if (!path[0]) {
        xfree(keys[j]); xfree(vals[j]);
        for (k = j + 1; keys[k]; k++) {
          keys[k - 1] = keys[k];
          vals[k - 1] = vals[k];
        }
        keys[k] = 0;
        vals[k] = 0;
      } else {
        xfree(vals[j]);
        vals[j] = xstrdup(path);
      }
    }
  }

  setlocale(LC_ALL, "");
  if (!strcmp(nl_langinfo(CODESET), "UTF-8")) utf8_mode = 1;

#if defined EJUDGE_SCRIPT_DIR
  if (!script_dir[0]) {
    snprintf(script_dir, sizeof(script_dir), "%s/lang", EJUDGE_SCRIPT_DIR);
  }
#endif
#if defined EJUDGE_LANG_CONFIG_DIR
  if (!config_dir[0]) {
    snprintf(config_dir, sizeof(config_dir), "%s", EJUDGE_LANG_CONFIG_DIR);
  }
#endif

  if (!script_dir[0]) die("script directory is not specified");
  if (stat(script_dir, &sb) < 0) die("script directory does not exist");
  if (!S_ISDIR(sb.st_mode)) die("script directory is not a directory");
  if (!config_dir[0]) die("config directory is not specified");
  if (stat(config_dir, &sb) < 0) die("config directory does not exist");
  if (!S_ISDIR(sb.st_mode)) die("config directory is not a directory");

  if (!batch_mode) return visual_setup(keys, vals);

  fprintf(stderr, "ejudge-configure-compilers %s, compiled %s\n",
          compile_version, compile_date);
  lang_configure_batch(script_dir, config_dir, keys, vals, stderr);
  save_config_files(stderr, 0);

  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "WINDOW" "ITEM" "PANEL" "MENU")
 * End:
 */
