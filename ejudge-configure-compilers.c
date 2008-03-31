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
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>

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

static void
get_compiler_info(const unsigned char *lang, unsigned char *buf, size_t size)
{
  path_t cmd;
  FILE *pf = 0;
  FILE *log_f = 0;
  char *log_t = 0;
  size_t log_z = 0;
  unsigned char tmpbuf[1024];

  buf[0] = 0;
  snprintf(cmd, sizeof(cmd), "\"%s/%s-version\" -l </dev/null 2>/dev/null", script_dir, lang);

  if (!(log_f = open_memstream(&log_t, &log_z))) goto cleanup;
  if (!(pf = popen(cmd, "r"))) {
    goto cleanup;
  }
  while (fgets(tmpbuf, sizeof(tmpbuf), pf))
    fputs(tmpbuf, log_f);
  pclose(pf); pf = 0;
  fclose(log_f); log_f = 0;
  snprintf(buf, size, "%.*s", log_z, log_t);
  xfree(log_t); log_t = 0;
  log_z = strlen(buf);
  while (log_z > 0 && isspace(buf[log_z - 1])) log_z--;
  buf[log_z] = 0;

 cleanup:
  if (pf) pclose(pf);
  if (log_f) fclose(log_f);
  if (log_t) xfree(log_t);
}

static int
lang_sort_func(const void *v1, const void *v2)
{
  const unsigned char *s1 = *(const unsigned char**) v1;
  const unsigned char *s2 = *(const unsigned char**) v2;
  return strcmp(s1, s2);
}

static int
list_all_compilers(void)
{
  DIR *d = 0;
  struct dirent *dd;
  int len, x, n, i;
  path_t langbase;
  path_t langinfo;
  int is_term = isatty(1);
  int column_num = 80, max_lang_len = -1;
  const unsigned char *env;
  unsigned char *outbuf = 0;
  size_t outbuf_size = 0;
  size_t outbuf_len = 0;
  strarray_t langs;

  memset(&langs, 0, sizeof(langs));
  if (is_term && (env = getenv("COLUMNS")) && sscanf(env, "%d%n", &x, &n) == 1
      && !env[n] && x > 0 && x < 10000 && (column_num = x));
  if (is_term) {
    if (column_num < 10) column_num = 10;
    outbuf_size = column_num + 100;
    outbuf = (unsigned char*) alloca(outbuf_size);
  }

  if (!(d = opendir(script_dir))) return 1;
  while ((dd = readdir(d))) {
    len = strlen(dd->d_name);
    if (len <= 8) continue;
    if (!strcmp(dd->d_name + len - 8, "-version")) {
      if (len - 8 > max_lang_len) max_lang_len = len - 8;
      xexpand(&langs);
      langs.v[langs.u++] = xmemdup(dd->d_name, len - 8);
    }
  }
  closedir(d); d = 0;
  if (langs.u <= 0) return 0;
  if (max_lang_len <= 0) return 0;

  qsort(langs.v, langs.u, sizeof(langs.v[0]), lang_sort_func);

  for (i = 0; i < langs.u; i++) {
    snprintf(langbase, sizeof(langbase), "%s", langs.v[i]);
    langinfo[0] = 0;
    get_compiler_info(langbase, langinfo, sizeof(langinfo));
    if (!langinfo[0]) continue;
    if (is_term) {
      snprintf(outbuf, outbuf_size, "%-*.*s %s", max_lang_len, max_lang_len,
               langbase, langinfo);
      outbuf_len = strlen(outbuf);
      if (outbuf_len > column_num - 1) {
        outbuf[column_num - 4] = '.';
        outbuf[column_num - 3] = '.';
        outbuf[column_num - 2] = '.';
        outbuf[column_num - 1] = 0;
      }
      printf("%s\n", outbuf);
    } else {
      printf("%-*.*s %s\n", max_lang_len, max_lang_len, langbase, langinfo);
    }
  }
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

static void
report_version(void)
{
  fprintf(stderr, "ejudge-configure-compilers %s, compiled %s\n",
          compile_version, compile_date);
  exit(0);
}

static const char help_txt[] =
"ejudge-configure-compilers: ejudge programming language configuration utility\n"
"Usage: ejudge-configure-compilers [OPTIONS]\n"
"  OPTIONS:\n"
"    --help\n"
"      write this help text and exit\n"
"    --version\n"
"      write the ejudge version and exit\n"
"    --list\n"
"      list the supported programming languages\n"
"    --batch\n"
"      batch mode configuration\n"
"    --visual\n"
"      visual (terminal-based) mode configuration (default)\n"
"    --enable-lang-config-dir=DIR\n"
"      use the DIR as the programming language configuration directory\n"
"      default value: %s\n"
"    --enable-lang-script-dir=DIR\n"
"      use the DIR as the programming language helper script directory\n"
"      default value: %s\n"
"    --with-LANG=PATH\n"
"      use the PATH as the path to the compiler/interpreter for LANG\n"
"    --without-LANG\n"
"      disable the compiler/interpreter LANG\n"
;

static void
report_help(void)
{
  path_t script_dir_default = { 0 };
  path_t config_dir_default = { 0 };
#if defined EJUDGE_SCRIPT_DIR
  snprintf(script_dir_default, sizeof(script_dir_default),
           "%s/lang", EJUDGE_SCRIPT_DIR);
#endif
#if defined EJUDGE_LANG_CONFIG_DIR
  snprintf(config_dir_default, sizeof(config_dir_default),
           "%s", EJUDGE_LANG_CONFIG_DIR);
#endif

  printf(help_txt, config_dir_default, script_dir_default);
  exit(0);
}

int
main(int argc, char **argv)
{
  int i, j, k;
  unsigned char **keys;
  unsigned char **vals;
  const unsigned char *val;
  int batch_mode = 0;
  int list_mode = 0;
  char *p;
  unsigned char key[1024];
  unsigned char path[1024];
  struct stat sb;

  progname = argv[0];

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
    } else if (!strcmp(argv[i], "--visual")) {
      batch_mode = 0;
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
    } else if (!strcmp(argv[i], "--version")) {
      report_version();
    } else if (!strcmp(argv[i], "--help")) {
      report_help();
    } else if (!strcmp(argv[i], "--list")) {
      list_mode = 1;
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

  if (list_mode) return list_all_compilers();
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
