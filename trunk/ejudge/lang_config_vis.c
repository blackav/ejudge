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

#include "lang_config_vis.h"
#include "ncurses_utils.h"
#include "pathutl.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <dirent.h>

static struct lang_config_info *lang_first, *lang_last;
static int lang_configured = 0;

struct lang_config_info *
lang_config_get_first(void)
{
  return lang_first;
}

static void
lang_config_clear(struct lang_config_info *p)
{
  if (!p) return;

  p->enabled = 0;
  xfree(p->cfg_txt); p->cfg_txt = 0;
  p->cfg_len = 0;
  xfree(p->short_name); p->short_name = 0;
  xfree(p->version); p->version = 0;
  p->cfg = shellconfig_free(p->cfg);
}

static struct lang_config_info *
lang_config_free(struct lang_config_info *p)
{
  if (!p) return 0;

  xfree(p->lang);
  xfree(p->config_arg);
  lang_config_clear(p);
  memset(p, 0, sizeof(*p));
  xfree(p);
  return 0;
}

static void
lang_config_unlink(struct lang_config_info *p)
{
  if (p == lang_first) {
    lang_first = lang_last = 0;
    p->prev = p->next = 0;
  } else if (!p->prev) {
    lang_first = p->next;
    lang_first->prev = 0;
    p->prev = p->next = 0;
  } else if (!p->next) {
    lang_last = p->prev;
    lang_last->next = 0;
    p->prev = p->next = 0;
  } else {
    p->next->prev = p->prev;
    p->prev->next = p->next;
    p->prev = p->next = 0;
  }
}


static void
lang_config_remove(const unsigned char *lang)
{
  struct lang_config_info *p;

  for (p = lang_first; p; p = p->next)
    if (!strcmp(lang, p->lang))
      break;
  if (!p) return;
  lang_config_unlink(p);
  lang_config_free(p);
}

struct lang_config_info *
lang_config_lookup(const unsigned char *lang)
{
  struct lang_config_info *p;

  for (p = lang_first; p; p = p->next)
    if (!strcmp(lang, p->lang))
      break;
  return p;
}

static struct lang_config_info *
lang_config_get(const unsigned char *lang)
{
  struct lang_config_info *p;

  for (p = lang_first; p; p = p->next)
    if (!strcmp(lang, p->lang))
      break;
  if (p) return p;

  XCALLOC(p, 1);
  p->lang = xstrdup(lang);
  if (!lang_first) {
    lang_first = lang_last = p;
  } else {
    p->prev = lang_last;
    lang_last->next = p;
    lang_last = p;
  }
  return p;
}

static int
reconfigure_language(
        const unsigned char *lang,
        const unsigned char *script_dir,
        const unsigned char *config_dir,
        unsigned char **keys,
        unsigned char **values,
        FILE *log_f,
        WINDOW *win)
{
  path_t fullpath, cfgpath;
  struct lang_config_info *p = 0;
  int fd_out[2] = { -1, -1 }, fd_err[2] = { -1, -1 };
  int ret_val = -1, pid, fd, max_fd, n, r, status, j, i;
  fd_set rset;
  unsigned char buf[4096];
  char *out_t = 0;
  size_t out_z = 0;
  FILE *out_f = 0;
  FILE *cfg_f = 0;
  shellconfig_t cfg = 0;
  const unsigned char *arg;

  snprintf(fullpath, sizeof(fullpath), "%s/%s-version", script_dir, lang);
  if (access(fullpath, X_OK) < 0) goto remove_language;
  p = lang_config_get(lang);
  ASSERT(p);
  lang_config_clear(p);

  if (config_dir) {
    snprintf(cfgpath, sizeof(cfgpath), "%s/%s.cfg", config_dir, lang);
    if ((out_f = open_memstream(&out_t, &out_z))) {
      if ((cfg_f = fopen(cfgpath, "r"))) {
        if ((cfg = shellconfig_parse(out_f, cfg_f, ""))) {
          if ((j = shellconfig_find_by_prefix(cfg, "arg", 3)) >= 0
              && (arg = shellconfig_get_value_by_num(cfg, j)) && *arg) {
            xfree(p->config_arg);
            p->config_arg = xstrdup(arg);
          }
          cfg = shellconfig_free(cfg);
        }
        fclose(cfg_f); cfg_f = 0;
      }
      fclose(out_f); out_f = 0;
      xfree(out_t); out_t = 0; out_z = 0;
    }
  }

  if (keys) {
    for (i = 0; keys[i]; i++)
      if (!strcmp(keys[i], lang))
        break;
    if (values[i] && *values[i]) {
      xfree(p->config_arg);
      p->config_arg = xstrdup(values[i]);
    }
  }

  // maybe it is too low-level?
  if (pipe(fd_out) < 0) goto remove_language;
  if (pipe(fd_err) < 0) goto remove_language;
  if ((pid = fork()) < 0) goto remove_language;
  if (!pid) {
    if ((fd = open("/dev/null", O_RDONLY, 0)) < 0) _exit(1);
    if (dup2(fd, 0) < 0) _exit(1);
    close(fd);
    if (dup2(fd_out[1], 1) < 0) _exit(1);
    close(fd_out[1]); close(fd_out[0]);
    if (dup2(fd_err[1], 2) < 0) _exit(1);
    close(fd_err[1]); close(fd_err[0]);
    // FIXME: chdir to somewhere
    execl(fullpath, fullpath, "-v", "-r", p->config_arg, NULL);
    _exit(1);
  }

  close(fd_out[1]); fd_out[1] = -1;
  close(fd_err[1]); fd_err[1] = -1;
  out_f = open_memstream(&out_t, &out_z);

  while (fd_out[0] >= 0 && fd_err[0] >= 0) {
    max_fd = -1;
    FD_ZERO(&rset);
    if (fd_out[0] >= 0) {
      FD_SET(fd_out[0], &rset);
      if (fd_out[0] > max_fd) max_fd = fd_out[0];
    }
    if (fd_err[0] >= 0) {
      FD_SET(fd_err[0], &rset);
      if (fd_err[0] > max_fd) max_fd = fd_err[0];
    }
    if (max_fd < 0) break;
    n = select(max_fd + 1, &rset, 0, 0, 0);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) goto remove_language;
    if (fd_out[0] >= 0 && FD_ISSET(fd_out[0], &rset)) {
      r = read(fd_out[0], buf, sizeof(buf));
      if (r < 0) goto remove_language;
      if (!r) {
        close(fd_out[0]); fd_out[0] = -1;
      } else {
        fwrite(buf, 1, r, out_f);
      }
    }
    if (fd_err[0] >= 0 && FD_ISSET(fd_err[0], &rset)) {
      r = read(fd_err[0], buf, sizeof(buf));
      if (r < 0) goto remove_language;
      if (!r) {
        close(fd_err[0]); fd_err[0] = -1;
      } else {
        if (win) {
          wprintw(win, "%.*s", r, buf);
          update_panels();
          doupdate();
        }
        if (log_f) {
          fprintf(log_f, "%.*s", r, buf);
        }
      }
    }
  }

  wait(&status);
  fclose(out_f); out_f = 0;
  if (strlen(out_t) != out_z) goto remove_language;
  p->cfg_txt = out_t; out_t = 0;
  p->cfg_len = out_z;
  out_t = 0;
  out_z = 0;
  if (!(out_f = open_memstream(&out_t, &out_z))) goto remove_language;
  if (!(cfg_f = fmemopen(p->cfg_txt, p->cfg_len, "r"))) goto remove_language;
  if (!(p->cfg = shellconfig_parse(out_f, cfg_f, ""))) goto cleanup;
  fclose(cfg_f); cfg_f = 0;
  fclose(out_f); out_f = 0;
  xfree(out_t); out_t = 0; out_z = 0;
  if ((j = shellconfig_find_by_prefix(p->cfg, "short_name", 10)) < 0) {
    p->short_name = xstrdup(lang);
  } else {
    p->short_name = xstrdup(shellconfig_get_value_by_num(p->cfg, j));
  }
  if ((j = shellconfig_find_by_prefix(p->cfg, "version", 7)) >= 0
      && WIFEXITED(status) && !WEXITSTATUS(status)) {
    p->version = xstrdup(shellconfig_get_value_by_num(p->cfg, j));
    if (p->version && *p->version) p->enabled = 1;
  }
  ret_val = 0;
  goto cleanup;

 remove_language:
  lang_config_remove(lang);
  goto cleanup;

 cleanup:
  if (cfg_f) fclose(cfg_f);
  if (out_f) fclose(out_f);
  if (out_t) xfree(out_t);
  if (fd_out[0] >= 0) close(fd_out[0]);
  if (fd_out[1] >= 0) close(fd_out[1]);
  if (fd_err[0] >= 0) close(fd_err[0]);
  if (fd_err[1] >= 0) close(fd_err[1]);
  return ret_val;
}

static void
reconfigure_all_languages(
        const unsigned char *script_dir,
        const unsigned char *config_dir,
        unsigned char **keys,
        unsigned char **values,
        FILE *log_f,
        WINDOW *win)
{
  path_t langbase;
  DIR *d = 0;
  struct dirent *dd;
  int len;

  if (!(d = opendir(script_dir))) {
    return;
  }
  while ((dd = readdir(d))) {
    len = strlen(dd->d_name);
    if (len <= 8) continue;
    if (strcmp(dd->d_name + len - 8, "-version") != 0) continue;
    snprintf(langbase, sizeof(langbase), "%.*s", len - 8, dd->d_name);
    reconfigure_language(langbase, script_dir, config_dir, keys,
                         values, log_f, win);
  }
  closedir(d); d = 0;

#if 0
  {
    struct lang_config_info *p;

    for (p = lang_first; p; p = p->next) {
      fprintf(stderr, "0x%08zx:\n", (size_t) p);
      fprintf(stderr, "  lang: >%s<\n", p->lang);
      fprintf(stderr, "  config_arg: >%s<\n", p->config_arg);
      fprintf(stderr, "  enabled: %d\n", p->enabled);
      fprintf(stderr, "  cfg_txt: >%s<\n", p->cfg_txt);
      fprintf(stderr, "  short_name: >%s<\n", p->short_name);
      fprintf(stderr, "  version: >%s<\n", p->version);
    }
  }
#endif
}

void
lang_configure_screen(
        const unsigned char *script_dir,
        const unsigned char *config_dir,
        unsigned char **keys,
        unsigned char **values,
        const unsigned char *header)
{
  WINDOW *in_win = 0, *out_win = 0;
  PANEL *in_pan = 0, *out_pan = 0;
  int c;

  if (lang_configured) return;
  lang_configured = 1;

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

  reconfigure_all_languages(script_dir, config_dir, keys, values, 0, in_win);
  ncurses_print_help("Press any key");
  doupdate();
  c = getch();

  if (in_pan) del_panel(in_pan);
  if (out_pan) del_panel(out_pan);
  if (out_win) delwin(out_win);
  if (in_win) delwin(in_win);
}

void
lang_configure_batch(
        const unsigned char *script_dir,
        const unsigned char *config_dir,
        unsigned char **keys,
        unsigned char **values,
        FILE *log_f)
{
  reconfigure_all_languages(script_dir, config_dir, keys, values, log_f, 0);
}

static int
lang_sort_func(const void *p1, const void *p2)
{
  const struct lang_config_info *v1 = *(const struct lang_config_info**) p1;
  const struct lang_config_info *v2 = *(const struct lang_config_info**) p2;
  return strcmp(v1->lang, v2->lang);
}

int
lang_config_menu(
        const unsigned char *script_dir,
        const unsigned char *header,
        int utf8_mode,
        int *p_cur_item)
{
  int ret_val = 0;
  int cur_item = *p_cur_item, lang_count = 0, i;
  struct lang_config_info *pcfg;
  struct lang_config_info **langs = 0;
  char **descs = 0;
  const unsigned char *arg_str, *ver_str;
  unsigned char buf[1024], buf2[1024];
  ITEM **items = 0;
  MENU *menu = 0;
  WINDOW *in_win = 0, *out_win = 0;
  PANEL *in_pan = 0, *out_pan = 0;
  int first_row = 0;
  int c, cmd, j;

  lang_configure_screen(script_dir, 0, 0, 0, header);

  for (pcfg = lang_first; pcfg; pcfg = pcfg->next) {
    // ignore everything that has no parsed config
    if (pcfg->cfg) lang_count++;
  }
  if (!lang_count) goto done;
  XCALLOC(langs, lang_count);
  for (pcfg = lang_first, i = 0; pcfg; pcfg = pcfg->next) {
    if (pcfg->cfg) langs[i++] = pcfg;
  }
  qsort(langs, lang_count, sizeof(langs[0]), lang_sort_func);

  XCALLOC(descs, lang_count);
  for (i = 0; i < lang_count; i++) {
    pcfg = langs[i];
    arg_str = "<default>";
    if (pcfg->config_arg && *pcfg->config_arg) arg_str = pcfg->config_arg;
    ver_str = "disabled";
    if (pcfg->enabled > 0 && pcfg->version && *pcfg->version)
      ver_str = pcfg->version;
    snprintf(buf, sizeof(buf), "%-10.10s %-10.10s %-50.50s",
             pcfg->lang, ver_str, arg_str);
    descs[i] = xstrdup(buf);
  }
  XCALLOC(items, lang_count + 1);
  for (i = 0; i < lang_count; i++)
    items[i] = new_item(descs[i], 0);
  menu = new_menu(items);
  set_menu_back(menu, COLOR_PAIR(1));
  set_menu_fore(menu, COLOR_PAIR(3));
  set_menu_grey(menu, COLOR_PAIR(5));
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
  set_menu_win(menu, in_win);
  set_menu_format(menu, LINES - 4, 0);

  if (cur_item < 0) cur_item = 0;
  if (cur_item >= lang_count) cur_item = lang_count - 1;
  first_row = cur_item - (LINES - 4)/2;
  if (first_row + LINES - 4 > lang_count) first_row = lang_count - (LINES - 4);
  if (first_row < 0) first_row = 0;
  set_top_row(menu, first_row);
  set_current_item(menu, items[cur_item]);

  while (1) {
    mvwprintw(stdscr, 0, 0, "%s > Compiler settings", header);
    wclrtoeol(stdscr);
    ncurses_print_help("Q - quit, Enter - edit, B - browse");
    show_panel(out_pan);
    show_panel(in_pan);
    post_menu(menu);
    update_panels();
    doupdate();

    while (1) {
      c = getch();
      cmd = -1;
      switch (c) {
      case 'q': case 'Q': case 'Ê' & 255: case 'ê' & 255: case 'G' & 31:
      case 033:
        c = 'q';
        goto menu_done;
      case '\n': case '\r':
        c = '\n';
        goto menu_done;
      case 'b': case 'B': case 'É' & 255: case 'é' & 255:
        c = 'b';
        goto menu_done;
      case KEY_UP: case KEY_LEFT:
        cmd = REQ_UP_ITEM;
        break;
      case KEY_DOWN: case KEY_RIGHT:
        cmd = REQ_DOWN_ITEM;
        break;
      case KEY_HOME:
        cmd = REQ_FIRST_ITEM;
        break;
      case KEY_END:
        cmd = REQ_LAST_ITEM;
        break;
      case KEY_NPAGE:
        i = item_index(current_item(menu));
        if (i + LINES - 4 >= lang_count) cmd = REQ_LAST_ITEM;
        else cmd = REQ_SCR_DPAGE;
        break;
      case KEY_PPAGE:
        i = item_index(current_item(menu));
        if (i - (LINES - 4) < 0) cmd = REQ_FIRST_ITEM;
        else cmd = REQ_SCR_UPAGE;
        break;
      }
      if (cmd != -1) {
        menu_driver(menu, cmd);
        update_panels();
        doupdate();
      }
    }
    menu_done:;
    if (c == 'q') {
      cur_item = item_index(current_item(menu));
      break;
    }
    if (c == '\n') {
      i = item_index(current_item(menu));
      arg_str = "";
      if (langs[i]->config_arg) arg_str = langs[i]->config_arg;
      snprintf(buf, sizeof(buf), "%s", arg_str);
      snprintf(buf2, sizeof(buf2), "Compiler path for %s", langs[i]->lang);
      j = ncurses_edit_string(LINES/2, COLS, buf2, buf, sizeof(buf), utf8_mode);
      if (j < 0) continue;
      xfree(langs[i]->config_arg); langs[i]->config_arg = 0;
      if (buf[0]) langs[i]->config_arg = xstrdup(buf);
      reconfigure_language(langs[i]->lang, script_dir, 0, 0, 0, 0, 0);
      cur_item = i;
      ret_val = 1;
      break;
    }
    if (c == 'b') {
      i = item_index(current_item(menu));
      arg_str = "";
      if (langs[i]->config_arg) arg_str = langs[i]->config_arg;
      snprintf(buf, sizeof(buf), "%s", arg_str);
      snprintf(buf2, sizeof(buf2), "Compiler path for %s", langs[i]->lang);
      j = ncurses_choose_file(buf2, buf, sizeof(buf), utf8_mode);
      if (j < 0) continue;
      xfree(langs[i]->config_arg); langs[i]->config_arg = 0;
      if (buf[0]) langs[i]->config_arg = xstrdup(buf);
      reconfigure_language(langs[i]->lang, script_dir, 0, 0, 0, 0, 0);
      cur_item = i;
      ret_val = 1;
      break;
    }
  }

 done:
  if (in_pan) del_panel(in_pan);
  if (out_pan) del_panel(out_pan);
  if (out_win) delwin(out_win);
  if (in_win) delwin(in_win);
  if (menu) free_menu(menu);
  if (items) {
    for (i = 0; i < lang_count; i++)
      free_item(items[i]);
  }
  if (descs) {
    for (i = 0; i < lang_count; i++)
      xfree(descs[i]);
  }
  xfree(descs);
  xfree(langs);
  *p_cur_item = cur_item;
  return ret_val;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "WINDOW" "ITEM" "PANEL" "MENU")
 * End:
 */
