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
#include "version.h"

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
#include <utime.h>
#include <time.h>

static struct lang_config_info *lang_first, *lang_last;
static int lang_configured = 0;

struct lang_id_info
{
  unsigned char *lang;
  int id;
};

static int lang_id_configured = 0;
static int lang_id_total = 0;
static int lang_id_max_id = 0;
static struct lang_id_info *lang_id_infos = 0;

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

static void
parse_lang_id_file(
        const unsigned char *script_dir,
        FILE *err_f,
        WINDOW *win)
{
  path_t id_file;
  FILE *in_f = 0;
  FILE *log_f = 0;
  char *log_t = 0;
  size_t log_z = 0;
  shellconfig_t cfg = 0;
  int i, val, j;
  char *eptr;

  if (lang_id_configured) return;
  lang_id_configured = 1;

  snprintf(id_file, sizeof(id_file), "%s/lang_ids.cfg", script_dir);
  if (!(in_f = fopen(id_file, "r"))) {
    log_printf(err_f, win, "cannot open `%s' for reading\n", id_file);
    goto cleanup;
  }
  if (!(log_f = open_memstream(&log_t, &log_z))) goto cleanup;
  if (!(cfg = shellconfig_parse(log_f, in_f, id_file))) {
    fclose(log_f); log_f = 0;
    log_printf(err_f, win, "%s", log_t);
    goto cleanup;
  }
  fclose(log_f); log_f = 0;
  xfree(log_t); log_t = 0; log_z = 0;
  fclose(in_f); in_f = 0;

  lang_id_total = cfg->usage;
  lang_id_max_id = 0;
  XCALLOC(lang_id_infos, lang_id_total);
  for (i = 0, j = 0; i < lang_id_total; i++) {
    errno = 0;
    val = strtol(cfg->values[i], &eptr, 10);
    if (errno || *eptr || val <= 0 || val > 999999) {
      log_printf(err_f, win, "invalid language id `%s' for language `%s'\n",
                 cfg->values[i], cfg->names[i]);
    } else {
      lang_id_infos[j].lang = xstrdup(cfg->names[i]);
      lang_id_infos[j].id = val;
      if (val > lang_id_max_id) lang_id_max_id = val;
      ++j;
    }
  }
  lang_id_total = j;
  if (!lang_id_total) {
    log_printf(err_f, win, "no language ids are configured\n");
  }

 cleanup:
  shellconfig_free(cfg);
  if (in_f) fclose(in_f);
  if (log_f) fclose(log_f);
  xfree(log_t);
}

static void
assign_lang_ids(void)
{
  struct lang_config_info *p;
  struct lang_config_info **m;
  int i;

  if (lang_id_total <= 0 || lang_id_max_id <= 0) return;
  for (p = lang_first; p; p = p->next)
    p->id = 0;

  XALLOCAZ(m, lang_id_max_id + 1);
  for (i = lang_id_total - 1; i >= 0; --i) {
    ASSERT(lang_id_infos[i].id > 0 && lang_id_infos[i].id <= lang_id_max_id);
    if (m[lang_id_infos[i].id] && m[lang_id_infos[i].id]->enabled) continue;
    for (p = lang_first; p; p = p->next) {
      if (p->short_name && !strcmp(lang_id_infos[i].lang, p->short_name))
        break;
      //else if (!p->short_name && !strcmp(lang_id_infos[i].lang, p->lang))
      //break;
    }
    if (!p) continue;
    if (m[lang_id_infos[i].id]) m[lang_id_infos[i].id]->id = 0;
    p->id = lang_id_infos[i].id;
    m[p->id] = p;
  }
}

static int
id_sort_func(const void *v1, const void *v2)
{
  const struct lang_config_info *p1 = *(const struct lang_config_info**) v1;
  const struct lang_config_info *p2 = *(const struct lang_config_info**) v2;
  return p1->id - p2->id;
}

void
lang_config_get_sorted(
        int *p_num,
        struct lang_config_info ***p_langs)
{
  int num, i;
  struct lang_config_info *p, **langs;

  assign_lang_ids();
  for (p = lang_first, num = 0; p; p = p->next)
    if (p->id > 0) num++;
  if (!num) {
    *p_num = 0;
    *p_langs = 0;
    return;
  }

  XCALLOC(langs, num);
  for (p = lang_first, i = 0; p; p = p->next)
    if (p->id > 0) langs[i++] = p;
  ASSERT(i == num);
  qsort(langs, num, sizeof(langs[0]), id_sort_func);
  *p_num = num;
  *p_langs = langs;
}

static unsigned char *
do_substitute(
        unsigned char *txt,
        const unsigned char * const *names,
        const unsigned char * const *values)
{
  int i, nlen, vlen, tlen;
  unsigned char *pp;
  unsigned char *txt2 = 0;

  if (!txt || !*txt) return txt;

  while (1) {
    pp = 0;
    for (i = 0; names[i]; i++)
      if ((pp = strstr(txt, names[i])))
        break;
    if (!pp) break;

    ASSERT(values[i]);
    nlen = strlen(names[i]);
    vlen = strlen(values[i]);
    tlen = strlen(txt);

    ASSERT(nlen > 0);
    txt2 = (unsigned char*) xmalloc(tlen - nlen + vlen + 1);
    sprintf(txt2, "%.*s%s%s", pp - txt, txt, values[i], pp + nlen);
    xfree(txt); txt = txt2; txt2 = 0;
  }

  return txt;
}
              

static void
update_language_script(
        const unsigned char *script_in,
        const unsigned char *script_out,
        const unsigned char *script_base,
        FILE *log_f,
        FILE *err_f,
        WINDOW *win)
{
  char *in_t = 0, *out_t = 0;
  FILE *in_f = 0, *out_f = 0;
  size_t in_z = 0, out_z = 0;
  FILE *f = 0;
  char buf[1024];
  static const unsigned char * const names[] = 
  {
    "@lang_config_dir@",
    "@prefix@",
    "@exec_prefix@",
    "@libexecdir@",
    "@local_dir@",
    "@contests_home_dir@",
    0
  };
  static const unsigned char * const values[] =
  {
#if defined EJUDGE_LANG_CONFIG_DIR
    EJUDGE_LANG_CONFIG_DIR,
#else
    "",
#endif
#if defined EJUDGE_PREFIX_DIR
    EJUDGE_PREFIX_DIR,
#else
    "",
#endif
#if defined EJUDGE_PREFIX_DIR
    EJUDGE_PREFIX_DIR,
#else
    "",
#endif
#if defined EJUDGE_LIBEXEC_DIR
    EJUDGE_LIBEXEC_DIR,
#else
    "",
#endif
#if defined EJUDGE_LOCAL_DIR
    EJUDGE_LOCAL_DIR,
#else
    "",
#endif
#if defined EJUDGE_CONTESTS_HOME_DIR
    EJUDGE_CONTESTS_HOME_DIR,
#else
    "",
#endif
    0
  };

  // read the source file
  if (!(f = fopen(script_in, "r"))) {
    log_printf(err_f, win, "error: cannot open `%s' for reading\n", script_in);
    goto cleanup;
  }
  if (!(in_f = open_memstream(&in_t, &in_z))) goto cleanup;
  while (fgets(buf, sizeof(buf), f))
    fputs(buf, in_f);
  fclose(in_f); in_f = 0;
  fclose(f); f = 0;

  // substitute stuff
  in_t = do_substitute(in_t, names, values);

  // read the destination file (if such exists)
  if ((f = fopen(script_out, "r"))) {
    if (!(out_f = open_memstream(&out_t, &out_z))) goto cleanup;
    while (fgets(buf, sizeof(buf), f))
      fputs(buf, out_f);
    fclose(out_f); out_f = 0;
    fclose(f); f = 0;
    if (!strcmp(out_t, in_t)) {
      // no difference, but update the modtime
      if (utime(script_out, 0) < 0) {
        log_printf(err_f, win, "error: cannot change mod time for `%s'\n",
                   script_out);
        // error
      }
      goto cleanup;
    }
    xfree(out_t); out_t = 0;
  }

  // write the output file
  if (!(f = fopen(script_out, "w"))) {
    log_printf(err_f, win, "error: cannot open `%s' for writing\n",
               script_out);
    goto cleanup;
  }
  fprintf(f, "%s", in_t);
  fflush(f);
  if (ferror(f)) {
    log_printf(err_f, win, "error: write to `%s' failed\n", script_out);
    goto cleanup;
  }
  fclose(f); f = 0;

  if (chmod(script_out, 0775) < 0) {
    log_printf(err_f, win, "error: cannot do chmod on `%s'", script_out);
  }

  fprintf(log_f, " %s", script_base);

 cleanup:
  if (f) fclose(f);
  if (in_f) fclose(in_f);
  xfree(in_t);
  if (out_f) fclose(out_f);
  xfree(out_t);
}

static void
update_language_scripts(
        const unsigned char *script_dir,
        FILE *log_f,
        WINDOW *win)
{
  path_t script_in_dir;
  path_t script_base;
  path_t script_in;
  path_t script_out;
  DIR *d = 0;
  struct dirent *dd;
  int nlen, need_update = -1;
  struct stat is, os;
  FILE *upd_f = 0;
  char *upd_t = 0;
  size_t upd_z = 0;

  if (!script_dir) return;
  snprintf(script_in_dir, sizeof(script_in_dir), "%s/in", script_dir);
  if (!(d = opendir(script_in_dir))) {
    log_printf(log_f, win, "error: directory `%s' does not exist\n",
               script_in_dir);
    return;
  }
  upd_f = open_memstream(&upd_t, &upd_z);
  while ((dd = readdir(d))) {
    need_update = -1;
    if ((nlen = strlen(dd->d_name)) <= 3) continue;
    if (strcmp(dd->d_name + nlen - 3, ".in") != 0) continue;
    snprintf(script_base, sizeof(script_base), "%.*s", nlen - 3, dd->d_name);
    snprintf(script_in, sizeof(script_in), "%s/in/%s.in",
             script_dir, script_base);
    snprintf(script_out, sizeof(script_out), "%s/%s", script_dir, script_base);
    if (stat(script_in, &is) < 0) continue;
    if (!S_ISREG(is.st_mode)) continue;
    if (stat(script_out, &os) >= 0) {
      if (!S_ISREG(os.st_mode)) {
        log_printf(log_f, win, "error: `%s' is not a regular file\n",
                   script_out);
        continue;
      }
      if (os.st_mtime >= is.st_mtime) continue;
    }
    update_language_script(script_in, script_out, script_base, upd_f, log_f,
                           win);
  }
  closedir(d); d = 0;
  fclose(upd_f); upd_f = 0;
  if (upd_t && *upd_t) log_printf(log_f, win, "Scripts updated:%s\n", upd_t);
  xfree(upd_t); upd_t = 0; upd_z = 0;
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

  update_language_scripts(script_dir, log_f, win);
  parse_lang_id_file(script_dir, log_f, win);

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

  assign_lang_ids();

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
  scrollok(in_win, TRUE);
  idlok(in_win, TRUE);
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
  unsigned char lang_id_buf[32];

  lang_configure_screen(script_dir, 0, 0, 0, header);
  assign_lang_ids();

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
    lang_id_buf[0] = 0;
    if (pcfg->id > 0) {
      snprintf(lang_id_buf, sizeof(lang_id_buf), "%d", pcfg->id);
    }
    snprintf(buf, sizeof(buf), "%-10.10s %-5.5s %-10.10s %-44.44s",
             pcfg->lang, lang_id_buf, ver_str, arg_str);
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

static void
generate_current_date(unsigned char *buf, size_t size)
{
  time_t curtime;
  struct tm *ptm;

  curtime = time(0);
  ptm = localtime(&curtime);
  snprintf(buf, size, "%04d/%02d/%02d %02d:%02d:%02d",
          ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
          ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
}

void
lang_config_generate_compile_cfg(
        FILE *f,
        const unsigned char *prog,
        const unsigned char *compile_home_dir,
        int serialization_key,
        const unsigned char *lang_config_dir)
{
  unsigned char date_buf[64];
  int lang_num = 0, i;
  struct lang_config_info **langs = 0;
  struct lang_config_info *p;
  const unsigned char *s;

  lang_config_get_sorted(&lang_num, &langs);

  generate_current_date(date_buf, sizeof(date_buf));

  fprintf(f, "# Generated by %s, version %s\n", prog, compile_version);
  fprintf(f, "# Generation date: %s\n\n", date_buf);
  fprintf(f, "root_dir = %s\n", compile_home_dir);
  fprintf(f, "cr_serialization_key = %d\n\n", serialization_key);

  fprintf(f,
          "sleep_time = 1000\n"
          "\n");

  if (lang_config_dir && lang_config_dir[0]) {
    fprintf(f, "lang_config_dir = \"%s\"\n\n", lang_config_dir);
  }

  for (i = 0; i < lang_num; i++) {
    p = langs[i];
    if (!p->cfg) continue;
    fprintf(f, "[language]\n");
    fprintf(f, "id = %d\n", p->id);
    if ((s = shellconfig_get(p->cfg, "short_name"))) {
      fprintf(f, "short_name = \"%s\"\n", s);
    } else {
      fprintf(f, "short_name = \"%s\"\n", p->lang);
    }
    s = shellconfig_get(p->cfg, "long_name");
    if (!s) s = "";
    fprintf(f, "long_name = \"%s\"\n", s);
    /*
    s = shellconfig_get(p->cfg, "version");
    if (!s) s = "";
    fprintf(f, "%s\"\n", s);
    */
    if ((s = shellconfig_get(p->cfg, "src_sfx"))) {
      fprintf(f, "src_sfx = \"%s\"\n", s);
    }
    if ((s = shellconfig_get(p->cfg, "exe_sfx"))) {
      fprintf(f, "exe_sfx = \"%s\"\n", s);
    }
    if ((s = shellconfig_get(p->cfg, "insecure"))) {
      fprintf(f, "insecure\n");
    }
    if (!(s = shellconfig_get(p->cfg, "cmd"))) s = p->lang;
    fprintf(f, "cmd = \"%s\"\n", s);
    if ((s = shellconfig_get(p->cfg, "arch"))) {
      fprintf(f, "arch = \"%s\"\n", s);
    }
    fprintf(f, "\n");
  }

  /*
  fprintf(f,
          "[language]\n"
          "id = 7\n"
          "short_name = \"tpc\"\n"
          "long_name = \"Turbo Pascal\"\n"
          "src_sfx = \".pas\"\n"
          "exe_sfx = \".exe\"\n"
          "cmd = \"bpcemu2\"\n"
          "arch = dos\n"
          "\n");
  */

  /*
  fprintf(f,
          "[language]\n"
          "id = 9\n"
          "short_name = \"bcc\"\n"
          "long_name = \"Borland C\"\n"
          "src_sfx = \".c\"\n"
          "exe_sfx = \".exe\"\n"
          "cmd = \"bccemu\"\n"
          "arch = dos\n"
          "\n");
  */

  /*
  fprintf(f,
          "[language]\n"
          "id = 10\n"
          "short_name = \"bpp\"\n"
          "long_name = \"Borland C++\"\n"
          "src_sfx = \".cpp\"\n"
          "exe_sfx = \".exe\"\n"
          "cmd = \"bppemu\"\n"
          "arch = dos\n"
          "\n");
  */

  /*
  fprintf(f,
          "[language]\n"
          "id = 16\n"
          "short_name = \"qb\"\n"
          "long_name = \"Quick Basic\"\n"
          "src_sfx = \".bas\"\n"
          "exe_sfx = \".exe\"\n"
          "cmd = \"qbemu\"\n"
          "arch = dos\n"
          "\n");
  */

  xfree(langs);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "WINDOW" "ITEM" "PANEL" "MENU")
 * End:
 */
