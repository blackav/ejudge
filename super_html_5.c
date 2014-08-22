/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008-2014 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_limits.h"
#include "ejudge/super_html.h"
#include "ejudge/super-serve.h"
#include "ejudge/super_proto.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>

#define ARMOR(s)  html_armor_buf(&ab, s)
#define URLARMOR(s)  url_armor_buf(&ab, s)
#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

static int
is_valid_package(
        unsigned char *buf,
        size_t size,
        const unsigned char *package)
{
  int i, len;

  buf[0] = 0;
  if (!package || !*package) return 1;
  len = strlen(package);
  if (package[0] == '.' || package[len - 1] == '.') return 0;
  for (i = 0; i < len; ++i) {
    if (!isalnum(package[i]) && package[i] != '_' && package[i] != '-' && package[i] != '.')
      return 0;
    if (package[i] == '.' && i > 0 && package[i - 1] == '.') return 0;
  }
  snprintf(buf, size, "%s", package);
  len = strlen(buf);
  for (i = 0; i < len; ++i)
    if (buf[i] == '.') buf[i] = '/';
  return 1;
}

static int
is_valid_dir(unsigned char *buf, size_t size, const unsigned char *name)
{
  if (!name || !*name) return 0;
  for (int i = 0, len = strlen(name); i < len; ++i)
    if (!isalnum(name[i]) && name[i] != '_' && name[i] != '-')
      return 0;
  snprintf(buf, size, "%s", name);
  return 1;
}

static int
is_valid_file(unsigned char *buf, size_t size, const unsigned char *name)
{
  if (!name || !*name) return 0;
  int len = strlen(name);
  if (len <= 4) return 0;
  if (strcmp(name + len - 4, ".xml")) return 0;
  len -= 4;
  for (int i = 0; i < len; ++i)
    if (!isalnum(name[i]) && name[i] != '_' && name[i] != '-')
      return 0;
  snprintf(buf, size, "%.*s", len, name);
  return 1;
}

enum
{
  DIRLIST_PACKAGE = 1,
  DIRLIST_PROBLEM,
  DIRLIST_PROBDIR,
};

struct dirlist_entry
{
  int kind;
  unsigned char *name;
};

static int
dl_sort_func(const void *v1, const void *v2)
{
  const struct dirlist_entry *p1 = (const struct dirlist_entry*) v1;
  const struct dirlist_entry *p2 = (const struct dirlist_entry*) v2;

  if (p1->kind != p2->kind) return p1->kind - p2->kind;
  return strcmp(p1->name, p2->name);
}

int
super_serve_op_browse_problem_packages(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  const unsigned char *package = 0;
  path_t pkgroot, pkgdir, pkgpath, fpath, fname;
  struct stat stb;
  DIR *d = 0;
  struct dirent *dd = 0;
  int dl_a = 0, dl_u = 0, kind = 0, i, j, len;
  struct dirlist_entry *dls = 0;
  unsigned char buf[1024], jbuf[1024];

  if (hr_cgi_param(phr, "package", &package) < 0)
    FAIL(SSERV_ERR_INV_PACKAGE);
  if (!package) package = "";
  if (!is_valid_package(pkgdir, sizeof(pkgdir), package))
    FAIL(SSERV_ERR_INV_PACKAGE);
  snprintf(pkgroot, sizeof(pkgroot), "%s/problems", EJUDGE_CONTESTS_HOME_DIR);
  if (stat(pkgroot, &stb) < 0) {
    if (mkdir(pkgroot, 0755) < 0) {
      err("%s: mkdir %s failed: %s", __FUNCTION__, pkgroot, os_ErrorMsg());
      FAIL(SSERV_ERR_INV_PACKAGE);
    }
    if (stat(pkgroot, &stb) < 0) {
      err("%s: stat %s failed: %s", __FUNCTION__, pkgroot, os_ErrorMsg());
      FAIL(SSERV_ERR_INV_PACKAGE);
    }
  }
  if (!S_ISDIR(stb.st_mode)) {
    err("%s: %s is not a directory", __FUNCTION__, pkgroot);
    FAIL(SSERV_ERR_INV_PACKAGE);
  }

  if (pkgdir[0]) {
    snprintf(pkgpath, sizeof(pkgpath), "%s/%s", pkgroot, pkgdir);
  } else {
    snprintf(pkgpath, sizeof(pkgpath), "%s", pkgroot);
  }
  if (stat(pkgpath, &stb) < 0) {
    err("%s: directory %s does not exist", __FUNCTION__, pkgpath);
    FAIL(SSERV_ERR_INV_PACKAGE);
  }
  if (!S_ISDIR(stb.st_mode)) {
    err("%s: %s is not a directory", __FUNCTION__, pkgpath);
    FAIL(SSERV_ERR_INV_PACKAGE);
  }
  if (!(d = opendir(pkgpath))) {
    err("%s: cannot open directory %s", __FUNCTION__, pkgpath);
    FAIL(SSERV_ERR_INV_PACKAGE);
  }
  while ((dd = readdir(d))) {
    if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, "..")) continue;
    snprintf(fpath, sizeof(fpath), "%s/%s", pkgpath, dd->d_name);
    if (stat(fpath, &stb) < 0) continue;
    if (S_ISDIR(stb.st_mode)) {
      if (!is_valid_dir(fname, sizeof(fname), dd->d_name)) continue;
      kind = DIRLIST_PACKAGE;
    } else if (S_ISREG(stb.st_mode)) {
      if (!is_valid_file(fname, sizeof(fname), dd->d_name)) continue;
      kind = DIRLIST_PROBLEM;
    }
    if (dl_u == dl_a) {
      if (!dl_a) dl_a = 16;
      dl_a *= 2;
      XREALLOC(dls, dl_a);
    }
    dls[dl_u].kind = kind;
    dls[dl_u].name = xstrdup(dd->d_name);
    dl_u++;
  }
  closedir(d); d = 0;

  for (i = 0; i < dl_u; ++i) {
    if (dls[i].kind == DIRLIST_PROBLEM) {
      for (j = 0; j < dl_u; ++j) {
        if (i != j && !strcmp(dls[i].name, dls[j].name)
            && dls[j].kind == DIRLIST_PACKAGE)
          dls[j].kind = DIRLIST_PROBDIR;
      }
    }
  }

  qsort(dls, dl_u, sizeof(dls[0]), dl_sort_func);

  if (package[0]) {
    snprintf(buf, sizeof(buf), "serve-control: %s, package %s",
             phr->html_name, package);
  } else {
    snprintf(buf, sizeof(buf), "serve-control: %s, root package",
             phr->html_name);
  }
  ss_write_html_header(out_f, phr, buf, 1, 0);

  fprintf(out_f, "<h1>%s</h1>\n<br/>\n", buf);

  i = 0;
  if (i < dl_u && dls[i].kind == DIRLIST_PACKAGE) {
    fprintf(out_f, "<h2>Packages</h2><br/>\n");
    fprintf(out_f, "<table class=\"cnts_edit\">\n");
    for (; i < dl_u && dls[i].kind == DIRLIST_PACKAGE; ++i) {
      if (package[0]) {
        snprintf(buf, sizeof(buf), "%s.%s", package, dls[i].name);
      } else {
        snprintf(buf, sizeof(buf), "%s", dls[i].name);
      }
      snprintf(jbuf, sizeof(jbuf), "ssPackage(%d, '%s')",
               SSERV_CMD_BROWSE_PROBLEM_PACKAGES, buf);
      fprintf(out_f, "<tr><td onClick=\"%s\" class=\"cnts_edit_legend\"><img src=\"%sicons/%s.png\" alt=\"folder\" /></td><td onClick=\"%s\" class=\"cnts_edit_legend\"><tt>%s</tt></td></tr>\n", jbuf, CONF_STYLE_PREFIX, "folder-16x16", jbuf, dls[i].name);
    }
    fprintf(out_f, "</table><br/>\n");
  }

  if (i < dl_u && dls[i].kind == DIRLIST_PROBLEM) {
    fprintf(out_f, "<h2>Problems</h2><br/>\n");
    fprintf(out_f, "<table class=\"cnts_edit\">\n");
    for (; i < dl_u && dls[i].kind == DIRLIST_PROBLEM; ++i) {
      snprintf(jbuf, sizeof(jbuf), "ssEditProblem(%d, '%s', '%s')",
               SSERV_CMD_EDIT_PROBLEM, package, dls[i].name);
      fprintf(out_f, "<tr><td onClick=\"%s\" class=\"cnts_edit_legend\"><img src=\"%sicons/%s.png\" alt=\"problem\" /></td><td onClick=\"%s\" class=\"cnts_edit_legend\"><tt>%s</tt></td></tr>\n", jbuf, CONF_STYLE_PREFIX, "edit_page-16x16", jbuf, dls[i].name);
    }
    fprintf(out_f, "</table><br/>\n");
  }

  fprintf(out_f, "<table class=\"cnts_edit\">\n");
  snprintf(jbuf, sizeof(jbuf), "ssPackageOp(%d, %d, '%s', arguments[0])",
           SSERV_CMD_CREATE_PACKAGE, SSERV_CMD_BROWSE_PROBLEM_PACKAGES,
           package);
  fprintf(out_f, "<tr><td class=\"cnts_edit_legend\">Create new package:&nbsp;</td><td class=\"cnts_edit_data\" width=\"200px\"><div class=\"cnts_edit_data\" dojoType=\"dijit.InlineEditBox\" onChange=\"%s\" autoSave=\"true\"></div></td></tr>\n", jbuf);
  snprintf(jbuf, sizeof(jbuf), "ssEditProblem(%d, '%s', arguments[0])",
           SSERV_CMD_CREATE_PROBLEM, package);
  fprintf(out_f, "<tr><td class=\"cnts_edit_legend\">Create new problem:&nbsp;</td><td class=\"cnts_edit_data\" width=\"200px\"><div class=\"cnts_edit_data\" dojoType=\"dijit.InlineEditBox\" onChange=\"%s\" autoSave=\"true\"></div></td></tr>\n", jbuf);
  fprintf(out_f, "</table><br/>\n");

  ss_dojo_button(out_f, "1", "home-32x32", "To the Top", "ssTopLevel()");
  if (package[0]) {
    snprintf(buf, sizeof(buf), "%s", package);
    len = strlen(buf);
    while (len > 0 && buf[len - 1] != '.') len--;
    if (len > 0) --len;
    buf[len] = 0;
    ss_dojo_button(out_f, "2", "back-32x32", "Level up",
                   "ssPackage(%d, \"%s\")",
                   SSERV_CMD_BROWSE_PROBLEM_PACKAGES, buf);
  }
  ss_write_html_footer(out_f);

 cleanup:
  for (i = 0; i < dl_u; ++i)
    xfree(dls[i].name);
  xfree(dls);
  if (d) closedir(d);
  return retval;
}

int
super_serve_op_package_operation(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int retval = 0;
  const unsigned char *package = 0;
  const unsigned char *item = 0;
  path_t pkgdir, pkgpath, fpath, pkgname;
  struct stat stb;

  phr->json_reply = 1;

  if (hr_cgi_param(phr, "package", &package) < 0)
    FAIL(SSERV_ERR_INV_PACKAGE);
  if (!package) package = "";
  if (!is_valid_package(pkgdir, sizeof(pkgdir), package))
    FAIL(SSERV_ERR_INV_PACKAGE);
  if (hr_cgi_param(phr, "item", &item) <= 0 || !item || !*item)
    FAIL(SSERV_ERR_INV_PACKAGE);
  if (!is_valid_dir(pkgname, sizeof(pkgname), item))
    FAIL(SSERV_ERR_INV_PACKAGE);

  snprintf(pkgpath, sizeof(pkgpath), "%s/problems/%s",
           EJUDGE_CONTESTS_HOME_DIR, pkgdir);
  if (stat(pkgpath, &stb) < 0 || !S_ISDIR(stb.st_mode))
    FAIL(SSERV_ERR_INV_PACKAGE);

  switch (phr->action) {
  case SSERV_CMD_CREATE_PACKAGE:
    snprintf(fpath, sizeof(fpath), "%s/%s", pkgpath, item);
    if (stat(fpath, &stb) >= 0)
      FAIL(SSERV_ERR_ITEM_EXISTS);
    if (mkdir(fpath, 0755) < 0)
      FAIL(SSERV_ERR_OPERATION_FAILED);
    break;
  default:
    abort();
  }

  retval = 1;

 cleanup:
  return retval;
}

int
super_serve_op_edit_problem(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  phr->json_reply = 1;
  return 1;
}
