/* $Id$ */

/* Copyright (C) 2006-2010 Alexander Chernov <cher@ejudge.ru> */

/*
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 */

#include "svn_xmllog.h"
#include "xalloc.h"

#include <stdarg.h>
#include <ctype.h>
#include <string.h>

static char const * const elem_map[] =
{
  0,
  "log",
  "logentry",
  "author",
  "date",
  "paths",
  "path",
  "msg",

  0,
};
static char const * const attr_map[] =
{
  0,
  "revision",
  "action",
  "copyfrom-rev",
  "copyfrom-path",
  "kind",

  0,
};

static size_t elem_sizes[] =
{
  0,
  [T_LOG] = sizeof(struct xmllog_root),
  [T_LOGENTRY] = sizeof(struct xmllog_entry),
  [T_AUTHOR] = 0,
  [T_DATE] = 0,
  [T_PATHS] = 0,
  [T_PATH] = sizeof(struct xmllog_path),
  [T_MSG] = 0,
};

static void *
elem_alloc(int tag)
{
  size_t sz;
  if (!(sz = elem_sizes[tag])) sz = sizeof(struct xml_tree);
  return xcalloc(1, sz);
}

static void *
attr_alloc(int tag)
{
  return xcalloc(1, sizeof(struct xml_attn));
}


static const char *xml_file_name;

static void *
elem_err(struct xml_tree *node, char const *format, ...)
{
  va_list args;
  char buf[512];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  if (xml_file_name)
    fprintf(stderr, "%s:%d:%d:%s\n", xml_file_name,
            node->line, node->column, buf);
  else
    fprintf(stderr, "%d:%d:%s\n", node->line, node->column, buf);
  return 0;
}

static void *
attr_err(struct xml_attn *node, char const *format, ...)
{
  va_list args;
  char buf[512];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  if (xml_file_name)
    fprintf(stderr, "%s:%d:%d:%s\n", xml_file_name,
            node->line, node->column, buf);
  else
    fprintf(stderr, "%d:%d:%s\n", node->line, node->column, buf);
  return 0;
}

static void *
is_empty_text(struct xml_tree *node)
{
  const unsigned char *s;

  if (!node) return node;
  if (!node->text) return node;
  s = (const unsigned char*) node->text;
  while (*s && isspace(*s)) s++;
  if (*s)
    return elem_err(node, "text is not allowed inside <%s>",
                    elem_map[node->tag]);
  xfree(node->text); node->text = 0;
  return node;
}

static void *
parse_date(struct xml_tree *node, const char *str, struct xmllog_date *pd)
{
  struct tm ntm;
  int year, mon, day, hour, min, sec, nsec, n;
  time_t ntt;

  if (sscanf(str, "%d-%d-%dT%d:%d:%d.%dZ%n",
             &year, &mon, &day, &hour, &min, &sec, &nsec, &n) != 7
      || str[n]) return elem_err(node, "cannot parse date specification");
  if (year < 1970 || year > 2100 || mon < 1 || mon > 12
      || day < 1 || day > 31 || hour < 0 || hour > 23
      || min < 0 || min > 59 || sec < 0 || sec > 61
      || nsec < 0 || nsec > 999999)
    return elem_err(node, "invalid date specification");

  memset(&ntm, 0, sizeof(ntm));
  ntm.tm_year = year - 1900;
  ntm.tm_mon = mon - 1;
  ntm.tm_mday = day;
  ntm.tm_hour = hour;
  ntm.tm_min = min;
  ntm.tm_sec = sec;
  ntt = timegm(&ntm);
  pd->year = year;
  pd->mon = mon;
  pd->mday = day;
  pd->nsec = nsec;
  pd->t = ntt;
  return node;
}
static void *
parse_paths(struct xml_tree *node, struct xmllog_entry *pe)
{
  struct xml_tree *p;
  struct xmllog_path *pp;
  struct xml_attn *a;
  int x, n;

  if (!node) return NULL;
  if (node->tag != T_PATHS) abort();

  if (node->first) return elem_err(node, "attributes are not allowed");
  if (!is_empty_text(node)) return 0;

  for (p = node->first_down; p; p = p->right) {
    if (p->tag != T_PATH) return elem_err(p, "unexpected element");
    pp = (struct xmllog_path*) p;
    for (a = p->first; a; a = a->next) {
      switch (a->tag) {
      case A_ACTION:
        if (!a->text || strlen(a->text) != 1)
          return attr_err(a, "invalid attribute value");
        switch (a->text[0]) {
        case 'D': case 'A': case 'M':
          break;
        default:
          return attr_err(a, "invalid attribute value");
        }
        pp->action = a->text[0];
        break;
      case A_COPYFROM_PATH:
        pp->copyfrom_path = a->text; a->text = 0;
        break;
      case A_COPYFROM_REV:
        if (sscanf(a->text, "%d%n", &x, &n) != 1 || a->text[n])
          return attr_err(a, "invalid attribute value");
        if (x < 1) return attr_err(a, "invalid attribute value");
        pp->copyfrom_rev = x;
        break;
      case A_KIND:
        break;
      default:
        return attr_err(a, "unexpected attribute");
      }
    }
    if (!pp->action) elem_err(p, "action attribute expected");
    pp->path = p->text; p->text = 0;
    XEXPAND2(pe->paths);
    pe->paths.v[pe->paths.u] = pp;
    pe->paths.u++;
  }
  return node;
}

static struct xmllog_entry *
parse_logentry(struct xml_tree *node)
{
  struct xmllog_entry *pe = (struct xmllog_entry*) node;
  struct xml_attn *pa;
  struct xml_tree *p;
  int v, n;

  if (!is_empty_text(node)) return 0;
  pe->revision = -1;
  for (pa = pe->b.first; pa; pa = pa->next) {
    if (pa->tag == A_REVISION) {
      if (sscanf(pa->text, "%d%n", &v, &n) != 1 || pa->text[n])
        return attr_err(pa, "cannot parse attribute value");
      if (v < 0)
        return attr_err(pa, "invalid attribute value");
      pe->revision = v;
    } else {
      return attr_err(pa, "unexpected attribute");
    }
  }
  if (pe->revision < 0)
    return elem_err(node, "attribute revision is undefined");

  for (p = pe->b.first_down; p; p = p->right) {
    switch (p->tag) {
    case T_AUTHOR:
      if (p->first) return elem_err(p, "attributes are not allowed");
      if (p->first_down)
        return elem_err(p, "nested elements are not allowed");
      if (pe->author) return elem_err(p, "author already defined");
      pe->author = p->text;
      p->text = 0;
      break;
    case T_DATE:
      if (p->first) return elem_err(p, "attributes are not allowed");
      if (p->first_down)
        return elem_err(p, "nested elements are not allowed");
      if (pe->date.year) return elem_err(p, "date already defined");
      if (parse_date(p, p->text, &pe->date) < 0) return 0;
      break;
    case T_PATHS:
      if (!parse_paths(p, pe)) return 0;
      break;
    case T_MSG:
      if (p->first) return elem_err(p, "attributes are not allowed");
      if (p->first_down)
        return elem_err(p, "nested elements are not allowed");
      if (pe->msg) return elem_err(p, "msg already defined");
      pe->msg = p->text;
      p->text = 0;
      break;
    default:
      return elem_err(p, "unexpected element");
    }
  }
  if (!pe->author) return elem_err(node, "author is not defined");

  return pe;
}

static struct xmllog_root *
parse_xmllog(struct xml_tree *root)
{
  struct xmllog_root *xmlroot;
  struct xml_tree *p;
  struct xmllog_entry *xmle;

  if (root->tag != T_LOG)
    return elem_err(root, "<log> element expected");
  if (!is_empty_text(root)) return 0;
  if (root->first) elem_err(root, "attributes not allowed for <log>");
  xmlroot = (struct xmllog_root*) root;

  for (p = root->first_down; p; p = p->right) {
    if (p->tag != T_LOGENTRY)
      return elem_err(p, "<logentry> element expected");
    if (!(xmle = parse_logentry(p))) return 0;
    XEXPAND2(xmlroot->e);
    xmlroot->e.v[xmlroot->e.u++] = xmle;
  }
  return xmlroot;
}

struct xmllog_root*
svnlog_build_tree_file(const char *fname, FILE *f, FILE *errlog)
{
  struct xml_tree *root;

  xml_file_name = fname;
  root = xml_build_tree_file(f, elem_map, attr_map,
                             elem_alloc, attr_alloc, stderr);
  if (!root) return NULL;
  return parse_xmllog(root);
}

struct xmllog_root*
svnlog_build_tree(const char *fname, FILE *errlog)
{
  struct xml_tree *root;

  xml_file_name = fname;
  root = xml_build_tree(fname, elem_map, attr_map, elem_alloc, attr_alloc,
                        stderr);
  if (!root) return NULL;
  return parse_xmllog(root);
}
