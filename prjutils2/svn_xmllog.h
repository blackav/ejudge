/* $Id$ */

/* Copyright (C) 2006-2010 Alexander Chernov <cher@ejudge.ru> */

#ifndef __SVN_XMLLOG_H__
#define __SVN_XMLLOG_H__

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include "expat_iface.h"
#include "xalloc.h"

#include <time.h>

enum
{
  T_LOG = 1,
  T_LOGENTRY,
  T_AUTHOR,
  T_DATE,
  T_PATHS,
  T_PATH,
  T_MSG,

  T_LAST_TAG,
};

enum
{
  A_REVISION = 1,
  A_ACTION,
  A_COPYFROM_REV,
  A_COPYFROM_PATH,
  A_KIND,

  A_LAST_ATTR,
};

struct xmllog_path
{
  struct xml_tree b;
  char action;
  char *path;
  char *copyfrom_path;
  int   copyfrom_rev;
};

struct xmllog_paths
{
  int a, u;
  struct xmllog_path **v;
};

struct xmllog_date
{
  time_t t;
  int nsec;
  int year, mon, mday;
};

struct xmllog_entry
{
  struct xml_tree b;
  int good_msg;
  int revision;
  char *author;
  struct xmllog_date date;
  struct xmllog_paths paths;
  char *msg;
  strarray_t msgl;              /* message split by lines */
};

struct xmllog_entries
{
  int a, u;
  struct xmllog_entry **v;
};

struct xmllog_root
{
  struct xml_tree b;
  struct xmllog_entries e;
};

struct xmllog_root *svnlog_build_tree_file(const char *fname,
                                           FILE *f,
                                           FILE *errlog);
struct xmllog_root *svnlog_build_tree(const char *fname,
                                      FILE *errlog);

#endif /* __SVN_XMLLOG_H__ */
