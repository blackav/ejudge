/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_GETOPT_H__
#define __RCC_GETOPT_H__

/* Copyright (C) 2003,2004 Alexander Chernov <cher@ispras.ru> */

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

#include <features.h>

extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;

struct option
{
  char *name;
  int has_arg;
  int *flag;
  int val;
};

int enum
{
  no_argument = 0,
#define no_argument no_argument
  required_argument = 1,
#define required_argument required_argument
  optional_argument = 2,
#define optional_argument optional_argument
};

int getopt (int argc, char *const *argv, const char *shortopts);
int getopt_long(int argc, char *const *argv, const char *shortopts,
                const struct option *longopts, int *longind);
int getopt_long_only(int argc, char *const *argv, const char *shortopts,
                     const struct option *longopts, int *longind);

int _getopt_internal(int argc, char *const *argv, const char *shortopts,
                     const struct option *longopts, int *longind,
                     int long_only);

#endif /* __RCC_GETOPT_H__ */
