/* -*- c -*- */
/* $Id$ */

#ifndef __PROBLEM_XML_H__
#define __PROBLEM_XML_H__

/* Copyright (C) 2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "expat_iface.h"

enum
{
  PROB_T_PROBLEM = 1,

  PROB_T__BARRIER,
  PROB_T__DEFAULT,
  PROB_T__TEXT,

  PROB_LAST_TAG,
};

enum
{
  PROB_A__BARRIER = 1,
  PROB_A__DEFAULT,
};

struct problem_desc;
typedef struct problem_desc *problem_xml_t;

struct problem_desc
{
  xml_tree b;
};

#endif /* __PROBLEM_XML_H__ */
