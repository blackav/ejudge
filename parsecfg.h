/* -*- c -*- */
/* $Id$ */
#ifndef __PARSECFG_H__
#define __PARSECFG_H__

/* Copyright (C) 2000 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

struct generic_section_config
{
  struct generic_section_config *next;
  char                           name[32];
  int                            data[0];
};

struct config_parse_info
{
  char          *name;
  char          *type;
  unsigned long  offset;
  unsigned long  size;
};

struct config_section_info
{
  char                     *name;
  unsigned long             size;
  struct config_parse_info *info;
  int                      *pcounter;
};

struct generic_section_config *parse_param(char const *path,
                                           void *f, /* actually, FILE * */
                                           struct config_section_info *,
                                           int quiet_flag);

#endif /* __PARSECFG_H__ */
