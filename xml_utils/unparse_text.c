/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2004 Alexander Chernov <cher@ispras.ru> */

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

#include "xml_utils.h"
#include "misctext.h"

#include <stdlib.h>

void
xml_unparse_text(FILE *f, const unsigned char *tag_name,
                 unsigned char const *val,
                 unsigned char const *ind)
{
  size_t alen = 0;
  unsigned char *astr;

  if (!val) return;
  if (html_armor_needed(val, &alen)) {
    astr = alloca(alen + 2);
    html_armor_string(val, astr);
    val = astr;
  }
  fprintf(f, "%s<%s>%s</%s>\n", ind, tag_name, val, tag_name);
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
