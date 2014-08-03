/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/html.h"

static const unsigned char * const months_names[] =
{
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

void
html_date_select(FILE *f, time_t t)
{
  int i;

  if (t <= 0) {
    fprintf(f, "Time: <input type=\"text\" name=\"d_hour\" value=\"\" size=\"2\" maxlength=\"2\"/>:<input type=\"text\" name=\"d_min\" value=\"\" size=\"2\" maxlength=\"2\"/>:<input type=\"text\" name=\"d_sec\" value=\"\" size=\"2\" maxlength=\"2\"/>");
    fprintf(f, "Date: <select name=\"d_mday\">");
    for (i = 1; i <= 31; i++) {
      fprintf(f, "<option value=\"%d\">%02d</option>", i, i);
    }
    fprintf(f, "</select>");
    fprintf(f, "/<select name=\"d_mon\">");
    for (i = 0; i < 12; i++) {
      fprintf(f, "<option value=\"%d\">%s</option>", i + 1, months_names[i]);
    }
    fprintf(f, "</select>");
    fprintf(f, "/<input type=\"text\" name=\"d_year\" value=\"\" size=\"4\" maxlength=\"4\"/>");
    fprintf(f, "<i>(Not set)</i>");
  } else {
    struct tm *tt = localtime(&t);

    fprintf(f, "Time: <input type=\"text\" name=\"d_hour\" value=\"%02d\" size=\"2\" maxlength=\"2\"/>:<input type=\"text\" name=\"d_min\" value=\"%02d\" size=\"2\" maxlength=\"2\"/>:<input type=\"text\" name=\"d_sec\" value=\"%02d\" size=\"2\" maxlength=\"2\"/>",
            tt->tm_hour, tt->tm_min, tt->tm_sec);
    fprintf(f, "Date: <select name=\"d_mday\">");
    for (i = 1; i <= 31; i++) {
      fprintf(f, "<option value=\"%d\"%s>%02d</option>",
              i, (i == tt->tm_mday)?" selected=\"1\"":"", i);
    }
    fprintf(f, "</select>");
    fprintf(f, "/<select name=\"d_mon\">");
    for (i = 0; i < 12; i++) {
      fprintf(f, "<option value=\"%d\"%s>%s</option>",
              i + 1, (i == tt->tm_mon)?" selected=\"1\"":"", months_names[i]);
    }
    fprintf(f, "</select>");
    fprintf(f, "/<input type=\"text\" name=\"d_year\" value=\"%d\" size=\"4\" maxlength=\"4\"/>", tt->tm_year + 1900);
  }
}
