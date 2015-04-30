/* -*- mode: c -*- */

/* Copyright (C) 2005-2015 Alexander Chernov <cher@ejudge.ru> */

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

void
html_date_select_2(
        FILE *out_f,
        time_t t,
        const unsigned char *id_prefix,
        const unsigned char *name_prefix,
        const unsigned char *html_class,
        int is_readonly,
        int is_hidden,
        int use_gmtime)
{
  struct tm *tt = NULL;
  unsigned char value_time[64];
  unsigned char value_date[64];
  const unsigned char *type = "text";

  if (is_hidden) type = "hidden";
  if (t != 0 && t != ~(time_t) 0) {
    if (use_gmtime) {
      tt = gmtime(&t);
    } else {
      tt = localtime(&t);
    }
  }
  value_time[0] = 0;
  value_date[0] = 0;
  if (tt) {
    snprintf(value_time, sizeof(value_time), "%02d:%02d:%02d",
             tt->tm_hour, tt->tm_min, tt->tm_sec);
    snprintf(value_date, sizeof(value_date), "%04d-%02d-%02d",
             tt->tm_year + 1900, tt->tm_mon + 1, tt->tm_mday);
  }
  fprintf(out_f, "<input type=\"%s\" id=\"%s_time\" name=\"%s_time\" value=\"%s\"",
          type, id_prefix, name_prefix, value_time);
  if (html_class) {
    fprintf(out_f, " class=\"%s\"", html_class);
  }
  if (is_readonly) {
    fprintf(out_f, " readonly=\"readonly\"");
  }
  fprintf(out_f, " />");

  fprintf(out_f, "<input type=\"%s\" id=\"%s_date\" name=\"%s_date\" value=\"%s\"",
          type, id_prefix, name_prefix, value_date);
  if (html_class) {
    fprintf(out_f, " class=\"%s\"", html_class);
  }
  if (is_readonly) {
    fprintf(out_f, " readonly=\"readonly\"");
  }
  fprintf(out_f, " />");
}
