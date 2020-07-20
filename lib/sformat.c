/* -*- mode: c -*- */

/* Copyright (C) 2001-2019 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/sformat.h"
#include "ejudge/prepare.h"
#include "ejudge/teamdb.h"
#include "ejudge/userlist.h"
#include "ejudge/misctext.h"
#include "ejudge/win32_compat.h"

#include "ejudge/xalloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

#define ARMOR(s)  html_armor_buf(&ab, (s))

/**
 * Valid format conversions as follows:
 *  G - global data
 *   Gr - contest root directory
 *  P - problem data
 *   Pi - problem id
 *   Ps - problem short name
 *   Pl - problem long name
 *   PS - problem standings name
 *   PL - problem internal name
 *  L - language data
 *   Li - id
 *   Ln - short name
 *   Ll - long name
 *   La - arch
 *   Ls - src_sfx
 *   Le - exe_sfx
 *   Lm - multi_header_suffix / short_name
 *  T - tester data
 *  M - team data
 *   Mi - team id
 *   Mn - team name
 *   Ml - team login
 *   Mc - city
 *   MC - city_en
 *   Mo - country
 *   MO - country_en
 *   Mr - region
 *   Mt - inst_short
 *   MT - inst_short_en
 *   Mu - inst
 *   MU - inst_en
 *   Mf - fac_short
 *   MF - fac_short_en
 *   Md - fac
 *   MD - fac_en
 *   ML - location
 *   Mp - printer_name
 *   My - exam_id
 *   MY - exam_cypher
 *  U - userinfo data
 *   Ui - user id
 *   Un - user name
 *   Ue - email
 *   Ul - login
 *   Uz - password (in plain text)
 *   UZ - team password (in plain text)
 *   Uc - city
 *   UC - city_en
 *   Uo - country
 *   UO - country_en
 *   Ur - region
 *   Ut - inst_short
 *   UT - inst_short_en
 *   Uu - inst
 *   UU - inst_en
 *   Uf - fac_short
 *   UF - fac_short_en
 *   Ud - fac
 *   UD - fac_en
 *   UL - location
 *   Up - printer_name
 *   Uy - exam_id
 *   UY - exam_cypher
 *   Uh - homepage
 *   UH - phones
 *   UP - languages
 *   UMp - participant
 *   UMr - reserve
 *   UMa - advisor
 *   UMc - coach
 *   UMg - guest
 *     f - firstname
 *     F - firstname_en
 *     m - middlename
 *     M - middlename_en
 *     s - surname
 *     S - surname_en
 *     g - group
 *     G - group_en
 *     e - email
 *     h - homepage
 *     o - occupation
 *     O - occupation_en
 *     u - inst
 *     U - inst_en
 *     t - inst_short
 *     T - inst_short_en
 *     d - fac
 *     D - fac_en
 *     a - facshort
 *     A - facshort_en
 *     H - phone
 *     b - status
 *     B - status_en
 *     c - grade
 *     C - number
 *     0 - field0
 *     9 - field9
 *  C - contest data
 *   Cn - name
 *   CN - name_en
 *  V - variable data
 *   VS - SID
 *   Vl - locale_id
 *   Vu - url
 *   V1 - str1
 *   Vn - server_name
 *   VN - server_name_en
 *   Vv - variant
 */

int
sformat_message(
        char *buf,
        size_t maxsize,
        int html_escape_flag,
        char const *format,
        const struct section_global_data *glob_data,
        const struct section_problem_data *prob_data,
        const struct section_language_data *lang_data,
        const struct section_tester_data *tester_data,
        const struct teamdb_export *team_data,
        const struct userlist_user *user_data,
        const struct contest_desc *cnts_data,
        const struct sformat_extra_data *extra_data)
{
  char const *pf = format;
  char const *specstart = 0;
  char *out = buf;
  char *mptr = 0;
  char *tmptr = 0;
  const char *papp;
  int   lapp, capp;
  size_t left = maxsize;
  size_t allocd = 0;
  size_t used = 0;
  char   tbuf[128];

  int nbsp_if_empty = 0;        /* e */
  int do_uppercase = 0;         /* u */
  int do_lowercase = 0;         /* l */
  int right_align = 0;          /* r */
  int center_align = 0;         /* c */
  int put_zeros = 0;            /* 0 */
  int width = -1;
  int prec = -1;
  int need_int_format = 0;
  int need_ullongx_format = 0;
  int int_format_value = 0;
  unsigned long long ullong_format_value = 0;
  int is_invalid = 0;
  int locale_dependant = 0;

  char   *sbuf = (char*) alloca(16);
  char   *psbuf;
  size_t  sbufsize = 16;
  const struct userlist_user_info *ui = 0;
  const struct userlist_user_info *tui = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (user_data) {
    if (cnts_data) {
      ui = userlist_get_user_info(user_data, cnts_data->id);
    }
    if (!ui) ui = user_data->cnts0;
  }

  if (team_data && team_data->user) tui = team_data->user->cnts0;

  if (maxsize == (size_t) -1) {
    mptr = (char*) xcalloc(16, 1);
    allocd = 16;
    out = mptr;
  }

  while (*pf) {
    papp = 0;
    nbsp_if_empty = 0;        /* e */
    do_uppercase = 0;         /* u */
    do_lowercase = 0;         /* l */
    right_align = 0;          /* r */
    center_align = 0;         /* c */
    put_zeros = 0;            /* 0 */
    width = -1;
    prec = -1;
    need_int_format = 0;
    need_ullongx_format = 0;
    int_format_value = 0;
    ullong_format_value = 0;
    is_invalid = 0;
    locale_dependant = 0;

    if (*pf != '%') {
      tbuf[0] = *pf;
      tbuf[1] = 0;
      papp = tbuf;
      pf++;
    } else if (*pf == '%' && pf[1] == '%') {
      tbuf[0] = *pf;
      tbuf[1] = 0;
      papp = tbuf;
      pf += 2;
    } else {
      specstart = pf;
      pf++;
      /* read flags */
      while (*pf) {
        switch (*pf) {
        case 'e':
          nbsp_if_empty = 1;
          break;
        case 'u':
          do_uppercase = 1;
          do_lowercase = 0;
          break;
        case 'l':
          do_lowercase = 1;
          do_uppercase = 0;
          break;
        case 'r':
          right_align = 1;
          put_zeros = 0;
          center_align = 0;
          break;
        case 'c':
          center_align = 1;
          right_align = 0;
          put_zeros = 0;
          break;
        case 'a':
          locale_dependant = 1;
          break;
        case '0':
          put_zeros = 1;
          right_align = 1;
          center_align = 0;
          break;
        default:
          goto read_flags_done;
        }
        pf++;
      }
    read_flags_done:
      /* read width, if applicable */
      if (*pf >= '0' && *pf <= '9') {
        errno = 0;
        width = strtol(pf, (char**) &pf, 10);
        if (errno == ERANGE) {
          width = -1;
          is_invalid = 1;
        }
      }
      /* read precision, if applicable */
      if (*pf == '.') {
        pf++;
        if (*pf >= '0' || *pf <= '9') {
          errno = 0;
          prec = strtol(pf, (char**) &pf, 10);
          if (errno == ERANGE) {
            prec = -1;
            is_invalid = 1;
          }
        } else {
          is_invalid = 1;
        }
      }
      /* read specification */
      switch (*pf) {
      case 'G':
        /*
         * Gr - contest root directory
         */
        pf++;
        switch (*pf) {
        case 'r':
          break;
        case 0:
          is_invalid = 1;
          break;
        default:
          is_invalid = 1;
          pf++;
          break;
        }
        if (!is_invalid && !glob_data) is_invalid = 1;
        if (!is_invalid) {
          switch (*pf) {
          case 'r':
            papp = glob_data->root_dir;
            break;
          default:
            abort();
          }
          pf++;
        }
        break;
      case 'P':
        /*
         * Pi - problem identifier
         * Ps - problem short name
         * Pl - problem long name
         * PS - problem standings name
         * PL - problem internal name
         */
        pf++;
        switch (*pf) {
        case 'i': case 's': case 'l': case 'S': case 'L':
          break;
        case 0:
          is_invalid = 1;
          break;
        default:
          is_invalid = 1;
          pf++;
          break;
        }
        if (!is_invalid && !prob_data) is_invalid = 1;
        if (!is_invalid) {
          switch (*pf) {
          case 'i':
            need_int_format = 1;
            int_format_value = prob_data->id;
            break;
          case 's':
            papp = prob_data->short_name;
            break;
          case 'l':
            papp = prob_data->long_name;
            break;
          case 'S':
            papp = prob_data->stand_name;
            break;
          case 'L':
            papp = prob_data->internal_name;
            break;
          default:
            abort();
          }
          pf++;
        }
        break;
        /*
         * Li - id
         * Ln - short name
         * Ll - long name
         * La - arch
         * Ls - src_sfx
         * Le - exe_sfx
         * Lm - multi_header_suffix / short_name
         */
      case 'L':
        pf++;
        switch (*pf) {
        case 'i': case 'n': case 'l': case 'a': case 's': case 'e': case 'm':
          break;
        case 0:
          is_invalid = 1;
          break;
        default:
          is_invalid = 1;
          pf++;
          break;
        }
        if (!is_invalid && !lang_data) is_invalid = 1;
        if (!is_invalid) {
          switch (*pf) {
          case 'i':
            need_int_format = 1;
            int_format_value = 0;
            if (lang_data) int_format_value = lang_data->id;
            break;
          case 'n':
            papp = "";
            if (lang_data) papp = lang_data->short_name;
            break;
          case 'l':
            papp = "";
            if (lang_data) papp = lang_data->long_name;
            break;
          case 'a':
            papp = "";
            if (lang_data) papp = lang_data->arch;
            break;
          case 's':
            papp = "";
            if (lang_data) papp = lang_data->src_sfx;
            break;
          case 'e':
            papp = "";
            if (lang_data) papp = lang_data->exe_sfx;
            break;
          case 'm':
            papp = "";
            if (lang_data && lang_data->multi_header_suffix && lang_data->multi_header_suffix[0]) {
              papp = lang_data->multi_header_suffix;
            } else if (lang_data) {
              papp = lang_data->short_name;
            }
          default:
            abort();
          }
          pf++;
        }
        break;
      case 'T':
        /*
         * Ti - tester identifier
         * Tn - tester name
         * Tj - reference problem identifier
         * Tp - reference problem short name
         * Ta - architecture
         * Tk - key
         */
        pf++;
        switch (*pf) {
        case 'i': case 'n': case 'j':
        case 'p': case 'a': case 'k':
          break;
        case 0:
          is_invalid = 1;
          break;
        default:
          is_invalid = 1;
          pf++;
          break;
        }
        if (!is_invalid && !tester_data) is_invalid = 1;
        if (!is_invalid) {
          switch (*pf) {
          case 'i':
            need_int_format = 1;
            int_format_value = tester_data->id;
            break;
          case 'n':
            papp = tester_data->name;
            break;
          case 'j':
            need_int_format = 1;
            int_format_value = tester_data->problem;
            break;
          case 'p':
            papp = tester_data->problem_name;
            break;
          case 'a':
            papp = tester_data->arch;
            break;
          case 'k':
            papp = tester_data->key;
            break;
          default:
            abort();
          }
          pf++;
        }
        break;
      case 'M':
        /*
         *   Mi - team id
         *   Mn - team name
         *   Ml - team login
         *   Mc - city
         *   MC - city_en
         *   Mo - country
         *   MO - country_en
         *   Mr - region
         *   Mt - inst_short
         *   MT - inst_short_en
         *   Mu - inst
         *   MU - inst_en
         *   Mf - fac_short
         *   MF - fac_short_en
         *   Md - fac
         *   MD - fac_en
         *   ML - location
         *   Mp - printer_name
         *   Uy - exam_id
         *   UY - exam_cypher
         *   M1 - extra1
         */
        pf++;

        switch (*pf) {
        case 'i': case 'n': case 'l':
        case 'c': case 'C':
        case 't': case 'T':
        case 'u': case 'U':
        case 'o': case 'O': case 'L': case 'p': case 'r':
        case 'f': case 'F': case 'd': case 'D': case 'y': case 'Y':
        case '1':
          break;
        case 0:
          is_invalid = 1;
          break;
        default:
          is_invalid = 1;
          pf++;
          break;
        }
        if (!is_invalid && !team_data) is_invalid = 1;
        if (!is_invalid) {
          switch (*pf) {
          case 'i':
            need_int_format = 1;
            int_format_value = team_data->id;
            break;
          case 'n':
            papp = team_data->name;
            break;
          case 'l':
            papp = team_data->login;
            break;
          case 'c':
            papp = "";
            if (tui && tui->city) papp = tui->city;
            break;
          case 'C':
            papp = "";
            if (tui && tui->city_en) papp = tui->city_en;
            break;
          case 'o':
            papp = "";
            if (tui && tui->country) papp = tui->country;
            break;
          case 'O':
            papp = "";
            if (tui && tui->country_en) papp = tui->country_en;
            break;
          case 'r':
            papp = "";
            if (tui && tui->region) papp = tui->region;
            break;
          case 't':
            papp = "";
            if (tui && tui->instshort) papp = tui->instshort;
            break;
          case 'T':
            papp = "";
            if (tui && tui->instshort_en) papp = tui->instshort_en;
            break;
          case 'u':
            papp = "";
            if (tui && tui->inst) papp = tui->inst;
            break;
          case 'U':
            papp = "";
            if (tui && tui->inst_en) papp = tui->inst_en;
            break;
          case 'f':
            papp = "";
            if (tui && tui->facshort) papp = tui->facshort;
            break;
          case 'F':
            papp = "";
            if (tui && tui->facshort_en) papp = tui->facshort_en;
            break;
          case 'd':
            papp = "";
            if (tui && tui->fac) papp = tui->fac;
            break;
          case 'D':
            papp = "";
            if (tui && tui->fac_en) papp = tui->fac_en;
            break;
          case 'L':
            papp = "";
            if (tui && tui->location) papp = tui->location;
            break;
          case 'p':
            papp = "";
            if (tui && tui->printer_name) papp = tui->printer_name;
            break;
          case 'y':
            papp = "";
            if (tui && tui->exam_id) papp = tui->exam_id;
            break;
          case 'Y':
            papp = "";
            if (tui && tui->exam_cypher) papp = tui->exam_cypher;
            break;
          case '1':
            papp = "";
            if (team_data->user && team_data->user->extra1)
              papp = team_data->user->extra1;
            break;
          default:
            abort();
          }
          if (html_escape_flag && papp) papp = ARMOR(papp);
          pf++;
        }
        break;
      case 'U':
        /*
         *   Ui - user id
         *   Un - user name
         *   Ul - login
         *   Ue - email
         *   Uz - password (in plain text)
         *   UZ - team password (in plain text)
         *   UM - information about team members (see below)
         *   Uc - city
         *   UC - city_en
         *   Uo - country
         *   UO - country_en
         *   Ur - region
         *   Ut - inst_short
         *   UT - inst_short_en
         *   Uu - inst
         *   UU - inst_en
         *   Uf - fac_short
         *   UF - fac_short_en
         *   Ud - fac
         *   UD - fac_en
         *   UL - location
         *   Up - printer_name
         *   Uy - exam_id
         *   UY - exam_cypher
         *   Uh - homepage
         *   UH - phones
         *   UP - languages
         *   U0 - field0
         *   U9 - field9
         */
        pf++;

        if (*pf == 'M') {
          const struct userlist_member *pp = 0;
          int idx = -1, n, nmemb;
          /*
           * UMp - participant
           * UMr - reserve
           * UMa - advisor
           * UMc - coach
           * UMg - guest
           */
          pf++;
          switch (*pf) {
          case 'p': idx = USERLIST_MB_CONTESTANT; break;
          case 'r': idx = USERLIST_MB_RESERVE; break;
          case 'a': idx = USERLIST_MB_ADVISOR; break;
          case 'c': idx = USERLIST_MB_COACH; break;
          case 'g': idx = USERLIST_MB_GUEST; break;
          default:
            is_invalid = 1;
            break;
          }
          if (is_invalid) break;
          pf++;
          if (*pf >= '0' && *pf <= '9') {
            if (sscanf(pf, "%d%n", &nmemb, &n) != 1) {
              is_invalid = 1;
              break;
            }
            nmemb--;
            pf += n;
          } else {
            nmemb = 0;
          }
          /*
           * f - firstname
           * F - firstname_en
           * m - middlename
           * M - middlename_en
           * s - surname
           * S - surname_en
           * g - group
           * G - group_en
           * e - email
           * h - homepage
           * o - occupation
           * O - occupation_en
           * u - inst
           * U - inst_en
           * t - inst_short
           * T - inst_short_en
           * d - fac
           * D - fac_en
           * a - facshort
           * A - facshort_en
           * H - phone
           * b - status
           * B - status_en
           * c - grade
           * C - number
           */
          switch (*pf) {
          case 'f': case 'F': case 'm': case 'M': case 's': case 'S':
          case 'g': case 'G': case 'e': case 'h': case 'H':
          case 'o': case 'O': case 'u': case 'U': case 't': case 'T':
          case 'd': case 'D': case 'a': case 'A': case 'b': case 'B':
          case 'c': case 'C':
            break;
          default:
            is_invalid = 1;
            break;
          }
          if (is_invalid) break;
          pf++;

          if (!user_data || !ui
              || !(pp = userlist_members_get_nth(ui->members, idx, nmemb))) {
            papp = "";
            break;
          }

          switch (pf[-1]) {
          case 'f': papp = pp->firstname; break;
          case 'F': papp = pp->firstname_en; break;
          case 'm': papp = pp->middlename; break;
          case 'M': papp = pp->middlename_en; break;
          case 's': papp = pp->surname; break;
          case 'S': papp = pp->surname_en; break;
          case 'g': papp = pp->group; break;
          case 'G': papp = pp->group_en; break;
          case 'e': papp = pp->email; break;
          case 'h': papp = pp->homepage; break;
          case 'H': papp = pp->phone; break;
          case 'o': papp = pp->occupation; break;
          case 'O': papp = pp->occupation_en; break;
          case 'u': papp = pp->inst; break;
          case 'U': papp = pp->inst_en; break;
          case 't': papp = pp->instshort; break;
          case 'T': papp = pp->instshort_en; break;
          case 'd': papp = pp->fac; break;
          case 'D': papp = pp->fac_en; break;
          case 'a': papp = pp->facshort; break;
          case 'A': papp = pp->facshort_en; break;
          case 'b': /* FIXME: implement */ break;
          case 'B': /* FIXME: implement */ break;
          case 'c':
            need_int_format = 1;
            int_format_value = pp->grade;
            break;
          case 'C':
            need_int_format = 1;
            int_format_value = nmemb;
            break;
          default:
            abort();
          }
          if (!need_int_format && !papp) papp = "";
          if (html_escape_flag && papp) papp = ARMOR(papp);
          break;
        }

        switch (*pf) {
        case 'i': case 'n': case 'l': case 'e':
        case 'z': case 'Z':
        case 'c': case 'C': case 'o': case 'O': case 't': case 'T':
        case 'u': case 'U': case 'f': case 'F': case 'd': case 'D':
        case 'L': case 'p': case 'h': case 'H': case 'P': case 'r':
        case 'y': case 'Y':
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
          break;
        case 0:
          is_invalid = 1;
          break;
        default:
          is_invalid = 1;
          pf++;
          break;
        }
        if (!user_data) is_invalid = 1;
        if (is_invalid) break;
        switch (*pf) {
        case 'i':
          need_int_format = 1;
          int_format_value = user_data->id;
          break;
        case 'n':
          if (ui) papp = ui->name;
          if (!papp) papp = "";
          break;
        case 'l':
          papp = user_data->login;
          if (!papp) papp = "";
          break;
        case 'e':
          papp = user_data->email;
          if (!papp) papp = "";
          break;
        case 'z':
          papp = user_data->passwd;
          if (!papp) papp = "";
          break;
        case 'Z':
          if (ui) papp = ui->team_passwd;
          if (!papp) papp = "";
          break;
        case 'c': if (ui) papp = ui->city; break;
        case 'C': if (ui) papp = ui->city_en; break;
        case 'o': if (ui) papp = ui->country; break;
        case 'O': if (ui) papp = ui->country_en; break;
        case 'r': if (ui) papp = ui->region; break;
        case 't': if (ui) papp = ui->instshort; break;
        case 'T': if (ui) papp = ui->instshort_en; break;
        case 'u': if (ui) papp = ui->inst; break;
        case 'U': if (ui) papp = ui->inst_en; break;
        case 'f': if (ui) papp = ui->facshort; break;
        case 'F': if (ui) papp = ui->facshort_en; break;
        case 'd': if (ui) papp = ui->fac; break;
        case 'D': if (ui) papp = ui->fac_en; break;
        case 'L': if (ui) papp = ui->location; break;
        case 'p': if (ui) papp = ui->printer_name; break;
        case 'y': if (ui) papp = ui->exam_id; break;
        case 'Y': if (ui) papp = ui->exam_cypher; break;
        case 'h': if (ui) papp = ui->homepage; break;
        case 'H': if (ui) papp = ui->phone; break;
        case 'P': if (ui) papp = ui->languages; break;
        case '0': if (ui) papp = ui->field0; break;
        case '1': if (ui) papp = ui->field1; break;
        case '2': if (ui) papp = ui->field2; break;
        case '3': if (ui) papp = ui->field3; break;
        case '4': if (ui) papp = ui->field4; break;
        case '5': if (ui) papp = ui->field5; break;
        case '6': if (ui) papp = ui->field6; break;
        case '7': if (ui) papp = ui->field7; break;
        case '8': if (ui) papp = ui->field8; break;
        case '9': if (ui) papp = ui->field9; break;
        default:
          abort();
        }
        pf++;
        if (!int_format_value && !papp) papp = "";
        if (html_escape_flag && papp) papp = ARMOR(papp);
        break;
      case 'C':
        pf++;
        switch (*pf) {
        case 'n': case 'N':
          break;
        case 0:
          is_invalid = 1;
          break;
        default:
          is_invalid = 1;
          pf++;
          break;
        }
        if (!is_invalid && !cnts_data) is_invalid = 1;
        if (!is_invalid) {
          switch (*pf) {
          case 'n':
            if (!locale_dependant) {
              papp = cnts_data->name;
              break;
            }
          case 'N':
            if (!locale_dependant) {
              papp = cnts_data->name_en;
              break;
            }
            papp = 0;
            if (extra_data && !extra_data->locale_id) papp = cnts_data->name_en;
            if (!papp) papp = cnts_data->name;
            break;
          default:
            abort();
          }
          pf++;
        }
        break;
      case 'V':
        /*
         *   Vl - locale_id
         *   VS - sid
         *   Vu - url
         *   V1 - str1
         *   Vn - server_name
         *   VN - server_name_en
         *   Vv - variant
         */
        pf++;
        switch (*pf) {
        case 'l':
        case 'u':
        case '1':
        case 'n': case 'N':
        case 'S':
        case 'v':
          break;
        case 0:
          is_invalid = 1;
          break;
        default:
          is_invalid = 1;
          pf++;
          break;
        }
        if (!is_invalid && !extra_data) is_invalid = 1;
        if (!is_invalid) {
          switch (*pf) {
          case 'l':
            need_int_format = 1;
            int_format_value = extra_data->locale_id;
            break;
          case 'v':
            need_int_format = 1;
            int_format_value = extra_data->variant;
            break;
          case 'S':
            need_ullongx_format = 1;
            ullong_format_value = extra_data->sid;
            break;
          case 'u':
            papp = extra_data->url;
            if (!papp) papp = "";
            break;
          case '1':
            papp = extra_data->str1;
            if (!papp) papp = "";
            break;
          case 'n':
            if (!locale_dependant) {
              papp = extra_data->server_name;
              if (!papp) papp = "";
              break;
            }
          case 'N':
            if (!locale_dependant) {
              papp = extra_data->server_name_en;
              if (!papp) papp = "";
              break;
            }
            papp = 0;
            if (extra_data && !extra_data->locale_id)
              papp = extra_data->server_name_en;
            if (!papp) papp = extra_data->server_name;
            if (!papp) papp = "";
            break;
          default:
            abort();
          }
          pf++;
        }
        break;
      case 0:
        is_invalid = 1;
        break;
      default:
        is_invalid = 1;
        pf++;
        break;
      }
    }

    if (is_invalid) {
      // FIXME: need reasonable behavour
      snprintf(tbuf, sizeof(tbuf), "<invalid:%.*s>", (int) (pf-specstart), specstart);
      papp = tbuf;
    }

    if (!is_invalid && need_int_format) {
      // FIXME: ugly hack
      if (width > 100) width = 100;
      if (width >= 0 && put_zeros) {
        snprintf(tbuf, sizeof(tbuf), "%0*d", width, int_format_value);
      } else {
        snprintf(tbuf, sizeof(tbuf), "%d", int_format_value);
      }
      papp = tbuf;
    }

    if (!is_invalid && need_ullongx_format) {
      // FIXME: ugly hack
      if (width > 100) width = 100;
      if (width >= 0 && put_zeros) {
        snprintf(tbuf, sizeof(tbuf), "%0*" EJ_PRINTF_LLSPEC "x", width, ullong_format_value);
      } else {
        snprintf(tbuf, sizeof(tbuf), "%" EJ_PRINTF_LLSPEC "x", ullong_format_value);
      }
      papp = tbuf;
    }

    if (nbsp_if_empty && (!papp || !*papp))
      papp = "&nbsp;";

    lapp = 0;
    if (papp)
      lapp = strlen(papp);

    if (width >= 0 || prec >= 0) {
      // width is the minimal width
      // prec is the maximal width
      if (prec == -1 || prec > lapp) {
        prec = lapp;
      }
      if (width == -1 || width < prec) {
        width = prec;
      }
      while (width >= sbufsize)
        sbufsize *= 2;
      sbuf = (char*) alloca(sbufsize);
      memset(sbuf, ' ', width);
      sbuf[width] = 0;
      if (center_align) {
        capp = (width - prec) / 2;
        if (prec > 0)
          memcpy(sbuf + capp, papp, prec);
      } else if (right_align) {
        if (prec > 0)
          memcpy(sbuf + width - prec, papp, prec);
      } else {
        if (prec > 0)
          memcpy(sbuf, papp, prec);
      }
      papp = sbuf;
    }
    if (do_uppercase && papp) {
      if (papp != sbuf) {
        lapp = strlen(papp) + 1;
        while (lapp > sbufsize)
          sbufsize *= 2;
        sbuf = (char*) alloca(sbufsize);
        strcpy(sbuf, papp);
        papp = sbuf;
      }
      // may assume, that papp is writable
      for (psbuf = sbuf; *psbuf; psbuf++)
        if (isalpha(*psbuf))
          *psbuf = toupper(*psbuf);
    }
    if (do_lowercase && papp) {
      if (papp != sbuf) {
        lapp = strlen(papp) + 1;
        while (lapp > sbufsize)
          sbufsize *= 2;
        sbuf = (char*) alloca(sbufsize);
        strcpy(sbuf, papp);
        papp = sbuf;
      }
      for (psbuf = sbuf; *psbuf; psbuf++)
        if (isalpha(*psbuf))
          *psbuf = tolower(*psbuf);
    }

    if (papp) {
      lapp = strlen(papp);
      if (maxsize == (size_t) -1 && lapp > 0) {
        while (used + lapp > allocd)
          allocd *= 2;
        tmptr = xrealloc(mptr, allocd);
        out = tmptr + (out - mptr);
        mptr = tmptr;
        memcpy(out, papp, lapp);
        out += lapp;
        used += lapp;
      } else if (maxsize == 0) {
        used += lapp;
      } else {
        if (left > 1) {
          capp = lapp;
          if (capp > left - 1) capp = left - 1;
          if (capp > 0) memcpy(out, papp, capp);
          out += capp;
          left -= capp;
        }
        used += lapp;
      }
    }
  }

  if (maxsize == (size_t) -1) {
    if (used == allocd) {
      allocd *= 2;
      mptr = (char*) xrealloc(mptr, allocd);
    }
    mptr[used] = 0;
    *(char **) buf = mptr;
  } else if (maxsize != 0) {
    *out = 0;
  }
  html_armor_free(&ab);
  return used;
}

int
sformat_message_2(
        unsigned char **pstr,
        int html_escape_flag,
        char const *format,
        const struct section_global_data *glob_data,
        const struct section_problem_data *prob_data,
        const struct section_language_data *lang_data,
        const struct section_tester_data *tester_data,
        const struct teamdb_export *team_data,
        const struct userlist_user *user_data,
        const struct contest_desc *cnts_data,
        const struct sformat_extra_data *extra_data)
{
  unsigned char tmp_buf[PATH_MAX];
  int ret = sformat_message(tmp_buf, sizeof(tmp_buf), html_escape_flag, format,
                            glob_data, prob_data, lang_data, tester_data,
                            team_data, user_data, cnts_data, extra_data);
  xstrdup3(pstr, tmp_buf);
  return ret;
}
