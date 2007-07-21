/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2001-2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "sformat.h"
#include "prepare.h"
#include "teamdb.h"
#include "userlist.h"

#include <reuse/xalloc.h>
#include <reuse/number_io.h>
#include <reuse/format_io.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

#if defined __GNUC__ && defined __MINGW32__
#include <malloc.h>
#endif

/**
 * Valid format conversions as follows:
 *  G - global data
 *  P - problem data
 *   Pi - problem id
 *   Ps - problem short name
 *  L - language data
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
 *  C - contest data
 *   Cn - name
 *   CN - name_en
 *  V - variable data
 *   Vl - locale_id
 *   Vu - url
 *   V1 - str1
 *   Vn - server_name
 *   VN - server_name_en
 */

int
sformat_message(char *buf, size_t maxsize, char const *format,
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
  int int_format_value = 0;
  int is_invalid = 0;
  int locale_dependant = 0;

  char   *sbuf = (char*) alloca(16);
  char   *psbuf;
  size_t  sbufsize = 16;
  const struct userlist_user_info *ui = 0;

  if (user_data) {
    if (cnts_data && cnts_data->id > 0
        && cnts_data->id < user_data->cntsinfo_a
        && user_data->cntsinfo[cnts_data->id]) {
      ui = &user_data->cntsinfo[cnts_data->id]->i;
    } else {
      ui = &user_data->i;
    }
  }

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
    int_format_value = 0;
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
        case 'L':
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
        pf++;
        switch (*pf) {
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
         */
        pf++;
        switch (*pf) {
        case 'i': case 's': case 'l':
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
          default:
            abort();
          }
          pf++;
        }
        break;
      case 'L':
        pf++;
        switch (*pf) {
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
            if (team_data->user && team_data->user->i.city)
              papp = team_data->user->i.city;
            break;
          case 'C':
            papp = "";
            if (team_data->user && team_data->user->i.city_en)
              papp = team_data->user->i.city_en;
            break;
          case 'o':
            papp = "";
            if (team_data->user && team_data->user->i.country)
              papp = team_data->user->i.country;
            break;
          case 'O':
            papp = "";
            if (team_data->user && team_data->user->i.country_en)
              papp = team_data->user->i.country_en;
            break;
          case 'r':
            papp = "";
            if (team_data->user && team_data->user->i.region)
              papp = team_data->user->i.region;
            break;
          case 't':
            papp = "";
            if (team_data->user && team_data->user->i.instshort)
              papp = team_data->user->i.instshort;
            break;
          case 'T':
            papp = "";
            if (team_data->user && team_data->user->i.instshort_en)
              papp = team_data->user->i.instshort_en;
            break;
          case 'u':
            papp = "";
            if (team_data->user && team_data->user->i.inst)
              papp = team_data->user->i.inst;
            break;
          case 'U':
            papp = "";
            if (team_data->user && team_data->user->i.inst_en)
              papp = team_data->user->i.inst_en;
            break;
          case 'f':
            papp = "";
            if (team_data->user && team_data->user->i.facshort)
              papp = team_data->user->i.facshort;
            break;
          case 'F':
            papp = "";
            if (team_data->user && team_data->user->i.facshort_en)
              papp = team_data->user->i.facshort_en;
            break;
          case 'd':
            papp = "";
            if (team_data->user && team_data->user->i.fac)
              papp = team_data->user->i.fac;
            break;
          case 'D':
            papp = "";
            if (team_data->user && team_data->user->i.fac_en)
              papp = team_data->user->i.fac_en;
            break;
          case 'L':
            papp = "";
            if (team_data->user && team_data->user->i.location)
              papp = team_data->user->i.location;
            break;
          case 'p':
            papp = "";
            if (team_data->user && team_data->user->i.printer_name)
              papp = team_data->user->i.printer_name;
            break;
          case 'y':
            papp = "";
            if (team_data->user && team_data->user->i.exam_id)
              papp = team_data->user->i.exam_id;
            break;
          case 'Y':
            papp = "";
            if (team_data->user && team_data->user->i.exam_cypher)
              papp = team_data->user->i.exam_cypher;
            break;
          case '1':
            papp = "";
            if (team_data->user && team_data->user->extra1)
              papp = team_data->user->extra1;
            break;
          default:
            abort();
          }
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
         */
        pf++;

        if (*pf == 'M') {
          struct userlist_members *pm = 0;
          struct userlist_member *pp = 0;
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
          if (sscanf(pf, "%d%n", &nmemb, &n) != 1) {
            is_invalid = 1;
            break;
          }
          nmemb--;
          pf += n;
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
            break;
          default:
            is_invalid = 1;
            break;
          }
          if (is_invalid) break;
          pf++;

          if (!user_data || !(pm = ui->members[idx])) {
            papp = "";
            break;
          }
          if (nmemb < 0 || nmemb >= pm->total || !(pp = pm->members[nmemb])) {
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
          break;
        }

        switch (*pf) {
        case 'i': case 'n': case 'l': case 'e':
        case 'z': case 'Z':
        case 'c': case 'C': case 'o': case 'O': case 't': case 'T':
        case 'u': case 'U': case 'f': case 'F': case 'd': case 'D':
        case 'L': case 'p': case 'h': case 'H': case 'P': case 'r':
        case 'y': case 'Y':
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
          papp = ui->name;
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
          papp = ui->team_passwd;
          if (!papp) papp = "";
          break;
        case 'c': papp = ui->city; break;
        case 'C': papp = ui->city_en; break;
        case 'o': papp = ui->country; break;
        case 'O': papp = ui->country_en; break;
        case 'r': papp = ui->region; break;
        case 't': papp = ui->instshort; break;
        case 'T': papp = ui->instshort_en; break;
        case 'u': papp = ui->inst; break;
        case 'U': papp = ui->inst_en; break;
        case 'f': papp = ui->facshort; break;
        case 'F': papp = ui->facshort_en; break;
        case 'd': papp = ui->fac; break;
        case 'D': papp = ui->fac_en; break;
        case 'L': papp = ui->location; break;
        case 'p': papp = ui->printer_name; break;
        case 'y': papp = ui->exam_id; break;
        case 'Y': papp = ui->exam_cypher; break;
        case 'h': papp = ui->homepage; break;
        case 'H': papp = ui->phone; break;
        case 'P': papp = ui->languages; break;
        default:
          abort();
        }
        pf++;
        if (!int_format_value && !papp) papp = "";
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
         *   Vu - url
         *   V1 - str1
         *   Vn - server_name
         *   VN - server_name_en
         */
        pf++;
        switch (*pf) {
        case 'l':
        case 'u':
        case '1':
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
        if (!is_invalid && !extra_data) is_invalid = 1;
        if (!is_invalid) {
          switch (*pf) {
          case 'l':
            need_int_format = 1;
            int_format_value = extra_data->locale_id;
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
      os_snprintf(tbuf, sizeof(tbuf), "<invalid:%.*s>", (int) (pf-specstart), specstart);
      papp = tbuf;
    }

    if (!is_invalid && need_int_format) {
      // FIXME: ugly hack
      if (width > 100) width = 100;
      if (width >= 0 && put_zeros) {
        os_snprintf(tbuf, sizeof(tbuf), "%0*d", width, int_format_value);
      } else {
        os_snprintf(tbuf, sizeof(tbuf), "%d", int_format_value);
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
  return used;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
