/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2001,2002 Alexander Chernov <cher@ispras.ru> */

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

#include "sformat.h"
#include "prepare.h"
#include "teamdb.h"

#include <reuse/xalloc.h>
#include <reuse/number_io.h>
#include <reuse/format_io.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

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
 *   Mp - team password (plain text)
 *   Ms - team password (scrambled)
 */

int
sformat_message(char *buf, size_t maxsize, char const *format,
                struct section_global_data *glob_data,
                struct section_problem_data *prob_data,
                struct section_language_data *lang_data,
                struct section_tester_data *tester_data,
                struct teamdb_export *team_data)
{
  char const *pf = format;
  char const *specstart = 0;
  char *out = buf;
  char *mptr = 0;
  char *tmptr = 0;
  char *papp;
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

  char   *sbuf = (char*) alloca(16);
  char   *psbuf;
  size_t  sbufsize = 16;

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

    if (*pf != '%') {
      tbuf[0] = *pf;
      tbuf[1] = 0;
      papp = tbuf;
      pf++;
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
         *   Mp - team password (plain text)
         *   Ms - team password (scrambled)
         */
        pf++;
        switch (*pf) {
        case 'i': case 'n': case 'l': case 'p': case 's':
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
          case 'p':
            papp = team_data->passwd;
            break;
          case 's':
            papp = team_data->scrambled;
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
      os_snprintf(tbuf, sizeof(tbuf), "<invalid:%.*s>", pf-specstart, specstart);
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

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 *  enable-multibute-characters: nil
 * End:
 */
