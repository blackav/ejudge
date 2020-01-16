/* -*- mode: c -*- */

/* Copyright (C) 2008-2017 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/meta_generic.h"
#include "ejudge/misctext.h"
#include "ejudge/xml_utils.h"
#include "ejudge/charsets.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <stdio.h>
#include <string.h>

struct meta_automaton *
meta_build_automaton(const struct meta_info_item *item, int item_num)
{
  int i, j, cur_st, c;
  unsigned char cmap[256];
  const unsigned char *s;
  unsigned char remap[256];
  struct meta_automaton *atm = 0;

  ASSERT(item);
  ASSERT(item_num);

  //fprintf(stderr, "Building the automaton\n");
  memset(cmap, 0, sizeof(cmap));
  cmap[0] = 1;
  for (i = 0; i < item_num; ++i) {
    if (!item[i].tag) continue;
    if (!(s = (const unsigned char*) item[i].name)) continue;
    ASSERT(*s);
    for (; *s; ++s) {
      ASSERT(*s >= ' ' && *s < 127);
      cmap[*s] = 1;
    }
  }

  memset(remap, 1, sizeof(remap));
  remap[0] = 0;
  j = 2;
  for (i = ' '; i < 127; i++)
    if (cmap[i])
      remap[i] = j++;
  //fprintf(stderr, "%d characters remapped\n", j);

  XCALLOC(atm, 1);
  memcpy(atm->remap, remap, sizeof(atm->remap));
  atm->char_num = j;

  atm->st_a = 16;
  XCALLOC(atm->st, atm->st_a);
  // 0 is the "no transition" indicator
  // 1 is the initial state
  XCALLOC(atm->st[1], atm->char_num);
  atm->st_u = 2;

  for (i = 0; i < item_num; ++i) {
    if (!item[i].tag) continue;
    if (!(s = (const unsigned char*) item[i].name)) continue;
    cur_st = 1;
    for (; *s; ++s) {
      c = atm->remap[*s];
      ASSERT(c > 1);
      if (atm->st[cur_st][c] > 0) {
        cur_st = atm->st[cur_st][c];
        continue;
      }

      // create a new state
      if (atm->st_u >= atm->st_a) {
        atm->st_a *= 2;
        XREALLOC(atm->st, atm->st_a);
      }
      XCALLOC(atm->st[atm->st_u], atm->char_num);
      atm->st[cur_st][c] = atm->st_u;
      cur_st = atm->st_u++;
    }
    if (atm->st[cur_st][0] < 0) {
      //fprintf(stderr, "items %d and %d are the same\n", -atm->st[cur_st][0], i);
    }
    atm->st[cur_st][0] = -i;
  }
  //fprintf(stderr, "The automaton has %d states\n", atm->st_u);

  /*
  fprintf(stderr, "automaton:\n");
  for (i = 1; i < atm->st_u; ++i) {
    fprintf(stderr, "%d:", i);
    for (j = 0; j < atm->char_num; ++j)
      fprintf(stderr, " %d", atm->st[i][j]);
    fprintf(stderr, "\n");
  }
  */

  return atm;
}

int
meta_lookup_string(const struct meta_automaton *atm, const char *str)
{
  const unsigned char *s = (const unsigned char *) str;
  int cur_st = 1;
  int c;

  ASSERT(atm);
  ASSERT(str);

  for (; *s; ++s) {
    if ((c = atm->remap[*s]) <= 1) return 0;
    if (!(cur_st = atm->st[cur_st][c])) return 0;
  }
  return -atm->st[cur_st][0];
}

void
meta_destroy_fields(const struct meta_methods *mth, void *ptr)
{
  int field_id, ft;
  void *fp;

  for (field_id = 1; field_id < mth->last_tag; ++field_id) {
    ft = mth->get_type(field_id);
    fp = mth->get_ptr_nc(ptr, field_id);
    if (!fp) continue;
    switch (ft) {
    case '0':                   /* ej_int_opt_0_t */
    case '3':                   /* ej_checkbox_t */
    case '4':                   /* ej_int_opt_1_t */
    case '5':
      break;
    case '1':                   /* ej_textbox_t */
    case '2':                   /* ej_textbox_opt_t */
      {
        unsigned char **pp = (unsigned char **) fp;
        xfree(*pp);
      }
      break;
    case 'x':
    case 'X':
      {
        unsigned char ***ppp = (unsigned char ***) fp;
        if (*ppp) {
          for (int i = 0; (*ppp)[i]; ++i) {
            xfree((*ppp)[i]);
          }
          xfree(*ppp);
        }
      }
      break;
    case 's':
      {
        unsigned char **pp = (unsigned char **) fp;
        xfree(*pp);
      }
      break;

    case 't':                   /* time_t */
    case 'b':                   /* ejbytebool_t */
    case 'B':                   /* ejintbool_t */
    case 'f':                   /* ejbyteflag_t */
    case 'z':                   /* ejintsize_t */
    case 'i':                   /* int type */
    case 'Z':                   /* size_t */
    case 'E':                   /* ej_size64_t */
      break;

    default:
      abort();
    }
  }
  memset(ptr, 0, mth->size);
}

#define CARMOR(s) c_armor_buf(&ab, (s))

void
meta_unparse_cfg(FILE *out_f, const struct meta_methods *mth, const void *ptr, const void *default_ptr)
{
  int field_id, ft, fz;
  const void *fp, *dfp;
  const char *fn;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char buf[256];

  if (!ptr) return;

  for (field_id = 1; field_id < mth->last_tag; ++field_id) {
    ft = mth->get_type(field_id);
    fp = mth->get_ptr(ptr, field_id);
    fz = mth->get_size(field_id);
    fn = mth->get_name(field_id);
    dfp = NULL;
    if (default_ptr) dfp = mth->get_ptr(default_ptr, field_id);
    if (!fp) continue;
    switch (ft) {
    case 't':                   /* time_t */
      if (!dfp || *(const time_t *) dfp != *(const time_t *) fp) {
        fprintf(out_f, "%s = \"%s\"\n", fn, xml_unparse_date(*(const time_t*) fp));
      }
      break;
    case 'b':                   /* ejbytebool_t */
    case 'B':                   /* ejintbool_t */
    case 'f':                   /* ejbyteflag_t */
      {
        int b = 0;
        int db = 0;
        switch (fz) {
        case 1:
          b = *(const char*) fp;
          if (dfp) db = *(const char*) dfp;
          break;
        case 2:
          b = *(const short*) fp;
          if (dfp) db = *(const short*) dfp;
          break;
        case 4:
          b = *(const int*) fp;
          if (dfp) db = *(const int*) dfp;
          break;
        case 8:
          if (*(const long long*) fp > 0) b = 1;
          if (dfp && *(const long long*) dfp > 0) db = 1;
          break;
        default:
          abort();
        }
        if (dfp && b != db && b >= 0) {
          fprintf(out_f, "%s = %d\n", fn, b);
        } else if (!dfp && b > 0) {
          fprintf(out_f, "%s = %d\n", fn, b);
        }
      }
      break;
    case 'z':                   /* ejintsize_t */
      ASSERT(fz == sizeof(int));
      if (!dfp || *(const int *) dfp != *(const int*) fp) {
        num_to_size_str(buf, sizeof(buf), *(const int*) fp);
        fprintf(out_f, "%s = %s\n", fn, buf);
      }
      break;
    case 'i':                   /* int type */
      ASSERT(fz == sizeof(int));
      if (!dfp || *(const int *) dfp != *(const int*) fp) {
        snprintf(buf, sizeof(buf), "%d", *(const int*) fp);
        fprintf(out_f, "%s = %s\n", fn, buf);
      }
      break;
    case 'S':                   /* path_t */
      fprintf(out_f, "%s = \"%s\"\n", fn, CARMOR((const unsigned char*) fp));
      break;
    case 's':                   /* char * type */
      if (*(const unsigned char **) fp) {
        fprintf(out_f, "%s = \"%s\"\n", fn, CARMOR(*(const unsigned char**) fp));
      }
      break;

    case 'x':                   /* ejstrlist_t */
    case 'X':                   /* ejenvlist_t */
      {
        const unsigned char **p = *(const unsigned char ***) fp;
        if (p) {
          for (int i = 0; p[i]; ++i) {
            fprintf(out_f, "%s = \"%s\"\n", fn, CARMOR(p[i]));
          }
        }
      }
      break;
    case 'Z':                   /* size_t */
      ASSERT(fz == sizeof(size_t));
      if (!dfp || *(const size_t*) dfp != *(const size_t*) fp) {
        // special handling of -1
        if (*(const size_t*) fp == (size_t) -1UL) {
          snprintf(buf, sizeof(buf), "-1");
        } else {
          size_t_to_size_str(buf, sizeof(buf), *(const size_t*) fp);
        }
        fprintf(out_f, "%s = %s\n", fn, buf);
      }
      break;
    case 'E':
      ASSERT(fz == sizeof(ej_size64_t));
      if (!dfp || *(const ej_size64_t *) dfp != *(const ej_size64_t*) fp) {
        ll_to_size_str(buf, sizeof(buf), *(const ej_size64_t *) fp);
        fprintf(out_f, "%s = %s\n", fn, buf);
      }
      break;
    case '0':                   /* ej_int_opt_0_t */
    case '1':                   /* ej_textbox_t */
    case '2':                   /* ej_textbox_opt_t */
    case '3':                   /* ej_checkbox_t */
    case '4':                   /* ej_int_opt_1_t */
    case '5':                   /* ej_int_opt_m1_t */
    default:
      abort();
    }
  }
  html_armor_free(&ab);
}

int
meta_parse_string(
        FILE *log_f,
        int lineno,
        void *obj,
        int field_id,
        const struct meta_methods *mm,
        const unsigned char *name,
        const unsigned char *value,
        int charset_id)
{
    int ft = mm->get_type(field_id);
    void *fp = mm->get_ptr_nc(obj, field_id);
    int fz = mm->get_size(field_id);

    switch (ft) {
    case 't':                   /* time_t */
      {
        time_t v = 0;
        if (xml_parse_date(NULL, 0, 0, 0, value, &v) < 0) {
          fprintf(log_f, "%d: date parameter expected for '%s'\n", lineno, name);
          return -1;
        }
        if (v < 0) v = 0;
        *(time_t*) fp = v;
      }
      break;
    case 'b':                   /* ejbytebool_t */
    case 'B':                   /* ejintbool_t */
    case 'f':                   /* ejbyteflag_t */
      {
        int bval = 0;
        if (!strcasecmp(value, "yes") || !strcasecmp(value, "true") || !strcasecmp(value, "on")) {
          bval = 1;
        } else if (!strcasecmp(value, "no") || !strcasecmp(value, "false") || !strcasecmp(value, "off")) {
          bval = 0;
        } else {
          if (size_str_to_num(value, &bval) < 0) {
            fprintf(log_f, "%d: invalid value of numeric parameter for '%s'\n", lineno, name);
            return -1;
          }
          if (bval < 0) bval = 0;
          else if (bval > 0) bval = 1;
        }
        switch (fz) {
        case 1:
          *(char*) fp = (char) bval;
          break;
        case 2:
          *(short*) fp = (short) bval;
          break;
        case 4:
          *(int*) fp = (int) bval;
          break;
        case 8:
          *(long long*) fp = (long long) bval;
          break;
        default:
          abort();
        }
      }
      break;
    case 'E':
      {
        ej_size64_t v = 0;
        if (size_str_to_size64_t(value, &v) < 0) {
          fprintf(log_f, "%d: invalid value of size64 parameter for '%s'\n", lineno, name);
          return -1;
        }
        *(ej_size64_t*) fp = v;
      }
      break;

    case 'Z':                   /* size_t */
      {
        size_t v = 0;
        if (size_str_to_size_t(value, &v) < 0) {
          fprintf(log_f, "%d: invalid value of size parameter for '%s'\n", lineno, name);
          return -1;
        }
        *(size_t*) fp = (size_t) v;
      }
      break;

    case 'z':                   /* ejintsize_t */
    case 'i':                   /* int type */
      {
        int v = 0;
        ASSERT(fz == sizeof(int));
        if (size_str_to_num(value, &v) < 0) {
          fprintf(log_f, "%d: invalid value of numeric parameter for '%s'\n", lineno, name);
          return -1;
        }
        *(int*) fp = (int) v;
      }
      break;

    case 'S':                   /* path_t */
      {
        if (strlen(value) >= fz) {
          fprintf(log_f, "%d: parameter '%s' is too long\n", lineno, name);
          return -1;
        }
        char *ptr = (char*) fp;
        strcpy(ptr, value);
        if (charset_id > 0) {
          charset_decode_buf(charset_id, ptr, fz);
        }
      }
      break;

    case 'x':                   /* ejstrlist_t */
    case 'X':                   /* ejenvlist_t */
      {
        char ***ppptr = 0;
        char **pptr = 0;
        int    j;

        ppptr = (char***) fp;
        if (!*ppptr) {
          *ppptr = (char**) xcalloc(16, sizeof(char*));
          (*ppptr)[15] = (char*) 1;
        }
        pptr = *ppptr;
        for (j = 0; pptr[j]; j++) {
        }
        if (pptr[j + 1] == (char*) 1) {
          int newsize = (j + 2) * 2;
          char **newptr = (char**) xcalloc(newsize, sizeof(char*));
          newptr[newsize - 1] = (char*) 1;
          memcpy(newptr, pptr, j * sizeof(char*));
          xfree(pptr);
          pptr = newptr;
          *ppptr = newptr;
        }
        if (charset_id > 0) {
          pptr[j] = charset_decode_to_heap(charset_id, value);
        } else {
          pptr[j] = xstrdup(value);
        }
        pptr[j + 1] = 0;
      }
      break;

    case '0':                   /* ej_int_opt_0_t */
    case '1':                   /* ej_textbox_t */
    case '2':                   /* ej_textbox_opt_t */
    case '3':                   /* ej_checkbox_t */
    case '4':                   /* ej_int_opt_1_t */
    case '5':                   /* ej_int_opt_m1_t */
      break;

    case 's':                   /* char * type */
      {
        char **pptr = (char**) fp;
        if (*pptr) {
          xfree(*pptr); *pptr = NULL;
        }
        if (charset_id > 0) {
          *pptr = charset_decode_to_heap(charset_id, value);
        } else {
          *pptr = xstrdup(value);
        }
      }
      break;
    default:
      abort();
    }

    return 0;
}

unsigned char *
meta_get_variable_str(
        const struct meta_methods *mth,
        const void *ptr,
        const unsigned char *name)
{
  int field_id = mth->lookup_field(name);
  if (field_id <= 0) return NULL;

  int ft = mth->get_type(field_id);
  int fz = mth->get_size(field_id);
  const void *fp = mth->get_ptr(ptr, field_id);
  if (!fp) return NULL;

  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char buf[256];

  switch (ft) {
  case 't':                   /* time_t */
    return xstrdup(xml_unparse_date(*(const time_t*) fp));

  case 'b':                   /* ejbytebool_t */
  case 'B':                   /* ejintbool_t */
  case 'f':                   /* ejbyteflag_t */
    {
      int b = 0;
      switch (fz) {
      case 1:
        b = *(const char*) fp;
        break;
      case 2:
        b = *(const short*) fp;
        break;
      case 4:
        b = *(const int*) fp;
        break;
      case 8:
        if (*(const long long*) fp > 0) b = 1;
        break;
      default:
        abort();
      }
      if (b > 0) b = 1;
      if (b < 0) b = 0;
      sprintf(buf, "%d", b);
      return xstrdup(buf);
    }
  case 'z':                   /* ejintsize_t */
    ASSERT(fz == sizeof(int));
    num_to_size_str(buf, sizeof(buf), *(const int*) fp);
    return xstrdup(buf);
  case 'i':                   /* int type */
    ASSERT(fz == sizeof(int));
    snprintf(buf, sizeof(buf), "%d", *(const int*) fp);
    return xstrdup(buf);
  case 'S':                   /* path_t */
    {
      const unsigned char *sv = (const unsigned char *) fp;
      if (!sv) return NULL;
      const unsigned char *sv2 = c_armor_buf(&ab, sv);
      if (sv2 == sv) return xstrdup(sv);
      return ab.buf;
    }
  case 's':                   /* char * type */
    {
      const unsigned char *sv = *(const unsigned char **) fp;
      if (!sv) return NULL;
      const unsigned char *sv2 = c_armor_buf(&ab, sv);
      if (sv2 == sv) return xstrdup(sv);
      return ab.buf;
    }

#if 0
  case 'x':                   /* ejstrlist_t */
  case 'X':                   /* ejenvlist_t */
    {
      const unsigned char **p = *(const unsigned char ***) fp;
      if (p) {
        for (int i = 0; p[i]; ++i) {
          fprintf(out_f, "%s = \"%s\"\n", fn, CARMOR(p[i]));
        }
      }
    }
    break;
#endif

  case 'Z':                   /* size_t */
    ASSERT(fz == sizeof(size_t));
    {
      size_t vz = *(const size_t*) fp;
      if (vz == (size_t) -1UL) return xstrdup("-1");
      size_t_to_size_str(buf, sizeof(buf), vz);
      return xstrdup(buf);
    }
  case 'E':
    ASSERT(fz == sizeof(ej_size64_t));
    {
      ll_to_size_str(buf, sizeof(buf), *(const ej_size64_t *) fp);
      return xstrdup(buf);
    }
  }

  return NULL;
}
