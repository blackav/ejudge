/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2002 Alexander Chernov <cher@ispras.ru> */

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

#include "nls.h"
#include "utf8_utils.h"
#include "userlist.h"
#include "pathutl.h"

#include <reuse/logger.h>

#include <expat.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

static char const * const tag_map[] =
{
  0,
  "userlist",
  "user",
  "login",
  "descr",
  "inst",
  "instshort",
  "fac",
  "facshort",
  "member",
  "reserve",
  "coach",
  "advisor",
  "name",
  "middlename",
  "surname",
  "course",
  "group",
  "occup",
  "email",
  "phone",
  "homepage",
  "password",
  "country",
  "zip",
  "city",
  "address",

  0
};

struct tag_list
{
  struct tag_list *next;

  int itag;
  int a, u;
  unsigned char *str;
  void *tree;
};

struct parser_data
{
  int nest;
  int skipping;
  int skip_stop;
  struct tag_list *tag_stack;
  int err_cntr;

  /* actual data to be parsed */
  struct userlist_data *userlist;
};

static int
encoding_hnd(void *data, const XML_Char *name, XML_Encoding *info)
{
  int i, o;
  unsigned char cb, cu1, cu2;
  struct nls_table *tab = nls_lookup_table(name);

  if (tab) {
    for (i = 0; i < 256; i++) {
      cb = i;
      tab->char2uni(&cb, &o, &cu1, &cu2);
      info->map[i] = (cu2 << 8) | cu1;
    }
    info->data = 0;
    info->convert = 0;
    info->release = 0;
    return 1;
  }

  // unsupported encoding
  return 0;
}

static void
handle_attrib(XML_Parser p,
              struct parser_data *pd, void *tree,
              unsigned char const *name, int itag,
              unsigned char const *attrib, unsigned char const *value)
{
  switch (itag) {
  case TAG_USERLIST:
    {
      struct userlist_data *d = (struct userlist_data*) tree;

      if (!strcmp(attrib, "name")) {
        d->name = strdup(value);
      } else goto invalid_attribute;
    }
    break;
  case TAG_USER:
    {
      struct user_data *d = (struct user_data*) tree;

      if (!strcmp(attrib, "id")) {
        char *endptr;
        int val;

        errno = 0;
        val = strtol(value, &endptr, 10);
        if (errno || *endptr || val <= 0 || val > 65535) goto invalid_value;
        d->id = val;
      } else if (!strcmp(attrib, "invisible")) {
        char *endptr;
        int val;

        errno = 0;
        val = strtol(value, &endptr, 10);
        if (errno || *endptr || val < 0 || val > 1) goto invalid_value;
        d->invisible = val;
      } else if (!strcmp(attrib, "banned")) {
        char *endptr;
        int val;

        errno = 0;
        val = strtol(value, &endptr, 10);
        if (errno || *endptr || val < 0 || val > 1) goto invalid_value;
        d->banned = val;
      } else goto invalid_attribute;
    }
    break;
  case TAG_PASSWORD:
    {
      struct user_data *ud = (struct user_data*) tree;

      if (!strcmp(attrib, "method")) {
        if (!strcmp(value, "plain")) {
          ud->passwd_method = PWD_PLAIN;
        } else if (!strcmp(value, "base64")) {
          ud->passwd_method = PWD_BASE64;
        } else if (!strcmp(value, "sha1")) {
          ud->passwd_method = PWD_SHA1;
        } else goto invalid_value;
      } else goto invalid_attribute;
    }
    break;
  case TAG_LOGIN:
  case TAG_DESCR:
  case TAG_INST:
  case TAG_INSTSHORT:
  case TAG_FAC:
  case TAG_FACSHORT:
  case TAG_MEMBER:
  case TAG_RESERVE:
  case TAG_COACH:
  case TAG_ADVISOR:
  case TAG_NAME:
  case TAG_MIDDLENAME:
  case TAG_SURNAME:
  case TAG_COURSE:
  case TAG_GROUP:
  case TAG_OCCUP:
  case TAG_PHONE:
  case TAG_EMAIL:
  case TAG_HOMEPAGE:
  case TAG_COUNTRY:
  case TAG_ZIP:
  case TAG_CITY:
  case TAG_ADDRESS:
    goto invalid_attribute;
  default:
    err("%d: Unknown tag: %s", XML_GetCurrentLineNumber(p), name);
    pd->err_cntr++;
    return;
  }
  return;

 invalid_value:
  err("%d: Invalid value of attribute `%s'",
      XML_GetCurrentLineNumber(p), attrib);
  pd->err_cntr++;
  return;

 invalid_attribute:
  err("%d: Invalid attribute `%s' for tag `%s'",
      XML_GetCurrentLineNumber(p), attrib, name);
  pd->err_cntr++;
}

static void
start_hnd(void *data, const XML_Char *name, const XML_Char **atts)
{
  XML_Parser p = (XML_Parser) data;
  int cur_val_size = 0, cur_attr_size = 0, val_len, attr_len;
  char *cur_val = 0, *cur_attr = 0;
  int cur_tag_size = 0, tag_len;
  char *cur_tag = 0;
  struct parser_data *pd = (struct parser_data*) XML_GetUserData(p);
  struct tag_list *tl = 0;
  void *tree = 0;
  int itag = 0;

  /* allocate initial space for attrib and value local buffers */
  cur_attr_size = 32;
  cur_attr = (char*) alloca(cur_attr_size);
  cur_val_size = 32;
  cur_val = (char*) alloca(cur_val_size);

  /* recode tag to koi8-r */
  cur_tag_size = 32;
  tag_len = strlen(name);
  while (cur_tag_size <= tag_len) {
    cur_tag_size *= 2;
  }
  cur_tag = (char*) alloca(cur_tag_size);
  str_utf8_to_koi8(cur_tag, cur_tag_size, name);

  if (pd->skipping) {
    pd->nest++;
    return;
  }

  for (itag = 1; tag_map[itag]; itag++) {
    if (!strcmp(cur_tag, tag_map[itag]))
      break;
  }
  if (!tag_map[itag]) {
    err("%d: Unknown tag: %s, skipping",
        XML_GetCurrentLineNumber(p), cur_tag);
    pd->err_cntr++;
    goto start_skipping;
  }

  switch (itag) {
  case TAG_USERLIST:
    if (pd->tag_stack) goto invalid_usage;
    pd->userlist = calloc(1, sizeof(*pd->userlist));
    tree = pd->userlist;
    break;
  case TAG_USER:
    if (!pd->tag_stack || pd->tag_stack->itag != TAG_USERLIST)
      goto invalid_usage;
    {
      struct user_data *ud = 0;
      struct userlist_data *ld = (struct userlist_data*) pd->tag_stack->tree;

      ud = (struct user_data *) calloc(1, sizeof(*ud));
      ud->parent = ld;
      tree = ud;
      if (!ld->last) {
        ld->first = ld->last = ud;
      } else {
        ld->last->next = ud;
        ld->last = ud;
      }
    }
    break;
  case TAG_LOGIN:
  case TAG_DESCR:
  case TAG_INST:
  case TAG_INSTSHORT:
  case TAG_FAC:
  case TAG_FACSHORT:
  case TAG_PASSWORD:
  case TAG_COUNTRY:
  case TAG_ZIP:
  case TAG_CITY:
  case TAG_ADDRESS:
    if (!pd->tag_stack || pd->tag_stack->itag != TAG_USER)
      goto invalid_usage;
    {
      struct user_data *ud = (struct user_data*) pd->tag_stack->tree;
      char *s = user_data_get_field(ud, itag);
      if (s) {
        err("%d: %s can be specified only once",
            XML_GetCurrentLineNumber(p), cur_tag);
        pd->err_cntr++;
        goto start_skipping;
      }
      tree = pd->tag_stack->tree;
    }
    break;
  case TAG_MEMBER:
  case TAG_RESERVE:
  case TAG_COACH:
  case TAG_ADVISOR:
    if (!pd->tag_stack || pd->tag_stack->itag != TAG_USER)
      goto invalid_usage;
    {
      struct user_data *ud = (struct user_data*) pd->tag_stack->tree;
      struct person_list *pl = user_data_get_list_ptr(ud, itag);
      struct person_data *id = 0;

      id = (struct person_data*) calloc(1, sizeof(*id));
      id->parent = ud;
      tree = id;
      if (!pl->last) {
        pl->first = pl->last = id;
      } else {
        pl->last->next = id;
        pl->last = id;
      }
    }
    break;

  case TAG_NAME:
  case TAG_MIDDLENAME:
  case TAG_SURNAME:
  case TAG_COURSE:
  case TAG_GROUP:
  case TAG_OCCUP:
    if (!pd->tag_stack ||
        (pd->tag_stack->itag != TAG_MEMBER
         && pd->tag_stack->itag != TAG_RESERVE
         && pd->tag_stack->itag != TAG_COACH
         && pd->tag_stack->itag != TAG_ADVISOR))
      goto invalid_usage;

    {
      struct person_data *id = (struct person_data*) pd->tag_stack->tree;
      unsigned char **ps = person_data_get_ptr(id, itag);
      if (*ps) {
        err("%d: %s can be specified only once",
            XML_GetCurrentLineNumber(p), cur_tag);
        pd->err_cntr++;
        goto start_skipping;
      }
      tree = id;
    }
    break;

  case TAG_EMAIL:
  case TAG_PHONE:
  case TAG_HOMEPAGE:
    {
      struct addr_info *ai = 0;
      struct addr_data *ad = 0;
      struct addr_list *al = 0;

      if (!pd->tag_stack) goto invalid_usage;
      if (pd->tag_stack->itag == TAG_USER) {
        struct user_data *ud = (struct user_data*) pd->tag_stack->tree;
        ai = &ud->addr;
      } else if (pd->tag_stack->itag == TAG_MEMBER
                 || pd->tag_stack->itag == TAG_RESERVE
                 || pd->tag_stack->itag == TAG_COACH
                 || pd->tag_stack->itag == TAG_ADVISOR) {
        struct person_data *id = (struct person_data*) pd->tag_stack->tree;
        ai = &id->addr;
      } else goto invalid_usage;
      al = addr_get_list(ai, itag);
      ad = (struct addr_data*) calloc(1, sizeof(*ad));
      tree = ad;
      if (!al->last) {
        al->first = al->last = ad;
      } else {
        al->last->next = ad;
        al->last = ad;
      }
    }
    break;
  default:
  invalid_usage:
    err("%d: Invalid tag `%s' usage", XML_GetCurrentLineNumber(p),
        cur_tag);
    pd->err_cntr++;
    goto start_skipping;
  }

  while (*atts) {
    attr_len = strlen(atts[0]);
    val_len = strlen(atts[1]);
    if (attr_len >= cur_attr_size) {
      while (attr_len >= cur_attr_size) {
        cur_attr_size *= 2;
      }
      cur_attr = (char*) alloca(cur_attr_size);
    }
    if (val_len >= cur_val_size) {
      while (val_len >= cur_val_size) {
        cur_val_size *= 2;
      }
      cur_val = (char*) alloca(cur_val_size);
    }
    str_utf8_to_koi8(cur_attr, cur_attr_size, atts[0]);
    str_utf8_to_koi8(cur_val, cur_val_size, atts[1]);
    handle_attrib(p, pd, tree, cur_tag, itag, cur_attr, cur_val);
    atts += 2;
  }

  tl = (struct tag_list*) calloc(1, sizeof(*tl));
  tl->itag = itag;
  tl->next = pd->tag_stack;
  tl->tree = tree;
  pd->tag_stack = tl;
  pd->nest++;
  return;

 start_skipping:
  pd->skipping = 1;
  pd->nest++;
  pd->skip_stop = pd->nest;
}

static void
end_hnd(void *data, const XML_Char *name)
{
  XML_Parser p = (XML_Parser) data;
  struct parser_data *pd = (struct parser_data*) XML_GetUserData(p);
  struct tag_list *tl;

  if (pd->skipping) {
    pd->nest--;
    if (pd->nest < pd->skip_stop) {
      pd->skip_stop = 0;
      pd->skipping = 0;
    }
    return;
  }

  tl = pd->tag_stack;
  pd->tag_stack = tl->next;
  pd->nest--;

  switch (tl->itag) {
  case TAG_USERLIST:
    break;
  case TAG_USER:
    break;
  case TAG_MEMBER:
  case TAG_RESERVE:
  case TAG_COACH:
  case TAG_ADVISOR:
    break;
  case TAG_LOGIN:
  case TAG_DESCR:
  case TAG_INST:
  case TAG_INSTSHORT:
  case TAG_FAC:
  case TAG_FACSHORT:
  case TAG_PASSWORD:
  case TAG_COUNTRY:
  case TAG_ZIP:
  case TAG_CITY:
  case TAG_ADDRESS:
    {
      struct user_data *ud = (struct user_data*) tl->tree;
      unsigned char *s = 0;

      s = str_utf8_to_koi8_heap(tl->str);
      user_data_set_field(ud, tl->itag, s);
    }
    break;
  case TAG_NAME:
  case TAG_MIDDLENAME:
  case TAG_SURNAME:
  case TAG_COURSE:
  case TAG_GROUP:
  case TAG_OCCUP:
    {
      struct person_data *id = (struct person_data *) tl->tree;
      unsigned char **ps = 0;
      unsigned char *s = 0;

      ps = person_data_get_ptr(id, tl->itag);
      s = str_utf8_to_koi8_heap(tl->str);
      *ps = s;
    }
    break;
  case TAG_EMAIL:
  case TAG_PHONE:
  case TAG_HOMEPAGE:
    {
      struct addr_data *ad = (struct addr_data *) tl->tree;
      ad->addr = str_utf8_to_koi8_heap(tl->str);
    }
    break;
  default:
    err("unexpected closing tag: %s", name);
    pd->err_cntr++;
  }

  free(tl->str);
}

static void
chardata_hnd(void *data, const XML_Char *s, int len)
{
  XML_Parser p = (XML_Parser) data;
  struct parser_data *pd = (struct parser_data*) XML_GetUserData(p);

  if (!pd->tag_stack) return;
  if (pd->skipping) return;
  switch (pd->tag_stack->itag) {
  case TAG_USERLIST:
  case TAG_USER:
  case TAG_MEMBER:
  case TAG_RESERVE:
  case TAG_COACH:
  case TAG_ADVISOR:
    break;
  case TAG_LOGIN:
  case TAG_DESCR:
  case TAG_INST:
  case TAG_INSTSHORT:
  case TAG_FAC:
  case TAG_FACSHORT:
  case TAG_NAME:
  case TAG_MIDDLENAME:
  case TAG_SURNAME:
  case TAG_COURSE:
  case TAG_GROUP:
  case TAG_OCCUP:
  case TAG_EMAIL:
  case TAG_PHONE:
  case TAG_HOMEPAGE:
  case TAG_PASSWORD:
  case TAG_COUNTRY:
  case TAG_ZIP:
  case TAG_CITY:
  case TAG_ADDRESS:
    if (!pd->tag_stack->a) pd->tag_stack->a = 32;
    while (pd->tag_stack->u + len >= pd->tag_stack->a)
      pd->tag_stack->a *= 2;
    pd->tag_stack->str = (char*) realloc(pd->tag_stack->str, pd->tag_stack->a);
    memmove(pd->tag_stack->str + pd->tag_stack->u, s, len);
    pd->tag_stack->u += len;
    pd->tag_stack->str[pd->tag_stack->u] = 0;
    break;
  default:
    err("unhandled character data in %d", pd->tag_stack->itag);
    pd->err_cntr++;
    return;
  }
}

struct userlist_data *
userlist_parse(char const *path)
{
  XML_Parser p = 0;
  FILE *f = 0;
  char buf[512];
  int len;
  struct parser_data data;

  memset(&data, 0, sizeof(data));
  ASSERT(path);

  if (!(f = fopen(path, "r"))) {
    err("cannot open input file `%s'", path);
    goto cleanup_and_exit;
  }
  if (!(p = XML_ParserCreate(NULL))) {
    err("cannot create an XML parser");
    goto cleanup_and_exit;
  }

  XML_SetUnknownEncodingHandler(p, encoding_hnd, NULL);
  XML_SetStartElementHandler(p, start_hnd);
  XML_SetEndElementHandler(p, end_hnd);
  XML_SetCharacterDataHandler(p, chardata_hnd);
  XML_SetUserData(p, &data);
  XML_UseParserAsHandlerArg(p);

  while (fgets(buf, sizeof(buf), f)) {
    len = strlen(buf);
    if (XML_Parse(p, buf, len, 0) == XML_STATUS_ERROR) {
      err("%s: %d: parse error: %s",
          path, XML_GetCurrentLineNumber(p),
          XML_ErrorString(XML_GetErrorCode(p)));
      goto cleanup_and_exit;
    }
  }
  if (ferror(f)) {
    err("%s: input error", path);
    goto cleanup_and_exit;
  }
  if (data.err_cntr) goto cleanup_and_exit;

  XML_ParserFree(p);
  fclose(f);
  return data.userlist;

 cleanup_and_exit:
  if (p) XML_ParserFree(p);
  if (f) fclose(f);
  if (data.userlist) userlist_free(data.userlist);
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "XML_Parser" "XML_Char" "XML_Encoding")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
