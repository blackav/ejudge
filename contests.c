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

#include "contests.h"
#include "pathutl.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <string.h>

#define MAX_CONTEST_ID 1000

static char const * const tag_map[] =
{
  0,
  "contests",
  "contest",
  "access",
  "ip",
  "field",
  "name",
  "contestants",
  "reserves",
  "coaches",
  "advisors",
  "guests",

  0
};
static char const * const attn_map[] =
{
  0,
  "id",
  "default",
  "allow",
  "deny",
  "mandatory",
  "optional",
  "min",
  "max",
  "autoregister",

  0
};
static size_t const tag_sizes[CONTEST_LAST_TAG] =
{
  0,
  sizeof(struct contest_list),  /* CONTEST_CONTESTS */
  sizeof(struct contest_desc),  /* CONTEST_CONTEST */
  sizeof(struct contest_access), /* CONTEST_ACCESS */
  sizeof(struct contest_ip),    /* CONTEST_IP */
  sizeof(struct contest_field), /* CONTEST_FIELD */
  0,                            /* CONTEST_NAME */
  sizeof(struct contest_member), /* CONTEST_CONTESTANTS */
  sizeof(struct contest_member), /* CONTEST_RESERVES */
  sizeof(struct contest_member), /* CONTEST_COACHES */
  sizeof(struct contest_member), /* CONTEST_ADVISORS */
  sizeof(struct contest_member), /* CONTEST_GUESTS */
};
static size_t const attn_sizes[CONTEST_LAST_ATTN] =
{
  0,
  sizeof(struct xml_attn),
};

static void *
node_alloc(int tag)
{
  size_t sz;
  ASSERT(tag >= 1 && tag < CONTEST_LAST_TAG);
  if (!(sz = tag_sizes[tag])) sz = sizeof(struct xml_tree);
  return xcalloc(1, sz);
}
static void *
attn_alloc(int tag)
{
  size_t sz;

  ASSERT(tag >= 1 && tag < CONTEST_LAST_ATTN);
  if (!(sz = attn_sizes[tag])) sz = sizeof(struct xml_attn);
  return xcalloc(1, sz);
}
static void
node_free(struct xml_tree *t)
{
  switch (t->tag) {
  case CONTEST_CONTESTS:
    xfree(((struct contest_list *) t)->id_map);
    break;
  }
}
static void
attn_free(struct xml_attn *a)
{
}

static char const * const field_map[] =
{
  0,
  "homepage",
  "inst",
  "instshort",
  "fac",
  "facshort",

  0
};

static char const * const member_field_map[] =
{
  0,
  "firstname",
  "middlename",
  "surname",
  "status",
  "grade",
  "group",
  "email",
  "homepage",
  "inst",
  "instshort",
  "fac",
  "facshort",
  "occupation",

  0,
};

static int
parse_bool(char const *str)
{
  if (!str) return -1;
  if (!strcasecmp(str, "true")
      || !strcasecmp(str, "yes")
      || !strcasecmp(str, "1")) return 1;
  if (!strcasecmp(str, "false")
      || !strcasecmp(str, "no")
      || !strcasecmp(str, "0")) return 0;
  return -1;
}

static int
parse_access(struct contest_access *acc, char const *path)
{
  struct xml_attn *a;
  struct xml_tree *t;
  struct contest_ip *ip;
  int n;
  unsigned int b1, b2, b3, b4;

  for (a = acc->b.first; a; a = a->next) {
    switch (a->tag) {
    case CONTEST_A_DEFAULT:
      if (!strcasecmp(a->text, "allow")) {
        acc->default_is_allow = 1;
      } else if (!strcasecmp(a->text, "deny")) {
        acc->default_is_allow = 0;
      } else {
        err("%s:%d:%d: invalid value for attribute", path, a->line, a->column);
        return -1;
      }
      break;
    default:
      err("%s:%d:%d: attribute \"%s\" is invalid here",
          path, a->line, a->column, attn_map[a->tag]);
      return -1;
    }
  }

  for (t = acc->b.first_down; t; t = t->right) {
    if (t->tag != CONTEST_IP) {
      err("%s:%d:%d: tag <%s> is invalid here",
          path, t->line, t->column, tag_map[t->tag]);
      return -1;
    }
    if (t->first_down) {
      err("%s:%d:%d: nested tags are not allowed", path, t->line, t->column);
      return -1;
    }

    ip = (struct contest_ip*) t;
    ip->allow = -1;
    for (a = ip->b.first; a; a = a->next) {
      if (a->tag != CONTEST_A_ALLOW && a->tag != CONTEST_A_DENY) {
        err("%s:%d:%d: attribute \"%s\" is invalid here",
            path, a->line, a->column, attn_map[a->tag]);
        return -1;
      }
      if (ip->allow != -1) {
        err("%s:%d:%d: attribute \"allow\" already defined",
            path, a->line, a->column);
        return -1;
      }
      if ((ip->allow = parse_bool(a->text)) < 0) {
        err("%s:%d:%d invalid boolean value",
            path, a->line, a->column);
        return -1;
      }
      if (a->tag == CONTEST_A_DENY) ip->allow = !ip->allow;
    }
    if (ip->allow == -1) ip->allow = 0;

    n = 0;
    if (sscanf(ip->b.text, "%u.%u.%u.%u %n", &b1, &b2, &b3, &b4, &n) == 4
        && !ip->b.text[n]
        && b1 <= 255 && b2 <= 255 && b3 <= 255 && b4 <= 255) {
      ip->addr = b1 << 24 | b2 << 16 | b3 << 8 | b4;
      ip->mask = 0xFFFFFFFF;
    } else if (sscanf(ip->b.text, "%u.%u.%u. %n", &b1, &b2, &b3, &n) == 3
               && !ip->b.text[n] && b1 <= 255 && b2 <= 255 && b3 <= 255) {
      ip->addr = b1 << 24 | b2 << 16 | b3 << 8;
      ip->mask = 0xFFFFFF00;
    } else if (sscanf(ip->b.text, "%u.%u. %n", &b1, &b2, &n) == 2
               && !ip->b.text[n] && b1 <= 255 && b2 <= 255) {
      ip->addr = b1 << 24 | b2 << 16;
      ip->mask = 0xFFFF0000;
    } else if (sscanf(ip->b.text, "%u. %n", &b1, &n) == 1
               && !ip->b.text[n] && b1 <= 255) {
      ip->addr = b1 << 24;
      ip->mask = 0xFF000000;
    } else {
      err("%s:%d:%d: invalid IP-address", path, ip->b.line, ip->b.column);
      return -1;
    }
  }

  xfree(acc->b.text); acc->b.text = 0;
  return 0;
}

static int
parse_member(struct contest_member *mb, char const *path)
{
  struct xml_attn *a;
  struct xml_tree *t;
  struct contest_field *pf;
  int i, n;

  mb->min_count = -1;
  mb->max_count = -1;
  for (a = mb->b.first; a; a = a->next) {
    switch (a->tag) {
    case CONTEST_A_MIN:
    case CONTEST_A_MAX:
      if (!a->text || sscanf(a->text, "%d %n", &i, &n) != 1
          || a->text[n] || i < 0 || i > 100) {
        err("%s:%d:%d: invalid value", path, a->line, a->column);
        return -1;
      }
      if (a->tag == CONTEST_A_MIN) {
        mb->min_count = i;
      } else {
        mb->max_count = i;
      }
      break;
    default:
      err("%s:%d:%d: attribute \"%s\" is invalid here",
          path, a->line, a->column, attn_map[a->tag]);
      return -1;
    }
  }

  xfree(mb->b.text); mb->b.text = 0;
  for (t = mb->b.first_down; t; t = t->right) {
    if (t->tag != CONTEST_FIELD) {
      err("%s:%d:%d: tag <%s> is invalid here",
          path, t->line, t->column, tag_map[t->tag]);
      return -1;
    }
    if (t->text && *t->text) {
      err("%s:%d:%d: tag <%s> cannot contain text",
          path, t->line, t->column, tag_map[t->tag]);
      return -1;
    }
    if (t->first_down) {
      err("%s:%d:%d: nested tags are not allowed",
          path, t->line, t->column);
      return -1;
    }
    pf = (struct contest_field*) t;

    pf->mandatory = -1;
    for (a = t->first; a; a = a->next) {
      switch (a->tag) {
      case CONTEST_A_ID:
        for (i = 1; i < CONTEST_LAST_MEMBER_FIELD; i++) {
          if (!member_field_map[i]) continue;
          if (!strcmp(a->text, member_field_map[i])) break;
        }
        if (i >= CONTEST_LAST_MEMBER_FIELD) {
          err("%s:%d:%d: invalid field id \"%s\"",
              path, a->line, a->column, a->text);
          return -1;
        }
        if (mb->fields[i]) {
          err("%s:%d:%d: field \"%s\" already defined",
              path, a->line, a->column, a->text);
          return -1;
        }
        mb->fields[i] = pf;
        break;
      case CONTEST_A_MANDATORY:
      case CONTEST_A_OPTIONAL:
        if (pf->mandatory != -1) {
          err("%s:%d:%d: attribute \"mandatory\" already defined",
              path, a->line, a->column);
          return -1;
        }
        if ((pf->mandatory = parse_bool(a->text)) < 0) {
          err("%s:%d:%d: invalid boolean value",
              path, a->line, a->column);
          return -1;
        }
        if (a->tag == CONTEST_A_OPTIONAL) pf->mandatory = !pf->mandatory;
        break;
      default:
        err("%s:%d:%d: attribute \"%s\" is invalid here",
            path, a->line, a->column, attn_map[a->tag]);
        return -1;
      }
    }
    if (pf->mandatory == -1) pf->mandatory = 0;
  }
  return 0;
}

static int
parse_contest(struct contest_desc *cnts, char const *path)
{
  struct xml_attn *a;
  struct xml_tree *t;
  int x, n, mb_id;

  for (a = cnts->b.first; a; a = a->next) {
    switch (a->tag) {
    case CONTEST_A_ID:
      x = n = 0;
      if (sscanf(a->text, "%d %n", &x, &n) != 1 || a->text[n]
          || x <= 0 || x > MAX_CONTEST_ID) {
        err("%s:%d:%d: attribute value is invalid", path, a->line, a->column);
        return -1;
      }
      cnts->id = x;
      break;
    case CONTEST_A_AUTOREGISTER:
      x = parse_bool(a->text);
      if (x < 0 || x > 1) {
        err("%s:%d:%d: attribute value is invalid", path, a->line, a->column);
        return -1;
      }
      cnts->autoregister = x;
      break;
    default:
      err("%s:%d:%d: attribute \"%s\" is invalid here",
          path, a->line, a->column, attn_map[a->tag]);
      return -1;
    }
  }

  if (!cnts->id) {
    err("%s:%d:%d: contest id is not defined",
        path, cnts->b.line, cnts->b.column);
    return -1;
  }

  for (t = cnts->b.first_down; t; t = t->right) {
    switch(t->tag) {
    case CONTEST_NAME:
      if (t->first_down) {
        err("%s:%d:%d: nested tags are not allowed",
            path, t->line, t->column);
        return -1;
      }
      if (cnts->name) {
        err("%s:%d:%d: contest name is already defined",
            path, t->line, t->column);
        return -1;
      }
      if (!t->text || !*t->text) {
        err("%s:%d:%d: contest name is empty",
            path, t->line, t->column);
        return -1;
      }
      cnts->name = t->text;
      break;
    case CONTEST_CONTESTANTS:
      mb_id = CONTEST_M_CONTESTANT;
      goto process_members;
    case CONTEST_RESERVES:
      mb_id = CONTEST_M_RESERVE;
      goto process_members;
    case CONTEST_COACHES:
      mb_id = CONTEST_M_COACH;
      goto process_members;
    case CONTEST_ADVISORS:
      mb_id = CONTEST_M_ADVISOR;
      goto process_members;
    case CONTEST_GUESTS:
      mb_id = CONTEST_M_GUEST;

    process_members:
      if (cnts->members[mb_id]) {
        err("%s:%d:%d: tag <%s> redefined",
            path, t->line, t->column, tag_map[t->tag]);
        return -1;
      }
      if (parse_member((struct contest_member*) t, path) < 0)
        return -1;
      cnts->members[mb_id] = (struct contest_member*) t;
      break;

    case CONTEST_ACCESS:
      if (cnts->access) {
        err("%s:%d:%d: contest access is already defined",
            path, t->line, t->column);
        return -1;
      }
      cnts->access = (struct contest_access*) t;
      if (parse_access(cnts->access, path) < 0) return -1;
      break;
    case CONTEST_FIELD:
      if (t->first_down) {
        err("%s:%d:%d: nested tags are not allowed", path, t->line, t->column);
        return -1;
      }
      if (t->text && t->text[0]) {
        err("%s:%d:%d: <field> tag cannot contain text",
            path, t->line, t->column);
        return -1;
      }
      xfree(t->text);
      t->text = 0;
      {
        struct contest_field *pf = (struct contest_field*) t;
        int i;

        pf->mandatory = -1;
        for (a = t->first; a; a = a->next) {
          switch (a->tag) {
          case CONTEST_A_ID:
            for (i = 1; i < CONTEST_LAST_FIELD; i++) {
              if (!field_map[i]) continue;
              if (!strcmp(a->text, field_map[i])) break;
            }
            if (i >= CONTEST_LAST_FIELD) {
              err("%s:%d:%d: invalid field id \"%s\"",
                  path, a->line, a->column, a->text);
              return -1;
            }
            if (cnts->fields[i]) {
              err("%s:%d:%d: field \"%s\" already defined",
                  path, a->line, a->column, a->text);
              return -1;
            }
            cnts->fields[i] = pf;
            break;
          case CONTEST_A_MANDATORY:
          case CONTEST_A_OPTIONAL:
            if (pf->mandatory != -1) {
              err("%s:%d:%d: attribute \"mandatory\" already defined",
                  path, a->line, a->column);
              return -1;
            }
            if ((pf->mandatory = parse_bool(a->text)) < 0) {
              err("%s:%d:%d: invalid boolean value",
                  path, a->line, a->column);
              return -1;
            }
            if (a->tag == CONTEST_A_OPTIONAL) pf->mandatory = !pf->mandatory;
            break;
          default:
            err("%s:%d:%d: attribute \"%s\" is invalid here",
                path, a->line, a->column, attn_map[a->tag]);
            return -1;
          }
        }
        if (pf->mandatory == -1) pf->mandatory = 0;
      }
      break;

    default:
      err("%s:%d:%d: tag <%s> is invalid here",
          path, t->line, t->column, tag_map[t->tag]);
      return -1;
    }
  }
  xfree(cnts->b.text); cnts->b.text = 0;

  if (!cnts->name) {
    err("%s:%d:%d: contest name is not defined",
        path, cnts->b.line, cnts->b.column);
    return -1;
  }

  return 0;
}

struct contest_list *
parse_contest_xml(char const *path)
{
  struct xml_tree *tree = 0, *t;
  struct contest_list *lst = 0;
  struct xml_attn *a;
  struct contest_desc *d = 0;
  int max_id;

  tree = xml_build_tree(path, tag_map, attn_map, node_alloc, attn_alloc);
  if (!tree) goto failed;
  if (tree->tag != CONTEST_CONTESTS) {
    err("%s:%d:%d: top-level tag must be <contests>",
        path, tree->line, tree->column);
    goto failed;
  }
  lst = (struct contest_list *) tree;

  if (tree->first) {
    err("%s:%d:%d: attribute \"%s\" is invalid here",
        path, a->line, a->column, attn_map[a->tag]);
    goto failed;
  }

  for (t = tree->first_down; t; t = t->right) {
    if (t->tag != CONTEST_CONTEST) {
      err("%s:%d:%d: tag <%s> is invalid here",
          path, t->line, t->column, tag_map[t->tag]);
      goto failed;
    }
    d = (struct contest_desc *) t;
    if (parse_contest(d, path) < 0) goto failed;
  }
  xfree(tree->text); tree->text = 0;

  max_id = -1;
  for (t = tree->first_down; t; t = t->right) {
    ASSERT(t->tag == CONTEST_CONTEST);
    d = (struct contest_desc *) t;
    ASSERT(d->id >= 1 && d->id <= MAX_CONTEST_ID);
    if (d->id > max_id) max_id = d->id;
  }
  if (max_id == -1) {
    err("%s: no contests defined", path);
    goto failed;
  }
  lst->id_map_size = max_id + 1;
  XCALLOC(lst->id_map, lst->id_map_size);
  for (t = tree->first_down; t; t = t->right) {
    d = (struct contest_desc *) t;
    if (lst->id_map[d->id]) {
      err("%s:%d:%d: duplicated contest id", path, t->line, t->column);
      goto failed;
    }
    lst->id_map[d->id] = d;
  }

  return lst;

 failed:
  if (tree) xml_tree_free(tree, node_free, attn_free);
  return 0;
}

int
contests_check_ip(struct contest_desc *d, unsigned long ip)
{
  struct contest_ip *p;

  if (!d->access) return 0;
  if (!ip && d->access->default_is_allow) return 1;
  if (!ip) return 0;

  for (p = (struct contest_ip*) d->access->b.first_down;
       p; p = (struct contest_ip*) p->b.right) {
    if ((ip & p->mask) == p->addr) return p->allow;
  }
  return d->access->default_is_allow;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
