/* -*- mode: c -*- */
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

#include "userlist_cfg.h"
#include "expat_iface.h"
#include "pathutl.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <stdio.h>

enum
  {
    TG_CONFIG = 1,
    TG_FILE,
    TG_SOCKET,
  };

static char const * const tag_map[] =
{
  0,
  "config",
  "file",
  "socket",

  0
};

static void *
tree_alloc_func(int tag)
{
  switch (tag) {
  case TG_CONFIG:
    return xcalloc(1, sizeof(struct userlist_cfg));
  case TG_SOCKET:
  case TG_FILE:
    return xcalloc(1, sizeof(struct xml_tree));
  default:
    SWERR(("unhandled tag: %d", tag));
  }
}

struct userlist_cfg *
userlist_cfg_parse(char const *path)
{
  struct xml_tree *tree = 0, *p;
  struct userlist_cfg *cfg = 0;

  tree = xml_build_tree(path, tag_map, 0, tree_alloc_func, 0);
  if (!tree) return 0;
  if (tree->tag != TG_CONFIG) {
    err("%s: %d: top-level tag must be <config>", path, tree->line);
    goto failed;
  }
  cfg = (struct userlist_cfg *) tree;
  xfree(cfg->b.text);
  cfg->b.text = 0;
  for (p = cfg->b.first_down; p; p = p->right) {
    if (p->tag == TG_FILE) {
      if (p->first_down) {
        err("%s: %d: tag <file> cannot contain nested tags", path, p->line);
        goto failed;
      }
      if (cfg->db_path) {
        err("%s: %d: tag <file> appears more than once", path, p->line);
        goto failed;
      }
      cfg->db_path = p->text;
    } else if (p->tag == TG_SOCKET) {
      if (p->first_down) {
        err("%s: %d: tag <socket> cannot contain nested tags", path, p->line);
        goto failed;
      }
      if (cfg->socket_path) {
        err("%s: %d: tag <socket> appears more than once", path, p->line);
        goto failed;
      }
      cfg->socket_path = p->text;
    } else {
      err("%s: %d: tag <%s> is not valid here", path,p->line,tag_map[p->tag]);
      goto failed;
    }
  }

  if (!cfg->db_path) {
    err("%s: tag <file> is not defined", path);
    goto failed;
  }
  if (!cfg->socket_path) {
    err("%s: tag <socket> is not defined", path);
    goto failed;
  }

  userlist_cfg_unparse(cfg, stdout);
  return cfg;

 failed:
  if (tree) userlist_cfg_free((struct userlist_cfg *) tree);
  return 0;
}

struct userlist_cfg *
userlist_cfg_free(struct userlist_cfg *cfg)
{
  xml_tree_free((struct xml_tree*) cfg, 0, 0);
  return 0;
}

static void
fmt_func(FILE *o, struct xml_tree const *p, int s, int n)
{
  switch (p->tag) {
  case TG_CONFIG:
    if (s == 1 || s == 3) fprintf(o, "\n");
    break;
  case TG_FILE:
  case TG_SOCKET:
    if (s == 3) fprintf(o, "\n");
    if (s == 0) fprintf(o, "  ");
    break;
  default:
    SWERR(("unhandled tag %d", p->tag));
  }
}

void
userlist_cfg_unparse(struct userlist_cfg *cfg, FILE *f)
{
  if (!cfg) return;

  xml_unparse_tree(stdout, (struct xml_tree*) cfg, tag_map, 0, 0, 0,
                   fmt_func);
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "XML_Parser" "XML_Char" "XML_Encoding")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
