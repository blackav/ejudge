/* -*- mode:c; coding: koi8-r -*- */
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

#include "tex_dom.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/hash.h>

#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>

typedef struct cmd_list_struct
{
  struct cmd_list_struct *next;
  int cmd;
} cmd_list_t;

typedef struct block_struct
{
  struct block_struct *up;
  int flags;
  unsigned char ignore_nl;
  tex_dom_t *pp;
  tex_dom_t node;
  int is_block;
  cmd_list_t *block_list;
  cmd_list_t **block_pp;
} block_t;

typedef struct
{
  const unsigned char *str;
  const unsigned char *cur;
  int line;
  tex_dom_result_t res;

  unsigned char *cmdname;
  size_t cmdsize;
  int cmdcode;
} parscontext_t;

static int initialized = 0;

static void initialize(void);
static void parse_error(parscontext_t *pc, const char *format, ...)
     __attribute__((format(printf,2,3)));
static int get_cmd_name(parscontext_t *pc);
static int get_cmd_code(const unsigned char *str);
static int parse_vmode(parscontext_t *pc, block_t *up_blk);
static int parse_hmode(parscontext_t *pc, block_t *up_blk);
static int is_par_end(parscontext_t *pc, block_t *up_blk);
static void free_cmd_list(cmd_list_t *p);
static void attach_command(block_t *blks, int cmd);
static cmd_list_t *get_cmd_list(block_t *blks);
static int do_cmd_list(parscontext_t *pc, block_t *up_blk, cmd_list_t *cmds);
static int get_env_code(const unsigned char *str);
static int get_env_name(parscontext_t *pc);
static void drop_trailing_spaces(tex_dom_t *pp);

/*static tex_dom_t make_word_1(const unsigned char *str);*/
static tex_dom_t make_word_2(const unsigned char *, const unsigned char *);
static tex_dom_t make_word_3(const unsigned char *beg, size_t len);
static tex_dom_t make_space(void);
static tex_dom_t make_dom_node(int tag);

tex_dom_result_t
tex_dom_parse(const unsigned char *str)
{
  tex_dom_result_t res;
  parscontext_t cntx;
  block_t blk;

  if (!initialized) initialize();

  XCALLOC(res, 1);
  memset(&cntx, 0, sizeof(cntx));
  cntx.str = str;
  cntx.cur = str;
  cntx.line = 1;
  cntx.res = res;
  memset(&blk, 0, sizeof(blk));
  res->tree = make_dom_node(TEX__DOC);
  blk.node = res->tree;
  blk.pp = &res->tree->first;
  blk.is_block = 1;
  blk.block_pp = &blk.block_list;

  parse_vmode(&cntx, &blk);
  if (!res->errcnt && *cntx.cur) {
    parse_error(&cntx, "EOF expected");
  }
  xfree(cntx.cmdname);
  free_cmd_list(blk.block_list);

  return res;
}

static int
parse_vmode(parscontext_t *pc, block_t *up_blk)
{
  block_t blk;
  tex_dom_t node;
  cmd_list_t *cmds;
  const unsigned char *saved_ptr;

  while (1) {
    if (!pc->cur[0]) break;
    if (pc->cur[0] == '\n') {
      pc->line++;
      pc->cur++;
      continue;
    }
    if (isspace(pc->cur[0])) {
      pc->cur++;
      continue;
    }
    if (pc->cur[0] < ' ') {
      parse_error(pc, "invalid character (code %d)", pc->cur[0]);
      pc->cur++;
      continue;
    }
    if (pc->cur[0] == '{') {
      XMEMZERO(&blk, 1);
      node = make_dom_node(TEX__BLOCK);
      pc->cur++;
      blk.up = up_blk;
      *up_blk->pp = node;
      up_blk->pp = &node->next;
      blk.node = node;
      blk.pp = &node->first;
      blk.is_block = 1;
      blk.block_pp = &blk.block_list;
      if (parse_vmode(pc, &blk) < 0) return -1;
      if (pc->cur[0] != '}') {
        parse_error(pc, "'}' expected");
        return -1;
      }
      free_cmd_list(blk.block_list);
      pc->cur++;
      continue;
    }
    if (pc->cur[0] == '}') {
      return 0;
    }
    if (pc->cur[0] != '\\') {
    enter_h_mode:
      XMEMZERO(&blk, 1);
      node = make_dom_node(TEX__PAR);
      blk.up = up_blk;
      *up_blk->pp = node;
      up_blk->pp = &node->next;
      blk.node = node;
      blk.pp = &node->first;
      cmds = get_cmd_list(up_blk);
      if (do_cmd_list(pc, &blk, cmds) < 0) return -1;
      continue;
    }

    // here parse \command
    ASSERT(pc->cur[0] == '\\');
    saved_ptr = pc->cur;
    pc->cur++;
    switch (pc->cur[0]) {
    default:
      if (get_cmd_name(pc) < 0) return -1;
      switch (pc->cmdcode) {
      case TEX_IT:
        pc->cur = saved_ptr;
        goto enter_h_mode;
      case TEX_END:
        pc->cur = saved_ptr;
        return 0;
      case TEX_BEGIN:
        if (get_env_name(pc) < 0) return -1;
        switch (pc->cmdcode) {
        case TEX_ENV_CENTER:
          XMEMZERO(&blk, 1);
          node = make_dom_node(TEX_ENV_CENTER);
          blk.up = up_blk;
          *up_blk->pp = node;
          up_blk->pp = &node->next;
          blk.node = node;
          blk.pp = &node->first;
          blk.is_block = 1;
          blk.block_pp = &blk.block_list;
          if (parse_vmode(pc, &blk) < 0) return -1;
          if (pc->cur[0] != '\\') {
            parse_error(pc, "\\end expected");
            return -1;
          }
          pc->cur++;
          if (get_cmd_name(pc) < 0) return -1;
          if (pc->cmdcode != TEX_END) {
            parse_error(pc, "\\end expected");
            return -1;
          }
          if (get_env_name(pc) < 0) return -1;
          if (pc->cmdcode != TEX_ENV_CENTER) {
            parse_error(pc, "\\end{center} expected");
            return -1;
          }
          free_cmd_list(blk.block_list);
          break;
        default:
          parse_error(pc, "unhandled environment %s", pc->cmdname);
          return -1;
        }
      }
    }
  }
  return 0;
}

static int
do_cmd_list(parscontext_t *pc, block_t *up_blk, cmd_list_t *cmds)
{
  block_t blk;
  tex_dom_t node;

  if (!cmds) return parse_hmode(pc, up_blk);

  XMEMZERO(&blk, 1);
  node = make_dom_node(cmds->cmd);
  blk.up = up_blk;
  *up_blk->pp = node;
  up_blk->pp = &node->next;
  blk.pp = &node->first;
  blk.node = node;
  return do_cmd_list(pc, &blk, cmds->next);
}

static int
parse_hmode(parscontext_t *pc, block_t *up_blk)
{
  const unsigned char *pp, *saved_cur;
  int par_end_flag = 0;
  tex_dom_t node;
  block_t blk;

  while (1) {
    if (!pc->cur[0]) return 0;
    if (is_par_end(pc, up_blk)) return 0;
    if (pc->cur[0] == '\n') {
      pc->line++;
      pc->cur++;
      continue;
    }
    if (isspace(pc->cur[0])) {
      pc->cur++;
      continue;
    }
    if (pc->cur[0] < ' ') {
      parse_error(pc, "invalid character (code %d)", pc->cur[0]);
      pc->cur++;
      continue;
    }
    break;
  }

  while (1) {
    if (pc->cur[0] == '\\') {
      saved_cur = pc->cur;
      pc->cur++;
      switch (pc->cur[0]) {
      default:
        if (get_cmd_name(pc) < 0) return -1;
        switch (pc->cmdcode) {
        case TEX_IT:
          /* attach the command to the closest block */
          attach_command(up_blk, pc->cmdcode);
          XMEMZERO(&blk, 1);
          node = make_dom_node(pc->cmdcode);
          blk.up = up_blk;
          *up_blk->pp = node;
          up_blk->pp = &node->next;
          blk.pp = &node->first;
          blk.node = node;
          return parse_hmode(pc, &blk);
        case TEX_BEGIN:
        case TEX_END:
          drop_trailing_spaces(&up_blk->node->first);
          pc->cur = saved_cur;
          return 0;
        }
      }
    }

    if (pc->cur[0] == '{') {
      XMEMZERO(&blk, 1);
      node = make_dom_node(TEX__BLOCK);
      pc->cur++;
      blk.up = up_blk;
      *up_blk->pp = node;
      up_blk->pp = &node->next;
      blk.node = node;
      blk.pp = &node->first;
      blk.is_block = 1;
      blk.block_pp = &blk.block_list;
      if (parse_hmode(pc, &blk) < 0) return -1;
      if (pc->cur[0] != '}') {
        parse_error(pc, "'}' expected");
        return -1;
      }
      free_cmd_list(blk.block_list);
      pc->cur++;
      goto get_spaces;
    }

    if (pc->cur[0] == '}') {
      return 0;
    }

    pp = pc->cur;
    while (*pp > ' ') pp++;
    node = make_word_2(pc->cur, pp);
    *up_blk->pp = node;
    up_blk->pp = &node->next;
    pc->cur = pp;

  get_spaces:
    par_end_flag = 0;
    while (1) {
      if (!pc->cur[0] || is_par_end(pc, up_blk)) {
        par_end_flag = 1;
        break;
      }
      if (pc->cur[0] == '\n') {
        pc->line++;
        pc->cur++;
        continue;
      }
      if (isspace(pc->cur[0])) {
        pc->cur++;
        continue;
      }
      if (pc->cur[0] < ' ') {
        parse_error(pc, "invalid character (code %d)", pc->cur[0]);
        pc->cur++;
        continue;
      }
      break;
    }

    if (par_end_flag) break;

    node = make_space();
    *up_blk->pp = node;
    up_blk->pp = &node->next;
  }
  return 0;
}

static int
is_par_end(parscontext_t *pc, block_t *up_blk)
{
  const unsigned char *pp = pc->cur + 1;
  if (pc->cur[0] != '\n') return 0;
  if (up_blk->ignore_nl) return 0;
  while (1) {
    if (!*pp) return 1;
    if (*pp == '\n') return 1;
    if (*pp > ' ') return 0;
    pp++;
  }
}

static int
get_cmd_name(parscontext_t *pc)
{
  const unsigned char *pp;
  size_t curcmdsize;

  if (!pc->cur[0]) {
    parse_error(pc, "unexpected EOF");
    return -1;
  }
  if (pc->cur[0] < ' ') {
    parse_error(pc, "unexpected control character %d after \\", pc->cur[0]);
    return -1;
  }
  if (!isalpha(pc->cur[0])) {
    /* FIXME: handle certain command */
    parse_error(pc, "invalid command \\%c", pc->cur[0]);
    return -1;
  }
  pp = pc->cur;
  while (*pp && isalpha(*pp)) pp++;
  curcmdsize = pp - pc->cur;
  if (curcmdsize >= pc->cmdsize) {
    xfree(pc->cmdname);
    if (!pc->cmdsize) pc->cmdsize = 32;
    while (pc->cmdsize <= curcmdsize) pc->cmdsize *= 2;
    pc->cmdname = (unsigned char*) xmalloc(pc->cmdsize);
  }
  memcpy(pc->cmdname, pc->cur, curcmdsize);
  pc->cmdname[curcmdsize] = 0;
  pc->cur = pp;
  if ((pc->cmdcode = get_cmd_code(pc->cmdname)) < 0) {
    parse_error(pc, "unknown command \\%s", pc->cmdname);
    return -1;
  }
  return 0;
}

static int
get_env_name(parscontext_t *pc)
{
  const unsigned char *pp;
  size_t curcmdsize;

  if (pc->cur[0] != '{') {
    parse_error(pc, "{ expected");
    return -1;
  }
  pc->cur++;
  pp = pc->cur;
  while (*pp && *pp != '}') {
    if (*pp <= ' ') {
      parse_error(pc, "invalid character (code == %d) in env name", *pp);
      return -1;
    }
    pp++;
  }
  if (!*pp) {
    parse_error(pc, "unexpected EOF");
    return -1;
  }

  curcmdsize = pp - pc->cur;
  if (curcmdsize >= pc->cmdsize) {
    xfree(pc->cmdname);
    if (!pc->cmdsize) pc->cmdsize = 32;
    while (pc->cmdsize <= curcmdsize) pc->cmdsize *= 2;
    pc->cmdname = (unsigned char*) xmalloc(pc->cmdsize);
  }
  memcpy(pc->cmdname, pc->cur, curcmdsize);
  pc->cmdname[curcmdsize] = 0;
  pc->cur = pp + 1;
  if ((pc->cmdcode = get_env_code(pc->cmdname)) < 0) {
    parse_error(pc, "unknown environment %s", pc->cmdname);
    return -1;
  }
  return 0;
}

static void
parse_error(parscontext_t *pc, const char *format, ...)
{
  va_list args;
  unsigned char buf[1024];
  unsigned char buf2[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);
  snprintf(buf2, sizeof(buf2), "%d: error: %s\n", pc->line, buf);
  pc->res->errlog = xstrmerge1(pc->res->errlog, buf2);
  pc->res->errcnt++;
}

/* command table */
struct cmdtable
{
  const unsigned char *cmdstr;
  int cmdcode;
  int cmdid;
};
static struct cmdtable cmdtable[] =
{
  { "begin", TEX_BEGIN },
  { "end", TEX_END },
  { "it", TEX_IT },

  { 0, 0, 0 },
};
static int *cmdidmap;
static int cmdidmapsize;

static struct cmdtable envtable[] =
{
  { "center", TEX_ENV_CENTER },

  { 0, 0, 0 },
};
static int *envidmap;
static int envidmapsize;

static ident_t
ident_put_str(const unsigned char *str)
{
  return ident_put(str, strlen(str));
}

static void
initialize(void)
{
  int i;
  int max_id;

  if (initialized) return;
  initialized = 1;

  /* initialize command table */
  for (i = 0; cmdtable[i].cmdstr; i++)
    cmdtable[i].cmdid = ident_put_str(cmdtable[i].cmdstr);

  max_id = 0;
  for (i = 0; cmdtable[i].cmdstr; i++)
    if (cmdtable[i].cmdid > max_id)
      max_id = cmdtable[i].cmdid;
  ASSERT(max_id > 0);

  cmdidmapsize = max_id + 1;
  XCALLOC(cmdidmap, cmdidmapsize);

  for (i = 0; cmdtable[i].cmdstr; i++)
    cmdidmap[cmdtable[i].cmdid] = cmdtable[i].cmdcode;

  /* initialize environment table */
  for (i = 0; envtable[i].cmdstr; i++)
    envtable[i].cmdid = ident_put_str(envtable[i].cmdstr);

  max_id = 0;
  for (i = 0; envtable[i].cmdstr; i++)
    if (envtable[i].cmdid > max_id)
      max_id = envtable[i].cmdid;
  ASSERT(max_id > 0);

  envidmapsize = max_id + 1;
  XCALLOC(envidmap, envidmapsize);

  for (i = 0; envtable[i].cmdstr; i++)
    envidmap[envtable[i].cmdid] = envtable[i].cmdcode;
}

static int
get_cmd_code(const unsigned char *str)
{
  ident_t id = ident_put(str, strlen(str));

  if (id <= 0 || id >= cmdidmapsize || !cmdidmap[id]) return -1;
  return cmdidmap[id];
}
static int
get_env_code(const unsigned char *str)
{
  ident_t id = ident_put(str, strlen(str));

  if (id <= 0 || id >= envidmapsize || !envidmap[id]) return -1;
  return envidmap[id];
}

/*
static tex_dom_t
make_word_1(const unsigned char *str)
{
  size_t len;

  ASSERT(str);
  len = strlen(str);
  return make_word_3(str, len);
}
*/
static tex_dom_t
make_word_2(const unsigned char *beg, const unsigned char *end)
{
  size_t len;

  ASSERT(beg);
  ASSERT(end);
  ASSERT(end > beg);
  len = end - beg;
  return make_word_3(beg, len);
}
static tex_dom_t
make_word_3(const unsigned char *beg, size_t len)
{
  tex_dom_t p;

  ASSERT(beg);
  ASSERT(len > 0);

  XCALLOC(p, 1);
  p->tag = TEX__WORD;
  p->txt = (unsigned char*) xmalloc(len + 1);
  memcpy(p->txt, beg, len);
  p->txt[len] = 0;
  return p;
}
static tex_dom_t
make_space(void)
{
  tex_dom_t p;

  XCALLOC(p, 1);
  p->tag = TEX__SPACE;
  return p;
}
static tex_dom_t
make_dom_node(int tag)
{
  tex_dom_t p;

  XCALLOC(p, 1);
  p->tag = tag;
  return p;
}

static void
attach_command(block_t *blks, int cmd)
{
  cmd_list_t *p;

  while (blks && !blks->is_block) blks = blks->up;
  ASSERT(blks);
  XCALLOC(p, 1);
  p->cmd = cmd;
  *blks->block_pp = p;
  blks->block_pp = &p->next;
}

static cmd_list_t *
get_cmd_list(block_t *blks)
{
  while (blks && !blks->is_block) blks = blks->up;
  ASSERT(blks);
  return blks->block_list;
}

static void
drop_trailing_spaces(tex_dom_t *pp)
{
  tex_dom_t p, q;

  while (1) {
    p = *pp;
    for (; p && p->tag == TEX__SPACE; p = p->next);
    if (!p) {
      p = *pp;
      *pp = 0;
      while (p) {
        q = p->next;
        xfree(p);
        p = q;
      }
      return;
    }
    pp = &p->next;
    while ((*pp) && (*pp)->tag != TEX__SPACE) pp = &(*pp)->next;
    if (!(*pp)) return;
  }
}

static void
free_cmd_list(cmd_list_t *p)
{
  cmd_list_t *q;

  if (!p) return;
  while (p) {
    q = p->next;
    xfree(p);
    p = q;
  }
}

tex_dom_result_t
tex_dom_free_result(tex_dom_result_t res)
{
  xfree(res->errlog);
  xfree(res);
  tex_dom_free(res->tree);
  return 0;
}


/*
 *  compile-command: "gcc -Wall -g -I. -I/home/cher/reuse/include -I/home/cher/reuse/include/ix86-linux -L. -L/home/cher/reuse/lib/ix86-linux ejudge_setup.c ncurses_utils.c tex_dom.c tex_dom_render.c -o ejudge_setup -lreuse -lmenu -lpanel -lncurses -lm"
 */

/*
 * Local variables:
 *  compile-command: "gcc -Wall -g -I/home/cher/reuse/include -I/home/cher/reuse/include/ix86-linux -L/home/cher/reuse/lib/ix86-linux tex_dom.c tex_dom_parse.c tex_dom_render.c tex_dom_doc.c tex_dom_test.c -o tex_dom -lreuse -lm"
 * End:
 */
