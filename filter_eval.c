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

#define YYSTYPE struct filter_tree *

#include "filter_tree.h"
#include "filter_expr.h"
#include "filter_eval.h"
#include "teamdb.h"

#include <reuse/logger.h>
#include <reuse/MemPage.h>

static unsigned char *envdup(struct filter_env *env,
                             unsigned char const *str)
{
  int len;
  unsigned char *s;

  if (!str) str = "";
  len = strlen(str);
  s = filter_tree_alloc(env->mem, len + 1);
  memcpy(s, str, len);
  return s;
}

static int
do_eval(struct filter_env *env,
        struct filter_tree *t,
        struct filter_tree *res)
{
  int c;
  struct filter_tree r1, r2;

  memset(res, 0, sizeof(res));
  switch (t->kind) {
  case TOK_LOGOR:
    res->kind = TOK_BOOL_L;
    res->type = FILTER_TYPE_BOOL;
    if ((c = do_eval(env, t->v.t[0], &r1)) < 0) return c;
    ASSERT(r1.kind == TOK_BOOL_L);
    if (!r1.v.b) {
      if ((c = do_eval(env, t->v.t[1], &r2)) < 0) return c;
      ASSERT(r2.kind == TOK_BOOL_L);
      res->v.b = r2.v.b;
    } else {
      res->v.b = 1;
    }
    break;
    
  case TOK_LOGAND:
    res->kind = TOK_BOOL_L;
    res->type = FILTER_TYPE_BOOL;
    if ((c = do_eval(env, t->v.t[0], &r1)) < 0) return c;
    ASSERT(r1.kind == TOK_BOOL_L);
    if (r1.v.b) {
      if ((c = do_eval(env, t->v.t[1], &r2)) < 0) return c;
      ASSERT(r2.kind == TOK_BOOL_L);
      res->v.b = r2.v.b;
    } else {
      res->v.b = 0;
    }
    break;

    /* binary */
  case '^':
  case '|':
  case '&':
  case '*':
  case '/':
  case '%':
  case '+':
  case '-':
  case '>':
  case '<':
  case TOK_EQ:
  case TOK_NE:
  case TOK_LE:
  case TOK_GE:
  case TOK_ASL:
  case TOK_ASR:
    if ((c = do_eval(env, t->v.t[0], &r1)) < 0) return c;
    if ((c = do_eval(env, t->v.t[1], &r2)) < 0) return c;
    return filter_tree_eval_node(env->mem, t->kind, res, &r1, &r2);

    /* unary */
  case '~':
  case '!':
  case TOK_UN_MINUS:
    if ((c = do_eval(env, t->v.t[0], &r1)) < 0) return c;
    return filter_tree_eval_node(env->mem, t->kind, res, &r1, 0);

  case TOK_TIME:
  case TOK_DUR:
  case TOK_SIZE:
  case TOK_HASH:
  case TOK_IP:
  case TOK_PROB:
  case TOK_UID:
  case TOK_LOGIN:
  case TOK_LANG:
  case TOK_RESULT:
  case TOK_SCORE:
  case TOK_TEST:
    if ((c = do_eval(env, t->v.t[0], &r1)) < 0) return c;
    ASSERT(r1.kind == TOK_INT_L);
    if (r1.v.i < 0) r1.v.i = env->rtotal + r1.v.i;
    if (r1.v.i >= env->rtotal) return -FILTER_ERR_RANGE;
    if (r1.v.i < 0) return -FILTER_ERR_RANGE;
    switch (t->kind) {
    case TOK_TIME:
      res->kind = TOK_TIME_L;
      res->type = FILTER_TYPE_TIME;
      res->v.a = env->rentries[r1.v.i].timestamp;
      break;
    case TOK_DUR:
      res->kind = TOK_DUR_L;
      res->type = FILTER_TYPE_DUR;
      res->v.u = env->rentries[r1.v.i].timestamp - env->rhead.start_time;
      break;
    case TOK_SIZE:
      res->kind = TOK_SIZE_L;
      res->type = FILTER_TYPE_SIZE;
      res->v.z = env->rentries[r1.v.i].size;
      break;
    case TOK_HASH:
      res->kind = TOK_HASH_L;
      res->type = FILTER_TYPE_HASH;
      memcpy(res->v.h, env->rentries[r1.v.i].sha1, sizeof(env->cur->sha1));
      break;
    case TOK_IP:
      res->kind = TOK_IP_L;
      res->type = FILTER_TYPE_IP;
      res->v.p = env->rentries[r1.v.i].ip;
      break;
    case TOK_PROB:
      res->kind = TOK_STRING_L;
      res->type = FILTER_TYPE_STRING;
      res->v.s = envdup(env, env->probs[env->rentries[r1.v.i].problem]->short_name);
      break;
    case TOK_UID:
      res->kind = TOK_INT_L;
      res->type = FILTER_TYPE_INT;
      res->v.i = env->rentries[r1.v.i].team;
      break;
    case TOK_LOGIN:
      res->kind = TOK_STRING_L;
      res->type = FILTER_TYPE_STRING;
      res->v.s = envdup(env, teamdb_get_login(env->rentries[r1.v.i].team));
      break;
    case TOK_LANG:
      res->kind = TOK_STRING_L;
      res->type = FILTER_TYPE_STRING;
      res->v.s = envdup(env, env->langs[env->rentries[r1.v.i].language]->short_name);
      break;
    case TOK_RESULT:
      res->kind = TOK_RESULT_L;
      res->type = FILTER_TYPE_RESULT;
      res->v.r = env->rentries[r1.v.i].status;
      break;
    case TOK_SCORE:
      res->kind = TOK_INT_L;
      res->type = FILTER_TYPE_INT;
      res->v.i = env->rentries[r1.v.i].score;
      break;
    case TOK_TEST:
      res->kind = TOK_INT_L;
      res->type = FILTER_TYPE_INT;
      res->v.i = env->rentries[r1.v.i].test;
      break;
    default:
      abort();
    }
    break;

  case TOK_INT:
  case TOK_STRING:
  case TOK_BOOL:
  case TOK_TIME_T:
  case TOK_DUR_T:
  case TOK_SIZE_T:
  case TOK_RESULT_T:
  case TOK_HASH_T:
  case TOK_IP_T:
    if ((c = do_eval(env, t->v.t[0], &r1)) < 0) return c;
    return filter_tree_eval_node(env->mem, t->kind, res, &r1, 0);

    /* variables */
  case TOK_ID:
    res->kind = TOK_INT_L;
    res->type = FILTER_TYPE_INT;
    res->v.i = env->rid;
    break;
  case TOK_CURTIME:
    res->kind = TOK_TIME_L;
    res->type = FILTER_TYPE_TIME;
    res->v.a = env->cur->timestamp;
    break;
  case TOK_CURDUR:
    res->kind = TOK_DUR_L;
    res->type = FILTER_TYPE_DUR;
    res->v.u = env->cur->timestamp - env->rhead.start_time;
    break;
  case TOK_CURSIZE:
    res->kind = TOK_SIZE_L;
    res->type = FILTER_TYPE_SIZE;
    res->v.z = env->cur->size;
    break;
  case TOK_CURHASH:
    res->kind = TOK_HASH_L;
    res->type = FILTER_TYPE_HASH;
    memcpy(res->v.h, env->cur->sha1, sizeof(env->cur->sha1));
    break;
  case TOK_CURIP:
    res->kind = TOK_IP_L;
    res->type = FILTER_TYPE_IP;
    res->v.p = env->cur->ip;
    break;
  case TOK_CURPROB:
    res->kind = TOK_STRING_L;
    res->type = FILTER_TYPE_STRING;
    res->v.s = envdup(env, env->probs[env->cur->problem]->short_name);
    break;
  case TOK_CURUID:
    res->kind = TOK_INT_L;
    res->type = FILTER_TYPE_INT;
    res->v.i = env->cur->team;
    break;
  case TOK_CURLOGIN:
    res->kind = TOK_STRING_L;
    res->type = FILTER_TYPE_STRING;
    res->v.s = envdup(env, teamdb_get_login(env->cur->team));
    break;
  case TOK_CURLANG:
    res->kind = TOK_STRING_L;
    res->type = FILTER_TYPE_STRING;
    res->v.s = envdup(env, env->langs[env->cur->language]->short_name);
    break;
  case TOK_CURRESULT:
    res->kind = TOK_RESULT_L;
    res->type = FILTER_TYPE_RESULT;
    res->v.r = env->cur->status;
    break;
  case TOK_CURSCORE:
    res->kind = TOK_INT_L;
    res->type = FILTER_TYPE_INT;
    res->v.i = env->cur->score;
    break;
  case TOK_CURTEST:
    res->kind = TOK_INT_L;
    res->type = FILTER_TYPE_INT;
    res->v.i = env->cur->test;
    break;

  case TOK_NOW:
    res->kind = TOK_TIME_L;
    res->type = FILTER_TYPE_TIME;
    res->v.a = env->cur_time;
    break;
  case TOK_START:
    res->kind = TOK_TIME_L;
    res->type = FILTER_TYPE_TIME;
    res->v.a = env->rhead.start_time;
    break;
  case TOK_FINISH:
    res->kind = TOK_TIME_L;
    res->type = FILTER_TYPE_TIME;
    res->v.a = env->rhead.stop_time;
    break;
  case TOK_TOTAL:
    res->kind = TOK_INT_L;
    res->type = FILTER_TYPE_INT;
    res->v.i = env->rtotal;
    break;

  case TOK_INT_L:
  case TOK_STRING_L:
  case TOK_BOOL_L:
  case TOK_TIME_L:
  case TOK_DUR_L:
  case TOK_SIZE_L:
  case TOK_RESULT_L:
  case TOK_HASH_L:
  case TOK_IP_L:
    *res = *t;
    return 0;

  default:
    SWERR(("unhandled kind: %d", t->kind));
  }

  return 0;
}

int
filter_tree_bool_eval(struct filter_env *env,
                      struct filter_tree *t)
{
  struct filter_tree *res = 0;
  int r;

  ASSERT(t);
  ASSERT(t->type == FILTER_TYPE_BOOL);
  res = filter_tree_new_int(env->mem, 0);
  env->cur = &env->rentries[env->rid];
  if ((r = do_eval(env, t, res)) < 0) return r;
  ASSERT(res->type == FILTER_TYPE_BOOL);
  ASSERT(res->kind == TOK_BOOL_L);
  return res->v.b;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "jmp_buf")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
