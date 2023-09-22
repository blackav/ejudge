/* -*- mode: c -*- */

/* Copyright (C) 2005-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/version.h"
#include "ejudge/super_html.h"
#include "ejudge/super-serve.h"
#include "ejudge/misctext.h"
#include "ejudge/mischtml.h"
#include "ejudge/prepare.h"
#include "ejudge/meta/prepare_meta.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/super_proto.h"
#include "ejudge/fileutl.h"
#include "ejudge/prepare_dflt.h"
#include "ejudge/xml_utils.h"
#include "ejudge/ej_process.h"
#include "ejudge/cpu.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/userlist_proto.h"
#include "ejudge/userlist.h"
#include "ejudge/prepare_serve.h"
#include "ejudge/errlog.h"
#include "ejudge/random.h"
#include "ejudge/compat.h"
#include "ejudge/file_perms.h"
#include "ejudge/build_support.h"
#include "ejudge/variant_map.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/wait.h>
#include <errno.h>

#if defined EJUDGE_CHARSET
#define INTERNAL_CHARSET EJUDGE_CHARSET
#else
#define INTERNAL_CHARSET "utf-8"
#endif

#define ARMOR(s)  html_armor_buf(&ab, (s))

void
html_select(FILE *f, int value, const unsigned char *param_name,
            const unsigned char * const *options)
{
  int i;

  fprintf(f, "<select name=\"%s\">", param_name);
  for (i = 0; options[i]; i++)
    fprintf(f, "<option value=\"%d\"%s>%s</option>",
            i, (i == value) ? " selected=\"1\"" : "", options[i]);
  fprintf(f, "</select>\n");
}

const unsigned char * const super_serve_help_urls[SSERV_CMD_LAST] =
{
  [SSERV_CMD_CNTS_DEFAULT_ACCESS] = "Contest.xml",
  [SSERV_CMD_CNTS_ADD_RULE] = "Contest.xml",
  [SSERV_CMD_CNTS_CHANGE_RULE] = "Contest.xml",
  [SSERV_CMD_CNTS_DELETE_RULE] = "Contest.xml",
  [SSERV_CMD_CNTS_UP_RULE] = "Contest.xml",
  [SSERV_CMD_CNTS_DOWN_RULE] = "Contest.xml",
  [SSERV_CMD_CNTS_COPY_ACCESS] = "Contest.xml",
  [SSERV_CMD_CNTS_DELETE_PERMISSION] = "Contest.xml",
  [SSERV_CMD_CNTS_ADD_PERMISSION] = "Contest.xml",
  [SSERV_CMD_CNTS_SAVE_PERMISSIONS] = "Contest.xml",
  [SSERV_CMD_CNTS_SET_PREDEF_PERMISSIONS] = "Contest.xml",
};

void
print_help_url(FILE *f, int action)
{
  const unsigned char *help_url = 0;

  if (action > 0 && action < SSERV_CMD_LAST) {
    help_url = super_serve_help_urls[action];
  }
  if (help_url) {
    fprintf(f, "<td><a target=\"_blank\" href=\"http://www.ejudge.ru/wiki/index.php/%s\">%s</a></td>",
            help_url, "Help");
  } else {
    fprintf(f, "<td>&nbsp;</td>");
  }
}

#define SIZE_G (1024 * 1024 * 1024)
#define SIZE_M (1024 * 1024)
#define SIZE_K (1024)

static int
super_html_find_lang_id(
        struct sid_state *sstate,
        const struct section_language_data *cs_lang)
{
  int i, max_cs_lang_id;

  /* out of currently activated languages */
  if (cs_lang->id >= sstate->lang_a) {
    return cs_lang->id;
  }
  /* not an activated slot */
  if (!sstate->langs[cs_lang->id]) {
    return cs_lang->id;
  }
  /* we cannot use the same id for compilation and contest server */
  max_cs_lang_id = 0;
  for (i = 1; i < sstate->cs_lang_total; ++i) {
    if (sstate->cs_langs[i]) {
      max_cs_lang_id = i;
    }
  }
  /* max_cs_lang_id is the max of lang_ids of compile server */
  /* consider 30 to be safe interval */
  i = max_cs_lang_id + 30;
  while (i < sstate->lang_a && sstate->langs[i] && sstate->loc_cs_map[i]) {
    ++i;
  }
  return i;
}

void
super_html_lang_activate(
        struct sid_state *sstate,
        int cs_lang_id)
{
  const struct section_language_data *cs_lang = 0;
  struct section_language_data *lang;
  int lang_id;

  ASSERT(sstate);
  if (cs_lang_id <= 0 || cs_lang_id >= sstate->cs_lang_total
      || !(cs_lang = sstate->cs_langs[cs_lang_id]))
    return;

  /* already activated */
  if (sstate->cs_loc_map[cs_lang_id] > 0) return;

  /* create language structure */
  lang = prepare_alloc_language();
  sstate->cfg = param_merge(&lang->g, sstate->cfg);

  lang_id = super_html_find_lang_id(sstate, cs_lang);
  if (lang_id <= 0) return;
  lang->id = lang_id;
  lang->compile_id = cs_lang_id;
  /*
  max_id = 0;
  for (i = 1; i < sstate->lang_a; i++)
    if (sstate->langs[i] && sstate->loc_cs_map[i] && i > max_id)
      max_id = i;

  if (cs_lang->id > max_id) {
    lang->id = cs_lang->id;
    lang->compile_id = cs_lang->id;
  } else {
    while (1) {
      max_id++;
      for (i = 1; i < sstate->lang_a; i++)
        if (sstate->langs[i] && sstate->langs[i]->id == max_id)
          break;
      if (i < sstate->lang_a) continue;
      for (i = 1; i < sstate->cs_lang_total; i++)
        if (sstate->cs_langs[i] && sstate->cs_langs[i]->id == max_id)
          break;
      if (i == sstate->cs_lang_total)
        break;
    }
    lang->id = max_id;
    lang->compile_id = cs_lang->id;
  }
  lang_id = lang->id;
  */

  /* extend the language arrays */
  if (lang_id >= sstate->lang_a) {
    int new_lang_a = sstate->lang_a;
    struct section_language_data **new_langs;
    int *new_loc_cs_map;
    unsigned char **new_lang_opts;
    unsigned char **new_lang_libs;
    int *new_lang_flags;

    if (!new_lang_a) new_lang_a = 4;
    while (lang_id >= new_lang_a) new_lang_a *= 2;
    XCALLOC(new_langs, new_lang_a);
    XCALLOC(new_loc_cs_map, new_lang_a);
    XCALLOC(new_lang_opts, new_lang_a);
    XCALLOC(new_lang_libs, new_lang_a);
    XCALLOC(new_lang_flags, new_lang_a);
    if (sstate->lang_a > 0) {
      XMEMMOVE(new_langs, sstate->langs, sstate->lang_a);
      XMEMMOVE(new_loc_cs_map, sstate->loc_cs_map, sstate->lang_a);
      XMEMMOVE(new_lang_opts, sstate->lang_opts, sstate->lang_a);
      XMEMMOVE(new_lang_libs, sstate->lang_libs, sstate->lang_a);
      XMEMMOVE(new_lang_flags, sstate->lang_flags, sstate->lang_a);
    }
    xfree(sstate->langs);
    xfree(sstate->loc_cs_map);
    xfree(sstate->lang_opts);
    xfree(sstate->lang_libs);
    xfree(sstate->lang_flags);
    sstate->lang_a = new_lang_a;
    sstate->langs = new_langs;
    sstate->loc_cs_map = new_loc_cs_map;
    sstate->lang_opts = new_lang_opts;
    sstate->lang_libs = new_lang_libs;
    sstate->lang_flags = new_lang_flags;
  }
  sstate->langs[lang_id] = lang;
  sstate->lang_opts[lang_id] = 0;
  sstate->lang_libs[lang_id] = 0;
  sstate->lang_flags[lang_id] = 0;
  sstate->cs_loc_map[lang->compile_id] = lang_id;

  strcpy(lang->short_name, cs_lang->short_name);
  if (sstate->cs_lang_names[cs_lang_id] && *sstate->cs_lang_names[cs_lang_id]) {
    usprintf(&lang->long_name, "%s", sstate->cs_lang_names[cs_lang_id]);
  } else if (cs_lang->long_name) {
    usprintf(&lang->long_name, "%s", cs_lang->long_name);
  } else {
    xstrdup3(&lang->long_name, "");
  }
  xstrdup3(&lang->arch, cs_lang->arch);
  strcpy(lang->src_sfx, cs_lang->src_sfx);
  strcpy(lang->exe_sfx, cs_lang->exe_sfx);
  lang->binary = cs_lang->binary;
  lang->insecure = cs_lang->insecure;
  lang->enable_custom = cs_lang->enable_custom;
  lang->enable_ejudge_env = cs_lang->enable_ejudge_env;
  lang->preserve_line_numbers = cs_lang->preserve_line_numbers;
  xstrdup3(&lang->content_type, cs_lang->content_type);
  lang->compile_dir_index = cs_lang->compile_dir_index;
  lang->max_vm_size = cs_lang->max_vm_size;
  lang->max_stack_size = cs_lang->max_stack_size;
  lang->max_file_size = cs_lang->max_file_size;
  xstrdup3(&lang->clean_up_cmd, cs_lang->clean_up_cmd);
}

void
super_html_lang_deactivate(
        struct sid_state *sstate,
        int cs_lang_id)
{
  struct section_language_data *lang = 0;
  int lang_id;

  ASSERT(sstate);
  if (cs_lang_id <= 0 || cs_lang_id >= sstate->cs_lang_total
      || !sstate->cs_langs[cs_lang_id])
    return;
  if ((lang_id = sstate->cs_loc_map[cs_lang_id]) <= 0) return;
  if (lang_id >= sstate->lang_a || !(lang = sstate->langs[lang_id])) return;
  if (sstate->loc_cs_map[lang_id]) return;

  sstate->langs[lang_id] = 0;
  xfree(sstate->lang_opts[lang_id]);
  xfree(sstate->lang_libs[lang_id]);
  sstate->lang_opts[lang_id] = 0;
  sstate->lang_libs[lang_id] = 0;
  sstate->lang_flags[lang_id] = 0;
  sstate->cs_loc_map[cs_lang_id] = 0;
}

int
super_html_lang_cmd(struct sid_state *sstate, int cmd,
                    int lang_id, const unsigned char *param2,
                    int param3, int param4)
{
  struct section_language_data *pl_new;

  if (!sstate->cs_langs) {
    return -SSERV_ERR_CONTEST_NOT_EDITED;
  }
  if (lang_id <= 0 || lang_id >= sstate->cs_lang_total
      || !sstate->cs_langs[lang_id]) {
    return -SSERV_ERR_INVALID_PARAMETER;
  }

  pl_new = 0;
  if (sstate->cs_loc_map[lang_id] > 0)
    pl_new = sstate->langs[sstate->cs_loc_map[lang_id]];

  switch (cmd) {
  case SSERV_CMD_LANG_SHOW_DETAILS:
    if (!pl_new) return 0;
    sstate->lang_flags[pl_new->id] = 1;
    break;

  case SSERV_CMD_LANG_HIDE_DETAILS:
    if (!pl_new) return 0;
    sstate->lang_flags[pl_new->id] = 0;
    break;

  case SSERV_CMD_LANG_DEACTIVATE:
    super_html_lang_deactivate(sstate, lang_id);
    break;

  case SSERV_CMD_LANG_ACTIVATE:
    super_html_lang_activate(sstate, lang_id);
    break;

  default:
    abort();
  }

  return 0;
}

int
super_html_update_versions(struct sid_state *sstate)
{
  int i, j;

  if (!sstate->cs_langs) {
    return -SSERV_ERR_CONTEST_NOT_EDITED;
  }

  for (i = 1; i < sstate->lang_a; i++) {
    if (!sstate->langs[i]) continue;
    j = 0;
    if (sstate->loc_cs_map) {
      j = sstate->loc_cs_map[i];
      if (j <= 0 || j >= sstate->cs_lang_total || !sstate->cs_langs[j])
        j = 0;
    }
    if (j > 0) {
      usprintf(&sstate->langs[i]->long_name, "%s", sstate->cs_lang_names[j]);
    }
  }
  return 0;
}

struct std_checker_info super_html_std_checkers[] =
{
  { "", "" },
  { "cmp_file", "compare two files (trailing whitespace ignored)" },
  { "cmp_file_nospace", "compare two files (duplicated whitespace ignored)" },
  { "cmp_bytes", "compare two files byte by byte" },
  { "cmp_int", "compare two ints (32 bit)" },
  { "cmp_int_seq", "compare two sequences of ints (32 bit)" },
  { "cmp_long_long", "compare two long longs (64 bit)" },
  { "cmp_long_long_seq", "compare two sequences of long longs (64 bit)" },
  { "cmp_unsigned_int", "compare two unsigned ints (32 bit)" },
  { "cmp_unsigned_int_seq", "compare two sequences of unsigned ints (32 bit)" },
  { "cmp_unsigned_long_long", "compare two unsigned long longs (64 bit)" },
  { "cmp_unsigned_long_long_seq", "compare two sequences of unsigned long longs (64 bit)" },
  { "cmp_huge_int", "compare two arbitrarily long ints" },
  { "cmp_double", "compare two doubles (EPS env. var is required)" },
  { "cmp_double_seq", "compare two sequences of doubles (EPS is required)" },
  { "cmp_long_double", "compare two long doubles (EPS is required)" },
  { "cmp_long_double_seq", "compare two sequences of long doubles (EPS is required)" },
  { "cmp_sexpr", "compare two S-expressions" },
  { "cmp_yesno", "compare YES/NO answers" },
  { 0, 0 },
};

const unsigned char *
super_html_get_standard_checker_description(const unsigned char *standard_checker)
{
  if (!standard_checker) return NULL;

  for (int i = 0; super_html_std_checkers[i].name; ++i) {
    if (!strcmp(super_html_std_checkers[i].name, standard_checker)) {
      return super_html_std_checkers[i].desc;
    }
  }
  return NULL;
}

void
problem_id_to_short_name(int num, unsigned char *buf)
{
  if (num < 0) num = 0;
  unsigned char *s = buf;
  if (!num) {
    *s++ = 'A';
    *s = 0;
  } else {
    while (num > 0) {
      *s++ = 'A' + (num % 26);
      num /= 26;
    }
    *s-- = 0;
    unsigned char *q = buf;
    while (q < s) {
      unsigned char t = *q; *q = *s; *s = t;
      ++q; --s;
    }
  }
}

int
super_html_add_problem(
        struct sid_state *sstate,
        int prob_id)
{
  int i;
  struct section_problem_data *prob = 0;

  if (prob_id < 0 || prob_id > EJ_MAX_PROB_ID)
    return -1;

  if (!prob_id) {
    for (i = 1; i < sstate->prob_a; i++)
      if (!sstate->probs[i])
        break;
    prob_id = i;
  }

  prob = super_html_create_problem(sstate, prob_id);
  if (!prob) return -SSERV_ERR_DUPLICATED_PROBLEM;

  problem_id_to_short_name(prob_id - 1, prob->short_name);
  if (sstate->aprob_u == 1)
    snprintf(prob->super, sizeof(prob->super), "%s",
             sstate->aprobs[0]->short_name);
  prob->variant_num = 0;
  return 0;
}

int
super_html_add_abstract_problem(
        struct sid_state *sstate,
        const unsigned char *short_name)
{
  struct section_problem_data *prob = 0;
  int i;

  if (!short_name || !*short_name) return -1;
  if (check_str(short_name, login_accept_chars) < 0) return -1;
  for (i = 0; i < sstate->prob_a; i++)
    if (sstate->probs[i] && !strcmp(sstate->probs[i]->short_name, short_name))
      break;
  if (i < sstate->prob_a) return -1;
  for (i = 0; i < sstate->aprob_u; i++)
    if (!strcmp(sstate->aprobs[i]->short_name, short_name))
      break;
  if (i < sstate->aprob_u) return -1;
  if (i == sstate->aprob_a) {
    if (!sstate->aprob_a) sstate->aprob_a = 4;
    sstate->aprob_a *= 2;
    XREALLOC(sstate->aprobs, sstate->aprob_a);
    XREALLOC(sstate->aprob_flags, sstate->aprob_a);
  }
  prob = prepare_alloc_problem();
  prepare_problem_init_func(&prob->g);
  sstate->cfg = param_merge(&prob->g, sstate->cfg);
  sstate->aprobs[i] = prob;
  sstate->aprob_flags[i] = 0;
  sstate->aprob_u++;
  snprintf(prob->short_name, sizeof(prob->short_name), "%s", short_name);
  prob->abstract = 1;
  prob->type = 0;
  prob->manual_checking = 0;
  prob->examinator_num = 0;
  prob->check_presentation = 0;
  prob->scoring_checker = 0;
  prob->enable_checker_token = 0;
  prob->interactive_valuer = 0;
  prob->disable_pe = 0;
  prob->disable_wtl = 0;
  prob->wtl_is_cf = 0;
  prob->use_stdin = 1;
  prob->use_stdout = 1;
  prob->combined_stdin = 0;
  prob->combined_stdout = 0;
  prob->binary_input = DFLT_P_BINARY_INPUT;
  prob->binary = 0;
  prob->ignore_exit_code = 0;
  prob->ignore_term_signal = 0;
  prob->olympiad_mode = 0;
  prob->score_latest = 0;
  prob->score_latest_or_unmarked = 0;
  prob->score_latest_marked = 0;
  prob->score_tokenized = 0;
  prob->time_limit = 1;
  prob->time_limit_millis = 0;
  prob->real_time_limit = 5;
  xstrdup3(&prob->test_dir, "%Ps");
  xstrdup3(&prob->test_sfx, ".dat");
  prob->use_corr = 1;
  xstrdup3(&prob->corr_dir, "%Ps");
  xstrdup3(&prob->corr_sfx, ".ans");
  prob->use_info = 0;
  xstrdup3(&prob->info_dir, "%Ps");
  xstrdup3(&prob->info_sfx, ".inf");
  prob->use_tgz = 0;
  xstrdup3(&prob->tgz_dir, "%Ps");
  xstrdup3(&prob->tgz_sfx, ".tgz");
  xstrdup3(&prob->tgzdir_sfx, ".dir");
  if (sstate->global && sstate->global->advanced_layout > 0) {
    usprintf(&prob->check_cmd, "%s", DFLT_P_CHECK_CMD);
  } else {
    usprintf(&prob->check_cmd, "%s", "check_%Ps");
  }
  prob->max_vm_size = 64 * SIZE_M;
  prob->variant_num = 0;
  return 0;
}

int
super_html_prob_cmd(struct sid_state *sstate, int cmd,
                    int prob_id, const unsigned char *param2,
                    int param3, int param4)
{
  int new_val_1, new_val_2;

  switch (cmd) {
  case SSERV_CMD_PROB_ADD:
    return super_html_add_problem(sstate, prob_id);

  case SSERV_CMD_PROB_ADD_ABSTRACT:
    return super_html_add_abstract_problem(sstate, param2);

  case SSERV_CMD_PROB_SHOW_DETAILS:
    new_val_1 = SID_STATE_SHOW_HIDDEN;
    new_val_2 = 0;
    goto do_handle_details_flag;
  case SSERV_CMD_PROB_HIDE_DETAILS:
    new_val_1 = 0;
    new_val_2 = SID_STATE_SHOW_HIDDEN;
    goto do_handle_details_flag;
  case SSERV_CMD_PROB_SHOW_ADVANCED:
    new_val_1 = SID_STATE_SHOW_CLOSED;
    new_val_2 = 0;
    goto do_handle_details_flag;
  case SSERV_CMD_PROB_HIDE_ADVANCED:
    new_val_1 = 0;
    new_val_2 = SID_STATE_SHOW_CLOSED;
    goto do_handle_details_flag;
  do_handle_details_flag:;
    if (prob_id <= 0) {
      prob_id = -prob_id;
      if (prob_id >= sstate->aprob_u)
        return -SSERV_ERR_INVALID_PARAMETER;
      sstate->aprob_flags[prob_id] |= new_val_1;
      sstate->aprob_flags[prob_id] &= ~new_val_2;
    } else {
      if (prob_id >= sstate->prob_a || !sstate->probs[prob_id])
        return -SSERV_ERR_INVALID_PARAMETER;
      sstate->prob_flags[prob_id] |= new_val_1;
      sstate->prob_flags[prob_id] &= ~new_val_2;
    }
    return 0;

  default:
    abort();
  }
}

#define PROB_ASSIGN_STRING(f) snprintf(prob->f, sizeof(prob->f), "%s", param2)
#define PROB_CLEAR_STRING(f) prob->f[0] = 0

int
super_html_prob_param(struct sid_state *sstate, int cmd,
                      int prob_id, const unsigned char *param2,
                      int param3, int param4)
{
  struct section_problem_data *prob;
  int i;

  if (prob_id > 0) {
    if (prob_id >= sstate->prob_a || !sstate->probs[prob_id])
      return -SSERV_ERR_INVALID_PARAMETER;
    prob = sstate->probs[prob_id];
  } else {
    prob_id = -prob_id;
    if (prob_id >= sstate->aprob_u || !sstate->aprobs[prob_id])
      return -SSERV_ERR_INVALID_PARAMETER;
    prob = sstate->aprobs[prob_id];
  }

  switch (cmd) {
  case SSERV_CMD_PROB_DELETE:
    if (prob->abstract && prob->short_name[0]) {
      for (i = 1; i < sstate->prob_a; i++)
        if (sstate->probs[i]
            && !strcmp(sstate->probs[i]->short_name, prob->short_name))
          break;
      if (i < sstate->prob_a) return -SSERV_ERR_PROBLEM_IS_USED;
      for (i = prob_id + 1; i < sstate->aprob_u; i++) {
        sstate->aprobs[i - 1] = sstate->aprobs[i];
        sstate->aprob_flags[i - 1] = sstate->aprob_flags[i];
      }
      sstate->aprob_u--;
      sstate->aprobs[sstate->aprob_u] = 0;
      sstate->aprob_flags[sstate->aprob_u] = 0;
    } else {
      sstate->probs[prob_id] = 0;
      sstate->prob_flags[prob_id] = 0;
    }
    return 0;

  default:
    abort();
  }
}

static unsigned char *
strsubst(const unsigned char *str, const unsigned char *from,
         const unsigned char *to)
{
  unsigned char *p, *q;
  size_t from_len = strlen(from);
  size_t to_len = strlen(to);
  size_t str_len = strlen(str);

  if (!(p = strstr(str, from))) return 0;

  q = xmalloc(str_len - from_len + to_len + 1);
  memcpy(q, str, p - str);
  memcpy(q + (p - str), to, to_len);
  strcpy(q + (p - str) + to_len, p + from_len);
  return q;
}

static void
subst_param(unsigned char **p_param,
            int n,
            unsigned char s_from[][32], unsigned char s_to[][32])
{
  int i;
  unsigned char *t;
  unsigned char *param = *p_param;

  if (!param) return;
  for (i = 0; i < n; i++) {
    if (!(t = strsubst(param, s_from[i], s_to[i]))) continue;
    xfree(param);
    *p_param = t;
    return;
  }
}

void
super_html_fix_serve(struct sid_state *sstate,
                     int orig_id, int contest_id)
{
  unsigned char substs_from[6][32];
  unsigned char substs_to[6][32];
  struct section_global_data *global = sstate->global;
  unsigned char *s;

  if (!global) return;

  snprintf(substs_from[0], sizeof(substs_from[0]), "%06d", orig_id);
  snprintf(substs_from[1], sizeof(substs_from[0]), "%05d", orig_id);
  snprintf(substs_from[2], sizeof(substs_from[0]), "%04d", orig_id);
  snprintf(substs_from[3], sizeof(substs_from[0]), "%03d", orig_id);
  snprintf(substs_from[4], sizeof(substs_from[0]), "%02d", orig_id);
  snprintf(substs_from[5], sizeof(substs_from[0]), "%d", orig_id);
  snprintf(substs_to[0], sizeof(substs_to[0]), "%06d", contest_id);
  snprintf(substs_to[1], sizeof(substs_to[0]), "%05d", contest_id);
  snprintf(substs_to[2], sizeof(substs_to[0]), "%04d", contest_id);
  snprintf(substs_to[3], sizeof(substs_to[0]), "%03d", contest_id);
  snprintf(substs_to[4], sizeof(substs_to[0]), "%02d", contest_id);
  snprintf(substs_to[5], sizeof(substs_to[0]), "%d", contest_id);

  s = xstrdup(global->standings_file_name);
  subst_param(&s, 6, substs_from, substs_to);
  xfree(global->standings_file_name);
  global->standings_file_name = s;

  if (global->stand2_file_name && global->stand2_file_name[0]) {
    s = xstrdup(global->stand2_file_name);
    subst_param(&s, 6, substs_from, substs_to);
    xfree(global->stand2_file_name);
    global->stand2_file_name = s;
  }

  if (global->plog_file_name && global->plog_file_name[0]) {
    s = xstrdup(global->plog_file_name);
    subst_param(&s, 6, substs_from, substs_to);
    xfree(global->plog_file_name);
    global->plog_file_name = s;
  }

  global->stand_ignore_after = 0;
}

static void
mkpath(unsigned char *out, const unsigned char *d, const unsigned char *n,
       const unsigned char *i)
{
  if (!n || !*n) {
    snprintf(out, sizeof(path_t), "%s/%s", d, i);
  } else if (!os_IsAbsolutePath(n)) {
    snprintf(out, sizeof(path_t), "%s/%s", d, n);
  } else {
    snprintf(out, sizeof(path_t), "%s", n);
  }
}

static int
check_test_file(
        FILE *flog,
        int n,
        const unsigned char *path,
        const unsigned char *pat,
        const unsigned char *sfx,
        int q_flag,
        int bin_flag,
        int file_group,
        int file_mode)
{
  path_t name;
  path_t name2;
  path_t full;
  path_t full2;
  struct stat stbuf;
  DIR *d;
  struct dirent *dd;
  char *test_txt = 0;
  size_t test_len = 0;
  unsigned char *d2u_txt = 0, *out_txt = 0;
  int changed = 0;
  int old_group = 0, old_mode = 0;

  if (pat && *pat) {
    snprintf(name, sizeof(name), pat, n);
  } else {
    snprintf(name, sizeof(name), "%03d%s", n, sfx);
  }

  snprintf(full, sizeof(full), "%s/%s", path, name);
  if (stat(full, &stbuf) < 0) {
    // try case-insensitive search
    name2[0] = 0;
    if (!(d = opendir(path))) {
      fprintf(flog, "Error: cannot open directory %s\n", path);
      return -1;
    }
    while ((dd = readdir(d))) {
      if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, ".."))
        continue;
      if (!strcasecmp(name, dd->d_name)) {
        snprintf(name2, sizeof(name2), "%s", dd->d_name);
        break;
      }
    }
    closedir(d);
    if (!name2[0]) {
      if (!q_flag)
        fprintf(flog, "Error: file %s not found even case insensetively\n", name);
      return 0;
    }
    snprintf(full2, sizeof(full2), "%s/%s", path, name2);
    fprintf(flog, "Info: found %s using case-insensetive search\n", name2);
    if (stat(full2, &stbuf) < 0) {
      fprintf(flog, "Error: file %s is not found. Strange!\n", full2);
      return -1;
    }
    if (!S_ISREG(stbuf.st_mode)) {
      fprintf(flog, "Error: file %s is not regular\n", full2);
      return -1;
    }
    if (rename(full2, full) < 0) {
      fprintf(flog, "Error: rename %s -> %s failed: %s\n", full2, full,
              os_ErrorMsg());
      return -1;
    }
    fprintf(flog, "Info: file renamed: %s -> %s\n", full2, full);
  } else {
    if (!S_ISREG(stbuf.st_mode)) {
      fprintf(flog, "Error: file %s is not regular\n", full);
      return -1;
    }
  }

  file_perms_get(full, &old_group, &old_mode);

  if (!bin_flag) {
    if (generic_read_file(&test_txt, 0, &test_len, 0, 0, full, 0) < 0) {
      fprintf(flog, "Error: failed to read %s\n", full);
      return -1;
    }
    if (test_len != strlen(test_txt)) {
      fprintf(flog, "Error: file %s contains NUL (\\0) bytes\n", full);
      xfree(test_txt);
      return -1;
    }
    d2u_txt = dos2unix_str(test_txt);
    if (strcmp(d2u_txt, test_txt)) {
      changed = 1;
      fprintf(flog, "Info: file %s converted from DOS to UNIX format\n", full);
    }
    xfree(test_txt); test_txt = 0;
    test_len = strlen(d2u_txt);
    if (test_len > 0 && d2u_txt[test_len - 1] != '\n') {
      changed = 1;
      out_txt = xmalloc(test_len + 2);
      strcpy(out_txt, d2u_txt);
      out_txt[test_len] = '\n';
      out_txt[test_len + 1] = 0;
      xfree(d2u_txt); d2u_txt = 0;
      fprintf(flog, "Info: file %s: final newline appended\n", full);
      test_len++;
    } else {
      out_txt = d2u_txt; d2u_txt = 0;
    }
  }

  if (changed) {
    if (generic_write_file(out_txt, test_len, KEEP_ON_FAIL, 0, full, 0) < 0) {
      fprintf(flog, "Error: write of %s failed\n", full);
      xfree(out_txt);
      return -1;
    }
    fprintf(flog, "Info: file %s successfully written\n", full);
    file_perms_set(flog, full, file_group, file_mode, old_group, old_mode);
  }

  xfree(out_txt);
  return 1;
}

static int
invoke_test_checker(
        FILE *flog,
        int n,
        const unsigned char *test_checker_cmd,
        char **test_checker_env,
        const unsigned char *tst_dir,
        const unsigned char *tst_pat,
        const unsigned char *tst_sfx,
        const unsigned char *ans_dir,
        const unsigned char *ans_pat,
        const unsigned char *ans_sfx)
{
  path_t tst_name;
  path_t tst_path;
  int retval = 0;
  char *args[4];
  unsigned char *out_text = 0;
  unsigned char *err_text = 0;

  if (!test_checker_cmd || !test_checker_cmd[0]) return 0;

  if (tst_pat && *tst_pat) {
    snprintf(tst_name, sizeof(tst_name), tst_pat, n);
  } else {
    snprintf(tst_name, sizeof(tst_name), "%03d%s", n, tst_sfx);
  }
  snprintf(tst_path, sizeof(tst_path), "%s/%s", tst_dir, tst_name);

  args[0] = (char*) test_checker_cmd;
  args[1] = NULL;

  retval = ejudge_invoke_process(args, test_checker_env, tst_dir, tst_path, NULL,
                                 1, &out_text, &err_text);
  if ((err_text && *err_text) || (out_text && *out_text) || retval != 0) {
    fprintf(flog, "%s %s\n", test_checker_cmd, tst_path);
  }
  if (err_text) {
    fprintf(flog, "%s", err_text);
    xfree(err_text); err_text = 0;
  }
  if (out_text) {
    fprintf(flog, "%s", out_text);
    xfree(out_text); out_text = 0;
  }
  if (retval >= 256) {
    fprintf(flog, "test checker process is terminated by signal %d %s\n",
            retval - 256, os_GetSignalString(retval - 256));
    retval = -1;
  } else if (retval > 0) {
    fprintf(flog, "test checker process exited with code %d\n", retval);
    retval = -1;
  }

  return retval;
}

static int
invoke_compile_process(
        FILE *flog,
        const unsigned char *cur_dir,
        const unsigned char *cmd)
{
  int retval = 0;
  unsigned char *out_text = 0, *err_text = 0;
  char *args[4];

  fprintf(flog, "Starting compilation: %s\n", cmd);

  args[0] = "/bin/sh";
  args[1] = "-c";
  args[2] = (char*) cmd;
  args[3] = 0;

  retval = ejudge_invoke_process(args, NULL, cur_dir, NULL, NULL, 1,
                                 &out_text, &err_text);
  if (err_text) {
    fprintf(flog, "%s", err_text);
    xfree(err_text); err_text = 0;
  }
  if (out_text) {
    fprintf(flog, "%s", out_text);
    xfree(out_text); out_text = 0;
  }

  if (!retval) {
    fprintf(flog, "process is completed successfully\n");
  } else if (retval >= 256) {
    fprintf(flog, "process is terminated by signal %d %s\n",
            retval - 256, os_GetSignalString(retval - 256));
  } else if (retval > 0) {
    fprintf(flog, "process exited with code %d\n", retval);
  }

  return retval;
}

enum
{
  CHECKER_LANG_FIRST,
  CHECKER_LANG_PAS = CHECKER_LANG_FIRST,
  CHECKER_LANG_DPR,
  CHECKER_LANG_C,
  CHECKER_LANG_CPP,

  CHECKER_LANG_LAST,
};
static const unsigned char * const supported_suffixes[] =
{
  ".pas",
  ".dpr",
  ".c",
  ".cpp",
  0,
};

static unsigned char *fpc_path = 0;
static unsigned char *dcc_path = 0;
static unsigned char *gcc_path = 0;
static unsigned char *gpp_path = 0;

static unsigned char *
get_compiler_path(
        const struct ejudge_cfg *config,
        const unsigned char *short_name,
        unsigned char *old_path)
{
  unsigned char *s = 0;
  path_t script_path;
  path_t cmd;

  if (old_path) return old_path;

  script_path[0] = 0;
  if (config->compile_home_dir) {
    snprintf(script_path, sizeof(script_path), "%s/scripts",
             config->compile_home_dir);
  }
  if (!script_path[0] && config->contests_home_dir) {
    snprintf(script_path, sizeof(script_path), "%s/compile/scripts",
             config->contests_home_dir);
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!script_path[0] && config->contests_home_dir) {
    snprintf(script_path, sizeof(script_path), "%s/compile/scripts",
             EJUDGE_CONTESTS_HOME_DIR);
  }
#endif

  snprintf(cmd, sizeof(cmd), "\"%s/%s-version\" -p",
           script_path, short_name);
  if (!(s = read_process_output(cmd, 0, 0, 0))) s = xstrdup("");
  return s;
}

static int
recompile_checker(
        const struct ejudge_cfg *config,
        FILE *f,
        const unsigned char *checker_path)
{
  struct stat stbuf1, stbuf2;
  path_t checker_src;
  path_t checker_obj;
  int need_recompile = 0, retcode = 0;
  path_t cmd;
  path_t check_dir;
  path_t filename;
  path_t filename2;
  int lang_ind, i;

  lang_ind = -1;
  for (i = CHECKER_LANG_FIRST; i < CHECKER_LANG_LAST; i++) {
    snprintf(checker_src, sizeof(checker_src), "%s%s", checker_path,
             supported_suffixes[i]);
    if (stat(checker_src, &stbuf2) < 0) continue;
    if (!S_ISREG(stbuf2.st_mode)) {
      fprintf(f, "Error: checker source %s is not a regular file\n", checker_src);
      return -1;
    }
    if (lang_ind >= 0) {
      fprintf(f, "Error: several source files (%s, %s) are found for a checker\n",
              supported_suffixes[lang_ind], supported_suffixes[i]);
      return -1;
    }
    lang_ind = i;
  }
  if (lang_ind < 0) {
    if (stat(checker_path, &stbuf1) < 0) {
      fprintf(f, "Error: checker %s does not exist and cannot be compiled\n",
              checker_path);
      return -1;
    }
    if (!S_ISREG(stbuf1.st_mode)) {
      fprintf(f, "Error: checker %s is not a regular file\n", checker_path);
      return -1;
    }
    if (access(checker_path, X_OK) < 0) {
      fprintf(f, "Error: checker %s is not executable\n", checker_path);
      return -1;
    }
    fprintf(f, "Warning: no source file or unsupported language for checker %s\n", checker_path);
    return 0;
  }

  snprintf(checker_src, sizeof(checker_src), "%s%s", checker_path,
           supported_suffixes[lang_ind]);
  // FIXME: make configurable object file suffix
  snprintf(checker_obj, sizeof(checker_obj), "%s.o", checker_path);
  if (stat(checker_path, &stbuf1) < 0) {
    fprintf(f, "Warning: checker %s does not exist\n", checker_path);
    if (stat(checker_src, &stbuf2) < 0) {
      fprintf(f, "Error: checker source %s is missing\n", checker_src);
      return -1;
    }
    need_recompile = 1;
  } else {
    if (stat(checker_src, &stbuf2) >= 0 && stbuf2.st_mtime > stbuf1.st_mtime) {
      fprintf(f, "Info: checker source %s is newer, than %s\n", checker_src,
              checker_path);
      need_recompile = 1;
    }
  }
  if (!need_recompile) return 0;

  os_rDirName(checker_path, check_dir, sizeof(check_dir));
  os_rGetBasename(checker_path, filename, sizeof(filename));
  snprintf(filename2, sizeof(filename2), "%s%s", filename,
           supported_suffixes[lang_ind]);

  switch (lang_ind) {
  case CHECKER_LANG_PAS:
    fpc_path = get_compiler_path(config, "fpc", fpc_path);
    if (!*fpc_path) {
      fprintf(f, "Error: Free Pascal support is not configured\n");
      return -1;
    }
    snprintf(cmd, sizeof(cmd), "%s -dEJUDGE -Fu%s/share/ejudge/testlib/fpc %s",
             fpc_path, EJUDGE_PREFIX_DIR, filename2);
    break;
  case CHECKER_LANG_DPR:
    dcc_path = get_compiler_path(config, "dcc", dcc_path);
    if (!*dcc_path) {
      fprintf(f, "Error: Delphi (Kylix) support is not configured\n");
      return -1;
    }
    snprintf(cmd, sizeof(cmd), "%s -DEJUDGE -U%s/share/ejudge/testlib/delphi %s",
             dcc_path, EJUDGE_PREFIX_DIR, filename2);
    break;
  case CHECKER_LANG_C:
    gcc_path = get_compiler_path(config, "gcc", gcc_path);
    if (!*gcc_path) {
      fprintf(f, "Error: GNU C support is not configured\n");
      return -1;
    }
    snprintf(cmd, sizeof(cmd), "%s -DEJUDGE -std=gnu11 -O2 -Wall -I%s/include/ejudge -L%s/lib -Wl,--rpath,%s/lib %s -o %s -lchecker -lm", gcc_path, EJUDGE_PREFIX_DIR, EJUDGE_PREFIX_DIR, EJUDGE_PREFIX_DIR, filename2, filename);
    break;
  case CHECKER_LANG_CPP:
    gpp_path = get_compiler_path(config, "g++", gpp_path);
    if (!*gpp_path) {
      fprintf(f, "Error: GNU C++ support is not configured\n");
      return -1;
    }
    snprintf(cmd, sizeof(cmd), "%s -DEJUDGE -O2 -Wall -I%s/include/ejudge -L%s/lib -Wl,--rpath,%s/lib %s -o %s -lchecker -lm", gpp_path, EJUDGE_PREFIX_DIR, EJUDGE_PREFIX_DIR, EJUDGE_PREFIX_DIR, filename2, filename);
    break;

  default:
    abort();
  }

  // remove old executable and object file
  unlink(checker_obj);
  unlink(checker_path);

  fprintf(f, "Info: using command line %s\n", cmd);
  if ((retcode = invoke_compile_process(f, check_dir, cmd)) < 0) {
    fprintf(f, "Error: failed to start the compiler\n");
    return -1;
  } else if (retcode > 0) {
    fprintf(f, "Error: compiler exit code %d\n", retcode);
    return -1;
  }
  if (stat(checker_path, &stbuf1)) {
    fprintf(f, "Error: checker is not created by the compiler\n");
    return -1;
  } else {
    fprintf(f, "Info: checker %s is recompiled\n", filename);
  }
  return 0;
}

static int
invoke_make(
        FILE *flog,
        const struct ejudge_cfg *config,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        int variant)
{
  path_t makefile_path;
  path_t problem_dir;
  struct stat stbuf;
  int r;
  unsigned char cmd[8192];

  get_advanced_layout_path(problem_dir, sizeof(problem_dir), global,
                           prob, NULL, variant);
  if (access(problem_dir, R_OK | X_OK) < 0) {
    fprintf(flog, "Error: problem directory %s does not exist or is not accessible\n", problem_dir);
    return -1;
  }
  snprintf(makefile_path, sizeof(makefile_path), "%s/Makefile", problem_dir);
  if (stat(makefile_path, &stbuf) < 0) {
    fprintf(flog, "Info: Makefile in %s does not exist\n", problem_dir);
    return 0;
  }

#if defined EJUDGE_LOCAL_DIR
  snprintf(cmd, sizeof(cmd), "make EJUDGE_PREFIX_DIR=\"%s\" EJUDGE_CONTESTS_HOME_DIR=\"%s\" EJUDGE_LOCAL_DIR=\"%s\" check_settings", EJUDGE_PREFIX_DIR, EJUDGE_CONTESTS_HOME_DIR, EJUDGE_LOCAL_DIR);
#else
  snprintf(cmd, sizeof(cmd), "make EJUDGE_PREFIX_DIR=\"%s\" EJUDGE_CONTESTS_HOME_DIR=\"%s\" check_settings", EJUDGE_PREFIX_DIR, EJUDGE_CONTESTS_HOME_DIR);
#endif
  r = invoke_compile_process(flog, problem_dir, cmd);
  if (r < 0) {
    fprintf(flog, "Error: failed to start make\n");
    return -1;
  } else if (r > 0) {
    fprintf(flog, "Error: make failed with exit code %d\n", r);
    return -1;
  }
  // check for checker
  if (!prob->standard_checker) {
    get_advanced_layout_path(cmd, sizeof(cmd), global, prob, prob->check_cmd, variant);
    if (access(cmd, X_OK) < 0) {
      fprintf(flog, "Error: checker executable %s is not created\n", cmd);
      return -1;
    }
  }
  // check for valuer
  if (prob->valuer_cmd && prob->valuer_cmd[0]) {
    get_advanced_layout_path(cmd, sizeof(cmd), global, prob, prob->valuer_cmd, variant);
    if (access(cmd, X_OK) < 0) {
      fprintf(flog, "Error: valuer executable %s is not created\n", cmd);
      return -1;
    }
  }
  // check for interactor
  if (prob->interactor_cmd && prob->interactor_cmd[0]) {
    // FIXME: complete
  }
  // check for style checker
  if (prob->style_checker_cmd && prob->style_checker_cmd[0]) {
    // FIXME: complete
  }
  // check for test checker
  if (prob->test_checker_cmd && prob->test_checker_cmd[0]) {
    get_advanced_layout_path(cmd, sizeof(cmd), global, prob,
                             prob->test_checker_cmd, variant);
    if (access(cmd, X_OK) < 0) {
      fprintf(flog, "Error: test checker executable %s is not created\n", cmd);
      return -1;
    }
  }

  return 1;
}

static int
check_test_score(FILE *flog, int ntests, int test_score, int full_score,
                 const unsigned char *test_score_list)
{
  int *scores;
  int i, sum;
  int index, score, n, tn = 1, was_indices = 0;
  const unsigned char *s;

  ASSERT(ntests >= 0);

  if (test_score < 0) {
    fprintf(flog, "Error: test_score is negative\n");
    return -1;
  }

  XALLOCA(scores, ntests + 1);
  for (i = 0; i <= ntests; i++)
    scores[i] = test_score;

  if (test_score_list && *test_score_list) {
    s = test_score_list;

    while (1) {
      while (*s > 0 && *s <= ' ') s++;
      if (!*s) break;

      if (*s == '[') {
        if (sscanf(s, "[ %d ] %d%n", &index, &score, &n) != 2) {
          fprintf(flog, "Error: invalid test_score_list specification \"%s\"\n",
                  test_score_list);
          return -1;
        }
        if (index < 1 || index > ntests) {
          fprintf(flog, "Error: test index %d is out of range\n", index);
          return -1;
        }
        if (score < 0) {
          fprintf(flog, "Error: score %d is invalid\n", score);
          return -1;
        }
        tn = index;
        was_indices = 1;
      } else {
        if (sscanf(s, "%d%n", &score, &n) != 1) {
          fprintf(flog, "Error: invalid test_score_list specification \"%s\"\n",
                  test_score_list);
          return -1;
        }
        if (score < 0) {
          fprintf(flog, "Error: score %d is invalid\n", score);
          return -1;
        }
        if (tn > ntests) {
          fprintf(flog, "Error: too many scores specified\n");
          return -1;
        }
      }
      scores[tn++] = score;
      s += n;
    }

    if (!was_indices && tn <= ntests) {
      fprintf(flog, "Info: test_score_list defines only %d tests\n", tn - 1);
    }
  }

  for (i = 1, sum = 0; i <= ntests; i++)
    sum += scores[i];

  if (sum > full_score) {
    fprintf(flog, "Error: summ of all test scores (%d) is greater than full_score (%d)\n", sum, full_score);
    return -1;
  } else if (sum < full_score) {
    fprintf(flog, "Warning: summ of all test scores (%d) is less than full_score (%d)\n", sum, full_score);
  }

  return 0;
}

int
super_html_new_check_tests(
        FILE *flog,
        const struct ejudge_cfg *config,
        struct sid_state *sstate)
{
  int retval = -1;
  path_t conf_path;
  path_t g_test_path;
  path_t g_corr_path;
  path_t g_info_path;
  path_t g_tgz_path;
  path_t g_checker_path;
  path_t test_path, corr_path, info_path, checker_path;
  path_t v_test_path, v_corr_path, v_info_path, v_checker_path;
  struct contest_desc *cnts;
  struct section_global_data *global;
  struct section_problem_data *prob, *abstr;
  struct section_problem_data *tmp_prob = 0;
  int i, j, k, variant;
  struct stat stbuf;
  int total_tests = 0, v_total_tests = 0;
  int file_group, file_mode;
  int already_compiled = 0;
  path_t test_checker_cmd;

  if (sstate->serve_parse_errors) {
    fprintf(flog, "%s\n", sstate->serve_parse_errors);
    goto cleanup;
  }

  if (!sstate->edited_cnts || !sstate->global) {
    fprintf(flog, "The tests cannot be checked: No contest\n");
    goto cleanup;
  }

  cnts = sstate->edited_cnts;
  global = sstate->global;

  file_group = file_perms_parse_group(cnts->file_group);
  file_mode = file_perms_parse_mode(cnts->file_mode);

  mkpath(conf_path, cnts->root_dir, cnts->conf_dir, DFLT_G_CONF_DIR);
  mkpath(g_test_path, conf_path, global->test_dir, DFLT_G_TEST_DIR);
  mkpath(g_corr_path, conf_path, global->corr_dir, DFLT_G_CORR_DIR);
  mkpath(g_info_path, conf_path, global->info_dir, DFLT_G_INFO_DIR);
  mkpath(g_tgz_path, conf_path, global->tgz_dir, DFLT_G_TGZ_DIR);
  mkpath(g_checker_path, conf_path, global->checker_dir, DFLT_G_CHECKER_DIR);

  for (i = 1; i < sstate->prob_a; i++) {
    if (!(prob = sstate->probs[i])) continue;
    already_compiled = 0;

    if (prob->internal_name && prob->internal_name[0]) {
      fprintf(flog, "*** Checking problem %s (%s) ***\n", prob->short_name, prob->internal_name);
    } else {
      fprintf(flog, "*** Checking problem %s ***\n", prob->short_name);
    }
    if (prob->disable_testing > 0) {
      fprintf(flog, "Testing is disabled, skipping\n");
      continue;
    }

    abstr = 0;
    if (prob->super[0]) {
      for (j = 0; j < sstate->aprob_u; j++)
        if (!strcmp(prob->super, sstate->aprobs[j]->short_name))
          break;
      if (j < sstate->aprob_u)
        abstr = sstate->aprobs[j];
      if (!abstr) {
        fprintf(flog, "Error: no abstract checker for problem `%s'\n",
                prob->short_name);
        goto cleanup;
      }
    }

    tmp_prob = prepare_problem_free(tmp_prob);
    tmp_prob = prepare_copy_problem(prob);
    prepare_set_prob_value(CNTSPROB_type, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_xml_file, tmp_prob, abstr, global);

    if (tmp_prob->type == PROB_TYPE_SELECT_ONE && tmp_prob->xml_file && tmp_prob->xml_file[0]) {
      fprintf(flog, "Select-one XML-specified problem, skipping\n");
      continue;
    }

    prepare_set_prob_value(CNTSPROB_normalization, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_use_stdin, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_use_stdout, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_combined_stdin, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_combined_stdout, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_input_file, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_output_file, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_scoring_checker, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_enable_checker_token, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_interactive_valuer, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_manual_checking, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_enable_testlib_mode, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_examinator_num, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_check_presentation, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_binary_input, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_binary, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_ignore_exit_code, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_ignore_term_signal, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_valuer_cmd, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_interactor_cmd, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_style_checker_cmd, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_test_checker_cmd, tmp_prob, abstr, global);
    //prepare_set_prob_value(CNTSPROB_test_checker_env, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_test_dir, tmp_prob, abstr, 0);
    prepare_set_prob_value(CNTSPROB_use_corr, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_test_sfx, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_test_pat, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_test_score, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_full_score, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_full_user_score, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_solution_cmd, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_solution_src, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_source_header, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_source_footer, tmp_prob, abstr, global);
    mkpath(test_path, g_test_path, tmp_prob->test_dir, "");
    if (tmp_prob->use_corr) {
      prepare_set_prob_value(CNTSPROB_corr_dir, tmp_prob, abstr, 0);
      prepare_set_prob_value(CNTSPROB_corr_sfx, tmp_prob, abstr, global);
      prepare_set_prob_value(CNTSPROB_corr_pat, tmp_prob, abstr, global);
      mkpath(corr_path, g_corr_path, tmp_prob->corr_dir, "");
    }
    prepare_set_prob_value(CNTSPROB_use_info, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_use_tgz, tmp_prob, abstr, global);
    if (tmp_prob->use_info) {
      prepare_set_prob_value(CNTSPROB_info_dir, tmp_prob, abstr, 0);
      prepare_set_prob_value(CNTSPROB_info_sfx, tmp_prob, abstr, global);
      prepare_set_prob_value(CNTSPROB_info_pat, tmp_prob, abstr, global);
      mkpath(info_path, g_info_path, tmp_prob->info_dir, "");
    }
    checker_path[0] = 0;
    if (!tmp_prob->standard_checker) {
      prepare_set_prob_value(CNTSPROB_check_cmd, tmp_prob, abstr, 0);
      if (global->advanced_layout > 0) {
        get_advanced_layout_path(checker_path, sizeof(checker_path),
                                 global, tmp_prob, tmp_prob->check_cmd, -1);
      } else {
        mkpath(checker_path, g_checker_path, tmp_prob->check_cmd, "");
      }
    }

    if (global->advanced_layout > 0) {
      if (prob->variant_num <= 0) {
        if (build_generate_makefile(flog, config, cnts, NULL, sstate, global, tmp_prob, 0) < 0)
          goto cleanup;
        if ((j = invoke_make(flog, config, global, tmp_prob, -1)) < 0)
          goto cleanup;
      } else {
        for (variant = 1; variant <= prob->variant_num; ++variant) {
          if (build_generate_makefile(flog, config, cnts, NULL, sstate, global, tmp_prob, variant) < 0)
            goto cleanup;
          if ((j = invoke_make(flog, config, global, tmp_prob, variant)) < 0)
            goto cleanup;
        }
      }
      continue;
    }

    if (!tmp_prob->standard_checker && !already_compiled) {
      if (prob->variant_num <= 0) {
        if (recompile_checker(config, flog, checker_path) < 0)
          goto cleanup;
      } else {
        for (variant = 1; variant <= prob->variant_num; variant++) {
          if (global->advanced_layout > 0) {
            get_advanced_layout_path(v_checker_path, sizeof(v_checker_path),
                                     global, tmp_prob, NULL, variant);
          } else {
            snprintf(v_checker_path, sizeof(v_checker_path), "%s-%d",
                     checker_path, variant);
          }
          if (recompile_checker(config, flog, v_checker_path) < 0)
            goto cleanup;
        }
      }
    }

    if (prob->type == PROB_TYPE_TESTS) goto skip_tests;

    // check tests
    if (prob->variant_num <= 0) {
      if (global->advanced_layout > 0) {
        get_advanced_layout_path(test_path, sizeof(test_path), global,
                                 tmp_prob, DFLT_P_TEST_DIR, -1);
      }
      if (stat(test_path, &stbuf) < 0) {
        fprintf(flog, "Error: test directory %s does not exist\n", test_path);
        goto cleanup;
      }
      if (!S_ISDIR(stbuf.st_mode)) {
        fprintf(flog, "Error: test directory %s is not a directory\n", test_path);
        goto cleanup;
      }
      if (tmp_prob->use_corr) {
        if (global->advanced_layout > 0) {
          get_advanced_layout_path(corr_path, sizeof(corr_path), global,
                                   tmp_prob, DFLT_P_CORR_DIR, -1);
        }
        if (stat(corr_path, &stbuf) < 0) {
          fprintf(flog, "Error: test directory %s does not exist\n", corr_path);
          goto cleanup;
        }
        if (!S_ISDIR(stbuf.st_mode)) {
          fprintf(flog, "Error: test directory %s is not a directory\n", corr_path);
          goto cleanup;
        }
      }
      if (tmp_prob->use_info) {
        if (global->advanced_layout > 0) {
          get_advanced_layout_path(info_path, sizeof(info_path), global,
                                   tmp_prob, DFLT_P_INFO_DIR, -1);
        }
        if (stat(info_path, &stbuf) < 0) {
          fprintf(flog, "Error: test directory %s does not exist\n", info_path);
          goto cleanup;
        }
        if (!S_ISDIR(stbuf.st_mode)) {
          fprintf(flog, "Error: test directory %s is not a directory\n", info_path);
          goto cleanup;
        }
      }

      test_checker_cmd[0] = 0;
      if (tmp_prob->test_checker_cmd && tmp_prob->test_checker_cmd[0]) {
        if (global->advanced_layout > 0) {
          get_advanced_layout_path(test_checker_cmd, sizeof(test_checker_cmd),
                                   global, tmp_prob,
                                   tmp_prob->test_checker_cmd, -1);
        } else if (os_IsAbsolutePath(tmp_prob->test_checker_cmd)) {
          snprintf(test_checker_cmd, sizeof(test_checker_cmd), "%s",
                   tmp_prob->test_checker_cmd);
        } else {
          snprintf(test_checker_cmd, sizeof(test_checker_cmd), "%s/%s",
                   global->checker_dir, tmp_prob->test_checker_cmd);
        }
        if (access(test_checker_cmd, X_OK) < 0) {
          fprintf(flog, "Error: test checker %s does not exist or non-executable", test_checker_cmd);
          goto cleanup;
        }
      }

      total_tests = 1;
      while (1) {
        k = check_test_file(flog, total_tests, test_path,
                            tmp_prob->test_pat, tmp_prob->test_sfx, 1,
                            tmp_prob->binary_input, file_group, file_mode);
        if (k < 0) goto cleanup;
        if (!k) break;
        total_tests++;
      }
      total_tests--;
      if (!total_tests) {
        fprintf(flog, "Error: no tests defined for the problem\n");
        goto cleanup;
      }
      if (tmp_prob->type > 0 && total_tests != 1) {
        fprintf(flog, "Error: output-only problem must have only one test\n");
        goto cleanup;
      }
      fprintf(flog, "Info: assuming, that there are %d tests for this problem\n",
              total_tests);

      for (j = 1; j <= total_tests; j++) {
        if (tmp_prob->use_corr
            && check_test_file(flog, j, corr_path, tmp_prob->corr_pat,
                               tmp_prob->corr_sfx, 0, tmp_prob->binary_input,
                               file_group, file_mode) <= 0)
          goto cleanup;
        if (tmp_prob->use_info
            && check_test_file(flog, j, info_path, tmp_prob->info_pat,
                               tmp_prob->info_sfx, 0, 0, file_group,
                               file_mode) <= 0)
          goto cleanup;

        if (invoke_test_checker(flog, j, test_checker_cmd,
                                tmp_prob->test_checker_env,
                                test_path, tmp_prob->test_pat,
                                tmp_prob->test_sfx,
                                corr_path, tmp_prob->corr_pat,
                                tmp_prob->corr_sfx) < 0)
          goto cleanup;
      }

      if (tmp_prob->use_corr
          && check_test_file(flog, j, corr_path, tmp_prob->corr_pat,
                             tmp_prob->corr_sfx, 1, tmp_prob->binary_input,
                             file_group, file_mode) != 0) {
        fprintf(flog, "Error: there is answer file for test %d, but no data file\n", j);
        goto cleanup;
      }
      if (tmp_prob->use_info
          && check_test_file(flog, j, info_path, tmp_prob->info_pat,
                             tmp_prob->info_sfx, 1, 0,
                             file_group, file_mode) != 0) {
        fprintf(flog, "Error: there is test info file for test %d, but no data file\n", j);
        goto cleanup;
      }
    } else {
      for (variant = 1; variant <= prob->variant_num; variant++) {
        if (global->advanced_layout > 0) {
          get_advanced_layout_path(v_test_path, sizeof(v_test_path), global,
                                   tmp_prob, DFLT_P_TEST_DIR, variant);
        } else {
          snprintf(v_test_path, sizeof(v_test_path), "%s-%d", test_path,
                   variant);
        }
        if (stat(v_test_path, &stbuf) < 0) {
          fprintf(flog, "Error: test directory %s does not exist\n", v_test_path);
          goto cleanup;
        }
        if (!S_ISDIR(stbuf.st_mode)) {
          fprintf(flog, "Error: test directory %s is not a directory\n", v_test_path);
          goto cleanup;
        }
        if (tmp_prob->use_corr) {
          if (global->advanced_layout > 0) {
            get_advanced_layout_path(v_corr_path, sizeof(v_corr_path), global,
                                     tmp_prob, DFLT_P_INFO_DIR, variant);
          } else {
            snprintf(v_corr_path, sizeof(v_corr_path), "%s-%d", corr_path,
                     variant);
          }
          if (stat(v_corr_path, &stbuf) < 0) {
            fprintf(flog, "Error: test directory %s does not exist\n", v_corr_path);
            goto cleanup;
          }
          if (!S_ISDIR(stbuf.st_mode)) {
            fprintf(flog, "Error: test directory %s is not a directory\n", v_corr_path);
            goto cleanup;
          }
        }
        if (tmp_prob->use_info) {
          if (global->advanced_layout > 0) {
            get_advanced_layout_path(v_info_path, sizeof(v_info_path), global,
                                     tmp_prob, DFLT_P_INFO_DIR, variant);
          } else {
            snprintf(v_info_path, sizeof(v_info_path), "%s-%d", info_path,
                     variant);
          }
          if (stat(v_info_path, &stbuf) < 0) {
            fprintf(flog, "Error: test directory %s does not exist\n", v_info_path);
            goto cleanup;
          }
          if (!S_ISDIR(stbuf.st_mode)) {
            fprintf(flog, "Error: test directory %s is not a directory\n", v_info_path);
            goto cleanup;
          }
        }

        test_checker_cmd[0] = 0;
        if (tmp_prob->test_checker_cmd && tmp_prob->test_checker_cmd[0]) {
          if (global->advanced_layout > 0) {
            get_advanced_layout_path(test_checker_cmd, sizeof(test_checker_cmd),
                                     global, tmp_prob,
                                     tmp_prob->test_checker_cmd, variant);
          } else if (os_IsAbsolutePath(tmp_prob->test_checker_cmd)) {
            snprintf(test_checker_cmd, sizeof(test_checker_cmd), "%s-%d",
                     tmp_prob->test_checker_cmd, variant);
          } else {
            snprintf(test_checker_cmd, sizeof(test_checker_cmd), "%s/%s-%d",
                     global->checker_dir, tmp_prob->test_checker_cmd, variant);
          }
          if (access(test_checker_cmd, X_OK) < 0) {
            fprintf(flog, "Error: test checker %s does not exist or non-executable", test_checker_cmd);
            goto cleanup;
          }
        }

        total_tests = 1;
        while (1) {
          k = check_test_file(flog, total_tests, v_test_path,
                              tmp_prob->test_pat, tmp_prob->test_sfx, 1,
                              tmp_prob->binary_input, file_group, file_mode);
          if (k < 0) goto cleanup;
          if (!k) break;
          total_tests++;
        }
        total_tests--;
        if (!total_tests) {
          fprintf(flog, "Error: no tests defined for the problem\n");
          goto cleanup;
        }
        if (tmp_prob->type > 0 && total_tests != 1) {
          fprintf(flog, "Error: output-only problem must have only one test\n");
          goto cleanup;
        }
        if (variant == 1) {
          fprintf(flog, "Info: assuming, that there are %d tests for this problem\n",
                  total_tests);
          v_total_tests = total_tests;
        } else {
          if (v_total_tests != total_tests) {
            fprintf(flog, "Error: variant 1 defines %d tests, but variant %d defines %d tests\n", v_total_tests, variant, total_tests);
            goto cleanup;
          }
        }

        for (j = 1; j <= total_tests; j++) {
          if (tmp_prob->use_corr
              && check_test_file(flog, j, v_corr_path, tmp_prob->corr_pat,
                                 tmp_prob->corr_sfx, 0, tmp_prob->binary_input,
                                 file_group, file_mode) <= 0)
            goto cleanup;
          if (tmp_prob->use_info
              && check_test_file(flog, j, v_info_path, tmp_prob->info_pat,
                                 tmp_prob->info_sfx, 0, 0, file_group,
                                 file_mode) <= 0)
            goto cleanup;

          if (invoke_test_checker(flog, j, test_checker_cmd,
                                  tmp_prob->test_checker_env,
                                  v_test_path, tmp_prob->test_pat,
                                  tmp_prob->test_sfx,
                                  v_corr_path, tmp_prob->corr_pat,
                                  tmp_prob->corr_sfx) < 0)
            goto cleanup;
        }

        if (tmp_prob->use_corr
            && check_test_file(flog, j, v_corr_path, tmp_prob->corr_pat,
                               tmp_prob->corr_sfx, 1, tmp_prob->binary_input,
                               file_group, file_mode) != 0) {
          fprintf(flog, "Error: there is answer file for test %d, but no data file, variant %d\n", j, variant);
          goto cleanup;
        }
        if (tmp_prob->use_info
            && check_test_file(flog, j, v_info_path, tmp_prob->info_pat,
                               tmp_prob->info_sfx, 1, 0, file_group,
                               file_mode) != 0) {
          fprintf(flog, "Error: there is test info file for test %d, but no data file, variant %d\n", j, variant);
          goto cleanup;
        }
      }
    }

    if (global->score_system != SCORE_ACM
        && global->score_system != SCORE_MOSCOW) {
      if (check_test_score(flog, total_tests, tmp_prob->test_score,
                           tmp_prob->full_score, tmp_prob->test_score_list) < 0)
        goto cleanup;
    }
  }

skip_tests:
  retval = 0;

cleanup:
  tmp_prob = prepare_problem_free(tmp_prob);

  return retval;
}

static __attribute__((unused)) int
vmap_sort_func(const void *v1, const void *v2)
{
  const struct variant_map_item *p1 = (typeof(p1)) v1;
  const struct variant_map_item *p2 = (typeof(p2)) v2;

  if (p1->user_id > 0 && p2->user_id > 0) {
    if (p1->user_id < p2->user_id) return -1;
    if (p1->user_id > p2->user_id) return 1;
    return 0;
  }
  if (p1->user_id > 0) return -1;
  if (p2->user_id > 0) return 1;
  return strcmp(p1->login, p2->login);
}

int
super_html_update_variant_map(FILE *flog, int contest_id,
                              struct userlist_clnt *server_conn,
                              const struct contest_desc *cnts,
                              struct section_global_data *global,
                              int total_probs,
                              struct section_problem_data **probs)
{
#if 0
  int r;
  unsigned char *xml_text = 0;
  struct userlist_list *users = 0;
  path_t conf_dir;
  path_t variant_file;
  struct stat stbuf;
  int var_prob_num, i, n, j, uid;
  struct variant_map *vmap = 0;
  int *tvec = 0, *new_map, *new_rev_map;
  struct userlist_user *user;
  struct userlist_user_info *ui;

  if (!cnts->root_dir && !cnts->root_dir[0]) {
    fprintf(flog, "update_variant_map: contest root_dir is not set");
    goto failed;
  }
  if (!os_IsAbsolutePath(cnts->root_dir)) {
    fprintf(flog, "update_variant_map: contest root_dir is not absolute");
    goto failed;
  }

  if (!global->variant_map) {
    if (!cnts->conf_dir || !cnts->conf_dir[0]) {
      snprintf(conf_dir, sizeof(conf_dir), "%s/conf", cnts->root_dir);
    } else if (!os_IsAbsolutePath(cnts->conf_dir)) {
      snprintf(conf_dir, sizeof(conf_dir), "%s/%s", cnts->root_dir, cnts->conf_dir);
    } else {
      snprintf(conf_dir, sizeof(conf_dir), "%s", cnts->conf_dir);
    }

    if (!global->variant_map_file) {
      xstrdup3(&global->variant_map_file, "variant.map");
    }

    if (!os_IsAbsolutePath(global->variant_map_file)) {
      snprintf(variant_file, sizeof(variant_file), "%s/%s", conf_dir, global->variant_map_file);
    } else {
      snprintf(variant_file, sizeof(variant_file), "%s", global->variant_map_file);
    }

    if (stat(variant_file, &stbuf) < 0) {
      XCALLOC(global->variant_map, 1);
    } else {
      if (!S_ISREG(stbuf.st_mode)) {
        fprintf(flog, "update_variant_map: variant map file %s is not regular file\n",
                variant_file);
        goto failed;
      }

      if (!(global->variant_map = variant_map_parse(flog, 0, variant_file)))
        goto failed;
    }
  }

  if (!(vmap = global->variant_map)) {
    fprintf(flog, "update_variant_map: variant map is not set");
    goto failed;
  }

  // remap problems, if necessary
  for (var_prob_num = 0, i = 1; i < total_probs; i++)
    if (probs[i] && probs[i]->variant_num > 0)
      var_prob_num++;

  if (!var_prob_num) {
    fprintf(flog, "update_variant_map: no variant problems");
    goto failed;
  }

  if (vmap->prob_map) {
    ASSERT(vmap->prob_map_size > 0);
    ASSERT(vmap->prob_rev_map_size > 0);
    ASSERT(vmap->prob_rev_map);
    // update forward and reverse mappings
    XCALLOC(new_map, total_probs);
    memset(new_map, -1, sizeof(new_map[0]) * total_probs);
    XCALLOC(new_rev_map, var_prob_num);
    for (i = 1, j = 0; i < total_probs; i++)
      if (probs[i] && probs[i]->variant_num > 0) {
        new_map[i] = j;
        new_rev_map[j] = i;
        j++;
      }
    for (i = 0; i < vmap->u; i++) {
      XCALLOC(tvec, var_prob_num);
      ASSERT(vmap->v[i].var_num == vmap->prob_rev_map_size);
      for (j = 0; j < vmap->prob_rev_map_size; j++) {
        n = vmap->prob_rev_map[j];
        if (n > 0 && n < total_probs && probs[n] && probs[n]->variant_num > 0)
          tvec[new_map[n]] = vmap->v[i].variants[j];
      }
      xfree(vmap->v[i].variants);
      vmap->v[i].var_num = var_prob_num;
      vmap->v[i].variants = tvec;
    }
    xfree(vmap->prob_map);
    xfree(vmap->prob_rev_map);
    vmap->prob_map = new_map;
    vmap->prob_map_size = total_probs;
    vmap->prob_rev_map = new_rev_map;
    vmap->prob_rev_map_size = var_prob_num;
  } else if (vmap->var_prob_num > 0) {
    // reallocate new array for each entry
    for (i = 0; i < vmap->u; i++) {
      if (vmap->v[i].var_num != var_prob_num) {
        XCALLOC(tvec, var_prob_num);
        if (vmap->v[i].var_num > 0) {
          n = vmap->v[i].var_num;
          if (n > var_prob_num) n = var_prob_num;
          memcpy(tvec, vmap->v[i].variants, n * sizeof(tvec[0]));
          xfree(vmap->v[i].variants);
        }
        vmap->v[i].var_num = var_prob_num;
        vmap->v[i].variants = tvec;
      }
    }
    // create forward and reverse mappings
    vmap->prob_map_size = total_probs;
    XCALLOC(vmap->prob_map, total_probs);
    memset(vmap->prob_map, -1, sizeof(vmap->prob_map[0]) * total_probs);
    vmap->prob_rev_map_size = var_prob_num;
    XCALLOC(vmap->prob_rev_map, var_prob_num);
    for (i = 1, j = 0; i < total_probs; i++)
      if (probs[i] && probs[i]->variant_num > 0) {
        vmap->prob_map[i] = j;
        vmap->prob_rev_map[j] = i;
        j++;
      }
  } else {
    // allocate new array
    for (i = 0; i < vmap->u; i++) {
      vmap->v[i].var_num = var_prob_num;
      XCALLOC(vmap->v[i].variants, var_prob_num);
    }
    // create forward and reverse mappings
    vmap->prob_map_size = total_probs;
    XCALLOC(vmap->prob_map, total_probs);
    memset(vmap->prob_map, -1, sizeof(vmap->prob_map[0]) * total_probs);
    vmap->prob_rev_map_size = var_prob_num;
    XCALLOC(vmap->prob_rev_map, var_prob_num);
    for (i = 1, j = 0; i < total_probs; i++)
      if (probs[i] && probs[i]->variant_num > 0) {
        vmap->prob_map[i] = j;
        vmap->prob_rev_map[j] = i;
        j++;
      }
  }

  if ((r = userlist_clnt_list_all_users(server_conn, ULS_LIST_ALL_USERS,
                                        contest_id, &xml_text)) < 0) {
    fprintf(flog, "update_variant_map: cannot get list of participants\n");
    goto failed;
  }
  if (!(users = userlist_parse_str(xml_text))) {
    fprintf(flog, "update_variant_map: parsing of XML file failed\n");
    goto failed;
  }
  xfree(xml_text); xml_text = 0;

  // find registered users, which are not in the variant map
  for (uid = 1; uid < users->user_map_size; uid++) {
    if (!(user = users->user_map[uid])) continue;
    ui = user->cnts0;
    if (!user->login || !user->login[0]) continue;
    for (i = 0; i < vmap->u; i++)
      if (!strcmp(user->login, vmap->v[i].login))
        break;
    if (i < vmap->u) {
      vmap->v[i].user_id = uid;
      if (vmap->v[i].name && ui && ui->name) {
        if (strcmp(vmap->v[i].name, ui->name)) {
          xfree(vmap->v[i].name);
          vmap->v[i].name = xstrdup(ui->name);
        }
      } else if (ui && ui->name) {
        vmap->v[i].name = xstrdup(ui->name);
      } else {
        xfree(vmap->v[i].name);
        vmap->v[i].name = 0;
      }
      continue;
    }
    if (vmap->u >= vmap->a) {
      if (!vmap->a) vmap->a = 32;
      vmap->a *= 2;
      vmap->v = (typeof(vmap->v)) xrealloc(vmap->v,
                                           vmap->a * sizeof(vmap->v[0]));
    }
    memset(&vmap->v[vmap->u], 0, sizeof(vmap->v[vmap->u]));
    vmap->v[vmap->u].login = xstrdup(user->login);
    vmap->v[vmap->u].user_id = uid;
    vmap->v[vmap->u].var_num = vmap->prob_rev_map_size;
    vmap->v[vmap->u].name = 0;
    if (ui && ui->name) vmap->v[vmap->u].name = xstrdup(ui->name);
    XCALLOC(vmap->v[vmap->u].variants, vmap->prob_rev_map_size);
    vmap->u++;
  }
  userlist_free(&users->b); users = 0;

  // sort the entries by the user_id
  qsort(vmap->v, vmap->u, sizeof(vmap->v[0]), vmap_sort_func);

  return 0;

 failed:
  xfree(xml_text);
  if (users) userlist_free(&users->b);
  return -1;
#endif
  return 0;
}

int
super_html_variant_param(struct sid_state *sstate, int cmd,
                         int map_i, const unsigned char *param2,
                         int param3, int param4)
{
#if 0
  struct variant_map *vmap = 0;
  const unsigned char *s;
  int n, total, i;
  int *vars = 0;
  struct section_problem_data *prob = 0;

  if (!sstate || !sstate->global) return -SSERV_ERR_INVALID_PARAMETER;
  if (!(vmap = sstate->global->variant_map)) return -SSERV_ERR_INVALID_PARAMETER;
  if (map_i < 0 || map_i >= vmap->u) return -SSERV_ERR_INVALID_PARAMETER;
  if (!sstate->prob_a || !sstate->probs) return -SSERV_ERR_INVALID_PARAMETER;

  s = param2;
  if (sscanf(s, "%d%n", &total, &n) != 1) return -SSERV_ERR_INVALID_PARAMETER;
  s += n;
  if (total < 0 || total != vmap->prob_rev_map_size)
    return -SSERV_ERR_INVALID_PARAMETER;
  XALLOCAZ(vars, total);
  for (i = 0; i < total; i++) {
    if (sscanf(s, "%d%n", &vars[i], &n) != 1) return -SSERV_ERR_INVALID_PARAMETER;
    s += n;
    if (vars[i] < 0 || vmap->prob_rev_map[i] <= 0
        || vmap->prob_rev_map[i] >= sstate->prob_a
        || !(prob = sstate->probs[vmap->prob_rev_map[i]]))
      return -SSERV_ERR_INVALID_PARAMETER;
    if (prob->variant_num <= 0 || vars[i] > prob->variant_num)
      return -SSERV_ERR_INVALID_PARAMETER;
  }

  switch (cmd) {
  case SSERV_CMD_PROB_DELETE_VARIANTS:
    if (vmap->v[map_i].user_id > 0) {
      for (i = 0; i < total; i++)
        vmap->v[map_i].variants[i] = 0;
    } else {
      xfree(vmap->v[map_i].variants);
      xfree(vmap->v[map_i].login);
      xfree(vmap->v[map_i].name);
      if (map_i < vmap->u - 1)
        memmove(&vmap->v[map_i], &vmap->v[map_i + 1],
                (vmap->u - map_i - 1) * sizeof(vmap->v[0]));
      vmap->u--;
    }
  case SSERV_CMD_PROB_CHANGE_VARIANTS:
    for (i = 0; i < total; i++)
      vmap->v[map_i].variants[i] = vars[i];
    break;
  default:
    abort();
  }
#endif
  return 0;
}

int
super_html_variant_prob_op(struct sid_state *sstate, int cmd, int prob_id)
{
#if 0
  struct variant_map *vmap = 0;
  struct section_problem_data *prob = 0;
  int j, i;

  if (!sstate || !sstate->global) return -SSERV_ERR_INVALID_PARAMETER;
  if (!(vmap = sstate->global->variant_map)) return-SSERV_ERR_INVALID_PARAMETER;
  if (!sstate->prob_a || !sstate->probs) return -SSERV_ERR_INVALID_PARAMETER;
  if (prob_id <= 0 || prob_id >= sstate->prob_a)
    return -SSERV_ERR_INVALID_PARAMETER;
  if (!(prob = sstate->probs[prob_id])) return -SSERV_ERR_INVALID_PARAMETER;
  if (prob->variant_num <= 0) return -SSERV_ERR_INVALID_PARAMETER;
  j = vmap->prob_map[prob_id];
  if (j < 0 || j >= vmap->prob_map_size) return -SSERV_ERR_INVALID_PARAMETER;

  switch (cmd) {
  case SSERV_CMD_PROB_CLEAR_VARIANTS:
    for (i = 0; i < vmap->u; i++)
      vmap->v[i].variants[j] = 0;
    break;
  case SSERV_CMD_PROB_RANDOM_VARIANTS:
    for (i = 0; i < vmap->u; i++) {
      if (prob->variant_num == 1) {
        vmap->v[i].variants[j] = 1;
        continue;
      }
      vmap->v[i].variants[j] = random_range(1, prob->variant_num + 1);
    }
    break;
  default:
    return -SSERV_ERR_INVALID_PARAMETER;
  }
#endif
  return 0;
}
