/* -*- c -*- */

/* Copyright (C) 2004-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/varsubst.h"
#include "ejudge/errlog.h"
#include "ejudge/serve_state.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <string.h>

static const unsigned char *
get_var_value(
        const serve_state_t state,
        const unsigned char *varname,
        const struct config_parse_info *global_vars,
        const struct config_parse_info *problem_vars,
        const struct config_parse_info *language_vars,
        const struct config_parse_info *tester_vars,
        const struct section_problem_data *prob,
        const struct section_language_data *lang,
        const struct section_tester_data *tester)
{
  int i;
  const unsigned char *valstr = 0;
  const struct config_parse_info *actual_parse_info = NULL;
  const void *actual_data = NULL;
  const unsigned char *orig_varname = varname;

  if (!strncmp(varname, "problem.", 8)) {
    actual_parse_info = problem_vars;
    actual_data = prob;
    varname += 8;
  } else if (!strncmp(varname, "language.", 9)) {
    actual_parse_info = language_vars;
    actual_data = lang;
    varname += 9;
  } else if (!strncmp(varname, "tester.", 7)) {
    actual_parse_info = tester_vars;
    actual_data = tester;
    varname += 7;
  } else if (!strncmp(varname, "global.", 7)) {
    actual_parse_info = global_vars;
    actual_data = state->global;
    varname += 7;
  } else {
    actual_parse_info = global_vars;
    actual_data = state->global;
  }
  // search in global variables
  for (i = 0; actual_parse_info[i].name; i++) {
    if (!strcmp(actual_parse_info[i].name, varname)) break;
  }
  if (!actual_parse_info[i].name) {
    err("configuration variable `%s' does not exist", orig_varname);
    return 0;
  }
  if (!strcmp(actual_parse_info[i].type, "s")) {
    if (!actual_data) {
      err("configuration variable '%s' section is NULL", orig_varname);
      return 0;
    }
    valstr = XPDEREF(unsigned char, actual_data, actual_parse_info[i].offset);
    return valstr;
  } else if (!strcmp(actual_parse_info[i].type, "S")) {
    if (!actual_data) {
      err("configuration variable '%s' section is NULL", orig_varname);
      return 0;
    }
    valstr = *(XPDEREF(unsigned char *, actual_data, actual_parse_info[i].offset));
    return valstr;
  } else {
    err("configuration variable `%s' has invalid type `%s'", varname, actual_parse_info[i].type);
    return 0;
  }
}

unsigned char *
varsubst_heap(
        const serve_state_t state,
        unsigned char *in_str,
        int free_flag,
        const struct config_parse_info *global_vars,
        const struct config_parse_info *problem_vars,
        const struct config_parse_info *language_vars,
        const struct config_parse_info *tester_vars,
        const struct section_problem_data *prob,
        const struct section_language_data *lang,
        const struct section_tester_data *tester)
{
  unsigned char *orig_in_str = in_str;
  unsigned char *out_str = 0, *p1, *p2;
  unsigned char *var_name = 0;
  size_t var_name_size = 0, in_str_len = 0, var_value_len = 0;
  const unsigned char *var_value = 0;

  //fprintf(stderr, ">>%s\n", in_str);

  in_str_len = strlen(in_str);
  while (1) {
    // find the first variable use
    p1 = in_str;
    for (p1 = in_str; *p1; p1++) {
      if (*p1 == '$' && p1[1] == '{') break;
    }
    if (!*p1) break;
    p2 = p1 + 2;
    while (*p2 && *p2 != '}') p2++;
    if (!*p2 || p2 == p1 + 2) {
      err("varsubst_heap: invalid variable name in %s", in_str);
      if (free_flag) xfree(in_str);
      xfree(var_name);
      return 0;
    }
    if (p2 - p1 > var_name_size) {
      var_name_size = p2 - p1;
      xfree(var_name);
      var_name = xmalloc(var_name_size);
    }
    memcpy(var_name, p1 + 2, p2 - p1 - 2);
    var_name[p2 - p1 - 2] = 0;
    var_value = get_var_value(state, var_name, global_vars, problem_vars,
                              language_vars, tester_vars, prob, lang, tester);
    if (!var_value) {
      if (free_flag) xfree(in_str);
      xfree(var_name);
      return 0;
    }
    var_value_len = strlen(var_value);
    out_str = xmalloc(in_str_len + var_value_len + 1);
    memcpy(out_str, in_str, p1 - in_str);
    memcpy(out_str + (p1 - in_str), var_value, var_value_len);
    strcpy(out_str + (p1 - in_str) + var_value_len, p2 + 1);

    if (free_flag) xfree(in_str);
    in_str = out_str;
    in_str_len = strlen(in_str);
    free_flag = 1;
  }
  xfree(var_name);

  //fprintf(stderr, ">>%s\n", in_str);

  // find whether there are dollar substitutions
  for (p1 = in_str; *p1; p1++) {
    if (*p1 == '$' && p1[1] == '$') break;
  }
  if (!*p1) {
    if (free_flag) {
      /*
      if (orig_in_str != in_str) {
        xfree(orig_in_str);
      }
      */
    } else {
      if (orig_in_str == in_str) {
        in_str = xstrdup(in_str);
      }
    }
    return in_str;
  }

  out_str = xmalloc(in_str_len + 1);
  for (p1 = in_str, p2 = out_str; *p1; p1++, p2++) {
    *p2 = *p1;
    if (*p1 == '$' && p1[1] == '$') p1++;
  }
  if (free_flag) xfree(in_str);
  return out_str;
}

static const unsigned char * const configure_names[] =
{
  "@lang_config_dir@",
  "@prefix@",
  "@exec_prefix@",
  "@libexecdir@",
  "@local_dir@",
  "@contests_home_dir@",
  0
};
static const unsigned char * const configure_values[] =
{
#if defined EJUDGE_LANG_CONFIG_DIR
  EJUDGE_LANG_CONFIG_DIR,
#else
  "",
#endif
#if defined EJUDGE_PREFIX_DIR
  EJUDGE_PREFIX_DIR,
#else
  "",
#endif
#if defined EJUDGE_PREFIX_DIR
  EJUDGE_PREFIX_DIR,
#else
  "",
#endif
#if defined EJUDGE_LIBEXEC_DIR
  EJUDGE_LIBEXEC_DIR,
#else
    "",
#endif
#if defined EJUDGE_LOCAL_DIR
  EJUDGE_LOCAL_DIR,
#else
  "",
#endif
#if defined EJUDGE_CONTESTS_HOME_DIR
  EJUDGE_CONTESTS_HOME_DIR,
#else
  "",
#endif
  0
};

static unsigned char *
do_substitute(
        unsigned char *txt,
        const unsigned char * const *names,
        const unsigned char * const *values)
{
  int i, nlen, vlen, tlen;
  unsigned char *pp;
  unsigned char *txt2 = 0;

  if (!txt || !*txt) return txt;

  while (1) {
    pp = 0;
    for (i = 0; names[i]; i++)
      if ((pp = strstr(txt, names[i])))
        break;
    if (!pp) break;

    ASSERT(values[i]);
    nlen = strlen(names[i]);
    vlen = strlen(values[i]);
    tlen = strlen(txt);

    ASSERT(nlen > 0);
    txt2 = (unsigned char*) xmalloc(tlen - nlen + vlen + 1);
    sprintf(txt2, "%.*s%s%s", (int) (pp - txt), txt, values[i], pp + nlen);
    xfree(txt); txt = txt2; txt2 = 0;
  }

  return txt;
}

unsigned char *
config_var_substitute_heap(unsigned char *txt)
{
  return do_substitute(txt, configure_names, configure_values);
}

unsigned char *
config_var_substitute_buf(unsigned char *buf, size_t bufsize)
{
  /* optimize it? */
  unsigned char *s = config_var_substitute_heap(xstrdup(buf));
  snprintf(buf, bufsize, "%s", s);
  xfree(s);
  return buf;
}
