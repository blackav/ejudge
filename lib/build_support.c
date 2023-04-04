/* -*- c -*- */

/* Copyright (C) 2012-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/build_support.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/ej_process.h"
#include "ejudge/serve_state.h"
#include "ejudge/prepare.h"
#include "ejudge/prepare_dflt.h"
#include "ejudge/super-serve.h"
#include "ejudge/super_proto.h"
#include "ejudge/file_perms.h"
#include "ejudge/fileutl.h"
#include "ejudge/misctext.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>

#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

static const unsigned char ej_makefile_begin[] = "### BEGIN ejudge auto-generated makefile ###";
static const unsigned char ej_makefile_end[] = "### END ejudge auto-generated makefile ###";

struct source_suffixes_s
{
  unsigned char *suffix;
  unsigned long mask;
};
static const struct source_suffixes_s source_suffixes[] =
{
  { ".c", LANG_C },
  { ".cpp", LANG_CPP },
  { ".java", LANG_JAVA },
  { ".pas", LANG_FPC },
  { ".dpr", LANG_DCC },
  { ".py", LANG_PY },
  { ".pl", LANG_PL },
  { ".sh", LANG_SH },
  { ".kum", LANG_KUM },
  { ".go", LANG_GO },
  { 0, 0 },
};

const unsigned char *
build_get_source_suffix(int mask)
{
  int i;
  for (i = 0; source_suffixes[i].suffix; ++i) {
    if (source_suffixes[i].mask == mask)
      return source_suffixes[i].suffix;
  }
  return NULL;
}

unsigned long
build_find_suffix(const unsigned char *str)
{
  if (!str || !*str) return 0;
  int len = strlen(str);
  for (int i = 0; source_suffixes[i].suffix; ++i) {
    int len2 = strlen(source_suffixes[i].suffix);
    if (len >= len2 && !strcmp(str + len - len2, source_suffixes[i].suffix))
      return source_suffixes[i].mask;
  }
  return 0;
}

unsigned long
build_guess_language_by_cmd(unsigned char *cmd, int *p_count)
{
  int len, i;
  unsigned char path2[PATH_MAX];
  struct stat stb;
  unsigned long mask = 0;
  int count = 0;

  if (!cmd || !*cmd) return 0;
  len = strlen(cmd);
  i = len - 1;
  while (i >= 0 && cmd[i] != '/' && cmd[i] != '.') --i;
  if (i >= 0 && cmd[i] == '.') {
    if (!strcmp(cmd + i, ".class") || !strcmp(cmd + i, ".jar")) {
      if (i > 0 && cmd[i - 1] != '/' && cmd[i - 1] != '.') {
        cmd[i] = 0;
        mask |= LANG_JAVA;
        ++count;
      }
    } else if (!strcmp(cmd + i, ".exe")) {
      if (i > 0 && cmd[i - 1] != '/' && cmd[i - 1] != '.') {
        cmd[i] = 0;
      }
    }
  }
  for (i = 0; source_suffixes[i].suffix; ++i) {
    snprintf(path2, sizeof(path2), "%s%s", cmd, source_suffixes[i].suffix);
    if (access(path2, R_OK) >= 0 && stat(path2, &stb) >= 0 && S_ISREG(stb.st_mode)
        && !(mask & source_suffixes[i].mask)) {
      mask |= source_suffixes[i].mask;
      ++count;
    }
  }
  if (p_count) *p_count = count;
  return mask;
}

unsigned long
build_guess_language_by_src(const unsigned char *src)
{
  int len, i, j;

  if (!src || !*src) return 0;
  len = strlen(src);
  i = len - 1;
  while (i >= 0 && src[i] != '/' && src[i] != '.') --i;
  if (i <= 0 || src[i] == '/') return 0;
  if (src[i - 1] == '/' || src[i - 1] == '.') return 0;
  for (j = 0; source_suffixes[j].suffix; ++j) {
    if (!strcmp(src + i, source_suffixes[j].suffix))
      return source_suffixes[j].mask;
  }
  return 0;
}

unsigned char *
build_get_compiler_script(
        FILE *log_f,
        const struct ejudge_cfg *config,
        const unsigned char *script_dir_default,
        const unsigned char *lang_short_name)
{
  unsigned char script_dir[PATH_MAX];
  unsigned char compiler_script[PATH_MAX];

  script_dir[0] = 0;
  if (script_dir_default && script_dir_default[0]) {
    snprintf(script_dir, sizeof(script_dir), "%s", script_dir_default);
  }
  if (!script_dir[0] && config && config->compile_home_dir) {
    snprintf(script_dir, sizeof(script_dir), "%s/scripts",
             config->compile_home_dir);
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!script_dir[0]) {
    snprintf(script_dir, sizeof(script_dir), "%s/compile/scripts",
             EJUDGE_CONTESTS_HOME_DIR);
  }
#endif
  snprintf(compiler_script, sizeof(compiler_script), "%s/%s", script_dir, lang_short_name);
  return xstrdup(compiler_script);
}

unsigned char *
build_get_compiler_path(
        FILE *log_f,
        const struct ejudge_cfg *config,
        const unsigned char *script_dir_default,
        const unsigned char *lang_short_name)
{
  unsigned char script_dir[PATH_MAX];
  unsigned char version_script[PATH_MAX];
  char *args[3];
  unsigned char *stdout_text = NULL;
  unsigned char *stderr_text = NULL;
  int retval = 0, slen;

  script_dir[0] = 0;
  if (script_dir_default && script_dir_default[0]) {
    snprintf(script_dir, sizeof(script_dir), "%s", script_dir_default);
  }
  if (!script_dir[0] && config && config->compile_home_dir) {
    snprintf(script_dir, sizeof(script_dir), "%s/scripts",
             config->compile_home_dir);
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!script_dir[0]) {
    snprintf(script_dir, sizeof(script_dir), "%s/compile/scripts",
             EJUDGE_CONTESTS_HOME_DIR);
  }
#endif
  snprintf(version_script, sizeof(version_script), "%s/%s-version", script_dir, lang_short_name);
  args[0] = version_script;
  args[1] = "-p";
  args[2] = NULL;
  retval = ejudge_invoke_process(args, NULL, NULL, NULL, NULL, 0, &stdout_text, &stderr_text);
  if (retval != 0) {
    if (stderr_text && *stderr_text) {
      fprintf(log_f, "%s failed:\n---\n%s\n---\n", version_script, stderr_text);
    } else {
      fprintf(log_f, "%s failed\n", version_script);
    }
    xfree(stdout_text);
    xfree(stderr_text);
    return NULL;
  }
  xfree(stderr_text); stderr_text = NULL;
  if (!stdout_text || !*stdout_text) {
    fprintf(log_f, "%s output is empty\n", version_script);
    xfree(stdout_text);
    return NULL;
  }
  slen = strlen(stdout_text);
  while (slen > 0 && isspace(stdout_text[slen - 1])) --slen;
  stdout_text[slen] = 0;
  if (!slen) {
    fprintf(log_f, "%s output is empty\n", version_script);
    xfree(stdout_text);
    return NULL;
  }
  return stdout_text;
}

static const unsigned char *
build_get_compiler_flags(
        serve_state_t cs,
        struct sid_state *sstate,
        const unsigned char *lang_short_name)
{
  static const unsigned char compiler_flags_prefix[] = "EJUDGE_FLAGS=";

  int lang_id, i;
  const struct section_language_data *lang;

  if (cs) {
    for (lang_id = 1; lang_id <= cs->max_lang; ++lang_id) {
      if (!(lang = cs->langs[lang_id]) || strcmp(lang->short_name, lang_short_name)) continue;
      if (!lang->compiler_env) return NULL;
      for (i = 0; lang->compiler_env[i]; ++i) {
        if (!strncmp(compiler_flags_prefix, lang->compiler_env[i], sizeof(compiler_flags_prefix) - 1))
          return lang->compiler_env[i] + sizeof(compiler_flags_prefix) - 1;
      }
    }
  } else if (sstate) {
    if (sstate->lang_a <= 0 || !sstate->langs || !sstate->lang_opts) return NULL;
    for (lang_id = 1; lang_id < sstate->lang_a; ++lang_id) {
      if (!(lang = sstate->langs[lang_id]) || strcmp(lang->short_name, lang_short_name)) continue;
      return sstate->lang_opts[lang_id];
    }
  }
  return NULL;
}

static unsigned char **
build_collect_suitable_names(const unsigned char *path, unsigned long *p_mask)
{
  unsigned char **names = NULL;
  int names_a = 0, names_u = 0;
  unsigned long m;
  DIR *d = NULL;
  struct dirent *dd;
  unsigned char path2[PATH_MAX];
  struct stat stb;

  if (!(d = opendir(path))) return NULL;
  while ((dd = readdir(d))) {
    if (dd->d_name[0] == '.') continue;
    snprintf(path2, sizeof(path2), "%s/%s", path, dd->d_name);
    if (stat(path2, &stb) < 0) continue;
    if (!S_ISREG(stb.st_mode)) continue;
    if (!(m = build_find_suffix(dd->d_name))) continue;
    if (!names) {
      names_a = 8;
      XCALLOC(names, names_a);
    } else if (names_u >= names_a - 1) {
      names_a *= 2;
      XREALLOC(names, names_a);
    }
    names[names_u++] = xstrdup(dd->d_name);
    names[names_u] = NULL;
    if (p_mask) *p_mask |= m;
  }
  closedir(d);

  return names;
}

static unsigned char *
build_remove_src_suffix(const unsigned char *str)
{
  if (!str || !*str) return NULL;
  int len = strlen(str);
  for (int i = 0; source_suffixes[i].suffix; ++i) {
    int len2 = strlen(source_suffixes[i].suffix);
    if (len > len2 && !strcmp(str + len - len2, source_suffixes[i].suffix))
      return xmemdup(str, len - len2);
  }
  return 0;
}

static unsigned char **
build_make_exe_suitable_names(unsigned char **names)
{
  unsigned char **exes = NULL;
  if (!names) return NULL;
  int count;
  for (count = 0; names[count]; ++count) {}
  XCALLOC(exes, count + 1);
  for (int i = 0; i < count; ++i) {
    exes[i] = build_remove_src_suffix(names[i]);
  }
  return exes;
}

static unsigned char **
build_free_suitable_names(unsigned char **ss)
{
  if (ss) {
    for (int i = 0; ss[i]; ++i) {
      xfree(ss[i]);
    }
    xfree(ss);
  }
  return NULL;
}

const unsigned char *
build_replace_cmd_suffix(unsigned char *buf, int size, const unsigned char *cmd, const unsigned char *suffix)
{
  int len, i;

  if (!cmd || !*cmd) {
    buf[0] = 0;
    return buf;
  }
  if (!suffix) suffix = "";
  len = strlen(cmd);
  i = len - 1;
  while (i >= 0 && cmd[i] != '/' && cmd[i] != '.') --i;
  if (i >= 0 && cmd[i] == '.') {
    if (!strcmp(cmd + i, ".class") || !strcmp(cmd + i, ".jar") || !strcmp(cmd + i, ".exe")) {
      snprintf(buf, size, "%.*s%s", i, cmd, suffix);
      return buf;
    }
  }
  snprintf(buf, size, "%s%s", cmd, suffix);
  return buf;
}

static int
is_makefile_rule_needed(const unsigned char *path);

static void
build_generate_checker_compilation_rule(
        FILE *out_f,
        const unsigned char *what,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        int variant,
        const unsigned char *cmd)
{
  unsigned char tmp_path[PATH_MAX];
  unsigned long languages = 0;
  const unsigned char *source_suffix = NULL;
  int count = 0;

  if (!is_makefile_rule_needed(cmd)) return;

  get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, cmd, variant);
  languages = build_guess_language_by_cmd(tmp_path, &count);
  if (count <= 0) {
    fprintf(out_f, "# no known source language is detected for %s '%s'\n", what, cmd);
  } else if (count > 1) {
    fprintf(out_f, "# several source languages are detected for %s '%s'\n", what, cmd);
  } else {
    source_suffix = build_get_source_suffix(languages);
    if (languages == LANG_C) {
      fprintf(out_f, "%s : %s%s\n", cmd, cmd, source_suffix);
      fprintf(out_f, "\t${CC} -DEJUDGE  ${CLIBCHECKERFLAGS} %s%s -o%s ${CLIBCHECKERLIBS}\n",
              cmd, source_suffix, cmd);
    } else if (languages == LANG_CPP) {
      fprintf(out_f, "%s : %s%s\n", cmd, cmd, source_suffix);
      fprintf(out_f, "\t${CXX} -DEJUDGE ${CXXLIBCHECKERFLAGS} %s%s -o%s ${CXXLIBCHECKERLIBS}\n",
              cmd, source_suffix, cmd);
    } else if (languages == LANG_FPC) {
      fprintf(out_f, "%s: %s%s\n", cmd, cmd, source_suffix);
      fprintf(out_f, "\t${FPC} -dEJUDGE ${FPCTESTLIBFLAGS} %s%s\n", cmd, source_suffix);
    } else if (languages == LANG_DCC) {
      fprintf(out_f, "%s: %s%s\n", cmd, cmd, source_suffix);
      fprintf(out_f, "\t${DCC} -DEJUDGE ${DCCTESTLIBFLAGS} %s%s\n", cmd, source_suffix);
    } else if (languages == LANG_JAVA) {
      fprintf(out_f, "%s: %s%s\n", cmd, cmd, source_suffix);
      if (prob && prob->enable_testlib_mode > 0) {
        fprintf(out_f, "\t${JAVAC} -cp testlib4j.jar %s%s\n", cmd, source_suffix);
        fprintf(out_f, "\t${JAR} cf %s.jar *.class\n", cmd);
        fprintf(out_f, "\trm -f *.class\n");
        fprintf(out_f, "\techo '#! /bin/sh' > %s\n", cmd);
        fprintf(out_f, "\techo 'd=\"`dirname $$0`\"' >> %s\n", cmd);
        fprintf(out_f, "\techo 'exec ${JAVA} -DEJUDGE=1 -cp \"$$d/testlib4j.jar:$$d/%s.jar\" ru.ifmo.testlib.CheckerFramework %s \"$$@\"' >> %s\n", cmd, cmd, cmd);
        fprintf(out_f, "\tchmod +x %s\n", cmd);
      } else {
        fprintf(out_f, "\t${JAVACHELPER} %s%s %s.jar\n", cmd, source_suffix, cmd);
        fprintf(out_f, "\trm -f *.class\n");
        fprintf(out_f, "\techo '#! /bin/sh' > %s\n", cmd);
        fprintf(out_f, "\techo 'd=\"`dirname $$0`\"' >> %s\n", cmd);
        fprintf(out_f, "\techo 'exec ${JAVA} -jar %s.jar \"$$@\"' >> %s\n", cmd, cmd);
        fprintf(out_f, "\tchmod +x %s\n", cmd);
      }
    } else if (languages == LANG_PY) {
      fprintf(out_f, "%s: %s%s\n", cmd, cmd, source_suffix);
      fprintf(out_f, "\t${PYCHELPER} %s%s %s\n", cmd, source_suffix, cmd);
    } else if (languages == LANG_GO) {
      fprintf(out_f, "%s: %s%s\n", cmd, cmd, source_suffix);
      fprintf(out_f, "\t${GOCHELPER} %s%s %s\n", cmd, source_suffix, cmd);
    } else {
      fprintf(out_f, "# no information how to build %s '%s'\n", what, cmd);
    }
  }
  fprintf(out_f, "\n");
}

static void
build_generate_solution_compilation_rule(
        FILE *mk_f,
        const unsigned char *dir_prefix,
        const unsigned char *exe_name,
        const unsigned char *src_name,
        const unsigned char *src_suffix,
        unsigned long language)
{
  unsigned char full_src_name[PATH_MAX];
  unsigned char full_exe_name[PATH_MAX];
  unsigned char last_src_name[PATH_MAX];
  unsigned char last_exe_name[PATH_MAX];
  const unsigned char *sep = "/";
  unsigned char cd_cmd[PATH_MAX];

  if (!dir_prefix || !*dir_prefix) {
    dir_prefix = "";
    sep = "";
  } else if (!strcmp(dir_prefix, "/")) {
    sep = "";
  }
  cd_cmd[0] = 0;
  if (dir_prefix && *dir_prefix) {
    snprintf(cd_cmd, sizeof(cd_cmd), "cd \"%s\" && ", dir_prefix);
  }

  // FIXME: transform exe_name to src_name correctly
  if (src_name && !src_suffix && !language) {
    // check for exe_name != NULL
    language = build_guess_language_by_src(src_name);
    src_suffix = build_get_source_suffix(language);
    snprintf(full_src_name, sizeof(full_src_name), "%s%s%s", dir_prefix, sep, src_name);
    snprintf(last_src_name, sizeof(last_src_name), "%s", src_name);
    snprintf(full_exe_name, sizeof(full_exe_name), "%s%s%s", dir_prefix, sep, exe_name);
    snprintf(last_exe_name, sizeof(last_exe_name), "%s", exe_name);
  } else if (!src_name && language) {
    src_suffix = build_get_source_suffix(language);
    src_name = exe_name;
    snprintf(full_src_name, sizeof(full_src_name), "%s%s%s%s", dir_prefix, sep, src_name, src_suffix);
    snprintf(last_src_name, sizeof(last_src_name), "%s%s", src_name, src_suffix);
    snprintf(full_exe_name, sizeof(full_exe_name), "%s%s%s", dir_prefix, sep, exe_name);
    snprintf(last_exe_name, sizeof(last_exe_name), "%s", exe_name);
  } else if (!src_name && src_suffix) {
    language = build_guess_language_by_src(src_suffix);
    src_name = exe_name;
    snprintf(full_src_name, sizeof(full_src_name), "%s%s%s%s", dir_prefix, sep, src_name, src_suffix);
    snprintf(last_src_name, sizeof(last_src_name), "%s%s", src_name, src_suffix);
    snprintf(full_exe_name, sizeof(full_exe_name), "%s%s%s", dir_prefix, sep, exe_name);
    snprintf(last_exe_name, sizeof(last_exe_name), "%s", exe_name);
  }

  if (language == LANG_C) {
    fprintf(mk_f, "%s : %s\n", full_exe_name, full_src_name);
    fprintf(mk_f, "\t%s${CC} -DEJUDGE ${CFLAGS} %s -o%s ${CLIBS}\n",
            cd_cmd, last_src_name, last_exe_name);
  } else if (language == LANG_CPP) {
    fprintf(mk_f, "%s : %s\n", full_exe_name, full_src_name);
    fprintf(mk_f, "\t%s${CXX} -DEJUDGE ${CXXFLAGS} %s -o%s ${CXXLIBS}\n",
            cd_cmd, last_src_name, last_exe_name);
  } else if (language == LANG_FPC) {
    fprintf(mk_f, "%s : %s\n", full_exe_name, full_src_name);
    fprintf(mk_f, "\t%s${FPC} -dEJUDGE ${FPCFLAGS} %s\n", cd_cmd, last_src_name);
  } else if (language == LANG_DCC) {
    fprintf(mk_f, "%s : %s\n", full_exe_name, full_src_name);
    fprintf(mk_f, "\t%s${DCC} -DEJUDGE ${DCCFLAGS} %s\n", cd_cmd, last_src_name);
  } else if (language == LANG_JAVA) {
    fprintf(mk_f, "%s : %s\n", full_exe_name, full_src_name);
    fprintf(mk_f, "\t%s${JAVACHELPER} %s %s%s\n", cd_cmd, last_src_name, last_exe_name, ".jar");
    fprintf(mk_f, "\t%srm -f *.class\n", cd_cmd);
    fprintf(mk_f, "\t%secho '#! /bin/sh' > %s\n", cd_cmd, last_exe_name);
    fprintf(mk_f, "\t%secho 'd=\"`dirname $$0`\"' >> %s\n", cd_cmd, last_exe_name);
    fprintf(mk_f, "\t%secho 'exec ${JAVA} -DEJUDGE=1 -jar \"$$d/%s.jar\" \"$$@\"' >> %s\n",
            cd_cmd, last_exe_name, last_exe_name);
    fprintf(mk_f, "\t%schmod +x %s\n", cd_cmd, last_exe_name);
  } else if (language == LANG_PY) {
    fprintf(mk_f, "%s : %s\n", full_exe_name, full_src_name);
    fprintf(mk_f, "\t%s${PYCHELPER} %s %s\n", cd_cmd, last_src_name, last_exe_name);
  } else if (language == LANG_GO) {
    fprintf(mk_f, "%s : %s\n", full_exe_name, full_src_name);
    fprintf(mk_f, "\t%s${GOCHELPER} %s %s\n", cd_cmd, last_src_name, last_exe_name);
  } else if (language == LANG_KUM) {
    fprintf(mk_f, "%s : %s\n", full_exe_name, full_src_name);
    fprintf(mk_f, "\t%s${KUMCHELPER} %s %s\n", cd_cmd, last_src_name, last_exe_name);
  }
}

static void
build_pattern_to_shell_pattern(
        unsigned char *buf,
        int len,
        const unsigned char *pattern)
{
  const unsigned char *src = pattern;
  unsigned char *dst = buf;
  int width = -1, prec = -1;

  while (*src) {
    if (*src == '%') {
      ++src;
      if (!*src) continue;
      if (*src == '%') {
        *dst++ = *src++;
        continue;
      }
      if (*src == '#' || *src == '0' || *src == '-' || *src == ' ' || *src == '+' || *src == '\'' || *src == 'I') {
        ++src;
      }
      if (*src >= '0' && *src <= '9') {
        width = 0;
        while (*src >= '0' && *src <= '9') {
          width = width * 10 + (*src - '0');
          ++src;
        }
      }
      if (*src == '.') {
        ++src;
        if (*src >= '0' && *src <= '9') {
          prec = 0;
          while (*src >= '0' && *src <= '9') {
            prec = prec * 10 + (*src - '0');
            ++src;
          }
        }
      }
      if (*src == 'h') {
        ++src;
        if (*src == 'h') ++src;
      } else if (*src == 'l') {
        ++src;
        if (*src == 'l') ++src;
      } else if (*src == 'L' && *src == 'q' && *src == 'j' && *src == 'z' && *src == 't') {
        ++src;
      }
      if (*src == 'd' || *src == 'i' || *src == 'o' || *src == 'u' || *src == 'x' || *src == 'X'
          || *src == 'e' || *src == 'E' || *src == 'f' || *src == 'F'
          || *src == 'g' || *src == 'G' || *src == 'a' || *src == 'A'
          || *src == 'c' || *src == 's' || *src == 'p' || *src == 'n'
          || *src == 'C' || *src == 'S' || *src == 'm') {
        ++src;
        if (width <= 0) {
          *dst++ = '*';
        } else {
          for (; width; --width) {
            *dst++ = '?';
          }
        }
      }
    } else {
      *dst++ = *src++;
    }
  }
  *dst = 0;
}

int
build_prepare_test_file_names(
        FILE *log_f,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        int variant,
        const unsigned char *pat_prefix,
        int buf_size,
        unsigned char *test_dir,
        unsigned char *test_pat,
        unsigned char *corr_pat,
        unsigned char *info_pat,
        unsigned char *tgz_pat,
        unsigned char *tgzdir_pat)
{
  int retval = 0;
  unsigned char corr_dir[PATH_MAX];
  unsigned char info_dir[PATH_MAX];
  unsigned char tgz_dir[PATH_MAX];
  unsigned char name1[PATH_MAX];
  unsigned char name2[PATH_MAX];

  if (pat_prefix == NULL) pat_prefix = "";

  test_dir[0] = 0;
  test_pat[0] = 0;
  corr_pat[0] = 0;
  info_pat[0] = 0;
  tgz_pat[0] = 0;
  tgzdir_pat[0] = 0;
  corr_dir[0] = 0;
  info_dir[0] = 0;
  tgz_dir[0] = 0;

  if (global->advanced_layout > 0) {
    get_advanced_layout_path(test_dir, buf_size, global, prob, DFLT_P_TEST_DIR, variant);
  } else if (variant > 0) {
    snprintf(test_dir, buf_size, "%s-%d", prob->test_dir, variant);
  } else {
    snprintf(test_dir, buf_size, "%s", prob->test_dir);
  }
  if (prob->test_pat) {
    snprintf(test_pat, buf_size, "%s%s", pat_prefix, prob->test_pat);
  } else if (prob->test_sfx) {
    snprintf(test_pat, buf_size, "%s%%03d%s", pat_prefix, prob->test_sfx);
  } else {
    snprintf(test_pat, buf_size, "%s%%03d%s", pat_prefix, ".dat");
  }
  snprintf(name1, sizeof(name1), test_pat, 1);
  snprintf(name2, sizeof(name2), test_pat, 2);
  if (!strcmp(name1, name2)) {
    fprintf(log_f, "invalid test files pattern\n");
    FAIL(SSERV_ERR_UNSUPPORTED_SETTINGS);
  }

  corr_dir[0] = 0;
  corr_pat[0] = 0;
  if (prob->use_corr > 0) {
    if (global->advanced_layout > 0) {
      get_advanced_layout_path(corr_dir, sizeof(corr_dir), global, prob, DFLT_P_CORR_DIR, variant);
    } else if (variant > 0) {
      snprintf(corr_dir, sizeof(corr_dir), "%s-%d", prob->corr_dir, variant);
    } else {
      snprintf(corr_dir, sizeof(corr_dir), "%s", prob->corr_dir);
    }
    if (strcmp(corr_dir, test_dir) != 0) {
      fprintf(log_f, "corr_dir and test_dir cannot be different\n");
      FAIL(SSERV_ERR_UNSUPPORTED_SETTINGS);
    }
    if (prob->corr_pat) {
      snprintf(corr_pat, buf_size, "%s%s", pat_prefix, prob->corr_pat);
    } else if (prob->corr_sfx) {
      snprintf(corr_pat, buf_size, "%s%%03d%s", pat_prefix, prob->corr_sfx);
    } else {
      snprintf(corr_pat, buf_size, "%s%%03d%s", pat_prefix, ".ans");
    }
    snprintf(name1, sizeof(name1), corr_pat, 1);
    snprintf(name2, sizeof(name2), corr_pat, 2);
    if (!strcmp(name1, name2)) {
      fprintf(log_f, "invalid correct files pattern\n");
      FAIL(SSERV_ERR_UNSUPPORTED_SETTINGS);
    }
  }

  info_dir[0] = 0;
  info_pat[0] = 0;
  if (prob->use_info > 0) {
    if (global->advanced_layout > 0) {
      get_advanced_layout_path(info_dir, sizeof(info_dir), global, prob, DFLT_P_INFO_DIR, variant);
    } else if (variant > 0) {
      snprintf(info_dir, sizeof(info_dir), "%s-%d", prob->info_dir, variant);
    } else {
      snprintf(info_dir, sizeof(info_dir), "%s", prob->info_dir);
    }
    if (strcmp(info_dir, test_dir) != 0) {
      fprintf(log_f, "info_dir and test_dir cannot be different\n");
      FAIL(SSERV_ERR_UNSUPPORTED_SETTINGS);
    }
    if (prob->info_pat) {
      snprintf(info_pat, buf_size, "%s%s", pat_prefix, prob->info_pat);
    } else if (prob->info_sfx) {
      snprintf(info_pat, buf_size, "%s%%03d%s", pat_prefix, prob->info_sfx);
    } else {
      snprintf(info_pat, buf_size, "%s%%03d%s", pat_prefix, ".inf");
    }
    snprintf(name1, sizeof(name1), info_pat, 1);
    snprintf(name2, sizeof(name2), info_pat, 2);
    if (!strcmp(name1, name2)) {
      fprintf(log_f, "invalid info files pattern\n");
      FAIL(SSERV_ERR_UNSUPPORTED_SETTINGS);
    }
  }

  tgz_dir[0] = 0;
  tgz_pat[0] = 0;
  tgzdir_pat[0] = 0;
  if (prob->use_tgz > 0) {
    if (global->advanced_layout > 0) {
      get_advanced_layout_path(tgz_dir, sizeof(tgz_dir), global, prob, DFLT_P_TGZ_DIR, variant);
    } else if (variant > 0) {
      snprintf(tgz_dir, sizeof(tgz_dir), "%s-%d", prob->tgz_dir, variant);
    } else {
      snprintf(tgz_dir, sizeof(tgz_dir), "%s", prob->tgz_dir);
    }
    if (strcmp(tgz_dir, test_dir) != 0) {
      fprintf(log_f, "tgz_dir and test_dir cannot be different\n");
      FAIL(SSERV_ERR_UNSUPPORTED_SETTINGS);
    }
    if (prob->tgz_pat) {
      snprintf(tgz_pat, buf_size, "%s%s", pat_prefix, prob->tgz_pat);
    } else if (prob->tgz_sfx) {
      snprintf(tgz_pat, buf_size, "%s%%03d%s", pat_prefix, prob->tgz_sfx);
    } else {
      snprintf(tgz_pat, buf_size, "%s%%03d%s", pat_prefix, ".tgz");
    }
    snprintf(name1, sizeof(name1), tgz_pat, 1);
    snprintf(name2, sizeof(name2), tgz_pat, 2);
    if (!strcmp(name1, name2)) {
      fprintf(log_f, "invalid tgz files pattern\n");
      FAIL(SSERV_ERR_UNSUPPORTED_SETTINGS);
    }
    if (prob->tgzdir_pat) {
      snprintf(tgzdir_pat, buf_size, "%s%s", pat_prefix, prob->tgzdir_pat);
    } else if (prob->tgzdir_sfx) {
      snprintf(tgzdir_pat, buf_size, "%s%%03d%s", pat_prefix, prob->tgzdir_sfx);
    } else {
      snprintf(tgzdir_pat, buf_size, "%s%%03d%s", pat_prefix, ".dir");
    }
    snprintf(name1, sizeof(name1), tgzdir_pat, 1);
    snprintf(name2, sizeof(name2), tgzdir_pat, 2);
    if (!strcmp(name1, name2)) {
      fprintf(log_f, "invalid tgzdir files pattern\n");
      FAIL(SSERV_ERR_UNSUPPORTED_SETTINGS);
    }
  }

cleanup:
  return retval;
}

static unsigned char *
merge_lines(unsigned char **lines, int beg, int end)
{
  int i, totlen = 0;
  unsigned char *str = NULL, *p;

  for (i = beg; i < end; ++i) {
    totlen += strlen(lines[i]) + 1;
  }
  if (totlen <= 0) return NULL;

  p = str = (unsigned char *) xmalloc((totlen + 1) * sizeof(*str));
  for (i = beg; i < end; ++i) {
    p = stpcpy(p, lines[i]);
    *p++ = '\n';
  }
  *p = 0;
  return str;
}

static void
extract_makefile_header_footer(
        const unsigned char *text,
        unsigned char **p_header,
        unsigned char **p_footer)
{
  unsigned char **lines = NULL;
  int i, slen, begin_idx = -1, end_idx = -1;

  if (!text || !*text) return;
  split_to_lines(text, (char***) &lines, 0);
  if (lines == NULL) return;

  for (i = 0; lines[i]; ++i) {
    slen = strlen(lines[i]);
    while (slen > 0 && isspace(lines[i][slen - 1])) --slen;
    lines[i][slen] = 0;
    if (begin_idx < 0 && !strcmp(lines[i], ej_makefile_begin)) {
      begin_idx = i;
    }
    if (!strcmp(lines[i], ej_makefile_end)) {
      end_idx = i;
    }
  }
  if (begin_idx >= 0 && end_idx >= 0 && begin_idx >= end_idx) {
    begin_idx = -1;
    end_idx = -1;
  }
  if (begin_idx >= 0) {
    *p_header = merge_lines(lines, 0, begin_idx);
  }
  if (end_idx >= 0) {
    *p_footer = merge_lines(lines, end_idx + 1, i);
  }

  for (i = 0; lines[i]; ++i) {
    xfree(lines[i]);
  }
  xfree(lines);
}

static int
need_file_update(const unsigned char *out_path, const unsigned char *tmp_path)
{
  FILE *f1 = NULL;
  FILE *f2 = NULL;
  int c1, c2;

  if (!(f1 = fopen(out_path, "r"))) return 1;
  if (!(f2 = fopen(tmp_path, "r"))) {
    fclose(f1);
    return -1;
  }
  do {
    c1 = getc_unlocked(f1);
    c2 = getc_unlocked(f2);
  } while (c1 != EOF && c2 != EOF && c1 == c2);
  fclose(f2);
  fclose(f1);
  return c1 != EOF || c2 != EOF;
}

static int
logged_rename(
        FILE *log_f,
        const unsigned char *oldpath,
        const unsigned char *newpath)
{
  if (!*oldpath || !*newpath) return 0;

  if (rename(oldpath, newpath) < 0 && errno != ENOENT) {
    fprintf(log_f, "rename: %s->%s failed: %s\n", oldpath, newpath, os_ErrorMsg());
    return -1;
  }
  return 0;
}

static int
is_makefile_rule_needed(const unsigned char *path)
{
  // empty value
  if (!path || !path[0]) return 0;
  // absolute path
  if (path[0] == '/') return 0;
  // relative-to-parent path
  if (path[0] == '.' && path[1] == '.' && path[2] == '/') return 0;
  // format substitution
  if (path[0] == '%') return 0;
  // variable substitution
  if (path[0] == '$') return 0;
  return 1;
}

static void
do_generate_makefile(
        FILE *log_f,
        FILE *mk_f,
        const struct ejudge_cfg *ejudge_config,
        const struct contest_desc *cnts,
        serve_state_t cs,
        struct sid_state *sstate,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        int variant)
{
  int retval = 0;
  unsigned char test_dir[PATH_MAX];
  unsigned char test_pat[PATH_MAX];
  unsigned char corr_pat[PATH_MAX];
  unsigned char info_pat[PATH_MAX];
  unsigned char tgz_pat[PATH_MAX];
  unsigned char tgzdir_pat[PATH_MAX];
  unsigned char test_pr_pat[PATH_MAX];
  unsigned char tgzdir_pr_pat[PATH_MAX];
  unsigned long languages = 0;
  unsigned long enabled_languages = 0;
  unsigned char tmp_path[PATH_MAX];
  unsigned char *compiler_path = NULL;
  const unsigned char *compiler_flags = NULL;
  int has_header = 0, need_c_libchecker = 0, need_cpp_libchecker = 0, has_solutions = 0;
  int enable_testlib_mode = 0;
  const unsigned char *source_suffix = NULL;
  int count = 0;
  unsigned char **good_names = NULL;
  unsigned char **fail_names = NULL;
  unsigned char **solutions_names = NULL;
  unsigned char **good_exe_names = NULL;
  unsigned char **fail_exe_names = NULL;
  unsigned char **solutions_exe_names = NULL;
  unsigned char ejudge_lib_dir[PATH_MAX];
  unsigned char ejudge_lib32_dir[PATH_MAX];
  const unsigned char *m32_opt = "";
  const unsigned char *libdir = NULL;

  test_dir[0] = 0;
  test_pat[0] = 0;
  corr_pat[0] = 0;
  info_pat[0] = 0;
  tgz_pat[0] = 0;
  tgzdir_pat[0] = 0;
  test_pr_pat[0] = 0;

  ejudge_lib_dir[0] = 0;
#if defined EJUDGE_LIB_DIR
  if (!strncmp(EJUDGE_LIB_DIR, EJUDGE_PREFIX_DIR, strlen(EJUDGE_PREFIX_DIR))) {
    snprintf(ejudge_lib_dir, sizeof(ejudge_lib_dir), "${EJUDGE_PREFIX_DIR}%s", EJUDGE_LIB_DIR + strlen(EJUDGE_PREFIX_DIR));
  } else {
    snprintf(ejudge_lib_dir, sizeof(ejudge_lib_dir), "%s", EJUDGE_LIB_DIR);
  }
#endif
  if (!ejudge_lib_dir[0]) {
    snprintf(ejudge_lib_dir, sizeof(ejudge_lib_dir), "${EJUDGE_PREFIX_DIR}/lib");
  }
  ejudge_lib32_dir[0] = 0;
#if defined EJUDGE_LIB32_DIR
  if (!strncmp(EJUDGE_LIB32_DIR, EJUDGE_PREFIX_DIR, strlen(EJUDGE_PREFIX_DIR))) {
    snprintf(ejudge_lib32_dir, sizeof(ejudge_lib32_dir), "${EJUDGE_PREFIX_DIR}%s", EJUDGE_LIB32_DIR + strlen(EJUDGE_PREFIX_DIR));
  } else {
    snprintf(ejudge_lib32_dir, sizeof(ejudge_lib32_dir), "%s", EJUDGE_LIB32_DIR);
  }
#endif
  if (!ejudge_lib32_dir[0]) {
    snprintf(ejudge_lib32_dir, sizeof(ejudge_lib32_dir), "${EJUDGE_PREFIX_DIR}/lib");
  }

  libdir = ejudge_lib_dir;
  if (global->enable_32bit_checkers > 0) {
    libdir = ejudge_lib32_dir;
    m32_opt = " -m32";
  }

  retval = build_prepare_test_file_names(log_f, cnts, global, prob, variant, NULL,
                                         sizeof(test_dir), test_dir, test_pat, corr_pat, info_pat,
                                         tgz_pat, tgzdir_pat);
  if (retval < 0) return;
  build_pattern_to_shell_pattern(test_pr_pat, sizeof(test_pr_pat), test_pat);

  // tmp_path is modified by guess_language_by_cmd
  if (is_makefile_rule_needed(prob->check_cmd)) {
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->check_cmd, variant);
    languages |= build_guess_language_by_cmd(tmp_path, NULL);
  }
  if (is_makefile_rule_needed(prob->valuer_cmd)) {
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->valuer_cmd, variant);
    languages |= build_guess_language_by_cmd(tmp_path, NULL);
  }
  if (is_makefile_rule_needed(prob->interactor_cmd)) {
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->interactor_cmd, variant);
    languages |= build_guess_language_by_cmd(tmp_path, NULL);
  }
  if (is_makefile_rule_needed(prob->style_checker_cmd)) {
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->style_checker_cmd, variant);
    languages |= build_guess_language_by_cmd(tmp_path, NULL);
  }
  if (is_makefile_rule_needed(prob->test_checker_cmd)) {
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->test_checker_cmd, variant);
    languages |= build_guess_language_by_cmd(tmp_path, NULL);
  }
  if (is_makefile_rule_needed(prob->init_cmd)) {
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->init_cmd, variant);
    languages |= build_guess_language_by_cmd(tmp_path, NULL);
  }
  if ((languages & LANG_C)) need_c_libchecker = 1;
  if ((languages & LANG_CPP)) need_cpp_libchecker = 1;
  if (prob->enable_testlib_mode > 0) enable_testlib_mode = 1;

  if (prob->type == PROB_TYPE_TESTS) {
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, "tests/good", variant);
    good_names = build_collect_suitable_names(tmp_path, &languages);
    good_exe_names = build_make_exe_suitable_names(good_names);
    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, "tests/fail", variant);
    fail_names = build_collect_suitable_names(tmp_path, &languages);
    fail_exe_names = build_make_exe_suitable_names(fail_names);
  } else if (prob->type == PROB_TYPE_STANDARD) {
    /* detect which languages we'll need */
    if (prob->source_header && prob->source_header[0]) {
      languages |= build_guess_language_by_src(prob->source_header);
    }
    if (prob->source_footer && prob->source_footer[0]) {
      languages |= build_guess_language_by_src(prob->source_footer);
    }
    if (prob->solution_src && prob->solution_src[0]) {
      languages |= build_guess_language_by_src(prob->solution_src);
    }

    if (prob->solution_cmd && prob->solution_cmd[0]) {
      get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->solution_cmd, variant);
      languages |= build_guess_language_by_cmd(tmp_path, NULL);
    }

    get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, "solutions", variant);
    struct stat stb;
    if (stat(tmp_path, &stb) >= 0 && S_ISDIR(stb.st_mode)) {
      has_solutions = 1;
      solutions_names = build_collect_suitable_names(tmp_path, &languages);
      solutions_exe_names = build_make_exe_suitable_names(solutions_names);
    }
  }

  fprintf(mk_f, "%s\n", ej_makefile_begin);
  fprintf(mk_f, "EJUDGE_PREFIX_DIR ?= %s\n", EJUDGE_PREFIX_DIR);
  fprintf(mk_f, "EJUDGE_CONTESTS_HOME_DIR ?= %s\n", EJUDGE_CONTESTS_HOME_DIR);
#if defined EJUDGE_LOCAL_DIR
  fprintf(mk_f, "EJUDGE_LOCAL_DIR ?= %s\n", EJUDGE_LOCAL_DIR);
#endif /* EJUDGE_LOCAL_DIR */
  fprintf(mk_f, "EJUDGE_SERVER_BIN_PATH ?= %s\n", EJUDGE_SERVER_BIN_PATH);
  fprintf(mk_f, "\n");

  if ((languages & LANG_C)) {
    compiler_path = build_get_compiler_path(log_f, ejudge_config, NULL, "gcc");
    if (!compiler_path) {
      fprintf(mk_f, "# C compiler is not found\nCC ?= /bin/false\n");
    } else {
      fprintf(mk_f, "CC = %s\n", compiler_path);
      enabled_languages |= LANG_C;
    }
    xfree(compiler_path); compiler_path = NULL;
    compiler_flags = build_get_compiler_flags(cs, sstate, "gcc");
    if (!compiler_flags) {
      fprintf(mk_f, "CFLAGS = -Wall -g -O2 -std=gnu11 -Wno-pointer-sign\n");
    } else {
      fprintf(mk_f, "CFLAGS = %s\n", compiler_flags);
    }
    compiler_flags = NULL;
    fprintf(mk_f, "CLIBS = -lm\n");
    if (need_c_libchecker) {
      fprintf(mk_f, "CLIBCHECKERFLAGS =%s -Wall -Wno-pointer-sign -g -std=gnu11 -O2 -I${EJUDGE_PREFIX_DIR}/include/ejudge -L%s -Wl,--rpath,%s\n", m32_opt, libdir, libdir);
      fprintf(mk_f, "CLIBCHECKERLIBS = -lchecker -lm\n");
    }
    fprintf(mk_f, "\n");
  }

  if ((languages & LANG_CPP)) {
    compiler_path = build_get_compiler_path(log_f, ejudge_config, NULL, "g++");
    if (!compiler_path) {
      fprintf(mk_f, "# C++ compiler is not found\nCXX ?= /bin/false\n");
    } else {
      fprintf(mk_f, "CXX = %s\n", compiler_path);
      enabled_languages |= LANG_CPP;
    }
    xfree(compiler_path); compiler_path = NULL;
    compiler_flags = build_get_compiler_flags(cs, sstate, "g++");
    if (!compiler_flags) {
      fprintf(mk_f, "CXXFLAGS = -Wall -g -O2\n");
    } else {
      fprintf(mk_f, "CXXFLAGS = %s\n", compiler_flags);
    }
    compiler_flags = NULL;
    if (need_cpp_libchecker) {
      if (enable_testlib_mode) {
        const unsigned char *options = ejudge_cfg_get_compiler_option(ejudge_config, "g++");
        if (!options) options = "-Wall -g -O2 -std=gnu++17";
        fprintf(mk_f, "CXXLIBCHECKERFLAGS =%s -DEJUDGE %s\n", m32_opt, options);
      } else {
        fprintf(mk_f, "CXXLIBCHECKERFLAGS =%s -Wall -g -O2 -I${EJUDGE_PREFIX_DIR}/include/ejudge -L%s -Wl,--rpath,%s\n",
                m32_opt, libdir, libdir);
        fprintf(mk_f, "CXXLIBCHECKERLIBS = -lchecker -lm\n");
      }
    }
    fprintf(mk_f, "\n");
  }

  if ((languages & LANG_FPC)) {
    compiler_path = build_get_compiler_path(log_f, ejudge_config, NULL, "fpc");
    if (!compiler_path) {
      fprintf(mk_f, "# FPC compiler is not found\nFPC ?= /bin/false\n");
    } else {
      fprintf(mk_f, "FPC = %s\n", compiler_path);
      enabled_languages |= LANG_FPC;
    }
    xfree(compiler_path); compiler_path = NULL;
    compiler_flags = build_get_compiler_flags(cs, sstate, "fpc");
    if (!compiler_flags) compiler_flags = "";
    fprintf(mk_f, "FPCFLAGS = %s\n", compiler_flags);
    compiler_flags = NULL;
    fprintf(mk_f, "FPCTESTLIBFLAGS = -Fu%s/share/ejudge/testlib/fpc\n", EJUDGE_PREFIX_DIR);
    fprintf(mk_f, "\n");
  }

  if ((languages & LANG_DCC)) {
    compiler_path = build_get_compiler_path(log_f, ejudge_config, NULL, "dcc");
    if (!compiler_path) {
      fprintf(mk_f, "# DCC compiler is not found\nDCC ?= /bin/false\n");
    } else {
      fprintf(mk_f, "DCC = %s\n", compiler_path);
      enabled_languages |= LANG_DCC;
    }
    xfree(compiler_path); compiler_path = NULL;
    compiler_flags = build_get_compiler_flags(cs, sstate, "dcc");
    if (!compiler_flags) compiler_flags = "";
    fprintf(mk_f, "DCCFLAGS = %s\n", compiler_flags);
    compiler_flags = NULL;
    fprintf(mk_f, "DCCTESTLIBFLAGS = -U%s/share/ejudge/testlib/delphi\n", EJUDGE_PREFIX_DIR);
    fprintf(mk_f, "\n");
  }

  if ((languages & LANG_JAVA)) {
    compiler_path = build_get_compiler_path(log_f, ejudge_config, NULL, "javac");
    if (!compiler_path) {
      fprintf(mk_f, "# JAVAC compiler is not found\n"
              "JAVAC ?= /bin/false\n");
    } else {
      fprintf(mk_f, "JAVAC = %s\n", compiler_path);
      unsigned char *dn = os_DirName(compiler_path);
      if (!dn || !*dn || !strcmp(dn, ".")) {
        fprintf(mk_f, "JAVA = java\n"
                "JAR = jar\n");
      } else {
        fprintf(mk_f, "JAVA = %s/java\n"
                "JAR = %s/jar\n", dn, dn);
      }
      xfree(dn); dn = NULL;
      enabled_languages |= LANG_JAVA;
    }
    xfree(compiler_path); compiler_path = NULL;
    compiler_path = build_get_compiler_script(log_f, ejudge_config, NULL, "javac");
    if (!compiler_path) {
      fprintf(mk_f, "JAVACHELPER ?= /bin/false\n");
    } else {
      fprintf(mk_f, "JAVACHELPER = %s\n", compiler_path);
    }
    xfree(compiler_path); compiler_path = NULL;
    compiler_flags = build_get_compiler_flags(cs, sstate, "javac");
    if (!compiler_flags) compiler_flags = "";
    fprintf(mk_f, "JAVACFLAGS = %s\n", compiler_flags);
    fprintf(mk_f, "\n");
  }

  if ((languages & LANG_PY)) {
    compiler_path = build_get_compiler_script(log_f, ejudge_config, NULL, "python3");
    if (!compiler_path) compiler_path = build_get_compiler_script(log_f, ejudge_config, NULL, "python");
    if (!compiler_path) {
      fprintf(mk_f, "PYCHELPER ?= /bin/false\n");
    } else {
      fprintf(mk_f, "PYCHELPER = %s\n", compiler_path);
      enabled_languages |= LANG_PY;
    }
    xfree(compiler_path); compiler_path = NULL;
    fprintf(mk_f, "\n");
  }

  if ((languages & LANG_GO)) {
    compiler_path = build_get_compiler_script(log_f, ejudge_config, NULL, "gccgo");
    if (!compiler_path) compiler_path = build_get_compiler_script(log_f, ejudge_config, NULL, "gccgo");
    if (!compiler_path) {
      fprintf(mk_f, "GOCHELPER ?= /bin/false\n");
    } else {
      fprintf(mk_f, "GOCHELPER = %s\n", compiler_path);
      enabled_languages |= LANG_GO;
    }
    xfree(compiler_path); compiler_path = NULL;
    fprintf(mk_f, "\n");
  }

  if ((languages & LANG_KUM)) {
    compiler_path = build_get_compiler_script(log_f, ejudge_config, NULL, "kumir");
    if (!compiler_path) {
      fprintf(mk_f, "KUMCHELPER ?= /bin/false\n");
    } else {
      fprintf(mk_f, "KUMCHELPER = %s\n", compiler_path);
      enabled_languages |= LANG_KUM;
    }
    xfree(compiler_path); compiler_path = NULL;
    fprintf(mk_f, "\n");
  }

  fprintf(mk_f, "EXECUTE = ${EJUDGE_PREFIX_DIR}/bin/ejudge-execute\n");
  fprintf(mk_f, "EXECUTE_FLAGS = ");
  if (prob->use_stdin > 0) fprintf(mk_f, " --use-stdin");
  if (prob->use_stdout > 0) fprintf(mk_f, " --use-stdout");
  if (prob->use_stdin <= 0 && prob->input_file && prob->input_file[0]) {
    fprintf(mk_f, " --input-file=%s", prob->input_file);
  }
  if (prob->use_stdout <= 0 && prob->output_file && prob->output_file[0]) {
    fprintf(mk_f, " --output-file=%s", prob->output_file);
  }
  if (test_pat[0] > ' ') fprintf(mk_f, " --test-pattern=%s", test_pat);
  if (corr_pat[0] > ' ') fprintf(mk_f, " --corr-pattern=%s", corr_pat);
  if (info_pat[0] > ' ') fprintf(mk_f, " --info-pattern=%s", info_pat);
  if (tgzdir_pat[0] > ' ') fprintf(mk_f, " --tgzdir-pattern=%s", tgzdir_pat);
  if (cnts->file_group && cnts->file_group[0]) fprintf(mk_f, " --group=%s", cnts->file_group);
  if (cnts->file_mode && cnts->file_mode[0]) fprintf(mk_f, " --mode=%s", cnts->file_mode);
  if (prob->time_limit_millis > 0) {
    fprintf(mk_f, " --time-limit-millis=%d", prob->time_limit_millis);
  } else if (prob->time_limit > 0) {
    fprintf(mk_f, " --time-limit=%d", prob->time_limit);
  }
  fprintf(mk_f, "\n");

  if (prob->test_checker_cmd && prob->test_checker_cmd[0]) {
    fprintf(mk_f, "TC_EXECUTE_FLAGS = --use-stdin");
    if (test_pat[0] > ' ') fprintf(mk_f, " --test-pattern=%s", test_pat);
    if (info_pat[0] > ' ') fprintf(mk_f, " --info-pattern=%s", info_pat);
    if (prob->test_checker_env && prob->test_checker_env[0]) {
      for (int i = 0; prob->test_checker_env[i]; ++i) {
        fprintf(mk_f, " --env=%s", prob->test_checker_env[i]);
      }
    }
    fprintf(mk_f, "\n");
  }

  if (prob->use_tgz > 0) {
    fprintf(mk_f, "MAKE_ARCHIVE = ${EJUDGE_PREFIX_DIR}/libexec/ejudge/lang/ej-make-archive\n");
    fprintf(mk_f, "MAKE_ARCHIVE_FLAGS = --tgzdir-pattern=%s --tgz-pattern=%s\n",
            tgzdir_pat, tgz_pat);
  }

  fprintf(mk_f, "\n");

  fprintf(mk_f, "NORMALIZE = ${EJUDGE_SERVER_BIN_PATH}/ej-normalize\n");
  fprintf(mk_f, "NORMALIZE_FLAGS = --workdir=tests");
  if (test_pat[0] > ' ') fprintf(mk_f, " --test-pattern=%s", test_pat);
  if (corr_pat[0] > ' ') fprintf(mk_f, " --corr-pattern=%s", corr_pat);
  if (cnts->file_group && cnts->file_group[0]) fprintf(mk_f, " --group=%s", cnts->file_group);
  if (cnts->file_mode && cnts->file_mode[0]) fprintf(mk_f, " --mode=%s", cnts->file_mode);
  if (prob->binary_input > 0) fprintf(mk_f, " --binary-input");
  if (prob->normalization && prob->normalization[0]) fprintf(mk_f, " --type=%s", prob->normalization);
  fprintf(mk_f, "\n\n");

  fprintf(mk_f, "all :");
  if (prob->solution_cmd && prob->solution_cmd[0]) {
    fprintf(mk_f, " %s", prob->solution_cmd);
  }
  if ((!prob->standard_checker || !prob->standard_checker[0])
      && is_makefile_rule_needed(prob->check_cmd)) {
    fprintf(mk_f, " %s", prob->check_cmd);
  }
  if (is_makefile_rule_needed(prob->valuer_cmd)) {
    fprintf(mk_f, " %s", prob->valuer_cmd);
  }
  if (is_makefile_rule_needed(prob->interactor_cmd)) {
    fprintf(mk_f, " %s", prob->interactor_cmd);
  }
  if (is_makefile_rule_needed(prob->test_checker_cmd)) {
    fprintf(mk_f, " %s", prob->test_checker_cmd);
  }
  if (is_makefile_rule_needed(prob->init_cmd)) {
    fprintf(mk_f, " %s", prob->init_cmd);
  }
  if (prob->type == PROB_TYPE_TESTS) {
    fprintf(mk_f, " good_progs fail_progs");
  }
  if (solutions_exe_names) {
    for (int i = 0; solutions_exe_names[i]; ++i) {
      fprintf(mk_f, " solutions/%s", solutions_exe_names[i]);
    }
  }
  fprintf(mk_f, "\n");
  if (prob->type == PROB_TYPE_TESTS) {
    fprintf(mk_f, "check_settings : all\n\n");
  } else {
    fprintf(mk_f, "check_settings : all normalize");
    if (prob->test_checker_cmd && prob->test_checker_cmd[0]) {
      fprintf(mk_f, " check_tests");
    }
    fprintf(mk_f, "\n\n");
  }

  /* solution compilation part  */
  if (prob->solution_cmd && prob->solution_cmd[0]) {
    if (prob->source_header && prob->source_header[0]) has_header = 1;
    if (prob->source_footer && prob->source_footer[0]) has_header = 1;
    if (prob->solution_src && prob->solution_src[0]) {
      languages = build_guess_language_by_src(prob->solution_src);
      source_suffix = build_get_source_suffix(languages);
      if (has_header) {
        fprintf(mk_f, "%s%s :", prob->solution_cmd, source_suffix);
        if (prob->source_header && prob->source_header[0]) {
          fprintf(mk_f, " %s", prob->source_header);
        }
        fprintf(mk_f, " %s", prob->solution_src);
        if (prob->source_footer && prob->source_footer[0]) {
          fprintf(mk_f, " %s", prob->source_footer);
        }
        fprintf(mk_f, "\n");
        fprintf(mk_f, "\tcat $^ > $@\n");
      }
      build_generate_solution_compilation_rule(mk_f, NULL, prob->solution_cmd, NULL, NULL, languages);
    } else if (!has_header) {
      get_advanced_layout_path(tmp_path, sizeof(tmp_path), global, prob, prob->solution_cmd, variant);
      languages = build_guess_language_by_cmd(tmp_path, &count);
      if (count <= 0) {
        fprintf(mk_f, "# no source language to build solution '%s'\n", prob->solution_cmd);
      } else if (count > 1) {
        fprintf(mk_f, "# several source languages to build solution '%s'\n", prob->solution_cmd);
      } else {
        build_generate_solution_compilation_rule(mk_f, NULL, prob->solution_cmd, NULL, NULL, languages);
      }
    } else {
      fprintf(mk_f, "# no information how to build solution '%s' with header or footer\n", prob->solution_cmd);
    }
  }
  fprintf(mk_f, "\n");

  /* checker compilation part */
  if (!prob->standard_checker || !prob->standard_checker[0]) {
    build_generate_checker_compilation_rule(mk_f, "check", global, prob, variant, prob->check_cmd);
  }

  build_generate_checker_compilation_rule(mk_f, "valuer", global, prob, variant, prob->valuer_cmd);
  build_generate_checker_compilation_rule(mk_f, "interactor", global, prob, variant, prob->interactor_cmd);
  build_generate_checker_compilation_rule(mk_f, "test_checker", global, prob, variant, prob->test_checker_cmd);
  build_generate_checker_compilation_rule(mk_f, "init", global, prob, variant, prob->init_cmd);

  /* test generation part */
  if (prob->type != PROB_TYPE_TESTS) {
    if (prob->solution_cmd && prob->solution_cmd[0]) {
      fprintf(mk_f, "answers : %s\n", prob->solution_cmd);
      fprintf(mk_f, "\t${EXECUTE} ${EXECUTE_FLAGS} --update-corr --test-dir=%s --workdir=%s --all-tests %s\n", "tests", "tests", prob->solution_cmd);
      fprintf(mk_f, "\n");
      fprintf(mk_f, "answer : %s\n", prob->solution_cmd);
      fprintf(mk_f, "\tcd tests && ${EXECUTE} ${EXECUTE_FLAGS} --update-corr --test-num=${TEST_NUM} ../%s\n", prob->solution_cmd);
      fprintf(mk_f, "\n");
    }
    if (prob->test_checker_cmd && prob->test_checker_cmd[0]) {
      fprintf(mk_f, "check_tests : %s\n", prob->test_checker_cmd);
      fprintf(mk_f, "\t${EXECUTE} ${TC_EXECUTE_FLAGS} --test-dir=%s --workdir=%s --all-tests %s\n", "tests", "tests", prob->test_checker_cmd);
      fprintf(mk_f, "\n");
      fprintf(mk_f, "check_test : %s\n", prob->test_checker_cmd);
      fprintf(mk_f, "\tcd tests && ${EXECUTE} ${TC_EXECUTE_FLAGS} --test-num=${TEST_NUM} ../%s\n", prob->test_checker_cmd);
      fprintf(mk_f, "\n");
    }
    fprintf(mk_f, "\n");

    fprintf(mk_f, "normalize :\n"
            "\t${NORMALIZE} ${NORMALIZE_FLAGS} --all-tests\n\n");

    /* archiving */
    if (prob->use_tgz > 0) {
      build_pattern_to_shell_pattern(tgzdir_pr_pat, sizeof(tgzdir_pr_pat), tgzdir_pat);
      fprintf(mk_f, "archives : \n");
      fprintf(mk_f, "\tcd tests && for i in %s; do ${MAKE_ARCHIVE} ${MAKE_ARCHIVE_FLAGS} $$i || { echo 'Archive failed on' $$i; exit 1; }; done;\n",
              tgzdir_pr_pat);
    }
  }

  if (solutions_exe_names) {
    for (int i = 0; solutions_exe_names[i]; ++i) {
      build_generate_solution_compilation_rule(mk_f, "solutions", solutions_exe_names[i],
                                               solutions_names[i], NULL, 0);
    }
  }

  // "Tests" problem
  if (prob->type == PROB_TYPE_TESTS) {
    fprintf(mk_f, "good_progs :");
    if (good_exe_names) {
      for (int i = 0; good_exe_names[i]; ++i) {
        fprintf(mk_f, " %s/%s", "tests/good", good_exe_names[i]);
      }
    }
    fprintf(mk_f, "\n");
    fprintf(mk_f, "fail_progs :");
    if (fail_exe_names) {
      for (int i = 0; fail_exe_names[i]; ++i) {
        fprintf(mk_f, " %s/%s", "tests/fail", fail_exe_names[i]);
      }
    }
    fprintf(mk_f, "\n");

    if (good_exe_names) {
      for (int i = 0; good_exe_names[i]; ++i) {
        build_generate_solution_compilation_rule(mk_f, "tests/good", good_exe_names[i], good_names[i], NULL, 0);
      }
    }
    if (fail_exe_names) {
      for (int i = 0; fail_exe_names[i]; ++i) {
        build_generate_solution_compilation_rule(mk_f, "tests/fail", fail_exe_names[i], fail_names[i], NULL, 0);
      }
    }
  }

  fprintf(mk_f, "clean :\n");
  fprintf(mk_f, "\t-rm -f *.o *.class *.exe *~ *.bak");
  if (prob->solution_cmd && prob->solution_cmd[0]) {
    fprintf(mk_f, " %s", prob->solution_cmd);
  }
  if ((!prob->standard_checker || !prob->standard_checker[0])
      && is_makefile_rule_needed(prob->check_cmd)) {
    fprintf(mk_f, " %s", prob->check_cmd);
  }
  if (is_makefile_rule_needed(prob->valuer_cmd)) {
    fprintf(mk_f, " %s", prob->valuer_cmd);
  }
  if (is_makefile_rule_needed(prob->interactor_cmd)) {
    fprintf(mk_f, " %s", prob->interactor_cmd);
  }
  if (is_makefile_rule_needed(prob->test_checker_cmd)) {
    fprintf(mk_f, " %s", prob->test_checker_cmd);
  }
  if (is_makefile_rule_needed(prob->init_cmd)) {
    fprintf(mk_f, " %s", prob->init_cmd);
  }
  if (has_solutions) {
    fprintf(mk_f, " solutions/*.o");
  }
  if (solutions_exe_names) {
    for (int i = 0; solutions_exe_names[i]; ++i) {
      fprintf(mk_f, " solutions/%s", solutions_exe_names[i]);
    }
  }
  fprintf(mk_f, "\n");
  if (prob->type == PROB_TYPE_TESTS) {
    fprintf(mk_f, "\t-cd tests/good && rm -f *.o *.class *.jar *.exe *~ *.bak");
    if (good_exe_names) {
      for (int i = 0; good_exe_names[i]; ++i) {
        fprintf(mk_f, " %s", good_exe_names[i]);
      }
    }
    fprintf(mk_f, "\n");
    fprintf(mk_f, "\t-cd tests/fail && rm -f *.o *.class *.jar *.exe *~ *.bak");
    if (fail_exe_names) {
      for (int i = 0; fail_exe_names[i]; ++i) {
        fprintf(mk_f, " %s", fail_exe_names[i]);
      }
    }
    fprintf(mk_f, "\n");
  }
  fprintf(mk_f, "\n");

  fprintf(mk_f, "%s\n", ej_makefile_end);

  good_names = build_free_suitable_names(good_names);
  good_exe_names = build_free_suitable_names(good_exe_names);
  fail_names = build_free_suitable_names(fail_names);
  fail_exe_names = build_free_suitable_names(fail_exe_names);
  solutions_names = build_free_suitable_names(solutions_names);
  solutions_exe_names = build_free_suitable_names(solutions_exe_names);
}

int
build_generate_makefile(
        FILE  *log_f,
        const struct ejudge_cfg *ejudge_config,
        const struct contest_desc *cnts,
        serve_state_t cs,
        struct sid_state *sstate,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        int variant)
{
  int retval = 0;
  unsigned char makefile_path[PATH_MAX];
  unsigned char tmp_makefile_path[PATH_MAX];
  unsigned char problem_path[PATH_MAX];
  unsigned char cnts_prob_path[PATH_MAX];
  int file_group = -1;
  int file_mode = -1;
  char *text = 0;
  size_t size = 0;
  unsigned char *header = NULL;
  unsigned char *footer = NULL;
  FILE *mk_f = NULL;
  int r;
  struct stat stbuf;

  tmp_makefile_path[0] = 0;

  if (cnts->file_group) {
    file_group = file_perms_parse_group(cnts->file_group);
    if (file_group <= 0) {
      fprintf(log_f, "invalid file group '%s'\n", cnts->file_group);
      FAIL(SSERV_ERR_INV_SYS_GROUP);
    }
  }
  if (cnts->file_mode) {
    file_mode = file_perms_parse_mode(cnts->file_mode);
    if (file_mode <= 0) {
      fprintf(log_f, "invalid file mode '%s'\n", cnts->file_mode);
      FAIL(SSERV_ERR_INV_SYS_MODE);
    }
  }

  if (global->advanced_layout <= 0) FAIL(SSERV_ERR_INV_CONTEST);

  get_advanced_layout_path(cnts_prob_path, sizeof(cnts_prob_path), global, NULL, NULL, 0);
  if (stat(cnts_prob_path, &stbuf) < 0) {
    fprintf(log_f, "contest problem directory '%s' does not exist", cnts_prob_path);
    FAIL(SSERV_ERR_FS_ERROR);
  }
  if (!S_ISDIR(stbuf.st_mode)) {
    fprintf(log_f, "contest problem directory '%s' must be directory", cnts_prob_path);
    FAIL(SSERV_ERR_FS_ERROR);
  }

  get_advanced_layout_path(problem_path, sizeof(problem_path), global, prob, NULL, variant);
  get_advanced_layout_path(tmp_makefile_path, sizeof(tmp_makefile_path), global, prob, "tmp_Makefile", variant);
  get_advanced_layout_path(makefile_path, sizeof(makefile_path), global, prob, DFLT_P_MAKEFILE, variant);

  if (stat(problem_path, &stbuf) < 0) {
    fprintf(log_f, "problem directory '%s' does not exist\n", problem_path);
    FAIL(SSERV_ERR_FS_ERROR);
  }
  if (!S_ISDIR(stbuf.st_mode)) {
    fprintf(log_f, "problem directory '%s' must be directory\n", problem_path);
    FAIL(SSERV_ERR_FS_ERROR);
  }
  if (access(problem_path, R_OK | W_OK | X_OK) < 0) {
    fprintf(log_f, "insufficent permissions for directory '%s'\n", problem_path);
    FAIL(SSERV_ERR_FS_ERROR);
  }

  if (generic_read_file(&text, 0, &size, 0, 0, makefile_path, 0) >= 0) {
    extract_makefile_header_footer(text, &header, &footer);
  }

  mk_f = fopen(tmp_makefile_path, "w");
  if (!mk_f) {
    fprintf(log_f, "cannot create file '%s'\n", tmp_makefile_path);
    FAIL(SSERV_ERR_FS_ERROR);
  }
  if (header) fprintf(mk_f, "%s", header);
  do_generate_makefile(log_f, mk_f, ejudge_config, cnts, cs, sstate, global, prob, variant);
  if (footer) fprintf(mk_f, "%s", footer);
  fclose(mk_f); mk_f = NULL;

  if (file_group > 0 || file_mode > 0) {
    file_perms_set(log_f, tmp_makefile_path, file_group, file_mode, -1, -1);
  }

  r = need_file_update(makefile_path, tmp_makefile_path);
  if (r < 0) {
    fprintf(log_f, "failed to update Makefile\n");
    FAIL(SSERV_ERR_FS_ERROR);
  }
  if (!r) {
    unlink(tmp_makefile_path);
    goto cleanup;
  }
  if (logged_rename(log_f, tmp_makefile_path, makefile_path) < 0) {
    fprintf(log_f, "failed to update Makefile\n");
    FAIL(SSERV_ERR_FS_ERROR);
  }

cleanup:
  if (mk_f) fclose(mk_f);
  if (tmp_makefile_path[0]) unlink(tmp_makefile_path);
  xfree(header);
  xfree(footer);
  xfree(text);
  return retval;
}
