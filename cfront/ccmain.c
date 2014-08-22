/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "lconfig.h"

#include "tree.h"
#include "scanner.h"
#include "sema.h"
//#include "mif_entry.h"
#include "c_errors.h"
//#include "backend/cvm_entry.h"
//#include "version.h"
#include "meta.h"

#include "ejudge/tempfile.h"
#include "ejudge/getopt.h"
#include "ejudge/osdeps.h"
#include "ejudge/xalloc.h"

#include <stdio.h>
#include <string.h>
#include <locale.h>

static optrec_t *sema_options_ptr = sema_options;
//static optrec_t *mif_options_ptr = mif_options;
static optrec_t *meta_options_ptr = meta_options;

static char buildinfo[128];
static void
make_buildinfo(void)
{
  buildinfo[0] = 0;
  /*
  snprintf(buildinfo, sizeof(buildinfo), "revision %s, copyright (C) 2003-2005 Alexander Chernov", compile_version);
  */
}

static void
cleanup_func(void)
{
  temp_Finalize();
}

static int is_system_file(char const *path, char *out, size_t outlen);

static short flag_verbose = 0;
static short flag_syntax_only = 0;
static short flag_dump_tree = 0;
static short flag_sema_only = 0;
static short flag_mif_only = 0;
static short flag_cvm_output = 0;
static short flag_meta_only = 0;
static short flag_tree_only = 0;

static char *output_name = 0;
static strarray_t input_files;
static char *input_name = 0;
static strarray_t system_include_dirs;

static short flag_ignored = 0;

static int
add_to_system_dirs(const char *opt, int id)
{
  xexpand(&system_include_dirs);
  system_include_dirs.v[system_include_dirs.u++] = xstrdup(opt + 8);
  return 0;
}

static int
add_to_system_dirs2(const char *opt, int id)
{
  xexpand(&system_include_dirs);
  system_include_dirs.v[system_include_dirs.u++] = xstrdup(opt + 11);
  return 0;
}

static optrec_t options[] =
{
  { 1, 0, "-V", "v", (void *) 1, 
    "Display version information", 0 },
  { 1, 0, "--version", "v", (void *) 1, 
    "Display version information", 0 },
  { 1, 0, "--help", "h", (void *) 1,
    "Display help message", 0 },
  { 1, 0, "-v", "s1", &flag_verbose,
    "Verbose operation", 0 },

  { 1, 0, "-o", "t1", &output_name,
    "Specify output file name", 0 },
  { 1, 0, "-isystem", "*8a", &add_to_system_dirs,
    "Add a system include directory", 0 },
  { 1, 0, "-isysbefore", "*11a", &add_to_system_dirs2,
    "Add a system include directory", 0 },

  { 1, 0, "--syntax", "s1", &flag_syntax_only,
    "Stop after parsing", 0 },
  { 1, 0, "--sema", "s1", &flag_sema_only,
    "Stop after semantics checking", 0 },
  { 1, 0, "--mif", "s1", &flag_mif_only,
    "Stop after MIF generation", 0 },
  { 1, 0, "--cvm", "s1", &flag_cvm_output,
    "Generate code for CVM machine", 0 },
  { 1, 0, "--dump-tree", "s1", &flag_dump_tree,
    "Dump the syntax tree", 0 },
  { 1, 0, "--meta", "s1", &flag_meta_only,
    "Generate metainformation", 0 },
  { 1, 0, "--tree", "s1", &flag_tree_only,
    "Dump the syntax tree", 0 },

  { 0, 0, "", "@@", &sema_options_ptr, 0, 0, 0 },
  { 0, 0, "", "@@", &meta_options_ptr, 0, 0, 0 },
  //{ 0, 0, "", "@@", &mif_options_ptr, 0, 0, 0 },
  //{ 0, 0, "", "@@", &cvm_backend_gate.opt_arr, 0, 0, 0 },

  { 1, 0, "-g", "s1", &flag_ignored, 0, 0 },
  { 1, 0, "-Wall", "s1", &flag_ignored, 0, 0 },

  { 1, 0, "-", "V-", &input_files,
    "file to process", 0 },
  { 1, 0, opt_default, "V+", &input_files,
    "file to process", 0 },

  { 0, 0, NULL, NULL, NULL, NULL, NULL }
};

int
main(int argc, char *argv[])
{
  int t;
  tree_t res;
  //mif_t mif;
  FILE *in = 0, *out = 0;

  make_buildinfo();
  opt_setargs(options, NULL, NULL, buildinfo, NULL, argc, argv, 0);
  atexit(cleanup_func);

  /*
  if (os_GuessProjectEnv(argv[0], CONF_ENV_PREFIX) < 0) {
    err_Startup("%s_HOME or %s_CONFIG are not set and cannot be guessed",
                CONF_ENV_PREFIX, CONF_ENV_PREFIX);
  }
  */

  while (opt_get() != OPT_END);
  opt_close();

  setlocale(LC_CTYPE, "");

  if (input_files.u > 1) {
    err_Startup("too many input files");
  }
  if (!input_files.u) {
    err_Startup("no input files");
  }
  input_name = input_files.v[0];

  /*
  if (flag_cvm_output && cvm_backend_gate.startup_func) {
    cvm_backend_gate.startup_func();
  }
  */

  if (!strcmp(input_name, "-")) {
    scanner_set_input("<stdin>", stdin);
  } else {
    in = fopen(input_name, "r");
    if (!in) {
      err_Startup("cannot open input file `%s'", input_name);
      return 1;
    }
    scanner_set_input(input_name, in);
  }

  t = parser_parse(&res);
  if (t || c_err_get_count() > 0) return 1;
  if (flag_syntax_only) return 0;
  if (flag_dump_tree) {
    tree_dump(stdout, res);
    return 0;
  }

  if (flag_meta_only) {
    flag_tree_only = 0;
  }

  if (flag_tree_only) {
    if (!output_name) output_name = "-";
    if (!strcmp(output_name, "-")) {
      out = stdout;
    } else {
      out = fopen(output_name, "w");
      if (!out) {
        err_Startup("cannot open output file `%s'", output_name);
      }
    }
    tree_dump(out, res);
    if (strcmp(output_name, "-") != 0) {
      fclose(out);
    }
    return 0;
  }

  setlocale(LC_CTYPE, "C");

  t = main_sema_analyze(res);
  if (t || c_err_get_count() > 0) return 1;
  if (flag_sema_only) return 0;

  if (flag_meta_only) {
    return main_meta_generate(res, output_name);
  }

  /*
  t = main_mif_generate(res, is_system_file, &mif);
  if (t || !mif || c_err_get_count() > 0) return 1;
  if (flag_mif_only) {
    if (!output_name) output_name = "-";
    if (!strcmp(output_name, "-")) {
      out = stdout;
    } else {
      out = fopen(output_name, "w");
      if (!out) {
        err_Startup("cannot open output file `%s'", output_name);
      }
    }
    main_mif_print(mif, out);
    if (strcmp(output_name, "-") != 0) {
      fclose(out);
    }
    return 0;
  }
  */

  /*
  if (flag_cvm_output && cvm_backend_gate.entry_func) {
    struct cvm_mod_in cvm_in;
    struct cvm_mod_out cvm_out;
    int r = -1;

    memset(&cvm_in, 0, sizeof(cvm_in));
    memset(&cvm_out, 0, sizeof(cvm_out));
    if (!output_name) output_name = "-";
    if (!strcmp(output_name, "-")) {
      out = stdout;
    } else {
      out = fopen(output_name, "w");
      if (!out) {
        err_Startup("cannot open output file `%s'", output_name);
      }
    }

    cvm_in.mif = mif;
    cvm_in.out_stream = out;
    cvm_in.out_name = output_name;
    r = cvm_backend_gate.entry_func(&cvm_in, &cvm_out);
    if (strcmp(output_name, "-") != 0) {
      fclose(out);
    }
    if (r < 0) return 1;
  }
  */

  return 0;
}

static int
is_system_file(char const *path, char *out, size_t outlen)
  __attribute__((unused));
static int
is_system_file(char const *path, char *out, size_t outlen)
{
  int i;
  int len1, len2;

  len2 = strlen(path);
  for (i = 0; i < system_include_dirs.u; i++) {
    len1 = strlen(system_include_dirs.v[i]);
    if (!strncmp(system_include_dirs.v[i], path, len1) && len1 < len2) break;
  }
  if (i >= system_include_dirs.u) return 0;
  if (!outlen) return 1;
  while (path[len1] == '/') len1++;
  snprintf(out, outlen, "<%s>", path + len1);

  return 1;
}
