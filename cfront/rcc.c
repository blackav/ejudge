/* -*- mode:c -*- */
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

#include "ejudge/integral.h"
#include "lconfig.h"
//#include "version.h"

#include "cfrontenv.h"
#include "ejudge/xalloc.h"
#include "ejudge/getopt.h"
#include "ejudge/osdeps.h"
#include "ejudge/errors.h"
#include "ejudge/tempfile.h"
#include "ejudge/exec.h"

#include <string.h>
#include <stdarg.h>
#include <signal.h>

static short verbose_flag = 0;

static short stop_after_cpp_flag = 0;
static short stop_after_cc_flag = 0;
static short force_h_processing = 0;
static char *output_name = 0;
static strarray_t input_files;

static char *compiler_base = 0;

static strarray_t cpp_options;
static short cpp_nostdinc_flag = 0;
static short cpp_undef_flag = 0;
static strarray_t cc_options;
static short gdb_cc_flag = 0;
static short mif_output_flag = 0;
static short tree_output_flag = 1;

static char *cpp_path;
static char *cc_path;

static int sys_incl_init;
static strarray_t sys_incl_dirs;
static strarray_t user_sys_incl_dirs;
static strarray_t user_sys_bef_incl_dirs;

#if !defined __MINGW32__
static short term_signaled = 0;
static void
term_handler(int signo)
{
  term_signaled = 1;
}
#endif

static void
split_at_comma(strarray_t *pa, char const *p)
{
  char const *q = 0;

  while (*p) {
    if (!(q = strchr(p, ','))) {
      xexpand(pa);
      pa->v[pa->u++] = xstrdup(p);
      break;
    }
    if (q != p) {
      xexpand(pa);
      pa->v[pa->u++] = xmemdup(p, q - p);
    }
    p = q + 1;
  }
}

/* -Wp, */
static int
add_cpp_option(char const *opt, int id)
{
  split_at_comma(&cpp_options, opt + 4);
  return 0;
}

/* -Wc, */
static int
add_cc_option(char const *opt, int id)
{
  split_at_comma(&cc_options, opt + 4);
  return 0;
}

static int
add_mif_option(char const *opt, int id)
{
  xexpand(&cc_options);
  cc_options.v[cc_options.u++] = xstrdup("--mif");
  mif_output_flag = 1;
  return 0;
}

static int
add_tree_option(char const *opt, int id)
{
  xexpand(&cc_options);
  cc_options.v[cc_options.u++] = xstrdup("--dump-tree");
  tree_output_flag = 1;
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
  { 1, 0, "-v", "s1", &verbose_flag,
    "Verbose operation", 0 },

  { 1, 0, "-E", "s1", &stop_after_cpp_flag,
    "Preprocess files only", 0 },
  { 1, 0, "-c", "s1", &stop_after_cc_flag,
    "The same as -S currently", 0 },
  { 1, 0, "-S", "s1", &stop_after_cc_flag,
    "Preprocess and compile to assembly language", 0 },
  { 1, 0, "-o", "t1", &output_name,
    "Specify output file name", 0 },

  { 1, 0, "--force-h", "s1", &force_h_processing,
    "Force processing .h files", 0 },
  { 1, 0, "-B", "t1", &compiler_base,
    "Specify a base directory to search files", 0 },
  { 1, 0, "--gdb-cc", "s1", &gdb_cc_flag,
    "Attach debugger to ccmain", 0 },

  { 1, 0, "-I", "V2", &cpp_options,
    "Add directory to include search", 0 },
  { 1, 0, "-D", "V2", &cpp_options,
    "Define a preprocessor symbol", 0 },
  { 1, 0, "-U", "V2", &cpp_options,
    "Undefine a preprocessor symbol", 0 },
  { 1, 0, "-I", "*2V-", &cpp_options,
    "Add directory to include search", 0 },
  { 1, 0, "-D", "*2V-", &cpp_options,
    "Define a preprocessor symbol", 0 },
  { 1, 0, "-U", "*2V-", &cpp_options,
    "Undefine a preprocessor symbol", 0 },
  { 1, 0, "-nostdinc", "s1", &cpp_nostdinc_flag,
    "Do not search in system include directories", 0 },
  { 1, 0, "-undef", "s1", &cpp_undef_flag,
    "Undefine all predefined macros", 0 },
  { 1, 0, "-Wp,", "*4a", &add_cpp_option,
    "Specify a preprocessor option", 0 },
  { 1, 0, "-isystem", "*8a", &user_sys_incl_dirs,
    "Add a system include directory", 0 },
  { 1, 0, "-isysbefore", "*11a", &user_sys_bef_incl_dirs,
    "Add a system include directory before the rcc's ones", 0 },
  { 1, 0, "-include", "V2", &cpp_options,
    "Include the file before the main source file", 0 },

  { 1, 0, "--syntax", "V-", &cc_options,
    "Check syntax only", 0 },
  { 1, 0, "--sema", "V-", &cc_options,
    "Check syntax and semantics", 0 },
  { 1, 0, "--meta", "V-", &cc_options,
    "Generate meta-information", 0 },
  { 1, 0, "--mif", "a", &add_mif_option,
    "Generate MIF", 0 },
  { 1, 0, "--tree", "a", &add_tree_option,
    "Generate CTree", 0 },
  { 1, 0, "--mif-pos", "V-", &cc_options,
    "Add position information into MIF", 0 },
  { 1, 0, "--mif-no-pos", "V-", &cc_options,
    "Do not add position information into MIF", 0 },
  { 1, 0, "-Wc,", "*4a", &add_cc_option,
    "Specify a main compiler option", 0 },
  { 1, 0, "--dump-tree", "V-", &cc_options,
    "Dump the parse tree", 0 },

  { 1, 0, "--meta-struct", "V2", &cc_options,
    "Specify the structure name for which metainformation is generated", 0 },
  { 1, 0, "--meta-enum-prefix", "V2", &cc_options,
    "Specify the meta enumeration prefix", 0 },
  { 1, 0, "--meta-func-prefix", "V2", &cc_options,
    "Specify the meta function prefix", 0 },
  { 1, 0, "--meta-timestamp", "V-", &cc_options,
    "Timestamp the generated files", 0 },

  { 1, 0, "-Wall", "V-", &cc_options,
    "Display all the warnings", 0 },
  { 1, 0, "-g", "V-", &cc_options,
    "Enable debugging info", 0 },
  { 1, 0, "-O", "*2V-", &cc_options,
    "Enable optimizations", 0 },

  { 1, 0, "-", "V-", &input_files,
    "file to process", 0 },
  { 1, 0, opt_default, "V+", &input_files,
    "file to process", 0 },

  { 0, 0, NULL, NULL, NULL, NULL, NULL }
};

static char buildinfo[128];
static void
make_buildinfo(void)
{
  buildinfo[0] = 0;
  /*
  sprintf(buildinfo, "revision %s, copyright (C) 2003-2005 Alexander Chernov",
          compile_version);
  */
}

#ifdef __GNUC__
static void mesg(char const *format, ...)
  __attribute__((format(printf, 1, 2)));
#endif
static void
mesg(char const *format, ...)
{
  va_list args;

  va_start(args, format);
  fprintf(stderr, "%s: ", opt_getname());
  vfprintf(stderr, format, args);
  fprintf(stderr, "\n");
  va_end(args);
}

static void
subprocess_error(const char *path, tpTask tsk)
{
  if (task_Status(tsk) == TSK_SIGNALED) {
    mesg("internal error: subprogram `%s' terminated with signal %d",
         path, task_TermSignal(tsk));
  } else {
    if (task_ExitCode(tsk) != 1) {
      mesg("internal_error: subprogram `%s' terminated with exit code %d",
           path, task_ExitCode(tsk));
    }
  }
}

static void
init_sys_incl_dir(void)
{
  char *s = 0;

  if (sys_incl_init) return;
  sys_incl_init = 1;
  if (cpp_nostdinc_flag) return;

  sys_incl_init = 1;
  s = xstrdup("-isystem");
  s = xstrmerge1(s, get_PRJ_HOME());
  s = xstrmerge1(s, CONF_DIRSEP "include" CONF_DIRSEP "stdlib");
  xexpand(&sys_incl_dirs);
  sys_incl_dirs.v[sys_incl_dirs.u++] = s;
}

static char *
find_program(char const *name)
{
  char *path = 0;

  /* handle -B option */
  if (compiler_base) {
    path = xstrdup(compiler_base);
    path = xstrmerge1(path, name);
    if (os_CheckAccess(path, REUSE_X_OK) >= 0) return path;
    xfree(path); path = 0;
  }

#if defined CONF_WRAPPERS && CONF_WRAPPERS == 0
  path = xstrdup(get_PRJ_HOME());
  path = xstrmerge1(path, CONF_DIRSEP "bin" CONF_DIRSEP);
  path = xstrmerge1(path, name);
#ifdef CONF_EXE_SUFFIX
  path = xstrmerge1(path, CONF_EXE_SUFFIX);
#endif /* CONF_EXE_SUFFIX */
  if (os_CheckAccess(path, REUSE_X_OK) >= 0) return path;
  xfree(path); path = 0;
#endif /* CONF_WRAPPERS */

  path = xstrdup(get_PRJ_HOME());
  path = xstrmerge1(path, CONF_DIRSEP "libexec" CONF_DIRSEP);
  path = xstrmerge1(path, get_PRJ_CONFIG());
  path = xstrmerge1(path, CONF_DIRSEP);
  path = xstrmerge1(path, name);
#ifdef CONF_EXE_SUFFIX
  path = xstrmerge1(path, CONF_EXE_SUFFIX);
#endif /* CONF_EXE_SUFFIX */
  if (os_CheckAccess(path, REUSE_X_OK) >= 0) return path;
  xfree(path); path = 0;

#ifdef CONF_RUNTIME_STR
  path = xstrdup(get_PRJ_HOME());
  path = xstrmerge1(path, CONF_DIRSEP "libexec" CONF_DIRSEP);
  path = xstrmerge1(path, CONF_RUNTIME_STR);
  path = xstrmerge1(path, CONF_DIRSEP);
  path = xstrmerge1(path, name);
#ifdef CONF_EXE_SUFFIX
  path = xstrmerge1(path, CONF_EXE_SUFFIX);
#endif /* CONF_EXE_SUFFIX */
  if (os_CheckAccess(path, REUSE_X_OK) >= 0) return path;
  xfree(path); path = 0;
#endif /* CONF_RUNTIME_STR */

  /*
  path = xstrdup(get_PRJ_HOME());
  path = xstrmerge1(path, CONF_DIRSEP);
  path = xstrmerge1(path, name);
  if (os_CheckAccess(path, REUSE_X_OK) >= 0) return path;
  xfree(path); path = 0;

  if ((path = os_FindInPath(name))) {
    if (os_CheckAccess(path, REUSE_X_OK) >= 0) return path;
    xfree(path); path = 0;
  }
  */

  err_Startup("`%s' is not found. Probably a configuration error.", name);
  return 0;
}

static int
run_cpp(char const *in, char const *out)
{
  tpTask cpp_task = 0;

  if (!cpp_path) cpp_path = find_program("ej-cpp");
  if (!cpp_path) return 1;

  init_sys_incl_dir();

  cpp_task = task_New();
  task_AddArg(cpp_task, cpp_path);
  //task_AddArg(cpp_task, "-nostdinc");
  //task_AddArg(cpp_task, "-no-gcc");
  //task_AddArg(cpp_task, "-undef");
  //task_AddArg(cpp_task, "-A-");
  if (verbose_flag) {
    task_AddArg(cpp_task, "-v");
  }
  if (!cpp_undef_flag) {
    char buf[64];

    sprintf(buf, "-D__RCC__=%d", CONF_VERSION_CODE);
    task_AddArg(cpp_task, buf);
    sprintf(buf, "-D__REPC__=%d", CONF_VERSION_CODE);
    task_AddArg(cpp_task, buf);
    task_AddArg(cpp_task, "-D__STDC__");
    task_AddArg(cpp_task, "-D__STDC_VERSION__=199409");

    task_AddArg(cpp_task, "-Dlinux");
  }

  task_pnAddArgs(cpp_task, cpp_options.u, cpp_options.v);

  task_pnAddArgs(cpp_task, user_sys_bef_incl_dirs.u, user_sys_bef_incl_dirs.v);
  task_pnAddArgs(cpp_task, sys_incl_dirs.u, sys_incl_dirs.v);
  task_pnAddArgs(cpp_task, user_sys_incl_dirs.u, user_sys_incl_dirs.v);

  /* hard-coded args */
  if (!cpp_nostdinc_flag) {
    task_AddArg(cpp_task, "-iwarn/usr/local/include");
    task_AddArg(cpp_task, "-iwarn/usr/include");
  }

  if (out) {
    task_AddArg(cpp_task, "-o");
    task_AddArg(cpp_task, out);
  }
  task_AddArg(cpp_task, in);

  task_SetPathAsArg0(cpp_task);
  if (task_Start(cpp_task) < 0) goto failure;
  if (!task_Wait(cpp_task)) goto failure;
  if (task_IsAbnormal(cpp_task)) {
    subprocess_error(cpp_path, cpp_task);
    goto failure;
  }
  task_Delete(cpp_task);
  return 0;

 failure:
  if (cpp_task) task_Delete(cpp_task);
  return 1;
}

static int
run_cc(char const *in, char const *out)
{
  tpTask cc_task = 0;

  if (!cc_path) cc_path = find_program("ej-ccmain");
  if (!cc_path) return 1;

  init_sys_incl_dir();

  cc_task = task_New();
  if (gdb_cc_flag) {
    task_AddArg(cc_task, "/usr/bin/gdb");
    task_AddArg(cc_task, "--args");
  }
  task_AddArg(cc_task, cc_path);
  if (mif_output_flag) {
    task_AddArg(cc_task, "--mif");
  } else if (tree_output_flag) {
    task_AddArg(cc_task, "--tree");
  }
  task_pnAddArgs(cc_task, cc_options.u, cc_options.v);
  task_pnAddArgs(cc_task, user_sys_bef_incl_dirs.u, user_sys_bef_incl_dirs.v);
  task_pnAddArgs(cc_task, sys_incl_dirs.u, sys_incl_dirs.v);
  task_pnAddArgs(cc_task, user_sys_incl_dirs.u, user_sys_incl_dirs.v);
  task_AddArg(cc_task, "-o");
  task_AddArg(cc_task, out);
  task_AddArg(cc_task, in);

  task_SetPathAsArg0(cc_task);
  if (task_Start(cc_task) < 0) goto failure;
  if (!task_Wait(cc_task)) goto failure;
  if (task_IsAbnormal(cc_task)) {
    subprocess_error(cc_path, cc_task);
    goto failure;
  }
  task_Delete(cc_task);
  return 0;

 failure:
  if (cc_task) task_Delete(cc_task);
  return 1;
}

static int
process_file(int i, char const *name)
{
  char suffix[64];
  int start_phase = -1;
  int in_temp_flag, out_temp_flag;
  char *in_name = 0, *out_name = 0;

  os_rGetSuffix(name, suffix, sizeof(suffix));
  if (!strcmp(suffix, ".c")) {
    start_phase = 0;
  } else if (!strcmp(suffix, ".h") && force_h_processing) {
    start_phase = 0;
  } else if (!strcmp(suffix, ".h")) {
    mesg("header file `%s' is ignored", name);
    return 0;
  } else if (!strcmp(suffix, ".i")) {
    start_phase = 1;
  }

  if (start_phase < 0) {
    mesg("file `%s' has unknown suffix `%s'", name, suffix);
    return 1;
  }
  if (start_phase == 1 && (stop_after_cpp_flag)) {
    mesg("preprocessed input file `%s' is ignored as compiling is not done",
         name);
    return 0;
  }
  in_name = xstrdup(name);
  in_temp_flag = 0;

  if (start_phase == 0) {
    if (stop_after_cpp_flag && output_name) {
      out_name = xstrdup(output_name);
      out_temp_flag = 0;
    } else if (stop_after_cpp_flag) {
      out_name = 0;
      out_temp_flag = 0;
    } else {
      out_name = temp_Create(0, "cvmcc", ".i");
      out_temp_flag = 1;
    }

    if (run_cpp(in_name, out_name)) goto failure;
    if (in_temp_flag) temp_Remove(in_name);
    //xfree(in_name);
    in_temp_flag = out_temp_flag;
    in_name = out_name;
    out_temp_flag = 0;
    out_name = 0;
  }
  if (stop_after_cpp_flag) return 0;

  if (start_phase <= 1) {
    if (stop_after_cc_flag && output_name) {
      out_name = xstrdup(output_name);
      out_temp_flag = 0;
    } else if (stop_after_cc_flag) {
      if (tree_output_flag) {
        out_name = os_SubstSuffix(name, ".tree");
      } else if (mif_output_flag) {
        out_name = os_SubstSuffix(name, ".mif");
      } else {
        out_name = os_SubstSuffix(name, ".s");
      }
      out_temp_flag = 0;
    } else {
      out_name = temp_Create(0, "cvmcc", ".s");
      out_temp_flag = 1;
    }
    if (run_cc(in_name, out_name)) goto failure;
    if (in_temp_flag) temp_Remove(in_name);
    //xfree(in_name);
    in_temp_flag = out_temp_flag;
    in_name = out_name;
    out_temp_flag = 0;
    out_name = 0;
  }
  if (stop_after_cc_flag) return 0;

  fprintf(stderr, "something bad happened!\n");
  abort();

 failure:
  if (in_temp_flag) temp_Remove(in_name);
  if (out_temp_flag) temp_Remove(out_name);
  //xfree(in_name);
  //xfree(out_name);
  return 1;
}

void
cleanup_func(void)
{
  temp_Finalize();
}

int
main(int argc, char **argv)
{
  int i;
  int was_errors = 0;

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

  if (verbose_flag) {
    task_SetFlag(0, 200);
  }

  if (stop_after_cpp_flag && stop_after_cc_flag) {
    err_Startup("conflicting options: -E and -S");
  }
  if (stop_after_cpp_flag && output_name && input_files.u > 1) {
    err_Startup("conflicting options: %d files, -E, -o", input_files.u);
  }
  if (stop_after_cc_flag && output_name && input_files.u > 1) {
    err_Startup("conflicting options: %d files, -S, -o", input_files.u);
  }
  if (!stop_after_cpp_flag) {
    stop_after_cc_flag = 1;
  }
  if (!input_files.u) {
    err_Startup("no input files");
  }

#if !defined __MINGW32__
  /* install handlers for everything, that may terminate process */
  signal(SIGHUP, term_handler);
  signal(SIGINT, term_handler);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGALRM, term_handler);
  signal(SIGTERM, term_handler);
  signal(SIGUSR1, term_handler);
  signal(SIGUSR2, term_handler);
#endif /* CONF_WIN32_API */

  for (i = 0; i < input_files.u; i++) {
    if (process_file(i, input_files.v[i])) {
      was_errors++;
    }
  }

  if (was_errors) return 1;
  return 0;
}
