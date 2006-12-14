/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>

static void fatal(const char *format, ...)
  __attribute__((noreturn, format(printf, 1, 2)));
static void
fatal(const char *format, ...)
{
  char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "fatal error: %s\n", buf);
  exit(1);
}

static unsigned char *
extract_class_name(const char *path)
{
  FILE *fin = 0;
  int c;
  size_t u = 0, a = 16;
  unsigned char *b = 0;
  int after_class = 0;

  if (!(b = (unsigned char*) malloc(a))) fatal("out of memory");

  if (!(fin = fopen(path, "r"))) fatal("cannot open input file `%s'", path);
  c = getc_unlocked(fin);
  while (c != EOF) {
    if (c == '/') {
      if ((c = getc_unlocked(fin)) == EOF) break;
      if (c == '/') {
        // line comment
        c = getc_unlocked(fin);
        while (c != EOF && c != '\n') c = getc_unlocked(fin);
        if (c != EOF) c = getc_unlocked(fin);
      } else if (c == '*') {
        // block comment
        c = getc_unlocked(fin);
        while (c != EOF) {
          if (c == '*') {
            if ((c = getc_unlocked(fin)) == EOF) break;
            if (c == '/') break;
          } else {
            c = getc_unlocked(fin);
          }
        }
        if (c != EOF) c = getc_unlocked(fin);
      }
    } else if (c == '\"') {
      // string
      if (after_class) goto invalid_class_name;
      c = getc_unlocked(fin);
      while (c != EOF) {
        if (c == '\"') break;
        if (c == '\\') {
          if ((c = getc_unlocked(fin)) == EOF) break;
        }
        c = getc_unlocked(fin);
      }
      if (c != EOF) c = getc_unlocked(fin);
    } else if (c == '\'') {
      if (after_class) goto invalid_class_name;
      c = getc_unlocked(fin);
      while (c != EOF) {
        if (c == '\'') break;
        if (c == '\\') {
          if ((c = getc_unlocked(fin)) == EOF) break;
        }
        c = getc_unlocked(fin);
      }
      if (c != EOF) c = getc_unlocked(fin);
    } else if (isalpha(c) || c == '_') {
      // identifier
      u = 0;
      while (isalnum(c) || c == '_') {
        if (u + 1 >= a) {
          a *= 2;
          if (!(b = (unsigned char*) realloc(b, a))) fatal("out of memory");
        }
        b[u++] = c;
        c = getc_unlocked(fin);
      }
      b[u] = 0;
      if (after_class) goto good_class_name;
      if (!strcmp(b, "class")) after_class = 1;
    } else if (c <= ' ') {
      c = getc_unlocked(fin);
    } else {
      // default
      if (after_class) goto invalid_class_name;
      c = getc_unlocked(fin);
    }
  }
  fclose(fin); fin = 0;
  return 0;

 good_class_name:
  if (fin) fclose(fin);
  return b;

 invalid_class_name:
  fprintf(stderr, "invalid class name\n");
  if (fin) fclose(fin);
  if (b) free(b);
  return 0;
}

/*
 * Synopsis: ej-javac INFILE OUTFILE [JAVACRUN [JAVAVER [JAVA_HOME ]]
 */
int
main(int argc, char *argv[])
{
  unsigned char *class_name = 0;
  const unsigned char *in_path = 0;
  const unsigned char *out_path = 0;
  const unsigned char *javac_path = 0;
  const unsigned char *java_version = 0;
  const unsigned char *java_home = 0;
  const unsigned char *ejudge_flags = 0;
  unsigned char version_opt[256] = { 0 };
  unsigned char jar_path[PATH_MAX] = "jar";
  unsigned char src_file[PATH_MAX] = { 0 };
  unsigned char out_file[PATH_MAX] = { 0 };
  unsigned char cmd[PATH_MAX];
  int i = 1;

  if (argc < 3) fatal("too few parameters");
  in_path = argv[i++];
  out_path = argv[i++];
  if (i < argc) javac_path = argv[i++];
  if (i < argc) java_version = argv[i++];
  if (i < argc) java_home = argv[i++];

  if (!(class_name = extract_class_name(in_path))) return 1;
  if (!javac_path || !*javac_path) javac_path = "java";
  if (java_version && *java_version) {
    snprintf(version_opt, sizeof(version_opt), " -source %s", java_version);
  }
  if (!java_home || !*java_home) java_home = getenv("JAVA_HOME");
  if (java_home && *java_home) {
    snprintf(jar_path, sizeof(jar_path), "%s/bin/jar", java_home);
  }
  ejudge_flags = getenv("EJUDGE_FLAGS");
  if (!ejudge_flags) ejudge_flags = "";
  snprintf(src_file, sizeof(src_file), "%s.java", class_name);
  snprintf(out_file, sizeof(out_file), "%s.class", class_name);

  if (rename(in_path, src_file) < 0) {
    fprintf(stderr, "rename `%s' -> `%s' failed: %s\n",
            in_path, src_file, strerror(errno));
    return 1;
  }

  snprintf(cmd, sizeof(cmd), "\"%s\"%s -Xlint:unchecked %s %s",
           javac_path, version_opt, ejudge_flags, src_file);
  fprintf(stderr, "%s\n", cmd);
  if (system(cmd) != 0) return 1;
  if (access(out_file, F_OK) < 0) {
    fprintf(stderr, "file `%s' is not created\n", out_file);
    return 1;
  }

  //"${JAVA_HOME}/bin/jar" cvf Main.jar *.class || exit 1
  snprintf(cmd, sizeof(cmd), "\"%s\" cvfe \"%s\" %s *.class",
           jar_path, out_path, class_name);
  fprintf(stderr, "%s\n", cmd);
  if (system(cmd) != 0) return 1;

  return 0;
}
