/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2010 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"
#include "ej_limits.h"
#include "version.h"

#include "mime_type.h"
#include "t3_packets.h"
#include "interrupt.h"
#include "startstop.h"
#include "ejudge_cfg.h"
#include "pathutl.h"
#include "fileutl.h"
#include "errlog.h"
#include "misctext.h"
#include "parsecfg.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>
#include <reuse/logger.h>

#if CONF_HAS_LIBZIP - 0 == 1
#include <zip.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

#ifndef EJ_PATH_MAX
#define EJ_PATH_MAX 4096
#endif

#define logerr(txt,...) flogerr(log, __FUNCTION__, txt,## __VA_ARGS__)

#define ROOT_XML_FILE_NAME "examcheck.xml"
#define OUTPUT_XML_FILE_NAME "examresults.xml"
#define MAX_ROOT_XML_SIZE  (128*1024*1024)
#define MAX_CONTEST_COUNT 1000000

static const unsigned char *program_name;
static unsigned char *program_dir;

/* this is a COMMON variable, so it is not initialized */
struct ejudge_cfg *ejudge_config;
static unsigned char *t3_mediator_dir;
static char *t3_var_dir;
static char *spool_in_dir;
static char *spool_out_dir;
static char *t3_conf_dir;

struct config_global_data
{
  struct generic_section_config g;

  /** directory polling interval */
  int sleep_time;
};

struct config_contest_data
{
  struct generic_section_config g;

  int id;
  unsigned char *guid;
};

#define XFSIZE(t, x) (sizeof(((t*) 0)->x))

#define GLOBAL_OFFSET(x)   XOFFSET(struct config_global_data, x)
#define GLOBAL_SIZE(x)     XFSIZE(struct config_global_data, x)
#define GLOBAL_PARAM(x, t) { #x, t, GLOBAL_OFFSET(x), GLOBAL_SIZE(x) }
static const struct config_parse_info config_global_params[] =
{
  GLOBAL_PARAM(sleep_time, "d"),

  { 0, 0, 0, 0 }
};

#define CONTEST_OFFSET(x)   XOFFSET(struct config_contest_data, x)
#define CONTEST_SIZE(x)     XFSIZE(struct config_contest_data, x)
#define CONTEST_PARAM(x, t) { #x, t, CONTEST_OFFSET(x), CONTEST_SIZE(x) }
static const struct config_parse_info config_contest_params[] =
{
  CONTEST_PARAM(id, "d"),
  CONTEST_PARAM(guid, "S"),

  { 0, 0, 0, 0 }
};

static const struct config_section_info params[] =
{
  { "global", sizeof(struct config_global_data), config_global_params, 0,0,0},
  { "contest",sizeof(struct config_contest_data),config_contest_params,0,0,0},
  { NULL, 0, NULL }
};

static struct generic_section_config *config;
static struct config_global_data *global = 0;
static int contest_count = 0;
static struct config_contest_data **contests = 0;

static void
die(const char *format, ...)
  __attribute__((noreturn, format(printf, 1, 2)));
static void
die(const char *format, ...)
{
  char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: fatal: %s\n", program_name, buf);
  exit(1);
}

static int
flogerr(FILE *log, const char *function, const char *format, ...)
  __attribute__((format(printf, 3, 4)));
static int
flogerr(FILE *log, const char *function, const char *format, ...)
{
  char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(log, "%s: %s\n", function, buf);
  return -1;
}

static void
get_program_dir(const unsigned char *program_path)
{
  unsigned char *workdir = 0;
  unsigned char fullpath[EJ_PATH_MAX];

  if (os_IsAbsolutePath(program_path)) {
    program_dir = os_DirName(program_path);
    os_normalize_path(program_dir);
    return;
  }

  workdir = os_GetWorkingDir();
  snprintf(fullpath, sizeof(fullpath), "%s/%s", workdir, program_path);
  xfree(workdir); workdir = 0;
  os_normalize_path(fullpath);
  program_dir = os_DirName(fullpath);
}

static void
print_version(void)
{
  printf("%s %s, compiled %s\n", program_name, compile_version, compile_date);
  exit(0);
}

static void
print_help(void)
{
  exit(0);
}

static int
handle_packet_zip_file(
        FILE *log,
        const unsigned char *path,
        const unsigned char *out_path)
{
#if CONF_HAS_LIBZIP - 0 == 1
  int zip_err = 0;
  struct zip *z = 0, *oz = 0;
  char errbuf[1024];
  int retval = -1;
  int root_xml_ind;
  struct zip_stat zs;
  unsigned char *root_xml_buf = 0;
  struct zip_file *zf = 0;
  struct t3_in_packet *in_packet = 0;
  int i, file_ind;
  struct t3_out_packet *out_packet = 0;
  FILE *res_f = 0;
  char *res_t = 0;
  size_t res_z = 0;
  struct zip_source *zr = 0;

  if (!(z = zip_open(path, ZIP_CHECKCONS, &zip_err))) {
    zip_error_to_str(errbuf, sizeof(errbuf), zip_err, errno);
    logerr("failed to open ZIP '%s': %s", path, errbuf);
    goto cleanup;
  }

  root_xml_ind = zip_name_locate(z, ROOT_XML_FILE_NAME, 0);
  if (root_xml_ind < 0) {
    logerr("failed to locate '%s' in '%s'", ROOT_XML_FILE_NAME, path);
    goto cleanup;
  }

  zip_stat_init(&zs);
  if (zip_stat_index(z, root_xml_ind, 0, &zs) < 0) {
    logerr("failed to stat entry '%s' (%d) in '%s'", ROOT_XML_FILE_NAME,
           root_xml_ind, path);
    goto cleanup;
  }

  if (!zs.size) {
    logerr("entry '%s' is empty in '%s'", ROOT_XML_FILE_NAME, path);
    goto cleanup;
  }
  if (zs.size > MAX_ROOT_XML_SIZE) {
    logerr("entry '%s' it too big (size = %ld) in '%s'",
           ROOT_XML_FILE_NAME, zs.size, path);
    goto cleanup;
  }

  XCALLOC(root_xml_buf, zs.size + 1);
  int rem_size = (int) zs.size;
  unsigned char *buf_ptr = root_xml_buf;

  if (!(zf = zip_fopen_index(z, root_xml_ind, 0))) {
    logerr("failed to open entry '%s' in '%s': %s", ROOT_XML_FILE_NAME,
           path, zip_strerror(z));
    goto cleanup;
  }

  while (rem_size > 0) {
    int r = zip_fread(zf, buf_ptr, rem_size);
    if (r < 0) {
      logerr("read error on '%s' in '%s': %s", ROOT_XML_FILE_NAME,
             path, zip_file_strerror(zf));
      goto cleanup;
    }
    if (!r) {
      logerr("zip_fread returned 0 on '%s' in '%s', why?", ROOT_XML_FILE_NAME,
             path);
      goto cleanup;
    }
    buf_ptr += r;
    rem_size -= r;
  }
  zip_fclose(zf); zf = 0;

  if (strlen(root_xml_buf) != zs.size) {
    logerr("entry '%s' in '%s' contains \\0 in the middle", ROOT_XML_FILE_NAME,
           path);
    goto cleanup;
  }

  in_packet = t3_in_packet_parse_str(log, root_xml_buf);
  if (!in_packet) {
    logerr("failed to parse entry '%s' in '%s'", ROOT_XML_FILE_NAME, path);
    goto cleanup;
  }

  printf("Count: %d\n", in_packet->submit_count);
  for (i = 0; i < in_packet->submit_count; ++i) {
    struct t3_in_submit *submit = &in_packet->submits[i];
    file_ind = zip_name_locate(z, submit->filename, 0);
    if (file_ind < 0) {
      logerr("entry '%s' is not found", submit->filename);
      goto cleanup;
    }
    zip_stat_init(&zs);
    if (zip_stat_index(z, file_ind, 0, &zs) < 0) {
      logerr("entry '%s' is not found", submit->filename);
      goto cleanup;
    }
    printf("[%d]: %s, %s, %s, %s, %s, %ld\n", i, submit->filename,
           submit->prob_guid, submit->user_guid, submit->prog_lang,
           submit->prog_charset, zs.size);
  }

  out_packet = t3_out_packet_make_from_in(in_packet);
  if (!out_packet) {
    logerr("failed to copy data");
    goto cleanup;
  }

  /* generate output */

  res_f = open_memstream(&res_t, &res_z);
  if (!res_f) { // this normally never happens
    logerr("open_memstream failed");
    goto cleanup;
  }
  t3_out_packet_write(res_f, out_packet);
  fclose(res_f); res_f = 0;

  zip_err = 0; errbuf[0] = 0;
  oz = zip_open(out_path, ZIP_CREATE, &zip_err);
  if (!oz) {
    zip_error_to_str(errbuf, sizeof(errbuf), zip_err, errno);
    logerr("failed to create '%s' in '%s': %s",
           OUTPUT_XML_FILE_NAME, out_path, errbuf);
    goto cleanup;
  }
  if (!(zr = zip_source_buffer(oz, res_t, res_z, 0))) {
    logerr("failed to create '%s' in '%s': %s",
           OUTPUT_XML_FILE_NAME, out_path, zip_strerror(oz));
    goto cleanup;
  }
  if (zip_add(oz, OUTPUT_XML_FILE_NAME, zr) < 0) {
    logerr("failed to create '%s' in '%s': %s",
           OUTPUT_XML_FILE_NAME, out_path, zip_strerror(oz));
    goto cleanup;
  }
  zr = 0;
  if (zip_close(oz) < 0) {
    logerr("zip_close() failed: %s", zip_strerror(oz));
  }
  oz = 0;
  xfree(res_t); res_t = 0; res_z = 0;

  retval = 0;

 cleanup:
  if (zr) {
    zip_source_free(zr); zr = 0;
  }
  if (oz) {
    zip_close(oz); oz = 0;
  }
  if (res_f) {
    fclose(res_f); res_f = 0;
  }
  xfree(res_t);
  out_packet = t3_out_packet_free(out_packet);
  in_packet = t3_in_packet_free(in_packet);
  if (zf) {
    zip_fclose(zf); zf = 0;
  }
  xfree(root_xml_buf);
  if (z) {
    zip_close(z); z = 0;
  }

  return retval;
#else
  logerr("Zip archives are not supported");
  return -1;
#endif /* CONF_HAS_LIBZIP */
}

static int
handle_packet_file(
        FILE *log,
        const unsigned char *path,
        const unsigned char *out_path)
{
  int mime_type = 0;
  struct stat stb;

  if (!path || !strlen(path)) {
    logerr("empty path");
    return -1;
  }
  if (stat(path, &stb) < 0) {
    logerr("file '%s' does not exist", path);
    return -1;
  }
  if (stb.st_size <= 0) {
    logerr("file '%s' is empty", path);
    return -1;
  }
  if (!S_ISREG(stb.st_mode)) {
    logerr("file '%s' is not a regular file", path);
    return -1;
  }
  mime_type = mime_type_guess_file(path, 0);
  if (mime_type < 0) {
    logerr("failed to guess type of file '%s'", path);
    return -1;
  }

  if (mime_type != MIME_TYPE_APPL_ZIP) {
    logerr("unsupported mime type '%s' of '%s'", mime_type_get_type(mime_type),
           path);
    return -1;
  }

  return handle_packet_zip_file(log, path, out_path);
}

static void
unique_name(
        unsigned char *out_path,
        int out_len,
        const unsigned char *name)
{
  struct timeval tv;

  gettimeofday(&tv, 0);
  snprintf(out_path, out_len, "%s_%d_%ld_%ld_%s",
           os_NodeName(), getpid(), tv.tv_sec, tv.tv_usec, name);
}

static int
move_out(
        unsigned char *out_path,
        int out_len,
        const unsigned char *pkt_name)
{
  unsigned char dir_path[EJ_PATH_MAX];
  unsigned char in_name[EJ_PATH_MAX];
  int r;
  struct stat stb;

  snprintf(dir_path, sizeof(dir_path), "%s/dir/%s", spool_in_dir, pkt_name);
  unique_name(in_name, sizeof(in_name), pkt_name);
  snprintf(out_path, out_len, "%s/out/%s", spool_in_dir, in_name);

  errno = 0;
  r = rename(dir_path, out_path);
  if (r < 0 && errno == ENOENT) {
    info("No entry '%s'", dir_path);
    out_path[0] = 0;
    return 0;
  }
  if (r < 0) {
    err("rename '%s'->'%s' failed: %s", dir_path, out_path, os_ErrorMsg());
    return -1;
  }

  if (stat(out_path, &stb) < 0) {
    err("stat failed on '%s': %s", dir_path, os_ErrorMsg());
    return -1;
  }
  if (stb.st_nlink == 1) {
    // everything is ok
    return 1;
  }

  rename(out_path, dir_path);
  return 0;
}

static int
move_in(const unsigned char *pkt_name, const unsigned char *path)
{
  unsigned char dir_path[EJ_PATH_MAX];
  int r;

  snprintf(dir_path, sizeof(dir_path), "%s/dir/%s", spool_out_dir, pkt_name);
  r = rename(path, dir_path);
  if (r < 0) {
    err("rename '%s'->'%s' failed: %s", path, dir_path, os_ErrorMsg());
  }
  return r;
}

static void
make_error_file(const char *out_path, const char *txt)
{
  unsigned char *escaped_str = 0;
  FILE *out = 0;

  if (!(out = fopen(out_path, "w"))) {
    err("failed to open '%s': %s", out_path, os_ErrorMsg());
    return;
  }

  escaped_str = html_armor_string_dup(txt);
  fprintf(out, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n");
  fprintf(out, "<examresults e=\"\">\n");
  fprintf(out, "  <error>%s</error>\n", escaped_str);
  fprintf(out, "</examresults>\n");
  xfree(escaped_str);

  fclose(out);
}

static int
server_loop(void)
{
  int r;
  unsigned char pkt_name[EJ_PATH_MAX];
  unsigned char in_path[EJ_PATH_MAX];
  unsigned char out_name[EJ_PATH_MAX];
  unsigned char out_path[EJ_PATH_MAX];
  FILE *log_f = 0;
  char *log_t = 0;
  size_t log_z = 0;

  info("ej-t3-mediator server started");
  interrupt_init();
  interrupt_disable();
  in_path[0] = 0;
  out_path[0] = 0;

  while (1) {
    if (in_path[0]) {
      unlink(in_path);
      in_path[0] = 0;
    }
    if (out_path[0]) {
      unlink(out_path);
      out_path[0] = 0;
    }

    if (interrupt_get_status() || interrupt_restart_requested()) break;

    r = scan_dir(spool_in_dir, pkt_name, sizeof(pkt_name));
    if (r < 0) {
      if (r == -ENOMEM || r == -ENOENT || r == -ENFILE) {
        err("trying to recover, sleep for 5 seconds");
        interrupt_enable();
        os_Sleep(5000);
        interrupt_disable();
        continue;
      }
      err("unrecoverable error, exiting");
      return -1;
    }

    if (!r) {
      interrupt_enable();
      os_Sleep(1000);
      interrupt_disable();
      continue;
    }

    /* handle the inbound packet */
    r = move_out(in_path, sizeof(in_path), pkt_name);
    if (!r) {
      // proceed to the next entry without waiting
      continue;
    }
    if (r < 0) {
      // unrecoverable error
      break;
    }

    unique_name(out_name, sizeof(out_name), pkt_name);
    snprintf(out_path, sizeof(out_path), "%s/in/%s", spool_out_dir, out_name);

    info("received packet '%s'", pkt_name);

    log_f = open_memstream(&log_t, &log_z);
    r = handle_packet_file(log_f, in_path, out_path);
    fclose(log_f); log_f = 0;

    if (r < 0) {
      make_error_file(out_path, log_t);
      fprintf(stderr, "%s", log_t);
    }
    xfree(log_t); log_t = 0; log_z = 0;

    move_in(pkt_name, out_path);

    info("packet '%s' handled", pkt_name);
  }

  return 0;
}

static int
parse_config(FILE *log)
{
  unsigned char config_path[EJ_PATH_MAX];
  FILE *f = 0;
  int retval = -1, i;
  struct generic_section_config *p;

  snprintf(config_path, sizeof(config_path), "%s/contests.cfg", t3_conf_dir);
  if (!(f = fopen(config_path, "r"))) {
    logerr("cannot open '%s'", config_path);
    return -1;
  }
  if (!(config = parse_param(config_path, 0, params, 1, 0, 0, 0)))
    goto cleanup;
  fclose(f); f = 0;

  for (p = config; p; p = p->next) {
    if (!p->name[0] || !strcmp(p->name, "global")) {
      global = (struct config_global_data *) p;
    }
  }
  if (!global) {
    logerr("no global section in configuration file");
    goto cleanup;
  }

  for (p = config; p; p = p->next) {
    if (!strcmp(p->name, "contest")) {
      ++contest_count;
    }
  }
  if (!contest_count) {
    logerr("no contests defined in configuration file");
    goto cleanup;
  }
  if (contest_count < 0 || contest_count > MAX_CONTEST_COUNT) {
    logerr("too many (%d) contests defined in configuration file",
           contest_count);
    goto cleanup;
  }

  XCALLOC(contests, contest_count);
  for (p = config, i = 0; p; p = p->next) {
    if (!strcmp(p->name, "contest")) {
      contests[i++] = (struct config_contest_data*) p;
    }
  }

  retval = 0;

 cleanup:
  if (f) {
    fclose(f);
  }
  return retval;
}

int
main(int argc, char *argv[])
{
  int i = 1, j = 0, pid;
  int daemon_mode = 0;
  int batch_mode = 0;
  char **argv_restart = 0;
  const unsigned char *ejudge_xml_path = 0;
  unsigned char pathbuf[EJ_PATH_MAX];

  start_set_self_args(argc, argv);
  XCALLOC(argv_restart, argc + 1);
  argv_restart[j++] = argv[0];

  if (argc <= 0 || !argv[0]) {
    fprintf(stderr, "invalid program name\n");
    return 1;
  }
  program_name = os_GetLastname(argv[0]);
  get_program_dir(argv[0]);

  while (i < argc) {
    if (!strcmp(argv[i], "--version")) {
      print_version();
      // never get here
    } else if (!strcmp(argv[i], "--help")) {
      print_help();
      // never get here
    } else if (!strcmp(argv[i], "-d")) {
      daemon_mode = 1;
      batch_mode = 0;
      argv_restart[j++] = "-d";
      ++i;
    } else if (!strcmp(argv[i], "-b")) {
      daemon_mode = 0;
      batch_mode = 1;
      argv_restart[j++] = argv[i];
      ++i;
    } else if (!strcmp(argv[i], "-s")) {
      batch_mode = 0;
      argv_restart[j++] = "-s";
      ++i;
    } else if (!strcmp(argv[i], "-x")) {
      if (i + 1 >= argc) {
        die("argument expected for '-x' option");
      }
      ejudge_xml_path = argv[++i];
      argv_restart[j++] = "-x";
      argv_restart[j++] = argv[i];
      ++i;
    } else if (!strcmp(argv[i], "--")) {
      ++i;
      break;
    } else if (argv[i][0] != '-') {
      break;
    } else {
      die("invalid option: %s", argv[i]);
    }
  }
  argv_restart[j] = 0;
  start_set_args(argv_restart);

  if (batch_mode) {
    if (i + 1 >= argc) {
      die("filename expected");
    }
    if (i + 2 < argc) {
      die("too many arguments");
    }

    i = handle_packet_file(stderr, argv[i], argv[i + 1]);
    return i < 0;
  }

  // check various configuration stuff
  if (i < argc) {
    die("too many arguments");
  }

  if ((pid = start_find_process("ej-t3-mediator", 0)) > 0) {
    fprintf(stderr, "%s: is already running as pid %d\n", argv[0], pid);
    return 1;
  }

#if defined EJUDGE_XML_PATH
  if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif
  if (!ejudge_xml_path) {
    die("path to ejudge.xml configuration file is not specified");
  }
  ejudge_config = ejudge_cfg_parse(ejudge_xml_path);
  if (!ejudge_config) {
    die("configuration file '%s' is invalid", ejudge_xml_path);
  }

  if (ejudge_config->contests_home_dir && ejudge_config->contests_home_dir[0]) {
    snprintf(pathbuf, sizeof(pathbuf), "%s/t3_mediator", ejudge_config->contests_home_dir);
    t3_mediator_dir = xstrdup(pathbuf);
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!t3_mediator_dir) {
    snprintf(pathbuf, sizeof(pathbuf), "%s/t3_mediator", EJUDGE_CONTESTS_HOME_DIR);
    t3_mediator_dir = xstrdup(pathbuf);
  }
#endif /* EJUDGE_CONTESTS_HOME_DIR */
  if (!t3_mediator_dir) {
    die("cannot determine work directory");
  }

  asprintf(&t3_var_dir, "%s/var", t3_mediator_dir);
  asprintf(&spool_in_dir, "%s/incoming", t3_var_dir);
  asprintf(&spool_out_dir, "%s/outcoming", t3_var_dir);
  asprintf(&t3_conf_dir, "%s/conf", t3_mediator_dir);

  if (parse_config(stderr) < 0) {
    die("failed to parse configuration file");
  }

  make_dir(t3_mediator_dir, 0755);
  make_dir(t3_var_dir, 0755);
  make_all_dir(spool_in_dir, 0777);
  make_all_dir(spool_out_dir, 0777);

#if !defined __WIN32__
  if (daemon_mode) {
    //...
  }
#endif /* __WIN32__ */

  if (server_loop() < 0) {
    return 1;
  }
  if (interrupt_restart_requested()) start_restart();

  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 * End:
 */
