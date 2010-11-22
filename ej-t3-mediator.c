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
#include "contests.h"
#include "serve_state.h"
#include "prepare.h"
#include "list_ops.h"

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
#include <zlib.h>

#ifndef EJ_PATH_MAX
#define EJ_PATH_MAX 4096
#endif

typedef int (*dir_listener_handler_t)(
        void *data,
        const unsigned char *spool_dir,
        const unsigned char *in_path,
        const unsigned char *pkt_name);
typedef void (*dir_listener_checker_t)(
        void *data,
        const unsigned char *spool_dir);

#define logerr(txt,...) flogerr(log, __FUNCTION__, txt,## __VA_ARGS__)

#define ROOT_XML_FILE_NAME "examcheck.xml"
#define OUTPUT_XML_FILE_NAME "examresults.xml"
#define MAX_ROOT_XML_SIZE  (128*1024*1024)
#define MAX_CONTEST_COUNT 1000000
#define MAX_COMPILER_COUNT 1000000

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

  /** pseudo contest_id for */
  int contest_id;
};

struct config_contest_data
{
  struct generic_section_config g;

  int id;
  unsigned char *guid;
};

struct config_compiler_data
{
  struct generic_section_config g;

  unsigned char *ext_name;
  unsigned char *short_name;
};

#define XFSIZE(t, x) (sizeof(((t*) 0)->x))

#define GLOBAL_OFFSET(x)   XOFFSET(struct config_global_data, x)
#define GLOBAL_SIZE(x)     XFSIZE(struct config_global_data, x)
#define GLOBAL_PARAM(x, t) { #x, t, GLOBAL_OFFSET(x), GLOBAL_SIZE(x) }
static const struct config_parse_info config_global_params[] =
{
  GLOBAL_PARAM(contest_id, "d"),

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

#define COMPILER_OFFSET(x)   XOFFSET(struct config_compiler_data, x)
#define COMPILER_SIZE(x)     XFSIZE(struct config_compiler_data, x)
#define COMPILER_PARAM(x, t) { #x, t, COMPILER_OFFSET(x), COMPILER_SIZE(x) }
static const struct config_parse_info config_compiler_params[] =
{
  COMPILER_PARAM(ext_name, "S"),
  COMPILER_PARAM(short_name, "S"),

  { 0, 0, 0, 0 }
};


static const struct config_section_info params[] =
{
  { "global", sizeof(struct config_global_data), config_global_params, 0,0,0},
  { "contest",sizeof(struct config_contest_data),config_contest_params,0,0,0},
  { "compiler",sizeof(struct config_compiler_data),config_compiler_params,0,0,0},
  { NULL, 0, NULL }
};

static struct generic_section_config *config;
static struct config_global_data *global = 0;
static int contest_count = 0;
static struct config_contest_data **contests = 0;
static int compiler_count = 0;
static struct config_compiler_data **compilers = 0;

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

struct generic_submit
{
  int run_id;
  int lang_id;
  int prob_id;
  int gzipped;
  long file_size;
};

struct packet_class;
struct packet_operations
{
  struct packet_class * (*destroy)(
        struct packet_class *data);
  int (*parse)(
        struct packet_class *data,
        FILE *log,
        const unsigned char *path);
  int (*generate)(
        struct packet_class *data,
        FILE *log,
        const unsigned char *out_path);
  void (*make_error_packet)(
        struct packet_class *data,
        FILE *log,
        const unsigned char *out_path,
        const unsigned char *log_t);
  const unsigned char *(*get_exam_guid)(
        struct packet_class *data);
  int (*bind)(
        struct packet_class *data,
        FILE *log,
        serve_state_t state,
        int base_run_id);
  int (*get_submit_count)(
        struct packet_class *data);
  int (*get_submit)(
        struct packet_class *data,
        FILE *log,
        int index,
        struct generic_submit *p_submit);
  int (*get_file)(
        struct packet_class *data,
        FILE *log,
        int index,
        unsigned char *text,
        int size);
};

struct packet_class
{
  struct packet_operations *ops;
};

#if CONF_HAS_LIBZIP - 0 == 1
static struct packet_class *
zip_packet_class_destroy(struct packet_class *data);
static int
zip_packet_class_parse(
        struct packet_class *data,
        FILE *log,
        const unsigned char *path);
static int
zip_packet_class_generate(
        struct packet_class *data,
        FILE *log,
        const unsigned char *out_path);
static void
zip_packet_make_error_packet(
        struct packet_class *data,
        FILE *log,
        const unsigned char *out_path,
        const unsigned char *log_t);
static const unsigned char *
zip_packet_get_exam_guid(
        struct packet_class *data);
static int
zip_packet_bind(
        struct packet_class *data,
        FILE *log,
        serve_state_t state,
        int base_run_id);
static int
zip_packet_get_submit_count(
        struct packet_class *data);
static int zip_packet_get_submit(
        struct packet_class *data,
        FILE *log,
        int index,
        struct generic_submit *p_submit);
static int zip_packet_get_file(
        struct packet_class *data,
        FILE *log,
        int index,
        unsigned char *text,
        int size);

struct packet_operations zip_packet_operations =
{
  .destroy = zip_packet_class_destroy,
  .parse = zip_packet_class_parse,
  .generate = zip_packet_class_generate,
  .make_error_packet = zip_packet_make_error_packet,
  .get_exam_guid = zip_packet_get_exam_guid,
  .bind = zip_packet_bind,
  .get_submit_count = zip_packet_get_submit_count,
  .get_submit = zip_packet_get_submit,
  .get_file = zip_packet_get_file,
};

struct zip_packet_class
{
  struct packet_class b;

  struct zip *in_zip;
  struct t3_in_packet *in_packet;
  struct t3_out_packet *out_packet;
};

static int
zip_packet_class_parse(
        struct packet_class *data,
        FILE *log,
        const unsigned char *path)
{
  struct zip_packet_class *zp = (struct zip_packet_class*) data;
  int zip_err = 0;
  struct zip *oz = 0;
  char errbuf[1024];
  int retval = -1;
  int root_xml_ind;
  struct zip_stat zs;
  unsigned char *root_xml_buf = 0;
  struct zip_file *zf = 0;
  int i, file_ind;

  if (!(zp->in_zip = zip_open(path, ZIP_CHECKCONS, &zip_err))) {
    zip_error_to_str(errbuf, sizeof(errbuf), zip_err, errno);
    logerr("failed to open ZIP '%s': %s", path, errbuf);
    goto cleanup;
  }

  root_xml_ind = zip_name_locate(zp->in_zip, ROOT_XML_FILE_NAME, 0);
  if (root_xml_ind < 0) {
    logerr("failed to locate '%s' in '%s'", ROOT_XML_FILE_NAME, path);
    goto cleanup;
  }

  zip_stat_init(&zs);
  if (zip_stat_index(zp->in_zip, root_xml_ind, 0, &zs) < 0) {
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

  if (!(zf = zip_fopen_index(zp->in_zip, root_xml_ind, 0))) {
    logerr("failed to open entry '%s' in '%s': %s", ROOT_XML_FILE_NAME,
           path, zip_strerror(zp->in_zip));
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

  zp->in_packet = t3_in_packet_parse_str(log, root_xml_buf);
  if (!zp->in_packet) {
    logerr("failed to parse entry '%s' in '%s'", ROOT_XML_FILE_NAME, path);
    goto cleanup;
  }

  printf("Count: %d\n", zp->in_packet->submit_count);
  for (i = 0; i < zp->in_packet->submit_count; ++i) {
    struct t3_in_submit *submit = &zp->in_packet->submits[i];
    file_ind = zip_name_locate(zp->in_zip, submit->filename, 0);
    if (file_ind < 0) {
      logerr("entry '%s' is not found", submit->filename);
      goto cleanup;
    }
    submit->zip_ind = file_ind;
    zip_stat_init(&zs);
    if (zip_stat_index(zp->in_zip, file_ind, 0, &zs) < 0) {
      logerr("entry '%s' is not found", submit->filename);
      goto cleanup;
    }
    submit->file_size = zs.size;
    
    //printf("[%d]: %s, %s, %s, %s, %s, %ld\n", i, submit->filename,
    //       submit->prob_guid, submit->user_guid, submit->prog_lang,
    //       submit->prog_charset, zs.size);
  }

  zp->out_packet = t3_out_packet_make_from_in(zp->in_packet);
  if (!zp->out_packet) {
    logerr("failed to copy data");
    goto cleanup;
  }

  retval = 0;

 cleanup:
  if (oz) {
    zip_close(oz); oz = 0;
  }
  if (zf) {
    zip_fclose(zf); zf = 0;
  }
  xfree(root_xml_buf);

  return retval;
}

static int
zip_packet_class_generate(
        struct packet_class *data,
        FILE *log,
        const unsigned char *out_path)
{
  struct zip_packet_class *zp = (struct zip_packet_class*) data;
  int retval = -1;
  FILE *res_f = 0;
  char *res_t = 0;
  size_t res_z = 0;
  int zip_err = 0;
  char errbuf[1024];
  struct zip *oz = 0;
  struct zip_source *zr = 0;

  res_f = open_memstream(&res_t, &res_z);
  if (!res_f) { // this normally never happens
    logerr("open_memstream failed");
    goto cleanup;
  }
  t3_out_packet_write(res_f, zp->out_packet);
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

  return retval;
}

static void
zip_packet_make_error_packet(
        struct packet_class *data,
        FILE *log,
        const unsigned char *out_path,
        const unsigned char *log_t)
{
  //struct zip_packet_class *zp = (struct zip_packet_class*) data;
  unsigned char *escaped_str = 0;
  char *pkt_t = 0;
  size_t pkt_z = 0;
  FILE *pkt_f = 0;
  int zip_err = 0;
  unsigned char errbuf[1024];
  struct zip *oz = 0;
  struct zip_source *zr = 0;

  pkt_f = open_memstream(&pkt_t, &pkt_z);
  escaped_str = html_armor_string_dup(log_t);
  fprintf(pkt_f, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n");
  fprintf(pkt_f, "<examresults e=\"\">\n");
  fprintf(pkt_f, "  <error>%s</error>\n", escaped_str);
  fprintf(pkt_f, "</examresults>\n");
  xfree(escaped_str); escaped_str = 0;
  fclose(pkt_f); pkt_f = 0;

  zip_err = 0; errbuf[0] = 0;
  oz = zip_open(out_path, ZIP_CREATE, &zip_err);
  if (!oz) {
    zip_error_to_str(errbuf, sizeof(errbuf), zip_err, errno);
    logerr("failed to create '%s' in '%s': %s",
           OUTPUT_XML_FILE_NAME, out_path, errbuf);
    goto cleanup;
  }
  if (!(zr = zip_source_buffer(oz, pkt_t, pkt_z, 0))) {
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

 cleanup:
  if (zr) {
    zip_source_free(zr); zr = 0;
  }
  if (oz) {
    zip_close(oz); oz = 0;
  }
}

static const unsigned char *
zip_packet_get_exam_guid(struct packet_class *data)
{
  struct zip_packet_class *zp = (struct zip_packet_class*) data;

  if (!zp || !zp->in_packet) return 0;
  return zp->in_packet->exam_guid;
}

static int
zip_packet_bind(
        struct packet_class *data,
        FILE *log,
        serve_state_t state,
        int base_run_id)
{
  struct zip_packet_class *zp = (struct zip_packet_class*) data;
  int retval = -1;
  int errcnt = 0;
  int i, j;
  const unsigned char *lang_short_name = 0;

  for (i = 0; i < zp->in_packet->submit_count; ++i) {
    struct t3_in_submit *sb = &zp->in_packet->submits[i];
    sb->cnts_run_id = base_run_id++;
  }

  // find appropriate languages
  for (i = 0; i < zp->in_packet->submit_count; ++i) {
    struct t3_in_submit *sb = &zp->in_packet->submits[i];

    // look in the local compiler mapping
    for (j = 0; j < compiler_count; ++j) {
      if (!strcmp(sb->prog_lang, compilers[j]->ext_name)) {
        lang_short_name = compilers[j]->short_name;
        break;
      }
    }
    if (j >= compiler_count) {
      lang_short_name = sb->prog_lang;
    }

    // look in the contest compilers
    for (j = 1; j <= state->max_lang; ++j) {
      if (state->langs[j] && !strcmp(state->langs[j]->short_name, lang_short_name)) {
        break;
      }
    }
    if (j > state->max_lang) {
      logerr("submit ('%s', '%s') language '%s' is undefined",
             sb->prob_guid, sb->user_guid, sb->prog_lang);
      ++errcnt;
    } else {
      sb->cnts_lang_id = j;
    }
  }

  // find appropriate problems
  for (i = 0; i < zp->in_packet->submit_count; ++i) {
    struct t3_in_submit *sb = &zp->in_packet->submits[i];

    for (j = 1; j <= state->max_prob; ++j) {
      if (state->probs[j] && state->probs[j]->extid
          && !strcmp(state->probs[j]->extid, sb->prob_extid))
        break;
    }
    if (j > state->max_prob) {
      logerr("submit ('%s', '%s') problem '%s' is undefined",
             sb->prob_guid, sb->user_guid, sb->prob_extid);
      ++errcnt;
    } else {
      sb->cnts_prob_id = j;
    }
  }
  if (errcnt > 0) goto cleanup;

  retval = 0;

 cleanup:;
  return retval;
}

static int
zip_packet_get_submit_count(struct packet_class *data)
{
  struct zip_packet_class *zp = (struct zip_packet_class*) data;

  if (!zp || !zp->in_packet) return 0;
  return zp->in_packet->submit_count;
}

static int
zip_packet_get_submit(
        struct packet_class *data,
        FILE *log,
        int index,
        struct generic_submit *p_submit)
{
  struct zip_packet_class *zp = (struct zip_packet_class*) data;
  struct t3_in_submit *t3sb;

  if (!zp || !log || !p_submit) {
    logerr("invalid parameters");
    return -1;
  }
  if (!zp->in_packet) {
    logerr("no input packet");
    return -1;
  }
  if (index < 0 || index >= zp->in_packet->submit_count) {
    logerr("index is out of range");
    return -1;
  }

  t3sb = &zp->in_packet->submits[index];
  memset(p_submit, 0, sizeof(*p_submit));
  p_submit->run_id = t3sb->cnts_run_id;
  p_submit->lang_id = t3sb->cnts_lang_id;
  p_submit->prob_id = t3sb->cnts_prob_id;
  p_submit->gzipped = t3sb->gzipped;
  p_submit->file_size = t3sb->file_size;

  return 0;
}

static int
zip_packet_get_file(
        struct packet_class *data,
        FILE *log,
        int index,
        unsigned char *text,
        int size)
{
  struct zip_packet_class *zp = (struct zip_packet_class*) data;

  if (!zp || !log || !text || size <= 0) {
    logerr("invalid parameters");
    return -1;
  }
  if (!zp->in_packet) {
    logerr("no input packet");
    return -1;
  }
  if (index < 0 || index >= zp->in_packet->submit_count) {
    logerr("index is out of range");
    return -1;
  }

  return 0;
}

static struct packet_class *
zip_packet_class_destroy(struct packet_class *data)
{
  struct zip_packet_class *zp = (struct zip_packet_class*) data;

  if (!data) return 0;

  if (zp->in_zip) {
    zip_close(zp->in_zip);
  }
  t3_in_packet_free(zp->in_packet);
  t3_out_packet_free(zp->out_packet);

  memset(zp, 0, sizeof(*zp));
  xfree(zp);
  return 0;
}
#endif /* CONF_HAS_LIBZIP */

static struct packet_class *
zip_packet_class_create(void)
{
#if CONF_HAS_LIBZIP - 0 == 1
  struct zip_packet_class *res = 0;

  XCALLOC(res, 1);
  res->b.ops = &zip_packet_operations;

  return (struct packet_class*) res;
#else
  return 0;
#endif /* CONF_HAS_LIBZIP */
}

static struct packet_class *
guess_packet_class(
        FILE *log,
        const unsigned char *path)
{
  int mime_type = 0;
  struct stat stb;
  struct packet_class *res = 0;

  if (!path || !strlen(path)) {
    logerr("empty path");
    return 0;
  }
  if (stat(path, &stb) < 0) {
    logerr("file '%s' does not exist", path);
    return 0;
  }
  if (stb.st_size <= 0) {
    logerr("file '%s' is empty", path);
    return 0;
  }
  if (!S_ISREG(stb.st_mode)) {
    logerr("file '%s' is not a regular file", path);
    return 0;
  }
  mime_type = mime_type_guess_file(path, 0);
  if (mime_type < 0) {
    logerr("failed to guess type of file '%s'", path);
    return 0;
  }

  if (mime_type != MIME_TYPE_APPL_ZIP) {
    logerr("unsupported mime type '%s' of '%s'", mime_type_get_type(mime_type),
           path);
    return 0;
  }

#if CONF_HAS_LIBZIP - 0 == 1
  res = zip_packet_class_create();
#endif

  if (!res) {
    logerr("support for mime type '%s' is not compiled in", mime_type_get_type(mime_type));
    return 0;
  }

  return res;
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
        const unsigned char *spool_dir,
        unsigned char *out_path,
        int out_len,
        const unsigned char *pkt_name)
{
  unsigned char dir_path[EJ_PATH_MAX];
  unsigned char in_name[EJ_PATH_MAX];
  int r;
  struct stat stb;

  snprintf(dir_path, sizeof(dir_path), "%s/dir/%s", spool_dir, pkt_name);
  unique_name(in_name, sizeof(in_name), pkt_name);
  snprintf(out_path, out_len, "%s/out/%s", spool_dir, in_name);

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
move_in(
        const unsigned char *spool_dir,
        const unsigned char *pkt_name,
        const unsigned char *path)
{
  unsigned char dir_path[EJ_PATH_MAX];
  int r;

  snprintf(dir_path, sizeof(dir_path), "%s/dir/%s", spool_dir, pkt_name);
  r = rename(path, dir_path);
  if (r < 0) {
    err("rename '%s'->'%s' failed: %s", path, dir_path, os_ErrorMsg());
  }
  return r;
}

static int
ungzip_to_memory(
        FILE *log,
        unsigned char **p_out_buf,
        int *p_out_size,
        const unsigned char *in_buf,
        int in_size)
{
  z_stream zf;
  int r, zf_initialized = 0, retval = -1;
  unsigned char *wb = 0;
  int wz = 0, zz = 0;

  wz = 4096;
  wb = (unsigned char *) xmalloc(wz);

  memset(&zf, 0, sizeof(zf));
  zf.zalloc = Z_NULL;
  zf.zfree = Z_NULL;
  zf.next_in = (unsigned char*) in_buf;
  zf.avail_in = in_size;
  zf.next_out = wb;
  zf.avail_out = wz;

  if (inflateInit(&zf) != Z_OK) {
    logerr("inflateInit failed");
    goto cleanup;
  }
  zf_initialized = 1;

  while (1) {
    r = inflate(&zf, Z_NO_FLUSH);
    if (r == Z_STREAM_END) break;
    if (r != Z_OK) {
      logerr("decompression error");
      goto cleanup;
    }
    zz = wz - zf.avail_out;
    if (zz < 0 || zz > wz) {
      logerr("decompression integrity check error");
      goto cleanup;
    }

    wz *= 2;
    wb = (unsigned char*) xrealloc(wb, wz);
    zf.next_out = wb + zz;
    zf.avail_out = wz - zz;
  }

  // append \0 to the end of file
  if (zf.avail_out < 1) {
    zz = wz - zf.avail_out;
    if (zz < 0 || zz > wz) {
      logerr("decompression integrity check error");
      goto cleanup;
    }

    wz *= 2;
    wb = (unsigned char*) xrealloc(wb, wz);
    zf.next_out = wb + zz;
    zf.avail_out = wz - zz;
  }
  *zf.next_out = 0;

  *p_out_buf = wb;
  *p_out_size = wz - zf.avail_out;

  retval = 0;

 cleanup:;
  if (zf_initialized) {
    inflateEnd(&zf);
  }
  xfree(wb);
  return 0;
}

static int
process_submit(
        struct packet_class *pkt,
        FILE *log,
        serve_state_t state,
        int submit_index)
{
  int retval = -1;
  struct generic_submit sb;
  unsigned char *orig_text = 0, *ungzip_text = 0, *utf8_text = 0;
  int orig_size = 0, ungzip_size = 0, utf8_size = 0;

  const unsigned char *text = 0;
  int size = 0;

  struct section_problem_data *prob = 0;
  struct section_language_data *lang = 0;

  if (pkt->ops->get_submit(pkt, log, submit_index, &sb) < 0) {
    logerr("failed to extract submit %d", submit_index);
    goto cleanup;
  }

  if (sb.prob_id > 0 && sb.prob_id <= state->max_prob) {
    prob = state->probs[sb.prob_id];
  }
  if (!prob) {
    logerr("invalid problem %d in submit %d", sb.prob_id, submit_index);
    goto cleanup;
  }
  if (sb.lang_id > 0 && sb.lang_id <= state->max_lang) {
    lang = state->langs[sb.lang_id];
  }

  if (sb.file_size <= 0) {
    logerr("invalid size of submit %d", submit_index);
    goto cleanup;
  }
  orig_size = sb.file_size;
  orig_text = (unsigned char*) xmalloc(orig_size + 1);
  memset(orig_text, 0, orig_size + 1);
  if (pkt->ops->get_file(pkt, log, submit_index, orig_text, orig_size) < 0) {
    logerr("failed to extract file of submit %d", submit_index);
    goto cleanup;
  }
  text = orig_text; size = orig_size;
  if (sb.gzipped) {
    if (ungzip_to_memory(log, &ungzip_text, &ungzip_size,
                         orig_text, orig_size) < 0) {
      logerr("failed to ungzip file of submit %d", submit_index);
      goto cleanup;
    }
    text = ungzip_text; size = ungzip_size;
    xfree(orig_text); orig_text = 0; orig_size = 0;
  }
  /* FIXME: handle only text submits for now */
  if (strlen(text) != size) {
    if ((utf8_size = ucs2_to_utf8(&utf8_text, text, size)) < 0) {
      logerr("UTF16 to UTF8 conversion failed in submit %d", submit_index);
      goto cleanup;
    }
    xfree(ungzip_text); ungzip_text = 0; ungzip_size = 0;
    xfree(orig_text); orig_text = 0; orig_size = 0;
    text = utf8_text;
    size = utf8_size;
  }

  /*
int
serve_compile_request(
        serve_state_t state,
        unsigned char const *str,
        int len,
        int contest_id,
        int run_id,
        int user_id,
        int lang_id,
        int locale_id,
        int output_only,
        unsigned char const *sfx,
        char **compiler_env,
        int style_check_only,
        const unsigned char *style_checker_cmd,
        char **style_checker_env,
        int accepting_mode,
        int priority_adjustment,
        int notify_flag,
        const struct section_problem_data *prob,
        const struct section_language_data *lang);

      if (serve_compile_request(cs, run_text, run_size, ?,
                                run_id, phr->user_id,
                                lang->compile_id, phr->locale_id, 0,
                                lang->src_sfx,
                                lang->compiler_env,
                                0, prob->style_checker_cmd,
                                prob->style_checker_env,
                                -1, 0, 0, prob, lang) < 0) {

   */

  // compile that stuff

  retval = 0;

 cleanup:;
  xfree(utf8_text);
  xfree(orig_text);
  xfree(ungzip_text);
  return retval;
}

struct t3_spool_packet_info
{
  struct t3_spool_packet_info *prev, *next;

  /* packet name */
  unsigned char *pkt_name;

  /* incoming spooling */
  unsigned char *spool_in_dir;
  unsigned char *in_path;

  /* outcoming spooling */
  unsigned char *spool_out_dir;
  unsigned char *out_path;

  /* logging */
  FILE *log_f;
  char *log_t;
  size_t log_z;

  struct packet_class *pkt;

  /* >=0 for OK, <0 for errors */
  int errcode;
  int completed;

  int submit_count;
  int base_run_id;              /* run_id assigned from base */
};

static int base_run_id = 0;

static int
process_packet(
        struct t3_spool_packet_info *pi,
        struct packet_class *pkt,
        FILE *log)
{
  int retval = -1;
  const unsigned char *exam_guid = 0;
  int contest_id = 0, i;
  const struct contest_desc *cnts = 0;
  serve_state_t serve_state = 0;

  exam_guid = pkt->ops->get_exam_guid(pkt);
  if (!exam_guid || !*exam_guid) {
    logerr("exam GUID is undefined");
    goto cleanup;
  }

  for (i = 0; i < contest_count; ++i) {
    if (!strcmp(contests[i]->guid, exam_guid))
      break;
  }
  if (i >= contest_count) {
    logerr("exam GUID '%s' is not mapped to a contest", exam_guid);
    goto cleanup;
  }
  contest_id = contests[i]->id;

  if (contests_get(contest_id, &cnts) < 0 || !cnts) {
    logerr("failed to load XML description of contest %d", contest_id);
    goto cleanup;
  }
  if (serve_state_load_contest(ejudge_config, contest_id, NULL, NULL, &serve_state, 0, 1) < 0) {
    logerr("failed to load contest %d", contest_id);
    goto cleanup;
  }

  pi->submit_count = pkt->ops->get_submit_count(pkt);
  if (base_run_id + pi->submit_count >= 1000000) {
    // FIXME: add some check
    base_run_id = 0;
  }
  pi->base_run_id = base_run_id;
  base_run_id += pi->submit_count + 1;

  // bind problems and languages
  if (pkt->ops->bind(pkt, log, serve_state, pi->base_run_id) < 0) {
    goto cleanup;
  }

  for (i = 0; i < pi->submit_count; ++i) {
    process_submit(pkt, log, serve_state, i);
  }

  retval = 0;

 cleanup:;
  serve_state = serve_state_destroy(serve_state, cnts, NULL);
  return retval;
}

struct t3_spool_info
{
  struct t3_spool_packet_info *first, *last;
};

static void
t3_spool_finalize_packet(
        struct t3_spool_info *info,
        struct t3_spool_packet_info *pi)
{
  if (pi->errcode >= 0) {
    pi->errcode = pi->pkt->ops->generate(pi->pkt, pi->log_f, pi->out_path);
  }
  fclose(pi->log_f); pi->log_f = 0;

  if (pi->errcode < 0) {
    pi->pkt->ops->make_error_packet(pi->pkt, stderr, pi->out_path, pi->log_t);
  }
  fprintf(stderr, "%s", pi->log_t);
  xfree(pi->log_t); pi->log_t = 0; pi->log_z = 0;

  move_in(pi->spool_out_dir, pi->pkt_name, pi->out_path);

  pi->pkt = pi->pkt->ops->destroy(pi->pkt);
  xfree(pi->pkt_name);
  xfree(pi->spool_in_dir);
  xfree(pi->in_path);
  xfree(pi->spool_out_dir);
  xfree(pi->out_path);

  UNLINK_FROM_LIST(pi, info->first, info->last, prev, next);
  memset(pi, 0, sizeof(*pi));
  xfree(pi);
}

static int
t3_spool_handler(
        void *data,
        const unsigned char *spool_dir,
        const unsigned char *in_path,
        const unsigned char *pkt_name)
{
  struct t3_spool_info *info = (struct t3_spool_info*) data;
  unsigned char out_name[EJ_PATH_MAX];
  unsigned char out_path[EJ_PATH_MAX];
  struct packet_class *pkt = 0;
  int r;
  struct t3_spool_packet_info *cur_info, *new_info = 0;

  /* check, that such packet is being handled */
  for (cur_info = info->first; cur_info; cur_info = cur_info->next) {
    if (!strcmp(cur_info->pkt_name, pkt_name)) {
      err("packet '%s' is already being handled", pkt_name);
      return 0;
    }
  }

  pkt = guess_packet_class(stderr, in_path);
  if (!pkt) return 0;

  XCALLOC(new_info, 1);
  LINK_FIRST(new_info, info->first, info->last, prev, next);

  unique_name(out_name, sizeof(out_name), pkt_name);
  snprintf(out_path, sizeof(out_path), "%s/in/%s", spool_out_dir, out_name);

  new_info->pkt_name = xstrdup(pkt_name);
  new_info->spool_in_dir = xstrdup(spool_dir);
  new_info->in_path = xstrdup(in_path);
  new_info->spool_out_dir = xstrdup(spool_out_dir);
  new_info->out_path = xstrdup(out_path);
  new_info->pkt = pkt;

  new_info->log_f = open_memstream(&new_info->log_t, &new_info->log_z);
  r = new_info->pkt->ops->parse(new_info->pkt, new_info->log_f,
                                new_info->in_path);
  if (r >= 0) r = process_packet(new_info, new_info->pkt, new_info->log_f);

  new_info->errcode = r;
  if (r < 0) {
    new_info->completed = 1;
  }

  return 0;
}

static void
t3_spool_checker(
        void *data,
        const unsigned char *spool_dir)
{
  struct t3_spool_info *info = (struct t3_spool_info*) data;
  struct t3_spool_packet_info *p = 0, *q = 0;

  if (!info) return;

  for (p = info->first; p; p = q) {
    q = p->next;
    if (p->completed) {
      t3_spool_finalize_packet(info, p);
    }
  }
}

struct submit_info
{
  int status;
};

struct submit_block_info
{
  struct submit_block_info *prev, *next;
  int contest_id;
  int first_run_id;
  int submit_count;

  // additional submit information
};

static struct submit_block_info *sb_first, *sb_last;

void
submit_block_add(int contest_id, int first_run_id, int submit_count)
{
  struct submit_block_info *p;

  ASSERT(contest_id > 0);
  ASSERT(first_run_id >= 0);
  ASSERT(submit_count > 0);

  // check for overlaying packet
  for (p = sb_first; p; p = p->next) {
    if (p->contest_id == contest_id
        && ((p->first_run_id < first_run_id + submit_count
             && p->first_run_id >= first_run_id)
            || (first_run_id < p->first_run_id + p->submit_count
                && first_run_id >= p->first_run_id))) {
      fprintf(stderr, "overlaying packets: contest_id=%d: (%d, %d), (%d, %d)",
              p->contest_id, p->first_run_id, p->submit_count,
              first_run_id, submit_count);
      abort();
    }
  }

  XCALLOC(p, 1);
  p->contest_id = contest_id;
  p->first_run_id = first_run_id;
  p->submit_count = submit_count;
  LINK_LAST(p, sb_first, sb_last, prev, next);
}

void
submit_block_remove(int contest_id, int first_run_id, int submit_count)
{
  struct submit_block_info *p;

  for (p = sb_first; p; p = p->next) {
    if (p->contest_id == contest_id && p->first_run_id == first_run_id
        && p->submit_count == submit_count) {
      break;
    }
  }
  if (!p) return;

  UNLINK_FROM_LIST(p, sb_first, sb_last, prev, next);
  // FIXME: free 'p' item
}

struct submit_block_info *
submit_block_find(int contest_id, int run_id)
{
  struct submit_block_info *p;

  for (p = sb_first; p; p = p->next) {
    if (p->contest_id == contest_id && p->first_run_id <= run_id
        && p->first_run_id + p->submit_count > run_id) {
      return p;
    }
  }

  return 0;
}

struct compile_spool_out_dirs
{
  struct compile_spool_dirs *prev, *next;
  unsigned char *compile_reply_dir;
  int nrefs;
};

struct compile_spool_info
{
  struct compile_spool_out_dirs *first_dir, *last_dir;
};

int
compile_dir_handler(
        void *data,
        const unsigned char *spool_dir,
        const unsigned char *in_path,
        const unsigned char *pkt_name)
{
  return 0;
}

struct dir_listener_info
{
  struct dir_listener_info *prev, *next;
  unsigned char *spool_dir;
  dir_listener_handler_t handler;
  dir_listener_checker_t checker;
  void *data;
};

static struct dir_listener_info *dir_listener_first, *dir_listener_last;

int
dir_listener_add(
        const unsigned char *spool_dir, 
        dir_listener_handler_t handler,
        dir_listener_checker_t checker,
        void *data)
{
  struct dir_listener_info *p = 0, *q;

  ASSERT(spool_dir);
  ASSERT(handler);

  for (p = dir_listener_first; p; p = p->next) {
    if (!strcmp(p->spool_dir, spool_dir))
      return -1;
  }

  XCALLOC(q, 1);
  q->spool_dir = xstrdup(spool_dir);
  q->handler = handler;
  q->checker = checker;
  q->data = data;
  LINK_LAST(q, dir_listener_first, dir_listener_last, prev, next);
  return 0;
}

int
dir_listener_remove(
        const unsigned char *spool_dir)
{
  struct dir_listener_info *p = 0;

  ASSERT(spool_dir);

  for (p = dir_listener_first; p; p = p->next) {
    if (!strcmp(p->spool_dir, spool_dir)) {
      UNLINK_FROM_LIST(p, dir_listener_first, dir_listener_last, prev, next);
      xfree(p->spool_dir);
      memset(p, 0, sizeof(*p));
      xfree(p);
      return 0;
    }
  }

  return -1;
}

int
dir_listener_find(
        const unsigned char *spool_dir,
        dir_listener_handler_t *p_handler,
        dir_listener_checker_t *p_checker,
        void **p_data)
{
  struct dir_listener_info *p;

  ASSERT(spool_dir);

  for (p = dir_listener_first; p; p = p->next) {
    if (!strcmp(p->spool_dir, spool_dir)) {
      if (p_handler) *p_handler = p->handler;
      if (p_checker) *p_checker = p->checker;
      if (p_data) *p_data = p->data;
      return 0;
    }
  }

  return -1;
}

static int
server_loop(void)
{
  int r;
  unsigned char pkt_name[EJ_PATH_MAX];
  unsigned char in_path[EJ_PATH_MAX];
  struct dir_listener_info *dlp;

  info("ej-t3-mediator server started");
  interrupt_init();
  interrupt_disable();
  in_path[0] = 0;

  while (1) {
    for (dlp = dir_listener_first; dlp; dlp = dlp->next) {
      if (dlp->checker) {
        dlp->checker(dlp->data, dlp->spool_dir);
      }
    }

    if (interrupt_get_status() || interrupt_restart_requested()) break;

    if (!dir_listener_first) {
      info("no directories to scan");
      break;
    }

    for (dlp = dir_listener_first; dlp; dlp = dlp->next) {
      r = scan_dir(dlp->spool_dir, pkt_name, sizeof(pkt_name));
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

      if (r > 0) break;
    }

    if (!dlp) {
      interrupt_enable();
      os_Sleep(1000);
      interrupt_disable();
      continue;
    }

    /* handle the inbound packet */
    r = move_out(dlp->spool_dir, in_path, sizeof(in_path), pkt_name);
    if (!r) {
      // proceed to the next entry without waiting
      continue;
    }
    if (r < 0) {
      // unrecoverable error
      break;
    }

    info("received packet '%s' at '%s'", pkt_name, dlp->spool_dir);

    r = dlp->handler(dlp->data, dlp->spool_dir, in_path, pkt_name);

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

  for (p = config; p; p = p->next) {
    if (!strcmp(p->name, "compiler")) {
      ++compiler_count;
    }
  }
  if (compiler_count < 0 || compiler_count > MAX_COMPILER_COUNT) {
    logerr("too many (%d) compilers defined in configuration file",
           compiler_count);
    goto cleanup;
  }
  if (compiler_count > 0) {
    XCALLOC(compilers, compiler_count);
    for (p = config, i = 0; p; p = p->next) {
      if (!strcmp(p->name, "compiler")) {
        struct config_compiler_data *comp = (struct config_compiler_data*) p;
        if (!comp->ext_name) {
          logerr("compiler ext_name is undefined");
          goto cleanup;
        }
        if (!comp->short_name) {
          logerr("compiler short_name is undefined");
          goto cleanup;
        }
        compilers[i++] = comp;
      }
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
  struct t3_spool_info *info = 0;

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

    /*
    i = handle_packet_file(stderr, argv[i], argv[i + 1]);
    */
    i = -1;
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

  XCALLOC(info, 1);
  dir_listener_add(spool_in_dir, t3_spool_handler, t3_spool_checker, info);

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
