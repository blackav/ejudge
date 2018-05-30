/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2010-2014 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_limits.h"
#include "ejudge/t3m_packet_class.h"
#include "ejudge/serve_state.h"
#include "ejudge/t3_packets.h"
#include "ejudge/misctext.h"
#include "ejudge/prepare.h"

#include "ejudge/xalloc.h"

#if CONF_HAS_LIBZIP - 0 == 1
#include <zip.h>
#endif
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

#define ROOT_XML_FILE_NAME "examcheck.xml"
#define OUTPUT_XML_FILE_NAME "examresults.xml"
#define MAX_ROOT_XML_SIZE  (128*1024*1024)

#if CONF_HAS_LIBZIP - 0 == 1
static struct t3m_packet_class *
zip_packet_class_destroy(struct t3m_packet_class *data);
static int
zip_packet_class_parse(
        struct t3m_packet_class *data,
        FILE *log,
        const unsigned char *path);
static int
zip_packet_class_generate(
        struct t3m_packet_class *data,
        FILE *log,
        const unsigned char *out_path);
static void
zip_packet_make_error_packet(
        struct t3m_packet_class *data,
        FILE *log,
        const unsigned char *out_path,
        const unsigned char *log_t);
static const unsigned char *
zip_packet_get_exam_guid(
        struct t3m_packet_class *data);
static int
zip_packet_bind(
        struct t3m_packet_class *data,
        FILE *log,
        struct serve_state *state,
        int base_run_id,
        int (*get_compiler_count)(void *data),
        const unsigned char *(*get_ext_name)(void *data, int index),
        const unsigned char *(*get_short_name)(void *data, int index),
        void *config_data);
static int
zip_packet_get_submit_count(
        struct t3m_packet_class *data);
static int zip_packet_get_submit(
        struct t3m_packet_class *data,
        FILE *log,
        int index,
        struct t3m_generic_submit *p_submit);
static int zip_packet_get_file(
        struct t3m_packet_class *data,
        FILE *log,
        int index,
        unsigned char *text,
        int size);
static int
zip_packet_set_submit(
        struct t3m_packet_class *data,
        FILE *log,
        int index,
        int status,
        int score,
        const unsigned char *text);

struct t3m_packet_operations zip_packet_operations =
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
  .set_submit = zip_packet_set_submit,
};

struct zip_packet_class
{
  struct t3m_packet_class b;

  struct zip *in_zip;
  struct t3_in_packet *in_packet;
  struct t3_out_packet *out_packet;
};

#define logerr(txt,...) flogerr(log, __FUNCTION__, txt,## __VA_ARGS__)

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

static int
zip_packet_class_parse(
        struct t3m_packet_class *data,
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
           ROOT_XML_FILE_NAME, (long) zs.size, path);
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

  for (i = 0; i < zp->in_packet->submit_count; ++i) {
    struct t3_in_submit *submit = &zp->in_packet->submits[i];
    if (submit->skip_flag) continue;
    file_ind = zip_name_locate(zp->in_zip, submit->filename, 0);
    if (file_ind < 0) {
      logerr("entry '%s' is not found", submit->filename);
      //goto cleanup;
      submit->skip_flag = 1;
      continue;
    }
    submit->zip_ind = file_ind;
    zip_stat_init(&zs);
    if (zip_stat_index(zp->in_zip, file_ind, 0, &zs) < 0) {
      logerr("entry '%s' is not found", submit->filename);
      //goto cleanup;
      submit->skip_flag = 1;
      continue;
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
        struct t3m_packet_class *data,
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
        struct t3m_packet_class *data,
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
zip_packet_get_exam_guid(struct t3m_packet_class *data)
{
  struct zip_packet_class *zp = (struct zip_packet_class*) data;

  if (!zp || !zp->in_packet) return 0;
  return zp->in_packet->exam_guid;
}

static int
zip_packet_bind(
        struct t3m_packet_class *data,
        FILE *log,
        serve_state_t state,
        int base_run_id,
        int (*get_compiler_count)(void *date),
        const unsigned char *(*get_ext_name)(void *data, int index),
        const unsigned char *(*get_short_name)(void *data, int index),
        void *config_data)
{
  struct zip_packet_class *zp = (struct zip_packet_class*) data;
  int retval = -1;
  int errcnt = 0;
  int i, j;
  const unsigned char *lang_short_name = 0, *ext_name = 0;
  int compiler_count = 0;

  for (i = 0; i < zp->in_packet->submit_count; ++i) {
    struct t3_in_submit *sb = &zp->in_packet->submits[i];
    sb->cnts_run_id = base_run_id++;
  }

  // find appropriate languages
  for (i = 0; i < zp->in_packet->submit_count; ++i) {
    struct t3_in_submit *sb = &zp->in_packet->submits[i];
    if (sb->skip_flag) continue;

    // look in the local compiler mapping
    compiler_count = get_compiler_count(config_data);
    for (j = 0; j < compiler_count; ++j) {
      ext_name = get_ext_name(config_data, j);
      if (ext_name && !strcmp(sb->prog_lang, ext_name)) {
        lang_short_name = get_short_name(config_data, j);
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
    if (sb->skip_flag) continue;

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
zip_packet_get_submit_count(struct t3m_packet_class *data)
{
  struct zip_packet_class *zp = (struct zip_packet_class*) data;

  if (!zp || !zp->in_packet) return 0;
  return zp->in_packet->submit_count;
}

static int
zip_packet_get_submit(
        struct t3m_packet_class *data,
        FILE *log,
        int index,
        struct t3m_generic_submit *p_submit)
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
  p_submit->skip_flag = t3sb->skip_flag;
  p_submit->run_id = t3sb->cnts_run_id;
  p_submit->lang_id = t3sb->cnts_lang_id;
  p_submit->prob_id = t3sb->cnts_prob_id;
  p_submit->gzipped = t3sb->gzipped;
  p_submit->file_size = t3sb->file_size;

  return 0;
}

static int
zip_packet_get_file(
        struct t3m_packet_class *data,
        FILE *log,
        int index,
        unsigned char *text,
        int size)
{
  struct zip_packet_class *zp = (struct zip_packet_class*) data;
  struct zip_file *zf = 0;
  int rr, rz;
  unsigned char *ptr;

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

  struct t3_in_submit *t3sb;
  t3sb = &zp->in_packet->submits[index];
  if (!t3sb->filename || t3sb->file_size < 0 || t3sb->zip_ind < 0) {
    logerr("invalid parameters");
    return -1;
  }

  /*
  fprintf(stderr, ">>%s, %ld, %d\n", t3sb->filename,
          t3sb->file_size, t3sb->zip_ind);
  */

  if (!t3sb->file_size) return 0;

  zf = zip_fopen_index(zp->in_zip, t3sb->zip_ind, 0);
  if (!zf) {
    logerr("cannot open '%s' for reading at index %d: %s",
           t3sb->filename, t3sb->zip_ind, zip_strerror(zp->in_zip));
    return -1;
  }

  ptr = text;
  rz = size;
  while (rz > 0) {
    rr = zip_fread(zf, ptr, rz);
    if (rr < 0) {
      logerr("read of '%s' failed: %s", t3sb->filename,
             zip_file_strerror(zf));
      zip_fclose(zf);
      return -1;
    }
    if (!rr) {
      logerr("read of '%s' returned 0", t3sb->filename);
      break;
    }
    rz -= rr;
    ptr += rr;
  }
  zip_fclose(zf);

  return 0;
}

static struct t3m_packet_class *
zip_packet_class_destroy(struct t3m_packet_class *data)
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

static int
zip_packet_set_submit(
        struct t3m_packet_class *data,
        FILE *log,
        int index,
        int status,
        int score,
        const unsigned char *text)
{
  struct zip_packet_class *zp = (struct zip_packet_class*) data;
  struct t3_out_submit *t3sb;

  if (!zp || !log) {
    logerr("invalid parameters");
    return -1;
  }
  if (!zp->out_packet) {
    logerr("no output packet");
    return -1;
  }
  if (index < 0 || index >= zp->out_packet->submit_count) {
    logerr("index is out of range");
    return -1;
  }

  t3sb = &zp->out_packet->submits[index];
  t3sb->status = status;
  t3sb->score = score;
  t3sb->data = xstrdup(text);

  return 0;
}

#endif /* CONF_HAS_LIBZIP */

struct t3m_packet_class *
zip_packet_class_create(void)
{
#if CONF_HAS_LIBZIP - 0 == 1
  struct zip_packet_class *res = 0;

  XCALLOC(res, 1);
  res->b.ops = &zip_packet_operations;

  return (struct t3m_packet_class*) res;
#else
  return 0;
#endif /* CONF_HAS_LIBZIP */
}
