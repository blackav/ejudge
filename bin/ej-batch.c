/* -*- c -*- */

/* Copyright (C) 2010-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/version.h"
#include "ejudge/mime_type.h"
#include "ejudge/t3_packets.h"
#include "ejudge/interrupt.h"
#include "ejudge/startstop.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/pathutl.h"
#include "ejudge/fileutl.h"
#include "ejudge/errlog.h"
#include "ejudge/misctext.h"
#include "ejudge/parsecfg.h"
#include "ejudge/contests.h"
#include "ejudge/serve_state.h"
#include "ejudge/prepare.h"
#include "ejudge/list_ops.h"
#include "ejudge/compile_packet.h"
#include "ejudge/t3m_dir_listener.h"
#include "ejudge/t3m_packet_class.h"
#include "ejudge/t3m_submits.h"
#include "ejudge/runlog.h"
#include "ejudge/run_packet.h"
#include "ejudge/testing_report_xml.h"
#include "ejudge/zip_utils.h"
#include "ejudge/xml_utils.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

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

#define logerr(txt,...) flogerr(log, __FUNCTION__, txt,## __VA_ARGS__)

#define MAX_CONTEST_ID    999999
#define MAX_CONTEST_COUNT 1000000
#define MAX_COMPILER_COUNT 1000000

int
compile_spool_add_reply_dir(const unsigned char *reply_dir);
int
run_spool_add_reply_dir(const unsigned char *reply_dir);

/* FIXME: remove it */
static struct dir_listener_state *global_dl_state = 0;
static struct submit_block_state *global_sb_state = 0;

static const unsigned char *program_name;
static unsigned char *program_dir;

//extern struct ejudge_cfg *ejudge_config;
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

static int
get_compiler_count(void *data)
{
  return compiler_count;
}

static const unsigned char *
get_ext_name(void *data, int index)
{
  if (!compilers || index < 0 || index >= compiler_count) return NULL;
  if (!compilers[index]) return NULL;
  return compilers[index]->ext_name;
}

static const unsigned char *
get_short_name(void *data, int index)
{
  if (!compilers || index < 0 || index >= compiler_count) return NULL;
  if (!compilers[index]) return NULL;
  return compilers[index]->short_name;
}

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

struct contest_extra
{
  int nrefs;
  int contest_id;
  time_t load_time;
  const struct contest_desc *cnts;
  serve_state_t state;
};

static int contest_extra_size = 0;
static struct contest_extra *contest_extras = 0;

struct contest_extra *
load_contest_extra(int contest_id)
{
  struct contest_extra *extra = 0;
  const struct contest_desc *cnts = 0;

  if (contest_id <= 0 || contest_id > MAX_CONTEST_ID) return NULL;

  if (contest_id >= contest_extra_size) {
    int new_size = contest_extra_size * 2;
    struct contest_extra *new_extra = 0;
    if (!new_size) new_size = 32;
    while (contest_id >= new_size) {
      new_size *= 2;
    }
    XCALLOC(new_extra, new_size);
    if (contest_extra_size > 0) {
      memcpy(new_extra, contest_extras, sizeof(new_extra[0]) * contest_extra_size);
      xfree(contest_extras);
    }
    contest_extra_size = new_size;
    contest_extras = new_extra;
  }
  if (contest_extras[contest_id].contest_id == contest_id) {
    return &contest_extras[contest_id];
  }

  if (contests_get(contest_id, &cnts) < 0 || !cnts) {
    fprintf(stderr, "get_contest_extra: failed to load XML description of contest %d\n",
            contest_id);
    return NULL;
  }

  extra = &contest_extras[contest_id];
  if (serve_state_load_contest(extra, ejudge_config, contest_id, NULL, NULL, 0, 1, NULL) < 0) {
    fprintf(stderr, "get_contest_extra: failed to load contest %d\n", contest_id);
    return NULL;
  }

  extra->contest_id = contest_id;
  extra->cnts = cnts;
  extra->load_time = time(0);

  return extra;
}

struct contest_extra *
get_contest_extra(int contest_id)
{
  struct contest_extra *extra = 0;

  if (contest_id <= 0 || contest_id >= contest_extra_size) return NULL;
  extra = &contest_extras[contest_id];
  if (extra->contest_id != contest_id) return NULL;
  return extra;
}

static struct t3m_packet_class *
guess_packet_class(
        FILE *log,
        const unsigned char *path)
{
  int mime_type = 0;
  struct stat stb;
  struct t3m_packet_class *res = 0;

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

  struct t3m_packet_class *pkt;

  /* >=0 for OK, <0 for errors */
  int pending_count;
  int errcode;
  int completed;

  int contest_id;
  int submit_count;
  int base_run_id;              /* run_id assigned from base */

  // some statistics
  int ignored_count;
  int wrong_format_count;
  int processed_count;

  time_t start_time;
  time_t finish_time;
};

static int
process_submit(
        struct t3m_packet_class *pkt,
        FILE *log,
        serve_state_t state,
        int submit_index,
        struct t3_spool_packet_info *pi)
{
  int retval = -1, r;
  struct t3m_generic_submit sb;
  unsigned char *orig_text = 0, *ungzip_text = 0, *utf8_text = 0;
  int orig_size = 0, ungzip_size = 0, utf8_size = 0;

  const unsigned char *text = 0;
  int size = 0;

  struct section_problem_data *prob = 0;
  struct section_language_data *lang = 0;
  unsigned char result_queue_dir[EJ_PATH_MAX];

  if (pkt->ops->get_submit(pkt, log, submit_index, &sb) < 0) {
    logerr("failed to extract submit %d", submit_index);
    goto cleanup;
  }
  if (sb.skip_flag) {
    ++pi->ignored_count;
    return 0;
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
  if (!lang) {
    logerr("invalid language %d in submit %d", sb.lang_id, submit_index);
    goto cleanup;
  }

  if (sb.file_size <= 0) {
    logerr("invalid size of submit %d", submit_index);
    ++pi->wrong_format_count;
    goto cleanup;
  }
  orig_size = sb.file_size;
  orig_text = (unsigned char*) xmalloc(orig_size + 1);
  memset(orig_text, 0, orig_size + 1);
  if (pkt->ops->get_file(pkt, log, submit_index, orig_text, orig_size) < 0) {
    logerr("failed to extract file of submit %d", submit_index);
    ++pi->wrong_format_count;
    goto cleanup;
  }
  text = orig_text; size = orig_size;
  if (sb.gzipped) {
    if (gzip_uncompress_to_memory(&ungzip_text, &ungzip_size,
                                  orig_text, orig_size) < 0) {
      logerr("failed to ungzip file of submit %d", submit_index);
      ++pi->wrong_format_count;
      goto cleanup;
    }
    text = ungzip_text; size = ungzip_size;
    xfree(orig_text); orig_text = 0; orig_size = 0;
  }
  /* FIXME: handle only text submits for now */
  if (strlen(text) != size) {
    if ((utf8_size = ucs2_to_utf8(&utf8_text, text, size)) < 0) {
      logerr("UTF16 to UTF8 conversion failed in submit %d", submit_index);
      ++pi->wrong_format_count;
      goto cleanup;
    }
    xfree(ungzip_text); ungzip_text = 0; ungzip_size = 0;
    xfree(orig_text); orig_text = 0; orig_size = 0;
    text = utf8_text;
    size = utf8_size;
  }

  snprintf(result_queue_dir, sizeof(result_queue_dir),
           "%s/%06d", lang->compile_dir, global->contest_id);

  compile_spool_add_reply_dir(result_queue_dir);

  r = serve_compile_request(ejudge_config, state, text, size, global->contest_id,
                            sb.run_id /* run_id */,
                            0 /* submit_id */,
                            1 /* user_id */,
                            0 /* variant */,
                            1 /* locale_id */,
                            0 /* output_only */,
                            lang->src_sfx /* sfx */,
                            0 /* style_check_only */,
                            0 /* accepting_mode */,
                            0 /* priority_adjustment */,
                            0 /* notify_flag */,
                            prob, lang,
                            1 /* no_db_flag */,
                            NULL /* uuid */,
                            NULL /* judge_uuid */,
                            0 /* store_flags */,
                            0 /* rejudge_flag */,
                            0 /* vcs_mode */,
                            0 /* not_ok_is_cf */,
                            NULL /* user */,
                            NULL /* ure */);
  if (r < 0) {
    // FIXME: handle error
    abort();
  }

  // compile that stuff
  ++pi->pending_count;
  retval = 0;

 cleanup:;
  xfree(utf8_text);
  xfree(orig_text);
  xfree(ungzip_text);
  return retval;
}

static int base_run_id = 0;

static int
process_compile_packet(
        void *data,
        struct submit_block_info *sb,
        struct compile_reply_packet *pkt,
        const unsigned char *report_txt,
        int report_len)
{
  struct t3_spool_packet_info *pi = (struct t3_spool_packet_info*) data;
  int run_index, r;
  struct contest_extra *extra = 0;
  unsigned char result_queue_dir[EJ_PATH_MAX];
  struct t3m_generic_submit t3sb;
  const struct section_problem_data *prob = 0;
  const struct section_language_data *lang = 0;
  FILE *log = stderr;

  run_index = pkt->run_id - pi->base_run_id;
  ASSERT(run_index >= 0 && run_index < pi->submit_count);
  if (pkt->status != RUN_OK && pkt->status != RUN_COMPILE_ERR
      && pkt->status != RUN_CHECK_FAILED
      && pkt->status != RUN_STYLE_ERR) {
    fprintf(stderr, "Invalid compilation status\n");
    abort();
  }

  if (pkt->status != RUN_OK) {
    pi->pkt->ops->set_submit(pi->pkt, pi->log_f, run_index,
                             pkt->status, 0, report_txt);
    ++pi->processed_count;
    if (!--pi->pending_count) pi->completed = 1;
    return 0;
  }

  extra = load_contest_extra(pi->contest_id);
  ASSERT(extra);

  memset(&t3sb, 0, sizeof(t3sb));
  if (pi->pkt->ops->get_submit(pi->pkt, log, run_index, &t3sb) < 0) {
    abort();
  }

  if (t3sb.prob_id > 0 && t3sb.prob_id <= extra->state->max_prob) {
    prob = extra->state->probs[t3sb.prob_id];
  }
  if (!prob) {
    logerr("invalid problem %d in submit %d", t3sb.prob_id, run_index);
    abort();
  }
  if (t3sb.lang_id > 0 && t3sb.lang_id <= extra->state->max_lang) {
    lang = extra->state->langs[t3sb.lang_id];
  }
  if (!lang) {
    logerr("invalid language %d in submit %d", t3sb.lang_id, run_index);
    abort();
  }

  // enqueue a run request
  // FIXME: hardcoded path
  snprintf(result_queue_dir, sizeof(result_queue_dir),
           "/home/judges/%06d/var/run/%06d", pi->contest_id,
           global->contest_id);
  run_spool_add_reply_dir(result_queue_dir);

  r = serve_run_request(ejudge_config, extra->state, NULL, stderr, report_txt, report_len,
                        global->contest_id,
                        pkt->run_id,
                        0 /* submit_id */,
                        1 /* user_id */,
                        t3sb.prob_id,
                        t3sb.lang_id,
                        0 /* variant */,
                        0 /* priority_adjustment */,
                        pkt->run_id, /* judge_id */
                        NULL,        /* judge_uuid */
                        0 /* accepting_mode */,
                        0 /* notify_flag */,
                        0 /* mime_type */,
                        0, /* eoln_type */
                        0, /* locale_id */
                        0 /* compile_report_dir */,
                        0 /* comp_pkt */,
                        1 /* no_db_flag */,
                        NULL /* uuid */,
                        0 /* rejudge_flag */,
                        0 /* zip_mode */,
                        0 /* store_flags */,
                        0 /* not_ok_is_cf */,
                        NULL /* inp_text */,
                        0 /* inp_size*/,
                        NULL /* ure */,
                        NULL /* src_text*/,
                        0 /* src_size */);
  if (r < 0) abort();

  return 0;
}

const unsigned char *
get_status_str_rus(int status)
{
  switch (status) {
  case RUN_OK:
    return "OK";
  case RUN_RUN_TIME_ERR:
    return "Ошибка_при_выполнении";
  case RUN_TIME_LIMIT_ERR:
    return "Превышение_времени";
  case RUN_PRESENTATION_ERR:
    return "Неверный_формат_вывода";
  case RUN_WRONG_ANSWER_ERR:
    return "Неверный_ответ";
  case RUN_CHECK_FAILED:
    return "Ошибка_проверки!";
  case RUN_MEM_LIMIT_ERR:
    return "Превышение_ограничения_по_памяти";
  case RUN_SECURITY_ERR:
    return "Недопустимая_системная_операция";
  case RUN_SYNC_ERR:
    return "Ошибка синхронизации";
  case RUN_WALL_TIME_LIMIT_ERR:
    return "Превышение_времени";
  default:
    return "Недопустимый_статус";
  }
}

unsigned char *
make_report_data(testing_report_xml_t report, struct t3m_generic_submit *psb)
{
  char *text = 0;
  size_t size = 0;
  FILE *file = 0;
  struct testing_report_test *tt;
  int i;

  file = open_memstream(&text, &size);
  if (!report) {
    fprintf(file, "No report\n");
    goto done;
  }
  if (report->run_tests <= 0) {
    fprintf(file, "No tests\n");
    goto done;
  }
  if (report->status == RUN_CHECK_FAILED) {
    fprintf(file, "Check failed: prob = %d\n", psb->prob_id);
  }
  for (i = 0; i < report->run_tests; ++i) {
    tt = report->tests[i];
    fprintf(file, "[%d] %s\n", i + 1, get_status_str_rus(tt->status));
  }

 done:
  if (file) fclose(file);
  return text;
}

static int
process_run_packet(
        void *data,
        struct submit_block_info *sb,
        struct run_reply_packet *pkt,
        const unsigned char *report_txt,
        int report_len)
{
  struct t3_spool_packet_info *pi = (struct t3_spool_packet_info*) data;
  testing_report_xml_t report = 0;
  int run_index;
  const unsigned char *start_ptr = 0;
  unsigned char *out_text = 0;
  struct t3m_generic_submit submit;

  run_index = pkt->run_id - pi->base_run_id;
  ASSERT(run_index >= 0 && run_index < pi->submit_count);

  memset(&submit, 0, sizeof(submit));
  if (pi->pkt->ops->get_submit(pi->pkt, stderr, run_index, &submit) < 0) {
    abort();
  }

  if (get_content_type(report_txt, &start_ptr) != CONTENT_TYPE_XML) {
    // we expect the master log in XML format
    abort();
  }

  report = testing_report_parse_xml(start_ptr);
  if (!report) {
    fprintf(stderr, ">>%s<<\n", start_ptr);
    ASSERT(report);
  }
  ASSERT(!report->compile_error);

  out_text = make_report_data(report, &submit);
  pi->pkt->ops->set_submit(pi->pkt, pi->log_f, run_index,
                           pkt->status, pkt->score, out_text);
  ++pi->processed_count;
  if (!--pi->pending_count) pi->completed = 1;

  xfree(out_text);
  testing_report_free(report);
  return 0;
}

static int
process_packet(
        struct t3_spool_packet_info *pi,
        struct t3m_packet_class *pkt,
        FILE *log)
{
  int retval = -1;
  const unsigned char *exam_guid = 0;
  int i;
  struct contest_extra *extra = 0;

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
  pi->contest_id = contests[i]->id;

  extra = load_contest_extra(pi->contest_id);
  if (!extra) goto cleanup;

  pi->submit_count = pkt->ops->get_submit_count(pkt);
  if (base_run_id + pi->submit_count >= 1000000) {
    // FIXME: add some check
    base_run_id = 0;
  }
  pi->base_run_id = base_run_id;
  base_run_id += pi->submit_count + 1;

  // bind problems and languages
  if (pkt->ops->bind(pkt, log, extra->state, pi->base_run_id,
                     get_compiler_count, get_ext_name, get_short_name,
                     NULL) < 0) {
    goto cleanup;
  }

  submit_block_add(global_sb_state, global->contest_id, pi->base_run_id, pi->submit_count, process_compile_packet, process_run_packet, pi);

  for (i = 0; i < pi->submit_count; ++i) {
    process_submit(pkt, log, extra->state, i, pi);
  }

  retval = 0;

 cleanup:;
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

  pi->finish_time = time(0);

  fprintf(stderr, "Packet statistics\n");
  fprintf(stderr, "Submit count:   %d\n", pi->submit_count);
  fprintf(stderr, "Ignored count:  %d\n", pi->ignored_count);
  fprintf(stderr, "Wrong format:   %d\n", pi->wrong_format_count);
  fprintf(stderr, "Processed:      %d\n", pi->processed_count);
  fprintf(stderr, "Started:        %s\n", xml_unparse_date(pi->start_time));
  fprintf(stderr, "Finished:       %s\n", xml_unparse_date(pi->finish_time));
  fprintf(stderr, "Duration:       %ld\n", pi->finish_time - pi->start_time);

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
  struct t3m_packet_class *pkt = 0;
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

  new_info->start_time = time(0);
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

struct compile_spool_out_dirs
{
  struct compile_spool_out_dirs *prev, *next;
  unsigned char *reply_dir;
  unsigned char *status_dir;
  unsigned char *report_dir;
  int nrefs;
};

struct compile_spool_info
{
  struct compile_spool_out_dirs *first_dir, *last_dir;
};

struct compile_spool_info compile_spool;

int
compile_dir_handler(
        void *data,
        const unsigned char *spool_dir,
        const unsigned char *in_path,
        const unsigned char *pkt_name);

int
compile_spool_add_reply_dir(const unsigned char *reply_dir)
{
  struct compile_spool_out_dirs *p;
  unsigned char buf[EJ_PATH_MAX];

  ASSERT(reply_dir);

  for (p = compile_spool.first_dir; p; p = p->next) {
    if (!strcmp(reply_dir, p->reply_dir))
      break;
  }
  if (p) {
    // already found
    return 0;
  }

  XCALLOC(p, 1);
  LINK_LAST(p, compile_spool.first_dir, compile_spool.last_dir, prev, next);

  p->reply_dir = xstrdup(reply_dir);
  snprintf(buf, sizeof(buf), "%s/status", reply_dir);
  p->status_dir = xstrdup(buf);
  snprintf(buf, sizeof(buf), "%s/report", reply_dir);
  p->report_dir = xstrdup(buf);

  // FIXME: handle errors properly
  if (make_dir(p->reply_dir, 0) < 0) exit(1);
  if (make_all_dir(p->status_dir, 0777) < 0) exit(1);
  if (make_dir(p->report_dir, 0777) < 0) exit(1);

  if (dir_listener_find(global_dl_state, p->status_dir, 0, 0, 0) >= 0) {
    // dir listener is already added, but why?
    fprintf(stderr, "dir listener for '%s' already registered!\n",
            p->status_dir);
    return 1;
  }

  dir_listener_add(global_dl_state, p->status_dir,
                   compile_dir_handler, NULL, NULL);

  return 1;
}

int
compile_dir_handler(
        void *data,
        const unsigned char *spool_dir,
        const unsigned char *in_path,
        const unsigned char *pkt_name)
{
  char *pkt_buf = 0, *report_buf = 0;
  size_t pkt_size = 0, report_size = 0;
  unsigned char src_path[EJ_PATH_MAX];
  int r, retval = 0;
  struct compile_reply_packet *pkt = 0;
  struct submit_block_info *sb = 0;
  struct compile_spool_out_dirs *sp = 0;
  int report_len;
  unsigned char *report_txt = 0;

  /* find spool_dir in compile_spool */
  for (sp = compile_spool.first_dir; sp; sp = sp->next) {
    if (!strcmp(sp->status_dir, spool_dir))
      break;
  }
  if (!sp) {
    fprintf(stderr, "spool directory '%s' is not registered\n", spool_dir);
    abort();
  }

  src_path[0] = 0;
  snprintf(src_path, sizeof(src_path), "%s/%s", sp->report_dir, pkt_name);

  r = generic_read_file(&pkt_buf, 0, &pkt_size, 0, NULL, in_path, NULL);
  if (r < 0) goto cleanup;
  if (compile_reply_packet_read(pkt_size, pkt_buf, &pkt) < 0) {
    goto cleanup;
  }
  if (pkt->contest_id <= 0) {
    err("compile_dir_handler: invalid contest_id %d", pkt->contest_id);
    goto cleanup;
  }
  if (pkt->run_id < 0) {
    err("compile_dir_handler: invalid run_id %d", pkt->run_id);
    goto cleanup;
  }

  r = generic_read_file(&report_buf, 0, &report_size, 0, NULL, src_path, NULL);
  if (r < 0) goto cleanup;

  report_txt = report_buf;
  report_len = report_size;
  if (report_len < 0) {
    err("compile_dir_handler: invalid report length");
    goto cleanup;
  }

  if (!(sb = submit_block_find(global_sb_state,
                               pkt->contest_id, pkt->run_id))) {
    err("compile_dir_handler: no submits for (%d, %d)",
        pkt->contest_id, pkt->run_id);
    goto cleanup;
  }

  if (sb->compile_result_handler) {
    sb->compile_result_handler(sb->data, sb, pkt, report_txt, report_len);
  }

cleanup:;
  if (src_path[0]) {
    unlink(src_path);
  }
  xfree(pkt_buf);
  compile_reply_packet_free(pkt);
  xfree(report_buf);

  return retval;
}

int
run_dir_handler(
        void *data,
        const unsigned char *spool_dir,
        const unsigned char *in_path,
        const unsigned char *pkt_name);

struct run_spool_out_dirs
{
  struct run_spool_out_dirs *prev, *next;
  unsigned char *reply_dir;
  unsigned char *status_dir;
  unsigned char *report_dir;
  int nrefs;
};

struct run_spool_info
{
  struct run_spool_out_dirs *first_dir, *last_dir;
};

struct run_spool_info run_spool;

int
run_spool_add_reply_dir(const unsigned char *reply_dir)
{
  struct run_spool_out_dirs *p;
  unsigned char buf[EJ_PATH_MAX];

  ASSERT(reply_dir);

  for (p = run_spool.first_dir; p; p = p->next) {
    if (!strcmp(reply_dir, p->reply_dir))
      break;
  }
  if (p) {
    // already found
    return 0;
  }

  XCALLOC(p, 1);
  LINK_LAST(p, run_spool.first_dir, run_spool.last_dir, prev, next);

  p->reply_dir = xstrdup(reply_dir);
  snprintf(buf, sizeof(buf), "%s/status", reply_dir);
  p->status_dir = xstrdup(buf);
  snprintf(buf, sizeof(buf), "%s/report", reply_dir);
  p->report_dir = xstrdup(buf);

  // FIXME: handle errors properly
  if (make_dir(p->reply_dir, 0) < 0) exit(1);
  if (make_all_dir(p->status_dir, 0777) < 0) exit(1);
  if (make_dir(p->report_dir, 0777) < 0) exit(1);

  if (dir_listener_find(global_dl_state, p->status_dir, 0, 0, 0) >= 0) {
    // dir listener is already added, but why?
    fprintf(stderr, "dir listener for '%s' already registered!\n",
            p->status_dir);
    return 1;
  }

  dir_listener_add(global_dl_state, p->status_dir,
                   run_dir_handler, NULL, NULL);

  return 1;
}

int
run_dir_handler(
        void *data,
        const unsigned char *spool_dir,
        const unsigned char *in_path,
        const unsigned char *pkt_name)
{
  struct run_spool_out_dirs *sp = 0;
  unsigned char src_path[EJ_PATH_MAX];
  struct run_reply_packet *pkt = 0;
  int r;
  char *pkt_buf = 0, *report_buf = 0;
  size_t pkt_size = 0, report_size = 0;
  unsigned char *report_txt = 0;
  int report_len = 0;
  struct submit_block_info *sb = 0;

  /* find spool_dir in compile_spool */
  for (sp = run_spool.first_dir; sp; sp = sp->next) {
    if (!strcmp(sp->status_dir, spool_dir))
      break;
  }
  if (!sp) {
    fprintf(stderr, "spool directory '%s' is not registered\n", spool_dir);
    abort();
  }

  src_path[0] = 0;
  snprintf(src_path, sizeof(src_path), "%s/%s", sp->report_dir, pkt_name);

  r = generic_read_file(&pkt_buf, 0, &pkt_size, 0, NULL, in_path, NULL);
  if (r < 0) goto cleanup;
  if (run_reply_packet_read(pkt_size, pkt_buf, &pkt) < 0) {
    goto cleanup;
  }
  if (pkt->contest_id <= 0) {
    err("run_dir_handler: invalid contest_id %d", pkt->contest_id);
    goto cleanup;
  }
  if (pkt->run_id < 0) {
    err("run_dir_handler: invalid run_id %d", pkt->run_id);
    goto cleanup;
  }

  r = generic_read_file(&report_buf, 0, &report_size, 0, NULL, src_path, NULL);
  if (r < 0) goto cleanup;

  report_txt = report_buf;
  report_len = report_size;
  if (report_len < 0) {
    err("run_dir_handler: invalid report length");
    goto cleanup;
  }

  if (!(sb = submit_block_find(global_sb_state,
                               pkt->contest_id, pkt->run_id))) {
    err("run_dir_handler: no submits for (%d, %d)",
        pkt->contest_id, pkt->run_id);
    goto cleanup;
  }

  if (sb->run_result_handler) {
    sb->run_result_handler(sb->data, sb, pkt, report_txt, report_len);
  }

 cleanup:;
  return 0;
}

static int
server_loop(struct dir_listener_state *dl_state)
{
  int r;
  unsigned char pkt_name[EJ_PATH_MAX];
  unsigned char in_path[EJ_PATH_MAX];
  struct dir_listener_info *dlp;

  info("ej-batch server started");
  interrupt_init();
  interrupt_disable();
  in_path[0] = 0;

  while (1) {
    for (dlp = dl_state->first; dlp; dlp = dlp->next) {
      if (dlp->checker) {
        dlp->checker(dlp->data, dlp->spool_dir);
      }
    }

    if (interrupt_get_status() || interrupt_restart_requested()) break;

    if (!dl_state->first) {
      info("no directories to scan");
      break;
    }

    for (dlp = dl_state->first; dlp; dlp = dlp->next) {
      r = scan_dir(dlp->spool_dir, pkt_name, sizeof(pkt_name), 0);
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
  if (global->contest_id <= 0) {
    logerr("global contest_id parameter is undefined");
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
  struct dir_listener_state *dl_state = 0;
  __attribute__((unused)) int _;

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

  if ((pid = start_find_process("ej-batch", NULL, 0)) > 0) {
    fprintf(stderr, "%s: is already running as pid %d\n", argv[0], pid);
    return 1;
  }

#if defined EJUDGE_XML_PATH
  if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif
  if (!ejudge_xml_path) {
    die("path to ejudge.xml configuration file is not specified");
  }
  ejudge_config = ejudge_cfg_parse(ejudge_xml_path, 0);
  if (!ejudge_config) {
    die("configuration file '%s' is invalid", ejudge_xml_path);
  }
  if (!ejudge_config->contests_dir) {
    die("contest_dir is not set in '%s'", ejudge_xml_path);
  }
  if (contests_set_directory(ejudge_config->contests_dir) < 0) {
    die("contests_dir '%s' is invalid in '%s'", ejudge_config->contests_dir, ejudge_xml_path);
  }

  if (ejudge_config->contests_home_dir && ejudge_config->contests_home_dir[0]) {
    snprintf(pathbuf, sizeof(pathbuf), "%s/batch", ejudge_config->contests_home_dir);
    t3_mediator_dir = xstrdup(pathbuf);
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!t3_mediator_dir) {
    snprintf(pathbuf, sizeof(pathbuf), "%s/batch", EJUDGE_CONTESTS_HOME_DIR);
    t3_mediator_dir = xstrdup(pathbuf);
  }
#endif /* EJUDGE_CONTESTS_HOME_DIR */
  if (!t3_mediator_dir) {
    die("cannot determine work directory");
  }

  _ = asprintf(&t3_var_dir, "%s/var", t3_mediator_dir);
  _ = asprintf(&spool_in_dir, "%s/incoming", t3_var_dir);
  _ = asprintf(&spool_out_dir, "%s/outcoming", t3_var_dir);
  _ = asprintf(&t3_conf_dir, "%s/conf", t3_mediator_dir);

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

  global_sb_state = submit_block_create();
  XCALLOC(info, 1);
  dl_state = dir_listener_create();
  global_dl_state = dl_state;
  dir_listener_add(dl_state, spool_in_dir, t3_spool_handler, t3_spool_checker, info);

  if (server_loop(dl_state) < 0) {
    return 1;
  }
  if (interrupt_restart_requested()) start_restart();

  return 0;
}
