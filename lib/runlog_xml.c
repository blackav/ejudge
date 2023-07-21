/* -*- mode: c -*- */

/* Copyright (C) 2003-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/runlog.h"
#include "ejudge/expat_iface.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/teamdb.h"
#include "ejudge/prepare.h"
#include "ejudge/misctext.h"
#include "ejudge/contests.h"
#include "ejudge/xml_utils.h"
#include "ejudge/serve_state.h"
#include "ejudge/mime_type.h"
#include "ejudge/archive_paths.h"
#include "ejudge/fileutl.h"
#include "ejudge/base64.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/runlog_state.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <errno.h>
#include <ctype.h>
#include <zlib.h>

#ifndef EJUDGE_CHARSET
#define EJUDGE_CHARSET EJ_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

struct run_element
{
  struct xml_tree b;
  struct run_entry r;

  unsigned char *source_enc;
  unsigned char *audit_enc;

  unsigned char *source_text, *audit_text;
  size_t source_size, audit_size;
};

enum
{
  RUNLOG_T_RUNLOG = 1,
  RUNLOG_T_RUNS,
  RUNLOG_T_RUN,
  RUNLOG_T_USERS,
  RUNLOG_T_USER,
  RUNLOG_T_PROBLEMS,
  RUNLOG_T_PROBLEM,
  RUNLOG_T_LANGUAGES,
  RUNLOG_T_LANGUAGE,
  RUNLOG_T_NAME,
  RUNLOG_T_SOURCE,
  RUNLOG_T_AUDIT,
  RUNLOG_T_XML_REPORT,
  RUNLOG_T_FULL_ARCHIVE,
  RUNLOG_T_USERRUNHEADERS,
  RUNLOG_T_USERRUNHEADER,

  RUNLOG_LAST_TAG,
};
enum
{
  RUNLOG_A_RUN_ID = 1,
  RUNLOG_A_TIME,
  RUNLOG_A_SIZE,
  RUNLOG_A_IP,
  RUNLOG_A_SHA1,
  RUNLOG_A_USER_ID,
  RUNLOG_A_PROB_ID,
  RUNLOG_A_LANG_ID,
  RUNLOG_A_LOCALE_ID,
  RUNLOG_A_STATUS,
  RUNLOG_A_SCORE,
  RUNLOG_A_TEST,
  RUNLOG_A_AUTHORITATIVE,
  RUNLOG_A_ID,
  RUNLOG_A_NAME,
  RUNLOG_A_SHORT_NAME,
  RUNLOG_A_LONG_NAME,
  RUNLOG_A_VARIANT,
  RUNLOG_A_READONLY,
  RUNLOG_A_NSEC,
  RUNLOG_A_SCORE_ADJ,
  RUNLOG_A_CONTEST_ID,
  RUNLOG_A_DURATION,
  RUNLOG_A_START_TIME,
  RUNLOG_A_STOP_TIME,
  RUNLOG_A_CURRENT_TIME,
  RUNLOG_A_IPV6,
  RUNLOG_A_SSL,
  RUNLOG_A_MIME_TYPE,
  RUNLOG_A_PAGES,
  RUNLOG_A_HIDDEN,
  RUNLOG_A_EXAMINABLE,
  RUNLOG_A_SCHED_START_TIME,
  RUNLOG_A_SCHED_STOP_TIME,
  RUNLOG_A_FOG_TIME,
  RUNLOG_A_UNFOG_TIME,
  RUNLOG_A_LANG_SHORT,
  RUNLOG_A_PROB_SHORT,
  RUNLOG_A_LOGIN,
  RUNLOG_A_RUN_UUID,
  RUNLOG_A_PASSED_MODE,
  RUNLOG_A_EOLN_TYPE,
  RUNLOG_A_STORE_FLAGS,
  RUNLOG_A_TOKEN_FLAGS,
  RUNLOG_A_TOKEN_COUNT,
  RUNLOG_A_IS_VIRTUAL,
  RUNLOG_A_EXT_USER_KIND,
  RUNLOG_A_EXT_USER,
  RUNLOG_A_NOTIFY_DRIVER,
  RUNLOG_A_NOTIFY_KIND,
  RUNLOG_A_NOTIFY_QUEUE,

  RUNLOG_LAST_ATTR,
};

static const char * const elem_map[] =
{
  [RUNLOG_T_RUNLOG]       = "runlog",
  [RUNLOG_T_RUNS]         = "runs",
  [RUNLOG_T_RUN]          = "run",
  [RUNLOG_T_USERS]        = "users",
  [RUNLOG_T_USER]         = "user",
  [RUNLOG_T_PROBLEMS]     = "problems",
  [RUNLOG_T_PROBLEM]      = "problem",
  [RUNLOG_T_LANGUAGES]    = "languages",
  [RUNLOG_T_LANGUAGE]     = "language",
  [RUNLOG_T_NAME]         = "name",
  [RUNLOG_T_SOURCE]       = "source",
  [RUNLOG_T_AUDIT]        = "audit",
  [RUNLOG_T_XML_REPORT]   = "xml_report",
  [RUNLOG_T_FULL_ARCHIVE] = "full_archive",
  [RUNLOG_T_USERRUNHEADERS]="userrunheaders",
  [RUNLOG_T_USERRUNHEADER]= "userrunheader",

  [RUNLOG_LAST_TAG] = 0,
};
static const char * const attr_map[] =
{
  [RUNLOG_A_RUN_ID]           = "run_id",
  [RUNLOG_A_TIME]             = "time",
  [RUNLOG_A_SIZE]             = "size",
  [RUNLOG_A_IP]               = "ip",
  [RUNLOG_A_SHA1]             = "sha1",
  [RUNLOG_A_USER_ID]          = "user_id",
  [RUNLOG_A_PROB_ID]          = "prob_id",
  [RUNLOG_A_LANG_ID]          = "lang_id",
  [RUNLOG_A_LOCALE_ID]        = "locale_id",
  [RUNLOG_A_STATUS]           = "status",
  [RUNLOG_A_SCORE]            = "score",
  [RUNLOG_A_TEST]             = "test",
  [RUNLOG_A_AUTHORITATIVE]    = "authoritative",
  [RUNLOG_A_ID]               = "id",
  [RUNLOG_A_NAME]             = "name",
  [RUNLOG_A_SHORT_NAME]       = "short_name",
  [RUNLOG_A_LONG_NAME]        = "long_name",
  [RUNLOG_A_VARIANT]          = "variant",
  [RUNLOG_A_READONLY]         = "readonly",
  [RUNLOG_A_NSEC]             = "nsec",
  [RUNLOG_A_SCORE_ADJ]        = "score_adj",
  [RUNLOG_A_CONTEST_ID]       = "contest_id",
  [RUNLOG_A_DURATION]         = "duration",
  [RUNLOG_A_START_TIME]       = "start_time",
  [RUNLOG_A_STOP_TIME]        = "stop_time",
  [RUNLOG_A_CURRENT_TIME]     = "current_time",
  [RUNLOG_A_IPV6]             = "ipv6",
  [RUNLOG_A_SSL]              = "ssl",
  [RUNLOG_A_MIME_TYPE]        = "mime_type",
  [RUNLOG_A_PAGES]            = "pages",
  [RUNLOG_A_HIDDEN]           =  "hidden",
  [RUNLOG_A_EXAMINABLE]       = "examinable",
  [RUNLOG_A_SCHED_START_TIME] = "sched_start_time",
  [RUNLOG_A_SCHED_STOP_TIME]  = "sched_stop_time",
  [RUNLOG_A_FOG_TIME]         = "fog_time",
  [RUNLOG_A_UNFOG_TIME]       = "unfog_time",
  [RUNLOG_A_LANG_SHORT]       = "lang_short",
  [RUNLOG_A_PROB_SHORT]       = "prob_short",
  [RUNLOG_A_LOGIN]            = "login",
  [RUNLOG_A_RUN_UUID]         = "run_uuid",
  [RUNLOG_A_PASSED_MODE]      = "passed_mode",
  [RUNLOG_A_EOLN_TYPE]        = "eoln_type",
  [RUNLOG_A_STORE_FLAGS]      = "store_flags",
  [RUNLOG_A_TOKEN_FLAGS]      = "token_flags",
  [RUNLOG_A_TOKEN_COUNT]      = "token_count",
  [RUNLOG_A_IS_VIRTUAL]       = "is_virtual",
  [RUNLOG_A_EXT_USER_KIND]    = "ext_user_kind",
  [RUNLOG_A_EXT_USER]         = "ext_user",
  [RUNLOG_A_NOTIFY_DRIVER]    = "notify_driver",
  [RUNLOG_A_NOTIFY_KIND]      = "notify_kind",
  [RUNLOG_A_NOTIFY_QUEUE]     = "notify_queue",

  [RUNLOG_LAST_ATTR] = 0,
};
static size_t const elem_sizes[RUNLOG_LAST_TAG] =
{
  [RUNLOG_T_RUN] = sizeof(struct run_element),
};

static struct xml_parse_spec runlog_parse_spec =
{
  .elem_map = elem_map,
  .attr_map = attr_map,
  .elem_sizes = elem_sizes,
  .attr_sizes = NULL,
  .default_elem = 0,
  .default_attr = 0,
  .elem_alloc = NULL,
  .attr_alloc = NULL,
  .elem_free = NULL,
  .attr_free = NULL,
};

static int
parse_status(const unsigned char *str)
{
  int n, x;

  if (!str) return -1;
  n = 0;
  if (sscanf(str, "%d %n", &x, &n) == 1 && !str[n]) {
    if (run_is_invalid_status(x)) return -1;
    return x;
  }

  if (run_str_short_to_status(str, &x) < 0) return -1;
  return x;
}

static int
decode_file(
        const unsigned char *enc_txt,
        size_t *p_size,
        unsigned char **p_buf)
{
  unsigned char *buf = 0, *buf2 = 0;
  size_t bufsize, enclen;
  int flag = 0;
  unsigned long dlen = 0;

  if (!enc_txt) {
    *p_buf = 0;
    *p_size = 0;
    return 0;
  }
  if (!*enc_txt) {
    buf = (unsigned char*) xmalloc(1);
    buf[0] = 0;
    *p_buf = buf;
    *p_size = 0;
    return 0;
  }

  enclen = strlen(enc_txt);
  bufsize = enclen + 32;
  buf2 = (unsigned char*) xmalloc(bufsize);
  bufsize = base64_decode(enc_txt, enclen, buf2, &flag);
  if (flag) goto failed;

  dlen = *p_size;
  buf = (unsigned char*) xmalloc(*p_size + 1);
  if (uncompress(buf, &dlen, buf2, bufsize) != Z_OK) goto failed;
  if (dlen != *p_size) goto failed;
  *p_buf = buf; buf = 0;
  xfree(buf2); buf2 = 0;
  return 0;

 failed:
  xfree(buf);
  xfree(buf2);
  *p_buf = 0;
  *p_size = 0;
  return -1;
}

static int
parse_encoded_file(struct xml_tree *p, unsigned char **p_text, size_t *p_size)
{
  struct xml_attr *a;
  unsigned long v;
  char *eptr = 0;

  if (p->first_down) return xml_err_nested_elems(p);
  if (!(a = p->first)) return xml_err_attr_undefined(p, RUNLOG_A_SIZE);
  if (a->tag != RUNLOG_A_SIZE) return xml_err_attr_not_allowed(p, a);
  if (a->next) return xml_err_attr_not_allowed(p, a->next);

  errno = 0;
  v = strtoul(a->text, &eptr, 10);
  if (errno || *eptr) return xml_err_attr_invalid(a);
  if (v >= 128 * 1024 * 1024) return xml_err_attr_invalid(a);

  *p_size = v;
  *p_text = p->text;
  p->text = 0;
  return 0;
}

static int
process_run_elements(struct xml_tree *xt, struct run_xml_helpers *helper)
{
  struct run_element *xr;
  struct xml_attr *xa;
  struct xml_tree *p;
  int iv, n;
  time_t tv;
  int lv;
  size_t sv;
  unsigned char bool_val;
  const unsigned char *ext_user_kind_str = NULL;
  const unsigned char *ext_user_str = NULL;
  const unsigned char *notify_driver_str = NULL;
  const unsigned char *notify_kind_str = NULL;
  const unsigned char *notify_queue_str = NULL;

  while (xt) {
    if (xt->tag != RUNLOG_T_RUN) return xml_err_top_level(xt, RUNLOG_T_RUN);
    if (xml_empty_text(xt) < 0) return -1;
    //if (xt->first_down) return xml_err_nested_elems(xt);
    xr = (struct run_element*) xt;

    for (p = xt->first_down; p; p = p->right) {
      switch (p->tag) {
      case RUNLOG_T_SOURCE:
        if (parse_encoded_file(p, &xr->source_enc, &xr->source_size) < 0)
          return -1;
        break;
      case RUNLOG_T_AUDIT:
        if (parse_encoded_file(p, &xr->audit_enc, &xr->audit_size) < 0)
          return -1;
        break;
      default:
        return xml_err_elem_not_allowed(p);
      }
    }

    /* set default values */
    xr->r.run_id = -1;
    xr->r.time = (time_t) -1;
    xr->r.status = 255;
    for (xa = xt->first; xa; xa = xa->next) {
      switch (xa->tag) {
      case RUNLOG_A_RUN_ID:
        if (!xa->text) goto empty_attr_value;
        n = 0;
        if (sscanf(xa->text, "%d %n", &iv, &n) != 1 || xa->text[n])
          goto invalid_attr_value;
        if (iv < 0) goto invalid_attr_value;
        xr->r.run_id = iv;
        break;
      case RUNLOG_A_TIME:
        if (!xa->text) goto empty_attr_value;
        n = 0;
        if (sscanf(xa->text, "%ld %n", &tv, &n) != 1 || xa->text[n])
          goto invalid_attr_value;
        xr->r.time = tv;
        break;
      case RUNLOG_A_SIZE:
        if (!xa->text) goto empty_attr_value;
        n = 0;
        if (sscanf(xa->text, "%zu %n", &sv, &n) != 1 || xa->text[n])
          goto invalid_attr_value;
        xr->r.size = sv;
        break;
      case RUNLOG_A_IP:
        if (xml_parse_ip(NULL, "<string>", xa->line, xa->column,
                         xa->text, &xr->r.a.ip) < 0) return -1;
        break;
      case RUNLOG_A_SHA1:
        if (!xa->text) goto empty_attr_value;
        if (parse_sha1(xr->r.h.sha1, xa->text) < 0) goto invalid_attr_value;
        break;
      case RUNLOG_A_USER_ID:
        if (!xa->text) goto empty_attr_value;
        n = 0;
        if (sscanf(xa->text, "%d %n", &iv, &n) != 1 || xa->text[n])
          goto invalid_attr_value;
        if (iv <= 0) goto invalid_attr_value;
        xr->r.user_id = iv;
        break;
      case RUNLOG_A_LOGIN:
        if (!xa->text) goto empty_attr_value;
        iv = -1;
        if (helper && helper->parse_login_func)
          iv = helper->parse_login_func(helper, xa->text);
        if (iv <= 0) goto invalid_attr_value;
        xr->r.user_id = iv;
        break;
      case RUNLOG_A_PROB_ID:
        if (!xa->text) goto empty_attr_value;
        n = 0;
        if (sscanf(xa->text, "%d %n", &iv, &n) != 1 || xa->text[n])
          goto invalid_attr_value;
        if (iv <= 0) goto invalid_attr_value;
        xr->r.prob_id = iv;
        break;
      case RUNLOG_A_PROB_SHORT:
        if (!xa->text) goto empty_attr_value;
        iv = -1;
        if (helper && helper->parse_prob_func)
          iv = helper->parse_prob_func(helper, xa->text);
        if (iv <= 0) goto invalid_attr_value;
        xr->r.prob_id = iv;
        break;
      case RUNLOG_A_LANG_ID:
        if (!xa->text) goto empty_attr_value;
        n = 0;
        if (sscanf(xa->text, "%d %n", &iv, &n) != 1 || xa->text[n])
          goto invalid_attr_value;
        if (iv <= 0 || iv >= 255) goto invalid_attr_value;
        xr->r.lang_id = iv;
        break;
      case RUNLOG_A_LANG_SHORT:
        if (!xa->text) goto empty_attr_value;
        iv = -1;
        if (helper && helper->parse_lang_func)
          iv = helper->parse_lang_func(helper, xa->text);
        if (iv <= 0 || iv >= 255) goto invalid_attr_value;
        xr->r.lang_id = iv;
        break;
      case RUNLOG_A_VARIANT:
        if (!xa->text) goto empty_attr_value;
        n = 0;
        if (sscanf(xa->text, "%d %n", &iv, &n) != 1 || xa->text[n])
          goto invalid_attr_value;
        if (iv < 0 || iv > 255) goto invalid_attr_value;
        xr->r.lang_id = iv;
        break;
      case RUNLOG_A_LOCALE_ID:
        if (!xa->text) goto empty_attr_value;
        n = 0;
        if (sscanf(xa->text, "%d %n", &iv, &n) != 1 || xa->text[n])
          goto invalid_attr_value;
        if (iv < 0 || iv >= 127) goto invalid_attr_value;
        xr->r.locale_id = iv;
        break;
      case RUNLOG_A_STATUS:
        if (!xa->text) goto empty_attr_value;
        if ((iv = parse_status(xa->text)) < 0) goto invalid_attr_value;
        xr->r.status = iv;
        break;
      case RUNLOG_A_SCORE:
        if (!xa->text) goto empty_attr_value;
        n = 0;
        if (sscanf(xa->text, "%d %n", &iv, &n) != 1 || xa->text[n])
          goto invalid_attr_value;
        if (iv < -1) goto invalid_attr_value;
        xr->r.score = iv;
        break;
      case RUNLOG_A_SCORE_ADJ:
        if (!xa->text) goto empty_attr_value;
        n = 0;
        if (sscanf(xa->text, "%d %n", &iv, &n) != 1 || xa->text[n]
            || iv < -128 || iv > 127)
          goto invalid_attr_value;
        xr->r.score_adj = iv;
        break;
      case RUNLOG_A_TEST:
        if (!xa->text) goto empty_attr_value;
        n = 0;
        if (sscanf(xa->text, "%d %n", &iv, &n) != 1 || xa->text[n])
          goto invalid_attr_value;
        if (iv < 0 || iv > 32767) goto invalid_attr_value;
        xr->r.test = iv;
        break;
      case RUNLOG_A_AUTHORITATIVE:
        if (xml_attr_bool(xa, &iv) < 0) return -1;
        xr->r.is_imported = !iv;
        break;
      case RUNLOG_A_READONLY:
        if (xml_attr_bool_byte(xa, &bool_val) < 0) return -1;
        xr->r.is_readonly = bool_val;
        break;
      case RUNLOG_A_HIDDEN:
        if (xml_attr_bool_byte(xa, &bool_val) < 0) return -1;
        xr->r.is_hidden = bool_val;
        break;
      case RUNLOG_A_EXAMINABLE:
        //if (xml_attr_bool_byte(xa, &xr->r.is_examinable) < 0) return -1;
        break;
      case RUNLOG_A_NSEC:
        if (!xa->text) goto empty_attr_value;
        n = 0;
        if (sscanf(xa->text, "%d %n", &lv, &n) != 1 || xa->text[n])
          goto invalid_attr_value;
        if (lv < 0 || lv >= 1000000000) goto invalid_attr_value;
        xr->r.nsec = lv;
        break;
      case RUNLOG_A_SSL:
        if (xml_attr_bool_byte(xa, &bool_val) < 0) return -1;
        xr->r.ssl_flag = bool_val;
        break;
      case RUNLOG_A_MIME_TYPE:
        if (!xa->text) goto empty_attr_value;
        iv = mime_type_parse(xa->text);
        if (iv < 0) goto invalid_attr_value;
        xr->r.mime_type = iv;
        break;
      case RUNLOG_A_PAGES:
        if (!xa->text) goto empty_attr_value;
        n = 0;
        if (sscanf(xa->text, "%d %n", &iv, &n) != 1 || xa->text[n])
          goto invalid_attr_value;
        if (iv < 0 || iv > 255) goto invalid_attr_value;
        xr->r.pages = iv;
        break;
      case RUNLOG_A_RUN_UUID:
#if CONF_HAS_LIBUUID - 0 != 0
        if (xa->text && xa->text[0]) {
          ej_uuid_parse(xa->text, &xr->r.run_uuid);
        }
#endif
        break;
      case RUNLOG_A_PASSED_MODE:
        if (xml_attr_bool_byte(xa, &xr->r.passed_mode) < 0) return -1;
        break;
      case RUNLOG_A_EOLN_TYPE:
        if (!xa->text) goto empty_attr_value;
        n = 0;
        if (sscanf(xa->text, "%d %n", &iv, &n) != 1 || xa->text[n])
          goto invalid_attr_value;
        if (iv < -1) goto invalid_attr_value;
        xr->r.eoln_type = iv;
        break;
      case RUNLOG_A_STORE_FLAGS:
        if (!xa->text) goto empty_attr_value;
        n = 0;
        if (sscanf(xa->text, "%d %n", &iv, &n) != 1 || xa->text[n])
          goto invalid_attr_value;
        if (iv < -1) goto invalid_attr_value;
        xr->r.store_flags = iv;
        break;
      case RUNLOG_A_TOKEN_FLAGS:
        if (!xa->text) goto empty_attr_value;
        n = 0;
        if (sscanf(xa->text, "%d %n", &iv, &n) != 1 || xa->text[n])
          goto invalid_attr_value;
        if (iv < -1) goto invalid_attr_value;
        xr->r.token_flags = iv;
        break;
      case RUNLOG_A_TOKEN_COUNT:
        if (!xa->text) goto empty_attr_value;
        n = 0;
        if (sscanf(xa->text, "%d %n", &iv, &n) != 1 || xa->text[n])
          goto invalid_attr_value;
        if (iv < -1) goto invalid_attr_value;
        xr->r.token_count = iv;
        break;
      case RUNLOG_A_EXT_USER_KIND:
        ext_user_kind_str = xa->text;
        break;
      case RUNLOG_A_EXT_USER:
        ext_user_str = xa->text;
        break;
      case RUNLOG_A_NOTIFY_DRIVER:
        notify_driver_str = xa->text;
        break;
      case RUNLOG_A_NOTIFY_KIND:
        notify_kind_str = xa->text;
        break;
      case RUNLOG_A_NOTIFY_QUEUE:
        notify_queue_str = xa->text;
        break;
      default:
        return xml_err_attr_not_allowed(xt, xa);
      }
    }

    if (xr->r.run_id < 0)
      return xml_err_attr_undefined(xt, RUNLOG_A_RUN_ID);
    if (xr->r.time == (time_t) -1)
      return xml_err_attr_undefined(xt, RUNLOG_A_TIME);
    if (!xr->r.user_id)
      return xml_err_attr_undefined(xt, RUNLOG_A_USER_ID);
    if (!xr->r.prob_id)
      return xml_err_attr_undefined(xt, RUNLOG_A_PROB_ID);
    if (xr->r.status == 255)
      return xml_err_attr_undefined(xt, RUNLOG_A_STATUS);

    if (ext_user_kind_str) {
      int ext_user_kind = mixed_id_parse_kind(ext_user_kind_str);
      if (ext_user_kind > 0 && ext_user_kind < MIXED_ID_LAST) {
        ej_mixed_id_t ext_user;
        if (mixed_id_unmarshall(&ext_user, ext_user_kind, ext_user_str) >= 0) {
          xr->r.ext_user_kind = ext_user_kind;
          xr->r.ext_user = ext_user;
        }
      }
    }
    if (notify_driver_str) {
      char *eptr = NULL;
      errno = 0;
      long v = strtol(notify_driver_str, &eptr, 10);
      if (!errno && !*eptr && eptr != (char*) notify_driver_str
          && v > 0 && v < 128) {
        int notify_kind = mixed_id_parse_kind(notify_kind_str);
        if (notify_kind > 0 && notify_kind < MIXED_ID_LAST) {
          ej_mixed_id_t notify_queue;
          if (mixed_id_unmarshall(&notify_queue, notify_kind, notify_queue_str) >= 0) {
            xr->r.notify_driver = v;
            xr->r.notify_kind = notify_kind;
            xr->r.notify_queue = notify_queue;
          }
        }
      }
    }

    if (decode_file(xr->source_enc, &xr->source_size, &xr->source_text) < 0) {
      err("process_run_elements: %d: source decoding error", xr->r.run_id);
      return -1;
    }
    if (decode_file(xr->audit_enc, &xr->audit_size, &xr->audit_text) < 0) {
      err("process_run_elements: %d: audit decoding error", xr->r.run_id);
      return -1;
    }
    xfree(xr->source_enc); xr->source_enc = 0;
    xfree(xr->audit_enc); xr->audit_enc = 0;

    xt = xt->right;
  }
  return 0;

 empty_attr_value:
 invalid_attr_value:
  return xml_err_attr_invalid(xa);
}

static int
process_runlog_element(
        struct xml_tree *xt,
        struct xml_tree **ptruns,
        struct run_xml_helpers *helper)
{
  struct xml_tree *tt;
  struct xml_tree *truns = 0;

  if (ptruns) *ptruns = 0;
  if (xt->tag != RUNLOG_T_RUNLOG)
    return xml_err_top_level(xt, RUNLOG_T_RUNLOG);
  if (xml_empty_text(xt) < 0) return -1;
  /*
  if (xt->first) {
    err("%d:%d: element <%s> cannot have attributes",
        xt->line, xt->column, elem_map[RUNLOG_T_RUNLOG]);
    return -1;
  }
  */

  for (tt = xt->first_down; tt; tt = tt->right) {
    if (tt->tag != RUNLOG_T_RUNS) continue;
    if (truns) return xml_err_elem_redefined(xt);
    truns = tt;
  }
  if (!truns) return xml_err_elem_undefined(xt, RUNLOG_T_RUNS);
  if (xml_empty_text(truns) < 0) return -1;
  truns = truns->first_down;

  if (process_run_elements(truns, helper) < 0)
    return -1;
  if (ptruns) *ptruns = truns;
  return 0;
}

static int
collect_runlog(struct xml_tree *xt, size_t *psize,
               struct run_entry **pentries, struct run_data **pdata)
{
  struct run_element *xr;
  struct xml_tree *xx;
  int max_run_id = -1, i, j;
  struct run_entry *ee;
  struct run_data *pd = 0;

  for (xx = xt; xx; xx = xx->right) {
    ASSERT(xx->tag == RUNLOG_T_RUN);
    xr = (struct run_element*) xx;
    if (xr->r.run_id > max_run_id) max_run_id = xr->r.run_id;
  }
  if (max_run_id == -1) {
    *psize = 0;
    *pentries = 0;
    return 0;
  }
  ee = (struct run_entry*) xcalloc(max_run_id + 1, sizeof(*ee));
  pd = (struct run_data*) xcalloc(max_run_id + 1, sizeof(*pd));
  for (i = 0; i <= max_run_id; i++) {
    ee[i].run_id = i;
    ee[i].status = RUN_EMPTY;
  }
  for (xx = xt; xx; xx = xx->right) {
    xr = (struct run_element*) xx;
    j = xr->r.run_id;
    ASSERT(j >= 0 && j <= max_run_id);
    if (ee[j].status != RUN_EMPTY) {
      xml_err(xx, "duplicated run_id %d", j);
      return -1;
    }
    memcpy(&ee[j], &xr->r, sizeof(ee[0]));
    if (ee[j].status == RUN_EMPTY) {
      memset(&ee[j], 0, sizeof(ee[0]));
      ee[j].status = RUN_EMPTY;
    }
    if (run_is_normal_status(ee[j].status) && pd) {
      pd[j].source.data = xr->source_text;
      pd[j].source.size = xr->source_size;
      pd[j].audit.data = xr->audit_text;
      pd[j].audit.size = xr->audit_size;
    } else {
      xfree(xr->source_text); xr->source_text = 0;
      xfree(xr->audit_text); xr->audit_text = 0;
    }
  }
  *psize = max_run_id + 1;
  *pentries = ee;
  if (pdata) *pdata = pd;
  return max_run_id + 1;
}


int
parse_runlog_xml(
        const unsigned char *str,
        struct run_header *phead,
        size_t *psize,
        struct run_entry **pentries,
        struct run_data **pdata,
        struct run_xml_helpers *helper)
{
  struct xml_tree *xt = 0;
  struct xml_tree *truns = 0;

  xml_err_path = "<string>";
  xml_err_spec = &runlog_parse_spec;

  xt = xml_build_tree_str(NULL, str, &runlog_parse_spec);
  memset(phead, 0, sizeof(*phead));
  if (!xt) return -1;
  if (process_runlog_element(xt, &truns, helper) < 0) {
    xml_tree_free(xt, &runlog_parse_spec);
    return -1;
  }
  if (collect_runlog(truns, psize, pentries, pdata) < 0) {
    xml_tree_free(xt, &runlog_parse_spec);
    return -1;
  }
  xml_tree_free(xt, &runlog_parse_spec);
  return 0;
}

static int
is_non_empty_sha1(const ruint32_t *psha1)
{
  int i;

  for (i = 0; i < 5; i++)
    if (psha1[i]) return 1;
  return 0;
}

static const unsigned char *
encode_file(
        struct html_armor_buffer *b1,
        struct html_armor_buffer *b2,
        const unsigned char *txt,
        size_t len)
{
  unsigned long comp_exp_len;
  unsigned long b64_len;

  if (!txt || !len) {
    html_armor_reserve(b2, 0);
    b2->buf[0] = 0;
    return b2->buf;
  }

  comp_exp_len = compressBound(len);
  html_armor_reserve(b1, comp_exp_len);
  compress2(b1->buf, &comp_exp_len, txt, len, 9);
  b64_len = (comp_exp_len * 4) / 3 + 32;
  html_armor_reserve(b2, b64_len);
  b64_len = base64_encode(b1->buf, comp_exp_len, b2->buf);
  b2->buf[b64_len] = 0;
  return b2->buf;
}

int
unparse_runlog_xml(
        serve_state_t state,
        const struct contest_desc *cnts,
        FILE *f,
        const struct run_header *phead,
        size_t begin, // first item index in entries
        size_t nelems,
        const struct run_entry *entries,
        int external_mode,
        int source_mode,
        time_t current_time)
{
  int i, flags;
  const struct run_entry *pp;
  time_t ts;
  int max_user_id;
  unsigned char *astr1, *astr2, *val1, *val2;
  size_t alen1, alen2, asize1, asize2;
  unsigned char status_buf[32];
  const struct section_global_data *global = state->global;
  path_t fpath;
  char *ftext = 0;
  size_t fsize = 0;
  struct html_armor_buffer b1 = HTML_ARMOR_INITIALIZER;
  struct html_armor_buffer b2 = HTML_ARMOR_INITIALIZER;

  asize2 = asize1 = 64;
  astr1 = alloca(asize1);
  astr2 = alloca(asize2);

  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n", EJUDGE_CHARSET);
  fprintf(f, "<%s", elem_map[RUNLOG_T_RUNLOG]);
  fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_CONTEST_ID], cnts->id);
  if (phead->duration > 0) {
    fprintf(f, " %s=\"%lld\"", attr_map[RUNLOG_A_DURATION], phead->duration);
  }
  if (phead->start_time > 0) {
    fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_START_TIME],
            xml_unparse_date(phead->start_time));
  }
  if (phead->stop_time > 0) {
    fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_STOP_TIME],
            xml_unparse_date(phead->stop_time));
  }
  if (current_time > 0) {
    fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_CURRENT_TIME],
            xml_unparse_date(current_time));
  }
  if (phead->sched_time > 0) {
    fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_SCHED_START_TIME],
            xml_unparse_date(phead->sched_time));
  }
  if (phead->finish_time > 0) {
    fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_SCHED_STOP_TIME],
            xml_unparse_date(phead->finish_time));
  }
  if (global->board_fog_time > 0) {
    fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_FOG_TIME], global->board_fog_time);
    if (global->board_unfog_time > 0) {
      fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_UNFOG_TIME], global->board_unfog_time);
    }
    /*
    fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_FOG_TIME],
            xml_unparse_date(global->board_fog_time));
    if (global->board_unfog_time > 0) {
      fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_UNFOG_TIME],
              xml_unparse_date(global->board_unfog_time));
    }
    */
  }
  fprintf(f, ">\n");
  if (external_mode) {
    val1 = cnts->name;
    if (val1 && html_armor_needed(val1, &alen1)) {
      while (alen1 >= asize1) asize1 *= 2;
      astr1 = alloca(asize1);
      html_armor_string(val1, astr1);
      val1 = astr1;
    }
    fprintf(f, "  <%s>%s</%s>\n", elem_map[RUNLOG_T_NAME],
            val1, elem_map[RUNLOG_T_NAME]);
    fprintf(f, "  <%s>\n", elem_map[RUNLOG_T_USERS]);
    if (global->disable_user_database > 0) {
      max_user_id = run_get_max_user_id(state->runlog_state);
    } else {
      max_user_id = teamdb_get_max_team_id(state->teamdb_state);
    }
    for (i = 1; i <= max_user_id; i++) {
      if (teamdb_lookup(state->teamdb_state, i) <= 0) continue;
      if ((flags = teamdb_get_flags(state->teamdb_state, i)) < 0) continue;
      if ((flags & (TEAM_BANNED | TEAM_INVISIBLE | TEAM_DISQUALIFIED))) continue;
      val1 = teamdb_get_name(state->teamdb_state, i);
      if (html_armor_needed(val1, &alen1)) {
        while (alen1 >= asize1) asize1 *= 2;
        astr1 = alloca(asize1);
        html_armor_string(val1, astr1);
        val1 = astr1;
      }
      fprintf(f, "    <%s %s=\"%d\" %s=\"%s\"/>\n",
              elem_map[RUNLOG_T_USER], attr_map[RUNLOG_A_ID], i,
              attr_map[RUNLOG_A_NAME], val1);
    }
    fprintf(f, "  </%s>\n", elem_map[RUNLOG_T_USERS]);

    fprintf(f, "  <%s>\n", elem_map[RUNLOG_T_PROBLEMS]);
    for (i = 1; i <= state->max_prob; i++) {
      if (!state->probs[i]) continue;
      val1 = state->probs[i]->short_name;
      val2 = state->probs[i]->long_name;
      if (!val2) val2 = "";
      if (html_armor_needed(val1, &alen1)) {
        while (alen1 >= asize1) asize1 *= 2;
        astr1 = alloca(asize1);
        html_armor_string(val1, astr1);
        val1 = astr1;
      }
      if (html_armor_needed(val2, &alen2)) {
        while (alen2 >= asize2) asize2 *= 2;
        astr2 = alloca(asize2);
        html_armor_string(val2, astr2);
        val2 = astr2;
      }
      fprintf(f, "    <%s %s=\"%d\" %s=\"%s\" %s=\"%s\"/>\n",
              elem_map[RUNLOG_T_PROBLEM],
              attr_map[RUNLOG_A_ID], i,
              attr_map[RUNLOG_A_SHORT_NAME], val1,
              attr_map[RUNLOG_A_LONG_NAME], val2);

    }
    fprintf(f, "  </%s>\n", elem_map[RUNLOG_T_PROBLEMS]);

    fprintf(f, "  <%s>\n", elem_map[RUNLOG_T_LANGUAGES]);
    for (i = 1; i <= state->max_lang; i++) {
      if (!state->langs[i]) continue;
      val1 = state->langs[i]->short_name;
      val2 = state->langs[i]->long_name;
      if (html_armor_needed(val1, &alen1)) {
        while (alen1 >= asize1) asize1 *= 2;
        astr1 = alloca(asize1);
        html_armor_string(val1, astr1);
        val1 = astr1;
      }
      if (html_armor_needed(val2, &alen2)) {
        while (alen2 >= asize2) asize2 *= 2;
        astr2 = alloca(asize2);
        html_armor_string(val2, astr2);
        val2 = astr2;
      }
      fprintf(f, "    <%s %s=\"%d\" %s=\"%s\" %s=\"%s\"/>\n",
              elem_map[RUNLOG_T_LANGUAGE],
              attr_map[RUNLOG_A_ID], i,
              attr_map[RUNLOG_A_SHORT_NAME], val1,
              attr_map[RUNLOG_A_LONG_NAME], val2);
    }
    fprintf(f, "  </%s>\n", elem_map[RUNLOG_T_LANGUAGES]);
  }
  fprintf(f, "  <%s>\n", elem_map[RUNLOG_T_USERRUNHEADERS]);
  {
    int user_id_low = 0, user_id_high = 0;
    run_get_user_run_header_id_range(state->runlog_state,
                                     &user_id_low, &user_id_high);
    for (int user_id = user_id_low; user_id < user_id_high; ++user_id) {
      const struct user_run_header_info *urhi = run_try_user_run_header(state->runlog_state, user_id);
      if (urhi) {
        fprintf(f, "    <%s", elem_map[RUNLOG_T_USERRUNHEADER]);
        if (source_mode) {
          fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_LOGIN],
                  teamdb_get_login(state->teamdb_state, user_id));
        } else {
          fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_USER_ID], user_id);
        }
        if (urhi->is_virtual > 0) {
          fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_IS_VIRTUAL],
                  (urhi->is_virtual > 0)?"yes":"no");
        }
        if (urhi->duration > 0) {
          fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_DURATION],
                  urhi->duration);

        }
        if (urhi->start_time > 0) {
          fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_START_TIME],
                  xml_unparse_date(urhi->start_time));
        }
        if (urhi->stop_time > 0) {
          fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_STOP_TIME],
                  xml_unparse_date(urhi->stop_time));
        }
        fprintf(f, " />\n");
      }
    }
  }
  fprintf(f, "  </%s>\n", elem_map[RUNLOG_T_USERRUNHEADERS]);
  fprintf(f, "  <%s>\n", elem_map[RUNLOG_T_RUNS]);
  for (i = begin; i < nelems; i++) {
    pp = &entries[i];
    //if (external_mode && pp->is_hidden) continue;
    if (pp->is_hidden) continue;
    switch (pp->status) {
    case RUN_EMPTY:
    case RUN_RUNNING:
    case RUN_COMPILED:
    case RUN_COMPILING:
    case RUN_REJUDGE:
      continue;
    }
    flags = teamdb_get_flags(state->teamdb_state, pp->user_id);
    if (external_mode && (flags & (TEAM_BANNED | TEAM_INVISIBLE | TEAM_DISQUALIFIED)))
      continue;
    fprintf(f, "    <%s", elem_map[RUNLOG_T_RUN]);
    fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_RUN_ID], pp->run_id);
    ts = pp->time;
    ts -= phead->start_time;
    if (ts < 0) ts = 0;
    fprintf(f, " %s=\"%ld\"", attr_map[RUNLOG_A_TIME], ts);
#if CONF_HAS_LIBUUID - 0 != 0
    if (pp->run_uuid.v[0] || pp->run_uuid.v[1] || pp->run_uuid.v[2] || pp->run_uuid.v[3]) {
      fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_RUN_UUID], ej_uuid_unparse(&pp->run_uuid, ""));
    }
#endif
    if (!external_mode && pp->size > 0) {
      fprintf(f, " %s=\"%u\"", attr_map[RUNLOG_A_SIZE], pp->size);
    }
    if (!external_mode) {
      if (pp->ipv6_flag > 0)
        fprintf(f, " %s=\"yes\"", attr_map[RUNLOG_A_IPV6]);
      if (pp->a.ip)
        fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_IP],
                xml_unparse_ip(pp->a.ip));
      if (pp->ssl_flag)
        fprintf(f, " %s=\"yes\"", attr_map[RUNLOG_A_SSL]);
    }
    if (!external_mode && is_non_empty_sha1(pp->h.sha1)) {
      fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_SHA1],
              unparse_sha1(pp->h.sha1));
    }
    run_status_to_str_short(status_buf, sizeof(status_buf), pp->status);
    fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_STATUS], status_buf);
    if (source_mode) {
      if (pp->user_id > 0) {
        fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_LOGIN],
                teamdb_get_login(state->teamdb_state, pp->user_id));
      }
    } else {
      if (pp->user_id) {
        fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_USER_ID], pp->user_id);
      }
    }
    if (source_mode) {
      if (pp->prob_id > 0) {
        fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_PROB_SHORT],
                state->probs[pp->prob_id]->short_name);
      }
    } else {
      if (pp->prob_id) {
        fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_PROB_ID], pp->prob_id);
      }
    }
    if (pp->lang_id > 0) {
      if (source_mode) {
        fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_LANG_SHORT],
                state->langs[pp->lang_id]->short_name);
      } else {
        fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_LANG_ID], pp->lang_id);
      }
    } else {
      fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_MIME_TYPE],
              mime_type_get_type(pp->mime_type));
    }
    if (pp->variant) {
      fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_VARIANT], pp->variant);
    }
    if (!external_mode && pp->locale_id >= 0) {
      fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_LOCALE_ID], pp->locale_id);
    }
    if (pp->score >= 0) {
      fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_SCORE], pp->score);
    }
    if (pp->score_adj > 0) {
      fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_SCORE_ADJ], pp->score_adj);
    }
    if (pp->passed_mode > 0) {
      if (pp->test >= 0) {
        fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_TEST], pp->test);
      }
    } else {
      if (pp->test > 0) {
        fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_TEST], pp->test);
      }
    }
    if (!external_mode) {
      fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_AUTHORITATIVE],
              (!pp->is_imported)?"yes":"no");
    }
    if (!external_mode && pp->is_hidden) {
      fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_HIDDEN],
              (pp->is_hidden)?"yes":"no");
    }
    if (pp->is_readonly) {
      fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_READONLY],
              (pp->is_readonly)?"yes":"no");
    }
    fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_NSEC], pp->nsec);
    if (!external_mode && pp->pages > 0) {
      fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_PAGES], pp->pages);
    }
    /*
    if (pp->is_examinable) {
      fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_EXAMINABLE], "yes");
    }
    */
    if (pp->passed_mode > 0) {
      fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_PASSED_MODE],
              (pp->passed_mode > 0)?"yes":"no");
    }
    if (pp->eoln_type > 0) {
      fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_EOLN_TYPE], pp->eoln_type);
    }
    if (pp->store_flags > 0) {
      fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_STORE_FLAGS], pp->store_flags);
    }
    if (pp->token_flags > 0) {
      fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_TOKEN_FLAGS], pp->token_flags);
    }
    if (pp->token_count > 0) {
      fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_TOKEN_COUNT], pp->token_count);
    }
    if (pp->ext_user_kind > 0 && pp->ext_user_kind < MIXED_ID_LAST) {
      fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_EXT_USER_KIND],
              mixed_id_unparse_kind(pp->ext_user_kind));
      unsigned char mbuf[64];
      val1 = mixed_id_marshall(mbuf, pp->ext_user_kind, &pp->ext_user);
      if (html_armor_needed(val1, &alen1)) {
        while (alen1 >= asize1) asize1 *= 2;
        astr1 = alloca(asize1);
        html_armor_string(val1, astr1);
        val1 = astr1;
      }
      fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_EXT_USER], val1);
    }
    if (pp->notify_driver > 0
        && pp->notify_kind > 0 && pp->notify_kind < MIXED_ID_LAST) {
      fprintf(f, " %s=\"%d\"", attr_map[RUNLOG_A_NOTIFY_DRIVER],
              pp->notify_driver);
      fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_NOTIFY_KIND],
              mixed_id_unparse_kind(pp->notify_kind));
      unsigned char mbuf[64];
      val1 = mixed_id_marshall(mbuf, pp->notify_kind, &pp->notify_queue);
      if (html_armor_needed(val1, &alen1)) {
        while (alen1 >= asize1) asize1 *= 2;
        astr1 = alloca(asize1);
        html_armor_string(val1, astr1);
        val1 = astr1;
      }
      fprintf(f, " %s=\"%s\"", attr_map[RUNLOG_A_NOTIFY_QUEUE], val1);
    }
    if (!source_mode || !run_is_normal_status(pp->status)) {
      fprintf(f, "/>\n");
      continue;
    }
    fprintf(f, ">\n");

    // read source
    if ((flags = serve_make_source_read_path(state, fpath, sizeof(fpath), pp)) >= 0) {
      if (generic_read_file(&ftext, 0, &fsize, flags, 0, fpath, 0) >= 0) {
        fprintf(f, "      <%s %s=\"%zu\">%s</%s>\n",
                elem_map[RUNLOG_T_SOURCE], attr_map[RUNLOG_A_SIZE], fsize,
                encode_file(&b1, &b2, ftext, fsize),
                elem_map[RUNLOG_T_SOURCE]);
        xfree(ftext); ftext = 0; fsize = 0;
      }
    }

#if 0
    // read XML report
    if ((flags = serve_make_xml_report_read_path(state, fpath, sizeof(fpath), pp)) >= 0) {
      if (generic_read_file(&ftext, 0, &fsize, flags, 0, fpath, 0) >= 0) {
        fprintf(f, "      <%s>%s</%s>\n",
                elem_map[RUNLOG_T_XML_REPORT],
                encode_file(&b1, &b2, ftext, fsize),
                elem_map[RUNLOG_T_XML_REPORT]);
        xfree(ftext); ftext = 0; fsize = 0;
      }
    }

    if (global->enable_full_archive) {
      // read full archive
      if ((flags = serve_make_full_report_read_path(state, fpath, sizeof(fpath), pp)) >= 0) {
        if (generic_read_file(&ftext, 0, &fsize, flags, 0, fpath, 0) >= 0) {
          fprintf(f, "      <%s>%s</%s>\n",
                  elem_map[RUNLOG_T_FULL_ARCHIVE],
                  encode_file(&b1, &b2, ftext, fsize),
                  elem_map[RUNLOG_T_FULL_ARCHIVE]);
          xfree(ftext); ftext = 0; fsize = 0;
        }
      }
    }
#endif

    // read audit
    if ((flags = serve_make_audit_read_path(state, fpath, sizeof(fpath), pp)) >= 0) {
      if (generic_read_file(&ftext, 0, &fsize, flags, 0, fpath, 0) >= 0) {
        fprintf(f, "      <%s %s=\"%zu\">%s</%s>\n",
                elem_map[RUNLOG_T_AUDIT], attr_map[RUNLOG_A_SIZE], fsize,
                encode_file(&b1, &b2, ftext, fsize),
                elem_map[RUNLOG_T_AUDIT]);
        xfree(ftext); ftext = 0; fsize = 0;
      }
    }

    fprintf(f, "    </%s>\n", elem_map[RUNLOG_T_RUN]);
  }
  fprintf(f, "  </%s>\n", elem_map[RUNLOG_T_RUNS]);
  fprintf(f, "</%s>\n", elem_map[RUNLOG_T_RUNLOG]);

  html_armor_free(&b1);
  html_armor_free(&b2);
  return 0;
}
