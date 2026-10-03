/* -*- mode: c -*- */

/* Copyright (C) 2026 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_types.h"
#include "ejudge/ej_limits.h"
#include "ejudge/new-server.h"
#include "ejudge/new_server_proto.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/userlist_proto.h"
#include "ejudge/cJSON.h"
#include "ejudge/random.h"
#include "ejudge/runlog.h"
#include "ejudge/json_serializers.h"
#include "ejudge/teamdb.h"
#include "ejudge/testing_report_xml.h"
#include "ejudge/misctext.h"
#include "ejudge/clarlog.h"
#include "ejudge/runlog.h"
#include "ejudge/fileutl.h"
#include "ejudge/l10n.h"
#include "ejudge/sha256utils.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/compat.h"
#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/errlog.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif
#define __(x) x

void
ns_emit_json_result(
        FILE *fout,
        struct http_request_info *phr,
        int ok,
        int err_num,
        unsigned err_id,
        const unsigned char *err_msg,
        cJSON *jr);

static int
make_contest_id_list(
        struct http_request_info *phr,
        const unsigned char *ids_str,
        int cap,
        int **p_ids);

void
ns_priv_list_reviews_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  cJSON *jr = cJSON_CreateObject();
  struct run_review_filter filter = { .run_id = -1 };
  struct run_review *reviews = NULL;
  size_t review_count = 0;
  int *contest_ids = NULL;
  int contest_count = 0;
  int ok = 0;
  const unsigned char *err_msg = NULL;
  int err_num = NEW_SRV_ERR_INV_PARAM;
  int http_status = 400;
  unsigned err_id = random_u32();
  const unsigned char *contest_ids_str = NULL;
  int date_mode = 0;
  int offset = 0;
  int count = 0;
  int list_mode = 0;
  size_t total_count = 0;
  int page = 0;
  long long serial_id_gt;

  // list_mode == 1 - premoderate list
  // list_mode == 2 - postapprove list
  hr_cgi_param_int_opt(phr, "list_mode", &list_mode, 0);

  info("audit:%s:%d:%d:%d", phr->action_str, phr->user_id, phr->contest_id, list_mode);

#define ERR(msg, ...) err("%s:%d:%08x:" msg, __PRETTY_FUNCTION__, __LINE__, err_id ,##__VA_ARGS__)

  int capbit = OPCAP_MASTER_LOGIN;
  if (list_mode == 1) {
    capbit = OPCAP_PREMOD_REVIEW;
  } else if (list_mode == 2) {
    capbit = OPCAP_COMMENT_RUN;
  } else {
    if (phr->role != USER_ROLE_ADMIN) {
      http_status = 403;
      err_num = NEW_SRV_ERR_PERMISSION_DENIED;
      ERR("no ADMIN role");
      goto done;
    }
  }
  if (opcaps_check(phr->caps, capbit) < 0) {
    http_status = 403;
    err_num = NEW_SRV_ERR_PERMISSION_DENIED;
    ERR("no required capability bit");
    goto done;
  }

  hr_cgi_param_int_opt(phr, "page", &page, 0);
  hr_cgi_param_int_opt(phr, "offset", &offset, 0);
  hr_cgi_param_int_opt(phr, "count", &count, 0);
  hr_cgi_param_int_opt(phr, "date_mode", &date_mode, 0);
  hr_cgi_param_i64_opt(phr, "serial_id_gt", &serial_id_gt, 0);
  hr_cgi_param(phr, "contest_ids", &contest_ids_str);
  contest_count = make_contest_id_list(phr, contest_ids_str, OPCAP_EXT_REVIEW, &contest_ids);
  if (contest_count < 0) {
    err_num = NEW_SRV_ERR_INV_CONTEST_ID;
    ERR("invalid contest_ids");
    goto done;
  }
  if (!contest_count) {
    err_num = NEW_SRV_ERR_NO_CONTESTS;
    ERR("no contest available");
    goto done;
  }

  filter.field_mask = RER_SERIAL_ID|RER_CREATION_TIME|RER_REVIEW_UUID|RER_CONTEST_ID|RER_RUN_ID|RER_STATUS|RER_PURPOSE|RER_STATUS|RER_LAST_UPDATE_TIME|RER_GENERATION;
  filter.contest_id_list = contest_ids;
  filter.contest_id_count = contest_count;
  filter.run_id = -1;
  if (list_mode == 2) {
    filter.include_status_mask = 1U << RERS_WAITING_APPROVAL;
  }
  filter.serial_id_gt = serial_id_gt;
  if (count <= 0) count = 50;
  if (count > 1000) count = 1000;
  filter.count = count;
  if (page > 0) {
    filter.offset = (page-1) * count;
  } else if (offset >= 0) {
    filter.offset = offset;
  }
  filter.need_total_count = 1;

  if (run_review_list(cs->runlog_state, &filter, &reviews, &review_count, &total_count) < 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    ERR("database error");
    goto done;
  }

  cJSON *jrs = cJSON_CreateArray();
  for (int i = 0; i < review_count; ++i) {
    cJSON *jr = json_serialize_run_review(&reviews[i], date_mode,
      RER_CREATION_TIME|RER_REVIEW_UUID|RER_CONTEST_ID|RER_RUN_ID|RER_STATUS|RER_PURPOSE|RER_STATUS|RER_LAST_UPDATE_TIME|RER_GENERATION|RER_SERIAL_ID,
      0);
    cJSON_AddItemToArray(jrs, jr);
  }
  cJSON *jres = cJSON_CreateObject();
  cJSON_AddItemToObject(jres, "reviews", jrs);
  cJSON_AddNumberToObject(jres, "last_page", (total_count + count-1)/count);
  cJSON_AddItemToObject(jr, "result", jres);
  ok = 1;
  err_num = 0;
  http_status = 200;

done:;
  phr->json_reply = 1;
  phr->status_code = http_status;
  ns_emit_json_result(fout, phr, ok, err_num, 0, err_msg, jr);
  if (jr) {
    cJSON_Delete(jr);
  }
  free(contest_ids);
  run_review_free_array(reviews, review_count);
#undef ERR
}

static int
scan_eligible_contests(
        struct http_request_info *phr,
        int cap,
        int **p_filtered)
{
  const int *cnts_ids = NULL;
  int count = contests_get_list(&cnts_ids);
  const struct contest_desc *cnts;
  opcap_t caps;
  opcap_t gcaps = 0;
  _Bool has_global_perm = 0;
  int *filtered = NULL;
  int filtered_count = 0;

  if (count <= 0) {
    return 0;
  }

  XCALLOC(filtered, count);

  if (opcaps_find(&phr->config->capabilities, phr->login, &gcaps) >= 0 && opcaps_check(gcaps, cap) >= 0) {
    has_global_perm = 1;
  }

  for (int i = 0; i < count; ++i) {
    if (contests_get(cnts_ids[i], &cnts) < 0 || !cnts) continue;
    if (cnts->closed > 0) continue;
    if (!contests_check_judge_ip_2(cnts, &phr->ip, phr->ssl_flag)) continue;
    if (!has_global_perm && opcaps_find(&cnts->capabilities, phr->login, &caps) < 0) continue;
    if (!has_global_perm && opcaps_check(caps, cap) < 0) continue;
    filtered[filtered_count++] = cnts_ids[i];
  }

  if (!filtered_count) {
    free(filtered); filtered = NULL;
  }
  *p_filtered = filtered;
  return filtered_count;
}

static int
parse_ints(const unsigned char *s, int **p_ids)
{
  int comma_count = 0;
  for (const unsigned char *p = s; *p; ++p) {
    comma_count += *p == ',';
  }
  int *ids = NULL;
  XCALLOC(ids, comma_count+1);
  const unsigned char *p = s;
  int j = 0;
  while (p) {
    char *eptr;
    errno = 0;
    long v = strtol(p, &eptr, 10);
    if (errno || v <= 0 || (int) v != v || p == (const unsigned char *) eptr) goto fail;
    ids[j++] = v;
    p = eptr;
    if (*p && *p != ',') goto fail;
    if (*p == ',') ++p;
  }
  if (!j) {
    free(ids); ids = NULL;
  }
  *p_ids = ids;
  return j;

fail:;
  free(ids);
  return -1;
}

static int
int_sort_func(const void *p1, const void *p2)
{
  int r;
  if (!__builtin_sub_overflow(*(const int *) p1, *(const int *) p2, &r)) {
    return r;
  }
  return *(const int*) p1;
}

static int
scan_contests_in_list(
        struct http_request_info *phr,
        const unsigned char *ids_str,
        int cap,
        int **p_ids)
{
  int *ids = NULL;
  int count = parse_ints(ids_str, &ids);
  if (count <= 0) {
    return count;
  }
  qsort(ids, count, sizeof(ids[0]), int_sort_func);
  int j = 1;
  for (int i = 1; i < count; ++i) {
    if (ids[i] != ids[j - 1]) {
      ids[j++] = ids[i];
    }
  }
  count = j;

  opcap_t gcaps;
  _Bool has_global_perm = 0;

  if (opcaps_find(&phr->config->capabilities, phr->login, &gcaps) >= 0 && opcaps_check(gcaps, cap) >= 0) {
    has_global_perm = 1;
  }
  j = 0;
  for (int i = 0; i < count; ++i) {
    const struct contest_desc *cnts = NULL;
    opcap_t caps = 0;
    if (contests_get(ids[i], &cnts) < 0 || !cnts) continue;
    if (cnts->closed > 0) continue;
    if (!contests_check_judge_ip_2(cnts, &phr->ip, phr->ssl_flag)) continue;
    if (!has_global_perm && opcaps_find(&cnts->capabilities, phr->login, &caps) < 0) continue;
    if (!has_global_perm && opcaps_check(caps, cap) < 0) continue;
    ids[j++] = ids[i];
  }
  count = j;

  if (!count) {
    free(ids);
    ids = NULL;
  }
  *p_ids = ids;
  return count;
}

static int
make_contest_id_list(
        struct http_request_info *phr,
        const unsigned char *ids_str,
        int cap,
        int **p_ids)
{
  if (ids_str && !strcmp(ids_str, "*")) {
    return scan_eligible_contests(phr, cap, p_ids);
  } else if (ids_str) {
    return scan_contests_in_list(phr, ids_str, cap, p_ids);
  } else {
    if (phr->contest_id <= 0) return 0;
    int *ids = NULL;
    XCALLOC(ids, 1);
    ids[0] = phr->contest_id;
    *p_ids = ids;
    return 1;
  }
}

void
ns_priv_list_pending_reviews_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  cJSON *jr = cJSON_CreateObject();
  int ok = 0;
  int err_num = NEW_SRV_ERR_INV_PARAM;
  const unsigned char *err_msg = NULL;
  int http_status = 400;
  const unsigned char *contest_ids_str = NULL;
  int date_mode = 0;
  int *contest_ids = NULL;
  int contest_count = 0;
  struct run_review_filter filter = {};
  int offset = 0;
  int count = 0;
  struct run_review *reviews = NULL;
  size_t review_count = 0;
  unsigned err_id = random_u32();

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  #define ERR(msg, ...) err("%s:%d:%08x:" msg, __PRETTY_FUNCTION__, __LINE__, err_id ,##__VA_ARGS__)

  if (opcaps_check(phr->caps, OPCAP_EXT_REVIEW) < 0) {
    http_status = 403;
    err_num = NEW_SRV_ERR_PERMISSION_DENIED;
    ERR("no OPCAP_EXT_REVIEW bit");
    goto done;
  }

  hr_cgi_param_int_opt(phr, "offset", &offset, 0);
  hr_cgi_param_int_opt(phr, "count", &count, 0);
  hr_cgi_param_int_opt(phr, "date_mode", &date_mode, 0);
  hr_cgi_param(phr, "contest_ids", &contest_ids_str);
  contest_count = make_contest_id_list(phr, contest_ids_str, OPCAP_EXT_REVIEW, &contest_ids);
  if (contest_count < 0) {
    err_num = NEW_SRV_ERR_INV_CONTEST_ID;
    ERR("invalid contest_ids");
    goto done;
  }
  if (!contest_count) {
    err_num = NEW_SRV_ERR_NO_CONTESTS;
    ERR("no contest available");
    goto done;
  }

  filter.field_mask = RER_SERIAL_ID|RER_CREATION_TIME|RER_REVIEW_UUID|RER_CONTEST_ID|RER_RUN_ID|RER_STATUS|RER_PURPOSE|RER_STATUS|RER_LAST_UPDATE_TIME|RER_GENERATION;
  filter.contest_id_list = contest_ids;
  filter.contest_id_count = contest_count;
  filter.run_id = -1;
  filter.include_status_mask = 1U << RERS_WAITING_REVIEW;
  if (count <= 0) count = 50;
  if (count > 100) count = 100;
  filter.offset = offset;
  filter.count = count;

  if (run_review_list(cs->runlog_state, &filter, &reviews, &review_count, NULL) < 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    ERR("database error");
    goto done;
  }

  cJSON *jrs = cJSON_CreateArray();
  for (int i = 0; i < review_count; ++i) {
    cJSON *jr = json_serialize_run_review(&reviews[i], date_mode,
      RER_CREATION_TIME|RER_REVIEW_UUID|RER_CONTEST_ID|RER_RUN_ID|RER_STATUS|RER_PURPOSE|RER_STATUS|RER_LAST_UPDATE_TIME|RER_GENERATION,
      0);
    cJSON_AddItemToArray(jrs, jr);
  }
  cJSON *jres = cJSON_CreateObject();
  cJSON_AddItemToObject(jres, "reviews", jrs);
  cJSON_AddItemToObject(jr, "result", jres);
  ok = 1;
  err_num = 0;
  http_status = 200;

done:;
  phr->json_reply = 1;
  phr->status_code = http_status;
  ns_emit_json_result(fout, phr, ok, err_num, 0, err_msg, jr);
  if (jr) {
    cJSON_Delete(jr);
  }
  free(contest_ids);
  run_review_free_array(reviews, review_count);
#undef ERR
}

static int
load_other_contest(
        const struct ejudge_cfg *config,
        struct server_framework_state *fw_state,
        struct userlist_clnt *ul_conn,
        int contest_id)
{
  const struct contest_desc *cnts = NULL;

  if (contests_get(contest_id, &cnts) < 0 || !cnts) {
    err("%s:%d: failed to load contest %d", __FUNCTION__, __LINE__, contest_id);
    return -1;
  }

  struct contest_extra *extra = ns_get_contest_extra(cnts, config);
  ASSERT(extra);

  struct teamdb_db_callbacks callbacks = {};
  callbacks.user_data = (void*) fw_state;
  callbacks.list_all_users = ns_list_all_users_callback;

  return serve_state_load_contest(extra, config, contest_id, ul_conn, &callbacks, NULL, 0, ns_load_problem_plugin);
}

/*
const unsigned char *
ns_get_language_name(int lang_id)
{
  static const unsigned char * const standard_languages[] =
  {
    [1] = "pascal",
    [2] = "c",
    [3] = "cpp",
    [4] = "pascal",
    [5] = "java",
    [6] = "fortran",
    [7] = "pascal",
    [8] = "delphi",
    [9] = "c",
    [10] = "cpp",
    [11] = "basic",
    [12] = "scheme",
    [13] = "python",
    [14] = "perl",
    [15] = "prolog",
    [16] = "basic",
    [17] = "java",
    [18] = "java",
    [19] = "csharp",
    [20] = "basic",
    [21] = "ruby",
    [22] = "php",
    [23] = "python",
    [24] = "kumir",
    [25] = "make",
    [26] = "haskell",
    [27] = "basic",
    [28] = "c",
    [29] = "cpp",
    [50] = "asm",
    [51] = "c",
    [52] = "cpp",
    [53] = "go",
    [54] = "make",
    [55] = "pascal_abc.net",
    [57] = "c",
    [58] = "cpp",
    [59] = "pascal",
    [60] = "basic",
    [61] = "c",
    [62] = "cpp",
    [63] = "python",
    [64] = "python",
    [65] = "kumir",
    [66] = "asm",
    [67] = "asm",
    [68] = "mips_assembly",
    [69] = "scala",
    [70] = "rust",
    [71] = "kotlin",
    [72] = "javascript",
    [73] = "csharp",
    [74] = "basic",
    [75] = "riscv_assembly",
    [76] = "swift",
    [79] = "postgres_sql",
    [80] = "zig",
    [81] = "bash",
  };
  if ((unsigned) lang_id >= sizeof(standard_languages)/sizeof(standard_languages[0])) {
    return "unknown";
  }
  if (!standard_languages[lang_id]) {
    return "unknown";
  }
  return standard_languages[lang_id];
}

unsigned char *
ns_safe_read_utf8_text_file(
        const unsigned char *dir,
        const unsigned char *file,
        unsigned err_id,
        int missing_is_ok)
{
  FILE *fin = NULL;
  FILE *fout = NULL;
  int fd = -1;
  struct stat stb;
  char *txt_s = NULL;
  size_t txt_z = 0;
  int c;
  unsigned char path_buf[PATH_MAX];
  const unsigned char *path = file;

  if (dir && *dir) {
    if (snprintf(path_buf, sizeof(path_buf), "%s/%s", dir, file) >= (int) sizeof(path_buf)) {
      err("%s:%d:%08x: path is too long, file '%s'", __PRETTY_FUNCTION__, __LINE__, err_id, file);
      goto fail;
    }
    path = path_buf;
  }
  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK, 0);
  if (fd < 0) {
    if (missing_is_ok && errno == ENOENT) return NULL;
    err("%s:%d:%08x: open '%s' failed: %s", __PRETTY_FUNCTION__, __LINE__, err_id, path, strerror(errno));
    goto fail;
  }
  if (fstat(fd, &stb) < 0) {
    err("%s:%d:%08x: fstat '%s' failed: %s", __PRETTY_FUNCTION__, __LINE__, err_id, path, strerror(errno));
    goto fail;
  }
  if (!S_ISREG(stb.st_mode)) {
    err("%s:%d:%08x: '%s' is not regular", __PRETTY_FUNCTION__, __LINE__, err_id, path);
    goto fail;
  }
  fin = fdopen(fd, "r");
  if (!fin) {
    err("%s:%d:%08x: fdopen failed: %s", __PRETTY_FUNCTION__, __LINE__, err_id, strerror(errno));
    goto fail;
  }
  fd = -1;
  fout = open_memstream(&txt_s, &txt_z);
  if (!fin) {
    err("%s:%d:%08x: open_memstream failed: %s", __PRETTY_FUNCTION__, __LINE__, err_id, strerror(errno));
    goto fail;
  }
  while ((c = getc_unlocked(fin)) != EOF) {
    putc_unlocked(c, fout);
  }
  fclose(fin);
  fclose(fout);
  utf8_fix_buf_2(&txt_s, &txt_z, 1, 1);
  return txt_s;

fail:;
  if (fout) fclose(fout);
  if (fin) fclose(fin);
  if (fd >= 0) close(fd);
  return NULL;
}
*/

static void
safe_add_to_object(cJSON *j, const char *n, unsigned char *s)
{
  if (!s) return;
  cJSON_AddStringToObject(j, n, s);
  free(s);
}

static void
add_run_report(
        cJSON *result,
        unsigned err_id,
        int contest_id,
        int run_id,
        serve_state_t cs,
        const struct run_entry *re)
{
  unsigned char rep_path[PATH_MAX];
  int rep_flag;
  testing_report_xml_t r = NULL;
  char *rep_text = NULL;
  size_t rep_size = 0;
  const unsigned char *start_ptr = NULL;
  unsigned char uuid_buf[64];

  if ((rep_flag = serve_make_xml_report_read_path(cs, rep_path, sizeof(rep_path), re)) < 0
      && (rep_flag = serve_make_report_read_path(cs, rep_path, sizeof(rep_path), re)) < 0) {
    err("%s:%d:%08x: contest %d: run %d: no report", __FUNCTION__, __LINE__, err_id, contest_id, run_id);
    goto done;
  }

  if (re->store_flags == STORE_FLAGS_UUID_BSON) {
    if (!(r = testing_report_parse_bson_file(rep_path))) {
      err("%s:%d:%08x: contest %d: run %d: invalid BSON report", __FUNCTION__, __LINE__, err_id, contest_id, run_id);
      goto done;
    }
  } else {
    if (generic_read_file(&rep_text, 0, &rep_size, rep_flag,0,rep_path, "") < 0) {
      err("%s:%d:%08x: contest %d: run %d: failed to load report", __FUNCTION__, __LINE__, err_id, contest_id, run_id);
      goto done;
    }
    if (get_content_type(rep_text, &start_ptr) != CONTENT_TYPE_XML) {
      err("%s:%d:%08x: contest %d: run %d: not XML format", __FUNCTION__, __LINE__, err_id, contest_id, run_id);
      goto done;
    }
    if (!(r = testing_report_parse_xml(start_ptr))) {
      err("%s:%d:%08x: contest %d: run %d: invalid XML report", __FUNCTION__, __LINE__, err_id, contest_id, run_id);
      goto done;
    }
    xfree(rep_text); rep_text = NULL;
  }

  cJSON *jr = cJSON_CreateObject();
  cJSON_AddNumberToObject(jr, "run_id", re->run_id);
  if (ej_uuid_is_nonempty(re->run_uuid)) {
      cJSON_AddStringToObject(jr, "run_uuid", ej_uuid_unparse_r_nonempty(uuid_buf, sizeof(uuid_buf), &re->run_uuid));
  }
  cJSON_AddNumberToObject(jr, "contest_id", cs->contest_id);
  cJSON_AddNumberToObject(jr, "status", re->status);
  cJSON_AddStringToObject(jr, "status_str",
                          run_status_short_str(re->status));
  cJSON_AddStringToObject(jr, "status_desc",
                          run_status_str(re->status, NULL, 0, 0, 0));

/*
    cJSON_AddNumberToObject(jr, "run_time", (double) re->time);
    cJSON_AddNumberToObject(jr, "nsec", (double) re->nsec);
    cJSON_AddNumberToObject(jr, "run_time_us",
                            (double) (re->time * 1000000LL + re->nsec / 1000));
*/

  cJSON_AddNumberToObject(jr, "user_id", re->user_id);
  const unsigned char *s = teamdb_get_login(cs->teamdb_state, re->user_id);
  if (s && *s) {
      cJSON_AddStringToObject(jr, "user_login", s);
  }
  s = teamdb_get_name(cs->teamdb_state, re->user_id);
  if (s && *s) {
      cJSON_AddStringToObject(jr, "user_name", s);
  }

  cJSON_AddNumberToObject(jr, "prob_id", re->prob_id);
  const struct section_problem_data *prob = NULL;
  if (re->prob_id > 0 && re->prob_id <= cs->max_prob) {
      prob = cs->probs[re->prob_id];
  }
  if (prob && prob->short_name[0]) {
      cJSON_AddStringToObject(jr, "prob_name", prob->short_name);
  }
  if (prob && prob->internal_name && prob->internal_name[0]) {
      cJSON_AddStringToObject(jr, "prob_internal_name", prob->internal_name);
  }
  if (ej_uuid_is_nonempty(re->prob_uuid)) {
      cJSON_AddStringToObject(jr, "prob_uuid",
                              ej_uuid_unparse_r_nonempty(uuid_buf, sizeof(uuid_buf), &re->prob_uuid));
  } else if (prob && prob->uuid && prob->uuid[0]) {
      cJSON_AddStringToObject(jr, "prob_uuid", prob->uuid);
  }
  cJSON_AddNumberToObject(jr, "lang_id", re->lang_id);
  const struct section_language_data *lang = NULL;
  if (re->lang_id > 0 && re->lang_id <= cs->max_lang) {
      lang = cs->langs[re->lang_id];
  }
  if (lang && lang->short_name[0]) {
      cJSON_AddStringToObject(jr, "lang_name", lang->short_name);
  }
  cJSON_AddNumberToObject(jr, "size", re->size);
  if (re->locale_id > 0) {
      cJSON_AddNumberToObject(jr, "locale_id", re->locale_id);
  }
  if (re->eoln_type > 0) {
      cJSON_AddNumberToObject(jr, "eoln_type", re->eoln_type);
  }
  if (re->score >= 0) {
      cJSON_AddNumberToObject(jr, "raw_score", re->score);
  }
  if (re->test >= 0) {
      cJSON_AddNumberToObject(jr, "raw_test", re->test);
  }
  if (re->is_marked) {
      cJSON_AddTrueToObject(jr, "is_marked");
  }
  if (re->score_adj != 0) {
      cJSON_AddNumberToObject(jr, "score_adj", re->score_adj);
  }
  if (re->is_checked) {
      cJSON_AddTrueToObject(jr, "is_checked");
  }
  if (re->is_vcs) {
      cJSON_AddTrueToObject(jr, "is_vcs");
  }
  if (re->verdict_bits) {
      cJSON_AddNumberToObject(jr, "verdict_bits", re->verdict_bits);
  }
  cJSON_AddItemToObject(result, "run", jr);

  if (r->compiler_output) {
    r->compiler_output = utf8_fix_string_2(r->compiler_output);
    cJSON_AddStringToObject(result, "compiler_messages", r->compiler_output);
  }

  // TODO: add info about tests

done:;
  xfree(rep_text);
  testing_report_free(r);
}

static cJSON *
make_review_document(
        const struct ejudge_cfg *config,
        unsigned err_id,
        int contest_id,
        int run_id,
        int purpose,
        const unsigned char *custom_prompt,
        const unsigned char *options,
        struct run_entry *pre)
{
  cJSON *result = cJSON_CreateObject();
  unsigned char global_conf_path[PATH_MAX];
  unsigned char prob_path[PATH_MAX];
  char *run_text = NULL;
  size_t run_size = 0;
  unsigned char *text = NULL;
  const unsigned char *source_language = NULL;
  __attribute__((unused)) int _;

  const struct contest_desc *cnts = NULL;

  snprintf(global_conf_path, sizeof(global_conf_path), "%s", EJUDGE_CONF_DIR);

#define ERR(msg, ...) err("%s:%d:%08x:" msg, __PRETTY_FUNCTION__, __LINE__, err_id ,##__VA_ARGS__)

  if (contests_get(contest_id, &cnts) < 0 || !cnts) {
    // logged many times at other locations
    goto fail;
  }
  struct contest_extra *extra = ns_get_contest_extra(cnts, config);
  ASSERT(extra);
  serve_state_t cs = extra->serve_state;
  if (!cs) {
    // error already reported
    goto fail;
  }

  struct run_entry local_re = {};
  if (!pre) pre = &local_re;
  if (run_id < 0 || run_id >= run_get_total(cs->runlog_state)) {
    ERR("contest %d:run %d:invalid run_id", contest_id, run_id);
    goto fail;
  }
  if (run_get_entry(cs->runlog_state, run_id, pre) < 0) {
    ERR("contest %d:run %d:failed to get run", contest_id, run_id);
    goto fail;
  }
  if (!(pre->status <= RUN_NORMAL_LAST || pre->status == RUN_SUMMONED)) {
    ERR("contest %d:run %d:invalid status %d", contest_id, run_id, pre->status);
    goto fail;
  }

  int prob_id = pre->prob_id;
  if (prob_id <= 0 || prob_id > cs->max_prob || !cs->probs[prob_id]) {
    ERR("contest %d:run %d:invalid problem %d", contest_id, run_id, prob_id);
    goto fail;
  }
  const struct section_problem_data *prob = cs->probs[prob_id];
  if (prob->enable_external_review <= 0) {
    ERR("contest %d:run %d:problem %s: external review disabled", contest_id, run_id, prob->short_name);
    goto fail;
  }
  if (!prob->md_file || !prob->md_file[0]) {
    ERR("contest %d:run %d:problem %s: md_file is not set", contest_id, run_id, prob->short_name);
    goto fail;
  }
  if (cs->global->advanced_layout <= 0) {
    ERR("contest %d:run %d:problem %s: advanced_layout is not set", contest_id, run_id, prob->short_name);
    goto fail;
  }

  unsigned char src_path[PATH_MAX];
  src_path[0] = 0;
  int src_flags = serve_make_source_read_path(cs, src_path, sizeof(src_path), pre);
  if (src_flags < 0) {
    ERR("contest %d:run %d:source is missing", contest_id, run_id);
    goto fail;
  }
  if (generic_read_file(&run_text, 0, &run_size, src_flags, NULL, src_path, NULL) < 0) {
    ERR("contest %d:run %d:source read error", contest_id, run_id);
    goto fail;
  }
  utf8_fix_buf_2(&run_text, &run_size, 1, 1);
  cJSON_AddStringToObject(result, "source_code", run_text);
  free(run_text); run_text = NULL; run_size = 0;

  source_language = ns_get_language_name(pre->lang_id);
  cJSON_AddStringToObject(result, "source_language", source_language);

  int variant = pre->variant;
  if (prob->variant_num > 0) {
    if (variant <= 0) variant = find_variant(cs, pre->user_id, pre->prob_id, NULL);
    if (variant <= 0) {
      ERR("contest %d:run %d:variant is not set", contest_id, run_id);
      goto fail;
    }
  } else {
    variant = 0;
  }
  get_advanced_layout_path(prob_path, sizeof(prob_path), cs->global, prob, NULL, variant);

  text = ns_safe_read_utf8_text_file(prob_path, prob->md_file, err_id, 0);
  if (!text) {
    ERR("contest %d:run %d:problem %s: failed to load statement", contest_id, run_id, prob->short_name);
    goto fail;
  }
  cJSON_AddStringToObject(result, "problem_statement", text);
  free(text); text = NULL;
  cJSON_AddStringToObject(result, "interface_language", l10n_unparse_locale(pre->locale_id));
  if (custom_prompt && custom_prompt[0]) {
    cJSON_AddStringToObject(result, "custom_prompt", custom_prompt);
  }
  if (options && options[0]) {
    cJSON_AddStringToObject(result, "options", options);
  }

  unsigned char filename[PATH_MAX];
  _ = snprintf(filename, sizeof(filename), "review.%s.md", source_language);

  cJSON *jg = cJSON_CreateObject();
  safe_add_to_object(jg, "hint", ns_safe_read_utf8_text_file(global_conf_path, "review.md", err_id, 1));
  safe_add_to_object(jg, "language_hint", ns_safe_read_utf8_text_file(global_conf_path, filename, err_id, 1));
  if (purpose == RERP_REVIEW) {
    safe_add_to_object(jg, "review_hint", ns_safe_read_utf8_text_file(global_conf_path, "review_user.md", err_id, 1));
  } else if (purpose == RERP_JUDGE_HELP) {
    safe_add_to_object(jg, "judge_help_hint", ns_safe_read_utf8_text_file(global_conf_path, "review_judge_help.md", err_id, 1));
  } else if (purpose == RERP_HELP) {
    safe_add_to_object(jg, "help_hint", ns_safe_read_utf8_text_file(global_conf_path, "review_help.md", err_id, 1));
  }
  cJSON_AddItemToObject(result, "global", jg);

  cJSON *jc = cJSON_CreateObject();
  safe_add_to_object(jc, "hint", ns_safe_read_utf8_text_file(cnts->conf_dir, "review.md", err_id, 1));
  safe_add_to_object(jc, "language_hint", ns_safe_read_utf8_text_file(cnts->conf_dir, filename, err_id, 1));
  if (purpose == RERP_REVIEW) {
    safe_add_to_object(jc, "review_hint", ns_safe_read_utf8_text_file(cnts->conf_dir, "review_user.md", err_id, 1));
  } else if (purpose == RERP_JUDGE_HELP) {
    safe_add_to_object(jc, "judge_help_hint", ns_safe_read_utf8_text_file(cnts->conf_dir, "review_judge_help.md", err_id, 1));
  } else if (purpose == RERP_HELP) {
    safe_add_to_object(jc, "help_hint", ns_safe_read_utf8_text_file(cnts->conf_dir, "review_help.md", err_id, 1));
  }
  cJSON_AddItemToObject(result, "contest", jc);

  cJSON *jp = cJSON_CreateObject();
  safe_add_to_object(jp, "hint", ns_safe_read_utf8_text_file(prob_path, "review.md", err_id, 1));
  safe_add_to_object(jp, "language_hint", ns_safe_read_utf8_text_file(prob_path, filename, err_id, 1));
  if (purpose == RERP_REVIEW) {
    safe_add_to_object(jp, "review_hint", ns_safe_read_utf8_text_file(prob_path, "review_user.md", err_id, 1));
  } else if (purpose == RERP_JUDGE_HELP) {
    safe_add_to_object(jp, "judge_help_hint", ns_safe_read_utf8_text_file(prob_path, "review_judge_help.md", err_id, 1));
  } else if (purpose == RERP_HELP) {
    safe_add_to_object(jp, "help_hint", ns_safe_read_utf8_text_file(prob_path, "review_help.md", err_id, 1));
  }
  cJSON_AddItemToObject(result, "problem", jp);

  add_run_report(result, err_id, contest_id, run_id, cs, pre);

#undef ERR

  return result;

fail:;
  cJSON_Delete(result);
  free(run_text);
  free(text);
  return NULL;
}

static cJSON *
get_request_json(
        struct http_request_info *phr,
        unsigned err_id)
{
  const unsigned char *s = hr_getenv(phr, "REQUEST_METHOD");
  if (!s) {
    err("%s:%d:%08x: REQUEST_METHOD undefined", __FUNCTION__, __LINE__, err_id);
    return NULL;
  }
  if (strcmp(s, "POST")) {
    err("%s:%d:%08x: POST method expected", __FUNCTION__, __LINE__, err_id);
    return NULL;
  }
  s = hr_getenv(phr, "CONTENT_TYPE");
  if (!s) {
    err("%s:%d:%08x: CONTENT_TYPE undefined", __FUNCTION__, __LINE__, err_id);
    return NULL;
  }
  if (strcmp(s, "application/json")) {
    err("%s:%d:%08x: json application type expected", __FUNCTION__, __LINE__, err_id);
    return NULL;
  }
  if (hr_cgi_param(phr, "JSON", &s) <= 0 && !s) {
    err("%s:%d:%08x: JSON expected", __FUNCTION__, __LINE__, err_id);
    return NULL;
  }
  cJSON *res = cJSON_Parse(s);
  if (!res) {
    err("%s:%d:%08x: parse JSON failed", __FUNCTION__, __LINE__, err_id);
    return NULL;
  }
  return res;
}

void
ns_priv_start_review_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  cJSON *jr = cJSON_CreateObject();
  cJSON *jdetail = NULL;
  int ok = 0;
  int err_num = NEW_SRV_ERR_INV_PARAM;
  const unsigned char *err_msg = NULL;
  int http_status = 400;
  const unsigned char *review_uuid_str = NULL;
  ej_uuid_t review_uuid = {};
  struct run_review review = {};
  struct run_review out_review = {};
  struct run_review res_review = {};
  const struct contest_desc *review_cnts = NULL;
  struct run_review_filter filter = { .run_id = -1 };
  const unsigned char *agent = NULL;
  unsigned char *review_source = NULL;
  size_t review_len = 0;
  unsigned err_id = random_u32();
  const unsigned char *heartbeat_status = NULL;
  int date_mode = 0;
  cJSON *request_json = NULL;

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  #define ERR(msg, ...) err("%s:%d:%08x:" msg, __PRETTY_FUNCTION__, __LINE__, err_id ,##__VA_ARGS__)

  if (opcaps_check(phr->caps, OPCAP_EXT_REVIEW) < 0) {
    http_status = 403;
    err_num = NEW_SRV_ERR_PERMISSION_DENIED;
    ERR("no OPCAP_EXT_REVIEW permission");
    goto done;
  }

  if (!(request_json = get_request_json(phr, err_id))) {
    goto done;
  }
  cJSON *jru = cJSON_GetObjectItem(request_json, "review_uuid");
  if (!jru || jru->type != cJSON_String) {
    ERR("review_uuid undefined or not string");
    goto done;
  }
  review_uuid_str = jru->valuestring;

  if (ej_uuid_parse(review_uuid_str, &review_uuid) < 0) {
    http_status = 400;
    err_num = NEW_SRV_ERR_INV_UUID;
    ERR("review_uuid invalid");
    goto done;
  }
  if (run_review_fetch(cs->runlog_state, &review_uuid,
      RER_SERIAL_ID|RER_REVIEW_UUID|RER_CONTEST_ID|RER_RUN_ID|RER_STATUS|RER_PURPOSE|RER_CUSTOM_PROMPT|RER_OPTIONS, &review) <= 0) {
    http_status = 404;
    err_num = NEW_SRV_ERR_INV_UUID;
    ERR("review '%s' not found", review_uuid_str);
    goto done;
  }
  if (review.contest_id <= 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    ERR("review '%s' contest_id <= 0", review_uuid_str);
    goto done;
  }
  if (contests_get(review.contest_id, &review_cnts) < 0 || !review_cnts) {
    http_status = 403;
    err_num = NEW_SRV_ERR_PERMISSION_DENIED;
    ERR("review '%s' failed to get contest %d", review_uuid_str, review.contest_id);
    goto done;
  }
  if (review_cnts->closed > 0) {
    http_status = 403;
    err_num = NEW_SRV_ERR_PERMISSION_DENIED;
    ERR("review '%s' contest %d is closed", review_uuid_str, review.contest_id);
    goto done;
  }
  if (!contests_check_judge_ip_2(review_cnts, &phr->ip, phr->ssl_flag)) {
    http_status = 403;
    err_num = NEW_SRV_ERR_PERMISSION_DENIED;
    ERR("review '%s' contest %d IP restricted", review_uuid_str, review.contest_id);
    goto done;
  }
  cJSON *jcur = cJSON_GetObjectItem(request_json, "agent");
  if (!jcur || jcur->type != cJSON_String) {
    ERR("agent is undefined or not string");
    goto done;
  }
  agent = jcur->valuestring;
  jcur = cJSON_GetObjectItem(request_json, "heartbeat_status");
  if (!jcur || jcur->type != cJSON_String) {
    ERR("heartbeat_status is undefined or not string");
    goto done;
  }
  heartbeat_status = jcur->valuestring;
  jcur = cJSON_GetObjectItem(request_json, "date_mode");
  if (jcur && jcur->type != cJSON_Number) {
    ERR("date_mode must be number");
    goto done;
  }
  if (jcur) date_mode = jcur->valueint;

  opcap_t gcaps = 0;
  opcap_t caps = 0;
  if ((opcaps_find(&phr->config->capabilities, phr->login, &gcaps) < 0 || opcaps_check(gcaps, OPCAP_EXT_REVIEW) < 0)
      && (opcaps_find(&review_cnts->capabilities, phr->login, &caps) < 0 || opcaps_check(caps, OPCAP_EXT_REVIEW) < 0)) {
    http_status = 403;
    err_num = NEW_SRV_ERR_PERMISSION_DENIED;
    ERR("review '%s' contest %d no capability OPCAP_EXT_REVIEW is set", review_uuid_str, review.contest_id);
    goto done;
  }

  if (load_other_contest(phr->config, phr->fw_state, ul_conn, review.contest_id) < 0) {
    http_status = 400;
    err_num = NEW_SRV_ERR_CNTS_UNAVAILABLE;
    ERR("failed to load contest %d", review.contest_id);
    goto done;
  }

  // switch to the correct contest
  extra = ns_get_contest_extra(review_cnts, phr->config);
  ASSERT(extra);
  cs = extra->serve_state;
  ASSERT(cs);

  struct run_entry re = {};
  jdetail = make_review_document(phr->config, err_id, review.contest_id, review.run_id, review.purpose, review.custom_prompt, review.options, &re);
  if (!jdetail) {
    http_status = 400;
    err_num = NEW_SRV_ERR_INV_PARAM;
    ERR("failed to generate review document");
    goto done;
  }
  review_source = cJSON_PrintUnformatted(jdetail);
  review_len = strlen(review_source);

  filter.review_uuid = review_uuid;
  filter.include_status_mask = 1ULL << RERS_WAITING_REVIEW;
  filter.null_field_mask = RER_REVIEWER_USER_ID | RER_REVIEW_START_TIME | RER_REVIEW_AGENT;

  out_review.last_update_time = -2;
  out_review.review_start_time = -2;
  out_review.review_heartbeat_time = -2;
  out_review.review_source = review_source; review_source = NULL;
  out_review.reviewer_user_id = phr->user_id;
  out_review.status = RERS_REVIEWING;
  out_review.review_agent = utf8_fix_string_dup(agent);
  sha256binbuf(out_review.review_source_sha256, out_review.review_source, review_len);
  if (heartbeat_status) out_review.review_heartbeat_status = utf8_fix_string_dup(heartbeat_status);

  int res = run_review_update(cs->runlog_state, &out_review,
    RER_LAST_UPDATE_TIME|RER_REVIEW_START_TIME|RER_REVIEW_HEARTBEAT_TIME
    |RER_REVIEW_SOURCE|RER_REVIEW_SOURCE_SHA256|RER_REVIEWER_USER_ID|RER_STATUS
    |RER_REVIEW_AGENT|RER_REVIEW_HEARTBEAT_STATUS,
    &filter);
  if (res < 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    ERR("database error");
    goto done;
  }
  if (res == 0) {
    http_status = 400;
    err_num = NEW_SRV_ERR_NO_AFFECTED_ROWS;
    ERR("no affected rows");
    goto done;
  }

  uint64_t final_field_mask = RER_LAST_UPDATE_TIME | RER_REVIEW_START_TIME | RER_REVIEW_HEARTBEAT_TIME
      | RER_REVIEW_UUID | RER_REVIEW_AGENT | RER_REVIEW_HEARTBEAT_STATUS
      | RER_REVIEW_SOURCE_SHA256 | RER_CONTEST_ID | RER_RUN_ID | RER_REVIEWER_USER_ID
      | RER_GENERATION | RER_STATUS | RER_PURPOSE | RER_GENERATION;
  if (run_review_fetch(cs->runlog_state, &review_uuid,
      final_field_mask, &res_review) <= 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    ERR("failed to reload review '%s'", review_uuid_str);
    goto done;
  }

  if (res_review.generation == re.review_gen) {
    run_change_review_status(cs->runlog_state, res_review.run_id, res_review.status, re.review_gen, re.hidden_review_status, re.hidden_review_gen, NULL);
  } else if (res_review.generation == re.hidden_review_gen) {
    run_change_review_status(cs->runlog_state, res_review.run_id, re.review_status, re.review_gen, res_review.status, re.hidden_review_gen, NULL);
  }

  cJSON *jfr = json_serialize_run_review(&res_review, date_mode, final_field_mask, 0);
  cJSON *jres = cJSON_CreateObject();
  cJSON_AddItemToObject(jres, "review", jfr);
  cJSON_AddItemToObject(jres, "details", jdetail); jdetail = NULL;
  cJSON_AddItemToObject(jr, "result", jres);

  ok = 1;
  err_num = 0;
  http_status = 200;

done:;
  free(review_source);
  run_review_free(&out_review);
  run_review_free(&review);
  run_review_free(&res_review);
  phr->json_reply = 1;
  phr->status_code = http_status;
  ns_emit_json_result(fout, phr, ok, err_num, err_id, err_msg, jr);
  if (jr) {
    cJSON_Delete(jr);
  }
  if (jdetail) {
    cJSON_Delete(jdetail);
  }
  if (request_json) {
    cJSON_Delete(request_json);
  }
#undef ERR
}

void
ns_priv_heartbeat_review_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int ok = 0;
  int err_num = NEW_SRV_ERR_INV_PARAM;
  const unsigned char *err_msg = NULL;
  int http_status = 400;
  unsigned err_id = random_u32();
  const unsigned char *review_uuid_str = NULL;
  ej_uuid_t review_uuid = {};
  cJSON *jr = cJSON_CreateObject();
  struct run_review res_review = {};
  struct run_review out_review = {};
  struct run_review_filter filter = { .run_id = -1 };
  const unsigned char *heartbeat_status = NULL;
  int date_mode = 0;
  cJSON *request_json = NULL;

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  #define ERR(msg, ...) err("%s:%d:%08x:" msg, __PRETTY_FUNCTION__, __LINE__, err_id ,##__VA_ARGS__)

  if (opcaps_check(phr->caps, OPCAP_EXT_REVIEW) < 0) {
    http_status = 403;
    err_num = NEW_SRV_ERR_PERMISSION_DENIED;
    ERR("no OPCAP_EXT_REVIEW permission");
    goto done;
  }

  if (!(request_json = get_request_json(phr, err_id))) {
    goto done;
  }
  cJSON *jru = cJSON_GetObjectItem(request_json, "review_uuid");
  if (!jru || jru->type != cJSON_String) {
    ERR("review_uuid undefined or not string");
    goto done;
  }
  review_uuid_str = jru->valuestring;
  if (ej_uuid_parse(review_uuid_str, &review_uuid) < 0) {
    http_status = 400;
    err_num = NEW_SRV_ERR_INV_UUID;
    ERR("review_uuid invalid");
    goto done;
  }
  cJSON *jcur = cJSON_GetObjectItem(request_json, "heartbeat_status");
  if (!jcur || jcur->type != cJSON_String) {
    ERR("heartbeat_status is undefined or not string");
    goto done;
  }
  heartbeat_status = jcur->valuestring;
  jcur = cJSON_GetObjectItem(request_json, "date_mode");
  if (jcur && jcur->type != cJSON_Number) {
    ERR("date_mode must be number");
    goto done;
  }
  if (jcur) date_mode = jcur->valueint;

  filter.include_status_mask = 1U << RERS_REVIEWING;
  filter.null_field_mask = RER_REVIEW_FINISH_TIME;
  filter.not_null_field_mask = RER_REVIEW_START_TIME;
  filter.review_uuid = review_uuid;
  filter.reviewer_user_id = phr->user_id;

  out_review.last_update_time = -2;
  out_review.review_heartbeat_time = -2;
  out_review.review_heartbeat_status = xstrdup(heartbeat_status);

  int res = run_review_update(cs->runlog_state, &out_review,
    RER_LAST_UPDATE_TIME|RER_REVIEW_HEARTBEAT_TIME|RER_REVIEW_HEARTBEAT_STATUS,
    &filter);
  if (res < 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    ERR("database error");
    goto done;
  }
  if (res == 0) {
    http_status = 400;
    err_num = NEW_SRV_ERR_NO_AFFECTED_ROWS;
    ERR("no affected rows");
    goto done;
  }

  uint64_t final_field_mask = RER_LAST_UPDATE_TIME | RER_REVIEW_START_TIME | RER_REVIEW_HEARTBEAT_TIME
      | RER_REVIEW_UUID | RER_REVIEW_AGENT | RER_REVIEW_HEARTBEAT_STATUS
      | RER_CONTEST_ID | RER_RUN_ID | RER_REVIEWER_USER_ID
      | RER_GENERATION | RER_STATUS | RER_PURPOSE;
  if (run_review_fetch(cs->runlog_state, &review_uuid,
      final_field_mask, &res_review) <= 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    ERR("failed to reload review '%s'", review_uuid_str);
    goto done;
  }

  cJSON *jfr = json_serialize_run_review(&res_review, date_mode, final_field_mask, 0);
  cJSON *jres = cJSON_CreateObject();
  cJSON_AddItemToObject(jres, "review", jfr);
  cJSON_AddItemToObject(jr, "result", jres);

  ok = 1;
  err_num = 0;
  http_status = 200;

done:;
  run_review_free(&out_review);
  run_review_free(&res_review);
  phr->json_reply = 1;
  phr->status_code = http_status;
  ns_emit_json_result(fout, phr, ok, err_num, err_id, err_msg, jr);
  if (jr) {
    cJSON_Delete(jr);
  }
  if (request_json) {
    cJSON_Delete(request_json);
  }
#undef ERR
}

static int
parse_recommended_status(const unsigned char *str)
{
  if (!str) {
    return -1;
  }
  if (!strcasecmp(str, "ok")) {
    return RUN_OK;
  } else if (!strcasecmp(str, "reject")) {
    return RUN_REJECTED;
  } else if (!strcasecmp(str, "disqualify")) {
    return RUN_DISQUALIFIED;
  } else if (!strcasecmp(str, "ignore")) {
    return RUN_IGNORED;
  } else if (!strcasecmp(str, "summon")) {
    return RUN_SUMMONED;
  }
  return -1;
}

void
ns_priv_finish_review_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int ok = 0;
  int err_num = NEW_SRV_ERR_INV_PARAM;
  const unsigned char *err_msg = NULL;
  int http_status = 400;
  unsigned err_id = random_u32();
  const unsigned char *review_uuid_str = NULL;
  ej_uuid_t review_uuid = {};
  cJSON *jr = cJSON_CreateObject();
  struct run_review review = {};
  struct run_review out_review = {};
  struct run_review_filter filter = { .run_id = -1 };
  struct run_review res_review = {};
  int date_mode = 0;
  cJSON *request_json = NULL;
  unsigned long long field_mask = 0;
  const struct contest_desc *review_cnts = NULL;

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  #define ERR(msg, ...) err("%s:%d:%08x:" msg, __PRETTY_FUNCTION__, __LINE__, err_id ,##__VA_ARGS__)

  if (opcaps_check(phr->caps, OPCAP_EXT_REVIEW) < 0) {
    http_status = 403;
    err_num = NEW_SRV_ERR_PERMISSION_DENIED;
    ERR("no OPCAP_EXT_REVIEW permission");
    goto done;
  }

  if (!(request_json = get_request_json(phr, err_id))) {
    goto done;
  }
  cJSON *jru = cJSON_GetObjectItem(request_json, "review_uuid");
  if (!jru || jru->type != cJSON_String) {
    ERR("review_uuid undefined or not string");
    goto done;
  }
  review_uuid_str = jru->valuestring;
  if (ej_uuid_parse(review_uuid_str, &review_uuid) < 0) {
    http_status = 400;
    err_num = NEW_SRV_ERR_INV_UUID;
    ERR("review_uuid invalid");
    goto done;
  }
  if (run_review_fetch(cs->runlog_state, &review_uuid,
      RER_SERIAL_ID|RER_REVIEW_UUID|RER_CONTEST_ID|RER_RUN_ID|RER_REVIEWER_USER_ID, &review) <= 0) {
    http_status = 404;
    err_num = NEW_SRV_ERR_INV_UUID;
    ERR("review '%s' not found", review_uuid_str);
    goto done;
  }
  if (review.reviewer_user_id != phr->user_id) {
    err_num = NEW_SRV_ERR_NO_AFFECTED_ROWS;
    ERR("wrong user_id: review: %d, request: %d", review.reviewer_user_id, phr->user_id);
    goto done;
  }
  if (review.contest_id <= 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    ERR("review '%s' contest_id <= 0", review_uuid_str);
    goto done;
  }
  if (contests_get(review.contest_id, &review_cnts) < 0 || !review_cnts) {
    err_num = NEW_SRV_ERR_CNTS_UNAVAILABLE;
    ERR("review '%s' failed to get contest %d", review_uuid_str, review.contest_id);
    goto done;
  }
  if (load_other_contest(phr->config, phr->fw_state, ul_conn, review.contest_id) < 0) {
    http_status = 400;
    err_num = NEW_SRV_ERR_CNTS_UNAVAILABLE;
    ERR("failed to load contest %d", review.contest_id);
    goto done;
  }

  struct contest_extra *review_extra = ns_get_contest_extra(review_cnts, phr->config);
  ASSERT(review_extra);
  serve_state_t review_cs = review_extra->serve_state;
  if (!review_cs) {
    err_num = NEW_SRV_ERR_CNTS_UNAVAILABLE;
    ERR("failed to load contest %d", review.contest_id);
    goto done;
  }
  if (review.run_id < 0 || review.run_id >= run_get_total(review_cs->runlog_state)) {
    err_num = NEW_SRV_ERR_CNTS_UNAVAILABLE;
    ERR("contest %d:run %d:invalid run_id", review.contest_id, review.run_id);
    goto done;
  }
  struct run_entry re = {};
  if (run_get_entry(review_cs->runlog_state, review.run_id, &re) < 0) {
    err_num = NEW_SRV_ERR_CNTS_UNAVAILABLE;
    ERR("contest %d:run %d:failed to get run", review.contest_id, review.run_id);
    goto done;
  }
  int prob_id = re.prob_id;
  if (prob_id <= 0 || prob_id > review_cs->max_prob || !review_cs->probs[prob_id]) {
    err_num = NEW_SRV_ERR_CNTS_UNAVAILABLE;
    ERR("contest %d:run %d:invalid problem %d", review.contest_id, review.run_id, prob_id);
    goto done;
  }
  const struct section_problem_data *prob = review_cs->probs[prob_id];

  cJSON *jcur = cJSON_GetObjectItem(request_json, "date_mode");
  if (jcur && jcur->type != cJSON_Number) {
    ERR("date_mode must be number");
    goto done;
  }
  if (jcur) date_mode = jcur->valueint;

  int new_review_status = RERS_COMPLETE;
  if ((jcur = cJSON_GetObjectItem(request_json, "status"))) {
    if (jcur->type != cJSON_String) {
      ERR("status must be string");
      goto done;
    }
    int r = run_parse_review_status(jcur->valuestring);
    if (r < 0) {
      ERR("recommended_status value '%s' is invalid", jcur->valuestring);
      goto done;
    }
    if (r != RERS_COMPLETE && r != RERS_FAILED) {
      ERR("recommended_status value '%s' is invalid", jcur->valuestring);
      goto done;
    }
    new_review_status = r;
  }
  if (new_review_status == RERS_COMPLETE) new_review_status = RERS_WAITING_APPROVAL;
  if ((jcur = cJSON_GetObjectItem(request_json, "recommended_status"))) {
    if (jcur->type != cJSON_String) {
      ERR("recommended_status must be string");
      goto done;
    }
    int r = parse_recommended_status(jcur->valuestring);
    if (r < 0) {
      ERR("recommended_status value '%s' is invalid", jcur->valuestring);
      goto done;
    }
    field_mask |= RER_REVIEW_RECOMMENDED_STATUS;
    out_review.review_recommended_status = r;
  }
  if ((jcur = cJSON_GetObjectItem(request_json, "result"))) {
    if (jcur->type != cJSON_String) {
      ERR("result must be string");
      goto done;
    }
    field_mask |= RER_REVIEW_RESULT;
    out_review.review_result = utf8_fix_string_dup(jcur->valuestring);
  }
  if ((jcur = cJSON_GetObjectItem(request_json, "judge_result"))) {
    if (jcur->type != cJSON_String) {
      ERR("judge_result must be string");
      goto done;
    }
    field_mask |= RER_REVIEW_JUDGE_RESULT;
    out_review.review_judge_result = utf8_fix_string_dup(jcur->valuestring);
  }
  if ((jcur = cJSON_GetObjectItem(request_json, "statistics"))) {
    if (jcur->type != cJSON_String) {
      ERR("statistics must be string");
      goto done;
    }
    field_mask |= RER_REVIEW_STATISTICS;
    out_review.review_statistics = utf8_fix_string_dup(jcur->valuestring);
  }
  if ((jcur = cJSON_GetObjectItem(request_json, "log"))) {
    if (jcur->type != cJSON_String) {
      ERR("model must be string");
      goto done;
    }
    field_mask |= RER_REVIEW_LOG;
    out_review.review_log = utf8_fix_string_dup(jcur->valuestring);
  }
  if ((jcur = cJSON_GetObjectItem(request_json, "model"))) {
    if (jcur->type != cJSON_String) {
      ERR("model must be string");
      goto done;
    }
    field_mask |= RER_MODEL;
    out_review.model = utf8_fix_string_dup(jcur->valuestring);
  }
  if ((jcur = cJSON_GetObjectItem(request_json, "input_tokens"))) {
    if (jcur->type != cJSON_Number) {
      ERR("input_tokens must be string");
      goto done;
    }
    if (jcur->valueint < 0 || jcur->valueint > 2000000000) {
      ERR("input_tokens value is invalid");
      goto done;
    }
    field_mask |= RER_INPUT_TOKENS;
    out_review.input_tokens = jcur->valueint;
  }
  if ((jcur = cJSON_GetObjectItem(request_json, "cached_input_tokens"))) {
    if (jcur->type != cJSON_Number) {
      ERR("cached_input_tokens must be string");
      goto done;
    }
    if (jcur->valueint < 0 || jcur->valueint > 2000000000) {
      ERR("cached_input_tokens value is invalid");
      goto done;
    }
    field_mask |= RER_CACHED_INPUT_TOKENS;
    out_review.cached_input_tokens = jcur->valueint;
  }
  if ((jcur = cJSON_GetObjectItem(request_json, "output_tokens"))) {
    if (jcur->type != cJSON_Number) {
      ERR("output_tokens must be string");
      goto done;
    }
    if (jcur->valueint < 0 || jcur->valueint > 2000000000) {
      ERR("output_tokens value is invalid");
      goto done;
    }
    field_mask |= RER_OUPUT_TOKENS;
    out_review.output_tokens = jcur->valueint;
  }
  if ((jcur = cJSON_GetObjectItem(request_json, "reasoning_tokens"))) {
    if (jcur->type != cJSON_Number) {
      ERR("reasoning_tokens must be string");
      goto done;
    }
    if (jcur->valueint < 0 || jcur->valueint > 2000000000) {
      ERR("reasoning_tokens value is invalid");
      goto done;
    }
    field_mask |= RER_REASONING_TOKENS;
    out_review.reasoning_tokens = jcur->valueint;
  }
  if ((jcur = cJSON_GetObjectItem(request_json, "total_tokens"))) {
    if (jcur->type != cJSON_Number) {
      ERR("total_tokens must be string");
      goto done;
    }
    if (jcur->valueint < 0 || jcur->valueint > 2000000000) {
      ERR("total_tokens value is invalid");
      goto done;
    }
    field_mask |= RER_TOTAL_TOKENS;
    out_review.total_tokens = jcur->valueint;
  }
  if ((jcur = cJSON_GetObjectItem(request_json, "ai_generation_score"))) {
    if (jcur->type != cJSON_Number) {
      ERR("ai_generation_score must be string");
      goto done;
    }
    if (jcur->valueint < 0 || jcur->valueint > 100) {
      ERR("ai_generation_score value is invalid");
      goto done;
    }
    field_mask |= RER_AI_GENERATION_SCORE;
    out_review.ai_generation_score = jcur->valueint;
  }

  filter.include_status_mask = 1U << RERS_REVIEWING;
  filter.null_field_mask = RER_REVIEW_FINISH_TIME;
  filter.not_null_field_mask = RER_REVIEW_START_TIME;
  filter.review_uuid = review_uuid;
  filter.reviewer_user_id = phr->user_id;

  out_review.last_update_time = -2; field_mask |= RER_LAST_UPDATE_TIME;
  out_review.review_heartbeat_time = 0; field_mask |= RER_REVIEW_HEARTBEAT_TIME;
  out_review.review_heartbeat_status = NULL; field_mask |= RER_REVIEW_HEARTBEAT_STATUS;
  out_review.review_finish_time = -2; field_mask |= RER_REVIEW_FINISH_TIME;
  out_review.status = new_review_status; field_mask |= RER_STATUS;
  if (new_review_status == RERS_WAITING_APPROVAL && prob->disable_post_approve > 0) {
    out_review.status = RERS_COMPLETE;
    out_review.status_approved_as_is = 1; field_mask |= RER_STATUS_APPROVED_AS_IS;
    out_review.review_approved_as_is = 1; field_mask |= RER_REVIEW_APPROVED_AS_IS;
    if (out_review.review_result) {
      out_review.approved_text = xstrdup(out_review.review_result); field_mask |= RER_APPROVED_TEXT;
    }
    if (out_review.review_judge_result) {
      out_review.judge_approved_text = xstrdup(out_review.review_judge_result); field_mask |= RER_JUDGE_APPROVED_TEXT;
    }
  }

  int res = run_review_update(cs->runlog_state, &out_review, field_mask, &filter);
  if (res < 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    ERR("database error");
    goto done;
  }
  if (res == 0) {
    http_status = 400;
    err_num = NEW_SRV_ERR_NO_AFFECTED_ROWS;
    ERR("no affected rows");
    goto done;
  }

  uint64_t final_field_mask = RER_LAST_UPDATE_TIME | RER_REVIEW_START_TIME | RER_REVIEW_FINISH_TIME
      | RER_REVIEW_UUID | RER_REVIEW_AGENT
      | RER_CONTEST_ID | RER_RUN_ID | RER_REVIEWER_USER_ID
      | RER_GENERATION | RER_STATUS | RER_PURPOSE;
  if (run_review_fetch(cs->runlog_state, &review_uuid,
      final_field_mask, &res_review) <= 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    ERR("failed to reload review '%s'", review_uuid_str);
    goto done;
  }

  if (res_review.purpose == RERP_JUDGE_HELP && re.hidden_review_gen == res_review.generation && re.hidden_review_status == RERS_REVIEWING) {
    res = run_change_review_status(review_cs->runlog_state, res_review.run_id,
      re.review_status, re.review_gen,
      res_review.status, re.hidden_review_gen, NULL);
  } else if ((res_review.purpose == RERP_REVIEW || res_review.purpose == RERP_HELP) && re.review_gen == res_review.generation && re.review_status == RERS_REVIEWING) {
    res = run_change_review_status(review_cs->runlog_state, res_review.run_id,
      res_review.status, re.review_gen,
      re.hidden_review_status, re.hidden_review_gen, NULL);
  }
  if (res < 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    ERR("failed to update run entry: contest_id=%d, run_id=%d", out_review.contest_id, out_review.run_id);
    goto done;
  }

  cJSON *jfr = json_serialize_run_review(&res_review, date_mode, final_field_mask, 0);
  cJSON *jres = cJSON_CreateObject();
  cJSON_AddItemToObject(jres, "review", jfr);
  cJSON_AddItemToObject(jr, "result", jres);

  ok = 1;
  err_num = 0;
  http_status = 200;

done:;
  phr->json_reply = 1;
  phr->status_code = http_status;
  ns_emit_json_result(fout, phr, ok, err_num, err_id, err_msg, jr);
  run_review_free(&review);
  run_review_free(&out_review);
  run_review_free(&res_review);
  if (jr) {
    cJSON_Delete(jr);
  }
  if (request_json) {
    cJSON_Delete(request_json);
  }
#undef ERR
}

void
ns_priv_list_active_reviews_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  cJSON *jr = cJSON_CreateObject();
  int ok = 0;
  int err_num = NEW_SRV_ERR_INV_PARAM;
  const unsigned char *err_msg = NULL;
  int http_status = 400;
  struct run_review *reviews = NULL;
  size_t review_count = 0;
  struct run_review_filter filter = { .run_id = -1 };
  int date_mode = 0;
  int offset = 0;
  int count = 0;

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  if (opcaps_check(phr->caps, OPCAP_EXT_REVIEW) < 0) {
    http_status = 403;
    err_num = NEW_SRV_ERR_PERMISSION_DENIED;
    goto done;
  }

  hr_cgi_param_int_opt(phr, "offset", &offset, 0);
  hr_cgi_param_int_opt(phr, "count", &count, 0);
  hr_cgi_param_int_opt(phr, "date_mode", &date_mode, 0);

  uint64_t field_mask = RER_LAST_UPDATE_TIME | RER_REVIEW_START_TIME | RER_REVIEW_HEARTBEAT_TIME
    | RER_REVIEW_UUID | RER_REVIEW_AGENT | RER_REVIEW_HEARTBEAT_STATUS
    | RER_REVIEW_SOURCE_SHA256 | RER_CONTEST_ID | RER_RUN_ID
    | RER_REVIEWER_USER_ID | RER_GENERATION | RER_STATUS | RER_PURPOSE;
  filter.field_mask = RER_SERIAL_ID | field_mask;
  filter.include_status_mask = 1U << RERS_REVIEWING;
  filter.not_null_field_mask = RER_REVIEW_START_TIME;
  filter.null_field_mask = RER_REVIEW_FINISH_TIME;
  filter.reviewer_user_id = phr->user_id;
  if (count <= 0) count = 50;
  filter.offset = offset;
  filter.count = count;
  if (run_review_list(cs->runlog_state, &filter, &reviews, &review_count, NULL) < 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    goto done;
  }

  cJSON *jrs = cJSON_CreateArray();
  for (int i = 0; i < review_count; ++i) {
    cJSON *jr = json_serialize_run_review(&reviews[i], date_mode,
      field_mask,
      0);
    cJSON_AddItemToArray(jrs, jr);
  }
  cJSON *jres = cJSON_CreateObject();
  cJSON_AddItemToObject(jres, "reviews", jrs);
  cJSON_AddItemToObject(jr, "result", jres);

  ok = 1;
  err_num = 0;
  http_status = 200;

done:;
  phr->json_reply = 1;
  phr->status_code = http_status;
  ns_emit_json_result(fout, phr, ok, err_num, 0, err_msg, jr);
  if (jr) {
    cJSON_Delete(jr);
  }
}

void
ns_priv_get_active_review_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  cJSON *jr = cJSON_CreateObject();
  int ok = 0;
  int err_num = NEW_SRV_ERR_INV_PARAM;
  const unsigned char *err_msg = NULL;
  int http_status = 400;
  unsigned err_id = random_u32();
  const unsigned char *review_uuid_str = NULL;
  ej_uuid_t review_uuid = {};
  struct run_review review = {};
  cJSON *jdetail = NULL;
  int date_mode = 0;

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  #define ERR(msg, ...) err("%s:%d:%08x:" msg, __PRETTY_FUNCTION__, __LINE__, err_id ,##__VA_ARGS__)

  if (opcaps_check(phr->caps, OPCAP_EXT_REVIEW) < 0) {
    http_status = 403;
    err_num = NEW_SRV_ERR_PERMISSION_DENIED;
    ERR("no OPCAP_EXT_REVIEW permission");
    goto done;
  }

  int r = hr_cgi_param(phr, "review_uuid", &review_uuid_str);
  if (!r) {
    http_status = 400;
    err_num = NEW_SRV_ERR_INV_UUID;
    ERR("review_uuid undefined");
    goto done;
  }
  if (r < 0) {
    http_status = 400;
    err_num = NEW_SRV_ERR_INV_UUID;
    ERR("review_uuid binary");
    goto done;
  }
  if (ej_uuid_parse(review_uuid_str, &review_uuid) < 0) {
    http_status = 400;
    err_num = NEW_SRV_ERR_INV_UUID;
    ERR("review_uuid invalid");
    goto done;
  }
  hr_cgi_param_int_opt(phr, "date_mode", &date_mode, 0);

  uint64_t field_mask = RER_LAST_UPDATE_TIME | RER_REVIEW_START_TIME | RER_REVIEW_HEARTBEAT_TIME
    | RER_REVIEW_UUID | RER_REVIEW_AGENT | RER_REVIEW_HEARTBEAT_STATUS
    | RER_REVIEW_SOURCE_SHA256 | RER_CONTEST_ID | RER_RUN_ID
    | RER_REVIEWER_USER_ID | RER_GENERATION | RER_STATUS | RER_PURPOSE | RER_REVIEW_SOURCE;
  r = run_review_fetch(cs->runlog_state, &review_uuid, field_mask | RER_SERIAL_ID, &review);
  if (r < 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    ERR("database failed");
    goto done;
  }
  if (!r) {
    http_status = 404;
    err_num = NEW_SRV_ERR_NO_AFFECTED_ROWS;
    ERR("review '%s' not found", review_uuid_str);
    goto done;
  }
  if (review.reviewer_user_id != phr->user_id || review.status != RERS_REVIEWING || review.review_start_time <= 0 || review.review_finish_time > 0) {
    http_status = 404;
    err_num = NEW_SRV_ERR_NO_AFFECTED_ROWS;
    ERR("review '%s' is in wrong state", review_uuid_str);
    goto done;
  }

  jdetail = cJSON_Parse(review.review_source);
  if (!jdetail) {
    http_status = 500;
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    ERR("failed to parse review_source as json");
    goto done;
  }
  field_mask &= ~RER_REVIEW_SOURCE;
  free(review.review_source); review.review_source = NULL;

  cJSON *jfr = json_serialize_run_review(&review, date_mode, field_mask, 0);
  cJSON *jres = cJSON_CreateObject();
  cJSON_AddItemToObject(jres, "review", jfr);
  cJSON_AddItemToObject(jres, "details", jdetail); jdetail = NULL;
  cJSON_AddItemToObject(jr, "result", jres);

  ok = 1;
  err_num = 0;
  http_status = 200;

done:;
  phr->json_reply = 1;
  phr->status_code = http_status;
  ns_emit_json_result(fout, phr, ok, err_num, err_id, err_msg, jr);
  run_review_free(&review);
  if (jdetail) {
    cJSON_Delete(jdetail);
  }
  if (jr) {
    cJSON_Delete(jr);
  }
#undef ERR
}

static int
do_request_review(
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        serve_state_t cs,
        int run_id,
        const struct run_entry *re,
        int unprivileged_mode,
        int skip_existing_mode,
        int force_on_incomplete_mode,
        unsigned err_id)
{
#define ERR(msg, ...) err("%s:%d:%08x:" msg, __PRETTY_FUNCTION__, __LINE__, err_id ,##__VA_ARGS__)

  int retval = -NEW_SRV_ERR_INV_PARAM;
  int purpose = 0;

  if (unprivileged_mode > 0) {
    if (skip_existing_mode > 0 && re->review_gen != 0) {
      retval = 0;
      goto done;
    }
    if (force_on_incomplete_mode <= 0 && re->review_gen && (re->review_status != RERS_COMPLETE && re->review_status != RERS_CANCELED && re->review_status != RERS_FAILED)) {
      // must finish previous review
      retval = -NEW_SRV_ERR_RUN_REVIEW_INCOMPLETE;
      ERR("previous run review incomplete for contest_id=%d, run_id=%d", phr->contest_id, run_id);
      goto done;
    }
    if (run_is_status_for_user_review(re->status)) {
      purpose = RERP_REVIEW;
    } else if (run_is_status_for_user_help(re->status)) {
      purpose = RERP_HELP;
    } else {
      retval = -NEW_SRV_ERR_INV_STATUS;
      ERR("invalid status for review for contest_id=%d, run_id=%d", phr->contest_id, run_id);
      goto done;
    }
  } else {
    if (skip_existing_mode > 0 && re->review_gen != 0) {
      retval = 0;
      goto done;
    }
    if (force_on_incomplete_mode <= 0 && re->hidden_review_gen && (re->hidden_review_status != RERS_COMPLETE && re->hidden_review_status != RERS_CANCELED && re->hidden_review_status != RERS_FAILED)) {
      // must finish previous review
      retval = -NEW_SRV_ERR_RUN_REVIEW_INCOMPLETE;
      ERR("previous run review incomplete for contest_id=%d, run_id=%d", phr->contest_id, run_id);
      goto done;
    }
    if (run_is_status_for_judge_help(re->status)) {
      purpose = RERP_JUDGE_HELP;
    } else {
      retval = -NEW_SRV_ERR_INV_STATUS;
      ERR("invalid status for review for contest_id=%d, run_id=%d", phr->contest_id, run_id);
      goto done;
    }
  }

  const struct section_problem_data *prob = NULL;
  if (re->prob_id > 0 && re->prob_id <= cs->max_prob) prob = cs->probs[re->prob_id];
  if (!prob) {
    retval = -NEW_SRV_ERR_INV_PROB_ID;
    ERR("invalid problem %d in contest_id=%d, run_id=%d", re->prob_id, phr->contest_id, run_id);
    goto done;
  }
  if (prob->enable_external_review <= 0) {
    retval = -NEW_SRV_ERR_INV_PROB_ID;
    ERR("external review disabled for problem %d in contest_id=%d, run_id=%d", re->prob_id, phr->contest_id, run_id);
    goto done;
  }
  if (purpose == RERP_HELP) {
    if (prob->enable_user_help_request <= 0) {
      ERR("user help request disabled for problem %d in contest_id=%d, run_id=%d", re->prob_id, phr->contest_id, run_id);
      goto done;
    }
  }

  int max_gen = 0;
  if (re->review_gen > max_gen) max_gen = re->review_gen;
  if (re->hidden_review_gen > max_gen) max_gen = re->hidden_review_gen;
  int review_status = RERS_REQUESTED_REVIEW;
  if (prob->disable_pre_moderation > 0 || purpose == RERP_JUDGE_HELP) review_status = RERS_WAITING_REVIEW;
  int r = run_review_create(cs->runlog_state, re->serial_id, run_id, max_gen + 1, review_status, purpose, phr->user_id, 0, NULL);
  if (r < 0) {
    retval = -NEW_SRV_ERR_DATABASE_FAILED;
    ERR("create review failed for problem %d in contest_id=%d, run_id=%d", re->prob_id, phr->contest_id, run_id);
    goto done;
  }

  int new_review_status = re->review_status;
  int new_review_gen = re->review_gen;
  int new_hidden_review_status = re->hidden_review_status;
  int new_hidden_review_gen = re->hidden_review_gen;
  if (purpose == RERP_JUDGE_HELP) {
    new_hidden_review_status = review_status;
    new_hidden_review_gen = max_gen + 1;
  } else {
    new_review_status = review_status;
    new_review_gen = max_gen + 1;
  }

  struct run_entry ure = {};
  r = run_change_review_status(cs->runlog_state, run_id,
                                new_review_status, new_review_gen,
                                new_hidden_review_status, new_hidden_review_gen, &ure);
  if (r < 0) {
    // TODO: remove review entry
    retval = -NEW_SRV_ERR_DATABASE_FAILED;
    ERR("update run review status failed in contest_id=%d, run_id=%d", phr->contest_id, run_id);
    goto done;
  }

  retval = 0;

done:;
  return retval;
#undef ERR
}

void
ns_priv_request_review_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  cJSON *jr = cJSON_CreateObject();
  int ok = 0;
  int err_num = NEW_SRV_ERR_INV_PARAM;
  const unsigned char *err_msg = NULL;
  int http_status = 400;
  unsigned err_id = random_u32();
  int r;
  int run_id;
  struct run_entry re;
  const unsigned char *s = NULL;
  int unprivileged_mode = 0;

#define ERR(msg, ...) err("%s:%d:%08x:" msg, __PRETTY_FUNCTION__, __LINE__, err_id ,##__VA_ARGS__)

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  if (opcaps_check(phr->caps, OPCAP_COMMENT_RUN) < 0) {
    http_status = 403;
    err_num = NEW_SRV_ERR_PERMISSION_DENIED;
    goto done;
  }

  r = hr_cgi_param(phr, "run_id", &s);
  if (!r) {
    err_num = NEW_SRV_ERR_INV_RUN_ID;
    ERR("run_id undefined");
    goto done;
  }
  if (r < 0) {
    err_num = NEW_SRV_ERR_INV_RUN_ID;
    ERR("run_id is binary");
    goto done;
  }
  {
    char *eptr = NULL;
    errno = 0;
    long v = strtol(s, &eptr, 10);
    if (errno || *eptr || s == (const unsigned char *)eptr || (int) v != v || v < 0) {
      err_num = NEW_SRV_ERR_INV_RUN_ID;
      ERR("invalid run_id");
      goto done;
    }
    run_id = v;
  }
  if (run_get_entry(cs->runlog_state, run_id, &re) < 0) {
    err_num = NEW_SRV_ERR_INV_RUN_ID;
    ERR("invalid run_id");
    goto done;
  }
  hr_cgi_param_int_opt(phr, "unprivileged_mode", &unprivileged_mode, 0);

  r = do_request_review(phr, cnts, cs, run_id, &re, unprivileged_mode, 0,  0, err_id);
  if (r < 0) {
    err_num = -r;
    goto done;
  }

  ok = 1;
  err_num = 0;
  http_status = 200;

done:;
  phr->json_reply = 1;
  phr->status_code = http_status;
  ns_emit_json_result(fout, phr, ok, err_num, err_id, err_msg, jr);
  if (jr) {
    cJSON_Delete(jr);
  }
#undef ERR
}

static void
send_email_notification(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t cs,
        int run_id,
        int user_id,
        int new_status)
{
  unsigned char nsubj[1024];
  FILE *msg_f = 0;
  char *msg_t = 0;
  size_t msg_z = 0;
  const unsigned char *s = NULL;

  if (cnts->default_locale_num > 0)
    l10n_setlocale(cnts->default_locale_num);

  snprintf(nsubj, sizeof(nsubj),
          _("Your submit has been commented in contest %d"),
          cnts->id);
  msg_f = open_memstream(&msg_t, &msg_z);
  switch (new_status) {
  case RUN_OK:
    s = _("Your submit has been commented and accepted\n");
    break;
  case RUN_REJECTED:
    s = _("Your submit has been commented and rejected\n");
    break;
  case RUN_IGNORED:
    s = _("Your submit has been commented and ignored\n");
    break;
  case RUN_DISQUALIFIED:
    s = _("Your submit has been commented and disqualified\n");
    break;
  case RUN_SUMMONED:
    s = _("Your submit has been commented and you are summoned for defence\n");
    break;
  default:
    abort();
  }
  fprintf(msg_f, "%s", s);
  fprintf(msg_f, _("Contest: %d (%s)\n"), cnts->id, cnts->name);
  fprintf(msg_f, "Run Id: %d\n", run_id);
  if (cnts->team_url) {
    fprintf(msg_f, "URL: %s?contest_id=%d&login=%s\n", cnts->team_url,
            cnts->id, teamdb_get_login(cs->teamdb_state, user_id));
  }
  // TODO: include report here?
  fprintf(msg_f, "%s\n", "See detailed report in ejudge.");
  fprintf(msg_f, "\n-\nRegards,\nthe ejudge contest management system (www.ejudge.ru)\n");
  close_memstream(msg_f); msg_f = NULL;
  l10n_resetlocale();
  serve_send_email_to_user(config, cnts, cs, user_id, nsubj, msg_t);
  xfree(msg_t); msg_t = 0; msg_z = 0;
}

static int
add_clar_record(
        struct http_request_info *phr,
        serve_state_t cs,
        int run_id,
        const struct run_entry *pre,
        int new_status)
{
  unsigned char subject[256];
  snprintf(subject, sizeof(subject), "%d %s", run_id, _("is commented"));
  unsigned char text[256];
  snprintf(text, sizeof(text), "Subject: %s\n\nSee the detailed report.\n", subject);
  int text_len = strlen(text);
  int old_status = pre->status + 1;
  ej_uuid_t clar_uuid = {};
  struct timeval precise_time;
  gettimeofday(&precise_time, 0);
  int clar_id = clar_add_record(cs->clarlog_state, precise_time.tv_sec, precise_time.tv_usec, text_len, &phr->ip, phr->ssl_flag,
      0, pre->user_id, 0, phr->user_id, 0, phr->locale_id, 0, NULL,
      run_id + 1, &pre->run_uuid, 0, old_status, new_status+1, 1, NULL, subject, &clar_uuid);
  if (clar_id < 0) {
    return -1;
  }
  if (clar_add_text(cs->clarlog_state, clar_id, &clar_uuid, text, text_len) < 0) {
    return -1;
  }
  return 0;
}

void
ns_priv_review_operation_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  cJSON *jr = cJSON_CreateObject();
  int ok = 0;
  int err_num = NEW_SRV_ERR_INV_PARAM;
  const unsigned char *err_msg = NULL;
  int http_status = 400;
  unsigned err_id = random_u32();
  const unsigned char *s;
  int run_id;
  struct run_entry re;
  int operation = 0;
  struct run_review review = {};
  struct run_review review2 = {};

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  #define ERR(msg, ...) err("%s:%d:%08x:" msg, __PRETTY_FUNCTION__, __LINE__, err_id ,##__VA_ARGS__)

  if (opcaps_check(phr->caps, OPCAP_PREMOD_REVIEW) < 0) {
    http_status = 403;
    err_num = NEW_SRV_ERR_PERMISSION_DENIED;
    ERR("no OPCAP_PREMOD_REVIEW permission");
    goto done;
  }

  if (hr_cgi_param(phr, "run_id", &s) <= 0 || !s) {
    http_status = 400;
    err_num = NEW_SRV_ERR_INV_CONTEST_ID;
    ERR("run_id unset or binary");
    goto done;
  }
  {
    char *eptr = NULL;
    errno = 0;
    long v = strtol(s, &eptr, 10);
    if (errno || *eptr || eptr == (char*) s || (int) v != v || v < 0) {
      http_status = 400;
      err_num = NEW_SRV_ERR_INV_CONTEST_ID;
      ERR("run_id is invalid");
      goto done;
    }
    run_id = v;
  }
  if (run_id >= run_get_total(cs->runlog_state)) {
    http_status = 400;
    err_num = NEW_SRV_ERR_INV_CONTEST_ID;
    ERR("run_id is out of range");
    goto done;
  }
  if (run_get_entry(cs->runlog_state, run_id, &re) < 0) {
    http_status = 400;
    err_num = NEW_SRV_ERR_INV_CONTEST_ID;
    ERR("no entry with run_id %d", run_id);
    goto done;
  }
  if (re.status == RUN_EMPTY || re.status == RUN_VIRTUAL_START || re.status == RUN_VIRTUAL_STOP) {
    http_status = 400;
    err_num = NEW_SRV_ERR_INV_CONTEST_ID;
    ERR("invalid status for run_id %d: %d", run_id, re.status);
    goto done;
  }
  hr_cgi_param_int_opt(phr, "operation", &operation, 0);
  if (!operation) goto success;
  if (operation == 2 || operation == 3) {
    // 2 - swap and reject
    // 3 - swap and ok
    if (re.hidden_review_gen == 0 || re.status != RUN_PENDING_REVIEW) {
      goto success;
    }
    if (re.hidden_review_status != RERS_COMPLETE) {
      http_status = 400;
      err_num = NEW_SRV_ERR_RUN_REVIEW_INV_STATE;
      ERR("invalid status for run %d review: %d", run_id, re.hidden_review_status);
      goto done;
    }
    if (re.review_gen && re.review_status != RERS_COMPLETE && re.review_status != RERS_CANCELED && re.review_status != RERS_FAILED) {
      http_status = 400;
      err_num = NEW_SRV_ERR_RUN_REVIEW_INV_STATE;
      ERR("invalid status for run %d review: %d", run_id, re.review_status);
      goto done;
    }
    int saved_review_gen = re.review_gen;
    int saved_review_status = re.review_status;
    int saved_hidden_review_gen = re.hidden_review_gen;
    int saved_hidden_review_status = re.hidden_review_status;
    if (run_review_fetch_by_crg(cs->runlog_state, run_id, re.hidden_review_gen, RER_REVIEW_UUID | RER_PURPOSE, &review) < 0) {
      http_status = 500;
      err_num = NEW_SRV_ERR_DATABASE_FAILED;
      goto done;
    }
    if (re.review_gen) {
      if (run_review_fetch_by_crg(cs->runlog_state, run_id, re.review_gen, RER_REVIEW_UUID | RER_PURPOSE, &review2) < 0) {
        http_status = 500;
        err_num = NEW_SRV_ERR_DATABASE_FAILED;
        goto done;
      }
    }
    review.purpose = RERP_REVIEW;
    struct run_review_filter filter =
    {
      .run_id = -1,
      .review_uuid = review.review_uuid,
    };
    if (run_review_update(cs->runlog_state, &review, RER_PURPOSE,  &filter) < 0) {
      http_status = 500;
      err_num = NEW_SRV_ERR_DATABASE_FAILED;
      goto done;
    }
    if (re.review_gen) {
      review2.purpose = RERP_JUDGE_HELP;
      struct run_review_filter filter =
      {
        .run_id = -1,
        .review_uuid = review2.review_uuid,
      };
      if (run_review_update(cs->runlog_state, &review2, RER_PURPOSE,  &filter) < 0) {
        http_status = 500;
        err_num = NEW_SRV_ERR_DATABASE_FAILED;
        goto done;
      }
    }
    int new_status = 0;
    if (operation == 2) {
      new_status = RUN_REJECTED;
    } else if (operation == 3) {
      new_status = RUN_OK;
    } else {
      abort();
    }
    if (add_clar_record(phr, cs, run_id, &re, new_status) < 0) {
      http_status = 500;
      err_num = NEW_SRV_ERR_CLARLOG_UPDATE_FAILED;
      ERR("add_clar_record failed");
      goto done;
    }
    if (operation == 2) {
      if (run_change_status_4(cs->runlog_state, run_id, RUN_REJECTED, &re) < 0) {
        http_status = 500;
        err_num = NEW_SRV_ERR_RUNLOG_UPDATE_FAILED;
        ERR("run_change_status_4 failed");
        goto done;
      }
      serve_notify_run_update(phr->config, cs, &re);
    } else if (operation == 3) {
    struct section_problem_data *prob = 0;
      int full_score = 0;
      int user_status = 0, user_score = 0;
      if (re.prob_id > 0 && re.prob_id <= cs->max_prob) prob = cs->probs[re.prob_id];
      if (prob) full_score = prob->full_score;
      if (cs->global->separate_user_score > 0 && re.is_saved) {
        user_status = RUN_OK;
        user_score = -1;
        if (prob) user_score = prob->full_user_score;
        if (prob && user_score < 0) user_score = prob->full_score;
        if (user_score < 0) user_score = 0;
      }
      int res = run_change_status_3(cs->runlog_state, run_id, RUN_OK, re.test, re.passed_mode, full_score, 0,
        re.saved_score, user_status, re.saved_test, user_score, re.verdict_bits, -2, NULL, &re);
      if (res < 0) {
        http_status = 500;
        err_num = NEW_SRV_ERR_RUNLOG_UPDATE_FAILED;
        ERR("run_change_status_3 failed");
        goto done;
      }
      serve_notify_run_update(phr->config, cs, &re);
    } else {
      abort();
    }
    if (run_change_review_status(cs->runlog_state, run_id, saved_hidden_review_status, saved_hidden_review_gen, saved_review_status, saved_review_gen, NULL) < 0) {
      http_status = 500;
      err_num = NEW_SRV_ERR_RUNLOG_UPDATE_FAILED;
      ERR("run_change_review_status failed");
      goto done;
    }
    const unsigned char *audit_cmd = NULL;
    if (operation == 2) {
      audit_cmd = "external-comment-run-reject";
    } else if (operation == 3) {
      audit_cmd = "external-comment-run-ok";
    } else {
      abort();
    }
    serve_audit_log(cs, run_id, &re, phr->user_id, &phr->ip, phr->ssl_flag, audit_cmd, "ok", new_status-1, NULL);

    if (cs->global->notify_clar_reply) {
      send_email_notification(phr->config, cnts, cs, run_id, re.user_id, new_status-1);
    }

    if (cnts->enable_user_telegram > 0 && !re.is_hidden) {
      serve_telegram_user_run_reviewed(ejudge_config, cnts, cs, re.user_id, run_id, new_status-1);
    }

    goto success;
  }
  if (operation != 1) {
    http_status = 400;
    err_num = NEW_SRV_ERR_INV_PARAM;
    ERR("invalid operation %d", operation);
    goto done;
  }
  if (re.review_gen == 0 && re.hidden_review_gen == 0) {
    goto success;
  }
  if (re.review_gen == 0 && re.hidden_review_gen != 0) {
    if (re.hidden_review_status != RERS_COMPLETE) {
      http_status = 400;
      err_num = NEW_SRV_ERR_RUN_REVIEW_INV_STATE;
      ERR("invalid status for run %d review: %d", run_id, re.hidden_review_status);
      goto done;
    }
    if (run_review_fetch_by_crg(cs->runlog_state, run_id, re.hidden_review_gen,
      RER_REVIEW_UUID | RER_PURPOSE, &review) < 0) {
      http_status = 500;
      err_num = NEW_SRV_ERR_DATABASE_FAILED;
      goto done;
    }
    review.purpose = RERP_REVIEW;
    struct run_review_filter filter =
    {
      .run_id = -1,
      .review_uuid = review.review_uuid,
    };
    if (run_review_update(cs->runlog_state, &review, RER_PURPOSE,  &filter) < 0) {
      http_status = 500;
      err_num = NEW_SRV_ERR_DATABASE_FAILED;
      goto done;
    }
    if (run_change_review_status(cs->runlog_state, run_id, re.hidden_review_status, re.hidden_review_gen, 0, 0, NULL) < 0) {
      http_status = 500;
      err_num = NEW_SRV_ERR_DATABASE_FAILED;
      goto done;
    }
    goto success;
  }
  if (re.review_gen != 0 && re.hidden_review_gen == 0) {
    if (re.review_status != RERS_COMPLETE) {
      http_status = 400;
      err_num = NEW_SRV_ERR_RUN_REVIEW_INV_STATE;
      ERR("invalid status for run_id %d: %d", run_id, re.status);
      goto done;
    }
    if (run_review_fetch_by_crg(cs->runlog_state, run_id, re.review_gen,
      RER_REVIEW_UUID | RER_PURPOSE, &review) < 0) {
      http_status = 500;
      err_num = NEW_SRV_ERR_DATABASE_FAILED;
      goto done;
    }
    review.purpose = RERP_JUDGE_HELP;
    struct run_review_filter filter =
    {
      .run_id = -1,
      .review_uuid = review.review_uuid,
    };
    if (run_review_update(cs->runlog_state, &review, RER_PURPOSE,  &filter) < 0) {
      http_status = 500;
      err_num = NEW_SRV_ERR_DATABASE_FAILED;
      goto done;
    }
    if (run_change_review_status(cs->runlog_state, run_id, 0, 0, re.review_status, re.review_gen, NULL) < 0) {
      http_status = 500;
      err_num = NEW_SRV_ERR_DATABASE_FAILED;
      goto done;
    }
    goto success;
  }
  if (re.review_gen != 0 && re.hidden_review_gen != 0) {
    http_status = 400;
    err_num = NEW_SRV_ERR_NOT_SUPPORTED;
    ERR("both visible and hidden reviews present");
    goto done;
  }

success:;
  ok = 1;
  err_num = 0;
  http_status = 200;

done:;
  phr->json_reply = 1;
  phr->status_code = http_status;
  ns_emit_json_result(fout, phr, ok, err_num, err_id, err_msg, jr);
  if (jr) {
    cJSON_Delete(jr);
  }
  run_review_free(&review);
  run_review_free(&review2);
#undef ERR
}

void
ns_priv_render_markdown(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  cJSON *jr = cJSON_CreateObject();
  int ok = 0;
  int err_num = NEW_SRV_ERR_INV_PARAM;
  const unsigned char *err_msg = NULL;
  int http_status = 400;
  unsigned err_id = random_u32();
  const unsigned char *s;
  struct md_content md = {};
  unsigned char *md_text = NULL;

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  #define ERR(msg, ...) err("%s:%d:%08x:" msg, __PRETTY_FUNCTION__, __LINE__, err_id ,##__VA_ARGS__)

  if (phr->role < USER_ROLE_JUDGE) {
    http_status = 403;
    err_num = NEW_SRV_ERR_PERMISSION_DENIED;
    ERR("no JUDGE role");
    goto done;
  }
  if (hr_cgi_param(phr, "markdown", &s) <= 0 || !*s) {
    ERR("markdown param is not set");
    goto done;
  }
  md_text = utf8_fix_string_dup(s);
  if (markdown_parse_str(md_text, &md) < 0) {
    ERR("invalid markdown");
    goto done;
  }

  cJSON *jres = cJSON_CreateObject();
  cJSON_AddStringToObject(jres, "html", md.data);
  cJSON_AddItemToObject(jr, "result", jres);
  ok = 1;
  err_num = 0;
  http_status = 200;

done:;
  phr->json_reply = 1;
  phr->status_code = http_status;
  ns_emit_json_result(fout, phr, ok, err_num, err_id, err_msg, jr);
  if (jr) {
    cJSON_Delete(jr);
  }
  markdown_free(&md);
  free(md_text);
#undef ERR
}

enum
{
  PA_OP_SKIP = 1,
  PA_OP_REJECT,
  PA_OP_IGNORE,
  PA_OP_OK,
  PA_OP_DISQUALIFY,
  PA_OP_SUMMON,
  PA_OP_REREVIEW,
  PA_OP_CANCEL,
  PA_OP_LAST,
};

void
ns_priv_postapprove_json(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  cJSON *jr = cJSON_CreateObject();
  int ok = 0;
  int err_num = NEW_SRV_ERR_INV_PARAM;
  const unsigned char *err_msg = NULL;
  int http_status = 400;
  unsigned err_id = random_u32();
  const unsigned char *s;
  long long serial_id;
  struct run_review review = {};
  const struct contest_desc *review_cnts = NULL;
  int operation = 0;
  struct run_review_filter filter = { .run_id = -1 };
  unsigned char *approved_text = NULL;

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  #define ERR(msg, ...) err("%s:%d:%08x:" msg, __PRETTY_FUNCTION__, __LINE__, err_id ,##__VA_ARGS__)

  if (opcaps_check(phr->caps, OPCAP_COMMENT_RUN) < 0) {
    http_status = 403;
    err_num = NEW_SRV_ERR_PERMISSION_DENIED;
    ERR("no OPCAP_PREMOD_REVIEW permission");
    goto done;
  }
  if (hr_cgi_param(phr, "serial_id", &s) <= 0 || !s) {
    http_status = 400;
    err_num = NEW_SRV_ERR_INV_PARAM;
    ERR("serial_id unset or binary");
    goto done;
  }
  {
    char *eptr = NULL;
    errno = 0;
    serial_id = strtoll(s, &eptr, 10);
    if (errno || *eptr || eptr == (char*) s || serial_id <= 0) {
      http_status = 400;
      err_num = NEW_SRV_ERR_INV_PARAM;
      ERR("serial_id is invalid");
      goto done;
    }
  }
  hr_cgi_param_int_opt(phr, "operation", &operation, 0);
  if (operation <= 0 || operation > PA_OP_LAST) {
    err_num = NEW_SRV_ERR_INV_PARAM;
    ERR("invalid operation %d", operation);
    goto done;
  }
  uint64_t field_mask = RER_SERIAL_ID | RER_REVIEW_UUID | RER_REVIEW_RESULT | RER_REVIEW_JUDGE_RESULT
    | RER_CONTEST_ID | RER_RUN_ID | RER_GENERATION | RER_STATUS | RER_PURPOSE;
  int r = run_review_fetch_by_serial_id(cs->runlog_state, serial_id, field_mask, &review);
  if (r < 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    ERR("fetch failed");
    goto done;
  }
  if (r == 0) {
    http_status = 404;
    err_num = NEW_SRV_ERR_NO_AFFECTED_ROWS;
    ERR("serial_id == %lld not found", serial_id);
    goto done;
  }
  if (review.status != RERS_WAITING_APPROVAL) {
    err_num = NEW_SRV_ERR_INV_STATUS;
    ERR("serial_id == %lld has invalid status %d", serial_id, review.status);
    goto done;
  }
  if (review.contest_id <= 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    ERR("review %lld contest_id <= 0", serial_id);
    goto done;
  }
  if (contests_get(review.contest_id, &review_cnts) < 0 || !review_cnts) {
    err_num = NEW_SRV_ERR_CNTS_UNAVAILABLE;
    ERR("review %lld failed to get contest %d", serial_id, review.contest_id);
    goto done;
  }
  opcap_t review_caps = 0;
  if (opcaps_find(&review_cnts->capabilities, phr->login, &review_caps) < 0 ||
      opcaps_check(review_caps, OPCAP_COMMENT_RUN) < 0) {
    http_status = 403;
    err_num = NEW_SRV_ERR_PERMISSION_DENIED;
    ERR("no COMMENT_RUN permission in contest %d", review.contest_id);
    goto done;
  }
  if (load_other_contest(phr->config, phr->fw_state, phr->userlist_clnt, review.contest_id) < 0) {
    http_status = 400;
    err_num = NEW_SRV_ERR_CNTS_UNAVAILABLE;
    ERR("failed to load contest %d", review.contest_id);
    goto done;
  }
  struct contest_extra *review_extra = ns_get_contest_extra(review_cnts, phr->config);
  ASSERT(review_extra);
  serve_state_t review_cs = review_extra->serve_state;
  if (!review_cs) {
    err_num = NEW_SRV_ERR_CNTS_UNAVAILABLE;
    ERR("failed to load contest %d", review.contest_id);
    goto done;
  }

  // work with review_cnts, review_cs
  if (review.run_id < 0 || review.run_id >= run_get_total(review_cs->runlog_state)) {
    err_num = NEW_SRV_ERR_CNTS_UNAVAILABLE;
    ERR("contest %d:run %d:invalid run_id", review.contest_id, review.run_id);
    goto done;
  }
  struct run_entry re = {};
  if (run_get_entry(review_cs->runlog_state, review.run_id, &re) < 0) {
    err_num = NEW_SRV_ERR_CNTS_UNAVAILABLE;
    ERR("contest %d:run %d:failed to get run", review.contest_id, review.run_id);
    goto done;
  }
  if (re.status == RUN_EMPTY || re.status == RUN_VIRTUAL_START || re.status == RUN_VIRTUAL_STOP) {
    http_status = 400;
    err_num = NEW_SRV_ERR_INV_CONTEST_ID;
    ERR("invalid status for run_id %d: %d", review.run_id, re.status);
    goto done;
  }
  if (operation == PA_OP_SKIP) {
    goto success;
  }

  _Bool need_update_review_status = 0;
  _Bool need_update_hidden_review_status = 0;
  if (review.purpose == RERP_REVIEW || review.purpose == RERP_HELP) {
    if (re.hidden_review_gen == review.generation) {
      http_status = 500;
      err_num = NEW_SRV_ERR_INTERNAL;
      ERR("review purpose mismatches run_entry review generation");
      goto done;
    }
    if (re.review_gen == review.generation) {
      if (re.review_status != RERS_WAITING_APPROVAL) {
        http_status = 500;
        err_num = NEW_SRV_ERR_INTERNAL;
        ERR("review purpose mismatches run_entry review status");
        goto done;
      }
      need_update_review_status = 1;
    }
  } else if (review.purpose == RERP_JUDGE_HELP) {
    if (re.review_gen == review.generation) {
      http_status = 500;
      err_num = NEW_SRV_ERR_INTERNAL;
      ERR("review purpose mismatches run_entry review generation");
      goto done;
    }
    if (re.hidden_review_gen == review.generation) {
      if (re.hidden_review_status != RERS_WAITING_APPROVAL) {
        http_status = 500;
        err_num = NEW_SRV_ERR_INTERNAL;
        ERR("review purpose mismatches run_entry review status");
        goto done;
      }
      need_update_hidden_review_status = 1;
    }
  } else {
    abort();
  }

  if (operation == PA_OP_CANCEL || operation == PA_OP_REREVIEW) {
    filter.serial_id = serial_id;
    filter.include_status_mask = 1U << RERS_WAITING_APPROVAL;
    review.status = RERS_CANCELED;
    review.last_update_time = -2;
    if (run_review_update(review_cs->runlog_state, &review, RER_STATUS | RER_LAST_UPDATE_TIME,  &filter) < 0) {
      http_status = 500;
      err_num = NEW_SRV_ERR_DATABASE_FAILED;
      goto done;
    }
    int r = 0;
    if (need_update_review_status) {
      r = run_change_review_status(review_cs->runlog_state, review.run_id, RERS_CANCELED, re.review_gen, re.hidden_review_status, re.hidden_review_gen, NULL);
    } else if (need_update_hidden_review_status) {
      r = run_change_review_status(review_cs->runlog_state, review.run_id, re.review_status, re.review_gen, RERS_CANCELED, re.hidden_review_gen, NULL);
    }
    if (r < 0) {
      http_status = 500;
      err_num = NEW_SRV_ERR_RUNLOG_UPDATE_FAILED;
      ERR("run_change_review_status failed");
      goto done;
    }
    if (operation == PA_OP_CANCEL) {
      goto success;
    }
    if (!need_update_review_status && !need_update_hidden_review_status) {
      goto success;
    }
    if (run_get_entry(review_cs->runlog_state, review.run_id, &re) < 0) {
      http_status = 500;
      err_num = NEW_SRV_ERR_INV_RUN_ID;
      ERR("run_get_entry failed");
      goto done;
    }
    r = do_request_review(phr, review_cnts, review_cs, review.run_id, &re, need_update_review_status, 0, 0, err_id);
    if (r < 0) {
      err_num = -r;
      goto done;
    }
    goto success;
  }

  int new_run_status = 0;
  switch (operation) {
  case PA_OP_REJECT:     new_run_status = RUN_REJECTED; break;
  case PA_OP_IGNORE:     new_run_status = RUN_IGNORED; break;
  case PA_OP_OK:         new_run_status = RUN_OK; break;
  case PA_OP_DISQUALIFY: new_run_status = RUN_DISQUALIFIED; break;
  case PA_OP_SUMMON:     new_run_status = RUN_SUMMONED; break;
  default: abort();
  }

  s = NULL;
  r = hr_cgi_param(phr, "approved_text", &s);
  if (r < 0) {
    http_status = 400;
    err_num = NEW_SRV_ERR_INV_CONTEST_ID;
    ERR("approved_text is binary");
    goto done;
  }
  int review_approved_as_is = 0;
  int status_approved_as_is = 0;
  if (!r || !s || !*s) {
    approved_text = utf8_fix_string_dup(review.review_result);
    review_approved_as_is = 1;
  } else {
    approved_text = utf8_fix_string_dup(s);
    unsigned char *orig_text = utf8_fix_string_dup(review.review_result);
    if (!strcmp(approved_text, orig_text)) { // FIXME: ignore whitespace?
      review_approved_as_is = 1;
      free(approved_text); approved_text = orig_text; orig_text = NULL;
    }
    free(orig_text);
  }

  filter.serial_id = serial_id;
  filter.include_status_mask = 1U << RERS_WAITING_APPROVAL;
  review.status = RERS_COMPLETE;
  review.last_update_time = -2;
  review.approval_time = -2;
  review.approver_user_id = phr->user_id;
  review.approved_text = approved_text; approved_text = NULL;
  review.review_approved_as_is = review_approved_as_is;
  review.status_approved_as_is = status_approved_as_is;
  field_mask = RER_STATUS | RER_LAST_UPDATE_TIME | RER_APPROVAL_TIME |
    RER_APPROVER_USER_ID | RER_APPROVED_TEXT |
    RER_REVIEW_APPROVED_AS_IS | RER_STATUS_APPROVED_AS_IS;
  if (run_review_update(review_cs->runlog_state, &review, field_mask,  &filter) < 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_DATABASE_FAILED;
    goto done;
  }

  r = 0;
  if (need_update_review_status) {
    r = run_change_review_status(review_cs->runlog_state, review.run_id, RERS_COMPLETE, re.review_gen, re.hidden_review_status, re.hidden_review_gen, NULL);
  } else if (need_update_hidden_review_status) {
    r = run_change_review_status(review_cs->runlog_state, review.run_id, re.review_status, re.review_gen, RERS_COMPLETE, re.hidden_review_gen, NULL);
  }
  if (r < 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_RUNLOG_UPDATE_FAILED;
    ERR("run_change_review_status failed");
    goto done;
  }
  if (!need_update_review_status) {
    goto success;
  }
  if (re.status != RUN_PENDING_REVIEW) {
    goto success;
  }

  if (add_clar_record(phr, review_cs, review.run_id, &re, new_run_status) < 0) {
    http_status = 500;
    err_num = NEW_SRV_ERR_CLARLOG_UPDATE_FAILED;
    ERR("add_clar_record failed");
    goto done;
  }
  if (new_run_status != RUN_OK) {
    if (run_change_status_4(review_cs->runlog_state, review.run_id, new_run_status, &re) < 0) {
      http_status = 500;
      err_num = NEW_SRV_ERR_RUNLOG_UPDATE_FAILED;
      ERR("run_change_status_4 failed");
      goto done;
    }
    serve_notify_run_update(phr->config, review_cs, &re);
  } else {
    struct section_problem_data *prob = 0;
    int full_score = 0;
    int user_status = 0, user_score = 0;
    if (re.prob_id > 0 && re.prob_id <= review_cs->max_prob) prob = review_cs->probs[re.prob_id];
    if (prob) full_score = prob->full_score;
    if (review_cs->global->separate_user_score > 0 && re.is_saved) {
      user_status = RUN_OK;
      user_score = -1;
      if (prob) user_score = prob->full_user_score;
      if (prob && user_score < 0) user_score = prob->full_score;
      if (user_score < 0) user_score = 0;
    }
    r = run_change_status_3(review_cs->runlog_state, review.run_id, RUN_OK,
      re.test, re.passed_mode, full_score, 0,
      re.saved_score, user_status, re.saved_test, user_score, re.verdict_bits, -2, NULL, &re);
    if (r < 0) {
      http_status = 500;
      err_num = NEW_SRV_ERR_RUNLOG_UPDATE_FAILED;
      ERR("run_change_status_3 failed");
      goto done;
    }
    serve_notify_run_update(phr->config, review_cs, &re);
  }

  const unsigned char *audit_cmd = NULL;
  switch (new_run_status) {
  case RUN_OK:
    audit_cmd = "external-comment-run-ok";
    break;
  case RUN_REJECTED:
    audit_cmd = "external-comment-run-reject";
    break;
  case RUN_IGNORED:
    audit_cmd = "external-comment-run-ignore";
    break;
  case RUN_DISQUALIFIED:
    audit_cmd = "external-comment-run-disqualify";
    break;
  case RUN_SUMMONED:
    audit_cmd = "external-comment-run-summon";
    break;
  default: abort();
  }
  serve_audit_log(review_cs, review.run_id, &re, phr->user_id, &phr->ip, phr->ssl_flag, audit_cmd, "ok", new_run_status, NULL);
  if (review_cs->global->notify_clar_reply) {
    send_email_notification(phr->config, review_cnts, review_cs, review.run_id, re.user_id, new_run_status);
  }
  if (review_cnts->enable_user_telegram > 0 && !re.is_hidden) {
    serve_telegram_user_run_reviewed(phr->config, review_cnts, review_cs, re.user_id, review.run_id, new_run_status);
  }

success:;
  ok = 1;
  err_num = 0;
  http_status = 200;

done:;
  phr->json_reply = 1;
  phr->status_code = http_status;
  ns_emit_json_result(fout, phr, ok, err_num, err_id, err_msg, jr);
  if (jr) {
    cJSON_Delete(jr);
  }
  run_review_free(&review);
  free(approved_text);
#undef ERR
}

#define BITS_PER_LONG (8*sizeof(unsigned long))
#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

int
ns_priv_review_displayed(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  unsigned long *mask = 0;
  size_t mask_size;
  int retval = 0;
  int review_mode = 0;
  unsigned total_runs = 0;
  unsigned err_id = random_u32();
  __attribute__((unused)) int _;

  if (ns_parse_run_mask(phr, 0, 0, &mask_size, &mask) < 0) FAIL(NEW_SRV_ERR_INV_PARAM);
  if (!mask_size) FAIL(NEW_SRV_ERR_NO_RUNS_TO_REJUDGE);
  hr_cgi_param_int_opt(phr, "review_mode", &review_mode, 0);
  if (review_mode <= 0 || review_mode > 8) FAIL(NEW_SRV_ERR_INV_PARAM);

/*
  <option value="1">Request user-visible review, skip if already reviewed</option>
  <option value="2">Request user-visible review, including the runs already reviewed</option>
  <option value="3">Request hidden review, skip if already reviewed</option>
  <option value="4">Request hidden review, including the runs already reviewed</option>
  <option value="5">Cancel user-visible reviews</option>
  <option value="6">Cancel hidden reviews</option>
  <option value="7">Clear user-visible reviews (DANGEROUS)</option>
  <option value="8">Clear hidden reviews (DANGEROUS)</option>
*/
  if (review_mode == 1 || review_mode == 3) {
    if (opcaps_check(phr->caps, OPCAP_COMMENT_RUN) < 0)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  } else {
    if (opcaps_check(phr->caps, OPCAP_EDIT_RUN) < 0)
      FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }

  info("audit:%s:%d:%d", phr->action_str, phr->user_id, phr->contest_id);

  total_runs = run_get_total(cs->runlog_state);
  if (total_runs > mask_size * BITS_PER_LONG) {
    total_runs = mask_size * BITS_PER_LONG;
  }

  int unprivileged_mode = (review_mode == 1 || review_mode == 2);
  int force_on_incomplete_mode = (review_mode == 2 || review_mode == 4);
  int skip_existing_mode = (review_mode == 1 || review_mode == 3);

  for (unsigned run_id = 0; run_id < total_runs; ++run_id) {
    if ((mask[run_id / BITS_PER_LONG] & (1UL << (run_id % BITS_PER_LONG))) == 0)
      continue;
    struct run_entry re;
    if (run_get_entry(cs->runlog_state, run_id, &re) < 0)
      continue;
    if (review_mode == 5) {
      if (re.review_gen && (re.review_status != RERS_FAILED && re.review_status != RERS_CANCELED)) {
        struct run_review newrr =
        {
          .status = RERS_CANCELED,
        };
        struct run_review_filter rrf =
        {
          .contest_id = cnts->id,
          .run_id = run_id,
          .generation = re.review_gen,
        };
        _ = run_review_update(cs->runlog_state, &newrr, RER_STATUS, &rrf);
        _ = run_change_review_status(cs->runlog_state, run_id, RERS_CANCELED, re.review_gen, re.hidden_review_status, re.hidden_review_gen, NULL);
      }
      continue;
    }
    if (review_mode == 6) {
      if (re.hidden_review_gen && (re.hidden_review_status != RERS_FAILED && re.hidden_review_status != RERS_CANCELED)) {
        struct run_review newrr =
        {
          .status = RERS_CANCELED,
        };
        struct run_review_filter rrf =
        {
          .contest_id = cnts->id,
          .run_id = run_id,
          .generation = re.hidden_review_gen,
        };
        _ = run_review_update(cs->runlog_state, &newrr, RER_STATUS, &rrf);
        _ = run_change_review_status(cs->runlog_state, run_id, re.review_status, re.review_gen, RERS_CANCELED, re.hidden_review_gen, NULL);
      }
      continue;
    }
    if (review_mode == 7) {
      // clear user-visible review
      if (re.review_gen) {
        _ = run_change_review_status(cs->runlog_state, run_id, 0, 0, re.hidden_review_status, re.hidden_review_gen, NULL);
      }
      continue;
    }
    if (review_mode == 8) {
      // clear hidden review
      if (re.hidden_review_gen) {
        _ = run_change_review_status(cs->runlog_state, run_id, re.review_status, re.review_gen, 0, 0, NULL);
      }
      continue;
    }
    _ = do_request_review(phr, cnts, cs, run_id, &re, unprivileged_mode, skip_existing_mode, force_on_incomplete_mode, err_id);
  }

  retval = 0;

cleanup:;
  xfree(mask);
  return retval;
}
