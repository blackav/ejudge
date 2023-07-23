/* -*- c -*- */

/* Copyright (C) 2005-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ej_types.h"
#include "ejudge/ej_limits.h"
#include "ejudge/ej_byteorder.h"
#include "ejudge/compile_packet.h"
#include "ejudge/compile_packet_priv.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/prepare.h"
#include "ejudge/runlog.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/integral.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define FAIL_IF(c) if (c)do { errcode = __LINE__; goto failed; } while (0)

int
compile_request_packet_write(
        const struct compile_request_packet *in_data,
        size_t *p_out_size,
        void **p_out_data)
{
  int errcode, i, out_size, env_num, sc_env_num;
  rint32_t *str_lens, *str_lens_out, *sc_str_lens, *sc_str_lens_out;
  struct compile_request_bin_packet *out_data = 0;
  unsigned char *out_ptr;
  int style_checker_len = 0;
  int src_sfx_len = 0;

  if (in_data->style_checker) {
    style_checker_len = strlen(in_data->style_checker);
  }
  if (in_data->src_sfx) {
    src_sfx_len = strlen(in_data->src_sfx);
  }

  int lang_short_name_len = 0;
  if (in_data->lang_short_name) {
    lang_short_name_len = strlen(in_data->lang_short_name);
  }
  int header_pat_len = 0;
  if (in_data->header_pat) {
    header_pat_len = strlen(in_data->header_pat);
  }
  int footer_pat_len = 0;
  if (in_data->footer_pat) {
    footer_pat_len = strlen(in_data->footer_pat);
  }
  int header_dir_len = 0;
  if (in_data->header_dir) {
    header_dir_len = strlen(in_data->header_dir);
  }
  int compiler_env_pat_len = 0;
  if (in_data->compiler_env_pat) {
    compiler_env_pat_len = strlen(in_data->compiler_env_pat);
  }
  int user_login_len = 0;
  if (in_data->user_login) {
    user_login_len = strlen(in_data->user_login);
  }
  int exam_cypher_len = 0;
  if (in_data->exam_cypher) {
    exam_cypher_len = strlen(in_data->exam_cypher);
  }
  int contest_server_id_len = 0;
  if (in_data->contest_server_id) {
    contest_server_id_len = strlen(in_data->contest_server_id);
  }
  int container_options_len = 0;
  if (in_data->container_options) {
    container_options_len = strlen(in_data->container_options);
  }
  int vcs_compile_cmd_len = 0;
  if (in_data->vcs_compile_cmd) {
    vcs_compile_cmd_len = strlen(in_data->vcs_compile_cmd);
  }
  int compile_cmd_len = 0;
  if (in_data->compile_cmd) {
    compile_cmd_len = strlen(in_data->compile_cmd);
  }
  int extra_src_dir_len = 0;
  if (in_data->extra_src_dir) {
    extra_src_dir_len = strlen(in_data->extra_src_dir);
  }

  FAIL_IF(in_data->judge_id < 0 || in_data->judge_id > EJ_MAX_JUDGE_ID);
  FAIL_IF(in_data->contest_id < 0 || in_data->contest_id > EJ_MAX_CONTEST_ID);
  FAIL_IF(in_data->run_id < 0 || in_data->run_id > EJ_MAX_RUN_ID);
  FAIL_IF(in_data->lang_id < 0 || in_data->lang_id > EJ_MAX_LANG_ID);
  FAIL_IF(in_data->locale_id < 0 || in_data->locale_id > EJ_MAX_LOCALE_ID);
  FAIL_IF(in_data->output_only < 0 || in_data->output_only > 1);
  FAIL_IF(in_data->style_check_only < 0 || in_data->style_check_only > 1);
  FAIL_IF(in_data->multi_header < 0 || in_data->multi_header > 1);
  FAIL_IF(in_data->lang_header < 0 || in_data->lang_header > 1);
  FAIL_IF(in_data->ts1_us < 0 || in_data->ts1_us > USEC_MAX);
  FAIL_IF(style_checker_len < 0 || style_checker_len > PATH_MAX);
  FAIL_IF(src_sfx_len < 0 || src_sfx_len > PATH_MAX);
  FAIL_IF(lang_short_name_len < 0 || lang_short_name_len > PATH_MAX);
  FAIL_IF(header_pat_len < 0 || header_pat_len > PATH_MAX);
  FAIL_IF(footer_pat_len < 0 || footer_pat_len > PATH_MAX);
  FAIL_IF(header_dir_len < 0 || header_dir_len > PATH_MAX);
  FAIL_IF(compiler_env_pat_len < 0 || compiler_env_pat_len > PATH_MAX);
  FAIL_IF(user_login_len < 0 || user_login_len > PATH_MAX);
  FAIL_IF(exam_cypher_len < 0 || exam_cypher_len > PATH_MAX);
  FAIL_IF(contest_server_id_len < 0 || contest_server_id_len > PATH_MAX);
  FAIL_IF(container_options_len < 0 || container_options_len > PATH_MAX);
  FAIL_IF(vcs_compile_cmd_len < 0 || vcs_compile_cmd_len > PATH_MAX);
  FAIL_IF(compile_cmd_len < 0 || compile_cmd_len > PATH_MAX);
  FAIL_IF(extra_src_dir_len < 0 || extra_src_dir_len > PATH_MAX);
  FAIL_IF(in_data->run_block_len < 0 || in_data->run_block_len > EJ_MAX_COMPILE_RUN_BLOCK_LEN);
  env_num = in_data->env_num;
  if (env_num == -1) {
    env_num = 0;
    if (in_data->env_vars) {
      for (i = 0; in_data->env_vars[i]; i++);
      env_num = i;
    }
  }
  FAIL_IF(env_num < 0 || env_num > EJ_MAX_COMPILE_ENV_NUM);
  XALLOCA(str_lens, env_num);
  XALLOCA(str_lens_out, env_num);
  for (i = 0; i < env_num; i++) {
    str_lens[i] = strlen(in_data->env_vars[i]);
    FAIL_IF(str_lens[i] < 0 || str_lens[i] > EJ_MAX_COMPILE_ENV_LEN);
    str_lens_out[i] = cvt_host_to_bin_32(str_lens[i]);
  }

  sc_env_num = in_data->sc_env_num;
  if (sc_env_num == -1) {
    sc_env_num = 0;
    if (in_data->sc_env_vars) {
      for (i = 0; in_data->sc_env_vars[i]; ++i);
      sc_env_num = i;
    }
  }
  FAIL_IF(sc_env_num < 0 || sc_env_num > EJ_MAX_COMPILE_ENV_NUM);
  XALLOCA(sc_str_lens, sc_env_num);
  XALLOCA(sc_str_lens_out, sc_env_num);
  for (i = 0; i < sc_env_num; ++i) {
    sc_str_lens[i] = strlen(in_data->sc_env_vars[i]);
    FAIL_IF(sc_str_lens[i] < 0 || sc_str_lens[i] > EJ_MAX_COMPILE_ENV_LEN);
    sc_str_lens_out[i] = cvt_host_to_bin_32(sc_str_lens[i]);
  }

  out_size = sizeof(*out_data);
  if (style_checker_len > 0) {
    out_size += pkt_bin_align(style_checker_len);
  }
  if (src_sfx_len > 0) {
    out_size += pkt_bin_align(src_sfx_len);
  }
  if (lang_short_name_len > 0) {
    out_size += pkt_bin_align(lang_short_name_len);
  }
  if (header_pat_len > 0) {
    out_size += pkt_bin_align(header_pat_len);
  }
  if (footer_pat_len > 0) {
    out_size += pkt_bin_align(footer_pat_len);
  }
  if (header_dir_len > 0) {
    out_size += pkt_bin_align(header_dir_len);
  }
  if (compiler_env_pat_len > 0) {
    out_size += pkt_bin_align(compiler_env_pat_len);
  }
  if (user_login_len > 0) {
    out_size += pkt_bin_align(user_login_len);
  }
  if (exam_cypher_len > 0) {
    out_size += pkt_bin_align(exam_cypher_len);
  }
  if (contest_server_id_len > 0) {
    out_size += pkt_bin_align(contest_server_id_len);
  }
  if (container_options_len > 0) {
    out_size += pkt_bin_align(container_options_len);
  }
  if (vcs_compile_cmd_len > 0) {
    out_size += pkt_bin_align(vcs_compile_cmd_len);
  }
  if (compile_cmd_len > 0) {
    out_size += pkt_bin_align(compile_cmd_len);
  }
  if (extra_src_dir_len > 0) {
    out_size += pkt_bin_align(extra_src_dir_len);
  }
  out_size += pkt_bin_align(in_data->run_block_len);
  out_size += pkt_bin_align(env_num * sizeof(rint32_t));
  for (i = 0; i < env_num; i++) {
    out_size += str_lens[i];
  }
  out_size = pkt_bin_align(out_size);
  out_size += pkt_bin_align(sc_env_num * sizeof(rint32_t));
  for (i = 0; i < sc_env_num; ++i) {
    out_size += sc_str_lens[i];
  }
  out_size = pkt_bin_align(out_size);
  FAIL_IF(out_size < sizeof(*out_data)||out_size > EJ_MAX_COMPILE_PACKET_SIZE);

  out_data = xcalloc(1, out_size);
  out_ptr = (unsigned char *) out_data + sizeof(*out_data);

  out_data->packet_len = cvt_host_to_bin_32(out_size);
  out_data->version = cvt_host_to_bin_32(EJ_COMPILE_PACKET_VERSION);
  out_data->judge_id = cvt_host_to_bin_32(in_data->judge_id);
  out_data->contest_id = cvt_host_to_bin_32(in_data->contest_id);
  out_data->submit_id = cvt_host_to_bin_64(in_data->submit_id);
  out_data->run_id = cvt_host_to_bin_32(in_data->run_id);
  out_data->lang_id = cvt_host_to_bin_32(in_data->lang_id);
  out_data->locale_id = cvt_host_to_bin_32(in_data->locale_id);
  out_data->output_only = cvt_host_to_bin_32(in_data->output_only);
  out_data->style_check_only = cvt_host_to_bin_32(in_data->style_check_only);
  out_data->ts1 = cvt_host_to_bin_32(in_data->ts1);
  out_data->ts1_us = cvt_host_to_bin_32(in_data->ts1_us);
  out_data->max_vm_size = cvt_host_to_bin_64(in_data->max_vm_size);
  out_data->max_stack_size = cvt_host_to_bin_64(in_data->max_stack_size);
  out_data->max_file_size = cvt_host_to_bin_64(in_data->max_file_size);
  out_data->max_rss_size = cvt_host_to_bin_64(in_data->max_rss_size);
  out_data->use_container = cvt_host_to_bin_32(in_data->use_container);
  out_data->vcs_mode = cvt_host_to_bin_32(in_data->vcs_mode);
  out_data->not_ok_is_cf = cvt_host_to_bin_32(in_data->not_ok_is_cf);
  out_data->preserve_numbers = cvt_host_to_bin_32(in_data->preserve_numbers);
  out_data->enable_remote_cache = cvt_host_to_bin_32(in_data->enable_remote_cache);
  out_data->use_uuid = cvt_host_to_bin_32(in_data->use_uuid);
  out_data->uuid = in_data->uuid;
  out_data->judge_uuid = in_data->judge_uuid;
  /*
  out_data->uuid.v[0] = cvt_host_to_bin_32(in_data->uuid.v[0]);
  out_data->uuid.v[1] = cvt_host_to_bin_32(in_data->uuid.v[1]);
  out_data->uuid.v[2] = cvt_host_to_bin_32(in_data->uuid.v[2]);
  out_data->uuid.v[3] = cvt_host_to_bin_32(in_data->uuid.v[3]);
  */
  out_data->multi_header = cvt_host_to_bin_32(in_data->multi_header);
  out_data->lang_header = cvt_host_to_bin_32(in_data->lang_header);
  out_data->style_checker_len = cvt_host_to_bin_32(style_checker_len);
  out_data->src_sfx_len = cvt_host_to_bin_32(src_sfx_len);
  out_data->run_block_len = cvt_host_to_bin_32(in_data->run_block_len);
  out_data->lang_short_name_len = cvt_host_to_bin_32(lang_short_name_len);
  out_data->header_pat_len = cvt_host_to_bin_32(header_pat_len);
  out_data->footer_pat_len = cvt_host_to_bin_32(footer_pat_len);
  out_data->header_dir_len = cvt_host_to_bin_32(header_dir_len);
  out_data->compiler_env_pat_len = cvt_host_to_bin_32(compiler_env_pat_len);
  out_data->user_login_len = cvt_host_to_bin_32(user_login_len);
  out_data->exam_cypher_len = cvt_host_to_bin_32(exam_cypher_len);
  out_data->contest_server_id_len = cvt_host_to_bin_32(contest_server_id_len);
  out_data->container_options_len = cvt_host_to_bin_32(container_options_len);
  out_data->vcs_compile_cmd_len = cvt_host_to_bin_32(vcs_compile_cmd_len);
  out_data->compile_cmd_len = cvt_host_to_bin_32(compile_cmd_len);
  out_data->extra_src_dir_len = cvt_host_to_bin_32(extra_src_dir_len);
  out_data->env_num = cvt_host_to_bin_32(env_num);
  out_data->sc_env_num = cvt_host_to_bin_32(sc_env_num);
  out_data->user_id = cvt_host_to_bin_32(in_data->user_id);
  if (style_checker_len > 0) {
    memcpy(out_ptr, in_data->style_checker, style_checker_len);
    out_ptr += style_checker_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (src_sfx_len > 0) {
    memcpy(out_ptr, in_data->src_sfx, src_sfx_len);
    out_ptr += src_sfx_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (in_data->run_block_len) {
    memcpy(out_ptr, in_data->run_block, in_data->run_block_len);
    out_ptr += in_data->run_block_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (lang_short_name_len > 0) {
    memcpy(out_ptr, in_data->lang_short_name, lang_short_name_len);
    out_ptr += lang_short_name_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (header_pat_len > 0) {
    memcpy(out_ptr, in_data->header_pat, header_pat_len);
    out_ptr += header_pat_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (footer_pat_len > 0) {
    memcpy(out_ptr, in_data->footer_pat, footer_pat_len);
    out_ptr += footer_pat_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (header_dir_len > 0) {
    memcpy(out_ptr, in_data->header_dir, header_dir_len);
    out_ptr += header_dir_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (compiler_env_pat_len > 0) {
    memcpy(out_ptr, in_data->compiler_env_pat, compiler_env_pat_len);
    out_ptr += compiler_env_pat_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (user_login_len > 0) {
    memcpy(out_ptr, in_data->user_login, user_login_len);
    out_ptr += user_login_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (exam_cypher_len > 0) {
    memcpy(out_ptr, in_data->exam_cypher, exam_cypher_len);
    out_ptr += exam_cypher_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (contest_server_id_len > 0) {
    memcpy(out_ptr, in_data->contest_server_id, contest_server_id_len);
    out_ptr += contest_server_id_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (container_options_len > 0) {
    memcpy(out_ptr, in_data->container_options, container_options_len);
    out_ptr += container_options_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (vcs_compile_cmd_len > 0) {
    memcpy(out_ptr, in_data->vcs_compile_cmd, vcs_compile_cmd_len);
    out_ptr += vcs_compile_cmd_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (compile_cmd_len > 0) {
    memcpy(out_ptr, in_data->compile_cmd, compile_cmd_len);
    out_ptr += compile_cmd_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (extra_src_dir_len > 0) {
    memcpy(out_ptr, in_data->extra_src_dir, extra_src_dir_len);
    out_ptr += extra_src_dir_len;
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (env_num) {
    memcpy(out_ptr, str_lens_out, env_num * sizeof(rint32_t));
    out_ptr += env_num * sizeof(rint32_t);
    pkt_bin_align_addr(out_ptr, out_data);
    for (i = 0; i < env_num; i++) {
      memcpy(out_ptr, in_data->env_vars[i], str_lens[i]);
      out_ptr += str_lens[i];
    }
    pkt_bin_align_addr(out_ptr, out_data);
  }
  if (sc_env_num) {
    memcpy(out_ptr, sc_str_lens_out, sc_env_num * sizeof(rint32_t));
    out_ptr += sc_env_num * sizeof(rint32_t);
    pkt_bin_align_addr(out_ptr, out_data);
    for (i = 0; i < sc_env_num; i++) {
      memcpy(out_ptr, in_data->sc_env_vars[i], sc_str_lens[i]);
      out_ptr += sc_str_lens[i];
    }
    pkt_bin_align_addr(out_ptr, out_data);
  }

  *p_out_size = (size_t) out_size;
  *p_out_data = out_data;
  return 0;

 failed:
  err("compile_request_packet_write: error %s, %d", "$Revision$", errcode);
  xfree(out_data);
  return -1;
}
