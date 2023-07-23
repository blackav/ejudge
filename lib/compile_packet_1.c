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

#if defined __GNUC__ && defined __MINGW32__
#include <malloc.h>
#endif

#define FAIL_IF(c) if (c)do { errcode = __LINE__; goto failed; } while (0)

int
compile_request_packet_read(
        size_t in_size,
        const void *in_data,
        struct compile_request_packet **p_out_data)
{
  const struct compile_request_bin_packet *pin = in_data;
  const unsigned char *pin_ptr, *end_ptr;
  struct compile_request_packet *pout = 0;
  int pkt_size, pkt_version, errcode = 0, i;
  rint32_t *str_lens;
  int style_checker_len = 0;
  int src_sfx_len = 0;

  FAIL_IF(in_size < sizeof(struct compile_request_bin_packet));
  pkt_size = cvt_bin_to_host_32(pin->packet_len);
  FAIL_IF(pkt_size != in_size);
  FAIL_IF(pkt_size < 0 || pkt_size > EJ_MAX_COMPILE_PACKET_SIZE);
  /* unaligned packet size */
  FAIL_IF((pkt_size & 0xf));
  pkt_version = cvt_bin_to_host_32(pin->version);
  FAIL_IF(pkt_version != EJ_COMPILE_PACKET_VERSION);
  XCALLOC(pout, 1);
  pout->judge_id = cvt_bin_to_host_32(pin->judge_id);
  FAIL_IF(pout->judge_id < 0 || pout->judge_id > EJ_MAX_JUDGE_ID);
  pout->contest_id = cvt_bin_to_host_32(pin->contest_id);
  FAIL_IF(pout->contest_id < 0 || pout->contest_id > EJ_MAX_CONTEST_ID);

  /* from now on the contest id is available */
  pout->submit_id = cvt_bin_to_host_64(pin->submit_id);
  pout->run_id = cvt_bin_to_host_32(pin->run_id);
  FAIL_IF(pout->run_id < 0 || pout->run_id > EJ_MAX_RUN_ID);
  pout->lang_id = cvt_bin_to_host_32(pin->lang_id);
  if (pout->contest_id > 0) {
    FAIL_IF(pout->lang_id < 0);
  }
  pout->locale_id = cvt_bin_to_host_32(pin->locale_id);
  FAIL_IF(pout->locale_id < 0 || pout->locale_id > EJ_MAX_LOCALE_ID);
  pout->output_only = cvt_bin_to_host_32(pin->output_only);
  FAIL_IF(pout->output_only < 0 || pout->output_only > 1);
  pout->style_check_only = cvt_bin_to_host_32(pin->style_check_only);
  FAIL_IF(pout->style_check_only < 0 || pout->style_check_only > 1);
  pout->ts1 = cvt_bin_to_host_32(pin->ts1);
  pout->ts1_us = cvt_bin_to_host_32(pin->ts1_us);
  FAIL_IF(pout->ts1_us < 0 || pout->ts1_us > USEC_MAX);

  pout->user_id = cvt_bin_to_host_32(pin->user_id);
  if (pout->user_id > 0) {
    FAIL_IF(pout->user_id < 0);
  }

  pout->max_vm_size = cvt_bin_to_host_64(pin->max_vm_size);
  pout->max_stack_size = cvt_bin_to_host_64(pin->max_stack_size);
  pout->max_file_size = cvt_bin_to_host_64(pin->max_file_size);
  pout->max_rss_size = cvt_bin_to_host_64(pin->max_rss_size);

  pout->use_uuid = cvt_bin_to_host_32(pin->use_uuid);
  // FIXME: convert byte order?
  pout->uuid = pin->uuid;
  pout->judge_uuid = pin->judge_uuid;
  /*
  pout->uuid.v[0] = cvt_bin_to_host_32(pin->uuid.v[0]);
  pout->uuid.v[1] = cvt_bin_to_host_32(pin->uuid.v[1]);
  pout->uuid.v[2] = cvt_bin_to_host_32(pin->uuid.v[2]);
  pout->uuid.v[3] = cvt_bin_to_host_32(pin->uuid.v[3]);
  */

  pout->use_container = cvt_bin_to_host_32(pin->use_container);
  pout->vcs_mode = cvt_bin_to_host_32(pin->vcs_mode);
  pout->not_ok_is_cf = cvt_bin_to_host_32(pin->not_ok_is_cf);
  pout->preserve_numbers = cvt_bin_to_host_32(pin->preserve_numbers);
  pout->enable_remote_cache = cvt_bin_to_host_32(pin->enable_remote_cache);

  pout->multi_header = cvt_bin_to_host_32(pin->multi_header);
  FAIL_IF(pout->multi_header < 0 || pout->multi_header > 1);
  pout->lang_header = cvt_bin_to_host_32(pin->lang_header);
  FAIL_IF(pout->lang_header < 0 || pout->lang_header > 1);

  /* extract the additional data */
  // set up the additional data pointer
  pin_ptr = (const unsigned char*) in_data + sizeof(*pin);
  // set up the packet end pointer
  end_ptr = (const unsigned char*) in_data + pkt_size;

  pout->style_checker = 0;
  style_checker_len = cvt_bin_to_host_32(pin->style_checker_len);
  FAIL_IF(style_checker_len < 0 || style_checker_len > PATH_MAX);
  FAIL_IF(pin_ptr + style_checker_len > end_ptr);
  if (style_checker_len > 0) {
    pout->style_checker = (unsigned char*) xmalloc(style_checker_len + 1);
    memcpy(pout->style_checker, pin_ptr, style_checker_len);
    pout->style_checker[style_checker_len] = 0;
    pin_ptr += pkt_bin_align(style_checker_len);
  }

  pout->src_sfx = 0;
  src_sfx_len = cvt_bin_to_host_32(pin->src_sfx_len);
  FAIL_IF(src_sfx_len < 0 || src_sfx_len > PATH_MAX);
  FAIL_IF(pin_ptr + src_sfx_len > end_ptr);
  if (src_sfx_len > 0) {
    pout->src_sfx = (unsigned char*) xmalloc(src_sfx_len + 1);
    memcpy(pout->src_sfx, pin_ptr, src_sfx_len);
    pout->src_sfx[src_sfx_len] = 0;
    pin_ptr += pkt_bin_align(src_sfx_len);
  }

  pout->run_block_len = cvt_bin_to_host_32(pin->run_block_len);
  FAIL_IF(pout->run_block_len < 0 || pout->run_block_len > EJ_MAX_COMPILE_RUN_BLOCK_LEN);
  FAIL_IF(pin_ptr + pout->run_block_len > end_ptr);
  if (pout->run_block_len > 0) {
    pout->run_block = xmalloc(pout->run_block_len);
    memcpy(pout->run_block, pin_ptr, pout->run_block_len);
    pin_ptr += pkt_bin_align(pout->run_block_len);
  }

  //unsigned char *lang_short_name; // additional suffix for multi-header/footer
  pout->lang_short_name = NULL;
  int lang_short_name_len = cvt_bin_to_host_32(pin->lang_short_name_len);
  FAIL_IF(lang_short_name_len < 0 || lang_short_name_len > PATH_MAX);
  FAIL_IF(pin_ptr + lang_short_name_len > end_ptr);
  if (lang_short_name_len > 0) {
    pout->lang_short_name = xmalloc(lang_short_name_len + 1);
    memcpy(pout->lang_short_name, pin_ptr, lang_short_name_len);
    pout->lang_short_name[lang_short_name_len] = 0;
    pin_ptr += pkt_bin_align(lang_short_name_len);
  }

  //unsigned char *header_pat;      // header number pattern
  pout->header_pat = NULL;
  int header_pat_len = cvt_bin_to_host_32(pin->header_pat_len);
  FAIL_IF(header_pat_len < 0 || header_pat_len > PATH_MAX);
  FAIL_IF(pin_ptr + header_pat_len > end_ptr);
  if (header_pat_len > 0) {
    pout->header_pat = xmalloc(header_pat_len + 1);
    memcpy(pout->header_pat, pin_ptr, header_pat_len);
    pout->header_pat[header_pat_len] = 0;
    pin_ptr += pkt_bin_align(header_pat_len);
  }

  //unsigned char *footer_pat;      // footer number pattern
  pout->footer_pat = NULL;
  int footer_pat_len = cvt_bin_to_host_32(pin->footer_pat_len);
  FAIL_IF(footer_pat_len < 0 || footer_pat_len > PATH_MAX);
  FAIL_IF(pin_ptr + footer_pat_len > end_ptr);
  if (footer_pat_len > 0) {
    pout->footer_pat = xmalloc(footer_pat_len + 1);
    memcpy(pout->footer_pat, pin_ptr, footer_pat_len);
    pout->footer_pat[footer_pat_len] = 0;
    pin_ptr += pkt_bin_align(footer_pat_len);
  }

  //unsigned char *header_dir;      // directory with multiple headers and footers
  pout->header_dir = NULL;
  int header_dir_len = cvt_bin_to_host_32(pin->header_dir_len);
  FAIL_IF(header_dir_len < 0 || header_dir_len > PATH_MAX);
  FAIL_IF(pin_ptr + header_dir_len > end_ptr);
  if (header_dir_len > 0) {
    pout->header_dir = xmalloc(header_dir_len + 1);
    memcpy(pout->header_dir, pin_ptr, header_dir_len);
    pout->header_dir[header_dir_len] = 0;
    pin_ptr += pkt_bin_align(header_dir_len);
  }

  //unsigned char *compiler_env_pat;      // compiler environment pattern
  pout->compiler_env_pat = NULL;
  int compiler_env_pat_len = cvt_bin_to_host_32(pin->compiler_env_pat_len);
  FAIL_IF(compiler_env_pat_len < 0 || compiler_env_pat_len > PATH_MAX);
  FAIL_IF(pin_ptr + compiler_env_pat_len > end_ptr);
  if (compiler_env_pat_len > 0) {
    pout->compiler_env_pat = xmalloc(compiler_env_pat_len + 1);
    memcpy(pout->compiler_env_pat, pin_ptr, compiler_env_pat_len);
    pout->compiler_env_pat[compiler_env_pat_len] = 0;
    pin_ptr += pkt_bin_align(compiler_env_pat_len);
  }

  pout->user_login = NULL;
  int user_login_len = cvt_bin_to_host_32(pin->user_login_len);
  FAIL_IF(user_login_len < 0 || user_login_len >= PATH_MAX);
  FAIL_IF(pin_ptr + user_login_len > end_ptr);
  if (user_login_len > 0) {
    pout->user_login = xmalloc(user_login_len + 1);
    memcpy(pout->user_login, pin_ptr, user_login_len);
    pout->user_login[user_login_len] = 0;
    pin_ptr += pkt_bin_align(user_login_len);
  }

  pout->exam_cypher = NULL;
  int exam_cypher_len = cvt_bin_to_host_32(pin->exam_cypher_len);
  FAIL_IF(exam_cypher_len < 0 || exam_cypher_len >= PATH_MAX);
  FAIL_IF(pin_ptr + exam_cypher_len > end_ptr);
  if (exam_cypher_len > 0) {
    pout->exam_cypher = xmalloc(exam_cypher_len + 1);
    memcpy(pout->exam_cypher, pin_ptr, exam_cypher_len);
    pout->exam_cypher[exam_cypher_len] = 0;
    pin_ptr += pkt_bin_align(exam_cypher_len);
  }

  pout->contest_server_id = NULL;
  int contest_server_id_len = cvt_bin_to_host_32(pin->contest_server_id_len);
  FAIL_IF(contest_server_id_len < 0 || contest_server_id_len >= PATH_MAX);
  FAIL_IF(pin_ptr + contest_server_id_len > end_ptr);
  if (contest_server_id_len > 0) {
    pout->contest_server_id = xmalloc(contest_server_id_len + 1);
    memcpy(pout->contest_server_id, pin_ptr, contest_server_id_len);
    pout->contest_server_id[contest_server_id_len] = 0;
    pin_ptr += pkt_bin_align(contest_server_id_len);
  }

  pout->container_options = NULL;
  int container_options_len = cvt_bin_to_host_32(pin->container_options_len);
  FAIL_IF(container_options_len < 0 || container_options_len >= PATH_MAX);
  FAIL_IF(pin_ptr + container_options_len > end_ptr);
  if (container_options_len > 0) {
    pout->container_options = xmalloc(container_options_len + 1);
    memcpy(pout->container_options, pin_ptr, container_options_len);
    pout->container_options[container_options_len] = 0;
    pin_ptr += pkt_bin_align(container_options_len);
  }

  pout->vcs_compile_cmd = NULL;
  int vcs_compile_cmd_len = cvt_bin_to_host_32(pin->vcs_compile_cmd_len);
  FAIL_IF(vcs_compile_cmd_len < 0 || vcs_compile_cmd_len >= PATH_MAX);
  FAIL_IF(pin_ptr + vcs_compile_cmd_len > end_ptr);
  if (vcs_compile_cmd_len > 0) {
    pout->vcs_compile_cmd = xmalloc(vcs_compile_cmd_len + 1);
    memcpy(pout->vcs_compile_cmd, pin_ptr, vcs_compile_cmd_len);
    pout->vcs_compile_cmd[vcs_compile_cmd_len] = 0;
    pin_ptr += pkt_bin_align(vcs_compile_cmd_len);
  }

  pout->compile_cmd = NULL;
  int compile_cmd_len = cvt_bin_to_host_32(pin->compile_cmd_len);
  FAIL_IF(compile_cmd_len < 0 || compile_cmd_len >= PATH_MAX);
  FAIL_IF(pin_ptr + compile_cmd_len > end_ptr);
  if (compile_cmd_len > 0) {
    pout->compile_cmd = xmalloc(compile_cmd_len + 1);
    memcpy(pout->compile_cmd, pin_ptr, compile_cmd_len);
    pout->compile_cmd[compile_cmd_len] = 0;
    pin_ptr += pkt_bin_align(compile_cmd_len);
  }

  pout->extra_src_dir = NULL;
  int extra_src_dir_len = cvt_bin_to_host_32(pin->extra_src_dir_len);
  FAIL_IF(extra_src_dir_len < 0 || extra_src_dir_len >= PATH_MAX);
  FAIL_IF(pin_ptr + extra_src_dir_len > end_ptr);
  if (extra_src_dir_len > 0) {
    pout->extra_src_dir = xmalloc(extra_src_dir_len + 1);
    memcpy(pout->extra_src_dir, pin_ptr, extra_src_dir_len);
    pout->extra_src_dir[extra_src_dir_len] = 0;
    pin_ptr += pkt_bin_align(extra_src_dir_len);
  }

  pout->env_num = cvt_bin_to_host_32(pin->env_num);
  FAIL_IF(pout->env_num < 0 || pout->env_num > EJ_MAX_COMPILE_ENV_NUM);
  FAIL_IF(pin_ptr + pout->env_num * sizeof(rint32_t) > end_ptr);
  if (pout->env_num > 0) {
    XCALLOC(pout->env_vars, pout->env_num + 1);
    str_lens = (rint32_t*) alloca(pout->env_num * sizeof(rint32_t));
    memcpy(str_lens, pin_ptr, pout->env_num * sizeof(rint32_t));
    for (i = 0; i < pout->env_num; i++) {
      str_lens[i] = cvt_bin_to_host_32(str_lens[i]);
      FAIL_IF(str_lens[i] < 0 || str_lens[i] > EJ_MAX_COMPILE_ENV_LEN);
      pout->env_vars[i] = xmalloc(str_lens[i] + 1);
    }
    pin_ptr += pkt_bin_align(pout->env_num * sizeof(rint32_t));

    for (i = 0; i < pout->env_num; i++) {
      FAIL_IF(pin_ptr + str_lens[i] > end_ptr);
      memcpy(pout->env_vars[i], pin_ptr, str_lens[i]);
      pout->env_vars[i][str_lens[i]] = 0;
      pin_ptr += str_lens[i];
    }
  }

  // align the address at the 16-byte boundary
  pkt_bin_align_addr(pin_ptr, in_data);

  pout->sc_env_num = cvt_bin_to_host_32(pin->sc_env_num);
  FAIL_IF(pout->sc_env_num < 0 || pout->sc_env_num > EJ_MAX_COMPILE_ENV_NUM);
  FAIL_IF(pin_ptr + pout->sc_env_num * sizeof(rint32_t) > end_ptr);
  if (pout->sc_env_num > 0) {
    XCALLOC(pout->sc_env_vars, pout->sc_env_num + 1);
    str_lens = (rint32_t*) alloca(pout->sc_env_num * sizeof(rint32_t));
    memcpy(str_lens, pin_ptr, pout->sc_env_num * sizeof(rint32_t));
    for (i = 0; i < pout->sc_env_num; i++) {
      str_lens[i] = cvt_bin_to_host_32(str_lens[i]);
      FAIL_IF(str_lens[i] < 0 || str_lens[i] > EJ_MAX_COMPILE_ENV_LEN);
      pout->sc_env_vars[i] = xmalloc(str_lens[i] + 1);
    }
    pin_ptr += pkt_bin_align(pout->sc_env_num * sizeof(rint32_t));
    for (i = 0; i < pout->sc_env_num; i++) {
      FAIL_IF(pin_ptr + str_lens[i] > end_ptr);
      memcpy(pout->sc_env_vars[i], pin_ptr, str_lens[i]);
      pout->sc_env_vars[i][str_lens[i]] = 0;
      pin_ptr += str_lens[i];
    }
  }

  pkt_bin_align_addr(pin_ptr, in_data);
  FAIL_IF(pin_ptr != end_ptr);

#if 0
  /* debugging */
  fprintf(stderr,
          "the compile request packet\n"
          "  judge_id:      %d\n"
          "  contest_id:    %d\n"
          "  run_id:        %d\n"
          "  lang_id:       %d\n"
          "  locale_id:     %d\n"
          "  ts1:           %d\n"
          "  ts1_us:        %d\n"
          "  run_block_len: %d\n"
          "  env_num:       %d\n",
          pout->judge_id, pout->contest_id, pout->run_id, pout->lang_id,
          pout->locale_id, pout->ts1, pout->ts1_us, pout->run_block_len,pout->env_num);
  for (i = 0; i < pout->env_num; i++) {
    fprintf(stderr, "    env[%d]: <%s>\n", i, pout->env_vars[i]);
  }
#endif

  *p_out_data = pout;
  return 1;

 failed:
  /* even the contest id is not available */
  err("compile_request_packet_read: error %s, %d", "$Revision$", errcode);
  compile_request_packet_free(pout);
  return -1;
}
