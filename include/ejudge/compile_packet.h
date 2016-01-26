/* -*- c -*- */
#ifndef __COMPILE_PACKET_H__
#define __COMPILE_PACKET_H__

/* Copyright (C) 2005-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdlib.h>

struct compile_request_packet
{
  int judge_id;
  int contest_id;
  int run_id;
  int lang_id;
  int locale_id;
  int output_only;
  int style_check_only;
  int ts1;
  int ts1_us;
  int use_uuid;
  int multi_header;                // 1, if multi-header/footer mode requested
  int lang_header;                 // 1, if header/footer lang-specific
  ej_uuid_t uuid;
  ej_size64_t max_vm_size;
  ej_size64_t max_stack_size;
  ej_size64_t max_file_size;
  unsigned char *style_checker;
  unsigned char *src_sfx;
  unsigned char *lang_short_name; // additional suffix for multi-header/footer
  unsigned char *header_pat;      // header number pattern
  unsigned char *footer_pat;      // footer number pattern
  unsigned char *header_dir;      // directory with multiple headers and footers
  unsigned char *compiler_env_pat;// pattern for compiler environment files
  int run_block_len;
  void *run_block;
  int env_num;
  int sc_env_num;
  unsigned char **env_vars;
  unsigned char **sc_env_vars;
};

struct compile_reply_packet
{
  int judge_id;
  int contest_id;
  int run_id;
  int status;
  /* time when the compile request was queued by serve */
  int ts1;
  int ts1_us;
  /* time when the compile request was received by compile */
  int ts2;
  int ts2_us;
  /* time when the compile request was completed by compile */
  int ts3;
  int ts3_us;
  int run_block_len;
  void *run_block;
  int use_uuid;
  ej_uuid_t uuid;
  int zip_mode;       // reply file is an archive of executables
};

int
compile_request_packet_read(
        size_t in_size,
        const void *in_data,
        struct compile_request_packet **p_out_data);

int
compile_request_packet_write(
        const struct compile_request_packet *in_data,
        size_t *p_out_size,
        void **p_out_data);

struct compile_request_packet *
compile_request_packet_free(struct compile_request_packet *in_data);

int
compile_reply_packet_read(
        size_t in_size,
        const void *in_data,
        struct compile_reply_packet **p_out_data);

int
compile_reply_packet_write(
        const struct compile_reply_packet *in_data,
        size_t *p_out_size,
        void **p_out_data);

struct compile_reply_packet *
compile_reply_packet_free(struct compile_reply_packet *in_data);

#endif /* __COMPILE_PACKET_H__ */
