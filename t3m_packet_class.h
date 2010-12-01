/* -*- c -*- */
/* $Id$ */
#ifndef __T3M_PACKET_CLASS_H__
#define __T3M_PACKET_CLASS_H__

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

#include <stdio.h>

struct serve_state;

struct t3m_generic_submit
{
  int skip_flag;
  int run_id;
  int lang_id;
  int prob_id;
  int gzipped;
  long file_size;
};

struct t3m_packet_class;
struct t3m_packet_operations
{
  struct t3m_packet_class * (*destroy)(
        struct t3m_packet_class *data);
  int (*parse)(
        struct t3m_packet_class *data,
        FILE *log,
        const unsigned char *path);
  int (*generate)(
        struct t3m_packet_class *data,
        FILE *log,
        const unsigned char *out_path);
  void (*make_error_packet)(
        struct t3m_packet_class *data,
        FILE *log,
        const unsigned char *out_path,
        const unsigned char *log_t);
  const unsigned char *(*get_exam_guid)(
        struct t3m_packet_class *data);
  int (*bind)(
        struct t3m_packet_class *data,
        FILE *log,
        struct serve_state *state,
        int base_run_id,
        int (*get_compiler_count)(void *date),
        const unsigned char *(*get_ext_name)(void *data, int index),
        const unsigned char *(*get_short_name)(void *data, int index),
        void *config_data);
  int (*get_submit_count)(
        struct t3m_packet_class *data);
  int (*get_submit)(
        struct t3m_packet_class *data,
        FILE *log,
        int index,
        struct t3m_generic_submit *p_submit);
  int (*get_file)(
        struct t3m_packet_class *data,
        FILE *log,
        int index,
        unsigned char *text,
        int size);
  int (*set_submit)(
        struct t3m_packet_class *data,
        FILE *log,
        int index,
        int status,
        int score,
        const unsigned char *text);
};

struct t3m_packet_class
{
  struct t3m_packet_operations *ops;
};

struct t3m_packet_class *
zip_packet_class_create(void);

#endif /* __T3M_PACKET_CLASS_H__ */
