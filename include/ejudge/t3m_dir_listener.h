/* -*- c -*- */
/* $Id$ */
#ifndef __T3M_DIR_LISTENER_H__
#define __T3M_DIR_LISTENER_H__

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

/*
 * Simple interface for subscribing/unsubscribing for incoming
 * spool directory handling
 */

typedef int (*dir_listener_handler_t)(
        void *data,
        const unsigned char *spool_dir,
        const unsigned char *in_path,
        const unsigned char *pkt_name);
typedef void (*dir_listener_checker_t)(
        void *data,
        const unsigned char *spool_dir);

struct dir_listener_info
{
  struct dir_listener_info *prev, *next;
  unsigned char *spool_dir;
  dir_listener_handler_t handler;
  dir_listener_checker_t checker;
  void *data;
};

struct dir_listener_state
{
  struct dir_listener_info *first, *last;
};

struct dir_listener_state *
dir_listener_create(void);

int
dir_listener_add(
        struct dir_listener_state *state,
        const unsigned char *spool_dir, 
        dir_listener_handler_t handler,
        dir_listener_checker_t checker,
        void *data);

int
dir_listener_remove(
        struct dir_listener_state *state,
        const unsigned char *spool_dir);

int
dir_listener_find(
        struct dir_listener_state *state,
        const unsigned char *spool_dir,
        dir_listener_handler_t *p_handler,
        dir_listener_checker_t *p_checker,
        void **p_data);

#endif /* __T3M_DIR_LISTENER_H__ */
