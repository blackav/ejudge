/* -*- c -*- */
/* $Id$ */

#ifndef __LIST_OPS_H__
#define __LIST_OPS_H__

/* Copyright (C) 2008-2010 Alexander Chernov <cher@ejudge.ru> */

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

#define UNLINK_FROM_LIST(elem, first, last, prev_field, next_field) \
  do { \
    if ((elem)->next_field) { \
      (elem)->next_field->prev_field = (elem)->prev_field; \
    } else { \
      (last) = (elem)->prev_field; \
    } \
    if ((elem)->prev_field) { \
      (elem)->prev_field->next_field = (elem)->next_field; \
    } else { \
      (first) = (elem)->next_field; \
    } \
    (elem)->prev_field = NULL; \
    (elem)->next_field = NULL; \
  } while (0)

#define MOVE_TO_FRONT(elem, first, last, prev_field, next_field) \
  do { \
    if ((elem) != (first)) { \
      if ((elem)->next_field) { \
        (elem)->next_field->prev_field = (elem)->prev_field; \
      } else { \
        (last) = (elem)->prev_field; \
      } \
      (elem)->prev_field->next_field = (elem)->next_field; \
      (elem)->prev_field = NULL; \
      (elem)->next_field = (first); \
      (first)->prev_field = (elem); \
      (first) = (elem); \
    } \
  } while (0)

#define CALCULATE_RANGE(min_var, max_var, first, field, next_field, iter) \
  do { \
    min_var = 0; \
    max_var = 0; \
    if (first) { \
      min_var = (first)->field; \
      max_var = (first)->field + 1; \
    } \
    for (iter = (first); iter; iter = iter->next_field) { \
      if (iter->field < min_var) min_var = iter->field; \
      if (iter->field >= max_var) max_var = iter->field + 1; \
    } \
  } while (0)

#define UPDATE_RANGE(min_var, max_var, first, value) \
  do { \
    if (!(first)) { \
      min_var = value; \
      max_var = value + 1; \
    } else { \
      if (value < min_var) min_var = value; \
      if (value >= max_var) max_var = value + 1; \
    } \
  } while (0)

#define LINK_FIRST(elem, first, last, prev_field, next_field) \
  do { \
    (elem)->next_field = (first); \
    if (first) { \
      (first)->prev_field = (elem); \
    } else { \
      (last) = (elem); \
    } \
    (first) = (elem); \
  } while (0)

#define LINK_LAST(elem, first, last, prev_field, next_field) \
  do { \
    (elem)->prev_field = (last); \
    if (last) { \
      (last)->next_field = (elem); \
    } else { \
      (first) = (elem); \
    } \
    (last) = (elem); \
  } while (0)

#endif /* __LIST_OPS_H__ */
