/* -*- c -*- */
/* $Id$ */

#ifndef __BITSET_H__
#define __BITSET_H__

/* Copyright (C) 2011 Alexander Chernov <cher@ejudge.ru> */

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

struct bitset_s
{
  int size;
  unsigned char *set;
};
typedef struct bitset_s bitset_t;

#define BITSET_INITIALIZER { 0, 0 }

void bitset_init(bitset_t *ss, int size);
void bitset_free(bitset_t *ss);
void bitset_resize(bitset_t *ss, int new_size);
void bitset_reset(bitset_t *ss, int new_size);

void bitset_clear(bitset_t *ss);
void bitset_fill(bitset_t *ss);

int
bitset_url_decode(
        const unsigned char *str,
        bitset_t *ss);
unsigned char *
bitset_url_encode(bitset_t *ss);
int
bitset_is_equal(
        bitset_t *s1,
        bitset_t *s2);

static inline __attribute__((always_inline)) int
bitset_get(bitset_t *ss, int index)
{
  return ss->set[index >> 3] & (1 << (index & 7));
}

static inline __attribute__((always_inline)) int
bitset_safe_get(bitset_t *ss, int index)
{
  if (ss && index >= 0 && index < ss->size) {
    return ss->set[index >> 3] & (1 << (index & 7));
  } else {
    return 0;
  }
}

static inline __attribute__((always_inline)) void
bitset_on(bitset_t *ss, int index)
{
  ss->set[index >> 3] |= (1 << (index & 7));
}

static inline __attribute__((always_inline)) void
bitset_safe_on(bitset_t *ss, int index)
{
  if (ss && index >= 0 && index < ss->size) {
    ss->set[index >> 3] |= (1 << (index & 7));
  }
}

static inline __attribute__((always_inline)) void
bitset_off(bitset_t *ss, int index)
{
  ss->set[index >> 3] &= ~(1 << (index & 7));
}

static inline __attribute__((always_inline)) void
bitset_safe_off(bitset_t *ss, int index)
{
  if (ss && index >= 0 && index < ss->size) {
    ss->set[index >> 3] &= ~(1 << (index & 7));
  }
}

static inline __attribute__((always_inline)) void
bitset_toggle(bitset_t *ss, int index)
{
  ss->set[index >> 3] ^= (1 << (index & 7));
}

static inline __attribute__((always_inline)) void
bitset_safe_toggle(bitset_t *ss, int index)
{
  if (ss && index >= 0 && index < ss->size) {
    ss->set[index >> 3] ^= (1 << (index & 7));
  }
}

#endif /* __BITSET_H__ */
