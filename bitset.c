/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2011-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/bitset.h"

#include "ejudge/xalloc.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static unsigned char const base64_encode_table[]=
"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_";
static signed char const base64_decode_table[] =
{
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
  25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, -1, -1, -1, -1, 63,
  -1, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
  51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

enum { ENCODE_BASE = 64 };
enum { MAX_VALUE = 1000000000 };

int
bitset_url_decode(
        const unsigned char *str,
        bitset_t *ss)
{
  int i = 0, len, cnt, d, start, count, j;
  int size = 0, alloc = 0;
  unsigned char *set = 0;
  int max_num = -1;

  if (ss) {
    ss->size = 0;
    xfree(ss->set); ss->set = NULL;
  }

  if (!str || !*str) goto empty;
  len = strlen(str);
  if (len < 0 || len > MAX_VALUE) goto fail;

  // count the size of the set and validate it
  while (i < len) {
    if (str[i] < '0' || str[i] > '9') goto fail;
    if (str[i] == '0') {
      ++i;
      continue;
    }
    cnt = str[i++] - '0';
    if (i + cnt > len) goto fail;
    start = 0;
    for (; cnt; --cnt, ++i) {
      d = base64_decode_table[str[i]];
      if (d < 0 || d >= ENCODE_BASE) goto fail;
      if (start >= MAX_VALUE / ENCODE_BASE - 1) goto fail;
      start = start * ENCODE_BASE + d;
    }
    if (start < 0 || start >= MAX_VALUE) goto fail;
    if (str[i] < '0' || str[i] > '9') goto fail;
    if (str[i] == '0') {
      if (start > max_num) max_num = start;
      ++i;
      continue;
    }
    cnt = str[i++] - '0';
    if (i + cnt > len) goto fail;
    count = 0;
    for (; cnt; --cnt, ++i) {
      d = base64_decode_table[str[i]];
      if (d < 0 || d >= ENCODE_BASE) goto fail;
      if (count >= MAX_VALUE / ENCODE_BASE - 1) goto fail;
      count = count * ENCODE_BASE + d;
    }
    if (count < 0 || count >= MAX_VALUE) goto fail;
    if (count == 0) {
      if (start > max_num) max_num = start;
      continue;
    }
    if (i + count > len) goto fail;
    for (; count; --count, ++i) {
      d = base64_decode_table[str[i]];
      if (d < 0 || d >= 64) goto fail;
      for (j = 0; j < 6; ++j, ++start) {
        if ((d & (1 << j))) {
          if (start > max_num) max_num = start;
        }
      }
    }
  }

  if (max_num < 0) goto empty;
  size = max_num + 1;
  alloc = (size + 7) / 8;
  set = (unsigned char *) malloc(alloc);
  memset(set, 0, alloc);
  i = 0;
  while (i < len) {
    if (!(cnt = str[i++] - '0')) continue;
    start = 0;
    for (; cnt; --cnt, ++i) {
      start = start * ENCODE_BASE + base64_decode_table[str[i]];
    }
    if (!(cnt = str[i++] - '0')) {
      set[start >> 3] |= 1 << (start & 7);
      continue;
    }
    count = 0;
    for (; cnt; --cnt, ++i) {
      count = count * ENCODE_BASE + base64_decode_table[str[i]];
    }
    if (!count) {
      set[start >> 3] |= 1 << (start & 7);
      continue;
    }
    for (; count; --count, ++i) {
      d = base64_decode_table[str[i]];
      for (j = 0; j < 6; ++j, ++start) {
        if ((d & (1 << j))) {
          set[start >> 3] |= 1 << (start & 7);
        }
      }
    }
  }

  if (ss) {
    ss->size = size;
    ss->set = set;
  }
  return 0;

empty:
  return 0;

fail:
  xfree(set);
  return -1;
}

static int
get_num_len(int val)
{
  int cnt = 0;
  if (val < 0) return 0;
  if (!val) return 1;
  while (val) {
    ++cnt;
    val /= ENCODE_BASE;
  }
  return cnt;
}

unsigned char *
bitset_url_encode(bitset_t *ss)
{
  int i, j, min_num, max_num, cur_num, size, alloc;
  unsigned char *str = 0, *s, *set;

  if (!ss || (size = ss->size) <= 0 || !(set = ss->set)) {
    return xstrdup("");
  }
  alloc = (size + 7) / 8;
  for (i = 0; i < alloc; ++i) {
    if (set[i]) break;
  }
  if (i >= alloc) return xstrdup("");
  for (j = 0; j < 8; ++j) {
    if ((set[i] & (1 << j)))
      break;
  }
  min_num = i * 8 + j;
  for (i = alloc - 1; i >= 0; --i) {
    if (set[i]) break;
  }
  if (i < 0) return xstrdup("");
  for (j = 7; j >= 0; --j) {
    if ((set[i] & (1 << j)))
      break;
  }
  max_num = i * 8 + j;

  // count the required size
  int out_size = 0;
  cur_num = min_num;
  while (cur_num <= max_num) {
    int num2 = cur_num + 1;
    while (num2 <= max_num && (set[num2 >> 3] & (1 << (num2 & 7)))) {
      ++num2;
    }
    if (num2 <= max_num) {
      while (1) {
        int num3 = num2;
        while (!(set[num3 >> 3] & (1 << (num3 & 7)))) {
          ++num3;
        }
        // series of '0': [num2, num3)
        // determine if we should terminate the current series
        int bi1 = (num2 - 1 - cur_num) / 6;
        int bi2 = (num3 - cur_num) / 6; 
        if (bi2 - bi1 > 5) {
          // the gap is too long
          break;
        }
        num2 = num3;
        while (num2 <= max_num && (set[num2 >> 3] & (1 << (num2 & 7)))) {
          ++num2;
        }
        if (num2 > max_num) {
          break;
        }
      }
    }
    // encode interval: [cur_num, num2)
    out_size += get_num_len(cur_num) + 1; // position bytes
    if (num2 - cur_num <= 1) {
      ++out_size;
    } else {
      int sb = (num2 - cur_num + 5) / 6;
      out_size += get_num_len(sb) + 1 + sb;
    }
    cur_num = num2;
    if (cur_num > max_num) break;
    while (!(set[cur_num >> 3] & (1 << (cur_num & 7)))) {
      ++cur_num;
    }
  }

  // out_size is the required size
  str = (unsigned char *) xmalloc(out_size + 1);
  s = str;
  cur_num = min_num;
  while (cur_num <= max_num) {
    int num2 = cur_num + 1;
    while (num2 <= max_num && (set[num2 >> 3] & (1 << (num2 & 7)))) {
      ++num2;
    }
    if (num2 <= max_num) {
      while (1) {
        int num3 = num2;
        while (!(set[num3 >> 3] & (1 << (num3 & 7)))) {
          ++num3;
        }
        // series of '0': [num2, num3)
        // determine if we should terminate the current series
        int bi1 = (num2 - 1 - cur_num) / 6;
        int bi2 = (num3 - cur_num) / 6; 
        if (bi2 - bi1 > 5) {
          // the gap is too long
          break;
        }
        num2 = num3;
        while (num2 <= max_num && (set[num2 >> 3] & (1 << (num2 & 7)))) {
          ++num2;
        }
        if (num2 > max_num) {
          break;
        }
      }
    }
    // encode interval: [cur_num, num2)
    int cnt = get_num_len(cur_num);
    *s++ = base64_encode_table[cnt];
    s += cnt;
    int val = cur_num;
    for (int cnt2 = cnt; cnt2; --cnt2) {
      *--s = base64_encode_table[val % ENCODE_BASE];
      val /= ENCODE_BASE;
    }
    s += cnt;
    if (num2 - cur_num <= 1) {
      *s++ = '0';
    } else {
      int sb = (num2 - cur_num + 5) / 6;
      cnt = get_num_len(sb);
      *s++ = base64_encode_table[cnt];
      s += cnt;
      val = sb;
      for (int cnt2 = cnt; cnt2; --cnt2) {
        *--s = base64_encode_table[val % ENCODE_BASE];
        val /= ENCODE_BASE;
      }
      s += cnt;
      val = 0;
      cnt = 0;
      for (; cur_num < num2; ++cur_num) {
        if ((set[cur_num >> 3] & (1 << (cur_num & 7)))) {
          val |= 1 << cnt;
        }
        if (++cnt == 6) {
          *s++ = base64_encode_table[val];
          val = 0;
          cnt = 0;
        }
      }
      if (cnt > 0) {
        *s++ = base64_encode_table[val];
      }
    }
    cur_num = num2;
    if (cur_num > max_num) break;
    while (!(set[cur_num >> 3] & (1 << (cur_num & 7)))) {
      ++cur_num;
    }
  }
  *s = 0;
  return str;
}

int
bitset_is_equal(
        bitset_t *s1,
        bitset_t *s2)
{
  int size1 = 0, size2 = 0;
  if (s1) size1 = s1->size;
  if (s2) size2 = s2->size;
  unsigned char *set1 = 0, *set2 = 0;
  if (s1) set1 = s1->set;
  if (s2) set2 = s2->set;

  if (size1 < 0 || !set1) size1 = 0;
  if (size2 < 0 || !set2) size2 = 0;
  if (!size1 && !size2) return 1;
  int min_size = size1;
  if (size2 < min_size) min_size = size2;
  int i = 0;
  for (; i < min_size; ++i) {
    if (((set1[i >> 3] ^ set2[i >> 3]) & (1 << (i & 7))))
      return 0;
  }
  if (size1 > min_size) {
    for (; i < size1; ++i) {
      if ((set1[i >> 3] & (1 << (i & 7))))
        return 0;
    }
  } else if (size2 > min_size) {
    for (; i < size2; ++i) {
      if ((set2[i >> 3] & (1 << (i & 7))))
        return 0;
    }
  }
  return 1;
}

void
bitset_free(bitset_t *ss)
{
  if (ss) {
    xfree(ss->set); ss->set = 0;
    ss->size = 0;
  }
}

void
bitset_resize(bitset_t *ss, int new_size)
{
  if (!ss || new_size <= 0 || new_size > MAX_VALUE || new_size <= ss->size) return;
  int new_alloc = (new_size + 7) / 8;
  unsigned char *new_set = (unsigned char *) malloc(new_alloc);
  memset(new_set, 0, new_alloc);
  if (ss->size > 0) {
    int old_alloc = (ss->size + 7) / 8;
    memcpy(new_set, ss->set, old_alloc);
    xfree(ss->set); ss->set = 0;
  }
  ss->size = new_size;
  ss->set = new_set;
}
