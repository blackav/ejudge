/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2022 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/trie.h"
#include "ejudge/trie_private.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct trie_data *
trie_create(void)
{
    struct trie_data *td = calloc(1, sizeof(*td));
    if (td) {
        td->reserved = 256;
        td->ptr = calloc(td->reserved, 1);
        td->size = 4;
    }
    return td;
}

struct trie_data *
trie_free(struct trie_data *td)
{
    if (td) {
        free(td->ptr);
        free(td);
    }
    return NULL;
}

static uint32_t
trie_alloc(struct trie_data *td, uint32_t size)
{
    if (!size) size = 4;
    size = (size + 3) & ~3;
    if (!size) return 0;
    uint32_t new_size;
    if (__builtin_add_overflow(td->size, size, &new_size)) return 0;
    if (new_size > td->reserved) {
        uint32_t new_reserved = td->reserved;
        while (new_size > new_reserved) {
            if (__builtin_mul_overflow(new_reserved, 2, &new_reserved)) return 0;
        }
        unsigned char *new_ptr = malloc(new_reserved);
        if (!new_ptr) return 0;
        memcpy(new_ptr, td->ptr, td->reserved);
        memset(new_ptr + td->reserved, 0, new_reserved - td->reserved);
        free(td->ptr);
        td->ptr = new_ptr;
        td->reserved = new_reserved;
    }
    uint32_t result = td->size;
    td->size = new_size;
    return result;
}

static uint32_t
make_trie_rec(
        struct trie_data *td,
        uint32_t low,
        uint32_t high,
        uint32_t index,
        uint32_t *sorted_idx,
        unsigned char **strs)
{
    if (low >= high) abort();

    uint32_t node_offset = trie_alloc(td, sizeof(struct trie_node));
    struct trie_node *node = TRIE_NODE(td, node_offset);
    uint32_t mem;

    if (!strs[sorted_idx[low]][index]) {
        node->num = sorted_idx[low] + 1;
        ++low;
    }
    if (low == high) {
        return node_offset;
    }

    if (low + 1 == high) {
        uint32_t orig_index = sorted_idx[low];
        const unsigned char *str = strs[orig_index];
        unsigned char c = str[index];
        // precond: str[index] != 0
        uint32_t len = 0;
        while (str[index + len]) ++len;
        // abcdef -> prefix: abcde, node: f
        // a -> node: a
        if (len > 1) {
            mem = trie_alloc(td, len);
            node = TRIE_NODE(td, node_offset);
            node->prefix_offset = mem;
            memcpy(TRIE_PREFIX(td, node_offset), str + index, len - 1);
        }
        c = str[index + len - 1];
        mem = trie_alloc(td, sizeof(uint32_t));
        node = TRIE_NODE(td, node_offset);
        node->children_offset = mem;
        node->low_c = c;
        node->high_c = c;
        mem = make_trie_rec(td, low, high, index + len, sorted_idx, strs);
        TRIE_CHILD(td, node_offset, 0) = mem;
        return node_offset;
    }

    // compute common prefix
    uint32_t pfx_len = 0;
    while (1) {
        unsigned char c = strs[sorted_idx[low]][index + pfx_len];
        uint32_t i = low + 1;
        for (; i < high; ++i) {
            if (strs[sorted_idx[i]][index + pfx_len] != c) {
                break;
            }
        }
        if (i < high) {
            break;
        }
        ++pfx_len;
    }

    if (pfx_len > 0) {
        // case 1:
        //   a
        //   aa
        //   ab
        //   -> pfx_len == 1, and c == 0
        // case 2:
        //   aa
        //   ab
        //   ac
        //   -> pfx_len == 1, and c != 0
        // case 3:
        //   aa
        //   aaa
        //   aab
        //   -> pfx_len > 1, and c == 0
        // case 4:
        //   aaa
        //   aab
        //   aac
        //   -> pfx_len > 1, and c != 0
        const unsigned char *str = strs[sorted_idx[low]];
        unsigned char c = str[index + pfx_len];
        if (!c) {
            // cases 1, 3
            if (pfx_len > 1) {
                mem = trie_alloc(td, pfx_len);
                node = TRIE_NODE(td, node_offset);
                node->prefix_offset = mem;
                memcpy(TRIE_PREFIX(td, node_offset), str + index, pfx_len - 1);
            }
            c = str[index + pfx_len - 1];
            mem = trie_alloc(td, sizeof(uint32_t));
            node = TRIE_NODE(td, node_offset);
            node->children_offset = mem;
            node->low_c = c;
            node->high_c = c;
            mem = make_trie_rec(td, low, high, index + pfx_len, sorted_idx, strs);
            TRIE_CHILD(td, node_offset, 0) = mem;
            return node_offset;
        }

        mem = trie_alloc(td, pfx_len + 1);
        node = TRIE_NODE(td, node_offset);
        node->prefix_offset = mem;
        memcpy(TRIE_PREFIX(td, node_offset), str + index, pfx_len);
        index += pfx_len;
    }

    // compute range of chars
    unsigned char low_c = strs[sorted_idx[low]][index];
    unsigned char high_c = strs[sorted_idx[low]][index];
    uint64_t cset[4] = {};
    uint32_t ccnt = 1;
    CHARSET_SET(cset, low_c);
    for (uint32_t i = low + 1; i < high; ++i) {
        unsigned char c = strs[sorted_idx[i]][index];
        if (c < low_c) low_c = c;
        if (c > high_c) high_c = c;
        if (!CHARSET_ISSET(cset, c)) {
            ++ccnt;
            CHARSET_SET(cset, c);
        }
    }

    // debug
    if (!low_c) abort();
    if (ccnt == 1) abort();

    node->low_c = low_c;
    node->high_c = high_c;

    // compare two sizes: with charmap and without charmap
    uint32_t no_cmap_size = (high_c - low_c + 1) * sizeof(uint32_t);
    uint32_t with_cmap_size = ((high_c - low_c + 1) + 3) & ~3U;
    with_cmap_size += (ccnt + 1) * sizeof(uint32_t);
    if (with_cmap_size < no_cmap_size) {
        // cmap on
        mem = trie_alloc(td, high_c - low_c + 1);
        node = TRIE_NODE(td, node_offset);
        node->cmap_offset = mem;
        mem = trie_alloc(td, (ccnt + 1) * sizeof(uint32_t));
        node = TRIE_NODE(td, node_offset);
        node->children_offset = mem;
        uint32_t cur_subind = 1;
        uint32_t low_ind = low, high_ind = low;
        while (low_ind < high) {
            unsigned char c = strs[sorted_idx[low_ind]][index];
            while (high_ind < high && strs[sorted_idx[high_ind]][index] == c) {
                ++high_ind;
            }
            uint32_t subind = cur_subind++;
            TRIE_CMAP(td, node_offset, c - low_c) = subind;
            mem = make_trie_rec(td, low_ind, high_ind, index + 1, sorted_idx, strs);
            TRIE_CHILD(td, node_offset, subind) = mem;
            low_ind = high_ind;
        }
    } else {
        mem = trie_alloc(td, (high_c - low_c + 1) * sizeof(uint32_t));
        node = TRIE_NODE(td, node_offset);
        node->children_offset = mem;
        uint32_t low_ind = low, high_ind = low;
        while (low_ind < high) {
            unsigned char c = strs[sorted_idx[low_ind]][index];
            while (high_ind < high && strs[sorted_idx[high_ind]][index] == c) {
                ++high_ind;
            }
            mem = make_trie_rec(td, low_ind, high_ind, index + 1, sorted_idx, strs);
            TRIE_CHILD(td, node_offset, c - low_c) = mem;
            low_ind = high_ind;
        }
    }
    return node_offset;
}

static int
sort_func(const void *p1, const void *p2, void *p3)
{
    unsigned int idx1 = *(const unsigned int*) p1;
    unsigned int idx2 = *(const unsigned int*) p2;
    char **strs = (char**) p3;
    return strcmp(strs[idx1], strs[idx2]);
}

struct trie_data *
trie_compile(size_t count, unsigned char **strs)
{
    struct trie_data *trie = NULL;

    if ((unsigned int) count != count || (int) count <= 0) return NULL;
    unsigned int size;
    if (__builtin_mul_overflow((unsigned int) count, (unsigned int) sizeof(unsigned int), &size)) return NULL;
    unsigned int *sorted_idx = malloc(size);
    if (!sorted_idx) return NULL;
    for (unsigned int i = 0; i < count; ++i) {
        sorted_idx[i] = i;
    }
    qsort_r(sorted_idx, count, sizeof(sorted_idx[0]), sort_func, strs);

    // just check for duplicates
    for (unsigned int i = 1; i < count; ++i) {
        if (!strcmp((char *) strs[sorted_idx[i - 1]], (char *) strs[sorted_idx[i]])) {
            abort();
        }
    }

    trie = trie_create();
    trie->root_offset = make_trie_rec(trie, 0, count, 0, sorted_idx, strs);
    free(sorted_idx);

    return trie;
}

struct trie_data *
trie_compile_f(unsigned char *(*index_func)(void *cntx, unsigned int index), void *cntx)
{
    uint32_t count = 0;
    while (1) {
        const unsigned char *s = index_func(cntx, count);
        if (!s) break;
        ++count;
    }

    unsigned char **strs = malloc(count * sizeof(strs[0]));
    for (uint32_t i = 0; i < count; ++i) {
        strs[i] = index_func(cntx, i);
    }
    struct trie_data *res = trie_compile(count, strs);
    free(strs);
    return res;
}

void
trie_dump(struct trie_data *trie, FILE *fout)
{
    fprintf(stderr, "reserved: %u, size: %u, offset: %u\n",
            trie->reserved, trie->size, trie->root_offset);
}

void
trie_generate_c(struct trie_data *trie, const char *varname, FILE *fout)
{
    fprintf(fout, "static const unsigned char %s_data[%u] =\n{\n",
            varname, trie->size);
    for (uint32_t i = 0; i < trie->size; ++i) {
        if (i % 16 == 0) fprintf(fout, " ");
        fprintf(fout, " %u,", trie->ptr[i]);
        if (i % 16 == 15) fprintf(fout, "\n");
    }
    if (trie->size % 16 != 0) fprintf(fout, "\n");
    fprintf(fout, "};\n");
    fprintf(fout, "const struct trie_data %s_trie =\n{\n"
            "  %s_data, %u, %u, %u,\n};\n",
            varname, varname, trie->reserved, trie->size, trie->root_offset);
}
