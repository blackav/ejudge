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

#ifdef EJUDGE_CHECKER
#include "trie.h"
#include "trie_private.h"
#else
#include "ejudge/trie.h"
#include "ejudge/trie_private.h"
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int
trie_check_16(const struct trie_data *td, const unsigned char *str)
{
    uint16_t current_offset = td->root_offset;
    while (1) {
        const struct trie_node_16 *node = TRIE_NODE_16(td, current_offset);
        if (!*str) {
            if (node->num) {
                return (int) node->num - 1;
            }
            return -1;
        }
        if (node->prefix_offset) {
            const unsigned char *prefix = TRIE_PREFIX_16(td, current_offset);
            while (*prefix) {
                if (*prefix != *str) {
                    return -1;
                }
                ++prefix;
                ++str;
            }
        }
        unsigned char c = *str;
        if (c < node->low_c || c > node->high_c) {
            return -1;
        }
        if (node->cmap_offset) {
            uint32_t subind = TRIE_CMAP_16(td, current_offset, c - node->low_c);
            if (!subind) {
                return -1;
            }
            current_offset = TRIE_CHILD_16(td, current_offset, subind);
        } else {
            current_offset = TRIE_CHILD_16(td, current_offset, c - node->low_c);
        }
        if (!current_offset) {
            return -1;
        }
        ++str;
    }
}
