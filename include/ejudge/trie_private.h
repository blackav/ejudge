/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __TRIE_PRIVATE_H__
#define __TRIE_PRIVATE_H__

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

struct trie_data;

struct trie_node
{
    uint32_t prefix_offset;
    uint32_t cmap_offset;
    uint32_t children_offset;
    uint32_t num;
    unsigned char low_c, high_c;
};

struct trie_data
{
    unsigned char *ptr;
    uint32_t reserved;
    uint32_t size;
    uint32_t root_offset;
    unsigned char mode_16;
};

#define TRIE_NODE(td, offset) ((struct trie_node *) ((td)->ptr + (offset)))
#define TRIE_CHILD(td, node_offset, index) ((uint32_t *)((td)->ptr + (TRIE_NODE(td, node_offset))->children_offset))[(index)]
#define TRIE_CMAP(td, node_offset, index) ((unsigned char *)((td)->ptr + (TRIE_NODE(td, node_offset))->cmap_offset))[(index)]
#define TRIE_PREFIX(td, node_offset) ((unsigned char *)((td)->ptr + (TRIE_NODE(td, node_offset))->prefix_offset))

#define CHARSET_SET(cs, ind) ((cs)[((unsigned char)(ind)) >> 6] |= 1ULL << (((unsigned char)(ind)) & 63))
#define CHARSET_ISSET(cs, ind) (((cs)[((unsigned char)(ind)) >> 6] & (1ULL << (((unsigned char)(ind)) & 63))) != 0)

struct trie_node_16
{
    uint16_t prefix_offset;
    uint16_t cmap_offset;
    uint16_t children_offset;
    uint16_t num;
    unsigned char low_c, high_c;
};

#define TRIE_NODE_16(td, offset) ((struct trie_node_16 *) ((td)->ptr + (offset)))
#define TRIE_CHILD_16(td, node_offset, index) ((uint16_t *)((td)->ptr + (TRIE_NODE_16(td, node_offset))->children_offset))[(index)]
#define TRIE_CMAP_16(td, node_offset, index) ((unsigned char *)((td)->ptr + (TRIE_NODE_16(td, node_offset))->cmap_offset))[(index)]
#define TRIE_PREFIX_16(td, node_offset) ((unsigned char *)((td)->ptr + (TRIE_NODE_16(td, node_offset))->prefix_offset))

#endif /* __TRIE_PRIVATE_H__ */
