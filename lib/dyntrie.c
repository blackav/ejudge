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

#include "ejudge/dyntrie.h"

#include <string.h>
#include <stdio.h>

static int
dyntrie_lookup(
        struct dyntrie_node *node,
        const unsigned char *s,
        uint32_t *p_index,
        struct dyntrie_item **p_item,
        uint32_t *p_matched)
{
    uint32_t low = 0, high = node->size, mid = 0;
    const unsigned char *part = NULL;
    struct dyntrie_item *item = NULL;

    while (low < high) {
        mid = (low + high) / 2;
        item = &node->children[mid];
        if (item->key_length <= sizeof(item->k.str)) {
            if (*s == item->k.str[0]) {
                part = item->k.str;
                break;
            } else if (*s < item->k.str[0]) {
                high = mid;
            } else /*if (*s > item->k.str[0])*/ {
                low = mid + 1;
            }
        } else {
            if (*s == item->k.ptr[0]) {
                part = item->k.ptr;
                break;
            } else if (*s < item->k.ptr[0]) {
                high = mid;
            } else /* if (*s > item->k.ptr[0]) */ {
                low = mid + 1;
            }
        }
    }
    if (!part) {
        if (low < high) abort();
        if (p_index) *p_index = low;
        if (p_item) *p_item = NULL;
        if (p_matched) *p_matched = 0;
        return 0;
    }
    if (p_index) *p_index = mid;
    if (p_item) *p_item = item;
    if (!*s) {
        if (p_matched) *p_matched = 1;
        return 1;
    }
    for (uint32_t j = 1; j < item->key_length; ++j) {
        if (s[j] != part[j]) {
            if (p_matched) *p_matched = j;
            return 0;
        }
    }

    if (p_matched) *p_matched = item->key_length;
    return 1;
}

// 0 - key already exists
// 1 - key inserted
int
dyntrie_insert(
        struct dyntrie_node **root,
        const unsigned char *key,
        void *value,
        int allow_replace,
        void **old_value)
{
    if (!root) abort();
    if (!*root) {
        struct dyntrie_node *node = calloc(1, sizeof(*node));
        node->reserved = 1;
        node->size = 1;
        node->children = calloc(1, sizeof(node->children[0]));
        struct dyntrie_item *item = &node->children[0];
        item->is_leaf = 1;
        item->key_length = strlen((const char *) key);
        item->t.value = value;
        if (item->key_length > sizeof(item->k.str)) {
            item->k.ptr = malloc(item->key_length);
            memcpy(item->k.ptr, key, item->key_length);
        } else if (item->key_length > 0) {
            memcpy(item->k.str, key, item->key_length);
        }
        *root = node;
        return 1;
    }

    struct dyntrie_node *node = *root;
    uint32_t index = 0;
    struct dyntrie_item *item = NULL;
    uint32_t matched = 0;
    int res = dyntrie_lookup(node, key, &index, &item, &matched);
    if (!res && !item) {
        // not found in children list, insert at position index
        if (node->size == node->reserved) {
            uint32_t new_reserved = node->reserved * 2;
            struct dyntrie_item *new_items = malloc(new_reserved * sizeof(new_items[0]));
            if (index > 0) {
                memcpy(new_items,
                       node->children,
                       index * sizeof(node->children[0]));
            }
            if (index < node->size) {
                memcpy(&new_items[index + 1],
                       &node->children[index],
                       (node->size - index) * sizeof(node->children[0]));
            }
            node->reserved = new_reserved;
            free(node->children);
            node->children = new_items;
        } else {
            if (index < node->size) {
                memmove(&node->children[index + 1],
                        &node->children[index],
                        (node->size - index) * sizeof(node->children[0]));
            }
        }
        ++node->size;
        struct dyntrie_item *item = &node->children[index];
        memset(item, 0, sizeof(*item));
        item->is_leaf = 1;
        item->key_length = strlen((const char *) key);
        item->t.value = value;
        if (item->key_length > sizeof(item->k.str)) {
            item->k.ptr = malloc(item->key_length);
            memcpy(item->k.ptr, key, item->key_length);
        } else if (item->key_length > 0) {
            memcpy(item->k.str, key, item->key_length);
        }
        return 1;
    }
    if (!res && item) {
        if (!*key) abort();
        if (!matched) abort();
        if (matched >= item->key_length) abort();
        // split
        const unsigned char *src_str = NULL;
        if (item->key_length > sizeof(item->k.str)) {
            src_str = item->k.ptr;
        } else {
            src_str = item->k.str;
        }
        struct dyntrie_node *new_node = calloc(2, sizeof(*new_node));
        new_node->reserved = 2;
        new_node->size = 1;
        new_node->children = calloc(new_node->reserved, sizeof(new_node->children[0]));
        struct dyntrie_item *new_item = &new_node->children[0];
        new_item->is_leaf = item->is_leaf;
        if (new_item->is_leaf) {
            new_item->t.value = item->t.value;
        } else {
            new_item->t.child = item->t.child;
        }
        new_item->key_length = item->key_length - matched;
        if (new_item->key_length > sizeof(new_item->k.str)) {
            new_item->k.ptr = malloc(new_item->key_length);
            memcpy(new_item->k.ptr, src_str + matched, new_item->key_length);
        } else if (new_item->key_length > 0) {
            memcpy(new_item->k.str, src_str + matched, new_item->key_length);
        }
        if (matched > sizeof(item->k.str)) {
            item->key_length = matched;
        } else if (item->key_length <= sizeof(item->k.str)) {
            item->key_length = matched;
        } else {
            unsigned char *old_str = item->k.ptr;
            memcpy(item->k.str, old_str, matched);
            free(old_str);
            item->key_length = matched;
        }
        item->is_leaf = 0;
        item->t.child = new_node;
        return dyntrie_insert(&item->t.child, key + matched, value,
                              allow_replace, old_value);
    }

    if (!res) abort();
    if (!item) abort();
    if (!*key) {
        if (!item->is_leaf) abort();
        if (allow_replace) {
            if (old_value) *old_value = item->t.value;
            item->t.value = value;
        }
        return 0;
    }
    if (!key[matched] && item->is_leaf) {
        if (allow_replace) {
            if (old_value) *old_value = item->t.value;
            item->t.value = value;
        }
        return 0;
    }
    if (item->is_leaf) {
        struct dyntrie_node *new_node = calloc(2, sizeof(*new_node));
        new_node->reserved = 2;
        new_node->size = 1;
        new_node->children = calloc(new_node->reserved, sizeof(new_node->children[0]));
        struct dyntrie_item *new_item = &new_node->children[0];
        new_item->is_leaf = 1;
        new_item->t.value = item->t.value;
        new_item->key_length = 0;
        item->is_leaf = 0;
        item->t.child = new_node;
        return dyntrie_insert(&item->t.child, key + matched, value,
                              allow_replace, old_value);
    }
    return dyntrie_insert(&item->t.child, key + matched, value,
                          allow_replace, old_value);
}

// 0 - key not found
// 1 - key found and value replaced
int
dyntrie_update(
        struct dyntrie_node **root,
        const unsigned char *key,
        void *value,
        void **old_value)
{
    if (!root || !key) return 0;
    const unsigned char *s = key;
    struct dyntrie_node *ptr = *root;
    while (ptr) {
        struct dyntrie_item *item = NULL;
        uint32_t matched = 0;
        int res = dyntrie_lookup(ptr, s, NULL, &item, &matched);
        if (!res) {
            return 0;
        }
        if (!*s) {
            if (!item) abort();
            if (!item->is_leaf) abort();
            if (old_value) *old_value = item->t.value;
            item->t.value = value;
            return 1;
        }
        if (item->is_leaf) {
            if (s[matched]) abort();
            if (old_value) *old_value = item->t.value;
            item->t.value = value;
            return 1;
        }
        s += matched;
        ptr = item->t.child;
    }
    return 0;
}

void *
dyntrie_get(
        struct dyntrie_node **root,
        const unsigned char *key)
{
    if (!root || !key) return NULL;
    const unsigned char *s = key;
    struct dyntrie_node *ptr = *root;
    while (ptr) {
        struct dyntrie_item *item = NULL;
        uint32_t matched = 0;
        int res = dyntrie_lookup(ptr, s, NULL, &item, &matched);
        if (!res) {
            return NULL;
        }
        if (!*s) {
            if (!item) abort();
            if (!item->is_leaf) abort();
            return item->t.value;
        }
        if (item->is_leaf) {
            if (s[matched]) abort();
            return item->t.value;
        }
        s += matched;
        ptr = item->t.child;
    }
    return NULL;
}

// 0 - key not found
// 1 - key found and removed
int
dyntrie_remove(
        struct dyntrie_node **root,
        const unsigned char *key,
        void **old_value)
{
    if (!root) return 0;
    struct dyntrie_node *node = *root;
    uint32_t index = 0;
    struct dyntrie_item *item = NULL;
    uint32_t matched = 0;
    int res = dyntrie_lookup(node, key, &index, &item, &matched);
    if (!res) return 0;
    if (!*key) {
        if (!item) abort();
        if (!item->is_leaf) abort();
        if (item->key_length > 1) abort();
        if (old_value) *old_value = item->t.value;
        item->t.value = NULL;
        if (node->size == 1) {
            free(node->children);
            free(node);
            *root = NULL;
            return 1;
        }
        if (index) abort();
        memmove(&node->children[0], &node->children[1],
                (node->size - 1) * sizeof(node->children[0]));
        --node->size;
        return 1;
    }
    if (matched != item->key_length) abort();
    if (item->is_leaf) {
        if (key[matched]) return 0;
        if (old_value) *old_value = item->t.value;
        item->t.value = NULL;
        if (item->key_length > sizeof(item->k.str)) {
            free(item->k.ptr);
        }
        if (node->size == 1) {
            free(node->children);
            free(node);
            *root = NULL;
            return 1;
        }
        if (index < node->size - 1) {
            memmove(&node->children[index], &node->children[index + 1],
                    (node->size - index - 1) * sizeof(node->children[0]));
        }
        --node->size;
        return 1;
    }

    res = dyntrie_remove(&item->t.child, key + matched, old_value);
    if (!res) return 0;
    struct dyntrie_node *node2 = item->t.child;
    if (!node2) {
        if (item->key_length > sizeof(item->k.str)) {
            free(item->k.str);
        }
        if (node->size == 1) {
            free(node->children);
            free(node);
            *root = NULL;
            return 1;
        }
        if (index < node->size - 1) {
            memmove(&node->children[index], &node->children[index + 1],
                    (node->size - index - 1) * sizeof(node->children[0]));
        }
        --node->size;
        return 1;
    }
    if (!node2->size) abort();
    if (node2->size > 1) return 1;
    struct dyntrie_item *item2 = &node2->children[0];
    if (item2->key_length == 0 ||
        (item2->key_length == 1 && !item2->k.str[0])) {
        item->is_leaf = item2->is_leaf;
        if (item->is_leaf) {
            item->t.value = item2->t.value;
        } else {
            item->t.child = item2->t.child;
        }
        free(node2->children);
        free(node2);
        return 1;
    }
    if (item->key_length + item2->key_length <= sizeof(item->k.str)) {
        memcpy(item->k.str + item->key_length, item2->k.str, item2->key_length);
    } else {
        unsigned char *new_str = malloc(item->key_length + item2->key_length);
        if (item->key_length <= sizeof(item->k.str)) {
            memcpy(new_str, item->k.str, item->key_length);
        } else {
            memcpy(new_str, item->k.ptr, item->key_length);
            free(item->k.ptr);
        }
        item->k.ptr = new_str;
        if (item2->key_length <= sizeof(item2->k.str)) {
            memcpy(new_str + item->key_length, item2->k.str, item2->key_length);
        } else {
            memcpy(new_str + item->key_length, item2->k.ptr, item2->key_length);
        }
    }
    item->key_length += item2->key_length;
    if (item2->key_length > sizeof(item2->k.str)) {
        free(item2->k.ptr);
    }
    item->is_leaf = item2->is_leaf;
    if (item->is_leaf) {
        item->t.value = item2->t.value;
    } else {
        item->t.child = item2->t.child;
    }
    free(node2->children);
    free(node2);
    return 1;
}

void
dyntrie_free(
        struct dyntrie_node **root,
        void (*value_free_func)(void *cntx, void *value),
        void *cntx)
{
    if (root && *root) {
        struct dyntrie_node *ptr = *root;
        for (uint32_t i = 0; i < ptr->size; ++i) {
            struct dyntrie_item *item = &ptr->children[i];
            if (item->key_length > sizeof(item->k.str)) {
                free(item->k.ptr);
            }
            if (item->is_leaf) {
                if (value_free_func) {
                    value_free_func(cntx, item->t.value);
                }
            } else {
                dyntrie_free(&item->t.child, value_free_func, cntx);
            }
        }
        free(ptr->children);
        free(ptr);
        *root = NULL;
    }
}

int
dyntrie_equal(
        const struct dyntrie_node *root1,
        const struct dyntrie_node *root2)
{
    if (!root1 && !root2) return 1;
    if (!root1) return 0;
    if (!root2) return 0;
    if (root1->size != root2->size) return 0;
    for (uint32_t i = 0; i < root1->size; ++i) {
        const struct dyntrie_item *item1 = &root1->children[i];
        const struct dyntrie_item *item2 = &root2->children[i];
        if (item1->key_length != item2->key_length) return 0;
        if (item1->key_length > sizeof(item1->k.str)) {
            if (memcmp(item1->k.ptr, item2->k.ptr, item1->key_length) != 0)
                return 0;
        } else if (item1->key_length > 0) {
            if (memcmp(item1->k.str, item2->k.str, item1->key_length) != 0)
                return 0;
        }
        if (item1->is_leaf != item2->is_leaf)
            return 0;
        if (!item1->is_leaf) {
            if (!dyntrie_equal(item1->t.child, item2->t.child))
                return 0;
        }
    }
    return 1;
}
