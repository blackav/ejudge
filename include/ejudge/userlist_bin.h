/* -*- c -*- */

#ifndef __USERLIST_BIN_H__
#define __USERLIST_BIN_H__

/* Copyright (C) 2017 Alexander Chernov <cher@ejudge.ru> */

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

#include "userlist.h"

#include <stdint.h>

#define USERLIST_BIN_VERSION 1

/* binary transfer protocol indended for data transfer between ej-users and ej-contests */

typedef struct UserlistBinaryHeader
{
    unsigned short reply_id;       // reserved for userlist-server reply code
    unsigned char endianness;      // 1 - LE
    unsigned char ptr_size;        // 4 or 8
    uint32_t pkt_size;             // reserved for the total packed length of userlist-server reply
    int32_t version;               // packet version
    uint32_t size;                 // total size of data[]
    uint32_t struct_size;          // size of structured data
    uint32_t string_size;          // size of strings
    uint32_t userlist_list_size;   // sizeof(struct userlist_list) aligned to 16
    uint32_t userlist_user_size;   // sizeof(struct userlist_user)
    uint32_t userlist_info_size;   // sizeof(struct userlist_user_info)
    uint32_t userlist_member_size; // sizeof(struct userlist_member)
    uint32_t max_user_id;          // maximum user_id in the data
    uint32_t root_offset;          // offset from data[] to the root of the tree, currently 16
    int32_t contest_id;
    unsigned char pad3[12];
    unsigned char data[];
} UserlistBinaryHeader;

typedef struct UserlistBinaryBuf
{
    unsigned char *v;
    size_t u, a;
} UserlistBinaryBuf;

typedef struct UserlistBinaryContext
{
    UserlistBinaryBuf d;  // structured data (16-byte aligned)
    UserlistBinaryBuf s;  // string data
    uint32_t max_user_id; // maximum user_id in the data
    size_t  user_offsets_size;
    size_t *user_offsets;
    uint32_t root_offset;
    size_t total_size;
} UserlistBinaryContext;

void
userlist_bin_marshall_user_list(
        UserlistBinaryContext *cntx,
        const struct userlist_list *ul,
        int contest_id);

void
userlist_bin_marshall_user(
        UserlistBinaryContext *cntx,
        const struct userlist_user *u,
        int contest_id);

UserlistBinaryHeader *
userlist_bin_marshall(
        void *dst,
        const UserlistBinaryContext *cntx,
        int contest_id);

void
userlist_bin_init_context(
        UserlistBinaryContext *cntx);
void
userlist_bin_finish_context(
        UserlistBinaryContext *cntx);
void
userlist_bin_destroy_context(
        UserlistBinaryContext *cntx);

const struct userlist_list *
userlist_bin_unmarshall(UserlistBinaryHeader *header);
const struct userlist_list *
userlist_bin_get_root(const UserlistBinaryHeader *header);

#endif /* __USERLIST_BIN_H__ */
