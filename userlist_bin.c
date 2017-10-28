/* -*- mode: c -*- */

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

#include "ejudge/userlist_bin.h"

#include "ejudge/logger.h"

#include <string.h>

#if 0
/* structure takes 40 bytes (without `name') on ia32 
   and 72 bytes (without `name') on x86_64
*/
struct xml_tree
{
  struct xml_tree *up, *first_down, *last_down, *left, *right;
  struct xml_attr *first, *last;
  unsigned short tag, column;
  int line;
  char *text;
  char *name[0];                /* when "default" node is enabled */
};
#endif

#if 0
struct userlist_list
{
  struct xml_tree b;

  unsigned char *name;
  int user_map_size;
  struct userlist_user **user_map;
  int member_serial;
  long long total;

  /* login hash information */
  size_t login_hash_size;
  size_t login_hash_step;
  size_t login_thresh;
  size_t login_cur_fill;
  struct userlist_user **login_hash_table;

  /* login cookie information */
  size_t cookie_hash_size;
  size_t cookie_hash_step;
  size_t cookie_thresh;
  size_t cookie_cur_fill;
  struct userlist_cookie **cookie_hash_table;

  /* client_key information */
  size_t client_key_hash_size;
  size_t client_key_hash_step;
  size_t client_key_thresh;
  size_t client_key_cur_fill;
  struct userlist_cookie **client_key_hash_table;

  /* user group information */
  struct xml_tree *groups_node;
  int group_map_size;
  struct userlist_group **group_map;

  /* group hash information */
  size_t group_hash_size;
  size_t group_hash_step;
  size_t group_thresh;
  size_t group_cur_fill;
  struct userlist_group **group_hash_table;

  /* group members information */
  struct xml_tree *groupmembers_node;
};
#endif

#define align16(x) (((x) + 15U) & ~15U)

static size_t
strsize(const unsigned char *str)
{
    return str?(strlen(str) + 1):0;
}

static void
userlist_bin_calculate_user_size(
        UserlistBinaryHeader *header,
        const struct userlist_user *u,
        int contest_id)
{
    if (!u) return;

    // find in contest registrations
    if (!u->contests) return;
    const struct userlist_contest *uc = NULL;
    for (const struct xml_tree *p = u->contests->first_down; p; p = p->right) {
        ASSERT(p->tag == USERLIST_T_CONTEST);
        const struct userlist_contest *uctmp = (const struct userlist_contest *) p;
        if (uc->id == contest_id) {
            uc = uctmp;
            break;
        }
    }
    if (!uc) return;

    // find in user_info
    const struct userlist_user_info *ui = NULL;
    if (contest_id > 0 && contest_id < u->cntsinfo_a) {
        ui = u->cntsinfo[contest_id];
    }
    if (!ui) ui = u->cntsinfo[0];
    if (!ui) ui = u->cnts0;
    (void) ui;

    // summ up strings
    header->string_size += strsize(u->login);
    header->string_size += strsize(u->email);
    header->string_size += strsize(u->passwd);
    header->string_size += strsize(u->extra1);

    if (ui) {
        header->string_size += strsize(ui->name);
        header->string_size += strsize(ui->team_passwd);
        header->string_size += strsize(ui->inst);
        header->string_size += strsize(ui->inst_en);
        header->string_size += strsize(ui->instshort);
        header->string_size += strsize(ui->instshort_en);
        header->string_size += strsize(ui->fac);
        header->string_size += strsize(ui->fac_en);
        header->string_size += strsize(ui->facshort);
        header->string_size += strsize(ui->facshort_en);
        header->string_size += strsize(ui->homepage);
        header->string_size += strsize(ui->city);
        header->string_size += strsize(ui->city_en);
        header->string_size += strsize(ui->country);
        header->string_size += strsize(ui->country_en);
        header->string_size += strsize(ui->region);
        header->string_size += strsize(ui->area);
        header->string_size += strsize(ui->zip);
        header->string_size += strsize(ui->street);
        header->string_size += strsize(ui->location);
        header->string_size += strsize(ui->spelling);
        header->string_size += strsize(ui->printer_name);
        header->string_size += strsize(ui->exam_id);
        header->string_size += strsize(ui->exam_cypher);
        header->string_size += strsize(ui->languages);
        header->string_size += strsize(ui->phone);
        header->string_size += strsize(ui->field0);
        header->string_size += strsize(ui->field1);
        header->string_size += strsize(ui->field2);
        header->string_size += strsize(ui->field3);
        header->string_size += strsize(ui->field4);
        header->string_size += strsize(ui->field5);
        header->string_size += strsize(ui->field6);
        header->string_size += strsize(ui->field7);
        header->string_size += strsize(ui->field8);
        header->string_size += strsize(ui->field9);
        header->string_size += strsize(ui->avatar_store);
        header->string_size += strsize(ui->avatar_id);
        header->string_size += strsize(ui->avatar_suffix);
    }
}

void
userlist_bin_calculate_size(
        UserlistBinaryHeader *header,
        const struct userlist_list *ul,
        int contest_id)
{
    memset(header, 0, sizeof(*header));
    header->endianness = 1;
    header->ptr_size = sizeof(void*);
    header->version = USERLIST_BIN_VERSION;
    header->userlist_list_size = align16(sizeof(struct userlist_list));
    header->userlist_user_size = align16(sizeof(struct userlist_user));
    header->userlist_info_size = align16(sizeof(struct userlist_user_info));
    header->struct_size += align16(sizeof(struct userlist_list));
    header->struct_size += align16(ul->user_map_size * sizeof(ul->user_map[0]));

    for (int user_id = 1; user_id < ul->user_map_size; ++user_id) {
        userlist_bin_calculate_user_size(header, ul->user_map[user_id], contest_id);
    }
}
