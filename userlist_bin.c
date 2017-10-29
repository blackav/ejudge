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
#include "ejudge/xalloc.h"

#include <string.h>

enum { FIRST_DATA_ITEM_OFFSET = 16 };

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

static unsigned char *
ulstrdup(UserlistBinaryHeader *header, const unsigned char *str)
{
    if (!str) return NULL;
    size_t len = strlen(str);
    unsigned char *dst = header->data + header->cur_string_offset;
    header->cur_string_offset += len + 1;
    memcpy(dst, str, len + 1);
    return (unsigned char *)(dst - header->data);
}

static void *
ulalloc(UserlistBinaryHeader *header, size_t size)
{
    if (!size) size = 1;
    size = align16(size);
    unsigned char *dst = header->data + header->cur_struct_offset;
    memset(dst, 0, size);
    header->cur_struct_offset += size;
    return dst;
}

/*static*/ void
userlist_bin_calculate_member_size(
        UserlistBinaryHeader *header,
        const struct userlist_member *m)
{
  if (!m) return;

  header->struct_size += align16(sizeof(struct userlist_member));

  header->string_size += strsize(m->firstname);
  header->string_size += strsize(m->firstname_en);
  header->string_size += strsize(m->middlename);
  header->string_size += strsize(m->middlename_en);
  header->string_size += strsize(m->surname);
  header->string_size += strsize(m->surname_en);
  header->string_size += strsize(m->group);
  header->string_size += strsize(m->group_en);
  header->string_size += strsize(m->email);
  header->string_size += strsize(m->homepage);
  header->string_size += strsize(m->occupation);
  header->string_size += strsize(m->occupation_en);
  header->string_size += strsize(m->discipline);
  header->string_size += strsize(m->inst);
  header->string_size += strsize(m->inst_en);
  header->string_size += strsize(m->instshort);
  header->string_size += strsize(m->instshort_en);
  header->string_size += strsize(m->fac);
  header->string_size += strsize(m->fac_en);
  header->string_size += strsize(m->facshort);
  header->string_size += strsize(m->facshort_en);
  header->string_size += strsize(m->phone);
}

void
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

    if (u->id > header->max_user_id) header->max_user_id = u->id;

    header->struct_size += align16(sizeof(*u));
    header->struct_size += align16(sizeof(struct xml_tree));
    header->struct_size += align16(sizeof(struct userlist_contest));

    // find in user_info
    const struct userlist_user_info *ui = userlist_get_user_info(u, contest_id);
    if (!ui) ui = u->cnts0;

    // summ up strings
    header->string_size += strsize(u->login);
    header->string_size += strsize(u->email);
    header->string_size += strsize(u->passwd);
    header->string_size += strsize(u->extra1);

    if (ui) {
        header->struct_size += align16(sizeof(struct xml_tree));
        header->struct_size += align16(sizeof(u->cis[0]));
        header->struct_size += align16(sizeof(*ui));

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

        if (ui->members && ui->members->u > 0) {
            header->struct_size += align16(sizeof(struct userlist_members));
            header->struct_size += align16(sizeof(struct userlist_member *) * ui->members->u);
            for (int i = 0; i < ui->members->u; ++i) {
                userlist_bin_calculate_member_size(header, ui->members->m[i]);
            }
        }
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
    header->userlist_member_size = align16(sizeof(struct userlist_member));
    header->struct_size += align16(sizeof(struct userlist_list));
    header->struct_size += align16(ul->user_map_size * sizeof(ul->user_map[0]));

    for (int user_id = 1; user_id < ul->user_map_size; ++user_id) {
        userlist_bin_calculate_user_size(header, ul->user_map[user_id], contest_id);
    }

    header->struct_size = align16(header->struct_size) + FIRST_DATA_ITEM_OFFSET;
    header->string_size = align16(header->string_size);
    header->size = header->struct_size + header->string_size;
}

void
userlist_bin_init_header(
        UserlistBinaryHeader *header)
{
    memset(header, 0, sizeof(*header));
    header->endianness = 1;
    header->ptr_size = sizeof(void*);
    header->version = USERLIST_BIN_VERSION;
    header->userlist_list_size = align16(sizeof(struct userlist_list));
    header->userlist_user_size = align16(sizeof(struct userlist_user));
    header->userlist_info_size = align16(sizeof(struct userlist_user_info));
    header->userlist_member_size = align16(sizeof(struct userlist_member));
}

void
userlist_bin_finish_header(
        UserlistBinaryHeader *header)
{
    header->struct_size += align16(sizeof(struct userlist_list));
    header->struct_size += align16((header->max_user_id + 1) * sizeof(struct userlist_user *));
    header->struct_size = align16(header->struct_size) + FIRST_DATA_ITEM_OFFSET;
    header->string_size = align16(header->string_size);
    header->size = header->struct_size + header->string_size;
    header->pkt_size = header->size + sizeof(UserlistBinaryHeader);
}

static struct userlist_member *
userlist_bin_marshall_member(
        UserlistBinaryHeader *header,
        const struct userlist_member *m)
{
    if (!m) return NULL;

    struct userlist_member *dm = ulalloc(header, sizeof(*dm));
    dm->b.tag = m->b.tag;

    dm->team_role = m->team_role;
    dm->serial = m->serial;
    dm->copied_from = m->copied_from;
    dm->status = m->status;
    dm->gender = m->gender;
    dm->grade = m->grade;

    dm->firstname = ulstrdup(header, m->firstname);
    dm->firstname_en = ulstrdup(header, m->firstname_en);
    dm->middlename = ulstrdup(header, m->middlename);
    dm->middlename_en = ulstrdup(header, m->middlename_en);
    dm->surname = ulstrdup(header, m->surname);
    dm->surname_en = ulstrdup(header, m->surname_en);
    dm->group = ulstrdup(header, m->group);
    dm->group_en = ulstrdup(header, m->group_en);
    dm->email = ulstrdup(header, m->email);
    dm->homepage = ulstrdup(header, m->homepage);
    dm->occupation = ulstrdup(header, m->occupation);
    dm->occupation_en = ulstrdup(header, m->occupation_en);
    dm->discipline = ulstrdup(header, m->discipline);
    dm->inst = ulstrdup(header, m->inst);
    dm->inst_en = ulstrdup(header, m->inst_en);
    dm->instshort = ulstrdup(header, m->instshort);
    dm->instshort_en = ulstrdup(header, m->instshort_en);
    dm->fac = ulstrdup(header, m->fac);
    dm->fac_en = ulstrdup(header, m->fac_en);
    dm->facshort = ulstrdup(header, m->facshort);
    dm->facshort_en = ulstrdup(header, m->facshort_en);
    dm->phone = ulstrdup(header, m->phone);

    dm->birth_date = m->birth_date;
    dm->entry_date = m->entry_date;
    dm->graduation_date = m->graduation_date;
    dm->create_time = m->create_time;
    dm->last_change_time = m->last_change_time;
    dm->last_access_time = m->last_access_time;

    return dm;
}

void
userlist_bin_marshall_user(
        UserlistBinaryHeader *header,
        const struct userlist_user *u,
        int contest_id)
{
    if (!u) return;
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

    struct userlist_list *dul = (struct userlist_list *) (header->data + header->root_offset);

    struct userlist_user *du = ulalloc(header, sizeof(*du));
    du->b.tag = USERLIST_T_USER;
    xml_link_node_last(&dul->b, &du->b);

    ASSERT(du->id < dul->user_map_size);
    dul->user_map[du->id] = du;

    du->id = u->id;
    du->is_privileged = u->is_privileged;
    du->is_invisible = u->is_invisible;
    du->is_banned = u->is_banned;
    du->is_locked = u->is_locked;
    du->show_login = u->show_login;
    du->show_email = u->show_email;
    du->read_only = u->read_only;
    du->never_clean = u->never_clean;
    du->simple_registration = u->simple_registration;
    du->login = ulstrdup(header, u->login);
    du->email = ulstrdup(header, u->email);
    du->passwd_method = u->passwd_method;
    du->passwd = ulstrdup(header, u->passwd);
    du->extra1 = ulstrdup(header, u->extra1);
    du->registration_time = u->registration_time;
    du->last_login_time = u->last_login_time;
    du->last_minor_change_time = u->last_minor_change_time;
    du->last_change_time = u->last_change_time;
    du->last_access_time = u->last_access_time;
    du->last_pwdchange_time = u->last_pwdchange_time;

    struct xml_tree *contests = ulalloc(header, sizeof(*contests));
    contests->tag = USERLIST_T_CONTESTS;
    xml_link_node_last(&du->b, contests);
    struct userlist_contest *duc = ulalloc(header, sizeof(*duc));
    duc->b.tag = USERLIST_T_CONTEST;
    xml_link_node_last(contests, &duc->b);
    duc->id = uc->id;
    duc->status = uc->status;
    duc->flags = uc->flags;
    duc->create_time = uc->create_time;
    duc->last_change_time = uc->last_change_time;

    const struct userlist_user_info *ui = userlist_get_user_info(u, contest_id);
    if (!ui) ui = u->cnts0;
    if (ui) {
        struct userlist_user_info *dui = ulalloc(header, sizeof(*dui));
        dui->b.tag = USERLIST_T_CNTSINFO;
        struct xml_tree *p = ulalloc(header, sizeof(*p));
        p->tag = USERLIST_T_CNTSINFOS;
        du->cis_a = 1;
        du->cis = ulalloc(header, sizeof(du->cis[0]));
        xml_link_node_last(&du->b, p);
        xml_link_node_last(p, &dui->b);
        du->cnts0 = dui;

        dui->contest_id = ui->contest_id;
        dui->cnts_read_only = ui->cnts_read_only;
        dui->name = ulstrdup(header, ui->name);
        dui->instnum = ui->instnum;
        dui->team_passwd_method = ui->team_passwd_method;
        dui->team_passwd = ulstrdup(header, ui->team_passwd);

        dui->inst = ulstrdup(header, ui->inst);
        dui->inst_en = ulstrdup(header, ui->inst_en);
        dui->instshort = ulstrdup(header, ui->instshort);
        dui->instshort_en = ulstrdup(header, ui->instshort_en);
        dui->fac = ulstrdup(header, ui->fac);
        dui->fac_en = ulstrdup(header, ui->fac_en);
        dui->facshort = ulstrdup(header, ui->facshort);
        dui->facshort_en = ulstrdup(header, ui->facshort_en);
        dui->homepage = ulstrdup(header, ui->homepage);
        dui->city = ulstrdup(header, ui->city);
        dui->city_en = ulstrdup(header, ui->city_en);
        dui->country = ulstrdup(header, ui->country);
        dui->country_en = ulstrdup(header, ui->country_en);
        dui->region = ulstrdup(header, ui->region);
        dui->area = ulstrdup(header, ui->area);
        dui->zip = ulstrdup(header, ui->zip);
        dui->street = ulstrdup(header, ui->street);
        dui->location = ulstrdup(header, ui->location);
        dui->spelling = ulstrdup(header, ui->spelling);
        dui->printer_name = ulstrdup(header, ui->printer_name);
        dui->exam_id = ulstrdup(header, ui->exam_id);
        dui->exam_cypher = ulstrdup(header, ui->exam_cypher);
        dui->languages = ulstrdup(header, ui->languages);
        dui->phone = ulstrdup(header, ui->phone);
        dui->field0 = ulstrdup(header, ui->field0);
        dui->field1 = ulstrdup(header, ui->field1);
        dui->field2 = ulstrdup(header, ui->field2);
        dui->field3 = ulstrdup(header, ui->field3);
        dui->field4 = ulstrdup(header, ui->field4);
        dui->field5 = ulstrdup(header, ui->field5);
        dui->field6 = ulstrdup(header, ui->field6);
        dui->field7 = ulstrdup(header, ui->field7);
        dui->field8 = ulstrdup(header, ui->field8);
        dui->field9 = ulstrdup(header, ui->field9);
        dui->avatar_store = ulstrdup(header, ui->avatar_store);
        dui->avatar_id = ulstrdup(header, ui->avatar_id);
        dui->avatar_suffix = ulstrdup(header, ui->avatar_suffix);
        dui->create_time = ui->create_time;
        dui->last_login_time = ui->last_login_time;
        dui->last_change_time = ui->last_change_time;
        dui->last_access_time = ui->last_access_time;
        dui->last_pwdchange_time = ui->last_pwdchange_time;

        if (ui->members && ui->members->u > 0) {
            struct userlist_members *members = ulalloc(header, sizeof(*members));
            dui->members = members;
            xml_link_node_last(&dui->b, &members->b);
            members->u = ui->members->u;
            members->a = ui->members->u;
            members->m = ulalloc(header, sizeof(members->m[0]) * members->a);
            for (int i = 0; i < ui->members->u; ++i) {
                struct userlist_member *dm = userlist_bin_marshall_member(header, ui->members->m[i]);
                members->m[i] = dm;
                xml_link_node_last(&members->b, &dm->b);
            }
        }
    }

    return;
}

UserlistBinaryHeader *
userlist_bin_marshall(
        void *dst,
        const UserlistBinaryHeader *in_header,
        const struct userlist_list *ul,
        int contest_id)
{
    UserlistBinaryHeader *header = dst;
    if (!header) header = xmalloc(in_header->size);
    memcpy(header, in_header, sizeof(*header));
    header->cur_struct_offset = FIRST_DATA_ITEM_OFFSET;
    header->cur_string_offset = header->struct_size;
    header->root_offset = FIRST_DATA_ITEM_OFFSET;

    struct userlist_list *dul = ulalloc(header, sizeof(*dul));
    dul->b.tag = USERLIST_T_USERLIST;
    dul->user_map_size = ul->user_map_size;
    if (dul->user_map_size > 0) {
        dul->user_map = ulalloc(header, dul->user_map_size * sizeof(dul->user_map[0]));
    }
    dul->member_serial = ul->member_serial;
    dul->total = ul->total;
    for (int user_id = 1; user_id < ul->user_map_size; ++user_id) {
        userlist_bin_marshall_user(header, ul->user_map[user_id], contest_id);
    }
    // fix pointers
    return header;
}

UserlistBinaryHeader *
userlist_bin_marshall_start(
        void *dst,
        const UserlistBinaryHeader *in_header,
        int contest_id)
{
    UserlistBinaryHeader *header = dst;
    if (!header) header = xmalloc(in_header->size);
    memcpy(header, in_header, sizeof(*header));
    header->cur_struct_offset = FIRST_DATA_ITEM_OFFSET;
    header->cur_string_offset = header->struct_size;
    header->root_offset = FIRST_DATA_ITEM_OFFSET;
    header->contest_id = contest_id;

    struct userlist_list *dul = ulalloc(header, sizeof(*dul));
    dul->b.tag = USERLIST_T_USERLIST;
    dul->user_map_size = header->max_user_id + 1;
    if (dul->user_map_size > 0) {
        dul->user_map = ulalloc(header, dul->user_map_size * sizeof(dul->user_map[0]));
    }

    return header;
}

void
userlist_bin_marshall_end(
        UserlistBinaryHeader *header)
{
    ASSERT(header->cur_struct_offset <= header->struct_size);
    ASSERT(header->cur_string_offset <= header->struct_size + header->string_size);

    // fix pointers
}
