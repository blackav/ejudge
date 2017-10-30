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

enum { FIRST_DATA_ITEM_OFFSET = 16, FIRST_STRING_ITEM_OFFSET = 1 };

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

#define align16(x) (((x) + 15U) & ~15U)
#define make_offset(cntx, ptr) (((unsigned char *)(ptr)) - (cntx)->d.v)
#define make_offset_ptr(cntx, ptr) ((void*)(((unsigned char *)(ptr)) - (cntx)->d.v))

static unsigned char *
ulstrdup(UserlistBinaryContext *cntx, const unsigned char *str)
{
    if (!str) return NULL;
    size_t size = strlen(str) + 1;
    if (cntx->s.u + size > cntx->s.a) {
        while (cntx->s.u + size > cntx->s.a)
            cntx->s.a *= 2;
        cntx->s.v = xrealloc(cntx->s.v, cntx->s.a * sizeof(cntx->s.v[0]));
    }
    unsigned char *dst = cntx->s.v + cntx->s.u;
    cntx->s.u += size;
    memcpy(dst, str, size);
    return (unsigned char *)(dst - cntx->s.v);
}

static void
ulreserve(UserlistBinaryContext *cntx, size_t size)
{
    if (cntx->d.u + size > cntx->d.a) {
        while (cntx->d.u + size > cntx->d.a) {
            cntx->d.a *= 2;
        }
        cntx->d.v = xrealloc(cntx->d.v, cntx->d.a * sizeof(cntx->d.v[0]));
    }
}

static void *
ulalloc(UserlistBinaryContext *cntx, size_t size)
{
    if (!size) size = 1;
    size = align16(size);
    if (cntx->d.u + size > cntx->d.a) {
        ulreserve(cntx, size);
    }
    unsigned char *dst = cntx->d.v + cntx->d.u;
    cntx->d.u += size;
    memset(dst, 0, size);
    return dst;
}

static void
register_userlist_user(UserlistBinaryContext *cntx, int user_id, struct userlist_user *u)
{
    if (user_id <= 0) return;
    if (user_id >= cntx->user_offsets_size) {
        size_t new_size = cntx->user_offsets_size;
        if (!new_size) new_size = 1024;
        while (user_id >= new_size) {
            new_size *= 2;
        }
        size_t *p;
        p = cntx->user_offsets = realloc(cntx->user_offsets, new_size * sizeof(p[0]));
        memset(&p[cntx->user_offsets_size], 0, (new_size - cntx->user_offsets_size) * sizeof(p[0]));
        cntx->user_offsets_size = new_size;
    }
    ASSERT(!cntx->user_offsets[user_id]);
    cntx->user_offsets[user_id] = (unsigned char *) u - cntx->d.v;
    if (user_id > cntx->max_user_id) cntx->max_user_id = user_id;
}

void
userlist_bin_init_context(UserlistBinaryContext *cntx)
{
    memset(cntx, 0, sizeof(*cntx));
    cntx->d.a = 1024;
    cntx->d.v = xmalloc(cntx->d.a);
    cntx->d.u = FIRST_DATA_ITEM_OFFSET;
    cntx->s.a = 1024;
    cntx->s.v = xmalloc(cntx->s.a);
    cntx->s.u = FIRST_STRING_ITEM_OFFSET;
}

static struct userlist_member *
userlist_bin_marshall_member(
        UserlistBinaryContext *cntx,
        const struct userlist_member *m)
{
    if (!m) return NULL;

    struct userlist_member *dm = ulalloc(cntx, sizeof(*dm));
    dm->b.tag = m->b.tag;

    dm->team_role = m->team_role;
    dm->serial = m->serial;
    dm->copied_from = m->copied_from;
    dm->status = m->status;
    dm->gender = m->gender;
    dm->grade = m->grade;

    dm->firstname = ulstrdup(cntx, m->firstname);
    dm->firstname_en = ulstrdup(cntx, m->firstname_en);
    dm->middlename = ulstrdup(cntx, m->middlename);
    dm->middlename_en = ulstrdup(cntx, m->middlename_en);
    dm->surname = ulstrdup(cntx, m->surname);
    dm->surname_en = ulstrdup(cntx, m->surname_en);
    dm->group = ulstrdup(cntx, m->group);
    dm->group_en = ulstrdup(cntx, m->group_en);
    dm->email = ulstrdup(cntx, m->email);
    dm->homepage = ulstrdup(cntx, m->homepage);
    dm->occupation = ulstrdup(cntx, m->occupation);
    dm->occupation_en = ulstrdup(cntx, m->occupation_en);
    dm->discipline = ulstrdup(cntx, m->discipline);
    dm->inst = ulstrdup(cntx, m->inst);
    dm->inst_en = ulstrdup(cntx, m->inst_en);
    dm->instshort = ulstrdup(cntx, m->instshort);
    dm->instshort_en = ulstrdup(cntx, m->instshort_en);
    dm->fac = ulstrdup(cntx, m->fac);
    dm->fac_en = ulstrdup(cntx, m->fac_en);
    dm->facshort = ulstrdup(cntx, m->facshort);
    dm->facshort_en = ulstrdup(cntx, m->facshort_en);
    dm->phone = ulstrdup(cntx, m->phone);

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
        UserlistBinaryContext *cntx,
        const struct userlist_user *u,
        int contest_id)
{
    if (!u) return;
    if (!u->contests) return;
    const struct userlist_contest *uc = NULL;
    for (const struct xml_tree *p = u->contests->first_down; p; p = p->right) {
        ASSERT(p->tag == USERLIST_T_CONTEST);
        const struct userlist_contest *uctmp = (const struct userlist_contest *) p;
        if (uctmp->id == contest_id) {
            uc = uctmp;
            break;
        }
    }
    if (!uc) return;

    // calculate reserve size
    size_t reserve_z = align16(sizeof(struct userlist_user));
    // for userlist_contest
    reserve_z += align16(sizeof(struct xml_tree));
    reserve_z += align16(sizeof(struct userlist_contest));
    // for user_info
    const struct userlist_user_info *ui = userlist_get_user_info(u, contest_id);
    if (!ui) ui = u->cnts0;
    if (ui) {
        reserve_z += align16(sizeof(struct xml_tree));
        reserve_z += align16(sizeof(struct userlist_user_info));
        reserve_z += align16(sizeof(struct userlist_user_info*));
        if (ui->members && ui->members->u > 0) {
            reserve_z += align16(sizeof(struct userlist_members));
            reserve_z += align16(ui->members->u * sizeof(struct userlist_member *));
            reserve_z += ui->members->u * align16(sizeof(struct userlist_member));
        }
    }
    ulreserve(cntx, reserve_z);

    struct userlist_user *du = ulalloc(cntx, sizeof(*du));
    du->b.tag = USERLIST_T_USER;
    register_userlist_user(cntx, u->id, du);

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
    du->login = ulstrdup(cntx, u->login);
    du->email = ulstrdup(cntx, u->email);
    du->passwd_method = u->passwd_method;
    du->passwd = ulstrdup(cntx, u->passwd);
    du->extra1 = ulstrdup(cntx, u->extra1);
    du->registration_time = u->registration_time;
    du->last_login_time = u->last_login_time;
    du->last_minor_change_time = u->last_minor_change_time;
    du->last_change_time = u->last_change_time;
    du->last_access_time = u->last_access_time;
    du->last_pwdchange_time = u->last_pwdchange_time;

    struct xml_tree *contests = ulalloc(cntx, sizeof(*contests));
    contests->tag = USERLIST_T_CONTESTS;
    xml_link_node_last(&du->b, contests);
    struct userlist_contest *duc = ulalloc(cntx, sizeof(*duc));
    duc->b.tag = USERLIST_T_CONTEST;
    xml_link_node_last(contests, &duc->b);
    duc->id = uc->id;
    duc->status = uc->status;
    duc->flags = uc->flags;
    duc->create_time = uc->create_time;
    duc->last_change_time = uc->last_change_time;

    if (ui) {
        struct userlist_user_info *dui = ulalloc(cntx, sizeof(*dui));
        dui->b.tag = USERLIST_T_CNTSINFO;
        struct xml_tree *p = ulalloc(cntx, sizeof(*p));
        p->tag = USERLIST_T_CNTSINFOS;
        du->cis_a = 1;
        du->cis = ulalloc(cntx, sizeof(du->cis[0]));
        du->cis[0] = dui;
        xml_link_node_last(&du->b, p);
        xml_link_node_last(p, &dui->b);
        du->cnts0 = dui;

        dui->contest_id = ui->contest_id;
        dui->cnts_read_only = ui->cnts_read_only;
        dui->name = ulstrdup(cntx, ui->name);
        dui->instnum = ui->instnum;
        dui->team_passwd_method = ui->team_passwd_method;
        dui->team_passwd = ulstrdup(cntx, ui->team_passwd);

        dui->inst = ulstrdup(cntx, ui->inst);
        dui->inst_en = ulstrdup(cntx, ui->inst_en);
        dui->instshort = ulstrdup(cntx, ui->instshort);
        dui->instshort_en = ulstrdup(cntx, ui->instshort_en);
        dui->fac = ulstrdup(cntx, ui->fac);
        dui->fac_en = ulstrdup(cntx, ui->fac_en);
        dui->facshort = ulstrdup(cntx, ui->facshort);
        dui->facshort_en = ulstrdup(cntx, ui->facshort_en);
        dui->homepage = ulstrdup(cntx, ui->homepage);
        dui->city = ulstrdup(cntx, ui->city);
        dui->city_en = ulstrdup(cntx, ui->city_en);
        dui->country = ulstrdup(cntx, ui->country);
        dui->country_en = ulstrdup(cntx, ui->country_en);
        dui->region = ulstrdup(cntx, ui->region);
        dui->area = ulstrdup(cntx, ui->area);
        dui->zip = ulstrdup(cntx, ui->zip);
        dui->street = ulstrdup(cntx, ui->street);
        dui->location = ulstrdup(cntx, ui->location);
        dui->spelling = ulstrdup(cntx, ui->spelling);
        dui->printer_name = ulstrdup(cntx, ui->printer_name);
        dui->exam_id = ulstrdup(cntx, ui->exam_id);
        dui->exam_cypher = ulstrdup(cntx, ui->exam_cypher);
        dui->languages = ulstrdup(cntx, ui->languages);
        dui->phone = ulstrdup(cntx, ui->phone);
        dui->field0 = ulstrdup(cntx, ui->field0);
        dui->field1 = ulstrdup(cntx, ui->field1);
        dui->field2 = ulstrdup(cntx, ui->field2);
        dui->field3 = ulstrdup(cntx, ui->field3);
        dui->field4 = ulstrdup(cntx, ui->field4);
        dui->field5 = ulstrdup(cntx, ui->field5);
        dui->field6 = ulstrdup(cntx, ui->field6);
        dui->field7 = ulstrdup(cntx, ui->field7);
        dui->field8 = ulstrdup(cntx, ui->field8);
        dui->field9 = ulstrdup(cntx, ui->field9);
        dui->avatar_store = ulstrdup(cntx, ui->avatar_store);
        dui->avatar_id = ulstrdup(cntx, ui->avatar_id);
        dui->avatar_suffix = ulstrdup(cntx, ui->avatar_suffix);
        dui->create_time = ui->create_time;
        dui->last_login_time = ui->last_login_time;
        dui->last_change_time = ui->last_change_time;
        dui->last_access_time = ui->last_access_time;
        dui->last_pwdchange_time = ui->last_pwdchange_time;

        if (ui->members && ui->members->u > 0) {
            struct userlist_members *members = ulalloc(cntx, sizeof(*members));
            members->b.tag = USERLIST_T_CONTESTANTS;
            dui->members = members;
            xml_link_node_last(&dui->b, &members->b);
            members->u = ui->members->u;
            members->a = ui->members->u;
            members->m = ulalloc(cntx, sizeof(members->m[0]) * members->a);
            for (int i = 0; i < ui->members->u; ++i) {
                struct userlist_member *dm = userlist_bin_marshall_member(cntx, ui->members->m[i]);
                members->m[i] = dm;
                xml_link_node_last(&members->b, &dm->b);
            }
        }
    }

    // FIX pointers

    return;
}

UserlistBinaryHeader *
userlist_bin_marshall(
        void *dst,
        const UserlistBinaryContext *cntx,
        int contest_id)
{
    UserlistBinaryHeader *header = dst;
    if (!header) header = xmalloc(cntx->total_size);
    memset(header, 0, sizeof(*header));
    header->endianness = 1;
    header->ptr_size = sizeof(void*);
    header->pkt_size = cntx->total_size;
    header->version = USERLIST_BIN_VERSION;
    header->userlist_list_size = align16(sizeof(struct userlist_list));
    header->userlist_user_size = align16(sizeof(struct userlist_user));
    header->userlist_info_size = align16(sizeof(struct userlist_user_info));
    header->userlist_member_size = align16(sizeof(struct userlist_member));
    header->size = cntx->d.u + cntx->s.u;
    header->struct_size = cntx->d.u;
    header->string_size = cntx->s.u;
    header->max_user_id = cntx->max_user_id;
    header->root_offset = cntx->root_offset;
    header->contest_id = contest_id;
    memcpy(header->data, cntx->d.v, cntx->d.u);
    memcpy(header->data + cntx->d.u, cntx->s.v, cntx->s.u);
    return header;
}

void
userlist_bin_marshall_user_list(
        UserlistBinaryContext *cntx,
        const struct userlist_list *ul,
        int contest_id)
{
    struct userlist_list *dul = ulalloc(cntx, sizeof(*dul));
    dul->b.tag = USERLIST_T_USERLIST;
    cntx->root_offset = make_offset(cntx, dul);
}

void
userlist_bin_finish_context(
        UserlistBinaryContext *cntx)
{
    cntx->s.u = align16(cntx->s.u);
    struct userlist_list *ul = (struct userlist_list *)(cntx->d.v + cntx->root_offset);
    if (cntx->max_user_id > 0) {
        ul->user_map_size = cntx->max_user_id + 1;
        ul->user_map = ulalloc(cntx, ul->user_map_size * sizeof(ul->user_map[0]));
        for (int i = 0; i < ul->user_map_size; ++i) {
            ul->user_map[i] = (struct userlist_user *) cntx->user_offsets[i];
            struct userlist_user *u = (struct userlist_user*) (cntx->d.v + cntx->user_offsets[i]);
            xml_link_node_last(&ul->b, &u->b);
        }
        // fix link pointers
        ul->user_map = make_offset_ptr(cntx, ul->user_map);
    }
    cntx->total_size = sizeof(UserlistBinaryHeader) + cntx->d.u + cntx->s.u;
}

void
userlist_bin_destroy_context(
        UserlistBinaryContext *cntx)
{
    xfree(cntx->d.v);
    xfree(cntx->s.v);
    xfree(cntx->user_offsets);
}
