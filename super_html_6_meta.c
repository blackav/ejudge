// This is an auto-generated file, do not edit
// Generated 2011/05/22 11:43:29

#include "super_html_6_meta.h"
#include "super_html_6.h"
#include "meta_generic.h"

#include "reuse_xalloc.h"

#include "reuse_logger.h"
#include <string.h>
#include <stdlib.h>

static struct meta_info_item meta_info_ss_op_param_USER_CREATE_ONE_ACTION_data[] =
{
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_contest_id] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_contest_id, '0', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, contest_id), "contest_id", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, contest_id) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_group_id] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_group_id, '0', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, group_id), "group_id", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, group_id) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_other_login] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_other_login, '1', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, other_login), "other_login", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, other_login) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_other_email] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_other_email, '2', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, other_email), "other_email", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, other_email) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_send_email] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_send_email, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, send_email), "send_email", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, send_email) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_confirm_email] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_confirm_email, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, confirm_email), "confirm_email", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, confirm_email) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_reg_password1] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_reg_password1, '1', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, reg_password1), "reg_password1", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, reg_password1) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_reg_password2] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_reg_password2, '1', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, reg_password2), "reg_password2", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, reg_password2) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_reg_sha1] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_reg_sha1, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, reg_sha1), "reg_sha1", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, reg_sha1) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_1] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_1, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, field_1), "field_1", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, field_1) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_2] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_2, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, field_2), "field_2", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, field_2) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_3] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_3, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, field_3), "field_3", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, field_3) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_4] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_4, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, field_4), "field_4", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, field_4) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_5] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_5, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, field_5), "field_5", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, field_5) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_6] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_6, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, field_6), "field_6", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, field_6) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_7] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_7, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, field_7), "field_7", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, field_7) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_8] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_8, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, field_8), "field_8", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, field_8) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_9] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_field_9, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, field_9), "field_9", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, field_9) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_reg_cnts_create] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_reg_cnts_create, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, reg_cnts_create), "reg_cnts_create", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, reg_cnts_create) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_other_contest_id_1] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_other_contest_id_1, '0', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, other_contest_id_1), "other_contest_id_1", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, other_contest_id_1) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_cnts_status] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_cnts_status, '4', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, cnts_status), "cnts_status", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, cnts_status) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_is_invisible] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_is_invisible, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, is_invisible), "is_invisible", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, is_invisible) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_is_banned] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_is_banned, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, is_banned), "is_banned", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, is_banned) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_is_locked] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_is_locked, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, is_locked), "is_locked", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, is_locked) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_is_incomplete] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_is_incomplete, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, is_incomplete), "is_incomplete", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, is_incomplete) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_is_disqualified] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_is_disqualified, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, is_disqualified), "is_disqualified", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, is_disqualified) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_cnts_use_reg_passwd] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_cnts_use_reg_passwd, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, cnts_use_reg_passwd), "cnts_use_reg_passwd", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, cnts_use_reg_passwd) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_cnts_null_passwd] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_cnts_null_passwd, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, cnts_null_passwd), "cnts_null_passwd", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, cnts_null_passwd) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_cnts_password1] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_cnts_password1, '2', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, cnts_password1), "cnts_password1", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, cnts_password1) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_cnts_password2] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_cnts_password2, '2', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, cnts_password2), "cnts_password2", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, cnts_password2) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_cnts_sha1] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_cnts_sha1, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, cnts_sha1), "cnts_sha1", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, cnts_sha1) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_cnts_name] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_cnts_name, '2', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, cnts_name), "cnts_name", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, cnts_name) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_group_create] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_group_create, '3', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, group_create), "group_create", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, group_create) },
  [META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_other_group_id] = { META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_other_group_id, '0', XSIZE(struct ss_op_param_USER_CREATE_ONE_ACTION, other_group_id), "other_group_id", XOFFSET(struct ss_op_param_USER_CREATE_ONE_ACTION, other_group_id) },
};

int meta_ss_op_param_USER_CREATE_ONE_ACTION_get_type(int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_LAST_FIELD);
  return meta_info_ss_op_param_USER_CREATE_ONE_ACTION_data[tag].type;
}

size_t meta_ss_op_param_USER_CREATE_ONE_ACTION_get_size(int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_LAST_FIELD);
  return meta_info_ss_op_param_USER_CREATE_ONE_ACTION_data[tag].size;
}

const char *meta_ss_op_param_USER_CREATE_ONE_ACTION_get_name(int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_LAST_FIELD);
  return meta_info_ss_op_param_USER_CREATE_ONE_ACTION_data[tag].name;
}

const void *meta_ss_op_param_USER_CREATE_ONE_ACTION_get_ptr(const struct ss_op_param_USER_CREATE_ONE_ACTION *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_ss_op_param_USER_CREATE_ONE_ACTION_data[tag].offset);
}

void *meta_ss_op_param_USER_CREATE_ONE_ACTION_get_ptr_nc(struct ss_op_param_USER_CREATE_ONE_ACTION *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_ss_op_param_USER_CREATE_ONE_ACTION_data[tag].offset);
}

int meta_ss_op_param_USER_CREATE_ONE_ACTION_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_ss_op_param_USER_CREATE_ONE_ACTION_data, META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods meta_ss_op_param_USER_CREATE_ONE_ACTION_methods =
{
  META_SS_OP_PARAM_USER_CREATE_ONE_ACTION_LAST_FIELD,
  sizeof(struct ss_op_param_USER_CREATE_ONE_ACTION),
  meta_ss_op_param_USER_CREATE_ONE_ACTION_get_type,
  meta_ss_op_param_USER_CREATE_ONE_ACTION_get_size,
  meta_ss_op_param_USER_CREATE_ONE_ACTION_get_name,
  (const void *(*)(const void *ptr, int tag))meta_ss_op_param_USER_CREATE_ONE_ACTION_get_ptr,
  (void *(*)(void *ptr, int tag))meta_ss_op_param_USER_CREATE_ONE_ACTION_get_ptr_nc,
  meta_ss_op_param_USER_CREATE_ONE_ACTION_lookup_field,
};

static struct meta_info_item meta_info_ss_op_param_USER_CREATE_MANY_ACTION_data[] =
{
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_contest_id] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_contest_id, '0', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, contest_id), "contest_id", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, contest_id) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_group_id] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_group_id, '0', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, group_id), "group_id", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, group_id) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_first_serial] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_first_serial, '5', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, first_serial), "first_serial", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, first_serial) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_last_serial] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_last_serial, '5', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, last_serial), "last_serial", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, last_serial) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_login_template] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_login_template, '1', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, login_template), "login_template", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, login_template) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_reg_random] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_reg_random, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, reg_random), "reg_random", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, reg_random) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_reg_password_template] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_reg_password_template, '2', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, reg_password_template), "reg_password_template", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, reg_password_template) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_reg_sha1] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_reg_sha1, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, reg_sha1), "reg_sha1", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, reg_sha1) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_1] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_1, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, field_1), "field_1", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, field_1) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_2] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_2, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, field_2), "field_2", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, field_2) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_3] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_3, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, field_3), "field_3", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, field_3) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_4] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_4, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, field_4), "field_4", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, field_4) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_5] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_5, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, field_5), "field_5", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, field_5) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_6] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_6, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, field_6), "field_6", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, field_6) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_7] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_7, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, field_7), "field_7", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, field_7) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_8] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_8, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, field_8), "field_8", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, field_8) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_9] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_field_9, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, field_9), "field_9", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, field_9) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_reg_cnts_create] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_reg_cnts_create, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, reg_cnts_create), "reg_cnts_create", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, reg_cnts_create) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_other_contest_id_1] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_other_contest_id_1, '0', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, other_contest_id_1), "other_contest_id_1", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, other_contest_id_1) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_cnts_status] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_cnts_status, '4', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, cnts_status), "cnts_status", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, cnts_status) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_is_invisible] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_is_invisible, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, is_invisible), "is_invisible", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, is_invisible) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_is_banned] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_is_banned, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, is_banned), "is_banned", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, is_banned) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_is_locked] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_is_locked, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, is_locked), "is_locked", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, is_locked) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_is_incomplete] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_is_incomplete, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, is_incomplete), "is_incomplete", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, is_incomplete) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_is_disqualified] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_is_disqualified, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, is_disqualified), "is_disqualified", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, is_disqualified) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_cnts_use_reg_passwd] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_cnts_use_reg_passwd, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, cnts_use_reg_passwd), "cnts_use_reg_passwd", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, cnts_use_reg_passwd) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_cnts_null_passwd] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_cnts_null_passwd, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, cnts_null_passwd), "cnts_null_passwd", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, cnts_null_passwd) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_cnts_random_passwd] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_cnts_random_passwd, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, cnts_random_passwd), "cnts_random_passwd", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, cnts_random_passwd) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_cnts_password_template] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_cnts_password_template, '2', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, cnts_password_template), "cnts_password_template", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, cnts_password_template) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_cnts_sha1] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_cnts_sha1, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, cnts_sha1), "cnts_sha1", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, cnts_sha1) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_cnts_name_template] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_cnts_name_template, '2', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, cnts_name_template), "cnts_name_template", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, cnts_name_template) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_group_create] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_group_create, '3', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, group_create), "group_create", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, group_create) },
  [META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_other_group_id] = { META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_other_group_id, '0', XSIZE(struct ss_op_param_USER_CREATE_MANY_ACTION, other_group_id), "other_group_id", XOFFSET(struct ss_op_param_USER_CREATE_MANY_ACTION, other_group_id) },
};

int meta_ss_op_param_USER_CREATE_MANY_ACTION_get_type(int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_LAST_FIELD);
  return meta_info_ss_op_param_USER_CREATE_MANY_ACTION_data[tag].type;
}

size_t meta_ss_op_param_USER_CREATE_MANY_ACTION_get_size(int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_LAST_FIELD);
  return meta_info_ss_op_param_USER_CREATE_MANY_ACTION_data[tag].size;
}

const char *meta_ss_op_param_USER_CREATE_MANY_ACTION_get_name(int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_LAST_FIELD);
  return meta_info_ss_op_param_USER_CREATE_MANY_ACTION_data[tag].name;
}

const void *meta_ss_op_param_USER_CREATE_MANY_ACTION_get_ptr(const struct ss_op_param_USER_CREATE_MANY_ACTION *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_ss_op_param_USER_CREATE_MANY_ACTION_data[tag].offset);
}

void *meta_ss_op_param_USER_CREATE_MANY_ACTION_get_ptr_nc(struct ss_op_param_USER_CREATE_MANY_ACTION *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_ss_op_param_USER_CREATE_MANY_ACTION_data[tag].offset);
}

int meta_ss_op_param_USER_CREATE_MANY_ACTION_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_ss_op_param_USER_CREATE_MANY_ACTION_data, META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods meta_ss_op_param_USER_CREATE_MANY_ACTION_methods =
{
  META_SS_OP_PARAM_USER_CREATE_MANY_ACTION_LAST_FIELD,
  sizeof(struct ss_op_param_USER_CREATE_MANY_ACTION),
  meta_ss_op_param_USER_CREATE_MANY_ACTION_get_type,
  meta_ss_op_param_USER_CREATE_MANY_ACTION_get_size,
  meta_ss_op_param_USER_CREATE_MANY_ACTION_get_name,
  (const void *(*)(const void *ptr, int tag))meta_ss_op_param_USER_CREATE_MANY_ACTION_get_ptr,
  (void *(*)(void *ptr, int tag))meta_ss_op_param_USER_CREATE_MANY_ACTION_get_ptr_nc,
  meta_ss_op_param_USER_CREATE_MANY_ACTION_lookup_field,
};

static struct meta_info_item meta_info_ss_op_param_USER_CREATE_FROM_CSV_ACTION_data[] =
{
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_contest_id] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_contest_id, '0', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, contest_id), "contest_id", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, contest_id) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_group_id] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_group_id, '0', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, group_id), "group_id", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, group_id) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_send_email] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_send_email, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, send_email), "send_email", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, send_email) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_confirm_email] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_confirm_email, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, confirm_email), "confirm_email", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, confirm_email) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_reg_random] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_reg_random, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, reg_random), "reg_random", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, reg_random) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_reg_sha1] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_reg_sha1, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, reg_sha1), "reg_sha1", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, reg_sha1) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_1] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_1, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_1), "field_1", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_1) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_2] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_2, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_2), "field_2", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_2) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_3] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_3, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_3), "field_3", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_3) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_4] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_4, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_4), "field_4", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_4) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_5] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_5, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_5), "field_5", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_5) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_6] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_6, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_6), "field_6", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_6) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_7] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_7, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_7), "field_7", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_7) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_8] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_8, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_8), "field_8", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_8) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_9] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_field_9, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_9), "field_9", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, field_9) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_reg_cnts_create] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_reg_cnts_create, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, reg_cnts_create), "reg_cnts_create", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, reg_cnts_create) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_other_contest_id_1] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_other_contest_id_1, '0', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, other_contest_id_1), "other_contest_id_1", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, other_contest_id_1) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_cnts_status] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_cnts_status, '4', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, cnts_status), "cnts_status", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, cnts_status) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_is_invisible] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_is_invisible, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, is_invisible), "is_invisible", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, is_invisible) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_is_banned] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_is_banned, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, is_banned), "is_banned", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, is_banned) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_is_locked] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_is_locked, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, is_locked), "is_locked", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, is_locked) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_is_incomplete] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_is_incomplete, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, is_incomplete), "is_incomplete", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, is_incomplete) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_is_disqualified] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_is_disqualified, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, is_disqualified), "is_disqualified", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, is_disqualified) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_cnts_use_reg_passwd] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_cnts_use_reg_passwd, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, cnts_use_reg_passwd), "cnts_use_reg_passwd", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, cnts_use_reg_passwd) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_cnts_null_passwd] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_cnts_null_passwd, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, cnts_null_passwd), "cnts_null_passwd", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, cnts_null_passwd) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_cnts_random_passwd] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_cnts_random_passwd, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, cnts_random_passwd), "cnts_random_passwd", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, cnts_random_passwd) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_cnts_sha1] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_cnts_sha1, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, cnts_sha1), "cnts_sha1", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, cnts_sha1) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_cnts_name_template] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_cnts_name_template, '2', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, cnts_name_template), "cnts_name_template", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, cnts_name_template) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_group_create] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_group_create, '3', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, group_create), "group_create", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, group_create) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_other_group_id] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_other_group_id, '0', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, other_group_id), "other_group_id", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, other_group_id) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_separator] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_separator, '2', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, separator), "separator", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, separator) },
  [META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_charset] = { META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_charset, '2', XSIZE(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, charset), "charset", XOFFSET(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION, charset) },
};

int meta_ss_op_param_USER_CREATE_FROM_CSV_ACTION_get_type(int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_LAST_FIELD);
  return meta_info_ss_op_param_USER_CREATE_FROM_CSV_ACTION_data[tag].type;
}

size_t meta_ss_op_param_USER_CREATE_FROM_CSV_ACTION_get_size(int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_LAST_FIELD);
  return meta_info_ss_op_param_USER_CREATE_FROM_CSV_ACTION_data[tag].size;
}

const char *meta_ss_op_param_USER_CREATE_FROM_CSV_ACTION_get_name(int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_LAST_FIELD);
  return meta_info_ss_op_param_USER_CREATE_FROM_CSV_ACTION_data[tag].name;
}

const void *meta_ss_op_param_USER_CREATE_FROM_CSV_ACTION_get_ptr(const struct ss_op_param_USER_CREATE_FROM_CSV_ACTION *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_ss_op_param_USER_CREATE_FROM_CSV_ACTION_data[tag].offset);
}

void *meta_ss_op_param_USER_CREATE_FROM_CSV_ACTION_get_ptr_nc(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_ss_op_param_USER_CREATE_FROM_CSV_ACTION_data[tag].offset);
}

int meta_ss_op_param_USER_CREATE_FROM_CSV_ACTION_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_ss_op_param_USER_CREATE_FROM_CSV_ACTION_data, META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods meta_ss_op_param_USER_CREATE_FROM_CSV_ACTION_methods =
{
  META_SS_OP_PARAM_USER_CREATE_FROM_CSV_ACTION_LAST_FIELD,
  sizeof(struct ss_op_param_USER_CREATE_FROM_CSV_ACTION),
  meta_ss_op_param_USER_CREATE_FROM_CSV_ACTION_get_type,
  meta_ss_op_param_USER_CREATE_FROM_CSV_ACTION_get_size,
  meta_ss_op_param_USER_CREATE_FROM_CSV_ACTION_get_name,
  (const void *(*)(const void *ptr, int tag))meta_ss_op_param_USER_CREATE_FROM_CSV_ACTION_get_ptr,
  (void *(*)(void *ptr, int tag))meta_ss_op_param_USER_CREATE_FROM_CSV_ACTION_get_ptr_nc,
  meta_ss_op_param_USER_CREATE_FROM_CSV_ACTION_lookup_field,
};

static struct meta_info_item meta_info_ss_op_param_USER_CREATE_REG_ACTION_data[] =
{
  [META_SS_OP_PARAM_USER_CREATE_REG_ACTION_other_user_id] = { META_SS_OP_PARAM_USER_CREATE_REG_ACTION_other_user_id, '0', XSIZE(struct ss_op_param_USER_CREATE_REG_ACTION, other_user_id), "other_user_id", XOFFSET(struct ss_op_param_USER_CREATE_REG_ACTION, other_user_id) },
  [META_SS_OP_PARAM_USER_CREATE_REG_ACTION_contest_id] = { META_SS_OP_PARAM_USER_CREATE_REG_ACTION_contest_id, '0', XSIZE(struct ss_op_param_USER_CREATE_REG_ACTION, contest_id), "contest_id", XOFFSET(struct ss_op_param_USER_CREATE_REG_ACTION, contest_id) },
  [META_SS_OP_PARAM_USER_CREATE_REG_ACTION_group_id] = { META_SS_OP_PARAM_USER_CREATE_REG_ACTION_group_id, '0', XSIZE(struct ss_op_param_USER_CREATE_REG_ACTION, group_id), "group_id", XOFFSET(struct ss_op_param_USER_CREATE_REG_ACTION, group_id) },
  [META_SS_OP_PARAM_USER_CREATE_REG_ACTION_other_contest_id_1] = { META_SS_OP_PARAM_USER_CREATE_REG_ACTION_other_contest_id_1, '0', XSIZE(struct ss_op_param_USER_CREATE_REG_ACTION, other_contest_id_1), "other_contest_id_1", XOFFSET(struct ss_op_param_USER_CREATE_REG_ACTION, other_contest_id_1) },
  [META_SS_OP_PARAM_USER_CREATE_REG_ACTION_status] = { META_SS_OP_PARAM_USER_CREATE_REG_ACTION_status, '4', XSIZE(struct ss_op_param_USER_CREATE_REG_ACTION, status), "status", XOFFSET(struct ss_op_param_USER_CREATE_REG_ACTION, status) },
  [META_SS_OP_PARAM_USER_CREATE_REG_ACTION_is_invisible] = { META_SS_OP_PARAM_USER_CREATE_REG_ACTION_is_invisible, '3', XSIZE(struct ss_op_param_USER_CREATE_REG_ACTION, is_invisible), "is_invisible", XOFFSET(struct ss_op_param_USER_CREATE_REG_ACTION, is_invisible) },
  [META_SS_OP_PARAM_USER_CREATE_REG_ACTION_is_banned] = { META_SS_OP_PARAM_USER_CREATE_REG_ACTION_is_banned, '3', XSIZE(struct ss_op_param_USER_CREATE_REG_ACTION, is_banned), "is_banned", XOFFSET(struct ss_op_param_USER_CREATE_REG_ACTION, is_banned) },
  [META_SS_OP_PARAM_USER_CREATE_REG_ACTION_is_locked] = { META_SS_OP_PARAM_USER_CREATE_REG_ACTION_is_locked, '3', XSIZE(struct ss_op_param_USER_CREATE_REG_ACTION, is_locked), "is_locked", XOFFSET(struct ss_op_param_USER_CREATE_REG_ACTION, is_locked) },
  [META_SS_OP_PARAM_USER_CREATE_REG_ACTION_is_incomplete] = { META_SS_OP_PARAM_USER_CREATE_REG_ACTION_is_incomplete, '3', XSIZE(struct ss_op_param_USER_CREATE_REG_ACTION, is_incomplete), "is_incomplete", XOFFSET(struct ss_op_param_USER_CREATE_REG_ACTION, is_incomplete) },
  [META_SS_OP_PARAM_USER_CREATE_REG_ACTION_is_disqualified] = { META_SS_OP_PARAM_USER_CREATE_REG_ACTION_is_disqualified, '3', XSIZE(struct ss_op_param_USER_CREATE_REG_ACTION, is_disqualified), "is_disqualified", XOFFSET(struct ss_op_param_USER_CREATE_REG_ACTION, is_disqualified) },
};

int meta_ss_op_param_USER_CREATE_REG_ACTION_get_type(int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_REG_ACTION_LAST_FIELD);
  return meta_info_ss_op_param_USER_CREATE_REG_ACTION_data[tag].type;
}

size_t meta_ss_op_param_USER_CREATE_REG_ACTION_get_size(int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_REG_ACTION_LAST_FIELD);
  return meta_info_ss_op_param_USER_CREATE_REG_ACTION_data[tag].size;
}

const char *meta_ss_op_param_USER_CREATE_REG_ACTION_get_name(int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_REG_ACTION_LAST_FIELD);
  return meta_info_ss_op_param_USER_CREATE_REG_ACTION_data[tag].name;
}

const void *meta_ss_op_param_USER_CREATE_REG_ACTION_get_ptr(const struct ss_op_param_USER_CREATE_REG_ACTION *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_REG_ACTION_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_ss_op_param_USER_CREATE_REG_ACTION_data[tag].offset);
}

void *meta_ss_op_param_USER_CREATE_REG_ACTION_get_ptr_nc(struct ss_op_param_USER_CREATE_REG_ACTION *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_CREATE_REG_ACTION_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_ss_op_param_USER_CREATE_REG_ACTION_data[tag].offset);
}

int meta_ss_op_param_USER_CREATE_REG_ACTION_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_ss_op_param_USER_CREATE_REG_ACTION_data, META_SS_OP_PARAM_USER_CREATE_REG_ACTION_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods meta_ss_op_param_USER_CREATE_REG_ACTION_methods =
{
  META_SS_OP_PARAM_USER_CREATE_REG_ACTION_LAST_FIELD,
  sizeof(struct ss_op_param_USER_CREATE_REG_ACTION),
  meta_ss_op_param_USER_CREATE_REG_ACTION_get_type,
  meta_ss_op_param_USER_CREATE_REG_ACTION_get_size,
  meta_ss_op_param_USER_CREATE_REG_ACTION_get_name,
  (const void *(*)(const void *ptr, int tag))meta_ss_op_param_USER_CREATE_REG_ACTION_get_ptr,
  (void *(*)(void *ptr, int tag))meta_ss_op_param_USER_CREATE_REG_ACTION_get_ptr_nc,
  meta_ss_op_param_USER_CREATE_REG_ACTION_lookup_field,
};

static struct meta_info_item meta_info_ss_op_param_USER_EDIT_REG_ACTION_data[] =
{
  [META_SS_OP_PARAM_USER_EDIT_REG_ACTION_other_user_id] = { META_SS_OP_PARAM_USER_EDIT_REG_ACTION_other_user_id, '0', XSIZE(struct ss_op_param_USER_EDIT_REG_ACTION, other_user_id), "other_user_id", XOFFSET(struct ss_op_param_USER_EDIT_REG_ACTION, other_user_id) },
  [META_SS_OP_PARAM_USER_EDIT_REG_ACTION_other_contest_id] = { META_SS_OP_PARAM_USER_EDIT_REG_ACTION_other_contest_id, '0', XSIZE(struct ss_op_param_USER_EDIT_REG_ACTION, other_contest_id), "other_contest_id", XOFFSET(struct ss_op_param_USER_EDIT_REG_ACTION, other_contest_id) },
  [META_SS_OP_PARAM_USER_EDIT_REG_ACTION_contest_id] = { META_SS_OP_PARAM_USER_EDIT_REG_ACTION_contest_id, '0', XSIZE(struct ss_op_param_USER_EDIT_REG_ACTION, contest_id), "contest_id", XOFFSET(struct ss_op_param_USER_EDIT_REG_ACTION, contest_id) },
  [META_SS_OP_PARAM_USER_EDIT_REG_ACTION_group_id] = { META_SS_OP_PARAM_USER_EDIT_REG_ACTION_group_id, '0', XSIZE(struct ss_op_param_USER_EDIT_REG_ACTION, group_id), "group_id", XOFFSET(struct ss_op_param_USER_EDIT_REG_ACTION, group_id) },
  [META_SS_OP_PARAM_USER_EDIT_REG_ACTION_next_op] = { META_SS_OP_PARAM_USER_EDIT_REG_ACTION_next_op, '0', XSIZE(struct ss_op_param_USER_EDIT_REG_ACTION, next_op), "next_op", XOFFSET(struct ss_op_param_USER_EDIT_REG_ACTION, next_op) },
  [META_SS_OP_PARAM_USER_EDIT_REG_ACTION_status] = { META_SS_OP_PARAM_USER_EDIT_REG_ACTION_status, '4', XSIZE(struct ss_op_param_USER_EDIT_REG_ACTION, status), "status", XOFFSET(struct ss_op_param_USER_EDIT_REG_ACTION, status) },
  [META_SS_OP_PARAM_USER_EDIT_REG_ACTION_is_invisible] = { META_SS_OP_PARAM_USER_EDIT_REG_ACTION_is_invisible, '3', XSIZE(struct ss_op_param_USER_EDIT_REG_ACTION, is_invisible), "is_invisible", XOFFSET(struct ss_op_param_USER_EDIT_REG_ACTION, is_invisible) },
  [META_SS_OP_PARAM_USER_EDIT_REG_ACTION_is_banned] = { META_SS_OP_PARAM_USER_EDIT_REG_ACTION_is_banned, '3', XSIZE(struct ss_op_param_USER_EDIT_REG_ACTION, is_banned), "is_banned", XOFFSET(struct ss_op_param_USER_EDIT_REG_ACTION, is_banned) },
  [META_SS_OP_PARAM_USER_EDIT_REG_ACTION_is_locked] = { META_SS_OP_PARAM_USER_EDIT_REG_ACTION_is_locked, '3', XSIZE(struct ss_op_param_USER_EDIT_REG_ACTION, is_locked), "is_locked", XOFFSET(struct ss_op_param_USER_EDIT_REG_ACTION, is_locked) },
  [META_SS_OP_PARAM_USER_EDIT_REG_ACTION_is_incomplete] = { META_SS_OP_PARAM_USER_EDIT_REG_ACTION_is_incomplete, '3', XSIZE(struct ss_op_param_USER_EDIT_REG_ACTION, is_incomplete), "is_incomplete", XOFFSET(struct ss_op_param_USER_EDIT_REG_ACTION, is_incomplete) },
  [META_SS_OP_PARAM_USER_EDIT_REG_ACTION_is_disqualified] = { META_SS_OP_PARAM_USER_EDIT_REG_ACTION_is_disqualified, '3', XSIZE(struct ss_op_param_USER_EDIT_REG_ACTION, is_disqualified), "is_disqualified", XOFFSET(struct ss_op_param_USER_EDIT_REG_ACTION, is_disqualified) },
};

int meta_ss_op_param_USER_EDIT_REG_ACTION_get_type(int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_EDIT_REG_ACTION_LAST_FIELD);
  return meta_info_ss_op_param_USER_EDIT_REG_ACTION_data[tag].type;
}

size_t meta_ss_op_param_USER_EDIT_REG_ACTION_get_size(int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_EDIT_REG_ACTION_LAST_FIELD);
  return meta_info_ss_op_param_USER_EDIT_REG_ACTION_data[tag].size;
}

const char *meta_ss_op_param_USER_EDIT_REG_ACTION_get_name(int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_EDIT_REG_ACTION_LAST_FIELD);
  return meta_info_ss_op_param_USER_EDIT_REG_ACTION_data[tag].name;
}

const void *meta_ss_op_param_USER_EDIT_REG_ACTION_get_ptr(const struct ss_op_param_USER_EDIT_REG_ACTION *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_EDIT_REG_ACTION_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_ss_op_param_USER_EDIT_REG_ACTION_data[tag].offset);
}

void *meta_ss_op_param_USER_EDIT_REG_ACTION_get_ptr_nc(struct ss_op_param_USER_EDIT_REG_ACTION *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_SS_OP_PARAM_USER_EDIT_REG_ACTION_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_ss_op_param_USER_EDIT_REG_ACTION_data[tag].offset);
}

int meta_ss_op_param_USER_EDIT_REG_ACTION_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_ss_op_param_USER_EDIT_REG_ACTION_data, META_SS_OP_PARAM_USER_EDIT_REG_ACTION_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods meta_ss_op_param_USER_EDIT_REG_ACTION_methods =
{
  META_SS_OP_PARAM_USER_EDIT_REG_ACTION_LAST_FIELD,
  sizeof(struct ss_op_param_USER_EDIT_REG_ACTION),
  meta_ss_op_param_USER_EDIT_REG_ACTION_get_type,
  meta_ss_op_param_USER_EDIT_REG_ACTION_get_size,
  meta_ss_op_param_USER_EDIT_REG_ACTION_get_name,
  (const void *(*)(const void *ptr, int tag))meta_ss_op_param_USER_EDIT_REG_ACTION_get_ptr,
  (void *(*)(void *ptr, int tag))meta_ss_op_param_USER_EDIT_REG_ACTION_get_ptr_nc,
  meta_ss_op_param_USER_EDIT_REG_ACTION_lookup_field,
};

