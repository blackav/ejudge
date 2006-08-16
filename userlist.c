/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2006 Alexander Chernov <cher@ispras.ru> */

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
#include "contests.h"
#include "pathutl.h"
#include "errlog.h"
#include "tsc.h"
#include "xml_utils.h"
#include "ej_limits.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define _(x) x

struct userlist_list *
userlist_new(void)
{
  struct userlist_list *p = 0;

  p = (struct userlist_list*) xcalloc(1, sizeof(*p));
  p->name = xstrdup("unknown");
  p->user_map_size = 16;
  p->user_map = xcalloc(p->user_map_size, sizeof(p->user_map[0]));
  p->member_serial = 1;
  return p;
}

void
userlist_remove_user(struct userlist_list *lst, struct userlist_user *usr)
{
  ASSERT(lst && lst->b.tag == USERLIST_T_USERLIST);
  ASSERT(usr && usr->b.tag == USERLIST_T_USER);
  ASSERT(usr->id > 0 && usr->id < lst->user_map_size);
  if (!usr->b.left) {
    lst->b.first_down = usr->b.right;
  } else {
    usr->b.left->right = usr->b.right;
  }
  if (!usr->b.right) {
    lst->b.last_down = usr->b.left;
  } else {
    usr->b.right->left = usr->b.left;
  }
  lst->user_map[usr->id] = 0;
  usr->b.up = 0;
  usr->b.left = 0;
  usr->b.right = 0;
  userlist_free((struct xml_tree*) usr);

  // FIXME: dumb!!!
  if (lst->login_hash_table) {
    if (userlist_build_login_hash(lst) < 0) {
      // FIXME: handle gracefully?
      SWERR(("userlist_build_login_hash failed unexpectedly"));
    }
  }
}

static char const * const member_status_string[] =
{
  "",
  _("School student"),
  _("Student"),
  _("Magistrant"),
  _("PhD student"),
  _("School teacher"),
  _("Professor"),
  _("Scientist"),
  _("Other")
};
unsigned char const *
userlist_member_status_str(int status)
{
  ASSERT(status >= 0 && status <= USERLIST_ST_LAST);
  return member_status_string[status];
}

const unsigned char *
userlist_unparse_date(time_t d, int show_null)
{
  static unsigned char buf[64];

  if (!d) {
    strcpy(buf, "<Not set>");
    return buf;
  }
  return xml_unparse_date(d);
}

int
userlist_get_member_field_str(unsigned char *buf, size_t len,
                              struct userlist_member *m, int field_id,
                              int convert_null)
{
  unsigned char *s = 0;

  switch (field_id) {
  case USERLIST_NM_SERIAL:
    return snprintf(buf, len, "%d", m->serial);
  case USERLIST_NM_COPIED_FROM:
    if (m->copied_from <= 0)
      return snprintf(buf, len, "<Not set>");
    else
      return snprintf(buf, len, "%d", m->copied_from);
  case USERLIST_NM_GRADE:
    return snprintf(buf, len, "%d", m->grade);
  case USERLIST_NM_STATUS:
    return snprintf(buf, len, "%s", userlist_member_status_str(m->status));
  case USERLIST_NM_FIRSTNAME:  s = m->firstname;  break;
  case USERLIST_NM_FIRSTNAME_EN: s = m->firstname_en; break;
  case USERLIST_NM_MIDDLENAME: s = m->middlename; break;
  case USERLIST_NM_MIDDLENAME_EN: s = m->middlename_en; break;
  case USERLIST_NM_SURNAME:    s = m->surname;    break;
  case USERLIST_NM_SURNAME_EN: s = m->surname_en; break;
  case USERLIST_NM_GROUP:      s = m->group;      break;
  case USERLIST_NM_GROUP_EN:   s = m->group_en;   break;
  case USERLIST_NM_OCCUPATION: s = m->occupation; break;
  case USERLIST_NM_OCCUPATION_EN: s = m->occupation_en; break;
  case USERLIST_NM_EMAIL:      s = m->email;      break;
  case USERLIST_NM_HOMEPAGE:   s = m->homepage;   break;
  case USERLIST_NM_PHONE:      s = m->phone;      break;
  case USERLIST_NM_INST:       s = m->inst;       break;
  case USERLIST_NM_INST_EN:    s = m->inst_en;    break;
  case USERLIST_NM_INSTSHORT:  s = m->instshort;  break;
  case USERLIST_NM_INSTSHORT_EN: s = m->instshort_en; break;
  case USERLIST_NM_FAC:        s = m->fac;        break;
  case USERLIST_NM_FAC_EN:     s = m->fac_en;     break;
  case USERLIST_NM_FACSHORT:   s = m->facshort;   break;
  case USERLIST_NM_FACSHORT_EN: s = m->facshort_en; break;
  default:
    SWERR(("unhandled field_id: %d", field_id));
  }
  if (!s) {
    if (convert_null) s = "<NULL>";
    else s = "";
  }
  return snprintf(buf, len, "%s", s);
}

int
userlist_delete_member_field(struct userlist_member *m, int field_id)
{
  unsigned char **ps = 0;

  switch (field_id) {
  case USERLIST_NM_GRADE:
    if (!m->grade) return 0;
    m->grade = 0;
    return 1;
  case USERLIST_NM_COPIED_FROM:
    if (!m->copied_from) return 0;
    m->copied_from = 0;
    return 1;
  case USERLIST_NM_STATUS:
    if (!m->status) return 0;
    m->status = 0;
    return 1;
  case USERLIST_NM_FIRSTNAME:
    ps = &m->firstname; goto do_text_field;
  case USERLIST_NM_FIRSTNAME_EN:
    ps = &m->firstname_en; goto do_text_field;
  case USERLIST_NM_MIDDLENAME:
    ps = &m->middlename; goto do_text_field;
  case USERLIST_NM_MIDDLENAME_EN:
    ps = &m->middlename_en; goto do_text_field;
  case USERLIST_NM_SURNAME:
    ps = &m->surname; goto do_text_field;
  case USERLIST_NM_SURNAME_EN:
    ps = &m->surname_en; goto do_text_field;
  case USERLIST_NM_GROUP:
    ps = &m->group; goto do_text_field;
  case USERLIST_NM_GROUP_EN:
    ps = &m->group_en; goto do_text_field;
  case USERLIST_NM_OCCUPATION:
    ps = &m->occupation; goto do_text_field;
  case USERLIST_NM_OCCUPATION_EN:
    ps = &m->occupation_en; goto do_text_field;
  case USERLIST_NM_EMAIL:
    ps = &m->email; goto do_text_field;
  case USERLIST_NM_HOMEPAGE:
    ps = &m->homepage; goto do_text_field;
  case USERLIST_NM_PHONE:
    ps = &m->phone; goto do_text_field;
  case USERLIST_NM_INST:
    ps = &m->inst; goto do_text_field;
  case USERLIST_NM_INST_EN:
    ps = &m->inst_en; goto do_text_field;
  case USERLIST_NM_INSTSHORT:
    ps = &m->instshort; goto do_text_field;
  case USERLIST_NM_INSTSHORT_EN:
    ps = &m->instshort_en; goto do_text_field;
  case USERLIST_NM_FAC:
    ps = &m->fac; goto do_text_field;
  case USERLIST_NM_FAC_EN:
    ps = &m->fac_en; goto do_text_field;
  case USERLIST_NM_FACSHORT:
    ps = &m->facshort; goto do_text_field;
  case USERLIST_NM_FACSHORT_EN:
    ps = &m->facshort_en; goto do_text_field;
  do_text_field:
    if (!*ps) return 0;
    xfree(*ps);
    *ps = 0;
    return 1;

  case USERLIST_NM_SERIAL:
  default:
    return -1;
  }
  return -1;
}

int
userlist_set_member_field_str(struct userlist_member *m, int field_id,
                              unsigned char const *field_val)
{
  unsigned char **ps = 0;
  int x, n;
  int updated = 0;

  switch (field_id) {
  case USERLIST_NM_SERIAL:
  case USERLIST_NM_COPIED_FROM:
    return -1;
  case USERLIST_NM_GRADE:
    if (!field_val) {
      x = 0;
    } else {
      if (sscanf(field_val, "%d %n", &x, &n) != 1 || field_val[n]
          || x < 0 || x >= 20) {
        return -1;
      }
    }
    if (x != m->grade) {
      m->grade = x;
      updated = 1;
    }
    return updated;
  case USERLIST_NM_STATUS:
    if (!field_val) {
      x = 0;
    } else {
      if (sscanf(field_val, "%d %n", &x, &n) != 1 || field_val[n]
          || x < 0 || x >= USERLIST_ST_LAST) {
        return -1;
      }
    }
    if (x != m->status) {
      m->status = x;
      updated = 1;
    }
    return updated;
  case USERLIST_NM_FIRSTNAME:  ps = &m->firstname;  break;
  case USERLIST_NM_FIRSTNAME_EN: ps = &m->firstname_en; break;
  case USERLIST_NM_MIDDLENAME: ps = &m->middlename; break;
  case USERLIST_NM_MIDDLENAME_EN: ps = &m->middlename_en; break;
  case USERLIST_NM_SURNAME:    ps = &m->surname;    break;
  case USERLIST_NM_SURNAME_EN: ps = &m->surname_en; break;
  case USERLIST_NM_GROUP:      ps = &m->group;      break;
  case USERLIST_NM_GROUP_EN:   ps = &m->group_en;   break;
  case USERLIST_NM_OCCUPATION: ps = &m->occupation; break;
  case USERLIST_NM_OCCUPATION_EN: ps = &m->occupation_en; break;
  case USERLIST_NM_EMAIL:      ps = &m->email;      break;
  case USERLIST_NM_HOMEPAGE:   ps = &m->homepage;   break;
  case USERLIST_NM_PHONE:      ps = &m->phone;      break;
  case USERLIST_NM_INST:       ps = &m->inst;       break;
  case USERLIST_NM_INST_EN:    ps = &m->inst_en;    break;
  case USERLIST_NM_INSTSHORT:  ps = &m->instshort;  break;
  case USERLIST_NM_INSTSHORT_EN: ps = &m->instshort_en; break;
  case USERLIST_NM_FAC:        ps = &m->fac;        break;
  case USERLIST_NM_FAC_EN:     ps = &m->fac_en;     break;
  case USERLIST_NM_FACSHORT:   ps = &m->facshort;   break;
  case USERLIST_NM_FACSHORT_EN: ps = &m->facshort_en; break;
  default:
    SWERR(("unhandled field_id: %d", field_id));
  }
  if (!ps) return -1;
  if (!*ps && field_val) {
    *ps = xstrdup(field_val);
    updated = 1;
  } else if (*ps && !field_val) { 
    xfree(*ps); *ps = 0;
    updated = 1;
  } else if (*ps && field_val && strcmp(*ps, field_val) != 0) {
    xfree(*ps); *ps = 0;
    *ps = xstrdup(field_val);
    updated = 1;
  }
  return updated;
}

int
userlist_get_user_field_str(unsigned char *buf, size_t len,
                            struct userlist_user *u,
                            struct userlist_user_info *ui,
                            int field_id,
                            int convert_null)
{
  unsigned char const *s = 0;

  if (!ui) ui = &u->i;

  switch (field_id) {
  case USERLIST_NN_ID:
    return snprintf(buf, len, "%d", u->id);
  case USERLIST_NN_LOGIN: s = u->login; break;
  case USERLIST_NN_EMAIL: s = u->email; break;
  case USERLIST_NN_NAME: s = ui->name; break;
  case USERLIST_NN_IS_PRIVILEGED:
    s = xml_unparse_bool(u->is_privileged); break;
  case USERLIST_NN_IS_INVISIBLE:
    s = xml_unparse_bool(u->is_invisible); break;
  case USERLIST_NN_IS_BANNED:
    s = xml_unparse_bool(u->is_banned); break;
  case USERLIST_NN_IS_LOCKED:
    s = xml_unparse_bool(u->is_locked); break;
  case USERLIST_NN_SHOW_LOGIN:
    s = xml_unparse_bool(u->show_login); break;
  case USERLIST_NN_SHOW_EMAIL:
    s = xml_unparse_bool(u->show_email); break;
  case USERLIST_NN_READ_ONLY:
    s = xml_unparse_bool(u->read_only); break;
  case USERLIST_NN_CNTS_READ_ONLY:
    s = xml_unparse_bool(ui->cnts_read_only); break;
  case USERLIST_NN_NEVER_CLEAN:
    s = xml_unparse_bool(u->never_clean); break;
  case USERLIST_NN_SIMPLE_REGISTRATION:
    s = xml_unparse_bool(u->simple_registration); break;
  case USERLIST_NN_TIMESTAMPS: break;    /* !!! */
  case USERLIST_NN_REG_TIME:
    s = userlist_unparse_date(u->registration_time, convert_null); break;
  case USERLIST_NN_LOGIN_TIME:
    s = userlist_unparse_date(u->last_login_time, convert_null); break;
  case USERLIST_NN_CREATE_TIME:
    s = userlist_unparse_date(ui->create_time, convert_null); break;
  case USERLIST_NN_ACCESS_TIME:
    s = userlist_unparse_date(u->last_access_time, convert_null); break;
  case USERLIST_NN_CHANGE_TIME:
    s = userlist_unparse_date(u->last_change_time, convert_null); break;
  case USERLIST_NN_PWD_CHANGE_TIME:
    s = userlist_unparse_date(u->last_pwdchange_time, convert_null); break;
  case USERLIST_NN_MINOR_CHANGE_TIME:
    s = userlist_unparse_date(u->last_minor_change_time, convert_null);break;
  case USERLIST_NN_PASSWORDS: break;     /* !!! */
  case USERLIST_NN_REG_PASSWORD:
    if (u->register_passwd) s = u->register_passwd->b.text;
    break;
  case USERLIST_NN_TEAM_PASSWORD:
    if (ui->team_passwd) s = ui->team_passwd->b.text;
    break;
  case USERLIST_NN_GENERAL_INFO: break;  /* !!! */
  case USERLIST_NN_INST: s = ui->inst; break;
  case USERLIST_NN_INST_EN: s = ui->inst_en; break;
  case USERLIST_NN_INSTSHORT: s = ui->instshort; break;
  case USERLIST_NN_INSTSHORT_EN: s = ui->instshort_en; break;
  case USERLIST_NN_FAC: s = ui->fac; break;
  case USERLIST_NN_FAC_EN: s = ui->fac_en; break;
  case USERLIST_NN_FACSHORT: s = ui->facshort; break;
  case USERLIST_NN_FACSHORT_EN: s = ui->facshort_en; break;
  case USERLIST_NN_HOMEPAGE: s = ui->homepage; break;
  case USERLIST_NN_PHONE: s = ui->phone; break;
  case USERLIST_NN_CITY: s = ui->city; break;
  case USERLIST_NN_CITY_EN: s = ui->city_en; break;
  case USERLIST_NN_COUNTRY: s = ui->country; break;
  case USERLIST_NN_COUNTRY_EN: s = ui->country_en; break;
  case USERLIST_NN_LOCATION: s = ui->location; break;
  case USERLIST_NN_SPELLING: s = ui->spelling; break;
  case USERLIST_NN_PRINTER_NAME: s = ui->printer_name; break;
  case USERLIST_NN_LANGUAGES: s = ui->languages; break;
  }
  if (!s) {
    if (convert_null) s = "<NULL>";
    else s = "";
  }
  return snprintf(buf, len, "%s", s);
}

int
userlist_set_user_field_str(struct userlist_list *lst,
                            struct userlist_user *u,
                            struct userlist_user_info *ui,
                            int field_id,
                            unsigned char const *field_val)
{
  int updated = 0;
  int *iptr;
  int new_ival, i;
  unsigned char **sptr, *old_login;
  userlist_login_hash_t login_hash;
  struct userlist_user *tmpu;

  if (!field_val) field_val = "";
  if (!ui) ui = &u->i;

  switch (field_id) {
  case USERLIST_NN_LOGIN:
    if (!*field_val) return -1;
    if (!lst) {
      sptr = &u->login;
      goto do_text_fields;
    }

    ASSERT(u->login);
    if (!strcmp(u->login, field_val)) break;

    /*
      We cannot simply change `login' field, as it is
      a primary key. We have to ensure its uniqueness.
     */
    if (lst->login_hash_table) {
      login_hash = userlist_login_hash(field_val);
      i = login_hash % lst->login_hash_size;
      while (1) {
        if (!(tmpu = lst->login_hash_table[i])) break;
        if (tmpu != u && tmpu->login_hash == login_hash
            && !strcmp(tmpu->login, field_val)) break;
        i = (i + lst->login_hash_step) % lst->login_hash_size;
      }
      if (lst->login_hash_table[i]) {
        /* new login is not unique */
        return -1;
      }
    } else {
      for (i = 1; i < lst->user_map_size; i++) {
        if (!lst->user_map[i]) continue;
        if (lst->user_map[i] == u) continue;
        if (!strcmp(field_val, lst->user_map[i]->login)) break;
      }
      if (i < lst->user_map_size) {
        /* new login is not unique */
        return -1;
      }
    }

    /* new login is unique */
    old_login = u->login;
    u->login = xstrdup(field_val);

    /* This is dump, however it will work */
    if (userlist_build_login_hash(lst) < 0) {
      SWERR(("userlist_build_login_hash failed unexpectedly"));
    }

    xfree(old_login);
    updated = 1;
    break;
  case USERLIST_NN_EMAIL:
    if (!*field_val) return -1;
    sptr = &u->email; goto do_text_fields;
  case USERLIST_NN_NAME:
    sptr = &ui->name;
  do_text_fields:
    if (*sptr && !strcmp(*sptr, field_val)) break;
    xfree(*sptr);
    *sptr = xstrdup(field_val);
    updated = 1;
    break;

  case USERLIST_NN_IS_PRIVILEGED:
    iptr = &u->is_privileged; goto do_bool_fields;
  case USERLIST_NN_IS_INVISIBLE:
    iptr = &u->is_invisible; goto do_bool_fields;
  case USERLIST_NN_IS_BANNED:
    iptr = &u->is_banned; goto do_bool_fields;
  case USERLIST_NN_IS_LOCKED:
    iptr = &u->is_locked; goto do_bool_fields;
  case USERLIST_NN_SHOW_LOGIN:
    iptr = &u->show_login; goto do_bool_fields;
  case USERLIST_NN_SHOW_EMAIL:
    iptr = &u->show_email; goto do_bool_fields;
  case USERLIST_NN_READ_ONLY:
    iptr = &u->read_only; goto do_bool_fields;
  case USERLIST_NN_CNTS_READ_ONLY:
    iptr = &ui->cnts_read_only; goto do_bool_fields;
  case USERLIST_NN_NEVER_CLEAN:
    iptr = &u->never_clean; goto do_bool_fields;
  case USERLIST_NN_SIMPLE_REGISTRATION:
    iptr = &u->simple_registration; goto do_bool_fields;
  do_bool_fields:
    new_ival = xml_parse_bool(0, 0, 0, field_val, 0);
    if (new_ival < 0 || new_ival > 1) return -1;
    if (new_ival == *iptr) break;
    *iptr = new_ival;
    updated = 1;
    break;

  case USERLIST_NN_REG_PASSWORD:
    if (!u->register_passwd) {
      u->register_passwd = (struct userlist_passwd*) userlist_node_alloc(USERLIST_T_PASSWORD);
      xml_link_node_last(&u->b, &u->register_passwd->b);
      u->register_passwd->b.text = xstrdup("");
      u->register_passwd->method = USERLIST_PWD_PLAIN;
      updated = 1;
    }
    if (!strcmp(u->register_passwd->b.text, field_val)) break;
    xfree(u->register_passwd->b.text);
    u->register_passwd->b.text = xstrdup(field_val);
    u->register_passwd->method = USERLIST_PWD_PLAIN;
    updated = 1;
    break;

  case USERLIST_NN_TEAM_PASSWORD:
    if (!ui->team_passwd) {
      ui->team_passwd = (struct userlist_passwd*) userlist_node_alloc(USERLIST_T_TEAM_PASSWORD);
      xml_link_node_last(&u->b, &ui->team_passwd->b);
      ui->team_passwd->b.text = xstrdup("");
      ui->team_passwd->method = USERLIST_PWD_PLAIN;
      updated = 1;
    }
    if (!strcmp(ui->team_passwd->b.text, field_val)) break;
    xfree(ui->team_passwd->b.text);
    ui->team_passwd->b.text = xstrdup(field_val);
    ui->team_passwd->method = USERLIST_PWD_PLAIN;
    updated = 1;
    break;

  case USERLIST_NN_INST:
    sptr = &ui->inst; goto do_text_fields;
  case USERLIST_NN_INST_EN:
    sptr = &ui->inst_en; goto do_text_fields;
  case USERLIST_NN_INSTSHORT:
    sptr = &ui->instshort; goto do_text_fields;
  case USERLIST_NN_INSTSHORT_EN:
    sptr = &ui->instshort_en; goto do_text_fields;
  case USERLIST_NN_FAC:
    sptr = &ui->fac; goto do_text_fields;
  case USERLIST_NN_FAC_EN:
    sptr = &ui->fac_en; goto do_text_fields;
  case USERLIST_NN_FACSHORT:
    sptr = &ui->facshort; goto do_text_fields;
  case USERLIST_NN_FACSHORT_EN:
    sptr = &ui->facshort_en; goto do_text_fields;
  case USERLIST_NN_HOMEPAGE:
    sptr = &ui->homepage; goto do_text_fields;
  case USERLIST_NN_PHONE:
    sptr = &ui->phone; goto do_text_fields;
  case USERLIST_NN_CITY:
    sptr = &ui->city; goto do_text_fields;
  case USERLIST_NN_CITY_EN:
    sptr = &ui->city_en; goto do_text_fields;
  case USERLIST_NN_COUNTRY:
    sptr = &ui->country; goto do_text_fields;
  case USERLIST_NN_COUNTRY_EN:
    sptr = &ui->country_en; goto do_text_fields;
  case USERLIST_NN_LOCATION:
    sptr = &ui->location; goto do_text_fields;
  case USERLIST_NN_SPELLING:
    sptr = &ui->spelling; goto do_text_fields;
  case USERLIST_NN_PRINTER_NAME:
    sptr = &ui->printer_name; goto do_text_fields;
  case USERLIST_NN_LANGUAGES:
    sptr = &ui->languages; goto do_text_fields;

  case USERLIST_NN_ID:
  case USERLIST_NN_TIMESTAMPS:
  case USERLIST_NN_REG_TIME:
  case USERLIST_NN_LOGIN_TIME:
  case USERLIST_NN_CREATE_TIME:
  case USERLIST_NN_ACCESS_TIME:
  case USERLIST_NN_CHANGE_TIME:
  case USERLIST_NN_PWD_CHANGE_TIME:
  case USERLIST_NN_MINOR_CHANGE_TIME:
  case USERLIST_NN_PASSWORDS:
  case USERLIST_NN_GENERAL_INFO:
  default:
    return -1;
  }
  return updated;
}

int
userlist_delete_user_field(struct userlist_user *u,
                           struct userlist_user_info *ui,
                           int field_id)
{
  time_t *tptr;
  int *iptr;
  unsigned char **sptr;
  int retval = -1;

  if (!ui) ui = &u->i;

  switch (field_id) {
  case USERLIST_NN_NAME:
    sptr = &ui->name;
    if (*sptr && **sptr) retval = 1;
    xfree(*sptr); *sptr = xstrdup("");
    break;

  case USERLIST_NN_IS_PRIVILEGED:
    iptr = &u->is_privileged; goto do_flags_delete;
  case USERLIST_NN_IS_INVISIBLE:
    iptr = &u->is_invisible; goto do_flags_delete;
  case USERLIST_NN_IS_BANNED:
    iptr = &u->is_banned; goto do_flags_delete;
  case USERLIST_NN_IS_LOCKED:
    iptr = &u->is_locked; goto do_flags_delete;
  case USERLIST_NN_SHOW_LOGIN:
    iptr = &u->show_login; goto do_flags_delete;
  case USERLIST_NN_SHOW_EMAIL:
    iptr = &u->show_email; goto do_flags_delete;
  case USERLIST_NN_READ_ONLY:
    iptr = &u->read_only; goto do_flags_delete;
  case USERLIST_NN_CNTS_READ_ONLY:
    iptr = &ui->cnts_read_only; goto do_flags_delete;
  case USERLIST_NN_NEVER_CLEAN:
    iptr = &u->never_clean; goto do_flags_delete;
  case USERLIST_NN_SIMPLE_REGISTRATION:
    iptr = &u->simple_registration; goto do_flags_delete;
  do_flags_delete:
    retval = !(*iptr == 0);
    *iptr = 0;
    break;

  case USERLIST_NN_REG_PASSWORD:
    return -1;
#if 0
    if (!u->register_passwd) break;
    if (!u->register_passwd->b.text || !*u->register_passwd->b.text) break;
    xfree(u->register_passwd->b.text);
    u->register_passwd->b.text = xstrdup("");
    break;
#endif

  case USERLIST_NN_TEAM_PASSWORD:
    if (!ui->team_passwd) break;
    xml_unlink_node(&ui->team_passwd->b);
    userlist_free(&ui->team_passwd->b);
    ui->team_passwd = 0;
    retval = 1;
    break;

  case USERLIST_NN_INST:
    sptr = &ui->inst; goto do_string_delete;
  case USERLIST_NN_INST_EN:
    sptr = &ui->inst_en; goto do_string_delete;
  case USERLIST_NN_INSTSHORT:
    sptr = &ui->instshort; goto do_string_delete;
  case USERLIST_NN_INSTSHORT_EN:
    sptr = &ui->instshort_en; goto do_string_delete;
  case USERLIST_NN_FAC:
    sptr = &ui->fac; goto do_string_delete;
  case USERLIST_NN_FAC_EN:
    sptr = &ui->fac_en; goto do_string_delete;
  case USERLIST_NN_FACSHORT:
    sptr = &ui->facshort; goto do_string_delete;
  case USERLIST_NN_FACSHORT_EN:
    sptr = &ui->facshort_en; goto do_string_delete;
  case USERLIST_NN_HOMEPAGE:
    sptr = &ui->homepage; goto do_string_delete;
  case USERLIST_NN_PHONE:
    sptr = &ui->phone; goto do_string_delete;
  case USERLIST_NN_CITY:
    sptr = &ui->city; goto do_string_delete;
  case USERLIST_NN_CITY_EN:
    sptr = &ui->city_en; goto do_string_delete;
  case USERLIST_NN_COUNTRY:
    sptr = &ui->country; goto do_string_delete;
  case USERLIST_NN_COUNTRY_EN:
    sptr = &ui->country_en; goto do_string_delete;
  case USERLIST_NN_LOCATION:
    sptr = &ui->location; goto do_string_delete;
  case USERLIST_NN_SPELLING:
    sptr = &ui->spelling; goto do_string_delete;
  case USERLIST_NN_PRINTER_NAME:
    sptr = &ui->printer_name; goto do_string_delete;
  case USERLIST_NN_LANGUAGES:
    sptr = &ui->languages; goto do_string_delete;
  do_string_delete:
    retval = !(*sptr == 0);
    xfree(*sptr); *sptr = 0;
    break;

  case USERLIST_NN_REG_TIME:
    tptr = &u->registration_time; goto do_timestamp_delete;
  case USERLIST_NN_LOGIN_TIME:
    tptr = &u->last_login_time; goto do_timestamp_delete;
  case USERLIST_NN_CREATE_TIME:
    tptr = &ui->create_time; goto do_timestamp_delete;
  case USERLIST_NN_ACCESS_TIME:
    tptr = &u->last_access_time; goto do_timestamp_delete;
  case USERLIST_NN_CHANGE_TIME:
    tptr = &u->last_change_time; goto do_timestamp_delete;
  case USERLIST_NN_PWD_CHANGE_TIME:
    tptr = &u->last_pwdchange_time; goto do_timestamp_delete;
  case USERLIST_NN_MINOR_CHANGE_TIME:
    tptr = &u->last_minor_change_time;
  do_timestamp_delete:
    retval = !(*tptr == 0);
    *tptr = 0;
    break;

  case USERLIST_NN_ID:
  case USERLIST_NN_LOGIN:
  case USERLIST_NN_EMAIL:
  case USERLIST_NN_TIMESTAMPS:
  case USERLIST_NN_PASSWORDS:
  case USERLIST_NN_GENERAL_INFO:
  default:
    return -1;
  }
  return retval;
}

static const unsigned char id_hash_map[256] =
{
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,64,62,65,
   0, 1, 2, 3, 4, 5, 6, 7, 8, 9,65,65,65,65,65,65,
  65,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,
  25,26,27,28,29,30,31,32,33,34,35,65,65,65,65,63,
  65,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,
  51,52,53,54,55,56,57,58,59,60,61,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
};

unsigned long
userlist_login_hash(const unsigned char *p)
{
  unsigned long hash = 0;

  if (!p) return 0;
  for (; *p; p++)
    hash = hash * 66 + id_hash_map[*p];
  return hash;
}

static int primes[] =
{
  4099,
  8209,
  16411,
  32771,
  65537,
  131101,
  262147,
  524309,
  1048583,
  0,
};

int
userlist_build_login_hash(struct userlist_list *p)
{
  int i, count, coll_count = 0, j, coll1_count = 0;
  struct userlist_user *u;
  ej_tsc_t tsc1, tsc2;

  if (p->login_hash_table) xfree(p->login_hash_table);
  p->login_hash_table = 0;
  p->login_hash_size = 0;
  p->login_hash_step = 23;

  for (i = 1, count = 0; i < p->user_map_size; i++)
    if (p->user_map[i])
      count++;

  for (i = 0; primes[i] && primes[i] < count * 3; i++);
  if (!primes[i]) {
    err("size of hash table %d is too large", count * 3);
    goto cleanup;
  }
  p->login_hash_size = primes[i];
  p->login_thresh = p->login_hash_size * 2 / 3;
  p->login_cur_fill = count;
  XCALLOC(p->login_hash_table, p->login_hash_size);

  rdtscll(tsc1);
  for (i = 1; i < p->user_map_size; i++) {
    u = p->user_map[i];
    if (!u) continue;
    ASSERT(u->login);
    u->login_hash = userlist_login_hash(u->login);
    j = u->login_hash % p->login_hash_size;
    while (p->login_hash_table[j]) {
      if (!strcmp(u->login, p->login_hash_table[j]->login)) {
        err("duplicated login %s", u->login);
        goto cleanup;
      }
      if (p->login_hash_table[j]->login_hash == u->login_hash) coll1_count++;
      coll_count++;
      j = (j + p->login_hash_step) % p->login_hash_size;
    }
    p->login_hash_table[j] = u;
  }
  rdtscll(tsc2);
  tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;

  info("login hashtable: size = %zu, shift = %zu, thresh = %zu, current = %zu",
       p->login_hash_size, p->login_hash_step, p->login_thresh,
       p->login_cur_fill);
  info("login hashtable: collisions = %d, hash collisions = %d",
       coll_count, coll1_count);
  info("login hashtable: time = %llu (us)", tsc2);
  return 0;

 cleanup:
  p->login_hash_size = 0;
  p->login_hash_step = 0;
  p->login_thresh = 0;
  p->login_cur_fill = 0;
  xfree(p->login_hash_table); p->login_hash_table = 0;
  return -1;
}

int
userlist_build_cookie_hash(struct userlist_list *p)
{
  struct userlist_user *u;
  int i, j;
  size_t cookie_count = 0, collision_count = 0;
  struct userlist_cookie *ck;
  ej_tsc_t tsc1, tsc2;

  rdtscll(tsc1);

  p->cookie_hash_size = 0;
  p->cookie_hash_step = 0;
  p->cookie_thresh = 0;
  p->cookie_cur_fill = 0;
  xfree(p->cookie_hash_table);
  p->cookie_hash_table = 0;

  /* count the number of cookies */
  for (i = 1; i < p->user_map_size; i++) {
    if (!(u = p->user_map[i])) continue;
    if (!u->cookies) continue;
    ASSERT(u->cookies->tag == USERLIST_T_COOKIES);
    ck = (struct userlist_cookie*) u->cookies->first_down;
    while (ck) {
      ASSERT(ck->b.tag == USERLIST_T_COOKIE);
      ASSERT(ck->user_id > 0);
      ASSERT(ck->user_id == u->id);
      ASSERT(ck->cookie);
      cookie_count++;
      ck = (struct userlist_cookie*) ck->b.right;
    }
  }

  /* choose hashtable size */
  for (i = 0; primes[i] && primes[i] < cookie_count * 3; i++);
  if (!primes[i]) {
    err("size of hash table %zu is too large", cookie_count * 3);
    goto cleanup;
  }
  p->cookie_hash_size = primes[i];
  p->cookie_hash_step = 37;
  p->cookie_thresh = p->cookie_hash_size * 2 / 3;
  p->cookie_cur_fill = cookie_count;
  XCALLOC(p->cookie_hash_table, p->cookie_hash_size);

  /* insert cookies to hashtable */
  for (i = 1; i < p->user_map_size; i++) {
    if (!(u = p->user_map[i])) continue;
    if (!u->cookies) continue;
    ck = (struct userlist_cookie*) u->cookies->first_down;
    while (ck) {
      j = ck->cookie % p->cookie_hash_size;
      while (p->cookie_hash_table[j]) {
        if (ck->cookie == p->cookie_hash_table[j]->cookie) {
          err("duplicated cookie value %016llx (uids=%d,%d)",
              ck->cookie, u->id, p->cookie_hash_table[j]->user_id);
          goto cleanup;
        }
        collision_count++;
        j = (j + p->cookie_hash_step) % p->cookie_hash_size;
      }
      p->cookie_hash_table[j] = ck;
      ck = (struct userlist_cookie*) ck->b.right;
    }
  }

  rdtscll(tsc2);
  tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;

  info("cookie hashtable: size = %zu, step = %zu, thresh = %zu, current = %zu",
       p->cookie_hash_size, p->cookie_hash_step, p->cookie_thresh,
       p->cookie_cur_fill);
  info("cookie hashtable: collisions = %zu", collision_count);
  info("cookie hashtable: time = %llu (us)", tsc2);

  return 0;

 cleanup:
  p->cookie_hash_size = 0;
  p->cookie_hash_step = 0;
  p->cookie_thresh = 0;
  p->cookie_cur_fill = 0;
  xfree(p->cookie_hash_table);
  p->cookie_hash_table = 0;
  return -1;
}

int
userlist_cookie_hash_add(struct userlist_list *p, struct userlist_cookie *ck)
{
  int i;

  ASSERT(p);
  if (!p->cookie_hash_table) return 0;
  ASSERT(ck);
  ASSERT(ck->b.tag == USERLIST_T_COOKIE);
  ASSERT(ck->cookie);
  ASSERT(ck->user_id > 0);

  if (p->cookie_cur_fill >= p->cookie_thresh) {
    if (userlist_build_cookie_hash(p) < 0) {
      SWERR(("userlist_build_cookie_hash failed unexpectedly"));
    }
  }

  i = ck->cookie % p->cookie_hash_size;
  while (p->cookie_hash_table[i]) {
    if (p->cookie_hash_table[i] == ck) return 0;
    if (p->cookie_hash_table[i]->cookie == ck->cookie) {
      err("duplicated cookie value %016llx (uids=%d,%d)",
          ck->cookie, ck->user_id, p->cookie_hash_table[i]->user_id);
      return -1;
    }
    i = (i + p->cookie_hash_step) % p->cookie_hash_size;
  }
  p->cookie_hash_table[i] = ck;
  p->cookie_cur_fill++;
  return 0;
}

int
userlist_cookie_hash_del(struct userlist_list *p, struct userlist_cookie *ck)
{
  int i;
  int rehash_count = 0;
  int j;
  struct userlist_cookie **saves;

  ASSERT(p);
  if (!p->cookie_hash_table) return 0;
  ASSERT(ck);
  ASSERT(ck->b.tag == USERLIST_T_COOKIE);
  ASSERT(ck->cookie);
  ASSERT(ck->user_id > 0);

  i = ck->cookie % p->cookie_hash_size;
  j = -1;
  while (p->cookie_hash_table[i]) {
    if (p->cookie_hash_table[i] == ck) {
      ASSERT(j == -1);
      j = i;
    } else {
      rehash_count++;
    }
    i = (i + p->cookie_hash_step) % p->cookie_hash_size;
  }
  if (j == -1) return 0;
  if (!rehash_count) {
    i = ck->cookie % p->cookie_hash_size;
    ASSERT(p->cookie_hash_table[i] == ck);
    p->cookie_hash_table[i] = 0;
    p->cookie_cur_fill--;
    return 0;
  }

  saves = alloca(rehash_count * sizeof(saves[0]));
  memset(saves, 0, rehash_count * sizeof(saves[0]));
  i = ck->cookie % p->cookie_hash_size;
  j = 0;
  while (p->cookie_hash_table[i]) {
    if (p->cookie_hash_table[i] != ck)
      saves[j++] = p->cookie_hash_table[i];
    p->cookie_hash_table[i] = 0;
    i = (i + p->cookie_hash_step) % p->cookie_hash_size;
  }
  ASSERT(j == rehash_count);

  for (j = 0; j < rehash_count; j++) {
    i = saves[j]->cookie % p->cookie_hash_size;
    while (p->cookie_hash_table[i])
      i = (i + p->cookie_hash_step) % p->cookie_hash_size;
    p->cookie_hash_table[i] = saves[j];
  }

  p->cookie_cur_fill--;
  return 0;
}

void
userlist_expand_cntsinfo(struct userlist_user *u, int contest_id)
{
  int new_size;
  struct userlist_cntsinfo **new_arr;

  if (contest_id < u->cntsinfo_a) return;

  if (!(new_size = u->cntsinfo_a)) new_size = 32;
  while (contest_id >= new_size) new_size *= 2;
  XCALLOC(new_arr, new_size);
  if (u->cntsinfo_a > 0) {
    memcpy(new_arr, u->cntsinfo, u->cntsinfo_a * sizeof(new_arr[0]));
  }
  xfree(u->cntsinfo);
  u->cntsinfo_a = new_size;
  u->cntsinfo = new_arr;
}

/*
 * if the source string is NULL, also NULL is returned, as opposed
 * to the `xstrdup', which returns "" in case of NULL.
 */
static unsigned char *
copy_field(const unsigned char *s)
{
  if (!s) return 0;
  return xstrdup(s);
}

struct userlist_member *
userlist_clone_member(struct userlist_member *src, int *p_serial,
                      time_t current_time)
{
  struct userlist_member *dst;

  if (!src) return 0;
  ASSERT(src->b.tag == USERLIST_T_MEMBER);

  dst = (struct userlist_member*) userlist_node_alloc(USERLIST_T_MEMBER);

  dst->serial = (*p_serial)++;
  dst->copied_from = src->serial;
  dst->status = src->status;
  dst->grade = src->grade;

  dst->firstname = copy_field(src->firstname);
  dst->firstname_en = copy_field(src->firstname_en);
  dst->middlename = copy_field(src->middlename);
  dst->middlename_en = copy_field(src->middlename_en);
  dst->surname = copy_field(src->surname);
  dst->surname_en = copy_field(src->surname_en);
  dst->group = copy_field(src->group);
  dst->group_en = copy_field(src->group_en);
  dst->email = copy_field(src->email);
  dst->homepage = copy_field(src->homepage);
  dst->phone = copy_field(src->phone);
  dst->occupation = copy_field(src->occupation);
  dst->occupation_en = copy_field(src->occupation_en);
  dst->inst = copy_field(src->inst);
  dst->inst_en = copy_field(src->inst_en);
  dst->instshort = copy_field(src->instshort);
  dst->instshort_en = copy_field(src->instshort_en);
  dst->fac = copy_field(src->fac);
  dst->fac_en = copy_field(src->fac_en);
  dst->facshort = copy_field(src->facshort);
  dst->facshort_en = copy_field(src->facshort_en);

  dst->create_time = current_time;
  dst->last_change_time = current_time;
  dst->last_access_time = 0;
  src->last_access_time = current_time;

  return dst;
}

struct userlist_cntsinfo *
userlist_clone_user_info(struct userlist_user *u, int contest_id,
                         int *p_serial, time_t current_time)
{
  struct xml_tree *p;
  struct userlist_cntsinfo *ci;
  struct userlist_passwd *tp;
  struct userlist_members *mm, *ms;
  int mt, i, sz;

  if (contest_id <= 0 || contest_id > MAX_CONTEST_ID) return 0;
  if (!u) return 0;
  if (u->cntsinfo && contest_id < u->cntsinfo_a && u->cntsinfo[contest_id])
    return u->cntsinfo[contest_id];

  // ok, needs clone
  // 1. find <cntsinfos> element in the list of childs
  for (p = u->b.first_down; p && p->tag != USERLIST_T_CNTSINFOS; p = p->right);
  if (!p) {
    // <cntsinfos> not found, create a new one
    p = userlist_node_alloc(USERLIST_T_CNTSINFOS);
    xml_link_node_last(&u->b, p);
  }

  ci = (struct userlist_cntsinfo*) userlist_node_alloc(USERLIST_T_CNTSINFO);
  xml_link_node_last(p, &ci->b);

  ci->contest_id = contest_id;

  // NOTE: should we reset the cnts_read_only flag?
  ci->i.cnts_read_only = u->i.cnts_read_only;

  ci->i.name = xstrdup(u->i.name);

  ci->i.inst = copy_field(u->i.inst);
  ci->i.inst_en = copy_field(u->i.inst_en);
  ci->i.instshort = copy_field(u->i.instshort);
  ci->i.instshort_en = copy_field(u->i.instshort_en);
  ci->i.fac = copy_field(u->i.fac);
  ci->i.fac_en = copy_field(u->i.fac_en);
  ci->i.facshort = copy_field(u->i.facshort);
  ci->i.facshort_en = copy_field(u->i.facshort_en);
  ci->i.homepage = copy_field(u->i.homepage);
  ci->i.city = copy_field(u->i.city);
  ci->i.city_en = copy_field(u->i.city_en);
  ci->i.country = copy_field(u->i.country);
  ci->i.country_en = copy_field(u->i.country_en);
  ci->i.location = copy_field(u->i.location);
  ci->i.spelling = copy_field(u->i.spelling);
  ci->i.printer_name = copy_field(u->i.printer_name);
  ci->i.languages = copy_field(u->i.languages);
  ci->i.phone = copy_field(u->i.phone);

  ci->i.create_time = current_time;
  ci->i.last_change_time = current_time;
  ci->i.last_access_time = 0;
  ci->i.last_pwdchange_time = u->i.last_pwdchange_time;
  u->i.last_access_time = current_time;

  if (u->i.team_passwd) {
    tp = (struct userlist_passwd*) userlist_node_alloc(USERLIST_T_TEAM_PASSWORD);
    ci->i.team_passwd = tp;
    xml_link_node_last(&ci->b, &tp->b);
    tp->b.text = xstrdup(u->i.team_passwd->b.text);
    tp->method = u->i.team_passwd->method;
  }

  for (mt = 0; mt < USERLIST_MB_LAST; mt++) {
    if (!u->i.members[mt]) continue;
    ms = u->i.members[mt];
    mm = (struct userlist_members*) userlist_node_alloc(USERLIST_T_CONTESTANTS);
    mm->role = mt;
    ci->i.members[mt] = mm;
    xml_link_node_last(&ci->b, &mm->b);

    sz = 1;
    while (sz < ms->total) sz *= 2;
    mm->allocd = sz;
    mm->total = ms->total;
    XCALLOC(mm->members, sz);
    for (i = 0; i < ms->total; i++) {
      mm->members[i] = userlist_clone_member(ms->members[i], p_serial,
                                             current_time);
      xml_link_node_last(&mm->b, &mm->members[i]->b);
    }
  }

  userlist_expand_cntsinfo(u, contest_id);
  u->cntsinfo[contest_id] = ci;

  return ci;
}

struct userlist_cntsinfo *
userlist_new_cntsinfo(struct userlist_user *u, int contest_id,
                      time_t current_time)
{
  struct xml_tree *p;
  struct userlist_cntsinfo *ci;

  ASSERT(contest_id > 0 && contest_id <= MAX_CONTEST_ID);
  ASSERT(u);

  if (u->cntsinfo && contest_id < u->cntsinfo_a && u->cntsinfo[contest_id])
    return u->cntsinfo[contest_id];

  // ok, needs clone
  // 1. find <cntsinfos> element in the list of childs
  for (p = u->b.first_down; p && p->tag != USERLIST_T_CNTSINFOS; p = p->right);
  if (!p) {
    // <cntsinfos> not found, create a new one
    p = userlist_node_alloc(USERLIST_T_CNTSINFOS);
    xml_link_node_last(&u->b, p);
  }

  ci = (struct userlist_cntsinfo*) userlist_node_alloc(USERLIST_T_CNTSINFO);
  xml_link_node_last(p, &ci->b);
  userlist_expand_cntsinfo(u, contest_id);
  u->cntsinfo[contest_id] = ci;

  ci->contest_id = contest_id;
  ci->i.create_time = current_time;
  ci->i.last_change_time = current_time;

  return ci;
}

struct userlist_user_info *
userlist_get_user_info(struct userlist_user *u, int contest_id)
{
  ASSERT(u);

  if (contest_id > 0 && contest_id < u->cntsinfo_a
      && u->cntsinfo[contest_id])
    return &u->cntsinfo[contest_id]->i;
  return &u->i;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
