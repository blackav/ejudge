/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2002 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "userlist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char *
user_data_get_field(struct user_data const *ud, int tag)
{
  unsigned char const *s = 0;

  switch (tag) {
  case TAG_LOGIN:     s = ud->login; break;
  case TAG_DESCR:     s = ud->descr; break;
  case TAG_INST:      s = ud->inst; break;
  case TAG_INSTSHORT: s = ud->instshort; break;
  case TAG_FAC:       s = ud->fac; break;
  case TAG_FACSHORT:  s = ud->facshort; break;
  case TAG_PASSWORD:  s = ud->passwd; break;
  case TAG_COUNTRY:   s = ud->country; break;
  case TAG_ZIP:       s = ud->zip; break;
  case TAG_CITY:      s = ud->city; break;
  case TAG_ADDRESS:   s = ud->address; break;
  default:
    fprintf(stderr, "invalid field tag: %d\n", tag);
    abort();
  }
  return (unsigned char*) s;
}

void
user_data_set_field(struct user_data *ud, int tag, unsigned char const *s)
{
  switch (tag) {
  case TAG_LOGIN:     ud->login = (unsigned char*) s; break;
  case TAG_DESCR:     ud->descr = (unsigned char*) s; break;
  case TAG_INST:      ud->inst = (unsigned char*) s; break;
  case TAG_INSTSHORT: ud->instshort = (unsigned char*) s; break;
  case TAG_FAC:       ud->fac = (unsigned char*) s; break;
  case TAG_FACSHORT:  ud->facshort = (unsigned char*) s; break;
  case TAG_PASSWORD:  ud->passwd = (unsigned char*) s; break;
  case TAG_COUNTRY:   ud->country = (unsigned char*) s; break;
  case TAG_ZIP:       ud->zip = (unsigned char*) s; break;
  case TAG_CITY:      ud->city = (unsigned char*) s; break;
  case TAG_ADDRESS:   ud->address = (unsigned char*) s; break;
  default:
    fprintf(stderr, "invalid field tag: %d\n", tag);
    abort();
  }
}

unsigned char **
person_data_get_ptr(struct person_data const *pd, int tag)
{
  switch (tag) {
  case TAG_NAME:       return (unsigned char**) &pd->name;
  case TAG_MIDDLENAME: return (unsigned char**) &pd->middlename;
  case TAG_SURNAME:    return (unsigned char**) &pd->surname;
  case TAG_COURSE:     return (unsigned char**) &pd->course;
  case TAG_GROUP:      return (unsigned char**) &pd->group;
  case TAG_OCCUP:      return (unsigned char**) &pd->occup;
  default:
    fprintf(stderr, "invalid field tag: %d\n", tag);
    abort();
  }
  return 0;
}

struct person_list *
user_data_get_list_ptr(struct user_data const *ud, int tag)
{
  switch (tag) {
  case TAG_MEMBER:  return (struct person_list *) &ud->member_list;
  case TAG_RESERVE: return (struct person_list *) &ud->reserve_list;
  case TAG_COACH:   return (struct person_list *) &ud->coach_list;
  case TAG_ADVISOR: return (struct person_list *) &ud->advisor_list;
  default:
    fprintf(stderr, "invalid field tag: %d\n", tag);
    abort();
  }
  return 0;
}

struct addr_list *
addr_get_list(struct addr_info const *ai, int tag)
{
  switch (tag) {
  case TAG_EMAIL: return (struct addr_list *) &ai->email_list;
  case TAG_PHONE: return (struct addr_list *) &ai->phone_list;
  case TAG_HOMEPAGE: return (struct addr_list *) &ai->homepage_list;
  default:
    fprintf(stderr, "invalid field tag: %d\n", tag);
    abort();
  }
  return 0;
}

int
user_data_validate(struct userlist_data *ul)
{
  return 0;
}

void
user_data_free(struct userlist_data *ul)
{
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */

