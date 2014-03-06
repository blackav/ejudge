/* -*- c -*- */
/* $Id$ */
#ifndef __NEW_SERVER_PI_H__
#define __NEW_SERVER_PI_H__

/* Copyright (C) 2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ej_types.h"

#include "external_action.h"

typedef struct PrivUserInfo
{
  int user_id;
  unsigned char *login;
  unsigned char *name;
  unsigned int role_mask;
} PrivUserInfo;

typedef struct PrivUserInfoArray
{
    int a, u;
    struct PrivUserInfo **v;
} PrivUserInfoArray;

typedef struct PrivViewPrivUsersPage
{
    PageInterface b;
    PrivUserInfoArray users;
} PrivViewPrivUsersPage;

/* */

typedef struct PrivUserIPItem
{
  int user_id;
  int ip_u;
  int ip_a;
  ej_ip_t *ips;
} PrivUserIPItem;

typedef struct PrivUserIPArray
{
    int a, u;
    PrivUserIPItem **v;
} PrivUserIPArray;

typedef struct PrivViewUserIPsPage
{
    PageInterface b;
    PrivUserIPArray users;
} PrivViewUserIPsPage;

/* */

typedef struct PrivIPUserItem
{
    ej_ip_t ip;
    unsigned char *ip_str;
    int uid_u, uid_a;
    int *uids;
} PrivIPUserItem;

typedef struct PrivIPUserArray
{
    int a, u;
    PrivIPUserItem *v;
} PrivIPUserArray;

typedef struct PrivViewIPUsersPage
{
    PageInterface b;
    PrivIPUserArray ips;
} PrivViewIPUsersPage;

#endif /* __NEW_SERVER_PI_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
