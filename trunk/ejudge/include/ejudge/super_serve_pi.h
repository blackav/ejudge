/* -*- c -*- */
/* $Id$ */
#ifndef __SUPER_SERVE_PI_H__
#define __SUPER_SERVE_PI_H__

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

#include "ejudge/ej_types.h"

#include "ejudge/external_action.h"

#include <time.h>

typedef struct CspContestInfo
{
    int serial;
    int id;
    unsigned char *name;
    int closed;
    int invisible;
    int details_enabled;
    int edit_users_enabled;
    int edit_settings_enabled;
    int edit_tests_enabled;
    int judge_enabled;
    int master_enabled;
    int user_enabled;
    unsigned char *comment;
} CspContestInfo;

typedef struct CspContestsArray
{
    int a, u;
    CspContestInfo **v;
} CspContestsArray;

typedef struct CspNewMainPage
{
    PageInterface b;
    CspContestsArray contests;
} CspNewMainPage;

typedef struct CspCheckTestsPage
{
    PageInterface b;
    int status;
    unsigned char *log_txt;
} CspCheckTestsPage;

void super_serve_pi_init(void);

#endif /* __SUPER_SERVE_PI_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
