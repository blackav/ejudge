/* -*- c -*- */
/* $Id$ */
#ifndef __EXTERNAL_ACTION_H__
#define __EXTERNAL_ACTION_H__

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

typedef struct ExternalActionState
{
    void *dl_handle;
    void *action_handler;
    unsigned char *err_msg;
} ExternalActionState;

ExternalActionState *
external_action_load(
        ExternalActionState *state,
        const unsigned char *dir,
        const unsigned char *action,
        const unsigned char *name_prefix);

#endif /* __EXTERNAL_ACTION_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
