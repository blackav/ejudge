/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __TELEGRAM_CHAT_H__
#define __TELEGRAM_CHAT_H__

/* Copyright (C) 2016-2022 Alexander Chernov <cher@ejudge.ru> */

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

/*
id 	Integer 	Unique identifier for this chat. This number may be greater than 32 bits and some programming languages may have difficulty/silent defects in interpreting it. But it smaller than 52 bits, so a signed 64 bit integer or double-precision float type are safe for storing this identifier.
type 	String 	Type of chat, can be either “private”, “group”, “supergroup” or “channel”
title 	String 	Optional. Title, for channels and group chats
username 	String 	Optional. Username, for private chats, supergroups and channels if available
first_name 	String 	Optional. First name of the other party in a private chat
last_name 	String 	Optional. Last name of the other party in a private chat
 */
struct telegram_chat
{
    long long _id;
    unsigned char *type;
    unsigned char *title;
    unsigned char *username;
    unsigned char *first_name;
    unsigned char *last_name;
};

struct telegram_chat *
telegram_chat_free(struct telegram_chat *tc);
struct telegram_chat *
telegram_chat_create(void);

#endif
