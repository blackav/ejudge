/* -*- c -*- */
#ifndef __TELEGRAM_DATA_H__
#define __TELEGRAM_DATA_H__

/* Copyright (C) 2016 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdlib.h>
#include "ejudge/cJSON.h"

typedef struct TeBase
{
    void (*destroy)(struct TeBase *base);
} TeBase;

typedef struct TeUser
{
    TeBase b;
    long long id;
    unsigned char *first_name;
    unsigned char *last_name;
    unsigned char *username;
} TeUser;

void TeUser_destroy(TeBase *b);
TeUser *TeUser_parse(cJSON *j);

typedef struct TeChat
{
    TeBase b;
    long long id;
    unsigned char *type;
    unsigned char *title;
    unsigned char *username;
    unsigned char *first_name;
    unsigned char *last_name;
} TeChat;

void TeChat_destroy(TeBase *b);
TeChat *TeChat_parse(cJSON *j);

/*
type 	String 	Type of the entity. Can be mention (@username), hashtag, bot_command, url, email, bold (bold text), italic (italic text), code (monowidth string), pre (monowidth block), text_link (for clickable text URLs), text_mention (for users without usernames)
offset 	Integer 	Offset in UTF-16 code units to the start of the entity
length 	Integer 	Length of the entity in UTF-16 code units
url 	String 	Optional. For “text_link” only, url that will be opened after user taps on the text
user 	User 	Optional. For “text_mention” only, the mentioned user
 */
typedef struct TeMessageEntity
{
    TeBase b;
    unsigned char *type;
    int offset;
    int length;
    unsigned char *url;
    TeUser *user;
} TeMessageEntity;

void TeMessageEntity_destroy(TeBase *b);
TeMessageEntity *TeMessageEntity_parse(cJSON *j);

/*
message_id 	Integer 	Unique message identifier
from 	User 	Optional. Sender, can be empty for messages sent to channels
date 	Integer 	Date the message was sent in Unix time
chat 	Chat 	Conversation the message belongs to
forward_from 	User 	Optional. For forwarded messages, sender of the original message
forward_from_chat 	Chat 	Optional. For messages forwarded from a channel, information about the original channel
forward_date 	Integer 	Optional. For forwarded messages, date the original message was sent in Unix time
reply_to_message 	Message 	Optional. For replies, the original message. Note that the Message object in this field will not contain further reply_to_message fields even if it itself is a reply.
edit_date 	Integer 	Optional. Date the message was last edited in Unix time
text 	String 	Optional. For text messages, the actual UTF-8 text of the message, 0-4096 characters.
entities 	Array of MessageEntity 	Optional. For text messages, special entities like usernames, URLs, bot commands, etc. that appear in the text
audio 	Audio 	Optional. Message is an audio file, information about the file
document 	Document 	Optional. Message is a general file, information about the file
photo 	Array of PhotoSize 	Optional. Message is a photo, available sizes of the photo
sticker 	Sticker 	Optional. Message is a sticker, information about the sticker
video 	Video 	Optional. Message is a video, information about the video
voice 	Voice 	Optional. Message is a voice message, information about the file
caption 	String 	Optional. Caption for the document, photo or video, 0-200 characters
contact 	Contact 	Optional. Message is a shared contact, information about the contact
location 	Location 	Optional. Message is a shared location, information about the location
venue 	Venue 	Optional. Message is a venue, information about the venue
new_chat_member 	User 	Optional. A new member was added to the group, information about them (this member may be the bot itself)
left_chat_member 	User 	Optional. A member was removed from the group, information about them (this member may be the bot itself)
new_chat_title 	String 	Optional. A chat title was changed to this value
new_chat_photo 	Array of PhotoSize 	Optional. A chat photo was change to this value
delete_chat_photo 	True 	Optional. Service message: the chat photo was deleted
group_chat_created 	True 	Optional. Service message: the group has been created
supergroup_chat_created 	True 	Optional. Service message: the supergroup has been created. This field can‘t be received in a message coming through updates, because bot can’t be a member of a supergroup when it is created. It can only be found in reply_to_message if someone replies to a very first message in a directly created supergroup.
channel_chat_created 	True 	Optional. Service message: the channel has been created. This field can‘t be received in a message coming through updates, because bot can’t be a member of a channel when it is created. It can only be found in reply_to_message if someone replies to a very first message in a channel.
migrate_to_chat_id 	Integer 	Optional. The group has been migrated to a supergroup with the specified identifier. This number may be greater than 32 bits and some programming languages may have difficulty/silent defects in interpreting it. But it smaller than 52 bits, so a signed 64 bit integer or double-precision float type are safe for storing this identifier.
migrate_from_chat_id 	Integer 	Optional. The supergroup has been migrated from a group with the specified identifier. This number may be greater than 32 bits and some programming languages may have difficulty/silent defects in interpreting it. But it smaller than 52 bits, so a signed 64 bit integer or double-precision float type are safe for storing this identifier.
pinned_message 	Message 	Optional. Specified message was pinned. Note that the Message object in this field will not contain further reply_to_message fields even if it is itself a reply.
 */
typedef struct TeMessage
{
    TeBase b;
    long long message_id;
    TeUser *from;
    int date;
    TeChat *chat;
    TeUser *forward_from;
    TeChat *forward_from_chat;
    int forward_date;
    struct TeMessage *reply_to_message;
    int edit_date;
    unsigned char *text;
    struct
    {
        int length;
        TeMessageEntity **v;
    } entities;
    // TeAudio *audio;
    // TeDocument *document;
    // photo 	Array of PhotoSize 	Optional
    // TeSticker *sticker;
    // TeVideo *video;
    // TeVoice *voice;
    unsigned char *caption;
    // TeContact *contact;
    // TeLocation *location;
    // TeVenue *venue;
    TeUser *new_chat_member;
    TeUser *left_chat_member;
    unsigned char *new_chat_title;
    // new_chat_photo 	Array of PhotoSize 	Optional
    int delete_chat_photo;
    int group_chat_created;
    int supergroup_chat_created;
    int channel_chat_created;
    long long migrate_to_chat_id;
    long long migrate_from_chat_id;
    struct TeMessage *pinned_message;
} TeMessage;

void TeMessage_destroy(TeBase *b);
TeMessage *TeMessage_parse(cJSON *j);

/*
update_id 	Integer 	The update‘s unique identifier. Update identifiers start from a certain positive number and increase sequentially. This ID becomes especially handy if you’re using Webhooks, since it allows you to ignore repeated updates or to restore the correct update sequence, should they get out of order.
message 	Message 	Optional. New incoming message of any kind — text, photo, sticker, etc.
edited_message 	Message 	Optional. New version of a message that is known to the bot and was edited
inline_query 	InlineQuery 	Optional. New incoming inline query
chosen_inline_result 	ChosenInlineResult 	Optional. The result of an inline query that was chosen by a user and sent to their chat partner.
callback_query 	CallbackQuery 	Optional. New incoming callback query
*/
typedef struct TeUpdate
{
    TeBase b;
    long long update_id;
    TeMessage *message;
    TeMessage *edited_message;
    // TeInlineQuery *inline_query;
    // TeChosenInlineResult *chosen_inline_result;
    // TeCallbackQuery *callback_query;
} TeUpdate;

void TeUpdate_destroy(TeBase *b);
TeUpdate *TeUpdate_parse(cJSON *j);

typedef struct TeGetUpdatesResult
{
    TeBase b;
    int ok;
    struct
    {
        int length;
        TeUpdate **v;
    } result;
} TeGetUpdatesResult;

void TeGetUpdatesResult_destroy(TeBase *b);
TeGetUpdatesResult *TeGetUpdatesResult_parse(cJSON *j);

#endif

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
