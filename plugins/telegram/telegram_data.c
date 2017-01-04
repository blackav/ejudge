/* -*- mode: c -*- */

/* Copyright (C) 2016-2017 Alexander Chernov <cher@ejudge.ru> */

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

#include "telegram_data.h"

#include "ejudge/errlog.h"
#include "ejudge/xalloc.h"

#define JSON_IFOBJECT(jj, j, f) ((jj = cJSON_GetObjectItem(j, f)) && jj->type == cJSON_Object)

void TeUser_destroy(TeBase *b)
{
    TeUser *u = (TeUser*) b;
    if (u) {
        xfree(u->first_name);
        xfree(u->last_name);
        xfree(u->username);
        xfree(u);
    }
}

TeUser *TeUser_parse(cJSON *j)
{
    TeUser *p = NULL;
    cJSON *jj;

    if (!j || j->type != cJSON_Object) return NULL;
    XCALLOC(p, 1);
    p->b.destroy = TeUser_destroy;
    jj = cJSON_GetObjectItem(j, "id");
    if (!jj || jj->type != cJSON_Number) goto cleanup;
    p->id = jj->valuedouble;
    jj = cJSON_GetObjectItem(j, "first_name");
    if (!jj || jj->type != cJSON_String) goto cleanup;
    p->first_name = xstrdup(jj->valuestring);
    jj = cJSON_GetObjectItem(j, "last_name");
    if (jj && jj->type == cJSON_String) {
        p->last_name = xstrdup(jj->valuestring);
    }
    jj = cJSON_GetObjectItem(j, "username");
    if (jj && jj->type == cJSON_String) {
        p->username = xstrdup(jj->valuestring);
    }
    return p;

cleanup:
    TeUser_destroy(&p->b);
    return NULL;
}

void TeChat_destroy(TeBase *b)
{
    TeChat *p = (TeChat*) b;
    if (p) {
        xfree(p->type);
        xfree(p->title);
        xfree(p->username);
        xfree(p->first_name);
        xfree(p->last_name);
        xfree(p);
    }
}

TeChat *TeChat_parse(cJSON *j)
{
    TeChat *p = NULL;
    cJSON *jj;

    if (!j || j->type != cJSON_Object) goto cleanup;
    XCALLOC(p, 1);
    p->b.destroy = TeChat_destroy;
    jj = cJSON_GetObjectItem(j, "id");
    if (!jj || jj->type != cJSON_Number) goto cleanup;
    p->id = jj->valuedouble;
    jj = cJSON_GetObjectItem(j, "type");
    if (!jj || jj->type != cJSON_String) goto cleanup;
    p->type = xstrdup(jj->valuestring);
    if ((jj = cJSON_GetObjectItem(j, "username")) && jj->type == cJSON_String) {
        p->username = xstrdup(jj->valuestring);
    }
    if ((jj = cJSON_GetObjectItem(j, "first_name")) && jj->type == cJSON_String) {
        p->first_name = xstrdup(jj->valuestring);
    }
    if ((jj = cJSON_GetObjectItem(j, "last_name")) && jj->type == cJSON_String) {
        p->last_name = xstrdup(jj->valuestring);
    }
    return p;

cleanup:
    TeChat_destroy(&p->b);
    return NULL;
}

void
TeMessageEntity_destroy(TeBase *b)
{
    TeMessageEntity *p = (TeMessageEntity*) b;
    if (p) {
        xfree(p->type);
        xfree(p->url);
        TeUser_destroy(&p->user->b);
        xfree(p);
    }
}
TeMessageEntity *
TeMessageEntity_parse(cJSON *j)
{
    TeMessageEntity *p = NULL;
    cJSON *jj;

    if (!j || j->type != cJSON_Object) goto cleanup;
    XCALLOC(p, 1);
    p->b.destroy = TeMessageEntity_destroy;
    p->offset = -1;
    p->length = -1;

    if ((jj = cJSON_GetObjectItem(j, "type")) && jj->type == cJSON_String) {
        p->type = xstrdup(jj->valuestring);
    }
    if ((jj = cJSON_GetObjectItem(j, "offset")) && jj->type == cJSON_Number) {
        p->offset = jj->valueint;
    }
    if ((jj = cJSON_GetObjectItem(j, "length")) && jj->type == cJSON_Number) {
        p->length = jj->valueint;
    }
    if ((jj = cJSON_GetObjectItem(j, "url")) && jj->type == cJSON_String) {
        p->url = xstrdup(jj->valuestring);
    }
    if (JSON_IFOBJECT(jj, j, "user")) {
        if (!(p->user = TeUser_parse(jj))) goto cleanup;
    }

    return p;

cleanup:
    TeMessageEntity_destroy(&p->b);
    return NULL;
}

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

void TeMessage_destroy(TeBase *b)
{
    TeMessage *p = (TeMessage*) b;
    if (p) {
        if (p->from) p->from->b.destroy(&p->from->b);
        if (p->chat) p->chat->b.destroy(&p->chat->b);
        if (p->forward_from) p->forward_from->b.destroy(&p->forward_from->b);
        if (p->forward_from_chat) p->forward_from_chat->b.destroy(&p->forward_from_chat->b);
        if (p->reply_to_message) p->reply_to_message->b.destroy(&p->reply_to_message->b);
        xfree(p->text);
        for (int i = 0; i < p->entities.length; ++i) {
            p->entities.v[i]->b.destroy(&p->entities.v[i]->b);
        }
        xfree(p->entities.v);
        // TeAudio *audio;
        // TeDocument *document;
        // photo 	Array of PhotoSize 	Optional
        // TeSticker *sticker;
        // TeVideo *video;
        // TeVoice *voice;
        xfree(p->caption);
        // TeContact *contact;
        // TeLocation *location;
        // TeVenue *venue;
        if (p->new_chat_member) p->new_chat_member->b.destroy(&p->new_chat_member->b);
        if (p->left_chat_member) p->left_chat_member->b.destroy(&p->left_chat_member->b);
        xfree(p->new_chat_title);
        // new_chat_photo 	Array of PhotoSize 	Optional
        if (p->pinned_message) p->pinned_message->b.destroy(&p->pinned_message->b);
        xfree(p);
    }
}

TeMessage *TeMessage_parse(cJSON *j)
{
    TeMessage *p = NULL;
    cJSON *jj;

    if (!j || j->type != cJSON_Object) goto cleanup;
    XCALLOC(p, 1);
    p->b.destroy = TeMessage_destroy;
    if (!(jj = cJSON_GetObjectItem(j, "message_id")) || jj->type != cJSON_Number) goto cleanup;
    p->message_id = jj->valuedouble;
    if (JSON_IFOBJECT(jj, j, "from")) {
        if (!(p->from = TeUser_parse(jj))) goto cleanup;
    }
    if (!(jj = cJSON_GetObjectItem(j, "date")) || jj->type != cJSON_Number || jj->valueint <= 0) goto cleanup;
    p->date = jj->valueint;
    if (JSON_IFOBJECT(jj, j, "chat")) {
        if (!(p->chat = TeChat_parse(jj))) goto cleanup;
    }
    if (JSON_IFOBJECT(jj, j, "forward_from")) {
        if (!(p->forward_from = TeUser_parse(jj))) goto cleanup;
    }
    if (JSON_IFOBJECT(jj, j, "forward_from_chat")) {
        if (!(p->forward_from_chat = TeChat_parse(jj))) goto cleanup;
    }
    if ((jj = cJSON_GetObjectItem(j, "forward_date")) && jj->type == cJSON_Number && jj->valueint > 0) {
        p->forward_date = jj->valueint;
    }
    if (JSON_IFOBJECT(jj, j, "reply_to_message")) {
        if (!(p->reply_to_message = TeMessage_parse(jj))) goto cleanup;
    }
    if ((jj = cJSON_GetObjectItem(j, "edit_date")) && jj->type == cJSON_Number && jj->valueint > 0) {
        p->edit_date = jj->valueint;
    }
    if ((jj = cJSON_GetObjectItem(j, "text")) && jj->type == cJSON_String) {
        p->text = xstrdup(jj->valuestring);
    }
    if ((jj = cJSON_GetObjectItem(j, "entities")) && jj->type == cJSON_Array) {
        int size = cJSON_GetArraySize(jj);
        if (size > 0) {
            p->entities.length = size;
            XCALLOC(p->entities.v, size);
            for (int i = 0; i < size; ++i) {
                TeMessageEntity *e = TeMessageEntity_parse(cJSON_GetArrayItem(jj, i));
                if (!e) goto cleanup;
                p->entities.v[i] = e;
            }
        }
    }
    if ((jj = cJSON_GetObjectItem(j, "caption")) && jj->type == cJSON_String) {
        p->caption = xstrdup(jj->valuestring);
    }
    if (JSON_IFOBJECT(jj, j, "new_chat_member")) {
        if (!(p->new_chat_member = TeUser_parse(jj))) goto cleanup;
    }
    if (JSON_IFOBJECT(jj, j, "left_chat_member")) {
        if (!(p->left_chat_member = TeUser_parse(jj))) goto cleanup;
    }
    if ((jj = cJSON_GetObjectItem(j, "new_chat_title")) && jj->type == cJSON_String) {
        p->new_chat_title = xstrdup(jj->valuestring);
    }
    if ((jj = cJSON_GetObjectItem(j, "delete_chat_photo")) && jj->type == cJSON_True) {
        p->delete_chat_photo = 1;
    }
    if ((jj = cJSON_GetObjectItem(j, "group_chat_created")) && jj->type == cJSON_True) {
        p->group_chat_created = 1;
    }
    if ((jj = cJSON_GetObjectItem(j, "supergroup_chat_created")) && jj->type == cJSON_True) {
        p->supergroup_chat_created = 1;
    }
    if ((jj = cJSON_GetObjectItem(j, "channel_chat_created")) && jj->type == cJSON_True) {
        p->channel_chat_created = 1;
    }
    if ((jj = cJSON_GetObjectItem(j, "migrate_to_chat_id")) && jj->type == cJSON_Number) {
        p->migrate_to_chat_id = jj->valuedouble;
    }
    if ((jj = cJSON_GetObjectItem(j, "migrate_from_chat_id")) && jj->type == cJSON_Number) {
        p->migrate_from_chat_id = jj->valuedouble;
    }
    if ((jj = cJSON_GetObjectItem(j, "pinned_message")) && jj->type == cJSON_Object) {
        if (!(p->pinned_message = TeMessage_parse(jj))) goto cleanup;
    }
    return p;

cleanup:
    TeMessage_destroy(&p->b);
    return NULL;
}

void TeUpdate_destroy(TeBase *b)
{
    TeUpdate *p = (TeUpdate*) b;
    if (p) {
        TeMessage_destroy(&p->message->b);
        TeMessage_destroy(&p->edited_message->b);
        xfree(p);
    }
}

TeUpdate *TeUpdate_parse(cJSON *j)
{
    TeUpdate *p = NULL;
    cJSON *jj;

    if (!j || j->type != cJSON_Object) goto cleanup;
    XCALLOC(p, 1);
    p->b.destroy = TeUpdate_destroy;
    if ((jj = cJSON_GetObjectItem(j, "update_id")) && jj->type == cJSON_Number) {
        p->update_id = jj->valuedouble;
    }
    if ((jj = cJSON_GetObjectItem(j, "message")) && jj->type == cJSON_Object) {
        if (!(p->message = TeMessage_parse(jj))) {
            err("%s:%d parse failed", __FUNCTION__, __LINE__);
            goto cleanup;
        }
    }
    if ((jj = cJSON_GetObjectItem(j, "edited_message")) && jj->type == cJSON_Object) {
        if (!(p->edited_message = TeMessage_parse(jj))) {
            err("%s:%d parse failed", __FUNCTION__, __LINE__);
            goto cleanup;
        }
    }
    return p;

cleanup:
    TeUpdate_destroy(&p->b);
    return NULL;
}

void TeGetUpdatesResult_destroy(TeBase *b)
{
    TeGetUpdatesResult *p = (TeGetUpdatesResult *) b;
    if (p) {
        for (int i = 0; i < p->result.length; ++i) {
            TeUpdate_destroy(&p->result.v[i]->b);
        }
        xfree(p->result.v);
        xfree(p);
    }
}

TeGetUpdatesResult *TeGetUpdatesResult_parse(cJSON *j)
{
    TeGetUpdatesResult *p = NULL;
    cJSON *jj;

    if (!j || j->type != cJSON_Object) goto cleanup;
    XCALLOC(p, 1);
    p->b.destroy = TeGetUpdatesResult_destroy;
    if ((jj = cJSON_GetObjectItem(j, "ok")) && jj->type == cJSON_True) {
        p->ok = 1;
    }
    if ((jj = cJSON_GetObjectItem(j, "result")) && jj->type == cJSON_Array) {
        int size = cJSON_GetArraySize(jj);
        if (size > 0) {
            p->result.length = size;
            XCALLOC(p->result.v, size);
            for (int i = 0; i < size; ++i) {
                TeUpdate *e = TeUpdate_parse(cJSON_GetArrayItem(jj, i));
                if (!e) {
                    err("%s:%d:%d parse failed", __FUNCTION__, __LINE__, i);
                    goto cleanup;
                }
                p->result.v[i] = e;
            }
        }
    }

    return p;

cleanup:
    TeGetUpdatesResult_destroy(&p->b);
    return NULL;
}

void TeSendMessageResult_destroy(TeBase *b)
{
    TeSendMessageResult *p = (TeSendMessageResult*) b;
    if (p) {
        if (p->result) p->result->b.destroy(&p->result->b);
        xfree(p);
    }
}

TeSendMessageResult *TeSendMessageResult_parse(cJSON *j)
{
    TeSendMessageResult *p = NULL;
    cJSON *jj;

    if (!j || j->type != cJSON_Object) goto cleanup;
    XCALLOC(p, 1);
    p->b.destroy = TeSendMessageResult_destroy;
    if ((jj = cJSON_GetObjectItem(j, "ok")) && jj->type == cJSON_True) {
        p->ok = 1;
    }
    if (JSON_IFOBJECT(jj, j, "result")) {
        if (!(p->result = TeMessage_parse(jj))) goto cleanup;
    }

    return p;

cleanup:
    TeSendMessageResult_destroy(&p->b);
    return NULL;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
