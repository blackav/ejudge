/* -*- c -*- */

#ifndef __WEBSOCKET_H__
#define __WEBSOCKET_H__

/* Copyright (C) 2018 Alexander Chernov <cher@ejudge.ru> */

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

enum
{
    WS_FRAME_NULL = 0,
    WS_FRAME_TEXT = 1,
    WS_FRAME_BIN = 2,
    WS_FRAME_CLOSE = 8,
    WS_FRAME_PING = 9,
    WS_FRAME_PONG = 10,
};

enum
{
    WS_STATUS_NORMAL = 1000,
    WS_STATUS_GOING_AWAY,
    WS_STATUS_PROTOCOL_ERROR,
    WS_STATUS_DATA_TYPE_UNSUPPORTED,
    WS_STATUS_1004,
    WS_STATUS_1005,
    WS_STATUS_1006,
    WS_STATUS_INVALID_DATA,
    WS_STATUS_POLICY_VIOLATION,
    WS_STATUS_MESSAGE_TOO_BIG,
    WS_STATUS_EXTENSION_NEEDED,
    WS_STATUS_INTERNAL_ERROR,
};

#endif
