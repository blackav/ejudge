/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/compile_packet.h"
#include "ejudge/compile_packet_priv.h"
#include "ejudge/errlog.h"
#include "ejudge/ej_byteorder.h"

int
compile_reply_packet_get_contest_id(
        size_t in_size,
        const void *in_data)
{
    const struct compile_reply_bin_packet *pin = in_data;

    if (in_size < sizeof(*pin)) {
        err("compile_reply_packet_get_contest_id: invalid size: %zu instead of %zu", in_size, sizeof(*pin));
        return -1;
    }
    size_t pkt_size = cvt_bin_to_host_32(pin->packet_len);
    if (pkt_size != in_size) {
        err("compile_reply_packet_get_contest_id: invalid packet size: %zu instead of %zu", pkt_size, in_size);
        return -1;
    }
    int pkt_version = cvt_bin_to_host_32(pin->version);
    if (pkt_version != EJ_COMPILE_REPLY_PACKET_VERSION) {
        err("compile_reply_packet_get_contest_id: invalid version %d instead of %d", pkt_version, EJ_COMPILE_REPLY_PACKET_VERSION);
        return -1;
    }
    int contest_id = cvt_bin_to_host_32(pin->contest_id);
    if (contest_id <= 0) {
        err("compile_reply_packet_get_contest_id: invalid contest_id %d", contest_id);
        return -1;
    }
    return contest_id;
}
