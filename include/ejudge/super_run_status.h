/* -*- c -*- */
#ifndef __SUPER_RUN_STATUS_H__
#define __SUPER_RUN_STATUS_H__

/* Copyright (C) 2015 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include "ejudge/ej_types.h"

struct super_run_status
{
    unsigned char  signature[4]; // 0: signature magic
    unsigned char  endiannes;    // 4: 1 - LE, 1 - BE
    unsigned char  pad1;
    unsigned short version;      // 6: packet version number (1, ...)
    unsigned short size;         // 8: packet size
    unsigned short strings_off;  // 10: offset of the string pool
    unsigned short str_end_off;  // 12: end of the strings
    unsigned char  pad2[2];
    long long      timestamp;    // 16: status timestamp, milliseconds from the epoch
    long long      last_run_ts;  // 24: time of the last testing performed

    unsigned short inst_id_idx;  // 32: instance id index
    unsigned short int_ip_idx;   // 34: internal IP address index
    unsigned short int_host_idx; // 36: internal host name index
    unsigned short ext_ip_idx;   // 38: external IP address index
    unsigned short ext_host_idx; // 40: external host name index
    unsigned short queue_idx;    // 42: testing queue name

    int            contest_id;   // 44: contest_id being tested
    int            run_id;       // 48: run_id being tested
    int            test_num;     // 52: test being tested
    short          status;       // 56: status
    unsigned short pkt_name_idx; // 58: packet name index
    unsigned char  pad3[4];

    unsigned char  pad4[192];

    unsigned char  strings[256]; // string pool
};

#endif /* __SUPER_RUN_STATUS_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
