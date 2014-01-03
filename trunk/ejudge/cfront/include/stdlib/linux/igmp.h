/* -*- c -*- */
/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `linux/igmp.h' of the Linux Kernel.
   The original copyright follows. */

/*
 *      Linux NET3:     Internet Group Management Protocol  [IGMP]
 *
 *      Authors:
 *              Alan Cox <Alan.Cox@linux.org>
 *
 *      Extended to talk the BSD extended IGMP protocol of mrouted 3.6
 *
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef __RCC_LINUX_IGMP_H__
#define __RCC_LINUX_IGMP_H__

/*
 *      Header in on cable format
 */

struct igmphdr
{
  unsigned char type;
  unsigned char code;
  unsigned short csum;
  unsigned int group;
};

int enum
{
  IGMP_HOST_MEMBERSHIP_QUERY = 0x11,
#define IGMP_HOST_MEMBERSHIP_QUERY IGMP_HOST_MEMBERSHIP_QUERY
  IGMP_HOST_MEMBERSHIP_REPORT = 0x12,
#define IGMP_HOST_MEMBERSHIP_REPORT IGMP_HOST_MEMBERSHIP_REPORT
  IGMP_DVMRP = 0x13,
#define IGMP_DVMRP IGMP_DVMRP
  IGMP_PIM = 0x14,
#define IGMP_PIM IGMP_PIM
  IGMP_TRACE = 0x15,
#define IGMP_TRACE IGMP_TRACE
  IGMP_HOST_NEW_MEMBERSHIP_REPORT = 0x16,
#define IGMP_HOST_NEW_MEMBERSHIP_REPORT IGMP_HOST_NEW_MEMBERSHIP_REPORT
  IGMP_HOST_LEAVE_MESSAGE = 0x17,
#define IGMP_HOST_LEAVE_MESSAGE IGMP_HOST_LEAVE_MESSAGE
  IGMP_MTRACE_RESP = 0x1e,
#define IGMP_MTRACE_RESP IGMP_MTRACE_RESP
  IGMP_MTRACE = 0x1f,
#define IGMP_MTRACE IGMP_MTRACE
  IGMP_DELAYING_MEMBER = 0x01,
#define IGMP_DELAYING_MEMBER IGMP_DELAYING_MEMBER
  IGMP_IDLE_MEMBER = 0x02,
#define IGMP_IDLE_MEMBER IGMP_IDLE_MEMBER
  IGMP_LAZY_MEMBER = 0x03,
#define IGMP_LAZY_MEMBER IGMP_LAZY_MEMBER
  IGMP_SLEEPING_MEMBER = 0x04,
#define IGMP_SLEEPING_MEMBER IGMP_SLEEPING_MEMBER
  IGMP_AWAKENING_MEMBER = 0x05,
#define IGMP_AWAKENING_MEMBER IGMP_AWAKENING_MEMBER
};

int enum
{
  IGMP_MINLEN = 8,
#define IGMP_MINLEN IGMP_MINLEN
  IGMP_MAX_HOST_REPORT_DELAY = 10,
#define IGMP_MAX_HOST_REPORT_DELAY IGMP_MAX_HOST_REPORT_DELAY
  IGMP_TIMER_SCALE = 10,
#define IGMP_TIMER_SCALE IGMP_TIMER_SCALE
  IGMP_AGE_THRESHOLD = 400,
#define IGMP_AGE_THRESHOLD IGMP_AGE_THRESHOLD
};

#define IGMP_ALL_HOSTS          htonl(0xE0000001L)
#define IGMP_ALL_ROUTER         htonl(0xE0000002L)
#define IGMP_LOCAL_GROUP        htonl(0xE0000000L)
#define IGMP_LOCAL_GROUP_MASK   htonl(0xFFFFFF00L)

#endif /* __RCC_LINUX_IGMP_H__ */
