/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `netinet/icmp6.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1991,92,93,94,95,96,97,2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef __RCC_NETINET_ICMP6_H__
#define __RCC_NETINET_ICMP6_H__ 1

/*#include <inttypes.h>*/
#include <features.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

int enum
{
  ICMP6_FILTER = 1,
#define ICMP6_FILTER ICMP6_FILTER
  ICMP6_FILTER_BLOCK = 1,
#define ICMP6_FILTER_BLOCK ICMP6_FILTER_BLOCK
  ICMP6_FILTER_PASS = 2,
#define ICMP6_FILTER_PASS ICMP6_FILTER_PASS
  ICMP6_FILTER_BLOCKOTHERS = 3,
#define ICMP6_FILTER_BLOCKOTHERS ICMP6_FILTER_BLOCKOTHERS
  ICMP6_FILTER_PASSONLY = 4,
#define ICMP6_FILTER_PASSONLY ICMP6_FILTER_PASSONLY
};

struct icmp6_filter
{
  uint32_t data[8];
};

struct icmp6_hdr
{
  uint8_t     icmp6_type;
  uint8_t     icmp6_code;
  uint16_t    icmp6_cksum;
  union
  {
    uint32_t  icmp6_un_data32[1];
    uint16_t  icmp6_un_data16[2];
    uint8_t   icmp6_un_data8[4];
  } icmp6_dataun;
};

#define icmp6_data32    icmp6_dataun.icmp6_un_data32
#define icmp6_data16    icmp6_dataun.icmp6_un_data16
#define icmp6_data8     icmp6_dataun.icmp6_un_data8
#define icmp6_pptr      icmp6_data32[0]  /* parameter prob */
#define icmp6_mtu       icmp6_data32[0]  /* packet too big */
#define icmp6_id        icmp6_data16[0]  /* echo request/reply */
#define icmp6_seq       icmp6_data16[1]  /* echo request/reply */
#define icmp6_maxdelay  icmp6_data16[0]  /* mcast group membership */

int enum
{
  ICMP6_DST_UNREACH = 1,
#define ICMP6_DST_UNREACH ICMP6_DST_UNREACH
  ICMP6_PACKET_TOO_BIG = 2,
#define ICMP6_PACKET_TOO_BIG ICMP6_PACKET_TOO_BIG
  ICMP6_TIME_EXCEEDED = 3,
#define ICMP6_TIME_EXCEEDED ICMP6_TIME_EXCEEDED
  ICMP6_PARAM_PROB = 4,
#define ICMP6_PARAM_PROB ICMP6_PARAM_PROB

  ICMP6_INFOMSG_MASK = 0x80,
#define ICMP6_INFOMSG_MASK ICMP6_INFOMSG_MASK

  ICMP6_ECHO_REQUEST = 128,
#define ICMP6_ECHO_REQUEST ICMP6_ECHO_REQUEST
  ICMP6_ECHO_REPLY = 129,
#define ICMP6_ECHO_REPLY ICMP6_ECHO_REPLY
  ICMP6_MEMBERSHIP_QUERY = 130,
#define ICMP6_MEMBERSHIP_QUERY ICMP6_MEMBERSHIP_QUERY
  ICMP6_MEMBERSHIP_REPORT = 131,
#define ICMP6_MEMBERSHIP_REPORT ICMP6_MEMBERSHIP_REPORT
  ICMP6_MEMBERSHIP_REDUCTION = 132,
#define ICMP6_MEMBERSHIP_REDUCTION ICMP6_MEMBERSHIP_REDUCTION

  ICMP6_DST_UNREACH_NOROUTE = 0,
#define ICMP6_DST_UNREACH_NOROUTE ICMP6_DST_UNREACH_NOROUTE
  ICMP6_DST_UNREACH_ADMIN = 1,
#define ICMP6_DST_UNREACH_ADMIN ICMP6_DST_UNREACH_ADMIN
  ICMP6_DST_UNREACH_NOTNEIGHBOR = 2,
#define ICMP6_DST_UNREACH_NOTNEIGHBOR ICMP6_DST_UNREACH_NOTNEIGHBOR
  ICMP6_DST_UNREACH_ADDR = 3,
#define ICMP6_DST_UNREACH_ADDR ICMP6_DST_UNREACH_ADDR
  ICMP6_DST_UNREACH_NOPORT = 4,
#define ICMP6_DST_UNREACH_NOPORT ICMP6_DST_UNREACH_NOPORT

  ICMP6_TIME_EXCEED_TRANSIT = 0,
#define ICMP6_TIME_EXCEED_TRANSIT ICMP6_TIME_EXCEED_TRANSIT
  ICMP6_TIME_EXCEED_REASSEMBLY = 1,
#define ICMP6_TIME_EXCEED_REASSEMBLY ICMP6_TIME_EXCEED_REASSEMBLY

  ICMP6_PARAMPROB_HEADER = 0,
#define ICMP6_PARAMPROB_HEADER ICMP6_PARAMPROB_HEADER
  ICMP6_PARAMPROB_NEXTHEADER = 1,
#define ICMP6_PARAMPROB_NEXTHEADER ICMP6_PARAMPROB_NEXTHEADER
  ICMP6_PARAMPROB_OPTION = 2,
#define ICMP6_PARAMPROB_OPTION ICMP6_PARAMPROB_OPTION
};

#define ICMP6_FILTER_WILLPASS(type, filterp) \
        ((((filterp)->data[(type) >> 5]) & (1 << ((type) & 31))) == 0)

#define ICMP6_FILTER_WILLBLOCK(type, filterp) \
        ((((filterp)->data[(type) >> 5]) & (1 << ((type) & 31))) != 0)

#define ICMP6_FILTER_SETPASS(type, filterp) \
        ((((filterp)->data[(type) >> 5]) &= ~(1 << ((type) & 31))))

#define ICMP6_FILTER_SETBLOCK(type, filterp) \
        ((((filterp)->data[(type) >> 5]) |=  (1 << ((type) & 31))))

#define ICMP6_FILTER_SETPASSALL(filterp) \
        memset (filterp, 0, sizeof (struct icmp6_filter));

#define ICMP6_FILTER_SETBLOCKALL(filterp) \
        memset (filterp, 0xFF, sizeof (struct icmp6_filter));

int enum
{
  ND_ROUTER_SOLICIT = 133,
#define ND_ROUTER_SOLICIT ND_ROUTER_SOLICIT
  ND_ROUTER_ADVERT = 134,
#define ND_ROUTER_ADVERT ND_ROUTER_ADVERT
  ND_NEIGHBOR_SOLICIT = 135,
#define ND_NEIGHBOR_SOLICIT ND_NEIGHBOR_SOLICIT
  ND_NEIGHBOR_ADVERT = 136,
#define ND_NEIGHBOR_ADVERT ND_NEIGHBOR_ADVERT
  ND_REDIRECT = 137,
#define ND_REDIRECT ND_REDIRECT
};

struct nd_router_solicit
{
  struct icmp6_hdr  nd_rs_hdr;
};

#define nd_rs_type               nd_rs_hdr.icmp6_type
#define nd_rs_code               nd_rs_hdr.icmp6_code
#define nd_rs_cksum              nd_rs_hdr.icmp6_cksum
#define nd_rs_reserved           nd_rs_hdr.icmp6_data32[0]

struct nd_router_advert
{
  struct icmp6_hdr  nd_ra_hdr;
  uint32_t   nd_ra_reachable;
  uint32_t   nd_ra_retransmit;
};

int enum
{
  ND_RA_FLAG_MANAGED = 0x80,
#define ND_RA_FLAG_MANAGED ND_RA_FLAG_MANAGED
  ND_RA_FLAG_OTHER = 0x40,
#define ND_RA_FLAG_OTHER ND_RA_FLAG_OTHER
  ND_RA_FLAG_HOME_AGENT = 0x20,
#define ND_RA_FLAG_HOME_AGENT ND_RA_FLAG_HOME_AGENT
};

#define nd_ra_type               nd_ra_hdr.icmp6_type
#define nd_ra_code               nd_ra_hdr.icmp6_code
#define nd_ra_cksum              nd_ra_hdr.icmp6_cksum
#define nd_ra_curhoplimit        nd_ra_hdr.icmp6_data8[0]
#define nd_ra_flags_reserved     nd_ra_hdr.icmp6_data8[1]
#define nd_ra_router_lifetime    nd_ra_hdr.icmp6_data16[1]

struct nd_neighbor_solicit
{
  struct icmp6_hdr  nd_ns_hdr;
  struct in6_addr   nd_ns_target;
};

#define nd_ns_type               nd_ns_hdr.icmp6_type
#define nd_ns_code               nd_ns_hdr.icmp6_code
#define nd_ns_cksum              nd_ns_hdr.icmp6_cksum
#define nd_ns_reserved           nd_ns_hdr.icmp6_data32[0]

struct nd_neighbor_advert
{
  struct icmp6_hdr  nd_na_hdr;
  struct in6_addr   nd_na_target;
};

#define nd_na_type               nd_na_hdr.icmp6_type
#define nd_na_code               nd_na_hdr.icmp6_code
#define nd_na_cksum              nd_na_hdr.icmp6_cksum
#define nd_na_flags_reserved     nd_na_hdr.icmp6_data32[0]

int enum
{
  ND_NA_FLAG_ROUTER = 0x00000080,
#define ND_NA_FLAG_ROUTER ND_NA_FLAG_ROUTER
  ND_NA_FLAG_SOLICITED = 0x00000040,
#define ND_NA_FLAG_SOLICITED ND_NA_FLAG_SOLICITED
  ND_NA_FLAG_OVERRIDE = 0x00000020,
#define ND_NA_FLAG_OVERRIDE ND_NA_FLAG_OVERRIDE
};

struct nd_redirect
{
  struct icmp6_hdr  nd_rd_hdr;
  struct in6_addr   nd_rd_target;
  struct in6_addr   nd_rd_dst;
};

#define nd_rd_type               nd_rd_hdr.icmp6_type
#define nd_rd_code               nd_rd_hdr.icmp6_code
#define nd_rd_cksum              nd_rd_hdr.icmp6_cksum
#define nd_rd_reserved           nd_rd_hdr.icmp6_data32[0]

struct nd_opt_hdr
{
  uint8_t  nd_opt_type;
  uint8_t  nd_opt_len;
};

int enum
{
  ND_OPT_SOURCE_LINKADDR = 1,
#define ND_OPT_SOURCE_LINKADDR ND_OPT_SOURCE_LINKADDR
  ND_OPT_TARGET_LINKADDR = 2,
#define ND_OPT_TARGET_LINKADDR ND_OPT_TARGET_LINKADDR
  ND_OPT_PREFIX_INFORMATION = 3,
#define ND_OPT_PREFIX_INFORMATION ND_OPT_PREFIX_INFORMATION
  ND_OPT_REDIRECTED_HEADER = 4,
#define ND_OPT_REDIRECTED_HEADER ND_OPT_REDIRECTED_HEADER
  ND_OPT_MTU = 5,
#define ND_OPT_MTU ND_OPT_MTU
  ND_OPT_RTR_ADV_INTERVAL = 7,
#define ND_OPT_RTR_ADV_INTERVAL ND_OPT_RTR_ADV_INTERVAL
  ND_OPT_HOME_AGENT_INFO = 8,
#define ND_OPT_HOME_AGENT_INFO ND_OPT_HOME_AGENT_INFO
};

struct nd_opt_prefix_info
{
  uint8_t   nd_opt_pi_type;
  uint8_t   nd_opt_pi_len;
  uint8_t   nd_opt_pi_prefix_len;
  uint8_t   nd_opt_pi_flags_reserved;
  uint32_t  nd_opt_pi_valid_time;
  uint32_t  nd_opt_pi_preferred_time;
  uint32_t  nd_opt_pi_reserved2;
  struct in6_addr  nd_opt_pi_prefix;
};

int enum
{
  ND_OPT_PI_FLAG_ONLINK = 0x80,
#define ND_OPT_PI_FLAG_ONLINK ND_OPT_PI_FLAG_ONLINK
  ND_OPT_PI_FLAG_AUTO = 0x40,
#define ND_OPT_PI_FLAG_AUTO ND_OPT_PI_FLAG_AUTO
  ND_OPT_PI_FLAG_RADDR = 0x20,
#define ND_OPT_PI_FLAG_RADDR ND_OPT_PI_FLAG_RADDR
};

struct nd_opt_rd_hdr
{
  uint8_t   nd_opt_rh_type;
  uint8_t   nd_opt_rh_len;
  uint16_t  nd_opt_rh_reserved1;
  uint32_t  nd_opt_rh_reserved2;
};

struct nd_opt_mtu
{
  uint8_t   nd_opt_mtu_type;
  uint8_t   nd_opt_mtu_len;
  uint16_t  nd_opt_mtu_reserved;
  uint32_t  nd_opt_mtu_mtu;
};

/* Mobile IPv6 extension: Advertisement Interval.  */
struct nd_opt_adv_interval
{
  uint8_t   nd_opt_adv_interval_type;
  uint8_t   nd_opt_adv_interval_len;
  uint16_t  nd_opt_adv_interval_reserved;
  uint32_t  nd_opt_adv_interval_ival;
};

/* Mobile IPv6 extension: Home Agent Info.  */
struct nd_opt_home_agent_info
{
  uint8_t   nd_opt_home_agent_info_type;
  uint8_t   nd_opt_home_agent_info_len;
  uint16_t  nd_opt_home_agent_info_reserved;
  int16_t   nd_opt_home_agent_info_preference;
  uint16_t  nd_opt_home_agent_info_lifetime;
};

#endif /* __RCC_NETINET_ICMP6_H__ */
