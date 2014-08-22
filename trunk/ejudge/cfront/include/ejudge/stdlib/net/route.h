/* $Id$ */
/* Copyright (C) 2004,2005 Alexander Chernov */

/* This file is derived from `net/route.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1997, 2002 Free Software Foundation, Inc.
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

/* Based on the 4.4BSD and Linux version of this file.  */

#ifndef __RCC_NET_ROUTE_H__
#define __RCC_NET_ROUTE_H__ 1

#include <features.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

/* This structure gets passed by the SIOCADDRT and SIOCDELRT calls. */
struct rtentry
{
  unsigned long int rt_pad1;
  struct sockaddr rt_dst;
  struct sockaddr rt_gateway;
  struct sockaddr rt_genmask;
  unsigned short int rt_flags;
  short int rt_pad2;
  unsigned long int rt_pad3;
  unsigned char rt_tos;
  unsigned char rt_class;
  short int rt_pad4;
  short int rt_metric;
  char *rt_dev;
  unsigned long int rt_mtu;
  unsigned long int rt_window;
  unsigned short int rt_irtt;
};
/* Compatibility hack.  */
#define rt_mss  rt_mtu


struct in6_rtmsg
{
  struct in6_addr rtmsg_dst;
  struct in6_addr rtmsg_src;
  struct in6_addr rtmsg_gateway;
  u_int32_t rtmsg_type;
  u_int16_t rtmsg_dst_len;
  u_int16_t rtmsg_src_len;
  u_int32_t rtmsg_metric;
  unsigned long int rtmsg_info;
  u_int32_t rtmsg_flags;
  int rtmsg_ifindex;
};

int enum
{
  RTF_UP = 0x0001,
#define RTF_UP RTF_UP
  RTF_GATEWAY = 0x0002,
#define RTF_GATEWAY RTF_GATEWAY
  RTF_HOST = 0x0004,
#define RTF_HOST RTF_HOST
  RTF_REINSTATE = 0x0008,
#define RTF_REINSTATE RTF_REINSTATE
  RTF_DYNAMIC = 0x0010,
#define RTF_DYNAMIC RTF_DYNAMIC
  RTF_MODIFIED = 0x0020,
#define RTF_MODIFIED RTF_MODIFIED
  RTF_MTU = 0x0040,
#define RTF_MTU RTF_MTU
  RTF_MSS = RTF_MTU,
#define RTF_MSS RTF_MSS
  RTF_WINDOW = 0x0080,
#define RTF_WINDOW RTF_WINDOW
  RTF_IRTT = 0x0100,
#define RTF_IRTT RTF_IRTT
  RTF_REJECT = 0x0200,
#define RTF_REJECT RTF_REJECT
  RTF_STATIC = 0x0400,
#define RTF_STATIC RTF_STATIC
  RTF_XRESOLVE = 0x0800,
#define RTF_XRESOLVE RTF_XRESOLVE
  RTF_NOFORWARD = 0x1000,
#define RTF_NOFORWARD RTF_NOFORWARD
  RTF_THROW = 0x2000,
#define RTF_THROW RTF_THROW
  RTF_NOPMTUDISC = 0x4000,
#define RTF_NOPMTUDISC RTF_NOPMTUDISC
  RTF_DEFAULT = 0x00010000,
#define RTF_DEFAULT RTF_DEFAULT
  RTF_ALLONLINK = 0x00020000,
#define RTF_ALLONLINK RTF_ALLONLINK
  RTF_ADDRCONF = 0x00040000,
#define RTF_ADDRCONF RTF_ADDRCONF
  RTF_LINKRT = 0x00100000,
#define RTF_LINKRT RTF_LINKRT
  RTF_NONEXTHOP = 0x00200000,
#define RTF_NONEXTHOP RTF_NONEXTHOP
  RTF_CACHE = 0x01000000,
#define RTF_CACHE RTF_CACHE
  RTF_FLOW = 0x02000000,
#define RTF_FLOW RTF_FLOW
  RTF_POLICY = 0x04000000,
#define RTF_POLICY RTF_POLICY
  RTCF_VALVE = 0x00200000,
#define RTCF_VALVE RTCF_VALVE
  RTCF_MASQ = 0x00400000,
#define RTCF_MASQ RTCF_MASQ
  RTCF_NAT = 0x00800000,
#define RTCF_NAT RTCF_NAT
  RTCF_DOREDIRECT = 0x01000000,
#define RTCF_DOREDIRECT RTCF_DOREDIRECT
  RTCF_LOG = 0x02000000,
#define RTCF_LOG RTCF_LOG
  RTCF_DIRECTSRC = 0x04000000,
#define RTCF_DIRECTSRC RTCF_DIRECTSRC
  RTF_LOCAL = 0x80000000,
#define RTF_LOCAL RTF_LOCAL
  RTF_INTERFACE = 0x40000000,
#define RTF_INTERFACE RTF_INTERFACE
  RTF_MULTICAST = 0x20000000,
#define RTF_MULTICAST RTF_MULTICAST
  RTF_BROADCAST = 0x10000000,
#define RTF_BROADCAST RTF_BROADCAST
  RTF_NAT = 0x08000000,
#define RTF_NAT RTF_NAT
};

int enum { RTF_ADDRCLASSMASK = 0xF8000000 };
#define RTF_ADDRCLASSMASK RTF_ADDRCLASSMASK

#define RT_ADDRCLASS(flags)     ((__u_int32_t) flags >> 23)
#define RT_TOS(tos)             ((tos) & IPTOS_TOS_MASK)
#define RT_LOCALADDR(flags)     ((flags & RTF_ADDRCLASSMASK) \
                                 == (RTF_LOCAL|RTF_INTERFACE))
int enum
{
  RT_CLASS_UNSPEC = 0,
#define RT_CLASS_UNSPEC RT_CLASS_UNSPEC
  RT_CLASS_DEFAULT = 253,
#define RT_CLASS_DEFAULT RT_CLASS_DEFAULT
  RT_CLASS_MAIN = 254,
#define RT_CLASS_MAIN RT_CLASS_MAIN
  RT_CLASS_LOCAL = 255,
#define RT_CLASS_LOCAL RT_CLASS_LOCAL
  RT_CLASS_MAX = 255,
#define RT_CLASS_MAX RT_CLASS_MAX
};

#define RTMSG_ACK NLMSG_ACK
#define RTMSG_OVERRUN NLMSG_OVERRUN

int enum
{
  RTMSG_NEWDEVICE = 0x11,
#define RTMSG_NEWDEVICE RTMSG_NEWDEVICE
  RTMSG_DELDEVICE = 0x12,
#define RTMSG_DELDEVICE RTMSG_DELDEVICE
  RTMSG_NEWROUTE = 0x21,
#define RTMSG_NEWROUTE RTMSG_NEWROUTE
  RTMSG_DELROUTE = 0x22,
#define RTMSG_DELROUTE RTMSG_DELROUTE
  RTMSG_NEWRULE = 0x31,
#define RTMSG_NEWRULE RTMSG_NEWRULE
  RTMSG_DELRULE = 0x32,
#define RTMSG_DELRULE RTMSG_DELRULE
  RTMSG_CONTROL = 0x40,
#define RTMSG_CONTROL RTMSG_CONTROL
  RTMSG_AR_FAILED = 0x51,
#define RTMSG_AR_FAILED RTMSG_AR_FAILED
};

#endif /* __RCC_NET_ROUTE_H__ */
