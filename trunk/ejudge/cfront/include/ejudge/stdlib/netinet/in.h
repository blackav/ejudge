/* -*- c -*- */
/* $Id$ */
/* Copyright (C) 2002-2005 Alexander Chernov <cher@ispras.ru> */

/* This file is derived from `netinet/in.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1991-1999, 2000, 2001 Free Software Foundation, Inc.
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

#ifndef __RCC_NETINET_IN_H__
#define __RCC_NETINET_IN_H__

#include <features.h>
#include <stdint.h>
#include <sys/types.h>

int enum
{
#defconst IP_TOS             1
#defconst IP_TTL             2
#defconst IP_HDRINCL         3
#defconst IP_OPTIONS         4
#defconst IP_ROUTER_ALERT    5
#defconst IP_RECVOPTS        6
#defconst IP_RETOPTS         7
#defconst IP_PKTINFO         8
#defconst IP_PKTOPTIONS      9
#defconst IP_PMTUDISC        10
#defconst IP_MTU_DISCOVER    10
#defconst IP_RECVERR         11
#defconst IP_RECVTTL         12
#defconst IP_RECVTOS         13
#defconst IP_MULTICAST_IF    32
#defconst IP_MULTICAST_TTL   33
#defconst IP_MULTICAST_LOOP  34
#defconst IP_ADD_MEMBERSHIP  35
#defconst IP_DROP_MEMBERSHIP 36
#defconst IP_RECVRETOPTS     IP_RETOPTS
};

/* IP_MTU_DISCOVER arguments.  */
int enum
{
#defconst IP_PMTUDISC_DONT 0
#defconst IP_PMTUDISC_WANT 1
#defconst IP_PMTUDISC_DO   2
};

/* To select the IP level.  */
#ifndef SOL_IP
int enum {
#defconst SOL_IP 0
};
#endif /* SOL_IP */

int enum
{
#defconst IP_DEFAULT_MULTICAST_TTL  1
#defconst IP_DEFAULT_MULTICAST_LOOP 1
#defconst IP_MAX_MEMBERSHIPS        20
};

/* Options for use with `getsockopt' and `setsockopt' at the IPv6 level.
   The first word in the comment at the right is the data type used;
   "bool" means a boolean value stored in an `int'.  */
int enum {
#defconst IPV6_ADDRFORM         1
#defconst IPV6_PKTINFO          2
#defconst IPV6_HOPOPTS          3
#defconst IPV6_DSTOPTS          4
#defconst IPV6_RTHDR            5
#defconst IPV6_PKTOPTIONS       6
#defconst IPV6_CHECKSUM         7
#defconst IPV6_HOPLIMIT         8
#defconst IPV6_NEXTHOP          9
#defconst IPV6_AUTHHDR          10
#defconst IPV6_UNICAST_HOPS     16
#defconst IPV6_MULTICAST_IF     17
#defconst IPV6_MULTICAST_HOPS   18
#defconst IPV6_MULTICAST_LOOP   19
#defconst IPV6_JOIN_GROUP       20
#defconst IPV6_LEAVE_GROUP      21
#defconst IPV6_ROUTER_ALERT     22
#defconst IPV6_MTU_DISCOVER     23
#defconst IPV6_MTU              24
#defconst IPV6_RECVERR          25
};

#define SCM_SRCRT               IPV6_RXSRCRT

/* Obsolete synonyms for the above.  */
#define IPV6_RXHOPOPTS          IPV6_HOPOPTS
#define IPV6_RXDSTOPTS          IPV6_DSTOPTS
#define IPV6_ADD_MEMBERSHIP     IPV6_JOIN_GROUP
#define IPV6_DROP_MEMBERSHIP    IPV6_LEAVE_GROUP

/* IPV6_MTU_DISCOVER values.  */
int enum{
#defconst IPV6_PMTUDISC_DONT    0       /* Never send DF frames.  */
#defconst IPV6_PMTUDISC_WANT    1       /* Use per route hints.  */
#defconst IPV6_PMTUDISC_DO      2       /* Always DF.  */
};

/* Socket level values for IPv6.  */
int enum {
#defconst SOL_IPV6        41
#defconst SOL_ICMPV6      58
};

/* Routing header options for IPv6.  */
int enum {
#defconst IPV6_RTHDR_LOOSE      0       /* Hop doesn't need to be neighbour. */
#defconst IPV6_RTHDR_STRICT     1       /* Hop must be a neighbour.  */
};

int enum {
#defconst IPV6_RTHDR_TYPE_0     0       /* IPv6 Routing header type 0.  */
};
    
int enum
{
  IPPROTO_IP = 0,
  IPPROTO_HOPOPTS = 0,
  IPPROTO_ICMP = 1,
  IPPROTO_IGMP = 2,
  IPPROTO_IPIP = 4,
  IPPROTO_TCP = 6,
  IPPROTO_EGP = 8,
  IPPROTO_PUP = 12,
  IPPROTO_UDP = 17,
  IPPROTO_IDP = 22,
  IPPROTO_TP = 29,
  IPPROTO_IPV6 = 41,
  IPPROTO_ROUTING = 43,
  IPPROTO_FRAGMENT = 44,
  IPPROTO_RSVP = 46,
  IPPROTO_GRE = 47,
  IPPROTO_ESP = 50,
  IPPROTO_AH = 51,
  IPPROTO_ICMPV6 = 58,
  IPPROTO_NONE = 59,
  IPPROTO_DSTOPTS = 60,
  IPPROTO_MTP = 92,
  IPPROTO_ENCAP = 98,
  IPPROTO_PIM = 103,
  IPPROTO_COMP = 108,
  IPPROTO_RAW = 255,
  IPPROTO_MAX
};

int enum
{
  IPPORT_ECHO = 7,
  IPPORT_DISCARD = 9,
  IPPORT_SYSTAT = 11,
  IPPORT_DAYTIME = 13,
  IPPORT_NETSTAT = 15,
  IPPORT_FTP = 21,
  IPPORT_TELNET = 23,
  IPPORT_SMTP = 25,
  IPPORT_TIMESERVER = 37,
  IPPORT_NAMESERVER = 42,
  IPPORT_WHOIS = 43,
  IPPORT_MTP = 57,
  IPPORT_TFTP = 69,
  IPPORT_RJE = 77,
  IPPORT_FINGER = 79,
  IPPORT_TTYLINK = 87,
  IPPORT_SUPDUP = 95,
  IPPORT_EXECSERVER = 512,
  IPPORT_LOGINSERVER = 513,
  IPPORT_CMDSERVER = 514,
  IPPORT_EFSSERVER = 520,
  IPPORT_BIFFUDP = 512,
  IPPORT_WHOSERVER = 513,
  IPPORT_ROUTESERVER = 520,
  IPPORT_USERRESERVED = 5000
};

#ifndef IPPORT_RESERVED
int enum { IPPORT_RESERVED = 1024 };
#define IPPORT_RESERVED IPPORT_RESERVED
#endif
typedef uint32_t in_addr_t;

struct in_addr
{
  unsigned int s_addr;
};

int IN_CLASSA(unsigned int);
unsigned int enum
{
  IN_CLASSA_NET = 0xff000000,
  IN_CLASSA_NSHIFT = 24,
  IN_CLASSA_HOST = (0xffffffff & ~IN_CLASSA_NET),
  IN_CLASSA_MAX = 128
};

int IN_CLASSB(unsigned int);
unsigned int enum
{
  IN_CLASSB_NET = 0xffff0000,
  IN_CLASSB_NSHIFT = 16,
  IN_CLASSB_HOST = (0xffffffff & ~IN_CLASSB_NET),
  IN_CLASSB_MAX = 65536
};

int IN_CLASSC(unsigned int);
unsigned int enum
{
  IN_CLASSC_NET = 0xffffff00,
  IN_CLASSC_NSHIFT = 8,
  IN_CLASSC_HOST = (0xffffffff & ~IN_CLASSC_NET)
};

int IN_CLASSD(unsigned int);
int IN_MULTICAST(unsigned int);
int IN_EXPERIMENTAL(unsigned int);
int IN_BADCLASS(unsigned int);

unsigned int enum
{
  INADDR_ANY = 0x00000000,
  INADDR_BROADCAST = 0xffffffff,
  INADDR_NONE = 0xffffffff,
  INADDR_LOOPBACK = 0x7f000001,
  INADDR_UNSPEC_GROUP = 0xe0000000,
  INADDR_ALLHOSTS_GROUP = 0xe0000001,
  INADDR_ALLRTRS_GROUP = 0xe0000002,
  INADDR_MAX_LOCAL_GROUP = 0xe00000ff
};

int enum { IN_LOOPBACKNET = 127 };

/* Structure used to describe IP options for IP_OPTIONS. The `ip_dst'
   field is used for the first-hop gateway when using a source route
   (this gets put into the header proper).  */
struct ip_opts
{
  struct in_addr ip_dst;      /* First hop; zero without source route.  */
  char ip_opts[40];           /* Actually variable in size.  */
};

/* Structure used for IP_ADD_MEMBERSHIP and IP_DROP_MEMBERSHIP. */
struct ip_mreq
{
  struct in_addr imr_multiaddr;       /* IP multicast address of group */
  struct in_addr imr_interface;       /* local IP address of interface */
};

/* As above but including interface specification by index.  */
struct ip_mreqn
{
  struct in_addr imr_multiaddr;       /* IP multicast address of group */
  struct in_addr imr_address;         /* local IP address of interface */
  int imr_ifindex;                    /* Interface index */
};

/* Structure used for IP_PKTINFO.  */
struct in_pktinfo
{
  int ipi_ifindex;                    /* Interface index  */
  struct in_addr ipi_spec_dst;        /* Routing destination address  */
  struct in_addr ipi_addr;            /* Header destination address  */
};

#ifndef __RCC_SA_FAMILY_T_DEFINED
#define __RCC_SA_FAMILY_T_DEFINED
typedef unsigned short int sa_family_t;
#endif
#include <sys/socket.h>

typedef unsigned short in_port_t;

struct sockaddr_in
{
  unsigned short sin_family;
  unsigned short sin_port;
  struct in_addr sin_addr;
  unsigned char sin_zero[sizeof (struct sockaddr) -
                         sizeof (unsigned short) -
                         sizeof (unsigned short) -
                         sizeof (struct in_addr)];
};

unsigned int ntohl(unsigned int);
unsigned short ntohs(unsigned short);
unsigned int htonl(unsigned int);
unsigned short htons(unsigned short);

struct in6_addr
{
  union
  {
    uint8_t u6_addr8[16];
    uint16_t u6_addr16[8];
    uint32_t u6_addr32[4];
  } in6_u;
#define s6_addr   in6_u.u6_addr8
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32
};

extern const struct in6_addr in6addr_any;
extern const struct in6_addr in6addr_loopback;
#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#define IN6ADDR_LOOPBACK_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }

#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

struct sockaddr_in6
{
  __SOCKADDR_COMMON (sin6_);
  in_port_t sin6_port;
  uint32_t sin6_flowinfo;
  struct in6_addr sin6_addr;
  uint32_t sin6_scope_id;
};

struct ipv6_mreq
{
  struct in6_addr ipv6mr_multiaddr;
  unsigned int ipv6mr_interface;
};

int IN6_IS_ADDR_UNSPECIFIED(void*);
int IN6_IS_ADDR_LOOPBACK(void*);
int IN6_IS_ADDR_MULTICAST(void *);
int IN6_IS_ADDR_LINKLOCAL(void*);
int IN6_IS_ADDR_SITELOCAL(void*);
int IN6_IS_ADDR_V4MAPPED(void*);
int IN6_IS_ADDR_V4COMPAT(void*);
int IN6_ARE_ADDR_EQUAL(void *a, void *b);

int bindresvport(int __sockfd, struct sockaddr_in *__sock_in);
int bindresvport6(int __sockfd, struct sockaddr_in6 *__sock_in);

int IN6_IS_ADDR_MC_NODELOCAL(void *a);
int IN6_IS_ADDR_MC_LINKLOCAL(void *a);
int IN6_IS_ADDR_MC_SITELOCAL(void *a);
int IN6_IS_ADDR_MC_ORGLOCAL(void *a);
int IN6_IS_ADDR_MC_GLOBAL(void *a);

struct in6_pktinfo
{
  struct in6_addr ipi6_addr;
  unsigned int ipi6_ifindex;
};

#endif /* __RCC_NETINET_IN_H__ */
