/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_SYS_SOCKET_H__
#define __RCC_SYS_SOCKET_H__

/* Copyright (C) 2002,2004 Alexander Chernov <cher@ispras.ru> */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <features.h>
#include <sys/types.h>

#ifndef RCC_SIZE_T_DEFINED
#define RCC_SIZE_T_DEFINED 1
typedef unsigned long size_t;
#endif /* RCC_SIZE_T_DEFINED */

#ifndef __RCC_SA_FAMILY_T_DEFINED
#define __RCC_SA_FAMILY_T_DEFINED
typedef unsigned short int sa_family_t;
#endif

#ifndef __RCC_SOCKLEN_T_DEFINED
#define __RCC_SOCKLEN_T_DEFINED
typedef unsigned int socklen_t;
#endif

enum __socket_type
{
  SOCK_STREAM = 1,
#define SOCK_STREAM SOCK_STREAM
  SOCK_DGRAM = 2,
#define SOCK_DGRAM SOCK_DGRAM
  SOCK_RAW = 3,
#define SOCK_RAW SOCK_RAW
  SOCK_RDM = 4,
#define SOCK_RDM SOCK_RDM
  SOCK_SEQPACKET = 5,
#define SOCK_SEQPACKET SOCK_SEQPACKET
  SOCK_PACKET = 10
#define SOCK_PACKET SOCK_PACKET
};

int enum
{
  PF_UNSPEC = 0,
#define PF_UNSPEC PF_UNSPEC
  PF_LOCAL = 1,
#define PF_LOCAL PF_LOCAL
  PF_UNIX = PF_LOCAL,
#define PF_UNIX PF_UNIX
  PF_FILE = PF_LOCAL,
#define PF_FILE PF_FILE
  PF_INET = 2,
#define PF_INET PF_INET
  PF_AX25 = 3,
#define PF_AX25 PF_AX25
  PF_IPX = 4,
#define PF_IPX PF_IPX
  PF_APPLETALK = 5,
#define PF_APPLETALK PF_APPLETALK
  PF_NETROM = 6,
#define PF_NETROM PF_NETROM
  PF_BRIDGE = 7,
#define PF_BRIDGE PF_BRIDGE
  PF_ATMPVC = 8,
#define PF_ATMPVC PF_ATMPVC
  PF_X25 = 9,
#define PF_X25 PF_X25
  PF_INET6 = 10,
#define PF_INET6 PF_INET6
  PF_ROSE = 11,
#define PF_ROSE PF_ROSE
  PF_DECnet = 12,
#define PF_DECnet PF_DECnet
  PF_NETBEUI = 13,
#define PF_NETBEUI PF_NETBEUI
  PF_SECURITY = 14,
#define PF_SECURITY PF_SECURITY
  PF_KEY = 15,
#define PF_KEY PF_KEY
  PF_NETLINK = 16,
#define PF_NETLINK PF_NETLINK
  PF_ROUTE = PF_NETLINK,
#define PF_ROUTE PF_ROUTE
  PF_PACKET = 17,
#define PF_PACKET PF_PACKET
  PF_ASH = 18,
#define PF_ASH PF_ASH
  PF_ECONET = 19,
#define PF_ECONET PF_ECONET
  PF_ATMSVC = 20,
#define PF_ATMSVC PF_ATMSVC
  PF_SNA = 22,
#define PF_SNA PF_SNA
  PF_IRDA = 23,
#define PF_IRDA PF_IRDA
  PF_MAX = 32
#define PF_MAX PF_MAX
};

int enum
{
  AF_UNSPEC = PF_UNSPEC,
#define AF_UNSPEC AF_UNSPEC
  AF_LOCAL = PF_LOCAL,
#define AF_LOCAL AF_LOCAL
  AF_UNIX = PF_UNIX,
#define AF_UNIX AF_UNIX
  AF_FILE = PF_FILE,
#define AF_FILE AF_FILE
  AF_INET = PF_INET,
#define AF_INET AF_INET
  AF_AX25 = PF_AX25,
#define AF_AX25 AF_AX25
  AF_IPX = PF_IPX,
#define AF_IPX AF_IPX
  AF_APPLETALK = PF_APPLETALK,
#define AF_APPLETALK AF_APPLETALK
  AF_NETROM = PF_NETROM,
#define AF_NETROM AF_NETROM
  AF_BRIDGE = PF_BRIDGE,
#define AF_BRIDGE AF_BRIDGE
  AF_ATMPVC = PF_ATMPVC,
#define AF_ATMPVC AF_ATMPVC
  AF_X25 = PF_X25,
#define AF_X25 AF_X25
  AF_INET6 = PF_INET6,
#define AF_INET6 AF_INET6
  AF_ROSE = PF_ROSE,
#define AF_ROSE AF_ROSE
  AF_DECnet = PF_DECnet,
#define AF_DECnet AF_DECnet
  AF_NETBEUI = PF_NETBEUI,
#define AF_NETBEUI AF_NETBEUI
  AF_SECURITY = PF_SECURITY,
#define AF_SECURITY AF_SECURITY
  AF_KEY = PF_KEY,
#define AF_KEY AF_KEY
  AF_NETLINK = PF_NETLINK,
#define AF_NETLINK AF_NETLINK
  AF_ROUTE = PF_ROUTE,
#define AF_ROUTE AF_ROUTE
  AF_PACKET = PF_PACKET,
#define AF_PACKET AF_PACKET
  AF_ASH = PF_ASH,
#define AF_ASH AF_ASH
  AF_ECONET = PF_ECONET,
#define AF_ECONET AF_ECONET
  AF_ATMSVC = PF_ATMSVC,
#define AF_ATMSVC AF_ATMSVC
  AF_SNA = PF_SNA,
#define AF_SNA AF_SNA
  AF_IRDA = PF_IRDA,
#define AF_IRDA AF_IRDA
  AF_MAX = PF_MAX
#define AF_MAX AF_MAX
};

int enum
{
  SOL_RAW = 255,
#define SOL_RAW SOL_RAW
  SOL_DECNET = 261,
#define SOL_DECNET SOL_DECNET
  SOL_X25 = 262,
#define SOL_X25 SOL_X25
  SOL_PACKET = 263,
#define SOL_PACKET SOL_PACKET
  SOL_ATM = 264,
#define SOL_ATM SOL_ATM
  SOL_AAL = 265,
#define SOL_AAL SOL_AAL
  SOL_IRDA = 266,
#define SOL_IRDA SOL_IRDA
  SOL_SOCKET = 1
#define SOL_SOCKET SOL_SOCKET
};

int enum
{
  SO_DEBUG = 1,
#define SO_DEBUG SO_DEBUG
  SO_REUSEADDR = 2,
#define SO_REUSEADDR SO_REUSEADDR
  SO_TYPE = 3,
#define SO_TYPE SO_TYPE
  SO_ERROR = 4,
#define SO_ERROR SO_ERROR
  SO_DONTROUTE = 5,
#define SO_DONTROUTE SO_DONTROUTE
  SO_BROADCAST = 6,
#define SO_BROADCAST SO_BROADCAST
  SO_SNDBUF = 7,
#define SO_SNDBUF SO_SNDBUF
  SO_RCVBUF = 8,
#define SO_RCVBUF SO_RCVBUF
  SO_KEEPALIVE = 9,
#define SO_KEEPALIVE SO_KEEPALIVE
  SO_OOBINLINE = 10,
#define SO_OOBINLINE SO_OOBINLINE
  SO_NO_CHECK = 11,
#define SO_NO_CHECK SO_NO_CHECK
  SO_PRIORITY = 12,
#define SO_PRIORITY SO_PRIORITY
  SO_LINGER = 13,
#define SO_LINGER SO_LINGER
  SO_BSDCOMPAT = 14,
#define SO_BSDCOMPAT SO_BSDCOMPAT
  SO_REUSEPORT = 15,
#define SO_REUSEPORT SO_REUSEPORT
  SO_PASSCRED = 16,
#define SO_PASSCRED SO_PASSCRED
  SO_PEERCRED = 17,
#define SO_PEERCRED SO_PEERCRED
  SO_RCVLOWAT = 18,
#define SO_RCVLOWAT SO_RCVLOWAT
  SO_SNDLOWAT = 19,
#define SO_SNDLOWAT SO_SNDLOWAT
  SO_RCVTIMEO = 20,
#define SO_RCVTIMEO SO_RCVTIMEO
  SO_SNDTIMEO = 21
#define SO_SNDTIMEO SO_SNDTIMEO
};

int enum
{
  SOMAXCONN = 128
#define SOMAXCONN SOMAXCONN
};

/* Bits in the FLAGS argument to `send', `recv', et al.  */
int enum
{
  MSG_OOB = 0x01,
#define MSG_OOB MSG_OOB
  MSG_PEEK = 0x02,
#define MSG_PEEK MSG_PEEK
  MSG_DONTROUTE = 0x04,
#define MSG_DONTROUTE MSG_DONTROUTE
  MSG_TRYHARD = MSG_DONTROUTE,
#define MSG_TRYHARD MSG_DONTROUTE
  MSG_CTRUNC = 0x08,
#define MSG_CTRUNC MSG_CTRUNC
  MSG_PROXY = 0x10,
#define MSG_PROXY MSG_PROXY
  MSG_TRUNC = 0x20,
#define MSG_TRUNC MSG_TRUNC
  MSG_DONTWAIT = 0x40,
#define MSG_DONTWAIT MSG_DONTWAIT
  MSG_EOR = 0x80,
#define MSG_EOR MSG_EOR
  MSG_WAITALL = 0x100,
#define MSG_WAITALL MSG_WAITALL
  MSG_FIN = 0x200,
#define MSG_FIN MSG_FIN
  MSG_SYN = 0x400,
#define MSG_SYN MSG_SYN
  MSG_CONFIRM = 0x800,
#define MSG_CONFIRM MSG_CONFIRM
  MSG_RST = 0x1000,
#define MSG_RST MSG_RST
  MSG_ERRQUEUE = 0x2000,
#define MSG_ERRQUEUE MSG_ERRQUEUE
  MSG_NOSIGNAL = 0x4000,
#define MSG_NOSIGNAL MSG_NOSIGNAL
  MSG_MORE = 0x8000,
#define MSG_MORE MSG_MORE
};

#define __SOCKADDR_COMMON(sa_prefix) sa_family_t sa_prefix##family
#define __SOCKADDR_COMMON_SIZE  (sizeof (unsigned short int))

struct sockaddr
{
  __SOCKADDR_COMMON(sa_);
  char sa_data[14];
};

#define __ss_aligntype int
#define _SS_SIZE       128
#define _SS_PADSIZE    (_SS_SIZE - (2 * sizeof (__ss_aligntype)))

struct sockaddr_storage
{
  __SOCKADDR_COMMON (ss_);
  __ss_aligntype __ss_align;
  char __ss_padding[_SS_PADSIZE];
};

int enum
{
  SHUT_RD = 0,
#define SHUT_RD         SHUT_RD
  SHUT_WR,
#define SHUT_WR         SHUT_WR
  SHUT_RDWR
#define SHUT_RDWR       SHUT_RDWR
};

struct iovec;
struct msghdr
{
  void *msg_name;
  socklen_t msg_namelen;
  struct iovec *msg_iov;
  size_t msg_iovlen;
  void *msg_control;
  size_t msg_controllen;
  int msg_flags;
};

struct cmsghdr
{
  size_t cmsg_len;
  int cmsg_level;
  int cmsg_type;
  unsigned char __cmsg_data[0];
};

/* the following are actually macros */
unsigned char CMSG_DATA(struct cmsghdr *);
struct cmsghdr *CMSG_FIRSTHDR(struct msghdr*);
struct cmsghdr *CMSG_NXTHDR(struct msghdr *, struct cmsghdr*);
size_t CMSG_ALIGN(size_t);
size_t CMSG_SPACE(size_t);
size_t CMSG_LEN(size_t);

int enum
{
  SCM_RIGHTS = 0x01,
#define SCM_RIGHTS SCM_RIGHTS
  SCM_CREDENTIALS = 0x02,
# define SCM_CREDENTIALS SCM_CREDENTIALS
};

struct ucred
{
  pid_t pid;
  uid_t uid;
  gid_t gid;
};

struct linger
{
  int l_onoff;
  int l_linger;
};

#include <sys/uio.h>

int socket(int, int, int);
int socketpair(int, int, int, int [2]);
int bind(int, const struct sockaddr *, socklen_t);
int getsockname(int, struct sockaddr *, socklen_t *);
int connect(int, const struct sockaddr *, socklen_t);
int getpeername(int, struct sockaddr *, socklen_t *);
int send(int, const void *, size_t, int);
int recv(int, void *, size_t, int);
int sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
int recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
int sendmsg(int, const struct msghdr *, int);
int recvmsg(int, struct msghdr *, int);
int getsockopt(int, int, int, void *, socklen_t *);
int setsockopt(int, int, int, const void *, socklen_t __optlen);
int listen(int, unsigned int);
int accept(int, struct sockaddr *, socklen_t *);
int shutdown(int, int);
int isfdtype(int, int);

#ifndef SOL_IP
int enum { SOL_IP = 0 };
#define SOL_IP SOL_IP
#endif /* SOL_IP */

#ifndef SIOCATMARK
int enum {
#defconst SIOCATMARK 0x8905
};
#endif /* SIOCATMARK */

#endif /* __RCC_SYS_SOCKET_H__ */
