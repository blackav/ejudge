/* -*- c -*- */
/* $Id$ */

#ifndef	__RCC_NETDB_H__
#define	__RCC_NETDB_H__ 1

/* Copyright (C) 2003-2004 Alexander Chernov <cher@ispras.ru> */

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
#include <netinet/in.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <rpc/netdb.h>

struct netent
{
  char *n_name;
  char **n_aliases;
  int n_addrtype;
  uint32_t n_net;
};

#define	_PATH_HEQUIV		"/etc/hosts.equiv"
#define	_PATH_HOSTS		"/etc/hosts"
#define	_PATH_NETWORKS		"/etc/networks"
#define	_PATH_NSSWITCH_CONF	"/etc/nsswitch.conf"
#define	_PATH_PROTOCOLS		"/etc/protocols"
#define	_PATH_SERVICES		"/etc/services"

#define h_errno (*__h_errno_location())
int *__h_errno_location(void);

int enum
{
  NETDB_INTERNAL = -1,
#define NETDB_INTERNAL NETDB_INTERNAL
  NETDB_SUCCESS = 0,
#define NETDB_SUCCESS NETDB_SUCCESS
  HOST_NOT_FOUND = 1,
#define HOST_NOT_FOUND HOST_NOT_FOUND
  TRY_AGAIN = 2,
#define TRY_AGAIN TRY_AGAIN
  NO_RECOVERY = 3,
#define NO_RECOVERY NO_RECOVERY
  NO_DATA = 4,
#define NO_DATA NO_DATA
  NO_ADDRESS = NO_DATA,
#define NO_ADDRESS NO_ADDRESS
};

#ifndef IPPORT_RESERVED
int enum { IPPORT_RESERVED = 1024 };
#define IPPORT_RESERVED IPPORT_RESERVED
#endif

#define SCOPE_DELIMITER	'%'

void herror(const char *__str);
const char *hstrerror(int __err_num);

struct hostent
{
  char *h_name;
  char **h_aliases;
  int h_addrtype;
  int h_length;
  char **h_addr_list;
#define	h_addr	h_addr_list[0]
};

void sethostent(int __stay_open);
void endhostent(void);
struct hostent *gethostent(void);
struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type);
struct hostent *gethostbyname(const char *name);
struct hostent *gethostbyname2(const char *__name, int __af);

int gethostent_r(struct hostent * __result_buf,
                 char * __buf, size_t __buflen,
                 struct hostent ** __result,
                 int * __h_errnop);
int gethostbyaddr_r(const void * __addr, socklen_t __len,
                    int __type,
                    struct hostent * __result_buf,
                    char * __buf, size_t __buflen,
                    struct hostent ** __result,
                    int * __h_errnop);
int gethostbyname_r (const char * __name,
                     struct hostent * __result_buf,
                     char * __buf, size_t __buflen,
                     struct hostent ** __result,
                     int * __h_errnop);
int gethostbyname2_r (const char * __name, int __af,
                      struct hostent * __result_buf,
                      char * __buf, size_t __buflen,
                      struct hostent ** __result,
                      int * __h_errnop);

void setnetent(int __stay_open);
void endnetent(void);
struct netent *getnetent(void);
struct netent *getnetbyaddr(uint32_t __net, int __type);
struct netent *getnetbyname(const char *__name);

int getnetent_r(struct netent * __result_buf,
                char * __buf, size_t __buflen,
                struct netent ** __result,
                int * __h_errnop);
int getnetbyaddr_r(uint32_t __net, int __type,
                   struct netent * __result_buf,
                   char * __buf, size_t __buflen,
                   struct netent ** __result,
                   int * __h_errnop);
int getnetbyname_r(const char * __name,
                   struct netent * __result_buf,
                   char * __buf, size_t __buflen,
                   struct netent ** __result,
                   int * __h_errnop);

struct servent
{
  char *s_name;
  char **s_aliases;
  int s_port;
  char *s_proto;
};

void setservent(int __stay_open);
void endservent(void);
struct servent *getservent(void);
struct servent *getservbyname(const char *__name,
                              const char *__proto);
struct servent *getservbyport(int __port, const char *__proto);

int getservent_r(struct servent * __result_buf,
                 char * __buf, size_t __buflen,
                 struct servent ** __result);
int getservbyname_r(const char * __name,
                    const char * __proto,
                    struct servent * __result_buf,
                    char * __buf, size_t __buflen,
                    struct servent ** __result);
int getservbyport_r(int __port, const char * __proto,
                    struct servent * __result_buf,
                    char * __buf, size_t __buflen,
                    struct servent ** __result);

struct protoent
{
  char *p_name;
  char **p_aliases;
  int p_proto;
};

void setprotoent(int __stay_open);
void endprotoent(void);
struct protoent *getprotoent(void);
struct protoent *getprotobyname(const char *__name);
struct protoent *getprotobynumber(int __proto);

int getprotoent_r(struct protoent * __result_buf,
                  char * __buf, size_t __buflen,
                  struct protoent ** __result);
int getprotobyname_r(const char * __name,
                     struct protoent * __result_buf,
                     char * __buf, size_t __buflen,
                     struct protoent ** __result);
int getprotobynumber_r(int __proto,
                       struct protoent * __result_buf,
                       char * __buf, size_t __buflen,
                       struct protoent ** __result);

int setnetgrent(const char *__netgroup);
void endnetgrent(void);
int getnetgrent(char ** __hostp,
                char ** __userp,
                char ** __domainp);

int innetgr(const char *__netgroup, const char *__host,
            const char *__user, const char *domain);
int getnetgrent_r(char ** __hostp,
                  char ** __userp,
                  char ** __domainp,
                  char * __buffer, size_t __buflen);

int rcmd(char ** __ahost, unsigned short int __rport,
         const char * __locuser,
         const char * __remuser,
         const char * __cmd, int * __fd2p);
int rcmd_af(char ** __ahost, unsigned short int __rport,
            const char * __locuser,
            const char * __remuser,
            const char * __cmd, int * __fd2p,
            sa_family_t __af);
int rexec(char ** __ahost, int __rport,
          const char * __name,
          const char * __pass,
          const char * __cmd, int * __fd2p);
int rexec_af(char ** __ahost, int __rport,
             const char * __name,
             const char * __pass,
             const char * __cmd, int * __fd2p,
             sa_family_t __af);

int ruserok(const char *__rhost, int __suser,
             const char *__remuser, const char *__locuser);
int ruserok_af(const char *__rhost, int __suser,
               const char *__remuser, const char *__locuser,
               sa_family_t __af);
int rresvport(int *__alport);
int rresvport_af(int *__alport, sa_family_t __af);

struct addrinfo
{
  int ai_flags;
  int ai_family;
  int ai_socktype;
  int ai_protocol;
  socklen_t ai_addrlen;
  struct sockaddr *ai_addr;
  char *ai_canonname;
  struct addrinfo *ai_next;
};

struct gaicb
{
  const char *ar_name;
  const char *ar_service;
  const struct addrinfo *ar_request;
  struct addrinfo *ar_result;
};

int enum
{
  GAI_WAIT = 0,
#define GAI_WAIT GAI_WAIT
  GAI_NOWAIT = 1,
#define GAI_NOWAIT GAI_NOWAIT
};

int enum
{
  AI_PASSIVE = 0x0001,
#define AI_PASSIVE AI_PASSIVE
  AI_CANONNAME = 0x0002,
#define AI_CANONNAME AI_CANONNAME
  AI_NUMERICHOST = 0x0004,
#define AI_NUMERICHOST AI_NUMERICHOST
};

int enum
{
  EAI_BADFLAGS = -1,
#define EAI_BADFLAGS EAI_BADFLAGS
  EAI_NONAME = -2,
#define EAI_NONAME EAI_NONAME
  EAI_AGAIN = -3,
#define EAI_AGAIN EAI_AGAIN
  EAI_FAIL = -4,
#define EAI_FAIL EAI_FAIL
  EAI_NODATA = -5,
#define EAI_NODATA EAI_NODATA
  EAI_FAMILY = -6,
#define EAI_FAMILY EAI_FAMILY
  EAI_SOCKTYPE = -7,
#define EAI_SOCKTYPE EAI_SOCKTYPE
  EAI_SERVICE = -8,
#define EAI_SERVICE EAI_SERVICE
  EAI_ADDRFAMILY = -9,
#define EAI_ADDRFAMILY EAI_ADDRFAMILY
  EAI_MEMORY = -10,
#define EAI_MEMORY EAI_MEMORY
  EAI_SYSTEM = -11,
#define EAI_SYSTEM EAI_SYSTEM
  EAI_INPROGRESS = -100,
#define EAI_INPROGRESS EAI_INPROGRESS
  EAI_CANCELED = -101,
#define EAI_CANCELED EAI_CANCELED
  EAI_NOTCANCELED = -102,
#define EAI_NOTCANCELED EAI_NOTCANCELED
  EAI_ALLDONE = -103,
#define EAI_ALLDONE EAI_ALLDONE
  EAI_INTR = -104,
#define EAI_INTR EAI_INTR
};

int enum
{
  NI_MAXHOST = 1025,
#define NI_MAXHOST NI_MAXHOST
  NI_MAXSERV = 32,
#define NI_MAXSERV NI_MAXSERV
  NI_NUMERICHOST = 1,
#define NI_NUMERICHOST NI_NUMERICHOST
  NI_NUMERICSERV = 2,
#define NI_NUMERICSERV NI_NUMERICSERV
  NI_NOFQDN = 4,
#define NI_NOFQDN NI_NOFQDN
  NI_NAMEREQD = 8,
#define NI_NAMEREQD NI_NAMEREQD
  NI_DGRAM = 16,
#define NI_DGRAM NI_DGRAM
};

int getaddrinfo(const char * __name,
                const char * __service,
                const struct addrinfo * __req,
                struct addrinfo ** __pai);
void freeaddrinfo(struct addrinfo *__ai);
const char *gai_strerror(int __ecode);
int getnameinfo (const struct sockaddr * __sa,
                 socklen_t __salen, char * __host,
                 socklen_t __hostlen, char * __serv,
                 socklen_t __servlen, unsigned int __flags);
int getaddrinfo_a(int __mode, struct gaicb *__list[],
                  int __ent, struct sigevent * __sig);
int gai_suspend(const struct gaicb *const __list[], int __ent,
                const struct timespec *__timeout);
int gai_error(struct gaicb *__req);
int gai_cancel(struct gaicb *__gaicbp);

#endif /* __RCC_NETDB_H__ */
