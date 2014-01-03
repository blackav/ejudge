/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `stropts.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1998, 1999, 2000, 2002 Free Software Foundation, Inc.
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

#ifndef __RCC_STROPTS_H__
#define __RCC_STROPTS_H__ 1

#include <features.h>
#include <sys/types.h>

typedef unsigned long int  t_uscalar_t;

/* Get system specific contants.  */
int enum
{
  __SID = ('S' << 8),
#define __SID __SID
  I_NREAD = (__SID | 1),
#define I_NREAD I_NREAD
  I_PUSH = (__SID | 2),
#define I_PUSH I_PUSH
  I_POP = (__SID | 3),
#define I_POP I_POP
  I_LOOK = (__SID | 4),
#define I_LOOK I_LOOK
  I_FLUSH = (__SID | 5),
#define I_FLUSH I_FLUSH
  I_SRDOPT = (__SID | 6),
#define I_SRDOPT I_SRDOPT
  I_GRDOPT = (__SID | 7),
#define I_GRDOPT I_GRDOPT
  I_STR = (__SID | 8),
#define I_STR I_STR
  I_SETSIG = (__SID | 9),
#define I_SETSIG I_SETSIG
  I_GETSIG = (__SID |10),
#define I_GETSIG I_GETSIG
  I_FIND = (__SID |11),
#define I_FIND I_FIND
  I_LINK = (__SID |12),
#define I_LINK I_LINK
  I_UNLINK = (__SID |13),
#define I_UNLINK I_UNLINK
  I_PEEK = (__SID |15),
#define I_PEEK I_PEEK
  I_FDINSERT = (__SID |16),
#define I_FDINSERT I_FDINSERT
  I_SENDFD = (__SID |17),
#define I_SENDFD I_SENDFD
  I_RECVFD = (__SID |14),
#define I_RECVFD I_RECVFD
  I_SWROPT = (__SID |19),
#define I_SWROPT I_SWROPT
  I_GWROPT = (__SID |20),
#define I_GWROPT I_GWROPT
  I_LIST = (__SID |21),
#define I_LIST I_LIST
  I_PLINK = (__SID |22),
#define I_PLINK I_PLINK
  I_PUNLINK = (__SID |23),
#define I_PUNLINK I_PUNLINK
  I_FLUSHBAND = (__SID |28),
#define I_FLUSHBAND I_FLUSHBAND
  I_CKBAND = (__SID |29),
#define I_CKBAND I_CKBAND
  I_GETBAND = (__SID |30),
#define I_GETBAND I_GETBAND
  I_ATMARK = (__SID |31),
#define I_ATMARK I_ATMARK
  I_SETCLTIME = (__SID |32),
#define I_SETCLTIME I_SETCLTIME
  I_GETCLTIME = (__SID |33),
#define I_GETCLTIME I_GETCLTIME
  I_CANPUT = (__SID |34),
#define I_CANPUT I_CANPUT
};

int enum { FMNAMESZ = 8 };
#define FMNAMESZ FMNAMESZ

/* Flush options.  */
int enum
{
  FLUSHR = 0x01,
#define FLUSHR FLUSHR
  FLUSHW = 0x02,
#define FLUSHW FLUSHW
  FLUSHRW = 0x03,
#define FLUSHRW FLUSHRW
  FLUSHBAND = 0x04,
#define FLUSHBAND FLUSHBAND
};

int enum
{
  S_INPUT = 0x0001,
#define S_INPUT S_INPUT
  S_HIPRI = 0x0002,
#define S_HIPRI S_HIPRI
  S_OUTPUT = 0x0004,
#define S_OUTPUT S_OUTPUT
  S_MSG = 0x0008,
#define S_MSG S_MSG
  S_ERROR = 0x0010,
#define S_ERROR S_ERROR
  S_HANGUP = 0x0020,
#define S_HANGUP S_HANGUP
  S_RDNORM = 0x0040,
#define S_RDNORM S_RDNORM
  S_WRNORM = S_OUTPUT,
#define S_WRNORM S_WRNORM
  S_RDBAND = 0x0080,
#define S_RDBAND S_RDBAND
  S_WRBAND = 0x0100,
#define S_WRBAND S_WRBAND
  S_BANDURG = 0x0200,
#define S_BANDURG S_BANDURG
};

int enum { RS_HIPRI = 0x01 };
#define RS_HIPRI RS_HIPRI

/* Options for `I_SRDOPT'.  */
int enum
{
  RNORM = 0x0000,
#define RNORM RNORM
  RMSGD = 0x0001,
#define RMSGD RMSGD
  RMSGN = 0x0002,
#define RMSGN RMSGN
  RPROTDAT = 0x0004,
#define RPROTDAT RPROTDAT
  RPROTDIS = 0x0008,
#define RPROTDIS RPROTDIS
  RPROTNORM = 0x0010,
#define RPROTNORM RPROTNORM
  RPROTMASK = 0x001C,
#define RPROTMASK RPROTMASK
};

/* Possible mode for `I_SWROPT'.  */
int enum
{
  SNDZERO = 0x001,
#define SNDZERO SNDZERO
  SNDPIPE = 0x002,
#define SNDPIPE SNDPIPE
};

int enum
{
  ANYMARK = 0x01,
#define ANYMARK ANYMARK
  LASTMARK = 0x02,
#define LASTMARK LASTMARK
};

/* Argument for `I_UNLINK'.  */
int enum { MUXID_ALL = (-1) };
#define MUXID_ALL MUXID_ALL

/* Macros for `getmsg', `getpmsg', `putmsg' and `putpmsg'.  */
int enum
{
  MSG_HIPRI = 0x01,
#define MSG_HIPRI MSG_HIPRI
  MSG_ANY = 0x02,
#define MSG_ANY MSG_ANY
  MSG_BAND = 0x04,
#define MSG_BAND MSG_BAND
};

/* Values returned by getmsg and getpmsg */
int enum
{
  MORECTL = 1,
#define MORECTL MORECTL
  MOREDATA = 2,
#define MOREDATA MOREDATA
};

struct bandinfo
{
  unsigned char bi_pri;
  int bi_flag;
};

struct strbuf
{
  int maxlen;
  int len;
  char *buf;
};

struct strpeek
{
  struct strbuf ctlbuf;
  struct strbuf databuf;
  t_uscalar_t flags;
};

struct strfdinsert
{
  struct strbuf ctlbuf;
  struct strbuf databuf;
  t_uscalar_t flags;
  int fildes;
  int offset;
};

struct strioctl
{
  int ic_cmd;
  int ic_timout;
  int ic_len;
  char *ic_dp;
};

struct strrecvfd
{
  int fd;
  uid_t uid;
  gid_t gid;
  char __fill[8];
};

struct str_mlist
{
  char l_name[FMNAMESZ + 1];
};

struct str_list
{
  int sl_nmods;
  struct str_mlist *sl_modlist;
};

int isastream(int fildes);
int getmsg(int fildes, struct strbuf *ctlptr, struct strbuf *dataptr,
           int *flagsp);
int getpmsg(int fildes, struct strbuf *ctlptr, struct strbuf *dataptr,
            int *bandp, int *flagsp);
int ioctl(int fd, unsigned long int request, ...);
int putmsg(int fildes, const struct strbuf *ctlptr,
           const struct strbuf *dataptr, int flags);
int putpmsg(int fildes, const struct strbuf *ctlptr,
            const struct strbuf *dataptr, int band, int flags);
int fattach(int fildes, const char *path);
int fdetach(const char *path);

#endif /* __RCC_STROPTS_H__ */
