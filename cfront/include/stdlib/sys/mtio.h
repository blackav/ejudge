/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `sys/mtio.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Structures and definitions for magnetic tape I/O control commands.
   Copyright (C) 1996, 1997 Free Software Foundation, Inc.
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

/* Written by H. Bergman <hennus@cybercomm.nl>.  */

#ifndef __RCC_SYS_MTIO_H__
#define __RCC_SYS_MTIO_H__ 1

/* Get necessary definitions from system and kernel headers.  */
#include <features.h>
#include <sys/types.h>
#include <sys/ioctl.h>

/* Structure for MTIOCTOP - magnetic tape operation command.  */
struct mtop
{
  short int mt_op;
  int mt_count;
};

#define _IOT_mtop _IOT (_IOTS (short), 1, _IOTS (int), 1, 0, 0)

/* Magnetic Tape operations [Not all operations supported by all drivers].  */
int enum
{
  MTRESET = 0,
#define MTRESET MTRESET
  MTFSF = 1,
#define MTFSF MTFSF
  MTBSF = 2,
#define MTBSF MTBSF
  MTFSR = 3,
#define MTFSR MTFSR
  MTBSR = 4,
#define MTBSR MTBSR
  MTWEOF = 5,
#define MTWEOF MTWEOF
  MTREW = 6,
#define MTREW MTREW
  MTOFFL = 7,
#define MTOFFL MTOFFL
  MTNOP = 8,
#define MTNOP MTNOP
  MTRETEN = 9,
#define MTRETEN MTRETEN
  MTBSFM = 10,
#define MTBSFM MTBSFM
  MTFSFM = 11,
#define MTFSFM MTFSFM
  MTEOM = 12,
#define MTEOM MTEOM
  MTERASE = 13,
#define MTERASE MTERASE
  MTRAS1 = 14,
#define MTRAS1 MTRAS1
  MTRAS2 = 15,
#define MTRAS2 MTRAS2
  MTRAS3 = 16,
#define MTRAS3 MTRAS3
  MTSETBLK = 20,
#define MTSETBLK MTSETBLK
  MTSETDENSITY = 21,
#define MTSETDENSITY MTSETDENSITY
  MTSEEK = 22,
#define MTSEEK MTSEEK
  MTTELL = 23,
#define MTTELL MTTELL
  MTSETDRVBUFFER = 24,
#define MTSETDRVBUFFER MTSETDRVBUFFER
  MTFSS = 25,
#define MTFSS MTFSS
  MTBSS = 26,
#define MTBSS MTBSS
  MTWSM = 27,
#define MTWSM MTWSM
  MTLOCK = 28,
#define MTLOCK MTLOCK
  MTUNLOCK = 29,
#define MTUNLOCK MTUNLOCK
  MTLOAD = 30,
#define MTLOAD MTLOAD
  MTUNLOAD = 31,
#define MTUNLOAD MTUNLOAD
  MTCOMPRESSION = 32,
#define MTCOMPRESSION MTCOMPRESSION
  MTSETPART = 33,
#define MTSETPART MTSETPART
  MTMKPART = 34,
#define MTMKPART MTMKPART
};

/* structure for MTIOCGET - mag tape get status command */
struct mtget
{
  long int mt_type;
  long int mt_resid;
  long int mt_dsreg;
  long int mt_gstat;
  long int mt_erreg;
  __daddr_t mt_fileno;
  __daddr_t mt_blkno;
};

#define _IOT_mtget _IOT(_IOTS (long), 7, 0, 0, 0, 0)


/* Constants for mt_type. Not all of these are supported, and
   these are not all of the ones that are supported.  */
int enum
{
  MT_ISUNKNOWN = 0x01,
#define MT_ISUNKNOWN MT_ISUNKNOWN
  MT_ISQIC02 = 0x02,
#define MT_ISQIC02 MT_ISQIC02
  MT_ISWT5150 = 0x03,
#define MT_ISWT5150 MT_ISWT5150
  MT_ISARCHIVE_5945L2 = 0x04,
#define MT_ISARCHIVE_5945L2 MT_ISARCHIVE_5945L2
  MT_ISCMSJ500 = 0x05,
#define MT_ISCMSJ500 MT_ISCMSJ500
  MT_ISTDC3610 = 0x06,
#define MT_ISTDC3610 MT_ISTDC3610
  MT_ISARCHIVE_VP60I = 0x07,
#define MT_ISARCHIVE_VP60I MT_ISARCHIVE_VP60I
  MT_ISARCHIVE_2150L = 0x08,
#define MT_ISARCHIVE_2150L MT_ISARCHIVE_2150L
  MT_ISARCHIVE_2060L = 0x09,
#define MT_ISARCHIVE_2060L MT_ISARCHIVE_2060L
  MT_ISARCHIVESC499 = 0x0A,
#define MT_ISARCHIVESC499 MT_ISARCHIVESC499
  MT_ISQIC02_ALL_FEATURES = 0x0F,
#define MT_ISQIC02_ALL_FEATURES MT_ISQIC02_ALL_FEATURES
  MT_ISWT5099EEN24 = 0x11,
#define MT_ISWT5099EEN24 MT_ISWT5099EEN24
  MT_ISTEAC_MT2ST = 0x12,
#define MT_ISTEAC_MT2ST MT_ISTEAC_MT2ST
  MT_ISEVEREX_FT40A = 0x32,
#define MT_ISEVEREX_FT40A MT_ISEVEREX_FT40A
  MT_ISDDS1 = 0x51,
#define MT_ISDDS1 MT_ISDDS1
  MT_ISDDS2 = 0x52,
#define MT_ISDDS2 MT_ISDDS2
  MT_ISSCSI1 = 0x71,
#define MT_ISSCSI1 MT_ISSCSI1
  MT_ISSCSI2 = 0x72,
#define MT_ISSCSI2 MT_ISSCSI2
  MT_ISFTAPE_UNKNOWN = 0x800000,
#define MT_ISFTAPE_UNKNOWN MT_ISFTAPE_UNKNOWN
  MT_ISFTAPE_FLAG = 0x800000,
#define MT_ISFTAPE_FLAG MT_ISFTAPE_FLAG
};

struct mt_tape_info
{
  long int t_type;
  char *t_name;
};

#define MT_TAPE_INFO \
  {                                                                           \
        {MT_ISUNKNOWN,          "Unknown type of tape device"},               \
        {MT_ISQIC02,            "Generic QIC-02 tape streamer"},              \
        {MT_ISWT5150,           "Wangtek 5150, QIC-150"},                     \
        {MT_ISARCHIVE_5945L2,   "Archive 5945L-2"},                           \
        {MT_ISCMSJ500,          "CMS Jumbo 500"},                             \
        {MT_ISTDC3610,          "Tandberg TDC 3610, QIC-24"},                 \
        {MT_ISARCHIVE_VP60I,    "Archive VP60i, QIC-02"},                     \
        {MT_ISARCHIVE_2150L,    "Archive Viper 2150L"},                       \
        {MT_ISARCHIVE_2060L,    "Archive Viper 2060L"},                       \
        {MT_ISARCHIVESC499,     "Archive SC-499 QIC-36 controller"},          \
        {MT_ISQIC02_ALL_FEATURES, "Generic QIC-02 tape, all features"},       \
        {MT_ISWT5099EEN24,      "Wangtek 5099-een24, 60MB"},                  \
        {MT_ISTEAC_MT2ST,       "Teac MT-2ST 155mb data cassette drive"},     \
        {MT_ISEVEREX_FT40A,     "Everex FT40A, QIC-40"},                      \
        {MT_ISSCSI1,            "Generic SCSI-1 tape"},                       \
        {MT_ISSCSI2,            "Generic SCSI-2 tape"},                       \
        {0, NULL}                                                             \
  }


/* Structure for MTIOCPOS - mag tape get position command.  */
struct mtpos
{
  long int mt_blkno;
};

#define _IOT_mtpos _IOT_SIMPLE (long)

/* Structure for MTIOCGETCONFIG/MTIOCSETCONFIG primarily intended
   as an interim solution for QIC-02 until DDI is fully implemented.  */
struct mtconfiginfo
{
  long int mt_type;
  long int ifc_type;
  unsigned short int irqnr;
  unsigned short int dmanr;
  unsigned short int port;
  unsigned long int debug;
  unsigned have_dens:1;
  unsigned have_bsf:1;
  unsigned have_fsr:1;
  unsigned have_bsr:1;
  unsigned have_eod:1;
  unsigned have_seek:1;
  unsigned have_tell:1;
  unsigned have_ras1:1;
  unsigned have_ras2:1;
  unsigned have_ras3:1;
  unsigned have_qfa:1;
  unsigned pad1:5;
  char reserved[10];
};

#define _IOT_mtconfiginfo _IOT (_IOTS (long), 2, _IOTS (short), 3, _IOTS (long), 1)


/* Magnetic tape I/O control commands.  */
#define MTIOCTOP        _IOW('m', 1, struct mtop)
#define MTIOCGET        _IOR('m', 2, struct mtget)
#define MTIOCPOS        _IOR('m', 3, struct mtpos)

/* The next two are used by the QIC-02 driver for runtime reconfiguration.
   See tpqic02.h for struct mtconfiginfo.  */
#define MTIOCGETCONFIG  _IOR('m', 4, struct mtconfiginfo)
#define MTIOCSETCONFIG  _IOW('m', 5, struct mtconfiginfo)

/* Generic Mag Tape (device independent) status macros for examining
   mt_gstat -- HP-UX compatible.
   There is room for more generic status bits here, but I don't
   know which of them are reserved. At least three or so should
   be added to make this really useful.  */
#define GMT_EOF(x)              ((x) & 0x80000000)
#define GMT_BOT(x)              ((x) & 0x40000000)
#define GMT_EOT(x)              ((x) & 0x20000000)
#define GMT_SM(x)               ((x) & 0x10000000)
#define GMT_EOD(x)              ((x) & 0x08000000)
#define GMT_WR_PROT(x)          ((x) & 0x04000000)
/* #define GMT_ ?               ((x) & 0x02000000) */
#define GMT_ONLINE(x)           ((x) & 0x01000000)
#define GMT_D_6250(x)           ((x) & 0x00800000)
#define GMT_D_1600(x)           ((x) & 0x00400000)
#define GMT_D_800(x)            ((x) & 0x00200000)
/* #define GMT_ ?               ((x) & 0x00100000) */
/* #define GMT_ ?               ((x) & 0x00080000) */
#define GMT_DR_OPEN(x)          ((x) & 0x00040000)
/* #define GMT_ ?               ((x) & 0x00020000) */
#define GMT_IM_REP_EN(x)        ((x) & 0x00010000)
/* 16 generic status bits unused.  */

/* SCSI-tape specific definitions.  Bitfield shifts in the status  */
int enum
{
  MT_ST_BLKSIZE_SHIFT = 0,
#define MT_ST_BLKSIZE_SHIFT MT_ST_BLKSIZE_SHIFT
  MT_ST_BLKSIZE_MASK = 0xffffff,
#define MT_ST_BLKSIZE_MASK MT_ST_BLKSIZE_MASK
  MT_ST_DENSITY_SHIFT = 24,
#define MT_ST_DENSITY_SHIFT MT_ST_DENSITY_SHIFT
  MT_ST_DENSITY_MASK = 0xff000000,
#define MT_ST_DENSITY_MASK MT_ST_DENSITY_MASK
  MT_ST_SOFTERR_SHIFT = 0,
#define MT_ST_SOFTERR_SHIFT MT_ST_SOFTERR_SHIFT
  MT_ST_SOFTERR_MASK = 0xffff,
#define MT_ST_SOFTERR_MASK MT_ST_SOFTERR_MASK
};

/* Bitfields for the MTSETDRVBUFFER ioctl.  */
int enum
{
  MT_ST_OPTIONS = 0xf0000000,
#define MT_ST_OPTIONS MT_ST_OPTIONS
  MT_ST_BOOLEANS = 0x10000000,
#define MT_ST_BOOLEANS MT_ST_BOOLEANS
  MT_ST_SETBOOLEANS = 0x30000000,
#define MT_ST_SETBOOLEANS MT_ST_SETBOOLEANS
  MT_ST_CLEARBOOLEANS = 0x40000000,
#define MT_ST_CLEARBOOLEANS MT_ST_CLEARBOOLEANS
  MT_ST_WRITE_THRESHOLD = 0x20000000,
#define MT_ST_WRITE_THRESHOLD MT_ST_WRITE_THRESHOLD
  MT_ST_DEF_BLKSIZE = 0x50000000,
#define MT_ST_DEF_BLKSIZE MT_ST_DEF_BLKSIZE
  MT_ST_DEF_OPTIONS = 0x60000000,
#define MT_ST_DEF_OPTIONS MT_ST_DEF_OPTIONS
  MT_ST_BUFFER_WRITES = 0x1,
#define MT_ST_BUFFER_WRITES MT_ST_BUFFER_WRITES
  MT_ST_ASYNC_WRITES = 0x2,
#define MT_ST_ASYNC_WRITES MT_ST_ASYNC_WRITES
  MT_ST_READ_AHEAD = 0x4,
#define MT_ST_READ_AHEAD MT_ST_READ_AHEAD
  MT_ST_DEBUGGING = 0x8,
#define MT_ST_DEBUGGING MT_ST_DEBUGGING
  MT_ST_TWO_FM = 0x10,
#define MT_ST_TWO_FM MT_ST_TWO_FM
  MT_ST_FAST_MTEOM = 0x20,
#define MT_ST_FAST_MTEOM MT_ST_FAST_MTEOM
  MT_ST_AUTO_LOCK = 0x40,
#define MT_ST_AUTO_LOCK MT_ST_AUTO_LOCK
  MT_ST_DEF_WRITES = 0x80,
#define MT_ST_DEF_WRITES MT_ST_DEF_WRITES
  MT_ST_CAN_BSR = 0x100,
#define MT_ST_CAN_BSR MT_ST_CAN_BSR
  MT_ST_NO_BLKLIMS = 0x200,
#define MT_ST_NO_BLKLIMS MT_ST_NO_BLKLIMS
  MT_ST_CAN_PARTITIONS = 0x400,
#define MT_ST_CAN_PARTITIONS MT_ST_CAN_PARTITIONS
  MT_ST_SCSI2LOGICAL = 0x800,
#define MT_ST_SCSI2LOGICAL MT_ST_SCSI2LOGICAL
  MT_ST_CLEAR_DEFAULT = 0xfffff,
#define MT_ST_CLEAR_DEFAULT MT_ST_CLEAR_DEFAULT
  MT_ST_DEF_DENSITY = (MT_ST_DEF_OPTIONS | 0x100000),
#define MT_ST_DEF_DENSITY MT_ST_DEF_DENSITY
  MT_ST_DEF_COMPRESSION = (MT_ST_DEF_OPTIONS | 0x200000),
#define MT_ST_DEF_COMPRESSION MT_ST_DEF_COMPRESSION
  MT_ST_DEF_DRVBUFFER = (MT_ST_DEF_OPTIONS | 0x300000),
#define MT_ST_DEF_DRVBUFFER MT_ST_DEF_DRVBUFFER
  MT_ST_HPLOADER_OFFSET = 10000,
#define MT_ST_HPLOADER_OFFSET MT_ST_HPLOADER_OFFSET
};

/* Specify default tape device.  */
#ifndef DEFTAPE
# define DEFTAPE        "/dev/tape"
#endif

#endif /* mtio.h */
