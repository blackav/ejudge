/* -*- c -*- */
/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `linux/fd.h' of the Linux Kernel. */

#ifndef __RCC_LINUX_FD_H__
#define __RCC_LINUX_FD_H__

#include <sys/ioctl.h>

/* New file layout: Now the ioctl definitions immediately follow the
 * definitions of the structures that they use */

int enum
{
  FD_STRETCH = 1,
#define FD_STRETCH FD_STRETCH
  FD_SWAPSIDES = 2,
#define FD_SWAPSIDES FD_SWAPSIDES
  FD_2M = 0x4,
#define FD_2M FD_2M
  FD_SIZECODEMASK = 0x38,
#define FD_SIZECODEMASK FD_SIZECODEMASK
  FD_PERP = 0x40,
#define FD_PERP FD_PERP
};

#define FD_SIZECODE(floppy) (((((floppy)->rate&FD_SIZECODEMASK)>> 3)+ 2) %8)
#define FD_SECTSIZE(floppy) ( (floppy)->rate & FD_2M ? \
                             512 : 128 << FD_SIZECODE(floppy) )

/*
 * Geometry
 */
struct floppy_struct
{
  unsigned int  size,
    sect,
    head,
    track,
    stretch;
  unsigned char gap,
    rate,
    spec1,
    fmt_gap;
  const char    * name;
};

/* commands needing write access have 0x40 set */
/* commands needing super user access have 0x80 set */

#define FDCLRPRM _IO(2, 0x41)
/* clear user-defined parameters */

#define FDSETPRM _IOW(2, 0x42, struct floppy_struct) 
#define FDSETMEDIAPRM FDSETPRM
/* set user-defined parameters for current media */

#define FDDEFPRM _IOW(2, 0x43, struct floppy_struct) 
#define FDGETPRM _IOR(2, 0x04, struct floppy_struct)
#define FDDEFMEDIAPRM FDDEFPRM
#define FDGETMEDIAPRM FDGETPRM
/* set/get disk parameters */


#define FDMSGON  _IO(2,0x45)
#define FDMSGOFF _IO(2,0x46)
/* issue/don't issue kernel messages on media type change */


/* 
 * Formatting (obsolete)
 */
#define FD_FILL_BYTE 0xF6 /* format fill byte. */

struct format_descr
{
  unsigned int device,head,track;
};

#define FDFMTBEG _IO(2,0x47)
/* begin formatting a disk */
#define FDFMTTRK _IOW(2,0x48, struct format_descr)
/* format the specified track */
#define FDFMTEND _IO(2,0x49)
/* end formatting a disk */


/*
 * Error thresholds
 */
struct floppy_max_errors
{
  unsigned int abort,
    read_track,
    reset,
    recal,
    reporting;
};

#define FDSETEMSGTRESH  _IO(2,0x4a)
/* set fdc error reporting threshold */

#define FDFLUSH  _IO(2,0x4b)
/* flush buffers for media; either for verifying media, or for
 * handling a media change without closing the file descriptor */

#define FDSETMAXERRS _IOW(2, 0x4c, struct floppy_max_errors)
#define FDGETMAXERRS _IOR(2, 0x0e, struct floppy_max_errors)
/* set/get abortion and read_track threshold. See also floppy_drive_params
 * structure */


typedef char floppy_drive_name[16];
#define FDGETDRVTYP _IOR(2, 0x0f, floppy_drive_name)
/* get drive type: 5 1/4 or 3 1/2 */


int enum
{
  FTD_MSG = 0x10,
#define FTD_MSG FTD_MSG
  FD_BROKEN_DCL = 0x20,
#define FD_BROKEN_DCL FD_BROKEN_DCL
  FD_DEBUG = 0x02,
#define FD_DEBUG FD_DEBUG
  FD_SILENT_DCL_CLEAR = 0x4,
#define FD_SILENT_DCL_CLEAR FD_SILENT_DCL_CLEAR
  FD_INVERTED_DCL = 0x80,
#define FD_INVERTED_DCL FD_INVERTED_DCL
};

/*
 * Drive parameters (user modifiable)
 */
struct floppy_drive_params
{
  signed char cmos;
  unsigned long max_dtr;
  unsigned long hlt;
  unsigned long hut;
  unsigned long srt;
  unsigned long spinup;
  unsigned long spindown;
  unsigned char spindown_offset;
  unsigned char select_delay;
  unsigned char rps;
  unsigned char tracks;
  unsigned long timeout;
  unsigned char interleave_sect;
  struct floppy_max_errors max_errors;
  char flags;
  char read_track;
  short autodetect[8];
  int checkfreq;
  int native_format;
};

enum
{
  FD_NEED_TWADDLE_BIT,
  FD_VERIFY_BIT,
  FD_DISK_NEWCHANGE_BIT,
  FD_UNUSED_BIT,
  FD_DISK_CHANGED_BIT,
  FD_DISK_WRITABLE_BIT
};

#define FDSETDRVPRM _IOW(2, 0x90, struct floppy_drive_params)
#define FDGETDRVPRM _IOR(2, 0x11, struct floppy_drive_params)
/* set/get drive parameters */

int enum
{
  FD_NEED_TWADDLE = (1 << FD_NEED_TWADDLE_BIT),
#define FD_NEED_TWADDLE FD_NEED_TWADDLE
  FD_VERIFY = (1 << FD_VERIFY_BIT),
#define FD_VERIFY FD_VERIFY
  FD_DISK_NEWCHANGE = (1 << FD_DISK_NEWCHANGE_BIT),
#define FD_DISK_NEWCHANGE FD_DISK_NEWCHANGE
  FD_DISK_CHANGED = (1 << FD_DISK_CHANGED_BIT),
#define FD_DISK_CHANGED FD_DISK_CHANGED
  FD_DISK_WRITABLE = (1 << FD_DISK_WRITABLE_BIT),
#define FD_DISK_WRITABLE FD_DISK_WRITABLE
};

/*
 * Current drive state (not directly modifiable by user, readonly)
 */
struct floppy_drive_struct
{
  unsigned long flags;
  unsigned long spinup_date;
  unsigned long select_date;
  unsigned long first_read_date;
  short probed_format;
  short track;
  short maxblock;
  short maxtrack;
  int generation;
  int keep_data;
  int fd_ref;
  int fd_device;
  unsigned long last_checked;
  char *dmabuf;
  int bufblocks;
};

#define FDGETDRVSTAT _IOR(2, 0x12, struct floppy_drive_struct)
#define FDPOLLDRVSTAT _IOR(2, 0x13, struct floppy_drive_struct)
/* get drive state: GET returns the cached state, POLL polls for new state */


/*
 * reset FDC
 */
enum reset_mode
{
  FD_RESET_IF_NEEDED,
  FD_RESET_IF_RAWCMD,
  FD_RESET_ALWAYS
};
#define FDRESET _IO(2, 0x54)

#define FD_DRIVER_VERSION 0x100

/*
 * FDC state
 */
struct floppy_fdc_state
{
  int spec1;
  int spec2;
  int dtr;
  unsigned char version;
  unsigned char dor;
  unsigned long address;
  unsigned int rawcmd:2;
  unsigned int reset:1;
  unsigned int need_configure:1;
  unsigned int perp_mode:2;
  unsigned int has_fifo:1;
  unsigned int driver_version;
  unsigned char track[4];
};

#define FDGETFDCSTAT _IOR(2, 0x15, struct floppy_fdc_state)


/*
 * Asynchronous Write error tracking
 */
struct floppy_write_errors
{
  unsigned int write_errors;
  unsigned long first_error_sector;
  int           first_error_generation;
  unsigned long last_error_sector;
  int           last_error_generation;
  unsigned int badness;
};

#define FDWERRORCLR  _IO(2, 0x56)
/* clear write error and badness information */
#define FDWERRORGET  _IOR(2, 0x17, struct floppy_write_errors)
/* get write error and badness information */

/*
 * Raw commands
 */
/* new interface flag: now we can do them in batches */
#define FDHAVEBATCHEDRAWCMD

int enum
{
  FD_RAW_READ = 1,
#define FD_RAW_READ FD_RAW_READ
  FD_RAW_WRITE = 2,
#define FD_RAW_WRITE FD_RAW_WRITE
  FD_RAW_NO_MOTOR = 4,
#define FD_RAW_NO_MOTOR FD_RAW_NO_MOTOR
  FD_RAW_DISK_CHANGE = 4,
#define FD_RAW_DISK_CHANGE FD_RAW_DISK_CHANGE
  FD_RAW_INTR = 8,
#define FD_RAW_INTR FD_RAW_INTR
  FD_RAW_SPIN = 0x10,
#define FD_RAW_SPIN FD_RAW_SPIN
  FD_RAW_NO_MOTOR_AFTER = 0x20,
#define FD_RAW_NO_MOTOR_AFTER FD_RAW_NO_MOTOR_AFTER
  FD_RAW_NEED_DISK = 0x40,
#define FD_RAW_NEED_DISK FD_RAW_NEED_DISK
  FD_RAW_NEED_SEEK = 0x80,
#define FD_RAW_NEED_SEEK FD_RAW_NEED_SEEK
  FD_RAW_MORE = 0x100,
#define FD_RAW_MORE FD_RAW_MORE
  FD_RAW_STOP_IF_FAILURE = 0x200,
#define FD_RAW_STOP_IF_FAILURE FD_RAW_STOP_IF_FAILURE
  FD_RAW_STOP_IF_SUCCESS = 0x400,
#define FD_RAW_STOP_IF_SUCCESS FD_RAW_STOP_IF_SUCCESS
  FD_RAW_SOFTFAILURE = 0x800,
#define FD_RAW_SOFTFAILURE FD_RAW_SOFTFAILURE
  FD_RAW_FAILURE = 0x10000,
#define FD_RAW_FAILURE FD_RAW_FAILURE
  FD_RAW_HARDFAILURE = 0x20000,
#define FD_RAW_HARDFAILURE FD_RAW_HARDFAILURE
};

struct floppy_raw_cmd
{
  unsigned int flags;
  void *data;
  char *kernel_data;
  struct floppy_raw_cmd *next;
  long length;
  long phys_length;
  int buffer_length;
  unsigned char rate;
  unsigned char cmd_count;
  unsigned char cmd[16];
  unsigned char reply_count;
  unsigned char reply[16];
  int track;
  int resultcode;
  int reserved1;
  int reserved2;
};

#define FDRAWCMD _IO(2, 0x58)
/* send a raw command to the fdc. Structure size not included, because of
 * batches */

#define FDTWADDLE _IO(2, 0x59)
/* flicker motor-on bit before reading a sector. Experimental */


#define FDEJECT _IO(2, 0x5a)
/* eject the disk */

#endif /* __RCC_LINUX_FD_H__ */
