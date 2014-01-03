/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_TERMIOS_H__
#define __RCC_TERMIOS_H__

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
#include <sys/types.h>
#include <sys/ttydefaults.h>

typedef unsigned char   cc_t;
typedef unsigned int    speed_t;
typedef unsigned int    tcflag_t;

int enum { NCCS = 32 };
#define NCCS NCCS

struct termios
{
  tcflag_t c_iflag;
  tcflag_t c_oflag;
  tcflag_t c_cflag;
  tcflag_t c_lflag;
  cc_t c_line;
  cc_t c_cc[NCCS];
  speed_t c_ispeed;
  speed_t c_ospeed;
};

/* c_cc characters */
int enum
{
  VINTR = 0,
#define VINTR VINTR
  VQUIT = 1,
#define VQUIT VQUIT
  VERASE = 2,
#define VERASE VERASE
  VKILL = 3,
#define VKILL VKILL
  VEOF = 4,
#define VEOF VEOF
  VTIME = 5,
#define VTIME VTIME
  VMIN = 6,
#define VMIN VMIN
  VSWTC = 7,
#define VSWTC VSWTC
  VSTART = 8,
#define VSTART VSTART
  VSTOP = 9,
#define VSTOP VSTOP
  VSUSP = 10,
#define VSUSP VSUSP
  VEOL = 11,
#define VEOL VEOL
  VREPRINT = 12,
#define VREPRINT VREPRINT
  VDISCARD = 13,
#define VDISCARD VDISCARD
  VWERASE = 14,
#define VWERASE VWERASE
  VLNEXT = 15,
#define VLNEXT VLNEXT
  VEOL2 = 16,
#define VEOL2 VEOL2
};

/* c_iflag bits */
int enum
{
  IGNBRK = 0000001,
#define IGNBRK IGNBRK
  BRKINT = 0000002,
#define BRKINT BRKINT
  IGNPAR = 0000004,
#define IGNPAR IGNPAR
  PARMRK = 0000010,
#define PARMRK PARMRK
  INPCK = 0000020,
#define INPCK INPCK
  ISTRIP = 0000040,
#define ISTRIP ISTRIP
  INLCR = 0000100,
#define INLCR INLCR
  IGNCR = 0000200,
#define IGNCR IGNCR
  ICRNL = 0000400,
#define ICRNL ICRNL
  IUCLC = 0001000,
#define IUCLC IUCLC
  IXON = 0002000,
#define IXON IXON
  IXANY = 0004000,
#define IXANY IXANY
  IXOFF = 0010000,
#define IXOFF IXOFF
  IMAXBEL = 0020000,
#define IMAXBEL IMAXBEL
};

/* c_oflag bits */
int enum
{
  OPOST = 0000001,
#define OPOST OPOST
  OLCUC = 0000002,
#define OLCUC OLCUC
  ONLCR = 0000004,
#define ONLCR ONLCR
  OCRNL = 0000010,
#define OCRNL OCRNL
  ONOCR = 0000020,
#define ONOCR ONOCR
  ONLRET = 0000040,
#define ONLRET ONLRET
  OFILL = 0000100,
#define OFILL OFILL
  OFDEL = 0000200,
#define OFDEL OFDEL
  NLDLY = 0000400,
#define NLDLY NLDLY
  NL0 = 0000000,
#define NL0 NL0
  NL1 = 0000400,
#define NL1 NL1
  CRDLY = 0003000,
#define CRDLY CRDLY
  CR0 = 0000000,
#define CR0 CR0
  CR1 = 0001000,
#define CR1 CR1
  CR2 = 0002000,
#define CR2 CR2
  CR3 = 0003000,
#define CR3 CR3
  TABDLY = 0014000,
#define TABDLY TABDLY
  TAB0 = 0000000,
#define TAB0 TAB0
  TAB1 = 0004000,
#define TAB1 TAB1
  TAB2 = 0010000,
#define TAB2 TAB2
  TAB3 = 0014000,
#define TAB3 TAB3
  BSDLY = 0020000,
#define BSDLY BSDLY
  BS0 = 0000000,
#define BS0 BS0
  BS1 = 0020000,
#define BS1 BS1
  FFDLY = 0100000,
#define FFDLY FFDLY
  FF0 = 0000000,
#define FF0 FF0
  FF1 = 0100000,
#define FF1 FF1
  VTDLY = 0040000,
#define VTDLY VTDLY
  VT0 = 0000000,
#define VT0 VT0
  VT1 = 0040000,
#define VT1 VT1
  XTABS = 0014000,
#define XTABS XTABS
};

/* c_cflag bit meaning */
int enum
{
  CBAUD = 0010017,
#define CBAUD CBAUD
  B0 = 0000000,
#define B0 B0
  B50 = 0000001,
#define B50 B50
  B75 = 0000002,
#define B75 B75
  B110 = 0000003,
#define B110 B110
  B134 = 0000004,
#define B134 B134
  B150 = 0000005,
#define B150 B150
  B200 = 0000006,
#define B200 B200
  B300 = 0000007,
#define B300 B300
  B600 = 0000010,
#define B600 B600
  B1200 = 0000011,
#define B1200 B1200
  B1800 = 0000012,
#define B1800 B1800
  B2400 = 0000013,
#define B2400 B2400
  B4800 = 0000014,
#define B4800 B4800
  B9600 = 0000015,
#define B9600 B9600
  B19200 = 0000016,
#define B19200 B19200
  B38400 = 0000017,
#define B38400 B38400
  EXTA = B19200,
#define EXTA EXTA
  EXTB = B38400,
#define EXTB EXTB
  CSIZE = 0000060,
#define CSIZE CSIZE
  CS5 = 0000000,
#define CS5 CS5
  CS6 = 0000020,
#define CS6 CS6
  CS7 = 0000040,
#define CS7 CS7
  CS8 = 0000060,
#define CS8 CS8
  CSTOPB = 0000100,
#define CSTOPB CSTOPB
  CREAD = 0000200,
#define CREAD CREAD
  PARENB = 0000400,
#define PARENB PARENB
  PARODD = 0001000,
#define PARODD PARODD
  HUPCL = 0002000,
#define HUPCL HUPCL
  CLOCAL = 0004000,
#define CLOCAL CLOCAL
  CBAUDEX = 0010000,
#define CBAUDEX CBAUDEX
  B57600 = 0010001,
#define B57600 B57600
  B115200 = 0010002,
#define B115200 B115200
  B230400 = 0010003,
#define B230400 B230400
  B460800 = 0010004,
#define B460800 B460800
  B500000 = 0010005,
#define B500000 B500000
  B576000 = 0010006,
#define B576000 B576000
  B921600 = 0010007,
#define B921600 B921600
  B1000000 = 0010010,
#define B1000000 B1000000
  B1152000 = 0010011,
#define B1152000 B1152000
  B1500000 = 0010012,
#define B1500000 B1500000
  B2000000 = 0010013,
#define B2000000 B2000000
  B2500000 = 0010014,
#define B2500000 B2500000
  B3000000 = 0010015,
#define B3000000 B3000000
  B3500000 = 0010016,
#define B3500000 B3500000
  B4000000 = 0010017,
#define B4000000 B4000000
  __MAX_BAUD = B4000000,
#define __MAX_BAUD __MAX_BAUD
  CIBAUD = 002003600000,
#define CIBAUD CIBAUD
  CRTSCTS = 020000000000,
#define CRTSCTS CRTSCTS
};

/* c_lflag bits */
int enum
{
  ISIG = 0000001,
#define ISIG ISIG
  ICANON = 0000002,
#define ICANON ICANON
  XCASE = 0000004,
#define XCASE XCASE
  ECHO = 0000010,
#define ECHO ECHO
  ECHOE = 0000020,
#define ECHOE ECHOE
  ECHOK = 0000040,
#define ECHOK ECHOK
  ECHONL = 0000100,
#define ECHONL ECHONL
  NOFLSH = 0000200,
#define NOFLSH NOFLSH
  TOSTOP = 0000400,
#define TOSTOP TOSTOP
  ECHOCTL = 0001000,
#define ECHOCTL ECHOCTL
  ECHOPRT = 0002000,
#define ECHOPRT ECHOPRT
  ECHOKE = 0004000,
#define ECHOKE ECHOKE
  FLUSHO = 0010000,
#define FLUSHO FLUSHO
  PENDIN = 0040000,
#define PENDIN PENDIN
  IEXTEN = 0100000,
#define IEXTEN IEXTEN
};

/* tcflow() and TCXONC use these */
int enum
{
  TCOOFF = 0,
#define TCOOFF TCOOFF
  TCOON = 1,
#define TCOON TCOON
  TCIOFF = 2,
#define TCIOFF TCIOFF
  TCION = 3,
#define TCION TCION
};

/* tcflush() and TCFLSH use these */
int enum
{
  TCIFLUSH = 0,
#define TCIFLUSH TCIFLUSH
  TCOFLUSH = 1,
#define TCOFLUSH TCOFLUSH
  TCIOFLUSH = 2,
#define TCIOFLUSH TCIOFLUSH
};

/* tcsetattr uses these */
int enum
{
  TCSANOW = 0,
#define TCSANOW TCSANOW
  TCSADRAIN = 1,
#define TCSADRAIN TCSADRAIN
  TCSAFLUSH = 2,
#define TCSAFLUSH TCSAFLUSH
};

#if 0
#define _IOT_termios /* Hurd ioctl type field.  */ \
  _IOT (_IOTS (cflag_t), 4, _IOTS (cc_t), NCCS, _IOTS (speed_t), 2)
#endif

/* Return the output baud rate stored in *TERMIOS_P.  */
speed_t cfgetospeed(const struct termios *termios_p);

/* Return the input baud rate stored in *TERMIOS_P.  */
speed_t cfgetispeed(const struct termios *termios_p);

/* Set the output baud rate stored in *TERMIOS_P to SPEED.  */
int cfsetospeed(struct termios *termios_p, speed_t speed);

/* Set the input baud rate stored in *TERMIOS_P to SPEED.  */
int cfsetispeed(struct termios *termios_p, speed_t speed);

/* Set both the input and output baud rates in *TERMIOS_OP to SPEED.  */
int cfsetspeed(struct termios *termios_p, speed_t speed);

/* Put the state of FD into *TERMIOS_P.  */
int tcgetattr(int fd, struct termios *termios_p);

/* Set the state of FD to *TERMIOS_P. */
int tcsetattr(int fd, int optional_actions, const struct termios *termios_p);

/* Set *TERMIOS_P to indicate raw mode.  */
void cfmakeraw(struct termios *termios_p);

/* Send zero bits on FD.  */
int tcsendbreak(int fd, int duration);

/* Wait for pending output to be written on FD.  */
int tcdrain(int fd);

/* Flush pending data on FD. */
int tcflush(int fd, int queue_selector);

/* Suspend or restart transmission on FD. */
int tcflow(int fd, int action);

/* Get process group ID for session leader for controlling terminal FD.  */
pid_t tcgetsid(int fd);

#endif /* __RCC_TERMIOS_H__ */
