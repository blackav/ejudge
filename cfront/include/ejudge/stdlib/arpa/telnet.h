/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `arpa/telnet.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/*
 * Copyright (c) 1983, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)telnet.h    8.2 (Berkeley) 12/15/93
 */

#ifndef __RCC_ARPA_TELNET_H__
#define __RCC_ARPA_TELNET_H__ 1

#include <features.h>

/*
 * Definitions for the TELNET protocol.
 */
int enum
{
  IAC = 255,
#define IAC IAC
  DONT = 254,
#define DONT DONT
  DO = 253,
#define DO DO
  WONT = 252,
#define WONT WONT
  WILL = 251,
#define WILL WILL
  SB = 250,
#define SB SB
  GA = 249,
#define GA GA
  EL = 248,
#define EL EL
  EC = 247,
#define EC EC
  AYT = 246,
#define AYT AYT
  AO = 245,
#define AO AO
  IP = 244,
#define IP IP
  BREAK = 243,
#define BREAK BREAK
  DM = 242,
#define DM DM
  NOP = 241,
#define NOP NOP
  SE = 240,
#define SE SE
  EOR = 239,
#define EOR EOR
  ABORT = 238,
#define ABORT ABORT
  SUSP = 237,
#define SUSP SUSP
  xEOF = 236,
#define xEOF xEOF
  SYNCH = 242,
#define SYNCH SYNCH
};

#ifdef TELCMDS
char *telcmds[] = {
        "EOF", "SUSP", "ABORT", "EOR",
        "SE", "NOP", "DMARK", "BRK", "IP", "AO", "AYT", "EC",
        "EL", "GA", "SB", "WILL", "WONT", "DO", "DONT", "IAC", 0,
};
#else
extern char *telcmds[];
#endif

int enum
{
  TELCMD_FIRST = xEOF,
#define TELCMD_FIRST TELCMD_FIRST
  TELCMD_LAST = IAC,
#define TELCMD_LAST TELCMD_LAST
};

#define TELCMD_OK(x)    ((unsigned int)(x) <= TELCMD_LAST && \
                         (unsigned int)(x) >= TELCMD_FIRST)
#define TELCMD(x)       telcmds[(x)-TELCMD_FIRST]

/* telnet options */
int enum
{
  TELOPT_BINARY = 0,
#define TELOPT_BINARY TELOPT_BINARY
  TELOPT_ECHO = 1,
#define TELOPT_ECHO TELOPT_ECHO
  TELOPT_RCP = 2,
#define TELOPT_RCP TELOPT_RCP
  TELOPT_SGA = 3,
#define TELOPT_SGA TELOPT_SGA
  TELOPT_NAMS = 4,
#define TELOPT_NAMS TELOPT_NAMS
  TELOPT_STATUS = 5,
#define TELOPT_STATUS TELOPT_STATUS
  TELOPT_TM = 6,
#define TELOPT_TM TELOPT_TM
  TELOPT_RCTE = 7,
#define TELOPT_RCTE TELOPT_RCTE
  TELOPT_NAOL = 8,
#define TELOPT_NAOL TELOPT_NAOL
  TELOPT_NAOP = 9,
#define TELOPT_NAOP TELOPT_NAOP
  TELOPT_NAOCRD = 10,
#define TELOPT_NAOCRD TELOPT_NAOCRD
  TELOPT_NAOHTS = 11,
#define TELOPT_NAOHTS TELOPT_NAOHTS
  TELOPT_NAOHTD = 12,
#define TELOPT_NAOHTD TELOPT_NAOHTD
  TELOPT_NAOFFD = 13,
#define TELOPT_NAOFFD TELOPT_NAOFFD
  TELOPT_NAOVTS = 14,
#define TELOPT_NAOVTS TELOPT_NAOVTS
  TELOPT_NAOVTD = 15,
#define TELOPT_NAOVTD TELOPT_NAOVTD
  TELOPT_NAOLFD = 16,
#define TELOPT_NAOLFD TELOPT_NAOLFD
  TELOPT_XASCII = 17,
#define TELOPT_XASCII TELOPT_XASCII
  TELOPT_LOGOUT = 18,
#define TELOPT_LOGOUT TELOPT_LOGOUT
  TELOPT_BM = 19,
#define TELOPT_BM TELOPT_BM
  TELOPT_DET = 20,
#define TELOPT_DET TELOPT_DET
  TELOPT_SUPDUP = 21,
#define TELOPT_SUPDUP TELOPT_SUPDUP
  TELOPT_SUPDUPOUTPUT = 22,
#define TELOPT_SUPDUPOUTPUT TELOPT_SUPDUPOUTPUT
  TELOPT_SNDLOC = 23,
#define TELOPT_SNDLOC TELOPT_SNDLOC
  TELOPT_TTYPE = 24,
#define TELOPT_TTYPE TELOPT_TTYPE
  TELOPT_EOR = 25,
#define TELOPT_EOR TELOPT_EOR
  TELOPT_TUID = 26,
#define TELOPT_TUID TELOPT_TUID
  TELOPT_OUTMRK = 27,
#define TELOPT_OUTMRK TELOPT_OUTMRK
  TELOPT_TTYLOC = 28,
#define TELOPT_TTYLOC TELOPT_TTYLOC
  TELOPT_3270REGIME = 29,
#define TELOPT_3270REGIME TELOPT_3270REGIME
  TELOPT_X3PAD = 30,
#define TELOPT_X3PAD TELOPT_X3PAD
  TELOPT_NAWS = 31,
#define TELOPT_NAWS TELOPT_NAWS
  TELOPT_TSPEED = 32,
#define TELOPT_TSPEED TELOPT_TSPEED
  TELOPT_LFLOW = 33,
#define TELOPT_LFLOW TELOPT_LFLOW
  TELOPT_LINEMODE = 34,
#define TELOPT_LINEMODE TELOPT_LINEMODE
  TELOPT_XDISPLOC = 35,
#define TELOPT_XDISPLOC TELOPT_XDISPLOC
  TELOPT_OLD_ENVIRON = 36,
#define TELOPT_OLD_ENVIRON TELOPT_OLD_ENVIRON
  TELOPT_AUTHENTICATION = 37,
#define TELOPT_AUTHENTICATION TELOPT_AUTHENTICATION
  TELOPT_ENCRYPT = 38,
#define TELOPT_ENCRYPT TELOPT_ENCRYPT
  TELOPT_NEW_ENVIRON = 39,
#define TELOPT_NEW_ENVIRON TELOPT_NEW_ENVIRON
  TELOPT_EXOPL = 255,
#define TELOPT_EXOPL TELOPT_EXOPL
  NTELOPTS = (1+TELOPT_NEW_ENVIRON),
#define NTELOPTS NTELOPTS
};

#ifdef TELOPTS
char *telopts[NTELOPTS+1] = {
        "BINARY", "ECHO", "RCP", "SUPPRESS GO AHEAD", "NAME",
        "STATUS", "TIMING MARK", "RCTE", "NAOL", "NAOP",
        "NAOCRD", "NAOHTS", "NAOHTD", "NAOFFD", "NAOVTS",
        "NAOVTD", "NAOLFD", "EXTEND ASCII", "LOGOUT", "BYTE MACRO",
        "DATA ENTRY TERMINAL", "SUPDUP", "SUPDUP OUTPUT",
        "SEND LOCATION", "TERMINAL TYPE", "END OF RECORD",
        "TACACS UID", "OUTPUT MARKING", "TTYLOC",
        "3270 REGIME", "X.3 PAD", "NAWS", "TSPEED", "LFLOW",
        "LINEMODE", "XDISPLOC", "OLD-ENVIRON", "AUTHENTICATION",
        "ENCRYPT", "NEW-ENVIRON",
        0,
};
#define TELOPT_FIRST    TELOPT_BINARY
#define TELOPT_LAST     TELOPT_NEW_ENVIRON
#define TELOPT_OK(x)    ((unsigned int)(x) <= TELOPT_LAST)
#define TELOPT(x)       telopts[(x)-TELOPT_FIRST]
#endif

/* sub-option qualifiers */
int enum
{
  TELQUAL_IS = 0,
#define TELQUAL_IS TELQUAL_IS
  TELQUAL_SEND = 1,
#define TELQUAL_SEND TELQUAL_SEND
  TELQUAL_INFO = 2,
#define TELQUAL_INFO TELQUAL_INFO
  TELQUAL_REPLY = 2,
#define TELQUAL_REPLY TELQUAL_REPLY
  TELQUAL_NAME = 3,
#define TELQUAL_NAME TELQUAL_NAME
};

int enum
{
  LFLOW_OFF = 0,
#define LFLOW_OFF LFLOW_OFF
  LFLOW_ON = 1,
#define LFLOW_ON LFLOW_ON
  LFLOW_RESTART_ANY = 2,
#define LFLOW_RESTART_ANY LFLOW_RESTART_ANY
  LFLOW_RESTART_XON = 3,
#define LFLOW_RESTART_XON LFLOW_RESTART_XON
};

/*
 * LINEMODE suboptions
 */

int enum
{
  LM_MODE = 1,
#define LM_MODE LM_MODE
  LM_FORWARDMASK = 2,
#define LM_FORWARDMASK LM_FORWARDMASK
  LM_SLC = 3,
#define LM_SLC LM_SLC
};

int enum
{
  MODE_EDIT = 0x01,
#define MODE_EDIT MODE_EDIT
  MODE_TRAPSIG = 0x02,
#define MODE_TRAPSIG MODE_TRAPSIG
  MODE_ACK = 0x04,
#define MODE_ACK MODE_ACK
  MODE_SOFT_TAB = 0x08,
#define MODE_SOFT_TAB MODE_SOFT_TAB
  MODE_LIT_ECHO = 0x10,
#define MODE_LIT_ECHO MODE_LIT_ECHO
  MODE_MASK = 0x1f,
#define MODE_MASK MODE_MASK
  MODE_FLOW = 0x0100,
#define MODE_FLOW MODE_FLOW
  MODE_ECHO = 0x0200,
#define MODE_ECHO MODE_ECHO
  MODE_INBIN = 0x0400,
#define MODE_INBIN MODE_INBIN
  MODE_OUTBIN = 0x0800,
#define MODE_OUTBIN MODE_OUTBIN
  MODE_FORCE = 0x1000,
#define MODE_FORCE MODE_FORCE
};

int enum
{
  SLC_SYNCH = 1,
#define SLC_SYNCH SLC_SYNCH
  SLC_BRK = 2,
#define SLC_BRK SLC_BRK
  SLC_IP = 3,
#define SLC_IP SLC_IP
  SLC_AO = 4,
#define SLC_AO SLC_AO
  SLC_AYT = 5,
#define SLC_AYT SLC_AYT
  SLC_EOR = 6,
#define SLC_EOR SLC_EOR
  SLC_ABORT = 7,
#define SLC_ABORT SLC_ABORT
  SLC_EOF = 8,
#define SLC_EOF SLC_EOF
  SLC_SUSP = 9,
#define SLC_SUSP SLC_SUSP
  SLC_EC = 10,
#define SLC_EC SLC_EC
  SLC_EL = 11,
#define SLC_EL SLC_EL
  SLC_EW = 12,
#define SLC_EW SLC_EW
  SLC_RP = 13,
#define SLC_RP SLC_RP
  SLC_LNEXT = 14,
#define SLC_LNEXT SLC_LNEXT
  SLC_XON = 15,
#define SLC_XON SLC_XON
  SLC_XOFF = 16,
#define SLC_XOFF SLC_XOFF
  SLC_FORW1 = 17,
#define SLC_FORW1 SLC_FORW1
  SLC_FORW2 = 18,
#define SLC_FORW2 SLC_FORW2
  NSLC = 18,
#define NSLC NSLC
};

/*
 * For backwards compatibility, we define SLC_NAMES to be the
 * list of names if SLC_NAMES is not defined.
 */
#define SLC_NAMELIST    "0", "SYNCH", "BRK", "IP", "AO", "AYT", "EOR", \
                        "ABORT", "EOF", "SUSP", "EC", "EL", "EW", "RP", \
                        "LNEXT", "XON", "XOFF", "FORW1", "FORW2", 0,
#ifdef  SLC_NAMES
char *slc_names[] = {
        SLC_NAMELIST
};
#else
extern char *slc_names[];
#define SLC_NAMES SLC_NAMELIST
#endif

#define SLC_NAME_OK(x)  ((unsigned int)(x) <= NSLC)
#define SLC_NAME(x)     slc_names[x]

int enum
{
  SLC_NOSUPPORT = 0,
#define SLC_NOSUPPORT SLC_NOSUPPORT
  SLC_CANTCHANGE = 1,
#define SLC_CANTCHANGE SLC_CANTCHANGE
  SLC_VARIABLE = 2,
#define SLC_VARIABLE SLC_VARIABLE
  SLC_DEFAULT = 3,
#define SLC_DEFAULT SLC_DEFAULT
  SLC_LEVELBITS = 0x03,
#define SLC_LEVELBITS SLC_LEVELBITS
  SLC_FUNC = 0,
#define SLC_FUNC SLC_FUNC
  SLC_FLAGS = 1,
#define SLC_FLAGS SLC_FLAGS
  SLC_VALUE = 2,
#define SLC_VALUE SLC_VALUE
  SLC_ACK = 0x80,
#define SLC_ACK SLC_ACK
  SLC_FLUSHIN = 0x40,
#define SLC_FLUSHIN SLC_FLUSHIN
  SLC_FLUSHOUT = 0x20,
#define SLC_FLUSHOUT SLC_FLUSHOUT
};

int enum
{
  OLD_ENV_VAR = 1,
#define OLD_ENV_VAR OLD_ENV_VAR
  OLD_ENV_VALUE = 0,
#define OLD_ENV_VALUE OLD_ENV_VALUE
  NEW_ENV_VAR = 0,
#define NEW_ENV_VAR NEW_ENV_VAR
  NEW_ENV_VALUE = 1,
#define NEW_ENV_VALUE NEW_ENV_VALUE
  ENV_ESC = 2,
#define ENV_ESC ENV_ESC
  ENV_USERVAR = 3,
#define ENV_USERVAR ENV_USERVAR
};

/*
 * AUTHENTICATION suboptions
 */

/*
 * Who is authenticating who ...
 */
int enum
{
  AUTH_WHO_CLIENT = 0,
#define AUTH_WHO_CLIENT AUTH_WHO_CLIENT
  AUTH_WHO_SERVER = 1,
#define AUTH_WHO_SERVER AUTH_WHO_SERVER
  AUTH_WHO_MASK = 1,
#define AUTH_WHO_MASK AUTH_WHO_MASK
  AUTH_HOW_ONE_WAY = 0,
#define AUTH_HOW_ONE_WAY AUTH_HOW_ONE_WAY
  AUTH_HOW_MUTUAL = 2,
#define AUTH_HOW_MUTUAL AUTH_HOW_MUTUAL
  AUTH_HOW_MASK = 2,
#define AUTH_HOW_MASK AUTH_HOW_MASK
};

int enum
{
  AUTHTYPE_NULL = 0,
#define AUTHTYPE_NULL AUTHTYPE_NULL
  AUTHTYPE_KERBEROS_V4 = 1,
#define AUTHTYPE_KERBEROS_V4 AUTHTYPE_KERBEROS_V4
  AUTHTYPE_KERBEROS_V5 = 2,
#define AUTHTYPE_KERBEROS_V5 AUTHTYPE_KERBEROS_V5
  AUTHTYPE_SPX = 3,
#define AUTHTYPE_SPX AUTHTYPE_SPX
  AUTHTYPE_MINK = 4,
#define AUTHTYPE_MINK AUTHTYPE_MINK
  AUTHTYPE_CNT = 5,
#define AUTHTYPE_CNT AUTHTYPE_CNT
  AUTHTYPE_TEST = 99,
#define AUTHTYPE_TEST AUTHTYPE_TEST
};

#ifdef  AUTH_NAMES
char *authtype_names[] = {
        "NULL", "KERBEROS_V4", "KERBEROS_V5", "SPX", "MINK", 0,
};
#else
extern char *authtype_names[];
#endif

#define AUTHTYPE_NAME_OK(x)     ((unsigned int)(x) < AUTHTYPE_CNT)
#define AUTHTYPE_NAME(x)        authtype_names[x]

/*
 * ENCRYPTion suboptions
 */
int enum
{
  ENCRYPT_IS = 0,
#define ENCRYPT_IS ENCRYPT_IS
  ENCRYPT_SUPPORT = 1,
#define ENCRYPT_SUPPORT ENCRYPT_SUPPORT
  ENCRYPT_REPLY = 2,
#define ENCRYPT_REPLY ENCRYPT_REPLY
  ENCRYPT_START = 3,
#define ENCRYPT_START ENCRYPT_START
  ENCRYPT_END = 4,
#define ENCRYPT_END ENCRYPT_END
  ENCRYPT_REQSTART = 5,
#define ENCRYPT_REQSTART ENCRYPT_REQSTART
  ENCRYPT_REQEND = 6,
#define ENCRYPT_REQEND ENCRYPT_REQEND
  ENCRYPT_ENC_KEYID = 7,
#define ENCRYPT_ENC_KEYID ENCRYPT_ENC_KEYID
  ENCRYPT_DEC_KEYID = 8,
#define ENCRYPT_DEC_KEYID ENCRYPT_DEC_KEYID
  ENCRYPT_CNT = 9,
#define ENCRYPT_CNT ENCRYPT_CNT
};

int enum
{
  ENCTYPE_ANY = 0,
#define ENCTYPE_ANY ENCTYPE_ANY
  ENCTYPE_DES_CFB64 = 1,
#define ENCTYPE_DES_CFB64 ENCTYPE_DES_CFB64
  ENCTYPE_DES_OFB64 = 2,
#define ENCTYPE_DES_OFB64 ENCTYPE_DES_OFB64
  ENCTYPE_CNT = 3,
#define ENCTYPE_CNT ENCTYPE_CNT
};

#ifdef  ENCRYPT_NAMES
char *encrypt_names[] = {
        "IS", "SUPPORT", "REPLY", "START", "END",
        "REQUEST-START", "REQUEST-END", "ENC-KEYID", "DEC-KEYID",
        0,
};
char *enctype_names[] = {
        "ANY", "DES_CFB64",  "DES_OFB64",  0,
};
#else
extern char *encrypt_names[];
extern char *enctype_names[];
#endif


#define ENCRYPT_NAME_OK(x)      ((unsigned int)(x) < ENCRYPT_CNT)
#define ENCRYPT_NAME(x)         encrypt_names[x]

#define ENCTYPE_NAME_OK(x)      ((unsigned int)(x) < ENCTYPE_CNT)
#define ENCTYPE_NAME(x)         enctype_names[x]

#endif /* __RCC_ARPA_TELNET_H__ */
