/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `linux/capability.h' of the Linux kernel.
   The original copyright follows. */

/*
 * This is <linux/capability.h>
 *
 * Andrew G. Morgan <morgan@transmeta.com>
 * Alexander Kjeldaas <astor@guardian.no>
 * with help from Aleph1, Roland Buresund and Andrew Main.
 *
 * See here for the libcap library ("POSIX draft" compliance):
 *
 * ftp://linux.kernel.org/pub/linux/libs/security/linux-privs/kernel-2.2/
 */ 

#ifndef __RCC_LINUX_CAPABILITY_H__
#define __RCC_LINUX_CAPABILITY_H__

#include <sys/types.h>
//#include <linux/fs.h>

#define _LINUX_CAPABILITY_VERSION  0x19980330

typedef struct __user_cap_header_struct
{
  uint32_t version;
  int pid;
} *cap_user_header_t;
 
typedef struct __user_cap_data_struct
{
  uint32_t effective;
  uint32_t permitted;
  uint32_t inheritable;
} *cap_user_data_t;

int enum
{
#defconst CAP_CHOWN            0
#defconst CAP_DAC_OVERRIDE     1
#defconst CAP_DAC_READ_SEARCH  2
#defconst CAP_FOWNER           3
#defconst CAP_FSETID           4
#defconst CAP_FS_MASK          0x1f
#defconst CAP_KILL             5
#defconst CAP_SETGID           6
#defconst CAP_SETUID           7
#defconst CAP_SETPCAP          8
#defconst CAP_LINUX_IMMUTABLE  9
#defconst CAP_NET_BIND_SERVICE 10
#defconst CAP_NET_BROADCAST    11
#defconst CAP_NET_ADMIN        12
#defconst CAP_NET_RAW          13
#defconst CAP_IPC_LOCK         14
#defconst CAP_IPC_OWNER        15
#defconst CAP_SYS_MODULE       16
#defconst CAP_SYS_RAWIO        17
#defconst CAP_SYS_CHROOT       18
#defconst CAP_SYS_PTRACE       19
#defconst CAP_SYS_PACCT        20
#defconst CAP_SYS_ADMIN        21
#defconst CAP_SYS_BOOT         22
#defconst CAP_SYS_NICE         23
#defconst CAP_SYS_RESOURCE     24
#defconst CAP_SYS_TIME         25
#defconst CAP_SYS_TTY_CONFIG   26
#defconst CAP_MKNOD            27
#defconst CAP_LEASE            28
#defconst CAP_SYS_OPERATIONS   29
#defconst CAP_SYS_ONE_EXEC     30
};

#endif /* __RCC_LINUX_CAPABILITY_H__ */
