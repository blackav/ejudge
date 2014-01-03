/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_UNISTD_H__
#define __RCC_UNISTD_H__

/* Copyright (C) 2002-2004 Alexander Chernov <cher@ispras.ru> */

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

/* What we claim to support */
#define _POSIX_VERSION     199506L
#define _POSIX2_C_VERSION  199209L
#define _POSIX2_VERSION    199209L
#define _POSIX2_C_BIND     1
#define _POSIX2_C_DEV      1
#define _POSIX2_SW_DEV     1
#define _POSIX2_LOCALEDEF  1
#define _XOPEN_VERSION     500
#define _XOPEN_XCU_VERSION 4
#define _XOPEN_XPG2        1
#define _XOPEN_XPG3        1
#define _XOPEN_XPG4        1
#define _XOPEN_UNIX        1
#define _XOPEN_CRYPT       1
#define _XOPEN_ENH_I18N    1
#define _XOPEN_LEGACY      1

#define _POSIX_JOB_CONTROL       1
#define _POSIX_SAVED_IDS         1
#define _POSIX_PRIORITY_SCHEDULING 1
#define _POSIX_SYNCHRONIZED_IO 1
#define _POSIX_FSYNC 1
#define _POSIX_MAPPED_FILES 1
#define _POSIX_MEMLOCK 1
#define _POSIX_MEMLOCK_RANGE 1
#define _POSIX_MEMORY_PROTECTION 1
#define _POSIX_POLL 1
#define _POSIX_SELECT 1
#define _POSIX_CHOWN_RESTRICTED 1
#define _POSIX_VDISABLE '\0'
#define _POSIX_NO_TRUNC 1
#define _XOPEN_REALTIME 1
#define _XOPEN_REALTIME_THREADS 1
#define _XOPEN_SHM 1
#define _POSIX_THREADS 1
#define _POSIX_REENTRANT_FUNCTIONS 1
#define _POSIX_THREAD_SAFE_FUNCTIONS 1
#define _POSIX_THREAD_PRIORITY_SCHEDULING 1
#define _POSIX_THREAD_ATTR_STACKSIZE 1
#define _POSIX_THREAD_ATTR_STACKADDR 1
#define _POSIX_SEMAPHORES 1
#define _POSIX_REALTIME_SIGNALS 1
#define _POSIX_ASYNCHRONOUS_IO 1
#define _LFS_ASYNCHRONOUS_IO 1
#define _LFS64_ASYNCHRONOUS_IO 1
#define _LFS_LARGEFILE 1
#define _LFS64_LARGEFILE 1
#define _LFS64_STDIO 1

# define _XBS5_ILP32_OFF32   1
# define _XBS5_LP64_OFF64   -1
# define _XBS5_LPBIG_OFFBIG -1

#include <sys/types.h>
#include <sys/stat.h>

#ifndef RCC_SIZE_T_DEFINED
#define RCC_SIZE_T_DEFINED 1
typedef unsigned long size_t;
#endif /* RCC_SIZE_T_DEFINED */

#ifndef RCC_SSIZE_T_DEFINED
#define RCC_SSIZE_T_DEFINED 1
typedef long ssize_t;
#endif /* RCC_SSIZE_T_DEFINED */

#ifndef RCC_PTRDIFF_T_DEFINED
#define RCC_PTRDIFF_T_DEFINED 1
typedef long ptrdiff_t;
#endif /* RCC_PTRDIFF_T_DEFINED */

#ifndef __RCC_INTPTR_T_DEFINED__
#define __RCC_INTPTR_T_DEFINED__
typedef int          intptr_t;
#endif /* __RCC_INTPTR_T_DEFINED__ */

typedef unsigned long useconds_t;

#ifndef RCC_X_OK_DEFINED
#define RCC_X_OK_DEFINED
int enum
  {
    R_OK = 4,
    W_OK = 2,
    X_OK = 1,
    F_OK = 0
  };
#endif /* RCC_X_OK_DEFINED */

int enum
{
  _PC_LINK_MAX,
#define _PC_LINK_MAX                    _PC_LINK_MAX
  _PC_MAX_CANON,
#define _PC_MAX_CANON                   _PC_MAX_CANON
  _PC_MAX_INPUT,
#define _PC_MAX_INPUT                   _PC_MAX_INPUT
  _PC_NAME_MAX,
#define _PC_NAME_MAX                    _PC_NAME_MAX
  _PC_PATH_MAX,
#define _PC_PATH_MAX                    _PC_PATH_MAX
  _PC_PIPE_BUF,
#define _PC_PIPE_BUF                    _PC_PIPE_BUF
  _PC_CHOWN_RESTRICTED,
#define _PC_CHOWN_RESTRICTED            _PC_CHOWN_RESTRICTED
  _PC_NO_TRUNC,
#define _PC_NO_TRUNC                    _PC_NO_TRUNC
  _PC_VDISABLE,
#define _PC_VDISABLE                    _PC_VDISABLE
  _PC_SYNC_IO,
#define _PC_SYNC_IO                     _PC_SYNC_IO
  _PC_ASYNC_IO,
#define _PC_ASYNC_IO                    _PC_ASYNC_IO
  _PC_PRIO_IO,
#define _PC_PRIO_IO                     _PC_PRIO_IO
  _PC_SOCK_MAXBUF,
#define _PC_SOCK_MAXBUF                 _PC_SOCK_MAXBUF
  _PC_FILESIZEBITS
#define _PC_FILESIZEBITS                _PC_FILESIZEBITS
};

int enum
{
  _SC_ARG_MAX,
#define _SC_ARG_MAX                     _SC_ARG_MAX
  _SC_CHILD_MAX,
#define _SC_CHILD_MAX                   _SC_CHILD_MAX
  _SC_CLK_TCK,
#define _SC_CLK_TCK                     _SC_CLK_TCK
  _SC_NGROUPS_MAX,
#define _SC_NGROUPS_MAX                 _SC_NGROUPS_MAX
  _SC_OPEN_MAX,
#define _SC_OPEN_MAX                    _SC_OPEN_MAX
  _SC_STREAM_MAX,
#define _SC_STREAM_MAX                  _SC_STREAM_MAX
  _SC_TZNAME_MAX,
#define _SC_TZNAME_MAX                  _SC_TZNAME_MAX
  _SC_JOB_CONTROL,
#define _SC_JOB_CONTROL                 _SC_JOB_CONTROL
  _SC_SAVED_IDS,
#define _SC_SAVED_IDS                   _SC_SAVED_IDS
  _SC_REALTIME_SIGNALS,
#define _SC_REALTIME_SIGNALS            _SC_REALTIME_SIGNALS
  _SC_PRIORITY_SCHEDULING,
#define _SC_PRIORITY_SCHEDULING         _SC_PRIORITY_SCHEDULING
  _SC_TIMERS,
#define _SC_TIMERS                      _SC_TIMERS
  _SC_ASYNCHRONOUS_IO,
#define _SC_ASYNCHRONOUS_IO             _SC_ASYNCHRONOUS_IO
  _SC_PRIORITIZED_IO,
#define _SC_PRIORITIZED_IO              _SC_PRIORITIZED_IO
  _SC_SYNCHRONIZED_IO,
#define _SC_SYNCHRONIZED_IO             _SC_SYNCHRONIZED_IO
  _SC_FSYNC,
#define _SC_FSYNC                       _SC_FSYNC
  _SC_MAPPED_FILES,
#define _SC_MAPPED_FILES                _SC_MAPPED_FILES
  _SC_MEMLOCK,
#define _SC_MEMLOCK                     _SC_MEMLOCK
  _SC_MEMLOCK_RANGE,
#define _SC_MEMLOCK_RANGE               _SC_MEMLOCK_RANGE
  _SC_MEMORY_PROTECTION,
#define _SC_MEMORY_PROTECTION           _SC_MEMORY_PROTECTION
  _SC_MESSAGE_PASSING,
#define _SC_MESSAGE_PASSING             _SC_MESSAGE_PASSING
  _SC_SEMAPHORES,
#define _SC_SEMAPHORES                  _SC_SEMAPHORES
  _SC_SHARED_MEMORY_OBJECTS,
#define _SC_SHARED_MEMORY_OBJECTS       _SC_SHARED_MEMORY_OBJECTS
  _SC_AIO_LISTIO_MAX,
#define _SC_AIO_LISTIO_MAX              _SC_AIO_LISTIO_MAX
  _SC_AIO_MAX,
#define _SC_AIO_MAX                     _SC_AIO_MAX
  _SC_AIO_PRIO_DELTA_MAX,
#define _SC_AIO_PRIO_DELTA_MAX          _SC_AIO_PRIO_DELTA_MAX
  _SC_DELAYTIMER_MAX,
#define _SC_DELAYTIMER_MAX              _SC_DELAYTIMER_MAX
  _SC_MQ_OPEN_MAX,
#define _SC_MQ_OPEN_MAX                 _SC_MQ_OPEN_MAX
  _SC_MQ_PRIO_MAX,
#define _SC_MQ_PRIO_MAX                 _SC_MQ_PRIO_MAX
  _SC_VERSION,
#define _SC_VERSION                     _SC_VERSION
  _SC_PAGESIZE,
#define _SC_PAGESIZE                    _SC_PAGESIZE
#define _SC_PAGE_SIZE                   _SC_PAGESIZE
  _SC_RTSIG_MAX,
#define _SC_RTSIG_MAX                   _SC_RTSIG_MAX
  _SC_SEM_NSEMS_MAX,
#define _SC_SEM_NSEMS_MAX               _SC_SEM_NSEMS_MAX
  _SC_SEM_VALUE_MAX,
#define _SC_SEM_VALUE_MAX               _SC_SEM_VALUE_MAX
  _SC_SIGQUEUE_MAX,
#define _SC_SIGQUEUE_MAX                _SC_SIGQUEUE_MAX
  _SC_TIMER_MAX,
#define _SC_TIMER_MAX                   _SC_TIMER_MAX
  _SC_BC_BASE_MAX,
#define _SC_BC_BASE_MAX                 _SC_BC_BASE_MAX
  _SC_BC_DIM_MAX,
#define _SC_BC_DIM_MAX                  _SC_BC_DIM_MAX
  _SC_BC_SCALE_MAX,
#define _SC_BC_SCALE_MAX                _SC_BC_SCALE_MAX
  _SC_BC_STRING_MAX,
#define _SC_BC_STRING_MAX               _SC_BC_STRING_MAX
  _SC_COLL_WEIGHTS_MAX,
#define _SC_COLL_WEIGHTS_MAX            _SC_COLL_WEIGHTS_MAX
  _SC_EQUIV_CLASS_MAX,
#define _SC_EQUIV_CLASS_MAX             _SC_EQUIV_CLASS_MAX
  _SC_EXPR_NEST_MAX,
#define _SC_EXPR_NEST_MAX               _SC_EXPR_NEST_MAX
  _SC_LINE_MAX,
#define _SC_LINE_MAX                    _SC_LINE_MAX
  _SC_RE_DUP_MAX,
#define _SC_RE_DUP_MAX                  _SC_RE_DUP_MAX
  _SC_CHARCLASS_NAME_MAX,
#define _SC_CHARCLASS_NAME_MAX          _SC_CHARCLASS_NAME_MAX
  _SC_2_VERSION,
#define _SC_2_VERSION                   _SC_2_VERSION
  _SC_2_C_BIND,
#define _SC_2_C_BIND                    _SC_2_C_BIND
  _SC_2_C_DEV,
#define _SC_2_C_DEV                     _SC_2_C_DEV
  _SC_2_FORT_DEV,
#define _SC_2_FORT_DEV                  _SC_2_FORT_DEV
  _SC_2_FORT_RUN,
#define _SC_2_FORT_RUN                  _SC_2_FORT_RUN
  _SC_2_SW_DEV,
#define _SC_2_SW_DEV                    _SC_2_SW_DEV
  _SC_2_LOCALEDEF,
#define _SC_2_LOCALEDEF                 _SC_2_LOCALEDEF
  _SC_PII,
#define _SC_PII                         _SC_PII
  _SC_PII_XTI,
#define _SC_PII_XTI                     _SC_PII_XTI
  _SC_PII_SOCKET,
#define _SC_PII_SOCKET                  _SC_PII_SOCKET
  _SC_PII_INTERNET,
#define _SC_PII_INTERNET                _SC_PII_INTERNET
  _SC_PII_OSI,
#define _SC_PII_OSI                     _SC_PII_OSI
  _SC_POLL,
#define _SC_POLL                        _SC_POLL
  _SC_SELECT,
#define _SC_SELECT                      _SC_SELECT
  _SC_UIO_MAXIOV,
#define _SC_UIO_MAXIOV                  _SC_UIO_MAXIOV
  _SC_PII_INTERNET_STREAM,
#define _SC_PII_INTERNET_STREAM         _SC_PII_INTERNET_STREAM
  _SC_PII_INTERNET_DGRAM,
#define _SC_PII_INTERNET_DGRAM          _SC_PII_INTERNET_DGRAM
  _SC_PII_OSI_COTS,
#define _SC_PII_OSI_COTS                _SC_PII_OSI_COTS
  _SC_PII_OSI_CLTS,
#define _SC_PII_OSI_CLTS                _SC_PII_OSI_CLTS
  _SC_PII_OSI_M,
#define _SC_PII_OSI_M                   _SC_PII_OSI_M
  _SC_T_IOV_MAX,
#define _SC_T_IOV_MAX                   _SC_T_IOV_MAX
  _SC_THREADS,
#define _SC_THREADS                     _SC_THREADS
  _SC_THREAD_SAFE_FUNCTIONS,
#define _SC_THREAD_SAFE_FUNCTIONS       _SC_THREAD_SAFE_FUNCTIONS
  _SC_GETGR_R_SIZE_MAX,
#define _SC_GETGR_R_SIZE_MAX            _SC_GETGR_R_SIZE_MAX
  _SC_GETPW_R_SIZE_MAX,
#define _SC_GETPW_R_SIZE_MAX            _SC_GETPW_R_SIZE_MAX
  _SC_LOGIN_NAME_MAX,
#define _SC_LOGIN_NAME_MAX              _SC_LOGIN_NAME_MAX
  _SC_TTY_NAME_MAX,
#define _SC_TTY_NAME_MAX                _SC_TTY_NAME_MAX
  _SC_THREAD_DESTRUCTOR_ITERATIONS,
#define _SC_THREAD_DESTRUCTOR_ITERATIONS _SC_THREAD_DESTRUCTOR_ITERATIONS
  _SC_THREAD_KEYS_MAX,
#define _SC_THREAD_KEYS_MAX             _SC_THREAD_KEYS_MAX
  _SC_THREAD_STACK_MIN,
#define _SC_THREAD_STACK_MIN            _SC_THREAD_STACK_MIN
  _SC_THREAD_THREADS_MAX,
#define _SC_THREAD_THREADS_MAX          _SC_THREAD_THREADS_MAX
  _SC_THREAD_ATTR_STACKADDR,
#define _SC_THREAD_ATTR_STACKADDR       _SC_THREAD_ATTR_STACKADDR
  _SC_THREAD_ATTR_STACKSIZE,
#define _SC_THREAD_ATTR_STACKSIZE       _SC_THREAD_ATTR_STACKSIZE
  _SC_THREAD_PRIORITY_SCHEDULING,
#define _SC_THREAD_PRIORITY_SCHEDULING  _SC_THREAD_PRIORITY_SCHEDULING
  _SC_THREAD_PRIO_INHERIT,
#define _SC_THREAD_PRIO_INHERIT         _SC_THREAD_PRIO_INHERIT
  _SC_THREAD_PRIO_PROTECT,
#define _SC_THREAD_PRIO_PROTECT         _SC_THREAD_PRIO_PROTECT
  _SC_THREAD_PROCESS_SHARED,
#define _SC_THREAD_PROCESS_SHARED       _SC_THREAD_PROCESS_SHARED
  _SC_NPROCESSORS_CONF,
#define _SC_NPROCESSORS_CONF            _SC_NPROCESSORS_CONF
  _SC_NPROCESSORS_ONLN,
#define _SC_NPROCESSORS_ONLN            _SC_NPROCESSORS_ONLN
  _SC_PHYS_PAGES,
#define _SC_PHYS_PAGES                  _SC_PHYS_PAGES
  _SC_AVPHYS_PAGES,
#define _SC_AVPHYS_PAGES                _SC_AVPHYS_PAGES
  _SC_ATEXIT_MAX,
#define _SC_ATEXIT_MAX                  _SC_ATEXIT_MAX
  _SC_PASS_MAX,
#define _SC_PASS_MAX                    _SC_PASS_MAX
  _SC_XOPEN_VERSION,
#define _SC_XOPEN_VERSION               _SC_XOPEN_VERSION
  _SC_XOPEN_XCU_VERSION,
#define _SC_XOPEN_XCU_VERSION           _SC_XOPEN_XCU_VERSION
  _SC_XOPEN_UNIX,
#define _SC_XOPEN_UNIX                  _SC_XOPEN_UNIX
  _SC_XOPEN_CRYPT,
#define _SC_XOPEN_CRYPT                 _SC_XOPEN_CRYPT
  _SC_XOPEN_ENH_I18N,
#define _SC_XOPEN_ENH_I18N              _SC_XOPEN_ENH_I18N
  _SC_XOPEN_SHM,
#define _SC_XOPEN_SHM                   _SC_XOPEN_SHM
  _SC_2_CHAR_TERM,
#define _SC_2_CHAR_TERM                 _SC_2_CHAR_TERM
  _SC_2_C_VERSION,
#define _SC_2_C_VERSION                 _SC_2_C_VERSION
  _SC_2_UPE,
#define _SC_2_UPE                       _SC_2_UPE
  _SC_XOPEN_XPG2,
#define _SC_XOPEN_XPG2                  _SC_XOPEN_XPG2
  _SC_XOPEN_XPG3,
#define _SC_XOPEN_XPG3                  _SC_XOPEN_XPG3
  _SC_XOPEN_XPG4,
#define _SC_XOPEN_XPG4                  _SC_XOPEN_XPG4
  _SC_CHAR_BIT,
#define _SC_CHAR_BIT                    _SC_CHAR_BIT
  _SC_CHAR_MAX,
#define _SC_CHAR_MAX                    _SC_CHAR_MAX
  _SC_CHAR_MIN,
#define _SC_CHAR_MIN                    _SC_CHAR_MIN
  _SC_INT_MAX,
#define _SC_INT_MAX                     _SC_INT_MAX
  _SC_INT_MIN,
#define _SC_INT_MIN                     _SC_INT_MIN
  _SC_LONG_BIT,
#define _SC_LONG_BIT                    _SC_LONG_BIT
  _SC_WORD_BIT,
#define _SC_WORD_BIT                    _SC_WORD_BIT
  _SC_MB_LEN_MAX,
#define _SC_MB_LEN_MAX                  _SC_MB_LEN_MAX
  _SC_NZERO,
#define _SC_NZERO                       _SC_NZERO
  _SC_SSIZE_MAX,
#define _SC_SSIZE_MAX                   _SC_SSIZE_MAX
  _SC_SCHAR_MAX,
#define _SC_SCHAR_MAX                   _SC_SCHAR_MAX
  _SC_SCHAR_MIN,
#define _SC_SCHAR_MIN                   _SC_SCHAR_MIN
  _SC_SHRT_MAX,
#define _SC_SHRT_MAX                    _SC_SHRT_MAX
  _SC_SHRT_MIN,
#define _SC_SHRT_MIN                    _SC_SHRT_MIN
  _SC_UCHAR_MAX,
#define _SC_UCHAR_MAX                   _SC_UCHAR_MAX
  _SC_UINT_MAX,
#define _SC_UINT_MAX                    _SC_UINT_MAX
  _SC_ULONG_MAX,
#define _SC_ULONG_MAX                   _SC_ULONG_MAX
  _SC_USHRT_MAX,
#define _SC_USHRT_MAX                   _SC_USHRT_MAX
  _SC_NL_ARGMAX,
#define _SC_NL_ARGMAX                   _SC_NL_ARGMAX
  _SC_NL_LANGMAX,
#define _SC_NL_LANGMAX                  _SC_NL_LANGMAX
  _SC_NL_MSGMAX,
#define _SC_NL_MSGMAX                   _SC_NL_MSGMAX
  _SC_NL_NMAX,
#define _SC_NL_NMAX                     _SC_NL_NMAX
  _SC_NL_SETMAX,
#define _SC_NL_SETMAX                   _SC_NL_SETMAX
  _SC_NL_TEXTMAX,
#define _SC_NL_TEXTMAX                  _SC_NL_TEXTMAX
  _SC_XBS5_ILP32_OFF32,
#define _SC_XBS5_ILP32_OFF32            _SC_XBS5_ILP32_OFF32
  _SC_XBS5_ILP32_OFFBIG,
#define _SC_XBS5_ILP32_OFFBIG           _SC_XBS5_ILP32_OFFBIG
  _SC_XBS5_LP64_OFF64,
#define _SC_XBS5_LP64_OFF64             _SC_XBS5_LP64_OFF64
  _SC_XBS5_LPBIG_OFFBIG,
#define _SC_XBS5_LPBIG_OFFBIG           _SC_XBS5_LPBIG_OFFBIG
  _SC_XOPEN_LEGACY,
#define _SC_XOPEN_LEGACY                _SC_XOPEN_LEGACY
  _SC_XOPEN_REALTIME,
#define _SC_XOPEN_REALTIME              _SC_XOPEN_REALTIME
  _SC_XOPEN_REALTIME_THREADS
#define _SC_XOPEN_REALTIME_THREADS      _SC_XOPEN_REALTIME_THREADS
};

int enum
{
  _CS_PATH,
#define _CS_PATH                _CS_PATH
  _CS_LFS_CFLAGS = 1000,
# define _CS_LFS_CFLAGS         _CS_LFS_CFLAGS
  _CS_LFS_LDFLAGS,
# define _CS_LFS_LDFLAGS        _CS_LFS_LDFLAGS
  _CS_LFS_LIBS,
# define _CS_LFS_LIBS           _CS_LFS_LIBS
  _CS_LFS_LINTFLAGS,
# define _CS_LFS_LINTFLAGS      _CS_LFS_LINTFLAGS
  _CS_LFS64_CFLAGS,
# define _CS_LFS64_CFLAGS       _CS_LFS64_CFLAGS
  _CS_LFS64_LDFLAGS,
# define _CS_LFS64_LDFLAGS      _CS_LFS64_LDFLAGS
  _CS_LFS64_LIBS,
# define _CS_LFS64_LIBS         _CS_LFS64_LIBS
  _CS_LFS64_LINTFLAGS,
#define _CS_LFS64_LINTFLAGS     _CS_LFS64_LINTFLAGS
  _CS_XBS5_ILP32_OFF32_CFLAGS = 1100,
# define _CS_XBS5_ILP32_OFF32_CFLAGS _CS_XBS5_ILP32_OFF32_CFLAGS
  _CS_XBS5_ILP32_OFF32_LDFLAGS,
# define _CS_XBS5_ILP32_OFF32_LDFLAGS _CS_XBS5_ILP32_OFF32_LDFLAGS
  _CS_XBS5_ILP32_OFF32_LIBS,
# define _CS_XBS5_ILP32_OFF32_LIBS _CS_XBS5_ILP32_OFF32_LIBS
  _CS_XBS5_ILP32_OFF32_LINTFLAGS,
# define _CS_XBS5_ILP32_OFF32_LINTFLAGS _CS_XBS5_ILP32_OFF32_LINTFLAGS
  _CS_XBS5_ILP32_OFFBIG_CFLAGS,
# define _CS_XBS5_ILP32_OFFBIG_CFLAGS _CS_XBS5_ILP32_OFFBIG_CFLAGS
  _CS_XBS5_ILP32_OFFBIG_LDFLAGS,
# define _CS_XBS5_ILP32_OFFBIG_LDFLAGS _CS_XBS5_ILP32_OFFBIG_LDFLAGS
  _CS_XBS5_ILP32_OFFBIG_LIBS,
# define _CS_XBS5_ILP32_OFFBIG_LIBS _CS_XBS5_ILP32_OFFBIG_LIBS
  _CS_XBS5_ILP32_OFFBIG_LINTFLAGS,
# define _CS_XBS5_ILP32_OFFBIG_LINTFLAGS _CS_XBS5_ILP32_OFFBIG_LINTFLAGS
  _CS_XBS5_LP64_OFF64_CFLAGS,
# define _CS_XBS5_LP64_OFF64_CFLAGS _CS_XBS5_LP64_OFF64_CFLAGS
  _CS_XBS5_LP64_OFF64_LDFLAGS,
# define _CS_XBS5_LP64_OFF64_LDFLAGS _CS_XBS5_LP64_OFF64_LDFLAGS
  _CS_XBS5_LP64_OFF64_LIBS,
# define _CS_XBS5_LP64_OFF64_LIBS _CS_XBS5_LP64_OFF64_LIBS
  _CS_XBS5_LP64_OFF64_LINTFLAGS,
# define _CS_XBS5_LP64_OFF64_LINTFLAGS _CS_XBS5_LP64_OFF64_LINTFLAGS
  _CS_XBS5_LPBIG_OFFBIG_CFLAGS,
# define _CS_XBS5_LPBIG_OFFBIG_CFLAGS _CS_XBS5_LPBIG_OFFBIG_CFLAGS
  _CS_XBS5_LPBIG_OFFBIG_LDFLAGS,
# define _CS_XBS5_LPBIG_OFFBIG_LDFLAGS _CS_XBS5_LPBIG_OFFBIG_LDFLAGS
  _CS_XBS5_LPBIG_OFFBIG_LIBS,
# define _CS_XBS5_LPBIG_OFFBIG_LIBS _CS_XBS5_LPBIG_OFFBIG_LIBS
  _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS
# define _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS
};

#include <getopt.h>

int mknod(const char *pathname, mode_t mode, dev_t dev);

int access(const char *name, int type);
int euidaccess(const char *name, int type);

#ifndef SEEK_SET
int enum
{
#defconst SEEK_SET 0
#defconst SEEK_CUR 1
#defconst SEEK_END 2
};
#endif /* SEEK_SET */

#ifndef STDIN_FILENO
int enum
{
#defconst STDIN_FILENO  0
#defconst STDOUT_FILENO 1
#defconst STDERR_FILENO 2
};
#endif /* STDIN_FILENO is defined */

off_t   lseek(int fd, off_t offset, int whence);
off64_t lseek64(int fd, off64_t offset, int whence);

int close(int fd);

ssize_t read(int fd, void *buf, size_t nbytes);
ssize_t write(int fd, const void *buf, size_t n);
ssize_t pread(int fd, void *buf, size_t nbytes, off_t offset);
ssize_t pwrite(int fd, const void *buf, size_t n, off_t offset);
ssize_t pread64(int fd, void *buf, size_t nbytes, off64_t offset);
ssize_t pwrite64(int fd, const void *buf, size_t n, off64_t offset);

int pipe(int pipedes[2]);

unsigned int alarm(unsigned int seconds);
unsigned int sleep(unsigned int seconds);
useconds_t ualarm(useconds_t value, useconds_t interval);
int usleep(useconds_t useconds);
int pause(void);

int chown(const char *file, uid_t owner, gid_t group);
int fchown(int fd, uid_t owner, gid_t group);
int lchown(const char *file, uid_t owner, gid_t group);

int chdir(const char *path);
int fchdir(int fd);

char *getcwd(char *buf, size_t size);
char *get_current_dir_name(void);
char *getwd(char *buf);

int dup(int fd);
int dup2(int oldfd, int newfd);

extern char **__environ;
extern char **environ;

int execve(const char *path, char *const argv[], char *const envp[]);
int fexecve(int fd, char *const argv[], char *const envp[]);
int execv(const char *path, char *const argv[]);
int execle(const char *path, const char *arg, ...);
int execl(const char *path, const char *arg, ...);
int execvp(const char *file, char *const argv[]);
int execlp(const char *file, const char *arg, ...);

int nice(int inc);

void _exit(int status) __attribute__((noreturn));

long int pathconf(const char *path, int name);
long int fpathconf(int fd, int name);
long int sysconf(int name);
size_t confstr(int name, char *buf, size_t len);

pid_t getpid(void);
pid_t getppid(void);

pid_t getpgrp(void);
pid_t getpgid(pid_t pid);
int setpgid(pid_t pid, pid_t pgid);
int setpgrp(void);

pid_t setsid(void);
pid_t getsid(pid_t pid);

uid_t getuid(void);
uid_t geteuid(void);
gid_t getgid(void);
gid_t getegid(void);
int getgroups(int size, gid_t list[]);
int group_member(gid_t gid);

int setuid(uid_t uid);
int setreuid(uid_t ruid, uid_t euid);
int seteuid(uid_t uid);
int setgid(gid_t gid);
int setregid(gid_t rgid, gid_t egid);
int setegid(gid_t gid);
int getresuid(uid_t *euid, uid_t *ruid, uid_t *suid);
int getresgid(gid_t *egid, gid_t *rgid, gid_t *sgid);
int setresuid(uid_t euid, uid_t ruid, uid_t suid);
int setresgid(gid_t egid, gid_t rgid, gid_t sgid);

pid_t fork(void);
pid_t vfork(void);

char *ttyname(int fd);
int ttyname_r(int fd, char *buf, size_t buflen);
int isatty(int fd);
int ttyslot(void);

int link(const char *from, const char *to);
int symlink(const char *from, const char *to);
int readlink(const char *path, char *buf, size_t len);
int unlink(const char *name);
int rmdir(const char *path);

pid_t tcgetpgrp(int fd);
int tcsetpgrp(int fd, pid_t pgrp_id);

char *getlogin(void);
int getlogin_r(char *name, size_t name_len);
int setlogin(const char *name);

int gethostname(char *name, size_t len);
int sethostname(const char *name, size_t len);
int sethostid(long int id);
int getdomainname(char *name, size_t len);
int setdomainname(const char *name, size_t len);

int vhangup(void);
int revoke(const char *file);

int profil(unsigned short int *sample_buffer, size_t size,
           size_t offset, unsigned int scale);
int acct(const char *name);

char *getusershell(void);
void endusershell(void);
void setusershell(void);

int daemon(int nochdir, int noclose);

int chroot(const char *path);
char *getpass(const char *prompt);

int fsync(int fd);
void sync(void);

long int gethostid(void);

int getpagesize(void);

int truncate(const char *file, off_t length);
int truncate64(const char *file, off64_t length);
int ftruncate(int fd, off_t length);
int ftruncate64(int fd, off64_t length);

int getdtablesize(void);

int brk(void *);
void *sbrk(intptr_t delta);

#ifndef F_ULOCK
int enum
{
  F_ULOCK = 0,
#define F_ULOCK F_ULOCK
  F_LOCK = 1,
#define F_LOCK F_LOCK
  F_TLOCK = 2,
#define F_TLOCK F_TLOCK
  F_TEST = 3,
#define F_TEST F_TEST
};
#endif

int lockf(int fd, int cmd, off_t len);
int lockf64(int fd, int cmd, off64_t len);

//# define TEMP_FAILURE_RETRY(expression) \
//  (__extension__							      \
//    ({ long int __result;						      \
//       do __result = (long int) (expression);				      \
//       while (__result == -1L && errno == EINTR);			      \
//       __result; }))
//#endif

int fdatasync(int fildes);

char *crypt(const char *key, const char *salt);
void encrypt(char *block, int edflag);

void swab(const void *from, void *to, ssize_t n);

char *ctermid(char *s);

int pthread_atfork(void (*prepare) (void), void (*parent) (void),
                   void (*child) (void));

#endif /* __RCC_UNISTD_H__ */
