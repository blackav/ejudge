/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `linux/unistd.h' of the Linux kernel.
   The original copyright follows. */

#ifndef __RCC_LINUX_UNISTD_H__
#define __RCC_LINUX_UNISTD_H__

extern int errno;

/*
 * This file contains the system call numbers.
 */

int enum
{
#defconst __NR_exit                 1
#defconst __NR_fork                 2
#defconst __NR_read                 3
#defconst __NR_write                4
#defconst __NR_open                 5
#defconst __NR_close                6
#defconst __NR_waitpid              7
#defconst __NR_creat                8
#defconst __NR_link                 9
#defconst __NR_unlink              10
#defconst __NR_execve              11
#defconst __NR_chdir               12
#defconst __NR_time                13
#defconst __NR_mknod               14
#defconst __NR_chmod               15
#defconst __NR_lchown              16
#defconst __NR_break               17
#defconst __NR_oldstat             18
#defconst __NR_lseek               19
#defconst __NR_getpid              20
#defconst __NR_mount               21
#defconst __NR_umount              22
#defconst __NR_setuid              23
#defconst __NR_getuid              24
#defconst __NR_stime               25
#defconst __NR_ptrace              26
#defconst __NR_alarm               27
#defconst __NR_oldfstat            28
#defconst __NR_pause               29
#defconst __NR_utime               30
#defconst __NR_stty                31
#defconst __NR_gtty                32
#defconst __NR_access              33
#defconst __NR_nice                34
#defconst __NR_ftime               35
#defconst __NR_sync                36
#defconst __NR_kill                37
#defconst __NR_rename              38
#defconst __NR_mkdir               39
#defconst __NR_rmdir               40
#defconst __NR_dup                 41
#defconst __NR_pipe                42
#defconst __NR_times               43
#defconst __NR_prof                44
#defconst __NR_brk                 45
#defconst __NR_setgid              46
#defconst __NR_getgid              47
#defconst __NR_signal              48
#defconst __NR_geteuid             49
#defconst __NR_getegid             50
#defconst __NR_acct                51
#defconst __NR_umount2             52
#defconst __NR_lock                53
#defconst __NR_ioctl               54
#defconst __NR_fcntl               55
#defconst __NR_mpx                 56
#defconst __NR_setpgid             57
#defconst __NR_ulimit              58
#defconst __NR_oldolduname         59
#defconst __NR_umask               60
#defconst __NR_chroot              61
#defconst __NR_ustat               62
#defconst __NR_dup2                63
#defconst __NR_getppid             64
#defconst __NR_getpgrp             65
#defconst __NR_setsid              66
#defconst __NR_sigaction           67
#defconst __NR_sgetmask            68
#defconst __NR_ssetmask            69
#defconst __NR_setreuid            70
#defconst __NR_setregid            71
#defconst __NR_sigsuspend          72
#defconst __NR_sigpending          73
#defconst __NR_sethostname         74
#defconst __NR_setrlimit           75
#defconst __NR_getrlimit           76
#defconst __NR_getrusage           77
#defconst __NR_gettimeofday        78
#defconst __NR_settimeofday        79
#defconst __NR_getgroups           80
#defconst __NR_setgroups           81
#defconst __NR_select              82
#defconst __NR_symlink             83
#defconst __NR_oldlstat            84
#defconst __NR_readlink            85
#defconst __NR_uselib              86
#defconst __NR_swapon              87
#defconst __NR_reboot              88
#defconst __NR_readdir             89
#defconst __NR_mmap                90
#defconst __NR_munmap              91
#defconst __NR_truncate            92
#defconst __NR_ftruncate           93
#defconst __NR_fchmod              94
#defconst __NR_fchown              95
#defconst __NR_getpriority         96
#defconst __NR_setpriority         97
#defconst __NR_profil              98
#defconst __NR_statfs              99
#defconst __NR_fstatfs            100
#defconst __NR_ioperm             101
#defconst __NR_socketcall         102
#defconst __NR_syslog             103
#defconst __NR_setitimer          104
#defconst __NR_getitimer          105
#defconst __NR_stat               106
#defconst __NR_lstat              107
#defconst __NR_fstat              108
#defconst __NR_olduname           109
#defconst __NR_iopl               110
#defconst __NR_vhangup            111
#defconst __NR_idle               112
#defconst __NR_vm86old            113
#defconst __NR_wait4              114
#defconst __NR_swapoff            115
#defconst __NR_sysinfo            116
#defconst __NR_ipc                117
#defconst __NR_fsync              118
#defconst __NR_sigreturn          119
#defconst __NR_clone              120
#defconst __NR_setdomainname      121
#defconst __NR_uname              122
#defconst __NR_modify_ldt         123
#defconst __NR_adjtimex           124
#defconst __NR_mprotect           125
#defconst __NR_sigprocmask        126
#defconst __NR_create_module      127
#defconst __NR_init_module        128
#defconst __NR_delete_module      129
#defconst __NR_get_kernel_syms    130
#defconst __NR_quotactl           131
#defconst __NR_getpgid            132
#defconst __NR_fchdir             133
#defconst __NR_bdflush            134
#defconst __NR_sysfs              135
#defconst __NR_personality        136
#defconst __NR_afs_syscall        137
#defconst __NR_setfsuid           138
#defconst __NR_setfsgid           139
#defconst __NR__llseek            140
#defconst __NR_getdents           141
#defconst __NR__newselect         142
#defconst __NR_flock              143
#defconst __NR_msync              144
#defconst __NR_readv              145
#defconst __NR_writev             146
#defconst __NR_getsid             147
#defconst __NR_fdatasync          148
#defconst __NR__sysctl            149
#defconst __NR_mlock              150
#defconst __NR_munlock            151
#defconst __NR_mlockall           152
#defconst __NR_munlockall         153
#defconst __NR_sched_setparam             154
#defconst __NR_sched_getparam             155
#defconst __NR_sched_setscheduler         156
#defconst __NR_sched_getscheduler         157
#defconst __NR_sched_yield                158
#defconst __NR_sched_get_priority_max     159
#defconst __NR_sched_get_priority_min     160
#defconst __NR_sched_rr_get_interval      161
#defconst __NR_nanosleep          162
#defconst __NR_mremap             163
#defconst __NR_setresuid          164
#defconst __NR_getresuid          165
#defconst __NR_vm86               166
#defconst __NR_query_module       167
#defconst __NR_poll               168
#defconst __NR_nfsservctl         169
#defconst __NR_setresgid          170
#defconst __NR_getresgid          171
#defconst __NR_prctl              172
#defconst __NR_rt_sigreturn       173
#defconst __NR_rt_sigaction       174
#defconst __NR_rt_sigprocmask     175
#defconst __NR_rt_sigpending      176
#defconst __NR_rt_sigtimedwait    177
#defconst __NR_rt_sigqueueinfo    178
#defconst __NR_rt_sigsuspend      179
#defconst __NR_pread              180
#defconst __NR_pwrite             181
#defconst __NR_chown              182
#defconst __NR_getcwd             183
#defconst __NR_capget             184
#defconst __NR_capset             185
#defconst __NR_sigaltstack        186
#defconst __NR_sendfile           187
#defconst __NR_getpmsg            188
#defconst __NR_putpmsg            189
#defconst __NR_vfork              190
#defconst __NR_ugetrlimit         191
#defconst __NR_mmap2              192
#defconst __NR_truncate64         193
#defconst __NR_ftruncate64        194
#defconst __NR_stat64             195
#defconst __NR_lstat64            196
#defconst __NR_fstat64            197
#defconst __NR_lchown32           198
#defconst __NR_getuid32           199
#defconst __NR_getgid32           200
#defconst __NR_geteuid32          201
#defconst __NR_getegid32          202
#defconst __NR_setreuid32         203
#defconst __NR_setregid32         204
#defconst __NR_getgroups32        205
#defconst __NR_setgroups32        206
#defconst __NR_fchown32           207
#defconst __NR_setresuid32        208
#defconst __NR_getresuid32        209
#defconst __NR_setresgid32        210
#defconst __NR_getresgid32        211
#defconst __NR_chown32            212
#defconst __NR_setuid32           213
#defconst __NR_setgid32           214
#defconst __NR_setfsuid32         215
#defconst __NR_setfsgid32         216
#defconst __NR_pivot_root         217
#defconst __NR_mincore            218
#defconst __NR_madvise            219
#defconst __NR_madvise1           219
#defconst __NR_getdents64         220
#defconst __NR_fcntl64            221
#defconst __NR_security           223
#defconst __NR_gettid             224
#defconst __NR_readahead          225
#defconst __NR_setxattr           226
#defconst __NR_lsetxattr          227
#defconst __NR_fsetxattr          228
#defconst __NR_getxattr           229
#defconst __NR_lgetxattr          230
#defconst __NR_fgetxattr          231
#defconst __NR_listxattr          232
#defconst __NR_llistxattr         233
#defconst __NR_flistxattr         234
#defconst __NR_removexattr        235
#defconst __NR_lremovexattr       236
#defconst __NR_fremovexattr       237
#defconst __NR_tkill              238
#defconst __NR_sendfile64         239
#defconst __NR_futex              240
#defconst __NR_sched_setaffinity  241
#defconst __NR_sched_getaffinity  242
#defconst __NR_set_thread_area    243
};

/* user-visible error numbers are in the range -1 - -124: see <asm-i386/errno.h> */

#define __syscall_return(type, res) \
do { \
        if ((unsigned long)(res) >= (unsigned long)(-125)) { \
                errno = -(res); \
                res = -1; \
        } \
        return (type) (res); \
} while (0)

#define _syscall0(type,name) \
type name(void) \
{ \
long __res; \
__syscall_return(type,__res); \
}

#define _syscall1(type,name,type1,arg1) \
type name(type1 arg1) \
{ \
long __res; \
__syscall_return(type,__res); \
}

#define _syscall2(type,name,type1,arg1,type2,arg2) \
type name(type1 arg1,type2 arg2) \
{ \
long __res; \
__syscall_return(type,__res); \
}

#define _syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type name(type1 arg1,type2 arg2,type3 arg3) \
{ \
long __res; \
__syscall_return(type,__res); \
}

#define _syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
type name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
{ \
long __res; \
__syscall_return(type,__res); \
} 

#define _syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
          type5,arg5) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{ \
long __res; \
__syscall_return(type,__res); \
}

#define _syscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
          type5,arg5,type6,arg6) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) \
{ \
long __res; \
__syscall_return(type,__res); \
}

#endif /* __RCC_LINUX_UNISTD_H__ */
