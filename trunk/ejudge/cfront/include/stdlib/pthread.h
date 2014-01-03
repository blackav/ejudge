/* $Id$ */
/* Copyright (C) 2004,2005 Alexander Chernov */

/* This file is derived from `pthread.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Linuxthreads - a simple clone()-based implementation of Posix        */
/* threads for Linux.                                                   */
/* Copyright (C) 1996 Xavier Leroy (Xavier.Leroy@inria.fr)              */
/*                                                                      */
/* This program is free software; you can redistribute it and/or        */
/* modify it under the terms of the GNU Library General Public License  */
/* as published by the Free Software Foundation; either version 2       */
/* of the License, or (at your option) any later version.               */
/*                                                                      */
/* This program is distributed in the hope that it will be useful,      */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU Library General Public License for more details.                 */

#ifndef __RCC_PTHREAD_H__
#define __RCC_PTHREAD_H__ 1

#include <features.h>
#include <sched.h>
#include <time.h>
#include <signal.h>

struct _pthread_fastlock
{
  long int __status;
  int __spinlock;
};

#ifndef __RCC_PTHREAD_DESCR_DEFINED
typedef struct _pthread_descr_struct *_pthread_descr;
#define __RCC_PTHREAD_DESCR_DEFINED
# define _PTHREAD_DESCR_DEFINED
#endif

/* Attributes for threads.  */
typedef struct __pthread_attr_s
{
  int __detachstate;
  int __schedpolicy;
  struct __sched_param __schedparam;
  int __inheritsched;
  int __scope;
  size_t __guardsize;
  int __stackaddr_set;
  void *__stackaddr;
  size_t __stacksize;
} pthread_attr_t;

/* Conditions (not abstract because of PTHREAD_COND_INITIALIZER */
typedef long long __pthread_cond_align_t;

typedef struct
{
  struct _pthread_fastlock __c_lock;
  _pthread_descr __c_waiting;
  char __padding[48 - sizeof (struct _pthread_fastlock)
                 - sizeof (_pthread_descr) - sizeof (__pthread_cond_align_t)];
  __pthread_cond_align_t __align;
} pthread_cond_t;

/* Attribute for conditionally variables.  */
typedef struct
{
  int __dummy;
} pthread_condattr_t;

/* Keys for thread-specific data */
typedef unsigned int pthread_key_t;

/* Mutexes (not abstract because of PTHREAD_MUTEX_INITIALIZER).  */
/* (The layout is unnatural to maintain binary compatibility
    with earlier releases of LinuxThreads.) */
typedef struct
{
  int __m_reserved;
  int __m_count;
  _pthread_descr __m_owner;
  int __m_kind;
  struct _pthread_fastlock __m_lock;
} pthread_mutex_t;

/* Attribute for mutex.  */
typedef struct
{
  int __mutexkind;
} pthread_mutexattr_t;

/* Once-only execution */
typedef int pthread_once_t;

/* Read-write locks.  */
typedef struct _pthread_rwlock_t
{
  struct _pthread_fastlock __rw_lock;
  int __rw_readers;
  _pthread_descr __rw_writer;
  _pthread_descr __rw_read_waiting;
  _pthread_descr __rw_write_waiting;
  int __rw_kind;
  int __rw_pshared;
} pthread_rwlock_t;

/* Attribute for read-write locks.  */
typedef struct
{
  int __lockkind;
  int __pshared;
} pthread_rwlockattr_t;

/* POSIX spinlock data type.  */
typedef volatile int pthread_spinlock_t;

/* POSIX barrier. */
typedef struct {
  struct _pthread_fastlock __ba_lock;
  int __ba_required;
  int __ba_present;
  _pthread_descr __ba_waiting;
} pthread_barrier_t;

/* barrier attribute */
typedef struct {
  int __pshared;
} pthread_barrierattr_t;

/* Thread identifiers */
typedef unsigned long int pthread_t;

#define __LT_SPINLOCK_INIT 0

/* Macros for lock initializers, using the above definition. */
#define __LOCK_INITIALIZER { 0, __LT_SPINLOCK_INIT }
#define __ALT_LOCK_INITIALIZER { 0, __LT_SPINLOCK_INIT }
#define __ATOMIC_INITIALIZER { 0, __LT_SPINLOCK_INIT }

/* Initializers.  */
#define PTHREAD_MUTEX_INITIALIZER \
  {0, 0, 0, PTHREAD_MUTEX_TIMED_NP, __LOCK_INITIALIZER}
#define PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP \
  {0, 0, 0, PTHREAD_MUTEX_RECURSIVE_NP, __LOCK_INITIALIZER}
#define PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP \
  {0, 0, 0, PTHREAD_MUTEX_ERRORCHECK_NP, __LOCK_INITIALIZER}
#define PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP \
  {0, 0, 0, PTHREAD_MUTEX_ADAPTIVE_NP, __LOCK_INITIALIZER}

#define PTHREAD_COND_INITIALIZER {__LOCK_INITIALIZER, 0, "", 0}

# define PTHREAD_RWLOCK_INITIALIZER \
  { __LOCK_INITIALIZER, 0, NULL, NULL, NULL,                                  \
    PTHREAD_RWLOCK_DEFAULT_NP, PTHREAD_PROCESS_PRIVATE }
# define PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP \
  { __LOCK_INITIALIZER, 0, NULL, NULL, NULL,                                  \
    PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP, PTHREAD_PROCESS_PRIVATE }

/* Values for attributes.  */
int enum
{
  PTHREAD_CREATE_JOINABLE,
#define PTHREAD_CREATE_JOINABLE PTHREAD_CREATE_JOINABLE
  PTHREAD_CREATE_DETACHED
#define PTHREAD_CREATE_DETACHED PTHREAD_CREATE_DETACHED
};

int enum
{
  PTHREAD_INHERIT_SCHED,
#define PTHREAD_INHERIT_SCHED   PTHREAD_INHERIT_SCHED
  PTHREAD_EXPLICIT_SCHED
#define PTHREAD_EXPLICIT_SCHED  PTHREAD_EXPLICIT_SCHED
};

int enum
{
  PTHREAD_SCOPE_SYSTEM,
#define PTHREAD_SCOPE_SYSTEM    PTHREAD_SCOPE_SYSTEM
  PTHREAD_SCOPE_PROCESS
#define PTHREAD_SCOPE_PROCESS   PTHREAD_SCOPE_PROCESS
};

int enum
{
  PTHREAD_MUTEX_TIMED_NP,
  PTHREAD_MUTEX_RECURSIVE_NP,
  PTHREAD_MUTEX_ERRORCHECK_NP,
  PTHREAD_MUTEX_ADAPTIVE_NP,
  PTHREAD_MUTEX_NORMAL = PTHREAD_MUTEX_TIMED_NP,
  PTHREAD_MUTEX_RECURSIVE = PTHREAD_MUTEX_RECURSIVE_NP,
  PTHREAD_MUTEX_ERRORCHECK = PTHREAD_MUTEX_ERRORCHECK_NP,
  PTHREAD_MUTEX_DEFAULT = PTHREAD_MUTEX_NORMAL,
  PTHREAD_MUTEX_FAST_NP = PTHREAD_MUTEX_ADAPTIVE_NP
};

int enum
{
  PTHREAD_PROCESS_PRIVATE,
#define PTHREAD_PROCESS_PRIVATE PTHREAD_PROCESS_PRIVATE
  PTHREAD_PROCESS_SHARED
#define PTHREAD_PROCESS_SHARED  PTHREAD_PROCESS_SHARED
};

int enum
{
  PTHREAD_RWLOCK_PREFER_READER_NP,
  PTHREAD_RWLOCK_PREFER_WRITER_NP,
  PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP,
  PTHREAD_RWLOCK_DEFAULT_NP = PTHREAD_RWLOCK_PREFER_WRITER_NP
};

#define PTHREAD_ONCE_INIT 0
# define PTHREAD_BARRIER_SERIAL_THREAD -1

/* Cleanup buffers */

struct _pthread_cleanup_buffer
{
  void (*__routine) (void *);
  void *__arg;
  int __canceltype;
  struct _pthread_cleanup_buffer *__prev;
};

/* Cancellation */

int enum
{
  PTHREAD_CANCEL_ENABLE,
#define PTHREAD_CANCEL_ENABLE   PTHREAD_CANCEL_ENABLE
  PTHREAD_CANCEL_DISABLE
#define PTHREAD_CANCEL_DISABLE  PTHREAD_CANCEL_DISABLE
};

int enum
{
  PTHREAD_CANCEL_DEFERRED,
#define PTHREAD_CANCEL_DEFERRED PTHREAD_CANCEL_DEFERRED
  PTHREAD_CANCEL_ASYNCHRONOUS
#define PTHREAD_CANCEL_ASYNCHRONOUS     PTHREAD_CANCEL_ASYNCHRONOUS
};
#define PTHREAD_CANCELED ((void *) -1)


/* Function for handling threads.  */
int pthread_create(pthread_t *threadp, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg);
pthread_t pthread_self(void);
int pthread_equal(pthread_t thread1, pthread_t thread2);
void pthread_exit(void *retval) __attribute__ ((noreturn));
int pthread_join(pthread_t th, void **thread_return);
int pthread_detach(pthread_t th);


/* Functions for handling attributes.  */
int pthread_attr_init(pthread_attr_t *attr);
int pthread_attr_destroy(pthread_attr_t *attr);
int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate);
int pthread_attr_getdetachstate(const pthread_attr_t *attr, int *detachstate);
int pthread_attr_setschedparam(pthread_attr_t *attr,
                               const struct sched_param *param);
int pthread_attr_getschedparam(const pthread_attr_t *attr,
                               struct sched_param *param);
int pthread_attr_setschedpolicy(pthread_attr_t *attr, int policy);
int pthread_attr_getschedpolicy(const pthread_attr_t *attr, int *policy);
int pthread_attr_setinheritsched(pthread_attr_t *attr, int inherit);
int pthread_attr_getinheritsched(const pthread_attr_t *attr, int *inherit);
int pthread_attr_setscope(pthread_attr_t *attr, int scope);
int pthread_attr_getscope(const pthread_attr_t *attr, int *scope);
int pthread_attr_setguardsize(pthread_attr_t *attr, size_t guardsize);
int pthread_attr_getguardsize(const pthread_attr_t * attr, size_t *guardsize);
int pthread_attr_setstackaddr(pthread_attr_t *attr, void *stackaddr);
int pthread_attr_getstackaddr(const pthread_attr_t *attr, void **stackaddr);
int pthread_attr_setstack(pthread_attr_t *attr, void *stackaddr,
                          size_t stacksize);
int pthread_attr_getstack(const pthread_attr_t *attr, void **stackaddr,
                          size_t *stacksize);
int pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize);
int pthread_attr_getstacksize(const pthread_attr_t * attr, size_t *stacksize);
int pthread_getattr_np(pthread_t th, pthread_attr_t *attr);

/* Functions for scheduling control.  */
int pthread_setschedparam(pthread_t target_thread, int policy,
                          const struct sched_param *param);
int pthread_getschedparam (pthread_t target_thread, int *policy,
                           struct sched_param *param);
int pthread_getconcurrency(void);
int pthread_setconcurrency(int level);
int pthread_yield(void);

/* Functions for mutex handling.  */
int pthread_mutex_init(pthread_mutex_t *mutex,
                       const pthread_mutexattr_t *mutex_attr);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_timedlock(pthread_mutex_t *mutex,
                            const struct timespec *abstime);
int pthread_mutex_unlock(pthread_mutex_t *mutex);

/* Functions for handling mutex attributes.  */
int pthread_mutexattr_init(pthread_mutexattr_t *attr);
int pthread_mutexattr_destroy(pthread_mutexattr_t *attr);
int pthread_mutexattr_getpshared(const pthread_mutexattr_t *attr,
                                 int *pshared);
int pthread_mutexattr_setpshared(pthread_mutexattr_t *attr, int pshared);
int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int kind);
int pthread_mutexattr_gettype(const pthread_mutexattr_t *attr, int *kind);

/* Functions for handling conditional variables.  */
int pthread_cond_init(pthread_cond_t *cond,
                      const pthread_condattr_t *cond_attr);
int pthread_cond_destroy(pthread_cond_t *cond);
int pthread_cond_signal(pthread_cond_t *cond);
int pthread_cond_broadcast(pthread_cond_t *cond);
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                           const struct timespec *abstime);

/* Functions for handling condition variable attributes.  */
int pthread_condattr_init(pthread_condattr_t *attr);
int pthread_condattr_destroy(pthread_condattr_t *attr);
int pthread_condattr_getpshared(const pthread_condattr_t *attr, int *pshared);
int pthread_condattr_setpshared(pthread_condattr_t *attr, int pshared);

/* Functions for handling read-write locks.  */
int pthread_rwlock_init(pthread_rwlock_t *rwlock,
                        const pthread_rwlockattr_t *attr);
int pthread_rwlock_destroy(pthread_rwlock_t *rwlock);
int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_timedrdlock(pthread_rwlock_t *rwlock,
                               const struct timespec *abstime) ;
int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_timedwrlock(pthread_rwlock_t *rwlock,
                               const struct timespec *abstime);
int pthread_rwlock_unlock(pthread_rwlock_t *rwlock);


/* Functions for handling read-write lock attributes.  */
int pthread_rwlockattr_init(pthread_rwlockattr_t *attr);
int pthread_rwlockattr_destroy(pthread_rwlockattr_t *attr);
int pthread_rwlockattr_getpshared(const pthread_rwlockattr_t *attr,
                                  int *pshared);
int pthread_rwlockattr_setpshared(pthread_rwlockattr_t *attr, int pshared);
int pthread_rwlockattr_getkind_np(const pthread_rwlockattr_t *attr, int *pref);
int pthread_rwlockattr_setkind_np(pthread_rwlockattr_t *attr, int pref);

/* The IEEE Std. 1003.1j-2000 introduces functions to implement
   spinlocks.  */
int pthread_spin_init(pthread_spinlock_t *lock, int pshared);
int pthread_spin_destroy(pthread_spinlock_t *lock);
int pthread_spin_lock(pthread_spinlock_t *lock);
int pthread_spin_trylock(pthread_spinlock_t *lock);
int pthread_spin_unlock (pthread_spinlock_t *lock);

/* Barriers are a also a new feature in 1003.1j-2000. */
int pthread_barrier_init(pthread_barrier_t *barrier,
                         const pthread_barrierattr_t *attr,
                         unsigned int count);
int pthread_barrier_destroy(pthread_barrier_t *barrier);
int pthread_barrierattr_init(pthread_barrierattr_t *attr);
int pthread_barrierattr_destroy(pthread_barrierattr_t *attr);
int pthread_barrierattr_getpshared(const pthread_barrierattr_t *attr,
                                   int *pshared);
int pthread_barrierattr_setpshared(pthread_barrierattr_t *attr, int pshared);
int pthread_barrier_wait(pthread_barrier_t *barrier);

/* Functions for handling thread-specific data.  */
int pthread_key_create(pthread_key_t *key, void (*destr_function)(void *));
int pthread_key_delete(pthread_key_t key);
int pthread_setspecific(pthread_key_t key, const void *pointer);
void *pthread_getspecific(pthread_key_t key);

/* Functions for handling initialization.  */
int pthread_once(pthread_once_t *once_control, void (*init_routine)(void));

/* Functions for handling cancellation.  */
int pthread_setcancelstate(int state, int *oldstate);
int pthread_setcanceltype(int type, int *oldtype);
int pthread_cancel(pthread_t cancelthread);
void pthread_testcancel(void);

#define pthread_cleanup_push(routine,arg) \
  { struct _pthread_cleanup_buffer _buffer;                                   \
    _pthread_cleanup_push (&_buffer, (routine), (arg));
void _pthread_cleanup_push(struct _pthread_cleanup_buffer *buffer,
                           void (*routine)(void *), void *arg);

#define pthread_cleanup_pop(execute) \
    _pthread_cleanup_pop (&_buffer, (execute)); }
void _pthread_cleanup_pop(struct _pthread_cleanup_buffer *buffer, int execute);

#define pthread_cleanup_push_defer_np(routine,arg) \
  { struct _pthread_cleanup_buffer _buffer;                                   \
    _pthread_cleanup_push_defer (&_buffer, (routine), (arg));

void _pthread_cleanup_push_defer(struct _pthread_cleanup_buffer *buffer,
                                 void (*routine)(void *), void *arg);

#define pthread_cleanup_pop_restore_np(execute) \
  _pthread_cleanup_pop_restore (&_buffer, (execute)); }
void _pthread_cleanup_pop_restore(struct _pthread_cleanup_buffer *buffer,
                                  int execute);

int pthread_getcpuclockid(pthread_t thread_id, clockid_t *clock_id);

/* Functions for handling signals.  */
int pthread_sigmask(int how, const sigset_t *newmask, sigset_t *oldmask);
int pthread_kill(pthread_t threadid, int signo);

/* Functions for handling process creation and process execution.  */
int pthread_atfork(void (*prepare)(void),
                   void (*parent)(void),
                   void (*child)(void));
void pthread_kill_other_threads_np(void);

#endif  /* __RCC_PTHREAD_H__ */

/*
 * Local variables:
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "_pthread_descr")
 * End:
 */
