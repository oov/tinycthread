/* -*- mode: c; tab-width: 2; indent-tabs-mode: nil; -*-
Copyright (c) 2012 Marcus Geelnard
Copyright (c) 2013-2016 Evan Nemerson

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

    1. The origin of this software must not be misrepresented; you must not
    claim that you wrote the original software. If you use this software
    in a product, an acknowledgment in the product documentation would be
    appreciated but is not required.

    2. Altered source versions must be plainly marked as such, and must not be
    misrepresented as being the original software.

    3. This notice may not be removed or altered from any source
    distribution.
*/

/* Activate some POSIX or GNU functionality (e.g. clock_gettime and recursive mutexes) */
#if !defined(_WIN32) && !defined(__WIN32__) && !defined(__WINDOWS__)
  #undef _FEATURES_H
  #if !defined(_GNU_SOURCE)
    #define _GNU_SOURCE
  #endif
  #if !defined(_POSIX_C_SOURCE) || ((_POSIX_C_SOURCE - 0) < 199309L)
    #undef _POSIX_C_SOURCE
    #define _POSIX_C_SOURCE 199309L
  #endif
  #if !defined(_XOPEN_SOURCE) || ((_XOPEN_SOURCE - 0) < 500)
    #undef _XOPEN_SOURCE
    #define _XOPEN_SOURCE 500
  #endif
  #define _XPG6
#endif

#include "tinycthread.h"
#include <stdbool.h>
#include <stdlib.h>

/* Platform specific includes */
#if defined(_TTHREAD_POSIX_)
  #include <pthread.h>
  #include <signal.h>
  #include <sched.h>
  #include <unistd.h>
  #include <sys/time.h>
  #include <errno.h>
#elif defined(_TTHREAD_WIN32_)
  #include <windows.h>
  #include <process.h>
  #include <sys/timeb.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Compiler-specific cmpxchg builtin */
#ifdef __GNUC__
static int cmpxchg(volatile int *address, int old_val, int new_val)
{
  return __sync_val_compare_and_swap(address, old_val, new_val);
}
#elif defined(MSVC)
static int cmpxchg(volatile int *address, int old_val, int new_val)
{
  return InterlockedCompareExchange(address, new_val, old_val);
}
#else
#error
#endif

/* Platform spacific underlying types, values */
#if defined(_TTHREAD_WIN32_)

typedef struct {
  union {
    CRITICAL_SECTION cs;      /* Critical section handle (used for non-timed mutexes) */
    HANDLE mut;               /* Mutex handle (used for timed mutex) */
  } mHandle;                  /* Mutex handle */
  bool mAlreadyLocked;         /* true if the mutex is already locked */
  bool mRecursive;             /* true if the mutex is recursive */
  bool mTimed;                 /* true if the mutex is timed */
} system_mtx_t;

typedef struct {
  HANDLE mEvents[2];                  /* Signal and broadcast event HANDLEs. */
  unsigned int mWaitersCount;         /* Count of the number of waiters. */
  CRITICAL_SECTION mWaitersCountLock; /* Serialize access to mWaitersCount. */
} system_cnd_t;

typedef HANDLE system_thrd_t;
typedef DWORD system_tss_t;

#define TSS_DTOR_ITERATIONS (4)

#else

typedef pthread_mutex_t system_mtx_t;
typedef pthread_cond_t system_cnd_t;
typedef pthread_t system_thrd_t;
typedef pthread_key_t system_tss_t;

#define TSS_DTOR_ITERATIONS PTHREAD_DESTRUCTOR_ITERATIONS

#endif

int mtx_init(mtx_t *opaque_mtx, int type)
{
  system_mtx_t *mtx = (system_mtx_t*)opaque_mtx;
#if defined(_TTHREAD_WIN32_)
  mtx->mAlreadyLocked = false;
  mtx->mRecursive = type & mtx_recursive;
  mtx->mTimed = type & mtx_timed;
  if (!mtx->mTimed)
  {
    InitializeCriticalSection(&(mtx->mHandle.cs));
  }
  else
  {
    mtx->mHandle.mut = CreateMutex(NULL, false, NULL);
    if (mtx->mHandle.mut == NULL)
    {
      return thrd_error;
    }
  }
  return thrd_success;
#else
  int ret;
  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  if (type & mtx_recursive)
  {
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  }
  ret = pthread_mutex_init(mtx, &attr);
  pthread_mutexattr_destroy(&attr);
  return ret == 0 ? thrd_success : thrd_error;
#endif
}

void mtx_destroy(mtx_t *opaque_mtx)
{
  system_mtx_t *mtx = (system_mtx_t*)opaque_mtx;
#if defined(_TTHREAD_WIN32_)
  if (!mtx->mTimed)
  {
    DeleteCriticalSection(&(mtx->mHandle.cs));
  }
  else
  {
    CloseHandle(mtx->mHandle.mut);
  }
#else
  pthread_mutex_destroy(mtx);
#endif
}

int mtx_lock(mtx_t *opaque_mtx)
{
  system_mtx_t *mtx = (system_mtx_t*)opaque_mtx;
#if defined(_TTHREAD_WIN32_)
  if (!mtx->mTimed)
  {
    EnterCriticalSection(&(mtx->mHandle.cs));
  }
  else
  {
    switch (WaitForSingleObject(mtx->mHandle.mut, INFINITE))
    {
      case WAIT_OBJECT_0:
        break;
      case WAIT_ABANDONED:
      default:
        return thrd_error;
    }
  }

  if (!mtx->mRecursive)
  {
    while(mtx->mAlreadyLocked) Sleep(1); /* Simulate deadlock... */
    mtx->mAlreadyLocked = true;
  }
  return thrd_success;
#else
  return pthread_mutex_lock(mtx) == 0 ? thrd_success : thrd_error;
#endif
}

int mtx_timedlock(mtx_t *opaque_mtx, const struct timespec *ts)
{
  system_mtx_t *mtx = (system_mtx_t*)opaque_mtx;
#if defined(_TTHREAD_WIN32_)
  struct timespec current_ts;
  DWORD timeoutMs;

  if (!mtx->mTimed)
  {
    return thrd_error;
  }

  timespec_get(&current_ts, TIME_UTC);

  if ((current_ts.tv_sec > ts->tv_sec) || ((current_ts.tv_sec == ts->tv_sec) && (current_ts.tv_nsec >= ts->tv_nsec)))
  {
    timeoutMs = 0;
  }
  else
  {
    timeoutMs  = (DWORD)(ts->tv_sec  - current_ts.tv_sec)  * 1000;
    timeoutMs += (ts->tv_nsec - current_ts.tv_nsec) / 1000000;
    timeoutMs += 1;
  }

  /* TODO: the timeout for WaitForSingleObject doesn't include time
     while the computer is asleep. */
  switch (WaitForSingleObject(mtx->mHandle.mut, timeoutMs))
  {
    case WAIT_OBJECT_0:
      break;
    case WAIT_TIMEOUT:
      return thrd_timedout;
    case WAIT_ABANDONED:
    default:
      return thrd_error;
  }

  if (!mtx->mRecursive)
  {
    while(mtx->mAlreadyLocked) Sleep(1); /* Simulate deadlock... */
    mtx->mAlreadyLocked = true;
  }

  return thrd_success;
#elif defined(_POSIX_TIMEOUTS) && (_POSIX_TIMEOUTS >= 200112L) && defined(_POSIX_THREADS) && (_POSIX_THREADS >= 200112L)
  switch (pthread_mutex_timedlock(mtx, ts)) {
    case 0:
      return thrd_success;
    case ETIMEDOUT:
      return thrd_timedout;
    default:
      return thrd_error;
  }
#else
  int rc;
  struct timespec cur, dur;

  /* Try to acquire the lock and, if we fail, sleep for 5ms. */
  while ((rc = pthread_mutex_trylock (mtx)) == EBUSY) {
    timespec_get(&cur, TIME_UTC);

    if ((cur.tv_sec > ts->tv_sec) || ((cur.tv_sec == ts->tv_sec) && (cur.tv_nsec >= ts->tv_nsec)))
    {
      break;
    }

    dur.tv_sec = ts->tv_sec - cur.tv_sec;
    dur.tv_nsec = ts->tv_nsec - cur.tv_nsec;
    if (dur.tv_nsec < 0)
    {
      dur.tv_sec--;
      dur.tv_nsec += 1000000000;
    }

    if ((dur.tv_sec != 0) || (dur.tv_nsec > 5000000))
    {
      dur.tv_sec = 0;
      dur.tv_nsec = 5000000;
    }

    nanosleep(&dur, NULL);
  }

  switch (rc) {
    case 0:
      return thrd_success;
    case ETIMEDOUT:
    case EBUSY:
      return thrd_timedout;
    default:
      return thrd_error;
  }
#endif
}

int mtx_trylock(mtx_t *opaque_mtx)
{
  system_mtx_t *mtx = (system_mtx_t*)opaque_mtx;
#if defined(_TTHREAD_WIN32_)
  int ret;

  if (!mtx->mTimed)
  {
    ret = TryEnterCriticalSection(&(mtx->mHandle.cs)) ? thrd_success : thrd_busy;
  }
  else
  {
    ret = (WaitForSingleObject(mtx->mHandle.mut, 0) == WAIT_OBJECT_0) ? thrd_success : thrd_busy;
  }

  if ((!mtx->mRecursive) && (ret == thrd_success))
  {
    if (mtx->mAlreadyLocked)
    {
      LeaveCriticalSection(&(mtx->mHandle.cs));
      ret = thrd_busy;
    }
    else
    {
      mtx->mAlreadyLocked = true;
    }
  }
  return ret;
#else
  return (pthread_mutex_trylock(mtx) == 0) ? thrd_success : thrd_busy;
#endif
}

int mtx_unlock(mtx_t *opaque_mtx)
{
  system_mtx_t *mtx = (system_mtx_t*)opaque_mtx;
#if defined(_TTHREAD_WIN32_)
  mtx->mAlreadyLocked = false;
  if (!mtx->mTimed)
  {
    LeaveCriticalSection(&(mtx->mHandle.cs));
  }
  else
  {
    if (!ReleaseMutex(mtx->mHandle.mut))
    {
      return thrd_error;
    }
  }
  return thrd_success;
#else
  return pthread_mutex_unlock(mtx) == 0 ? thrd_success : thrd_error;;
#endif
}

#if defined(_TTHREAD_WIN32_)
#define _CONDITION_EVENT_ONE 0
#define _CONDITION_EVENT_ALL 1
#endif

int cnd_init(cnd_t *opaque_cond)
{
  system_cnd_t *cond = (system_cnd_t*)opaque_cond;
#if defined(_TTHREAD_WIN32_)
  cond->mWaitersCount = 0;

  /* Init critical section */
  InitializeCriticalSection(&cond->mWaitersCountLock);

  /* Init events */
  cond->mEvents[_CONDITION_EVENT_ONE] = CreateEvent(NULL, false, false, NULL);
  if (cond->mEvents[_CONDITION_EVENT_ONE] == NULL)
  {
    cond->mEvents[_CONDITION_EVENT_ALL] = NULL;
    return thrd_error;
  }
  cond->mEvents[_CONDITION_EVENT_ALL] = CreateEvent(NULL, true, false, NULL);
  if (cond->mEvents[_CONDITION_EVENT_ALL] == NULL)
  {
    CloseHandle(cond->mEvents[_CONDITION_EVENT_ONE]);
    cond->mEvents[_CONDITION_EVENT_ONE] = NULL;
    return thrd_error;
  }

  return thrd_success;
#else
  return pthread_cond_init(cond, NULL) == 0 ? thrd_success : thrd_error;
#endif
}

void cnd_destroy(cnd_t *opaque_cond)
{
  system_cnd_t *cond = (system_cnd_t*)opaque_cond;
#if defined(_TTHREAD_WIN32_)
  if (cond->mEvents[_CONDITION_EVENT_ONE] != NULL)
  {
    CloseHandle(cond->mEvents[_CONDITION_EVENT_ONE]);
  }
  if (cond->mEvents[_CONDITION_EVENT_ALL] != NULL)
  {
    CloseHandle(cond->mEvents[_CONDITION_EVENT_ALL]);
  }
  DeleteCriticalSection(&cond->mWaitersCountLock);
#else
  pthread_cond_destroy(cond);
#endif
}

int cnd_signal(cnd_t *opaque_cond)
{
  system_cnd_t *cond = (system_cnd_t*)opaque_cond;
#if defined(_TTHREAD_WIN32_)
  int haveWaiters;

  /* Are there any waiters? */
  EnterCriticalSection(&cond->mWaitersCountLock);
  haveWaiters = (cond->mWaitersCount > 0);
  LeaveCriticalSection(&cond->mWaitersCountLock);

  /* If we have any waiting threads, send them a signal */
  if(haveWaiters)
  {
    if (SetEvent(cond->mEvents[_CONDITION_EVENT_ONE]) == 0)
    {
      return thrd_error;
    }
  }

  return thrd_success;
#else
  return pthread_cond_signal(cond) == 0 ? thrd_success : thrd_error;
#endif
}

int cnd_broadcast(cnd_t *opaque_cond)
{
  system_cnd_t *cond = (system_cnd_t*)opaque_cond;
#if defined(_TTHREAD_WIN32_)
  int haveWaiters;

  /* Are there any waiters? */
  EnterCriticalSection(&cond->mWaitersCountLock);
  haveWaiters = (cond->mWaitersCount > 0);
  LeaveCriticalSection(&cond->mWaitersCountLock);

  /* If we have any waiting threads, send them a signal */
  if(haveWaiters)
  {
    if (SetEvent(cond->mEvents[_CONDITION_EVENT_ALL]) == 0)
    {
      return thrd_error;
    }
  }

  return thrd_success;
#else
  return pthread_cond_broadcast(cond) == 0 ? thrd_success : thrd_error;
#endif
}

#if defined(_TTHREAD_WIN32_)
static int _cnd_timedwait_win32(cnd_t *opaque_cond, mtx_t *mtx, DWORD timeout)
{
  system_cnd_t *cond = (system_cnd_t*)opaque_cond;
  DWORD result;
  int lastWaiter;

  /* Increment number of waiters */
  EnterCriticalSection(&cond->mWaitersCountLock);
  ++ cond->mWaitersCount;
  LeaveCriticalSection(&cond->mWaitersCountLock);

  /* Release the mutex while waiting for the condition (will decrease
     the number of waiters when done)... */
  mtx_unlock(mtx);

  /* Wait for either event to become signaled due to cnd_signal() or
     cnd_broadcast() being called */
  result = WaitForMultipleObjects(2, cond->mEvents, false, timeout);
  if (result == WAIT_TIMEOUT)
  {
    /* The mutex is locked again before the function returns, even if an error occurred */
    mtx_lock(mtx);
    return thrd_timedout;
  }
  else if (result == WAIT_FAILED)
  {
    /* The mutex is locked again before the function returns, even if an error occurred */
    mtx_lock(mtx);
    return thrd_error;
  }

  /* Check if we are the last waiter */
  EnterCriticalSection(&cond->mWaitersCountLock);
  -- cond->mWaitersCount;
  lastWaiter = (result == (WAIT_OBJECT_0 + _CONDITION_EVENT_ALL)) &&
               (cond->mWaitersCount == 0);
  LeaveCriticalSection(&cond->mWaitersCountLock);

  /* If we are the last waiter to be notified to stop waiting, reset the event */
  if (lastWaiter)
  {
    if (ResetEvent(cond->mEvents[_CONDITION_EVENT_ALL]) == 0)
    {
      /* The mutex is locked again before the function returns, even if an error occurred */
      mtx_lock(mtx);
      return thrd_error;
    }
  }

  /* Re-acquire the mutex */
  mtx_lock(mtx);

  return thrd_success;
}
#endif

int cnd_wait(cnd_t *opaque_cond, mtx_t *opaque_mtx)
{
#if defined(_TTHREAD_WIN32_)
  return _cnd_timedwait_win32(opaque_cond, opaque_mtx, INFINITE);
#else
  system_mtx_t *mtx = (system_mtx_t*)opaque_mtx;
  system_cnd_t *cond = (system_cnd_t*)opaque_cond;
  return pthread_cond_wait(cond, mtx) == 0 ? thrd_success : thrd_error;
#endif
}

int cnd_timedwait(cnd_t *opaque_cond, mtx_t *opaque_mtx, const struct timespec *ts)
{
#if defined(_TTHREAD_WIN32_)
  struct timespec now;
  if (timespec_get(&now, TIME_UTC) == TIME_UTC)
  {
    unsigned long long nowInMilliseconds = now.tv_sec * 1000 + now.tv_nsec / 1000000;
    unsigned long long tsInMilliseconds  = ts->tv_sec * 1000 + ts->tv_nsec / 1000000;
    DWORD delta = (tsInMilliseconds > nowInMilliseconds) ?
      (DWORD)(tsInMilliseconds - nowInMilliseconds) : 0;
    return _cnd_timedwait_win32(opaque_cond, opaque_mtx, delta);
  }
  else
    return thrd_error;
#else
  system_mtx_t *mtx = (system_mtx_t*)opaque_mtx;
  system_cnd_t *cond = (system_cnd_t*)opaque_cond;
  int ret;
  ret = pthread_cond_timedwait(cond, mtx, ts);
  if (ret == ETIMEDOUT)
  {
    return thrd_timedout;
  }
  return ret == 0 ? thrd_success : thrd_error;
#endif
}

#if defined(_TTHREAD_WIN32_)
struct TinyCThreadTSSData {
  void* value;
  system_tss_t key;
  struct TinyCThreadTSSData* next;
};

static tss_dtor_t _tinycthread_tss_dtors[1088] = { NULL, };

static _Thread_local struct TinyCThreadTSSData* _tinycthread_tss_head = NULL;
static _Thread_local struct TinyCThreadTSSData* _tinycthread_tss_tail = NULL;

static void _tinycthread_tss_cleanup (void);

static void _tinycthread_tss_cleanup (void) {
  struct TinyCThreadTSSData* data;
  int iteration;
  unsigned int again = 1;
  void* value;

  for (iteration = 0 ; iteration < TSS_DTOR_ITERATIONS && again > 0 ; iteration++)
  {
    again = 0;
    for (data = _tinycthread_tss_head ; data != NULL ; data = data->next)
    {
      if (data->value != NULL)
      {
        value = data->value;
        data->value = NULL;

        if (_tinycthread_tss_dtors[data->key] != NULL)
        {
          again = 1;
          _tinycthread_tss_dtors[data->key](value);
        }
      }
    }
  }

  while (_tinycthread_tss_head != NULL) {
    data = _tinycthread_tss_head->next;
    free (_tinycthread_tss_head);
    _tinycthread_tss_head = data;
  }
  _tinycthread_tss_head = NULL;
  _tinycthread_tss_tail = NULL;
}

static void NTAPI _tinycthread_tss_callback(PVOID h, DWORD dwReason, PVOID pv)
{
  (void)h;
  (void)pv;

  if (_tinycthread_tss_head != NULL && (dwReason == DLL_THREAD_DETACH || dwReason == DLL_PROCESS_DETACH))
  {
    _tinycthread_tss_cleanup();
  }
}

#if defined(_MSC_VER)
  #ifdef _M_X64
    #pragma const_seg(".CRT$XLB")
  #else
    #pragma data_seg(".CRT$XLB")
  #endif
  PIMAGE_TLS_CALLBACK p_thread_callback = _tinycthread_tss_callback;
  #ifdef _M_X64
    #pragma data_seg()
  #else
    #pragma const_seg()
  #endif
#else
  PIMAGE_TLS_CALLBACK p_thread_callback __attribute__((section(".CRT$XLB"))) = _tinycthread_tss_callback;
#endif

#endif /* defined(_TTHREAD_WIN32_) */

/** Information to pass to the new thread (what to run). */
typedef struct {
  thrd_start_t mFunction; /**< Pointer to the function to be executed. */
  void * mArg;            /**< Function argument for the thread function. */
} _thread_start_info;

/* Thread wrapper function. */
#if defined(_TTHREAD_WIN32_)
static DWORD WINAPI _thrd_wrapper_function(LPVOID aArg)
#elif defined(_TTHREAD_POSIX_)
static void * _thrd_wrapper_function(void * aArg)
#endif
{
  thrd_start_t fun;
  void *arg;
  int  res;

  /* Get thread startup information */
  _thread_start_info *ti = (_thread_start_info *) aArg;
  fun = ti->mFunction;
  arg = ti->mArg;

  /* The thread is responsible for freeing the startup information */
  free((void *)ti);

  /* Call the actual client thread function */
  res = fun(arg);

#if defined(_TTHREAD_WIN32_)
  if (_tinycthread_tss_head != NULL)
  {
    _tinycthread_tss_cleanup();
  }

  return (DWORD)res;
#else
  return (void*)(intptr_t)res;
#endif
}

int thrd_create(thrd_t *opaque_thr, thrd_start_t func, void *arg)
{
  system_thrd_t *thr = (system_thrd_t*)opaque_thr;
  /* Fill out the thread startup information (passed to the thread wrapper,
     which will eventually free it) */
  _thread_start_info* ti = (_thread_start_info*)malloc(sizeof(_thread_start_info));
  if (ti == NULL)
  {
    return thrd_nomem;
  }
  ti->mFunction = func;
  ti->mArg = arg;

  /* Create the thread */
#if defined(_TTHREAD_WIN32_)
  *thr = CreateThread(NULL, 0, _thrd_wrapper_function, (LPVOID) ti, 0, NULL);
#elif defined(_TTHREAD_POSIX_)
  if(pthread_create(thr, NULL, _thrd_wrapper_function, (void *)ti) != 0)
  {
    *thr = 0;
  }
#endif

  /* Did we fail to create the thread? */
  if(!*thr)
  {
    free(ti);
    return thrd_error;
  }

  return thrd_success;
}

thrd_t thrd_current(void)
{
  system_thrd_t t;
#if defined(_TTHREAD_WIN32_)
  t = GetCurrentThread();
#else
  t = pthread_self();
#endif
  return *((thrd_t*)&t);
}

int thrd_detach(thrd_t opaque_thr)
{
  system_thrd_t *thr = (system_thrd_t*)&opaque_thr;
#if defined(_TTHREAD_WIN32_)
  /* https://stackoverflow.com/questions/12744324/how-to-detach-a-thread-on-windows-c#answer-12746081 */
  return CloseHandle(*thr) != 0 ? thrd_success : thrd_error;
#else
  return pthread_detach(*thr) == 0 ? thrd_success : thrd_error;
#endif
}

int thrd_equal(thrd_t opaque_thr0, thrd_t opaque_thr1)
{
  system_thrd_t *thr0 = (system_thrd_t*)&opaque_thr0;
  system_thrd_t *thr1 = (system_thrd_t*)&opaque_thr1;
#if defined(_TTHREAD_WIN32_)
  return GetThreadId(*thr0) == GetThreadId(*thr1);
#else
  return pthread_equal(*thr0, *thr1);
#endif
}

void thrd_exit(int res)
{
#if defined(_TTHREAD_WIN32_)
  if (_tinycthread_tss_head != NULL)
  {
    _tinycthread_tss_cleanup();
  }

  ExitThread((DWORD)res);
#else
  pthread_exit((void*)(intptr_t)res);
#endif
}

int thrd_join(thrd_t opaque_thr, int *res)
{
  system_thrd_t thr = *((system_thrd_t*)&opaque_thr);
#if defined(_TTHREAD_WIN32_)
  DWORD dwRes;

  if (WaitForSingleObject(thr, INFINITE) == WAIT_FAILED)
  {
    return thrd_error;
  }
  if (res != NULL)
  {
    if (GetExitCodeThread(thr, &dwRes) != 0)
    {
      *res = (int) dwRes;
    }
    else
    {
      return thrd_error;
    }
  }
  CloseHandle(thr);
#elif defined(_TTHREAD_POSIX_)
  void *pres;
  if (pthread_join(thr, &pres) != 0)
  {
    return thrd_error;
  }
  if (res != NULL)
  {
    *res = (int)(intptr_t)pres;
  }
#endif
  return thrd_success;
}

int thrd_sleep(const struct timespec *duration, struct timespec *remaining)
{
#if !defined(_TTHREAD_WIN32_)
  int res = nanosleep(duration, remaining);
  if (res == 0) {
    return 0;
  } else if (errno == EINTR) {
    return -1;
  } else {
    return -2;
  }
#else
  struct timespec start;
  DWORD t;

  timespec_get(&start, TIME_UTC);

  t = SleepEx((DWORD)(duration->tv_sec * 1000 +
              duration->tv_nsec / 1000000 +
              (((duration->tv_nsec % 1000000) == 0) ? 0 : 1)),
              true);

  if (t == 0) {
    return 0;
  } else {
    if (remaining != NULL) {
      timespec_get(remaining, TIME_UTC);
      remaining->tv_sec -= start.tv_sec;
      remaining->tv_nsec -= start.tv_nsec;
      if (remaining->tv_nsec < 0)
      {
        remaining->tv_nsec += 1000000000;
        remaining->tv_sec -= 1;
      }
    }

    return (t == WAIT_IO_COMPLETION) ? -1 : -2;
  }
#endif
}

void thrd_yield(void)
{
#if defined(_TTHREAD_WIN32_)
  Sleep(0);
#else
  sched_yield();
#endif
}

int tss_create(tss_t *opaque_key, tss_dtor_t dtor)
{
  system_tss_t *key = (system_tss_t*)opaque_key;
#if defined(_TTHREAD_WIN32_)
  *key = TlsAlloc();
  if (*key == TLS_OUT_OF_INDEXES)
  {
    return thrd_error;
  }
  _tinycthread_tss_dtors[*key] = dtor;
#else
  if (pthread_key_create(key, dtor) != 0)
  {
    return thrd_error;
  }
#endif
  return thrd_success;
}

void tss_delete(tss_t opaque_key)
{
  system_tss_t key = *((system_tss_t*)&opaque_key);
#if defined(_TTHREAD_WIN32_)
  struct TinyCThreadTSSData* data = (struct TinyCThreadTSSData*) TlsGetValue (key);
  struct TinyCThreadTSSData* prev = NULL;
  if (data != NULL)
  {
    if (data == _tinycthread_tss_head)
    {
      _tinycthread_tss_head = data->next;
    }
    else
    {
      prev = _tinycthread_tss_head;
      if (prev != NULL)
      {
        while (prev->next != data)
        {
          prev = prev->next;
        }
      }
    }

    if (data == _tinycthread_tss_tail)
    {
      _tinycthread_tss_tail = prev;
    }

    free (data);
  }
  _tinycthread_tss_dtors[key] = NULL;
  TlsFree(key);
#else
  pthread_key_delete(key);
#endif
}

void *tss_get(tss_t opaque_key)
{
  system_tss_t key = *((system_tss_t*)&opaque_key);
#if defined(_TTHREAD_WIN32_)
  struct TinyCThreadTSSData* data = (struct TinyCThreadTSSData*)TlsGetValue(key);
  if (data == NULL)
  {
    return NULL;
  }
  return data->value;
#else
  return pthread_getspecific(key);
#endif
}

int tss_set(tss_t opaque_key, void *val)
{
  system_tss_t key = *((system_tss_t*)&opaque_key);
#if defined(_TTHREAD_WIN32_)
  struct TinyCThreadTSSData* data = (struct TinyCThreadTSSData*)TlsGetValue(key);
  if (data == NULL)
  {
    data = (struct TinyCThreadTSSData*)malloc(sizeof(struct TinyCThreadTSSData));
    if (data == NULL)
    {
      return thrd_error;
	}

    data->value = NULL;
    data->key = key;
    data->next = NULL;

    if (_tinycthread_tss_tail != NULL)
    {
      _tinycthread_tss_tail->next = data;
    }
    else
    {
      _tinycthread_tss_tail = data;
    }

    if (_tinycthread_tss_head == NULL)
    {
      _tinycthread_tss_head = data;
    }

    if (!TlsSetValue(key, data))
    {
      free (data);
	  return thrd_error;
    }
  }
  data->value = val;
#else
  if (pthread_setspecific(key, val) != 0)
  {
    return thrd_error;
  }
#endif
  return thrd_success;
}

#if defined(_TTHREAD_EMULATE_TIMESPEC_GET_)
int timespec_get(struct timespec *ts, int base)
{
#if defined(_TTHREAD_WIN32_)
  struct _timeb tb;
#elif !defined(CLOCK_REALTIME)
  struct timeval tv;
#endif

  if (base != TIME_UTC)
  {
    return 0;
  }

#if defined(_TTHREAD_WIN32_)
  _ftime_s(&tb);
  ts->tv_sec = (time_t)tb.time;
  ts->tv_nsec = 1000000L * (long)tb.millitm;
#elif defined(CLOCK_REALTIME)
  base = (clock_gettime(CLOCK_REALTIME, ts) == 0) ? base : 0;
#else
  gettimeofday(&tv, NULL);
  ts->tv_sec = (time_t)tv.tv_sec;
  ts->tv_nsec = 1000L * (long)tv.tv_usec;
#endif

  return base;
}
#endif /* _TTHREAD_EMULATE_TIMESPEC_GET_ */

void call_once(once_flag *flag, void (*func)(void))
{
  /* The idea here is that we use a spin lock (via the cmpxchg
     function) to restrict access to the critical section until
     we have initialized it, then we use the critical section to
     block until the callback has completed execution. */
  while (flag->_status < 3)
  {
    switch (flag->_status)
    {
      case 0:
        if (cmpxchg(&(flag->_status), 0, 1) == 0) {
          mtx_init(&(flag->_lock), mtx_plain);
	  mtx_lock(&(flag->_lock));
          flag->_status = 2;
          func();
          flag->_status = 3;
	  mtx_unlock(&(flag->_lock));
	  return;
        }
        break;
      case 1:
        break;
      case 2:
        mtx_lock(&(flag->_lock));
        mtx_unlock(&(flag->_lock));
        break;
    }
  }
}

#ifdef __cplusplus
}
#endif
