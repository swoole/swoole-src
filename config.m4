dnl $Id$
dnl config.m4 for extension swoole

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

dnl Otherwise use enable:

PHP_ARG_ENABLE(swoole-debug, whether to enable swoole debug,
[  --enable-swoole-debug     Enable swoole debug], no, no)

PHP_ARG_ENABLE(msgqueue, set ipc mode,
[  --enable-msgqueue         Use message queue], no, no)

PHP_ARG_ENABLE(async-mysql, enable async-mysql,
[  --enable-async-mysql      Enable async mysql], no, no)

PHP_ARG_WITH(swoole, swoole support,
[  --with-swoole             Include swoole support])

AC_DEFUN([AC_SWOOLE_KQUEUE],
[
	AC_MSG_CHECKING([for kqueue])

	AC_TRY_COMPILE(
	[ 
		#include <sys/types.h>
		#include <sys/event.h>
		#include <sys/time.h>
	], [
		int kfd;
		struct kevent k;
		kfd = kqueue();
		/* 0 -> STDIN_FILENO */
		EV_SET(&k, 0, EVFILT_READ , EV_ADD | EV_CLEAR, 0, 0, NULL);
	], [
		AC_DEFINE([HAVE_KQUEUE], 1, [do we have kqueue?])
		AC_MSG_RESULT([yes])
	], [
		AC_MSG_RESULT([no])
	])
])

AC_DEFUN([AC_SWOOLE_CPU_AFFINITY],
[
    AC_MSG_CHECKING([for cpu affinity])
    AC_TRY_COMPILE(
    [
		#include <sched.h>
    ], [
		cpu_set_t cpu_set;
		CPU_ZERO(&cpu_set);
    ], [
        AC_DEFINE([HAVE_CPU_AFFINITY], 1, [cpu affinity?])
        AC_MSG_RESULT([yes])
    ], [
        AC_MSG_RESULT([no])
    ])
])

AC_DEFUN([AC_SWOOLE_TIMERFD],
[
	AC_MSG_CHECKING([for timerfd])

	AC_TRY_COMPILE(
	[ 
	    #include <sys/time.h>
		#include <sys/timerfd.h>
	], [
        timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK | TFD_CLOEXEC);
	], [
		AC_DEFINE([HAVE_TIMERFD], 1, [do we have timerfd?])
		AC_MSG_RESULT([yes])
	], [
		AC_MSG_RESULT([no])
	])
])

AC_DEFUN([AC_SWOOLE_EPOLL],
[
	AC_MSG_CHECKING([for epoll])

	AC_TRY_COMPILE(
	[ 
		#include <sys/epoll.h>
	], [
		int epollfd;
		struct epoll_event e;

		epollfd = epoll_create(1);
		if (epollfd < 0) {
			return 1;
		}

		e.events = EPOLLIN | EPOLLET;
		e.data.fd = 0;

		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, 0, &e) == -1) {
			return 1;
		}

		e.events = 0;
		if (epoll_wait(epollfd, &e, 1, 1) < 0) {
			return 1;
		}
	], [
		AC_DEFINE([HAVE_EPOLL], 1, [do we have epoll?])
		AC_MSG_RESULT([yes])
	], [
		AC_MSG_RESULT([no])
	])
])

AC_DEFUN([AC_SWOOLE_EVENTFD],
[
	AC_MSG_CHECKING([for eventfd])

	AC_TRY_COMPILE(
	[ 
		#include <sys/eventfd.h>
	], [
		int efd;

		efd = eventfd(0, 0);
		if (efd < 0) {
			return 1;
		}
	], [
		AC_DEFINE([HAVE_EVENTFD], 1, [do we have eventfd?])
		AC_MSG_RESULT([yes])
	], [
		AC_MSG_RESULT([no])
	])
])

if test "$PHP_SWOOLE" != "no"; then
    PHP_ADD_INCLUDE($SWOOLE_DIR/include)
    PHP_SUBST(SWOOLE_SHARED_LIBADD)

    AC_ARG_ENABLE(debug, 
        [--enable-debug,  compile with debug symbols],
        [PHP_DEBUG=$enableval],
        [PHP_DEBUG=0]
    )
  
    if test "$PHP_SWOOLE_DEBUG" != "no"; then
        AC_DEFINE(SW_DEBUG, 1, [do we enable swoole debug])
    fi
    
    if test "$PHP_MSGQUEUE" != "no"; then
        AC_DEFINE(SW_WORKER_IPC_MODE, 2, [use message queue])
    else
        AC_DEFINE(SW_WORKER_IPC_MODE, 1, [use unix socket])
    fi
    
    if test "$PHP_ASYNC_MYSQL" != "no"; then
        AC_DEFINE(SW_ASYNC_MYSQL, 1, [enable async mysql])
    fi
    
    AC_SWOOLE_EVENTFD
    AC_SWOOLE_EPOLL
    AC_SWOOLE_KQUEUE
    AC_SWOOLE_TIMERFD
    AC_SWOOLE_CPU_AFFINITY
  
    AC_CHECK_LIB(pthread, accept4, AC_DEFINE(SW_USE_ACCEPT4, 1, [have accept4]))
    AC_CHECK_LIB(pthread, pthread_spin_lock, AC_DEFINE(HAVE_SPINLOCK, 1, [have pthread_spin_lock]))
    AC_CHECK_LIB(rt, clock_gettime, AC_DEFINE(HAVE_CLOCK_GETTIME, 1, [have clock_gettime]))

    dnl PHP_ADD_LIBRARY(rt, 1, SWOOLE_SHARED_LIBADD)
    PHP_ADD_LIBRARY(pthread, 1, SWOOLE_SHARED_LIBADD)

    PHP_NEW_EXTENSION(swoole, swoole.c swoole_lock.c swoole_client.c\
        src/core/Base.c \
        src/core/log.c \
        src/core/hashmap.c \
        src/core/RingQueue.c \
        src/core/Channel.c \
        src/core/timer.c \
        src/memory/ShareMemory.c \
        src/memory/MemoryPool.c \
        src/factory/Factory.c \
        src/factory/FactoryThread.c \
        src/factory/FactoryProcess.c \
        src/reactor/ReactorBase.c \
        src/reactor/ReactorSelect.c \
        src/reactor/ReactorPoll.c \
        src/reactor/ReactorEpoll.c \
        src/reactor/ReactorKqueue.c \
        src/pipe/PipeBase.c \
        src/pipe/PipeEventfd.c \
        src/pipe/PipeUnsock.c \
        src/queue/Msg.c \
        src/lock/Semaphore.c \
        src/lock/Mutex.c \
        src/lock/RWLock.c \
        src/lock/SpinLock.c \
        src/lock/FileLock.c \
        src/network/Server.c \
        src/network/Client.c \
        src/network/buffer.c \
        src/network/ProcessPool.c \
      , $ext_shared)
      
    PHP_ADD_INCLUDE([$ext_srcdir/include])
    PHP_ADD_BUILD_DIR($ext_builddir/src/core)
    PHP_ADD_BUILD_DIR($ext_builddir/src/memory)
    PHP_ADD_BUILD_DIR($ext_builddir/src/factory)
    PHP_ADD_BUILD_DIR($ext_builddir/src/reactor)
    PHP_ADD_BUILD_DIR($ext_builddir/src/pipe)
    PHP_ADD_BUILD_DIR($ext_builddir/src/queue)
    PHP_ADD_BUILD_DIR($ext_builddir/src/lock)
    PHP_ADD_BUILD_DIR($ext_builddir/src/network)
fi

