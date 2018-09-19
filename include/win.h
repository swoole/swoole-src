/*
   +----------------------------------------------------------------------+
   | PHP Version 7                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2018 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
 */
#ifndef SW_WINDOWS_H
#define SW_WINDOWS_H

#include <Winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <windows.h>

typedef CRITICAL_SECTION pthread_mutex_t;
typedef CONDITION_VARIABLE pthread_cond_t;
typedef HANDLE pthread_t;
typedef int pthread_mutexattr_t;
typedef size_t off_t;
typedef intptr_t ssize_t;
typedef DWORD pid_t;
typedef intptr_t key_t;

#ifndef LOCALE_INVARIANT
# define LOCALE_INVARIANT 0x007f
#endif

#define bzero(p, s)            memset(p, 0, s)
#define getpid()               GetCurrentProcessId()
#define sched_yield()          SwitchToThread()

#define __thread
#define EHOSTDOWN               WSAEHOSTDOWN

#define SIGHUP                1
#define SIGINT                2
#define SIGILL                4
#define SIGABRT_COMPAT        6
#define SIGFPE                8
#define SIGKILL               9
#define SIGSEGV              11
#define SIGTERM              15
#define SIGBREAK             21
#define SIGABRT              22
#define SIGWINCH             28

#endif
