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

#ifdef _WIN32

#pragma comment(lib, "Ws2_32.lib")

#include <Winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <windows.h>
#if _MSC_VER == 1900
#include <vcruntime.h>
#include <corecrt_io.h>
#endif
#define WIN32_LEAN_AND_MEAN
#include <winnt.h>
#undef socklen_t
#include <WS2tcpip.h>
#include <math.h>
#include <fcntl.h>
#include <process.h>
#include <io.h>
#include <malloc.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <direct.h>
#include <winerror.h>
#include <memory.h>
#include <mswsock.h> //for SO_UPDATE_ACCEPT_CONTEXT
#include <Ws2tcpip.h>//for InetNtop
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <sys/utime.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <inttypes.h>

typedef CRITICAL_SECTION pthread_mutex_t;
typedef CONDITION_VARIABLE pthread_cond_t;
typedef HANDLE pthread_t;
typedef int pthread_mutexattr_t;
typedef intptr_t ssize_t;

typedef DWORD pid_t;
typedef intptr_t key_t;
typedef long off_t;
#define getpid()               GetCurrentProcessId()

#ifndef LOCALE_INVARIANT
# define LOCALE_INVARIANT 0x007f
#endif

enum
{
	F_DUPFD,
	F_GETFD,
	F_SETFD,
	F_GETFL,
	F_SETFL,
	F_GETLK,
	F_SETLK,
	F_SETLKW,
	FD_CLOEXEC
};

#define F_GETFL 0
#define F_SETFL 0
#define O_NONBLOCK 0
#define O_SYNC 0
#define O_NOCTTY 0

#define pow10(x)               pow(x,10)
#define alloca                 _alloca
#define strdup                 _strdup
#define vsnprintf              _vsnprintf

#define bzero(p, s)            memset(p, 0, s)
#define open                   _open
#define access                 _access
#define sched_yield()          SwitchToThread()
#define STDOUT_FILENO          fileno(stdout)
#define STDERR_FILENO          fileno(stderr)
#define PATH_MAX               MAX_PATH


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

#define R_OK 4
#define W_OK 2
#define X_OK 0
#define F_OK 0

#define SHUT_RD              SD_RECEIVE      
#define SHUT_WR              SD_SEND
#define SHUT_RDWR            SD_BOTH         



#define O_APPEND    _O_APPEND
#define MAP_FAILED  ((void *) -1)
#define MSG_DONTWAIT       0

typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID EntryPoint;
	ULONG StackZeroBits;
	ULONG StackReserved;
	ULONG StackCommit;
	ULONG ImageSubsystem;
	WORD SubSystemVersionLow;
	WORD SubSystemVersionHigh;
	ULONG Unknown1;
	ULONG ImageCharacteristics;
	ULONG ImageMachineType;
	ULONG Unknown2[3];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_INFORMATION {
	ULONG Size;
	HANDLE Process;
	HANDLE Thread;
	CLIENT_ID ClientId;
	SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED	0x00000001
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES		0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE		0x00000004

#define RTL_CLONE_PARENT				0
#define RTL_CLONE_CHILD					297

typedef DWORD pid_t;

typedef NTSTATUS(*RtlCloneUserProcess_f)(ULONG ProcessFlags,
	PSECURITY_DESCRIPTOR ProcessSecurityDescriptor /* optional */,
	PSECURITY_DESCRIPTOR ThreadSecurityDescriptor /* optional */,
	HANDLE DebugPort /* optional */,
	PRTL_USER_PROCESS_INFORMATION ProcessInformation);

pid_t fork(void)
{
	HMODULE mod;
	RtlCloneUserProcess_f clone_p;
	RTL_USER_PROCESS_INFORMATION process_info;
	NTSTATUS result;

	mod = GetModuleHandle("ntdll.dll");
	if (!mod)
		return -ENOSYS;

	clone_p = (RtlCloneUserProcess_f)GetProcAddress(mod, "RtlCloneUserProcess");
	if (clone_p == NULL)
	{
		return -ENOSYS;
	}

	/* lets do this */
	result = clone_p(RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED | RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, NULL, NULL, NULL, &process_info);

	if (result == RTL_CLONE_PARENT)
	{
		HANDLE me, hp, ht, hcp = 0;
		DWORD pi, ti;
		me = GetCurrentProcess();
		pi = (DWORD) process_info.ClientId.UniqueProcess;
		ti = (DWORD) process_info.ClientId.UniqueThread;

		assert(hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi));
		assert(ht = OpenThread(THREAD_ALL_ACCESS, FALSE, ti));

		ResumeThread(ht);
		CloseHandle(ht);
		CloseHandle(hp);
		return (pid_t)pi;
	}
	else if (result == RTL_CLONE_CHILD)
	{
		/* fix stdio */
		AllocConsole();
		return 0;
	}
	else
	{
		return -1;
	}

	/* NOTREACHED */
	return -1;
}


typedef int nfds_t;

static inline int poll(struct pollfd *fds, nfds_t nfds, int mille_timeout)
{
	struct timeval timeout;
	timeout.tv_sec = mille_timeout / 1000;
	timeout.tv_usec = 1000000 * mille_timeout % 1000;

	struct fd_set* fd = (fd_set*)malloc(2 * nfds * sizeof(fd_set));
	if (!fd)
	{
		return -1;
	}

	u_int* readerCount = &fd[0].fd_count;
	*readerCount = 0;
	SOCKET* fdReader = fd[0].fd_array;
	int writer = nfds;
	u_int* writerCount = &fd[nfds].fd_count;
	*writerCount = 0;
	SOCKET* fdWriter = fd[nfds].fd_array;

	for (int i = 0; i<nfds; i++)
	{
		if (fds[i].events & POLLIN)
		{
			fdReader[*readerCount] = fds[i].fd;
			*readerCount++;
		}
		if (fds[i].events & POLLOUT)
		{
			fdWriter[*writerCount] = fds[i].fd;
			*writerCount++;
		}
	}

	fd_set fdExcept;
	fdExcept.fd_count = 0;
	const int ok = select(nfds, &fd[0], &fd[nfds], &fdExcept, &timeout);
	free(fd);

	return ok;
}
#endif

#endif
