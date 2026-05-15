/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#pragma once

#ifndef _WIN32

#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/utsname.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// POSIX platform: standard macros for cross-platform compatibility
static inline int sw_close_socket(int fd) {
	return close(fd);
}

static inline int sw_close_file(int fd) {
	return close(fd);
}

static inline int sw_errno() {
	return errno;
}

static inline void sw_set_errno(int e) {
	errno = e;
}

// Cross-platform socket file descriptor type
// On POSIX: int (same as always)
// On Windows: SOCKET (UINT_PTR, 8 bytes on x64)
// This avoids truncation when SOCKET values exceed int range on 64-bit Windows.
typedef int swSocketFd;
#define SW_BAD_SOCKET ((swSocketFd) -1)

#define sw_usleep usleep
#define sw_strndup strndup
#define sw_strdup strdup
#define sw_pread pread
#define sw_pwrite pwrite
#define sw_flock flock
#define sw_fsync fsync
#define sw_ftruncate ftruncate
#define sw_kill kill
#define sw_access access
#define sw_getrlimit getrlimit
#define sw_setrlimit setrlimit
#define sw_wait wait
#define sw_waitpid waitpid
#define sw_opendir opendir
#define sw_readdir readdir
#define sw_closedir closedir

#endif
