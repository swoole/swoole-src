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

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef __PRETTY_FUNCTION__
#define __PRETTY_FUNCTION__ __FUNCTION__
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

// Winsock2 must be included before windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>

#include <io.h>
#include <direct.h>
#include <process.h>
#include <basetsd.h>

// ============================================================================
// Missing POSIX type definitions
// ============================================================================

#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef SSIZE_T ssize_t;
#endif

// pid_t: PHP's php.h also defines this on Windows.
#ifndef PHP_H
#ifndef _PID_T_DEFINED
#define _PID_T_DEFINED
typedef int pid_t;
#endif
#endif

#ifndef _MODE_T_DEFINED
#define _MODE_T_DEFINED
typedef unsigned short mode_t;
#endif

// uid_t/gid_t: PHP's php.h defines these on Windows (as int) without guards.
// Only define if PHP has not been included.
#ifndef PHP_H
#ifndef _UID_T_DEFINED
#define _UID_T_DEFINED
typedef unsigned int uid_t;
#endif

#ifndef _GID_T_DEFINED
#define _GID_T_DEFINED
typedef unsigned int gid_t;
#endif
#endif

// off_t: use 64-bit for large file support
// PHP's php.h defines off_t as _off_t on Windows; skip if PHP has been included.
#ifndef PHP_H
#ifndef _OFF_T_DEFINED
#define _OFF_T_DEFINED
typedef __int64 off_t;
#endif
#endif

typedef uint32_t uint;

// iovec structure (from sys/uio.h)
#ifndef _IOVEC_DEFINED
#define _IOVEC_DEFINED
struct iovec {
    void *iov_base;
    size_t iov_len;
};
#endif

// utsname structure (from sys/utsname.h)
#ifndef _UTSNAME_DEFINED
#define _UTSNAME_DEFINED
#define SW_UTSNAME_LENGTH 65
struct utsname {
    char sysname[SW_UTSNAME_LENGTH];
    char nodename[SW_UTSNAME_LENGTH];
    char release[SW_UTSNAME_LENGTH];
    char version[SW_UTSNAME_LENGTH];
    char machine[SW_UTSNAME_LENGTH];
};
#endif

// timezone structure (for gettimeofday)
#ifndef _TIMEZONE_DEFINED
#define _TIMEZONE_DEFINED
struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};
#endif

// ============================================================================
// Process / wait status macros (from sys/wait.h)
// ============================================================================

#ifndef WNOHANG
#define WNOHANG 1
#endif

#ifndef WEXITSTATUS
#define WEXITSTATUS(status) (((status) >> 8) & 0xFF)
#endif

#ifndef WTERMSIG
#define WTERMSIG(status) ((status) & 0x7F)
#endif

#ifndef WIFEXITED
#define WIFEXITED(status) (WTERMSIG(status) == 0)
#endif

#ifndef WIFSIGNALED
#define WIFSIGNALED(status) (((signed char)(((status) & 0x7F) + 1) >> 1) > 0)
#endif

// SIGKILL is not available on Windows; define a value that won't conflict
#ifndef SIGKILL
#define SIGKILL 9
#endif

// ============================================================================
// System V IPC types (from sys/types.h, sys/ipc.h)
// These are NOT available on Windows; the entire SysV IPC subsystem is absent.
// ============================================================================

#ifndef _KEY_T_DEFINED
#define _KEY_T_DEFINED
typedef int key_t;
#endif

// ============================================================================
// Standard file descriptor constants
// ============================================================================

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

// ============================================================================
// Signals missing on Windows
// ============================================================================

#ifndef SIGHUP
#define SIGHUP 1
#endif

#ifndef SIGPIPE
#define SIGPIPE SIGABRT
#endif

#ifndef SIGUSR1
#define SIGUSR1 10
#endif

#ifndef SIGUSR2
#define SIGUSR2 12
#endif

#ifndef SIGALRM
#define SIGALRM 14
#endif

// ============================================================================
// Socket error code mappings (WSA -> POSIX errno)
// ============================================================================

#ifndef EAGAIN
#define EAGAIN WSAEWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif

#ifndef EINPROGRESS
#define EINPROGRESS WSAEINPROGRESS
#endif

#ifndef EINTR
#define EINTR WSAEINTR
#endif

#ifndef ECONNREFUSED
#define ECONNREFUSED WSAECONNREFUSED
#endif

#ifndef ECONNRESET
#define ECONNRESET WSAECONNRESET
#endif

#ifndef ECONNABORTED
#define ECONNABORTED WSAECONNABORTED
#endif

#ifndef ETIMEDOUT
#define ETIMEDOUT WSAETIMEDOUT
#endif

#ifndef ENOTCONN
#define ENOTCONN WSAENOTCONN
#endif

#ifndef EADDRINUSE
#define EADDRINUSE WSAEADDRINUSE
#endif

#ifndef ENETDOWN
#define ENETDOWN WSAENETDOWN
#endif

#ifndef ENETUNREACH
#define ENETUNREACH WSAENETUNREACH
#endif

#ifndef EHOSTUNREACH
#define EHOSTUNREACH WSAEHOSTUNREACH
#endif

#ifndef EMSGSIZE
#define EMSGSIZE WSAEMSGSIZE
#endif

// ============================================================================
// File open flags (POSIX -> Windows CRT)
// ============================================================================

#ifndef O_NONBLOCK
#define O_NONBLOCK 0x4000
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef F_GETFL
#define F_GETFL 0
#endif

#ifndef F_SETFL
#define F_SETFL 1
#endif

#ifndef F_GETFD
#define F_GETFD 2
#endif

#ifndef F_SETFD
#define F_SETFD 3
#endif

#ifndef FD_CLOEXEC
#define FD_CLOEXEC 1
#endif

#ifndef F_RDLCK
#define F_RDLCK 0
#endif

#ifndef F_WRLCK
#define F_WRLCK 1
#endif

#ifndef F_UNLCK
#define F_UNLCK 2
#endif

#ifndef F_SETLK
#define F_SETLK 4
#endif

#ifndef F_SETLKW
#define F_SETLKW 5
#endif

// File mode bits
#ifndef S_IRUSR
#define S_IRUSR _S_IREAD
#endif

#ifndef S_IWUSR
#define S_IWUSR _S_IWRITE
#endif

#ifndef S_IXUSR
#define S_IXUSR 0
#endif

#ifndef S_IRGRP
#define S_IRGRP 0
#endif

#ifndef S_IWGRP
#define S_IWGRP 0
#endif

#ifndef S_IXGRP
#define S_IXGRP 0
#endif

#ifndef S_IROTH
#define S_IROTH 0
#endif

#ifndef S_IWOTH
#define S_IWOTH 0
#endif

#ifndef S_IXOTH
#define S_IXOTH 0
#endif

#ifndef S_ISREG
#define S_ISREG(mode) (((mode) & _S_IFMT) == _S_IFREG)
#endif

#ifndef S_ISDIR
#define S_ISDIR(mode) (((mode) & _S_IFMT) == _S_IFDIR)
#endif

// ============================================================================
// RLIMIT_NOFILE (not available on Windows, provide stub)
// ============================================================================

#ifndef RLIMIT_NOFILE
#define RLIMIT_NOFILE 0
#endif

typedef unsigned long rlim_t;

struct rlimit {
    rlim_t rlim_cur;
    rlim_t rlim_max;
};

// ============================================================================
// File lock operations (sys/file.h)
// ============================================================================

#ifndef LOCK_SH
#define LOCK_SH 1
#endif

#ifndef LOCK_EX
#define LOCK_EX 2
#endif

#ifndef LOCK_UN
#define LOCK_UN 8
#endif

#ifndef LOCK_NB
#define LOCK_NB 4
#endif

// ============================================================================
// File access mode (for access() function)
// ============================================================================

#ifndef R_OK
#define R_OK 4
#endif

#ifndef W_OK
#define W_OK 2
#endif

#ifndef X_OK
#define X_OK 1
#endif

#ifndef F_OK
#define F_OK 0
#endif

// ============================================================================
// Socket compatibility
// ============================================================================

// On Windows, use closesocket() for sockets
#define SW_CLOSE_SOCKET(fd) closesocket(fd)

// AF_UNIX support: Windows 10 1803+ supports AF_UNIX
// For older Windows, this will fail at runtime
#ifndef AF_UNIX
#define AF_UNIX 1
#endif

// sockaddr_un structure (from sys/un.h)
// Windows 10 1803+ provides this in <afunix.h>, but we define a compatible
// version for older Windows and to avoid header dependency issues.
#ifndef _SOCKADDR_UN_DEFINED
#define _SOCKADDR_UN_DEFINED
struct sockaddr_un {
    ADDRESS_FAMILY sun_family;
    char sun_path[108];
};
#endif

// nfds_t type (from poll.h)
#ifndef _NFDS_T_DEFINED
#define _NFDS_T_DEFINED
typedef ULONG nfds_t;
#endif

// DIR and dirent structures (from dirent.h)
// Windows does not have native dirent; this provides a minimal compatible definition.
// PHP's win32/readdir.h (guarded by READDIR_H) also defines these on Windows.
#ifndef _DIRENT_DEFINED
#ifndef READDIR_H
#define _DIRENT_DEFINED
struct dirent {
    long d_ino;
    unsigned short d_reclen;
    unsigned short d_namlen;
    unsigned d_type;
    char d_name[260];
};
typedef struct _sw_DIR {
    void *handle;
    struct dirent entry;
    int first;
} DIR;
#endif
#endif

// struct statvfs (from sys/statvfs.h)
// Windows does not have native statvfs; this provides a compatible definition.
#ifndef _STATVFS_DEFINED
#define _STATVFS_DEFINED
struct statvfs {
    unsigned long f_bsize;
    unsigned long f_frsize;
    unsigned long long f_blocks;
    unsigned long long f_bfree;
    unsigned long long f_bavail;
    unsigned long long f_files;
    unsigned long long f_ffree;
    unsigned long long f_favail;
    unsigned long f_fsid;
    unsigned long f_flag;
    unsigned long f_namemax;
};
#endif

// struct msghdr (from sys/socket.h)
// Windows has WSAMSG in mswsock.h but with different field names.
// We define a POSIX-compatible msghdr for the coroutine API.
#ifndef _MSGHDR_DEFINED
#define _MSGHDR_DEFINED
struct msghdr {
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    int msg_flags;
};
#endif

// SHUT_RDWR etc. - Windows uses SD_BOTH etc.
#ifndef SHUT_RD
#define SHUT_RD SD_RECEIVE
#endif

#ifndef SHUT_WR
#define SHUT_WR SD_SEND
#endif

#ifndef SHUT_RDWR
#define SHUT_RDWR SD_BOTH
#endif

// TCP_NODELAY and other TCP options are defined in winsock2.h
// IPPROTO_TCP is also defined

// Missing socket options
#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE TCP_KEEPALIVE
#endif

// MSG_DONTWAIT - not available on Windows, use non-blocking socket instead
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

// ============================================================================
// Utility function declarations (implemented in src/os/win32.cc)
// ============================================================================

SW_EXTERN_C_BEGIN

// uname() replacement
int uname(struct utsname *buf);

// usleep() replacement
int sw_usleep(unsigned int microseconds);

// gettimeofday() replacement
int sw_gettimeofday(struct timeval *tv, struct timezone *tz);

// strndup() replacement
char *sw_strndup(const char *s, size_t n);

// pread/pwrite replacements
ssize_t sw_pread(int fd, void *buf, size_t count, off_t offset);
ssize_t sw_pwrite(int fd, const void *buf, size_t count, off_t offset);

// WSA initialization/cleanup
void sw_wsastartup();
void sw_wsacleanup();

// socketpair() replacement using TCP loopback
int sw_socketpair(int domain, int type, int protocol, int sv[2]);

// setsockopt compatibility for TCP_KEEPIDLE etc.
int sw_setsockopt_keepalive(int sockfd, int idle, int interval, int count);

// flock() replacement
int sw_flock(int fd, int operation);

// fsync() replacement
int sw_fsync(int fd);

// ftruncate() replacement
int sw_ftruncate(int fd, off_t length);

// getrlimit/setrlimit stubs (always returns -1 on Windows)
int getrlimit(int resource, struct rlimit *rlim);
int setrlimit(int resource, const struct rlimit *rlim);

// wait()/waitpid() replacements (limited functionality on Windows)
pid_t wait(int *status);
pid_t waitpid(pid_t pid, int *status, int options);

// kill() replacement (uses TerminateProcess on Windows)
int sw_kill(pid_t pid, int sig);

// access() replacement (Windows uses _access with different mode values)
int sw_access(const char *path, int mode);

SW_EXTERN_C_END

// ============================================================================
// POSIX function name overrides
// These macros replace POSIX function names with Windows equivalents.
// They are intentionally scoped to avoid conflicts with class/method names.
// ============================================================================

// poll() -> WSAPoll() (same signature, defined in winsock2.h)
// Note: only affects standalone poll() calls, not identifiers containing 'poll'
#define poll WSAPoll

// ============================================================================
// Socket errno abstraction
// On Windows, socket errors are retrieved via WSAGetLastError(), not errno.
// WSAGetLastError() returns WSA error codes (e.g., WSAEINTR = 10004) which
// differ from POSIX errno values (e.g., EINTR = 4).
// sw_socket_errno() translates WSA error codes to POSIX-compatible errno values.
// ============================================================================

// Translate WSA error code to POSIX errno value
int sw_socket_errno(void);

#define SW_SOCKET_ERRNO sw_socket_errno()
#define SW_SOCKET_SET_ERRNO(e) WSASetLastError(e)

// On Windows, close() cannot be used for sockets; use closesocket() instead.
// For file descriptors, use _close() instead of close().
// Use SW_CLOSE_SOCKET() for sockets (already defined above) and SW_CLOSE_FILE for files.
#define SW_CLOSE_FILE(fd) _close(fd)

// Override POSIX functions not available in Windows CRT
#define usleep sw_usleep
#define strndup sw_strndup
#define pread sw_pread
#define pwrite sw_pwrite
#define flock sw_flock
#define fsync sw_fsync
#define ftruncate sw_ftruncate
#define kill sw_kill
#define access sw_access

// ============================================================================
// pthread compatibility (minimal stubs for header compilation)
// The actual implementation should use C++11 <thread>/<mutex> or
// pthreads-win32 library
// ============================================================================

// Note: pthread.h is NOT available on Windows. Source files that use
// pthread functions directly must be adapted individually.
// For SW_USE_THREAD_CONTEXT, C++11 <thread>/<mutex> is used instead.

#endif  // _WIN32
