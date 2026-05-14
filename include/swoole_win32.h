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
#include <iphlpapi.h>

// CRITICAL: Include <float.h> BEFORE #undef'ing its macros.
// <float.h> defines SW_INVALID, SW_OVERFLOW, etc. as floating-point status
// word macros. If we #undef them here but <float.h> is later re-included
// (e.g. via C++ standard library headers like <limits>, <sstream>), the
// macros would be re-defined and corrupt Swoole's enum values.
// By including <float.h> first, its include guard prevents re-inclusion.
#include <float.h>

// Undefine Windows macros that conflict with Swoole/STL names.
// Windows defines SW_MAX/SW_MIN as ShowWindow constants (e.g. SW_MAX=3),
// which conflicts with Swoole's SW_MAX(A,B)/SW_MIN(A,B) macros.
#undef SW_MAX
#undef SW_MIN

// Windows CRT <float.h> defines SW_* as floating-point status word flags
// (e.g. SW_INVALID = _SW_INVALID), which conflict with Swoole enum values.
#undef SW_INVALID
#undef SW_DENORMAL
#undef SW_ZERODIVIDE
#undef SW_OVERFLOW
#undef SW_UNDERFLOW
#undef SW_INEXACT
#undef SW_UNEMULATED
#undef SW_SQRTNEG
#undef SW_STACKOVERFLOW
#undef SW_STACKUNDERFLOW

// Windows SDK <winerror.h> defines ERROR_TIMEOUT as 1460L,
// which conflicts with Swoole's coroutine::Channel::ErrorCode::ERROR_TIMEOUT.
#undef ERROR_TIMEOUT

// PHP's php.h includes <windows.h> before this header, so NOMINMAX
// defined above may be too late. Undefine min/max macros here.
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

#include <cstdint>
#include <io.h>
#include <direct.h>
#include <process.h>
#include <basetsd.h>

// POSIX string functions not available on Windows
// PHP's zend_config.w32.h already defines these, so guard with #ifndef
#ifndef strncasecmp
#define strncasecmp _strnicmp
#endif
#ifndef strcasecmp
#define strcasecmp _stricmp
#endif

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

// off_t and _off_t: must define BOTH because Windows CRT's sys/stat.h uses _off_t
// and guards it with _OFF_T_DEFINED. If we set _OFF_T_DEFINED without defining _off_t,
// the CRT skips its definition and _off_t remains undefined, causing st_size errors
// in struct stat.
// PHP's php.h defines off_t as _off_t on Windows; skip if PHP has been included.
#ifndef PHP_H
#ifndef _OFF_T_DEFINED
#define _OFF_T_DEFINED
typedef long _off_t;
typedef _off_t off_t;
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

// SIGCHLD - not available on Windows
#ifndef SIGCHLD
#define SIGCHLD 17
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

// ESOCKTNOSUPPORT is guarded by #if 0 in WinSock2.h, so it's not available
#ifndef ESOCKTNOSUPPORT
#define ESOCKTNOSUPPORT WSAESOCKTNOSUPPORT
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

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
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
// PHP's php_filestat.h also defines these on Windows (without #ifndef guards).
// When building as a PHP extension, skip our definitions to avoid conflicts.
// PHP defines S_IXUSR as S_IEXEC while we define it as 0, etc.
#ifndef PHP_H
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
#endif /* PHP_H */

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

// Cross-platform socket file descriptor type
// On Windows, SOCKET is UINT_PTR (8 bytes on x64), which cannot be safely stored in int (4 bytes).
typedef SOCKET sw_socket_t;
#define SW_BAD_SOCKET INVALID_SOCKET

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
    HANDLE handle;
    WIN32_FIND_DATAW find_data;  // Used internally by FindFirstFileW/FindNextFileW
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
// MSVC does not support C++ alternative tokens (and, or, not, etc.)
// These are standard C++ keywords but MSVC treats them as identifiers.
// Define them as macros for compatibility.
// ============================================================================
#ifndef and
#define and &&
#endif
#ifndef or
#define or ||
#endif
#ifndef not
#define not !
#endif
#ifndef bitand
#define bitand &
#endif
#ifndef bitor
#define bitor |
#endif
#ifndef xor
#define xor ^
#endif
#ifndef and_eq
#define and_eq &=
#endif
#ifndef or_eq
#define or_eq |=
#endif
#ifndef xor_eq
#define xor_eq ^=
#endif
#ifndef not_eq
#define not_eq !=
#endif
#ifndef compl
#define compl ~
#endif

// ============================================================================
// Missing POSIX constants and types
// ============================================================================

// PATH_MAX - Windows has _MAX_PATH (260) but not PATH_MAX
#ifndef PATH_MAX
#define PATH_MAX _MAX_PATH
#endif

// SIGTERM - not defined by Windows CRT signals
#ifndef SIGTERM
#define SIGTERM 15
#endif

// SIGWINCH - window resize signal, not available on Windows
#ifndef SIGWINCH
#define SIGWINCH 28
#endif

// SIGIO - I/O possible signal, not available on Windows
#ifndef SIGIO
#define SIGIO 29
#endif

// in_port_t - POSIX type for port numbers
#ifndef _IN_PORT_T_DEFINED
#define _IN_PORT_T_DEFINED
typedef uint16_t in_port_t;
#endif

// Missing WSA errno mappings
#ifndef EPFNOSUPPORT
#define EPFNOSUPPORT WSAEPFNOSUPPORT
#endif

#ifndef ESHUTDOWN
#define ESHUTDOWN WSAESHUTDOWN
#endif

#ifndef EHOSTDOWN
#define EHOSTDOWN WSAEHOSTDOWN
#endif

// ECANCELED - may not be defined on Windows
#ifndef ECANCELED
#define ECANCELED WSAECANCELLED
#endif

// EALREADY - may not be defined on Windows
#ifndef EALREADY
#define EALREADY WSAEALREADY
#endif

// ENOTSOCK - may not be defined on Windows
#ifndef ENOTSOCK
#define ENOTSOCK WSAENOTSOCK
#endif

// EDESTADDRREQ
#ifndef EDESTADDRREQ
#define EDESTADDRREQ WSAEDESTADDRREQ
#endif

// EMSGSIZE already defined above

// EPROTOTYPE
#ifndef EPROTOTYPE
#define EPROTOTYPE WSAEPROTOTYPE
#endif

// ENOPROTOOPT
#ifndef ENOPROTOOPT
#define ENOPROTOOPT WSAENOPROTOOPT
#endif

// EPROTONOSUPPORT
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT WSAEPROTONOSUPPORT
#endif

// EOPNOTSUPP
#ifndef EOPNOTSUPP
#define EOPNOTSUPP WSAEOPNOTSUPP
#endif

// EAFNOSUPPORT
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#endif

// EADDRNOTAVAIL
#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL WSAEADDRNOTAVAIL
#endif

// ENETRESET
#ifndef ENETRESET
#define ENETRESET WSAENETRESET
#endif

// ENOBUFS
#ifndef ENOBUFS
#define ENOBUFS WSAENOBUFS
#endif

// EISCONN
#ifndef EISCONN
#define EISCONN WSAEISCONN
#endif

// POSIX string/token function replacements
#define strtok_r strtok_s

// memmem() - find byte sequence in memory (not available on Windows)
// Declared here; implemented in src/os/win32.cc
SW_EXTERN_C_BEGIN
void *swoole_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
SW_EXTERN_C_END
#define memmem swoole_memmem

// S_ISLNK - Windows has no symbolic link concept in stat
#ifndef S_ISLNK
#define S_ISLNK(mode) 0
#endif

// NTSTATUS type for RtlGetVersion (normally in winternl.h or ntdef.h)
#ifndef _NTSTATUS_DEFINED
typedef LONG NTSTATUS;
#endif

// mmap protection flags (from sys/mman.h)
// Windows uses VirtualAlloc/VirtualProtect instead, but these constants
// are needed for sw_shm_protect() compatibility.
#ifndef PROT_READ
#define PROT_READ 0x1
#endif
#ifndef PROT_WRITE
#define PROT_WRITE 0x2
#endif
#ifndef PROT_EXEC
#define PROT_EXEC 0x4
#endif
#ifndef PROT_NONE
#define PROT_NONE 0x0
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
int sw_socketpair(int domain, int type, int protocol, sw_socket_t sv[2]);

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

// Directory traversal replacements (opendir/readdir/closedir)
DIR *opendir(const char *name);
struct dirent *readdir(DIR *dir);
int closedir(DIR *dir);

// nanosleep() replacement
int sw_nanosleep(const struct timespec *req, struct timespec *rem);

// strptime() replacement
char *sw_strptime(const char *buf, const char *fmt, struct tm *tm);

SW_EXTERN_C_END

// ============================================================================
// POSIX function name overrides
// These macros replace POSIX function names with Windows equivalents.
// They are intentionally scoped to avoid conflicts with class/method names.
// ============================================================================

// poll() -> WSAPoll() (same signature, defined in winsock2.h)
// Note: only affects standalone poll() calls, not identifiers containing 'poll'
#define poll WSAPoll

// lstat -> stat on Windows (no symbolic link distinction)
// lstat -> stat on Windows (no symbolic link distinction)
// Use #undef to avoid C4005 warning when php.h also defines lstat
#undef lstat
#define lstat stat

// realpath -> _fullpath on Windows
#define realpath(path, resolved) _fullpath(resolved, path, PATH_MAX)

// nanosleep -> sw_nanosleep (implemented in src/os/win32.cc)
#define nanosleep sw_nanosleep

// socketpair -> sw_socketpair
#define socketpair sw_socketpair

// strptime -> sw_strptime (implemented in src/os/win32.cc)
#define strptime sw_strptime

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


static inline const char *sw_win32_strerror(DWORD error) {
    static char buf[256];
    buf[0] = '\0';

    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL,
                   error,
                   MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                   buf,
                   sizeof(buf),
                   NULL);
    // 去除消息末尾的换行符
    char *p = buf;
    while (*p) {
        if (*p == '\r' || *p == '\n') {
            *p = '\0';
            break;
        }
        p++;
    }
    return buf;
}

// On Windows, close() cannot be used for sockets; use closesocket() instead.
// For file descriptors, use _close() instead of close().
// Use SW_CLOSE_SOCKET() for sockets (already defined above) and SW_CLOSE_FILE for files.
#define SW_CLOSE_FILE(fd) _close(fd)

// Override POSIX functions not available in Windows CRT
#define usleep sw_usleep
#define strndup sw_strndup
#define pread sw_pread
#define pwrite sw_pwrite
// flock: PHP's flock_compat.h also defines flock on Windows.
// Guard with #ifndef to avoid redefinition.
#ifndef flock
#define flock sw_flock
#endif
// fsync/ftruncate: PHP's php_network.h also defines these on Windows.
#ifndef fsync
#define fsync sw_fsync
#endif
#ifndef ftruncate
#define ftruncate sw_ftruncate
#endif
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

// pthread_t typedef for Windows (native thread handle)
#ifndef _PTHREAD_T_DEFINED
#define _PTHREAD_T_DEFINED
typedef void *pthread_t;
#endif

#define swoole_jump_fcontext jump_fcontext
#define swoole_make_fcontext make_fcontext

void swoole_signal_block_all();

#endif  // _WIN32
