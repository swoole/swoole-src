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

#ifdef _WIN32

#include "swoole.h"

#include <sstream>
#include <algorithm>

// ============================================================================
// WSA initialization
// ============================================================================

static WSADATA wsa_data;
static bool wsa_initialized = false;

void sw_wsastartup() {
    if (!wsa_initialized) {
        WSAStartup(MAKEWORD(2, 2), &wsa_data);
        wsa_initialized = true;
    }
}

void sw_wsacleanup() {
    if (wsa_initialized) {
        WSACleanup();
        wsa_initialized = false;
    }
}

// ============================================================================
// uname() - get system name information
// ============================================================================

int uname(struct utsname *buf) {
    if (!buf) {
        errno = EFAULT;
        return -1;
    }

    // Get computer name
    DWORD size = SW_UTSNAME_LENGTH;
    if (!GetComputerNameA(buf->nodename, &size)) {
        strncpy(buf->nodename, "unknown", SW_UTSNAME_LENGTH - 1);
    }

    // Get Windows version info
    OSVERSIONINFOEXW osvi;
    ZeroMemory(&osvi, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    // Use RtlGetVersion as GetVersionEx is deprecated
    typedef NTSTATUS(WINAPI * RtlGetVersionPtr)(OSVERSIONINFOEXW *);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        auto RtlGetVersion = reinterpret_cast<RtlGetVersionPtr>(GetProcAddress(ntdll, "RtlGetVersion"));
        if (RtlGetVersion) {
            RtlGetVersion(&osvi);
        }
    }

    strncpy(buf->sysname, "Windows", SW_UTSNAME_LENGTH - 1);

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        strncpy(buf->machine, "x86_64", SW_UTSNAME_LENGTH - 1);
        break;
    case PROCESSOR_ARCHITECTURE_ARM64:
        strncpy(buf->machine, "arm64", SW_UTSNAME_LENGTH - 1);
        break;
    case PROCESSOR_ARCHITECTURE_ARM:
        strncpy(buf->machine, "arm", SW_UTSNAME_LENGTH - 1);
        break;
    case PROCESSOR_ARCHITECTURE_INTEL:
        strncpy(buf->machine, "x86", SW_UTSNAME_LENGTH - 1);
        break;
    default:
        strncpy(buf->machine, "unknown", SW_UTSNAME_LENGTH - 1);
        break;
    }

    // Build release string (e.g. "10.0.19045")
    snprintf(buf->release, SW_UTSNAME_LENGTH, "%lu.%lu.%lu",
             osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);

    // Build version string
    snprintf(buf->version, SW_UTSNAME_LENGTH,
             "Windows %lu.%lu Build %lu",
             osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);

    return 0;
}

// ============================================================================
// usleep() - high-resolution sleep
// ============================================================================

int sw_usleep(unsigned int microseconds) {
    HANDLE timer = CreateWaitableTimerExW(NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    if (timer) {
        LARGE_INTEGER due_time;
        due_time.QuadPart = -(static_cast<LONGLONG>(microseconds) * 10);  // convert to 100-nanosecond intervals
        if (SetWaitableTimer(timer, &due_time, 0, NULL, NULL, 0)) {
            WaitForSingleObject(timer, INFINITE);
        }
        CloseHandle(timer);
        return 0;
    }

    // Fallback: use Sleep for millisecond resolution
    Sleep((microseconds + 999) / 1000);
    return 0;
}

// ============================================================================
// gettimeofday() - get time of day
// ============================================================================

int sw_gettimeofday(struct timeval *tv, struct timezone *tz) {
    if (!tv) {
        errno = EFAULT;
        return -1;
    }

    // GetTickCount64 provides millisecond precision, but we need microsecond.
    // Use QueryPerformanceCounter for higher resolution.
    static LARGE_INTEGER frequency = {0};
    static bool frequency_initialized = false;

    if (!frequency_initialized) {
        QueryPerformanceFrequency(&frequency);
        frequency_initialized = true;
    }

    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);

    // Convert FILETIME (100-ns intervals since 1601-01-01) to Unix epoch
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    // Offset from 1601-01-01 to 1970-01-01 in 100-ns intervals
    static const ULONGLONG epoch_offset = 116444736000000000ULL;
    uli.QuadPart -= epoch_offset;

    tv->tv_sec = static_cast<long>(uli.QuadPart / 10000000ULL);
    tv->tv_usec = static_cast<long>((uli.QuadPart % 10000000ULL) / 10);

    if (tz) {
        // Windows does not support timezone info via this interface
        tz->tz_minuteswest = 0;
        tz->tz_dsttime = 0;
    }

    return 0;
}

// ============================================================================
// strndup() - duplicate string with length limit
// ============================================================================

char *sw_strndup(const char *s, size_t n) {
    if (!s) {
        return nullptr;
    }
    size_t len = strlen(s);
    if (len > n) {
        len = n;
    }
    char *result = static_cast<char *>(malloc(len + 1));
    if (!result) {
        return nullptr;
    }
    memcpy(result, s, len);
    result[len] = '\0';
    return result;
}

// ============================================================================
// pread()/pwrite() - positioned file I/O
// ============================================================================

ssize_t sw_pread(int fd, void *buf, size_t count, off_t offset) {
    HANDLE h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    if (h == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }

    OVERLAPPED ov = {};
    ov.Offset = static_cast<DWORD>(offset & 0xFFFFFFFF);
    ov.OffsetHigh = static_cast<DWORD>(offset >> 32);

    DWORD bytes_read = 0;
    if (!ReadFile(h, buf, static_cast<DWORD>(count), &bytes_read, &ov)) {
        DWORD err = GetLastError();
        if (err == ERROR_HANDLE_EOF) {
            return 0;  // EOF
        }
        errno = (err == ERROR_BROKEN_PIPE) ? 0 : EIO;
        return -1;
    }

    return static_cast<ssize_t>(bytes_read);
}

ssize_t sw_pwrite(int fd, const void *buf, size_t count, off_t offset) {
    HANDLE h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    if (h == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }

    OVERLAPPED ov = {};
    ov.Offset = static_cast<DWORD>(offset & 0xFFFFFFFF);
    ov.OffsetHigh = static_cast<DWORD>(offset >> 32);

    DWORD bytes_written = 0;
    if (!WriteFile(h, buf, static_cast<DWORD>(count), &bytes_written, &ov)) {
        errno = EIO;
        return -1;
    }

    return static_cast<ssize_t>(bytes_written);
}

// ============================================================================
// socketpair() - create a pair of connected sockets using TCP loopback
// ============================================================================

int sw_socketpair(int domain, int type, int protocol, int sv[2]) {
    SOCKET listener = INVALID_SOCKET;
    SOCKET connector = INVALID_SOCKET;
    SOCKET acceptor = INVALID_SOCKET;
    struct sockaddr_in addr;
    int addrlen = sizeof(addr);

    // Create listener socket
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener == INVALID_SOCKET) {
        goto fail;
    }

    // Bind to loopback on a random port
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;  // let the OS pick a port

    if (bind(listener, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        goto fail;
    }

    if (listen(listener, 1) == SOCKET_ERROR) {
        goto fail;
    }

    // Get the assigned port
    if (getsockname(listener, reinterpret_cast<struct sockaddr *>(&addr), &addrlen) == SOCKET_ERROR) {
        goto fail;
    }

    // Create connector socket
    connector = socket(AF_INET, SOCK_STREAM, 0);
    if (connector == INVALID_SOCKET) {
        goto fail;
    }

    // Connect to the listener
    if (connect(connector, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        goto fail;
    }

    // Accept the connection
    acceptor = accept(listener, nullptr, nullptr);
    if (acceptor == INVALID_SOCKET) {
        goto fail;
    }

    // Close listener - no longer needed
    closesocket(listener);
    listener = INVALID_SOCKET;

    sv[0] = static_cast<int>(connector);
    sv[1] = static_cast<int>(acceptor);
    return 0;

fail:
    if (listener != INVALID_SOCKET) closesocket(listener);
    if (connector != INVALID_SOCKET) closesocket(connector);
    if (acceptor != INVALID_SOCKET) closesocket(acceptor);
    errno = EIO;
    return -1;
}

// ============================================================================
// setsockopt keepalive compatibility
// ============================================================================

int sw_setsockopt_keepalive(int sockfd, int idle, int interval, int count) {
    DWORD val;

    // Enable keepalive
    val = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char *>(&val), sizeof(val)) != 0) {
        return SOCKET_ERROR;
    }

    // TCP_KEEPALIVE is the Windows equivalent of TCP_KEEPIDLE (in milliseconds)
    val = static_cast<DWORD>(idle * 1000);
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPALIVE, reinterpret_cast<const char *>(&val), sizeof(val)) != 0) {
        return SOCKET_ERROR;
    }

    // TCP_KEEPINTVL (Windows 10+)
#ifdef TCP_KEEPINTVL
    val = static_cast<DWORD>(interval * 1000);
    setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, reinterpret_cast<const char *>(&val), sizeof(val));
#endif

    // TCP_KEEPCNT (Windows 10+)
#ifdef TCP_KEEPCNT
    val = static_cast<DWORD>(count);
    setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, reinterpret_cast<const char *>(&val), sizeof(val));
#endif

    return 0;
}

// ============================================================================
// flock() - file locking (using LockFileEx/UnlockFileEx)
// ============================================================================

int sw_flock(int fd, int operation) {
    HANDLE h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    if (h == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }

    DWORD flags = 0;
    if (operation & LOCK_NB) {
        flags |= LOCKFILE_FAIL_IMMEDIATELY;
    }

    OVERLAPPED ov = {};
    DWORD reserved = 0;

    if (operation & LOCK_UN) {
        // Unlock
        if (!UnlockFileEx(h, reserved, MAXDWORD, MAXDWORD, &ov)) {
            errno = EIO;
            return -1;
        }
    } else if (operation & LOCK_EX) {
        // Exclusive lock
        if (!LockFileEx(h, flags, reserved, MAXDWORD, MAXDWORD, &ov)) {
            errno = (GetLastError() == ERROR_LOCK_VIOLATION) ? EWOULDBLOCK : EIO;
            return -1;
        }
    } else if (operation & LOCK_SH) {
        // Shared lock
        if (!LockFileEx(h, flags | 0x00000000, reserved, MAXDWORD, MAXDWORD, &ov)) {
            // 0x00000000 = no LOCKFILE_EXCLUSIVE_LOCK means shared lock
            errno = (GetLastError() == ERROR_LOCK_VIOLATION) ? EWOULDBLOCK : EIO;
            return -1;
        }
    }

    return 0;
}

// ============================================================================
// fsync() - flush file buffers to disk
// ============================================================================

int sw_fsync(int fd) {
    HANDLE h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    if (h == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }
    if (!FlushFileBuffers(h)) {
        errno = EIO;
        return -1;
    }
    return 0;
}

// ============================================================================
// ftruncate() - truncate file to specified length
// ============================================================================

int sw_ftruncate(int fd, off_t length) {
    HANDLE h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    if (h == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }

    LARGE_INTEGER li;
    li.QuadPart = length;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN)) {
        errno = EIO;
        return -1;
    }
    if (!SetEndOfFile(h)) {
        errno = EIO;
        return -1;
    }
    return 0;
}

// ============================================================================
// getrlimit()/setrlimit() - stubs (not supported on Windows)
// ============================================================================

int getrlimit(int /*resource*/, struct rlimit *rlim) {
    if (!rlim) {
        errno = EFAULT;
        return -1;
    }
    // Return some reasonable defaults
    rlim->rlim_cur = 512;  // Windows default FD limit
    rlim->rlim_max = 2048;
    return 0;
}

int setrlimit(int /*resource*/, const struct rlimit * /*rlim*/) {
    errno = ENOSYS;
    return -1;
}

// ============================================================================
// wait()/waitpid() - process waiting (limited on Windows)
// ============================================================================

pid_t wait(int *status) {
    return waitpid(-1, status, 0);
}

pid_t waitpid(pid_t pid, int *status, int options) {
    if (!status) {
        errno = EFAULT;
        return -1;
    }

    HANDLE hProcess;
    if (pid > 0) {
        hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
        if (!hProcess) {
            errno = ECHILD;
            return -1;
        }
    } else {
        // Waiting for any child process is not fully supported on Windows
        errno = ENOSYS;
        return -1;
    }

    DWORD wait_ms = (options & WNOHANG) ? 0 : INFINITE;
    DWORD result = WaitForSingleObject(hProcess, wait_ms);

    if (result == WAIT_TIMEOUT) {
        CloseHandle(hProcess);
        return 0;  // WNOHANG and process hasn't exited
    }

    if (result == WAIT_FAILED) {
        CloseHandle(hProcess);
        errno = ECHILD;
        return -1;
    }

    // Get exit code
    DWORD exit_code = 0;
    if (!GetExitCodeProcess(hProcess, &exit_code)) {
        CloseHandle(hProcess);
        errno = ECHILD;
        return -1;
    }

    // Encode exit status in POSIX-compatible format
    *status = (exit_code & 0xFF) << 8;

    CloseHandle(hProcess);
    return pid;
}

// ============================================================================
// kill() - send signal to process (limited on Windows)
// ============================================================================

int sw_kill(pid_t pid, int sig) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
    if (!hProcess) {
        errno = ESRCH;
        return -1;
    }

    int ret = 0;
    if (sig == SIGKILL) {
        // TerminateProcess is the Windows equivalent of SIGKILL
        if (!TerminateProcess(hProcess, 1)) {
            errno = EPERM;
            ret = -1;
        }
    } else if (sig == SIGTERM) {
        // Try to post a WM_CLOSE message to the process's windows
        // This is a best-effort approach; console processes need Ctrl+C
        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            DWORD pid;
            GetWindowThreadProcessId(hwnd, &pid);
            if (pid == static_cast<DWORD>(lParam)) {
                PostMessageW(hwnd, WM_CLOSE, 0, 0);
            }
            return TRUE;
        }, static_cast<LPARAM>(pid));

        // For console processes, try GenerateConsoleCtrlEvent
        // This only works if the target is in the same console group
        GenerateConsoleCtrlEvent(CTRL_C_EVENT, static_cast<DWORD>(pid));
    }
    // For other signals, we silently succeed (Windows doesn't support POSIX signals)

    CloseHandle(hProcess);
    return ret;
}

// ============================================================================
// access() - check file accessibility
// ============================================================================

int sw_access(const char *path, int mode) {
    if (!path) {
        errno = EFAULT;
        return -1;
    }

    // _access on Windows supports: 0=exist, 2=write, 4=read, 6=read+write
    // This maps directly to R_OK=4, W_OK=2, X_OK=1, F_OK=0
    // X_OK is not meaningful on Windows; treat as existence check
    int win_mode = 0;
    if (mode & R_OK) win_mode |= 4;
    if (mode & W_OK) win_mode |= 2;
    if (mode & X_OK) {
        // X_OK: on Windows, just check existence (no execute permission concept)
        win_mode |= 0;
    }
    if (mode == F_OK) win_mode = 0;

    return _access(path, win_mode);
}

// ============================================================================
// sw_socket_errno() - translate WSA error code to POSIX errno value
// ============================================================================

int sw_socket_errno(void) {
    int wsa_err = WSAGetLastError();
    switch (wsa_err) {
    case 0:
        return 0;
    case WSAEINTR:
        return EINTR;
    case WSAEBADF:
        return EBADF;
    case WSAEACCES:
        return EACCES;
    case WSAEFAULT:
        return EFAULT;
    case WSAEINVAL:
        return EINVAL;
    case WSAEMFILE:
        return EMFILE;
    case WSAEWOULDBLOCK:
        return EAGAIN;  // EWOULDBLOCK == EAGAIN on most platforms
    case WSAEINPROGRESS:
        return EINPROGRESS;
    case WSAEALREADY:
        return EALREADY;
    case WSAENOTSOCK:
        return ENOTSOCK;
    case WSAEDESTADDRREQ:
        return EDESTADDRREQ;
    case WSAEMSGSIZE:
        return EMSGSIZE;
    case WSAEPROTOTYPE:
        return EPROTOTYPE;
    case WSAENOPROTOOPT:
        return ENOPROTOOPT;
    case WSAEPROTONOSUPPORT:
        return EPROTONOSUPPORT;
    case WSAESOCKTNOSUPPORT:
        return ESOCKTNOSUPPORT;
    case WSAEOPNOTSUPP:
        return EOPNOTSUPP;
    case WSAEPFNOSUPPORT:
        return EPFNOSUPPORT;
    case WSAEAFNOSUPPORT:
        return EAFNOSUPPORT;
    case WSAEADDRINUSE:
        return EADDRINUSE;
    case WSAEADDRNOTAVAIL:
        return EADDRNOTAVAIL;
    case WSAENETDOWN:
        return ENETDOWN;
    case WSAENETUNREACH:
        return ENETUNREACH;
    case WSAENETRESET:
        return ENETRESET;
    case WSAECONNABORTED:
        return ECONNABORTED;
    case WSAECONNRESET:
        return ECONNRESET;
    case WSAENOBUFS:
        return ENOBUFS;
    case WSAEISCONN:
        return EISCONN;
    case WSAENOTCONN:
        return ENOTCONN;
    case WSAESHUTDOWN:
        return ESHUTDOWN;
    case WSAETIMEDOUT:
        return ETIMEDOUT;
    case WSAECONNREFUSED:
        return ECONNREFUSED;
    case WSAEHOSTDOWN:
        return EHOSTDOWN;
    case WSAEHOSTUNREACH:
        return EHOSTUNREACH;
    case WSAECANCELLED:
        return ECANCELED;
    default:
        // For unknown WSA errors, return the raw value + a base offset
        // to avoid colliding with standard errno values
        return wsa_err;
    }
}

#endif  // _WIN32
