/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "swoole_socket.h"

#include <limits>

namespace swoole {
namespace detail {

// Adapt BSD's status-plus-byte-count result to the byte-count contract used by the socket layer.
// The native adapter initializes its in/out length on every call. The callback also lets core tests
// exercise interrupted syscalls without depending on signal timing.
ssize_t sendfile_with_retry(
    int out_fd, int in_fd, off_t *offset, size_t size, int (*sendfile)(int, int, off_t, size_t, off_t *)) {
    // BSD interprets zero as "to EOF", whereas this wrapper's size is an explicit byte budget.
    if (size == 0) {
        return 0;
    }
    size = std::min(size, static_cast<size_t>(std::numeric_limits<ssize_t>::max()));
    while (true) {
        off_t sent_bytes = 0;
        const int result = sendfile(out_fd, in_fd, *offset, size, &sent_bytes);
        const int error = errno;
        if (result < 0 && error != EINTR && error != EAGAIN) {
            // In particular, Darwin may leave its input length untouched after an early error.
            return -1;
        }
        if (sent_bytes > 0) {
            *offset += sent_bytes;
            return sent_bytes;
        }
        if (result == 0) {
            return 0;
        }
        if (error != EINTR) {
            return -1;
        }
        // No progress: retry the unchanged range. Positive progress is returned to the caller, which owns
        // the remaining byte budget and readiness/timeout handling.
    }
}

}  // namespace detail
}  // namespace swoole

#ifdef _WIN32
// Windows: use TransmitFile for zero-copy sendfile
ssize_t swoole_sendfile(int out_fd, int in_fd, off_t *offset, size_t size) {
    HANDLE hFile = reinterpret_cast<HANDLE>(_get_osfhandle(in_fd));
    if (hFile == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }

    // For now, use read+send as a fallback since TransmitFile
    // requires the socket to be in a particular state
    char buf[SW_BUFFER_SIZE_BIG];
    size_t readn = size > sizeof(buf) ? sizeof(buf) : size;
    ssize_t n = sw_pread(in_fd, buf, readn, *offset);

    if (n > 0) {
        ssize_t ret = ::send(out_fd, buf, n, 0);
        if (ret < 0) {
            swoole_sys_warning("send() in sendfile failed");
        } else {
            *offset += ret;
        }
        return ret;
    } else if (n == 0) {
        return 0;
    } else {
        swoole_sys_warning("pread() in sendfile failed");
        return SW_ERR;
    }
}
#elif defined(__linux__)
#include <sys/sendfile.h>

ssize_t swoole_sendfile(int out_fd, int in_fd, off_t *offset, size_t size) {
    return sendfile(out_fd, in_fd, offset, size);
}
#elif defined(HAVE_SENDFILE) && defined(HAVE_KQUEUE)
ssize_t swoole_sendfile(int out_fd, int in_fd, off_t *offset, size_t size) {
    const auto native_sendfile = [](int out_fd, int in_fd, off_t begin, size_t count, off_t *sent_bytes) {
#ifdef __MACH__
        *sent_bytes = static_cast<off_t>(count);
        return ::sendfile(in_fd, out_fd, begin, sent_bytes, nullptr, 0);
#else
        return ::sendfile(in_fd, out_fd, begin, count, nullptr, sent_bytes, 0);
#endif
    };
    const auto ret = swoole::detail::sendfile_with_retry(out_fd, in_fd, offset, size, native_sendfile);
    const int error = errno;
    swoole_trace(
        "send file, ret: %zd, out_fd:%d, in_fd:%d, offset:%jd, size:%zu", ret, out_fd, in_fd, (intmax_t) *offset, size);
    errno = error;
    return ret;
}
#else
ssize_t swoole_sendfile(int out_fd, int in_fd, off_t *offset, size_t size) {
    char buf[SW_BUFFER_SIZE_BIG];
    size_t readn = size > sizeof(buf) ? sizeof(buf) : size;
    ssize_t n = sw_pread(in_fd, buf, readn, *offset);

    if (n > 0) {
        ssize_t ret = write(out_fd, buf, n);
        if (ret < 0) {
            swoole_sys_warning("write() failed");
        } else {
            *offset += ret;
        }
        return ret;
    } else if (n == 0) {
        return 0;
    } else {
        swoole_sys_warning("pread() failed");
        return SW_ERR;
    }
}
#endif
