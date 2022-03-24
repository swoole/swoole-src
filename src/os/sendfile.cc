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

#include "swoole.h"
#if defined(HAVE_KQUEUE) && defined(HAVE_SENDFILE)
#include <sys/socket.h>
#include <sys/uio.h>

int swoole_sendfile(int out_fd, int in_fd, off_t *offset, size_t size) {
    ssize_t ret;

#ifdef __MACH__
    struct sf_hdtr hdtr;
    hdtr.headers = nullptr;
    hdtr.hdr_cnt = 0;
    hdtr.trailers = nullptr;
    hdtr.trl_cnt = 0;
#else
    off_t sent_bytes;
#endif

_do_sendfile:
#ifdef __MACH__
    ret = sendfile(in_fd, out_fd, *offset, (off_t *) &size, &hdtr, 0);
#else
    ret = sendfile(in_fd, out_fd, *offset, size, 0, &sent_bytes, 0);
#endif

    // sent_bytes = (off_t)size;
    swoole_trace(
        "send file, ret:%d, out_fd:%d, in_fd:%d, offset:%jd, size:%zu", ret, out_fd, in_fd, (intmax_t) *offset, size);

#ifdef __MACH__
    *offset += size;
#else
    *offset += sent_bytes;
#endif

    if (ret == -1) {
        if (errno == EINTR) {
            goto _do_sendfile;
        } else {
            return ret;
        }
    } else if (ret == 0) {
        return size;
    } else {
        swoole_sys_warning("sendfile failed");
        return SW_ERR;
    }
    return SW_OK;
}
#elif !defined(HAVE_SENDFILE)
int swoole_sendfile(int out_fd, int in_fd, off_t *offset, size_t size) {
    char buf[SW_BUFFER_SIZE_BIG];
    size_t readn = size > sizeof(buf) ? sizeof(buf) : size;
    ssize_t n = pread(in_fd, buf, readn, *offset);

    if (n > 0) {
        ssize_t ret = write(out_fd, buf, n);
        if (ret < 0) {
            swoole_sys_warning("write() failed");
        } else {
            *offset += ret;
        }
        return ret;
    } else {
        swoole_sys_warning("pread() failed");
        return SW_ERR;
    }
}
#endif
