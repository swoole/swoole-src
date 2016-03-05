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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "swoole.h"

#ifdef HAVE_KQUEUE

#include <sys/uio.h>

int swoole_sendfile(int out_fd, int in_fd, off_t *offset, size_t size)
{
    off_t sent_bytes;
    int ret;

#ifdef __MACH__
    struct sf_hdtr hdtr;
    hdtr.headers = NULL;
    hdtr.hdr_cnt = 0;
    hdtr.trailers = NULL;
    hdtr.trl_cnt = 0;
#endif

    //sent_bytes = (off_t)size;
    swTrace("send file, out_fd:%d, in_fd:%d, offset:%d, size:%d", out_fd, in_fd, *offset, size);

    do_sendfile:
#ifdef __MACH__
    ret = sendfile(in_fd, out_fd, *offset, &size, &hdtr, 0);
#else
    ret = sendfile(in_fd, out_fd, *offset, size, 0, &sent_bytes, 0);
#endif
    if (ret == -1)
    {
        if (errno == EAGAIN)
        {
            *offset += sent_bytes;
            return sent_bytes;
        }
        else if (errno == EINTR)
        {
            goto do_sendfile;
        }
        else
        {
            return -1;
        }
    }
    else if (ret == 0)
    {
        *offset += size;
        return size;
    }
    else
    {
        swWarn("sendfile failed. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }
    return SW_OK;
}
#elif !defined(HAVE_SENDFILE)
int swoole_sendfile(int out_fd, int in_fd, off_t *offset, size_t size)
{
    char buf[SW_BUFFER_SIZE_BIG];
    int readn = size > sizeof(buf) ? sizeof(buf) : size;

    int ret;
    int n = pread(in_fd, buf, readn, *offset);

    if (n > 0)
    {
        ret = write(out_fd, buf, n);
        if (ret < 0)
        {
            swSysError("write() failed.");
        }
        else
        {
            *offset += ret;
        }
        return ret;
    }
    else
    {
        swSysError("pread() failed.");
        return SW_ERR;
    }
}
#endif
