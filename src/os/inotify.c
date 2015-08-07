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
#include <sys/inotify.h>

int swInotify_init()
{
#ifdef HAVE_INOTIFY_INIT1
    int ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
#else
    int ifd = inotify_init();
#endif

    if (ifd < 0)
    {
        swSysError("inotify_init() failed.");
        return SW_ERR;
    }
    swSetNonBlock(ifd);

    return ifd;
}
