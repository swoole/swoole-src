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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"
#include "swoole_socket.h"

namespace swoole {
struct Pipe {
    void *object;
    int blocking;
    double timeout;

    network::Socket *master_socket;
    network::Socket *worker_socket;

    ssize_t (*read)(Pipe *, void *_buf, size_t length);
    ssize_t (*write)(Pipe *, const void *_buf, size_t length);
    void (*close)(Pipe *);

    network::Socket *get_socket(bool _master) {
        return _master ? master_socket : worker_socket;
    }
    
    void set_timeout(double _timeout) {
        timeout = _timeout;
    }
};
}  // namespace swoole

enum swPipe_close_which {
    SW_PIPE_CLOSE_MASTER = 1,
    SW_PIPE_CLOSE_WORKER = 2,
    SW_PIPE_CLOSE_READ = 3,
    SW_PIPE_CLOSE_WRITE = 4,
    SW_PIPE_CLOSE_BOTH = 0,
};

int swPipeBase_create(swPipe *p, int blocking);
int swPipeEventfd_create(swPipe *p, int blocking, int semaphore, int timeout);
int swPipeUnsock_create(swPipe *p, int blocking, int protocol);
int swPipeUnsock_close_ext(swPipe *p, int which);
int swPipe_init_socket(swPipe *p, int master_fd, int worker_fd, int blocking);

static inline int swPipeNotify_auto(swPipe *p, int blocking, int semaphore) {
#ifdef HAVE_EVENTFD
    return swPipeEventfd_create(p, blocking, semaphore, 0);
#else
    return swPipeBase_create(p, blocking);
#endif
}
