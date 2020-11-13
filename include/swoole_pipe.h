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

class Pipe {
  protected:
    bool blocking;
    double timeout;

    /**
     * master : socks[1]
     * worker : socks[0]
     */
    int socks[2];
    /**
     * master pipe is closed
     */
    bool pipe_master_closed;
    /**
     * worker pipe is closed
     */
    bool pipe_worker_closed;

    network::Socket *master_socket;
    network::Socket *worker_socket;
    bool init_socket(int master_fd, int worker_fd);

 public:
    Pipe(bool blocking);
    virtual ssize_t read(void *_buf, size_t length);
    virtual ssize_t write(const void *_buf, size_t length);
    virtual bool close(int which = 0);
    virtual ~Pipe();

    network::Socket *get_socket(bool _master) {
        return _master ? master_socket : worker_socket;
    }
    
    bool ready() {
        return master_socket != nullptr;
    }

    void set_timeout(double _timeout) {
        timeout = _timeout;
    }
};

class UnixSocket : public Pipe {
  public:
    UnixSocket(bool blocking, int protocol);
    ~UnixSocket();

    ssize_t read(void *_buf, size_t length) override;
    ssize_t write(const void *_buf, size_t length) override;
};

}  // namespace swoole

enum swPipe_close_which {
    SW_PIPE_CLOSE_MASTER = 1,
    SW_PIPE_CLOSE_WORKER = 2,
    SW_PIPE_CLOSE_READ = 3,
    SW_PIPE_CLOSE_WRITE = 4,
    SW_PIPE_CLOSE_BOTH = 0,
};
