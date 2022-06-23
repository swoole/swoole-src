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
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"

#include <sys/types.h>

namespace swoole {

struct QueueNode {
    long mtype;                      /* type of received/sent message */
    char mdata[sizeof(EventData)];   /* text of the message */
};

class MsgQueue {
  private:
    bool blocking_;
    int msg_id_;
    key_t msg_key_;
    int flags_;
    int perms_;
  public:
    explicit MsgQueue(key_t msg_key, bool blocking = true, int perms = 0);
    ~MsgQueue();

    bool ready() {
        return msg_id_ >= 0;
    }

    int get_id() {
        return msg_id_;
    }

    void set_blocking(bool blocking);
    bool set_capacity(size_t queue_bytes);
    bool push(QueueNode *in, size_t mdata_length);
    ssize_t pop(QueueNode *out, size_t mdata_size);
    bool stat(size_t *queue_num, size_t *queue_bytes);
    bool destroy();
};
}
