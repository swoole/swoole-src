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
  | Author: Xinyu Zhu  <xyzhu1120@gmail.com>                             |
  |         shiguangqi <shiguangqi2008@gmail.com>                        |
  |         Twosee  <twose@qq.com>                                       |
  |         Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
 */

#pragma once

#include "swoole.h"
#include "swoole_lock.h"

namespace swoole {

enum ChannelFlag {
    SW_CHAN_LOCK = 1u << 1,
    SW_CHAN_NOTIFY = 1u << 2,
    SW_CHAN_SHM = 1u << 3,
};

struct Channel {
    off_t head;
    off_t tail;
    size_t size;
    char head_tag;
    char tail_tag;
    int num;
    int max_num;
    /**
     * Data length, excluding structure
     */
    size_t bytes;
    int flags;
    int maxlen;
    /**
     * memory point
     */
    void *mem;
    Lock *lock;
    Pipe *notify_pipe;

    inline bool empty() {
        return num == 0;
    }
    inline bool full() {
        return ((head == tail && tail_tag != head_tag) || (bytes + sizeof(int) * num == size));
    }
    int pop(void *out_buf, int buffer_length);
    int push(const void *in_data, int data_length);
    int out(void *out_buf, int buffer_length);
    int in(const void *in_data, int data_length);
    int peek(void *out, int buffer_length);
    int wait();
    int notify();
    void destroy();
    void print();
    inline int count() {
        return num;
    }
    inline int get_bytes() {
        return bytes;
    }
    static Channel *make(size_t size, size_t maxlen, int flags);
};
}  // namespace swoole
