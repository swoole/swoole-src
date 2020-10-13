/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2018 The Swoole Group                             |
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

#pragma once

#include <vector>
#include <string>

#ifndef O_DIRECT
#define O_DIRECT 040000
#endif

enum flag {
    SW_AIO_WRITE_FSYNC = 1u << 1,
    SW_AIO_EOF = 1u << 2,
};

namespace swoole {

struct AsyncEvent {
    int fd;
    size_t task_id;
    uint8_t lock;
    uint8_t canceled;
    /**
     * input & output
     */
    uint16_t flags;
    off_t offset;
    size_t nbytes;
    void *buf;
    void *req;
    /**
     * output
     */
    ssize_t ret;
    int error;
    /**
     * internal use only
     */
    network::Socket *pipe_socket;
    double timestamp;
    void *object;
    void (*handler)(AsyncEvent *event);
    void (*callback)(AsyncEvent *event);
};

namespace async {

typedef void (*Handler)(AsyncEvent *event);

ssize_t dispatch(const AsyncEvent *request);
AsyncEvent *dispatch2(const AsyncEvent *request);
int cancel(int task_id);
int callback(Reactor *reactor, swEvent *_event);
size_t thread_count();

#ifdef SW_DEBUG
void notify_one();
#endif

void handler_gethostbyname(AsyncEvent *event);
void handler_getaddrinfo(AsyncEvent *event);

}  // namespace async
};  // namespace swoole
