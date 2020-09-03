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
namespace async {

struct Event {
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
    swSocket *pipe_socket;
    double timestamp;
    void *object;
    void (*handler)(Event *event);
    void (*callback)(Event *event);
};

typedef void (*Handler)(Event *event);

ssize_t dispatch(const Event *request);
Event *dispatch2(const Event *request);
int cancel(int task_id);
int callback(Reactor *reactor, swEvent *_event);
size_t thread_count();

#ifdef SW_DEBUG
void notify_one();
#endif

void handler_fread(Event *event);
void handler_fwrite(Event *event);
void handler_read(Event *event);
void handler_write(Event *event);
void handler_gethostbyname(Event *event);
void handler_getaddrinfo(Event *event);
void handler_fgets(Event *event);
void handler_read_file(Event *event);
void handler_write_file(Event *event);

}  // namespace async
};  // namespace swoole
