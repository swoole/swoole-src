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
 | Author: Tianfeng Han  <rango@swoole.com>                             |
 +----------------------------------------------------------------------+
 */

#pragma once

#include <vector>
#include <string>

#ifndef O_DIRECT
#define O_DIRECT 040000
#endif

namespace swoole {

enum AsyncFlag {
    SW_AIO_WRITE_FSYNC = 1u << 1,
    SW_AIO_EOF = 1u << 2,
};

struct AsyncRequest {
    virtual ~AsyncRequest() = default;
};

struct AsyncEvent {
    size_t task_id;
    uint8_t canceled;
    int error;
    /**
     * input & output
     */
    std::shared_ptr<AsyncRequest> data;
    /**
     * output
     */
    ssize_t retval;
    /**
     * internal use only
     */
    network::Socket *pipe_socket;
    double timestamp;
    void *object;
    void (*handler)(AsyncEvent *event);
    void (*callback)(AsyncEvent *event);

    bool catch_error() {
        return (error == SW_ERROR_AIO_TIMEOUT || error == SW_ERROR_AIO_CANCELED);
    }
};

struct GethostbynameRequest : public AsyncRequest {
    std::string name;
    int family;
    char *addr;
    size_t addr_len;

    GethostbynameRequest(std::string _name, int _family) : name(std::move(_name)), family(_family) {
        addr_len = _family == AF_INET6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN;
        addr = new char[addr_len];
    }

    ~GethostbynameRequest() override {
        delete[] addr;
    }
};

struct GetaddrinfoRequest : public AsyncRequest {
    std::string hostname;
    std::string service;
    int family;
    int socktype;
    int protocol;
    int error;
    std::vector<struct sockaddr_in6> results;
    int count;

    void parse_result(std::vector<std::string> &retval);

    GetaddrinfoRequest(std::string _hostname, int _family, int _socktype, int _protocol, std::string _service)
        : hostname(std::move(_hostname)),
          service(std::move(_service)) {
        family =_family;
        socktype =_socktype;
        protocol =_protocol;
        count = 0;
        error = 0;
    }

    ~GetaddrinfoRequest() override = default;
};

class AsyncThreads {
  public:
    size_t task_num = 0;
    Pipe *pipe = nullptr;
    std::shared_ptr<async::ThreadPool> pool;
    network::Socket *read_socket = nullptr;
    network::Socket *write_socket = nullptr;

    AsyncThreads();
    ~AsyncThreads();

    size_t get_task_num() {
        return task_num;
    }

    size_t get_queue_size();
    size_t get_worker_num();
    void notify_one();

    static int callback(Reactor *reactor, Event *event);
};

namespace async {

typedef void (*Handler)(AsyncEvent *event);

AsyncEvent *dispatch(const AsyncEvent *request);

void handler_gethostbyname(AsyncEvent *event);
void handler_getaddrinfo(AsyncEvent *event);

}  // namespace async
};  // namespace swoole
