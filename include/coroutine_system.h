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

#pragma once

#include "coroutine.h"
#include <string>
#include <vector>

namespace swoole { namespace coroutine {
//-------------------------------------------------------------------------------
class System
{
public:
    static int sleep(double sec);
    static swString* read_file(const char *file, int lock);
    static ssize_t write_file(const char *file, char *buf, size_t length, int lock, int flags);
    static std::string gethostbyname(const std::string &hostname, int domain, double timeout = -1);
    static std::vector<std::string> getaddrinfo(
        const std::string &hostname, int family = AF_INET, int socktype = SOCK_STREAM, int protocol = IPPROTO_TCP,
        const std::string &service = "", double timeout = -1
    );
    static void set_dns_cache_expire(time_t expire);
    static void set_dns_cache_capacity(size_t capacity);
    static void clear_dns_cache();
    static bool socket_poll(std::unordered_map<int, socket_poll_fd> &fds, double timeout);
};
//-------------------------------------------------------------------------------
}}
