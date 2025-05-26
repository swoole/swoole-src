/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2017 The Swoole Group                             |
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

#include "swoole_proxy.h"

namespace swoole {
const char *Socks5Proxy::strerror(int code) {
    switch (code) {
    case 0x01:
        return "General failure";
    case 0x02:
        return "Connection not allowed by ruleset";
    case 0x03:
        return "Network unreachable";
    case 0x04:
        return "Host unreachable";
    case 0x05:
        return "Connection refused by destination host";
    case 0x06:
        return "TTL expired";
    case 0x07:
        return "command not supported / protocol error";
    case 0x08:
        return "address type not supported";
    default:
        return "Unknown error";
    }
}

Socks5Proxy *Socks5Proxy::create(const std::string &host, int port, const std::string &user, const std::string &pwd) {
    auto socks5_proxy = new Socks5Proxy();
    socks5_proxy->host = host;
    socks5_proxy->port = port;
    socks5_proxy->dns_tunnel = 1;
    if (!user.empty() && !pwd.empty()) {
        socks5_proxy->method = SW_SOCKS5_METHOD_AUTH;
        socks5_proxy->username = user;
        socks5_proxy->password = pwd;
    }
    return socks5_proxy;
}
}  // namespace swoole
