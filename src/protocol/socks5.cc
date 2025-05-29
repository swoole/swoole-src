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
#include "swoole_socket.h"

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

ssize_t Socks5Proxy::pack_connect_request(int socket_type) {
    char *p = buf;
    p[0] = SW_SOCKS5_VERSION_CODE;
    p[1] = 0x01;  // CONNECT command
    p[2] = 0x00;  // Reserved byte
    p += 3;

    if (dns_tunnel) {
        p[0] = 0x03;
        p[1] = target_host.length();
        p += 2;
        memcpy(p, target_host.c_str(), target_host.length());
        p += target_host.length();
    } else {
        network::Address target_addr;
        if (!target_addr.assign(static_cast<SocketType>(socket_type), target_host, target_port, false)) {
            swoole_error_log(
                SW_LOG_NOTICE,
                SW_ERROR_SOCKS5_HANDSHAKE_FAILED,
                "When disable SOCKS5 proxy DNS tunnel connection, the destination host must be an IP address.");
            return SW_ERR;
        }
        if (network::Socket::is_inet4(static_cast<SocketType>(socket_type))) {
            p[0] = 0x01;  // IPv4 address type
            p += 1;
            memcpy(p, &target_addr.addr.inet_v4.sin_addr, sizeof(target_addr.addr.inet_v4.sin_addr));
            p += sizeof(target_addr.addr.inet_v4.sin_addr);
        } else if (network::Socket::is_inet6(static_cast<SocketType>(socket_type))) {
            p[0] = 0x04;  // IPv6 address type
            p += 1;
            memcpy(p, &target_addr.addr.inet_v6.sin6_addr, sizeof(target_addr.addr.inet_v6.sin6_addr));
            p += sizeof(target_addr.addr.inet_v6.sin6_addr);
        } else {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_HANDSHAKE_FAILED, "Unsupported socket type for SOCKS5");
            return SW_ERR;
        }
    }
    const auto _target_port = htons(target_port);
    memcpy(p, &_target_port, sizeof(_target_port));
    p += 2;
    return p - buf;
}
}  // namespace swoole
