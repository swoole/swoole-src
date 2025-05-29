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

Socks5Proxy *Socks5Proxy::create(
    int socket_type, const std::string &host, int port, const std::string &user, const std::string &pwd) {
    if (user.length() > 250 || pwd.length() > 250) {
        swoole_error_log(SW_LOG_NOTICE,
                         SW_ERROR_SOCKS5_AUTH_FAILED,
                         "SOCKS5 username or password is too long, max length is 250 bytes");
        return nullptr;
    }
    auto socks5_proxy = new Socks5Proxy();
    socks5_proxy->host = host;
    socks5_proxy->port = port;
    socks5_proxy->dns_tunnel = 1;
    socks5_proxy->socket_type = socket_type;
    if (!user.empty() && !pwd.empty()) {
        socks5_proxy->username = user;
        socks5_proxy->password = pwd;
    }
    return socks5_proxy;
}

ssize_t Socks5Proxy::pack_negotiate_request() {
    char *p = buf;
    p[0] = SW_SOCKS5_VERSION_CODE;  // Version
    p[1] = 0x01;
    method = username.empty() ? SW_SOCKS5_METHOD_NO_AUTH : SW_SOCKS5_METHOD_AUTH;
    p[2] = method;
    return 3;
}

ssize_t Socks5Proxy::pack_auth_request() {
    char *p = buf;
    // username
    p[0] = 0x01;
    p[1] = username.length();
    p += 2;
    if (!username.empty()) {
        memcpy(p, username.c_str(), username.length());
        p += username.length();
    }
    // password
    p[0] = password.length();
    p += 1;
    if (!password.empty()) {
        memcpy(p, password.c_str(), password.length());
        p += password.length();
    }
    return p - buf;
}

bool Socks5Proxy::handshake(const char *rbuf,
                            size_t rlen,
                            const std::function<ssize_t(const char *buf, size_t len)> &send_fn) {
    if (rlen < 2) {
        swoole_error_log(
            SW_LOG_NOTICE, SW_ERROR_SOCKS5_HANDSHAKE_FAILED, "SOCKS5 handshake failed, data length is too short");
        return false;
    }

    const uchar resp_version = rbuf[0];
    const uchar resp_result = rbuf[1];

    if (state == SW_SOCKS5_STATE_HANDSHAKE) {
        if (resp_version != SW_SOCKS5_VERSION_CODE) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported");
            return false;
        }
        if (method != resp_result) {
            swoole_error_log(
                SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_METHOD, "SOCKS authentication method is not supported");
            return false;
        }
        // authenticate request
        if (method == SW_SOCKS5_METHOD_AUTH) {
            const auto len = pack_auth_request();
            state = SW_SOCKS5_STATE_AUTH;
            return send_fn(buf, len) == len;
        }
        // send connect request
        else {
        _send_connect_request:
            state = SW_SOCKS5_STATE_CONNECT;
            const auto len = pack_connect_request();
            if (len < 0) {
                return false;
            }
            return send_fn(buf, len) == len;
        }
    } else if (state == SW_SOCKS5_STATE_AUTH) {
        if (resp_version != 0x01) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported");
            return false;
        }
        if (resp_result != 0) {
            swoole_error_log(
                SW_LOG_NOTICE, SW_ERROR_SOCKS5_AUTH_FAILED, "SOCKS username/password authentication failed");
            return false;
        }
        goto _send_connect_request;
    } else if (state == SW_SOCKS5_STATE_CONNECT) {
        if (resp_version != SW_SOCKS5_VERSION_CODE) {
            swoole_error_log(SW_LOG_NOTICE, SW_ERROR_SOCKS5_UNSUPPORT_VERSION, "SOCKS version is not supported");
            return false;
        }
#if 0
        uchar reg = recv_data[2];
        uchar type = recv_data[3];
        uint32_t ip = *(uint32_t *) (recv_data + 4);
        uint16_t port = *(uint16_t *) (recv_data + 8);
#endif
        if (resp_result == 0) {
            state = SW_SOCKS5_STATE_READY;
            return true;
        } else {
            swoole_error_log(SW_LOG_NOTICE,
                             SW_ERROR_SOCKS5_SERVER_ERROR,
                             "Socks5 server error, reason :%s",
                             Socks5Proxy::strerror(resp_result));
            return false;
        }
    }
    return true;
}

ssize_t Socks5Proxy::pack_connect_request() {
    char *p = buf;
    p[0] = SW_SOCKS5_VERSION_CODE;
    p[1] = 0x01;  // CONNECT command
    p[2] = 0x00;  // Reserved byte
    p += 3;

    if (dns_tunnel) {
        if (host.length() > 480) {
            swoole_error_log(
                SW_LOG_NOTICE, SW_ERROR_SOCKS5_AUTH_FAILED, "SOCKS5 host is too long, max length is 480 bytes");
            return -1;
        }
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
