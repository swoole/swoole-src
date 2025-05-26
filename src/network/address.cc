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
 +----------------------------------------------------------------------+
 */

#include "swoole_socket.h"

#include <regex>

static bool IN_IS_ADDR_LOOPBACK(const in_addr *a) {
    return a->s_addr == htonl(INADDR_LOOPBACK);
}

namespace swoole {
namespace network {

static thread_local char tmp_address[INET6_ADDRSTRLEN];

const char *Address::get_addr() const {
    if (type == SW_SOCK_TCP || type == SW_SOCK_UDP) {
        if (inet_ntop(AF_INET, &addr.inet_v4.sin_addr, tmp_address, sizeof(tmp_address))) {
            return tmp_address;
        }
    } else if (type == SW_SOCK_TCP6 || type == SW_SOCK_UDP6) {
        if (inet_ntop(AF_INET6, &addr.inet_v6.sin6_addr, tmp_address, sizeof(tmp_address))) {
            return tmp_address;
        }
    } else if (type == SW_SOCK_UNIX_STREAM || type == SW_SOCK_UNIX_DGRAM) {
        return addr.un.sun_path;
    }
    return "unknown";
}

bool Address::empty() const {
    return type == 0;
}

int Address::get_port() const {
    if (type == SW_SOCK_TCP || type == SW_SOCK_UDP) {
        return ntohs(addr.inet_v4.sin_port);
    } else if (type == SW_SOCK_TCP6 || type == SW_SOCK_UDP6) {
        return ntohs(addr.inet_v6.sin6_port);
    } else {
        return 0;
    }
}

void Address::set_port(int _port) {
    if (type == SW_SOCK_TCP || type == SW_SOCK_UDP) {
        addr.inet_v4.sin_port = htons(_port);
    } else if (type == SW_SOCK_TCP6 || type == SW_SOCK_UDP6) {
        addr.inet_v6.sin6_port = htons(_port);
    }
}

bool Address::assign(SocketType _type, const std::string &_host, int _port, bool _resolve_name) {
    type = _type;
    const char *host = _host.c_str();

    if (_port < 0 || _port > 65535) {
        swoole_set_last_error(SW_ERROR_BAD_PORT);
        return false;
    }

    if (Socket::is_inet4(_type)) {
        addr.inet_v4.sin_family = AF_INET;
        addr.inet_v4.sin_port = htons(_port);
        len = sizeof(addr.inet_v4);

        if (inet_pton(AF_INET, host, &addr.inet_v4.sin_addr.s_addr) != 1) {
            if (!_resolve_name) {
                swoole_set_last_error(SW_ERROR_BAD_HOST_ADDR);
                return false;
            }
            if (gethostbyname(AF_INET, host, (char *) &addr.inet_v4.sin_addr) < 0) {
                swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
                return false;
            }
        }
    } else if (Socket::is_inet6(_type)) {
        addr.inet_v6.sin6_family = AF_INET6;
        addr.inet_v6.sin6_port = htons(_port);
        len = sizeof(addr.inet_v6);
        if (inet_pton(AF_INET6, host, addr.inet_v6.sin6_addr.s6_addr) != 1) {
            if (!_resolve_name) {
                swoole_set_last_error(SW_ERROR_BAD_HOST_ADDR);
                return false;
            }
            if (gethostbyname(AF_INET6, host, (char *) &addr.inet_v6.sin6_addr) < 0) {
                swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
                return false;
            }
        }
    } else if (Socket::is_local(_type)) {
        if (_host.length() >= sizeof(addr.un.sun_path) - 1) {
            swoole_set_last_error(SW_ERROR_NAME_TOO_LONG);
            return false;
        }
        addr.un.sun_family = AF_UNIX;
        swoole_strlcpy(addr.un.sun_path, host, sizeof(addr.un.sun_path));
        addr.un.sun_path[sizeof(addr.un.sun_path) - 1] = 0;
        len = sizeof(addr.un.sun_path);
    } else {
        swoole_set_last_error(SW_ERROR_BAD_SOCKET_TYPE);
        return false;
    }

    return true;
}

const char *Address::type_str(SocketType type) {
    if (Socket::is_inet4(type)) {
        return "IPv4";
    }
    if (Socket::is_inet6(type)) {
        return "IPv6";
    }
    if (Socket::is_local(type)) {
        return "UnixSocket";
    }
    return "Unknown";
}

bool Address::assign(const std::string &url) {
    static const std::regex unix_pattern(R"(^(unix|udg)://(/[^?#]+))");
    static const std::regex inet4_pattern(R"(^(tcp|udp)://([^:\[]+):(\d+)$)");
    static const std::regex inet6_pattern(R"(^(tcp|udp)://\[([^\]]+)\]:(\d+)$)");
    std::smatch match;

    if (std::regex_match(url, match, unix_pattern)) {
        std::string proto = match[1];
        std::string path = match[2];
        type = proto == "unix" ? SW_SOCK_UNIX_STREAM : SW_SOCK_UNIX_DGRAM;
        return assign(type, path, 0);
    } else if (std::regex_match(url, match, inet4_pattern)) {
        std::string proto = match[1];
        std::string host = match[2];
        int port = std::stoi(match[3]);
        type = proto == "tcp" ? SW_SOCK_TCP : SW_SOCK_UDP;
        return assign(type, host, port);
    } else if (std::regex_match(url, match, inet6_pattern)) {
        std::string proto = match[1];
        std::string host = match[2];
        int port = std::stoi(match[3]);
        type = proto == "tcp" ? SW_SOCK_TCP6 : SW_SOCK_UDP6;
        return assign(type, host, port);
    } else {
        swoole_error_log(SW_LOG_NOTICE, SW_ERROR_BAD_HOST_ADDR, "Invalid address '%s'", url.c_str());
        return false;
    }
}

bool Address::is_loopback_addr() {
    if (type == SW_SOCK_TCP || type == SW_SOCK_UDP) {
        return IN_IS_ADDR_LOOPBACK(&addr.inet_v4.sin_addr);
    } else if (type == SW_SOCK_TCP6 || type == SW_SOCK_UDP6) {
        return IN6_IS_ADDR_LOOPBACK(&addr.inet_v6.sin6_addr);
    }
    return false;
}

}  // namespace network
}  // namespace swoole
