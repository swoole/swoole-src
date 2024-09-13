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

namespace swoole {
namespace network {

static thread_local char tmp_address[INET6_ADDRSTRLEN];

const char *Address::get_addr() {
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

int Address::get_port() {
    if (type == SW_SOCK_TCP || type == SW_SOCK_UDP) {
        return ntohs(addr.inet_v4.sin_port);
    } else if (type == SW_SOCK_TCP6 || type == SW_SOCK_UDP6) {
        return ntohs(addr.inet_v6.sin6_port);
    } else {
        return 0;
    }
}

bool Address::assign(SocketType _type, const std::string &_host, int _port) {
    type = _type;
    const char *host = _host.c_str();
    if (_type == SW_SOCK_TCP || _type == SW_SOCK_UDP) {
        addr.inet_v4.sin_family = AF_INET;
        addr.inet_v4.sin_port = htons(_port);
        len = sizeof(addr.inet_v4);
        if (inet_pton(AF_INET, host, &addr.inet_v4.sin_addr.s_addr)) {
            return true;
        }
    } else if (_type == SW_SOCK_TCP6 || _type == SW_SOCK_UDP6) {
        addr.inet_v6.sin6_family = AF_INET6;
        addr.inet_v6.sin6_port = htons(_port);
        len = sizeof(addr.inet_v6);
        if (inet_pton(AF_INET6, host, addr.inet_v6.sin6_addr.s6_addr)) {
            return true;
        }
    } else if (_type == SW_SOCK_UNIX_STREAM || _type == SW_SOCK_UNIX_DGRAM) {
        addr.un.sun_family = AF_UNIX;
        swoole_strlcpy(addr.un.sun_path, host, sizeof(addr.un.sun_path));
        addr.un.sun_path[sizeof(addr.un.sun_path) - 1] = 0;
        len = sizeof(addr.un.sun_path);
        return true;
    }

    return false;
}

bool Address::assign(const std::string &url) {
    std::regex pattern(R"((tcp|udp)://([\[\]a-zA-Z0-9.-:]+):(\d+))");
    std::smatch match;

    if (std::regex_match(url, match, pattern)) {
        std::string host = match[2];
        auto port = std::stoi(match[3]);

        if (host[0] == '[') {
        	type = SW_SOCK_TCP6;
        	addr.inet_v6.sin6_family = AF_INET6;
            addr.inet_v6.sin6_port = htons(port);
            len = sizeof(addr.inet_v6);
            if (inet_pton(AF_INET6, host.substr(1, host.size() - 2).c_str(), addr.inet_v6.sin6_addr.s6_addr)) {
                return true;
            }
        } else {
        	type = SW_SOCK_TCP;
        	addr.inet_v4.sin_family = AF_INET;
            addr.inet_v4.sin_port = htons(port);
    		len = sizeof(addr.inet_v4);
			if (!inet_pton(AF_INET, host.c_str(), &addr.inet_v4.sin_addr.s_addr)) {
		        if (gethostbyname(AF_INET, host.c_str(), (char *) &addr.inet_v4.sin_addr.s_addr) < 0) {
		            swoole_set_last_error(SW_ERROR_DNSLOOKUP_RESOLVE_FAILED);
		            return false;
		        }
			}
			return true;
        }
    }

	swoole_error_log(SW_LOG_NOTICE, SW_ERROR_BAD_HOST_ADDR, "Invalid address['%s']", url.c_str());
	return false;
}

}  // namespace network
}  // namespace swoole
