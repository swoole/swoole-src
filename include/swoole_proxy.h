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

#pragma once

#include <string>
#include <cstdint>

#define SW_SOCKS5_VERSION_CODE 0x05

enum swHttpProxyState {
    SW_HTTP_PROXY_STATE_WAIT = 0,
    SW_HTTP_PROXY_STATE_HANDSHAKE,
    SW_HTTP_PROXY_STATE_READY,
};

enum swSocks5State {
    SW_SOCKS5_STATE_WAIT = 0,
    SW_SOCKS5_STATE_HANDSHAKE,
    SW_SOCKS5_STATE_AUTH,
    SW_SOCKS5_STATE_CONNECT,
    SW_SOCKS5_STATE_READY,
};

enum swSocks5Method {
    SW_SOCKS5_METHOD_AUTH = 0x02,
};

namespace swoole {
struct HttpProxy {
    uint8_t state;
    uint8_t dont_handshake;
    int proxy_port;
    std::string proxy_host;
    std::string username;
    std::string password;
    std::string target_host;
    int target_port;
    char buf[512];

    std::string get_auth_str();
};

struct Socks5Proxy {
    std::string host;
    int port;
    uint8_t state;
    uint8_t version;
    uint8_t method;
    uint8_t dns_tunnel;
    std::string username;
    std::string password;
    std::string target_host;
    int target_port;
    char buf[600];

    static const char *strerror(int code);

    static void pack(char *buf, int method) {
        buf[0] = SW_SOCKS5_VERSION_CODE;
        buf[1] = 0x01;
        buf[2] = method;
    }
};
}  // namespace swoole
