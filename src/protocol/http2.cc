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

#include "swoole.h"
#include "swoole_socket.h"
#include "swoole_http2.h"

using swoole::PacketLength;
using swoole::Protocol;
using swoole::network::Socket;

namespace swoole {
namespace http2 {

int send_setting_frame(Protocol *protocol, Socket *_socket) {
    char setting_frame[SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_SETTING_OPTION_SIZE * 3];
    char *p = setting_frame;
    uint16_t id;
    uint32_t value;

    set_frame_header(p, SW_HTTP2_TYPE_SETTINGS, SW_HTTP2_SETTING_OPTION_SIZE * 3, 0, 0);
    p += SW_HTTP2_FRAME_HEADER_SIZE;

    id = htons(SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
    memcpy(p, &id, sizeof(id));
    value = htonl(SW_HTTP2_MAX_MAX_CONCURRENT_STREAMS);
    memcpy(p + 2, &value, sizeof(value));
    p += SW_HTTP2_SETTING_OPTION_SIZE;

    id = htons(SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE);
    memcpy(p, &id, sizeof(id));
    value = htonl(SW_HTTP2_DEFAULT_WINDOW_SIZE);
    memcpy(p + 2, &value, sizeof(value));
    p += SW_HTTP2_SETTING_OPTION_SIZE;

    id = htons(SW_HTTP2_SETTINGS_MAX_FRAME_SIZE);
    memcpy(p, &id, sizeof(id));
    value = htonl(SW_HTTP2_MAX_MAX_FRAME_SIZE);
    memcpy(p + 2, &value, sizeof(value));

    return _socket->send(setting_frame, sizeof(setting_frame), 0);
}

/**
 +-----------------------------------------------+
 |                 Length (24)                   |
 +---------------+---------------+---------------+
 |   Type (8)    |   Flags (8)   |
 +-+-------------+---------------+-------------------------------+
 |R|                 Stream Identifier (31)                      |
 +=+=============================================================+
 |                   Frame Payload (0...)                      ...
 +---------------------------------------------------------------+
 */
ssize_t get_frame_length(const Protocol *protocol, Socket *conn, PacketLength *pl) {
    if (pl->buf_size < SW_HTTP2_FRAME_HEADER_SIZE) {
        return 0;
    }
    return get_length(pl->buf) + SW_HTTP2_FRAME_HEADER_SIZE;
}

const char *get_type(int type) {
    switch (type) {
    case SW_HTTP2_TYPE_DATA:
        return "DATA";
    case SW_HTTP2_TYPE_HEADERS:
        return "HEADERS";
    case SW_HTTP2_TYPE_PRIORITY:
        return "PRIORITY";
    case SW_HTTP2_TYPE_RST_STREAM:
        return "RST_STREAM";
    case SW_HTTP2_TYPE_SETTINGS:
        return "SETTINGS";
    case SW_HTTP2_TYPE_PUSH_PROMISE:
        return "PUSH_PROMISE";
    case SW_HTTP2_TYPE_PING:
        return "PING";
    case SW_HTTP2_TYPE_GOAWAY:
        return "GOAWAY";
    case SW_HTTP2_TYPE_WINDOW_UPDATE:
        return "WINDOW_UPDATE";
    case SW_HTTP2_TYPE_CONTINUATION:
        return "CONTINUATION";
    default:
        return "UNKOWN";
    }
}

int get_type_color(int type) {
    switch (type) {
    case SW_HTTP2_TYPE_DATA:
    case SW_HTTP2_TYPE_WINDOW_UPDATE:
        return SW_COLOR_MAGENTA;
    case SW_HTTP2_TYPE_HEADERS:
    case SW_HTTP2_TYPE_SETTINGS:
    case SW_HTTP2_TYPE_PUSH_PROMISE:
    case SW_HTTP2_TYPE_CONTINUATION:
        return SW_COLOR_GREEN;
    case SW_HTTP2_TYPE_PING:
    case SW_HTTP2_TYPE_PRIORITY:
        return SW_COLOR_WHITE;
    case SW_HTTP2_TYPE_RST_STREAM:
    case SW_HTTP2_TYPE_GOAWAY:
    default:
        return SW_COLOR_RED;
    }
}

}  // namespace http2
}  // namespace swoole
