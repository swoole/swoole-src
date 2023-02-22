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
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole_protocol.h"

#define SW_HTTP2_PRI_STRING "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

enum swHttp2ErrorCode {
    SW_HTTP2_ERROR_NO_ERROR = 0x0,
    SW_HTTP2_ERROR_PROTOCOL_ERROR = 0x1,
    SW_HTTP2_ERROR_INTERNAL_ERROR = 0x2,
    SW_HTTP2_ERROR_FLOW_CONTROL_ERROR = 0x3,
    SW_HTTP2_ERROR_SETTINGS_TIMEOUT = 0x4,
    SW_HTTP2_ERROR_STREAM_CLOSED = 0x5,
    SW_HTTP2_ERROR_FRAME_SIZE_ERROR = 0x6,
    SW_HTTP2_ERROR_REFUSED_STREAM = 0x7,
    SW_HTTP2_ERROR_CANCEL = 0x8,
    SW_HTTP2_ERROR_COMPRESSION_ERROR = 0x9,
    SW_HTTP2_ERROR_CONNECT_ERROR = 0xa,
    SW_HTTP2_ERROR_ENHANCE_YOUR_CALM = 0xb,
    SW_HTTP2_ERROR_INADEQUATE_SECURITY = 0xc,
    SW_HTTP2_ERROR_HTTP_1_1_REQUIRED = 0xd,
};

enum swHttp2FrameType {
    SW_HTTP2_TYPE_DATA = 0,
    SW_HTTP2_TYPE_HEADERS = 1,
    SW_HTTP2_TYPE_PRIORITY = 2,
    SW_HTTP2_TYPE_RST_STREAM = 3,
    SW_HTTP2_TYPE_SETTINGS = 4,
    SW_HTTP2_TYPE_PUSH_PROMISE = 5,
    SW_HTTP2_TYPE_PING = 6,
    SW_HTTP2_TYPE_GOAWAY = 7,
    SW_HTTP2_TYPE_WINDOW_UPDATE = 8,
    SW_HTTP2_TYPE_CONTINUATION = 9,
};

enum swHttp2FrameFlag {
    SW_HTTP2_FLAG_NONE = 0x00,
    SW_HTTP2_FLAG_ACK = 0x01,
    SW_HTTP2_FLAG_END_STREAM = 0x01,
    SW_HTTP2_FLAG_END_HEADERS = 0x04,
    SW_HTTP2_FLAG_PADDED = 0x08,
    SW_HTTP2_FLAG_PRIORITY = 0x20,
};

enum swHttp2SettingId {
    SW_HTTP2_SETTING_HEADER_TABLE_SIZE = 0x1,
    SW_HTTP2_SETTINGS_ENABLE_PUSH = 0x2,
    SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
    SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE = 0x4,
    SW_HTTP2_SETTINGS_MAX_FRAME_SIZE = 0x5,
    SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x6,
};

enum swHttp2StreamFlag {
    SW_HTTP2_STREAM_NORMAL = 0,
    SW_HTTP2_STREAM_REQUEST_END = 1 << 0,
    SW_HTTP2_STREAM_PIPELINE_REQUEST = 1 << 1,
    SW_HTTP2_STREAM_PIPELINE_RESPONSE = 1 << 2,
    SW_HTTP2_STREAM_USE_PIPELINE_READ = 1 << 3,
};

#define SW_HTTP2_FRAME_HEADER_SIZE 9
#define SW_HTTP2_SETTING_OPTION_SIZE 6
#define SW_HTTP2_SETTING_FRAME_SIZE (SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_SETTING_OPTION_SIZE * 6)
#define SW_HTTP2_FRAME_PING_PAYLOAD_SIZE 8

#define SW_HTTP2_RST_STREAM_SIZE 4
#define SW_HTTP2_PRIORITY_SIZE 5
#define SW_HTTP2_PING_SIZE 8
#define SW_HTTP2_RST_STREAM_SIZE 4
#define SW_HTTP2_GOAWAY_SIZE 8
#define SW_HTTP2_WINDOW_UPDATE_SIZE 4
#define SW_HTTP2_STREAM_ID_SIZE 4
#define SW_HTTP2_SETTINGS_PARAM_SIZE 6

#define swoole_http2_frame_trace_log(_trace_fn, _trace_str, ...)                                                       \
    swoole_trace_log(SW_TRACE_HTTP2,                                                                                   \
                     "%s [" SW_ECHO_GREEN "] frame"                                                                    \
                     "<length=%jd, flags=(%s), stream_id=%d> " _trace_str,                                             \
                     #_trace_fn,                                                                                       \
                     swoole::http2::get_type(type),                                                                    \
                     length,                                                                                           \
                     swoole::http2::get_flag_string(flags).c_str(),                                                    \
                     stream_id,                                                                                        \
                     ##__VA_ARGS__)

namespace swoole {
namespace http2 {

struct Settings {
    uint32_t header_table_size;
    uint32_t enable_push;
    uint32_t max_concurrent_streams;
    uint32_t init_window_size;
    uint32_t max_frame_size;
    uint32_t max_header_list_size;
};

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
struct Frame {
    uint32_t length : 24;
    uint32_t type : 8;
    uint32_t flags : 8;
    uint32_t rsv1 : 1;
    uint32_t identifier : 31;
    char data[0];
};

static sw_inline ssize_t get_length(const char *buf) {
    return (((uint8_t) buf[0]) << 16) + (((uint8_t) buf[1]) << 8) + (uint8_t) buf[2];
}

void put_default_setting(enum swHttp2SettingId id, uint32_t value);
uint32_t get_default_setting(enum swHttp2SettingId id);
size_t pack_setting_frame(char *buf, const Settings &settings, bool server_side);
ssize_t get_frame_length(const Protocol *protocol, network::Socket *conn, PacketLength *pl);
int send_setting_frame(Protocol *protocol, network::Socket *conn);
const char *get_type(int type);
int get_type_color(int type);

static sw_inline void init_settings(Settings *settings) {
    settings->header_table_size = get_default_setting(SW_HTTP2_SETTING_HEADER_TABLE_SIZE);
    settings->enable_push = get_default_setting(SW_HTTP2_SETTINGS_ENABLE_PUSH);
    settings->max_concurrent_streams = get_default_setting(SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
    settings->init_window_size = get_default_setting(SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE);
    settings->max_frame_size = get_default_setting(SW_HTTP2_SETTINGS_MAX_FRAME_SIZE);
    settings->max_header_list_size = get_default_setting(SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE);
}

static inline const std::string get_flag_string(int __flags) {
    std::string str;
    if (__flags & SW_HTTP2_FLAG_ACK) {
        str.append("ACK|");
    }
    if (__flags & SW_HTTP2_FLAG_END_STREAM) {
        str.append("END_STREAM|");
    }
    if (__flags & SW_HTTP2_FLAG_END_HEADERS) {
        str.append("END_HEADERS|");
    }
    if (__flags & SW_HTTP2_FLAG_PADDED) {
        str.append("PADDED|");
    }
    if (__flags & SW_HTTP2_FLAG_PRIORITY) {
        str.append("PRIORITY|");
    }
    if (str.back() == '|') {
        return str.substr(0, str.length() - 1);
    } else {
        return "none";
    }
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
static sw_inline void set_frame_header(char *buffer, uint8_t type, uint32_t length, uint8_t flags, uint32_t stream_id) {
    buffer[0] = length >> 16;
    buffer[1] = length >> 8;
    buffer[2] = length;
    buffer[3] = type;
    buffer[4] = flags;
    *(uint32_t *) (buffer + 5) = htonl(stream_id);
}

}  // namespace http2
}  // namespace swoole
