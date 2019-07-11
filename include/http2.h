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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#ifndef SW_HTTP2_H_
#define SW_HTTP2_H_

SW_EXTERN_C_BEGIN

#define SW_HTTP2_PRI_STRING  "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

enum swHttp2_error_code
{
    SW_HTTP2_ERROR_NO_ERROR = 0,
    SW_HTTP2_ERROR_PROTOCOL_ERROR = 1,
    SW_HTTP2_ERROR_INTERNAL_ERROR = 2,
    SW_HTTP2_ERROR_FLOW_CONTROL_ERROR = 3,
    SW_HTTP2_ERROR_SETTINGS_TIMEOUT = 4,
    SW_HTTP2_ERROR_STREAM_CLOSED = 5,
    SW_HTTP2_ERROR_FRAME_SIZE_ERROR = 6,
    SW_HTTP2_ERROR_REFUSED_STREAM = 7,
    SW_HTTP2_ERROR_CANCEL = 8,
    SW_HTTP2_ERROR_COMPRESSION_ERROR = 9,
    SW_HTTP2_ERROR_CONNECT_ERROR = 10,
    SW_HTTP2_ERROR_ENHANCE_YOUR_CALM = 11,
    SW_HTTP2_ERROR_INADEQUATE_SECURITY = 12,
};

enum swHttp2_frame_type
{
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

enum swHttp2FrameFlag
{
    SW_HTTP2_FLAG_NONE = 0x00,
    SW_HTTP2_FLAG_ACK = 0x01,
    SW_HTTP2_FLAG_END_STREAM = 0x01,
    SW_HTTP2_FLAG_END_HEADERS = 0x04,
    SW_HTTP2_FLAG_PADDED = 0x08,
    SW_HTTP2_FLAG_PRIORITY = 0x20,
};

enum swHttp2_setting_id
{
    SW_HTTP2_SETTING_HEADER_TABLE_SIZE       = 0x1,
    SW_HTTP2_SETTINGS_ENABLE_PUSH            = 0x2,
    SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
    SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE       = 0x4,
    SW_HTTP2_SETTINGS_MAX_FRAME_SIZE         = 0x5,
    SW_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE   = 0x6,
};

enum swHttp2_stream_type
{
    SW_HTTP2_STREAM_NORMAL      = 0,
    SW_HTTP2_STREAM_PIPELINE    = 1,
};

#define SW_HTTP2_FRAME_HEADER_SIZE            9
#define SW_HTTP2_SETTING_OPTION_SIZE          6
#define SW_HTTP2_FRAME_PING_PAYLOAD_SIZE      8

#define SW_HTTP2_RST_STREAM_SIZE              4
#define SW_HTTP2_PRIORITY_SIZE                5
#define SW_HTTP2_PING_SIZE                    8
#define SW_HTTP2_RST_STREAM_SIZE              4
#define SW_HTTP2_GOAWAY_SIZE                  8
#define SW_HTTP2_WINDOW_UPDATE_SIZE           4
#define SW_HTTP2_STREAM_ID_SIZE               4
#define SW_HTTP2_SETTINGS_PARAM_SIZE          6

#define swHttp2FrameTraceLogFlags \
    ((flags & SW_HTTP2_FLAG_ACK) ? "\nEND_ACK |" : ""), \
    ((flags & SW_HTTP2_FLAG_END_STREAM) ? "\nEND_STREAM |" : ""), \
    ((flags & SW_HTTP2_FLAG_END_HEADERS) ? "\nEND_HEADERS |" : ""), \
    ((flags & SW_HTTP2_FLAG_PADDED) ? "\nEND_PADDED |" : ""), \
    ((flags & SW_HTTP2_FLAG_PRIORITY) ? "\nEND_PRIORITY |" : "")

#define swHttp2FrameTraceLog(recv, str, ...) \
    swTraceLog( \
        SW_TRACE_HTTP2, \
        "\nrecv [" "\e[3" "%d" "m" "%s" "\e[0m" "] frame <length=%jd, flags=%d, stream_id=%d> " str "%s%s%s%s%s", \
        swHttp2_get_type_color(type), swHttp2_get_type(type), length, flags, stream_id, \
        ##__VA_ARGS__, \
        swHttp2FrameTraceLogFlags \
    );

typedef struct _swHttp2_settings
{
    uint32_t header_table_size;
    uint32_t window_size;
    uint32_t max_concurrent_streams;
    uint32_t max_frame_size;
    uint32_t max_header_list_size;
} swHttp2_settings;

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
typedef struct _swHttp2_frame
{
    uint32_t length :24;
    uint32_t type :8;
    uint32_t flags :8;
    uint32_t rsv1 :1;
    uint32_t identifier :31;
    char data[0];
} swHttp2_frame;

static sw_inline ssize_t swHttp2_get_length(char *buf)
{
    return (((uint8_t) buf[0]) << 16) + (((uint8_t) buf[1]) << 8) + (uint8_t) buf[2];
}

ssize_t swHttp2_get_frame_length(swProtocol *protocol, swConnection *conn, char *buf, uint32_t length);
int swHttp2_send_setting_frame(swProtocol *protocol, swConnection *conn);
char* swHttp2_get_type(int type);
int swHttp2_get_type_color(int type);

static sw_inline void swHttp2_init_settings(swHttp2_settings *settings)
{
    settings->header_table_size = SW_HTTP2_DEFAULT_HEADER_TABLE_SIZE;
    settings->window_size = SW_HTTP2_DEFAULT_WINDOW_SIZE;
    settings->max_concurrent_streams = SW_HTTP2_MAX_MAX_CONCURRENT_STREAMS;
    settings->max_frame_size = SW_HTTP2_MAX_MAX_FRAME_SIZE;
    settings->max_header_list_size = SW_HTTP2_DEFAULT_MAX_HEADER_LIST_SIZE;
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
static sw_inline void swHttp2_set_frame_header(char *buffer, uint8_t type, uint32_t length, uint8_t flags, uint32_t stream_id)
{
    buffer[0] = length >> 16;
    buffer[1] = length >> 8;
    buffer[2] = length;
    buffer[3] = type;
    buffer[4] = flags;
    *(uint32_t *) (buffer + 5) = htonl(stream_id);
}

SW_EXTERN_C_END

#endif /* SW_HTTP2_H_ */
