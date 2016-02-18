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

#ifdef __cplusplus
extern "C"
{
#endif

enum swHttp2ErrorCode
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

enum swHttp2FrameType
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

/**
0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | R |     Length (14)           |   Type (8)    |   Flags (8)   |
 +-+-+-----------+---------------+-------------------------------+
 |R|                 Stream Identifier (31)                      |
 +=+=============================================================+
 |                   Frame Payload (0...)                      ...
 +---------------------------------------------------------------+
 */
typedef struct
{
    uint32_t rsv1 :2;
    uint32_t length :14;
    uint32_t type :8;
    uint32_t flags :4;
    uint32_t rsv2 :1;
    uint32_t identifier :31;
    char data[0];
} swHttp2_frame;

int swHttp2_get_frame_length(swProtocol *protocol, swConnection *conn, char *buf, uint32_t length);

#ifdef __cplusplus
}
#endif

#endif /* SW_HTTP2_H_ */
