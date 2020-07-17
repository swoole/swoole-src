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

#pragma once

#include "http.h"

#define SW_WEBSOCKET_SEC_KEY_LEN 16
#define SW_WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define SW_WEBSOCKET_HEADER_LEN 2
#define SW_WEBSOCKET_MASK_LEN 4
#define SW_WEBSOCKET_MASK_DATA "258E"
#define SW_WEBSOCKET_EXT16_MAX_LEN 0xFFFF
#define SW_WEBSOCKET_EXT16_LENGTH 0x7E
#define SW_WEBSOCKET_EXT64_LENGTH 0x7F
#define SW_WEBSOCKET_CLOSE_CODE_LEN 2
#define SW_WEBSOCKET_CLOSE_REASON_MAX_LEN 125
#define SW_WEBSOCKET_OPCODE_MAX WEBSOCKET_OPCODE_PONG

enum swWebsocket_status {
    WEBSOCKET_STATUS_NONE = 0,
    WEBSOCKET_STATUS_CONNECTION = 1,
    WEBSOCKET_STATUS_HANDSHAKE = 2,
    WEBSOCKET_STATUS_ACTIVE = 3,
    WEBSOCKET_STATUS_CLOSING = 4,
};

enum swWebSocket_frame_flag {
    SW_WEBSOCKET_FLAG_FIN = 1 << 0, /* BC: must be 1 */
    SW_WEBSOCKET_FLAG_COMPRESS = 1 << 1,
    // readonly for user
    SW_WEBSOCKET_FLAG_RSV1 = 1 << 2,
    SW_WEBSOCKET_FLAG_RSV2 = 1 << 3,
    SW_WEBSOCKET_FLAG_RSV3 = 1 << 4,
    SW_WEBSOCKET_FLAG_MASK = 1 << 5,
    // for encoder/decoder
    SW_WEBSOCKET_FLAG_ENCODE_HEADER_ONLY = 1 << 6,
};

enum swWebSocket_frame_union_flag {
    SW_WEBSOCKET_FLAGS_ALL = /* used to prevent overflow  */
    SW_WEBSOCKET_FLAG_FIN | SW_WEBSOCKET_FLAG_RSV1 | SW_WEBSOCKET_FLAG_RSV2 | SW_WEBSOCKET_FLAG_RSV3 |
    SW_WEBSOCKET_FLAG_MASK | SW_WEBSOCKET_FLAG_COMPRESS
};

struct swWebSocket_frame_header {
    /**
     * fin:1 rsv1:1 rsv2:1 rsv3:1 opcode:4
     */
    uchar OPCODE :4;
    uchar RSV3 :1;
    uchar RSV2 :1;
    uchar RSV1 :1;
    uchar FIN :1;
    uchar LENGTH :7;
    uchar MASK :1;
};

struct swWebSocket_frame {
    swWebSocket_frame_header header;
    char mask_key[SW_WEBSOCKET_MASK_LEN];
    uint16_t header_length;
    size_t payload_length;
    char *payload;
};

#define WEBSOCKET_VERSION 13

enum swWebsocket_opcode {
    WEBSOCKET_OPCODE_CONTINUATION = 0x0,
    WEBSOCKET_OPCODE_TEXT = 0x1,
    WEBSOCKET_OPCODE_BINARY = 0x2,
    WEBSOCKET_OPCODE_CLOSE = 0x8,
    WEBSOCKET_OPCODE_PING = 0x9,
    WEBSOCKET_OPCODE_PONG = 0xa,
};

enum swWebsocket_close_reason {
    WEBSOCKET_CLOSE_NORMAL = 1000,
    WEBSOCKET_CLOSE_GOING_AWAY = 1001,
    WEBSOCKET_CLOSE_PROTOCOL_ERROR = 1002,
    WEBSOCKET_CLOSE_DATA_ERROR = 1003,
    WEBSOCKET_CLOSE_STATUS_ERROR = 1005,
    WEBSOCKET_CLOSE_ABNORMAL = 1006,
    WEBSOCKET_CLOSE_MESSAGE_ERROR = 1007,
    WEBSOCKET_CLOSE_POLICY_ERROR = 1008,
    WEBSOCKET_CLOSE_MESSAGE_TOO_BIG = 1009,
    WEBSOCKET_CLOSE_EXTENSION_MISSING = 1010,
    WEBSOCKET_CLOSE_SERVER_ERROR = 1011,
    WEBSOCKET_CLOSE_TLS = 1015,
};

static inline uchar swWebSocket_get_flags(swWebSocket_frame *frame) {
    uchar flags = 0;
    if (frame->header.FIN) {
        flags |= SW_WEBSOCKET_FLAG_FIN;
    }
    if (frame->header.RSV1) {
        flags |= SW_WEBSOCKET_FLAG_RSV1;
    }
    if (frame->header.RSV2) {
        flags |= SW_WEBSOCKET_FLAG_RSV2;
    }
    if (frame->header.RSV3) {
        flags |= SW_WEBSOCKET_FLAG_RSV3;
    }
    if (frame->header.MASK) {
        flags |= SW_WEBSOCKET_FLAG_MASK;
    }
    return flags;
}

static inline uchar swWebSocket_set_flags(uchar fin, uchar mask, uchar rsv1, uchar rsv2, uchar rsv3) {
    uchar flags = 0;
    if (fin) {
        flags |= SW_WEBSOCKET_FLAG_FIN;
    }
    if (mask) {
        flags |= SW_WEBSOCKET_FLAG_MASK;
    }
    if (rsv1) {
        flags |= SW_WEBSOCKET_FLAG_RSV1;
    }
    if (rsv2) {
        flags |= SW_WEBSOCKET_FLAG_RSV2;
    }
    if (rsv3) {
        flags |= SW_WEBSOCKET_FLAG_RSV3;
    }
    return flags;
}

void swWebSocket_encode(swString *buffer, const char *data, size_t length, char opcode, uint8_t flags);
void swWebSocket_decode(swWebSocket_frame *frame, swString *data);
int swWebSocket_pack_close_frame(swString *buffer, int code, char *reason, size_t length, uint8_t flags);
void swWebSocket_print_frame(swWebSocket_frame *frame);

ssize_t swWebSocket_get_package_length(swProtocol *protocol, swSocket *conn, const char *data, uint32_t length);
int swWebSocket_dispatch_frame(swProtocol *protocol, swSocket *conn, const char *data, uint32_t length);
