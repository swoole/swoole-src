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
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole_http.h"

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
#define SW_WEBSOCKET_OPCODE_MAX swoole::websocket::OPCODE_PONG
#define SW_WEBSOCKET_MESSAGE_HEADER_SIZE (SW_WEBSOCKET_HEADER_LEN + SW_WEBSOCKET_MASK_LEN + sizeof(uint64_t))

namespace swoole {
namespace websocket {

enum Status {
    STATUS_NONE = 0,
    STATUS_CONNECTION = 1,
    STATUS_HANDSHAKE = 2,
    STATUS_ACTIVE = 3,
    STATUS_CLOSING = 4,
};

enum Flag {
    FLAG_FIN = 1 << 0, /* BC: must be 1 */
    FLAG_COMPRESS = 1 << 1,
    // readonly for user
    FLAG_RSV1 = 1 << 2,
    FLAG_RSV2 = 1 << 3,
    FLAG_RSV3 = 1 << 4,
    FLAG_MASK = 1 << 5,
    // for encoder/decoder
    FLAG_ENCODE_HEADER_ONLY = 1 << 6,
    FLAGS_ALL = /* used to prevent overflow  */
    FLAG_FIN | FLAG_RSV1 | FLAG_RSV2 | FLAG_RSV3 | FLAG_MASK | FLAG_COMPRESS
};

struct Header {
    /**
     * fin:1 rsv1:1 rsv2:1 rsv3:1 opcode:4
     */
    uchar OPCODE : 4;
    uchar RSV3 : 1;
    uchar RSV2 : 1;
    uchar RSV1 : 1;
    uchar FIN : 1;
    uchar LENGTH : 7;
    uchar MASK : 1;
};

struct Frame {
    Header header;
    char mask_key[SW_WEBSOCKET_MASK_LEN];
    uint16_t header_length;
    size_t payload_length;
    char *payload;
};

#define WEBSOCKET_VERSION 13

enum Opcode {
    OPCODE_CONTINUATION = 0x0,
    OPCODE_TEXT = 0x1,
    OPCODE_BINARY = 0x2,
    OPCODE_CLOSE = 0x8,
    OPCODE_PING = 0x9,
    OPCODE_PONG = 0xa,
};

enum CloseReason {
    CLOSE_NORMAL = 1000,
    CLOSE_GOING_AWAY = 1001,
    CLOSE_PROTOCOL_ERROR = 1002,
    CLOSE_DATA_ERROR = 1003,
    CLOSE_STATUS_ERROR = 1005,
    CLOSE_ABNORMAL = 1006,
    CLOSE_MESSAGE_ERROR = 1007,
    CLOSE_POLICY_ERROR = 1008,
    CLOSE_MESSAGE_TOO_BIG = 1009,
    CLOSE_EXTENSION_MISSING = 1010,
    CLOSE_SERVER_ERROR = 1011,
    CLOSE_TLS = 1015,
};

static inline uchar get_flags(Frame *frame) {
    uchar flags = 0;
    if (frame->header.FIN) {
        flags |= FLAG_FIN;
    }
    if (frame->header.RSV1) {
        flags |= FLAG_RSV1;
    }
    if (frame->header.RSV2) {
        flags |= FLAG_RSV2;
    }
    if (frame->header.RSV3) {
        flags |= FLAG_RSV3;
    }
    if (frame->header.MASK) {
        flags |= FLAG_MASK;
    }
    return flags;
}

static inline uchar set_flags(uchar fin, uchar mask, uchar rsv1, uchar rsv2, uchar rsv3) {
    uchar flags = 0;
    if (fin) {
        flags |= FLAG_FIN;
    }
    if (mask) {
        flags |= FLAG_MASK;
    }
    if (rsv1) {
        flags |= FLAG_RSV1;
    }
    if (rsv2) {
        flags |= FLAG_RSV2;
    }
    if (rsv3) {
        flags |= FLAG_RSV3;
    }
    return flags;
}

bool encode(String *buffer, const char *data, size_t length, char opcode, uint8_t flags);
bool decode(Frame *frame, char *data, size_t length);
int pack_close_frame(String *buffer, int code, char *reason, size_t length, uint8_t flags);
void print_frame(Frame *frame);

static inline bool decode(Frame *frame, String *str) {
    return decode(frame, str->str, str->length);
}

ssize_t get_package_length(const Protocol *protocol, network::Socket *conn, PacketLength *pl);
int dispatch_frame(const Protocol *protocol, network::Socket *conn, const RecvData *rdata);

}  // namespace websocket
}  // namespace swoole
