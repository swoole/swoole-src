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

#ifndef SW_WEBSOCKET_H_
#define SW_WEBSOCKET_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "Http.h"

#define SW_WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define SW_WEBSOCKET_HEADER_LEN  2
#define SW_WEBSOCKET_MASK_LEN    4
#define SW_WEBSOCKET_EXT16_LENGTH 0x7E
#define SW_WEBSOCKET_EXT16_MAX_LEN 0xFFFF
#define SW_WEBSOCKET_EXT64_LENGTH 0x7F
#define SW_WEBSOCKET_MASKED(frm) (frm->header.MASK)

#define FRAME_SET_FIN(BYTE) (((BYTE) & 0x01) << 7)
#define FRAME_SET_OPCODE(BYTE) ((BYTE) & 0x0F)
#define FRAME_SET_MASK(BYTE) (((BYTE) & 0x01) << 7)
#define FRAME_SET_LENGTH(X64, IDX) (unsigned char)(((X64) >> ((IDX)*8)) & 0xFF)

enum swWebsocketStatus
{
    WEBSOCKET_STATUS_CONNECTION = 1,
    WEBSOCKET_STATUS_HANDSHAKE = 2,
    WEBSOCKET_STATUS_FRAME = 3,
};

typedef struct
{
    /**
     * fin:1 rsv1:1 rsv2:1 rsv3:1 opcode:4
     */
    struct
    {
        unsigned char OPCODE :4;
        unsigned char RSV3 :1;
        unsigned char RSV2 :1;
        unsigned char RSV1 :1;
        unsigned char FIN :1;
        unsigned char LENGTH :7;
        unsigned char MASK :1;
    } header;
    char mask[SW_WEBSOCKET_MASK_LEN];
    size_t length;
    char *payload;
} swWebSocket_frame;

enum swWebsocketCode
{
    WEBSOCKET_OPCODE_CONTINUATION_FRAME = 0x0,
    WEBSOCKET_OPCODE_TEXT_FRAME = 0x1,
    WEBSOCKET_OPCODE_BINARY_FRAME = 0x2,
    WEBSOCKET_OPCODE_CONNECTION_CLOSE = 0x8,
    WEBSOCKET_OPCODE_PING = 0x9,
    WEBSOCKET_OPCODE_PONG = 0xa,

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
    WEBSOCKET_VERSION = 13,

};

void swWebSocket_encode(swString *buffer, char *data, size_t length, char opcode, int fin, int isMask);
int swWebSocket_decode(swHttpRequest *request);
int swWebSocket_isEof(char *data);
int swWebSocket_decode_frame(char *data, swString * str, int n);

#ifdef __cplusplus
}
#endif

#endif /* SW_WEBSOCKET_H_ */