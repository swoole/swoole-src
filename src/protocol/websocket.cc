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
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"
#include "server.h"
#include "websocket.h"

using swoole::Server;

static inline uint16_t swWebSocket_get_ext_flags(uchar opcode, uchar flags) {
    uint16_t ext_flags = opcode;
    ext_flags = ext_flags << 8;
    ext_flags += flags;
    return ext_flags;
}

/*  The following is websocket data frame:
 +-+-+-+-+-------+-+-------------+-------------------------------+
 0                   1                   2                   3   |
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 |
 +-+-+-+-+-------+-+-------------+-------------------------------+
 |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
 |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
 |N|V|V|V|       |S|             |   (if payload len==126/127)   |
 | |1|2|3|       |K|             |                               |
 +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
 |     Extended payload length continued, if payload len == 127  |
 + - - - - - - - - - - - - - - - +-------------------------------+
 |                               |Masking-key, if MASK set to 1  |
 +-------------------------------+-------------------------------+
 | Masking-key (continued)       |          Payload Data         |
 +-------------------------------- - - - - - - - - - - - - - - - +
 :                     Payload Data continued ...                :
 + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 |                     Payload Data continued ...                |
 +---------------------------------------------------------------+
 */

ssize_t swWebSocket_get_package_length(swProtocol *protocol, swSocket *conn, const char *buf, uint32_t length) {
    // need more data
    if (length < SW_WEBSOCKET_HEADER_LEN) {
        return 0;
    }

    char mask = (buf[1] >> 7) & 0x1;
    // 0-125
    uint64_t payload_length = buf[1] & 0x7f;
    size_t header_length = SW_WEBSOCKET_HEADER_LEN;
    buf += SW_WEBSOCKET_HEADER_LEN;

    // uint16_t, 2byte
    if (payload_length == SW_WEBSOCKET_EXT16_LENGTH) {
        header_length += sizeof(uint16_t);
        if (length < header_length) {
            protocol->real_header_length = header_length;
            return 0;
        }
        payload_length = ntohs(*((uint16_t *) buf));
        buf += sizeof(uint16_t);
    }
    // uint64_t, 8byte
    else if (payload_length == SW_WEBSOCKET_EXT64_LENGTH) {
        header_length += sizeof(uint64_t);
        if (length < header_length) {
            protocol->real_header_length = header_length;
            return 0;
        }
        payload_length = swoole_ntoh64(*((uint64_t *) buf));
        buf += sizeof(uint64_t);
    }
    if (mask) {
        header_length += SW_WEBSOCKET_MASK_LEN;
        if (length < header_length) {
            protocol->real_header_length = header_length;
            return 0;
        }
    }
    swTraceLog(SW_TRACE_LENGTH_PROTOCOL, "header_length=%zu, payload_length=%u", header_length, payload_length);
    return header_length + payload_length;
}

static sw_inline void swWebSocket_mask(char *data, size_t len, const char *mask_key) {
    size_t n = len / 8;
    uint64_t mask_key64 = ((uint64_t)(*((uint32_t *) mask_key)) << 32) | *((uint32_t *) mask_key);
    size_t i;

    for (i = 0; i < n; i++) {
        ((uint64_t *) data)[i] ^= mask_key64;
    }

    for (i = n * 8; i < len; i++) {
        data[i] ^= mask_key[i % SW_WEBSOCKET_MASK_LEN];
    }
}

void swWebSocket_encode(swString *buffer, const char *data, size_t length, char opcode, uint8_t _flags) {
    int pos = 0;
    char frame_header[16];
    swWebSocket_frame_header *header = (swWebSocket_frame_header *) frame_header;
    header->FIN = !!(_flags & SW_WEBSOCKET_FLAG_FIN);
    header->OPCODE = opcode;
    header->RSV1 = !!(_flags & SW_WEBSOCKET_FLAG_RSV1);
    header->RSV2 = 0;
    header->RSV3 = 0;
    header->MASK = !!(_flags & SW_WEBSOCKET_FLAG_MASK);
    pos = 2;

    if (length < 126) {
        header->LENGTH = length;
    } else if (length < 65536) {
        header->LENGTH = SW_WEBSOCKET_EXT16_LENGTH;
        uint16_t *length_ptr = (uint16_t *) (frame_header + pos);
        *length_ptr = htons(length);
        pos += sizeof(*length_ptr);
    } else {
        header->LENGTH = SW_WEBSOCKET_EXT64_LENGTH;
        uint64_t *length_ptr = (uint64_t *) (frame_header + pos);
        *length_ptr = swoole_hton64(length);
        pos += sizeof(*length_ptr);
    }
    swString_append_ptr(buffer, frame_header, pos);
    /**
     * frame body
     */
    if (header->MASK) {
        swString_append_ptr(buffer, SW_WEBSOCKET_MASK_DATA, SW_WEBSOCKET_MASK_LEN);
        if (length > 0) {
            size_t offset = buffer->length;
            // Warn: buffer may be extended, string pointer will change
            swString_append_ptr(buffer, data, length);
            swWebSocket_mask(buffer->str + offset, length, SW_WEBSOCKET_MASK_DATA);
        }
    } else {
        if (length > 0) {
            swString_append_ptr(buffer, data, length);
        }
    }
}

void swWebSocket_decode(swWebSocket_frame *frame, swString *data) {
    memcpy(frame, data->str, SW_WEBSOCKET_HEADER_LEN);

    // 0-125
    size_t payload_length = frame->header.LENGTH;
    uint8_t header_length = SW_WEBSOCKET_HEADER_LEN;
    char *buf = data->str + SW_WEBSOCKET_HEADER_LEN;

    // uint16_t, 2byte
    if (frame->header.LENGTH == 0x7e) {
        payload_length = ntohs(*((uint16_t *) buf));
        header_length += 2;
    }
    // uint64_t, 8byte
    else if (frame->header.LENGTH > 0x7e) {
        payload_length = swoole_ntoh64(*((uint64_t *) buf));
        header_length += 8;
    }

    if (frame->header.MASK) {
        memcpy(frame->mask_key, data->str + header_length, SW_WEBSOCKET_MASK_LEN);
        header_length += SW_WEBSOCKET_MASK_LEN;
        if (payload_length > 0) {
            swWebSocket_mask(data->str + header_length, payload_length, frame->mask_key);
        }
    }

    frame->header_length = header_length;
    frame->payload = data->str + header_length;
    frame->payload_length = payload_length;
}

int swWebSocket_pack_close_frame(swString *buffer, int code, char *reason, size_t length, uint8_t flags) {
    if (sw_unlikely(length > SW_WEBSOCKET_CLOSE_REASON_MAX_LEN)) {
        swWarn("the max length of close reason is %d", SW_WEBSOCKET_CLOSE_REASON_MAX_LEN);
        return SW_ERR;
    }

    char payload[SW_WEBSOCKET_HEADER_LEN + SW_WEBSOCKET_CLOSE_CODE_LEN + SW_WEBSOCKET_CLOSE_REASON_MAX_LEN];
    payload[0] = (char) ((code >> 8 & 0xFF));
    payload[1] = (char) ((code & 0xFF));
    if (length > 0) {
        memcpy(payload + SW_WEBSOCKET_CLOSE_CODE_LEN, reason, length);
    }
    flags |= SW_WEBSOCKET_FLAG_FIN;
    swWebSocket_encode(buffer, payload, SW_WEBSOCKET_CLOSE_CODE_LEN + length, WEBSOCKET_OPCODE_CLOSE, flags);
    return SW_OK;
}

void swWebSocket_print_frame(swWebSocket_frame *frame) {
    printf("FIN: %x, RSV1: %d, RSV2: %d, RSV3: %d, opcode: %d, MASK: %d, length: %ld\n",
           frame->header.FIN,
           frame->header.RSV1,
           frame->header.RSV2,
           frame->header.RSV3,
           frame->header.OPCODE,
           frame->header.MASK,
           frame->payload_length);

    if (frame->payload_length) {
        printf("payload: %.*s\n", (int) frame->payload_length, frame->payload);
    }
}

int swWebSocket_dispatch_frame(swProtocol *proto, swSocket *_socket, const char *data, uint32_t length) {
    swServer *serv = (swServer *) proto->private_data_2;
    swConnection *conn = (swConnection *) _socket->object;
    swString frame;
    sw_memset_zero(&frame, sizeof(frame));
    frame.str = const_cast<char *>(data);
    frame.length = length;

    swString send_frame = {};
    char buf[SW_WEBSOCKET_HEADER_LEN + SW_WEBSOCKET_CLOSE_CODE_LEN + SW_WEBSOCKET_CLOSE_REASON_MAX_LEN];
    send_frame.str = buf;
    send_frame.size = sizeof(buf);

    swWebSocket_frame ws;
    swWebSocket_decode(&ws, &frame);

    swString *frame_buffer;
    int frame_length;
    swListenPort *port;

    size_t offset;
    switch (ws.header.OPCODE) {
    case WEBSOCKET_OPCODE_CONTINUATION:
        frame_buffer = conn->websocket_buffer;
        if (frame_buffer == nullptr) {
            swWarn("bad frame[opcode=0]. remote_addr=%s:%d",
                   swSocket_get_ip(conn->socket_type, &conn->info),
                   swSocket_get_port(conn->socket_type, &conn->info));
            return SW_ERR;
        }
        offset = length - ws.payload_length;
        frame_length = length - offset;
        port = serv->get_port_by_fd(conn->fd);
        // frame data overflow
        if (frame_buffer->length + frame_length > port->protocol.package_max_length) {
            swWarn("websocket frame is too big, remote_addr=%s:%d",
                   swSocket_get_ip(conn->socket_type, &conn->info),
                   swSocket_get_port(conn->socket_type, &conn->info));
            return SW_ERR;
        }
        // merge incomplete data
        swString_append_ptr(frame_buffer, data + offset, frame_length);
        // frame is finished, do dispatch
        if (ws.header.FIN) {
            proto->ext_flags = conn->websocket_buffer->offset;
            proto->ext_flags |= SW_WEBSOCKET_FLAG_FIN;
            Server::dispatch_task(proto, _socket, frame_buffer->str, frame_buffer->length);
            swString_free(frame_buffer);
            conn->websocket_buffer = nullptr;
        }
        break;

    case WEBSOCKET_OPCODE_TEXT:
    case WEBSOCKET_OPCODE_BINARY: {
        offset = length - ws.payload_length;
        proto->ext_flags = swWebSocket_get_ext_flags(ws.header.OPCODE, swWebSocket_get_flags(&ws));

        if (!ws.header.FIN) {
            if (conn->websocket_buffer) {
                swWarn("merging incomplete frame, bad request. remote_addr=%s:%d",
                       swSocket_get_ip(conn->socket_type, &conn->info),
                       swSocket_get_port(conn->socket_type, &conn->info));
                return SW_ERR;
            }
            conn->websocket_buffer = swString_dup(data + offset, length - offset);
            conn->websocket_buffer->offset = proto->ext_flags;
        } else {
            Server::dispatch_task(proto, _socket, data + offset, length - offset);
        }
        break;
    }
    case WEBSOCKET_OPCODE_PING:
        if (length >= (sizeof(buf) - SW_WEBSOCKET_HEADER_LEN)) {
            swWarn("ping frame application data is too big. remote_addr=%s:%d",
                   swSocket_get_ip(conn->socket_type, &conn->info),
                   swSocket_get_port(conn->socket_type, &conn->info));
            return SW_ERR;
        } else if (length == SW_WEBSOCKET_HEADER_LEN) {
            swWebSocket_encode(&send_frame, nullptr, 0, WEBSOCKET_OPCODE_PONG, SW_WEBSOCKET_FLAG_FIN);
        } else {
            offset = ws.header.MASK ? SW_WEBSOCKET_HEADER_LEN + SW_WEBSOCKET_MASK_LEN : SW_WEBSOCKET_HEADER_LEN;
            swWebSocket_encode(
                &send_frame, data += offset, length - offset, WEBSOCKET_OPCODE_PONG, SW_WEBSOCKET_FLAG_FIN);
        }
        swSocket_send(_socket, send_frame.str, send_frame.length, 0);
        break;

    case WEBSOCKET_OPCODE_PONG:
        break;

    case WEBSOCKET_OPCODE_CLOSE:
        if ((length - SW_WEBSOCKET_HEADER_LEN) > SW_WEBSOCKET_CLOSE_REASON_MAX_LEN) {
            return SW_ERR;
        }

        if (conn->websocket_status != WEBSOCKET_STATUS_CLOSING) {
            // Dispatch the frame with the same format of message frame
            offset = length - ws.payload_length;
            proto->ext_flags = swWebSocket_get_ext_flags(ws.header.OPCODE, swWebSocket_get_flags(&ws));

            Server::dispatch_task(proto, _socket, data + offset, length - offset);

            // Client attempt to close
            send_frame.str[0] = 0x88;  // FIN | OPCODE: WEBSOCKET_OPCODE_CLOSE
            send_frame.str[1] = ws.payload_length;
            // Get payload and return it as it is
            memcpy(send_frame.str + SW_WEBSOCKET_HEADER_LEN,
                   frame.str + frame.length - ws.payload_length,
                   ws.payload_length);
            send_frame.length = SW_WEBSOCKET_HEADER_LEN + ws.payload_length;
            swSocket_send(_socket, send_frame.str, send_frame.length, 0);
        } else {
            // Server attempt to close, frame sent by swoole_websocket_server->disconnect()
            conn->websocket_status = 0;
        }

        return SW_ERR;

    default:
        swWarn("unknown opcode [%d]", ws.header.OPCODE);
        break;
    }
    return SW_OK;
}
