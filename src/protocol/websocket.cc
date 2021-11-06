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
#include "swoole_server.h"
#include "swoole_websocket.h"

using swoole::Connection;
using swoole::Protocol;
using swoole::Server;
using swoole::String;
using swoole::network::Socket;

namespace swoole {
namespace websocket {
static inline uint16_t get_ext_flags(uchar opcode, uchar flags) {
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

ssize_t get_package_length(Protocol *protocol, Socket *conn, const char *buf, uint32_t length) {
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
    swoole_trace_log(SW_TRACE_LENGTH_PROTOCOL, "header_length=%zu, payload_length=%lu", header_length, payload_length);
    return header_length + payload_length;
}

static sw_inline void mask(char *data, size_t len, const char *mask_key) {
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

bool encode(String *buffer, const char *data, size_t length, char opcode, uint8_t _flags) {
    int pos = 0;
    char frame_header[16];
    Header *header = (Header *) frame_header;
    header->FIN = !!(_flags & FLAG_FIN);
    header->OPCODE = opcode;
    header->RSV1 = !!(_flags & FLAG_RSV1);
    header->RSV2 = 0;
    header->RSV3 = 0;
    header->MASK = !!(_flags & FLAG_MASK);
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
    buffer->append(frame_header, pos);
    /**
     * frame body
     */
    if (header->MASK) {
        buffer->append(SW_WEBSOCKET_MASK_DATA, SW_WEBSOCKET_MASK_LEN);
        if (_flags & FLAG_ENCODE_HEADER_ONLY) {
            return false;
        }
        if (length > 0) {
            size_t offset = buffer->length;
            // Warn: buffer may be extended, string pointer will change
            buffer->append(data, length);
            mask(buffer->str + offset, length, SW_WEBSOCKET_MASK_DATA);
        }
    } else {
        if (length > 0 and !(_flags & FLAG_ENCODE_HEADER_ONLY)) {
            buffer->append(data, length);
        }
    }

    return true;
}

bool decode(Frame *frame, char *data, size_t length) {
    memcpy(frame, data, SW_WEBSOCKET_HEADER_LEN);

    // 0-125
    size_t payload_length = frame->header.LENGTH;
    uint8_t header_length = SW_WEBSOCKET_HEADER_LEN;
    char *buf = data + SW_WEBSOCKET_HEADER_LEN;

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

    swoole_trace_log(SW_TRACE_WEBSOCKET,
                     "decode frame, payload_length=%ld, mask=%d, opcode=%d",
                     payload_length,
                     frame->header.MASK,
                     frame->header.OPCODE);

    if (payload_length == 0) {
        frame->header_length = header_length;
        frame->payload_length = 0;
        frame->payload = nullptr;

        return true;
    }

    if (frame->header.MASK) {
        memcpy(frame->mask_key, data + header_length, SW_WEBSOCKET_MASK_LEN);
        header_length += SW_WEBSOCKET_MASK_LEN;
        mask(data + header_length, payload_length, frame->mask_key);
    }

    frame->payload = data + header_length;
    frame->header_length = header_length;
    frame->payload_length = payload_length;

    return true;
}

int pack_close_frame(String *buffer, int code, char *reason, size_t length, uint8_t flags) {
    if (sw_unlikely(length > SW_WEBSOCKET_CLOSE_REASON_MAX_LEN)) {
        swoole_warning("the max length of close reason is %d", SW_WEBSOCKET_CLOSE_REASON_MAX_LEN);
        return SW_ERR;
    }

    char payload[SW_WEBSOCKET_HEADER_LEN + SW_WEBSOCKET_CLOSE_CODE_LEN + SW_WEBSOCKET_CLOSE_REASON_MAX_LEN];
    payload[0] = (char) ((code >> 8 & 0xFF));
    payload[1] = (char) ((code & 0xFF));
    if (length > 0) {
        memcpy(payload + SW_WEBSOCKET_CLOSE_CODE_LEN, reason, length);
    }
    flags |= FLAG_FIN;
    encode(buffer, payload, SW_WEBSOCKET_CLOSE_CODE_LEN + length, OPCODE_CLOSE, flags);
    return SW_OK;
}

void print_frame(Frame *frame) {
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

int dispatch_frame(const Protocol *proto, Socket *_socket, const RecvData *rdata) {
    Server *serv = (Server *) proto->private_data_2;
    Connection *conn = (Connection *) _socket->object;
    RecvData dispatch_data{};
    String send_frame{};
    const char *data = rdata->data;
    const uint32_t length = rdata->info.len;
    char buf[SW_WEBSOCKET_HEADER_LEN + SW_WEBSOCKET_CLOSE_CODE_LEN + SW_WEBSOCKET_CLOSE_REASON_MAX_LEN];
    send_frame.str = buf;
    send_frame.size = sizeof(buf);

    Frame ws;
    decode(&ws, const_cast<char *>(data), length);

    String *frame_buffer;
    int frame_length;
    ListenPort *port;

    size_t offset;
    switch (ws.header.OPCODE) {
    case OPCODE_CONTINUATION:
        frame_buffer = conn->websocket_buffer;
        if (frame_buffer == nullptr) {
            swoole_warning("bad frame[opcode=0]. remote_addr=%s:%d", conn->info.get_ip(), conn->info.get_port());
            return SW_ERR;
        }
        offset = length - ws.payload_length;
        frame_length = length - offset;
        port = serv->get_port_by_fd(conn->fd);
        // frame data overflow
        if (frame_buffer->length + frame_length > port->protocol.package_max_length) {
            swoole_warning("websocket frame is too big, remote_addr=%s:%d", conn->info.get_ip(), conn->info.get_port());
            return SW_ERR;
        }
        // merge incomplete data
        frame_buffer->append(data + offset, frame_length);
        // frame is finished, do dispatch
        if (ws.header.FIN) {
            dispatch_data.info.ext_flags = conn->websocket_buffer->offset | FLAG_FIN;
            dispatch_data.info.len = frame_buffer->length;
            dispatch_data.data = frame_buffer->str;
            Server::dispatch_task(proto, _socket, &dispatch_data);
            delete frame_buffer;
            conn->websocket_buffer = nullptr;
        }
        break;

    case OPCODE_TEXT:
    case OPCODE_BINARY: {
        offset = length - ws.payload_length;
        int ext_flags = get_ext_flags(ws.header.OPCODE, get_flags(&ws));
        if (!ws.header.FIN) {
            if (conn->websocket_buffer) {
                swoole_warning("merging incomplete frame, bad request. remote_addr=%s:%d",
                               conn->info.get_ip(),
                               conn->info.get_port());
                return SW_ERR;
            }
            conn->websocket_buffer = new swoole::String(data + offset, length - offset);
            conn->websocket_buffer->offset = ext_flags;
        } else {
            dispatch_data.info.ext_flags = ext_flags;
            dispatch_data.info.len = length - offset;
            dispatch_data.data = data + offset;
            Server::dispatch_task(proto, _socket, &dispatch_data);
        }
        break;
    }
    case OPCODE_PING:
    case OPCODE_PONG:
        if (length >= (sizeof(buf) - SW_WEBSOCKET_HEADER_LEN)) {
            swoole_warning("%s frame application data is too big. remote_addr=%s:%d",
                           ws.header.OPCODE == OPCODE_PING ? "ping" : "pong",
                           conn->info.get_ip(),
                           conn->info.get_port());
            return SW_ERR;
        } else if (length == SW_WEBSOCKET_HEADER_LEN) {
            dispatch_data.data = nullptr;
            dispatch_data.info.len = 0;
        } else {
            offset = ws.header.MASK ? SW_WEBSOCKET_HEADER_LEN + SW_WEBSOCKET_MASK_LEN : SW_WEBSOCKET_HEADER_LEN;
            dispatch_data.info.len = length - offset;
            dispatch_data.data = dispatch_data.info.len == 0 ? nullptr : data + offset;
        }
        dispatch_data.info.ext_flags = get_ext_flags(ws.header.OPCODE, get_flags(&ws));
        Server::dispatch_task(proto, _socket, &dispatch_data);
        break;

    case OPCODE_CLOSE:
        if ((length - SW_WEBSOCKET_HEADER_LEN) > SW_WEBSOCKET_CLOSE_REASON_MAX_LEN) {
            return SW_ERR;
        }

        if (conn->websocket_status != STATUS_CLOSING) {
            // Dispatch the frame with the same format of message frame
            offset = length - ws.payload_length;
            dispatch_data.info.ext_flags = get_ext_flags(ws.header.OPCODE, get_flags(&ws));
            dispatch_data.info.len = length - offset;
            dispatch_data.data = data + offset;
            Server::dispatch_task(proto, _socket, &dispatch_data);

            // Client attempt to close
            send_frame.str[0] = 0x88;  // FIN | OPCODE: WEBSOCKET_OPCODE_CLOSE
            send_frame.str[1] = ws.payload_length;
            // Get payload and return it as it is
            memcpy(send_frame.str + SW_WEBSOCKET_HEADER_LEN, data + length - ws.payload_length, ws.payload_length);
            send_frame.length = SW_WEBSOCKET_HEADER_LEN + ws.payload_length;
            _socket->send(send_frame.str, send_frame.length, 0);
        } else {
            // Server attempt to close, frame sent by swoole_websocket_server->disconnect()
            conn->websocket_status = 0;
        }

        return SW_ERR;

    default:
        swoole_warning("unknown opcode [%d]", ws.header.OPCODE);
        break;
    }
    return SW_OK;
}
}  // namespace websocket
}  // namespace swoole
