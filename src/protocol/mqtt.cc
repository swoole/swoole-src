/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
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
 | Author: Xinhua Guo  <guoxinhua@swoole.com>                           |
 +----------------------------------------------------------------------+
 */

#include "swoole_mqtt.h"
#include "swoole_protocol.h"

using swoole::network::Socket;

namespace swoole {
namespace mqtt {

void print_package(Packet *pkg) {
    printf("type=%d, length=%d\n", pkg->type, pkg->length);
}

void set_protocol(Protocol *protocol) {
    protocol->package_length_size = SW_MQTT_MAX_LENGTH_SIZE;
    protocol->package_length_offset = 1;
    protocol->package_body_offset = 0;
    protocol->get_package_length = get_package_length;
}

// recv variable_header packet twice may cause that the '*data' contain the payload data,
// but there's no chance to read the next mqtt request ,because MQTT client will recv ACK blocking
#define SW_MQTT_RECV_LEN_AGAIN 0

ssize_t get_package_length(const Protocol *protocol, Socket *conn, PacketLength *pl) {
    //-1 cause the arg 'size' contain length_offset(1 byte len)
    uint32_t recv_variable_header_size = (pl->buf_size - 1);
    if (recv_variable_header_size < SW_MQTT_MIN_LENGTH_SIZE) {  // recv continue
        return SW_MQTT_RECV_LEN_AGAIN;
    }

    uint8_t byte;
    int mul = 1;
    ssize_t length = 0;
    ssize_t variable_header_byte_count = 0;
    while (1) {
        variable_header_byte_count++;
        byte = pl->buf[variable_header_byte_count];
        length += (byte & 127) * mul;
        mul *= 128;
        if ((byte & 128) == 0) {  // done! there is no surplus length byte
            break;
        }
        if (variable_header_byte_count >= SW_MQTT_MAX_LENGTH_SIZE) {
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_PACKAGE_LENGTH_TOO_LARGE,
                             "bad request, the variable header size is larger than %d",
                             SW_MQTT_MAX_LENGTH_SIZE);
            return SW_ERR;
        }
        if (variable_header_byte_count >= recv_variable_header_size) {  // length not enough
            return SW_MQTT_RECV_LEN_AGAIN;
        }
    }
    // payload_length + variable_header_byte_count + length_offset(1)
    return length + variable_header_byte_count + 1;
}

}  // namespace mqtt
}  // namespace swoole
