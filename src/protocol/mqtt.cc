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

ssize_t get_package_length(const Protocol *protocol, Socket *conn, PacketLength *pl) {
    uint32_t remaining_length = 0;
    // Byte zero is the fixed header. Inspect at most four received Remaining Length bytes.
    for (uint32_t index = 0; index < SW_MQTT_MAX_LENGTH_SIZE; index++) {
        const uint32_t offset = index + 1;
        if (offset >= pl->buf_size) {
            return 0;
        }
        const auto byte = static_cast<uint8_t>(pl->buf[offset]);
        remaining_length |= static_cast<uint32_t>(byte & 0x7f) << (7 * index);
        if ((byte & 0x80) == 0) {
            return remaining_length + offset + 1;
        }
    }
    swoole_error_log(SW_LOG_WARNING,
                     SW_ERROR_PACKAGE_LENGTH_TOO_LARGE,
                     "bad request, the variable header size is larger than %d",
                     SW_MQTT_MAX_LENGTH_SIZE);
    return SW_ERR;
}

}  // namespace mqtt
}  // namespace swoole
