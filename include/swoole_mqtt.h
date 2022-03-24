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
 +----------------------------------------------------------------------+
 */
#pragma once

#include "swoole.h"
#include "swoole_protocol.h"

#define SW_MQTT_MIN_LENGTH_SIZE 1
#define SW_MQTT_MAX_LENGTH_SIZE 4
#define SW_MQTT_MAX_PAYLOAD_SIZE 268435455

#define SW_MQTT_SETRETAIN(HDR, R) (HDR | (R))
#define SW_MQTT_SETQOS(HDR, Q) (HDR | ((Q) << 1))
#define SW_MQTT_SETDUP(HDR, D) (HDR | ((D) << 3))

namespace swoole {
namespace mqtt {

enum Opcode {
    SW_MQTT_CONNECT = 0x10,
    SW_MQTT_CONNACK = 0x20,
    SW_MQTT_PUBLISH = 0x30,
    SW_MQTT_PUBACK = 0x40,
    SW_MQTT_PUBREC = 0x50,
    SW_MQTT_PUBREL = 0x60,
    SW_MQTT_PUBCOMP = 0x70,
    SW_MQTT_SUBSCRIBE = 0x80,
    SW_MQTT_SUBACK = 0x90,
    SW_MQTT_UNSUBSCRIBE = 0xA0,
    SW_MQTT_UNSUBACK = 0xB0,
    SW_MQTT_PINGREQ = 0xC0,
    SW_MQTT_PINGRESP = 0xD0,
    SW_MQTT_DISCONNECT = 0xE0,
};

struct Packet {
    uint8_t type : 4;
    uint8_t dup : 1;
    uint8_t qos : 2;
    uint8_t retain : 1;
    uint32_t length;
    char protocol_name[8];
};

ssize_t get_package_length(const Protocol *protocol, network::Socket *conn, PacketLength *pl);
void set_protocol(Protocol *protocol);
}  // namespace mqtt
}  // namespace swoole
