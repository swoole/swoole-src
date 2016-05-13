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
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#ifndef SW_MQTT_H_
#define SW_MQTT_H_

#include "swoole.h"

#define SW_MQTT_MIN_LENGTH                   2
#define SW_MQTT_MAX_PAYLOAD_SIZE             268435455

enum swMqtt_type
{
    CONNECT = 0x10,
    CONNACK = 0x20,
    PUBLISH = 0x30,
    PUBACK = 0x40,
    PUBREC = 0x50,
    PUBREL = 0x60,
    PUBCOMP = 0x70,
    SUBSCRIBE = 0x80,
    SUBACK = 0x90,
    UNSUBSCRIBE = 0xA0,
    UNSUBACK = 0xB0,
    PINGREQ = 0xC0,
    PINGRESP = 0xD0,
    DISCONNECT = 0xE0,
};

typedef struct
{
    uint8_t type :4;
    uint8_t dup :1;
    uint8_t qos :2;
    uint8_t retain :1;

    uint32_t length;

    char protocol_name[8];

} swMqtt_package;


#define SETRETAIN(HDR, R)   (HDR | (R))
#define SETQOS(HDR, Q)      (HDR | ((Q) << 1))
#define SETDUP(HDR, D)      (HDR | ((D) << 3))

int swMqtt_get_package_length(swProtocol *protocol, swConnection *conn, char *data, uint32_t size);

#endif /* SW_MQTT_H_ */
