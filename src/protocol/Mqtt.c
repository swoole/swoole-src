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

#include "mqtt.h"

void swMqtt_print_package(swMqtt_package *pkg)
{
    printf("type=%d, length=%d\n", pkg->type, pkg->length);
}

static sw_inline int swMqtt_get_length(char *data, uint32_t size, int *count)
{
    uint8_t byte;
    int mul = 1;
    int length = 0;

    *count = 0;
    do
    {
        byte = data[*count + 1];
        length += (byte & 127) * mul;
        mul *= 128;
        (*count)++;
    } while ((byte & 128) != 0);

    return length;
}

//int swMqtt_unpack(swMqtt_package *pkg, char *data, uint32_t size)
//{
//    uint8_t byte = data[0];
//    off_t offset;
//
//    pkg->type = (byte & 0xF0) >> 4;
//    pkg->dup = (byte & 0x08) >> 3;
//    pkg->qos = (byte & 0x06) >> 1;
//    pkg->retain = byte & 0x01;
//
//    offset += 1;
//
//    int count = 0;
//    pkg->length = swMqtt_get_length(data, size, &count);
//    offset += count + 1;
//}

int swMqtt_get_package_length(swProtocol *protocol, swConnection *conn, char *data, uint32_t size)
{
    if (size < SW_MQTT_MIN_LENGTH)
    {
        return 0;
    }
    int count = 0;
    int length = swMqtt_get_length(data, size, &count);
    return length + count + 1;
}
