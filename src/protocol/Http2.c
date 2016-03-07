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
#include "Connection.h"
#include "http2.h"

int swHttp2_parse_frame(swProtocol *protocol, swConnection *conn, char *data, uint32_t length)
{
    int wait_body = 0;
    int package_length;

    while (length > 0)
    {
        if (wait_body)
        {
            if (length >= package_length)
            {
                protocol->onPackage(conn, data, package_length);
                wait_body = 0;
                data += package_length;
                length -= package_length;
                continue;
            }
            else
            {
                break;
            }
        }
        else
        {
            package_length = protocol->get_package_length(protocol, conn, data, length);
            if (package_length < 0)
            {
                return SW_ERR;
            }
            else if (package_length == 0)
            {
                return SW_OK;
            }
            else
            {
                wait_body = 1;
            }
        }
    }
    return SW_OK;
}

int swHttp2_send_setting_frame(swProtocol *protocol, swConnection *conn)
{
    char setting_frame[(SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_SETTING_OPTION_SIZE) * 3];
    char *p = setting_frame;
    uint16_t id;
    uint32_t value;

    swHttp2_set_frame_header(p, SW_HTTP2_TYPE_SETTINGS, SW_HTTP2_SETTING_OPTION_SIZE, 0, 0);
    id = ntohs(SW_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
    memcpy(p + SW_HTTP2_FRAME_HEADER_SIZE, &id, sizeof(id));
    value = ntohl(SW_HTTP2_MAX_CONCURRENT_STREAMS);
    memcpy(p + SW_HTTP2_FRAME_HEADER_SIZE + 2, &value, sizeof(value));
    p += SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_SETTING_OPTION_SIZE;

    swHttp2_set_frame_header(p, SW_HTTP2_TYPE_SETTINGS, SW_HTTP2_SETTING_OPTION_SIZE, 0, 0);
    id = ntohs(SW_HTTP2_SETTINGS_INIT_WINDOW_SIZE);
    memcpy(p + SW_HTTP2_FRAME_HEADER_SIZE, &id, sizeof(id));
    value = ntohl(SW_HTTP2_MAX_WINDOW);
    memcpy(p + SW_HTTP2_FRAME_HEADER_SIZE + 2, &value, sizeof(value));
    p += SW_HTTP2_FRAME_HEADER_SIZE + SW_HTTP2_SETTING_OPTION_SIZE;

    swHttp2_set_frame_header(p, SW_HTTP2_TYPE_SETTINGS, SW_HTTP2_SETTING_OPTION_SIZE, 0, 0);
    id = ntohs(SW_HTTP2_SETTINGS_MAX_FRAME_SIZE);
    memcpy(p + SW_HTTP2_FRAME_HEADER_SIZE, &id, sizeof(id));
    value = ntohl(SW_HTTP2_MAX_FRAME_SIZE);
    memcpy(p + SW_HTTP2_FRAME_HEADER_SIZE + 2, &value, sizeof(value));

    return swConnection_send(conn, setting_frame, sizeof(setting_frame), 0);
}

/**
 +-----------------------------------------------+
 |                 Length (24)                   |
 +---------------+---------------+---------------+
 |   Type (8)    |   Flags (8)   |
 +-+-------------+---------------+-------------------------------+
 |R|                 Stream Identifier (31)                      |
 +=+=============================================================+
 |                   Frame Payload (0...)                      ...
 +---------------------------------------------------------------+
 */
int swHttp2_get_frame_length(swProtocol *protocol, swConnection *conn, char *buf, uint32_t length)
{
    if (length < SW_HTTP2_FRAME_HEADER_SIZE)
    {
        return 0;
    }
    return swHttp2_get_length(buf) + SW_HTTP2_FRAME_HEADER_SIZE;
}

char* swHttp2_get_type(int type)
{
    switch(type)
    {
    case SW_HTTP2_TYPE_DATA:
        return "DATA";
    case SW_HTTP2_TYPE_HEADERS:
        return "HEADERS";
    case SW_HTTP2_TYPE_PRIORITY:
        return "PRIORITY";
    case SW_HTTP2_TYPE_RST_STREAM:
        return "RST_STREAM";
    case SW_HTTP2_TYPE_SETTINGS:
        return "SETTINGS";
    case SW_HTTP2_TYPE_PUSH_PROMISE:
        return "PUSH_PROMISE";
    case SW_HTTP2_TYPE_PING:
        return "PING";
    case SW_HTTP2_TYPE_GOAWAY:
        return "GOAWAY";
    case SW_HTTP2_TYPE_WINDOW_UPDATE:
        return "WINDOW_UPDATE";
    case SW_HTTP2_TYPE_CONTINUATION:
        return "CONTINUATION";
    default:
        return "UNKOWN";
    }
}
