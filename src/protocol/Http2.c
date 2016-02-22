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

int swHttp2_get_frame_length(swProtocol *protocol, swConnection *conn, char *buf, uint32_t length)
{
    if (length < SW_HTTP2_FRAME_HEADER_SIZE)
    {
        return 0;
    }
    return swHttp2_get_length(buf) + SW_HTTP2_FRAME_HEADER_SIZE;
}

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
    char setting_frame[12];
    bzero(setting_frame, sizeof(setting_frame));
    setting_frame[3] = SW_HTTP2_TYPE_SETTINGS;
    return swConnection_send(conn, setting_frame, SW_HTTP2_FRAME_HEADER_SIZE, 0);
}

