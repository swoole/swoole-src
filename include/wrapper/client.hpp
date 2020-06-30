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

#pragma once

#include "client.h"

namespace swoole
{

class Client
{
private:
    swClient client;
    bool connected = false;
    bool created = false;
    enum swSocket_type type;
public:
    Client(enum swSocket_type _type) :
            type(_type)
    {

    }

    bool connect(const char *host, int port, double timeout = -1)
    {
        if (connected)
        {
            return false;
        }
        if (!created)
        {
            if (swClient_create(&client, type, 0) < 0)
            {
                return false;
            }
            created = true;
        }
        if (client.connect(&client, host, port, timeout, 0) < 0)
        {
            return false;
        }
        connected = true;
        return true;
    }

    ssize_t send(const char *buf, size_t len)
    {
        return client.send(&client, buf, len, 0);
    }

    ssize_t recv(char *buf, size_t len)
    {
        return client.recv(&client, buf, len, 0);
    }

    bool close()
    {
        if (!created)
        {
            return false;
        }
        client.close(&client);
        swClient_free(&client);
        created = false;
        return true;
    }

    ~Client()
    {
        if (created)
        {
            close();
        }
    }
};
}
