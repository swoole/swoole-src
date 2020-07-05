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
#include <string>
#include <functional>

namespace swoole
{

class Client
{
protected:
    swClient client;
    bool connected = false;
    bool created;
    bool async = false;
    enum swSocket_type type;
public:
    Client(enum swSocket_type _type, bool _async = false) :
            async(_async), type(_type)
    {
        created = swClient_create(&client, type, async) == 0;
    }

    bool connect(const char *host, int port, double timeout = -1)
    {
        if (connected || !created)
        {
            return false;
        }
        if (client.connect(&client, host, port, timeout, 0) < 0)
        {
            return false;
        }
        connected = true;
        return true;
    }

    ssize_t send(const std::string &data)
    {
        return client.send(&client, data.c_str(), data.length(), 0);
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
        if (!created || client.closed)
        {
            return false;
        }
        client.close(&client);
        if (client.socket)
        {
            swClient_free(&client);
        }
        created = false;
        return true;
    }

    virtual ~Client()
    {
        if (created)
        {
            close();
        }
    }
};

class AsyncClient: public Client
{
protected:
    std::function<void(AsyncClient *)> _onConnect = nullptr;
    std::function<void(AsyncClient *)> _onError = nullptr;
    std::function<void(AsyncClient *)> _onClose = nullptr;
    std::function<void(AsyncClient *, const char *data, uint32_t length)> _onReceive = nullptr;

public:
    AsyncClient(enum swSocket_type _type) :
            Client(_type, true)
    {

    }

    bool connect(const char *host, int port, double timeout = -1)
    {
        client.object = this;
        client.onConnect = [](swClient *cli)
        {
            AsyncClient *ac = (AsyncClient *) cli->object;
            ac->_onConnect(ac);
        };
        client.onError = [](swClient *cli)
        {
            AsyncClient *ac = (AsyncClient *) cli->object;
            ac->_onError(ac);
        };
        client.onClose = [](swClient *cli)
        {
            AsyncClient *ac = (AsyncClient *) cli->object;
            ac->_onClose(ac);
        };
        client.onReceive = [](swClient *cli, const char *data, uint32_t length)
        {
            AsyncClient *ac = (AsyncClient *) cli->object;
            ac->_onReceive(ac, data, length);
        };
        return Client::connect(host, port, timeout);
    }

    void on_connect(std::function<void(AsyncClient *)> fn)
    {
        _onConnect = fn;
    }

    void on_error(std::function<void(AsyncClient *)> fn)
    {
        _onError = fn;
    }

    void on_close(std::function<void(AsyncClient *)> fn)
    {
        _onClose = fn;
    }

    void on_receive(std::function<void(AsyncClient *, const char *data, size_t length)> fn)
    {
        _onReceive = fn;
    }
};
}
