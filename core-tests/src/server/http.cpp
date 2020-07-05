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
  | @link     https://www.swoole.com/                                    |
  | @contact  team@swoole.com                                            |
  | @license  https://github.com/swoole/swoole-src/blob/master/LICENSE   |
  | @author   Tianfeng Han  <mikan.tenny@gmail.com>                      |
  +----------------------------------------------------------------------+
*/

#include "tests.h"
#include "httplib_client.h"
#include "wrapper/client.hpp"

using namespace swoole;
using namespace std;

static void test_run_server(function<void(swServer *)> fn)
{
    swServer serv(SW_MODE_BASE);
    serv.worker_num = 1;
    serv.ptr2 = (void*) &fn;

    swLog_set_level(SW_LOG_WARNING);

    swListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port)
    {
        swWarn("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }
    port->open_http_protocol = 1;

    serv.create();

    serv.onWorkerStart = [](swServer *serv, int worker_id)
    {
        function<void(swServer *)> fn = *(function<void(swServer *)> *)serv->ptr2;
        thread t1(fn, serv);
        t1.detach();
    };

    serv.onReceive = [](swServer *serv, swEventData *task) -> int
    {
        char *data = nullptr;
        size_t length = serv->get_packet(serv, task, &data);
        string req(data, length);

        EXPECT_TRUE(req.find("\r\n\r\n"));
        EXPECT_TRUE(req.find("localhost"));

        string resp = string("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world");
        serv->send(serv, task->info.fd, resp.c_str(), resp.length());

        return SW_OK;
    };

    serv.start();
}

TEST(http_server, get)
{
    test_run_server([](swServer *serv)
    {
        swSignal_none();

        auto port = serv->ports.front();

        httplib::Client cli(TEST_HOST, port->port);
        auto resp = cli.Get("/index.html");
        EXPECT_EQ(resp->status, 200);
        EXPECT_EQ(resp->body, string("hello world"));

        kill(getpid(), SIGTERM);
    });
}

TEST(http_server, post)
{
    test_run_server([](swServer *serv)
    {
        swSignal_none();

        auto port = serv->get_primary_port();

        httplib::Client cli(TEST_HOST, port->port);
        httplib::Params params;
        params.emplace("name", "john");
        params.emplace("note", "coder");
        auto resp = cli.Post("/index.html", params);
        EXPECT_EQ(resp->status, 200);
        EXPECT_EQ(resp->body, string("hello world"));

        kill(getpid(), SIGTERM);
    });
}
