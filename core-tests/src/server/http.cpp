#include "test_server.h"
#include "httplib_client.h"
#include "wrapper/client.hpp"

using namespace swoole;
using namespace std;

static void test_run_server(function<void(swServer *)> fn)
{
    swServer serv;
    swServer_init(&serv);
    serv.worker_num = 1;
    serv.factory_mode = SW_MODE_BASE;
    serv.ptr2 = (void*) &fn;
    swServer_create(&serv);

    swLog_set_level(SW_LOG_WARNING);

    swListenPort *port = swServer_add_port(&serv, SW_SOCK_TCP, TEST_HOST, 0);
    if (!port)
    {
        swWarn("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }
    port->open_http_protocol = 1;

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

    swServer_start(&serv);
}

TEST(http_server, get)
{
    test_run_server([](swServer *serv)
    {
        swSignal_none();

        auto port = serv->listen_list->front();

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

        auto port = serv->listen_list->front();

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

