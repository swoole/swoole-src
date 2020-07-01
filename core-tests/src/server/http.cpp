#include "test_server.h"
#include "wrapper/client.hpp"

using namespace swoole;
using namespace std;

TEST(http_server, get)
{
    swServer serv;
    swServer_init(&serv);
    serv.worker_num = 1;
    serv.factory_mode = SW_MODE_BASE;
    swServer_create(&serv);

    swLog_set_level(SW_LOG_WARNING);

    swListenPort *port = swServer_add_port(&serv, SW_SOCK_TCP, TEST_HOST, 0);
    if (!port)
    {
        swWarn("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }
    port->open_http_protocol = 1;

    swLock lock;
    swMutex_create(&lock, 0);
    lock.lock(&lock);
    serv.ptr2 = &lock;

    std::thread t1([&]()
    {
        swSignal_none();

        lock.lock(&lock);

        swoole::Client c(SW_SOCK_TCP);
        c.connect(TEST_HOST, port->port);
        c.send("GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n");
        char buf[1024];
        auto n = c.recv(buf, sizeof(buf));
        EXPECT_GT(n, 0);

        string resp(buf, n);
        ASSERT_TRUE( resp.find("200 OK"));

        c.close();

        kill(getpid(), SIGTERM);
    });

    serv.onWorkerStart = [](swServer *serv, int worker_id)
    {
        swLock *lock = (swLock *) serv->ptr2;
        lock->unlock(lock);
    };

    serv.onReceive = [](swServer *serv, swEventData *task) -> int
    {
        char *data = nullptr;
        size_t length = serv->get_packet(serv, task, &data);
        EXPECT_EQ(string(data + length - 4, 4), string("\r\n\r\n"));

        string req(data, length);
        EXPECT_TRUE(req.find("localhost"));

        string resp = string("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world");
        serv->send(serv, task->info.fd, resp.c_str(), resp.length());

        return SW_OK;
    };

    swServer_start(&serv);
    t1.join();
}
