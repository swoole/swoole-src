#include "test_server.h"
#include "wrapper/client.hpp"

using namespace std;

TEST(server, create_pipe_buffers)
{
    int ret;
    swServer serv;

    create_test_server(&serv);

    ret = swServer_create_pipe_buffers(&serv);
    ASSERT_EQ(0, ret);
    ASSERT_NE(nullptr, serv.pipe_buffers);
    for (uint32_t i = 0; i < serv.reactor_num; i++)
    {
        ASSERT_NE(nullptr, serv.pipe_buffers[i]);
    }
}

const char *packet = "hello world\n";

static void server_test_func(int mode)
{
    swServer serv;
    swServer_init(&serv);
    serv.worker_num = 1;
    serv.factory_mode = mode;
    swServer_create(&serv);

    swLog_set_level(SW_LOG_WARNING);

    swListenPort *port = swServer_add_port(&serv, SW_SOCK_TCP, TEST_HOST, TEST_PORT);
    if (!port)
    {
        swWarn("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    swLock lock;
    swMutex_create(&lock, 0);
    lock.lock(&lock);
    serv.ptr2 = &lock;

    std::thread t1([&]()
    {
        swSignal_none();

        lock.lock(&lock);

        swoole::Client c(SW_SOCK_TCP);
        c.connect(TEST_HOST, TEST_PORT);
        c.send(packet, strlen(packet));
        char buf[1024];
        c.recv(buf, sizeof(buf));
        c.close();

        kill(getpid(), SIGTERM);
    });

    if (mode == SW_MODE_BASE)
    {
        serv.onWorkerStart = [](swServer *serv, int worker_id)
        {
            swLock *lock = (swLock *) serv->ptr2;
            lock->unlock(lock);
        };
    }
    else
    {
        serv.onStart = [](swServer *serv)
        {
            swLock *lock = (swLock *) serv->ptr2;
            lock->unlock(lock);
        };
    }

    serv.onReceive = [](swServer *serv, swEventData *req) -> int
    {
        char *data = nullptr;
        size_t length = serv->get_packet(serv, req, &data);
        EXPECT_EQ(string(data, length), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(serv, req->info.fd, resp.c_str(), resp.length());

        return SW_OK;
    };

    swServer_start(&serv);
    t1.join();
}

TEST(server, base)
{
    server_test_func(SW_MODE_BASE);
}

TEST(server, process)
{
    server_test_func(SW_MODE_PROCESS);
}

