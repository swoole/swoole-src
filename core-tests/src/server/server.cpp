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

TEST(server, base)
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
        c.send(packet, strlen(packet));
        char buf[1024];
        c.recv(buf, sizeof(buf));
        c.close();

        kill(getpid(), SIGTERM);
    });

    serv.onWorkerStart = [](swServer *serv, int worker_id)
    {
        swLock *lock = (swLock *) serv->ptr2;
        lock->unlock(lock);
    };

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

TEST(server, process)
{
    swServer serv;
    swServer_init(&serv);
    serv.worker_num = 1;
    serv.factory_mode = SW_MODE_PROCESS;
    swServer_create(&serv);

    SwooleG.running = 1;

    swLog_set_level(SW_LOG_WARNING);

    swLock *lock = (swLock *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(*lock));
    swMutex_create(lock, 1);
    lock->lock(lock);
    serv.ptr2 = lock;

    swListenPort *port = swServer_add_port(&serv, SW_SOCK_TCP, TEST_HOST, 0);
    if (!port)
    {
        swWarn("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    serv.onStart = [](swServer *serv)
    {
        thread t1([=]() {
            swSignal_none();

            swLock *lock = (swLock *) serv->ptr2;
            lock->lock(lock);

            swListenPort *port = serv->listen_list->front();

            swoole::Client c(SW_SOCK_TCP);
            c.connect(TEST_HOST, port->port);
            c.send(packet, strlen(packet));
            char buf[1024];
            c.recv(buf, sizeof(buf));
            c.close();

            kill(serv->gs->master_pid, SIGTERM);
        });
        t1.detach();
    };

    serv.onWorkerStart = [](swServer *serv, int worker_id)
    {
        swLock *lock = (swLock *) serv->ptr2;
        lock->unlock(lock);
    };

    serv.onReceive = [](swServer *serv, swEventData *req) -> int
    {
        char *data = nullptr;
        size_t length = serv->get_packet(serv, req, &data);
        EXPECT_EQ(string(data, length), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(serv, req->info.fd, resp.c_str(), resp.length());

        return SW_OK;
    };

    ASSERT_EQ(swServer_start(&serv), 0);
}

