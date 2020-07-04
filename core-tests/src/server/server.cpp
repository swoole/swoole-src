#include "tests.h"
#include "wrapper/client.hpp"

using namespace std;

static void test_create_server(swServer *serv)
{
    serv->create();

    SwooleG.memory_pool = swMemoryGlobal_new(SW_GLOBAL_MEMORY_PAGESIZE, 1);
    serv->workers = (swWorker *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, serv->worker_num * sizeof(swWorker));
    swFactoryProcess_create(&serv->factory, serv->worker_num);
}

TEST(server, create_pipe_buffers)
{
    int ret;
    swServer serv;

    test_create_server(&serv);

    ret = swServer_create_pipe_buffers(&serv);
    ASSERT_EQ(0, ret);
    ASSERT_NE(nullptr, serv.pipe_buffers);
    for (uint32_t i = 0; i < serv.reactor_num; i++)
    {
        ASSERT_NE(nullptr, serv.pipe_buffers[i]);
    }
}

static const char *packet = "hello world\n";

TEST(server, base)
{
    swServer serv;
    serv.worker_num = 1;
    serv.factory_mode = SW_MODE_BASE;
    ASSERT_EQ(serv.create(), SW_OK);

    swLog_set_level(SW_LOG_WARNING);

    swListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port)
    {
        swWarn("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    swLock lock;
    swMutex_create(&lock, 0);
    lock.lock(&lock);

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

    serv.onWorkerStart = [&lock](swServer *serv, int worker_id)
    {
        lock.unlock(&lock);
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

    serv.start();
    t1.join();
}

TEST(server, process)
{
    swServer serv;
    serv.worker_num = 1;
    serv.factory_mode = SW_MODE_PROCESS;
    ASSERT_EQ(serv.create(), SW_OK);

    SwooleG.running = 1;

    swLog_set_level(SW_LOG_WARNING);

    swLock *lock = (swLock *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(*lock));
    swMutex_create(lock, 1);
    lock->lock(lock);

    swListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port)
    {
        swWarn("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    serv.onStart = [&lock](swServer *serv)
    {
        thread t1([=]() {
            swSignal_none();

            lock->lock(lock);

            swListenPort *port = serv->get_primary_port();

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

    ASSERT_EQ(serv.start(), 0);
}

