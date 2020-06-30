#include "test_server.h"
#include "wrapper/client.hpp"

using namespace std;

static const char *packet = "hello world\n";

TEST(server, send_buffer)
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
        char buf[4096];

        while(1)
        {
            ssize_t retval = c.recv(buf, sizeof(buf));
            if (retval <= 0)
            {
                break;
            }
            usleep(100);
        }

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

        swoole::String resp(swoole::make_string(1024*1024*16));
        auto str = resp.get();
        swString_repeat(str, "A", 1, resp.size());
        serv->send(serv, req->info.fd, str->str, str->length);
        serv->close(serv, req->info.fd, 0);

        return SW_OK;
    };

    swServer_start(&serv);
    t1.join();
}

