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
#include "wrapper/client.hpp"

using namespace std;

static const char *packet = "hello world\n";

TEST(server, send_buffer)
{
    swServer serv(SW_MODE_BASE);
    serv.worker_num = 1;

    swLog_set_level(SW_LOG_WARNING);

    swListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port)
    {
        swWarn("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    ASSERT_EQ(serv.create(), SW_OK);

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

    serv.onWorkerStart = [&lock](swServer *serv, int worker_id)
    {
        lock.unlock(&lock);
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

    serv.start();
    t1.join();
}

