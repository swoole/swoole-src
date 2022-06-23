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
  | @Author   Tianfeng Han  <rango@swoole.com>                           |
  +----------------------------------------------------------------------+
*/

#include "test_core.h"
#include "swoole_server.h"

using namespace std;
using namespace swoole;

static const char *packet = "hello world\n";

TEST(server, send_buffer) {
    swServer serv(swoole::Server::MODE_BASE);
    serv.worker_num = 1;

    sw_logger()->set_level(SW_LOG_WARNING);

    swListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    ASSERT_EQ(serv.create(), SW_OK);

    mutex lock;
    lock.lock();

    std::thread t1([&]() {
        swoole_signal_block_all();

        lock.lock();

        swoole::network::SyncClient c(SW_SOCK_TCP);
        c.connect(TEST_HOST, port->port);
        c.send(packet, strlen(packet));
        char buf[4096];

        while (1) {
            ssize_t retval = c.recv(buf, sizeof(buf));
            if (retval <= 0) {
                break;
            }
            usleep(100);
        }

        c.close();

        kill(getpid(), SIGTERM);
    });

    serv.onWorkerStart = [&lock](swServer *serv, int worker_id) { lock.unlock(); };

    serv.onReceive = [](swServer *serv, swRecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        swString resp(1024 * 1024 * 16);
        resp.repeat("A", 1, resp.capacity());
        EXPECT_TRUE(serv->send(req->info.fd, resp.value(), resp.get_length()));
        EXPECT_TRUE(serv->close(req->info.fd, 0));

        return SW_OK;
    };

    serv.start();
    t1.join();
}
