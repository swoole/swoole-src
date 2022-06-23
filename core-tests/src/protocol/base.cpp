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
#include "test_coroutine.h"
#include "redis_client.h"
#include "swoole_redis.h"

using namespace swoole;
using namespace std;

constexpr int PKG_N = 32;
constexpr int MAX_SIZE = 128000;
constexpr int MIN_SIZE = 512;

TEST(protocol, eof) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;

    String pkgs[PKG_N];

    for (int i = 0; i < PKG_N; i++) {
        pkgs[i].append_random_bytes(swoole_rand(MIN_SIZE, MAX_SIZE), true);
        pkgs[i].append("\r\n");
    }

    sw_logger()->set_level(SW_LOG_WARNING);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);
    port->set_eof_protocol("\r\n", false);

    mutex lock;
    lock.lock();
    serv.create();

    thread t1([&]() {
        lock.lock();

        network::Client cli(SW_SOCK_TCP, false);
        EXPECT_EQ(cli.connect(&cli, TEST_HOST, port->port, 1, 0), 0);

        for (int i = 0; i < PKG_N; i++) {
            EXPECT_EQ(cli.send(&cli, pkgs[i].str, pkgs[i].length, 0), pkgs[i].length);
        }
    });

    serv.onWorkerStart = [&lock](Server *serv, WorkerId worker_id) { lock.unlock(); };

    int recv_count = 0;

    serv.onReceive = [&](Server *serv, RecvData *req) -> int {
        //        printf("[1]LEN=%d, count=%d\n%s\n---------------------------------\n", req->info.len,  recv_count,
        //        req->data); printf("[2]LEN=%d\n%s\n---------------------------------\n", pkgs[recv_count].length,
        //        pkgs[recv_count].str);

        EXPECT_EQ(memcmp(req->data, pkgs[recv_count].str, req->info.len), 0);

        recv_count++;

        if (recv_count == PKG_N) {
            kill(serv->get_master_pid(), SIGTERM);
        }

        return SW_OK;
    };

    serv.start();

    t1.join();
}
