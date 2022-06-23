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
using namespace swoole::network;

TEST(stream, send) {
    swServer serv(swoole::Server::MODE_BASE);
    serv.worker_num = 1;
    int ori_log_level = sw_logger()->get_level();
    sw_logger()->set_level(SW_LOG_ERROR);

    swListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, TEST_PORT);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    port->open_length_check = true;
    Stream::set_protocol(&port->protocol);

    mutex lock;
    lock.lock();

    char buf[65536];
    ASSERT_EQ(swoole_random_bytes(buf, sizeof(buf)), sizeof(buf));

    ASSERT_EQ(serv.create(), SW_OK);

    std::thread t1([&]() {
        swoole_signal_block_all();

        lock.lock();

        swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

        // bad request
        auto stream0 = Stream::create(TEST_TMP_FILE, 0, SW_SOCK_UNIX_STREAM);
        ASSERT_EQ(stream0, nullptr);

        // bad request
        auto stream1 = Stream::create(TEST_HOST, 39999, SW_SOCK_TCP);
        ASSERT_TRUE(stream1);
        stream1->response = [](Stream *stream, const char *data, uint32_t length) {
            EXPECT_EQ(data, nullptr);
            EXPECT_EQ(stream->errCode, ECONNREFUSED);
        };
        ASSERT_EQ(stream1->send(buf, sizeof(buf)), SW_OK);

        // success requset
        auto stream2 = Stream::create(TEST_HOST, TEST_PORT, SW_SOCK_TCP);
        ASSERT_TRUE(stream2);
        stream2->private_data = new string(buf, sizeof(buf));
        stream2->response = [](Stream *stream, const char *data, uint32_t length) {
            string *buf = (string *) stream->private_data;
            string pkt = string("Server: ") + *buf;
            EXPECT_EQ(string(data, length), pkt);
            delete buf;
        };
        ASSERT_EQ(stream2->send(buf, sizeof(buf)), SW_OK);

        swoole_event_wait();

        kill(getpid(), SIGTERM);
    });

    serv.onWorkerStart = [&lock](swServer *serv, int worker_id) { lock.unlock(); };

    serv.onReceive = [&buf](swServer *serv, swRecvData *req) -> int {
        string req_body(req->data + 4, req->info.len - 4);

        EXPECT_EQ(string(buf, sizeof(buf)), req_body);

        string pkt = string("Server: ") + req_body;
        int packed_len = htonl(pkt.length());

        EXPECT_TRUE(serv->send(req->info.fd, &packed_len, sizeof(packed_len)));
        EXPECT_TRUE(serv->send(req->info.fd, pkt.c_str(), pkt.length()));

        // end stream
        packed_len = htonl(0);
        EXPECT_TRUE(serv->send(req->info.fd, &packed_len, sizeof(packed_len)));

        return SW_OK;
    };

    serv.start();
    t1.join();

    sw_logger()->set_level(ori_log_level);
}
