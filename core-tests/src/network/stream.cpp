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
#include "swoole_log.h"

using namespace std;
using namespace swoole;

static Log logger;

TEST(stream, send) {
    swServer serv;
    serv.worker_num = 1;
    serv.factory_mode = SW_MODE_BASE;
    int ori_log_level = logger.get_level();
    logger.set_level(SW_LOG_ERROR);

    swListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, TEST_PORT);
    if (!port) {
        swWarn("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    port->open_length_check = true;
    swStream_set_protocol(&port->protocol);

    mutex lock;
    lock.lock();

    char buf[65536];
    ASSERT_EQ(swoole_random_bytes(buf, sizeof(buf)), sizeof(buf));

    ASSERT_EQ(serv.create(), SW_OK);

    std::thread t1([&]()
    {
        swSignal_none();

        lock.lock();

        swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

        //bad request
        auto stream1 = swStream_new(TEST_HOST, 39999, SW_SOCK_TCP);
        stream1->response = [](swStream *stream, const char *data, uint32_t length) {
            EXPECT_EQ(data, nullptr);
            EXPECT_EQ(stream->errCode, ECONNREFUSED);
        };
        ASSERT_EQ(swStream_send(stream1, buf, sizeof(buf)), SW_OK);

        //success requset
        auto stream2 = swStream_new(TEST_HOST, TEST_PORT, SW_SOCK_TCP);
        stream2->private_data = new string(buf, sizeof(buf));
        stream2->response = [](swStream *stream, const char *data, uint32_t length) {
            string *buf = (string *) stream->private_data;
            string pkt = string("Server: ") + *buf;
            EXPECT_EQ(string(data, length), pkt);
            delete buf;
        };
        ASSERT_EQ(swStream_send(stream2, buf, sizeof(buf)), SW_OK);

        swoole_event_wait();

        kill(getpid(), SIGTERM);
    });

    serv.onWorkerStart = [&lock](swServer *serv, int worker_id)
    {
        lock.unlock();
    };

    serv.onReceive = [&buf](swServer *serv, swEventData *req) -> int
    {
        char *data = nullptr;
        size_t length = serv->get_packet(serv, req, &data);

        string req_body(data + 4, length - 4);

        EXPECT_EQ(string(buf, sizeof(buf)), req_body);

        string pkt = string("Server: ") + req_body;
        int packed_len = htonl(pkt.length());

        serv->send(serv, req->info.fd, &packed_len, sizeof(packed_len));
        serv->send(serv, req->info.fd, pkt.c_str(), pkt.length());

        //end stream
        packed_len = htonl(0);
        serv->send(serv, req->info.fd, &packed_len, sizeof(packed_len));

        return SW_OK;
    };

    serv.start();
    t1.join();

    logger.set_level(ori_log_level);
}
