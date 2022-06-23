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

const std::string REDIS_TEST_KEY = "key-swoole";
const std::string REDIS_TEST_VALUE = "value-swoole";

TEST(redis, get) {
    test::coroutine::run([](void *arg) {
        RedisClient redis;
        ASSERT_TRUE(redis.Connect("127.0.0.1", 6379));
        ASSERT_TRUE(redis.Set(REDIS_TEST_KEY, REDIS_TEST_VALUE));
        ASSERT_EQ(redis.Get(REDIS_TEST_KEY), REDIS_TEST_VALUE);
    });
}

TEST(redis, server) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;
    serv.enable_static_handler = true;

    sw_logger()->set_level(SW_LOG_WARNING);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);
    port->open_redis_protocol = true;

    serv.create();

    serv.onWorkerStart = [&](swServer *serv, int worker_id) {
        if (worker_id != 0) {
            return;
        }
        swoole::Coroutine::create(
            [](void *arg) {
                Server *serv = reinterpret_cast<Server *>(arg);
                RedisClient redis;
                ASSERT_TRUE(redis.Connect("127.0.0.1", serv->get_primary_port()->port));
                ASSERT_TRUE(redis.Set(REDIS_TEST_KEY, REDIS_TEST_VALUE));
                ASSERT_EQ(redis.Get(REDIS_TEST_KEY), REDIS_TEST_VALUE);
                kill(serv->gs->master_pid, SIGTERM);
            },
            serv);
    };

    serv.onReceive = [](swServer *serv, swRecvData *req) -> int {
        int session_id = req->info.fd;
        auto list = redis::parse(req->data, req->info.len);

        String *buffer = sw_tg_buffer();
        buffer->clear();

        if (strcasecmp(list[0].c_str(), "GET") == 0) {
            redis::format(buffer, redis::REPLY_STRING, REDIS_TEST_VALUE);
            serv->send(session_id, buffer->str, buffer->length);
        } else if (strcasecmp(list[0].c_str(), "SET") == 0) {
            redis::format(buffer, redis::REPLY_STATUS, "OK");
            serv->send(session_id, buffer->str, buffer->length);
        }

        return SW_OK;
    };

    serv.start();
}
