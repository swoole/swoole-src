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

#include "test_coroutine.h"
#include "httplib_server.h"

using namespace swoole::test;
using namespace httplib;
using namespace std;

TEST(coroutine_http_server, get) {
    Server svr;
    mutex lock;
    lock.lock();

    thread t1([&lock]() {
        lock.lock();
        Client cli(TEST_HOST, 8080);
        auto resp1 = cli.Get("/hi");
        EXPECT_EQ(resp1->status, 200);
        EXPECT_EQ(resp1->body, string("Hello World!"));

        auto resp2 = cli.Get("/stop");
        EXPECT_EQ(resp2->status, 200);
        EXPECT_EQ(resp2->body, string("Stop Server!"));
    });

    coroutine::run([&lock, &svr](void *arg) {
        svr.Get("/hi", [](const Request &req, Response &res) { res.set_content("Hello World!", "text/plain"); });

        svr.Get("/stop", [&svr](const Request &req, Response &res) {
            res.set_content("Stop Server!", "text/plain");
            svr.stop();
        });

        svr.Post("/post", [](const Request &req, Response &res) { res.set_content("Hello World!", "text/plain"); });

        svr.BeforeListen([&lock]() { lock.unlock(); });

        ASSERT_TRUE(svr.listen(TEST_HOST, 8080));
    });

    t1.join();
}

TEST(coroutine_http_server, post) {
    Server svr;
    mutex lock;
    lock.lock();

    std::thread t1([&lock]() {
        lock.lock();

        Client cli(TEST_HOST, 8080);

        httplib::Params params;
        params.emplace("name", "john");
        params.emplace("note", "coder");

        auto resp1 = cli.Post("/post", params);
        EXPECT_EQ(resp1->status, 200);
        EXPECT_EQ(resp1->body, string("Hello World!"));

        auto resp2 = cli.Get("/stop");
        EXPECT_EQ(resp2->status, 200);
        EXPECT_EQ(resp2->body, string("Stop Server!"));
    });

    coroutine::run([&lock, &svr](void *arg) {
        svr.Get("/stop", [&svr](const Request &req, Response &res) {
            res.set_content("Stop Server!", "text/plain");
            svr.stop();
        });

        svr.Post("/post", [](const Request &req, Response &res) { res.set_content("Hello World!", "text/plain"); });

        svr.BeforeListen([&lock]() { lock.unlock(); });

        svr.listen(TEST_HOST, 8080);
    });

    t1.join();
}
