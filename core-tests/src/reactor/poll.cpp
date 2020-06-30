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

static const char* pkt = "hello world\r\n";

TEST(reactor_poll, create)
{
    swReactor reactor = {};
    ASSERT_EQ(swReactorPoll_create(&reactor, 1024), SW_OK);
    reactor.onFinish = [](swReactor *reactor)
    {
        if (reactor->event_num == 0)
        {
            reactor->running = 0;
        }
    };

    swPipe p;
    ASSERT_EQ(swPipeBase_create(&p, 1), SW_OK);
    swReactor_set_handler(&reactor, SW_FD_PIPE | SW_EVENT_READ, [](swReactor *reactor, swEvent *event) -> int
    {
        char buf[1024];
        size_t l = strlen(pkt);
        size_t n = read(event->fd, buf, sizeof(buf));
        EXPECT_EQ(n, l);
        buf[n] = 0;
        EXPECT_EQ(std::string(buf, n), std::string(pkt));
        reactor->del(reactor, event->socket);

        return SW_OK;
    });
    swReactor_set_handler(&reactor, SW_FD_PIPE | SW_EVENT_WRITE, [](swReactor *reactor, swEvent *event) -> int
    {
        size_t l = strlen(pkt);
        EXPECT_EQ(write(event->fd, pkt, l), l);
        reactor->del(reactor, event->socket);

        return SW_OK;
    });
    reactor.add(&reactor, p.getSocket(&p, 0), SW_EVENT_READ);
    reactor.add(&reactor, p.getSocket(&p, 1), SW_EVENT_WRITE);
    reactor.wait(&reactor, nullptr);
    reactor.free(&reactor);

    p.close(&p);
}
