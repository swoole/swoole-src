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
#include "swoole_memory.h"
#include "swoole_signal.h"
#include "swoole_lock.h"

using namespace std;
using namespace swoole;

constexpr int DATA_SIZE = 2 * SW_NUM_MILLION;

struct TestPacket {
    SessionId fd;
    std::string data;
};

struct TestMB {
    std::vector<TestPacket> q;
    MessageBus mb;
    std::function<ssize_t(network::Socket *)> read_func;

    bool send_empty_packet(network::Socket *sock) {
        SendData _data4;
        _data4.data = "hello world";
        _data4.info.fd = 4;
        _data4.info.len = 0;
        if (!mb.write(sock, &_data4)) {
            return false;
        }

        SendData _data5;
        _data5.data = nullptr;
        _data5.info.fd = 5;
        _data5.info.len = 10;
        if (!mb.write(sock, &_data5)) {
            return false;
        }

        return true;
    }

    int read(Event *ev) {
        auto retval = read_func(ev->socket);
        if (retval == 0) {
            return SW_OK;
        } else if (retval < 0) {
            swoole_event_del(ev->socket);
            return SW_ERR;
        }

        auto packet = mb.get_packet();

        q.push_back(TestPacket{
            mb.get_buffer()->info.fd,
            std::string(packet.data, packet.length),
        });

        if (q.size() == 5) {
            swoole_event_del(ev->socket);
        }

        return SW_OK;
    }
};

#define MB_SEND(i, s)                                                                                                  \
    String pkt##i(s);                                                                                                  \
    pkt##i.append_random_bytes(pkt##i.size - 1, false);                                                                \
    pkt##i.append('\0');                                                                                               \
                                                                                                                       \
    SendData _data##i{};                                                                                               \
    _data##i.data = pkt##i.value();                                                                                    \
    _data##i.info.fd = i;                                                                                              \
    _data##i.info.len = pkt##i.get_length();                                                                           \
    ASSERT_TRUE(tmb.mb.write(p.get_socket(true), &_data##i));

#define MB_ASSERT(i)                                                                                                   \
    auto r##i = tmb.q.at(i - 1);                                                                                       \
    ASSERT_EQ(r##i.fd, i);                                                                                             \
    ASSERT_STREQ(r##i.data.c_str(), pkt##i.value());

TEST(message_bus, read) {
    UnixSocket p(true, SOCK_STREAM);
    ASSERT_TRUE(p.ready());

    ASSERT_EQ(swoole_event_init(SW_EVENTLOOP_WAIT_EXIT), SW_OK);
    p.set_blocking(false);
    p.set_buffer_size(65536);

    uint64_t msg_id = 0;

    TestMB tmb{};
    tmb.mb.set_buffer_size(65536);
    tmb.mb.set_id_generator([&msg_id]() { return msg_id++; });
    tmb.mb.alloc_buffer();

    tmb.read_func = [&tmb](network::Socket *sock) {
        return tmb.mb.read(sock);
    };

    sw_reactor()->ptr = &tmb;

    ASSERT_EQ(swoole_event_add(p.get_socket(false), SW_EVENT_READ), SW_OK);

    swoole_event_set_handler(SW_FD_PIPE | SW_EVENT_READ, [](Reactor *reactor, Event *ev) -> int {
        TestMB *tmb = (TestMB *) reactor->ptr;
        return tmb->read(ev);
    });

    MB_SEND(1, DATA_SIZE);
    MB_SEND(2, tmb.mb.get_buffer_size());
    MB_SEND(3, 2341);

    tmb.send_empty_packet(p.get_socket(true));

    ASSERT_EQ(swoole_event_wait(), SW_OK);

    MB_ASSERT(1);
    MB_ASSERT(2);
    MB_ASSERT(3);

    auto r4 = tmb.q.at(3);
    ASSERT_EQ(r4.fd, 4);
    ASSERT_STREQ(r4.data.c_str(), "");

    auto r5 = tmb.q.at(4);
    ASSERT_EQ(r5.fd, 5);
    ASSERT_STREQ(r5.data.c_str(), "");
}

TEST(message_bus, read_with_buffer) {
    UnixSocket p(true, SOCK_DGRAM);
    ASSERT_TRUE(p.ready());

    ASSERT_EQ(swoole_event_init(SW_EVENTLOOP_WAIT_EXIT), SW_OK);
    p.set_blocking(false);
    p.set_buffer_size(65536);

    uint64_t msg_id = 0;

    TestMB tmb{};
    tmb.mb.set_buffer_size(65536);
    tmb.mb.set_id_generator([&msg_id]() { return msg_id++; });
    tmb.mb.alloc_buffer();

    tmb.read_func = [&tmb](network::Socket *sock) {
        return tmb.mb.read_with_buffer(sock);
    };

    sw_reactor()->ptr = &tmb;

    ASSERT_EQ(swoole_event_add(p.get_socket(false), SW_EVENT_READ), SW_OK);

    swoole_event_set_handler(SW_FD_PIPE | SW_EVENT_READ, [](Reactor *reactor, Event *ev) -> int {
        TestMB *tmb = (TestMB *) reactor->ptr;
        return tmb->read(ev);
    });

    MB_SEND(1, DATA_SIZE);
    MB_SEND(2, tmb.mb.get_buffer_size());
    MB_SEND(3, 2341);

    tmb.send_empty_packet(p.get_socket(true));

    ASSERT_EQ(swoole_event_wait(), SW_OK);

    MB_ASSERT(1);
    MB_ASSERT(2);
    MB_ASSERT(3);

    auto r4 = tmb.q.at(3);
    ASSERT_EQ(r4.fd, 4);
    ASSERT_STREQ(r4.data.c_str(), "");

    auto r5 = tmb.q.at(4);
    ASSERT_EQ(r5.fd, 5);
    ASSERT_STREQ(r5.data.c_str(), "");
}
