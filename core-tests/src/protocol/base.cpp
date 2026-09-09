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

constexpr int PKG_N = 128;
constexpr int MAX_SIZE = 1 * 1024 * 1024 + 65536;
constexpr int MIN_SIZE = 512;

static void test_protocol(Server &serv, ListenPort *port, String *pkgs) {
    mutex lock;
    lock.lock();
    serv.create();

    String wbuf;

    for (int i = 0; i < PKG_N; i++) {
        wbuf.append(pkgs[i]);
    }

    DEBUG() << "data total length: " << wbuf.length << "\n";

    thread t1([&]() {
        swoole_signal_block_all();
        lock.lock();

        network::Client cli(SW_SOCK_TCP, false);
        EXPECT_EQ(cli.connect(TEST_HOST, port->port, 1, 0), 0);

        off_t offset = 0;
        while (offset < (off_t) wbuf.length) {
            auto n = wbuf.length - offset > 65536 ? swoole_random_int() % 65536 + 1 : wbuf.length - offset;
            ASSERT_EQ(cli.send(wbuf.str + offset, n), n);
            offset += n;
        }

        usleep(100000);
    });

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock.unlock(); };

    int recv_count = 0;

    serv.onReceive = [&](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(memcmp(req->data, pkgs[recv_count].str, req->info.len), 0);
        recv_count++;
        if (recv_count == PKG_N) {
            usleep(100000);
            serv->shutdown();
        }
        return SW_OK;
    };

    serv.start();

    t1.join();
}

TEST(protocol, length) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;

    String pkgs[PKG_N];

    for (int i = 0; i < PKG_N; i++) {
        auto pkt_len = swoole_rand(MIN_SIZE, MAX_SIZE);
        auto pkt_len_net = htonl(pkt_len);
        pkgs[i].append((char *) &pkt_len_net, sizeof(pkt_len_net));
        pkgs[i].append_random_bytes(pkt_len, false);
    }

    sw_logger()->set_level(SW_LOG_WARNING);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);
    port->set_stream_protocol();

    test_protocol(serv, port, pkgs);
}

TEST(protocol, length_2) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);
    port->set_stream_protocol();

    mutex lock;
    lock.lock();
    serv.create();

    thread t1([&]() {
        swoole_signal_block_all();
        lock.lock();
        char rbuf[32];
        usleep(50000);

        //  测试分多次发送长度
        {
            network::Client cli(SW_SOCK_TCP, false);
            EXPECT_EQ(cli.connect(TEST_HOST, port->port, 1, 0), 0);

            String wbuf;

            auto pkt_len = swoole_rand(MIN_SIZE, MAX_SIZE);
            auto pkt_len_net = htonl(pkt_len);
            wbuf.append((char *) &pkt_len_net, sizeof(pkt_len_net));
            wbuf.append_random_bytes(pkt_len, false);

            ASSERT_EQ(cli.send(wbuf.str, 2), 2);
            usleep(10);
            ASSERT_EQ(cli.send(wbuf.str + 2, 4), 4);
            usleep(10);
            ASSERT_EQ(cli.send(wbuf.str + 2, wbuf.length - 6), wbuf.length - 6);

            ASSERT_EQ(cli.recv(rbuf, sizeof(rbuf), 0), 3);
            ASSERT_STREQ(rbuf, "OK");
        }

        //  发送 0 长度的包
        {
            network::Client cli(SW_SOCK_TCP, false);
            EXPECT_EQ(cli.connect(TEST_HOST, port->port, 1, 0), 0);

            auto pkt_len = 0;
            auto pkt_len_net = htonl(pkt_len);

            ASSERT_EQ(cli.send((char *) &pkt_len_net, sizeof(pkt_len)), sizeof(pkt_len));
            ASSERT_EQ(cli.recv(rbuf, sizeof(rbuf), 0), 3);
            ASSERT_STREQ(rbuf, "OK");
        }

        //  发送 INT_MAX 长度的包
        {
            network::Client cli(SW_SOCK_TCP, false);
            EXPECT_EQ(cli.connect(TEST_HOST, port->port, 1, 0), 0);

            auto pkt_len = INT_MAX;
            auto pkt_len_net = htonl(pkt_len);

            ASSERT_EQ(cli.send((char *) &pkt_len_net, sizeof(pkt_len)), sizeof(pkt_len));
            ASSERT_EQ(cli.recv(rbuf, sizeof(rbuf), 0), 0);
        }
        usleep(50000);
        serv.shutdown();
    });

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock.unlock(); };

    serv.onReceive = [&](Server *serv, RecvData *req) -> int {
        serv->send(req->session_id(), SW_STRL("OK\0"));
        return SW_OK;
    };

    serv.start();
    t1.join();
}

TEST(protocol, length_3) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);
    port->set_length_protocol(0, 'l', 4);

    mutex lock;
    lock.lock();
    serv.create();

    thread t1([&]() {
        swoole_signal_block_all();
        lock.lock();
        char rbuf[32];
        usleep(50000);

        network::Client cli(SW_SOCK_TCP, false);
        EXPECT_EQ(cli.connect(TEST_HOST, port->port, 1, 0), 0);

        auto pkt_len = -1;

        ASSERT_EQ(cli.send((char *) &pkt_len, sizeof(pkt_len)), sizeof(pkt_len));
        ASSERT_EQ(cli.recv(rbuf, sizeof(rbuf), 0), 0);

        usleep(50000);
        serv.shutdown();
    });

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock.unlock(); };

    serv.onReceive = [&](Server *serv, RecvData *req) -> int {
        serv->send(req->session_id(), SW_STRL("OK\0"));
        return SW_OK;
    };

    serv.start();
    t1.join();
}

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

    test_protocol(serv, port, pkgs);
}

TEST(protocol, socks5_strerror) {
    SW_LOOP_N(16) {
        auto error = Socks5Proxy::strerror(i);
        if (i > 0x08) {
            ASSERT_STREQ("Unknown error", error);
        } else {
            ASSERT_GT(strlen(error), 5);
        }
    }
}

TEST(protocol, socks5_dns_tunnel_target_host_length) {
    auto proxy = Socks5Proxy::create(SW_SOCK_TCP, "127.0.0.1", 1080, "", "");
    ASSERT_NE(proxy, nullptr);
    proxy->dns_tunnel = 1;
    proxy->target_host = std::string(500, 'a');
    proxy->target_port = 80;
    // pack_connect_request should validate target_host (not proxy host) in DNS tunnel mode
    ASSERT_EQ(proxy->pack_connect_request(), -1);
    delete proxy;
}

TEST(protocol, socks5_fragmented_no_auth_response) {
    auto proxy = std::unique_ptr<Socks5Proxy>(Socks5Proxy::create(SW_SOCK_TCP, "127.0.0.1", 1080, "", ""));
    ASSERT_NE(proxy, nullptr);
    proxy->target_host = "socks5-target.test";
    proxy->target_port = 80;

    ASSERT_EQ(proxy->pack_negotiate_request(), 3);
    ASSERT_MEMEQ(proxy->buf, "\x05\x01\x00", 3);
    proxy->state = SW_SOCKS5_STATE_HANDSHAKE;

    std::vector<std::string> requests;
    auto send_fn = [&requests](const char *buf, size_t len) {
        requests.emplace_back(buf, len);
        return static_cast<ssize_t>(len);
    };

    ASSERT_TRUE(proxy->handshake("\x05", 1, send_fn));
    ASSERT_EQ(proxy->get_recv_length(), 1);
    ASSERT_EQ(proxy->pack_negotiate_request(), 3);
    ASSERT_EQ(proxy->get_recv_length(), 2);
    ASSERT_TRUE(proxy->handshake("\x05", 1, send_fn));
    ASSERT_EQ(proxy->get_recv_length(), 1);
    ASSERT_TRUE(proxy->handshake("\x00", 1, send_fn));
    ASSERT_EQ(proxy->state, SW_SOCKS5_STATE_CONNECT);
    ASSERT_EQ(proxy->get_recv_length(), 4);
    ASSERT_EQ(requests.size(), 1);
    ASSERT_EQ(requests[0].length(), 25);
    ASSERT_MEMEQ(requests[0].data(), "\x05\x01\x00\x03", 4);
    ASSERT_EQ(static_cast<uchar>(requests[0][4]), 18);
    ASSERT_MEMEQ(requests[0].data() + 5, "socks5-target.test", 18);

    const std::string response("\x05\x00\x00\x01\x7f\x00\x00\x01\x1f\x90", 10);
    const size_t remaining[] = {3, 2, 1, 6, 5, 4, 3, 2, 1, 0};
    for (size_t i = 0; i < response.length(); i++) {
        ASSERT_TRUE(proxy->handshake(response.data() + i, 1, send_fn));
        ASSERT_EQ(proxy->get_recv_length(), remaining[i]);
    }
    ASSERT_EQ(proxy->state, SW_SOCKS5_STATE_READY);
}

TEST(protocol, socks5_fragmented_auth_and_domain_response) {
    auto proxy =
        std::unique_ptr<Socks5Proxy>(Socks5Proxy::create(SW_SOCK_TCP, "127.0.0.1", 1080, "username", "password"));
    ASSERT_NE(proxy, nullptr);
    proxy->target_host = "socks5-target.test";
    proxy->target_port = 80;

    ASSERT_EQ(proxy->pack_negotiate_request(), 3);
    ASSERT_MEMEQ(proxy->buf, "\x05\x01\x02", 3);
    proxy->state = SW_SOCKS5_STATE_HANDSHAKE;

    std::vector<std::string> requests;
    auto send_fn = [&requests](const char *buf, size_t len) {
        requests.emplace_back(buf, len);
        return static_cast<ssize_t>(len);
    };

    ASSERT_TRUE(proxy->handshake("\x05", 1, send_fn));
    ASSERT_EQ(proxy->get_recv_length(), 1);
    ASSERT_TRUE(proxy->handshake("\x02", 1, send_fn));
    ASSERT_EQ(proxy->state, SW_SOCKS5_STATE_AUTH);
    ASSERT_EQ(proxy->get_recv_length(), 2);
    ASSERT_EQ(requests.size(), 1);
    ASSERT_EQ(requests[0].length(), 19);
    ASSERT_MEMEQ(requests[0].data(), "\x01\x08username\x08password", 19);

    ASSERT_TRUE(proxy->handshake("\x01", 1, send_fn));
    ASSERT_EQ(proxy->get_recv_length(), 1);
    ASSERT_TRUE(proxy->handshake("\x00", 1, send_fn));
    ASSERT_EQ(proxy->state, SW_SOCKS5_STATE_CONNECT);
    ASSERT_EQ(proxy->get_recv_length(), 4);
    ASSERT_EQ(requests.size(), 2);

    const std::string response("\x05\x00\x00\x03\x03"
                               "abc\x1f\x90",
                               10);
    const size_t remaining[] = {3, 2, 1, 1, 5, 4, 3, 2, 1, 0};
    for (size_t i = 0; i < response.length(); i++) {
        ASSERT_TRUE(proxy->handshake(response.data() + i, 1, send_fn));
        ASSERT_EQ(proxy->get_recv_length(), remaining[i]);
    }
    ASSERT_EQ(proxy->state, SW_SOCKS5_STATE_READY);
}

TEST(protocol, socks5_fragmented_ipv6_response) {
    auto send_fn = [](const char *, size_t len) { return static_cast<ssize_t>(len); };

    auto ipv6_proxy = std::unique_ptr<Socks5Proxy>(Socks5Proxy::create(SW_SOCK_TCP6, "::1", 1080, "", ""));
    ASSERT_NE(ipv6_proxy, nullptr);
    ipv6_proxy->state = SW_SOCKS5_STATE_CONNECT;
    const std::string ipv6_response(
        "\x05\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x1f\x90", 22);
    for (size_t i = 0; i < ipv6_response.length(); i++) {
        ASSERT_TRUE(ipv6_proxy->handshake(ipv6_response.data() + i, 1, send_fn));
        ASSERT_EQ(ipv6_proxy->get_recv_length(), i < 3 ? 3 - i : 21 - i);
    }
    ASSERT_EQ(ipv6_proxy->state, SW_SOCKS5_STATE_READY);
}

TEST(protocol, socks5_long_domain_response) {
    auto send_fn = [](const char *, size_t len) { return static_cast<ssize_t>(len); };
    auto domain_proxy = std::unique_ptr<Socks5Proxy>(Socks5Proxy::create(SW_SOCK_TCP, "127.0.0.1", 1080, "", ""));
    ASSERT_NE(domain_proxy, nullptr);
    domain_proxy->state = SW_SOCKS5_STATE_CONNECT;
    const std::string domain_header("\x05\x00\x00\x03\xff", 5);
    ASSERT_TRUE(domain_proxy->handshake(domain_header.data(), 4, send_fn));
    ASSERT_EQ(domain_proxy->get_recv_length(), 1);
    ASSERT_TRUE(domain_proxy->handshake(domain_header.data() + 4, 1, send_fn));
    ASSERT_EQ(domain_proxy->get_recv_length(), 257);
    std::string domain(255, 'a');
    domain.append("\x1f\x90", 2);
    ASSERT_TRUE(domain_proxy->handshake(domain.data(), domain.length(), send_fn));
    ASSERT_EQ(domain_proxy->state, SW_SOCKS5_STATE_READY);
}

TEST(protocol, socks5_response_errors) {
    auto send_fn = [](const char *, size_t len) { return static_cast<ssize_t>(len); };

    auto version_proxy = std::unique_ptr<Socks5Proxy>(Socks5Proxy::create(SW_SOCK_TCP, "127.0.0.1", 1080, "", ""));
    ASSERT_NE(version_proxy, nullptr);
    version_proxy->state = SW_SOCKS5_STATE_CONNECT;
    ASSERT_FALSE(version_proxy->handshake("\x04\x00\x00\x01", 4, send_fn));
    ASSERT_ERREQ(SW_ERROR_SOCKS5_UNSUPPORT_VERSION);

    auto server_proxy = std::unique_ptr<Socks5Proxy>(Socks5Proxy::create(SW_SOCK_TCP, "127.0.0.1", 1080, "", ""));
    ASSERT_NE(server_proxy, nullptr);
    server_proxy->state = SW_SOCKS5_STATE_CONNECT;
    ASSERT_FALSE(server_proxy->handshake("\x05\x05\x00\xff", 4, send_fn));
    ASSERT_ERREQ(SW_ERROR_SOCKS5_SERVER_ERROR);

    auto address_proxy = std::unique_ptr<Socks5Proxy>(Socks5Proxy::create(SW_SOCK_TCP, "127.0.0.1", 1080, "", ""));
    ASSERT_NE(address_proxy, nullptr);
    address_proxy->state = SW_SOCKS5_STATE_CONNECT;
    ASSERT_FALSE(address_proxy->handshake("\x05\x00\x00\xff", 4, send_fn));
    ASSERT_ERREQ(SW_ERROR_SOCKS5_HANDSHAKE_FAILED);

    auto method_proxy = std::unique_ptr<Socks5Proxy>(Socks5Proxy::create(SW_SOCK_TCP, "127.0.0.1", 1080, "", ""));
    ASSERT_NE(method_proxy, nullptr);
    ASSERT_EQ(method_proxy->pack_negotiate_request(), 3);
    method_proxy->state = SW_SOCKS5_STATE_HANDSHAKE;
    ASSERT_FALSE(method_proxy->handshake("\x05\x02", 2, send_fn));
    ASSERT_ERREQ(SW_ERROR_SOCKS5_UNSUPPORT_METHOD);

    auto auth_version_proxy =
        std::unique_ptr<Socks5Proxy>(Socks5Proxy::create(SW_SOCK_TCP, "127.0.0.1", 1080, "username", "password"));
    ASSERT_NE(auth_version_proxy, nullptr);
    ASSERT_EQ(auth_version_proxy->pack_negotiate_request(), 3);
    auth_version_proxy->state = SW_SOCKS5_STATE_AUTH;
    ASSERT_FALSE(auth_version_proxy->handshake("\x02\x00", 2, send_fn));
    ASSERT_ERREQ(SW_ERROR_SOCKS5_UNSUPPORT_VERSION);

    auto auth_proxy =
        std::unique_ptr<Socks5Proxy>(Socks5Proxy::create(SW_SOCK_TCP, "127.0.0.1", 1080, "username", "password"));
    ASSERT_NE(auth_proxy, nullptr);
    ASSERT_EQ(auth_proxy->pack_negotiate_request(), 3);
    auth_proxy->state = SW_SOCKS5_STATE_AUTH;
    ASSERT_FALSE(auth_proxy->handshake("\x01\x01", 2, send_fn));
    ASSERT_ERREQ(SW_ERROR_SOCKS5_AUTH_FAILED);
}

TEST(protocol, swap_byte_order) {
    {
        EXPECT_EQ(swoole_swap_endian16(0x1234), 0x3412);
        EXPECT_EQ(swoole_swap_endian16(0x0001), 0x0100);
        EXPECT_EQ(swoole_swap_endian16(0x00FF), 0xFF00);
        EXPECT_EQ(swoole_swap_endian16(0xFF00), 0x00FF);
        EXPECT_EQ(swoole_swap_endian16(0xFFFF), 0xFFFF);
    }

    {
        EXPECT_EQ(swoole_swap_endian32(0x12345678), 0x78563412);
        EXPECT_EQ(swoole_swap_endian32(0x00000001), 0x01000000);
        EXPECT_EQ(swoole_swap_endian32(0x0000FF00), 0x00FF0000);
        EXPECT_EQ(swoole_swap_endian32(0xFF000000), 0x000000FF);
        EXPECT_EQ(swoole_swap_endian32(0xFFFFFFFF), 0xFFFFFFFF);
    }

    {
        uint16_t v = 0xABCD;
        EXPECT_EQ(swoole_swap_endian16(swoole_swap_endian16(v)), v);
    }

    {
        uint32_t v = 0xABCDEF01;
        EXPECT_EQ(swoole_swap_endian32(swoole_swap_endian32(v)), v);
    }

    {
        uint64_t val = 0x1122334455667788ULL;
        auto converted = swoole_swap_endian64(val);

        auto str = (uchar *) &converted;
        EXPECT_EQ(str[0], 0x11);
        EXPECT_EQ(str[1], 0x22);
        EXPECT_EQ(str[2], 0x33);
        EXPECT_EQ(str[3], 0x44);
        EXPECT_EQ(str[4], 0x55);
        EXPECT_EQ(str[5], 0x66);
        EXPECT_EQ(str[6], 0x77);
        EXPECT_EQ(str[7], 0x88);
    }
}

// Helper function to create binary data for testing
template <typename T>
void createBinaryData(T value, char *buffer) {
    memcpy(buffer, &value, sizeof(T));
}

TEST(protocol, unpack) {
    // Tests for 8-bit integer formats
    {
        char buffer[8];

        // Test signed char ('c')
        int8_t c_val = -42;
        createBinaryData(c_val, buffer);
        EXPECT_EQ(swoole_unpack('c', buffer), -42);

        // Test unsigned char ('C')
        uint8_t C_val = 200;
        createBinaryData(C_val, buffer);
        EXPECT_EQ(swoole_unpack('C', buffer), 200);

        // Test extreme values
        createBinaryData<int8_t>(INT8_MIN, buffer);
        EXPECT_EQ(swoole_unpack('c', buffer), INT8_MIN);

        createBinaryData<int8_t>(INT8_MAX, buffer);
        EXPECT_EQ(swoole_unpack('c', buffer), INT8_MAX);

        createBinaryData<uint8_t>(UINT8_MAX, buffer);
        EXPECT_EQ(swoole_unpack('C', buffer), UINT8_MAX);
    }

    // Tests for 16-bit integer formats
    {
        char buffer[8];

        // Test signed short ('s')
        int16_t s_val = -12345;
        createBinaryData(s_val, buffer);
        EXPECT_EQ(swoole_unpack('s', buffer), -12345);

        // Test unsigned short ('S')
        uint16_t S_val = 54321;
        createBinaryData(S_val, buffer);
        EXPECT_EQ(swoole_unpack('S', buffer), 54321);

        // Test big-endian unsigned short ('n')
        uint16_t n_val = 0x1234;
        uint16_t n_be = (n_val >> 8) | (n_val << 8);  // Convert to big-endian
        createBinaryData(n_be, buffer);
        EXPECT_EQ(swoole_unpack('n', buffer), 0x1234);

        // Test little-endian unsigned short ('v')
        uint16_t v_val = 0x1234;
        createBinaryData(v_val, buffer);
        EXPECT_EQ(swoole_unpack('v', buffer), 0x1234);

        // Test extreme values
        createBinaryData<int16_t>(INT16_MIN, buffer);
        EXPECT_EQ(swoole_unpack('s', buffer), INT16_MIN);

        createBinaryData<int16_t>(INT16_MAX, buffer);
        EXPECT_EQ(swoole_unpack('s', buffer), INT16_MAX);

        createBinaryData<uint16_t>(UINT16_MAX, buffer);
        EXPECT_EQ(swoole_unpack('S', buffer), UINT16_MAX);
    }

    // Tests for 32-bit integer formats
    {
        char buffer[8];

        // Test signed long ('l')
        int32_t l_val = -123456789;
        createBinaryData(l_val, buffer);
        EXPECT_EQ(swoole_unpack('l', buffer), -123456789);

        // Test unsigned long ('L')
        uint32_t L_val = 3000000000;
        createBinaryData(L_val, buffer);
        EXPECT_EQ(swoole_unpack('L', buffer), 3000000000);

        // Test big-endian unsigned long ('N')
        uint32_t N_val = 0x12345678;
        uint32_t N_be =
            ((N_val & 0xFF) << 24) | ((N_val & 0xFF00) << 8) | ((N_val & 0xFF0000) >> 8) | ((N_val & 0xFF000000) >> 24);
        createBinaryData(N_be, buffer);
        EXPECT_EQ(swoole_unpack('N', buffer), 0x12345678);

        // Test little-endian unsigned long ('V')
        uint32_t V_val = 0x12345678;
        createBinaryData(V_val, buffer);
        EXPECT_EQ(swoole_unpack('V', buffer), 0x12345678);

        // Test extreme values
        createBinaryData<int32_t>(INT32_MIN, buffer);
        EXPECT_EQ(swoole_unpack('l', buffer), INT32_MIN);

        createBinaryData<int32_t>(INT32_MAX, buffer);
        EXPECT_EQ(swoole_unpack('l', buffer), INT32_MAX);

        createBinaryData<uint32_t>(UINT32_MAX, buffer);
        EXPECT_EQ(swoole_unpack('L', buffer), UINT32_MAX);
    }

    // Tests for 64-bit integer formats
    {
        char buffer[8];

        // Test signed long long ('q')
        int64_t q_val = -1234567890123456789LL;
        createBinaryData(q_val, buffer);
        EXPECT_EQ(swoole_unpack('q', buffer), -1234567890123456789LL);

        // Test unsigned long long ('Q')
        uint64_t Q_val = 10234567890123456789ULL;
        createBinaryData(Q_val, buffer);
        EXPECT_EQ(swoole_unpack('Q', buffer), 10234567890123456789ULL);

        // Test big-endian unsigned long long ('J')
        uint64_t J_val = 0x123456789ABCDEF0ULL;
        uint64_t J_be = swoole_swap_endian64(J_val);  // Use our swap function for test
        createBinaryData(J_be, buffer);
        EXPECT_EQ(swoole_unpack('J', buffer), 0x123456789ABCDEF0ULL);

        // Test little-endian unsigned long long ('P')
        uint64_t P_val = 0x123456789ABCDEF0ULL;
        createBinaryData(P_val, buffer);
        EXPECT_EQ(swoole_unpack('P', buffer), 0x123456789ABCDEF0ULL);

        // Test extreme values (be careful with signed min/max due to two's complement)
        createBinaryData<int64_t>(INT64_MIN, buffer);
        EXPECT_EQ(swoole_unpack('q', buffer), INT64_MIN);

        createBinaryData<int64_t>(INT64_MAX, buffer);
        EXPECT_EQ(swoole_unpack('q', buffer), INT64_MAX);

        // For UINT64_MAX, be aware that the return type is int64_t, so this might not work as expected
        // This test might fail due to the limitation of the return type
        createBinaryData<uint64_t>(UINT64_MAX, buffer);
        EXPECT_EQ(swoole_unpack('Q', buffer), (int64_t) UINT64_MAX);
    }

    // Tests for machine-dependent integer formats
    {
        char buffer[8];

        // Test signed integer ('i')
        int i_val = -987654321;
        createBinaryData(i_val, buffer);
        EXPECT_EQ(swoole_unpack('i', buffer), -987654321);

        // Test unsigned integer ('I')
        unsigned int I_val = 3000000000;
        createBinaryData(I_val, buffer);
        EXPECT_EQ(swoole_unpack('I', buffer), 3000000000);

        // Test extreme values
        createBinaryData<int>(INT_MIN, buffer);
        EXPECT_EQ(swoole_unpack('i', buffer), INT_MIN);

        createBinaryData<int>(INT_MAX, buffer);
        EXPECT_EQ(swoole_unpack('i', buffer), INT_MAX);

        createBinaryData<unsigned int>(UINT_MAX, buffer);
        EXPECT_EQ(swoole_unpack('I', buffer), (int64_t) UINT_MAX);
    }

    // Test for invalid format specifier
    {
        char buffer[8] = {0};

        // Test invalid format specifier
        EXPECT_EQ(swoole_unpack('x', buffer), -1);
        EXPECT_EQ(swoole_unpack('?', buffer), -1);
        EXPECT_EQ(swoole_unpack('Z', buffer), -1);
    }

    // Test for endianness-specific behavior
    {
        char buffer[8];

        // Test that 'n' and 'v' formats handle endianness correctly
        buffer[0] = 0x12;
        buffer[1] = 0x34;
        EXPECT_EQ(swoole_unpack('n', buffer), 0x1234);

        buffer[0] = 0x34;
        buffer[1] = 0x12;
        EXPECT_EQ(swoole_unpack('v', buffer), 0x1234);

        // Test that 'N' and 'V' formats handle endianness correctly
        buffer[0] = 0x12;
        buffer[1] = 0x34;
        buffer[2] = 0x56;
        buffer[3] = 0x78;
        EXPECT_EQ(swoole_unpack('N', buffer), 0x12345678);

        buffer[0] = 0x78;
        buffer[1] = 0x56;
        buffer[2] = 0x34;
        buffer[3] = 0x12;
        EXPECT_EQ(swoole_unpack('V', buffer), 0x12345678);

        // Test that 'J' and 'P' formats handle endianness correctly
        buffer[0] = 0x12;
        buffer[1] = 0x34;
        buffer[2] = 0x56;
        buffer[3] = 0x78;
        buffer[4] = 0x9A;
        buffer[5] = 0xBC;
        buffer[6] = 0xDE;
        buffer[7] = 0xF0;
        EXPECT_EQ(swoole_unpack('J', buffer), 0x123456789ABCDEF0ULL);

        buffer[0] = 0xF0;
        buffer[1] = 0xDE;
        buffer[2] = 0xBC;
        buffer[3] = 0x9A;
        buffer[4] = 0x78;
        buffer[5] = 0x56;
        buffer[6] = 0x34;
        buffer[7] = 0x12;
        EXPECT_EQ(swoole_unpack('P', buffer), 0x123456789ABCDEF0ULL);
    }

    {
        char buffer[8];

        // Test that 'n' format uses ntohs() correctly
        uint16_t test16 = 0x1234;
        uint16_t be16 = htons(test16);  // Convert to network byte order
        createBinaryData(be16, buffer);
        EXPECT_EQ(swoole_unpack('n', buffer), 0x1234);

        // Test that 'N' format uses ntohl() correctly
        uint32_t test32 = 0x12345678;
        uint32_t be32 = htonl(test32);  // Convert to network byte order
        createBinaryData(be32, buffer);
        EXPECT_EQ(swoole_unpack('N', buffer), 0x12345678);

        // Test that 'J' format uses swoole_ntoh64() correctly
        uint64_t test64 = 0x123456789ABCDEF0ULL;
        uint64_t be64 = swoole_hton64(test64);  // Convert to network byte order
        createBinaryData(be64, buffer);
        EXPECT_EQ(swoole_unpack('J', buffer), 0x123456789ABCDEF0ULL);
    }
}

TEST(protocol, hton64) {
    {
        uint64_t val = 0x1122334455667788ULL;
        uint64_t converted = swoole_hton64(val);

        auto str = (uchar *) &converted;
        EXPECT_EQ(str[0], 0x11);
        EXPECT_EQ(str[1], 0x22);
        EXPECT_EQ(str[2], 0x33);
        EXPECT_EQ(str[3], 0x44);
        EXPECT_EQ(str[4], 0x55);
        EXPECT_EQ(str[5], 0x66);
        EXPECT_EQ(str[6], 0x77);
        EXPECT_EQ(str[7], 0x88);

        uint64_t reversed = swoole_ntoh64(converted);
        EXPECT_EQ(reversed, val);
    }

    {
        uint64_t min_val = 0ULL;
        uint64_t min_converted = swoole_hton64(min_val);

        auto min_str = (unsigned char *) &min_converted;
        for (int i = 0; i < 8; i++) {
            EXPECT_EQ(min_str[i], 0x00) << "Byte " << i << " should be 0x00";
        }

        EXPECT_EQ(swoole_ntoh64(min_converted), min_val);

        // 测试最大值
        uint64_t max_val = UINT64_MAX;
        uint64_t max_converted = swoole_hton64(max_val);

        auto max_str = (unsigned char *) &max_converted;
        for (int i = 0; i < 8; i++) {
            EXPECT_EQ(max_str[i], 0xFF) << "Byte " << i << " should be 0xFF";
        }

        EXPECT_EQ(swoole_ntoh64(max_converted), max_val);
    }

    {
        uint64_t alt_pattern = 0xAAAAAAAAAAAAAAAAULL;
        uint64_t alt_converted = swoole_hton64(alt_pattern);
        EXPECT_EQ(swoole_ntoh64(alt_converted), alt_pattern);

        uint64_t alt_pattern2 = 0x5555555555555555ULL;
        uint64_t alt_converted2 = swoole_hton64(alt_pattern2);
        EXPECT_EQ(swoole_ntoh64(alt_converted2), alt_pattern2);

        // 测试单字节模式
        for (int i = 0; i < 8; i++) {
            uint64_t single_byte = 0xFFULL << (i * 8);
            uint64_t converted = swoole_hton64(single_byte);
            EXPECT_EQ(swoole_ntoh64(converted), single_byte) << "Failed for byte position " << i;
        }
    }

    {
        for (int i = 0; i < 100; i++) {
            uint64_t random_val = swoole_random_int();
            uint64_t converted = swoole_hton64(random_val);
            uint64_t reversed = swoole_ntoh64(converted);

            EXPECT_EQ(reversed, random_val) << "Failed for random value: 0x" << std::hex << random_val;
        }
    }

    {
        uint64_t test_val = 0x0102030405060708ULL;
        uint64_t converted = swoole_hton64(test_val);

        auto bytes = (unsigned char *) &converted;

        EXPECT_EQ(bytes[0], 0x01);
        EXPECT_EQ(bytes[1], 0x02);
        EXPECT_EQ(bytes[2], 0x03);
        EXPECT_EQ(bytes[3], 0x04);
        EXPECT_EQ(bytes[4], 0x05);
        EXPECT_EQ(bytes[5], 0x06);
        EXPECT_EQ(bytes[6], 0x07);
        EXPECT_EQ(bytes[7], 0x08);
    }

    {
        for (int i = 0; i < 100; i++) {
            uint64_t val = swoole_random_int();
            EXPECT_EQ(swoole_ntoh64(swoole_hton64(val)), val) << "hton64->ntoh64 failed for 0x" << std::hex << val;
            EXPECT_EQ(swoole_hton64(swoole_ntoh64(val)), val) << "ntoh64->hton64 failed for 0x" << std::hex << val;
        }
    }
}
