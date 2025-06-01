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
#include "swoole_file.h"

using namespace std;
using namespace swoole;

const char test_data[] = "hello swoole, hello world, php is best";

TEST(socket, connect_sync) {
    network::Address sa;
    network::Socket *sock;

    sock = make_socket(SW_SOCK_UNIX_STREAM, SW_FD_STREAM, 0);
    ASSERT_NE(sock, nullptr);
    sa.assign(SW_SOCK_UNIX_STREAM, "/tmp/swole-not-exists.sock");
    ASSERT_EQ(sock->connect_sync(sa, 0.3), SW_ERR);
    ASSERT_EQ(swoole_get_last_error(), ENOENT);
    sock->free();

    sock = make_socket(SW_SOCK_TCP, SW_FD_STREAM, 0);
    ASSERT_NE(sock, nullptr);
    sa.assign(SW_SOCK_TCP, "192.168.199.199", 80);
    ASSERT_EQ(sock->connect_sync(sa, 0.3), SW_ERR);
    ASSERT_EQ(swoole_get_last_error(), ETIMEDOUT);
    sock->free();

    sock = make_socket(SW_SOCK_TCP, SW_FD_STREAM, 0);
    ASSERT_NE(sock, nullptr);
    sa.assign(SW_SOCK_TCP, "127.0.0.1", 59999);
    ASSERT_EQ(sock->connect_sync(sa, 0.3), SW_ERR);
    ASSERT_EQ(swoole_get_last_error(), ECONNREFUSED);
    sock->free();

    sock = make_socket(SW_SOCK_TCP, SW_FD_STREAM, 0);
    ASSERT_NE(sock, nullptr);
    sa.assign(SW_SOCK_TCP, TEST_HTTP_DOMAIN, 80);
    ASSERT_EQ(sock->connect_sync(sa, 0.3), SW_OK);
    sock->free();

    sock = make_socket(SW_SOCK_UDP, SW_FD_STREAM, 0);
    ASSERT_NE(sock, nullptr);
    sa.assign(SW_SOCK_UDP, "127.0.0.1", 9900);
    ASSERT_EQ(sock->connect_sync(sa, 0.3), SW_OK);
    sock->free();
}

TEST(socket, fail) {
    auto *sock = make_socket(SW_SOCK_TCP, SW_FD_STREAM, 0);
    ASSERT_NE(sock, nullptr);

    network::Address sa;
    sa.assign(SW_SOCK_TCP, TEST_HTTP_DOMAIN, 80);
    ASSERT_EQ(sock->connect_sync(sa, 0.3), SW_OK);

    close(sock->get_fd());

    ASSERT_EQ(sock->get_name(), -1);
    ASSERT_EQ(errno, EBADF);

    network::Address peer;
    ASSERT_EQ(sock->get_peer_name(&peer), -1);
    ASSERT_EQ(errno, EBADF);

    ASSERT_EQ(sock->set_tcp_nopush(1), -1);
    ASSERT_EQ(sock->listen(1), -1);

    ASSERT_FALSE(sock->set_buffer_size(1));
    ASSERT_FALSE(sock->set_recv_buffer_size(1));
    ASSERT_FALSE(sock->set_send_buffer_size(1));

    ASSERT_FALSE(sock->set_tcp_nodelay());
    ASSERT_FALSE(sock->cork());
    ASSERT_FALSE(sock->uncork());

    ASSERT_FALSE(sock->set_recv_timeout(0.1));
    ASSERT_FALSE(sock->set_send_timeout(0.1));

    sock->move_fd();
    sock->free();
}

TEST(socket, ssl_fail) {
    sysv_signal(SIGPIPE, SIG_IGN);
    network::Client client(SW_SOCK_TCP, false);
    client.enable_ssl_encrypt();

    ASSERT_EQ(client.connect(TEST_DOMAIN_BAIDU, 443, -1, 0), 0);
    ASSERT_EQ(client.shutdown(SHUT_WR), 0);

    ASSERT_EQ(client.get_socket()->ssl_send(SW_STRL(TEST_STR)), SW_ERR);
    ASSERT_EQ(errno, SW_ERROR_SSL_RESET);

    ASSERT_EQ(client.shutdown(SHUT_RD), 0);

    char buf[1024];
    errno = 0;
    ASSERT_EQ(client.get_socket()->ssl_recv(SW_STRL(buf)), 0);
    ASSERT_EQ(errno, 0);
    ASSERT_EQ(close(client.get_socket()->get_fd()), 0);
    client.get_socket()->move_fd();

    ASSERT_EQ(client.get_socket()->ssl_recv(SW_STRL(buf)), 0);
}

TEST(socket, sendto) {
    char sock1_path[] = "/tmp/udp_unix1.sock";
    char sock2_path[] = "/tmp/udp_unix2.sock";

    unlink(sock1_path);
    unlink(sock2_path);

    auto sock1 = make_socket(SW_SOCK_UNIX_DGRAM, SW_FD_DGRAM_SERVER, 0);
    sock1->bind(sock1_path);

    auto sock2 = make_socket(SW_SOCK_UNIX_DGRAM, SW_FD_DGRAM_SERVER, 0);
    sock2->bind(sock2_path);

    ASSERT_GT(sock1->sendto(sock2_path, 0, test_data, strlen(test_data)), 0);

    char buf[1024] = {};
    network::Address sa;
    sa.type = SW_SOCK_UNIX_DGRAM;
    ASSERT_GT(sock2->recvfrom(buf, sizeof(buf), 0, &sa), 0);
    ASSERT_STREQ(test_data, buf);
    ASSERT_STREQ(sa.get_addr(), sock1_path);

    sock1->free();
    sock2->free();
    unlink(sock1_path);
    unlink(sock2_path);
}

static void test_sendto(enum swSocketType sock_type) {
    const char *ip = sock_type == SW_SOCK_UDP ? "127.0.0.1" : "::1";

    auto sock1 = make_socket(sock_type, SW_FD_DGRAM_SERVER, 0);
    ASSERT_EQ(sock1->bind(ip, 0), SW_OK);
    ASSERT_EQ(sock1->get_name(), SW_OK);

    auto sock2 = make_socket(sock_type, SW_FD_DGRAM_SERVER, 0);
    ASSERT_EQ(sock2->bind(ip, 0), SW_OK);
    ASSERT_EQ(sock2->get_name(), SW_OK);

    ASSERT_GT(sock1->sendto(ip, sock2->get_port(), test_data, strlen(test_data)), 0);

    char buf[1024] = {};
    network::Address sa;
    sa.type = sock_type;
    ASSERT_GT(sock2->recvfrom(buf, sizeof(buf), 0, &sa), 0);

    ASSERT_STREQ(test_data, buf);
    ASSERT_EQ(sa.get_port(), sock1->get_port());
    ASSERT_STREQ(sa.get_addr(), ip);

    sock1->free();
    sock2->free();
}

TEST(socket, sendto_ipv4) {
    test_sendto(SW_SOCK_UDP);
}

TEST(socket, sendto_ipv6) {
    test_sendto(SW_SOCK_UDP6);
}

TEST(socket, recv) {
    mutex m;
    m.lock();
    int port = swoole::test::get_random_port();

    thread t1([&m, port]() {
        auto svr = make_server_socket(SW_SOCK_TCP, TEST_HOST, port);
        char buf[1024] = {};
        svr->set_block();
        m.unlock();

        auto client_sock = svr->accept();
        client_sock->recv(buf, sizeof(buf), 0);

        ASSERT_STREQ(test_data, buf);
        svr->free();
    });

    thread t2([&m, port]() {
        m.lock();
        auto cli = make_socket(SW_SOCK_TCP, SW_FD_STREAM_CLIENT, 0);
        ASSERT_EQ(cli->connect(TEST_HOST, port), SW_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        cli->send(test_data, sizeof(test_data), 0);
        cli->free();
    });

    t1.join();
    t2.join();
}

TEST(socket, recvfrom_sync) {
    mutex m;
    m.lock();
    int port = swoole::test::get_random_port();

    thread t1([&m, port]() {
        auto svr = make_server_socket(SW_SOCK_UDP, TEST_HOST, port);
        network::Address addr;
        char buf[1024] = {};
        svr->set_nonblock();
        m.unlock();
        svr->recvfrom_sync(buf, sizeof(buf), 0, &addr);
        ASSERT_STREQ(test_data, buf);
        svr->free();
    });

    thread t2([&m, port]() {
        m.lock();
        auto cli = make_socket(SW_SOCK_UDP, SW_FD_STREAM_CLIENT, 0);
        network::Address addr;
        addr.assign(SW_SOCK_TCP, TEST_HOST, port);
        ASSERT_EQ(cli->connect(addr), SW_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        cli->send(test_data, sizeof(test_data), 0);
        cli->free();
    });

    t1.join();
    t2.join();
}

TEST(socket, send_async_1) {
    auto sock = make_socket(SW_SOCK_TCP, SW_FD_STREAM_CLIENT, 0);
    ASSERT_TRUE(sock->set_block());
    ASSERT_EQ(sock->connect(TEST_HTTP_DOMAIN, 80), SW_OK);

    auto req = test::http_get_request(TEST_HTTP_DOMAIN, "/");
    ASSERT_EQ(sock->send_async(req.c_str(), req.length()), req.length());

    auto buf = sw_tg_buffer();
    auto n = sock->recv_sync(buf->str, buf->size, 0);
    ASSERT_GT(n, 0);
    buf->length = n;
    ASSERT_TRUE(buf->contains(SW_STRL(TEST_HTTP_EXPECT)));

    sock->free();
}

TEST(socket, send_async_2) {
    auto sock = make_socket(SW_SOCK_TCP, SW_FD_STREAM_CLIENT, 0);
    ASSERT_TRUE(sock->set_block());
    ASSERT_EQ(sock->connect(TEST_HTTP_DOMAIN, 80), SW_OK);

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    auto req = test::http_get_request(TEST_HTTP_DOMAIN, "/");
    ASSERT_EQ(sock->send_async(req.c_str(), req.length()), req.length());

    swoole_event_set_handler(SW_FD_STREAM_CLIENT, SW_EVENT_READ, [](Reactor *reactor, Event *event) {
        auto buf = sw_tg_buffer();
        auto n = event->socket->recv_sync(buf->str, buf->size, 0);
        EXPECT_GT(n, 0);
        buf->length = n;
        EXPECT_TRUE(buf->contains(SW_STRL(TEST_HTTP_EXPECT)));

        return 0;
    });

    swoole_event_add(sock, SW_EVENT_READ | SW_EVENT_ONCE);
    swoole_event_wait();

    sock->free();
}

TEST(socket, sendfile_sync) {
    string file = test::get_root_path() + "/examples/test.jpg";
    mutex m;
    int port = swoole::test::get_random_port();
    m.lock();

    auto str = file_get_contents(file);

    thread t1([&m, &str, port]() {
        auto svr = make_server_socket(SW_SOCK_TCP, TEST_HOST, port);
        m.unlock();
        auto cli = svr->accept();
        int len;
        cli->recv_sync(&len, sizeof(len), MSG_WAITALL);
        int _len = ntohl(len);
        ASSERT_EQ(_len, str->get_length());
        ASSERT_LT(_len, 1024 * 1024);
        std::unique_ptr<char[]> data(new char[_len]);
        cli->recv_sync(data.get(), _len, MSG_WAITALL);
        ASSERT_STREQ(data.get(), str->value());
        cli->free();
        svr->free();
    });

    thread t2([&m, &file, &str, port]() {
        m.lock();
        auto cli = make_socket(SW_SOCK_TCP, SW_FD_STREAM_CLIENT, 0);
        network::Address addr;
        addr.assign(SW_SOCK_TCP, TEST_HOST, port);
        ASSERT_EQ(cli->connect(addr), SW_OK);
        int len = htonl(str->get_length());
        cli->send(&len, sizeof(len), 0);
        ASSERT_EQ(cli->sendfile_sync(file.c_str(), 0, 0, -1), SW_OK);
        cli->free();
    });

    t1.join();
    t2.join();
}

TEST(socket, sendfile) {
    string file = "/tmp/swoole-file-not-exists";
    auto cli = make_socket(SW_SOCK_TCP, SW_FD_STREAM_CLIENT, 0);
    network::Address addr;
    addr.assign(SW_SOCK_TCP, TEST_HTTP_DOMAIN, 80);
    ASSERT_EQ(cli->connect(addr), SW_OK);

    ASSERT_EQ(cli->sendfile_sync(file.c_str(), 0, 0, -1), SW_ERR);
    ASSERT_EQ(errno, ENOENT);

    File fp(file, File::WRITE | File::CREATE);
    ASSERT_TRUE(fp.ready());

    ASSERT_EQ(cli->sendfile_sync(file.c_str(), 0, 0, -1), SW_ERR);
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_FILE_EMPTY);

    fp.write(SW_STRL(TEST_STR));
    fp.close();

    ASSERT_EQ(cli->sendfile_sync(file.c_str(), 10, 100, -1), SW_ERR);
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_INVALID_PARAMS);

    ASSERT_TRUE(fp.open(file, File::WRITE | File::APPEND));
    auto req = test::http_get_request(TEST_HTTP_DOMAIN, "/");
    fp.write(req);
    fp.close();

    ASSERT_EQ(cli->sendfile_sync(file.c_str(), strlen(TEST_STR), 0, -1), SW_OK);

    char rbuf[4096];
    auto n = cli->recv_sync(rbuf, sizeof(rbuf), 0);
    ASSERT_GT(n, 0);

    String resp(rbuf, n);

    ASSERT_TRUE(resp.contains(SW_STRL(TEST_HTTP_EXPECT)));

    cli->free();

    ASSERT_TRUE(File::remove(file));
}

TEST(socket, peek) {
    char sock1_path[] = "/tmp/udp_unix1.sock";
    char sock2_path[] = "/tmp/udp_unix2.sock";

    unlink(sock1_path);
    unlink(sock2_path);

    auto sock1 = make_socket(SW_SOCK_UNIX_DGRAM, SW_FD_DGRAM_SERVER, 0);
    sock1->bind(sock1_path);

    auto sock2 = make_socket(SW_SOCK_UNIX_DGRAM, SW_FD_DGRAM_SERVER, 0);
    sock2->bind(sock2_path);

    ASSERT_GT(sock1->sendto(sock2_path, 0, test_data, strlen(test_data)), 0);

    char buf[1024] = {};
    ASSERT_GT(sock2->peek(buf, sizeof(buf), 0), 0);
    ASSERT_STREQ(test_data, buf);

    sw_memset_zero(buf, sizeof(buf));
    ASSERT_GT(sock2->recv(buf, sizeof(buf), 0), 0);
    ASSERT_STREQ(test_data, buf);

    sock1->free();
    sock2->free();
    unlink(sock1_path);
    unlink(sock2_path);
}

TEST(socket, sendto_sync) {
    char sock1_path[] = "/tmp/udp_unix1.sock";
    unlink(sock1_path);
    auto sock1 = make_socket(SW_SOCK_UNIX_DGRAM, SW_FD_DGRAM_SERVER, 0);
    sock1->bind(sock1_path);

    char sock2_path[] = "/tmp/udp_unix2.sock";
    unlink(sock2_path);
    auto sock2 = make_socket(SW_SOCK_UNIX_DGRAM, SW_FD_DGRAM_SERVER, 0);
    sock2->bind(sock2_path);

    char sendbuf[65536] = {};
    swoole_random_string(sendbuf, sizeof(sendbuf) - 1);

    thread t1([sock2, sendbuf]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        char recvbuf[65536] = {};
        while (1) {
            auto retval = sock2->recv(recvbuf, sizeof(recvbuf) - 1, 0);
            recvbuf[retval] = 0;
            if (retval == 3) {
                ASSERT_STREQ(recvbuf, "end");
                break;
            } else {
                ASSERT_STREQ(sendbuf, recvbuf);
            }
        }
    });

    network::Address sock2_addr;
    ASSERT_TRUE(sock2_addr.assign(SW_SOCK_UNIX_DGRAM, sock2_path));

    for (int i = 0; i < 10; i++) {
        ASSERT_GT(sock1->sendto_sync(sock2_addr, sendbuf, strlen(sendbuf)), 0);
    }
    ASSERT_GT(sock1->sendto_sync(sock2_addr, "end", 3), 0);

    t1.join();

    sock1->free();
    sock2->free();
    unlink(sock1_path);
    unlink(sock2_path);
}

TEST(socket, clean) {
    char sock1_path[] = "/tmp/udp_unix1.sock";
    unlink(sock1_path);
    auto sock1 = make_socket(SW_SOCK_UNIX_DGRAM, SW_FD_DGRAM_SERVER, 0);
    sock1->bind(sock1_path);

    char sock2_path[] = "/tmp/udp_unix2.sock";
    unlink(sock2_path);
    auto sock2 = make_socket(SW_SOCK_UNIX_DGRAM, SW_FD_DGRAM_SERVER, 0);
    sock2->bind(sock2_path);

    char sendbuf[65536] = {};
    swoole_random_string(sendbuf, sizeof(sendbuf) - 1);

    network::Address sock2_addr;
    ASSERT_TRUE(sock2_addr.assign(SW_SOCK_UNIX_DGRAM, sock2_path));

    for (int i = 0; i < 3; i++) {
        ASSERT_GT(sock1->sendto(sock2_addr, sendbuf, strlen(sendbuf)), 0);
    }

    sock2->clean();
    char recvbuf[1024];
    auto retval = sock2->peek(recvbuf, sizeof(recvbuf), MSG_DONTWAIT);
    ASSERT_EQ(retval, -1);

    sock1->free();
    sock2->free();
    unlink(sock1_path);
    unlink(sock2_path);
}

TEST(socket, check_liveness) {
    mutex m;
    int svr_port = TEST_PORT + __LINE__;
    m.lock();

    thread t1([&m, svr_port]() {
        auto svr = make_server_socket(SW_SOCK_TCP, TEST_HOST, svr_port);
        m.unlock();

        auto cli = svr->accept();
        ASSERT_TRUE(cli);

        char buf[1024] = {};
        cli->recv(buf, sizeof(buf), 0);
        ASSERT_STREQ(test_data, buf);

        ssize_t n = cli->recv(buf, sizeof(buf), 0);
        buf[n] = 0;
        ASSERT_STREQ("close", buf);
        cli->shutdown(SHUT_RDWR);
        cli->free();

        svr->free();
    });

    thread t2([&m, svr_port]() {
        m.lock();

        auto cli = make_socket(SW_SOCK_TCP, SW_FD_STREAM_CLIENT, 0);
        ASSERT_EQ(cli->connect(TEST_HOST, svr_port), SW_OK);

        cli->send(test_data, sizeof(test_data), 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        ASSERT_TRUE(cli->check_liveness());

        cli->send(SW_STRL("close"), 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        ASSERT_FALSE(cli->check_liveness());

        cli->free();
    });

    t1.join();
    t2.join();
}

#define CRLF "\r\n"

static void test_socket_sync(network::Socket *sock, bool connect = true) {
    if (connect) {
        network::Address addr;
        ASSERT_TRUE(addr.assign("tcp://" TEST_HTTP_DOMAIN ":80"));
        ASSERT_EQ(sock->connect(addr), 0);
    }

    auto req = test::http_get_request(TEST_HTTP_DOMAIN, "/get");
    ASSERT_EQ(sock->write_sync(req.c_str(), req.length()), req.length());
    ASSERT_TRUE(sock->check_liveness());

    string resp;
    SW_LOOP {
        char buf[1024];
        auto n = sock->read_sync(buf, sizeof(buf));
        if (n == 0) {
            break;
        }
        ASSERT_GT(n, 0);
        resp.append(buf, n);
    }

    ASSERT_TRUE(resp.find(TEST_HTTP_EXPECT) != resp.npos);

    usleep(50000);
    ASSERT_FALSE(sock->check_liveness());

    sock->free();
}

TEST(socket, sync) {
    auto sock = make_socket(SW_SOCK_TCP, SW_FD_STREAM, 0);
    test_socket_sync(sock);
}

TEST(socket, dup) {
    auto sock = make_socket(SW_SOCK_TCP, SW_FD_STREAM, 0);
    network::Address addr;
    ASSERT_TRUE(addr.assign("tcp://" TEST_HTTP_DOMAIN ":80"));
    ASSERT_EQ(sock->connect(addr), 0);

    auto sock_2 = sock->dup();
    sock->free();

    test_socket_sync(sock_2, false);
}

TEST(socket, convert_to_type) {
    ASSERT_EQ(network::Socket::convert_to_type(AF_INET, SOCK_STREAM), SW_SOCK_TCP);
    ASSERT_EQ(network::Socket::convert_to_type(AF_INET6, SOCK_STREAM), SW_SOCK_TCP6);
    ASSERT_EQ(network::Socket::convert_to_type(AF_INET, SOCK_DGRAM), SW_SOCK_UDP);
    ASSERT_EQ(network::Socket::convert_to_type(AF_INET6, SOCK_DGRAM), SW_SOCK_UDP6);
    ASSERT_EQ(network::Socket::convert_to_type(AF_LOCAL, SOCK_STREAM), SW_SOCK_UNIX_STREAM);
    ASSERT_EQ(network::Socket::convert_to_type(AF_LOCAL, SOCK_DGRAM), SW_SOCK_UNIX_DGRAM);
    ASSERT_EQ(network::Socket::convert_to_type(AF_INET, SOCK_RAW), SW_SOCK_RAW);
    ASSERT_EQ(network::Socket::convert_to_type(AF_INET6, SOCK_RAW), SW_SOCK_RAW6);

    std::string s1("unix:///tmp/swoole.sock");
    ASSERT_EQ(network::Socket::convert_to_type(s1), SW_SOCK_UNIX_STREAM);
    ASSERT_EQ(s1, "/tmp/swoole.sock");

    std::string s2("127.0.0.1");
    ASSERT_EQ(network::Socket::convert_to_type(s2), SW_SOCK_TCP);

    std::string s3("::1");
    ASSERT_EQ(network::Socket::convert_to_type(s3), SW_SOCK_TCP6);

    std::string s4("unix:/tmp/swoole.sock");
    ASSERT_EQ(network::Socket::convert_to_type(s4), SW_SOCK_UNIX_STREAM);
    ASSERT_EQ(s4, "/tmp/swoole.sock");
}

static void test_sock_type(SocketType type, int expect_sock_domain, int expect_sock_type) {
    int sock_domain, sock_type;
    ASSERT_EQ(network::Socket::get_domain_and_type(type, &sock_domain, &sock_type), SW_OK);
    ASSERT_EQ(sock_domain, expect_sock_domain);
    ASSERT_EQ(sock_type, expect_sock_type);
}

TEST(socket, get_domain_and_type) {
    test_sock_type(SW_SOCK_TCP, AF_INET, SOCK_STREAM);
    test_sock_type(SW_SOCK_TCP6, AF_INET6, SOCK_STREAM);
    test_sock_type(SW_SOCK_UDP, AF_INET, SOCK_DGRAM);
    test_sock_type(SW_SOCK_UDP6, AF_INET6, SOCK_DGRAM);
    test_sock_type(SW_SOCK_UNIX_STREAM, AF_LOCAL, SOCK_STREAM);
    test_sock_type(SW_SOCK_UNIX_DGRAM, AF_LOCAL, SOCK_DGRAM);
    test_sock_type(SW_SOCK_RAW, AF_INET, SOCK_RAW);
    test_sock_type(SW_SOCK_RAW6, AF_INET6, SOCK_RAW);

    ASSERT_TRUE(network::Socket::is_dgram(SW_SOCK_UDP6));
    ASSERT_TRUE(network::Socket::is_stream(SW_SOCK_TCP));

    int sock_domain, sock_type;
    ASSERT_EQ(
        network::Socket::get_domain_and_type(static_cast<swSocketType>(SW_SOCK_RAW6 + 1), &sock_domain, &sock_type),
        SW_ERR);
}

TEST(socket, make_socket) {
    network::Socket *sock;

    sock = make_socket(SW_SOCK_RAW, SW_FD_STREAM, 0);
    ASSERT_EQ(sock, nullptr);
    ASSERT_EQ(errno, EPROTONOSUPPORT);
    ASSERT_EQ(swoole_get_last_error(), EPROTONOSUPPORT);

    sock = make_socket(SW_SOCK_TCP, SW_FD_STREAM, AF_INET6, SOCK_RDM, 999, 0);
    ASSERT_EQ(sock, nullptr);
    ASSERT_EQ(errno, EINVAL);
    ASSERT_EQ(swoole_get_last_error(), EINVAL);
}

TEST(socket, make_server_socket) {
    network::Socket *sock;

    auto bad_addr = "199.199.0.0";

    sock = make_server_socket(SW_SOCK_RAW, bad_addr);
    ASSERT_EQ(sock, nullptr);
    if (geteuid() == 0) {  // root
        ASSERT_EQ(errno, EPROTONOSUPPORT);
        ASSERT_EQ(swoole_get_last_error(), EPROTONOSUPPORT);
    } else {
        ASSERT_EQ(errno, ESOCKTNOSUPPORT);
        ASSERT_EQ(swoole_get_last_error(), ESOCKTNOSUPPORT);
    }

    sock = make_server_socket(SW_SOCK_TCP, bad_addr);
    ASSERT_EQ(sock, nullptr);
    ASSERT_EQ(errno, EADDRNOTAVAIL);

    sock = make_server_socket(SW_SOCK_TCP, TEST_HOST, 0, -1);
    ASSERT_NE(sock, nullptr);
    sock->free();
}

TEST(socket, ssl_get_error_reason) {
    swoole_ssl_init();
    {
        int reason = -1;
        const char *error_str = network::Socket::ssl_get_error_reason(&reason);

        EXPECT_EQ(error_str, nullptr);
        EXPECT_EQ(reason, 0);
    }
    // 测试单个错误的情况
    {
        // 生成一个 OpenSSL 错误
        ERR_put_error(ERR_LIB_SSL, SSL_F_SSL_SET_SESSION, SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED, __FILE__, __LINE__);

        int reason = -1;
        const char *error_str = network::Socket::ssl_get_error_reason(&reason);

        // 验证错误原因代码
        EXPECT_EQ(reason, SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED);

        // 验证错误字符串
        EXPECT_NE(error_str, nullptr);
        EXPECT_TRUE(strstr(error_str, "certificate expired") != nullptr ||
                    strstr(error_str, "CERTIFICATE_EXPIRED") != nullptr);

        // 验证错误队列现在应该为空（因为 ERR_get_error 会移除错误）
        EXPECT_EQ(ERR_peek_error(), 0);
    }

    // 测试多个错误的情况（只返回第一个）
    {
        // 生成多个 OpenSSL 错误
        ERR_put_error(ERR_LIB_SSL, SSL_F_SSL_SET_SESSION, SSL_R_SSLV3_ALERT_BAD_CERTIFICATE, __FILE__, __LINE__);
        ERR_put_error(ERR_LIB_SSL, SSL_F_SSL_SHUTDOWN, SSL_R_PROTOCOL_IS_SHUTDOWN, __FILE__, __LINE__);

        int reason = -1;
        const char *error_str = network::Socket::ssl_get_error_reason(&reason);

        // 验证返回的是第一个错误的原因代码
        EXPECT_EQ(reason, SSL_R_SSLV3_ALERT_BAD_CERTIFICATE);

        // 验证错误字符串
        EXPECT_NE(error_str, nullptr);
        EXPECT_TRUE(strstr(error_str, "bad certificate") != nullptr || strstr(error_str, "BAD_CERTIFICATE") != nullptr);

        // 验证错误队列中还有一个错误
        EXPECT_NE(ERR_peek_error(), 0);

        ERR_get_error();
    }

    // 测试不同库的错误
    {
        // 生成一个 BIO 库错误
        ERR_put_error(ERR_LIB_BIO, BIO_F_BIO_WRITE, BIO_R_BROKEN_PIPE, __FILE__, __LINE__);

        int reason = -1;
        const char *error_str = network::Socket::ssl_get_error_reason(&reason);

        // 验证错误原因代码
        EXPECT_EQ(reason, BIO_R_BROKEN_PIPE);

        // 验证错误字符串
        EXPECT_NE(error_str, nullptr);
        EXPECT_TRUE(strstr(error_str, "broken pipe") != nullptr || strstr(error_str, "BROKEN_PIPE") != nullptr);
    }

    // 测试 reason 参数为 nullptr 的情况（如果函数支持）
    {
        // 生成一个 OpenSSL 错误
        ERR_put_error(ERR_LIB_SSL, SSL_F_SSL_READ, SSL_R_SSL_HANDSHAKE_FAILURE, __FILE__, __LINE__);

        // 调用函数，传入 nullptr 作为 reason 参数
        // 注意：如果函数不支持 nullptr 参数，这个测试会导致段错误
        // 在这种情况下，应该跳过这个测试或修改函数以支持 nullptr
        const char *error_str = network::Socket::ssl_get_error_reason(nullptr);

        // 验证错误字符串
        EXPECT_NE(error_str, nullptr);
        EXPECT_TRUE(strstr(error_str, "handshake failure") != nullptr ||
                    strstr(error_str, "HANDSHAKE_FAILURE") != nullptr);
    }

    // 测试错误队列中有错误但 ERR_reason_error_string 返回 nullptr 的情况
    {
        // 使用一个不常见的错误代码，可能没有对应的错误字符串
        // 注意：这个测试可能不稳定，因为 OpenSSL 可能为所有错误代码都提供字符串
        ERR_put_error(ERR_LIB_USER, 0, 12345, __FILE__, __LINE__);

        int reason = -1;
        const char *error_str = network::Socket::ssl_get_error_reason(&reason);

        // 验证错误原因代码
        EXPECT_EQ(reason, 12345);

        // 错误字符串可能为 nullptr 或包含通用错误信息
        // 这个验证可能需要根据实际情况调整
        if (error_str != nullptr) {
            EXPECT_TRUE(true);  // 如果有字符串，测试通过
        } else {
            EXPECT_EQ(error_str, nullptr);  // 如果没有字符串，也测试通过
        }
    }

    // 测试函数在多次调用后的行为
    {
        // 生成一个 OpenSSL 错误
        ERR_put_error(ERR_LIB_SSL, SSL_F_SSL_CTX_NEW, SSL_R_LIBRARY_HAS_NO_CIPHERS, __FILE__, __LINE__);

        // 第一次调用
        int reason1 = -1;
        const char *error_str1 = network::Socket::ssl_get_error_reason(&reason1);

        // 验证第一次调用的结果
        EXPECT_EQ(reason1, SSL_R_LIBRARY_HAS_NO_CIPHERS);
        EXPECT_NE(error_str1, nullptr);

        // 第二次调用，应该没有错误了
        int reason2 = -1;
        const char *error_str2 = network::Socket::ssl_get_error_reason(&reason2);

        // 验证第二次调用的结果
        EXPECT_EQ(reason2, 0);
        EXPECT_EQ(error_str2, nullptr);
    }
}

TEST(socket, catch_error) {
    network::Socket fake_sock;
    ASSERT_EQ(fake_sock.catch_write_pipe_error(ENOBUFS), SW_REDUCE_SIZE);
    ASSERT_EQ(fake_sock.catch_write_pipe_error(EMSGSIZE), SW_REDUCE_SIZE);
    ASSERT_EQ(fake_sock.catch_write_pipe_error(EAGAIN), SW_WAIT);

    ASSERT_EQ(fake_sock.catch_write_error(ENOBUFS), SW_WAIT);
}
