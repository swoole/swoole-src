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

TEST(socket, sendto) {
    char sock1_path[] = "/tmp/udp_unix1.sock";
    char sock2_path[] = "/tmp/udp_unix2.sock";

    unlink(sock1_path);
    unlink(sock2_path);

    auto sock1 = make_socket(SW_SOCK_UNIX_DGRAM, SW_FD_DGRAM_SERVER, 0);
    sock1->bind(sock1_path, nullptr);

    auto sock2 = make_socket(SW_SOCK_UNIX_DGRAM, SW_FD_DGRAM_SERVER, 0);
    sock2->bind(sock2_path, nullptr);

    ASSERT_GT(sock1->sendto(sock2_path, 0, test_data, strlen(test_data)), 0);

    char buf[1024] = {};
    network::Address sa;
    sa.type = SW_SOCK_UNIX_DGRAM;
    ASSERT_GT(sock2->recvfrom(buf, sizeof(buf), 0, &sa), 0);
    ASSERT_STREQ(test_data, buf);
    ASSERT_STREQ(sa.get_ip(), sock1_path);

    sock1->free();
    sock2->free();
    unlink(sock1_path);
    unlink(sock2_path);
}

static void test_sendto(enum swSocketType sock_type) {
    int port1 = 0, port2 = 0;
    const char *ip = sock_type == SW_SOCK_UDP ? "127.0.0.1" : "::1";

    auto sock1 = make_socket(sock_type, SW_FD_DGRAM_SERVER, 0);
    sock1->bind(ip, &port1);

    auto sock2 = make_socket(sock_type, SW_FD_DGRAM_SERVER, 0);
    sock2->bind(ip, &port2);

    ASSERT_GT(sock1->sendto(ip, port2, test_data, strlen(test_data)), 0);

    char buf[1024] = {};
    network::Address sa;
    sa.type = sock_type;
    ASSERT_GT(sock2->recvfrom(buf, sizeof(buf), 0, &sa), 0);

    ASSERT_STREQ(test_data, buf);
    ASSERT_EQ(sa.get_port(), port1);
    ASSERT_STREQ(sa.get_ip(), ip);

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
    sock1->bind(sock1_path, nullptr);

    auto sock2 = make_socket(SW_SOCK_UNIX_DGRAM, SW_FD_DGRAM_SERVER, 0);
    sock2->bind(sock2_path, nullptr);

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
    sock1->bind(sock1_path, nullptr);
    sock1->info.assign(SW_SOCK_UNIX_DGRAM, sock1_path, 0);

    char sock2_path[] = "/tmp/udp_unix2.sock";
    unlink(sock2_path);
    auto sock2 = make_socket(SW_SOCK_UNIX_DGRAM, SW_FD_DGRAM_SERVER, 0);
    sock2->bind(sock2_path, nullptr);
    sock2->info.assign(SW_SOCK_UNIX_DGRAM, sock2_path, 0);

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

    for (int i = 0; i < 10; i++) {
        ASSERT_GT(sock1->sendto_sync(sock2->info, sendbuf, strlen(sendbuf)), 0);
    }
    ASSERT_GT(sock1->sendto_sync(sock2->info, "end", 3), 0);

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
    sock1->bind(sock1_path, nullptr);
    sock1->info.assign(SW_SOCK_UNIX_DGRAM, sock1_path, 0);

    char sock2_path[] = "/tmp/udp_unix2.sock";
    unlink(sock2_path);
    auto sock2 = make_socket(SW_SOCK_UNIX_DGRAM, SW_FD_DGRAM_SERVER, 0);
    sock2->bind(sock2_path, nullptr);
    sock2->info.assign(SW_SOCK_UNIX_DGRAM, sock2_path, 0);

    char sendbuf[65536] = {};
    swoole_random_string(sendbuf, sizeof(sendbuf) - 1);

    for (int i = 0; i < 3; i++) {
        ASSERT_GT(sock1->sendto_sync(sock2->info, sendbuf, strlen(sendbuf)), 0);
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
    int svr_port = swoole::test::get_random_port();
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

TEST(socket, ipv4_addr) {
    auto sock = make_socket(SW_SOCK_TCP, SW_FD_STREAM, 0);
    network::Address addr;

    ASSERT_TRUE(addr.assign("tcp://127.0.0.1:12345"));
    ASSERT_EQ(sock->connect(addr), SW_ERR);
    ASSERT_EQ(errno, ECONNREFUSED);

    ASSERT_TRUE(addr.assign("tcp://localhost:12345"));
    ASSERT_EQ(sock->connect(addr), SW_ERR);
    ASSERT_EQ(errno, ECONNREFUSED);

    sock->free();
}

TEST(socket, ipv6_addr) {
    auto sock = make_socket(SW_SOCK_TCP6, SW_FD_STREAM, 0);
    network::Address addr;

    ASSERT_TRUE(addr.assign("tcp://[::1]:12345"));
    ASSERT_EQ(sock->connect(addr), SW_ERR);
    ASSERT_EQ(errno, ECONNREFUSED);

    ASSERT_TRUE(addr.assign("tcp://[ip6-localhost]:12345"));
    ASSERT_EQ(sock->connect(addr), SW_ERR);
    ASSERT_EQ(errno, ECONNREFUSED);

    sock->free();
}

TEST(socket, unix_addr) {
    auto sock = make_socket(SW_SOCK_UNIX_STREAM, SW_FD_STREAM, 0);
    network::Address addr;
    ASSERT_TRUE(addr.assign("unix:///tmp/swoole-not-exists.sock"));
    ASSERT_EQ(sock->connect(addr), SW_ERR);
    ASSERT_EQ(errno, ENOENT);
    sock->free();
}

TEST(socket, bad_addr) {
    network::Address addr;
    ASSERT_FALSE(addr.assign("test://[::1]:12345"));
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_BAD_HOST_ADDR);
}

TEST(socket, bad_port) {
    network::Address addr;
    ASSERT_FALSE(addr.assign("tcp://[::1]:92345"));
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_BAD_PORT);
}

TEST(socket, loopback_addr) {
    network::Address addr1;
    addr1.assign(SW_SOCK_TCP, "127.0.0.1", 0);
    ASSERT_TRUE(addr1.is_loopback_addr());

    network::Address addr2;
    addr2.assign(SW_SOCK_TCP6, "::1", 0);
    ASSERT_TRUE(addr1.is_loopback_addr());

    network::Address addr3;
    addr3.assign(SW_SOCK_TCP, "192.168.1.2", 0);
    ASSERT_FALSE(addr3.is_loopback_addr());

    network::Address addr4;
    addr4.assign(SW_SOCK_TCP6, "192::66::88", 0);
    ASSERT_FALSE(addr4.is_loopback_addr());
}
