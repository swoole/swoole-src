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
  | Author: NathanFreeman  <mariasocute@163.com>                         |
  +----------------------------------------------------------------------+
 */

#include "test_coroutine.h"
#include "swoole_uring_socket.h"

#include <sys/file.h>
#include <sys/stat.h>

#ifdef SW_USE_IOURING
using swoole::Iouring;
using swoole::Reactor;

using swoole::coroutine::UringSocket;
using swoole::test::coroutine;
using swoole::test::create_socket_pair;

TEST(uring_socket, connect) {
    coroutine::run([](void *arg) {
        UringSocket sock(SW_SOCK_TCP);
        bool retval = sock.connect(TEST_HTTP_DOMAIN, 80);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);

        ssize_t rv;

        auto req = swoole::test::http_get_request(TEST_HTTP_DOMAIN, "/");

        rv = sock.send(req.c_str(), req.length());
        ASSERT_EQ(rv, req.length());

        char buf[4096];

        rv = sock.recv(buf, sizeof(buf));
        ASSERT_GT(rv, 100);

        std::string s{buf};
        ASSERT_TRUE(s.find(TEST_HTTP_EXPECT) != s.npos);
    });
}

TEST(uring_socket, ssl_connect) {
    coroutine::run([](void *arg) {
        UringSocket sock(SW_SOCK_TCP);
        sock.enable_ssl_encrypt();
        sock.set_tls_host_name(TEST_HTTP_DOMAIN);
        sock.set_ssl_verify_peer(true);

        auto req = swoole::test::http_get_request(TEST_HTTP_DOMAIN, "/");

        bool retval = sock.connect(TEST_HTTP_DOMAIN, 443);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);

        auto rv = sock.send(req.c_str(), req.length());
        ASSERT_EQ(rv, req.length());

        ASSERT_TRUE(sock.check_liveness());

        swoole::String buf(1024 * 1024);
        while (true) {
            char rbuf[16384];
            ssize_t nr = sock.recv(rbuf, sizeof(rbuf));
            if (nr <= 0) {
                break;
            }
            buf.append(rbuf, nr);
        }
        ASSERT_TRUE(buf.contains(TEST_HTTPS_EXPECT));
    });
}

TEST(uring_socket, accept) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run({[port](void *arg) {
                        UringSocket sock(SW_SOCK_TCP);
                        bool retval = sock.bind("127.0.0.1", port);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.listen(128), true);

                        UringSocket *conn = sock.accept();
                        ASSERT_NE(conn, nullptr);
                        conn->write(TEST_STR, strlen(TEST_STR));

                        char buf[128];
                        auto n = conn->recv(buf, sizeof(buf));
                        ASSERT_EQ(n, strlen(TEST_STR2));
                        buf[n] = '\0';
                        ASSERT_STREQ(buf, TEST_STR2);

                        delete conn;
                    },

                    [port](void *arg) {
                        UringSocket sock(SW_SOCK_TCP);
                        bool retval = sock.connect("127.0.0.1", port, -1);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.errCode, 0);

                        char buf[128];
                        auto n = sock.read(buf, sizeof(buf));
                        ASSERT_EQ(n, strlen(TEST_STR));
                        buf[n] = '\0';
                        ASSERT_STREQ(buf, TEST_STR);

                        ASSERT_EQ(sock.send(TEST_STR2, strlen(TEST_STR2)), strlen(TEST_STR2));

                        sock.close();
                    }});
}

TEST(uring_socket, ssl_accept) {
    const int port = __LINE__ + TEST_PORT;
    auto svr = [port](void *arg) {
        UringSocket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", port);
        ASSERT_EQ(retval, true);

        sock.enable_ssl_encrypt();
        sock.set_ssl_cert_file(swoole::test::get_ssl_dir() + "/server.crt");
        sock.set_ssl_key_file(swoole::test::get_ssl_dir() + "/server.key");
        sock.set_ssl_dhparam(swoole::test::get_ssl_dir() + "/dhparams.pem");
        sock.set_ssl_ecdh_curve("secp256r1");

        ASSERT_EQ(sock.listen(128), true);

        UringSocket *conn = sock.accept();
        ASSERT_NE(conn, nullptr);
        ASSERT_TRUE(conn->ssl_handshake());
        ASSERT_EQ(conn->send(EOF_PACKET, strlen(EOF_PACKET)), strlen(EOF_PACKET));
        char rbuf[1024];

        auto n = conn->recv(rbuf, sizeof(rbuf));
        ASSERT_GT(n, 0);
        rbuf[n] = 0;

        ASSERT_STREQ(rbuf, EOF_PACKET_2);
        conn->close();
        delete conn;
    };

    auto cli = [port](void *arg) {
        UringSocket sock(SW_SOCK_TCP);
        sock.enable_ssl_encrypt();
        bool retval = sock.connect("127.0.0.1", port, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);

        char rbuf[1024];
        auto n = sock.recv(rbuf, sizeof(rbuf));
        ASSERT_GT(n, 0);
        rbuf[n] = 0;
        ASSERT_STREQ(rbuf, EOF_PACKET);
        ASSERT_EQ(sock.send(EOF_PACKET_2, strlen(EOF_PACKET_2)), strlen(EOF_PACKET_2));

        sock.close();
    };

    coroutine::run({svr, cli});
}

static void socket_set_length_protocol_1(UringSocket &sock) {
    sock.protocol = {};

    sock.protocol.package_length_type = 'n';
    sock.protocol.package_length_size = swoole_type_size(sock.protocol.package_length_type);
    sock.protocol.package_body_offset = 2;
    sock.protocol.get_package_length = swoole::Protocol::default_length_func;
    sock.protocol.package_max_length = 65535;

    sock.open_length_check = true;
}

TEST(uring_socket, length_3) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run({[](void *arg) {
                        UringSocket sock(SW_SOCK_TCP);
                        bool retval = sock.bind("127.0.0.1", port);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.listen(128), true);

                        UringSocket *conn = sock.accept();
                        char buf[1024];
                        memset(buf, 'A', sizeof(buf));
                        *(uint16_t *) buf = htons(65530);

                        conn->send(buf, sizeof(buf));
                    },

                    [](void *arg) {
                        UringSocket sock(SW_SOCK_TCP);
                        bool retval = sock.connect("127.0.0.1", port, -1);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.errCode, 0);

                        socket_set_length_protocol_1(sock);
                        sock.protocol.package_max_length = 4096;

                        ssize_t l = sock.recv_packet(RECV_TIMEOUT);
                        ASSERT_EQ(l, -1);
                        ASSERT_EQ(sock.errCode, SW_ERROR_PACKAGE_LENGTH_TOO_LARGE);
                    }});
}

#endif
