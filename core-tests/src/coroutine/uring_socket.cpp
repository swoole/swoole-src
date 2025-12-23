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
#include "swoole_util.h"

#include <sys/file.h>
#include <sys/stat.h>

#ifdef SW_USE_IOURING
using swoole::Coroutine;
using swoole::Iouring;
using swoole::Reactor;
using swoole::String;

using swoole::coroutine::System;
using swoole::coroutine::UringSocket;
using swoole::network::IOVector;
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

TEST(uring_socket, sendmsg_and_recvmsg) {
    coroutine::run([&](void *arg) {
        int pairs[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);

        std::string text = "Hello World";
        const size_t length = text.length();

        Coroutine::create([&](void *) {
            UringSocket sock(pairs[0], SW_SOCK_UNIX_STREAM);
            struct msghdr msg;
            struct iovec ivec;

            msg.msg_control = nullptr;
            msg.msg_controllen = 0;
            msg.msg_flags = 0;
            msg.msg_name = nullptr;
            msg.msg_namelen = 0;
            msg.msg_iov = &ivec;
            msg.msg_iovlen = 1;

            ivec.iov_base = (void *) text.c_str();
            ivec.iov_len = length;

            ssize_t ret = sock.sendmsg(&msg, 0);
            sock.close();
            ASSERT_EQ(ret, length);
        });

        UringSocket sock(pairs[1], SW_SOCK_UNIX_STREAM);
        struct msghdr msg;
        struct iovec ivec;
        char buf[length + 1];

        msg.msg_control = nullptr;
        msg.msg_controllen = 0;
        msg.msg_flags = 0;
        msg.msg_name = nullptr;
        msg.msg_namelen = 0;
        msg.msg_iov = &ivec;
        msg.msg_iovlen = 1;

        ivec.iov_base = buf;
        ivec.iov_len = length;

        ssize_t ret = sock.recvmsg(&msg, 0);
        buf[ret] = '\0';
        sock.close();
        ASSERT_STREQ(buf, text.c_str());
    });
}

static void test_sendto_recvfrom(enum swSocketType sock_type) {
    coroutine::run([&](void *arg) {
        std::string server_text = "hello world!!!";
        size_t server_length = server_text.length();
        std::string client_text = "hello swoole!!!";
        size_t client_length = client_text.length();

        const char *ip = sock_type == SW_SOCK_UDP ? "127.0.0.1" : "::1";
        const char *local = "localhost";

        int port = swoole::test::get_random_port();

        UringSocket sock_server(sock_type);
        UringSocket sock_client(sock_type);
        sock_server.bind(ip, port);
        sock_client.bind(ip, port + 1);

        ON_SCOPE_EXIT {
            sock_server.close();
            sock_client.close();
        };

        sock_server.sendto(ip, port + 1, (const void *) server_text.c_str(), server_length);

        char data_from_server[128] = {};
        struct sockaddr_in serveraddr;
        bzero(&serveraddr, sizeof(serveraddr));
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_addr.s_addr = inet_addr(ip);
        serveraddr.sin_port = htons(port);
        socklen_t addr_length = sizeof(serveraddr);

        // receive data from server
        ssize_t result =
            sock_client.recvfrom(data_from_server, server_length, (struct sockaddr *) &serveraddr, &addr_length);
        data_from_server[result] = '\0';
        ASSERT_EQ(result, server_length);
        ASSERT_STREQ(data_from_server, server_text.c_str());

        // receive data from client
        char data_from_client[128] = {};
        sock_client.sendto(local, port, (const void *) client_text.c_str(), client_length);
        result = sock_server.recvfrom(data_from_client, client_length);
        data_from_client[client_length] = '\0';
        ASSERT_EQ(result, client_length);
        ASSERT_STREQ(data_from_client, client_text.c_str());
    });
}

TEST(uring_socket, sendto_recvfrom_udp) {
    test_sendto_recvfrom(SW_SOCK_UDP);
    test_sendto_recvfrom(SW_SOCK_UDP6);
}

TEST(uring_socket, writev_and_readv) {
    coroutine::run([&](void *arg) {
        int iovcnt = 3;
        int pairs[2];
        std::string text = "Hello World";
        size_t length = text.length();
        socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);

        Coroutine::create([&](void *) {
            std::unique_ptr<iovec[]> iov(new iovec[iovcnt]);
            for (int i = 0; i < iovcnt; i++) {
                iov[i].iov_base = (void *) text.c_str();
                iov[i].iov_len = length;
            }
            IOVector io_vector((struct iovec *) iov.get(), iovcnt);

            UringSocket sock(pairs[0], SW_SOCK_UNIX_STREAM);
            ssize_t result = sock.writev(&io_vector);
            sock.close();
            ASSERT_EQ(result, length * 3);
        });

        std::vector<std::string> results(iovcnt);
        std::unique_ptr<iovec[]> iov(new iovec[iovcnt]);
        for (int i = 0; i < iovcnt; i++) {
            iov[i].iov_base = (void *) results[i].c_str();
            iov[i].iov_len = length;
        }
        IOVector io_vector((struct iovec *) iov.get(), iovcnt);

        UringSocket sock(pairs[1], SW_SOCK_UNIX_STREAM);
        ssize_t result = sock.readv(&io_vector);
        sock.close();
        ASSERT_EQ(result, length * 3);

        for (auto iter = results.begin(); iter != results.end(); iter++) {
            (*iter)[length] = '\0';
            ASSERT_STREQ(text.c_str(), (*iter).c_str());
        }
    });
}

TEST(uring_socket, writevall_and_readvall) {
    coroutine::run([&](void *arg) {
        int write_iovcnt = 4;
        int pairs[2];

        char buf[65536];
        swoole_random_bytes(buf, sizeof(buf));

        std::string text(buf, sizeof(buf));
        size_t length = text.length();
        socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);

        Coroutine::create([&](void *) {
            std::unique_ptr<iovec[]> iov(new iovec[write_iovcnt]);
            for (int i = 0; i < write_iovcnt; i++) {
                iov[i].iov_base = (void *) text.c_str();
                iov[i].iov_len = length;
            }

            UringSocket sock(pairs[0], SW_SOCK_UNIX_STREAM);
            sock.get_socket()->set_send_buffer_size(sizeof(buf));

            IOVector io_vector1((struct iovec *) iov.get(), write_iovcnt);
            ASSERT_EQ(sock.writev_all(&io_vector1), write_iovcnt * sizeof(buf));

            System::sleep(0.01);

            IOVector io_vector2((struct iovec *) iov.get(), write_iovcnt);
            ASSERT_EQ(sock.writev_all(&io_vector2), write_iovcnt * sizeof(buf));

            sock.close();
        });

        int read_iovcnt = 8;
        std::unique_ptr<iovec[]> iov(new iovec[read_iovcnt]);
        for (int i = 0; i < read_iovcnt; i++) {
            iov[i].iov_base = sw_malloc(length);
            iov[i].iov_len = length;
        }
        IOVector io_vector((struct iovec *) iov.get(), read_iovcnt);

        UringSocket sock(pairs[1], SW_SOCK_UNIX_STREAM);
        sock.get_socket()->set_recv_buffer_size(sizeof(buf));

        ssize_t result = sock.readv_all(&io_vector);
        sock.close();
        ASSERT_EQ(result, length * read_iovcnt);

        for (int i = 0; i < read_iovcnt; i++) {
            ASSERT_MEMEQ(iov[i].iov_base, buf, sizeof(buf));
            sw_free(iov[i].iov_base);
        }
    });
}

TEST(uring_socket, sendfile) {
    coroutine::run([&](void *arg) {
        int pairs[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);
        Coroutine::create([&](void *) {
            std::string file = swoole::test::get_jpg_file();
            UringSocket sock(pairs[0], SW_SOCK_UNIX_STREAM);
            bool result = sock.sendfile(file.c_str(), 0, 0);
            std::cout << sock.errMsg << "\n";
            sock.close();
            ASSERT_TRUE(result);
        });

        char data[250000];
        UringSocket sock(pairs[1], SW_SOCK_UNIX_STREAM);
        ssize_t result = sock.read(data, 250000);
        data[result] = '\0';
        sock.close();
        ASSERT_GT(result, 0);
    });
}

TEST(uring_socket, send_and_recv_all) {
    coroutine::run([&](void *arg) {
        int pairs[2];

        String wbuf;
        wbuf.append_random_bytes(4 * 1024 * 1024, false);
        socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);

        Coroutine::create([&](void *) {
            UringSocket sock(pairs[0], SW_SOCK_UNIX_STREAM);
            sock.get_socket()->set_send_buffer_size(65536);

            ASSERT_EQ(sock.send_all(wbuf.str, wbuf.length), wbuf.length);

            System::sleep(0.1);

            sock.close();
        });

        UringSocket sock(pairs[1], SW_SOCK_UNIX_STREAM);
        sock.get_socket()->set_recv_buffer_size(65536);

        String rbuf(wbuf.length);
        ssize_t result = sock.recv_all(rbuf.str, wbuf.length);
        ASSERT_EQ(result, wbuf.length);
        ASSERT_MEMEQ(wbuf.str, rbuf.str, wbuf.length);
        System::sleep(0.1);
        sock.close();
    });
}

TEST(uring_socket, poll) {
    coroutine::run([&](void *arg) {
        int pairs[2];

        String wbuf;
        wbuf.append_random_bytes(4 * 1024 * 1024, false);
        socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);

        UringSocket sock(pairs[1], SW_SOCK_UNIX_STREAM);
        sock.get_socket()->set_recv_buffer_size(65536);

        bool rs;

        rs = sock.poll(SW_EVENT_READ, 0.01);
        ASSERT_FALSE(rs);
        ASSERT_EQ(sock.errCode, ETIMEDOUT);

        TEST_WRITE(pairs[0], TEST_STR);
        rs = sock.poll(SW_EVENT_READ, 0.01);
        ASSERT_TRUE(rs);
    });
}

TEST(uring_socket, ssl_readv) {
    coroutine::run([&](void *arg) {
        UringSocket client(SW_SOCK_TCP);
        client.enable_ssl_encrypt();
        client.set_tls_host_name(TEST_HTTP_DOMAIN);
        ASSERT_TRUE(client.connect(TEST_HTTP_DOMAIN, 443));

        auto req = swoole::test::http_get_request(TEST_HTTP_DOMAIN, "/");

        constexpr off_t offset1 = TEST_WRITEV_OFFSET;
        iovec wr_iov[2];
        wr_iov[0].iov_base = (void *) req.c_str();
        wr_iov[0].iov_len = offset1;
        wr_iov[1].iov_base = (char *) req.c_str() + offset1;
        wr_iov[1].iov_len = req.length() - offset1;

        swoole::network::IOVector wr_vec(wr_iov, 2);
        ASSERT_EQ(client.writev(&wr_vec), req.length());

        sw_tg_buffer()->clear();
        if (sw_tg_buffer()->size < 1024 * 1024) {
            sw_tg_buffer()->extend(1024 * 1024);
        }

        constexpr off_t offset2 = TEST_READV_OFFSET;
        iovec rd_iov[2];
        rd_iov[0].iov_base = sw_tg_buffer()->str;
        rd_iov[0].iov_len = offset2;
        rd_iov[1].iov_base = sw_tg_buffer()->str + offset2;
        rd_iov[1].iov_len = sw_tg_buffer()->size - offset2;

        swoole::network::IOVector rd_vec(rd_iov, 2);
        auto rv = client.readv(&rd_vec);
        ASSERT_GT(rv, 1024);
        sw_tg_buffer()->length = rv;
        sw_tg_buffer()->set_null_terminated();

        ASSERT_TRUE(sw_tg_buffer()->contains(TEST_HTTPS_EXPECT));
    });
}
#endif
