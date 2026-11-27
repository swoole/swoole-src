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

#include "test_process.h"
#include "test_coroutine.h"
#include "test_server.h"
#include "swoole_async.h"

#include <future>
#include <stdexcept>

using swoole::Coroutine;
using swoole::HttpProxy;
using swoole::Protocol;
using swoole::RecvData;
using swoole::Socks5Proxy;
using swoole::String;
using swoole::coroutine::Socket;
using swoole::coroutine::System;
using swoole::network::Address;
using swoole::network::IOVector;
using swoole::test::coroutine;
using swoole::test::create_socket_pair;
using swoole::test::Process;
using swoole::test::Server;

const std::string host = "www.baidu.com";

template <typename Guard>
static void check_timeout_guard_restoration(Socket &socket) {
    const double original[] = {0.125, 0.25, 0.5, 1.0};
    for (size_t i = 0; i < SW_ARRAY_SIZE(Socket::timeout_type_list); ++i) {
        socket.set_timeout(original[i], Socket::timeout_type_list[i]);
    }
    for (unsigned subset = 0; subset < (1u << SW_ARRAY_SIZE(Socket::timeout_type_list)); ++subset) {
        int mask = 0;
        for (size_t i = 0; i < SW_ARRAY_SIZE(Socket::timeout_type_list); ++i) {
            if (subset & (1u << i)) {
                mask |= Socket::timeout_type_list[i];
            }
        }
        bool caught = false;
        try {
            Guard guard(&socket, 2.0, static_cast<swoole::TimeoutType>(mask));
            for (size_t i = 0; i < SW_ARRAY_SIZE(Socket::timeout_type_list); ++i) {
                EXPECT_EQ(socket.get_timeout(Socket::timeout_type_list[i]), (subset & (1u << i)) ? 2.0 : original[i]);
            }
            throw std::runtime_error("unwind timeout guard");
        } catch (const std::runtime_error &) {
            caught = true;
        }
        EXPECT_TRUE(caught);
        for (size_t i = 0; i < SW_ARRAY_SIZE(Socket::timeout_type_list); ++i) {
            EXPECT_EQ(socket.get_timeout(Socket::timeout_type_list[i]), original[i]);
        }
    }
}

TEST(coroutine_socket, timeout_guards_restore_all_masks_after_exception) {
    coroutine::run([](void *) {
        Socket socket(SW_SOCK_TCP);
        check_timeout_guard_restoration<Socket::TimeoutSetter>(socket);
        check_timeout_guard_restoration<Socket::TimeoutController>(socket);
    });
}

TEST(coroutine_socket, nested_timeout_guards_restore_outer_values) {
    coroutine::run([](void *) {
        Socket socket(SW_SOCK_TCP);
        socket.set_timeout(0.125);
        do {
            Socket::TimeoutSetter outer(&socket, 1.0, SW_TIMEOUT_ALL);
            do {
                Socket::TimeoutController inner(&socket, 2.0, SW_TIMEOUT_RDWR);
                EXPECT_EQ(socket.get_timeout(SW_TIMEOUT_DNS), 1.0);
                EXPECT_EQ(socket.get_timeout(SW_TIMEOUT_CONNECT), 1.0);
                EXPECT_EQ(socket.get_timeout(SW_TIMEOUT_READ), 2.0);
                EXPECT_EQ(socket.get_timeout(SW_TIMEOUT_WRITE), 2.0);
            } while (0);
            Socket::TimeoutSetter unchanged(&socket, 0, SW_TIMEOUT_ALL);
            for (auto type : Socket::timeout_type_list) {
                EXPECT_EQ(socket.get_timeout(type), 1.0);
            }
        } while (0);
        for (auto type : Socket::timeout_type_list) {
            EXPECT_EQ(socket.get_timeout(type), 0.125);
        }
    });
}

TEST(coroutine_socket, connect_refused) {
    coroutine::run([](void *arg) {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9801);
        ASSERT_EQ(retval, false);
        ASSERT_EQ(sock.errCode, ECONNREFUSED);
    });
}

TEST(coroutine_socket, connect_timeout) {
    coroutine::run([](void *arg) {
        Socket sock(SW_SOCK_TCP);

        sock.set_timeout(0.5);
        ASSERT_EQ(sock.get_timeout(SW_TIMEOUT_DNS), 0.5);
        ASSERT_EQ(sock.get_timeout(SW_TIMEOUT_CONNECT), 0.5);
        ASSERT_EQ(sock.get_timeout(SW_TIMEOUT_READ), 0.5);
        ASSERT_EQ(sock.get_timeout(SW_TIMEOUT_WRITE), 0.5);

        sock.set_timeout(1.5, SW_TIMEOUT_RDWR);
        ASSERT_EQ(sock.get_timeout(SW_TIMEOUT_DNS), 0.5);
        ASSERT_EQ(sock.get_timeout(SW_TIMEOUT_CONNECT), 0.5);
        ASSERT_EQ(sock.get_timeout(SW_TIMEOUT_READ), 1.5);
        ASSERT_EQ(sock.get_timeout(SW_TIMEOUT_WRITE), 1.5);

        bool retval = sock.connect("192.0.0.1", 9801);
        ASSERT_EQ(retval, false);
        ASSERT_EQ(sock.errCode, ETIMEDOUT);
    });
}

TEST(coroutine_socket, timeout_controller) {
    coroutine::run([](void *arg) {
        const int port = __LINE__ + TEST_PORT;
        Coroutine::create([](void *arg) {
            Socket sock(SW_SOCK_TCP);
            bool retval = sock.bind("127.0.0.1", port);
            ASSERT_EQ(retval, true);
            ASSERT_EQ(sock.listen(128), true);

            Socket *conn = sock.accept();
            conn->send(TEST_STR);
            System::sleep(1);
            delete conn;
        });

        Socket sock(SW_SOCK_TCP);
        Socket::TimeoutController tc(&sock, 0.5, SW_TIMEOUT_ALL);
        ASSERT_TRUE(sock.connect("127.0.0.1", port));

        char buf[128];
        off_t offset = 0;
        sock.errCode = 0;
        while (true) {
            if (sw_unlikely(tc.has_timedout(SW_TIMEOUT_READ))) {
                break;
            }
            auto rv = sock.recv(buf + offset, sizeof(buf) - offset);
            if (rv <= 0) {
                break;
            }
            offset += rv;
        }
        ASSERT_TRUE(tc.has_timedout(SW_TIMEOUT_READ));
        ASSERT_EQ(sock.errCode, ETIMEDOUT);
    });
}

TEST(coroutine_socket, timeout_setter) {
    coroutine::run([](void *arg) {
        const int port = __LINE__ + TEST_PORT;
        Coroutine::create([](void *arg) {
            Socket sock(SW_SOCK_TCP);
            bool retval = sock.bind("127.0.0.1", port);
            ASSERT_EQ(retval, true);
            ASSERT_EQ(sock.listen(128), true);

            Socket *conn = sock.accept();
            conn->send(TEST_STR);
            System::sleep(1);
            delete conn;
        });

        Socket sock(SW_SOCK_TCP);
        Socket::TimeoutSetter ts(&sock, 0.5, SW_TIMEOUT_ALL);
        ASSERT_TRUE(sock.connect("127.0.0.1", port));

        char buf[128];
        off_t offset = 0;
        sock.errCode = 0;
        while (true) {
            auto rv = sock.recv(buf + offset, sizeof(buf) - offset);
            if (rv <= 0) {
                break;
            }
            offset += rv;
        }
        ASSERT_EQ(sock.errCode, ETIMEDOUT);
    });
}

TEST(coroutine_socket, connect_with_dns) {
    coroutine::run([](void *arg) {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect(host, 80);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
    });
}

TEST(coroutine_socket, tcp6) {
    coroutine::run([](void *arg) {
        Socket sock(SW_SOCK_TCP6);
        bool retval = sock.connect("::1", 80);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
    });
}

TEST(coroutine_socket, unixsock_fail) {
    coroutine::run([](void *arg) {
        Socket sock(SW_SOCK_UNIX_STREAM);
        bool retval = sock.connect("/tmp/unix.sock");
        ASSERT_EQ(retval, false);
        ASSERT_EQ(sock.errCode, ENOENT);
    });
}

TEST(coroutine_socket, recv_success) {
    pid_t pid;
    int port = swoole::test::get_random_port();

    Process proc([port](Process *proc) {
        Server serv(TEST_HOST, port, swoole::Server::MODE_BASE, SW_SOCK_TCP);
        serv.on("Receive", [](ON_RECEIVE_PARAMS) {
            SERVER_THIS->send(req->info.fd, req->data, req->info.len);
            return 0;
        });
        serv.start();
    });

    pid = proc.start();

    sleep(1);  // wait for the test server to start

    coroutine::run([port](void *arg) {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect(TEST_HOST, port, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
        sock.send(SW_STRS("hello world\n"));
        char buf[128];
        int n = sock.recv(buf, sizeof(buf));
        buf[n] = 0;
        ASSERT_EQ(strcmp(buf, "hello world\n"), 0);
    });

    kill(pid, SIGTERM);
    int status;
    wait(&status);
}

TEST(coroutine_socket, recv_fail) {
    pid_t pid;
    int port = swoole::test::get_random_port();

    Process proc([port](Process *proc) {
        Server serv(TEST_HOST, port, swoole::Server::MODE_BASE, SW_SOCK_TCP);
        serv.on("Receive", [](ON_PACKET_PARAMS) -> int {
            serv->close(req->info.fd, 0);
            return 0;
        });
        serv.start();
    });

    pid = proc.start();

    sleep(1);  // wait for the test server to start

    coroutine::run([port](void *arg) {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect(TEST_HOST, port, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
        sock.send("close", 6);
        char buf[128];
        int n = sock.recv(buf, sizeof(buf));
        ASSERT_EQ(n, 0);
    });

    kill(pid, SIGTERM);
    int status;
    wait(&status);
}

TEST(coroutine_socket, bind_success) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run([port](void *arg) {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", port);
        ASSERT_EQ(retval, true);

        Socket sock_1(SW_SOCK_UNIX_DGRAM);
        retval = sock_1.bind("/tmp/swoole-core-tests.sock");
        ASSERT_EQ(retval, true);
    });
}

TEST(coroutine_socket, bind_fail) {
    coroutine::run([](void *arg) {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("192.111.11.1", 9909);
        ASSERT_EQ(retval, false);
        ASSERT_EQ(sock.errCode, EADDRNOTAVAIL);

        Socket sock_1(SW_SOCK_TCP);
        retval = sock_1.bind("127.0.0.1", 70000);
        ASSERT_EQ(retval, false);
    });
}

TEST(coroutine_socket, listen) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run([port](void *arg) {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", port);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.listen(128), true);
    });
}

TEST(coroutine_socket, accept) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run({[port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.bind("127.0.0.1", port);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.listen(128), true);

                        Socket *conn = sock.accept();
                        ASSERT_NE(conn, nullptr);
                        delete conn;
                    },

                    [port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.connect("127.0.0.1", port, -1);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.errCode, 0);
                        sock.close();
                    }});
}

static void socket_set_eof_protocol(Socket &sock) {
    memcpy(sock.protocol.package_eof, SW_STRL(CRLF));
    sock.protocol.package_eof_len = 2;
    sock.open_eof_check = true;
}

TEST(coroutine_socket, eof_packet_survives_timeout) {
    coroutine::run([](void *) {
        int pair[2];
        ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, pair), 0);
        Socket reader(pair[0], SW_SOCK_UNIX_STREAM);
        Socket writer(pair[1], SW_SOCK_UNIX_STREAM);
        socket_set_eof_protocol(reader);

        ASSERT_EQ(writer.send_all(SW_STRL("hello\r")), 6);
        for (int i = 0; i < 2; i++) {
            ASSERT_EQ(reader.recv_packet(0.01), -1);
            EXPECT_EQ(reader.errCode, ETIMEDOUT);
            EXPECT_FALSE(reader.is_closed());
        }

        ASSERT_EQ(writer.send_all(SW_STRL("\nnext\r\ntruncated")), 16);
        ASSERT_TRUE(writer.close());

        ASSERT_EQ(reader.recv_packet(1), 7);
        EXPECT_MEMEQ(reader.get_read_buffer()->str, "hello\r\n", 7);
        ASSERT_EQ(reader.recv_packet(1), 6);
        EXPECT_MEMEQ(reader.get_read_buffer()->str, "next\r\n", 6);
        EXPECT_EQ(reader.recv_packet(1), 0);
        EXPECT_TRUE(reader.get_read_buffer()->empty());
    });
}

TEST(coroutine_socket, eof_1) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run({[port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.bind("127.0.0.1", port);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.listen(128), true);

                        Socket *conn = sock.accept();
                        char buf[1024];
                        ssize_t l = conn->recv(buf, sizeof(buf));
                        EXPECT_EQ(string(buf, l), string("start\r\n"));
                        conn->send(EOF_PACKET);
                    },

                    [port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.connect("127.0.0.1", port, -1);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.errCode, 0);
                        sock.send("start\r\n");

                        socket_set_eof_protocol(sock);

                        ssize_t l = sock.recv_packet(RECV_TIMEOUT);
                        size_t eof_packet_len = strlen(EOF_PACKET);
                        auto buf = sock.get_read_buffer();

                        ASSERT_EQ(l, eof_packet_len);
                        ASSERT_EQ(string(buf->str, l), string(EOF_PACKET));
                        ASSERT_EQ(buf->length, eof_packet_len);
                        ASSERT_EQ(buf->offset, eof_packet_len);
                    }});
}

TEST(coroutine_socket, eof_2) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run({[port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        ASSERT_TRUE(sock.bind("127.0.0.1", port));
                        ASSERT_TRUE(sock.listen(128));

                        Socket *conn = sock.accept();
                        char buf[1024];
                        ssize_t l = conn->recv(buf, sizeof(buf));
                        EXPECT_EQ(string(buf, l), string("start\r\n"));
                        conn->send(EOF_PACKET EOF_PACKET_2);
                    },

                    [port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.connect("127.0.0.1", port, -1);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.errCode, 0);
                        sock.send("start\r\n");

                        socket_set_eof_protocol(sock);

                        // packet 1
                        {
                            ssize_t l = sock.recv_packet(RECV_TIMEOUT);
                            size_t eof_packet_len = strlen(EOF_PACKET);
                            auto buf = sock.get_read_buffer();

                            ASSERT_EQ(l, eof_packet_len);
                            ASSERT_EQ(string(buf->str, l), string(EOF_PACKET));
                            ASSERT_EQ(buf->length, strlen(EOF_PACKET EOF_PACKET_2));
                            ASSERT_EQ(buf->offset, eof_packet_len);
                        }
                        // packet 2
                        {
                            ssize_t l = sock.recv_packet(RECV_TIMEOUT);
                            size_t eof_packet_len = strlen(EOF_PACKET_2);
                            auto buf = sock.get_read_buffer();

                            ASSERT_EQ(l, eof_packet_len);
                            ASSERT_EQ(string(buf->str, l), string(EOF_PACKET_2));
                            ASSERT_EQ(buf->length, strlen(EOF_PACKET_2));
                            ASSERT_EQ(buf->offset, eof_packet_len);
                        }
                    }});
}

TEST(coroutine_socket, eof_3) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run({[port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.bind("127.0.0.1", port);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.listen(128), true);

                        Socket *conn = sock.accept();
                        char buf[1024];
                        ssize_t l = conn->recv(buf, sizeof(buf));
                        EXPECT_EQ(string(buf, l), string("start\r\n"));
                        conn->shutdown();
                    },

                    [port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.connect("127.0.0.1", port, -1);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.errCode, 0);
                        sock.send("start\r\n");

                        socket_set_eof_protocol(sock);

                        ssize_t l = sock.recv_packet(RECV_TIMEOUT);
                        ASSERT_EQ(l, 0);
                    }});
}

TEST(coroutine_socket, eof_4) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run({[port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.bind("127.0.0.1", port);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.listen(128), true);

                        Socket *conn = sock.accept();
                        char buf[1024];
                        ssize_t l = conn->recv(buf, sizeof(buf));
                        EXPECT_EQ(string(buf, l), string("start\r\n"));
                        conn->send(EOF_PACKET, strlen(EOF_PACKET) - strlen(CRLF));  // no eof
                        conn->shutdown();
                    },

                    [port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.connect("127.0.0.1", port, -1);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.errCode, 0);
                        sock.send("start\r\n");

                        socket_set_eof_protocol(sock);

                        ssize_t l = sock.recv_packet(RECV_TIMEOUT);
                        ASSERT_EQ(l, 0);

                        auto buf = sock.get_read_buffer();
                        ASSERT_EQ(string(buf->str, 10), string(EOF_PACKET, 10));
                    }});
}

TEST(coroutine_socket, eof_5) {
    const int port = __LINE__ + TEST_PORT;
    size_t pkt_len = 512 * 1024;
    coroutine::run({[pkt_len, port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.bind("127.0.0.1", port);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.listen(128), true);

                        Socket *conn = sock.accept();
                        char buf[1024];
                        ssize_t l = conn->recv(buf, sizeof(buf));
                        EXPECT_EQ(string(buf, l), string("start\r\n"));

                        String *s = swoole::make_string(pkt_len);
                        s->repeat("A", 1, pkt_len - 16);
                        s->append(SW_STRL(CRLF));

                        conn->get_socket()->set_send_buffer_size(65536);
                        conn->send_all(s->str, s->length);
                    },

                    [pkt_len, port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.connect("127.0.0.1", port, -1);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.errCode, 0);
                        sock.send("start\r\n");

                        socket_set_eof_protocol(sock);

                        sock.get_socket()->set_recv_buffer_size(65536);
                        ssize_t l = sock.recv_packet(RECV_TIMEOUT);
                        ASSERT_EQ(l, pkt_len - 14);
                    }});
}

TEST(coroutine_socket, eof_6) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run({[port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.bind("127.0.0.1", port);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.listen(128), true);

                        Socket *conn = sock.accept();
                        char buf[1024];
                        ssize_t l = conn->recv(buf, sizeof(buf));
                        EXPECT_EQ(string(buf, l), string("start\r\n"));

                        String s(128 * 1024);
                        s.repeat("A", 1, 128 * 1024 - 16);
                        s.append(SW_STRL(CRLF));

                        conn->send_all(s.value(), s.get_length());
                    },

                    [port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.connect("127.0.0.1", port, -1);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.errCode, 0);
                        sock.send("start\r\n");

                        socket_set_eof_protocol(sock);
                        sock.protocol.package_max_length = 1024 * 64;

                        ssize_t l = sock.recv_packet(RECV_TIMEOUT);
                        ASSERT_EQ(l, -1);
                        ASSERT_EQ(sock.errCode, SW_ERROR_PACKAGE_LENGTH_TOO_LARGE);
                    }});
}

static void socket_set_length_protocol_1(Socket &sock) {
    sock.protocol = {};

    sock.protocol.package_length_type = 'n';
    sock.protocol.package_length_size = swoole_type_size(sock.protocol.package_length_type);
    sock.protocol.package_body_offset = 2;
    sock.protocol.get_package_length = Protocol::default_length_func;
    sock.protocol.package_max_length = 65535;

    sock.open_length_check = true;
}

static void socket_set_length_protocol_2(Socket &sock) {
    sock.protocol = {};

    sock.protocol.package_length_type = 'N';
    sock.protocol.package_length_size = swoole_type_size(sock.protocol.package_length_type);
    sock.protocol.package_body_offset = 4;
    sock.protocol.get_package_length = Protocol::default_length_func;
    sock.protocol.package_max_length = 2 * 1024 * 1024;

    sock.open_length_check = true;
}

TEST(coroutine_socket, length_1) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run({[port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.bind("127.0.0.1", port);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.listen(128), true);

                        Socket *conn = sock.accept();
                        char buf[1024];
                        ssize_t l = swoole_random_bytes(buf + 2, sizeof(buf) - 2);
                        *(uint16_t *) buf = htons(l);

                        conn->send(buf, l + 2);
                    },

                    [port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.connect("127.0.0.1", port, -1);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.errCode, 0);

                        socket_set_length_protocol_1(sock);

                        ssize_t l = sock.recv_packet(RECV_TIMEOUT);
                        auto buf = sock.get_read_buffer();

                        ASSERT_EQ(l, 1024);
                        ASSERT_EQ(buf->length, l);
                        ASSERT_EQ(buf->offset, l);
                    }});
}

TEST(coroutine_socket, length_2) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run({[port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.bind("127.0.0.1", port);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.listen(128), true);

                        Socket *conn = sock.accept();
                        char buf[1024];
                        *(uint16_t *) buf = htons(0);

                        conn->send(buf, 2);
                    },

                    [port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.connect("127.0.0.1", port, -1);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.errCode, 0);

                        socket_set_length_protocol_1(sock);

                        ssize_t l = sock.recv_packet(RECV_TIMEOUT);
                        auto buf = sock.get_read_buffer();

                        ASSERT_EQ(l, 2);
                        ASSERT_EQ(buf->length, 2);
                        ASSERT_EQ(buf->offset, 2);
                    }});
}

TEST(coroutine_socket, length_3) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run({[](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.bind("127.0.0.1", port);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.listen(128), true);

                        Socket *conn = sock.accept();
                        char buf[1024];
                        memset(buf, 'A', sizeof(buf));
                        *(uint16_t *) buf = htons(65530);

                        conn->send(buf, sizeof(buf));
                    },

                    [](void *arg) {
                        Socket sock(SW_SOCK_TCP);
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

static string pkt_1;
static string pkt_2;

static void length_protocol_server_func(void *arg, int port) {
    Socket sock(SW_SOCK_TCP);
    bool retval = sock.bind("127.0.0.1", port);
    ASSERT_EQ(retval, true);
    ASSERT_EQ(sock.listen(128), true);

    Socket *conn = sock.accept();
    String strbuf(256 * 1024);

    uint32_t pack_len;

    size_t l_1 = swoole_rand(65536, 65536 * 2);
    pack_len = htonl(l_1);
    strbuf.append((char *) &pack_len, sizeof(pack_len));
    strbuf.append_random_bytes(l_1);

    pkt_1 = string(strbuf.str, l_1 + 4);

    size_t l_2 = swoole_rand(65536, 65536 * 2);
    pack_len = htonl(l_2);
    strbuf.append((char *) &pack_len, sizeof(pack_len));
    strbuf.append_random_bytes(l_2);

    pkt_2 = string(strbuf.str + pkt_1.length(), l_2 + 4);

    conn->send_all(strbuf.str, strbuf.length);
}

TEST(coroutine_socket, length_4) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run({[port](void *arg) { length_protocol_server_func(arg, port); },

                    [port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.connect("127.0.0.1", port, -1);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.errCode, 0);

                        socket_set_length_protocol_2(sock);

                        size_t bytes = 0;
                        for (int i = 0; i < 2; i++) {
                            ssize_t l = sock.recv_packet(RECV_TIMEOUT);
                            bytes += l;
                            auto buf = sock.get_read_buffer();
                            uint32_t unpack_len = ntohl(*(uint32_t *) buf->str);

                            if (i == 0) {
                                ASSERT_EQ(pkt_1, string(buf->str, buf->length));
                            } else {
                                ASSERT_EQ(pkt_2, string(buf->str, buf->length));
                            }

                            ASSERT_EQ(unpack_len, l - 4);
                            ASSERT_EQ(buf->length, l);
                            ASSERT_EQ(buf->offset, l);
                        }
                        ASSERT_GE(bytes, 65536 * 2);
                    }});
}

TEST(coroutine_socket, length_5) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run({[port](void *arg) { length_protocol_server_func(arg, port); },

                    [port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.connect("127.0.0.1", port, -1);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.errCode, 0);

                        socket_set_length_protocol_2(sock);

                        size_t bytes = 0;
                        for (int i = 0; i < 2; i++) {
                            ssize_t l = sock.recv_packet(RECV_TIMEOUT);
                            bytes += l;
                            char *data = sock.pop_packet();
                            uint32_t unpack_len = ntohl(*(uint32_t *) data);
                            ASSERT_EQ(unpack_len, l - 4);

                            if (i == 0) {
                                ASSERT_EQ(pkt_1, string(data, l));
                            } else {
                                ASSERT_EQ(pkt_2, string(data, l));
                            }
                        }
                        ASSERT_GE(bytes, 65536 * 2);
                    }});
}

TEST(coroutine_socket, length_7) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run({[port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.bind("127.0.0.1", port);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.listen(128), true);

                        Socket *conn = sock.accept();
                        char buf[1024];
                        *(uint32_t *) buf = htons(0);

                        conn->send(buf, 2);
                        System::sleep(0.01);
                        conn->send(buf + 2, 2);
                    },

                    [port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.connect("127.0.0.1", port, -1);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.errCode, 0);

                        socket_set_length_protocol_2(sock);

                        ssize_t l = sock.recv_packet(RECV_TIMEOUT);
                        auto buf = sock.get_read_buffer();

                        ASSERT_EQ(l, 4);
                        ASSERT_EQ(buf->length, 4);
                        ASSERT_EQ(buf->offset, 4);
                    }});
}

TEST(coroutine_socket, event_hup) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run({[port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.bind("127.0.0.1", port);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.listen(128), true);

                        Socket *conn = sock.accept();
                        System::sleep(0.05);
                        char buf[1024];
                        auto ret_n = conn->recv(buf, sizeof(buf));
                        ASSERT_EQ(ret_n, 0);
                        delete conn;
                    },

                    [port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.connect("127.0.0.1", port, -1);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.errCode, 0);

                        auto buf = sock.get_read_buffer();
                        Coroutine::create([&sock](void *args) {
                            System::sleep(0.01);
                            sock.shutdown(SHUT_RDWR);
                        });
                        auto n = sock.recv_all(buf->str, buf->size);
                        ASSERT_EQ(sock.get_socket()->event_hup, 1);
                        ASSERT_EQ(n, 0);
                    }});
}

TEST(coroutine_socket, recv_line) {
    const int port = __LINE__ + TEST_PORT;
    coroutine::run({[port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.bind("127.0.0.1", port);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.listen(128), true);

                        Socket *conn = sock.accept();
                        conn->send("hello world\n");
                        conn->send("\r");
                        char buf[256];
                        memset(buf, 'A', 128);
                        memset(buf + 128, 'B', 125);
                        conn->send(buf, 253);
                        delete conn;
                    },

                    [port](void *arg) {
                        Socket sock(SW_SOCK_TCP);
                        bool retval = sock.connect("127.0.0.1", port, -1);
                        ASSERT_EQ(retval, true);
                        ASSERT_EQ(sock.errCode, 0);

                        size_t n;
                        auto buf = sock.get_read_buffer();

                        n = sock.recv_line(buf->str, 128);
                        ASSERT_EQ(n, 12);
                        ASSERT_MEMEQ(buf->str, "hello world\n", 12);

                        n = sock.recv_line(buf->str, 128);
                        ASSERT_EQ(n, 1);
                        ASSERT_MEMEQ(buf->str, "\r", 1);

                        char buf_2[256];
                        memset(buf_2, 'A', 128);
                        memset(buf_2 + 128, 'B', 125);

                        n = sock.recv_line(buf->str, 128);
                        ASSERT_EQ(n, 128);
                        ASSERT_MEMEQ(buf->str, buf_2, 128);

                        n = sock.recv_line(buf->str, 128);
                        ASSERT_EQ(n, 125);
                        ASSERT_MEMEQ(buf->str, buf_2 + 128, 125);

                        n = sock.recv_line(buf->str, 128);
                        ASSERT_EQ(n, 0);
                    }});
}

TEST(coroutine_socket, getsockname) {
    coroutine::run([](void *arg) {
        Socket sock(SW_SOCK_TCP);
        ASSERT_TRUE(sock.connect(host, 80));
        ASSERT_TRUE(sock.getsockname());
        sock.close();
    });
}

TEST(coroutine_socket, buffer) {
    Socket sock(SW_SOCK_TCP);
    auto rbuf = sock.get_read_buffer();
    auto wbuf = sock.get_write_buffer();

    auto rbuf_pop = sock.pop_read_buffer();
    auto wbuf_pop = sock.pop_write_buffer();

    ASSERT_EQ(rbuf, rbuf_pop);
    ASSERT_EQ(wbuf, wbuf_pop);

    auto rbuf2 = sock.get_read_buffer();
    auto wbuf2 = sock.get_write_buffer();

    ASSERT_NE(rbuf2, rbuf);
    ASSERT_NE(wbuf2, wbuf);

    delete rbuf_pop;
    delete wbuf_pop;
}

TEST(coroutine_socket, check_liveness) {
    coroutine::run([](void *arg) {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect(host, 80);
        ASSERT_EQ(retval, true);

        bool result = sock.check_liveness();
        sock.close();
        ASSERT_EQ(result, true);
        result = sock.check_liveness();
        ASSERT_EQ(result, false);
    });
}

TEST(coroutine_socket, write_and_read) {
    coroutine::run([&](void *arg) {
        int pairs[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);
        std::string text = "Hello World";
        size_t length = text.length();

        Coroutine::create([&](void *) {
            Socket sock(pairs[0], SW_SOCK_UNIX_STREAM);
            ssize_t result = sock.write(text.c_str(), length);
            sock.close();
            ASSERT_EQ(result, length);
        });

        char data[128];
        Socket sock(pairs[1], SW_SOCK_UNIX_STREAM);
        ssize_t result = sock.read(data, 128);
        sock.close();
        ASSERT_GT(result, 0);
        data[result] = '\0';
        ASSERT_STREQ(text.c_str(), data);
    });
}

TEST(coroutine_socket, write_and_read_2) {
    // test for Socket::Socket(int _fd, int _domain, int _type, int _protocol) construct function
    coroutine::run([&](void *arg) {
        int pairs[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);
        std::string text = "Hello World";
        size_t length = text.length();

        Coroutine::create([&](void *) {
            Socket sock(pairs[0], AF_UNIX, SOCK_STREAM, 0);
            ssize_t result = sock.write(text.c_str(), length);
            sock.close();
            ASSERT_EQ(result, length);
        });

        char data[128];
        Socket sock(pairs[1], AF_UNIX, SOCK_STREAM, 0);
        ssize_t result = sock.read(data, 128);
        sock.close();
        ASSERT_GT(result, 0);
        data[result] = '\0';
        ASSERT_STREQ(text.c_str(), data);
    });
}

TEST(coroutine_socket, writev_and_readv) {
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

            Socket sock(pairs[0], SW_SOCK_UNIX_STREAM);
            ssize_t result = sock.writev(&io_vector);
            sock.close();
            ASSERT_EQ(result, length * 3);
        });

        std::vector<std::string> results(iovcnt, std::string(length, '\0'));
        std::unique_ptr<iovec[]> iov(new iovec[iovcnt]);
        for (int i = 0; i < iovcnt; i++) {
            iov[i].iov_base = &results[i][0];
            iov[i].iov_len = length;
        }
        IOVector io_vector((struct iovec *) iov.get(), iovcnt);

        Socket sock(pairs[1], SW_SOCK_UNIX_STREAM);
        ssize_t result = sock.readv(&io_vector);
        sock.close();
        ASSERT_EQ(result, length * 3);

        for (const auto &value : results) {
            ASSERT_EQ(value, text);
        }
    });
}

TEST(coroutine_socket, send_and_recv_all) {
    coroutine::run([&](void *arg) {
        int pairs[2];

        String wbuf;
        wbuf.append_random_bytes(4 * 1024 * 1024, false);
        socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);

        Coroutine::create([&](void *) {
            Socket sock(pairs[0], SW_SOCK_UNIX_STREAM);
            sock.get_socket()->set_send_buffer_size(65536);

            ASSERT_EQ(sock.send_all(wbuf.str, wbuf.length), wbuf.length);

            System::sleep(0.1);

            sock.close();
        });

        Socket sock(pairs[1], SW_SOCK_UNIX_STREAM);
        sock.get_socket()->set_recv_buffer_size(65536);

        String rbuf(wbuf.length);
        ssize_t result = sock.recv_all(rbuf.str, wbuf.length);
        ASSERT_EQ(result, wbuf.length);
        ASSERT_MEMEQ(wbuf.str, rbuf.str, wbuf.length);
        System::sleep(0.1);
        sock.close();
    });
}

TEST(coroutine_socket, writevall_and_readvall) {
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

            Socket sock(pairs[0], SW_SOCK_UNIX_STREAM);
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

        Socket sock(pairs[1], SW_SOCK_UNIX_STREAM);
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

TEST(coroutine_socket, sendfile) {
    coroutine::run([&](void *arg) {
        int pairs[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);
        Coroutine::create([&](void *) {
            std::string file = swoole::test::get_jpg_file();
            Socket sock(pairs[0], SW_SOCK_UNIX_STREAM);
            bool result = sock.sendfile(file.c_str(), 0, 0);
            sock.close();
            ASSERT_TRUE(result);
        });

        char data[250000];
        Socket sock(pairs[1], SW_SOCK_UNIX_STREAM);
        ssize_t result = sock.recv_all(data, 250000);
        data[result] = '\0';
        sock.close();
        ASSERT_GT(result, 0);
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

        Socket sock_server(sock_type);
        Socket sock_client(sock_type);
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

TEST(coroutine_socket, sendto_recvfrom_udp) {
    test_sendto_recvfrom(SW_SOCK_UDP);
    test_sendto_recvfrom(SW_SOCK_UDP6);
}

static void socket_test_request_baidu(Socket &sock) {
    ASSERT_GT(sock.send(SW_STRL(TEST_REQUEST_BAIDU)), 0);

    String buf(65536);
    while (true) {
        char rbuf[4096];
        ssize_t nr = sock.recv(rbuf, sizeof(rbuf));
        if (nr <= 0) {
            break;
        }
        buf.append(rbuf, nr);
    }
    ASSERT_TRUE(buf.contains("www.baidu.com"));
}

static void proxy_test(Socket &sock, bool https) {
    if (https) {
        sock.enable_ssl_encrypt();
    }

    bool retval = sock.connect(host, https ? 443 : 80);
    ON_SCOPE_EXIT {
        sock.close();
    };
    ASSERT_EQ(retval, true);

    if (https) {
        ASSERT_NE(sock.ssl_get_peer_cert(), "");
    }

    socket_test_request_baidu(sock);
}

static void proxy_set_socks5_proxy(Socket &socket, int port, bool auth) {
    std::string username, password;
    if (auth) {
        username = std::string(TEST_SOCKS5_PROXY_USER);
        password = std::string(TEST_SOCKS5_PROXY_PASSWORD);
    }
    socket.set_socks5_proxy(TEST_SOCKS5_PROXY_HOST, port, username, password);
}

TEST(coroutine_socket, https_get_with_socks5_proxy) {
    coroutine::run([](void *arg) {
        if (swoole::test::is_github_ci()) {
            Socket sock(SW_SOCK_TCP);
            proxy_set_socks5_proxy(sock, TEST_SOCKS5_PROXY_PORT, true);
            proxy_test(sock, true);
        }
        // no auth
        {
            Socket sock(SW_SOCK_TCP);
            proxy_set_socks5_proxy(sock, TEST_SOCKS5_PROXY_NO_AUTH_PORT, false);
            proxy_test(sock, true);
        }
    });
}

TEST(coroutine_socket, http_get_with_socks5_proxy) {
    coroutine::run([](void *arg) {
        if (swoole::test::is_github_ci()) {
            Socket sock(SW_SOCK_TCP);
            proxy_set_socks5_proxy(sock, TEST_SOCKS5_PROXY_PORT, true);
            proxy_test(sock, false);
        }
        // no auth
        {
            Socket sock(SW_SOCK_TCP);
            proxy_set_socks5_proxy(sock, TEST_SOCKS5_PROXY_NO_AUTH_PORT, false);
            proxy_test(sock, false);
        }
    });
}

static void proxy_set_http_proxy(Socket &socket) {
    std::string username, password;
    if (swoole::test::is_github_ci()) {
        username = std::string(TEST_HTTP_PROXY_USER);
        password = std::string(TEST_HTTP_PROXY_PASSWORD);
    }
    socket.set_http_proxy(TEST_HTTP_PROXY_HOST, TEST_HTTP_PROXY_PORT, username, password);
}

TEST(coroutine_socket, http_get_with_http_proxy) {
    coroutine::run([&](void *arg) {
        Socket sock(SW_SOCK_TCP);
        proxy_set_http_proxy(sock);
        proxy_test(sock, false);
    });
}

TEST(coroutine_socket, https_get_with_http_proxy) {
    coroutine::run([&](void *arg) {
        Socket sock(SW_SOCK_TCP);
        proxy_set_http_proxy(sock);
        proxy_test(sock, true);
    });
}

TEST(coroutine_socket, ssl) {
    coroutine::run([&](void *arg) {
        Socket sock(SW_SOCK_TCP);

        sock.enable_ssl_encrypt();
        sock.set_ssl_cert_file(swoole::test::get_ssl_dir() + "/client.crt");
        sock.set_ssl_key_file(swoole::test::get_ssl_dir() + "/client.key");
        sock.set_ssl_verify_peer(false);
        sock.set_ssl_allow_self_signed(true);
        sock.set_ssl_cafile(swoole::test::get_ssl_dir() + "/ca.crt");

        proxy_test(sock, true);
    });
}

TEST(coroutine_socket, ssl_accept) {
    const int port = __LINE__ + TEST_PORT;
    auto svr = [port](void *arg) {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", port);
        ASSERT_EQ(retval, true);

        ASSERT_FALSE(sock.ssl_handshake());
        EXPECT_EQ(sock.errCode, SW_ERROR_SSL_NOT_READY);
        ASSERT_TRUE(sock.enable_ssl_encrypt());
        sock.set_ssl_cert_file(swoole::test::get_ssl_dir() + "/server.crt");
        sock.set_ssl_key_file(swoole::test::get_ssl_dir() + "/server.key");
        sock.set_ssl_dhparam(swoole::test::get_ssl_dir() + "/dhparams.pem");
        sock.set_ssl_ecdh_curve("secp256r1");

        ASSERT_EQ(sock.listen(128), true);

        Socket *conn = sock.accept();
        ASSERT_NE(conn, nullptr);
        conn->set_err(ETIMEDOUT);
        ASSERT_TRUE(conn->ssl_handshake());
        EXPECT_EQ(conn->errCode, 0);
        EXPECT_FALSE(conn->ssl_handshake());
        EXPECT_EQ(conn->errCode, SW_ERROR_WRONG_OPERATION);
        conn->send(EOF_PACKET);
        char rbuf[1024];
        auto n = conn->recv(rbuf, sizeof(rbuf));
        rbuf[n] = 0;

        ASSERT_STREQ(rbuf, EOF_PACKET_2);
        conn->close();
        delete conn;
    };

    auto cli = [port](void *arg) {
        Socket sock(SW_SOCK_TCP);
        sock.enable_ssl_encrypt();
        bool retval = sock.connect("127.0.0.1", port, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);

        char rbuf[1024];
        auto n = sock.recv(rbuf, sizeof(rbuf));
        rbuf[n] = 0;
        ASSERT_STREQ(rbuf, EOF_PACKET);
        sock.send(EOF_PACKET_2);

        sock.close();
    };

    coroutine::run({svr, cli});
}

TEST(coroutine_socket, peek) {
    coroutine::run([&](void *arg) {
        int pairs[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);
        std::string text = "Hello World";
        size_t length = text.length();

        Coroutine::create([&](void *) {
            Socket sock(pairs[0], SW_SOCK_UNIX_STREAM);
            ssize_t result = sock.write(text.c_str(), length);
            sock.close();
            ASSERT_EQ(result, length);
        });

        char data[128];
        Socket sock(pairs[1], SW_SOCK_UNIX_STREAM);
        ssize_t result = sock.peek(data, 5);
        sock.close();
        ASSERT_EQ(result, 5);
        data[result] = '\0';
        ASSERT_STREQ("Hello", data);
    });
}

TEST(coroutine_socket, sendmsg_and_recvmsg) {
    coroutine::run([&](void *arg) {
        int pairs[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);

        std::string text = "Hello World";
        const size_t length = text.length();

        Coroutine::create([&](void *) {
            Socket sock(pairs[0], SW_SOCK_UNIX_STREAM);
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

        Socket sock(pairs[1], SW_SOCK_UNIX_STREAM);
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

std::pair<std::shared_ptr<Socket>, std::shared_ptr<Socket> > swoole::test::create_socket_pair() {
    int pairs[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);

    auto sock0 = new Socket(pairs[0], SW_SOCK_UNIX_STREAM);
    auto sock1 = new Socket(pairs[1], SW_SOCK_UNIX_STREAM);

    sock0->get_socket()->set_buffer_size(65536);
    sock1->get_socket()->set_buffer_size(65536);

    std::pair<std::shared_ptr<Socket>, std::shared_ptr<Socket> > result(sock0, sock1);
    return result;
}

TEST(coroutine_socket, close) {
    coroutine::run([&](void *arg) {
        auto pair = create_socket_pair();

        auto buffer = sw_tg_buffer();
        buffer->clear();
        buffer->append_random_bytes(256 * 1024, false);

        std::map<std::string, bool> results;
        swoole::coroutine::ChannelImpl<bool> finished(2);
        auto _sock = pair.first;

        // write co
        Coroutine::create([&](void *) {
            SW_LOOP_N(32) {
                ssize_t result = _sock->write(buffer->value(), buffer->get_length());
                if (result < 0 && _sock->errCode == ECANCELED) {
                    ASSERT_FALSE(_sock->close());
                    ASSERT_EQ(_sock->errCode, EBADF);
                    results["write"] = true;
                    finished.push(true);
                    ASSERT_EQ(_sock->write(buffer->value(), buffer->get_length()), -1);
                    ASSERT_EQ(_sock->errCode, EBADF);
                    break;
                }
            }
        });

        // read co
        Coroutine::create([&](void *) {
            SW_LOOP_N(32) {
                char buf[4096];
                ssize_t result = _sock->read(buf, sizeof(buf));
                if (result < 0 && _sock->errCode == ECANCELED) {
                    ASSERT_FALSE(_sock->close());
                    ASSERT_EQ(_sock->errCode, EBADF);
                    results["read"] = true;
                    finished.push(true);
                    break;
                }
            }
        });

        System::sleep(0.1);
        ASSERT_TRUE(_sock->close());
        ASSERT_TRUE(_sock->is_closed());
        for (int i = 0; i < 2; ++i) {
            bool done = false;
            ASSERT_TRUE(finished.pop(&done, 2));
            ASSERT_TRUE(done);
        }
        ASSERT_TRUE(results["write"]);
        ASSERT_TRUE(results["read"]);
        ASSERT_FALSE(_sock->close());
        ASSERT_EQ(_sock->errCode, EBADF);
    });
}

static void test_concurrent_close_barrier(bool destructor_callback) {
    coroutine::run([&](void *) {
        auto pair = create_socket_pair();
        auto socket = pair.first;
        const auto main_cid = Coroutine::get_current()->get_cid();
        swoole::coroutine::ChannelImpl<bool> finished(2);
        bool winner_returned = false;
        int releases = 0;
        const auto owner_cid = Coroutine::create([&](void *) {
            auto release = [&](Socket *) {
                ++releases;
                swoole_event_defer(
                    [main_cid](void *) {
                        if (auto *main = Coroutine::get_by_cid(main_cid)) {
                            main->resume();
                        }
                    },
                    nullptr);
                Coroutine::get_current()->yield();
            };
            if (destructor_callback) {
                socket->set_dtor(release);
                EXPECT_TRUE(socket->close());
            } else {
                EXPECT_TRUE(socket->close(release));
            }
            EXPECT_TRUE(socket->is_closed());
            EXPECT_EQ(socket->errCode, 0);
            winner_returned = true;
        });
        Coroutine::get_current()->yield();
        long loser_cid = 0;
        for (int i = 0; i < 2; ++i) {
            const auto cid = Coroutine::create([&](void *) {
                EXPECT_FALSE(socket->close());
                EXPECT_EQ(socket->errCode, EBADF);
                EXPECT_TRUE(socket->is_closed());
                EXPECT_TRUE(winner_returned);
                finished.push(true);
            });
            loser_cid = cid;
        }
        auto *loser = Coroutine::get_by_cid(loser_cid);
        ASSERT_NE(loser, nullptr);
        EXPECT_FALSE(loser->cancel());
        loser->resume();
        EXPECT_EQ(finished.length(), 0);
        EXPECT_EQ(socket->is_closed(), destructor_callback);
        EXPECT_EQ(releases, 1);
        auto *owner = Coroutine::get_by_cid(owner_cid);
        ASSERT_NE(owner, nullptr);
        owner->resume();
        EXPECT_TRUE(winner_returned);
        for (int i = 0; i < 2; ++i) {
            bool done = false;
            ASSERT_TRUE(finished.pop(&done, 2));
            EXPECT_TRUE(done);
        }
        EXPECT_EQ(releases, 1);
        EXPECT_FALSE(socket->close());
        EXPECT_EQ(socket->errCode, EBADF);
    });
}

TEST(coroutine_socket, concurrent_close_waits_for_descriptor_release) {
    test_concurrent_close_barrier(false);
}

TEST(coroutine_socket, concurrent_close_waits_for_post_release_callback) {
    test_concurrent_close_barrier(true);
}

TEST(coroutine_socket, cancel) {
    coroutine::run([&](void *arg) {
        auto pair = create_socket_pair();

        auto buffer = sw_tg_buffer();
        buffer->clear();
        buffer->append_random_bytes(256 * 1024, false);

        std::map<std::string, bool> results;
        // read co
        Coroutine::create([&](void *) {
            SW_LOOP_N(32) {
                char buf[4096];
                ssize_t result = pair.first->read(buf, sizeof(buf));
                if (result < 0 && pair.first->errCode == ECANCELED) {
                    results["read"] = true;
                    break;
                }
            }
        });

        System::sleep(0.1);
        pair.first->cancel(SW_EVENT_READ);
        ASSERT_TRUE(results["read"]);
    });
}

static void check_socket_dns_cancellation(swoole::EventType event,
                                          bool close_socket,
                                          bool completed,
                                          bool return_address = false,
                                          bool finish_early = false) {
    struct State {
        std::promise<void> entered;
        std::promise<void> release;
        std::promise<void> resolved;
        std::shared_future<void> resume = release.get_future().share();
        long cid = -1;
        int returned = 0;
        int finished = 0;
        bool canceled = false;
        bool released = false;
        bool finish_early = false;
    } state;
    state.finish_early = finish_early;
    const auto core_workers = SwooleG.aio_core_worker_num;
    const auto max_workers = SwooleG.aio_worker_num;
    auto resolvers = std::move(SwooleTG.name_resolvers);
    SwooleTG.name_resolvers.clear();
    SwooleG.aio_core_worker_num = SwooleG.aio_worker_num = 1;
    ON_SCOPE_EXIT {
        SwooleTG.name_resolvers = std::move(resolvers);
        SwooleG.aio_core_worker_num = core_workers;
        SwooleG.aio_worker_num = max_workers;
    };
    std::unique_ptr<Socket> socket;
    coroutine::run([&](void *) {
        ON_SCOPE_EXIT {
            if (!state.released) {
                state.release.set_value();
            }
        };
        // A custom resolver forces the real thread-pool DNS path even in c-ares builds.
        swoole::NameResolver resolver{};
        resolver.type = swoole::NameResolver::TYPE_USER;
        resolver.resolve = [&](const std::string &, swoole::NameResolver::Context *ctx, void *) {
            ctx->final_ = true;
            auto result = swoole::coroutine::gethostbyname_impl_with_async("localhost", ctx->type, 5);
            state.canceled = Coroutine::get_current()->is_canceled();
            return return_address ? std::string("127.0.0.1") : result;
        };
        swoole_name_resolver_add(resolver);
        swoole::AsyncEvent barrier{};
        barrier.object = &state;
        barrier.handler = [](swoole::AsyncEvent *event) {
            auto *state = static_cast<State *>(event->object);
            state->entered.set_value();
            state->resume.wait();
        };
        ASSERT_NE(swoole::async::dispatch(&barrier), nullptr);
        ASSERT_EQ(state.entered.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
        socket = std::make_unique<Socket>(SW_SOCK_TCP);
        state.cid = Coroutine::create([&](void *) {
            EXPECT_FALSE(socket->connect("socket-cancel.test", 1));
            EXPECT_EQ(socket->errCode, ECANCELED);
            EXPECT_FALSE(socket->is_connected());
            ++state.returned;
            if (!finish_early) {
                // A late DNS callback must not wake this unrelated wait.
                Coroutine::get_current()->yield();
            }
            ++state.finished;
        });
        ASSERT_GT(state.cid, 0);
        EXPECT_TRUE(socket->has_bound(SW_EVENT_READ));
        EXPECT_TRUE(socket->has_bound(SW_EVENT_WRITE));
        swoole::AsyncEvent fence{};
        fence.object = &state;
        fence.handler = [](swoole::AsyncEvent *event) { static_cast<State *>(event->object)->resolved.set_value(); };
        fence.callback = [](swoole::AsyncEvent *event) {
            auto *state = static_cast<State *>(event->object);
            EXPECT_EQ(state->finished, state->finish_early ? 1 : 0);
            auto *co = Coroutine::get_by_cid(state->cid);
            if (state->finish_early) {
                EXPECT_EQ(co, nullptr);
            } else if (co) {
                co->resume();
            }
        };
        ASSERT_NE(swoole::async::dispatch(&fence), nullptr);
        if (completed) {
            state.release.set_value();
            state.released = true;
            // Single-worker FIFO makes this a fence for DNS completion, before reactor delivery.
            ASSERT_EQ(state.resolved.get_future().wait_for(std::chrono::seconds(3)), std::future_status::ready);
        }
        if (close_socket) {
            EXPECT_TRUE(socket->close());
        } else {
            EXPECT_TRUE(socket->cancel(event));
        }
        EXPECT_EQ(state.returned, 1);
        EXPECT_TRUE(state.canceled);
        EXPECT_FALSE(socket->has_bound());
        if (close_socket) {
            EXPECT_FALSE(socket->close());
            EXPECT_EQ(socket->errCode, EBADF);
        } else {
            EXPECT_TRUE(socket->close());
        }
        if (!state.released) {
            state.release.set_value();
            state.released = true;
        }
    });
    EXPECT_EQ(state.returned, 1);
    EXPECT_EQ(state.finished, 1);
}

TEST(coroutine_socket, cancel_dns_read_while_pending) {
    check_socket_dns_cancellation(SW_EVENT_READ, false, false);
}

TEST(coroutine_socket, cancel_dns_write_while_pending) {
    check_socket_dns_cancellation(SW_EVENT_WRITE, false, false);
}

TEST(coroutine_socket, cancel_dns_after_resolution) {
    check_socket_dns_cancellation(SW_EVENT_READ, false, true);
}

TEST(coroutine_socket, close_during_dns) {
    check_socket_dns_cancellation(SW_EVENT_READ, true, false);
}

TEST(coroutine_socket, close_after_dns_resolution) {
    check_socket_dns_cancellation(SW_EVENT_READ, true, true);
}

TEST(coroutine_socket, canceled_dns_resolver_cannot_return_success) {
    check_socket_dns_cancellation(SW_EVENT_READ, false, false, true);
}

TEST(coroutine_socket, canceled_dns_coroutine_may_end_before_result) {
    check_socket_dns_cancellation(SW_EVENT_READ, false, false, false, true);
}

TEST(coroutine_socket, close_dns_preserves_pending_cancellation) {
    auto resolvers = std::move(SwooleTG.name_resolvers);
    SwooleTG.name_resolvers.clear();
    ON_SCOPE_EXIT {
        SwooleTG.name_resolvers = std::move(resolvers);
    };
    coroutine::run([](void *) {
        int cancellation_count = 0;
        swoole::NameResolver resolver{};
        resolver.type = swoole::NameResolver::TYPE_USER;
        resolver.resolve = [&](const std::string &, swoole::NameResolver::Context *, void *) {
            // Model a resolver whose I/O acknowledges cancellation before the completion resumes its coroutine.
            Coroutine::CancelFunc cancel = [&](Coroutine *) {
                ++cancellation_count;
                return true;
            };
            Coroutine::get_current()->yield(&cancel);
            return std::string("127.0.0.1");
        };
        swoole_name_resolver_add(resolver);
        Socket socket(SW_SOCK_TCP);
        bool returned = false;
        auto cid = Coroutine::create([&](void *) {
            EXPECT_FALSE(socket.connect("pending-cancel.test", 1));
            EXPECT_EQ(socket.errCode, ECANCELED);
            returned = true;
        });
        ASSERT_GT(cid, 0);
        bool closed = false;
        swoole::coroutine::ChannelImpl<bool> finished(1);
        Coroutine::create([&](void *) {
            EXPECT_TRUE(socket.close());
            closed = true;
            finished.push(true);
        });
        EXPECT_FALSE(returned);
        EXPECT_FALSE(closed);
        // One resolver owns both bindings; close must cancel it once and wait for its cleanup.
        EXPECT_EQ(cancellation_count, 1);
        auto *co = Coroutine::get_by_cid(cid);
        ASSERT_NE(co, nullptr);
        co->resume();
        EXPECT_TRUE(returned);
        bool done = false;
        ASSERT_TRUE(finished.pop(&done, 2));
        EXPECT_TRUE(closed);
        EXPECT_TRUE(done);
        EXPECT_TRUE(socket.is_closed());
        EXPECT_FALSE(socket.close());
        EXPECT_EQ(socket.errCode, EBADF);
    });
}

TEST(coroutine_socket, resolver_cannot_join_close_while_owning_its_binding) {
    auto resolvers = std::move(SwooleTG.name_resolvers);
    SwooleTG.name_resolvers.clear();
    ON_SCOPE_EXIT {
        SwooleTG.name_resolvers = std::move(resolvers);
    };
    coroutine::run([](void *) {
        Socket socket(SW_SOCK_TCP);
        swoole::NameResolver resolver{};
        resolver.type = swoole::NameResolver::TYPE_USER;
        resolver.resolve = [&](const std::string &, swoole::NameResolver::Context *, void *) {
            Coroutine::CancelFunc cancel = [](Coroutine *co) {
                co->resume();
                return true;
            };
            Coroutine::get_current()->yield(&cancel);
            EXPECT_FALSE(socket.close());
            EXPECT_EQ(socket.errCode, EDEADLK);
            return std::string("127.0.0.1");
        };
        swoole_name_resolver_add(resolver);
        bool returned = false;
        Coroutine::create([&](void *) {
            EXPECT_FALSE(socket.connect("self-close.test", 1));
            EXPECT_EQ(socket.errCode, ECANCELED);
            returned = true;
        });
        EXPECT_TRUE(socket.close());
        EXPECT_TRUE(socket.is_closed());
        EXPECT_TRUE(returned);
    });
}

TEST(coroutine_socket, get_event_str) {
    Socket sock;
    ASSERT_STREQ(sock.get_event_str(SW_EVENT_READ), "reading");
    ASSERT_STREQ(sock.get_event_str(SW_EVENT_WRITE), "writing");
}

TEST(coroutine_socket, option) {
    Socket sock(SW_SOCK_TCP);
    int optval;

    ASSERT_TRUE(sock.get_option(SOL_SOCKET, SO_RCVBUF, &optval));
    ASSERT_GT(optval, 65536);

    optval *= 2;
    ASSERT_TRUE(sock.set_option(SOL_SOCKET, SO_RCVBUF, optval));
}

static void test_ssl_verify() {
    Socket sock(SW_SOCK_TCP);
    sock.enable_ssl_encrypt();
    sock.set_tls_host_name(TEST_HTTP_DOMAIN);
    sock.set_ssl_verify_peer(true);
    ASSERT_TRUE(sock.connect(TEST_HTTP_DOMAIN, 443));
    ASSERT_TRUE(sock.ssl_verify(false));

    auto req = swoole::test::http_get_request(TEST_HTTP_DOMAIN, "/");
    ASSERT_EQ(sock.send(req.c_str(), req.length()), req.length());
    ASSERT_TRUE(sock.check_liveness());

    String buf(65536);
    SW_LOOP {
        auto n = sock.recv(buf.str + buf.length, buf.size - buf.length);
        if (n <= 0) {
            break;
        }
        buf.grow(n);
    }

    ASSERT_TRUE(buf.contains(TEST_HTTPS_EXPECT));

    usleep(50000);
    ASSERT_FALSE(sock.check_liveness());
}

TEST(coroutine_socket, ssl_verify) {
    coroutine::run([](void *arg) { test_ssl_verify(); });
}

TEST(coroutine_socket, shutdown) {
    coroutine::run([](void *arg) {
        Socket sock(SW_SOCK_TCP);
        ASSERT_TRUE(sock.connect(TEST_HTTP_DOMAIN, 80));
        ASSERT_TRUE(sock.shutdown(SHUT_RD));
        ASSERT_FALSE(sock.shutdown(SHUT_RD));
        ASSERT_ERREQ(ENOTCONN);

        ASSERT_TRUE(sock.shutdown(SHUT_WR));
        ASSERT_FALSE(sock.shutdown(SHUT_WR));
        ASSERT_ERREQ(ENOTCONN);

        ASSERT_FALSE(sock.shutdown());
        ASSERT_ERREQ(ENOTCONN);
    });
}

TEST(coroutine_socket, recv_packet) {
    coroutine::run([](void *arg) {
        Socket sock(SW_SOCK_TCP);
        ASSERT_TRUE(sock.connect(TEST_HTTP_DOMAIN, 80));
        auto req = swoole::test::http_get_request(TEST_HTTP_DOMAIN, "/");
        ASSERT_EQ(sock.send(req.c_str(), req.length()), req.length());
        ASSERT_TRUE(sock.check_liveness());
        auto n = sock.recv_packet();
        ASSERT_GT(n, 0);
        auto buf = sock.get_read_buffer();
        ASSERT_TRUE(buf->contains(TEST_HTTP_EXPECT));
    });
}

TEST(coroutine_socket, set_error) {
    Socket sock(SW_SOCK_TCP);
    sock.set_err(1000, std::string(TEST_STR));

    ASSERT_EQ(sock.errCode, 1000);
    ASSERT_STREQ(sock.errMsg, TEST_STR);
}

TEST(coroutine_socket, reinit) {
    coroutine::run([](void *arg) {
        Socket sock(SW_SOCK_TCP6);
        ASSERT_EQ(sock.get_sock_domain(), AF_INET6);
        proxy_set_socks5_proxy(sock, TEST_SOCKS5_PROXY_PORT, true);
        sock.connect("::1", 80);
        ASSERT_EQ(sock.get_sock_domain(), AF_INET);
    });
}
