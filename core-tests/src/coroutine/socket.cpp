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

#include "test_process.h"
#include "test_coroutine.h"
#include "test_server.h"

using namespace swoole::test;

using swoole::coroutine::Socket;
using swoole::coroutine::System;
using swoole::test::Server;

TEST(coroutine_socket, connect_refused)
{
    coroutine::run([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9801);
        ASSERT_EQ(retval, false);
        ASSERT_EQ(sock.errCode, ECONNREFUSED);
    });
}

TEST(coroutine_socket, connect_timeout)
{
    coroutine::run([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        sock.set_timeout(0.5);
        bool retval = sock.connect("192.0.0.1", 9801);
        ASSERT_EQ(retval, false);
        ASSERT_EQ(sock.errCode, ETIMEDOUT);
    });
}

TEST(coroutine_socket, connect_with_dns)
{
    coroutine::run([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("www.baidu.com", 80);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
    });
}

TEST(coroutine_socket, recv_success)
{
    pid_t pid;

    Process proc([](Process *proc)
    {
        on_receive_lambda_type receive_fn = [](ON_RECEIVE_PARAMS)
        {
            char *data_ptr = NULL;
            size_t data_len = SERVER_THIS->get_packet(req, (char **) &data_ptr);

            SERVER_THIS->send(req->info.fd, data_ptr, data_len);
        };

        Server serv(TEST_HOST, TEST_PORT, SW_MODE_BASE, SW_SOCK_TCP);
        serv.on("onReceive", (void *) receive_fn);
        serv.start();
    });

    pid = proc.start();

    sleep(1); // wait for the test server to start

    coroutine::run([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect(TEST_HOST, TEST_PORT, -1);
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

TEST(coroutine_socket, recv_fail)
{
    pid_t pid;

    Process proc([](Process *proc)
    {
        on_receive_lambda_type receive_fn = [](ON_RECEIVE_PARAMS)
        {
            SERVER_THIS->close(req->info.fd, 0);
        };

        Server serv(TEST_HOST, TEST_PORT, SW_MODE_BASE, SW_SOCK_TCP);
        serv.on("onReceive", (void *) receive_fn);
        serv.start();
    });

    pid = proc.start();

    sleep(1); // wait for the test server to start

    coroutine::run([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect(TEST_HOST, TEST_PORT, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
        sock.send("close", 6);
        char buf[128];
        int n = sock.recv(buf, sizeof(buf));
        ASSERT_EQ(n, 0);
    });

    kill(pid, SIGKILL);
}

TEST(coroutine_socket, bind_success)
{
    coroutine::run([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", 9909);
        ASSERT_EQ(retval, true);
    });
}

TEST(coroutine_socket, bind_fail)
{
    coroutine::run([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("192.111.11.1", 9909);
        ASSERT_EQ(retval, false);
        ASSERT_EQ(sock.errCode, EADDRNOTAVAIL);
    });
}

TEST(coroutine_socket, listen)
{
    coroutine::run([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", 9909);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.listen(128), true);
    });
}

TEST(coroutine_socket, accept)
{
    coroutine::run({
        [](void *arg)
        {
            Socket sock(SW_SOCK_TCP);
            bool retval = sock.bind("127.0.0.1", 9909);
            ASSERT_EQ(retval, true);
            ASSERT_EQ(sock.listen(128), true);

            Socket *conn = sock.accept();
            ASSERT_NE(conn, nullptr);
        },

        [](void *arg)
        {
            Socket sock(SW_SOCK_TCP);
            bool retval = sock.connect("127.0.0.1", 9909, -1);
            ASSERT_EQ(retval, true);
            ASSERT_EQ(sock.errCode, 0);
            sock.close();
        }
    });
}

#define CRLF  "\r\n"
#define EOF_PACKET "hello world" CRLF
#define EOF_PACKET_2 "php&swoole, java&golang" CRLF
#define RECV_TIMEOUT 10.0

static void socket_set_eof_protocol(Socket &sock)
{
    memcpy( sock.protocol.package_eof, SW_STRL(CRLF));
    sock.protocol.package_eof_len = 2;
    sock.open_eof_check = true;
}

TEST(coroutine_socket, eof_1)
{
    coroutine::run({
        [](void *arg)
        {
            Socket sock(SW_SOCK_TCP);
            bool retval = sock.bind("127.0.0.1", 9909);
            ASSERT_EQ(retval, true);
            ASSERT_EQ(sock.listen(128), true);

            Socket *conn = sock.accept();
            char buf[1024];
            ssize_t l = conn->recv(buf, sizeof(buf));
            EXPECT_EQ(string(buf, l), string("start\r\n"));
            conn->send(EOF_PACKET);
        },

        [](void *arg)
        {
            Socket sock(SW_SOCK_TCP);
            bool retval = sock.connect("127.0.0.1", 9909, -1);
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
        }
    });
}

TEST(coroutine_socket, eof_2)
{
    coroutine::run({
        [](void *arg)
        {
            Socket sock(SW_SOCK_TCP);
            bool retval = sock.bind("127.0.0.1", 9909);
            ASSERT_EQ(retval, true);
            ASSERT_EQ(sock.listen(128), true);

            Socket *conn = sock.accept();
            char buf[1024];
            ssize_t l = conn->recv(buf, sizeof(buf));
            EXPECT_EQ(string(buf, l), string("start\r\n"));
            conn->send(EOF_PACKET EOF_PACKET_2);
        },

        [](void *arg)
        {
            Socket sock(SW_SOCK_TCP);
            bool retval = sock.connect("127.0.0.1", 9909, -1);
            ASSERT_EQ(retval, true);
            ASSERT_EQ(sock.errCode, 0);
            sock.send("start\r\n");

            socket_set_eof_protocol(sock);

            //packet 1
            {
                ssize_t l = sock.recv_packet(RECV_TIMEOUT);
                size_t eof_packet_len = strlen(EOF_PACKET);
                auto buf = sock.get_read_buffer();

                ASSERT_EQ(l, eof_packet_len);
                ASSERT_EQ(string(buf->str, l), string(EOF_PACKET));
                ASSERT_EQ(buf->length, strlen(EOF_PACKET EOF_PACKET_2));
                ASSERT_EQ(buf->offset, eof_packet_len);
            }
            //packet 2
            {
                 ssize_t l = sock.recv_packet(RECV_TIMEOUT);
                 size_t eof_packet_len = strlen(EOF_PACKET_2);
                 auto buf = sock.get_read_buffer();

                 ASSERT_EQ(l, eof_packet_len);
                 ASSERT_EQ(string(buf->str, l), string(EOF_PACKET_2));
                 ASSERT_EQ(buf->length, strlen(EOF_PACKET_2));
                 ASSERT_EQ(buf->offset, eof_packet_len);
             }
        }
    });
}

TEST(coroutine_socket, eof_3)
{
    coroutine::run({
        [](void *arg)
        {
            Socket sock(SW_SOCK_TCP);
            bool retval = sock.bind("127.0.0.1", 9909);
            ASSERT_EQ(retval, true);
            ASSERT_EQ(sock.listen(128), true);

            Socket *conn = sock.accept();
            char buf[1024];
            ssize_t l = conn->recv(buf, sizeof(buf));
            EXPECT_EQ(string(buf, l), string("start\r\n"));
            conn->shutdown();
        },

        [](void *arg)
        {
            Socket sock(SW_SOCK_TCP);
            bool retval = sock.connect("127.0.0.1", 9909, -1);
            ASSERT_EQ(retval, true);
            ASSERT_EQ(sock.errCode, 0);
            sock.send("start\r\n");

            socket_set_eof_protocol(sock);

            ssize_t l = sock.recv_packet(RECV_TIMEOUT);
            ASSERT_EQ(l, 0);
        }
    });
}

TEST(coroutine_socket, eof_4)
{
    coroutine::run({
        [](void *arg)
        {
            Socket sock(SW_SOCK_TCP);
            bool retval = sock.bind("127.0.0.1", 9909);
            ASSERT_EQ(retval, true);
            ASSERT_EQ(sock.listen(128), true);

            Socket *conn = sock.accept();
            char buf[1024];
            ssize_t l = conn->recv(buf, sizeof(buf));
            EXPECT_EQ(string(buf, l), string("start\r\n"));
            conn->send(EOF_PACKET, strlen(EOF_PACKET) - strlen(CRLF)); //no eof
            conn->shutdown();
        },

        [](void *arg)
        {
            Socket sock(SW_SOCK_TCP);
            bool retval = sock.connect("127.0.0.1", 9909, -1);
            ASSERT_EQ(retval, true);
            ASSERT_EQ(sock.errCode, 0);
            sock.send("start\r\n");

            socket_set_eof_protocol(sock);

            ssize_t l = sock.recv_packet(RECV_TIMEOUT);
            ASSERT_EQ(l, 0);

            auto buf = sock.get_read_buffer();
            ASSERT_EQ(string(buf->str, 10), string(EOF_PACKET, 10));
        }
    });
}

TEST(coroutine_socket, eof_5)
{
    coroutine::run(
    { [](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", 9909);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.listen(128), true);

        Socket *conn = sock.accept();
        char buf[1024];
        ssize_t l = conn->recv(buf, sizeof(buf));
        EXPECT_EQ(string(buf, l), string("start\r\n"));

        swString *s = swoole::make_string(128*1024);
        swString_repeat(s, "A", 1, 128 * 1024 - 16);
        swString_append_ptr(s, SW_STRL(CRLF));

        conn->send_all(s->str, s->length);
    },

    [](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9909, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
        sock.send("start\r\n");

        socket_set_eof_protocol(sock);

        ssize_t l = sock.recv_packet(RECV_TIMEOUT);
        ASSERT_EQ(l, 128 * 1024 - 14);
    } });
}

TEST(coroutine_socket, eof_6)
{
    coroutine::run(
    { [](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", 9909);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.listen(128), true);

        Socket *conn = sock.accept();
        char buf[1024];
        ssize_t l = conn->recv(buf, sizeof(buf));
        EXPECT_EQ(string(buf, l), string("start\r\n"));

        swString *s = swoole::make_string(128*1024);
        swString_repeat(s, "A", 1, 128 * 1024 - 16);
        swString_append_ptr(s, SW_STRL(CRLF));

        conn->send_all(s->str, s->length);
    },

    [](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9909, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
        sock.send("start\r\n");

        socket_set_eof_protocol(sock);
        sock.protocol.package_max_length = 1024 * 64;

        ssize_t l = sock.recv_packet(RECV_TIMEOUT);
        ASSERT_EQ(l, -1);
        ASSERT_EQ(sock.errCode, SW_ERROR_PACKAGE_LENGTH_TOO_LARGE);
    } });
}

static void socket_set_length_protocol_1(Socket &sock)
{
    sock.protocol = {};

    sock.protocol.package_length_type = 'n';
    sock.protocol.package_length_size = swoole_type_size(sock.protocol.package_length_type);
    sock.protocol.package_body_offset = 2;
    sock.protocol.get_package_length = swProtocol_get_package_length;
    sock.protocol.package_max_length = 65535;

    sock.open_length_check = true;
}

static void socket_set_length_protocol_2(Socket &sock)
{
    sock.protocol = {};

    sock.protocol.package_length_type = 'N';
    sock.protocol.package_length_size = swoole_type_size(sock.protocol.package_length_type);
    sock.protocol.package_body_offset = 4;
    sock.protocol.get_package_length = swProtocol_get_package_length;
    sock.protocol.package_max_length = 2*1024*1024;

    sock.open_length_check = true;
}

TEST(coroutine_socket, length_1)
{
    coroutine::run(
    { [](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", 9502);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.listen(128), true);

        Socket *conn = sock.accept();
        char buf[1024];
        ssize_t l = swoole_random_bytes(buf + 2, sizeof(buf) - 2);
        *(uint16_t *)buf = htons(l);

        conn->send(buf, l+2);
    },

    [](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9502, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);

        socket_set_length_protocol_1(sock);

        ssize_t l = sock.recv_packet(RECV_TIMEOUT);
        auto buf = sock.get_read_buffer();

        ASSERT_EQ(l, 1024);
        ASSERT_EQ(buf->length, l);
        ASSERT_EQ(buf->offset, l);
    } });
}

TEST(coroutine_socket, length_2)
{
    coroutine::run(
    { [](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", 9502);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.listen(128), true);

        Socket *conn = sock.accept();
        char buf[1024];
        *(uint16_t *)buf = htons(0);

        conn->send(buf, 2);
    },

    [](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9502, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);

        socket_set_length_protocol_1(sock);

        ssize_t l = sock.recv_packet(RECV_TIMEOUT);
        auto buf = sock.get_read_buffer();

        ASSERT_EQ(l, 2);
        ASSERT_EQ(buf->length, 2);
        ASSERT_EQ(buf->offset, 2);
    } });
}

TEST(coroutine_socket, length_3)
{
    coroutine::run(
    { [](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", 9502);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.listen(128), true);

        Socket *conn = sock.accept();
        char buf[1024];
        memset(buf, 'A', sizeof(buf));
        *(uint16_t *)buf = htons(65530);

        conn->send(buf, sizeof(buf));
    },

    [](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9502, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);

        socket_set_length_protocol_1(sock);
        sock.protocol.package_max_length = 4096;

        ssize_t l = sock.recv_packet(RECV_TIMEOUT);
        ASSERT_EQ(l, -1);
        ASSERT_EQ(sock.errCode, SW_ERROR_PACKAGE_LENGTH_TOO_LARGE);
    } });
}

static string pkt_1;
static string pkt_2;

static void length_protocol_server_func(void *arg)
{
    Socket sock(SW_SOCK_TCP);
    bool retval = sock.bind("127.0.0.1", 9502);
    ASSERT_EQ(retval, true);
    ASSERT_EQ(sock.listen(128), true);

    Socket *conn = sock.accept();
    auto strbuf = swoole::make_string(256 * 1024);
    swoole::String s(strbuf);

    uint32_t pack_len;

    size_t l_1 = swoole_rand(65536, 65536 * 2);
    pack_len = htonl(l_1);
    swString_append_ptr(strbuf, (char*) &pack_len, sizeof(pack_len));
    swString_append_random_bytes(strbuf, l_1);

    pkt_1 = string(strbuf->str, l_1 + 4);

    size_t l_2 = swoole_rand(65536, 65536 * 2);
    pack_len = htonl(l_2);
    swString_append_ptr(strbuf, (char*) &pack_len, sizeof(pack_len));
    swString_append_random_bytes(strbuf, l_2);

    pkt_2 = string(strbuf->str + pkt_1.length(), l_2 + 4);

    conn->send_all(strbuf->str, strbuf->length);
}

TEST(coroutine_socket, length_4)
{
    coroutine::run(
    { length_protocol_server_func,

    [](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9502, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);

        socket_set_length_protocol_2(sock);

        size_t bytes = 0;
        for(int i=0; i< 2; i++)
        {
            ssize_t l = sock.recv_packet(RECV_TIMEOUT);
            bytes+=l;
            auto buf = sock.get_read_buffer();
            uint32_t unpack_len = ntohl(*(uint32_t *)buf->str);

            if (i == 0)
            {
                ASSERT_EQ(pkt_1, string(buf->str, buf->length));
            }
            else
            {
                ASSERT_EQ(pkt_2, string(buf->str, buf->length));
            }

            ASSERT_EQ(unpack_len, l - 4);
            ASSERT_EQ(buf->length, l);
            ASSERT_EQ(buf->offset, l);
        }
        ASSERT_GE(bytes, 65536*2);
    } });
}

TEST(coroutine_socket, length_5)
{
    coroutine::run(
    { length_protocol_server_func,

    [](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9502, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);

        socket_set_length_protocol_2(sock);

        size_t bytes = 0;
        for(int i=0; i< 2; i++)
        {
            ssize_t l = sock.recv_packet(RECV_TIMEOUT);
            bytes+=l;
            char *data = sock.pop_packet();
            uint32_t unpack_len = ntohl(*(uint32_t *)data);
            ASSERT_EQ(unpack_len, l - 4);

            if (i == 0)
            {
                ASSERT_EQ(pkt_1, string(data, l));
            }
            else
            {
                ASSERT_EQ(pkt_2, string(data, l));
            }
        }
        ASSERT_GE(bytes, 65536*2);
    } });
}

TEST(coroutine_socket, length_7)
{
    coroutine::run(
    { [](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", 9502);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.listen(128), true);

        Socket *conn = sock.accept();
        char buf[1024];
        *(uint32_t *)buf = htons(0);

        conn->send(buf, 2);
        System::sleep(0.01);
        conn->send(buf + 2, 2);
    },

    [](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9502, -1);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);

        socket_set_length_protocol_2(sock);

        ssize_t l = sock.recv_packet(RECV_TIMEOUT);
        auto buf = sock.get_read_buffer();

        ASSERT_EQ(l, 4);
        ASSERT_EQ(buf->length, 4);
        ASSERT_EQ(buf->offset, 4);
    } });
}
