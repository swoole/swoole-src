#include "test_coroutine.h"
#include "test_process.h"
#include "test_server.h"
#include "swoole_cxx.h"

using namespace swoole::test;

using swoole::coroutine::Socket;

TEST(coroutine_socket, connect_refused)
{
    swoole_event_init();
    SwooleTG.reactor->wait_exit = 1;

    test::coroutine::run([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9801, 0.5);
        ASSERT_EQ(retval, false);
        ASSERT_EQ(sock.errCode, ECONNREFUSED);
    });
}

TEST(coroutine_socket, connect_timeout)
{
    test::coroutine::run([](void *arg)
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
    test::coroutine::run([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("www.baidu.com", 80, 0.5);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.errCode, 0);
    });
}

TEST(coroutine_socket, recv_success)
{
    pid_t pid;

    process proc([](process *proc)
    {
        on_receive_lambda_type receive_fn = [](ON_RECEIVE_PARAMS)
        {
            char *data_ptr = NULL;
            size_t data_len = SERVER_THIS->get_packet(req, (char **) &data_ptr);

            SERVER_THIS->send(req->info.fd, data_ptr, data_len);
        };

        server serv(TEST_HOST, TEST_PORT, SW_MODE_BASE, SW_SOCK_TCP);
        serv.on("onReceive", (void *) receive_fn);
        serv.start();
    });

    pid = proc.start();

    sleep(1); // wait for the test server to start

    test::coroutine::run([](void *arg)
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

    kill(pid, SIGKILL);
}

TEST(coroutine_socket, recv_fail)
{
    pid_t pid;

    process proc([](process *proc)
    {
        on_receive_lambda_type receive_fn = [](ON_RECEIVE_PARAMS)
        {
            SERVER_THIS->close(req->info.fd, 0);
        };

        server serv(TEST_HOST, TEST_PORT, SW_MODE_BASE, SW_SOCK_TCP);
        serv.on("onReceive", (void *) receive_fn);
        serv.start();
    });

    pid = proc.start();

    sleep(1); // wait for the test server to start

    test::coroutine::run([](void *arg)
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
    test::coroutine::run([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", 9909);
        ASSERT_EQ(retval, true);
    });
}

TEST(coroutine_socket, bind_fail)
{
    test::coroutine::run([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("192.111.11.1", 9909);
        ASSERT_EQ(retval, false);
        ASSERT_EQ(sock.errCode, EADDRNOTAVAIL);
    });
}

TEST(coroutine_socket, listen)
{
    test::coroutine::run([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", 9909);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.listen(128), true);
    });
}

TEST(coroutine_socket, accept)
{
    test::coroutine::run({
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
    test::coroutine::run({
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
    test::coroutine::run({
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
    test::coroutine::run({
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
            conn->close();
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
    test::coroutine::run({
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
            conn->close();
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
    test::coroutine::run(
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
    test::coroutine::run(
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
