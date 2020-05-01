#include "test_coroutine.h"
#include "test_process.h"
#include "test_server.h"

using namespace swoole::test;

using swoole::coroutine::Socket;

TEST(coroutine_socket, connect_refused)
{
    swoole_event_init();
    SwooleTG.reactor->wait_exit = 1;

    test::coroutine::test([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.connect("127.0.0.1", 9801, 0.5);
        ASSERT_EQ(retval, false);
        ASSERT_EQ(sock.errCode, ECONNREFUSED);
    });
}

TEST(coroutine_socket, connect_timeout)
{
    test::coroutine::test([](void *arg)
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
    test::coroutine::test([](void *arg)
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

    test::coroutine::test([](void *arg)
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

    test::coroutine::test([](void *arg) 
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
    test::coroutine::test([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", 9909);
        ASSERT_EQ(retval, true);
    });
}

TEST(coroutine_socket, bind_fail)
{
    test::coroutine::test([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("192.111.11.1", 9909);
        ASSERT_EQ(retval, false);
        ASSERT_EQ(sock.errCode, EADDRNOTAVAIL);
    });
}

TEST(coroutine_socket, listen)
{
    test::coroutine::test([](void *arg)
    {
        Socket sock(SW_SOCK_TCP);
        bool retval = sock.bind("127.0.0.1", 9909);
        ASSERT_EQ(retval, true);
        ASSERT_EQ(sock.listen(128), true);
    });
}

TEST(coroutine_socket, accept)
{
    test::coroutine::test({
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
