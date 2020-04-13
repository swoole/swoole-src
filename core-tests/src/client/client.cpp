#include "tests.h"
#include "process.h"
#include "wrapper/server.h"

#define GREETER "Hello Swoole"
#define GREETER_SIZE sizeof(GREETER)

using swoole::test::process;
using swoole::test::server;

static void tcp_on_receive(ON_RECEIVE_PARAMS)
{
    char *data_ptr = NULL;

    size_t data_len = SERVER_THIS->get_packet(req, (char **) &data_ptr);

    SERVER_THIS->send(req->info.fd, data_ptr, data_len);
}

TEST(client, tcp)
{
    int ret;
    swClient cli;
    char buf[128];

    pid_t pid;

    process proc([](process *proc)
    {
        server serv(TEST_HOST, TEST_PORT, SW_MODE_BASE, SW_SOCK_TCP);
        serv.on("onReceive", (void *) tcp_on_receive);
        serv.start();
    });

    pid = proc.start();

    sleep(1); // wait for the test server to start

    ret = swClient_create(&cli, SW_SOCK_TCP, SW_SOCK_SYNC);
    ASSERT_EQ(ret, 0);
    ret = cli.connect(&cli, TEST_HOST, TEST_PORT, -1, 0);
    ASSERT_EQ(ret, 0);
    ret = cli.send(&cli, SW_STRS(GREETER), 0);
    ASSERT_GT(ret, 0);
    ret = cli.recv(&cli, buf, 128, 0);
    ASSERT_EQ(ret, GREETER_SIZE);
    ASSERT_STREQ(GREETER, buf);
    cli.close(&cli);
    kill(pid, SIGKILL);
}

static void udp_on_packet(ON_PACKET_PARAMS)
{
    swDgramPacket *packet = nullptr;

    SERVER_THIS->get_packet(req, (char **) &packet);

    SERVER_THIS->sendto(&packet->socket_addr, packet->data, packet->length, req->info.server_fd);
}

TEST(client, udp)
{
    int ret;
    swClient cli;
    char buf[128];

    pid_t pid;

    process proc([](process *proc)
    {
        server serv(TEST_HOST, TEST_PORT, SW_MODE_BASE, SW_SOCK_UDP);
        serv.on("onPacket", (void *) udp_on_packet);
        serv.start();
    });

    pid = proc.start();

    sleep(1); // wait for the test server to start

    ret = swClient_create(&cli, SW_SOCK_UDP, SW_SOCK_SYNC);
    ASSERT_EQ(ret, 0);
    ret = cli.connect(&cli, TEST_HOST, TEST_PORT, -1, 0);
    ASSERT_EQ(ret, 0);
    ret = cli.send(&cli, SW_STRS(GREETER), 0);
    ASSERT_GT(ret, 0);
    ret = cli.recv(&cli, buf, 128, 0);
    ASSERT_EQ(ret, GREETER_SIZE);
    ASSERT_STREQ(GREETER, buf);
    cli.close(&cli);
    kill(pid, SIGKILL);
}
