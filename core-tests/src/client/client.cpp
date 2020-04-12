#include "tests.h"
#include "process.h"
#include "wrapper/server.h"

#define GREETER "Hello Swoole"
#define GREETER_SIZE sizeof(GREETER)

using swoole::test::process;
using swoole::test::server;

static void tcp_on_receive(swServer *serv, swEventData *data)
{
    char *data_ptr = NULL;
    size_t data_len = serv->get_packet(serv, data, &data_ptr);

    serv->send(serv, data->info.fd, data_ptr, data_len);
}

TEST(client, tcp)
{
    int ret;
    swClient cli;
    char buf[128];

    pid_t pid;

    process proc([](process *proc)
    {
        server serv("127.0.0.1", 9501, SW_MODE_BASE, SW_SOCK_TCP);
        serv.on("onReceive", (void *) tcp_on_receive);
        serv.start();
    });

    pid = proc.start();

    sleep(1); // wait for the test server to start

    ret = swClient_create(&cli, SW_SOCK_TCP, SW_SOCK_SYNC);
    ASSERT_EQ(ret, 0);
    ret = cli.connect(&cli, "127.0.0.1", 9501, -1, 0);
    ASSERT_EQ(ret, 0);
    ret = cli.send(&cli, SW_STRS(GREETER), 0);
    ASSERT_GT(ret, 0);
    ret = cli.recv(&cli, buf, 128, 0);
    ASSERT_EQ(ret, GREETER_SIZE);
    ASSERT_STREQ(GREETER, buf);
    cli.close(&cli);
    kill(pid, SIGKILL);
}

static void udp_on_packet(swServer *serv, swEventData *data)
{
    char *data_ptr = NULL;
    serv->get_packet(serv, data, &data_ptr);
    swDgramPacket *packet = (swDgramPacket *) data_ptr;
    char ip[256];
    
    inet_ntop(AF_INET, &packet->socket_addr.addr.inet_v4.sin_addr, ip, sizeof(ip));
    uint16_t port = ntohs(packet->socket_addr.addr.inet_v4.sin_port);

    swSocket_udp_sendto(data->info.server_fd, ip, port, packet->data, packet->length);
}

TEST(client, udp)
{
    int ret;
    swClient cli;
    char buf[128];

    pid_t pid;

    process proc([](process *proc)
    {
        server serv("127.0.0.1", 9501, SW_MODE_BASE, SW_SOCK_UDP);
        serv.on("onPacket", (void *) udp_on_packet);
        serv.start();
    });

    pid = proc.start();

    sleep(1); // wait for the test server to start

    ret = swClient_create(&cli, SW_SOCK_UDP, SW_SOCK_SYNC);
    ASSERT_EQ(ret, 0);
    ret = cli.connect(&cli, "127.0.0.1", 9501, -1, 0);
    ASSERT_EQ(ret, 0);
    ret = cli.send(&cli, SW_STRS(GREETER), 0);
    ASSERT_GT(ret, 0);
    ret = cli.recv(&cli, buf, 128, 0);
    ASSERT_EQ(ret, GREETER_SIZE);
    ASSERT_STREQ(GREETER, buf);
    cli.close(&cli);
    kill(pid, SIGKILL);
}
