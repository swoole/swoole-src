#include "test_core.h"
#include "test_server.h"
#include "wrapper/client.hpp"
#include "test_process.h"

#define GREETER "Hello Swoole"
#define GREETER_SIZE sizeof(GREETER)

using swoole::AsyncClient;
using swoole::test::Process;
using swoole::test::Server;

TEST(client, tcp) {
    int ret;
    swClient cli;
    char buf[128];

    pid_t pid;

    Process proc([](Process *proc) {
        on_receive_lambda_type receive_fn = [](ON_RECEIVE_PARAMS) {
            SERVER_THIS->send(req->info.fd, req->data, req->info.len);
        };

        Server serv(TEST_HOST, TEST_PORT, SW_MODE_BASE, SW_SOCK_TCP);
        serv.on("onReceive", (void *) receive_fn);
        serv.start();
    });

    pid = proc.start();

    sleep(1);  // wait for the test server to start

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

    kill(pid, SIGTERM);
    int status;
    wait(&status);
}

TEST(client, udp) {
    int ret;
    swClient cli;
    char buf[128];

    pid_t pid;

    Process proc([](Process *proc) {
        on_packet_lambda_type packet_fn = [](ON_PACKET_PARAMS) {
            swDgramPacket *packet = (swDgramPacket *) req->data;
            SERVER_THIS->sendto(&packet->socket_addr, packet->data, packet->length, req->info.server_fd);
        };

        Server serv(TEST_HOST, TEST_PORT, SW_MODE_BASE, SW_SOCK_UDP);
        serv.on("onPacket", (void *) packet_fn);
        serv.start();
    });

    pid = proc.start();

    sleep(1);  // wait for the test server to start

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

    kill(pid, SIGTERM);
    int status;
    wait(&status);
}

TEST(client, async_tcp) {
    pid_t pid;

    swPipe p;
    ASSERT_EQ(swPipeNotify_auto(&p, 1, 1), 0);

    Process proc([&p](Process *proc) {
        on_receive_lambda_type receive_fn = [](ON_RECEIVE_PARAMS) {
            SERVER_THIS->send(req->info.fd, req->data, req->info.len);
        };

        Server serv(TEST_HOST, TEST_PORT, SW_MODE_BASE, SW_SOCK_TCP);

        serv.set_private_data("pipe", &p);

        serv.on("onReceive", (void *) receive_fn);

        on_workerstart_lambda_type worker_start_fn = [](ON_WORKERSTART_PARAMS) {
            swPipe *p = (swPipe *) SERVER_THIS->get_private_data("pipe");
            int64_t value = 1;
            p->write(p, &value, sizeof(value));
        };

        serv.on("onWorkerStart", (void *) worker_start_fn);

        serv.start();
    });

    pid = proc.start();
    int64_t value;
    swPipe_set_timeout(&p, 10);
    p.read(&p, &value, sizeof(value));
    p.close(&p);

    swoole_event_init(SW_EVENTLOOP_WAIT_EXIT);

    AsyncClient ac(SW_SOCK_TCP);

    ac.on_connect([](AsyncClient *ac) { ac->send(SW_STRS(GREETER)); });

    ac.on_close([](AsyncClient *ac) {

    });
    ac.on_error([](AsyncClient *ac) {

    });

    ac.on_receive([](AsyncClient *ac, const char *data, size_t len) {
        ASSERT_EQ(len, GREETER_SIZE);
        ASSERT_STREQ(GREETER, data);
        ac->close();
    });

    bool retval = ac.connect(TEST_HOST, TEST_PORT);
    EXPECT_TRUE(retval);

    swoole_event_wait();

    kill(pid, SIGTERM);
    int status;
    wait(&status);
}

TEST(client, connect_refuse) {
    int ret;
    swClient cli;

    ret = swClient_create(&cli, SW_SOCK_TCP, SW_SOCK_SYNC);
    ret = cli.connect(&cli, TEST_HOST, TEST_PORT + 10001, -1, 0);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(swoole_get_last_error(), ECONNREFUSED);
    cli.close(&cli);
}

TEST(client, connect_timeout) {
    int ret;
    swClient cli;

    ret = swClient_create(&cli, SW_SOCK_TCP, SW_SOCK_SYNC);
    ret = cli.connect(&cli, "19.168.0.99", TEST_PORT + 10001, 0.2, 0);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(swoole_get_last_error(), ETIMEDOUT);
    cli.close(&cli);
}
