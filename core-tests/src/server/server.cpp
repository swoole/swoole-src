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

#include "swoole_server.h"
#include "swoole_memory.h"
#include "swoole_signal.h"
#include "swoole_lock.h"

using namespace std;
using namespace swoole;

TEST(server, schedule) {
    int ret;
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 6;
    serv.dispatch_mode = Server::DISPATCH_IDLE_WORKER;
    ret = serv.create();
    ASSERT_EQ(SW_OK, ret);

    for (uint32_t i = 0; i < serv.worker_num; i++) {
        serv.workers[i].status = SW_WORKER_BUSY;
    }

    std::set<int> _worker_id_set;

    for (uint32_t i = 0; i < serv.worker_num; i++) {
        auto worker_id = serv.schedule_worker(i * 13, nullptr);
        _worker_id_set.insert(worker_id);
    }
    ASSERT_EQ(_worker_id_set.size(), serv.worker_num);

    for (uint32_t i = 1; i < serv.worker_num - 1; i++) {
        serv.workers[i].status = SW_WORKER_IDLE;
    }

    _worker_id_set.clear();
    for (uint32_t i = 0; i < serv.worker_num; i++) {
        auto worker_id = serv.schedule_worker(i * 13, nullptr);
        _worker_id_set.insert(worker_id);
    }
    ASSERT_EQ(_worker_id_set.size(), serv.worker_num - 2);
}

static const char *packet = "hello world\n";

TEST(server, base) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;

    sw_logger()->set_level(SW_LOG_WARNING);

    swListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    mutex lock;
    lock.lock();

    ASSERT_EQ(serv.create(), SW_OK);

    std::thread t1([&]() {
        swoole_signal_block_all();

        lock.lock();

        swoole::network::SyncClient c(SW_SOCK_TCP);
        c.connect(TEST_HOST, port->port);
        c.send(packet, strlen(packet));
        char buf[1024];
        c.recv(buf, sizeof(buf));
        c.close();

        kill(getpid(), SIGTERM);
    });

    serv.onWorkerStart = [&lock](swServer *serv, int worker_id) { lock.unlock(); };

    serv.onReceive = [](swServer *serv, swRecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        return SW_OK;
    };

    serv.start();
    t1.join();
}

TEST(server, process) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 1;

    SwooleG.running = 1;

    sw_logger()->set_level(SW_LOG_WARNING);

    Mutex *lock = new Mutex(Mutex::PROCESS_SHARED);
    lock->lock();

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onStart = [&lock](swServer *serv) {
        thread t1([=]() {
            swoole_signal_block_all();

            lock->lock();

            swListenPort *port = serv->get_primary_port();

            swoole::network::SyncClient c(SW_SOCK_TCP);
            c.connect(TEST_HOST, port->port);
            c.send(packet, strlen(packet));
            char buf[1024];
            c.recv(buf, sizeof(buf));
            c.close();

            kill(serv->gs->master_pid, SIGTERM);
        });
        t1.detach();
    };

    serv.onWorkerStart = [&lock](swServer *serv, int worker_id) { lock->unlock(); };

    serv.onReceive = [](swServer *serv, swRecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        return SW_OK;
    };

    ASSERT_EQ(serv.start(), 0);

    delete lock;
}

#ifdef SW_USE_OPENSSL
TEST(server, ssl) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 1;

    SwooleG.running = 1;

    sw_logger()->set_level(SW_LOG_WARNING);

    Mutex *lock = new Mutex(Mutex::PROCESS_SHARED);
    lock->lock();

    ListenPort *port = serv.add_port((enum swSocketType)(SW_SOCK_TCP | SW_SOCK_SSL), TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    port->ssl_set_cert_file(test::get_root_path() + "/tests/include/ssl_certs/server.crt");
    port->ssl_set_key_file(test::get_root_path() + "/tests/include/ssl_certs/server.key");
    port->ssl_init();

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onStart = [&lock](Server *serv) {
        thread t1([=]() {
            swoole_signal_block_all();

            lock->lock();

            ListenPort *port = serv->get_primary_port();

            EXPECT_EQ(port->ssl, 1);
            EXPECT_EQ(swoole_ssl_is_thread_safety(), true);

            swoole::network::SyncClient c(SW_SOCK_TCP);
            c.connect(TEST_HOST, port->port);
            c.enable_ssl_encrypt();
            c.send(packet, strlen(packet));
            char buf[1024];
            c.recv(buf, sizeof(buf));
            c.close();

            kill(serv->gs->master_pid, SIGTERM);
        });
        t1.detach();
    };

    serv.onWorkerStart = [&lock](Server *serv, int worker_id) { lock->unlock(); };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        return SW_OK;
    };

    ASSERT_EQ(serv.start(), 0);

    delete lock;
}

TEST(server, dtls) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;

    SwooleG.running = 1;

    sw_logger()->set_level(SW_LOG_WARNING);

    Mutex *lock = new Mutex(Mutex::PROCESS_SHARED);
    lock->lock();

    ListenPort *port = serv.add_port((enum swSocketType)(SW_SOCK_UDP | SW_SOCK_SSL), TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    port->ssl_set_cert_file(test::get_root_path() + "/tests/include/ssl_certs/server.crt");
    port->ssl_set_key_file(test::get_root_path() + "/tests/include/ssl_certs/server.key");
    port->ssl_init();

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onStart = [&lock](Server *serv) {
        thread t1([=]() {
            swoole_signal_block_all();

            lock->lock();

            ListenPort *port = serv->get_primary_port();

            EXPECT_EQ(port->ssl, 1);

            swoole::network::SyncClient c(SW_SOCK_UDP);
            c.connect(TEST_HOST, port->port);
            c.enable_ssl_encrypt();
            c.send(packet, strlen(packet));
            char buf[1024];
            c.recv(buf, sizeof(buf));
            c.close();

            kill(serv->gs->master_pid, SIGTERM);
        });
        t1.detach();
    };

    serv.onWorkerStart = [&lock](Server *serv, int worker_id) { lock->unlock(); };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        return SW_OK;
    };

    ASSERT_EQ(serv.start(), 0);

    delete lock;
}
#endif

TEST(server, task_worker) {
    Server serv;
    serv.worker_num = 1;
    serv.task_worker_num = 1;

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    serv.onTask = [](swServer *serv, swEventData *task) -> int {
        EXPECT_EQ(string(task->data, task->info.len), string(packet));
        serv->gs->task_workers.running = 0;
        return 0;
    };

    ASSERT_EQ(serv.create(), SW_OK);
    ASSERT_EQ(serv.create_task_workers(), SW_OK);

    thread t1([&serv]() {
        serv.gs->task_workers.running = 1;
        serv.gs->task_workers.main_loop(&serv.gs->task_workers, &serv.gs->task_workers.workers[0]);
    });

    usleep(10000);

    EventData buf;
    memset(&buf.info, 0, sizeof(buf.info));

    buf.info.ext_flags = SW_TASK_NOREPLY;
    buf.info.len = strlen(packet);
    memcpy(buf.data, packet, strlen(packet));

    int _dst_worker_id = 0;

    ASSERT_GE(serv.gs->task_workers.dispatch(&buf, &_dst_worker_id), 0);

    t1.join();
    serv.gs->task_workers.destroy();
}

TEST(server, max_connection) {
    Server serv;

    serv.set_max_connection(0);
    ASSERT_EQ(serv.get_max_connection(), SW_MIN(SW_MAX_CONNECTION, SwooleG.max_sockets));

    serv.set_max_connection(SwooleG.max_sockets + 13);
    ASSERT_EQ(serv.get_max_connection(), SwooleG.max_sockets);

    serv.set_max_connection(SwooleG.max_sockets - 13);
    ASSERT_EQ(serv.get_max_connection(), SwooleG.max_sockets - 13);

    uint32_t last_value = serv.get_max_connection();

    serv.create();

    serv.set_max_connection(100);
    ASSERT_EQ(serv.get_max_connection(), last_value);
}

TEST(server, min_connection) {
    Server serv;

    serv.task_worker_num = 14;
    serv.worker_num = 5;

    serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);

    serv.set_max_connection(15);
    serv.create();
    ASSERT_EQ(serv.get_max_connection(), SwooleG.max_sockets);
}

TEST(server, worker_num) {
    Server serv;

    serv.worker_num = SW_CPU_NUM * SW_MAX_WORKER_NCPU + 99;
    serv.task_worker_num = SW_CPU_NUM * SW_MAX_WORKER_NCPU + 99;
    serv.create();

    ASSERT_EQ(serv.worker_num, SW_CPU_NUM * SW_MAX_WORKER_NCPU);
    ASSERT_EQ(serv.task_worker_num, SW_CPU_NUM * SW_MAX_WORKER_NCPU);
}

TEST(server, reactor_num_base) {
    Server serv(Server::MODE_BASE);
    serv.reactor_num = SW_CPU_NUM * SW_MAX_THREAD_NCPU + 99;
    serv.create();

    ASSERT_EQ(serv.reactor_num, serv.worker_num);
}

TEST(server, reactor_num_large) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = SW_CPU_NUM * SW_MAX_WORKER_NCPU;
    serv.reactor_num = SW_CPU_NUM * SW_MAX_THREAD_NCPU + 99;
    serv.create();

    ASSERT_EQ(serv.reactor_num, SW_CPU_NUM * SW_MAX_THREAD_NCPU);
}

TEST(server, reactor_num_large2) {
    Server serv(Server::MODE_PROCESS);
    serv.reactor_num = SW_CPU_NUM * SW_MAX_THREAD_NCPU + 99;
    serv.create();

    ASSERT_EQ(serv.reactor_num, serv.worker_num);
}

TEST(server, reactor_num_zero) {
    Server serv;
    serv.reactor_num = 0;
    serv.create();

    ASSERT_EQ(serv.reactor_num, SW_CPU_NUM);
}

void test_command(enum Server::Mode _mode) {
    Server serv(_mode);
    serv.worker_num = 4;
    serv.task_worker_num = 4;
    serv.reactor_num = 2;

    SwooleG.running = 1;

    sw_logger()->set_level(SW_LOG_WARNING);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    ASSERT_EQ(serv.create(), SW_OK);

    serv.add_command("test", Server::Command::ALL_PROCESS, [](Server *, const std::string &msg) -> std::string {
        return std::string("json result, ") + msg;
    });

    serv.onStart = [](Server *serv) {
        static Server::Command::Callback fn = [&](Server *serv, const std::string &msg) {
            usleep(50000);
            if (msg == "json result, hello world [0]") {
                if (serv->is_base_mode()) {
                    goto _send_to_event_worker;
                } else {
                    serv->command(1, Server::Command::REACTOR_THREAD, "test", "hello world [1]", fn);
                }
            } else if (msg == "json result, hello world [1]") {
            _send_to_event_worker:
                serv->command(1, Server::Command::EVENT_WORKER, "test", "hello world [2]", fn);
            } else if (msg == "json result, hello world [2]") {
                serv->command(1, Server::Command::TASK_WORKER, "test", "hello world [3]", fn);
            } else if (msg == "json result, hello world [3]") {
                serv->command(1, Server::Command::MANAGER, "test", "hello world [4]", fn);
            } else if (msg == "json result, hello world [4]") {
                swoole_timer_after(50, [serv](Timer *, TimerNode *) { serv->shutdown(); });
            } else {
                ASSERT_TRUE(0);
            }
        };
        serv->command(1, Server::Command::MASTER, "test", "hello world [0]", fn);
    };

    serv.onWorkerStart = [](Server *serv, int worker_id) {

    };

    serv.onTask = [](Server *, EventData *) -> int { return SW_OK; };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        return SW_OK;
    };

    ASSERT_EQ(serv.start(), 0);
}

TEST(server, command_1) {
    test_command(Server::MODE_PROCESS);
}

TEST(server, command_2) {
    test_command(Server::MODE_BASE);
}
