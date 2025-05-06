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
#include "swoole_util.h"

using namespace std;
using namespace swoole;

int beforeReloadPid = 0;

TEST(server, schedule) {
    int ret;
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 6;
    serv.dispatch_mode = Server::DISPATCH_IDLE_WORKER;
    serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ret = serv.create();
    ASSERT_EQ(SW_OK, ret);

    for (uint32_t i = 0; i < serv.worker_num; i++) {
        serv.workers[i].set_status_to_busy();
    }

    std::set<int> _worker_id_set;

    for (uint32_t i = 0; i < serv.worker_num; i++) {
        auto worker_id = serv.schedule_worker(i * 13, nullptr);
        _worker_id_set.insert(worker_id);
    }
    ASSERT_EQ(_worker_id_set.size(), serv.worker_num);

    for (uint32_t i = 1; i < serv.worker_num - 1; i++) {
        serv.workers[i].set_status_to_idle();
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

    swoole_set_log_level(SW_LOG_WARNING);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    mutex lock;
    lock.lock();

    ASSERT_EQ(serv.create(), SW_OK);

    std::thread t1([&]() {
        swoole_signal_block_all();

        lock.lock();

        network::SyncClient c(SW_SOCK_TCP);
        c.connect(TEST_HOST, port->port);
        c.send(packet, strlen(packet));
        char buf[1024];
        c.recv(buf, sizeof(buf));
        c.close();

        kill(getpid(), SIGTERM);
    });

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock.unlock(); };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        EXPECT_EQ(serv->get_connection_num(), 1);
        EXPECT_EQ(serv->get_primary_port()->get_connection_num(), 1);

        return SW_OK;
    };

    serv.start();
    t1.join();
}

TEST(server, process) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 1;
    swoole_set_log_level(SW_LOG_WARNING);

    Mutex *lock = new Mutex(Mutex::PROCESS_SHARED);
    lock->lock();

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onStart = [&lock](Server *serv) {
        thread t1([=]() {
            swoole_signal_block_all();

            lock->lock();

            ListenPort *port = serv->get_primary_port();

            network::SyncClient c(SW_SOCK_TCP);
            c.connect(TEST_HOST, port->port);
            c.send(packet, strlen(packet));
            char buf[1024];
            c.recv(buf, sizeof(buf));
            c.close();

            kill(serv->gs->master_pid, SIGTERM);
        });
        t1.detach();
    };

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock->unlock(); };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        EXPECT_EQ(serv->get_connection_num(), 1);
        EXPECT_EQ(serv->get_primary_port()->get_connection_num(), 1);

        return SW_OK;
    };

    ASSERT_EQ(serv.start(), 0);

    delete lock;
}

#ifdef SW_THREAD
TEST(server, thread) {
    Server serv(Server::MODE_THREAD);
    serv.worker_num = 2;

    swoole_set_log_level(SW_LOG_WARNING);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    mutex lock;
    lock.lock();

    ASSERT_EQ(serv.create(), SW_OK);

    std::thread t1([&]() {
        swoole_signal_block_all();

        lock.lock();

        network::SyncClient c(SW_SOCK_TCP);
        c.connect(TEST_HOST, port->port);
        c.send(packet, strlen(packet));
        char buf[1024];
        c.recv(buf, sizeof(buf));
        c.close();

        serv.shutdown();
    });

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock.unlock(); };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        EXPECT_EQ(serv->get_connection_num(), 1);
        EXPECT_EQ(serv->get_primary_port()->get_connection_num(), 1);

        return SW_OK;
    };

    serv.start();
    t1.join();
}

TEST(server, task_thread) {
    Server serv(Server::MODE_THREAD);
    serv.worker_num = 2;
    serv.task_worker_num = 2;

    swoole_set_log_level(SW_LOG_WARNING);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    mutex lock;
    lock.lock();

    ASSERT_EQ(serv.create(), SW_OK);

    std::thread t1([&]() {
        swoole_signal_block_all();

        lock.lock();

        network::SyncClient c(SW_SOCK_TCP);
        c.connect(TEST_HOST, port->port);
        c.send(packet, strlen(packet));
        char buf[1024];
        c.recv(buf, sizeof(buf));
        c.close();

        serv.shutdown();
    });

    std::atomic<int> count(0);

    serv.onWorkerStart = [&lock, &count](Server *serv, Worker *worker) {
        count++;
        if (count.load() == 4) {
            lock.unlock();
        }
    };

    serv.onFinish = [](Server *serv, EventData *task) -> int {
        SessionId client_fd;
        memcpy(&client_fd, task->data, sizeof(client_fd));
        string resp = string("Server: ") + string(packet);
        serv->send(client_fd, resp.c_str(), resp.length());
        return 0;
    };

    serv.onTask = [](Server *serv, EventData *task) -> int {
        EXPECT_TRUE(serv->finish(task->data, task->info.len, 0, task));
        return 0;
    };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        EventData msg;
        SessionId client_fd = req->info.fd;
        Server::task_pack(&msg, &client_fd, sizeof(client_fd));
        msg.info.ext_flags |= SW_TASK_NONBLOCK;

        int dst_worker_id = -1;
        EXPECT_TRUE(serv->task(&msg, &dst_worker_id));

        return SW_OK;
    };

    serv.start();
    t1.join();
}

TEST(server, reload_thread) {
    Server serv(Server::MODE_THREAD);
    serv.worker_num = 2;
    serv.task_worker_num = 2;

    swoole_set_log_level(SW_LOG_WARNING);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    Worker user_worker{};

    serv.add_worker(&user_worker);

    mutex lock;
    lock.lock();

    ASSERT_EQ(serv.create(), SW_OK);

    std::thread t1([&]() {
        swoole_signal_block_all();
        lock.lock();
        serv.reload(true);
        sleep(1);
        serv.shutdown();
    });

    std::atomic<int> count(0);

    serv.onUserWorkerStart = [&lock, &count](Server *serv, Worker *worker) {
        while (serv->running) {
            usleep(100000);
        }
    };

    serv.onWorkerStart = [&lock, &count](Server *serv, Worker *worker) {
        count++;
        if (count.load() == 4) {
            lock.unlock();
        }
    };

    serv.onTask = [](Server *serv, EventData *task) -> int { return 0; };

    serv.onReceive = [](Server *serv, RecvData *req) -> int { return SW_OK; };

    serv.start();
    t1.join();
}

TEST(server, reload_thread_2) {
    Server serv(Server::MODE_THREAD);
    serv.worker_num = 2;
    serv.task_worker_num = 2;

    std::unordered_map<std::string, bool> flags;
    swoole_set_log_level(SW_LOG_WARNING);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    Worker user_worker{};

    serv.add_worker(&user_worker);

    mutex lock;
    lock.lock();

    ASSERT_EQ(serv.create(), SW_OK);

    std::atomic<int> count(0);

    serv.onUserWorkerStart = [&lock, &count](Server *serv, Worker *worker) {
        while (serv->running) {
            usleep(100000);
        }
    };

    serv.onWorkerStart = [&lock, &count](Server *serv, Worker *worker) {
        count++;
        if (count.load() == 4) {
            lock.unlock();
        }
    };

    serv.onTask = [](Server *serv, EventData *task) -> int { return 0; };

    serv.onReceive = [](Server *serv, RecvData *req) -> int { return SW_OK; };

    serv.onBeforeReload = [&flags](Server *serv) { flags["onBeforeReload"] = true; };

    serv.onAfterReload = [&flags](Server *serv) {
        flags["onAfterReload"] = true;
        swoole_timer_after(500, [serv, &flags](auto r1, auto r2) {
            flags["shutdown"] = true;
            serv->shutdown();
        });
    };

    serv.onManagerStart = [&flags](Server *serv) {
        swoole_timer_after(500, [serv, &flags](auto r1, auto r2) {
            flags["reload"] = true;
            serv->reload(true);
        });
    };

    serv.onManagerStop = [&flags](Server *serv) { flags["onManagerStop"] = true; };

    serv.start();

    ASSERT_TRUE(flags["onBeforeReload"]);
    ASSERT_TRUE(flags["onAfterReload"]);
    ASSERT_TRUE(flags["onManagerStop"]);
    ASSERT_TRUE(flags["reload"]);
    ASSERT_TRUE(flags["shutdown"]);
}
#endif

TEST(server, reload_all_workers) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    serv.task_worker_num = 2;
    serv.max_wait_time = 1;
    serv.task_enable_coroutine = 1;

    swoole_set_log_level(SW_LOG_WARNING);

    serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    serv.onTask = [](Server *serv, EventData *task) -> int { return 0; };
    serv.onReceive = [](Server *serv, RecvData *data) -> int { return 0; };

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onWorkerStart = [&](Server *serv, Worker *worker) {
        std::string filename = "/tmp/worker_1.pid";
        if (worker->id == 1) {
            if (access(filename.c_str(), R_OK) == -1) {
                ofstream file(filename);
                file << getpid();
                file.close();
                kill(serv->gs->manager_pid, SIGUSR2);
                sleep(1);
                kill(serv->gs->manager_pid, SIGUSR1);
            } else {
                char buf[10] = {0};
                ifstream file(filename.c_str());
                file >> buf;
                file.close();

                int oldPid = 0;
                stringstream stringPid(buf);
                stringPid >> oldPid;

                EXPECT_TRUE(oldPid != getpid());

                sleep(1);
                remove(filename.c_str());
                kill(serv->gs->master_pid, SIGTERM);
            }
        }
    };

    ASSERT_EQ(serv.start(), 0);
}

TEST(server, reload_all_workers2) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    serv.task_worker_num = 2;
    serv.max_wait_time = 1;
    swoole_set_log_level(SW_LOG_WARNING);

    serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    serv.onTask = [](Server *serv, EventData *task) -> int { return 0; };
    serv.onReceive = [](Server *serv, RecvData *data) -> int { return 0; };

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onWorkerStart = [&](Server *serv, Worker *worker) {
        std::string filename = "/tmp/worker_2.pid";
        if (worker->id == 1) {
            if (access(filename.c_str(), R_OK) == -1) {
                ofstream file(filename);
                file << getpid();
                file.close();
                kill(serv->gs->master_pid, SIGUSR2);
                sleep(1);
                kill(serv->gs->master_pid, SIGUSR1);
            } else {
                char buf[10] = {0};
                ifstream file(filename.c_str());
                file >> buf;
                file.close();

                int oldPid = 0;
                stringstream stringPid(buf);
                stringPid >> oldPid;

                EXPECT_TRUE(oldPid != getpid());

                sleep(1);
                remove(filename.c_str());
                kill(serv->gs->master_pid, SIGTERM);
            }
        }
    };

    ASSERT_EQ(serv.start(), 0);
}

TEST(server, kill_user_workers) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;
    serv.task_worker_num = 2;
    serv.max_wait_time = 1;
    swoole_set_log_level(SW_LOG_WARNING);

    Worker *worker1 = new Worker();
    Worker *worker2 = new Worker();
    ASSERT_EQ(serv.add_worker(worker1), worker1->id);
    ASSERT_EQ(serv.add_worker(worker2), worker2->id);
    ASSERT_TRUE(serv.add_port(SW_SOCK_TCP, TEST_HOST, 0));

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onUserWorkerStart = [&](Server *serv, Worker *worker) { EXPECT_GT(worker->id, 0); };

    serv.onTask = [](Server *serv, EventData *task) -> int {
        while (1) {
        }
    };

    serv.onWorkerStart = [&](Server *serv, Worker *worker) {
        if (worker->id == 1) {
            sleep(1);
            kill(serv->get_manager_pid(), SIGTERM);
        }
    };

    serv.onReceive = [](Server *serv, RecvData *data) -> int { return 0; };

    ASSERT_EQ(serv.start(), 0);
}

TEST(server, kill_user_workers1) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 1;
    serv.task_worker_num = 2;
    serv.max_wait_time = 1;
    swoole_set_log_level(SW_LOG_WARNING);

    Worker *worker1 = new Worker();
    Worker *worker2 = new Worker();
    ASSERT_EQ(serv.add_worker(worker1), worker1->id);
    ASSERT_EQ(serv.add_worker(worker2), worker2->id);

    ASSERT_TRUE(serv.add_port(SW_SOCK_TCP, TEST_HOST, 0));

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onUserWorkerStart = [&](Server *serv, Worker *worker) { EXPECT_GT(worker->id, 0); };

    serv.onTask = [](Server *serv, EventData *task) -> int {
        while (1) {
        }
    };

    serv.onWorkerStart = [&](Server *serv, Worker *worker) {
        if (worker->id == 1) {
            sleep(1);
            kill(serv->gs->master_pid, SIGTERM);
        }
    };

    serv.onReceive = [](Server *serv, RecvData *data) -> int { return 0; };

    ASSERT_EQ(serv.start(), 0);
}

#ifdef SW_USE_OPENSSL
TEST(server, ssl) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 1;
    swoole_set_log_level(SW_LOG_WARNING);

    Mutex *lock = new Mutex(Mutex::PROCESS_SHARED);
    lock->lock();

    ListenPort *port = serv.add_port((enum swSocketType)(SW_SOCK_TCP | SW_SOCK_SSL), TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    port->set_ssl_cert_file(test::get_ssl_dir() + "/server.crt");
    port->set_ssl_key_file(test::get_ssl_dir() + "/server.key");
    port->ssl_init();

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onStart = [&lock](Server *serv) {
        thread t1([=]() {
            swoole_signal_block_all();

            lock->lock();

            ListenPort *port = serv->get_primary_port();

            EXPECT_EQ(port->ssl, 1);
            EXPECT_EQ(swoole_ssl_is_thread_safety(), true);

            network::SyncClient c(SW_SOCK_TCP);
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

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock->unlock(); };

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
    swoole_set_log_level(SW_LOG_WARNING);

    Mutex *lock = new Mutex(Mutex::PROCESS_SHARED);
    lock->lock();

    ListenPort *port = serv.add_port((enum swSocketType)(SW_SOCK_UDP | SW_SOCK_SSL), TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    port->set_ssl_cert_file(test::get_ssl_dir() + "/server.crt");
    port->set_ssl_key_file(test::get_ssl_dir() + "/server.key");
    port->ssl_init();

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onStart = [&lock](Server *serv) {
        thread t1([=]() {
            swoole_signal_block_all();

            lock->lock();

            ListenPort *port = serv->get_primary_port();

            EXPECT_EQ(port->ssl, 1);

            network::SyncClient c(SW_SOCK_UDP);
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

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock->unlock(); };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        return SW_OK;
    };

    ASSERT_EQ(serv.start(), 0);

    delete lock;
}

TEST(server, dtls2) {
    Server *server = new Server(Server::MODE_PROCESS);
    server->worker_num = 2;
    server->single_thread = false;
    ListenPort *port = server->add_port((enum swSocketType)(SW_SOCK_UDP | SW_SOCK_SSL), TEST_HOST, 0);

    port->set_ssl_cert_file(test::get_ssl_dir() + "/server.crt");
    port->set_ssl_key_file(test::get_ssl_dir() + "/server.key");
    port->ssl_init();

    server->create();
    server->onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        return SW_OK;
    };

    pid_t pid = swoole_fork(0);

    if (pid > 0) {
        server->start();
    }

    if (pid == 0) {
        sleep(1);
        auto port = server->get_primary_port();

        network::SyncClient c(SW_SOCK_UDP);
        c.connect(TEST_HOST, port->port);
        c.enable_ssl_encrypt();
        c.send(packet, strlen(packet));
        char buf[1024];
        c.recv(buf, sizeof(buf));
        c.close();

        kill(server->get_master_pid(), SIGTERM);
        exit(0);
    }
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

    serv.onTask = [](Server *serv, EventData *task) -> int {
        EXPECT_EQ(serv->get_tasking_num(), 1);
        EXPECT_EQ(string(task->data, task->info.len), string(packet));
        serv->gs->task_workers.running = 0;
        serv->gs->task_count++;
        serv->gs->tasking_num--;
        return 0;
    };

    ASSERT_EQ(serv.create(), SW_OK);

    thread t1([&serv]() {
        serv.gs->task_workers.running = 1;
        serv.gs->task_workers.main_loop(&serv.gs->task_workers, &serv.gs->task_workers.workers[0]);
        EXPECT_EQ(serv.get_tasking_num(), 0);
        serv.gs->tasking_num--;
        EXPECT_EQ(serv.get_tasking_num(), 0);
        EXPECT_EQ(serv.get_idle_task_worker_num(), serv.task_worker_num);
    });

    usleep(10000);

    EventData buf;
    memset(&buf.info, 0, sizeof(buf.info));

    buf.info.ext_flags = SW_TASK_NOREPLY;
    buf.info.len = strlen(packet);
    memcpy(buf.data, packet, strlen(packet));

    int _dst_worker_id = 0;

    ASSERT_TRUE(serv.task(&buf, &_dst_worker_id));
    ASSERT_EQ(serv.gs->task_count, 1);

    t1.join();
    serv.gs->task_workers.destroy();

    ASSERT_EQ(serv.gs->task_count, 2);
}

// PHP_METHOD(swoole_server, task)
TEST(server, task_worker2) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    serv.task_worker_num = 3;
    serv.task_enable_coroutine = 1;

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    serv.onReceive = [](Server *server, RecvData *req) -> int { return SW_OK; };

    serv.onTask = [](Server *serv, EventData *task) -> int {
        EXPECT_EQ(string(task->data, task->info.len), string(packet));
        EXPECT_TRUE(serv->finish(task->data, task->info.len, 0, task));
        return 0;
    };

    serv.onFinish = [](Server *serv, EventData *task) -> int {
        EXPECT_EQ(string(task->data, task->info.len), string(packet));
        return 0;
    };

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onWorkerStart = [&](Server *serv, Worker *worker) {
        if (worker->id == 1) {
            int _dst_worker_id = 0;

            EventData buf{};
            memset(&buf.info, 0, sizeof(buf.info));
            buf.info.len = strlen(packet);
            memcpy(buf.data, packet, strlen(packet));
            buf.info.reactor_id = worker->id;
            buf.info.ext_flags |= (SW_TASK_NONBLOCK | SW_TASK_CALLBACK);
            ASSERT_EQ(serv->gs->task_workers.dispatch(&buf, &_dst_worker_id), SW_OK);
            sleep(1);
            kill(serv->gs->master_pid, SIGTERM);
        }
    };

    ASSERT_EQ(serv.start(), 0);
}

// static PHP_METHOD(swoole_server, taskCo)
TEST(server, task_worker3) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    serv.task_worker_num = 3;
    serv.task_enable_coroutine = 1;

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    serv.onReceive = [](Server *server, RecvData *req) -> int { return SW_OK; };

    serv.onTask = [](Server *serv, EventData *task) -> int {
        EXPECT_EQ(string(task->data, task->info.len), string(packet));
        EXPECT_TRUE(serv->finish(task->data, task->info.len, 0, task));
        return 0;
    };

    serv.onFinish = [](Server *serv, EventData *task) -> int {
        EXPECT_EQ(string(task->data, task->info.len), string(packet));
        return 0;
    };

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onWorkerStart = [&](Server *serv, Worker *worker) {
        if (worker->id == 1) {
            int _dst_worker_id = 0;

            EventData buf{};
            memset(&buf.info, 0, sizeof(buf.info));
            buf.info.len = strlen(packet);
            memcpy(buf.data, packet, strlen(packet));
            buf.info.ext_flags |= (SW_TASK_NONBLOCK | SW_TASK_COROUTINE);
            buf.info.reactor_id = worker->id;
            serv->gs->task_workers.dispatch(&buf, &_dst_worker_id);
            sleep(1);
            kill(serv->gs->master_pid, SIGTERM);
        }
    };

    ASSERT_EQ(serv.start(), 0);
}

// static PHP_METHOD(swoole_server, taskwait)
TEST(server, task_worker4) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    serv.task_worker_num = 3;
    serv.task_enable_coroutine = 1;

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    serv.onReceive = [](Server *server, RecvData *req) -> int { return SW_OK; };

    serv.onTask = [](Server *serv, EventData *task) -> int {
        EXPECT_EQ(string(task->data, task->info.len), string(packet));
        EXPECT_TRUE(serv->finish(task->data, task->info.len, 0, task));
        return 0;
    };

    serv.onFinish = [](Server *serv, EventData *task) -> int {
        EXPECT_EQ(string(task->data, task->info.len), string(packet));
        return 0;
    };

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onWorkerStart = [&](Server *serv, Worker *worker) {
        if (worker->id == 1) {
            int _dst_worker_id = 0;

            EventData buf{};
            memset(&buf.info, 0, sizeof(buf.info));
            buf.info.len = strlen(packet);
            memcpy(buf.data, packet, strlen(packet));
            buf.info.ext_flags |= (SW_TASK_NONBLOCK | SW_TASK_COROUTINE);
            buf.info.reactor_id = worker->id;
            serv->gs->task_workers.dispatch(&buf, &_dst_worker_id);
            sleep(1);

            EventData *task_result = serv->get_task_result();
            sw_memset_zero(task_result, sizeof(*task_result));
            memset(&buf.info, 0, sizeof(buf.info));
            buf.info.len = strlen(packet);
            memcpy(buf.data, packet, strlen(packet));
            buf.info.reactor_id = worker->id;
            sw_atomic_fetch_add(&serv->gs->tasking_num, 1);
            serv->gs->task_workers.dispatch(&buf, &_dst_worker_id);
            sw_atomic_fetch_add(&serv->gs->tasking_num, 0);
            kill(serv->gs->master_pid, SIGTERM);
        }
    };

    ASSERT_EQ(serv.start(), 0);
}

// static PHP_METHOD(swoole_server, taskWaitMulti)
TEST(server, task_worker5) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    serv.task_worker_num = 3;
    serv.task_enable_coroutine = 1;

    char data[SW_IPC_MAX_SIZE * 2] = {};
    swoole_random_string(data, SW_IPC_MAX_SIZE * 2);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    serv.onReceive = [](Server *server, RecvData *req) -> int { return SW_OK; };

    serv.onTask = [&data](Server *serv, EventData *task) -> int {
        PacketTask *pkg = (PacketTask *) task->data;
        ifstream ifs;
        ifs.open(pkg->tmpfile);
        char resp[SW_IPC_MAX_SIZE * 2] = {0};
        ifs >> resp;
        ifs.close();

        EXPECT_EQ(string(resp), string(data));
        EXPECT_TRUE(serv->finish(resp, SW_IPC_MAX_SIZE * 2, 0, task));
        return 0;
    };

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onWorkerStart = [&data](Server *serv, Worker *worker) {
        if (worker->id == 1) {
            int _dst_worker_id = 0;

            EventData *task_result = &(serv->task_results[worker->id]);
            sw_memset_zero(task_result, sizeof(*task_result));

            File fp = make_tmpfile();
            std::string file_path = fp.get_path();
            fp.close();
            int *finish_count = (int *) task_result->data;
            *finish_count = 0;

            swoole_strlcpy(task_result->data + 4, file_path.c_str(), SW_TASK_TMP_PATH_SIZE);

            EventData buf{};
            memset(&buf.info, 0, sizeof(buf.info));
            Server::task_pack(&buf, data, SW_IPC_MAX_SIZE * 2);
            buf.info.ext_flags |= SW_TASK_WAITALL;
            buf.info.reactor_id = worker->id;
            serv->gs->task_workers.dispatch(&buf, &_dst_worker_id);
            sleep(3);

            ifstream ifs;
            ifs.open(task_result->data + 4);
            char recv[sizeof(EventData)] = {0};
            ifs >> recv;
            ifs.close();

            EventData *task = (EventData *) recv;
            PacketTask *pkg = (PacketTask *) task->data;
            ifs.open(pkg->tmpfile);
            char resp[SW_IPC_MAX_SIZE * 2] = {0};
            ifs >> resp;
            ifs.close();
            EXPECT_EQ(string(resp), string(data));

            kill(serv->gs->master_pid, SIGTERM);
        }
    };

    ASSERT_EQ(serv.start(), 0);
}

TEST(server, task_sync) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    serv.task_worker_num = 2;

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    serv.onReceive = [](Server *server, RecvData *req) -> int { return SW_OK; };

    serv.onTask = [](Server *serv, EventData *task) -> int {
        EXPECT_EQ(string(task->data, task->info.len), string(packet));
        EXPECT_TRUE(serv->finish(task->data, task->info.len, 0, task));
        return 0;
    };

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onWorkerStart = [&](Server *serv, Worker *worker) {
        if (worker->id == 1) {
            int _dst_worker_id = -1;
            EventData buf{};
            Server::task_pack(&buf, packet, strlen(packet));
            EXPECT_TRUE(serv->task_sync(&buf, &_dst_worker_id, 0.5));
            auto task_result = serv->get_task_result();
            EXPECT_EQ(string(task_result->data, task_result->info.len), string(packet));
            kill(serv->gs->master_pid, SIGTERM);
        }
    };

    ASSERT_EQ(serv.start(), 0);
}

static void test_task_ipc(Server &serv) {
    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    serv.onReceive = [](Server *server, RecvData *req) -> int { return SW_OK; };

    serv.onTask = [](Server *serv, EventData *task) -> int {
        EXPECT_EQ(string(task->data, task->info.len), string(packet));
        EXPECT_TRUE(serv->finish(task->data, task->info.len, 0, task));
        return 0;
    };

    serv.onFinish = [](Server *serv, EventData *task) -> int {
        EXPECT_EQ(string(task->data, task->info.len), string(packet));
        serv->shutdown();
        return 0;
    };

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onWorkerStart = [](Server *serv, Worker *worker) {
        if (worker->id == 1) {
            int _dst_worker_id = -1;
            EventData buf{};
            Server::task_pack(&buf, packet, strlen(packet));
            buf.info.ext_flags |= (SW_TASK_NONBLOCK | SW_TASK_CALLBACK);
            EXPECT_TRUE(serv->task(&buf, &_dst_worker_id));
        }
    };

    ASSERT_EQ(serv.start(), 0);
}

TEST(server, task_ipc_queue_1) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    serv.task_worker_num = 2;
    serv.task_ipc_mode = Server::TASK_IPC_MSGQUEUE;

    test_task_ipc(serv);
}

TEST(server, task_ipc_queue_2) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    serv.task_worker_num = 2;
    serv.task_ipc_mode = Server::TASK_IPC_PREEMPTIVE;

    test_task_ipc(serv);
}

TEST(server, task_ipc_queue_3) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    serv.task_worker_num = 2;
    serv.task_ipc_mode = Server::TASK_IPC_STREAM;

    test_task_ipc(serv);
}

TEST(server, task_ipc_queue_4) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 2;
    serv.task_worker_num = 2;
    serv.task_ipc_mode = Server::TASK_IPC_MSGQUEUE;

    test_task_ipc(serv);
}

TEST(server, task_ipc_queue_5) {
    Server serv(Server::MODE_THREAD);
    serv.worker_num = 2;
    serv.task_worker_num = 2;
    serv.task_ipc_mode = Server::TASK_IPC_MSGQUEUE;

    test_task_ipc(serv);
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

    ASSERT_TRUE(serv.add_port(SW_SOCK_TCP, TEST_HOST, 0));

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

    ASSERT_TRUE(serv.add_port(SW_SOCK_TCP, TEST_HOST, 0));

    serv.create();

    ASSERT_EQ(serv.worker_num, SW_CPU_NUM * SW_MAX_WORKER_NCPU);
    ASSERT_EQ(serv.task_worker_num, SW_CPU_NUM * SW_MAX_WORKER_NCPU);
}

TEST(server, reactor_num_base) {
    Server serv(Server::MODE_BASE);
    serv.reactor_num = SW_CPU_NUM * SW_MAX_THREAD_NCPU + 99;
    ASSERT_TRUE(serv.add_port(SW_SOCK_TCP, TEST_HOST, 0));
    serv.create();

    ASSERT_EQ(serv.reactor_num, serv.worker_num);
}

TEST(server, reactor_num_large) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = SW_CPU_NUM * SW_MAX_WORKER_NCPU;
    serv.reactor_num = SW_CPU_NUM * SW_MAX_THREAD_NCPU + 99;
    ASSERT_TRUE(serv.add_port(SW_SOCK_TCP, TEST_HOST, 0));
    serv.create();

    ASSERT_EQ(serv.reactor_num, SW_CPU_NUM * SW_MAX_THREAD_NCPU);
}

TEST(server, reactor_num_large2) {
    Server serv(Server::MODE_PROCESS);
    serv.reactor_num = SW_CPU_NUM * SW_MAX_THREAD_NCPU + 99;
    ASSERT_TRUE(serv.add_port(SW_SOCK_TCP, TEST_HOST, 0));
    serv.create();

    ASSERT_EQ(serv.reactor_num, serv.worker_num);
}

TEST(server, reactor_num_zero) {
    Server serv;
    serv.reactor_num = 0;
    ASSERT_TRUE(serv.add_port(SW_SOCK_TCP, TEST_HOST, 0));
    serv.create();

    ASSERT_EQ(serv.reactor_num, SW_CPU_NUM);
}

void test_command(enum Server::Mode _mode) {
    Server serv(_mode);
    serv.worker_num = 4;
    serv.task_worker_num = 4;
    serv.reactor_num = 2;
    swoole_set_log_level(SW_LOG_WARNING);

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

    serv.onWorkerStart = [](Server *serv, Worker *worker) {

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

TEST(server, sendwait) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;
    swoole_set_log_level(SW_LOG_WARNING);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    mutex lock;
    lock.lock();

    ASSERT_EQ(serv.create(), SW_OK);

    std::thread t1([&]() {
        swoole_signal_block_all();

        lock.lock();

        network::SyncClient c(SW_SOCK_TCP);
        c.connect(TEST_HOST, port->port);
        c.send(packet, strlen(packet));
        char buf[1024];
        c.recv(buf, sizeof(buf));
        c.close();

        kill(getpid(), SIGTERM);
    });

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock.unlock(); };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->sendwait(req->info.fd, resp.c_str(), resp.length());

        return SW_OK;
    };

    serv.start();
    t1.join();
}

TEST(server, system) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;
    swoole_set_log_level(SW_LOG_WARNING);

    mutex lock;
    lock.lock();

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int svr_port = swoole::test::get_random_port();
    struct sockaddr_in serv_addr;
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_addr.s_addr = inet_addr(TEST_HOST);
    serv_addr.sin_port = htons(svr_port);
    serv_addr.sin_family = AF_INET;
    bind(fd, (struct sockaddr *) &serv_addr, sizeof(struct sockaddr));
    listen(fd, 1024);

    setenv("LISTEN_FDS_START", to_string(fd).c_str(), 1);
    setenv("LISTEN_FDS", "1", 1);
    setenv("LISTEN_PID", to_string(getpid()).c_str(), 1);

    EXPECT_GT(serv.add_systemd_socket(), 0);
    ASSERT_EQ(serv.create(), SW_OK);

    std::thread t1([&]() {
        swoole_signal_block_all();
        lock.lock();

        network::SyncClient c(SW_SOCK_TCP);
        c.connect(TEST_HOST, svr_port);
        c.send(packet, strlen(packet));
        char buf[1024];
        c.recv(buf, sizeof(buf));
        c.close();

        kill(getpid(), SIGTERM);
    });

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock.unlock(); };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->sendwait(req->info.fd, resp.c_str(), resp.length());

        return SW_OK;
    };

    serv.start();
    t1.join();
}

TEST(server, reopen_log) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    swoole_set_log_level(SW_LOG_WARNING);
    string filename = "/tmp/swoole.log";
    swoole_set_log_file(filename.c_str());

    ASSERT_TRUE(serv.add_port(SW_SOCK_TCP, TEST_HOST, 0));
    ASSERT_EQ(serv.create(), SW_OK);

    serv.onWorkerStart = [&filename](Server *serv, Worker *worker) {
        if (worker->id != 0) {
            return;
        }
        EXPECT_TRUE(access(filename.c_str(), R_OK) != -1);
        usleep(10000);
        unlink(filename.c_str());
        EXPECT_TRUE(access(filename.c_str(), R_OK) == -1);
        kill(serv->gs->master_pid, SIGRTMIN);
        sleep(2);
        EXPECT_TRUE(access(filename.c_str(), R_OK) != -1);
        kill(serv->gs->master_pid, SIGTERM);
    };

    serv.onReceive = [](Server *server, RecvData *req) -> int { return SW_OK; };

    ASSERT_EQ(serv.start(), 0);
}

TEST(server, udp_packet) {
    Server *server = new Server(Server::MODE_PROCESS);
    server->worker_num = 2;
    server->add_port(SW_SOCK_UDP, TEST_HOST, 0);

    server->create();
    server->onPacket = [](Server *serv, RecvData *req) {
        DgramPacket *recv_data = (DgramPacket *) req->data;
        EXPECT_EQ(string(recv_data->data, recv_data->length), string(packet));
        network::Socket *server_socket = serv->get_server_socket(req->info.server_fd);
        string resp = string(packet);
        server_socket->sendto(recv_data->socket_addr, resp.c_str(), resp.length(), 0);
        return SW_OK;
    };

    server->onReceive = [](Server *server, RecvData *req) -> int { return SW_OK; };

    pid_t pid = swoole_fork(0);

    if (pid > 0) {
        server->start();
    }

    if (pid == 0) {
        sleep(1);
        auto port = server->get_primary_port();

        network::Client cli(SW_SOCK_UDP, false);
        int ret = cli.connect(&cli, TEST_HOST, port->port, -1, 0);
        EXPECT_EQ(ret, 0);
        ret = cli.send(&cli, packet, strlen(packet), 0);
        EXPECT_GT(ret, 0);

        char buf[1024];
        sleep(1);
        cli.recv(&cli, buf, 128, 0);
        ASSERT_STREQ(buf, packet);
        cli.close();

        kill(server->get_master_pid(), SIGTERM);
        exit(0);
    }
}

TEST(server, protocols) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;
    swoole_set_log_level(SW_LOG_WARNING);
    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);

    port->open_eof_check = true;
    ASSERT_STREQ(port->get_protocols(), "eof");
    port->open_eof_check = false;

    port->open_length_check = true;
    ASSERT_STREQ(port->get_protocols(), "length");
    port->open_length_check = false;

    port->open_http_protocol = true;
    ASSERT_STREQ(port->get_protocols(), "http");
    port->open_http_protocol = false;

    port->open_http_protocol = true;
    port->open_http2_protocol = true;
    port->open_websocket_protocol = true;
    ASSERT_STREQ(port->get_protocols(), "http|http2|websocket");
    port->open_http2_protocol = false;
    port->open_websocket_protocol = false;
    port->open_http_protocol = false;

    port->open_http_protocol = true;
    port->open_http2_protocol = true;
    ASSERT_STREQ(port->get_protocols(), "http|http2");
    port->open_http2_protocol = false;
    port->open_http_protocol = false;

    port->open_http_protocol = true;
    port->open_websocket_protocol = true;
    ASSERT_STREQ(port->get_protocols(), "http|websocket");
    port->open_websocket_protocol = false;
    port->open_http_protocol = false;

    port->open_mqtt_protocol = true;
    ASSERT_STREQ(port->get_protocols(), "mqtt");
    port->open_mqtt_protocol = false;

    port->open_redis_protocol = true;
    ASSERT_STREQ(port->get_protocols(), "redis");
    port->open_redis_protocol = false;

    port->clear_protocol();
    ASSERT_EQ(port->open_eof_check, 0);
    ASSERT_EQ(port->open_length_check, 0);
    ASSERT_EQ(port->open_http_protocol, 0);
    ASSERT_EQ(port->open_websocket_protocol, 0);
    ASSERT_EQ(port->open_http2_protocol, 0);
    ASSERT_EQ(port->open_mqtt_protocol, 0);
    ASSERT_EQ(port->open_redis_protocol, 0);
    ASSERT_STREQ(port->get_protocols(), "raw");
}

TEST(server, pipe_message) {
    Server *server = new Server(Server::MODE_PROCESS);
    server->worker_num = 2;
    server->add_port(SW_SOCK_TCP, TEST_HOST, 0);

    server->create();
    server->onPipeMessage = [](Server *serv, EventData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));
        return SW_OK;
    };

    server->onReceive = [](Server *server, RecvData *req) -> int { return SW_OK; };

    server->onWorkerStart = [&](Server *server, Worker *worker) {
        if (worker->id == 1) {
            EventData buf{};
            string data = string(packet);

            memset(&buf.info, 0, sizeof(buf.info));
            ASSERT_TRUE(Server::task_pack(&buf, data.c_str(), data.length()));
            ASSERT_TRUE(server->send_pipe_message(worker->id - 1, &buf));
            sleep(1);

            kill(server->get_master_pid(), SIGTERM);
        }
    };

    server->start();
}

TEST(server, forward_message) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 2;

    swoole_set_log_level(SW_LOG_WARNING);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    swoole::Mutex lock(swoole::Mutex::PROCESS_SHARED);
    lock.lock();

    ASSERT_EQ(serv.create(), SW_OK);

    std::thread t1([&]() {
        swoole_signal_block_all();

        lock.lock();

        network::SyncClient c(SW_SOCK_TCP);
        c.connect(TEST_HOST, port->port);
        c.send(packet, strlen(packet));
        char buf[1024];
        c.recv(buf, sizeof(buf));
        c.close();

        kill(getpid(), SIGTERM);
    });

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock.unlock(); };

    serv.onPipeMessage = [](Server *serv, EventData *req) -> void {
        SessionId client_fd;
        memcpy(&client_fd, req->data, sizeof(client_fd));
        string resp = string("Server: ") + string(packet);
        serv->send(client_fd, resp.c_str(), resp.length());
    };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EventData msg;
        SessionId client_fd = req->info.fd;
        Server::task_pack(&msg, &client_fd, sizeof(client_fd));
        EXPECT_TRUE(serv->send_pipe_message(1 - swoole_get_process_id(), &msg));
        return SW_OK;
    };

    serv.start();
    t1.join();
}

TEST(server, abnormal_pipeline_data) {
    Server *server = new Server(Server::MODE_PROCESS);
    server->worker_num = 2;
    server->add_port(SW_SOCK_TCP, TEST_HOST, 0);

    uint64_t msg_id = swoole_rand(1, INT_MAX);
    string filename = "/tmp/swoole.log";
    swoole_set_log_file(filename.c_str());

    server->create();

    server->onReceive = [](Server *server, RecvData *req) -> int { return SW_OK; };

    server->onWorkerStart = [&](Server *server, Worker *worker) {
        if (worker->id == 1) {
            auto send_fn = [server](int flags, uint64_t msg_id) {
                auto sock = server->get_worker_pipe_master(0);
                size_t len = swoole_rand(1000, 8000);
                EventData ev;
                ev.info.msg_id = msg_id;
                ev.info.flags = flags;
                ev.info.len = len;
                swoole_random_bytes(ev.data, len);

                sock->send_sync(&ev, sizeof(ev.info) + len);
            };

            send_fn(SW_EVENT_DATA_CHUNK | SW_EVENT_DATA_BEGIN, msg_id);
            send_fn(SW_EVENT_DATA_CHUNK, msg_id + 9999);

            usleep(100000);
            server->shutdown();
        }
    };

    server->start();

    File fp(filename, File::READ);
    auto cont = fp.read_content();
    ASSERT_TRUE(cont->contains(std::string("abnormal pipeline data, msg_id=") + std::to_string(msg_id + 9999)));

    unlink(filename.c_str());
}

TEST(server, startup_error) {
    Server *server = new Server(Server::MODE_PROCESS);
    server->task_worker_num = 2;

    server->add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_EQ(server->create(), 0);

    server->onReceive = [](Server *server, RecvData *req) -> int { return SW_OK; };
    server->onWorkerStart = [&](Server *server, Worker *worker) {};

    ASSERT_EQ(server->start(), -1);
    auto startup_error = String(server->get_startup_error_message());
    ASSERT_TRUE(startup_error.contains("require 'onTask' callback"));
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_SERVER_INVALID_CALLBACK);
}

TEST(server, reactor_thread_pipe_writable) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 1;

    String rdata(4 * 1024 * 1024);
    rdata.append_random_bytes(rdata.capacity());

    swoole_set_log_level(SW_LOG_WARNING);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);
    port->open_length_check = true;
    port->protocol.package_max_length = 8 * 1024 * 1024;
    network::Stream::set_protocol(&port->protocol);

    swoole::Mutex lock(swoole::Mutex::PROCESS_SHARED);
    lock.lock();

    ASSERT_EQ(serv.create(), SW_OK);

    std::thread t1([&]() {
        swoole_signal_block_all();

        lock.lock();

        network::SyncClient c(SW_SOCK_TCP);
        c.connect(TEST_HOST, port->port);
        c.set_stream_protocol();
        c.set_package_max_length(8 * 1024 * 1024);

        uint32_t len = htonl(rdata.length);
        c.send((char *) &len, sizeof(len));
        c.send(rdata.str, rdata.length);

        auto rbuf = new String(rdata.size + 1024);

        uint32_t pkt_len;
        ssize_t rn;

        rn = c.recv((char *) &pkt_len, sizeof(pkt_len));
        EXPECT_EQ(rn, sizeof(pkt_len));

        rn = c.recv(rbuf->str, ntohl(pkt_len), MSG_WAITALL);
        EXPECT_EQ(rn, rdata.length);

        c.close();

        EXPECT_MEMEQ(rbuf->str, rdata.str, rdata.length);
        delete rbuf;

        serv.shutdown();
    });

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) {
        lock.unlock();
        usleep(300000);
    };

    serv.onReceive = [&](Server *serv, RecvData *req) -> int {
        uint32_t len = htonl(rdata.length);
        serv->send(req->info.fd, &len, sizeof(len));
        serv->send(req->info.fd, rdata.str, rdata.length);
        return SW_OK;
    };

    serv.start();
    t1.join();
}
