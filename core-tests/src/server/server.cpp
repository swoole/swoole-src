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

#include <numeric>

using namespace std;
using namespace swoole;
using swoole::network::AsyncClient;

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

TEST(server, schedule_1) {
    int ret;
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 8;
    serv.dispatch_mode = Server::DISPATCH_ROUND;
    serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);

    ret = serv.create();
    ASSERT_EQ(SW_OK, ret);

    std::vector<size_t> counter;
    size_t schedule_count = 1024;

    counter.resize(serv.worker_num);
    SW_LOOP_N(schedule_count) {
        auto worker_id = serv.schedule_worker(i * 13, nullptr);
        counter[worker_id]++;
    }

    SW_LOOP_N(serv.worker_num) {
        ASSERT_EQ(counter[i], schedule_count / serv.worker_num);
    }
}

double average_combined(const std::vector<size_t> &v1, const std::vector<size_t> &v2) {
    size_t total_size = v1.size() + v2.size();
    if (total_size == 0) return 0.0;
    size_t sum1 = std::accumulate(v1.begin(), v1.end(), size_t{0});
    size_t sum2 = std::accumulate(v2.begin(), v2.end(), size_t{0});
    return static_cast<double>(sum1 + sum2) / total_size;
}

template <typename T, typename M, M T::*member>
static void test_worker_schedule(int dispatch_mode) {
    int ret;
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 8;
    serv.dispatch_mode = dispatch_mode;
    auto port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);

    ret = serv.create();
    ASSERT_EQ(SW_OK, ret);

    std::vector<size_t> counter;
    counter.resize(serv.worker_num);

    size_t schedule_count = 256 * serv.worker_num;

    std::vector<size_t> init_counter;
    init_counter.resize(serv.worker_num);

    SW_LOOP_N(serv.worker_num) {
        T &worker = serv.workers[i];
        init_counter[i] = worker.*member = swoole_rand(32, 512);
    }

    network::Socket fake_sock{};
    fake_sock.fd = 199;
    serv.add_connection(port, &fake_sock, port->get_fd());

    SW_LOOP_N(schedule_count) {
        auto worker_id = serv.schedule_worker(fake_sock.fd, nullptr);
        counter[worker_id]++;
        T &worker = serv.workers[worker_id];
        (worker.*member)++;
    }

    auto avg_elem = average_combined(init_counter, counter);
    SW_LOOP_N(serv.worker_num) {
        ASSERT_GE(counter[i] + init_counter[i], (int) avg_elem * 2 - 10);
    }
}

TEST(server, schedule_9) {
    test_worker_schedule<Worker, size_t, &Worker::coroutine_num>(Server::DISPATCH_CO_REQ_LB);
}

TEST(server, schedule_10) {
    test_worker_schedule<Worker, uint32_t, &Worker::concurrency>(Server::DISPATCH_CONCURRENT_LB);
}

static const char *packet = "hello world\n";

TEST(server, base) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;
    serv.pid_file = "/tmp/swoole-core-tests.pid";

    swoole_set_log_level(SW_LOG_WARNING);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    ASSERT_EQ(serv.add_hook(
                  Server::HOOK_WORKER_START,
                  [](void *ptr) {
                      void **args = (void **) ptr;
                      Server *serv = (Server *) args[0];
                      ASSERT_TRUE(serv->is_started());
                  },
                  false),
              0);

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

    serv.onStart = [](Server *serv) { ASSERT_EQ(access(serv->pid_file.c_str(), R_OK), 0); };

    serv.start();
    t1.join();

    ASSERT_EQ(access(serv.pid_file.c_str(), R_OK), -1);
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

    thread t1;
    serv.onStart = [&lock, &t1](Server *serv) {
        t1 = thread([=]() {
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

    t1.join();
    delete lock;
}

#ifdef SW_THREAD
TEST(server, thread) {
    Server serv(Server::MODE_THREAD);
    serv.worker_num = 2;

    swoole_set_trace_flags(SW_TRACE_THREAD);
    swoole_set_log_level(SW_LOG_TRACE);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    mutex lock;
    lock.lock();

    ASSERT_EQ(serv.create(), SW_OK);

    std::thread t1([&]() {
        swoole_signal_block_all();

        lock.lock();

        usleep(1000);

        network::SyncClient c(SW_SOCK_TCP);
        ASSERT_TRUE(c.connect(TEST_HOST, port->port));
        ASSERT_EQ(c.send(packet, strlen(packet)), strlen(packet));
        char buf[1024];
        ASSERT_EQ(c.recv(buf, sizeof(buf)), strlen(packet) + 8);
        string resp = string("Server: ") + string(packet);
        ASSERT_MEMEQ(buf, resp.c_str(), resp.length());
        c.close();

        usleep(10);

        DEBUG() << "shutdown\n";

        serv.shutdown();
    });

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock.unlock(); };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        DEBUG() << "send\n";

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

    thread t1;

    serv.onStart = [&lock, &t1](Server *serv) {
        t1 = thread([=]() {
            swoole_signal_block_all();

            lock->lock();

            ListenPort *port = serv->get_primary_port();

            EXPECT_EQ(port->ssl, 1);

            network::SyncClient c(SW_SOCK_TCP);
            c.connect(TEST_HOST, port->port);
            c.enable_ssl_encrypt();
            c.send(packet, strlen(packet));
            char buf[1024];
            c.recv(buf, sizeof(buf));
            c.close();

            kill(serv->gs->master_pid, SIGTERM);
        });
    };

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock->unlock(); };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        return SW_OK;
    };

    ASSERT_EQ(serv.start(), 0);

    t1.join();
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

    thread t1;
    serv.onStart = [&lock, &t1](Server *serv) {
        t1 = thread([=]() {
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
    };

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock->unlock(); };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        return SW_OK;
    };

    ASSERT_EQ(serv.start(), 0);

    t1.join();
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

static void test_ssl_client_cert(Server::Mode mode) {
    Server serv(mode);
    serv.worker_num = 1;
    swoole_set_log_level(SW_LOG_INFO);

    Mutex *lock = new Mutex(Mutex::PROCESS_SHARED);
    lock->lock();

    ListenPort *port = serv.add_port((enum swSocketType)(SW_SOCK_TCP | SW_SOCK_SSL), TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    port->set_ssl_cert_file(test::get_ssl_dir() + "/server.crt");
    port->set_ssl_key_file(test::get_ssl_dir() + "/server.key");
    port->set_ssl_verify_peer(true);
    port->set_ssl_allow_self_signed(true);
    port->set_ssl_client_cert_file(test::get_ssl_dir() + "/ca-cert.pem");
    port->ssl_init();

    ASSERT_EQ(serv.create(), SW_OK);

    thread t1;
    serv.onStart = [&lock, &t1](Server *serv) {
        t1 = thread([=]() {
            swoole_signal_block_all();

            lock->lock();

            ListenPort *port = serv->get_primary_port();

            EXPECT_EQ(port->ssl, 1);

            network::SyncClient c(SW_SOCK_TCP);
            c.enable_ssl_encrypt();
            c.get_client()->set_ssl_cert_file(test::get_ssl_dir() + "/client-cert.pem");
            c.get_client()->set_ssl_key_file(test::get_ssl_dir() + "/client-key.pem");
            c.connect(TEST_HOST, port->port);
            EXPECT_EQ(c.send(packet, strlen(packet)), strlen(packet));

            char buf[1024];
            EXPECT_GT(c.recv(buf, sizeof(buf)), 0);
            c.close();

            kill(serv->gs->master_pid, SIGTERM);
        });
    };

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock->unlock(); };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        auto conn = serv->get_connection_by_session_id(req->session_id());
        EXPECT_NE(conn->ssl_client_cert, nullptr);
        EXPECT_GT(conn->ssl_client_cert->length, 16);

        char *buffer = NULL;
        size_t size = 0;
        FILE *stream = open_memstream(&buffer, &size);
        swoole_set_stdout_stream(stream);
        swoole::test::dump_cert_info(conn->ssl_client_cert->str, conn->ssl_client_cert->length);
        fflush(stream);
        swoole_set_stdout_stream(stdout);

        EXPECT_NE(strstr(buffer, "organizationName: swoole"), nullptr);

        fclose(stream);
        free(buffer);

        return SW_OK;
    };

    ASSERT_EQ(serv.start(), 0);

    t1.join();
    delete lock;
}

TEST(server, ssl_client_cert_1) {
    test_ssl_client_cert(Server::MODE_BASE);
}

TEST(server, ssl_client_cert_2) {
    test_ssl_client_cert(Server::MODE_PROCESS);
}

TEST(server, ssl_client_cert_3) {
    test_ssl_client_cert(Server::MODE_THREAD);
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
    string filename = TEST_LOG_FILE;
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
    remove(filename.c_str());
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
        int ret = cli.connect(TEST_HOST, port->port, -1, 0);
        EXPECT_EQ(ret, 0);
        ret = cli.send(packet, strlen(packet), 0);
        EXPECT_GT(ret, 0);

        char buf[1024];
        sleep(1);
        cli.recv(buf, 128, 0);
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
        EXPECT_TRUE(serv->send_pipe_message(1 - swoole_get_worker_id(), &msg));
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
    string filename = TEST_LOG_FILE;
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

TEST(server, abort_worker) {
    Server *server = new Server(Server::MODE_BASE);
    server->worker_num = 2;

    auto port = server->add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_EQ(server->create(), 0);

    swoole::Mutex lock(swoole::Mutex::PROCESS_SHARED);
    lock.lock();

    std::thread t1([&]() {
        swoole_signal_block_all();

        lock.lock();

        network::SyncClient c1(SW_SOCK_TCP);
        c1.connect(TEST_HOST, port->port);

        char buf[1024];
        auto rn = c1.recv(buf, sizeof(buf), MSG_WAITALL);
        ASSERT_EQ(rn, 0);

        c1.close();

        network::SyncClient c2(SW_SOCK_TCP);
        c2.connect(TEST_HOST, port->port);
        c2.send(SW_STRL("info"));
        auto n = c2.recv(buf, sizeof(buf));
        buf[n] = 0;
        c2.close();

        ASSERT_STREQ(buf, "OK");

        server->shutdown();
    });

    server->onConnect = [](Server *server, DataHead *ev) {
        if (ev->fd == 1) {
            swoole_timer_after(100, [server](auto r1, auto r2) { kill(getpid(), SIGKILL); });
        }
    };

    server->onReceive = [](Server *server, RecvData *req) -> int {
        size_t count = 0;
        SW_LOOP_N(SW_SESSION_LIST_SIZE) {
            Session *session = server->get_session(i);
            if (session->fd && session->id) {
                count++;
            }
        }
        EXPECT_EQ(count, 1);
        if (count == 1) {
            server->send(req->info.fd, "OK", 2);
        } else {
            server->send(req->info.fd, "ERR", 3);
        }
        return 0;
    };

    server->onWorkerStart = [&](Server *server, Worker *worker) {
        if (worker->id == 0) {
            lock.unlock();
        }
    };

    ASSERT_EQ(server->start(), 0);
    t1.join();
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

    Mutex lock(Mutex::PROCESS_SHARED);
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
        EXPECT_TRUE(req->info.flags & SW_EVENT_DATA_OBJ_PTR);
        EXPECT_TRUE(serv->send(req->info.fd, &len, sizeof(len)));
        EXPECT_TRUE(serv->send(req->info.fd, rdata.str, rdata.length));
        EXPECT_MEMEQ(req->data + 4, rdata.str, rdata.length);
        EXPECT_NE(serv->get_worker_message_bus()->move_packet(), nullptr);
        return SW_OK;
    };

    serv.start();
    t1.join();
}

static void test_heartbeat_check(Server::Mode mode, bool single_thread = false) {
    Server serv(mode);
    serv.worker_num = 1;
    serv.heartbeat_check_interval = 1;
    serv.single_thread = single_thread;

    swoole_set_print_backtrace_on_error(true);

    std::unordered_map<std::string, bool> flags;
    AsyncClient ac(SW_SOCK_TCP);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onReceive = [](Server *serv, RecvData *req) -> int { return SW_OK; };

    serv.onStart = [port, &ac, &flags](Server *_serv) {
        ac.on_connect([&](AsyncClient *ac) { flags["on_connect"] = true; });

        ac.on_close([_serv, &flags](AsyncClient *ac) {
            flags["on_close"] = true;
            _serv->shutdown();
        });

        ac.on_error([&](AsyncClient *ac) { flags["on_error"] = true; });

        ac.on_receive([&](AsyncClient *ac, const char *data, size_t len) { flags["on_receive"] = true; });

        bool retval = ac.connect(TEST_HOST, port->get_port());
        EXPECT_TRUE(retval);
        flags["connected"] = true;
    };

    serv.start();

    ASSERT_TRUE(flags["connected"]);
    ASSERT_TRUE(flags["on_connect"]);
    ASSERT_FALSE(flags["on_error"]);
    ASSERT_FALSE(flags["on_receive"]);
    ASSERT_TRUE(flags["on_close"]);
}

TEST(server, heartbeat_check_1) {
    test_heartbeat_check(Server::MODE_BASE);
}

TEST(server, heartbeat_check_2) {
    test_heartbeat_check(Server::MODE_PROCESS);
}

TEST(server, heartbeat_check_3) {
    test_heartbeat_check(Server::MODE_THREAD);
}

TEST(server, heartbeat_check_4) {
    test_heartbeat_check(Server::MODE_PROCESS);
}

static void test_close(Server::Mode mode, bool close_in_client, bool single_thread = false) {
    Server serv(mode);
    serv.worker_num = 1;
    serv.single_thread = single_thread;

    std::unordered_map<std::string, bool> flags;
    AsyncClient ac(SW_SOCK_TCP);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onConnect = [&flags, close_in_client](Server *serv, DataHead *ev) { flags["server_on_connect"] = true; };

    serv.onReceive = [&flags, close_in_client](Server *serv, RecvData *req) {
        serv->send(req->session_id(), req->data, req->length());
        if (!close_in_client) {
            serv->close(req->session_id());
        }
        flags["server_on_receive"] = true;
        return SW_OK;
    };

    serv.onClose = [&flags, close_in_client](Server *serv, DataHead *ev) {
        if (!close_in_client) {
            ASSERT_LT(ev->reactor_id, 0);
        }
        flags["server_on_close"] = true;
    };

    serv.onWorkerStop = [&flags](Server *serv, Worker *worker) {
        ASSERT_TRUE(flags["server_on_connect"]);
        ASSERT_TRUE(flags["server_on_receive"]);
        ASSERT_TRUE(flags["server_on_close"]);
    };

    serv.onStart = [port, &ac, &flags, close_in_client](Server *_serv) {
        ac.on_connect([&](AsyncClient *ac) {
            flags["client_on_connect"] = true;
            ac->send(SW_STRL(TEST_STR));
        });

        ac.on_close([_serv, &flags](AsyncClient *ac) {
            flags["client_on_close"] = true;
            swoole_timer_after(50, [_serv, ac](TIMER_PARAMS) { _serv->shutdown(); });
        });

        ac.on_error([&](AsyncClient *ac) { flags["client_on_error"] = true; });

        ac.on_receive([&](AsyncClient *ac, const char *data, size_t len) {
            flags["client_on_receive"] = true;
            if (close_in_client) {
                /**
                 * When a client initiates a connection to its own port in the current process,
                 * the epoll does not trigger a readable event upon executing close;
                 * it is necessary to perform a shutdown first to trigger the event.
                 */
                ac->get_client()->shutdown(SHUT_RDWR);
                ac->close();
            }
        });

        bool retval = ac.connect(TEST_HOST, port->get_port());
        EXPECT_TRUE(retval);
        flags["client_connected"] = true;
    };

    ASSERT_EQ(serv.start(), SW_OK);

    ASSERT_TRUE(flags["client_connected"]);
    ASSERT_TRUE(flags["client_on_connect"]);
    ASSERT_FALSE(flags["client_on_error"]);
    ASSERT_TRUE(flags["client_on_receive"]);
    ASSERT_TRUE(flags["client_on_close"]);
}

TEST(server, close_1) {
    test_close(Server::MODE_PROCESS, false);
}

TEST(server, close_2) {
    test_close(Server::MODE_BASE, false);
}

TEST(server, close_3) {
    test_close(Server::MODE_THREAD, false);
}

TEST(server, close_4) {
    test_close(Server::MODE_PROCESS, false, true);
}

TEST(server, close_5) {
    test_close(Server::MODE_PROCESS, true);
}

TEST(server, close_6) {
    test_close(Server::MODE_BASE, true);
}

TEST(server, close_7) {
    test_close(Server::MODE_THREAD, true);
}

TEST(server, close_8) {
    test_close(Server::MODE_PROCESS, true, true);
}

TEST(server, eof_check) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);
    port->set_eof_protocol("\r\n", true);
    ASSERT_EQ(serv.create(), SW_OK);

    std::unordered_map<std::string, bool> flags;
    AsyncClient ac(SW_SOCK_TCP);

    int count = 0;

    serv.onWorkerStart = [&count, &flags, port, &ac](Server *serv, Worker *worker) {
        ac.on_connect([&](AsyncClient *ac) { flags["on_connect"] = true; });

        ac.on_close([serv, &flags](AsyncClient *ac) {
            flags["on_close"] = true;
            serv->shutdown();
        });

        ac.on_error([&](AsyncClient *ac) { flags["on_error"] = true; });

        ac.on_receive([&](AsyncClient *ac, const char *data, size_t len) {
            flags["on_receive"] = true;
            ASSERT_MEMEQ(data, "OK", len);
            count++;

            if (count == 1) {
                ac->send("hello world\r\n");
            } else if (count == 2) {
                ac->send("hello world\r\nhello world\r\n");
            } else if (count == 3) {
                ac->send("hello world\r\nhello world\r\nhello world\r\n");
            } else if (count == 4) {
                ac->close();
            }
        });

        bool retval = ac.connect(TEST_HOST, port->get_port());
        EXPECT_TRUE(retval);
        flags["connected"] = true;
    };

    int recv_count = 0;

    serv.onReceive = [&](Server *serv, RecvData *req) -> int {
        serv->send(req->info.fd, "OK", 2);
        recv_count++;
        return SW_OK;
    };

    serv.onConnect = [&](Server *serv, DataHead *ev) { serv->send(ev->fd, "OK", 2); };

    serv.start();

    ASSERT_TRUE(flags["connected"]);
    ASSERT_TRUE(flags["on_connect"]);
    ASSERT_FALSE(flags["on_error"]);
    ASSERT_TRUE(flags["on_receive"]);
    ASSERT_TRUE(flags["on_close"]);
    ASSERT_TRUE(flags["on_close"]);
    ASSERT_EQ(recv_count, 3);
}

static void test_clean_worker(Server::Mode mode) {
    Server serv(mode);
    serv.worker_num = 2;

    test::counter_init();

    AsyncClient ac(SW_SOCK_TCP);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);
    ASSERT_EQ(serv.create(), SW_OK);

    serv.onConnect = [&ac](Server *serv, DataHead *ev) {
        DEBUG() << "server onConnect\n";
        swoole_event_defer(
            [serv, &ac](void *) {
                DEBUG() << "clean_worker_connections\n";
                serv->clean_worker_connections(sw_worker());
                DEBUG() << "client shutdown\n";
                ac.get_client()->shutdown();
                serv->stop_async_worker(sw_worker());
            },
            nullptr);
    };

    serv.onReceive = [](Server *serv, RecvData *req) {
        serv->send(req->info.fd, "OK", 2);
        test::counter_incr(0, 1);
        DEBUG() << "server onReceive\n";
        return SW_OK;
    };

    serv.onClose = [](Server *serv, DataHead *ev) { test::counter_incr(2, 1); };

    serv.onWorkerStart = [](Server *serv, Worker *worker) {
        ASSERT_EQ(serv->get_connection_num(), 0);
        DEBUG() << "worker#" << worker->id << " start\n";
        if (test::counter_incr(1, 1) == 3) {
            swoole_timer_after(100, [serv](TIMER_PARAMS) {
                DEBUG() << "server shutdown\n";
                serv->shutdown();
            });
        }
    };

    serv.onWorkerStop = [](Server *serv, Worker *worker) { DEBUG() << "worker#" << worker->id << " stop\n"; };

    serv.onStart = [port, &ac](Server *_serv) {
        DEBUG() << "server is started\n";
        swoole_timer_after(100, [port, _serv, &ac](TIMER_PARAMS) {
            ac.on_connect([&](AsyncClient *ac) { ac->send(SW_STRL(TEST_STR)); });

            ac.on_close([_serv](AsyncClient *ac) {
                DEBUG() << "client onClose\n";
            });

            ac.on_error([](AsyncClient *ac) { swoole_warning("connect failed, error=%d", swoole_get_last_error()); });

            ac.on_receive([](AsyncClient *ac, const char *data, size_t len) {
                DEBUG() << "received\n";
                test::counter_incr(3, 1);
            });

            bool retval = ac.connect(TEST_HOST, port->get_port());
            EXPECT_TRUE(retval);
            DEBUG() << "client is connected\n";
        });
    };

    ASSERT_EQ(serv.start(), SW_OK);
    ASSERT_EQ(test::counter_get(0), 0); // Server on_receive
    ASSERT_EQ(test::counter_get(1), 3); // worker start
    ASSERT_EQ(test::counter_get(2), 1); // Server on_close
    ASSERT_EQ(test::counter_get(3), 0); // Client on_receive
}

TEST(server, clean_worker_1) {
    test_clean_worker(Server::MODE_BASE);
}

TEST(server, clean_worker_2) {
    test_clean_worker(Server::MODE_THREAD);
}

static void test_kill_worker(Server::Mode mode, bool wait_reactor = true) {
    Server serv(mode);
    serv.worker_num = 2;

    test::counter_init();
    int *counter = test::counter_ptr();

    swoole::Mutex lock(swoole::Mutex::PROCESS_SHARED);
    lock.lock();

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onConnect = [counter](Server *serv, DataHead *ev) {
        counter[4] = ev->fd;
        counter[5] = sw_worker()->id;
    };

    serv.onReceive = [counter](Server *serv, RecvData *req) {
        serv->send(req->info.fd, "OK", 2);
        sw_atomic_fetch_add(&counter[0], 1);

        return SW_OK;
    };

    serv.onWorkerStop = [counter](Server *_serv, Worker *worker) {
        _serv->close(counter[4]);
        _serv->drain_worker_pipe();
    };

    serv.onClose = [counter](Server *serv, DataHead *ev) { sw_atomic_fetch_add(&counter[2], 1); };

    serv.onWorkerStart = [counter](Server *_serv, Worker *worker) { sw_atomic_fetch_add(&counter[1], 1); };

    serv.onStart = [&lock](Server *_serv) {
        if (!sw_worker()) {
            ASSERT_FALSE(_serv->kill_worker(-1, true));
        }
        lock.unlock();
    };

    std::thread t([&]() {
        swoole_signal_block_all();

        lock.lock();

        usleep(50000);

        network::SyncClient c(SW_SOCK_TCP);
        EXPECT_TRUE(c.connect(TEST_HOST, port->port));

        EXPECT_EQ(c.send(SW_STRL(TEST_STR)), strlen(TEST_STR));

        String rbuf(1024);
        auto rn = c.recv(rbuf.str, rbuf.size);
        EXPECT_EQ(rn, 2);

        serv.kill_worker(1 - counter[5], wait_reactor);

        rn = c.recv(rbuf.str, rbuf.size);
        EXPECT_EQ(rn, 0);

        sw_atomic_fetch_add(&counter[3], 1);

        usleep(50000);

        serv.shutdown();
    });

    ASSERT_EQ(serv.start(), SW_OK);
    t.join();

    ASSERT_EQ(counter[0], 1);  // Client receive
    ASSERT_EQ(counter[1], 3);  // Server onWorkeStart
    ASSERT_EQ(counter[2], 1);  // Server onClose
    ASSERT_EQ(counter[3], 1);  // Client close
}

TEST(server, kill_worker_1) {
    test_kill_worker(Server::MODE_BASE);
}

TEST(server, kill_worker_2) {
    test_kill_worker(Server::MODE_PROCESS);
}

TEST(server, kill_worker_3) {
    test_kill_worker(Server::MODE_THREAD);
}

TEST(server, kill_worker_4) {
    test_kill_worker(Server::MODE_BASE, false);
}

TEST(server, kill_worker_5) {
    test_kill_worker(Server::MODE_PROCESS, false);
}

TEST(server, kill_worker_6) {
    test_kill_worker(Server::MODE_THREAD, false);
}

static void test_kill_self(Server::Mode mode) {
    Server serv(mode);
    serv.worker_num = 2;

    int *counter = (int *) sw_mem_pool()->alloc(sizeof(int) * 6);

    swoole::Mutex lock(swoole::Mutex::PROCESS_SHARED);
    lock.lock();

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onConnect = [counter](Server *serv, DataHead *ev) {
        counter[4] = ev->fd;
        counter[5] = sw_worker()->id;
    };

    serv.onReceive = [counter](Server *serv, RecvData *req) {
        serv->send(req->info.fd, "OK", 2);
        sw_atomic_fetch_add(&counter[0], 1);

        return SW_OK;
    };

    serv.onWorkerStop = [counter](Server *_serv, Worker *worker) { _serv->close(counter[4]); };

    serv.onClose = [counter](Server *serv, DataHead *ev) { sw_atomic_fetch_add(&counter[2], 1); };

    serv.onWorkerStart = [counter](Server *_serv, Worker *worker) { sw_atomic_fetch_add(&counter[1], 1); };

    serv.onStart = [&lock](Server *_serv) {
        if (!sw_worker()) {
            ASSERT_FALSE(_serv->kill_worker(-1, true));
        }
        lock.unlock();
    };

    std::thread t([&]() {
        swoole_signal_block_all();

        lock.lock();

        usleep(50000);

        network::SyncClient c(SW_SOCK_TCP);
        EXPECT_TRUE(c.connect(TEST_HOST, port->port));

        EXPECT_EQ(c.send(SW_STRL(TEST_STR)), strlen(TEST_STR));

        String rbuf(1024);
        auto rn = c.recv(rbuf.str, rbuf.size);
        EXPECT_EQ(rn, 2);

        serv.kill_worker(counter[5], false);

        rn = c.recv(rbuf.str, rbuf.size);
        EXPECT_EQ(rn, 0);

        sw_atomic_fetch_add(&counter[3], 1);

        usleep(50000);

        serv.shutdown();
    });

    ASSERT_EQ(serv.start(), SW_OK);
    t.join();

    ASSERT_EQ(counter[0], 1);  // Client receive
    ASSERT_EQ(counter[1], 3);  // Server onWorkeStart
    ASSERT_EQ(counter[2], 1);  // Server onClose
    ASSERT_EQ(counter[3], 1);  // Client close
}

TEST(server, kill_self) {
    test_kill_self(Server::MODE_BASE);
}
