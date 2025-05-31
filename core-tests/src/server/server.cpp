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

    serv.destroy();
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

TEST(server, schedule_4) {
    int ret;
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 4;
    serv.dispatch_mode = Server::DISPATCH_IPMOD;

    auto port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_NE(port, nullptr);

    auto port6 = serv.add_port(SW_SOCK_TCP6, "::", 0);
    ASSERT_NE(port6, nullptr);

    ret = serv.create();
    ASSERT_EQ(SW_OK, ret);

    std::vector<size_t> counter;
    counter.resize(serv.worker_num);

    size_t schedule_count = 256 * serv.worker_num;

    std::vector<size_t> init_counter;
    init_counter.resize(serv.worker_num);

    network::Socket fake_sock{};
    fake_sock.fd = 100;
    fake_sock.info.assign(SW_SOCK_TCP, "127.0.0.1", 9501, false);
    serv.add_connection(port, &fake_sock, port->get_fd());

    SW_LOOP_N(schedule_count) {
        auto worker_id = serv.schedule_worker(fake_sock.fd, nullptr);
        counter[worker_id]++;
    }

    network::Socket fake_sock6{};
    fake_sock6.fd = 101;
    fake_sock6.info.assign(SW_SOCK_TCP6, "::1", 9502, false);
    serv.add_connection(port6, &fake_sock6, port6->get_fd());

    SW_LOOP_N(schedule_count) {
        auto worker_id = serv.schedule_worker(fake_sock6.fd, nullptr);
        counter[worker_id]++;
    }

    SendData sdata;
    auto pkt = reinterpret_cast<DgramPacket *>(sw_tg_buffer()->str);
    pkt->socket_addr.assign(SW_SOCK_UDP, "192.168.1.103", 29321, false);
    sdata.data = (char *) pkt;
    auto worker_id = serv.schedule_worker(9999, &sdata);
    counter[worker_id]++;

    ASSERT_EQ(counter[0], 0);
    ASSERT_EQ(counter[1], schedule_count);
    ASSERT_EQ(counter[2], 0);
    ASSERT_EQ(counter[3], schedule_count + 1);
}

TEST(server, schedule_5) {
    int ret;
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 4;
    serv.dispatch_mode = Server::DISPATCH_UIDMOD;

    auto port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_NE(port, nullptr);

    auto port6 = serv.add_port(SW_SOCK_TCP6, "::", 0);
    ASSERT_NE(port6, nullptr);

    ret = serv.create();
    ASSERT_EQ(SW_OK, ret);

    std::vector<size_t> counter;
    counter.resize(serv.worker_num);

    size_t schedule_count = 256 * serv.worker_num;

    std::vector<size_t> init_counter;
    init_counter.resize(serv.worker_num);

    network::Socket fake_sock{};
    fake_sock.fd = 100;
    fake_sock.info.assign(SW_SOCK_TCP, "127.0.0.1", 9501, false);
    auto conn = serv.add_connection(port, &fake_sock, port->get_fd());
    conn->uid = 0;

    SW_LOOP_N(schedule_count) {
        auto worker_id = serv.schedule_worker(fake_sock.fd, nullptr);
        counter[worker_id]++;
    }

    network::Socket fake_sock6{};
    fake_sock6.fd = 101;

    fake_sock6.info.assign(SW_SOCK_TCP6, "::1", 9502, false);
    auto conn6 = serv.add_connection(port6, &fake_sock6, port6->get_fd());
    conn6->uid = 839922;

    SW_LOOP_N(schedule_count) {
        auto worker_id = serv.schedule_worker(fake_sock6.fd, nullptr);
        counter[worker_id]++;
    }

    ASSERT_EQ(counter[0], schedule_count);
    ASSERT_EQ(counter[1], 0);
    ASSERT_EQ(counter[2], schedule_count);
    ASSERT_EQ(counter[3], 0);
}

TEST(server, schedule_8) {
    int ret;
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 4;
    serv.dispatch_mode = Server::DISPATCH_CO_CONN_LB;

    auto port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_NE(port, nullptr);

    auto port6 = serv.add_port(SW_SOCK_TCP6, "::", 0);
    ASSERT_NE(port6, nullptr);

    ret = serv.create();
    ASSERT_EQ(SW_OK, ret);

    std::vector<size_t> counter;
    counter.resize(serv.worker_num);

    size_t schedule_count = 256 * serv.worker_num;

    std::vector<size_t> init_counter;
    init_counter.resize(serv.worker_num);

    network::Socket fake_sock{};
    fake_sock.fd = 100;
    fake_sock.info.assign(SW_SOCK_TCP, "127.0.0.1", 9501, false);
    auto conn = serv.add_connection(port, &fake_sock, port->get_fd());
    conn->worker_id = 1;

    SW_LOOP_N(schedule_count) {
        auto worker_id = serv.schedule_worker(fake_sock.fd, nullptr);
        counter[worker_id]++;
    }

    network::Socket fake_sock6{};
    fake_sock6.fd = 101;

    fake_sock6.info.assign(SW_SOCK_TCP6, "::1", 9502, false);
    serv.add_connection(port6, &fake_sock6, port6->get_fd());

    SW_LOOP_N(schedule_count) {
        auto worker_id = serv.schedule_worker(fake_sock6.fd, nullptr);
        counter[worker_id]++;
    }

    auto worker_id = serv.schedule_worker(9999, nullptr);
    counter[worker_id]++;

    ASSERT_EQ(counter[0], schedule_count);
    ASSERT_EQ(counter[1], schedule_count);
    ASSERT_EQ(counter[2], 0);
    ASSERT_EQ(counter[3], 1);
}

TEST(server, schedule_9) {
    test_worker_schedule<Worker, size_t, &Worker::coroutine_num>(Server::DISPATCH_CO_REQ_LB);
}

TEST(server, schedule_10) {
    test_worker_schedule<Worker, uint32_t, &Worker::concurrency>(Server::DISPATCH_CONCURRENT_LB);
}

static const char *packet = "hello world\n";

static void test_base() {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;
    serv.pid_file = "/tmp/swoole-core-tests.pid";

    test::counter_init();
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

    swoole_clear_last_error();
    ASSERT_FALSE(serv.shutdown());
    ASSERT_ERREQ(SW_ERROR_WRONG_OPERATION);

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

        EXPECT_FALSE(serv->finish(resp.c_str(), resp.length()));

        EXPECT_EQ(serv->get_connection_num(), 1);
        EXPECT_EQ(serv->get_primary_port()->get_connection_num(), 1);

        EXPECT_EQ(serv->get_worker_message_bus()->move_packet(), nullptr);

        // session not exists
        SessionId client_fd = 9999;
        swoole_clear_last_error();
        EXPECT_FALSE(serv->send(client_fd, resp.c_str(), resp.length()));
        EXPECT_ERREQ(SW_ERROR_SESSION_NOT_EXIST);

        swoole_clear_last_error();
        EXPECT_FALSE(serv->close(client_fd));
        EXPECT_ERREQ(SW_ERROR_SESSION_NOT_EXIST);

        swoole_clear_last_error();
        SendData sd{};
        sd.info.fd = client_fd;
        sd.info.type = SW_SERVER_EVENT_CLOSE;
        EXPECT_EQ(serv->send_to_connection(&sd), SW_ERR);
        EXPECT_ERREQ(SW_ERROR_SESSION_NOT_EXIST);

        return SW_OK;
    };

    serv.onStart = [](Server *serv) { ASSERT_EQ(access(serv->pid_file.c_str(), R_OK), 0); };

    serv.onBeforeShutdown = [](Server *serv) {
        beforeReloadPid = serv->gs->master_pid;
        test::counter_incr(10);
        DEBUG() << "onBeforeShutdown: master_pid=" << beforeReloadPid << "\n";
    };

    serv.start();
    t1.join();

    ASSERT_EQ(access(serv.pid_file.c_str(), R_OK), -1);
    ASSERT_EQ(test::counter_get(10), 1);  // onBeforeShutdown called
}

TEST(server, base) {
    test_base();
}

static void test_process(bool single_thread = false) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 1;
    serv.single_thread = single_thread;
    serv.task_worker_num = 3;
    swoole_set_log_level(SW_LOG_WARNING);

    test::counter_init();
    auto counter = test::counter_ptr();

    Mutex *lock = new Mutex(Mutex::PROCESS_SHARED);
    lock->lock();

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    ASSERT_EQ(serv.create(), SW_OK);

    swoole_clear_last_error();
    ASSERT_EQ(serv.add_port(SW_SOCK_TCP, TEST_HOST, 0), nullptr);
    ASSERT_ERREQ(SW_ERROR_WRONG_OPERATION);

    swoole_clear_last_error();
    Worker fake_worker{};
    ASSERT_EQ(serv.add_worker(&fake_worker), SW_ERR);
    ASSERT_ERREQ(SW_ERROR_WRONG_OPERATION);

    thread t1;
    serv.onStart = [&lock, &t1](Server *serv) {
        t1 = thread([=]() {
            swoole_signal_block_all();

            lock->lock();

            kill(serv->get_worker(0)->pid, SIGRTMIN);

            ListenPort *port = serv->get_primary_port();

            network::SyncClient c(SW_SOCK_TCP);
            c.connect(TEST_HOST, port->port);
            c.send(packet, strlen(packet));
            char buf[1024];
            c.recv(buf, sizeof(buf));
            c.close();

            sleep(2);

            kill(serv->gs->master_pid, SIGTERM);
        });

        // command tests
        swoole_clear_last_error();
        serv->call_command_callback(9999, TEST_STR);
        ASSERT_ERREQ(SW_ERROR_SERVER_INVALID_COMMAND);

        swoole_clear_last_error();
        serv->call_command_handler_in_master(9999, TEST_STR);
        ASSERT_ERREQ(SW_ERROR_SERVER_INVALID_COMMAND);
    };

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) {
        if (worker->id == 0) {
            lock->unlock();
        }
        test::counter_incr(3);
        DEBUG() << "onWorkerStart: id=" << worker->id << "\n";
    };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        EXPECT_EQ(serv->get_connection_num(), 1);
        EXPECT_EQ(serv->get_primary_port()->get_connection_num(), 1);

        swoole_timer_after(100, [serv](TIMER_PARAMS) { serv->kill_worker(1 + swoole_random_int() % 3); });

        return SW_OK;
    };

    serv.onTask = [](Server *serv, EventData *task) -> int { return 0; };

    serv.manager_alarm = 1;

    serv.add_hook(
        Server::HOOK_MANAGER_TIMER,
        [](void *args) {
            test::counter_incr(2);
            DEBUG() << "manager timer callback\n";
        },
        true);

    serv.onManagerStart = [](Server *serv) {
        DEBUG() << "onManagerStart\n";
        test::counter_incr(1);
    };

    serv.onManagerStop = [](Server *serv) {
        DEBUG() << "onManagerStop\n";
        test::counter_incr(1);
    };

    serv.onBeforeShutdown = [](Server *serv) {
        beforeReloadPid = serv->gs->master_pid;
        test::counter_incr(10);
        DEBUG() << "onBeforeShutdown: master_pid=" << beforeReloadPid << "\n";
    };

    serv.onShutdown = [](Server *serv) {
        DEBUG() << "onShutdown\n";
        test::counter_incr(9);
    };

    ASSERT_EQ(serv.start(), 0);

    t1.join();
    delete lock;
    ASSERT_EQ(counter[1], 2);             // manager callback
    ASSERT_GE(counter[2], 2);             // manager timer
    ASSERT_GE(counter[3], 4);             // worker start
    ASSERT_EQ(test::counter_get(9), 1);   // onShutdown called
    ASSERT_EQ(test::counter_get(10), 1);  // onBeforeShutdown called
}

TEST(server, process) {
    test_process();
    test::wait_all_child_processes();
}

TEST(server, process_single_thread) {
    test_process(true);
    test::wait_all_child_processes();
}

static void test_process_send_in_user_worker() {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    swoole_set_log_level(SW_LOG_WARNING);

    test::counter_init();
    auto counter = test::counter_ptr();

    Mutex lock(Mutex::PROCESS_SHARED);
    lock.lock();

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_NE(port, nullptr);

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onUserWorkerStart = [&lock, port](Server *serv, Worker *worker) {
        lock.lock();
        DEBUG() << "onUserWorkerStart: id=" << worker->id << "\n";
        sleep(1);
        serv->shutdown();
    };

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) {
        if (worker->id == 0) {
            lock.unlock();
        }
        test::counter_incr(3);
        DEBUG() << "onWorkerStart: id=" << worker->id << "\n";
    };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        EXPECT_EQ(serv->get_connection_num(), 1);
        EXPECT_EQ(serv->get_primary_port()->get_connection_num(), 1);

        swoole_timer_after(100, [serv](TIMER_PARAMS) { serv->kill_worker(1 + swoole_random_int() % 3); });

        return SW_OK;
    };

    serv.onShutdown = [](Server *serv) {
        DEBUG() << "onShutdown\n";
        test::counter_incr(9);
    };

    ASSERT_EQ(serv.start(), 0);

    ASSERT_EQ(counter[1], 2);             // manager callback
    ASSERT_GE(counter[2], 2);             // manager timer
    ASSERT_GE(counter[3], 4);             // worker start
    ASSERT_EQ(test::counter_get(9), 1);   // onShutdown called
    ASSERT_EQ(test::counter_get(10), 1);  // onBeforeShutdown called
}

// TEST(server, process_send_in_user_worker) {
//     test_process_send_in_user_worker();
//     test::wait_all_child_processes();
// }

#ifdef SW_THREAD
TEST(server, thread) {
    Server serv(Server::MODE_THREAD);
    serv.worker_num = 2;

    swoole_set_trace_flags(SW_TRACE_THREAD);
    swoole_set_log_level(SW_LOG_TRACE);
    test::counter_init();

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

        usleep(1000);

        ASSERT_FALSE(serv.get_event_worker_pool()->read_message);
        kill(serv.get_master_pid(), SIGIO);
        usleep(1000);
        ASSERT_TRUE(serv.get_event_worker_pool()->read_message);

        DEBUG() << "shutdown\n";

        serv.shutdown();
    });

    serv.onStart = [&lock](Server *serv) {
        DEBUG() << "onStart\n";
        lock.unlock();
    };

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) {
        DEBUG() << "onWorkerStart: id=" << worker->id << "\n";
        serv->send_pipe_message(1 - worker->id, SW_STRL(TEST_STR));
    };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        DEBUG() << "send\n";

        EXPECT_EQ(serv->get_connection_num(), 1);
        EXPECT_EQ(serv->get_primary_port()->get_connection_num(), 1);

        return SW_OK;
    };

    serv.onPipeMessage = [](Server *serv, EventData *req) {
        DEBUG() << "onPipeMessage: " << string(req->data, req->info.len) << "\n";
        test::counter_incr(4);
    };

    ASSERT_EQ(serv.start(), SW_OK);
    t1.join();

    test::wait_all_child_processes();
    ASSERT_EQ(test::counter_get(4), 2);  // onPipeMessage called
}

TEST(server, task_thread) {
    DEBUG() << "new server\n";
    Server serv(Server::MODE_THREAD);
    serv.worker_num = 2;
    serv.task_worker_num = 2;

    swoole_set_log_level(SW_LOG_INFO);

    DEBUG() << "add port\n";
    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    mutex lock{};
    lock.lock();

    DEBUG() << "create server\n";
    ASSERT_EQ(serv.create(), SW_OK);

    std::thread t1([&]() {
        swoole_signal_block_all();

        lock.lock();

        network::SyncClient c(SW_SOCK_TCP);
        ASSERT_TRUE(c.connect(TEST_HOST, port->port));
        c.send(packet, strlen(packet));
        char buf[1024];
        c.recv(buf, sizeof(buf));
        c.close();

        usleep(100000);
        serv.shutdown();
    });

    std::atomic<int> count(0);

    serv.onStart = [&lock](Server *serv) {
        DEBUG() << "onStart\n";
        lock.unlock();
    };

    serv.onWorkerStart = [&lock, &count](Server *serv, Worker *worker) {
        ++count;
        DEBUG() << "onWorkerStart: id=" << worker->id << "\n";
    };

    serv.onFinish = [](Server *serv, EventData *task) -> int {
        SessionId client_fd;
        memcpy(&client_fd, task->data, sizeof(client_fd));
        string resp = string("Server: ") + string(packet);
        EXPECT_TRUE(serv->send(client_fd, resp.c_str(), resp.length()));
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

    DEBUG() << "start server\n";
    ASSERT_EQ(serv.start(), SW_OK);
    t1.join();

    ASSERT_EQ(count.load(), serv.get_core_worker_num());
    test::wait_all_child_processes();
}

TEST(server, reload_thread) {
    DEBUG() << "new server\n";
    Server serv(Server::MODE_THREAD);
    serv.worker_num = 2;
    serv.task_worker_num = 2;

    swoole_set_trace_flags(SW_TRACE_ALL);
    swoole_set_log_level(SW_LOG_TRACE);

    DEBUG() << "add port\n";
    ASSERT_NE(serv.add_port(SW_SOCK_TCP, TEST_HOST, 0), nullptr);

    Worker user_worker{};
    ASSERT_NE(serv.add_worker(&user_worker), SW_ERR);

    mutex lock{};
    lock.lock();

    DEBUG() << "create server\n";
    ASSERT_EQ(serv.create(), SW_OK);

    std::thread t1([&]() {
        swoole_thread_init();
        lock.lock();
        usleep(10000);
        EXPECT_TRUE(serv.reload(true));
        EXPECT_FALSE(serv.reload(true));  // reload again should fail
        EXPECT_ERREQ(SW_ERROR_OPERATION_NOT_SUPPORT);
        sleep(1);
        DEBUG() << "shutdown\n";
        serv.shutdown();
        swoole_thread_clean();
    });

    std::atomic<size_t> count(0);

    serv.onUserWorkerStart = [&lock, &count](Server *serv, Worker *worker) {
        DEBUG() << "onUserWorkerStart: id=" << worker->id << "\n";
        while (serv->running) {
            usleep(100000);
        }
    };

    serv.onStart = [&lock](Server *serv) { DEBUG() << "onStart\n"; };

    serv.onManagerStart = [&lock](Server *serv) {
        DEBUG() << "onManagerStart\n";
        lock.unlock();
    };

    serv.onBeforeReload = [](Server *serv) {
        DEBUG() << "onBeforeReload: master_pid=" << serv->get_manager_pid() << "\n";
    };

    serv.onAfterReload = [](Server *serv) {
        DEBUG() << "onAfterReload: master_pid=" << serv->get_manager_pid() << "\n";
    };

    serv.onWorkerStart = [&count](Server *serv, Worker *worker) {
        ++count;
        DEBUG() << "onWorkerStart: id=" << worker->id << "\n";
    };

    serv.onWorkerStop = [](Server *serv, Worker *worker) { DEBUG() << "onWorkerStop: id=" << worker->id << "\n"; };

    serv.onTask = [](Server *serv, EventData *task) -> int { return 0; };

    serv.onReceive = [](Server *serv, RecvData *req) -> int { return SW_OK; };

    DEBUG() << "start server\n";
    ASSERT_EQ(serv.start(), SW_OK);
    t1.join();
    ASSERT_EQ(count.load(), serv.get_core_worker_num() * 2);
    test::wait_all_child_processes();
}

TEST(server, reload_thread_2) {
    Server serv(Server::MODE_THREAD);
    serv.worker_num = 2;
    serv.task_worker_num = 2;

    test::counter_init();

    std::unordered_map<std::string, bool> flags;
    swoole_set_log_level(SW_LOG_INFO);

    ASSERT_NE(serv.add_port(SW_SOCK_TCP, TEST_HOST, 0), nullptr);

    Worker user_worker{};

    ASSERT_EQ(serv.add_worker(&user_worker), SW_OK);

    mutex lock;
    lock.lock();

    ASSERT_EQ(serv.create(), SW_OK);

    std::atomic<size_t> count(0);

    serv.onUserWorkerStart = [](Server *serv, Worker *worker) {
        usleep(500000);
        test::counter_incr(4, 1);
        DEBUG() << "onUserWorkerStart: id=" << worker->id << "\n";
    };

    serv.onWorkerStart = [&lock, &count](Server *serv, Worker *worker) {
        if (++count == serv->get_core_worker_num()) {
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
            EXPECT_TRUE(serv->reload(true));
        });
    };

    serv.onManagerStop = [&flags](Server *serv) { flags["onManagerStop"] = true; };

    ASSERT_EQ(serv.start(), SW_OK);

    ASSERT_TRUE(flags["onBeforeReload"]);
    ASSERT_TRUE(flags["onAfterReload"]);
    ASSERT_TRUE(flags["onManagerStop"]);
    ASSERT_TRUE(flags["reload"]);
    ASSERT_TRUE(flags["shutdown"]);
    ASSERT_GE(test::counter_get(4), 2);

    test::wait_all_child_processes();
}
#endif

TEST(server, reload_all_workers) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    serv.task_worker_num = 2;
    serv.max_wait_time = 1;
    serv.task_enable_coroutine = true;

    test::counter_init();

    swoole_set_log_level(SW_LOG_WARNING);

    serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    serv.onTask = [](Server *serv, EventData *task) -> int { return 0; };
    serv.onReceive = [](Server *serv, RecvData *data) -> int { return 0; };

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onBeforeReload = [](Server *serv) {
        test::counter_incr(10);
        DEBUG() << "onBeforeReload: master_pid=" << beforeReloadPid << "\n";
    };

    serv.onAfterReload = [](Server *serv) {
        DEBUG() << "onAfterReload: master_pid=" << beforeReloadPid << "\n";
        test::counter_incr(11);
    };

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
    ASSERT_EQ(test::counter_get(10), 2);  // onBeforeReload called
    ASSERT_EQ(test::counter_get(11), 2);  // onAfterReload called
}

TEST(server, reload_all_workers2) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    serv.task_worker_num = 2;
    serv.max_wait_time = 1;
    swoole_set_log_level(SW_LOG_WARNING);

    test::counter_init();
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

    serv.onBeforeReload = [](Server *serv) {
        test::counter_incr(10);
        DEBUG() << "onBeforeReload: master_pid=" << beforeReloadPid << "\n";
    };

    serv.onAfterReload = [](Server *serv) {
        DEBUG() << "onAfterReload: master_pid=" << beforeReloadPid << "\n";
        test::counter_incr(11);
    };

    ASSERT_EQ(serv.start(), 0);
    ASSERT_EQ(test::counter_get(10), 2);  // onBeforeReload called
    ASSERT_EQ(test::counter_get(11), 2);  // onAfterReload called
}

TEST(server, kill_user_workers) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;
    serv.task_worker_num = 2;
    serv.max_wait_time = 1;
    swoole_set_log_level(SW_LOG_WARNING);

    auto *worker1 = new Worker();
    auto *worker2 = new Worker();
    ASSERT_EQ(serv.add_worker(worker1), worker1->id);
    ASSERT_EQ(serv.add_worker(worker2), worker2->id);
    ASSERT_TRUE(serv.add_port(SW_SOCK_TCP, TEST_HOST, 0));

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onUserWorkerStart = [&](Server *serv, Worker *worker) {
        EXPECT_GT(worker->id, 0);
        while (true) {
            sleep(1);
        }
    };

    serv.onTask = [](Server *serv, EventData *task) -> int {
        while (true) {
            sleep(1);
        }
        return 0;
    };

    serv.onWorkerStart = [&](Server *serv, Worker *worker) {
        if (worker->id == 1) {
            sleep(1);
            kill(serv->get_manager_pid(), SIGTERM);
        }
    };

    serv.onReceive = [](Server *serv, RecvData *data) -> int { return 0; };

    ASSERT_EQ(serv.start(), 0);
    delete worker1;
    delete worker2;
}

TEST(server, force_kill_all_workers) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    serv.task_worker_num = 3;
    serv.max_wait_time = 1;
    swoole_set_log_level(SW_LOG_WARNING);

    auto *worker1 = new Worker();
    auto *worker2 = new Worker();
    ASSERT_EQ(serv.add_worker(worker1), worker1->id);
    ASSERT_EQ(serv.add_worker(worker2), worker2->id);
    ASSERT_TRUE(serv.add_port(SW_SOCK_TCP, TEST_HOST, 0));

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onUserWorkerStart = [&](Server *serv, Worker *worker) {
        test::counter_incr(1);
        DEBUG() << "onUserWorkerStart: id=" << worker->id << "\n";
        while (true) {
            sleep(1);
        }
    };

    serv.onTask = [](Server *serv, EventData *task) -> int { return 0; };

    serv.onWorkerStart = [&](Server *serv, Worker *worker) {
        test::counter_incr(1);
        DEBUG() << "onWorkerStart: id=" << worker->id << "\n";
        if (serv->is_task_worker()) {
            while (true) {
                sleep(1);
            }
        } else {
            swoole_timer_tick(10000, [serv](TIMER_PARAMS) {});
        }
    };

    serv.onReceive = [](Server *serv, RecvData *data) -> int { return 0; };

    serv.onManagerStart = [](Server *serv) { swoole_timer_after(200, [serv](TIMER_PARAMS) { serv->shutdown(); }); };

    ASSERT_EQ(serv.start(), 0);
    ASSERT_EQ(test::counter_get(1), 7);

    delete worker1;
    delete worker2;
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

TEST(server, create_task_worker_fail) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 1;
    serv.task_worker_num = 2;
    serv.task_enable_coroutine = true;
    serv.task_ipc_mode = Server::TASK_IPC_MSGQUEUE;
    swoole_set_log_level(SW_LOG_WARNING);

    ASSERT_TRUE(serv.add_port(SW_SOCK_TCP, TEST_HOST, 0));
    ASSERT_EQ(serv.create(), SW_ERR);
    ASSERT_ERREQ(SW_ERROR_WRONG_OPERATION);
}

#ifdef SW_USE_OPENSSL
TEST(server, ssl) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 1;
    swoole_set_log_level(SW_LOG_WARNING);

    Mutex *lock = new Mutex(Mutex::PROCESS_SHARED);
    lock->lock();

    ListenPort *port = serv.add_port(static_cast<enum swSocketType>(SW_SOCK_TCP | SW_SOCK_SSL), TEST_HOST, 0);
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

            // bad SSL connection, send plain text packet to SSL server
            network::SyncClient c2(SW_SOCK_TCP);
            c2.connect(TEST_HOST, port->port);
            c2.send(packet, strlen(packet));
            ASSERT_EQ(c2.recv(buf, sizeof(buf)), 0);
            c2.close();

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

TEST(server, ssl_error) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 1;
    swoole_set_log_level(SW_LOG_WARNING);

    Mutex lock(Mutex::PROCESS_SHARED);
    lock.lock();

    ListenPort *port = serv.add_port(static_cast<enum swSocketType>(SW_SOCK_TCP | SW_SOCK_SSL), TEST_HOST, 0);
    ASSERT_NE(port, nullptr);

    port->set_ssl_cert_file(test::get_ssl_dir() + "/server-not-exists.crt");
    port->set_ssl_key_file(test::get_ssl_dir() + "/server-not-exists.key");
    ASSERT_FALSE(port->ssl_init());
    ASSERT_ERREQ(SW_ERROR_WRONG_OPERATION);

    ASSERT_EQ(serv.create(), SW_OK);

    thread t1;

    serv.onStart = [&lock, &t1](Server *serv) {
        t1 = thread([&lock, serv]() {
            swoole_signal_block_all();

            lock.lock();

            ListenPort *port = serv->get_primary_port();
            EXPECT_EQ(port->ssl, 1);

            network::SyncClient c(SW_SOCK_TCP);
            c.connect(TEST_HOST, port->port);
            c.enable_ssl_encrypt();
            c.send(packet, strlen(packet));
            char buf[1024];
            ASSERT_EQ(c.recv(buf, sizeof(buf)), 0);
            c.close();

            kill(serv->gs->master_pid, SIGTERM);
        });
    };

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock.unlock(); };

    serv.onReceive = [](Server *serv, RecvData *req) -> int { return SW_OK; };

    serv.onConnect = [](Server *serv, DataHead *req) { test::counter_incr(0); };

    ASSERT_EQ(serv.start(), 0);

    t1.join();
    ASSERT_EQ(test::counter_get(0), 0);
}

TEST(server, ssl_write) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 1;
    swoole_set_log_level(SW_LOG_WARNING);

    Mutex lock(Mutex::PROCESS_SHARED);
    lock.lock();

    ListenPort *port = serv.add_port(static_cast<enum swSocketType>(SW_SOCK_TCP | SW_SOCK_SSL), TEST_HOST, 0);
    ASSERT_NE(port, nullptr);

    port->set_ssl_cert_file(test::get_ssl_dir() + "/server.crt");
    port->set_ssl_key_file(test::get_ssl_dir() + "/server.key");
    ASSERT_TRUE(port->ssl_init());

    ASSERT_EQ(serv.create(), SW_OK);

    String wbuf(4 * 1024 * 1024);
    wbuf.append_random_bytes(wbuf.size);

    thread t1;

    serv.onStart = [&lock, &t1, &wbuf](Server *serv) {
        t1 = thread([&lock, serv, &wbuf]() {
            swoole_signal_block_all();

            lock.lock();

            ListenPort *port = serv->get_primary_port();
            EXPECT_EQ(port->ssl, 1);

            network::SyncClient c(SW_SOCK_TCP);
            c.connect(TEST_HOST, port->port);
            c.enable_ssl_encrypt();
            c.send(packet, strlen(packet));

            String rbuf(2 * 1024 * 1024);

            while (true) {
                size_t recv_n = rbuf.size - rbuf.length;
                if (recv_n > 65536) {
                    recv_n = 65536;
                }
                auto n = c.recv(rbuf.str + rbuf.length, rbuf.size - rbuf.length);
                if (n <= 0) {
                    break;
                }
                rbuf.length += n;
                usleep(5000);
            }

            ASSERT_MEMEQ(rbuf.str, wbuf.str, rbuf.length);
            c.close();

            kill(serv->gs->master_pid, SIGTERM);
        });
    };

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock.unlock(); };

    serv.onReceive = [&wbuf](Server *serv, RecvData *req) -> int {
        EXPECT_TRUE(serv->send(req->session_id(), wbuf.str, wbuf.length));
        test::counter_incr(0);
        return SW_OK;
    };

    ASSERT_EQ(serv.start(), 0);

    t1.join();
    ASSERT_EQ(test::counter_get(0), 1);
}

TEST(server, dtls) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;
    swoole_set_log_level(SW_LOG_WARNING);

    auto *lock = new Mutex(Mutex::PROCESS_SHARED);
    lock->lock();

    auto port = serv.add_port((enum swSocketType)(SW_SOCK_UDP | SW_SOCK_SSL), TEST_HOST, 0);
    ASSERT_NE(port, nullptr);

    auto port6 = serv.add_port((enum swSocketType)(SW_SOCK_UDP6 | SW_SOCK_SSL), TEST_HOST6, 0);
    ASSERT_NE(port6, nullptr);

    port->set_ssl_cert_file(test::get_ssl_dir() + "/server.crt");
    port->set_ssl_key_file(test::get_ssl_dir() + "/server.key");
    port->ssl_init();

    port6->set_ssl_cert_file(test::get_ssl_dir() + "/server.crt");
    port6->set_ssl_key_file(test::get_ssl_dir() + "/server.key");
    port6->ssl_init();

    ASSERT_EQ(serv.create(), SW_OK);

    thread t1;
    serv.onStart = [&lock, &t1](Server *serv) {
        t1 = thread([=]() {
            swoole_signal_block_all();

            lock->lock();

            auto port = serv->ports.at(0);
            EXPECT_EQ(port->ssl, 1);

            auto cli_fn = [](network::SyncClient &c) {
                c.enable_ssl_encrypt();
                c.send(packet, strlen(packet));
                char buf[1024];
                c.recv(buf, sizeof(buf));
                c.close();
            };

            network::SyncClient c(SW_SOCK_UDP);
            c.connect(TEST_HOST, port->port);
            cli_fn(c);

            auto port6 = serv->ports.at(1);
            EXPECT_EQ(port6->ssl, 1);

            network::SyncClient c2(SW_SOCK_UDP6);
            c2.connect(TEST_HOST6, port6->port);
            cli_fn(c2);

            usleep(10000);
            serv->shutdown();
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
        delete server;
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
        serv->get_task_worker_pool()->running = 0;
        serv->gs->task_count++;
        serv->gs->tasking_num--;
        return 0;
    };

    ASSERT_EQ(serv.create(), SW_OK);

    thread t1([&serv]() {
        auto pool = serv.get_task_worker_pool();
        pool->running = true;
        pool->main_loop(pool, &pool->workers[0]);
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
    serv.get_task_worker_pool()->destroy();

    ASSERT_EQ(serv.gs->task_count, 2);
}

TEST(server, task_worker2) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 1;
    serv.task_worker_num = 2;
    test::counter_init();

    auto port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_NE(port, nullptr);

    serv.onTask = [](Server *serv, EventData *task) -> int { return 0; };

    serv.onPipeMessage = [](Server *serv, EventData *task) {
        EXPECT_MEMEQ(task->data, TEST_STR, strlen(TEST_STR));
        test::counter_incr(7);
    };

    serv.onWorkerStart = [](Server *serv, Worker *worker) {
        if (worker->id == 0) {
            swoole_timer_after(50, [serv](TIMER_PARAMS) {
                EventData ev;
                ev.info = {};
                ev.info.type = SW_SERVER_EVENT_SHUTDOWN;
                ev.info.len = 0;
                DEBUG() << "send SW_SERVER_EVENT_SHUTDOWN packet\n";
                ASSERT_GT(serv->send_to_worker_from_worker(1, &ev, SW_PIPE_MASTER | SW_PIPE_NONBLOCK), 0);
            });

            swoole_timer_after(60,
                               [serv](TIMER_PARAMS) { ASSERT_TRUE(serv->send_pipe_message(2, SW_STRL(TEST_STR))); });

            swoole_timer_after(70, [serv](TIMER_PARAMS) {
                EventData ev;
                ev.info = {};
                ev.info.type = SW_SERVER_EVENT_SHUTDOWN + 99;
                ev.info.len = 0;
                DEBUG() << "send error type packet\n";
                ASSERT_GT(serv->send_to_worker_from_worker(0, &ev, SW_PIPE_MASTER | SW_PIPE_NONBLOCK), 0);
            });

            swoole_timer_after(100, [serv](TIMER_PARAMS) { serv->shutdown(); });
        }
        test::counter_incr(1);
        DEBUG() << "onWorkerStart: id=" << worker->id << "\n";
    };

    serv.onReceive = [](Server *serv, RecvData *req) -> int { return 0; };

    ASSERT_EQ(serv.create(), SW_OK);
    ASSERT_EQ(serv.start(), SW_OK);

    ASSERT_EQ(test::counter_get(1), 4);  // onWorkerStart
    ASSERT_EQ(test::counter_get(7), 1);  // onPipeMessage
}

TEST(server, task_worker_3) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;
    serv.task_worker_num = 2;
    test::counter_init();

    auto port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_NE(port, nullptr);

    serv.onTask = [](Server *serv, EventData *task) -> int { return 0; };

    serv.onWorkerStart = [](Server *serv, Worker *worker) {
        test::counter_incr(1);
        DEBUG() << "onWorkerStart: id=" << worker->id << "\n";
        if (worker->id == 0) {
            swoole_timer_after(50, [serv](TIMER_PARAMS) { kill(serv->get_worker_pid(2), SIGTERM); });
            swoole_timer_after(60, [serv](TIMER_PARAMS) { kill(serv->get_manager_pid(), SIGRTMIN); });
            swoole_timer_after(100, [serv](TIMER_PARAMS) { serv->shutdown(); });
        }
        if (worker->id == 1 && test::counter_get(30) == 0) {
            test::counter_set(30, 1);
            swoole_timer_after(20, [serv](TIMER_PARAMS) { serv->kill_worker(-1); });
        }
    };

    serv.onReceive = [](Server *serv, RecvData *req) -> int { return 0; };

    ASSERT_EQ(serv.create(), SW_OK);
    ASSERT_EQ(serv.start(), SW_OK);

    ASSERT_EQ(test::counter_get(1), 5);  // onWorkerStart
}

TEST(server, reload_single_process) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;
    test::counter_init();

    auto port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_NE(port, nullptr);

    serv.onTask = [](Server *serv, EventData *task) -> int { return 0; };

    serv.onWorkerStart = [](Server *serv, Worker *worker) {
        if (worker->id == 0) {
            swoole_timer_after(50, [serv](TIMER_PARAMS) {
                ASSERT_FALSE(serv->reload(true));
                ASSERT_ERREQ(SW_ERROR_OPERATION_NOT_SUPPORT);
                swoole_timer_after(80, [serv](TIMER_PARAMS) { serv->shutdown(); });
            });
        }
        test::counter_incr(1);
        DEBUG() << "onWorkerStart: id=" << worker->id << "\n";
    };

    serv.onReceive = [](Server *serv, RecvData *req) -> int { return 0; };

    ASSERT_EQ(serv.create(), SW_OK);
    ASSERT_EQ(serv.start(), SW_OK);

    ASSERT_EQ(test::counter_get(1), 1);  // onWorkerStart
}

TEST(server, reload_no_task_worker) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 2;
    test::counter_init();

    auto port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_NE(port, nullptr);

    serv.onTask = [](Server *serv, EventData *task) -> int { return 0; };

    serv.onWorkerStart = [](Server *serv, Worker *worker) {
        if (worker->id == 0) {
            swoole_timer_after(50, [serv](TIMER_PARAMS) {
                ASSERT_TRUE(serv->reload(false));
                swoole_timer_after(80, [serv](TIMER_PARAMS) { serv->shutdown(); });
            });
        }
        test::counter_incr(1);
        DEBUG() << "onWorkerStart: id=" << worker->id << "\n";
    };

    serv.onReceive = [](Server *serv, RecvData *req) -> int { return 0; };

    ASSERT_EQ(serv.create(), SW_OK);
    ASSERT_EQ(serv.start(), SW_OK);

    ASSERT_EQ(test::counter_get(1), 2);  // onWorkerStart
}

static void test_task(Server::Mode mode, uint8_t task_ipc_mode = Server::TASK_IPC_UNIXSOCK) {
    Server serv(mode);
    serv.worker_num = 2;
    serv.task_ipc_mode = task_ipc_mode;
    serv.task_worker_num = 3;

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
        DEBUG() << "onWorkerStart: id=" << worker->id << "\n";
        if (worker->id == 1) {
            int _dst_worker_id = 0;

            EventData buf{};
            memset(&buf.info, 0, sizeof(buf.info));
            buf.info.len = strlen(packet);
            memcpy(buf.data, packet, strlen(packet));
            buf.info.reactor_id = worker->id;
            buf.info.ext_flags |= (SW_TASK_NONBLOCK | SW_TASK_CALLBACK);
            ASSERT_TRUE(serv->task(&buf, &_dst_worker_id));
            sleep(1);
            serv->shutdown();
        }
    };

    ASSERT_EQ(serv.start(), 0);
}

// PHP_METHOD(swoole_server, task)
TEST(server, task_base) {
    test_task(Server::MODE_BASE);
}

TEST(server, task_process) {
    test_task(Server::MODE_PROCESS);
}

TEST(server, task_ipc_stream) {
    test_task(Server::MODE_PROCESS, Server::TASK_IPC_STREAM);
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
            serv->get_task_worker_pool()->dispatch(&buf, &_dst_worker_id);
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
            serv->get_task_worker_pool()->dispatch(&buf, &_dst_worker_id);
            sleep(1);

            EventData *task_result = serv->get_task_result();
            sw_memset_zero(task_result, sizeof(*task_result));
            memset(&buf.info, 0, sizeof(buf.info));
            buf.info.len = strlen(packet);
            memcpy(buf.data, packet, strlen(packet));
            buf.info.reactor_id = worker->id;
            sw_atomic_fetch_add(&serv->gs->tasking_num, 1);
            serv->get_task_worker_pool()->dispatch(&buf, &_dst_worker_id);
            sw_atomic_fetch_add(&serv->gs->tasking_num, 0);
            kill(serv->gs->master_pid, SIGTERM);
        }
    };

    ASSERT_EQ(serv.start(), 0);
}

TEST(server, task_sync_multi_task) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    serv.task_worker_num = 3;

    std::vector<std::string> tasks;
    std::vector<std::string> results;
    int n_task = 16;
    size_t len_task = SW_IPC_MAX_SIZE * 2;
    SW_LOOP_N(n_task) {
        char data[len_task] = {};
        swoole_random_string(data, len_task - 1);
        tasks.push_back(string(data, len_task - 1));
    }

    results.resize(n_task);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    serv.onReceive = [](Server *server, RecvData *req) -> int { return SW_OK; };

    serv.onTask = [](Server *serv, EventData *task) -> int {
        PacketPtr packet{};
        String buffer(32 * 1024);
        if (!Server::task_unpack(task, &buffer, &packet)) {
            return -1;
        }
        Server::task_dump(task);
        EXPECT_TRUE(serv->finish(packet.data, packet.length, 0, task));
        return 0;
    };

    ASSERT_EQ(serv.create(), SW_OK);
    SwooleG.current_task_id = 100;

    serv.onWorkerStart = [&tasks, &results](Server *serv, Worker *worker) {
        if (worker->id == 1) {
            Server::MultiTask mt(tasks.size());
            mt.pack = [tasks](uint16_t i, EventData *buf) -> TaskId {
                auto &task = tasks.at(i);
                if (!Server::task_pack(buf, task.c_str(), task.length())) {
                    return -1;
                } else {
                    return buf->info.fd;
                }
            };

            mt.unpack = [&tasks, &results](uint16_t i, EventData *result) {
                String buffer(32 * 1024);
                PacketPtr packet;
                if (Server::task_unpack(result, &buffer, &packet)) {
                    results[i] = std::string(packet.data, packet.length);
                }
            };

            mt.fail = [&results](uint16_t i) { DEBUG() << "task failed: " << i << std::endl; };

            EXPECT_TRUE(serv->task_sync(mt, 10));

            SW_LOOP_N(tasks.size()) {
                EXPECT_EQ(tasks[i], results[i]);
            }

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
        Server::task_dump(task);
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
        usleep(100000);
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

    test::wait_all_child_processes();

    test_task_ipc(serv);
}

TEST(server, max_connection) {
    Server serv;

    auto ori_max_sockets = SwooleG.max_sockets;

    serv.set_max_connection(0);
    ASSERT_EQ(serv.get_max_connection(), SW_MIN(SW_MAX_CONNECTION, SwooleG.max_sockets));

    serv.set_max_connection(SwooleG.max_sockets + 13);
    ASSERT_EQ(serv.get_max_connection(), SwooleG.max_sockets);

    serv.set_max_connection(SwooleG.max_sockets - 13);
    ASSERT_EQ(serv.get_max_connection(), SwooleG.max_sockets - 13);

    SwooleG.max_sockets = SW_SESSION_LIST_SIZE + 1024;
    serv.set_max_connection(SW_SESSION_LIST_SIZE + 999);
    ASSERT_EQ(serv.get_max_connection(), SW_SESSION_LIST_SIZE);
    SwooleG.max_sockets = ori_max_sockets;

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

TEST(server, reopen_log2) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    swoole_set_log_level(SW_LOG_DEBUG);
    string filename = TEST_LOG_FILE;
    swoole_set_log_file(filename.c_str());

    ASSERT_TRUE(serv.add_port(SW_SOCK_TCP, TEST_HOST, 0));
    ASSERT_EQ(serv.create(), SW_OK);

    serv.onStart = [](Server *serv) {
        swoole_timer_after(50, [serv](TIMER_PARAMS) {
            serv->signal_handler_reopen_logger();
            swoole_timer_after(50, [serv](TIMER_PARAMS) { serv->shutdown(); });
        });
    };

    serv.onWorkerStart = [&filename](Server *serv, Worker *worker) { test::counter_incr(0, 1); };

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
        int status;
        waitpid(pid, &status, 0);
    } else if (pid == 0) {
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
        ASSERT_MEMEQ(buf, packet, strlen(packet));
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

    ASSERT_NE(server->add_port(SW_SOCK_TCP, TEST_HOST, 0), nullptr);
    ASSERT_NE(server->add_port(SW_SOCK_UDP, TEST_HOST, 0), nullptr);
    ASSERT_EQ(server->create(), 0);

    ASSERT_EQ(server->start(), -1);
    auto startup_error = String(server->get_startup_error_message());
    ASSERT_TRUE(startup_error.contains("require 'onTask' callback"));
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_SERVER_INVALID_CALLBACK);

    server->onTask = [](Server *server, EventData *req) -> int { return SW_OK; };

    ASSERT_EQ(server->start(), -1);
    ASSERT_NE(strstr(server->get_startup_error_message(), "require 'onReceive' callback"), nullptr);

    auto ori_log_level = swoole_get_log_level();
    swoole_set_log_level(SW_LOG_NONE);

    ASSERT_EQ(server->start(), -1);
    auto startup_error2 = std::string(server->get_startup_error_message());
    ASSERT_EQ(startup_error2, std::to_string(SW_ERROR_SERVER_INVALID_CALLBACK));
    ASSERT_EQ(swoole_get_last_error(), SW_ERROR_SERVER_INVALID_CALLBACK);

    swoole_set_log_level(ori_log_level);

    server->onReceive = [](Server *server, RecvData *req) -> int { return SW_OK; };

    ASSERT_EQ(server->start(), -1);
    ASSERT_NE(strstr(server->get_startup_error_message(), "require 'onPacket' callback"), nullptr);
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

        /**
         * After using MessageBus::move_packet(), the data pointer will be out of the control of message_bus,
         * and this part of the memory must be manually released; otherwise, a memory leak will occur.
         */
        char *data = serv->get_worker_message_bus()->move_packet();
        EXPECT_NE(data, nullptr);
        sw_free(data);

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

            ac.on_close([_serv](AsyncClient *ac) { DEBUG() << "client onClose\n"; });

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
    ASSERT_EQ(test::counter_get(0), 0);  // Server on_receive
    ASSERT_EQ(test::counter_get(1), 3);  // worker start
    ASSERT_EQ(test::counter_get(2), 1);  // Server on_close
    ASSERT_EQ(test::counter_get(3), 0);  // Client on_receive
}

TEST(server, clean_worker_1) {
    test_clean_worker(Server::MODE_BASE);
}

TEST(server, clean_worker_2) {
    test_clean_worker(Server::MODE_THREAD);
}

struct Options {
    bool reload_async = true;
    bool worker_exit_callback = false;
    bool test_shutdown_event = false;
};

static long test_timer;

static void test_kill_worker(Server::Mode mode, const Options &options) {
    Server serv(mode);
    serv.worker_num = 2;
    serv.reload_async = options.reload_async;

    test::counter_init();
    int *counter = test::counter_ptr();

    Mutex lock(Mutex::PROCESS_SHARED);
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
        DEBUG() << "worker#" << worker->id << " stop \n";
    };

    serv.onClose = [counter](Server *serv, DataHead *ev) { sw_atomic_fetch_add(&counter[2], 1); };

    serv.onWorkerStart = [counter, &options](Server *serv, Worker *worker) {
        auto c = sw_atomic_fetch_add(&counter[1], 1);
        DEBUG() << "worker#" << worker->id << " start \n";
        if (options.worker_exit_callback) {
            test_timer = swoole_timer_tick(5000, [counter](TIMER_PARAMS) {});
        }

        if (c < 2 && options.test_shutdown_event && worker->id == 0) {
            EventData ev;
            ev.info = {};
            ev.info.type = SW_SERVER_EVENT_SHUTDOWN;
            ev.info.len = 0;
            DEBUG() << "send SW_SERVER_EVENT_SHUTDOWN packet\n";
            ASSERT_GT(serv->send_to_worker_from_worker(1, &ev, SW_PIPE_MASTER | SW_PIPE_NONBLOCK), 0);
        }
    };

    if (options.worker_exit_callback) {
        serv.onWorkerExit = [counter](Server *_serv, Worker *worker) {
            swoole_timer_clear(test_timer);
            test::counter_incr(6, 1);
            DEBUG() << "worker#" << worker->id << " exit \n";
        };
    }

    serv.onStart = [&lock, &options](Server *_serv) {
        if (!sw_worker()) {
            ASSERT_FALSE(_serv->kill_worker(-1));
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

        serv.kill_worker(1 - counter[5]);

        rn = c.recv(rbuf.str, rbuf.size);
        EXPECT_EQ(rn, 0);

        sw_atomic_fetch_add(&counter[3], 1);

        usleep(50000);

        serv.shutdown();
    });

    ASSERT_EQ(serv.start(), SW_OK);
    t.join();

    ASSERT_EQ(counter[0], 1);                                    // Client receive
    ASSERT_EQ(counter[1], options.test_shutdown_event ? 4 : 3);  // Server onWorkerStart
    ASSERT_EQ(counter[2], 1);                                    // Server onClose
    ASSERT_EQ(counter[3], 1);                                    // Client close
    // counter[4] is the client fd
    // counter[5] is the worker id
    // counter[6] is the worker exit count

    if (options.worker_exit_callback) {
        ASSERT_EQ(counter[6], 3);  // Worker exit
    }
}

TEST(server, kill_worker_1) {
    Options opt;
    opt.reload_async = true;
    test_kill_worker(Server::MODE_BASE, opt);
}

TEST(server, kill_worker_2) {
    Options opt;
    opt.reload_async = true;
    test_kill_worker(Server::MODE_PROCESS, opt);
}

TEST(server, kill_worker_3) {
    Options opt;
    opt.reload_async = true;
    test_kill_worker(Server::MODE_THREAD, opt);
}

TEST(server, kill_worker_4) {
    Options opt;
    opt.reload_async = false;
    test_kill_worker(Server::MODE_BASE, opt);
}

TEST(server, kill_worker_5) {
    Options opt;
    opt.reload_async = false;
    test_kill_worker(Server::MODE_PROCESS, opt);
}

TEST(server, kill_worker_6) {
    Options opt;
    opt.reload_async = false;
    test_kill_worker(Server::MODE_THREAD, opt);
}

TEST(server, worker_exit) {
    Options opt;
    opt.worker_exit_callback = true;
    test_kill_worker(Server::MODE_PROCESS, opt);
}

TEST(server, shutdown_event) {
    Options opt;
    opt.test_shutdown_event = true;
    test_kill_worker(Server::MODE_PROCESS, opt);
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
            ASSERT_FALSE(_serv->kill_worker(-1));
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

        serv.kill_worker(counter[5]);

        rn = c.recv(rbuf.str, rbuf.size);
        EXPECT_EQ(rn, 0);

        sw_atomic_fetch_add(&counter[3], 1);

        usleep(50000);

        serv.shutdown();
    });

    ASSERT_EQ(serv.start(), SW_OK);
    t.join();

    ASSERT_EQ(counter[0], 1);  // Client receive
    ASSERT_EQ(counter[1], 3);  // Server onWorkerStart
    ASSERT_EQ(counter[2], 1);  // Server onClose
    ASSERT_EQ(counter[3], 1);  // Client close
}

TEST(server, kill_self) {
    test_kill_self(Server::MODE_BASE);
}

TEST(server, no_idle_worker) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 4;
    serv.dispatch_mode = 3;

    swoole_set_log_file(TEST_LOG_FILE);
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

            SW_LOOP_N(1024) {
                c.send(packet, strlen(packet));
            }

            sleep(3);

            c.close();

            kill(serv->gs->master_pid, SIGTERM);
        });
    };

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock->unlock(); };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        usleep(10000);
        return SW_OK;
    };

    ASSERT_EQ(serv.start(), 0);

    t1.join();
    delete lock;

    auto log = swoole::file_get_contents(TEST_LOG_FILE);
    ASSERT_TRUE(log->contains("No idle worker is available"));

    remove(TEST_LOG_FILE);
}

TEST(server, no_idle_task_worker) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 1;
    serv.task_worker_num = 4;
    serv.dispatch_mode = 3;

    swoole_set_log_file(TEST_LOG_FILE);
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

            sleep(3);
            c.close();

            kill(serv->gs->master_pid, SIGTERM);
        });
    };

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock->unlock(); };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        SW_LOOP_N(1024) {
            int _dst_worker_id = -1;
            EventData buf{};
            Server::task_pack(&buf, packet, strlen(packet));
            buf.info.ext_flags |= (SW_TASK_NONBLOCK | SW_TASK_CALLBACK);
            EXPECT_TRUE(serv->task(&buf, &_dst_worker_id));
        }
        return SW_OK;
    };

    serv.onTask = [](Server *serv, EventData *task) -> int {
        EXPECT_EQ(string(task->data, task->info.len), string(packet));
        usleep(10000);
        return 0;
    };

    ASSERT_EQ(serv.start(), 0);

    t1.join();
    delete lock;

    auto log = swoole::file_get_contents(TEST_LOG_FILE);
    ASSERT_TRUE(log->contains("No idle task worker is available"));

    remove(TEST_LOG_FILE);
}

static void test_conn_overflow(Server::Mode mode, bool send_yield) {
    Server serv(mode);
    serv.worker_num = 1;
    serv.send_yield = send_yield;
    swoole_set_log_level(SW_LOG_WARNING);

    test::counter_init();
    auto counter = test::counter_ptr();

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

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) {
        if (worker->id == 0) {
            lock->unlock();
        }
        test::counter_incr(3);
        DEBUG() << "onWorkerStart: id=" << worker->id << "\n";
    };

    serv.onReceive = [counter, send_yield](Server *serv, RecvData *req) -> int {
        auto sid = req->session_id();
        auto conn = serv->get_connection_by_session_id(sid);
        conn->overflow = 1;

        EXPECT_FALSE(serv->send(sid, SW_STRL(TEST_STR)));
        EXPECT_ERREQ(send_yield ? SW_ERROR_OUTPUT_SEND_YIELD : SW_ERROR_OUTPUT_BUFFER_OVERFLOW);

        counter[0] = 1;

        swoole_timer_after(100, [serv, sid](TIMER_PARAMS) { serv->close(sid); });

        return SW_OK;
    };

    ASSERT_EQ(serv.start(), 0);

    t1.join();
    delete lock;
    ASSERT_EQ(counter[0], 1);
    ASSERT_EQ(counter[3], 1);
}

TEST(server, overflow_1) {
    test_conn_overflow(Server::MODE_BASE, false);
}

TEST(server, overflow_2) {
    test_conn_overflow(Server::MODE_PROCESS, false);
}

TEST(server, overflow_3) {
    test_conn_overflow(Server::MODE_BASE, true);
}

TEST(server, overflow_4) {
    test_conn_overflow(Server::MODE_PROCESS, true);
}

TEST(server, send_timeout) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;
    swoole_set_log_level(SW_LOG_WARNING);

    test::counter_init();
    auto counter = test::counter_ptr();

    Mutex *lock = new Mutex(Mutex::PROCESS_SHARED);
    lock->lock();

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    port->max_idle_time = 1;

    String wbuf(2 * 1024 * 1024);
    wbuf.append_random_bytes(2 * 1024 * 1024, false);

    ASSERT_EQ(serv.create(), SW_OK);

    thread t1;
    serv.onStart = [&lock, &t1, &wbuf](Server *serv) {
        t1 = thread([=]() {
            swoole_signal_block_all();

            lock->lock();

            ListenPort *port = serv->get_primary_port();

            network::SyncClient c(SW_SOCK_TCP);
            c.connect(TEST_HOST, port->port);
            c.send(packet, strlen(packet));

            String rbuf(3 * 1024 * 1024);

            auto rn = c.recv(rbuf.str, 1024);
            EXPECT_EQ(rn, 1024);
            rbuf.length += 1024;

            sleep(2);

            while (true) {
                rn = c.recv(rbuf.str + rbuf.length, rbuf.size - rbuf.length);
                if (rn <= 0) {
                    break;
                }
                rbuf.length += rn;
            }

            EXPECT_MEMEQ(rbuf.str, wbuf.str, rbuf.length);
            c.close();

            kill(serv->gs->master_pid, SIGTERM);
        });
    };

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) {
        if (worker->id == 0) {
            lock->unlock();
        }
        test::counter_incr(3);
        DEBUG() << "onWorkerStart: id=" << worker->id << "\n";
    };

    serv.onReceive = [&wbuf](Server *serv, RecvData *req) -> int {
        auto sid = req->session_id();
        auto conn = serv->get_connection_by_session_id(sid);

        swoole_timer_del(conn->socket->recv_timer);
        conn->socket->recv_timer = nullptr;
        conn->socket->set_buffer_size(65536);

        EXPECT_TRUE(serv->send(sid, wbuf.str, wbuf.length));

        test::counter_incr(0);

        return SW_OK;
    };

    ASSERT_EQ(serv.start(), 0);

    t1.join();
    delete lock;
    ASSERT_EQ(counter[0], 1);
    ASSERT_EQ(counter[3], 1);
}

static void test_max_request(Server::Mode mode) {
    Server serv(mode);
    serv.worker_num = 2;
    serv.max_request = 128;

    Mutex *lock = new Mutex(Mutex::PROCESS_SHARED);
    lock->lock();

    ASSERT_NE(serv.add_port(SW_SOCK_TCP, TEST_HOST, 0), nullptr);
    ASSERT_EQ(serv.create(), SW_OK);

    thread t1;
    serv.onStart = [&lock, &t1](Server *serv) {
        t1 = thread([=]() {
            swoole_signal_block_all();
            lock->lock();
            ListenPort *port = serv->get_primary_port();

            auto client_fn = [&]() {
                network::SyncClient c(SW_SOCK_TCP);
                c.connect(TEST_HOST, port->port);

                SW_LOOP_N(128) {
                    if (c.send(packet, strlen(packet)) < 0) {
                        break;
                    }
                    usleep(1000);
                }
                c.close();
            };

            SW_LOOP_N(8) {
                client_fn();
                usleep(10000);
            }

            sleep(1);

            serv->shutdown();
        });
    };

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) {
        lock->unlock();
        test::counter_incr(0);
    };

    serv.onReceive = [](Server *serv, RecvData *req) -> int { return SW_OK; };

    ASSERT_EQ(serv.start(), 0);

    t1.join();
    delete lock;

    ASSERT_GE(test::counter_get(0), 8);
}

TEST(server, max_request_1) {
    test_max_request(Server::MODE_PROCESS);
}

TEST(server, max_request_2) {
    test_max_request(Server::MODE_THREAD);
}

TEST(server, watermark) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;

    Mutex *lock = new Mutex(Mutex::PROCESS_SHARED);
    lock->lock();

    String wbuf;
    wbuf.append_random_bytes(2 * 1024 * 1024);

    auto port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_NE(port, nullptr);
    ASSERT_EQ(serv.create(), SW_OK);

    port->get_socket()->set_buffer_size(65536);
    port->buffer_high_watermark = 1024 * 1024;
    port->buffer_low_watermark = 65536;

    thread t1;
    serv.onStart = [&lock, &t1](Server *serv) {
        t1 = thread([=]() {
            swoole_signal_block_all();
            lock->lock();
            ListenPort *port = serv->get_primary_port();

            network::SyncClient c(SW_SOCK_TCP);
            c.connect(TEST_HOST, port->port);
            c.get_client()->get_socket()->set_buffer_size(65536);
            c.send(packet, strlen(packet));
            usleep(1000);

            String rbuf(2 * 1024 * 1024);
            while (rbuf.length < rbuf.size) {
                auto rn = c.recv(rbuf.str + rbuf.length, 65536);
                usleep(10000);
                if (rn <= 0) {
                    break;
                }
                rbuf.length += rn;
            }

            sleep(1);
            c.close();
            serv->shutdown();
        });
    };

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) {
        lock->unlock();
        test::counter_incr(0);
    };

    serv.onReceive = [&wbuf](Server *serv, RecvData *req) -> int {
        EXPECT_TRUE(serv->send(req->session_id(), wbuf.str, wbuf.length));
        return SW_OK;
    };

    serv.onBufferEmpty = [](Server *serv, DataHead *ev) { test::counter_incr(1); };

    serv.onBufferFull = [](Server *serv, DataHead *ev) { test::counter_incr(2); };

    ASSERT_EQ(serv.start(), 0);

    t1.join();
    delete lock;

    ASSERT_GE(test::counter_get(1), 1);
    ASSERT_GE(test::counter_get(2), 1);
}

TEST(server, discard_data) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    serv.dispatch_mode = 3;
    serv.discard_timeout_request = true;
    serv.disable_notify = true;

    swoole_set_log_file(TEST_LOG_FILE);
    swoole_set_log_level(SW_LOG_WARNING);

    Mutex *lock = new Mutex(Mutex::PROCESS_SHARED);
    lock->lock();

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swoole_warning("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    ASSERT_EQ(serv.create(), SW_OK);

    String rdata;
    rdata.append_random_bytes(8192);

    thread t1;
    serv.onStart = [&lock, &t1, &rdata](Server *serv) {
        t1 = thread([&lock, &rdata, serv]() {
            swoole_signal_block_all();

            lock->lock();

            ListenPort *port = serv->get_primary_port();

            network::SyncClient c(SW_SOCK_TCP);
            c.connect(TEST_HOST, port->port);

            SW_LOOP_N(128) {
                c.send(rdata.str, rdata.length);
                usleep(10);
            }

            sleep(1);

            kill(serv->gs->master_pid, SIGTERM);
        });
    };

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock->unlock(); };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        usleep(10000);
        serv->close(req->session_id());
        return SW_OK;
    };

    ASSERT_EQ(serv.start(), 0);

    t1.join();
    delete lock;

    auto log = file_get_contents(TEST_LOG_FILE);
    DEBUG() << log->str << std::endl;
    ASSERT_TRUE(log->contains("discard_data() (ERRNO 1007)"));
    remove(TEST_LOG_FILE);
}

TEST(server, worker_set_isolation) {
    Server::worker_set_isolation("not-exists-group", "not-exists-user", "/tmp/not-exists-dir");
}

TEST(server, pause_and_resume) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 2;

    swoole_set_log_level(SW_LOG_TRACE);

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    Mutex lock(Mutex::PROCESS_SHARED);
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
        auto t1 = microtime();
        ASSERT_EQ(c.recv(buf, sizeof(buf)), strlen(packet) + 8);
        auto t2 = microtime();
        ASSERT_GE(t2 - t1, 0.048);  // Ensure that the pause and resume took some time
        string resp = string("Server: ") + string(packet);
        ASSERT_MEMEQ(buf, resp.c_str(), resp.length());
        c.close();

        usleep(1000);
        DEBUG() << "shutdown\n";
        serv.shutdown();
    });

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock.unlock(); };

    serv.onConnect = [](Server *serv, DataHead *ev) {
        auto session_id = ev->fd;
        DEBUG() << "onConnect: fd=" << session_id << ", reactor_id=" << ev->reactor_id << std::endl;
        ASSERT_TRUE(serv->feedback(serv->get_connection_by_session_id(session_id), SW_SERVER_EVENT_PAUSE_RECV));
        DEBUG() << "pause recv ok, session_id=" << session_id << std::endl;
        swoole_timer_after(50, [ev, serv, session_id](TIMER_PARAMS) {
            ASSERT_TRUE(serv->feedback(serv->get_connection_by_session_id(session_id), SW_SERVER_EVENT_RESUME_RECV));
            DEBUG() << "resume recv ok, session_id=" << session_id << std::endl;
        });
    };

    serv.onReceive = [](Server *serv, RecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));
        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());
        return SW_OK;
    };

    serv.start();
    t1.join();
}

TEST(server, max_queued_bytes) {
    Server serv(Server::MODE_PROCESS);
    serv.worker_num = 2;
    serv.max_queued_bytes = 65536;

    test::counter_init();
    swoole_set_log_level(SW_LOG_TRACE);

    int buffer_size = 65536;
    int send_count = 256;

    ListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    Mutex lock(Mutex::PROCESS_SHARED);
    lock.lock();

    ASSERT_EQ(serv.create(), SW_OK);

    std::thread t1([&]() {
        swoole_signal_block_all();
        lock.lock();

        usleep(1000);

        String wbuf;
        wbuf.append_random_bytes(buffer_size);

        network::SyncClient c(SW_SOCK_TCP);
        ASSERT_TRUE(c.connect(TEST_HOST, port->port));
        SW_LOOP_N(send_count) {
            ASSERT_EQ(c.send(wbuf.str, wbuf.length), wbuf.length);
        }
        char buf[1024];
        ASSERT_EQ(c.recv(buf, sizeof(buf)), strlen(TEST_STR));
        c.close();

        usleep(1000);
        DEBUG() << "shutdown\n";
        serv.shutdown();
    });

    serv.onWorkerStart = [&lock](Server *serv, Worker *worker) { lock.unlock(); };

    serv.onConnect = [](Server *serv, DataHead *ev) { usleep(100000); };

    serv.onReceive = [=](Server *serv, RecvData *req) -> int {
        if (test::counter_incr(0, req->info.len) == send_count * buffer_size) {
            serv->send(req->session_id(), SW_STRL(TEST_STR));
        }
        return SW_OK;
    };

    serv.start();
    t1.join();
    ASSERT_EQ(send_count * buffer_size, test::counter_get(0));
}

TEST(server, ssl_matches_wildcard_name) {
    // Test exact match
    {
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("example.com", "example.com"));
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("test.example.com", "test.example.com"));
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("EXAMPLE.COM", "example.com"));  // Case insensitive
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("example.com", "EXAMPLE.COM"));  // Case insensitive
    }

    // Test no match
    {
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("example.com", "example.org"));
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("test.example.com", "test.example.org"));
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("sub.example.com", "example.com"));
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("example.com", "sub.example.com"));
    }

    // Test wildcard in leftmost component
    {
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("test.example.com", "*.example.com"));
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("sub.example.com", "*.example.com"));
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("TEST.example.com", "*.example.com"));  // Case insensitive
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("test.example.com", "*.EXAMPLE.COM"));  // Case insensitive
    }

    // Test wildcard with prefix
    {
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("subtest.example.com", "sub*.example.com"));
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("subthing.example.com", "sub*.example.com"));
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("wrongtest.example.com", "sub*.example.com"));
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("test.example.com", "sub*.example.com"));
    }

    // Test wildcard in non-leftmost component (should fail)
    {
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("test.example.com", "test.*.com"));
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("test.sub.example.com", "test.*.example.com"));
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("example.com", "example.*"));
    }

    // Test wildcard with dot in prefix (should fail)
    {
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("test.example.com", "test.*.com"));
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("sub.test.example.com", "sub.*.example.com"));
    }

    // Test multiple wildcards (only first one should be considered)
    {
        // EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("test.example.com", "*.*example.com"));
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("test.sub.example.com", "*.*example.com"));
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("test.example.com", "*.*"));
    }

    // Test wildcard matching with dots between prefix and suffix
    {
        // These should fail because there's a dot between the prefix and suffix
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("test.sub.example.com", "*.example.com"));
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("a.b.c.example.com", "*.example.com"));

        // This should pass because there's no dot in the wildcard portion
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("testexample.com", "*example.com"));
    }

    // Test suffix length conditions
    {
        // Suffix longer than subject (should fail)
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("test.com", "*.example.com"));
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("short", "*.verylongdomain.com"));

        // Suffix exactly matches subject length (edge case)
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("example.com", "*.example.com"));
    }

    // Test empty strings and edge cases
    {
        // EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("", ""));
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("example.com", ""));
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("", "example.com"));
        // EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("", "*"));
        // EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("test", "*"));
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("*", "*"));  // Exact match
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("test", "*est"));
    }

    // Test wildcard at beginning with no prefix
    {
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("test.example.com", "*.example.com"));
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("example.com", "*example.com"));
        // EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("test.example.com", "*test.example.com"));
    }

    // Test wildcard at end with no suffix
    {
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("example.com", "example*"));
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("example.com", "example.*"));
    }

    // Test practical examples from real-world scenarios
    {
        // Common wildcard cert patterns
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("www.example.com", "*.example.com"));
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("api.example.com", "*.example.com"));
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("login.example.com", "*.example.com"));

        // Subdomain matching
        EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("sub.api.example.com", "*.example.com"));
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("sub.api.example.com", "*.api.example.com"));

        // IP addresses (wildcards shouldn't work with IPs in practice)
        // EXPECT_FALSE(ListenPort::ssl_matches_wildcard_name("192.168.1.1", "*.168.1.1"));

        // Partial wildcard matches
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("dev-server.example.com", "dev-*.example.com"));
        EXPECT_TRUE(ListenPort::ssl_matches_wildcard_name("staging-server.example.com", "*-server.example.com"));
    }
}

TEST(server, wait_other_worker) {
    Server serv(Server::MODE_BASE);
    serv.worker_num = 1;
    serv.task_worker_num = 2;
    test::counter_init();

    auto port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_NE(port, nullptr);

    serv.onWorkerStart = [](Server *serv, Worker *worker) {
        test::counter_incr(1);
        DEBUG() << "onWorkerStart: id=" << worker->id << "\n";
    };

    ASSERT_EQ(serv.create(), SW_OK);

    ExitStatus fake_exit(getpid(), 0);
    auto pool = serv.get_task_worker_pool();
    auto worker = serv.get_worker(2);
    worker->pid = getpid();
    pool->add_worker(worker);
    serv.wait_other_worker(pool, fake_exit);

    test::wait_all_child_processes();

    ASSERT_EQ(test::counter_get(1), 1);
}
