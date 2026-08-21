#include "test_core.h"
#include "swoole_process_pool.h"

#include <csignal>

#ifdef __MACH__
#define sysv_signal signal
#endif

#include "swoole_signal.h"
#include <sys/ipc.h>
#include <sys/msg.h>
#include <string>
#include <vector>
using namespace swoole;

constexpr int magic_number = 99900011;
static ProcessPool *current_pool = nullptr;
static Worker *current_worker = nullptr;

static void test_func(ProcessPool &pool) {
    EventData data{};
    size_t size = swoole_system_random(1024, 4096);
    String rmem(size);
    rmem.append_random_bytes(size - 1);
    rmem.append("\0");

    data.info.len = size;
    memcpy(data.data, rmem.value(), size);

    DEBUG() << "dispatch: " << size << " bytes\n";

    int worker_id = -1;
    ASSERT_EQ(pool.dispatch_sync(&data, &worker_id), SW_OK);

    pool.running = true;
    pool.ptr = &rmem;
    if (pool.onWorkerStart) {
        pool.onWorkerStart(&pool, pool.get_worker(0));
    }
    pool.main_loop(&pool, pool.get_worker(0));
    pool.destroy();
}

static void test_func_task_protocol(ProcessPool &pool) {
    pool.set_protocol(SW_PROTOCOL_TASK);
    pool.onTask = [](ProcessPool *pool, Worker *worker, EventData *task) -> int {
        pool->running = false;
        auto *_data = (String *) pool->ptr;
        usleep(10000);
        EXPECT_MEMEQ(_data->str, task->data, task->len());
        return 0;
    };
    test_func(pool);
}

static void test_func_message_protocol(ProcessPool &pool) {
    pool.set_protocol(SW_PROTOCOL_MESSAGE);
    pool.onMessage = [](ProcessPool *pool, RecvData *rdata) {
        pool->running = false;
        String *_data = static_cast<String *>(pool->ptr);
        usleep(10000);

        DEBUG() << "received: " << rdata->info.len << " bytes\n";
        EXPECT_MEMEQ(_data->str, rdata->data, rdata->info.len);
    };
    test_func(pool);
}

static void test_func_stream_protocol(ProcessPool &pool) {
    pool.set_protocol(SW_PROTOCOL_STREAM);
    pool.onMessage = [](ProcessPool *pool, RecvData *rdata) {
        pool->running = false;
        String *_data = (String *) pool->ptr;
        EventData *msg = (EventData *) rdata->data;
        usleep(10000);

        DEBUG() << "received: " << rdata->info.len << " bytes\n";
        EXPECT_MEMEQ(_data->str, msg->data, msg->len());
    };
    test_func(pool);
}

TEST(process_pool, tcp) {
    ProcessPool pool{};
    int svr_port = TEST_PORT + __LINE__;
    ASSERT_EQ(pool.create(1, 0, SW_IPC_SOCKET), SW_OK);
    ASSERT_EQ(pool.listen(TEST_HOST, svr_port, 128), SW_OK);

    test_func_task_protocol(pool);
}

TEST(process_pool, unix_sock) {
    ProcessPool pool{};
    signal(SIGPIPE, SIG_IGN);
    ASSERT_EQ(pool.create(1, 0, SW_IPC_UNIXSOCK), SW_OK);
    ASSERT_EQ(pool.listen(TEST_HOST, TEST_PORT, 128), SW_ERR);
    ASSERT_ERREQ(SW_ERROR_OPERATION_NOT_SUPPORT);
    ASSERT_EQ(pool.listen(TEST_SOCK_FILE, 128), SW_ERR);
    ASSERT_ERREQ(SW_ERROR_OPERATION_NOT_SUPPORT);

    test_func_task_protocol(pool);
}

TEST(process_pool, tcp_raw) {
    ProcessPool pool{};
    constexpr int size = 2 * 1024 * 1024;
    int svr_port = TEST_PORT + __LINE__;
    ASSERT_EQ(pool.create(1, 0, SW_IPC_SOCKET), SW_OK);
    ASSERT_EQ(pool.listen(TEST_HOST, svr_port, 128), SW_OK);
    pool.set_max_packet_size(size);
    pool.set_protocol(SW_PROTOCOL_STREAM);

    String data(size);
    data.append_random_bytes(size - 1);
    data.append("\0");

    ASSERT_EQ(pool.dispatch_sync(data.str, data.length), SW_OK);

    pool.running = true;
    pool.ptr = &data;
    pool.onMessage = [](ProcessPool *pool, RecvData *rdata) -> void {
        pool->running = false;
        String *_data = (String *) pool->ptr;
        EXPECT_MEMEQ(_data->str, rdata->data, rdata->info.len);
    };
    pool.main_loop(&pool, pool.get_worker(0));
    pool.destroy();
}

#ifdef HAVE_MSGQUEUE
TEST(process_pool, msgqueue) {
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0x9501, SW_IPC_MSGQUEUE), SW_OK);

    test_func_task_protocol(pool);
}

TEST(process_pool, msgqueue_2) {
    auto key = 0x9501 + __LINE__;
    auto msg_id_ = msgget(key, IPC_CREAT);
    ASSERT_GE(msg_id_, 0);

    test::spawn_exec_and_wait([key]() {
        ProcessPool pool{};
        swoole_set_isolation("", "nobody", "");
        ASSERT_EQ(pool.create(1, key, SW_IPC_MSGQUEUE), SW_ERR);
        ASSERT_ERREQ(EACCES);
    });
}
#endif

TEST(process_pool, message_protocol) {
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0, SW_IPC_UNIXSOCK), SW_OK);

    test_func_message_protocol(pool);
}

TEST(process_pool, message_protocol_with_timer) {
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0, SW_IPC_UNIXSOCK), SW_OK);

    pool.set_protocol(SW_PROTOCOL_MESSAGE);

    swoole_signal_set(SIGTERM, [](int) {
        DEBUG() << "received  SIGTERM signal\n";
        current_pool->running = false;
    });

    pool.onWorkerStart = [](ProcessPool *pool, Worker *worker) {
        DEBUG() << "onStart\n";
        current_pool = pool;
        swoole_timer_after(50, [pool](TIMER_PARAMS) {
            DEBUG() << "kill master\n";
            kill(getpid(), SIGTERM);
        });
    };

    pool.onMessage = [](ProcessPool *pool, RecvData *rdata) {
        auto *_data = static_cast<String *>(pool->ptr);
        usleep(10000);

        DEBUG() << "received: " << rdata->info.len << " bytes\n";
        EXPECT_MEMEQ(_data->str, rdata->data, rdata->info.len);
    };

    test_func(pool);
}

TEST(process_pool, stream_protocol) {
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0, SW_IPC_UNIXSOCK), SW_OK);

    test_func_stream_protocol(pool);
}

TEST(process_pool, stream_protocol_with_msgq) {
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0x9501, SW_IPC_MSGQUEUE), SW_OK);

    test_func_stream_protocol(pool);
}

TEST(process_pool, shutdown) {
    ProcessPool pool{};
    int *shm_value = (int *) sw_mem_pool()->alloc(sizeof(int));
    ASSERT_EQ(pool.create(1, 0x9501, SW_IPC_MSGQUEUE), SW_OK);

    // init
    pool.set_max_packet_size(8192);
    pool.set_protocol(SW_PROTOCOL_TASK);
    pool.ptr = shm_value;
    pool.onWorkerStart = [](ProcessPool *pool, Worker *worker) {
        int *shm_value = (int *) pool->ptr;
        *shm_value = magic_number;
        usleep(1);
    };

    pool.onTask = [](ProcessPool *pool, Worker *worker, EventData *task) -> int {
        usleep(1000);
        kill(pool->master_pid, SIGTERM);
        return 0;
    };

    pool.onStart = [](ProcessPool *pool) {
        EventData msg{};
        msg.info.len = 128;
        swoole_random_string(msg.data, msg.info.len);
        int worker_id = -1;
        pool->dispatch_sync(&msg, &worker_id);
    };

    current_pool = &pool;
    sysv_signal(SIGTERM, [](int sig) { current_pool->running = false; });

    // start
    ASSERT_EQ(pool.start(), SW_OK);
    // wait
    ASSERT_EQ(pool.wait(), SW_OK);

    pool.destroy();

    ASSERT_EQ(*shm_value, magic_number);

    sysv_signal(SIGTERM, SIG_DFL);
}

TEST(process_pool, reload) {
    ProcessPool pool{};
    test::counter_init();
    ASSERT_EQ(pool.create(2), SW_OK);

    // init
    pool.set_max_packet_size(8192);
    pool.max_wait_time = 1;

    pool.onWorkerStart = [](ProcessPool *pool, Worker *worker) {
        test::counter_incr(0);
        current_pool = pool;

        DEBUG() << "onWorkerStart " << worker->id << "\n";

        sysv_signal(SIGTERM, SIG_IGN);
        sysv_signal(SIGRTMIN, [](int) { current_pool->reopen_logger(); });
        sysv_signal(SIGWINCH, [](int) { current_pool->reopen_logger(); });

        while (true) {
            sleep(10000);
        }
    };

    pool.onStart = [](ProcessPool *pool) {
        pool->reopen_logger();
        swoole_timer_after(50, [pool](TIMER_PARAMS) { kill(pool->get_worker(0)->pid, SIGRTMIN); });
        swoole_timer_after(100, [pool](TIMER_PARAMS) { pool->reload(); });
    };

    pool.onBeforeReload = [](ProcessPool *pool) { DEBUG() << "onBeforeReload\n"; };

    pool.onAfterReload = [](ProcessPool *pool) {
        DEBUG() << "onAfterReload\n";
        swoole_timer_after(100, [pool](TIMER_PARAMS) { pool->shutdown(); });
    };

    pid_t other_child_pid = test::spawn_exec([]() {
        usleep(10000);
        exit(123);
    });
    test::counter_set(20, other_child_pid);

    pool.onWorkerError = [](ProcessPool *pool, Worker *worker, const ExitStatus &exit_status) {
        DEBUG() << "onWorkerError " << exit_status.get_pid() << "\n";
        ASSERT_EQ(exit_status.get_signal(), SIGKILL);
    };

    pool.onWorkerMessage = [](ProcessPool *pool, EventData *msg) {
        DEBUG() << "onWorkerMessage: type " << msg->info.type << ", content=" << std::string(msg->data, msg->info.len);
        EXPECT_EQ(msg->info.type, SW_WORKER_MESSAGE_STOP + 1);
        EXPECT_MEMEQ(msg->data, TEST_STR, msg->info.len);
    };

    pool.onWorkerNotFound = [](ProcessPool *pool, const ExitStatus &exit_status) -> int {
        DEBUG() << "onWorkerNotFound " << exit_status.get_pid() << "\n";
        EXPECT_EQ(exit_status.get_pid(), test::counter_get(20));
        EXPECT_EQ(exit_status.get_code(), 123);
        EXPECT_EQ(pool->push_message(SW_WORKER_MESSAGE_STOP + 1, SW_STRL(TEST_STR)), SW_OK);
        return SW_OK;
    };

    current_pool = &pool;
    sysv_signal(SIGTERM, [](int sig) { current_pool->running = false; });
    sysv_signal(SIGIO, [](int sig) { current_pool->read_message = true; });

    ASSERT_EQ(pool.start(), SW_OK);
    ASSERT_EQ(pool.wait(), SW_OK);

    pool.destroy();

    ASSERT_EQ(test::counter_get(0), 4);

    sysv_signal(SIGTERM, SIG_DFL);
}

static void test_async_pool() {
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0, SW_IPC_UNIXSOCK), SW_OK);

    // init
    pool.set_max_packet_size(8192);
    pool.set_protocol(SW_PROTOCOL_TASK);
    pool.async = true;
    test::counter_init();

    pool.onStart = [](ProcessPool *pool) {
        current_pool = pool;
        sysv_signal(SIGTERM, [](int sig) { current_pool->running = false; });
    };

    pool.onWorkerStart = [](ProcessPool *pool, Worker *worker) {
        test::counter_set(0, magic_number);
        current_worker = worker;
        current_pool = pool;
        sysv_signal(SIGTERM, [](int sig) { current_pool->running = false; });

        swoole_signal_set(SIGTERM, [](int sig) {
            DEBUG() << "value: " << test::counter_incr(0) << "; "
                    << "SIGTERM, stop worker\n";
            current_pool->stop(current_worker);
        });

        usleep(10);
    };

    pool.onMessage = [](ProcessPool *pool, RecvData *msg) {
        DEBUG() << "value: " << test::counter_incr(0) << "; "
                << "onMessage, kill\n";
        kill(pool->master_pid, SIGTERM);
    };

    // start
    ASSERT_EQ(pool.start(), SW_OK);

    EventData msg{};
    msg.info.len = 128;
    swoole_random_string(msg.data, msg.info.len);
    int worker_id = -1;
    pool.dispatch_sync(&msg, &worker_id);

    // wait
    ASSERT_EQ(pool.wait(), SW_OK);

    pool.destroy();

    ASSERT_EQ(test::counter_get(0), magic_number + 2);

    swoole_signal_clear();
    sysv_signal(SIGTERM, SIG_DFL);
}

TEST(process_pool, async) {
    test_async_pool();
    // ASSERT_EQ(test::spawn_exec_and_wait([]() { test_async_pool(); }), 0);
}

static void test_async_pool_with_mb() {
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0, SW_IPC_UNIXSOCK), SW_OK);
    ASSERT_EQ(pool.create_message_bus(), SW_OK);

    if (swoole_timer_is_available()) {
        swoole_timer_free();
    }
    swoole_signal_clear();

    // init
    pool.set_max_packet_size(8192);
    pool.set_protocol(SW_PROTOCOL_TASK);
    test::counter_init();
    pool.async = true;

    pool.onWorkerStart = [](ProcessPool *pool, Worker *worker) {
        current_worker = worker;
        current_pool = pool;

        test::counter_incr_and_put_log(0, "onWorkerStart");

        swoole_signal_set(SIGTERM, [](int sig) {
            test::counter_incr_and_put_log(0, "SIGTERM, stop worker");
            current_pool->stop(sw_worker());
        });

        usleep(10);
    };

    pool.onWorkerStop = [](ProcessPool *pool, Worker *worker) {
        current_worker = worker;
        current_pool = pool;

        test::counter_incr_and_put_log(0, "onWorkerStop");
    };

    pool.onWorkerExit = [](ProcessPool *pool, Worker *worker) { test::counter_incr_and_put_log(0, "onWorkerExit"); };

    pool.onStart = [](ProcessPool *pool) {
        current_pool = pool;
        swoole_signal_set(SIGTERM, [](int sig) { current_pool->running = false; });
        swoole_signal_set(SIGIO, [](int sig) { current_pool->read_message = true; });

        test::counter_incr_and_put_log(0, "onStart");

        swoole_timer_after(100, [pool](TIMER_PARAMS) {
            pool->send_message(0, SW_STRL("detach"));

            swoole_timer_after(100, [pool](TIMER_PARAMS) { pool->send_message(0, SW_STRL("shutdown")); });
        });
    };

    pool.onShutdown = [](ProcessPool *pool) { test::counter_incr_and_put_log(0, "onShutdown"); };

    pool.onMessage = [](ProcessPool *pool, RecvData *msg) {
        auto req = std::string(msg->data, msg->info.len);

        if (req == "detach") {
            test::counter_incr_and_put_log(0, "onMessage, detach");
            ASSERT_TRUE(pool->detach());
        } else if ((req == "shutdown")) {
            test::counter_incr_and_put_log(0, "onMessage, shutdown");
            pool->shutdown();
        }
    };

    // start
    ASSERT_EQ(pool.start(), SW_OK);
    // wait
    ASSERT_EQ(pool.wait(), SW_OK);

    pool.destroy();

    ASSERT_GE(test::counter_get(0), 8);

    swoole_signal_clear();
    sysv_signal(SIGTERM, SIG_DFL);
    sysv_signal(SIGIO, SIG_DFL);
}

TEST(process_pool, async_mb) {
    test_async_pool_with_mb();
}

TEST(process_pool, mb1) {
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0, SW_IPC_NONE), SW_OK);
    ASSERT_EQ(pool.create_message_bus(), SW_ERR);
    ASSERT_ERREQ(SW_ERROR_OPERATION_NOT_SUPPORT);

    pool.destroy();
}

TEST(process_pool, mb2) {
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0, SW_IPC_UNIXSOCK), SW_OK);
    ASSERT_EQ(pool.create_message_bus(), SW_OK);
    ASSERT_EQ(pool.create_message_bus(), SW_ERR);
    ASSERT_ERREQ(SW_ERROR_WRONG_OPERATION);

    pool.destroy();
}

TEST(process_pool, socket) {
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0, SW_IPC_SOCKET), SW_OK);
    ASSERT_EQ(pool.start(), SW_ERR);
    ASSERT_ERREQ(SW_ERROR_WRONG_OPERATION);

    pool.destroy();
}

TEST(process_pool, listen) {
    ProcessPool pool{};
    auto port = TEST_PORT + __LINE__;
    ASSERT_EQ(pool.create(1, 0, SW_IPC_SOCKET), SW_OK);
    ASSERT_EQ(pool.listen("127.0.0.1", port, 128), SW_OK);

    pool.set_protocol(SW_PROTOCOL_STREAM);

    size_t size = 2048;
    String rmem(size);
    rmem.append_random_bytes(size - 1);
    rmem.append('\0');

    String wmem(size);
    wmem.append_random_bytes(size - 1);
    wmem.append('\0');

    pool.ptr = &wmem;

    pool.onMessage = [](ProcessPool *pool, RecvData *msg) {
        String *wmem = (String *) pool->ptr;
        ASSERT_EQ(pool->response(wmem->str, wmem->length), SW_OK);
        ASSERT_EQ(pool->response(nullptr, 999), SW_ERR);
        ASSERT_ERREQ(SW_ERROR_INVALID_PARAMS);
        ASSERT_EQ(pool->response(wmem->str, 0), SW_ERR);
        ASSERT_ERREQ(SW_ERROR_INVALID_PARAMS);
    };

    current_pool = &pool;
    sysv_signal(SIGTERM, [](int sig) { current_pool->running = false; });

    ASSERT_EQ(pool.start(), SW_OK);

    std::thread t1([&]() {
        swoole_signal_block_all();

        network::SyncClient c(SW_SOCK_TCP);
        c.connect("127.0.0.1", port);

        uint32_t pkt_len = htonl(rmem.length);

        c.send((char *) &pkt_len, sizeof(pkt_len));
        c.send(rmem.str, rmem.length);
        char buf[4096];

        EXPECT_EQ(c.recv((char *) &pkt_len, sizeof(pkt_len)), 4);
        c.recv(buf, ntohl(pkt_len));

        EXPECT_MEMEQ(buf, wmem.str, wmem.length);

        ASSERT_EQ(pool.response(wmem.str, wmem.length), SW_ERR);
        ASSERT_ERREQ(SW_ERROR_INVALID_PARAMS);

        c.close();

        kill(getpid(), SIGTERM);
    });

    ASSERT_EQ(pool.wait(), SW_OK);
    pool.destroy();

    sysv_signal(SIGTERM, SIG_DFL);

    t1.join();
}

TEST(process_pool, listen_rejects_truncated_stream_packet) {
    ProcessPool pool{};
    auto port = swoole::test::get_random_port();
    ASSERT_EQ(pool.create(1, 0, SW_IPC_SOCKET), SW_OK);
    ASSERT_EQ(pool.listen("127.0.0.1", port, 128), SW_OK);

    pool.set_max_packet_size(64);
    pool.set_protocol(SW_PROTOCOL_STREAM);

    std::vector<std::string> messages;
    pool.ptr = &messages;
    pool.onMessage = [](ProcessPool *pool, RecvData *msg) {
        auto *messages = static_cast<std::vector<std::string> *>(pool->ptr);
        messages->emplace_back(msg->data, msg->info.len);
        if (messages->back() == "sentinel") {
            pool->running = false;
        }
    };

    network::SyncClient c1(SW_SOCK_TCP);
    network::SyncClient c2(SW_SOCK_TCP);
    network::SyncClient c3(SW_SOCK_TCP);
    ASSERT_TRUE(c1.connect("127.0.0.1", port));
    ASSERT_TRUE(c2.connect("127.0.0.1", port));
    ASSERT_TRUE(c3.connect("127.0.0.1", port));

    uint32_t packet_len = htonl(8);
    ASSERT_EQ(c1.send((char *) &packet_len, sizeof(packet_len)), static_cast<ssize_t>(sizeof(packet_len)));
    ASSERT_EQ(c1.send(SW_STRL("message1")), 8);
    ASSERT_EQ(c2.send((char *) &packet_len, sizeof(packet_len)), static_cast<ssize_t>(sizeof(packet_len)));
    ASSERT_EQ(c2.send(SW_STRL("xx")), 2);
    ASSERT_EQ(c2.get_client()->shutdown(SHUT_WR), SW_OK);
    ASSERT_EQ(c3.send((char *) &packet_len, sizeof(packet_len)), static_cast<ssize_t>(sizeof(packet_len)));
    ASSERT_EQ(c3.send(SW_STRL("sentinel")), 8);

    auto *worker = pool.get_worker(0);
    worker->init();
    pool.running = true;
    pool.main_loop(&pool, worker);
    pool.destroy();

    ASSERT_EQ(messages.size(), 2);
    EXPECT_EQ(messages[0], "message1");
    EXPECT_EQ(messages[1], "sentinel");
}

TEST(process_pool, listen_rejects_truncated_task_packet) {
    ProcessPool pool{};
    auto port = swoole::test::get_random_port();
    ASSERT_EQ(pool.create(1, 0, SW_IPC_SOCKET), SW_OK);
    ASSERT_EQ(pool.listen("127.0.0.1", port, 128), SW_OK);
    pool.set_protocol(SW_PROTOCOL_TASK);

    std::vector<std::string> messages;
    pool.ptr = &messages;
    pool.onTask = [](ProcessPool *pool, Worker *worker, EventData *task) -> int {
        auto *messages = static_cast<std::vector<std::string> *>(pool->ptr);
        messages->emplace_back(task->data, task->info.len);
        if (messages->back() == "sentinel") {
            pool->running = false;
        }
        return SW_OK;
    };

    EventData event1{};
    EventData event2{};
    EventData event3{};
    event1.info.len = 8;
    event2.info.len = 8;
    event3.info.len = 8;
    memcpy(event1.data, SW_STRL("message1"));
    memcpy(event2.data, SW_STRL("xx"));
    memcpy(event3.data, SW_STRL("sentinel"));

    network::SyncClient c1(SW_SOCK_TCP);
    network::SyncClient c2(SW_SOCK_TCP);
    network::SyncClient c3(SW_SOCK_TCP);
    ASSERT_TRUE(c1.connect("127.0.0.1", port));
    ASSERT_TRUE(c2.connect("127.0.0.1", port));
    ASSERT_TRUE(c3.connect("127.0.0.1", port));

    uint32_t packet_len = htonl(event1.size());
    ASSERT_EQ(c1.send((char *) &packet_len, sizeof(packet_len)), static_cast<ssize_t>(sizeof(packet_len)));
    ASSERT_EQ(c1.send(reinterpret_cast<char *>(&event1), event1.size()), event1.size());

    packet_len = htonl(event2.size());
    ASSERT_EQ(c2.send((char *) &packet_len, sizeof(packet_len)), static_cast<ssize_t>(sizeof(packet_len)));
    ASSERT_EQ(c2.send(reinterpret_cast<char *>(&event2), sizeof(event2.info) + 2),
              static_cast<ssize_t>(sizeof(event2.info) + 2));
    ASSERT_EQ(c2.get_client()->shutdown(SHUT_WR), SW_OK);

    packet_len = htonl(event3.size());
    ASSERT_EQ(c3.send((char *) &packet_len, sizeof(packet_len)), static_cast<ssize_t>(sizeof(packet_len)));
    ASSERT_EQ(c3.send(reinterpret_cast<char *>(&event3), event3.size()), event3.size());

    auto *worker = pool.get_worker(0);
    worker->init();
    pool.running = true;
    pool.main_loop(&pool, worker);
    pool.destroy();

    ASSERT_EQ(messages.size(), 2);
    EXPECT_EQ(messages[0], "message1");
    EXPECT_EQ(messages[1], "sentinel");
}

const char *test_sock = "/tmp/swoole_process_pool.sock";

TEST(process_pool, listen_unixsock) {
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0, SW_IPC_SOCKET), SW_OK);
    ASSERT_EQ(pool.listen(test_sock, 128), SW_OK);

    pool.set_protocol(SW_PROTOCOL_STREAM);

    size_t size = 2048;
    String rmem(size);
    rmem.append_random_bytes(size - 1);
    rmem.append('\0');

    String wmem(size);
    wmem.append_random_bytes(size - 1);
    wmem.append('\0');

    pool.ptr = &wmem;

    pool.onMessage = [](ProcessPool *pool, RecvData *msg) {
        String *wmem = (String *) pool->ptr;
        pool->response(wmem->str, wmem->length);
    };

    current_pool = &pool;
    sysv_signal(SIGTERM, [](int sig) { current_pool->running = false; });

    ASSERT_EQ(pool.start(), SW_OK);

    std::thread t1([&]() {
        swoole_signal_block_all();

        network::SyncClient c(SW_SOCK_UNIX_STREAM);
        c.connect(test_sock, 0);

        uint32_t pkt_len = htonl(rmem.length);

        c.send((char *) &pkt_len, sizeof(pkt_len));
        c.send(rmem.str, rmem.length);
        char buf[4096];

        EXPECT_EQ(c.recv((char *) &pkt_len, sizeof(pkt_len)), 4);
        c.recv(buf, ntohl(pkt_len));

        EXPECT_MEMEQ(buf, wmem.str, wmem.length);

        c.close();

        kill(getpid(), SIGTERM);
    });

    ASSERT_EQ(pool.wait(), SW_OK);

    pool.destroy();

    sysv_signal(SIGTERM, SIG_DFL);

    t1.join();
}

TEST(process_pool, worker) {
    Worker worker{};
    worker.init();

    ASSERT_TRUE(worker.is_running());
    ASSERT_GT(worker.start_time, 0);
    worker.set_max_request(1000, 200);

    ASSERT_GT(SwooleWG.max_request, 1000);
    ASSERT_LE(SwooleWG.max_request, 1200);

    worker.shutdown();
    ASSERT_TRUE(worker.is_shutdown());

    swoole_set_worker_type(SW_USER_WORKER);
    ASSERT_EQ(swoole_get_worker_symbol(), '@');

    swoole_set_worker_type(SW_TASK_WORKER);
    ASSERT_EQ(swoole_get_worker_symbol(), '^');

    swoole_set_worker_type(SW_WORKER);
    ASSERT_EQ(swoole_get_worker_symbol(), '*');

    swoole_set_worker_type(SW_MASTER);
    ASSERT_EQ(swoole_get_worker_symbol(), '#');

    swoole_set_worker_type(SW_MANAGER);
    ASSERT_EQ(swoole_get_worker_symbol(), '$');

    worker.set_status_to_idle();
    ASSERT_TRUE(worker.is_idle());
    ASSERT_FALSE(worker.is_busy());

    worker.set_status_to_busy();
    ASSERT_FALSE(worker.is_idle());
    ASSERT_TRUE(worker.is_busy());

    worker.set_status(SW_WORKER_EXIT);
    ASSERT_FALSE(worker.is_idle());
    ASSERT_FALSE(worker.is_busy());
}

TEST(process_pool, add_worker) {
    Worker worker{};
    worker.pid = getpid();

    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0, SW_IPC_UNIXSOCK), SW_OK);

    pool.add_worker(&worker);

    auto *worker2 = pool.get_worker_by_pid(getpid());
    ASSERT_EQ(&worker, worker2);

    ASSERT_TRUE(pool.del_worker(worker2));
}
