#include "test_core.h"
#include "swoole_process_pool.h"

#include <csignal>

#ifdef __MACH__
#define sysv_signal signal
#endif

#include "swoole_signal.h"

using namespace swoole;

static void test_func(ProcessPool &pool) {
    EventData data{};
    size_t size = swoole_system_random(1024, 4096);
    String rmem(size);
    rmem.append_random_bytes(size - 1);
    rmem.append("\0");

    data.info.len = size;
    memcpy(data.data, rmem.value(), size);

    int worker_id = -1;
    ASSERT_EQ(pool.dispatch_sync(&data, &worker_id), SW_OK);

    pool.running = true;
    pool.ptr = &rmem;
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
        String *_data = (String *) pool->ptr;
        usleep(10000);
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
        EXPECT_MEMEQ(_data->str, msg->data, msg->len());
    };
    test_func(pool);
}

static int test_incr_shm_value(ProcessPool *pool) {
    auto shm_value = static_cast<int *>(pool->ptr);
    return sw_atomic_add_fetch(shm_value, 1);
}

static MAYBE_UNUSED int test_get_shm_value(ProcessPool *pool) {
    auto shm_value = static_cast<int *>(pool->ptr);
    return *shm_value;
}

static void test_set_shm_value(ProcessPool *pool, int value) {
    auto shm_value = static_cast<int *>(pool->ptr);
    *shm_value = value;
}

TEST(process_pool, tcp) {
    ProcessPool pool{};
    int svr_port = swoole::test::get_random_port();
    ASSERT_EQ(pool.create(1, 0, SW_IPC_SOCKET), SW_OK);
    ASSERT_EQ(pool.listen(TEST_HOST, svr_port, 128), SW_OK);

    test_func_task_protocol(pool);
}

TEST(process_pool, unix_sock) {
    ProcessPool pool{};
    signal(SIGPIPE, SIG_IGN);
    ASSERT_EQ(pool.create(1, 0, SW_IPC_UNIXSOCK), SW_OK);

    test_func_task_protocol(pool);
}

TEST(process_pool, tcp_raw) {
    ProcessPool pool{};
    constexpr int size = 2 * 1024 * 1024;
    int svr_port = swoole::test::get_random_port();
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

TEST(process_pool, msgqueue) {
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0x9501, SW_IPC_MSGQUEUE), SW_OK);

    test_func_task_protocol(pool);
}

TEST(process_pool, message_protocol) {
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0, SW_IPC_UNIXSOCK), SW_OK);

    test_func_message_protocol(pool);
}

TEST(process_pool, stream_protocol) {
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0, SW_IPC_UNIXSOCK), SW_OK);

    test_func_stream_protocol(pool);
}

constexpr int magic_number = 99900011;
static ProcessPool *current_pool = nullptr;
static Worker *current_worker = nullptr;

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
        kill(pool->master_pid, SIGTERM);

        return 0;
    };

    current_pool = &pool;
    sysv_signal(SIGTERM, [](int sig) { current_pool->running = false; });

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

    ASSERT_EQ(*shm_value, magic_number);

    sysv_signal(SIGTERM, SIG_DFL);
}

TEST(process_pool, reload) {
    ProcessPool pool{};
    int *shm_value = (int *) sw_mem_pool()->alloc(sizeof(int));
    ASSERT_EQ(pool.create(2), SW_OK);

    // init
    pool.set_max_packet_size(8192);
    pool.ptr = shm_value;
    pool.max_wait_time = 1;

    pool.onWorkerStart = [](ProcessPool *pool, Worker *worker) {
        int *shm_value = (int *) pool->ptr;
        (*shm_value)++;

        sysv_signal(SIGTERM, SIG_IGN);

        while (true) {
            sleep(10000);
        }
    };

    pool.onStart = [](ProcessPool *pool) { swoole_timer_after(100, [pool](TIMER_PARAMS) { pool->reload(); }); };

    pool.onBeforeReload = [](ProcessPool *pool) { printf("onBeforeReload\n"); };

    pool.onAfterReload = [](ProcessPool *pool) {
        printf("onAfterReload\n");
        swoole_timer_after(100, [pool](TIMER_PARAMS) { pool->shutdown(); });
    };

    current_pool = &pool;
    sysv_signal(SIGTERM, [](int sig) { current_pool->running = false; });

    ASSERT_EQ(pool.start(), SW_OK);
    ASSERT_EQ(pool.wait(), SW_OK);

    pool.destroy();

    ASSERT_EQ(*shm_value, 4);
}

TEST(process_pool, async) {
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0, SW_IPC_UNIXSOCK), SW_OK);

    // init
    pool.set_max_packet_size(8192);
    pool.set_protocol(SW_PROTOCOL_TASK);
    int *shm_value = (int *) sw_mem_pool()->alloc(sizeof(int));
    pool.ptr = shm_value;
    pool.async = true;

    pool.onStart = [](ProcessPool *pool) {
        current_pool = pool;
        sysv_signal(SIGTERM, [](int sig) { current_pool->running = false; });
    };

    pool.onWorkerStart = [](ProcessPool *pool, Worker *worker) {
        test_set_shm_value(pool, magic_number);
        current_worker = worker;
        current_pool = pool;
        sysv_signal(SIGTERM, [](int sig) { current_pool->running = false; });

        swoole_signal_set(SIGTERM, [](int sig) {
            DEBUG() << "value: " << test_incr_shm_value(current_pool) << "; " << "SIGTERM, stop worker\n";
            current_pool->stop(current_worker);
        });

        usleep(10);
    };

    pool.onMessage = [](ProcessPool *pool, RecvData *msg) {
        DEBUG() << "value: " << test_incr_shm_value(current_pool) << "; " << "onMessage, kill\n";
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

    ASSERT_EQ(*shm_value, magic_number + 2);

    swoole_signal_clear();
    sysv_signal(SIGTERM, SIG_DFL);
}

TEST(process_pool, async_mb) {
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0, SW_IPC_UNIXSOCK), SW_OK);
    ASSERT_EQ(pool.create_message_bus(), SW_OK);

    swoole_signal_clear();

    // init
    pool.set_max_packet_size(8192);
    pool.set_protocol(SW_PROTOCOL_TASK);
    auto shm_value = (int *) sw_mem_pool()->alloc(sizeof(int));
    *shm_value = 0;
    pool.ptr = shm_value;
    pool.async = true;

    pool.onWorkerStart = [](ProcessPool *pool, Worker *worker) {
        current_worker = worker;
        current_pool = pool;

        sysv_signal(SIGTERM, [](int sig) { current_pool->running = false; });

        auto rv = test_incr_shm_value(pool);
        DEBUG() << "value: " << rv << "; " << "onWorkerStart\n";

        if (rv == 4) {
            DEBUG() << "value: " << test_incr_shm_value(pool) << "; " << "shutdown\n";
            pool->shutdown();
        }

        swoole_signal_set(SIGTERM, [](int sig) {
            DEBUG() << "value: " << test_incr_shm_value(current_pool) << "; " << "SIGTERM, stop worker\n";
            current_pool->stop(current_worker);
        });

        usleep(10);
    };

    pool.onWorkerExit = [](ProcessPool *pool, Worker *worker) {
        DEBUG() << "value: " << test_incr_shm_value(pool) << "; " << "onWorkerExit\n";
    };

    pool.onStart = [](ProcessPool *pool) {
        current_pool = pool;
        sysv_signal(SIGTERM, [](int sig) { current_pool->running = false; });
        sysv_signal(SIGIO, [](int sig) { current_pool->read_message = true; });

        DEBUG() << "value: " << test_incr_shm_value(pool) << "; " << "onStart\n";
    };

    pool.onShutdown = [](ProcessPool *pool) {
        DEBUG() << "value: " << test_incr_shm_value(pool) << "; " << "onShutdown\n";
    };

    pool.onMessage = [](ProcessPool *pool, RecvData *msg) {
        DEBUG() << "value: " << test_incr_shm_value(pool) << "; " << "onMessage, detach()\n";
        ASSERT_TRUE(pool->detach());
        swoole_signal_set(SIGTERM, [](int sig) {
            exit(2);
        });
    };

    // start
    ASSERT_EQ(pool.start(), SW_OK);

    char msg[128];
    swoole_random_string(msg, sizeof(msg));
    pool.send_message(0, msg, sizeof(msg));

    // wait
    ASSERT_EQ(pool.wait(), SW_OK);

    pool.destroy();

    ASSERT_EQ(*shm_value, 8);

    swoole_signal_clear();
    sysv_signal(SIGTERM, SIG_DFL);
    sysv_signal(SIGIO, SIG_DFL);
}

TEST(process_pool, listen) {
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0, SW_IPC_SOCKET), SW_OK);
    ASSERT_EQ(pool.listen("127.0.0.1", 9509, 128), SW_OK);

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

        network::SyncClient c(SW_SOCK_TCP);
        c.connect("127.0.0.1", 9509);

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
