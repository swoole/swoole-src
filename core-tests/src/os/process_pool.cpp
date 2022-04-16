#include "test_core.h"
#include "swoole_process_pool.h"

#include <signal.h>

#ifdef __MACH__
#define sysv_signal signal
#endif

using namespace swoole;

static void test_func(ProcessPool &pool) {
    EventData data{};
    data.info.len = strlen(TEST_JPG_MD5SUM);
    strcpy(data.data, TEST_JPG_MD5SUM);

    int worker_id = -1;
    ASSERT_EQ(pool.dispatch_blocking(&data, &worker_id), SW_OK);

    pool.running = true;
    pool.onTask = [](ProcessPool *pool, EventData *task) -> int {
        pool->running = false;
        EXPECT_MEMEQ(task->data, TEST_JPG_MD5SUM, task->info.len);
        return 0;
    };
    pool.main_loop(&pool, pool.get_worker(0));
    pool.destroy();
}

TEST(process_pool, tcp) { 
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0, SW_IPC_SOCKET), SW_OK);
    ASSERT_EQ(pool.listen(TEST_HOST, TEST_PORT, 128), SW_OK);
    
    test_func(pool);
}

TEST(process_pool, unix_sock) { 
    ProcessPool pool{};
    signal(SIGPIPE, SIG_IGN);
    ASSERT_EQ(pool.create(1, 0, SW_IPC_UNIXSOCK), SW_OK);

    test_func(pool);
}

TEST(process_pool, tcp_raw) { 
    ProcessPool pool{};
    constexpr int size = 2*1024*1024;
    ASSERT_EQ(pool.create(1, 0, SW_IPC_SOCKET), SW_OK);
    ASSERT_EQ(pool.listen(TEST_HOST, TEST_PORT, 128), SW_OK);
    pool.set_protocol(0, size);

    String data(size);
    data.append_random_bytes(size-1);
    data.append("\0");
    
    ASSERT_EQ(pool.dispatch_blocking(data.str, data.length), SW_OK);

    pool.running = true;
    pool.ptr = &data;
    pool.onMessage = [](ProcessPool *pool, const char *recv_data, uint32_t len) -> void {
        pool->running = false;
        String *_data = (String *) pool->ptr;
        EXPECT_MEMEQ(_data->str, recv_data, len);
    };
    pool.main_loop(&pool, pool.get_worker(0));
    pool.destroy();
}

TEST(process_pool, msgqueue) { 
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0x9501, SW_IPC_MSGQUEUE), SW_OK);

    test_func(pool);
}

constexpr int magic_number = 99900011;
static ProcessPool *current_pool = nullptr;

TEST(process_pool, shutdown) { 
    ProcessPool pool{};
    int *shm_value = (int *) sw_mem_pool()->alloc(sizeof(int));    
    ASSERT_EQ(pool.create(1, 0x9501, SW_IPC_MSGQUEUE), SW_OK);

    // init 
    pool.set_protocol(1, 8192);
    pool.ptr = shm_value;
    pool.onWorkerStart = [](ProcessPool *pool, int worker_id) {
        int *shm_value = (int *) pool->ptr;
        *shm_value = magic_number;
        usleep(1);
    };

    pool.onTask =  [](ProcessPool *pool, EventData *task) -> int {
        kill(pool->master_pid, SIGTERM);

        return 0;
    };

    current_pool = &pool;
    sysv_signal(SIGTERM, [](int sig) {
        current_pool->running = false;
    });
    
    // start
    ASSERT_EQ(pool.start(), SW_OK);

    EventData msg{};
    msg.info.len = 128;
    swoole_random_string(msg.data, msg.info.len);
    int worker_id = -1;
    pool.dispatch_blocking(&msg, &worker_id);

    // wait
    ASSERT_EQ(pool.wait(), SW_OK);

    // shutdown
    pool.shutdown();
    pool.destroy();
    
    ASSERT_EQ(*shm_value, magic_number);
}
