#include "test_core.h"
#include "swoole_process_pool.h"

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
}

TEST(process_pool, tcp) { 
    ProcessPool pool{};
    ASSERT_EQ(pool.create(1, 0, SW_IPC_SOCKET), SW_OK);
    ASSERT_EQ(pool.create_tcp_socket(TEST_HOST, TEST_PORT, 128), SW_OK);
    
    test_func(pool);
}

TEST(process_pool, unix_sock) { 
    ProcessPool pool{};
    signal(SIGPIPE, SIG_IGN);
    ASSERT_EQ(pool.create(1, 0, SW_IPC_SOCKET), SW_OK);
    ASSERT_EQ(pool.create_unix_socket(TEST_TMP_FILE, 128), SW_OK);

    test_func(pool);
}
