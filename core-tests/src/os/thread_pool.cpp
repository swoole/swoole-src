#ifndef __MACH__
#include "tests.h"
#include "thread_pool.h"

#include <sys/eventfd.h>

static swThreadPool pool;
static int _pipe;
const static int N = 10000;

static int thread_onTask(swThreadPool *pool, void *task, int task_len) {
    sw_atomic_long_t *n = (sw_atomic_long_t *) task;
    sw_atomic_fetch_add(n, 1);
    if (*n == N) {
        write(_pipe, (void *) n, sizeof(long));
    }
    return SW_OK;
}

TEST(thread_pool, dispatch) {
    ASSERT_EQ(swThreadPool_create(&pool, 4), SW_OK);
    pool.onTask = thread_onTask;
    ASSERT_EQ(swThreadPool_run(&pool), SW_OK);
    sw_atomic_long_t result = 0;

    _pipe = eventfd(0, 0);

    for (long i = 0; i < N; i++) {
        ASSERT_EQ(swThreadPool_dispatch(&pool, (void *) &result, sizeof(result)), SW_OK);
    }

    long buf;
    read(_pipe, (void *) &buf, sizeof(buf));
    close(_pipe);

    ASSERT_EQ(swThreadPool_free(&pool), SW_OK);
    ASSERT_EQ(result, N);
}
#endif
