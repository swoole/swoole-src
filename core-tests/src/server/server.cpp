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
  | @author   Tianfeng Han  <mikan.tenny@gmail.com>                      |
  +----------------------------------------------------------------------+
*/

#include "test_core.h"
#include "swoole_memory.h"
#include "lock.h"
#include "wrapper/client.hpp"
#include "swoole_log.h"

using namespace std;
using namespace swoole;

static void test_create_server(swServer *serv) {
    serv->create();

    SwooleG.memory_pool = swMemoryGlobal_new(SW_GLOBAL_MEMORY_PAGESIZE, 1);
    serv->workers = (swWorker *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, serv->worker_num * sizeof(swWorker));
    swFactoryProcess_create(&serv->factory, serv->worker_num);
}

TEST(server, create_pipe_buffers) {
    int ret;
    swServer serv;

    test_create_server(&serv);

    ret = serv.create_pipe_buffers();
    ASSERT_EQ(0, ret);
    ASSERT_NE(nullptr, serv.pipe_buffers);
    for (uint32_t i = 0; i < serv.reactor_num; i++) {
        ASSERT_NE(nullptr, serv.pipe_buffers[i]);
    }
}

static const char *packet = "hello world\n";

TEST(server, base) {
    swServer serv;
    serv.worker_num = 1;
    serv.factory_mode = SW_MODE_BASE;

    sw_logger()->set_level(SW_LOG_WARNING);

    swListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    ASSERT_TRUE(port);

    mutex lock;
    lock.lock();

    ASSERT_EQ(serv.create(), SW_OK);

    std::thread t1([&]() {
        swSignal_none();

        lock.lock();

        swoole::Client c(SW_SOCK_TCP);
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
    swServer serv;
    serv.worker_num = 1;
    serv.factory_mode = SW_MODE_PROCESS;

    SwooleG.running = 1;

    sw_logger()->set_level(SW_LOG_WARNING);

    swLock *lock = (swLock *) SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(*lock));
    swMutex_create(lock, 1);
    lock->lock(lock);

    swListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swWarn("listen failed, [error=%d]", swoole_get_last_error());
        exit(2);
    }

    ASSERT_EQ(serv.create(), SW_OK);

    serv.onStart = [&lock](swServer *serv) {
        thread t1([=]() {
            swSignal_none();

            lock->lock(lock);

            swListenPort *port = serv->get_primary_port();

            swoole::Client c(SW_SOCK_TCP);
            c.connect(TEST_HOST, port->port);
            c.send(packet, strlen(packet));
            char buf[1024];
            c.recv(buf, sizeof(buf));
            c.close();

            kill(serv->gs->master_pid, SIGTERM);
        });
        t1.detach();
    };

    serv.onWorkerStart = [&lock](swServer *serv, int worker_id) { lock->unlock(lock); };

    serv.onReceive = [](swServer *serv, swRecvData *req) -> int {
        EXPECT_EQ(string(req->data, req->info.len), string(packet));

        string resp = string("Server: ") + string(packet);
        serv->send(req->info.fd, resp.c_str(), resp.length());

        return SW_OK;
    };

    ASSERT_EQ(serv.start(), 0);

    SwooleG.memory_pool->free(SwooleG.memory_pool, lock);
}

TEST(server, task_worker) {
    swServer serv;
    serv.worker_num = 1;
    serv.task_worker_num = 1;

    swListenPort *port = serv.add_port(SW_SOCK_TCP, TEST_HOST, 0);
    if (!port) {
        swWarn("listen failed, [error=%d]", swoole_get_last_error());
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

    swEventData buf;
    memset(&buf.info, 0, sizeof(buf.info));

    swTask_type(&buf) |= SW_TASK_NOREPLY;
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
