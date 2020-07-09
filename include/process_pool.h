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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"
#include "lock.h"

struct swProcessPool;

enum swWorker_status
{
    SW_WORKER_BUSY = 1,
    SW_WORKER_IDLE = 2,
};

struct swWorker
{
    /**
     * worker process
     */
    pid_t pid;

    /**
     * worker thread
     */
    pthread_t tid;

    swProcessPool *pool;

    swMemoryPool *pool_output;

    swMsgQueue *queue;

    /**
     * redirect stdout to pipe_master
     */
    uchar redirect_stdout :1;

    /**
     * redirect stdin to pipe_worker
     */
    uchar redirect_stdin :1;

    /**
     * redirect stderr to pipe_worker
     */
    uchar redirect_stderr :1;

    /**
     * worker status, IDLE or BUSY
     */
    uint8_t status;
    uint8_t type;
    uint8_t ipc_mode;
    uint8_t child_process;

    /**
     * tasking num
     */
    sw_atomic_t tasking_num;

    time_t start_time;

    long dispatch_count;
    long request_count;

    /**
     * worker id
     */
    uint32_t id;

    swLock lock;

    swPipe *pipe_object;

    swSocket *pipe_master;
    swSocket *pipe_worker;
    swSocket *pipe_current;

    void *ptr;
    void *ptr2;
};

struct swWorkerGlobal
{
    /**
     * Always run
     */
    uint8_t run_always;
    /**
     * pipe_worker
     */
    int pipe_used;

    uchar shutdown :1;

    uint32_t max_request;

    swString **output_buffer;
    swWorker *worker;
    time_t exit_time;
};

struct swStreamInfo {
    swSocket *socket;
    swSocket *last_connection;
    char *socket_file;
    swString *response_buffer;
};

struct swProcessPool
{
    /**
     * reloading
     */
    uint8_t reloading;
    uint8_t running;
    uint8_t reload_init;
    uint8_t dispatch_mode;
    uint8_t ipc_mode;
    uint8_t started;
    uint32_t reload_worker_i;
    uint32_t max_wait_time;
    swWorker *reload_workers;

    /**
     * process type
     */
    uint8_t type;

    /**
     * worker->id = start_id + i
     */
    uint16_t start_id;

    /**
     * use message queue IPC
     */
    uint8_t use_msgqueue;

    /**
     * use stream socket IPC
     */
    uint8_t use_socket;

    char *packet_buffer;
    uint32_t max_packet_size;

    /**
     * message queue key
     */
    key_t msgqueue_key;

    uint32_t worker_num;
    uint32_t max_request;
    uint32_t max_request_grace;

    /**
     * No idle task work process is available.
     */
    uint8_t scheduler_warning;
    time_t warning_time;

    int (*onTask)(swProcessPool *pool, swEventData *task);

    void (*onWorkerStart)(swProcessPool *pool, int worker_id);
    void (*onMessage)(swProcessPool *pool, const char *data, uint32_t length);
    void (*onWorkerStop)(swProcessPool *pool, int worker_id);

    int (*main_loop)(swProcessPool *pool, swWorker *worker);
    int (*onWorkerNotFound)(swProcessPool *pool, pid_t pid, int status);

    sw_atomic_t round_id;

    swWorker *workers;
    swPipe *pipes;
    std::unordered_map<pid_t, swWorker *> *map;
    swReactor *reactor;
    swMsgQueue *queue;
    swStreamInfo *stream;

    void *ptr;
    void *ptr2;
};

static sw_inline void swProcessPool_set_type(swProcessPool *pool, int type)
{
    uint32_t i;
    pool->type = type;
    for (i = 0; i < pool->worker_num; i++)
    {
        pool->workers[i].type = type;
    }
}

static sw_inline swWorker *swProcessPool_get_worker(swProcessPool *pool, int worker_id)
{
    return &(pool->workers[worker_id - pool->start_id]);
}

static sw_inline void swProcessPool_set_start_id(swProcessPool *pool, int start_id)
{
    uint32_t i;
    pool->start_id = start_id;
    for (i = 0; i < pool->worker_num; i++)
    {
        pool->workers[i].id = pool->start_id + i;
    }
}

int swProcessPool_create(swProcessPool *pool, uint32_t worker_num, key_t msgqueue_key, int ipc_mode);
int swProcessPool_create_unix_socket(swProcessPool *pool, const char *socket_file, int blacklog);
int swProcessPool_create_tcp_socket(swProcessPool *pool, const char *host, int port, int blacklog);
int swProcessPool_set_protocol(swProcessPool *pool, int task_protocol, uint32_t max_packet_size);
void swProcessPool_set_max_request(swProcessPool *pool, uint32_t max_request, uint32_t max_request_grace);
int swProcessPool_wait(swProcessPool *pool);
int swProcessPool_start(swProcessPool *pool);
void swProcessPool_shutdown(swProcessPool *pool);
pid_t swProcessPool_spawn(swProcessPool *pool, swWorker *worker);
int swProcessPool_dispatch(swProcessPool *pool, swEventData *data, int *worker_id);
int swProcessPool_response(swProcessPool *pool, const char *data, int length);
int swProcessPool_dispatch_blocking(swProcessPool *pool, swEventData *data, int *dst_worker_id);
int swProcessPool_add_worker(swProcessPool *pool, swWorker *worker);
int swProcessPool_del_worker(swProcessPool *pool, swWorker *worker);
int swProcessPool_get_max_request(swProcessPool *pool);
void swProcessPool_free(swProcessPool *pool);

static sw_inline int swoole_waitpid(pid_t __pid, int *__stat_loc, int __options)
{
    int ret;
    do
    {
        ret = waitpid(__pid, __stat_loc, __options);
    } while (ret < 0 && errno == EINTR);
    return ret;
}

static sw_inline int swoole_kill(pid_t __pid, int __sig)
{
    if (__pid <= 0)
    {
        return -1;
    }
    return kill(__pid, __sig);
}

extern swWorkerGlobal SwooleWG;             //Worker Global Variable
