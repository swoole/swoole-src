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
#include <signal.h>
#include "lock.h"

enum swWorker_status {
    SW_WORKER_BUSY = 1,
    SW_WORKER_IDLE = 2,
};

enum swIPC_type {
    SW_IPC_NONE = 0,
    SW_IPC_UNIXSOCK = 1,
    SW_IPC_MSGQUEUE = 2,
    SW_IPC_SOCKET = 3,
};


struct swStreamInfo {
    swSocket *socket;
    swSocket *last_connection;
    char *socket_file;
    swString *response_buffer;
};

namespace swoole {

struct ProcessPool;
struct Worker;

struct WorkerGlobal {
    /**
     * Always run
     */
    uint8_t run_always;
    /**
     * pipe_worker
     */
    int pipe_used;

    uchar shutdown : 1;

    uint32_t max_request;

    swString **output_buffer;
    Worker *worker;
    time_t exit_time;
};
    
struct Worker {
    /**
     * worker process
     */
    pid_t pid;

    /**
     * worker thread
     */
    pthread_t tid;

    swoole::ProcessPool *pool;

    swMemoryPool *pool_output;

    swMsgQueue *queue;

    /**
     * redirect stdout to pipe_master
     */
    uchar redirect_stdout : 1;

    /**
     * redirect stdin to pipe_worker
     */
    uchar redirect_stdin : 1;

    /**
     * redirect stderr to pipe_worker
     */
    uchar redirect_stderr : 1;

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

struct ProcessPool {
    /**
     * reloading
     */
    bool reloading;
    bool running;
    bool reload_init;
    bool started;
    uint8_t dispatch_mode;
    uint8_t ipc_mode;
    uint32_t reload_worker_i;
    uint32_t max_wait_time;
    Worker *reload_workers;

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

    std::function<int(ProcessPool *pool, swEventData *task)> onTask;
    std::function<void(ProcessPool *pool, int worker_id)> onWorkerStart;
    std::function<void(ProcessPool *pool, const char *data, uint32_t length)> onMessage;
    std::function<void(ProcessPool *pool, int worker_id)> onWorkerStop;

    std::function<int(ProcessPool *pool, Worker *worker)> main_loop;
    std::function<int(ProcessPool *pool, pid_t pid, int status)> onWorkerNotFound;

    sw_atomic_t round_id;

    Worker *workers;
    swPipe *pipes;
    std::unordered_map<pid_t, Worker *> *map;
    swReactor *reactor;
    swMsgQueue *queue;
    swStreamInfo *stream_info_;

    void *ptr;
    void *ptr2;

    inline void set_type(int _type) {
        uint32_t i;
        type = _type;
        for (i = 0; i < worker_num; i++) {
            workers[i].type = type;
        }
    }

    inline void set_start_id(int _start_id) {
        uint32_t i;
        start_id = _start_id;
        for (i = 0; i < worker_num; i++) {
            workers[i].id = start_id + i;
        }
    }
    
    inline Worker *get_worker(int worker_id) {
        return &(workers[worker_id - start_id]);
    }

    void set_max_request(uint32_t max_request, uint32_t max_request_grace);
    int get_max_request();
    int set_protocol(int task_protocol, uint32_t max_packet_size);
    int wait();
    int start();
    void shutdown();
    pid_t spawn(Worker *worker);
    int dispatch(swEventData *data, int *worker_id);
    int response(const char *data, int length);
    int dispatch_blocking(swEventData *data, int *dst_worker_id);
    int add_worker(Worker *worker);
    int del_worker(Worker *worker);
    void destroy();
    int create_unix_socket(const char *socket_file, int blacklog);
    int create_tcp_socket(const char *host, int port, int blacklog);
    int schedule();

    static int create(ProcessPool *pool, uint32_t worker_num, key_t msgqueue_key, int ipc_mode);
};
};

typedef swoole::ProcessPool swProcessPool;
typedef swoole::Worker swWorker;
typedef swoole::WorkerGlobal swWorkerGlobal;

static sw_inline int swoole_waitpid(pid_t __pid, int *__stat_loc, int __options) {
    int ret;
    do {
        ret = waitpid(__pid, __stat_loc, __options);
    } while (ret < 0 && errno == EINTR);
    return ret;
}

static sw_inline int swoole_kill(pid_t __pid, int __sig) {
    if (__pid <= 0) {
        return -1;
    }
    return kill(__pid, __sig);
}

extern swWorkerGlobal SwooleWG;  // Worker Global Variable
