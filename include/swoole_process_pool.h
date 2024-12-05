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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  |         Twosee  <twose@qq.com>                                       |
  +----------------------------------------------------------------------+
*/

#pragma once

#include "swoole.h"

#include <signal.h>
#include <unordered_map>

#include "swoole_lock.h"
#include "swoole_pipe.h"
#include "swoole_channel.h"
#include "swoole_msg_queue.h"
#include "swoole_message_bus.h"

enum swWorkerStatus {
    SW_WORKER_BUSY = 1,
    SW_WORKER_IDLE = 2,
    SW_WORKER_EXIT = 3,
};

enum swIPCMode {
    SW_IPC_NONE = 0,
    SW_IPC_UNIXSOCK = 1,
    SW_IPC_MSGQUEUE = 2,
    SW_IPC_SOCKET = 3,
};

namespace swoole {

enum WorkerMessageType {
    SW_WORKER_MESSAGE_STOP = 1,
};

enum ProtocolType {
    SW_PROTOCOL_TASK = 1,
    SW_PROTOCOL_STREAM,
    SW_PROTOCOL_MESSAGE,
};

struct WorkerStopMessage {
    pid_t pid;
    uint16_t worker_id;
};

class ExitStatus {
  private:
    pid_t pid_;
    int status_;

  public:
    ExitStatus(pid_t _pid, int _status) : pid_(_pid), status_(_status) {}

    pid_t get_pid() const {
        return pid_;
    }

    int get_status() const {
        return status_;
    }

    int get_code() const {
        return WEXITSTATUS(status_);
    }

    int get_signal() const {
        return WTERMSIG(status_);
    }

    bool is_normal_exit() {
        return WIFEXITED(status_);
    }
};

static inline ExitStatus wait_process() {
    int status = 0;
    pid_t pid = ::wait(&status);
    return ExitStatus(pid, status);
}

static inline ExitStatus wait_process(pid_t _pid, int options) {
    int status = 0;
    pid_t pid = ::waitpid(_pid, &status, options);
    return ExitStatus(pid, status);
}

struct ProcessPool;
struct Worker;

struct WorkerGlobal {
    bool shutdown;
    bool running;
    uint32_t max_request;
    /**
     * worker is shared memory, visible in other work processes.
     * When a worker process restarts, it may be held by both the old and new processes simultaneously,
     * necessitating careful handling of the state.
     */
    Worker *worker;
    /**
     *  worker_copy is a copy of worker,
     *  but it must be local memory and only used within the current process or thread.
     *  It is not visible to other worker processes.
     */
    Worker *worker_copy;
    time_t exit_time;
};

struct Worker {
    pid_t pid;
    WorkerId id;
    ProcessPool *pool;
    MsgQueue *queue;
    bool shared;

    bool redirect_stdout;
    bool redirect_stdin;
    bool redirect_stderr;

    /**
     * worker status, IDLE or BUSY
     */
    uint8_t status;
    uint8_t type;
    uint8_t msgqueue_mode;
    uint8_t child_process;

    uint32_t concurrency;
    time_t start_time;

    sw_atomic_long_t dispatch_count;
    sw_atomic_long_t request_count;
    sw_atomic_long_t response_count;
    size_t coroutine_num;

    Mutex *lock;
    UnixSocket *pipe_object;

    network::Socket *pipe_master;
    network::Socket *pipe_worker;
    network::Socket *pipe_current;

    void *ptr;
    void *ptr2;

    ssize_t send_pipe_message(const void *buf, size_t n, int flags);
    bool has_exceeded_max_request();
    void set_max_request(uint32_t max_request, uint32_t max_request_grace);
    void report_error(const ExitStatus &exit_status);
    /**
     * Init global state for worker process.
     * Must be called after the process is spawned and before the main loop is executed.
     */
    void init();
    void shutdown();
    bool is_shutdown();
    bool is_running();

    void set_status(enum swWorkerStatus _status) {
        status = _status;
    }

    void set_status_to_idle() {
        set_status(SW_WORKER_IDLE);
    }

    void set_status_to_busy() {
        set_status(SW_WORKER_BUSY);
    }

    void add_request_count() {
        request_count++;
    }

    bool is_busy() {
        return status == SW_WORKER_BUSY;
    }

    bool is_idle() {
        return status == SW_WORKER_IDLE;
    }
};

struct StreamInfo {
    network::Socket *socket;
    network::Socket *last_connection;
    char *socket_file;
    int socket_port;
    String *response_buffer;
};

struct ProcessPool {
    /**
     * reloading
     */
    bool reloading;
    bool running;
    bool reload_init;
    bool read_message;
    bool started;
    bool schedule_by_sysvmsg;
    bool async;

    uint8_t ipc_mode;
    enum ProtocolType protocol_type_;
    pid_t master_pid;
    uint32_t reload_worker_i;
    uint32_t max_wait_time;
    uint64_t reload_count;
    time_t reload_last_time;
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
    uint32_t max_packet_size_;

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

    void (*onStart)(ProcessPool *pool);
    void (*onShutdown)(ProcessPool *pool);
    int (*onTask)(ProcessPool *pool, Worker *worker, EventData *task);
    void (*onWorkerStart)(ProcessPool *pool, Worker *worker);
    void (*onMessage)(ProcessPool *pool, RecvData *msg);
    void (*onWorkerExit)(ProcessPool *pool, Worker *worker);
    void (*onWorkerStop)(ProcessPool *pool, Worker *worker);
    void (*onWorkerError)(ProcessPool *pool, Worker *worker, const ExitStatus &exit_status);
    void (*onWorkerMessage)(ProcessPool *pool, EventData *msg);
    int (*onWorkerNotFound)(ProcessPool *pool, const ExitStatus &exit_status);
    int (*main_loop)(ProcessPool *pool, Worker *worker);

    sw_atomic_t round_id;

    Worker *workers;
    std::vector<std::shared_ptr<UnixSocket>> *pipes;
    std::unordered_map<pid_t, Worker *> *map_;
    MsgQueue *queue;
    StreamInfo *stream_info_;
    Channel *message_box = nullptr;
    MessageBus *message_bus = nullptr;

    void *ptr;

    void set_type(int _type) {
        uint32_t i;
        type = _type;
        for (i = 0; i < worker_num; i++) {
            workers[i].type = type;
        }
    }

    void set_start_id(int _start_id) {
        uint32_t i;
        start_id = _start_id;
        for (i = 0; i < worker_num; i++) {
            workers[i].id = start_id + i;
        }
    }

    Worker *get_worker(int worker_id) {
        return &(workers[worker_id - start_id]);
    }

    Worker *get_worker_by_pid(pid_t pid) {
        auto iter = map_->find(pid);
        if (iter == map_->end()) {
            return nullptr;
        }
        return iter->second;
    }

    TaskId get_task_id(EventData *task) {
        return task->info.fd;
    }

    WorkerId get_task_src_worker_id(EventData *task) {
        return task->info.reactor_id;
    }

    void set_max_packet_size(uint32_t _max_packet_size) {
        max_packet_size_ = _max_packet_size;
    }

    void set_protocol(enum ProtocolType _protocol_type);

    void set_max_request(uint32_t _max_request, uint32_t _max_request_grace);
    int get_max_request();
    bool detach();
    int wait();
    int start_check();
    int start();
    void shutdown();
    bool reload();
    pid_t spawn(Worker *worker);
    void stop(Worker *worker);
    swResultCode dispatch(EventData *data, int *worker_id);
    int response(const char *data, int length);
    swResultCode dispatch_blocking(EventData *data, int *dst_worker_id);
    swResultCode dispatch_blocking(const char *data, uint32_t len);
    void add_worker(Worker *worker);
    int del_worker(Worker *worker);
    void destroy();
    int create(uint32_t worker_num, key_t msgqueue_key = 0, swIPCMode ipc_mode = SW_IPC_NONE);
    int create_message_box(size_t memory_size);
    int create_message_bus();
    int push_message(uint8_t type, const void *data, size_t length);
    int push_message(EventData *msg);
    int pop_message(void *data, size_t size);
    int listen(const char *socket_file, int blacklog);
    int listen(const char *host, int port, int blacklog);
    int schedule();
    bool is_worker_running(Worker *worker);

    static void kill_timeout_worker(Timer *timer, TimerNode *tnode);

  private:
    static int run_with_task_protocol(ProcessPool *pool, Worker *worker);
    static int run_with_stream_protocol(ProcessPool *pool, Worker *worker);
    static int run_with_message_protocol(ProcessPool *pool, Worker *worker);
    static int run_async(ProcessPool *pool, Worker *worker);
};
};  // namespace swoole

static sw_inline int swoole_waitpid(pid_t __pid, int *__stat_loc, int __options) {
    int ret;
    do {
        ret = waitpid(__pid, __stat_loc, __options);
    } while (ret < 0 && errno == EINTR);
    return ret;
}

static sw_inline int swoole_kill(pid_t __pid, int __sig) {
    return kill(__pid, __sig);
}

typedef swoole::ProtocolType swProtocolType;

extern SW_THREAD_LOCAL swoole::WorkerGlobal SwooleWG;

static inline swoole::Worker *sw_worker() {
    return SwooleWG.worker;
}
