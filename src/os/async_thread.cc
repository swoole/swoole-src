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
 +----------------------------------------------------------------------+
 */

#include "swoole_api.h"
#include "swoole_socket.h"
#include "swoole_reactor.h"
#include "swoole_string.h"
#include "swoole_signal.h"
#include "swoole_pipe.h"
#include "swoole_async.h"
#include "swoole_util.h"

#include <thread>
#include <atomic>
#include <unordered_map>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <sstream>

namespace swoole {
namespace async {
//-------------------------------------------------------------------------------
static std::mutex init_lock;
static std::atomic<int> refcount(0);
static void aio_thread_release(AsyncEvent *event);
static thread_local std::string tmp_thread_id;

static const char *get_thread_id(std::thread::id id) {
    std::stringstream ss;
    ss << id;
    tmp_thread_id = ss.str();
    return tmp_thread_id.c_str();
}

class EventQueue {
  public:
    inline void push(AsyncEvent *event) {
        _queue.push(event);
    }

    inline AsyncEvent *pop() {
        if (_queue.empty()) {
            return nullptr;
        }
        AsyncEvent *retval = _queue.front();
        _queue.pop();
        return retval;
    }

    inline double get_max_wait_time() {
        if (_queue.empty()) {
            return 0;
        } else {
            AsyncEvent *event = _queue.front();
            return swoole_microtime() - event->timestamp;
        }
    }

    inline size_t count() {
        return _queue.size();
    }

  private:
    std::queue<AsyncEvent *> _queue;
};

class ThreadPool {
  public:
    ThreadPool(size_t _core_worker_num, size_t _worker_num, double _max_wait_time, double _max_idle_time) {
        running = false;

        core_worker_num = _core_worker_num == 0 ? SW_CPU_NUM : SW_MAX(1, _core_worker_num);
        worker_num = _worker_num == 0 ? SW_CPU_NUM * SW_AIO_THREAD_NUM_MULTIPLE : SW_MAX(core_worker_num, _worker_num);
        max_wait_time = _max_wait_time == 0 ? SW_AIO_TASK_MAX_WAIT_TIME : _max_wait_time;
        max_idle_time = _max_idle_time == 0 ? SW_AIO_THREAD_MAX_IDLE_TIME : _max_idle_time;

        creator_pid = getpid();
    }

    ~ThreadPool() {
        shutdown();
    }

    bool start() {
        running = true;
        current_task_id = 0;
        n_waiting = 0;
        n_closing = 0;
        for (size_t i = 0; i < core_worker_num; i++) {
            create_thread(true);
        }
        return true;
    }

    bool shutdown() {
        if (!running) {
            return false;
        }

        event_mutex.lock();
        running = false;
        _cv.notify_all();
        event_mutex.unlock();

        for (auto &i : threads) {
            std::thread *_thread = i.second;
            if (_thread->joinable()) {
                _thread->join();
            }
            delete _thread;
        }

        return true;
    }

    void schedule() {
        if (n_waiting == 0 && threads.size() < worker_num && max_wait_time > 0) {
            event_mutex.lock();
            double _max_wait_time = _queue.get_max_wait_time();
            event_mutex.unlock();

            if (_max_wait_time > max_wait_time) {
                size_t n = 1;
                /**
                 * maybe we can find a better strategy
                 */
                if (threads.size() + n > worker_num) {
                    n = worker_num - threads.size();
                }
                swTraceLog(SW_TRACE_AIO,
                           "Create %zu thread due to wait %fs, we will have %zu threads",
                           n,
                           _max_wait_time,
                           threads.size() + n);
                while (n--) {
                    create_thread();
                }
            }
        }
    }

    AsyncEvent *dispatch(const AsyncEvent *request) {
        if (SwooleTG.aio_schedule) {
            schedule();
        }
        auto _event_copy = new AsyncEvent(*request);
        _event_copy->task_id = current_task_id++;
        _event_copy->timestamp = swoole_microtime();
        _event_copy->pipe_socket = SwooleTG.aio_write_socket;
        event_mutex.lock();
        _queue.push(_event_copy);
        _cv.notify_one();
        event_mutex.unlock();
        swDebug("push and notify one: %f", swoole_microtime());
        return _event_copy;
    }

    inline size_t worker_count() {
        return threads.size();
    }

    inline size_t queue_count() {
        std::unique_lock<std::mutex> lock(event_mutex);
        return _queue.count();
    }

    pid_t get_creator_pid() {
        return creator_pid;
    }

    void release_thread(std::thread::id tid) {
        auto i = threads.find(tid);
        if (i == threads.end()) {
            swWarn("AIO thread#%s is missing", get_thread_id(tid));
            return;
        } else {
            std::thread *_thread = i->second;
            swTraceLog(SW_TRACE_AIO, "release idle thread#%s, we have %zu now", get_thread_id(tid), threads.size() - 1);
            if (_thread->joinable()) {
                _thread->join();
            }
            threads.erase(i);
            delete _thread;
        }
    }

#ifdef SW_DEBUG
    void notify_one() {
        _cv.notify_one();
    }
#endif

  private:
    void create_thread(const bool is_core_worker = false);

    size_t core_worker_num;
    size_t worker_num;
    double max_wait_time;
    double max_idle_time;

    bool running;

    std::atomic<size_t> n_waiting;
    std::atomic<size_t> n_closing;
    size_t current_task_id = 0;
    pid_t creator_pid;
    std::unordered_map<std::thread::id, std::thread *> threads;
    EventQueue _queue;
    std::mutex event_mutex;
    std::condition_variable _cv;
};

static ThreadPool *pool = nullptr;

void ThreadPool::create_thread(const bool is_core_worker) {
    try {
        std::thread *_thread = new std::thread([this, is_core_worker]() {
            bool exit_flag = false;
            SwooleTG.buffer_stack = new String(SW_STACK_BUFFER_SIZE);
            ON_SCOPE_EXIT {
                delete SwooleTG.buffer_stack;
                SwooleTG.buffer_stack = nullptr;
            };

            swSignal_none();

            while (running) {
                event_mutex.lock();
                AsyncEvent *event = _queue.pop();
                event_mutex.unlock();

                swDebug("%s: %f", event ? "pop 1 event" : "no event", swoole_microtime());

                if (event) {
                    if (sw_unlikely(event->handler == nullptr)) {
                        event->error = SW_ERROR_AIO_BAD_REQUEST;
                        event->ret = -1;
                    } else if (sw_unlikely(event->canceled)) {
                        event->error = SW_ERROR_AIO_CANCELED;
                        event->ret = -1;
                    } else {
                        event->handler(event);
                    }

                    swTraceLog(SW_TRACE_AIO,
                               "aio_thread %s. ret=%d, error=%d",
                               event->ret > 0 ? "ok" : "failed",
                               event->ret,
                               event->error);

                _send_event:
                    while (true) {
                        ssize_t ret = event->pipe_socket->write(&event, sizeof(event));
                        if (ret < 0) {
                            if (errno == EAGAIN) {
                                event->pipe_socket->wait_event(1000, SW_EVENT_WRITE);
                                continue;
                            } else if (errno == EINTR) {
                                continue;
                            } else {
                                delete event;
                                swSysWarn("sendto swoole_aio_pipe_write failed");
                            }
                        }
                        break;
                    }

                    // exit
                    if (exit_flag) {
                        n_closing--;
                        break;
                    }
                } else {
                    std::unique_lock<std::mutex> lock(event_mutex);
                    if (_queue.count() > 0) {
                        continue;
                    }
                    if (!running) {
                        break;
                    }
                    ++n_waiting;
                    if (is_core_worker || max_idle_time <= 0) {
                        _cv.wait(lock);
                    } else {
                        while (true) {
                            if (_cv.wait_for(lock, std::chrono::microseconds((size_t)(max_idle_time * 1000 * 1000))) ==
                                    std::cv_status::timeout) {
                                if (running && n_closing != 0) {
                                    // wait for the next round
                                    continue;
                                }
                                /* notifies the main thread to release this thread */
                                event = new AsyncEvent;
                                event->object = new std::thread::id(std::this_thread::get_id());
                                event->callback = aio_thread_release;
                                event->pipe_socket = SwooleG.aio_default_socket;
                                event->canceled = false;

                                --n_waiting;
                                ++n_closing;
                                exit_flag = true;
                                goto _send_event;
                            }
                            break;
                        }
                    }
                    --n_waiting;
                }
            }
        });
        threads[_thread->get_id()] = _thread;
    } catch (const std::system_error &e) {
        swSysNotice("create aio thread failed, please check your system configuration or adjust aio_worker_num");
        return;
    }
}

static void aio_thread_release(AsyncEvent *event) {
    std::thread::id *tid = reinterpret_cast<std::thread::id *>(event->object);
    pool->release_thread(*tid);
    delete tid;
    // balance
    SwooleTG.aio_task_num++;
}

static void destroy(void *private_data) {
    if (!SwooleTG.aio_init) {
        return;
    }
    SwooleTG.aio_init = 0;
    swoole_event_del(SwooleTG.aio_read_socket);

    if (pool->get_creator_pid() == getpid()) {
        if ((--refcount) == 0) {
            delete pool;
            pool = nullptr;

            SwooleTG.aio_pipe->close(SwooleTG.aio_pipe);
            SwooleTG.aio_read_socket = nullptr;
            SwooleTG.aio_write_socket = nullptr;
            delete SwooleTG.aio_pipe;
            SwooleTG.aio_pipe = nullptr;
        }
    }
}

static int init() {
    if (SwooleTG.aio_init) {
        swWarn("aio_thread_pool has already been initialized");
        return SW_ERR;
    }
    if (!SwooleTG.reactor) {
        swWarn("no event loop, cannot initialized");
        return SW_ERR;
    }

    SwooleTG.aio_pipe = new Pipe();

    if (swPipeBase_create(SwooleTG.aio_pipe, 0) < 0) {
        swoole_throw_error(SW_ERROR_SYSTEM_CALL_FAIL);
    }

    SwooleTG.aio_read_socket = SwooleTG.aio_pipe->get_socket(false);
    SwooleTG.aio_write_socket = SwooleTG.aio_pipe->get_socket(true);
    SwooleTG.aio_read_socket->fd_type = SW_FD_AIO;
    SwooleTG.aio_write_socket->fd_type = SW_FD_AIO;

    swoole_event_add(SwooleTG.aio_read_socket, SW_EVENT_READ);

    sw_reactor()->add_destroy_callback(destroy);
    sw_reactor()->set_exit_condition(Reactor::EXIT_CONDITION_AIO_TASK,
                                     [](Reactor *reactor, int &event_num) -> bool {
                                         if (SwooleTG.aio_init && SwooleTG.aio_task_num == 0) {
                                             event_num--;
                                         }
                                         return true;
                                     });

    init_lock.lock();
    if ((refcount++) == 0) {
        pool = new ThreadPool(
            SwooleG.aio_core_worker_num, SwooleG.aio_worker_num, SwooleG.aio_max_wait_time, SwooleG.aio_max_idle_time);
        pool->start();
        SwooleTG.aio_schedule = 1;
        SwooleG.aio_default_socket = SwooleTG.aio_write_socket;
    }
    SwooleTG.aio_init = 1;
    init_lock.unlock();

    return SW_OK;
}

size_t thread_count() {
    return pool ? pool->worker_count() : 0;
}

AsyncEvent *dispatch(const AsyncEvent *request) {
    if (sw_unlikely(!SwooleTG.aio_init)) {
        init();
    }
    AsyncEvent *event = pool->dispatch(request);
    if (sw_likely(event)) {
        SwooleTG.aio_task_num++;
    }
    return event;
}

int callback(Reactor *reactor, Event *event) {
    if (SwooleTG.aio_schedule) {
        pool->schedule();
    }

    AsyncEvent *events[SW_AIO_EVENT_NUM];
    ssize_t n = event->socket->read(events, sizeof(AsyncEvent *) * SW_AIO_EVENT_NUM);
    if (n < 0) {
        swSysWarn("read() aio events failed");
        return SW_ERR;
    }
    for (size_t i = 0; i < n / sizeof(AsyncEvent *); i++) {
        AsyncEvent *event = events[i];
        if (!event->canceled) {
            event->callback(event);
        }
        SwooleTG.aio_task_num--;
        delete event;
    }

    return SW_OK;
}

#ifdef SW_DEBUG
void notify_one() {
    if (pool) {
        pool->notify_one();
    }
}
#endif

//-------------------------------------------------------------------------------
}  // namespace async
};  // namespace swoole
