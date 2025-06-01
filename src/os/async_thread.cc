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
 +----------------------------------------------------------------------+
 */

#include "swoole_api.h"
#include "swoole_socket.h"
#include "swoole_reactor.h"
#include "swoole_pipe.h"
#include "swoole_async.h"
#include "swoole_util.h"
#include "swoole_thread.h"

#include <thread>
#include <atomic>
#include <unordered_map>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <system_error>

static std::mutex async_thread_lock;
static std::shared_ptr<swoole::async::ThreadPool> async_thread_pool;

swoole::AsyncThreads *sw_async_threads() {
    return SwooleTG.async_threads;
}

namespace swoole {
namespace async {
//-------------------------------------------------------------------------------
class EventQueue {
  public:
    void push(AsyncEvent *event) {
        queue_.push(event);
    }

    AsyncEvent *pop() {
        if (queue_.empty()) {
            return nullptr;
        }
        AsyncEvent *retval = queue_.front();
        queue_.pop();
        return retval;
    }

    double get_max_wait_time() const {
        if (queue_.empty()) {
            return 0;
        }
        const AsyncEvent *event = queue_.front();
        return microtime() - event->timestamp;
    }

    size_t count() const {
        return queue_.size();
    }

    bool empty() const {
        return queue_.empty();
    }

  private:
    std::queue<AsyncEvent *> queue_;
};

class ThreadPool {
  public:
    ThreadPool(size_t _core_worker_num, size_t _worker_num, double _max_wait_time, double _max_idle_time) {
        running = false;

        core_worker_num = _core_worker_num == 0 ? SW_CPU_NUM : SW_MAX(1, _core_worker_num);
        worker_num = _worker_num == 0 ? SW_CPU_NUM * SW_AIO_THREAD_NUM_MULTIPLE : SW_MAX(core_worker_num, _worker_num);
        max_wait_time = _max_wait_time == 0 ? SW_AIO_TASK_MAX_WAIT_TIME : _max_wait_time;
        max_idle_time = _max_idle_time == 0 ? SW_AIO_THREAD_MAX_IDLE_TIME : _max_idle_time;
    }

    ~ThreadPool() {
        shutdown();
    }

    bool is_running() const {
        return running;
    }

    bool start() {
        running = true;
        current_task_id = 0;
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
        event_mutex.unlock();
        _cv.notify_all();

        for (auto &i : threads) {
            std::thread *_thread = i.second;
            if (_thread->joinable()) {
                _thread->join();
            }
            delete _thread;
        }
        threads.clear();

        return true;
    }

    void schedule() {
        if (n_waiting == 0 && threads.size() < worker_num && max_wait_time > 0) {
            double _max_wait_time = queue_.get_max_wait_time();
            if (_max_wait_time > max_wait_time) {
                size_t n = 1;
                /**
                 * maybe we can find a better strategy
                 */
                if (threads.size() + n > worker_num) {
                    n = worker_num - threads.size();
                }
                swoole_trace_log(SW_TRACE_AIO,
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
        auto _event_copy = new AsyncEvent(*request);
        event_mutex.lock();
        schedule();
        _event_copy->task_id = current_task_id++;
        _event_copy->timestamp = microtime();
        _event_copy->pipe_socket = SwooleTG.async_threads->write_socket;
        queue_.push(_event_copy);
        event_mutex.unlock();
        _cv.notify_one();
        swoole_debug("push and notify one: %f", microtime());
        return _event_copy;
    }

    size_t get_worker_num() const {
        return threads.size();
    }

    size_t get_queue_size() {
        std::unique_lock<std::mutex> lock(event_mutex);
        return queue_.count();
    }

    void release_thread(std::thread::id tid) {
        auto i = threads.find(tid);
        if (i == threads.end()) {
            swoole_warning("AIO thread#%s is missing", swoole_thread_id_to_str(tid).c_str());
            return;
        }
        std::thread *_thread = i->second;
        swoole_trace_log(SW_TRACE_AIO,
                         "release idle thread#%s, we have %zu now",
                         swoole_thread_id_to_str(tid).c_str(),
                         threads.size() - 1);
        if (_thread->joinable()) {
            _thread->join();
        }
        threads.erase(i);
        delete _thread;
    }

    static void release_callback(AsyncEvent *event) {
        auto *tid = static_cast<std::thread::id *>(event->object);
        SwooleTG.async_threads->pool->release_thread(*tid);
        delete tid;
        // balance
        SwooleTG.async_threads->task_num++;
    }

    void notify_one() {
        _cv.notify_one();
    }

  private:
    void create_thread(bool is_core_worker = false);
    void main_func(bool is_core_worker);

    size_t core_worker_num;
    size_t worker_num;
    double max_wait_time;
    double max_idle_time;

    bool running;

    std::atomic<size_t> n_waiting{0};
    std::atomic<size_t> n_closing{0};
    size_t current_task_id = 0;
    std::unordered_map<std::thread::id, std::thread *> threads;
    EventQueue queue_;
    std::mutex event_mutex;
    std::condition_variable _cv;
};

void ThreadPool::main_func(const bool is_core_worker) {
    bool exit_flag = false;
    swoole_thread_init(false);

    while (running) {
        bool timeout = false;
        std::unique_lock<std::mutex> lock(event_mutex);
        ++n_waiting;
        if (is_core_worker || max_idle_time <= 0) {
            _cv.wait(lock, [this] { return !queue_.empty() || !running; });
        } else {
            timeout = !_cv.wait_for(lock,
                                    std::chrono::microseconds(static_cast<long>(max_idle_time) * 1000 * 1000),
                                    [this] { return !queue_.empty() || !running; });
        }
        --n_waiting;

        AsyncEvent *event = queue_.pop();
        lock.unlock();
        swoole_debug("%s: %f", event ? "pop 1 event" : "no event", microtime());
        if (event) {
            if (sw_unlikely(event->handler == nullptr)) {
                event->error = SW_ERROR_AIO_BAD_REQUEST;
                event->retval = -1;
            } else if (sw_unlikely(event->canceled)) {
                event->error = SW_ERROR_AIO_CANCELED;
                event->retval = -1;
            } else {
                event->handler(event);
            }

            swoole_trace_log(SW_TRACE_AIO,
                             "aio_thread %s. ret=%ld, error=%d",
                             event->retval > 0 ? "ok" : "failed",
                             event->retval,
                             event->error);

        _send_event:
            if (event->pipe_socket->write_sync_optimistic(&event, sizeof(event)) <= 0) {
                swoole_sys_warning("sendto swoole_aio_pipe_write failed");
                delete event;
            }
            // exit
            if (exit_flag) {
                --n_closing;
                break;
            }
        } else if (timeout) {
            if (n_closing != 0) {
                // wait for the next round
                continue;
            }
            /* notifies the main thread to release this thread */
            event = new AsyncEvent;
            event->object = new std::thread::id(std::this_thread::get_id());
            event->callback = release_callback;
            event->pipe_socket = SwooleG.aio_default_socket;
            event->canceled = false;

            ++n_closing;
            exit_flag = true;
            goto _send_event;
        }
    }
    swoole_thread_clean(false);
}

void ThreadPool::create_thread(const bool is_core_worker) {
    try {
        auto *_thread = new std::thread([this, is_core_worker]() { main_func(is_core_worker); });
        threads[_thread->get_id()] = _thread;
    } catch (const std::system_error &e) {
        swoole_sys_notice("create aio thread failed, please check your system configuration or adjust aio_worker_num");
    }
}

AsyncEvent *dispatch(const AsyncEvent *request) {
    if (sw_unlikely(!SwooleTG.async_threads)) {
        SwooleTG.async_threads = new AsyncThreads();
    }
    AsyncEvent *event = SwooleTG.async_threads->pool->dispatch(request);
    if (sw_likely(event)) {
        SwooleTG.async_threads->task_num++;
    }
    return event;
}

//-------------------------------------------------------------------------------
}  // namespace async

int AsyncThreads::callback(Reactor *reactor, Event *event) {
    AsyncEvent *events[SW_AIO_EVENT_NUM];
    ssize_t n = event->socket->read(events, sizeof(AsyncEvent *) * SW_AIO_EVENT_NUM);
    if (n < 0) {
        swoole_sys_warning("read() aio events failed");
        return SW_ERR;
    }
    for (size_t i = 0; i < n / sizeof(AsyncEvent *); i++) {
        AsyncEvent *_event = events[i];
        if (!_event->canceled) {
            _event->callback(_event);
        }
        SwooleTG.async_threads->task_num--;
        delete _event;
    }

    return SW_OK;
}

size_t AsyncThreads::get_worker_num() const {
    return pool ? pool->get_worker_num() : 0;
}

size_t AsyncThreads::get_queue_size() const {
    return pool ? pool->get_queue_size() : 0;
}

void AsyncThreads::notify_one() const {
    if (pool) {
        pool->notify_one();
    }
}

AsyncThreads::AsyncThreads() {
    if (!SwooleTG.reactor) {
        swoole_warning("no event loop, cannot initialized");
        throw Exception(SW_ERROR_WRONG_OPERATION);
    }

    pipe = new Pipe(false);
    if (!pipe->ready()) {
        delete pipe;
        pipe = nullptr;
        swoole_throw_error(SW_ERROR_SYSTEM_CALL_FAIL);
        return;
    }

    read_socket = pipe->get_socket(false);
    write_socket = pipe->get_socket(true);
    read_socket->fd_type = SW_FD_AIO;
    write_socket->fd_type = SW_FD_AIO;

    swoole_event_add(read_socket, SW_EVENT_READ);

    sw_reactor()->add_destroy_callback([](void *data) {
        if (!SwooleTG.async_threads) {
            return;
        }
        swoole_event_del(SwooleTG.async_threads->read_socket);
        delete SwooleTG.async_threads;
        SwooleTG.async_threads = nullptr;
    });

    sw_reactor()->set_exit_condition(Reactor::EXIT_CONDITION_AIO_TASK, [](Reactor *reactor, size_t &event_num) -> bool {
        if (SwooleTG.async_threads && SwooleTG.async_threads->task_num == 0) {
            event_num--;
        }
        return true;
    });

    async_thread_lock.lock();
    if (!async_thread_pool) {
        async_thread_pool = std::make_shared<async::ThreadPool>(
            SwooleG.aio_core_worker_num, SwooleG.aio_worker_num, SwooleG.aio_max_wait_time, SwooleG.aio_max_idle_time);
    }
    if (!async_thread_pool->is_running()) {
        async_thread_pool->start();
    }
    pool = async_thread_pool;
    async_thread_lock.unlock();

    SwooleG.aio_default_socket = write_socket;
    SwooleTG.async_threads = this;
}

AsyncThreads::~AsyncThreads() {
    pool.reset();
    async_thread_lock.lock();
    /**
     * When the reference count is 1, it means that all reactor threads have ended
     * and all aio threads can be terminated.
     */
    if (async_thread_pool.use_count() == 1) {
        async_thread_pool->shutdown();
    }
    async_thread_lock.unlock();
    pipe->close();
    read_socket = nullptr;
    write_socket = nullptr;
    delete pipe;
    pipe = nullptr;
}
};  // namespace swoole
