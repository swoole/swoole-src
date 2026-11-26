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

#include "swoole_socket.h"
#include "swoole_reactor.h"
#include "swoole_pipe.h"
#include "swoole_async.h"
#include "swoole_util.h"
#include "swoole_thread.h"
#include "swoole_signal.h"

#include <thread>
#include <atomic>
#include <algorithm>
#include <list>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <new>
#include <system_error>

static std::mutex async_thread_lock;
static std::shared_ptr<swoole::async::ThreadPool> async_thread_pool;

swoole::AsyncThreads *sw_async_threads() {
    return SwooleTG.async_threads;
}

namespace swoole {
namespace async {
//-------------------------------------------------------------------------------
struct Task {
    AsyncThreads *receiver;
    AsyncEvent event;

    Task(AsyncThreads *receiver, const AsyncEvent &request) : receiver(receiver), event(request) {}
};

using TaskList = std::list<Task>;

struct CompletionQueue {
    // Protected by ThreadPool::event_mutex. The reactor waits for active handlers
    // before releasing contexts referenced by their requests.
    TaskList tasks;
    size_t active = 0;
    bool stopping = false;
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

    bool start() {
        running.store(true, std::memory_order_release);
        current_task_id = 0;
        for (size_t i = 0; i < core_worker_num; i++) {
            if (!create_thread(true)) {
                shutdown();
                return false;
            }
        }
        return true;
    }

    bool shutdown() {
        std::thread retired;
        do {
            std::lock_guard<std::mutex> lock(event_mutex);
            if (!running.load(std::memory_order_relaxed)) {
                return false;
            }
            running.store(false, std::memory_order_release);
            retired = std::move(retired_thread);
        } while (0);

        _cv.notify_all();

        std::list<std::thread> shutdown_threads;
        {
            std::lock_guard<std::mutex> lock(threads_mutex);
            shutdown_threads.swap(threads);
        }

        for (auto &thread : shutdown_threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }

        // A retiree already picked up by a worker was joined by that worker.
        if (retired.joinable()) {
            retired.join();
        }
        n_closing.store(0, std::memory_order_release);
        return true;
    }

    void schedule(double now) {
        const size_t thread_count = get_worker_num();
        if (thread_count >= worker_num || queue_.empty()) {
            return;
        }

        const size_t idle_worker_num = n_waiting.load(std::memory_order_acquire);
        const size_t queue_size = queue_.size();
        const bool insufficient_idle_workers = queue_size > idle_worker_num;
        const double queue_wait_time = now - queue_.front().event.timestamp;
        const bool waited_too_long = max_wait_time > 0 && queue_wait_time > max_wait_time;
        if (!insufficient_idle_workers && !waited_too_long) {
            return;
        }

        size_t n = insufficient_idle_workers ? queue_size - idle_worker_num : 1;
        n = SW_MIN(n, worker_num - thread_count);
        scale_up_count.fetch_add(1, std::memory_order_acq_rel);
        swoole_trace_log(SW_TRACE_AIO,
                         "Create %zu thread due to queue_size=%zu, idle_workers=%zu, wait=%fs, we will have %zu "
                         "threads",
                         n,
                         queue_size,
                         idle_worker_num,
                         queue_wait_time,
                         thread_count + n);
        for (size_t i = 0; i < n; i++) {
            if (!create_thread()) {
                break;
            }
        }
    }

    AsyncEvent *dispatch(AsyncThreads *receiver, const AsyncEvent &request) {
        std::unique_lock<std::mutex> lock(event_mutex);
        if (sw_unlikely(!running.load(std::memory_order_relaxed) || receiver->completions->stopping)) {
            swoole_set_last_error(SW_ERROR_WRONG_OPERATION);
            return nullptr;
        }
        if (sw_unlikely(!receiver->write_socket)) {
            swoole_set_last_error(SW_ERROR_SYSTEM_CALL_FAIL);
            return nullptr;
        }
        queue_.emplace_back(receiver, request);
        auto &event = queue_.back().event;
        event.task_id = current_task_id++;
        event.timestamp = std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
        // Schedule after the push so the queued task is counted; a task that arrives while every
        // worker is blocked would otherwise never trigger pool growth.
        schedule(event.timestamp);
        lock.unlock();
        _cv.notify_one();
        return &event;
    }

    size_t get_worker_num() const {
        std::lock_guard<std::mutex> lock(threads_mutex);
        return threads.size();
    }

    size_t get_idle_worker_num() const {
        return n_waiting.load(std::memory_order_acquire);
    }

    size_t get_closing_num() const {
        return n_closing.load(std::memory_order_acquire);
    }

    size_t get_peak_worker_num() const {
        return peak_worker_num.load(std::memory_order_acquire);
    }

    size_t get_created_worker_num() const {
        return created_worker_num.load(std::memory_order_acquire);
    }

    size_t get_released_worker_num() const {
        return released_worker_num.load(std::memory_order_acquire);
    }

    size_t get_scale_up_count() const {
        return scale_up_count.load(std::memory_order_acquire);
    }

    size_t get_scale_down_count() const {
        return scale_down_count.load(std::memory_order_acquire);
    }

    size_t get_queue_size() {
        std::lock_guard<std::mutex> lock(event_mutex);
        return queue_.size();
    }

    void notify_one() {
        _cv.notify_one();
    }

    void stop_receiving(AsyncThreads *receiver, bool deliver_pending);
    void take_completions(AsyncThreads *receiver, TaskList &tasks) {
        std::lock_guard<std::mutex> lock(event_mutex);
        tasks.swap(receiver->completions->tasks);
    }
    void restore_completions(AsyncThreads *receiver, TaskList &tasks);

  private:
    bool create_thread(bool is_core_worker = false);
    void main_func(bool is_core_worker, TaskList &work);
    std::thread take_thread(std::thread::id tid);
    static void notify_receiver(AsyncThreads *receiver);
    void complete(TaskList &work);

    size_t core_worker_num;
    size_t worker_num;
    double max_wait_time;
    double max_idle_time;

    std::atomic_bool running{false};

    std::atomic<size_t> n_waiting{0};
    std::atomic<size_t> n_closing{0};
    std::atomic<size_t> peak_worker_num{0};
    std::atomic<size_t> created_worker_num{0};
    std::atomic<size_t> released_worker_num{0};
    std::atomic<size_t> scale_up_count{0};
    std::atomic<size_t> scale_down_count{0};
    size_t current_task_id = 0;
    std::list<std::thread> threads;
    mutable std::mutex threads_mutex;
    TaskList queue_;
    std::mutex event_mutex;
    // Excluded from pool capacity. The handle is handed off under event_mutex and joined outside it.
    std::thread retired_thread;
    std::condition_variable _cv;
    std::condition_variable receiver_idle;
};

std::thread ThreadPool::take_thread(std::thread::id tid) {
    std::lock_guard<std::mutex> lock(threads_mutex);
    auto it = std::find_if(
        threads.begin(), threads.end(), [tid](const std::thread &worker) { return worker.get_id() == tid; });
    if (it == threads.end()) {
        return {};
    }
    auto worker = std::move(*it);
    threads.erase(it);
    return worker;
}

void ThreadPool::notify_receiver(AsyncThreads *receiver) {
    if (!receiver->write_socket) {
        return;
    }
    const char ready = 0;
    ssize_t n;
    int error;
    do {
        n = ::send(receiver->write_socket->fd, &ready, sizeof(ready), MSG_NOSIGNAL);
        error = n < 0 ? sw_errno() : 0;
    } while (n < 0 && error == EINTR);
    if (n > 0 || error == EAGAIN || error == EWOULDBLOCK) {
        return;
    }

    swoole_sys_warning("wake AIO reactor failed");
    // The receiver still owns the queued results. Closing the write end wakes it via EOF.
    receiver->pipe->close(SW_PIPE_CLOSE_MASTER);
    receiver->write_socket = nullptr;
}

void ThreadPool::complete(TaskList &work) {
    auto *receiver = work.front().receiver;
    std::lock_guard<std::mutex> lock(event_mutex);
    auto &completions = *receiver->completions;
    const bool needs_wakeup = completions.tasks.empty() && !completions.stopping;
    completions.tasks.splice(completions.tasks.end(), work);
    if (needs_wakeup) {
        notify_receiver(receiver);
    }
    if (--completions.active == 0 && completions.stopping) {
        receiver_idle.notify_all();
    }
}

void ThreadPool::restore_completions(AsyncThreads *receiver, TaskList &tasks) {
    std::lock_guard<std::mutex> lock(event_mutex);
    auto &pending = receiver->completions->tasks;
    const bool needs_wakeup = pending.empty();
    pending.splice(pending.begin(), tasks);
    if (needs_wakeup) {
        notify_receiver(receiver);
    }
}

void ThreadPool::stop_receiving(AsyncThreads *receiver, bool deliver_pending) {
    TaskList abandoned;
    std::unique_lock<std::mutex> lock(event_mutex);
    auto &completions = *receiver->completions;
    if (!completions.stopping) {
        completions.stopping = true;
        for (auto it = queue_.begin(); it != queue_.end();) {
            auto current = it++;
            if (current->receiver == receiver) {
                abandoned.splice(abandoned.end(), queue_, current);
            }
        }
    }

    // A running handler may still refer to a suspended coroutine's stack. Only that
    // receiver waits, and the wait releases the pool lock for workers and other reactors.
    receiver_idle.wait(lock, [&completions] { return completions.active == 0; });
    if (deliver_pending) {
        for (auto &task : abandoned) {
            task.event.error = SW_ERROR_SYSTEM_CALL_FAIL;
            task.event.retval = -1;
        }
        completions.tasks.splice(completions.tasks.end(), abandoned);
    } else {
        abandoned.splice(abandoned.end(), completions.tasks);
    }
}

void ThreadPool::main_func(const bool is_core_worker, TaskList &work) {
    const auto idle_timeout =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::duration<double>(max_idle_time));
    const auto safe_idle_timeout = idle_timeout.count() > 0 ? idle_timeout : std::chrono::microseconds(1);

    while (running.load(std::memory_order_acquire)) {
        bool timed_out = false;
        std::unique_lock<std::mutex> lock(event_mutex);
        const auto ready = [this] {
            return retired_thread.joinable() || !queue_.empty() || !running.load(std::memory_order_acquire);
        };
        n_waiting.fetch_add(1, std::memory_order_acq_rel);
        if (is_core_worker || max_idle_time <= 0) {
            _cv.wait(lock, ready);
        } else {
            timed_out = !_cv.wait_for(lock, safe_idle_timeout, ready);
        }
        n_waiting.fetch_sub(1, std::memory_order_acq_rel);

        if (retired_thread.joinable()) {
            auto worker = std::move(retired_thread);
            lock.unlock();
            worker.join();
            released_worker_num.fetch_add(1, std::memory_order_acq_rel);
            scale_down_count.fetch_add(1, std::memory_order_acq_rel);
            n_closing.store(0, std::memory_order_release);
            continue;
        }
        if (timed_out && n_closing.load(std::memory_order_acquire) == 0) {
            retired_thread = take_thread(std::this_thread::get_id());
            if (retired_thread.joinable()) {
                n_closing.store(1, std::memory_order_release);
                lock.unlock();
                _cv.notify_one();
                break;
            }
        }

        if (queue_.empty() || !running.load(std::memory_order_relaxed)) {
            continue;
        }
        work.splice(work.end(), queue_, queue_.begin());
        ++work.front().receiver->completions->active;
        lock.unlock();

        auto *event = &work.front().event;
        try {
            if (sw_unlikely(event->handler == nullptr)) {
                event->error = SW_ERROR_AIO_BAD_REQUEST;
                event->retval = -1;
            } else if (sw_unlikely(event->is_canceled())) {
                event->error = SW_ERROR_AIO_CANCELED;
                event->retval = -1;
            } else {
                event->handler(event);
            }
        } catch (const Exception &error) {
            event->error = error.code;
            event->retval = -1;
        } catch (const std::bad_alloc &) {
            event->error = SW_ERROR_MALLOC_FAIL;
            event->retval = -1;
        } catch (...) {
            event->error = SW_ERROR_AIO_BAD_REQUEST;
            event->retval = -1;
        }
        swoole_trace_log(SW_TRACE_AIO, "aio_thread completed. ret=%ld, error=%d", event->retval, event->error);
        complete(work);
    }
}

bool ThreadPool::create_thread(const bool is_core_worker) {
    const bool restore_signal_mask = swoole_signal_block_all();
    ON_SCOPE_EXIT {
        if (restore_signal_mask) {
            swoole_signal_unblock_all();
        }
    };

    try {
        std::lock_guard<std::mutex> lock(threads_mutex);
        std::promise<bool> startup;
        auto initialized = startup.get_future();
        // Construct the thread in its owning node, so no allocation can fail between starting and storing it.
        threads.emplace_back([this, is_core_worker, startup = std::move(startup), work = TaskList{}]() mutable {
            try {
                swoole_thread_init(false);
            } catch (...) {
                startup.set_value(false);
                return;
            }
            startup.set_value(true);
            main_func(is_core_worker, work);
            swoole_thread_clean(false);
        });
        if (!initialized.get()) {
            threads.back().join();
            threads.pop_back();
            swoole_warning("initialize aio thread failed");
            return false;
        }
        const size_t thread_count = threads.size();
        created_worker_num.fetch_add(1, std::memory_order_acq_rel);
        if (thread_count > peak_worker_num.load(std::memory_order_relaxed)) {
            peak_worker_num.store(thread_count, std::memory_order_release);
        }
        return true;
    } catch (const std::exception &) {
        swoole_sys_notice("create aio thread failed, please check your system configuration or adjust aio_worker_num");
        return false;
    }
}

AsyncEvent *dispatch(const AsyncEvent *request) try {
    if (sw_unlikely(!swoole_event_is_available())) {
        swoole_set_last_error(SW_ERROR_WRONG_OPERATION);
        return nullptr;
    }
    if (sw_unlikely(!SwooleTG.async_threads)) {
        SwooleTG.async_threads = new AsyncThreads();
    }
    auto *receiver = SwooleTG.async_threads;
    AsyncEvent *event = receiver->pool->dispatch(receiver, *request);
    if (sw_likely(event)) {
        receiver->task_num++;
    }
    return event;
} catch (const Exception &error) {
    swoole_set_last_error(error.code);
    return nullptr;
} catch (const std::bad_alloc &) {
    swoole_set_last_error(SW_ERROR_MALLOC_FAIL);
    return nullptr;
}

#ifndef _WIN32
bool fork_without_pool(pid_t *pid) {
    std::lock_guard<std::mutex> lock(async_thread_lock);
    if (sw_unlikely(async_thread_pool)) {
        return false;
    }
    if (pid) {
        // Keep another reactor from starting an AIO pool between this check and fork.
        *pid = ::fork();
    }
    return true;
}
#endif

//-------------------------------------------------------------------------------
}  // namespace async

int AsyncThreads::callback(Reactor *reactor, Event *event) {
    auto *receiver = SwooleTG.async_threads;
    async::TaskList batch;
    char bytes[SW_AIO_EVENT_NUM];
    const ssize_t n = event->socket->read(bytes, sizeof(bytes));
    if (sw_unlikely(n < 0)) {
        const int error = sw_errno();
        if (error == EINTR || (!event->socket->event_hup && (error == EAGAIN || error == EWOULDBLOCK))) {
            return SW_OK;
        }
        swoole_sys_warning("read() AIO wakeup failed");
    }
    if (sw_unlikely(n <= 0)) {
        receiver->pool->stop_receiving(receiver, true);
    }

    receiver->pool->take_completions(receiver, batch);
    ON_SCOPE_EXIT {
        if (!batch.empty()) {
            // A native callback may throw. Retain the rest of the batch and wake the reactor again.
            receiver->pool->restore_completions(receiver, batch);
        }
    };
    while (!batch.empty()) {
        auto &completed = batch.front().event;
        ON_SCOPE_EXIT {
            receiver->task_num--;
            batch.pop_front();
        };
        if (!completed.is_canceled() && completed.callback) {
            completed.callback(&completed);
        }
    }
    if (sw_unlikely(n <= 0)) {
        reactor->del(event->socket);
    }

    return SW_OK;
}

size_t AsyncThreads::get_worker_num() const {
    return pool->get_worker_num();
}

size_t AsyncThreads::get_idle_worker_num() const {
    return pool->get_idle_worker_num();
}

size_t AsyncThreads::get_pending_release_worker_num() const {
    return pool->get_closing_num();
}

size_t AsyncThreads::get_peak_worker_num() const {
    return pool->get_peak_worker_num();
}

size_t AsyncThreads::get_created_worker_num() const {
    return pool->get_created_worker_num();
}

size_t AsyncThreads::get_released_worker_num() const {
    return pool->get_released_worker_num();
}

size_t AsyncThreads::get_scale_up_count() const {
    return pool->get_scale_up_count();
}

size_t AsyncThreads::get_scale_down_count() const {
    return pool->get_scale_down_count();
}

size_t AsyncThreads::get_queue_size() const {
    return pool->get_queue_size();
}

void AsyncThreads::notify_one() const {
    pool->notify_one();
}

AsyncThreads::AsyncThreads() : completions(std::make_unique<async::CompletionQueue>()) {
    if (!swoole_event_is_available()) {
        swoole_warning("no event loop, cannot initialized");
        throw Exception(SW_ERROR_WRONG_OPERATION);
    }

    std::unique_ptr<SocketPair> new_pipe(
#ifdef _WIN32
        new Pipe(false));
#else
        new UnixSocket(false, SOCK_STREAM));
#endif
    if (!new_pipe->ready()) {
        throw Exception(SW_ERROR_SYSTEM_CALL_FAIL);
    }

    read_socket = new_pipe->get_socket(false);
    write_socket = new_pipe->get_socket(true);
    read_socket->fd_type = SW_FD_AIO;
    write_socket->fd_type = SW_FD_AIO;

    bool registered = false;
    ON_SCOPE_EXIT {
        if (new_pipe) {
            if (registered) {
                swoole_event_del(read_socket);
            }
            read_socket = nullptr;
            write_socket = nullptr;
        }
    };
    if (swoole_event_add(read_socket, SW_EVENT_READ) < 0) {
        throw Exception(SW_ERROR_SYSTEM_CALL_FAIL);
    }
    registered = true;

    sw_reactor()->destroy_callbacks.prepend(
        [](void *) {
            if (!SwooleTG.async_threads) {
                return;
            }
            auto *receiver = SwooleTG.async_threads;
            if (!receiver->read_socket->removed) {
                swoole_event_del(receiver->read_socket);
            }
            SwooleTG.async_threads = nullptr;
            delete receiver;
        },
        nullptr);

    sw_reactor()->set_exit_condition(Reactor::EXIT_CONDITION_AIO_TASK, [](Reactor *reactor, size_t &event_num) -> bool {
        auto *receiver = SwooleTG.async_threads;
        if (receiver) {
            if (receiver->task_num != 0) {
                return false;
            }
            if (reactor->exists(receiver->read_socket) && event_num > 0) {
                event_num--;
            }
        }
        return true;
    });

    std::unique_lock<std::mutex> lock(async_thread_lock);
    if (sw_unlikely(!async_thread_pool)) {
        auto new_pool = std::make_shared<async::ThreadPool>(
            SwooleG.aio_core_worker_num, SwooleG.aio_worker_num, SwooleG.aio_max_wait_time, SwooleG.aio_max_idle_time);
        if (sw_unlikely(!new_pool->start())) {
            throw Exception(SW_ERROR_SYSTEM_CALL_FAIL);
        }
        async_thread_pool = std::move(new_pool);
    }
    pool = async_thread_pool;
    lock.unlock();

    pipe = new_pipe.release();
    SwooleTG.async_threads = this;
}

AsyncThreads::~AsyncThreads() {
    pool->stop_receiving(this, false);
    do {
        std::lock_guard<std::mutex> lock(async_thread_lock);
        pool.reset();
        if (async_thread_pool.use_count() == 1) {
            async_thread_pool.reset();
        }
    } while (0);
    pipe->close();
    read_socket = nullptr;
    write_socket = nullptr;
    delete pipe;
    pipe = nullptr;
}
};  // namespace swoole
