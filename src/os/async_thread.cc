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

#include "swoole.h"
#include "swoole_api.h"
#include "swoole_socket.h"
#include "swoole_reactor.h"
#include "swoole_string.h"
#include "swoole_signal.h"
#include "swoole_pipe.h"
#include "swoole_async.h"
#include "swoole_util.h"
#include "swoole_coroutine.h"
#if defined(__linux__) && defined(SW_USE_IOURING)
#include "linux/version.h"
#endif

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
            return microtime() - event->timestamp;
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
        if (SwooleTG.async_threads->schedule) {
            schedule();
        }
        auto _event_copy = new AsyncEvent(*request);
        _event_copy->task_id = current_task_id++;
        _event_copy->timestamp = microtime();
        _event_copy->pipe_socket = SwooleTG.async_threads->write_socket;
        event_mutex.lock();
        _queue.push(_event_copy);
        _cv.notify_one();
        event_mutex.unlock();
        swoole_debug("push and notify one: %f", microtime());
        return _event_copy;
    }

    inline size_t get_worker_num() {
        return threads.size();
    }

    inline size_t get_queue_size() {
        std::unique_lock<std::mutex> lock(event_mutex);
        return _queue.count();
    }

    static std::string get_thread_id(std::thread::id id) {
        std::stringstream ss;
        ss << id;
        return ss.str();
    }

    void release_thread(std::thread::id tid) {
        auto i = threads.find(tid);
        if (i == threads.end()) {
            swoole_warning("AIO thread#%s is missing", get_thread_id(tid).c_str());
            return;
        } else {
            std::thread *_thread = i->second;
            swoole_trace_log(SW_TRACE_AIO,
                             "release idle thread#%s, we have %zu now",
                             get_thread_id(tid).c_str(),
                             threads.size() - 1);
            if (_thread->joinable()) {
                _thread->join();
            }
            threads.erase(i);
            delete _thread;
        }
    }

    static void release_callback(AsyncEvent *event) {
        std::thread::id *tid = reinterpret_cast<std::thread::id *>(event->object);
        SwooleTG.async_threads->pool->release_thread(*tid);
        delete tid;
        // balance
        SwooleTG.async_threads->task_num++;
    }

    void notify_one() {
        _cv.notify_one();
    }

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
    std::unordered_map<std::thread::id, std::thread *> threads;
    EventQueue _queue;
    std::mutex event_mutex;
    std::condition_variable _cv;
};

void ThreadPool::create_thread(const bool is_core_worker) {
    try {
        std::thread *_thread = new std::thread([this, is_core_worker]() {
            bool exit_flag = false;
            SwooleTG.buffer_stack = new String(SW_STACK_BUFFER_SIZE);
            ON_SCOPE_EXIT {
                delete SwooleTG.buffer_stack;
                SwooleTG.buffer_stack = nullptr;
            };

            swoole_signal_block_all();

            while (running) {
                event_mutex.lock();
                AsyncEvent *event = _queue.pop();
                event_mutex.unlock();

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
                                swoole_sys_warning("sendto swoole_aio_pipe_write failed");
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
                            if (_cv.wait_for(lock, std::chrono::microseconds((size_t) (max_idle_time * 1000 * 1000))) ==
                                std::cv_status::timeout) {
                                if (running && n_closing != 0) {
                                    // wait for the next round
                                    continue;
                                }
                                /* notifies the main thread to release this thread */
                                event = new AsyncEvent;
                                event->object = new std::thread::id(std::this_thread::get_id());
                                event->callback = release_callback;
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
        swoole_sys_notice("create aio thread failed, please check your system configuration or adjust aio_worker_num");
        return;
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
    if (SwooleTG.async_threads->schedule) {
        SwooleTG.async_threads->pool->schedule();
    }

    AsyncEvent *events[SW_AIO_EVENT_NUM];
    ssize_t n = event->socket->read(events, sizeof(AsyncEvent *) * SW_AIO_EVENT_NUM);
    if (n < 0) {
        swoole_sys_warning("read() aio events failed");
        return SW_ERR;
    }
    for (size_t i = 0; i < n / sizeof(AsyncEvent *); i++) {
        AsyncEvent *event = events[i];
        if (!event->canceled) {
            event->callback(event);
        }
        SwooleTG.async_threads->task_num--;
        delete event;
    }

    return SW_OK;
}

size_t AsyncThreads::get_worker_num() {
    return pool ? pool->get_worker_num() : 0;
}

size_t AsyncThreads::get_queue_size() {
    return pool ? pool->get_queue_size() : 0;
}

void AsyncThreads::notify_one() {
    if (pool) {
        pool->notify_one();
    }
}

AsyncThreads::AsyncThreads() {
    if (!SwooleTG.reactor) {
        swoole_warning("no event loop, cannot initialized");
        throw swoole::Exception(SW_ERROR_WRONG_OPERATION);
    }

    pipe = new Pipe(false);
    if (!pipe->ready()) {
        delete pipe;
        pipe = nullptr;
        swoole_throw_error(SW_ERROR_SYSTEM_CALL_FAIL);
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

    init_lock.lock();
    pool = new async::ThreadPool(
        SwooleG.aio_core_worker_num, SwooleG.aio_worker_num, SwooleG.aio_max_wait_time, SwooleG.aio_max_idle_time);
    pool->start();
    schedule = true;
    init_lock.unlock();

    SwooleG.aio_default_socket = write_socket;
    SwooleTG.async_threads = this;
}

AsyncThreads::~AsyncThreads() {
    delete pool;
    pool = nullptr;
    pipe->close();
    read_socket = nullptr;
    write_socket = nullptr;
    delete pipe;
    pipe = nullptr;
}

#if defined(__linux__) && defined(SW_USE_IOURING)
AsyncIOUring::AsyncIOUring(Reactor *reactor_) {
    if (!SwooleTG.reactor) {
        swoole_warning("no event loop, cannot initialized");
        throw swoole::Exception(SW_ERROR_WRONG_OPERATION);
    }

    reactor = reactor_;
    if (SwooleG.iouring_entries > 0) {
        uint32_t i = 6;
        while ((1U << i) < SwooleG.iouring_entries) {
            i++;
        }
        entries = 1 << i;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
    int ret = io_uring_queue_init(entries, &ring, IORING_SETUP_COOP_TASKRUN | IORING_SETUP_SUBMIT_ALL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    int ret = io_uring_queue_init(
        entries, &ring, IORING_SETUP_COOP_TASKRUN | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_SINGLE_ISSUER);
#else
    int ret = io_uring_queue_init(entries, &ring, 0);
#endif

    if (ret < 0) {
        swoole_warning("create io_uring failed");
        throw swoole::Exception(SW_ERROR_WRONG_OPERATION);
        return;
    }
    ring_fd = ring.ring_fd;

    iou_socket = make_socket(ring_fd, SW_FD_IOURING);
    if (!iou_socket) {
        swoole_sys_warning("create io_uring socket failed");
        return;
    }

    reactor->set_exit_condition(Reactor::EXIT_CONDITION_IOURING, [](Reactor *reactor, size_t &event_num) -> bool {
        if (SwooleTG.async_iouring && SwooleTG.async_iouring->get_task_num() == 0 &&
            SwooleTG.async_iouring->is_empty_wait_events()) {
            event_num--;
        }
        return true;
    });

    reactor->add_destroy_callback([](void *data) {
        if (!SwooleTG.async_iouring) {
            return;
        }
        SwooleTG.async_iouring->delete_event();
        delete SwooleTG.async_iouring;
        SwooleTG.async_iouring = nullptr;
    });
}

AsyncIOUring::~AsyncIOUring() {
    if (ring_fd >= 0) {
        ::close(ring_fd);
    }

    if (iou_socket) {
        delete iou_socket;
    }

    io_uring_queue_exit(&ring);
}

void AsyncIOUring::add_event() {
    reactor->add(iou_socket, SW_EVENT_READ);
}

void AsyncIOUring::delete_event() {
    reactor->del(iou_socket);
}

bool AsyncIOUring::wakeup() {
    unsigned num = entries * 2;
    struct io_uring_cqe *cqes[num];
    unsigned count = get_iouring_cqes(cqes, num);
    if (count == 0) {
        return true;
    }
    if (count < 0) {
        return false;
    }

    unsigned i = 0;
    AsyncEvent *tasks[count];
    void *data = nullptr;
    AsyncEvent *task = nullptr;
    struct io_uring_cqe *cqe = nullptr;
    for (i = 0; i < count; i++) {
        cqe = cqes[i];
        data = get_iouring_cqe_data(cqe);
        task = reinterpret_cast<AsyncEvent *>(data);

        task->retval = cqe->res;
        /**
         * cqe->res indicates a negative value of errno. Here, -17 indicates that the folder has already been
         * created by another process, so we can simply return 0 in this case.
         */
        if (task->opcode == AsyncIOUring::SW_IORING_OP_MKDIRAT && cqe->res == -17) {
            task->retval = 0;
        }

        tasks[i] = task;
        task_num--;
    }
    finish_iouring_cqes(count);

    AsyncEvent *waitEvent = nullptr;
    for (i = 0; i < count; i++) {
        task = tasks[i];
        if (is_empty_wait_events()) {
            task->callback(task);
            continue;
        }

        waitEvent = waitEvents.front();
        waitEvents.pop();
        if (waitEvent->opcode == AsyncIOUring::SW_IORING_OP_OPENAT) {
            open(waitEvent);
        } else if (waitEvent->opcode == AsyncIOUring::SW_IORING_OP_CLOSE) {
            close(waitEvent);
        } else if (waitEvent->opcode == AsyncIOUring::SW_IORING_OP_FSTAT ||
                   waitEvent->opcode == AsyncIOUring::SW_IORING_OP_LSTAT) {
            statx(waitEvent);
        } else if (waitEvent->opcode == AsyncIOUring::SW_IORING_OP_READ ||
                   waitEvent->opcode == AsyncIOUring::SW_IORING_OP_WRITE) {
            wr(waitEvent);
        } else if (waitEvent->opcode == AsyncIOUring::SW_IORING_OP_RENAMEAT) {
            rename(waitEvent);
        } else if (waitEvent->opcode == AsyncIOUring::SW_IORING_OP_UNLINK_FILE ||
                   waitEvent->opcode == AsyncIOUring::SW_IORING_OP_UNLINK_DIR) {
            unlink(waitEvent);
        } else if (waitEvent->opcode == AsyncIOUring::SW_IORING_OP_MKDIRAT) {
            mkdir(waitEvent);
        } else if (waitEvent->opcode == AsyncIOUring::SW_IORING_OP_FSYNC ||
                   waitEvent->opcode == AsyncIOUring::SW_IORING_OP_FDATASYNC) {
            fsync(waitEvent);
        }

        task->callback(task);
    }

    return true;
}

bool AsyncIOUring::open(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waitEvents.push(event);
        return true;
    }

    set_iouring_sqe_data(sqe, (void *) event);
    sqe->addr = (uintptr_t) event->pathname;
    sqe->fd = AT_FDCWD;
    sqe->len = event->mode;
    sqe->opcode = SW_IORING_OP_OPENAT;
    sqe->open_flags = event->flags | O_CLOEXEC;

    bool result = submit_iouring_sqe();

    if (!result) {
        return false;
    }

    task_num++;
    return true;
}

bool AsyncIOUring::close(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waitEvents.push(event);
        return true;
    }

    set_iouring_sqe_data(sqe, (void *) event);
    sqe->fd = event->fd;
    sqe->opcode = SW_IORING_OP_CLOSE;

    bool result = submit_iouring_sqe();

    if (!result) {
        return false;
    }

    task_num++;
    return true;
}

bool AsyncIOUring::wr(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waitEvents.push(event);
        return true;
    }

    set_iouring_sqe_data(sqe, (void *) event);
    sqe->fd = event->fd;
    sqe->addr = event->opcode == SW_IORING_OP_READ ? (uintptr_t) event->rbuf : (uintptr_t) event->wbuf;
    sqe->len = event->count;
    sqe->off = -1;
    sqe->opcode = event->opcode;

    bool result = submit_iouring_sqe();

    if (!result) {
        return false;
    }

    task_num++;
    return true;
}

bool AsyncIOUring::statx(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waitEvents.push(event);
        return true;
    }

    set_iouring_sqe_data(sqe, (void *) event);
    if (event->opcode == SW_IORING_OP_FSTAT) {
        sqe->addr = (uintptr_t) "";
        sqe->fd = event->fd;
        sqe->statx_flags |= AT_EMPTY_PATH;
    } else {
        sqe->addr = (uintptr_t) event->pathname;
        sqe->fd = AT_FDCWD;
        sqe->statx_flags |= AT_SYMLINK_NOFOLLOW;
    }
    //    sqe->len = 0xFFF;
    sqe->opcode = SW_IORING_OP_STATX;
    sqe->off = (uintptr_t) event->statxbuf;

    bool result = submit_iouring_sqe();

    if (!result) {
        return false;
    }

    task_num++;
    return true;
}

bool AsyncIOUring::mkdir(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waitEvents.push(event);
        return true;
    }

    set_iouring_sqe_data(sqe, (void *) event);
    sqe->addr = (uintptr_t) event->pathname;
    sqe->fd = AT_FDCWD;
    sqe->len = event->mode;
    sqe->opcode = SW_IORING_OP_MKDIRAT;
    bool result = submit_iouring_sqe();

    if (!result) {
        return false;
    }

    task_num++;
    return true;
}

bool AsyncIOUring::unlink(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waitEvents.push(event);
        return true;
    }

    set_iouring_sqe_data(sqe, (void *) event);

    sqe->addr = (uintptr_t) event->pathname;
    sqe->fd = AT_FDCWD;
    sqe->opcode = SW_IORING_OP_UNLINKAT;
    if (event->opcode == SW_IORING_OP_UNLINK_DIR) {
        sqe->unlink_flags |= AT_REMOVEDIR;
    }
    bool result = submit_iouring_sqe();

    if (!result) {
        return false;
    }

    task_num++;
    return true;
}

bool AsyncIOUring::rename(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waitEvents.push(event);
        return true;
    }

    set_iouring_sqe_data(sqe, (void *) event);

    sqe->addr = (uintptr_t) event->pathname;
    sqe->addr2 = (uintptr_t) event->pathname2;
    sqe->fd = AT_FDCWD;
    sqe->len = AT_FDCWD;
    sqe->opcode = SW_IORING_OP_RENAMEAT;
    bool result = submit_iouring_sqe();

    if (!result) {
        return false;
    }

    task_num++;
    return true;
}

bool AsyncIOUring::fsync(AsyncEvent *event) {
    struct io_uring_sqe *sqe = get_iouring_sqe();
    if (!sqe) {
        waitEvents.push(event);
        return true;
    }

    set_iouring_sqe_data(sqe, (void *) event);
    sqe->fd = event->fd;
    sqe->addr = (unsigned long) nullptr;
    sqe->opcode = IORING_OP_FSYNC;
    sqe->len = 0;
    sqe->off = 0;
    sqe->fsync_flags = 0;

    if (event->opcode == SW_IORING_OP_FDATASYNC) {
        sqe->fsync_flags = IORING_FSYNC_DATASYNC;
    }

    bool result = submit_iouring_sqe();

    if (!result) {
        return false;
    }

    task_num++;
    return true;
}

int AsyncIOUring::callback(Reactor *reactor, Event *event) {
    AsyncIOUring *iouring = SwooleTG.async_iouring;
    return iouring->wakeup() ? 1 : 0;
}
#endif
};  // namespace swoole
