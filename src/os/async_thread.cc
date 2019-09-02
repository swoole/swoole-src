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
#include "async.h"

#include <thread>
#include <atomic>
#include <unordered_map>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <queue>

using namespace std;

typedef swAio_event AsyncEvent;

static std::once_flag init_flag;
static std::atomic<int> refcount;

static void aio_thread_release(AsyncEvent *event);

namespace swoole { namespace async {
//-------------------------------------------------------------------------------
class EventQueue
{
public:
    inline void push(AsyncEvent *event)
    {
        unique_lock<mutex> lock(_mutex);
        _queue.push(event);
    }

    inline AsyncEvent* pop()
    {
        unique_lock<mutex> lock(_mutex);
        if (_queue.empty())
        {
            return nullptr;
        }
        AsyncEvent* retval = _queue.front();
        _queue.pop();
        return retval;
    }

    inline double get_max_wait_time()
    {
        unique_lock<mutex> lock(_mutex);
        if (_queue.empty())
        {
            return 0;
        }
        else
        {
            AsyncEvent* event = _queue.front();
            return swoole_microtime() - event->timestamp;
        }
    }

    inline size_t count()
    {
        unique_lock<mutex> lock(_mutex);
        return _queue.size();
    }

private:
    queue<AsyncEvent *> _queue;
    mutex _mutex;
};

class ThreadPool
{
public:
    ThreadPool(size_t _core_worker_num, size_t _worker_num, double _max_wait_time, double _max_idle_time)
    {
        running = false;

        core_worker_num = _core_worker_num == 0 ? SW_CPU_NUM : SW_MAX(1, _core_worker_num);
        worker_num = _worker_num == 0 ? SW_CPU_NUM * SW_AIO_THREAD_NUM_MULTIPLE : SW_MAX(core_worker_num, _worker_num);
        max_wait_time = _max_wait_time == 0 ? SW_AIO_TASK_MAX_WAIT_TIME : _max_wait_time;
        max_idle_time = _max_idle_time == 0 ? SW_AIO_THREAD_MAX_IDLE_TIME : _max_idle_time;

        current_pid = getpid();
    }

    ~ThreadPool()
    {
        shutdown();
    }

    bool start()
    {
        running = true;
        current_task_id = 0;
        n_waiting = 0;
        n_closing = 0;
        for (size_t i = 0; i < core_worker_num; i++)
        {
            create_thread(true);
        }
        return true;
    }

    bool shutdown()
    {
        if (!running)
        {
            return false;
        }
        running = false;

        event_mutex.lock();
        _cv.notify_all();
        event_mutex.unlock();

        for (auto &i : threads)
        {
            thread *_thread = i.second;
            if (_thread->joinable())
            {
                _thread->join();
            }
            delete _thread;
        }

        return true;
    }

    void schedule()
    {
        unique_lock<mutex> lock(schedule_mutex);
        if (n_waiting == 0 && threads.size() < worker_num && max_wait_time > 0)
        {
            double _max_wait_time = _queue.get_max_wait_time();
            if (_max_wait_time > max_wait_time)
            {
                size_t n = 1;
                /**
                 * maybe we can find a better strategy
                 */
                if (threads.size() + n > worker_num)
                {
                    n = worker_num - threads.size();
                }
                swTraceLog(SW_TRACE_AIO, "Create %zu thread due to wait %fs, we will have %zu threads", n, _max_wait_time, threads.size() + n);
                while (n--)
                {
                    create_thread();
                }
            }
        }
    }

    AsyncEvent* dispatch(const AsyncEvent *request)
    {
        schedule();

        auto _event_copy = new AsyncEvent(*request);
        _event_copy->task_id = current_task_id++;
        _event_copy->timestamp = swoole_microtime();
        _event_copy->pipe_fd = SwooleTG.aio_pipe_write;
        _queue.push(_event_copy);
        _cv.notify_one();
        return _event_copy;
    }

    inline size_t worker_count()
    {
        return threads.size();
    }

    inline size_t queue_count()
    {
        return _queue.count();
    }

    pid_t current_pid;

    void release_thread(thread::id tid)
    {
        auto i = threads.find(tid);
        if (i == threads.end())
        {
            swWarn("AIO thread#%zu is missing", tid);
            return;
        }
        else
        {
            thread *_thread = i->second;
            swTraceLog(SW_TRACE_AIO, "release idle thread#%zu, we have %zu now", tid, threads.size() - 1);
            if (_thread->joinable()) {
                _thread->join();
            }
            threads.erase(i);
            delete _thread;
        }
    }

private:

    void create_thread(const bool is_core_worker = false)
    {
        try
        {
            thread *_thread = new thread([this, is_core_worker]()
            {
                bool exit_flag = false;

                SwooleTG.buffer_stack = swString_new(SW_STACK_BUFFER_SIZE);
                if (SwooleTG.buffer_stack == nullptr)
                {
                    return;
                }

                swSignal_none();

                while (running)
                {
                    AsyncEvent *event = _queue.pop();
                    if (event)
                    {
                        if (sw_unlikely(event->handler == nullptr))
                        {
                            event->error = SW_ERROR_AIO_BAD_REQUEST;
                            event->ret = -1;
                        }
                        else if (sw_unlikely(event->canceled))
                        {
                            event->error = SW_ERROR_AIO_CANCELED;
                            event->ret = -1;
                        }
                        else
                        {
                            event->handler(event);
                        }

                        // swTraceLog(SW_TRACE_AIO, "aio_thread %s. ret=%d, error=%d", event->ret > 0 ? "ok" : "failed", event->ret, event->error);

                        _send_event:
                        while (true)
                        {
                            int ret = write(event->pipe_fd, &event, sizeof(event));
                            if (ret < 0)
                            {
                                if (errno == EAGAIN)
                                {
                                    swSocket_wait(SwooleTG.aio_pipe_write, 1000, SW_EVENT_WRITE);
                                    continue;
                                }
                                else if (errno == EINTR)
                                {
                                    continue;
                                }
                                else
                                {
                                    swSysWarn("sendto swoole_aio_pipe_write failed");
                                }
                            }
                            break;
                        }

                        // exit
                        if (exit_flag)
                        {
                            n_closing--;
                            break;
                        }
                    }
                    else if (running)
                    {
                        unique_lock<mutex> lock(event_mutex);
                        ++n_waiting;
                        if (is_core_worker || max_idle_time <= 0)
                        {
                            _cv.wait(lock);
                        }
                        else
                        {
                            while (true)
                            {
                                if (_cv.wait_for(lock, chrono::microseconds((size_t) (max_idle_time * 1000 * 1000))) == cv_status::timeout)
                                {
                                    if (running && n_closing != 0)
                                    {
                                        // wait for the next round
                                        continue;
                                    }
                                    /* notifies the main thread to release this thread */
                                    event = new AsyncEvent;
                                    event->object = new thread::id(this_thread::get_id());
                                    event->callback = aio_thread_release;

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
        }
        catch (const std::system_error& e)
        {
            swSysNotice("create aio thread failed, please check your system configuration or adjust aio_worker_num");
            return;
        }
    }

    size_t core_worker_num;
    size_t worker_num;
    double max_wait_time;
    double max_idle_time;

    bool running;

    atomic<size_t> n_waiting;
    atomic<size_t> n_closing;
    size_t current_task_id = 0;

    unordered_map<thread::id, thread *> threads;
    EventQueue _queue;
    mutex schedule_mutex;
    mutex event_mutex;
    condition_variable _cv;
};
//-------------------------------------------------------------------------------
}};

static swoole::async::ThreadPool *pool = nullptr;

static void aio_thread_release(swAio_event *event)
{
    thread::id *tid = static_cast<thread::id *>(event->object);
    pool->release_thread(*tid);
    delete tid;
    // balance
    SwooleTG.aio_task_num++;
}

static void swAio_free(void *private_data)
{
    if (!SwooleTG.aio_init)
    {
        return;
    }
    SwooleTG.aio_init = 0;
    swoole_event_del(SwooleTG.aio_pipe_read);
    SwooleTG.aio_pipe.close(&SwooleTG.aio_pipe);
    if (pool->current_pid == getpid())
    {
        if ((--refcount) == 0)
        {
            delete pool;
            pool = nullptr;
        }
    }
}

static int swAio_init()
{
    if (SwooleTG.aio_init)
    {
        swWarn("aio_thread_pool has already been initialized");
        return SW_ERR;
    }
    if (!SwooleTG.reactor)
    {
        swWarn("no event loop, cannot initialized");
        return SW_ERR;
    }

    if (swPipeBase_create(&SwooleTG.aio_pipe, 0) < 0)
    {
        swoole_throw_error(SW_ERROR_SYSTEM_CALL_FAIL);
    }

    SwooleTG.aio_pipe_read = SwooleTG.aio_pipe.getFd(&SwooleTG.aio_pipe, 0);
    SwooleTG.aio_pipe_write = SwooleTG.aio_pipe.getFd(&SwooleTG.aio_pipe, 1);
    swoole_event_add(SwooleTG.aio_pipe_read, SW_EVENT_READ, SW_FD_AIO);
    swReactor_add_destroy_callback(SwooleTG.reactor, swAio_free, nullptr);

    call_once(init_flag, []() {
        pool = new swoole::async::ThreadPool(SwooleG.aio_core_worker_num, SwooleG.aio_worker_num, SwooleG.aio_max_wait_time,
                SwooleG.aio_max_idle_time);
        pool->start();
    });

    refcount++;
    SwooleTG.aio_init = 1;

    return SW_OK;
}

size_t swAio_thread_count()
{
    return pool ? pool->worker_count() : 0;
}

ssize_t swAio_dispatch(const swAio_event *request)
{
    AsyncEvent *event = swAio_dispatch2(request);
    if (event == nullptr)
    {
        return -1;
    }
    return event->task_id;
}

swAio_event* swAio_dispatch2(const swAio_event *request)
{
    if (sw_unlikely(!SwooleTG.aio_init))
    {
        swAio_init();
    }
    AsyncEvent *event = pool->dispatch(request);
    if (sw_likely(event))
    {
        SwooleTG.aio_task_num++;
    }
    return event;
}

int swAio_callback(swReactor *reactor, swEvent *event)
{
    pool->schedule();

    AsyncEvent *events[SW_AIO_EVENT_NUM];
    ssize_t n = read(event->fd, events, sizeof(AsyncEvent *) * SW_AIO_EVENT_NUM);
    if (n < 0)
    {
        swSysWarn("read() aio events failed");
        return SW_ERR;
    }
    for (size_t i = 0; i < n / sizeof(AsyncEvent *); i++)
    {
        AsyncEvent *event = events[i];
        if (!event->canceled)
        {
            event->callback(events[i]);
        }
        SwooleTG.aio_task_num--;
        delete event;
    }

    return SW_OK;
}
