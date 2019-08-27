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
#include <condition_variable>
#include <mutex>
#include <queue>

using namespace std;

typedef swAio_event async_event;

swAsyncIO SwooleAIO;

static void swAio_free(void *private_data);

int swAio_callback(swReactor *reactor, swEvent *_event)
{
    async_event *events[SW_AIO_EVENT_NUM];
    ssize_t n = read(_event->fd, events, sizeof(async_event*) * SW_AIO_EVENT_NUM);
    if (n < 0)
    {
        swSysWarn("read() failed");
        return SW_ERR;
    }
    for (size_t i = 0; i < n / sizeof(async_event *); i++)
    {
        if (!events[i]->canceled)
        {
            events[i]->callback(events[i]);
        }
        SwooleAIO.task_num--;
        delete events[i];
    }
    return SW_OK;
}

struct thread_context
{
    thread *_thread;
    atomic<bool> *_exit_flag;
    thread_context(thread *_thread, atomic<bool> *_exit_flag) : _thread(_thread), _exit_flag(_exit_flag) { }
};

class async_event_queue
{
public:
    inline bool push(async_event *event)
    {
        unique_lock<mutex> lock(_mutex);
        _queue.push(event);
        return true;
    }
    inline async_event* pop()
    {
        unique_lock<mutex> lock(_mutex);
        if (_queue.empty())
        {
            return nullptr;
        }
        async_event* retval = _queue.front();
        _queue.pop();
        return retval;
    }
    inline bool empty()
    {
        unique_lock<mutex> lock(_mutex);
        return _queue.empty();
    }
    inline size_t count()
    {
        return _queue.size();
    }
private:
    queue<async_event*> _queue;
    mutex _mutex;
};

class async_thread_pool
{
public:
    async_thread_pool(size_t _min_threads, size_t _max_threads)
    {
        n_waiting = 0;
        running = false;
        min_threads = SW_MAX(SW_AIO_THREAD_DEFAULT_NUM, _min_threads);
        max_threads = SW_MAX(min_threads, _max_threads);
        current_task_id = 0;
        current_pid = getpid();

        if (swPipeBase_create(&_aio_pipe, 0) < 0)
        {
            swoole_throw_error(SW_ERROR_SYSTEM_CALL_FAIL);
        }
        _pipe_read = _aio_pipe.getFd(&_aio_pipe, 0);
        _pipe_write = _aio_pipe.getFd(&_aio_pipe, 1);
        swoole_event_add(_pipe_read, SW_EVENT_READ, SW_FD_AIO);
    }

    ~async_thread_pool()
    {
        shutdown();
        if (SwooleTG.reactor)
        {
            swoole_event_del(_pipe_read);
        }
        _aio_pipe.close(&_aio_pipe);
    }

    void schedule()
    {
        //++
        if (n_waiting == 0 && threads.size() < max_threads)
        {
            create_thread();
        }
        //--
        else if (n_waiting - n_closing > min_threads)
        {
            thread_context *tc = &threads.front();
            *tc->_exit_flag = true;
            n_closing++;
            tc->_thread->detach();
            delete tc->_thread;
            threads.pop();
        }
    }

    bool start()
    {
        running = true;
        for (size_t i = 0; i < min_threads; i++)
        {
            create_thread();
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

        _mutex.lock();
        _cv.notify_all();
        _mutex.unlock();

        while (!threads.empty())
        {
            thread_context *tc = &threads.front();
            if (tc->_thread->joinable())
            {
                tc->_thread->join();
            }
            threads.pop();
        }

        return true;
    }

    async_event* dispatch(const async_event *request)
    {
        auto _event_copy = new async_event(*request);
        schedule();
        _event_copy->task_id = current_task_id++;
        _queue.push(_event_copy);
        _cv.notify_one();
        return _event_copy;
    }

    inline size_t thread_count()
    {
        return threads.size();
    }

    inline size_t queue_count()
    {
        return _queue.count();
    }

    pid_t current_pid;

private:
    void create_thread()
    {
        atomic<bool> *_exit_flag = new atomic<bool>(false);
        try
        {
            thread *_thread = new thread([this, _exit_flag]()
            {
                SwooleTG.buffer_stack = swString_new(SW_STACK_BUFFER_SIZE);
                if (SwooleTG.buffer_stack == nullptr)
                {
                    return;
                }

                swSignal_none();

                while (running)
                {
                    async_event *event = _queue.pop();
                    if (event)
                    {
                        if (sw_unlikely(event->handler == nullptr))
                        {
                            event->error = SW_ERROR_AIO_BAD_REQUEST;
                            event->ret = -1;
                            goto _error;
                        }
                        else if (sw_unlikely(event->canceled))
                        {
                            event->error = SW_ERROR_AIO_BAD_REQUEST;
                            event->ret = -1;
                            goto _error;
                        }
                        else
                        {
                            event->handler(event);
                        }

                        swTrace("aio_thread ok. ret=%d, error=%d", event->ret, event->error);

                        _error:
                        while (true)
                        {
                            SwooleAIO.lock.lock(&SwooleAIO.lock);
                            int ret = write(_pipe_write, &event, sizeof(event));
                            SwooleAIO.lock.unlock(&SwooleAIO.lock);
                            if (ret < 0)
                            {
                                if (errno == EAGAIN)
                                {
                                    swSocket_wait(_pipe_write, 1000, SW_EVENT_WRITE);
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
                        if (*_exit_flag)
                        {
                            n_closing--;
                            break;
                        }
                    }
                    else
                    {
                        unique_lock<mutex> lock(_mutex);
                        if (running)
                        {
                            ++n_waiting;
                            _cv.wait(lock);
                            --n_waiting;
                        }
                    }
                }

                delete _exit_flag;
            });
            threads.push(thread_context(_thread, _exit_flag));
        }
        catch (const std::system_error& e)
        {
            swSysNotice("create aio thread failed, please check your system configuration or adjust max_thread_count");
            delete _exit_flag;
            return;
        }
    }

    size_t min_threads;
    size_t max_threads;

    swPipe _aio_pipe;
    int _pipe_read;
    int _pipe_write;
    int current_task_id;

    queue<thread_context> threads;
    async_event_queue _queue;
    bool running;
    atomic<size_t> n_waiting;
    atomic<size_t> n_closing;
    mutex _mutex;
    condition_variable _cv;
};

static async_thread_pool *pool = nullptr;

static int swAio_init()
{
    if (SwooleAIO.init)
    {
        swWarn("AIO has already been initialized");
        return SW_ERR;
    }
    if (!SwooleTG.reactor)
    {
        swWarn("no event loop, cannot initialized");
        return SW_ERR;
    }

    if (swMutex_create(&SwooleAIO.lock, 0) < 0)
    {
        swWarn("create mutex lock error");
        return SW_ERR;
    }

    if (SwooleAIO.min_thread_num == 0)
    {
        SwooleAIO.min_thread_num = SW_AIO_THREAD_DEFAULT_NUM;
    }
    if (SwooleAIO.max_thread_num == 0)
    {
        SwooleAIO.max_thread_num = (SW_CPU_NUM * 2) * SW_AIO_THREAD_NUM_MULTIPLE;
    }
    if (SwooleAIO.min_thread_num > SwooleAIO.max_thread_num)
    {
        SwooleAIO.max_thread_num = SwooleAIO.min_thread_num;
    }

    swReactor_add_destroy_callback(SwooleTG.reactor, swAio_free, nullptr);

    pool = new async_thread_pool(SwooleAIO.min_thread_num, SwooleAIO.max_thread_num);
    pool->start();
    SwooleAIO.init = 1;

    return SW_OK;
}

size_t swAio_thread_count()
{
    return pool ? pool->thread_count() : 0;
}

int swAio_dispatch(const swAio_event *request)
{
    if (sw_unlikely(!SwooleAIO.init))
    {
        swAio_init();
    }
    SwooleAIO.task_num++;
    async_event *event = pool->dispatch(request);
    return event->task_id;
}

swAio_event* swAio_dispatch2(const swAio_event *request)
{
    if (sw_unlikely(!SwooleAIO.init))
    {
        swAio_init();
    }
    SwooleAIO.task_num++;
    return pool->dispatch(request);
}

static void swAio_free(void *private_data)
{
    if (!SwooleAIO.init)
    {
        return;
    }
    if (pool->current_pid == getpid())
    {
        delete pool;
    }
    pool = nullptr;
    SwooleAIO.init = 0;
}
