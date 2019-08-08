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

#include "swoole.h"
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
static int swAio_callback(swReactor *reactor, swEvent *_event)
{
    int i;
    async_event *events[SW_AIO_EVENT_NUM];
    ssize_t n = read(_event->fd, events, sizeof(async_event*) * SW_AIO_EVENT_NUM);
    if (n < 0)
    {
        swSysWarn("read() failed");
        return SW_ERR;
    }
    for (i = 0; i < n / (int) sizeof(async_event*); i++)
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
    async_thread_pool(int _min_threads, int _max_threads)
    {
        n_waiting = 0;
        running = false;
        min_threads = _min_threads;
        max_threads = _max_threads;
        current_task_id = 0;

        if (swPipeBase_create(&_aio_pipe, 0) < 0)
        {
            swoole_throw_error(SW_ERROR_SYSTEM_CALL_FAIL);
        }
        _pipe_read = _aio_pipe.getFd(&_aio_pipe, 0);
        _pipe_write = _aio_pipe.getFd(&_aio_pipe, 1);

        swReactor_set_handler(SwooleG.main_reactor, SW_FD_AIO, swAio_callback);
        SwooleG.main_reactor->add(SwooleG.main_reactor, _pipe_read, SW_FD_AIO);
    }

    ~async_thread_pool()
    {
        shutdown();
        if (SwooleG.main_reactor)
        {
            SwooleG.main_reactor->del(SwooleG.main_reactor, _pipe_read);
        }
        _aio_pipe.close(&_aio_pipe);
    }

    void schedule()
    {
        //++
        if (n_waiting == 0 && (int) threads.size() < max_threads)
        {
            int i = threads.size();
            exit_flags[i] = make_shared<atomic<bool>>(false);
            create_thread(i);
        }
        //--
        else if (n_waiting > min_threads)
        {
            int i = threads.size() - 1;
            *exit_flags[i] = true;
            threads[i]->detach();
            threads.erase(i);
            exit_flags.erase(i);
        }
    }

    bool start()
    {
        running = true;
        for (int i = 0; i < min_threads; i++)
        {
            create_thread(i);
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

        for (int i = 0; i < static_cast<int>(threads.size()); ++i)
        {
            if (threads[i]->joinable())
            {
                threads[i]->join();
            }
        }

        threads.clear();
        exit_flags.clear();
        return true;
    }

    async_event* dispatch(const async_event *request)
    {
        auto _event_copy = new async_event(*request);
        schedule();
        _event_copy->task_id = current_task_id++;
        queue.push(_event_copy);
        _cv.notify_one();
        return _event_copy;
    }

    inline size_t thread_count()
    {
        return threads.size();
    }

    inline size_t queue_count()
    {
        return queue.count();
    }

private:
    void create_thread(int i)
    {
        exit_flags[i] = make_shared<atomic<bool>>(false);
        shared_ptr<atomic<bool>> flag(exit_flags[i]);

        thread *_thread = new thread([this, flag]()
        {
            SwooleTG.buffer_stack = swString_new(SW_STACK_BUFFER_SIZE);
            if (SwooleTG.buffer_stack == nullptr)
            {
                return;
            }

            swSignal_none();

            atomic<bool> &_flag = *flag;
            async_event *event;
            _accept:
            event = queue.pop();
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
                //exit
                if (_flag)
                {
                    return;
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
            if (running)
            {
                goto _accept;
            }
        });
        threads[i] = unique_ptr<thread>(_thread);
    }

    swPipe _aio_pipe;
    int _pipe_read;
    int _pipe_write;
    int current_task_id;

    unordered_map<int, unique_ptr<thread>> threads;
    unordered_map<int, shared_ptr<atomic<bool>>> exit_flags;

    async_event_queue queue;
    bool running;
    atomic<int> n_waiting;
    int min_threads;
    int max_threads;
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
    if (!SwooleG.main_reactor)
    {
        swWarn("no event loop, cannot initialized");
        return SW_ERR;
    }

    if (swMutex_create(&SwooleAIO.lock, 0) < 0)
    {
        swWarn("create mutex lock error");
        return SW_ERR;
    }

    if (SwooleAIO.min_thread_count == 0)
    {
        SwooleAIO.min_thread_count = SW_AIO_THREAD_MIN_NUM;
    }
    if (SwooleAIO.max_thread_count == 0)
    {
        SwooleAIO.max_thread_count = SW_AIO_THREAD_MAX_NUM;
    }
    if (SwooleAIO.min_thread_count > SwooleAIO.max_thread_count)
    {
        SwooleAIO.max_thread_count = SwooleAIO.min_thread_count;
    }

    swReactor_add_destroy_callback(SwooleG.main_reactor, swAio_free, nullptr);

    pool = new async_thread_pool(SwooleAIO.min_thread_count, SwooleAIO.max_thread_count);
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
    delete pool;
    pool = nullptr;
    SwooleAIO.init = 0;
}
