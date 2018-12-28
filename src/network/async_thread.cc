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

class async_event_queue
{
public:
    bool push(async_event *event)
    {
        unique_lock<mutex> lock(_mutex);
        _queue.push(event);
        return true;
    }
    async_event* pop()
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
    bool empty()
    {
        unique_lock<mutex> lock(_mutex);
        return _queue.empty();
    }
private:
    queue<async_event*> _queue;
    mutex _mutex;
};

class async_thread_pool
{
public:
    static int event_callback(swReactor *reactor, swEvent *_event)
    {
        int i;
        async_event *events[SW_AIO_EVENT_NUM];
        ssize_t n = read(_event->fd, events, sizeof(async_event*) * SW_AIO_EVENT_NUM);
        if (n < 0)
        {
            swWarn("read() failed. Error: %s[%d]", strerror(errno), errno);
            return SW_ERR;
        }
        for (i = 0; i < n / (int) sizeof(async_event*); i++)
        {
            events[i]->callback(events[i]);
            SwooleAIO.task_num--;
            sw_free(events[i]);
        }
        return SW_OK;
    }

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

        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_AIO, event_callback);
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

    bool dispatch(async_event *ev)
    {
        async_event *_event = new async_event;
        *_event = *ev;

        schedule();
        _event->task_id = current_task_id++;
        queue.push(_event);
        _cv.notify_one();
        return true;
    }

private:
    void create_thread(int i)
    {
        exit_flags[i] = make_shared<atomic<bool>>(false);
        shared_ptr<atomic<bool>> flag(exit_flags[i]);

        thread *_thread = new thread([this, flag]()
        {
            atomic<bool> &_flag = *flag;
            async_event *event;
            _accept: event = queue.pop();
            if (event)
            {
                if (event->handler == NULL)
                {
                    event->error = SW_ERROR_AIO_BAD_REQUEST;
                    event->ret = -1;
                    goto _error;
                }
                event->handler(event);

                swTrace("aio_thread ok. ret=%d, error=%d", async_event->ret, async_event->error);

                _error: while (1)
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
                            swSysError("sendto swoole_aio_pipe_write failed.");
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
                ++n_waiting;
                _cv.wait(lock);
                --n_waiting;
            }
            if (running )
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

static int swAio_init(void)
{
    if (SwooleAIO.init)
    {
        swWarn("AIO has already been initialized");
        return SW_ERR;
    }
    if (!SwooleG.main_reactor)
    {
        swWarn("No eventloop, cannot initialized");
        return SW_ERR;
    }

    if (swMutex_create(&SwooleAIO.lock, 0) < 0)
    {
        swWarn("create mutex lock error.");
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

    pool = new async_thread_pool(SwooleAIO.min_thread_count, SwooleAIO.min_thread_count);
    pool->start();

    SwooleAIO.init = 1;

    return SW_OK;
}

int swAio_dispatch(swAio_event *_event)
{
    if (unlikely(SwooleAIO.init == 0))
    {
        swAio_init();
    }
    if (!pool->dispatch(_event))
    {
        return SW_ERR;
    }
    else
    {
        SwooleAIO.task_num++;
        return _event->task_id;
    }
}

void swAio_free(void)
{
    if (!SwooleAIO.init)
    {
        return;
    }
    delete pool;
    pool = nullptr;
    SwooleAIO.init = 0;
}
