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

#include "coroutine.h"
#include "coroutine_system.h"
#include "lru_cache.h"

using namespace std;
using namespace swoole;
using swoole::coroutine::System;

struct AsyncTask
{
    Coroutine *co;
    swAio_event *original_event;
};

static size_t dns_cache_capacity = 1000;
static time_t dns_cache_expire = 60;
static LRUCache *dns_cache = nullptr;

void System::set_dns_cache_expire(time_t expire)
{
    dns_cache_expire = expire;
}

void System::set_dns_cache_capacity(size_t capacity)
{
    dns_cache_capacity = capacity;
    delete dns_cache;
    dns_cache = nullptr;
}

void System::clear_dns_cache()
{
    if (dns_cache)
    {
        dns_cache->clear();
    }
}

static void aio_onReadFileCompleted(swAio_event *event)
{
    AsyncTask *task = (AsyncTask *) event->object;
    task->original_event->buf = event->buf;
    task->original_event->nbytes = event->ret;
    task->original_event->error = event->error;
    ((Coroutine *) task->co)->resume();
}

static void aio_onWriteFileCompleted(swAio_event *event)
{
    AsyncTask *task = (AsyncTask *) event->object;
    task->original_event->ret = event->ret;
    task->original_event->error = event->error;
    ((Coroutine *) task->co)->resume();
}

static void aio_onDNSCompleted(swAio_event *event)
{
    if (event->canceled)
    {
        return;
    }
    AsyncTask *task = (AsyncTask *) event->object;
    task->original_event->ret = event->ret;
    task->original_event->error = event->error;
    ((Coroutine *) task->co)->resume();
}

static void aio_onDNSTimeout(swTimer *timer, swTimer_node *tnode)
{
    swAio_event *event = (swAio_event *) tnode->data;
    event->canceled = 1;
    AsyncTask *task = (AsyncTask *) event->object;
    task->original_event->ret = -1;
    task->original_event->error = SW_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT;
    ((Coroutine *) task->co)->resume();
}

static void sleep_timeout(swTimer *timer, swTimer_node *tnode)
{
    ((Coroutine *) tnode->data)->resume();
}

int System::sleep(double sec)
{
    Coroutine* co = Coroutine::get_current_safe();
    if (swoole_timer_add((long) (sec * 1000), SW_FALSE, sleep_timeout, co) == NULL)
    {
        return -1;
    }
    co->yield();
    return 0;
}

swString* System::read_file(const char *file, bool lock)
{
    AsyncTask task;

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    task.co = Coroutine::get_current_safe();
    task.original_event = &ev;

    ev.lock = lock ? 1 : 0;
    ev.object = (void*) &task;
    ev.handler = swAio_handler_read_file;
    ev.callback = aio_onReadFileCompleted;
    ev.req = (void*) file;

    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return NULL;
    }
    task.co->yield();
    if (ev.error == 0)
    {
        swString *str = (swString *) sw_malloc(sizeof(swString));
        if (!str)
        {
            return NULL;
        }
        str->str = (char*) ev.buf;
        str->length = ev.nbytes;
        return str;
    }
    else
    {
        swoole_set_last_error(ev.error);
        return NULL;
    }
}

ssize_t System::write_file(const char *file, char *buf, size_t length, bool lock, int flags)
{
    AsyncTask task;

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    task.co = Coroutine::get_current_safe();
    task.original_event = &ev;

    ev.lock = lock ? 1 : 0;
    ev.buf = buf;
    ev.nbytes = length;
    ev.object = (void*) &task;
    ev.handler = swAio_handler_write_file;
    ev.callback = aio_onWriteFileCompleted;
    ev.req = (void*) file;
    ev.flags = flags;

    ssize_t ret = swAio_dispatch(&ev);
    if (ret < 0)
    {
        return -1;
    }
    task.co->yield();
    if (ev.error != 0)
    {
        swoole_set_last_error(ev.error);
    }
    return ev.ret;
}

string System::gethostbyname(const string &hostname, int domain, double timeout)
{
    if (dns_cache == nullptr && dns_cache_capacity != 0)
    {
        dns_cache = new LRUCache(dns_cache_capacity);
    }

    string cache_key;
    if (dns_cache)
    {
        cache_key.append(domain == AF_INET ? "4_" : "6_");
        cache_key.append(hostname);
        auto cache = dns_cache->get(cache_key);

        if (cache)
        {
            return *(string *)cache.get();
        }
    }

    swAio_event ev;
    AsyncTask task;

    bzero(&ev, sizeof(swAio_event));
    if (hostname.size() < SW_IP_MAX_LENGTH)
    {
        ev.nbytes = SW_IP_MAX_LENGTH + 1;
    }
    else
    {
        ev.nbytes = hostname.size() + 1;
    }

    task.co = Coroutine::get_current_safe();
    task.original_event = &ev;

    ev.buf = sw_malloc(ev.nbytes);
    if (!ev.buf)
    {
        return "";
    }

    memcpy(ev.buf, hostname.c_str(), hostname.size());
    ((char *) ev.buf)[hostname.size()] = 0;
    ev.flags = domain;
    ev.object = (void*) &task;
    ev.handler = swAio_handler_gethostbyname;
    ev.callback = aio_onDNSCompleted;
    /* TODO: find a better way */
    ev.ret = 1;

    swAio_event *event = swAio_dispatch2(&ev);
    swTimer_node *timer = nullptr;
    if (timeout > 0)
    {
        timer = swoole_timer_add((long) (timeout * 1000), SW_FALSE, aio_onDNSTimeout, event);
    }
    task.co->yield();
    if (ev.ret == 1)
    {
        /* TODO: find a better way */
        /* canceled */
        event->canceled = 1;
        ev.ret = -1;
        ev.error = SW_ERROR_DNSLOOKUP_RESOLVE_FAILED;
    }
    if (timer)
    {
        swoole_timer_del(timer);
    }

    if (ev.ret == -1)
    {
        swoole_set_last_error(ev.error);
        return "";
    }
    else
    {
        if (dns_cache)
        {
            string *addr = new string((char *) ev.buf);
            dns_cache->set(cache_key, shared_ptr<string>(addr), dns_cache_expire);
            sw_free(ev.buf);
            return *addr;
        }

        string addr((char *) ev.buf);
        sw_free(ev.buf);
        return addr;
    }
}

vector<string> System::getaddrinfo(const string &hostname, int family, int socktype, int protocol,
        const string &service, double timeout)
{
    assert(!hostname.empty());
    assert(family == AF_INET || family == AF_INET6);

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    swRequest_getaddrinfo req;
    bzero(&req, sizeof(swRequest_getaddrinfo));

    AsyncTask task;

    task.co = Coroutine::get_current_safe();
    task.original_event = &ev;

    ev.object = &task;
    ev.handler = swAio_handler_getaddrinfo;
    ev.callback = aio_onDNSCompleted;
    ev.req = &req;

    struct sockaddr_in6 result_buffer[SW_DNS_HOST_BUFFER_SIZE];

    req.hostname = hostname.c_str();
    req.family = family;
    req.socktype = socktype;
    req.protocol = protocol;
    req.service = service.empty() ? nullptr : service.c_str();
    req.result = result_buffer;

    swAio_event *event = swAio_dispatch2(&ev);
    swTimer_node *timer = nullptr;
    if (timeout > 0)
    {
        timer = swoole_timer_add((long) (timeout * 1000), SW_FALSE, aio_onDNSTimeout, event);
    }
    task.co->yield();
    if (timer)
    {
        swoole_timer_del(timer);
    }

    vector<string> retval;

    if (ev.ret == -1)
    {
        swoole_set_last_error(ev.error);
    }

    struct sockaddr_in *addr_v4;
    struct sockaddr_in6 *addr_v6;

    if (req.error == 0)
    {
        int i;
        char tmp[INET6_ADDRSTRLEN];
        const char *r;

        for (i = 0; i < req.count; i++)
        {
            if (req.family == AF_INET)
            {
                addr_v4 = (struct sockaddr_in *) ((char*) req.result + (i * sizeof(struct sockaddr_in)));
                r = inet_ntop(AF_INET, (const void*) &addr_v4->sin_addr, tmp, sizeof(tmp));
            }
            else
            {
                addr_v6 = (struct sockaddr_in6 *) ((char*) req.result + (i * sizeof(struct sockaddr_in6)));
                r = inet_ntop(AF_INET6, (const void*) &addr_v6->sin6_addr, tmp, sizeof(tmp));
            }
            if (r)
            {
                retval.push_back(tmp);
            }
        }
    }
    else
    {
        swoole_set_last_error(ev.error);
    }

    return retval;
}

struct coro_poll_task
{
    std::unordered_map<int, socket_poll_fd> *fds;
    Coroutine *co = nullptr;
    swTimer_node *timer = nullptr;
    bool success = false;
    bool wait = true;
};

static inline void socket_poll_clean(coro_poll_task *task)
{
    for (auto i = task->fds->begin(); i != task->fds->end(); i++)
    {
        swSocket *socket = i->second.socket;
        if (!socket)
        {
            continue;
        }
        int retval = swoole_event_del(i->second.socket);
        /**
         * Temporary socket, fd marked -1, skip close
         */
        socket->fd = -1;
        swSocket_free(socket);
        i->second.socket = nullptr;
        if (retval < 0)
        {
            continue;
        }
    }
}

static void socket_poll_timeout(swTimer *timer, swTimer_node *tnode)
{
    coro_poll_task *task = (coro_poll_task *) tnode->data;
    task->timer = nullptr;
    task->success = false;
    task->wait = false;
    socket_poll_clean(task);
    task->co->resume();
}

static void socket_poll_completed(void *data)
{
    coro_poll_task *task = (coro_poll_task *) data;
    socket_poll_clean(task);
    task->co->resume();
}

static inline void socket_poll_trigger_event(swReactor *reactor, coro_poll_task *task, int fd, enum swEvent_type event)
{
    auto i = task->fds->find(fd);
    if (event == SW_EVENT_ERROR && !(i->second.events & SW_EVENT_ERROR))
    {
        if (i->second.events & SW_EVENT_READ)
        {
            i->second.revents |= SW_EVENT_READ;
        }
        if (i->second.events & SW_EVENT_WRITE)
        {
            i->second.revents |= SW_EVENT_WRITE;
        }
    }
    else
    {
        i->second.revents |= event;
    }
    if (task->wait)
    {
        task->wait = false;
        task->success = true;
        if (task->timer)
        {
            swoole_timer_del(task->timer);
            task->timer = nullptr;
        }
        reactor->defer(reactor, socket_poll_completed, task);
    }
}

static int socket_poll_read_callback(swReactor *reactor, swEvent *event)
{
    socket_poll_trigger_event(reactor, (coro_poll_task *) event->socket->object, event->fd, SW_EVENT_READ);
    return SW_OK;
}

static int socket_poll_write_callback(swReactor *reactor, swEvent *event)
{
    socket_poll_trigger_event(reactor, (coro_poll_task *) event->socket->object, event->fd, SW_EVENT_WRITE);
    return SW_OK;
}

static int socket_poll_error_callback(swReactor *reactor, swEvent *event)
{
    socket_poll_trigger_event(reactor, (coro_poll_task *) event->socket->object, event->fd, SW_EVENT_ERROR);
    return SW_OK;
}

static int translate_events_to_poll(int events)
{
    int poll_events = 0;

    if (events & SW_EVENT_READ)
    {
        poll_events |= POLLIN;
    }
    if (events & SW_EVENT_WRITE)
    {
        poll_events |= POLLOUT;
    }

    return poll_events;
}

static int translate_events_from_poll(int events)
{
    int sw_events = 0;

    if (events & POLLIN)
    {
        sw_events |= SW_EVENT_READ;
    }
    if (events & POLLOUT)
    {
        sw_events |= SW_EVENT_WRITE;
    }
    //ignore ERR and HUP, because event is already processed at IN and OUT handler.
    if ((((events & POLLERR) || (events & POLLHUP)) && !((events & POLLIN) || (events & POLLOUT))))
    {
        sw_events |= SW_EVENT_ERROR;
    }

    return sw_events;
}

bool System::socket_poll(std::unordered_map<int, socket_poll_fd> &fds, double timeout)
{
    if (timeout == 0)
    {
        struct pollfd *event_list = (struct pollfd *) sw_calloc(fds.size(), sizeof(struct pollfd));
        if (!event_list)
        {
            swWarn("calloc() failed");
            return false;
        }
        int n = 0;
        for (auto i = fds.begin(); i != fds.end(); i++, n++)
        {
            event_list[n].fd = i->first;
            event_list[n].events = translate_events_to_poll(i->second.events);
            event_list[n].revents = 0;
        }
        int retval = ::poll(event_list, n, 0);
        if (retval > 0)
        {
            int n = 0;
            for (auto i = fds.begin(); i != fds.end(); i++, n++)
            {
                i->second.revents = translate_events_from_poll(event_list[n].revents);
            }
        }
        sw_free(event_list);
        return retval > 0;
    }

    size_t tasked_num = 0;
    coro_poll_task task;
    task.fds = &fds;
    task.co = Coroutine::get_current_safe();

    for (auto i = fds.begin(); i != fds.end(); i++)
    {
        i->second.socket = swSocket_new(i->first, SW_FD_CORO_POLL);
        if (i->second.socket == nullptr)
        {
            continue;
        }
        if (swoole_event_add(i->second.socket, i->second.events) < 0)
        {
            continue;
        }
        i->second.socket->object = &task;
        tasked_num++;
    }

    if (sw_unlikely(tasked_num == 0))
    {
        return false;
    }

    if (timeout > 0)
    {
        task.timer = swoole_timer_add((long) (timeout * 1000), SW_FALSE, socket_poll_timeout, &task);
    }

    task.co->yield();

    return task.success;
}

struct event_waiter
{
    swSocket *socket;
    swTimer_node *timer;
    Coroutine *co;
    int revents;

    event_waiter(int fd, int events, double timeout)
    {
        revents = 0;
        if (!(socket = swSocket_new(fd, SW_FD_CORO_EVENT)))
        {
            swoole_set_last_error(errno);
            return;
        }
        socket->object = this;
        if (swoole_event_add(socket, events) < 0)
        {
            swoole_set_last_error(errno);
            goto _done;
        }
        if (timeout > 0)
        {
            timer = swoole_timer_add((long) (timeout * 1000), SW_FALSE, [](swTimer *timer, swTimer_node *tnode){
                event_waiter *waiter = (event_waiter *) tnode->data;
                waiter->timer = nullptr;
                waiter->co->resume();
            }, this);
        }
        else
        {
            timer = nullptr;
        }
        co = Coroutine::get_current();

        co->yield();

        if (timer != nullptr)
        {
            swoole_timer_del(timer);
        }
        else if (timeout > 0)
        {
            swoole_set_last_error(ETIMEDOUT);
        }
        swoole_event_del(socket);
        _done:
        socket->fd = -1; /* skip close */
        swSocket_free(socket);
    }

};

static inline void event_waiter_callback(swReactor *reactor, event_waiter *waiter, enum swEvent_type event)
{
    if (waiter->revents == 0) {
        reactor->defer(reactor, [](void *data) {
            event_waiter *waiter = (event_waiter *) data;
            waiter->co->resume();
        }, waiter);
    }
    waiter->revents |= event;
}

static int event_waiter_read_callback(swReactor *reactor, swEvent *event)
{
    event_waiter_callback(reactor, (event_waiter *) event->socket->object, SW_EVENT_READ);
    return SW_OK;
}

static int event_waiter_write_callback(swReactor *reactor, swEvent *event)
{
    event_waiter_callback(reactor, (event_waiter *) event->socket->object, SW_EVENT_WRITE);
    return SW_OK;
}

static int event_waiter_error_callback(swReactor *reactor, swEvent *event)
{
    event_waiter_callback(reactor, (event_waiter *) event->socket->object, SW_EVENT_ERROR);
    return SW_OK;
}

int System::wait_event(int fd, int events, double timeout)
{
    events &= SW_EVENT_READ | SW_EVENT_WRITE;
    if (events == 0)
    {
        swoole_set_last_error(EINVAL);
        return 0;
    }

    if (timeout == 0)
    {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = translate_events_to_poll(events);
        pfd.revents = 0;

        int retval = ::poll(&pfd, 1, 0);
        if (retval == 1)
        {
            return translate_events_from_poll(pfd.revents);
        }
        if (retval < 0)
        {
            swoole_set_last_error(errno);
        }
        return 0;
    }

    int revents = event_waiter(fd, events, timeout).revents;

    if (revents & SW_EVENT_ERROR)
    {
        revents ^= SW_EVENT_ERROR;
        if (events & SW_EVENT_READ)
        {
            revents |= SW_EVENT_READ;
        }
        if (events & SW_EVENT_WRITE)
        {
            revents |= SW_EVENT_WRITE;
        }
    }

    return revents;
}

void System::init_reactor(swReactor *reactor)
{
    swReactor_set_handler(reactor, SW_FD_CORO_POLL | SW_EVENT_READ, socket_poll_read_callback);
    swReactor_set_handler(reactor, SW_FD_CORO_POLL | SW_EVENT_WRITE, socket_poll_write_callback);
    swReactor_set_handler(reactor, SW_FD_CORO_POLL | SW_EVENT_ERROR, socket_poll_error_callback);

    swReactor_set_handler(reactor, SW_FD_CORO_EVENT | SW_EVENT_READ, event_waiter_read_callback);
    swReactor_set_handler(reactor, SW_FD_CORO_EVENT | SW_EVENT_WRITE, event_waiter_write_callback);
    swReactor_set_handler(reactor, SW_FD_CORO_EVENT | SW_EVENT_ERROR, event_waiter_error_callback);

    swReactor_set_handler(reactor, SW_FD_AIO | SW_EVENT_READ, swAio_callback);
}

static void async_task_completed(swAio_event *event)
{
    if (event->canceled)
    {
        return;
    }
    AsyncTask *task = (AsyncTask *) event->object;
    task->original_event->error = event->error;
    task->original_event->ret = event->ret;
    task->co->resume();
}

static void async_task_timeout(swTimer *timer, swTimer_node *tnode)
{
    swAio_event *event = (swAio_event *) tnode->data;
    event->canceled = 1;
    AsyncTask *task = (AsyncTask *) event->object;
    task->original_event->error = SW_ERROR_AIO_TIMEOUT;
    task->co->resume();
}

bool coroutine::async(swAio_handler handler, swAio_event &event, double timeout)
{
    AsyncTask task;
    swTimer_node *timer = nullptr;

    task.co = Coroutine::get_current_safe();
    task.original_event = &event;

    event.object = (void*) &task;
    event.handler = handler;
    event.callback = async_task_completed;

    swAio_event *_ev = swAio_dispatch2(&event);
    if (_ev == nullptr)
    {
        return false;
    }
    if (timeout > 0)
    {
        timer = swoole_timer_add((long) (timeout * 1000), SW_FALSE, async_task_timeout, _ev);
    }
    task.co->yield();
    if (event.error == SW_ERROR_AIO_TIMEOUT)
    {
        return false;
    }
    else
    {
        if (timer)
        {
            swoole_timer_del(timer);
        }
        return true;
    }
}

struct AsyncLambdaTask
{
    Coroutine *co;
    std::function<void(void)> fn;
};

static void async_lambda_handler(swAio_event *event)
{
    AsyncLambdaTask *task = reinterpret_cast<AsyncLambdaTask *>(event->object);
    task->fn();
    event->error = 0;
    event->ret = 0;
}

static void async_lambda_callback(swAio_event *event)
{
    if (event->canceled)
    {
        return;
    }
    AsyncLambdaTask *task = reinterpret_cast<AsyncLambdaTask *>(event->object);
    task->co->resume();
}

bool coroutine::async(const std::function<void(void)> &fn, double timeout)
{
    swTimer_node *timer = nullptr;
    swAio_event event = {};

    AsyncLambdaTask task;
    task.co = Coroutine::get_current_safe();
    task.fn = fn;

    event.object = &task;
    event.handler = async_lambda_handler;
    event.callback = async_lambda_callback;

    swAio_event *_ev = swAio_dispatch2(&event);
    if (_ev == nullptr)
    {
        return false;
    }
    if (timeout > 0)
    {
        timer = swoole_timer_add((long) (timeout * 1000), SW_FALSE, async_task_timeout, _ev);
    }
    task.co->yield();
    if (event.error == SW_ERROR_AIO_TIMEOUT)
    {
        return false;
    }
    else
    {
        if (timer)
        {
            swoole_timer_del(timer);
        }
        return true;
    }
}
