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

struct aio_task
{
    Coroutine *co;
    swAio_event *event;
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
    aio_task *task = (aio_task *) event->object;
    task->event->buf = event->buf;
    task->event->nbytes = event->ret;
    task->event->error = event->error;
    ((Coroutine *) task->co)->resume();
}

static void aio_onWriteFileCompleted(swAio_event *event)
{
    aio_task *task = (aio_task *) event->object;
    task->event->ret = event->ret;
    task->event->error = event->error;
    ((Coroutine *) task->co)->resume();
}

static void aio_onDNSCompleted(swAio_event *event)
{
    if (event->canceled)
    {
        return;
    }
    aio_task *task = (aio_task *) event->object;
    task->event->ret = event->ret;
    task->event->error = event->error;
    ((Coroutine *) task->co)->resume();
}

static void aio_onDNSTimeout(swTimer *timer, swTimer_node *tnode)
{
    swAio_event *event = (swAio_event *) tnode->data;
    event->canceled = 1;
    aio_task *task = (aio_task *) event->object;
    task->event->ret = -1;
    task->event->error = SW_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT;
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

swString* System::read_file(const char *file, int lock)
{
    aio_task task;

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    task.co = Coroutine::get_current_safe();
    task.event = &ev;

    ev.lock = lock ? 1 : 0;
    ev.type = SW_AIO_READ_FILE;
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
        SwooleG.error = ev.error;
        return NULL;
    }
}

ssize_t System::write_file(const char *file, char *buf, size_t length, int lock, int flags)
{
    aio_task task;

    swAio_event ev;
    bzero(&ev, sizeof(swAio_event));

    task.co = Coroutine::get_current_safe();
    task.event = &ev;

    ev.lock = lock ? 1 : 0;
    ev.type = SW_AIO_WRITE_FILE;
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
        SwooleG.error = ev.error;
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
    aio_task task;

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
    task.event = &ev;

    ev.buf = sw_malloc(ev.nbytes);
    if (!ev.buf)
    {
        return "";
    }

    memcpy(ev.buf, hostname.c_str(), hostname.size());
    ((char *) ev.buf)[hostname.size()] = 0;
    ev.flags = domain;
    ev.type = SW_AIO_GETHOSTBYNAME;
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
        SwooleG.error = ev.error;
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

    aio_task task;

    task.co = Coroutine::get_current_safe();
    task.event = &ev;

    ev.type = SW_AIO_GETADDRINFO;
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
        SwooleG.error = ev.error;
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
        SwooleG.error = ev.error;
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

static std::unordered_map<int, coro_poll_task *> coro_poll_task_map;

static inline void socket_poll_clean(coro_poll_task *task)
{
    for (auto i = task->fds->begin(); i != task->fds->end(); i++)
    {
        coro_poll_task_map.erase(i->first);
        if (swoole_event_del(i->first) < 0)
        {
            //TODO print error log
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

static inline void socket_poll_trigger_event(swReactor *reactor, int fd, enum swEvent_type event)
{
    coro_poll_task *task = coro_poll_task_map[fd];
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
    socket_poll_trigger_event(reactor, event->fd, SW_EVENT_READ);
    return SW_OK;
}

static int socket_poll_write_callback(swReactor *reactor, swEvent *event)
{
    socket_poll_trigger_event(reactor, event->fd, SW_EVENT_WRITE);
    return SW_OK;
}

static int socket_poll_error_callback(swReactor *reactor, swEvent *event)
{
    socket_poll_trigger_event(reactor, event->fd, SW_EVENT_ERROR);
    return SW_OK;
}

void System::init_reactor(swReactor *reactor)
{
    swReactor_set_handler(reactor, SW_FD_CORO_POLL | SW_EVENT_READ, socket_poll_read_callback);
    swReactor_set_handler(reactor, SW_FD_CORO_POLL | SW_EVENT_WRITE, socket_poll_write_callback);
    swReactor_set_handler(reactor, SW_FD_CORO_POLL | SW_EVENT_ERROR, socket_poll_error_callback);
    swReactor_set_handler(reactor, SW_FD_AIO | SW_EVENT_READ, swAio_callback);
}

bool System::socket_poll(std::unordered_map<int, socket_poll_fd> &fds, double timeout)
{
    if (timeout == 0)
    {
        struct pollfd *event_list = (struct pollfd *) sw_calloc(fds.size(), sizeof(struct pollfd));
        if (!event_list)
        {
            swWarn("malloc[1] failed");
            return false;
        }
        int j = 0;
        for (auto i = fds.begin(); i != fds.end(); i++)
        {
            event_list[j].fd = i->first;
            event_list[j].events = i->second.events;
            event_list[j].revents = 0;
            j++;
        }
        int retval = ::poll(event_list, fds.size(), 0);
        if (retval > 0)
        {
            for (size_t i = 0; i < fds.size(); i++)
            {
                auto _e = fds.find(event_list[i].fd);
                int16_t revents = event_list[i].revents;
                int16_t sw_revents = 0;
                if (revents & POLLIN)
                {
                    sw_revents |= SW_EVENT_READ;
                }
                if (revents & POLLOUT)
                {
                    sw_revents |= SW_EVENT_WRITE;
                }
                //ignore ERR and HUP, because event is already processed at IN and OUT handler.
                if ((((revents & POLLERR) || (revents & POLLHUP)) && !((revents & POLLIN) || (revents & POLLOUT))))
                {
                    sw_revents |= SW_EVENT_ERROR;
                }
                _e->second.revents = sw_revents;
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
        if (swoole_event_add(i->first, i->second.events, SW_FD_CORO_POLL) < 0)
        {
            continue;
        }
        else
        {
            coro_poll_task_map[i->first] = &task;
            tasked_num++;
        }
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
