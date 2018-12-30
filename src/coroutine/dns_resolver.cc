#include "dns_resolver.h"

using namespace swoole;
using namespace std;

double DNSResolver::resolve_timeout = 5;

#ifdef SW_USE_CARES
struct _ares_dns_task
{
    ares_channel channel;
    ares_options options;
    bool finish;
    string result;
    Coroutine *co;

    _ares_dns_task()
    {
        finish = false;
        co = nullptr;
        options.flags = ARES_FLAG_STAYOPEN; // don't close socket in end_query.

        if (ares_init_options(&channel, &options, ARES_OPT_FLAGS) != ARES_SUCCESS)
        {
            finish = true;
        }
    }

    ~_ares_dns_task()
    {
        ares_destroy(channel);
    }
};
typedef _ares_dns_task ares_dns_task;

static void ares_dns_callback(void *arg, int status, int timeouts, struct hostent* hptr)
{
    auto task = (ares_dns_task *) arg;
    if (task->finish)
    {
        return;
    }

    if (status == ARES_SUCCESS)
    {
        char *pptr = *hptr->h_addr_list;
        if (pptr)
        {
            char addr[INET6_ADDRSTRLEN];
            inet_ntop(hptr->h_addrtype, pptr, addr, INET6_ADDRSTRLEN);
            task->result.append(addr);
        }
        else
        {
            SwooleG.error = SW_ERROR_DNSLOOKUP_RESOLVE_FAILED;
        }
    }
    else
    {
        SwooleG.error = SW_ERROR_DNSLOOKUP_RESOLVE_FAILED;
    }

    task->finish = true;
}

static void ares_dns_timeout(swTimer *timer, swTimer_node *tnode)
{
    auto task = (ares_dns_task *) tnode->data;
    auto co = task->co;

    task->finish = true;
    SwooleG.error = SW_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT;
    co->resume();
}

static int ares_event_read(swReactor *reactor, swEvent *event)
{
    auto task = (ares_dns_task *) event->socket->object;
    auto co = task->co;

    ares_process_fd(task->channel, event->fd, ARES_SOCKET_BAD);
    co->resume();

    return SW_OK;
}

static int ares_event_write(swReactor *reactor, swEvent *event)
{
    auto task = (ares_dns_task *) event->socket->object;
    auto co = task->co;

    ares_process_fd(task->channel, ARES_SOCKET_BAD, event->fd);
    co->resume();

    return SW_OK;
}

static int ares_event_error(swReactor *reactor, swEvent *event)
{
    return SW_OK;
}

string DNSResolver::resolve(const std::string &hostname, int domain, double timeout)
{
    if (timeout == 0)
    {
        timeout = resolve_timeout;
    }

    auto reactor = SwooleG.main_reactor;
    if (unlikely(!reactor))
    {
        return "";
    }

    ares_dns_task task;
    auto channel = task.channel;
    if (task.finish)
    {
        return "";
    }

    Coroutine *co = Coroutine::get_current();
    task.co = co;

    swTimer_node* timer = nullptr;
    if (timeout > 0)
    {
        timer = swTimer_add(&SwooleG.timer, (long) (timeout * 1000), 0, &task, ares_dns_timeout);
    }

    ares_gethostbyname(channel, hostname.c_str(), domain, ares_dns_callback, &task);
    int bitmap;
    ares_socket_t sock[ARES_GETSOCK_MAXNUM];

    if (unlikely(!swReactor_handle_isset(reactor, SW_FD_ARES)))
    {
        reactor->setHandle(reactor, SW_FD_ARES | SW_EVENT_READ, ares_event_read);
        reactor->setHandle(reactor, SW_FD_ARES | SW_EVENT_WRITE, ares_event_write);
        reactor->setHandle(reactor, SW_FD_ARES | SW_EVENT_ERROR, ares_event_error);
    }

    ares_socket_t active_sock[ARES_GETSOCK_MAXNUM];
    for (int i = 0; i < ARES_GETSOCK_MAXNUM; ++i)
    {
        active_sock[i] = ARES_SOCKET_BAD;
    }

    for (;;)
    {
        bitmap = ares_getsock(channel, sock, ARES_GETSOCK_MAXNUM);
        if (bitmap == 0)
        {
            break;
        }

        for (int i = 0; i < ARES_GETSOCK_MAXNUM; ++i)
        {
            if (ARES_GETSOCK_WRITABLE(bitmap, i))
            {
                // if it's writeable, it must be readable too.
                if (unlikely(reactor->add(reactor, sock[i], SW_FD_ARES | SW_EVENT_READ | SW_EVENT_WRITE) < 0))
                {
                    return "";
                }

                active_sock[i] = sock[i];
                auto sw_conn = swReactor_get(reactor, sock[i]);
                sw_conn->object = &task;
                sw_conn->removed = 0;
            }
            else if (ARES_GETSOCK_READABLE(bitmap, i))
            {
                // only readable
                if (unlikely(reactor->add(reactor, sock[i], SW_FD_ARES | SW_EVENT_READ) < 0))
                {
                    return "";
                }

                active_sock[i] = sock[i];
                auto sw_conn = swReactor_get(reactor, sock[i]);
                sw_conn->object = &task;
                sw_conn->removed = 0;
            }
            else
            {
                // don't have more socket
                break;
            }
        }

        co->yield();

        for (int i = 0; i < ARES_GETSOCK_MAXNUM; ++i)
        {
            if (active_sock[i] != ARES_SOCKET_BAD)
            {
                swReactor_get(reactor, active_sock[i])->removed = 1;
                reactor->del(reactor, active_sock[i]);
                active_sock[i] = ARES_SOCKET_BAD;
            }
            else
            {
                break;
            }
        }

        if (task.finish)
        {
            break;
        }
    }

    if (timer)
    {
        swTimer_del(&SwooleG.timer, timer);
    }

    return task.result;
}
#else
struct aio_task
{
    Coroutine *co;
    swAio_event *event;
};

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

string DNSResolver::resolve(const std::string &hostname, int domain, double timeout)
{
    if (timeout == 0)
    {
        timeout = resolve_timeout;
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
    ev.buf = sw_malloc(ev.nbytes);
    if (!ev.buf)
    {
        return "";
    }

    task.co = Coroutine::get_current();
    task.event = &ev;

    memcpy(ev.buf, hostname.c_str(), hostname.size());
    ((char *) ev.buf)[hostname.size()] = 0;
    ev.flags = domain;
    ev.type = SW_AIO_GETHOSTBYNAME;
    ev.object = (void*) &task;
    ev.handler = swAio_handler_gethostbyname;
    ev.callback = aio_onDNSCompleted;

    swAio_event *event = swAio_dispatch2(&ev);
    swTimer_node* timer = nullptr;
    if (timeout > 0)
    {
        timer = swTimer_add(&SwooleG.timer, (long) (timeout * 1000), 0, event, aio_onDNSTimeout);
    }
    task.co->yield();
    if (timer)
    {
        swTimer_del(&SwooleG.timer, timer);
    }

    if (ev.ret == -1)
    {
        SwooleG.error = ev.error;
        return "";
    }
    else
    {
        string addr((char *) ev.buf);
        sw_free(ev.buf);
        return addr;
    }
}
#endif