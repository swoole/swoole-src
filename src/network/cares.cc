#ifdef SW_USE_CARES
#include "cares.h"
#include "coroutine.h"
#include "ares.h"

using namespace swoole;
using namespace std;

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

string CAres::resolve(const std::string &hostname, int domain, double timeout)
{
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
    if (unlikely(!co))
    {
        return "";
    }
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
#endif