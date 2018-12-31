#ifdef SW_USE_CARES
#include "cares.h"
#include "coroutine.h"
#include "ares.h"
#include "sys/uio.h"

using namespace swoole;
using namespace std;

static ares_socket_t asocket(int af, int type, int protocol, void *data)
{
    int fd = socket(af, type, protocol);
    swSetNonBlock(fd);

    int ev_type = SW_FD_ARES | SW_EVENT_READ;
    if (type == SOCK_STREAM)
    {
        ev_type |= SW_EVENT_WRITE;
    }

    if (unlikely(SwooleG.main_reactor->add(SwooleG.main_reactor, fd, ev_type) < 0))
    {
        close(fd);
        return -1;
    }

    auto sock = swReactor_get(SwooleG.main_reactor, fd);
    sock->removed = 0;
    sock->fd = fd;
    sock->object = data;
    return fd;
}

static int aclose(ares_socket_t sock, void *data)
{
    swReactor_get(SwooleG.main_reactor, sock)->removed = 1;
    SwooleG.main_reactor->del(SwooleG.main_reactor, sock);

    return close(sock);
}

static int aconnect(ares_socket_t sock, const struct sockaddr *sock_addr, ares_socklen_t sock_len, void *data)
{
    return connect(sock, sock_addr, sock_len);
}

static ares_ssize_t arecvfrom(ares_socket_t sock, void *buf, size_t len, int flag,
        struct sockaddr *from, ares_socklen_t *from_len, void *data)
{
    return recvfrom(sock, buf, len, flag, from, from_len);
}

static ares_ssize_t asendv(ares_socket_t sock, const struct iovec *vector, int count, void *data)
{
    return writev(sock, vector, count);
}

struct _ares_dns_task
{
    ares_channel channel;
    ares_options options;
    ares_socket_functions sock_func;
    bool finish;
    string result;
    Coroutine *co;

    _ares_dns_task()
    {
        finish = false;
        co = nullptr;
        options.flags = ARES_FLAG_STAYOPEN; // don't close socket in end_query.
        sock_func.asocket = asocket;
        sock_func.aclose = aclose;
        sock_func.aconnect = aconnect;
        sock_func.arecvfrom = arecvfrom;
        sock_func.asendv = asendv;

        if (unlikely(ares_init_options(&channel, &options, ARES_OPT_FLAGS) != ARES_SUCCESS))
        {
            finish = true;
        }

        ares_set_socket_functions(channel, &sock_func, this);
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

    ares_process_fd(task->channel, event->fd, ARES_SOCKET_BAD);
    if (task->finish) task->co->resume();
    return SW_OK;
}

static int ares_event_write(swReactor *reactor, swEvent *event)
{
    auto task = (ares_dns_task *) event->socket->object;

    ares_process_fd(task->channel, ARES_SOCKET_BAD, event->fd);
    if (task->finish) task->co->resume();
    return SW_OK;
}

string CAres::resolve(const std::string &hostname, int domain, double timeout)
{
    auto reactor = SwooleG.main_reactor;
    if (unlikely(!reactor))
    {
        return "";
    }

    if (unlikely(!swReactor_handle_isset(reactor, SW_FD_ARES)))
    {
        reactor->setHandle(reactor, SW_FD_ARES | SW_EVENT_READ, ares_event_read);
        reactor->setHandle(reactor, SW_FD_ARES | SW_EVENT_WRITE, ares_event_write);
        reactor->setHandle(reactor, SW_FD_ARES | SW_EVENT_ERROR, ares_event_read);
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
    co->yield();

    if (timer)
    {
        swTimer_del(&SwooleG.timer, timer);
    }

    return task.result;
}
#endif