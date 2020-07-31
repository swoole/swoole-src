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

#include "coroutine_system.h"
#include "lru_cache.h"
#include "swoole_signal.h"

#include <fcntl.h>
#include <assert.h>

using namespace std;
using namespace swoole;
using swoole::coroutine::System;
using swoole::async::Event;

struct AsyncTask {
    Coroutine *co;
    Event *original_event;
};

static size_t dns_cache_capacity = 1000;
static time_t dns_cache_expire = 60;
static LRUCache *dns_cache = nullptr;

void System::set_dns_cache_expire(time_t expire) {
    dns_cache_expire = expire;
}

void System::set_dns_cache_capacity(size_t capacity) {
    dns_cache_capacity = capacity;
    delete dns_cache;
    dns_cache = nullptr;
}

void System::clear_dns_cache() {
    if (dns_cache) {
        dns_cache->clear();
    }
}

static void aio_onReadFileCompleted(Event *event) {
    AsyncTask *task = (AsyncTask *) event->object;
    task->original_event->buf = event->buf;
    task->original_event->nbytes = event->ret;
    task->original_event->error = event->error;
    ((Coroutine *) task->co)->resume();
}

static void aio_onWriteFileCompleted(Event *event) {
    AsyncTask *task = (AsyncTask *) event->object;
    task->original_event->ret = event->ret;
    task->original_event->error = event->error;
    ((Coroutine *) task->co)->resume();
}

static void aio_onDNSCompleted(Event *event) {
    if (event->canceled) {
        return;
    }
    AsyncTask *task = (AsyncTask *) event->object;
    task->original_event->ret = event->ret;
    task->original_event->error = event->error;
    ((Coroutine *) task->co)->resume();
}

static void aio_onDNSTimeout(swTimer *timer, TimerNode *tnode) {
    Event *event = (Event *) tnode->data;
    event->canceled = 1;
    AsyncTask *task = (AsyncTask *) event->object;
    task->original_event->ret = -1;
    task->original_event->error = SW_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT;
    ((Coroutine *) task->co)->resume();
}

static void sleep_timeout(swTimer *timer, TimerNode *tnode) {
    ((Coroutine *) tnode->data)->resume();
}

int System::sleep(double sec) {
    Coroutine *co = Coroutine::get_current_safe();
    if (sec < SW_TIMER_MIN_SEC) {
        swoole_event_defer([co](void *data) { co->resume(); }, nullptr);
    } else if (swoole_timer_add((long) (sec * 1000), false, sleep_timeout, co) == nullptr) {
        return -1;
    }
    co->yield();
    return 0;
}

swString *System::read_file(const char *file, bool lock) {
    AsyncTask task;

    Event ev;
    sw_memset_zero(&ev, sizeof(Event));

    task.co = Coroutine::get_current_safe();
    task.original_event = &ev;

    ev.lock = lock ? 1 : 0;
    ev.object = (void *) &task;
    ev.handler = async::handler_read_file;
    ev.callback = aio_onReadFileCompleted;
    ev.req = (void *) file;

    ssize_t ret = async::dispatch(&ev);
    if (ret < 0) {
        return nullptr;
    }
    task.co->yield();
    if (ev.error == 0) {
        return (swString *) ev.buf;
    } else {
        swoole_set_last_error(ev.error);
        return nullptr;
    }
}

ssize_t System::write_file(const char *file, char *buf, size_t length, bool lock, int flags) {
    AsyncTask task;

    Event ev;
    sw_memset_zero(&ev, sizeof(Event));

    task.co = Coroutine::get_current_safe();
    task.original_event = &ev;

    ev.lock = lock ? 1 : 0;
    ev.buf = buf;
    ev.nbytes = length;
    ev.object = (void *) &task;
    ev.handler = async::handler_write_file;
    ev.callback = aio_onWriteFileCompleted;
    ev.req = (void *) file;
    ev.flags = flags | O_CREAT | O_WRONLY;

    ssize_t ret = async::dispatch(&ev);
    if (ret < 0) {
        return -1;
    }
    task.co->yield();
    if (ev.error != 0) {
        swoole_set_last_error(ev.error);
    }
    return ev.ret;
}

string System::gethostbyname(const string &hostname, int domain, double timeout) {
    if (dns_cache == nullptr && dns_cache_capacity != 0) {
        dns_cache = new LRUCache(dns_cache_capacity);
    }

    string cache_key;
    if (dns_cache) {
        cache_key.append(domain == AF_INET ? "4_" : "6_");
        cache_key.append(hostname);
        auto cache = dns_cache->get(cache_key);

        if (cache) {
            return *(string *) cache.get();
        }
    }

    Event ev;
    AsyncTask task;

    sw_memset_zero(&ev, sizeof(Event));
    if (hostname.size() < SW_IP_MAX_LENGTH) {
        ev.nbytes = SW_IP_MAX_LENGTH + 1;
    } else {
        ev.nbytes = hostname.size() + 1;
    }

    task.co = Coroutine::get_current_safe();
    task.original_event = &ev;

    ev.buf = sw_malloc(ev.nbytes);
    if (!ev.buf) {
        return "";
    }

    memcpy(ev.buf, hostname.c_str(), hostname.size());
    ((char *) ev.buf)[hostname.size()] = 0;
    ev.flags = domain;
    ev.object = (void *) &task;
    ev.handler = async::handler_gethostbyname;
    ev.callback = aio_onDNSCompleted;
    /* TODO: find a better way */
    ev.ret = 1;

    Event *event = async::dispatch2(&ev);
    TimerNode *timer = nullptr;
    if (timeout > 0) {
        timer = swoole_timer_add((long) (timeout * 1000), false, aio_onDNSTimeout, event);
    }
    task.co->yield();
    if (ev.ret == 1) {
        /* TODO: find a better way */
        /* canceled */
        event->canceled = 1;
        ev.ret = -1;
        ev.error = SW_ERROR_DNSLOOKUP_RESOLVE_FAILED;
    }
    if (timer) {
        swoole_timer_del(timer);
    }

    if (ev.ret == -1) {
        swoole_set_last_error(ev.error);
        return "";
    } else {
        if (dns_cache) {
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

vector<string> System::getaddrinfo(
    const string &hostname, int family, int socktype, int protocol, const string &service, double timeout) {
    assert(!hostname.empty());
    assert(family == AF_INET || family == AF_INET6);

    Event ev;
    sw_memset_zero(&ev, sizeof(Event));

    swRequest_getaddrinfo req;
    sw_memset_zero(&req, sizeof(swRequest_getaddrinfo));

    AsyncTask task;

    task.co = Coroutine::get_current_safe();
    task.original_event = &ev;

    ev.object = &task;
    ev.handler = async::handler_getaddrinfo;
    ev.callback = aio_onDNSCompleted;
    ev.req = &req;

    struct sockaddr_in6 result_buffer[SW_DNS_HOST_BUFFER_SIZE];

    req.hostname = hostname.c_str();
    req.family = family;
    req.socktype = socktype;
    req.protocol = protocol;
    req.service = service.empty() ? nullptr : service.c_str();
    req.result = result_buffer;

    Event *event = async::dispatch2(&ev);
    TimerNode *timer = nullptr;
    if (timeout > 0) {
        timer = swoole_timer_add((long) (timeout * 1000), false, aio_onDNSTimeout, event);
    }
    task.co->yield();
    if (timer) {
        swoole_timer_del(timer);
    }

    vector<string> retval;

    if (ev.ret == -1 || req.error != 0) {
        swoole_set_last_error(ev.error);
    } else {
        req.parse_result(retval);
    }

    return retval;
}

bool System::wait_signal(int signo, double timeout) {
    static Coroutine *listeners[SW_SIGNO_MAX];
    Coroutine *co = Coroutine::get_current_safe();

    if (SwooleTG.signal_listener_num > 0) {
        errno = EBUSY;
        return false;
    }
    if (signo < 0 || signo >= SW_SIGNO_MAX || signo == SIGCHLD) {
        errno = EINVAL;
        return false;
    }

    /* resgiter signal */
    listeners[signo] = co;
    // for swSignalfd_setup
    sw_reactor()->check_signalfd = true;
    // exit condition
    if (!sw_reactor()->isset_exit_condition(SW_REACTOR_EXIT_CONDITION_CO_SIGNAL_LISTENER)) {
        sw_reactor()->set_exit_condition(
            SW_REACTOR_EXIT_CONDITION_CO_SIGNAL_LISTENER,
            [](swReactor *reactor, int &event_num) -> bool { return SwooleTG.co_signal_listener_num == 0; });
    }
    /* always enable signalfd */
    SwooleG.use_signalfd = SwooleG.enable_signalfd = 1;
    swSignal_set(signo, [](int signo) {
        Coroutine *co = listeners[signo];
        if (co) {
            listeners[signo] = nullptr;
            co->resume();
        }
    });
    SwooleTG.co_signal_listener_num++;

    TimerNode *timer = nullptr;
    if (timeout > 0) {
        timer = swoole_timer_add(
            timeout * 1000,
            0,
            [](swTimer *timer, TimerNode *tnode) {
                Coroutine *co = (Coroutine *) tnode->data;
                co->resume();
            },
            co);
    }

    co->yield();

    swSignal_set(signo, nullptr);
    SwooleTG.co_signal_listener_num--;

    if (listeners[signo] != nullptr) {
        listeners[signo] = nullptr;
        errno = ETIMEDOUT;
        return false;
    }

    if (timer) {
        swoole_timer_del(timer);
    }

    return true;
}

struct coro_poll_task {
    std::unordered_map<int, socket_poll_fd> *fds;
    Coroutine *co = nullptr;
    TimerNode *timer = nullptr;
    bool success = false;
    bool wait = true;
};

static inline void socket_poll_clean(coro_poll_task *task) {
    for (auto i = task->fds->begin(); i != task->fds->end(); i++) {
        swSocket *socket = i->second.socket;
        if (!socket) {
            continue;
        }
        int retval = swoole_event_del(i->second.socket);
        /**
         * Temporary socket, fd marked -1, skip close
         */
        socket->fd = -1;
        socket->free();
        i->second.socket = nullptr;
        if (retval < 0) {
            continue;
        }
    }
}

static void socket_poll_timeout(swTimer *timer, TimerNode *tnode) {
    coro_poll_task *task = (coro_poll_task *) tnode->data;
    task->timer = nullptr;
    task->success = false;
    task->wait = false;
    socket_poll_clean(task);
    task->co->resume();
}

static void socket_poll_completed(void *data) {
    coro_poll_task *task = (coro_poll_task *) data;
    socket_poll_clean(task);
    task->co->resume();
}

static inline void socket_poll_trigger_event(swReactor *reactor,
                                             coro_poll_task *task,
                                             int fd,
                                             enum swEvent_type event) {
    auto i = task->fds->find(fd);
    if (event == SW_EVENT_ERROR && !(i->second.events & SW_EVENT_ERROR)) {
        if (i->second.events & SW_EVENT_READ) {
            i->second.revents |= SW_EVENT_READ;
        }
        if (i->second.events & SW_EVENT_WRITE) {
            i->second.revents |= SW_EVENT_WRITE;
        }
    } else {
        i->second.revents |= event;
    }
    if (task->wait) {
        task->wait = false;
        task->success = true;
        if (task->timer) {
            swoole_timer_del(task->timer);
            task->timer = nullptr;
        }
        reactor->defer(socket_poll_completed, task);
    }
}

static int socket_poll_read_callback(swReactor *reactor, swEvent *event) {
    socket_poll_trigger_event(reactor, (coro_poll_task *) event->socket->object, event->fd, SW_EVENT_READ);
    return SW_OK;
}

static int socket_poll_write_callback(swReactor *reactor, swEvent *event) {
    socket_poll_trigger_event(reactor, (coro_poll_task *) event->socket->object, event->fd, SW_EVENT_WRITE);
    return SW_OK;
}

static int socket_poll_error_callback(swReactor *reactor, swEvent *event) {
    socket_poll_trigger_event(reactor, (coro_poll_task *) event->socket->object, event->fd, SW_EVENT_ERROR);
    return SW_OK;
}

static int translate_events_to_poll(int events) {
    int poll_events = 0;

    if (events & SW_EVENT_READ) {
        poll_events |= POLLIN;
    }
    if (events & SW_EVENT_WRITE) {
        poll_events |= POLLOUT;
    }

    return poll_events;
}

static int translate_events_from_poll(int events) {
    int sw_events = 0;

    if (events & POLLIN) {
        sw_events |= SW_EVENT_READ;
    }
    if (events & POLLOUT) {
        sw_events |= SW_EVENT_WRITE;
    }
    // ignore ERR and HUP, because event is already processed at IN and OUT handler.
    if ((((events & POLLERR) || (events & POLLHUP)) && !((events & POLLIN) || (events & POLLOUT)))) {
        sw_events |= SW_EVENT_ERROR;
    }

    return sw_events;
}

bool System::socket_poll(std::unordered_map<int, socket_poll_fd> &fds, double timeout) {
    if (timeout == 0) {
        struct pollfd *event_list = (struct pollfd *) sw_calloc(fds.size(), sizeof(struct pollfd));
        if (!event_list) {
            swWarn("calloc() failed");
            return false;
        }
        int n = 0;
        for (auto i = fds.begin(); i != fds.end(); i++, n++) {
            event_list[n].fd = i->first;
            event_list[n].events = translate_events_to_poll(i->second.events);
            event_list[n].revents = 0;
        }
        int retval = ::poll(event_list, n, 0);
        if (retval > 0) {
            int n = 0;
            for (auto i = fds.begin(); i != fds.end(); i++, n++) {
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

    for (auto i = fds.begin(); i != fds.end(); i++) {
        i->second.socket = swoole::make_socket(i->first, SW_FD_CORO_POLL);
        if (swoole_event_add(i->second.socket, i->second.events) < 0) {
            i->second.socket->free();
            continue;
        }
        i->second.socket->object = &task;
        tasked_num++;
    }

    if (sw_unlikely(tasked_num == 0)) {
        return false;
    }

    if (timeout > 0) {
        task.timer = swoole_timer_add((long) (timeout * 1000), false, socket_poll_timeout, &task);
    }

    task.co->yield();

    return task.success;
}

struct EventWaiter {
    swSocket *socket;
    TimerNode *timer;
    Coroutine *co;
    int revents;

    EventWaiter(int fd, int events, double timeout) {
        revents = 0;
        socket = swoole::make_socket(fd, SW_FD_CORO_EVENT);
        socket->object = this;
        if (swoole_event_add(socket, events) < 0) {
            swoole_set_last_error(errno);
            goto _done;
        }
        if (timeout > 0) {
            timer = swoole_timer_add((long) (timeout * 1000),
                                     false,
                                     [](swTimer *timer, TimerNode *tnode) {
                                         EventWaiter *waiter = (EventWaiter *) tnode->data;
                                         waiter->timer = nullptr;
                                         waiter->co->resume();
                                     },
                                     this);
        } else {
            timer = nullptr;
        }
        co = Coroutine::get_current();

        co->yield();

        if (timer != nullptr) {
            swoole_timer_del(timer);
        } else if (timeout > 0) {
            swoole_set_last_error(ETIMEDOUT);
        }
        swoole_event_del(socket);
    _done:
        socket->fd = -1; /* skip close */
        socket->free();
    }
};

static inline void event_waiter_callback(swReactor *reactor, EventWaiter *waiter, enum swEvent_type event) {
    if (waiter->revents == 0) {
        reactor->defer([waiter](void *data) { waiter->co->resume(); });
    }
    waiter->revents |= event;
}

static int event_waiter_read_callback(swReactor *reactor, swEvent *event) {
    event_waiter_callback(reactor, (EventWaiter *) event->socket->object, SW_EVENT_READ);
    return SW_OK;
}

static int event_waiter_write_callback(swReactor *reactor, swEvent *event) {
    event_waiter_callback(reactor, (EventWaiter *) event->socket->object, SW_EVENT_WRITE);
    return SW_OK;
}

static int event_waiter_error_callback(swReactor *reactor, swEvent *event) {
    event_waiter_callback(reactor, (EventWaiter *) event->socket->object, SW_EVENT_ERROR);
    return SW_OK;
}

int System::wait_event(int fd, int events, double timeout) {
    events &= SW_EVENT_READ | SW_EVENT_WRITE;
    if (events == 0) {
        swoole_set_last_error(EINVAL);
        return 0;
    }

    if (timeout == 0) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = translate_events_to_poll(events);
        pfd.revents = 0;

        int retval = ::poll(&pfd, 1, 0);
        if (retval == 1) {
            return translate_events_from_poll(pfd.revents);
        }
        if (retval < 0) {
            swoole_set_last_error(errno);
        }
        return 0;
    }

    int revents = EventWaiter(fd, events, timeout).revents;

    if (revents & SW_EVENT_ERROR) {
        revents ^= SW_EVENT_ERROR;
        if (events & SW_EVENT_READ) {
            revents |= SW_EVENT_READ;
        }
        if (events & SW_EVENT_WRITE) {
            revents |= SW_EVENT_WRITE;
        }
    }

    return revents;
}

void System::init_reactor(swReactor *reactor) {
    reactor->set_handler(SW_FD_CORO_POLL | SW_EVENT_READ, socket_poll_read_callback);
    reactor->set_handler(SW_FD_CORO_POLL | SW_EVENT_WRITE, socket_poll_write_callback);
    reactor->set_handler(SW_FD_CORO_POLL | SW_EVENT_ERROR, socket_poll_error_callback);

    reactor->set_handler(SW_FD_CORO_EVENT | SW_EVENT_READ, event_waiter_read_callback);
    reactor->set_handler(SW_FD_CORO_EVENT | SW_EVENT_WRITE, event_waiter_write_callback);
    reactor->set_handler(SW_FD_CORO_EVENT | SW_EVENT_ERROR, event_waiter_error_callback);

    reactor->set_handler(SW_FD_AIO | SW_EVENT_READ, async::callback);
}

static void async_task_completed(Event *event) {
    if (event->canceled) {
        return;
    }
    AsyncTask *task = (AsyncTask *) event->object;
    task->original_event->error = event->error;
    task->original_event->ret = event->ret;
    task->co->resume();
}

static void async_task_timeout(swTimer *timer, TimerNode *tnode) {
    Event *event = (Event *) tnode->data;
    event->canceled = 1;
    AsyncTask *task = (AsyncTask *) event->object;
    task->original_event->error = SW_ERROR_AIO_TIMEOUT;
    task->co->resume();
}

bool coroutine::async(async::Handler handler, Event &event, double timeout) {
    AsyncTask task;
    TimerNode *timer = nullptr;

    task.co = Coroutine::get_current_safe();
    task.original_event = &event;

    event.object = (void *) &task;
    event.handler = handler;
    event.callback = async_task_completed;

    Event *_ev = async::dispatch2(&event);
    if (_ev == nullptr) {
        return false;
    }
    if (timeout > 0) {
        timer = swoole_timer_add((long) (timeout * 1000), false, async_task_timeout, _ev);
    }
    task.co->yield();
    if (event.error == SW_ERROR_AIO_TIMEOUT) {
        return false;
    } else {
        if (timer) {
            swoole_timer_del(timer);
        }
        return true;
    }
}

struct AsyncLambdaTask {
    Coroutine *co;
    std::function<void(void)> fn;
};

static void async_lambda_handler(Event *event) {
    AsyncLambdaTask *task = reinterpret_cast<AsyncLambdaTask *>(event->object);
    task->fn();
    event->error = 0;
    event->ret = 0;
}

static void async_lambda_callback(Event *event) {
    if (event->canceled) {
        return;
    }
    AsyncLambdaTask *task = reinterpret_cast<AsyncLambdaTask *>(event->object);
    task->co->resume();
}

bool coroutine::async(const std::function<void(void)> &fn, double timeout) {
    TimerNode *timer = nullptr;
    Event event = {};

    AsyncLambdaTask task;
    task.co = Coroutine::get_current_safe();
    task.fn = fn;

    event.object = &task;
    event.handler = async_lambda_handler;
    event.callback = async_lambda_callback;

    Event *_ev = async::dispatch2(&event);
    if (_ev == nullptr) {
        return false;
    }
    if (timeout > 0) {
        timer = swoole_timer_add((long) (timeout * 1000), false, async_task_timeout, _ev);
    }
    task.co->yield();
    if (event.error == SW_ERROR_AIO_TIMEOUT) {
        return false;
    } else {
        if (timer) {
            swoole_timer_del(timer);
        }
        return true;
    }
}
