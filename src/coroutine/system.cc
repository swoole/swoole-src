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
  | Author: Tianfeng Han  <rango@swoole.com>                             |
  +----------------------------------------------------------------------+
*/

#include "swoole_coroutine_system.h"
#include "swoole_coroutine_socket.h"
#include "swoole_lru_cache.h"
#include "swoole_signal.h"

namespace swoole {
namespace coroutine {

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

static void sleep_callback(Coroutine *co, bool *canceled) {
    if (*canceled == false) {
        co->resume();
    }
    delete canceled;
}

int System::sleep(double sec) {
    Coroutine *co = Coroutine::get_current_safe();

    bool *canceled = new bool(false);
    TimerNode *tnode = nullptr;

    if (sec < SW_TIMER_MIN_SEC) {
        swoole_event_defer([co, canceled](void *data) { sleep_callback(co, canceled); }, nullptr);
    } else {
        auto fn = [canceled](Timer *timer, TimerNode *tnode) { sleep_callback((Coroutine *) tnode->data, canceled); };
        tnode = swoole_timer_add((long) (sec * 1000), false, fn, co);
        if (tnode == nullptr) {
            delete canceled;
            return -1;
        }
    }
    Coroutine::CancelFunc cancel_fn = [canceled, tnode](Coroutine *co) {
        *canceled = true;
        if (tnode) {
            swoole_timer_del(tnode);
        }
        co->resume();
        return true;
    };
    co->yield(&cancel_fn);
    if (co->is_canceled()) {
        swoole_set_last_error(SW_ERROR_CO_CANCELED);
        return SW_ERR;
    }
    return SW_OK;
}

std::shared_ptr<String> System::read_file(const char *file, bool lock) {
    std::shared_ptr<String> result;
    async([&result, file, lock]() {
        File fp(file, O_RDONLY);
        if (!fp.ready()) {
            swoole_sys_warning("open(%s, O_RDONLY) failed", file);
            return;
        }
        if (lock && !fp.lock(LOCK_SH)) {
            swoole_sys_warning("flock(%s, LOCK_SH) failed", file);
            return;
        }
        ssize_t filesize = fp.get_size();
        if (filesize > 0) {
            auto content = make_string(filesize + 1);
            content->length = fp.read_all(content->str, filesize);
            content->str[content->length] = 0;
            result = std::shared_ptr<String>(content);
        } else {
            result = fp.read_content();
        }
        if (lock && !fp.unlock()) {
            swoole_sys_warning("flock(%s, LOCK_UN) failed", file);
        }
    });
    return result;
}

ssize_t System::write_file(const char *file, char *buf, size_t length, bool lock, int flags) {
    ssize_t retval = -1;
    int file_flags = flags | O_CREAT | O_WRONLY;
    async([&]() {
        File _file(file, file_flags, 0644);
        if (!_file.ready()) {
            swoole_sys_warning("open(%s, %d) failed", file, file_flags);
            return;
        }
        if (lock && !_file.lock(LOCK_EX)) {
            swoole_sys_warning("flock(%s, LOCK_EX) failed", file);
            return;
        }
        size_t bytes = _file.write_all(buf, length);
        if ((file_flags & SW_AIO_WRITE_FSYNC) && !_file.sync()) {
            swoole_sys_warning("fsync(%s) failed", file);
        }
        if (lock && !_file.unlock()) {
            swoole_sys_warning("flock(%s, LOCK_UN) failed", file);
        }
        retval = bytes;
    });
    return retval;
}

std::string gethostbyname_impl_with_async(const std::string &hostname, int domain, double timeout) {
    AsyncEvent ev{};

    if (hostname.size() < SW_IP_MAX_LENGTH) {
        ev.nbytes = SW_IP_MAX_LENGTH + 1;
    } else {
        ev.nbytes = hostname.size() + 1;
    }

    ev.buf = sw_malloc(ev.nbytes);
    if (!ev.buf) {
        return "";
    }

    memcpy(ev.buf, hostname.c_str(), hostname.size());
    ((char *) ev.buf)[hostname.size()] = 0;
    ev.flags = domain;
    ev.retval = 1;

    coroutine::async(async::handler_gethostbyname, ev, timeout);

    if (ev.retval == -1) {
        if (ev.error == SW_ERROR_AIO_TIMEOUT) {
            ev.error = SW_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT;
        }
        swoole_set_last_error(ev.error);
        return "";
    } else {
        std::string addr((char *) ev.buf);
        sw_free(ev.buf);
        return addr;
    }
}

std::string System::gethostbyname(const std::string &hostname, int domain, double timeout) {
    if (dns_cache == nullptr && dns_cache_capacity != 0) {
        dns_cache = new LRUCache(dns_cache_capacity);
    }

    std::string cache_key;
    std::string result;

    if (dns_cache) {
        cache_key.append(domain == AF_INET ? "4_" : "6_");
        cache_key.append(hostname);
        auto cache = dns_cache->get(cache_key);

        if (cache) {
            return *(std::string *) cache.get();
        }
    }

#ifdef SW_USE_CARES
    auto result_list = dns_lookup_impl_with_cares(hostname.c_str(), domain, timeout);
    if (!result_list.empty()) {
        if (SwooleG.dns_lookup_random) {
            result = result_list[rand() % result_list.size()];
        } else {
            result = result_list[0];
        }
    }
#else
    result = gethostbyname_impl_with_async(hostname, domain, timeout);
#endif

    if (dns_cache && !result.empty()) {
        dns_cache->set(cache_key, std::make_shared<std::string>(result), dns_cache_expire);
    }

    return result;
}

std::vector<std::string> System::getaddrinfo(
    const std::string &hostname, int family, int socktype, int protocol, const std::string &service, double timeout) {
    assert(!hostname.empty());
    assert(family == AF_INET || family == AF_INET6);

    AsyncEvent ev{};
    network::GetaddrinfoRequest req{};

    ev.req = &req;

    struct sockaddr_in6 result_buffer[SW_DNS_HOST_BUFFER_SIZE];

    req.hostname = hostname.c_str();
    req.family = family;
    req.socktype = socktype;
    req.protocol = protocol;
    req.service = service.empty() ? nullptr : service.c_str();
    req.result = result_buffer;

    coroutine::async(async::handler_getaddrinfo, ev, timeout);

    std::vector<std::string> retval;

    if (ev.retval == -1 || req.error != 0) {
        if (ev.error == SW_ERROR_AIO_TIMEOUT) {
            ev.error = SW_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT;
        }
        swoole_set_last_error(ev.error);
    } else {
        req.parse_result(retval);
    }

    return retval;
}

/**
 * @error: swoole_get_last_error()
 */
bool System::wait_signal(int signo, double timeout) {
    static Coroutine *listeners[SW_SIGNO_MAX];
    Coroutine *co = Coroutine::get_current_safe();

    if (SwooleTG.signal_listener_num > 0) {
        swoole_set_last_error(EBUSY);
        return false;
    }
    if (signo < 0 || signo >= SW_SIGNO_MAX || signo == SIGCHLD) {
        swoole_set_last_error(EINVAL);
        return false;
    }

    /* resgiter signal */
    listeners[signo] = co;
    // for swSignalfd_setup
    sw_reactor()->check_signalfd = true;
    // exit condition
    if (!sw_reactor()->isset_exit_condition(Reactor::EXIT_CONDITION_CO_SIGNAL_LISTENER)) {
        sw_reactor()->set_exit_condition(
            Reactor::EXIT_CONDITION_CO_SIGNAL_LISTENER,
            [](Reactor *reactor, size_t &event_num) -> bool { return SwooleTG.co_signal_listener_num == 0; });
    }
    /* always enable signalfd */
    SwooleG.use_signalfd = SwooleG.enable_signalfd = 1;
    swoole_signal_set(signo, [](int signo) {
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
            timeout,
            0,
            [](Timer *timer, TimerNode *tnode) {
                Coroutine *co = (Coroutine *) tnode->data;
                co->resume();
            },
            co);
    }

    Coroutine::CancelFunc cancel_fn = [timer](Coroutine *co) {
        if (timer) {
            swoole_timer_del(timer);
        }
        co->resume();
        return true;
    };
    co->yield(&cancel_fn);

    swoole_signal_set(signo, nullptr);
    SwooleTG.co_signal_listener_num--;

    if (listeners[signo] != nullptr) {
        listeners[signo] = nullptr;
        swoole_set_last_error(co->is_canceled() ? SW_ERROR_CO_CANCELED : ETIMEDOUT);
        return false;
    }

    if (timer) {
        swoole_timer_del(timer);
    }

    return !co->is_canceled();
}

struct CoroPollTask {
    std::unordered_map<int, coroutine::PollSocket> *fds;
    Coroutine *co = nullptr;
    TimerNode *timer = nullptr;
    bool success = false;
    bool wait = true;
};

static inline void socket_poll_clean(CoroPollTask *task) {
    for (auto i = task->fds->begin(); i != task->fds->end(); i++) {
        network::Socket *socket = i->second.socket;
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

static void socket_poll_timeout(Timer *timer, TimerNode *tnode) {
    CoroPollTask *task = (CoroPollTask *) tnode->data;
    task->timer = nullptr;
    task->success = false;
    task->wait = false;
    socket_poll_clean(task);
    task->co->resume();
}

static void socket_poll_completed(void *data) {
    CoroPollTask *task = (CoroPollTask *) data;
    socket_poll_clean(task);
    task->co->resume();
}

static inline void socket_poll_trigger_event(Reactor *reactor, CoroPollTask *task, int fd, EventType event) {
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

static int socket_poll_read_callback(Reactor *reactor, Event *event) {
    socket_poll_trigger_event(reactor, (CoroPollTask *) event->socket->object, event->fd, SW_EVENT_READ);
    return SW_OK;
}

static int socket_poll_write_callback(Reactor *reactor, Event *event) {
    socket_poll_trigger_event(reactor, (CoroPollTask *) event->socket->object, event->fd, SW_EVENT_WRITE);
    return SW_OK;
}

static int socket_poll_error_callback(Reactor *reactor, Event *event) {
    socket_poll_trigger_event(reactor, (CoroPollTask *) event->socket->object, event->fd, SW_EVENT_ERROR);
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

bool System::socket_poll(std::unordered_map<int, PollSocket> &fds, double timeout) {
    if (timeout == 0) {
        struct pollfd *event_list = (struct pollfd *) sw_calloc(fds.size(), sizeof(struct pollfd));
        if (!event_list) {
            swoole_warning("calloc() failed");
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
    CoroPollTask task;
    task.fds = &fds;
    task.co = Coroutine::get_current_safe();

    for (auto i = fds.begin(); i != fds.end(); i++) {
        i->second.socket = swoole::make_socket(i->first, SW_FD_CO_POLL);
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
        task.timer = swoole_timer_add(timeout, false, socket_poll_timeout, &task);
    }

    task.co->yield();

    return task.success;
}

struct EventWaiter {
    network::Socket *socket;
    TimerNode *timer;
    Coroutine *co;
    int revents;
    int error_;

    EventWaiter(int fd, int events, double timeout) {
        error_ = revents = 0;
        socket = swoole::make_socket(fd, SW_FD_CO_EVENT);
        socket->object = this;
        timer = nullptr;
        co = Coroutine::get_current_safe();

        Coroutine::CancelFunc cancel_fn = [this](Coroutine *) {
            if (timer) {
                swoole_timer_del(timer);
            }
            error_ = SW_ERROR_CO_CANCELED;
            co->resume();
            return true;
        };

        if (swoole_event_add(socket, events) < 0) {
            swoole_set_last_error(errno);
            goto _done;
        }

        if (timeout > 0) {
            timer = swoole_timer_add(timeout,
                                     false,
                                     [](Timer *timer, TimerNode *tnode) {
                                         EventWaiter *waiter = (EventWaiter *) tnode->data;
                                         waiter->timer = nullptr;
                                         waiter->error_ = ETIMEDOUT;
                                         waiter->co->resume();
                                     },
                                     this);
        }

        co->yield(&cancel_fn);

        if (timer != nullptr) {
            swoole_timer_del(timer);
        }
        if (error_) {
            swoole_set_last_error(error_);
        }
        swoole_event_del(socket);
    _done:
        socket->fd = -1; /* skip close */
        socket->free();
    }
};

static inline void event_waiter_callback(Reactor *reactor, EventWaiter *waiter, EventType event) {
    if (waiter->revents == 0) {
        reactor->defer([waiter](void *data) { waiter->co->resume(); });
    }
    waiter->revents |= event;
}

static int event_waiter_read_callback(Reactor *reactor, Event *event) {
    event_waiter_callback(reactor, (EventWaiter *) event->socket->object, SW_EVENT_READ);
    return SW_OK;
}

static int event_waiter_write_callback(Reactor *reactor, Event *event) {
    event_waiter_callback(reactor, (EventWaiter *) event->socket->object, SW_EVENT_WRITE);
    return SW_OK;
}

static int event_waiter_error_callback(Reactor *reactor, Event *event) {
    event_waiter_callback(reactor, (EventWaiter *) event->socket->object, SW_EVENT_ERROR);
    return SW_OK;
}

/**
 * @errror: errno & swoole_get_last_error()
 */
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

    EventWaiter waiter(fd, events, timeout);
    if (waiter.error_) {
        errno = swoole_get_last_error();
        return SW_ERR;
    }

    int revents = waiter.revents;
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

void System::init_reactor(Reactor *reactor) {
    reactor->set_handler(SW_FD_CO_POLL | SW_EVENT_READ, socket_poll_read_callback);
    reactor->set_handler(SW_FD_CO_POLL | SW_EVENT_WRITE, socket_poll_write_callback);
    reactor->set_handler(SW_FD_CO_POLL | SW_EVENT_ERROR, socket_poll_error_callback);

    reactor->set_handler(SW_FD_CO_EVENT | SW_EVENT_READ, event_waiter_read_callback);
    reactor->set_handler(SW_FD_CO_EVENT | SW_EVENT_WRITE, event_waiter_write_callback);
    reactor->set_handler(SW_FD_CO_EVENT | SW_EVENT_ERROR, event_waiter_error_callback);

    reactor->set_handler(SW_FD_AIO | SW_EVENT_READ, AsyncThreads::callback);
}

static void async_task_completed(AsyncEvent *event) {
    if (event->canceled) {
        return;
    }
    Coroutine *co = (Coroutine *) event->object;
    co->resume();
}

/**
 * @error: swoole_get_last_error()
 */
bool async(async::Handler handler, AsyncEvent &event, double timeout) {
    Coroutine *co = Coroutine::get_current_safe();

    event.object = co;
    event.handler = handler;
    event.callback = async_task_completed;

    AsyncEvent *_ev = async::dispatch(&event);
    if (_ev == nullptr) {
        return false;
    }

    if (!co->yield_ex(timeout)) {
        event.canceled = _ev->canceled = true;
        event.retval = -1;
        event.error = errno = swoole_get_last_error();
        return false;
    } else {
        event.canceled = _ev->canceled;
        event.error =  errno = _ev->error;
        event.retval = _ev->retval;
        return true;
    }
}

struct AsyncLambdaTask {
    Coroutine *co;
    std::function<void(void)> fn;
};

static void async_lambda_handler(AsyncEvent *event) {
    AsyncLambdaTask *task = reinterpret_cast<AsyncLambdaTask *>(event->object);
    task->fn();
    event->error = errno;
    event->retval = 0;
}

static void async_lambda_callback(AsyncEvent *event) {
    if (event->canceled) {
        return;
    }
    AsyncLambdaTask *task = reinterpret_cast<AsyncLambdaTask *>(event->object);
    task->co->resume();
}

bool async(const std::function<void(void)> &fn, double timeout) {
    AsyncEvent event{};
    AsyncLambdaTask task{Coroutine::get_current_safe(), fn};

    event.object = &task;
    event.handler = async_lambda_handler;
    event.callback = async_lambda_callback;

    AsyncEvent *_ev = async::dispatch(&event);
    if (_ev == nullptr) {
        return false;
    }

    if (!task.co->yield_ex(timeout)) {
        _ev->canceled = true;
        errno = swoole_get_last_error();
        return false;
    } else {
        errno = _ev->error;
        return true;
    }
}

}  // namespace coroutine
}  // namespace swoole
