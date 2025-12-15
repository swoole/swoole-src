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

#ifdef SW_USE_IOURING
#include "swoole_iouring.h"
using swoole::Iouring;
#endif

namespace swoole {
namespace coroutine {

static struct {
    size_t capacity;
    time_t expire;
    LRUCache<std::string> *data;
    size_t miss_count;
    size_t hit_count;
} dns_cache = {
    1000,
    60,
    nullptr,
    0,
    0,
};

void System::set_dns_cache_expire(time_t expire) {
    dns_cache.expire = expire;
}

void System::set_dns_cache_capacity(size_t capacity) {
    dns_cache.capacity = capacity;
    clear_dns_cache();
    delete dns_cache.data;
    dns_cache.data = nullptr;
}

void System::clear_dns_cache() {
    if (dns_cache.data) {
        dns_cache.data->clear();
    }
    dns_cache.miss_count = 0;
    dns_cache.hit_count = 0;
}

float System::get_dns_cache_hit_ratio() {
    auto total = dns_cache.hit_count + dns_cache.miss_count;
    if (total == 0) {
        return 0;
    }
    return (float) dns_cache.hit_count / (float) total;
}

int System::sleep(double sec) {
    Coroutine *co = Coroutine::get_current_safe();
    if (sec < SW_TIMER_MIN_SEC) {
        sec = SW_TIMER_MIN_SEC;
    }
    co->yield_ex(sec);
    return co->is_canceled() ? SW_ERR : SW_OK;
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

ssize_t System::write_file(const char *file, const char *buf, size_t length, bool lock, int flags) {
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
    auto req = new GethostbynameRequest(hostname, domain);
    ev.data = std::shared_ptr<AsyncRequest>(req);
    ev.retval = 1;

    coroutine::async(async::handler_gethostbyname, ev, timeout);

    if (ev.retval == -1) {
        if (ev.error == SW_ERROR_AIO_TIMEOUT) {
            ev.error = SW_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT;
        }
        swoole_set_last_error(ev.error);
        return "";
    } else {
        return req->addr;
    }
}

std::string System::gethostbyname(const std::string &hostname, int domain, double timeout) {
    if (dns_cache.data == nullptr && dns_cache.capacity != 0) {
        dns_cache.data = new LRUCache<std::string>(dns_cache.capacity);
    }

    std::string cache_key;
    std::string result;

    if (dns_cache.data) {
        /**
         * The cache key must end with a prefix that uses a dot.
         * The domain name cannot contain the `.` symbol, and other characters are considered unsafe.
         */
        cache_key.append(domain == AF_INET ? "IPv4." : "IPv6.");
        cache_key.append(hostname);
        auto cache = dns_cache.data->get(cache_key);

        if (cache) {
            dns_cache.hit_count++;
            return *(std::string *) cache.get();
        } else {
            dns_cache.miss_count++;
        }
    }

#ifdef SW_USE_CARES
    auto result_list = dns_lookup_impl_with_cares(hostname.c_str(), domain, timeout);
    if (!result_list.empty()) {
        if (SwooleG.dns_lookup_random) {
            result = result_list[swoole_rand() % result_list.size()];
        } else {
            result = result_list[0];
        }
    }
#else
    result = gethostbyname_impl_with_async(hostname, domain, timeout);
#endif

    if (dns_cache.data && !result.empty()) {
        dns_cache.data->set(cache_key, std::make_shared<std::string>(result), dns_cache.expire);
    }

    return result;
}

std::vector<std::string> System::getaddrinfo(
    const std::string &hostname, int family, int socktype, int protocol, const std::string &service, double timeout) {
    assert(!hostname.empty());
    assert(family == AF_INET || family == AF_INET6);

    AsyncEvent ev{};
    auto req = new GetaddrinfoRequest(hostname, family, socktype, protocol, service);
    ev.data = std::shared_ptr<AsyncRequest>(req);

    coroutine::async(async::handler_getaddrinfo, ev, timeout);

    std::vector<std::string> retval;

    if (ev.retval == -1 || req->error != 0) {
        if (ev.error == SW_ERROR_AIO_TIMEOUT) {
            ev.error = SW_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT;
        }
        swoole_set_last_error(ev.error);
    } else {
        req->parse_result(retval);
    }

    return retval;
}

struct SignalListener {
    Coroutine *co;
    int signo;
};

/**
 * Only the main thread should listen for signals,
 * without modifying it to a thread-local variable.
 */
static SignalListener *listeners[SW_SIGNO_MAX];

int System::wait_signal(int signal, double timeout) {
    std::vector<int> signals = {signal};
    return wait_signal(signals, timeout);
}

/**
 * @error: swoole_get_last_error()
 */
int System::wait_signal(const std::vector<int> &signals, double timeout) {
    SignalListener listener = {
        Coroutine::get_current_safe(),
        -1,
    };

    if (SwooleG.signal_listener_num > 0) {
        swoole_set_last_error(EBUSY);
        return -1;
    }

    auto callback_fn = [](int signo) {
        auto listener = listeners[signo];
        if (listener) {
            listeners[signo] = nullptr;
            listener->signo = signo;
            listener->co->resume();
        }
    };

    for (auto &signo : signals) {
        if (signo < 0 || signo >= SW_SIGNO_MAX || signo == SIGCHLD) {
            swoole_set_last_error(EINVAL);
            return -1;
        }

        /* resgiter signal */
        listeners[signo] = &listener;

#ifdef SW_USE_THREAD_CONTEXT
        swoole_event_defer([signo, &callback_fn](void *) { swoole_signal_set(signo, callback_fn); }, nullptr);
#else
        swoole_signal_set(signo, callback_fn);
#endif
    }

    // exit condition
    if (!sw_reactor()->isset_exit_condition(Reactor::EXIT_CONDITION_CO_SIGNAL_LISTENER)) {
        sw_reactor()->set_exit_condition(
            Reactor::EXIT_CONDITION_CO_SIGNAL_LISTENER,
            [](Reactor *reactor, size_t &event_num) -> bool { return SwooleG.signal_async_listener_num == 0; });
    }

    SwooleG.signal_async_listener_num++;

    bool retval = listener.co->yield_ex(timeout);

    for (auto &signo : signals) {
#ifdef SW_USE_THREAD_CONTEXT
        swoole_event_defer([signo](void *) { swoole_signal_set(signo, nullptr); }, nullptr);
#else
        swoole_signal_set(signo, nullptr);
#endif
        listeners[signo] = nullptr;
    }

    SwooleG.signal_async_listener_num--;

    return retval ? listener.signo : -1;
}

struct CoroPollTask {
    std::unordered_map<int, PollSocket> *fds = nullptr;
    Coroutine *co = nullptr;
    TimerNode *timer = nullptr;
    bool success = false;
    bool wait = true;
};

static inline void socket_poll_clean(const CoroPollTask *task) {
    for (auto &fd : *task->fds) {
        network::Socket *socket = fd.second.socket;
        if (!socket) {
            continue;
        }
        int retval = swoole_event_del(fd.second.socket);
        socket->move_fd();
        socket->free();
        fd.second.socket = nullptr;
        if (retval < 0) {
            continue;
        }
    }
}

static void socket_poll_timeout(Timer *timer, TimerNode *tnode) {
    auto *task = static_cast<CoroPollTask *>(tnode->data);
    task->timer = nullptr;
    task->success = false;
    task->wait = false;
    socket_poll_clean(task);
    task->co->resume();
}

static void socket_poll_completed(void *data) {
    auto *task = static_cast<CoroPollTask *>(data);
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

bool System::socket_poll(std::unordered_map<int, PollSocket> &fds, double timeout) {
    if (timeout == 0) {
        auto *event_list = static_cast<struct pollfd *>(sw_calloc(fds.size(), sizeof(struct pollfd)));
        if (!event_list) {
            swoole_warning("calloc() failed");
            return false;
        }
        int n = 0;
        for (auto i = fds.begin(); i != fds.end(); ++i, n++) {
            event_list[n].fd = i->first;
            event_list[n].events = translate_events_to_poll(i->second.events);
            event_list[n].revents = 0;
        }
        int retval = ::poll(event_list, n, 0);
        if (retval > 0) {
            int _n = 0;
            for (auto i = fds.begin(); i != fds.end(); ++i, _n++) {
                i->second.revents = translate_events_from_poll(event_list[_n].revents);
            }
        }
        sw_free(event_list);
        return retval > 0;
    }

    size_t tasked_num = 0;
    CoroPollTask task;
    task.fds = &fds;
    task.co = Coroutine::get_current_safe();

    for (auto &fd : fds) {
        fd.second.socket = make_socket(fd.first, SW_FD_CO_POLL);
        if (swoole_event_add(fd.second.socket, fd.second.events) < 0) {
            // socket_poll() is not the owner of the socket,
            // so the socket should not be closed upon failure or successful return;
            // it is necessary to release control over the fd.
            fd.second.socket->move_fd();
            fd.second.socket->free();
            continue;
        }
        fd.second.socket->object = &task;
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
    Coroutine *co;
    int revents;
    int error_;

    EventWaiter(int fd, int events, double timeout) {
        error_ = revents = 0;
        socket = swoole::make_socket(fd, SW_FD_CO_EVENT);
        socket->object = this;
        co = Coroutine::get_current_safe();

        if (swoole_event_add(socket, events) < 0) {
            error_ = swoole_get_last_error();
            goto _done;
        }

        if (!co->yield_ex(timeout)) {
            error_ = swoole_get_last_error();
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
        return -1;
    }

    if (timeout == 0) {
        pollfd pfd;
        pfd.fd = fd;
        pfd.events = translate_events_to_poll(events);
        pfd.revents = 0;

        int retval = ::poll(&pfd, 1, 0);
        if (retval == 1) {
            if (pfd.revents & POLLNVAL) {
                swoole_set_last_error(EBADF);
                return -1;
            }
            return translate_events_from_poll(pfd.revents);
        }
        swoole_set_last_error(retval < 0 ? errno : ETIMEDOUT);
        return -1;
    }

    EventWaiter waiter(fd, events, timeout);
    if (waiter.error_) {
        errno = waiter.error_;
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

bool System::exec(const char *command, bool get_error_stream, std::shared_ptr<String> buffer, int *status) {
    Coroutine::get_current_safe();

    pid_t pid;
    int fd = swoole_shell_exec(command, &pid, get_error_stream);
    if (fd < 0) {
        swoole_sys_warning("Unable to execute '%s'", command);
        return false;
    }

    Socket socket(fd, SW_SOCK_UNIX_STREAM);
    while (true) {
        ssize_t retval = socket.read(buffer->str + buffer->length, buffer->size - buffer->length);
        if (retval > 0) {
            buffer->length += retval;
            if (buffer->length == buffer->size) {
                buffer->extend();
            }
        } else {
            break;
        }
    }
    socket.close();

    return waitpid_safe(pid, status, 0) == pid;
}

void System::init_reactor(Reactor *reactor) {
    reactor->set_handler(SW_FD_CO_POLL, SW_EVENT_READ, socket_poll_read_callback);
    reactor->set_handler(SW_FD_CO_POLL, SW_EVENT_WRITE, socket_poll_write_callback);
    reactor->set_handler(SW_FD_CO_POLL, SW_EVENT_ERROR, socket_poll_error_callback);

    reactor->set_handler(SW_FD_CO_EVENT, SW_EVENT_READ, event_waiter_read_callback);
    reactor->set_handler(SW_FD_CO_EVENT, SW_EVENT_WRITE, event_waiter_write_callback);
    reactor->set_handler(SW_FD_CO_EVENT, SW_EVENT_ERROR, event_waiter_error_callback);

    reactor->set_handler(SW_FD_AIO, SW_EVENT_READ, AsyncThreads::callback);
#ifdef SW_USE_IOURING
    reactor->set_handler(SW_FD_IOURING, SW_EVENT_READ, Iouring::callback);
#endif
}

static void async_task_completed(AsyncEvent *event) {
    if (event->canceled) {
        return;
    }
    auto *co = static_cast<Coroutine *>(event->object);
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
        event.error = errno = _ev->error;
        event.retval = _ev->retval;
        return true;
    }
}

struct AsyncLambdaTask {
    Coroutine *co;
    std::function<void()> fn;
};

static void async_lambda_handler(AsyncEvent *event) {
    auto *task = static_cast<AsyncLambdaTask *>(event->object);
    task->fn();
    event->error = errno;
    event->retval = 0;
}

static void async_lambda_callback(AsyncEvent *event) {
    auto *task = static_cast<AsyncLambdaTask *>(event->object);
    task->co->resume();
}

bool async(const std::function<void()> &fn) {
    AsyncEvent event{};
    AsyncLambdaTask task{Coroutine::get_current_safe(), fn};

    event.object = &task;
    event.handler = async_lambda_handler;
    event.callback = async_lambda_callback;

    AsyncEvent *_ev = async::dispatch(&event);
    if (_ev == nullptr) {
        return false;
    }

    task.co->yield();
    errno = _ev->error;
    return true;
}

bool wait_for(const std::function<bool(void)> &fn) {
    double second = 0.001;
    while (true) {
        if (fn()) {
            break;
        }
        if (System::sleep(second) != SW_OK) {
            return false;
        }
        second *= 2;
    }
    return true;
}

}  // namespace coroutine
}  // namespace swoole
