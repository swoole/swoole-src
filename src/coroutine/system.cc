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
#include "swoole_lru_cache.h"
#include "swoole_signal.h"
#ifndef _WIN32
#include "swoole_iouring.h"
#else
#include "swoole_iocp.h"
#endif
#include "swoole_socket_impl.h"

#ifndef _WIN32
#include <pthread.h>
#endif

namespace swoole {
namespace coroutine {
namespace {

struct DnsCache {
    DnsCache();

    std::mutex mutex;
    size_t capacity = 1000;
    time_t expire = 60;
    std::unique_ptr<LRUCache<std::string>> data;
    size_t miss_count = 0;
    size_t hit_count = 0;
    uint64_t generation = 0;

    // The caller holds mutex. Outstanding lookups belong to the previous cache.
    void reset() {
        data.reset();
        miss_count = hit_count = 0;
        ++generation;
    }
};

DnsCache dns_cache;

DnsCache::DnsCache() {
#ifndef _WIN32
    // Hold the cache lock across fork and release it in both the parent and the child.
    void (*const unlock)() = [] { dns_cache.mutex.unlock(); };
    pthread_atfork([] { dns_cache.mutex.lock(); }, unlock, unlock);
#endif
}

}  // namespace

void System::set_dns_cache_expire(time_t expire) {
    std::lock_guard<std::mutex> lock(dns_cache.mutex);
    dns_cache.expire = expire;
}

void System::set_dns_cache_capacity(size_t capacity) {
    std::lock_guard<std::mutex> lock(dns_cache.mutex);
    dns_cache.capacity = capacity;
    dns_cache.reset();
}

void System::clear_dns_cache() {
    std::lock_guard<std::mutex> lock(dns_cache.mutex);
    dns_cache.reset();
}

float System::get_dns_cache_hit_ratio() {
    std::lock_guard<std::mutex> lock(dns_cache.mutex);
    auto total = dns_cache.hit_count + dns_cache.miss_count;
    if (total == 0) {
        return 0;
    }
    return (float) dns_cache.hit_count / (float) total;
}

int System::sleep(double sec) {
#if SW_USE_IOURING
    return Iouring::sleep(sec);
#endif
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
    std::string cache_key;
    std::shared_ptr<std::string> cached;
    uint64_t generation;
    do {
        std::lock_guard<std::mutex> lock(dns_cache.mutex);
        generation = dns_cache.generation;
        if (dns_cache.capacity != 0) {
            if (!dns_cache.data) {
                dns_cache.data = std::make_unique<LRUCache<std::string>>(dns_cache.capacity);
            }
            cache_key.append(domain == AF_INET ? "IPv4." : "IPv6.");
            cache_key.append(hostname);
            cached = dns_cache.data->get(cache_key);
            if (cached) {
                dns_cache.hit_count++;
            } else {
                dns_cache.miss_count++;
            }
        }
    } while (0);
    if (cached) {
        return *cached;
    }

    // The resolver may yield, so it must run outside the cache lock.
    std::string result;
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

    if (!cache_key.empty() && !result.empty()) {
        std::lock_guard<std::mutex> lock(dns_cache.mutex);
        if (dns_cache.generation == generation) {
            dns_cache.data->set(cache_key, std::make_shared<std::string>(result), dns_cache.expire);
        }
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

#ifndef _WIN32
struct SignalListener {
    struct PreviousSignal {
        SignalHandler handler = nullptr;
        bool registered = false;
    };

    Coroutine *co;
    int signo = -1;
    PreviousSignal previous_signals[SW_SIGNO_MAX];
};

/**
 * Only the main thread should listen for signals,
 * without modifying it to a thread-local variable.
 */
static SignalListener *listeners[SW_SIGNO_MAX];

void System::clear_signal_waiters_after_fork() {
    sw_memset_zero(listeners, sizeof(listeners));
    SwooleG.signal_async_listener_num = 0;
}

int System::wait_signal(int signal, double timeout) {
    std::vector<int> signals = {signal};
    return wait_signal(signals, timeout);
}

/**
 * @error: swoole_get_last_error()
 */
int System::wait_signal(const std::vector<int> &signals, double timeout) {
    auto *co = Coroutine::get_current_safe();

    if (SwooleG.signal_listener_num > 0) {
        swoole_set_last_error(EBUSY);
        return -1;
    }

    // Validate every signal before registering any of them.
    for (auto &signo : signals) {
        if (signo < 0 || signo >= SW_SIGNO_MAX || signo == SIGCHLD) {
            swoole_set_last_error(EINVAL);
            return -1;
        }
        if (sw_unlikely(listeners[signo] != nullptr)) {
            swoole_set_last_error(EBUSY);
            return -1;
        }
    }

    auto callback_fn = [](int signo) {
        auto *listener = listeners[signo];
        if (listener && listener->signo == -1) {
            listener->signo = signo;
            listener->co->resume();
        }
    };

    auto register_signal = [callback_fn](int signo, SignalListener &listener) {
        auto &previous = listener.previous_signals[signo];
        previous.handler = swoole_signal_get_handler(signo);
        previous.registered = true;
        swoole_signal_set(signo, callback_fn);
    };

#ifdef SW_USE_THREAD_CONTEXT
    // A canceled waiter can return before the main thread runs its deferred registration.
    auto listener_owner = std::make_shared<SignalListener>();
    auto &listener = *listener_owner;
#else
    SignalListener listener;
#endif
    listener.co = co;

    // exit condition
    if (!sw_reactor()->isset_exit_condition(Reactor::EXIT_CONDITION_CO_SIGNAL_LISTENER)) {
        sw_reactor()->set_exit_condition(
            Reactor::EXIT_CONDITION_CO_SIGNAL_LISTENER,
            [](Reactor *reactor, size_t &event_num) -> bool { return SwooleG.signal_async_listener_num == 0; });
    }

    SwooleG.signal_async_listener_num++;
    ON_SCOPE_EXIT {
        bool owns_wait = signals.empty();
        for (int signo : signals) {
            if (listeners[signo] != &listener) {
                continue;
            }
            owns_wait = true;
            listeners[signo] = nullptr;
            const auto &previous = listener.previous_signals[signo];
            if (!previous.registered) {
                continue;
            }
            auto handler = previous.handler;
#ifdef SW_USE_THREAD_CONTEXT
            swoole_event_defer([signo, handler](void *) { swoole_signal_set(signo, handler); }, nullptr);
#else
            swoole_signal_set(signo, handler);
#endif
        }
        if (owns_wait) {
            SwooleG.signal_async_listener_num--;
        }
    };

    for (int signo : signals) {
        if (listeners[signo] == &listener) {
            continue;
        }
        listeners[signo] = &listener;
#ifdef SW_USE_THREAD_CONTEXT
        swoole_event_defer(
            [signo, listener_owner, register_signal](void *) {
                if (listeners[signo] == listener_owner.get()) {
                    register_signal(signo, *listener_owner);
                }
            },
            nullptr);
#else
        register_signal(signo, listener);
#endif
    }

    return co->yield_ex(timeout) ? listener.signo : -1;
}
#endif

struct CoroPollTask {
    std::unordered_map<swSocketFd, PollSocket> *fds = nullptr;
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
        swoole_event_del(socket);
        socket->move_fd();
        socket->free();
        fd.second.socket = nullptr;
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

static inline void socket_poll_trigger_event(Reactor *reactor, CoroPollTask *task, swSocketFd fd, EventType event) {
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

bool System::socket_poll(std::unordered_map<swSocketFd, PollSocket> &fds, double timeout) {
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
        auto *socket = make_socket(fd.first, SW_FD_CO_POLL);
        if (swoole_event_add(socket, fd.second.events) < 0) {
            // socket_poll() is not the owner of the socket,
            // so the socket should not be closed upon failure or successful return;
            // it is necessary to release control over the fd.
            socket->move_fd();
            socket->free();
            continue;
        }
        socket->object = &task;
        fd.second.socket = socket;
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
    // shared with the deferred resume task, which may run after this object is destroyed
    std::shared_ptr<bool> waiting;

    EventWaiter(int fd, int events, double timeout) {
        error_ = revents = 0;
        waiting = std::make_shared<bool>(true);
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
        *waiting = false;

        swoole_event_del(socket);
    _done:
        socket->fd = SW_BAD_SOCKET; /* skip close */
        socket->free();
    }
};

static inline void event_waiter_callback(Reactor *reactor, EventWaiter *waiter, EventType event) {
    if (waiter->revents == 0) {
        reactor->defer([co = waiter->co, waiting = waiter->waiting](void *data) {
            // the timeout may have already resumed the coroutine and finished the wait
            if (*waiting) {
                co->resume();
            }
        });
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

pid_t System::waitpid_safe(pid_t _pid, int *_stat_loc, int _options) {
    if (sw_unlikely(SwooleTG.reactor == nullptr || !Coroutine::get_current() || (_options & WNOHANG))) {
        return ::sw_waitpid(_pid, _stat_loc, _options);
    }

#if SW_USE_IOURING
    auto rs = Iouring::waitpid(_pid, _stat_loc, _options, -1);
    if (rs < 0) {
        swoole_set_last_error(errno);
    }
    return rs;
#endif

    pid_t retval = -1;
    wait_for([_pid, &retval, _stat_loc]() -> bool {
        retval = ::sw_waitpid(_pid, _stat_loc, WNOHANG);
        return retval != 0;
    });

    return retval;
}

bool System::exec(const char *command, bool get_error_stream, std::shared_ptr<String> buffer, int *status) {
    Coroutine::get_current_safe();

    pid_t pid;
    int fd = swoole_shell_exec(command, &pid, get_error_stream);
    if (fd < 0) {
        swoole_sys_warning("Unable to execute '%s'", command);
        return false;
    }

    SocketImpl socket(fd,
#ifndef _WIN32
                      SW_SOCK_UNIX_STREAM
#else
                      SW_SOCK_TCP
#endif
    );
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
    reactor->set_handler(SW_FD_AIO, SW_EVENT_ERROR, AsyncThreads::callback);
#ifdef SW_USE_IOURING
    reactor->set_handler(SW_FD_IOURING, SW_EVENT_READ, Iouring::callback);
#endif
}

static void async_task_completed(AsyncEvent *event) {
    if (event->is_canceled()) {
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
        event.retval = -1;
        event.error = errno = swoole_get_last_error();
        return false;
    }

    if (!co->yield_ex(timeout)) {
        _ev->set_canceled(true);
        event.set_canceled(true);
        event.retval = -1;
        event.error = errno = swoole_get_last_error();
        return false;
    } else {
        event.set_canceled(_ev->is_canceled());
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
        errno = swoole_get_last_error();
        return false;
    }

    task.co->yield();
    errno = _ev->error;
    if (_ev->retval < 0) {
        swoole_set_last_error(_ev->error);
        return false;
    }
    return true;
}

bool wait_for(const std::function<bool(void)> &fn) {
    double second = SW_FILE_LOCK_DEFAULT_SECOND;
    while (true) {
        if (fn()) {
            break;
        }
        if (System::sleep(second) != SW_OK) {
            return false;
        }
        // Limit the maximum waiting time to 0.1 second; otherwise, this exponential time waiting
        // will make it increasingly difficult to acquire the lock.
        second = (second >= SW_FILE_LOCK_MAX_SECOND) ? SW_FILE_LOCK_DEFAULT_SECOND
                                                     : SW_MIN(second * 2, SW_FILE_LOCK_MAX_SECOND);
    }
    return true;
}

}  // namespace coroutine
}  // namespace swoole
