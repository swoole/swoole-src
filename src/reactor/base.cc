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

#include "swoole_socket.h"
#include "swoole_signal.h"
#include "swoole_reactor.h"
#include "swoole_timer.h"

#include "swoole_api.h"

namespace swoole {
using network::Socket;

#ifdef SW_USE_MALLOC_TRIM
#ifdef __APPLE__
#include <sys/malloc.h>
#else
#include <malloc.h>
#endif
#endif

#ifdef HAVE_EPOLL
ReactorImpl *make_reactor_epoll(Reactor *_reactor, int max_events);
#endif

#ifdef HAVE_KQUEUE
ReactorImpl *make_reactor_kqueue(Reactor *_reactor, int max_events);
#endif

ReactorImpl *make_reactor_poll(Reactor *_reactor, int max_events);

void ReactorImpl::after_removal_failure(const Socket *_socket) const {
    if (!_socket->silent_remove) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_EVENT_REMOVE_FAILED,
                         "failed to delete events[fd=%d#%d, type=%d, events=%d, errno=%d]",
                         _socket->fd,
                         reactor_->id,
                         _socket->fd_type,
                         _socket->events,
                         errno);
        swoole_print_backtrace_on_error();
    }
}

Reactor::Reactor(int max_event, Type _type) {
    if (_type == TYPE_AUTO) {
#ifdef HAVE_EPOLL
        type_ = TYPE_EPOLL;
#else
        type_ = TYPE_POLL;
#ifdef HAVE_KQUEUE
        /**
         * When kqueue is enabled, the Process mode of the Server module and functionalities such as Task operations,
         * pipe messaging, and inter-process message forwarding that rely on pipe communication will be unavailable.
         */
        if (SwooleG.enable_kqueue) {
            type_ = TYPE_KQUEUE;
        }
#endif
#endif
    } else {
        type_ = _type;
    }

    switch (type_) {
#ifdef HAVE_EPOLL
    case TYPE_EPOLL:
        impl = make_reactor_epoll(this, max_event);
        break;
#endif
#ifdef HAVE_KQUEUE
    case TYPE_KQUEUE:
        impl = make_reactor_kqueue(this, max_event);
        break;
#endif
    default:
        impl = make_reactor_poll(this, max_event);
        break;
    }

    if (!impl->ready()) {
        running = false;
        return;
    }

    running = true;
    timeout_msec = -1;
    idle_task = {};
    future_task = {};

    write = _write;
    writev = _writev;
    close = _close;

    default_write_handler = _writable_callback;

    if (swoole_isset_hook(SW_GLOBAL_HOOK_ON_REACTOR_CREATE)) {
        swoole_call_hook(SW_GLOBAL_HOOK_ON_REACTOR_CREATE, this);
    }

    set_end_callback(PRIORITY_DEFER_TASK, [](Reactor *reactor) {
        CallbackManager *cm = reactor->defer_tasks;
        if (cm) {
            reactor->defer_tasks = nullptr;
            cm->execute();
            delete cm;
        }
    });

    set_exit_condition(EXIT_CONDITION_DEFER_TASK,
                       [](Reactor *reactor, size_t &event_num) -> bool { return reactor->defer_tasks == nullptr; });

    set_end_callback(PRIORITY_IDLE_TASK, [](Reactor *reactor) {
        if (reactor->idle_task.callback) {
            reactor->idle_task.callback(reactor->idle_task.data);
        }
    });

    if (swoole_is_main_thread()) {
        set_end_callback(PRIORITY_SIGNAL_CALLBACK, [](Reactor *) { swoole_signal_dispatch(); });
    }

    set_end_callback(PRIORITY_TRY_EXIT, [](Reactor *reactor) {
        if (reactor->wait_exit && reactor->if_exit()) {
            reactor->running = false;
        }
    });

#ifdef SW_USE_MALLOC_TRIM
    if (swoole_is_main_thread()) {
        set_end_callback(PRIORITY_MALLOC_TRIM, [](Reactor *reactor) {
            time_t now = ::time(nullptr);
            if (reactor->last_malloc_trim_time < now - SW_MALLOC_TRIM_INTERVAL) {
                malloc_trim(SW_MALLOC_TRIM_PAD);
                reactor->last_malloc_trim_time = now;
            }
        });
    }
#endif

    set_exit_condition(EXIT_CONDITION_DEFAULT, [](Reactor *, size_t &event_num) -> bool { return event_num == 0; });
}

void Reactor::set_handler(const int fd_type, const int event, const ReactorHandler handler) {
    if (isset_read_event(event)) {
        read_handler[fd_type] = handler;
    } else if (isset_write_event(event)) {
        write_handler[fd_type] = handler;
    } else if (isset_error_event(event)) {
        error_handler[fd_type] = handler;
    } else {
        assert(0);
    }
}

bool Reactor::isset_handler(const int fd_type, const int event) const {
    if (isset_read_event(event)) {
        return read_handler[fd_type] != nullptr;
    } else if (isset_write_event(event)) {
        return write_handler[fd_type] != nullptr;
    } else if (isset_error_event(event)) {
        return error_handler[fd_type] != nullptr;
    } else {
        return false;
    }
}

bool Reactor::if_exit() {
    size_t _event_num = get_event_num();
    for (auto &kv : exit_conditions) {
        if (kv.second(this, _event_num) == false) {
            return false;
        }
    }
    return true;
}

int Reactor::_close(Reactor *reactor, Socket *socket) {
    swoole_trace_log(SW_TRACE_CLOSE, "fd=%d", socket->fd);
    socket->free();
    return SW_OK;
}

ssize_t Reactor::write_func(const Reactor *reactor,
                            Socket *socket,
                            const size_t _len,
                            const std::function<ssize_t()> &send_fn,
                            const std::function<void(Buffer *buffer)> &append_fn) {
    Buffer *buffer = socket->out_buffer;

    if (socket->buffer_size == 0) {
        socket->set_memory_buffer_size(Socket::default_buffer_size);
    }

    if (socket->nonblock == 0) {
        socket->set_fd_option(1, -1);
    }

    if ((uint32_t) _len > socket->buffer_size) {
        swoole_error_log(SW_LOG_WARNING,
                         SW_ERROR_PACKAGE_LENGTH_TOO_LARGE,
                         "data packet is too large, cannot exceed the socket buffer size");
        return SW_ERR;
    }

    if (Buffer::empty(buffer)) {
        ssize_t retval;
#ifdef SW_USE_OPENSSL
        if (socket->ssl_send_) {
            goto _alloc_buffer;
        }
#endif
    _do_send:
        retval = send_fn();

        if (retval > 0) {
            if ((ssize_t) _len == retval) {
                return retval;
            } else {
                goto _alloc_buffer;
            }
        } else if (socket->catch_write_error(errno) == SW_WAIT) {
        _alloc_buffer:
            if (!socket->out_buffer) {
                buffer = new Buffer(socket->chunk_size);
                socket->out_buffer = buffer;
            }
            if (!socket->isset_writable_event()) {
                reactor->add_write_event(socket);
            }
            /**
             * Part of the data has been successfully written to the kernel's socket buffer,
             * and at this point, writing to the memory queue is permitted under any circumstances.
             * Ensure that the async write operation either succeeds completely or fails entirely.
             */
            goto _append_buffer;
        } else if (errno == EINTR) {
            goto _do_send;
        } else {
            swoole_set_last_error(errno);
            return SW_ERR;
        }
    } else {
        if (buffer->length() + _len > socket->buffer_size) {
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_OUTPUT_BUFFER_OVERFLOW,
                             "socket#%d output buffer overflow: (%u/%u)",
                             socket->get_fd(),
                             buffer->length(),
                             socket->buffer_size);
            return SW_ERR;
        }
    _append_buffer:
        append_fn(buffer);
    }
    return _len;
}

ssize_t Reactor::_write(Reactor *reactor, Socket *socket, const void *buf, size_t n) {
    ssize_t send_bytes = 0;
    auto send_fn = [&send_bytes, socket, buf, n]() -> ssize_t {
        send_bytes = socket->send(buf, n, 0);
        return send_bytes;
    };
    auto append_fn = [&send_bytes, buf, n](Buffer *buffer) {
        ssize_t offset = send_bytes > 0 ? send_bytes : 0;
        buffer->append(static_cast<const char *>(buf) + offset, n - offset);
    };
    return write_func(reactor, socket, n, send_fn, append_fn);
}

ssize_t Reactor::_writev(Reactor *reactor, Socket *socket, const iovec *iov, size_t iovcnt) {
#ifdef SW_USE_OPENSSL
    if (socket->ssl) {
        swoole_error_log(SW_LOG_WARNING, SW_ERROR_OPERATION_NOT_SUPPORT, "does not support SSL");
        return SW_ERR;
    }
#endif

    ssize_t send_bytes = 0;
    size_t n = 0;
    SW_LOOP_N(iovcnt) {
        n += iov[i].iov_len;
    }
    auto send_fn = [&send_bytes, socket, iov, iovcnt]() -> ssize_t {
        send_bytes = socket->writev(iov, iovcnt);
        return send_bytes;
    };
    auto append_fn = [&send_bytes, iov, iovcnt](Buffer *buffer) {
        ssize_t offset = send_bytes > 0 ? send_bytes : 0;
        buffer->append(iov, iovcnt, offset);
    };
    return write_func(reactor, socket, n, send_fn, append_fn);
}

int Reactor::_writable_callback(Reactor *reactor, Event *ev) {
    int ret;

    Socket *socket = ev->socket;
    Buffer *buffer = socket->out_buffer;

    while (!Buffer::empty(buffer)) {
        BufferChunk *chunk = buffer->front();
        if (chunk->type == BufferChunk::TYPE_CLOSE) {
            return reactor->close(reactor, ev->socket);
        } else if (chunk->type == BufferChunk::TYPE_SENDFILE) {
            ret = socket->handle_sendfile();
        } else {
            ret = socket->handle_send();
        }

        if (ret < 0) {
            if (socket->close_wait) {
                return reactor->trigger_close_event(ev);
            } else if (socket->send_wait) {
                return SW_OK;
            }
        }
    }

    if (socket->send_timer) {
        swoole_timer_del(socket->send_timer);
        socket->send_timer = nullptr;
    }

    // remove EPOLLOUT event
    if (Buffer::empty(buffer)) {
        reactor->remove_write_event(ev->socket);
    }

    return SW_OK;
}

void Reactor::drain_write_buffer(Socket *socket) {
    Event event = {};
    event.socket = socket;
    event.fd = socket->fd;

    while (!Buffer::empty(socket->out_buffer)) {
        if (socket->wait_event(static_cast<int>(sec2msec(Socket::default_write_timeout)), SW_EVENT_WRITE) == SW_ERR) {
            break;
        }
        _writable_callback(this, &event);
        if (socket->close_wait || socket->removed) {
            break;
        }
    }
}

void Reactor::add_destroy_callback(const Callback &cb, void *data) {
    destroy_callbacks.append(cb, data);
}

void Reactor::set_end_callback(const EndCallback _id, const std::function<void(Reactor *)> &fn) {
    end_callbacks[_id] = fn;
}

void Reactor::erase_end_callback(const EndCallback _id) {
    end_callbacks.erase(_id);
}

/**
 * Returns false, the reactor cannot be exited, the next condition is skipped
 * Returns true, the reactor can exit and will continue to execute the next conditional function
 */
void Reactor::set_exit_condition(const ExitCondition _id, const std::function<bool(Reactor *, size_t &)> &fn) {
    exit_conditions[_id] = fn;
}

void Reactor::defer(const Callback &cb, void *data) {
    if (defer_tasks == nullptr) {
        defer_tasks = new CallbackManager;
    }
    defer_tasks->append(cb, data);
}

void Reactor::execute_end_callbacks(bool _timed_out) {
    timed_out = _timed_out;
    for (auto &kv : end_callbacks) {
        kv.second(this);
    }
}

void Reactor::execute_begin_callback() const {
    if (future_task.callback) {
        future_task.callback(future_task.data);
    }
}

Reactor::~Reactor() {
    destroyed = true;
    destroy_callbacks.execute();
    delete impl;
    if (swoole_isset_hook(SW_GLOBAL_HOOK_ON_REACTOR_DESTROY)) {
        swoole_call_hook(SW_GLOBAL_HOOK_ON_REACTOR_DESTROY, this);
    }
}
}  // namespace swoole
