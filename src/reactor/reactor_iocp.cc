/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  +----------------------------------------------------------------------+
*/

#include "swoole_afd.h"
#include "swoole_iocp.h"
#include "swoole_reactor.h"
#include "swoole_socket.h"

#if defined(_WIN32) && defined(SW_USE_IOCP)

#include <unordered_map>

namespace swoole {
using network::Socket;

class ReactorIocp final : public ReactorImpl {
    struct PollOperation;

    struct PollState {
        Socket *socket = nullptr;
        PollOperation *operation = nullptr;
        int events = 0;
    };

    struct PollOperation {
        IocpEvent event;
        ReactorIocp *reactor;
        afd::PollInfo poll_info;

        PollOperation(ReactorIocp *reactor_, Socket *socket, ULONG events)
            : event(SW_IOCP_CUSTOM, socket->fd), reactor(reactor_) {
            event.callback = on_complete;
            event.private_data = this;
            event.exit_blocking = false;
            afd::init_poll_info(&poll_info, socket->fd, events);
        }

        static void on_complete(IocpEvent *event, DWORD transferred, DWORD error) {
            (void) transferred;
            auto *operation = static_cast<PollOperation *>(event->private_data);
            ReactorIocp *reactor = operation->reactor;
            if (reactor && !event->orphaned) {
                reactor->complete(operation, error);
            }
            delete operation;
        }
    };

    std::unordered_map<swSocketFd, PollState> states_;
    int max_events_;

    static ULONG events_to_afd(int events) {
        ULONG poll_events = afd::POLL_DISCONNECT | afd::POLL_ABORT | afd::POLL_LOCAL_CLOSE | afd::POLL_CONNECT_FAIL;

        if (Reactor::isset_read_event(events)) {
            poll_events |= afd::POLL_RECEIVE | afd::POLL_RECEIVE_EXPEDITED;
        }
        if (Reactor::isset_write_event(events)) {
            poll_events |= afd::POLL_SEND;
        }

        return poll_events;
    }

    static int events_from_afd(ULONG events, LONG status, DWORD error) {
        int sw_events = 0;

        if (events & (afd::POLL_RECEIVE | afd::POLL_RECEIVE_EXPEDITED | afd::POLL_DISCONNECT)) {
            sw_events |= SW_EVENT_READ;
        }
        if (events & afd::POLL_SEND) {
            sw_events |= SW_EVENT_WRITE;
        }
        if (error != ERROR_SUCCESS || status != 0 || (events & afd::POLL_ERROR_EVENTS)) {
            sw_events |= SW_EVENT_ERROR;
        }

        return sw_events;
    }

    void cancel(PollOperation *operation) {
        if (!operation || operation->event.completed) {
            return;
        }
        if (SwooleTG.iocp) {
            SwooleTG.iocp->cancel_submission(&operation->event);
        } else {
            operation->event.orphaned = true;
        }
        CancelIoEx(reinterpret_cast<HANDLE>(operation->event.fd), &operation->event.overlapped);
    }

    int submit(PollState *state) {
        if (!state->socket || state->socket->removed || state->operation) {
            return SW_OK;
        }

        auto *operation = new PollOperation(this, state->socket, events_to_afd(state->events));
        state->operation = operation;
        SwooleTG.iocp->submit(&operation->event);

        DWORD bytes = 0;
        BOOL ok = DeviceIoControl(reinterpret_cast<HANDLE>(state->socket->fd),
                                  afd::IOCTL_POLL,
                                  &operation->poll_info,
                                  sizeof(operation->poll_info),
                                  &operation->poll_info,
                                  sizeof(operation->poll_info),
                                  &bytes,
                                  &operation->event.overlapped);
        const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        if (!ok && error != ERROR_IO_PENDING) {
            SwooleTG.iocp->cancel_submission(&operation->event);
            state->operation = nullptr;
            delete operation;
            Iocp::set_error(error);
            return SW_ERR;
        }

        return SW_OK;
    }

    int submit_all() {
        for (auto &kv : states_) {
            if (submit(&kv.second) < 0) {
                return SW_ERR;
            }
        }
        return SW_OK;
    }

    void complete(PollOperation *operation, DWORD error) {
        const swSocketFd fd = operation->event.fd;
        auto iter = states_.find(fd);
        if (iter == states_.end() || iter->second.operation != operation) {
            return;
        }

        PollState *state = &iter->second;
        state->operation = nullptr;

        const auto &handle = operation->poll_info.handles[0];
        const int events = events_from_afd(handle.events, handle.status, error);
        if (events) {
            dispatch(fd, events);
        }
    }

    void dispatch(swSocketFd fd, int events) {
        if (!reactor_->exists(fd)) {
            return;
        }

        Event event = {};
        event.socket = reactor_->get_socket(fd);
        event.fd = fd;
        event.reactor_id = reactor_->id;
        event.type = event.socket->fd_type;

        if (events & SW_EVENT_ERROR) {
            event.socket->event_hup = 1;
        }

        int ret;
        ReactorHandler handler;
        bool handled = false;

        if ((events & SW_EVENT_READ) && (event.socket->events & SW_EVENT_READ) && !event.socket->removed) {
            handler = reactor_->get_handler(event.type, SW_EVENT_READ);
            if (handler) {
                ret = handler(reactor_, &event);
                handled = true;
                if (ret < 0) {
                    swoole_sys_warning("IOCP READ handle failed. fd=%d", event.fd);
                    swoole_print_backtrace_on_error();
                }
            }
        }

        if ((events & SW_EVENT_WRITE) && (event.socket->events & SW_EVENT_WRITE) && !event.socket->removed) {
            handler = reactor_->get_handler(event.type, SW_EVENT_WRITE);
            if (handler) {
                ret = handler(reactor_, &event);
                handled = true;
                if (ret < 0) {
                    swoole_sys_warning("IOCP WRITE handle failed. fd=%d", event.fd);
                    swoole_print_backtrace_on_error();
                }
            }
        }

        if ((events & SW_EVENT_ERROR) && !handled && !event.socket->removed) {
            handler = reactor_->get_error_handler(event.type);
            if (handler) {
                ret = handler(reactor_, &event);
                if (ret < 0) {
                    swoole_sys_warning("IOCP ERROR handle failed. fd=%d", event.fd);
                    swoole_print_backtrace_on_error();
                }
            }
        }

        if (!event.socket->removed && (event.socket->events & SW_EVENT_ONCE)) {
            del(event.socket);
        }
    }

  public:
    ReactorIocp(Reactor *_reactor, int max_events) : ReactorImpl(_reactor), max_events_(max_events) {
        reactor_->max_event_num = max_events;
        Iocp::init(reactor_);
    }

    ~ReactorIocp() override {
        for (auto &kv : states_) {
            cancel(kv.second.operation);
            kv.second.operation = nullptr;
        }
    }

    bool ready() override {
        return SwooleTG.iocp && SwooleTG.iocp->ready();
    }

    int add(Socket *socket, int events) override {
        if (reactor_->_exists(socket)) {
            swoole_error_log(
                SW_LOG_WARNING,
                SW_ERROR_EVENT_ADD_FAILED,
                "[Reactor#%d] failed to add events[fd=%d, fd_type=%d, events=%d], the socket#%d is already exists",
                reactor_->id,
                socket->fd,
                socket->fd_type,
                events,
                socket->fd);
            swoole_print_backtrace_on_error();
            return SW_ERR;
        }

        if (reactor_->get_event_num() == static_cast<size_t>(max_events_)) {
            swoole_error_log(
                SW_LOG_WARNING, SW_ERROR_EVENT_ADD_FAILED, "too many sockets, the max events is %d", max_events_);
            swoole_print_backtrace_on_error();
            return SW_ERR;
        }

        if (!SwooleTG.iocp->associate_socket(socket->fd)) {
            return SW_ERR;
        }

        reactor_->_add(socket, events);
        states_[socket->fd] = PollState{socket, nullptr, events};
        return SW_OK;
    }

    int set(Socket *socket, int events) override {
        if (!reactor_->_exists(socket)) {
            swoole_error_log(
                SW_LOG_WARNING,
                SW_ERROR_SOCKET_NOT_EXISTS,
                "[Reactor#%d] failed to set events[fd=%d, fd_type=%d, events=%d], the socket#%d has already been removed",
                reactor_->id,
                socket->fd,
                socket->fd_type,
                events,
                socket->fd);
            swoole_print_backtrace_on_error();
            return SW_ERR;
        }

        auto &state = states_[socket->fd];
        cancel(state.operation);
        state.operation = nullptr;
        state.socket = socket;
        state.events = events;
        reactor_->_set(socket, events);
        return SW_OK;
    }

    int del(Socket *socket) override {
        if (socket->removed) {
            swoole_error_log(
                SW_LOG_WARNING,
                SW_ERROR_SOCKET_NOT_EXISTS,
                "[Reactor#%d] failed to delete events[fd=%d, fd_type=%d], the socket#%d has already been removed",
                reactor_->id,
                socket->fd,
                socket->fd_type,
                socket->fd);
            swoole_print_backtrace_on_error();
            return SW_ERR;
        }

        if (!reactor_->_exists(socket)) {
            swoole_error_log(SW_LOG_WARNING,
                             SW_ERROR_SOCKET_NOT_EXISTS,
                             "[Reactor#%d] failed to delete events[fd=%d, fd_type=%d], the socket#%d is not exists",
                             reactor_->id,
                             socket->fd,
                             socket->fd_type,
                             socket->fd);
            swoole_print_backtrace_on_error();
            return SW_ERR;
        }

        auto iter = states_.find(socket->fd);
        if (iter != states_.end()) {
            cancel(iter->second.operation);
            states_.erase(iter);
        }
        reactor_->_del(socket);
        return SW_OK;
    }

    int wait() override {
        reactor_->before_wait();

        while (reactor_->running) {
            reactor_->execute_begin_callback();

            int ret;
            if (submit_all() < 0) {
                ret = SW_ERR;
            } else if (reactor_->if_exit()) {
                reactor_->running = false;
                break;
            } else if (SwooleTG.iocp && SwooleTG.iocp->get_task_num() > 0) {
                ret = SwooleTG.iocp->wait(reactor_->get_timeout_msec());
            } else {
                const int timeout = reactor_->get_timeout_msec();
                Sleep(timeout < 0 ? 1 : timeout);
                ret = 0;
            }

            if (ret < 0) {
                if (!reactor_->catch_error()) {
                    swoole_sys_warning("[Reactor#%d] IOCP wait(timeout=%d) failed",
                                       reactor_->id,
                                       reactor_->get_timeout_msec());
                    break;
                }
            } else if (ret == 0) {
                reactor_->execute_end_callbacks(true);
                SW_REACTOR_CONTINUE;
            } else {
                reactor_->execute_end_callbacks(false);
                SW_REACTOR_CONTINUE;
            }
        }

        return SW_OK;
    }
};

ReactorImpl *make_reactor_iocp(Reactor *_reactor, int max_events) {
    return new ReactorIocp(_reactor, max_events);
}
}  // namespace swoole

#endif
