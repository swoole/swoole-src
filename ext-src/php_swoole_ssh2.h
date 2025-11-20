#pragma once

#include "php_swoole_cxx.h"
#include "php_swoole_ssh2_def.h"

#include <libssh2.h>
#include <libssh2_sftp.h>
#include <libssh2_publickey.h>

using CoSocket = swoole::coroutine::Socket;

typedef struct _php_ssh2_session_data {
    /* Userspace callback functions */
    zval *ignore_cb;
    zval *debug_cb;
    zval *macerror_cb;
    zval *disconnect_cb;

    CoSocket *socket;
} php_ssh2_session_data;

static inline swoole::EventType ssh2_get_event_type(LIBSSH2_SESSION *session) {
    int dir = libssh2_session_block_directions(session);
    if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
        return SW_EVENT_WRITE;
    } else {
        return SW_EVENT_READ;
    }
}

static inline CoSocket *ssh2_get_socket(LIBSSH2_SESSION *session) {
    auto session_data = (php_ssh2_session_data **) libssh2_session_abstract(session);
    return (*session_data)->socket;
}

static inline void ssh2_set_socket_timeout(LIBSSH2_SESSION *session, int timeout_ms) {
    auto sock = ssh2_get_socket(session);
    sock->set_timeout(timeout_ms / 1000, SW_TIMEOUT_ALL);
}

class ResourceGuard {
    zval zres_;

  public:
    ResourceGuard(zval *zres) {
        zval_addref_p(zres);
        zres_ = *zres;
    }
    ~ResourceGuard() {
        zval_ptr_dtor(&zres_);
    }
};

static inline int ssh2_async_call(LIBSSH2_SESSION *session, const std::function<int(void)> &fn) {
    auto event = ssh2_get_event_type(session);
    auto socket = ssh2_get_socket(session);

    socket->check_bound_co(SW_EVENT_READ);
    socket->check_bound_co(SW_EVENT_WRITE);

    int rc = 0;
    while (1) {
        rc = fn();
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            if (!socket->poll(event)) {
                return LIBSSH2_ERROR_SOCKET_NONE;
            }
            continue;
        }
        break;
    }
    return rc;
}

template <typename T>
static inline T *ssh2_async_call_ex(LIBSSH2_SESSION *session, const std::function<T *(void)> &fn) {
    auto event = ssh2_get_event_type(session);
    auto socket = ssh2_get_socket(session);

    socket->check_bound_co(SW_EVENT_READ);
    socket->check_bound_co(SW_EVENT_WRITE);

    T *handle;
    while (1) {
        handle = fn();
        if (handle) {
            return handle;
        }
        if (libssh2_session_last_errno(session) == LIBSSH2_ERROR_EAGAIN && socket->poll(event)) {
            continue;
        }
        break;
    }
    return nullptr;
}
