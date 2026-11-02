/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2018 The Swoole Group                             |
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

#include "php_swoole_pgsql.h"
#include "php_swoole_private.h"
#include "php_swoole_coroutine.h"

#include "swoole_socket_impl.h"

#include <algorithm>
#include <unordered_map>

#ifdef SW_USE_PGSQL

using swoole::Coroutine;
using swoole::EventType;
using swoole::Reactor;
using swoole::Timer;
using swoole::translate_events_to_poll;

static bool swoole_pgsql_blocking = true;
struct PgsqlIoError {
    int code;
    bool handled;
};
// Only interrupted I/O is recorded. PDO owns connection disposal and persistent-pool eviction.
static SW_THREAD_LOCAL std::unordered_map<PGconn *, PgsqlIoError> pgsql_io_errors;
/**
 * In macOS, under special circumstances, the poll function will not return a readable or writable signal. It is
 * necessary to set a relatively short poll timeout value to allow it to fail quickly. Then, re-execute PQconnectPoll,
 * and let the libpq underlying code determine whether the connection is ready or if an error has occurred.
 */
static const double swoole_pgsql_poll_timeout = 0.1;

void swoole_libpq_version(char *buf, size_t len)
{
    int version = PQlibVersion();
    int major = version / 10000;
    if (major >= 10) {
        int minor = version % 10000;
        snprintf(buf, len, "%d.%d", major, minor);
    } else {
        int minor = version / 100 % 100;
        int revision = version % 100;
        snprintf(buf, len, "%d.%d.%d", major, minor, revision);
    }
}

static int swoole_pgsql_socket_poll(PGconn *conn, EventType event) {
    if (swoole_pgsql_blocking) {
        struct pollfd fds[1];
        fds[0].fd = PQsocket(conn);
        fds[0].events = translate_events_to_poll(event);
        fds[0].revents = 0;

        int result = poll(fds, 1, swoole_pgsql_poll_timeout * 1000);
        return result < 0 && errno == EINTR ? 0 : result;
    }

    SocketImpl sock(PQsocket(conn), SW_SOCK_RAW);
    sock.get_socket()->nonblock = 1;

    bool retval = sock.poll(event, swoole_pgsql_poll_timeout);
    int error = sock.errCode;

    sock.move_fd();
    if (retval) {
        return 1;
    }
    if (error == ETIMEDOUT) {
        return 0;
    }
    pgsql_io_errors.emplace(conn, PgsqlIoError{error ? error : EIO, false});
    return -1;
}

static int swoole_pgsql_flush(PGconn *conn) {
    int flush_ret;

    while ((flush_ret = PQflush(conn)) == 1) {
        int ret = swoole_pgsql_socket_poll(conn, SW_EVENT_WRITE);
        if (sw_unlikely(ret < 0)) {
            return -1;
        }
        swoole_trace_log(SW_TRACE_CO_PGSQL, "PQflush(conn=%p)", conn);
    }

    return flush_ret;
}

static bool swoole_pgsql_wait_result(PGconn *conn) {
    while (PQisBusy(conn)) {
        if (swoole_pgsql_socket_poll(conn, SW_EVENT_READ) < 0) {
            return false;
        }
        if (PQconsumeInput(conn) == 0) {
            return false;
        }
    }
    return true;
}

static PGresult *swoole_pgsql_get_result(PGconn *conn) {
    PGresult *result, *last_result = nullptr;
    // without the hook PQgetResult() may block
    if (swoole_pgsql_blocking && sw_unlikely(swoole_pgsql_socket_poll(conn, SW_EVENT_READ) < 0)) {
        return nullptr;
    }

    while (swoole_pgsql_blocking || swoole_pgsql_wait_result(conn)) {
        swoole_trace_log(SW_TRACE_CO_PGSQL, "PQgetResult(conn=%p)", conn);
        result = PQgetResult(conn);
        if (!result) {
            return last_result;
        }
        PQclear(last_result);
        last_result = result;
    }

    PQclear(last_result);
    return nullptr;
}

static bool swoole_pgsql_wait_connect(PGconn *conn, PostgresPollingStatusType (*poll_connection)(PGconn *)) {
    // PQconnectPoll() ignores connect_timeout, so the caller has to enforce it.
    long timeout = 0;
    size_t host_count = 1;
    size_t address_count = 0;
    PQconninfoOption *options = PQconninfo(conn);
    for (PQconninfoOption *option = options; option && option->keyword; option++) {
        if (!option->val || option->val[0] == '\0') {
            continue;
        }
        if (strcmp(option->keyword, "connect_timeout") == 0) {
            timeout = strtol(option->val, nullptr, 10);
        } else if (strcmp(option->keyword, "host") == 0) {
            host_count = std::count(option->val, option->val + strlen(option->val), ',') + 1;
        } else if (strcmp(option->keyword, "hostaddr") == 0) {
            address_count = std::count(option->val, option->val + strlen(option->val), ',') + 1;
        }
    }
    PQconninfoFree(options);
    // libpq before 17 treats a connect_timeout of 1 as 2.
    if (timeout == 1 && PQlibVersion() < 170000) {
        timeout = 2;
    }
    // The public polling API cannot skip an expired target. Give the complete configured list its combined budget
    // instead, allowing libpq to perform failover without depending on private target indexes or address APIs.
    const size_t target_count = address_count ? address_count : host_count;
    const int64_t start_msec = Timer::get_absolute_msec();
    int r = PGRES_POLLING_WRITING;

    SW_LOOP {
        EventType event;

        switch (r) {
        case PGRES_POLLING_READING:
            event = SW_EVENT_READ;
            break;
        case PGRES_POLLING_WRITING:
            event = SW_EVENT_WRITE;
            break;
        default:
            swoole_warning("unexpected PQconnectPoll() status[%d]", r);
            return false;
        }

        int poll_result = swoole_pgsql_socket_poll(conn, event);
        if (poll_result < 0) {
            break;
        }
        // Divide the elapsed time to avoid overflowing when multiplying a user-supplied timeout by the target count.
        const uint64_t elapsed_sec = (Timer::get_absolute_msec() - start_msec) / 1000;
        if (timeout > 0 && elapsed_sec / target_count >= static_cast<uint64_t>(timeout)) {
            break;
        }
        // libpq sends its first packet from these states and assumes the socket is writable.
        if (poll_result == 0 && (PQstatus(conn) == CONNECTION_STARTED || PQstatus(conn) == CONNECTION_MADE)) {
            continue;
        }
        r = poll_connection(conn);
        if (r == PGRES_POLLING_OK || r == PGRES_POLLING_FAILED) {
            break;
        }
    }

    return PQstatus(conn) == CONNECTION_OK;
}

PGconn *swoole_pgsql_connectdb(const char *conninfo) {
    PGconn *conn = PQconnectStart(conninfo);
    if (conn == nullptr || PQsocket(conn) < 0) {
        return conn;
    }
    PQsetnonblocking(conn, !swoole_pgsql_blocking && Coroutine::get_current() ? 1 : 0);
    swoole_pgsql_wait_connect(conn, PQconnectPoll);
    return conn;
}

PGresult *swoole_pgsql_prepare(
    PGconn *conn, const char *stmt_name, const char *query, int n_params, const Oid *param_types) {
    swoole_trace_log(SW_TRACE_CO_PGSQL, "PQsendPrepare(conn=%p, stmt_name='%s')", conn, stmt_name);
    int ret = PQsendPrepare(conn, stmt_name, query, n_params, param_types);
    if (ret == 0) {
        return nullptr;
    }

    if (swoole_pgsql_flush(conn) == -1) {
        return nullptr;
    }

    return swoole_pgsql_get_result(conn);
}

PGresult *swoole_pgsql_exec_prepared(PGconn *conn,
                                     const char *stmt_name,
                                     int n_params,
                                     const char *const *param_values,
                                     const int *param_lengths,
                                     const int *param_formats,
                                     int result_format) {
    swoole_trace_log(SW_TRACE_CO_PGSQL, "PQsendQueryPrepared(conn=%p, stmt_name='%s')", conn, stmt_name);
    int ret = PQsendQueryPrepared(conn, stmt_name, n_params, param_values, param_lengths, param_formats, result_format);
    if (ret == 0) {
        return nullptr;
    }

    if (swoole_pgsql_flush(conn) == -1) {
        return nullptr;
    }

    return swoole_pgsql_get_result(conn);
}

PGresult *swoole_pgsql_exec(PGconn *conn, const char *query) {
    swoole_trace_log(SW_TRACE_CO_PGSQL, "PQsendQuery(conn=%p, query='%s')", conn, query);
    int ret = PQsendQuery(conn, query);
    if (ret == 0) {
        return nullptr;
    }

    if (swoole_pgsql_flush(conn) == -1) {
        return nullptr;
    }

    return swoole_pgsql_get_result(conn);
}

PGresult *swoole_pgsql_exec_params(PGconn *conn,
                                   const char *command,
                                   int n_params,
                                   const Oid *param_types,
                                   const char *const *param_values,
                                   const int *param_lengths,
                                   const int *param_formats,
                                   int result_format) {
    swoole_trace_log(SW_TRACE_CO_PGSQL, "PQsendQueryParams(conn=%p, command='%s')", conn, command);
    int ret = PQsendQueryParams(
        conn, command, n_params, param_types, param_values, param_lengths, param_formats, result_format);
    if (ret == 0) {
        return nullptr;
    }

    if (swoole_pgsql_flush(conn) == -1) {
        return nullptr;
    }

    return swoole_pgsql_get_result(conn);
}

#ifdef HAVE_PQCLOSEPREPARED
PGresult *swoole_pgsql_close_prepared(PGconn *conn, const char *stmtName) {
    int result = PQsendClosePrepared(conn, stmtName);
    if (sw_likely(result)) {
        return swoole_pgsql_get_result(conn);
    }

    return nullptr;
}
#endif

void swoole_pgsql_set_blocking(bool blocking) {
    swoole_pgsql_blocking = blocking;
}

void swoole_pgsql_finish(PGconn *conn) {
    pgsql_io_errors.erase(conn);
    PQfinish(conn);
}

bool php_swoole_pgsql_handle_io_error(pdo_dbh_t *dbh, const char **message) {
    auto *handle = static_cast<pdo_pgsql_db_handle *>(dbh->driver_data);
    auto error = pgsql_io_errors.find(handle->server);
    if (error == pgsql_io_errors.end()) {
        return false;
    }
    int error_code = error->second.code;

    // An incomplete reply must not be reused. Keep PGconn alive for PDO statements and LOBs
    // that still reference it; their normal destructors release it through PQfinish().
    if (!error->second.handled) {
        error->second.handled = true;
        int fd = PQsocket(handle->server);
        if (fd >= 0) {
            shutdown(fd, SHUT_RDWR);
            PQconsumeInput(handle->server);
        }
        if (dbh->is_persistent && dbh->persistent_id) {
            auto *resource = static_cast<zend_resource *>(
                zend_hash_str_find_ptr(&EG(persistent_list), dbh->persistent_id, dbh->persistent_id_len));
            if (resource && resource->ptr == dbh) {
                // Drop only the pool's ownership. Live PDO/statement objects must retain their handle.
                resource->ptr = nullptr;
                ZEND_ASSERT(dbh->refcount > 1);
                dbh->refcount--;
                zend_hash_str_del(&EG(persistent_list), dbh->persistent_id, dbh->persistent_id_len);
            }
        }
    }
    *message = swoole_strerror(error_code);
    return true;
}

zend_result php_swoole_pgsql_check_liveness(pdo_dbh_t *dbh) {
    auto *handle = static_cast<pdo_pgsql_db_handle *>(dbh->driver_data);
    if (pgsql_io_errors.count(handle->server)) {
        return FAILURE;
    }
    if (!PQconsumeInput(handle->server) || PQstatus(handle->server) == CONNECTION_BAD) {
        if (!swoole_pgsql_blocking) {
            if (!PQresetStart(handle->server) || PQsocket(handle->server) < 0) {
                return FAILURE;
            }
            PQsetnonblocking(handle->server, 1);
            return swoole_pgsql_wait_connect(handle->server, PQresetPoll) ? SUCCESS : FAILURE;
        }
        PQreset(handle->server);
    }
    return PQstatus(handle->server) == CONNECTION_OK ? SUCCESS : FAILURE;
}

void php_swoole_pgsql_minit(int module_id) {
    if (zend_hash_str_find(&php_pdo_get_dbh_ce()->constants_table, ZEND_STRL("PGSQL_ATTR_DISABLE_PREPARES")) ==
        nullptr) {
#if PHP_VERSION_ID >= 80500
        REGISTER_PDO_CLASS_CONST_LONG_DEPRECATED_85("PGSQL_ATTR_DISABLE_PREPARES", PDO_PGSQL_ATTR_DISABLE_PREPARES);
        REGISTER_PDO_CLASS_CONST_LONG_DEPRECATED_85("PGSQL_TRANSACTION_IDLE", (zend_long) PGSQL_TRANSACTION_IDLE);
        REGISTER_PDO_CLASS_CONST_LONG_DEPRECATED_85("PGSQL_TRANSACTION_ACTIVE", (zend_long) PGSQL_TRANSACTION_ACTIVE);
        REGISTER_PDO_CLASS_CONST_LONG_DEPRECATED_85("PGSQL_TRANSACTION_INTRANS", (zend_long) PGSQL_TRANSACTION_INTRANS);
        REGISTER_PDO_CLASS_CONST_LONG_DEPRECATED_85("PGSQL_TRANSACTION_INERROR", (zend_long) PGSQL_TRANSACTION_INERROR);
        REGISTER_PDO_CLASS_CONST_LONG_DEPRECATED_85("PGSQL_TRANSACTION_UNKNOWN", (zend_long) PGSQL_TRANSACTION_UNKNOWN);
#else
        REGISTER_PDO_CLASS_CONST_LONG("PGSQL_ATTR_DISABLE_PREPARES", PDO_PGSQL_ATTR_DISABLE_PREPARES);
        REGISTER_PDO_CLASS_CONST_LONG("PGSQL_TRANSACTION_IDLE", (zend_long) PGSQL_TRANSACTION_IDLE);
        REGISTER_PDO_CLASS_CONST_LONG("PGSQL_TRANSACTION_ACTIVE", (zend_long) PGSQL_TRANSACTION_ACTIVE);
        REGISTER_PDO_CLASS_CONST_LONG("PGSQL_TRANSACTION_INTRANS", (zend_long) PGSQL_TRANSACTION_INTRANS);
        REGISTER_PDO_CLASS_CONST_LONG("PGSQL_TRANSACTION_INERROR", (zend_long) PGSQL_TRANSACTION_INERROR);
        REGISTER_PDO_CLASS_CONST_LONG("PGSQL_TRANSACTION_UNKNOWN", (zend_long) PGSQL_TRANSACTION_UNKNOWN);
#endif
    }
    php_pdo_unregister_driver(&swoole_pdo_pgsql_driver);
    php_pdo_register_driver(&swoole_pdo_pgsql_driver);
}

void php_swoole_pgsql_mshutdown(void) {
    php_pdo_unregister_driver(&swoole_pdo_pgsql_driver);
}

#endif
